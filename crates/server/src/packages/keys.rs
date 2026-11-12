use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use sha2::{Digest as _, Sha256};
use vmkek_packager::{PackageKey, SealedRelease};
use vmkek_protocol::{Digest, ModuleManifest, PackageFrame, VmDescriptor};
use zeroize::Zeroizing;

use super::{PackageError, PackageStore, ReleaseScope};

const MAX_PROVISIONED_KEYS: usize = 64;
const MAX_NEGOTIATED_KEYS: usize = 128;

#[derive(Clone)]
pub struct ModuleKeyStore {
    pub(crate) packages: PackageStore,
    keys: Arc<Mutex<HashMap<Digest, KeyEntry>>>,
}

impl ModuleKeyStore {
    pub fn new(packages: PackageStore) -> Self {
        Self {
            packages,
            keys: Arc::default(),
        }
    }

    /// Trusted build-plane handoff for an already-published, exactly matching artifact.
    pub async fn provision(
        &self,
        scope: ReleaseScope,
        sealed: SealedRelease,
    ) -> Result<(), PackageError> {
        self.packages.provision_key(self, scope, sealed).await
    }

    pub(super) fn insert_fixed(
        &self,
        manifest: Digest,
        key: &PackageKey,
    ) -> Result<(), PackageError> {
        let mut keys = self.keys.lock().map_err(|_| PackageError::Unavailable)?;
        if !keys.contains_key(&manifest) && keys.len() >= MAX_PROVISIONED_KEYS {
            return Err(PackageError::Unavailable);
        }
        keys.insert(
            manifest,
            KeyEntry {
                key: copy_key(key),
                pending: None,
            },
        );
        Ok(())
    }

    pub(crate) fn manifest_ids(&self) -> Result<Vec<Vec<u8>>, PackageError> {
        let keys = self.keys.lock().map_err(|_| PackageError::Unavailable)?;
        Ok(keys.keys().map(|id| id.to_vec()).collect())
    }

    pub(crate) fn stage_negotiated(
        &self,
        manifest: Digest,
        key: &PackageKey,
        retired: Vec<Vec<u8>>,
    ) -> Result<PendingKey<'_>, PackageError> {
        let mut keys = self.keys.lock().map_err(|_| PackageError::Unavailable)?;
        for id in retired {
            keys.remove(id.as_slice());
        }
        let identity = if let Some(entry) = keys.get(&manifest) {
            entry.pending.clone()
        } else {
            if keys.len() >= MAX_NEGOTIATED_KEYS {
                return Err(PackageError::Unavailable);
            }
            let identity = Arc::new(());
            keys.insert(
                manifest,
                KeyEntry {
                    key: copy_key(key),
                    pending: Some(identity.clone()),
                },
            );
            Some(identity)
        };
        Ok(PendingKey {
            store: self,
            manifest,
            identity,
        })
    }

    pub(crate) fn has_manifest(&self, manifest: &Digest) -> Result<bool, PackageError> {
        Ok(self
            .keys
            .lock()
            .map_err(|_| PackageError::Unavailable)?
            .get(manifest)
            .is_some_and(|entry| entry.pending.is_none()))
    }

    pub(super) fn lookup(&self, manifest: &Digest) -> Result<Zeroizing<[u8; 32]>, PackageError> {
        let keys = self.keys.lock().map_err(|_| PackageError::Unavailable)?;
        let entry = keys
            .get(manifest)
            .filter(|entry| entry.pending.is_none())
            .ok_or(PackageError::Denied)?;
        Ok(entry.key.clone())
    }
}

struct KeyEntry {
    key: Zeroizing<[u8; 32]>,
    pending: Option<Arc<()>>,
}

pub(crate) struct PendingKey<'a> {
    store: &'a ModuleKeyStore,
    manifest: Digest,
    identity: Option<Arc<()>>,
}

impl PendingKey<'_> {
    pub(crate) fn commit(mut self) -> Result<(), PackageError> {
        if let Some(identity) = self.identity.as_ref() {
            let mut keys = self
                .store
                .keys
                .lock()
                .map_err(|_| PackageError::Unavailable)?;
            if let Some(entry) = keys
                .get_mut(&self.manifest)
                .filter(|entry| owns_entry(entry, identity))
            {
                entry.pending = None;
            }
        }
        self.identity = None;
        Ok(())
    }
}

impl Drop for PendingKey<'_> {
    fn drop(&mut self) {
        if let (Some(identity), Ok(mut keys)) = (self.identity.take(), self.store.keys.lock()) {
            if Arc::strong_count(&identity) == 2
                && keys
                    .get(&self.manifest)
                    .is_some_and(|entry| owns_entry(entry, &identity))
            {
                keys.remove(&self.manifest);
            }
            drop(identity);
        }
    }
}

fn owns_entry(entry: &KeyEntry, identity: &Arc<()>) -> bool {
    entry
        .pending
        .as_ref()
        .is_some_and(|pending| Arc::ptr_eq(pending, identity))
}

fn copy_key(key: &PackageKey) -> Zeroizing<[u8; 32]> {
    let mut owned = Zeroizing::new([0; 32]);
    owned.copy_from_slice(key.as_secret());
    owned
}

pub(super) fn verify_key(
    frame: PackageFrame<'_>,
    manifest: &ModuleManifest,
    key: &PackageKey,
) -> Result<(), PackageError> {
    let descriptor = VmDescriptor::decode(frame.descriptor)?;
    let mut plaintext = Zeroizing::new(frame.ciphertext.to_vec());
    let cipher = ChaCha20Poly1305::new(key.as_secret().into());
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&manifest.nonce),
            &manifest.authentication_data()?,
            &mut plaintext,
            Tag::from_slice(&manifest.tag),
        )
        .map_err(|_| PackageError::Denied)?;
    if Sha256::digest(&plaintext[..]).as_slice() != descriptor.program_sha256 {
        return Err(PackageError::Denied);
    }
    Ok(())
}
