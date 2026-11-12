use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use tokio::time::Instant;
use vmkek_protocol::{
    decode_module_key, Digest, GrantBinding, Id, ModuleFetch, ModuleOpen, ModulePurpose,
    PackageFrame, PermissionKind, MAX_DEADLINE_MS,
};
use zeroize::Zeroizing;

use crate::{ClientError, DeviceSigner, Lease, SessionClient};

#[derive(Clone, Copy)]
pub struct ModuleSelection {
    pub module_id: Id,
    pub module_version: u64,
    pub manifest_sha256: Digest,
}

/// Snapshot of the exact signed authority for one admitted call.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LeaseToken {
    binding: GrantBinding,
    sequence: u64,
    expires: std::time::Instant,
}

impl LeaseToken {
    pub(crate) fn binding(self) -> GrantBinding {
        self.binding
    }

    pub(crate) fn sequence(self) -> u64 {
        self.sequence
    }

    pub fn expires(self) -> std::time::Instant {
        self.expires
    }
}

/// Authenticated ciphertext transport. Ownership does not include a key.
pub struct ModuleCiphertext(Bytes);

impl ModuleCiphertext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One package and its authorized artifact key. The key has no Debug implementation.
pub struct OpenedModule {
    frame: Bytes,
    key: Zeroizing<[u8; 32]>,
    deadline: std::time::Instant,
}

impl OpenedModule {
    pub fn frame_bytes(&self) -> &[u8] {
        &self.frame
    }
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    pub fn lease_deadline(&self) -> std::time::Instant {
        self.deadline
    }
    pub fn into_ciphertext(self) -> ModuleCiphertext {
        ModuleCiphertext(self.frame)
    }
}

impl<S: DeviceSigner> SessionClient<S> {
    pub fn lease_deadline(&self) -> Option<std::time::Instant> {
        self.active
            .as_ref()
            .filter(|lease| Instant::now() < lease.expires)
            .map(|lease| lease.expires.into_std())
    }

    pub fn lease_token(&self) -> Option<LeaseToken> {
        self.active
            .as_ref()
            .filter(|lease| Instant::now() < lease.expires)
            .map(|lease| LeaseToken {
                binding: lease.grant.binding,
                sequence: lease.grant.sequence,
                expires: lease.expires.into_std(),
            })
    }

    /// Request one key for the exact still-current grant and cached module.
    /// The caller owns cancellation and handles a real transport failure.
    pub async fn request_artifact_key(
        &self,
        token: LeaseToken,
        selection: ModuleSelection,
        call_deadline: std::time::Instant,
        network_deadline: std::time::Instant,
        attempted: &AtomicBool,
    ) -> Result<Zeroizing<[u8; 32]>, ClientError> {
        if self.lease_token() != Some(token) {
            return Err(ClientError::Expired);
        }
        let cutoff = call_deadline.min(token.expires).min(network_deadline);
        let deadline = Instant::from_std(cutoff);
        let fetch = self.module_request(token.binding, token.sequence, selection)?;
        if Instant::now() >= deadline {
            return Err(ClientError::Expired);
        }
        let timeout = if cutoff == network_deadline && cutoff < token.expires {
            ClientError::Timeout
        } else {
            ClientError::Expired
        };
        attempted.store(true, Ordering::Release);
        let key = tokio::time::timeout_at(deadline, self.exchange_key(fetch, selection))
            .await
            .map_err(|_| timeout)??;
        if Instant::now() >= deadline {
            return Err(timeout);
        }
        Ok(key)
    }

    /// Open the selected ciphertext and one artifact key under the current grant.
    /// The caller still verifies the signed manifest, decrypts and checks its bytecode.
    pub async fn open_module(
        &mut self,
        selection: ModuleSelection,
    ) -> Result<OpenedModule, ClientError> {
        let lease = self.active.take().ok_or(ClientError::NoSession)?;
        let now = Instant::now();
        if now >= lease.expires {
            return Err(ClientError::Expired);
        }
        let deadline = lease
            .expires
            .min(now + Duration::from_millis(MAX_DEADLINE_MS.into()));
        let result = tokio::time::timeout_at(deadline, self.exchange_module(&lease, selection))
            .await
            .map_err(|_| ClientError::Timeout)??;
        if Instant::now() >= deadline {
            return Err(ClientError::Expired);
        }
        self.active = Some(lease);
        Ok(result)
    }

    async fn exchange_module(
        &self,
        lease: &Lease,
        selection: ModuleSelection,
    ) -> Result<OpenedModule, ClientError> {
        let fetch = self.module_request(lease.grant.binding, lease.grant.sequence, selection)?;
        let body = self.signed(fetch.encode(), fetch.signature_digest())?;
        let frame = self.endpoint.post("/v1/module/fetch", body).await?;
        let parsed = PackageFrame::decode(&frame).map_err(|_| ClientError::InvalidResponse)?;
        if Sha256::digest(parsed.manifest).as_slice() != selection.manifest_sha256 {
            return Err(ClientError::Verification);
        }

        let key = self
            .exchange_key(
                ModuleFetch {
                    request_id: request_id()?,
                    ..fetch
                },
                selection,
            )
            .await?;
        Ok(OpenedModule {
            frame,
            key,
            deadline: lease.expires.into_std(),
        })
    }

    fn module_request(
        &self,
        binding: GrantBinding,
        sequence: u64,
        selection: ModuleSelection,
    ) -> Result<ModuleFetch, ClientError> {
        let permission = self.identity.permission;
        if permission.kind != PermissionKind::Function {
            return Err(ClientError::Denied);
        }
        Ok(ModuleFetch {
            app_id: binding.app_id,
            build_id: binding.build_id,
            device_id: binding.device_id,
            session_id: binding.session_id,
            generation_id: binding.generation_id,
            function_id: permission.id,
            module_id: selection.module_id,
            module_version: selection.module_version,
            purpose: ModulePurpose::Bytecode,
            sequence,
            request_id: request_id()?,
        })
    }

    async fn exchange_key(
        &self,
        fetch: ModuleFetch,
        selection: ModuleSelection,
    ) -> Result<Zeroizing<[u8; 32]>, ClientError> {
        let open = ModuleOpen {
            fetch,
            manifest_sha256: selection.manifest_sha256,
        };
        let body = self.signed(open.encode(), open.signature_digest())?;
        let response = self.endpoint.post_secret("/v1/module/open", body).await?;
        let digest = open.digest().map_err(|_| ClientError::Verification)?;
        decode_module_key(response.as_ref(), &digest, &selection.manifest_sha256)
            .map_err(|_| ClientError::Verification)
    }
}

pub(crate) fn request_id() -> Result<Id, ClientError> {
    let mut id = [0; 16];
    OsRng
        .try_fill_bytes(&mut id)
        .map_err(|_| ClientError::Entropy)?;
    Ok(id)
}
