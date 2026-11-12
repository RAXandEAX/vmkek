use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::zeroize::Zeroizing;

use crate::crypto::{sha256, AEAD_KEY_LEN, AEAD_NONCE_LEN};
use crate::error::{msg, Error, Result};

use super::{os_random, BlockPurpose, BlockScope, ScopeSecret};

mod wire;
use wire::signature_transcript;
pub use wire::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Platform {
    Pe32Plus = 1,
    Elf64 = BOOTSTRAP_PLATFORM_ELF64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Profile {
    Lab = BOOTSTRAP_PROFILE_LAB,
    Online = 2,
}

/// Expected bootstrap metadata obtained from trusted configuration, independent of the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapContext {
    pub platform: Platform,
    pub profile: Profile,
    pub scope: BlockScope,
    /// Payload RVA for PE or file offset for ELF.
    pub payload_offset: u64,
    pub payload_len: u32,
    pub original_entry_rva: u32,
    pub preferred_base: u64,
}

impl BootstrapContext {
    fn validate(&self, scope: BlockScope, actual_len: usize) -> Result<()> {
        if self.scope.purpose != BlockPurpose::Payload {
            return Err(msg("authenticated bootstrap requires payload purpose"));
        }
        if self.scope != scope {
            return Err(msg("authenticated bootstrap scope mismatch"));
        }
        let end = self.payload_offset.checked_add(u64::from(self.payload_len));
        if actual_len == 0
            || actual_len > BOOTSTRAP_MAX_PAYLOAD
            || self.payload_len as usize != actual_len
            || end.is_none()
            || (self.platform == Platform::Pe32Plus && end > Some(u64::from(u32::MAX) + 1))
        {
            return Err(msg("invalid authenticated bootstrap payload extent"));
        }
        Ok(())
    }

    fn core(&self, pin: &ManufacturerPin, block: &BlockCoordinate) -> [u8; BOOTSTRAP_CORE_LEN] {
        let mut core = [0; BOOTSTRAP_CORE_LEN];
        core[..16].copy_from_slice(BOOTSTRAP_MAGIC);
        core[16..18].copy_from_slice(&BOOTSTRAP_VERSION.to_le_bytes());
        core[18..20].copy_from_slice(&BOOTSTRAP_TYPE.to_le_bytes());
        core[20..22].copy_from_slice(&(BOOTSTRAP_CORE_LEN as u16).to_le_bytes());
        core[22] = self.platform as u8;
        core[23] = self.profile as u8;
        core[24..90].copy_from_slice(&self.scope.bytes());
        core[90..98].copy_from_slice(&self.payload_offset.to_le_bytes());
        core[98..102].copy_from_slice(&self.payload_len.to_le_bytes());
        core[102..106].copy_from_slice(&self.payload_len.to_le_bytes());
        core[106..110].copy_from_slice(&self.original_entry_rva.to_le_bytes());
        core[110..BOOTSTRAP_KEY_ID_OFFSET].copy_from_slice(&self.preferred_base.to_le_bytes());
        core[BOOTSTRAP_KEY_ID_OFFSET..BOOTSTRAP_SALT_OFFSET].copy_from_slice(&pin.id);
        core[BOOTSTRAP_SALT_OFFSET..BOOTSTRAP_SEQUENCE_OFFSET].copy_from_slice(&block.salt);
        core[BOOTSTRAP_SEQUENCE_OFFSET..BOOTSTRAP_NONCE_OFFSET]
            .copy_from_slice(&block.sequence.to_le_bytes());
        core[BOOTSTRAP_NONCE_OFFSET..].copy_from_slice(&block.nonce());
        core
    }
}

/// Manufacturer public key obtained from trusted provisioning, never from the package.
pub struct ManufacturerPin {
    key: VerifyingKey,
    id: [u8; 32],
}

impl ManufacturerPin {
    /// Pin the exact SEC1 uncompressed P-256 point.
    pub fn from_sec1(public: &[u8; 65]) -> Result<Self> {
        if public[0] != 4 {
            return Err(msg("manufacturer pin must be an uncompressed P-256 point"));
        }
        let key =
            VerifyingKey::from_sec1_bytes(public).map_err(|_| msg("invalid manufacturer pin"))?;
        Ok(Self {
            key,
            id: sha256(public),
        })
    }

    /// SHA-256 key ID bound into the authenticated manifest.
    #[must_use]
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }
}

struct BlockCoordinate {
    salt: [u8; 32],
    sequence: u64,
}

impl BlockCoordinate {
    fn nonce(&self) -> [u8; AEAD_NONCE_LEN] {
        let mut nonce = [0; AEAD_NONCE_LEN];
        nonce[4..].copy_from_slice(&self.sequence.to_le_bytes());
        nonce
    }

    fn from_manifest(manifest: &[u8; BOOTSTRAP_MANIFEST_LEN]) -> Result<Self> {
        let salt =
            crate::error::exact_bytes(&manifest[BOOTSTRAP_SALT_OFFSET..BOOTSTRAP_SEQUENCE_OFFSET])?;
        let sequence = u64::from_le_bytes(crate::error::exact_bytes(
            &manifest[BOOTSTRAP_SEQUENCE_OFFSET..BOOTSTRAP_NONCE_OFFSET],
        )?);
        Ok(Self { salt, sequence })
    }
}

/// Authenticated format v2. The manifest contains no signing or encryption secret.
pub struct SealedBootstrap {
    pub manifest: [u8; BOOTSTRAP_MANIFEST_LEN],
    pub ciphertext: Vec<u8>,
}

/// Per-artifact key that the PE lab loader can embed. The key is extractable
/// from that executable. It carries no authority to derive other keys.
pub struct LabBootstrapKey(Zeroizing<[u8; AEAD_KEY_LEN]>);

impl LabBootstrapKey {
    /// Bytes for the lab loader plan. Keep them outside reports and manifests.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; AEAD_KEY_LEN] {
        &self.0
    }
}

/// Build-only sealing state. Every call draws a new 256-bit block-key salt from the OS.
pub struct BootstrapSealer<'a> {
    scope: &'a ScopeSecret,
    sequence: u64,
}

impl<'a> BootstrapSealer<'a> {
    #[must_use]
    pub fn new(scope: &'a ScopeSecret) -> Self {
        Self { scope, sequence: 0 }
    }

    /// Sign with a separately loaded manufacturer key matching the independent pin.
    pub fn seal(
        &mut self,
        expected: &BootstrapContext,
        pin: &ManufacturerPin,
        signing: &SigningKey,
        plaintext: &[u8],
    ) -> Result<SealedBootstrap> {
        self.seal_with_key(expected, pin, signing, plaintext)
            .map(|(sealed, _)| sealed)
    }

    /// PE lab handoff. The encrypted bootstrap and its extractable artifact key
    /// are delivered separately so an online caller cannot request an embedded key.
    pub fn seal_for_native_lab(
        &mut self,
        expected: &BootstrapContext,
        pin: &ManufacturerPin,
        signing: &SigningKey,
        plaintext: &[u8],
    ) -> Result<(SealedBootstrap, LabBootstrapKey)> {
        if expected.platform != Platform::Pe32Plus || expected.profile != Profile::Lab {
            return Err(msg(
                "embedded bootstrap keys are restricted to the PE lab profile",
            ));
        }
        self.seal_with_key(expected, pin, signing, plaintext)
    }

    /// Seal for a native ELF lab only. The embedded block key is extractable.
    pub fn seal_for_elf_lab(
        &mut self,
        expected: &BootstrapContext,
        pin: &ManufacturerPin,
        signing: &SigningKey,
        plaintext: &[u8],
    ) -> Result<(SealedBootstrap, LabBootstrapKey)> {
        if expected.platform != Platform::Elf64 || expected.profile != Profile::Lab {
            return Err(msg(
                "ELF embedded bootstrap keys require the ELF lab profile",
            ));
        }
        self.seal_with_key(expected, pin, signing, plaintext)
    }

    fn seal_with_key(
        &mut self,
        expected: &BootstrapContext,
        pin: &ManufacturerPin,
        signing: &SigningKey,
        plaintext: &[u8],
    ) -> Result<(SealedBootstrap, LabBootstrapKey)> {
        expected.validate(self.scope.binding(), plaintext.len())?;
        if signing.verifying_key() != &pin.key {
            return Err(Error::BadSignature);
        }
        let sequence = self.sequence;
        self.sequence = sequence
            .checked_add(1)
            .ok_or_else(|| msg("authenticated bootstrap sequence exhausted"))?;
        let block = BlockCoordinate {
            salt: *os_random()?,
            sequence,
        };
        let key = self.scope.block_key(&block.salt, block.sequence)?;
        let sealed = seal_at(expected, pin, signing, plaintext, &block, &key)?;
        Ok((sealed, LabBootstrapKey(key)))
    }
}

fn seal_at(
    expected: &BootstrapContext,
    pin: &ManufacturerPin,
    signing: &SigningKey,
    plaintext: &[u8],
    block: &BlockCoordinate,
    key: &[u8; AEAD_KEY_LEN],
) -> Result<SealedBootstrap> {
    let core = expected.core(pin, block);
    let mut data = Zeroizing::new(plaintext.to_vec());
    let tag = cipher(key)?
        .encrypt_in_place_detached(&Nonce::from(block.nonce()), &core, &mut data)
        .map_err(|_| Error::Integrity)?;
    let ciphertext = std::mem::take(&mut *data);
    let manifest = sign_manifest(&core, &ciphertext, &tag, signing)?;
    Ok(SealedBootstrap {
        manifest,
        ciphertext,
    })
}

fn cipher(key: &[u8; AEAD_KEY_LEN]) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Integrity)
}

fn sign_manifest(
    core: &[u8; BOOTSTRAP_CORE_LEN],
    ciphertext: &[u8],
    tag: &Tag,
    signing: &SigningKey,
) -> Result<[u8; BOOTSTRAP_MANIFEST_LEN]> {
    let mut manifest = [0; BOOTSTRAP_MANIFEST_LEN];
    manifest[..BOOTSTRAP_CORE_LEN].copy_from_slice(core);
    manifest[BOOTSTRAP_HASH_OFFSET..BOOTSTRAP_TAG_OFFSET].copy_from_slice(&sha256(ciphertext));
    manifest[BOOTSTRAP_TAG_OFFSET..BOOTSTRAP_SIGNATURE_OFFSET].copy_from_slice(tag);
    let signature: Signature = signing
        .try_sign(&signature_transcript(&manifest))
        .map_err(|_| Error::BadSignature)?;
    manifest[BOOTSTRAP_SIGNATURE_OFFSET..].copy_from_slice(&signature.to_bytes());
    Ok(manifest)
}

/// Validate exact trusted metadata, signature, ciphertext digest, and AEAD tag before release.
pub fn open_bootstrap(
    scope: &ScopeSecret,
    expected: &BootstrapContext,
    pin: &ManufacturerPin,
    manifest: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    expected.validate(scope.binding(), ciphertext.len())?;
    let manifest: &[u8; BOOTSTRAP_MANIFEST_LEN] = manifest
        .try_into()
        .map_err(|_| msg("invalid authenticated bootstrap manifest length"))?;
    if &manifest[..16] != BOOTSTRAP_MAGIC
        || manifest[16..18] != BOOTSTRAP_VERSION.to_le_bytes()
        || manifest[18..20] != BOOTSTRAP_TYPE.to_le_bytes()
        || manifest[20..22] != (BOOTSTRAP_CORE_LEN as u16).to_le_bytes()
    {
        return Err(msg("unsupported authenticated bootstrap manifest format"));
    }
    let block = BlockCoordinate::from_manifest(manifest)?;
    let core = expected.core(pin, &block);
    if manifest[..BOOTSTRAP_CORE_LEN] != core {
        return Err(Error::Integrity);
    }
    let signature = Signature::from_slice(&manifest[BOOTSTRAP_SIGNATURE_OFFSET..])
        .map_err(|_| Error::BadSignature)?;
    pin.key
        .verify(&signature_transcript(manifest), &signature)
        .map_err(|_| Error::BadSignature)?;
    if manifest[BOOTSTRAP_HASH_OFFSET..BOOTSTRAP_TAG_OFFSET] != sha256(ciphertext) {
        return Err(Error::Integrity);
    }
    let mut data = Zeroizing::new(ciphertext.to_vec());
    let tag = Tag::from_slice(&manifest[BOOTSTRAP_TAG_OFFSET..BOOTSTRAP_SIGNATURE_OFFSET]);
    let key = scope.block_key(&block.salt, block.sequence)?;
    cipher(&key)?
        .decrypt_in_place_detached(&Nonce::from(block.nonce()), &core, &mut data, tag)
        .map_err(|_| Error::Integrity)?;
    Ok(data)
}

#[cfg(test)]
mod tests;
