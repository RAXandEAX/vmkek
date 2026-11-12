//! Build-plane sealing for verified, named Online stack bytecode.

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use p256::ecdsa::SigningKey;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use vmkek_protocol::{
    public_key_id, Digest, Id, ModuleManifest, ModulePurpose, PackageFrame, Profile, ProtocolError,
    SignedModuleManifest, VerifiedProgram, VmDescriptor, VmForm, COPY_INPUT_CAPABILITY,
    MAX_BODY_BYTES, SCHEMA_VERSION,
};
use zeroize::Zeroizing;

const KEY_DOMAIN: &[u8] = b"vmkek.packager.v1.online-bytecode-key\0";
const MAX_NAME: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PackagerError {
    #[error("invalid named build input")]
    Name,
    #[error("unsupported package bytecode or descriptor")]
    Incompatible,
    #[error("invalid package bytecode")]
    Bytecode,
    #[error("invalid package size")]
    Limit,
    #[error("operating-system entropy unavailable")]
    Entropy,
    #[error("package cryptography failed")]
    Crypto,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

/// A validated reference to a named build input. Borrowing keeps the checked bytes
/// and descriptor immutable between verification and sealing.
pub struct VerifiedInput<'a> {
    descriptor: &'a VmDescriptor,
    bytecode: &'a [u8],
}

impl<'a> VerifiedInput<'a> {
    pub fn verify(
        name: &str,
        descriptor: &'a VmDescriptor,
        bytecode: &'a [u8],
    ) -> Result<Self, PackagerError> {
        Self::verify_for(name, descriptor, bytecode, false)
    }

    /// Admit the reviewed R13 Stack or Register v1/depth-2 representations.
    pub fn verify_negotiated(
        name: &str,
        descriptor: &'a VmDescriptor,
        bytecode: &'a [u8],
    ) -> Result<Self, PackagerError> {
        Self::verify_for(name, descriptor, bytecode, true)
    }

    fn verify_for(
        name: &str,
        descriptor: &'a VmDescriptor,
        bytecode: &'a [u8],
        negotiated: bool,
    ) -> Result<Self, PackagerError> {
        if name.is_empty()
            || name.len() > MAX_NAME
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(PackagerError::Name);
        }
        if bytecode.len() > MAX_BODY_BYTES {
            return Err(PackagerError::Limit);
        }
        descriptor.encode()?;
        if descriptor.profile != Profile::Online
            || (descriptor.form != VmForm::Stack
                && (!negotiated || descriptor.form != VmForm::Register))
            || descriptor.depth != 2
            || !bytecode.starts_with(&SCHEMA_VERSION.to_le_bytes())
            || descriptor
                .capabilities
                .iter()
                .any(|capability| capability.id != COPY_INPUT_CAPABILITY)
        {
            return Err(PackagerError::Incompatible);
        }
        // The v1 stack verifier is exposed through Lab. Only the verification
        // copy uses that profile; package identity and AAD retain Online.
        let mut verification = descriptor.clone();
        verification.profile = Profile::Lab;
        VerifiedProgram::verify(&verification, bytecode).map_err(|_| PackagerError::Bytecode)?;
        Ok(Self {
            descriptor,
            bytecode,
        })
    }
}

#[derive(Clone, Copy)]
pub struct Release {
    pub module_id: Id,
    pub module_version: u64,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
}

/// Explicit build-plane handoff. This type has no Debug or serialization API.
pub struct PackageKey(Zeroizing<[u8; 32]>);

impl PackageKey {
    /// The one artifact key for a trusted build-plane key recipient.
    pub fn as_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct SealedRelease {
    pub package: SealedPackage,
    pub key: PackageKey,
}

/// Opaque output of verified sealing. Release publication must still check
/// the canonical signature, configured trust, scope and revocation.
pub struct SealedPackage {
    descriptor: Vec<u8>,
    manifest: SignedModuleManifest,
    ciphertext: Vec<u8>,
    report: PublicReport,
}

impl SealedPackage {
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor
    }

    pub fn manifest_bytes(&self) -> &[u8] {
        self.manifest.as_bytes()
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn public_report(&self) -> &PublicReport {
        &self.report
    }
}

/// Allowlisted release metadata suitable for public evidence.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicReport {
    pub schema_version: u16,
    pub profile: Profile,
    pub app_id: Id,
    pub build_id: Id,
    pub function_id: Id,
    pub generation_id: Id,
    pub module_id: Id,
    pub module_version: u64,
    pub signing_key_id: Digest,
    pub descriptor_sha256: Digest,
    pub manifest_sha256: Digest,
    pub ciphertext_sha256: Digest,
    pub ciphertext_size: u32,
}

pub fn seal(
    input: VerifiedInput<'_>,
    release: Release,
    signer: &SigningKey,
) -> Result<SealedRelease, PackagerError> {
    // Published release versions must fit PostgreSQL BIGINT.
    if i64::try_from(release.module_version).is_err() {
        return Err(ProtocolError::Invalid.into());
    }
    let mut seed = Zeroizing::new([0; 32]);
    let mut nonce = [0; 12];
    let mut rng = OsRng;
    rng.try_fill_bytes(seed.as_mut())
        .map_err(|_| PackagerError::Entropy)?;
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| PackagerError::Entropy)?;
    seal_with_entropy(input, release, signer, &seed, nonce)
}

fn seal_with_entropy(
    input: VerifiedInput<'_>,
    release: Release,
    signer: &SigningKey,
    seed: &[u8; 32],
    nonce: [u8; 12],
) -> Result<SealedRelease, PackagerError> {
    let descriptor = input.descriptor.encode()?;
    let mut manifest = ModuleManifest {
        descriptor_sha256: Sha256::digest(&descriptor).into(),
        module_id: release.module_id,
        module_version: release.module_version,
        ciphertext_sha256: [0; 32],
        ciphertext_size: u32::try_from(input.bytecode.len()).map_err(|_| PackagerError::Limit)?,
        nonce,
        tag: [0; 16],
        signing_key_id: public_key_id(signer.verifying_key()),
        purpose: ModulePurpose::Bytecode,
        not_before_ms: release.not_before_ms,
        expires_at_ms: release.expires_at_ms,
        extensions: Vec::new(),
    };
    let aad = manifest.authentication_data()?;
    let key = derive_key(seed, &aad)?;
    let mut ciphertext = Zeroizing::new(input.bytecode.to_vec());
    let cipher = ChaCha20Poly1305::new(key.as_secret().into());
    manifest.tag = cipher
        .encrypt_in_place_detached((&nonce).into(), &aad, &mut ciphertext)
        .map_err(|_| PackagerError::Crypto)?
        .into();
    manifest.ciphertext_sha256 = Sha256::digest(ciphertext.as_slice()).into();
    let signed = SignedModuleManifest::sign(manifest.clone(), signer)?;
    PackageFrame {
        descriptor: &descriptor,
        manifest: signed.as_bytes(),
        ciphertext: &ciphertext,
    }
    .encoded_len()?;
    let report = report(input, &manifest, &signed);
    Ok(SealedRelease {
        package: SealedPackage {
            descriptor,
            manifest: signed,
            ciphertext: std::mem::take(&mut *ciphertext),
            report,
        },
        key,
    })
}

fn derive_key(seed: &[u8; 32], aad: &[u8]) -> Result<PackageKey, PackagerError> {
    // A fresh CSPRNG seed for each seal. AAD binds the descriptor (including
    // app/build/function/generation/depth), purpose, release and fresh nonce.
    let kdf = Hkdf::<Sha256>::new(Some(KEY_DOMAIN), seed);
    let mut key = Zeroizing::new([0; 32]);
    kdf.expand(aad, key.as_mut())
        .map_err(|_| PackagerError::Crypto)?;
    Ok(PackageKey(key))
}

fn report(
    input: VerifiedInput<'_>,
    manifest: &ModuleManifest,
    signed: &SignedModuleManifest,
) -> PublicReport {
    PublicReport {
        schema_version: SCHEMA_VERSION,
        profile: input.descriptor.profile,
        app_id: input.descriptor.app_id,
        build_id: input.descriptor.build_id,
        function_id: input.descriptor.function_id,
        generation_id: input.descriptor.generation_id,
        module_id: manifest.module_id,
        module_version: manifest.module_version,
        signing_key_id: manifest.signing_key_id,
        descriptor_sha256: manifest.descriptor_sha256,
        manifest_sha256: Sha256::digest(signed.as_bytes()).into(),
        ciphertext_sha256: manifest.ciphertext_sha256,
        ciphertext_size: manifest.ciphertext_size,
    }
}

#[cfg(test)]
mod tests;
