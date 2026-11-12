use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::canonical::{
    decode_extensions, encode_extensions, envelope, push_field, split_envelope, Reader, GRANT,
    HEADER_BYTES, MANIFEST, SIGNATURE_BYTES,
};
use crate::{
    Digest, Extension, Id, ProtocolError as Error, VmDescriptor, MAX_BODY_BYTES,
    MAX_GRANT_LIFETIME_MS, SESSION_CHALLENGE_EXTENSION,
};

type Result<T> = std::result::Result<T, Error>;

const MANIFEST_DOMAIN: &[u8] = b"vmkek.protocol.v1.module-signature\0";
const GRANT_DOMAIN: &[u8] = b"vmkek.protocol.v1.grant-signature\0";
const MODULE_AAD_DOMAIN: &[u8] = b"vmkek.protocol.v1.module-aad\0";
const MAX_PERMISSIONS: usize = 256;

#[must_use]
pub fn public_key_id(key: &VerifyingKey) -> Digest {
    Sha256::digest(key.to_encoded_point(false).as_bytes()).into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ModulePurpose {
    Payload = 1,
    Bytecode = 2,
    Dispatcher = 3,
}

impl TryFrom<u8> for ModulePurpose {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Payload),
            2 => Ok(Self::Bytecode),
            3 => Ok(Self::Dispatcher),
            _ => Err(Error::Invalid),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleManifest {
    pub descriptor_sha256: Digest,
    pub module_id: Id,
    pub module_version: u64,
    pub ciphertext_sha256: Digest,
    pub ciphertext_size: u32,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub signing_key_id: Digest,
    pub purpose: ModulePurpose,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub extensions: Vec<Extension>,
}

impl ModuleManifest {
    fn validate(&self) -> Result<()> {
        if self.ciphertext_size == 0 || self.ciphertext_size as usize > MAX_BODY_BYTES {
            return Err(Error::Limit);
        }
        if self.module_version == 0 || self.not_before_ms >= self.expires_at_ms {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// Canonical AEAD AAD. Hash and tag are produced by sealing and covered by the signature.
    pub fn authentication_data(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = MODULE_AAD_DOMAIN.to_vec();
        push_field(&mut out, &self.descriptor_sha256);
        push_field(&mut out, &self.module_id);
        push_field(&mut out, &self.module_version.to_le_bytes());
        push_field(&mut out, &self.ciphertext_size.to_le_bytes());
        push_field(&mut out, &self.nonce);
        self.encode_identity(&mut out);
        encode_extensions(&mut out, &self.extensions)?;
        Ok(out)
    }

    fn encode_identity(&self, out: &mut Vec<u8>) {
        push_field(out, &self.signing_key_id);
        push_field(out, &[self.purpose as u8]);
        push_field(out, &self.not_before_ms.to_le_bytes());
        push_field(out, &self.expires_at_ms.to_le_bytes());
    }
}

/// Caller-supplied identity for a module. The current time comes from its trust policy.
pub struct ModuleExpectation<'a> {
    pub descriptor: &'a VmDescriptor,
    pub module_id: Id,
    pub module_version: u64,
    pub purpose: ModulePurpose,
    pub now_ms: u64,
}

#[derive(Clone, Debug)]
pub struct SignedModuleManifest(Signed<ModuleManifest>);

impl SignedModuleManifest {
    pub fn sign(payload: ModuleManifest, key: &SigningKey) -> Result<Self> {
        Signed::sign(payload, key).map(Self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Signed::decode(bytes).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    pub fn verify_for(
        &self,
        pinned_key: &VerifyingKey,
        expected: &ModuleExpectation<'_>,
        ciphertext: &[u8],
    ) -> Result<&ModuleManifest> {
        let payload = self.0.verify(pinned_key)?;
        if payload.descriptor_sha256 != expected.descriptor.sha256()?
            || payload.module_id != expected.module_id
            || payload.module_version != expected.module_version
            || payload.purpose != expected.purpose
            || ciphertext.len() != payload.ciphertext_size as usize
            || Sha256::digest(ciphertext).as_slice() != payload.ciphertext_sha256
        {
            return Err(Error::Binding);
        }
        if !(payload.not_before_ms..payload.expires_at_ms).contains(&expected.now_ms) {
            return Err(Error::Expired);
        }
        Ok(payload)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantBinding {
    pub session_id: Id,
    pub device_id: Id,
    pub license_id: Id,
    pub app_id: Id,
    pub build_id: Id,
    pub generation_id: Id,
}

impl GrantBinding {
    pub(super) fn encode(self, out: &mut Vec<u8>) {
        for id in [
            self.session_id,
            self.device_id,
            self.license_id,
            self.app_id,
            self.build_id,
            self.generation_id,
        ] {
            push_field(out, &id);
        }
    }

    pub(super) fn decode(body: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            session_id: body.fixed()?,
            device_id: body.fixed()?,
            license_id: body.fixed()?,
            app_id: body.fixed()?,
            build_id: body.fixed()?,
            generation_id: body.fixed()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PermissionKind {
    Function = 1,
    Operation = 2,
}

impl TryFrom<u8> for PermissionKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Function),
            2 => Ok(Self::Operation),
            _ => Err(Error::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Permission {
    pub kind: PermissionKind,
    pub id: Id,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantPayload {
    pub binding: GrantBinding,
    pub policy_epoch: u64,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub lifetime_ms: u32,
    pub permissions: Vec<Permission>,
    pub signing_key_id: Digest,
    pub extensions: Vec<Extension>,
}

impl GrantPayload {
    fn expires_at_ms(&self) -> Result<u64> {
        if self.lifetime_ms == 0 || self.lifetime_ms > MAX_GRANT_LIFETIME_MS {
            return Err(Error::Limit);
        }
        self.issued_at_ms
            .checked_add(u64::from(self.lifetime_ms))
            .ok_or(Error::Invalid)
    }

    fn validate(&self) -> Result<()> {
        self.expires_at_ms()?;
        if self.permissions.len() > MAX_PERMISSIONS {
            return Err(Error::Limit);
        }
        if self.permissions.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Trusted context supplied by a grant consumer. Sequence persistence belongs to the caller.
pub struct GrantExpectation {
    pub binding: GrantBinding,
    pub policy_epoch: u64,
    pub minimum_sequence: u64,
    pub permission: Permission,
    pub now_ms: u64,
}

/// Exact exchange binding for a grant anchored by the caller's monotonic clock.
pub struct SessionGrantExpectation {
    pub binding: GrantBinding,
    pub policy_epoch: u64,
    pub sequence: u64,
    pub permission: Permission,
    pub challenge_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct SessionGrant(Signed<GrantPayload>);

impl SessionGrant {
    pub fn sign(payload: GrantPayload, key: &SigningKey) -> Result<Self> {
        Signed::sign(payload, key).map(Self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Signed::decode(bytes).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    pub fn verify_session(
        &self,
        pinned_key: &VerifyingKey,
        expected: &SessionGrantExpectation,
    ) -> Result<&GrantPayload> {
        let payload = self.0.verify(pinned_key)?;
        if payload.binding != expected.binding
            || payload.policy_epoch != expected.policy_epoch
            || payload.sequence != expected.sequence
            || payload.permissions.as_slice() != [expected.permission]
            || !payload.extensions.iter().any(|ext| {
                ext.id == SESSION_CHALLENGE_EXTENSION
                    && ext.bytes.as_slice() == expected.challenge_digest
            })
        {
            return Err(Error::Binding);
        }
        payload.expires_at_ms()?;
        Ok(payload)
    }

    pub fn verify_for(
        &self,
        pinned_key: &VerifyingKey,
        expected: &GrantExpectation,
    ) -> Result<&GrantPayload> {
        let payload = self.0.verify(pinned_key)?;
        if payload.binding != expected.binding
            || payload.policy_epoch != expected.policy_epoch
            || payload.sequence < expected.minimum_sequence
            || payload
                .permissions
                .binary_search(&expected.permission)
                .is_err()
        {
            return Err(Error::Binding);
        }
        if !(payload.issued_at_ms..payload.expires_at_ms()?).contains(&expected.now_ms) {
            return Err(Error::Expired);
        }
        Ok(payload)
    }
}

pub(super) trait Payload: Sized {
    const KIND: u16;
    const DOMAIN: &'static [u8];

    fn key_id(&self) -> &Digest;
    fn encode_body(&self) -> Result<Vec<u8>>;
    fn decode_body(body: &[u8]) -> Result<Self>;
}

#[derive(Clone, Debug)]
pub(super) struct Signed<T> {
    payload: T,
    bytes: Vec<u8>,
}

impl<T: Payload> Signed<T> {
    pub(super) fn sign(payload: T, key: &SigningKey) -> Result<Self> {
        if payload.key_id() != &public_key_id(key.verifying_key()) {
            return Err(Error::Signature);
        }
        let mut bytes = envelope(T::KIND, payload.encode_body()?, SIGNATURE_BYTES)?;
        let signature: Signature = key
            .sign_prehash(&signature_digest(T::DOMAIN, &bytes))
            .map_err(|_| Error::Signature)?;
        bytes.extend_from_slice(&signature.to_bytes());
        Ok(Self { payload, bytes })
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        let (signed, signature) = split_envelope(bytes, T::KIND, SIGNATURE_BYTES)?;
        Signature::from_slice(signature).map_err(|_| Error::Signature)?;
        let payload = T::decode_body(&signed[HEADER_BYTES..])?;
        Ok(Self {
            payload,
            bytes: bytes.to_vec(),
        })
    }

    pub(super) fn payload(&self) -> &T {
        &self.payload
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn verify(&self, key: &VerifyingKey) -> Result<&T> {
        if self.payload.key_id() != &public_key_id(key) {
            return Err(Error::Signature);
        }
        let (signed, raw_signature) = split_envelope(&self.bytes, T::KIND, SIGNATURE_BYTES)?;
        let signature = Signature::from_slice(raw_signature).map_err(|_| Error::Signature)?;
        key.verify_prehash(&signature_digest(T::DOMAIN, signed), &signature)
            .map_err(|_| Error::Signature)?;
        Ok(&self.payload)
    }
}

fn signature_digest(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    digest.finalize().into()
}

impl Payload for ModuleManifest {
    const KIND: u16 = MANIFEST;
    const DOMAIN: &'static [u8] = MANIFEST_DOMAIN;

    fn key_id(&self) -> &Digest {
        &self.signing_key_id
    }

    fn encode_body(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_field(&mut out, &self.descriptor_sha256);
        push_field(&mut out, &self.module_id);
        push_field(&mut out, &self.module_version.to_le_bytes());
        push_field(&mut out, &self.ciphertext_sha256);
        push_field(&mut out, &self.ciphertext_size.to_le_bytes());
        push_field(&mut out, &self.nonce);
        push_field(&mut out, &self.tag);
        self.encode_identity(&mut out);
        encode_extensions(&mut out, &self.extensions)?;
        Ok(out)
    }

    fn decode_body(body: &[u8]) -> Result<Self> {
        let mut body = Reader::new(body);
        let payload = Self {
            descriptor_sha256: body.fixed()?,
            module_id: body.fixed()?,
            module_version: body.field_u64()?,
            ciphertext_sha256: body.fixed()?,
            ciphertext_size: body.field_u32()?,
            nonce: body.fixed()?,
            tag: body.fixed()?,
            signing_key_id: body.fixed()?,
            purpose: ModulePurpose::try_from(body.field_u8()?)?,
            not_before_ms: body.field_u64()?,
            expires_at_ms: body.field_u64()?,
            extensions: decode_extensions(&mut body)?,
        };
        body.finish()?;
        payload.validate()?;
        Ok(payload)
    }
}

impl Payload for GrantPayload {
    const KIND: u16 = GRANT;
    const DOMAIN: &'static [u8] = GRANT_DOMAIN;

    fn key_id(&self) -> &Digest {
        &self.signing_key_id
    }

    fn encode_body(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        self.binding.encode(&mut out);
        push_field(&mut out, &self.policy_epoch.to_le_bytes());
        push_field(&mut out, &self.sequence.to_le_bytes());
        push_field(&mut out, &self.issued_at_ms.to_le_bytes());
        push_field(&mut out, &self.lifetime_ms.to_le_bytes());
        encode_permissions(&mut out, &self.permissions);
        push_field(&mut out, &self.signing_key_id);
        encode_extensions(&mut out, &self.extensions)?;
        Ok(out)
    }

    fn decode_body(body: &[u8]) -> Result<Self> {
        let mut body = Reader::new(body);
        let payload = Self {
            binding: GrantBinding::decode(&mut body)?,
            policy_epoch: body.field_u64()?,
            sequence: body.field_u64()?,
            issued_at_ms: body.field_u64()?,
            lifetime_ms: body.field_u32()?,
            permissions: decode_permissions(&mut body)?,
            signing_key_id: body.fixed()?,
            extensions: decode_extensions(&mut body)?,
        };
        body.finish()?;
        payload.validate()?;
        Ok(payload)
    }
}

fn encode_permissions(out: &mut Vec<u8>, permissions: &[Permission]) {
    let mut value = Vec::with_capacity(2 + permissions.len() * 17);
    value.extend_from_slice(&(permissions.len() as u16).to_le_bytes());
    for permission in permissions {
        value.push(permission.kind as u8);
        value.extend_from_slice(&permission.id);
    }
    push_field(out, &value);
}

fn decode_permissions(body: &mut Reader<'_>) -> Result<Vec<Permission>> {
    let mut value = Reader::new(body.field(2 + MAX_PERMISSIONS * 17)?);
    let count = value.u16()? as usize;
    if count > MAX_PERMISSIONS {
        return Err(Error::Limit);
    }
    let mut permissions = Vec::with_capacity(count);
    for _ in 0..count {
        permissions.push(Permission {
            kind: PermissionKind::try_from(value.u8()?)?,
            id: value.array()?,
        });
    }
    value.finish()?;
    Ok(permissions)
}
