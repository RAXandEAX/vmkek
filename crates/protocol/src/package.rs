use p256::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{
    canonical::{envelope, envelope_prefix, push_field, split_envelope, Reader, HEADER_BYTES},
    session::{prehash, sign, verify},
    Digest, Id, ModulePurpose, ProtocolError as Error, MAX_BODY_BYTES, SESSION_PROOF_BYTES,
};

const FETCH: u16 = 9;
const PACKAGE: u16 = 10;
pub const MODULE_FETCH_BYTES: usize = 197;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleFetch {
    pub app_id: Id,
    pub build_id: Id,
    pub device_id: Id,
    pub session_id: Id,
    pub generation_id: Id,
    pub function_id: Id,
    pub module_id: Id,
    pub module_version: u64,
    pub purpose: ModulePurpose,
    pub sequence: u64,
    pub request_id: Id,
}

impl ModuleFetch {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(MODULE_FETCH_BYTES - HEADER_BYTES);
        for id in [
            self.app_id,
            self.build_id,
            self.device_id,
            self.session_id,
            self.generation_id,
            self.function_id,
            self.module_id,
        ] {
            push_field(&mut bytes, &id);
        }
        push_field(&mut bytes, &self.module_version.to_le_bytes());
        push_field(&mut bytes, &[self.purpose as u8]);
        push_field(&mut bytes, &self.sequence.to_le_bytes());
        push_field(&mut bytes, &self.request_id);
        envelope(FETCH, bytes, 0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (encoded, _) = split_envelope(bytes, FETCH, 0)?;
        let mut input = Reader::new(&encoded[HEADER_BYTES..]);
        let fetch = Self {
            app_id: input.fixed()?,
            build_id: input.fixed()?,
            device_id: input.fixed()?,
            session_id: input.fixed()?,
            generation_id: input.fixed()?,
            function_id: input.fixed()?,
            module_id: input.fixed()?,
            module_version: input.field_u64()?,
            purpose: input.field_u8()?.try_into()?,
            sequence: input.field_u64()?,
            request_id: input.fixed()?,
        };
        input.finish()?;
        fetch.validate()?;
        Ok(fetch)
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    pub fn signature_digest(&self) -> Result<Digest> {
        Ok(prehash(
            b"vmkek.protocol.v1.module-fetch\0",
            &self.encode()?,
        ))
    }

    pub fn sign(&self, key: &SigningKey) -> Result<[u8; SESSION_PROOF_BYTES]> {
        sign(key, &self.signature_digest()?)
    }

    pub fn verify(&self, key: &VerifyingKey, proof: &[u8; SESSION_PROOF_BYTES]) -> Result<()> {
        verify(key, &self.signature_digest()?, proof)
    }

    fn validate(&self) -> Result<()> {
        if self.session_id == [0; 16]
            || !(1..=i64::MAX as u64).contains(&self.sequence)
            || !(1..=i64::MAX as u64).contains(&self.module_version)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Borrowed package framing. Its manifest and descriptor must be verified before use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageFrame<'a> {
    pub descriptor: &'a [u8],
    pub manifest: &'a [u8],
    pub ciphertext: &'a [u8],
}

impl<'a> PackageFrame<'a> {
    pub fn encoded_len(&self) -> Result<usize> {
        [self.descriptor, self.manifest, self.ciphertext]
            .into_iter()
            .try_fold(HEADER_BYTES + 12, |size, field| {
                if field.is_empty() {
                    return Err(Error::Invalid);
                }
                size.checked_add(field.len())
                    .filter(|total| *total <= MAX_BODY_BYTES)
                    .ok_or(Error::Limit)
            })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = envelope_prefix(PACKAGE, self.encoded_len()? - HEADER_BYTES, 0)?;
        for field in [self.descriptor, self.manifest, self.ciphertext] {
            push_field(&mut bytes, field);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        let (encoded, _) = split_envelope(bytes, PACKAGE, 0)?;
        let mut input = Reader::new(&encoded[HEADER_BYTES..]);
        let frame = Self {
            descriptor: input.field(MAX_BODY_BYTES)?,
            manifest: input.field(MAX_BODY_BYTES)?,
            ciphertext: input.field(MAX_BODY_BYTES)?,
        };
        input.finish()?;
        if frame.descriptor.is_empty() || frame.manifest.is_empty() || frame.ciphertext.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(frame)
    }
}
