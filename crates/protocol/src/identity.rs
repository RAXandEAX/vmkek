use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::canonical::{envelope, push_field, split_envelope, Reader, HEADER_BYTES};
use crate::{public_key_id, Digest, Id, ProtocolError};

#[cfg(windows)]
pub(crate) mod windows_cng;

const ENROLLMENT: u16 = 5;
const DOMAIN: &[u8] = b"vmkek.protocol.v1.device-enrollment\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceTrust {
    Software = 1,
    TpmAttested = 2,
}

impl TryFrom<u8> for DeviceTrust {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Software),
            2 => Ok(Self::TpmAttested),
            _ => Err(ProtocolError::Invalid),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentChallenge {
    pub app_id: Id,
    pub license_id: Id,
    pub challenge_id: Id,
    pub nonce: Digest,
    pub key_id: Digest,
    pub trust: DeviceTrust,
    pub expires_unix_ms: u64,
}

impl EnrollmentChallenge {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut body = Vec::with_capacity(149);
        push_field(&mut body, &self.app_id);
        push_field(&mut body, &self.license_id);
        push_field(&mut body, &self.challenge_id);
        push_field(&mut body, &self.nonce);
        push_field(&mut body, &self.key_id);
        push_field(&mut body, &[self.trust as u8]);
        push_field(&mut body, &self.expires_unix_ms.to_le_bytes());
        envelope(ENROLLMENT, body, 0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (canonical, _) = split_envelope(bytes, ENROLLMENT, 0)?;
        let mut input = Reader::new(&canonical[HEADER_BYTES..]);
        let value = Self {
            app_id: input.fixed()?,
            license_id: input.fixed()?,
            challenge_id: input.fixed()?,
            nonce: input.fixed()?,
            key_id: input.fixed()?,
            trust: input.field_u8()?.try_into()?,
            expires_unix_ms: input.field_u64()?,
        };
        input.finish()?;
        Ok(value)
    }

    /// SHA-256 prehash for fixed-width P-256 ECDSA signatures.
    pub fn signature_digest(&self) -> Result<Digest, ProtocolError> {
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(self.encode()?);
        Ok(digest.finalize().into())
    }

    pub fn verify_proof(&self, sec1: &[u8; 65], proof: &[u8; 64]) -> Result<(), ProtocolError> {
        let key = VerifyingKey::from_sec1_bytes(sec1).map_err(|_| ProtocolError::Invalid)?;
        if public_key_id(&key) != self.key_id {
            return Err(ProtocolError::Binding);
        }
        let signature = Signature::from_slice(proof).map_err(|_| ProtocolError::Signature)?;
        key.verify_prehash(&self.signature_digest()?, &signature)
            .map_err(|_| ProtocolError::Signature)
    }
}
