use crate::{
    canonical::{envelope, push_field, split_envelope, Reader, HEADER_BYTES, SIGNATURE_BYTES},
    Digest, Id, ProtocolError as Error,
};
use p256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest as _, Sha256};

const INTENT: u16 = 6;
const CHALLENGE: u16 = 7;
pub const SESSION_INTENT_BYTES: usize = 145;
pub const SESSION_CHALLENGE_BYTES: usize = 120;
pub const SESSION_PROOF_BYTES: usize = SIGNATURE_BYTES;
pub const SESSION_CHALLENGE_EXTENSION: u16 = 1;
pub const SESSION_HEARTBEAT_MS: u32 = 10_000;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionOperation {
    Open = 1,
    Renew = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionIntent {
    pub operation: SessionOperation,
    pub app_id: Id,
    pub build_id: Id,
    pub device_id: Id,
    pub generation_id: Id,
    pub session_id: Id,
    pub sequence: u64,
    pub request_id: Id,
}

impl SessionIntent {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut body = Vec::with_capacity(SESSION_INTENT_BYTES - HEADER_BYTES);
        push_field(&mut body, &[self.operation as u8]);
        for id in [
            self.app_id,
            self.build_id,
            self.device_id,
            self.generation_id,
            self.session_id,
        ] {
            push_field(&mut body, &id);
        }
        push_field(&mut body, &self.sequence.to_le_bytes());
        push_field(&mut body, &self.request_id);
        envelope(INTENT, body, 0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (encoded, _) = split_envelope(bytes, INTENT, 0)?;
        let mut input = Reader::new(&encoded[HEADER_BYTES..]);
        let intent = Self {
            operation: match input.field_u8()? {
                1 => SessionOperation::Open,
                2 => SessionOperation::Renew,
                _ => return Err(Error::Invalid),
            },
            app_id: input.fixed()?,
            build_id: input.fixed()?,
            device_id: input.fixed()?,
            generation_id: input.fixed()?,
            session_id: input.fixed()?,
            sequence: input.field_u64()?,
            request_id: input.fixed()?,
        };
        input.finish()?;
        intent.validate()?;
        Ok(intent)
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    pub fn signature_digest(&self) -> Result<Digest> {
        Ok(prehash(
            b"vmkek.protocol.v1.session-intent\0",
            &self.encode()?,
        ))
    }

    pub fn sign(&self, key: &SigningKey) -> Result<[u8; SIGNATURE_BYTES]> {
        sign(key, &self.signature_digest()?)
    }

    pub fn verify(&self, key: &VerifyingKey, proof: &[u8; SIGNATURE_BYTES]) -> Result<()> {
        verify(key, &self.signature_digest()?, proof)
    }

    fn validate(&self) -> Result<()> {
        let initial = self.session_id == [0; 16];
        match self.operation {
            SessionOperation::Open if initial && self.sequence == 1 => Ok(()),
            SessionOperation::Renew
                if !initial && (2..=i64::MAX as u64).contains(&self.sequence) =>
            {
                Ok(())
            }
            _ => Err(Error::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionChallenge {
    pub intent_digest: Digest,
    pub session_id: Id,
    pub challenge_id: Id,
    pub nonce: Digest,
}

impl SessionChallenge {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(SESSION_CHALLENGE_BYTES - HEADER_BYTES);
        push_field(&mut body, &self.intent_digest);
        push_field(&mut body, &self.session_id);
        push_field(&mut body, &self.challenge_id);
        push_field(&mut body, &self.nonce);
        envelope(CHALLENGE, body, 0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (encoded, _) = split_envelope(bytes, CHALLENGE, 0)?;
        let mut input = Reader::new(&encoded[HEADER_BYTES..]);
        let challenge = Self {
            intent_digest: input.fixed()?,
            session_id: input.fixed()?,
            challenge_id: input.fixed()?,
            nonce: input.fixed()?,
        };
        input.finish()?;
        Ok(challenge)
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    pub fn signature_digest(&self) -> Result<Digest> {
        Ok(prehash(
            b"vmkek.protocol.v1.session-challenge\0",
            &self.encode()?,
        ))
    }

    pub fn sign(&self, key: &SigningKey) -> Result<[u8; SIGNATURE_BYTES]> {
        sign(key, &self.signature_digest()?)
    }

    pub fn verify(&self, key: &VerifyingKey, proof: &[u8; SIGNATURE_BYTES]) -> Result<()> {
        verify(key, &self.signature_digest()?, proof)
    }
}

pub(super) fn prehash(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

pub(super) fn sign(key: &SigningKey, digest: &Digest) -> Result<[u8; SIGNATURE_BYTES]> {
    let signature: Signature = key.sign_prehash(digest).map_err(|_| Error::Signature)?;
    Ok(signature.to_bytes().into())
}

pub(super) fn verify(
    key: &VerifyingKey,
    digest: &Digest,
    proof: &[u8; SIGNATURE_BYTES],
) -> Result<()> {
    let signature = Signature::from_slice(proof).map_err(|_| Error::Signature)?;
    key.verify_prehash(digest, &signature)
        .map_err(|_| Error::Signature)
}
