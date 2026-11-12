use p256::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{
    canonical::{push_field, Reader},
    signed::{Payload, Signed},
    Digest, Id, ProtocolError as Error,
};

const KIND: u16 = 20;
pub const RECOVERY_SNAPSHOT_VERSION: u16 = 1;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryScope {
    pub deployment_id: Id,
    pub app_id: Id,
    pub build_id: Id,
    pub history_id: Id,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryCheckpoint {
    pub scope: RecoveryScope,
    pub fence_id: Id,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub service_epoch: u64,
    pub policy_epoch: u64,
    pub snapshot_version: u16,
    pub snapshot_sha256: Digest,
    pub signing_key_id: Digest,
}

#[derive(Clone, Debug)]
pub struct SignedRecoveryCheckpoint(Signed<RecoveryCheckpoint>);

impl SignedRecoveryCheckpoint {
    pub fn sign(checkpoint: RecoveryCheckpoint, signer: &SigningKey) -> Result<Self> {
        Signed::sign(checkpoint, signer).map(Self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Signed::decode(bytes).map(Self)
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn digest(&self) -> Digest {
        Sha256::digest(self.as_bytes()).into()
    }

    pub fn verify_for(&self, pin: &VerifyingKey) -> Result<&RecoveryCheckpoint> {
        self.0.verify(pin)
    }
}

impl Payload for RecoveryCheckpoint {
    const KIND: u16 = KIND;
    const DOMAIN: &'static [u8] = b"vmkek.protocol.v1.recovery-checkpoint\0";
    fn key_id(&self) -> &Digest {
        &self.signing_key_id
    }

    fn encode_body(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut body = Vec::new();
        for id in [
            self.scope.deployment_id,
            self.scope.app_id,
            self.scope.build_id,
            self.scope.history_id,
            self.fence_id,
        ] {
            push_field(&mut body, &id);
        }
        for field in [
            self.sequence,
            self.issued_at_ms,
            self.service_epoch,
            self.policy_epoch,
        ] {
            push_field(&mut body, &field.to_le_bytes());
        }
        push_field(&mut body, &self.snapshot_version.to_le_bytes());
        push_field(&mut body, &self.snapshot_sha256);
        push_field(&mut body, &self.signing_key_id);
        Ok(body)
    }

    fn decode_body(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let checkpoint = Self {
            scope: RecoveryScope {
                deployment_id: r.fixed()?,
                app_id: r.fixed()?,
                build_id: r.fixed()?,
                history_id: r.fixed()?,
            },
            fence_id: r.fixed()?,
            sequence: r.field_u64()?,
            issued_at_ms: r.field_u64()?,
            service_epoch: r.field_u64()?,
            policy_epoch: r.field_u64()?,
            snapshot_version: r.field_u16()?,
            snapshot_sha256: r.fixed()?,
            signing_key_id: r.fixed()?,
        };
        r.finish()?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }
}

impl RecoveryCheckpoint {
    fn validate(&self) -> Result<()> {
        if self.snapshot_version != RECOVERY_SNAPSHOT_VERSION {
            return Err(Error::Version);
        }
        if [
            self.scope.deployment_id,
            self.scope.app_id,
            self.scope.build_id,
            self.scope.history_id,
            self.fence_id,
        ]
        .contains(&[0; 16])
            || [
                self.sequence,
                self.issued_at_ms,
                self.service_epoch,
                self.policy_epoch,
            ]
            .iter()
            .any(|value| !(1..=i64::MAX as u64).contains(value))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
