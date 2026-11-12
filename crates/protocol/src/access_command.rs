use p256::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{
    canonical::{Reader, SIGNATURE_BYTES},
    signed::{Payload, Signed},
    Digest, Id, ProtocolError as Error, MAX_DEADLINE_MS,
};

const KIND: u16 = 17;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessAction {
    Revoke,
    Restore { prior_decision_id: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AccessReason {
    Administrator = 1,
    Compromised = 2,
    ReviewedRestore = 3,
}

/// The trusted control-plane principal role. It never comes from command bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessRole {
    Administrator,
    Observer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessCommand {
    pub app_id: Id,
    pub actor_id: Id,
    pub license_id: Id,
    pub device_id: Option<Id>,
    pub request_id: Id,
    pub policy_version: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub action: AccessAction,
    pub reason: AccessReason,
    pub key_id: Digest,
}

/// Values taken from the server's pinned, trusted administrator registry.
#[derive(Clone, Copy)]
pub struct AccessAuthority<'a> {
    pub app_id: Id,
    pub actor_id: Id,
    pub role: AccessRole,
    pub key: &'a VerifyingKey,
}

#[derive(Clone, Debug)]
pub struct SignedAccessCommand(Signed<AccessCommand>);

/// An authenticated administrative decision. The store still checks target
/// membership, legal transition, prior decision, replay and current policy.
pub struct VerifiedAccessCommand<'a> {
    payload: &'a AccessCommand,
    digest: Digest,
}

impl VerifiedAccessCommand<'_> {
    pub fn payload(&self) -> &AccessCommand {
        self.payload
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }
}

impl SignedAccessCommand {
    pub fn sign(command: AccessCommand, key: &SigningKey) -> Result<Self> {
        Signed::sign(command, key).map(Self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Signed::decode(bytes).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn verify_for(
        &self,
        authority: AccessAuthority<'_>,
        policy_version: u64,
        now_ms: u64,
    ) -> Result<VerifiedAccessCommand<'_>> {
        let payload = self.0.verify(authority.key)?;
        if authority.role != AccessRole::Administrator
            || (payload.app_id, payload.actor_id) != (authority.app_id, authority.actor_id)
            || payload.policy_version != policy_version
        {
            return Err(Error::Binding);
        }
        if !(payload.issued_at_ms..payload.expires_at_ms).contains(&now_ms) {
            return Err(Error::Expired);
        }
        let bytes = self.as_bytes();
        let digest = Sha256::digest(&bytes[..bytes.len() - SIGNATURE_BYTES]).into();
        Ok(VerifiedAccessCommand { payload, digest })
    }
}

impl AccessCommand {
    fn validate(&self) -> Result<()> {
        let valid_action = match (self.action, self.reason) {
            (AccessAction::Revoke, AccessReason::Administrator | AccessReason::Compromised) => true,
            (AccessAction::Restore { prior_decision_id }, AccessReason::ReviewedRestore) => {
                (1..=i64::MAX as u64).contains(&prior_decision_id)
            }
            _ => false,
        };
        let ttl = self.expires_at_ms.checked_sub(self.issued_at_ms);
        if !valid_action
            || !ttl.is_some_and(|ttl| (1..=u64::from(MAX_DEADLINE_MS)).contains(&ttl))
            || !(1..=i64::MAX as u64).contains(&self.policy_version)
            || [self.app_id, self.actor_id, self.license_id, self.request_id].contains(&[0; 16])
            || self.device_id == Some([0; 16])
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    fn read_action(input: &mut Reader<'_>) -> Result<AccessAction> {
        match (input.u8()?, input.u64()?) {
            (1, 0) => Ok(AccessAction::Revoke),
            (2, id) => Ok(AccessAction::Restore {
                prior_decision_id: id,
            }),
            (1, _) => Err(Error::Invalid),
            _ => Err(Error::UnknownMandatory),
        }
    }

    fn write_action(&self, out: &mut Vec<u8>) {
        let (action, decision) = match self.action {
            AccessAction::Revoke => (1, 0),
            AccessAction::Restore { prior_decision_id } => (2, prior_decision_id),
        };
        out.push(action);
        out.extend(decision.to_le_bytes());
        out.push(self.reason as u8);
    }
}

impl Payload for AccessCommand {
    const KIND: u16 = KIND;
    const DOMAIN: &'static [u8] = b"vmkek.protocol.v1.access-command\0";

    fn key_id(&self) -> &Digest {
        &self.key_id
    }

    fn encode_body(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut body = Vec::new();
        for id in [
            self.app_id,
            self.actor_id,
            self.license_id,
            self.device_id.unwrap_or([0; 16]),
            self.request_id,
        ] {
            body.extend(id);
        }
        body.extend(self.policy_version.to_le_bytes());
        body.extend(self.issued_at_ms.to_le_bytes());
        body.extend(self.expires_at_ms.to_le_bytes());
        self.write_action(&mut body);
        body.extend(self.key_id);
        Ok(body)
    }

    fn decode_body(body: &[u8]) -> Result<Self> {
        let mut input = Reader::new(body);
        let app_id = input.array()?;
        let actor_id = input.array()?;
        let license_id = input.array()?;
        let device = input.array()?;
        let command = Self {
            app_id,
            actor_id,
            license_id,
            device_id: (device != [0; 16]).then_some(device),
            request_id: input.array()?,
            policy_version: input.u64()?,
            issued_at_ms: input.u64()?,
            expires_at_ms: input.u64()?,
            action: Self::read_action(&mut input)?,
            reason: match input.u8()? {
                1 => AccessReason::Administrator,
                2 => AccessReason::Compromised,
                3 => AccessReason::ReviewedRestore,
                _ => return Err(Error::UnknownMandatory),
            },
            key_id: input.array()?,
        };
        input.finish()?;
        command.validate()?;
        Ok(command)
    }
}
