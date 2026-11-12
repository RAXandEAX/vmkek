//! Trusted in-process access decisions. No runtime HTTP route accepts them.

mod store;
#[cfg(test)]
mod tests;

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use p256::ecdsa::VerifyingKey;
use sqlx::PgPool;
use vmkek_protocol::{
    access_command::{AccessAuthority, AccessRole, SignedAccessCommand},
    public_key_id, Id, ProtocolError,
};

pub(crate) use store::revoke_legacy;

#[derive(Clone)]
pub struct AdminPin {
    pub app_id: Id,
    pub actor_id: Id,
    pub role: AccessRole,
    pub key: VerifyingKey,
}

#[derive(Clone)]
pub struct AccessAdmin {
    pool: PgPool,
    pins: Arc<HashMap<Id, AdminPin>>,
    policy_version: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessDecision {
    pub id: u64,
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AccessError {
    #[error("invalid administrative configuration")]
    Configuration,
    #[error("administrative decision denied")]
    Denied,
    #[error("administrative decision expired")]
    Expired,
    #[error("administrative request conflicts with a decision")]
    Conflict,
    #[error("administrative store unavailable")]
    Unavailable,
}

impl From<sqlx::Error> for AccessError {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

impl From<ProtocolError> for AccessError {
    fn from(error: ProtocolError) -> Self {
        match error {
            ProtocolError::Expired => Self::Expired,
            _ => Self::Denied,
        }
    }
}

impl AccessAdmin {
    /// Constructs an admin authority from the trusted service configuration.
    /// Runtime device, grant and package keys do not supply this registry.
    pub fn new(
        pool: PgPool,
        policy_version: u64,
        pins: impl IntoIterator<Item = AdminPin>,
    ) -> Result<Self, AccessError> {
        if !(1..=i64::MAX as u64).contains(&policy_version) {
            return Err(AccessError::Configuration);
        }
        let mut registry = HashMap::new();
        let mut keys = HashSet::new();
        for pin in pins {
            if pin.app_id == [0; 16]
                || pin.actor_id == [0; 16]
                || !keys.insert(public_key_id(&pin.key))
                || registry.insert(pin.actor_id, pin).is_some()
            {
                return Err(AccessError::Configuration);
            }
        }
        Ok(Self {
            pool,
            pins: Arc::new(registry),
            policy_version,
        })
    }

    /// The actor selector identifies an independently configured pin. The
    /// signature proves its possession and must bind that same actor and app.
    pub async fn apply(
        &self,
        actor: Id,
        signed: &SignedAccessCommand,
    ) -> Result<AccessDecision, AccessError> {
        let pin = self.pins.get(&actor).ok_or(AccessError::Denied)?;
        let authority = AccessAuthority {
            app_id: pin.app_id,
            actor_id: pin.actor_id,
            role: pin.role,
            key: &pin.key,
        };
        store::apply(&self.pool, authority, self.policy_version, signed).await
    }
}
