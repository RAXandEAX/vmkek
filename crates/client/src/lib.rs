//! Online R10 sessions over verified TLS 1.3.

mod generation;
mod module;
mod observation;
mod operation;
mod tls;

use std::time::Duration;

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use tokio::time::Instant;
use vmkek_protocol::{
    Digest, GrantBinding, GrantPayload, Id, Permission, SessionChallenge, SessionGrant,
    SessionGrantExpectation, SessionIntent, SessionOperation, MAX_GRANT_LIFETIME_MS,
    SESSION_HEARTBEAT_MS,
};

pub use generation::{GenerationCapabilities, GenerationSelection};
pub use module::{LeaseToken, ModuleCiphertext, ModuleSelection, OpenedModule};
pub use operation::SampleReceiptCall;
pub use tls::TlsEndpoint;

const HEARTBEAT: Duration = Duration::from_millis(SESSION_HEARTBEAT_MS as u64);
const CHALLENGE_PATH: &str = "/v1/session/challenge";
const OPEN_PATH: &str = "/v1/session/open";
const RENEW_PATH: &str = "/v1/session/renew";

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ClientError {
    #[error("invalid R10 client configuration")]
    Configuration,
    #[error("session service is unavailable")]
    Unavailable,
    #[error("TLS 1.3 authentication or handshake failed")]
    Tls,
    #[error("session request timed out")]
    Timeout,
    #[error("session request denied")]
    Denied,
    #[error("invalid session response")]
    InvalidResponse,
    #[error("session request or response exceeds the body limit")]
    BodyLimit,
    #[error("session response has invalid proof or identity binding")]
    Verification,
    #[error("device signing failed")]
    Signing,
    #[error("operating-system entropy unavailable")]
    Entropy,
    #[error("no current online session")]
    NoSession,
    #[error("online session has expired")]
    Expired,
}

/// Sign the canonical protocol prehash using the enrolled device key.
pub trait DeviceSigner {
    fn sign_prehash(&self, digest: &Digest) -> Result<[u8; 64], ClientError>;
}

impl DeviceSigner for SigningKey {
    fn sign_prehash(&self, digest: &Digest) -> Result<[u8; 64], ClientError> {
        let signature: Signature =
            PrehashSigner::sign_prehash(self, digest).map_err(|_| ClientError::Signing)?;
        Ok(signature.to_bytes().into())
    }
}

/// Trusted expected identities, epoch and permission for this client.
#[derive(Clone, Copy)]
pub struct SessionIdentity {
    pub app_id: Id,
    pub build_id: Id,
    pub device_id: Id,
    pub generation_id: Id,
    pub license_id: Id,
    pub policy_epoch: u64,
    pub permission: Permission,
}

struct Lease {
    grant: GrantPayload,
    expires: Instant,
    heartbeat: Instant,
}

impl Lease {
    fn new(grant: GrantPayload, started: Instant, now: Instant) -> Result<Self, ClientError> {
        if grant.lifetime_ms == 0 || grant.lifetime_ms > MAX_GRANT_LIFETIME_MS {
            return Err(ClientError::Verification);
        }
        let expires = started + Duration::from_millis(u64::from(grant.lifetime_ms));
        if now >= expires {
            return Err(ClientError::Expired);
        }
        Ok(Self {
            grant,
            expires,
            heartbeat: (started + HEARTBEAT).min(expires),
        })
    }
}

/// A process-local client. Consumers drive `heartbeat` and consult `current_grant`
/// before protected operations. Session grants are kept only in memory.
pub struct SessionClient<S> {
    endpoint: TlsEndpoint,
    identity: SessionIdentity,
    signer: S,
    grant_key: VerifyingKey,
    active: Option<Lease>,
}

impl<S: DeviceSigner> SessionClient<S> {
    pub fn new(
        endpoint: TlsEndpoint,
        identity: SessionIdentity,
        signer: S,
        grant_key: VerifyingKey,
    ) -> Self {
        Self {
            endpoint,
            identity,
            signer,
            grant_key,
            active: None,
        }
    }

    pub fn current_grant(&self) -> Option<&GrantPayload> {
        self.active
            .as_ref()
            .filter(|lease| Instant::now() < lease.expires)
            .map(|lease| &lease.grant)
    }

    /// Open a fresh session. Any prior local authority is cleared first.
    pub async fn open(&mut self) -> Result<&GrantPayload, ClientError> {
        self.active = None;
        let lease = self.exchange(SessionOperation::Open, [0; 16], 1).await?;
        Ok(&self.active.insert(lease).grant)
    }

    /// Renew using the current session and the next sequence. Any error clears
    /// the prior lease, including cancellation of this future after it starts.
    pub async fn renew(&mut self) -> Result<&GrantPayload, ClientError> {
        let old = self.active.take().ok_or(ClientError::NoSession)?;
        if Instant::now() >= old.expires {
            return Err(ClientError::Expired);
        }
        let sequence = old
            .grant
            .sequence
            .checked_add(1)
            .ok_or(ClientError::Verification)?;
        let exchange = self.exchange(
            SessionOperation::Renew,
            old.grant.binding.session_id,
            sequence,
        );
        let lease = complete_renewal(old.expires, exchange).await?;
        Ok(&self.active.insert(lease).grant)
    }

    /// Wait for the ten-second heartbeat point and attempt one renewal.
    pub async fn heartbeat(&mut self) -> Result<&GrantPayload, ClientError> {
        let at = self
            .active
            .as_ref()
            .ok_or(ClientError::NoSession)?
            .heartbeat;
        tokio::time::sleep_until(at).await;
        self.renew().await
    }

    /// Clear local authority immediately after another operation reports a known failure.
    pub fn invalidate(&mut self) {
        self.active = None;
    }

    async fn exchange(
        &self,
        operation: SessionOperation,
        session_id: Id,
        sequence: u64,
    ) -> Result<Lease, ClientError> {
        let started = Instant::now();
        let intent = self.intent(operation, session_id, sequence)?;
        let challenge = self.challenge(&intent).await?;
        let path = match operation {
            SessionOperation::Open => OPEN_PATH,
            SessionOperation::Renew => RENEW_PATH,
        };
        let request = self.signed(challenge.encode(), challenge.signature_digest())?;
        let reply = self.endpoint.post(path, request).await?;
        let grant = self.verify_grant(&reply, &challenge, sequence)?;
        Lease::new(grant, started, Instant::now())
    }

    fn intent(
        &self,
        operation: SessionOperation,
        session_id: Id,
        sequence: u64,
    ) -> Result<SessionIntent, ClientError> {
        let mut request_id = [0; 16];
        OsRng
            .try_fill_bytes(&mut request_id)
            .map_err(|_| ClientError::Entropy)?;
        Ok(SessionIntent {
            operation,
            app_id: self.identity.app_id,
            build_id: self.identity.build_id,
            device_id: self.identity.device_id,
            generation_id: self.identity.generation_id,
            session_id,
            sequence,
            request_id,
        })
    }

    async fn challenge(&self, intent: &SessionIntent) -> Result<SessionChallenge, ClientError> {
        let request = self.signed(intent.encode(), intent.signature_digest())?;
        let reply = self.endpoint.post(CHALLENGE_PATH, request).await?;
        let challenge = SessionChallenge::decode(&reply).map_err(|_| ClientError::Verification)?;
        if challenge.intent_digest != intent.digest().map_err(|_| ClientError::Verification)?
            || challenge.session_id == [0; 16]
            || (intent.operation == SessionOperation::Renew
                && challenge.session_id != intent.session_id)
        {
            return Err(ClientError::Verification);
        }
        Ok(challenge)
    }

    fn verify_grant(
        &self,
        bytes: &[u8],
        challenge: &SessionChallenge,
        sequence: u64,
    ) -> Result<GrantPayload, ClientError> {
        let grant = SessionGrant::decode(bytes).map_err(|_| ClientError::Verification)?;
        let expected = SessionGrantExpectation {
            binding: GrantBinding {
                session_id: challenge.session_id,
                device_id: self.identity.device_id,
                license_id: self.identity.license_id,
                app_id: self.identity.app_id,
                build_id: self.identity.build_id,
                generation_id: self.identity.generation_id,
            },
            policy_epoch: self.identity.policy_epoch,
            sequence,
            permission: self.identity.permission,
            challenge_digest: challenge.digest().map_err(|_| ClientError::Verification)?,
        };
        grant
            .verify_session(&self.grant_key, &expected)
            .cloned()
            .map_err(|_| ClientError::Verification)
    }

    fn signed(
        &self,
        bytes: Result<Vec<u8>, vmkek_protocol::ProtocolError>,
        digest: Result<Digest, vmkek_protocol::ProtocolError>,
    ) -> Result<Vec<u8>, ClientError> {
        let mut bytes = bytes.map_err(|_| ClientError::Verification)?;
        bytes.extend_from_slice(
            &self
                .signer
                .sign_prehash(&digest.map_err(|_| ClientError::Verification)?)?,
        );
        Ok(bytes)
    }
}

async fn complete_renewal<T>(
    expires: Instant,
    exchange: impl std::future::Future<Output = Result<T, ClientError>>,
) -> Result<T, ClientError> {
    let lease = tokio::time::timeout_at(expires, exchange)
        .await
        .map_err(|_| ClientError::Expired)??;
    // A ready exchange can win the timeout poll at the deadline.
    if Instant::now() >= expires {
        return Err(ClientError::Expired);
    }
    Ok(lease)
}

#[cfg(test)]
#[tokio::test(start_paused = true)]
async fn renewal_ready_at_old_expiry_is_rejected() {
    let expires = Instant::now() + Duration::from_secs(1);
    let renewal = complete_renewal(expires, async {
        tokio::time::sleep_until(expires).await;
        Ok(())
    });
    assert_eq!(renewal.await, Err(ClientError::Expired));
}
