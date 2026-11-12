use std::time::Duration;

use tokio::time::Instant;
use vmkek_protocol::{
    session_observation::{ObservationAction, ObservationRecord, SessionObservation},
    PermissionKind, MAX_DEADLINE_MS,
};

use crate::{module::request_id, ClientError, DeviceSigner, LeaseToken, SessionClient};

impl<S: DeviceSigner> SessionClient<S> {
    /// Best-effort telemetry for a lease captured before local authority was cleared.
    /// This operation cannot renew or restore the captured lease.
    pub async fn report_local_stop(
        &self,
        token: LeaseToken,
        policy_epoch: u64,
        record: ObservationRecord,
    ) -> Result<(), ClientError> {
        let binding = token.binding();
        if self.identity.permission.kind != PermissionKind::Function
            || (
                binding.app_id,
                binding.build_id,
                binding.device_id,
                binding.license_id,
            ) != (
                self.identity.app_id,
                self.identity.build_id,
                self.identity.device_id,
                self.identity.license_id,
            )
        {
            return Err(ClientError::Verification);
        }
        let expires = Instant::from_std(token.expires());
        let now = Instant::now();
        if now >= expires {
            return Err(ClientError::Expired);
        }
        let message = SessionObservation {
            app_id: binding.app_id,
            build_id: binding.build_id,
            device_id: binding.device_id,
            session_id: binding.session_id,
            generation_id: binding.generation_id,
            function_id: self.identity.permission.id,
            request_id: request_id()?,
            sequence: token.sequence(),
            detection_policy_epoch: policy_epoch,
            action: ObservationAction::RequestOwnStop,
            records: vec![record],
        };
        let body = self.signed(message.encode(), message.signature_digest())?;
        let deadline = expires.min(now + Duration::from_millis(MAX_DEADLINE_MS.into()));
        let reply = tokio::time::timeout_at(
            deadline,
            self.endpoint
                .post_bounded("/v1/session/observation", body, 0),
        )
        .await
        .map_err(|_| ClientError::Timeout)??;
        if Instant::now() >= deadline {
            return Err(ClientError::Expired);
        }
        if !reply.is_empty() {
            return Err(ClientError::InvalidResponse);
        }
        Ok(())
    }
}
