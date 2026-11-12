use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use p256::ecdsa::VerifyingKey;
use vmkek_protocol::{
    Id, OperationReceipt, PermissionKind, SampleJob, SampleOperationRequest,
    SignedOperationReceipt, SAMPLE_JOB_RECEIPT_OPERATION, SAMPLE_OPERATION_RECEIPT_BYTES,
};

use crate::{ClientError, DeviceSigner, LeaseToken, SessionClient};

/// Inputs and deadlines captured for one authorized receipt request.
pub struct SampleReceiptCall<'a> {
    pub token: LeaseToken,
    pub request_id: Id,
    pub job: SampleJob,
    pub receipt_pin: &'a VerifyingKey,
    pub call_deadline: Instant,
    pub network_deadline: Instant,
    pub attempted: &'a AtomicBool,
}

impl<S: DeviceSigner> SessionClient<S> {
    /// Request a typed server receipt on the current session without opening a module.
    /// The caller owns cancellation and invalidation after a known transport failure.
    pub async fn request_sample_receipt(
        &self,
        call: SampleReceiptCall<'_>,
    ) -> Result<OperationReceipt, ClientError> {
        if self.lease_token() != Some(call.token) {
            return Err(ClientError::Expired);
        }
        let grant = self.current_grant().ok_or(ClientError::Expired)?;
        let [permission] = grant.permissions.as_slice() else {
            return Err(ClientError::Verification);
        };
        if permission.kind != PermissionKind::Function {
            return Err(ClientError::Denied);
        }
        if call.receipt_pin == &self.grant_key {
            return Err(ClientError::Configuration);
        }
        let binding = grant.binding;
        let request = SampleOperationRequest {
            app_id: binding.app_id,
            build_id: binding.build_id,
            device_id: binding.device_id,
            session_id: binding.session_id,
            generation_id: binding.generation_id,
            function_id: permission.id,
            operation_id: SAMPLE_JOB_RECEIPT_OPERATION,
            request_id: call.request_id,
            sequence: grant.sequence,
            job: call.job,
        };
        let (cutoff, timeout) = receipt_cutoff(
            call.call_deadline,
            call.token.expires(),
            call.network_deadline,
        );
        let deadline = tokio::time::Instant::from_std(cutoff);
        if tokio::time::Instant::now() >= deadline {
            return Err(ClientError::Expired);
        }
        let body = self.signed(request.encode(), request.signature_digest())?;
        if tokio::time::Instant::now() >= deadline {
            return Err(ClientError::Expired);
        }
        call.attempted.store(true, Ordering::Release);
        let bytes = tokio::time::timeout_at(
            deadline,
            self.endpoint.post_bounded(
                "/v1/operation/sample-job-receipt",
                body,
                SAMPLE_OPERATION_RECEIPT_BYTES,
            ),
        )
        .await
        .map_err(|_| timeout)??;
        if tokio::time::Instant::now() >= deadline {
            return Err(timeout);
        }
        if bytes.len() != SAMPLE_OPERATION_RECEIPT_BYTES {
            return Err(ClientError::InvalidResponse);
        }
        let signed =
            SignedOperationReceipt::decode(&bytes).map_err(|_| ClientError::InvalidResponse)?;
        let verified = signed
            .verify_for(call.receipt_pin, &request, binding, grant.policy_epoch)
            .map_err(|_| ClientError::Verification)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(timeout);
        }
        Ok(*verified)
    }
}

fn receipt_cutoff(call: Instant, lease: Instant, network: Instant) -> (Instant, ClientError) {
    let local = call.min(lease);
    if network <= call && network < lease {
        (network, ClientError::Timeout)
    } else {
        (local, ClientError::Expired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn default_call_tie_is_network_timeout_but_lease_or_shorter_call_is_local() {
        let now = Instant::now();
        let early = now + Duration::from_secs(1);
        let late = now + Duration::from_secs(2);
        assert_eq!(
            receipt_cutoff(early, late, early),
            (early, ClientError::Timeout)
        );
        assert_eq!(
            receipt_cutoff(early, late, late),
            (early, ClientError::Expired)
        );
        assert_eq!(
            receipt_cutoff(late, early, early),
            (early, ClientError::Expired)
        );
        assert_eq!(
            receipt_cutoff(late, late, early),
            (early, ClientError::Timeout)
        );
    }
}
