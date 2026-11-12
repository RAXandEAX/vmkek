use std::time::{Duration, Instant};

use p256::ecdsa::VerifyingKey;
use vmkek_protocol::{OperationReceipt, SampleJob, MAX_DEADLINE_MS};

use crate::{online, state, Status, VmkRequestId, VmkRuntime};

/// Invoke the typed server operation on an already-active Online runtime.
/// The request ID is also the idempotency key and can be cancelled with the existing API.
pub fn invoke_sample_receipt(
    handle: VmkRuntime,
    request_id: VmkRequestId,
    job: SampleJob,
    receipt_pin: &VerifyingKey,
    timeout: Duration,
) -> Result<OperationReceipt, Status> {
    crate::process_fence()?;
    let started = Instant::now();
    request_id.validate()?;
    if job.job_id == [0; 16] || !(1..=128).contains(&job.units) || timeout.is_zero() {
        return Err(Status::InvalidArgument);
    }
    let runtime = state::get(handle)?;
    let call = runtime.begin(request_id)?;
    let token = call.key_token.ok_or(Status::Incompatible)?;
    let maximum = Duration::from_millis(MAX_DEADLINE_MS.into());
    let network_deadline = started + maximum;
    let generation = Duration::from_millis(call.generation.deadline_ms.into());
    let deadline = (started + timeout.min(maximum).min(generation)).min(token.expires());
    let (receipt, _reservation) = online::acquire_receipt(
        &runtime,
        &call,
        request_id.bytes,
        job,
        *receipt_pin,
        deadline,
        network_deadline,
    )?;
    call.commit_receipt(deadline, receipt)
}
