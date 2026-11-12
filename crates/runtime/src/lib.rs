#![deny(unsafe_op_in_unsafe_fn)]

mod abi;
pub mod observations;
#[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
mod online;
#[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
mod operation;
#[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
pub use operation::invoke_sample_receipt;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod r13_swap;
mod state;

use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use abi::{borrow_input, initialization_version, validate_layout, validate_version, Span};
pub use abi::{
    VmkBytes, VmkInitializeV1, VmkInitializeV2, VmkInvokeResultV1, VmkInvokeV1, VmkOutput,
    VmkRequestId, VmkScalar, ABI_VERSION, ONLINE_ABI_VERSION, PROFILE_LAB, PROFILE_ONLINE,
    SCALAR_I64, SCALAR_NONE, SCALAR_U64,
};
use state::{Generation, GenerationCode, Reservation, Runtime};
use vmkek_protocol::{
    Execution, ExecutionControl, Profile, ProtocolError, Scalar, VerifiedProgram, VmDescriptor,
    VmError, MAX_BODY_BYTES, MAX_SCALAR_ARGS,
};
use zeroize::Zeroizing;

pub type VmkRuntime = u64;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Ok = 0,
    Unavailable = 1,
    Expired = 2,
    Denied = 3,
    Revoked = 4,
    Incompatible = 5,
    InvalidPackage = 6,
    ResourceLimit = 7,
    Cancelled = 8,
    Internal = 9,
    InvalidArgument = 10,
    OutputTooSmall = 11,
    NotFound = 12,
}

impl From<VmError> for Status {
    fn from(error: VmError) -> Self {
        match error {
            VmError::Unavailable => Self::Unavailable,
            VmError::Incompatible => Self::Incompatible,
            VmError::InvalidProgram => Self::InvalidPackage,
            VmError::InvalidInput => Self::InvalidArgument,
            VmError::OutputTooSmall => Self::OutputTooSmall,
            VmError::FuelExhausted | VmError::DeadlineExpired | VmError::ResourceLimit => {
                Self::ResourceLimit
            }
            VmError::Cancelled => Self::Cancelled,
        }
    }
}

pub(crate) fn process_fence() -> Result<(), Status> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use std::sync::atomic::{AtomicU32, Ordering};
        static OWNER: AtomicU32 = AtomicU32::new(0);
        // SAFETY: getpid is async-signal-safe and needs no caller storage.
        let pid = unsafe { libc::getpid() } as u32;
        let mut owner = OWNER.load(Ordering::Acquire);
        if owner == 0 {
            owner = OWNER
                .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire)
                .unwrap_or_else(|existing| existing);
            if owner == 0 {
                owner = pid;
            }
        }
        if owner != pid {
            return Err(Status::Unavailable);
        }
    }
    Ok(())
}

fn ffi(call: impl FnOnce() -> Result<(), Status>) -> u32 {
    if let Err(status) = process_fence() {
        return status as u32;
    }
    match catch_unwind(AssertUnwindSafe(call)) {
        Ok(Ok(())) => Status::Ok as u32,
        Ok(Err(status)) => status as u32,
        Err(payload) => {
            // A panic payload can have a panicking destructor.
            let _ = catch_unwind(AssertUnwindSafe(|| drop(payload))).map_err(std::mem::forget);
            Status::Internal as u32
        }
    }
}

/// Initializes an unsigned local Lab program after descriptor and code verification.
///
/// # Safety
/// The caller must provide the readable input and exclusive writable storage
/// required by the ABI header. Output is written only on success.
#[no_mangle]
pub unsafe extern "C" fn vmk_initialize(
    args: *const VmkInitializeV1,
    out_runtime: *mut VmkRuntime,
) -> u32 {
    // SAFETY: all pointer operations inherit the C caller's storage contract.
    ffi(|| unsafe { initialize(args, out_runtime) })
}

unsafe fn initialize(
    args: *const VmkInitializeV1,
    out_runtime: *mut VmkRuntime,
) -> Result<(), Status> {
    let metadata = Span::one(args)?;
    let out = Span::one(out_runtime)?;
    out.disjoint(&[&metadata])?;
    if unsafe { initialization_version(args)? } == ONLINE_ABI_VERSION {
        return unsafe { initialize_online(args.cast(), out_runtime) };
    }
    unsafe { validate_version(args)? };
    let args = unsafe { args.read() };
    check_profile(args.profile, args.reserved)?;
    let descriptor = Span::new(args.descriptor.data, args.descriptor.len, MAX_BODY_BYTES)?;
    let program = Span::new(args.program.data, args.program.len, MAX_BODY_BYTES)?;
    out.disjoint(&[&descriptor, &program])?;
    if descriptor
        .count
        .checked_add(program.count)
        .ok_or(Status::ResourceLimit)?
        > MAX_BODY_BYTES
    {
        return Err(Status::ResourceLimit);
    }
    let descriptor = unsafe { borrow_input(args.descriptor.data, &descriptor) };
    let program = unsafe { borrow_input(args.program.data, &program) };
    let handle = state::insert(verified_runtime(descriptor, program, None)?)?;
    unsafe { out_runtime.write(handle) };
    Ok(())
}

unsafe fn initialize_online(
    args: *const VmkInitializeV2,
    out_runtime: *mut VmkRuntime,
) -> Result<(), Status> {
    const MAX_PATH_BYTES: usize = 4096;
    let metadata = Span::one(args)?;
    let output = Span::one(out_runtime)?;
    output.disjoint(&[&metadata])?;
    unsafe { validate_layout(args, ONLINE_ABI_VERSION)? };
    let args = unsafe { args.read() };
    if args.profile != PROFILE_ONLINE || args.reserved != 0 || args.reserved_tail != [0; 2] {
        return Err(Status::Incompatible);
    }
    let path = Span::new(args.config_path.data, args.config_path.len, MAX_PATH_BYTES)?;
    output.disjoint(&[&path])?;
    let path = unsafe { borrow_input(args.config_path.data, &path) };
    let path = std::str::from_utf8(path).map_err(|_| Status::InvalidArgument)?;
    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    {
        let handle = state::insert(online::initialize(path)?)?;
        unsafe { out_runtime.write(handle) };
        Ok(())
    }
    #[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
    {
        let _ = path;
        Err(Status::Unavailable)
    }
}

fn check_profile(profile: u32, reserved: u32) -> Result<(), Status> {
    if reserved != 0 {
        return Err(Status::Incompatible);
    }
    match profile {
        PROFILE_LAB => Ok(()),
        PROFILE_ONLINE => Err(Status::Unavailable),
        _ => Err(Status::Incompatible),
    }
}

/// Initializes the local Lab runtime with an activated Offline observation
/// profile. The trusted launcher owns policy storage and sampling. Invocation
/// and shutdown use the same ABI and handle as an ordinary Lab runtime.
#[cfg(any(
    all(windows, target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "x86_64"),
    test
))]
pub fn initialize_observed_lab(
    descriptor: &[u8],
    program: &[u8],
    observation_gate: Arc<observations::ObservationGate>,
) -> Result<VmkRuntime, Status> {
    process_fence()?;
    if descriptor.len().saturating_add(program.len()) > MAX_BODY_BYTES {
        return Err(Status::ResourceLimit);
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    if !observation_gate.matches_native_build(
        observations::windows::native_windows_build().map_err(|_| Status::Incompatible)?,
    ) {
        return Err(Status::Incompatible);
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if !observation_gate.matches_linux_release(
        observations::linux::native_release().map_err(|_| Status::Incompatible)?,
    ) {
        return Err(Status::Incompatible);
    }
    state::insert(verified_runtime(
        descriptor,
        program,
        Some(observation_gate),
    )?)
}

/// Returns the scoped local assessment for an opt-in runtime by handle.
pub fn runtime_observation(
    runtime: VmkRuntime,
    signal_id: vmkek_protocol::session_observation::SignalId,
) -> Result<Option<observations::ObservationAssessment>, Status> {
    process_fence()?;
    Ok(state::get(runtime)?.observation(signal_id))
}

/// Latest local stop notification enqueue result, independent of admission.
pub fn runtime_observation_delivery(
    runtime: VmkRuntime,
) -> Result<observations::ObservationDelivery, Status> {
    process_fence()?;
    Ok(state::get(runtime)?.observation_delivery())
}

/// Latest online own-stop report acknowledgement for this runtime.
pub fn runtime_observation_report(
    runtime: VmkRuntime,
) -> Result<observations::ObservationReport, Status> {
    process_fence()?;
    Ok(state::get(runtime)?.observation_report())
}

fn verified_runtime(
    descriptor: &[u8],
    program: &[u8],
    observation_gate: Option<Arc<observations::ObservationGate>>,
) -> Result<Runtime, Status> {
    let overhead = size_of::<Runtime>() + size_of::<Generation>();
    // Canonical decoding copies extension contents and allocates typed
    // records. The wire length bounds the bytes copied and record count.
    let descriptor_estimate = descriptor
        .len()
        .checked_mul(size_of::<vmkek_protocol::Extension>() + 1)
        .and_then(|bytes| bytes.checked_add(size_of::<VmDescriptor>()))
        .ok_or(Status::ResourceLimit)?;
    let descriptor_reservation = Reservation::new(descriptor_estimate, false)?;
    let descriptor = VmDescriptor::decode(descriptor).map_err(descriptor_error)?;
    match descriptor.profile {
        Profile::Lab => {}
        Profile::Online => return Err(Status::Unavailable),
        Profile::Legacy => return Err(Status::Incompatible),
    }
    if observation_gate
        .as_ref()
        .is_some_and(|gate| !gate.matches_offline_artifact(descriptor.app_id, descriptor.build_id))
    {
        return Err(Status::InvalidPackage);
    }
    let estimate = VerifiedProgram::verification_bytes_for(&descriptor, program)?;
    let working = overhead
        .checked_add(estimate)
        .ok_or(Status::ResourceLimit)?;
    let mut reservation = Reservation::new(working, false)?;
    let verified = VerifiedProgram::verify(&descriptor, program)?;
    let budgets = descriptor.budgets;
    let (generation_id, form) = (descriptor.generation_id, descriptor.form);
    drop(descriptor);
    drop(descriptor_reservation);
    reservation.shrink(
        overhead
            .checked_add(verified.memory_bytes())
            .ok_or(Status::ResourceLimit)?,
    )?;
    let runtime = Runtime::from_generation(
        Generation::new(
            generation_id,
            form,
            verified,
            budgets.deadline_ms,
            usize::from(budgets.active_contexts),
            reservation,
        ),
        None,
    );
    if let Some(gate) = observation_gate {
        gate.check_time()?;
        runtime.attach_observation_gate(gate);
    }
    Ok(runtime)
}

fn descriptor_error(error: ProtocolError) -> Status {
    match error {
        ProtocolError::Version | ProtocolError::UnknownMandatory => Status::Incompatible,
        ProtocolError::Limit => Status::ResourceLimit,
        _ => Status::InvalidPackage,
    }
}

/// Executes a verified local Lab program and publishes its complete result.
///
/// # Safety
/// The caller must honor the ABI storage and exclusivity requirements for
/// args, out_result, and every buffer referenced by args.
#[no_mangle]
pub unsafe extern "C" fn vmk_invoke(
    runtime: VmkRuntime,
    args: *const VmkInvokeV1,
    out_result: *mut VmkInvokeResultV1,
) -> u32 {
    // SAFETY: all pointer operations inherit the C caller's storage contract.
    ffi(|| unsafe { invoke(runtime, args, out_result) })
}

struct ScopedExecution {
    result: Execution,
    _memory: Reservation,
}

struct Invocation {
    args: VmkInvokeV1,
    scalars: Span,
    input: Span,
    output: Span,
}

unsafe fn check_invocation(
    args: *const VmkInvokeV1,
    out: *mut VmkInvokeResultV1,
) -> Result<Invocation, Status> {
    let metadata = Span::one(args)?;
    let result = Span::one(out)?;
    result.disjoint(&[&metadata])?;
    unsafe { validate_version(args)? };
    let args = unsafe { args.read() };
    args.request_id.validate()?;
    let scalars = Span::new(args.scalars, args.scalar_count, MAX_SCALAR_ARGS)?;
    let input = Span::new(args.input.data, args.input.len, MAX_BODY_BYTES)?;
    let output = Span::new(args.output.data, args.output.capacity, MAX_BODY_BYTES)?;
    result.disjoint(&[&scalars, &input])?;
    output.disjoint(&[&metadata, &scalars, &input, &result])?;
    unsafe { validate_version(out)? };
    Ok(Invocation {
        args,
        scalars,
        input,
        output,
    })
}

unsafe fn invoke(
    handle: VmkRuntime,
    args: *const VmkInvokeV1,
    out: *mut VmkInvokeResultV1,
) -> Result<(), Status> {
    let started = Instant::now();
    let invocation = unsafe { check_invocation(args, out)? };
    let runtime = state::get(handle)?;
    let call = runtime.begin(invocation.args.request_id)?;
    let local_deadline = started + Duration::from_millis(u64::from(call.generation.deadline_ms));
    let deadline = call
        .lease
        .map_or(local_deadline, |lease| lease.min(local_deadline));
    let control = ExecutionControl {
        deadline,
        cancelled: &call.cancelled,
    };
    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    let _active;
    let executed = match &call.generation.code {
        GenerationCode::Lab(program) => unsafe { invocation.run(program, &control, true) },
        #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
        GenerationCode::Online(frame) => {
            let network_deadline =
                started + Duration::from_millis(u64::from(vmkek_protocol::MAX_DEADLINE_MS));
            let (program, retained, working) = frame
                .load(&runtime, &call, deadline, network_deadline)
                .map_err(|status| call.failure(status))?;
            #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
            r13_swap::before_execute(&call, deadline);
            _active = working;
            let executed = unsafe { invocation.run(&program, &control, false) };
            drop(program);
            drop(retained);
            executed
        }
    };
    let executed = executed.map_err(|status| {
        let status = if call.lease.is_some_and(|expires| Instant::now() >= expires) {
            Status::Expired
        } else {
            status
        };
        call.failure(status)
    })?;
    #[cfg(test)]
    observations::tests::pause_before_offline_commit();
    call.commit(|| {
        if Instant::now() >= deadline {
            return Err(Status::ResourceLimit);
        }
        unsafe { invocation.publish(&executed.result, out) }
    })
}

impl Invocation {
    unsafe fn run(
        &self,
        program: &VerifiedProgram,
        control: &ExecutionControl<'_>,
        reserve_context: bool,
    ) -> Result<ScopedExecution, Status> {
        if control.cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return Err(Status::Cancelled);
        }
        if Instant::now() >= control.deadline {
            return Err(Status::ResourceLimit);
        }
        let needed = program.required_call_bytes(self.input.count, self.output.count)?;
        let reservation = Reservation::new(needed, reserve_context)?;
        let executed = unsafe { self.execute(program, control) }?;
        Ok(ScopedExecution {
            result: executed,
            _memory: reservation,
        })
    }

    unsafe fn execute(
        &self,
        program: &VerifiedProgram,
        control: &ExecutionControl<'_>,
    ) -> Result<Execution, Status> {
        let raw = unsafe { borrow_input(self.args.scalars, &self.scalars) };
        let mut values = Zeroizing::new(Vec::new());
        values
            .try_reserve_exact(raw.len())
            .map_err(|_| Status::ResourceLimit)?;
        for value in raw {
            values.push(decode_scalar(*value)?);
        }
        let mut input = Zeroizing::new(Vec::new());
        input
            .try_reserve_exact(self.input.count)
            .map_err(|_| Status::ResourceLimit)?;
        input.extend_from_slice(unsafe { borrow_input(self.args.input.data, &self.input) });
        program
            .execute(&values, &input, self.output.count, control)
            .map_err(Status::from)
    }

    unsafe fn publish(
        &self,
        execution: &Execution,
        out: *mut VmkInvokeResultV1,
    ) -> Result<(), Status> {
        if execution.output.len() > self.output.count {
            return Err(Status::OutputTooSmall);
        }
        let len = execution.output.len();
        if len != 0 {
            unsafe {
                ptr::copy_nonoverlapping(execution.output.as_ptr(), self.args.output.data, len)
            };
        }
        let result = VmkInvokeResultV1 {
            size: size_of::<VmkInvokeResultV1>() as u32,
            abi_version: ABI_VERSION,
            scalar: encode_scalar(execution.value),
            output_len: len as u64,
        };
        unsafe { out.write(result) };
        Ok(())
    }
}

fn decode_scalar(value: VmkScalar) -> Result<Scalar, Status> {
    if value.reserved != 0 {
        return Err(Status::InvalidArgument);
    }
    match value.kind {
        SCALAR_U64 => Ok(Scalar::U64(value.bits)),
        SCALAR_I64 => Ok(Scalar::I64(i64::from_ne_bytes(value.bits.to_ne_bytes()))),
        _ => Err(Status::InvalidArgument),
    }
}

fn encode_scalar(value: Option<Scalar>) -> VmkScalar {
    let (kind, bits) = match value {
        Some(Scalar::U64(value)) => (SCALAR_U64, value),
        Some(Scalar::I64(value)) => (SCALAR_I64, u64::from_ne_bytes(value.to_ne_bytes())),
        None => (SCALAR_NONE, 0),
    };
    VmkScalar {
        kind,
        reserved: 0,
        bits,
    }
}

#[no_mangle]
pub extern "C" fn vmk_cancel(runtime: VmkRuntime, request_id: VmkRequestId) -> u32 {
    ffi(|| state::get(runtime)?.cancel(request_id.validate()?))
}

#[no_mangle]
pub extern "C" fn vmk_shutdown(runtime: VmkRuntime) -> u32 {
    ffi(|| state::shutdown(runtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_panic_returns_a_stable_status() {
        assert_eq!(ffi(|| panic!("test unwind")), Status::Internal as u32);
        assert_eq!(ffi(|| Ok(())), Status::Ok as u32);
    }
}
