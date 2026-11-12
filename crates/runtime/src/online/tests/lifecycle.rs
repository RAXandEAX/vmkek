use std::cell::RefCell;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::{Duration, Instant};

use super::{native_open, WipeObservation, WIPE_OBSERVATION};
use crate::{
    state::{self, Call},
    vmk_cancel, vmk_invoke, vmk_shutdown, Status, VmkBytes, VmkInvokeResultV1, VmkInvokeV1,
    VmkOutput, VmkRequestId, VmkRuntime, VmkScalar, ABI_VERSION, SCALAR_I64, SCALAR_NONE,
};

const WAIT: Duration = Duration::from_secs(35);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::online) enum Checkpoint {
    Decrypted,
    Verified,
}

struct Probe {
    at: Checkpoint,
    arrived: SyncSender<(Instant, WipeObservation)>,
    resume: Receiver<()>,
}

thread_local! {
    static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
}

pub(in crate::online) fn pause(at: Checkpoint, call: &Call) {
    let probe = PROBE.with_borrow_mut(|slot| {
        if slot.as_ref().is_some_and(|probe| probe.at == at) {
            slot.take()
        } else {
            None
        }
    });
    if let Some(probe) = probe {
        let wipes = WIPE_OBSERVATION.with(|slot| slot.get().unwrap());
        probe.arrived.send((call.lease.unwrap(), wipes)).unwrap();
        probe.resume.recv_timeout(WAIT).unwrap();
    }
}

struct Handle(VmkRuntime);

impl Drop for Handle {
    fn drop(&mut self) {
        assert_eq!(vmk_shutdown(self.0), Status::Ok as u32);
    }
}

#[test]
#[ignore = "requires a private copy-input Online fixture over loopback TLS and isolated PostgreSQL"]
fn native_ffi_owned_allocations_clear_on_cancel_and_captured_lease_expiry() {
    let config = std::env::var("VMKEK_R14_LIFECYCLE_CONFIG").unwrap();
    let handle = Handle(native_open(&config));
    exercise(
        &handle,
        Checkpoint::Decrypted,
        51,
        Status::Cancelled,
        |_, request| {
            assert_eq!(vmk_cancel(handle.0, request), Status::Ok as u32);
        },
    );
    invoke_expect(handle.0, request(52), Status::Ok);
    exercise(
        &handle,
        Checkpoint::Verified,
        55,
        Status::ResourceLimit,
        |_, _| {
            std::thread::sleep(Duration::from_millis(
                u64::from(vmkek_protocol::MAX_DEADLINE_MS) + 10,
            ))
        },
    );

    let captured = exercise(
        &handle,
        Checkpoint::Verified,
        53,
        Status::Expired,
        |lease, _| {
            let remaining = lease.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero() && remaining < WAIT);
            std::thread::sleep(remaining + Duration::from_millis(10));
        },
    );
    let renewed = state::get(handle.0).unwrap().begin(request(54)).unwrap();
    assert!(renewed.lease.unwrap() > captured);
    drop(renewed);
    invoke_after_renewal(handle.0, request(54));
    eprintln!("R14 native FFI: cancel, call deadline and captured lease expiry left outputs untouched; owned key and plaintext wiped; same handle recovered");
}

fn invoke_after_renewal(handle: VmkRuntime, id: VmkRequestId) {
    let retry_until = Instant::now() + Duration::from_secs(2);
    loop {
        let status = invoke_and_check_output(handle, id);
        // A request queued with the previous token during heartbeat is cancelled.
        if status != Status::Cancelled as u32 || Instant::now() >= retry_until {
            assert_eq!(status, Status::Ok as u32);
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn exercise(
    handle: &Handle,
    at: Checkpoint,
    id: u8,
    expected: Status,
    act: impl FnOnce(Instant, VmkRequestId),
) -> Instant {
    let request = request(id);
    let (arrived, wait) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    let raw = handle.0;
    let invoke = std::thread::spawn(move || {
        PROBE.with_borrow_mut(|slot| {
            *slot = Some(Probe {
                at,
                arrived,
                resume,
            })
        });
        WIPE_OBSERVATION.with(|slot| slot.set(Some(WipeObservation::default())));
        invoke_expect(raw, request, expected);
        WIPE_OBSERVATION.with(|slot| slot.take().unwrap())
    });
    let (lease, before) = wait.recv_timeout(Duration::from_secs(6)).unwrap();
    assert_eq!(before.failures, 0);
    assert_eq!(
        before.count,
        if at == Checkpoint::Decrypted {
            [0, 0]
        } else {
            [1, 1]
        }
    );
    act(lease, request);
    release.send(()).unwrap();
    let after = invoke.join().unwrap();
    assert_eq!(after.count, [1, 1]);
    assert_eq!(after.failures, 0);
    assert_eq!(vmk_cancel(handle.0, request), Status::NotFound as u32);
    lease
}

fn request(id: u8) -> VmkRequestId {
    VmkRequestId { bytes: [id; 16] }
}

fn invoke_expect(handle: VmkRuntime, request_id: VmkRequestId, expected: Status) {
    assert_eq!(invoke_and_check_output(handle, request_id), expected as u32);
}

fn invoke_and_check_output(handle: VmkRuntime, request_id: VmkRequestId) -> u32 {
    let argument = VmkScalar {
        kind: SCALAR_I64,
        reserved: 0,
        bits: (-17i64) as u64,
    };
    let input = [11u8, 23, 42, 71];
    let mut output = [0xa5u8; 4];
    let args = VmkInvokeV1 {
        size: size_of::<VmkInvokeV1>() as u32,
        abi_version: ABI_VERSION,
        request_id,
        scalars: &argument,
        scalar_count: 1,
        input: VmkBytes {
            data: input.as_ptr(),
            len: input.len() as u64,
        },
        output: VmkOutput {
            data: output.as_mut_ptr(),
            capacity: output.len() as u64,
        },
    };
    let mut result = VmkInvokeResultV1 {
        size: size_of::<VmkInvokeResultV1>() as u32,
        abi_version: ABI_VERSION,
        scalar: VmkScalar {
            kind: SCALAR_NONE,
            reserved: 0,
            bits: 0,
        },
        output_len: 0,
    };
    let sentinel = result;
    // SAFETY: all inputs, output and result are separate live allocations for this call.
    let status = unsafe { vmk_invoke(handle, &args, &mut result) };
    if status == Status::Ok as u32 {
        assert_eq!(result.scalar, argument);
        assert_eq!(result.output_len, input.len() as u64);
        assert_eq!(output, input);
    } else {
        assert_eq!(result, sentinel);
        assert_eq!(output, [0xa5; 4]);
    }
    status
}
