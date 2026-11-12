use std::cell::RefCell;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

use vmkek_protocol::{VmForm, MAX_GRANT_LIFETIME_MS, SESSION_HEARTBEAT_MS};

use crate::{
    state::{self, Call, Generation},
    vmk_cancel, vmk_initialize, vmk_invoke, vmk_shutdown, Status, VmkBytes, VmkInitializeV2,
    VmkInvokeResultV1, VmkInvokeV1, VmkOutput, VmkRequestId, VmkRuntime, VmkScalar, ABI_VERSION,
    ONLINE_ABI_VERSION, PROFILE_ONLINE, SCALAR_I64, SCALAR_NONE,
};

struct Pause {
    reached: SyncSender<(Weak<Generation>, Instant)>,
    resume: Receiver<()>,
}

thread_local! {
    static PAUSE: RefCell<Option<Pause>> = const { RefCell::new(None) };
}

pub(super) fn before_execute(call: &Call, deadline: Instant) {
    if let Some(pause) = PAUSE.with_borrow_mut(Option::take) {
        pause
            .reached
            .send((Arc::downgrade(&call.generation), deadline))
            .unwrap();
        pause.resume.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}

#[test]
#[ignore = "requires the private Linux swap fixture over loopback TLS and isolated PostgreSQL"]
fn native_ffi_pins_active_generation_during_live_swap_and_cancels_old_call() {
    let handle = open();
    let initial = active(handle).unwrap();
    let old = initial.generation.identity();
    assert_eq!(old.1, VmForm::Stack);
    // The fixture issues full 30-second grants. The client schedules heartbeat
    // and expiry from the same monotonic start.
    let heartbeat = initial.lease.unwrap()
        - Duration::from_millis(u64::from(MAX_GRANT_LIFETIME_MS - SESSION_HEARTBEAT_MS));
    drop(initial);
    invoke_expect(handle, request(79), Status::Ok);
    let invoke_at = heartbeat - Duration::from_secs(2);
    assert!(invoke_at > Instant::now());
    thread::sleep(invoke_at.saturating_duration_since(Instant::now()));

    let old_request = request(81);
    thread::scope(|scope| {
        let (reached, wait) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        let invoke = scope.spawn(move || {
            PAUSE.with_borrow_mut(|pause| *pause = Some(Pause { reached, resume }));
            invoke_expect(handle, old_request, Status::Cancelled);
        });
        let (pinned, deadline) = wait.recv_timeout(Duration::from_secs(4)).unwrap();
        assert!(Instant::now() < heartbeat);
        let new = wait_for_install(handle, deadline);
        assert_ne!(new.0, old.0);
        assert_eq!(new.1, VmForm::Register);
        assert_eq!(pinned.upgrade().unwrap().identity(), old);

        invoke_expect(handle, request(82), Status::Ok);
        assert_eq!(pinned.upgrade().unwrap().identity(), old);
        assert!(Instant::now() < deadline);
        assert_eq!(vmk_cancel(handle, old_request), Status::Ok as u32);
        release.send(()).unwrap();
        invoke.join().unwrap();
        assert!(pinned.upgrade().is_none());
    });
    assert_eq!(vmk_cancel(handle, old_request), Status::NotFound as u32);
    assert_eq!(
        active(handle).unwrap().generation.identity().1,
        VmForm::Register
    );
    invoke_expect(handle, request(83), Status::Ok);
    assert_eq!(vmk_shutdown(handle), Status::Ok as u32);
    eprintln!("R13 native FFI: live Stack/Register swap, equivalent output, cancelled old call unchanged, old frame retired");
}

fn active(handle: VmkRuntime) -> Result<Call, Status> {
    state::get(handle)?.begin(request(80))
}

fn wait_for_install(handle: VmkRuntime, deadline: Instant) -> (vmkek_protocol::Id, VmForm) {
    loop {
        assert!(
            Instant::now() < deadline,
            "generation did not install before the old call deadline"
        );
        match active(handle) {
            Ok(call) => return call.generation.identity(),
            Err(Status::ResourceLimit | Status::Unavailable) => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(status) => panic!("generation installation failed: {status:?}"),
        }
    }
}

fn open() -> VmkRuntime {
    let path = std::env::var("VMKEK_R13_LIVE_SWAP_CONFIG").unwrap();
    let config = VmkInitializeV2 {
        size: size_of::<VmkInitializeV2>() as u32,
        abi_version: ONLINE_ABI_VERSION,
        profile: PROFILE_ONLINE,
        reserved: 0,
        config_path: VmkBytes {
            data: path.as_ptr(),
            len: path.len() as u64,
        },
        reserved_tail: [0; 2],
    };
    let mut handle = 0;
    // SAFETY: the versioned initializer, UTF-8 path and result are live and disjoint.
    assert_eq!(
        unsafe { vmk_initialize((&raw const config).cast(), &mut handle) },
        Status::Ok as u32
    );
    handle
}

fn request(id: u8) -> VmkRequestId {
    VmkRequestId { bytes: [id; 16] }
}

fn invoke_expect(handle: VmkRuntime, request_id: VmkRequestId, expected: Status) {
    let scalar = VmkScalar {
        kind: SCALAR_I64,
        reserved: 0,
        bits: (-17i64) as u64,
    };
    let input = [23u8, 42, 71];
    let mut output = [0xa5u8; 3];
    let call = VmkInvokeV1 {
        size: size_of::<VmkInvokeV1>() as u32,
        abi_version: ABI_VERSION,
        request_id,
        scalars: &scalar,
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
    // SAFETY: every input and output range is live and the output ranges are exclusive.
    assert_eq!(
        unsafe { vmk_invoke(handle, &call, &mut result) },
        expected as u32
    );
    if expected == Status::Ok {
        assert_eq!(result.scalar, scalar);
        assert_eq!(result.output_len, input.len() as u64);
        assert_eq!(output, input);
    } else {
        assert_eq!(result, sentinel);
        assert_eq!(output, [0xa5; 3]);
    }
}
