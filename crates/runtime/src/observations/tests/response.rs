use super::*;
use std::{
    cell::RefCell,
    sync::mpsc::{self, SyncSender},
    thread::{self, JoinHandle},
};

thread_local! {
    static BEFORE_COMMIT: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

pub(crate) fn pause_before_offline_commit() {
    let pause = BEFORE_COMMIT.with(|slot| slot.borrow_mut().take());
    if let Some(pause) = pause {
        pause();
    }
}

#[cfg(windows)]
mod observer {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_support/response_observer.rs"
    ));
}

#[test]
fn response_offline_stop_discards_admitted_work_and_latches_for_the_activation() {
    let (descriptor, program) = lab_fixture();
    let bytes = descriptor.encode().unwrap();
    let gate = signed_gate(ObservationProfile::Offline, ObservationMode::Enforce);
    gate.publish(vec![clean_sample(&gate)]).unwrap();
    let handle = initialize_observed_lab(&bytes, &program, gate.clone()).unwrap();
    let runtime = crate::state::get(handle).unwrap();
    let previous = invoke(handle, 1, Status::Ok);
    let first = Held::start(handle, 2, Some(3));
    let second = Held::start(handle, 4, None);

    let inconclusive = gate
        .begin_sample()
        .attachment(Observation::Inconclusive, ObservationReason::ApiFailure);
    gate.publish(vec![inconclusive]).unwrap();
    invoke(handle, 5, Status::Unavailable);
    gate.publish(vec![clean_sample(&gate)]).unwrap();
    invoke(handle, 6, Status::Ok);

    let observed = stop_sample(&gate);
    gate.publish(vec![observed]).unwrap();
    first.finish(handle);
    second.finish(handle);
    assert_eq!(previous, [0x6a, 1]);
    #[cfg(windows)]
    if std::env::var_os("VMKEK_A03_RESAMPLE_READY").is_some() {
        observer::wait_for("VMKEK_A03_RESAMPLE_READY", "VMKEK_A03_RESAMPLE_RELEASE");
    }
    gate.publish(vec![clean_sample(&gate)]).unwrap();
    assert!(matches!(runtime.begin(id(7)), Err(Status::Denied)));
    invoke(handle, 8, Status::Denied);
    assert_eq!(vmk_shutdown(handle), Status::Ok as u32);

    let fresh = signed_gate(ObservationProfile::Offline, ObservationMode::Enforce);
    fresh.publish(vec![clean_sample(&fresh)]).unwrap();
    let handle = initialize_observed_lab(&bytes, &program, fresh).unwrap();
    invoke(handle, 9, Status::Ok);
    assert_eq!(vmk_shutdown(handle), Status::Ok as u32);
    let revision = gate.policy.revision();
    let digest = revision
        .digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let proof = format!(
        "active=2 reentry=committed cancelled=2 outputs=intact inconclusive=recovered fresh=allowed policy_sha256={digest} epoch={}\n",
        revision.epoch
    );
    if let Some(record) = std::env::var_os("VMKEK_A07_RESPONSE_RECORD") {
        std::fs::write(record, proof).unwrap();
    } else {
        print!("{proof}");
    }
}

fn clean_sample(gate: &ObservationGate) -> ObservationSample {
    #[cfg(windows)]
    if std::env::var_os("VMKEK_T6_READY").is_some() {
        let sample =
            super::super::windows::debugger_attachment_sample(gate.begin_sample()).unwrap();
        assert_eq!(
            sample.record.finding,
            ObservationFinding::NotObservedWithinScope
        );
        return sample;
    }
    gate.begin_sample()
        .attachment(Observation::NotObservedWithinScope, ObservationReason::None)
}

fn stop_sample(gate: &ObservationGate) -> ObservationSample {
    #[cfg(windows)]
    if std::env::var_os("VMKEK_T6_READY").is_some() {
        observer::wait_for("VMKEK_T6_READY", "VMKEK_T6_RELEASE");
        let sample =
            super::super::windows::debugger_attachment_sample(gate.begin_sample()).unwrap();
        assert_eq!(sample.record.finding, ObservationFinding::Observed);
        return sample;
    }
    gate.begin_sample()
        .attachment(Observation::Observed, ObservationReason::None)
}

struct Held {
    tag: u8,
    release: SyncSender<()>,
    thread: JoinHandle<[u8; 2]>,
}

impl Held {
    fn start(handle: u64, tag: u8, reenter: Option<u8>) -> Self {
        let (arrived, wait) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            BEFORE_COMMIT.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    if let Some(tag) = reenter {
                        invoke(handle, tag, Status::Ok);
                    }
                    arrived.send(()).unwrap();
                    resume.recv_timeout(Duration::from_secs(5)).unwrap();
                }));
            });
            invoke(handle, tag, Status::Denied)
        });
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            tag,
            release,
            thread,
        }
    }

    fn finish(self, handle: u64) {
        self.release.send(()).unwrap();
        assert_eq!(self.thread.join().unwrap(), [0xa5; 2]);
        assert_eq!(
            crate::vmk_cancel(handle, id(self.tag)),
            Status::NotFound as u32
        );
    }
}

fn id(tag: u8) -> VmkRequestId {
    VmkRequestId { bytes: [tag; 16] }
}

pub(super) fn invoke(handle: u64, tag: u8, expected: Status) -> [u8; 2] {
    let input = [0x6a, tag];
    let mut output = [0xa5; 2];
    let args = VmkInvokeV1 {
        size: size_of::<VmkInvokeV1>() as u32,
        abi_version: ABI_VERSION,
        request_id: id(tag),
        scalars: std::ptr::null(),
        scalar_count: 0,
        input: VmkBytes {
            data: input.as_ptr(),
            len: 2,
        },
        output: VmkOutput {
            data: output.as_mut_ptr(),
            capacity: 2,
        },
    };
    let sentinel = VmkInvokeResultV1 {
        size: size_of::<VmkInvokeResultV1>() as u32,
        abi_version: ABI_VERSION,
        scalar: VmkScalar {
            kind: 0,
            reserved: 0,
            bits: 0,
        },
        output_len: 99,
    };
    let mut result = sentinel;
    // SAFETY: all arguments and disjoint buffers remain live for this ABI call.
    let status = unsafe { vmk_invoke(handle, &args, &mut result) };
    assert_eq!(status, expected as u32);
    if expected == Status::Ok {
        assert_eq!(result.output_len, 2);
        assert_eq!(output, input);
    } else {
        assert_eq!(result, sentinel);
        assert_eq!(output, [0xa5; 2]);
    }
    output
}
