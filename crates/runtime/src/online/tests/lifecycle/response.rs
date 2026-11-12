use super::*;
use crate::{observations::ObservationReport, runtime_observation_report};

mod config {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_support/response_config.rs"
    ));
}

#[test]
#[ignore = "requires A07 loopback TLS and the owned Windows observer"]
fn native_response_active_reentry_and_parallel() {
    let (handle, digest) = open_observed();
    invoke_expect(handle.0, request(61), Status::Ok);
    let first = Held::start(handle.0, 62, Some(request(63)));
    let second = Held::start(handle.0, 64, None);
    wait_for_attach();
    wait_for_report(handle.0, ObservationReport::Acknowledged);
    first.finish(handle.0);
    second.finish(handle.0);
    invoke_expect(handle.0, request(65), Status::Denied);
    record(
        "active=2 reentry=committed cancelled=2 outputs=intact wipes=verified report=acknowledged",
        digest,
    );
}

#[test]
#[ignore = "requires A07 loopback TLS transport controls and the owned Windows observer"]
fn native_response_loss_keeps_local_denial_and_allows_fresh_session() {
    let control = std::path::PathBuf::from(std::env::var_os("VMKEK_A07_ONLINE_CONTROL").unwrap());
    let (handle, digest) = open_observed();
    invoke_expect(handle.0, request(71), Status::Ok);
    set_transport(&control, "transport-off", "transport-offline");
    wait_for_attach();
    wait_for_report(handle.0, ObservationReport::Failed(Status::Unavailable));
    invoke_expect(handle.0, request(72), Status::Denied);
    invoke_expect(handle.0, request(73), Status::Denied);
    set_transport(&control, "transport-on", "transport-online");
    let base = std::env::var("VMKEK_A07_ONLINE_CONFIG").unwrap();
    let fresh = Handle(native_open(&base));
    invoke_expect(fresh.0, request(74), Status::Ok);
    invoke_expect(handle.0, request(75), Status::Denied);
    record(
        "transport=unavailable local_deny=latched outputs=intact same_license_fresh=allowed",
        digest,
    );
}

fn set_transport(control: &std::path::Path, command: &str, marker: &str) {
    assert!(!control.join(marker).exists());
    std::fs::write(control.join(command), []).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !control.join(marker).is_file() {
        assert!(
            Instant::now() < deadline,
            "fixture transport command not acknowledged"
        );
        std::thread::sleep(Duration::from_millis(15));
    }
}

fn open_observed() -> (Handle, vmkek_protocol::Digest) {
    let base = std::path::PathBuf::from(std::env::var_os("VMKEK_A07_ONLINE_CONFIG").unwrap());
    let build = crate::observations::windows::native_windows_build().unwrap();
    let (path, digest) = config::write(&base, build);
    let handle = Handle(native_open(path.to_str().unwrap()));
    std::fs::remove_file(path).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let runtime = state::get(handle.0).unwrap();
    loop {
        match runtime.begin(request(60)) {
            Ok(_) => break,
            Err(Status::Unavailable) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(15))
            }
            _ => panic!("initial clean observation unavailable"),
        }
    }
    (handle, digest)
}

fn wait_for_report(handle: VmkRuntime, expected: ObservationReport) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match runtime_observation_report(handle).unwrap() {
            result if result == expected => return,
            ObservationReport::NotCompleted if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(15));
            }
            report => panic!("native own-stop report: {report:?}"),
        }
    }
}

fn record(proof: &str, digest: vmkek_protocol::Digest) {
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let record = std::env::var_os("VMKEK_A07_RESPONSE_RECORD").unwrap();
    std::fs::write(
        record,
        format!("{proof} policy_sha256={digest} epoch={}\n", config::EPOCH),
    )
    .unwrap();
}

struct Held {
    id: VmkRequestId,
    release: SyncSender<()>,
    call: std::thread::JoinHandle<WipeObservation>,
}

impl Held {
    fn start(handle: VmkRuntime, tag: u8, reenter: Option<VmkRequestId>) -> Self {
        let id = request(tag);
        let (arrived, wait) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        let call = std::thread::spawn(move || {
            PROBE.with_borrow_mut(|slot| {
                *slot = Some(Probe {
                    at: Checkpoint::Decrypted,
                    arrived,
                    resume,
                    reenter: reenter.map(|id| (handle, id)),
                });
            });
            WIPE_OBSERVATION.with(|slot| slot.set(Some(WipeObservation::default())));
            invoke_expect(handle, id, Status::Denied);
            WIPE_OBSERVATION.with(|slot| slot.take().unwrap())
        });
        let (_, before) = wait.recv_timeout(Duration::from_secs(6)).unwrap();
        assert_eq!(before.count, [0, 0]);
        assert_eq!(before.failures, 0);
        Self { id, release, call }
    }

    fn finish(self, handle: VmkRuntime) {
        self.release.send(()).unwrap();
        let after = self.call.join().unwrap();
        assert_eq!(after.count, [1, 1]);
        assert_eq!(after.failures, 0);
        assert_eq!(vmk_cancel(handle, self.id), Status::NotFound as u32);
    }
}

mod observer {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_support/response_observer.rs"
    ));
}
fn wait_for_attach() {
    observer::wait_for("VMKEK_T6_READY", "VMKEK_T6_RELEASE");
}
