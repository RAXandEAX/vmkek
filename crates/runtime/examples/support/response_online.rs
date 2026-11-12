use super::*;
use std::{fs, path::PathBuf, time::Duration};
use vmkek_runtime::{
    observations::ObservationReport, runtime_observation_report, vmk_initialize, VmkInitializeV2,
    ONLINE_ABI_VERSION, PROFILE_ONLINE, SCALAR_I64,
};
mod config {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_support/response_config.rs"
    ));
}

pub(super) fn run(record: &mut File, mode: ObservationMode, scenario: &str) {
    assert_eq!(mode, ObservationMode::Enforce);
    let handle = initialize(record);
    if scenario == "online_late" {
        wait_for_sample(handle, false);
        assert_eq!(invoke_online(handle, 90), (Status::Ok as u32, true));
        writeln!(record, "online_clean_before_attach=true").unwrap();
    }
    phase(record, "idle");
    record.flush().unwrap();
    wait_for_release("VMKEK_T6_READY", "VMKEK_T6_RELEASE");
    phase(record, "protected_call");
    let assessment = wait_for_sample(handle, true);
    let sample = assessment.sample.unwrap();
    assert!(matches!(
        assessment.decision,
        ObservationDecision::RequestOwnStop(_)
    ));
    writeln!(
        record,
        "observation={:?} reason={:?} decision=RequestOwnStop tick_ms={}",
        sample.record.finding,
        sample.reason,
        tick()
    )
    .unwrap();
    let (status, output_check) = invoke_online(handle, 1);
    writeln!(record, "invoke_status={status} output_check={output_check}").unwrap();
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        match runtime_observation_report(handle).unwrap() {
            ObservationReport::Acknowledged => break,
            ObservationReport::NotCompleted if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(15));
            }
            result => panic!("own-stop acknowledgement: {result:?}"),
        }
    }
    assert_eq!(invoke_online(handle, 2), (Status::Denied as u32, true));
    writeln!(record, "online_report=acknowledged repeated_deny=true").unwrap();
    assert_eq!(vmk_shutdown(handle), Status::Ok as u32);
    phase(record, "shutdown");
}

fn wait_for_sample(
    handle: u64,
    attached: bool,
) -> vmkek_runtime::observations::ObservationAssessment {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(assessment) = runtime_observation(handle, SignalId::DEBUGGER).unwrap() {
            if (attached && matches!(assessment.decision, ObservationDecision::RequestOwnStop(_)))
                || (!attached && matches!(assessment.decision, ObservationDecision::ReportOnly(_)))
            {
                return assessment;
            }
        }
        assert!(
            Instant::now() < deadline,
            "native online debugger sample missing"
        );
        thread::sleep(Duration::from_millis(15));
    }
}

fn initialize(record: &mut File) -> u64 {
    let base = PathBuf::from(env::var_os("VMKEK_A07_ONLINE_CONFIG").unwrap());
    let (path, digest) = config::write(&base, native_windows_build().unwrap());
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    writeln!(
        record,
        "policy_sha256={digest} policy_epoch={}",
        config::EPOCH
    )
    .unwrap();
    let name = path.to_str().unwrap();
    let init = VmkInitializeV2 {
        size: size_of::<VmkInitializeV2>() as u32,
        abi_version: ONLINE_ABI_VERSION,
        profile: PROFILE_ONLINE,
        reserved: 0,
        config_path: VmkBytes {
            data: name.as_ptr(),
            len: name.len() as u64,
        },
        reserved_tail: [0; 2],
    };
    let mut handle = 0;
    // SAFETY: the initializer and UTF-8 path remain live until the ABI returns.
    let status = unsafe { vmk_initialize((&raw const init).cast(), &mut handle) };
    fs::remove_file(&path).unwrap();
    assert_eq!(status, Status::Ok as u32);
    handle
}

fn invoke_online(handle: u64, tag: u8) -> (u32, bool) {
    let value = VmkScalar {
        kind: SCALAR_I64,
        reserved: 0,
        bits: (-17i64) as u64,
    };
    let input = [0xcc, 42];
    let mut output = [0xa5u8; 2];
    let args = VmkInvokeV1 {
        size: size_of::<VmkInvokeV1>() as u32,
        abi_version: ABI_VERSION,
        request_id: VmkRequestId { bytes: [tag; 16] },
        scalars: &value,
        scalar_count: 1,
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
    // SAFETY: all ABI inputs and output buffers are live and disjoint.
    let status = unsafe { vmk_invoke(handle, &args, &mut result) };
    let intact = if status == Status::Ok as u32 {
        result.scalar == value && result.output_len == 2 && output == input
    } else {
        result == sentinel && output == [0xa5; 2]
    };
    (status, intact)
}
