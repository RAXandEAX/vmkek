use std::{mem::size_of, sync::Arc};

use p256::ecdsa::SigningKey;
use sha2::{Digest as _, Sha256};
use vmkek_protocol::{
    detection::{
        BuildRange, DetectionPolicy, ImagePurpose, ImageRule, ObservationDecision, ObservationMode,
        ObservationReaction, ObservationRule, ObservationSettings, SignedDetectionPolicy,
    },
    lab::{Instruction, LabProgram},
    public_key_id, Budgets, Capability, Profile, VmDescriptor, VmForm, COPY_INPUT_CAPABILITY,
};

use super::*;
use crate::{
    initialize_observed_lab, runtime_observation, vmk_invoke, vmk_shutdown, Status, VmkBytes,
    VmkInvokeResultV1, VmkInvokeV1, VmkOutput, VmkRequestId, VmkScalar, ABI_VERSION,
};

const APP: [u8; 16] = [1; 16];
const BUILD_ID: [u8; 16] = [2; 16];

fn signed_gate(profile: ObservationProfile, mode: ObservationMode) -> Arc<ObservationGate> {
    signed_gate_at(profile, mode, Instant::now(), false)
}

fn signed_gate_at(
    profile: ObservationProfile,
    mode: ObservationMode,
    anchor: Instant,
    include_code: bool,
) -> Arc<ObservationGate> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    let build = super::windows::native_windows_build().unwrap();
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    let build = 26_300;
    let key = SigningKey::from_slice(&[0x31; 32]).unwrap();
    let mut rules = vec![ObservationRule {
        signal_id: SignalId::DEBUGGER,
        required: true,
        reaction: ObservationReaction::Stop,
    }];
    let mut images = Vec::new();
    if include_code {
        rules.push(ObservationRule {
            signal_id: SignalId {
                kind: ObservationKind::CodeIntegrity,
                rule_id: 1,
            },
            required: true,
            reaction: ObservationReaction::Stop,
        });
        images.push(ImageRule {
            id: 1,
            purpose: ImagePurpose::CodeIntegrity,
            file_digest: [1; 32],
            code_rva: 4096,
            code_len: 1,
            code_digest: [2; 32],
        });
    }
    let policy = DetectionPolicy {
        app_id: APP,
        build_id: BUILD_ID,
        key_id: public_key_id(key.verifying_key()),
        epoch: 7,
        issued_ms: 100,
        expires_ms: 60_000,
        windows_builds: BuildRange {
            first: build,
            last: build,
        },
        artifacts: vec![],
        images,
    };
    let settings = ObservationSettings {
        profile,
        mode,
        max_age_ms: 30_000,
        rules,
    };
    let supported = &[
        ObservationKind::DebuggerAttachment,
        ObservationKind::CodeIntegrity,
    ];
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let observation = {
        use vmkek_protocol::detection::LinuxProfileContext;
        let release = super::linux::native_release().unwrap();
        let signed =
            SignedDetectionPolicy::sign_for_linux_profile(policy, settings, release, &key).unwrap();
        signed
            .verify_for_linux_profile(
                key.verifying_key(),
                LinuxProfileContext {
                    app_id: APP,
                    build_id: BUILD_ID,
                    epoch_floor: 7,
                    now_ms: 100,
                    release,
                    profile,
                    supported,
                    previous: None,
                },
            )
            .unwrap()
            .observation_policy()
            .unwrap()
    };
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    let observation = {
        use vmkek_protocol::detection::{PolicyContext, ProfileContext};
        let signed = SignedDetectionPolicy::sign_for_profile(policy, settings, &key).unwrap();
        signed
            .verify_for_profile(
                key.verifying_key(),
                ProfileContext {
                    policy: PolicyContext {
                        app_id: APP,
                        build_id: BUILD_ID,
                        epoch_floor: 7,
                        windows_build: build,
                        now_ms: 100,
                    },
                    profile,
                    supported,
                    previous: None,
                },
            )
            .unwrap()
            .observation_policy()
            .unwrap()
    };
    Arc::new(ObservationGate::new(observation, anchor))
}

fn lab_fixture() -> (VmDescriptor, Vec<u8>) {
    let program = LabProgram {
        arguments: vec![],
        result: None,
        instructions: vec![Instruction::CopyInput, Instruction::Return],
    }
    .encode()
    .unwrap();
    let descriptor = VmDescriptor {
        abi_version: vmkek_protocol::ABI_VERSION,
        app_id: APP,
        build_id: BUILD_ID,
        function_id: [3; 16],
        generation_id: [4; 16],
        form: VmForm::Stack,
        depth: 2,
        capabilities: vec![Capability {
            id: COPY_INPUT_CAPABILITY,
            required: true,
        }],
        program_sha256: Sha256::digest(&program).into(),
        budgets: Budgets::default(),
        profile: Profile::Lab,
        extensions: vec![],
    };
    (descriptor, program)
}

#[test]
fn observed_offline_launcher_applies_policy_before_vmk_invoke() {
    let (descriptor, program) = lab_fixture();
    let gate = signed_gate(ObservationProfile::Offline, ObservationMode::Enforce);
    let bytes = descriptor.encode().unwrap();
    let mismatched = VmDescriptor {
        build_id: [3; 16],
        ..descriptor
    };
    assert_eq!(
        initialize_observed_lab(&mismatched.encode().unwrap(), &program, gate.clone()),
        Err(Status::InvalidPackage),
    );
    assert_eq!(
        initialize_observed_lab(
            &bytes,
            &program,
            signed_gate(ObservationProfile::Online, ObservationMode::Enforce),
        ),
        Err(Status::InvalidPackage),
    );
    let handle = initialize_observed_lab(&bytes, &program, gate.clone()).unwrap();
    let call = |expected| {
        let mut output = [0u8; 1];
        let input = [42u8];
        let args = VmkInvokeV1 {
            size: size_of::<VmkInvokeV1>() as u32,
            abi_version: ABI_VERSION,
            request_id: VmkRequestId { bytes: [1; 16] },
            scalars: std::ptr::null(),
            scalar_count: 0,
            input: VmkBytes {
                data: input.as_ptr(),
                len: 1,
            },
            output: VmkOutput {
                data: output.as_mut_ptr(),
                capacity: 1,
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
        // SAFETY: args and its buffers remain live and disjoint for this call.
        assert_eq!(
            unsafe { vmk_invoke(handle, &args, &mut result) },
            expected as u32
        );
        if expected == Status::Ok {
            assert_eq!(result.output_len, 1);
            assert_eq!(output, input);
        } else {
            assert_eq!(result, sentinel);
            assert_eq!(output, [0]);
        }
    };
    call(Status::Unavailable);
    let inconclusive = gate
        .begin_sample()
        .attachment(Observation::Inconclusive, ObservationReason::ApiFailure);
    gate.publish(vec![inconclusive]).unwrap();
    assert_eq!(
        runtime_observation(handle, SignalId::DEBUGGER).unwrap(),
        Some(ObservationAssessment {
            sample: Some(inconclusive),
            decision: ObservationDecision::Unavailable(ObservationReason::ApiFailure),
        }),
    );
    call(Status::Unavailable);
    let clean = gate
        .begin_sample()
        .attachment(Observation::NotObservedWithinScope, ObservationReason::None);
    gate.publish(vec![clean]).unwrap();
    call(Status::Ok);
    let invalid_future = ObservationSample {
        sampled_at: Duration::MAX - Duration::from_secs(1),
        valid_until: Duration::MAX,
        ..clean
    };
    assert_eq!(
        gate.publish(vec![invalid_future]),
        Err(ProtocolError::Invalid)
    );
    assert_eq!(
        gate.assessment(SignalId::DEBUGGER).unwrap().sample,
        Some(clean)
    );
    assert_eq!(
        gate.publish(vec![inconclusive]),
        Err(ProtocolError::Binding)
    );
    call(Status::Ok);
    let observed = gate
        .begin_sample()
        .attachment(Observation::Observed, ObservationReason::None);
    gate.publish(vec![observed]).unwrap();
    call(Status::Denied);
    assert_eq!(vmk_shutdown(handle), Status::Ok as u32);
}

#[cfg(any(
    all(windows, target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "x86_64")
))]
mod release;
mod response;
pub(crate) use response::pause_before_offline_commit;

#[test]
fn observed_offline_launcher_rejects_an_expired_gate() {
    let (descriptor, program) = lab_fixture();
    let gate = signed_gate_at(
        ObservationProfile::Offline,
        ObservationMode::Observe,
        Instant::now() - Duration::from_secs(60),
        false,
    );
    assert_eq!(
        initialize_observed_lab(&descriptor.encode().unwrap(), &program, gate),
        Err(Status::Expired),
    );
}

#[test]
fn observation_samples_are_bound_to_the_exact_signed_revision() {
    let anchor = Instant::now();
    let observe = signed_gate_at(
        ObservationProfile::Offline,
        ObservationMode::Observe,
        anchor,
        false,
    );
    let enforce = signed_gate_at(
        ObservationProfile::Offline,
        ObservationMode::Enforce,
        anchor,
        false,
    );
    let observed = observe
        .begin_sample()
        .attachment(Observation::Observed, ObservationReason::None);
    assert_eq!(enforce.publish(vec![observed]), Err(ProtocolError::Binding));
    assert_eq!(
        enforce.decision(),
        ObservationDecision::Unavailable(ObservationReason::Missing)
    );
}

#[test]
fn observation_sample_time_uses_one_process_clock() {
    let older_wall_anchor = signed_gate_at(
        ObservationProfile::Offline,
        ObservationMode::Enforce,
        Instant::now() - Duration::from_secs(5),
        false,
    );
    let newer_wall_anchor = signed_gate(ObservationProfile::Offline, ObservationMode::Enforce);
    let earlier = older_wall_anchor.begin_sample().sampled_at;
    let later = newer_wall_anchor.begin_sample().sampled_at;
    assert!(
        earlier <= later,
        "sample timestamps must use the same origin"
    );
}

#[test]
fn cached_expired_code_does_not_drop_fresh_debugger_sample() {
    let gate = signed_gate_at(
        ObservationProfile::Offline,
        ObservationMode::Enforce,
        Instant::now(),
        true,
    );
    let window = gate.begin_sample();
    let mut code = window.sample(
        ObservationRecord {
            kind: ObservationKind::CodeIntegrity,
            rule_id: 1,
            finding: ObservationFinding::NotObservedWithinScope,
        },
        ObservationReason::None,
    );
    code.valid_until = code.sampled_at + Duration::from_nanos(1);
    let debug = gate
        .begin_sample()
        .attachment(Observation::Observed, ObservationReason::None);
    gate.publish(vec![debug, code]).unwrap();
    assert_eq!(
        gate.assessment(code.signal_id()).unwrap().decision,
        ObservationDecision::Unavailable(ObservationReason::Stale)
    );
    assert_eq!(gate.decision(), ObservationDecision::RequestOwnStop(debug));
}
