use vmkek_protocol::{
    lab::{Instruction, LabProgram},
    public_key_id, Budgets, GrantBinding, ModuleManifest, ABI_VERSION,
};

use super::*;

pub(super) mod lifecycle;

const KEY: [u8; 32] = [20; 32];

fn fixture(bad_tag: bool) -> (Vec<u8>, GrantPayload, ModuleSelection, SigningKey) {
    let code = LabProgram {
        arguments: vec![],
        result: None,
        instructions: vec![Instruction::Return],
    }
    .encode()
    .unwrap();
    let descriptor = VmDescriptor {
        abi_version: ABI_VERSION,
        app_id: [1; 16],
        build_id: [2; 16],
        function_id: [3; 16],
        generation_id: [4; 16],
        form: VmForm::Stack,
        depth: 2,
        capabilities: vec![],
        program_sha256: Sha256::digest(&code).into(),
        budgets: Budgets::default(),
        profile: Profile::Online,
        extensions: vec![],
    };
    let signer = SigningKey::from_slice(&[5; 32]).unwrap();
    let mut manifest = ModuleManifest {
        descriptor_sha256: descriptor.sha256().unwrap(),
        module_id: [6; 16],
        module_version: 1,
        ciphertext_sha256: [0; 32],
        ciphertext_size: code.len() as u32,
        nonce: [7; 12],
        tag: [0; 16],
        signing_key_id: public_key_id(signer.verifying_key()),
        purpose: ModulePurpose::Bytecode,
        not_before_ms: 10,
        expires_at_ms: 100,
        extensions: vec![],
    };
    let mut ciphertext = code;
    manifest.tag = ChaCha20Poly1305::new((&KEY).into())
        .encrypt_in_place_detached(
            (&manifest.nonce).into(),
            &manifest.authentication_data().unwrap(),
            &mut ciphertext,
        )
        .unwrap()
        .into();
    if bad_tag {
        manifest.tag[0] ^= 1;
    }
    manifest.ciphertext_sha256 = Sha256::digest(&ciphertext).into();
    let signed = SignedModuleManifest::sign(manifest, &signer).unwrap();
    let selection = ModuleSelection {
        module_id: [6; 16],
        module_version: 1,
        manifest_sha256: Sha256::digest(signed.as_bytes()).into(),
    };
    let frame = PackageFrame {
        descriptor: &descriptor.encode().unwrap(),
        manifest: signed.as_bytes(),
        ciphertext: &ciphertext,
    }
    .encode()
    .unwrap();
    let grant = GrantPayload {
        binding: GrantBinding {
            session_id: [8; 16],
            device_id: [9; 16],
            license_id: [10; 16],
            app_id: descriptor.app_id,
            build_id: descriptor.build_id,
            generation_id: descriptor.generation_id,
        },
        policy_epoch: 1,
        sequence: 1,
        issued_at_ms: 20,
        lifetime_ms: 30_000,
        permissions: vec![Permission {
            kind: PermissionKind::Function,
            id: descriptor.function_id,
        }],
        signing_key_id: [0; 32],
        extensions: vec![],
    };
    (frame, grant, selection, signer)
}

#[test]
fn online_runtime_independently_rejects_signed_bad_tag_wrong_key_and_wrong_grant() {
    let (frame, mut grant, selection, signer) = fixture(false);
    let trusted = signer.verifying_key();
    assert!(
        authenticate_module(&frame, &KEY, &grant, Selection::Fixed(selection), trusted).is_ok()
    );
    let (bad_tag, _, bad_selection, _) = fixture(true);
    assert!(matches!(
        authenticate_module(
            &bad_tag,
            &KEY,
            &grant,
            Selection::Fixed(bad_selection),
            trusted
        ),
        Err(Status::InvalidPackage)
    ));
    assert!(matches!(
        authenticate_module(
            &frame,
            &[99; 32],
            &grant,
            Selection::Fixed(selection),
            trusted
        ),
        Err(Status::InvalidPackage)
    ));
    grant.binding.build_id = [98; 16];
    assert!(matches!(
        authenticate_module(&frame, &KEY, &grant, Selection::Fixed(selection), trusted),
        Err(Status::InvalidPackage)
    ));
}

fn test_runtime(descriptor: &VmDescriptor, plaintext: &[u8]) -> Runtime {
    let (program, reservation) = verify_program(descriptor, plaintext).unwrap();
    Runtime::from_generation(
        Generation::new(
            descriptor.generation_id,
            descriptor.form,
            program,
            descriptor.budgets.deadline_ms,
            usize::from(descriptor.budgets.active_contexts),
            reservation,
        ),
        None,
    )
}

#[test]
fn renewal_does_not_extend_lease_with_a_wrong_key_or_different_identity() {
    use crate::VmkRequestId;

    let (frame, grant, selection, signer) = fixture(false);
    let trusted = signer.verifying_key();
    let module =
        authenticate_module(&frame, &KEY, &grant, Selection::Fixed(selection), trusted).unwrap();
    let initial = Instant::now() + Duration::from_secs(10);
    let replacement = Instant::now() + Duration::from_secs(20);
    let runtime = Arc::new(test_runtime(&module.descriptor, &module.plaintext));
    runtime.set_lease(initial).unwrap();
    let call = runtime.begin(VmkRequestId { bytes: [1; 16] }).unwrap();
    assert_eq!(call.lease, Some(initial));
    let refresh = authenticate_module(
        &frame,
        &[98; 32],
        &grant,
        Selection::Fixed(selection),
        trusted,
    )
    .map(|module| (module.identity, replacement));
    assert_eq!(
        publish_refresh(&runtime, module.identity, refresh),
        Err(Status::InvalidPackage)
    );
    assert_eq!(
        call.commit(|| panic!("failed renewal must not publish")),
        Err(Status::InvalidPackage)
    );

    let runtime = Arc::new(test_runtime(&module.descriptor, &module.plaintext));
    runtime.set_lease(initial).unwrap();
    assert_eq!(
        publish_refresh(
            &runtime,
            module.identity,
            Ok((module.identity, replacement))
        ),
        Ok(())
    );
    let call = runtime.begin(VmkRequestId { bytes: [2; 16] }).unwrap();
    assert_eq!(call.lease, Some(replacement));
    let different = ModuleIdentity {
        program: [99; 32],
        ..module.identity
    };
    assert_eq!(
        publish_refresh(&runtime, module.identity, Ok((different, replacement))),
        Err(Status::InvalidPackage)
    );
    assert_eq!(
        call.commit(|| panic!("different module must not publish")),
        Err(Status::InvalidPackage)
    );
}

#[test]
#[ignore = "requires the explicitly provisioned R12 TLS/PostgreSQL fixture"]
fn native_ffi_initializes_and_invokes_online() {
    let config = std::env::var("VMKEK_R12_NATIVE_CONFIG").unwrap();
    let handle = native_open(&config);
    native_invoke(handle, 7);
    assert_eq!(crate::vmk_shutdown(handle), Status::Ok as u32);
}

#[test]
#[ignore = "requires the explicitly provisioned R13 generation catalog and TLS/PostgreSQL fixture"]
fn native_ffi_negotiates_distinct_launches_and_swaps_generation() {
    use crate::{state, vmk_shutdown, VmkRequestId};
    let startup = std::env::var("VMKEK_R13_NATIVE_CONFIG").unwrap();
    let rotation = std::env::var("VMKEK_R13_SWAP_CONFIG").unwrap();
    let generation = |handle| {
        let runtime = state::get(handle).unwrap();
        runtime
            .begin(VmkRequestId { bytes: [8; 16] })
            .map(|call| call.generation.identity())
    };

    let first = native_open(&startup);
    let (first_id, first_form) = generation(first).unwrap();
    assert_eq!(first_form, VmForm::Stack);
    native_invoke(first, 9);
    assert_eq!(vmk_shutdown(first), Status::Ok as u32);

    let second = native_open(&rotation);
    let (second_id, second_form) = generation(second).unwrap();
    assert_eq!(second_form, VmForm::Register);
    assert_ne!(first_id, second_id);
    native_invoke(second, 10);
    let deadline = Instant::now() + Duration::from_secs(20);
    let (third_id, third_form) = loop {
        match generation(second) {
            Ok((id, form)) if id != second_id => break (id, form),
            Ok(_) | Err(Status::Unavailable) if Instant::now() < deadline => {}
            result => panic!("planned generation swap did not complete: {result:?}"),
        }
        thread::sleep(Duration::from_millis(50));
    };
    assert_ne!(first_id, third_id);
    assert_eq!(third_form, VmForm::Stack);
    eprintln!("R13 forms Stack/Register/Stack, distinct generation IDs, equivalent i64 output");
    native_invoke(second, 11);
    assert_eq!(vmk_shutdown(second), Status::Ok as u32);
}

fn native_open(config: &str) -> crate::VmkRuntime {
    use crate::{vmk_initialize, VmkBytes, VmkInitializeV2, ONLINE_ABI_VERSION, PROFILE_ONLINE};
    let init = VmkInitializeV2 {
        size: size_of::<VmkInitializeV2>() as u32,
        abi_version: ONLINE_ABI_VERSION,
        profile: PROFILE_ONLINE,
        reserved: 0,
        config_path: VmkBytes {
            data: config.as_ptr(),
            len: config.len() as u64,
        },
        reserved_tail: [0; 2],
    };
    let mut handle = 0;
    assert_eq!(
        unsafe { vmk_initialize((&raw const init).cast(), &mut handle) },
        Status::Ok as u32
    );
    handle
}

fn native_invoke(handle: crate::VmkRuntime, request: u8) {
    native_invoke_expect(handle, request, Status::Ok);
}

fn native_invoke_expect(handle: crate::VmkRuntime, request: u8, expected: Status) {
    use crate::{
        vmk_invoke, VmkBytes, VmkInvokeResultV1, VmkInvokeV1, VmkOutput, VmkRequestId, VmkScalar,
        ABI_VERSION, SCALAR_I64, SCALAR_NONE,
    };
    use std::ptr::{null, null_mut};

    let argument = VmkScalar {
        kind: SCALAR_I64,
        reserved: 0,
        bits: (-17i64) as u64,
    };
    let call = VmkInvokeV1 {
        size: size_of::<VmkInvokeV1>() as u32,
        abi_version: ABI_VERSION,
        request_id: VmkRequestId {
            bytes: [request; 16],
        },
        scalars: &argument,
        scalar_count: 1,
        input: VmkBytes {
            data: null(),
            len: 0,
        },
        output: VmkOutput {
            data: null_mut(),
            capacity: 0,
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
    assert_eq!(
        unsafe { vmk_invoke(handle, &call, &mut result) },
        expected as u32
    );
    if expected == Status::Ok {
        assert_eq!(result.scalar, argument);
    } else {
        assert_eq!(result, sentinel);
    }
}

#[test]
fn initialization_reserves_process_quota_before_touching_configuration() {
    const CHILD: &str = "VMKEK_R12_QUOTA_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "online::tests::initialization_reserves_process_quota_before_touching_configuration"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }
    let quota = Reservation::new(vmkek_protocol::MAX_VM_MEMORY_BYTES, false).unwrap();
    assert!(matches!(
        initialize("relative-config"),
        Err(Status::ResourceLimit)
    ));
    drop(quota);
    assert!(matches!(
        initialize("relative-config"),
        Err(Status::InvalidArgument)
    ));
}

#[test]
#[ignore = "requires a live isolated R14 fixture with revoke control"]
fn native_ffi_requests_new_key_and_denies_after_revoke() {
    let config = std::env::var("VMKEK_R14_NATIVE_CONFIG").unwrap();
    let control = std::path::PathBuf::from(std::env::var_os("VMKEK_R14_FIXTURE_CONTROL").unwrap());
    let handle = native_open(&config);
    let runtime = crate::state::get(handle).unwrap();
    let call = runtime
        .begin(crate::VmkRequestId { bytes: [19; 16] })
        .unwrap();
    assert!(matches!(
        call.generation.code,
        crate::state::GenerationCode::Online(_)
    ));
    drop(call);
    native_invoke(handle, 20);
    native_invoke(handle, 21);
    std::fs::write(control.join("revoke"), []).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !control.join("revoked").is_file() {
        assert!(
            Instant::now() < deadline,
            "isolated fixture did not acknowledge revoke"
        );
        thread::sleep(Duration::from_millis(20));
    }
    native_invoke_expect(handle, 22, Status::Denied);
    native_invoke_expect(handle, 23, Status::Denied);
    assert_eq!(crate::vmk_shutdown(handle), Status::Ok as u32);
}

#[test]
fn retained_ciphertext_permits_limit_frames_and_aggregate_bytes() {
    const CHILD: &str = "VMKEK_R14_PREFETCH_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "online::tests::retained_ciphertext_permits_limit_frames_and_aggregate_bytes",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }

    let frames: Vec<_> = (0..MAX_PREFETCH_FRAMES)
        .map(|_| FramePermit::new(1).unwrap())
        .collect();
    assert!(matches!(FramePermit::new(1), Err(Status::ResourceLimit)));
    drop(frames);
    let frame = FramePermit::new(MAX_BODY_BYTES).unwrap();
    assert!(matches!(FramePermit::new(1), Err(Status::ResourceLimit)));
    drop(frame);
    assert!(FramePermit::new(MAX_BODY_BYTES).is_ok());
}

#[test]
#[ignore = "requires an isolated R14 fixture and key-open stall control"]
fn native_ffi_key_timeout_clears_authority() {
    let config = std::env::var("VMKEK_R14_NATIVE_CONFIG").unwrap();
    let control = std::path::PathBuf::from(std::env::var_os("VMKEK_R14_FIXTURE_CONTROL").unwrap());
    let handle = native_open(&config);
    native_invoke(handle, 27);
    std::fs::write(control.join("stall-request"), []).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !control.join("stalled").is_file() {
        assert!(
            Instant::now() < deadline,
            "isolated fixture did not acknowledge the stall"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let started = Instant::now();
    native_invoke_expect(handle, 28, Status::Unavailable);
    assert!(started.elapsed() >= Duration::from_secs(4));
    let retry = Instant::now();
    native_invoke_expect(handle, 29, Status::Unavailable);
    assert!(retry.elapsed() < Duration::from_secs(1));
    assert_eq!(crate::vmk_shutdown(handle), Status::Ok as u32);
}

#[derive(Clone, Copy, Default)]
struct WipeObservation {
    count: [usize; 2],
    failures: usize,
}

thread_local! {
    static WIPE_OBSERVATION: std::cell::Cell<Option<WipeObservation>> = const { std::cell::Cell::new(None) };
}

pub(super) fn observe_wipe(kind: usize, bytes: &[u8]) {
    WIPE_OBSERVATION.with(|probe| {
        if let Some(mut observation) = probe.get() {
            observation.count[kind] += 1;
            if bytes.is_empty() || bytes.iter().any(|byte| *byte != 0) {
                observation.failures += 1;
            }
            probe.set(Some(observation));
        }
    });
}

#[test]
fn owned_key_and_plaintext_wipe_before_free_on_completion_and_unwind() {
    let (frame, grant, selection, signer) = fixture(false);
    let trusted = signer.verifying_key();
    let mut canary = KEY;
    canary[16..].fill(0xa5);

    WIPE_OBSERVATION.with(|probe| probe.set(Some(WipeObservation::default())));
    let key = OwnedKey(Box::new(canary));
    assert_ne!(key.0[..16], key.0[16..]);
    drop(key);
    let module =
        authenticate_module(&frame, &KEY, &grant, Selection::Fixed(selection), trusted).unwrap();
    assert!(module.plaintext.iter().any(|byte| *byte != 0));
    drop(module);

    // The bad tag fails after the allocation exists, then frees it via Drop.
    assert!(matches!(
        authenticate_module(
            &frame,
            &canary,
            &grant,
            Selection::Fixed(selection),
            trusted
        ),
        Err(Status::InvalidPackage)
    ));
    let panic = std::panic::catch_unwind(|| {
        let _key = OwnedKey(Box::new(canary));
        let _plaintext = Plaintext(vec![0x6b; 79]);
        panic!("owned synthetic R14 unwind");
    });
    assert!(panic.is_err());
    let observed = WIPE_OBSERVATION.with(|probe| probe.take().unwrap());
    assert_eq!(observed.count, [2, 3]);
    assert_eq!(observed.failures, 0);
}

#[test]
#[ignore = "requires the final free generation in an isolated R14 catalog"]
fn native_ffi_no_choice_renews_ciphertext_generation() {
    let path = std::env::var("VMKEK_R13_SWAP_CONFIG").unwrap();
    let handle = native_open(&path);
    let runtime = crate::state::get(handle).unwrap();
    let snapshot = || {
        runtime
            .begin(crate::VmkRequestId { bytes: [31; 16] })
            .map(|call| (call.generation.identity(), call.lease.unwrap()))
    };
    let (identity, old_deadline) = snapshot().unwrap();
    native_invoke(handle, 32);
    let limit = Instant::now() + Duration::from_secs(20);
    loop {
        match snapshot() {
            Ok((current, deadline)) if deadline > old_deadline => {
                assert_eq!(current, identity);
                break;
            }
            Ok(_) | Err(Status::Unavailable) if Instant::now() < limit => {}
            result => panic!("no-choice did not renew the admitted generation: {result:?}"),
        }
        thread::sleep(Duration::from_millis(50));
    }
    native_invoke(handle, 33);
    assert_eq!(crate::vmk_shutdown(handle), Status::Ok as u32);
}

#[test]
#[ignore = "requires the native R15 hybrid TLS/PostgreSQL fixture"]
fn native_runtime_receipt_uses_current_session_without_opening_module() {
    use crate::{invoke_sample_receipt, VmkRequestId};

    let config = std::env::var("VMKEK_R15_NATIVE_CONFIG").unwrap();
    let pin = std::env::var("VMKEK_R15_NATIVE_RECEIPT_PIN").unwrap();
    let pin = VerifyingKey::from_sec1_bytes(&std::fs::read(pin).unwrap()).unwrap();
    let handle = native_open(&config);
    native_invoke(handle, 91);
    let runtime = crate::state::get(handle).unwrap();
    let generation = runtime
        .begin(VmkRequestId { bytes: [95; 16] })
        .map(|call| call.generation.identity().0)
        .unwrap();
    let request = VmkRequestId { bytes: [92; 16] };
    let job = SampleJob {
        job_id: [93; 16],
        units: 7,
    };

    let reserved: Vec<_> = (0..MAX_ACTIVE_CONTEXTS)
        .map(|_| Reservation::new(0, true).unwrap())
        .collect();
    assert_eq!(
        invoke_sample_receipt(handle, request, job, &pin, Duration::from_secs(5)),
        Err(Status::ResourceLimit),
    );
    drop(reserved);
    WIPE_OBSERVATION.with(|probe| probe.set(Some(WipeObservation::default())));
    let receipt =
        invoke_sample_receipt(handle, request, job, &pin, Duration::from_secs(5)).unwrap();
    let retry = invoke_sample_receipt(handle, request, job, &pin, Duration::from_secs(5)).unwrap();
    let observed = WIPE_OBSERVATION.with(|probe| probe.take().unwrap());
    assert_eq!(observed.count, [0, 0]);
    assert_eq!(receipt, retry);
    assert_eq!(receipt.binding.generation_id, generation);
    assert_eq!(receipt.job, job);
    assert_eq!(receipt.request_id, request.bytes);
    assert_eq!(receipt.value, 49);
    let cancelled = VmkRequestId { bytes: [96; 16] };
    let call = runtime.begin(cancelled).unwrap();
    runtime.cancel(cancelled).unwrap();
    assert_eq!(
        call.commit_receipt(Instant::now() + Duration::from_secs(1), receipt),
        Err(Status::Cancelled)
    );
    drop(call);
    native_invoke(handle, 94);
    let control = std::path::PathBuf::from(std::env::var_os("VMKEK_R15_NATIVE_CONTROL").unwrap());
    std::fs::write(control.join("stall-operation"), b"stall").unwrap();
    let ready = Instant::now() + Duration::from_secs(2);
    while !control.join("operation-stalled").exists() {
        assert!(Instant::now() < ready, "operation stall did not start");
        thread::sleep(Duration::from_millis(10));
    }
    let shorter = VmkRequestId { bytes: [97; 16] };
    assert_eq!(
        invoke_sample_receipt(handle, shorter, job, &pin, Duration::from_millis(150)),
        Err(Status::ResourceLimit),
    );
    let live = runtime.begin(VmkRequestId { bytes: [98; 16] }).unwrap();
    drop(live);
    let default = VmkRequestId { bytes: [99; 16] };
    assert_eq!(
        invoke_sample_receipt(handle, default, job, &pin, Duration::from_secs(5)),
        Err(Status::Unavailable),
    );
    native_invoke_expect(handle, 100, Status::Unavailable);
    assert_eq!(crate::vmk_shutdown(handle), Status::Ok as u32);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
#[ignore = "requires the native R17 TLS/PostgreSQL fixture and local trusted config copy"]
fn native_owned_code_stop_cancels_and_reports_without_permanent_revoke() {
    use crate::{
        observations::windows::{self, OwnedModule},
        VmkRequestId,
    };
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature};
    use std::{
        io::Write,
        sync::atomic::AtomicBool,
        time::{SystemTime, UNIX_EPOCH},
    };
    use vmkek_protocol::{
        detection::{BuildRange, DetectionPolicy, ImagePurpose, ImageRule, SignedDetectionPolicy},
        public_key_id,
        session_observation::{ObservationFinding, ObservationKind},
    };
    use zeroize::Zeroizing;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut std::ffi::c_void;
    }
    let base_path = std::path::PathBuf::from(std::env::var_os("VMKEK_R17_NATIVE_CONFIG").unwrap());
    let control = std::path::PathBuf::from(std::env::var_os("VMKEK_R17_NATIVE_CONTROL").unwrap());
    let mut config = Zeroizing::new(std::fs::read(&base_path).unwrap());
    assert_eq!(&config[..8], b"VMKR13\0\0");
    let app_id = config[8..24].try_into().unwrap();
    let build_id = config[24..40].try_into().unwrap();
    let pin_key = SigningKey::from_slice(&[0x72; 32]).unwrap();
    let pin = *pin_key.verifying_key();
    let build = windows::native_windows_build().unwrap();
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    // SAFETY: null asks for the owned test executable's already-loaded main module.
    let base = unsafe { GetModuleHandleW(std::ptr::null()) } as usize;
    assert_ne!(base, 0);
    let address = crate::vmk_initialize as *const () as usize;
    let code_rva = u32::try_from(address.checked_sub(base).unwrap()).unwrap();
    let image = std::env::current_exe().unwrap();
    let file_digest = Sha256::digest(std::fs::read(image).unwrap()).into();
    // SAFETY: the entry byte is within our own live executable function.
    let current_byte = unsafe { (address as *const u8).read() };
    let signed_mismatch: [u8; 32] = Sha256::digest([current_byte ^ 1]).into();
    let signed = |purpose, digest| {
        SignedDetectionPolicy::sign(
            DetectionPolicy {
                app_id,
                build_id,
                key_id: public_key_id(&pin),
                epoch: 1,
                issued_ms: now.saturating_sub(1000),
                expires_ms: now + 60_000,
                windows_builds: BuildRange {
                    first: build,
                    last: build,
                },
                artifacts: vec![],
                images: vec![ImageRule {
                    id: 1,
                    purpose,
                    file_digest: digest,
                    code_rva,
                    code_len: 1,
                    code_digest: signed_mismatch,
                }],
            },
            &pin_key,
        )
        .unwrap()
    };
    let flags = stop_policy::OWN_CODE;
    let consent = |policy: &SignedDetectionPolicy| -> [u8; 64] {
        let signature: Signature = pin_key
            .sign_prehash(&stop_policy::consent_digest(policy.as_bytes(), flags))
            .unwrap();
        signature.to_bytes().into()
    };
    let wrong_file = signed(ImagePurpose::CodeIntegrity, [0; 32]);
    let weak = signed(ImagePurpose::RegisteredInstrumentation, file_digest);
    for policy in [&wrong_file, &weak] {
        let checked = StopPolicy::new(
            policy.as_bytes(),
            pin,
            consent(policy),
            flags,
            app_id,
            build_id,
            1,
        )
        .unwrap();
        assert!(checked.stop_candidate(checked.sample()).is_none());
    }
    let policy = signed(ImagePurpose::CodeIntegrity, file_digest);
    let proof = consent(&policy);
    assert!(StopPolicy::new(
        policy.as_bytes(),
        pin,
        proof,
        stop_policy::DEBUGGER,
        app_id,
        build_id,
        1
    )
    .is_err());
    let checked =
        StopPolicy::new(policy.as_bytes(), pin, proof, flags, app_id, build_id, 1).unwrap();
    let observed = checked
        .stop_candidate(checked.sample())
        .expect("native owned exact file and code mismatch")
        .record;
    assert_eq!(observed.kind, ObservationKind::CodeIntegrity);
    assert_eq!(observed.finding, ObservationFinding::SignedMismatch);
    assert!(OwnedModule::from_address(address).is_ok());

    const TRUST_ROOT_OFFSET: usize = 8 + 5 * 16 + 8 + 16 + 65;
    const TRANSPORT_OFFSET: usize = TRUST_ROOT_OFFSET + 65 + 8 + 4 + 32;
    let mut reader = ConfigReader(&config[TRANSPORT_OFFSET..]);
    reader.field(64).unwrap();
    reader.field(253).unwrap();
    reader.field(16 * 1024).unwrap();
    let trust_offset = config.len() - reader.0.len();
    let base_length = config.len();
    config[..8].copy_from_slice(b"VMKR17\0\0");
    config.push(flags);
    config.extend(pin.to_encoded_point(false).as_bytes());
    config.extend(1u64.to_le_bytes());
    config.extend(proof);
    config.extend(
        u32::try_from(policy.as_bytes().len())
            .unwrap()
            .to_le_bytes(),
    );
    config.extend_from_slice(policy.as_bytes());
    let replacement_root = SigningKey::from_slice(&[0x73; 32]).unwrap();
    let active = SigningKey::from_slice(&[0x74; 32]).unwrap();
    let sec1 = |key: &VerifyingKey| -> [u8; 65] {
        key.to_encoded_point(false).as_bytes().try_into().unwrap()
    };
    for (next, revoked, admissible) in [
        (None, vec![], true),
        (Some(sec1(&pin)), vec![], false),
        (None, vec![public_key_id(&pin)], false),
    ] {
        let replacement = SignedTrustBundle::sign(
            vmkek_protocol::TrustBundle {
                app_id,
                epoch: 1,
                active: sec1(active.verifying_key()),
                next,
                revoked,
                root_key_id: public_key_id(replacement_root.verifying_key()),
                extensions: vec![],
            },
            &replacement_root,
        )
        .unwrap();
        let mut alternate = Zeroizing::new(config[..trust_offset].to_vec());
        alternate[TRUST_ROOT_OFFSET..TRUST_ROOT_OFFSET + 65]
            .copy_from_slice(&sec1(replacement_root.verifying_key()));
        alternate.extend(
            u32::try_from(replacement.as_bytes().len())
                .unwrap()
                .to_le_bytes(),
        );
        alternate.extend_from_slice(replacement.as_bytes());
        alternate.extend_from_slice(&config[base_length..]);
        let result = Configuration::decode(&alternate, None);
        if admissible {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(Status::InvalidArgument)));
        }
    }
    let configured = base_path.with_file_name("observed-config.bin");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&configured)
        .unwrap();
    file.write_all(&config).unwrap();
    drop(file);
    drop(config);
    let handle = native_open(configured.to_str().unwrap());
    std::fs::remove_file(&configured).unwrap();
    let runtime = crate::state::get(handle).unwrap();
    let call = runtime.begin(VmkRequestId { bytes: [104; 16] }).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match runtime.begin(VmkRequestId { bytes: [105; 16] }) {
            Err(Status::Denied) => break,
            Ok(_) | Err(Status::ResourceLimit) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20))
            }
            _ => panic!("owned code observation did not stop runtime"),
        }
    }
    let committed = AtomicBool::new(false);
    assert!(call.cancelled.load(Ordering::Acquire));
    assert_eq!(
        call.commit(|| {
            committed.store(true, Ordering::Release);
            Ok(())
        }),
        Err(Status::Denied)
    );
    assert!(!committed.load(Ordering::Acquire));
    let reported = Instant::now() + Duration::from_secs(5);
    while !control.join("observed-stop").exists() {
        assert!(
            Instant::now() < reported,
            "server did not acknowledge own-stop telemetry"
        );
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        crate::runtime_observation_delivery(handle).unwrap(),
        crate::observations::ObservationDelivery::Queued,
    );
    drop(call);
    assert_eq!(crate::vmk_shutdown(handle), Status::Ok as u32);
    let fresh = native_open(base_path.to_str().unwrap());
    native_invoke(fresh, 106);
    assert_eq!(crate::vmk_shutdown(fresh), Status::Ok as u32);
}
