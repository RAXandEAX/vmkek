#[cfg(not(all(windows, target_arch = "x86_64")))]
fn main() {}

#[cfg(all(windows, target_arch = "x86_64"))]
fn main() {
    fixture::run();
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod fixture {
    use std::{
        env,
        ffi::c_void,
        fs,
        mem::size_of,
        os::windows::ffi::OsStrExt,
        path::Path,
        sync::Arc,
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use p256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};
    use vmkek_protocol::{
        detection::{
            BuildRange, DetectionPolicy, ImagePurpose, ImageRule, ObservationDecision,
            ObservationMode, ObservationProfile, ObservationReaction, ObservationRule,
            ObservationSettings, PolicyContext, ProfileContext, SignedDetectionPolicy,
        },
        lab::{Instruction, LabProgram},
        public_key_id,
        session_observation::{ObservationKind, SignalId},
        Budgets, Capability, Profile, VmDescriptor, VmForm, COPY_INPUT_CAPABILITY,
    };
    use vmkek_runtime::{
        initialize_observed_lab,
        observations::{
            windows::{native_windows_build, OwnedModule},
            ObservationGate,
        },
        runtime_observation, vmk_invoke, vmk_shutdown, Status, VmkBytes, VmkInvokeResultV1,
        VmkInvokeV1, VmkOutput, VmkRequestId, VmkScalar, ABI_VERSION,
    };

    type Handle = *mut c_void;
    type Marker = extern "C" fn() -> u32;
    type MarkerAddress = extern "C" fn() -> *const u8;

    #[repr(C)]
    struct MemoryInfo {
        base: Handle,
        allocation_base: Handle,
        allocation_protect: u32,
        partition: u16,
        size: usize,
        state: u32,
        protect: u32,
        kind: u32,
    }

    const APP: [u8; 16] = [51; 16];
    const BUILD: [u8; 16] = [52; 16];
    const SIGNAL: SignalId = SignalId {
        kind: ObservationKind::CodeIntegrity,
        rule_id: 1,
    };
    const BYTES: usize = 16;
    const EPOCH: u64 = 1;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(path: *const u16) -> Handle;
        fn FreeLibrary(module: Handle) -> i32;
        fn GetProcAddress(module: Handle, name: *const u8) -> Handle;
        fn GetCurrentThreadId() -> u32;
        fn GetTickCount64() -> u64;
        fn GetCurrentProcess() -> Handle;
        fn GetProcessMitigationPolicy(
            process: Handle,
            policy: u32,
            flags: *mut u32,
            size: usize,
        ) -> i32;
        fn VirtualQuery(address: Handle, result: *mut MemoryInfo, size: usize) -> usize;
        fn VirtualProtect(address: Handle, length: usize, protection: u32, old: *mut u32) -> i32;
    }

    struct Module(Handle);

    impl Module {
        fn open(path: &Path) -> Self {
            let path: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
            // SAFETY: The path is the NUL-terminated absolute path of our lab DLL.
            let module = unsafe { LoadLibraryW(path.as_ptr()) };
            assert!(!module.is_null(), "owned lab module did not load");
            Self(module)
        }

        fn export(&self, name: &[u8]) -> Handle {
            // SAFETY: The owned module stays loaded and names are static C strings.
            let address = unsafe { GetProcAddress(self.0, name.as_ptr()) };
            assert!(!address.is_null(), "owned lab export not found");
            address
        }
    }

    impl Drop for Module {
        fn drop(&mut self) {
            // SAFETY: We release our own LoadLibraryW reference.
            unsafe { FreeLibrary(self.0) };
        }
    }

    pub(super) fn run() {
        let arguments: Vec<_> = env::args_os().skip(1).collect();
        assert!((2..=3).contains(&arguments.len()));
        let dll = Path::new(&arguments[0]);
        let mode = arguments[1].to_str().unwrap();
        assert!(matches!(
            mode,
            "baseline" | "profiler" | "gadget" | "marker" | "marker-clean"
        ));
        let library = Module::open(dll);
        let probe = if matches!(mode, "marker" | "marker-clean") {
            // SAFETY: The fixture exports a function returning its inert marker address.
            let address: MarkerAddress =
                unsafe { std::mem::transmute(library.export(b"a05_marker\0")) };
            address().cast_mut().cast()
        } else {
            library.export(b"a05_probe\0")
        };
        // SAFETY: The fixture DLL declares a05_run with this exact C signature.
        let marker: Marker = unsafe { std::mem::transmute(library.export(b"a05_run\0")) };
        assert_eq!(marker(), 44);

        let build = native_windows_build().unwrap();
        let key = SigningKey::from_slice(&[0x55; 32]).unwrap();
        let anchor = Instant::now();
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let signed = signed_policy(dll, &library, probe, &key, build, now);
        let context = PolicyContext {
            app_id: APP,
            build_id: BUILD,
            epoch_floor: EPOCH,
            windows_build: build,
            now_ms: now,
        };
        let policy = signed
            .verify_for_profile(
                key.verifying_key(),
                ProfileContext {
                    policy: context,
                    profile: ObservationProfile::Offline,
                    supported: &[ObservationKind::CodeIntegrity],
                    previous: None,
                },
            )
            .unwrap();
        let gate = Arc::new(ObservationGate::new(
            policy.observation_policy().unwrap(),
            anchor,
        ));
        let owned = OwnedModule::from_address(probe as usize).unwrap();
        let prepared = owned.prepare_integrity(&policy, now).unwrap();
        let handle = open_lab(gate.clone());

        // SAFETY: This Win32 query returns the current thread ID without using pointers.
        let thread_id = unsafe { GetCurrentThreadId() };
        write_gate(
            "ready",
            &format!("{} {thread_id} {}", std::process::id(), tick()),
        );
        await_gate("measure");
        let _gadget = if mode == "gadget" {
            Some(Module::open(Path::new(&arguments[2])))
        } else {
            None
        };
        if mode == "gadget" {
            await_gate("gadget_measure");
        }
        let control_ns = if mode == "profiler" {
            let mut elapsed = 0u128;
            for _ in 0..128 {
                let start = Instant::now();
                assert_eq!(marker(), 44);
                elapsed += start.elapsed().as_nanos();
            }
            elapsed
        } else {
            0
        };
        let change_tick = if mode == "marker" {
            change_owned_marker(probe);
            tick()
        } else {
            0
        };
        let protection = page_protection(probe);
        let (dynamic, cfg, shadow) = (mitigation(2), mitigation(7), mitigation(15));
        assert_eq!(marker(), 44);
        let start = Instant::now();
        let elapsed_ms = u64::try_from(anchor.elapsed().as_millis()).unwrap();
        let (samples, _) = prepared
            .observe_samples(&policy, now + elapsed_ms, gate.begin_sample())
            .unwrap();
        let sample_tick = tick();
        let elapsed_ns = start.elapsed().as_nanos();
        gate.publish(samples).unwrap();
        let assessment = runtime_observation(handle, SIGNAL).unwrap().unwrap();
        let ObservationDecision::ReportOnly(sample) = assessment.decision else {
            panic!("observe policy did not publish its sample");
        };
        let call = invoke(handle);
        assert_eq!(call, Status::Ok as u32);
        assert_eq!(vmk_shutdown(handle), Status::Ok as u32);
        let record = format!(
            "finding={:?} reason={:?} decision=ReportOnly tick_ms={sample_tick} elapsed_ns={elapsed_ns} policy_epoch={EPOCH} policy_sha256={:x} marker=44 abi={call} control_ns={control_ns} change_tick={change_tick} protection={protection:x} dynamic={dynamic:x} cfg={cfg:x} shadow={shadow:x}",
            sample.record.finding, sample.reason, Sha256::digest(signed.as_bytes()),
        );
        println!("fixture {record}");
        write_gate("result", &record);
        // The controller owns teardown after it has captured this result.
        thread::sleep(Duration::from_secs(10));
        panic!("owned fixture did not receive its expected job teardown");
    }

    fn signed_policy(
        dll: &Path,
        module: &Module,
        probe: Handle,
        key: &SigningKey,
        build: u32,
        now: u64,
    ) -> SignedDetectionPolicy {
        let rva = u32::try_from((probe as usize).checked_sub(module.0 as usize).unwrap()).unwrap();
        // SAFETY: The own fixture export has a longer unoptimized prologue. The
        // controller releases the measure gate only after this clean reference.
        let initial = unsafe { std::slice::from_raw_parts(probe.cast::<u8>(), BYTES) };
        SignedDetectionPolicy::sign_for_profile(
            DetectionPolicy {
                app_id: APP,
                build_id: BUILD,
                key_id: public_key_id(key.verifying_key()),
                epoch: EPOCH,
                issued_ms: now,
                expires_ms: now + 60_000,
                windows_builds: BuildRange {
                    first: build,
                    last: build,
                },
                artifacts: vec![],
                images: vec![ImageRule {
                    id: SIGNAL.rule_id,
                    purpose: ImagePurpose::CodeIntegrity,
                    file_digest: Sha256::digest(fs::read(dll).unwrap()).into(),
                    code_rva: rva,
                    code_len: BYTES as u32,
                    code_digest: Sha256::digest(initial).into(),
                }],
            },
            ObservationSettings {
                profile: ObservationProfile::Offline,
                mode: ObservationMode::Observe,
                max_age_ms: 5_000,
                rules: vec![ObservationRule {
                    signal_id: SIGNAL,
                    required: true,
                    reaction: ObservationReaction::Report,
                }],
            },
            key,
        )
        .unwrap()
    }

    fn open_lab(gate: Arc<ObservationGate>) -> u64 {
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
            build_id: BUILD,
            function_id: [53; 16],
            generation_id: [54; 16],
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
        initialize_observed_lab(&descriptor.encode().unwrap(), &program, gate).unwrap()
    }

    fn invoke(handle: u64) -> u32 {
        let input = [5u8, 44];
        let mut output = [0u8; 2];
        let arguments = VmkInvokeV1 {
            size: size_of::<VmkInvokeV1>() as u32,
            abi_version: ABI_VERSION,
            request_id: VmkRequestId { bytes: [1; 16] },
            scalars: std::ptr::null(),
            scalar_count: 0,
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
                kind: 0,
                reserved: 0,
                bits: 0,
            },
            output_len: 99,
        };
        // SAFETY: The ABI structures and backing buffers remain valid and disjoint.
        let status = unsafe { vmk_invoke(handle, &arguments, &mut result) };
        assert_eq!(result.output_len, input.len() as u64);
        assert_eq!(output, input);
        status
    }

    fn change_owned_marker(address: Handle) {
        let mut prior = 0;
        // SAFETY: The pointer names the fixed inert marker in the owned DLL.
        assert_ne!(unsafe { VirtualProtect(address, 1, 4, &mut prior) }, 0);
        assert_eq!(prior, 0x20);
        // SAFETY: The one marker byte is writable and is never executed.
        unsafe { address.cast::<u8>().write_volatile(0x52) };
        let mut changed = 0;
        // SAFETY: Restore the exact prior RX protection of our marker page.
        assert_ne!(
            unsafe { VirtualProtect(address, 1, prior, &mut changed) },
            0
        );
    }

    fn page_protection(address: Handle) -> u32 {
        let mut info = std::mem::MaybeUninit::<MemoryInfo>::uninit();
        // SAFETY: The query initializes the ABI struct on a full-length result.
        assert_eq!(
            unsafe { VirtualQuery(address, info.as_mut_ptr(), size_of::<MemoryInfo>()) },
            size_of::<MemoryInfo>(),
        );
        // SAFETY: The complete result was verified above.
        unsafe { info.assume_init() }.protect
    }

    fn mitigation(policy: u32) -> u32 {
        let mut flags = 0u32;
        // SAFETY: These mitigation policies each return one DWORD of flags.
        assert_ne!(
            unsafe { GetProcessMitigationPolicy(GetCurrentProcess(), policy, &mut flags, 4) },
            0
        );
        flags
    }

    fn write_gate(name: &str, text: &str) {
        let partial = format!("{name}.tmp");
        fs::write(&partial, text).unwrap();
        fs::rename(partial, name).unwrap();
    }

    fn await_gate(name: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !Path::new(name).is_file() {
            assert!(Instant::now() < deadline, "lab gate {name} expired");
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn tick() -> u64 {
        // SAFETY: The OS uptime query takes no pointers.
        unsafe { GetTickCount64() }
    }
}
