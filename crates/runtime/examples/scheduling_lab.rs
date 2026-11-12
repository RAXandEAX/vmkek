#[cfg(not(all(windows, target_arch = "x86_64")))]
fn main() {}

#[cfg(all(windows, target_arch = "x86_64"))]
fn main() {
    fixture::run();
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod fixture {
    mod assessment {
        include!("support/assessment.rs");
    }
    use std::{
        env,
        ffi::c_void,
        fs,
        mem::size_of,
        ptr,
        sync::{
            atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
            Arc,
        },
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
            VerifiedPolicy,
        },
        lab::{Instruction, LabProgram},
        public_key_id,
        session_observation::{
            ObservationFinding, ObservationKind, ObservationReason, ObservationRecord, SignalId,
        },
        Budgets, Capability, Profile, VmDescriptor, VmForm, COPY_INPUT_CAPABILITY,
    };
    use vmkek_runtime::{
        initialize_observed_lab,
        observations::{
            scheduler::{IntegritySchedule, ObservationWorker, DEBUGGER_INTERVAL},
            windows::{debugger_attachment_sample, native_windows_build, OwnedModule},
            ObservationGate, SampleWindow,
        },
        runtime_observation, vmk_initialize, vmk_invoke, vmk_shutdown, Status, VmkBytes,
        VmkInitializeV1, VmkInvokeResultV1, VmkInvokeV1, VmkOutput, VmkRequestId, VmkRuntime,
        VmkScalar, ABI_VERSION, PROFILE_LAB,
    };

    const APP: [u8; 16] = [61; 16];
    const BUILD: [u8; 16] = [62; 16];
    const TTL_MS: u32 = 650;
    const CALLS: usize = 512;
    const STEADY_SECONDS: u64 = 600;
    const CLEAN: u8 = 0;
    const PAUSED: u8 = 1;
    const ATTACHED: u8 = 2;
    const READ_ERROR: u8 = 3;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn GetProcessTimes(
            process: *mut c_void,
            create: *mut u64,
            exit: *mut u64,
            kernel: *mut u64,
            user: *mut u64,
        ) -> i32;
        fn K32GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut MemoryCounters,
            size: u32,
        ) -> i32;
    }

    #[repr(C)]
    struct MemoryCounters {
        size: u32,
        faults: u32,
        bytes: [usize; 9],
    }

    struct Policy {
        signed: SignedDetectionPolicy,
        pin: SigningKey,
        context: PolicyContext,
    }

    impl Policy {
        fn verify(&self) -> VerifiedPolicy<'_> {
            self.signed
                .verify_for_profile(
                    self.pin.verifying_key(),
                    ProfileContext {
                        policy: self.context,
                        profile: ObservationProfile::Offline,
                        supported: &[
                            ObservationKind::DebuggerAttachment,
                            ObservationKind::CodeIntegrity,
                        ],
                        previous: None,
                    },
                )
                .unwrap()
        }
    }

    pub(super) fn run() {
        let args: Vec<_> = env::args().skip(1).collect();
        match args.as_slice() {
            [] => matrix(),
            [command] if command == "--prepare" => measure_preparation(),
            [command, profile, seed] if command == "--assessment" => {
                assessment::run(profile, seed.parse().unwrap());
            }

            [command, mode]
                if command == "--steady" && matches!(mode.as_str(), "enabled" | "disabled") =>
            {
                steady(mode == "enabled")
            }
            _ => panic!("unsupported scheduling fixture arguments"),
        }
    }

    fn matrix() {
        let (descriptor, program) = program();
        let signed = policy(ObservationMode::Enforce, false);
        let start = Instant::now();
        let baseline = plain(&descriptor, &program);
        let baseline_start = start.elapsed();
        let load = Arc::new(AtomicBool::new(true));
        let loads: Vec<_> = (0..2)
            .map(|_| {
                let load = load.clone();
                thread::spawn(move || {
                    while load.load(Ordering::Acquire) {
                        std::hint::black_box((0..256u64).fold(0u64, u64::wrapping_add));
                    }
                })
            })
            .collect();
        let baseline_admission = benchmark(baseline);
        close(baseline);

        let start = Instant::now();
        let verified = signed.verify();
        let verification = start.elapsed();
        let gate = Arc::new(ObservationGate::new(
            verified.observation_policy().unwrap(),
            start,
        ));
        let runtime = initialize_observed_lab(&descriptor, &program, gate.clone()).unwrap();
        invoke(runtime, 0, Status::Unavailable);
        let mode = Arc::new(AtomicU8::new(CLEAN));
        let published = Arc::new(AtomicU64::new(0));
        let worker =
            observation_fixture_worker(gate.clone(), mode.clone(), published.clone(), start);
        wait_for(|| gate.admit().is_ok());
        let observed_start = start.elapsed();
        let observed_admission = benchmark(runtime);
        thread::scope(|scope| {
            for caller in 1..=3 {
                scope.spawn(move || {
                    for _ in 0..32 {
                        invoke(runtime, caller, Status::Ok);
                    }
                });
            }
        });
        load.store(false, Ordering::Release);
        for handle in loads {
            handle.join().unwrap();
        }
        println!("scheduling scenario=concurrent_load result=verified calls=96");

        mode.store(PAUSED, Ordering::Release);
        thread::sleep(Duration::from_millis(u64::from(TTL_MS) + 100));
        invoke(runtime, 0, Status::Unavailable);
        assert_eq!(
            runtime_observation(runtime, SignalId::DEBUGGER)
                .unwrap()
                .unwrap()
                .decision,
            ObservationDecision::Unavailable(ObservationReason::Stale)
        );
        println!("scheduling scenario=stale result=verified invoke=Unavailable");

        mode.store(READ_ERROR, Ordering::Release);
        wait_for(|| {
            matches!(
                gate.decision(),
                ObservationDecision::Unavailable(ObservationReason::ApiFailure)
            )
        });
        invoke(runtime, 0, Status::Unavailable);
        println!("scheduling scenario=read_error result=verified invoke=Unavailable");
        mode.store(CLEAN, Ordering::Release);
        wait_for(|| gate.admit().is_ok());
        invoke(runtime, 0, Status::Ok);
        println!("scheduling scenario=resumed result=verified invoke=Ok");

        let event_ns = nanos(start.elapsed());
        mode.store(ATTACHED, Ordering::Release);
        wait_for(|| published.load(Ordering::Acquire) != 0);
        let seen_ns = published.load(Ordering::Acquire);
        invoke(runtime, 0, Status::Denied);
        let reaction = nanos(start.elapsed()).saturating_sub(seen_ns);
        println!("scheduling scenario=sustained_event result=verified invoke=Denied detect_ns={} reaction_ns={reaction}", seen_ns.saturating_sub(event_ns));
        let close_start = Instant::now();
        drop(worker);
        close(runtime);
        invoke(runtime, 0, Status::NotFound);
        println!(
            "scheduling scenario=closed result=verified close_ns={}",
            nanos(close_start.elapsed())
        );

        let observe = policy(ObservationMode::Observe, false);
        let verified = observe.verify();
        let gate = Arc::new(ObservationGate::new(
            verified.observation_policy().unwrap(),
            Instant::now(),
        ));
        let runtime = initialize_observed_lab(&descriptor, &program, gate.clone()).unwrap();
        invoke(runtime, 0, Status::Ok);
        publish(&gate, ATTACHED);
        assert!(matches!(
            gate.assessment(SignalId::DEBUGGER).unwrap().decision,
            ObservationDecision::ReportOnly(_)
        ));
        invoke(runtime, 0, Status::Ok);
        close(runtime);
        println!("scheduling scenario=observe_continues result=verified invoke=Ok");
        println!(
            "cost baseline_start_ns={} observed_start_ns={} verification_ns={}",
            nanos(baseline_start),
            nanos(observed_start),
            nanos(verification)
        );
        print_cost("disabled", baseline_admission);
        print_cost("enabled", observed_admission);
        println!(
            "policy epoch=1 sha256={:x}",
            Sha256::digest(signed.signed.as_bytes())
        );
        println!(
            "policy epoch=1 sha256={:x}",
            Sha256::digest(observe.signed.as_bytes())
        );
    }

    fn observation_fixture_worker(
        gate: Arc<ObservationGate>,
        mode: Arc<AtomicU8>,
        published: Arc<AtomicU64>,
        start: Instant,
    ) -> ObservationWorker {
        ObservationWorker::start(move |control| {
            while !control.is_cancelled() {
                let current = mode.load(Ordering::Acquire);
                if current != PAUSED {
                    publish(&gate, current);
                    if current == ATTACHED {
                        let _ = published.compare_exchange(
                            0,
                            nanos(start.elapsed()),
                            Ordering::Release,
                            Ordering::Relaxed,
                        );
                    }
                }
                if !control.wait(DEBUGGER_INTERVAL) {
                    break;
                }
            }
        })
        .unwrap()
    }

    fn publish(gate: &ObservationGate, mode: u8) {
        let (finding, reason) = match mode {
            CLEAN => (
                ObservationFinding::NotObservedWithinScope,
                ObservationReason::None,
            ),
            ATTACHED => (ObservationFinding::Observed, ObservationReason::None),
            READ_ERROR => (
                ObservationFinding::Inconclusive,
                ObservationReason::ApiFailure,
            ),
            _ => panic!("invalid fixture mode"),
        };
        gate.publish(vec![gate.begin_sample().sample(
            ObservationRecord {
                kind: ObservationKind::DebuggerAttachment,
                rule_id: 0,
                finding,
            },
            reason,
        )])
        .unwrap();
    }

    fn wait_for(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !condition() {
            assert!(Instant::now() < deadline, "scheduling fixture deadline");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn benchmark(runtime: VmkRuntime) -> [u64; 3] {
        let mut samples = [0u64; CALLS];
        for sample in &mut samples {
            let before = Instant::now();
            invoke(runtime, 0, Status::Ok);
            *sample = nanos(before.elapsed());
        }
        samples.sort_unstable();
        [
            samples[CALLS.div_ceil(2) - 1],
            samples[(CALLS * 95).div_ceil(100) - 1],
            samples[CALLS - 1],
        ]
    }

    fn print_cost(mode: &str, [p50, p95, max]: [u64; 3]) {
        println!("admission mode={mode} count={CALLS} p50_ns={p50} p95_ns={p95} max_ns={max}");
    }

    fn measure_preparation() {
        let policy = policy(ObservationMode::Observe, true);
        let verified = policy.verify();
        let own = OwnedModule::from_address(owned_marker as *const () as usize).unwrap();
        let start = Instant::now();
        let prepared = own
            .prepare_integrity(&verified, policy.context.now_ms)
            .unwrap();
        let initial = start.elapsed();
        let reads = prepared.preparation_reads();
        let start = Instant::now();
        let (samples, incremental) = prepared
            .observe_samples(
                &verified,
                policy.context.now_ms,
                SampleWindow::for_verified(&verified, Duration::from_millis(u64::from(TTL_MS))),
            )
            .unwrap();
        assert_eq!(
            samples[0].record.finding,
            ObservationFinding::NotObservedWithinScope
        );
        println!("preparation cache=warm file_bytes={} layout_bytes={} prepare_ns={} incremental_memory_bytes={} incremental_ns={}",
            reads.file_bytes, reads.layout_bytes, nanos(initial), incremental.memory_bytes, nanos(start.elapsed()));
    }

    fn steady(enabled: bool) {
        let (descriptor, program) = program();
        let policy = policy(ObservationMode::Observe, true);
        let verified = policy.verify();
        let gate = Arc::new(ObservationGate::new(
            verified.observation_policy().unwrap(),
            Instant::now(),
        ));
        let runtime = if enabled {
            initialize_observed_lab(&descriptor, &program, gate.clone()).unwrap()
        } else {
            plain(&descriptor, &program)
        };
        let debugger = Arc::new(AtomicU64::new(0));
        let code = Arc::new(AtomicU64::new(0));
        let worker = enabled.then(|| steady_worker(policy, gate, debugger.clone(), code.clone()));
        if enabled {
            wait_for(|| code.load(Ordering::Acquire) != 0);
        }
        let before = resources();
        let started = Instant::now();
        let base_debugger = debugger.load(Ordering::Acquire);
        let base_code = code.load(Ordering::Acquire);
        let mut peak = before.1;
        for tick in 1..=STEADY_SECONDS {
            thread::sleep(
                (started + Duration::from_secs(tick)).saturating_duration_since(Instant::now()),
            );
            invoke(runtime, 0, Status::Ok);
            peak = peak.max(resources().1);
        }
        let after = resources();
        let wall = started.elapsed();
        let mode = if enabled { "enabled" } else { "disabled" };
        println!("steady mode={mode} wall_ns={} cpu_100ns={} private_start={} private_peak={} debugger_samples={} code_samples={}",
            nanos(wall), after.0 - before.0, before.1, peak,
            debugger.load(Ordering::Acquire) - base_debugger, code.load(Ordering::Acquire) - base_code);
        drop(worker);
        close(runtime);
    }

    fn steady_worker(
        policy: Policy,
        gate: Arc<ObservationGate>,
        debugger: Arc<AtomicU64>,
        code: Arc<AtomicU64>,
    ) -> ObservationWorker {
        ObservationWorker::start(move |control| {
            let verified = policy.verify();
            let own = OwnedModule::from_address(owned_marker as *const () as usize).unwrap();
            let prepared = own
                .prepare_integrity(&verified, policy.context.now_ms)
                .unwrap();
            let mut cadence = IntegritySchedule::default();
            let start = Instant::now();
            let mut last_code = Vec::new();
            while !control.is_cancelled() {
                let elapsed = start.elapsed();
                let now = policy.context.now_ms + elapsed.as_millis() as u64;
                let observation = debugger_attachment_sample(gate.begin_sample()).unwrap();
                if cadence.due(elapsed) {
                    let window = SampleWindow::for_verified(
                        &verified,
                        Duration::from_millis(u64::from(TTL_MS)),
                    );
                    let (samples, read) = prepared.observe_samples(&verified, now, window).unwrap();
                    assert_eq!(
                        samples[0].record.finding,
                        ObservationFinding::NotObservedWithinScope
                    );
                    assert_eq!((read.file_bytes, read.layout_bytes), (0, 0));
                    last_code = samples;
                    code.fetch_add(1, Ordering::Release);
                }
                if control.is_cancelled() {
                    break;
                }
                gate.publish(
                    std::iter::once(observation)
                        .chain(last_code.iter().copied())
                        .collect(),
                )
                .unwrap();
                debugger.fetch_add(1, Ordering::Release);
                if !control.wait(DEBUGGER_INTERVAL) {
                    break;
                }
            }
        })
        .unwrap()
    }

    fn resources() -> (u64, usize) {
        let (mut created, mut exited, mut kernel, mut user) = (0, 0, 0, 0);
        let mut memory = MemoryCounters {
            size: size_of::<MemoryCounters>() as u32,
            faults: 0,
            bytes: [0; 9],
        };
        // SAFETY: Each FILETIME destination is an aligned eight-byte word; the
        // EX process memory structure has its native x64 layout.
        unsafe {
            let process = GetCurrentProcess();
            assert_ne!(
                GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user),
                0
            );
            assert_ne!(
                K32GetProcessMemoryInfo(process, &mut memory, size_of::<MemoryCounters>() as u32),
                0
            );
        }
        (kernel + user, memory.bytes[8])
    }

    fn nanos(duration: Duration) -> u64 {
        duration.as_nanos().try_into().unwrap()
    }

    fn program() -> (Vec<u8>, Vec<u8>) {
        let code = LabProgram {
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
            function_id: [63; 16],
            generation_id: [64; 16],
            form: VmForm::Stack,
            depth: 2,
            capabilities: vec![Capability {
                id: COPY_INPUT_CAPABILITY,
                required: true,
            }],
            program_sha256: Sha256::digest(&code).into(),
            budgets: Budgets {
                active_contexts: 4,
                ..Budgets::default()
            },
            profile: Profile::Lab,
            extensions: vec![],
        }
        .encode()
        .unwrap();
        (descriptor, code)
    }

    #[inline(never)]
    extern "C" fn owned_marker(input: u64) -> u64 {
        input.rotate_left(19) ^ 0x3456_789a
    }

    fn policy(mode: ObservationMode, integrity: bool) -> Policy {
        policy_for_signals(mode, true, integrity.then_some(false), BUILD)
    }

    fn policy_for_signals(
        mode: ObservationMode,
        debugger: bool,
        integrity: Option<bool>,
        build_id: vmkek_protocol::Id,
    ) -> Policy {
        let pin = SigningKey::from_slice(&[0x55; 32]).unwrap();
        let build = native_windows_build().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let context = PolicyContext {
            app_id: APP,
            build_id,
            epoch_floor: 1,
            windows_build: build,
            now_ms: now,
        };
        let mut rules: Vec<_> = debugger
            .then_some(ObservationRule {
                signal_id: SignalId::DEBUGGER,
                required: true,
                reaction: ObservationReaction::Stop,
            })
            .into_iter()
            .collect();
        let mut images = Vec::new();
        if let Some(required) = integrity {
            let addr = owned_marker as *const () as usize;
            let image = fs::read(env::current_exe().unwrap()).unwrap();
            let (rva, bytes) = marker_in_file(&image, addr);
            images.push(ImageRule {
                id: 1,
                purpose: ImagePurpose::CodeIntegrity,
                file_digest: Sha256::digest(&image).into(),
                code_rva: rva,
                code_len: 8,
                code_digest: Sha256::digest(bytes).into(),
            });
            rules.push(ObservationRule {
                signal_id: SignalId {
                    kind: ObservationKind::CodeIntegrity,
                    rule_id: 1,
                },
                required,
                reaction: if required {
                    ObservationReaction::Stop
                } else {
                    ObservationReaction::Report
                },
            });
        }
        let signed = SignedDetectionPolicy::sign_for_profile(
            DetectionPolicy {
                app_id: APP,
                build_id,
                key_id: public_key_id(pin.verifying_key()),
                epoch: 1,
                issued_ms: now,
                expires_ms: now + 900_000,
                windows_builds: BuildRange {
                    first: build,
                    last: build,
                },
                artifacts: vec![],
                images,
            },
            ObservationSettings {
                profile: ObservationProfile::Offline,
                mode,
                max_age_ms: TTL_MS,
                rules,
            },
            &pin,
        )
        .unwrap();
        Policy {
            signed,
            pin,
            context,
        }
    }

    fn marker_in_file(image: &[u8], address: usize) -> (u32, &[u8]) {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        }
        // SAFETY: Null asks for the process's held executable.
        let base = unsafe { GetModuleHandleW(ptr::null()) } as usize;
        assert_ne!(base, 0);
        let rva = u32::try_from(address.checked_sub(base).unwrap()).unwrap();
        let read16 = |offset| u16::from_le_bytes(image[offset..offset + 2].try_into().unwrap());
        let read32 = |offset| u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap());
        let pe = read32(60) as usize;
        let sections = pe + 24 + read16(pe + 20) as usize;
        for index in 0..read16(pe + 6) as usize {
            let section = sections + index * 40;
            let start = read32(section + 12);
            if let Some(delta) = rva.checked_sub(start) {
                if delta + 8 <= read32(section + 16) {
                    let offset = (read32(section + 20) + delta) as usize;
                    return (rva, &image[offset..offset + 8]);
                }
            }
        }
        panic!("marker outside image file");
    }

    fn plain(descriptor: &[u8], code: &[u8]) -> VmkRuntime {
        let args = VmkInitializeV1 {
            size: size_of::<VmkInitializeV1>() as u32,
            abi_version: ABI_VERSION,
            profile: PROFILE_LAB,
            reserved: 0,
            descriptor: VmkBytes {
                data: descriptor.as_ptr(),
                len: descriptor.len() as u64,
            },
            program: VmkBytes {
                data: code.as_ptr(),
                len: code.len() as u64,
            },
        };
        let mut handle = 0;
        // SAFETY: Arguments and both immutable input buffers are live and disjoint from output.
        assert_eq!(
            unsafe { vmk_initialize((&raw const args).cast(), &mut handle) },
            Status::Ok as u32
        );
        handle
    }

    fn invoke(runtime: VmkRuntime, id: u8, expected: Status) {
        let mut output = [0u8; 1];
        let input = [42u8];
        let args = VmkInvokeV1 {
            size: size_of::<VmkInvokeV1>() as u32,
            abi_version: ABI_VERSION,
            request_id: VmkRequestId {
                bytes: [id + 1; 16],
            },
            scalars: ptr::null(),
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
        // SAFETY: Input, output and metadata are live and nonoverlapping.
        assert_eq!(
            unsafe { vmk_invoke(runtime, &args, &mut result) },
            expected as u32
        );
        if expected == Status::Ok {
            assert_eq!((output, result.output_len), (input, 1));
        } else {
            assert_eq!((output, result), ([0], sentinel));
        }
    }

    fn close(runtime: VmkRuntime) {
        assert_eq!(vmk_shutdown(runtime), Status::Ok as u32);
    }
}
