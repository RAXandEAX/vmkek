#[cfg(not(all(windows, target_arch = "x86_64")))]
fn main() {}

#[cfg(all(windows, target_arch = "x86_64"))]
fn main() {
    lab::run();
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod lab {
    use std::{
        env,
        ffi::c_void,
        fs::File,
        io::Write,
        mem::size_of,
        os::windows::ffi::OsStrExt,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Barrier,
        },
        thread,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    mod compatibility {
        include!("support/compatibility.rs");
    }

    mod response_online {
        include!("support/response_online.rs");
    }

    use p256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};
    use vmkek_protocol::{
        detection::{
            BuildRange, DetectionPolicy, ObservationDecision, ObservationMode, ObservationProfile,
            ObservationReaction, ObservationRule, ObservationSettings, PolicyContext,
            ProfileContext, SignedDetectionPolicy,
        },
        lab::{Instruction, LabProgram},
        public_key_id,
        session_observation::{ObservationKind, SignalId},
        Budgets, Capability, Profile, VmDescriptor, VmForm, COPY_INPUT_CAPABILITY,
    };
    use vmkek_runtime::{
        initialize_observed_lab,
        observations::{
            windows::{debugger_attachment_sample, native_windows_build},
            ObservationGate,
        },
        runtime_observation, vmk_invoke, vmk_shutdown, Status, VmkBytes, VmkInvokeResultV1,
        VmkInvokeV1, VmkOutput, VmkRequestId, VmkScalar, ABI_VERSION,
    };

    type Handle = *mut c_void;
    const APP: [u8; 16] = [21; 16];
    const BUILD: [u8; 16] = [22; 16];
    const EPOCH: u64 = 1;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetTickCount64() -> u64;
        fn DebugBreak();
        fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> Handle;
        fn SetEvent(event: Handle) -> i32;
        fn WaitForSingleObject(event: Handle, milliseconds: u32) -> u32;
        fn CloseHandle(event: Handle) -> i32;
    }

    pub(super) fn run() {
        let mut record = File::create_new(env::var_os("VMKEK_A02_RECORD").unwrap()).unwrap();
        phase(&mut record, "startup");
        let mode = match env::var("VMKEK_A02_PROFILE").unwrap().as_str() {
            "observe" => ObservationMode::Observe,
            "enforce" => ObservationMode::Enforce,
            _ => panic!("invalid lab profile"),
        };
        let scenario = env::var("VMKEK_A03_SCENARIO").unwrap_or_default();
        if env::var_os("VMKEK_A07_ONLINE_CONFIG").is_some() {
            response_online::run(&mut record, mode, &scenario);
            return;
        }
        let compatibility = compatibility::initialize(&scenario);
        let debugger_enabled = scenario != "disabled";
        let (gate, policy_hash) = gate(mode, debugger_enabled);
        writeln!(record, "policy_sha256={policy_hash} policy_epoch={EPOCH}").unwrap();
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
            function_id: [23; 16],
            generation_id: [24; 16],
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
        let handle =
            initialize_observed_lab(&descriptor.encode().unwrap(), &program, gate.clone()).unwrap();
        phase(&mut record, "idle");
        if scenario == "hardware" {
            writeln!(
                record,
                "hardware_target=0x{:x}",
                breakpoint_target as *const () as usize
            )
            .unwrap();
        }
        record.flush().unwrap();
        wait_for_release("VMKEK_T6_READY", "VMKEK_T6_RELEASE");

        match scenario.as_str() {
            "software" => {
                // SAFETY: The lab observer has attached to this owned child and
                // releases its gate before the fixture requests this breakpoint.
                unsafe { DebugBreak() };
            }
            "data" => writeln!(record, "data_byte=0xcc").unwrap(),
            "hardware" | "breakpoint_control" => {
                assert_eq!(breakpoint_target(7), 8);
                assert_eq!(breakpoint_target(7), 8);
                writeln!(record, "breakpoint_function=restored").unwrap();
            }
            _ => {}
        }
        let mut call = || sample_and_invoke(&mut record, handle, &gate, debugger_enabled, 1);
        if let Some(activity) = compatibility {
            activity.exercise(&mut record, |record| {
                sample_and_invoke(record, handle, &gate, debugger_enabled, 1);
                check_repeated_calls(handle, 3);
            });
        } else if scenario == "cpu_load" {
            let iterations = with_cpu_load(call);
            writeln!(record, "load_workers=4 load_iterations={iterations}").unwrap();
        } else {
            call();
        }
        if scenario == "detach" {
            phase(&mut record, "recovery_wait");
            record.flush().unwrap();
            wait_for_release("VMKEK_A03_RESAMPLE_READY", "VMKEK_A03_RESAMPLE_RELEASE");
            sample_and_invoke(&mut record, handle, &gate, debugger_enabled, 2);
        }
        if scenario == "concurrent" {
            check_repeated_calls(handle, 3);
            let ready = Barrier::new(3);
            thread::scope(|scope| {
                let ready = &ready;
                for tag in [21, 22] {
                    scope.spawn(move || {
                        ready.wait();
                        assert_eq!(invoke(handle, tag), (Status::Ok as u32, true));
                    });
                }
                ready.wait();
            });
            writeln!(record, "call_integrity=recursive_and_concurrent").unwrap();
        }
        assert_eq!(vmk_shutdown(handle), Status::Ok as u32);
        phase(&mut record, "shutdown");
    }

    #[inline(never)]
    extern "C" fn breakpoint_target(value: u64) -> u64 {
        std::hint::black_box(value) + 1
    }

    fn sample_and_invoke(
        record: &mut File,
        handle: u64,
        gate: &ObservationGate,
        enabled: bool,
        tag: u8,
    ) {
        phase(record, "protected_call");
        if enabled {
            let sample = debugger_attachment_sample(gate.begin_sample()).unwrap();
            let sampled_tick = tick();
            gate.publish(vec![sample]).unwrap();
            let assessment = runtime_observation(handle, SignalId::DEBUGGER)
                .unwrap()
                .unwrap();
            let decision = match assessment.decision {
                ObservationDecision::Allow => "Allow",
                ObservationDecision::ReportOnly(_) => "ReportOnly",
                ObservationDecision::RequestOwnStop(_) => "RequestOwnStop",
                ObservationDecision::Unavailable(_) => "Unavailable",
            };
            writeln!(
                record,
                "observation={:?} reason={:?} decision={decision} tick_ms={sampled_tick}",
                sample.record.finding, sample.reason
            )
            .unwrap();
        } else {
            assert!(runtime_observation(handle, SignalId::DEBUGGER)
                .unwrap()
                .is_none());
            writeln!(
                record,
                "observation=Disabled reason=None decision=Allow tick_ms={}",
                tick()
            )
            .unwrap();
        }
        let (status, output_check, output) = invoke_with_output(handle, tag);
        if env::var_os("VMKEK_A08_ACTIVITY_DLL").is_some() && output_check {
            writeln!(record, "output_sha256={:x}", Sha256::digest(output)).unwrap();
        }
        writeln!(record, "invoke_status={status} output_check={output_check}").unwrap();
    }

    fn invoke(handle: u64, tag: u8) -> (u32, bool) {
        let (status, verified, _) = invoke_with_output(handle, tag);
        (status, verified)
    }

    fn invoke_with_output(handle: u64, tag: u8) -> (u32, bool, [u8; 2]) {
        let input = [0xcc, 42];
        let mut output = [0u8; 2];
        let args = VmkInvokeV1 {
            size: size_of::<VmkInvokeV1>() as u32,
            abi_version: ABI_VERSION,
            request_id: VmkRequestId { bytes: [tag; 16] },
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
        // SAFETY: The arguments and their disjoint buffers remain live for this call.
        let status = unsafe { vmk_invoke(handle, &args, &mut result) };
        let output_check = if status == Status::Ok as u32 {
            result.output_len == input.len() as u64 && output == input
        } else {
            result == sentinel && output == [0; 2]
        };
        (status, output_check, output)
    }

    fn check_repeated_calls(handle: u64, depth: u8) {
        assert_eq!(invoke(handle, 10 + depth), (Status::Ok as u32, true));
        if depth > 1 {
            check_repeated_calls(handle, depth - 1);
        }
        assert_eq!(invoke(handle, 15 + depth), (Status::Ok as u32, true));
    }

    fn with_cpu_load(action: impl FnOnce()) -> u64 {
        let done = AtomicBool::new(false);
        let ready = Barrier::new(5);
        thread::scope(|scope| {
            let workers: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        let mut count = 1u64;
                        ready.wait();
                        while !done.load(Ordering::Relaxed) {
                            count += std::hint::black_box(1);
                        }
                        count
                    })
                })
                .collect();
            ready.wait();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
            done.store(true, Ordering::Relaxed);
            let iterations = workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .sum();
            if let Err(payload) = result {
                std::panic::resume_unwind(payload);
            }
            iterations
        })
    }

    fn gate(mode: ObservationMode, enabled: bool) -> (Arc<ObservationGate>, String) {
        let build = native_windows_build().unwrap();
        let key = SigningKey::from_slice(&[0x32; 32]).unwrap();
        let anchor = Instant::now();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let signed = SignedDetectionPolicy::sign_for_profile(
            DetectionPolicy {
                app_id: APP,
                build_id: BUILD,
                key_id: public_key_id(key.verifying_key()),
                epoch: EPOCH,
                issued_ms: now_ms,
                expires_ms: now_ms + 60_000,
                windows_builds: BuildRange {
                    first: build,
                    last: build,
                },
                artifacts: vec![],
                images: vec![],
            },
            ObservationSettings {
                profile: ObservationProfile::Offline,
                mode,
                max_age_ms: 10_000,
                rules: enabled
                    .then_some(ObservationRule {
                        signal_id: SignalId::DEBUGGER,
                        required: true,
                        reaction: ObservationReaction::Stop,
                    })
                    .into_iter()
                    .collect(),
            },
            &key,
        )
        .unwrap();
        let verified = signed
            .verify_for_profile(
                key.verifying_key(),
                ProfileContext {
                    policy: PolicyContext {
                        app_id: APP,
                        build_id: BUILD,
                        epoch_floor: EPOCH,
                        windows_build: build,
                        now_ms,
                    },
                    profile: ObservationProfile::Offline,
                    supported: &[ObservationKind::DebuggerAttachment],
                    previous: None,
                },
            )
            .unwrap();
        (
            Arc::new(ObservationGate::new(
                verified.observation_policy().unwrap(),
                anchor,
            )),
            format!("{:x}", Sha256::digest(signed.as_bytes())),
        )
    }

    fn wait_for_release(ready_key: &str, release_key: &str) {
        if env::var_os(ready_key).is_none() {
            return;
        }
        let ready = open_gate(ready_key, 2);
        let release = open_gate(release_key, 0x0010_0000);
        // SAFETY: Both handles refer to live events opened by this process.
        unsafe {
            let signaled = SetEvent(ready);
            let wait = WaitForSingleObject(release, 10_000);
            CloseHandle(ready);
            CloseHandle(release);
            assert_ne!(signaled, 0);
            assert_eq!(wait, 0);
        }
    }

    fn open_gate(key: &str, access: u32) -> Handle {
        let name: Vec<_> = env::var_os(key).unwrap().encode_wide().chain([0]).collect();
        // SAFETY: The buffer is a live NUL-terminated UTF-16 event name.
        let event = unsafe { OpenEventW(access, 0, name.as_ptr()) };
        assert!(!event.is_null());
        event
    }

    fn phase(record: &mut File, phase: &str) {
        writeln!(record, "phase={phase} tick_ms={}", tick()).unwrap();
    }

    fn tick() -> u64 {
        // SAFETY: The API takes no pointers and reads the system uptime.
        unsafe { GetTickCount64() }
    }
}
