#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    lab::run();
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod lab {
    use p256::ecdsa::SigningKey;
    use sha2::{Digest as _, Sha256};
    use std::{
        env, fs,
        mem::size_of,
        sync::Arc,
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use vmkek_protocol::{
        detection::{
            BuildRange, DetectionPolicy, ImagePurpose, ImageRule, LinuxProfileContext,
            ObservationDecision, ObservationMode, ObservationProfile, ObservationReaction,
            ObservationRule, ObservationSettings, SignedDetectionPolicy,
        },
        lab::{Instruction, LabProgram},
        public_key_id,
        session_observation::{ObservationKind, SignalId},
        Budgets, Capability, Id, Profile, VmDescriptor, VmForm, COPY_INPUT_CAPABILITY,
    };
    use vmkek_runtime::{
        initialize_observed_lab,
        observations::{linux, ObservationGate},
        runtime_observation, vmk_invoke, vmk_shutdown, Status, VmkBytes, VmkInvokeResultV1,
        VmkInvokeV1, VmkOutput, VmkRequestId, VmkScalar, ABI_VERSION,
    };

    mod online {
        include!("support/linux_observation_online.rs");
    }

    const APP: Id = [21; 16];
    const BUILD: Id = [22; 16];
    const EPOCH: u64 = 7;
    const INTEGRITY: SignalId = SignalId {
        kind: ObservationKind::CodeIntegrity,
        rule_id: 1,
    };
    const MARKER: &[u8; 8] = b"A10ELF01";
    const INPUT: &[u8; 2] = &[0xcc, 42];

    // Dedicated, page-aligned inert RX data. The fixture never executes these bytes.
    std::arch::global_asm!(
        ".pushsection .text.vmkek_a10_marker,\"ax\",@progbits",
        ".balign 4096",
        ".global vmkek_a10_marker",
        "vmkek_a10_marker:",
        ".ascii \"A10ELF01\"",
        ".space 4088",
        ".popsection",
    );
    extern "C" {
        static vmkek_a10_marker: u8;
    }

    fn wall_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap()
    }

    fn signed_policy(
        key: &SigningKey,
        app: Id,
        build: Id,
        profile: ObservationProfile,
        mode: ObservationMode,
        signals: Vec<SignalId>,
        images: Vec<ImageRule>,
    ) -> SignedDetectionPolicy {
        let now = wall_ms();
        SignedDetectionPolicy::sign_for_linux_profile(
            DetectionPolicy {
                app_id: app,
                build_id: build,
                key_id: public_key_id(key.verifying_key()),
                epoch: EPOCH,
                issued_ms: now.saturating_sub(1000),
                expires_ms: now + 900_000,
                windows_builds: BuildRange { first: 1, last: 1 },
                artifacts: vec![],
                images,
            },
            ObservationSettings {
                profile,
                mode,
                max_age_ms: 1000,
                rules: signals
                    .into_iter()
                    .map(|signal_id| ObservationRule {
                        signal_id,
                        required: true,
                        reaction: ObservationReaction::Stop,
                    })
                    .collect(),
            },
            linux::native_release().unwrap(),
            key,
        )
        .unwrap()
    }

    pub(super) fn run() {
        let args: Vec<_> = env::args().skip(1).collect();
        let [case, mode, marker] = args.as_slice() else {
            panic!("expected lab case, mode and marker");
        };
        let mode = match mode.as_str() {
            "observe" => ObservationMode::Observe,
            "enforce" => ObservationMode::Enforce,
            _ => panic!("unknown profile"),
        };
        if case.starts_with("online-") {
            online::run(case, mode);
            return;
        }
        let start = Instant::now();
        let key = SigningKey::from_slice(&[0x32; 32]).unwrap();
        let integrity = case.starts_with("integrity-");
        let signals = if integrity {
            vec![INTEGRITY]
        } else if matches!(case.as_str(), "baseline" | "steady-baseline") {
            vec![]
        } else {
            vec![SignalId::DEBUGGER]
        };
        let image = integrity
            .then(|| {
                let code_rva = u32::from_str_radix(marker, 16).unwrap();
                let mut digest: [u8; 32] =
                    Sha256::digest(fs::read("/proc/self/exe").unwrap()).into();
                if case == "integrity-outside" {
                    digest[0] ^= 1;
                }
                ImageRule {
                    id: INTEGRITY.rule_id,
                    purpose: ImagePurpose::CodeIntegrity,
                    file_digest: digest,
                    code_rva,
                    code_len: MARKER.len() as u32,
                    code_digest: Sha256::digest(MARKER).into(),
                }
            })
            .into_iter()
            .collect();
        let signed = signed_policy(
            &key,
            APP,
            BUILD,
            ObservationProfile::Offline,
            mode,
            signals,
            image,
        );
        println!(
            "policy_sha256={:x} policy_epoch={EPOCH}",
            Sha256::digest(signed.as_bytes())
        );
        let gate = Arc::new(
            linux::activate_offline(&signed, key.verifying_key(), APP, BUILD, EPOCH, None).unwrap(),
        );
        let handle = initialize(&gate);
        println!("startup_us={}", start.elapsed().as_micros());
        if case.starts_with("steady-") {
            steady(handle, &gate, case == "steady-active");
            return;
        }
        let signal = if integrity {
            INTEGRITY
        } else {
            SignalId::DEBUGGER
        };
        if integrity {
            let verified = signed
                .verify_for_linux_profile(
                    key.verifying_key(),
                    LinuxProfileContext {
                        app_id: APP,
                        build_id: BUILD,
                        epoch_floor: EPOCH,
                        now_ms: wall_ms(),
                        release: linux::native_release().unwrap(),
                        profile: ObservationProfile::Offline,
                        supported: &[ObservationKind::CodeIntegrity],
                        previous: None,
                    },
                )
                .unwrap();
            let started = Instant::now();
            let (image, cold) = linux::PreparedElfIntegrity::prepare(&verified, wall_ms()).unwrap();
            println!(
                "cold_file_bytes={} cold_us={}",
                cold.file_bytes,
                started.elapsed().as_micros()
            );
            let changed = case == "integrity-changed";
            let inaccessible = case == "integrity-inaccessible";
            if changed || inaccessible {
                set_marker(changed, inaccessible);
            }
            let started = Instant::now();
            let (rows, hot) = image
                .observe(&verified, wall_ms(), gate.begin_sample())
                .unwrap();
            println!(
                "hot_file_bytes={} memory_bytes={} hot_us={}",
                hot.file_bytes,
                hot.memory_bytes,
                started.elapsed().as_micros()
            );
            if changed || inaccessible {
                set_marker(false, false);
            }
            gate.publish(rows).unwrap();
        } else if case != "baseline" {
            let start = Instant::now();
            gate.publish(vec![
                linux::tracer_attachment_sample(gate.begin_sample()).unwrap()
            ])
            .unwrap();
            println!("sample_us={}", start.elapsed().as_micros());
        }
        if case == "stale" {
            thread::sleep(Duration::from_millis(1050));
        }
        if case == "threaded" {
            thread::scope(|scope| {
                for tag in [10, 11, 12, 13] {
                    scope.spawn(move || {
                        let (status, intact, _) = invoke(handle, tag, false);
                        assert_eq!((status, intact), (Status::Ok as u32, true), "thread ABI");
                    });
                }
            });
            println!("threaded_calls=4");
        }
        if case == "profiled" {
            let before = clock_ns(libc::CLOCK_THREAD_CPUTIME_ID);
            for tag in 20..40 {
                let (status, intact, _) = invoke(handle, tag, false);
                assert_eq!((status, intact), (Status::Ok as u32, true));
            }
            let cpu = clock_ns(libc::CLOCK_THREAD_CPUTIME_ID)
                .checked_sub(before)
                .unwrap();
            assert!(cpu > 0);
            println!("profiled_calls=20 profiled_cpu_ns={cpu}");
        }
        report(handle, signal);
        let (status, verified, elapsed) = invoke(handle, 1, false);
        println!("invoke_status={status} output_verified={verified} invoke_ns={elapsed}");
        assert!(verified);
        assert_eq!(vmk_shutdown(handle), Status::Ok as u32);
    }

    fn steady(handle: u64, gate: &ObservationGate, active: bool) {
        let duration = Duration::from_secs(600);
        let period = Duration::from_millis(250);
        let began = Instant::now();
        let cpu = clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID);
        let mut samples = 0;
        while began.elapsed() < duration {
            if active {
                gate.publish(vec![
                    linux::tracer_attachment_sample(gate.begin_sample()).unwrap()
                ])
                .unwrap();
            }
            samples += 1;
            thread::sleep(period);
        }
        let cpu_ns = clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID) - cpu;
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        // SAFETY: The resource query writes into this live output on success.
        assert_eq!(
            unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
            0
        );
        // SAFETY: A successful getrusage initialized the result.
        let usage = unsafe { usage.assume_init() };
        println!(
            "steady_active={active} elapsed_ns={} cpu_ns={cpu_ns} max_rss_kib={} cycles={samples}",
            began.elapsed().as_nanos(),
            usage.ru_maxrss
        );
        let (status, intact, _) = invoke(handle, 1, false);
        assert_eq!((status, intact), (Status::Ok as u32, true));
        assert_eq!(vmk_shutdown(handle), Status::Ok as u32);
    }

    fn clock_ns(clock: libc::clockid_t) -> u128 {
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes into this live timespec output.
        assert_eq!(unsafe { libc::clock_gettime(clock, &mut value) }, 0);
        value.tv_sec as u128 * 1_000_000_000 + value.tv_nsec as u128
    }

    fn set_marker(changed: bool, inaccessible: bool) {
        let address = (&raw const vmkek_a10_marker).cast_mut();
        // SAFETY: sysconf reads process constants and takes no pointer.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert_eq!(page, 4096);
        assert_eq!(address as usize % 4096, 0);
        // SAFETY: This exact private fixture page contains only inert lab bytes.
        // The test toggles RW then RX; no executable bytes are ever written or run.
        unsafe {
            assert_eq!(
                libc::mprotect(address.cast(), 4096, libc::PROT_READ | libc::PROT_WRITE),
                0
            );
            address.write_volatile(if changed { b'Z' } else { MARKER[0] });
            let protection = if inaccessible {
                libc::PROT_NONE
            } else {
                libc::PROT_READ | libc::PROT_EXEC
            };
            assert_eq!(libc::mprotect(address.cast(), 4096, protection), 0);
        }
        println!("own_marker_changed={changed} own_marker_inaccessible={inaccessible}");
    }

    fn initialize(gate: &Arc<ObservationGate>) -> u64 {
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
        initialize_observed_lab(&descriptor.encode().unwrap(), &program, gate.clone()).unwrap()
    }

    fn report(handle: u64, signal: SignalId) {
        match runtime_observation(handle, signal).unwrap() {
            None => println!("observation=Disabled reason=None decision=Allow"),
            Some(value) => {
                let (decision, unavailable) = match value.decision {
                    ObservationDecision::Allow => ("Allow", "None".to_owned()),
                    ObservationDecision::ReportOnly(_) => ("ReportOnly", "None".to_owned()),
                    ObservationDecision::RequestOwnStop(_) => ("RequestOwnStop", "None".to_owned()),
                    ObservationDecision::Unavailable(reason) => {
                        ("Unavailable", format!("{reason:?}"))
                    }
                };
                if let Some(sample) = value.sample {
                    println!("observation={:?} reason={:?} decision={decision} unavailable={unavailable}",
                        sample.record.finding, sample.reason);
                } else {
                    println!("observation=Missing reason=Missing decision={decision} unavailable={unavailable}");
                }
            }
        }
    }

    fn invoke(handle: u64, tag: u8, online: bool) -> (u32, bool, u128) {
        let mut output = [0xa5; 2];
        let value = VmkScalar {
            kind: vmkek_runtime::SCALAR_I64,
            reserved: 0,
            bits: (-17i64) as u64,
        };
        let args = VmkInvokeV1 {
            size: size_of::<VmkInvokeV1>() as u32,
            abi_version: ABI_VERSION,
            request_id: VmkRequestId { bytes: [tag; 16] },
            scalars: if online { &value } else { std::ptr::null() },
            scalar_count: u64::from(online),
            input: VmkBytes {
                data: INPUT.as_ptr(),
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
        let started = Instant::now();
        // SAFETY: the input and output ABI buffers are live, valid and disjoint.
        let status = unsafe { vmk_invoke(handle, &args, &mut result) };
        let elapsed = started.elapsed().as_nanos();
        let intact = if status == Status::Ok as u32 {
            (!online || result.scalar == value) && result.output_len == 2 && output == *INPUT
        } else {
            result == sentinel && output == [0xa5; 2]
        };
        (status, intact, elapsed)
    }
}
