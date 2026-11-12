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
        os::windows::ffi::OsStrExt,
        path::Path,
        ptr,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use p256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};
    use vmkek_protocol::{
        detection::{
            BuildRange, DetectionPolicy, ImagePurpose, ImageRule, PolicyContext,
            SignedDetectionPolicy,
        },
        public_key_id, ProtocolError,
    };
    use vmkek_runtime::observations::{
        windows::{native_windows_build, CodeObservation, IntegrityReadStats, OwnedModule},
        Observation, SampleWindow,
    };

    type Handle = *mut c_void;
    const PREFERRED: usize = 0x0005_0000_0000;
    const PAGE_NOACCESS: u32 = 1;
    const PAGE_READWRITE: u32 = 4;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const RANGE_BYTES: usize = 8;
    const APP: [u8; 16] = [41; 16];
    const BUILD: [u8; 16] = [42; 16];

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(path: *const u16) -> Handle;
        fn FreeLibrary(module: Handle) -> i32;
        fn GetProcAddress(module: Handle, name: *const u8) -> Handle;
        fn VirtualAlloc(base: Handle, size: usize, kind: u32, protect: u32) -> Handle;
        fn VirtualFree(base: Handle, size: usize, kind: u32) -> i32;
        fn VirtualProtect(base: Handle, size: usize, protect: u32, old: *mut u32) -> i32;
        fn GetCurrentProcess() -> Handle;
        fn GetProcessMitigationPolicy(
            process: Handle,
            policy: u32,
            flags: *mut u32,
            size: usize,
        ) -> i32;
    }

    struct Loaded(Handle);
    impl Drop for Loaded {
        fn drop(&mut self) {
            // SAFETY: This is our one reference from LoadLibraryW.
            unsafe { FreeLibrary(self.0) };
        }
    }

    struct Protection {
        base: *mut u8,
        length: usize,
        old: u32,
    }
    impl Drop for Protection {
        fn drop(&mut self) {
            let mut ignored = 0;
            // SAFETY: The fixture holds the owning module while changing its inert marker page.
            assert_ne!(
                unsafe { VirtualProtect(self.base.cast(), self.length, self.old, &mut ignored) },
                0
            );
        }
    }

    pub(super) fn run() {
        let paths: Vec<_> = env::args_os().skip(1).collect();
        assert_eq!(paths.len(), 2);
        let key = SigningKey::from_slice(&[0x44; 32]).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let build = native_windows_build().unwrap();
        for (name, policy) in [("dynamic_code", 2), ("cfg", 7), ("shadow_stack", 15)] {
            let mut flags = 0u32;
            // SAFETY: The requested Win32 policies each return one DWORD in our buffer.
            let ok =
                unsafe { GetProcessMitigationPolicy(GetCurrentProcess(), policy, &mut flags, 4) };
            println!("mitigation name={name} available={ok} flags=0x{flags:08x}");
        }

        // SAFETY: Reserve only a vacant own-process address interval, without committing memory.
        let reservation =
            unsafe { VirtualAlloc(PREFERRED as Handle, 65536, 0x2000, PAGE_NOACCESS) };
        let original_path = Path::new(&paths[0]);
        let original = open(original_path);
        let address = original.0 as usize;
        assert_ne!(address, PREFERRED);
        let (inside, outside, relocated, call) = exports(&original);
        let signed = sign(
            &key,
            original_path,
            (address, inside, relocated),
            1,
            build,
            now,
        );
        let policy = signed
            .verify_for(key.verifying_key(), context(1, build, now))
            .unwrap();
        let owned = OwnedModule::from_address(inside as usize).unwrap();
        drop(original);
        assert_eq!(call(), 1);
        println!("integrity scenario=held_module result=verified call=1");

        let start = Instant::now();
        let prepared = owned.prepare_integrity(&policy, now).unwrap();
        assert_eq!(prepared.preferred_base(), Some(PREFERRED as u64));
        let (rows, read) = prepared.observe(&policy, now).unwrap();
        report("full", start, prepared.preparation_reads(), read);
        assert_eq!(rows[0].code, CodeObservation::MatchesSignedBytes);
        assert_eq!(rows[1].code, CodeObservation::Inconclusive);
        assert_eq!(
            (rows[2].file, rows[2].code),
            (
                Observation::NotObservedWithinScope,
                CodeObservation::Unsupported
            )
        );
        let (typed, _) = prepared
            .observe_samples(
                &policy,
                now,
                SampleWindow::for_verified(&policy, Duration::from_secs(1)),
            )
            .unwrap();
        use vmkek_protocol::session_observation::{ObservationFinding, ObservationReason};
        assert_eq!(
            (typed[0].record.finding, typed[0].reason),
            (
                ObservationFinding::NotObservedWithinScope,
                ObservationReason::None
            )
        );
        assert_eq!(
            (typed[1].record.finding, typed[1].reason),
            (
                ObservationFinding::Inconclusive,
                ObservationReason::InvalidData
            )
        );
        assert_eq!(
            (typed[2].record.finding, typed[2].reason),
            (
                ObservationFinding::Unsupported,
                ObservationReason::OutsideScope
            )
        );
        println!("integrity scenario=clean result=verified call=1 relocated=excluded wrong_file=unsupported preferred=0x{PREFERRED:x} loaded=0x{address:x}");

        let start = Instant::now();
        let (rows, read) = prepared.observe(&policy, now).unwrap();
        report("incremental", start, IntegrityReadStats::default(), read);
        assert_eq!(rows[0].code, CodeObservation::MatchesSignedBytes);
        assert_eq!(read.file_bytes, 0);
        assert_eq!(read.layout_bytes, 0);

        change(outside, 0xe4);
        expect(
            &prepared,
            &policy,
            now,
            "outside_scope",
            CodeObservation::MatchesSignedBytes,
        );
        change(outside, 0x30);
        change(inside, 0xe3);
        expect(
            &prepared,
            &policy,
            now,
            "inside_scope",
            CodeObservation::DiffersFromSignedBytes,
        );
        change(inside, 1);
        {
            let _unavailable = protect(inside, RANGE_BYTES, PAGE_NOACCESS);
            expect(
                &prepared,
                &policy,
                now,
                "inaccessible",
                CodeObservation::Inconclusive,
            );
        }
        expect(
            &prepared,
            &policy,
            now,
            "restored",
            CodeObservation::MatchesSignedBytes,
        );
        assert_eq!(call(), 1);
        drop(prepared);
        drop(owned);
        assert!(OwnedModule::from_address(inside as usize).is_err());
        println!("integrity scenario=unloaded result=verified");

        let updated_path = Path::new(&paths[1]);
        let update = open(updated_path);
        let base = update.0 as usize;
        let (inside, _, relocated, call) = exports(&update);
        let signed = sign(&key, updated_path, (base, inside, relocated), 2, build, now);
        let newer = signed
            .verify_for(key.verifying_key(), context(2, build, now))
            .unwrap();
        let owned = OwnedModule::from_address(inside as usize).unwrap();
        let prepared = owned.prepare_integrity(&newer, now).unwrap();
        assert_eq!(
            prepared.observe(&policy, now).unwrap_err(),
            ProtocolError::Binding
        );
        assert_eq!(
            prepared.observe(&newer, now).unwrap().0[0].code,
            CodeObservation::MatchesSignedBytes
        );
        assert_eq!(call(), 2);
        println!("integrity scenario=signed_update result=verified call=2 policy_epoch=2 policy_sha256={:x}", Sha256::digest(signed.as_bytes()));

        if !reservation.is_null() {
            // SAFETY: Release exactly the reservation made above.
            assert_ne!(unsafe { VirtualFree(reservation, 0, 0x8000) }, 0);
        }
    }

    fn expect(
        prepared: &vmkek_runtime::observations::windows::PreparedIntegrity<'_>,
        policy: &vmkek_protocol::detection::VerifiedPolicy<'_>,
        now: u64,
        name: &str,
        expected: CodeObservation,
    ) {
        let (rows, _) = prepared.observe(policy, now).unwrap();
        assert_eq!(rows[0].file, Observation::Observed);
        assert_eq!(rows[0].code, expected);
        println!("integrity scenario={name} result=verified code={expected:?}");
    }

    fn report(
        name: &str,
        start: Instant,
        preparation: IntegrityReadStats,
        sample: IntegrityReadStats,
    ) {
        println!(
            "cost pass={name} file_bytes={} layout_bytes={} memory_bytes={} elapsed_ns={}",
            preparation.file_bytes,
            preparation.layout_bytes,
            sample.memory_bytes,
            start.elapsed().as_nanos()
        );
    }

    fn open(path: &Path) -> Loaded {
        assert!(path.is_absolute());
        let wide: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: Only absolute paths to the two synthetic DLLs built by this runner are supplied.
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        assert!(!module.is_null(), "{}", std::io::Error::last_os_error());
        Loaded(module)
    }

    fn exports(module: &Loaded) -> (*mut u8, *mut u8, *mut u8, extern "C" fn() -> u32) {
        // SAFETY: The module is our held fixture DLL with exactly these two C exports.
        unsafe {
            let range = GetProcAddress(module.0, c"a04_range".as_ptr().cast());
            let call = GetProcAddress(module.0, c"a04_call".as_ptr().cast());
            assert!(!range.is_null() && !call.is_null());
            let range: extern "C" fn(u32) -> *mut u8 = std::mem::transmute(range);
            let call: extern "C" fn() -> u32 = std::mem::transmute(call);
            (range(0), range(1), range(2), call)
        }
    }

    fn change(address: *mut u8, byte: u8) {
        let _protection = protect(address, 1, PAGE_READWRITE);
        // SAFETY: The selected address is a byte of our inert fixture marker, not executable code.
        unsafe { ptr::write_volatile(address, byte) };
    }

    fn protect(address: *mut u8, length: usize, permission: u32) -> Protection {
        let mut old = 0;
        // SAFETY: This address belongs to the explicitly allocated, held fixture RX section.
        assert_ne!(
            unsafe { VirtualProtect(address.cast(), length, permission, &mut old) },
            0
        );
        assert_eq!(old, PAGE_EXECUTE_READ);
        Protection {
            base: address,
            length,
            old,
        }
    }

    fn context(epoch: u64, build: u32, now: u64) -> PolicyContext {
        PolicyContext {
            app_id: APP,
            build_id: BUILD,
            epoch_floor: epoch,
            windows_build: build,
            now_ms: now,
        }
    }

    fn sign(
        key: &SigningKey,
        path: &Path,
        target: (usize, *mut u8, *mut u8),
        epoch: u64,
        build: u32,
        now: u64,
    ) -> SignedDetectionPolicy {
        let (base, marker, relocated) = target;
        let file_digest = Sha256::digest(fs::read(path).unwrap()).into();
        let rva = |address: *mut u8| {
            u32::try_from((address as usize).checked_sub(base).unwrap()).unwrap()
        };
        let rule = ImageRule {
            id: 1,
            purpose: ImagePurpose::CodeIntegrity,
            file_digest,
            code_rva: rva(marker),
            code_len: RANGE_BYTES as u32,
            code_digest: Sha256::digest([epoch as u8, 0x13, 0x29, 0x37, 0x41, 0x53, 0x67, 0x79])
                .into(),
        };
        let signed = SignedDetectionPolicy::sign(
            DetectionPolicy {
                app_id: APP,
                build_id: BUILD,
                key_id: public_key_id(key.verifying_key()),
                epoch,
                issued_ms: now,
                expires_ms: now + 60_000,
                windows_builds: BuildRange {
                    first: build,
                    last: build,
                },
                artifacts: vec![],
                images: vec![
                    rule,
                    ImageRule {
                        id: 2,
                        code_rva: rva(relocated),
                        ..rule
                    },
                    ImageRule {
                        id: 3,
                        file_digest: [0; 32],
                        ..rule
                    },
                ],
            },
            key,
        )
        .unwrap();
        println!(
            "policy epoch={epoch} sha256={:x}",
            Sha256::digest(signed.as_bytes())
        );
        signed
    }
}
