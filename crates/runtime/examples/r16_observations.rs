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
        hint::black_box,
        os::windows::ffi::OsStrExt,
        ptr,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    use p256::ecdsa::SigningKey;
    use sha2::{Digest as _, Sha256};
    use vmkek_protocol::{
        detection::{
            Advice, ArtifactKind, ArtifactRule, BuildRange, DetectionPolicy, ImagePurpose,
            ImageRule, PolicyContext, Severity, SignedDetectionPolicy,
        },
        public_key_id, Digest,
    };
    use vmkek_runtime::observations::{
        evaluate_inventory,
        windows::{debugger_attachment, native_windows_build, CodeObservation, OwnedModule},
        ArtifactFinding, Inventory, Observation,
    };

    type Handle = *mut c_void;
    const APP: [u8; 16] = [1; 16];
    const BUILD_ID: [u8; 16] = [2; 16];
    const CODE_LEN: u32 = 4;
    static ORDINARY_DATA: [u8; 4] = [0x41, 0xcc, 0x43, 0x44];

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleW(name: *const u16) -> Handle;
        fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> Handle;
        fn SetEvent(event: Handle) -> i32;
        fn WaitForSingleObject(event: Handle, milliseconds: u32) -> u32;
        fn CloseHandle(event: Handle) -> i32;
    }

    #[inline(never)]
    extern "C" fn owned_marker(input: u32) -> u32 {
        input.rotate_left(11) ^ 0x67cfbb14
    }

    pub(super) fn run() {
        assert_eq!(black_box(owned_marker)(5), 0x67cf9314);
        assert_eq!(black_box(&ORDINARY_DATA)[1], 0xcc);
        let gated = release_at_debug_gate();
        let expected = if gated {
            env::var("VMKEK_T6_DEBUG_EXPECTED").unwrap() == "1"
        } else {
            env::var("VMKEK_R16_EXPECT_DEBUG").as_deref() == Ok("1")
        };
        let observed = if expected {
            Observation::Observed
        } else {
            Observation::NotObservedWithinScope
        };
        assert_eq!(debugger_attachment(), observed);
        println!("debugger={observed:?}");
        let build = native_windows_build().unwrap();
        exercise_images(build);
        exercise_artifact(build);
        if env::var("VMKEK_R16_SAMPLE_TIMING").as_deref() == Ok("1") {
            measure_observation(observed);
        }
    }

    fn exercise_images(build: u32) {
        let executable = fs::read(env::current_exe().unwrap()).unwrap();
        let file_digest = Sha256::digest(&executable).into();
        let address = owned_marker as *const () as usize;
        let base = unsafe { GetModuleHandleW(ptr::null()) } as usize;
        assert_ne!(base, 0);
        let rva = u32::try_from(address.checked_sub(base).unwrap()).unwrap();
        let data_rva = u32::try_from(ORDINARY_DATA.as_ptr() as usize - base).unwrap();
        let code_digest: Digest = Sha256::digest(file_bytes(&executable, rva, CODE_LEN)).into();
        let mut different = code_digest;
        different[0] ^= 1;
        let base_rule = ImageRule {
            id: 1,
            purpose: ImagePurpose::CodeIntegrity,
            file_digest,
            code_rva: rva,
            code_len: CODE_LEN,
            code_digest,
        };
        let (signed, key, context) = sign_policy(
            build,
            vec![
                base_rule,
                ImageRule {
                    id: 2,
                    code_digest: different,
                    ..base_rule
                },
                ImageRule {
                    id: 3,
                    code_rva: data_rva,
                    ..base_rule
                },
                ImageRule {
                    id: 4,
                    file_digest: [0; 32],
                    ..base_rule
                },
                ImageRule {
                    id: 5,
                    purpose: ImagePurpose::RegisteredInstrumentation,
                    ..base_rule
                },
            ],
            None,
        );
        let verified = signed.verify_for(key.verifying_key(), context).unwrap();
        let image = OwnedModule::from_address(address).unwrap();
        let observed = image.observe(&verified, now_ms()).unwrap();
        assert_eq!(observed[0].file, Observation::Observed);
        assert_eq!(observed[0].code, CodeObservation::MatchesSignedBytes);
        assert_eq!(observed[1].code, CodeObservation::DiffersFromSignedBytes);
        assert_eq!(observed[2].code, CodeObservation::Inconclusive);
        assert_eq!(observed[3].file, Observation::NotObservedWithinScope);
        assert_eq!(observed[3].code, CodeObservation::Unsupported);
        assert_eq!(observed[4].instrumentation, Observation::Observed);
        println!("build={build} image_match=1 image_mismatch=1 ordinary_0xcc=1 unknown_image=1 owned_provider=1");
    }

    fn exercise_artifact(build: u32) {
        let Some(artifact) = env::var_os("VMKEK_R16_BENIGN_FILE").filter(|value| !value.is_empty())
        else {
            return;
        };
        let expected = env::var("VMKEK_R16_BENIGN_EXPECTED").unwrap();
        assert_eq!(expected.len(), 64);
        let mut expected_digest = [0; 32];
        for (index, byte) in expected_digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&expected[index * 2..index * 2 + 2], 16).unwrap();
        }
        let bytes = fs::read(artifact).unwrap();
        let digest = Sha256::digest(&bytes).into();
        let (signed, key, context) = sign_policy(build, Vec::new(), Some(expected_digest));
        let verified = signed.verify_for(key.verifying_key(), context).unwrap();
        let finding = evaluate_inventory(
            &verified,
            ArtifactKind::ApplicationFile,
            Inventory::Snapshot(&[digest]),
            now_ms(),
        )
        .unwrap();
        assert_eq!(finding[0].finding, ArtifactFinding::BenignException);
        println!("benign_file_rule={}", finding[0].rule_id);
    }

    fn sign_policy(
        build: u32,
        images: Vec<ImageRule>,
        artifact: Option<Digest>,
    ) -> (SignedDetectionPolicy, SigningKey, PolicyContext) {
        let key = SigningKey::from_slice(&[17; 32]).unwrap();
        let now = now_ms();
        let build_range = BuildRange {
            first: build,
            last: build,
        };
        let policy = DetectionPolicy {
            app_id: APP,
            build_id: BUILD_ID,
            key_id: public_key_id(key.verifying_key()),
            epoch: 1,
            issued_ms: now,
            expires_ms: now + 10_000,
            windows_builds: build_range,
            artifacts: artifact
                .into_iter()
                .map(|digest| ArtifactRule {
                    id: 10,
                    kind: ArtifactKind::ApplicationFile,
                    digest,
                    severity: Severity::Warning,
                    advice: Advice::Review,
                    benign_builds: Some(build_range),
                })
                .collect(),
            images,
        };
        let context = PolicyContext {
            app_id: APP,
            build_id: BUILD_ID,
            epoch_floor: 1,
            windows_build: build,
            now_ms: now,
        };
        (
            SignedDetectionPolicy::sign(policy, &key).unwrap(),
            key,
            context,
        )
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn measure_observation(expected: Observation) {
        let mut samples = [0; 2000];
        for duration in &mut samples {
            let start = Instant::now();
            assert_eq!(debugger_attachment(), expected);
            *duration = start.elapsed().as_nanos();
        }
        samples.sort_unstable();
        println!(
            "samples={} median_ns={} p95_ns={}",
            samples.len(),
            samples[999],
            samples[1899]
        );
    }

    fn release_at_debug_gate() -> bool {
        if env::var_os("VMKEK_T6_READY").is_none_or(|value| value.is_empty()) {
            return false;
        }
        assert_eq!(debugger_attachment(), Observation::NotObservedWithinScope);
        let ready = open_gate("VMKEK_T6_READY", 2);
        let release = open_gate("VMKEK_T6_RELEASE", 0x00100000);
        assert_ne!(unsafe { SetEvent(ready) }, 0);
        assert_eq!(unsafe { WaitForSingleObject(release, 10_000) }, 0);
        unsafe {
            CloseHandle(ready);
            CloseHandle(release);
        }
        true
    }

    fn open_gate(key: &str, access: u32) -> Handle {
        let name: Vec<u16> = env::var_os(key).unwrap().encode_wide().chain([0]).collect();
        let handle = unsafe { OpenEventW(access, 0, name.as_ptr()) };
        assert!(!handle.is_null());
        handle
    }

    fn file_bytes(image: &[u8], rva: u32, count: u32) -> &[u8] {
        let u16_at = |at| u16::from_le_bytes(image[at..at + 2].try_into().unwrap());
        let u32_at = |at| u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
        let pe = u32_at(0x3c) as usize;
        assert_eq!(&image[pe..pe + 4], &[b'P', b'E', 0, 0]);
        let first_section = pe + 24 + usize::from(u16_at(pe + 20));
        for index in 0..usize::from(u16_at(pe + 6)) {
            let section = first_section + 40 * index;
            let virtual_address = u32_at(section + 12);
            let raw_size = u32_at(section + 16);
            if let Some(offset) = rva.checked_sub(virtual_address) {
                if offset + count <= raw_size {
                    assert_ne!(u32_at(section + 36) & 0x20000000, 0);
                    let start = (u32_at(section + 20) + offset) as usize;
                    return &image[start..start + count as usize];
                }
            }
        }
        panic!("owned marker has no executable on-disk section");
    }
}
