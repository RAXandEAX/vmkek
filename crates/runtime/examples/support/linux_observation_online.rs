use super::*;
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::{Path, PathBuf}};

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature};
use vmkek_runtime::{
    observations::ObservationReport, runtime_observation_report, vmk_initialize, VmkInitializeV2,
    ONLINE_ABI_VERSION, PROFILE_ONLINE,
};
use zeroize::Zeroizing;

const BASE_KEY_OFFSET: usize = 8 + 5 * 16 + 8 + 16 + 65 + 65 + 8 + 4;

pub(super) fn run(case: &str, mode: ObservationMode) {
    let base = PathBuf::from(env::var_os("VMKEK_A10_ONLINE_CONFIG").unwrap());
    let directory = PathBuf::from(env::var_os("VMKEK_A10_PRIVATE").unwrap());
    let name = directory.join("observed.bin");
    write_config(&base, &directory, &name, mode);
    let path = name.to_str().unwrap();
    let init = VmkInitializeV2 {
        size: size_of::<VmkInitializeV2>() as u32, abi_version: ONLINE_ABI_VERSION,
        profile: PROFILE_ONLINE, reserved: 0,
        config_path: VmkBytes { data: path.as_ptr(), len: path.len() as u64 },
        reserved_tail: [0; 2],
    };
    let mut handle = 0;
    let start = Instant::now();
    // SAFETY: The ABI inputs, path and output handle are live and disjoint.
    let status = unsafe { vmk_initialize((&raw const init).cast(), &mut handle) };
    fs::remove_file(name).unwrap();
    fs::remove_file(directory.join("device.key")).unwrap();
    assert_eq!(status, Status::Ok as u32, "online initialization");
    let expected = if case == "online-gdb" { "Observed" } else { "NotObservedWithinScope" };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(sample) = runtime_observation(handle, SignalId::DEBUGGER).unwrap().and_then(|row| row.sample) {
            if format!("{:?}", sample.record.finding) == expected { break; }
        }
        assert!(Instant::now() < deadline, "timed out waiting for online sample");
        thread::sleep(Duration::from_millis(5));
    }
    println!("online_sample_us={}", start.elapsed().as_micros());
    report(handle, SignalId::DEBUGGER);
    let (status, verified, elapsed) = invoke(handle, 1, true);
    println!("invoke_status={status} output_verified={verified} invoke_ns={elapsed}");
    assert!(verified);
    if case == "online-gdb" && mode == ObservationMode::Enforce {
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            match runtime_observation_report(handle).unwrap() {
                ObservationReport::Acknowledged => break,
                ObservationReport::NotCompleted if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                result => panic!("online own-stop report did not complete: {result:?}"),
            }
        }
        let (status, intact, _) = invoke(handle, 2, true);
        assert_eq!((status, intact), (Status::Denied as u32, true));
        println!("online_report=acknowledged repeated_deny=true");
    } else {
        assert_eq!(status, Status::Ok as u32);
        assert_eq!(runtime_observation_report(handle).unwrap(), ObservationReport::NotCompleted);
        println!("online_report=none repeated_deny=false");
    }
    assert_eq!(vmk_shutdown(handle), Status::Ok as u32);
}

fn private_write(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)
        .unwrap().write_all(bytes).unwrap();
}

fn write_config(base: &Path, directory: &Path, name: &Path, mode: ObservationMode) {
    let mut source = Zeroizing::new(fs::read(base).unwrap());
    assert!((BASE_KEY_OFFSET + 32..=128 * 1024).contains(&source.len()));
    assert_eq!(&source[..8], b"VMKR13\0\0");
    let key = SigningKey::from_slice(&[0x75; 32]).unwrap();
    let signed = signed_policy(&key, source[8..24].try_into().unwrap(),
        source[24..40].try_into().unwrap(), ObservationProfile::Online, mode,
        vec![SignalId::DEBUGGER], Vec::new());
    let digest = Sha256::digest(signed.as_bytes());
    println!("policy_sha256={digest:x} policy_epoch={EPOCH}");
    let mut hash = Sha256::new();
    hash.update(b"vmkek.protocol.v1.r17.local-stop\0");
    hash.update(digest);
    hash.update([1]);
    let consent: Signature = key.sign_prehash(&hash.finalize()).unwrap();
    private_write(&directory.join("device.key"), &source[BASE_KEY_OFFSET..BASE_KEY_OFFSET + 32]);
    let mut config = Zeroizing::new(Vec::new());
    source[..8].copy_from_slice(b"VMKRA10\0");
    config.extend_from_slice(&source[..BASE_KEY_OFFSET]);
    config.extend_from_slice(&source[BASE_KEY_OFFSET + 32..]);
    config.push(1);
    config.extend_from_slice(key.verifying_key().to_encoded_point(false).as_bytes());
    config.extend(EPOCH.to_le_bytes());
    config.extend(consent.to_bytes());
    config.extend(u32::try_from(signed.as_bytes().len()).unwrap().to_le_bytes());
    config.extend(signed.as_bytes());
    private_write(name, &config);
}