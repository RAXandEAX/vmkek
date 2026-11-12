use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest as _, Sha256};
use vmkek_protocol::{
    detection::{
        BuildRange, DetectionPolicy, ObservationMode, ObservationProfile, ObservationReaction,
        ObservationRule, ObservationSettings, SignedDetectionPolicy,
    },
    public_key_id,
    session_observation::SignalId,
    Digest,
};
use zeroize::Zeroizing;

pub const EPOCH: u64 = 7;
const FLAGS: u8 = 1;

pub fn write(base: &Path, windows_build: u32) -> (PathBuf, Digest) {
    let mut config = Zeroizing::new(fs::read(base).unwrap());
    assert_eq!(&config[..8], b"VMKR13\0\0");
    let key = SigningKey::from_slice(&[0x75; 32]).unwrap();
    let signed = policy(&config, &key, windows_build);
    let mut hash = Sha256::new();
    hash.update(b"vmkek.protocol.v1.r17.local-stop\0");
    hash.update(Sha256::digest(signed.as_bytes()));
    hash.update([FLAGS]);
    let consent: Signature = key.sign_prehash(&hash.finalize()).unwrap();
    config[..8].copy_from_slice(b"VMKR17\0\0");
    config.push(FLAGS);
    config.extend(key.verifying_key().to_encoded_point(false).as_bytes());
    config.extend(EPOCH.to_le_bytes());
    config.extend(consent.to_bytes());
    config.extend(
        u32::try_from(signed.as_bytes().len())
            .unwrap()
            .to_le_bytes(),
    );
    config.extend(signed.as_bytes());
    let digest = Sha256::digest(signed.as_bytes()).into();
    let path = base.with_file_name(format!("a07-observed-{}.bin", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(&config).unwrap();
    drop(file);
    drop(config);
    (path, digest)
}

fn policy(config: &[u8], key: &SigningKey, build: u32) -> SignedDetectionPolicy {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    SignedDetectionPolicy::sign_for_profile(
        DetectionPolicy {
            app_id: config[8..24].try_into().unwrap(),
            build_id: config[24..40].try_into().unwrap(),
            key_id: public_key_id(key.verifying_key()),
            epoch: EPOCH,
            issued_ms: now.saturating_sub(1000),
            expires_ms: now + 60_000,
            windows_builds: BuildRange {
                first: build,
                last: build,
            },
            artifacts: vec![],
            images: vec![],
        },
        ObservationSettings {
            profile: ObservationProfile::Online,
            mode: ObservationMode::Enforce,
            max_age_ms: 2_000,
            rules: vec![ObservationRule {
                signal_id: SignalId::DEBUGGER,
                required: true,
                reaction: ObservationReaction::Stop,
            }],
        },
        key,
    )
    .unwrap()
}
