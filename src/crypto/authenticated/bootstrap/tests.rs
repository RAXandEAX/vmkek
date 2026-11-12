use super::*;
use crate::crypto::authenticated::{BlockPurpose, MasterSecret};

const PLAIN: &[u8] = b"R02 authenticated bootstrap";

fn context() -> BootstrapContext {
    BootstrapContext {
        platform: Platform::Pe32Plus,
        profile: Profile::Lab,
        scope: BlockScope {
            app: [1; 16],
            build: [2; 16],
            function: [3; 16],
            generation: [4; 16],
            level: 1,
            purpose: BlockPurpose::Payload,
        },
        payload_offset: 0x4000,
        payload_len: PLAIN.len() as u32,
        original_entry_rva: 0x1234,
        preferred_base: 0x140000000,
    }
}

fn manufacturer(scalar: u8) -> (SigningKey, ManufacturerPin) {
    let mut fixture_scalar = [0; 32];
    fixture_scalar[31] = scalar;
    let key = SigningKey::from_slice(&fixture_scalar).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let pin = ManufacturerPin::from_sec1(point.as_bytes().try_into().unwrap()).unwrap();
    (key, pin)
}

#[test]
fn canonical_core_and_ciphertext_match_independent_vector() {
    // Python cryptography 41.0.7 HKDF and ChaCha20Poly1305 over independently
    // encoded fixed fields. The only fixed master and salt are test fixtures.
    let master = MasterSecret(Zeroizing::new([0x11; 32]));
    let context = context();
    let scope = master.scope(context.scope).unwrap();
    let (signing, pin) = manufacturer(1);
    let block = BlockCoordinate {
        salt: [0xa5; 32],
        sequence: 7,
    };
    let key = scope.block_key(&block.salt, block.sequence).unwrap();
    let sealed = seal_at(&context, &pin, &signing, PLAIN, &block, &key).unwrap();
    assert_eq!(
        hex::encode(sha256(&sealed.manifest[..BOOTSTRAP_CORE_LEN])),
        "940ff97dce5dcf6118a755dde72c5404601f519b59b45d1785c4f074f008e56f"
    );
    assert_eq!(
        hex::encode(&sealed.ciphertext),
        "da907576b2b170eb0bd64202829fe0b04c58f5b9594c571e0b4d11"
    );
    assert_eq!(
        hex::encode(&sealed.manifest[BOOTSTRAP_TAG_OFFSET..BOOTSTRAP_SIGNATURE_OFFSET]),
        "395987a49ff12b44b748246615e8f772"
    );
    let opened =
        open_bootstrap(&scope, &context, &pin, &sealed.manifest, &sealed.ciphertext).unwrap();
    assert_eq!(opened.as_slice(), PLAIN);
}

#[test]
fn corrupt_metadata_ciphertext_tag_and_signature_are_refused() {
    let context = context();
    let scope = MasterSecret::generate()
        .unwrap()
        .scope(context.scope)
        .unwrap();
    let (signing, pin) = manufacturer(1);
    let sealed = BootstrapSealer::new(&scope)
        .seal(&context, &pin, &signing, PLAIN)
        .unwrap();
    let verify = |manifest: &[u8], ciphertext: &[u8]| {
        open_bootstrap(&scope, &context, &pin, manifest, ciphertext)
    };
    for offset in [
        0,
        16,
        18,
        20,
        22,
        23,
        24,
        90,
        98,
        102,
        106,
        110,
        BOOTSTRAP_KEY_ID_OFFSET,
        BOOTSTRAP_SALT_OFFSET,
        BOOTSTRAP_SEQUENCE_OFFSET,
        BOOTSTRAP_NONCE_OFFSET,
        BOOTSTRAP_HASH_OFFSET,
        BOOTSTRAP_TAG_OFFSET,
        BOOTSTRAP_SIGNATURE_OFFSET,
    ] {
        let mut corrupted = sealed.manifest;
        corrupted[offset] ^= 1;
        assert!(
            verify(&corrupted, &sealed.ciphertext).is_err(),
            "offset {offset}"
        );
    }
    let mut forged_tag = sealed.manifest;
    forged_tag[BOOTSTRAP_TAG_OFFSET] ^= 1;
    let signature: Signature = signing.sign(&signature_transcript(&forged_tag));
    forged_tag[BOOTSTRAP_SIGNATURE_OFFSET..].copy_from_slice(&signature.to_bytes());
    assert!(matches!(
        verify(&forged_tag, &sealed.ciphertext),
        Err(Error::Integrity)
    ));
    let mut ciphertext = sealed.ciphertext;
    ciphertext[0] ^= 1;
    assert!(verify(&sealed.manifest, &ciphertext).is_err());
    assert!(verify(&sealed.manifest[..BOOTSTRAP_MANIFEST_LEN - 1], &ciphertext).is_err());
    let mut forged = sealed.manifest;
    forged[BOOTSTRAP_HASH_OFFSET..BOOTSTRAP_TAG_OFFSET].copy_from_slice(&sha256(&ciphertext));
    let signature: Signature = signing.sign(&signature_transcript(&forged));
    forged[BOOTSTRAP_SIGNATURE_OFFSET..].copy_from_slice(&signature.to_bytes());
    assert!(matches!(
        verify(&forged, &ciphertext),
        Err(Error::Integrity)
    ));
}

#[test]
fn wrong_pin_and_changed_trusted_scope_are_refused() {
    let context = context();
    let master = MasterSecret::generate().unwrap();
    let scope = master.scope(context.scope).unwrap();
    let (signing, pin) = manufacturer(1);
    let (_, wrong_pin) = manufacturer(2);
    let mut sealer = BootstrapSealer::new(&scope);
    assert!(matches!(
        sealer.seal(&context, &wrong_pin, &signing, PLAIN),
        Err(Error::BadSignature)
    ));
    let sealed = sealer.seal(&context, &pin, &signing, PLAIN).unwrap();
    let verify = |scope, expected, pin| {
        open_bootstrap(scope, expected, pin, &sealed.manifest, &sealed.ciphertext)
    };
    assert!(verify(&scope, &context, &wrong_pin).is_err());
    let changed = BootstrapContext {
        scope: BlockScope {
            generation: [0xff; 16],
            ..context.scope
        },
        ..context
    };
    let changed_scope = master.scope(changed.scope).unwrap();
    assert!(verify(&changed_scope, &changed, &pin).is_err());
    let foreign = MasterSecret::generate()
        .unwrap()
        .scope(context.scope)
        .unwrap();
    assert!(verify(&foreign, &context, &pin).is_err());
    assert!(ManufacturerPin::from_sec1(&[0; 65]).is_err());
}

#[test]
fn repeat_reads_and_restarted_sealing_use_the_expected_coordinates() {
    let context = context();
    let scope = MasterSecret::generate()
        .unwrap()
        .scope(context.scope)
        .unwrap();
    let (signing, pin) = manufacturer(1);
    let mut sealer = BootstrapSealer::new(&scope);
    let mut restarted = BootstrapSealer::new(&scope);
    let first = sealer.seal(&context, &pin, &signing, PLAIN).unwrap();
    let second = sealer.seal(&context, &pin, &signing, PLAIN).unwrap();
    let other = restarted.seal(&context, &pin, &signing, PLAIN).unwrap();
    let (a, b, c) = (
        BlockCoordinate::from_manifest(&first.manifest).unwrap(),
        BlockCoordinate::from_manifest(&second.manifest).unwrap(),
        BlockCoordinate::from_manifest(&other.manifest).unwrap(),
    );
    assert_eq!((a.sequence, b.sequence, c.sequence), (0, 1, 0));
    assert_ne!(a.salt, c.salt);
    assert_ne!(first.ciphertext, other.ciphertext);
    for _ in 0..3 {
        let opened =
            open_bootstrap(&scope, &context, &pin, &first.manifest, &first.ciphertext).unwrap();
        assert_eq!(opened.as_slice(), PLAIN);
    }
    sealer.sequence = u64::MAX;
    assert!(sealer
        .seal(&context, &pin, &signing, PLAIN)
        .err()
        .expect("exhausted sequence")
        .to_string()
        .contains("sequence exhausted"));
}

#[test]
fn lab_handoff_is_per_artifact_and_rejects_online_embedding() {
    let context = context();
    let scope = MasterSecret::generate()
        .unwrap()
        .scope(context.scope)
        .unwrap();
    let (signing, pin) = manufacturer(1);
    let mut sealer = BootstrapSealer::new(&scope);
    let (first, key) = sealer
        .seal_for_native_lab(&context, &pin, &signing, PLAIN)
        .unwrap();
    let (_, other_key) = sealer
        .seal_for_native_lab(&context, &pin, &signing, PLAIN)
        .unwrap();
    assert!(key.as_bytes() != other_key.as_bytes());
    assert!(!first
        .manifest
        .windows(AEAD_KEY_LEN)
        .any(|part| part == key.as_bytes()));
    assert!(sealer
        .seal_for_native_lab(
            &BootstrapContext {
                profile: Profile::Online,
                ..context
            },
            &pin,
            &signing,
            PLAIN
        )
        .is_err());
}

#[test]
fn invalid_trusted_payload_extents_fail_before_encryption() {
    let context = context();
    let scope = MasterSecret::generate()
        .unwrap()
        .scope(context.scope)
        .unwrap();
    let (signing, pin) = manufacturer(1);
    let mut sealer = BootstrapSealer::new(&scope);
    for expected in [
        BootstrapContext {
            payload_offset: u64::MAX,
            ..context
        },
        BootstrapContext {
            payload_offset: u64::from(u32::MAX),
            ..context
        },
        BootstrapContext {
            payload_len: 0,
            ..context
        },
        BootstrapContext {
            payload_len: BOOTSTRAP_MAX_PAYLOAD as u32 + 1,
            ..context
        },
    ] {
        assert!(sealer.seal(&expected, &pin, &signing, PLAIN).is_err());
    }
    assert_eq!(sealer.sequence, 0);
}

#[test]
fn bootstrap_rejects_non_payload_scope() {
    let mut expected = context();
    expected.scope.purpose = BlockPurpose::Dispatcher;
    let scope = MasterSecret::generate()
        .unwrap()
        .scope(expected.scope)
        .unwrap();
    let (signing, pin) = manufacturer(1);
    let mut sealer = BootstrapSealer::new(&scope);
    assert!(sealer.seal(&expected, &pin, &signing, PLAIN).is_err());
    assert_eq!(sealer.sequence, 0);
}
