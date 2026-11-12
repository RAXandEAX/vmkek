use chacha20poly1305::Tag;
use vmkek_protocol::{
    lab::{Instruction, LabProgram, Scalar, ScalarType},
    Budgets, Extension, ModuleExpectation, ABI_VERSION,
};

use super::*;

const RELEASE: Release = Release {
    module_id: [5; 16],
    module_version: 1,
    not_before_ms: 100,
    expires_at_ms: 200,
};

fn signer(value: u8) -> SigningKey {
    SigningKey::from_slice(&[value; 32]).unwrap()
}

fn fixture() -> (VmDescriptor, Vec<u8>) {
    let program = LabProgram {
        arguments: Vec::new(),
        result: Some(ScalarType::U64),
        instructions: vec![Instruction::Constant(Scalar::U64(42)), Instruction::Return],
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
        capabilities: Vec::new(),
        program_sha256: Sha256::digest(&program).into(),
        budgets: Budgets::default(),
        profile: Profile::Online,
        extensions: Vec::new(),
    };
    (descriptor, program)
}

fn fixed_release(descriptor: &VmDescriptor, program: &[u8]) -> SealedRelease {
    seal_with_entropy(
        VerifiedInput::verify("fixture", descriptor, program).unwrap(),
        RELEASE,
        &signer(7),
        &[8; 32],
        [9; 12],
    )
    .unwrap()
}

fn expected(descriptor: &VmDescriptor) -> ModuleExpectation<'_> {
    ModuleExpectation {
        descriptor,
        module_id: RELEASE.module_id,
        module_version: RELEASE.module_version,
        purpose: ModulePurpose::Bytecode,
        now_ms: 150,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

#[test]
fn canonical_seal_matches_independent_python_cryptography_vector() {
    let (descriptor, program) = fixture();
    let SealedRelease { package, key } = fixed_release(&descriptor, &program);
    let signed = SignedModuleManifest::decode(package.manifest_bytes()).unwrap();
    let manifest = signed
        .verify_for(
            signer(7).verifying_key(),
            &expected(&descriptor),
            package.ciphertext(),
        )
        .unwrap();
    let aad = manifest.authentication_data().unwrap();
    assert_eq!(
        hex(&manifest.descriptor_sha256),
        "714ae4b5c1b44a2781072e1d990fb0e4a0af65321c63f278343646fd06f03df3"
    );
    assert_eq!(
        hex(&Sha256::digest(&aad)),
        "ecc7924628e4ec9348d6a2e4eef2a9821f2e0b2403cc1ff8fa9c52c2fe0cee00"
    );
    assert_eq!(
        hex(package.ciphertext()),
        "1e1904a81674de508fb5629e0e1473fdbdb60e2186dec2abfae13423ef242b82329b41cffe9f79"
    );
    assert_eq!(hex(&manifest.tag), "f6134e36e329353facd4ef1fdbc354dd");
    let unsigned = &package.manifest_bytes()[..package.manifest_bytes().len() - 64];
    let mut transcript = Sha256::new();
    transcript.update(b"vmkek.protocol.v1.module-signature\0");
    transcript.update(unsigned);
    assert_eq!(
        hex(&transcript.finalize()),
        "b524909ef8748b2d4b81933f092eb0bae91d8f52edf1ba794f0cfee8796f9a52"
    );
    let frame = PackageFrame {
        descriptor: package.descriptor_bytes(),
        manifest: package.manifest_bytes(),
        ciphertext: package.ciphertext(),
    };
    let encoded = frame.encode().unwrap();
    assert_eq!(encoded.len(), frame.encoded_len().unwrap());
    assert_eq!(
        PackageFrame::decode(&encoded).unwrap().ciphertext,
        package.ciphertext()
    );
    assert_eq!(
        VmDescriptor::decode(package.descriptor_bytes())
            .unwrap()
            .profile,
        Profile::Online
    );
    let cipher = ChaCha20Poly1305::new(key.as_secret().into());
    let mut opened = package.ciphertext().to_vec();
    cipher
        .decrypt_in_place_detached(
            (&manifest.nonce).into(),
            &aad,
            &mut opened,
            Tag::from_slice(&manifest.tag),
        )
        .unwrap();
    assert_eq!(opened, program);
    let mut bad_aad = aad;
    bad_aad[0] ^= 1;
    assert!(cipher
        .decrypt_in_place_detached(
            (&manifest.nonce).into(),
            &bad_aad,
            &mut package.ciphertext().to_vec(),
            Tag::from_slice(&manifest.tag)
        )
        .is_err());
    let mut bad_tag = manifest.tag;
    bad_tag[0] ^= 1;
    assert!(cipher
        .decrypt_in_place_detached(
            (&manifest.nonce).into(),
            &manifest.authentication_data().unwrap(),
            &mut package.ciphertext().to_vec(),
            Tag::from_slice(&bad_tag)
        )
        .is_err());
}

#[test]
fn tamper_unknown_signer_wrong_scope_and_lengths_are_rejected() {
    let (descriptor, program) = fixture();
    let package = fixed_release(&descriptor, &program).package;
    let signed = SignedModuleManifest::decode(package.manifest_bytes()).unwrap();
    let trusted = signer(7);
    let verify = |descriptor: &VmDescriptor, bytes: &[u8]| {
        signed
            .verify_for(trusted.verifying_key(), &expected(descriptor), bytes)
            .map(|_| ())
    };
    let mut tampered = package.ciphertext().to_vec();
    tampered[0] ^= 1;
    assert_eq!(verify(&descriptor, &tampered), Err(ProtocolError::Binding));
    assert_eq!(
        verify(&descriptor, &tampered[1..]),
        Err(ProtocolError::Binding)
    );
    assert_eq!(
        signed.verify_for(
            signer(10).verifying_key(),
            &expected(&descriptor),
            package.ciphertext()
        ),
        Err(ProtocolError::Signature)
    );
    for wrong in [
        VmDescriptor {
            app_id: [9; 16],
            ..descriptor.clone()
        },
        VmDescriptor {
            build_id: [9; 16],
            ..descriptor.clone()
        },
        VmDescriptor {
            function_id: [9; 16],
            ..descriptor.clone()
        },
        VmDescriptor {
            generation_id: [9; 16],
            ..descriptor.clone()
        },
        VmDescriptor {
            profile: Profile::Lab,
            ..descriptor.clone()
        },
    ] {
        assert_eq!(
            verify(&wrong, package.ciphertext()),
            Err(ProtocolError::Binding)
        );
    }

    let mut metadata = package.manifest_bytes().to_vec();
    metadata[12] ^= 1;
    let tampered = SignedModuleManifest::decode(&metadata).unwrap();
    assert_eq!(
        tampered.verify_for(
            trusted.verifying_key(),
            &expected(&descriptor),
            package.ciphertext()
        ),
        Err(ProtocolError::Signature)
    );
    metadata[0] = 0;
    assert!(matches!(
        SignedModuleManifest::decode(&metadata),
        Err(ProtocolError::Version)
    ));
    assert!(SignedModuleManifest::decode(
        &package.manifest_bytes()[..package.manifest_bytes().len() - 1]
    )
    .is_err());
}

#[test]
fn verification_requires_online_stack_valid_bytecode_and_known_fields() {
    let (descriptor, program) = fixture();
    assert!(matches!(
        VerifiedInput::verify("../fixture", &descriptor, &program),
        Err(PackagerError::Name)
    ));
    let lab = VmDescriptor {
        profile: Profile::Lab,
        ..descriptor.clone()
    };
    let register = VmDescriptor {
        form: VmForm::Register,
        ..descriptor.clone()
    };
    for wrong in [lab, register] {
        assert!(matches!(
            VerifiedInput::verify("fixture", &wrong, &program),
            Err(PackagerError::Incompatible)
        ));
    }
    let mut tampered = program;
    *tampered.last_mut().unwrap() = 0xff;
    let invalid = VmDescriptor {
        program_sha256: Sha256::digest(&tampered).into(),
        ..descriptor.clone()
    };
    assert!(matches!(
        VerifiedInput::verify("fixture", &invalid, &tampered),
        Err(PackagerError::Bytecode)
    ));
    let unknown = VmDescriptor {
        extensions: vec![Extension {
            id: 1,
            required: true,
            bytes: vec![],
        }],
        ..descriptor
    };
    assert!(matches!(
        VerifiedInput::verify("fixture", &unknown, &tampered),
        Err(PackagerError::Protocol(ProtocolError::UnknownMandatory))
    ));
}

#[test]
fn fresh_seals_get_distinct_ciphertexts_and_keys() {
    let (descriptor, program) = fixture();
    let input = || VerifiedInput::verify("local-build-label", &descriptor, &program).unwrap();
    let signer = signer(7);
    let a = seal(input(), RELEASE, &signer).unwrap();
    let b = seal(input(), RELEASE, &signer).unwrap();
    assert!(a.key.as_secret() != b.key.as_secret());
    assert_ne!(a.package.ciphertext(), b.package.ciphertext());
    assert_ne!(a.package.manifest_bytes(), b.package.manifest_bytes());
    let report = a.package.public_report();
    assert_eq!(
        report.manifest_sha256,
        <[u8; 32]>::from(Sha256::digest(a.package.manifest_bytes()))
    );
    assert_eq!(report.ciphertext_size as usize, program.len());
    let text = format!("{report:?}");
    assert!(!text.contains("local-build-label"));
    assert!(!text.contains("nonce"));
    assert!(!text.contains("bytecode"));
    assert!(!text.contains(&hex(a.key.as_secret())));
}

#[test]
fn release_version_fits_signed_database_boundary() {
    let (descriptor, program) = fixture();
    let input = || VerifiedInput::verify("fixture", &descriptor, &program).unwrap();
    let signer = signer(7);
    let maximum = Release {
        module_version: i64::MAX as u64,
        ..RELEASE
    };
    let accepted = seal(input(), maximum, &signer).unwrap();
    assert_eq!(
        accepted.package.public_report().module_version,
        maximum.module_version
    );
    let oversized = Release {
        module_version: maximum.module_version + 1,
        ..maximum
    };
    assert!(matches!(
        seal(input(), oversized, &signer),
        Err(PackagerError::Protocol(ProtocolError::Invalid))
    ));
}
