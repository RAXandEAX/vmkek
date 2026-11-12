mod common;

use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use common::hex;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest as _, Sha256};
use vmkek_protocol::{
    public_key_id, Capability, Extension, GrantBinding, GrantExpectation, ModuleExpectation,
    ModulePurpose, Permission, PermissionKind, Profile, ProtocolError, SessionGrant,
    SignedModuleManifest, VmDescriptor, VmForm, MAX_GRANT_LIFETIME_MS,
};

const OPTIONAL: &[u8] = b"future optional";

fn descriptor() -> (Vec<u8>, VmDescriptor) {
    let bytes = hex(include_str!("fixtures/descriptor-v1.hex"));
    let decoded = VmDescriptor::decode(&bytes).unwrap();
    (bytes, decoded)
}

fn key(value: u8) -> SigningKey {
    SigningKey::from_slice(&[value; 32]).unwrap()
}

#[test]
fn descriptor_roundtrip_preserves_the_independent_v1_vector() {
    let (bytes, descriptor) = descriptor();
    assert_eq!(descriptor.abi_version, 1);
    assert_eq!(descriptor.profile, Profile::Lab);
    assert_eq!(descriptor.form, VmForm::Stack);
    assert_eq!(descriptor.depth, 2);
    assert_eq!(descriptor.app_id, [1; 16]);
    assert_eq!(descriptor.generation_id, [4; 16]);
    assert_eq!(
        descriptor.extensions,
        [Extension {
            id: 7,
            required: false,
            bytes: OPTIONAL.to_vec()
        }]
    );
    assert_eq!(descriptor.encode().unwrap(), bytes);
}

#[test]
fn version_mandatory_optional_order_and_extent_are_checked() {
    let (bytes, mut value) = descriptor();
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(VmDescriptor::decode(&extra), Err(ProtocolError::Invalid));
    let mut version = bytes.clone();
    version[0] = 2;
    assert_eq!(VmDescriptor::decode(&version), Err(ProtocolError::Version));
    let mut oversized_field = bytes.clone();
    oversized_field[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        VmDescriptor::decode(&oversized_field),
        Err(ProtocolError::Limit)
    );

    let mut required_extension = bytes;
    let flag = required_extension.len() - OPTIONAL.len() - 5;
    required_extension[flag] = 1;
    assert_eq!(
        VmDescriptor::decode(&required_extension),
        Err(ProtocolError::UnknownMandatory)
    );

    value.capabilities.push(Capability {
        id: 7,
        required: false,
    });
    let optional = value.encode().unwrap();
    assert_eq!(
        VmDescriptor::decode(&optional).unwrap().encode().unwrap(),
        optional
    );
    value.capabilities[1].required = true;
    assert_eq!(value.encode(), Err(ProtocolError::UnknownMandatory));
    value.capabilities[1] = value.capabilities[0];
    assert_eq!(value.encode(), Err(ProtocolError::Invalid));
    value.capabilities.pop();
    value.extensions.push(value.extensions[0].clone());
    assert_eq!(value.encode(), Err(ProtocolError::Invalid));
}

#[test]
fn independent_manifest_binds_pin_descriptor_purpose_and_aead_data() {
    let (_, descriptor) = descriptor();
    let manufacturer = key(0x21);
    let bytes = hex(include_str!("fixtures/manifest-v1.hex"));
    let ciphertext = hex(include_str!("fixtures/module-ciphertext-v1.hex"));
    let signed = SignedModuleManifest::decode(&bytes).unwrap();
    assert_eq!(signed.as_bytes(), bytes);
    let expected = ModuleExpectation {
        descriptor: &descriptor,
        module_id: [5; 16],
        module_version: 1,
        purpose: ModulePurpose::Bytecode,
        now_ms: 1_000,
    };
    let manifest = signed
        .verify_for(manufacturer.verifying_key(), &expected, &ciphertext)
        .unwrap();
    assert_eq!(
        manifest.signing_key_id,
        public_key_id(manufacturer.verifying_key())
    );
    let aad = manifest.authentication_data().unwrap();
    assert_eq!(aad, hex(include_str!("fixtures/module-aad-v1.hex")));
    let mut plaintext = ciphertext.clone();
    ChaCha20Poly1305::new((&[0x6c; 32]).into())
        .decrypt_in_place_detached(
            Nonce::from_slice(&manifest.nonce),
            &aad,
            &mut plaintext,
            Tag::from_slice(&manifest.tag),
        )
        .unwrap();
    assert_eq!(plaintext, hex(include_str!("fixtures/lab-program-v1.hex")));
    assert_eq!(
        Sha256::digest(plaintext).as_slice(),
        descriptor.program_sha256
    );
    let newly_signed = SignedModuleManifest::sign(manifest.clone(), &manufacturer).unwrap();
    assert_eq!(
        newly_signed.verify_for(manufacturer.verifying_key(), &expected, &ciphertext),
        Ok(manifest)
    );
    assert_manifest_refusals(&signed, &expected, &ciphertext);
}

fn assert_manifest_refusals(
    signed: &SignedModuleManifest,
    expected: &ModuleExpectation<'_>,
    ciphertext: &[u8],
) {
    let manufacturer = key(0x21);
    let pin = manufacturer.verifying_key();
    assert_eq!(
        signed.verify_for(key(0x22).verifying_key(), expected, ciphertext),
        Err(ProtocolError::Signature)
    );
    let mut damaged = ciphertext.to_vec();
    damaged[0] ^= 1;
    assert_eq!(
        signed.verify_for(pin, expected, &damaged),
        Err(ProtocolError::Binding)
    );
    let mut different = expected.descriptor.clone();
    different.generation_id[0] ^= 1;
    let wrong_descriptor = ModuleExpectation {
        descriptor: &different,
        ..*expected
    };
    assert_eq!(
        signed.verify_for(pin, &wrong_descriptor, ciphertext),
        Err(ProtocolError::Binding)
    );
    let wrong_purpose = ModuleExpectation {
        purpose: ModulePurpose::Dispatcher,
        ..*expected
    };
    assert_eq!(
        signed.verify_for(pin, &wrong_purpose, ciphertext),
        Err(ProtocolError::Binding)
    );
    let expired = ModuleExpectation {
        now_ms: 2_000,
        ..*expected
    };
    assert_eq!(
        signed.verify_for(pin, &expired, ciphertext),
        Err(ProtocolError::Expired)
    );
    let mut bytes = signed.as_bytes().to_vec();
    let last_optional_byte = bytes.len() - 65;
    bytes[last_optional_byte] ^= 1;
    assert_eq!(
        SignedModuleManifest::decode(&bytes)
            .unwrap()
            .verify_for(pin, expected, ciphertext),
        Err(ProtocolError::Signature)
    );
}

fn grant_expectation() -> GrantExpectation {
    GrantExpectation {
        binding: GrantBinding {
            session_id: [0x11; 16],
            device_id: [0x12; 16],
            license_id: [0x13; 16],
            app_id: [1; 16],
            build_id: [2; 16],
            generation_id: [4; 16],
        },
        policy_epoch: 9,
        minimum_sequence: 3,
        permission: Permission {
            kind: PermissionKind::Function,
            id: [3; 16],
        },
        now_ms: 1_500,
    }
}

#[test]
fn independent_grant_checks_binding_sequence_permissions_and_expiry() {
    let bytes = hex(include_str!("fixtures/grant-v1.hex"));
    let grant = SessionGrant::decode(&bytes).unwrap();
    let server = key(0x22);
    let pin = server.verifying_key();
    let mut expected = grant_expectation();
    let verified = grant.verify_for(pin, &expected).unwrap();
    assert_eq!(grant.as_bytes(), bytes);
    assert_eq!(verified.sequence, 3);
    assert_eq!(verified.lifetime_ms, 2_000);
    assert_eq!(
        SessionGrant::sign(verified.clone(), &server)
            .unwrap()
            .verify_for(pin, &expected),
        Ok(verified)
    );

    let mut too_long = verified.clone();
    too_long.lifetime_ms = MAX_GRANT_LIFETIME_MS + 1;
    assert_eq!(
        SessionGrant::sign(too_long, &server).unwrap_err(),
        ProtocolError::Limit
    );

    expected.minimum_sequence = 4;
    assert_eq!(
        grant.verify_for(pin, &expected),
        Err(ProtocolError::Binding)
    );
    expected.minimum_sequence = 3;
    expected.policy_epoch = 10;
    assert_eq!(
        grant.verify_for(pin, &expected),
        Err(ProtocolError::Binding)
    );
    expected.policy_epoch = 9;
    expected.binding.device_id[0] ^= 1;
    assert_eq!(
        grant.verify_for(pin, &expected),
        Err(ProtocolError::Binding)
    );
    expected = grant_expectation();
    expected.permission.id[0] ^= 1;
    assert_eq!(
        grant.verify_for(pin, &expected),
        Err(ProtocolError::Binding)
    );
    expected = grant_expectation();
    expected.now_ms = 3_000;
    assert_eq!(
        grant.verify_for(pin, &expected),
        Err(ProtocolError::Expired)
    );
}

#[test]
fn manifest_and_grant_signatures_have_distinct_domains() {
    let server = key(0x22);
    let mut bytes = hex(include_str!("fixtures/grant-v1.hex"));
    let unsigned_len = bytes.len() - 64;
    let mut wrong_domain = b"vmkek.protocol.v1.module-signature\0".to_vec();
    wrong_domain.extend_from_slice(&bytes[..unsigned_len]);
    let wrong_signature: Signature = server.sign(&wrong_domain);
    bytes[unsigned_len..].copy_from_slice(&wrong_signature.to_bytes());
    let grant = SessionGrant::decode(&bytes).unwrap();
    assert_eq!(
        grant.verify_for(server.verifying_key(), &grant_expectation()),
        Err(ProtocolError::Signature)
    );
    assert_eq!(
        SignedModuleManifest::decode(&bytes).unwrap_err(),
        ProtocolError::Type
    );
}
