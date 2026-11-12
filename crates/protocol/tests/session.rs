use p256::ecdsa::SigningKey;
use vmkek_protocol::{
    ProtocolError, SessionChallenge, SessionIntent, SessionOperation, SESSION_CHALLENGE_BYTES,
    SESSION_INTENT_BYTES,
};

#[test]
fn canonical_session_exchange_matches_independent_vector() {
    let intent = SessionIntent {
        operation: SessionOperation::Open,
        app_id: [1; 16],
        build_id: [2; 16],
        device_id: [3; 16],
        generation_id: [4; 16],
        session_id: [0; 16],
        sequence: 1,
        request_id: [5; 16],
    };
    let intent_bytes = intent.encode().unwrap();
    assert_eq!(intent_bytes.len(), SESSION_INTENT_BYTES);
    assert_eq!(intent_bytes, from_hex(INTENT_HEX));
    assert_eq!(SessionIntent::decode(&intent_bytes), Ok(intent));
    assert_eq!(
        intent.signature_digest().unwrap().to_vec(),
        from_hex(INTENT_PREHASH)
    );
    let challenge = SessionChallenge {
        intent_digest: intent.digest().unwrap(),
        session_id: [6; 16],
        challenge_id: [7; 16],
        nonce: [8; 32],
    };
    let challenge_bytes = challenge.encode().unwrap();
    assert_eq!(challenge_bytes.len(), SESSION_CHALLENGE_BYTES);
    assert_eq!(challenge_bytes, from_hex(CHALLENGE_HEX));
    assert_eq!(SessionChallenge::decode(&challenge_bytes), Ok(challenge));
    assert_eq!(
        challenge.signature_digest().unwrap().to_vec(),
        from_hex(CHALLENGE_PREHASH)
    );
    let key = SigningKey::from_slice(&[9; 32]).unwrap();
    let intent_proof = intent.sign(&key).unwrap();
    let challenge_proof = challenge.sign(&key).unwrap();
    assert_eq!(intent.verify(key.verifying_key(), &intent_proof), Ok(()));
    assert_eq!(
        challenge.verify(key.verifying_key(), &challenge_proof),
        Ok(())
    );
    assert_eq!(
        challenge.verify(key.verifying_key(), &intent_proof),
        Err(ProtocolError::Signature)
    );
    let mut invalid_version = challenge_bytes;
    invalid_version[0] = 2;
    assert_eq!(
        SessionChallenge::decode(&invalid_version),
        Err(ProtocolError::Version)
    );
    assert_eq!(
        SessionIntent::decode(&intent_bytes[..144]),
        Err(ProtocolError::Invalid)
    );
    assert_eq!(
        SessionIntent {
            sequence: 2,
            ..intent
        }
        .encode(),
        Err(ProtocolError::Invalid)
    );
}

fn from_hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
const INTENT_HEX: &str = concat!(
    "0100060089000000010000000110000000010101010101010101010101010101",
    "0110000000020202020202020202020202020202021000000003030303030303",
    "0303030303030303031000000004040404040404040404040404040404100000",
    "0000000000000000000000000000000000080000000100000000000000100000",
    "0005050505050505050505050505050505",
);
const CHALLENGE_HEX: &str = concat!(
    "0100070070000000200000005d91b9d27d5da67260a79e5f68521dfd495cd65c",
    "1dcb819cc26bc02ef0cc72571000000006060606060606060606060606060606",
    "1000000007070707070707070707070707070707200000000808080808080808",
    "080808080808080808080808080808080808080808080808",
);
const INTENT_PREHASH: &str = "2d9b635a58506277b523b0fd217abdfc567a1e065105070786126e61272f8dc8";
const CHALLENGE_PREHASH: &str = "725a291725c89f0c8c303f2a26d53c5e68851e3c73169c5312090cf720409408";

#[test]
fn signed_permission_superset_is_rejected_for_session() {
    use vmkek_protocol::{
        public_key_id, Extension, GrantBinding, GrantPayload, Permission, PermissionKind,
        SessionGrant, SessionGrantExpectation, SESSION_CHALLENGE_EXTENSION,
    };

    let signer = SigningKey::from_slice(&[3; 32]).unwrap();
    let permission = Permission {
        kind: PermissionKind::Function,
        id: [1; 16],
    };
    let extra = Permission {
        kind: PermissionKind::Operation,
        id: [2; 16],
    };
    let expected = SessionGrantExpectation {
        binding: GrantBinding {
            session_id: [1; 16],
            device_id: [2; 16],
            license_id: [3; 16],
            app_id: [4; 16],
            build_id: [5; 16],
            generation_id: [6; 16],
        },
        policy_epoch: 1,
        sequence: 1,
        permission,
        challenge_digest: [7; 32],
    };
    let payload = GrantPayload {
        binding: expected.binding,
        policy_epoch: expected.policy_epoch,
        sequence: expected.sequence,
        issued_at_ms: 1,
        lifetime_ms: 30_000,
        permissions: vec![permission],
        signing_key_id: public_key_id(signer.verifying_key()),
        extensions: vec![Extension {
            id: SESSION_CHALLENGE_EXTENSION,
            required: false,
            bytes: expected.challenge_digest.to_vec(),
        }],
    };
    let exact = SessionGrant::sign(payload.clone(), &signer).unwrap();
    assert!(exact
        .verify_session(signer.verifying_key(), &expected)
        .is_ok());
    let extra = SessionGrant::sign(
        GrantPayload {
            permissions: vec![permission, extra],
            ..payload
        },
        &signer,
    )
    .unwrap();
    assert_eq!(
        extra.verify_session(signer.verifying_key(), &expected),
        Err(ProtocolError::Binding),
    );
}
