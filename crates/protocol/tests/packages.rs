use p256::ecdsa::SigningKey;
use vmkek_protocol::{
    public_key_id, Extension, ModuleFetch, ModulePurpose, PackageFrame, ProtocolError,
    SignedTrustBundle, TrustBundle, MAX_BODY_BYTES,
};

fn key(value: u8) -> SigningKey {
    let mut scalar = [0; 32];
    scalar[31] = value;
    SigningKey::from_slice(&scalar).unwrap()
}

fn public(key: &SigningKey) -> [u8; 65] {
    key.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}

#[test]
fn trust_envelope_has_pinned_scope_and_fail_closed_rotation() {
    let root = key(1);
    let active = key(2);
    let next = key(3);
    let bundle = TrustBundle {
        app_id: [1; 16],
        epoch: 7,
        active: public(&active),
        next: Some(public(&next)),
        revoked: vec![[0x80; 32]],
        root_key_id: public_key_id(root.verifying_key()),
        extensions: vec![],
    };
    let signed = SignedTrustBundle::sign(bundle.clone(), &root).unwrap();
    let bytes = signed.as_bytes();
    assert_eq!(&bytes[..bytes.len() - 64], decode(TRUST_PREFIX));
    let signed = SignedTrustBundle::decode(bytes).unwrap();
    assert_eq!(
        signed.verify_for(root.verifying_key(), bundle.app_id, 7),
        Ok(&bundle)
    );
    assert_eq!(
        signed.verify_for(active.verifying_key(), bundle.app_id, 7),
        Err(ProtocolError::Signature)
    );
    assert_eq!(
        signed.verify_for(root.verifying_key(), [2; 16], 7),
        Err(ProtocolError::Binding)
    );
    assert_eq!(
        signed.verify_for(root.verifying_key(), bundle.app_id, 8),
        Err(ProtocolError::Binding)
    );
    let mut tampered = bytes.to_vec();
    tampered[12] ^= 1;
    let altered = SignedTrustBundle::decode(&tampered).unwrap();
    assert_eq!(
        altered.verify_for(root.verifying_key(), [0; 16], 7),
        Err(ProtocolError::Signature)
    );

    let promoted = TrustBundle {
        epoch: 8,
        active: public(&next),
        next: None,
        ..bundle.clone()
    };
    assert_eq!(promoted.check_successor(&bundle), Ok(()));
    assert_eq!(
        TrustBundle {
            active: public(&key(4)),
            ..promoted.clone()
        }
        .check_successor(&bundle),
        Err(ProtocolError::Binding)
    );
    assert_eq!(
        TrustBundle {
            revoked: vec![],
            ..promoted.clone()
        }
        .check_successor(&bundle),
        Err(ProtocolError::Binding)
    );
    assert!(matches!(
        SignedTrustBundle::sign(
            TrustBundle {
                extensions: vec![Extension {
                    id: 1,
                    required: true,
                    bytes: vec![]
                }],
                ..promoted
            },
            &root
        ),
        Err(ProtocolError::UnknownMandatory)
    ));
}

#[test]
fn module_fetch_and_package_frame_have_canonical_bounded_layouts() {
    let request = ModuleFetch {
        app_id: [1; 16],
        build_id: [2; 16],
        device_id: [3; 16],
        session_id: [4; 16],
        generation_id: [5; 16],
        function_id: [6; 16],
        module_id: [7; 16],
        module_version: 8,
        purpose: ModulePurpose::Bytecode,
        sequence: 9,
        request_id: [10; 16],
    };
    let bytes = request.encode().unwrap();
    assert_eq!(bytes, decode(FETCH_HEX));
    assert_eq!(ModuleFetch::decode(&bytes), Ok(request));
    let key = key(1);
    let proof = request.sign(&key).unwrap();
    assert_eq!(request.verify(key.verifying_key(), &proof), Ok(()));
    let foreign = ModuleFetch {
        module_version: 9,
        ..request
    };
    assert_eq!(
        foreign.verify(key.verifying_key(), &proof),
        Err(ProtocolError::Signature)
    );
    let frame = PackageFrame {
        descriptor: b"a",
        manifest: b"bc",
        ciphertext: b"def",
    };
    let bytes = frame.encode().unwrap();
    assert_eq!(
        bytes,
        decode("01000a0012000000010000006102000000626303000000646566")
    );
    assert_eq!(bytes.len(), frame.encoded_len().unwrap());
    assert_eq!(PackageFrame::decode(&bytes), Ok(frame));
    assert_eq!(
        PackageFrame::decode(&bytes[..bytes.len() - 1]),
        Err(ProtocolError::Invalid)
    );
    let oversized = vec![0; MAX_BODY_BYTES];
    assert_eq!(
        PackageFrame {
            ciphertext: &oversized,
            ..frame
        }
        .encoded_len(),
        Err(ProtocolError::Limit)
    );
}

fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
const TRUST_PREFIX: &str = concat!(
    "01000800fe000000100000000101010101010101010101010101010108000000",
    "070000000000000041000000047cf27b188d034f7e8a52380304b51ac3c08969",
    "e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dad",
    "e63ce982299e04b79d227873d141000000045ecbe4d1a6330a44c8f7ef951d4b",
    "f165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64",
    "a2ecd82ab036384fb83d9a79b127a27d50322600000001002000000080808080",
    "8080808080808080808080808080808080808080808080808080808020000000",
    "698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be",
    "020000000000",
);
const FETCH_HEX: &str = concat!(
    "01000900bd000000100000000101010101010101010101010101010110000000",
    "0202020202020202020202020202020210000000030303030303030303030303",
    "0303030310000000040404040404040404040404040404041000000005050505",
    "0505050505050505050505051000000006060606060606060606060606060606",
    "1000000007070707070707070707070707070707080000000800000000000000",
    "0100000002080000000900000000000000100000000a0a0a0a0a0a0a0a0a0a0a",
    "0a0a0a0a0a",
);
