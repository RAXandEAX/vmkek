use p256::ecdsa::SigningKey;
use vmkek_protocol::{
    detection::{
        Advice, ArtifactKind, ArtifactRule, BuildRange, DetectionPolicy, PolicyContext, Severity,
        SignedDetectionPolicy,
    },
    public_key_id, ProtocolError,
};
use vmkek_runtime::observations::{evaluate_inventory, ArtifactFinding, Inventory};

const BUILD: u32 = 26300;
const DIGEST: [u8; 32] = [9; 32];

fn context(build: u32) -> PolicyContext {
    PolicyContext {
        app_id: [1; 16],
        build_id: [2; 16],
        epoch_floor: 3,
        windows_build: build,
        now_ms: 101,
    }
}

fn test_key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn policy() -> DetectionPolicy {
    DetectionPolicy {
        app_id: [1; 16],
        build_id: [2; 16],
        key_id: public_key_id(test_key(1).verifying_key()),
        epoch: 3,
        issued_ms: 100,
        expires_ms: 110,
        windows_builds: BuildRange {
            first: BUILD - 1,
            last: BUILD + 1,
        },
        artifacts: [
            ArtifactKind::ApplicationFile,
            ArtifactKind::RunningApplication,
            ArtifactKind::DriverPackage,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| ArtifactRule {
            id: index as u16 + 1,
            kind,
            digest: DIGEST,
            severity: Severity::Warning,
            advice: Advice::Review,
            benign_builds: Some(BuildRange {
                first: BUILD,
                last: BUILD,
            }),
        })
        .collect(),
        images: Vec::new(),
    }
}

#[test]
fn signed_policy_rejects_wrong_context_and_noncanonical_wire() {
    let key = test_key(1);
    let signed = SignedDetectionPolicy::sign(policy(), &key).unwrap();
    let decoded = SignedDetectionPolicy::decode(signed.as_bytes()).unwrap();
    for (expected, result) in [
        (
            ProtocolError::Signature,
            decoded.verify_for(test_key(2).verifying_key(), context(BUILD)),
        ),
        (
            ProtocolError::Binding,
            decoded.verify_for(key.verifying_key(), context(BUILD + 2)),
        ),
        (
            ProtocolError::Binding,
            decoded.verify_for(
                key.verifying_key(),
                PolicyContext {
                    epoch_floor: 4,
                    ..context(BUILD)
                },
            ),
        ),
        (
            ProtocolError::Binding,
            decoded.verify_for(
                key.verifying_key(),
                PolicyContext {
                    build_id: [0; 16],
                    ..context(BUILD)
                },
            ),
        ),
        (
            ProtocolError::Binding,
            decoded.verify_for(
                key.verifying_key(),
                PolicyContext {
                    app_id: [0; 16],
                    ..context(BUILD)
                },
            ),
        ),
        (
            ProtocolError::Expired,
            decoded.verify_for(
                key.verifying_key(),
                PolicyContext {
                    now_ms: 110,
                    ..context(BUILD)
                },
            ),
        ),
    ] {
        assert!(matches!(result, Err(error) if error == expected));
    }
    let mut bytes = signed.as_bytes().to_vec();
    bytes[0] = 2;
    assert!(matches!(
        SignedDetectionPolicy::decode(&bytes),
        Err(ProtocolError::Version)
    ));
    bytes.copy_from_slice(signed.as_bytes());
    bytes[110] = 255;
    assert!(matches!(
        SignedDetectionPolicy::decode(&bytes),
        Err(ProtocolError::UnknownMandatory)
    ));
    bytes.copy_from_slice(signed.as_bytes());
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let altered = SignedDetectionPolicy::decode(&bytes).unwrap();
    assert!(matches!(
        altered.verify_for(key.verifying_key(), context(BUILD)),
        Err(ProtocolError::Signature)
    ));

    let mut duplicate = policy();
    duplicate.artifacts[1].kind = ArtifactKind::ApplicationFile;
    assert!(matches!(
        SignedDetectionPolicy::sign(duplicate, &key),
        Err(ProtocolError::Invalid)
    ));
}

#[test]
fn inventory_evidence_stays_in_source_and_benign_scope() {
    let key = test_key(1);
    let signed = SignedDetectionPolicy::sign(policy(), &key).unwrap();
    let verified = signed
        .verify_for(key.verifying_key(), context(BUILD))
        .unwrap();
    let source = ArtifactKind::ApplicationFile;
    for (inventory, expected) in [
        (
            Inventory::Snapshot(&[DIGEST]),
            ArtifactFinding::BenignException,
        ),
        (
            Inventory::Snapshot(&[[0; 32]]),
            ArtifactFinding::NotObservedWithinScope,
        ),
        (
            Inventory::Snapshot(&[DIGEST; 129]),
            ArtifactFinding::Inconclusive,
        ),
        (Inventory::Inconclusive, ArtifactFinding::Inconclusive),
        (Inventory::Unsupported, ArtifactFinding::Unsupported),
    ] {
        let result = evaluate_inventory(&verified, source, inventory, 101).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, 1);
        assert_eq!(result[0].finding, expected);
        assert_eq!(result[0].advice, Advice::Record);
    }
    assert_eq!(
        evaluate_inventory(&verified, source, Inventory::Snapshot(&[DIGEST]), 110),
        Err(ProtocolError::Expired)
    );
    let outside_exception = signed
        .verify_for(key.verifying_key(), context(BUILD + 1))
        .unwrap();
    let result = evaluate_inventory(
        &outside_exception,
        ArtifactKind::DriverPackage,
        Inventory::Snapshot(&[DIGEST]),
        101,
    )
    .unwrap();
    assert_eq!(result[0].rule_id, 3);
    assert_eq!(result[0].finding, ArtifactFinding::ExactMatch);
    assert_eq!(result[0].advice, Advice::Review);
}
