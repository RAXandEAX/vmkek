use p256::ecdsa::SigningKey;
use vmkek_protocol::{
    public_key_id, ProtocolError, RecoveryCheckpoint, RecoveryScope, SignedRecoveryCheckpoint,
    RECOVERY_SNAPSHOT_VERSION,
};

#[test]
fn checkpoint_wire_is_versioned_pinned_and_exact() {
    let signer = SigningKey::from_slice(&[1; 32]).unwrap();
    let foreign = SigningKey::from_slice(&[2; 32]).unwrap();
    let checkpoint = RecoveryCheckpoint {
        scope: RecoveryScope {
            deployment_id: [3; 16],
            app_id: [4; 16],
            build_id: [5; 16],
            history_id: [6; 16],
        },
        fence_id: [7; 16],
        sequence: 8,
        issued_at_ms: 9,
        service_epoch: 10,
        policy_epoch: 11,
        snapshot_version: RECOVERY_SNAPSHOT_VERSION,
        snapshot_sha256: [12; 32],
        signing_key_id: public_key_id(signer.verifying_key()),
    };
    let signed = SignedRecoveryCheckpoint::sign(checkpoint, &signer).unwrap();
    let bytes = signed.as_bytes();
    assert_eq!(&bytes[..8], &[1, 0, 20, 0, 226, 0, 0, 0]);
    assert_eq!(bytes.len(), 298);
    let decoded = SignedRecoveryCheckpoint::decode(bytes).unwrap();
    assert_eq!(decoded.digest(), signed.digest());
    assert_eq!(decoded.verify_for(signer.verifying_key()), Ok(&checkpoint));
    assert_eq!(
        decoded.verify_for(foreign.verifying_key()),
        Err(ProtocolError::Signature)
    );
    let mut altered = bytes.to_vec();
    altered[12] ^= 1;
    let altered = SignedRecoveryCheckpoint::decode(&altered).unwrap();
    assert_eq!(
        altered.verify_for(signer.verifying_key()),
        Err(ProtocolError::Signature)
    );
    let mut bad_version = bytes.to_vec();
    bad_version[0] = 2;
    assert!(matches!(
        SignedRecoveryCheckpoint::decode(&bad_version),
        Err(ProtocolError::Version)
    ));
    let mut bad_snapshot = bytes.to_vec();
    bad_snapshot[160] = 2;
    assert!(matches!(
        SignedRecoveryCheckpoint::decode(&bad_snapshot),
        Err(ProtocolError::Version)
    ));
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(matches!(
        SignedRecoveryCheckpoint::decode(&trailing),
        Err(ProtocolError::Invalid)
    ));
}
