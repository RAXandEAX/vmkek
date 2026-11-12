use p256::ecdsa::SigningKey;
use vmkek_protocol::{
    access_command::{
        AccessAction, AccessAuthority, AccessCommand, AccessReason, AccessRole, SignedAccessCommand,
    },
    public_key_id,
    session_observation::{
        ObservationAction, ObservationFinding, ObservationKind, ObservationRecord,
        SessionObservation, MAX_OBSERVATIONS, MAX_SESSION_OBSERVATION_BYTES,
    },
    ProtocolError,
};

const DEBUG: ObservationRecord = ObservationRecord {
    kind: ObservationKind::DebuggerAttachment,
    rule_id: 0,
    finding: ObservationFinding::Observed,
};

const CODE: ObservationRecord = ObservationRecord {
    kind: ObservationKind::CodeIntegrity,
    rule_id: 9,
    finding: ObservationFinding::SignedMismatch,
};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn report() -> SessionObservation {
    SessionObservation {
        app_id: [1; 16],
        build_id: [2; 16],
        device_id: [3; 16],
        session_id: [4; 16],
        generation_id: [5; 16],
        function_id: [6; 16],
        request_id: [7; 16],
        sequence: 8,
        detection_policy_epoch: 9,
        action: ObservationAction::ReportOnly,
        records: vec![DEBUG, CODE],
    }
}

#[test]
fn observation_proof_binds_target_action_and_policy() {
    let report = report();
    let device_key = key(7);
    let proof = report.sign(&device_key).unwrap();
    let bytes = report.encode().unwrap();
    assert_eq!(&bytes[..8], &[1, 0, 16, 0, 138, 0, 0, 0]);
    let decoded = SessionObservation::decode(&bytes).unwrap();
    assert_eq!(decoded, report);
    assert_eq!(decoded.digest().unwrap(), report.digest().unwrap());
    assert_eq!(decoded.verify(device_key.verifying_key(), &proof), Ok(()));
    assert_eq!(
        decoded.verify(key(8).verifying_key(), &proof),
        Err(ProtocolError::Signature)
    );

    let mutations: [fn(&mut SessionObservation); 5] = [
        |r| r.session_id = [10; 16],
        |r| r.generation_id = [10; 16],
        |r| r.sequence += 1,
        |r| r.detection_policy_epoch += 1,
        |r| r.action = ObservationAction::RequestOwnStop,
    ];
    for change in mutations {
        let mut modified = report.clone();
        change(&mut modified);
        assert_ne!(modified.digest().unwrap(), report.digest().unwrap());
        assert_eq!(
            modified.verify(device_key.verifying_key(), &proof),
            Err(ProtocolError::Signature)
        );
    }
}

#[test]
fn observation_wire_limits_order_and_stop_eligibility() {
    let mut report = report();
    report.action = ObservationAction::RequestOwnStop;
    for evidence in [DEBUG, CODE] {
        report.records = vec![evidence];
        assert!(evidence.can_request_own_stop());
        assert!(report.encode().is_ok());
    }
    for evidence in [
        ObservationRecord {
            finding: ObservationFinding::Unsupported,
            ..DEBUG
        },
        ObservationRecord {
            finding: ObservationFinding::Inconclusive,
            ..CODE
        },
        ObservationRecord {
            kind: ObservationKind::RegisteredProvider,
            rule_id: 1,
            finding: ObservationFinding::Observed,
        },
        ObservationRecord {
            kind: ObservationKind::DriverPackage,
            rule_id: 2,
            finding: ObservationFinding::BenignException,
        },
    ] {
        report.records = vec![evidence];
        assert!(!evidence.can_request_own_stop());
        assert_eq!(report.encode(), Err(ProtocolError::Invalid));
        report.action = ObservationAction::ReportOnly;
        assert!(report.encode().is_ok());
        report.action = ObservationAction::RequestOwnStop;
    }
    for records in [vec![], vec![CODE, DEBUG], vec![CODE, CODE]] {
        report.records = records;
        assert_eq!(report.encode(), Err(ProtocolError::Invalid));
    }
    report.records = vec![CODE; MAX_OBSERVATIONS + 1];
    assert_eq!(report.encode(), Err(ProtocolError::Limit));
    assert_eq!(
        SessionObservation::decode(&[0; MAX_SESSION_OBSERVATION_BYTES + 1]),
        Err(ProtocolError::Limit)
    );
    report.records = vec![CODE];
    let mut bytes = report.encode().unwrap();
    bytes[138] = 255;
    assert_eq!(
        SessionObservation::decode(&bytes),
        Err(ProtocolError::UnknownMandatory)
    );
    bytes[138] = ObservationKind::CodeIntegrity as u8;
    bytes[0] = 2;
    assert_eq!(
        SessionObservation::decode(&bytes),
        Err(ProtocolError::Version)
    );
    bytes[0] = 1;
    assert_eq!(
        SessionObservation::decode(&bytes[..bytes.len() - 1]),
        Err(ProtocolError::Invalid)
    );
}

fn command(key: &SigningKey) -> AccessCommand {
    AccessCommand {
        app_id: [1; 16],
        actor_id: [2; 16],
        license_id: [3; 16],
        device_id: None,
        request_id: [4; 16],
        policy_version: 5,
        issued_at_ms: 100,
        expires_at_ms: 200,
        action: AccessAction::Revoke,
        reason: AccessReason::Administrator,
        key_id: public_key_id(key.verifying_key()),
    }
}

#[test]
fn administrative_proof_requires_pinned_role_scope_and_current_policy() {
    let key = key(10);
    let command = command(&key);
    let authority = AccessAuthority {
        app_id: command.app_id,
        actor_id: command.actor_id,
        role: AccessRole::Administrator,
        key: key.verifying_key(),
    };
    let signed = SignedAccessCommand::sign(command, &key).unwrap();
    assert_eq!(&signed.as_bytes()[..8], &[1, 0, 17, 0, 146, 0, 0, 0]);
    let decoded = SignedAccessCommand::decode(signed.as_bytes()).unwrap();
    let verified = decoded.verify_for(authority, 5, 100).unwrap();
    assert_eq!(*verified.payload(), command);
    assert_eq!(
        verified.digest(),
        signed.verify_for(authority, 5, 100).unwrap().digest()
    );
    assert_eq!(
        SignedAccessCommand::decode(&report().encode().unwrap()).unwrap_err(),
        ProtocolError::Type
    );

    let other = self::key(11);
    let checks = [
        (
            AccessAuthority {
                role: AccessRole::Observer,
                ..authority
            },
            5,
            100,
            ProtocolError::Binding,
        ),
        (
            AccessAuthority {
                actor_id: [0; 16],
                ..authority
            },
            5,
            100,
            ProtocolError::Binding,
        ),
        (
            AccessAuthority {
                app_id: [0; 16],
                ..authority
            },
            5,
            100,
            ProtocolError::Binding,
        ),
        (
            AccessAuthority {
                key: other.verifying_key(),
                ..authority
            },
            5,
            100,
            ProtocolError::Signature,
        ),
        (authority, 6, 100, ProtocolError::Binding),
        (authority, 5, 99, ProtocolError::Expired),
        (authority, 5, 200, ProtocolError::Expired),
    ];
    for (authority, policy, time, error) in checks {
        assert!(
            matches!(decoded.verify_for(authority, policy, time), Err(actual) if actual == error)
        );
    }

    let mut tampered = signed.as_bytes().to_vec();
    tampered[8 + 2 * 16] ^= 1;
    let tampered = SignedAccessCommand::decode(&tampered).unwrap();
    assert!(matches!(
        tampered.verify_for(authority, 5, 100),
        Err(ProtocolError::Signature)
    ));
}

#[test]
fn administrative_restore_requires_explicit_prior_decision_and_reason() {
    let key = key(10);
    let command = command(&key);
    for invalid in [
        AccessCommand {
            action: AccessAction::Restore {
                prior_decision_id: 0,
            },
            reason: AccessReason::ReviewedRestore,
            ..command
        },
        AccessCommand {
            action: AccessAction::Restore {
                prior_decision_id: 2,
            },
            ..command
        },
        AccessCommand {
            reason: AccessReason::ReviewedRestore,
            ..command
        },
        AccessCommand {
            expires_at_ms: 5_101,
            ..command
        },
        AccessCommand {
            device_id: Some([0; 16]),
            ..command
        },
    ] {
        assert!(matches!(
            SignedAccessCommand::sign(invalid, &key),
            Err(ProtocolError::Invalid)
        ));
    }

    let restore = AccessCommand {
        action: AccessAction::Restore {
            prior_decision_id: 29,
        },
        reason: AccessReason::ReviewedRestore,
        device_id: Some([11; 16]),
        ..command
    };
    let signed = SignedAccessCommand::sign(restore, &key).unwrap();
    let authority = AccessAuthority {
        app_id: restore.app_id,
        actor_id: restore.actor_id,
        role: AccessRole::Administrator,
        key: key.verifying_key(),
    };
    let verified = signed.verify_for(authority, 5, 130).unwrap();
    assert_eq!(*verified.payload(), restore);
    let revoke = SignedAccessCommand::sign(command, &key).unwrap();
    assert_ne!(
        verified.digest(),
        revoke.verify_for(authority, 5, 130).unwrap().digest()
    );
}
