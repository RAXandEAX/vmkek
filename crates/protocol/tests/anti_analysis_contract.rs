use std::time::Duration;

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest as _, Sha256};
use vmkek_protocol::{
    detection::{
        BuildRange, DetectionPolicy, ImagePurpose, ImageRule, ObservationDecision, ObservationMode,
        ObservationPolicy, ObservationProfile, ObservationReaction, ObservationRule,
        ObservationSettings, PolicyContext, ProfileContext, SignedDetectionPolicy,
    },
    public_key_id,
    session_observation::{
        DependencyGroup, Observation, ObservationAction, ObservationFinding, ObservationKind,
        ObservationPlatform, ObservationReason, ObservationRecord, ObservationSample,
        ObservationScope, ObservationSource, SessionObservation, SignalId,
    },
    ProtocolError,
};

const BUILD: u32 = 26_300;
const EPOCH: u64 = 7;
const ISSUE: u64 = 1_000;
const EXPIRY: u64 = 2_000;
const AGE: u32 = 10;
const DEBUGGER: SignalId = SignalId::DEBUGGER;
const CODE: SignalId = SignalId {
    kind: ObservationKind::CodeIntegrity,
    rule_id: 1,
};

fn fixture() -> (SigningKey, DetectionPolicy, PolicyContext) {
    let key = SigningKey::from_slice(&[0x31; 32]).unwrap();
    let context = PolicyContext {
        app_id: [1; 16],
        build_id: [2; 16],
        epoch_floor: EPOCH,
        windows_build: BUILD,
        now_ms: ISSUE,
    };
    let policy = DetectionPolicy {
        app_id: context.app_id,
        build_id: context.build_id,
        key_id: public_key_id(key.verifying_key()),
        epoch: EPOCH,
        issued_ms: ISSUE,
        expires_ms: EXPIRY,
        windows_builds: BuildRange {
            first: BUILD,
            last: BUILD,
        },
        artifacts: Vec::new(),
        images: Vec::new(),
    };
    (key, policy, context)
}

fn settings(
    profile: ObservationProfile,
    mode: ObservationMode,
    reaction: ObservationReaction,
    required: bool,
    signal_id: SignalId,
) -> ObservationSettings {
    ObservationSettings {
        profile,
        mode,
        max_age_ms: AGE,
        rules: vec![ObservationRule {
            signal_id,
            required,
            reaction,
        }],
    }
}

fn activate(settings: ObservationSettings) -> ObservationPolicy {
    let (key, mut policy, context) = fixture();
    policy.images.push(ImageRule {
        id: 1,
        purpose: ImagePurpose::CodeIntegrity,
        file_digest: [9; 32],
        code_rva: 10,
        code_len: 1,
        code_digest: [10; 32],
    });
    let profile = settings.profile;
    SignedDetectionPolicy::sign_for_profile(policy, settings, &key)
        .unwrap()
        .verify_for_profile(
            key.verifying_key(),
            ProfileContext {
                policy: context,
                profile,
                supported: &[
                    ObservationKind::DebuggerAttachment,
                    ObservationKind::CodeIntegrity,
                ],
                previous: None,
            },
        )
        .unwrap()
        .observation_policy()
        .unwrap()
}

fn sample(
    signal_id: SignalId,
    finding: ObservationFinding,
    reason: ObservationReason,
) -> ObservationSample {
    ObservationSample {
        record: ObservationRecord {
            kind: signal_id.kind,
            rule_id: signal_id.rule_id,
            finding,
        },
        reason,
        platform: ObservationPlatform::Windows { build: BUILD },
        policy_epoch: EPOCH,
        policy_digest: None,
        sampled_at: Duration::from_millis(100),
        valid_until: Duration::from_millis(110),
    }
}

fn bound_sample(
    policy: &ObservationPolicy,
    signal_id: SignalId,
    finding: ObservationFinding,
    reason: ObservationReason,
) -> ObservationSample {
    ObservationSample {
        policy_digest: Some(policy.revision().digest),
        ..sample(signal_id, finding, reason)
    }
}

#[test]
fn decision_table_preserves_outcomes_reasons_and_freshness() {
    use ObservationDecision as Decision;
    use ObservationFinding as Finding;
    use ObservationReason as Reason;
    for profile in [ObservationProfile::Offline, ObservationProfile::Online] {
        for mode in [ObservationMode::Observe, ObservationMode::Enforce] {
            for reaction in [ObservationReaction::Report, ObservationReaction::Stop] {
                for required in [false, true] {
                    let policy = activate(settings(profile, mode, reaction, required, DEBUGGER));
                    for (finding, outcome, reason) in [
                        (Finding::Observed, Observation::Observed, Reason::None),
                        (
                            Finding::NotObservedWithinScope,
                            Observation::NotObservedWithinScope,
                            Reason::None,
                        ),
                        (
                            Finding::Inconclusive,
                            Observation::Inconclusive,
                            Reason::SourcesDisagree,
                        ),
                        (
                            Finding::Unsupported,
                            Observation::Unsupported,
                            Reason::PlatformUnsupported,
                        ),
                    ] {
                        let sample = bound_sample(&policy, DEBUGGER, finding, reason);
                        assert_eq!(sample.outcome(), outcome);
                        for (instant, fresh) in
                            [(99, false), (100, true), (109, true), (110, false)]
                        {
                            let enforced = mode == ObservationMode::Enforce;
                            let expected = match (fresh, finding) {
                                (false, _) if enforced && required => {
                                    Decision::Unavailable(Reason::Stale)
                                }
                                (false, _) => Decision::Allow,
                                (true, Finding::Inconclusive | Finding::Unsupported)
                                    if enforced && required =>
                                {
                                    Decision::Unavailable(reason)
                                }
                                (true, Finding::Observed)
                                    if enforced && reaction == ObservationReaction::Stop =>
                                {
                                    Decision::RequestOwnStop(sample)
                                }
                                _ => Decision::ReportOnly(sample),
                            };
                            assert_eq!(
                                policy.decide(DEBUGGER, &[sample], ISSUE, Duration::from_millis(instant)),
                                Some(expected),
                                "{profile:?} {mode:?} {reaction:?} {required} {finding:?} {instant}",
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn stale_foreign_or_duplicate_samples_cannot_grant_admission_or_stop() {
    use ObservationDecision::Unavailable;
    use ObservationReason as Reason;
    let policy = activate(settings(
        ObservationProfile::Online,
        ObservationMode::Enforce,
        ObservationReaction::Stop,
        true,
        DEBUGGER,
    ));
    let fresh = bound_sample(
        &policy,
        DEBUGGER,
        ObservationFinding::Observed,
        Reason::None,
    );
    let now = Duration::from_millis(100);
    for (samples, reason) in [
        (vec![], Reason::Missing),
        (vec![fresh, fresh], Reason::InvalidData),
        (
            vec![ObservationSample {
                policy_epoch: EPOCH - 1,
                ..fresh
            }],
            Reason::ContextMismatch,
        ),
        (
            vec![ObservationSample {
                platform: ObservationPlatform::Windows { build: BUILD - 1 },
                ..fresh
            }],
            Reason::ContextMismatch,
        ),
        (
            vec![ObservationSample {
                reason: Reason::ApiFailure,
                ..fresh
            }],
            Reason::InvalidData,
        ),
        (
            vec![bound_sample(
                &policy,
                CODE,
                ObservationFinding::SignedMismatch,
                Reason::SignedMismatch,
            )],
            Reason::Missing,
        ),
    ] {
        assert_eq!(
            policy.decide(DEBUGGER, &samples, ISSUE, now),
            Some(Unavailable(reason))
        );
    }
    let overlong = ObservationSample {
        valid_until: Duration::MAX,
        ..fresh
    };
    assert_eq!(
        policy.decide(DEBUGGER, &[overlong], ISSUE, Duration::from_millis(110)),
        Some(Unavailable(Reason::Stale)),
    );
    assert_eq!(
        policy.decide(DEBUGGER, &[fresh], EXPIRY, now),
        Some(Unavailable(Reason::PolicyExpired)),
    );
    assert_eq!(fresh.source(), ObservationSource::WindowsDebuggerApis);
    assert_eq!(fresh.scope(), ObservationScope::CurrentProcess);
    assert_eq!(fresh.dependency_group(), DependencyGroup::ProcessDebugState);
    assert_eq!(
        ObservationSample {
            platform: ObservationPlatform::Linux {
                major: 6,
                minor: 6,
                patch: 1
            },
            ..fresh
        }
        .source(),
        ObservationSource::LinuxProcStatus,
    );
}

#[test]
fn only_a_fresh_exact_signed_code_mismatch_can_request_a_stop() {
    use ObservationDecision as Decision;
    use ObservationFinding as Finding;
    use ObservationReason as Reason;
    let policy = activate(settings(
        ObservationProfile::Online,
        ObservationMode::Enforce,
        ObservationReaction::Stop,
        true,
        CODE,
    ));
    let now = Duration::from_millis(100);
    for (finding, reason, stop) in [
        (Finding::Observed, Reason::None, false),
        (Finding::NotObservedWithinScope, Reason::None, false),
        (Finding::SignedMismatch, Reason::SignedMismatch, true),
    ] {
        let current = bound_sample(&policy, CODE, finding, reason);
        assert_eq!(
            policy.decide(CODE, &[current], ISSUE, now),
            Some(if stop {
                Decision::RequestOwnStop(current)
            } else {
                Decision::ReportOnly(current)
            }),
        );
        assert_eq!(current.scope(), ObservationScope::SignedImageRule);
        assert_eq!(current.dependency_group(), DependencyGroup::OwnedImage);
    }
    let outside = bound_sample(&policy, CODE, Finding::Unsupported, Reason::OutsideScope);
    assert_eq!(
        policy.decide(CODE, &[outside], ISSUE, now),
        Some(Decision::Unavailable(Reason::OutsideScope)),
    );
}

#[test]
fn signed_policy_binds_build_profile_time_and_rollback_state() {
    let (key, policy, context) = fixture();
    let settings = settings(
        ObservationProfile::Offline,
        ObservationMode::Enforce,
        ObservationReaction::Stop,
        true,
        DEBUGGER,
    );
    let sign =
        |policy, settings| SignedDetectionPolicy::sign_for_profile(policy, settings, &key).unwrap();
    let signed = sign(policy.clone(), settings.clone());
    let decoded = SignedDetectionPolicy::decode(signed.as_bytes()).unwrap();
    let verify = |policy, profile, supported, previous| ProfileContext {
        policy,
        profile,
        supported,
        previous,
    };
    let supported = &[ObservationKind::DebuggerAttachment][..];
    let offline = ObservationProfile::Offline;
    let valid = decoded
        .verify_for_profile(
            key.verifying_key(),
            verify(context, offline, supported, None),
        )
        .unwrap();
    let revision = valid.revision();
    assert_eq!(revision.epoch, EPOCH);
    assert_eq!(
        revision.digest,
        <[u8; 32]>::from(Sha256::digest(signed.as_bytes()))
    );
    assert!(decoded
        .verify_for_profile(
            key.verifying_key(),
            verify(context, offline, supported, Some(revision))
        )
        .is_ok());
    for (context, expected) in [
        (
            PolicyContext {
                app_id: [9; 16],
                ..context
            },
            ProtocolError::Binding,
        ),
        (
            PolicyContext {
                build_id: [9; 16],
                ..context
            },
            ProtocolError::Binding,
        ),
        (
            PolicyContext {
                windows_build: BUILD + 1,
                ..context
            },
            ProtocolError::Binding,
        ),
        (
            PolicyContext {
                epoch_floor: EPOCH + 1,
                ..context
            },
            ProtocolError::Binding,
        ),
        (
            PolicyContext {
                now_ms: ISSUE - 1,
                ..context
            },
            ProtocolError::Expired,
        ),
        (
            PolicyContext {
                now_ms: EXPIRY,
                ..context
            },
            ProtocolError::Expired,
        ),
    ] {
        assert_eq!(
            decoded
                .verify_for_profile(
                    key.verifying_key(),
                    verify(context, offline, supported, None)
                )
                .err(),
            Some(expected),
        );
    }
    assert_eq!(
        decoded
            .verify_for_profile(
                key.verifying_key(),
                verify(context, ObservationProfile::Online, supported, None)
            )
            .err(),
        Some(ProtocolError::Binding),
    );
    assert_eq!(
        decoded
            .verify_for_profile(key.verifying_key(), verify(context, offline, &[], None))
            .err(),
        Some(ProtocolError::UnknownMandatory),
    );
    let reverted = ObservationSettings {
        rules: Vec::new(),
        ..settings.clone()
    };
    let same_epoch = sign(policy.clone(), reverted.clone());
    assert_eq!(
        same_epoch
            .verify_for_profile(
                key.verifying_key(),
                verify(context, offline, supported, Some(revision))
            )
            .err(),
        Some(ProtocolError::Binding),
    );
    assert!(sign(
        DetectionPolicy {
            epoch: EPOCH + 1,
            ..policy.clone()
        },
        reverted
    )
    .verify_for_profile(
        key.verifying_key(),
        verify(context, offline, &[], Some(revision))
    )
    .is_ok());

    let mut corrupt = signed.as_bytes().to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    let altered = SignedDetectionPolicy::decode(&corrupt).unwrap();
    assert_eq!(
        altered
            .verify_for_profile(
                key.verifying_key(),
                verify(context, offline, supported, None)
            )
            .err(),
        Some(ProtocolError::Signature),
    );
    corrupt[0] = 2;
    assert_eq!(
        SignedDetectionPolicy::decode(&corrupt).err(),
        Some(ProtocolError::Version)
    );
    let mut unknown_settings = signed.as_bytes().to_vec();
    unknown_settings[8 + 102] = 2;
    assert_eq!(
        SignedDetectionPolicy::decode(&unknown_settings).err(),
        Some(ProtocolError::Version)
    );

    let optional = sign(
        policy,
        ObservationSettings {
            rules: vec![ObservationRule {
                required: false,
                ..settings.rules[0]
            }],
            ..settings
        },
    );
    let optional = optional
        .verify_for_profile(key.verifying_key(), verify(context, offline, &[], None))
        .unwrap()
        .observation_policy()
        .unwrap();
    let supplied = sample(
        DEBUGGER,
        ObservationFinding::Observed,
        ObservationReason::None,
    );
    let Some(ObservationDecision::ReportOnly(unavailable)) =
        optional.decide(DEBUGGER, &[supplied], ISSUE, Duration::from_millis(100))
    else {
        panic!("missing capability must be observable without enforcing a stop");
    };
    assert_eq!(unavailable.outcome(), Observation::Unsupported);
    assert_eq!(unavailable.reason, ObservationReason::PlatformUnsupported);
}

#[test]
fn legacy_policy_and_session_wire_keep_their_existing_layout() {
    let (key, policy, context) = fixture();
    let signed = SignedDetectionPolicy::sign(policy.clone(), &key).unwrap();
    // Independent encoding of the original fixed R16 policy prefix with no rules.
    let mut original = vec![1, 0, 15, 0, 102, 0, 0, 0];
    original.extend(policy.app_id);
    original.extend(policy.build_id);
    original.extend(policy.key_id);
    original.extend(EPOCH.to_le_bytes());
    original.extend(ISSUE.to_le_bytes());
    original.extend(EXPIRY.to_le_bytes());
    original.extend(0x8664u16.to_le_bytes());
    original.extend(BUILD.to_le_bytes());
    original.extend(BUILD.to_le_bytes());
    original.extend([0; 4]);
    let mut hash = Sha256::new();
    hash.update(b"vmkek.protocol.v1.windows-observation-policy\0");
    hash.update(&original);
    let signature: Signature = key.sign_prehash(&hash.finalize()).unwrap();
    original.extend(signature.to_bytes());
    assert_eq!(signed.as_bytes(), original);
    assert!(signed
        .verify_for(key.verifying_key(), context)
        .unwrap()
        .observation_policy()
        .is_none());
    let profiled = SignedDetectionPolicy::sign_for_profile(
        policy,
        settings(
            ObservationProfile::Offline,
            ObservationMode::Observe,
            ObservationReaction::Report,
            false,
            DEBUGGER,
        ),
        &key,
    )
    .unwrap();
    assert_eq!(
        profiled.verify_for(key.verifying_key(), context).err(),
        Some(ProtocolError::UnknownMandatory)
    );

    for (finding, reason, encoded) in [
        (ObservationFinding::Observed, ObservationReason::None, 1),
        (
            ObservationFinding::NotObservedWithinScope,
            ObservationReason::None,
            2,
        ),
        (
            ObservationFinding::Inconclusive,
            ObservationReason::ReadFailure,
            3,
        ),
        (
            ObservationFinding::Unsupported,
            ObservationReason::PlatformUnsupported,
            4,
        ),
    ] {
        let sample = sample(DEBUGGER, finding, reason);
        let report = SessionObservation {
            app_id: [1; 16],
            build_id: [2; 16],
            device_id: [3; 16],
            session_id: [4; 16],
            generation_id: [5; 16],
            function_id: [6; 16],
            request_id: [7; 16],
            sequence: 1,
            detection_policy_epoch: EPOCH,
            action: ObservationAction::ReportOnly,
            records: vec![sample.record],
        };
        let bytes = report.encode().unwrap();
        assert_eq!(&bytes[bytes.len() - 4..], &[1, 0, 0, encoded]);
        assert_eq!(SessionObservation::decode(&bytes).unwrap(), report);
        let stop = SessionObservation {
            action: ObservationAction::RequestOwnStop,
            ..report
        };
        assert_eq!(
            stop.encode().is_ok(),
            finding == ObservationFinding::Observed
        );
    }
}

#[test]
fn linux_policy_is_bound_to_exact_release_and_distinct_from_windows() {
    use vmkek_protocol::detection::{LinuxProfileContext, LinuxRelease};
    let (key, policy, context) = fixture();
    let settings = settings(
        ObservationProfile::Offline,
        ObservationMode::Enforce,
        ObservationReaction::Stop,
        true,
        DEBUGGER,
    );
    let release = LinuxRelease::from_uname(b"6.18.58.1-microsoft-standard-WSL2").unwrap();
    let other = LinuxRelease::from_uname(b"6.18.58-native").unwrap();
    assert_eq!(release.platform(), other.platform());
    let windows =
        SignedDetectionPolicy::sign_for_profile(policy.clone(), settings.clone(), &key).unwrap();
    let linux =
        SignedDetectionPolicy::sign_for_linux_profile(policy, settings, release, &key).unwrap();
    let linux = SignedDetectionPolicy::decode(linux.as_bytes()).unwrap();
    let binding = |release| LinuxProfileContext {
        app_id: context.app_id,
        build_id: context.build_id,
        epoch_floor: EPOCH,
        now_ms: ISSUE,
        release,
        profile: ObservationProfile::Offline,
        supported: &[ObservationKind::DebuggerAttachment],
        previous: None,
    };
    let verified = linux
        .verify_for_linux_profile(key.verifying_key(), binding(release))
        .unwrap();
    assert_eq!(
        verified.observation_policy().unwrap().linux_release(),
        Some(release)
    );
    assert!(matches!(
        linux.verify_for_linux_profile(key.verifying_key(), binding(other)),
        Err(ProtocolError::Binding)
    ));
    assert!(matches!(
        windows.verify_for_linux_profile(key.verifying_key(), binding(release)),
        Err(ProtocolError::Binding)
    ));
    assert!(matches!(
        linux.verify_for_profile(
            key.verifying_key(),
            ProfileContext {
                policy: context,
                profile: ObservationProfile::Offline,
                supported: &[ObservationKind::DebuggerAttachment],
                previous: None,
            }
        ),
        Err(ProtocolError::Binding)
    ));
}
