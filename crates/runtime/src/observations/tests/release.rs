use super::*;

use crate::VmkRuntime;
use vmkek_protocol::detection::VerifiedPolicy;

const INITIAL: u64 = 31;
const DEFECTIVE: u64 = INITIAL + 1;
const RECOVERY: u64 = DEFECTIVE + 1;
const NOW: u64 = 1000;

struct Package {
    key: SigningKey,
    #[cfg(windows)]
    build: u32,
    #[cfg(target_os = "linux")]
    release: vmkek_protocol::detection::LinuxRelease,
}

impl Package {
    fn new() -> Self {
        Self {
            key: SigningKey::from_slice(&[0x71; 32]).unwrap(),
            #[cfg(windows)]
            build: super::super::windows::native_windows_build().unwrap(),
            #[cfg(target_os = "linux")]
            release: super::super::linux::native_release().unwrap(),
        }
    }

    fn sign(&self, epoch: u64, mode: ObservationMode) -> SignedDetectionPolicy {
        #[cfg(windows)]
        let build = self.build;
        #[cfg(target_os = "linux")]
        let build = 1;
        let policy = DetectionPolicy {
            app_id: APP,
            build_id: BUILD_ID,
            key_id: public_key_id(self.key.verifying_key()),
            epoch,
            issued_ms: NOW,
            expires_ms: NOW + 30_000,
            windows_builds: BuildRange {
                first: build,
                last: build,
            },
            artifacts: vec![],
            images: vec![],
        };
        let settings = ObservationSettings {
            profile: ObservationProfile::Offline,
            mode,
            max_age_ms: 5_000,
            rules: vec![ObservationRule {
                signal_id: SignalId::DEBUGGER,
                required: true,
                reaction: ObservationReaction::Stop,
            }],
        };
        #[cfg(windows)]
        let signed = SignedDetectionPolicy::sign_for_profile(policy, settings, &self.key);
        #[cfg(target_os = "linux")]
        let signed = SignedDetectionPolicy::sign_for_linux_profile(
            policy,
            settings,
            self.release,
            &self.key,
        );
        SignedDetectionPolicy::decode(signed.unwrap().as_bytes()).unwrap()
    }

    fn verify<'a>(
        &self,
        signed: &'a SignedDetectionPolicy,
        previous: Option<PolicyRevision>,
    ) -> Result<VerifiedPolicy<'a>, ProtocolError> {
        let supported = &[ObservationKind::DebuggerAttachment];
        let epoch_floor = previous.map_or(INITIAL, |revision| revision.epoch);
        #[cfg(windows)]
        {
            use vmkek_protocol::detection::{PolicyContext, ProfileContext};
            signed.verify_for_profile(
                self.key.verifying_key(),
                ProfileContext {
                    policy: PolicyContext {
                        app_id: APP,
                        build_id: BUILD_ID,
                        epoch_floor,
                        windows_build: self.build,
                        now_ms: NOW,
                    },
                    profile: ObservationProfile::Offline,
                    supported,
                    previous,
                },
            )
        }
        #[cfg(target_os = "linux")]
        {
            use vmkek_protocol::detection::LinuxProfileContext;
            signed.verify_for_linux_profile(
                self.key.verifying_key(),
                LinuxProfileContext {
                    app_id: APP,
                    build_id: BUILD_ID,
                    epoch_floor,
                    now_ms: NOW,
                    release: self.release,
                    profile: ObservationProfile::Offline,
                    supported,
                    previous,
                },
            )
        }
    }
}

struct Lab(VmkRuntime);

impl Lab {
    fn open(policy: &VerifiedPolicy<'_>, collect: bool) -> Self {
        let gate = Arc::new(ObservationGate::new(
            policy.observation_policy().unwrap(),
            Instant::now(),
        ));
        if collect {
            #[cfg(windows)]
            let sample =
                super::super::windows::debugger_attachment_sample(gate.begin_sample()).unwrap();
            #[cfg(target_os = "linux")]
            let sample =
                super::super::linux::tracer_attachment_sample(gate.begin_sample()).unwrap();
            assert_eq!(
                sample.record.finding,
                ObservationFinding::NotObservedWithinScope
            );
            gate.publish(vec![sample]).unwrap();
        }
        let (descriptor, program) = lab_fixture();
        Self(initialize_observed_lab(&descriptor.encode().unwrap(), &program, gate).unwrap())
    }

    fn invoke(&self, id: u8, expected: Status) {
        super::response::invoke(self.0, id, expected);
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        assert_eq!(vmk_shutdown(self.0), Status::Ok as u32);
    }
}

#[test]
#[ignore = "runs the native release rollout and signed policy fixture"]
fn staged_policy_rollout_recovers_with_a_higher_epoch() {
    let package = Package::new();
    let initial = package.sign(INITIAL, ObservationMode::Observe);
    let baseline = package.verify(&initial, None).unwrap();
    let control = Lab::open(&baseline, true);
    let initial_canary = Lab::open(&baseline, true);
    control.invoke(1, Status::Ok);
    initial_canary.invoke(2, Status::Ok);
    drop(initial_canary);
    print_revision("baseline", baseline.revision());

    let defective = package.sign(DEFECTIVE, ObservationMode::Enforce);
    let staged = package
        .verify(&defective, Some(baseline.revision()))
        .unwrap();
    let canary = Lab::open(&staged, false);
    canary.invoke(3, Status::Unavailable);
    control.invoke(4, Status::Ok);
    print_revision("canary_missing_required_sample", staged.revision());
    reject_unsafe_updates(&package, &initial, &defective, staged.revision());

    let recovered = package.sign(RECOVERY, ObservationMode::Observe);
    let accepted = package.verify(&recovered, Some(staged.revision())).unwrap();
    let fresh_canary = Lab::open(&accepted, false);
    fresh_canary.invoke(5, Status::Ok);
    canary.invoke(6, Status::Unavailable);
    control.invoke(7, Status::Ok);
    print_revision("recovered_canary", accepted.revision());

    let promoted = package
        .verify(&recovered, Some(baseline.revision()))
        .unwrap();
    assert_eq!(accepted.revision(), promoted.revision());
    let fresh_control = Lab::open(&promoted, true);
    fresh_control.invoke(8, Status::Ok);
    println!("staged_then_promoted=true old_handles_unchanged=true");
}

fn reject_unsafe_updates(
    package: &Package,
    initial: &SignedDetectionPolicy,
    defective: &SignedDetectionPolicy,
    staged: PolicyRevision,
) {
    assert!(matches!(
        package.verify(initial, Some(staged)),
        Err(ProtocolError::Binding)
    ));
    let replacement = package.sign(DEFECTIVE, ObservationMode::Observe);
    assert!(matches!(
        package.verify(&replacement, Some(staged)),
        Err(ProtocolError::Binding)
    ));
    assert!(package.verify(defective, Some(staged)).is_ok());
    let mut corrupted = defective.as_bytes().to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    let corrupted = SignedDetectionPolicy::decode(&corrupted).unwrap();
    assert!(matches!(
        package.verify(&corrupted, Some(staged)),
        Err(ProtocolError::Signature)
    ));
    let mut unsupported = defective.as_bytes().to_vec();
    unsupported[0] = 0xff;
    assert!(matches!(
        SignedDetectionPolicy::decode(&unsupported),
        Err(ProtocolError::Version)
    ));
    println!("lower_epoch=rejected same_epoch_change=rejected signed_replay=accepted corrupt_signature=rejected unknown_wire_version=rejected");
}

fn print_revision(stage: &str, revision: PolicyRevision) {
    let digest: String = revision
        .digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!(
        "stage={stage} policy_epoch={} policy_sha256={digest}",
        revision.epoch
    );
}
