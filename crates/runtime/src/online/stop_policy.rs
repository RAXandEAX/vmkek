use std::{
    sync::{Arc, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc as async_mpsc;
use vmkek_client::LeaseToken;
use vmkek_protocol::{
    detection::{
        ObservationDecision, ObservationProfile, PolicyContext, ProfileContext,
        SignedDetectionPolicy, VerifiedPolicy,
    },
    session_observation::{ObservationKind, ObservationRecord, ObservationSample},
    Digest, Id, ProtocolError,
};

use crate::{
    observations::{
        monotonic_now,
        scheduler::{ObservationWorker, WorkerControl},
        ObservationGate,
    },
    state::Runtime,
    Status,
};

#[cfg(target_arch = "x86_64")]
use vmkek_protocol::session_observation::{ObservationReason, SignalId};

#[cfg(target_arch = "x86_64")]
use crate::observations::{
    scheduler::{IntegritySchedule, DEBUGGER_INTERVAL, INTEGRITY_INTERVAL},
    windows, ObservationDelivery, SampleWindow,
};

pub(super) const DEBUGGER: u8 = 1;
pub(super) const OWN_CODE: u8 = 2;
#[cfg(target_arch = "x86_64")]
const PREPARE_RETRY: Duration = Duration::from_secs(2);

pub(super) struct StopPolicy {
    signed: SignedDetectionPolicy,
    pin: VerifyingKey,
    context: PolicyContext,
    anchor: Duration,
    flags: u8,
    expires_ms: u64,
    gate: Option<Arc<ObservationGate>>,
}

pub(super) struct StopNotice {
    pub token: LeaseToken,
    pub epoch: u64,
    pub record: ObservationRecord,
}

impl StopPolicy {
    pub(super) fn new(
        bytes: &[u8],
        pin: VerifyingKey,
        consent: [u8; 64],
        flags: u8,
        app_id: Id,
        build_id: Id,
        epoch_floor: u64,
    ) -> Result<Self, Status> {
        if flags == 0 || flags & !(DEBUGGER | OWN_CODE) != 0 || epoch_floor == 0 {
            return Err(Status::InvalidArgument);
        }
        let proof = Signature::from_slice(&consent).map_err(|_| Status::InvalidPackage)?;
        pin.verify_prehash(&consent_digest(bytes, flags), &proof)
            .map_err(|_| Status::InvalidPackage)?;
        let signed = SignedDetectionPolicy::decode(bytes).map_err(policy_error)?;
        let windows_build = windows_build()?;
        let anchor = monotonic_now();
        let context = PolicyContext {
            app_id,
            build_id,
            epoch_floor,
            windows_build,
            now_ms: u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Status::Unavailable)?
                    .as_millis(),
            )
            .map_err(|_| Status::Unavailable)?,
        };
        let verified = verify(&signed, &pin, context, flags).map_err(policy_error)?;
        let expires_ms = verified.expires_ms();
        let gate = verified
            .observation_policy()
            .map(|policy| Arc::new(ObservationGate::new_at(policy, anchor)));
        Ok(Self {
            signed,
            pin,
            context,
            anchor,
            flags,
            expires_ms,
            gate,
        })
    }

    pub(super) fn gate(&self) -> Option<Arc<ObservationGate>> {
        self.gate.clone()
    }

    fn policy_now_ms(&self, elapsed: Duration) -> u64 {
        u64::try_from(elapsed.as_millis())
            .ok()
            .and_then(|elapsed| self.context.now_ms.checked_add(elapsed))
            .unwrap_or(u64::MAX)
    }

    pub(super) fn stop_candidate(
        &self,
        samples: Vec<ObservationSample>,
    ) -> Option<ObservationSample> {
        if let Some(gate) = &self.gate {
            gate.publish(samples).ok()?;
            return match gate.decision() {
                ObservationDecision::RequestOwnStop(sample) => Some(sample),
                _ => None,
            };
        }
        let now = monotonic_now();
        if self.policy_now_ms(monotonic_now().saturating_sub(self.anchor)) >= self.expires_ms {
            return None;
        }
        samples.into_iter().find(|sample| {
            sample.record.can_request_own_stop()
                && (sample.sampled_at..sample.valid_until).contains(&now)
        })
    }

    #[cfg(all(test, target_arch = "x86_64"))]
    pub(super) fn sample(&self) -> Vec<ObservationSample> {
        let now_ms = self.policy_now_ms(monotonic_now().saturating_sub(self.anchor));
        let Ok(policy) = verify(
            &self.signed,
            &self.pin,
            PolicyContext {
                now_ms,
                ..self.context
            },
            self.flags,
        ) else {
            return Vec::new();
        };
        let mut samples = Vec::new();
        if self.flags & DEBUGGER != 0 && self.selects(SignalId::DEBUGGER) {
            if let Ok(sample) = windows::debugger_attachment_sample(self.sample_window(&policy)) {
                if self.gate.is_none() && sample.record.can_request_own_stop() {
                    return vec![sample];
                }
                samples.push(sample);
            }
        }
        if self.flags & OWN_CODE != 0 {
            samples.extend(self.sample_owned_code(&policy, |window| {
                windows::OwnedModule::from_address(crate::vmk_initialize as *const () as usize)
                    .map_err(|_| ObservationReason::ApiFailure)?
                    .observe_samples(&policy, now_ms, window)
                    .map_err(measurement_reason)
            }));
        }
        samples
    }

    #[cfg(target_arch = "x86_64")]
    fn sample_window(&self, policy: &VerifiedPolicy<'_>) -> SampleWindow {
        match &self.gate {
            Some(gate) => gate.begin_sample(),
            None => SampleWindow::for_verified(policy, Duration::from_secs(1)),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn selects(&self, signal_id: SignalId) -> bool {
        self.gate
            .as_ref()
            .is_none_or(|gate| gate.selects(signal_id))
    }

    #[cfg(target_arch = "x86_64")]
    fn sample_owned_code(
        &self,
        policy: &VerifiedPolicy<'_>,
        measure: impl FnOnce(SampleWindow) -> Result<Vec<ObservationSample>, ObservationReason>,
    ) -> Vec<ObservationSample> {
        use vmkek_protocol::{detection::ImagePurpose, session_observation::ObservationFinding};

        let mut code_rules = policy
            .image_rules()
            .iter()
            .filter_map(|rule| {
                let id = SignalId {
                    kind: ObservationKind::CodeIntegrity,
                    rule_id: rule.id,
                };
                (rule.purpose == ImagePurpose::CodeIntegrity && self.selects(id)).then_some(id)
            })
            .peekable();
        if code_rules.peek().is_none() {
            return Vec::new();
        }
        let window = self.sample_window(policy);
        match measure(window) {
            Ok(measured) => measured
                .into_iter()
                .filter(|sample| {
                    sample.record.kind == ObservationKind::CodeIntegrity
                        && self.selects(sample.signal_id())
                })
                .collect(),
            Err(reason) => {
                let finding = if reason == ObservationReason::OutsideScope {
                    ObservationFinding::Unsupported
                } else {
                    ObservationFinding::Inconclusive
                };
                code_rules
                    .map(|signal| {
                        window.sample(
                            ObservationRecord {
                                kind: signal.kind,
                                rule_id: signal.rule_id,
                                finding,
                            },
                            reason,
                        )
                    })
                    .collect()
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn run(
        self,
        control: WorkerControl,
        runtime: Weak<Runtime>,
        priority: async_mpsc::Sender<StopNotice>,
    ) {
        let period = if self.gate.is_none() {
            INTEGRITY_INTERVAL
        } else {
            DEBUGGER_INTERVAL
        };
        // The version-one profile preserves its first 500 ms wait. New
        // profiled policies start immediately and are unavailable until sampled.
        if self.gate.is_none() && !control.wait(period) {
            return;
        }
        let Ok(policy) = verify(&self.signed, &self.pin, self.context, self.flags) else {
            return;
        };
        let code_enabled = self.flags & OWN_CODE != 0
            && policy.image_rules().iter().any(|rule| {
                rule.purpose == vmkek_protocol::detection::ImagePurpose::CodeIntegrity
                    && self.selects(SignalId {
                        kind: ObservationKind::CodeIntegrity,
                        rule_id: rule.id,
                    })
            });
        let owned = code_enabled
            .then(|| {
                windows::OwnedModule::from_address(crate::vmk_initialize as *const () as usize).ok()
            })
            .flatten();
        let mut prepared = None::<windows::PreparedIntegrity<'_>>;
        let mut retry_at = Duration::ZERO;
        let mut integrity = IntegritySchedule::default();
        let mut last_code = Vec::new();
        loop {
            let now = monotonic_now();
            let now_ms = self.policy_now_ms(now.saturating_sub(self.anchor));
            if control.is_cancelled() || policy.check_time(now_ms).is_err() {
                break;
            }
            let debugger = if self.flags & DEBUGGER != 0 && self.selects(SignalId::DEBUGGER) {
                windows::debugger_attachment_sample(self.sample_window(&policy)).ok()
            } else {
                None
            };
            if !self.publish(&control, &runtime, &priority, debugger, &last_code) {
                break;
            }
            if code_enabled && integrity.due(now) {
                // Only the worker opens the loader's trusted path. A successfully
                // prepared module stays held until this exact policy is retired.
                if let Some(module) = &owned {
                    if now >= retry_at
                        && prepared
                            .as_ref()
                            .is_none_or(windows::PreparedIntegrity::retryable)
                    {
                        prepared = module.prepare_integrity(&policy, now_ms).ok();
                        retry_at = monotonic_now().saturating_add(PREPARE_RETRY);
                    }
                }
                if control.is_cancelled() {
                    break;
                }
                let now_ms = self.policy_now_ms(monotonic_now().saturating_sub(self.anchor));
                last_code = self.sample_owned_code(&policy, |window| {
                    prepared
                        .as_ref()
                        .ok_or(ObservationReason::ReadFailure)?
                        .observe_samples(&policy, now_ms, window)
                        .map(|(rows, _)| rows)
                        .map_err(measurement_reason)
                });
                if !self.publish(&control, &runtime, &priority, debugger, &last_code) {
                    break;
                }
            }
            if !control.wait(period) {
                break;
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn publish(
        &self,
        control: &WorkerControl,
        runtime: &Weak<Runtime>,
        priority: &async_mpsc::Sender<StopNotice>,
        debugger: Option<ObservationSample>,
        code: &[ObservationSample],
    ) -> bool {
        if control.is_cancelled() {
            return false;
        }
        let Some(runtime) = runtime.upgrade() else {
            return false;
        };
        let samples = debugger.into_iter().chain(code.iter().copied()).collect();
        !runtime.stop_for_observation(
            || {
                (!control.is_cancelled())
                    .then(|| self.stop_candidate(samples))
                    .flatten()
            },
            |token, sample| {
                deliver(
                    priority,
                    StopNotice {
                        token,
                        epoch: sample.policy_epoch,
                        record: sample.record,
                    },
                )
            },
        )
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn run(self, _: WorkerControl, _: Weak<Runtime>, _: async_mpsc::Sender<StopNotice>) {
        let _ = (&self.signed, &self.pin, self.flags);
    }
}

fn verify<'a>(
    signed: &'a SignedDetectionPolicy,
    pin: &VerifyingKey,
    policy: PolicyContext,
    flags: u8,
) -> Result<VerifiedPolicy<'a>, ProtocolError> {
    if !signed.has_profile() {
        return signed.verify_for(pin, policy);
    }
    use ObservationKind::{CodeIntegrity, DebuggerAttachment};
    let supported = match flags {
        DEBUGGER => &[DebuggerAttachment][..],
        OWN_CODE => &[CodeIntegrity][..],
        _ => &[DebuggerAttachment, CodeIntegrity][..],
    };
    signed.verify_for_profile(
        pin,
        ProfileContext {
            policy,
            profile: ObservationProfile::Online,
            supported,
            previous: None,
        },
    )
}

fn policy_error(error: ProtocolError) -> Status {
    match error {
        ProtocolError::Version | ProtocolError::UnknownMandatory => Status::Incompatible,
        _ => Status::InvalidPackage,
    }
}

#[cfg(target_arch = "x86_64")]
fn windows_build() -> Result<u32, Status> {
    crate::observations::windows::native_windows_build().map_err(|_| Status::Incompatible)
}

#[cfg(not(target_arch = "x86_64"))]
fn windows_build() -> Result<u32, Status> {
    Err(Status::Incompatible)
}

pub(super) fn consent_digest(policy: &[u8], flags: u8) -> Digest {
    let mut hash = Sha256::new();
    hash.update(b"vmkek.protocol.v1.r17.local-stop\0");
    hash.update(Sha256::digest(policy));
    hash.update([flags]);
    hash.finalize().into()
}

#[cfg(target_arch = "x86_64")]
fn measurement_reason(error: ProtocolError) -> ObservationReason {
    match error {
        ProtocolError::Binding => ObservationReason::OutsideScope,
        _ => ObservationReason::ReadFailure,
    }
}

#[cfg(target_arch = "x86_64")]
fn deliver<T>(queue: &async_mpsc::Sender<T>, notice: T) -> ObservationDelivery {
    use async_mpsc::error::TrySendError;
    match queue.try_send(notice) {
        Ok(()) => ObservationDelivery::Queued,
        Err(TrySendError::Full(_)) => ObservationDelivery::DroppedFull,
        Err(TrySendError::Closed(_)) => ObservationDelivery::ReceiverClosed,
    }
}

pub(super) fn start_observer(
    policy: StopPolicy,
    runtime: Weak<Runtime>,
    priority: async_mpsc::Sender<StopNotice>,
) -> Result<ObservationWorker, Status> {
    ObservationWorker::start(move |control| policy.run(control, runtime, priority))
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use vmkek_protocol::{
        detection::{
            BuildRange, DetectionPolicy, ObservationMode, ObservationReaction, ObservationRule,
            ObservationSettings,
        },
        public_key_id,
        session_observation::{Observation, ObservationReason},
    };

    use super::*;

    #[test]
    fn terminal_notice_keeps_queue_pressure_distinct() {
        let (sender, mut receiver) = async_mpsc::channel(1);
        assert_eq!(deliver(&sender, 7), ObservationDelivery::Queued);
        assert_eq!(deliver(&sender, 8), ObservationDelivery::DroppedFull);
        assert_eq!(receiver.try_recv().unwrap(), 7);
        drop(receiver);
        assert_eq!(deliver(&sender, 9), ObservationDelivery::ReceiverClosed);
    }

    #[test]
    fn profiled_online_stop_policy_checks_capabilities_before_sampling() {
        let build = windows_build().unwrap();
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let key = SigningKey::from_slice(&[0x58; 32]).unwrap();
        let pin = *key.verifying_key();
        let app_id = [1; 16];
        let build_id = [2; 16];
        let policy = DetectionPolicy {
            app_id,
            build_id,
            key_id: public_key_id(&pin),
            epoch: 7,
            issued_ms: now,
            expires_ms: now + 60_000,
            windows_builds: BuildRange {
                first: build,
                last: build,
            },
            artifacts: vec![],
            images: vec![],
        };
        let activate = |required, flags| {
            let signed = SignedDetectionPolicy::sign_for_profile(
                policy.clone(),
                ObservationSettings {
                    profile: ObservationProfile::Online,
                    mode: ObservationMode::Observe,
                    max_age_ms: 10_000,
                    rules: vec![ObservationRule {
                        signal_id: SignalId::DEBUGGER,
                        required,
                        reaction: ObservationReaction::Stop,
                    }],
                },
                &key,
            )
            .unwrap();
            let proof: Signature = key
                .sign_prehash(&consent_digest(signed.as_bytes(), flags))
                .unwrap();
            StopPolicy::new(
                signed.as_bytes(),
                pin,
                proof.to_bytes().into(),
                flags,
                app_id,
                build_id,
                7,
            )
        };
        assert!(matches!(
            activate(true, OWN_CODE),
            Err(Status::Incompatible)
        ));
        let optional = activate(false, OWN_CODE).unwrap();
        assert!(optional.stop_candidate(optional.sample()).is_none());
        let gate = optional.gate().unwrap();
        let report = gate.assessment(SignalId::DEBUGGER).unwrap();
        let sample = report.sample.unwrap();
        assert_eq!(sample.outcome(), Observation::Unsupported);
        assert_eq!(sample.reason, ObservationReason::PlatformUnsupported);
        assert_eq!(report.decision, ObservationDecision::ReportOnly(sample));
        assert_eq!(gate.admit(), Ok(()));

        let supported = activate(true, DEBUGGER).unwrap();
        let native = supported.sample();
        assert_eq!(native.len(), 1);
        let sample = native[0];
        assert!(supported.stop_candidate(native).is_none());
        assert_eq!(
            supported
                .gate()
                .unwrap()
                .assessment(SignalId::DEBUGGER)
                .unwrap()
                .decision,
            ObservationDecision::ReportOnly(sample),
        );
    }
}
