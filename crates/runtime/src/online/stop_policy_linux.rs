use std::{
    sync::{Arc, Weak},
    time::Duration,
};

use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc as async_mpsc;
use vmkek_client::LeaseToken;
use vmkek_protocol::{
    detection::{
        LinuxProfileContext, LinuxRelease, ObservationDecision, ObservationProfile,
        SignedDetectionPolicy,
    },
    session_observation::{
        ObservationFinding, ObservationKind, ObservationReason, ObservationRecord, SignalId,
    },
    Id,
};

use crate::{
    observations::{
        linux::{self, PreparedElfIntegrity},
        scheduler::{IntegritySchedule, ObservationWorker, DEBUGGER_INTERVAL},
        ObservationDelivery, ObservationGate,
    },
    state::Runtime,
    Status,
};

pub(super) struct StopPolicy {
    signed: SignedDetectionPolicy,
    pin: VerifyingKey,
    app_id: Id,
    build_id: Id,
    floor: u64,
    release: LinuxRelease,
    wall_ms: u64,
    anchor: Duration,
    flags: u8,
    gate: Arc<ObservationGate>,
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
        floor: u64,
    ) -> Result<Self, Status> {
        if flags == 0 || flags & !3 != 0 || floor == 0 {
            return Err(Status::InvalidArgument);
        }
        let proof = Signature::from_slice(&consent).map_err(|_| Status::InvalidPackage)?;
        let mut hash = Sha256::new();
        hash.update(b"vmkek.protocol.v1.r17.local-stop\0");
        hash.update(Sha256::digest(bytes));
        hash.update([flags]);
        pin.verify_prehash(&hash.finalize(), &proof)
            .map_err(|_| Status::InvalidPackage)?;
        let signed = SignedDetectionPolicy::decode(bytes).map_err(linux::policy_error)?;
        let release = linux::native_release().map_err(|_| Status::Incompatible)?;
        let anchor = linux::boottime().map_err(|_| Status::Unavailable)?;
        let wall_ms = linux::wall_ms()?;
        let verified = signed
            .verify_for_linux_profile(
                &pin,
                LinuxProfileContext {
                    app_id,
                    build_id,
                    epoch_floor: floor,
                    now_ms: wall_ms,
                    release,
                    profile: ObservationProfile::Online,
                    supported: supported(flags),
                    previous: None,
                },
            )
            .map_err(linux::policy_error)?;
        let gate = Arc::new(ObservationGate::new_at(
            verified.observation_policy().ok_or(Status::Incompatible)?,
            anchor,
        ));
        Ok(Self {
            signed,
            pin,
            app_id,
            build_id,
            floor,
            release,
            wall_ms,
            anchor,
            flags,
            gate,
        })
    }

    pub(super) fn gate(&self) -> Option<Arc<ObservationGate>> {
        Some(self.gate.clone())
    }

    fn now_ms(&self) -> Option<u64> {
        let elapsed = linux::boottime().ok()?.checked_sub(self.anchor)?;
        self.wall_ms
            .checked_add(elapsed.as_millis().try_into().ok()?)
    }
}

fn supported(flags: u8) -> &'static [ObservationKind] {
    use ObservationKind::{CodeIntegrity, DebuggerAttachment};
    match flags {
        1 => &[DebuggerAttachment],
        2 => &[CodeIntegrity],
        _ => &[DebuggerAttachment, CodeIntegrity],
    }
}

pub(super) fn start_observer(
    policy: StopPolicy,
    runtime: Weak<Runtime>,
    priority: async_mpsc::Sender<StopNotice>,
) -> Result<ObservationWorker, Status> {
    linux::pin_observer_module()?;
    ObservationWorker::start(move |control| {
        let Ok(verified) = policy.signed.verify_for_linux_profile(
            &policy.pin,
            LinuxProfileContext {
                app_id: policy.app_id,
                build_id: policy.build_id,
                epoch_floor: policy.floor,
                now_ms: policy.wall_ms,
                release: policy.release,
                profile: ObservationProfile::Online,
                supported: supported(policy.flags),
                previous: None,
            },
        ) else {
            return;
        };
        let code: Vec<_> = verified
            .image_rules()
            .iter()
            .filter_map(|image| {
                let id = SignalId {
                    kind: ObservationKind::CodeIntegrity,
                    rule_id: image.id,
                };
                (policy.flags & 2 != 0 && policy.gate.selects(id)).then_some(id)
            })
            .collect();
        let debugger = policy.flags & 1 != 0 && policy.gate.selects(SignalId::DEBUGGER);
        let mut prepared = None;
        let mut retry_after = Duration::ZERO;
        let mut schedule = IntegritySchedule::default();
        let mut last_code = Vec::new();
        while !control.is_cancelled() {
            let Some(now_ms) = policy
                .now_ms()
                .filter(|&now| verified.check_time(now).is_ok())
            else {
                break;
            };
            let Ok(now) = linux::boottime() else {
                break;
            };
            let debugger_sample = if debugger {
                linux::tracer_attachment_sample(policy.gate.begin_sample()).ok()
            } else {
                None
            };
            if !publish(
                &policy,
                &control,
                &runtime,
                &priority,
                debugger_sample,
                &last_code,
            ) {
                break;
            }
            if !code.is_empty() && schedule.due(now) {
                if prepared.is_none() && now >= retry_after {
                    prepared = PreparedElfIntegrity::prepare(&verified, now_ms)
                        .ok()
                        .map(|(image, _)| image);
                    retry_after = now.saturating_add(Duration::from_secs(2));
                }
                let window = policy.gate.begin_sample();
                last_code = prepared
                    .as_ref()
                    .and_then(|image| image.observe(&verified, policy.now_ms()?, window).ok())
                    .map(|(rows, _)| {
                        rows.into_iter()
                            .filter(|row| code.contains(&row.signal_id()))
                            .collect()
                    })
                    .unwrap_or_else(|| {
                        code.iter()
                            .map(|id| {
                                window.sample(
                                    ObservationRecord {
                                        kind: id.kind,
                                        rule_id: id.rule_id,
                                        finding: ObservationFinding::Inconclusive,
                                    },
                                    ObservationReason::ReadFailure,
                                )
                            })
                            .collect()
                    });
            }
            if !code.is_empty()
                && !last_code.is_empty()
                && !publish(
                    &policy,
                    &control,
                    &runtime,
                    &priority,
                    debugger_sample,
                    &last_code,
                )
            {
                break;
            }
            if !control.wait(DEBUGGER_INTERVAL) {
                break;
            }
        }
    })
}

fn publish(
    policy: &StopPolicy,
    control: &crate::observations::scheduler::WorkerControl,
    runtime: &Weak<Runtime>,
    priority: &async_mpsc::Sender<StopNotice>,
    debugger: Option<vmkek_protocol::session_observation::ObservationSample>,
    code: &[vmkek_protocol::session_observation::ObservationSample],
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
            if control.is_cancelled() || policy.gate.publish(samples).is_err() {
                return None;
            }
            match policy.gate.decision() {
                ObservationDecision::RequestOwnStop(sample) => Some(sample),
                _ => None,
            }
        },
        |token, sample| match priority.try_send(StopNotice {
            token,
            epoch: sample.policy_epoch,
            record: sample.record,
        }) {
            Ok(()) => ObservationDelivery::Queued,
            Err(async_mpsc::error::TrySendError::Full(_)) => ObservationDelivery::DroppedFull,
            Err(async_mpsc::error::TrySendError::Closed(_)) => ObservationDelivery::ReceiverClosed,
        },
    )
}
