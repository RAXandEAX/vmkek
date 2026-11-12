use std::{
    sync::{mpsc, Weak},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc as async_mpsc;
use vmkek_client::LeaseToken;
use vmkek_protocol::{
    detection::{PolicyContext, SignedDetectionPolicy},
    session_observation::ObservationRecord,
    Digest, Id,
};

use crate::{state::Runtime, Status};

pub(super) const DEBUGGER: u8 = 1;
pub(super) const OWN_CODE: u8 = 2;

pub(super) struct StopPolicy {
    signed: SignedDetectionPolicy,
    pin: VerifyingKey,
    context: PolicyContext,
    anchor: Instant,
    flags: u8,
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
        let signed = SignedDetectionPolicy::decode(bytes).map_err(|_| Status::InvalidPackage)?;
        let anchor = Instant::now();
        let context = PolicyContext {
            app_id,
            build_id,
            epoch_floor,
            windows_build: windows_build()?,
            now_ms: u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Status::Unavailable)?
                    .as_millis(),
            )
            .map_err(|_| Status::Unavailable)?,
        };
        signed
            .verify_for(&pin, context)
            .map_err(|_| Status::InvalidPackage)?;
        Ok(Self {
            signed,
            pin,
            context,
            anchor,
            flags,
        })
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn sample(&self) -> Option<(u64, ObservationRecord)> {
        use crate::observations::{
            windows::{self, CodeObservation, OwnedModule},
            Observation,
        };
        use vmkek_protocol::{
            detection::ImagePurpose,
            session_observation::{ObservationFinding, ObservationKind},
        };

        let now_ms = self
            .context
            .now_ms
            .checked_add(u64::try_from(self.anchor.elapsed().as_millis()).ok()?)?;
        let policy = self
            .signed
            .verify_for(
                &self.pin,
                PolicyContext {
                    now_ms,
                    ..self.context
                },
            )
            .ok()?;
        if self.flags & DEBUGGER != 0 && windows::debugger_attachment() == Observation::Observed {
            return Some((
                policy.epoch(),
                ObservationRecord {
                    kind: ObservationKind::DebuggerAttachment,
                    rule_id: 0,
                    finding: ObservationFinding::Observed,
                },
            ));
        }
        if self.flags & OWN_CODE == 0 || policy.image_rules().is_empty() {
            return None;
        }
        let owned = OwnedModule::from_address(crate::vmk_initialize as *const () as usize).ok()?;
        let observed = owned.observe(&policy, now_ms).ok()?;
        observed
            .into_iter()
            .find(|sample| {
                sample.file == Observation::Observed
                    && sample.code == CodeObservation::DiffersFromSignedBytes
                    && policy.image_rules().iter().any(|rule| {
                        rule.id == sample.rule_id && rule.purpose == ImagePurpose::CodeIntegrity
                    })
            })
            .map(|sample| {
                (
                    policy.epoch(),
                    ObservationRecord {
                        kind: ObservationKind::CodeIntegrity,
                        rule_id: sample.rule_id,
                        finding: ObservationFinding::SignedMismatch,
                    },
                )
            })
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub(super) fn sample(&self) -> Option<(u64, ObservationRecord)> {
        let _ = (
            &self.signed,
            &self.pin,
            self.context,
            self.anchor,
            self.flags,
        );
        None
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

pub(super) struct Observer {
    stop: mpsc::Sender<()>,
    join: Option<JoinHandle<()>>,
}

impl Observer {
    pub(super) fn start(
        policy: StopPolicy,
        runtime: Weak<Runtime>,
        priority: async_mpsc::Sender<StopNotice>,
    ) -> Result<Self, Status> {
        let (stop, stopped) = mpsc::channel();
        let join = thread::Builder::new()
            .name("vmkek-observation".into())
            .spawn(move || {
                while let Err(mpsc::RecvTimeoutError::Timeout) =
                    stopped.recv_timeout(Duration::from_millis(500))
                {
                    if let Some((epoch, record)) = policy.sample() {
                        if let Some(runtime) = runtime.upgrade() {
                            runtime.stop_for_observation(|token| {
                                let _ = priority.try_send(StopNotice {
                                    token,
                                    epoch,
                                    record,
                                });
                            });
                        }
                        break;
                    }
                    if runtime.strong_count() == 0 {
                        break;
                    }
                }
            })
            .map_err(|_| Status::ResourceLimit)?;
        Ok(Self {
            stop,
            join: Some(join),
        })
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(join) = self.join.take() {
            if join.thread().id() != thread::current().id() {
                let _ = join.join();
            }
        }
    }
}
