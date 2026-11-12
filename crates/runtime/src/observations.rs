//! Bounded observations of the current application for local policy decisions.

use std::{
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use vmkek_protocol::{
    detection::{
        Advice, ArtifactKind, ObservationDecision, ObservationPolicy, ObservationProfile,
        PolicyRevision, Severity, VerifiedPolicy,
    },
    session_observation::{
        ObservationFinding, ObservationKind, ObservationPlatform, ObservationReason,
        ObservationRecord, ObservationSample, SignalId,
    },
    Digest, ProtocolError,
};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod linux;
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows;

#[cfg(test)]
pub(crate) mod tests;

pub mod scheduler;

const MAX_INVENTORY: usize = 128;
#[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
static OBSERVATION_CLOCK: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);

#[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
pub(crate) fn monotonic_now() -> Duration {
    OBSERVATION_CLOCK.elapsed()
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn monotonic_now() -> Duration {
    linux::boottime().unwrap_or(Duration::MAX)
}

#[cfg(windows)]
pub(crate) fn monotonic_now() -> Duration {
    #[link(name = "kernel32")]
    extern "system" {
        fn QueryInterruptTimePrecise(time: *mut u64);
    }
    let mut ticks = 0;
    // SAFETY: The Win32 API writes one ULONGLONG to this live output.
    unsafe { QueryInterruptTimePrecise(&mut ticks) };
    Duration::new(ticks / 10_000_000, ((ticks % 10_000_000) * 100) as u32)
}

pub use vmkek_protocol::session_observation::Observation;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ObservationDelivery {
    #[default]
    NotAttempted,
    Queued,
    DroppedFull,
    ReceiverClosed,
}

/// Delivery of the one-shot online own-stop report, independent of local denial.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ObservationReport {
    #[default]
    NotCompleted,
    Acknowledged,
    Failed(crate::Status),
}

/// A sampling interval on the process monotonic clock.
#[derive(Clone, Copy)]
pub struct SampleWindow {
    platform: ObservationPlatform,
    policy_epoch: u64,
    policy_digest: Option<Digest>,
    sampled_at: Duration,
    valid_until: Duration,
}

impl SampleWindow {
    pub fn new(platform: ObservationPlatform, policy_epoch: u64, max_age: Duration) -> Self {
        let sampled_at = monotonic_now();
        Self {
            platform,
            policy_epoch,
            policy_digest: None,
            sampled_at,
            valid_until: sampled_at.saturating_add(max_age),
        }
    }

    /// Starts a local sample for the exact signed policy revision.
    pub fn for_verified(policy: &VerifiedPolicy<'_>, max_age: Duration) -> Self {
        Self::for_revision(policy.platform(), policy.revision(), max_age)
    }

    fn for_revision(
        platform: ObservationPlatform,
        revision: PolicyRevision,
        max_age: Duration,
    ) -> Self {
        Self {
            policy_digest: Some(revision.digest),
            ..Self::new(platform, revision.epoch, max_age)
        }
    }

    pub fn sample(self, record: ObservationRecord, reason: ObservationReason) -> ObservationSample {
        ObservationSample {
            record,
            reason,
            platform: self.platform,
            policy_epoch: self.policy_epoch,
            policy_digest: self.policy_digest,
            sampled_at: self.sampled_at,
            valid_until: self.valid_until,
        }
    }

    fn check_policy(self, policy: &VerifiedPolicy<'_>) -> Result<(), ProtocolError> {
        let revision = policy.revision();
        if self.policy_epoch != revision.epoch
            || self.policy_digest != Some(revision.digest)
            || self.platform != policy.platform()
        {
            return Err(ProtocolError::Binding);
        }
        Ok(())
    }

    pub(crate) fn attachment(
        self,
        outcome: Observation,
        reason: ObservationReason,
    ) -> ObservationSample {
        self.sample(
            ObservationRecord {
                kind: ObservationKind::DebuggerAttachment,
                rule_id: 0,
                finding: match outcome {
                    Observation::Observed => ObservationFinding::Observed,
                    Observation::NotObservedWithinScope => {
                        ObservationFinding::NotObservedWithinScope
                    }
                    Observation::Inconclusive => ObservationFinding::Inconclusive,
                    Observation::Unsupported => ObservationFinding::Unsupported,
                },
            },
            reason,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationAssessment {
    pub sample: Option<ObservationSample>,
    pub decision: ObservationDecision,
}

/// Local admission for a verified profile. The launcher captures the anchor
/// with the activation wall-clock reading used to verify the signed policy.
pub struct ObservationGate {
    policy: ObservationPolicy,
    anchor: Duration,
    age_at_anchor: Duration,
    state: Mutex<GateState>,
}

#[derive(Default)]
struct GateState {
    samples: Box<[ObservationSample]>,
    offline_stop: Option<ObservationSample>,
    offline_runtimes: Vec<(crate::VmkRuntime, Weak<crate::state::Runtime>)>,
}

impl ObservationGate {
    pub fn new(policy: ObservationPolicy, anchor: Instant) -> Self {
        Self::with_elapsed(policy, monotonic_now(), anchor.elapsed())
    }

    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn new_at(policy: ObservationPolicy, anchor: Duration) -> Self {
        Self::with_elapsed(policy, anchor, Duration::ZERO)
    }

    fn with_elapsed(policy: ObservationPolicy, anchor: Duration, age_at_anchor: Duration) -> Self {
        Self {
            policy,
            anchor,
            age_at_anchor,
            state: Mutex::new(GateState::default()),
        }
    }

    pub(crate) fn matches_offline_artifact(
        &self,
        app_id: vmkek_protocol::Id,
        build_id: vmkek_protocol::Id,
    ) -> bool {
        self.policy
            .matches_artifact(ObservationProfile::Offline, app_id, build_id)
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    pub(crate) fn matches_native_build(&self, build: u32) -> bool {
        self.policy.platform() == (ObservationPlatform::Windows { build })
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn matches_linux_release(
        &self,
        release: vmkek_protocol::detection::LinuxRelease,
    ) -> bool {
        self.anchor != Duration::MAX && self.policy.linux_release() == Some(release)
    }

    pub fn begin_sample(&self) -> SampleWindow {
        SampleWindow::for_revision(
            self.policy.platform(),
            self.policy.revision(),
            self.policy.max_age(),
        )
    }

    /// Replace the bounded snapshot. Each selected signal may appear once.
    pub fn publish(&self, samples: Vec<ObservationSample>) -> Result<(), ProtocolError> {
        if samples.len() > self.policy.rules().len() {
            return Err(ProtocolError::Limit);
        }
        if samples
            .windows(2)
            .any(|pair| pair[0].signal_id() >= pair[1].signal_id())
            || samples
                .iter()
                .any(|sample| !self.selects(sample.signal_id()))
        {
            return Err(ProtocolError::Invalid);
        }
        let now = monotonic_now();
        for sample in &samples {
            self.policy.validate_sample(*sample, now)?;
        }
        let mut state = crate::state::lock(&self.state);
        let current = &state.samples;
        if samples.iter().any(|sample| {
            current
                .binary_search_by_key(&sample.signal_id(), |entry| entry.signal_id())
                .is_ok_and(|index| current[index].sampled_at > sample.sampled_at)
        }) {
            return Err(ProtocolError::Binding);
        }
        state.samples = samples.into_boxed_slice();
        let listeners = self.latch_offline_stop(&mut state);
        drop(state);
        for (_, listener) in listeners {
            if let Some(runtime) = listener.upgrade() {
                runtime.stop_offline_observation();
            }
        }
        Ok(())
    }

    fn latch_offline_stop(
        &self,
        state: &mut GateState,
    ) -> Vec<(crate::VmkRuntime, Weak<crate::state::Runtime>)> {
        if self.policy.profile() != ObservationProfile::Offline || state.offline_stop.is_some() {
            return Vec::new();
        }
        let ObservationDecision::RequestOwnStop(sample) = self.current_decision(&state.samples)
        else {
            return Vec::new();
        };
        state.offline_stop = Some(sample);
        std::mem::take(&mut state.offline_runtimes)
    }

    pub(crate) fn offline_stop_latched(&self) -> bool {
        self.policy.profile() == ObservationProfile::Offline
            && crate::state::lock(&self.state).offline_stop.is_some()
    }

    pub(crate) fn bind_offline_runtime(
        &self,
        handle: crate::VmkRuntime,
        runtime: &Arc<crate::state::Runtime>,
    ) -> bool {
        if self.policy.profile() != ObservationProfile::Offline {
            return false;
        }
        let mut state = crate::state::lock(&self.state);
        if state.offline_stop.is_some() {
            return true;
        }
        state
            .offline_runtimes
            .push((handle, Arc::downgrade(runtime)));
        false
    }

    pub(crate) fn unbind_offline_runtime(&self, handle: crate::VmkRuntime) {
        if self.policy.profile() == ObservationProfile::Offline {
            crate::state::lock(&self.state)
                .offline_runtimes
                .retain(|(id, _)| *id != handle);
        }
    }

    pub(crate) fn commit<T>(
        &self,
        publish: impl FnOnce() -> Result<T, crate::Status>,
    ) -> Result<T, crate::Status> {
        if self.policy.profile() == ObservationProfile::Offline {
            let state = crate::state::lock(&self.state);
            if state.offline_stop.is_some() {
                return Err(crate::Status::Denied);
            }
            // Hold the observation lock through publication. Stop takes this
            // lock before notifying runtimes, then releases it before callbacks.
            publish()
        } else {
            publish()
        }
    }

    pub(crate) fn selects(&self, signal_id: SignalId) -> bool {
        self.policy
            .rules()
            .binary_search_by_key(&signal_id, |rule| rule.signal_id)
            .is_ok()
    }

    pub(crate) fn check_time(&self) -> Result<(), crate::Status> {
        let (now_ms, _) = self.now();
        self.policy
            .check_time(now_ms)
            .map_err(|_| crate::Status::Expired)
    }

    /// Check a protected operation before its admission.
    pub fn admit(&self) -> Result<(), crate::Status> {
        match self.decision() {
            ObservationDecision::Unavailable(_) => Err(crate::Status::Unavailable),
            ObservationDecision::RequestOwnStop(_) => Err(crate::Status::Denied),
            _ => Ok(()),
        }
    }

    pub fn assessment(&self, signal_id: SignalId) -> Option<ObservationAssessment> {
        let state = crate::state::lock(&self.state);
        let (now_ms, now) = self.now();
        self.evaluate(signal_id, &state.samples, now_ms, now)
    }

    /// A confirmed offline stop latches for this activation. Current
    /// assessments and availability still use the bounded sample window.
    pub fn decision(&self) -> ObservationDecision {
        let state = crate::state::lock(&self.state);
        state.offline_stop.map_or_else(
            || self.current_decision(&state.samples),
            ObservationDecision::RequestOwnStop,
        )
    }

    fn current_decision(&self, samples: &[ObservationSample]) -> ObservationDecision {
        let (now_ms, now) = self.now();
        let mut decision = ObservationDecision::Allow;
        for rule in self.policy.rules() {
            match self
                .evaluate(rule.signal_id, samples, now_ms, now)
                .map(|assessment| assessment.decision)
            {
                Some(stop @ ObservationDecision::RequestOwnStop(_)) => return stop,
                Some(unavailable @ ObservationDecision::Unavailable(_))
                    if !matches!(decision, ObservationDecision::Unavailable(_)) =>
                {
                    decision = unavailable;
                }
                _ => {}
            }
        }
        decision
    }

    fn now(&self) -> (u64, Duration) {
        let now = monotonic_now();
        let now_ms = u64::try_from(
            now.saturating_sub(self.anchor)
                .saturating_add(self.age_at_anchor)
                .as_millis(),
        )
        .ok()
        .and_then(|elapsed| self.policy.verified_at_ms().checked_add(elapsed))
        .unwrap_or(u64::MAX);
        (now_ms, now)
    }

    fn evaluate(
        &self,
        signal_id: SignalId,
        samples: &[ObservationSample],
        now_ms: u64,
        now: Duration,
    ) -> Option<ObservationAssessment> {
        let index = samples.binary_search_by_key(&signal_id, |sample| sample.signal_id());
        let current = match index {
            Ok(index) => std::slice::from_ref(&samples[index]),
            Err(_) => &[],
        };
        let decision = self.policy.decide(signal_id, current, now_ms, now)?;
        let sample = match decision {
            ObservationDecision::ReportOnly(sample)
            | ObservationDecision::RequestOwnStop(sample) => Some(sample),
            _ => current.first().copied(),
        };
        Some(ObservationAssessment { sample, decision })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactFinding {
    ExactMatch,
    BenignException,
    NotObservedWithinScope,
    Inconclusive,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactObservation {
    pub rule_id: u16,
    pub finding: ArtifactFinding,
    pub severity: Severity,
    pub advice: Advice,
}

/// One explicitly selected inventory source, supplied by the trusted launcher.
/// A snapshot for one source conveys nothing about any other source.
#[derive(Clone, Copy)]
pub enum Inventory<'a> {
    Snapshot(&'a [Digest]),
    Inconclusive,
    Unsupported,
}

/// A finding describes one exact inventory source. Its provenance remains advisory.
pub fn evaluate_inventory(
    policy: &VerifiedPolicy<'_>,
    source: ArtifactKind,
    inventory: Inventory<'_>,
    now_ms: u64,
) -> Result<Vec<ArtifactObservation>, ProtocolError> {
    policy.check_time(now_ms)?;
    Ok(policy
        .artifact_rules()
        .iter()
        .filter(|rule| rule.kind == source)
        .map(|rule| {
            let finding = match inventory {
                Inventory::Snapshot(records) if records.len() <= MAX_INVENTORY => {
                    if !records.contains(&rule.digest) {
                        ArtifactFinding::NotObservedWithinScope
                    } else if rule
                        .benign_builds
                        .is_some_and(|range| range.contains(policy.windows_build()))
                    {
                        ArtifactFinding::BenignException
                    } else {
                        ArtifactFinding::ExactMatch
                    }
                }
                Inventory::Snapshot(_) | Inventory::Inconclusive => ArtifactFinding::Inconclusive,
                Inventory::Unsupported => ArtifactFinding::Unsupported,
            };
            let (severity, advice) = if finding == ArtifactFinding::ExactMatch {
                (rule.severity, rule.advice)
            } else {
                (Severity::Informational, Advice::Record)
            };
            ArtifactObservation {
                rule_id: rule.id,
                finding,
                severity,
                advice,
            }
        })
        .collect())
}

/// Project the same launcher snapshot onto the local observation contract.
pub fn evaluate_inventory_samples(
    policy: &VerifiedPolicy<'_>,
    source: ArtifactKind,
    inventory: Inventory<'_>,
    now_ms: u64,
    window: SampleWindow,
) -> Result<Vec<ObservationSample>, ProtocolError> {
    window.check_policy(policy)?;
    let kind = match source {
        ArtifactKind::ApplicationFile => ObservationKind::ApplicationFile,
        ArtifactKind::RunningApplication => ObservationKind::RunningApplication,
        ArtifactKind::DriverPackage => ObservationKind::DriverPackage,
    };
    Ok(evaluate_inventory(policy, source, inventory, now_ms)?
        .into_iter()
        .map(|sample| {
            let (finding, reason) = match sample.finding {
                ArtifactFinding::ExactMatch => {
                    (ObservationFinding::Observed, ObservationReason::None)
                }
                ArtifactFinding::BenignException => (
                    ObservationFinding::BenignException,
                    ObservationReason::BenignException,
                ),
                ArtifactFinding::NotObservedWithinScope => (
                    ObservationFinding::NotObservedWithinScope,
                    ObservationReason::None,
                ),
                ArtifactFinding::Inconclusive => (
                    ObservationFinding::Inconclusive,
                    if matches!(inventory, Inventory::Snapshot(_)) {
                        ObservationReason::InvalidData
                    } else {
                        ObservationReason::ReadFailure
                    },
                ),
                ArtifactFinding::Unsupported => (
                    ObservationFinding::Unsupported,
                    ObservationReason::PlatformUnsupported,
                ),
            };
            window.sample(
                ObservationRecord {
                    kind,
                    rule_id: sample.rule_id,
                    finding,
                },
                reason,
            )
        })
        .collect())
}
