use std::time::Duration;

use crate::{detection::PolicyRevision, Digest};

use super::{ObservationFinding, ObservationKind, ObservationRecord};

/// The outcome of one bounded observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    Observed,
    NotObservedWithinScope,
    Inconclusive,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationPlatform {
    Windows { build: u32 },
    Linux { major: u32, minor: u32, patch: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationSource {
    WindowsDebuggerApis,
    LinuxProcStatus,
    OwnedImage,
    LauncherInventory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationScope {
    CurrentProcess,
    SignedImageRule,
    InventoryKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyGroup {
    ProcessDebugState,
    OwnedImage,
    LauncherInventory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationReason {
    None,
    ApiFailure,
    SourcesDisagree,
    ReadFailure,
    InvalidData,
    PlatformUnsupported,
    OutsideScope,
    SignedMismatch,
    BenignException,
    Missing,
    Stale,
    ContextMismatch,
    PolicyExpired,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SignalId {
    pub kind: ObservationKind,
    pub rule_id: u16,
}

impl SignalId {
    pub const DEBUGGER: Self = Self {
        kind: ObservationKind::DebuggerAttachment,
        rule_id: 0,
    };

    pub(crate) fn valid(self) -> bool {
        (self.kind == ObservationKind::DebuggerAttachment) == (self.rule_id == 0)
    }

    pub(crate) fn may_stop(self) -> bool {
        matches!(
            self.kind,
            ObservationKind::DebuggerAttachment | ObservationKind::CodeIntegrity
        )
    }
}

/// A local observation. Both times are relative to the same process-local
/// monotonic anchor. Sampling time is the beginning of the measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationSample {
    pub record: ObservationRecord,
    pub reason: ObservationReason,
    pub platform: ObservationPlatform,
    pub policy_epoch: u64,
    pub policy_digest: Option<Digest>,
    pub sampled_at: Duration,
    pub valid_until: Duration,
}

impl ObservationSample {
    pub fn signal_id(self) -> SignalId {
        self.record.signal_id()
    }

    pub fn source(self) -> ObservationSource {
        use ObservationKind::*;
        match (self.record.kind, self.platform) {
            (DebuggerAttachment, ObservationPlatform::Windows { .. }) => {
                ObservationSource::WindowsDebuggerApis
            }
            (DebuggerAttachment, ObservationPlatform::Linux { .. }) => {
                ObservationSource::LinuxProcStatus
            }
            (CodeIntegrity | RegisteredProvider, _) => ObservationSource::OwnedImage,
            (ApplicationFile | RunningApplication | DriverPackage, _) => {
                ObservationSource::LauncherInventory
            }
        }
    }

    pub fn scope(self) -> ObservationScope {
        match self.source() {
            ObservationSource::WindowsDebuggerApis | ObservationSource::LinuxProcStatus => {
                ObservationScope::CurrentProcess
            }
            ObservationSource::OwnedImage => ObservationScope::SignedImageRule,
            ObservationSource::LauncherInventory => ObservationScope::InventoryKind,
        }
    }

    pub fn dependency_group(self) -> DependencyGroup {
        match self.source() {
            ObservationSource::WindowsDebuggerApis | ObservationSource::LinuxProcStatus => {
                DependencyGroup::ProcessDebugState
            }
            ObservationSource::OwnedImage => DependencyGroup::OwnedImage,
            ObservationSource::LauncherInventory => DependencyGroup::LauncherInventory,
        }
    }

    pub fn outcome(self) -> Observation {
        match self.record.finding {
            ObservationFinding::Observed
            | ObservationFinding::SignedMismatch
            | ObservationFinding::BenignException => Observation::Observed,
            ObservationFinding::NotObservedWithinScope => Observation::NotObservedWithinScope,
            ObservationFinding::Inconclusive => Observation::Inconclusive,
            ObservationFinding::Unsupported => Observation::Unsupported,
        }
    }

    pub(crate) fn validate_at(
        self,
        signal_id: SignalId,
        platform: ObservationPlatform,
        revision: PolicyRevision,
        now: Duration,
        max_age: Duration,
    ) -> Result<(), ObservationReason> {
        self.validate_context(signal_id, platform, revision)?;
        if !(self.sampled_at..self.valid_until).contains(&now) || now - self.sampled_at >= max_age {
            return Err(ObservationReason::Stale);
        }
        Ok(())
    }

    pub(crate) fn validate_context(
        self,
        signal_id: SignalId,
        platform: ObservationPlatform,
        revision: PolicyRevision,
    ) -> Result<(), ObservationReason> {
        use ObservationReason::*;
        if !self.record.valid()
            || self.signal_id() != signal_id
            || self.platform != platform
            || self.policy_epoch != revision.epoch
            || self.policy_digest != Some(revision.digest)
        {
            return Err(ContextMismatch);
        }
        if self.valid_until <= self.sampled_at {
            return Err(InvalidData);
        }
        match (self.record.finding, self.reason) {
            (ObservationFinding::Observed | ObservationFinding::NotObservedWithinScope, None)
            | (ObservationFinding::SignedMismatch, SignedMismatch)
            | (ObservationFinding::BenignException, BenignException)
            | (
                ObservationFinding::Inconclusive,
                ApiFailure | SourcesDisagree | ReadFailure | InvalidData,
            )
            | (ObservationFinding::Unsupported, PlatformUnsupported | OutsideScope) => Ok(()),
            _ => Err(InvalidData),
        }
    }
}
