use std::time::Duration;

use crate::{
    canonical::{flag, Reader},
    session_observation::{
        Observation, ObservationFinding, ObservationKind, ObservationPlatform, ObservationReason,
        ObservationRecord, ObservationSample, SignalId,
    },
    Id, ProtocolError as Error,
};

use super::{
    ArtifactKind, DetectionPolicy, ImagePurpose, LinuxRelease, PolicyRevision, MAX_IMAGE_RULES,
    MAX_RULES,
};

pub(super) fn capability_bit(kind: ObservationKind) -> u8 {
    1 << (kind as u8 - 1)
}

const OBSERVATION_SETTINGS_VERSION: u16 = 1;
const MAX_OBSERVATION_RULES: usize = 1 + MAX_IMAGE_RULES + MAX_RULES;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObservationProfile {
    Offline = 1,
    Online = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObservationMode {
    Observe = 1,
    Enforce = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObservationReaction {
    Report = 1,
    Stop = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationRule {
    pub signal_id: SignalId,
    pub required: bool,
    pub reaction: ObservationReaction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationSettings {
    pub profile: ObservationProfile,
    pub mode: ObservationMode,
    pub max_age_ms: u32,
    /// Ordered by signal ID. Empty settings allow an explicit new-epoch rollback.
    pub rules: Vec<ObservationRule>,
}

impl ObservationSettings {
    pub(super) fn validate(&self, policy: &DetectionPolicy) -> Result<()> {
        if self.rules.len() > MAX_OBSERVATION_RULES {
            return Err(Error::Limit);
        }
        if policy.app_id == [0; 16]
            || policy.build_id == [0; 16]
            || policy.epoch > i64::MAX as u64
            || self.max_age_ms == 0
            || self
                .rules
                .windows(2)
                .any(|pair| pair[0].signal_id >= pair[1].signal_id)
            || self.rules.iter().any(|rule| !valid_rule(*rule, policy))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.extend(OBSERVATION_SETTINGS_VERSION.to_le_bytes());
        out.extend([self.profile as u8, self.mode as u8]);
        out.extend(self.max_age_ms.to_le_bytes());
        out.extend((self.rules.len() as u16).to_le_bytes());
        for rule in &self.rules {
            out.push(rule.signal_id.kind as u8);
            out.extend(rule.signal_id.rule_id.to_le_bytes());
            out.extend([u8::from(rule.required), rule.reaction as u8]);
        }
    }

    pub(super) fn decode(reader: &mut Reader<'_>, policy: &DetectionPolicy) -> Result<Self> {
        if reader.u16()? != OBSERVATION_SETTINGS_VERSION {
            return Err(Error::Version);
        }
        let profile = match reader.u8()? {
            1 => ObservationProfile::Offline,
            2 => ObservationProfile::Online,
            _ => return Err(Error::UnknownMandatory),
        };
        let mode = match reader.u8()? {
            1 => ObservationMode::Observe,
            2 => ObservationMode::Enforce,
            _ => return Err(Error::UnknownMandatory),
        };
        let max_age_ms = reader.u32()?;
        let count = usize::from(reader.u16()?);
        if count > MAX_OBSERVATION_RULES {
            return Err(Error::Limit);
        }
        let rules = (0..count)
            .map(|_| {
                let signal_id = SignalId {
                    kind: ObservationKind::try_from(reader.u8()?)?,
                    rule_id: reader.u16()?,
                };
                let required = flag(reader.u8()?)?;
                let reaction = match reader.u8()? {
                    1 => ObservationReaction::Report,
                    2 => ObservationReaction::Stop,
                    _ => return Err(Error::UnknownMandatory),
                };
                Ok(ObservationRule {
                    signal_id,
                    required,
                    reaction,
                })
            })
            .collect::<Result<_>>()?;
        let settings = Self {
            profile,
            mode,
            max_age_ms,
            rules,
        };
        settings.validate(policy)?;
        Ok(settings)
    }
}

fn valid_rule(rule: ObservationRule, policy: &DetectionPolicy) -> bool {
    use ObservationKind::*;
    let id = rule.signal_id;
    if !id.valid() || (rule.reaction == ObservationReaction::Stop && !id.may_stop()) {
        return false;
    }
    match id.kind {
        DebuggerAttachment => true,
        CodeIntegrity | RegisteredProvider => {
            let purpose = match id.kind {
                CodeIntegrity => ImagePurpose::CodeIntegrity,
                _ => ImagePurpose::RegisteredInstrumentation,
            };
            policy
                .images
                .iter()
                .any(|image| image.id == id.rule_id && image.purpose == purpose)
        }
        ApplicationFile | RunningApplication | DriverPackage => {
            let kind = match id.kind {
                ApplicationFile => ArtifactKind::ApplicationFile,
                RunningApplication => ArtifactKind::RunningApplication,
                _ => ArtifactKind::DriverPackage,
            };
            policy
                .artifacts
                .iter()
                .any(|artifact| artifact.id == id.rule_id && artifact.kind == kind)
        }
    }
}

/// Local decisions. Only the two record-bearing variants can be projected to
/// the existing session report format. That format makes no device-state claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationDecision {
    Allow,
    ReportOnly(ObservationSample),
    RequestOwnStop(ObservationSample),
    Unavailable(ObservationReason),
}

/// Verified local policy detached from its signed input bytes.
#[derive(Clone, Debug)]
pub struct ObservationPolicy {
    pub(super) settings: ObservationSettings,
    pub(super) app_id: Id,
    pub(super) build_id: Id,
    pub(super) supported: u8,
    pub(super) platform: ObservationPlatform,
    pub(super) linux_release: Option<LinuxRelease>,
    pub(super) revision: PolicyRevision,
    pub(super) issued_ms: u64,
    pub(super) expires_ms: u64,
    pub(super) verified_at_ms: u64,
}

impl ObservationPolicy {
    pub fn profile(&self) -> ObservationProfile {
        self.settings.profile
    }

    pub fn matches_artifact(&self, profile: ObservationProfile, app_id: Id, build_id: Id) -> bool {
        (self.profile(), self.app_id, self.build_id) == (profile, app_id, build_id)
    }

    pub fn revision(&self) -> PolicyRevision {
        self.revision
    }

    pub fn platform(&self) -> ObservationPlatform {
        self.platform
    }

    pub fn linux_release(&self) -> Option<LinuxRelease> {
        self.linux_release
    }

    pub fn verified_at_ms(&self) -> u64 {
        self.verified_at_ms
    }

    pub fn check_time(&self, now_ms: u64) -> Result<()> {
        if (self.issued_ms..self.expires_ms).contains(&now_ms) {
            Ok(())
        } else {
            Err(Error::Expired)
        }
    }

    pub fn max_age(&self) -> Duration {
        Duration::from_millis(self.settings.max_age_ms.into())
    }

    pub fn rules(&self) -> &[ObservationRule] {
        &self.settings.rules
    }

    /// Validate provenance before caching a sample. Already expired samples may
    /// be retained as diagnostics and are evaluated as stale.
    pub fn validate_sample(&self, sample: ObservationSample, now: Duration) -> Result<()> {
        sample
            .validate_context(sample.signal_id(), self.platform, self.revision)
            .map_err(|reason| {
                if reason == ObservationReason::ContextMismatch {
                    Error::Binding
                } else {
                    Error::Invalid
                }
            })?;
        if sample.sampled_at > now {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// Evaluate one exact rule. A set of observations never increases the
    /// confidence of any member and duplicate samples are ambiguous.
    pub fn decide(
        &self,
        signal_id: SignalId,
        samples: &[ObservationSample],
        now_ms: u64,
        now: Duration,
    ) -> Option<ObservationDecision> {
        let index = self
            .settings
            .rules
            .binary_search_by_key(&signal_id, |rule| rule.signal_id)
            .ok()?;
        let rule = self.settings.rules[index];
        let mandatory = self.settings.mode == ObservationMode::Enforce && rule.required;
        let unavailable = |reason| {
            if mandatory {
                ObservationDecision::Unavailable(reason)
            } else {
                ObservationDecision::Allow
            }
        };
        if self.check_time(now_ms).is_err() {
            return Some(unavailable(ObservationReason::PolicyExpired));
        }
        if self.supported & capability_bit(signal_id.kind) == 0 {
            // This samples the verified launcher's capability declaration,
            // rather than attempting a detector that the launcher lacks.
            return Some(ObservationDecision::ReportOnly(ObservationSample {
                record: ObservationRecord {
                    kind: signal_id.kind,
                    rule_id: signal_id.rule_id,
                    finding: ObservationFinding::Unsupported,
                },
                reason: ObservationReason::PlatformUnsupported,
                platform: self.platform,
                policy_epoch: self.revision.epoch,
                policy_digest: Some(self.revision.digest),
                sampled_at: now,
                valid_until: now.saturating_add(self.max_age()),
            }));
        }
        if samples.len() > MAX_OBSERVATION_RULES {
            return Some(unavailable(ObservationReason::InvalidData));
        }
        let mut matches = samples
            .iter()
            .copied()
            .filter(|sample| sample.signal_id() == signal_id);
        let Some(sample) = matches.next() else {
            return Some(unavailable(ObservationReason::Missing));
        };
        if matches.next().is_some() {
            return Some(unavailable(ObservationReason::InvalidData));
        }
        if let Err(reason) =
            sample.validate_at(signal_id, self.platform, self.revision, now, self.max_age())
        {
            return Some(unavailable(reason));
        }
        if mandatory
            && matches!(
                sample.outcome(),
                Observation::Inconclusive | Observation::Unsupported
            )
        {
            return Some(ObservationDecision::Unavailable(sample.reason));
        }
        if self.settings.mode == ObservationMode::Enforce
            && rule.reaction == ObservationReaction::Stop
            && sample.record.can_request_own_stop()
        {
            return Some(ObservationDecision::RequestOwnStop(sample));
        }
        Some(ObservationDecision::ReportOnly(sample))
    }
}
