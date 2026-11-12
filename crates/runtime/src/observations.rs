//! Advisory observations for a trusted launcher. This module does not change runtime authority.

use vmkek_protocol::{
    detection::{Advice, ArtifactKind, Severity, VerifiedPolicy},
    Digest, ProtocolError,
};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod linux;
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows;

const MAX_INVENTORY: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    Observed,
    NotObservedWithinScope,
    Inconclusive,
    Unsupported,
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
