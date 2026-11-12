use serde::{Deserialize, Serialize};

use crate::error::{msg, Result};

use super::evidence::is_hex;
use super::{EvidenceClaim, EvidenceStatus, Profile, SymbolReport, REPORT_VERSION};

#[derive(Deserialize)]
struct Version {
    #[serde(default = "legacy_version")]
    report_version: u32,
}

fn legacy_version() -> u32 {
    1
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedReport<C> {
    #[serde(default = "legacy_version")]
    report_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<Profile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<Vec<C>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diversity: Option<SavedDiversity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    virtualized: Option<Vec<SymbolReport>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mutated: Option<Vec<SymbolReport>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_rva: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authenticode_resign_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    windows_native: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedDiversity {
    #[serde(skip_serializing_if = "Option::is_none")]
    window: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_len: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    different_bytes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    difference_percent: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    varies: Option<Vec<String>>,
    #[serde(rename = "equivalence", skip_serializing)]
    _equivalence: Option<String>,
    #[serde(rename = "difference_claim", skip_serializing)]
    _difference_claim: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    pass: Option<String>,
    #[serde(rename = "claim", skip_serializing)]
    _claim: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attacker_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_anchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine: Option<String>,
    status: Option<EvidenceStatus>,
}

/// Render a saved report. User-supplied claims carry no independently approved evidence.
pub fn view_json(input: &str) -> Result<String> {
    if !input.trim_start().starts_with('{') {
        return Err(msg("report must be a JSON object"));
    }
    let version: Version = serde_json::from_str(input)?;
    match version.report_version {
        1 => view_legacy(input),
        REPORT_VERSION => view_v2(input),
        version => Err(msg(format!("unsupported report version: {version}"))),
    }
}

fn view_legacy(input: &str) -> Result<String> {
    let mut report: SavedReport<LegacyClaim> = serde_json::from_str(input)?;
    report.profile = Some(Profile::Legacy);
    report.artifact_sha256 = None;
    for claim in report.claims.iter_mut().flatten() {
        claim.status = Some(EvidenceStatus::Pending);
    }
    Ok(serde_json::to_string_pretty(&report)?)
}

fn view_v2(input: &str) -> Result<String> {
    let mut report: SavedReport<EvidenceClaim> = serde_json::from_str(input)?;
    if report.profile.is_none() {
        return Err(msg("report profile is required"));
    }
    let digest = report
        .artifact_sha256
        .as_deref()
        .filter(|digest| is_hex(digest, &[64]))
        .ok_or_else(|| msg("invalid protected artifact SHA-256"))?;
    let claims = report
        .claims
        .as_mut()
        .ok_or_else(|| msg("report claims are required"))?;
    for claim in claims {
        if claim.subject_sha256 != digest {
            return Err(msg("claim subject differs from the protected artifact"));
        }
        claim.status = claim.effective_status("", digest, &[]);
    }
    Ok(serde_json::to_string_pretty(&report)?)
}
