use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

mod evidence;
mod view;
pub use evidence::{EvidenceArtifact, EvidenceClaim, EvidenceKind, EvidenceStatus, Property};
pub use view::view_json;

use crate::proof::{Claim, PassClaim};

pub fn push_pass(passes: &mut Vec<String>, name: &str) {
    if !passes.iter().any(|item| item == name) {
        passes.push(name.to_string());
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolReport {
    pub name: String,
    pub rva: u32,
    pub size: u32,
    pub action: String,
    /// `register` or `stack` for a virtualized function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// Set for a virtualized function. Single-path functions have data-dependent edges.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single_path: Option<bool>,
    /// Set for a virtualized function. The stub picks the next handler entry from the gate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_dependent: Option<bool>,
}

/// Measured stub diversity for one protect build. The protect seed is not stored here.
#[derive(Clone, Debug, Serialize)]
pub struct StubDiversity {
    /// Named handler window the percent is computed on. Shorter than the full stub.
    pub window: &'static str,
    /// Longer compared window, in bytes. `difference_percent` divides by this.
    pub window_len: u32,
    /// Bytes that differ, including the tail that exists only on the longer window.
    pub different_bytes: u32,
    /// Integer percent `different_bytes * 100 / window_len`.
    pub difference_percent: u32,
    /// Oracle equivalence of the metamorphic stub.
    #[serde(skip)]
    pub equivalence: &'static str,
    /// Strength of the byte-difference claim.
    #[serde(skip)]
    pub difference_claim: &'static str,
    /// Slot permutation, handler variants, cipher salt, and junk order.
    pub varies: &'static [&'static str],
}

/// JSON object keys [`Report`] is allowed to emit. Secret keys, the opcode map, and IR are absent.
pub const REPORT_VERSION: u32 = 2;

pub const REPORT_FIELDS: &[&str] = &[
    "report_version",
    "profile",
    "artifact_sha256",
    "seed",
    "passes",
    "claims",
    "diversity",
    "virtualized",
    "mutated",
    "entry_rva",
    "public_key",
    "signature",
    "authenticode_resign_required",
    "windows_native",
];

#[derive(Clone, Debug)]
pub struct Report {
    /// Present only when protect was asked for a debug seed dump.
    pub seed: Option<u64>,
    pub passes: Vec<String>,
    /// Historical in-process catalog. JSON consumers use the evidence claims.
    pub claims: Vec<PassClaim>,
    /// SHA-256 of the bytes returned by the protector.
    pub artifact_sha256: String,
    /// Measured difference of the handler window. The protect seed is not stored here.
    pub diversity: StubDiversity,
    pub virtualized: Vec<SymbolReport>,
    pub mutated: Vec<SymbolReport>,
    pub entry_rva: u32,
    pub public_key: String,
    pub signature: String,
    /// Rewriting discarded the PE certificate table. Sign the output again.
    pub authenticode_resign_required: bool,
    /// The output uses the native Windows profile and keeps OS-managed imports.
    pub windows_native: bool,
}

impl Serialize for Report {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let count = 12 + usize::from(self.seed.is_some()) + usize::from(self.windows_native);
        let mut out = serializer.serialize_struct("Report", count)?;
        write_report(&mut out, self)?;
        out.end()
    }
}

fn write_report<S: SerializeStruct>(
    out: &mut S,
    report: &Report,
) -> std::result::Result<(), S::Error> {
    out.serialize_field("report_version", &REPORT_VERSION)?;
    out.serialize_field("profile", &report.profile())?;
    out.serialize_field("artifact_sha256", &report.artifact_sha256)?;
    if let Some(seed) = report.seed {
        out.serialize_field("seed", &seed)?;
    }
    out.serialize_field("passes", &report.passes)?;
    out.serialize_field("claims", &report.evidence_claims())?;
    out.serialize_field("diversity", &report.diversity)?;
    out.serialize_field("virtualized", &report.virtualized)?;
    out.serialize_field("mutated", &report.mutated)?;
    out.serialize_field("entry_rva", &report.entry_rva)?;
    out.serialize_field("public_key", &report.public_key)?;
    out.serialize_field("signature", &report.signature)?;
    out.serialize_field(
        "authenticode_resign_required",
        &report.authenticode_resign_required,
    )?;
    if report.windows_native {
        out.serialize_field("windows_native", &report.windows_native)?;
    }
    Ok(())
}

impl Report {
    /// Evidence claims describing the applied passes and the verification still required.
    #[must_use]
    pub fn evidence_claims(&self) -> Vec<EvidenceClaim> {
        evidence::from_registry(&self.claims, self.windows_native, &self.artifact_sha256)
    }

    fn profile(&self) -> Profile {
        if self
            .passes
            .iter()
            .any(|pass| matches!(pass.as_str(), "external-key" | "authenticated-bootstrap"))
        {
            Profile::Lab
        } else {
            Profile::Legacy
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Profile {
    Legacy,
    Lab,
    Online,
}

/// Integer percent of bytes that differ between two `.vmkek` section bodies.
///
/// The denominator is the longer body. Bytes that exist on only one side count
/// as different. An empty pair is `0`, which is below the 25% threshold.
#[must_use]
pub fn section_difference_percent(left: &[u8], right: &[u8]) -> u32 {
    let compared = left.len().max(right.len());
    if compared == 0 {
        return 0;
    }
    let mut different = left.len().abs_diff(right.len());
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        if left_byte != right_byte {
            different += 1;
        }
    }
    let percent = different.saturating_mul(100) / compared;
    u32::try_from(percent).unwrap_or(u32::MAX)
}

/// `true` when this report was built without a seed and its JSON omits the field and the decimal seed.
#[must_use]
pub fn report_hides_seed(report: &Report, seed: u64) -> bool {
    if report.seed.is_some() {
        return false;
    }
    let Ok(text) = serde_json::to_string(report) else {
        return false;
    };
    !text.contains("\"seed\"") && !text.contains(&seed.to_string())
}

/// `true` when every `Proven` claim has an anchor and no claim states virtual black-box.
#[must_use]
pub fn claims_are_anchored(claims: &[PassClaim]) -> bool {
    claims.iter().all(claim_is_anchored)
}

fn claim_is_anchored(item: &PassClaim) -> bool {
    if item.claim == Claim::Proven && item.proof_anchor.unwrap_or("").is_empty() {
        return false;
    }
    let text = format!(
        "{} {} {} {} {}",
        item.pass,
        item.attacker_model,
        item.proof_anchor.unwrap_or(""),
        item.channel,
        item.machine
    );
    let lower = text.to_ascii_lowercase();
    !lower.contains("virtual black-box")
        && !lower.contains("virtual-black-box")
        && !lower.contains("virtual black box")
}
