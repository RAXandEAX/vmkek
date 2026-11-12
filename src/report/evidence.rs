use serde::{Deserialize, Serialize};

use crate::proof::{Claim, PassClaim};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Property {
    Correctness,
    Confidentiality,
    Authenticity,
    Resilience,
    Compatibility,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Tested,
    Formal,
    Reduction,
    Empirical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Pending,
    Pass,
    Fail,
    #[serde(rename = "not-run")]
    NotRun,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifact {
    pub sha256: String,
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounds: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceClaim {
    pub pass: String,
    pub property: Property,
    pub evidence: EvidenceKind,
    pub status: EvidenceStatus,
    pub scope: String,
    pub assumptions: String,
    pub attacker: String,
    pub subject_sha256: String,
    pub commit: Option<String>,
    pub artifact: Option<EvidenceArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
}

impl EvidenceClaim {
    /// Accept a pass only for an exact record independently verified for the expected
    /// revision. The caller supplies records approved against the actual evidence
    /// artifacts, including the verifier and bounds for formal claims.
    #[must_use]
    pub fn effective_status(
        &self,
        expected_commit: &str,
        expected_subject_sha256: &str,
        independently_approved: &[Self],
    ) -> EvidenceStatus {
        if self.status != EvidenceStatus::Pass {
            return self.status;
        }
        if !is_hex(expected_commit, &[40, 64])
            || self.commit.as_deref() != Some(expected_commit)
            || !is_hex(expected_subject_sha256, &[64])
            || self.subject_sha256 != expected_subject_sha256
            || self.scope.trim().is_empty()
            || self.assumptions.trim().is_empty()
            || self.attacker.trim().is_empty()
            || self.artifact.as_ref().is_none_or(|artifact| {
                !is_hex(&artifact.sha256, &[64])
                    || artifact.tool.trim().is_empty()
                    || (self.evidence == EvidenceKind::Formal
                        && artifact
                            .bounds
                            .as_deref()
                            .is_none_or(|bounds| bounds.trim().is_empty()))
            })
            || (self.property == Property::Resilience && self.evidence != EvidenceKind::Empirical)
            || !independently_approved.contains(self)
        {
            return EvidenceStatus::Pending;
        }
        EvidenceStatus::Pass
    }
}

pub(super) fn is_hex(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn from_registry(
    rows: &[PassClaim],
    windows_native: bool,
    subject_sha256: &str,
) -> Vec<EvidenceClaim> {
    let mut claims = Vec::new();
    for row in rows {
        claims.push(classify(row));
        if let Some(claim) = supplemental(row, windows_native) {
            claims.push(claim);
        }
    }
    for claim in &mut claims {
        claim.subject_sha256 = subject_sha256.into();
    }
    claims
}

fn classify(row: &PassClaim) -> EvidenceClaim {
    use EvidenceKind::{Empirical, Reduction, Tested};
    use EvidenceStatus::{NotRun, Pending};
    use Property::{Authenticity, Compatibility, Confidentiality, Correctness, Resilience};

    let (property, kind, status, scope) = match row.pass {
        "template-diversity" | "layout-stealth" | "mutation-diversity" => (
            Resilience,
            Empirical,
            NotRun,
            "analysis recovery and transfer on a holdout corpus",
        ),
        "authenticated-bootstrap" => (
            Authenticity,
            Tested,
            Pending,
            "bootstrap signature, digest and AEAD checks against the provisioned manufacturer pin",
        ),
        "aead-runtime" => (
            Authenticity,
            Tested,
            NotRun,
            "native loader authentication of the whole payload",
        ),
        "aead-inspect" | "ecdsa-p256" => (
            Authenticity,
            Tested,
            Pending,
            "inspect with a pinned verification key on the tested fixture",
        ),
        "external-key" => (
            Confidentiality,
            Tested,
            NotRun,
            "raw key search in the readable regions of the Linux sample process",
        ),
        "offline-key" | "string-encrypt" => (
            Confidentiality,
            Reduction,
            NotRun,
            "confidentiality against the operator of the protected process",
        ),
        "external-sample" | "early-init" | "direct-syscall-linux" => (
            Compatibility,
            Tested,
            NotRun,
            "execution of the applicable Linux sample",
        ),
        "linux-tracer-pid" | "linux-ptrace" | "linux-clock" => (
            Correctness,
            Tested,
            NotRun,
            "isolated Linux detector behavior on its native fixture",
        ),
        _ => (
            Correctness,
            Tested,
            if row.claim == Claim::Proven {
                Pending
            } else {
                NotRun
            },
            "behavior of the cited pass on the test fixtures",
        ),
    };
    let mut claim = new_claim(row, property, kind, status, scope);
    if row.pass == "aead-runtime" {
        claim.assumptions = "Legacy loader decrypts with ChaCha20 after a checksum; inspect performs authentication separately.".into();
    } else if row.pass == "authenticated-bootstrap" {
        claim.assumptions = "The pin is provisioned independently. The lab image embeds an extractable artifact key; native execution requires separate evidence.".into();
    } else if row.pass == "external-key" {
        claim.assumptions = "The lab agent is a local process; the test samples readable regions and the guest receives plaintext.".into();
    }
    claim
}

fn supplemental(row: &PassClaim, windows_native: bool) -> Option<EvidenceClaim> {
    use EvidenceKind::{Reduction, Tested};
    use EvidenceStatus::NotRun;
    use Property::{Compatibility, Confidentiality, Correctness};

    let mut claim = match row.pass {
        "mba" => new_claim(
            row,
            Correctness,
            EvidenceKind::Formal,
            EvidenceStatus::Pending,
            "S1 integer identities under the covered operand and flag conditions",
        ),
        "bytecode-encrypt" | "per-instruction-stream" => new_claim(
            row,
            Confidentiality,
            Reduction,
            NotRun,
            "bytecode confidentiality against the operator of the protected process",
        ),
        "aead-inspect" => new_claim(
            row,
            Correctness,
            Tested,
            EvidenceStatus::Pending,
            "payload encryption and authenticated opening on the test fixtures",
        ),
        "authenticated-bootstrap" => new_claim(
            row,
            Compatibility,
            Tested,
            NotRun,
            if windows_native {
                "native Windows lab startup with the required CNG imports"
            } else {
                "native lab startup on the target platform"
            },
        ),
        "image-hygiene" => new_claim(
            row,
            Compatibility,
            Tested,
            NotRun,
            if windows_native {
                "native Windows execution with supported OS mitigations"
            } else {
                "execution on the native target OS with the rewritten image"
            },
        ),
        _ => return None,
    };
    if row.pass == "mba" {
        claim.anchor = Some("docs/c5-kani.md".into());
        claim.assumptions = "The historical Kani run covers the documented integer and flag model. Its provenance is not linked to this build.".into();
    }
    Some(claim)
}

fn new_claim(
    row: &PassClaim,
    property: Property,
    evidence: EvidenceKind,
    status: EvidenceStatus,
    scope: &str,
) -> EvidenceClaim {
    let assumptions = if row.machine.is_empty() {
        "Evidence must cover the stated scope and exact source revision.".into()
    } else {
        format!(
            "Registry fixture uses {}. A run artifact must establish its limits and revision.",
            row.machine
        )
    };
    EvidenceClaim {
        pass: row.pass.into(),
        property,
        evidence,
        status,
        scope: scope.into(),
        assumptions,
        attacker: match property {
            Property::Correctness | Property::Compatibility => {
                "No adversary is assumed for the scoped behavior check."
            }
            Property::Confidentiality | Property::Resilience => {
                "Analyst with the protected artifact and control of the client process."
            }
            Property::Authenticity => row.attacker_model,
        }
        .into(),
        subject_sha256: String::new(),
        commit: None,
        artifact: None,
        anchor: row.proof_anchor.map(str::to_owned),
    }
}
