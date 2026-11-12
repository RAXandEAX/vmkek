use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use vmkek::report::{self, EvidenceArtifact, EvidenceClaim, EvidenceStatus};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER_COMMIT: &str = "76543210fedcba9876543210fedcba9876543210";
const OTHER_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn pass_claim() -> EvidenceClaim {
    serde_json::from_value(json!({
        "pass": "mba",
        "property": "correctness",
        "evidence": "formal",
        "status": "pass",
        "scope": "S1 identities over 64-bit operands under the documented flag conditions",
        "assumptions": "Kani covers the stated operand and flag model",
        "attacker": "outside the scope of this correctness claim",
        "commit": COMMIT,
        "subject_sha256": DIGEST,
        "artifact": {"sha256": OTHER_DIGEST, "tool": "Kani 0.68.0", "bounds": "64-bit operands and documented flags"}
    }))
    .unwrap()
}

#[test]
fn pass_requires_approved_evidence_for_the_expected_commit_and_build() {
    let claim = pass_claim();
    let approved = std::slice::from_ref(&claim);
    assert_eq!(
        claim.effective_status(COMMIT, DIGEST, approved),
        EvidenceStatus::Pass
    );
    assert_eq!(
        claim.effective_status(OTHER_COMMIT, DIGEST, approved),
        EvidenceStatus::Pending
    );
    assert_eq!(
        claim.effective_status(COMMIT, DIGEST, &[]),
        EvidenceStatus::Pending
    );

    assert_eq!(
        claim.effective_status(COMMIT, OTHER_DIGEST, approved),
        EvidenceStatus::Pending
    );
    let mut transplanted = claim.clone();
    transplanted.subject_sha256 = OTHER_DIGEST.into();
    assert_eq!(
        transplanted.effective_status(COMMIT, OTHER_DIGEST, approved),
        EvidenceStatus::Pending
    );
    let mut changed = claim.clone();
    changed.scope.push_str(", all x86 instructions");
    assert_eq!(
        changed.effective_status(COMMIT, DIGEST, approved),
        EvidenceStatus::Pending
    );
    changed.artifact = None;
    assert_eq!(
        changed.effective_status(COMMIT, DIGEST, &[changed.clone()]),
        EvidenceStatus::Pending
    );
    changed.artifact = Some(EvidenceArtifact {
        sha256: DIGEST.into(),
        tool: "Kani 0.68.0".into(),
        bounds: None,
    });
    assert_eq!(
        changed.effective_status(COMMIT, DIGEST, &[changed.clone()]),
        EvidenceStatus::Pending
    );
    changed.status = EvidenceStatus::NotRun;
    assert_eq!(
        changed.effective_status(COMMIT, DIGEST, &[changed.clone()]),
        EvidenceStatus::NotRun
    );
}

#[test]
fn reads_legacy_and_rejects_unknown_version_and_required_values() {
    let legacy = report::view_json(
        r#"{"claims":[{"claim":"Proven"}],"diversity":{"equivalence":"Proven","window_len":10}}"#,
    )
    .unwrap();
    let document: Value = serde_json::from_str(&legacy).unwrap();
    assert_eq!(document["report_version"], 1);
    assert_eq!(document["profile"], "legacy");
    assert_eq!(document["diversity"]["window_len"], 10);
    assert_eq!(document["claims"][0]["status"], "pending");
    assert!(!legacy.contains("Proven"));
    assert_eq!(report::view_json(&legacy).unwrap(), legacy);
    let forged_legacy = report::view_json(r#"{"claims":[{"status":"pass"}]}"#).unwrap();
    let forged_legacy: Value = serde_json::from_str(&forged_legacy).unwrap();
    assert_eq!(forged_legacy["claims"][0]["status"], "pending");
    for input in [
        r#"[1]"#,
        r#"{"report_version":3}"#,
        r#"{"report_version":null}"#,
        r#"{"report_version":1,"report_version":2}"#,
        r#"{"private_key":"secret"}"#,
        r#"{"claims":[{"claim":"Proven","private_key":"secret"}]}"#,
    ] {
        assert!(report::view_json(input).is_err(), "{input}");
    }

    let mut v2 = json!({
        "report_version":2, "profile":"legacy", "artifact_sha256":DIGEST,
        "claims":[pass_claim()]
    });
    let output: Value = serde_json::from_str(&report::view_json(&v2.to_string()).unwrap()).unwrap();
    assert_eq!(output["claims"][0]["status"], "pending");
    let mut other_build = v2.clone();
    other_build["artifact_sha256"] = json!(OTHER_DIGEST);
    assert!(report::view_json(&other_build.to_string()).is_err());

    let mut nested_unknown = v2.clone();
    nested_unknown["diversity"] = json!({"window_len": 10, "private_key": "secret"});
    assert!(report::view_json(&nested_unknown.to_string()).is_err());
    v2["claims"][0]["property"] = json!("unknown");
    assert!(report::view_json(&v2.to_string()).is_err());
}

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> Fixture {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vmkek-r01-{}-{stamp}", std::process::id()));
    fs::create_dir(&path).unwrap();
    Fixture(path)
}

#[test]
fn cli_protection_emits_v2_for_the_actual_artifact() {
    let dir = fixture();
    let input = dir.0.join("source.exe");
    let output = dir.0.join("protected.exe");
    let report = dir.0.join("protected.exe.report.json");
    fs::write(&input, vmkek::sample::build().unwrap().bytes).unwrap();
    let protect = Command::new(env!("CARGO_BIN_EXE_vmkek"))
        .arg("protect")
        .arg(input)
        .arg("-o")
        .arg(&output)
        .args(["--virtualize-all", "--seed", "91"])
        .output()
        .unwrap();
    assert!(
        protect.status.success(),
        "{}",
        String::from_utf8_lossy(&protect.stderr)
    );
    let view = Command::new(env!("CARGO_BIN_EXE_vmkek"))
        .arg("report")
        .arg(&report)
        .output()
        .unwrap();
    assert!(
        view.status.success(),
        "{}",
        String::from_utf8_lossy(&view.stderr)
    );
    let json: Value = serde_json::from_slice(&view.stdout).unwrap();
    assert_eq!(json["report_version"], 2);
    assert_eq!(json["profile"], "legacy");
    assert_eq!(
        json["artifact_sha256"],
        hex::encode(Sha256::digest(fs::read(output).unwrap()))
    );
    assert_protection_claims(&json);
}

fn assert_protection_claims(json: &Value) {
    let rows = json["claims"].as_array().unwrap();
    for (pass, property, evidence, status) in [
        ("bytecode-encrypt", "correctness", "tested", "pending"),
        (
            "bytecode-encrypt",
            "confidentiality",
            "reduction",
            "not-run",
        ),
        ("aead-inspect", "authenticity", "tested", "pending"),
        ("layout-stealth", "resilience", "empirical", "not-run"),
        ("image-hygiene", "compatibility", "tested", "not-run"),
    ] {
        assert!(
            rows.iter().any(|r| r["pass"] == pass
                && r["property"] == property
                && r["evidence"] == evidence
                && r["status"] == status),
            "{pass} {property}"
        );
    }
    assert!(rows
        .iter()
        .all(|row| row["status"] != "pass" && row["subject_sha256"] == json["artifact_sha256"]));
    assert!(json["diversity"].get("equivalence").is_none());
    assert!(json["diversity"].get("difference_claim").is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn external_key_report_identifies_its_lab_profile_and_elf() {
    let input = vmkek::elf::sample::build().unwrap();
    let options = vmkek::protect::Options {
        virtualize_all: true,
        seed: 91,
        virtualize: Default::default(),
        mutate: Default::default(),
        mutate_all: false,
        random_key: false,
        debug_seed: false,
    };
    let protected =
        vmkek::protect::protect_external(&input, &options, "/tmp/vmkek-r01.sock").unwrap();
    let json = serde_json::to_value(&protected.report).unwrap();
    assert_eq!(json["profile"], "lab");
    assert_eq!(
        json["artifact_sha256"],
        hex::encode(Sha256::digest(protected.bytes))
    );
    let claims = json["claims"].as_array().unwrap();
    assert!(claims.iter().any(|row| row["pass"] == "external-key"
        && row["property"] == "confidentiality"
        && row["status"] == "not-run"));
}
