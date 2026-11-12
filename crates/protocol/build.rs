use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[allow(dead_code)]
#[path = "src/lab/r06_rules.rs"]
mod r06_rules;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(r06_proved)");
    println!("cargo:rerun-if-changed=src/lab/r06_rules.rs");
    println!("cargo:rerun-if-changed=proofs/check_r06.py");
    if std::env::var_os("CARGO_FEATURE_R06_EXPERIMENTAL").is_none() {
        return;
    }
    match check_rules() {
        Ok(receipt) => {
            println!("cargo:rustc-cfg=r06_proved");
            println!("cargo:warning=R06 Lab rules admitted by {receipt}");
        }
        Err(error) => println!("cargo:warning=R06 Lab rules unavailable: {error}"),
    }
}

fn check_rules() -> io::Result<String> {
    if !cfg!(unix) {
        return Err(io::Error::other(
            "the bounded Z3 runner requires a Unix build host",
        ));
    }
    let output = PathBuf::from(
        std::env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("missing OUT_DIR"))?,
    );
    let proof = obligations();
    fs::write(output.join("r06.smt2"), &proof)?;
    let mut check = Command::new("python3")
        .arg("proofs/check_r06.py")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    check
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing solver stdin"))?
        .write_all(proof.as_bytes())?;
    let run = check.wait_with_output()?;
    if !run.status.success() {
        return Err(io::Error::other(format!(
            "{} {}",
            run.status,
            String::from_utf8_lossy(&run.stderr).trim()
        )));
    }
    let receipt = String::from_utf8(run.stdout).map_err(io::Error::other)?;
    let receipt = receipt.trim();
    if receipt.is_empty() || receipt.lines().count() != 1 {
        return Err(io::Error::other("unexpected Z3 receipt"));
    }
    fs::write(output.join("r06-proof.txt"), format!("{receipt}\n"))?;
    Ok(receipt.into())
}

fn obligations() -> String {
    use std::fmt::Write as _;

    let mut proof = String::from(concat!(
        "(set-logic QF_BV)\n",
        "(set-option :timeout 4000)\n",
        "(declare-const x (_ BitVec 64))\n",
        "(declare-const a (_ BitVec 64))\n",
        "(declare-const b (_ BitVec 64))\n",
        "(define-fun reference () (_ BitVec 64) (bvadd (bvadd x a) b))\n",
    ));
    for rule in r06_rules::RULES {
        let operation = match rule.operation {
            r06_rules::Operation::Add => "bvadd",
            r06_rules::Operation::Subtract => "bvsub",
        };
        let immediate = if rule.negate_sum {
            "(bvneg (bvadd a b))"
        } else {
            "(bvadd a b)"
        };
        let candidate = format!("({operation} x {immediate})");
        writeln!(
            proof,
            "(push)\n(assert (distinct reference {candidate}))\n(check-sat)\n(pop)"
        )
        .unwrap();
    }
    proof.push_str("(assert (distinct reference (bvadd reference (_ bv1 64))))\n(check-sat)\n");
    proof
}
