//! System differential for SSE3–FMA. A missing CPUID bit is a recorded skip.

use iced_x86::{Code, Mnemonic};

use crate::isa::census::{self, Group, Status};

use super::{census_code, Host};

#[test]
fn every_l4_mnemonic_matches_linux_or_records_why_not() {
    let mut host = Host::spawn("l4");
    let mut proven = Vec::new();
    let mut skipped = Vec::new();
    for mnemonic in Mnemonic::values() {
        sort_mnemonic(&mut host, mnemonic, &mut proven, &mut skipped);
    }
    print_l4(&proven, &skipped);
    assert!(proven.len() > 40, "proven {}", proven.len());
    let expected = Mnemonic::values()
        .filter(|&mnemonic| {
            let row = census::entry(mnemonic);
            row.group == Group::L4LateSse && row.status == Status::Lift
        })
        .count();
    assert_eq!(proven.len() + skipped.len(), expected);
    assert!(skipped.iter().any(|item| item.contains("nondeterministic")));
    assert!(skipped.iter().any(|item| item.contains("FS/GS")));
}

fn sort_mnemonic(
    host: &mut Host,
    mnemonic: Mnemonic,
    proven: &mut Vec<String>,
    skipped: &mut Vec<String>,
) {
    let row = census::entry(mnemonic);
    if row.group != Group::L4LateSse || row.status != Status::Lift {
        return;
    }
    match crate::sse::claim::skip_reason(mnemonic) {
        Some(reason) => record_skip(mnemonic, &reason, row.proven, skipped),
        None => {
            assert!(row.proven, "{mnemonic:?} ran without a proven bit");
            prove(host, mnemonic);
            proven.push(format!("{mnemonic:?}"));
        }
    }
}

fn record_skip(mnemonic: Mnemonic, reason: &str, proven: bool, skipped: &mut Vec<String>) {
    if crate::sse::claim::blocked(mnemonic) {
        assert!(
            proven,
            "{mnemonic:?} advertises its CPUID bit, so the inventory stays proven"
        );
    } else {
        assert!(!proven, "{mnemonic:?} is proven despite {reason}");
    }
    assert!(!reason.is_empty(), "{mnemonic:?}");
    skipped.push(format!("{mnemonic:?}: {reason}"));
}

fn prove(host: &mut Host, mnemonic: Mnemonic) {
    let mut reasons = Vec::new();
    for code in Code::values() {
        if !same_mnemonic(mnemonic, code) {
            continue;
        }
        if census_code(host, mnemonic, code, &mut reasons, true) {
            return;
        }
    }
    panic!("{mnemonic:?}: {}", reasons.join(" | "));
}

fn same_mnemonic(mnemonic: Mnemonic, code: Code) -> bool {
    code != Code::INVALID && code.mnemonic() == mnemonic && !code.is_privileged()
}

fn print_l4(proven: &[String], skipped: &[String]) {
    println!("L4 proven {}:", proven.len());
    for item in proven {
        println!("  {item}");
    }
    println!("L4 skipped {}:", skipped.len());
    for item in skipped {
        println!("  {item}");
    }
}
