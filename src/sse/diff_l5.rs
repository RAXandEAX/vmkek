//! System differential for AVX and AVX2. A missing CPUID bit is a recorded skip.
//! Every YMM register is compared as 32 raw bytes.

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use crate::ir::Sse;
use crate::isa::census::{self, Group, Status};

use super::{agree, build, census_fault, check, emulate, encode_avx, fresh, regs2, xmm_ps, Host};

#[test]
fn every_l5_mnemonic_matches_linux_or_records_why_not() {
    let mut host = Host::spawn("l5");
    let mut proven = Vec::new();
    let mut skipped = Vec::new();
    for mnemonic in Mnemonic::values() {
        sort_mnemonic(&mut host, mnemonic, &mut proven, &mut skipped);
    }
    print_l5(&proven, &skipped);
    if proven.is_empty() {
        assert!(
            skipped
                .iter()
                .any(|item| item.contains("AVX2") || item.contains("AVX")),
            "empty L5 proof needs the missing CPUID bit: {skipped:?}"
        );
    } else {
        assert!(proven.len() > 200, "proven {}", proven.len());
    }
}

#[test]
fn vex_upper_zeroing_matches_linux() {
    if let Some(reason) = crate::sse::claim::l5_skip_reason(Mnemonic::Vaddps) {
        assert!(
            reason.contains("AVX") || reason.contains("XCR0"),
            "{reason}"
        );
        return;
    }
    let mut host = Host::spawn("upper");
    legacy_keeps_upper(&mut host);
    vex_xmm_zeroes_upper(&mut host);
    vex_ymm_writes_upper(&mut host);
    vzeroupper_clears_high_half(&mut host);
    vzeroall_clears_ymm(&mut host);
}

fn sort_mnemonic(
    host: &mut Host,
    mnemonic: Mnemonic,
    proven: &mut Vec<String>,
    skipped: &mut Vec<String>,
) {
    let row = census::entry(mnemonic);
    if row.group != Group::L5Avx || row.status != Status::Lift {
        return;
    }
    match crate::sse::claim::l5_skip_reason(mnemonic) {
        Some(reason) => record_skip(mnemonic, &reason, row.proven, skipped),
        None => {
            assert!(row.proven, "{mnemonic:?} ran without a proven bit");
            prove(host, mnemonic);
            proven.push(format!("{mnemonic:?}"));
        }
    }
}

fn record_skip(mnemonic: Mnemonic, reason: &str, proven: bool, skipped: &mut Vec<String>) {
    assert!(!proven, "{mnemonic:?} is proven despite {reason}");
    assert!(!reason.is_empty(), "{mnemonic:?}");
    assert!(
        reason.contains("CPUID") || reason.contains("XCR0"),
        "{mnemonic:?}: {reason}"
    );
    skipped.push(format!("{mnemonic:?}: {reason}"));
}

fn prove(host: &mut Host, mnemonic: Mnemonic) {
    let mut reasons = Vec::new();
    for code in Code::values() {
        if !same_mnemonic(mnemonic, code) {
            continue;
        }
        let bytes = match encode_avx(code) {
            Ok(bytes) => bytes,
            Err(err) => {
                reasons.push(format!("{code:?} {err}"));
                continue;
            }
        };
        let case = l5_case(&bytes);
        if round(host, mnemonic, code, &case, &mut reasons) {
            return;
        }
    }
    panic!("{mnemonic:?}: {}", reasons.join(" | "));
}

fn round(
    host: &mut Host,
    mnemonic: Mnemonic,
    code: Code,
    case: &super::Case,
    reasons: &mut Vec<String>,
) -> bool {
    match host.roundtrip(case) {
        Err(err) => census_fault(host, mnemonic, code, case, &err, reasons),
        Ok(linux) => {
            agree(mnemonic, case, &linux);
            true
        }
    }
}

fn same_mnemonic(mnemonic: Mnemonic, code: Code) -> bool {
    code != Code::INVALID && code.mnemonic() == mnemonic && !code.is_privileged()
}

fn l5_case(bytes: &[u8]) -> super::Case {
    let mut case = fresh();
    paint(&mut case.sse);
    case.code = bytes.to_vec();
    tune_gather(&mut case);
    case
}

fn paint(sse: &mut Sse) {
    for (index, lane) in sse.upper.iter_mut().enumerate() {
        *lane = [0xA0 + index as u8; 16];
    }
}

fn tune_gather(case: &mut super::Case) {
    let mut decoder = Decoder::with_ip(64, &case.code, 0, DecoderOptions::NONE);
    let insn = decoder.decode();
    if !insn.is_vsib() {
        return;
    }
    write_index(&mut case.sse, insn.memory_index(), insn.is_vsib64());
    let mask = insn.op_register(2);
    let ones = [0xFFu8; 32];
    super::super::write_vector(&mut case.sse, mask, &ones[..mask.size()]);
}

fn write_index(sse: &mut Sse, index: Register, qword: bool) {
    let width = if qword { 8 } else { 4 };
    let mut raw = [0u8; 32];
    let slots = index.size() / width.max(1);
    for slot in 0..slots {
        let at = slot * width;
        let off = (slot as u64).wrapping_mul(8);
        raw[at..at + width].copy_from_slice(&off.to_le_bytes()[..width]);
    }
    super::super::write_vector(sse, index, &raw[..index.size()]);
}

fn print_l5(proven: &[String], skipped: &[String]) {
    println!("L5 proven {}:", proven.len());
    for item in proven {
        println!("  {item}");
    }
    println!("L5 skipped {}:", skipped.len());
    for item in skipped {
        println!("  {item}");
    }
}

fn legacy_keeps_upper(host: &mut Host) {
    let mut case = fresh();
    paint(&mut case.sse);
    case.sse.xmm[0] = xmm_ps([1.0, 2.0, 3.0, 4.0]);
    case.sse.xmm[1] = xmm_ps([5.0, 6.0, 7.0, 8.0]);
    case.code = regs2(Code::Addps_xmm_xmmm128, Register::XMM0, Register::XMM1);
    check(host, &case);
    let got = emulate(&case).expect("addps");
    assert_eq!(got.sse.upper[0], [0xA0; 16]);
    assert_eq!(&got.sse.xmm[0][0..4], &6.0f32.to_le_bytes());
}

fn vex_xmm_zeroes_upper(host: &mut Host) {
    let mut case = fresh();
    paint(&mut case.sse);
    case.sse.xmm[0] = xmm_ps([1.0, 2.0, 3.0, 4.0]);
    case.sse.xmm[1] = xmm_ps([5.0, 6.0, 7.0, 8.0]);
    case.code = regs3(
        Code::VEX_Vaddps_xmm_xmm_xmmm128,
        Register::XMM0,
        Register::XMM0,
        Register::XMM1,
    );
    check(host, &case);
    let got = emulate(&case).expect("vaddps xmm");
    assert_eq!(
        got.sse.upper[0], [0; 16],
        "vex xmm write zeroes bits 255:128"
    );
    assert_eq!(got.sse.upper[1], [0xA1; 16]);
    assert_eq!(got.sse.xmm[0], xmm_ps([6.0, 8.0, 10.0, 12.0]));
}

fn vex_ymm_writes_upper(host: &mut Host) {
    let mut case = fresh();
    paint(&mut case.sse);
    case.sse.xmm[0] = xmm_ps([1.0, 1.0, 1.0, 1.0]);
    case.sse.xmm[1] = xmm_ps([2.0, 2.0, 2.0, 2.0]);
    case.sse.upper[0] = xmm_ps([3.0, 3.0, 3.0, 3.0]);
    case.sse.upper[1] = xmm_ps([4.0, 4.0, 4.0, 4.0]);
    case.code = regs3(
        Code::VEX_Vaddps_ymm_ymm_ymmm256,
        Register::YMM0,
        Register::YMM0,
        Register::YMM1,
    );
    check(host, &case);
    let got = emulate(&case).expect("vaddps ymm");
    assert_eq!(got.sse.xmm[0], xmm_ps([3.0, 3.0, 3.0, 3.0]));
    assert_eq!(got.sse.upper[0], xmm_ps([7.0, 7.0, 7.0, 7.0]));
    assert_eq!(got.sse.upper[2], [0xA2; 16]);
}

fn vzeroupper_clears_high_half(host: &mut Host) {
    let mut case = fresh();
    paint(&mut case.sse);
    case.sse.xmm[3] = xmm_ps([9.0, 0.0, 0.0, 0.0]);
    case.code = build(Code::VEX_Vzeroupper, |_| {});
    check(host, &case);
    let got = emulate(&case).expect("vzeroupper");
    assert!(got.sse.upper.iter().all(|lane| *lane == [0; 16]));
    assert_eq!(got.sse.xmm[3], xmm_ps([9.0, 0.0, 0.0, 0.0]));
}

fn vzeroall_clears_ymm(host: &mut Host) {
    let mut case = fresh();
    paint(&mut case.sse);
    case.sse.xmm[1] = xmm_ps([9.0, 0.0, 0.0, 0.0]);
    case.code = build(Code::VEX_Vzeroall, |_| {});
    check(host, &case);
    let got = emulate(&case).expect("vzeroall");
    assert!(got.sse.xmm.iter().all(|lane| *lane == [0; 16]));
    assert!(got.sse.upper.iter().all(|lane| *lane == [0; 16]));
}

fn regs3(code: Code, a: Register, b: Register, c: Register) -> Vec<u8> {
    build(code, |insn| set3(insn, a, b, c))
}

fn set3(insn: &mut Instruction, a: Register, b: Register, c: Register) {
    insn.set_op0_kind(OpKind::Register);
    insn.set_op0_register(a);
    insn.set_op1_kind(OpKind::Register);
    insn.set_op1_register(b);
    insn.set_op2_kind(OpKind::Register);
    insn.set_op2_register(c);
}
