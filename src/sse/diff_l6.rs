//! System differential for AVX-512. A missing CPUID or XCR0 bit is a recorded
//! skip. Every ZMM register is compared as 64 raw bytes, and k0–k7 as a qword
//! each. `proven: true` is set only when this host can run the opcode.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use iced_x86::code_asm::{
    dword_ptr, eax, ecx, edi, qword_ptr, r12, r12d, r15, rax, rcx, rdx, rsi, rsp, CodeAssembler,
    CodeLabel,
};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use crate::ir::Sse;
use crate::isa::census::{self, Group, Status};

// Same guest data window as the L3 carrier so the emulator's page base matches.
const ENTRY: u64 = 0x400100;
const GUEST: u64 = 0x401000;
const DATA: u64 = 0x402000;
const SAVE: u64 = 0x403000;
const SCRATCH: u64 = 0x403200;
const XSTATE: u64 = 0x404000;
const ZMM_STATE: u64 = 0x404200;
const K_STATE: u64 = 0x404A00;
const STACK: u64 = 0x407f00;
const DATA_LEN: usize = 0x1000;
const XSTATE_LEN: usize = 512;
const ZMM_LEN: usize = 2048;
const K_LEN: usize = 64;
const MAX_CODE: usize = 64;
const RESULT: usize = 136 + XSTATE_LEN + ZMM_LEN + K_LEN + DATA_LEN;
const MAGIC: u64 = 0x99AA_BBCC_DDEE_FF01;

#[test]
fn every_l6_mnemonic_matches_linux_or_records_why_not() {
    let mut host = None;
    let mut proven = Vec::new();
    let mut skipped = Vec::new();
    for mnemonic in Mnemonic::values() {
        sort_mnemonic(&mut host, mnemonic, &mut proven, &mut skipped);
    }
    print_l6(&proven, &skipped);
    if proven.is_empty() {
        assert!(
            skipped.iter().any(|item| {
                item.contains("AVX512") || item.contains("AVX-512") || item.contains("XCR0")
            }),
            "empty L6 proof needs the missing CPUID bit: {skipped:?}"
        );
    } else {
        assert!(proven.len() > 40, "proven {}", proven.len());
    }
}

#[test]
fn merge_and_zeroing_match_linux_and_the_mask_model() {
    let old = lanes(1.0);
    let computed = lanes(3.0);
    let mask = 0b0101_0000_0000_0101u64;
    let merged = super::super::mask::apply(&old, &computed, mask, 4, false);
    let zeroed = super::super::mask::apply(&old, &computed, mask, 4, true);
    assert_eq!(merged[0..4], 3.0f32.to_le_bytes());
    assert_eq!(merged[4..8], 1.0f32.to_le_bytes());
    assert_eq!(zeroed[4..8], 0.0f32.to_le_bytes());
    if let Some(reason) = crate::sse::claim::l6_skip_reason(Mnemonic::Vaddps) {
        assert!(
            reason.contains("CPUID") || reason.contains("XCR0"),
            "{reason}"
        );
        return;
    }
    let mut host = L6Host::spawn("mask");
    check_mask(&mut host, false, &merged);
    check_mask(&mut host, true, &zeroed);
}

#[test]
fn high_zmm_is_distinct_from_the_low_bank() {
    if let Some(reason) = crate::sse::claim::l6_skip_reason(Mnemonic::Vmovdqu64) {
        assert!(
            reason.contains("CPUID") || reason.contains("XCR0"),
            "{reason}"
        );
        return;
    }
    let mut host = L6Host::spawn("zmm16");
    let mut case = l6_case(&movdqu16());
    let source = [0x22u8; 64];
    case.sse.xmm[1].copy_from_slice(&source[..16]);
    case.sse.upper[1].copy_from_slice(&source[16..32]);
    case.sse.zmm_hi256[1].copy_from_slice(&source[32..]);
    let kept = lane(&case.sse, 0);
    let linux = host.roundtrip(&case).expect("vmovdqu64");
    agree(Mnemonic::Vmovdqu64, &case, &linux);
    assert_eq!(lane(&linux.sse, 16), source);
    assert_eq!(lane(&linux.sse, 0), kept);
}

#[test]
fn legacy_sse_preserves_zmm_hi256_for_a_later_evex_read() {
    let Some(mut host) = l6_host("hi256") else {
        return;
    };
    preserved(&mut host, Code::Addps_xmm_xmmm128, Mnemonic::Addps);
    preserved(&mut host, Code::Xorps_xmm_xmmm128, Mnemonic::Xorps);
    preserved(&mut host, Code::Movss_xmm_xmmm32, Mnemonic::Movss);
}

#[test]
fn vex_writes_still_zero_zmm_hi256() {
    let Some(mut host) = l6_host("vexhi") else {
        return;
    };
    let xmm = vex3(
        Code::VEX_Vaddps_xmm_xmm_xmmm128,
        Register::XMM0,
        Register::XMM1,
    );
    let ymm = vex3(
        Code::VEX_Vaddps_ymm_ymm_ymmm256,
        Register::YMM0,
        Register::YMM1,
    );
    zeroed(&mut host, xmm, Mnemonic::Vaddps, true);
    zeroed(&mut host, ymm, Mnemonic::Vaddps, false);
    vzeroupper_zeroes_hi(&mut host);
}

#[test]
fn census_encodes_and_prefers_the_zmm_or_mask_form() {
    let zmm = operand_code(Mnemonic::Vmovdqu64, "zmm_or_mem");
    let encoded = super::encode_evex(zmm).expect("zmm_or_mem");
    let insn = crate::sse::decode(&encoded, 0).expect("zmm");
    assert!(
        insn.op0_register().is_zmm() || insn.op1_register().is_zmm(),
        "{zmm:?}"
    );
    let mask = operand_code(Mnemonic::Kmovw, "k_or_mem");
    let kbytes = super::encode_evex(mask).expect("k_or_mem");
    let kinsn = crate::sse::decode(&kbytes, 0).expect("k");
    assert_eq!(kinsn.mnemonic(), Mnemonic::Kmovw);
    assert!(kinsn.op0_register().is_k() || kinsn.op1_register().is_k());
    let chosen = proof_codes(Mnemonic::Vmovdqu64)
        .into_iter()
        .find(|code| super::encode_evex(*code).is_ok())
        .expect("vmovdqu64");
    assert_eq!(super::wide_rank(chosen), 0, "{chosen:?}");
}

fn l6_host(tag: &str) -> Option<L6Host> {
    if let Some(reason) = crate::sse::claim::l6_skip_reason(Mnemonic::Vaddps) {
        assert!(
            reason.contains("CPUID") || reason.contains("XCR0"),
            "{reason}"
        );
        return None;
    }
    Some(L6Host::spawn(tag))
}

fn preserved(host: &mut L6Host, code: Code, mnemonic: Mnemonic) {
    let op = super::regs2(code, Register::XMM0, Register::XMM1);
    let case = painted(chain(op));
    let linux = host.roundtrip(&case).expect("legacy");
    agree(mnemonic, &case, &linux);
    assert_eq!(
        &lane(&linux.sse, 0)[32..],
        &[0xC0; 32],
        "{mnemonic:?} zmm hi"
    );
    assert_eq!(
        &lane(&linux.sse, 0)[16..32],
        &[0xB0; 16],
        "{mnemonic:?} ymm hi"
    );
    assert_eq!(
        lane(&linux.sse, 2),
        lane(&linux.sse, 0),
        "{mnemonic:?} evex read"
    );
}

fn zeroed(host: &mut L6Host, op: Vec<u8>, mnemonic: Mnemonic, clear_ymm: bool) {
    let case = painted(chain(op));
    let linux = host.roundtrip(&case).expect("vex");
    agree(mnemonic, &case, &linux);
    assert_eq!(&lane(&linux.sse, 0)[32..], &[0; 32], "{mnemonic:?} zmm hi");
    assert_eq!(
        lane(&linux.sse, 2),
        lane(&linux.sse, 0),
        "{mnemonic:?} evex read"
    );
    assert_ne!(&lane(&linux.sse, 1)[32..], &[0; 32], "source hi stays");
    if clear_ymm {
        assert_eq!(&lane(&linux.sse, 0)[16..32], &[0; 16], "vex.128 ymm");
    }
}

fn vzeroupper_zeroes_hi(host: &mut L6Host) {
    let op = super::build(Code::VEX_Vzeroupper, |_| {});
    let mut case = l6_case(&chain(op));
    let xmm = super::xmm_ps([9.0, 0.0, 0.0, 0.0]);
    case.sse.xmm[0] = xmm;
    let linux = host.roundtrip(&case).expect("vzeroupper");
    agree(Mnemonic::Vzeroupper, &case, &linux);
    assert_eq!(&lane(&linux.sse, 0)[..16], &xmm);
    assert_eq!(&lane(&linux.sse, 0)[16..], &[0; 48]);
    assert_eq!(lane(&linux.sse, 16), [0xD0; 64]);
}

fn painted(code: Vec<u8>) -> super::Case {
    let mut case = l6_case(&code);
    case.sse.xmm[0] = super::xmm_ps([1.0, 2.0, 3.0, 4.0]);
    case.sse.xmm[1] = super::xmm_ps([5.0, 6.0, 7.0, 8.0]);
    case
}

fn chain(op: Vec<u8>) -> Vec<u8> {
    let mut code = op;
    code.extend(super::build(Code::EVEX_Vmovdqu64_zmm_k1z_zmmm512, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::ZMM2);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(Register::ZMM0);
    }));
    code
}

fn vex3(code: Code, dst: Register, src: Register) -> Vec<u8> {
    super::build(code, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(dst);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(dst);
        insn.set_op2_kind(OpKind::Register);
        insn.set_op2_register(src);
    })
}

fn operand_code(mnemonic: Mnemonic, kind: &str) -> Code {
    Code::values()
        .find(|code| code.mnemonic() == mnemonic && operand_is(*code, kind))
        .unwrap_or_else(|| panic!("{mnemonic:?} lacks {kind}"))
}

fn operand_is(code: Code, kind: &str) -> bool {
    let info = code.op_code();
    (0..info.op_count()).any(|index| format!("{:?}", info.op_kind(index)) == kind)
}

fn sort_mnemonic(
    host: &mut Option<L6Host>,
    mnemonic: Mnemonic,
    proven: &mut Vec<String>,
    skipped: &mut Vec<String>,
) {
    let row = census::entry(mnemonic);
    if row.group != Group::L6Avx512 || row.status != Status::Lift {
        return;
    }
    match crate::sse::claim::l6_skip_reason(mnemonic) {
        Some(reason) => record_skip(mnemonic, &reason, row.proven, skipped),
        None => {
            assert!(row.proven, "{mnemonic:?} ran without a proven bit");
            let host = host.get_or_insert_with(|| L6Host::spawn("l6"));
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

fn prove(host: &mut L6Host, mnemonic: Mnemonic) {
    let mut reasons = Vec::new();
    for code in proof_codes(mnemonic) {
        let bytes = match super::encode_evex(code) {
            Ok(bytes) => bytes,
            Err(err) => {
                reasons.push(format!("{code:?} {err}"));
                continue;
            }
        };
        let case = l6_case(&bytes);
        if round(host, mnemonic, code, &case, &mut reasons) {
            return;
        }
    }
    panic!("{mnemonic:?}: {}", reasons.join(" | "));
}

fn proof_codes(mnemonic: Mnemonic) -> Vec<Code> {
    let mut codes: Vec<Code> = Code::values()
        .filter(|code| same(mnemonic, *code) && !crate::sse::claim::feature_missing(*code))
        .collect();
    codes.sort_by_key(|code| super::wide_rank(*code));
    codes
}

fn round(
    host: &mut L6Host,
    mnemonic: Mnemonic,
    code: Code,
    case: &super::Case,
    reasons: &mut Vec<String>,
) -> bool {
    match host.roundtrip(case) {
        Err(err) => faulted(host, mnemonic, code, case, &err, reasons),
        Ok(linux) => {
            agree(mnemonic, case, &linux);
            true
        }
    }
}

fn faulted(
    host: &mut L6Host,
    mnemonic: Mnemonic,
    code: Code,
    case: &super::Case,
    err: &str,
    reasons: &mut Vec<String>,
) -> bool {
    let signal = super::signal_of(err);
    reasons.push(format!(
        "{code:?} sig={signal:?} {}",
        super::hex(&case.code)
    ));
    *host = L6Host::spawn("census");
    if matches!(signal, Some(4 | 7 | 8 | 11)) {
        let vm = super::emulate(case);
        let ir = super::emulate_ir(case);
        assert!(
            vm.is_err() && ir.is_err(),
            "{mnemonic:?} {code:?} retired after linux fault {err}"
        );
        return false;
    }
    panic!("{mnemonic:?} {code:?}: {err}");
}

fn same(mnemonic: Mnemonic, code: Code) -> bool {
    code != Code::INVALID
        && code.mnemonic() == mnemonic
        && !code.is_privileged()
        && code.op_code().is_available_in_mode(64)
        && !crate::isa::encoding_outside_user_x64(code)
}

fn l6_case(bytes: &[u8]) -> super::Case {
    let mut case = super::fresh();
    paint(&mut case.sse);
    case.code = bytes.to_vec();
    tune_vsib(&mut case);
    case
}

fn paint(sse: &mut Sse) {
    for (index, lane) in sse.upper.iter_mut().enumerate() {
        *lane = [0xB0 + index as u8; 16];
    }
    for (index, lane) in sse.zmm_hi256.iter_mut().enumerate() {
        *lane = [0xC0 + index as u8; 32];
    }
    for (index, lane) in sse.zmm_hi16.iter_mut().enumerate() {
        *lane = [0xD0 + index as u8; 64];
    }
    for (index, mask) in sse.opmask.iter_mut().enumerate() {
        *mask = 0x0101_0101_0101_0101u64.wrapping_mul(index as u64 + 1);
    }
}

fn tune_vsib(case: &mut super::Case) {
    let mut decoder = Decoder::with_ip(64, &case.code, 0, DecoderOptions::NONE);
    let insn = decoder.decode();
    if !insn.is_vsib() {
        return;
    }
    case.sse.opmask[1] = u64::MAX;
    let index = insn.memory_index();
    let width = if insn.is_vsib64() { 8 } else { 4 };
    let data = insn.memory_size().info().element_size().max(1);
    let mut raw = vec![0u8; index.size()];
    let slots = index.size() / width.max(1);
    for slot in 0..slots {
        let at = slot * width;
        let off = (slot as u64).wrapping_mul(data as u64);
        raw[at..at + width].copy_from_slice(&off.to_le_bytes()[..width]);
    }
    super::super::write_vector(&mut case.sse, index, &raw);
}

fn agree(mnemonic: Mnemonic, case: &super::Case, linux: &super::Observed) {
    let vm = super::emulate(case)
        .unwrap_or_else(|err| panic!("{mnemonic:?} emu {err}\n{}", super::hex(&case.code)));
    let ir = super::emulate_ir(case)
        .unwrap_or_else(|err| panic!("{mnemonic:?} ir {err}\n{}", super::hex(&case.code)));
    let text = format!("{mnemonic:?} {}", super::render(&case.code));
    assert_l6(&vm, linux, &text);
    assert_l6(&ir, linux, &text);
}

fn assert_l6(left: &super::Observed, right: &super::Observed, text: &str) {
    super::assert_same(left, right, text);
    for index in 0..32 {
        assert_eq!(
            lane(&left.sse, index),
            lane(&right.sse, index),
            "zmm{index} {text}"
        );
    }
    assert_eq!(left.sse.opmask, right.sse.opmask, "k0-k7 {text}");
}

fn lane(sse: &Sse, index: usize) -> [u8; 64] {
    let mut out = [0u8; 64];
    if index < 16 {
        out[..16].copy_from_slice(&sse.xmm[index]);
        out[16..32].copy_from_slice(&sse.upper[index]);
        out[32..].copy_from_slice(&sse.zmm_hi256[index]);
    } else {
        out = sse.zmm_hi16[index - 16];
    }
    out
}

fn check_mask(host: &mut L6Host, zeroing: bool, model: &[u8]) {
    let mut case = l6_case(&masked_add(zeroing));
    fill_ps(&mut case.sse, 0, 1.0);
    fill_ps(&mut case.sse, 1, 2.0);
    case.sse.opmask[1] = 0b0101_0000_0000_0101;
    let linux = host.roundtrip(&case).expect("masked vaddps");
    agree(Mnemonic::Vaddps, &case, &linux);
    assert_eq!(&lane(&linux.sse, 0)[..model.len()], model);
}

fn fill_ps(sse: &mut Sse, index: usize, value: f32) {
    let raw = lanes(value);
    sse.xmm[index].copy_from_slice(&raw[..16]);
    sse.upper[index].copy_from_slice(&raw[16..32]);
    sse.zmm_hi256[index].copy_from_slice(&raw[32..]);
}

fn lanes(value: f32) -> [u8; 64] {
    let mut out = [0u8; 64];
    let bytes = value.to_le_bytes();
    for lane in 0..16 {
        let at = lane * 4;
        out[at..at + 4].copy_from_slice(&bytes);
    }
    out
}

fn masked_add(zeroing: bool) -> Vec<u8> {
    super::build(Code::EVEX_Vaddps_zmm_k1z_zmm_zmmm512b32_er, |insn| {
        set_masked(insn, zeroing)
    })
}

fn set_masked(insn: &mut Instruction, zeroing: bool) {
    insn.set_op0_kind(OpKind::Register);
    insn.set_op0_register(Register::ZMM0);
    insn.set_op1_kind(OpKind::Register);
    insn.set_op1_register(Register::ZMM0);
    insn.set_op2_kind(OpKind::Register);
    insn.set_op2_register(Register::ZMM1);
    insn.set_op_mask(Register::K1);
    insn.set_zeroing_masking(zeroing);
}

fn movdqu16() -> Vec<u8> {
    super::build(Code::EVEX_Vmovdqu64_zmm_k1z_zmmm512, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::ZMM16);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(Register::ZMM1);
    })
}

fn print_l6(proven: &[String], skipped: &[String]) {
    println!("L6 proven {}:", proven.len());
    for item in proven {
        println!("  {item}");
    }
    println!("L6 skipped {}:", skipped.len());
    for item in skipped {
        println!("  {item}");
    }
}

struct L6Host {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
}

impl L6Host {
    fn spawn(tag: &str) -> Self {
        let path = carrier_path(tag);
        let bytes = harness_bytes();
        assert!(
            bytes.len() < (GUEST - ENTRY) as usize,
            "harness {} overlaps the guest slot",
            bytes.len()
        );
        std::fs::write(&path, super::elf_image(&bytes)).expect("write carrier");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let mut child = Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|err| panic!("spawn {}: {err}", path.display()));
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        Self {
            child: Some(child),
            stdin: Some(stdin),
            stdout,
        }
    }

    fn roundtrip(&mut self, case: &super::Case) -> std::result::Result<super::Observed, String> {
        if let Err(err) = self.send(case) {
            return Err(self.fail(err.to_string()));
        }
        let mut buf = vec![0u8; RESULT];
        if let Err(err) = super::read_full(&mut self.stdout, &mut buf) {
            return Err(self.fail(err.to_string()));
        }
        Ok(parse_l6(&buf))
    }

    fn send(&mut self, case: &super::Case) -> std::io::Result<()> {
        let stdin = self.stdin.as_mut().expect("stdin");
        let image = super::image_of(&case.x87, &case.sse);
        let len = u32::try_from(case.code.len()).expect("len");
        stdin.write_all(&len.to_le_bytes())?;
        stdin.write_all(&case.code)?;
        for reg in case.regs {
            stdin.write_all(&reg.to_le_bytes())?;
        }
        stdin.write_all(&case.rflags.to_le_bytes())?;
        stdin.write_all(&image)?;
        stdin.write_all(&super::super::zmm_image(&case.sse))?;
        stdin.write_all(&super::super::mask_image(&case.sse))?;
        stdin.write_all(&case.data)?;
        Ok(())
    }

    fn fail(&mut self, why: String) -> String {
        let status = self.child.take().map(|mut child| {
            let _ = child.kill();
            child.wait().ok()
        });
        let signal = status.as_ref().and_then(|item| item.as_ref()?.signal());
        format!("{why}; status={status:?}; signal={signal:?}")
    }
}

impl Drop for L6Host {
    fn drop(&mut self) {
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = stdin.write_all(&0u32.to_le_bytes());
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }
}

fn carrier_path(tag: &str) -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("l6-carrier-{tag}-{id}"));
    std::fs::create_dir_all(path.parent().expect("target")).expect("target dir");
    path
}

fn parse_l6(buf: &[u8]) -> super::Observed {
    let mut head = observed_head(buf);
    let zmm_at = 136 + XSTATE_LEN;
    let mut zmm = [0u8; ZMM_LEN];
    zmm.copy_from_slice(&buf[zmm_at..zmm_at + ZMM_LEN]);
    super::super::apply_zmm(&mut head.sse, &zmm);
    let k_at = zmm_at + ZMM_LEN;
    let mut masks = [0u8; K_LEN];
    masks.copy_from_slice(&buf[k_at..k_at + K_LEN]);
    super::super::apply_mask(&mut head.sse, &masks);
    head.data = buf[k_at + K_LEN..].to_vec();
    head
}

fn observed_head(buf: &[u8]) -> super::Observed {
    let mut regs = [0u64; 16];
    for (index, reg) in regs.iter_mut().enumerate() {
        let start = index * 8;
        let raw: [u8; 8] = buf[start..start + 8].try_into().expect("reg");
        *reg = u64::from_le_bytes(raw);
    }
    let flags = u64::from_le_bytes(buf[128..136].try_into().expect("flags"));
    let mut image = [0u8; 512];
    image.copy_from_slice(&buf[136..136 + XSTATE_LEN]);
    let mut x87 = crate::ir::X87::default();
    let mut sse = Sse::default();
    super::super::load_image(&mut x87, &mut sse, &image);
    super::Observed {
        regs,
        rflags: flags,
        x87,
        sse,
        data: Vec::new(),
    }
}

fn harness_bytes() -> Vec<u8> {
    let mut asm = CodeAssembler::new(64).expect("assembler");
    asm.set_prefer_short_branch(false);
    let mut top = asm.create_label();
    let mut read_exact = asm.create_label();
    let mut read_done = asm.create_label();
    let fail = asm.create_label();
    let mut done = asm.create_label();
    let mut epilogue = asm.create_label();
    load_inputs(&mut asm, &mut top, read_exact, fail, done);
    enter_guest(&mut asm, &mut epilogue);
    save_guest(&mut asm);
    report(&mut asm, top);
    io_loop(&mut asm, &mut read_exact, &mut read_done, fail, &mut done);
    finish(asm, &epilogue)
}

fn load_inputs(
    asm: &mut CodeAssembler,
    top: &mut CodeLabel,
    read_exact: CodeLabel,
    fail: CodeLabel,
    done: CodeLabel,
) {
    ok(asm.mov(rsp, STACK));
    ok(asm.set_label(top));
    ok(asm.mov(r15, SCRATCH));
    read_at(asm, read_exact, SCRATCH, 4);
    ok(asm.mov(eax, dword_ptr(r15)));
    ok(asm.test(eax, eax));
    ok(asm.jz(done));
    ok(asm.cmp(eax, MAX_CODE as i32));
    ok(asm.ja(fail));
    ok(asm.mov(r12d, eax));
    ok(asm.mov(rsi, GUEST));
    ok(asm.mov(rdx, r12));
    ok(asm.call(read_exact));
    read_at(asm, read_exact, SAVE, 128);
    read_at(asm, read_exact, SAVE + 128, 8);
    read_at(asm, read_exact, XSTATE, XSTATE_LEN as u64);
    read_at(asm, read_exact, ZMM_STATE, ZMM_LEN as u64);
    read_at(asm, read_exact, K_STATE, K_LEN as u64);
    read_at(asm, read_exact, DATA, DATA_LEN as u64);
}

fn read_at(asm: &mut CodeAssembler, read_exact: CodeLabel, addr: u64, len: u64) {
    if len == 0 {
        return;
    }
    ok(asm.mov(rsi, addr));
    ok(asm.mov(rdx, len));
    ok(asm.call(read_exact));
}

fn enter_guest(asm: &mut CodeAssembler, epilogue: &mut CodeLabel) {
    plant_jump(asm);
    ok(asm.mov(rsp, STACK));
    ok(asm.mov(rax, XSTATE));
    ok(asm.db(&[0x48, 0x0f, 0xae, 0x08]));
    ok(asm.mov(rax, ZMM_STATE));
    emit_zmm(asm, false, 0);
    ok(asm.mov(rax, K_STATE));
    emit_k(asm, false, 0);
    ok(asm.mov(r15, SAVE));
    ok(asm.mov(rax, qword_ptr(r15 + 128i32)));
    ok(asm.push(rax));
    ok(asm.popfq());
    load_gprs(asm);
    ok(asm.jmp(GUEST));
    ok(asm.set_label(epilogue));
}

fn plant_jump(asm: &mut CodeAssembler) {
    ok(asm.mov(rax, GUEST));
    ok(asm.add(rax, r12));
    ok(asm.db(&[0xC6, 0x00, 0xE9]));
    ok(asm.mov(rcx, MAGIC));
    ok(asm.lea(rdx, qword_ptr(rax + 5i32)));
    ok(asm.sub(rcx, rdx));
    ok(asm.mov(dword_ptr(rax + 1i32), ecx));
}

fn load_gprs(asm: &mut CodeAssembler) {
    use iced_x86::code_asm::{r10, r11, r13, r14, r8, r9, rax, rbp, rbx, rcx, rdi, rdx, rsi};
    let regs = [
        rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    ];
    for (index, reg) in regs.into_iter().enumerate() {
        if index == 4 || index == 15 {
            continue;
        }
        ok(asm.mov(reg, qword_ptr(r15 + (index * 8) as i32)));
    }
    ok(asm.mov(rsp, qword_ptr(r15 + 32i32)));
    ok(asm.mov(r15, qword_ptr(r15 + 120i32)));
}

fn save_guest(asm: &mut CodeAssembler) {
    ok(asm.db(&[0xA6; 7]));
    ok(asm.mov(r15, ZMM_STATE));
    emit_zmm(asm, true, 15);
    ok(asm.mov(r15, K_STATE));
    emit_k(asm, true, 15);
    ok(asm.mov(r15, XSTATE));
    ok(asm.db(&[0x49, 0x0f, 0xae, 0x07]));
    ok(asm.mov(r15, SAVE));
    store_gprs(asm);
    ok(asm.db(&[0xA7; 7]));
    ok(asm.mov(qword_ptr(r15 + 120i32), rax));
    ok(asm.mov(rax, rsp));
    ok(asm.mov(qword_ptr(r15 + 32i32), rax));
}

fn store_gprs(asm: &mut CodeAssembler) {
    use iced_x86::code_asm::{r10, r11, r13, r14, r8, r9, rax, rbp, rbx, rcx, rdi, rdx, rsi};
    let regs = [
        rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    ];
    for (index, reg) in regs.into_iter().enumerate() {
        if index == 4 || index == 15 {
            continue;
        }
        ok(asm.mov(qword_ptr(r15 + (index * 8) as i32), reg));
    }
}

fn report(asm: &mut CodeAssembler, top: CodeLabel) {
    ok(asm.mov(rsp, STACK));
    ok(asm.pushfq());
    ok(asm.pop(rax));
    ok(asm.mov(qword_ptr(r15 + 128i32), rax));
    write_out(asm, SAVE, 136);
    write_out(asm, XSTATE, XSTATE_LEN as u64);
    write_out(asm, ZMM_STATE, ZMM_LEN as u64);
    write_out(asm, K_STATE, K_LEN as u64);
    write_out(asm, DATA, DATA_LEN as u64);
    ok(asm.jmp(top));
}

fn write_out(asm: &mut CodeAssembler, buf: u64, len: u64) {
    ok(asm.mov(eax, 1i32));
    ok(asm.mov(edi, 1i32));
    ok(asm.mov(rsi, buf));
    ok(asm.mov(rdx, len));
    ok(asm.syscall());
}

fn emit_zmm(asm: &mut CodeAssembler, store: bool, base: usize) {
    for index in 0..32 {
        let mut bytes = Vec::new();
        super::super::evex::append_zmm(&mut bytes, store, index, base, (index as u32) * 64)
            .expect("zmm move");
        ok(asm.db(&bytes));
    }
}

fn emit_k(asm: &mut CodeAssembler, store: bool, base: usize) {
    for index in 0..8 {
        let mut bytes = Vec::new();
        super::super::evex::append_k(&mut bytes, store, index, base, (index as u32) * 8)
            .expect("k move");
        ok(asm.db(&bytes));
    }
}

fn io_loop(
    asm: &mut CodeAssembler,
    read_exact: &mut CodeLabel,
    read_done: &mut CodeLabel,
    fail: CodeLabel,
    done: &mut CodeLabel,
) {
    ok(asm.set_label(read_exact));
    ok(asm.test(rdx, rdx));
    ok(asm.jz(*read_done));
    ok(asm.xor(eax, eax));
    ok(asm.xor(edi, edi));
    ok(asm.syscall());
    ok(asm.cmp(rax, 1i32));
    ok(asm.jl(fail));
    ok(asm.add(rsi, rax));
    ok(asm.sub(rdx, rax));
    ok(asm.jmp(*read_exact));
    ok(asm.set_label(read_done));
    ok(asm.ret());
    let mut fail = fail;
    ok(asm.set_label(&mut fail));
    ok(asm.mov(eax, 60i32));
    ok(asm.mov(edi, 3i32));
    ok(asm.syscall());
    ok(asm.set_label(done));
    ok(asm.mov(eax, 60i32));
    ok(asm.xor(edi, edi));
    ok(asm.syscall());
}

fn finish(mut asm: CodeAssembler, epilogue: &CodeLabel) -> Vec<u8> {
    use iced_x86::BlockEncoderOptions;
    let result = asm
        .assemble_options(ENTRY, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .expect("assemble harness");
    let epi = result.label_ip(epilogue).expect("epilogue");
    let mut code = result.inner.code_buffer;
    patch_magic(&mut code, epi);
    patch_rip(&mut code, &[0xA6; 7], 0x4C, 0x89, 0x3D);
    patch_rip(&mut code, &[0xA7; 7], 0x48, 0x8B, 0x05);
    code
}

fn patch_magic(code: &mut [u8], epi: u64) {
    let needle = MAGIC.to_le_bytes();
    let at = code
        .windows(8)
        .position(|window| window == needle)
        .expect("epilogue immediate");
    code[at..at + 8].copy_from_slice(&epi.to_le_bytes());
}

fn patch_rip(code: &mut [u8], marker: &[u8], rex: u8, opcode: u8, modrm: u8) {
    let at = code
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("scratch marker");
    let next = ENTRY + at as u64 + 7;
    let disp = i32::try_from(SCRATCH as i64 - next as i64).expect("scratch disp");
    code[at] = rex;
    code[at + 1] = opcode;
    code[at + 2] = modrm;
    code[at + 3..at + 7].copy_from_slice(&disp.to_le_bytes());
}

fn ok(result: std::result::Result<(), iced_x86::IcedError>) {
    result.expect("harness instruction");
}
