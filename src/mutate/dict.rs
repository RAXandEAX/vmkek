//! Dictionary of semantically equivalent instructions. Nothing here changes length.

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Instruction, MemoryOperand, Mnemonic, OpKind, Register,
};

struct Rule {
    /// Read by the emulator proof. Not part of the rewrite itself.
    #[cfg_attr(not(test), allow(dead_code))]
    name: &'static str,
    /// Algebra or flag note. Read by the emulator proof.
    #[cfg_attr(not(test), allow(dead_code))]
    anchor: &'static str,
    rewrite: fn(&Instruction, &[Instruction], usize) -> Option<Vec<u8>>,
}

const RULES: &[Rule] = &[
    Rule {
        name: "add_imm_to_lea",
        anchor: "add reg,imm = lea [reg+imm] when status flags are dead",
        rewrite: add_imm_to_lea,
    },
    Rule {
        name: "sub_imm_to_add",
        anchor: "a-b=a+(-b)",
        rewrite: sub_imm_to_add,
    },
    Rule {
        name: "mov_zero_to_xor",
        anchor: "mov reg,0 = xor reg,reg when status flags are dead",
        rewrite: mov_zero_to_xor,
    },
    Rule {
        name: "inc_to_add",
        anchor: "inc = add 1 when CF is dead; other modeled flags match",
        rewrite: inc_to_add,
    },
    Rule {
        name: "dec_to_sub",
        anchor: "dec = sub 1 when CF is dead; other modeled flags match",
        rewrite: dec_to_sub,
    },
    Rule {
        name: "mov_rr_reencode",
        anchor: "mov reg,reg direction swap writes no status flags",
        rewrite: mov_rr_reencode,
    },
    Rule {
        name: "xchg_rr_reencode",
        anchor: "xchg operand swap writes no status flags",
        rewrite: xchg_rr_reencode,
    },
    Rule {
        name: "add_self_to_shl",
        anchor: "a+b=(a^b)+2*(a&b)",
        rewrite: add_self_to_shl,
    },
];

/// Apply same-length dictionary rewrites whose flag preconditions hold.
///
/// `ip` is the address of `bytes`. A rule is skipped when the replacement
/// would change the instruction length or when a flag it clobbers is still
/// live on any path. Instructions that no rule accepts are copied unchanged.
#[must_use]
pub fn rewrite(bytes: &[u8], ip: u64) -> Vec<u8> {
    let insns = decode(bytes, ip);
    let mut out = bytes.to_vec();
    for (index, insn) in insns.iter().enumerate() {
        apply_at(&mut out, ip, &insns, index, insn);
    }
    out
}

fn decode(bytes: &[u8], ip: u64) -> Vec<Instruction> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let end = ip.saturating_add(bytes.len() as u64);
    let mut insns = Vec::new();
    while decoder.can_decode() && decoder.ip() < end {
        let insn = decoder.decode();
        if insn.is_invalid() {
            break;
        }
        insns.push(insn);
    }
    insns
}

fn apply_at(out: &mut [u8], base: u64, insns: &[Instruction], index: usize, insn: &Instruction) {
    let Some(at) = insn
        .ip()
        .checked_sub(base)
        .and_then(|off| usize::try_from(off).ok())
    else {
        return;
    };
    let Some(next) = match_rule(insn, insns, index) else {
        return;
    };
    let Some(end) = at.checked_add(next.len()) else {
        return;
    };
    if next.len() == insn.len() && end <= out.len() && next.as_slice() != &out[at..end] {
        out[at..end].copy_from_slice(&next);
    }
}

fn match_rule(insn: &Instruction, insns: &[Instruction], index: usize) -> Option<Vec<u8>> {
    RULES
        .iter()
        .find_map(|rule| (rule.rewrite)(insn, insns, index))
}

fn add_imm_to_lea(insn: &Instruction, insns: &[Instruction], index: usize) -> Option<Vec<u8>> {
    if insn.mnemonic() != Mnemonic::Add || !plain(insn) || !status_dead(insns, index) {
        return None;
    }
    let reg = gpr(insn, 0)?;
    let disp = signed_imm(insn, 1)?;
    try_lea(insn, reg, disp)
}

fn sub_imm_to_add(insn: &Instruction, insns: &[Instruction], index: usize) -> Option<Vec<u8>> {
    if insn.mnemonic() != Mnemonic::Sub || !plain(insn) || !status_dead(insns, index) {
        return None;
    }
    let reg = gpr(insn, 0)?;
    let value = signed_imm(insn, 1)?.wrapping_neg();
    accept_first(insn, &imm_candidates(reg, value, true))
}

fn mov_zero_to_xor(insn: &Instruction, insns: &[Instruction], index: usize) -> Option<Vec<u8>> {
    if insn.mnemonic() != Mnemonic::Mov || !plain(insn) || !status_dead(insns, index) {
        return None;
    }
    if !imm_zero(insn) {
        return None;
    }
    let reg = gpr(insn, 0)?;
    let code = xor_code(reg)?;
    let next = Instruction::with2(code, reg, reg).ok()?;
    same_len(insn, &next)
}

fn inc_to_add(insn: &Instruction, insns: &[Instruction], index: usize) -> Option<Vec<u8>> {
    widen(insn, insns, index, Mnemonic::Inc, true)
}

fn dec_to_sub(insn: &Instruction, insns: &[Instruction], index: usize) -> Option<Vec<u8>> {
    widen(insn, insns, index, Mnemonic::Dec, false)
}

fn widen(
    insn: &Instruction,
    insns: &[Instruction],
    index: usize,
    mnemonic: Mnemonic,
    add: bool,
) -> Option<Vec<u8>> {
    if insn.mnemonic() != mnemonic || !plain(insn) || insn.op_count() != 1 {
        return None;
    }
    if !carry_dead(insns, index) {
        return None;
    }
    let reg = gpr(insn, 0)?;
    accept_first(insn, &imm_candidates(reg, 1, add))
}

fn mov_rr_reencode(insn: &Instruction, _insns: &[Instruction], _index: usize) -> Option<Vec<u8>> {
    if insn.mnemonic() != Mnemonic::Mov || !plain(insn) || writes_status(insn) {
        return None;
    }
    let dest = gpr(insn, 0)?;
    let src = gpr(insn, 1)?;
    if dest.size() != src.size() {
        return None;
    }
    let code = alt_mov(insn.code())?;
    let next = Instruction::with2(code, dest, src).ok()?;
    if writes_status(&next) {
        return None;
    }
    same_len(insn, &next)
}

fn xchg_rr_reencode(insn: &Instruction, _insns: &[Instruction], _index: usize) -> Option<Vec<u8>> {
    if insn.mnemonic() != Mnemonic::Xchg || !plain(insn) || writes_status(insn) {
        return None;
    }
    let left = gpr(insn, 0)?;
    let right = gpr(insn, 1)?;
    let next = Instruction::with2(insn.code(), right, left).ok()?;
    if writes_status(&next) {
        return None;
    }
    same_len(insn, &next)
}

// S1 `add_xor_shl` at `a == b`: a+a = (a^a)+2*(a&a) = a<<1.
// SHL leaves AF undefined, so status flags still have to be dead.
fn add_self_to_shl(insn: &Instruction, insns: &[Instruction], index: usize) -> Option<Vec<u8>> {
    if insn.mnemonic() != Mnemonic::Add || !plain(insn) || !status_dead(insns, index) {
        return None;
    }
    let dest = gpr(insn, 0)?;
    let src = gpr(insn, 1)?;
    if dest != src {
        return None;
    }
    let code = shl_code(dest)?;
    let next = Instruction::with2(code, dest, 1i32).ok()?;
    same_len(insn, &next)
}

fn try_lea(origin: &Instruction, reg: Register, disp: i64) -> Option<Vec<u8>> {
    let code = lea_code(reg)?;
    let base = reg.full_register();
    for size in disp_sizes(disp) {
        let mem = MemoryOperand::with_base_displ_size(base, disp, size);
        let Ok(lea) = Instruction::with2(code, reg, mem) else {
            continue;
        };
        if let Some(bytes) = same_len(origin, &lea) {
            return Some(bytes);
        }
    }
    None
}

fn disp_sizes(disp: i64) -> Vec<u32> {
    let mut sizes = Vec::new();
    if i8::try_from(disp).is_ok() {
        sizes.push(1);
    }
    if i32::try_from(disp).is_ok() {
        sizes.push(4);
    }
    if disp == 0 {
        sizes.push(0);
    }
    sizes
}

fn imm_candidates(reg: Register, value: i64, add: bool) -> Vec<Instruction> {
    let mut out = Vec::new();
    if i8::try_from(value).is_ok() {
        push_imm8(&mut out, reg, value, add);
    }
    if i32::try_from(value).is_ok() {
        push_imm32(&mut out, reg, value, add);
    }
    out
}

fn push_imm8(out: &mut Vec<Instruction>, reg: Register, value: i64, add: bool) {
    let imm = value as i32;
    if reg == Register::AL {
        let code = if add {
            Code::Add_AL_imm8
        } else {
            Code::Sub_AL_imm8
        };
        push2(out, code, Register::AL, imm);
    }
    let Some(code) = rm_imm8(reg, add) else {
        return;
    };
    push2(out, code, reg, imm);
}

fn rm_imm8(reg: Register, add: bool) -> Option<Code> {
    Some(match (add, reg.size()) {
        (true, 8) => Code::Add_rm64_imm8,
        (true, 4) => Code::Add_rm32_imm8,
        (true, 2) => Code::Add_rm16_imm8,
        (true, 1) => Code::Add_rm8_imm8,
        (false, 8) => Code::Sub_rm64_imm8,
        (false, 4) => Code::Sub_rm32_imm8,
        (false, 2) => Code::Sub_rm16_imm8,
        (false, 1) => Code::Sub_rm8_imm8,
        _ => return None,
    })
}

fn push_imm32(out: &mut Vec<Instruction>, reg: Register, value: i64, add: bool) {
    let imm = value as i32;
    push_accumulator(out, reg, value, imm, add);
    let Some(code) = rm_imm32(reg, add) else {
        return;
    };
    push2(out, code, reg, imm);
}

fn push_accumulator(out: &mut Vec<Instruction>, reg: Register, value: i64, imm: i32, add: bool) {
    if let Some(code) = accumulator(reg, value, add) {
        push2(out, code, reg, imm);
    }
}

fn accumulator(reg: Register, value: i64, add: bool) -> Option<Code> {
    Some(match (add, reg) {
        (true, Register::RAX) => Code::Add_RAX_imm32,
        (true, Register::EAX) => Code::Add_EAX_imm32,
        (true, Register::AX) if i16::try_from(value).is_ok() => Code::Add_AX_imm16,
        (false, Register::RAX) => Code::Sub_RAX_imm32,
        (false, Register::EAX) => Code::Sub_EAX_imm32,
        (false, Register::AX) if i16::try_from(value).is_ok() => Code::Sub_AX_imm16,
        _ => return None,
    })
}

fn rm_imm32(reg: Register, add: bool) -> Option<Code> {
    Some(match (add, reg.size()) {
        (true, 8) => Code::Add_rm64_imm32,
        (true, 4) => Code::Add_rm32_imm32,
        (false, 8) => Code::Sub_rm64_imm32,
        (false, 4) => Code::Sub_rm32_imm32,
        _ => return None,
    })
}

fn accept_first(origin: &Instruction, cands: &[Instruction]) -> Option<Vec<u8>> {
    cands.iter().find_map(|cand| same_len(origin, cand))
}

fn same_len(origin: &Instruction, cand: &Instruction) -> Option<Vec<u8>> {
    let bytes = encode(cand, origin.ip())?;
    (bytes.len() == origin.len()).then_some(bytes)
}

fn encode(insn: &Instruction, ip: u64) -> Option<Vec<u8>> {
    let mut encoder = Encoder::new(64);
    let len = encoder.encode(insn, ip).ok()?;
    let bytes = encoder.take_buffer();
    if bytes.len() != len || len == 0 {
        return None;
    }
    let mut decoder = Decoder::with_ip(64, &bytes, ip, DecoderOptions::NONE);
    let back = decoder.decode();
    if back.is_invalid() || back.len() != bytes.len() {
        return None;
    }
    Some(bytes)
}

fn push2(out: &mut Vec<Instruction>, code: Code, reg: Register, imm: i32) {
    if let Ok(insn) = Instruction::with2(code, reg, imm) {
        out.push(insn);
    }
}

fn status_dead(insns: &[Instruction], index: usize) -> bool {
    super::flags_dead(insns, index, super::STATUS)
}

fn carry_dead(insns: &[Instruction], index: usize) -> bool {
    super::flags_dead(insns, index, iced_x86::RflagsBits::CF)
}

fn writes_status(insn: &Instruction) -> bool {
    insn.rflags_modified() & super::STATUS != 0
}

fn plain(insn: &Instruction) -> bool {
    !insn.has_lock_prefix() && !insn.has_rep_prefix() && !insn.has_repne_prefix()
}

fn gpr(insn: &Instruction, index: u32) -> Option<Register> {
    if insn.op_kind(index) != OpKind::Register {
        return None;
    }
    let reg = insn.op_register(index);
    reg.is_gpr().then_some(reg)
}

fn signed_imm(insn: &Instruction, index: u32) -> Option<i64> {
    Some(match insn.op_kind(index) {
        OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
            i64::from(insn.immediate8() as i8)
        }
        OpKind::Immediate16 => i64::from(insn.immediate16() as i16),
        OpKind::Immediate32 | OpKind::Immediate32to64 => i64::from(insn.immediate32() as i32),
        OpKind::Immediate64 => insn.immediate64() as i64,
        _ => return None,
    })
}

fn imm_zero(insn: &Instruction) -> bool {
    match insn.op1_kind() {
        OpKind::Immediate8
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64 => insn.immediate8() == 0,
        OpKind::Immediate16 => insn.immediate16() == 0,
        OpKind::Immediate32 | OpKind::Immediate32to64 => insn.immediate32() == 0,
        OpKind::Immediate64 => insn.immediate64() == 0,
        _ => false,
    }
}

fn lea_code(reg: Register) -> Option<Code> {
    Some(match reg.size() {
        8 => Code::Lea_r64_m,
        4 => Code::Lea_r32_m,
        _ => return None,
    })
}

fn xor_code(reg: Register) -> Option<Code> {
    Some(match reg.size() {
        8 => Code::Xor_rm64_r64,
        4 => Code::Xor_rm32_r32,
        2 => Code::Xor_rm16_r16,
        1 => Code::Xor_rm8_r8,
        _ => return None,
    })
}

fn shl_code(reg: Register) -> Option<Code> {
    Some(match reg.size() {
        8 => Code::Shl_rm64_1,
        4 => Code::Shl_rm32_1,
        2 => Code::Shl_rm16_1,
        1 => Code::Shl_rm8_1,
        _ => return None,
    })
}

fn alt_mov(code: Code) -> Option<Code> {
    Some(match code {
        Code::Mov_rm64_r64 => Code::Mov_r64_rm64,
        Code::Mov_r64_rm64 => Code::Mov_rm64_r64,
        Code::Mov_rm32_r32 => Code::Mov_r32_rm32,
        Code::Mov_r32_rm32 => Code::Mov_rm32_r32,
        Code::Mov_rm16_r16 => Code::Mov_r16_rm16,
        Code::Mov_r16_rm16 => Code::Mov_rm16_r16,
        Code::Mov_rm8_r8 => Code::Mov_r8_rm8,
        Code::Mov_r8_rm8 => Code::Mov_rm8_r8,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::Flags;

    const CODE: u64 = 0x40_0000;
    const VALUES: [u64; 8] = [
        0,
        1,
        0x7f,
        0x80,
        0xff,
        0x8000_0000,
        0x7fff_ffff_ffff_ffff,
        u64::MAX,
    ];
    const FLAG_GRID: [Flags; 4] = [
        Flags {
            cf: false,
            pf: false,
            zf: false,
            sf: false,
            of: false,
        },
        Flags {
            cf: true,
            pf: false,
            zf: false,
            sf: false,
            of: false,
        },
        Flags {
            cf: false,
            pf: true,
            zf: true,
            sf: true,
            of: true,
        },
        Flags {
            cf: true,
            pf: true,
            zf: false,
            sf: true,
            of: true,
        },
    ];

    struct State {
        regs: [u64; 16],
        flags: Flags,
        af: bool,
    }

    #[test]
    fn mutation_rules_match_the_emulator() {
        assert!(RULES.len() >= 6, "{}", RULES.len());
        for rule in RULES {
            prove(rule.name);
        }
        unchanged(&[0x90, 0xc3]);
        preserves_neighbors();
        prove_div_idiv_are_not_kills();
        prove_one_operand_mul_is_not_a_status_kill();
        prove_mul_still_kills_carry();
        prove_two_operand_imul_writes_status();
        prove_width_bounded_double_shift();
    }

    #[test]
    fn div_and_idiv_do_not_kill_status_flags() {
        prove_div_idiv_are_not_kills();
    }

    #[test]
    fn one_operand_mul_does_not_kill_status_flags() {
        prove_one_operand_mul_is_not_a_status_kill();
    }

    #[test]
    fn mul_carry_kill_still_rewrites_inc() {
        prove_mul_still_kills_carry();
    }

    #[test]
    fn two_operand_imul_still_writes_status() {
        prove_two_operand_imul_writes_status();
    }

    #[test]
    fn double_shift_count_must_fit_the_operand() {
        prove_width_bounded_double_shift();
    }

    #[test]
    fn jo_reaching_a_carry_consumer_is_not_rewritten() {
        // inc al; jo LBL; xor eax, eax; ret; LBL: jb CARRY; mov al, 2; ret; CARRY: mov al, 1; ret
        // `jo` does not read CF, but its taken path does. INC keeps CF; ADD writes it.
        let inc = [
            0xfe, 0xc0, 0x70, 0x03, 0x31, 0xc0, 0xc3, 0x72, 0x03, 0xb0, 0x02, 0xc3, 0xb0, 0x01,
            0xc3,
        ];
        let add = [
            0x04, 0x01, 0x70, 0x03, 0x31, 0xc0, 0xc3, 0x72, 0x03, 0xb0, 0x02, 0xc3, 0xb0, 0x01,
            0xc3,
        ];
        let flags = Flags {
            cf: true,
            ..Flags::default()
        };
        let mut regs = [0; 16];
        regs[0] = 0x7f;
        assert_ne!(
            exec(&inc, regs, flags).regs[0],
            exec(&add, regs, flags).regs[0],
            "add al, 1 drops CF that the taken path still reads"
        );
        unchanged(&inc);
    }

    #[test]
    fn jrcxz_reaching_a_carry_consumer_is_not_rewritten() {
        // add rax, 1; jrcxz LBL; xor ecx, ecx; ret; LBL: jb ...
        unchanged(&[
            0x48, 0x83, 0xc0, 0x01, 0xe3, 0x03, 0x31, 0xc9, 0xc3, 0x72, 0x00,
        ]);
    }

    #[test]
    fn loop_back_to_a_carry_consumer_is_not_rewritten() {
        // LBL: jc SKIP; inc al; loop LBL; SKIP: ret
        unchanged(&[0x72, 0x04, 0xfe, 0xc0, 0xe2, 0xfa, 0xc3]);
    }

    #[test]
    fn variable_shift_does_not_kill_a_live_flag() {
        let carry = Flags {
            cf: true,
            ..Flags::default()
        };
        let zero = Flags {
            zf: true,
            ..Flags::default()
        };
        // inc al; shl cl, cl; jb CARRY; mov al, 2; ret; CARRY: mov al, 1; ret
        // Count zero leaves CF untouched. INC keeps it; ADD clears it (2 vs 1).
        live_flag_blocks(
            &[
                0xfe, 0xc0, 0xd2, 0xe1, 0x72, 0x03, 0xb0, 0x02, 0xc3, 0xb0, 0x01, 0xc3,
            ],
            &[
                0x04, 0x01, 0xd2, 0xe1, 0x72, 0x03, 0xb0, 0x02, 0xc3, 0xb0, 0x01, 0xc3,
            ],
            carry,
            1,
            2,
        );
        // add rax, 1; shl rdx, cl; jnz SPLIT; mov al, 1; ret; SPLIT: mov al, 2; ret
        live_flag_blocks(
            &[
                0x48, 0x83, 0xc0, 0x01, 0x48, 0xd3, 0xe2, 0x75, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02,
                0xc3,
            ],
            &[
                0x48, 0x8d, 0x40, 0x01, 0x48, 0xd3, 0xe2, 0x75, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02,
                0xc3,
            ],
            zero,
            2,
            1,
        );
        // mov al, 0; shl cl, cl; jnz SPLIT; mov al, 1; ret; SPLIT: mov al, 2; ret
        live_flag_blocks(
            &[
                0xb0, 0x00, 0xd2, 0xe1, 0x75, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3,
            ],
            &[
                0x30, 0xc0, 0xd2, 0xe1, 0x75, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3,
            ],
            Flags::default(),
            2,
            1,
        );
    }

    #[test]
    fn rep_string_op_does_not_kill_a_live_flag() {
        let carry = Flags {
            cf: true,
            ..Flags::default()
        };
        // inc al; mov rcx, 0; repne scasb; jb CARRY; mov al, 2; ret; CARRY: mov al, 1; ret
        // RCX == 0 skips the body, so CF survives. ADD would drop it (2 vs 1).
        live_flag_blocks(
            &[
                0xfe, 0xc0, 0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0xf2, 0xae, 0x72, 0x03, 0xb0,
                0x02, 0xc3, 0xb0, 0x01, 0xc3,
            ],
            &[
                0x04, 0x01, 0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0xf2, 0xae, 0x72, 0x03, 0xb0,
                0x02, 0xc3, 0xb0, 0x01, 0xc3,
            ],
            carry,
            1,
            2,
        );
        // inc al; mov rcx, 0; repe cmpsb; jb CARRY; ...
        live_flag_blocks(
            &[
                0xfe, 0xc0, 0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0xf3, 0xa6, 0x72, 0x03, 0xb0,
                0x02, 0xc3, 0xb0, 0x01, 0xc3,
            ],
            &[
                0x04, 0x01, 0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0xf3, 0xa6, 0x72, 0x03, 0xb0,
                0x02, 0xc3, 0xb0, 0x01, 0xc3,
            ],
            carry,
            1,
            2,
        );
    }

    #[test]
    fn other_variable_counts_do_not_kill_flags() {
        let carry = Flags {
            cf: true,
            ..Flags::default()
        };
        let zero = Flags {
            zf: true,
            ..Flags::default()
        };
        // inc al; {shr,sar,rol,ror} cl, cl; jb CARRY; mov al, 2; ret; CARRY: mov al, 1; ret
        let carry_tail = [0x72, 0x03, 0xb0, 0x02, 0xc3, 0xb0, 0x01, 0xc3];
        for shift in [
            &[0xd2, 0xe9][..],
            &[0xd2, 0xf9][..],
            &[0xd2, 0xc1][..],
            &[0xd2, 0xc9][..],
        ] {
            live_flag_blocks(
                &counted(&[0xfe, 0xc0], &counted(shift, &carry_tail)),
                &counted(&[0x04, 0x01], &counted(shift, &carry_tail)),
                carry,
                1,
                2,
            );
        }
        // add rax, 1; {shld,shrd} rdx, rax, cl; jnz; mov al, 1; ret; SPLIT: mov al, 2; ret
        let tail = [0x75, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3];
        for shift in [&[0x48, 0x0f, 0xa5, 0xc2][..], &[0x48, 0x0f, 0xad, 0xc2][..]] {
            live_flag_blocks(
                &counted(&[0x48, 0x83, 0xc0, 0x01], &counted(shift, &tail)),
                &counted(&[0x48, 0x8d, 0x40, 0x01], &counted(shift, &tail)),
                zero,
                2,
                1,
            );
        }
    }

    #[test]
    fn fallthrough_out_of_fragment_keeps_flags_live() {
        // add rax, 1 — the stream continues past this window.
        unchanged(&[0x48, 0x83, 0xc0, 0x01]);
        // add rax, 1; nop — nop falls off the end.
        unchanged(&[0x48, 0x83, 0xc0, 0x01, 0x90]);
    }

    #[test]
    fn immediate_shift_and_return_still_end_a_flag() {
        // inc al; jnz +2; xor ecx, ecx; xor edx, edx; ret
        let branched = [0xfe, 0xc0, 0x75, 0x02, 0x31, 0xc9, 0x31, 0xd2, 0xc3];
        let branched_add = [0x04, 0x01, 0x75, 0x02, 0x31, 0xc9, 0x31, 0xd2, 0xc3];
        expect(&branched, &branched_add);
        grid(&branched, &branched_add, 0);
        // inc al; shl cl, 1; ret — implicit and imm8 counts are real writes.
        let one = [0xfe, 0xc0, 0xd0, 0xe1, 0xc3];
        let one_add = [0x04, 0x01, 0xd0, 0xe1, 0xc3];
        expect(&one, &one_add);
        grid(&one, &one_add, 0);
        let imm = [0xfe, 0xc0, 0xc0, 0xe1, 0x01, 0xc3];
        let imm_add = [0x04, 0x01, 0xc0, 0xe1, 0x01, 0xc3];
        expect(&imm, &imm_add);
        grid(&imm, &imm_add, 0);
        // add rax, 1; shl rdx, 1; ret
        let wide = [0x48, 0x83, 0xc0, 0x01, 0x48, 0xd1, 0xe2, 0xc3];
        let wide_lea = [0x48, 0x8d, 0x40, 0x01, 0x48, 0xd1, 0xe2, 0xc3];
        expect(&wide, &wide_lea);
        grid(&wide, &wide_lea, 0);
        // add rax, 1; ret — `ret` is an explicit path end.
        expect(
            &[0x48, 0x83, 0xc0, 0x01, 0xc3],
            &[0x48, 0x8d, 0x40, 0x01, 0xc3],
        );
    }

    #[test]
    fn immediate_double_shift_still_kills_flags() {
        // add rax, 1; shld rdx, rax, 1; ret — count is the third operand.
        let shld = [0x48, 0x83, 0xc0, 0x01, 0x48, 0x0f, 0xa4, 0xc2, 0x01, 0xc3];
        let shld_lea = [0x48, 0x8d, 0x40, 0x01, 0x48, 0x0f, 0xa4, 0xc2, 0x01, 0xc3];
        expect(&shld, &shld_lea);
        grid(&shld, &shld_lea, 0);
        // add rax, 1; shrd rdx, rax, 1; ret
        let shrd = [0x48, 0x83, 0xc0, 0x01, 0x48, 0x0f, 0xac, 0xc2, 0x01, 0xc3];
        let shrd_lea = [0x48, 0x8d, 0x40, 0x01, 0x48, 0x0f, 0xac, 0xc2, 0x01, 0xc3];
        expect(&shrd, &shrd_lea);
        grid(&shrd, &shrd_lea, 0);
    }

    #[test]
    fn flag_readers_still_block_rewrites() {
        // adc, sbb, rcl, rcr, cmovz, setz, lahf, pushfq.
        unchanged(&[0xfe, 0xc0, 0x10, 0xcb, 0xc3]);
        unchanged(&[0xfe, 0xc0, 0x18, 0xcb, 0xc3]);
        unchanged(&[0xfe, 0xc0, 0xd0, 0xd3, 0xc3]);
        unchanged(&[0xfe, 0xc0, 0xd0, 0xdb, 0xc3]);
        unchanged(&[0x48, 0x83, 0xc0, 0x01, 0x48, 0x0f, 0x44, 0xc1, 0xc3]);
        unchanged(&[0x48, 0x83, 0xc0, 0x01, 0x0f, 0x94, 0xc0, 0xc3]);
        unchanged(&[0xfe, 0xc0, 0x9f, 0xc3]);
        unchanged(&[0xfe, 0xc0, 0x9c, 0xc3]);
    }

    fn prove(name: &str) {
        match name {
            "add_imm_to_lea" => prove_add_imm_to_lea(),
            "sub_imm_to_add" => prove_sub_imm_to_add(),
            "mov_zero_to_xor" => prove_mov_zero_to_xor(),
            "inc_to_add" => prove_inc_to_add(),
            "dec_to_sub" => prove_dec_to_sub(),
            "mov_rr_reencode" => prove_mov_rr_reencode(),
            "xchg_rr_reencode" => prove_xchg_rr_reencode(),
            "add_self_to_shl" => prove_add_self_to_shl(),
            other => panic!("rule {other} has no emulator proof"),
        }
    }

    fn prove_add_imm_to_lea() {
        let before = [0x48, 0x83, 0xc0, 0x01, 0x31, 0xc9, 0xc3];
        let after = [0x48, 0x8d, 0x40, 0x01, 0x31, 0xc9, 0xc3];
        expect(&before, &after);
        grid(&before, &after, 0);
        let narrow = [0x83, 0xc0, 0x01, 0x31, 0xc9, 0xc3];
        let narrow_after = [0x8d, 0x40, 0x01, 0x31, 0xc9, 0xc3];
        expect(&narrow, &narrow_after);
        grid(&narrow, &narrow_after, 0);
        let wide = [0x49, 0x83, 0xc0, 0x01, 0x31, 0xc9, 0xc3];
        let wide_after = [0x4d, 0x8d, 0x40, 0x01, 0x31, 0xc9, 0xc3];
        expect(&wide, &wide_after);
        grid(&wide, &wide_after, 8);
        unchanged(&[0x48, 0x83, 0xc0, 0x01, 0x75, 0x00, 0xc3]);
        unchanged(&[0x48, 0x83, 0xc4, 0x01, 0xc3]);
    }

    fn prove_sub_imm_to_add() {
        let before = [0x48, 0x83, 0xe8, 0x01, 0x31, 0xc9, 0xc3];
        let after = [0x48, 0x83, 0xc0, 0xff, 0x31, 0xc9, 0xc3];
        expect(&before, &after);
        grid(&before, &after, 0);
        unchanged(&[0x48, 0x83, 0xe8, 0x01, 0x75, 0x00, 0xc3]);
        unchanged(&[0x48, 0x83, 0xe8, 0x80, 0xc3]);
        catalog_has(anchor("sub_imm_to_add"));
    }

    fn prove_mov_zero_to_xor() {
        let before = [0xb0, 0x00, 0x31, 0xc9, 0xc3];
        let after = [0x30, 0xc0, 0x31, 0xc9, 0xc3];
        expect(&before, &after);
        grid(&before, &after, 0);
        unchanged(&[0xb0, 0x00, 0x75, 0x00, 0xc3]);
        unchanged(&[0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3]);
    }

    fn prove_inc_to_add() {
        let before = [0xfe, 0xc0, 0x31, 0xc9, 0xc3];
        let after = [0x04, 0x01, 0x31, 0xc9, 0xc3];
        expect(&before, &after);
        grid(&before, &after, 0);
        let live = [0xfe, 0xc0, 0x75, 0x02, 0x31, 0xc9, 0x31, 0xd2, 0xc3];
        let live_after = [0x04, 0x01, 0x75, 0x02, 0x31, 0xc9, 0x31, 0xd2, 0xc3];
        expect(&live, &live_after);
        grid(&live, &live_after, 0);
        unchanged(&[0xfe, 0xc0, 0x72, 0x00, 0xc3]);
        unchanged(&[0xff, 0xc0, 0xc3]);
    }

    fn prove_dec_to_sub() {
        let before = [0xfe, 0xc8, 0x31, 0xc9, 0xc3];
        let after = [0x2c, 0x01, 0x31, 0xc9, 0xc3];
        expect(&before, &after);
        grid(&before, &after, 0);
        unchanged(&[0xfe, 0xc8, 0x72, 0x00, 0xc3]);
        unchanged(&[0xff, 0xc8, 0xc3]);
    }

    fn prove_mov_rr_reencode() {
        let before = [0x48, 0x89, 0xc8, 0xc3];
        let after = [0x48, 0x8b, 0xc1, 0xc3];
        expect(&before, &after);
        reg_grid(&before, &after, 1);
        let live = [0x48, 0x89, 0xc8, 0x75, 0x00, 0xc3];
        let live_after = [0x48, 0x8b, 0xc1, 0x75, 0x00, 0xc3];
        expect(&live, &live_after);
        reg_grid(&live, &live_after, 1);
        unchanged(&[0x67, 0x48, 0x89, 0xc8, 0xc3]);
    }

    fn prove_xchg_rr_reencode() {
        let before = [0x48, 0x87, 0xd1, 0xc3];
        let after = [0x48, 0x87, 0xca, 0xc3];
        expect(&before, &after);
        xchg_grid(&before, &after);
        let live = [0x48, 0x87, 0xd1, 0x75, 0x00, 0xc3];
        let live_after = [0x48, 0x87, 0xca, 0x75, 0x00, 0xc3];
        expect(&live, &live_after);
        xchg_grid(&live, &live_after);
        unchanged(&[0x48, 0x91, 0xc3]);
    }

    fn prove_add_self_to_shl() {
        let before = [0x48, 0x01, 0xc0, 0x31, 0xc9, 0xc3];
        let after = [0x48, 0xd1, 0xe0, 0x31, 0xc9, 0xc3];
        expect(&before, &after);
        grid(&before, &after, 0);
        unchanged(&[0x48, 0x01, 0xc0, 0x75, 0x00, 0xc3]);
        catalog_has(anchor("add_self_to_shl"));
        status_flags_match(&[0x48, 0x01, 0xc0, 0xc3], &[0x48, 0xd1, 0xe0, 0xc3], 0);
    }

    fn preserves_neighbors() {
        let before = [0x50, 0x48, 0x83, 0xc0, 0x01, 0x58, 0x31, 0xc9, 0xc3];
        let after = [0x50, 0x48, 0x8d, 0x40, 0x01, 0x58, 0x31, 0xc9, 0xc3];
        expect(&before, &after);
        grid(&before, &after, 0);
    }

    fn anchor(name: &str) -> &'static str {
        RULES
            .iter()
            .find(|rule| rule.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
            .anchor
    }

    fn catalog_has(text: &str) {
        assert!(
            crate::obf::identities::catalog()
                .iter()
                .any(|identity| identity.anchor == text),
            "{text}"
        );
    }

    fn expect(before: &[u8], after: &[u8]) {
        assert_eq!(rewrite(before, CODE), after);
        assert_eq!(before.len(), after.len());
    }

    fn unchanged(bytes: &[u8]) {
        assert_eq!(rewrite(bytes, CODE), bytes);
    }

    fn live_flag_blocks(
        kept: &[u8],
        clobber: &[u8],
        flags: Flags,
        kept_rax: u64,
        clobber_rax: u64,
    ) {
        diverge(kept, clobber, [0; 16], flags, kept_rax, clobber_rax);
    }

    fn diverge(
        kept: &[u8],
        clobber: &[u8],
        regs: [u64; 16],
        flags: Flags,
        kept_rax: u64,
        clobber_rax: u64,
    ) {
        assert_eq!(exec(kept, regs, flags).regs[0], kept_rax, "original");
        assert_eq!(exec(clobber, regs, flags).regs[0], clobber_rax, "rewritten");
        unchanged(kept);
    }

    fn prove_div_idiv_are_not_kills() {
        let tail = [0x75, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3];
        let regs = gpr3(u64::MAX, 1, 0);
        // add rax, 1; {div,idiv} rcx; jnz. Prior ZF survives (1 vs 2).
        for op in [[0x48, 0xf7, 0xf1], [0x48, 0xf7, 0xf9]] {
            let kept = counted(&[0x48, 0x83, 0xc0, 0x01], &counted(&op, &tail));
            let next = counted(&[0x48, 0x8d, 0x40, 0x01], &counted(&op, &tail));
            diverge(&kept, &next, regs, Flags::default(), 1, 2);
        }
        // inc al; div bl; jb. CF survives (1 vs 2).
        diverge(
            &[
                0xfe, 0xc0, 0xf6, 0xf3, 0x72, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3,
            ],
            &[
                0x04, 0x01, 0xf6, 0xf3, 0x72, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3,
            ],
            gpr3(0xff, 0, 1),
            Flags::default(),
            1,
            2,
        );
    }

    fn prove_one_operand_mul_is_not_a_status_kill() {
        let tail = [0x75, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3];
        let regs = gpr3(u64::MAX, 1, 0);
        // add rax, 1; {mul,imul} rcx; jnz. Only CF/OF are written (1 vs 2).
        for op in [[0x48, 0xf7, 0xe1], [0x48, 0xf7, 0xe9]] {
            let kept = counted(&[0x48, 0x83, 0xc0, 0x01], &counted(&op, &tail));
            let next = counted(&[0x48, 0x8d, 0x40, 0x01], &counted(&op, &tail));
            diverge(&kept, &next, regs, Flags::default(), 1, 2);
        }
        // mov al, 0; mul bl; jnz. ZF survives (2 vs 1).
        diverge(
            &[
                0xb0, 0x00, 0xf6, 0xe3, 0x75, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3,
            ],
            &[
                0x30, 0xc0, 0xf6, 0xe3, 0x75, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3,
            ],
            [0; 16],
            Flags::default(),
            2,
            1,
        );
    }

    fn prove_mul_still_kills_carry() {
        // inc al; mul bl; jb. CF is a real write, so inc → add matches.
        let before = [
            0xfe, 0xc0, 0xf6, 0xe3, 0x72, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3,
        ];
        let after = [
            0x04, 0x01, 0xf6, 0xe3, 0x72, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3,
        ];
        expect(&before, &after);
        for flags in FLAG_GRID {
            for al in [0, 1, 0x7f, 0xff] {
                same(&before, &after, gpr3(al, 0, 1), flags);
            }
        }
    }

    fn prove_two_operand_imul_writes_status() {
        // add rax, 1; imul rdx, rcx; jnz. 0F AF stores logic flags, unlike F7 /5.
        let before = counted(
            &[0x48, 0x83, 0xc0, 0x01, 0x48, 0x0f, 0xaf, 0xd1],
            &[0x75, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3],
        );
        let after = lea_head(&before);
        expect(&before, &after);
        for flags in FLAG_GRID {
            for rdx in [0, 1, 5, u64::MAX] {
                let mut regs = gpr3(u64::MAX, 3, 0);
                regs[2] = rdx;
                same(&before, &after, regs, flags);
            }
        }
    }

    fn prove_width_bounded_double_shift() {
        // RAX=MAX, RCX=0x1234, RBX=0xab, ZF=0.
        let regs = gpr3(u64::MAX, 0x1234, 0xab);
        decline_shift(0xa4, 0x11, regs);
        decline_shift(0xac, 0x14, regs);
        decline_shift(0xa4, 0x20, regs);
        accept_shift(0xa4, 0x10, regs);
        accept_shift(0xac, 0x10, regs);
    }

    fn decline_shift(opcode: u8, count: u8, regs: [u64; 16]) {
        let kept = double_shift(opcode, count);
        diverge(&kept, &lea_head(&kept), regs, Flags::default(), 1, 2);
    }

    fn accept_shift(opcode: u8, count: u8, regs: [u64; 16]) {
        let before = double_shift(opcode, count);
        let after = lea_head(&before);
        expect(&before, &after);
        for flags in FLAG_GRID {
            same(&before, &after, regs, flags);
        }
    }

    fn double_shift(opcode: u8, count: u8) -> Vec<u8> {
        let head = [0x48, 0x83, 0xc0, 0x01, 0x66, 0x0f, opcode, 0xcb, count];
        counted(&head, &[0x75, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x02, 0xc3])
    }

    fn lea_head(bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        out[..4].copy_from_slice(&[0x48, 0x8d, 0x40, 0x01]);
        out
    }

    fn gpr3(rax: u64, rcx: u64, rbx: u64) -> [u64; 16] {
        let mut regs = [0; 16];
        regs[0] = rax;
        regs[1] = rcx;
        regs[3] = rbx;
        regs
    }

    fn counted(head: &[u8], tail: &[u8]) -> Vec<u8> {
        let mut out = head.to_vec();
        out.extend(tail);
        out
    }

    fn grid(before: &[u8], after: &[u8], slot: usize) {
        for flags in FLAG_GRID {
            for value in VALUES {
                let mut regs = [0x1111_2222_3333_4444; 16];
                regs[slot] = value;
                same(before, after, regs, flags);
            }
        }
    }

    fn reg_grid(before: &[u8], after: &[u8], slot: usize) {
        for flags in FLAG_GRID {
            for value in VALUES {
                let mut regs = [0x2222_3333_4444_5555; 16];
                regs[slot] = value;
                same(before, after, regs, flags);
            }
        }
    }

    fn xchg_grid(before: &[u8], after: &[u8]) {
        for flags in FLAG_GRID {
            for value in VALUES {
                let mut regs = [0; 16];
                regs[1] = value;
                regs[2] = value ^ 0x5a5a_5a5a_5a5a_5a5a;
                same(before, after, regs, flags);
            }
        }
    }

    fn status_flags_match(before: &[u8], after: &[u8], slot: usize) {
        for flags in FLAG_GRID {
            for value in VALUES {
                let mut regs = [0; 16];
                regs[slot] = value;
                let left = exec(before, regs, flags);
                let right = exec(after, regs, flags);
                assert_eq!(left.regs, right.regs, "{value:#x}");
                assert_eq!(left.flags, right.flags, "{value:#x} {flags:?}");
            }
        }
    }

    fn same(before: &[u8], after: &[u8], regs: [u64; 16], flags: Flags) {
        let left = exec(before, regs, flags);
        let right = exec(after, regs, flags);
        assert_eq!(left.regs, right.regs, "{flags:?} {regs:x?}");
        assert_eq!(left.flags, right.flags, "{flags:?} rax={:#x}", regs[0]);
        assert_eq!(left.af, right.af, "{flags:?}");
    }

    fn exec(code: &[u8], regs: [u64; 16], flags: Flags) -> State {
        let mut machine = crate::emu::bare(crate::emu::Policy::default()).expect("machine");
        let rsp = machine.regs[4];
        let mut data = code.to_vec();
        // `Vec::resize` truncates, so a fragment longer than the pad must be kept whole.
        data.resize(data.len().max(16), 0xcc);
        machine
            .regions
            .push(crate::emu::Region { base: CODE, data });
        machine.rip = CODE;
        machine.regs = regs;
        machine.regs[4] = rsp;
        machine.flags = flags;
        machine.af = true;
        machine.run().expect("fragment");
        State {
            regs: machine.regs,
            flags: machine.flags,
            af: machine.af,
        }
    }
}
