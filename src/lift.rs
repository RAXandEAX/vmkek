use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, Register,
};

use crate::error::{msg, Result};
use crate::ir::{Address, Exit, FuncIr, Op, Program, XBlock, ARCH};

#[path = "lift_l1.rs"]
mod l1;
#[path = "lift_l2.rs"]
mod l2;
#[path = "lift_l3.rs"]
mod l3;

pub fn lift(name: &str, bytes: &[u8], rva: u32, size: u32, image_base: u64) -> Result<FuncIr> {
    program(name, bytes, rva, size, image_base)?.into_integer()
}

/// Lift `bytes` into a program that may mix integer ops with the x87 stack and SSE.
///
/// Integer instructions match [`lift`]. x87 instructions stay on the 80-bit
/// stack. SSE through AVX2, including VEX.128 and VEX.256, are lifted by
/// `l3::encode` and stay on the YMM file. `rva` is the function's offset from
/// `image_base`.
pub fn program(name: &str, bytes: &[u8], rva: u32, size: u32, image_base: u64) -> Result<Program> {
    let start = image_base + u64::from(rva);
    let code = bytes
        .get(..size as usize)
        .ok_or_else(|| msg(format!("{name} is outside its section")))?;
    let mut decoder = Decoder::with_ip(64, code, start, DecoderOptions::NONE);
    let mut insns = Vec::new();
    let end = start + u64::from(size);
    while decoder.can_decode() && decoder.ip() < end {
        let insn = decoder.decode();
        if insn.is_invalid() {
            return Err(msg(format!("{name} contains an invalid instruction")));
        }
        insns.push(insn);
    }
    if insns.is_empty() {
        return Err(msg(format!("{name} is empty")));
    }
    let mut leaders = vec![0usize];
    for (index, insn) in insns.iter().enumerate() {
        if (insn.mnemonic().jcc_short_or_near()
            || matches!(
                insn.mnemonic(),
                Mnemonic::Jmp | Mnemonic::Call | Mnemonic::Ret
            ))
            && index + 1 < insns.len()
        {
            leaders.push(index + 1);
        }
        if let Some(target) = branch_target(insn) {
            if let Some(found) = insns.iter().position(|item| item.ip() == target) {
                leaders.push(found);
            }
        }
    }
    leaders.sort_unstable();
    leaders.dedup();
    let mut block_of = vec![0u32; insns.len()];
    for (ordinal, leader) in leaders.iter().enumerate() {
        let stop = leaders.get(ordinal + 1).copied().unwrap_or(insns.len());
        for slot in &mut block_of[*leader..stop] {
            *slot = ordinal as u32;
        }
    }
    let mut blocks = (0..leaders.len())
        .map(|_| XBlock {
            ops: Vec::new(),
            exit: Exit::Ret,
            opaque: false,
        })
        .collect::<Vec<_>>();
    for (ordinal, leader) in leaders.iter().enumerate() {
        let stop = leaders.get(ordinal + 1).copied().unwrap_or(insns.len());
        let mut cursor = l1::Cursor::new(&mut blocks, ordinal as u32);
        let last = stop - 1;
        for insn in &insns[*leader..last] {
            emit(&mut cursor, insn, image_base)?;
        }
        let exit = if is_control(&insns[last]) {
            let mut extra = Vec::new();
            let exit = lift_exit(&insns[last], &insns, &block_of, image_base, &mut extra)?;
            cursor.extend(extra);
            exit
        } else {
            emit(&mut cursor, &insns[last], image_base)?;
            let next = insns
                .iter()
                .position(|item| item.ip() == insns[last].next_ip())
                .map(|index| block_of[index]);
            match next {
                Some(block) => Exit::Jmp(block),
                None => Exit::Ret,
            }
        };
        cursor.seal(exit);
    }
    Ok(Program {
        name: name.into(),
        rva,
        blocks,
        entry: 0,
    })
}

fn lift_exit(
    insn: &Instruction,
    insns: &[Instruction],
    block_of: &[u32],
    image_base: u64,
    ops: &mut Vec<Op>,
) -> Result<Exit> {
    let local = |target: u64| {
        insns
            .iter()
            .position(|item| item.ip() == target)
            .map(|index| block_of[index])
    };
    if insn.mnemonic().jcc_short_or_near() {
        let cond = jcc(insn.mnemonic()).ok_or_else(|| bad(insn))?;
        let yes = local(insn.near_branch_target()).ok_or_else(|| msg("jcc leaves the function"))?;
        let no = local(insn.next_ip()).ok_or_else(|| msg("jcc fallthrough missing"))?;
        return Ok(Exit::Jcc(cond, yes, no));
    }
    match insn.mnemonic() {
        Mnemonic::Jmp => {
            let target =
                local(insn.near_branch_target()).ok_or_else(|| msg("jump leaves the function"))?;
            Ok(Exit::Jmp(target))
        }
        Mnemonic::Call => {
            let next = local(insn.next_ip()).ok_or_else(|| msg("call fallthrough missing"))?;
            if insn.op0_kind() == OpKind::Register {
                Ok(Exit::CallAbs {
                    reg: gpr64(insn, insn.op_register(0))?,
                    next,
                })
            } else if insn.op0_kind() == OpKind::Memory {
                let tmp = mem_into(insn, image_base, ops)?;
                ops.push(Op::Load64(tmp, tmp));
                Ok(Exit::CallAbs { reg: tmp, next })
            } else {
                let target = insn.near_branch_target();
                if local(target).is_some() {
                    return Err(msg("internal calls are represented as rvas"));
                }
                let rva = target
                    .checked_sub(image_base)
                    .and_then(|offset| u32::try_from(offset).ok())
                    .ok_or_else(|| msg("call target outside the image"))?;
                Ok(Exit::CallRva { rva, next })
            }
        }
        Mnemonic::Ret => Ok(Exit::Ret),
        _ => {
            ops.extend(lift_ops(insn, image_base)?);
            let next = local(insn.next_ip());
            Ok(match next {
                Some(block) => Exit::Jmp(block),
                None => Exit::Ret,
            })
        }
    }
}

fn lift_ops(insn: &Instruction, image_base: u64) -> Result<Vec<Op>> {
    let reg0 = || gpr64(insn, insn.op_register(0));
    let reg1 = || gpr64(insn, insn.op_register(1));
    let mut out = Vec::new();
    let op = match insn.mnemonic() {
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Lea => lift_data(insn, image_base, &mut out)?,
        Mnemonic::Add => alu(insn, true)?,
        Mnemonic::Sub => alu(insn, false)?,
        Mnemonic::Xor => logic(insn, 0)?,
        Mnemonic::And => logic(insn, 1)?,
        Mnemonic::Or => logic(insn, 2)?,
        Mnemonic::Cmp => cmp(insn)?,
        Mnemonic::Test => test(insn)?,
        Mnemonic::Inc => Op::Inc(reg0()?),
        Mnemonic::Dec => Op::Dec(reg0()?),
        Mnemonic::Not => Op::Not(reg0()?),
        Mnemonic::Neg => Op::Neg(reg0()?),
        Mnemonic::Shl | Mnemonic::Shr if is_imm(insn.op1_kind()) => {
            let dst = reg0()?;
            let count = imm64(insn, 1) as u8;
            if insn.mnemonic() == Mnemonic::Shl {
                Op::Shl(dst, count)
            } else {
                Op::Shr(dst, count)
            }
        }
        Mnemonic::Imul if insn.op_count() == 3 && insn.op1_kind() == OpKind::Register => {
            let dest = reg0()?;
            let source = reg1()?;
            if dest != source {
                out.push(Op::MovRr(dest, source));
            }
            Op::ImulRi(dest, imm64(insn, 2) as i32)
        }
        Mnemonic::Imul if insn.op_count() == 2 && insn.op1_kind() == OpKind::Register => {
            Op::ImulRr(reg0()?, reg1()?)
        }
        Mnemonic::Imul if insn.op_count() == 2 && is_imm(insn.op1_kind()) => {
            Op::ImulRi(reg0()?, imm64(insn, 1) as i32)
        }
        Mnemonic::Div => Op::Div(reg0()?),
        Mnemonic::Push => Op::Push(reg0()?),
        Mnemonic::Pop => Op::Pop(reg0()?),
        Mnemonic::Nop => Op::MovRr(0, 0),
        _ => return Err(bad(insn)),
    };
    out.push(op);
    Ok(out)
}

fn lift_data(insn: &Instruction, image_base: u64, out: &mut Vec<Op>) -> Result<Op> {
    let reg0 = || gpr64(insn, insn.op_register(0));
    let reg1 = || gpr64(insn, insn.op_register(1));
    match insn.mnemonic() {
        Mnemonic::Mov
            if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Register =>
        {
            Ok(Op::MovRr(reg0()?, reg1()?))
        }
        Mnemonic::Movzx
            if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Register =>
        {
            Err(bad(insn))
        }
        Mnemonic::Mov if insn.op0_kind() == OpKind::Register && is_imm(insn.op1_kind()) => {
            Ok(Op::MovRi(reg0()?, imm64(insn, 1)))
        }
        Mnemonic::Movzx | Mnemonic::Mov | Mnemonic::Lea => lift_memory(insn, image_base, out),
        _ => Err(bad(insn)),
    }
}

fn lift_memory(insn: &Instruction, image_base: u64, out: &mut Vec<Op>) -> Result<Op> {
    let reg0 = || gpr64(insn, insn.op_register(0));
    let reg1 = || gpr64(insn, insn.op_register(1));
    match insn.mnemonic() {
        Mnemonic::Movzx if insn.op1_kind() == OpKind::Memory => {
            if insn.memory_size().size() != 1 {
                return Err(bad(insn));
            }
            let addr = mem_into(insn, image_base, out)?;
            Ok(Op::Load8(reg0()?, addr))
        }
        Mnemonic::Mov
            if insn.op0_kind() == OpKind::Memory && insn.op1_kind() == OpKind::Register =>
        {
            let addr = mem_into(insn, image_base, out)?;
            match insn.memory_size().size() {
                1 => Ok(Op::Store8(addr, gpr8(insn, insn.op_register(1))?)),
                8 => Ok(Op::Store64(addr, reg1()?)),
                _ => Err(bad(insn)),
            }
        }
        Mnemonic::Mov if insn.op0_kind() == OpKind::Memory && is_imm(insn.op1_kind()) => {
            let addr = mem_into(insn, image_base, out)?;
            out.push(Op::MovRi(29, imm64(insn, 1)));
            match insn.memory_size().size() {
                1 => Ok(Op::Store8(addr, 29)),
                8 => Ok(Op::Store64(addr, 29)),
                _ => Err(bad(insn)),
            }
        }
        Mnemonic::Mov
            if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Memory =>
        {
            let addr = mem_into(insn, image_base, out)?;
            if insn.memory_size().size() == 8 {
                Ok(Op::Load64(reg0()?, addr))
            } else {
                Err(bad(insn))
            }
        }
        Mnemonic::Lea => Ok(Op::Lea(reg0()?, address_of(insn, image_base)?)),
        _ => Err(bad(insn)),
    }
}

/// Materialize a direct native call target without altering guest ABI registers.
pub(crate) fn native_call_address(ops: &mut Vec<Op>, rva: u32) -> u16 {
    ops.push(Op::Lea(l1::ADDR, Address::Rva(rva)));
    l1::ADDR
}

fn mem_into(insn: &Instruction, image_base: u64, out: &mut Vec<Op>) -> Result<u16> {
    out.push(Op::Lea(28, address_of(insn, image_base)?));
    Ok(28)
}

fn alu(insn: &Instruction, add: bool) -> Result<Op> {
    let dst = gpr64(insn, insn.op_register(0))?;
    if insn.op1_kind() == OpKind::Register {
        Ok(if add {
            Op::AddRr(dst, gpr64(insn, insn.op_register(1))?)
        } else {
            Op::SubRr(dst, gpr64(insn, insn.op_register(1))?)
        })
    } else if is_imm(insn.op1_kind()) {
        let imm = imm64(insn, 1) as i32;
        Ok(if add {
            Op::AddRi(dst, imm)
        } else {
            Op::SubRi(dst, imm)
        })
    } else {
        Err(bad(insn))
    }
}

fn logic(insn: &Instruction, kind: u8) -> Result<Op> {
    let dst = gpr64(insn, insn.op_register(0))?;
    if insn.op1_kind() == OpKind::Register {
        let src = gpr64(insn, insn.op_register(1))?;
        Ok(match kind {
            0 => Op::XorRr(dst, src),
            1 => Op::AndRr(dst, src),
            _ => Op::OrRr(dst, src),
        })
    } else if is_imm(insn.op1_kind()) {
        let imm = imm64(insn, 1) as i32;
        Ok(match kind {
            0 => Op::XorRi(dst, imm),
            1 => Op::AndRi(dst, imm),
            _ => Op::OrRi(dst, imm),
        })
    } else {
        Err(bad(insn))
    }
}

fn cmp(insn: &Instruction) -> Result<Op> {
    let dst = gpr64(insn, insn.op_register(0))?;
    if insn.op1_kind() == OpKind::Register {
        Ok(Op::CmpRr(dst, gpr64(insn, insn.op_register(1))?))
    } else if is_imm(insn.op1_kind()) {
        Ok(Op::CmpRi(dst, imm64(insn, 1) as i32))
    } else {
        Err(bad(insn))
    }
}

fn test(insn: &Instruction) -> Result<Op> {
    if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Register {
        Ok(Op::TestRr(
            gpr64(insn, insn.op_register(0))?,
            gpr64(insn, insn.op_register(1))?,
        ))
    } else if insn.op0_kind() == OpKind::Register && is_imm(insn.op1_kind()) {
        Ok(Op::TestRi(
            gpr64(insn, insn.op_register(0))?,
            imm64(insn, 1) as i32,
        ))
    } else {
        Err(bad(insn))
    }
}

pub(super) fn address_of(insn: &Instruction, image_base: u64) -> Result<Address> {
    if insn.is_ip_rel_memory_operand() {
        let target = insn.ip_rel_memory_address();
        let rva = u32::try_from(target.wrapping_sub(image_base)).map_err(|_| bad(insn))?;
        return Ok(Address::Rva(rva));
    }
    let base = insn.memory_base();
    let index_reg = insn.memory_index();
    let index = if index_reg == Register::None {
        None
    } else {
        Some(gpr64(insn, index_reg)?)
    };
    let scale = if index.is_some() {
        insn.memory_index_scale() as u8
    } else {
        1
    };
    let disp = insn.memory_displacement64() as i64;
    Ok(Address::Sib {
        base: if base == Register::None || base == Register::RIP || base == Register::EIP {
            None
        } else {
            Some(gpr64(insn, base)?)
        },
        index,
        scale,
        disp,
    })
}

fn emit(cursor: &mut l1::Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    if insn.has_lock_prefix() && !crate::gp::lock_ok(insn) {
        return Err(bad(insn));
    }
    if crate::x87::is_x87(insn.mnemonic()) {
        return l2::encode(cursor, insn, image_base);
    }
    if crate::sse::accepts(insn) {
        return l3::encode(cursor, insn, image_base);
    }
    match lift_ops(insn, image_base) {
        Ok(ops) => {
            cursor.extend(ops);
            Ok(())
        }
        Err(crate::error::Error::Unsupported { .. }) => l1::encode(cursor, insn, image_base),
        Err(err) => Err(err),
    }
}

fn is_control(insn: &Instruction) -> bool {
    insn.mnemonic().jcc_short_or_near()
        || matches!(
            insn.mnemonic(),
            Mnemonic::Jmp | Mnemonic::Call | Mnemonic::Ret
        )
}

fn gpr_index(reg: Register) -> Result<u16> {
    if !reg.is_gpr() {
        return Err(msg(format!("{reg:?} is not a general register")));
    }
    let index = reg.full_register().number();
    if index >= ARCH {
        return Err(msg("register is outside the architectural file"));
    }
    Ok(index as u16)
}

fn gpr64(insn: &Instruction, reg: Register) -> Result<u16> {
    if reg.size() != 8 {
        return Err(bad(insn));
    }
    gpr_index(reg)
}

fn gpr8(insn: &Instruction, reg: Register) -> Result<u16> {
    if reg.size() != 1 {
        return Err(bad(insn));
    }
    gpr_index(reg)
}

fn branch_target(insn: &Instruction) -> Option<u64> {
    if (insn.mnemonic().jcc_short_or_near()
        || matches!(insn.mnemonic(), Mnemonic::Jmp | Mnemonic::Call))
        && insn.op0_kind() == OpKind::NearBranch64
    {
        return Some(insn.near_branch_target());
    }
    None
}

fn jcc(mnemonic: Mnemonic) -> Option<u8> {
    Some(match mnemonic {
        Mnemonic::Jo => 0,
        Mnemonic::Jno => 1,
        Mnemonic::Jb => 2,
        Mnemonic::Jae => 3,
        Mnemonic::Je => 4,
        Mnemonic::Jne => 5,
        Mnemonic::Jbe => 6,
        Mnemonic::Ja => 7,
        Mnemonic::Js => 8,
        Mnemonic::Jns => 9,
        Mnemonic::Jp => 10,
        Mnemonic::Jnp => 11,
        Mnemonic::Jl => 12,
        Mnemonic::Jge => 13,
        Mnemonic::Jle => 14,
        Mnemonic::Jg => 15,
        _ => return None,
    })
}

fn is_imm(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64
    )
}

fn imm64(insn: &Instruction, operand: u32) -> u64 {
    match insn.op_kind(operand) {
        OpKind::Immediate8 => u64::from(insn.immediate8()),
        OpKind::Immediate16 => u64::from(insn.immediate16()),
        OpKind::Immediate32 => u64::from(insn.immediate32()),
        OpKind::Immediate64 => insn.immediate64(),
        OpKind::Immediate8to32 => insn.immediate8to32() as u64,
        OpKind::Immediate8to64 => insn.immediate8to64() as u64,
        OpKind::Immediate32to64 => insn.immediate32to64() as u64,
        _ => 0,
    }
}

fn bad(insn: &Instruction) -> crate::error::Error {
    let mut text = String::new();
    IntelFormatter::new().format(insn, &mut text);
    crate::error::Error::Unsupported {
        rva: insn.ip(),
        text,
    }
}

trait JccProbe {
    fn jcc_short_or_near(self) -> bool;
}

impl JccProbe for Mnemonic {
    fn jcc_short_or_near(self) -> bool {
        jcc(self).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::Flags;
    use crate::ir::{exec_func, MapMem};
    use crate::pe::parse;
    use crate::sample::{self, build};

    #[test]
    fn direct_call_below_image_is_rejected() {
        // A direct call from RVA 0x10 to one byte below the image, followed by ret.
        let bytes = [0xe8, 0xea, 0xff, 0xff, 0xff, 0xc3];
        let error = lift("caller", &bytes, 0x10, bytes.len() as u32, 0x400000).unwrap_err();
        assert!(error.to_string().contains("call target outside the image"));
    }

    #[test]
    fn lifted_functions_match_the_reference() {
        let built = build().unwrap();
        let image = parse(&built.bytes).unwrap();
        let text = &image.sections[0];
        let mut funcs = Vec::new();
        for symbol in &built.symbols {
            let off = (symbol.rva - text.rva) as usize;
            funcs.push(
                lift(
                    &symbol.name,
                    &text.bytes[off..],
                    symbol.rva,
                    symbol.size,
                    image.image_base,
                )
                .unwrap(),
            );
        }
        let mut arch = [0u64; 16];
        arch[1] = 10;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut absent =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        exec_func(
            &funcs,
            0,
            &mut arch,
            &mut flags,
            &mut mem,
            image.image_base,
            &mut absent,
        )
        .unwrap();
        assert_eq!(arch[0], sample::mix(10));
        arch = [0; 16];
        arch[1] = 10;
        arch[4] = 0x8_0000;
        exec_func(
            &funcs,
            1,
            &mut arch,
            &mut flags,
            &mut mem,
            image.image_base,
            &mut absent,
        )
        .unwrap();
        assert_eq!(arch[0], sample::compute(10));
    }

    #[test]
    fn narrow_mov_zero_extends_and_shr_jl_are_lifted() {
        let narrow = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
        let func = lift("narrow", &narrow, 0x1000, narrow.len() as u32, 0x140000000).unwrap();
        let mut arch = [0u64; 16];
        arch[0] = 0xffff_ffff_ffff_ffff;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut absent =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        exec_func(
            &[func],
            0,
            &mut arch,
            &mut flags,
            &mut mem,
            0x140000000,
            &mut absent,
        )
        .unwrap();
        assert_eq!(arch[0], 1);

        let shr = [0x48, 0xc1, 0xe8, 0x01, 0xc3];
        let func = lift("shr", &shr, 0x1000, shr.len() as u32, 0x140000000).unwrap();
        assert!(func
            .blocks
            .iter()
            .any(|block| block.ops.contains(&Op::Shr(0, 1))));

        let jl = [0x48, 0x83, 0xf8, 0x00, 0x7c, 0x01, 0xc3, 0xc3];
        let func = lift("jl", &jl, 0x1000, jl.len() as u32, 0x140000000).unwrap();
        assert!(func
            .blocks
            .iter()
            .any(|block| matches!(block.exit, Exit::Jcc(12, _, _))));
    }

    #[test]
    fn imul_uses_encoded_source_and_sets_overflow_flags() {
        let distinct = [0x48, 0x6b, 0xc1, 7, 0xc3];
        let same = [0x48, 0x6b, 0xc0, 7, 0xc3];
        let register = [0x48, 0x0f, 0xaf, 0xc1, 0xc3];
        let negative = [0x48, 0x6b, 0xc1, 0xf9, 0xc3];
        let memory = [0x48, 0x6b, 0x01, 7, 0xc3];
        let max = i64::MAX as u64;
        let cases = [
            (distinct, 0, 5, 35, false),
            (same, 5, 0, 35, false),
            (register, 3, 5, 15, false),
            (negative, 0, 5, (-35i64) as u64, false),
            (distinct, 0, max, max.wrapping_mul(7), true),
            (memory, 0, 0x2000, 35, false),
        ];
        for (code, rax, rcx, expected, overflow) in cases {
            let base = 0x140000000;
            let func = lift("imul", &code, 0x1000, code.len() as u32, base).unwrap();
            let mut arch = [0; ARCH];
            arch[0] = rax;
            arch[1] = rcx;
            let mut flags = Flags {
                cf: !overflow,
                of: !overflow,
                ..Flags::default()
            };
            let mut mem = MapMem::default();
            crate::ir::MemIo::write(&mut mem, 0x2000, &5u64.to_le_bytes()).unwrap();
            let mut absent = |_: &mut [u64; ARCH],
                              _: &mut Flags,
                              _: &mut dyn crate::ir::MemIo,
                              _: u64| { panic!("unexpected call") };
            exec_func(
                &[func],
                0,
                &mut arch,
                &mut flags,
                &mut mem,
                base,
                &mut absent,
            )
            .unwrap();
            assert_eq!(
                (arch[0], arch[1], flags.cf, flags.of),
                (expected, rcx, overflow, overflow),
                "{code:02x?}"
            );
        }
    }
}
