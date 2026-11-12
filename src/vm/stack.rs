//! Stack-machine expansion and execution.
//!
//! Each register operation becomes pushes, one stack opcode, and a pop.
//! Control, memory, and the guest stack stay register ops. The operand stack
//! is empty between those original operations.

use crate::error::{msg, Result};
use crate::flags::{self, Flags};

use super::{Bc, VSTACK_CAP};

/// `true` when `op` is a stack opcode and its bytes were appended.
pub(super) fn put(op: &Bc, out: &mut Vec<u8>) -> bool {
    match *op {
        Bc::PushR(slot) => out.extend([0x34, slot]),
        Bc::PushI(imm) => {
            out.push(0x35);
            out.extend(imm.to_le_bytes());
        }
        Bc::StackAlu(kind) => out.extend([0x36, kind]),
        Bc::PopR(slot) => out.extend([0x37, slot]),
        Bc::StackUnary(kind) => out.extend([0x38, kind]),
        Bc::StackCmp(kind) => out.extend([0x39, kind]),
        Bc::StackShift(kind, count) => out.extend([0x3a, kind, count]),
        Bc::StackImul => out.push(0x3b),
        _ => return false,
    }
    true
}

/// Expand register data ops. Jump targets are indexes into `ops` and are rewritten.
pub(super) fn expand(ops: Vec<Bc>) -> Result<(Vec<Bc>, Vec<u32>)> {
    let mut map = Vec::with_capacity(ops.len());
    let mut out = Vec::with_capacity(ops.len().saturating_mul(2));
    for op in ops {
        map.push(u32::try_from(out.len()).unwrap_or(u32::MAX));
        emit(&mut out, op);
    }
    retarget(&mut out, &map)?;
    Ok((out, map))
}

fn emit(out: &mut Vec<Bc>, op: Bc) {
    if emit_move(out, &op) || emit_logic(out, &op) {
        return;
    }
    out.push(op);
}

fn emit_move(out: &mut Vec<Bc>, op: &Bc) -> bool {
    match *op {
        Bc::MovRr(dst, src) => {
            out.push(Bc::PushR(src));
            out.push(Bc::PopR(dst));
        }
        Bc::MovRi(dst, imm) => {
            out.push(Bc::PushI(imm));
            out.push(Bc::PopR(dst));
        }
        Bc::AluRr(kind, dst, src) => push_bin(out, kind, dst, src),
        Bc::AluRi(kind, dst, imm) => push_imm(out, kind, dst, imm),
        _ => return false,
    }
    true
}

fn emit_logic(out: &mut Vec<Bc>, op: &Bc) -> bool {
    match *op {
        Bc::CmpRr(dst, src) => push_cmp(out, 0, dst, src),
        Bc::CmpRi(dst, imm) => push_cmp_imm(out, 0, dst, imm),
        Bc::TestRr(dst, src) => push_cmp(out, 1, dst, src),
        Bc::TestRi(dst, imm) => push_cmp_imm(out, 1, dst, imm),
        Bc::Unary(kind, dst) => {
            out.push(Bc::PushR(dst));
            out.push(Bc::StackUnary(kind));
            out.push(Bc::PopR(dst));
        }
        Bc::Shift(kind, dst, count) => {
            out.push(Bc::PushR(dst));
            out.push(Bc::StackShift(kind, count));
            out.push(Bc::PopR(dst));
        }
        Bc::ImulRr(dst, src) => {
            out.push(Bc::PushR(dst));
            out.push(Bc::PushR(src));
            out.push(Bc::StackImul);
            out.push(Bc::PopR(dst));
        }
        Bc::ImulRi(dst, imm) => {
            out.push(Bc::PushR(dst));
            out.push(Bc::PushI(sext(imm)));
            out.push(Bc::StackImul);
            out.push(Bc::PopR(dst));
        }
        _ => return false,
    }
    true
}

fn push_bin(out: &mut Vec<Bc>, kind: u8, dst: u8, src: u8) {
    out.push(Bc::PushR(dst));
    out.push(Bc::PushR(src));
    out.push(Bc::StackAlu(kind));
    out.push(Bc::PopR(dst));
}

fn push_imm(out: &mut Vec<Bc>, kind: u8, dst: u8, imm: i32) {
    out.push(Bc::PushR(dst));
    out.push(Bc::PushI(sext(imm)));
    out.push(Bc::StackAlu(kind));
    out.push(Bc::PopR(dst));
}

fn push_cmp(out: &mut Vec<Bc>, kind: u8, dst: u8, src: u8) {
    out.push(Bc::PushR(dst));
    out.push(Bc::PushR(src));
    out.push(Bc::StackCmp(kind));
}

fn push_cmp_imm(out: &mut Vec<Bc>, kind: u8, dst: u8, imm: i32) {
    out.push(Bc::PushR(dst));
    out.push(Bc::PushI(sext(imm)));
    out.push(Bc::StackCmp(kind));
}

fn sext(imm: i32) -> u64 {
    imm as i64 as u64
}

fn retarget(ops: &mut [Bc], map: &[u32]) -> Result<()> {
    for op in ops {
        let (Bc::Jmp(target) | Bc::Jcc(_, target)) = op else {
            continue;
        };
        *target = *map
            .get(*target as usize)
            .ok_or_else(|| msg("stack retarget is out of range"))?;
    }
    Ok(())
}

/// `Ok(true)` when `op` was a stack opcode.
pub(super) fn apply(
    op: &Bc,
    regs: &mut [u64],
    flags: &mut Flags,
    stack: &mut Vec<u64>,
) -> Result<bool> {
    match *op {
        Bc::PushR(slot) => push(stack, reg(regs, slot)?)?,
        Bc::PushI(imm) => {
            let _pad = reg(regs, 0)?;
            push(stack, imm)?;
        }
        Bc::PopR(slot) => {
            let value = pop(stack)?;
            let cell = regs
                .get_mut(usize::from(slot))
                .ok_or_else(|| msg("register index out of range"))?;
            *cell = value;
            super::balance::note_store();
        }
        Bc::StackAlu(kind) => alu(kind, flags, stack)?,
        Bc::StackCmp(kind) => cmp(kind, flags, stack)?,
        Bc::StackUnary(kind) => unary(kind, flags, stack)?,
        Bc::StackShift(kind, count) => shift(kind, count, flags, stack)?,
        Bc::StackImul => imul(flags, stack)?,
        _ => return Ok(false),
    }
    Ok(true)
}

fn alu(kind: u8, flags: &mut Flags, stack: &mut Vec<u64>) -> Result<()> {
    let right = pop(stack)?;
    let left = pop(stack)?;
    let (value, next) = form_alu(kind, left, right)?;
    super::balance::write_flags(flags, next);
    push(stack, value)
}

fn form_alu(kind: u8, left: u64, right: u64) -> Result<(u64, Flags)> {
    Ok(match kind {
        0 => flags::add(left, right, 64),
        1 => flags::sub(left, right, 64),
        2 => flags::logic_xor(left, right, 64),
        3 => flags::logic_and(left, right, 64),
        4 => flags::logic_or(left, right, 64),
        _ => return Err(msg("unknown stack alu")),
    })
}

fn cmp(kind: u8, flags: &mut Flags, stack: &mut Vec<u64>) -> Result<()> {
    let right = pop(stack)?;
    let left = pop(stack)?;
    let next = stack_cmp(kind, left, right)?;
    super::balance::write_flags(flags, next);
    Ok(())
}

fn stack_cmp(kind: u8, left: u64, right: u64) -> Result<Flags> {
    Ok(match kind {
        0 => flags::sub(left, right, 64).1,
        1 => flags::logic_and(left, right, 64).1,
        _ => return Err(msg("unknown stack compare")),
    })
}

fn unary(kind: u8, flags: &mut Flags, stack: &mut Vec<u64>) -> Result<()> {
    let value = pop(stack)?;
    let old = super::balance::read_flags(flags);
    let (bits, next) = stack_unary(kind, value, old)?;
    super::balance::write_flags(flags, next);
    push(stack, bits)
}

fn stack_unary(kind: u8, value: u64, old: Flags) -> Result<(u64, Flags)> {
    if kind == 0 {
        return Ok((!value, old));
    }
    unary_flags(kind, value, old)
}

fn unary_flags(kind: u8, value: u64, old: Flags) -> Result<(u64, Flags)> {
    Ok(match kind {
        1 => flags::neg(value, 64),
        2 => flags::inc(value, 64, old),
        3 => flags::dec(value, 64, old),
        _ => return Err(msg("unknown stack unary")),
    })
}

fn shift(kind: u8, count: u8, flags: &mut Flags, stack: &mut Vec<u64>) -> Result<()> {
    let value = pop(stack)?;
    let count = count & 0x3f;
    let old = super::balance::read_flags(flags);
    let (bits, next) = shifted(kind, value, count, old)?;
    super::balance::write_flags(flags, next);
    push(stack, bits)
}

fn shifted(kind: u8, value: u64, count: u8, old: Flags) -> Result<(u64, Flags)> {
    if count == 0 {
        return Ok((value, old));
    }
    shift_kind(kind, value, count, old)
}

fn shift_kind(kind: u8, value: u64, count: u8, old: Flags) -> Result<(u64, Flags)> {
    let count = u32::from(count);
    Ok(match kind {
        0 => flags::shift_left(value, count, 64, old),
        1 => flags::shift_right(value, count, 64, old),
        2 => flags::shift_arith(value, count, 64, old),
        3 => flags::rotate_left(value, count, 64, old),
        4 => flags::rotate_right(value, count, 64, old),
        _ => return Err(msg("unknown stack shift")),
    })
}

fn imul(flags: &mut Flags, stack: &mut Vec<u64>) -> Result<()> {
    let right = pop(stack)?;
    let left = pop(stack)?;
    let (bits, next) = flags::imul(left, right);
    super::balance::write_flags(flags, next);
    push(stack, bits)
}

fn push(stack: &mut Vec<u64>, value: u64) -> Result<()> {
    if stack.len() >= VSTACK_CAP {
        return Err(msg("vm operand stack overflow"));
    }
    stack.push(value);
    super::balance::note_store();
    Ok(())
}

fn pop(stack: &mut Vec<u64>) -> Result<u64> {
    let value = stack
        .pop()
        .ok_or_else(|| msg("vm operand stack underflow"))?;
    super::balance::note_load();
    Ok(value)
}

fn reg(regs: &[u64], slot: u8) -> Result<u64> {
    let value = regs
        .get(usize::from(slot))
        .copied()
        .ok_or_else(|| msg("register index out of range"))?;
    super::balance::note_load();
    Ok(value)
}

pub(super) fn shape_ops(
    ops: Vec<Bc>,
    entry: u32,
    shape: super::form::MachineForm,
) -> Result<(Vec<Bc>, u32)> {
    if shape != super::form::MachineForm::Stack {
        return Ok((ops, entry));
    }
    let (ops, map) = expand(ops)?;
    let entry = *map
        .get(entry as usize)
        .ok_or_else(|| msg("stack entry is out of range"))?;
    Ok((ops, entry))
}
