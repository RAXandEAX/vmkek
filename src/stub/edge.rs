//! Data-dependent edge between handlers.
//!
//! `goto` adds the value left in `rax` into the gate and wipes the unmasked
//! immediate. The level-2 tail reads the low bit of that gate and jumps to one
//! of two handler entries. Those entries are seed-varying stamps; both fall
//! into the same handler body. The cache stays masked.

use iced_x86::code_asm::*;

use crate::error::Result;
use crate::vm::{FRAME_GATE, FRAME_PLAIN, RT_INDEX, RT_SCHED};

use super::ice;

/// Opcodes whose payload contains a data immediate. Matches `form::imm_span`.
const IMM_MASK: u64 = (1 << 0x03)
    | (1 << 0x15)
    | (1 << 0x16)
    | (1 << 0x17)
    | (1 << 0x18)
    | (1 << 0x19)
    | (1 << 0x21)
    | (1 << 0x23)
    | (1 << 0x2e)
    | (1 << 0x35);

fn asm(step: std::result::Result<(), IcedError>) -> Result<()> {
    step.map_err(ice)
}

/// Fold `rax` into the gate and return to the dispatcher.
///
/// The next handler address is chosen later, from the low bit of this gate.
pub(super) fn goto(a: &mut CodeAssembler, dispatch: &CodeLabel) -> Result<()> {
    wipe(a)?;
    mix_gate(a)?;
    asm(a.jmp(*dispatch))?;
    Ok(())
}

fn wipe(a: &mut CodeAssembler) -> Result<()> {
    asm(a.mov(qword_ptr(rbx + FRAME_PLAIN), 0i32))?;
    asm(a.mov(qword_ptr(rbx + (FRAME_PLAIN + 8)), 0i32))?;
    Ok(())
}

fn mix_gate(a: &mut CodeAssembler) -> Result<()> {
    // `rax` is the result, or the flag image `store_flags` left after that result.
    asm(a.mov(rcx, qword_ptr(rbx + FRAME_GATE)))?;
    asm(a.add(rcx, rax))?;
    asm(a.inc(rcx))?;
    asm(a.mov(qword_ptr(rbx + FRAME_GATE), rcx))?;
    Ok(())
}

/// Copy one instruction and XOR its data immediate. The cache stays masked.
pub(super) fn emit_mix(a: &mut CodeAssembler, mix: &mut CodeLabel) -> Result<()> {
    let mut skip = a.create_label();
    asm(a.set_label(mix))?;
    asm(a.movzx(ecx, byte_ptr(r12)))?;
    asm(a.mov(rax, IMM_MASK as i64))?;
    asm(a.bt(rax, rcx))?;
    asm(a.jnc(skip))?;
    asm(a.mov(rax, qword_ptr(r13 + RT_SCHED)))?;
    asm(a.test(rax, rax))?;
    asm(a.jz(skip))?;
    asm(a.mov(r10b, cl))?;
    load_mask(a)?;
    asm(a.movzx(ecx, r10b))?;
    apply_mask(a, &skip)?;
    asm(a.set_label(&mut skip))?;
    asm(a.ret())?;
    Ok(())
}

fn load_mask(a: &mut CodeAssembler) -> Result<()> {
    asm(a.mov(rdx, 0x9E37_79B9_7F4A_7C15u64 as i64))?;
    asm(a.mul(rdx))?;
    asm(a.mov(ecx, dword_ptr(r13 + RT_INDEX)))?;
    asm(a.add(rax, rcx))?;
    asm(a.imul_3(rcx, r14, 0x0100_001B))?;
    asm(a.add(rax, rcx))?;
    asm(a.or(rax, 1i32))?;
    Ok(())
}

fn apply_mask(a: &mut CodeAssembler, skip: &CodeLabel) -> Result<()> {
    let mut wide = a.create_label();
    let mut pushi = a.create_label();
    let mut dword = a.create_label();
    asm(a.cmp(ecx, 0x03u32))?;
    asm(a.je(wide))?;
    asm(a.cmp(ecx, 0x35u32))?;
    asm(a.je(pushi))?;
    dword_tag(a, &dword, skip)?;
    asm(a.set_label(&mut wide))?;
    stage(a)?;
    asm(a.xor(qword_ptr(r12 + 2i32), rax))?;
    asm(a.jmp(*skip))?;
    asm(a.set_label(&mut pushi))?;
    stage(a)?;
    asm(a.xor(qword_ptr(r12 + 1i32), rax))?;
    asm(a.jmp(*skip))?;
    asm(a.set_label(&mut dword))?;
    stage(a)?;
    asm(a.xor(dword_ptr(r12 + 2i32), eax))?;
    asm(a.jmp(*skip))?;
    Ok(())
}

fn dword_tag(a: &mut CodeAssembler, dword: &CodeLabel, skip: &CodeLabel) -> Result<()> {
    asm(a.cmp(ecx, 0x15u32))?;
    asm(a.jb(*skip))?;
    asm(a.cmp(ecx, 0x19u32))?;
    asm(a.jbe(*dword))?;
    asm(a.cmp(ecx, 0x21u32))?;
    asm(a.je(*dword))?;
    asm(a.cmp(ecx, 0x23u32))?;
    asm(a.je(*dword))?;
    asm(a.cmp(ecx, 0x2eu32))?;
    asm(a.je(*dword))?;
    asm(a.jmp(*skip))?;
    Ok(())
}

fn stage(a: &mut CodeAssembler) -> Result<()> {
    asm(a.mov(r10, qword_ptr(r12)))?;
    asm(a.mov(qword_ptr(rbx + FRAME_PLAIN), r10))?;
    asm(a.movzx(r10d, byte_ptr(r12 + 8i32)))?;
    asm(a.mov(byte_ptr(rbx + (FRAME_PLAIN + 8)), r10b))?;
    asm(a.movzx(r10d, byte_ptr(r12 + 9i32)))?;
    asm(a.mov(byte_ptr(rbx + (FRAME_PLAIN + 9)), r10b))?;
    asm(a.lea(r12, qword_ptr(rbx + FRAME_PLAIN)))?;
    Ok(())
}
