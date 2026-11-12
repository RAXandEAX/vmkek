//! Native stack machine. Operands move through `FRAME_VSTACK`.
//! The register handlers stay in place for the register form and for ops this
//! machine does not rewrite (memory, calls, guest push).

use iced_x86::code_asm::*;

use crate::error::{msg, Result};
use crate::vm::{FRAME_FLAGS, FRAME_VSP, FRAME_VSTACK, SLOT_COUNT, VSTACK_CAP};

use super::ice;

fn asm(step: std::result::Result<(), IcedError>) -> Result<()> {
    step.map_err(ice)
}

pub(super) fn emit(
    a: &mut CodeAssembler,
    tag: u8,
    dispatch: &mut CodeLabel,
    fail: CodeLabel,
) -> Result<()> {
    match tag {
        0x34 => push_r(a, fail)?,
        0x35 => push_i(a, fail)?,
        0x36 => alu(a, fail)?,
        0x37 => pop_r(a, fail)?,
        0x38 => unary(a, fail)?,
        0x39 => cmp(a, fail)?,
        0x3a => shift(a, fail)?,
        0x3b => imul(a, fail)?,
        _ => return Err(msg("stack handler is missing")),
    }
    super::handlers::finish(a, dispatch)
}

fn push_r(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    asm(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    bound(a, ecx, fail)?;
    asm(a.mov(rax, qword_ptr(rbx + rcx * 8)))?;
    push_rax(a, fail)
}

fn push_i(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    asm(a.mov(rax, qword_ptr(r12 + 1i32)))?;
    push_rax(a, fail)
}

fn pop_r(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    pop_rax(a, fail)?;
    asm(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    bound(a, ecx, fail)?;
    asm(a.mov(qword_ptr(rbx + rcx * 8), rax))?;
    Ok(())
}

fn alu(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    pop_rax(a, fail)?;
    asm(a.mov(r8, rax))?;
    pop_rax(a, fail)?;
    asm(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    apply_alu(a)?;
    keep(a, fail)
}

fn apply_alu(a: &mut CodeAssembler) -> Result<()> {
    let mut sub = a.create_label();
    let mut xor = a.create_label();
    let mut and = a.create_label();
    let mut or = a.create_label();
    let mut done = a.create_label();
    asm(a.cmp(cl, 1u32))?;
    asm(a.je(sub))?;
    asm(a.cmp(cl, 2u32))?;
    asm(a.je(xor))?;
    asm(a.cmp(cl, 3u32))?;
    asm(a.je(and))?;
    asm(a.cmp(cl, 4u32))?;
    asm(a.je(or))?;
    asm(a.add(rax, r8))?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut sub))?;
    asm(a.sub(rax, r8))?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut xor))?;
    asm(a.xor(rax, r8))?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut and))?;
    asm(a.and(rax, r8))?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut or))?;
    asm(a.or(rax, r8))?;
    asm(a.set_label(&mut done))?;
    Ok(())
}

fn cmp(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    pop_rax(a, fail)?;
    asm(a.mov(r8, rax))?;
    pop_rax(a, fail)?;
    asm(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    let mut test = a.create_label();
    let mut store = a.create_label();
    asm(a.cmp(cl, 0u32))?;
    asm(a.jne(test))?;
    asm(a.cmp(rax, r8))?;
    asm(a.jmp(store))?;
    asm(a.set_label(&mut test))?;
    asm(a.test(rax, r8))?;
    asm(a.set_label(&mut store))?;
    super::handlers::store_flags(a)
}

fn unary(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    pop_rax(a, fail)?;
    asm(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    let mut neg = a.create_label();
    let mut inc = a.create_label();
    let mut dec = a.create_label();
    let mut done = a.create_label();
    asm(a.cmp(cl, 0u32))?;
    asm(a.jne(neg))?;
    asm(a.not(rax))?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut neg))?;
    asm(a.cmp(cl, 1u32))?;
    asm(a.jne(inc))?;
    asm(a.neg(rax))?;
    keep_flags(a)?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut inc))?;
    asm(a.cmp(cl, 2u32))?;
    asm(a.jne(dec))?;
    reload_flags(a)?;
    asm(a.inc(rax))?;
    keep_flags(a)?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut dec))?;
    reload_flags(a)?;
    asm(a.dec(rax))?;
    keep_flags(a)?;
    asm(a.set_label(&mut done))?;
    push_rax(a, fail)
}

fn shift(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    pop_rax(a, fail)?;
    asm(a.movzx(ecx, byte_ptr(r12 + 2i32)))?;
    asm(a.and(ecx, 0x3fu32))?;
    let mut nonzero = a.create_label();
    let mut done = a.create_label();
    asm(a.test(ecx, ecx))?;
    asm(a.jnz(nonzero))?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut nonzero))?;
    shift_kind(a)?;
    keep_flags(a)?;
    asm(a.set_label(&mut done))?;
    push_rax(a, fail)
}

fn shift_kind(a: &mut CodeAssembler) -> Result<()> {
    asm(a.movzx(edx, byte_ptr(r12 + 1i32)))?;
    let mut shr = a.create_label();
    let mut sar = a.create_label();
    let mut rol = a.create_label();
    let mut ror = a.create_label();
    let mut done = a.create_label();
    asm(a.cmp(dl, 0u32))?;
    asm(a.jne(shr))?;
    asm(a.shl(rax, cl))?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut shr))?;
    asm(a.cmp(dl, 1u32))?;
    asm(a.jne(sar))?;
    asm(a.shr(rax, cl))?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut sar))?;
    asm(a.cmp(dl, 2u32))?;
    asm(a.jne(rol))?;
    asm(a.sar(rax, cl))?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut rol))?;
    asm(a.cmp(dl, 3u32))?;
    asm(a.jne(ror))?;
    reload_flags(a)?;
    asm(a.rol(rax, cl))?;
    asm(a.jmp(done))?;
    asm(a.set_label(&mut ror))?;
    reload_flags(a)?;
    asm(a.ror(rax, cl))?;
    asm(a.set_label(&mut done))?;
    Ok(())
}

fn imul(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    pop_rax(a, fail)?;
    asm(a.mov(r8, rax))?;
    pop_rax(a, fail)?;
    asm(a.imul_2(rax, r8))?;
    keep(a, fail)
}

fn keep(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    keep_flags(a)?;
    push_rax(a, fail)
}

fn keep_flags(a: &mut CodeAssembler) -> Result<()> {
    asm(a.mov(r11, rax))?;
    super::handlers::store_flags(a)?;
    asm(a.mov(rax, r11))?;
    Ok(())
}

fn reload_flags(a: &mut CodeAssembler) -> Result<()> {
    asm(a.mov(r10, qword_ptr(rbx + FRAME_FLAGS)))?;
    asm(a.push(r10))?;
    asm(a.popfq())?;
    Ok(())
}

fn push_rax(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    ready_vsp(a)?;
    asm(a.cmp(rdx, VSTACK_CAP as i32))?;
    asm(a.jae(fail))?;
    asm(a.mov(qword_ptr(rbx + rdx * 8 + FRAME_VSTACK), rax))?;
    asm(a.inc(rdx))?;
    asm(a.mov(qword_ptr(rbx + FRAME_VSP), rdx))?;
    Ok(())
}

fn pop_rax(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    ready_vsp(a)?;
    asm(a.test(rdx, rdx))?;
    asm(a.jz(fail))?;
    asm(a.dec(rdx))?;
    asm(a.mov(rax, qword_ptr(rbx + rdx * 8 + FRAME_VSTACK)))?;
    asm(a.mov(qword_ptr(rbx + FRAME_VSP), rdx))?;
    Ok(())
}

/// A value above the cap is an uninitialized frame, not a live stack.
fn ready_vsp(a: &mut CodeAssembler) -> Result<()> {
    let mut ready = a.create_label();
    asm(a.mov(rdx, qword_ptr(rbx + FRAME_VSP)))?;
    asm(a.cmp(rdx, VSTACK_CAP as i32))?;
    asm(a.jbe(ready))?;
    asm(a.xor(edx, edx))?;
    asm(a.mov(qword_ptr(rbx + FRAME_VSP), rdx))?;
    asm(a.set_label(&mut ready))?;
    Ok(())
}

fn bound(a: &mut CodeAssembler, index: AsmRegister32, fail: CodeLabel) -> Result<()> {
    asm(a.cmp(index, SLOT_COUNT as u32))?;
    asm(a.jae(fail))?;
    Ok(())
}
