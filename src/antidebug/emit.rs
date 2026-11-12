//! Detectors added after the five from S6. Each one jumps to `poison`, which
//! mixes the woven key and then fail-closes with `0xDEB6`.

use iced_x86::code_asm::*;

use crate::emu::djb2;
use crate::error::Result;

use super::{
    step, DEBUGGER_IMAGES, GS_PEB, HEAP_FLAGS, HEAP_FORCE, HEAP_GROWABLE, KEY_POISON,
    PROCESS_BASIC, PROCESS_DEBUG_FLAGS, PROCESS_DEBUG_OBJECT, PROCESS_DEBUG_PORT, PROCESS_IMAGE,
    PROTECTED_HANDLE,
};

pub(super) fn later(
    a: &mut CodeAssembler,
    resolve: u64,
    bad: &mut CodeLabel,
    poison: &mut CodeLabel,
    runtime: u64,
) -> Result<()> {
    hardware(a, resolve, poison)?;
    protected_handle(a, resolve, poison)?;
    int2d(a, poison)?;
    heap(a, poison)?;
    find_ntdll(a, poison)?;
    debug_port(a, resolve, poison)?;
    debug_object(a, resolve, poison)?;
    debug_flags(a, resolve, poison)?;
    parent(a, resolve, poison)?;
    super::woven::checks(a, resolve, bad, runtime)
}

pub(crate) fn emit_poison(a: &mut CodeAssembler, runtime: u64) -> Result<()> {
    let poison = i32::from(KEY_POISON);
    step(a.mov(rax, runtime as i64))?;
    step(a.xor(byte_ptr(rax + crate::vm::RT_KEY), poison))?;
    step(a.xor(byte_ptr(rax + crate::vm::RT_TERM), poison))?;
    Ok(())
}

fn hardware(a: &mut CodeAssembler, resolve: u64, poison: &mut CodeLabel) -> Result<()> {
    super::emit_resolve(a, resolve, "GetThreadContext")?;
    step(a.sub(rsp, 0xc0i32))?;
    step(a.lea(rdx, qword_ptr(rsp + 0x20i32)))?;
    step(a.mov(dword_ptr(rdx + 0x30i32), 0x0010_0010u32))?;
    step(a.mov(rcx, -2i64))?;
    step(a.call(rax))?;
    step(a.lea(rdx, qword_ptr(rsp + 0x20i32)))?;
    or_debug_regs(a)?;
    step(a.add(rsp, 0xc0i32))?;
    step(a.test(rax, rax))?;
    step(a.jnz(*poison))?;
    Ok(())
}

fn or_debug_regs(a: &mut CodeAssembler) -> Result<()> {
    step(a.mov(rax, qword_ptr(rdx + 0x48i32)))?;
    step(a.or(rax, qword_ptr(rdx + 0x50i32)))?;
    step(a.or(rax, qword_ptr(rdx + 0x58i32)))?;
    step(a.or(rax, qword_ptr(rdx + 0x60i32)))?;
    step(a.mov(rcx, qword_ptr(rdx + 0x68i32)))?;
    step(a.or(rax, rcx))?;
    step(a.or(rax, qword_ptr(rdx + 0x70i32)))?;
    Ok(())
}

fn protected_handle(a: &mut CodeAssembler, resolve: u64, poison: &mut CodeLabel) -> Result<()> {
    super::emit_resolve(a, resolve, "SetHandleInformation")?;
    step(a.mov(rcx, PROTECTED_HANDLE as i64))?;
    step(a.mov(edx, 2u32))?;
    step(a.mov(r8d, 2u32))?;
    step(a.call(rax))?;
    super::emit_resolve(a, resolve, "CloseHandle")?;
    step(a.mov(rcx, PROTECTED_HANDLE as i64))?;
    step(a.call(rax))?;
    step(a.test(eax, eax))?;
    step(a.jnz(*poison))?;
    Ok(())
}

fn int2d(a: &mut CodeAssembler, poison: &mut CodeLabel) -> Result<()> {
    // The byte after `int 2d` is the one a debugger skips. The emulator always
    // consumes it and reports the clean result in `eax`.
    step(a.xor(eax, eax))?;
    step(a.db(&[0xcd, 0x2d]))?;
    step(a.nop())?;
    step(a.cmp(eax, 1u32))?;
    step(a.jne(*poison))?;
    Ok(())
}

fn heap(a: &mut CodeAssembler, poison: &mut CodeLabel) -> Result<()> {
    let mut clean = a.create_label();
    step(a.db(&GS_PEB))?;
    step(a.mov(rcx, qword_ptr(rax + 0x30i32)))?;
    step(a.test(rcx, rcx))?;
    step(a.jz(clean))?;
    step(a.mov(edx, dword_ptr(rcx + HEAP_FLAGS)))?;
    step(a.mov(eax, dword_ptr(rcx + HEAP_FORCE)))?;
    step(a.and(edx, !HEAP_GROWABLE))?;
    step(a.or(edx, eax))?;
    step(a.test(edx, edx))?;
    step(a.jnz(*poison))?;
    step(a.set_label(&mut clean))?;
    Ok(())
}

fn debug_port(a: &mut CodeAssembler, resolve: u64, poison: &mut CodeLabel) -> Result<()> {
    query_qword(a, resolve, PROCESS_DEBUG_PORT, poison)
}

fn debug_object(a: &mut CodeAssembler, resolve: u64, poison: &mut CodeLabel) -> Result<()> {
    query_qword(a, resolve, PROCESS_DEBUG_OBJECT, poison)
}

fn debug_flags(a: &mut CodeAssembler, resolve: u64, poison: &mut CodeLabel) -> Result<()> {
    step(a.sub(rsp, 0x60i32))?;
    call_query(a, resolve, PROCESS_DEBUG_FLAGS, 4, -1)?;
    step(a.mov(eax, dword_ptr(rsp + 0x28i32)))?;
    step(a.add(rsp, 0x60i32))?;
    step(a.test(eax, eax))?;
    step(a.jz(*poison))?;
    Ok(())
}

fn query_qword(
    a: &mut CodeAssembler,
    resolve: u64,
    class: u32,
    poison: &mut CodeLabel,
) -> Result<()> {
    step(a.sub(rsp, 0x60i32))?;
    call_query(a, resolve, class, 8, -1)?;
    step(a.mov(rax, qword_ptr(rsp + 0x28i32)))?;
    step(a.add(rsp, 0x60i32))?;
    step(a.test(rax, rax))?;
    step(a.jnz(*poison))?;
    Ok(())
}

fn call_query(
    a: &mut CodeAssembler,
    resolve: u64,
    class: u32,
    len: u32,
    handle: i64,
) -> Result<()> {
    super::emit_resolve_reg(a, resolve, r13, "NtQueryInformationProcess")?;
    step(a.mov(r11, rax))?;
    step(a.mov(rcx, handle))?;
    step(a.mov(edx, class))?;
    step(a.lea(r8, qword_ptr(rsp + 0x28i32)))?;
    step(a.mov(r9d, len))?;
    step(a.xor(eax, eax))?;
    step(a.mov(qword_ptr(rsp + 0x20i32), rax))?;
    step(a.call(r11))?;
    Ok(())
}

fn parent(a: &mut CodeAssembler, resolve: u64, poison: &mut CodeLabel) -> Result<()> {
    let mut hashed = a.create_label();
    let mut done = a.create_label();
    step(a.sub(rsp, 0x240i32))?;
    read_parent(a, resolve)?;
    step(a.test(rcx, rcx))?;
    step(a.jnz(hashed))?;
    step(a.add(rsp, 0x240i32))?;
    step(a.jmp(done))?;
    step(a.set_label(&mut hashed))?;
    hash_parent_name(a)?;
    step(a.add(rsp, 0x240i32))?;
    name_hits(a, poison)?;
    step(a.set_label(&mut done))?;
    Ok(())
}

fn read_parent(a: &mut CodeAssembler, resolve: u64) -> Result<()> {
    call_query(a, resolve, PROCESS_BASIC, 0x30, -1)?;
    super::emit_resolve_reg(a, resolve, r13, "NtQueryInformationProcess")?;
    step(a.mov(r11, rax))?;
    step(a.mov(rcx, qword_ptr(rsp + 0x50i32)))?;
    step(a.mov(edx, PROCESS_IMAGE))?;
    step(a.lea(r8, qword_ptr(rsp + 0x60i32)))?;
    step(a.mov(r9d, 0x1e0u32))?;
    step(a.xor(eax, eax))?;
    step(a.mov(qword_ptr(rsp + 0x20i32), rax))?;
    step(a.call(r11))?;
    Ok(())
}

fn hash_parent_name(a: &mut CodeAssembler) -> Result<()> {
    step(a.movzx(ecx, word_ptr(rsp + 0x60i32)))?;
    step(a.mov(r8, qword_ptr(rsp + 0x68i32)))?;
    base_name(a)?;
    hash_ascii(a)
}

fn base_name(a: &mut CodeAssembler) -> Result<()> {
    let mut scan = a.create_label();
    let mut advance = a.create_label();
    let mut hash = a.create_label();
    step(a.lea(r11, qword_ptr(r8 + rcx)))?;
    step(a.mov(r9, r8))?;
    step(a.set_label(&mut scan))?;
    step(a.cmp(r8, r11))?;
    step(a.jae(hash))?;
    step(a.movzx(eax, byte_ptr(r8)))?;
    step(a.cmp(eax, 0x5cu32))?;
    step(a.jne(advance))?;
    step(a.lea(r9, qword_ptr(r8 + 2i32)))?;
    step(a.set_label(&mut advance))?;
    step(a.add(r8, 2i32))?;
    step(a.jmp(scan))?;
    step(a.set_label(&mut hash))?;
    step(a.mov(rcx, r11))?;
    step(a.sub(rcx, r9))?;
    step(a.mov(r8, r9))?;
    Ok(())
}

fn hash_ascii(a: &mut CodeAssembler) -> Result<()> {
    let mut loop_l = a.create_label();
    let mut done = a.create_label();
    step(a.mov(eax, 5381u32))?;
    step(a.set_label(&mut loop_l))?;
    step(a.test(rcx, rcx))?;
    step(a.jz(done))?;
    step(a.movzx(edx, byte_ptr(r8)))?;
    step(a.imul_3(eax, eax, 33i32))?;
    step(a.add(eax, edx))?;
    step(a.add(r8, 2i32))?;
    step(a.sub(rcx, 2i32))?;
    step(a.jmp(loop_l))?;
    step(a.set_label(&mut done))?;
    Ok(())
}

fn name_hits(a: &mut CodeAssembler, poison: &mut CodeLabel) -> Result<()> {
    for name in DEBUGGER_IMAGES {
        step(a.cmp(eax, djb2(name.as_bytes()) as i32))?;
        step(a.je(*poison))?;
    }
    Ok(())
}

fn find_ntdll(a: &mut CodeAssembler, miss: &mut CodeLabel) -> Result<()> {
    let mut walk = a.create_label();
    let mut next = a.create_label();
    let mut found = a.create_label();
    step(a.db(&GS_PEB))?;
    step(a.mov(rax, qword_ptr(rax + 0x18i32)))?;
    step(a.lea(rbx, qword_ptr(rax + 0x20i32)))?;
    step(a.mov(rcx, qword_ptr(rbx)))?;
    step(a.set_label(&mut walk))?;
    step(a.cmp(rcx, rbx))?;
    step(a.je(*miss))?;
    step(a.mov(r13, qword_ptr(rcx + 0x20i32)))?;
    step(a.mov(r8, qword_ptr(rcx + 0x50i32)))?;
    step(a.cmp(word_ptr(r8), 0x6ei32))?;
    step(a.jne(next))?;
    step(a.cmp(word_ptr(r8 + 2i32), 0x74i32))?;
    step(a.je(found))?;
    step(a.set_label(&mut next))?;
    step(a.mov(rcx, qword_ptr(rcx)))?;
    step(a.jmp(walk))?;
    step(a.set_label(&mut found))?;
    Ok(())
}
