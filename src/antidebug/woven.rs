//! Debugger signals mixed into the per-thread key.
//!
//! A clean signal contributes zero, so the xor leaves the chain key where the
//! loader copied it. A substituted answer xors `KEY_POISON` into the chain, the
//! block-0 key, and the terminal, then the loader returns `0xDEB6`.
//!
//! Old kernel-debugger module names are compared and discarded. That compare
//! does not xor the key and it is not a System claim.

use iced_x86::code_asm::*;

use crate::emu::djb2;
use crate::error::Result;
use crate::vm::{GS_CHAIN_PTR, RT_KEY, RT_MASTER, RT_TERM};

use super::{
    emit_resolve_reg, step, BREAKIN_CLEAN, GS_PEB, INT3_MARK, KEY_POISON, LEGACY_KERNEL_MODULES,
    PEB_INSTRUMENTATION, SYSTEM_KERNEL_DEBUGGER, SYSTEM_MODULE_INFORMATION, THREAD_HIDE,
};

pub(super) fn checks(
    a: &mut CodeAssembler,
    resolve: u64,
    bad: &mut CodeLabel,
    runtime: u64,
) -> Result<()> {
    trap_flag(a, bad, runtime)?;
    int3_page(a, bad, runtime)?;
    thread_hide(a, resolve, bad, runtime)?;
    kernel_info(a, resolve, bad, runtime)?;
    weak_module(a, resolve)?;
    remote_breakin(a, resolve, bad, runtime)?;
    instrumentation(a, bad, runtime)
}

fn trap_flag(a: &mut CodeAssembler, bad: &mut CodeLabel, runtime: u64) -> Result<()> {
    let mut hit = a.create_label();
    let mut done = a.create_label();
    step(a.pushfq())?;
    step(a.pop(rax))?;
    step(a.test(eax, 0x100i32))?;
    step(a.jnz(hit))?;
    step(a.xor(eax, eax))?;
    step(a.jmp(done))?;
    step(a.set_label(&mut hit))?;
    step(a.mov(eax, i32::from(KEY_POISON)))?;
    step(a.set_label(&mut done))?;
    fold(a, bad, runtime)
}

fn int3_page(a: &mut CodeAssembler, bad: &mut CodeLabel, runtime: u64) -> Result<()> {
    let mut mark = a.create_label();
    let mut skip = a.create_label();
    let mut scan = a.create_label();
    let mut hit = a.create_label();
    let mut done = a.create_label();
    step(a.jmp(skip))?;
    step(a.set_label(&mut mark))?;
    step(a.db(&INT3_MARK))?;
    step(a.db(&[0]))?;
    step(a.set_label(&mut skip))?;
    step(a.mov(ebx, 0xc0i32))?;
    step(a.or(ebx, 0x0ci32))?;
    step(a.lea(rax, qword_ptr(mark)))?;
    step(a.mov(r11, !0xfffi64))?;
    step(a.and(rax, r11))?;
    scan_page(a, &mut scan, &mut hit)?;
    step(a.xor(eax, eax))?;
    step(a.jmp(done))?;
    step(a.set_label(&mut hit))?;
    step(a.mov(eax, i32::from(KEY_POISON)))?;
    step(a.set_label(&mut done))?;
    fold(a, bad, runtime)
}

fn scan_page(a: &mut CodeAssembler, scan: &mut CodeLabel, hit: &mut CodeLabel) -> Result<()> {
    let mut next = a.create_label();
    // Walk the page. Only the byte after the marker is the breakpoint slot, so an
    // 0xCC inside an immediate elsewhere on the page is not a hit.
    step(a.mov(ecx, 0xffdi32))?;
    step(a.set_label(scan))?;
    step(a.cmp(byte_ptr(rax), 0xa5i32))?;
    step(a.jne(next))?;
    step(a.cmp(byte_ptr(rax + 1), 0x5ai32))?;
    step(a.jne(next))?;
    step(a.cmp(byte_ptr(rax + 2), 0xe3i32))?;
    step(a.jne(next))?;
    step(a.cmp(byte_ptr(rax + 3), bl))?;
    step(a.je(*hit))?;
    step(a.set_label(&mut next))?;
    step(a.inc(rax))?;
    step(a.dec(ecx))?;
    step(a.jnz(*scan))?;
    Ok(())
}

fn thread_hide(
    a: &mut CodeAssembler,
    resolve: u64,
    bad: &mut CodeLabel,
    runtime: u64,
) -> Result<()> {
    let mut hit = a.create_label();
    let mut done = a.create_label();
    emit_resolve_reg(a, resolve, r13, "NtQueryInformationThread")?;
    step(a.mov(r11, rax))?;
    step(a.sub(rsp, 0x48i32))?;
    clear_slot(a)?;
    step(a.mov(rcx, -2i64))?;
    step(a.mov(edx, THREAD_HIDE))?;
    step(a.lea(r8, byte_ptr(rsp + 0x30i32)))?;
    step(a.mov(r9d, 1u32))?;
    step(a.call(r11))?;
    step(a.mov(al, byte_ptr(rsp + 0x30i32)))?;
    step(a.add(rsp, 0x48i32))?;
    poison_if_set(a, &mut hit, &mut done)?;
    fold(a, bad, runtime)
}

fn kernel_info(
    a: &mut CodeAssembler,
    resolve: u64,
    bad: &mut CodeLabel,
    runtime: u64,
) -> Result<()> {
    let mut hit = a.create_label();
    let mut done = a.create_label();
    system_query(a, resolve, SYSTEM_KERNEL_DEBUGGER, 2)?;
    step(a.mov(al, byte_ptr(rsp + 0x30i32)))?;
    step(a.add(rsp, 0x40i32))?;
    poison_if_set(a, &mut hit, &mut done)?;
    fold(a, bad, runtime)
}

fn weak_module(a: &mut CodeAssembler, resolve: u64) -> Result<()> {
    system_query(a, resolve, SYSTEM_MODULE_INFORMATION, 4)?;
    step(a.mov(eax, dword_ptr(rsp + 0x30i32)))?;
    step(a.add(rsp, 0x40i32))?;
    note_legacy(a)
}

fn system_query(a: &mut CodeAssembler, resolve: u64, class: u32, len: u32) -> Result<()> {
    emit_resolve_reg(a, resolve, r13, "NtQuerySystemInformation")?;
    step(a.mov(r11, rax))?;
    step(a.sub(rsp, 0x40i32))?;
    clear_slot(a)?;
    step(a.mov(ecx, class))?;
    step(a.lea(rdx, byte_ptr(rsp + 0x30i32)))?;
    step(a.mov(r8d, len))?;
    step(a.xor(r9, r9))?;
    step(a.call(r11))?;
    Ok(())
}

fn clear_slot(a: &mut CodeAssembler) -> Result<()> {
    step(a.xor(eax, eax))?;
    step(a.mov(byte_ptr(rsp + 0x30i32), al))?;
    step(a.mov(qword_ptr(rsp + 0x20i32), rax))?;
    Ok(())
}

fn poison_if_set(a: &mut CodeAssembler, hit: &mut CodeLabel, done: &mut CodeLabel) -> Result<()> {
    step(a.test(al, al))?;
    step(a.jnz(*hit))?;
    step(a.xor(eax, eax))?;
    step(a.jmp(*done))?;
    step(a.set_label(hit))?;
    step(a.mov(eax, i32::from(KEY_POISON)))?;
    step(a.set_label(done))?;
    Ok(())
}

fn note_legacy(a: &mut CodeAssembler) -> Result<()> {
    step(a.xor(edx, edx))?;
    for name in LEGACY_KERNEL_MODULES {
        step(a.cmp(eax, djb2(name.as_bytes()) as i32))?;
        step(a.sete(cl))?;
        step(a.or(dl, cl))?;
    }
    // The match bit is dropped. A name on the list does not change the key.
    step(a.xor(edx, edx))?;
    Ok(())
}

fn remote_breakin(
    a: &mut CodeAssembler,
    resolve: u64,
    bad: &mut CodeLabel,
    runtime: u64,
) -> Result<()> {
    let mut hit = a.create_label();
    let mut done = a.create_label();
    emit_resolve_reg(a, resolve, r13, "DbgUiRemoteBreakin")?;
    step(a.mov(dl, byte_ptr(rax)))?;
    step(a.cmp(dl, i32::from(BREAKIN_CLEAN)))?;
    step(a.jne(hit))?;
    step(a.xor(eax, eax))?;
    step(a.jmp(done))?;
    step(a.set_label(&mut hit))?;
    step(a.mov(eax, i32::from(KEY_POISON)))?;
    step(a.set_label(&mut done))?;
    fold(a, bad, runtime)
}

fn instrumentation(a: &mut CodeAssembler, bad: &mut CodeLabel, runtime: u64) -> Result<()> {
    let mut hit = a.create_label();
    let mut done = a.create_label();
    step(a.db(&GS_PEB))?;
    step(a.mov(rax, qword_ptr(rax + PEB_INSTRUMENTATION)))?;
    step(a.test(rax, rax))?;
    step(a.jnz(hit))?;
    step(a.xor(eax, eax))?;
    step(a.jmp(done))?;
    step(a.set_label(&mut hit))?;
    step(a.mov(eax, i32::from(KEY_POISON)))?;
    step(a.set_label(&mut done))?;
    fold(a, bad, runtime)
}

fn fold(a: &mut CodeAssembler, bad: &mut CodeLabel, runtime: u64) -> Result<()> {
    let chain = gs_chain();
    step(a.mov(bl, al))?;
    step(a.db(&chain))?;
    step(a.xor(byte_ptr(rax), bl))?;
    step(a.mov(rax, runtime as i64))?;
    step(a.xor(byte_ptr(rax + RT_KEY), bl))?;
    step(a.xor(byte_ptr(rax + RT_MASTER), bl))?;
    step(a.xor(byte_ptr(rax + RT_TERM), bl))?;
    step(a.test(bl, bl))?;
    step(a.jnz(*bad))?;
    Ok(())
}

fn gs_chain() -> [u8; 9] {
    let disp = (GS_CHAIN_PTR as u32).to_le_bytes();
    [
        0x65, 0x48, 0x8b, 0x04, 0x25, disp[0], disp[1], disp[2], disp[3],
    ]
}
