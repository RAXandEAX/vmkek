//! Per-thread keyed chain. The running ChaCha key and fold cursor live in the
//! block addressed by `gs:[GS_CHAIN_PTR]`. Each thread owns the `gs` base, so
//! the pointer is not a word in the shared image.

use std::{cell::Cell, marker::PhantomData, rc::Rc};

use iced_x86::code_asm::*;

use crate::error::{msg, Result};
use crate::vm::{
    CHAIN_BYTES, CHAIN_FOLD, CHAIN_SLOTS, CTX_BOUND, CTX_CACHE, CTX_DEPTH, CTX_INDEX, CTX_KEYS,
    CTX_LEVEL, CTX_MAP, CTX_MAP_SLOTS, CTX_MAP_STRIDE, CTX_SALT, GS_CHAIN_PTR, GS_FRAME_AT,
    GS_FRAME_PTR, GS_MAP_BYTES, GS_TID, TRAMP_DEPTH, TRAMP_SAVE, TRAMP_SLOTS, TRAMP_STRIDE,
};

use super::ice;
use crate::vm::{FILE_STACK_BYTES, FRAME_BYTES, WEAVE_SAVE};

/// Static TLS owned and initialized by the PE loader.
pub(crate) const PE_TLS_VECTOR: i32 = 0x58;
pub(crate) const PE_TLS_INDEX_BYTES: usize = 8;
pub(crate) const PE_VM_PROBE_BASE: u64 = 0x1_4000_0000;
pub(crate) const PE_TLS_PROBE_INDEX: u64 = PE_VM_PROBE_BASE + 0x3000;
pub(crate) const PE_TLS_LIMIT: usize = 4 * 1024 * 1024;
pub(super) const PE_FRAME_BASE: i32 = CHAIN_BYTES.next_multiple_of(16) as i32;
pub(super) const PE_FRAME_STRIDE: i32 =
    (FRAME_BYTES + FILE_STACK_BYTES + super::pe_unwind::ENTRY_SAVE_BYTES).next_multiple_of(16)
        as i32;
pub(crate) const PE_TLS_CACHE_BASE: usize =
    PE_FRAME_BASE as usize + (TRAMP_SLOTS + 1) * PE_FRAME_STRIDE as usize;

#[derive(Clone, Copy)]
struct PeTls {
    index: u64,
    bytes: u32,
    bridges: Option<PeBridges>,
    guarded: bool,
}

#[derive(Clone, Copy)]
pub(super) struct PeBridges {
    pub base: u64,
    pub runtime: u64,
    pub count: usize,
}

thread_local! {
    static PE_TLS: Cell<Option<PeTls>> = const { Cell::new(None) };
}

pub(crate) struct PeTlsGuard {
    previous: Option<PeTls>,
    _thread: PhantomData<Rc<()>>,
}

impl Drop for PeTlsGuard {
    fn drop(&mut self) {
        PE_TLS.set(self.previous);
    }
}

/// Bind the PE static TLS slot address and size for one assembler pass.
pub(crate) fn bind_pe_tls(index: u64, bytes: u32) -> PeTlsGuard {
    PeTlsGuard {
        previous: PE_TLS.replace(Some(PeTls {
            index,
            bytes,
            bridges: None,
            guarded: false,
        })),
        _thread: PhantomData,
    }
}

pub(crate) fn bind_pe_bridges(base: u64, runtime: u64, count: usize) -> Result<PeTlsGuard> {
    let mut tls = PE_TLS
        .get()
        .ok_or_else(|| msg("native bridge layout requires PE TLS"))?;
    if count > CTX_MAP_SLOTS {
        return Err(msg("native bridge layout exceeds its function limit"));
    }
    tls.bridges = Some(PeBridges {
        base,
        runtime,
        count,
    });
    Ok(PeTlsGuard {
        previous: PE_TLS.replace(Some(tls)),
        _thread: PhantomData,
    })
}

pub(super) fn pe_bridges() -> Result<PeBridges> {
    PE_TLS
        .get()
        .and_then(|tls| tls.bridges)
        .ok_or_else(|| msg("missing native bridge layout"))
}

pub(crate) fn bind_pe_guarded() -> Result<PeTlsGuard> {
    let mut tls = PE_TLS
        .get()
        .ok_or_else(|| msg("native guarded profile requires PE TLS"))?;
    tls.guarded = true;
    Ok(PeTlsGuard {
        previous: PE_TLS.replace(Some(tls)),
        _thread: PhantomData,
    })
}

pub(super) fn pe_guarded() -> bool {
    PE_TLS.get().is_some_and(|tls| tls.guarded)
}

pub(super) fn pe_tls_bound() -> bool {
    PE_TLS.get().is_some()
}

fn emit_pe_tls(
    a: &mut CodeAssembler,
    dest: AsmRegister64,
    rex: u8,
    modrm: u8,
    index: u64,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    // GS belongs to Windows. Read its TLS vector and index into the OS-owned
    // slot. XMM5 is volatile in the integer Win64 profile. A scratch push
    // here could overwrite the lifted guest's saved registers on its stack.
    go(a.movq(xmm5, r10))?;
    go(a.db(&gs_disp(rex, 0x8B, modrm, PE_TLS_VECTOR)))?;
    crate::loader::emit_image_address(a, iced_x86::Register::R10, index)?;
    go(a.mov(r10d, dword_ptr(r10)))?;
    go(a.mov(dest, qword_ptr(dest + r10 * 8)))?;
    go(a.movq(r10, xmm5))?;
    Ok(())
}

fn emit_chain(a: &mut CodeAssembler, dest: AsmRegister64, rex: u8, modrm: u8) -> Result<()> {
    match PE_TLS.get() {
        Some(tls) => emit_pe_tls(a, dest, rex, modrm, tls.index),
        None => a.db(&gs_mem(rex, 0x8B, modrm)).map_err(ice),
    }
}

/// Absolute `gs:[disp32]`. ModRM `rm=101` is RIP-relative even with a GS prefix,
/// so the address uses a SIB with no base and no index.
fn gs_disp(rex: u8, opcode: u8, modrm: u8, disp: i32) -> [u8; 9] {
    let disp = (disp as u32).to_le_bytes();
    [
        0x65, rex, opcode, modrm, 0x25, disp[0], disp[1], disp[2], disp[3],
    ]
}

fn gs_mem(rex: u8, opcode: u8, modrm: u8) -> [u8; 9] {
    gs_disp(rex, opcode, modrm, GS_CHAIN_PTR)
}

pub(super) fn emit_load_rax(a: &mut CodeAssembler) -> Result<()> {
    emit_chain(a, rax, 0x48, 0x04)
}

pub(super) fn emit_store_rax(a: &mut CodeAssembler) -> Result<()> {
    a.db(&gs_mem(0x48, 0x89, 0x04)).map_err(ice)
}

pub(super) fn emit_load_r8(a: &mut CodeAssembler) -> Result<()> {
    emit_chain(a, r8, 0x4C, 0x04)
}

pub(super) fn emit_load_r11(a: &mut CodeAssembler) -> Result<()> {
    emit_chain(a, r11, 0x4C, 0x1C)
}

fn emit_gs_r11(a: &mut CodeAssembler, disp: i32) -> Result<()> {
    a.db(&gs_disp(0x4C, 0x8B, 0x1C, disp)).map_err(ice)
}

pub(super) fn emit_load_r15(a: &mut CodeAssembler) -> Result<()> {
    emit_chain(a, r15, 0x4C, 0x3C)
}

pub(super) fn emit_lock_xadd(a: &mut CodeAssembler) -> Result<()> {
    a.db(&[0xF0, 0x0F, 0xC1, 0x01]).map_err(ice)
}

/// Claim a pool slot when this thread has no chain block yet.
///
/// Guest registers and flags are preserved. A full pool returns `0xbad1`.
pub(super) fn emit_bind_chain(a: &mut CodeAssembler, chains: u64) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    if pe_tls_bound() {
        return Ok(());
    }
    let mut ready = a.create_label();
    let mut full = a.create_label();
    go(a.pushfq())?;
    go(a.push(rax))?;
    go(a.push(rcx))?;
    go(a.push(rdx))?;
    emit_load_rax(a)?;
    go(a.test(rax, rax))?;
    go(a.jnz(ready))?;
    go(a.mov(rcx, chains as i64))?;
    go(a.mov(eax, 1u32))?;
    emit_lock_xadd(a)?;
    go(a.cmp(eax, CHAIN_SLOTS as u32))?;
    go(a.jae(full))?;
    go(a.imul_3(eax, eax, CHAIN_BYTES as i32))?;
    go(a.add(rax, rcx))?;
    go(a.add(rax, 8i32))?;
    zero_block(a)?;
    emit_store_rax(a)?;
    go(a.jmp(ready))?;
    go(a.set_label(&mut full))?;
    go(a.pop(rdx))?;
    go(a.pop(rcx))?;
    go(a.pop(rax))?;
    go(a.popfq())?;
    go(a.mov(eax, 0xbad1u32))?;
    go(a.ret())?;
    go(a.set_label(&mut ready))?;
    go(a.pop(rdx))?;
    go(a.pop(rcx))?;
    go(a.pop(rax))?;
    go(a.popfq())?;
    Ok(())
}

fn zero_block(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut step = a.create_label();
    let mut done = a.create_label();
    // The pool slot is filled with 0xA5 so it is not a pointer table. A fresh
    // context must not inherit that fill as a nest level or a cache pointer.
    go(a.push(rcx))?;
    go(a.push(rdx))?;
    go(a.xor(ecx, ecx))?;
    go(a.xor(edx, edx))?;
    go(a.set_label(&mut step))?;
    go(a.cmp(ecx, CHAIN_BYTES as u32))?;
    go(a.jae(done))?;
    go(a.mov(byte_ptr(rax + rcx), dl))?;
    go(a.inc(ecx))?;
    go(a.jmp(step))?;
    go(a.set_label(&mut done))?;
    go(a.pop(rdx))?;
    go(a.pop(rcx))?;
    Ok(())
}

fn push_claim(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.pushfq())?;
    go(a.push(rax))?;
    go(a.push(rcx))?;
    go(a.push(rdx))?;
    go(a.push(rsi))?;
    go(a.push(rdi))?;
    go(a.push(r8))?;
    go(a.push(r9))?;
    go(a.push(r10))?;
    go(a.push(r11))?;
    Ok(())
}

fn pop_claim(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.pop(r11))?;
    go(a.pop(r10))?;
    go(a.pop(r9))?;
    go(a.pop(r8))?;
    go(a.pop(rdi))?;
    go(a.pop(rsi))?;
    go(a.pop(rdx))?;
    go(a.pop(rcx))?;
    go(a.pop(rax))?;
    go(a.popfq())?;
    Ok(())
}

/// Give this thread a private GS page when it still shares someone else's base.
///
/// Guest registers are restored on both paths. Failure jumps to `fail`.
pub(super) fn emit_claim_gs(a: &mut CodeAssembler, fail: &CodeLabel) -> Result<()> {
    if let Some(tls) = PE_TLS.get() {
        return emit_check_pe_tls(a, tls.index, fail);
    }
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut alloc = a.create_label();
    let mut ready = a.create_label();
    let mut bail = a.create_label();
    let mut done = a.create_label();
    push_claim(a)?;
    go(a.xor(r9d, r9d))?;
    read_gs_base(a)?;
    go(a.test(rax, rax))?;
    go(a.jz(alloc))?;
    go(a.mov(r9, rax))?;
    note_owner(a, &mut alloc, &mut ready)?;
    go(a.set_label(&mut alloc))?;
    map_gs_page(a, &mut bail)?;
    go(a.set_label(&mut ready))?;
    pop_claim(a)?;
    go(a.jmp(done))?;
    go(a.set_label(&mut bail))?;
    pop_claim(a)?;
    go(a.jmp(*fail))?;
    go(a.set_label(&mut done))?;
    Ok(())
}

fn emit_check_pe_tls(a: &mut CodeAssembler, index: u64, fail: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut bad = a.create_label();
    let mut done = a.create_label();
    go(a.pushfq())?;
    go(a.push(rax))?;
    go(a.db(&gs_disp(0x48, 0x8B, 0x04, PE_TLS_VECTOR)))?;
    go(a.test(rax, rax))?;
    go(a.jz(bad))?;
    emit_pe_tls(a, rax, 0x48, 0x04, index)?;
    go(a.test(rax, rax))?;
    go(a.jz(bad))?;
    go(a.cmp(dword_ptr(rax + CTX_LEVEL), TRAMP_SLOTS as u32))?;
    go(a.ja(bad))?;
    go(a.pop(rax))?;
    go(a.popfq())?;
    go(a.jmp(done))?;
    go(a.set_label(&mut bad))?;
    go(a.pop(rax))?;
    go(a.popfq())?;
    go(a.jmp(*fail))?;
    go(a.set_label(&mut done))?;
    go(a.nop())
}

fn read_gs_base(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    // `ARCH_GET_GS` writes the base to `[rsi]`. A zero base must not be read
    // through `gs:`, or the first instruction on a fresh thread faults.
    go(a.sub(rsp, 8i32))?;
    go(a.xor(eax, eax))?;
    go(a.mov(qword_ptr(rsp), rax))?;
    go(a.mov(eax, 158u32))?;
    go(a.mov(edi, 0x1004u32))?;
    go(a.mov(rsi, rsp))?;
    go(a.syscall())?;
    go(a.mov(rax, qword_ptr(rsp)))?;
    go(a.add(rsp, 8i32))?;
    Ok(())
}

fn note_owner(a: &mut CodeAssembler, alloc: &mut CodeLabel, ready: &mut CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(r8, qword_ptr(r9 + GS_TID)))?;
    go(a.mov(eax, 186u32))?;
    go(a.syscall())?;
    go(a.cmp(rax, r8))?;
    go(a.jne(*alloc))?;
    go(a.mov(rax, qword_ptr(r9 + GS_FRAME_PTR)))?;
    go(a.test(rax, rax))?;
    go(a.jz(*alloc))?;
    go(a.jmp(*ready))?;
    Ok(())
}

fn map_gs_page(a: &mut CodeAssembler, bail: &mut CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    // `r9` is the previous GS base. `mmap` needs that register as the offset.
    go(a.push(r9))?;
    go(a.mov(eax, 9u32))?;
    go(a.xor(edi, edi))?;
    go(a.mov(esi, GS_MAP_BYTES as u32))?;
    go(a.mov(edx, 3u32))?;
    go(a.mov(r10d, 0x22u32))?;
    go(a.mov(r8, -1i64))?;
    go(a.xor(r9d, r9d))?;
    go(a.syscall())?;
    go(a.pop(r9))?;
    go(a.test(rax, rax))?;
    go(a.js(*bail))?;
    fill_gs_page(a, bail)
}

fn copy_peb(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut done = a.create_label();
    // A fresh page is its own PEB until an older GS page names a real one.
    // The chain pointer stays private either way.
    go(a.mov(qword_ptr(r11 + 0x60i32), r11))?;
    go(a.test(r9, r9))?;
    go(a.jz(done))?;
    go(a.mov(rax, qword_ptr(r9 + 0x60i32)))?;
    go(a.test(rax, rax))?;
    go(a.jz(done))?;
    go(a.mov(qword_ptr(r11 + 0x60i32), rax))?;
    go(a.set_label(&mut done))?;
    Ok(())
}

fn fill_gs_page(a: &mut CodeAssembler, bail: &mut CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(r11, rax))?;
    copy_peb(a)?;
    go(a.lea(rcx, qword_ptr(r11 + GS_FRAME_AT as i32)))?;
    go(a.mov(qword_ptr(r11 + GS_FRAME_PTR), rcx))?;
    // `gettid` clobbers `r11`. The page pointer has to survive it.
    go(a.push(r11))?;
    go(a.mov(eax, 186u32))?;
    go(a.syscall())?;
    go(a.pop(r11))?;
    go(a.mov(qword_ptr(r11 + GS_TID), rax))?;
    go(a.mov(rsi, r11))?;
    go(a.mov(eax, 158u32))?;
    go(a.mov(edi, 0x1001u32))?;
    go(a.syscall())?;
    go(a.test(rax, rax))?;
    go(a.jnz(*bail))?;
    Ok(())
}

/// Load this thread's frame into `r11`, or `fallback` when the page has none.
pub(super) fn emit_load_frame(a: &mut CodeAssembler, fallback: u64) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    if let Some(tls) = PE_TLS.get() {
        emit_pe_tls(a, r11, 0x4C, 0x1C, tls.index)?;
        go(a.movq(xmm5, r10))?;
        go(a.mov(r10d, dword_ptr(r11 + CTX_LEVEL)))?;
        go(a.imul_3(r10d, r10d, PE_FRAME_STRIDE))?;
        go(a.lea(r11, qword_ptr(r11 + r10 + PE_FRAME_BASE)))?;
        return go(a.movq(r10, xmm5));
    }
    let mut have = a.create_label();
    emit_gs_r11(a, GS_FRAME_PTR)?;
    go(a.test(r11, r11))?;
    go(a.jnz(have))?;
    go(a.mov(r11, fallback as i64))?;
    go(a.set_label(&mut have))?;
    Ok(())
}

/// Recover the caller's current Win64 frame after a native call returns.
pub(super) fn emit_load_active_pe_frame(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    emit_load_rax(a)?;
    go(a.movq(xmm5, r10))?;
    go(a.mov(r10d, dword_ptr(rax + CTX_LEVEL)))?;
    go(a.imul_3(r10d, r10d, PE_FRAME_STRIDE))?;
    go(a.lea(
        rax,
        qword_ptr(rax + r10 + (PE_FRAME_BASE - PE_FRAME_STRIDE)),
    ))?;
    go(a.movq(r10, xmm5))
}

fn slot_addr(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    // `ecx` is the 1-based level. The record is `(level - 1) * stride`.
    go(a.mov(edx, ecx))?;
    go(a.dec(edx))?;
    go(a.imul_3(edx, edx, TRAMP_STRIDE))?;
    go(a.lea(r8, qword_ptr(rax + TRAMP_SAVE)))?;
    go(a.add(r8, rdx))?;
    Ok(())
}

fn save_outer_slot(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.push(rdx))?;
    go(a.push(r8))?;
    go(a.push(rsi))?;
    slot_addr(a)?;
    copy_key(a, true)?;
    go(a.mov(edx, dword_ptr(rax + CHAIN_FOLD)))?;
    go(a.mov(dword_ptr(r8 + CHAIN_FOLD), edx))?;
    go(a.mov(rsi, qword_ptr(rax + CTX_DEPTH)))?;
    go(a.mov(qword_ptr(r8 + TRAMP_DEPTH), rsi))?;
    go(a.pop(rsi))?;
    go(a.pop(r8))?;
    go(a.pop(rdx))?;
    Ok(())
}

fn copy_key(a: &mut CodeAssembler, to_slot: bool) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    for word in 0..4i32 {
        if to_slot {
            go(a.mov(rsi, qword_ptr(rax + (word * 8))))?;
            go(a.mov(qword_ptr(r8 + (word * 8)), rsi))?;
        } else {
            go(a.mov(rsi, qword_ptr(r8 + (word * 8))))?;
            go(a.mov(qword_ptr(rax + (word * 8)), rsi))?;
        }
    }
    Ok(())
}

fn restore_outer_slot(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    slot_addr(a)?;
    copy_key(a, false)?;
    go(a.mov(edx, dword_ptr(r8 + CHAIN_FOLD)))?;
    go(a.mov(dword_ptr(rax + CHAIN_FOLD), edx))?;
    go(a.mov(rsi, qword_ptr(r8 + TRAMP_DEPTH)))?;
    go(a.mov(qword_ptr(rax + CTX_DEPTH), rsi))?;
    Ok(())
}

/// Save a live outer key when this thread re-enters through the trampoline.
pub(super) fn emit_enter_nest(a: &mut CodeAssembler, fail: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut fresh = a.create_label();
    emit_load_rax(a)?;
    go(a.mov(ecx, dword_ptr(rax + CTX_LEVEL)))?;
    go(a.test(ecx, ecx))?;
    go(a.jz(fresh))?;
    go(a.cmp(ecx, TRAMP_SLOTS as u32))?;
    go(a.ja(*fail))?;
    save_outer_slot(a)?;
    go(a.set_label(&mut fresh))?;
    go(a.inc(ecx))?;
    go(a.mov(dword_ptr(rax + CTX_LEVEL), ecx))?;
    go(a.xor(edx, edx))?;
    go(a.mov(qword_ptr(rax + CTX_DEPTH), rdx))?;
    Ok(())
}

/// Drop one trampoline entry and put the outer key back when one remains.
pub(super) fn emit_leave_nest(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut done = a.create_label();
    emit_load_rax(a)?;
    go(a.mov(ecx, dword_ptr(rax + CTX_LEVEL)))?;
    go(a.test(ecx, ecx))?;
    go(a.jz(done))?;
    go(a.dec(ecx))?;
    go(a.mov(dword_ptr(rax + CTX_LEVEL), ecx))?;
    go(a.test(ecx, ecx))?;
    go(a.jz(done))?;
    restore_outer_slot(a)?;
    go(a.set_label(&mut done))?;
    Ok(())
}

pub(super) fn emit_clear_idle_key(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut done = a.create_label();
    emit_load_rax(a)?;
    go(a.cmp(dword_ptr(rax + CTX_LEVEL), 0i32))?;
    go(a.jne(done))?;
    go(a.xor(ecx, ecx))?;
    for offset in [0, 8, 16, 24, CHAIN_FOLD, CTX_DEPTH] {
        go(a.mov(qword_ptr(rax + offset), rcx))?;
    }
    go(a.set_label(&mut done))?;
    go(a.nop())
}

fn push_bind(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.push(rax))?;
    go(a.push(rcx))?;
    go(a.push(rdx))?;
    go(a.push(rsi))?;
    go(a.push(rdi))?;
    go(a.push(r8))?;
    go(a.push(r9))?;
    go(a.push(r10))?;
    go(a.push(r11))?;
    go(a.push(r15))?;
    Ok(())
}

fn pop_bind(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.pop(r15))?;
    go(a.pop(r11))?;
    go(a.pop(r10))?;
    go(a.pop(r9))?;
    go(a.pop(r8))?;
    go(a.pop(rdi))?;
    go(a.pop(rsi))?;
    go(a.pop(rdx))?;
    go(a.pop(rcx))?;
    go(a.pop(rax))?;
    Ok(())
}

/// Point this thread's cache and key table at a private copy of `r13`.
///
/// `rbx`, `r13`, `r14`, and `rdx` stay put. Failure jumps to `fail`.
pub(super) fn emit_bind_fn(a: &mut CodeAssembler, fail: &CodeLabel, external: bool) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut scan = a.create_label();
    let mut alloc = a.create_label();
    let mut hit = a.create_label();
    let mut done = a.create_label();
    let mut bail = a.create_label();
    let mut leave = a.create_label();
    push_bind(a)?;
    if external {
        go(a.cmp(dword_ptr(r13 + crate::vm::RT_FOLD), 0i32))?;
        go(a.je(bail))?;
    }
    emit_load_r15(a)?;
    go(a.mov(rax, qword_ptr(r15 + CTX_BOUND)))?;
    go(a.cmp(rax, r13))?;
    go(a.jne(scan))?;
    go(a.mov(rax, qword_ptr(r15 + CTX_CACHE)))?;
    go(a.test(rax, rax))?;
    go(a.jnz(done))?;
    go(a.set_label(&mut scan))?;
    go(a.xor(ecx, ecx))?;
    scan_map(a, &mut alloc, &mut hit, &mut bail)?;
    go(a.set_label(&mut alloc))?;
    alloc_cache(a, &bail, external)?;
    go(a.jmp(done))?;
    go(a.set_label(&mut hit))?;
    install_slot(a)?;
    go(a.set_label(&mut done))?;
    pop_bind(a)?;
    go(a.jmp(leave))?;
    go(a.set_label(&mut bail))?;
    pop_bind(a)?;
    go(a.jmp(*fail))?;
    go(a.set_label(&mut leave))?;
    Ok(())
}

fn scan_map(
    a: &mut CodeAssembler,
    alloc: &mut CodeLabel,
    hit: &mut CodeLabel,
    miss: &mut CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut step = a.create_label();
    go(a.set_label(&mut step))?;
    go(a.cmp(ecx, CTX_MAP_SLOTS as u32))?;
    go(a.jae(*miss))?;
    go(a.imul_3(eax, ecx, CTX_MAP_STRIDE))?;
    go(a.lea(r8, qword_ptr(r15 + CTX_MAP)))?;
    go(a.add(r8, rax))?;
    go(a.mov(rax, qword_ptr(r8)))?;
    go(a.cmp(rax, r13))?;
    go(a.je(*hit))?;
    go(a.test(rax, rax))?;
    go(a.jz(*alloc))?;
    go(a.inc(ecx))?;
    go(a.jmp(step))?;
    Ok(())
}

fn install_slot(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(rax, qword_ptr(r8 + 8i32)))?;
    go(a.mov(qword_ptr(r15 + CTX_CACHE), rax))?;
    go(a.mov(rax, qword_ptr(r8 + 16i32)))?;
    go(a.mov(qword_ptr(r15 + CTX_KEYS), rax))?;
    go(a.mov(qword_ptr(r15 + CTX_BOUND), r13))?;
    Ok(())
}

fn alloc_cache(a: &mut CodeAssembler, bail: &CodeLabel, external: bool) -> Result<()> {
    measure_cache(a, bail, external)?;
    if let Some(tls) = PE_TLS.get() {
        emit_pe_cache(a, tls.bytes, bail)?;
    } else {
        alloc_linux_cache(a, bail, external)?;
    }
    remember_cache(a)?;
    Ok(())
}

fn emit_pe_cache(a: &mut CodeAssembler, bytes: u32, bail: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(eax, dword_ptr(r13 + WEAVE_SAVE)))?;
    go(a.cmp(eax, PE_TLS_CACHE_BASE as u32))?;
    go(a.jb(*bail))?;
    go(a.lea(rcx, qword_ptr(rax + r11)))?;
    go(a.cmp(rcx, bytes as i32))?;
    go(a.ja(*bail))?;
    go(a.add(rax, r15))
}

fn measure_cache(a: &mut CodeAssembler, bail: &CodeLabel, external: bool) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut sum = a.create_label();
    let mut summed = a.create_label();
    go(a.mov(rax, qword_ptr(r13)))?;
    go(a.cmp(rax, crate::vm::NATIVE_MAX_RUNTIME_INSNS as i32))?;
    go(a.ja(*bail))?;
    go(a.mov(r9, rax))?;
    go(a.shl(r9, 5u32))?;
    go(a.mov(r10, qword_ptr(r13 + 32i32)))?;
    if external {
        check_external_lengths(a, bail)?;
    }
    go(a.xor(ecx, ecx))?;
    go(a.xor(edx, edx))?;
    go(a.set_label(&mut sum))?;
    go(a.cmp(rcx, rax))?;
    go(a.jae(summed))?;
    go(a.add(edx, dword_ptr(r10 + rcx * 4)))?;
    go(a.jc(*bail))?;
    go(a.inc(ecx))?;
    go(a.jmp(sum))?;
    go(a.set_label(&mut summed))?;
    if external {
        check_external_sum(a, bail)?;
    }
    go(a.mov(r11, rax))?;
    go(a.add(r11, rdx))?;
    go(a.add(r11, r9))?;
    Ok(())
}

fn check_external_lengths(a: &mut CodeAssembler, bail: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.lea(rcx, qword_ptr(r13 + crate::vm::TABLES_AT)))?;
    go(a.cmp(r10, rcx))?;
    go(a.jb(*bail))?;
    go(a.lea(rcx, qword_ptr(rax * 4)))?;
    go(a.add(rcx, r10))?;
    go(a.jc(*bail))?;
    go(a.mov(rdx, r13))?;
    go(a.add(rdx, crate::vm::RUNTIME_WINDOW as i32))?;
    go(a.jc(*bail))?;
    go(a.cmp(rcx, rdx))?;
    go(a.ja(*bail))
}

fn check_external_sum(a: &mut CodeAssembler, bail: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(ecx, dword_ptr(r13 + crate::vm::RT_FOLD)))?;
    go(a.cmp(ecx, edx))?;
    go(a.jne(*bail))?;
    go(a.cmp(ecx, crate::vm::RUNTIME_WINDOW as u32))?;
    go(a.ja(*bail))
}

fn alloc_linux_cache(a: &mut CodeAssembler, bail: &CodeLabel, external: bool) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    if !external {
        return mmap_cache(a, bail);
    }
    go(a.add(r11, 8i32))?;
    go(a.jc(*bail))?;
    mmap_cache(a, bail)?;
    // External cache allocations prefix the independent mapped data capacity.
    // Existing key and data pointers still reference their original regions.
    go(a.mov(rdx, r11))?;
    go(a.sub(rdx, r9))?;
    go(a.sub(rdx, 8i32))?;
    go(a.mov(qword_ptr(rax), rdx))?;
    go(a.add(rax, 8i32))
}

fn mmap_cache(a: &mut CodeAssembler, bail: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    // `r11` is the byte count. `syscall` clobbers `rcx` and `r11`, so the
    // size and the map slot ride on the stack across the call.
    go(a.push(r8))?;
    go(a.push(r9))?;
    go(a.push(r15))?;
    go(a.push(r13))?;
    go(a.push(r11))?;
    go(a.mov(rsi, r11))?;
    go(a.mov(eax, 9u32))?;
    go(a.xor(edi, edi))?;
    go(a.mov(edx, 3u32))?;
    go(a.mov(r10d, 0x22u32))?;
    go(a.mov(r8, -1i64))?;
    go(a.xor(r9d, r9d))?;
    go(a.syscall())?;
    go(a.pop(r11))?;
    go(a.pop(r13))?;
    go(a.pop(r15))?;
    go(a.pop(r9))?;
    go(a.pop(r8))?;
    go(a.test(rax, rax))?;
    go(a.js(*bail))?;
    Ok(())
}

fn remember_cache(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    // `rax` is the mapping. Keys sit at the front, plaintext flags after them.
    go(a.mov(qword_ptr(r8 + 16i32), rax))?;
    go(a.add(rax, r9))?;
    go(a.mov(qword_ptr(r8 + 8i32), rax))?;
    go(a.mov(qword_ptr(r8), r13))?;
    install_slot(a)?;
    Ok(())
}

/// `r11` is the chain. `r8` becomes the key table for the current block.
pub(super) fn emit_keys_r8(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut have = a.create_label();
    go(a.mov(r8, qword_ptr(r11 + CTX_KEYS)))?;
    go(a.test(r8, r8))?;
    go(a.jnz(have))?;
    go(a.mov(r8, qword_ptr(r13 + crate::vm::RT_KEYS)))?;
    go(a.set_label(&mut have))?;
    Ok(())
}

/// `r10` becomes this thread's instruction cache, falling back to the runtime.
pub(super) fn emit_cache_r10(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut have = a.create_label();
    emit_load_r8(a)?;
    go(a.mov(r10, qword_ptr(r8 + CTX_CACHE)))?;
    go(a.test(r10, r10))?;
    go(a.jnz(have))?;
    go(a.mov(r10, qword_ptr(r13 + 8i32)))?;
    go(a.mov(qword_ptr(r8 + CTX_CACHE), r10))?;
    go(a.set_label(&mut have))?;
    Ok(())
}

/// Copy the function salt into this thread's nonce and set the block index.
pub(super) fn emit_nonce(a: &mut CodeAssembler, index_is_r14: bool) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    emit_load_r15(a)?;
    if index_is_r14 {
        go(a.mov(dword_ptr(r15 + CTX_INDEX), r14d))?;
    }
    go(a.mov(eax, dword_ptr(r13 + crate::vm::RT_SALT)))?;
    go(a.mov(dword_ptr(r15 + CTX_SALT), eax))?;
    go(a.mov(eax, dword_ptr(r13 + (crate::vm::RT_SALT + 4))))?;
    go(a.mov(dword_ptr(r15 + (CTX_SALT + 4)), eax))?;
    go(a.mov(eax, dword_ptr(r13 + crate::vm::RT_INDEX)))?;
    go(a.xor(dword_ptr(r15 + CTX_SALT), eax))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::emu::{bare, Machine, Policy, Region, GS_BASE, SENTINEL};
    use crate::ir::{Block, Exit, FuncIr, MemIo, Op, RAX};
    use crate::stub::{
        assemble_resume, assemble_trampoline, assemble_vm, place_runtime, Resume, Trampoline,
    };
    use crate::vm::{
        exec_image, plain_insn, runtime_fits, BcImage, CHAIN_BYTES, CHAIN_FOLD, CTX_DEPTH,
        CTX_LEVEL, GS_CHAIN_AT, GS_CHAIN_PTR, RT_FOLD, RT_KEY, RUNTIME_WINDOW, WEAVE_FRAME,
        WEAVE_SAVE,
    };

    use super::gs_mem;

    fn decode(bytes: &[u8]) -> Instruction {
        let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
        let insn = decoder.decode();
        assert!(!insn.is_invalid());
        assert_eq!(insn.len(), bytes.len());
        insn
    }

    #[test]
    fn native_pe_trampoline_reads_os_tls_without_raw_syscalls() {
        let index = super::PE_TLS_PROBE_INDEX;
        let _tls = super::bind_pe_tls(index, super::PE_TLS_LIMIT as u32);
        let origin = 0x1400_01000;
        let bytes = assemble_trampoline(&Trampoline {
            origin,
            frame: origin + 0x1000,
            runtime: origin + 0x2000,
            entry: 0,
            dispatch: origin + 0x3000,
            image_base: origin - 0x1000,
            chains: origin + 0x4000,
        })
        .unwrap();
        let mut reads = 0;
        for insn in Decoder::with_ip(64, &bytes, origin, DecoderOptions::NONE) {
            assert!(!insn.is_invalid());
            assert_ne!(insn.mnemonic(), Mnemonic::Syscall);
            if insn.segment_prefix() == Register::GS {
                assert_eq!(insn.op1_kind(), OpKind::Memory);
                assert_eq!(insn.memory_displacement64(), super::PE_TLS_VECTOR as u64);
                reads += 1;
            }
        }
        assert!(reads > 0);
    }

    #[test]
    fn gs_chain_ops_match_the_decoder() {
        let load = decode(&gs_mem(0x48, 0x8B, 0x04));
        assert_eq!(load.mnemonic(), Mnemonic::Mov);
        assert_eq!(load.op0_register(), Register::RAX);
        assert_eq!(load.memory_base(), Register::None);
        assert_eq!(load.memory_segment(), Register::GS);
        assert_eq!(load.memory_displacement64(), u64::from(GS_CHAIN_PTR as u32));
        let r11 = decode(&gs_mem(0x4C, 0x8B, 0x1C));
        assert_eq!(r11.op0_register(), Register::R11);
        assert_eq!(r11.memory_segment(), Register::GS);
        let r15 = decode(&gs_mem(0x4C, 0x8B, 0x3C));
        assert_eq!(r15.op0_register(), Register::R15);
        let r8 = decode(&gs_mem(0x4C, 0x8B, 0x04));
        assert_eq!(r8.op0_register(), Register::R8);
        let store = decode(&gs_mem(0x48, 0x89, 0x04));
        assert_eq!(store.op0_kind(), OpKind::Memory);
        assert_eq!(store.op1_register(), Register::RAX);
        assert_eq!(store.memory_displacement64(), 0x190);
        let xadd = decode(&[0xF0, 0x0F, 0xC1, 0x01]);
        assert!(xadd.has_lock_prefix());
        assert_eq!(xadd.mnemonic(), Mnemonic::Xadd);
        assert_eq!(xadd.op1_register(), Register::EAX);
    }

    fn read_u64(machine: &Machine, at: u64) -> u64 {
        let bytes = machine.read(at, 8).unwrap();
        u64::from_le_bytes(bytes.try_into().unwrap())
    }

    fn point(machine: &mut Machine, at: u64) {
        machine
            .write(GS_BASE + GS_CHAIN_PTR as u64, &at.to_le_bytes())
            .unwrap();
    }

    fn chain_at(index: usize) -> u64 {
        GS_BASE + GS_CHAIN_AT as u64 + index as u64 * CHAIN_BYTES as u64
    }

    fn key_of(machine: &Machine) -> [u8; 32] {
        let at = read_u64(machine, machine.gs + GS_CHAIN_PTR as u64);
        machine.read(at, 32).unwrap().try_into().unwrap()
    }

    fn depth_of(machine: &Machine) -> u64 {
        let at = read_u64(machine, machine.gs + GS_CHAIN_PTR as u64);
        read_u64(machine, at + CTX_DEPTH as u64)
    }

    fn live_ptr(machine: &Machine) -> u64 {
        read_u64(machine, machine.gs + GS_CHAIN_PTR as u64)
    }

    fn key_at(machine: &Machine, at: u64) -> [u8; 32] {
        machine.read(at, 32).unwrap().try_into().unwrap()
    }

    fn fold_at(machine: &Machine, at: u64) -> u32 {
        let bytes = machine.read(at + CHAIN_FOLD as u64, 4).unwrap();
        u32::from_le_bytes(bytes.try_into().unwrap())
    }

    fn block_of(machine: &Machine, at: u64) -> Vec<u8> {
        machine.read(at, CHAIN_BYTES).unwrap()
    }

    struct Fix {
        origin: u64,
        base: u64,
        vm: crate::stub::NativeVm,
        image: BcImage,
        machine: Machine,
    }

    fn crc_of(image: &BcImage, index: usize) -> u32 {
        let func = &image.funcs[index];
        let mut crc = 0u32;
        for slot in 0..func.insns.len() {
            let plain = plain_insn(func, slot, &image.inv).unwrap();
            if plain.first() == Some(&0x60) && plain.len() >= 5 {
                crc = u32::from_le_bytes(plain[1..5].try_into().unwrap());
            }
        }
        crc
    }

    fn install(fix: &mut Fix) {
        let image = &fix.image;
        let table_at = fix.base + image.funcs.len() as u64 * RUNTIME_WINDOW;
        let mut cursor = table_at + 0x1000;
        let mut table = Vec::new();
        table.extend((image.funcs.len() as u32).to_le_bytes());
        for (index, func) in image.funcs.iter().enumerate() {
            let runtime = fix.base + index as u64 * RUNTIME_WINDOW;
            place_runtime(
                func,
                &image.inv,
                crc_of(image, index),
                &image.slots,
                image.handler_mix,
                &mut fix.machine,
                runtime,
                cursor,
            )
            .unwrap();
            cursor += func.insns.len() as u64 * 32;
            table.extend(func.rva.to_le_bytes());
            table.extend(func.entry.to_le_bytes());
            table.extend(runtime.to_le_bytes());
        }
        fix.machine.write(table_at, &table).unwrap();
        fix.machine
            .write(fix.origin + fix.vm.calls as u64, &table_at.to_le_bytes())
            .unwrap();
    }

    fn fixture(funcs: &[FuncIr]) -> Fix {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let image = crate::vm::lower_image(funcs, &mut rng).unwrap();
        let origin = 0x400000u64;
        let vm = assemble_vm(origin).unwrap();
        let base = 0x500000u64;
        let mut machine = bare(Policy::default()).unwrap();
        machine.regions.push(Region {
            base: origin,
            data: vm.bytes.clone(),
        });
        let keys: usize = image.funcs.iter().map(|func| func.insns.len() * 32).sum();
        let span = image.funcs.len() * RUNTIME_WINDOW as usize + 0x1000 + keys;
        machine.regions.push(Region {
            base,
            data: vec![0; span],
        });
        let mut fix = Fix {
            origin,
            base,
            vm,
            image,
            machine,
        };
        install(&mut fix);
        fix
    }

    fn park(machine: &mut Machine) {
        let rsp = machine.regs[4].wrapping_sub(8);
        machine.write(rsp, &SENTINEL.to_le_bytes()).unwrap();
        machine.regs[4] = rsp;
    }

    fn launch(fix: &mut Fix, index: usize, resume: bool) {
        let entry = fix.image.funcs[index].entry;
        let runtime = fix.base + index as u64 * RUNTIME_WINDOW;
        let frame = fix.origin + fix.vm.frame as u64;
        let slot = u64::from(fix.image.slots.arch(4));
        fix.machine.exit_code = None;
        fix.machine
            .write(frame + slot * 8, &fix.machine.regs[4].to_le_bytes())
            .unwrap();
        fix.machine.regs[3] = frame;
        fix.machine.regs[13] = runtime;
        fix.machine.regs[14] = u64::from(entry);
        let at = if resume {
            fix.vm.resume
        } else {
            fix.vm.dispatch
        };
        fix.machine.rip = fix.origin + at as u64;
        fix.machine.run().unwrap();
    }

    fn prime(fix: &mut Fix, index: usize) {
        let entry = fix.image.funcs[index].entry;
        let runtime = fix.base + index as u64 * RUNTIME_WINDOW;
        let frame = fix.origin + fix.vm.frame as u64;
        let slot = u64::from(fix.image.slots.arch(4));
        fix.machine.exit_code = None;
        fix.machine
            .write(frame + slot * 8, &fix.machine.regs[4].to_le_bytes())
            .unwrap();
        fix.machine.regs[3] = frame;
        fix.machine.regs[13] = runtime;
        fix.machine.regs[14] = u64::from(entry);
        fix.machine.rip = fix.origin + fix.vm.dispatch as u64;
    }

    fn exec_rax(image: &BcImage) -> u64 {
        let mut arch = [0u64; 16];
        let mut flags = crate::flags::Flags::default();
        let mut mem = crate::ir::MapMem::default();
        let mut host =
            |_: &mut [u64; 16], _: &mut crate::flags::Flags, _: &mut dyn MemIo, _: u64| Ok(());
        exec_image(image, 0, &mut arch, &mut flags, &mut mem, 0, &mut host).unwrap();
        arch[0]
    }

    fn assert_global(fix: &Fix, index: usize) {
        let runtime = fix.base + index as u64 * RUNTIME_WINDOW;
        let key = fix.machine.read(runtime + RT_KEY as u64, 32).unwrap();
        let fold = fix.machine.read(runtime + RT_FOLD as u64, 4).unwrap();
        let save = fix
            .machine
            .read(runtime + WEAVE_SAVE as u64, 32 * WEAVE_FRAME as usize)
            .unwrap();
        assert_eq!(key, fix.image.funcs[index].key.bytes());
        assert_eq!(fold, [0, 0, 0, 0]);
        assert!(save.iter().all(|byte| *byte == 0));
    }

    fn branch() -> FuncIr {
        FuncIr {
            name: "branch".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![
                Block {
                    ops: vec![Op::MovRi(RAX, 1), Op::CmpRi(RAX, 1)],
                    exit: Exit::Jcc(4, 1, 2),
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRi(RAX, 7)],
                    exit: Exit::Ret,
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRi(RAX, 9)],
                    exit: Exit::Ret,
                    opaque: false,
                },
            ],
        }
    }

    fn blob_len(image: &BcImage) -> usize {
        image.funcs[0]
            .insns
            .iter()
            .map(|insn| insn.bytes.len())
            .sum()
    }

    fn flip_cold(fix: &mut Fix) {
        let func = &fix.image.funcs[0];
        let tables = runtime_fits(fix.base, func.insns.len(), blob_len(&fix.image)).unwrap();
        let flags = fix.machine.read(tables.cache, func.insns.len()).unwrap();
        let cold = flags.iter().position(|byte| *byte == 0).expect("cold");
        let off = u32::from_le_bytes(
            fix.machine
                .read(tables.offs + cold as u64 * 4, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let at = tables.blob + u64::from(off);
        let byte = fix.machine.read(at, 1).unwrap()[0] ^ 1;
        fix.machine.write(at, &[byte]).unwrap();
    }

    #[test]
    fn two_contexts_keep_a_corrupt_block_local() {
        let mut fix = fixture(&[branch()]);
        let honest = exec_rax(&fix.image);
        launch(&mut fix, 0, false);
        assert_eq!(fix.machine.regs[0], honest);
        let saved = block_of(&fix.machine, chain_at(0));
        assert_eq!(
            key_at(&fix.machine, chain_at(0)),
            fix.image.funcs[0].terminal
        );
        assert_ne!(fold_at(&fix.machine, chain_at(0)), 0);
        assert_global(&fix, 0);
        flip_cold(&mut fix);
        point(&mut fix.machine, chain_at(1));
        park(&mut fix.machine);
        launch(&mut fix, 0, false);
        assert_eq!(fix.machine.regs[0], 0xbad1);
        assert_eq!(block_of(&fix.machine, chain_at(0)), saved);
        point(&mut fix.machine, chain_at(0));
        park(&mut fix.machine);
        launch(&mut fix, 0, true);
        assert_eq!(fix.machine.regs[0], honest);
        assert_global(&fix, 0);
    }

    #[test]
    fn thread_state_is_not_in_the_result() {
        let mut fix = fixture(&[branch()]);
        let honest = exec_rax(&fix.image);
        launch(&mut fix, 0, false);
        assert_eq!(fix.machine.regs[0], honest);
        let left = key_at(&fix.machine, chain_at(0));
        point(&mut fix.machine, chain_at(1));
        park(&mut fix.machine);
        launch(&mut fix, 0, false);
        assert_eq!(fix.machine.regs[0], honest);
        assert_eq!(left, fix.image.funcs[0].terminal);
        assert_eq!(key_at(&fix.machine, chain_at(1)), left);
        assert_ne!(chain_at(0), chain_at(1));
        assert_global(&fix, 0);
    }

    fn call_pair() -> Vec<FuncIr> {
        vec![
            FuncIr {
                name: "caller".into(),
                rva: 0x1000,
                entry: 0,
                blocks: vec![
                    Block {
                        ops: vec![Op::MovRi(RAX, 1)],
                        exit: Exit::CallRva {
                            rva: 0x2000,
                            next: 1,
                        },
                        opaque: false,
                    },
                    Block {
                        ops: vec![Op::AddRi(RAX, 1)],
                        exit: Exit::Ret,
                        opaque: false,
                    },
                ],
            },
            FuncIr {
                name: "callee".into(),
                rva: 0x2000,
                entry: 0,
                blocks: vec![Block {
                    ops: vec![Op::MovRi(RAX, 5)],
                    exit: Exit::Ret,
                    opaque: false,
                }],
            },
        ]
    }

    fn outer_key_came_back(machine: &mut Machine) -> bool {
        let mut outer = None;
        let mut saw_inner = false;
        let mut differed = false;
        let mut restored = false;
        for _ in 0..2_000_000 {
            if machine.exit_code.is_some() {
                break;
            }
            machine.step().expect("step");
            if machine.exit_code.is_some() {
                break;
            }
            let depth = depth_of(machine);
            let key = key_of(machine);
            if depth == 0 && !saw_inner {
                outer = Some(key);
            } else if depth > 0 {
                saw_inner = true;
                differed |= outer.as_ref().is_some_and(|prev| prev != &key);
            } else if outer.as_ref() == Some(&key) {
                restored = true;
            }
        }
        assert!(machine.exit_code.is_some(), "nested run did not return");
        assert!(saw_inner, "call never entered the callee");
        assert!(differed, "callee reused the outer key");
        restored
    }

    #[test]
    fn nested_call_restores_the_outer_chain() {
        let mut fix = fixture(&call_pair());
        assert_eq!(exec_rax(&fix.image), 6);
        prime(&mut fix, 0);
        assert!(outer_key_came_back(&mut fix.machine));
        assert_eq!(fix.machine.regs[0], 6);
        assert_global(&fix, 0);
        assert_global(&fix, 1);
    }

    fn ret_imm(value: u64) -> FuncIr {
        FuncIr {
            name: "ret".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![Op::MovRi(RAX, value)],
                exit: Exit::Ret,
                opaque: false,
            }],
        }
    }

    fn trampoline_of(fix: &Fix, at: u64) -> Vec<u8> {
        assemble_trampoline(&Trampoline {
            origin: at,
            frame: fix.origin + fix.vm.frame as u64,
            runtime: fix.base,
            entry: fix.image.funcs[0].entry,
            dispatch: fix.origin + fix.vm.dispatch as u64,
            image_base: 0,
            chains: fix.origin + fix.vm.chains as u64,
        })
        .unwrap()
    }

    #[test]
    fn trampoline_claims_one_slot_per_context() {
        let mut fix = fixture(&[ret_imm(0x21)]);
        let at = 0x480000u64;
        let bytes = trampoline_of(&fix, at);
        fix.machine.regions.push(Region {
            base: at,
            data: bytes,
        });
        point(&mut fix.machine, 0);
        fix.machine.rip = at;
        fix.machine.run().unwrap();
        let slot0 = live_ptr(&fix.machine);
        assert_eq!(slot0, fix.origin + fix.vm.chains as u64 + 8);
        assert_eq!(fix.machine.regs[0], 0x21);
        let saved = block_of(&fix.machine, slot0);
        fix.machine
            .write(fix.machine.gs + GS_CHAIN_PTR as u64, &0u64.to_le_bytes())
            .unwrap();
        park(&mut fix.machine);
        fix.machine.exit_code = None;
        fix.machine.rip = at;
        fix.machine.run().unwrap();
        let slot1 = live_ptr(&fix.machine);
        assert_eq!(slot1, slot0 + CHAIN_BYTES as u64);
        assert_eq!(block_of(&fix.machine, slot0), saved);
        assert_eq!(fix.machine.regs[0], 0x21);
        let next = fix
            .machine
            .read(fix.origin + fix.vm.chains as u64, 4)
            .unwrap();
        assert_eq!(next, (2u32).to_le_bytes());
    }

    #[test]
    fn trampoline_reentry_restores_the_outer_key() {
        let mut fix = fixture(&[ret_imm(0x21)]);
        let at = 0x480000u64;
        fix.machine.regions.push(Region {
            base: at,
            data: trampoline_of(&fix, at),
        });
        point(&mut fix.machine, 0);
        fix.machine.rip = at;
        fix.machine.run().unwrap();
        assert_eq!(fix.machine.regs[0], 0x21);
        let slot = live_ptr(&fix.machine);
        poke_reentry(&mut fix.machine, slot);
        park(&mut fix.machine);
        fix.machine.exit_code = None;
        fix.machine.rip = at;
        fix.machine.run().unwrap();
        assert_eq!(fix.machine.regs[0], 0x21);
        assert_eq!(key_at(&fix.machine, slot), [0x5A; 32]);
        assert_eq!(fold_at(&fix.machine, slot), 7);
        assert_eq!(read_u64(&fix.machine, slot + CTX_DEPTH as u64), 3);
        let level = fix.machine.read(slot + CTX_LEVEL as u64, 4).unwrap();
        assert_eq!(level, 1u32.to_le_bytes());
    }

    fn poke_reentry(machine: &mut Machine, slot: u64) {
        machine.write(slot, &[0x5A; 32]).unwrap();
        machine
            .write(slot + CHAIN_FOLD as u64, &7u32.to_le_bytes())
            .unwrap();
        machine
            .write(slot + CTX_DEPTH as u64, &3u64.to_le_bytes())
            .unwrap();
        machine
            .write(slot + CTX_LEVEL as u64, &1u32.to_le_bytes())
            .unwrap();
    }

    #[test]
    fn parallel_threads_keep_a_corrupt_block_local() {
        let staged = stage_parallel();
        let _guard = GsGuard::capture();
        let sync = Arc::new(ParallelSync::new());
        let first = run_entry(staged.tramp);
        let ptr = gs_qword(GS_CHAIN_PTR as u64);
        let block = chain_bytes(ptr);
        let fold = u32::from_le_bytes(block[CHAIN_FOLD as usize..][..4].try_into().unwrap());
        assert_eq!(first, 0x21, "fold={fold} ptr={ptr:#x}");
        let saved = chain_bytes(ptr);
        let parent_base = rdgsbase();
        let child = spawn_child(staged.tramp, Arc::clone(&sync));
        sync.bar_a.wait();
        assert_parent_isolated(ptr, parent_base, &sync);
        flip_blob(staged.blob);
        sync.bar_b.wait();
        let resumed = run_entry(staged.resume);
        child.join().unwrap();
        assert_eq!(resumed, 0x21);
        assert_eq!(sync.second.load(Ordering::SeqCst), 0xbad1);
        assert_eq!(gs_qword(GS_CHAIN_PTR as u64), ptr);
        assert!(
            chain_bytes(ptr) == saved,
            "parent chain changed after resume"
        );
    }

    fn assert_parent_isolated(ptr: u64, parent_base: u64, sync: &ParallelSync) {
        assert_eq!(gs_qword(GS_CHAIN_PTR as u64), ptr);
        assert_ne!(ptr, 0x2222);
        assert_eq!(sync.first.load(Ordering::SeqCst), 0x21);
        let child_base = sync.base.load(Ordering::SeqCst);
        assert_ne!(child_base, 0);
        assert_ne!(child_base, parent_base);
        assert_eq!(rdgsbase(), parent_base);
    }

    fn spawn_child(tramp: u64, sync: Arc<ParallelSync>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || child_thread(tramp, &sync))
    }

    fn child_thread(tramp: u64, sync: &ParallelSync) {
        sync.first.store(run_entry(tramp), Ordering::SeqCst);
        let saved = gs_qword(GS_CHAIN_PTR as u64);
        sync.base.store(rdgsbase(), Ordering::SeqCst);
        gs_store(0x2222);
        sync.bar_a.wait();
        gs_store(saved);
        sync.bar_b.wait();
        sync.second.store(run_entry(tramp), Ordering::SeqCst);
    }

    struct ParallelSync {
        bar_a: Barrier,
        bar_b: Barrier,
        base: AtomicU64,
        first: AtomicU64,
        second: AtomicU64,
    }

    impl ParallelSync {
        fn new() -> Self {
            Self {
                bar_a: Barrier::new(2),
                bar_b: Barrier::new(2),
                base: AtomicU64::new(0),
                first: AtomicU64::new(0),
                second: AtomicU64::new(0),
            }
        }
    }

    struct Staged {
        _mem: MapGuard,
        tramp: u64,
        resume: u64,
        blob: u64,
    }

    struct MapGuard {
        ptr: *mut u8,
        len: usize,
    }

    impl Drop for MapGuard {
        fn drop(&mut self) {
            munmap(self.ptr, self.len);
        }
    }

    struct GsGuard(u64);

    impl GsGuard {
        fn capture() -> Self {
            Self(rdgsbase())
        }
    }

    impl Drop for GsGuard {
        fn drop(&mut self) {
            set_gs(self.0);
        }
    }

    fn stage_parallel() -> Staged {
        let len = 0x20_0000;
        let mem = map_rwx(len);
        let built = build_image(mem as u64);
        assert!(built.bytes.len() <= len);
        // SAFETY: `mem` is the RWX mapping and `built.bytes` fits in it.
        unsafe {
            std::ptr::copy_nonoverlapping(built.bytes.as_ptr(), mem, built.bytes.len());
        }
        Staged {
            _mem: MapGuard { ptr: mem, len },
            tramp: built.tramp,
            resume: built.resume,
            blob: built.blob,
        }
    }

    struct Built {
        bytes: Vec<u8>,
        tramp: u64,
        resume: u64,
        blob: u64,
    }

    fn build_image(base: u64) -> Built {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let image = crate::vm::lower_image(&[ret_imm(0x21)], &mut rng).unwrap();
        let vm = assemble_vm(base).unwrap();
        let tramp = align_up(base + vm.bytes.len() as u64, 16);
        let resume_at = tramp + 0x1000;
        let runtime = resume_at + 0x1000;
        let keys = runtime + RUNTIME_WINDOW;
        let mut host = bare(Policy::default()).unwrap();
        host.regions.push(Region {
            base,
            data: vec![0; (keys + 0x2000 - base) as usize],
        });
        host.write(base, &vm.bytes).unwrap();
        place_one(&mut host, &image, base, &vm, runtime, keys);
        let resume = write_stubs(&mut host, &image, base, &vm, runtime, tramp);
        let blob = runtime_fits(runtime, image.funcs[0].insns.len(), blob_len(&image))
            .unwrap()
            .blob;
        let bytes = host
            .regions
            .iter()
            .find(|region| region.base == base)
            .unwrap()
            .data
            .clone();
        Built {
            bytes,
            tramp,
            resume,
            blob,
        }
    }

    fn place_one(
        host: &mut Machine,
        image: &BcImage,
        base: u64,
        vm: &crate::stub::NativeVm,
        runtime: u64,
        keys: u64,
    ) {
        let table = keys + 0x1000;
        place_runtime(
            &image.funcs[0],
            &image.inv,
            crc_of(image, 0),
            &image.slots,
            image.handler_mix,
            host,
            runtime,
            keys,
        )
        .unwrap();
        let mut bytes = Vec::new();
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(image.funcs[0].rva.to_le_bytes());
        bytes.extend(image.funcs[0].entry.to_le_bytes());
        bytes.extend(runtime.to_le_bytes());
        host.write(table, &bytes).unwrap();
        host.write(base + vm.calls as u64, &table.to_le_bytes())
            .unwrap();
    }

    fn write_stubs(
        host: &mut Machine,
        image: &BcImage,
        base: u64,
        vm: &crate::stub::NativeVm,
        runtime: u64,
        tramp: u64,
    ) -> u64 {
        let resume_at = tramp + 0x1000;
        let tramp_bytes = assemble_trampoline(&Trampoline {
            origin: tramp,
            frame: 0,
            runtime,
            entry: image.funcs[0].entry,
            dispatch: base + vm.dispatch as u64,
            image_base: 0,
            chains: base + vm.chains as u64,
        })
        .unwrap();
        assert!(tramp_bytes.len() < 0x1000);
        host.write(tramp, &tramp_bytes).unwrap();
        let resume_bytes = assemble_resume(&Resume {
            origin: resume_at,
            frame: 0,
            runtime,
            entry: image.funcs[0].entry,
            dispatch: base + vm.resume as u64,
        })
        .unwrap();
        assert!(resume_bytes.len() < 0x1000);
        host.write(resume_at, &resume_bytes).unwrap();
        resume_at
    }

    fn align_up(value: u64, align: u64) -> u64 {
        (value + align - 1) & !(align - 1)
    }

    fn run_entry(at: u64) -> u64 {
        let value: u64;
        // SAFETY: `at` is a generated entry in this test's executable mapping.
        // A resumed guest can return the registers from its previous VM frame.
        // Save the actual caller's SysV nonvolatiles and keep the stack aligned.
        unsafe {
            std::arch::asm!(
                "push rbp", "push rbx", "push r12", "push r13", "push r14", "push r15",
                "call rdi",
                "pop r15", "pop r14", "pop r13", "pop r12", "pop rbx", "pop rbp",
                in("rdi") at,
                lateout("rax") value,
                clobber_abi("C"),
            );
        }
        value
    }

    fn chain_bytes(ptr: u64) -> Vec<u8> {
        assert!(ptr > 0x10000);
        // SAFETY: `ptr` is a chain block inside this test's mapping.
        unsafe { std::slice::from_raw_parts(ptr as *const u8, CHAIN_BYTES).to_vec() }
    }

    fn flip_blob(at: u64) {
        // SAFETY: `at` is one ciphertext byte inside this test's mapping.
        unsafe {
            let byte = &mut *(at as *mut u8);
            *byte ^= 1;
        }
    }

    fn gs_qword(disp: u64) -> u64 {
        let value: u64;
        // SAFETY: `disp` is an offset on this thread's GS page. The load does not write.
        unsafe {
            std::arch::asm!(
                "mov {value}, qword ptr gs:[{disp}]",
                value = out(reg) value,
                disp = in(reg) disp,
            );
        }
        value
    }

    fn gs_store(value: u64) {
        let disp = GS_CHAIN_PTR as u64;
        // SAFETY: stores one qword at `gs:[GS_CHAIN_PTR]` for this thread only.
        unsafe {
            std::arch::asm!(
                "mov qword ptr gs:[{disp}], {value}",
                disp = in(reg) disp,
                value = in(reg) value,
            );
        }
    }

    fn rdgsbase() -> u64 {
        let gs: u64;
        // SAFETY: `rdgsbase` reads this thread's GS base into a register.
        unsafe {
            std::arch::asm!("rdgsbase {gs}", gs = out(reg) gs, options(nomem, nostack));
        }
        gs
    }

    fn set_gs(base: u64) {
        let rc: u64;
        // SAFETY: `arch_prctl(ARCH_SET_GS)` sets this thread's GS base and nothing else.
        unsafe {
            std::arch::asm!(
                "syscall",
                in("rax") 158u64,
                in("rdi") 0x1001u64,
                in("rsi") base,
                lateout("rax") rc,
                out("rcx") _,
                out("r11") _,
            );
        }
        assert_eq!(rc, 0);
    }

    fn map_rwx(len: usize) -> *mut u8 {
        let ptr: usize;
        // SAFETY: anonymous RWX mapping. A negative return is an errno, not a pointer.
        unsafe {
            std::arch::asm!(
                "syscall",
                in("rax") 9usize,
                in("rdi") 0usize,
                in("rsi") len,
                in("rdx") 7usize,
                in("r10") 0x22usize,
                in("r8") usize::MAX,
                in("r9") 0usize,
                lateout("rax") ptr,
                out("rcx") _,
                out("r11") _,
            );
        }
        assert!((ptr as isize) > 0, "mmap failed");
        ptr as *mut u8
    }

    fn munmap(ptr: *mut u8, len: usize) {
        let rc: usize;
        // SAFETY: `ptr` and `len` describe the mapping created by `map_rwx`.
        unsafe {
            std::arch::asm!(
                "syscall",
                in("rax") 11usize,
                in("rdi") ptr,
                in("rsi") len,
                lateout("rax") rc,
                out("rcx") _,
                out("r11") _,
            );
        }
        assert_eq!(rc, 0);
    }
}
