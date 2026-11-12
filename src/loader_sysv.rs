//! Linux SysV entry for a protected ELF64 image.
//!
//! Decrypts the same ChaCha20 payload as the PE loader, fills GOT slots from
//! djb2 hashes, and calls the original entry. Linux probes in this loader are
//! a copy: the bytecode check still poisons the thread chain if they are nopped.

use iced_x86::code_asm::*;

use super::{
    emit_aead_decrypt, emit_checksum, emit_loader_prefix, emit_map_restore, emit_strings,
    LoaderPlan,
};
use crate::error::{msg, Result};
use crate::vm::{GS_FRAME_AT, GS_FRAME_PTR, GS_MAP_BYTES, GS_TID};

/// Addresses baked into one SysV loader image. Length does not depend on them
/// while every absolute address stays in the signed 32-bit range.
pub struct Plan {
    pub origin: u64,
    pub payload: u64,
    pub payload_len: u32,
    pub checksum: u32,
    pub aead_key: [u8; 32],
    pub aead_nonce: [u8; 12],
    pub strings: u64,
    pub imports: u64,
    pub table: u64,
    pub calls: u64,
    pub image_base: u64,
    pub dynamic: u64,
    pub original: u64,
    pub gs: u64,
    /// Entry function runtime. Zero skips the loader probes.
    pub runtime: u64,
}

impl Drop for Plan {
    fn drop(&mut self) {
        crate::secret::wipe(&mut self.aead_key);
    }
}

/// Assemble the SysV loader described by `plan`.
///
/// The image decrypts the payload, fills GOT slots from djb2 hashes, and calls
/// the original entry.
///
/// # Errors
///
/// Returns an error when assembly fails or the embedded AEAD prefix moves.
pub fn assemble(plan: &Plan) -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut corrupt = a.create_label();
    let mut resolve = a.create_label();
    let mut write = a.create_label();
    let mut exit = a.create_label();
    let win = window(plan);
    emit_loader_prefix(&mut a, &win)?;
    emit_checksum(&mut a, &win, &mut corrupt, false)?;
    emit_aead_decrypt(&mut a, &win, false)?;
    step(a.mov(r15, plan.image_base as i64))?;
    emit_strings(&mut a, &win)?;
    emit_unlock(&mut a, &win)?;
    emit_map_restore(&mut a, &win)?;
    emit_imports(&mut a, plan, &mut resolve, &mut corrupt, write, exit)?;
    emit_handoff(&mut a, plan, &mut corrupt)?;
    step(a.set_label(&mut corrupt))?;
    emit_exit(&mut a, 0xbad1)?;
    step(a.jmp(corrupt))?;
    step(a.set_label(&mut resolve))?;
    emit_resolve(&mut a, plan.dynamic)?;
    crate::syscall::emit_linux_stubs(&mut a, &mut write, &mut exit)?;
    let bytes = a
        .assemble(plan.origin)
        .map_err(|err| msg(err.to_string()))?;
    super::ensure_embedded_key(&bytes, &win)?;
    Ok(bytes)
}

fn window(plan: &Plan) -> LoaderPlan {
    LoaderPlan {
        origin: plan.origin,
        payload: plan.payload,
        payload_len: plan.payload_len,
        checksum: plan.checksum,
        aead_key: plan.aead_key,
        aead_nonce: plan.aead_nonce,
        strings: plan.strings,
        imports: plan.imports,
        table: plan.table,
        calls: plan.calls,
        module: 0,
        resolve: 0,
        original: plan.original,
        cave: 0,
        runtime: 0,
        name_key: [0; 16],
    }
}

fn emit_unlock(a: &mut CodeAssembler, plan: &LoaderPlan) -> Result<()> {
    let mut top = a.create_label();
    let mut done = a.create_label();
    step(a.mov(rsi, plan.strings as i64))?;
    step(a.mov(ecx, dword_ptr(rsi)))?;
    step(a.add(rsi, 4i32))?;
    step(a.imul_3(ecx, ecx, 12i32))?;
    step(a.add(rsi, rcx))?;
    step(a.mov(ecx, dword_ptr(rsi)))?;
    step(a.add(rsi, 4i32))?;
    step(a.set_label(&mut top))?;
    step(a.test(ecx, ecx))?;
    step(a.jz(done))?;
    emit_prot(a)?;
    step(a.add(rsi, 12i32))?;
    step(a.dec(ecx))?;
    step(a.jmp(top))?;
    step(a.set_label(&mut done))?;
    step(a.nop())?;
    Ok(())
}

fn emit_prot(a: &mut CodeAssembler) -> Result<()> {
    step(a.mov(eax, dword_ptr(rsi)))?;
    step(a.mov(edx, dword_ptr(rsi + 4i32)))?;
    step(a.lea(rdi, qword_ptr(r15 + rax)))?;
    step(a.mov(r10, rdi))?;
    step(a.and(r10, -4096i32))?;
    step(a.mov(r11, rdi))?;
    step(a.add(r11, rdx))?;
    step(a.add(r11, 4095i32))?;
    step(a.and(r11, -4096i32))?;
    step(a.sub(r11, r10))?;
    step(a.push(rsi))?;
    step(a.push(rcx))?;
    step(a.mov(rdi, r10))?;
    step(a.mov(rsi, r11))?;
    step(a.mov(edx, 7u32))?;
    step(a.mov(eax, 10u32))?;
    step(a.syscall())?;
    step(a.pop(rcx))?;
    step(a.pop(rsi))?;
    Ok(())
}

fn emit_imports(
    a: &mut CodeAssembler,
    plan: &Plan,
    resolve: &mut CodeLabel,
    corrupt: &mut CodeLabel,
    write: CodeLabel,
    exit: CodeLabel,
) -> Result<()> {
    let mut imp = a.create_label();
    let mut done = a.create_label();
    step(a.mov(rsi, plan.imports as i64))?;
    step(a.mov(ecx, dword_ptr(rsi)))?;
    step(a.add(rsi, 4i32))?;
    step(a.set_label(&mut imp))?;
    step(a.test(ecx, ecx))?;
    step(a.jz(done))?;
    step(a.mov(r12d, dword_ptr(rsi)))?;
    step(a.mov(r13d, dword_ptr(rsi + 4i32)))?;
    step(a.push(rsi))?;
    step(a.push(rcx))?;
    step(a.push(r15))?;
    step(a.push(r12))?;
    step(a.push(r13))?;
    step(a.push(rax))?;
    crate::syscall::emit_elf_bind(a, *resolve, write, exit)?;
    step(a.mov(r11, rax))?;
    step(a.pop(rax))?;
    step(a.pop(r13))?;
    step(a.pop(r12))?;
    step(a.pop(r15))?;
    step(a.pop(rcx))?;
    step(a.pop(rsi))?;
    step(a.test(r11, r11))?;
    step(a.jz(*corrupt))?;
    step(a.lea(r10, qword_ptr(r15 + r12)))?;
    step(a.mov(qword_ptr(r10), r11))?;
    step(a.add(rsi, 8i32))?;
    step(a.dec(ecx))?;
    step(a.jmp(imp))?;
    step(a.set_label(&mut done))?;
    Ok(())
}

fn emit_handoff(a: &mut CodeAssembler, plan: &Plan, corrupt: &mut CodeLabel) -> Result<()> {
    let mut trip = a.create_label();
    crate::antidebug::emit_linux_loader(a, plan.runtime, &mut trip)?;
    step(a.mov(rax, plan.table as i64))?;
    step(a.mov(r11, plan.calls as i64))?;
    step(a.mov(qword_ptr(r11), rax))?;
    emit_private_gs(a, corrupt)?;
    step(a.and(rsp, -16i32))?;
    emit_trace_entry(a)?;
    step(a.mov(rax, plan.original as i64))?;
    step(a.call(rax))?;
    step(a.mov(edi, eax))?;
    step(a.mov(eax, 231u32))?;
    step(a.syscall())?;
    step(a.set_label(&mut trip))?;
    crate::antidebug::emit_linux_exit(a)?;
    Ok(())
}

fn emit_trace_entry(a: &mut CodeAssembler) -> Result<()> {
    step(a.push(rdx))?;
    step(a.sub(rsp, 16i32))?;
    step(a.mov(rax, i64::from_le_bytes(*b"entry\n\0\0")))?;
    step(a.mov(qword_ptr(rsp), rax))?;
    step(a.mov(eax, 1u32))?;
    step(a.mov(edi, 2u32))?;
    step(a.mov(rsi, rsp))?;
    step(a.mov(edx, 6u32))?;
    step(a.syscall())?;
    step(a.add(rsp, 16i32))?;
    step(a.pop(rdx))?;
    Ok(())
}

fn emit_private_gs(a: &mut CodeAssembler, corrupt: &mut CodeLabel) -> Result<()> {
    // `mmap` uses `edx`. `rdx` at process entry is the atexit pointer.
    step(a.push(rdx))?;
    read_old_gs(a)?;
    step(a.push(r9))?;
    map_thread_gs(a, corrupt)?;
    step(a.pop(r9))?;
    fill_thread_gs(a, corrupt)?;
    step(a.pop(rdx))?;
    Ok(())
}

fn read_old_gs(a: &mut CodeAssembler) -> Result<()> {
    step(a.sub(rsp, 8i32))?;
    step(a.xor(eax, eax))?;
    step(a.mov(qword_ptr(rsp), rax))?;
    step(a.mov(eax, 158u32))?;
    step(a.mov(edi, 0x1004u32))?;
    step(a.mov(rsi, rsp))?;
    step(a.syscall())?;
    step(a.mov(r9, qword_ptr(rsp)))?;
    step(a.add(rsp, 8i32))?;
    Ok(())
}

fn map_thread_gs(a: &mut CodeAssembler, corrupt: &mut CodeLabel) -> Result<()> {
    step(a.mov(eax, 9u32))?;
    step(a.xor(edi, edi))?;
    step(a.mov(esi, GS_MAP_BYTES as u32))?;
    step(a.mov(edx, 3u32))?;
    step(a.mov(r10d, 0x22u32))?;
    step(a.mov(r8, -1i64))?;
    step(a.xor(r9d, r9d))?;
    step(a.syscall())?;
    step(a.test(rax, rax))?;
    step(a.js(*corrupt))?;
    Ok(())
}

fn fill_thread_gs(a: &mut CodeAssembler, corrupt: &mut CodeLabel) -> Result<()> {
    // The VM probe reads BeingDebugged into `al`. Keep a real PEB pointer when
    // the process already has one; otherwise the aligned page is its own PEB.
    step(a.mov(r11, rax))?;
    step(a.mov(qword_ptr(r11 + 0x60i32), r11))?;
    copy_old_peb(a)?;
    step(a.lea(rcx, qword_ptr(r11 + GS_FRAME_AT as i32)))?;
    step(a.mov(qword_ptr(r11 + GS_FRAME_PTR), rcx))?;
    step(a.push(r11))?;
    step(a.mov(eax, 186u32))?;
    step(a.syscall())?;
    step(a.pop(r11))?;
    step(a.mov(qword_ptr(r11 + GS_TID), rax))?;
    step(a.mov(rsi, r11))?;
    step(a.mov(eax, 158u32))?;
    step(a.mov(edi, 0x1001u32))?;
    step(a.syscall())?;
    step(a.test(rax, rax))?;
    step(a.jnz(*corrupt))?;
    Ok(())
}

fn copy_old_peb(a: &mut CodeAssembler) -> Result<()> {
    let mut done = a.create_label();
    step(a.test(r9, r9))?;
    step(a.jz(done))?;
    step(a.mov(rcx, qword_ptr(r9 + 0x60i32)))?;
    step(a.test(rcx, rcx))?;
    step(a.jz(done))?;
    step(a.mov(qword_ptr(r11 + 0x60i32), rcx))?;
    step(a.set_label(&mut done))?;
    Ok(())
}

pub(crate) struct ElfAuthPlan {
    pub origin: u64,
    pub verifier: u64,
    pub manifest: u64,
    pub expected: u64,
    pub trusted_public: u64,
    pub key: u64,
    pub payload: u64,
    pub payload_len: u32,
    pub table: u64,
    pub calls: u64,
    pub original: u64,
}

pub(crate) fn assemble_elf_auth(plan: &ElfAuthPlan) -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut fail = a.create_label();
    emit_elf_auth_verify(&mut a, plan, fail)?;
    step(a.mov(rax, plan.calls as i64))?;
    step(a.mov(r11, plan.table as i64))?;
    step(a.mov(qword_ptr(rax), r11))?;
    emit_private_gs(&mut a, &mut fail)?;
    step(a.jmp(plan.original))?;
    step(a.set_label(&mut fail))?;
    emit_exit(&mut a, 0xbad1)?;
    step(a.jmp(fail))?;
    a.assemble(plan.origin).map_err(|err| msg(err.to_string()))
}

fn emit_elf_auth_verify(a: &mut CodeAssembler, plan: &ElfAuthPlan, fail: CodeLabel) -> Result<()> {
    // Preserve the glibc finalizer in RDX and the process startup stack.
    step(a.push(rdx))?;
    step(a.sub(rsp, 8i32))?;
    step(a.mov(rdi, plan.manifest as i64))?;
    step(a.mov(rsi, plan.expected as i64))?;
    step(a.mov(rdx, plan.trusted_public as i64))?;
    step(a.mov(rcx, plan.key as i64))?;
    step(a.mov(r8, plan.payload as i64))?;
    step(a.mov(r9d, plan.payload_len))?;
    step(a.call(plan.verifier))?;
    step(a.add(rsp, 8i32))?;
    step(a.pop(rdx))?;
    step(a.cmp(eax, 1))?;
    step(a.jne(fail))
}

fn emit_exit(a: &mut CodeAssembler, code: u32) -> Result<()> {
    step(a.mov(edi, code))?;
    step(a.mov(eax, 231u32))?;
    step(a.syscall())?;
    Ok(())
}

fn emit_resolve(a: &mut CodeAssembler, dynamic: u64) -> Result<()> {
    let mut miss = a.create_label();
    push_resolve(a)?;
    step(a.mov(r15d, edi))?;
    step(a.mov(rbp, rsp))?;
    emit_debug_scan(a, dynamic, miss)?;
    let walk = walk_labels(a, miss);
    emit_map_walk(a, walk)?;
    finish_resolve_miss(a, &mut miss)
}

fn push_resolve(a: &mut CodeAssembler) -> Result<()> {
    step(a.push(rbx))?;
    step(a.push(rbp))?;
    step(a.push(r12))?;
    step(a.push(r13))?;
    step(a.push(r14))?;
    step(a.push(r15))?;
    Ok(())
}

fn emit_debug_scan(a: &mut CodeAssembler, dynamic: u64, miss: CodeLabel) -> Result<()> {
    let mut scan = a.create_label();
    let mut found = a.create_label();
    step(a.mov(rsi, dynamic as i64))?;
    step(a.set_label(&mut scan))?;
    step(a.mov(rax, qword_ptr(rsi)))?;
    step(a.test(rax, rax))?;
    step(a.jz(miss))?;
    step(a.cmp(rax, 21i32))?;
    step(a.je(found))?;
    step(a.add(rsi, 16i32))?;
    step(a.jmp(scan))?;
    step(a.set_label(&mut found))?;
    step(a.mov(rax, qword_ptr(rsi + 8i32)))?;
    step(a.test(rax, rax))?;
    step(a.jz(miss))?;
    step(a.mov(rbx, qword_ptr(rax + 8i32)))?;
    step(a.mov(r13d, 64u32))?;
    Ok(())
}

fn walk_labels(a: &mut CodeAssembler, miss: CodeLabel) -> Walk {
    Walk {
        map: a.create_label(),
        next_map: a.create_label(),
        miss,
        dyn_loop: a.create_label(),
        dyn_next: a.create_label(),
        dyn_done: a.create_label(),
        have: a.create_label(),
        sym: a.create_label(),
        sym_next: a.create_label(),
        hash: a.create_label(),
        hashed: a.create_label(),
    }
}

fn finish_resolve_miss(a: &mut CodeAssembler, miss: &mut CodeLabel) -> Result<()> {
    step(a.set_label(miss))?;
    step(a.xor(eax, eax))?;
    step(a.mov(rsp, rbp))?;
    pop_resolve(a)?;
    step(a.ret())?;
    Ok(())
}

fn pop_resolve(a: &mut CodeAssembler) -> Result<()> {
    step(a.pop(r15))?;
    step(a.pop(r14))?;
    step(a.pop(r13))?;
    step(a.pop(r12))?;
    step(a.pop(rbp))?;
    step(a.pop(rbx))?;
    Ok(())
}

struct Walk {
    map: CodeLabel,
    next_map: CodeLabel,
    miss: CodeLabel,
    dyn_loop: CodeLabel,
    dyn_next: CodeLabel,
    dyn_done: CodeLabel,
    have: CodeLabel,
    sym: CodeLabel,
    sym_next: CodeLabel,
    hash: CodeLabel,
    hashed: CodeLabel,
}

fn emit_map_walk(a: &mut CodeAssembler, mut walk: Walk) -> Result<()> {
    emit_map_head(a, &mut walk)?;
    emit_dyn_tags(a, &mut walk)?;
    emit_symbol_count(a, &mut walk)?;
    emit_symbol_scan(a, &mut walk)
}

fn emit_map_head(a: &mut CodeAssembler, walk: &mut Walk) -> Result<()> {
    step(a.set_label(&mut walk.map))?;
    step(a.dec(r13d))?;
    step(a.jz(walk.miss))?;
    step(a.test(rbx, rbx))?;
    step(a.jz(walk.miss))?;
    step(a.mov(r12, qword_ptr(rbx)))?;
    step(a.mov(rsi, qword_ptr(rbx + 16i32)))?;
    step(a.mov(r14, qword_ptr(rbx + 24i32)))?;
    step(a.sub(rsp, 48i32))?;
    step(a.xor(eax, eax))?;
    step(a.mov(qword_ptr(rbp - 8i32), rax))?;
    step(a.mov(qword_ptr(rbp - 16i32), rax))?;
    step(a.mov(qword_ptr(rbp - 24i32), rax))?;
    step(a.mov(qword_ptr(rbp - 32i32), rax))?;
    step(a.mov(rax, 24i64))?;
    step(a.mov(qword_ptr(rbp - 40i32), rax))?;
    Ok(())
}

fn emit_dyn_tags(a: &mut CodeAssembler, walk: &mut Walk) -> Result<()> {
    step(a.set_label(&mut walk.dyn_loop))?;
    step(a.mov(rax, qword_ptr(rsi)))?;
    step(a.test(rax, rax))?;
    step(a.jz(walk.dyn_done))?;
    store_ptr(a, &mut walk.dyn_next, 6, -8)?;
    store_ptr(a, &mut walk.dyn_next, 5, -16)?;
    store_ptr(a, &mut walk.dyn_next, 4, -24)?;
    store_tag(a, &mut walk.dyn_next, 11, -40)?;
    step(a.mov(rcx, 0x6fff_fef5i64))?;
    step(a.cmp(rax, rcx))?;
    step(a.jne(walk.dyn_next))?;
    step(a.mov(rcx, qword_ptr(rsi + 8i32)))?;
    adjust_base(a)?;
    step(a.mov(qword_ptr(rbp - 32i32), rcx))?;
    step(a.set_label(&mut walk.dyn_next))?;
    step(a.add(rsi, 16i32))?;
    step(a.jmp(walk.dyn_loop))?;
    step(a.set_label(&mut walk.dyn_done))?;
    step(a.mov(rax, qword_ptr(rbp - 8i32)))?;
    step(a.test(rax, rax))?;
    step(a.jz(walk.next_map))?;
    step(a.mov(rax, qword_ptr(rbp - 16i32)))?;
    step(a.test(rax, rax))?;
    step(a.jz(walk.next_map))?;
    Ok(())
}

fn store_tag(a: &mut CodeAssembler, next: &mut CodeLabel, tag: i32, disp: i32) -> Result<()> {
    let mut skip = a.create_label();
    step(a.cmp(rax, tag))?;
    step(a.jne(skip))?;
    step(a.mov(rcx, qword_ptr(rsi + 8i32)))?;
    step(a.mov(qword_ptr(rbp + disp), rcx))?;
    step(a.jmp(*next))?;
    step(a.set_label(&mut skip))?;
    Ok(())
}

fn store_ptr(a: &mut CodeAssembler, next: &mut CodeLabel, tag: i32, disp: i32) -> Result<()> {
    let mut skip = a.create_label();
    step(a.cmp(rax, tag))?;
    step(a.jne(skip))?;
    step(a.mov(rcx, qword_ptr(rsi + 8i32)))?;
    adjust_base(a)?;
    step(a.mov(qword_ptr(rbp + disp), rcx))?;
    step(a.jmp(*next))?;
    step(a.set_label(&mut skip))?;
    Ok(())
}

/// vDSO keeps dynamic pointers as offsets from `l_addr`. Relocated objects already hold absolute addresses.
fn adjust_base(a: &mut CodeAssembler) -> Result<()> {
    let mut absolute = a.create_label();
    step(a.test(rcx, rcx))?;
    step(a.jz(absolute))?;
    step(a.cmp(rcx, r12))?;
    step(a.jae(absolute))?;
    step(a.add(rcx, r12))?;
    step(a.set_label(&mut absolute))?;
    Ok(())
}

fn emit_symbol_count(a: &mut CodeAssembler, walk: &mut Walk) -> Result<()> {
    let mut gnu = a.create_label();
    step(a.mov(rax, qword_ptr(rbp - 24i32)))?;
    step(a.test(rax, rax))?;
    step(a.jz(gnu))?;
    step(a.mov(ecx, dword_ptr(rax + 4i32)))?;
    step(a.jmp(walk.have))?;
    step(a.set_label(&mut gnu))?;
    step(a.mov(rax, qword_ptr(rbp - 32i32)))?;
    step(a.test(rax, rax))?;
    step(a.jz(walk.next_map))?;
    emit_gnu_count(a, &mut walk.have, &mut walk.next_map)?;
    step(a.set_label(&mut walk.have))?;
    step(a.cmp(ecx, 0x10_0000i32))?;
    step(a.ja(walk.next_map))?;
    step(a.xor(edx, edx))?;
    Ok(())
}

fn emit_gnu_count(
    a: &mut CodeAssembler,
    have: &mut CodeLabel,
    next_map: &mut CodeLabel,
) -> Result<()> {
    let mut walk_chain = a.create_label();
    emit_gnu_buckets(a, have, &mut walk_chain)?;
    emit_gnu_chain(a, have, next_map, &mut walk_chain)
}

fn emit_gnu_buckets(
    a: &mut CodeAssembler,
    have: &mut CodeLabel,
    walk_chain: &mut CodeLabel,
) -> Result<()> {
    let mut bucket = a.create_label();
    let mut bucket_inc = a.create_label();
    let mut bucket_done = a.create_label();
    step(a.mov(ecx, dword_ptr(rax)))?;
    step(a.mov(r8d, dword_ptr(rax + 4i32)))?;
    step(a.mov(r9d, dword_ptr(rax + 8i32)))?;
    step(a.mov(r11, r9))?;
    step(a.shl(r11, 3u32))?;
    step(a.add(r11, rax))?;
    step(a.add(r11, 16i32))?;
    step(a.xor(r10d, r10d))?;
    step(a.xor(edx, edx))?;
    step(a.xor(esi, esi))?;
    step(a.set_label(&mut bucket))?;
    step(a.cmp(edx, ecx))?;
    step(a.jae(bucket_done))?;
    step(a.mov(eax, dword_ptr(r11 + rdx * 4)))?;
    step(a.test(eax, eax))?;
    step(a.jz(bucket_inc))?;
    step(a.cmp(eax, r8d))?;
    step(a.jb(bucket_inc))?;
    step(a.mov(esi, 1u32))?;
    step(a.cmp(eax, r10d))?;
    step(a.jbe(bucket_inc))?;
    step(a.mov(r10d, eax))?;
    step(a.set_label(&mut bucket_inc))?;
    step(a.inc(edx))?;
    step(a.jmp(bucket))?;
    step(a.set_label(&mut bucket_done))?;
    step(a.test(esi, esi))?;
    step(a.jnz(*walk_chain))?;
    step(a.mov(ecx, r8d))?;
    step(a.jmp(*have))?;
    Ok(())
}

fn emit_gnu_chain(
    a: &mut CodeAssembler,
    have: &mut CodeLabel,
    next_map: &mut CodeLabel,
    walk_chain: &mut CodeLabel,
) -> Result<()> {
    let mut chain = a.create_label();
    let mut chain_done = a.create_label();
    step(a.set_label(walk_chain))?;
    step(a.mov(rax, rcx))?;
    step(a.lea(r9, qword_ptr(r11 + rax * 4)))?;
    step(a.mov(eax, r10d))?;
    step(a.set_label(&mut chain))?;
    step(a.cmp(eax, 0x10_0000i32))?;
    step(a.ja(*next_map))?;
    step(a.mov(edx, eax))?;
    step(a.sub(edx, r8d))?;
    step(a.mov(edx, dword_ptr(r9 + rdx * 4)))?;
    step(a.test(edx, 1u32))?;
    step(a.jnz(chain_done))?;
    step(a.inc(eax))?;
    step(a.jmp(chain))?;
    step(a.set_label(&mut chain_done))?;
    step(a.inc(eax))?;
    step(a.mov(ecx, eax))?;
    step(a.jmp(*have))?;
    Ok(())
}

fn emit_symbol_scan(a: &mut CodeAssembler, walk: &mut Walk) -> Result<()> {
    step(a.set_label(&mut walk.sym))?;
    step(a.cmp(edx, ecx))?;
    step(a.jae(walk.next_map))?;
    step(a.mov(rax, rdx))?;
    step(a.mov(r8, qword_ptr(rbp - 40i32)))?;
    step(a.imul_2(r8, rax))?;
    step(a.add(r8, qword_ptr(rbp - 8i32)))?;
    step(a.mov(eax, dword_ptr(r8)))?;
    step(a.test(eax, eax))?;
    step(a.jz(walk.sym_next))?;
    step(a.movzx(r9d, word_ptr(r8 + 6i32)))?;
    step(a.test(r9d, r9d))?;
    step(a.jz(walk.sym_next))?;
    step(a.movzx(r9d, byte_ptr(r8 + 4i32)))?;
    step(a.and(r9d, 0x0fi32))?;
    step(a.cmp(r9d, 10i32))?;
    step(a.je(walk.sym_next))?;
    step(a.mov(r9, qword_ptr(rbp - 16i32)))?;
    step(a.add(r9, rax))?;
    step(a.mov(eax, 5381u32))?;
    step(a.set_label(&mut walk.hash))?;
    step(a.movzx(r10d, byte_ptr(r9)))?;
    step(a.test(r10d, r10d))?;
    step(a.jz(walk.hashed))?;
    step(a.imul_3(eax, eax, 33i32))?;
    step(a.add(eax, r10d))?;
    step(a.inc(r9))?;
    step(a.jmp(walk.hash))?;
    step(a.set_label(&mut walk.hashed))?;
    step(a.cmp(eax, r15d))?;
    step(a.jne(walk.sym_next))?;
    step(a.mov(rax, qword_ptr(r8 + 8i32)))?;
    step(a.add(rax, r12))?;
    step(a.mov(rsp, rbp))?;
    pop_resolve(a)?;
    step(a.ret())?;
    step(a.set_label(&mut walk.sym_next))?;
    step(a.inc(edx))?;
    step(a.jmp(walk.sym))?;
    step(a.set_label(&mut walk.next_map))?;
    step(a.mov(rsp, rbp))?;
    step(a.mov(rbx, r14))?;
    step(a.jmp(walk.map))?;
    Ok(())
}

fn step(result: std::result::Result<(), iced_x86::IcedError>) -> Result<()> {
    result.map_err(|err| msg(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(origin: u64) -> Plan {
        Plan {
            origin,
            payload: origin + 0x2000,
            payload_len: 32,
            checksum: 0,
            aead_key: [0x11; 32],
            aead_nonce: [0x22; 12],
            strings: origin + 0x2000,
            imports: origin + 0x2100,
            table: origin + 0x2200,
            calls: origin + 0x1800,
            image_base: 0x400000,
            dynamic: 0x402010,
            original: 0x401000,
            gs: origin + 0x3000,
            runtime: origin + 0x4000,
        }
    }

    #[test]
    fn sysv_loader_keeps_a_stable_size_and_the_aead_prefix() {
        let first = assemble(&plan(0x403000)).unwrap();
        let second = assemble(&plan(0x405000)).unwrap();
        assert_eq!(first.len(), second.len());
        assert_eq!(first[0], 0xeb);
        assert!(super::super::is_loader_prologue(&first));
    }
}
