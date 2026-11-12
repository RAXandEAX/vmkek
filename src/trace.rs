//! Per-call import gates and sealed sample strings.
//!
//! A resolved export address lives in a register only while that call runs.
//! The name hash is keyed. The key bytes are not stored in the clear in the
//! file: they sit in the sealed payload and are re-derived from the seed.
//! The sample literal is opened for the write and sealed again before the
//! gate returns. Volatile argument registers are cleared on the way out.

use std::cell::Cell;

use iced_x86::code_asm::*;

use crate::error::{msg, Result};
use crate::loader::LoaderPlan;
use crate::syscall::{NR_STD_HANDLE, NR_WRITE};

/// Bytes of the HKDF name-hash key stored at the front of the sealed payload.
pub const NAME_KEY_LEN: usize = 16;
/// `r8d` value that asks the write gate to format the sample line.
pub const LINE_NUMBER: u32 = 0x7A11;
/// Length of the sample literal `vmkek-ok:`.
pub const PREFIX_LEN: u32 = 9;
/// Fixed import gates. The sample and the driver image both fit.
pub const GATE_COUNT: usize = 8;
/// `mov eax, index; jmp rel32`.
pub const STUB_LEN: usize = 10;

thread_local! {
    static ACTIVE_KEY: Cell<[u8; 16]> = const { Cell::new([0; 16]) };
}

/// Install `key` for hashed imports assembled on this thread. Returns the previous key.
pub fn set_name_key(key: [u8; 16]) -> [u8; 16] {
    ACTIVE_KEY.with(|cell| cell.replace(key))
}

/// Key currently installed for import-name hashing. All zeros selects plain djb2.
#[must_use]
pub fn active_name_key() -> [u8; 16] {
    ACTIVE_KEY.with(|cell| cell.get())
}

/// Name-hash key for `seed`. The bytes are not written into the loader image.
pub fn name_key(seed: u64) -> Result<[u8; 16]> {
    let mut out = [0u8; NAME_KEY_LEN];
    crate::crypto::hkdf_sha256(&seed.to_le_bytes(), b"vmkek.name", b"import-hash", &mut out)?;
    Ok(out)
}

/// djb2 starting from the first key word, then mixed with the second word.
#[must_use]
pub fn keyed_hash(name: &[u8], key: &[u8; NAME_KEY_LEN]) -> u32 {
    let mut hash = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
    for byte in name {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(*byte));
    }
    hash ^ u32::from_le_bytes([key[4], key[5], key[6], key[7]])
}

/// Hash `name` with the active key, or plain djb2 when that key is all zeros.
#[must_use]
pub fn import_hash(name: &[u8]) -> u32 {
    let key = active_name_key();
    if key == [0; NAME_KEY_LEN] {
        crate::emu::djb2(name)
    } else {
        keyed_hash(name, &key)
    }
}

/// Export walker. `key_addr == 0` keeps the unkeyed djb2 the unit test uses.
pub fn assemble_resolver(origin: u64, key_addr: u64) -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(64).map_err(ice)?;
    let mut miss = a.create_label();
    let mut none = a.create_label();
    let mut scan = a.create_label();
    let mut hash_loop = a.create_label();
    let mut hashed = a.create_label();
    emit_resolve_entry(&mut a)?;
    emit_export_dir(&mut a, &mut scan, &none)?;
    emit_keyed_name(&mut a, key_addr, &mut hash_loop, &mut hashed)?;
    emit_export_hit(&mut a, &mut miss, &mut none, &scan)?;
    a.assemble(origin).map_err(ice)
}

fn emit_resolve_entry(a: &mut CodeAssembler) -> Result<()> {
    step(a.push(rbx))?;
    step(a.push(rsi))?;
    step(a.push(rdi))?;
    step(a.push(r12))?;
    step(a.push(r13))?;
    step(a.mov(rbx, rcx))?;
    step(a.mov(r12d, edx))?;
    Ok(())
}

fn emit_export_dir(a: &mut CodeAssembler, scan: &mut CodeLabel, none: &CodeLabel) -> Result<()> {
    step(a.mov(eax, dword_ptr(rbx + 0x3ci32)))?;
    step(a.lea(r8, qword_ptr(rbx + rax)))?;
    step(a.mov(eax, dword_ptr(r8 + 136i32)))?;
    step(a.lea(r8, qword_ptr(rbx + rax)))?;
    step(a.mov(r9d, dword_ptr(r8 + 0x18i32)))?;
    step(a.mov(r10d, dword_ptr(r8 + 0x1ci32)))?;
    step(a.mov(esi, dword_ptr(r8 + 0x20i32)))?;
    step(a.mov(edi, dword_ptr(r8 + 0x24i32)))?;
    step(a.xor(ecx, ecx))?;
    step(a.set_label(scan))?;
    step(a.cmp(rcx, r9))?;
    step(a.jae(*none))?;
    step(a.lea(r11, qword_ptr(rbx + rsi)))?;
    step(a.mov(eax, dword_ptr(r11 + rcx * 4)))?;
    step(a.lea(r11, qword_ptr(rbx + rax)))?;
    Ok(())
}

fn emit_keyed_name(
    a: &mut CodeAssembler,
    key_addr: u64,
    hash_loop: &mut CodeLabel,
    hashed: &mut CodeLabel,
) -> Result<()> {
    let mut load = a.create_label();
    emit_key_ptr(a, key_addr)?;
    step(a.test(r13, r13))?;
    step(a.jnz(load))?;
    step(a.mov(eax, 5381u32))?;
    step(a.jmp(*hash_loop))?;
    step(a.set_label(&mut load))?;
    step(a.mov(eax, dword_ptr(r13)))?;
    step(a.set_label(hash_loop))?;
    emit_hash_step(a, hash_loop, hashed)?;
    emit_hash_finish(a, hashed)?;
    Ok(())
}

fn emit_key_ptr(a: &mut CodeAssembler, key_addr: u64) -> Result<()> {
    let mut bytes = [0u8; 10];
    bytes[0] = 0x49;
    bytes[1] = 0xbd;
    bytes[2..].copy_from_slice(&key_addr.to_le_bytes());
    step(a.db(&bytes))?;
    Ok(())
}

fn emit_hash_step(a: &mut CodeAssembler, hash_loop: &CodeLabel, hashed: &CodeLabel) -> Result<()> {
    step(a.movzx(edx, byte_ptr(r11)))?;
    step(a.test(dl, dl))?;
    step(a.jz(*hashed))?;
    step(a.imul_3(eax, eax, 33i32))?;
    step(a.add(eax, edx))?;
    step(a.inc(r11))?;
    step(a.jmp(*hash_loop))?;
    Ok(())
}

fn emit_hash_finish(a: &mut CodeAssembler, hashed: &mut CodeLabel) -> Result<()> {
    let mut plain = a.create_label();
    step(a.set_label(hashed))?;
    step(a.test(r13, r13))?;
    step(a.jz(plain))?;
    step(a.xor(eax, dword_ptr(r13 + 4i32)))?;
    step(a.set_label(&mut plain))?;
    Ok(())
}

fn emit_export_hit(
    a: &mut CodeAssembler,
    miss: &mut CodeLabel,
    none: &mut CodeLabel,
    scan: &CodeLabel,
) -> Result<()> {
    step(a.cmp(eax, r12d))?;
    step(a.jne(*miss))?;
    emit_export_va(a)?;
    step(a.set_label(miss))?;
    step(a.inc(rcx))?;
    step(a.jmp(*scan))?;
    step(a.set_label(none))?;
    step(a.xor(eax, eax))?;
    pop_resolve(a)?;
    step(a.ret())?;
    Ok(())
}

fn emit_export_va(a: &mut CodeAssembler) -> Result<()> {
    step(a.lea(r11, qword_ptr(rbx + rdi)))?;
    step(a.movzx(eax, word_ptr(r11 + rcx * 2)))?;
    step(a.lea(r11, qword_ptr(rbx + r10)))?;
    step(a.mov(eax, dword_ptr(r11 + rax * 4)))?;
    step(a.add(rax, rbx))?;
    pop_resolve(a)?;
    step(a.ret())?;
    Ok(())
}

fn pop_resolve(a: &mut CodeAssembler) -> Result<()> {
    step(a.pop(r13))?;
    step(a.pop(r12))?;
    step(a.pop(rdi))?;
    step(a.pop(rsi))?;
    step(a.pop(rbx))?;
    Ok(())
}

/// Point each IAT slot at its gate. The resolved export is not written.
pub fn emit_plant(
    a: &mut CodeAssembler,
    plan: &LoaderPlan,
    stubs: CodeLabel,
    corrupt: CodeLabel,
) -> Result<()> {
    let mut imp = a.create_label();
    let mut done = a.create_label();
    step(a.mov(r10, plan.module as i64))?;
    step(a.mov(qword_ptr(r10), r12))?;
    step(a.mov(rsi, plan.imports as i64))?;
    step(a.mov(ecx, dword_ptr(rsi)))?;
    step(a.add(rsi, 4i32))?;
    step(a.xor(eax, eax))?;
    emit_plant_loop(a, &mut imp, &mut done, stubs, corrupt)?;
    Ok(())
}

fn emit_plant_loop(
    a: &mut CodeAssembler,
    imp: &mut CodeLabel,
    done: &mut CodeLabel,
    stubs: CodeLabel,
    corrupt: CodeLabel,
) -> Result<()> {
    step(a.set_label(imp))?;
    step(a.test(ecx, ecx))?;
    step(a.jz(*done))?;
    step(a.cmp(eax, GATE_COUNT as i32))?;
    step(a.jae(corrupt))?;
    step(a.mov(r11d, dword_ptr(rsi)))?;
    step(a.lea(r10, qword_ptr(stubs)))?;
    step(a.imul_3(r9d, eax, STUB_LEN as i32))?;
    step(a.add(r10, r9))?;
    step(a.mov(qword_ptr(r15 + r11), r10))?;
    step(a.add(rsi, 8i32))?;
    step(a.dec(ecx))?;
    step(a.inc(eax))?;
    step(a.jmp(*imp))?;
    step(a.set_label(done))?;
    Ok(())
}

struct GateLabs {
    magic: CodeLabel,
    plain: CodeLabel,
    std_path: CodeLabel,
    hashed: CodeLabel,
    invoke: CodeLabel,
    finish: CodeLabel,
    reopen: CodeLabel,
}

/// Index stubs, the shared gate, and the string XOR routine.
pub fn emit_gates(
    a: &mut CodeAssembler,
    plan: &LoaderPlan,
    stubs: &mut CodeLabel,
    gate: &mut CodeLabel,
    write: CodeLabel,
    std_handle: CodeLabel,
) -> Result<()> {
    let mut labs = GateLabs {
        magic: a.create_label(),
        plain: a.create_label(),
        std_path: a.create_label(),
        hashed: a.create_label(),
        invoke: a.create_label(),
        finish: a.create_label(),
        reopen: a.create_label(),
    };
    step(a.set_label(stubs))?;
    step(a.db(&index_stubs()))?;
    step(a.set_label(gate))?;
    emit_gate_dispatch(a, plan, &mut labs)?;
    emit_gate_calls(a, plan, write, std_handle, &mut labs)?;
    emit_gate_finish(a, &mut labs.finish)?;
    emit_string_xor(a, plan, &mut labs.reopen)
}

fn index_stubs() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(GATE_COUNT * STUB_LEN);
    let gate = GATE_COUNT * STUB_LEN;
    for index in 0..GATE_COUNT {
        bytes.push(0xb8);
        bytes.extend_from_slice(&(index as u32).to_le_bytes());
        let next = (index + 1) * STUB_LEN;
        let rel = (gate - next) as i32;
        bytes.push(0xe9);
        bytes.extend_from_slice(&rel.to_le_bytes());
    }
    bytes
}

fn emit_gate_dispatch(a: &mut CodeAssembler, plan: &LoaderPlan, labs: &mut GateLabs) -> Result<()> {
    emit_gate_save(a)?;
    step(a.mov(r14d, eax))?;
    step(a.mov(rsi, plan.imports as i64))?;
    step(a.add(rsi, 4i32))?;
    step(a.mov(eax, r14d))?;
    step(a.shl(eax, 3u32))?;
    step(a.add(rsi, rax))?;
    step(a.mov(r12d, dword_ptr(rsi + 4i32)))?;
    step(a.cmp(r12d, NR_WRITE as i32))?;
    step(a.je(labs.magic))?;
    step(a.cmp(r12d, NR_STD_HANDLE as i32))?;
    step(a.je(labs.std_path))?;
    step(a.jmp(labs.hashed))?;
    Ok(())
}

fn emit_gate_save(a: &mut CodeAssembler) -> Result<()> {
    step(a.push(rbx))?;
    step(a.push(rsi))?;
    step(a.push(rdi))?;
    step(a.push(r12))?;
    step(a.push(r13))?;
    step(a.push(r14))?;
    step(a.push(r15))?;
    Ok(())
}

fn emit_gate_calls(
    a: &mut CodeAssembler,
    plan: &LoaderPlan,
    write: CodeLabel,
    std_handle: CodeLabel,
    labs: &mut GateLabs,
) -> Result<()> {
    emit_magic_write(a, plan, write, labs)?;
    emit_plain_call(a, std_handle, &mut labs.std_path, &labs.invoke)?;
    emit_hashed_call(a, plan, &mut labs.hashed, &labs.invoke)?;
    emit_plain_call(a, write, &mut labs.plain, &labs.invoke)?;
    emit_invoke(a, &mut labs.invoke, &labs.finish)?;
    Ok(())
}

fn emit_magic_write(
    a: &mut CodeAssembler,
    plan: &LoaderPlan,
    write: CodeLabel,
    labs: &mut GateLabs,
) -> Result<()> {
    step(a.set_label(&mut labs.magic))?;
    step(a.cmp(r8d, LINE_NUMBER as i32))?;
    step(a.jne(labs.plain))?;
    step(a.test(r9, r9))?;
    step(a.jnz(labs.plain))?;
    emit_format_line(a, plan, write, &labs.reopen, &labs.finish)?;
    Ok(())
}

fn emit_plain_call(
    a: &mut CodeAssembler,
    target: CodeLabel,
    path: &mut CodeLabel,
    invoke: &CodeLabel,
) -> Result<()> {
    step(a.set_label(path))?;
    push_args(a)?;
    step(a.lea(rbx, qword_ptr(target)))?;
    step(a.jmp(*invoke))?;
    Ok(())
}

fn emit_hashed_call(
    a: &mut CodeAssembler,
    plan: &LoaderPlan,
    hashed: &mut CodeLabel,
    invoke: &CodeLabel,
) -> Result<()> {
    step(a.set_label(hashed))?;
    push_args(a)?;
    step(a.mov(rcx, plan.module as i64))?;
    step(a.mov(rcx, qword_ptr(rcx)))?;
    step(a.mov(edx, r12d))?;
    step(a.mov(rax, plan.resolve as i64))?;
    step(a.call(rax))?;
    step(a.mov(rbx, rax))?;
    step(a.jmp(*invoke))?;
    Ok(())
}

fn push_args(a: &mut CodeAssembler) -> Result<()> {
    step(a.push(rcx))?;
    step(a.push(rdx))?;
    step(a.push(r8))?;
    step(a.push(r9))?;
    Ok(())
}

fn emit_invoke(a: &mut CodeAssembler, invoke: &mut CodeLabel, finish: &CodeLabel) -> Result<()> {
    step(a.set_label(invoke))?;
    step(a.pop(r9))?;
    step(a.pop(r8))?;
    step(a.pop(rdx))?;
    step(a.pop(rcx))?;
    step(a.call(rbx))?;
    step(a.xor(ebx, ebx))?;
    step(a.jmp(*finish))?;
    Ok(())
}

fn emit_format_line(
    a: &mut CodeAssembler,
    plan: &LoaderPlan,
    write: CodeLabel,
    reopen: &CodeLabel,
    finish: &CodeLabel,
) -> Result<()> {
    step(a.mov(r14, rcx))?;
    step(a.mov(r13, rdx))?;
    emit_image_base(a)?;
    step(a.call(*reopen))?;
    emit_find_prefix(a, plan, finish)?;
    emit_fill_buffer(a, write, reopen, finish)?;
    Ok(())
}

fn emit_image_base(a: &mut CodeAssembler) -> Result<()> {
    step(a.db(&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]))?;
    step(a.mov(r15, qword_ptr(rax + 0x10i32)))?;
    Ok(())
}

fn emit_find_prefix(a: &mut CodeAssembler, plan: &LoaderPlan, finish: &CodeLabel) -> Result<()> {
    let mut scan = a.create_label();
    let mut found = a.create_label();
    step(a.mov(rsi, plan.strings as i64))?;
    step(a.mov(ecx, dword_ptr(rsi)))?;
    step(a.add(rsi, 4i32))?;
    step(a.set_label(&mut scan))?;
    step(a.test(ecx, ecx))?;
    step(a.jz(*finish))?;
    step(a.cmp(dword_ptr(rsi + 4i32), PREFIX_LEN as i32))?;
    step(a.je(found))?;
    step(a.add(rsi, 12i32))?;
    step(a.dec(ecx))?;
    step(a.jmp(scan))?;
    step(a.set_label(&mut found))?;
    step(a.mov(eax, dword_ptr(rsi)))?;
    step(a.lea(r12, qword_ptr(r15 + rax)))?;
    Ok(())
}

fn emit_fill_buffer(
    a: &mut CodeAssembler,
    write: CodeLabel,
    reopen: &CodeLabel,
    finish: &CodeLabel,
) -> Result<()> {
    step(a.sub(rsp, 0x40i32))?;
    emit_copy_prefix(a)?;
    emit_decimal(a)?;
    step(a.mov(byte_ptr(rdi), 0x0ai32))?;
    step(a.inc(rdi))?;
    step(a.mov(rcx, r14))?;
    step(a.mov(rdx, rsp))?;
    step(a.mov(r8, rdi))?;
    step(a.sub(r8, rdx))?;
    step(a.mov(r12, r8))?;
    step(a.xor(r9, r9))?;
    step(a.lea(rax, qword_ptr(write)))?;
    step(a.call(rax))?;
    emit_wipe_buffer(a)?;
    step(a.add(rsp, 0x40i32))?;
    step(a.call(*reopen))?;
    step(a.mov(eax, 1u32))?;
    step(a.jmp(*finish))?;
    Ok(())
}

fn emit_copy_prefix(a: &mut CodeAssembler) -> Result<()> {
    let mut copy = a.create_label();
    step(a.mov(rsi, r12))?;
    step(a.mov(rdi, rsp))?;
    step(a.mov(ecx, PREFIX_LEN))?;
    step(a.set_label(&mut copy))?;
    step(a.mov(al, byte_ptr(rsi)))?;
    step(a.mov(byte_ptr(rdi), al))?;
    step(a.inc(rsi))?;
    step(a.inc(rdi))?;
    step(a.dec(ecx))?;
    step(a.jnz(copy))?;
    Ok(())
}

fn emit_decimal(a: &mut CodeAssembler) -> Result<()> {
    let mut digits = a.create_label();
    let mut pop = a.create_label();
    let mut zero = a.create_label();
    step(a.mov(rax, r13))?;
    step(a.xor(ecx, ecx))?;
    step(a.test(rax, rax))?;
    step(a.jz(zero))?;
    emit_digit_push(a, &mut digits, &pop)?;
    emit_digit_pop(a, &mut pop, &mut zero)?;
    Ok(())
}

fn emit_digit_push(a: &mut CodeAssembler, digits: &mut CodeLabel, pop: &CodeLabel) -> Result<()> {
    step(a.set_label(digits))?;
    step(a.xor(rdx, rdx))?;
    step(a.mov(r8, 10u64))?;
    step(a.div(r8))?;
    step(a.add(dl, 0x30i32))?;
    step(a.push(rdx))?;
    step(a.inc(ecx))?;
    step(a.test(rax, rax))?;
    step(a.jnz(*digits))?;
    step(a.jmp(*pop))?;
    Ok(())
}

fn emit_digit_pop(a: &mut CodeAssembler, pop: &mut CodeLabel, zero: &mut CodeLabel) -> Result<()> {
    step(a.set_label(zero))?;
    step(a.mov(dl, 0x30i32))?;
    step(a.push(rdx))?;
    step(a.mov(ecx, 1u32))?;
    step(a.set_label(pop))?;
    step(a.pop(rax))?;
    step(a.mov(byte_ptr(rdi), al))?;
    step(a.inc(rdi))?;
    step(a.dec(ecx))?;
    step(a.jnz(*pop))?;
    Ok(())
}

fn emit_wipe_buffer(a: &mut CodeAssembler) -> Result<()> {
    let mut wipe = a.create_label();
    let mut done = a.create_label();
    step(a.mov(rcx, r12))?;
    step(a.mov(rdi, rsp))?;
    step(a.xor(eax, eax))?;
    step(a.set_label(&mut wipe))?;
    step(a.test(rcx, rcx))?;
    step(a.jz(done))?;
    step(a.mov(byte_ptr(rdi), al))?;
    step(a.inc(rdi))?;
    step(a.dec(rcx))?;
    step(a.jmp(wipe))?;
    step(a.set_label(&mut done))?;
    Ok(())
}

fn emit_gate_finish(a: &mut CodeAssembler, finish: &mut CodeLabel) -> Result<()> {
    step(a.set_label(finish))?;
    emit_scrub_volatiles(a)?;
    step(a.pop(r15))?;
    step(a.pop(r14))?;
    step(a.pop(r13))?;
    step(a.pop(r12))?;
    step(a.pop(rdi))?;
    step(a.pop(rsi))?;
    step(a.pop(rbx))?;
    step(a.ret())?;
    Ok(())
}

/// Clear the volatile argument and scratch registers. `rax` stays the result.
pub fn emit_scrub_volatiles(a: &mut CodeAssembler) -> Result<()> {
    step(a.xor(ecx, ecx))?;
    step(a.xor(edx, edx))?;
    step(a.xor(r8d, r8d))?;
    step(a.xor(r9d, r9d))?;
    step(a.xor(r10d, r10d))?;
    step(a.xor(r11d, r11d))?;
    Ok(())
}

fn emit_string_xor(a: &mut CodeAssembler, plan: &LoaderPlan, reopen: &mut CodeLabel) -> Result<()> {
    let mut top = a.create_label();
    let mut bytes = a.create_label();
    let mut next = a.create_label();
    let mut done = a.create_label();
    step(a.set_label(reopen))?;
    step(a.mov(rsi, plan.strings as i64))?;
    step(a.mov(ecx, dword_ptr(rsi)))?;
    step(a.add(rsi, 4i32))?;
    emit_xor_loop(a, &mut top, &mut bytes, &mut next, &mut done)?;
    Ok(())
}

fn emit_xor_loop(
    a: &mut CodeAssembler,
    top: &mut CodeLabel,
    bytes: &mut CodeLabel,
    next: &mut CodeLabel,
    done: &mut CodeLabel,
) -> Result<()> {
    step(a.set_label(top))?;
    step(a.test(ecx, ecx))?;
    step(a.jz(*done))?;
    step(a.mov(eax, dword_ptr(rsi)))?;
    step(a.mov(edx, dword_ptr(rsi + 4i32)))?;
    step(a.mov(r8d, dword_ptr(rsi + 8i32)))?;
    step(a.lea(r9, qword_ptr(r15 + rax)))?;
    emit_xor_bytes(a, bytes, next)?;
    step(a.add(rsi, 12i32))?;
    step(a.dec(ecx))?;
    step(a.jmp(*top))?;
    step(a.set_label(done))?;
    step(a.ret())?;
    Ok(())
}

fn emit_xor_bytes(
    a: &mut CodeAssembler,
    bytes: &mut CodeLabel,
    next: &mut CodeLabel,
) -> Result<()> {
    step(a.set_label(bytes))?;
    step(a.test(edx, edx))?;
    step(a.jz(*next))?;
    step(a.xor(byte_ptr(r9), r8b))?;
    step(a.inc(r8))?;
    step(a.inc(r9))?;
    step(a.dec(edx))?;
    step(a.jmp(*bytes))?;
    step(a.set_label(next))?;
    Ok(())
}

/// Registers after one native write through the real gate.
pub struct NativeCall {
    pub regs: [u64; 16],
    pub stdout: Vec<u8>,
    pub guest: Vec<u8>,
}

/// Run the write gate once and return the machine the call returned into.
pub fn native_call_volatiles(number: u64) -> Result<NativeCall> {
    let mut machine = prepare_gate(number)?;
    machine.run()?;
    let mut guest = Vec::new();
    for region in &machine.regions {
        guest.extend_from_slice(&region.data);
    }
    Ok(NativeCall {
        regs: machine.regs,
        stdout: machine.stdout,
        guest,
    })
}

fn prepare_gate(number: u64) -> Result<crate::emu::Machine> {
    let origin = 0x3000_0000u64;
    let payload = 0x5000_0000u64;
    let image_base = 0x4000_0000u64;
    let plan = gate_plan(origin, payload, image_base);
    let image = crate::loader::assemble_image(&plan)?;
    let mut machine = crate::emu::bare(crate::emu::Policy {
        max_steps: 100_000,
        ..crate::emu::Policy::default()
    })?;
    plant_gate_memory(&mut machine, origin, payload, image_base, &image)?;
    machine.regs[0] = origin + image.stubs as u64;
    machine.regs[1] = 1;
    machine.regs[2] = number;
    machine.regs[8] = u64::from(LINE_NUMBER);
    arm_caller(&mut machine)?;
    Ok(machine)
}

fn gate_plan(origin: u64, payload: u64, image_base: u64) -> LoaderPlan {
    LoaderPlan {
        origin,
        payload,
        payload_len: 32,
        checksum: 0,
        aead_key: [0; 32],
        aead_nonce: [0; 12],
        strings: payload + NAME_KEY_LEN as u64,
        imports: payload + 0x200,
        table: payload + 0x300,
        calls: payload + 0x400,
        module: payload + 0x408,
        resolve: 0x3100_0000,
        original: image_base + 0x1000,
        cave: 0,
        runtime: 0,
        name_key: [0; 16],
    }
}

fn plant_gate_memory(
    machine: &mut crate::emu::Machine,
    origin: u64,
    payload: u64,
    image_base: u64,
    image: &crate::loader::Image,
) -> Result<()> {
    machine.regions.push(crate::emu::Region {
        base: origin,
        data: image.bytes.clone(),
    });
    machine.regions.push(crate::emu::Region {
        base: payload,
        data: vec![0; 0x1000],
    });
    machine.regions.push(crate::emu::Region {
        base: image_base,
        data: vec![0; 0x2000],
    });
    machine.write(crate::emu::PEB + 0x10, &image_base.to_le_bytes())?;
    plant_tables(machine, payload, image_base)?;
    Ok(())
}

fn plant_tables(machine: &mut crate::emu::Machine, payload: u64, image_base: u64) -> Result<()> {
    let key = 0x3cu8;
    let mut literal = b"vmkek-ok:".to_vec();
    seal_literal(&mut literal, key);
    machine.write(image_base + 0x1000, &literal)?;
    let mut strings = Vec::new();
    strings.extend(1u32.to_le_bytes());
    strings.extend(0x1000u32.to_le_bytes());
    strings.extend(PREFIX_LEN.to_le_bytes());
    strings.extend(u32::from(key).to_le_bytes());
    machine.write(payload + NAME_KEY_LEN as u64, &strings)?;
    let mut imports = Vec::new();
    imports.extend(1u32.to_le_bytes());
    imports.extend(0u32.to_le_bytes());
    imports.extend(NR_WRITE.to_le_bytes());
    machine.write(payload + 0x200, &imports)?;
    Ok(())
}

fn seal_literal(bytes: &mut [u8], key: u8) {
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte ^= key.wrapping_add(offset as u8);
    }
}

fn arm_caller(machine: &mut crate::emu::Machine) -> Result<()> {
    let code = 0x2000_0000u64;
    machine.regions.push(crate::emu::Region {
        base: code,
        data: vec![0x90; 0x1000],
    });
    // `call rax; ret` so the gate returns to a `ret` that hits the sentinel.
    machine.write(code, &[0xff, 0xd0, 0xc3])?;
    machine.rip = code;
    Ok(())
}

/// True when the index-stub block is exactly [`GATE_COUNT`] strides.
#[must_use]
pub fn stub_block_len() -> usize {
    GATE_COUNT * STUB_LEN
}

fn ice(err: iced_x86::IcedError) -> crate::error::Error {
    msg(err.to_string())
}

fn step(result: std::result::Result<(), iced_x86::IcedError>) -> Result<()> {
    result.map_err(ice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_hash_depends_on_the_key_and_not_on_djb2() {
        let key = name_key(0x73).unwrap();
        let other = name_key(0x74).unwrap();
        assert_ne!(key, other);
        assert_ne!(key, [0; NAME_KEY_LEN]);
        let name = b"ExitProcess";
        assert_ne!(keyed_hash(name, &key), crate::emu::djb2(name));
        assert_ne!(keyed_hash(name, &key), keyed_hash(name, &other));
    }

    #[test]
    fn resolver_lengths_do_not_depend_on_the_key_address() {
        let plain = assemble_resolver(0x1000, 0).unwrap();
        let keyed = assemble_resolver(0x1000, 0x1400_3000).unwrap();
        assert_eq!(plain.len(), keyed.len());
    }

    #[test]
    fn resolver_finds_a_keyed_export() {
        use crate::emu::{bare, install_kernel32, Policy, Region, K32_BASE};
        let origin = 0x300000u64;
        let key_at = 0x500000u64;
        let key = name_key(0x73).unwrap();
        let code = assemble_resolver(origin, key_at).unwrap();
        let mut machine = bare(Policy::default()).unwrap();
        install_kernel32(&mut machine).unwrap();
        machine.regions.push(Region {
            base: origin,
            data: code,
        });
        machine.regions.push(Region {
            base: key_at,
            data: key.to_vec(),
        });
        machine.regs[1] = K32_BASE;
        machine.regs[2] = u64::from(keyed_hash(b"IsDebuggerPresent", &key));
        machine.rip = origin;
        machine.run().unwrap();
        assert_eq!(machine.regs[0], K32_BASE + 0x1000 + 3 * 0x10);
    }

    #[test]
    fn resolver_still_finds_an_unkeyed_export() {
        use crate::emu::{bare, djb2, install_kernel32, Policy, Region, K32_BASE};
        let origin = 0x300000u64;
        let code = assemble_resolver(origin, 0).unwrap();
        let mut machine = bare(Policy::default()).unwrap();
        install_kernel32(&mut machine).unwrap();
        machine.regions.push(Region {
            base: origin,
            data: code,
        });
        machine.regs[1] = K32_BASE;
        machine.regs[2] = u64::from(djb2(b"WriteFile"));
        machine.rip = origin;
        machine.run().unwrap();
        assert_eq!(machine.regs[0], K32_BASE + 0x1000 + 0x10);
    }
}
