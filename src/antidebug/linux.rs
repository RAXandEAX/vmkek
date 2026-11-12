//! Linux probes for a protected ELF.
//!
//! `TracerPid`, a failed `ptrace(PTRACE_TRACEME)`, and a `clock_gettime` delta
//! each have their own bit in the function runtime. The open loader can exit
//! early. The bytecode check calls the same probes and, on a hit, xors the
//! thread chain that S5b keeps as the block key. Nopping only the loader
//! leaves that check in place.

use std::cell::Cell;

use iced_x86::code_asm::*;

use crate::error::{msg, Result};
use crate::vm::{RT_CLOCK_NS, RT_KEY, RT_LINUX, RT_MASTER, RT_TERM};

use super::{step, KEY_POISON};

/// `TracerPid` in `/proc/self/status`.
pub const LINUX_TRACER: u32 = 1;
/// `ptrace(PTRACE_TRACEME)` fails because a tracer is already attached.
pub const LINUX_PTRACE: u32 = 2;
/// Two `clock_gettime` samples differ by more than the stored limit.
pub const LINUX_CLOCK: u32 = 4;
/// Every Linux probe. This is the mask `protect` writes unless a test overrides it.
pub const LINUX_ALL: u32 = LINUX_TRACER | LINUX_PTRACE | LINUX_CLOCK;
/// Default delta ceiling, in nanoseconds.
pub const CLOCK_LIMIT_NS: u32 = 1_000_000_000;

const LOADER_MARK: u32 = 0xE311_4C01;
const LOADER_MARK_END: u32 = 0xE311_4C02;
pub(crate) const EARLY_MARK: u32 = 0xC6EA_1101;
pub(crate) const EARLY_END: u32 = 0xC6EA_1102;
const STACK: i32 = 0xC00;
const OFF_BUF: i32 = 0;
const BUF_LEN: i32 = 0x800;
const OFF_PATH: i32 = 0x800;
const OFF_NEEDLE: i32 = 0x820;
const OFF_FD: i32 = 0x830;
const OFF_T0: i32 = 0x840;
const OFF_T1: i32 = 0x850;
const SPIN: u32 = 0x4000;
const SYS_CLOSE: u32 = 3;
const SYS_PTRACE: u32 = 101;
const SYS_CLOCK: u32 = 228;
const SYS_EXIT: u32 = 231;
const SYS_OPENAT: u32 = 257;

#[derive(Clone, Copy)]
struct Arm {
    mask: u32,
    limit: u32,
}

thread_local! {
    static ARM: Cell<Arm> = const {
        Cell::new(Arm {
            mask: LINUX_ALL,
            limit: CLOCK_LIMIT_NS,
        })
    };
}

struct Restore(Arm);

impl Drop for Restore {
    fn drop(&mut self) {
        ARM.with(|cell| cell.set(self.0));
    }
}

/// Run `body` while ELF `protect` stamps `mask` and `limit_ns` into the entry runtime.
pub fn with_linux_detectors<T>(mask: u32, limit_ns: u32, body: impl FnOnce() -> T) -> T {
    let prev = ARM.with(|cell| {
        cell.replace(Arm {
            mask,
            limit: limit_ns,
        })
    });
    let _restore = Restore(prev);
    body()
}

pub(crate) fn linux_arm() -> (u32, u32) {
    ARM.with(|cell| {
        let arm = cell.get();
        (arm.mask, arm.limit)
    })
}

/// Nop the loader's Linux block. The bytecode check is outside that range.
pub fn neutralize_loader_linux(file: &mut [u8]) -> Result<()> {
    let (from, _) = find_mov_r11d(file, LOADER_MARK)?;
    let (_, to) = find_mov_r11d(file, LOADER_MARK_END)?;
    if to <= from || to - from > 0x1000 {
        return Err(msg("linux loader marks are out of range"));
    }
    file[from..to].fill(0x90);
    Ok(())
}

/// Loader prefix. A hit jumps to `trip` with `r13` still the runtime.
pub(crate) fn emit_linux_loader(
    a: &mut CodeAssembler,
    runtime: u64,
    trip: &mut CodeLabel,
) -> Result<()> {
    let mut skip = a.create_label();
    step(a.mov(r11d, LOADER_MARK))?;
    step(a.mov(r13, runtime as i64))?;
    step(a.test(r13, r13))?;
    step(a.jz(skip))?;
    step(a.push(rdx))?;
    step(a.sub(rsp, STACK))?;
    emit_checks(a, trip, false)?;
    step(a.add(rsp, STACK))?;
    step(a.pop(rdx))?;
    step(a.set_label(&mut skip))?;
    step(a.mov(r11d, LOADER_MARK_END))?;
    Ok(())
}

/// `.init_array` tracer. `r13` addresses a runtime whose linux mask is set.
pub(crate) fn emit_early_tracer(a: &mut CodeAssembler, trip: &mut CodeLabel) -> Result<()> {
    step(a.mov(r11d, EARLY_MARK))?;
    step(a.sub(rsp, STACK))?;
    emit_tracer(a, trip)?;
    step(a.add(rsp, STACK))?;
    step(a.mov(r11d, EARLY_END))?;
    Ok(())
}

/// Poison the block key the chain copies, then exit `0xDEB6`.
pub(crate) fn emit_linux_exit(a: &mut CodeAssembler) -> Result<()> {
    let poison = i32::from(KEY_POISON);
    step(a.xor(byte_ptr(r13 + RT_KEY), poison))?;
    step(a.xor(byte_ptr(r13 + RT_MASTER), poison))?;
    step(a.xor(byte_ptr(r13 + RT_TERM), poison))?;
    step(a.mov(edi, 0xdeb6u32))?;
    step(a.mov(eax, SYS_EXIT))?;
    step(a.syscall())?;
    Ok(())
}

/// Bytecode check gate. A non-zero return jumps to the chain poison path.
pub(crate) fn emit_linux_gate(
    a: &mut CodeAssembler,
    body: CodeLabel,
    poison: &mut CodeLabel,
) -> Result<()> {
    let mut skip = a.create_label();
    step(a.cmp(dword_ptr(r13 + RT_LINUX), 0i32))?;
    step(a.je(skip))?;
    step(a.call(body))?;
    step(a.test(eax, eax))?;
    step(a.jnz(*poison))?;
    step(a.set_label(&mut skip))?;
    Ok(())
}

/// Probe body. Returns `1` when a bit trips and `0` when every armed probe is clean.
pub(crate) fn emit_linux_body(a: &mut CodeAssembler, body: &mut CodeLabel) -> Result<()> {
    let mut trip = a.create_label();
    let mut done = a.create_label();
    step(a.set_label(body))?;
    step(a.sub(rsp, STACK))?;
    emit_checks(a, &mut trip, true)?;
    step(a.xor(eax, eax))?;
    step(a.jmp(done))?;
    step(a.set_label(&mut trip))?;
    step(a.mov(eax, 1u32))?;
    step(a.set_label(&mut done))?;
    step(a.add(rsp, STACK))?;
    step(a.ret())?;
    Ok(())
}

fn emit_checks(a: &mut CodeAssembler, trip: &mut CodeLabel, ptrace: bool) -> Result<()> {
    emit_tracer(a, trip)?;
    emit_clock(a, trip)?;
    if ptrace {
        emit_ptrace(a, trip)?;
    }
    Ok(())
}

fn emit_tracer(a: &mut CodeAssembler, trip: &mut CodeLabel) -> Result<()> {
    let mut skip = a.create_label();
    emit_bit(a, LINUX_TRACER, &mut skip)?;
    emit_plant(a)?;
    emit_read_status(a, trip, &mut skip)?;
    step(a.set_label(&mut skip))?;
    Ok(())
}

fn emit_clock(a: &mut CodeAssembler, trip: &mut CodeLabel) -> Result<()> {
    let mut skip = a.create_label();
    let mut spin = a.create_label();
    emit_bit(a, LINUX_CLOCK, &mut skip)?;
    emit_gettime(a, OFF_T0, trip)?;
    step(a.mov(ecx, SPIN))?;
    step(a.set_label(&mut spin))?;
    step(a.dec(ecx))?;
    step(a.jnz(spin))?;
    emit_gettime(a, OFF_T1, trip)?;
    emit_delta(a, trip)?;
    step(a.set_label(&mut skip))?;
    Ok(())
}

fn emit_ptrace(a: &mut CodeAssembler, trip: &mut CodeLabel) -> Result<()> {
    let mut skip = a.create_label();
    emit_bit(a, LINUX_PTRACE, &mut skip)?;
    step(a.mov(eax, SYS_PTRACE))?;
    step(a.xor(edi, edi))?;
    step(a.xor(esi, esi))?;
    step(a.xor(edx, edx))?;
    step(a.xor(r10, r10))?;
    step(a.syscall())?;
    step(a.test(rax, rax))?;
    step(a.jnz(*trip))?;
    step(a.set_label(&mut skip))?;
    Ok(())
}

fn emit_bit(a: &mut CodeAssembler, bit: u32, skip: &mut CodeLabel) -> Result<()> {
    step(a.mov(eax, dword_ptr(r13 + RT_LINUX)))?;
    step(a.test(eax, bit as i32))?;
    step(a.jz(*skip))?;
    Ok(())
}

fn emit_plant(a: &mut CodeAssembler) -> Result<()> {
    let path_lo = i64::from_le_bytes(*b"/proc/se");
    let path_hi = i64::from_le_bytes(*b"lf/statu");
    let needle = i64::from_le_bytes(*b"TracerPi");
    step(a.mov(rax, path_lo))?;
    step(a.mov(qword_ptr(rsp + OFF_PATH), rax))?;
    step(a.mov(rax, path_hi))?;
    step(a.mov(qword_ptr(rsp + OFF_PATH + 8), rax))?;
    step(a.mov(byte_ptr(rsp + OFF_PATH + 16), i32::from(b's')))?;
    step(a.mov(byte_ptr(rsp + OFF_PATH + 17), 0i32))?;
    step(a.mov(rax, needle))?;
    step(a.mov(qword_ptr(rsp + OFF_NEEDLE), rax))?;
    step(a.mov(ax, i32::from(u16::from_le_bytes(*b"d:"))))?;
    step(a.mov(word_ptr(rsp + OFF_NEEDLE + 8), ax))?;
    Ok(())
}

fn emit_read_status(
    a: &mut CodeAssembler,
    trip: &mut CodeLabel,
    skip: &mut CodeLabel,
) -> Result<()> {
    emit_open(a, trip)?;
    step(a.mov(dword_ptr(rsp + OFF_FD), eax))?;
    step(a.mov(edi, eax))?;
    step(a.lea(rsi, qword_ptr(rsp + OFF_BUF)))?;
    step(a.mov(edx, BUF_LEN as u32))?;
    step(a.xor(eax, eax))?;
    step(a.syscall())?;
    step(a.mov(r8, rax))?;
    emit_close(a)?;
    step(a.test(r8, r8))?;
    step(a.jle(*trip))?;
    emit_find_pid(a, trip, skip)
}

fn emit_open(a: &mut CodeAssembler, trip: &mut CodeLabel) -> Result<()> {
    step(a.mov(eax, SYS_OPENAT))?;
    step(a.mov(rdi, -100i64))?;
    step(a.lea(rsi, qword_ptr(rsp + OFF_PATH)))?;
    step(a.xor(edx, edx))?;
    step(a.xor(r10, r10))?;
    step(a.syscall())?;
    step(a.test(rax, rax))?;
    step(a.js(*trip))?;
    Ok(())
}

fn emit_close(a: &mut CodeAssembler) -> Result<()> {
    step(a.mov(edi, dword_ptr(rsp + OFF_FD)))?;
    step(a.mov(eax, SYS_CLOSE))?;
    step(a.syscall())?;
    Ok(())
}

fn emit_find_pid(a: &mut CodeAssembler, trip: &mut CodeLabel, skip: &mut CodeLabel) -> Result<()> {
    let mut scan = a.create_label();
    let mut next = a.create_label();
    let mut matched = a.create_label();
    step(a.lea(rsi, qword_ptr(rsp + OFF_BUF)))?;
    step(a.mov(rcx, r8))?;
    step(a.set_label(&mut scan))?;
    step(a.cmp(rcx, 10i32))?;
    step(a.jb(*trip))?;
    step(a.mov(eax, dword_ptr(rsi)))?;
    step(a.cmp(eax, dword_ptr(rsp + OFF_NEEDLE)))?;
    step(a.jne(next))?;
    step(a.mov(eax, dword_ptr(rsi + 4i32)))?;
    step(a.cmp(eax, dword_ptr(rsp + OFF_NEEDLE + 4)))?;
    step(a.jne(next))?;
    step(a.movzx(eax, word_ptr(rsi + 8i32)))?;
    step(a.cmp(ax, word_ptr(rsp + OFF_NEEDLE + 8)))?;
    step(a.je(matched))?;
    step(a.set_label(&mut next))?;
    step(a.inc(rsi))?;
    step(a.dec(rcx))?;
    step(a.jmp(scan))?;
    step(a.set_label(&mut matched))?;
    emit_pid_value(a, trip, skip)
}

fn emit_pid_value(a: &mut CodeAssembler, trip: &mut CodeLabel, skip: &mut CodeLabel) -> Result<()> {
    let mut spaces = a.create_label();
    let mut more = a.create_label();
    let mut digit = a.create_label();
    step(a.add(rsi, 10i32))?;
    step(a.set_label(&mut spaces))?;
    step(a.movzx(eax, byte_ptr(rsi)))?;
    step(a.cmp(al, 0x20i32))?;
    step(a.je(more))?;
    step(a.cmp(al, 9i32))?;
    step(a.jne(digit))?;
    step(a.set_label(&mut more))?;
    step(a.inc(rsi))?;
    step(a.jmp(spaces))?;
    step(a.set_label(&mut digit))?;
    step(a.cmp(al, i32::from(b'0')))?;
    step(a.jne(*trip))?;
    step(a.movzx(ecx, byte_ptr(rsi + 1i32)))?;
    step(a.cmp(cl, i32::from(b'0')))?;
    step(a.jb(*skip))?;
    step(a.cmp(cl, i32::from(b'9')))?;
    step(a.ja(*skip))?;
    step(a.jmp(*trip))?;
    Ok(())
}

fn emit_gettime(a: &mut CodeAssembler, off: i32, trip: &mut CodeLabel) -> Result<()> {
    step(a.mov(eax, SYS_CLOCK))?;
    step(a.mov(edi, 1u32))?;
    step(a.lea(rsi, qword_ptr(rsp + off)))?;
    step(a.syscall())?;
    step(a.test(rax, rax))?;
    step(a.js(*trip))?;
    Ok(())
}

fn emit_delta(a: &mut CodeAssembler, trip: &mut CodeLabel) -> Result<()> {
    step(a.mov(rax, qword_ptr(rsp + OFF_T0)))?;
    step(a.mov(rcx, qword_ptr(rsp + OFF_T1)))?;
    step(a.sub(rcx, rax))?;
    step(a.ja(*trip))?;
    step(a.mov(rax, qword_ptr(rsp + OFF_T0 + 8)))?;
    step(a.mov(rcx, qword_ptr(rsp + OFF_T1 + 8)))?;
    step(a.sub(rcx, rax))?;
    step(a.mov(eax, dword_ptr(r13 + RT_CLOCK_NS)))?;
    step(a.cmp(rcx, rax))?;
    step(a.ja(*trip))?;
    Ok(())
}

fn find_mov_r11d(file: &[u8], imm: u32) -> Result<(usize, usize)> {
    let bytes = imm.to_le_bytes();
    let mut found = None;
    for index in 0..file.len().saturating_sub(4) {
        if file[index..index + 4] != bytes {
            continue;
        }
        let site = mov_r11d_at(file, index);
        if let Some(span) = site {
            if found.is_some() {
                return Err(msg("linux loader mark is not unique"));
            }
            found = Some(span);
        }
    }
    found.ok_or_else(|| msg("linux loader mark is missing"))
}

fn mov_r11d_at(file: &[u8], index: usize) -> Option<(usize, usize)> {
    if index >= 2 && file[index - 2..index] == [0x41, 0xBB] {
        return Some((index - 2, index + 4));
    }
    if index >= 3 && file[index - 3..index] == [0x41, 0xC7, 0xC3] {
        return Some((index - 3, index + 4));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_exit_xors_the_block_key() {
        let mut a = CodeAssembler::new(64).unwrap();
        emit_linux_exit(&mut a).unwrap();
        let bytes = a.assemble(0x1000).unwrap();
        let hits = bytes.iter().filter(|byte| **byte == KEY_POISON).count();
        assert!(hits >= 3, "block key poison {hits}");
    }
}
