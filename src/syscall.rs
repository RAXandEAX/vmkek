//! Direct syscall slots for the sample's own kernel calls.
//!
//! Each slot is a number, not an API name. The loader plants a separate stub
//! for that number. The sample call enters its own stub and does not pass
//! through the kernel32 export walk or the libc link-map walk. Other imports
//! stay on those walks so the detectors still resolve.

use iced_x86::code_asm::*;

use crate::emu::djb2;
use crate::error::{msg, Result};

/// Linux `write`.
pub const NR_WRITE: u32 = 1;
/// Linux `exit_group`. Matches the process exit of libc `exit`.
pub const NR_EXIT_GROUP: u32 = 231;
/// M-EMU stand-in for the sample's `GetStdHandle`. Not an NT syscall index.
pub const NR_STD_HANDLE: u32 = 199;

/// Syscall number when `name` is one of the sample's own kernel calls.
#[must_use]
pub fn direct_nr(name: &[u8]) -> Option<u32> {
    match name {
        b"WriteFile" | b"write" => Some(NR_WRITE),
        b"exit" => Some(NR_EXIT_GROUP),
        b"GetStdHandle" => Some(NR_STD_HANDLE),
        _ => None,
    }
}

/// Slot word stored beside an IAT or GOT rva: a syscall number, or a djb2 hash.
#[must_use]
pub fn slot_value(name: &[u8]) -> u32 {
    direct_nr(name).unwrap_or_else(|| djb2(name))
}

/// `true` when `value` selects a direct stub instead of a hashed import.
#[must_use]
pub fn is_direct_slot(value: u32) -> bool {
    matches!(value, NR_WRITE | NR_EXIT_GROUP | NR_STD_HANDLE)
}

/// Load-time choice for one PE slot. `edx` is the slot word and `r12` is kernel32.
///
/// `rax` is the stub, or the export the hash walk returned. The sample call
/// does not enter this sequence.
pub fn emit_pe_bind(
    a: &mut CodeAssembler,
    resolve: u64,
    write: CodeLabel,
    std_handle: CodeLabel,
) -> Result<()> {
    let mut not_write = a.create_label();
    let mut hashed = a.create_label();
    let mut ready = a.create_label();
    step(a.cmp(edx, NR_WRITE as i32))?;
    step(a.jne(not_write))?;
    step(a.lea(rax, qword_ptr(write)))?;
    step(a.jmp(ready))?;
    step(a.set_label(&mut not_write))?;
    step(a.cmp(edx, NR_STD_HANDLE as i32))?;
    step(a.jne(hashed))?;
    step(a.lea(rax, qword_ptr(std_handle)))?;
    step(a.jmp(ready))?;
    step(a.set_label(&mut hashed))?;
    step(a.mov(rcx, r12))?;
    step(a.mov(rax, resolve as i64))?;
    step(a.call(rax))?;
    step(a.set_label(&mut ready))?;
    Ok(())
}

/// Load-time choice for one ELF slot. `r13d` is the slot word.
///
/// `rax` is the stub, or the libc symbol the link-map walk returned.
pub fn emit_elf_bind(
    a: &mut CodeAssembler,
    resolve: CodeLabel,
    write: CodeLabel,
    exit: CodeLabel,
) -> Result<()> {
    let mut not_write = a.create_label();
    let mut hashed = a.create_label();
    let mut ready = a.create_label();
    step(a.cmp(r13d, NR_WRITE as i32))?;
    step(a.jne(not_write))?;
    step(a.lea(rax, qword_ptr(write)))?;
    step(a.jmp(ready))?;
    step(a.set_label(&mut not_write))?;
    step(a.cmp(r13d, NR_EXIT_GROUP as i32))?;
    step(a.jne(hashed))?;
    step(a.lea(rax, qword_ptr(exit)))?;
    step(a.jmp(ready))?;
    step(a.set_label(&mut hashed))?;
    step(a.mov(edi, r13d))?;
    step(a.call(resolve))?;
    step(a.set_label(&mut ready))?;
    Ok(())
}

/// Win64 `GetStdHandle` and `WriteFile` stubs. Each ends in its own `syscall`.
pub fn emit_pe_stubs(
    a: &mut CodeAssembler,
    write: &mut CodeLabel,
    std_handle: &mut CodeLabel,
) -> Result<()> {
    emit_std_stub(a, std_handle)?;
    emit_write_stub(a, write)
}

/// SysV `write` and `exit` stubs. Each ends in its own `syscall`.
pub fn emit_linux_stubs(
    a: &mut CodeAssembler,
    write: &mut CodeLabel,
    exit: &mut CodeLabel,
) -> Result<()> {
    emit_linux_write(a, write)?;
    emit_linux_exit(a, exit)
}

fn emit_std_stub(a: &mut CodeAssembler, std_handle: &mut CodeLabel) -> Result<()> {
    // `syscall` may clobber `rcx` and `r11`. The import leaves `rdi` live.
    step(a.set_label(std_handle))?;
    step(a.push(rdi))?;
    step(a.push(rcx))?;
    step(a.push(r11))?;
    step(a.mov(rdi, rcx))?;
    step(a.mov(eax, NR_STD_HANDLE))?;
    step(a.syscall())?;
    step(a.pop(r11))?;
    step(a.pop(rcx))?;
    step(a.pop(rdi))?;
    step(a.ret())
}

fn emit_write_stub(a: &mut CodeAssembler, write: &mut CodeLabel) -> Result<()> {
    let mut skip = a.create_label();
    step(a.set_label(write))?;
    save_write_regs(a)?;
    step(a.mov(rdi, rcx))?;
    step(a.mov(rsi, rdx))?;
    step(a.mov(rdx, r8))?;
    step(a.mov(eax, NR_WRITE))?;
    step(a.syscall())?;
    restore_write_regs(a)?;
    step(a.test(r9, r9))?;
    step(a.jz(skip))?;
    step(a.mov(dword_ptr(r9), eax))?;
    step(a.set_label(&mut skip))?;
    step(a.mov(eax, 1u32))?;
    step(a.ret())
}

fn save_write_regs(a: &mut CodeAssembler) -> Result<()> {
    step(a.push(r9))?;
    step(a.push(rdi))?;
    step(a.push(rsi))?;
    step(a.push(rdx))?;
    step(a.push(rcx))?;
    step(a.push(r11))
}

fn restore_write_regs(a: &mut CodeAssembler) -> Result<()> {
    step(a.pop(r11))?;
    step(a.pop(rcx))?;
    step(a.pop(rdx))?;
    step(a.pop(rsi))?;
    step(a.pop(rdi))?;
    step(a.pop(r9))
}

fn emit_linux_write(a: &mut CodeAssembler, write: &mut CodeLabel) -> Result<()> {
    step(a.set_label(write))?;
    step(a.mov(eax, NR_WRITE))?;
    step(a.syscall())?;
    step(a.ret())
}

fn emit_linux_exit(a: &mut CodeAssembler, exit: &mut CodeLabel) -> Result<()> {
    step(a.set_label(exit))?;
    step(a.mov(eax, NR_EXIT_GROUP))?;
    step(a.syscall())?;
    step(a.ud2())
}

fn step(result: std::result::Result<(), iced_x86::IcedError>) -> Result<()> {
    result.map_err(|err| msg(err.to_string()))
}

/// Assembled PE stubs. `write` and `other` are offsets of the two entries.
pub struct StubImage {
    pub bytes: Vec<u8>,
    pub write: usize,
    pub other: usize,
}

/// Win64 stubs used by the PE loader and by the M-EMU comparison.
pub fn pe_stubs() -> Result<StubImage> {
    assemble_stubs(true)
}

/// SysV stubs used by the ELF loader and by the M-LINUX image scan.
pub fn linux_stubs() -> Result<StubImage> {
    assemble_stubs(false)
}

/// Bytes of one stub. The two entries do not overlap.
#[must_use]
pub fn stub_body(image: &StubImage, at: usize) -> &[u8] {
    let end = if at == image.write {
        image.other
    } else {
        image.write
    };
    let end = if end > at { end } else { image.bytes.len() };
    &image.bytes[at..end]
}

fn assemble_stubs(pe: bool) -> Result<StubImage> {
    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut write = a.create_label();
    let mut other = a.create_label();
    if pe {
        emit_pe_stubs(&mut a, &mut write, &mut other)?;
    } else {
        emit_linux_stubs(&mut a, &mut write, &mut other)?;
    }
    let origin = 0x400000u64;
    let encoded = a
        .assemble_options(
            origin,
            iced_x86::BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )
        .map_err(|err| msg(err.to_string()))?;
    let write_ip = encoded
        .label_ip(&write)
        .map_err(|err| msg(err.to_string()))?;
    let other_ip = encoded
        .label_ip(&other)
        .map_err(|err| msg(err.to_string()))?;
    Ok(StubImage {
        bytes: encoded.inner.code_buffer,
        write: off(write_ip, origin)?,
        other: off(other_ip, origin)?,
    })
}

fn off(ip: u64, origin: u64) -> Result<usize> {
    usize::try_from(ip.wrapping_sub(origin)).map_err(|_| msg("stub ip"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_slots_are_not_name_hashes() {
        for name in [b"WriteFile".as_slice(), b"write", b"exit", b"GetStdHandle"] {
            let slot = slot_value(name);
            assert!(
                is_direct_slot(slot),
                "{}",
                std::str::from_utf8(name).unwrap()
            );
            assert_ne!(slot, djb2(name));
        }
        let hashed = slot_value(b"ExitProcess");
        assert!(!is_direct_slot(hashed));
        assert_eq!(hashed, djb2(b"ExitProcess"));
        assert!(hashed > 0x1_0000);
    }

    #[test]
    fn each_stub_is_its_own_syscall() {
        for image in [pe_stubs().unwrap(), linux_stubs().unwrap()] {
            let write = stub_body(&image, image.write);
            let other = stub_body(&image, image.other);
            assert_ne!(write, other);
            assert!(write.windows(2).any(|word| word == [0x0f, 0x05]));
            assert!(other.windows(2).any(|word| word == [0x0f, 0x05]));
            assert!(!write.contains(&0xe8));
            assert!(!other.contains(&0xe8));
        }
    }
}
