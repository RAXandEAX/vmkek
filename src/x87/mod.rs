//! User-mode x87. The 80-bit stack, control word, and status word live in the IR.
//! Arithmetic is performed by the host x87 unit with that control word loaded,
//! so the rounding mode is not Rust's `f64` rounding. Comparisons with the host
//! use the raw 10 bytes of each stack register.

mod host;

use iced_x86::{Decoder, DecoderOptions, Encoder, Instruction, Mnemonic, OpKind, Register};

use crate::error::{msg, Result};
use crate::flags::Flags;
use crate::gp::{self, Cpu};
use crate::ir::{MemIo, X87};
use crate::isa::census::{self, Group, Status};

#[cfg(test)]
mod diff;

/// `true` when the mnemonic is in the L2 x87 group of the L0 census.
#[must_use]
pub fn is_x87(mnemonic: Mnemonic) -> bool {
    let row = census::entry(mnemonic);
    row.status == Status::Lift && row.group == Group::L2X87
}

/// Execute the first x87 instruction in `bytes` on the host unit.
///
/// Bytes after that instruction are not fetched. `ea` is the memory operand's
/// effective address, or `None` when the instruction does not touch memory.
/// Precision and rounding follow the control word in `state`.
#[allow(
    clippy::too_many_arguments,
    reason = "the x87 stack, GPR file, flags, and memory operand are updated through separate borrows"
)]
pub fn execute(
    state: &mut X87,
    regs: &mut [u64; 16],
    flags: &mut Flags,
    af: &mut bool,
    df: bool,
    mem: &mut dyn MemIo,
    bytes: &[u8],
    ip: u64,
    ea: Option<u64>,
) -> Result<()> {
    let insn = decode(bytes, ip)?;
    checked(&insn, state)?;
    let mut buffer = read_operand(mem, ea, &insn)?;
    let mut rax = regs[0];
    host::run(
        state,
        &mut rax,
        flags,
        af,
        df,
        &mut buffer,
        &bytes[..insn.len()],
        ip,
        ea,
        writes_flags(insn.mnemonic()),
    )?;
    regs[0] = rax;
    write_operand(mem, ea, &buffer)
}

/// Apply one decoded x87 instruction to `state`.
///
/// The effective address matches the emulator: a 32-bit address size keeps the
/// low 32 bits, and a GS override adds `cpu.gs`.
pub fn apply(
    state: &mut X87,
    cpu: &mut Cpu,
    mem: &mut dyn MemIo,
    insn: &Instruction,
    original: &[u8],
) -> Result<()> {
    if !is_x87(insn.mnemonic()) {
        return Err(msg("not an x87 instruction"));
    }
    let ea = if has_memory(insn) {
        Some(effective_address(&cpu.regs, cpu.gs, insn)?)
    } else {
        None
    };
    let bytes = bytes_to_run(insn, original)?;
    execute(
        state,
        &mut cpu.regs,
        &mut cpu.flags,
        &mut cpu.af,
        cpu.df,
        mem,
        &bytes,
        insn.ip(),
        ea,
    )
}

/// Effective address of an x87 memory operand.
///
/// This is the emulator's formula: [`gp::address`] masks a 32-bit address size
/// and then adds `gs` for a GS override.
pub(crate) fn effective_address(regs: &[u64; 16], gs: u64, insn: &Instruction) -> Result<u64> {
    let cpu = Cpu {
        regs: *regs,
        flags: Flags::default(),
        af: false,
        df: false,
        gs,
    };
    gp::address(&cpu, insn)
}

/// Host encoding of `bytes` plus the effective address, if the instruction
/// touches memory. The address uses [`effective_address`].
pub(crate) fn machine_step(
    bytes: &[u8],
    ip: u64,
    regs: &[u64; 16],
    gs: u64,
) -> Result<(Vec<u8>, Option<u64>)> {
    let insn = decode(bytes, ip)?;
    let ea = if has_memory(&insn) {
        Some(effective_address(regs, gs, &insn)?)
    } else {
        None
    };
    Ok((bytes_to_run(&insn, bytes)?, ea))
}

pub(crate) fn original_bytes(insn: &Instruction) -> Result<Vec<u8>> {
    encode_insn(insn)
}

/// One owner of the host x87/SSE unit. SSE replay uses the same lock.
pub(crate) fn lock_unit() -> std::sync::MutexGuard<'static, ()> {
    host::lock_unit()
}

fn checked(insn: &Instruction, state: &X87) -> Result<()> {
    if !is_x87(insn.mnemonic()) {
        return Err(msg("not an x87 instruction"));
    }
    if insn.has_lock_prefix() || insn.has_rep_prefix() || insn.has_repne_prefix() {
        return Err(gp::invalid());
    }
    if waiting(insn.mnemonic()) && pending_unmasked(state) {
        return Err(msg("x87 fault"));
    }
    Ok(())
}

fn read_operand(mem: &mut dyn MemIo, ea: Option<u64>, insn: &Instruction) -> Result<Vec<u8>> {
    let mem_len = if ea.is_some() {
        insn.memory_size().size()
    } else {
        0
    };
    if ea.is_some() && mem_len == 0 {
        return Err(msg("x87 memory operand has no size"));
    }
    if let Some(addr) = ea {
        mem.read(addr, mem_len)
    } else {
        Ok(Vec::new())
    }
}

fn write_operand(mem: &mut dyn MemIo, ea: Option<u64>, buffer: &[u8]) -> Result<()> {
    if let Some(addr) = ea {
        mem.write(addr, buffer)?;
    }
    Ok(())
}

pub(crate) fn has_memory(insn: &Instruction) -> bool {
    (0..insn.op_count()).any(|index| insn.op_kind(index) == OpKind::Memory)
}

pub(crate) fn machine_bytes(insn: &Instruction) -> Result<Vec<u8>> {
    let mut copy = *insn;
    if has_memory(insn) {
        copy.set_memory_base(Register::R15);
        copy.set_memory_index(Register::None);
        copy.set_memory_index_scale(1);
        copy.set_memory_displacement64(0);
        copy.set_memory_displ_size(0);
        copy.set_segment_prefix(Register::None);
    }
    encode_insn(&copy)
}

fn bytes_to_run(insn: &Instruction, original: &[u8]) -> Result<Vec<u8>> {
    if has_memory(insn) || original.is_empty() || original.len() > 15 {
        machine_bytes(insn)
    } else {
        Ok(original.to_vec())
    }
}

fn encode_insn(insn: &Instruction) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(64);
    encoder
        .encode(insn, insn.ip())
        .map_err(|_| msg("x87 encoding failed"))?;
    let buf = encoder.take_buffer();
    if buf.is_empty() || buf.len() > 15 {
        return Err(msg("x87 encoding does not fit"));
    }
    Ok(buf)
}

fn decode(bytes: &[u8], ip: u64) -> Result<Instruction> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let insn = decoder.decode();
    if insn.is_invalid() || insn.len() == 0 || insn.len() > bytes.len() {
        return Err(msg("invalid x87 encoding"));
    }
    Ok(insn)
}

fn pending_unmasked(state: &X87) -> bool {
    let exceptions = state.sw & 0x3f;
    let masks = state.cw & 0x3f;
    exceptions & !masks != 0
}

/// Waiting instructions sample a pending unmasked exception before they run.
fn waiting(mnemonic: Mnemonic) -> bool {
    !matches!(
        mnemonic,
        Mnemonic::Fninit
            | Mnemonic::Fnclex
            | Mnemonic::Fnstsw
            | Mnemonic::Fnstcw
            | Mnemonic::Fnstenv
            | Mnemonic::Fnsave
            | Mnemonic::Fneni
            | Mnemonic::Fndisi
            | Mnemonic::Fnsetpm
    )
}

fn writes_flags(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Fcomi | Mnemonic::Fcomip | Mnemonic::Fucomi | Mnemonic::Fucomip
    )
}

pub(crate) fn export_image(state: &X87, image: &mut [u8; 512]) {
    image[0..2].copy_from_slice(&state.cw.to_le_bytes());
    image[2..4].copy_from_slice(&state.sw.to_le_bytes());
    image[4] = compress_tags(state.tw);
    image[5] = 0;
    image[6..8].copy_from_slice(&state.fop.to_le_bytes());
    image[8..16].copy_from_slice(&state.fip.to_le_bytes());
    image[16..24].copy_from_slice(&state.fdp.to_le_bytes());
    for (index, reg) in state.st.iter().enumerate() {
        let off = 32 + index * 16;
        image[off..off + 10].copy_from_slice(reg);
        image[off + 10..off + 16].fill(0);
    }
}

pub(crate) fn import_image(state: &mut X87, image: &[u8; 512]) {
    state.cw = u16::from_le_bytes([image[0], image[1]]);
    state.sw = u16::from_le_bytes([image[2], image[3]]);
    state.fop = u16::from_le_bytes([image[6], image[7]]);
    state.fip = u64::from_le_bytes(image[8..16].try_into().expect("fip"));
    state.fdp = u64::from_le_bytes(image[16..24].try_into().expect("fdp"));
    for (index, reg) in state.st.iter_mut().enumerate() {
        let off = 32 + index * 16;
        reg.copy_from_slice(&image[off..off + 10]);
    }
    state.tw = tag_word(&state.st, state.sw, image[4]);
}

fn compress_tags(tw: u16) -> u8 {
    let mut bits = 0u8;
    for phys in 0..8 {
        let tag = (tw >> (2 * phys)) & 0b11;
        if tag != 0b11 {
            bits |= 1 << phys;
        }
    }
    bits
}

/// Full tag word from the FXSAVE compressed tag byte.
///
/// Bit `i` of `ftw` is physical register `i` (0 empty, 1 occupied). Occupied
/// tags are reclassified from the 80-bit value the same way `FXRSTOR` does.
pub(super) fn tag_word(st: &[[u8; 10]; 8], sw: u16, ftw: u8) -> u16 {
    let top = ((sw >> 11) & 7) as usize;
    let mut tw = 0u16;
    for phys in 0..8usize {
        let logical = phys.wrapping_sub(top) & 7;
        let tag = if ftw & (1 << phys) == 0 {
            0b11
        } else {
            classify(&st[logical])
        };
        tw |= tag << (2 * phys);
    }
    tw
}

fn classify(value: &[u8; 10]) -> u16 {
    let exp = u16::from_le_bytes([value[8], value[9]]) & 0x7fff;
    let significand_zero = value[..8].iter().all(|byte| *byte == 0);
    let integer = value[7] & 0x80 != 0;
    if exp == 0 && significand_zero {
        0b01
    } else if exp == 0 || exp == 0x7fff || !integer {
        0b10
    } else {
        0b00
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f];

    #[test]
    fn stack_is_eight_registers_of_ten_bytes() {
        let state = X87::default();
        assert_eq!(state.st.len(), 8);
        assert!(state.st.iter().all(|reg| reg.len() == 10));
        assert_eq!(state.cw, 0x037f);
        assert_eq!(state.sw, 0);
        assert_eq!(state.tw, 0xffff);
        assert_eq!(state.top(), 0);
    }

    #[test]
    fn trailing_opcode_after_x87_is_not_executed() {
        let mut state = X87::default();
        let mut regs = [0u64; 16];
        let mut flags = Flags::default();
        let mut af = false;
        let mut mem = crate::ir::MapMem::default();
        // fld1; add eax, 1. The add must not run inside the host stub.
        let bytes = [0xd9, 0xe8, 0x83, 0xc0, 0x01];
        execute(
            &mut state, &mut regs, &mut flags, &mut af, false, &mut mem, &bytes, 0x1000, None,
        )
        .expect("fld1");
        assert_eq!(regs[0], 0, "bytes after the x87 instruction must not run");
        assert_eq!(state.st[0], ONE);
        assert_eq!(state.top(), 7);
    }

    fn fld_mem(base: Register, index: Register, scale: u32, disp: i64, seg: Register) -> Vec<u8> {
        let mut insn = Instruction::default();
        insn.set_code(iced_x86::Code::Fld_m32fp);
        insn.set_op0_kind(OpKind::Memory);
        insn.set_memory_base(base);
        if index != Register::None {
            insn.set_memory_index(index);
            insn.set_memory_index_scale(scale);
        }
        if disp != 0 {
            insn.set_memory_displ_size(1);
            insn.set_memory_displacement64(disp as u64);
        }
        if seg != Register::None {
            insn.set_segment_prefix(seg);
        }
        let mut encoder = Encoder::new(64);
        encoder.encode(&insn, 0x1000).expect("encode fld");
        encoder.take_buffer()
    }

    fn emulate_load(bytes: &[u8], regs: [u64; 16], gs: u64, mem: &mut crate::ir::MapMem) -> X87 {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let insn = decoder.decode();
        let mut cpu = crate::gp::Cpu {
            regs,
            flags: Flags::default(),
            af: false,
            df: false,
            gs,
        };
        let mut state = X87::default();
        apply(&mut state, &mut cpu, mem, &insn, bytes).expect("apply");
        state
    }

    fn lift_load(bytes: &[u8], mut regs: [u64; 16], gs: u64, mem: &mut crate::ir::MapMem) -> X87 {
        let program =
            crate::lift::program("x", bytes, 0x1000, bytes.len() as u32, 0).expect("lift");
        let mut flags = Flags::default();
        let mut af = false;
        let mut df = false;
        let mut state = X87::default();
        let mut sse = crate::ir::Sse::default();
        let mut absent =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        crate::ir::exec_program(
            &[program],
            0,
            &mut regs,
            &mut flags,
            &mut af,
            &mut df,
            &mut state,
            &mut sse,
            gs,
            mem,
            0,
            &mut absent,
        )
        .expect("exec");
        state
    }

    fn check_load(bytes: &[u8], regs: [u64; 16], gs: u64, ea: u64) {
        let mut mem = crate::ir::MapMem::default();
        mem.write(ea, &1.0f32.to_le_bytes()).expect("seed");
        let emu = emulate_load(bytes, regs, gs, &mut mem);
        let mut mem = crate::ir::MapMem::default();
        mem.write(ea, &1.0f32.to_le_bytes()).expect("seed");
        let ir = lift_load(bytes, regs, gs, &mut mem);
        assert_eq!(emu.st[0], ONE, "emulator did not load 1.0 from {ea:#x}");
        assert_eq!(ir.st[0], emu.st[0], "ir address diverged from the emulator");
        assert_eq!(ir.fdp, emu.fdp, "fdp");
        assert_eq!(ir.fip, emu.fip, "fip");
    }

    #[test]
    fn gs_base_is_added_on_both_paths() {
        let bytes = fld_mem(Register::RAX, Register::None, 1, 0, Register::GS);
        let mut regs = [0u64; 16];
        regs[0] = 0x20;
        check_load(&bytes, regs, 0x5000, 0x5020);
    }

    #[test]
    fn lifted_x87_address_matches_the_emulator() {
        let bytes = fld_mem(Register::EAX, Register::None, 1, 0, Register::None);
        let mut regs = [0u64; 16];
        regs[0] = 0x1_0000_1200;
        check_load(&bytes, regs, 0, 0x1200);

        let bytes = fld_mem(Register::EAX, Register::ECX, 4, 8, Register::None);
        let mut regs = [0u64; 16];
        regs[0] = 0x1_0000_1000;
        regs[1] = 0x1_0000_0010;
        check_load(&bytes, regs, 0, 0x1048);

        let bytes = fld_mem(Register::RAX, Register::None, 1, 0, Register::GS);
        let mut regs = [0u64; 16];
        regs[0] = 0x20;
        check_load(&bytes, regs, 0x5000, 0x5020);

        let bytes = fld_mem(Register::EAX, Register::None, 1, 0, Register::GS);
        let mut regs = [0u64; 16];
        regs[0] = 0x1_0000_0030;
        check_load(&bytes, regs, 0x8000, 0x8030);

        check_load(&fld_rip(0x1000, 0x1800, Register::None), [0; 16], 0, 0x1800);
        check_load(
            &fld_rip(0x1000, 0x1800, Register::GS),
            [0; 16],
            0x100,
            0x1900,
        );
    }

    fn fld_rip(ip: u64, target: u64, seg: Register) -> Vec<u8> {
        let mut insn = Instruction::default();
        insn.set_code(iced_x86::Code::Fld_m32fp);
        insn.set_op0_kind(OpKind::Memory);
        insn.set_memory_base(Register::RIP);
        insn.set_memory_displacement64(target);
        insn.set_memory_displ_size(4);
        if seg != Register::None {
            insn.set_segment_prefix(seg);
        }
        let mut encoder = Encoder::new(64);
        encoder.encode(&insn, ip).expect("encode rip fld");
        encoder.take_buffer()
    }

    #[test]
    fn stub_page_drops_write_before_the_call() {
        let mut state = X87::default();
        let mut regs = [0u64; 16];
        let mut flags = Flags::default();
        let mut af = false;
        let mut mem = crate::ir::MapMem::default();
        execute(
            &mut state,
            &mut regs,
            &mut flags,
            &mut af,
            false,
            &mut mem,
            &[0xd9, 0xe8],
            0x1000,
            None,
        )
        .expect("fld1");
        let (code, data) = host::page_perms().expect("perms");
        assert!(code.starts_with("r-x"), "{code}");
        assert!(!code.contains('w'), "{code}");
        assert!(data.starts_with("rw-"), "{data}");
        assert!(!data.contains('x'), "{data}");
    }

    #[test]
    fn gs_address_matches_the_cpu() {
        let gs = rdgsbase();
        let mut slot = Aligned::<16>([0u8; 16]);
        slot.0[..4].copy_from_slice(&1.0f32.to_le_bytes());
        let addr = slot.0.as_ptr() as u64;
        let rax = addr.wrapping_sub(gs);
        let bytes = fld_mem(Register::RAX, Register::None, 1, 0, Register::GS);
        let cpu_st = cpu_fld_gs(rax);
        let mut regs = [0u64; 16];
        regs[0] = rax;
        check_load(&bytes, regs, gs, addr);
        assert_eq!(cpu_st, ONE, "cpu gs load");
    }

    fn rdgsbase() -> u64 {
        let gs: u64;
        // SAFETY: `rdgsbase` only reads the GS base into a register.
        unsafe {
            std::arch::asm!("rdgsbase {gs}", gs = out(reg) gs, options(nomem, nostack));
        }
        gs
    }

    fn cpu_fld_gs(rax: u64) -> [u8; 10] {
        let mut before = Aligned::<512>([0u8; 512]);
        let mut after = Aligned::<512>([0u8; 512]);
        // SAFETY: both buffers are 16-byte aligned and 512 bytes long. The
        // sequence saves the host x87/SSE image, loads one GS-relative dword,
        // saves that image, and restores the host image.
        unsafe {
            std::arch::asm!(
                "fxsave64 [{before}]",
                "fld dword ptr gs:[{rax}]",
                "fxsave64 [{after}]",
                "fxrstor64 [{before}]",
                before = in(reg) before.0.as_mut_ptr(),
                after = in(reg) after.0.as_mut_ptr(),
                rax = in(reg) rax,
            );
        }
        let mut st = [0u8; 10];
        st.copy_from_slice(&after.0[32..42]);
        st
    }

    #[repr(C, align(16))]
    struct Aligned<const N: usize>([u8; N]);

    #[test]
    fn tag_word_is_indexed_by_physical_register() {
        let mut st = [[0u8; 10]; 8];
        st[1] = ONE;
        // TOP = 6, so ST(0) is physical 6 (zero) and ST(1) is physical 7 (one).
        let tw = tag_word(&st, 0x3000, 0xc0);
        assert_eq!(tw, 0x1fff);
        assert_eq!(compress_tags(tw), 0xc0);
        assert_eq!(tag_word(&st, 0x3800, 0), 0xffff);
    }
}
