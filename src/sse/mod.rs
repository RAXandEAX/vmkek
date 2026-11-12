//! User-mode SSE through AVX-512. The ZMM file, opmasks, and MXCSR live in the IR.
//!
//! Scalar and packed arithmetic run on the host SSE/AVX unit with the guest
//! MXCSR loaded, so rounding is not Rust `f32` or `f64` rounding. Results are
//! the raw bytes of each register: 16 for the XMM half, 16 for bits
//! [255:128], and 32 for bits [511:256]. Masked exceptions appear as sticky
//! MXCSR flags. An unmasked exception is a fault: the instruction does not retire.
//!
//! A legacy SSE write of an XMM register leaves bits [511:128] unchanged.
//! A VEX-encoded write of that XMM register zeroes bits [511:128]. A VEX write
//! of a YMM register replaces the low 256 bits and zeroes bits [511:256].
//! `VZEROUPPER` and `VZEROALL` follow the same hardware rule.
//!
//! MMX encodings of the same mnemonics alias the x87 registers. The host image
//! round-trips that stack together with the XMM half. L4 adds legacy SSE3
//! through FMA. L5 accepts VEX.128 and VEX.256 AVX/AVX2, including YMM
//! operands. The host YMM file is saved around every such opcode and the guest
//! YMM file is loaded before it and stored after it. L6 accepts EVEX and the
//! VEX opmask forms: ZMM0–ZMM31 and k0–k7 are loaded around the opcode and the
//! host copies are restored, including on a fault after the save. Merge-masking
//! (`{k}`) and zeroing-masking (`{k}{z}`) are the EVEX prefix on that opcode.
//! XOP stays out.

pub(crate) mod claim;
mod evex;
mod gather;
mod host;
mod mask;

use iced_x86::{
    Decoder, DecoderOptions, Encoder, EncodingKind, Instruction, InstructionInfoFactory, Mnemonic,
    OpAccess, OpKind, Register,
};

use crate::error::{msg, Result};
use crate::flags::Flags;
use crate::gp::{self, Cpu};
use crate::ir::{MemIo, Sse, X87};
use crate::isa::census::{self, Group, Status};

#[cfg(test)]
mod diff;
#[cfg(test)]
mod kat;

/// `true` when the mnemonic is in the L3 SSE/SSE2 group of the L0 census.
#[must_use]
pub fn is_sse(mnemonic: Mnemonic) -> bool {
    let row = census::entry(mnemonic);
    row.status == Status::Lift && row.group == Group::L3Sse
}

/// `true` when this encoding is replayed on the ZMM, YMM, or GPR file.
///
/// String `movsd` and `cmpsd` share a mnemonic with the scalar SSE2 forms and
/// stay on the integer path. XOP stays out. `RDRAND` and `FSGSBASE` are not
/// replayed: see [`claim`]. User EVEX and L6 opmask forms are replayed.
#[must_use]
pub fn accepts(insn: &Instruction) -> bool {
    if stays_with_integer(insn) || insn.code().is_privileged() {
        return false;
    }
    if avx512_encoding(insn) {
        return avx512_user(insn);
    }
    let encoding = insn.code().op_code().encoding();
    if is_sse(insn.mnemonic()) {
        return encoding == EncodingKind::Legacy;
    }
    if is_late_group(insn.mnemonic()) {
        return late_shape(insn) && !claim::blocked(insn.mnemonic());
    }
    is_avx_group(insn.mnemonic()) && avx_shape(insn)
}

/// `true` when the mnemonic is in the L6 AVX-512 group of the L0 census.
#[must_use]
pub fn is_avx512_group(mnemonic: Mnemonic) -> bool {
    let row = census::entry(mnemonic);
    row.status == Status::Lift && row.group == Group::L6Avx512
}

/// `true` when the mnemonic is in the L5 AVX/AVX2 group of the L0 census.
#[must_use]
pub fn is_avx_group(mnemonic: Mnemonic) -> bool {
    let row = census::entry(mnemonic);
    row.status == Status::Lift && row.group == Group::L5Avx
}

/// `true` when the mnemonic is in the L4 group of the L0 census.
#[must_use]
pub fn is_late_group(mnemonic: Mnemonic) -> bool {
    let row = census::entry(mnemonic);
    row.status == Status::Lift && row.group == Group::L4LateSse
}

fn late_shape(insn: &Instruction) -> bool {
    let encoding = insn.code().op_code().encoding();
    matches!(encoding, EncodingKind::Legacy | EncodingKind::VEX) && !insn_wide(insn)
}

fn avx_shape(insn: &Instruction) -> bool {
    insn.code().op_code().encoding() == EncodingKind::VEX && !foreign_vector(insn)
}

fn avx512_encoding(insn: &Instruction) -> bool {
    let encoding = insn.code().op_code().encoding();
    encoding == EncodingKind::EVEX
        || (is_avx512_group(insn.mnemonic()) && encoding == EncodingKind::VEX)
}

fn avx512_user(insn: &Instruction) -> bool {
    let code = insn.code();
    code.op_code().is_available_in_mode(64)
        && !crate::isa::encoding_outside_user_x64(code)
        && !mentions_tmm(insn)
}

fn insn_wide(insn: &Instruction) -> bool {
    let memory = (0..insn.op_count()).any(|index| insn.op_kind(index) == OpKind::Memory)
        && insn.memory_size().size() > 16;
    memory || vector_reg(insn)
}

fn foreign_vector(insn: &Instruction) -> bool {
    let high = (0..insn.op_count()).any(|index| {
        insn.op_kind(index) == OpKind::Register && high_vector(insn.op_register(index))
    });
    high || high_vector(insn.memory_index()) || insn.memory_size().size() > host::MEM_CAP
}

fn high_vector(reg: Register) -> bool {
    reg.is_zmm() || reg.is_k() || reg.is_tmm() || (reg.is_vector_register() && reg.number() >= 16)
}

fn mentions_tmm(insn: &Instruction) -> bool {
    let operand = (0..insn.op_count())
        .any(|index| insn.op_kind(index) == OpKind::Register && insn.op_register(index).is_tmm());
    operand || insn.memory_index().is_tmm()
}

fn vector_reg(insn: &Instruction) -> bool {
    (0..insn.op_count())
        .any(|index| insn.op_kind(index) == OpKind::Register && wide_reg(insn.op_register(index)))
}

fn wide_reg(reg: Register) -> bool {
    reg.is_ymm() || reg.is_zmm()
}

/// Bytes of `insn` as the lifter stores them.
pub(crate) fn original_bytes(insn: &Instruction) -> Result<Vec<u8>> {
    encode_insn(insn)
}

/// Host replay plan for `insn`. `ea` is the guest effective address, if any.
pub(crate) fn prepare(insn: &Instruction, original: &[u8], ea: Option<u64>) -> Result<Replay> {
    if !accepts(insn) {
        return Err(msg("not an sse instruction"));
    }
    if insn.len() == 0 || insn.len() > original.len() || insn.len() > 15 {
        return Err(msg("sse encoding does not fit"));
    }
    let encoded = &original[..insn.len()];
    let align = ea
        .map(|addr| (addr & align_mask(insn)) as usize)
        .unwrap_or(0);
    let data = data_gprs(insn);
    let (bytes, addr) = if explicit_memory(insn) {
        let mut banned = data;
        banned[4] = true;
        let addr = pick_addr(&banned).ok_or_else(|| msg("sse address register unavailable"))?;
        let bytes = machine_bytes(insn, gpr(addr))?;
        (bytes, Some(addr))
    } else if implicit_rdi(insn) {
        (strip_address_prefixes(encoded), Some(7))
    } else {
        (encoded.to_vec(), None)
    };
    let executed = decode(&bytes, 0)?;
    let mut anchor_ban = data_gprs(&executed);
    if let Some(addr) = addr {
        anchor_ban[addr] = true;
    }
    anchor_ban[4] = true;
    anchor_ban[12] = true;
    let anchor = pick_anchor(&anchor_ban).ok_or_else(|| msg("sse anchor register unavailable"))?;
    Ok(Replay {
        bytes,
        anchor,
        addr,
        load_rsp: reads_rsp(&executed),
        align,
        save_ymm: saves_ymm(&executed),
        save_zmm: saves_zmm(&executed),
        mem_at: mem_slot(&executed),
    })
}

/// Execute the first SSE/SSE2 instruction in `bytes`.
///
/// Bytes after that instruction are not fetched. Memory uses the emulator's
/// effective address, including a 32-bit address size and a GS override.
#[allow(
    clippy::too_many_arguments,
    reason = "XMM, x87, GPR, flags, and memory are updated through separate borrows"
)]
pub fn execute(
    sse: &mut Sse,
    x87: &mut X87,
    regs: &mut [u64; 16],
    flags: &mut Flags,
    af: &mut bool,
    df: bool,
    mem: &mut dyn MemIo,
    bytes: &[u8],
    ip: u64,
    gs: u64,
) -> Result<()> {
    let insn = decode(bytes, ip)?;
    checked(&insn)?;
    if insn.is_vsib() {
        return gather::execute(sse, x87, regs, flags, af, df, mem, &insn, bytes, gs);
    }
    let ea = addressed(regs, gs, &insn)?;
    let replay = prepare(&insn, bytes, ea)?;
    let executed = decode(&replay.bytes, 0)?;
    let mut buffer = operand_buffer(mem, &insn, ea)?;
    let before = *regs;
    host::run(
        sse,
        x87,
        regs,
        flags,
        af,
        df,
        &mut buffer,
        &replay,
        executed.rflags_modified() != 0,
    )?;
    keep_gpr(regs, &before, &executed);
    note_alias(sse, &executed);
    store_operand(mem, &insn, ea, &buffer)
}

fn addressed(regs: &[u64; 16], gs: u64, insn: &Instruction) -> Result<Option<u64>> {
    if touches_memory(insn) {
        Ok(Some(effective_address(regs, gs, insn)?))
    } else {
        Ok(None)
    }
}

fn operand_buffer(mem: &mut dyn MemIo, insn: &Instruction, ea: Option<u64>) -> Result<Vec<u8>> {
    let (size, must_map, _) = memory_effect(insn);
    if size > host::MEM_CAP {
        return Err(msg("sse memory operand is too large"));
    }
    let Some(addr) = ea else {
        if size > 0 {
            return Err(msg("sse memory operand has no address"));
        }
        return Ok(vec![0u8; size]);
    };
    if size == 0 {
        if must_map {
            mem.read(addr, 1)?;
        }
        return Ok(Vec::new());
    }
    if must_map {
        return mem.read(addr, size);
    }
    read_prefetch(mem, addr, size)
}

fn read_prefetch(mem: &mut dyn MemIo, addr: u64, size: usize) -> Result<Vec<u8>> {
    if !canonical_span(addr, size) {
        return Err(msg("general protection"));
    }
    match mem.read(addr, size) {
        Ok(bytes) => Ok(bytes),
        Err(err) if missing_page(&err) => Ok(vec![0u8; size]),
        Err(err) => Err(err),
    }
}

fn missing_page(err: &crate::error::Error) -> bool {
    match err {
        crate::error::Error::Msg(text) => text.contains("unmapped"),
        _ => false,
    }
}

/// 4-level long mode. Bits 63:48 must copy bit 47. A non-canonical prefetch is `#GP`.
fn canonical(addr: u64) -> bool {
    let shifted = addr >> 47;
    shifted == 0 || shifted == (u64::MAX >> 47)
}

fn canonical_span(addr: u64, size: usize) -> bool {
    let Some(last) = size.checked_sub(1).and_then(|n| addr.checked_add(n as u64)) else {
        return size == 0 && canonical(addr);
    };
    canonical(addr) && canonical(last)
}

pub(super) fn keep_gpr(regs: &mut [u64; 16], before: &[u64; 16], executed: &Instruction) {
    let written = written_gprs(executed);
    for (index, reg) in regs.iter_mut().enumerate() {
        if !written[index] {
            *reg = before[index];
        }
    }
}

fn store_operand(
    mem: &mut dyn MemIo,
    insn: &Instruction,
    ea: Option<u64>,
    buffer: &[u8],
) -> Result<()> {
    let (_, _, writes) = memory_effect(insn);
    if writes {
        if let Some(addr) = ea {
            mem.write(addr, buffer)?;
        }
    }
    Ok(())
}

/// Apply one decoded SSE/SSE2 instruction.
pub fn apply(
    sse: &mut Sse,
    x87: &mut X87,
    cpu: &mut Cpu,
    mem: &mut dyn MemIo,
    insn: &Instruction,
    original: &[u8],
) -> Result<()> {
    if !accepts(insn) {
        return Err(msg("not an sse instruction"));
    }
    execute(
        sse,
        x87,
        &mut cpu.regs,
        &mut cpu.flags,
        &mut cpu.af,
        cpu.df,
        mem,
        original,
        insn.ip(),
        cpu.gs,
    )
}

pub(super) struct Replay {
    bytes: Vec<u8>,
    anchor: usize,
    addr: Option<usize>,
    load_rsp: bool,
    align: usize,
    /// VEX opcodes that write an XMM register zero the host YMM upper bits.
    save_ymm: bool,
    /// EVEX and opmask opcodes replace the host ZMM and k file for one instruction.
    save_zmm: bool,
    /// Operand window on the data page. 64-byte accesses use [`ZMM_MEM`].
    mem_at: u32,
}

/// 64-byte aligned operand window. `MEM` is only 32-byte aligned.
pub(super) const ZMM_MEM: u32 = 0xE00;

fn align_mask(insn: &Instruction) -> u64 {
    let size = insn.memory_size().size();
    if size >= 64 {
        63
    } else if insn.is_vsib() || size >= 32 {
        31
    } else {
        15
    }
}

fn mem_slot(insn: &Instruction) -> u32 {
    if insn.memory_size().size() > 32 {
        ZMM_MEM
    } else {
        host::MEM
    }
}

fn saves_ymm(insn: &Instruction) -> bool {
    insn.code().op_code().encoding() == EncodingKind::VEX
        && (mentions_vector(insn)
            || matches!(insn.mnemonic(), Mnemonic::Vzeroall | Mnemonic::Vzeroupper))
}

fn saves_zmm(insn: &Instruction) -> bool {
    avx512_encoding(insn)
}

/// Pack the guest YMM file, low 16 bytes then bits [255:128], 32 bytes each.
pub(super) fn ymm_image(sse: &Sse) -> [u8; 512] {
    let mut out = [0u8; 512];
    for (index, (low, high)) in sse.xmm.iter().zip(sse.upper.iter()).enumerate() {
        let at = index * 32;
        out[at..at + 16].copy_from_slice(low);
        out[at + 16..at + 32].copy_from_slice(high);
    }
    out
}

/// Install a YMM image. The low half replaces [`Sse::xmm`].
pub(super) fn apply_ymm(sse: &mut Sse, raw: &[u8; 512]) {
    for (index, (low, high)) in sse.xmm.iter_mut().zip(sse.upper.iter_mut()).enumerate() {
        let at = index * 32;
        low.copy_from_slice(&raw[at..at + 16]);
        high.copy_from_slice(&raw[at + 16..at + 32]);
    }
}

/// Pack ZMM0–ZMM31. ZMM0–ZMM15 are XMM, then YMM upper, then bits [511:256].
pub(super) fn zmm_image(sse: &Sse) -> [u8; evex::ZMM_BYTES] {
    let mut out = [0u8; evex::ZMM_BYTES];
    for index in 0..16 {
        let at = index * evex::ZMM_WIDTH;
        out[at..at + 16].copy_from_slice(&sse.xmm[index]);
        out[at + 16..at + 32].copy_from_slice(&sse.upper[index]);
        out[at + 32..at + 64].copy_from_slice(&sse.zmm_hi256[index]);
    }
    for (index, lane) in sse.zmm_hi16.iter().enumerate() {
        let at = (index + 16) * evex::ZMM_WIDTH;
        out[at..at + 64].copy_from_slice(lane);
    }
    out
}

/// Install a ZMM image into the XMM, YMM-upper, and high halves.
pub(super) fn apply_zmm(sse: &mut Sse, raw: &[u8; evex::ZMM_BYTES]) {
    for index in 0..16 {
        let at = index * evex::ZMM_WIDTH;
        sse.xmm[index].copy_from_slice(&raw[at..at + 16]);
        sse.upper[index].copy_from_slice(&raw[at + 16..at + 32]);
        sse.zmm_hi256[index].copy_from_slice(&raw[at + 32..at + 64]);
    }
    for (index, lane) in sse.zmm_hi16.iter_mut().enumerate() {
        let at = (index + 16) * evex::ZMM_WIDTH;
        lane.copy_from_slice(&raw[at..at + 64]);
    }
}

/// Pack k0–k7.
pub(super) fn mask_image(sse: &Sse) -> [u8; evex::K_BYTES] {
    let mut out = [0u8; evex::K_BYTES];
    for (index, mask) in sse.opmask.iter().enumerate() {
        let at = index * 8;
        out[at..at + 8].copy_from_slice(&mask.to_le_bytes());
    }
    out
}

/// Install k0–k7. A `kmovw` image keeps only bits [15:0]; `kmovq` keeps all 64.
pub(super) fn apply_mask(sse: &mut Sse, raw: &[u8; evex::K_BYTES]) {
    copy_opmask(sse, raw, evex::mask_is_qword());
}

pub(super) fn copy_opmask(sse: &mut Sse, raw: &[u8; evex::K_BYTES], qword: bool) {
    for (index, mask) in sse.opmask.iter_mut().enumerate() {
        let at = index * 8;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&raw[at..at + 8]);
        let mut value = u64::from_le_bytes(buf);
        if !qword {
            value &= 0xFFFF;
        }
        *mask = value;
    }
}

pub(super) fn vector_bytes(sse: &Sse, reg: Register) -> [u8; 64] {
    let mut out = [0u8; 64];
    let slot = reg.number();
    if slot < 16 && reg.is_vector_register() {
        out[..16].copy_from_slice(&sse.xmm[slot]);
        out[16..32].copy_from_slice(&sse.upper[slot]);
        out[32..].copy_from_slice(&sse.zmm_hi256[slot]);
    } else if (16..32).contains(&slot) && reg.is_vector_register() {
        out.copy_from_slice(&sse.zmm_hi16[slot - 16]);
    }
    out
}

pub(super) fn write_vector(sse: &mut Sse, reg: Register, bytes: &[u8]) {
    let slot = reg.number();
    if slot < 16 && reg.is_vector_register() {
        copy_low_vector(sse, slot, bytes);
    } else if (16..32).contains(&slot) && reg.is_vector_register() {
        let width = bytes.len().min(64);
        sse.zmm_hi16[slot - 16][..width].copy_from_slice(&bytes[..width]);
    }
}

fn copy_low_vector(sse: &mut Sse, slot: usize, bytes: &[u8]) {
    let low = bytes.len().min(16);
    sse.xmm[slot][..low].copy_from_slice(&bytes[..low]);
    if bytes.len() > 16 {
        let high = (bytes.len() - 16).min(16);
        sse.upper[slot][..high].copy_from_slice(&bytes[16..16 + high]);
    }
    if bytes.len() > 32 {
        let hi = (bytes.len() - 32).min(32);
        sse.zmm_hi256[slot][..hi].copy_from_slice(&bytes[32..32 + hi]);
    }
}

/// Legacy SSE leaves bits [511:256] alone. A VEX write does not reload ZMM,
/// so zero the high 256 bits the CPU clears for that destination.
pub(super) fn note_alias(sse: &mut Sse, insn: &Instruction) {
    if saves_zmm(insn) {
        return;
    }
    if matches!(insn.mnemonic(), Mnemonic::Vzeroall | Mnemonic::Vzeroupper) {
        sse.zmm_hi256 = [[0; 32]; 16];
        return;
    }
    if insn.code().op_code().encoding() != EncodingKind::VEX {
        return;
    }
    zero_written_hi(sse, insn);
}

fn zero_written_hi(sse: &mut Sse, insn: &Instruction) {
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(insn);
    for used in info.used_registers() {
        if !writes_access(used.access()) {
            continue;
        }
        let reg = used.register();
        let slot = reg.number();
        if slot < 16 && (reg.is_xmm() || reg.is_ymm() || reg.is_zmm()) {
            sse.zmm_hi256[slot] = [0; 32];
        }
    }
}

fn mentions_vector(insn: &Instruction) -> bool {
    (0..insn.op_count()).any(|index| {
        if insn.op_kind(index) != OpKind::Register {
            return false;
        }
        let reg = insn.op_register(index);
        reg.is_xmm() || reg.is_ymm() || reg.is_zmm()
    })
}

/// Overlay `x87` and `sse` onto an FXSAVE image. MXCSR_MASK at bytes 28..32 is kept.
pub(crate) fn store_image(x87: &X87, sse: &Sse, image: &mut [u8; 512]) {
    crate::x87::export_image(x87, image);
    image[24..28].copy_from_slice(&sse.mxcsr.to_le_bytes());
    for (index, xmm) in sse.xmm.iter().enumerate() {
        let off = xmm_offset(index);
        image[off..off + 16].copy_from_slice(xmm);
    }
}

/// Read x87, XMM, and MXCSR back from an FXSAVE image.
pub(crate) fn load_image(x87: &mut X87, sse: &mut Sse, image: &[u8; 512]) {
    crate::x87::import_image(x87, image);
    sse.mxcsr = u32::from_le_bytes([image[24], image[25], image[26], image[27]]);
    for (index, xmm) in sse.xmm.iter_mut().enumerate() {
        let off = xmm_offset(index);
        xmm.copy_from_slice(&image[off..off + 16]);
    }
}

fn xmm_offset(index: usize) -> usize {
    if index < 8 {
        160 + index * 16
    } else {
        288 + (index - 8) * 16
    }
}

fn checked(insn: &Instruction) -> Result<()> {
    if !accepts(insn) {
        return Err(msg("not an sse instruction"));
    }
    if insn.has_lock_prefix() || insn.has_rep_prefix() || insn.has_repne_prefix() {
        return Err(gp::invalid());
    }
    Ok(())
}

fn stays_with_integer(insn: &Instruction) -> bool {
    matches!(
        insn.code(),
        iced_x86::Code::Movsd_m32_m32 | iced_x86::Code::Cmpsd_m32_m32
    )
}

fn effective_address(regs: &[u64; 16], gs: u64, insn: &Instruction) -> Result<u64> {
    let cpu = Cpu {
        regs: *regs,
        flags: Flags::default(),
        af: false,
        df: false,
        gs,
    };
    gp::address(&cpu, insn)
}

fn touches_memory(insn: &Instruction) -> bool {
    explicit_memory(insn) || implicit_rdi(insn)
}

fn explicit_memory(insn: &Instruction) -> bool {
    (0..insn.op_count()).any(|index| insn.op_kind(index) == OpKind::Memory)
}

fn implicit_rdi(insn: &Instruction) -> bool {
    (0..insn.op_count()).any(|index| {
        matches!(
            insn.op_kind(index),
            OpKind::MemorySegDI
                | OpKind::MemorySegEDI
                | OpKind::MemorySegRDI
                | OpKind::MemoryESDI
                | OpKind::MemoryESEDI
                | OpKind::MemoryESRDI
        )
    })
}

fn ignore_unmapped(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Prefetchnta
            | Mnemonic::Prefetcht0
            | Mnemonic::Prefetcht1
            | Mnemonic::Prefetcht2
            | Mnemonic::Prefetchw
            | Mnemonic::Prefetchwt1
            | Mnemonic::Prefetchit0
            | Mnemonic::Prefetchit1
    )
}

fn memory_effect(insn: &Instruction) -> (usize, bool, bool) {
    if !touches_memory(insn) {
        return (0, false, false);
    }
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(insn);
    let mut size = insn.memory_size().size();
    let mut writes = false;
    for mem in info.used_memory() {
        size = size.max(mem.memory_size().size());
        if writes_access(mem.access()) {
            writes = true;
        }
    }
    if implicit_rdi(insn) {
        let width = if insn.mnemonic() == Mnemonic::Maskmovq {
            8
        } else {
            16
        };
        size = size.max(width);
        writes = true;
    }
    // `clflush` reports no data access but still faults if the address is unmapped.
    // Software prefetches do not.
    let must_map = touches_memory(insn) && !ignore_unmapped(insn.mnemonic());
    (size, must_map, writes)
}

fn data_gprs(insn: &Instruction) -> [bool; 16] {
    let mut used = [false; 16];
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(insn);
    for reg in info.used_registers() {
        if let Some(slot) = gpr_slot(reg.register()) {
            used[slot] = true;
        }
    }
    if explicit_memory(insn) {
        for reg in [insn.memory_base(), insn.memory_index()] {
            if let Some(slot) = gpr_slot(reg) {
                if !reg_operand(insn, reg) {
                    used[slot] = false;
                }
            }
        }
    }
    mark_gpr_operands(&mut used, insn);
    used
}

fn mark_gpr_operands(used: &mut [bool; 16], insn: &Instruction) {
    for index in 0..insn.op_count() {
        if insn.op_kind(index) != OpKind::Register {
            continue;
        }
        if let Some(slot) = gpr_slot(insn.op_register(index)) {
            used[slot] = true;
        }
    }
}

fn written_gprs(insn: &Instruction) -> [bool; 16] {
    let mut written = [false; 16];
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(insn);
    for reg in info.used_registers() {
        if writes_access(reg.access()) {
            if let Some(slot) = gpr_slot(reg.register()) {
                written[slot] = true;
            }
        }
    }
    written
}

fn reads_rsp(insn: &Instruction) -> bool {
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(insn);
    info.used_registers()
        .iter()
        .any(|reg| reads_access(reg.access()) && gpr_slot(reg.register()) == Some(4))
}

fn reg_operand(insn: &Instruction, reg: Register) -> bool {
    let full = reg.full_register();
    (0..insn.op_count()).any(|index| {
        insn.op_kind(index) == OpKind::Register
            && insn.op_register(index).is_gpr()
            && insn.op_register(index).full_register() == full
    })
}

fn gpr_slot(reg: Register) -> Option<usize> {
    if !reg.is_gpr() {
        return None;
    }
    let slot = reg.full_register().number();
    if slot < 16 {
        Some(slot)
    } else {
        None
    }
}

fn gpr(index: usize) -> Register {
    const REGS: [Register; 16] = [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RBX,
        Register::RSP,
        Register::RBP,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ];
    REGS[index]
}

fn pick_addr(banned: &[bool; 16]) -> Option<usize> {
    // Avoid registers whose bare `[reg]` encoding needs a displacement or SIB.
    const ORDER: [usize; 12] = [11, 10, 9, 8, 14, 15, 3, 1, 2, 6, 7, 0];
    ORDER.into_iter().find(|index| !banned[*index])
}

fn pick_anchor(banned: &[bool; 16]) -> Option<usize> {
    // RSP and R12 need a SIB byte when used as a base.
    const ORDER: [usize; 14] = [11, 10, 9, 8, 14, 15, 3, 1, 2, 6, 7, 0, 5, 13];
    ORDER.into_iter().find(|index| !banned[*index])
}

fn reads_access(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn writes_access(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn machine_bytes(insn: &Instruction, base: Register) -> Result<Vec<u8>> {
    let mut copy = *insn;
    copy.set_memory_base(base);
    if !insn.is_vsib() {
        copy.set_memory_index(Register::None);
    }
    copy.set_memory_index_scale(1);
    copy.set_memory_displacement64(0);
    copy.set_memory_displ_size(0);
    copy.set_segment_prefix(Register::None);
    encode_insn(&copy)
}

fn encode_insn(insn: &Instruction) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(64);
    encoder
        .encode(insn, insn.ip())
        .map_err(|_| msg("sse encoding failed"))?;
    let buf = encoder.take_buffer();
    if buf.is_empty() || buf.len() > 15 {
        return Err(msg("sse encoding does not fit"));
    }
    Ok(buf)
}

pub(super) fn decode(bytes: &[u8], ip: u64) -> Result<Instruction> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let insn = decoder.decode();
    if insn.is_invalid() || insn.len() == 0 || insn.len() > bytes.len() {
        return Err(msg("invalid sse encoding"));
    }
    Ok(insn)
}

fn strip_address_prefixes(bytes: &[u8]) -> Vec<u8> {
    let mut kept = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let prefix = matches!(
            byte,
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67
        ) || (0x40..0x50).contains(&byte);
        if !prefix {
            break;
        }
        let drop = matches!(byte, 0x67 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65);
        if !drop {
            kept.push(byte);
        }
        index += 1;
    }
    kept.extend_from_slice(&bytes[index..]);
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directed_rounding_changes_the_divss_bits() {
        let mut sse = Sse {
            mxcsr: 0x3f80,
            ..Sse::default()
        };
        sse.xmm[0][0..4].copy_from_slice(&1.0f32.to_le_bytes());
        sse.xmm[1][0..4].copy_from_slice(&3.0f32.to_le_bytes());
        let mut image = host::capture_template();
        store_image(&X87::default(), &sse, &mut image);
        let stored = u32::from_le_bytes(image[24..28].try_into().unwrap());
        assert_eq!(stored, 0x3f80, "image {:02x?}", &image[24..32]);
        let mut x87 = X87::default();
        let mut regs = [0u64; 16];
        let mut flags = Flags::default();
        let mut af = false;
        let mut mem = crate::ir::MapMem::default();
        execute(
            &mut sse,
            &mut x87,
            &mut regs,
            &mut flags,
            &mut af,
            false,
            &mut mem,
            &[0xF3, 0x0F, 0x5E, 0xC1],
            0x1000,
            0,
        )
        .expect("divss");
        assert_eq!(sse.mxcsr & 0x6000, 0x2000, "mxcsr {:#x}", sse.mxcsr);
        assert_eq!(
            &sse.xmm[0][0..4],
            &[0xAA, 0xAA, 0xAA, 0x3E],
            "mxcsr {:#x} bits {:02x?}",
            sse.mxcsr,
            &sse.xmm[0][..4]
        );
    }

    #[test]
    fn xmm_file_is_sixteen_raw_registers() {
        let state = Sse::default();
        assert_eq!(state.xmm.len(), 16);
        assert!(state.xmm.iter().all(|reg| reg.len() == 16));
        assert!(state.xmm.iter().all(|reg| *reg == [0; 16]));
        assert_eq!(state.mxcsr, 0x1f80);
    }

    #[test]
    fn trailing_opcode_after_sse_is_not_executed() {
        let mut sse = Sse::default();
        sse.xmm[0][0..4].copy_from_slice(&1.0f32.to_le_bytes());
        sse.xmm[1][0..4].copy_from_slice(&2.0f32.to_le_bytes());
        let mut regs = [0u64; 16];
        let mut flags = Flags::default();
        let mut af = false;
        let mut x87 = X87::default();
        let mut mem = crate::ir::MapMem::default();
        // addss xmm0, xmm1; add eax, 1. The add must not run inside the stub.
        let bytes = [0xF3, 0x0F, 0x58, 0xC1, 0x83, 0xC0, 0x01];
        execute(
            &mut sse, &mut x87, &mut regs, &mut flags, &mut af, false, &mut mem, &bytes, 0x1000, 0,
        )
        .expect("addss");
        assert_eq!(regs[0], 0, "bytes after the sse instruction must not run");
        assert_eq!(&sse.xmm[0][0..4], &3.0f32.to_le_bytes());
        assert_eq!(&sse.xmm[0][4..], &[0; 12]);
    }

    #[test]
    fn word_mask_image_keeps_sixteen_bits() {
        let mut raw = [0u8; evex::K_BYTES];
        raw[..8].copy_from_slice(&0xFFFF_FFFF_FFFF_A5A5u64.to_le_bytes());
        let mut sse = Sse::default();
        copy_opmask(&mut sse, &raw, false);
        assert_eq!(sse.opmask[0], 0xA5A5);
        copy_opmask(&mut sse, &raw, true);
        assert_eq!(sse.opmask[0], 0xFFFF_FFFF_FFFF_A5A5);
    }

    #[test]
    fn integer_view_rejects_sse_and_keeps_string_movsd() {
        let err = crate::lift::lift("addps", &[0x0F, 0x58, 0xC1], 0x42, 3, 0).unwrap_err();
        match err {
            crate::error::Error::Unsupported { rva, text } => {
                assert_eq!(rva, 0x42);
                assert!(text.contains("sse"), "{text}");
            }
            other => panic!("expected Unsupported, got {other}"),
        }
        let program = crate::lift::program("movsd", &[0xA5], 0x1000, 1, 0).expect("string movsd");
        assert!(program.blocks.iter().all(|block| {
            block
                .ops
                .iter()
                .all(|step| !matches!(step, crate::ir::Step::Sse(_)))
        }));
        crate::lift::lift("movsd", &[0xA5], 0x1000, 1, 0).expect("string movsd stays integer");
    }

    #[test]
    fn stub_page_drops_write_before_the_call() {
        let mut sse = Sse::default();
        let mut x87 = X87::default();
        let mut regs = [0u64; 16];
        let mut flags = Flags::default();
        let mut af = false;
        let mut mem = crate::ir::MapMem::default();
        execute(
            &mut sse,
            &mut x87,
            &mut regs,
            &mut flags,
            &mut af,
            false,
            &mut mem,
            &[0x0F, 0x57, 0xC0],
            0x1000,
            0,
        )
        .expect("xorps");
        let (code, data) = host::page_perms().expect("perms");
        assert!(code.starts_with("r-x"), "{code}");
        assert!(!code.contains('w'), "{code}");
        assert!(data.starts_with("rw-"), "{data}");
        assert!(!data.contains('x'), "{data}");
    }

    struct MissingMem;

    impl MemIo for MissingMem {
        fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
            Err(msg(format!("unmapped read {addr:#x}+{len}")))
        }

        fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            Err(msg(format!("unmapped write {addr:#x}+{}", data.len())))
        }
    }

    fn run_at(bytes: &[u8], addr: u64, mem: &mut dyn MemIo) -> (Result<()>, Sse) {
        let mut sse = Sse::default();
        let mut x87 = X87::default();
        let mut regs = [0u64; 16];
        regs[0] = addr;
        let mut flags = Flags::default();
        let mut af = false;
        let result = execute(
            &mut sse, &mut x87, &mut regs, &mut flags, &mut af, false, mem, bytes, 0x1000, 0,
        );
        assert_eq!(regs[0], addr);
        (result, sse)
    }

    #[test]
    fn prefetch_miss_leaves_state_and_clflush_still_faults() {
        let before = Sse::default();
        let mut mem = MissingMem;
        let (prefetch, sse) = run_at(&[0x0F, 0x18, 0x08], 0x5000, &mut mem);
        prefetch.expect("prefetch of an unmapped canonical page");
        assert_eq!(sse, before);
        let (flush, sse) = run_at(&[0x0F, 0xAE, 0x38], 0x5000, &mut mem);
        let err = flush.expect_err("clflush of an unmapped page");
        assert!(err.to_string().contains("unmapped"), "{err}");
        assert_eq!(sse, before);
    }

    #[test]
    fn prefetch_noncanonical_is_general_protection() {
        let before = Sse::default();
        let mut mem = crate::ir::MapMem::default();
        let (result, sse) = run_at(&[0x0F, 0x18, 0x08], 1 << 63, &mut mem);
        let err = result.expect_err("non-canonical prefetch");
        assert!(err.to_string().contains("general protection"), "{err}");
        assert_eq!(sse, before);
    }
}
