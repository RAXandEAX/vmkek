//! Gather and scatter. Each enabled VSIB element is copied through the stub
//! buffer and the index is retargeted at those slots. Hardware leaves the
//! index unchanged, so the original index is written back afterwards. An EVEX
//! opmask uses the bit for that element; a VEX mask uses the top bit of the
//! lane. Scatter writes the stub buffer back to the original addresses.

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpKind, Register};

use crate::error::{msg, Result};
use crate::flags::Flags;
use crate::ir::{MemIo, Sse, X87};

#[derive(Clone, Copy)]
struct Shape {
    elems: usize,
    data: usize,
    index: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Gather,
    Scatter,
    Prefetch,
}

#[allow(
    clippy::too_many_arguments,
    reason = "gather threads the vector file, GPRs, flags, and the element buffer"
)]
pub(super) fn execute(
    sse: &mut Sse,
    x87: &mut X87,
    regs: &mut [u64; 16],
    flags: &mut Flags,
    af: &mut bool,
    df: bool,
    mem: &mut dyn MemIo,
    insn: &Instruction,
    bytes: &[u8],
    gs: u64,
) -> Result<()> {
    let shape = shape(insn).ok_or_else(|| msg("not a gather"))?;
    let index = insn.memory_index();
    let original = super::vector_bytes(sse, index);
    let enabled = enabled_lanes(sse, insn, shape);
    let addrs = addresses(insn, regs, gs, sse, shape, &enabled)?;
    let mut buffer = vec![0u8; shape.elems * shape.data];
    let kind = kind(insn);
    if kind == Kind::Gather {
        read_lanes(mem, &addrs, &enabled, shape, &mut buffer)?;
    }
    let mut local = *sse;
    plant(&mut local, index, shape);
    let replay = super::prepare(insn, bytes, None)?;
    run_vsib(
        &mut local,
        x87,
        regs,
        flags,
        af,
        df,
        &mut buffer,
        &replay,
        index,
        &original,
    )?;
    if kind == Kind::Scatter {
        write_lanes(mem, &addrs, &enabled, shape, &buffer)?;
    }
    super::note_alias(&mut local, insn);
    *sse = local;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the gathered opcode is replayed with the same separated borrows as SSE"
)]
fn run_vsib(
    sse: &mut Sse,
    x87: &mut X87,
    regs: &mut [u64; 16],
    flags: &mut Flags,
    af: &mut bool,
    df: bool,
    buffer: &mut [u8],
    replay: &super::Replay,
    index: Register,
    original: &[u8; 64],
) -> Result<()> {
    let executed = super::decode(&replay.bytes, 0)?;
    let before = *regs;
    super::host::run(
        sse,
        x87,
        regs,
        flags,
        af,
        df,
        buffer,
        replay,
        executed.rflags_modified() != 0,
    )?;
    super::keep_gpr(regs, &before, &executed);
    let width = index.size().min(original.len());
    super::write_vector(sse, index, &original[..width]);
    Ok(())
}

fn kind(insn: &Instruction) -> Kind {
    if prefetch(insn.mnemonic()) {
        return Kind::Prefetch;
    }
    if writes_memory(insn) {
        Kind::Scatter
    } else {
        Kind::Gather
    }
}

fn writes_memory(insn: &Instruction) -> bool {
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(insn);
    info.used_memory().iter().any(|item| {
        matches!(
            item.access(),
            iced_x86::OpAccess::Write
                | iced_x86::OpAccess::CondWrite
                | iced_x86::OpAccess::ReadWrite
                | iced_x86::OpAccess::ReadCondWrite
        )
    })
}

fn prefetch(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Vgatherpf0dpd
            | Mnemonic::Vgatherpf0dps
            | Mnemonic::Vgatherpf0qpd
            | Mnemonic::Vgatherpf0qps
            | Mnemonic::Vgatherpf1dpd
            | Mnemonic::Vgatherpf1dps
            | Mnemonic::Vgatherpf1qpd
            | Mnemonic::Vgatherpf1qps
            | Mnemonic::Vgatherpf0hintdpd
            | Mnemonic::Vgatherpf0hintdps
            | Mnemonic::Vscatterpf0dpd
            | Mnemonic::Vscatterpf0dps
            | Mnemonic::Vscatterpf0qpd
            | Mnemonic::Vscatterpf0qps
            | Mnemonic::Vscatterpf1dpd
            | Mnemonic::Vscatterpf1dps
            | Mnemonic::Vscatterpf1qpd
            | Mnemonic::Vscatterpf1qps
            | Mnemonic::Vscatterpf0hintdpd
            | Mnemonic::Vscatterpf0hintdps
    )
}

fn shape(insn: &Instruction) -> Option<Shape> {
    if !insn.is_vsib() {
        return None;
    }
    let index = if insn.is_vsib64() { 8 } else { 4 };
    let info = insn.memory_size().info();
    let data = info.element_size();
    if data == 0 || data > 8 {
        return None;
    }
    let elems = elem_count(insn, data, index);
    if elems == 0 || elems > 16 || elems * data > super::host::MEM_CAP {
        return None;
    }
    Some(Shape { elems, data, index })
}

fn elem_count(insn: &Instruction, data: usize, index_width: usize) -> usize {
    let index_slots = insn.memory_index().size() / index_width.max(1);
    let vector = vector_len(insn);
    let data_slots = if data > 0 && vector >= data && vector.is_multiple_of(data) {
        vector / data
    } else {
        index_slots
    };
    index_slots.min(data_slots)
}

fn vector_len(insn: &Instruction) -> usize {
    (0..insn.op_count())
        .filter(|index| insn.op_kind(*index) == OpKind::Register)
        .map(|index| insn.op_register(index))
        .find(|reg| reg.is_vector_register())
        .map_or(0, Register::size)
}

fn enabled_lanes(sse: &Sse, insn: &Instruction, shape: Shape) -> Vec<bool> {
    (0..shape.elems)
        .map(|elem| lane_on(sse, insn, elem, shape.data))
        .collect()
}

fn lane_on(sse: &Sse, insn: &Instruction, elem: usize, width: usize) -> bool {
    let mask = insn.op_mask();
    if mask.is_k() {
        let bits = sse.opmask.get(mask.number()).copied().unwrap_or(0);
        return (bits >> elem) & 1 == 1;
    }
    if insn.op_count() > 2 && insn.op_kind(2) == OpKind::Register {
        return high_bit(sse, insn.op_register(2), elem, width);
    }
    true
}

fn high_bit(sse: &Sse, mask: Register, elem: usize, width: usize) -> bool {
    let raw = super::vector_bytes(sse, mask);
    let at = elem * width + width - 1;
    raw.get(at).is_some_and(|byte| byte & 0x80 != 0)
}

fn plant(sse: &mut Sse, index: Register, shape: Shape) {
    let mut raw = vec![0u8; shape.elems * shape.index];
    for elem in 0..shape.elems {
        let at = elem * shape.index;
        let value = u64::try_from(elem * shape.data).unwrap_or(0);
        raw[at..at + shape.index].copy_from_slice(&value.to_le_bytes()[..shape.index]);
    }
    super::write_vector(sse, index, &raw);
}

fn addresses(
    insn: &Instruction,
    regs: &[u64; 16],
    gs: u64,
    sse: &Sse,
    shape: Shape,
    enabled: &[bool],
) -> Result<Vec<u64>> {
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(insn);
    let used = info
        .used_memory()
        .iter()
        .find(|item| item.vsib_size() != 0)
        .ok_or_else(|| msg("gather has no vsib"))?;
    let mut out = Vec::with_capacity(shape.elems);
    for (elem, on) in enabled.iter().enumerate() {
        let addr = if *on {
            used.virtual_address(elem, |reg, index, size| {
                lane(reg, index, size, regs, sse, gs)
            })
            .ok_or_else(|| msg("gather address"))?
        } else {
            0
        };
        out.push(addr);
    }
    Ok(out)
}

fn read_lanes(
    mem: &mut dyn MemIo,
    addrs: &[u64],
    enabled: &[bool],
    shape: Shape,
    data: &mut [u8],
) -> Result<()> {
    for elem in 0..shape.elems {
        if enabled[elem] {
            copy_in(mem, addrs[elem], elem, shape.data, data)?;
        }
    }
    Ok(())
}

fn copy_in(
    mem: &mut dyn MemIo,
    addr: u64,
    elem: usize,
    width: usize,
    data: &mut [u8],
) -> Result<()> {
    let got = mem.read(addr, width)?;
    let at = elem * width;
    data[at..at + width].copy_from_slice(&got);
    Ok(())
}

fn write_lanes(
    mem: &mut dyn MemIo,
    addrs: &[u64],
    enabled: &[bool],
    shape: Shape,
    data: &[u8],
) -> Result<()> {
    for elem in 0..shape.elems {
        if enabled[elem] {
            let at = elem * shape.data;
            mem.write(addrs[elem], &data[at..at + shape.data])?;
        }
    }
    Ok(())
}

fn lane(
    reg: Register,
    elem: usize,
    size: usize,
    regs: &[u64; 16],
    sse: &Sse,
    gs: u64,
) -> Option<u64> {
    if reg.is_gpr() {
        let slot = reg.full_register().number();
        return (slot < 16).then_some(regs[slot]);
    }
    if reg.is_vector_register() {
        return vector_lane(sse, reg, elem, size);
    }
    if reg == Register::GS {
        return Some(gs);
    }
    Some(0)
}

fn vector_lane(sse: &Sse, reg: Register, elem: usize, size: usize) -> Option<u64> {
    if size > 8 {
        return None;
    }
    let raw = super::vector_bytes(sse, reg);
    let at = elem.checked_mul(size)?;
    let end = at.checked_add(size)?;
    let slot = raw.get(at..end)?;
    let mut buf = [0u8; 8];
    buf[..size].copy_from_slice(slot);
    Some(u64::from_le_bytes(buf))
}
