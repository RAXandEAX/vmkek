use std::collections::{HashMap, HashSet};

use crate::error::{msg, Result};

use super::dynamic;
use super::header::{self, va_file};
use super::read::{self, at};
use super::{
    DynamicEntry, DynamicTag, ElfBytes, Got, GotSlot, PltEntry, RelocKind, Relocation, Section,
    Segment, SegmentKind,
};

const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

struct Decoded {
    got: Option<u64>,
    push: Option<u32>,
    resolver: bool,
}

struct RelocIndex<'a> {
    first: HashMap<u64, usize>,
    slot: HashMap<u64, usize>,
    jumps: Vec<usize>,
    relocations: &'a [Relocation],
}

impl<'a> RelocIndex<'a> {
    fn build(relocations: &'a [Relocation]) -> Self {
        let mut first = HashMap::with_capacity(relocations.len());
        let mut slot = HashMap::new();
        let mut jumps = Vec::new();
        for (index, reloc) in relocations.iter().enumerate() {
            first.entry(reloc.offset).or_insert(index);
            if matches!(reloc.kind, RelocKind::JumpSlot | RelocKind::GlobDat) {
                slot.entry(reloc.offset).or_insert(index);
            }
            if reloc.kind == RelocKind::JumpSlot {
                jumps.push(index);
            }
        }
        Self {
            first,
            slot,
            jumps,
            relocations,
        }
    }

    fn at(&self, addr: u64) -> Option<&Relocation> {
        self.first.get(&addr).map(|&index| &self.relocations[index])
    }

    fn jump_or_glob(&self, addr: u64) -> Option<&Relocation> {
        self.slot.get(&addr).map(|&index| &self.relocations[index])
    }

    fn jump(&self, nth: u32) -> Option<&Relocation> {
        self.jumps
            .get(nth as usize)
            .map(|&index| &self.relocations[index])
    }
}

pub(super) fn got(
    data: &[u8],
    segments: &[Segment],
    sections: &[Section],
    dynamic: &[DynamicEntry],
    relocations: &[Relocation],
) -> Result<Got> {
    let index = RelocIndex::build(relocations);
    let plt_addr = plt_got_addr(sections, dynamic)?;
    let mut plt_slots = plt_slots(data, segments, sections, plt_addr, relocations)?;
    let (mut addr, mut slots) = plain_got(data, segments, sections)?;
    if slots.is_empty() {
        slots = slots_from_relocs(data, segments, relocations, plt_addr, &plt_slots)?;
        if addr == 0 {
            if let Some(slot) = slots.first() {
                addr = slot.addr;
            }
        }
    }
    annotate(&mut slots, &index);
    annotate(&mut plt_slots, &index);
    Ok(Got {
        addr,
        slots,
        plt_addr: plt_addr.unwrap_or(0),
        plt_slots,
    })
}

pub(super) fn entries(
    data: &[u8],
    segments: &[Segment],
    sections: &[Section],
    dynamic: &[DynamicEntry],
    relocations: &[Relocation],
) -> Result<Vec<PltEntry>> {
    let index = RelocIndex::build(relocations);
    let mut out = Vec::new();
    let mut named = false;
    for section in sections {
        if !is_plt(&section.name) {
            continue;
        }
        named = true;
        decode_section(data, section, &index, &mut out)?;
    }
    if !named
        && relocations
            .iter()
            .any(|reloc| reloc.kind == RelocKind::JumpSlot)
    {
        let pltgot = dynamic::pointer(dynamic, DynamicTag::PltGot).unwrap_or(0);
        scan_loads(data, segments, &index, pltgot, &mut out)?;
    }
    Ok(out)
}

fn plt_got_addr(sections: &[Section], dynamic: &[DynamicEntry]) -> Result<Option<u64>> {
    let section = sections.iter().find(|section| section.name == ".got.plt");
    let tagged = dynamic::tag(dynamic, DynamicTag::PltGot);
    if let (Some(section), Some(addr)) = (section, tagged) {
        if section.addr != addr {
            return Err(msg("DT_PLTGOT does not match .got.plt"));
        }
    }
    if let Some(section) = section {
        return Ok(Some(section.addr));
    }
    Ok(dynamic::pointer(dynamic, DynamicTag::PltGot))
}

fn plain_got(
    data: &[u8],
    segments: &[Segment],
    sections: &[Section],
) -> Result<(u64, Vec<GotSlot>)> {
    let Some(section) = sections.iter().find(|section| section.name == ".got") else {
        return Ok((0, Vec::new()));
    };
    let slots = read_slots(data, segments, section.addr, section.offset, section.size)?;
    Ok((section.addr, slots))
}

fn plt_slots(
    data: &[u8],
    segments: &[Segment],
    sections: &[Section],
    addr: Option<u64>,
    relocations: &[Relocation],
) -> Result<Vec<GotSlot>> {
    if let Some(section) = sections.iter().find(|section| section.name == ".got.plt") {
        return read_slots(data, segments, section.addr, section.offset, section.size);
    }
    let Some(addr) = addr else {
        return Ok(Vec::new());
    };
    let jumps = relocations
        .iter()
        .filter(|reloc| reloc.kind == RelocKind::JumpSlot)
        .count();
    let bytes = 24usize
        .checked_add(
            jumps
                .checked_mul(8)
                .ok_or_else(|| msg("too many PLT relocations"))?,
        )
        .ok_or_else(|| msg("too many PLT relocations"))?;
    let off = va_file(segments, addr, bytes as u64)?;
    read_slots(data, segments, addr, off, bytes as u64)
}

fn slots_from_relocs(
    data: &[u8],
    segments: &[Segment],
    relocations: &[Relocation],
    plt_addr: Option<u64>,
    plt_slots: &[GotSlot],
) -> Result<Vec<GotSlot>> {
    let plt_end = plt_addr
        .map(|addr| span_end(addr, plt_slots.len()))
        .transpose()?;
    let mut seen = HashSet::new();
    let mut slots = Vec::new();
    let loads = has_load(segments);
    for reloc in relocations {
        if reloc.kind != RelocKind::GlobDat || !seen.insert(reloc.offset) {
            continue;
        }
        if let (Some(start), Some(end)) = (plt_addr, plt_end) {
            if reloc.offset >= start && reloc.offset < end {
                continue;
            }
        }
        slots.push(GotSlot {
            addr: reloc.offset,
            value: got_place(data, segments, reloc.offset, loads)?,
            symbol: None,
            reloc: None,
        });
    }
    slots.sort_by_key(|slot| slot.addr);
    Ok(slots)
}

fn read_slots(
    data: &[u8],
    segments: &[Segment],
    addr: u64,
    offset: u64,
    size: u64,
) -> Result<Vec<GotSlot>> {
    if !size.is_multiple_of(8) {
        return Err(msg("GOT size is not a multiple of 8"));
    }
    let count = usize::try_from(size / 8).map_err(|_| msg("GOT is too large"))?;
    if count > super::MAX_RELOCS {
        return Err(msg("GOT is too large"));
    }
    if count > 0 {
        let _ = scaled(addr, count - 1, 8, "GOT address")?;
        let _ = scaled(offset, count - 1, 8, "GOT offset")?;
    }
    let loads = has_load(segments);
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        out.push(one_slot(data, segments, addr, offset, index, loads)?);
    }
    Ok(out)
}

fn one_slot(
    data: &[u8],
    segments: &[Segment],
    addr: u64,
    offset: u64,
    index: usize,
    loads: bool,
) -> Result<GotSlot> {
    let slot_addr = scaled(addr, index, 8, "GOT address")?;
    let file_off = scaled(offset, index, 8, "GOT offset")?;
    let value = if loads {
        match header::place(data, segments, slot_addr, 8)? {
            Some(_) => read::le_u64(at(data, file_off, 8, "GOT slot")?),
            None => 0,
        }
    } else {
        read::le_u64(at(data, file_off, 8, "GOT slot")?)
    };
    Ok(GotSlot {
        addr: slot_addr,
        value,
        symbol: None,
        reloc: None,
    })
}

fn got_place(data: &[u8], segments: &[Segment], addr: u64, loads: bool) -> Result<u64> {
    if !loads {
        return Ok(0);
    }
    match header::place(data, segments, addr, 8)? {
        Some(bytes) => Ok(read::le_u64(bytes)),
        None => Ok(0),
    }
}

fn annotate(slots: &mut [GotSlot], index: &RelocIndex<'_>) {
    for slot in slots {
        let Some(reloc) = index.at(slot.addr) else {
            continue;
        };
        slot.reloc = Some(reloc.kind);
        if !reloc.symbol.is_empty() {
            slot.symbol = Some(reloc.symbol.clone());
        }
    }
}

fn is_plt(name: &ElfBytes) -> bool {
    name == ".plt" || name == ".iplt" || name.starts_with(".plt.")
}

fn decode_section(
    data: &[u8],
    section: &Section,
    index: &RelocIndex<'_>,
    out: &mut Vec<PltEntry>,
) -> Result<()> {
    if section.size == 0 {
        return Ok(());
    }
    let entsize = plt_entsize(section)?;
    let count = usize::try_from(section.size / entsize).map_err(|_| msg("too many PLT entries"))?;
    if count > super::MAX_RELOCS || out.len().saturating_add(count) > super::MAX_RELOCS {
        return Err(msg("too many PLT entries"));
    }
    if count > 0 {
        let _ = scaled(section.addr, count - 1, entsize, "PLT address")?;
        let _ = scaled(section.offset, count - 1, entsize, "PLT offset")?;
    }
    for nth in 0..count {
        let addr = scaled(section.addr, nth, entsize, "PLT address")?;
        let off = scaled(section.offset, nth, entsize, "PLT offset")?;
        let bytes = at(data, off, entsize as usize, "PLT entry")?;
        out.push(finish(addr, entsize, &section.name, bytes, index));
    }
    Ok(())
}

fn plt_entsize(section: &Section) -> Result<u64> {
    if section.entsize == 16 || section.entsize == 8 {
        return Ok(section.entsize);
    }
    if section.entsize == 0 && section.size.is_multiple_of(16) {
        return Ok(16);
    }
    if section.entsize == 0 && section.size.is_multiple_of(8) {
        return Ok(8);
    }
    Err(msg(format!(
        "plt section {} entry size is unknown",
        section.name
    )))
}

fn scan_loads(
    data: &[u8],
    segments: &[Segment],
    index: &RelocIndex<'_>,
    pltgot: u64,
    out: &mut Vec<PltEntry>,
) -> Result<()> {
    for segment in segments {
        if segment.kind != SegmentKind::Load || segment.flags & 1 == 0 || segment.filesz < 16 {
            continue;
        }
        let bytes = at(
            data,
            segment.offset,
            segment.filesz as usize,
            "load segment",
        )?;
        scan_segment(segment, bytes, index, pltgot, out)?;
    }
    Ok(())
}

fn scan_segment(
    segment: &Segment,
    bytes: &[u8],
    index: &RelocIndex<'_>,
    pltgot: u64,
    out: &mut Vec<PltEntry>,
) -> Result<()> {
    let mut off = 0usize;
    while off + 16 <= bytes.len() {
        let window = &bytes[off..off + 16];
        let addr = segment
            .vaddr
            .checked_add(off as u64)
            .ok_or_else(|| msg("PLT address overflows"))?;
        if let Some(decoded) = decode(window, addr) {
            if relevant(&decoded, index, pltgot) {
                push_plt(
                    out,
                    finish(addr, 16, &ElfBytes::from("load"), window, index),
                )?;
                off += 16;
                continue;
            }
        }
        off += 16;
    }
    Ok(())
}

fn push_plt(out: &mut Vec<PltEntry>, entry: PltEntry) -> Result<()> {
    if out.len() >= super::MAX_RELOCS {
        return Err(msg("too many PLT entries"));
    }
    out.push(entry);
    Ok(())
}

fn finish(
    addr: u64,
    size: u64,
    section: &ElfBytes,
    bytes: &[u8],
    index: &RelocIndex<'_>,
) -> PltEntry {
    let decoded = decode(bytes, addr).unwrap_or(Decoded {
        got: None,
        push: None,
        resolver: false,
    });
    let (symbol, symbol_index, resolver) = plt_symbol(&decoded, index);
    PltEntry {
        addr,
        size,
        section: section.clone(),
        got: decoded.got,
        symbol,
        symbol_index,
        resolver,
        bytes: bytes.to_vec(),
    }
}

fn plt_symbol(decoded: &Decoded, index: &RelocIndex<'_>) -> (Option<ElfBytes>, Option<u32>, bool) {
    if let Some(got) = decoded.got {
        if let Some(reloc) = index.jump_or_glob(got) {
            return (named(reloc), Some(reloc.symbol_index), false);
        }
    }
    if let Some(push) = decoded.push {
        if let Some(reloc) = index.jump(push) {
            return (named(reloc), Some(reloc.symbol_index), decoded.resolver);
        }
    }
    (None, None, decoded.resolver)
}

fn named(reloc: &Relocation) -> Option<ElfBytes> {
    if reloc.symbol.is_empty() {
        None
    } else {
        Some(reloc.symbol.clone())
    }
}

fn relevant(decoded: &Decoded, index: &RelocIndex<'_>, pltgot: u64) -> bool {
    if let Some(got) = decoded.got {
        if index.jump_or_glob(got).is_some() {
            return true;
        }
        if decoded.resolver && pltgot != 0 && plt_reserved(got, pltgot) {
            return true;
        }
    }
    decoded.push.is_some_and(|push| index.jump(push).is_some())
}

fn plt_reserved(got: u64, pltgot: u64) -> bool {
    got == pltgot.wrapping_add(8) || got == pltgot.wrapping_add(16)
}

fn decode(bytes: &[u8], addr: u64) -> Option<Decoded> {
    if bytes.len() < 6 {
        return None;
    }
    let mut cursor = 0usize;
    if bytes.len() >= 4 && bytes[0..4] == ENDBR64 {
        cursor = 4;
    }
    if bytes.len() >= cursor + 6 && bytes[cursor] == 0xff && bytes[cursor + 1] == 0x35 {
        let disp = read::le_i32(&bytes[cursor + 2..cursor + 6]);
        return Some(Decoded {
            got: Some(rip_target(addr, cursor, disp)),
            push: None,
            resolver: true,
        });
    }
    if bytes.len() >= cursor + 6 && bytes[cursor] == 0xff && bytes[cursor + 1] == 0x25 {
        let disp = read::le_i32(&bytes[cursor + 2..cursor + 6]);
        let after = cursor + 6;
        let push = if bytes.len() >= after + 5 && bytes[after] == 0x68 {
            Some(read::le_u32(&bytes[after + 1..after + 5]))
        } else {
            None
        };
        return Some(Decoded {
            got: Some(rip_target(addr, cursor, disp)),
            push,
            resolver: false,
        });
    }
    if bytes.len() >= cursor + 5 && bytes[cursor] == 0x68 {
        let push = read::le_u32(&bytes[cursor + 1..cursor + 5]);
        return Some(Decoded {
            got: None,
            push: Some(push),
            resolver: false,
        });
    }
    None
}

fn rip_target(addr: u64, cursor: usize, disp: i32) -> u64 {
    addr.wrapping_add(cursor as u64)
        .wrapping_add(6)
        .wrapping_add_signed(i64::from(disp))
}

fn scaled(base: u64, index: usize, step: u64, what: &str) -> Result<u64> {
    let index = u64::try_from(index).map_err(|_| msg(format!("{what} overflows")))?;
    let delta = index
        .checked_mul(step)
        .ok_or_else(|| msg(format!("{what} overflows")))?;
    base.checked_add(delta)
        .ok_or_else(|| msg(format!("{what} overflows")))
}

fn span_end(addr: u64, count: usize) -> Result<u64> {
    if count == 0 {
        return Ok(addr);
    }
    scaled(addr, count, 8, "GOT address")
}

fn has_load(segments: &[Segment]) -> bool {
    segments
        .iter()
        .any(|segment| segment.kind == SegmentKind::Load)
}
