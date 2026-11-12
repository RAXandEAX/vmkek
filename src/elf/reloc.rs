use std::collections::HashSet;

use crate::error::{msg, Result};

use super::dynamic::{self, Linked};
use super::header::{self, va_file};
use super::read::{self, at};
use super::{
    DynamicEntry, DynamicTag, ElfBytes, ElfKind, RelocKind, Relocation, Section, SectionKind,
    Segment, SymbolTableId, MAX_RELOCS,
};

struct Image<'a> {
    data: &'a [u8],
    kind: ElfKind,
    segments: &'a [Segment],
    sections: &'a [Section],
    linked: &'a Linked,
}

struct Explicit<'a> {
    addr: u64,
    size: u64,
    entsize: u64,
    rela: bool,
    name: &'a str,
    table: SymbolTableId,
}

struct Draft {
    offset: u64,
    info: u64,
    addend: i64,
    section: ElfBytes,
    target: ElfBytes,
    table: SymbolTableId,
}

pub(super) fn collect(
    data: &[u8],
    kind: ElfKind,
    segments: &[Segment],
    sections: &[Section],
    dynamic: &[DynamicEntry],
    linked: &Linked,
) -> Result<Vec<Relocation>> {
    let image = Image {
        data,
        kind,
        segments,
        sections,
        linked,
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for section in sections {
        match section.kind {
            SectionKind::Rela => {
                rela_section(sections, linked, section, &mut seen, &mut out)?;
            }
            SectionKind::Rel => rel_section(&image, section, &mut seen, &mut out)?,
            SectionKind::Relr => relr_section(data, segments, section, &mut seen, &mut out)?,
            _ => {}
        }
    }
    dynamic_rela(data, segments, dynamic, linked, &mut seen, &mut out)?;
    dynamic_rel(data, segments, dynamic, linked, &mut seen, &mut out)?;
    dynamic_jmprel(data, segments, dynamic, linked, &mut seen, &mut out)?;
    dynamic_relr(data, segments, dynamic, &mut seen, &mut out)?;
    Ok(out)
}

fn rela_section(
    sections: &[Section],
    linked: &Linked,
    section: &Section,
    seen: &mut HashSet<u64>,
    out: &mut Vec<Relocation>,
) -> Result<()> {
    let bytes = reloc_bytes(section, 24)?;
    let table = reloc_table(sections, section.link)?;
    let target = target_name(sections, section.info)?;
    for (index, entry) in bytes.chunks(24).enumerate() {
        let at = section.offset + index as u64 * 24;
        if !seen.insert(at) {
            continue;
        }
        let offset = read::le_u64(&entry[0..8]);
        let info = read::le_u64(&entry[8..16]);
        let addend = read::le_i64(&entry[16..24]);
        push(
            out,
            linked,
            Draft {
                offset,
                info,
                addend,
                section: section.name.clone(),
                target: target.clone(),
                table,
            },
        )?;
    }
    Ok(())
}

fn rel_section(
    image: &Image<'_>,
    section: &Section,
    seen: &mut HashSet<u64>,
    out: &mut Vec<Relocation>,
) -> Result<()> {
    let bytes = reloc_bytes(section, 16)?;
    let table = reloc_table(image.sections, section.link)?;
    let target = target_name(image.sections, section.info)?;
    for (index, entry) in bytes.chunks(16).enumerate() {
        let at = section.offset + index as u64 * 16;
        if !seen.insert(at) {
            continue;
        }
        let offset = read::le_u64(&entry[0..8]);
        let info = read::le_u64(&entry[8..16]);
        let reloc_kind = RelocKind::from_u32(info as u32);
        let addend = implicit_addend(
            image.data,
            image.kind,
            image.segments,
            image.sections,
            section.info,
            offset,
            reloc_kind,
        )?;
        push(
            out,
            image.linked,
            Draft {
                offset,
                info,
                addend,
                section: section.name.clone(),
                target: target.clone(),
                table,
            },
        )?;
    }
    Ok(())
}

fn relr_section(
    data: &[u8],
    segments: &[Segment],
    section: &Section,
    seen: &mut HashSet<u64>,
    out: &mut Vec<Relocation>,
) -> Result<()> {
    let bytes = reloc_bytes(section, 8)?;
    decode_relr(
        data,
        segments,
        section.offset,
        bytes,
        &section.name,
        seen,
        out,
    )
}

fn dynamic_rela(
    data: &[u8],
    segments: &[Segment],
    dynamic: &[DynamicEntry],
    linked: &Linked,
    seen: &mut HashSet<u64>,
    out: &mut Vec<Relocation>,
) -> Result<()> {
    let Some(addr) = dynamic::pointer(dynamic, DynamicTag::Rela) else {
        return Ok(());
    };
    let size = dynamic::tag(dynamic, DynamicTag::RelaSize).unwrap_or(0);
    decode_explicit(
        data,
        segments,
        linked,
        Explicit {
            addr,
            size,
            entsize: 24,
            rela: true,
            name: "DT_RELA",
            table: SymbolTableId::Dynsym,
        },
        seen,
        out,
    )
}

fn dynamic_rel(
    data: &[u8],
    segments: &[Segment],
    dynamic: &[DynamicEntry],
    linked: &Linked,
    seen: &mut HashSet<u64>,
    out: &mut Vec<Relocation>,
) -> Result<()> {
    let Some(addr) = dynamic::pointer(dynamic, DynamicTag::Rel) else {
        return Ok(());
    };
    let size = dynamic::tag(dynamic, DynamicTag::RelSize).unwrap_or(0);
    decode_explicit(
        data,
        segments,
        linked,
        Explicit {
            addr,
            size,
            entsize: 16,
            rela: false,
            name: "DT_REL",
            table: SymbolTableId::Dynsym,
        },
        seen,
        out,
    )
}

fn dynamic_jmprel(
    data: &[u8],
    segments: &[Segment],
    dynamic: &[DynamicEntry],
    linked: &Linked,
    seen: &mut HashSet<u64>,
    out: &mut Vec<Relocation>,
) -> Result<()> {
    let Some(addr) = dynamic::pointer(dynamic, DynamicTag::JmpRel) else {
        return Ok(());
    };
    let size = dynamic::tag(dynamic, DynamicTag::PltRelSize).unwrap_or(0);
    if size == 0 {
        return Ok(());
    }
    let kind = dynamic::tag(dynamic, DynamicTag::PltRel)
        .ok_or_else(|| msg("PLT relocation type is missing"))?;
    let (entsize, rela) = match kind {
        7 => (24u64, true),
        17 => (16, false),
        _ => return Err(msg("PLT relocation type is unsupported")),
    };
    decode_explicit(
        data,
        segments,
        linked,
        Explicit {
            addr,
            size,
            entsize,
            rela,
            name: "DT_JMPREL",
            table: SymbolTableId::Dynsym,
        },
        seen,
        out,
    )
}

fn dynamic_relr(
    data: &[u8],
    segments: &[Segment],
    dynamic: &[DynamicEntry],
    seen: &mut HashSet<u64>,
    out: &mut Vec<Relocation>,
) -> Result<()> {
    let Some(addr) = dynamic::pointer(dynamic, DynamicTag::Relr) else {
        return Ok(());
    };
    let size = dynamic::tag(dynamic, DynamicTag::RelrSize).unwrap_or(0);
    if size == 0 {
        return Ok(());
    }
    if !size.is_multiple_of(8) {
        return Err(msg(
            "relocation table size is not a multiple of its entry size",
        ));
    }
    let len = usize::try_from(size).map_err(|_| msg("relocation table is too large"))?;
    let off = va_file(segments, addr, size)?;
    let bytes = at(data, off, len, "RELR table")?;
    decode_relr(
        data,
        segments,
        off,
        bytes,
        &ElfBytes::from("DT_RELR"),
        seen,
        out,
    )
}

fn decode_explicit(
    data: &[u8],
    segments: &[Segment],
    linked: &Linked,
    spec: Explicit<'_>,
    seen: &mut HashSet<u64>,
    out: &mut Vec<Relocation>,
) -> Result<()> {
    if spec.size == 0 {
        return Ok(());
    }
    if !spec.size.is_multiple_of(spec.entsize) {
        return Err(msg(
            "relocation table size is not a multiple of its entry size",
        ));
    }
    let len = usize::try_from(spec.size).map_err(|_| msg("relocation table is too large"))?;
    let off = va_file(segments, spec.addr, spec.size)?;
    let bytes = at(data, off, len, "relocation table")?;
    let step = spec.entsize as usize;
    for (index, entry) in bytes.chunks(step).enumerate() {
        let at = off + index as u64 * spec.entsize;
        if !seen.insert(at) {
            continue;
        }
        let offset = read::le_u64(&entry[0..8]);
        let info = read::le_u64(&entry[8..16]);
        let reloc_kind = RelocKind::from_u32(info as u32);
        let addend = if spec.rela {
            read::le_i64(&entry[16..24])
        } else {
            implicit_place(data, segments, offset, reloc_kind)?
        };
        push(
            out,
            linked,
            Draft {
                offset,
                info,
                addend,
                section: spec.name.into(),
                target: ElfBytes::new(),
                table: spec.table,
            },
        )?;
    }
    Ok(())
}

fn decode_relr(
    data: &[u8],
    segments: &[Segment],
    file_off: u64,
    bytes: &[u8],
    name: &ElfBytes,
    seen: &mut HashSet<u64>,
    out: &mut Vec<Relocation>,
) -> Result<()> {
    if !bytes.len().is_multiple_of(8) {
        return Err(msg(
            "relocation table size is not a multiple of its entry size",
        ));
    }
    let mut where_addr = None;
    for (index, entry) in bytes.chunks(8).enumerate() {
        let at = (index as u64)
            .checked_mul(8)
            .and_then(|step| file_off.checked_add(step))
            .ok_or_else(|| msg("relr address overflows"))?;
        if !seen.insert(at) {
            continue;
        }
        let value = read::le_u64(entry);
        where_addr = Some(relr_word(data, segments, value, where_addr, name, out)?);
    }
    Ok(())
}

fn relr_word(
    data: &[u8],
    segments: &[Segment],
    value: u64,
    where_addr: Option<u64>,
    name: &ElfBytes,
    out: &mut Vec<Relocation>,
) -> Result<u64> {
    if value & 1 == 0 {
        let addend = implicit_place(data, segments, value, RelocKind::Relative)?;
        push_relr(out, value, addend, name)?;
        return relr_addr(value, 8);
    }
    let base = where_addr.ok_or_else(|| msg("relr bitmap has no base address"))?;
    apply_relr_bits(data, segments, base, value, name, out)?;
    relr_addr(base, 63 * 8)
}

fn apply_relr_bits(
    data: &[u8],
    segments: &[Segment],
    base: u64,
    value: u64,
    name: &ElfBytes,
    out: &mut Vec<Relocation>,
) -> Result<()> {
    let mut bits = value;
    let mut slot = 0u64;
    loop {
        bits >>= 1;
        if bits == 0 {
            return Ok(());
        }
        if bits & 1 != 0 {
            let delta = slot
                .checked_mul(8)
                .ok_or_else(|| msg("relr address overflows"))?;
            let addr = relr_addr(base, delta)?;
            let addend = implicit_place(data, segments, addr, RelocKind::Relative)?;
            push_relr(out, addr, addend, name)?;
        }
        slot += 1;
    }
}

fn relr_addr(base: u64, add: u64) -> Result<u64> {
    base.checked_add(add)
        .ok_or_else(|| msg("relr address overflows"))
}

fn push_relr(out: &mut Vec<Relocation>, offset: u64, addend: i64, name: &ElfBytes) -> Result<()> {
    if out.len() >= MAX_RELOCS {
        return Err(msg("too many relocations"));
    }
    out.push(Relocation {
        offset,
        kind: RelocKind::Relative,
        symbol_index: 0,
        symbol: ElfBytes::new(),
        addend,
        section: name.clone(),
        target: ElfBytes::new(),
        table: SymbolTableId::None,
    });
    Ok(())
}

fn push(out: &mut Vec<Relocation>, linked: &Linked, draft: Draft) -> Result<()> {
    if out.len() >= MAX_RELOCS {
        return Err(msg("too many relocations"));
    }
    let symbol_index = (draft.info >> 32) as u32;
    let kind = RelocKind::from_u32(draft.info as u32);
    let symbol = symbol_name(linked, draft.table, symbol_index)?;
    out.push(Relocation {
        offset: draft.offset,
        kind,
        symbol_index,
        symbol,
        addend: draft.addend,
        section: draft.section,
        target: draft.target,
        table: draft.table,
    });
    Ok(())
}

fn symbol_name(linked: &Linked, table: SymbolTableId, index: u32) -> Result<ElfBytes> {
    if index == 0 {
        return Ok(ElfBytes::new());
    }
    let symbols = match table {
        SymbolTableId::Dynsym => &linked.dynamic_symbols,
        SymbolTableId::Symtab => &linked.symbols,
        SymbolTableId::None => {
            return Err(msg("relocation symbol index is out of range"));
        }
    };
    symbols
        .get(index as usize)
        .map(|symbol| symbol.name.clone())
        .ok_or_else(|| msg("relocation symbol index is out of range"))
}

fn reloc_bytes(section: &Section, entsize: u64) -> Result<&[u8]> {
    if section.entsize != 0 && section.entsize != entsize {
        return Err(msg(format!(
            "section {} entry size is not {entsize}",
            section.name
        )));
    }
    if !section.size.is_multiple_of(entsize) {
        return Err(msg(
            "relocation table size is not a multiple of its entry size",
        ));
    }
    if section.bytes_omitted || section.bytes.len() as u64 != section.size {
        return Err(msg(format!("section {} is too large", section.name)));
    }
    Ok(&section.bytes)
}

fn reloc_table(sections: &[Section], link: u32) -> Result<SymbolTableId> {
    if link == 0 {
        return Ok(SymbolTableId::None);
    }
    let section = sections
        .get(link as usize)
        .ok_or_else(|| msg("relocation symbol table is out of range"))?;
    match section.kind {
        SectionKind::Dynsym => Ok(SymbolTableId::Dynsym),
        SectionKind::Symtab => Ok(SymbolTableId::Symtab),
        _ => Err(msg("relocation symbol table is the wrong type")),
    }
}

fn target_name(sections: &[Section], info: u32) -> Result<ElfBytes> {
    if info == 0 {
        return Ok(ElfBytes::new());
    }
    sections
        .get(info as usize)
        .map(|section| section.name.clone())
        .ok_or_else(|| msg("relocation target section is out of range"))
}

fn implicit_addend(
    data: &[u8],
    kind: ElfKind,
    segments: &[Segment],
    sections: &[Section],
    target: u32,
    offset: u64,
    reloc: RelocKind,
) -> Result<i64> {
    let width = reloc.place_width();
    if width == 0 {
        return Ok(0);
    }
    if kind == ElfKind::Relocatable {
        let section = sections
            .get(target as usize)
            .ok_or_else(|| msg("relocation target section is out of range"))?;
        let start =
            usize::try_from(offset).map_err(|_| msg("relocation addend is outside the section"))?;
        let end = start
            .checked_add(width)
            .ok_or_else(|| msg("relocation addend is outside the section"))?;
        if end > section.bytes.len() {
            return Err(msg("relocation addend is outside the section"));
        }
        return Ok(place_value(&section.bytes[start..end]));
    }
    implicit_place(data, segments, offset, reloc)
}

fn implicit_place(data: &[u8], segments: &[Segment], addr: u64, reloc: RelocKind) -> Result<i64> {
    let width = reloc.place_width();
    if width == 0 {
        return Ok(0);
    }
    match header::place(data, segments, addr, width)? {
        Some(bytes) => Ok(place_value(bytes)),
        None => Ok(0),
    }
}

fn place_value(bytes: &[u8]) -> i64 {
    match bytes.len() {
        1 => i64::from(bytes[0] as i8),
        2 => i64::from(i16::from_le_bytes([bytes[0], bytes[1]])),
        4 => i64::from(read::le_i32(bytes)),
        8 => read::le_i64(bytes),
        _ => 0,
    }
}
