use std::collections::{HashMap, HashSet};

use crate::error::{msg, Result};

use super::header;
use super::read::{self, at};
use super::{
    DynamicEntry, DynamicTag, ElfBytes, Export, Import, PltEntry, RelocKind, Relocation, Section,
    SectionKind, Segment, Symbol, SymbolBind, SymbolKind, SymbolSection, SymbolTableId, Visibility,
    MAX_SYMBOLS,
};

pub(super) struct Linked {
    pub symbols: Vec<Symbol>,
    pub dynamic_symbols: Vec<Symbol>,
    pub needed: Vec<ElfBytes>,
    pub soname: Option<ElfBytes>,
    pub rpath: Option<ElfBytes>,
    pub runpath: Option<ElfBytes>,
}

pub(super) fn tag(dynamic: &[DynamicEntry], wanted: DynamicTag) -> Option<u64> {
    dynamic
        .iter()
        .find(|entry| entry.tag == wanted)
        .map(|entry| entry.value)
}

pub(super) fn pointer(dynamic: &[DynamicEntry], wanted: DynamicTag) -> Option<u64> {
    tag(dynamic, wanted).filter(|value| *value != 0)
}

pub(super) fn entries(
    data: &[u8],
    segments: &[Segment],
    sections: &[Section],
) -> Result<Vec<DynamicEntry>> {
    let Some((offset, size)) = dynamic_range(segments, sections)? else {
        return Ok(Vec::new());
    };
    if !size.is_multiple_of(16) {
        return Err(msg("dynamic table is truncated"));
    }
    let count = usize::try_from(size / 16).map_err(|_| msg("dynamic table is too large"))?;
    let bytes = at(data, offset, size as usize, "dynamic table")?;
    let mut out = Vec::with_capacity(count.min(super::MAX_DYNAMIC));
    let mut saw_null = false;
    for chunk in bytes.chunks(16) {
        if out.len() >= super::MAX_DYNAMIC {
            return Err(msg("dynamic table is too large"));
        }
        let raw = read::le_i64(chunk);
        let value = read::le_u64(&chunk[8..16]);
        let tag = DynamicTag::from_i64(raw);
        if tag == DynamicTag::Null {
            out.push(DynamicEntry { tag, value });
            saw_null = true;
            break;
        }
        push_unique(&mut out, tag, value)?;
    }
    if !saw_null {
        return Err(msg("dynamic table is not terminated"));
    }
    expect_ent(&out, DynamicTag::SymEnt, 24, "dynamic symbol")?;
    expect_ent(&out, DynamicTag::RelaEnt, 24, "RELA")?;
    expect_ent(&out, DynamicTag::RelEnt, 16, "REL")?;
    expect_ent(&out, DynamicTag::RelrEnt, 8, "RELR")?;
    Ok(out)
}

fn push_unique(out: &mut Vec<DynamicEntry>, tag: DynamicTag, value: u64) -> Result<()> {
    if tag == DynamicTag::Needed {
        out.push(DynamicEntry { tag, value });
        return Ok(());
    }
    if let Some(prev) = out.iter().find(|entry| entry.tag == tag) {
        if prev.value != value {
            return Err(msg("duplicate dynamic tag disagrees"));
        }
        return Ok(());
    }
    out.push(DynamicEntry { tag, value });
    Ok(())
}

fn expect_ent(dynamic: &[DynamicEntry], tag: DynamicTag, expected: u64, what: &str) -> Result<()> {
    if let Some(value) = self::tag(dynamic, tag) {
        if value != expected {
            return Err(msg(format!("{what} entry size is not {expected}")));
        }
    }
    Ok(())
}

fn dynamic_range(segments: &[Segment], sections: &[Section]) -> Result<Option<(u64, u64)>> {
    let mut segment = None;
    for item in segments {
        if item.kind != super::SegmentKind::Dynamic {
            continue;
        }
        if segment.is_some() {
            return Err(msg("multiple dynamic segments"));
        }
        segment = Some(item);
    }
    let section = only(sections, SectionKind::Dynamic, "dynamic")?;
    match (segment, section) {
        (Some(segment), Some(section)) => {
            if section.offset != segment.offset || section.size != segment.filesz {
                return Err(msg("dynamic segment and section disagree"));
            }
            Ok(Some((segment.offset, segment.filesz)))
        }
        (Some(segment), None) => Ok(Some((segment.offset, segment.filesz))),
        (None, Some(section)) => Ok(Some((section.offset, section.size))),
        (None, None) => Ok(None),
    }
}

pub(super) fn link(
    data: &[u8],
    segments: &[Segment],
    sections: &[Section],
    dynamic: &[DynamicEntry],
) -> Result<Linked> {
    let strtab = dynamic_strtab(data, segments, sections, dynamic)?;
    let needed = needed_names(dynamic, &strtab)?;
    let soname = optional_string(dynamic, DynamicTag::SoName, &strtab)?;
    let rpath = optional_string(dynamic, DynamicTag::RPath, &strtab)?;
    let runpath = optional_string(dynamic, DynamicTag::RunPath, &strtab)?;
    let symbols = static_symbols(sections)?;
    let mut dynamic_symbols = dynamic_symbols(data, segments, sections, dynamic, &strtab)?;
    apply_versions(
        data,
        segments,
        sections,
        dynamic,
        &strtab,
        &mut dynamic_symbols,
    )?;
    Ok(Linked {
        symbols,
        dynamic_symbols,
        needed,
        soname,
        rpath,
        runpath,
    })
}

fn needed_names(dynamic: &[DynamicEntry], strtab: &[u8]) -> Result<Vec<ElfBytes>> {
    let mut names = Vec::new();
    for entry in dynamic {
        if entry.tag != DynamicTag::Needed {
            continue;
        }
        let name = dyn_string(strtab, entry.value)?;
        if name.is_empty() {
            return Err(msg("DT_NEEDED string is empty"));
        }
        names.push(name);
    }
    Ok(names)
}

fn optional_string(
    dynamic: &[DynamicEntry],
    wanted: DynamicTag,
    strtab: &[u8],
) -> Result<Option<ElfBytes>> {
    let Some(offset) = tag(dynamic, wanted) else {
        return Ok(None);
    };
    let name = dyn_string(strtab, offset)?;
    if name.is_empty() {
        return Err(msg("dynamic string is empty"));
    }
    Ok(Some(name))
}

fn dyn_string(strtab: &[u8], offset: u64) -> Result<ElfBytes> {
    let off = usize::try_from(offset).map_err(|_| msg("dynamic string is out of range"))?;
    read::cstr(strtab, off, "dynamic string")
}

fn dynamic_strtab(
    data: &[u8],
    segments: &[Segment],
    sections: &[Section],
    dynamic: &[DynamicEntry],
) -> Result<Vec<u8>> {
    if let Some(dynsym) = only(sections, SectionKind::Dynsym, "dynamic symbol")? {
        let linked = section_bytes(sections, dynsym.link, "dynamic symbol string table")?;
        if let Some(section) = sections.get(dynsym.link as usize) {
            agree_addr(
                tag(dynamic, DynamicTag::StrTab),
                section.addr,
                "dynamic string table address disagrees",
            )?;
        }
        if let Some(size) = tag(dynamic, DynamicTag::StrSize) {
            if size != linked.len() as u64 {
                return Err(msg("dynamic string table size disagrees"));
            }
        }
        return Ok(linked);
    }
    let Some(addr) = pointer(dynamic, DynamicTag::StrTab) else {
        return Ok(Vec::new());
    };
    let Some(size) = tag(dynamic, DynamicTag::StrSize) else {
        return Err(msg("dynamic string table size is missing"));
    };
    if size > super::MAX_ESSENTIAL {
        return Err(msg("dynamic string table is too large"));
    }
    let bytes = header::va_slice(data, segments, addr, size as usize)?;
    Ok(bytes.to_vec())
}

fn static_symbols(sections: &[Section]) -> Result<Vec<Symbol>> {
    let Some(table) = only(sections, SectionKind::Symtab, "symbol")? else {
        return Ok(Vec::new());
    };
    let index = section_index(sections, table)?;
    let bytes = require_bytes(table)?;
    let strtab = section_bytes(sections, table.link, "symbol string table")?;
    let shndx = shndx_bytes(sections, index, bytes.len() / 24)?;
    decode_symbols(bytes, &strtab, shndx.as_deref(), sections.len(), true)
}

fn dynamic_symbols(
    data: &[u8],
    segments: &[Segment],
    sections: &[Section],
    dynamic: &[DynamicEntry],
    strtab: &[u8],
) -> Result<Vec<Symbol>> {
    let section = only(sections, SectionKind::Dynsym, "dynamic symbol")?;
    if let Some(section) = section {
        agree_addr(
            tag(dynamic, DynamicTag::SymTab),
            section.addr,
            "dynamic symbol table address disagrees",
        )?;
    }
    let Some(count) = symbol_count(data, segments, section, dynamic)? else {
        return Ok(Vec::new());
    };
    read_dynamic_symbols(data, segments, sections, dynamic, strtab, section, count)
}

fn agree_addr(recorded: Option<u64>, section_addr: u64, what: &str) -> Result<()> {
    if let Some(addr) = recorded {
        if addr != section_addr {
            return Err(msg(what));
        }
    }
    Ok(())
}

fn symbol_count(
    data: &[u8],
    segments: &[Segment],
    section: Option<&Section>,
    dynamic: &[DynamicEntry],
) -> Result<Option<usize>> {
    let section_count = section.map(table_count).transpose()?;
    let hash_count = pointer(dynamic, DynamicTag::Hash)
        .map(|addr| sysv_count(data, segments, addr))
        .transpose()?;
    let gnu = pointer(dynamic, DynamicTag::GnuHash)
        .map(|addr| gnu_count(data, segments, addr))
        .transpose()?;
    // SysV `nchain` is the full dynsym length. A GNU hash only chains the
    // symbols it indexes, so an object with no exported names can report a
    // shorter count than `.dynsym`.
    if let (Some(hash), Some(gnu)) = (hash_count, gnu) {
        if gnu > hash {
            return Err(msg("dynamic symbol counts disagree"));
        }
    }
    if let Some(section_count) = section_count {
        return checked_section_count(section_count, hash_count, gnu).map(Some);
    }
    if let Some(hash) = hash_count {
        return Ok(Some(hash));
    }
    if let Some(gnu) = gnu {
        return Ok(Some(gnu));
    }
    if pointer(dynamic, DynamicTag::SymTab).is_some() {
        return Err(msg("dynamic symbol count is missing"));
    }
    Ok(None)
}

fn checked_section_count(
    section_count: usize,
    hash: Option<usize>,
    gnu: Option<usize>,
) -> Result<usize> {
    if let Some(hash) = hash {
        if hash != section_count {
            return Err(msg("dynamic symbol counts disagree"));
        }
    }
    if let Some(gnu) = gnu {
        if gnu > section_count {
            return Err(msg("dynamic symbol counts disagree"));
        }
    }
    Ok(section_count)
}

fn read_dynamic_symbols(
    data: &[u8],
    segments: &[Segment],
    sections: &[Section],
    dynamic: &[DynamicEntry],
    strtab: &[u8],
    section: Option<&Section>,
    count: usize,
) -> Result<Vec<Symbol>> {
    if let Some(section) = section {
        let index = section_index(sections, section)?;
        let bytes = require_bytes(section)?;
        let names = section_bytes(sections, section.link, "dynamic symbol string table")?;
        let shndx = shndx_bytes(sections, index, bytes.len() / 24)?;
        return decode_symbols(bytes, &names, shndx.as_deref(), sections.len(), true);
    }
    let addr = pointer(dynamic, DynamicTag::SymTab)
        .ok_or_else(|| msg("dynamic symbol table is missing"))?;
    let bytes = symbol_bytes(count)?;
    let bytes = header::va_slice(data, segments, addr, bytes)?;
    decode_symbols(bytes, strtab, None, sections.len(), !sections.is_empty())
}

fn symbol_bytes(count: usize) -> Result<usize> {
    count
        .checked_mul(24)
        .ok_or_else(|| msg("too many dynamic symbols"))
}

fn table_count(section: &Section) -> Result<usize> {
    if section.entsize != 0 && section.entsize != 24 {
        return Err(msg("symbol table entry size is not 24"));
    }
    if !section.size.is_multiple_of(24) {
        return Err(msg("symbol table size is not a multiple of 24"));
    }
    let count = usize::try_from(section.size / 24).map_err(|_| msg("too many symbols"))?;
    if count > MAX_SYMBOLS {
        return Err(msg("too many symbols"));
    }
    Ok(count)
}

fn sysv_count(data: &[u8], segments: &[Segment], addr: u64) -> Result<usize> {
    let hdr = header::va_slice(data, segments, addr, 8)?;
    let nbucket = read::le_u32(&hdr[0..4]);
    let nchain = read::le_u32(&hdr[4..8]);
    if nbucket as usize > MAX_SYMBOLS || nchain as usize > MAX_SYMBOLS {
        return Err(msg("hash table is too large"));
    }
    let words = u64::from(nbucket)
        .checked_add(u64::from(nchain))
        .ok_or_else(|| msg("hash table is too large"))?;
    let bytes = words
        .checked_mul(4)
        .and_then(|rest| rest.checked_add(8))
        .ok_or_else(|| msg("hash table is too large"))?;
    let len = usize::try_from(bytes).map_err(|_| msg("hash table is too large"))?;
    let _ = header::va_slice(data, segments, addr, len)?;
    Ok(nchain as usize)
}

struct GnuHeader {
    nbuckets: u32,
    symoffset: u32,
    bloom_size: u32,
}

fn gnu_count(data: &[u8], segments: &[Segment], addr: u64) -> Result<usize> {
    let (header, buckets_at) = gnu_header(data, segments, addr)?;
    let Some(max_idx) = gnu_max_bucket(
        data,
        segments,
        buckets_at,
        header.nbuckets,
        header.symoffset,
    )?
    else {
        return Ok(header.symoffset as usize);
    };
    gnu_chain_len(
        data,
        segments,
        buckets_at,
        header.nbuckets,
        header.symoffset,
        max_idx,
    )
}

fn gnu_header(data: &[u8], segments: &[Segment], addr: u64) -> Result<(GnuHeader, u64)> {
    let hdr = header::va_slice(data, segments, addr, 16)?;
    let header = GnuHeader {
        nbuckets: read::le_u32(&hdr[0..4]),
        symoffset: read::le_u32(&hdr[4..8]),
        bloom_size: read::le_u32(&hdr[8..12]),
    };
    let bloom_shift = read::le_u32(&hdr[12..16]);
    if bloom_shift > 63 {
        return Err(msg("gnu hash bloom shift is invalid"));
    }
    if header.nbuckets as usize > MAX_SYMBOLS
        || header.bloom_size as usize > MAX_SYMBOLS
        || header.symoffset as usize > MAX_SYMBOLS
    {
        return Err(msg("gnu hash table is too large"));
    }
    let bloom_bytes = u64::from(header.bloom_size)
        .checked_mul(8)
        .ok_or_else(|| msg("gnu hash table is too large"))?;
    let bloom_at = addr
        .checked_add(16)
        .ok_or_else(|| msg("gnu hash table is too large"))?;
    let bloom_len = usize::try_from(bloom_bytes).map_err(|_| msg("gnu hash table is too large"))?;
    let _ = header::va_slice(data, segments, bloom_at, bloom_len)?;
    let buckets_at = bloom_at
        .checked_add(bloom_bytes)
        .ok_or_else(|| msg("gnu hash table is too large"))?;
    Ok((header, buckets_at))
}

fn gnu_max_bucket(
    data: &[u8],
    segments: &[Segment],
    buckets_at: u64,
    nbuckets: u32,
    symoffset: u32,
) -> Result<Option<u32>> {
    let mut max_idx = symoffset;
    let mut any = false;
    for index in 0..nbuckets {
        let word_va = gnu_word(buckets_at, index)?;
        let word = header::va_slice(data, segments, word_va, 4)?;
        let bucket = read::le_u32(word);
        if bucket == 0 {
            continue;
        }
        if bucket < symoffset {
            return Err(msg("gnu hash bucket is out of range"));
        }
        any = true;
        if bucket > max_idx {
            max_idx = bucket;
        }
    }
    Ok(any.then_some(max_idx))
}

fn gnu_chain_len(
    data: &[u8],
    segments: &[Segment],
    buckets_at: u64,
    nbuckets: u32,
    symoffset: u32,
    max_idx: u32,
) -> Result<usize> {
    let chains_at = gnu_word(buckets_at, nbuckets)?;
    let mut idx = max_idx;
    loop {
        let chain_index = u64::from(idx - symoffset);
        let chain_va = chains_at
            .checked_add(
                chain_index
                    .checked_mul(4)
                    .ok_or_else(|| msg("gnu hash chain is truncated"))?,
            )
            .ok_or_else(|| msg("gnu hash chain is truncated"))?;
        let word = header::va_slice(data, segments, chain_va, 4)?;
        if read::le_u32(word) & 1 != 0 {
            let count = idx as usize + 1;
            if count > MAX_SYMBOLS {
                return Err(msg("too many dynamic symbols"));
            }
            return Ok(count);
        }
        idx = idx
            .checked_add(1)
            .ok_or_else(|| msg("gnu hash chain is truncated"))?;
        if idx as usize > MAX_SYMBOLS {
            return Err(msg("gnu hash chain is too long"));
        }
    }
}

fn gnu_word(base: u64, index: u32) -> Result<u64> {
    base.checked_add(
        u64::from(index)
            .checked_mul(4)
            .ok_or_else(|| msg("gnu hash table is too large"))?,
    )
    .ok_or_else(|| msg("gnu hash table is too large"))
}

struct Versions<'a> {
    versym: Option<&'a [u8]>,
    verneed: Option<&'a [u8]>,
    verdef: Option<&'a [u8]>,
}

fn apply_versions(
    data: &[u8],
    segments: &[Segment],
    sections: &[Section],
    dynamic: &[DynamicEntry],
    strtab: &[u8],
    symbols: &mut [Symbol],
) -> Result<()> {
    let versions = load_versions(data, segments, sections, dynamic)?;
    if versions.versym.is_none() && versions.verneed.is_none() && versions.verdef.is_none() {
        return Ok(());
    }
    let versym = versions
        .versym
        .ok_or_else(|| msg("version symbol table is missing"))?;
    if symbols.is_empty() || versym.len() < symbols.len() * 2 || !versym.len().is_multiple_of(2) {
        return Err(msg("version symbol table does not match symbols"));
    }
    let need = match versions.verneed {
        Some(bytes) => parse_verneed(bytes, strtab, tag(dynamic, DynamicTag::VerNeedNum))?,
        None => HashMap::new(),
    };
    let def = match versions.verdef {
        Some(bytes) => parse_verdef(bytes, strtab, tag(dynamic, DynamicTag::VerDefNum))?,
        None => HashMap::new(),
    };
    assign_symbol_versions(symbols, versym, &need, &def);
    Ok(())
}

fn load_versions<'a>(
    data: &'a [u8],
    segments: &[Segment],
    sections: &'a [Section],
    dynamic: &[DynamicEntry],
) -> Result<Versions<'a>> {
    Ok(Versions {
        versym: version_bytes(
            data,
            segments,
            sections,
            dynamic,
            SectionKind::GnuVersym,
            DynamicTag::VerSym,
            "version symbol",
        )?,
        verneed: version_bytes(
            data,
            segments,
            sections,
            dynamic,
            SectionKind::GnuVerneed,
            DynamicTag::VerNeed,
            "version need",
        )?,
        verdef: version_bytes(
            data,
            segments,
            sections,
            dynamic,
            SectionKind::GnuVerdef,
            DynamicTag::VerDef,
            "version definition",
        )?,
    })
}

fn assign_symbol_versions(
    symbols: &mut [Symbol],
    versym: &[u8],
    need: &HashMap<u16, (ElfBytes, ElfBytes)>,
    def: &HashMap<u16, ElfBytes>,
) {
    for (index, symbol) in symbols.iter_mut().enumerate() {
        let raw = read::le_u16(&versym[index * 2..index * 2 + 2]);
        let ndx = raw & 0x7fff;
        if ndx <= 1 {
            continue;
        }
        if symbol.section == SymbolSection::Undefined {
            if let Some((file, version)) = need.get(&ndx) {
                symbol.version_file = Some(file.clone());
                symbol.version = Some(version.clone());
            }
        } else if let Some(version) = def.get(&ndx) {
            symbol.version = Some(version.clone());
        } else if let Some((file, version)) = need.get(&ndx) {
            symbol.version_file = Some(file.clone());
            symbol.version = Some(version.clone());
        }
    }
}

fn version_bytes<'a>(
    data: &'a [u8],
    segments: &[Segment],
    sections: &'a [Section],
    dynamic: &[DynamicEntry],
    kind: SectionKind,
    tag: DynamicTag,
    what: &str,
) -> Result<Option<&'a [u8]>> {
    let section = only(sections, kind, what)?;
    let addr = self::tag(dynamic, tag);
    if let (Some(section), Some(addr)) = (section, addr) {
        if section.addr != addr {
            return Err(msg(format!("{what} address disagrees")));
        }
    }
    if let Some(section) = section {
        return Ok(Some(require_bytes(section)?));
    }
    let Some(addr) = addr.filter(|value| *value != 0) else {
        return Ok(None);
    };
    Ok(Some(version_window(data, segments, addr)?))
}

fn version_window<'a>(data: &'a [u8], segments: &[Segment], addr: u64) -> Result<&'a [u8]> {
    for segment in segments {
        if segment.kind != super::SegmentKind::Load || segment.filesz == 0 {
            continue;
        }
        let file_end = segment
            .vaddr
            .checked_add(segment.filesz)
            .ok_or_else(|| msg("load segment end overflows"))?;
        if addr < segment.vaddr || addr >= file_end {
            continue;
        }
        let available = file_end - addr;
        let len = available.min(super::MAX_ESSENTIAL);
        let off = segment
            .offset
            .checked_add(addr - segment.vaddr)
            .ok_or_else(|| msg("load segment offset overflows"))?;
        let len = usize::try_from(len).map_err(|_| msg("version table is too large"))?;
        return at(data, off, len, "version table");
    }
    Err(msg(format!(
        "virtual address {addr:#x} is not in a load segment"
    )))
}

fn parse_verneed(
    bytes: &[u8],
    strtab: &[u8],
    count: Option<u64>,
) -> Result<HashMap<u16, (ElfBytes, ElfBytes)>> {
    let mut map = HashMap::new();
    let mut off = 0usize;
    let mut seen = 0u64;
    let limit = count.unwrap_or(4096).min(4096);
    while seen < limit {
        let next = read_verneed(bytes, strtab, off, &mut map)?;
        seen += 1;
        let Some(next) = next else {
            break;
        };
        off = step_chain(off, next, "version need")?;
    }
    if let Some(count) = count {
        if seen != count {
            return Err(msg("version need count disagrees"));
        }
    }
    Ok(map)
}

fn read_verneed(
    bytes: &[u8],
    strtab: &[u8],
    off: usize,
    map: &mut HashMap<u16, (ElfBytes, ElfBytes)>,
) -> Result<Option<usize>> {
    if off + 16 > bytes.len() {
        return Err(msg("version need is truncated"));
    }
    if read::le_u16(&bytes[off..off + 2]) != 1 {
        return Err(msg("unsupported version need"));
    }
    let aux_count = usize::from(read::le_u16(&bytes[off + 2..off + 4]));
    let file_off = read::le_u32(&bytes[off + 4..off + 8]) as usize;
    let aux = read::le_u32(&bytes[off + 8..off + 12]) as usize;
    let next = read::le_u32(&bytes[off + 12..off + 16]) as usize;
    let file = read::cstr(strtab, file_off, "version file")?;
    read_verneed_aux(bytes, strtab, off, aux, aux_count, &file, map)?;
    Ok((next != 0).then_some(next))
}

fn read_verneed_aux(
    bytes: &[u8],
    strtab: &[u8],
    off: usize,
    aux: usize,
    aux_count: usize,
    file: &ElfBytes,
    map: &mut HashMap<u16, (ElfBytes, ElfBytes)>,
) -> Result<()> {
    let mut cursor = off
        .checked_add(aux)
        .ok_or_else(|| msg("version need is truncated"))?;
    if aux_count > 4096 {
        return Err(msg("version need is too large"));
    }
    for index in 0..aux_count {
        if cursor + 16 > bytes.len() {
            return Err(msg("version need is truncated"));
        }
        let other = read::le_u16(&bytes[cursor + 6..cursor + 8]);
        let name_off = read::le_u32(&bytes[cursor + 8..cursor + 12]) as usize;
        let aux_next = read::le_u32(&bytes[cursor + 12..cursor + 16]) as usize;
        let name = read::cstr(strtab, name_off, "version name")?;
        map.insert(other, (file.clone(), name));
        if aux_next == 0 {
            if index + 1 != aux_count {
                return Err(msg("version need chain is short"));
            }
            break;
        }
        cursor = step_chain(cursor, aux_next, "version need")?;
    }
    Ok(())
}

fn parse_verdef(bytes: &[u8], strtab: &[u8], count: Option<u64>) -> Result<HashMap<u16, ElfBytes>> {
    let mut map = HashMap::new();
    let mut off = 0usize;
    let mut seen = 0u64;
    let limit = count.unwrap_or(4096).min(4096);
    while seen < limit {
        let next = read_verdef(bytes, strtab, off, &mut map)?;
        seen += 1;
        let Some(next) = next else {
            break;
        };
        off = step_chain(off, next, "version definition")?;
    }
    if let Some(count) = count {
        if seen != count {
            return Err(msg("version definition count disagrees"));
        }
    }
    Ok(map)
}

fn read_verdef(
    bytes: &[u8],
    strtab: &[u8],
    off: usize,
    map: &mut HashMap<u16, ElfBytes>,
) -> Result<Option<usize>> {
    if off + 20 > bytes.len() {
        return Err(msg("version definition is truncated"));
    }
    if read::le_u16(&bytes[off..off + 2]) != 1 {
        return Err(msg("unsupported version definition"));
    }
    let ndx = read::le_u16(&bytes[off + 4..off + 6]);
    let aux_count = usize::from(read::le_u16(&bytes[off + 6..off + 8]));
    let aux = read::le_u32(&bytes[off + 12..off + 16]) as usize;
    let next = read::le_u32(&bytes[off + 16..off + 20]) as usize;
    if let Some(name) = verdef_aux(bytes, strtab, off, aux, aux_count)? {
        map.insert(ndx, name);
    }
    Ok((next != 0).then_some(next))
}

fn verdef_aux(
    bytes: &[u8],
    strtab: &[u8],
    off: usize,
    aux: usize,
    aux_count: usize,
) -> Result<Option<ElfBytes>> {
    let mut cursor = off
        .checked_add(aux)
        .ok_or_else(|| msg("version definition is truncated"))?;
    let mut name = None;
    for _ in 0..aux_count {
        if cursor + 8 > bytes.len() {
            return Err(msg("version definition is truncated"));
        }
        let name_off = read::le_u32(&bytes[cursor..cursor + 4]) as usize;
        let aux_next = read::le_u32(&bytes[cursor + 4..cursor + 8]) as usize;
        if name.is_none() {
            name = Some(read::cstr(strtab, name_off, "version name")?);
        }
        if aux_next == 0 {
            break;
        }
        cursor = step_chain(cursor, aux_next, "version definition")?;
    }
    Ok(name)
}

fn step_chain(off: usize, next: usize, what: &str) -> Result<usize> {
    let step = off
        .checked_add(next)
        .ok_or_else(|| msg(format!("{what} is truncated")))?;
    if step <= off {
        return Err(msg(format!("{what} chain loops")));
    }
    Ok(step)
}

fn decode_symbols(
    bytes: &[u8],
    strtab: &[u8],
    shndx: Option<&[u8]>,
    section_count: usize,
    sections_known: bool,
) -> Result<Vec<Symbol>> {
    if !bytes.len().is_multiple_of(24) {
        return Err(msg("symbol table size is not a multiple of 24"));
    }
    let count = bytes.len() / 24;
    if count > MAX_SYMBOLS {
        return Err(msg("too many symbols"));
    }
    if let Some(shndx) = shndx {
        if shndx.len() != count * 4 {
            return Err(msg("symbol section index table does not match symbols"));
        }
    }
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let entry = &bytes[index * 24..index * 24 + 24];
        let name_off = read::le_u32(&entry[0..4]) as usize;
        let info = entry[4];
        let other = entry[5];
        let raw_shndx = read::le_u16(&entry[6..8]);
        let extended = shndx.map(|table| read::le_u32(&table[index * 4..index * 4 + 4]));
        let name = if name_off == 0 {
            ElfBytes::new()
        } else {
            read::cstr(strtab, name_off, "symbol name")?
        };
        out.push(Symbol {
            name,
            value: read::le_u64(&entry[8..16]),
            size: read::le_u64(&entry[16..24]),
            bind: SymbolBind::from_u8(info >> 4),
            kind: SymbolKind::from_u8(info & 0xf),
            visibility: Visibility::from_u8(other),
            section: symbol_section(raw_shndx, extended, section_count, sections_known)?,
            version: None,
            version_file: None,
        });
    }
    Ok(out)
}

fn symbol_section(
    raw: u16,
    extended: Option<u32>,
    section_count: usize,
    sections_known: bool,
) -> Result<SymbolSection> {
    let index = if raw == 0xffff {
        extended.ok_or_else(|| msg("symbol section index is unresolved"))?
    } else {
        u32::from(raw)
    };
    let section = match index {
        0 => SymbolSection::Undefined,
        0xfff1 => SymbolSection::Absolute,
        0xfff2 => SymbolSection::Common,
        reserved if (0xff00..=0xffff).contains(&reserved) => {
            SymbolSection::Reserved(reserved as u16)
        }
        other => {
            if sections_known && other as usize >= section_count {
                return Err(msg("symbol section index is out of range"));
            }
            SymbolSection::Index(other)
        }
    };
    Ok(section)
}

fn shndx_bytes(sections: &[Section], table: usize, count: usize) -> Result<Option<Vec<u8>>> {
    let mut found = None;
    for section in sections {
        if section.kind != SectionKind::SymtabShndx || section.link as usize != table {
            continue;
        }
        if found.is_some() {
            return Err(msg("multiple symbol index sections"));
        }
        found = Some(require_bytes(section)?.to_vec());
    }
    if let Some(bytes) = &found {
        if bytes.len() != count * 4 {
            return Err(msg("symbol section index table does not match symbols"));
        }
    }
    Ok(found)
}

fn only<'a>(sections: &'a [Section], kind: SectionKind, what: &str) -> Result<Option<&'a Section>> {
    let mut found = None;
    for section in sections {
        if section.kind != kind {
            continue;
        }
        if found.is_some() {
            return Err(msg(format!("multiple {what} sections")));
        }
        found = Some(section);
    }
    Ok(found)
}

fn section_index(sections: &[Section], wanted: &Section) -> Result<usize> {
    sections
        .iter()
        .position(|section| std::ptr::eq(section, wanted))
        .ok_or_else(|| msg("section is missing"))
}

fn section_bytes(sections: &[Section], link: u32, what: &str) -> Result<Vec<u8>> {
    let section = sections
        .get(link as usize)
        .ok_or_else(|| msg(format!("{what} is out of range")))?;
    if section.kind != SectionKind::Strtab && what.contains("string") {
        return Err(msg(format!("{what} is not a string table")));
    }
    require_bytes(section).map(ToOwned::to_owned)
}

fn require_bytes(section: &Section) -> Result<&[u8]> {
    if section.bytes_omitted || section.bytes.len() as u64 != section.size {
        return Err(msg(format!("section {} is too large", section.name)));
    }
    Ok(&section.bytes)
}

struct SymbolUses {
    copy: HashSet<(u8, u32)>,
    jump: HashMap<(u8, u32), u64>,
    glob: HashMap<(u8, u32), u64>,
    plt: HashMap<u32, (u64, u8, bool)>,
}

pub(super) fn bind(
    linked: &Linked,
    relocations: &[Relocation],
    plt: &[PltEntry],
) -> (Vec<Export>, Vec<Import>) {
    let Some((table, id)) = symbol_source(linked) else {
        return (Vec::new(), Vec::new());
    };
    let uses = symbol_uses(relocations, plt);
    let mut exports = Vec::new();
    let mut imports = Vec::new();
    for (index, symbol) in table.iter().enumerate() {
        if !published(index, symbol) {
            continue;
        }
        classify_symbol(index as u32, symbol, id, &uses, &mut exports, &mut imports);
    }
    (exports, imports)
}

fn symbol_source(linked: &Linked) -> Option<(&[Symbol], SymbolTableId)> {
    if !linked.dynamic_symbols.is_empty() {
        Some((linked.dynamic_symbols.as_slice(), SymbolTableId::Dynsym))
    } else if !linked.symbols.is_empty() {
        Some((linked.symbols.as_slice(), SymbolTableId::Symtab))
    } else {
        None
    }
}

fn published(index: usize, symbol: &Symbol) -> bool {
    index != 0
        && !symbol.name.is_empty()
        && symbol.kind.named_object()
        && symbol.bind.exported()
        && symbol.visibility.is_dynamic()
}

fn symbol_uses(relocations: &[Relocation], plt: &[PltEntry]) -> SymbolUses {
    let mut uses = SymbolUses {
        copy: HashSet::new(),
        jump: HashMap::new(),
        glob: HashMap::new(),
        plt: HashMap::new(),
    };
    for reloc in relocations {
        let key = (table_key(reloc.table), reloc.symbol_index);
        match reloc.kind {
            RelocKind::Copy => {
                uses.copy.insert(key);
            }
            // Later entries replace earlier ones, matching the previous scan.
            RelocKind::JumpSlot => {
                uses.jump.insert(key, reloc.offset);
            }
            RelocKind::GlobDat => {
                uses.glob.insert(key, reloc.offset);
            }
            _ => {}
        }
    }
    for entry in plt {
        remember_plt(&mut uses.plt, entry);
    }
    uses
}

fn classify_symbol(
    index: u32,
    symbol: &Symbol,
    table: SymbolTableId,
    uses: &SymbolUses,
    exports: &mut Vec<Export>,
    imports: &mut Vec<Import>,
) {
    let key = (table_key(table), index);
    let copied = uses.copy.contains(&key);
    if symbol.section.defined() && !copied {
        exports.push(Export {
            name: symbol.name.clone(),
            value: symbol.value,
            size: symbol.size,
            kind: symbol.kind,
            bind: symbol.bind,
            version: symbol.version.clone(),
        });
        return;
    }
    if symbol.section == SymbolSection::Undefined || copied {
        imports.push(Import {
            name: symbol.name.clone(),
            bind: symbol.bind,
            kind: symbol.kind,
            library: symbol.version_file.clone(),
            version: symbol.version.clone(),
            got: uses
                .jump
                .get(&key)
                .copied()
                .or_else(|| uses.glob.get(&key).copied()),
            plt: uses.plt.get(&index).map(|best| best.0),
        });
    }
}

fn remember_plt(plt: &mut HashMap<u32, (u64, u8, bool)>, entry: &PltEntry) {
    let Some(index) = entry.symbol_index else {
        return;
    };
    if entry.resolver {
        return;
    }
    let rank = plt_rank(&entry.section);
    let has_got = entry.got.is_some();
    let candidate = (entry.addr, rank, has_got);
    plt.entry(index)
        .and_modify(|best| {
            if rank < best.1 || (rank == best.1 && has_got && !best.2) {
                *best = candidate;
            }
        })
        .or_insert(candidate);
}

fn table_key(id: SymbolTableId) -> u8 {
    match id {
        SymbolTableId::None => 0,
        SymbolTableId::Symtab => 1,
        SymbolTableId::Dynsym => 2,
    }
}

fn plt_rank(section: &ElfBytes) -> u8 {
    if section == ".plt.sec" {
        0
    } else if section == ".plt.got" || section == ".iplt" {
        1
    } else if section == ".plt" {
        2
    } else {
        3
    }
}
