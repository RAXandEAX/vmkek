use crate::error::{msg, Result};

use super::read::{self, at};
use super::{
    ElfBytes, ElfKind, Section, SectionKind, Segment, SegmentKind, MAX_ALLOC_COPY, MAX_ESSENTIAL,
    MAX_OTHER_COPY, MAX_SECTIONS, MAX_SEGMENTS, MAX_STRING, MAX_TOTAL_COPY,
};

const SHF_COMPRESSED: u64 = 0x800;
const PN_XNUM: u16 = 0xffff;
const SHN_XINDEX: u16 = 0xffff;

pub(super) struct Header {
    pub kind: ElfKind,
    pub os_abi: u8,
    pub abi_version: u8,
    pub entry: u64,
    pub flags: u32,
    pub phoff: u64,
    pub shoff: u64,
    pub phnum: usize,
    pub shnum: usize,
    pub shstrndx: usize,
}

struct Counts {
    phnum: usize,
    shnum: usize,
    shstrndx: usize,
}

pub(super) fn header(data: &[u8]) -> Result<Header> {
    check_ident(data)?;
    let kind = file_kind(data)?;
    let entry = read::u64_at(data, 24)?;
    let phoff = read::u64_at(data, 32)?;
    let shoff = read::u64_at(data, 40)?;
    let flags = read::u32_at(data, 48)?;
    if read::u16(data, 52)? != 64 {
        return Err(msg("unexpected ELF header size"));
    }
    let phentsize = read::u16(data, 54)?;
    let shentsize = read::u16(data, 58)?;
    let counts = table_counts(data, shoff)?;
    check_entry_sizes(phentsize, shentsize, counts.phnum, counts.shnum)?;
    check_shstrndx(counts.shnum, counts.shstrndx)?;
    Ok(Header {
        kind,
        os_abi: data[7],
        abi_version: data[8],
        entry,
        flags,
        phoff,
        shoff,
        phnum: counts.phnum,
        shnum: counts.shnum,
        shstrndx: counts.shstrndx,
    })
}

fn check_ident(data: &[u8]) -> Result<()> {
    if data.len() < 4 || data[0] != 0x7f || &data[1..4] != b"ELF" {
        return Err(msg("not an ELF image"));
    }
    if data.len() < 16 {
        return Err(msg("elf header is truncated"));
    }
    if data[4] != 2 {
        return Err(msg("only ELF64 is supported"));
    }
    if data[5] != 1 {
        return Err(msg("only little-endian ELF is supported"));
    }
    if data[6] != 1 {
        return Err(msg("unsupported ELF version"));
    }
    if data.len() < 64 {
        return Err(msg("elf header is truncated"));
    }
    Ok(())
}

fn file_kind(data: &[u8]) -> Result<ElfKind> {
    let kind = match read::u16(data, 16)? {
        1 => ElfKind::Relocatable,
        2 => ElfKind::Executable,
        3 => ElfKind::Shared,
        _ => return Err(msg("unsupported ELF type")),
    };
    if read::u16(data, 18)? != 62 {
        return Err(msg("only x86-64 ELF is supported"));
    }
    if read::u32_at(data, 20)? != 1 {
        return Err(msg("unsupported ELF version"));
    }
    Ok(kind)
}

fn table_counts(data: &[u8], shoff: u64) -> Result<Counts> {
    let raw_phnum = read::u16(data, 56)?;
    let raw_shnum = read::u16(data, 60)?;
    let raw_shstr = read::u16(data, 62)?;
    let mut counts = Counts {
        phnum: usize::from(raw_phnum),
        shnum: usize::from(raw_shnum),
        shstrndx: usize::from(raw_shstr),
    };
    if shoff != 0 && (raw_shnum == 0 || raw_shstr == SHN_XINDEX || raw_phnum == PN_XNUM) {
        apply_extended(data, shoff, raw_shnum, raw_shstr, raw_phnum, &mut counts)?;
    } else if shoff == 0 && raw_shnum != 0 {
        return Err(msg("section headers are missing"));
    } else if shoff == 0 && raw_phnum == PN_XNUM {
        return Err(msg("extended program header count is missing"));
    }
    if counts.phnum > MAX_SEGMENTS {
        return Err(msg("too many program headers"));
    }
    if counts.shnum > MAX_SECTIONS {
        return Err(msg("too many sections"));
    }
    Ok(counts)
}

fn apply_extended(
    data: &[u8],
    shoff: u64,
    raw_shnum: u16,
    raw_shstr: u16,
    raw_phnum: u16,
    counts: &mut Counts,
) -> Result<()> {
    let first = at(data, shoff, 64, "section header")?;
    if raw_shnum == 0 {
        counts.shnum =
            usize::try_from(read::le_u64(&first[32..40])).map_err(|_| msg("too many sections"))?;
    }
    if raw_shstr == SHN_XINDEX {
        counts.shstrndx =
            usize::try_from(read::le_u32(&first[40..44])).map_err(|_| msg("too many sections"))?;
    }
    if raw_phnum == PN_XNUM {
        counts.phnum = usize::try_from(read::le_u32(&first[44..48]))
            .map_err(|_| msg("too many program headers"))?;
    }
    Ok(())
}

fn check_entry_sizes(phentsize: u16, shentsize: u16, phnum: usize, shnum: usize) -> Result<()> {
    if phnum > 0 && phentsize != 56 {
        return Err(msg("unexpected program header size"));
    }
    if phnum == 0 && phentsize != 0 && phentsize != 56 {
        return Err(msg("unexpected program header size"));
    }
    if shnum > 0 && shentsize != 64 {
        return Err(msg("unexpected section header size"));
    }
    if shnum == 0 && shentsize != 0 && shentsize != 64 {
        return Err(msg("unexpected section header size"));
    }
    Ok(())
}

fn check_shstrndx(shnum: usize, shstrndx: usize) -> Result<()> {
    if shnum == 0 {
        if shstrndx != 0 {
            return Err(msg("section header string table is missing"));
        }
        return Ok(());
    }
    if shstrndx >= shnum {
        return Err(msg("section header string table is missing"));
    }
    Ok(())
}

pub(super) fn segments(data: &[u8], header: &Header) -> Result<Vec<Segment>> {
    if header.phnum == 0 {
        return Ok(Vec::new());
    }
    let end = read::table_len(header.phoff, header.phnum as u64, 56, "program header")?;
    if end > data.len() as u64 {
        return Err(msg("program headers are outside the file"));
    }
    let mut out = Vec::with_capacity(header.phnum);
    for index in 0..header.phnum {
        let off = header
            .phoff
            .checked_add(index as u64 * 56)
            .ok_or_else(|| msg("program headers are outside the file"))?;
        let bytes = at(data, off, 56, "program header")?;
        let segment = Segment {
            kind: SegmentKind::from_u32(read::le_u32(&bytes[0..4])),
            flags: read::le_u32(&bytes[4..8]),
            offset: read::le_u64(&bytes[8..16]),
            vaddr: read::le_u64(&bytes[16..24]),
            paddr: read::le_u64(&bytes[24..32]),
            filesz: read::le_u64(&bytes[32..40]),
            memsz: read::le_u64(&bytes[40..48]),
            align: read::le_u64(&bytes[48..56]),
        };
        if segment.filesz > 0 {
            let file_end = segment
                .offset
                .checked_add(segment.filesz)
                .ok_or_else(|| msg("segment is outside the file"))?;
            if file_end > data.len() as u64 {
                return Err(msg("segment is outside the file"));
            }
        }
        if segment.kind == SegmentKind::Load {
            if segment.filesz > segment.memsz {
                return Err(msg("load segment file size exceeds memory size"));
            }
            if segment.memsz > 0 && segment.vaddr.checked_add(segment.memsz).is_none() {
                return Err(msg("load segment end overflows"));
            }
        }
        out.push(segment);
    }
    Ok(out)
}

pub(super) fn sections(data: &[u8], header: &Header) -> Result<Vec<Section>> {
    if header.shnum == 0 {
        return Ok(Vec::new());
    }
    let end = read::table_len(header.shoff, header.shnum as u64, 64, "section header")?;
    if end > data.len() as u64 {
        return Err(msg("section headers are outside the file"));
    }
    let mut raw = Vec::with_capacity(header.shnum);
    for index in 0..header.shnum {
        let off = header
            .shoff
            .checked_add(index as u64 * 64)
            .ok_or_else(|| msg("section headers are outside the file"))?;
        raw.push(at(data, off, 64, "section header")?.to_vec());
    }
    if SectionKind::from_u32(read::le_u32(&raw[0][4..8])) != SectionKind::Null {
        return Err(msg("section 0 is not SHT_NULL"));
    }
    let names = section_names(data, &raw, header.shstrndx)?;
    let mut budget = 0usize;
    let mut out = Vec::with_capacity(raw.len());
    for (index, bytes) in raw.iter().enumerate() {
        out.push(one_section(data, index, bytes, &names[index], &mut budget)?);
    }
    Ok(out)
}

fn section_names(data: &[u8], raw: &[Vec<u8>], shstrndx: usize) -> Result<Vec<ElfBytes>> {
    let strtab = &raw[shstrndx];
    let kind = SectionKind::from_u32(read::le_u32(&strtab[4..8]));
    if kind != SectionKind::Strtab {
        return Err(msg("section header string table has the wrong type"));
    }
    let offset = read::le_u64(&strtab[24..32]);
    let size = read::le_u64(&strtab[32..40]);
    if size > MAX_STRING as u64 * 16 {
        return Err(msg("section header string table is too large"));
    }
    let bytes = if size == 0 {
        &[][..]
    } else {
        at(data, offset, size as usize, "section header string table")?
    };
    let mut names = Vec::with_capacity(raw.len());
    for header in raw {
        let name_off = read::le_u32(&header[0..4]) as usize;
        names.push(read::cstr(bytes, name_off, "section name")?);
    }
    Ok(names)
}

fn one_section(
    data: &[u8],
    index: usize,
    bytes: &[u8],
    name: &ElfBytes,
    budget: &mut usize,
) -> Result<Section> {
    let kind = SectionKind::from_u32(read::le_u32(&bytes[4..8]));
    let flags = read::le_u64(&bytes[8..16]);
    let addr = read::le_u64(&bytes[16..24]);
    let offset = read::le_u64(&bytes[24..32]);
    let mut size = read::le_u64(&bytes[32..40]);
    let mut link = read::le_u32(&bytes[40..44]);
    let mut info = read::le_u32(&bytes[44..48]);
    let addralign = read::le_u64(&bytes[48..56]);
    let entsize = read::le_u64(&bytes[56..64]);
    if index == 0 {
        size = 0;
        link = 0;
        info = 0;
    }
    let (copied, omitted) = copy_section(data, name, kind, flags, offset, size, budget)?;
    Ok(Section {
        name: name.clone(),
        kind,
        flags,
        addr,
        offset,
        size,
        link,
        info,
        addralign,
        entsize,
        bytes: copied,
        bytes_omitted: omitted,
    })
}

fn copy_section(
    data: &[u8],
    name: &ElfBytes,
    kind: SectionKind,
    flags: u64,
    offset: u64,
    size: u64,
    budget: &mut usize,
) -> Result<(Vec<u8>, bool)> {
    if kind == SectionKind::Null || kind == SectionKind::Nobits || size == 0 {
        return Ok((Vec::new(), false));
    }
    let end = offset
        .checked_add(size)
        .ok_or_else(|| msg(format!("section {name} is outside the file")))?;
    if end > data.len() as u64 {
        return Err(msg(format!("section {name} is outside the file")));
    }
    let required = kind.essential();
    if required && flags & SHF_COMPRESSED != 0 {
        return Err(msg(format!("compressed section {name} is not supported")));
    }
    let limit = if required {
        MAX_ESSENTIAL
    } else if flags & 2 != 0 {
        MAX_ALLOC_COPY
    } else {
        MAX_OTHER_COPY
    };
    if size > limit || budget.saturating_add(size as usize) > MAX_TOTAL_COPY {
        if required {
            return Err(msg(format!("section {name} is too large")));
        }
        return Ok((Vec::new(), true));
    }
    let start =
        usize::try_from(offset).map_err(|_| msg(format!("section {name} is outside the file")))?;
    let len = usize::try_from(size).map_err(|_| msg(format!("section {name} is too large")))?;
    *budget += len;
    Ok((data[start..start + len].to_vec(), false))
}

pub(super) fn interpreter(data: &[u8], segments: &[Segment]) -> Result<Option<ElfBytes>> {
    let mut found = None;
    for segment in segments {
        if segment.kind != SegmentKind::Interp {
            continue;
        }
        if found.is_some() {
            return Err(msg("multiple interpreter segments"));
        }
        if segment.filesz == 0 || segment.filesz > MAX_STRING as u64 {
            return Err(msg("interpreter path is invalid"));
        }
        let bytes = at(data, segment.offset, segment.filesz as usize, "interpreter")?;
        found = Some(read::cstr(bytes, 0, "interpreter path")?);
    }
    Ok(found)
}

/// File offset of `[va, va + len)` when that whole range is in one `PT_LOAD` file image.
pub(super) fn va_file(segments: &[Segment], va: u64, len: u64) -> Result<u64> {
    let end = va
        .checked_add(len)
        .ok_or_else(|| msg("virtual address range overflows"))?;
    for segment in segments {
        if segment.kind != SegmentKind::Load || segment.filesz == 0 {
            continue;
        }
        let file_end = segment
            .vaddr
            .checked_add(segment.filesz)
            .ok_or_else(|| msg("load segment end overflows"))?;
        let inside = if len == 0 {
            va >= segment.vaddr && va <= file_end
        } else {
            va >= segment.vaddr && end <= file_end
        };
        if inside {
            return segment
                .offset
                .checked_add(va - segment.vaddr)
                .ok_or_else(|| msg("load segment offset overflows"));
        }
    }
    Err(msg(format!(
        "virtual address {va:#x} is not in a load segment"
    )))
}

pub(super) fn va_slice<'a>(
    data: &'a [u8],
    segments: &[Segment],
    va: u64,
    len: usize,
) -> Result<&'a [u8]> {
    let len_u = u64::try_from(len).map_err(|_| msg("virtual address range overflows"))?;
    let off = va_file(segments, va, len_u)?;
    at(data, off, len, "virtual address")
}

/// Bytes at `va` when they are in the file.
///
/// `Ok(None)` is only a place that lies entirely in `p_memsz` and entirely past `p_filesz`.
pub(super) fn place<'a>(
    data: &'a [u8],
    segments: &[Segment],
    va: u64,
    len: usize,
) -> Result<Option<&'a [u8]>> {
    if len == 0 {
        return Ok(Some(&[]));
    }
    let len_u = u64::try_from(len).map_err(|_| msg("relocation place overflows"))?;
    let end = va
        .checked_add(len_u)
        .ok_or_else(|| msg("relocation place overflows"))?;
    for segment in segments {
        if segment.kind != SegmentKind::Load || segment.memsz == 0 {
            continue;
        }
        let mem_end = segment
            .vaddr
            .checked_add(segment.memsz)
            .ok_or_else(|| msg("load segment end overflows"))?;
        if va < segment.vaddr || end > mem_end {
            continue;
        }
        return place_in_segment(data, segment, va, end, len);
    }
    Err(msg(format!(
        "relocation place {va:#x} is not in a load segment"
    )))
}

fn place_in_segment<'a>(
    data: &'a [u8],
    segment: &Segment,
    va: u64,
    end: u64,
    len: usize,
) -> Result<Option<&'a [u8]>> {
    let file_end = segment
        .vaddr
        .checked_add(segment.filesz)
        .ok_or_else(|| msg("load segment end overflows"))?;
    if va >= file_end {
        return Ok(None);
    }
    if end > file_end {
        return Err(msg(format!(
            "relocation place {va:#x} crosses file and bss"
        )));
    }
    let off = segment
        .offset
        .checked_add(va - segment.vaddr)
        .ok_or_else(|| msg("load segment offset overflows"))?;
    Ok(Some(at(data, off, len, "relocation place")?))
}
