use std::{
    io::{self, Read, Seek, SeekFrom},
    ops::Range,
    time::Instant,
};

use vmkek_protocol::detection::ImageRule;

const MAX_SECTIONS: usize = 96;
const MAX_OPTIONAL_BYTES: usize = 4096;
const MAX_RELOCATION_BYTES: u32 = 4 * 1024 * 1024;
const MAX_SCOPE_READ_BYTES: u64 = MAX_RELOCATION_BYTES as u64 + 128 * 1024;
const RX_FLAGS: u32 = 0x6000_0000;
const WRITE_FLAG: u32 = 0x8000_0000;

struct Section {
    backed: Range<u32>,
    file_offset: u32,
    flags: u32,
}

pub(super) struct Layout {
    pub(super) image_size: u32,
    pub(super) preferred_base: u64,
    pub(super) header_size: usize,
    pub(super) image_base_offset: usize,
    pub(super) allowed: Vec<bool>,
}

pub(super) fn validate(
    file: &mut (impl Read + Seek),
    file_size: u64,
    rules: &[ImageRule],
    deadline: Instant,
) -> io::Result<(Layout, u64)> {
    let mut reader = Reader {
        file,
        file_size,
        deadline,
        bytes: 0,
    };
    let dos = reader.read::<64>(0)?;
    if &dos[..2] != b"MZ" {
        return Err(invalid());
    }
    let pe_offset = u64::from(u32_at(&dos, 60));
    let coff = reader.read::<24>(pe_offset)?;
    let count = usize::from(u16_at(&coff, 6));
    let optional_size = usize::from(u16_at(&coff, 20));
    if &coff[..4] != b"PE\0\0"
        || u16_at(&coff, 4) != super::AMD64
        || !(1..=MAX_SECTIONS).contains(&count)
        || !(112..=MAX_OPTIONAL_BYTES).contains(&optional_size)
    {
        return Err(invalid());
    }
    let optional_offset = pe_offset + 24;
    let mut optional = vec![0; optional_size];
    reader.read_into(optional_offset, &mut optional)?;
    if u16_at(&optional, 0) != 0x20b {
        return Err(invalid());
    }
    let image_size = u32_at(&optional, 56);
    let preferred_base = u64::from_le_bytes(optional[24..32].try_into().unwrap());
    let section_offset = optional_offset + optional_size as u64;
    let header_size = u64::from(u32_at(&optional, 60));
    if image_size == 0
        || header_size > u64::from(super::MAX_HEADER_BYTES)
        || header_size > u64::from(image_size)
        || section_offset + (count as u64 * 40) > header_size
    {
        return Err(invalid());
    }
    let mut sections = Vec::with_capacity(count);
    for index in 0..count as u64 {
        let data = reader.read::<40>(section_offset + 40 * index)?;
        let start = u32_at(&data, 12);
        let len = u32_at(&data, 8).min(u32_at(&data, 16));
        let end = start
            .checked_add(len)
            .filter(|end| *end <= image_size)
            .ok_or_else(invalid)?;
        let file_offset = u32_at(&data, 20);
        if u64::from(file_offset) + u64::from(len) > file_size {
            return Err(invalid());
        }
        if len != 0 {
            sections.push(Section {
                backed: start..end,
                file_offset,
                flags: u32_at(&data, 36),
            });
        }
    }
    sections.sort_unstable_by_key(|section| section.backed.start);
    if sections
        .windows(2)
        .any(|pair| overlaps(&pair[0].backed, &pair[1].backed))
    {
        return Err(invalid());
    }
    let dirs = usize::try_from(u32_at(&optional, 108)).map_err(|_| invalid())?;
    if dirs > (optional_size - 112) / 8 {
        return Err(invalid());
    }
    let directory = |index: usize| -> io::Result<Option<Range<u32>>> {
        if index >= dirs {
            return Ok(None);
        }
        let offset = 112 + index * 8;
        let start = u32_at(&optional, offset);
        let len = u32_at(&optional, offset + 4);
        match (start, len) {
            (0, 0) => Ok(None),
            (0, _) | (_, 0) => Err(invalid()),
            _ => start
                .checked_add(len)
                .filter(|end| *end <= image_size)
                .map(|end| Some(start..end))
                .ok_or_else(invalid),
        }
    };
    let imports = directory(1)?;
    let relocations = directory(5)?;
    let tls = directory(9)?;
    let load_config = directory(10)?;
    let iat = directory(12)?;
    let delay_imports = directory(13)?;
    let exclusions = [&imports, &relocations, &tls, &load_config, &iat];
    let ranges: Vec<_> = rules
        .iter()
        .map(|r| r.code_rva..r.code_rva + r.code_len)
        .collect();
    let mut allowed: Vec<_> = ranges
        .iter()
        .map(|range| {
            delay_imports.is_none()
                && (imports.is_none() || iat.is_some())
                && !exclusions
                    .iter()
                    .filter_map(|item| item.as_ref())
                    .any(|item| overlaps(range, item))
                && sections.iter().any(|section| {
                    contains(&section.backed, range)
                        && section.flags & (RX_FLAGS | WRITE_FLAG) == RX_FLAGS
                })
        })
        .collect();
    if let (Some(imports), Some(iat)) = (&imports, &iat) {
        validate_imports(&mut reader, &sections, imports, iat)?;
    }
    if let Some(tls) = &tls {
        let data = read_directory(&mut reader, &sections, tls, 40)?;
        exclude_pointer(
            &data,
            16,
            4,
            preferred_base,
            image_size,
            &ranges,
            &mut allowed,
        )?;
    }
    if let Some(load_config) = &load_config {
        let prefix = read_directory(&mut reader, &sections, load_config, 4)?;
        let size = u32_at(&prefix, 0) as usize;
        if !(4..=4096).contains(&size) {
            return Err(invalid());
        }
        let data = read_directory(&mut reader, &sections, load_config, size)?;
        // Dynamic relocations, hotpatching and hybrid images have additional
        // loader-write contracts this observer does not interpret.
        for (offset, len) in [
            (192, 16),
            (224, 8),
            (240, 8),
            (320, data.len().saturating_sub(320)),
        ] {
            if data
                .get(offset..)
                .is_some_and(|tail| tail.iter().take(len).any(|byte| *byte != 0))
            {
                return Err(invalid());
            }
        }
        for offset in [88, 112, 120, 216, 232, 280, 288, 296, 304, 312] {
            if data.len() > offset {
                exclude_pointer(
                    &data,
                    offset,
                    8,
                    preferred_base,
                    image_size,
                    &ranges,
                    &mut allowed,
                )?;
            }
        }
    }
    if let Some(relocations) = relocations {
        check_relocations(&mut reader, &sections, relocations, &ranges, &mut allowed)?;
    }
    Ok((
        Layout {
            image_size,
            preferred_base,
            header_size: header_size as usize,
            image_base_offset: optional_offset as usize + 24,
            allowed,
        },
        reader.bytes,
    ))
}

fn file_offset(sections: &[Section], rva: u32, len: u32) -> io::Result<u64> {
    let end = rva.checked_add(len).ok_or_else(invalid)?;
    let section = sections
        .iter()
        .find(|s| contains(&s.backed, &(rva..end)))
        .ok_or_else(invalid)?;
    Ok(u64::from(section.file_offset) + u64::from(rva - section.backed.start))
}

fn read_directory(
    reader: &mut Reader<'_, impl Read + Seek>,
    sections: &[Section],
    range: &Range<u32>,
    len: usize,
) -> io::Result<Vec<u8>> {
    if len > (range.end - range.start) as usize {
        return Err(invalid());
    }
    let mut data = vec![0; len];
    reader.read_into(file_offset(sections, range.start, len as u32)?, &mut data)?;
    Ok(data)
}

fn exclude_pointer(
    data: &[u8],
    offset: usize,
    len: u32,
    preferred: u64,
    size: u32,
    ranges: &[Range<u32>],
    allowed: &mut [bool],
) -> io::Result<()> {
    let bytes = data.get(offset..offset + 8).ok_or_else(invalid)?;
    let address = u64::from_le_bytes(bytes.try_into().unwrap());
    if address == 0 {
        return Ok(());
    }
    let rva = address
        .checked_sub(preferred)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(invalid)?;
    let end = rva
        .checked_add(len)
        .filter(|end| *end <= size)
        .ok_or_else(invalid)?;
    exclude(&(rva..end), ranges, allowed);
    Ok(())
}

fn validate_imports(
    reader: &mut Reader<'_, impl Read + Seek>,
    sections: &[Section],
    imports: &Range<u32>,
    iat: &Range<u32>,
) -> io::Result<()> {
    let descriptors = ((imports.end - imports.start) / 20).min(512);
    for index in 0..descriptors {
        let offset = file_offset(sections, imports.start + index * 20, 20)?;
        let data = reader.read::<20>(offset)?;
        if data == [0; 20] {
            return Ok(());
        }
        let first = u32_at(&data, 16);
        if !iat.contains(&first) || first % 8 != 0 {
            return Err(invalid());
        }
        let lookup = u32_at(&data, 0);
        let lookup = if lookup == 0 { first } else { lookup };
        let mut terminated = false;
        for offset in (0..(iat.end - first) / 8).map(|index| index * 8) {
            let rva = lookup.checked_add(offset).ok_or_else(invalid)?;
            if reader.read::<8>(file_offset(sections, rva, 8)?)? == [0; 8] {
                terminated = true;
                break;
            }
        }
        if !terminated {
            return Err(invalid());
        }
    }
    Err(invalid())
}

fn exclude(target: &Range<u32>, ranges: &[Range<u32>], allowed: &mut [bool]) {
    for (range, eligible) in ranges.iter().zip(allowed) {
        if overlaps(range, target) {
            *eligible = false;
        }
    }
}

fn check_relocations(
    reader: &mut Reader<'_, impl Read + Seek>,
    sections: &[Section],
    relocations: Range<u32>,
    ranges: &[Range<u32>],
    allowed: &mut [bool],
) -> io::Result<()> {
    let len = relocations.end - relocations.start;
    if len > MAX_RELOCATION_BYTES {
        return Err(invalid());
    }
    let section = sections
        .iter()
        .find(|s| contains(&s.backed, &relocations))
        .ok_or_else(invalid)?;
    let mut file_offset =
        u64::from(section.file_offset) + u64::from(relocations.start - section.backed.start);
    let end = file_offset + u64::from(len);
    let mut entries = [0u8; 8192];
    while file_offset < end {
        if end - file_offset < 8 {
            return Err(invalid());
        }
        let header = reader.read::<8>(file_offset)?;
        let page = u32_at(&header, 0);
        let size = u32_at(&header, 4);
        if page & 0xfff != 0
            || size < 8
            || size % 4 != 0
            || u64::from(size) > end - file_offset
            || (size - 8) as usize > entries.len()
        {
            return Err(invalid());
        }
        let data = &mut entries[..(size - 8) as usize];
        reader.read_into(file_offset + 8, data)?;
        for entry in data.chunks_exact(2) {
            let value = u16_at(entry, 0);
            match value >> 12 {
                0 => continue,
                10 => {}
                _ => return Err(invalid()),
            }
            let start = page
                .checked_add(u32::from(value & 0xfff))
                .ok_or_else(invalid)?;
            let end = start.checked_add(8).ok_or_else(invalid)?;
            exclude(&(start..end), ranges, allowed);
        }
        file_offset += u64::from(size);
    }
    Ok(())
}

fn contains(outer: &Range<u32>, inner: &Range<u32>) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

fn overlaps(a: &Range<u32>, b: &Range<u32>) -> bool {
    a.start < b.end && b.start < a.end
}

struct Reader<'a, F> {
    file: &'a mut F,
    file_size: u64,
    deadline: Instant,
    bytes: u64,
}

impl<F: Read + Seek> Reader<'_, F> {
    fn read<const N: usize>(&mut self, offset: u64) -> io::Result<[u8; N]> {
        let mut bytes = [0; N];
        self.read_into(offset, &mut bytes)?;
        Ok(bytes)
    }

    fn read_into(&mut self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        super::within_deadline(self.deadline)?;
        let count = bytes.len() as u64;
        if self.bytes + count > MAX_SCOPE_READ_BYTES {
            return Err(invalid());
        }
        if offset
            .checked_add(count)
            .is_none_or(|end| end > self.file_size)
        {
            return Err(invalid());
        }
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(bytes)?;
        self.bytes += count;
        super::within_deadline(self.deadline)
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unsupported or invalid PE scope",
    )
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
