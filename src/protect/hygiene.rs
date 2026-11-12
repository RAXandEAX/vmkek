//! Image hygiene for T4. The payload section name comes from the protect seed.
//! Foreign formats are rejected. Maps that describe virtualized code are sealed
//! with the same byte mask the loader already applies to recorded spans.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};

use super::payload;
use crate::error::{msg, Result};
use crate::pe::{self, PeImage};

const ARM: &[u16] = &[0x01c0, 0x01c2, 0x01c4, 0xaa64];
const I386: u16 = 0x014c;
const PE32: u16 = 0x010b;
const PE32_PLUS: u16 = 0x020b;
const PACKERS: &[&[u8]] = &[
    b"UPX0",
    b"UPX1",
    b"UPX2",
    b".UPX",
    b"UPX!",
    b".aspack",
    b".adata",
    b".nsp0",
    b".nsp1",
    b".vmp0",
    b".vmp1",
    b".themida",
    b"MPRESS1",
    b"MPRESS2",
    b".petite",
    b".pec2",
    b"FSG!",
];
const GUARD_TABLE: usize = 0x80;
const GUARD_COUNT: usize = 0x88;
const GUARD_NEED: usize = 0x90;

/// One sealed range. `rva` selects the mask byte the loader record stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Span {
    pub rva: u32,
    pub len: u32,
}

/// Eight-character section name. It changes with `seed` and is never `.vmkek`.
#[must_use]
pub fn section_name(seed: u64) -> String {
    let mut mixed = seed ^ 0xC3C3_3C3C_A5A5_5A5A;
    let mut name = String::with_capacity(8);
    name.push('.');
    for _ in 0..7 {
        mixed = mixed.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17);
        let letter = b'a' + ((mixed >> 40) as u8 % 26);
        name.push(letter as char);
    }
    name
}

/// Reject an ELF the pipeline does not prove: ARM, 32-bit x86, or UPX.
pub fn reject_elf(data: &[u8]) -> Result<()> {
    if data.len() < 20 {
        return Ok(());
    }
    let machine = u16::from_le_bytes([data[18], data[19]]);
    if machine == 40 || machine == 183 {
        return Err(msg("arm images are rejected"));
    }
    if data[4] == 1 || machine == 3 {
        return Err(msg("pe32 x86 images are rejected"));
    }
    if data.windows(4).any(|window| window == b"UPX!") {
        return Err(msg("foreign packer images are rejected"));
    }
    Ok(())
}

/// Reject CLR, PE32 x86, ARM, and an input that already has a foreign unpacker.
pub fn reject_pe(data: &[u8]) -> Result<()> {
    let Some(coff) = coff(data) else {
        return Ok(());
    };
    if ARM.contains(&coff.machine) {
        return Err(msg("arm images are rejected"));
    }
    if coff.machine == I386 || coff.magic == PE32 {
        return Err(msg("pe32 x86 images are rejected"));
    }
    if clr_directory(data, &coff) || clr_section(data, &coff) {
        return Err(msg("clr/.net images are rejected"));
    }
    if foreign_packer(data, &coff) {
        return Err(msg("foreign packer images are rejected"));
    }
    Ok(())
}

struct Coff {
    lfanew: usize,
    machine: u16,
    magic: u16,
}

fn coff(data: &[u8]) -> Option<Coff> {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return None;
    }
    let lfanew = u32::from_le_bytes(data.get(0x3c..0x40)?.try_into().ok()?) as usize;
    let machine = u16::from_le_bytes(data.get(lfanew + 4..lfanew + 6)?.try_into().ok()?);
    let magic = u16::from_le_bytes(data.get(lfanew + 24..lfanew + 26)?.try_into().ok()?);
    Some(Coff {
        lfanew,
        machine,
        magic,
    })
}

fn clr_directory(data: &[u8], coff: &Coff) -> bool {
    if coff.magic != PE32_PLUS {
        return false;
    }
    let opt = coff.lfanew + 24;
    let count = dir_count(data, opt);
    if count <= 14 {
        return false;
    }
    let at = opt + 112 + 14 * 8;
    data.get(at..at + 4)
        .is_some_and(|bytes| u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])) != 0)
}

fn dir_count(data: &[u8], opt: usize) -> usize {
    data.get(opt + 108..opt + 112)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])) as usize)
        .unwrap_or(0)
}

fn clr_section(data: &[u8], coff: &Coff) -> bool {
    section_names(data, coff)
        .iter()
        .any(|name| name.starts_with(b".cormeta"))
}

fn foreign_packer(data: &[u8], coff: &Coff) -> bool {
    if data.windows(4).any(|window| window == b"UPX!") {
        return true;
    }
    section_names(data, coff).iter().any(packer_name)
}

fn packer_name(name: &[u8; 8]) -> bool {
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    PACKERS.iter().any(|marker| name[..end] == **marker)
}

fn section_names(data: &[u8], coff: &Coff) -> Vec<[u8; 8]> {
    let Some(count) = data.get(coff.lfanew + 6..coff.lfanew + 8) else {
        return Vec::new();
    };
    let count = u16::from_le_bytes([count[0], count[1]]) as usize;
    let size = data
        .get(coff.lfanew + 20..coff.lfanew + 22)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
        .unwrap_or(0);
    let table = coff.lfanew.saturating_add(24).saturating_add(size);
    let mut names = Vec::new();
    for index in 0..count.min(96) {
        let at = table + index * 40;
        let Some(name) = data.get(at..at + 8) else {
            break;
        };
        let mut buf = [0u8; 8];
        buf.copy_from_slice(name);
        names.push(buf);
    }
    names
}

/// Constant pools, jump tables, RTTI names, and GFIDS referenced by `funcs`.
pub(crate) fn collect(file: &[u8], image: &PeImage, funcs: &[(u32, u32)]) -> Result<Vec<Span>> {
    let mut spans = rtti_spans(image);
    spans.extend(jump_tables(image, funcs));
    for func in funcs {
        spans.extend(pools(image, *func)?);
    }
    spans.extend(gfids(file, image));
    Ok(kept(image, spans))
}

/// `.pdata` / `.xdata` after the trampoline rewrite.
pub(crate) fn push_unwind(image: &PeImage, spans: &mut Vec<Span>) {
    for section in &image.sections {
        if section.name == ".pdata" || section.name == ".xdata" {
            push_fit(image, spans, section.rva, section.bytes.len() as u32);
        }
    }
    merge(spans);
}

pub(crate) fn extend_skips(skips: &[(u32, u32)], spans: &[Span]) -> Vec<(u32, u32)> {
    let mut out = skips.to_vec();
    for span in spans {
        out.push((span.rva, span.len));
    }
    out
}

/// Mask `spans` and return records the loader opens once, before the original entry.
pub(crate) fn seal(image: &mut PeImage, seed: u64, spans: &[Span]) -> Result<Vec<(u32, u32, u8)>> {
    let mut maps = Vec::new();
    for span in spans {
        if let Some(record) = seal_one(image, seed, *span)? {
            maps.push(record);
        }
    }
    Ok(maps)
}

fn seal_one(image: &mut PeImage, seed: u64, span: Span) -> Result<Option<(u32, u32, u8)>> {
    if span.len == 0 {
        return Ok(None);
    }
    let mut buf = pe::read_rva(image, span.rva, span.len as usize)?.to_vec();
    let key = payload::string_key(seed, span.rva as u8);
    payload::encrypt_span(&mut buf, key);
    pe::write_rva(image, span.rva, &buf)?;
    Ok(Some((span.rva, span.len, key)))
}

/// Invert [`seal`] on one range. The loader applies the same mask.
pub fn mask_span(bytes: &mut [u8], seed: u64, rva: u32) {
    let key = payload::string_key(seed, rva as u8);
    payload::encrypt_span(bytes, key);
}

/// Zero a debug directory that lived in the input sections. `emit` does not
/// copy that data-directory slot, so the body has to be cleared on the image.
pub(crate) fn drop_debug(image: &mut PeImage, file: &[u8]) {
    let Some(slot) = debug_slot(file) else {
        return;
    };
    let Some(head) = file.get(slot..slot + 8) else {
        return;
    };
    let rva = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    let size = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
    if rva == 0 || size == 0 || size > 4096 {
        return;
    }
    zero_image(image, rva, size);
    let Some(off) = rva_off(file, rva) else {
        return;
    };
    for (data_rva, _, len) in debug_entries(file, off, size) {
        if data_rva != 0 {
            zero_image(image, data_rva, len as u32);
        }
    }
}

fn zero_image(image: &mut PeImage, rva: u32, len: u32) {
    if len == 0 || pe::read_rva(image, rva, len as usize).is_err() {
        return;
    }
    let zeros = vec![0u8; len as usize];
    let _ = pe::write_rva(image, rva, &zeros);
}

/// Normalize the emitted PE headers. Input debug records are removed by `drop_debug`.
pub(crate) fn scrub_pe(bytes: &mut [u8], seed: u64) -> Result<()> {
    clear_rich(bytes)?;
    write_stamp(bytes, stamp(seed))?;
    if let Some(slot) = debug_slot(bytes) {
        bytes[slot..slot + 8].fill(0);
    }
    Ok(())
}

pub(crate) fn elf_spans(image: &crate::elf::ElfImage, funcs: &[(u32, u32)]) -> Vec<Span> {
    let mut spans = frame_spans(image);
    spans.extend(elf_rtti(image));
    spans.extend(elf_tables(image, funcs));
    spans.retain(|span| !over_got(image, *span));
    merge(&mut spans);
    spans
}

pub(crate) fn commit_elf(
    file: &mut [u8],
    image: &crate::elf::ElfImage,
    seed: u64,
    spans: &[Span],
) -> Result<Vec<(u32, u32, u8)>> {
    let mut maps = Vec::new();
    for span in spans {
        if let Some(record) = commit_span(file, image, seed, *span)? {
            maps.push(record);
        }
    }
    Ok(maps)
}

fn frame_spans(image: &crate::elf::ElfImage) -> Vec<Span> {
    let mut spans = Vec::new();
    for section in &image.sections {
        if is_elf_map(&section.name) {
            if let Some(span) = section_span(image, section) {
                spans.push(span);
            }
        }
    }
    spans
}

fn elf_rtti(image: &crate::elf::ElfImage) -> Vec<Span> {
    let mut spans = Vec::new();
    for section in &image.sections {
        let Some(span_base) = section_rva(image, section) else {
            continue;
        };
        mark_descriptors(&section.bytes, span_base, &mut spans);
    }
    let names = elf_names(image, &spans);
    for section in &image.sections {
        let Some(span_base) = section_rva(image, section) else {
            continue;
        };
        mark_copies(&section.bytes, span_base, &names, &mut spans);
    }
    spans
}

fn elf_names(image: &crate::elf::ElfImage, spans: &[Span]) -> Vec<String> {
    let mut names = Vec::new();
    for span in spans {
        let Some(bytes) = section_slice(image, span.rva, span.len) else {
            continue;
        };
        if let Some(name) = class_name(bytes) {
            if name.len() >= 4 && !names.iter().any(|item| item == &name) {
                names.push(name);
            }
        }
    }
    names
}

fn elf_tables(image: &crate::elf::ElfImage, funcs: &[(u32, u32)]) -> Vec<Span> {
    let pe = elf_as_pe(image);
    let mut spans = jump_tables(&pe, funcs);
    for section in &image.sections {
        if section.flags & 4 == 0 {
            continue;
        }
        let Some(rva) = section_rva(image, section) else {
            continue;
        };
        if let Ok(found) = pools(&pe, (rva, section.bytes.len() as u32)) {
            spans.extend(found);
        }
    }
    spans
}

fn elf_as_pe(image: &crate::elf::ElfImage) -> PeImage {
    PeImage {
        image_base: image.image_base,
        entry_rva: 0,
        sections: image
            .sections
            .iter()
            .filter(|section| kept_name(&section.name))
            .filter_map(|section| pe_section(image, section))
            .collect(),
        exports: Vec::new(),
        imports: Vec::new(),
        export_rva: 0,
        export_size: 0,
        import_rva: 0,
        import_size: 0,
        iat_rva: 0,
        iat_size: 0,
        exception_rva: 0,
        exception_size: 0,
        tls_rva: 0,
        tls_size: 0,
    }
}

fn kept_name(name: &crate::elf::ElfBytes) -> bool {
    !matches!(
        name.as_str(),
        Some(
            ".got"
                | ".got.plt"
                | ".plt"
                | ".dynamic"
                | ".dynsym"
                | ".dynstr"
                | ".hash"
                | ".gnu.hash"
                | ".interp"
                | ".shstrtab"
        )
    )
}

fn pe_section(image: &crate::elf::ElfImage, section: &crate::elf::Section) -> Option<pe::Section> {
    Some(pe::Section {
        name: section.name.as_str().unwrap_or("").to_string(),
        rva: section_rva(image, section)?,
        bytes: section.bytes.clone(),
        characteristics: 0,
    })
}

fn section_rva(image: &crate::elf::ElfImage, section: &crate::elf::Section) -> Option<u32> {
    let delta = section.addr.checked_sub(image.image_base)?;
    u32::try_from(delta).ok()
}

fn section_span(image: &crate::elf::ElfImage, section: &crate::elf::Section) -> Option<Span> {
    let len = u32::try_from(section.size.min(section.bytes.len() as u64)).ok()?;
    Some(Span {
        rva: section_rva(image, section)?,
        len,
    })
    .filter(|span| span.len > 0)
}

fn section_slice(image: &crate::elf::ElfImage, rva: u32, len: u32) -> Option<&[u8]> {
    image.sections.iter().find_map(|section| {
        let base = section_rva(image, section)?;
        let at = rva.checked_sub(base)? as usize;
        let end = at.checked_add(len as usize)?;
        section.bytes.get(at..end)
    })
}

fn commit_span(
    file: &mut [u8],
    image: &crate::elf::ElfImage,
    seed: u64,
    span: Span,
) -> Result<Option<(u32, u32, u8)>> {
    let (off, end) = file_span(file, image, span).unwrap_or((0, 0));
    if off >= end {
        return Ok(None);
    }
    let key = payload::string_key(seed, span.rva as u8);
    payload::encrypt_span(&mut file[off..end], key);
    let len = u32::try_from(end - off).unwrap_or(0);
    Ok((len > 0).then_some((span.rva, len, key)))
}

fn file_span(file: &[u8], image: &crate::elf::ElfImage, span: Span) -> Option<(usize, usize)> {
    let section = image.sections.iter().find(|section| {
        let Some(base) = section_rva(image, section) else {
            return false;
        };
        let end = base.saturating_add(section.bytes.len() as u32);
        span.rva >= base && span.rva < end
    })?;
    let base = section_rva(image, section)?;
    let off = usize::try_from(section.offset).ok()? + (span.rva - base) as usize;
    let room = section.bytes.len() - (span.rva - base) as usize;
    let len = (span.len as usize).min(room);
    let end = off.saturating_add(len).min(file.len());
    (off < end).then_some((off, end))
}

fn over_got(image: &crate::elf::ElfImage, span: Span) -> bool {
    let start = image.image_base.saturating_add(u64::from(span.rva));
    let end = start.saturating_add(u64::from(span.len));
    hits(image.got.addr, image.got.slots.len(), start, end)
        || hits(image.got.plt_addr, image.got.plt_slots.len(), start, end)
}

fn hits(addr: u64, slots: usize, start: u64, end: u64) -> bool {
    if addr == 0 || slots == 0 {
        return false;
    }
    let stop = addr.saturating_add((slots as u64).saturating_mul(8));
    start < stop && addr < end
}

fn is_elf_map(name: &crate::elf::ElfBytes) -> bool {
    name == ".eh_frame" || name == ".eh_frame_hdr" || name == ".gcc_except_table"
}

fn marker_len(bytes: &[u8]) -> usize {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    end.min(96).min(bytes.len())
}

fn stamp(seed: u64) -> u32 {
    let mixed = seed.wrapping_mul(0x9E37_79B9).rotate_left(7) ^ 0xA5A5_5A5A;
    let value = mixed as u32;
    if value == 0 {
        1
    } else {
        value
    }
}

fn clear_rich(bytes: &mut [u8]) -> Result<()> {
    if bytes.len() < 0x40 {
        return Ok(());
    }
    let lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
    if lfanew > bytes.len() || lfanew <= 0x40 {
        return Ok(());
    }
    bytes[0x40..lfanew].fill(0);
    Ok(())
}

fn write_stamp(bytes: &mut [u8], value: u32) -> Result<()> {
    if bytes.len() < 0x40 {
        return Ok(());
    }
    let lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
    let at = lfanew.saturating_add(8);
    if at + 4 <= bytes.len() {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

fn debug_slot(bytes: &[u8]) -> Option<usize> {
    let coff = coff(bytes)?;
    if coff.magic != PE32_PLUS || dir_count(bytes, coff.lfanew + 24) <= 6 {
        return None;
    }
    let at = coff.lfanew + 24 + 112 + 6 * 8;
    (at + 8 <= bytes.len()).then_some(at)
}

fn debug_entries(bytes: &[u8], off: usize, size: u32) -> Vec<(u32, u32, usize)> {
    let mut out = Vec::new();
    let mut at = off;
    let end = off.saturating_add(size as usize).min(bytes.len());
    while at + 28 <= end && out.len() < 16 {
        let size_of = u32::from_le_bytes(bytes[at + 16..at + 20].try_into().unwrap_or([0; 4]));
        let data_rva = u32::from_le_bytes(bytes[at + 20..at + 24].try_into().unwrap_or([0; 4]));
        let raw = u32::from_le_bytes(bytes[at + 24..at + 28].try_into().unwrap_or([0; 4]));
        let len = (size_of as usize).min(4096);
        if len > 0 && (data_rva != 0 || raw != 0) {
            out.push((data_rva, raw, len));
        }
        at += 28;
    }
    out
}

fn rva_off(bytes: &[u8], rva: u32) -> Option<usize> {
    let image = pe::parse(bytes).ok()?;
    let section = image.sections.iter().find(|item| {
        let end = item.rva as usize + item.bytes.len();
        rva >= item.rva && (rva as usize) < end
    })?;
    let base = pe::section_file_offset(bytes, &section.name).ok()?;
    Some(base + (rva - section.rva) as usize)
}

fn rtti_spans(image: &PeImage) -> Vec<Span> {
    let mut spans = Vec::new();
    for section in &image.sections {
        mark_descriptors(&section.bytes, section.rva, &mut spans);
    }
    let names = class_names(image, &spans);
    for section in &image.sections {
        mark_copies(&section.bytes, section.rva, &names, &mut spans);
    }
    spans
}

fn mark_descriptors(bytes: &[u8], base: u32, spans: &mut Vec<Span>) {
    for marker in [b".?AV".as_slice(), b".?AU".as_slice(), b"_ZTS".as_slice()] {
        let mut from = 0usize;
        while let Some(rel) = bytes[from..]
            .windows(marker.len())
            .position(|w| w == marker)
        {
            let at = from + rel;
            let len = descriptor_len(&bytes[at..], marker);
            push_raw(spans, base.saturating_add(at as u32), len as u32);
            from = at + len;
        }
    }
}

fn descriptor_len(bytes: &[u8], marker: &[u8]) -> usize {
    if marker == b"_ZTS" {
        return marker_len(bytes);
    }
    bytes
        .windows(2)
        .position(|window| window == b"@@")
        .map(|at| (at + 2).min(bytes.len()))
        .unwrap_or_else(|| marker_len(bytes))
}

fn class_names(image: &PeImage, spans: &[Span]) -> Vec<String> {
    let mut names = Vec::new();
    for span in spans {
        let Ok(bytes) = pe::read_rva(image, span.rva, span.len as usize) else {
            continue;
        };
        if let Some(name) = class_name(bytes) {
            if name.len() >= 4 && !names.iter().any(|item| item == &name) {
                names.push(name);
            }
        }
    }
    names
}

fn class_name(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let rest = text
        .strip_prefix(".?AV")
        .or_else(|| text.strip_prefix(".?AU"))?;
    let end = rest.find("@@")?;
    Some(rest[..end].to_string())
}

fn mark_copies(bytes: &[u8], base: u32, names: &[String], spans: &mut Vec<Span>) {
    for name in names {
        mark_exact(bytes, base, name.as_bytes(), spans);
        mark_exact(bytes, base, &utf16(name), spans);
    }
}

fn mark_exact(bytes: &[u8], base: u32, needle: &[u8], spans: &mut Vec<Span>) {
    if needle.len() < 4 {
        return;
    }
    let mut from = 0usize;
    while let Some(rel) = bytes[from..]
        .windows(needle.len())
        .position(|w| w == needle)
    {
        let at = from + rel;
        push_raw(spans, base.saturating_add(at as u32), needle.len() as u32);
        from = at + needle.len();
    }
}

fn utf16(name: &str) -> Vec<u8> {
    name.encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

fn jump_tables(image: &PeImage, funcs: &[(u32, u32)]) -> Vec<Span> {
    let mut spans = Vec::new();
    for section in &image.sections {
        let mut index = 0usize;
        while index + 16 <= section.bytes.len() {
            let rva = section.rva.saturating_add(index as u32);
            let rel = rel_run(&section.bytes[index..], funcs);
            let len = run_len(&section.bytes[index..], funcs).or(rel);
            if let Some(len) = len {
                if !overlaps_any(rva, len, funcs) {
                    push_raw(&mut spans, rva, len);
                }
                index += len as usize;
            } else {
                index += 4;
            }
        }
    }
    spans
}

fn rel_run(bytes: &[u8], funcs: &[(u32, u32)]) -> Option<u32> {
    let mut count = 0u32;
    let mut owner: Option<(u32, u32)> = None;
    while count < 64 {
        let off = count as usize * 4;
        let raw = bytes.get(off..off + 4)?;
        let value = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let Some(func) = same_owner(value, funcs, owner) else {
            break;
        };
        owner = Some(func);
        count += 1;
    }
    (count >= 4).then_some(count * 4)
}

fn same_owner(value: u32, funcs: &[(u32, u32)], owner: Option<(u32, u32)>) -> Option<(u32, u32)> {
    if value == 0 {
        return None;
    }
    let func = funcs.iter().copied().find(|(start, size)| {
        value < *size && in_range(start.wrapping_add(value), *start, *size)
    })?;
    owner.filter(|prev| *prev != func).is_none().then_some(func)
}

fn run_len(bytes: &[u8], funcs: &[(u32, u32)]) -> Option<u32> {
    let mut count = 0u32;
    while count < 64 {
        let off = count as usize * 4;
        let raw = bytes.get(off..off + 4)?;
        let value = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if !funcs
            .iter()
            .any(|(start, size)| in_range(value, *start, *size))
        {
            break;
        }
        count += 1;
    }
    if count >= 4 {
        Some(count * 4)
    } else {
        None
    }
}

fn pools(image: &PeImage, func: (u32, u32)) -> Result<Vec<Span>> {
    let (rva, size) = func;
    if size == 0 {
        return Ok(Vec::new());
    }
    let bytes = pe::read_rva(image, rva, size as usize)?;
    let start = image.image_base + u64::from(rva);
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let end = start + u64::from(size);
    let mut spans = Vec::new();
    while decoder.can_decode() && decoder.ip() < end {
        let insn = decoder.decode();
        if insn.is_invalid() {
            break;
        }
        push_pool(image, &insn, func, &mut spans);
    }
    Ok(spans)
}

fn push_pool(image: &PeImage, insn: &Instruction, func: (u32, u32), spans: &mut Vec<Span>) {
    if insn.mnemonic() != Mnemonic::Mov || !insn.is_ip_rel_memory_operand() {
        return;
    }
    if insn.op0_kind() != OpKind::Register || insn.op1_kind() != OpKind::Memory {
        return;
    }
    let len = insn.memory_size().size() as u32;
    if len < 4 {
        return;
    }
    let target = insn.ip_rel_memory_address();
    let Ok(rva) = u32::try_from(target.wrapping_sub(image.image_base)) else {
        return;
    };
    if in_range(rva, func.0, func.1) || in_directory(image, rva, len) {
        return;
    }
    push_raw(spans, rva, len);
}

fn gfids(file: &[u8], image: &PeImage) -> Vec<Span> {
    let Some(coff) = coff(file) else {
        return Vec::new();
    };
    if coff.magic != PE32_PLUS || dir_count(file, coff.lfanew + 24) <= 10 {
        return Vec::new();
    }
    let at = coff.lfanew + 24 + 112 + 10 * 8;
    let Some(raw) = file.get(at..at + 8) else {
        return Vec::new();
    };
    let rva = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let size = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    if rva == 0 || size < GUARD_NEED as u32 {
        return Vec::new();
    }
    guard_table(image, rva).into_iter().collect()
}

fn guard_table(image: &PeImage, rva: u32) -> Option<Span> {
    let cfg = pe::read_rva(image, rva, GUARD_NEED).ok()?;
    let table = u64::from_le_bytes(cfg.get(GUARD_TABLE..GUARD_TABLE + 8)?.try_into().ok()?);
    let count = u64::from_le_bytes(cfg.get(GUARD_COUNT..GUARD_COUNT + 8)?.try_into().ok()?);
    if table == 0 || count == 0 || count > 4096 {
        return None;
    }
    let table_rva = u32::try_from(table.checked_sub(image.image_base)?).ok()?;
    let len = u32::try_from(count.checked_mul(4)?).ok()?;
    if in_directory(image, table_rva, len) {
        return None;
    }
    Some(Span {
        rva: table_rva,
        len,
    })
}

fn kept(image: &PeImage, mut spans: Vec<Span>) -> Vec<Span> {
    spans.retain(|span| fits(image, *span) && !in_directory(image, span.rva, span.len));
    merge(&mut spans);
    spans
}

fn push_fit(image: &PeImage, spans: &mut Vec<Span>, rva: u32, len: u32) {
    push_raw(spans, rva, len);
    spans.retain(|span| fits(image, *span));
    merge(spans);
}

fn push_raw(spans: &mut Vec<Span>, rva: u32, len: u32) {
    if len > 0 {
        spans.push(Span { rva, len });
    }
}

fn fits(image: &PeImage, span: Span) -> bool {
    image.sections.iter().any(|section| {
        let end = span.rva as usize + span.len as usize;
        span.rva >= section.rva && end <= section.rva as usize + section.bytes.len()
    })
}

fn merge(spans: &mut Vec<Span>) {
    if spans.is_empty() {
        return;
    }
    spans.sort_by_key(|span| (span.rva, span.len));
    let mut folded = Vec::with_capacity(spans.len());
    let mut cur = spans[0];
    for span in spans.iter().skip(1).copied() {
        let end = cur.rva.saturating_add(cur.len);
        if span.rva <= end {
            let span_end = span.rva.saturating_add(span.len);
            cur.len = span_end.max(end).saturating_sub(cur.rva);
        } else {
            folded.push(cur);
            cur = span;
        }
    }
    folded.push(cur);
    *spans = folded;
}

fn overlaps_any(rva: u32, len: u32, funcs: &[(u32, u32)]) -> bool {
    let end = rva.saturating_add(len);
    funcs.iter().any(|(start, size)| {
        let stop = start.saturating_add(*size);
        rva < stop && *start < end
    })
}

fn in_range(rva: u32, start: u32, size: u32) -> bool {
    rva >= start && rva < start.saturating_add(size)
}

fn in_directory(image: &PeImage, rva: u32, len: u32) -> bool {
    let end = rva.saturating_add(len);
    [
        (image.iat_rva, image.iat_size),
        (image.import_rva, image.import_size),
        (image.export_rva, image.export_size),
        (image.tls_rva, image.tls_size),
        (image.exception_rva, image.exception_size),
    ]
    .into_iter()
    .any(|(start, size)| {
        if start == 0 || size == 0 {
            return false;
        }
        let stop = start.saturating_add(size);
        rva < stop && start < end
    })
}

#[cfg(test)]
mod hygiene_review_tests {
    use super::*;

    #[test]
    fn pe_header_cleanup_preserves_application_section_bytes() {
        let built = crate::sample::build().unwrap();
        let mut bytes = built.bytes;
        let rdata = pe::section_file_offset(&bytes, ".rdata").unwrap();
        let application_data = b"RSDS is an application format";
        bytes[rdata..rdata + application_data.len()].copy_from_slice(application_data);
        scrub_pe(&mut bytes, 42).unwrap();
        assert_eq!(
            &bytes[rdata..rdata + application_data.len()],
            application_data
        );
    }
}
