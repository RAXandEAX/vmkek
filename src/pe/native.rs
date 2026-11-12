//! PE metadata validated and retained by the native Windows backend.

use super::native_cfg::GuardConfig;
use super::native_reloc::Relocations;
use super::*;

const COFF_RELOCS_STRIPPED: u16 = 0x0001;
const IMAGE_BASE_ALIGN: u64 = 0x10000;
const DIRECTORY_RESOURCE: usize = 2;
const DIRECTORY_CERTIFICATE: usize = 4;
const DIRECTORY_RELOCATION: usize = 5;
const DIRECTORY_DEBUG: usize = 6;
const DIRECTORY_LOAD_CONFIG: usize = 10;
const DIRECTORY_DELAY_IMPORT: usize = 13;

const DEBUG_ENTRY_SIZE: usize = 28;
const DEBUG_TYPE_DLL_CHARACTERISTICS: u32 = 20;
const CET_SHADOW_STACK: u32 = 1;
const CET_SECTION_NAME: &str = ".cetmeta";

pub(crate) struct NativeSecurity {
    pub(crate) resign_required: bool,
    load_config: (u32, u32),
    resource: (u32, u32),
    debug_spans: Vec<(u32, u32)>,
    cet: bool,
    relocations: Option<Relocations>,
    guard: Option<GuardConfig>,
}

pub(crate) fn native_security(
    data: &[u8],
    image: &PeImage,
    kind: ImageKind,
    allow_dynamic: bool,
) -> Result<NativeSecurity> {
    check_no_writable_code(image)?;
    if image.image_base == 0
        || !image.image_base.is_multiple_of(IMAGE_BASE_ALIGN)
        || image
            .image_base
            .checked_add(u64::from(MAX_IMAGE_SPAN))
            .is_none()
    {
        return Err(msg(
            "native PE image base must be nonzero, 64-KiB aligned, and in range",
        ));
    }
    let opt = optional_header(data)?;
    let dir = |index| checked_directory(data, opt, index);
    let relocations = read_relocations(image, kind, dir(DIRECTORY_RELOCATION)?, allow_dynamic)?;
    let guarded = kind.dll_characteristics & DLL_GUARD_CF != 0;
    if guarded && relocations.is_none() {
        return Err(msg("CFG image requires a relocatable native PE backend"));
    }
    if dir(DIRECTORY_DELAY_IMPORT)? != (0, 0) {
        return Err(msg("native PE backend does not support delay imports"));
    }
    let load_config = dir(DIRECTORY_LOAD_CONFIG)?;
    let configuration = read_load_config(image, load_config, guarded, relocations.as_ref())?;
    let resource = dir(DIRECTORY_RESOURCE)?;
    if resource != (0, 0) {
        containing_data_section(image, resource.0, resource.1)?;
    }
    let debug = dir(DIRECTORY_DEBUG)?;
    let (cet, debug_spans) = debug_metadata(data, image, debug)?;
    check_debug_overlap(
        data,
        image,
        opt,
        &configuration,
        relocations.as_ref(),
        &debug_spans,
    )?;
    if let Some(relocations) = &relocations {
        relocations.reject_rewrite((image.entry_rva, 64))?;
    }
    check_rewrite_layout(
        data,
        image,
        opt,
        3 + usize::from(cet)
            + usize::from(relocations.is_some())
            + usize::from(configuration.guard.is_some()),
    )?;
    let resign_required = check_certificate(data, dir(DIRECTORY_CERTIFICATE)?)?;
    Ok(NativeSecurity {
        resign_required,
        load_config,
        resource,
        debug_spans,
        cet,
        relocations,
        guard: configuration.guard,
    })
}

fn checked_directory(data: &[u8], opt: usize, index: usize) -> Result<(u32, u32)> {
    match data_directory(data, opt - 24, opt, index)? {
        (0, 0) => Ok((0, 0)),
        (0, _) | (_, 0) => Err(msg(format!("incomplete PE directory {index}"))),
        dir => Ok(dir),
    }
}

fn read_relocations(
    image: &PeImage,
    kind: ImageKind,
    range: (u32, u32),
    allow_dynamic: bool,
) -> Result<Option<Relocations>> {
    let dynamic = kind.dll_characteristics & DLL_DYNAMIC_BASE != 0;
    let high_entropy = kind.dll_characteristics & DLL_HIGH_ENTROPY_VA != 0;
    if !dynamic && !high_entropy && range == (0, 0) {
        return Ok(None);
    }
    if !allow_dynamic {
        return Err(msg(
            "native PE backend requires a fixed image without base relocations",
        ));
    }
    if !dynamic || kind.characteristics & COFF_RELOCS_STRIPPED != 0 {
        return Err(msg("inconsistent PE ASLR flags and base relocations"));
    }
    let relocations = Relocations::parse(image, range)?;
    relocations.reject_rewrite(range)?;
    Ok(Some(relocations))
}

struct LoadConfig {
    cookie: Option<u32>,
    guard: Option<GuardConfig>,
}

fn read_load_config(
    image: &PeImage,
    (rva, len): (u32, u32),
    guarded: bool,
    relocations: Option<&Relocations>,
) -> Result<LoadConfig> {
    if (rva, len) == (0, 0) {
        if guarded {
            return Err(msg("missing PE Guard CF load configuration"));
        }
        return Ok(LoadConfig {
            cookie: None,
            guard: None,
        });
    }
    let layout = load_config_bytes(image, rva, len)?;
    let guard = if guarded {
        let relocations =
            relocations.ok_or_else(|| msg("CFG load configuration requires base relocations"))?;
        Some(GuardConfig::read(image, rva, layout, relocations)?)
    } else {
        check_unguarded_config(layout)?;
        None
    };
    let cookie = security_cookie(image, rd_u64(layout, 88)?)?;
    if let (Some(_), Some(relocations)) = (cookie, relocations) {
        if !relocations.contains(rva + 88) {
            return Err(msg("PE security cookie pointer lacks a DIR64 relocation"));
        }
    }
    Ok(LoadConfig { cookie, guard })
}

fn load_config_bytes(image: &PeImage, rva: u32, len: u32) -> Result<&[u8]> {
    containing_data_section(image, rva, len)?;
    let layout = read_rva(image, rva, len as usize)?;
    let size = rd_u32(layout, 0)? as usize;
    if size < 112
        || size > layout.len()
        || (size > 144 && size < 148)
        || layout[size..].iter().any(|&byte| byte != 0)
    {
        return Err(msg("unsupported PE load configuration size"));
    }
    if layout[40..48]
        .iter()
        .chain(&layout[80..88])
        .chain(&layout[96..112])
        .any(|&byte| byte != 0)
    {
        return Err(msg("unsupported reserved PE load configuration fields"));
    }
    Ok(&layout[..size])
}

fn check_unguarded_config(layout: &[u8]) -> Result<()> {
    let size = layout.len();
    if layout[112..size.min(144)]
        .iter()
        .chain(layout.get(148..).unwrap_or(&[]))
        .any(|&byte| byte != 0)
        || (size >= 148 && rd_u32(layout, 144)? & !0x0800 != 0)
    {
        return Err(msg(
            "PE guard configuration cannot be rewritten without CFG",
        ));
    }
    Ok(())
}

fn security_cookie(image: &PeImage, va: u64) -> Result<Option<u32>> {
    if va == 0 {
        return Ok(None);
    }
    let rva = va
        .checked_sub(image.image_base)
        .and_then(|offset| u32::try_from(offset).ok())
        .ok_or_else(|| msg("PE security cookie VA is outside the image"))?;
    let section = containing_data_section(image, rva, 8)?;
    if !rva.is_multiple_of(8) || section.characteristics & SCN_WRITE == 0 {
        return Err(msg("PE security cookie is not aligned writable data"));
    }
    Ok(Some(rva))
}

fn debug_metadata(
    data: &[u8],
    image: &PeImage,
    (rva, len): (u32, u32),
) -> Result<(bool, Vec<(u32, u32)>)> {
    if (rva, len) == (0, 0) {
        return Ok((false, Vec::new()));
    }
    let mut spans = Vec::new();
    add_debug_span(data, image, &mut spans, rva, len)?;
    let records = read_rva(image, rva, len as usize)?;
    if len > 4096 || !records.len().is_multiple_of(DEBUG_ENTRY_SIZE) {
        return Err(msg("invalid PE debug directory size"));
    }
    let mut found = None;
    for entry in records.chunks_exact(DEBUG_ENTRY_SIZE) {
        let length = rd_u32(entry, 16)?;
        let address = rd_u32(entry, 20)?;
        let offset = rd_u32(entry, 24)? as usize;
        if length != 0 {
            if offset == 0 {
                return Err(msg("missing PE debug record file offset"));
            }
            rd(data, offset, length as usize)?;
            if address != 0 {
                let mapped = add_debug_span(data, image, &mut spans, address, length)?;
                if mapped != offset {
                    return Err(msg("inconsistent PE mapped debug record offset"));
                }
            }
        }
        if rd_u32(entry, 12)? == DEBUG_TYPE_DLL_CHARACTERISTICS
            && found.replace(cet_flags(data, offset, length)?).is_some()
        {
            return Err(msg("duplicate PE extended DLL characteristics"));
        }
    }
    Ok((found.unwrap_or(0) == CET_SHADOW_STACK, spans))
}

fn add_debug_span(
    data: &[u8],
    image: &PeImage,
    spans: &mut Vec<(u32, u32)>,
    rva: u32,
    len: u32,
) -> Result<usize> {
    let section = containing_data_section(image, rva, len)?;
    if section.characteristics & SCN_WRITE != 0 {
        return Err(msg("PE debug metadata is in a writable section"));
    }
    let (_, count, table) = pe_table(data)?;
    let delta = rva - section.rva;
    for index in 0..count {
        let offset = table + index * 40;
        if rd_u32(data, offset + 12)? != section.rva {
            continue;
        }
        let raw_len = rd_u32(data, offset + 16)?;
        if delta.checked_add(len).is_none_or(|end| end > raw_len) {
            return Err(msg("PE debug range exceeds file-backed section data"));
        }
        if spans.iter().any(|span| overlaps(*span, (rva, len))) {
            return Err(msg("overlapping PE debug metadata"));
        }
        spans.push((rva, len));
        let raw = rd_u32(data, offset + 20)?;
        return Ok(raw as usize + delta as usize);
    }
    Err(msg("PE debug section is missing"))
}

fn check_debug_overlap(
    data: &[u8],
    image: &PeImage,
    opt: usize,
    configuration: &LoadConfig,
    relocations: Option<&Relocations>,
    spans: &[(u32, u32)],
) -> Result<()> {
    if spans.is_empty() {
        return Ok(());
    }
    let mut reserved = vec![
        (image.import_rva, image.import_size),
        (image.iat_rva, image.iat_size),
    ];
    for index in [0, DIRECTORY_RESOURCE, 3, 9, DIRECTORY_LOAD_CONFIG] {
        reserved.push(checked_directory(data, opt, index)?);
    }
    if let Some(cookie) = configuration.cookie {
        reserved.push((cookie, 8));
    }
    if let Some(guard) = &configuration.guard {
        reserved.extend(&guard.data);
    }
    if let Some(relocations) = relocations {
        reserved.push(relocations.input_range());
        for &span in spans {
            relocations.reject_rewrite(span)?;
        }
    }
    for import in &image.imports {
        reserved.push((import.iat_rva, 8));
        reserved.push((import.dll_rva, (import.dll.len() + 1) as u32));
        if let Some(hint) = import.name_rva.checked_sub(2) {
            reserved.push((hint, (import.name.len() + 3) as u32));
        }
    }
    for (_, _, unwind) in unwind_entries(image)? {
        reserved.push((unwind, unwind_info_prefix(image, unwind)?));
    }
    if spans
        .iter()
        .any(|span| reserved.iter().any(|other| overlaps(*span, *other)))
    {
        return Err(msg("PE debug metadata overlaps OS-owned image data"));
    }
    Ok(())
}

fn unwind_info_prefix(image: &PeImage, rva: u32) -> Result<u32> {
    let header = read_rva(image, rva, 4)?;
    let version = header[0] & 7;
    let flags = header[0] >> 3;
    if !matches!(version, 1 | 2) || flags > 4 {
        return Err(msg("invalid PE unwind info header"));
    }
    let code_bytes = u32::from(header[2]).next_multiple_of(2) * 2;
    let tail = if flags & 4 != 0 {
        12
    } else if flags & 3 != 0 {
        4
    } else {
        0
    };
    let size = 4 + code_bytes + tail;
    containing_data_section(image, rva, size)?;
    if flags & 3 != 0 {
        let info = read_rva(image, rva, size as usize)?;
        let handler = rd_u32(info, (size - 4) as usize)?;
        let end = handler
            .checked_add(1)
            .ok_or_else(|| msg("unwind handler RVA overflows"))?;
        super::native_unwind::check_code_range(image, handler, end)?;
    }
    Ok(size)
}

pub(super) fn overlaps((a, n): (u32, u32), (b, m): (u32, u32)) -> bool {
    n != 0
        && m != 0
        && u64::from(a) < u64::from(b) + u64::from(m)
        && u64::from(b) < u64::from(a) + u64::from(n)
}

fn cet_flags(data: &[u8], offset: usize, len: u32) -> Result<u32> {
    if offset == 0 || (len != 2 && len != 4) {
        return Err(msg("unsupported PE extended DLL characteristics record"));
    }
    let mut raw = [0; 4];
    raw[..len as usize].copy_from_slice(rd(data, offset, len as usize)?);
    let flags = u32::from_le_bytes(raw);
    if flags & !CET_SHADOW_STACK != 0 {
        return Err(msg("unsupported PE forward-CFI or extended CET flags"));
    }
    Ok(flags)
}

pub(super) fn containing_data_section(image: &PeImage, rva: u32, size: u32) -> Result<&Section> {
    let end = rva
        .checked_add(size)
        .ok_or_else(|| msg("PE data range overflows"))?;
    image
        .sections
        .iter()
        .find(|section| {
            !executable(section)
                && rva >= section.rva
                && u64::from(end) <= u64::from(section.rva) + section.bytes.len() as u64
        })
        .ok_or_else(|| msg("PE metadata must be in a mapped non-executable section"))
}

impl NativeSecurity {
    pub(crate) fn is_relocatable(&self) -> bool {
        self.relocations.is_some()
    }

    pub(crate) fn is_cfg_guarded(&self) -> bool {
        self.guard.is_some()
    }

    pub(crate) fn check_rewrites(
        &self,
        virtualized: impl IntoIterator<Item = (u32, u32)>,
        mutated: impl IntoIterator<Item = (u32, u32)>,
    ) -> Result<()> {
        for selection in virtualized {
            if let Some(relocations) = &self.relocations {
                relocations.reject_rewrite(selection)?;
            }
            if let Some(guard) = &self.guard {
                guard.validate_rewrite(selection)?;
            }
        }
        for selection in mutated {
            if self.is_cfg_guarded() {
                return Err(msg("native CFG profile does not support mutation"));
            }
            if let Some(relocations) = &self.relocations {
                relocations.reject_rewrite(selection)?;
            }
        }
        Ok(())
    }

    pub(crate) fn drop_debug(&self, image: &mut PeImage) -> Result<()> {
        for &(rva, len) in &self.debug_spans {
            write_rva(image, rva, &vec![0; len as usize])?;
        }
        Ok(())
    }

    pub(crate) fn append_metadata(&self, image: &mut PeImage) -> Result<()> {
        if let Some(guard) = &self.guard {
            guard.publish(image)?;
        }
        if let Some(relocations) = &self.relocations {
            relocations.publish(image)?;
        }
        if !self.cet {
            return Ok(());
        }
        if image
            .sections
            .iter()
            .any(|section| section.name == CET_SECTION_NAME)
        {
            return Err(msg(
                "PE CET metadata section name collides with an existing section",
            ));
        }
        let rva = image_span(image)?;
        let mut bytes = vec![0; DEBUG_ENTRY_SIZE + 4];
        put32(&mut bytes, 12, DEBUG_TYPE_DLL_CHARACTERISTICS);
        put32(&mut bytes, 16, 4);
        put32(&mut bytes, 20, rva + DEBUG_ENTRY_SIZE as u32);
        put32(&mut bytes, DEBUG_ENTRY_SIZE, CET_SHADOW_STACK);
        image.sections.push(Section {
            name: CET_SECTION_NAME.into(),
            rva,
            bytes,
            characteristics: CH_RDATA,
        });
        Ok(())
    }

    pub(crate) fn restore_directories(&self, bytes: &mut [u8]) -> Result<()> {
        let (pe, _, _) = pe_table(bytes)?;
        let characteristics = pe + COFF_CHARACTERISTICS;
        let mut flags = rd_u16(bytes, characteristics)?;
        if self.is_relocatable() {
            flags &= !COFF_RELOCS_STRIPPED;
            Relocations::restore_directory(bytes)?;
        } else {
            flags |= COFF_RELOCS_STRIPPED;
        }
        write_u16(bytes, characteristics, flags)?;
        put_dir(
            bytes,
            DIRECTORY_LOAD_CONFIG,
            self.load_config.0,
            self.load_config.1,
        );
        put_dir(bytes, DIRECTORY_RESOURCE, self.resource.0, self.resource.1);
        if self.cet {
            let (_, count, table) = pe_table(bytes)?;
            let last = count
                .checked_sub(1)
                .ok_or_else(|| msg("PE CET metadata section is missing"))?;
            let section = table + last * 40;
            if rd(bytes, section, 8)? != CET_SECTION_NAME.as_bytes() {
                return Err(msg("PE CET metadata section is missing"));
            }
            let rva = rd_u32(bytes, section + 12)?;
            let raw = rd_u32(bytes, section + 20)?;
            rd(bytes, raw as usize, DEBUG_ENTRY_SIZE + 4)?;
            put32(bytes, raw as usize + 24, raw + DEBUG_ENTRY_SIZE as u32);
            put_dir(bytes, DIRECTORY_DEBUG, rva, DEBUG_ENTRY_SIZE as u32);
        }
        Ok(())
    }
}

pub(super) fn unwind_entries(image: &PeImage) -> Result<Vec<(u32, u32, u32)>> {
    let rva = image.exception_rva;
    let size = image.exception_size;
    match (rva, size) {
        (0, 0) => return Ok(Vec::new()),
        (0, _) | (_, 0) => return Err(msg("incomplete PE exception directory")),
        _ => {}
    }
    containing_data_section(image, rva, size)?;
    let entries = read_rva(image, rva, size as usize)?;
    if !entries.len().is_multiple_of(12) {
        return Err(msg("truncated PE runtime function entry"));
    }
    let mut out = Vec::new();
    let mut last_end = 0;
    for entry in entries.chunks_exact(12) {
        let begin = rd_u32(entry, 0)?;
        let end = rd_u32(entry, 4)?;
        let unwind = rd_u32(entry, 8)?;
        if begin >= end || begin < last_end || unwind == 0 || !unwind.is_multiple_of(4) {
            return Err(msg("invalid or unsupported PE runtime function entry"));
        }
        super::native_unwind::check_code_range(image, begin, end)?;
        unwind_info_prefix(image, unwind)?;
        last_end = end;
        out.push((begin, end, unwind));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_dynamic_pe_preserves_gfids_and_adds_only_generated_tls_fixups() {
        let (image, input) = guarded_image();
        let kind = image_kind(&input).unwrap();
        assert!(native_security(&input, &image, kind, false).is_err());
        let security = native_security(&input, &image, kind, true).unwrap();
        assert!(security.is_cfg_guarded());
        assert!(security.is_relocatable());
        assert!(security.check_rewrites([(0x1000, 8)], []).is_ok());
        assert!(security.check_rewrites([(0x1000, 9)], []).is_err());
        assert!(security.check_rewrites([], [(0x1010, 8)]).is_err());

        let mut image = image;
        add_tls(&mut image);
        security.append_metadata(&mut image).unwrap();
        let mut output = emit(&image).unwrap();
        set_image_kind(&mut output, &kind).unwrap();
        security.restore_directories(&mut output).unwrap();
        let opt = optional_header(&output).unwrap();
        let directory = checked_directory(&output, opt, DIRECTORY_RELOCATION).unwrap();
        let parsed = parse(&output).unwrap();
        let relocations = Relocations::parse(&parsed, directory).unwrap();
        for site in [
            0x2670, 0x2678, 0x2680, 0x2700, 0x2708, 0x5000, 0x5008, 0x5010, 0x5018, 0x5050,
        ] {
            assert!(relocations.contains(site), "{site:#x}");
        }
        assert_eq!(
            checked_directory(&output, opt, DIRECTORY_LOAD_CONFIG).unwrap(),
            (0x2600, 0x94)
        );
        let config = read_rva(&parsed, 0x2600, 0x94).unwrap();
        let table = (rd_u64(config, 0x80).unwrap() - parsed.image_base) as u32;
        assert_eq!(rd_u64(config, 0x88).unwrap(), 4);
        assert_eq!(
            read_rva(&parsed, table, 16).unwrap(),
            &[0, 0x10, 0, 0, 8, 0x10, 0, 0, 0, 0x60, 0, 0, 0x10, 0x60, 0, 0],
        );
        assert_eq!(
            read_rva(&parsed, 0x2720, 8).unwrap(),
            read_rva(&image, 0x2720, 8).unwrap()
        );
        assert_eq!(
            image_kind(&output).unwrap().dll_characteristics & DLL_GUARD_CF,
            DLL_GUARD_CF
        );
    }

    fn guarded_image() -> (PeImage, Vec<u8>) {
        let mut image = parse(&crate::sample::build().unwrap().bytes).unwrap();
        let mut config = [0; 0x94];
        put32(&mut config, 0, 0x94);
        put64(&mut config, 0x70, image.image_base + 0x2700);
        put64(&mut config, 0x78, image.image_base + 0x2708);
        put64(&mut config, 0x80, image.image_base + 0x2720);
        put64(&mut config, 0x88, 2);
        put32(&mut config, 0x90, 0x500);
        write_rva(&mut image, 0x2600, &config).unwrap();
        let mut slots = [0; 16];
        put64(&mut slots, 0, image.image_base + 0x1000);
        put64(&mut slots, 8, image.image_base + 0x1008);
        write_rva(&mut image, 0x2700, &slots).unwrap();
        write_rva(&mut image, 0x2720, &[0, 0x10, 0, 0, 8, 0x10, 0, 0]).unwrap();
        let mut relocations = vec![0; 20];
        put32(&mut relocations, 0, 0x2000);
        put32(&mut relocations, 4, 20);
        for (slot, fixup) in relocations[8..]
            .chunks_exact_mut(2)
            .zip([0xa670_u16, 0xa678, 0xa680, 0xa700, 0xa708, 0])
        {
            slot.copy_from_slice(&fixup.to_le_bytes());
        }
        image.sections.push(Section {
            name: ".reloc".into(),
            rva: 0x4000,
            bytes: relocations,
            characteristics: CH_RDATA,
        });
        let mut input = emit(&image).unwrap();
        put_dir(&mut input, DIRECTORY_RELOCATION, 0x4000, 20);
        put_dir(&mut input, DIRECTORY_LOAD_CONFIG, 0x2600, 0x94);
        let mut kind = image_kind(&input).unwrap();
        kind.dll_characteristics |= DLL_DYNAMIC_BASE | DLL_GUARD_CF;
        set_image_kind(&mut input, &kind).unwrap();
        (image, input)
    }

    fn add_tls(image: &mut PeImage) {
        let mut bytes = vec![0; 0x60];
        for (field, target) in [
            (0, 0x5040),
            (8, 0x5048),
            (16, 0x5048),
            (24, 0x5050),
            (0x50, 0x6010),
        ] {
            put64(&mut bytes, field, image.image_base + target);
        }
        image.sections.push(Section {
            name: ".tls".into(),
            rva: 0x5000,
            bytes,
            characteristics: CH_DATA,
        });
        image.tls_rva = 0x5000;
        image.tls_size = 40;
        image.sections.push(Section {
            name: ".loader".into(),
            rva: 0x6000,
            bytes: vec![0x90; 0x20],
            characteristics: CH_TEXT,
        });
        image.entry_rva = 0x6000;
    }
}
