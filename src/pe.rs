use crate::error::{msg, Result};

mod native;
mod native_cfg;
mod native_reloc;
mod native_unwind;
pub(crate) use native::{native_security, NativeSecurity};
pub(crate) use native_unwind::NativeUnwind;

pub const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
const FILE_ALIGN: u32 = 0x200;
pub(crate) const SECTION_ALIGN: u32 = 0x1000;
const SCN_CODE: u32 = 0x0000_0020;
const SCN_INIT: u32 = 0x0000_0040;
const SCN_EXEC: u32 = 0x2000_0000;
const SCN_READ: u32 = 0x4000_0000;
const SCN_WRITE: u32 = 0x8000_0000;

pub const CH_TEXT: u32 = SCN_CODE | SCN_EXEC | SCN_READ;
pub const CH_DATA: u32 = SCN_INIT | SCN_READ | SCN_WRITE;
pub const CH_RDATA: u32 = SCN_INIT | SCN_READ;
/// `IMAGE_SUBSYSTEM_NATIVE`. A driver image (`.sys`) uses this subsystem.
pub const SUBSYSTEM_NATIVE: u16 = 1;
/// `IMAGE_SUBSYSTEM_WINDOWS_CUI`. [`emit`] writes this; [`set_image_kind`] restores the input.
pub const SUBSYSTEM_WINDOWS_CUI: u16 = 3;
const COFF_CHARACTERISTICS: usize = 22;
const OPT_SUBSYSTEM: usize = 68;
const OPT_DLL_CHARACTERISTICS: usize = 70;
/// `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA`. Needs a base-relocation directory.
const DLL_HIGH_ENTROPY_VA: u16 = 0x0020;
/// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`. Needs a base-relocation directory.
const DLL_DYNAMIC_BASE: u16 = 0x0040;
/// `IMAGE_DLLCHARACTERISTICS_GUARD_CF`. Needs the load-config directory.
const DLL_GUARD_CF: u16 = 0x4000;
/// Bits [`emit`] cannot honestly keep: the directories they name are not written,
/// and the VM image uses absolute addresses.
const DLL_NEEDS_DIRECTORY: u16 = DLL_HIGH_ENTROPY_VA | DLL_DYNAMIC_BASE | DLL_GUARD_CF;
const MAX_SECTION_BYTES: usize = 4 * 1024 * 1024;
const MAX_IMAGE_SPAN: u32 = 32 * 1024 * 1024;
const MAX_SECTIONS: usize = 96;
const MIN_OPTIONAL: usize = 112 + 13 * 8;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    pub bytes: Vec<u8>,
    pub characteristics: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    pub rva: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    pub dll: String,
    pub name: String,
    pub iat_rva: u32,
    pub name_rva: u32,
    pub dll_rva: u32,
}

#[derive(Clone, Debug)]
pub struct PeImage {
    pub image_base: u64,
    pub entry_rva: u32,
    pub sections: Vec<Section>,
    pub exports: Vec<Export>,
    pub imports: Vec<Import>,
    pub export_rva: u32,
    pub export_size: u32,
    pub import_rva: u32,
    pub import_size: u32,
    pub iat_rva: u32,
    pub iat_size: u32,
    /// Exception directory (`.pdata`). Zero when the image has no unwind data.
    pub exception_rva: u32,
    pub exception_size: u32,
    /// TLS directory. Zero when the image has no TLS callbacks.
    pub tls_rva: u32,
    pub tls_size: u32,
}

fn align(value: u32, boundary: u32) -> u32 {
    value.div_ceil(boundary) * boundary
}

pub fn emit(image: &PeImage) -> Result<Vec<u8>> {
    if image.sections.is_empty() {
        return Err(msg("pe has no sections"));
    }
    let (headers, layout, raw) = section_layout(image);
    let mut out = vec![0u8; raw as usize];
    emit_headers(&mut out, image, headers)?;
    emit_section_bytes(&mut out, image, &layout);
    Ok(out)
}

fn header_bytes(sections: usize) -> u32 {
    align((0x188 + sections * 40) as u32, FILE_ALIGN)
}

fn section_layout(image: &PeImage) -> (u32, Vec<(u32, u32)>, u32) {
    let headers = header_bytes(image.sections.len());
    let mut raw = headers;
    let mut layout = Vec::new();
    for section in &image.sections {
        let size = align(section.bytes.len() as u32, FILE_ALIGN).max(FILE_ALIGN);
        layout.push((raw, size));
        raw += size;
    }
    (headers, layout, raw)
}

fn emit_headers(out: &mut [u8], image: &PeImage, headers: u32) -> Result<()> {
    out[0] = b'M';
    out[1] = b'Z';
    out[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    out[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(out, 0x84, 0x8664);
    put16(out, 0x86, image.sections.len() as u16);
    put16(out, 0x94, 0x00f0);
    put16(out, 0x96, 0x0022);
    put16(out, 0x98, 0x020b);
    put16(out, 0x9a, 14);
    put32(out, 0xa8, image.entry_rva);
    put32(out, 0xac, image.sections[0].rva);
    put64(out, 0xb0, image.image_base);
    put32(out, 0xb8, SECTION_ALIGN);
    put32(out, 0xbc, FILE_ALIGN);
    put16(out, 0xc0, 6);
    put16(out, 0xc8, 6);
    put32(out, 0xd0, image_span(image)?);
    put32(out, 0xd4, headers);
    put16(out, 0xdc, 3);
    put16(out, 0xde, 0x0100);
    put64(out, 0xe0, 0x100000);
    put64(out, 0xe8, 0x1000);
    put64(out, 0xf0, 0x100000);
    put64(out, 0xf8, 0x1000);
    put32(out, 0x104, 16);
    emit_directories(out, image);
    Ok(())
}

fn image_span(image: &PeImage) -> Result<u32> {
    let mut image_end = 0u32;
    for section in &image.sections {
        let end = section
            .rva
            .checked_add(section.bytes.len() as u32)
            .ok_or_else(|| msg("section rva overflows"))?;
        image_end = image_end.max(end);
    }
    Ok(align(image_end, SECTION_ALIGN))
}

fn emit_directories(out: &mut [u8], image: &PeImage) {
    put_dir(out, 0, image.export_rva, image.export_size);
    put_dir(out, 1, image.import_rva, image.import_size);
    put_dir(out, 3, image.exception_rva, image.exception_size);
    put_dir(out, 9, image.tls_rva, image.tls_size);
    put_dir(out, 12, image.iat_rva, image.iat_size);
}

fn emit_section_bytes(out: &mut [u8], image: &PeImage, layout: &[(u32, u32)]) {
    for (index, section) in image.sections.iter().enumerate() {
        let off = 0x188 + index * 40;
        let mut name = [0u8; 8];
        let bytes = section.name.as_bytes();
        name[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
        out[off..off + 8].copy_from_slice(&name);
        let (raw_ptr, raw_size) = layout[index];
        put32(out, off + 8, section.bytes.len() as u32);
        put32(out, off + 12, section.rva);
        put32(out, off + 16, raw_size);
        put32(out, off + 20, raw_ptr);
        put32(out, off + 36, section.characteristics);
        out[raw_ptr as usize..raw_ptr as usize + section.bytes.len()]
            .copy_from_slice(&section.bytes);
    }
}

fn put_dir(out: &mut [u8], index: usize, rva: u32, size: u32) {
    let off = 0x108 + index * 8;
    put32(out, off, rva);
    put32(out, off + 4, size);
}

fn put16(out: &mut [u8], off: usize, value: u16) {
    out[off..off + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(out: &mut [u8], off: usize, value: u32) {
    out[off..off + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(out: &mut [u8], off: usize, value: u64) {
    out[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn rd(data: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    let end = off.checked_add(len).ok_or_else(|| msg("pe truncated"))?;
    data.get(off..end).ok_or_else(|| msg("pe truncated"))
}

fn rd_u16(data: &[u8], off: usize) -> Result<u16> {
    let bytes = rd(data, off, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn rd_u32(data: &[u8], off: usize) -> Result<u32> {
    let bytes = rd(data, off, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn rd_u64(data: &[u8], off: usize) -> Result<u64> {
    let bytes = rd(data, off, 8)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

struct SecFile {
    name: String,
    raw: usize,
}

fn pe_table(data: &[u8]) -> Result<(usize, usize, usize)> {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return Err(msg("not a PE image"));
    }
    let lfanew = rd_u32(data, 0x3c)? as usize;
    if lfanew > 1024 * 1024 {
        return Err(msg("e_lfanew is out of range"));
    }
    if rd(data, lfanew, 4)? != b"PE\0\0" {
        return Err(msg("missing pe signature"));
    }
    let count = rd_u16(data, lfanew + 6)? as usize;
    if count > MAX_SECTIONS {
        return Err(msg("too many sections"));
    }
    let optional = rd_u16(data, lfanew + 20)? as usize;
    if optional < MIN_OPTIONAL {
        return Err(msg("optional header is too small"));
    }
    let table = lfanew
        .checked_add(24)
        .and_then(|off| off.checked_add(optional))
        .ok_or_else(|| msg("pe truncated"))?;
    let bytes = count
        .checked_mul(40)
        .ok_or_else(|| msg("section table is too large"))?;
    if rd(data, table, bytes).is_err() && count > 0 {
        return Err(msg("section header is outside the file"));
    }
    Ok((lfanew, count, table))
}

fn section_files(data: &[u8]) -> Result<Vec<SecFile>> {
    let (_lfanew, count, table) = pe_table(data)?;
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let off = table + index * 40;
        let name = String::from_utf8_lossy(rd(data, off, 8)?)
            .trim_end_matches('\0')
            .to_string();
        let raw = rd_u32(data, off + 20)? as usize;
        sections.push(SecFile { name, raw });
    }
    Ok(sections)
}

fn data_directory(data: &[u8], lfanew: usize, opt: usize, index: usize) -> Result<(u32, u32)> {
    let directories = rd_u32(data, opt + 108)? as usize;
    if index >= directories {
        return Ok((0, 0));
    }
    let off = opt + 112 + index * 8;
    if off + 8 > opt + rd_u16(data, lfanew + 20)? as usize {
        return Err(msg("data directory is outside the optional header"));
    }
    Ok((rd_u32(data, off)?, rd_u32(data, off + 4)?))
}

fn read_section(data: &[u8], off: usize) -> Result<Section> {
    let name = String::from_utf8_lossy(rd(data, off, 8)?)
        .trim_end_matches('\0')
        .to_string();
    let virtual_size = rd_u32(data, off + 8)? as usize;
    let rva = rd_u32(data, off + 12)?;
    let raw_size = rd_u32(data, off + 16)? as usize;
    let raw_ptr = rd_u32(data, off + 20)? as usize;
    let characteristics = rd_u32(data, off + 36)?;
    let take = if virtual_size == 0 {
        raw_size
    } else {
        virtual_size
    };
    if take > MAX_SECTION_BYTES {
        return Err(msg("section virtual size is too large"));
    }
    let end = rva
        .checked_add(take as u32)
        .ok_or_else(|| msg("section rva overflows"))?;
    if end > MAX_IMAGE_SPAN {
        return Err(msg("section extends past the mapped image limit"));
    }
    let available = section_bytes(data, raw_ptr, raw_size)?;
    let mut bytes = vec![0u8; take];
    let copy = take.min(available.len());
    bytes[..copy].copy_from_slice(&available[..copy]);
    Ok(Section {
        name,
        rva,
        bytes,
        characteristics,
    })
}

fn section_bytes(data: &[u8], raw_ptr: usize, raw_size: usize) -> Result<&[u8]> {
    if raw_size == 0 {
        return Ok(&[]);
    }
    let raw_end = raw_ptr
        .checked_add(raw_size)
        .ok_or_else(|| msg("section raw data is outside the file"))?;
    if raw_end > data.len() {
        return Err(msg("section raw data is outside the file"));
    }
    Ok(&data[raw_ptr..raw_end])
}

pub fn section_file_offset(file: &[u8], name: &str) -> Result<usize> {
    section_files(file)?
        .into_iter()
        .find(|section| section.name == name)
        .map(|section| section.raw)
        .ok_or_else(|| msg(format!("section {name} is missing")))
}

/// COFF characteristics and the optional-header subsystem. [`emit`] does not
/// store these on [`PeImage`]; callers that must keep a driver image native
/// read them before emit and write them back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageKind {
    pub characteristics: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
}

/// Read the file identity [`emit`] would otherwise replace.
pub fn image_kind(data: &[u8]) -> Result<ImageKind> {
    let opt = optional_header(data)?;
    Ok(ImageKind {
        characteristics: rd_u16(data, opt - 24 + COFF_CHARACTERISTICS)?,
        subsystem: rd_u16(data, opt + OPT_SUBSYSTEM)?,
        dll_characteristics: rd_u16(data, opt + OPT_DLL_CHARACTERISTICS)?,
    })
}

/// Validate PE mitigations the legacy emitter would otherwise drop. Returns
/// whether rewriting discards a certificate table and requires re-signing.
pub(crate) fn check_rewrite_security(
    data: &[u8],
    image: &PeImage,
    kind: ImageKind,
) -> Result<bool> {
    check_no_writable_code(image)?;
    if kind.dll_characteristics & DLL_GUARD_CF != 0 {
        return Err(msg(
            "CFG image cannot be rewritten without preserving its load configuration",
        ));
    }
    let opt = optional_header(data)?;
    check_rewrite_layout(data, image, opt, 2)?;
    if has_guard_configuration(data, image, opt)? {
        return Err(msg(
            "PE guard configuration cannot be rewritten by this backend",
        ));
    }
    let (debug, debug_len) = data_directory(data, opt - 24, opt, 6)?;
    if debug != 0 && debug_len != 0 && extended_cfi(data, image, debug, debug_len)? {
        return Err(msg(
            "CET/forward-CFI image cannot be rewritten by this backend",
        ));
    }
    check_certificate(data, data_directory(data, opt - 24, opt, 4)?)
}

fn check_no_writable_code(image: &PeImage) -> Result<()> {
    if image
        .sections
        .iter()
        .any(|section| section.characteristics & (SCN_EXEC | SCN_WRITE) == SCN_EXEC | SCN_WRITE)
    {
        return Err(msg("PE has a writable executable section"));
    }
    Ok(())
}

// The Certificate Table address is a file offset, unlike other directories.
fn check_certificate(data: &[u8], (cert, cert_len): (u32, u32)) -> Result<bool> {
    match (cert, cert_len) {
        (0, 0) => Ok(false),
        (0, _) | (_, 0) => Err(msg("incomplete PE certificate table")),
        (off, len) => {
            rd(data, off as usize, len as usize)?;
            Ok(true)
        }
    }
}

fn check_rewrite_layout(data: &[u8], image: &PeImage, opt: usize, extra: usize) -> Result<()> {
    const OPT_SECTION_ALIGNMENT: usize = 32;
    let count = image.sections.len() + extra;
    let headers = header_bytes(count);
    if rd_u32(data, opt + OPT_SECTION_ALIGNMENT)? != SECTION_ALIGN
        || count > MAX_SECTIONS
        || image
            .sections
            .iter()
            .any(|section| !section.rva.is_multiple_of(SECTION_ALIGN) || section.rva < headers)
    {
        return Err(msg(
            "PE sections cannot be rewritten with page-aligned permissions",
        ));
    }
    Ok(())
}

fn has_guard_configuration(data: &[u8], image: &PeImage, opt: usize) -> Result<bool> {
    const GUARD_FLAGS: usize = 0x90;
    const GUARD_END: u32 = (GUARD_FLAGS + 4) as u32;
    const SECURITY_COOKIE_UNUSED: u32 = 0x0800;
    let (rva, len) = data_directory(data, opt - 24, opt, 10)?;
    match (rva, len) {
        (0, 0) => return Ok(false),
        (0, _) | (_, 0) => return Err(msg("incomplete PE load configuration")),
        _ => {}
    }
    let layout = read_rva(image, rva, len as usize)?;
    let declared = rd_u32(layout, 0)?;
    if declared > len {
        return Err(msg("truncated PE load configuration"));
    }
    if declared < GUARD_END {
        return Ok(false);
    }
    let flags = rd_u32(layout, GUARD_FLAGS)?;
    Ok(flags & !SECURITY_COOKIE_UNUSED != 0)
}

fn extended_cfi(data: &[u8], image: &PeImage, rva: u32, len: u32) -> Result<bool> {
    const EX_DLL_CHARACTERISTICS: u32 = 20;
    const CET_OR_FORWARD_CFI: u16 = 0x007f;
    let directory = read_rva(image, rva, len as usize)?;
    if !directory.len().is_multiple_of(28) {
        return Err(msg("invalid PE debug directory size"));
    }
    for entry in directory.chunks_exact(28) {
        if rd_u32(entry, 12)? != EX_DLL_CHARACTERISTICS {
            continue;
        }
        if rd_u32(entry, 16)? < 2 {
            return Err(msg("truncated extended DLL characteristics"));
        }
        let address = rd_u32(entry, 20)?;
        let flags = if address == 0 {
            rd_u16(data, rd_u32(entry, 24)? as usize)?
        } else {
            rd_u16(read_rva(image, address, 2)?, 0)?
        };
        if flags & CET_OR_FORWARD_CFI != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Drop DLL-characteristic bits whose directory [`emit`] does not write.
///
/// A protected image keeps the subsystem and the COFF characteristics, including
/// the DLL bit of a `.sys`. It does not keep `DYNAMIC_BASE`, `HIGH_ENTROPY_VA`,
/// or `GUARD_CF`: there is no relocation directory and no load-config directory,
/// and the VM addresses are absolute.
#[must_use]
pub fn without_unbacked_dll_bits(kind: ImageKind) -> ImageKind {
    ImageKind {
        dll_characteristics: kind.dll_characteristics & !DLL_NEEDS_DIRECTORY,
        ..kind
    }
}

/// Restore [`image_kind`] after [`emit`]. Does not change the entry point.
pub fn set_image_kind(data: &mut [u8], kind: &ImageKind) -> Result<()> {
    let opt = optional_header(data)?;
    write_u16(data, opt - 24 + COFF_CHARACTERISTICS, kind.characteristics)?;
    write_u16(data, opt + OPT_SUBSYSTEM, kind.subsystem)?;
    write_u16(
        data,
        opt + OPT_DLL_CHARACTERISTICS,
        kind.dll_characteristics,
    )
}

fn optional_header(data: &[u8]) -> Result<usize> {
    let (lfanew, _, _) = pe_table(data)?;
    let opt = lfanew + 24;
    if rd_u16(data, opt)? != 0x20b {
        return Err(msg("only pe32+ images are supported"));
    }
    Ok(opt)
}

fn write_u16(data: &mut [u8], off: usize, value: u16) -> Result<()> {
    let end = off.checked_add(2).ok_or_else(|| msg("pe truncated"))?;
    data.get_mut(off..end)
        .ok_or_else(|| msg("pe truncated"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn check_section_layout(data: &[u8], table: usize, count: usize) -> Result<()> {
    let mut spans = Vec::with_capacity(count);
    for index in 0..count {
        let off = table + index * 40;
        let virtual_len = rd_u32(data, off + 8)?;
        let start = rd_u32(data, off + 12)?;
        let raw_len = rd_u32(data, off + 16)?;
        let len = if virtual_len == 0 {
            raw_len
        } else {
            virtual_len
        };
        if len == 0 {
            continue;
        }
        let end = start
            .checked_add(len)
            .ok_or_else(|| msg("section rva overflows"))?;
        spans.push((start, end));
    }
    check_virtual_spans(&mut spans)
}

pub(crate) fn check_final_layout(image: &PeImage) -> Result<()> {
    let mut spans = Vec::with_capacity(image.sections.len());
    for section in &image.sections {
        if section.bytes.len() > MAX_SECTION_BYTES {
            return Err(msg("section virtual size is too large"));
        }
        if section.bytes.is_empty() {
            continue;
        }
        let end = section
            .rva
            .checked_add(section.bytes.len() as u32)
            .ok_or_else(|| msg("section rva overflows"))?;
        if end > MAX_IMAGE_SPAN {
            return Err(msg("section extends past the mapped image limit"));
        }
        spans.push((section.rva, end));
    }
    check_virtual_spans(&mut spans)
}

fn check_virtual_spans(spans: &mut [(u32, u32)]) -> Result<()> {
    spans.sort_unstable();
    if spans.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(msg("PE virtual sections overlap"));
    }
    Ok(())
}

pub fn parse(data: &[u8]) -> Result<PeImage> {
    if data.len() < 0x200 {
        return Err(msg("not a PE image"));
    }
    let (lfanew, sections_n, sec_off) = pe_table(data)?;
    if rd_u16(data, lfanew + 4)? != 0x8664 {
        return Err(msg("only pe32+ x86-64 is supported"));
    }
    let opt = lfanew + 24;
    if rd_u16(data, opt)? != 0x20b {
        return Err(msg("only pe32+ images are supported"));
    }
    let entry = rd_u32(data, opt + 16)?;
    let image_base = rd_u64(data, opt + 24)?;
    let (export_rva, export_size) = data_directory(data, lfanew, opt, 0)?;
    let (import_rva, import_size) = data_directory(data, lfanew, opt, 1)?;
    let (exception_rva, exception_size) = data_directory(data, lfanew, opt, 3)?;
    let (tls_rva, tls_size) = data_directory(data, lfanew, opt, 9)?;
    let (iat_rva, iat_size) = data_directory(data, lfanew, opt, 12)?;
    check_section_layout(data, sec_off, sections_n)?;
    let mut sections = Vec::new();
    for index in 0..sections_n {
        sections.push(read_section(data, sec_off + index * 40)?);
    }
    let exports = read_exports(data, &sections, export_rva)?;
    let imports = read_imports(data, &sections, import_rva)?;
    Ok(PeImage {
        image_base,
        entry_rva: entry,
        sections,
        exports,
        imports,
        export_rva,
        export_size,
        import_rva,
        import_size,
        iat_rva,
        iat_size,
        exception_rva,
        exception_size,
        tls_rva,
        tls_size,
    })
}

pub fn read_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn va_bytes<'a>(file: &'a [u8], image: &PeImage, rva: u32) -> Result<&'a [u8]> {
    for section in &image.sections {
        let end = section.rva + section.bytes.len() as u32;
        if rva >= section.rva && rva < end {
            let delta = (rva - section.rva) as usize;
            let raw = raw_ptr(file, section)?;
            let start = raw + delta;
            if start >= file.len() {
                return Err(msg("section raw data is truncated"));
            }
            return Ok(&file[start..]);
        }
    }
    Err(msg(format!("rva {rva:#x} is not in a section")))
}

fn raw_ptr(file: &[u8], section: &Section) -> Result<usize> {
    section_file_offset(file, &section.name)
}

fn rva_bytes<'a>(file: &'a [u8], image: &PeImage, rva: u32, len: usize) -> Result<&'a [u8]> {
    let bytes = va_bytes(file, image, rva)?;
    if bytes.len() < len {
        return Err(msg("rva read is truncated"));
    }
    Ok(&bytes[..len])
}

fn rva_u32(file: &[u8], image: &PeImage, rva: u32) -> Result<u32> {
    let bytes = rva_bytes(file, image, rva, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn rva_u16(file: &[u8], image: &PeImage, rva: u32) -> Result<u16> {
    let bytes = rva_bytes(file, image, rva, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_exports(file: &[u8], sections: &[Section], rva: u32) -> Result<Vec<Export>> {
    if rva == 0 {
        return Ok(Vec::new());
    }
    let image = PeImage {
        image_base: 0,
        entry_rva: 0,
        sections: sections.to_vec(),
        exports: Vec::new(),
        imports: Vec::new(),
        export_rva: rva,
        export_size: 0,
        import_rva: 0,
        import_size: 0,
        iat_rva: 0,
        iat_size: 0,
        exception_rva: 0,
        exception_size: 0,
        tls_rva: 0,
        tls_size: 0,
    };
    let dir = va_bytes(file, &image, rva)?;
    if dir.len() < 40 {
        return Err(msg("export directory truncated"));
    }
    let n_names = u32::from_le_bytes([dir[24], dir[25], dir[26], dir[27]]);
    let funcs = u32::from_le_bytes([dir[28], dir[29], dir[30], dir[31]]);
    let names = u32::from_le_bytes([dir[32], dir[33], dir[34], dir[35]]);
    let ords = u32::from_le_bytes([dir[36], dir[37], dir[38], dir[39]]);
    if n_names > 4096 {
        return Err(msg("export directory is too large"));
    }
    let mut exports = Vec::new();
    for index in 0..n_names {
        let name_rva = rva_u32(file, &image, names + index * 4)?;
        let ord = rva_u16(file, &image, ords + index * 2)?;
        let func_rva = rva_u32(file, &image, funcs + u32::from(ord) * 4)?;
        let name = read_cstr(va_bytes(file, &image, name_rva)?);
        exports.push(Export {
            name,
            rva: func_rva,
        });
    }
    Ok(exports)
}

fn read_imports(file: &[u8], sections: &[Section], rva: u32) -> Result<Vec<Import>> {
    if rva == 0 {
        return Ok(Vec::new());
    }
    let image = import_image(sections, rva);
    let mut imports = Vec::new();
    let mut desc = rva;
    for _ in 0..256 {
        let bytes = va_bytes(file, &image, desc)?;
        if bytes.len() < 20 {
            break;
        }
        let original = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let name_rva = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let iat = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        if original == 0 && name_rva == 0 && iat == 0 {
            break;
        }
        let dll = read_cstr(va_bytes(file, &image, name_rva)?);
        read_thunks(file, &image, &mut imports, &dll, original, iat, name_rva)?;
        desc += 20;
    }
    Ok(imports)
}

fn import_image(sections: &[Section], rva: u32) -> PeImage {
    PeImage {
        image_base: 0,
        entry_rva: 0,
        sections: sections.to_vec(),
        exports: Vec::new(),
        imports: Vec::new(),
        export_rva: 0,
        export_size: 0,
        import_rva: rva,
        import_size: 0,
        iat_rva: 0,
        iat_size: 0,
        exception_rva: 0,
        exception_size: 0,
        tls_rva: 0,
        tls_size: 0,
    }
}

fn read_thunks(
    file: &[u8],
    image: &PeImage,
    imports: &mut Vec<Import>,
    dll: &str,
    original: u32,
    iat: u32,
    name_rva: u32,
) -> Result<()> {
    let mut slot = 0u32;
    loop {
        if slot > 4096 {
            return Err(msg("import directory is too large"));
        }
        let thunk = rva_u32(file, image, original + slot * 8)?;
        let high = rva_u32(file, image, original + slot * 8 + 4)?;
        if thunk == 0 && high == 0 {
            break;
        }
        let by_ordinal = high & 0x8000_0000 != 0;
        let name = if by_ordinal {
            format!("ord:{thunk}")
        } else {
            let hint = va_bytes(file, image, thunk)?;
            if hint.len() < 2 {
                return Err(msg("import name is truncated"));
            }
            read_cstr(&hint[2..])
        };
        imports.push(Import {
            dll: dll.to_string(),
            name,
            iat_rva: iat + slot * 8,
            name_rva: if by_ordinal { 0 } else { thunk.wrapping_add(2) },
            dll_rva: name_rva,
        });
        slot += 1;
    }
    Ok(())
}

pub fn section_mut<'a>(image: &'a mut PeImage, name: &str) -> Result<&'a mut Section> {
    image
        .sections
        .iter_mut()
        .find(|section| section.name == name)
        .ok_or_else(|| msg(format!("missing section {name}")))
}

pub(crate) fn executable(section: &Section) -> bool {
    section.characteristics & SCN_EXEC != 0
}

pub(crate) fn allow_data_writes(image: &mut PeImage, rva: u32, len: u32) -> Result<()> {
    let end = u64::from(rva) + u64::from(len);
    let section = image
        .sections
        .iter_mut()
        .find(|section| {
            rva >= section.rva && end <= u64::from(section.rva) + section.bytes.len() as u64
        })
        .ok_or_else(|| msg("PE runtime write is outside the mapped image"))?;
    if executable(section) {
        return Err(msg("PE runtime write would target executable code"));
    }
    section.characteristics |= SCN_WRITE;
    Ok(())
}

pub(crate) fn exec_cave_limit(image: &PeImage, index: usize) -> u32 {
    let rvas = section_rvas(image);
    let section = &image.sections[index];
    limit_at(&rvas, section.rva, section.bytes.len())
}

fn section_rvas(image: &PeImage) -> Vec<u32> {
    image.sections.iter().map(|section| section.rva).collect()
}

fn limit_at(rvas: &[u32], rva: u32, len: usize) -> u32 {
    if let Some(next) = rvas.iter().copied().filter(|other| *other > rva).min() {
        return next;
    }
    let end = rva.saturating_add(u32::try_from(len).unwrap_or(u32::MAX));
    align(end, SECTION_ALIGN)
}

/// Writes `bytes` into an executable section. A cave past the stored bytes
/// extends the section through the gap that ends at the next section, or at
/// the section-alignment boundary when this section is last.
pub fn write_cave(image: &mut PeImage, rva: u32, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| msg("cave is too large"))?;
    let end = rva
        .checked_add(len)
        .ok_or_else(|| msg("cave rva overflows"))?;
    let index = cave_index(image, rva, end)?;
    paint_cave(&mut image.sections[index], rva, bytes, end)
}

fn cave_index(image: &PeImage, rva: u32, end: u32) -> Result<usize> {
    let rvas = section_rvas(image);
    image
        .sections
        .iter()
        .position(|section| {
            executable(section)
                && rva >= section.rva
                && end <= limit_at(&rvas, section.rva, section.bytes.len())
        })
        .ok_or_else(|| msg(format!("rva {rva:#x} is not a code cave")))
}

fn paint_cave(section: &mut Section, rva: u32, bytes: &[u8], end: u32) -> Result<()> {
    let need = (end - section.rva) as usize;
    if need > MAX_SECTION_BYTES {
        return Err(msg("cave is too large"));
    }
    if section.bytes.len() < need {
        section.bytes.resize(need, 0);
    }
    let off = (rva - section.rva) as usize;
    section.bytes[off..off + bytes.len()].copy_from_slice(bytes);
    Ok(())
}

pub fn write_rva(image: &mut PeImage, rva: u32, bytes: &[u8]) -> Result<()> {
    let section = image
        .sections
        .iter_mut()
        .find(|section| {
            rva >= section.rva
                && (rva as usize) + bytes.len() <= section.rva as usize + section.bytes.len()
        })
        .ok_or_else(|| msg(format!("rva {rva:#x} is not writable")))?;
    let off = (rva - section.rva) as usize;
    section.bytes[off..off + bytes.len()].copy_from_slice(bytes);
    Ok(())
}

/// Virtual addresses of the TLS callbacks. Empty when the directory is absent.
pub fn tls_callbacks(image: &PeImage) -> Result<Vec<u64>> {
    if (image.tls_rva, image.tls_size) == (0, 0) {
        return Ok(Vec::new());
    }
    if image.tls_rva == 0 || image.tls_size < 40 {
        return Err(msg("invalid PE TLS directory"));
    }
    let dir = read_rva(image, image.tls_rva, image.tls_size as usize)?;
    let ptrs = rd_u64(dir, 24)?;
    if ptrs == 0 {
        return Ok(Vec::new());
    }
    let rva = rva_of(image.image_base, ptrs)?;
    read_callbacks(image, rva)
}

fn read_callbacks(image: &PeImage, rva: u32) -> Result<Vec<u64>> {
    let table = image
        .sections
        .iter()
        .find_map(|section| section_tail(section, rva).filter(|tail| !tail.is_empty()))
        .ok_or_else(|| msg("PE TLS callback table is not mapped"))?;
    let mut callbacks = Vec::new();
    for slot in table.chunks_exact(std::mem::size_of::<u64>()) {
        let callback = rd_u64(slot, 0)?;
        if callback == 0 {
            return Ok(callbacks);
        }
        callbacks.push(callback);
    }
    Err(msg(
        "PE TLS callback table is not terminated within its section",
    ))
}

fn rva_of(base: u64, va: u64) -> Result<u32> {
    let rva = va
        .checked_sub(base)
        .ok_or_else(|| msg("tls callback is below the image"))?;
    u32::try_from(rva).map_err(|_| msg("tls callback rva does not fit"))
}

pub fn read_rva(image: &PeImage, rva: u32, len: usize) -> Result<&[u8]> {
    image
        .sections
        .iter()
        .find_map(|section| section_tail(section, rva)?.get(..len))
        .ok_or_else(|| msg(format!("rva {rva:#x} is not readable")))
}

fn section_tail(section: &Section, rva: u32) -> Option<&[u8]> {
    let offset = usize::try_from(rva.checked_sub(section.rva)?).ok()?;
    section.bytes.get(offset..)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_parse_roundtrip() {
        let image = PeImage {
            image_base: IMAGE_BASE,
            entry_rva: 0x1000,
            sections: vec![Section {
                name: ".text".into(),
                rva: 0x1000,
                bytes: vec![0xc3],
                characteristics: CH_TEXT,
            }],
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
        };
        let bytes = emit(&image).unwrap();
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.entry_rva, 0x1000);
        assert_eq!(parsed.image_base, IMAGE_BASE);
        assert_eq!(parsed.sections[0].bytes[0], 0xc3);
        assert_eq!(parsed.exception_rva, 0);
        assert_eq!(parsed.exception_size, 0);
        let kind = image_kind(&bytes).unwrap();
        assert_eq!(kind.subsystem, SUBSYSTEM_WINDOWS_CUI);
        assert_eq!(kind.characteristics, 0x0022);
        assert_eq!(kind.dll_characteristics, 0x0100);
    }

    #[test]
    fn image_kind_restores_a_native_subsystem() {
        let image = PeImage {
            image_base: IMAGE_BASE,
            entry_rva: 0x1000,
            sections: vec![Section {
                name: ".text".into(),
                rva: 0x1000,
                bytes: vec![0xc3],
                characteristics: CH_TEXT,
            }],
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
        };
        let mut bytes = emit(&image).unwrap();
        let native = ImageKind {
            characteristics: 0x2022,
            subsystem: SUBSYSTEM_NATIVE,
            dll_characteristics: 0x0160,
        };
        set_image_kind(&mut bytes, &native).unwrap();
        assert_eq!(image_kind(&bytes).unwrap(), native);
        let marked = ImageKind {
            // GUARD_CF | NX_COMPAT | FORCE_INTEGRITY | DYNAMIC_BASE | HIGH_ENTROPY_VA.
            dll_characteristics: 0x41e0,
            ..native
        };
        let cleared = without_unbacked_dll_bits(marked);
        assert_eq!(cleared.characteristics, native.characteristics);
        assert_eq!(cleared.subsystem, SUBSYSTEM_NATIVE);
        // NX_COMPAT | FORCE_INTEGRITY. The three directory-backed bits are gone.
        assert_eq!(cleared.dll_characteristics, 0x0180);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.entry_rva, 0x1000);
        assert_eq!(parsed.sections[0].bytes, vec![0xc3]);
    }

    #[test]
    fn hostile_headers_are_errors() {
        let mut early = vec![0u8; 0x200];
        early[0] = b'M';
        early[1] = b'Z';
        early[0x3c..0x40].copy_from_slice(&0x1feu32.to_le_bytes());
        assert!(parse(&early).is_err());

        let image = PeImage {
            image_base: IMAGE_BASE,
            entry_rva: 0x1000,
            sections: vec![Section {
                name: ".text".into(),
                rva: 0x1000,
                bytes: vec![0xc3],
                characteristics: CH_TEXT,
            }],
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
        };
        let mut bytes = emit(&image).unwrap();
        let lfanew = 0x80usize;
        bytes[lfanew + 6..lfanew + 8].copy_from_slice(&500u16.to_le_bytes());
        assert!(parse(&bytes).is_err());

        let mut bytes = emit(&image).unwrap();
        let optional =
            u16::from_le_bytes(bytes[lfanew + 20..lfanew + 22].try_into().unwrap()) as usize;
        let virtual_size = lfanew + 24 + optional + 8;
        bytes[virtual_size..virtual_size + 4]
            .copy_from_slice(&((MAX_SECTION_BYTES as u32) + 1).to_le_bytes());
        assert!(parse(&bytes).is_err());

        let mut bytes = emit(&image).unwrap();
        bytes[lfanew + 20..lfanew + 22].copy_from_slice(&0u16.to_le_bytes());
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn image_span_follows_the_highest_rva() {
        let image = PeImage {
            image_base: IMAGE_BASE,
            entry_rva: 0x3000,
            sections: vec![
                Section {
                    name: ".high".into(),
                    rva: 0x3000,
                    bytes: vec![0x90],
                    characteristics: CH_TEXT,
                },
                Section {
                    name: ".low".into(),
                    rva: 0x1000,
                    bytes: vec![0xc3],
                    characteristics: CH_TEXT,
                },
            ],
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
        };
        let bytes = emit(&image).unwrap();
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.sections[0].rva, 0x3000);
        assert_eq!(parsed.sections[1].bytes[0], 0xc3);
        let machine = crate::emu::load(&parsed, crate::emu::Policy::default()).unwrap();
        assert_eq!(
            machine.read(IMAGE_BASE + 0x3000, 1).unwrap().as_slice(),
            &[0x90]
        );
    }
}
