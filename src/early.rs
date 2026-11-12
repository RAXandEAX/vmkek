//! Early anti-debug and integrity, before the original entry.
//!
//! PE runs the check from a TLS callback. The emulator calls that callback
//! before `AddressOfEntryPoint`, which is the M-EMU model of the Windows
//! loader. ELF runs it from `.init_array`, which the dynamic linker calls
//! before `e_entry` on M-LINUX.
//!
//! The check fails closed on its own. Nopping only the original entry body
//! still fails the run, because the checksum of that body no longer matches.

use iced_x86::code_asm::*;

use crate::elf::{DynamicTag, ElfImage, SegmentKind};
use crate::error::{msg, Result};
use crate::pe::{self, PeImage, Section};
use crate::vm::RT_LINUX;

const GS_PEB: [u8; 9] = [0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
const PE_MARK: u32 = 0xC6E1_0001;
const PE_END: u32 = 0xC6E1_0002;
const CODE_GAP: usize = 0x600;
const RUNTIME_LEN: usize = 0x90;
const ARRAY_ROOM: usize = 64;
const EARLY_LIMIT: usize = 0x800;
pub(crate) const PE_CALLBACK_ROOM: usize = 0x100;

/// Offsets of the copied dynamic table inside the protected ELF section.
pub(crate) struct Planted {
    pub dyn_off: u32,
    pub dyn_len: u32,
    /// Trampoline that calls the `.init_array` check, then the SysV loader.
    pub entry: u64,
}

/// Nop the TLS BeingDebugged branch. The entry checksum stays in place.
pub fn neutralize_early_pe(file: &mut [u8]) -> Result<()> {
    nop_between(file, PE_MARK, PE_END)
}

/// Nop the `.init_array` tracer. The entry checksum stays in place.
pub fn neutralize_early_elf(file: &mut [u8]) -> Result<()> {
    nop_between(
        file,
        crate::antidebug::EARLY_MARK,
        crate::antidebug::EARLY_END,
    )
}

pub(crate) fn plant_pe(
    image: &mut PeImage,
    code_section: &mut Section,
    state_section: &mut Section,
    code_off: usize,
    entry_rva: u32,
    span: usize,
    tls_size: u32,
) -> Result<()> {
    let sum = span_sum(pe::read_rva(image, entry_rva, span)?);
    let entry = image.image_base.wrapping_add(u64::from(entry_rva));
    let origin = image.image_base + u64::from(code_section.rva) + code_off as u64;
    let state_base = image.image_base + u64::from(state_section.rva);
    let status = (tls_size != 0).then_some(state_base + 4);
    let code = pe_callback(origin, entry, u32_of(span)?, sum, status)?;
    if code.len() > PE_CALLBACK_ROOM {
        return Err(msg("PE TLS callback exceeds its code slot"));
    }
    code_section
        .bytes
        .get_mut(code_off..code_off + code.len())
        .ok_or_else(|| msg("PE TLS callback code slot is outside the section"))?
        .copy_from_slice(&code);
    let dir_off = tls_blob(state_section, state_base, origin, tls_size);
    let rva = state_section
        .rva
        .checked_add(u32_of(dir_off)?)
        .ok_or_else(|| msg("tls rva overflows"))?;
    image.tls_rva = rva;
    image.tls_size = 40;
    Ok(())
}

pub(crate) fn plant_elf(
    file: &[u8],
    image: &ElfImage,
    body: &mut Vec<u8>,
    section_va: u64,
    entry_va: u64,
    span: usize,
) -> Result<Planted> {
    let sum = span_sum(read_va(file, image, entry_va, span)?);
    let blob_off = align_len(body.len(), 16);
    let origin = section_va.wrapping_add(blob_off as u64);
    let runtime = origin.wrapping_add(CODE_GAP as u64);
    let code = elf_code(origin, entry_va, u32_of(span)?, sum, runtime)?;
    let tramp_off = blob_off + code.len();
    let tramp_va = section_va.wrapping_add(tramp_off as u64);
    let loader = section_va.wrapping_add(crate::crypto::HEADER_LEN as u64);
    let tramp = link_stub(tramp_va, origin, loader)?;
    fit_code(tramp_off - blob_off + tramp.len())?;
    let array = init_array(file, image, origin)?;
    let array_off = blob_off + CODE_GAP + RUNTIME_LEN;
    let array_va = section_va.wrapping_add(array_off as u64);
    let dyn_bytes = extend_dynamic(file, image, array_va, array.len() as u64)?;
    let dyn_off = array_off + ARRAY_ROOM;
    write_elf(
        body, blob_off, &code, array_off, &array, dyn_off, &dyn_bytes,
    )?;
    body[tramp_off..tramp_off + tramp.len()].copy_from_slice(&tramp);
    let new_dyn = section_va.wrapping_add(dyn_off as u64);
    retarget_dynamic(body, dynamic_va(image)?, new_dyn)?;
    Ok(Planted {
        dyn_off: u32_of(dyn_off)?,
        dyn_len: u32_of(dyn_bytes.len())?,
        entry: tramp_va,
    })
}

pub(crate) fn publish_dynamic(
    file: &mut [u8],
    section_va: u64,
    dyn_off: u32,
    dyn_len: u32,
) -> Result<()> {
    let image = crate::elf::parse(file)?;
    let load = image
        .segments
        .iter()
        .find(|segment| segment.kind == SegmentKind::Load && segment.vaddr == section_va)
        .ok_or_else(|| msg("early segment is missing"))?;
    let offset = load
        .offset
        .checked_add(u64::from(dyn_off))
        .ok_or_else(|| msg("dynamic offset overflows"))?;
    let va = section_va.wrapping_add(u64::from(dyn_off));
    patch_dynamic(file, va, offset, u64::from(dyn_len))
}

/// Point `e_entry` at the trampoline. `install_section` writes the loader.
pub(crate) fn publish_entry(file: &mut [u8], entry: u64) {
    file[24..32].copy_from_slice(&entry.to_le_bytes());
}

fn pe_callback(
    origin: u64,
    entry: u64,
    len: u32,
    sum: u32,
    status: Option<u64>,
) -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut back = a.create_label();
    let mut fail = a.create_label();
    step(a.cmp(edx, 1i32))?;
    step(a.jne(back))?;
    emit_peb(&mut a, &mut fail)?;
    emit_integrity(&mut a, entry, len, sum, &fail, status.is_some())?;
    if let Some(address) = status {
        crate::loader::emit_image_address(&mut a, iced_x86::Register::R10, address)?;
        step(a.mov(dword_ptr(r10), 1u32))?;
    }
    step(a.xor(eax, eax))?;
    step(a.ret())?;
    step(a.set_label(&mut back))?;
    step(a.xor(eax, eax))?;
    step(a.ret())?;
    step(a.set_label(&mut fail))?;
    step(a.mov(eax, if status.is_some() { 0 } else { 0xdeb6u32 }))?;
    step(a.ret())?;
    a.assemble(origin).map_err(|err| msg(err.to_string()))
}

fn emit_peb(a: &mut CodeAssembler, fail: &mut CodeLabel) -> Result<()> {
    step(a.mov(r11d, PE_MARK))?;
    step(a.db(&GS_PEB))?;
    step(a.mov(dl, byte_ptr(rax + 2i32)))?;
    step(a.test(dl, dl))?;
    step(a.jnz(*fail))?;
    step(a.mov(r11d, PE_END))?;
    Ok(())
}

fn elf_code(origin: u64, entry: u64, len: u32, sum: u32, runtime: u64) -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut fail = a.create_label();
    emit_stderr(&mut a, *b"early\n\0\0")?;
    step(a.mov(r13, runtime as i64))?;
    crate::antidebug::emit_early_tracer(&mut a, &mut fail)?;
    emit_integrity(&mut a, entry, len, sum, &fail, false)?;
    step(a.xor(eax, eax))?;
    step(a.ret())?;
    step(a.set_label(&mut fail))?;
    step(a.mov(edi, 0xdeb6u32))?;
    step(a.mov(eax, 231u32))?;
    step(a.syscall())?;
    a.assemble(origin).map_err(|err| msg(err.to_string()))
}

fn emit_integrity(
    a: &mut CodeAssembler,
    entry: u64,
    len: u32,
    sum: u32,
    fail: &CodeLabel,
    native: bool,
) -> Result<()> {
    let mut top = a.create_label();
    let mut check = a.create_label();
    if native {
        crate::loader::emit_image_address(a, iced_x86::Register::R10, entry)?;
    } else {
        step(a.mov(r10, entry as i64))?;
    }
    step(a.mov(ecx, len))?;
    step(a.xor(eax, eax))?;
    step(a.set_label(&mut top))?;
    step(a.test(ecx, ecx))?;
    step(a.jz(check))?;
    step(a.movzx(edx, byte_ptr(r10)))?;
    // Wrapping add stays nonzero for a trampoline whose bytes XOR to zero,
    // so an all-zero excision still fails closed.
    step(a.add(eax, edx))?;
    step(a.inc(r10))?;
    step(a.dec(ecx))?;
    step(a.jmp(top))?;
    step(a.set_label(&mut check))?;
    step(a.cmp(eax, sum as i32))?;
    step(a.jne(*fail))?;
    Ok(())
}

fn span_sum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0, |acc, byte| acc.wrapping_add(u32::from(*byte)))
}

fn emit_stderr(a: &mut CodeAssembler, text: [u8; 8]) -> Result<()> {
    step(a.sub(rsp, 16i32))?;
    step(a.mov(rax, i64::from_le_bytes(text)))?;
    step(a.mov(qword_ptr(rsp), rax))?;
    step(a.mov(eax, 1u32))?;
    step(a.mov(edi, 2u32))?;
    step(a.mov(rsi, rsp))?;
    step(a.mov(edx, 6u32))?;
    step(a.syscall())?;
    step(a.add(rsp, 16i32))?;
    Ok(())
}

fn tls_blob(section: &mut Section, base: u64, origin: u64, tls_size: u32) -> usize {
    let template_off = align_len(section.bytes.len(), 16);
    let native = tls_size != 0;
    let index_off = if native { 0 } else { template_off };
    // The whole template is file-backed so the loader allocates and copies
    // the full size on Windows versions that do not honor TLS zero-fill.
    let ptr_off = template_off + (tls_size as usize).max(8);
    let dir_off = ptr_off + 16;
    section.bytes.resize(dir_off + 40, 0);
    section.bytes[ptr_off..ptr_off + 8].copy_from_slice(&origin.to_le_bytes());
    let dir = tls_dir(base, template_off, index_off, ptr_off, tls_size);
    section.bytes[dir_off..dir_off + 40].copy_from_slice(&dir);
    dir_off
}

fn tls_dir(base: u64, template: usize, index: usize, callbacks: usize, size: u32) -> [u8; 40] {
    let mut out = [0u8; 40];
    if size != 0 {
        let start = base + template as u64;
        out[0..8].copy_from_slice(&start.to_le_bytes());
        out[8..16].copy_from_slice(&(start + u64::from(size)).to_le_bytes());
        out[36..40].copy_from_slice(&0x0050_0000u32.to_le_bytes());
    }
    out[16..24].copy_from_slice(&(base + index as u64).to_le_bytes());
    out[24..32].copy_from_slice(&(base + callbacks as u64).to_le_bytes());
    out
}

fn write_elf(
    body: &mut Vec<u8>,
    blob_off: usize,
    code: &[u8],
    array_off: usize,
    array: &[u8],
    dyn_off: usize,
    dyn_bytes: &[u8],
) -> Result<()> {
    let total = dyn_off
        .checked_add(dyn_bytes.len())
        .ok_or_else(|| msg("early blob overflows"))?;
    body.resize(total, 0);
    body[blob_off..blob_off + code.len()].copy_from_slice(code);
    let mask_at = blob_off + CODE_GAP + RT_LINUX as usize;
    let mask = crate::antidebug::linux_arm().0.to_le_bytes();
    body[mask_at..mask_at + 4].copy_from_slice(&mask);
    body[array_off..array_off + array.len()].copy_from_slice(array);
    body[dyn_off..dyn_off + dyn_bytes.len()].copy_from_slice(dyn_bytes);
    Ok(())
}

fn init_array(file: &[u8], image: &ElfImage, origin: u64) -> Result<Vec<u8>> {
    let mut array = origin.to_le_bytes().to_vec();
    if let Some(span) = image.init_array {
        let old = read_va(file, image, span.addr, usize_of(span.size)?)?;
        array.extend_from_slice(old);
    }
    if array.len() > ARRAY_ROOM {
        return Err(msg("init array does not fit"));
    }
    Ok(array)
}

fn extend_dynamic(file: &[u8], image: &ElfImage, array_va: u64, size: u64) -> Result<Vec<u8>> {
    let mut bytes = copy_dynamic(file, image)?;
    strip_null(&mut bytes)?;
    upsert(&mut bytes, DynamicTag::InitArray, array_va);
    upsert(&mut bytes, DynamicTag::InitArraySize, size);
    push_dyn(&mut bytes, DynamicTag::Null, 0);
    Ok(bytes)
}

fn copy_dynamic(file: &[u8], image: &ElfImage) -> Result<Vec<u8>> {
    let segment = image
        .segments
        .iter()
        .find(|item| item.kind == SegmentKind::Dynamic && item.filesz >= 16)
        .ok_or_else(|| msg("elf has no dynamic segment"))?;
    let off = usize_of(segment.offset)?;
    let size = usize_of(segment.filesz)?;
    file.get(off..off + size)
        .map(|bytes| bytes.to_vec())
        .ok_or_else(|| msg("dynamic table is outside the file"))
}

fn strip_null(bytes: &mut Vec<u8>) -> Result<()> {
    let mut at = 0;
    while at + 16 <= bytes.len() {
        if bytes[at..at + 8] == [0; 8] {
            bytes.truncate(at);
            return Ok(());
        }
        at += 16;
    }
    Err(msg("dynamic table is not terminated"))
}

fn upsert(bytes: &mut Vec<u8>, tag: DynamicTag, value: u64) {
    let raw = tag_raw(tag);
    let mut at = 0;
    while at + 16 <= bytes.len() {
        let found = i64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        if found == raw {
            bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
            return;
        }
        at += 16;
    }
    push_dyn(bytes, tag, value);
}

fn push_dyn(bytes: &mut Vec<u8>, tag: DynamicTag, value: u64) {
    bytes.extend_from_slice(&tag_raw(tag).to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn tag_raw(tag: DynamicTag) -> i64 {
    match tag {
        DynamicTag::Null => 0,
        DynamicTag::InitArray => 25,
        DynamicTag::InitArraySize => 27,
        _ => 0,
    }
}

fn patch_dynamic(file: &mut [u8], va: u64, offset: u64, len: u64) -> Result<()> {
    let (phoff, entsize, count) = program_headers(file)?;
    for index in 0..count {
        let at = phoff + index * entsize;
        let kind = u32::from_le_bytes(file[at..at + 4].try_into().unwrap());
        if kind == 2 {
            write_dynamic_span(file, at, va, offset, len);
            return Ok(());
        }
    }
    Err(msg("elf has no dynamic header"))
}

fn write_dynamic_span(file: &mut [u8], at: usize, va: u64, offset: u64, len: u64) {
    file[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
    file[at + 16..at + 24].copy_from_slice(&va.to_le_bytes());
    file[at + 24..at + 32].copy_from_slice(&va.to_le_bytes());
    file[at + 32..at + 40].copy_from_slice(&len.to_le_bytes());
    file[at + 40..at + 48].copy_from_slice(&len.to_le_bytes());
}

fn program_headers(file: &[u8]) -> Result<(usize, usize, usize)> {
    if file.len() < 64 {
        return Err(msg("elf header is truncated"));
    }
    let phoff = usize_of(u64::from_le_bytes(file[32..40].try_into().unwrap()))?;
    let entsize = u16::from_le_bytes(file[54..56].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(file[56..58].try_into().unwrap()) as usize;
    let end = phoff
        .checked_add(
            entsize
                .checked_mul(count)
                .ok_or_else(|| msg("program headers overflow"))?,
        )
        .ok_or_else(|| msg("program headers overflow"))?;
    if entsize < 56 || end > file.len() {
        return Err(msg("program headers are outside the file"));
    }
    Ok((phoff, entsize, count))
}

fn read_va<'a>(file: &'a [u8], image: &ElfImage, va: u64, len: usize) -> Result<&'a [u8]> {
    let off = va_file(image, va)?;
    file.get(off..off + len)
        .ok_or_else(|| msg("early range is outside the file"))
}

fn va_file(image: &ElfImage, va: u64) -> Result<usize> {
    for segment in &image.segments {
        if segment.kind != SegmentKind::Load || segment.filesz == 0 {
            continue;
        }
        let end = segment.vaddr.saturating_add(segment.filesz);
        if va >= segment.vaddr && va < end {
            let delta = usize_of(va - segment.vaddr)?;
            return Ok(usize_of(segment.offset)? + delta);
        }
    }
    Err(msg("address is not in a load segment"))
}

fn fit_code(len: usize) -> Result<()> {
    if len <= CODE_GAP {
        Ok(())
    } else {
        Err(msg("early init does not fit"))
    }
}

/// `call early; jmp loader`. glibc runs a main executable's `.init_array` from
/// the C runtime, which a protected image never enters, so `e_entry` calls it.
fn link_stub(at: u64, early: u64, loader: u64) -> Result<[u8; 10]> {
    let mut out = [0u8; 10];
    out[0] = 0xE8;
    out[1..5].copy_from_slice(&rel32(early, at + 5)?.to_le_bytes());
    out[5] = 0xE9;
    out[6..10].copy_from_slice(&rel32(loader, at + 10)?.to_le_bytes());
    Ok(out)
}

fn rel32(dest: u64, next: u64) -> Result<i32> {
    i32::try_from(dest as i64 - next as i64).map_err(|_| msg("early branch is out of range"))
}

fn dynamic_va(image: &ElfImage) -> Result<u64> {
    image
        .segments
        .iter()
        .find(|item| item.kind == SegmentKind::Dynamic && item.vaddr != 0)
        .map(|item| item.vaddr)
        .ok_or_else(|| msg("elf has no dynamic segment"))
}

fn retarget_dynamic(body: &mut [u8], old: u64, new: u64) -> Result<()> {
    let mut needle = [0x48, 0xBE, 0, 0, 0, 0, 0, 0, 0, 0];
    needle[2..].copy_from_slice(&old.to_le_bytes());
    let mut found = None;
    for index in 0..body.len().saturating_sub(needle.len()) {
        if body[index..index + needle.len()] != needle {
            continue;
        }
        if found.is_some() {
            return Err(msg("loader dynamic address is not unique"));
        }
        found = Some(index + 2);
    }
    let Some(at) = found else {
        return Err(msg("loader dynamic address is missing"));
    };
    body[at..at + 8].copy_from_slice(&new.to_le_bytes());
    Ok(())
}

fn nop_between(file: &mut [u8], from_imm: u32, to_imm: u32) -> Result<()> {
    let (from, _) = find_mark(file, from_imm)?;
    let (_, to) = find_mark(file, to_imm)?;
    if to <= from || to - from > EARLY_LIMIT {
        return Err(msg("early marks are out of range"));
    }
    file[from..to].fill(0x90);
    Ok(())
}

fn find_mark(file: &[u8], imm: u32) -> Result<(usize, usize)> {
    let bytes = imm.to_le_bytes();
    let mut found = None;
    for index in 0..file.len().saturating_sub(4) {
        if file[index..index + 4] != bytes {
            continue;
        }
        let Some(span) = mov_r11d(file, index) else {
            continue;
        };
        if found.is_some() {
            return Err(msg("early mark is not unique"));
        }
        found = Some(span);
    }
    found.ok_or_else(|| msg("early mark is missing"))
}

fn mov_r11d(file: &[u8], index: usize) -> Option<(usize, usize)> {
    if index >= 2 && file[index - 2..index] == [0x41, 0xBB] {
        return Some((index - 2, index + 4));
    }
    if index >= 3 && file[index - 3..index] == [0x41, 0xC7, 0xC3] {
        return Some((index - 3, index + 4));
    }
    None
}

fn align_len(len: usize, align: usize) -> usize {
    len.div_ceil(align) * align
}

fn u32_of(len: usize) -> Result<u32> {
    u32::try_from(len).map_err(|_| msg("early image offset does not fit"))
}

fn usize_of(len: u64) -> Result<usize> {
    usize::try_from(len).map_err(|_| msg("early image offset does not fit"))
}

fn step(result: std::result::Result<(), IcedError>) -> Result<()> {
    result.map_err(|err| msg(err.to_string()))
}
