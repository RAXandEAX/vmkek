//! ELF64 x86-64 protect path.
//!
//! The lifter, obfuscator, VM, mutation caves, and AEAD seal are the PE passes.
//! This module only maps them onto a fixed executable and a SysV loader.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use super::payload;
use super::{
    assemble_report, mutate_function, note_mutation, parse_selector, reachable_size, section_end,
    select, Selector, Sym, PAYLOAD_PASSES,
};
use super::{Options, Protected};
use crate::crypto::{self, Header, HEADER_LEN};
use crate::elf::{self, DynamicTag, ElfImage, ElfKind, SegmentKind, SymbolKind};
use crate::error::{msg, Result};
use crate::ir::{Exit, FuncIr};
use crate::lift::{lift, native_call_address};
use crate::loader::{self, SysvPlan};
use crate::obf::obfuscate;
use crate::pe::{self, PeImage, Section};
use crate::report::push_pass;
use crate::stub::{self, Trampoline};
use crate::vm::{self, BcImage};

mod authenticated;
pub(super) use authenticated::protect_authenticated;

const ELF_VM_PASSES: &[&str] = &[
    "opcode-polymorph",
    "bytecode-encrypt",
    "per-instruction-stream",
    "vm-equivalence",
    "layout-stealth",
    "integrity-cookies",
    "fail-closed-handlers",
    "anti-debug",
    "peb-being-debugged",
    "heap-flags",
];

const PAGE: u64 = 0x1000;
const GLOB_DAT: u32 = 6;
const JUMP_SLOT: u32 = 7;

pub(super) fn protect(input: &[u8], options: &Options, socket: Option<&str>) -> Result<Protected> {
    let image = elf::parse(input)?;
    if image.kind != ElfKind::Executable || image.pie {
        return Err(msg("elf protect accepts a fixed executable"));
    }
    if image.entry == 0 {
        return Err(msg("image has no entry point"));
    }
    let mut file = input.to_vec();
    let symbols = discover(&image, &file, options)?;
    let (virt, mutated) = select(&symbols, options, false)?;
    let (lowered, mut passes) = lower_passes(&file, &image, &virt, options.seed)?;
    let section_va = next_va(&image)?;
    let layout = measure(section_va, lowered.funcs.len(), socket.is_some())?;
    let skips = write_trampolines(&mut file, &image, &virt, section_va, &layout, &mut passes)?;
    let funcs: Vec<(u32, u32)> = virt.iter().map(|sym| (sym.rva, sym.size)).collect();
    let spans = super::hygiene::elf_spans(&image, &funcs);
    let skips = super::hygiene::extend_skips(&skips, &spans);
    preserve_ranges(&mut file, &image, &virt)?;
    let imports = hashed_imports(&image)?;
    if !imports.is_empty() {
        push_pass(&mut passes, "import-hash");
    }
    if image
        .imports
        .iter()
        .any(|item| crate::syscall::direct_nr(item.name.as_bytes()).is_some())
    {
        push_pass(&mut passes, "direct-syscall-linux");
    }
    let strings = encrypt_writable(&mut file, &image, options.seed, &skips)?;
    if !strings.is_empty() {
        push_pass(&mut passes, "string-encrypt");
    }
    clear_import_text(&mut file, &image)?;
    let changed = mutate_elf(&mut file, &image, &mutated, options.seed, &mut passes)?;
    let maps = super::hygiene::commit_elf(&mut file, &image, options.seed, &spans)?;
    finish_elf(
        &mut file, &image, &lowered, &strings, &maps, &imports, options, section_va, &layout,
        passes, &virt, &changed, socket,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_elf(
    file: &mut Vec<u8>,
    image: &ElfImage,
    lowered: &BcImage,
    strings: &[(u32, u32, u8)],
    maps: &[(u32, u32, u8)],
    imports: &[(u32, u32)],
    options: &Options,
    section_va: u64,
    layout: &Layout,
    mut passes: Vec<String>,
    virt: &[Sym],
    changed: &[Sym],
    socket: Option<&str>,
) -> Result<Protected> {
    let tables = payload::StringTables {
        trace: strings,
        maps,
    };
    let (mut body, header) = build_body(
        image, lowered, &tables, imports, options, section_va, layout, socket,
    )?;
    let planted = attach_early(file, image, &mut body, section_va, virt)?;
    super::note_key_mode(&mut passes, socket.is_some());
    for pass in PAYLOAD_PASSES {
        push_pass(&mut passes, pass);
    }
    let name = super::hygiene::section_name(options.seed);
    let entry = install_section(file, image, section_va, &body, &name)?;
    crate::early::publish_dynamic(file, section_va, planted.dyn_off, planted.dyn_len)?;
    crate::early::publish_entry(file, planted.entry);
    push_pass(&mut passes, "early-init");
    write_sealed_header(file, section_va, &header)?;
    push_pass(&mut passes, "image-hygiene");
    push_pass(&mut passes, "sealed-maps");
    let report = assemble_report(
        options.debug_seed.then_some(options.seed),
        options.seed,
        passes,
        (virt, changed),
        entry,
        (&header, file),
        lowered,
    )?;
    Ok(Protected {
        bytes: std::mem::take(file),
        report,
        custody: external_package(lowered, socket)?,
    })
}

fn attach_early(
    file: &[u8],
    image: &ElfImage,
    body: &mut Vec<u8>,
    section_va: u64,
    virt: &[Sym],
) -> Result<crate::early::Planted> {
    let rva = va_rva(image, image.entry)?;
    let span = super::entry_span(virt, rva);
    crate::early::plant_elf(file, image, body, section_va, image.entry, span)
}

fn external_package(
    lowered: &BcImage,
    socket: Option<&str>,
) -> Result<Option<crate::agent::Package>> {
    if socket.is_none() {
        return Ok(None);
    }
    Ok(Some(crate::agent::Package::from_image(lowered)?))
}

fn lower_passes(
    file: &[u8],
    image: &ElfImage,
    virt: &[Sym],
    seed: u64,
) -> Result<(BcImage, Vec<String>)> {
    let (funcs, mut passes) = virtualize(file, image, virt, seed, false)?;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let lowered = vm::lower_image(&funcs.0, &mut rng)?;
    drop(funcs);
    for pass in ELF_VM_PASSES {
        push_pass(&mut passes, pass);
    }
    note_linux(&mut passes);
    Ok((lowered, passes))
}

fn note_linux(passes: &mut Vec<String>) {
    let mask = crate::antidebug::linux_arm().0;
    if mask & crate::antidebug::LINUX_TRACER != 0 {
        push_pass(passes, "linux-tracer-pid");
    }
    if mask & crate::antidebug::LINUX_PTRACE != 0 {
        push_pass(passes, "linux-ptrace");
    }
    if mask & crate::antidebug::LINUX_CLOCK != 0 {
        push_pass(passes, "linux-clock");
    }
}

fn preserve_ranges(file: &mut [u8], image: &ElfImage, virt: &[Sym]) -> Result<()> {
    for symbol in virt {
        let start = image.image_base + u64::from(symbol.rva);
        let end = start + u64::from(symbol.size);
        let _ = crate::unwind::preserve_elf(&mut elf::parse(file)?, start, end)?;
    }
    Ok(())
}

fn clear_import_text(file: &mut [u8], image: &ElfImage) -> Result<()> {
    zero_import_names(file, image)?;
    neutralize_relocs(file, image)
}

fn write_sealed_header(file: &mut [u8], section_va: u64, header: &Header) -> Result<()> {
    let encoded = header.to_bytes();
    let body_off = body_file_off(file, section_va)?;
    file[body_off..body_off + HEADER_LEN].copy_from_slice(&encoded);
    Ok(())
}

struct Layout {
    external: bool,
    loader_len: usize,
    /// Bytes before the VM so its origin is 8-byte aligned.
    vm_pad: usize,
    vm_len: usize,
    vm_frame: usize,
    vm_dispatch: usize,
    vm_calls: usize,
    tramp_len: usize,
    tramp_off: u32,
    payload_off: u32,
}

fn discover(image: &ElfImage, file: &[u8], options: &Options) -> Result<Vec<Sym>> {
    let mut symbols = listed_symbols(image)?;
    apply_rva_selectors(&mut symbols, options)?;
    symbols.sort_by_key(|item| item.rva);
    fill_sizes(image, file, &mut symbols)?;
    Ok(symbols)
}

fn listed_symbols(image: &ElfImage) -> Result<Vec<Sym>> {
    let mut symbols = Vec::new();
    for export in &image.exports {
        if export.kind != SymbolKind::Func {
            continue;
        }
        let rva = va_rva(image, export.value)?;
        if symbols.iter().any(|item: &Sym| item.rva == rva) {
            continue;
        }
        let (size, explicit) = fit_size(export.size)?;
        symbols.push(Sym {
            name: utf8(export.name.as_bytes())?,
            rva,
            size,
            explicit_size: explicit,
        });
    }
    let entry_rva = va_rva(image, image.entry)?;
    if entry_rva != 0 && !symbols.iter().any(|item| item.rva == entry_rva) {
        symbols.push(Sym {
            name: format!("entry_{entry_rva:x}"),
            rva: entry_rva,
            size: 0,
            explicit_size: false,
        });
    }
    Ok(symbols)
}

fn fill_sizes(image: &ElfImage, file: &[u8], symbols: &mut [Sym]) -> Result<()> {
    let projected = project(image, file, false)?;
    for index in 0..symbols.len() {
        if symbols[index].explicit_size {
            if symbols[index].size == 0 {
                return Err(msg("rva selector has an empty size"));
            }
            continue;
        }
        let limit = symbols
            .get(index + 1)
            .map(|item| item.rva)
            .unwrap_or_else(|| section_end(&projected, symbols[index].rva));
        let window = limit.saturating_sub(symbols[index].rva);
        symbols[index].size = reachable_size(&projected, symbols[index].rva, window)?;
        if symbols[index].size == 0 {
            return Err(msg(format!(
                "{} does not start with a valid instruction",
                symbols[index].name
            )));
        }
    }
    Ok(())
}

fn fit_size(size: u64) -> Result<(u32, bool)> {
    if size == 0 {
        return Ok((0, false));
    }
    let size = u32::try_from(size).map_err(|_| msg("symbol size does not fit"))?;
    Ok((size, true))
}

fn apply_rva_selectors(symbols: &mut Vec<Sym>, options: &Options) -> Result<()> {
    for token in options.virtualize.iter().chain(options.mutate.iter()) {
        let Selector::Rva { rva, size } = parse_selector(token)? else {
            continue;
        };
        if let Some(symbol) = symbols.iter_mut().find(|item| item.rva == rva) {
            if let Some(size) = size {
                symbol.size = size;
                symbol.explicit_size = true;
            }
        } else {
            symbols.push(Sym {
                name: format!("rva_{rva:x}"),
                rva,
                size: size.unwrap_or(0),
                explicit_size: size.is_some(),
            });
        }
    }
    Ok(())
}

fn virtualize(
    file: &[u8],
    image: &ElfImage,
    virt: &[Sym],
    seed: u64,
    authenticated: bool,
) -> Result<(super::BuildIr, Vec<String>)> {
    let mut funcs = super::BuildIr(Vec::new());
    let mut passes = Vec::new();
    for symbol in virt {
        let va = image.image_base + u64::from(symbol.rva);
        let bytes = read_span(file, image, va, symbol.size as usize)?;
        let mut func = lift(
            &symbol.name,
            bytes,
            symbol.rva,
            symbol.size,
            image.image_base,
        )?;
        route_direct_calls(image, virt, &mut func)?;
        let mut rng = ChaCha20Rng::seed_from_u64(seed ^ u64::from(symbol.rva));
        let obf = if authenticated {
            crate::obf::obfuscate_for_authenticated_elf(&func, &mut rng)?
        } else {
            obfuscate(&func, &mut rng)
        };
        for pass in obf.passes {
            push_pass(&mut passes, pass);
        }
        funcs.0.push(obf.func);
    }
    if funcs.0.is_empty() {
        return Err(msg("nothing to virtualize"));
    }
    Ok((funcs, passes))
}

fn route_direct_calls(image: &ElfImage, virt: &[Sym], func: &mut FuncIr) -> Result<()> {
    for block in &mut func.blocks {
        let Exit::CallRva { rva, next } = block.exit else {
            continue;
        };
        if virt.iter().any(|symbol| symbol.rva == rva) {
            continue;
        }

        let va = image.image_base.checked_add(u64::from(rva));
        let executable = va.is_some_and(|va| {
            image.segments.iter().any(|segment| {
                segment.kind == SegmentKind::Load
                    && segment.flags & 1 != 0
                    && va >= segment.vaddr
                    && va - segment.vaddr < segment.filesz
            })
        });
        let rewritten = virt
            .iter()
            .any(|symbol| rva > symbol.rva && rva - symbol.rva < symbol.size);
        if !executable || rewritten {
            return Err(msg(format!(
                "unsupported ELF direct call target RVA {rva:#x}"
            )));
        }

        // The VM table contains selected entries only. Native callees use the
        // existing SysV bridge with an image-relative target.
        let reg = native_call_address(&mut block.ops, rva);
        block.exit = Exit::CallAbs { reg, next };
    }
    Ok(())
}

fn write_trampolines(
    file: &mut [u8],
    image: &ElfImage,
    virt: &[Sym],
    section_va: u64,
    layout: &Layout,
    passes: &mut Vec<String>,
) -> Result<Vec<(u32, u32)>> {
    let mut skips = Vec::new();
    for (index, symbol) in virt.iter().enumerate() {
        let target =
            section_va + u64::from(layout.tramp_off) + index as u64 * layout.tramp_len as u64;
        write_site(file, image, symbol, target)?;
        skips.push((symbol.rva, symbol.size));
        push_pass(passes, "trampoline");
    }
    Ok(skips)
}

fn write_site(file: &mut [u8], image: &ElfImage, symbol: &Sym, target: u64) -> Result<()> {
    if symbol.size < 5 {
        return Err(msg(format!(
            "{} is too small for a trampoline",
            symbol.name
        )));
    }
    let site = image.image_base + u64::from(symbol.rva);
    let next = site + 5;
    let rel = i32::try_from(
        i64::try_from(target).map_err(|_| msg("trampoline target does not fit"))?
            - i64::try_from(next).map_err(|_| msg("trampoline site does not fit"))?,
    )
    .map_err(|_| msg("trampoline is out of range"))?;
    let off = file_off(image, site)?;
    let end = off
        .checked_add(symbol.size as usize)
        .ok_or_else(|| msg("trampoline site is outside the file"))?;
    let slot = file
        .get_mut(off..end)
        .ok_or_else(|| msg("trampoline site is outside the file"))?;
    slot.fill(0xcc);
    slot[0] = 0xe9;
    slot[1..5].copy_from_slice(&rel.to_le_bytes());
    Ok(())
}

fn hashed_imports(image: &ElfImage) -> Result<Vec<(u32, u32)>> {
    let mut out = Vec::new();
    for import in &image.imports {
        let name = import.name.as_bytes();
        if name.is_empty() {
            continue;
        }
        let Some(got) = import.got else {
            if import.kind == SymbolKind::Func {
                return Err(msg(format!(
                    "{} has no got slot",
                    String::from_utf8_lossy(name)
                )));
            }
            continue;
        };
        out.push((va_rva(image, got)?, crate::syscall::slot_value(name)));
    }
    Ok(out)
}

fn encrypt_writable(
    file: &mut [u8],
    image: &ElfImage,
    seed: u64,
    skip: &[(u32, u32)],
) -> Result<Vec<(u32, u32, u8)>> {
    let strtab = strtab_span(image)?;
    let mut found = Vec::new();
    for index in 0..image.segments.len() {
        let segment = &image.segments[index];
        if segment.kind != SegmentKind::Load || segment.flags & 2 == 0 || segment.filesz == 0 {
            continue;
        }
        let base = file_off(image, segment.vaddr)?;
        let len = usize::try_from(segment.filesz).map_err(|_| msg("load segment is too large"))?;
        let rva_base = va_rva(image, segment.vaddr)?;
        let mut cursor = 0usize;
        while cursor < len {
            if !is_text(file[base + cursor]) || in_strtab(strtab, base + cursor) {
                cursor += 1;
                continue;
            }
            let start = cursor;
            while cursor < len && is_text(file[base + cursor]) && !in_strtab(strtab, base + cursor)
            {
                cursor += 1;
            }
            let run = (cursor - start) as u32;
            let rva = rva_base + start as u32;
            if cursor - start >= 6 && !overlaps(rva, run, skip) {
                let key = payload::string_key(seed, start as u8);
                payload::encrypt_span(&mut file[base + start..base + cursor], key);
                found.push((rva, run, key));
            }
        }
    }
    Ok(found)
}

fn strtab_span(image: &ElfImage) -> Result<Option<(usize, usize)>> {
    let (Some(addr), Some(size)) = (
        image.dynamic_value(DynamicTag::StrTab),
        image.dynamic_value(DynamicTag::StrSize),
    ) else {
        return Ok(None);
    };
    if size == 0 {
        return Ok(None);
    }
    let off = file_off(image, addr)?;
    let len = usize::try_from(size).map_err(|_| msg("string table is too large"))?;
    Ok(Some((off, len)))
}

fn in_strtab(span: Option<(usize, usize)>, off: usize) -> bool {
    span.is_some_and(|(start, len)| off >= start && off < start + len)
}

fn is_text(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

fn overlaps(rva: u32, len: u32, skip: &[(u32, u32)]) -> bool {
    let end = rva.saturating_add(len);
    skip.iter().any(|(start, size)| {
        let stop = start.saturating_add(*size);
        rva < stop && *start < end
    })
}

fn zero_import_names(file: &mut [u8], image: &ElfImage) -> Result<()> {
    for import in &image.imports {
        let name = import.name.as_bytes();
        if name.is_empty() {
            continue;
        }
        let mut from = 0usize;
        while let Some(at) = find_bounded(file, name, from) {
            file[at..at + name.len()].fill(0);
            from = at + name.len() + 1;
        }
    }
    Ok(())
}

fn find_bounded(file: &[u8], name: &[u8], from: usize) -> Option<usize> {
    let needle = name.len().checked_add(1)?;
    let rest = file.get(from..)?;
    if rest.len() < needle {
        return None;
    }
    for (index, window) in rest.windows(needle).enumerate() {
        if window[..name.len()] != *name || window[name.len()] != 0 {
            continue;
        }
        let at = from + index;
        if at == 0 || file[at - 1] == 0 {
            return Some(at);
        }
    }
    None
}

fn neutralize_relocs(file: &mut [u8], image: &ElfImage) -> Result<()> {
    for (addr_tag, size_tag) in [
        (DynamicTag::Rela, DynamicTag::RelaSize),
        (DynamicTag::JmpRel, DynamicTag::PltRelSize),
    ] {
        let (Some(addr), Some(size)) =
            (image.dynamic_value(addr_tag), image.dynamic_value(size_tag))
        else {
            continue;
        };
        if addr == 0 || size == 0 {
            continue;
        }
        if !size.is_multiple_of(24) {
            return Err(msg("relocation table is not a multiple of 24"));
        }
        let off = file_off(image, addr)?;
        let len = usize::try_from(size).map_err(|_| msg("relocation table is too large"))?;
        let table = file
            .get_mut(off..off + len)
            .ok_or_else(|| msg("relocation table is outside the file"))?;
        for entry in table.chunks_mut(24) {
            let info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            let kind = info as u32;
            if kind == GLOB_DAT || kind == JUMP_SLOT {
                entry[8..16].copy_from_slice(&(info & !0xffff_ffff).to_le_bytes());
            }
        }
    }
    Ok(())
}

fn mutate_elf(
    file: &mut [u8],
    image: &ElfImage,
    mutated: &[Sym],
    seed: u64,
    passes: &mut Vec<String>,
) -> Result<Vec<Sym>> {
    if mutated.is_empty() {
        return Ok(Vec::new());
    }
    let mut projected = project(image, file, true)?;
    let mut changed = Vec::new();
    for symbol in mutated {
        if let Some(substituted) = mutate_function(&mut projected, symbol, seed)? {
            changed.push(symbol.clone());
            note_mutation(passes, substituted);
        }
    }
    copy_back(file, image, &projected)?;
    Ok(changed)
}

fn project(image: &ElfImage, file: &[u8], slack: bool) -> Result<PeImage> {
    let mut sections = Vec::new();
    for segment in &image.segments {
        if segment.kind != SegmentKind::Load || segment.filesz == 0 {
            continue;
        }
        let rva = va_rva(image, segment.vaddr)?;
        let off = file_off(image, segment.vaddr)?;
        let len = usize::try_from(segment.filesz).map_err(|_| msg("load segment is too large"))?;
        let mut bytes = file
            .get(off..off + len)
            .ok_or_else(|| msg("load segment is outside the file"))?
            .to_vec();
        let characteristics = if segment.flags & 1 == 0 {
            pe::CH_DATA
        } else {
            pe::CH_TEXT
        };
        if slack && segment.flags & 1 != 0 {
            trim_tail(&mut bytes);
        }
        sections.push(Section {
            name: format!("load_{rva:x}"),
            rva,
            bytes,
            characteristics,
        });
    }
    sections.sort_by_key(|section| section.rva);
    Ok(PeImage {
        image_base: image.image_base,
        entry_rva: va_rva(image, image.entry)?,
        sections,
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
    })
}

fn trim_tail(bytes: &mut Vec<u8>) {
    while bytes.len() > 1 && bytes.last() == Some(&0) {
        bytes.pop();
    }
}

fn copy_back(file: &mut [u8], image: &ElfImage, projected: &PeImage) -> Result<()> {
    for section in &projected.sections {
        let segment = image
            .segments
            .iter()
            .find(|segment| {
                segment.kind == SegmentKind::Load
                    && segment.vaddr.saturating_sub(image.image_base) == u64::from(section.rva)
            })
            .ok_or_else(|| msg("mutated section left the load"))?;
        if section.bytes.len() as u64 > segment.filesz {
            return Err(msg("code cave does not fit in the load"));
        }
        let off = file_off(image, segment.vaddr)?;
        file[off..off + section.bytes.len()].copy_from_slice(&section.bytes);
    }
    Ok(())
}

struct Built<'a> {
    image: &'a ElfImage,
    lowered: &'a BcImage,
    strings: &'a payload::StringTables<'a>,
    imports: &'a [(u32, u32)],
    options: &'a Options,
    section_va: u64,
    layout: &'a Layout,
    socket: Option<&'a str>,
}

#[allow(clippy::too_many_arguments)]
fn build_body(
    image: &ElfImage,
    lowered: &BcImage,
    strings: &payload::StringTables<'_>,
    imports: &[(u32, u32)],
    options: &Options,
    section_va: u64,
    layout: &Layout,
    socket: Option<&str>,
) -> Result<(Vec<u8>, Header)> {
    let built = Built {
        image,
        lowered,
        strings,
        imports,
        options,
        section_va,
        layout,
        socket,
    };
    assemble_body(&built)
}

fn assemble_body(built: &Built<'_>) -> Result<(Vec<u8>, Header)> {
    let payload_addr = built.section_va + u64::from(built.layout.payload_off);
    let ready = prepare_payload(built, payload_addr)?;
    let original = va_rva(built.image, built.image.entry)?;
    let keys = key_span(built.lowered)?;
    let spare = built.layout.payload_off as usize + ready.sealed.ciphertext.len() + keys;
    let gs = align_up(built.section_va + spare as u64, 0x100);
    let vm_origin = aligned_vm_origin(built.section_va, built.layout);
    let mut vm = checked_vm(vm_origin, built.layout)?;
    stub::install_socket(&mut vm.bytes, built.socket)?;
    let tramps = trampolines(built, payload_addr, ready.runtime_base, vm_origin, &vm)?;
    let loader = sysv_loader(built, &ready, payload_addr, &vm, gs)?;
    let gs_end = gs_limit(gs, built.section_va)?;
    let mut body = Vec::with_capacity(gs_end);
    body.extend_from_slice(&[0u8; HEADER_LEN]);
    body.extend_from_slice(&loader);
    body.extend(std::iter::repeat_n(0u8, built.layout.vm_pad));
    body.extend_from_slice(&vm.bytes);
    body.extend_from_slice(&tramps);
    if body.len() != built.layout.payload_off as usize {
        return Err(msg("elf section layout moved between passes"));
    }
    body.extend_from_slice(&ready.sealed.ciphertext);
    body.extend(std::iter::repeat_n(0u8, keys));
    if body.len() != spare {
        return Err(msg("elf gs page moved"));
    }
    body.resize(gs_end, 0);
    let header = Header {
        payload_off: built.layout.payload_off,
        payload_len: ready.sealed.ciphertext.len() as u32,
        raw_len: ready.raw_len,
        crc32: vm::crc32(&ready.sealed.ciphertext),
        sha256: crypto::sha256(&ready.sealed.ciphertext),
        nonce: ready.sealed.nonce,
        tag: ready.sealed.tag,
        public: ready.sealed.public,
        signature: ready.sealed.signature,
        original_entry: original,
        image_base: built.image.image_base,
    };
    Ok((body, header))
}

fn gs_limit(gs: u64, section_va: u64) -> Result<usize> {
    let tail = u64::try_from(vm::GS_CHAIN_PTR + 8).map_err(|_| msg("elf gs page does not fit"))?;
    let page = tail.next_multiple_of(0x100);
    let end = gs
        .checked_sub(section_va)
        .and_then(|base| base.checked_add(page))
        .ok_or_else(|| msg("elf gs page does not fit"))?;
    usize::try_from(end).map_err(|_| msg("elf gs page does not fit"))
}

fn key_span(lowered: &BcImage) -> Result<usize> {
    let mut total = 0usize;
    for func in &lowered.funcs {
        let add = func
            .insns
            .len()
            .checked_mul(32)
            .ok_or_else(|| msg("vm keys do not fit"))?;
        total = total
            .checked_add(add)
            .ok_or_else(|| msg("vm keys do not fit"))?;
    }
    Ok(total)
}

fn checked_vm(origin: u64, layout: &Layout) -> Result<stub::NativeVm> {
    if !origin.is_multiple_of(8) {
        return Err(msg("vm origin is not 8-byte aligned"));
    }
    let vm = assemble_legacy_vm(origin, layout.external)?;
    if vm.bytes.len() != layout.vm_len
        || vm.frame != layout.vm_frame
        || vm.dispatch != layout.vm_dispatch
        || vm.calls != layout.vm_calls
    {
        return Err(msg("vm stub size changed between passes"));
    }
    Ok(vm)
}

fn trampolines(
    built: &Built<'_>,
    payload_addr: u64,
    runtime_base: u32,
    vm_origin: u64,
    vm: &stub::NativeVm,
) -> Result<Vec<u8>> {
    let mut tramps = Vec::new();
    for (index, func) in built.lowered.funcs.iter().enumerate() {
        let origin = built.section_va
            + u64::from(built.layout.tramp_off)
            + index as u64 * built.layout.tramp_len as u64;
        let bytes = stub::assemble_trampoline_mode(
            &Trampoline {
                origin,
                frame: vm_origin + vm.frame as u64,
                runtime: payload_addr + u64::from(runtime_base) + index as u64 * vm::RUNTIME_WINDOW,
                entry: func.entry,
                dispatch: vm_origin + vm.dispatch as u64,
                image_base: built.image.image_base,
                chains: vm_origin + vm.chains as u64,
            },
            built.layout.external,
        )?;
        if bytes.len() != built.layout.tramp_len {
            return Err(msg("trampoline size changed between passes"));
        }
        tramps.extend(bytes);
    }
    Ok(tramps)
}

struct Prepared {
    raw_len: u32,
    sealed: crypto::PayloadSeal,
    table_off: u32,
    import_off: u32,
    runtime_base: u32,
    runtime: u64,
}

fn prepare_payload(built: &Built<'_>, payload_addr: u64) -> Result<Prepared> {
    let (payload, table_off, runtime_base, import_off) = payload::layout_hashed(
        built.lowered,
        built.strings,
        payload_addr,
        built.imports,
        built.socket.is_some(),
    )?;
    let mut payload = crate::secret::WipeBuffer(payload);
    let runtime = stamp_linux(built, &mut payload.0, payload_addr, runtime_base)?;
    let original = va_rva(built.image, built.image.entry)?;
    let sealed = crypto::seal_payload(
        &payload.0,
        built.options.seed,
        built.options.random_key,
        original,
        built.image.image_base,
    )?;
    Ok(Prepared {
        raw_len: u32_of(payload.0.len(), "payload")?,
        sealed,
        table_off,
        import_off,
        runtime_base,
        runtime,
    })
}

fn stamp_linux(
    built: &Built<'_>,
    payload: &mut [u8],
    payload_addr: u64,
    runtime_base: u32,
) -> Result<u64> {
    let entry = va_rva(built.image, built.image.entry)?;
    let Some(index) = built
        .lowered
        .funcs
        .iter()
        .position(|func| func.rva == entry)
    else {
        return Ok(0);
    };
    let (mask, limit) = crate::antidebug::linux_arm();
    write_linux(payload, runtime_base, index, mask, limit)?;
    Ok(linux_addr(payload_addr, runtime_base, index))
}

fn write_linux(
    payload: &mut [u8],
    runtime_base: u32,
    index: usize,
    mask: u32,
    limit: u32,
) -> Result<()> {
    let at = linux_off(runtime_base, index)?;
    copy_at(payload, at + vm::RT_LINUX as usize, &mask.to_le_bytes())?;
    copy_at(payload, at + vm::RT_CLOCK_NS as usize, &limit.to_le_bytes())
}

fn linux_off(runtime_base: u32, index: usize) -> Result<usize> {
    let step = index
        .checked_mul(vm::RUNTIME_WINDOW as usize)
        .ok_or_else(|| msg("linux runtime overflows"))?;
    (runtime_base as usize)
        .checked_add(step)
        .ok_or_else(|| msg("linux runtime overflows"))
}

fn linux_addr(payload_addr: u64, runtime_base: u32, index: usize) -> u64 {
    payload_addr + u64::from(runtime_base) + index as u64 * vm::RUNTIME_WINDOW
}

fn copy_at(payload: &mut [u8], at: usize, bytes: &[u8]) -> Result<()> {
    let end = at
        .checked_add(bytes.len())
        .ok_or_else(|| msg("linux mask is outside the payload"))?;
    payload
        .get_mut(at..end)
        .ok_or_else(|| msg("linux mask is outside the payload"))?
        .copy_from_slice(bytes);
    Ok(())
}

fn sysv_loader(
    built: &Built<'_>,
    ready: &Prepared,
    payload_addr: u64,
    vm: &stub::NativeVm,
    gs: u64,
) -> Result<Vec<u8>> {
    let plan = sysv_plan(built, ready, payload_addr, vm, gs)?;
    let loader = loader::assemble_sysv(&plan)?;
    if loader.len() != built.layout.loader_len {
        return Err(msg("loader size changed between passes"));
    }
    Ok(loader)
}

fn sysv_plan(
    built: &Built<'_>,
    ready: &Prepared,
    payload_addr: u64,
    vm: &stub::NativeVm,
    gs: u64,
) -> Result<SysvPlan> {
    let loader_origin = built.section_va + HEADER_LEN as u64;
    let vm_origin = aligned_vm_origin(built.section_va, built.layout);
    let plan = SysvPlan {
        origin: loader_origin,
        payload: payload_addr,
        payload_len: u32_of(ready.sealed.ciphertext.len(), "payload")?,
        checksum: loader::checksum(&ready.sealed.ciphertext),
        aead_key: ready.sealed.key,
        aead_nonce: ready.sealed.nonce,
        strings: payload_addr,
        imports: payload_addr + u64::from(ready.import_off),
        table: payload_addr + u64::from(ready.table_off),
        calls: vm_origin + vm.calls as u64,
        image_base: built.image.image_base,
        dynamic: dynamic_va(built.image)?,
        original: built.image.entry,
        gs,
        runtime: ready.runtime,
    };
    fit_plan(&plan)?;
    Ok(plan)
}

fn fit_plan(plan: &SysvPlan) -> Result<()> {
    for addr in [
        plan.origin,
        plan.payload,
        plan.strings,
        plan.imports,
        plan.table,
        plan.calls,
        plan.image_base,
        plan.dynamic,
        plan.original,
        plan.gs,
        plan.runtime,
    ] {
        fit_addr(addr)?;
    }
    Ok(())
}

fn aligned_vm_origin(section_va: u64, layout: &Layout) -> u64 {
    section_va + HEADER_LEN as u64 + layout.loader_len as u64 + layout.vm_pad as u64
}

fn measure(section_va: u64, functions: usize, external: bool) -> Result<Layout> {
    let loader_len = loader::assemble_sysv(&dummy_plan(0x403200))?.len();
    let raw = section_va + HEADER_LEN as u64 + loader_len as u64;
    let vm_pad = stub::align_pad(raw);
    let vm = assemble_legacy_vm(raw + vm_pad as u64, external)?;
    let tramp_len = stub::trampoline_len_mode(external)?;
    let head = HEADER_LEN + loader_len + vm_pad + vm.bytes.len();
    let tramp_off = u32_of(head, "trampolines")?;
    let payload_off = tramp_off
        .checked_add(u32_of(tramp_len.saturating_mul(functions), "payload")?)
        .ok_or_else(|| msg("elf section is too large"))?;
    Ok(Layout {
        external,
        loader_len,
        vm_pad,
        vm_len: vm.bytes.len(),
        vm_frame: vm.frame,
        vm_dispatch: vm.dispatch,
        vm_calls: vm.calls,
        tramp_len,
        tramp_off,
        payload_off,
    })
}

fn assemble_legacy_vm(origin: u64, external: bool) -> Result<stub::NativeVm> {
    if external {
        stub::assemble_vm_for_external_lab(origin)
    } else {
        stub::assemble_vm(origin)
    }
}

fn dummy_plan(origin: u64) -> SysvPlan {
    SysvPlan {
        origin,
        payload: origin + 0x2000,
        payload_len: 32,
        checksum: 0,
        aead_key: [0; 32],
        aead_nonce: [0; 12],
        strings: origin + 0x2000,
        imports: origin + 0x2100,
        table: origin + 0x2200,
        calls: origin + 0x1800,
        image_base: 0x400000,
        dynamic: 0x402010,
        original: 0x401000,
        gs: origin + 0x3000,
        runtime: origin + 0x4000,
    }
}

fn install_section(
    file: &mut Vec<u8>,
    image: &ElfImage,
    section_va: u64,
    body: &[u8],
    name: &str,
) -> Result<u32> {
    let file_off = align_up(file.len() as u64, PAGE);
    if file_off != file.len() as u64 {
        file.resize(file_off as usize, 0);
    }
    file.extend_from_slice(body);
    let filesz = align_up(body.len() as u64, PAGE);
    file.resize(file_off as usize + filesz as usize, 0);
    write_load(file, file_off, section_va, filesz)?;
    let entry = section_va + HEADER_LEN as u64;
    file[24..32].copy_from_slice(&entry.to_le_bytes());
    write_sections(file, file_off, section_va, body.len() as u64, name)?;
    va_rva(image, entry)
}

fn body_file_off(file: &[u8], section_va: u64) -> Result<usize> {
    file_off(&elf::parse(file)?, section_va)
}

fn write_load(file: &mut [u8], offset: u64, vaddr: u64, filesz: u64) -> Result<()> {
    let (phoff, phentsize, phnum) = phdrs(file)?;
    let mut slot = None;
    for index in 0..phnum {
        let at = phoff + index * phentsize;
        let kind = u32::from_le_bytes(file[at..at + 4].try_into().unwrap());
        if kind == 0 {
            slot = Some(at);
            break;
        }
    }
    let Some(at) = slot else {
        return Err(msg("elf has no spare program header"));
    };
    let mut header = [0u8; 56];
    header[0..4].copy_from_slice(&1u32.to_le_bytes());
    header[4..8].copy_from_slice(&7u32.to_le_bytes());
    header[8..16].copy_from_slice(&offset.to_le_bytes());
    header[16..24].copy_from_slice(&vaddr.to_le_bytes());
    header[24..32].copy_from_slice(&vaddr.to_le_bytes());
    header[32..40].copy_from_slice(&filesz.to_le_bytes());
    header[40..48].copy_from_slice(&filesz.to_le_bytes());
    header[48..56].copy_from_slice(&PAGE.to_le_bytes());
    file[at..at + 56].copy_from_slice(&header);
    Ok(())
}

fn write_sections(
    file: &mut Vec<u8>,
    body_off: u64,
    body_va: u64,
    body_len: u64,
    name: &str,
) -> Result<()> {
    let mut strings = b"\0.shstrtab\0".to_vec();
    let name_at = u32::try_from(strings.len()).map_err(|_| msg("section name overflows"))?;
    strings.extend_from_slice(name.as_bytes());
    strings.push(0);
    let str_off = file.len() as u64;
    file.extend_from_slice(&strings);
    let shoff = file.len() as u64;
    file.extend_from_slice(&[0u8; 64]);
    file.extend_from_slice(&shdr(1, 3, 0, 0, str_off, strings.len() as u64, 1));
    file.extend_from_slice(&shdr(name_at, 1, 7, body_va, body_off, body_len, 16));
    file[40..48].copy_from_slice(&shoff.to_le_bytes());
    file[58..60].copy_from_slice(&64u16.to_le_bytes());
    file[60..62].copy_from_slice(&3u16.to_le_bytes());
    file[62..64].copy_from_slice(&1u16.to_le_bytes());
    Ok(())
}

fn shdr(
    name: u32,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    align: u64,
) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..4].copy_from_slice(&name.to_le_bytes());
    out[4..8].copy_from_slice(&kind.to_le_bytes());
    out[8..16].copy_from_slice(&flags.to_le_bytes());
    out[16..24].copy_from_slice(&addr.to_le_bytes());
    out[24..32].copy_from_slice(&offset.to_le_bytes());
    out[32..40].copy_from_slice(&size.to_le_bytes());
    out[48..56].copy_from_slice(&align.to_le_bytes());
    out
}

fn phdrs(file: &[u8]) -> Result<(usize, usize, usize)> {
    if file.len() < 64 {
        return Err(msg("elf header is truncated"));
    }
    let phoff = u64::from_le_bytes(file[32..40].try_into().unwrap());
    let phentsize = u16::from_le_bytes(file[54..56].try_into().unwrap());
    let phnum = u16::from_le_bytes(file[56..58].try_into().unwrap());
    if phentsize != 56 {
        return Err(msg("unexpected program header size"));
    }
    let phoff = usize::try_from(phoff).map_err(|_| msg("program headers are outside the file"))?;
    let phnum = usize::from(phnum);
    let end = phoff
        .checked_add(phnum.saturating_mul(56))
        .ok_or_else(|| msg("program headers are outside the file"))?;
    if end > file.len() {
        return Err(msg("program headers are outside the file"));
    }
    Ok((phoff, 56, phnum))
}

fn next_va(image: &ElfImage) -> Result<u64> {
    let end = image
        .segments
        .iter()
        .filter(|segment| segment.kind == SegmentKind::Load)
        .map(|segment| segment.vaddr.saturating_add(segment.memsz))
        .max()
        .unwrap_or(image.image_base);
    Ok(align_up(end, PAGE))
}

fn dynamic_va(image: &ElfImage) -> Result<u64> {
    image
        .segments
        .iter()
        .find(|segment| segment.kind == SegmentKind::Dynamic && segment.vaddr != 0)
        .map(|segment| segment.vaddr)
        .ok_or_else(|| msg("elf has no dynamic segment"))
}

fn align_up(value: u64, page: u64) -> u64 {
    value.div_ceil(page) * page
}

fn va_rva(image: &ElfImage, va: u64) -> Result<u32> {
    let rva = va
        .checked_sub(image.image_base)
        .ok_or_else(|| msg("address is below the image base"))?;
    u32::try_from(rva).map_err(|_| msg("rva does not fit"))
}

fn file_off(image: &ElfImage, va: u64) -> Result<usize> {
    for segment in &image.segments {
        if segment.kind != SegmentKind::Load || segment.filesz == 0 {
            continue;
        }
        let end = segment.vaddr.saturating_add(segment.filesz);
        if va >= segment.vaddr && va < end {
            let off = segment.offset + (va - segment.vaddr);
            return usize::try_from(off).map_err(|_| msg("file offset does not fit"));
        }
    }
    Err(msg(format!("address {va:#x} is not in a load segment")))
}

fn read_span<'a>(file: &'a [u8], image: &ElfImage, va: u64, len: usize) -> Result<&'a [u8]> {
    let off = file_off(image, va)?;
    file.get(off..off + len)
        .ok_or_else(|| msg("function is outside the file"))
}

fn utf8(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| msg("symbol name is not utf-8"))
}

fn u32_of(value: usize, what: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| msg(format!("{what} does not fit")))
}

fn fit_addr(addr: u64) -> Result<()> {
    i32::try_from(addr)
        .map(|_| ())
        .map_err(|_| msg("elf address does not fit the sysv loader"))
}
