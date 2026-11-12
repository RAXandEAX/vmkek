use super::*;
use crate::crypto::authenticated::{
    BlockPurpose, BlockScope, BootstrapContext, BootstrapSealer, LabBootstrapKey, ManufacturerPin,
    MasterSecret, Platform, Profile, SealedBootstrap, BOOTSTRAP_CORE_LEN, BOOTSTRAP_MANIFEST_LEN,
    BOOTSTRAP_SIGNATURE_OFFSET, ELF_LAB_ENTRY_AFTER_MANIFEST, ELF_LAB_HELPER_VA,
};
use crate::elf::{RelocKind, SymbolSection};
use crate::error::exact_bytes;
use crate::protect::NativeAuthentication;

const LOAD_RX: u32 = 5;
const LOAD_RW: u32 = 6;
const WRAPPER_ROOM: usize = 512;
const PAGE_USIZE: usize = PAGE as usize;
const BUILD_PASS: &str = "authenticated-bootstrap";

pub(in crate::protect) fn protect_authenticated(
    input: &[u8],
    options: &Options,
    auth: &NativeAuthentication<'_>,
    helper: &[u8],
) -> Result<Protected> {
    let image = elf::parse(input)?;
    validate_input(&image, options)?;
    validate_loads(&image)?;
    let helper = trusted_helper(helper)?;
    let master = MasterSecret::generate()?;
    let scope = BlockScope::for_new_build(auth.application_id, [0; 16], 1, BlockPurpose::Payload)?;
    let layout_input = Input {
        file: input,
        image: &image,
        options,
        auth,
        helper,
        master: &master,
        scope,
    };
    let symbols = discover_local_functions(&image, input, options)?;
    let (virt, _) = select(&symbols, options, false)?;
    validate_selection(&image, &virt)?;
    let (funcs, passes) = virtualize(input, &image, &virt, options.seed, true)?;
    let mut rng = ChaCha20Rng::seed_from_u64(options.seed);
    let lowered = vm::lower_image_scoped(&funcs.0, &mut rng, &master, scope)?;
    drop(funcs);
    build_authenticated(&layout_input, &virt, &lowered, passes)
}

fn validate_input(image: &ElfImage, options: &Options) -> Result<()> {
    if image.kind != ElfKind::Executable
        || image.pie
        || image.entry == 0
        || image
            .interp
            .as_ref()
            .is_none_or(|item| item != "/lib64/ld-linux-x86-64.so.2")
        || image.needed.len() != 1
        || image.needed[0] != "libc.so.6"
        || image
            .segments
            .iter()
            .filter(|item| item.kind == SegmentKind::Dynamic)
            .count()
            != 1
        || image.rpath.is_some()
        || image.runpath.is_some()
        || image.init.is_some()
        || image.init_array.is_some()
        || image.preinit_array.is_some()
        || image
            .relocations
            .iter()
            .any(|item| item.kind == RelocKind::Irelative)
        || image
            .dynamic_symbols
            .iter()
            .any(|item| item.kind == SymbolKind::Ifunc)
        || image.dynamic.iter().any(|item| {
            matches!(
                item.tag,
                DynamicTag::Init
                    | DynamicTag::InitArray
                    | DynamicTag::InitArraySize
                    | DynamicTag::PreinitArray
                    | DynamicTag::PreinitArraySize
                    | DynamicTag::TextRel
                    | DynamicTag::Other(0x6fff_fefb | 0x6fff_fefc | 0x7fff_fffd | 0x7fff_ffff)
            ) || (item.tag == DynamicTag::Flags && item.value & 4 != 0)
        })
    {
        return Err(msg("authenticated ELF lab requires a fixed glibc executable without existing startup hooks"));
    }
    if !image.exports.is_empty() {
        return Err(msg(
            "authenticated ELF lab rejects executable exports before entry",
        ));
    }
    if options.virtualize_all
        || options.virtualize.is_empty()
        || options.mutate_all
        || !options.mutate.is_empty()
        || options.random_key
    {
        return Err(msg(
            "authenticated ELF lab requires explicit function selection and independent signing",
        ));
    }
    Ok(())
}

fn discover_local_functions(image: &ElfImage, file: &[u8], options: &Options) -> Result<Vec<Sym>> {
    let mut symbols = Vec::new();
    for symbol in image.symbols.iter().chain(&image.dynamic_symbols) {
        if symbol.kind != SymbolKind::Func
            || !matches!(symbol.section, SymbolSection::Index(_))
            || symbol.name.is_empty()
        {
            continue;
        }
        let rva = va_rva(image, symbol.value)?;
        if symbols.iter().any(|item: &Sym| item.rva == rva) {
            continue;
        }
        let (size, explicit_size) = fit_size(symbol.size)?;
        symbols.push(Sym {
            name: utf8(symbol.name.as_bytes())?,
            rva,
            size,
            explicit_size,
        });
    }
    apply_rva_selectors(&mut symbols, options)?;
    symbols.sort_by_key(|item| item.rva);
    fill_sizes(image, file, &mut symbols)?;
    Ok(symbols)
}

fn validate_loads(image: &ElfImage) -> Result<()> {
    let mut ranges = Vec::new();
    for segment in &image.segments {
        match segment.kind {
            SegmentKind::Load => {
                if segment.flags & 3 == 3 || segment.align != PAGE {
                    return Err(msg("authenticated ELF lab requires page-aligned W^X loads"));
                }
                let end = segment
                    .vaddr
                    .checked_add(segment.memsz)
                    .and_then(|end| end.checked_next_multiple_of(PAGE))
                    .filter(|end| *end <= ELF_LAB_HELPER_VA)
                    .ok_or_else(|| msg("ELF load overlaps the fixed verifier address"))?;
                let start = segment.vaddr & !(PAGE - 1);
                if ranges
                    .iter()
                    .any(|range: &std::ops::Range<u64>| range.start < end && start < range.end)
                {
                    return Err(msg("authenticated ELF lab rejects overlapping load pages"));
                }
                ranges.push(start..end);
            }
            SegmentKind::GnuProperty => {
                return Err(msg("authenticated ELF lab does not support GNU properties"))
            }
            _ => {}
        }
    }
    if image
        .segments
        .iter()
        .filter(|item| item.kind == SegmentKind::GnuStack)
        .map(|item| item.flags)
        .collect::<Vec<_>>()
        != [LOAD_RW]
    {
        return Err(msg(
            "authenticated ELF lab requires a non-executable GNU stack",
        ));
    }
    if !is_executable_span(image, image.entry, 1) {
        return Err(msg("ELF original entry is outside an executable load"));
    }
    Ok(())
}

fn is_executable_span(image: &ElfImage, address: u64, len: u64) -> bool {
    image.segments.iter().any(|item| {
        item.kind == SegmentKind::Load
            && item.flags == LOAD_RX
            && address
                .checked_sub(item.vaddr)
                .and_then(|offset| offset.checked_add(len))
                .is_some_and(|end| end <= item.filesz)
    })
}

fn validate_selection(image: &ElfImage, symbols: &[Sym]) -> Result<()> {
    for symbol in symbols {
        let start = image
            .image_base
            .checked_add(u64::from(symbol.rva))
            .ok_or_else(|| msg("symbol address overflows"))?;
        let end = start
            .checked_add(u64::from(symbol.size))
            .ok_or_else(|| msg("symbol extent overflows"))?;
        if !is_executable_span(image, start, u64::from(symbol.size)) {
            return Err(msg("selected ELF symbol is outside an executable load"));
        }
        if (start..end).contains(&image.entry) {
            return Err(msg(
                "authenticated ELF lab leaves the original entry native",
            ));
        }
    }
    Ok(())
}

struct Helper<'a> {
    bytes: &'a [u8],
    entry: u64,
}

fn trusted_helper(file: &[u8]) -> Result<Helper<'_>> {
    if file.len() > 128 * 1024 {
        return Err(msg("trusted ELF verifier file exceeds size limit"));
    }
    let image = elf::parse(file)?;
    let [load] = image.segments.as_slice() else {
        return Err(msg("ELF verifier must have one RX load"));
    };
    let range = load.vaddr
        ..load
            .vaddr
            .checked_add(load.filesz)
            .ok_or_else(|| msg("ELF verifier address overflows"))?;
    if image.kind != ElfKind::Executable
        || image.pie
        || load.kind != SegmentKind::Load
        || load.flags != LOAD_RX
        || load.align != PAGE
        || load.vaddr != ELF_LAB_HELPER_VA
        || load.filesz != load.memsz
        || load.filesz > 64 * 1024
        || !range.contains(&image.entry)
        || load.offset % PAGE != 0
        || !image.relocations.is_empty()
        || !image.dynamic.is_empty()
    {
        return Err(msg("unexpected trusted ELF verifier layout"));
    }
    let start =
        usize::try_from(load.offset).map_err(|_| msg("ELF verifier file offset overflows"))?;
    let len = usize::try_from(load.filesz).map_err(|_| msg("ELF verifier length overflows"))?;
    let bytes = file
        .get(
            start
                ..start
                    .checked_add(len)
                    .ok_or_else(|| msg("ELF verifier extent overflows"))?,
        )
        .ok_or_else(|| msg("ELF verifier is outside the file"))?;
    Ok(Helper {
        bytes,
        entry: image.entry,
    })
}

struct Input<'a> {
    file: &'a [u8],
    image: &'a ElfImage,
    options: &'a Options,
    auth: &'a NativeAuthentication<'a>,
    helper: Helper<'a>,
    master: &'a MasterSecret,
    scope: BlockScope,
}

struct Layout {
    manifest: usize,
    expected: usize,
    pin: usize,
    wrapper: usize,
    tramp: usize,
    vm: usize,
    split: usize,
    payload: usize,
}

impl Layout {
    fn new(helper_len: usize, probe: &stub::NativeVm, tramp_bytes: usize) -> Self {
        let manifest = helper_len.next_multiple_of(16);
        let expected = manifest + BOOTSTRAP_MANIFEST_LEN;
        let pin = expected + BOOTSTRAP_CORE_LEN;
        let wrapper = manifest + ELF_LAB_ENTRY_AFTER_MANIFEST;
        let tramp = wrapper + WRAPPER_ROOM;
        let split = (tramp + tramp_bytes + probe.frame).next_multiple_of(PAGE_USIZE);
        let vm = split - probe.frame;
        let payload = (vm + probe.bytes.len()).next_multiple_of(16);
        Self {
            manifest,
            expected,
            pin,
            wrapper,
            tramp,
            vm,
            split,
            payload,
        }
    }

    fn va(&self, offset: usize) -> u64 {
        ELF_LAB_HELPER_VA + offset as u64
    }
}

fn build_authenticated(
    input: &Input<'_>,
    symbols: &[Sym],
    lowered: &BcImage,
    mut passes: Vec<String>,
) -> Result<Protected> {
    let probe =
        stub::assemble_vm_seeded_for_authenticated_lab(ELF_LAB_HELPER_VA, input.options.seed)?;
    let tramp_len = stub::trampoline_len()?;
    let layout = Layout::new(input.helper.bytes.len(), &probe, tramp_len * symbols.len());
    let vm_origin = layout.va(layout.vm);
    let stub = stub::assemble_vm_seeded_for_authenticated_lab(vm_origin, input.options.seed)?;
    if stub.frame != probe.frame || stub.bytes.len() != probe.bytes.len() {
        return Err(msg("ELF authenticated VM layout changed"));
    }
    let file_off = input.file.len().next_multiple_of(PAGE_USIZE);
    let body = build_body(input, lowered, &stub, &layout, file_off)?;
    let mut file = input.file.to_vec();
    for (i, symbol) in symbols.iter().enumerate() {
        write_site(
            &mut file,
            input.image,
            symbol,
            layout.va(layout.tramp + i * tramp_len),
        )?;
    }
    install_body(&mut file, input.image, &body, &layout, file_off)?;
    push_pass(&mut passes, "trampoline");
    push_pass(&mut passes, BUILD_PASS);
    let report = assemble_report(
        input.options.debug_seed.then_some(input.options.seed),
        input.options.seed,
        passes,
        (symbols, &[]),
        va_rva(input.image, layout.va(layout.wrapper))?,
        (&body.header, &file),
        lowered,
    )?;
    Ok(Protected {
        bytes: file,
        report,
        custody: None,
    })
}

struct Body {
    bytes: Vec<u8>,
    header: Header,
}

fn build_body(
    input: &Input<'_>,
    lowered: &BcImage,
    stub: &stub::NativeVm,
    layout: &Layout,
    file_off: usize,
) -> Result<Body> {
    let payload_va = layout.va(layout.payload);
    let payload::AuthenticatedElfPayload {
        bytes: payload,
        table_off,
        runtimes,
    } = payload::layout_authenticated_elf(lowered, payload_va)?;
    let original_rva = va_rva(input.image, input.image.entry)?;
    let (sealed, key) = seal_payload(input, &payload.0, file_off + layout.payload, original_rva)?;
    let end = layout.payload + payload.0.len() + key_span(lowered)?;
    let state = end.next_multiple_of(16);
    let plan = loader::ElfAuthPlan {
        origin: layout.va(layout.wrapper),
        verifier: input.helper.entry,
        manifest: layout.va(layout.manifest),
        expected: layout.va(layout.expected),
        trusted_public: layout.va(layout.pin),
        key: layout.va(state),
        payload: payload_va,
        payload_len: u32_of(payload.0.len(), "payload")?,
        table: payload_va + u64::from(table_off),
        calls: layout.va(layout.vm + stub.calls),
        original: input.image.entry,
    };
    let wrapper = loader::assemble_elf_auth(&plan)?;
    if wrapper.len() > WRAPPER_ROOM {
        return Err(msg("ELF auth wrapper exceeded its code slot"));
    }
    let mut bytes = vec![0; (state + 32).next_multiple_of(PAGE_USIZE)];
    copy_at(&mut bytes, 0, input.helper.bytes)?;
    copy_at(&mut bytes, layout.manifest, &sealed.manifest)?;
    copy_at(
        &mut bytes,
        layout.expected,
        &sealed.manifest[..BOOTSTRAP_CORE_LEN],
    )?;
    copy_at(&mut bytes, layout.pin, input.auth.trusted_public)?;
    copy_at(&mut bytes, layout.wrapper, &wrapper)?;
    copy_at(&mut bytes, layout.vm, &stub.bytes)?;
    copy_at(&mut bytes, layout.payload, &sealed.ciphertext)?;
    copy_at(&mut bytes, state, key.as_bytes())?;
    write_trampolines(&mut bytes, input, lowered, stub, layout, &runtimes)?;
    // The report reads the signing identity, while the ELF stores the v2 manifest.
    let header = Header {
        payload_off: 0,
        payload_len: plan.payload_len,
        raw_len: plan.payload_len,
        crc32: 0,
        sha256: crypto::sha256(&sealed.ciphertext),
        nonce: [0; 12],
        tag: [0; 16],
        public: *input.auth.trusted_public,
        signature: exact_bytes(&sealed.manifest[BOOTSTRAP_SIGNATURE_OFFSET..])?,
        original_entry: original_rva,
        image_base: input.image.image_base,
    };
    Ok(Body { bytes, header })
}

fn write_trampolines(
    bytes: &mut [u8],
    input: &Input<'_>,
    lowered: &BcImage,
    vm: &stub::NativeVm,
    layout: &Layout,
    runtimes: &[u64],
) -> Result<()> {
    if lowered.funcs.len() != runtimes.len() {
        return Err(msg(
            "ELF runtime layout does not cover the selected functions",
        ));
    }
    let len = stub::trampoline_len()?;
    for (index, (func, &runtime)) in lowered.funcs.iter().zip(runtimes).enumerate() {
        let offset = layout.tramp + index * len;
        let trampoline = stub::assemble_trampoline(&Trampoline {
            origin: layout.va(offset),
            frame: layout.va(layout.vm + vm.frame),
            runtime,
            entry: func.entry,
            dispatch: layout.va(layout.vm + vm.dispatch),
            image_base: input.image.image_base,
            chains: layout.va(layout.vm + vm.chains),
        })?;
        if trampoline.len() != len {
            return Err(msg("ELF trampoline layout changed"));
        }
        copy_at(bytes, offset, &trampoline)?;
    }
    Ok(())
}

fn seal_payload(
    input: &Input<'_>,
    plaintext: &[u8],
    file_off: usize,
    original_rva: u32,
) -> Result<(SealedBootstrap, LabBootstrapKey)> {
    let context = BootstrapContext {
        platform: Platform::Elf64,
        profile: Profile::Lab,
        scope: input.scope,
        payload_offset: file_off as u64,
        payload_len: u32_of(plaintext.len(), "payload")?,
        original_entry_rva: original_rva,
        preferred_base: input.image.image_base,
    };
    let key = input.master.scope(input.scope)?;
    let pin = ManufacturerPin::from_sec1(input.auth.trusted_public)?;
    BootstrapSealer::new(&key).seal_for_elf_lab(&context, &pin, input.auth.signing_key, plaintext)
}

fn install_body(
    file: &mut Vec<u8>,
    image: &ElfImage,
    body: &Body,
    layout: &Layout,
    file_off: usize,
) -> Result<()> {
    let (phoff, phsize, phnum) = phdrs(file)?;
    let table_end = phoff + phsize * phnum;
    let new_end = table_end + phsize;
    if !image
        .segments
        .last()
        .is_some_and(|segment| segment.kind == SegmentKind::Null)
    {
        return Err(msg("authenticated ELF lab requires a final PT_NULL slot"));
    }
    if file
        .get(table_end..new_end)
        .is_none_or(|gap| gap != [0; 56])
    {
        return Err(msg(
            "authenticated ELF lab requires one unused program header extent",
        ));
    }
    let phdr = header_slot(image, SegmentKind::Phdr, phoff)?;
    validate_phdr_growth(image, phoff, table_end, new_end, phdr)?;
    let count = u16::try_from(phnum + 1).map_err(|_| msg("too many ELF program headers"))?;
    let header_len = (phsize * usize::from(count)) as u64;
    file[56..58].copy_from_slice(&count.to_le_bytes());
    file[phdr + 32..phdr + 40].copy_from_slice(&header_len.to_le_bytes());
    file[phdr + 40..phdr + 48].copy_from_slice(&header_len.to_le_bytes());
    load(
        file,
        table_end - phsize,
        1,
        LOAD_RX,
        file_off,
        layout.va(0),
        layout.split,
        PAGE,
    )?;
    load(
        file,
        table_end,
        1,
        LOAD_RW,
        file_off + layout.split,
        layout.va(layout.split),
        body.bytes.len() - layout.split,
        PAGE,
    )?;
    file[24..32].copy_from_slice(&layout.va(layout.wrapper).to_le_bytes());
    file.resize(file_off, 0);
    file.extend_from_slice(&body.bytes);
    Ok(())
}

fn validate_phdr_growth(
    image: &ElfImage,
    phoff: usize,
    old_end: usize,
    new_end: usize,
    phdr: usize,
) -> Result<()> {
    let old_end = old_end as u64;
    let new_end = new_end as u64;
    let ph = &image.segments[(phdr - phoff) / 56];
    let table_start = phoff as u64;
    let len = old_end - table_start;
    if ph.offset != table_start
        || ph.filesz != len
        || ph.memsz != len
        || !image.segments.iter().any(|segment| {
            segment.kind == SegmentKind::Load
                && segment.offset == 0
                && segment.flags & 4 != 0
                && segment.filesz >= new_end
                && segment.vaddr.checked_add(table_start) == Some(ph.vaddr)
        })
    {
        return Err(msg(
            "ELF program header table is not mapped at its declared address",
        ));
    }
    let overlaps = |off: u64, len: u64| {
        len != 0 && off < new_end && off.checked_add(len).is_none_or(|end| end > old_end)
    };
    if image.segments.iter().any(|item| {
        !matches!(item.kind, SegmentKind::Load | SegmentKind::Phdr)
            && overlaps(item.offset, item.filesz)
    }) || image
        .sections
        .iter()
        .any(|item| item.kind != elf::SectionKind::Nobits && overlaps(item.offset, item.size))
    {
        return Err(msg(
            "ELF program header growth would overwrite file contents",
        ));
    }
    Ok(())
}

fn header_slot(image: &ElfImage, kind: SegmentKind, phoff: usize) -> Result<usize> {
    let mut matches = image
        .segments
        .iter()
        .enumerate()
        .filter(|(_, item)| item.kind == kind);
    let Some((index, _)) = matches.next() else {
        return Err(msg("required ELF program header missing"));
    };
    if matches.next().is_some() {
        return Err(msg("required ELF program header is ambiguous"));
    }
    Ok(phoff + index * 56)
}

#[allow(clippy::too_many_arguments)]
fn load(
    file: &mut [u8],
    slot: usize,
    kind: u32,
    flags: u32,
    offset: usize,
    va: u64,
    len: usize,
    align: u64,
) -> Result<()> {
    let mut bytes = [0; 56];
    bytes[..4].copy_from_slice(&kind.to_le_bytes());
    bytes[4..8].copy_from_slice(&flags.to_le_bytes());
    for (index, value) in [offset as u64, va, va, len as u64, len as u64, align]
        .into_iter()
        .enumerate()
    {
        let at = 8 + index * 8;
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    copy_at(file, slot, &bytes)
}
