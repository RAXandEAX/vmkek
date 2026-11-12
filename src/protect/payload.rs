use crate::crypto::authenticated::{
    BootstrapContext, BootstrapSealer, ManufacturerPin, Platform, Profile, BOOTSTRAP_CORE_LEN,
    BOOTSTRAP_MANIFEST_LEN, BOOTSTRAP_MAX_PAYLOAD, BOOTSTRAP_NONCE_OFFSET,
    BOOTSTRAP_SIGNATURE_OFFSET, BOOTSTRAP_TAG_OFFSET,
};
use crate::crypto::{self, Header, HEADER_LEN};
use crate::error::{exact_bytes, msg, Result};
use crate::loader::{self, LoaderPlan};
use crate::pe::{PeImage, Section, CH_DATA, CH_TEXT};
use crate::stub;
use crate::vm::{self, BcImage};

use super::{Built, CodeLayout, NativeAuth, Options};

pub(super) fn build_section(
    image: &PeImage,
    lowered: &BcImage,
    strings: &StringTables<'_>,
    options: &Options,
    layout: &CodeLayout,
    cave: u64,
    authentication: Option<&NativeAuth<'_>>,
) -> Result<Built> {
    let seed = options.seed;
    let payload_rva = layout
        .section_rva
        .checked_add(layout.payload_off)
        .ok_or_else(|| msg("PE payload RVA overflows"))?;
    let payload_addr = image
        .image_base
        .checked_add(u64::from(payload_rva))
        .ok_or_else(|| msg("PE payload address overflows"))?;
    let data_base = image.image_base + u64::from(layout.data_rva);
    let (cache_offsets, tls_size) = pe_tls_layout(layout.windows_native, lowered)?;
    let _tls = layout
        .windows_native
        .then(|| stub::bind_pe_tls(data_base, tls_size));
    let _cfg = layout.guarded.then(stub::bind_pe_guarded).transpose()?;
    let (payload, table_off, runtime_base, import_off) =
        layout_payload_with_tls(lowered, strings, payload_addr, image, seed, &cache_offsets)?;
    let (raw_len, material) = seal_bound(payload, options, image, payload_rva, authentication)?;
    assemble_section(
        image,
        lowered,
        layout,
        seed,
        tls_size,
        PeSectionPayload {
            material,
            raw_len,
            payload_addr,
            table_off,
            runtime_base,
            import_off,
            cave,
        },
    )
}

struct PeSectionPayload {
    material: PayloadMaterial,
    raw_len: usize,
    payload_addr: u64,
    table_off: u32,
    runtime_base: u32,
    import_off: u32,
    cave: u64,
}

fn assemble_section(
    image: &PeImage,
    lowered: &BcImage,
    layout: &CodeLayout,
    seed: u64,
    tls_size: u32,
    payload: PeSectionPayload,
) -> Result<Built> {
    let PeSectionPayload {
        material,
        raw_len,
        payload_addr,
        table_off,
        runtime_base,
        import_off,
        cave,
    } = payload;
    let sealed = &material.sealed;
    let (loader_origin, resolve_origin, vm_origin) = section_origins(image.image_base, layout);
    let vm = checked_vm(
        vm_origin,
        layout,
        bridge_base(image, layout),
        payload_addr + u64::from(runtime_base),
        lowered.funcs.len(),
    )?;
    let bridges = native_bridges(image, lowered, layout, &vm, vm_origin)?;
    let resolve = checked_resolve(resolve_origin, layout, payload_addr)?;
    let positions = (payload_addr, runtime_base, vm_origin);
    let tramps = trampoline_bytes(image, lowered, layout, positions, &vm)?;
    let state_start = (layout.data_rva - layout.section_rva) as usize - layout.vm_off;
    let (state, module) = state_image(&vm, state_start, payload_addr, &sealed.ciphertext, lowered);
    let (loader, startup_unwind) = section_loader(
        image,
        layout,
        payload_addr,
        &material,
        [loader_origin, resolve_origin, vm_origin],
        (table_off, import_off, runtime_base, vm.calls),
        (cave, seed, module),
    )?;
    let prefix = [&loader[..], &resolve[..], &tramps[..], &bridges.code[..]];
    let mut code = section_image(prefix, layout.vm_off, &vm.bytes[..state_start]);
    if let Some(manifest) = &material.manifest {
        code[..manifest.len()].copy_from_slice(manifest);
    }
    let code = CodeMaterial {
        bytes: code,
        startup_unwind,
        authenticated: material.manifest.is_some(),
    };
    let header = section_header(image, layout.payload_off, raw_len, sealed);
    Ok(finish_section(
        layout, code, state, header, seed, tls_size, bridges,
    ))
}

#[derive(Default)]
struct NativeBridges {
    code: Vec<u8>,
    ranges: Vec<(u32, u32, u32)>,
    cleanup: Option<u32>,
}

fn bridge_base(image: &PeImage, layout: &CodeLayout) -> u64 {
    image.image_base + u64::from(layout.section_rva) + layout.bridge_off as u64
}

fn native_bridges(
    image: &PeImage,
    lowered: &BcImage,
    layout: &CodeLayout,
    vm: &stub::NativeVm,
    vm_origin: u64,
) -> Result<NativeBridges> {
    if !layout.windows_native || layout.guarded {
        return Ok(NativeBridges::default());
    }
    let resume = vm
        .pe_host_resume
        .ok_or_else(|| msg("native host resume is missing"))?;
    let cleanup = vm
        .pe_unwind_cleanup
        .ok_or_else(|| msg("native unwind cleanup is missing"))?;
    let mut code = Vec::with_capacity(lowered.funcs.len() * stub::HOST_BRIDGE_LEN);
    let mut ranges = Vec::with_capacity(lowered.funcs.len());
    let to_rva = |value| u32::try_from(value).map_err(|_| msg("native host bridge RVA overflows"));
    for func in &lowered.funcs {
        let begin = u64::from(layout.section_rva) + layout.bridge_off as u64 + code.len() as u64;
        let end = begin + stub::HOST_BRIDGE_LEN as u64;
        let bridge = stub::host_bridge(image.image_base + begin, vm_origin + resume as u64)?;
        code.extend(bridge);
        ranges.push((func.rva, to_rva(begin)?, to_rva(end)?));
    }
    let cleanup = to_rva(vm_origin - image.image_base + cleanup as u64)?;
    Ok(NativeBridges {
        code,
        ranges,
        cleanup: Some(cleanup),
    })
}

fn pe_tls_layout(native: bool, lowered: &BcImage) -> Result<(Vec<u32>, u32)> {
    if !native {
        return Ok((Vec::new(), 0));
    }
    if lowered.funcs.len() > vm::CTX_MAP_SLOTS {
        return Err(msg("native PE exceeds its per-thread function limit"));
    }
    let mut cursor = stub::PE_TLS_CACHE_BASE;
    let mut offsets = Vec::with_capacity(lowered.funcs.len());
    for func in &lowered.funcs {
        offsets.push(cursor as u32);
        let bytes = func
            .insns
            .iter()
            .map(|insn| 33 + insn.bytes.len())
            .sum::<usize>();
        cursor += bytes.next_multiple_of(16);
        if cursor > stub::PE_TLS_LIMIT {
            return Err(msg("native PE TLS exceeds its size limit"));
        }
    }
    Ok((offsets, cursor as u32))
}

fn section_origins(image_base: u64, layout: &CodeLayout) -> (u64, u64, u64) {
    let loader = image_base + u64::from(layout.section_rva) + HEADER_LEN as u64;
    let resolve = loader + layout.loader_len as u64;
    let vm = image_base + u64::from(layout.section_rva) + layout.vm_off as u64;
    (loader, resolve, vm)
}

struct CodeMaterial {
    bytes: Vec<u8>,
    startup_unwind: Vec<loader::NativeStartupUnwind>,
    authenticated: bool,
}

fn finish_section(
    layout: &CodeLayout,
    code: CodeMaterial,
    state: Vec<u8>,
    header: Header,
    seed: u64,
    tls_size: u32,
    bridges: NativeBridges,
) -> Built {
    Built {
        section: Section {
            name: super::hygiene::section_name(seed),
            rva: layout.section_rva,
            bytes: code.bytes,
            characteristics: CH_TEXT,
        },
        state: Section {
            name: super::hygiene::section_name(!seed),
            rva: layout.data_rva,
            bytes: state,
            characteristics: CH_DATA,
        },
        entry_rva: layout.section_rva + HEADER_LEN as u32,
        header,
        tls_size,
        native_bridges: bridges.ranges,
        native_cleanup: bridges.cleanup,
        native_startup_unwind: code.startup_unwind,
        authenticated: code.authenticated,
    }
}

fn checked_vm(
    origin: u64,
    layout: &CodeLayout,
    bridge: u64,
    runtime: u64,
    functions: usize,
) -> Result<stub::NativeVm> {
    let _bridges = layout
        .windows_native
        .then(|| stub::bind_pe_bridges(bridge, runtime, functions))
        .transpose()?;
    if !origin.is_multiple_of(8) {
        return Err(msg("vm origin is not 8-byte aligned"));
    }
    let vm = if layout.auth_imports.is_some() {
        stub::assemble_vm_for_authenticated_lab(origin)?
    } else {
        stub::assemble_vm(origin)?
    };
    if vm.bytes.len() != layout.vm_len
        || vm.frame != layout.vm_frame
        || vm.dispatch != layout.vm_dispatch
        || vm.calls != layout.vm_calls
    {
        return Err(msg(format!(
            "vm stub size changed between passes at {origin:#x}: actual {:?}, planned {:?}",
            (vm.bytes.len(), vm.frame, vm.dispatch, vm.calls),
            (
                layout.vm_len,
                layout.vm_frame,
                layout.vm_dispatch,
                layout.vm_calls
            )
        )));
    }
    Ok(vm)
}

fn checked_resolve(origin: u64, layout: &CodeLayout, key_addr: u64) -> Result<Vec<u8>> {
    if layout.windows_native {
        return Ok(Vec::new());
    }
    let resolve = crate::trace::assemble_resolver(origin, key_addr)?;
    if resolve.len() != layout.resolve_len {
        return Err(msg("resolver size changed between passes"));
    }
    Ok(resolve)
}

fn trampoline_bytes(
    image: &PeImage,
    lowered: &BcImage,
    layout: &CodeLayout,
    positions: (u64, u32, u64),
    vm: &stub::NativeVm,
) -> Result<Vec<u8>> {
    let (payload_addr, runtime_base, vm_origin) = positions;
    let mut tramps = Vec::new();
    for (index, func) in lowered.funcs.iter().enumerate() {
        let origin = image.image_base
            + u64::from(layout.section_rva)
            + u64::from(layout.tramp_off)
            + index as u64 * layout.tramp_len as u64;
        let bytes = stub::assemble_trampoline(&stub::Trampoline {
            origin,
            frame: vm_origin + vm.frame as u64,
            runtime: payload_addr + u64::from(runtime_base) + index as u64 * vm::RUNTIME_WINDOW,
            entry: func.entry,
            dispatch: vm_origin + vm.dispatch as u64,
            image_base: image.image_base,
            chains: vm_origin + vm.chains as u64,
        })?;
        if bytes.len() != layout.tramp_len {
            return Err(msg("trampoline size changed between passes"));
        }
        tramps.extend(bytes);
    }
    Ok(tramps)
}

fn section_loader(
    image: &PeImage,
    layout: &CodeLayout,
    payload_addr: u64,
    material: &PayloadMaterial,
    origins: [u64; 3],
    offs: (u32, u32, u32, usize),
    places: (u64, u64, u64),
) -> Result<(Vec<u8>, Vec<loader::NativeStartupUnwind>)> {
    let sealed = &material.sealed;
    let [loader_origin, resolve_origin, vm_origin] = origins;
    let (table_off, import_off, runtime_base, calls) = offs;
    let (cave, seed, module) = places;
    let runtime = payload_addr.wrapping_add(u64::from(runtime_base));
    let plan = LoaderPlan {
        origin: loader_origin,
        payload: payload_addr,
        payload_len: sealed.ciphertext.len() as u32,
        checksum: loader::checksum(&sealed.ciphertext),
        aead_key: sealed.key,
        aead_nonce: sealed.nonce,
        strings: payload_addr + crate::trace::NAME_KEY_LEN as u64,
        imports: payload_addr + u64::from(import_off),
        table: payload_addr + u64::from(table_off),
        calls: vm_origin + calls as u64,
        module,
        resolve: resolve_origin,
        original: image.image_base + u64::from(image.entry_rva),
        cave,
        runtime,
        name_key: crate::trace::name_key(seed)?,
    };
    let mut unwind = Vec::new();
    let loader = if layout.windows_native {
        let native = loader::NativeLoader {
            startup_status: image.image_base + u64::from(layout.data_rva) + 4,
            preferred_base: image.image_base,
            functions: layout.function_count,
        };
        if let Some(manifest) = &material.manifest {
            let auth = loader::NativeAuthLoader {
                imports: layout
                    .auth_imports
                    .ok_or_else(|| msg("CNG imports are missing"))?,
                expected_core: (&manifest[..BOOTSTRAP_CORE_LEN])
                    .try_into()
                    .map_err(|_| msg("invalid authenticated bootstrap core"))?,
                trusted_public: &sealed.public,
            };
            let image = loader::assemble_windows_native_authenticated(&plan, native, &auth)?;
            unwind.extend(image.unwind);
            image.bytes
        } else {
            loader::assemble_windows_native(&plan, native)?
        }
    } else {
        loader::assemble(&plan)?
    };
    if loader.len() != layout.loader_len {
        return Err(msg("loader size changed between passes"));
    }
    Ok((loader, unwind))
}

fn section_image(prefix: [&[u8]; 4], vm_off: usize, vm_code: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; HEADER_LEN];
    for part in prefix {
        body.extend(part);
    }
    body.resize(vm_off, 0);
    body.extend(vm_code);
    body
}

fn state_image(
    vm: &stub::NativeVm,
    state_start: usize,
    payload_addr: u64,
    ciphertext: &[u8],
    lowered: &BcImage,
) -> (Vec<u8>, u64) {
    let mut state = vm.bytes[state_start..].to_vec();
    let key_bytes: usize = lowered
        .funcs
        .iter()
        .map(|func| func.insns.len().saturating_mul(32))
        .sum();
    let data_bytes = (ciphertext.len() + key_bytes).next_multiple_of(8);
    let module = payload_addr + data_bytes as u64;
    state.extend(ciphertext);
    state.resize(vm.bytes.len() - state_start + data_bytes + 8, 0);
    (state, module)
}

fn section_header(
    image: &PeImage,
    payload_off: u32,
    raw_len: usize,
    sealed: &crypto::PayloadSeal,
) -> Header {
    Header {
        payload_off,
        payload_len: sealed.ciphertext.len() as u32,
        raw_len: raw_len as u32,
        crc32: vm::crc32(&sealed.ciphertext),
        sha256: crypto::sha256(&sealed.ciphertext),
        nonce: sealed.nonce,
        tag: sealed.tag,
        public: sealed.public,
        signature: sealed.signature,
        original_entry: image.entry_rva,
        image_base: image.image_base,
    }
}

struct PayloadMaterial {
    sealed: crypto::PayloadSeal,
    manifest: Option<[u8; BOOTSTRAP_MANIFEST_LEN]>,
}

fn seal_bound(
    payload: Vec<u8>,
    options: &Options,
    image: &PeImage,
    payload_rva: u32,
    authentication: Option<&NativeAuth<'_>>,
) -> Result<(usize, PayloadMaterial)> {
    let payload = crate::secret::WipeBuffer(payload);
    let material = if let Some(auth) = authentication {
        seal_auth_bootstrap(&payload.0, image, payload_rva, auth)?
    } else {
        PayloadMaterial {
            sealed: crypto::seal_payload(
                &payload.0,
                options.seed,
                options.random_key,
                image.entry_rva,
                image.image_base,
            )?,
            manifest: None,
        }
    };
    Ok((payload.0.len(), material))
}

fn seal_auth_bootstrap(
    payload: &[u8],
    image: &PeImage,
    payload_rva: u32,
    auth: &NativeAuth<'_>,
) -> Result<PayloadMaterial> {
    let credentials = auth.credentials;
    let scope = auth.scope;
    let scope_key = auth.master.scope(scope)?;
    let pin = ManufacturerPin::from_sec1(credentials.trusted_public)?;
    let context = BootstrapContext {
        platform: Platform::Pe32Plus,
        profile: Profile::Lab,
        scope,
        payload_offset: u64::from(payload_rva),
        payload_len: u32::try_from(payload.len()).map_err(|_| msg("PE payload exceeds limits"))?,
        original_entry_rva: image.entry_rva,
        preferred_base: image.image_base,
    };
    let (sealed, key) = BootstrapSealer::new(&scope_key).seal_for_native_lab(
        &context,
        &pin,
        credentials.signing_key,
        payload,
    )?;
    let nonce = exact_bytes(&sealed.manifest[BOOTSTRAP_NONCE_OFFSET..BOOTSTRAP_CORE_LEN])?;
    let tag = exact_bytes(&sealed.manifest[BOOTSTRAP_TAG_OFFSET..BOOTSTRAP_SIGNATURE_OFFSET])?;
    let signature = exact_bytes(&sealed.manifest[BOOTSTRAP_SIGNATURE_OFFSET..])?;
    Ok(PayloadMaterial {
        sealed: crypto::PayloadSeal {
            key: *key.as_bytes(),
            nonce,
            tag,
            ciphertext: sealed.ciphertext,
            public: *credentials.trusted_public,
            signature,
        },
        manifest: Some(sealed.manifest),
    })
}

pub(super) struct StringTables<'a> {
    pub trace: &'a [(u32, u32, u8)],
    pub maps: &'a [(u32, u32, u8)],
}

pub(super) fn dummy_plan(origin: u64) -> LoaderPlan {
    LoaderPlan {
        origin,
        payload: 0x1400_3000,
        payload_len: 32,
        checksum: 0,
        aead_key: [0; 32],
        aead_nonce: [0; 12],
        strings: 0x1400_3000,
        imports: 0x1400_3100,
        table: 0x1400_3200,
        calls: 0x1400_2100,
        module: 0x1400_3300,
        resolve: 0x1400_1800,
        original: 0x140001000,
        cave: 0x1400_4000,
        runtime: 0x1400_5000,
        name_key: [0; 16],
    }
}

fn payload_prefix(
    lowered: &BcImage,
    tables: &StringTables<'_>,
    payload_addr: u64,
    imports: &[(u32, u32)],
) -> (Vec<u8>, u32, u32, u32) {
    let (mut header, import_off, table_off) = prefix_records(tables, imports);
    let runtime_base = align16(table_off + 4 + lowered.funcs.len() as u32 * 16);
    let runtime_addrs = (0..lowered.funcs.len())
        .map(|index| payload_addr + u64::from(runtime_base) + index as u64 * vm::RUNTIME_WINDOW);
    write_call_table(&mut header, lowered, runtime_addrs);
    (header, import_off, table_off, runtime_base)
}

fn prefix_records(tables: &StringTables<'_>, imports: &[(u32, u32)]) -> (Vec<u8>, u32, u32) {
    let mut header = Vec::new();
    write_records(&mut header, tables.trace);
    write_records(&mut header, tables.maps);
    let import_off = header.len() as u32;
    header.extend((imports.len() as u32).to_le_bytes());
    for (rva, hash) in imports {
        header.extend(rva.to_le_bytes());
        header.extend(hash.to_le_bytes());
    }
    let table_off = align16(header.len() as u32);
    while header.len() < table_off as usize {
        header.push(0);
    }
    (header, import_off, table_off)
}

fn write_call_table(
    header: &mut Vec<u8>,
    lowered: &BcImage,
    runtimes: impl IntoIterator<Item = u64>,
) {
    header.extend((lowered.funcs.len() as u32).to_le_bytes());
    for (func, runtime) in lowered.funcs.iter().zip(runtimes) {
        header.extend(func.rva.to_le_bytes());
        header.extend(func.entry.to_le_bytes());
        header.extend(runtime.to_le_bytes());
    }
}

fn write_records(header: &mut Vec<u8>, rows: &[(u32, u32, u8)]) {
    header.extend((rows.len() as u32).to_le_bytes());
    for (rva, len, key) in rows {
        header.extend(rva.to_le_bytes());
        header.extend(len.to_le_bytes());
        header.extend(u32::from(*key).to_le_bytes());
    }
}

#[cfg(test)]
pub(super) fn layout_payload(
    lowered: &BcImage,
    tables: &StringTables<'_>,
    payload_addr: u64,
    image: &PeImage,
    seed: u64,
) -> Result<(Vec<u8>, u32, u32, u32)> {
    layout_payload_with_tls(lowered, tables, payload_addr, image, seed, &[])
}

fn layout_payload_with_tls(
    lowered: &BcImage,
    tables: &StringTables<'_>,
    payload_addr: u64,
    image: &PeImage,
    seed: u64,
    offsets: &[u32],
) -> Result<(Vec<u8>, u32, u32, u32)> {
    let key = crate::trace::name_key(seed)?;
    let imports = keyed_imports(image, &key);
    let shifted = payload_addr + crate::trace::NAME_KEY_LEN as u64;
    let (body, table_off, runtime_base, import_off) =
        layout_hashed_with_tls(lowered, tables, shifted, &imports, false, offsets)?;
    Ok(prefix_key(&key, body, table_off, runtime_base, import_off))
}

fn keyed_imports(image: &PeImage, key: &[u8; crate::trace::NAME_KEY_LEN]) -> Vec<(u32, u32)> {
    image
        .imports
        .iter()
        .map(|import| (import.iat_rva, import_slot(import.name.as_bytes(), key)))
        .collect()
}

fn import_slot(name: &[u8], key: &[u8; crate::trace::NAME_KEY_LEN]) -> u32 {
    crate::syscall::direct_nr(name).unwrap_or_else(|| crate::trace::keyed_hash(name, key))
}

fn prefix_key(
    key: &[u8],
    body: Vec<u8>,
    table_off: u32,
    runtime_base: u32,
    import_off: u32,
) -> (Vec<u8>, u32, u32, u32) {
    let mut prefixed = key.to_vec();
    prefixed.extend(body);
    let shift = crate::trace::NAME_KEY_LEN as u32;
    (
        prefixed,
        table_off + shift,
        runtime_base + shift,
        import_off + shift,
    )
}

pub(super) fn layout_hashed(
    lowered: &BcImage,
    tables: &StringTables<'_>,
    payload_addr: u64,
    imports: &[(u32, u32)],
    external: bool,
) -> Result<(Vec<u8>, u32, u32, u32)> {
    layout_hashed_with_tls(lowered, tables, payload_addr, imports, external, &[])
}

fn layout_hashed_with_tls(
    lowered: &BcImage,
    tables: &StringTables<'_>,
    payload_addr: u64,
    imports: &[(u32, u32)],
    external: bool,
    offsets: &[u32],
) -> Result<(Vec<u8>, u32, u32, u32)> {
    let (mut header, import_off, table_off, runtime_base) =
        payload_prefix(lowered, tables, payload_addr, imports);
    while header.len() < runtime_base as usize {
        header.push(0);
    }
    let mut body = header;
    let runtime_bytes = lowered.funcs.len() * vm::RUNTIME_WINDOW as usize;
    body.resize(runtime_base as usize + runtime_bytes, 0);
    let mut key_at = payload_addr + body.len() as u64;
    for (index, func) in lowered.funcs.iter().enumerate() {
        let at = payload_addr + u64::from(runtime_base) + index as u64 * vm::RUNTIME_WINDOW;
        write_runtime(
            &mut body,
            payload_addr,
            at,
            func,
            &lowered.inv,
            &lowered.slots,
            lowered.handler_mix,
            key_at,
            external,
        )?;
        if let Some(offset) = offsets.get(index) {
            put(
                &mut body,
                payload_addr,
                at + vm::WEAVE_SAVE as u64,
                &offset.to_le_bytes(),
            )?;
        }
        key_at += func.insns.len() as u64 * 32;
    }
    Ok((body, table_off, runtime_base, import_off))
}

pub(super) struct AuthenticatedElfPayload {
    pub(super) bytes: crate::secret::WipeBuffer,
    pub(super) table_off: u32,
    pub(super) runtimes: Vec<u64>,
}

struct ElfRuntimeSlot {
    at: u64,
    tables: vm::RuntimeTables,
    blob_len: usize,
}

pub(super) fn layout_authenticated_elf(
    lowered: &BcImage,
    payload_addr: u64,
) -> Result<AuthenticatedElfPayload> {
    let empty = StringTables {
        trace: &[],
        maps: &[],
    };
    let (mut header, _, table_off) = prefix_records(&empty, &[]);
    let (slots, len) = elf_runtime_slots(lowered, payload_addr, table_off as usize)?;
    let runtimes: Vec<u64> = slots.iter().map(|slot| slot.at).collect();
    write_call_table(&mut header, lowered, runtimes.iter().copied());
    header.resize(len, 0);
    let mut bytes = crate::secret::WipeBuffer(header);
    let mut key_at = payload_addr + len as u64;
    for (func, slot) in lowered.funcs.iter().zip(slots) {
        let words = runtime_words(func, &lowered.inv, slot.blob_len)?;
        let head = RuntimeHead {
            at: slot.at,
            func,
            slots: &lowered.slots,
            handler_mix: lowered.handler_mix,
            keys: key_at,
            crc: words.crc,
            external: false,
        };
        put_runtime(
            &mut bytes.0,
            payload_addr,
            &head,
            &slot.tables,
            &words,
            &lowered.inv,
        )?;
        key_at += func.insns.len() as u64 * 32;
    }
    Ok(AuthenticatedElfPayload {
        bytes,
        table_off,
        runtimes,
    })
}

fn elf_runtime_slots(
    lowered: &BcImage,
    payload_addr: u64,
    table_off: usize,
) -> Result<(Vec<ElfRuntimeSlot>, usize)> {
    let limit = || {
        msg(format!(
        "unsupported authenticated ELF runtime layout: payload exceeds {BOOTSTRAP_MAX_PAYLOAD} bytes"
    ))
    };
    let count = lowered.funcs.len();
    // The existing call table has a u32 count and 16-byte rows. The minimum
    // slot bounds this count before reserving storage for the plan.
    if count == 0 || count > BOOTSTRAP_MAX_PAYLOAD / vm::RUNTIME_WINDOW as usize {
        return Err(limit());
    }
    let mut len = (table_off + 4 + count * 16).next_multiple_of(16);
    let mut slots = Vec::with_capacity(count);
    for func in &lowered.funcs {
        let instructions = func.insns.len();
        if instructions == 0 || instructions > vm::NATIVE_MAX_RUNTIME_INSNS {
            return Err(msg(format!(
                "unsupported authenticated ELF runtime layout: {instructions} instructions exceeds native range 1..={}",
                vm::NATIVE_MAX_RUNTIME_INSNS
            )));
        }
        let at = payload_addr.checked_add(len as u64).ok_or_else(limit)?;
        let blob_len = runtime_blob_len(func)?;
        let tables = vm::runtime_tables(at, instructions, blob_len)?;
        let extent = (tables.end - at).max(vm::RUNTIME_WINDOW);
        let span = usize::try_from(extent)
            .ok()
            .and_then(|value| value.checked_next_multiple_of(16))
            .ok_or_else(limit)?;
        len = len
            .checked_add(span)
            .filter(|&end| end <= BOOTSTRAP_MAX_PAYLOAD)
            .ok_or_else(limit)?;
        slots.push(ElfRuntimeSlot {
            at,
            tables,
            blob_len,
        });
    }
    let key_span: usize = lowered.funcs.iter().map(|func| func.insns.len() * 32).sum();
    payload_addr
        .checked_add(len as u64)
        .and_then(|end| end.checked_add(key_span as u64))
        .ok_or_else(limit)?;
    Ok((slots, len))
}

struct RuntimeWords {
    blob: Vec<u8>,
    offs: Vec<u8>,
    lens: Vec<u8>,
    crc: u32,
}

struct RuntimeHead<'a> {
    at: u64,
    func: &'a crate::vm::BcFunc,
    slots: &'a crate::vm::SlotMap,
    handler_mix: u32,
    keys: u64,
    crc: u32,
    external: bool,
}

fn runtime_words(
    func: &crate::vm::BcFunc,
    inv: &[u8; 256],
    blob_len: usize,
) -> Result<RuntimeWords> {
    // The lowerer inserts the one checksum instruction at the function entry.
    // Opening that instruction weaves the preceding ciphertext once.
    let check = crate::secret::WipeBuffer(vm::plain_insn(func, func.entry as usize, inv)?);
    let Some((0x60, checksum)) = check.0.split_first() else {
        return Err(msg("runtime entry is missing its checksum instruction"));
    };
    let crc = u32::from_le_bytes(exact_bytes(checksum)?);
    drop(check);
    let mut blob = Vec::with_capacity(blob_len);
    let mut offs = Vec::with_capacity(func.insns.len() * 4);
    let mut lens = Vec::with_capacity(func.insns.len() * 4);
    for insn in &func.insns {
        offs.extend((blob.len() as u32).to_le_bytes());
        lens.extend((insn.bytes.len() as u32).to_le_bytes());
        blob.extend(&insn.bytes);
    }
    Ok(RuntimeWords {
        blob,
        offs,
        lens,
        crc,
    })
}

fn runtime_blob_len(func: &crate::vm::BcFunc) -> Result<usize> {
    func.insns
        .iter()
        .try_fold(0usize, |len, insn| len.checked_add(insn.bytes.len()))
        .ok_or_else(|| msg("unsupported runtime layout: extent overflows"))
}

fn runtime_fits_buf(buf: &[u8], payload_addr: u64, end: u64) -> Result<()> {
    let span = end
        .checked_sub(payload_addr)
        .ok_or_else(|| msg("runtime layout is outside the allocated payload"))?;
    if span > buf.len() as u64 {
        return Err(msg("runtime layout is outside the allocated payload"));
    }
    Ok(())
}

// Eight independent fields of one runtime window. A wrapper would only rename them.
#[allow(clippy::too_many_arguments)]
fn write_runtime(
    buf: &mut [u8],
    payload_addr: u64,
    at: u64,
    func: &crate::vm::BcFunc,
    inv: &[u8; 256],
    slots: &crate::vm::SlotMap,
    handler_mix: u32,
    keys: u64,
    external: bool,
) -> Result<()> {
    let blob_len = runtime_blob_len(func)?;
    let tables = vm::runtime_fits(at, func.insns.len(), blob_len)?;
    runtime_fits_buf(buf, payload_addr, tables.end)?;
    let words = runtime_words(func, inv, blob_len)?;
    put_runtime(
        buf,
        payload_addr,
        &RuntimeHead {
            at,
            func,
            slots,
            handler_mix,
            keys,
            crc: words.crc,
            external,
        },
        &tables,
        &words,
        inv,
    )
}

fn put_runtime(
    buf: &mut [u8],
    payload_addr: u64,
    head: &RuntimeHead<'_>,
    tables: &vm::RuntimeTables,
    words: &RuntimeWords,
    inv: &[u8; 256],
) -> Result<()> {
    let at = head.at;
    put(
        buf,
        payload_addr,
        at,
        &(head.func.insns.len() as u64).to_le_bytes(),
    )?;
    put(buf, payload_addr, at + 8, &tables.cache.to_le_bytes())?;
    put(buf, payload_addr, at + 16, &tables.offs.to_le_bytes())?;
    put(buf, payload_addr, at + 24, &tables.blob.to_le_bytes())?;
    put(buf, payload_addr, at + 32, &tables.lens.to_le_bytes())?;
    put(buf, payload_addr, at + 0x28, &tables.inv.to_le_bytes())?;
    put(buf, payload_addr, at + 0x30, &head.crc.to_le_bytes())?;
    put(
        buf,
        payload_addr,
        at + vm::RT_MIX as u64,
        &vm::reg_layout_bytes(head.slots, head.handler_mix),
    )?;
    put(buf, payload_addr, at + vm::RT_SALT as u64, &head.func.salt)?;
    put_held_key(buf, payload_addr, at, head.external, &head.func.key)?;
    put_runtime_tail(buf, payload_addr, at, head, tables, words, inv)
}

fn put_held_key(
    buf: &mut [u8],
    payload_addr: u64,
    at: u64,
    external: bool,
    key: &crate::secret::KeyPage,
) -> Result<()> {
    let mut bytes = key.bytes();
    let zero = [0u8; 32];
    let published_key = published(external, &bytes, &zero);
    let stored = put(buf, payload_addr, at + vm::RT_KEY as u64, published_key)
        .and_then(|_| put(buf, payload_addr, at + vm::RT_MASTER as u64, published_key));
    crate::secret::wipe(&mut bytes);
    stored
}

fn put_runtime_tail(
    buf: &mut [u8],
    payload_addr: u64,
    at: u64,
    head: &RuntimeHead<'_>,
    tables: &vm::RuntimeTables,
    words: &RuntimeWords,
    inv: &[u8; 256],
) -> Result<()> {
    put(
        buf,
        payload_addr,
        at + vm::RT_KEYS as u64,
        &head.keys.to_le_bytes(),
    )?;
    put_words(buf, payload_addr, at, head)?;
    let external_blob_len = if head.external {
        u32::try_from(words.blob.len()).map_err(|_| msg("external bytecode extent overflows"))?
    } else {
        0
    };
    put(
        buf,
        payload_addr,
        at + vm::RT_FOLD as u64,
        &external_blob_len.to_le_bytes(),
    )?;
    let zero = [0u8; 32];
    put(
        buf,
        payload_addr,
        at + vm::RT_TERM as u64,
        published(head.external, &head.func.terminal, &zero),
    )?;
    if head.external {
        put(
            buf,
            payload_addr,
            at + vm::WEAVE_SAVE as u64,
            &head.func.rva.to_le_bytes(),
        )?;
    }
    put(buf, payload_addr, tables.offs, &words.offs)?;
    put(buf, payload_addr, tables.lens, &words.lens)?;
    put(buf, payload_addr, tables.inv, inv)?;
    put(buf, payload_addr, tables.blob, &words.blob)?;
    put_inner(buf, payload_addr, at, head)
}

fn put_words(buf: &mut [u8], payload_addr: u64, at: u64, head: &RuntimeHead<'_>) -> Result<()> {
    put(
        buf,
        payload_addr,
        at + vm::RT_INDEX as u64,
        &head.func.rva.to_le_bytes(),
    )?;
    put(
        buf,
        payload_addr,
        at + vm::RT_SCHED as u64,
        &head.func.sched.to_le_bytes(),
    )?;
    Ok(())
}

fn put_inner(buf: &mut [u8], payload_addr: u64, at: u64, head: &RuntimeHead<'_>) -> Result<()> {
    let sealed = head.func.dispatcher()?;
    let zero = [0u8; 32];
    put(
        buf,
        payload_addr,
        at + vm::INNER_KEY as u64,
        published(head.external, &sealed.key, &zero),
    )?;
    put(
        buf,
        payload_addr,
        at + vm::INNER_NONCE as u64,
        &sealed.nonce,
    )?;
    put(
        buf,
        payload_addr,
        at + vm::INNER_LEN as u64,
        &(sealed.bytes.len() as u32).to_le_bytes(),
    )?;
    put(buf, payload_addr, at + vm::INNER_READY as u64, &[0])?;
    put(
        buf,
        payload_addr,
        at + vm::INNER_CIPHER as u64,
        &sealed.bytes,
    )?;
    Ok(())
}

fn published<'a>(external: bool, key: &'a [u8; 32], zero: &'a [u8; 32]) -> &'a [u8; 32] {
    if external {
        zero
    } else {
        key
    }
}

pub(super) fn put(buf: &mut [u8], base: u64, at: u64, data: &[u8]) -> Result<()> {
    let off = usize::try_from(
        at.checked_sub(base)
            .ok_or_else(|| msg("payload write is outside the buffer"))?,
    )
    .map_err(|_| msg("payload write is outside the buffer"))?;
    let end = off
        .checked_add(data.len())
        .ok_or_else(|| msg("payload write is outside the buffer"))?;
    buf.get_mut(off..end)
        .ok_or_else(|| msg("payload write is outside the buffer"))?
        .copy_from_slice(data);
    Ok(())
}

fn align16(value: u32) -> u32 {
    value.div_ceil(16) * 16
}

pub(super) fn encrypt_strings(
    image: &mut PeImage,
    seed: u64,
    skip: &[(u32, u32)],
) -> Vec<(u32, u32, u8)> {
    let mut found = Vec::new();
    for section in &mut image.sections {
        if crate::pe::executable(section) {
            continue;
        }
        let mut index = 0usize;
        while index < section.bytes.len() {
            if !is_text(section.bytes[index]) {
                index += 1;
                continue;
            }
            let start = index;
            while index < section.bytes.len() && is_text(section.bytes[index]) {
                index += 1;
            }
            let rva = section.rva + start as u32;
            let len = (index - start) as u32;
            if index - start >= 6 && !range_overlaps(rva, len, skip) {
                let key = string_key(seed, start as u8);
                encrypt_span(&mut section.bytes[start..index], key);
                found.push((rva, len, key));
            }
        }
    }
    found
}

pub(super) fn string_key(seed: u64, start: u8) -> u8 {
    (seed as u8).wrapping_add(start).wrapping_add(0x5a)
}

pub(super) fn encrypt_span(bytes: &mut [u8], key: u8) {
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte ^= key.wrapping_add(offset as u8);
    }
}

fn is_text(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

fn range_overlaps(rva: u32, len: u32, skip: &[(u32, u32)]) -> bool {
    let end = rva.saturating_add(len);
    skip.iter().any(|(start, size)| {
        let stop = start.saturating_add(*size);
        rva < stop && *start < end
    })
}

pub(super) fn clear_import_names(image: &mut PeImage) -> Result<()> {
    let places: Vec<u32> = image
        .imports
        .iter()
        .flat_map(|import| [import.name_rva, import.dll_rva])
        .filter(|rva| *rva != 0)
        .collect();
    for rva in places {
        zero_cstr(image, rva)?;
    }
    Ok(())
}

fn zero_cstr(image: &mut PeImage, rva: u32) -> Result<()> {
    let section = image
        .sections
        .iter_mut()
        .find(|section| {
            rva >= section.rva && (rva as usize) < section.rva as usize + section.bytes.len()
        })
        .ok_or_else(|| msg(format!("rva {rva:#x} is not writable")))?;
    let mut off = (rva - section.rva) as usize;
    let end = (off + 256).min(section.bytes.len());
    while off < end {
        let byte = section.bytes[off];
        section.bytes[off] = 0;
        off += 1;
        if byte == 0 {
            break;
        }
    }
    Ok(())
}

pub(super) fn payload_bytes(bytes: &[u8], at: usize, off: u32, len: u32) -> Result<&[u8]> {
    let start = at
        .checked_add(usize::try_from(off).map_err(|_| msg("payload is outside the file"))?)
        .ok_or_else(|| msg("payload is outside the file"))?;
    let end = start
        .checked_add(usize::try_from(len).map_err(|_| msg("payload is outside the file"))?)
        .ok_or_else(|| msg("payload is outside the file"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| msg("payload is outside the file"))
}

/// Check the caller's public key, the Poly1305 tag, and the P-256 signature.
///
/// Returns the header only when every check passes. The caller's key must match
/// the header; a key read only from the file is not accepted. Ignoring the result
/// skips the tag and signature checks.
#[must_use = "ignoring the result skips the tag and signature checks"]
pub fn inspect(bytes: &[u8], expected_public: &[u8; 65]) -> Result<Header> {
    let at = crypto::find_header(bytes)?;
    let header = Header::parse(&bytes[at..])?;
    // The caller's key is the trust anchor. A key read only from the header is not enough.
    if header.public != *expected_public {
        return Err(crate::error::Error::BadSignature);
    }
    let payload = payload_bytes(bytes, at, header.payload_off, header.payload_len)?;
    let loader_at = at
        .checked_add(HEADER_LEN)
        .ok_or_else(|| msg("loader is missing the aead key"))?;
    let loader = bytes
        .get(loader_at..)
        .ok_or_else(|| msg("loader is missing the aead key"))?;
    let (key, nonce) = loader::read_embedded_aead(loader)?;
    if nonce != header.nonce {
        return Err(crate::error::Error::Integrity);
    }
    let aad = crypto::payload_aad(
        &header.public,
        &header.nonce,
        header.raw_len,
        header.payload_len,
        header.original_entry,
        header.image_base,
    );
    crypto::open_payload(&key, &header.nonce, &header.tag, payload, &aad)?;
    crypto::verify_signature(
        expected_public,
        &header.signature,
        &crypto::signed_message(
            &key,
            &header.nonce,
            &header.tag,
            payload,
            header.original_entry,
            header.image_base,
        ),
    )?;
    if crypto::sha256(payload) != header.sha256 || vm::crc32(payload) != header.crc32 {
        return Err(crate::error::Error::Integrity);
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Block, Exit, FuncIr};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn runtime_fixture() -> FuncIr {
        FuncIr {
            name: "fit".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: Vec::new(),
                exit: Exit::Ret,
                opaque: false,
            }],
        }
    }

    fn scoped_runtime_fixture(funcs: &[FuncIr]) -> BcImage {
        use crate::crypto::authenticated::{BlockPurpose, BlockScope, MasterSecret};
        let master = MasterSecret::generate().unwrap();
        let scope = BlockScope::for_new_build([1; 16], [0; 16], 1, BlockPurpose::Payload).unwrap();
        vm::lower_image_scoped(funcs, &mut ChaCha20Rng::seed_from_u64(1025), &master, scope)
            .unwrap()
    }

    #[test]
    fn authenticated_elf_runtime_preserves_fixed_slot_bytes_when_they_fit() {
        let image = scoped_runtime_fixture(&[runtime_fixture()]);
        let tables = StringTables {
            trace: &[],
            maps: &[],
        };
        let at = 0x500000;
        let (fixed, table, runtime, _) = layout_hashed(&image, &tables, at, &[], false).unwrap();
        let authenticated = layout_authenticated_elf(&image, at).unwrap();
        assert_eq!(authenticated.bytes.0, fixed);
        assert_eq!(authenticated.table_off, table);
        assert_eq!(authenticated.runtimes, [at + u64::from(runtime)]);
    }

    #[test]
    fn authenticated_elf_runtime_uses_ordered_nonoverlapping_slots() {
        let mut large = runtime_fixture();
        large.blocks[0].ops = vec![crate::ir::Op::MovRi(crate::ir::RAX, 7); 6_000];
        let mut small = runtime_fixture();
        small.rva += 0x1000;
        let image = scoped_runtime_fixture(&[large, small]);
        let at = 0x500000;
        let payload = layout_authenticated_elf(&image, at).unwrap();
        let [first, second] = payload.runtimes[..] else {
            panic!("expected two runtime addresses");
        };
        let blob_len = runtime_blob_len(&image.funcs[0]).unwrap();
        let end = vm::runtime_tables(first, image.funcs[0].insns.len(), blob_len)
            .unwrap()
            .end;
        assert!(end - first > vm::RUNTIME_WINDOW);
        assert_eq!(second, end.next_multiple_of(16));
        assert_eq!(
            at + payload.bytes.0.len() as u64,
            second + vm::RUNTIME_WINDOW
        );
        let table = payload.table_off as usize;
        assert_eq!(payload.bytes.0[table..table + 4], 2u32.to_le_bytes());
        assert_eq!(payload.bytes.0[table + 12..table + 20], first.to_le_bytes());
        assert_eq!(
            payload.bytes.0[table + 28..table + 36],
            second.to_le_bytes()
        );
    }

    #[test]
    fn authenticated_elf_runtime_enforces_signed_and_native_limits_before_opening() {
        let mut image = scoped_runtime_fixture(&[runtime_fixture()]);
        image.funcs[0].insns[0].bytes = vec![0; BOOTSTRAP_MAX_PAYLOAD / 2];
        let error = layout_authenticated_elf(&image, 0x500000).err().unwrap();
        assert_eq!(
            error.to_string(),
            "unsupported authenticated ELF runtime layout: payload exceeds 4194304 bytes"
        );
        image.funcs[0]
            .insns
            .resize_with(vm::NATIVE_MAX_RUNTIME_INSNS + 1, || vm::EncodedInsn {
                seed: 1,
                bytes: Vec::new(),
            });
        let error = layout_authenticated_elf(&image, 0x500000).err().unwrap();
        assert!(error
            .to_string()
            .contains("65537 instructions exceeds native range 1..=65536"));
    }

    #[test]
    fn runtime_payload_keeps_the_entry_checksum_and_rejects_a_wrong_entry() {
        let mut image = scoped_runtime_fixture(&[runtime_fixture()]);
        let func = &image.funcs[0];
        let mut checks = Vec::new();
        let mut non_check = None;
        for index in 0..func.insns.len() {
            let plain = crate::secret::WipeBuffer(vm::plain_insn(func, index, &image.inv).unwrap());
            if let Some((0x60, checksum)) = plain.0.split_first() {
                checks.push((index, u32::from_le_bytes(exact_bytes(checksum).unwrap())));
            } else {
                non_check = Some(index);
            }
        }
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].0, func.entry as usize);
        let tables = StringTables {
            trace: &[],
            maps: &[],
        };
        let (payload, _, runtime, _) =
            layout_hashed(&image, &tables, 0x500000, &[], false).unwrap();
        let crc_at = runtime as usize + 0x30;
        assert_eq!(payload[crc_at..crc_at + 4], checks[0].1.to_le_bytes());
        image.funcs[0].entry = non_check.unwrap() as u32;
        let error = layout_hashed(&image, &tables, 0x500000, &[], false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "runtime entry is missing its checksum instruction"
        );
    }

    #[test]
    fn oversized_runtime_is_rejected_before_opening_instructions() {
        let mut image =
            vm::lower_image(&[runtime_fixture()], &mut ChaCha20Rng::seed_from_u64(1025)).unwrap();
        image.funcs[0].insns[0].bytes.clear();
        image.funcs[0].insns[1].bytes = vec![0; vm::RUNTIME_WINDOW as usize];
        let tables = StringTables {
            trace: &[],
            maps: &[],
        };
        let error = layout_hashed(&image, &tables, 0x500000, &[], false).unwrap_err();
        assert!(error
            .to_string()
            .starts_with("unsupported runtime layout: requires "));
        assert!(error.to_string().ends_with("limit is 98304 bytes"));
    }
}
