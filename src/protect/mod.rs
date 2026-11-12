use std::collections::BTreeSet;

mod elf;
mod hygiene;
mod payload;
pub use hygiene::{mask_span, section_name};
pub use payload::inspect;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::crypto::authenticated::{BlockPurpose, BlockScope, MasterSecret};
use crate::crypto::{Header, HEADER_LEN};
use crate::error::{msg, Result};
use crate::lift::lift;
use crate::loader;
use crate::obf::obfuscate;
use crate::pe::{self, PeImage, Section};
use crate::proof;
use crate::report::{push_pass, Report, SymbolReport};
use crate::stub::{self, assemble_resolve};
use crate::vm;

#[derive(Clone, Debug)]
pub struct Options {
    pub virtualize: BTreeSet<String>,
    pub mutate: BTreeSet<String>,
    pub virtualize_all: bool,
    pub mutate_all: bool,
    pub seed: u64,
    /// Draw the AEAD and signing keys from the OS RNG. Default is HKDF-SHA256(`seed`).
    pub random_key: bool,
    /// Include `seed` in the JSON report. Off by default.
    pub debug_seed: bool,
}

#[derive(Clone, Debug)]
pub struct Protected {
    pub bytes: Vec<u8>,
    pub report: Report,
    /// ChaCha20 custody for `external-key`. Offline images leave this empty.
    pub custody: Option<crate::agent::Package>,
}

const VM_PASSES: &[&str] = &[
    "opcode-polymorph",
    "bytecode-encrypt",
    "per-instruction-stream",
    "vm-equivalence",
    "layout-stealth",
    "integrity-cookies",
    "fail-closed-handlers",
    "anti-debug",
    "peb-being-debugged",
    "nt-global-flag",
];
const LEGACY_PE_DETECTORS: &[&str] = &[
    "is-debugger-present",
    "remote-debugger",
    "tick-delta",
    "hardware-dr",
    "debug-port",
    "debug-object",
    "process-debug-flags",
    "heap-flags",
    "int-2d",
    "protected-handle",
    "parent-debugger",
    "trap-flag",
    "int3-page",
    "thread-hide",
    "kernel-debugger",
    "remote-breakin",
    "instrumentation-callback",
];

const PAYLOAD_PASSES: &[&str] = &[
    "aead-runtime",
    "aead-inspect",
    "crc32",
    "sha256",
    "ecdsa-p256",
];

/// Read an input image without allocating from an unbounded file length.
pub fn read_input(path: impl AsRef<std::path::Path>) -> Result<Vec<u8>> {
    use std::io::Read;
    const MAX_INPUT: u64 = 128 * 1024 * 1024;
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_INPUT {
        return Err(msg("input image exceeds the size limit"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err(msg("input image exceeds the size limit"));
    }
    Ok(bytes)
}

// The retained build IR is wiped even if lifting or lowering fails.
struct BuildIr(Vec<crate::ir::FuncIr>);

impl Drop for BuildIr {
    fn drop(&mut self) {
        for func in &mut self.0 {
            func.wipe();
        }
    }
}

pub fn protect(input: &[u8], options: &Options) -> Result<Protected> {
    protect_profile(input, options, false, None)
}

/// Build a PE for native Windows execution with the original OS-managed imports.
pub fn protect_windows_native(input: &[u8], options: &Options) -> Result<Protected> {
    protect_profile(input, options, true, None)
}

/// Independently provisioned signing credentials for a native PE lab build.
pub struct NativeAuthentication<'a> {
    pub signing_key: &'a p256::ecdsa::SigningKey,
    pub trusted_public: &'a [u8; 65],
    pub application_id: [u8; 16],
}

/// Build a native PE whose entry verifies its signed and authenticated bootstrap.
/// The input must already import the supported CNG entry points from bcrypt.dll.
pub fn protect_windows_native_authenticated(
    input: &[u8],
    options: &Options,
    authentication: &NativeAuthentication<'_>,
) -> Result<Protected> {
    if options.random_key {
        return Err(msg(
            "authenticated PE startup always uses OS entropy and separate signing credentials",
        ));
    }
    protect_profile(input, options, true, Some(authentication))
}

/// Build a native ELF lab artifact using a trusted, fixed-address verifier artifact.
/// The verifier bytes must come from a trusted build of `tools/elf-auth-helper`.
pub fn protect_elf_authenticated(
    input: &[u8],
    options: &Options,
    authentication: &NativeAuthentication<'_>,
    helper: &[u8],
) -> Result<Protected> {
    elf::protect_authenticated(input, options, authentication, helper)
}

struct NativeAuth<'a> {
    credentials: &'a NativeAuthentication<'a>,
    imports: loader::AuthImports,
    master: MasterSecret,
    scope: BlockScope,
}

fn protect_profile(
    input: &[u8],
    options: &Options,
    windows_native: bool,
    authentication: Option<&NativeAuthentication<'_>>,
) -> Result<Protected> {
    // Both layout passes call `assemble_vm` with no seed argument. The guard
    // keeps that size stable inside this build and different across seeds.
    let _morph = stub::bind_metamorphic_seed(options.seed);
    if crate::elf::is_elf(input) {
        if windows_native {
            return Err(msg("Windows-native protection requires a PE executable"));
        }
        hygiene::reject_elf(input)?;
        return elf::protect(input, options, None);
    }
    hygiene::reject_pe(input)?;
    let kind = pe::image_kind(input)?;
    let mut image = pe::parse(input)?;
    let native_auth = authentication
        .map(|credentials| -> Result<NativeAuth<'_>> {
            Ok(NativeAuth {
                credentials,
                imports: loader::AuthImports::read(&image)?,
                master: MasterSecret::generate()?,
                scope: BlockScope::for_new_build(
                    credentials.application_id,
                    [0; 16],
                    1,
                    BlockPurpose::Payload,
                )?,
            })
        })
        .transpose()?;
    if windows_native && (kind.characteristics & 0x2000 != 0 || kind.subsystem == 1) {
        return Err(msg(
            "Windows-native protection requires a user-mode PE executable",
        ));
    }
    if windows_native && (image.tls_rva != 0 || image.tls_size != 0) {
        return Err(msg(
            "native PE rewriting requires an input without static TLS",
        ));
    }
    let native_security = windows_native
        .then(|| pe::native_security(input, &image, kind, true))
        .transpose()?;
    let authenticode_resign_required = if let Some(security) = &native_security {
        security.drop_debug(&mut image)?;
        security.resign_required
    } else {
        let resign_required = pe::check_rewrite_security(input, &image, kind)?;
        hygiene::drop_debug(&mut image, input);
        resign_required
    };
    if image.entry_rva == 0 {
        return Err(msg("image has no entry point"));
    }
    let symbols = discover(&image, options)?;
    let (virt, mutated) = select(&symbols, options, windows_native)?;
    if let Some(security) = &native_security {
        security.check_rewrites(
            virt.iter().map(|symbol| (symbol.rva, symbol.size)),
            mutated.iter().map(|symbol| (symbol.rva, symbol.size)),
        )?;
    }
    let guarded = native_security
        .as_ref()
        .is_some_and(pe::NativeSecurity::is_cfg_guarded);
    let native_unwind = windows_native
        .then(|| {
            pe::NativeUnwind::plan(
                &image,
                virt.iter().map(|symbol| (symbol.rva, symbol.size)),
                mutated.iter().map(|symbol| (symbol.rva, symbol.size)),
                guarded,
            )
        })
        .transpose()?;
    let (funcs, mut passes) =
        virtualize_symbols(&image, &virt, options.seed, windows_native, guarded)?;
    let mut rng = ChaCha20Rng::seed_from_u64(options.seed);
    let lowered = match &native_auth {
        Some(auth) => vm::lower_image_scoped(&funcs.0, &mut rng, &auth.master, auth.scope)?,
        None => vm::lower_image(&funcs.0, &mut rng)?,
    };
    drop(funcs);
    for pass in VM_PASSES {
        push_pass(&mut passes, pass);
    }
    if !windows_native {
        for pass in LEGACY_PE_DETECTORS {
            push_pass(&mut passes, pass);
        }
    }
    let mut spans = if windows_native {
        Vec::new()
    } else {
        map_spans(input, &image, &virt)?
    };
    if !windows_native {
        for symbol in &virt {
            crate::unwind::preserve_pe(&mut image, symbol.rva, symbol.size)?;
        }
    }
    let auth_imports = native_auth.as_ref().map(|auth| auth.imports);
    let layout = code_layout(
        &image,
        lowered.funcs.len(),
        windows_native,
        guarded,
        auth_imports,
    )?;
    let skips = write_trampolines(&mut image, &virt, &layout, &mut passes)?;
    let noted = if windows_native {
        Noted {
            trace: Vec::new(),
            maps: Vec::new(),
        }
    } else {
        hygiene::push_unwind(&image, &mut spans);
        spans.retain(|span| {
            !image.sections.iter().any(|section| {
                pe::executable(section)
                    && span.rva >= section.rva
                    && u64::from(span.rva) < u64::from(section.rva) + section.bytes.len() as u64
            })
        });
        note_imports_and_strings(&mut image, options, &skips, &spans, &mut passes)?
    };
    let tables = payload::StringTables {
        trace: &noted.trace,
        maps: &noted.maps,
    };
    if !windows_native {
        allow_loader_writes(&mut image, &tables)?;
    }
    let changed = mutate_selected(&mut image, &mutated, options.seed, &mut passes)?;
    let mut protected = finish_protect(
        image,
        options,
        passes,
        kind,
        ProtectTail {
            virt: &virt,
            changed: &changed,
            lowered: &lowered,
            strings: &tables,
            layout: &layout,
            native_security: native_security.as_ref(),
            native_unwind: native_unwind.as_ref(),
            native_auth: native_auth.as_ref(),
        },
    )?;
    protected.report.authenticode_resign_required = authenticode_resign_required;
    protected.report.windows_native = windows_native;
    Ok(protected)
}

fn allow_loader_writes(image: &mut PeImage, tables: &payload::StringTables<'_>) -> Result<()> {
    for &(rva, len, _) in tables.trace.iter().chain(tables.maps) {
        pe::allow_data_writes(image, rva, len)?;
    }
    let imports: Vec<_> = image.imports.iter().map(|import| import.iat_rva).collect();
    for rva in imports {
        pe::allow_data_writes(image, rva, 8)?;
    }
    Ok(())
}

struct ProtectTail<'a> {
    virt: &'a [Sym],
    changed: &'a [Sym],
    lowered: &'a vm::BcImage,
    strings: &'a payload::StringTables<'a>,
    layout: &'a CodeLayout,
    native_security: Option<&'a pe::NativeSecurity>,
    native_unwind: Option<&'a pe::NativeUnwind>,
    native_auth: Option<&'a NativeAuth<'a>>,
}

fn note_imports_and_strings(
    image: &mut PeImage,
    options: &Options,
    skips: &[(u32, u32)],
    spans: &[hygiene::Span],
    passes: &mut Vec<String>,
) -> Result<Noted> {
    if !image.imports.is_empty() {
        push_pass(passes, "import-hash");
    }
    if image
        .imports
        .iter()
        .any(|item| crate::syscall::direct_nr(item.name.as_bytes()).is_some())
    {
        push_pass(passes, "direct-syscall");
    }
    payload::clear_import_names(image)?;
    note_strings(image, options, skips, spans, passes)
}

struct Noted {
    trace: Vec<(u32, u32, u8)>,
    maps: Vec<(u32, u32, u8)>,
}

fn note_strings(
    image: &mut PeImage,
    options: &Options,
    skips: &[(u32, u32)],
    spans: &[hygiene::Span],
    passes: &mut Vec<String>,
) -> Result<Noted> {
    let skip_all = hygiene::extend_skips(skips, spans);
    let trace = payload::encrypt_strings(image, options.seed, &skip_all);
    if !trace.is_empty() {
        push_pass(passes, "string-encrypt");
    }
    if !image.imports.is_empty() || !trace.is_empty() {
        push_pass(passes, "call-trace");
    }
    let maps = hygiene::seal(image, options.seed, spans)?;
    Ok(Noted { trace, maps })
}

fn map_spans(file: &[u8], image: &PeImage, virt: &[Sym]) -> Result<Vec<hygiene::Span>> {
    let funcs: Vec<(u32, u32)> = virt.iter().map(|sym| (sym.rva, sym.size)).collect();
    hygiene::collect(file, image, &funcs)
}

fn finish_protect(
    mut image: PeImage,
    options: &Options,
    mut passes: Vec<String>,
    kind: pe::ImageKind,
    tail: ProtectTail<'_>,
) -> Result<Protected> {
    let span = entry_span(tail.virt, image.entry_rva);
    let cave = if tail.layout.windows_native {
        0
    } else {
        let rva = crate::antidebug::plant_cave(&mut image, options.seed)?;
        image.image_base.wrapping_add(u64::from(rva))
    };
    let mut built = payload::build_section(
        &image,
        tail.lowered,
        tail.strings,
        options,
        tail.layout,
        cave,
        tail.native_auth,
    )?;
    let entry = image.entry_rva;
    crate::early::plant_pe(
        &mut image,
        &mut built.section,
        &mut built.state,
        tail.layout.early_off,
        entry,
        span,
        built.tls_size,
    )?;
    push_pass(&mut passes, "early-tls");
    if tail.native_auth.is_some() {
        push_pass(&mut passes, "authenticated-bootstrap");
    } else {
        note_key_mode(&mut passes, false);
        for pass in PAYLOAD_PASSES {
            push_pass(&mut passes, pass);
        }
    }
    let (mut bytes, header, entry_rva) =
        apply_section(&mut image, built, tail.native_security, tail.native_unwind)?;
    if tail.native_security.is_some() {
        pe::set_image_kind(&mut bytes, &kind)?;
    } else {
        pe::set_image_kind(&mut bytes, &pe::without_unbacked_dll_bits(kind))?;
    }
    hygiene::scrub_pe(&mut bytes, options.seed)?;
    if let Some(security) = tail.native_security {
        security.restore_directories(&mut bytes)?;
    }
    push_pass(&mut passes, "image-hygiene");
    if !tail.layout.windows_native {
        push_pass(&mut passes, "sealed-maps");
    }
    let report = assemble_report(
        options.debug_seed.then_some(options.seed),
        options.seed,
        passes,
        (tail.virt, tail.changed),
        entry_rva,
        (&header, &bytes),
        tail.lowered,
    )?;
    Ok(Protected {
        bytes,
        report,
        custody: None,
    })
}

/// Protect a fixed ELF and keep the bytecode key in `socket`'s agent.
pub fn protect_external(input: &[u8], options: &Options, socket: &str) -> Result<Protected> {
    let _morph = stub::bind_metamorphic_seed(options.seed);
    if !crate::elf::is_elf(input) {
        return Err(msg("external-key protects an ELF image"));
    }
    crate::agent::check_path(socket)?;
    elf::protect(input, options, Some(socket))
}

pub(super) fn note_key_mode(passes: &mut Vec<String>, external: bool) {
    if external {
        push_pass(passes, "external-key");
        push_pass(passes, "external-sample");
    } else {
        push_pass(passes, "offline-key");
    }
}

fn apply_section(
    image: &mut PeImage,
    built: Built,
    native_security: Option<&pe::NativeSecurity>,
    native_unwind: Option<&pe::NativeUnwind>,
) -> Result<(Vec<u8>, Header, u32)> {
    let Built {
        section,
        state,
        header,
        entry_rva,
        native_bridges,
        native_cleanup,
        native_startup_unwind,
        authenticated,
        ..
    } = built;
    let name = section.name.clone();
    image.entry_rva = entry_rva;
    if native_security.is_none() {
        image.import_rva = 0;
        image.import_size = 0;
        image.iat_rva = 0;
        image.iat_size = 0;
    }
    if section.name == state.name
        || image
            .sections
            .iter()
            .any(|existing| existing.name == section.name || existing.name == state.name)
    {
        return Err(msg(
            "generated PE section name collides with an existing section",
        ));
    }
    image.sections.extend([section, state]);
    if let Some(unwind) = native_unwind {
        unwind.publish(
            image,
            &native_bridges,
            native_cleanup,
            &native_startup_unwind,
        )?;
    }
    if let Some(security) = native_security {
        security.append_metadata(image)?;
    }
    pe::check_final_layout(image)?;
    let bytes = if authenticated {
        pe::emit(image)?
    } else {
        emit_with_header(image, &header, &name)?
    };
    Ok((bytes, header, entry_rva))
}

fn virtualize_symbols(
    image: &PeImage,
    virt: &[Sym],
    seed: u64,
    windows_native: bool,
    guarded: bool,
) -> Result<(BuildIr, Vec<String>)> {
    let mut funcs = BuildIr(Vec::new());
    let mut passes = Vec::new();
    for symbol in virt {
        let bytes = function_bytes(image, symbol)?;
        let mut func = lift(
            &symbol.name,
            bytes,
            symbol.rva,
            symbol.size,
            image.image_base,
        )?;
        if guarded
            && func.blocks.iter().any(|block| {
                matches!(
                    block.exit,
                    crate::ir::Exit::CallRva { .. } | crate::ir::Exit::CallAbs { .. }
                )
            })
        {
            return Err(msg(
                "native CFG currently requires functions without guest calls",
            ));
        }
        if windows_native {
            route_win64_calls(image, virt, &mut func)?;
        }
        let mut rng = ChaCha20Rng::seed_from_u64(seed ^ u64::from(symbol.rva));
        let obf = obfuscate(&func, &mut rng);
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

fn route_win64_calls(image: &PeImage, virt: &[Sym], func: &mut crate::ir::FuncIr) -> Result<()> {
    use crate::ir::Exit;

    for block in &mut func.blocks {
        let Exit::CallRva { rva, next } = block.exit else {
            continue;
        };
        let executable = image.sections.iter().any(|section| {
            pe::executable(section)
                && rva >= section.rva
                && ((rva - section.rva) as usize) < section.bytes.len()
        });
        let enters_rewritten_body = virt
            .iter()
            .any(|symbol| rva > symbol.rva && rva - symbol.rva < symbol.size);
        if !executable || enters_rewritten_body {
            return Err(msg(format!("unsupported native call target RVA {rva:#x}")));
        }
        let reg = crate::lift::native_call_address(&mut block.ops, rva);
        // A physical call pushes a Win64 return address even when the target
        // is another VM entry. SEH can then see every active guest frame.
        block.exit = Exit::CallAbs { reg, next };
    }
    Ok(())
}

fn write_trampolines(
    image: &mut PeImage,
    virt: &[Sym],
    layout: &CodeLayout,
    passes: &mut Vec<String>,
) -> Result<Vec<(u32, u32)>> {
    let mut skips = Vec::new();
    for (index, symbol) in virt.iter().enumerate() {
        let target = image.image_base
            + u64::from(layout.section_rva)
            + u64::from(layout.tramp_off)
            + index as u64 * layout.tramp_len as u64;
        write_trampoline_site(image, symbol, target)?;
        skips.push((symbol.rva, symbol.size));
        push_pass(passes, "trampoline");
    }
    Ok(skips)
}

fn mutate_selected(
    image: &mut PeImage,
    mutated: &[Sym],
    seed: u64,
    passes: &mut Vec<String>,
) -> Result<Vec<Sym>> {
    let mut changed = Vec::new();
    for symbol in mutated {
        if let Some(substituted) = mutate_function(image, symbol, seed)? {
            changed.push(symbol.clone());
            note_mutation(passes, substituted);
        }
    }
    Ok(changed)
}

fn note_mutation(passes: &mut Vec<String>, substituted: bool) {
    if substituted {
        push_pass(passes, "instruction-substitution");
    }
    push_pass(passes, "code-cave");
    push_pass(passes, "linear-desync");
    push_pass(passes, "mutation-diversity");
}

fn emit_with_header(image: &PeImage, header: &Header, name: &str) -> Result<Vec<u8>> {
    let mut bytes = pe::emit(image)?;
    let encoded = header.to_bytes();
    let section_off = pe::section_file_offset(&bytes, name)?;
    bytes[section_off..section_off + HEADER_LEN].copy_from_slice(&encoded);
    Ok(bytes)
}

fn assemble_report(
    seed: Option<u64>,
    morph_seed: u64,
    passes: Vec<String>,
    symbols: (&[Sym], &[Sym]),
    entry_rva: u32,
    artifact: (&Header, &[u8]),
    image: &vm::BcImage,
) -> Result<Report> {
    use sha2::{Digest, Sha256};

    let (virt, changed) = symbols;
    let (header, bytes) = artifact;
    let claims = proof::claims_for(&passes)?;
    let measured = stub::measure_handler_difference(morph_seed)?;
    Ok(Report {
        seed,
        passes,
        claims,
        artifact_sha256: hex::encode(Sha256::digest(bytes)),
        authenticode_resign_required: false,
        windows_native: false,
        diversity: crate::report::StubDiversity {
            window: measured.window,
            window_len: measured.window_len,
            different_bytes: measured.different_bytes,
            difference_percent: measured.difference_percent,
            equivalence: "Proven",
            difference_claim: "ReducedToAssumption",
            varies: vm::VARYING_ELEMENTS,
        },
        virtualized: virt
            .iter()
            .map(|sym| symbol_report(sym, "virtualize", image))
            .collect(),
        mutated: changed
            .iter()
            .map(|sym| symbol_report(sym, "mutate", image))
            .collect(),
        entry_rva,
        public_key: hex::encode(header.public),
        signature: hex::encode(header.signature),
    })
}

fn symbol_report(sym: &Sym, action: &str, image: &vm::BcImage) -> SymbolReport {
    let func = (action == "virtualize")
        .then(|| find_lowered(sym, image))
        .flatten();
    SymbolReport {
        name: sym.name.clone(),
        rva: sym.rva,
        size: sym.size,
        action: action.into(),
        machine: func.map(|item| item.form.as_str().to_string()),
        single_path: func.map(|item| item.single_path),
        data_dependent: func.map(|item| item.data_dependent),
    }
}

fn find_lowered<'a>(sym: &Sym, image: &'a vm::BcImage) -> Option<&'a vm::BcFunc> {
    image
        .funcs
        .iter()
        .find(|item| item.name == sym.name && item.rva == sym.rva)
}

#[derive(Clone, Debug)]
struct Sym {
    name: String,
    rva: u32,
    size: u32,
    explicit_size: bool,
}

enum Selector {
    Name(String),
    Rva { rva: u32, size: Option<u32> },
}

fn parse_selector(text: &str) -> Result<Selector> {
    let Some(rest) = text.strip_prefix("rva:") else {
        return Ok(Selector::Name(text.to_string()));
    };
    let (hex, size) = match rest.split_once('+') {
        Some((hex, size)) => {
            if size.is_empty() {
                return Err(msg(format!("bad rva selector {text}")));
            }
            let size = u32::from_str_radix(size, 16)
                .map_err(|_| msg(format!("bad rva selector {text}")))?;
            (hex, Some(size))
        }
        None => (rest, None),
    };
    if hex.is_empty() {
        return Err(msg(format!("bad rva selector {text}")));
    }
    let rva = u32::from_str_radix(hex, 16).map_err(|_| msg(format!("bad rva selector {text}")))?;
    Ok(Selector::Rva { rva, size })
}

fn discover(image: &PeImage, options: &Options) -> Result<Vec<Sym>> {
    let mut symbols: Vec<Sym> = image
        .exports
        .iter()
        .map(|item| Sym {
            name: item.name.clone(),
            rva: item.rva,
            size: 0,
            explicit_size: false,
        })
        .collect();
    if image.entry_rva != 0 && !symbols.iter().any(|item| item.rva == image.entry_rva) {
        symbols.push(Sym {
            name: format!("entry_{:x}", image.entry_rva),
            rva: image.entry_rva,
            size: 0,
            explicit_size: false,
        });
    }
    for token in options.virtualize.iter().chain(options.mutate.iter()) {
        if let Selector::Rva { rva, size } = parse_selector(token)? {
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
    }
    symbols.sort_by_key(|item| item.rva);
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
            .unwrap_or_else(|| section_end(image, symbols[index].rva));
        let window = limit.saturating_sub(symbols[index].rva);
        symbols[index].size = reachable_size(image, symbols[index].rva, window)?;
        if symbols[index].size == 0 {
            return Err(msg(format!(
                "{} does not start with a valid instruction",
                symbols[index].name
            )));
        }
    }
    Ok(symbols)
}

fn section_end(image: &PeImage, rva: u32) -> u32 {
    image
        .sections
        .iter()
        .find(|sec| rva >= sec.rva && (rva as usize) < sec.rva as usize + sec.bytes.len())
        .map(|sec| sec.rva + sec.bytes.len() as u32)
        .unwrap_or(rva)
}

fn reachable_size(image: &PeImage, rva: u32, window: u32) -> Result<u32> {
    let code = pe::read_rva(image, rva, window as usize)?;
    let start = image.image_base + u64::from(rva);
    let mut decoder = iced_x86::Decoder::with_ip(64, code, start, iced_x86::DecoderOptions::NONE);
    let mut insns = Vec::new();
    while decoder.can_decode() && decoder.ip() < start + u64::from(window) {
        let insn = decoder.decode();
        if insn.is_invalid() {
            break;
        }
        insns.push(insn);
    }
    if insns.is_empty() {
        return Err(msg("function does not start with a valid instruction"));
    }
    let mut seen = vec![false; insns.len()];
    let mut stack = vec![0usize];
    let mut max_end = 0u32;
    while let Some(index) = stack.pop() {
        if index >= seen.len() {
            return Err(msg("function boundary walk left the instruction list"));
        }
        if seen[index] {
            continue;
        }
        seen[index] = true;
        let insn = &insns[index];
        max_end = max_end.max((insn.next_ip() - start) as u32);
        let local = |target: u64| insns.iter().position(|item| item.ip() == target);
        match insn.mnemonic() {
            iced_x86::Mnemonic::Ret => {}
            iced_x86::Mnemonic::Jmp => {
                if let Some(next) = local(insn.near_branch_target()) {
                    stack.push(next);
                }
            }
            iced_x86::Mnemonic::Call => {
                if let Some(next) = local(insn.next_ip()) {
                    stack.push(next);
                }
            }
            mnemonic if jcc(mnemonic) => {
                if let Some(next) = local(insn.near_branch_target()) {
                    stack.push(next);
                }
                if let Some(next) = local(insn.next_ip()) {
                    stack.push(next);
                }
            }
            _ => {
                if let Some(next) = local(insn.next_ip()) {
                    stack.push(next);
                }
            }
        }
    }
    Ok(max_end)
}

fn jcc(mnemonic: iced_x86::Mnemonic) -> bool {
    matches!(
        mnemonic,
        iced_x86::Mnemonic::Jo
            | iced_x86::Mnemonic::Jno
            | iced_x86::Mnemonic::Jb
            | iced_x86::Mnemonic::Jae
            | iced_x86::Mnemonic::Je
            | iced_x86::Mnemonic::Jne
            | iced_x86::Mnemonic::Jbe
            | iced_x86::Mnemonic::Ja
            | iced_x86::Mnemonic::Js
            | iced_x86::Mnemonic::Jns
            | iced_x86::Mnemonic::Jp
            | iced_x86::Mnemonic::Jnp
            | iced_x86::Mnemonic::Jl
            | iced_x86::Mnemonic::Jge
            | iced_x86::Mnemonic::Jle
            | iced_x86::Mnemonic::Jg
    )
}

fn chosen(symbol: &Sym, tokens: &BTreeSet<String>) -> Result<bool> {
    for token in tokens {
        match parse_selector(token)? {
            Selector::Name(name) if name == symbol.name => return Ok(true),
            Selector::Rva { rva, .. } if rva == symbol.rva => return Ok(true),
            _ => {}
        }
    }
    Ok(false)
}

fn select(
    symbols: &[Sym],
    options: &Options,
    windows_native: bool,
) -> Result<(Vec<Sym>, Vec<Sym>)> {
    let virt = if options.virtualize_all
        || (options.virtualize.is_empty() && options.mutate.is_empty() && !options.mutate_all)
    {
        symbols.to_vec()
    } else {
        let mut out = Vec::new();
        for item in symbols {
            if chosen(item, &options.virtualize)? {
                out.push(item.clone());
            }
        }
        out
    };
    let mut mutate: Vec<Sym> =
        if options.mutate_all || (!windows_native && !options.virtualize.is_empty()) {
            symbols
                .iter()
                .filter(|item| !virt.iter().any(|picked| picked.name == item.name))
                .cloned()
                .collect()
        } else {
            let mut out = Vec::new();
            for item in symbols {
                if chosen(item, &options.mutate)? {
                    out.push(item.clone());
                }
            }
            out
        };
    mutate.retain(|item| !virt.iter().any(|picked| picked.rva == item.rva));
    Ok((virt, mutate))
}

fn entry_span(symbols: &[Sym], rva: u32) -> usize {
    let size = symbols
        .iter()
        .find(|item| item.rva == rva)
        .map(|item| item.size)
        .unwrap_or(16);
    (size as usize).clamp(5, 64)
}

fn function_bytes<'a>(image: &'a PeImage, symbol: &Sym) -> Result<&'a [u8]> {
    pe::read_rva(image, symbol.rva, symbol.size as usize)
}

fn write_trampoline_site(image: &mut PeImage, symbol: &Sym, target: u64) -> Result<()> {
    if symbol.size < 5 {
        return Err(msg(format!(
            "{} is too small for a trampoline",
            symbol.name
        )));
    }
    let site = image.image_base + u64::from(symbol.rva);
    let next = site + 5;
    let rel = i64::try_from(target).map_err(|_| msg("trampoline target does not fit"))?
        - i64::try_from(next).map_err(|_| msg("trampoline site does not fit"))?;
    let rel = i32::try_from(rel).map_err(|_| msg("trampoline is out of range"))?;
    let mut bytes = vec![0xccu8; symbol.size as usize];
    bytes[0] = 0xe9;
    bytes[1..5].copy_from_slice(&rel.to_le_bytes());
    pe::write_rva(image, symbol.rva, &bytes)
}

fn mutate_function(image: &mut PeImage, symbol: &Sym, seed: u64) -> Result<Option<bool>> {
    if (seed ^ u64::from(symbol.rva)) & 1 != 0 {
        return Ok(None);
    }
    let bytes = function_bytes(image, symbol)?.to_vec();
    let start = image.image_base + u64::from(symbol.rva);
    let rewritten = crate::mutate::rewrite(&bytes, start);
    let place = crate::mutate::cave::plan(image, &symbol.name, symbol.rva, &rewritten, seed)?;
    crate::mutate::cave::commit(image, symbol.rva, &place)?;
    Ok(Some(rewritten != bytes))
}

struct Built {
    native_bridges: Vec<(u32, u32, u32)>,
    native_cleanup: Option<u32>,
    native_startup_unwind: Vec<loader::NativeStartupUnwind>,
    authenticated: bool,
    section: Section,
    state: Section,
    tls_size: u32,
    entry_rva: u32,
    header: Header,
}

struct CodeLayout {
    windows_native: bool,
    guarded: bool,
    auth_imports: Option<loader::AuthImports>,
    function_count: u32,
    section_rva: u32,
    loader_len: usize,
    resolve_len: usize,
    vm_off: usize,
    early_off: usize,
    data_rva: u32,
    vm_len: usize,
    vm_frame: usize,
    vm_dispatch: usize,
    vm_calls: usize,
    tramp_len: usize,
    tramp_off: u32,
    bridge_off: usize,
    payload_off: u32,
}

fn next_section_rva(image: &PeImage) -> u32 {
    image
        .sections
        .iter()
        .map(|sec| sec.rva + sec.bytes.len() as u32)
        .max()
        .unwrap_or(0x1000)
        .div_ceil(0x1000)
        * 0x1000
}

fn measured_loader(
    image: &PeImage,
    section_rva: u32,
    windows_native: bool,
    functions: u32,
    auth_imports: Option<loader::AuthImports>,
) -> Result<usize> {
    if !windows_native {
        return Ok(loader::assemble(&payload::dummy_plan(0x2000))?.len());
    }
    let origin = image.image_base + u64::from(section_rva) + HEADER_LEN as u64;
    let mut plan = payload::dummy_plan(origin);
    plan.original = image.image_base + u64::from(image.entry_rva);
    plan.payload = origin + 0x1000;
    plan.table = origin + 0x2000;
    plan.calls = origin + 0x3000;
    plan.runtime = origin + 0x5000;
    let native = loader::NativeLoader {
        startup_status: origin + 0x4000,
        preferred_base: image.image_base,
        functions,
    };
    if let Some(imports) = auth_imports {
        plan.payload_len = 1;
        let auth = loader::NativeAuthLoader {
            imports,
            expected_core: &[0; crate::crypto::authenticated::BOOTSTRAP_CORE_LEN],
            trusted_public: &[0; 65],
        };
        return Ok(
            loader::assemble_windows_native_authenticated(&plan, native, &auth)?
                .bytes
                .len(),
        );
    }
    Ok(loader::assemble_windows_native(&plan, native)?.len())
}

fn code_layout(
    image: &PeImage,
    functions: usize,
    windows_native: bool,
    guarded: bool,
    auth_imports: Option<loader::AuthImports>,
) -> Result<CodeLayout> {
    let section_rva = next_section_rva(image);
    let function_count = u32::try_from(functions).map_err(|_| msg("too many functions"))?;
    let (loader_len, resolve_len, vm, tramp_len) = measure_pe_code(
        image,
        section_rva,
        function_count,
        windows_native,
        guarded,
        auth_imports,
    )?;
    let tramp = HEADER_LEN + loader_len + resolve_len;
    let bridge_off = tramp + tramp_len * functions;
    let early_off = bridge_off + usize::from(windows_native) * functions * stub::HOST_BRIDGE_LEN;
    let early_off = if guarded {
        early_off.next_multiple_of(16)
    } else {
        early_off
    };
    let (vm_off, data_rva, payload_off) = split_pe_vm(&vm, early_off, section_rva, windows_native)?;
    let tramp_off = u32::try_from(tramp).map_err(|_| msg("VM section is too large"))?;
    Ok(CodeLayout {
        windows_native,
        guarded,
        auth_imports,
        function_count,
        section_rva,
        loader_len,
        resolve_len,
        vm_off,
        early_off,
        data_rva,
        vm_len: vm.bytes.len(),
        vm_frame: vm.frame,
        vm_dispatch: vm.dispatch,
        vm_calls: vm.calls,
        tramp_len,
        tramp_off,
        bridge_off,
        payload_off,
    })
}

fn split_pe_vm(
    vm: &stub::NativeVm,
    early_off: usize,
    section_rva: u32,
    windows_native: bool,
) -> Result<(usize, u32, u32)> {
    let state_start = vm.frame - usize::from(windows_native) * stub::PE_TLS_INDEX_BYTES;
    let min_split = early_off + crate::early::PE_CALLBACK_ROOM + state_start;
    let split = min_split.next_multiple_of(pe::SECTION_ALIGN as usize);
    let vm_off = split - state_start;
    let to_u32 = |value: usize| u32::try_from(value).map_err(|_| msg("VM section is too large"));
    let data_rva = section_rva
        .checked_add(to_u32(split)?)
        .ok_or_else(|| msg("PE runtime RVA overflows"))?;
    let payload_off = to_u32(vm_off + vm.bytes.len())?;
    Ok((vm_off, data_rva, payload_off))
}

fn measure_pe_code(
    image: &PeImage,
    section_rva: u32,
    functions: u32,
    windows_native: bool,
    guarded: bool,
    auth_imports: Option<loader::AuthImports>,
) -> Result<(usize, usize, stub::NativeVm, usize)> {
    let _tls = windows_native
        .then(|| stub::bind_pe_tls(stub::PE_TLS_PROBE_INDEX, stub::PE_TLS_LIMIT as u32));
    let _guarded = guarded.then(stub::bind_pe_guarded).transpose()?;
    let loader = measured_loader(image, section_rva, windows_native, functions, auth_imports)?;
    let resolve = if windows_native {
        0
    } else {
        assemble_resolve(0x1000)?.len()
    };
    let vm = measure_pe_vm(windows_native, functions as usize, auth_imports.is_some())?;
    Ok((loader, resolve, vm, stub::trampoline_len()?))
}

fn measure_pe_vm(
    windows_native: bool,
    functions: usize,
    authenticated: bool,
) -> Result<stub::NativeVm> {
    let _bridges = windows_native
        .then(|| {
            stub::bind_pe_bridges(
                stub::PE_TLS_PROBE_INDEX + 0x1000,
                stub::PE_TLS_PROBE_INDEX + 0x2000,
                functions,
            )
        })
        .transpose()?;
    let origin = if windows_native {
        stub::PE_VM_PROBE_BASE + 0x1000
    } else {
        0x1000
    };
    if authenticated {
        stub::assemble_vm_for_authenticated_lab(origin)
    } else {
        stub::assemble_vm(origin)
    }
}

#[cfg(test)]
mod tests {
    use super::payload::{layout_payload, payload_bytes, put};
    use super::*;
    use crate::crypto::{self, Header, HEADER_LEN};
    use crate::emu::{self, Policy};
    use crate::loader;
    use crate::sample::{self, build};
    use crate::vm::BcImage;

    #[test]
    fn native_direct_calls_preserve_an_image_relative_target() {
        use crate::ir::{Address, Block, Exit, FuncIr, Op, ARCH};

        let image = pe::parse(&build().unwrap().bytes).unwrap();
        let rva = image.entry_rva;
        let mut func = FuncIr {
            name: "caller".into(),
            rva,
            entry: 0,
            blocks: vec![Block {
                ops: Vec::new(),
                exit: Exit::CallRva { rva, next: 1 },
                opaque: false,
            }],
        };
        let target = Sym {
            name: "callee".into(),
            rva,
            size: 8,
            explicit_size: true,
        };
        route_win64_calls(&image, std::slice::from_ref(&target), &mut func).unwrap();
        let Exit::CallAbs { reg, next: 1 } = func.blocks[0].exit else {
            panic!("direct call did not receive a native return path");
        };
        assert!(usize::from(reg) >= ARCH);
        assert_eq!(func.blocks[0].ops, [Op::Lea(reg, Address::Rva(rva))]);

        for bad_rva in [rva + 1, image.import_rva, u32::MAX] {
            func.blocks[0].exit = Exit::CallRva {
                rva: bad_rva,
                next: 1,
            };
            assert!(route_win64_calls(&image, std::slice::from_ref(&target), &mut func).is_err());
        }
    }

    fn all(seed: u64) -> Options {
        Options {
            virtualize: BTreeSet::new(),
            mutate: BTreeSet::new(),
            virtualize_all: true,
            mutate_all: false,
            seed,
            random_key: false,
            debug_seed: false,
        }
    }

    #[test]
    fn protected_sample_matches_and_hides_plaintext() {
        let built = build().unwrap();
        let first = protect(&built.bytes, &all(1)).unwrap();
        let second = protect(&built.bytes, &all(2)).unwrap();
        assert_ne!(first.bytes, second.bytes);
        assert!(first.bytes.windows(9).all(|window| window != b"vmkek-ok:"));
        assert!(first.bytes.windows(9).all(|window| window != b"WriteFile"));
        let ran = emu::run_pe(&first.bytes, Policy::default()).unwrap();
        assert_eq!(ran.exit_code, 0, "{}", String::from_utf8_lossy(&ran.stdout));
        assert_eq!(ran.stdout, sample::line().into_bytes());
        let key = public_key(&first.report.public_key);
        assert!(first.bytes.windows(5).any(|window| window[0] == 0xe9));
        assert!(!first.report.passes.iter().any(|pass| pass == "dead-code"));
        assert!(first.report.passes.iter().any(|pass| pass == "trampoline"));
        assert!(!serde_json::to_string(&first.report)
            .unwrap()
            .contains("\"seed\""));
        let mut tampered = first.bytes.clone();
        let header = inspect(&first.bytes, &key).unwrap();
        let at = crypto::find_header(&tampered).unwrap();
        let flip = at + header.payload_off as usize + 8;
        tampered[flip] ^= 0xff;
        assert!(inspect(&tampered, &key).is_err());
        let forged = resign_swapped_payload(&first.bytes, &header, at);
        assert!(inspect(&forged.bytes, &key).is_err());
        let planted = {
            let mut bytes = first.bytes.clone();
            bytes[0x40..0x48].copy_from_slice(b"VMKEK64\0");
            bytes
        };
        assert_eq!(crypto::find_header(&planted).unwrap(), at);
        let debugged = emu::run_pe(
            &first.bytes,
            Policy {
                being_debugged: 1,
                ..Policy::default()
            },
        )
        .unwrap();
        assert_eq!(debugged.exit_code, 0xdeb6);
    }

    fn public_key(text: &str) -> [u8; 65] {
        let bytes = hex::decode(text).unwrap();
        bytes.try_into().unwrap()
    }

    struct Resigned {
        bytes: Vec<u8>,
        public: [u8; 65],
    }

    fn resign_swapped_payload(image: &[u8], header: &Header, at: usize) -> Resigned {
        let payload_at = at + header.payload_off as usize;
        let mut swapped = image[payload_at..payload_at + header.payload_len as usize].to_vec();
        swapped[8] ^= 0xff;
        let loader = &image[at + HEADER_LEN..];
        let (key, nonce) = loader::read_embedded_aead(loader).unwrap();
        assert_eq!(nonce, header.nonce);
        let foreign = crypto::seal_with(
            &swapped,
            &key,
            &nonce,
            header.original_entry,
            header.image_base,
        )
        .unwrap();
        let mut forged_header = header.clone();
        forged_header.public = foreign.public;
        forged_header.signature = foreign.signature;
        forged_header.tag = foreign.tag;
        forged_header.nonce = foreign.nonce;
        forged_header.raw_len = swapped.len() as u32;
        forged_header.payload_len = foreign.ciphertext.len() as u32;
        forged_header.sha256 = crypto::sha256(&foreign.ciphertext);
        forged_header.crc32 = vm::crc32(&foreign.ciphertext);
        let encoded = forged_header.to_bytes();
        let mut bytes = image.to_vec();
        bytes[at..at + encoded.len()].copy_from_slice(&encoded);
        let write_at = at + forged_header.payload_off as usize;
        bytes[write_at..write_at + foreign.ciphertext.len()].copy_from_slice(&foreign.ciphertext);
        Resigned {
            bytes,
            public: foreign.public,
        }
    }

    #[test]
    fn aead_inspect_rejects_tamper_and_forged_key() {
        let built = build().unwrap();
        let protected = protect(&built.bytes, &all(1)).unwrap();
        let pinned = public_key(&protected.report.public_key);
        let header = inspect(&protected.bytes, &pinned).unwrap();
        let at = crypto::find_header(&protected.bytes).unwrap();
        let payload_at = at + header.payload_off as usize;

        let mut flipped = protected.bytes.clone();
        flipped[payload_at + 8] ^= 0xff;
        assert!(inspect(&flipped, &pinned).is_err());

        let mut tag_header = header.clone();
        tag_header.tag[0] ^= 0xff;
        let mut tag_flipped = protected.bytes.clone();
        let encoded = tag_header.to_bytes();
        tag_flipped[at..at + encoded.len()].copy_from_slice(&encoded);
        assert!(inspect(&tag_flipped, &pinned).is_err());

        let forged = resign_swapped_payload(&protected.bytes, &header, at);
        assert_ne!(forged.public, pinned);
        assert!(inspect(&forged.bytes, &pinned).is_err());
        assert!(inspect(&forged.bytes, &forged.public).is_ok());

        let loader = &protected.bytes[at + HEADER_LEN..];
        let (key, _) = loader::read_embedded_aead(loader).unwrap();
        let header_bytes = &protected.bytes[at..at + HEADER_LEN];
        assert!(!crypto::header_exposes_key(header_bytes, &key));
        let scalar = crypto::deterministic_signing_scalar(1).unwrap();
        assert!(protected.bytes.windows(32).all(|window| window != scalar));
        assert!(protected
            .bytes
            .windows(9)
            .all(|window| window != b"vmkek-ok:" && window != b"WriteFile"));
    }

    #[test]
    fn inspect_rejects_a_flipped_signature_byte() {
        let built = build().unwrap();
        let protected = protect(&built.bytes, &all(1)).unwrap();
        let pinned = public_key(&protected.report.public_key);
        let header = inspect(&protected.bytes, &pinned).unwrap();
        let at = crypto::find_header(&protected.bytes).unwrap();
        let mut bad = header;
        bad.signature[0] ^= 0xff;
        let mut image = protected.bytes;
        let encoded = bad.to_bytes();
        image[at..at + encoded.len()].copy_from_slice(&encoded);
        let err = inspect(&image, &pinned).unwrap_err();
        assert_eq!(err.to_string(), "signature verification failed");
    }

    #[test]
    fn inspect_rejects_a_substituted_entry_and_image_base() {
        let built = build().unwrap();
        let protected = protect(&built.bytes, &all(1)).unwrap();
        let pinned = public_key(&protected.report.public_key);
        let header = inspect(&protected.bytes, &pinned).unwrap();
        let at = crypto::find_header(&protected.bytes).unwrap();
        for (entry, base) in [
            (header.original_entry ^ 1, header.image_base),
            (header.original_entry, header.image_base ^ 1),
        ] {
            let mut forged = header.clone();
            forged.original_entry = entry;
            forged.image_base = base;
            let mut image = protected.bytes.clone();
            let encoded = forged.to_bytes();
            image[at..at + encoded.len()].copy_from_slice(&encoded);
            assert!(
                inspect(&image, &pinned).is_err(),
                "substituted entry {entry:#x} base {base:#x} must not inspect"
            );
        }
    }

    fn assert_image_has_dispatcher(bytes: &[u8], seed: u64) {
        let stub = crate::stub::assemble_vm_seeded(0x1000, seed).unwrap();
        assert!(
            bytes
                .windows(stub.dispatcher().len())
                .any(|window| window == stub.dispatcher()),
            "build seed {seed} does not contain its dispatcher"
        );
    }

    fn assert_diversity_report(report: &Report) {
        assert!(report.seed.is_none());
        assert_eq!(report.diversity.equivalence, "Proven");
        assert_eq!(report.diversity.difference_claim, "ReducedToAssumption");
        assert!(report.diversity.difference_percent >= 25);
        assert_eq!(report.diversity.window, crate::stub::HANDLER_WINDOW);
        assert!(report.diversity.window_len > 0);
        assert_eq!(
            u64::from(report.diversity.difference_percent),
            u64::from(report.diversity.different_bytes) * 100
                / u64::from(report.diversity.window_len)
        );
        assert_eq!(report.diversity.varies, crate::vm::VARYING_ELEMENTS);
        let rendered = serde_json::to_string(report).unwrap();
        assert!(!rendered.contains("\"seed\""));
        assert!(rendered.contains("перестановка слотов"));
        assert!(rendered.contains("варианты хендлеров"));
        assert!(rendered.contains("соль шифра"));
        assert!(rendered.contains("порядок junk"));
        assert!(!rendered.contains("virtual-black-box"));
        assert!(report.passes.iter().any(|pass| pass == "vm-equivalence"));
        assert!(report.passes.iter().any(|pass| pass == "layout-stealth"));
        assert!(report.claims.iter().any(|item| {
            item.pass == "vm-equivalence" && item.claim == crate::proof::Claim::Proven
        }));
        assert!(report.claims.iter().any(|item| {
            item.pass == "layout-stealth" && item.claim == crate::proof::Claim::ReducedToAssumption
        }));
    }

    #[test]
    fn report_names_the_handler_window_and_the_varying_elements() {
        let built = build().unwrap();
        let first = protect(&built.bytes, &all(1)).unwrap();
        let second = protect(&built.bytes, &all(2)).unwrap();
        assert_ne!(first.bytes, second.bytes);
        assert_image_has_dispatcher(&first.bytes, 1);
        assert_image_has_dispatcher(&second.bytes, 2);
        let foreign = crate::stub::assemble_vm_seeded(0x1000, 2).unwrap();
        assert!(first
            .bytes
            .windows(foreign.dispatcher().len())
            .all(|window| window != foreign.dispatcher()));
        assert_diversity_report(&first.report);
        assert_diversity_report(&second.report);
        let ran = emu::run_pe(&second.bytes, Policy::default()).unwrap();
        assert_eq!(ran.exit_code, 0, "{}", String::from_utf8_lossy(&ran.stdout));
        assert_eq!(ran.stdout, sample::line().into_bytes());
    }

    #[test]
    fn code_layout_is_stable_within_one_build() {
        let built = build().unwrap();
        let once = protect(&built.bytes, &all(1)).unwrap();
        let twice = protect(&built.bytes, &all(1)).unwrap();
        assert_eq!(once.bytes.len(), twice.bytes.len());
        assert_eq!(once.bytes, twice.bytes);
    }

    #[test]
    fn deterministic_seed_is_byte_identical_and_stays_out_of_the_report() {
        let built = build().unwrap();
        let seed = 0x5a5a_11ce_u64;
        let first = protect(&built.bytes, &all(seed)).unwrap();
        let second = protect(&built.bytes, &all(seed)).unwrap();
        assert_eq!(first.bytes, second.bytes);
        assert!(first.report.seed.is_none());
        let rendered = serde_json::to_string(&first.report).unwrap();
        assert!(!rendered.contains("\"seed\""));
        assert!(!rendered.contains("\"nonce\""));
        assert!(!rendered.contains("\"masks\""));
        assert!(!rendered.contains("\"key\""));
        assert!(!rendered.contains(&seed.to_string()));
        let at = crypto::find_header(&first.bytes).unwrap();
        let (key, nonce) = loader::read_embedded_aead(&first.bytes[at + HEADER_LEN..]).unwrap();
        assert!(!rendered.contains(&hex::encode(key)));
        assert!(!rendered.contains(&hex::encode(nonce)));
        let scalar = crypto::deterministic_signing_scalar(seed).unwrap();
        assert!(!rendered.contains(&hex::encode(scalar)));
        assert!(first.bytes.windows(32).all(|window| window != scalar));
        let mut debug = all(seed);
        debug.debug_seed = true;
        let dumped = protect(&built.bytes, &debug).unwrap();
        assert_eq!(dumped.bytes, first.bytes);
        assert_eq!(dumped.report.seed, Some(seed));
        assert!(serde_json::to_string(&dumped.report)
            .unwrap()
            .contains("\"seed\""));
        let mut random = all(seed);
        random.random_key = true;
        let once = protect(&built.bytes, &random).unwrap();
        let twice = protect(&built.bytes, &random).unwrap();
        assert_ne!(once.bytes, twice.bytes);
        assert!(once.report.seed.is_none());
        assert!(!serde_json::to_string(&once.report)
            .unwrap()
            .contains("\"seed\""));
    }

    #[test]
    fn undecodable_export_is_an_error() {
        let image = pe::PeImage {
            image_base: crate::pe::IMAGE_BASE,
            entry_rva: 0x1000,
            sections: vec![pe::Section {
                name: ".text".into(),
                rva: 0x1000,
                bytes: vec![0x06, 0x06, 0x06, 0x06],
                characteristics: crate::pe::CH_TEXT,
            }],
            exports: vec![pe::Export {
                name: "start".into(),
                rva: 0x1000,
            }],
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
        let err = discover(&image, &all(1)).unwrap_err();
        assert!(err.to_string().contains("valid instruction"));
    }

    #[test]
    fn entry_point_is_virtualized_even_without_an_export() {
        let mut code = vec![0x90u8; 16];
        code[..10].copy_from_slice(&[0x48, 0xb8, 42, 0, 0, 0, 0, 0, 0, 0]);
        code[10] = 0xc3;
        let image = pe::PeImage {
            image_base: crate::pe::IMAGE_BASE,
            entry_rva: 0x1000,
            sections: vec![pe::Section {
                name: ".text".into(),
                rva: 0x1000,
                bytes: code,
                characteristics: crate::pe::CH_TEXT,
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
        let bytes = pe::emit(&image).unwrap();
        let protected = protect(&bytes, &all(3)).unwrap();
        let parsed = pe::parse(&protected.bytes).unwrap();
        let text = parsed
            .sections
            .iter()
            .find(|section| section.name == ".text")
            .unwrap();
        assert_eq!(text.bytes[0], 0xe9);
        let ran = emu::run_pe(&protected.bytes, Policy::default()).unwrap();
        assert_eq!(ran.exit_code, 42);
    }

    #[test]
    fn mutation_keeps_live_flags_and_uses_the_seed() {
        let dead = [0x48u8, 0x83, 0xc0, 0x01, 0xc3];
        let live = [0x48u8, 0x83, 0xc0, 0x01, 0x75, 0x00, 0xc3];
        let symbol = Sym {
            name: "t".into(),
            rva: 0x1000,
            size: dead.len() as u32,
            explicit_size: true,
        };
        let mut changed = image_with(&dead);
        assert_eq!(
            mutate_function(&mut changed, &symbol, 0x1000).unwrap(),
            Some(true)
        );
        assert_eq!(
            placed_body(&changed, symbol.size, 0x1000, 5),
            [0x48, 0x8d, 0x40, 0x01, 0xc3]
        );
        let mut skipped = image_with(&dead);
        assert_eq!(
            mutate_function(&mut skipped, &symbol, 0x1001).unwrap(),
            None
        );
        assert_eq!(skipped.sections[0].bytes, dead);
        let mut flagged = image_with(&live);
        let symbol = Sym {
            size: live.len() as u32,
            ..symbol
        };
        assert_eq!(
            mutate_function(&mut flagged, &symbol, 0x1000).unwrap(),
            Some(false)
        );
        assert_eq!(placed_body(&flagged, symbol.size, 0x1000, live.len()), live);
    }

    #[test]
    fn two_seeds_change_the_mutated_function_bytes() {
        let dead = [0x48u8, 0x83, 0xc0, 0x01, 0xc3];
        let symbol = Sym {
            name: "t".into(),
            rva: 0x1000,
            size: dead.len() as u32,
            explicit_size: true,
        };
        let mut first = image_with(&dead);
        let mut second = image_with(&dead);
        mutate_function(&mut first, &symbol, 0x1000).unwrap();
        mutate_function(&mut second, &symbol, 0x1002).unwrap();
        assert_ne!(first.sections[0].bytes, second.sections[0].bytes);
    }

    #[test]
    fn missing_cave_is_an_error_for_that_function() {
        let body = [0x48u8, 0x83, 0xc0, 0x01, 0xc3];
        let mut image = image_with(&body);
        image.sections.push(pe::Section {
            name: ".rdata".into(),
            rva: 0x1005,
            bytes: vec![0],
            characteristics: pe::CH_RDATA,
        });
        let symbol = Sym {
            name: "tight".into(),
            rva: 0x1000,
            size: body.len() as u32,
            explicit_size: true,
        };
        let err = mutate_function(&mut image, &symbol, 0x1000).unwrap_err();
        assert_eq!(err.to_string(), "tight has no code cave");
        assert_eq!(image.sections[0].bytes, body);
    }

    #[test]
    fn sample_mutation_fires_and_the_report_records_it() {
        let built = build().unwrap();
        let mix = built
            .symbols
            .iter()
            .find(|sym| sym.name == "mix")
            .expect("mix");
        let protected = protect(&built.bytes, &mutate_mix(u64::from(mix.rva & 1))).unwrap();
        assert!(protected
            .report
            .passes
            .iter()
            .any(|pass| pass == "instruction-substitution"));
        assert!(protected
            .report
            .passes
            .iter()
            .any(|pass| pass == "mutation-diversity"));
        assert!(protected.report.mutated.iter().any(|sym| sym.name == "mix"));
        assert_eq!(
            claim_of(&protected.report, "instruction-substitution"),
            proof::Claim::Proven
        );
        assert_eq!(
            claim_of(&protected.report, "mutation-diversity"),
            proof::Claim::ReducedToAssumption
        );
        assert_eq!(
            claim_of(&protected.report, "code-cave"),
            proof::Claim::Proven
        );
        assert_eq!(
            claim_of(&protected.report, "linear-desync"),
            proof::Claim::Proven
        );
        assert_mix_changed(&built.bytes, &protected.bytes, mix.rva, mix.size);
    }

    fn mutate_mix(seed: u64) -> Options {
        let mut virtualize = BTreeSet::new();
        virtualize.insert("start".into());
        virtualize.insert("compute".into());
        Options {
            virtualize,
            mutate: BTreeSet::new(),
            virtualize_all: false,
            mutate_all: false,
            seed,
            random_key: false,
            debug_seed: false,
        }
    }

    fn claim_of(report: &crate::report::Report, pass: &str) -> proof::Claim {
        report
            .claims
            .iter()
            .find(|item| item.pass == pass)
            .unwrap_or_else(|| panic!("missing {pass}"))
            .claim
    }

    fn assert_mix_changed(before: &[u8], after: &[u8], rva: u32, size: u32) {
        let orig = pe::parse(before).unwrap();
        let image = pe::parse(after).unwrap();
        let plain = pe::read_rva(&orig, rva, size as usize).unwrap().to_vec();
        let stub = pe::read_rva(&image, rva, size as usize).unwrap();
        assert_ne!(plain.as_slice(), stub);
        assert_eq!(stub[0], 0xe9);
        let ip = pe::IMAGE_BASE + u64::from(rva);
        let rewritten = crate::mutate::rewrite(&plain, ip);
        let seed = u64::from(rva & 1);
        assert_eq!(
            cave_body(&image, rva, size, seed, rewritten.len()),
            rewritten.as_slice()
        );
        for arg in [0u64, 1, 10, u64::MAX] {
            assert_eq!(mix_rax(&orig, rva, arg), mix_rax(&image, rva, arg), "{arg}");
        }
    }

    fn placed_body(image: &PeImage, size: u32, seed: u64, len: usize) -> &[u8] {
        cave_body(image, 0x1000, size, seed, len)
    }

    fn cave_body(image: &PeImage, rva: u32, size: u32, seed: u64, len: usize) -> &[u8] {
        let stub = pe::read_rva(image, rva, size as usize).unwrap();
        let rel = i32::from_le_bytes(stub[1..5].try_into().unwrap());
        let cave = (i64::from(rva) + 5 + i64::from(rel)) as u32;
        let skip = crate::mutate::desync::prefix(seed).len() as u32;
        pe::read_rva(image, cave + skip, len).unwrap()
    }

    fn mix_rax(image: &PeImage, rva: u32, arg: u64) -> u64 {
        let mut machine = emu::bare(Policy::default()).unwrap();
        let rsp = machine.regs[4];
        for section in image
            .sections
            .iter()
            .filter(|section| pe::executable(section))
        {
            machine.regions.push(emu::Region {
                base: image.image_base + u64::from(section.rva),
                data: section.bytes.clone(),
            });
        }
        machine.rip = image.image_base + u64::from(rva);
        machine.regs[1] = arg;
        machine.regs[4] = rsp;
        machine.run().unwrap();
        machine.regs[0]
    }

    #[test]
    fn layout_import_offset_points_at_the_import_count() {
        let mut image = image_with(&[0xc3]);
        image.imports.push(pe::Import {
            dll: "kernel32.dll".into(),
            name: "WriteFile".into(),
            iat_rva: 0x2100,
            name_rva: 0x2200,
            dll_rva: 0x2300,
        });
        let lowered = BcImage {
            perm: [0; 256],
            inv: [0; 256],
            slots: crate::vm::SlotMap::identity(),
            handler_mix: 0,
            funcs: Vec::new(),
        };
        let strings = [(0x2000u32, 8u32, 1u8)];
        let tables = payload::StringTables {
            trace: &strings,
            maps: &[],
        };
        let (body, _table, _runtime, import_off) =
            layout_payload(&lowered, &tables, 0x1400_3000, &image, 1).unwrap();
        let off = import_off as usize;
        assert_eq!(
            u32::from_le_bytes(body[off..off + 4].try_into().unwrap()),
            1
        );
        assert_eq!(
            u32::from_le_bytes(body[off + 4..off + 8].try_into().unwrap()),
            0x2100
        );
    }

    #[test]
    fn payload_past_the_address_space_is_outside_the_file() {
        let err = payload_bytes(&[0; 16], usize::MAX - 8, 16, 8).unwrap_err();
        assert_eq!(err.to_string(), "payload is outside the file");
    }

    #[test]
    fn payload_write_before_the_buffer_is_an_error() {
        let mut buf = [0u8; 4];
        let err = put(&mut buf, 10, 9, &[1]).unwrap_err();
        assert_eq!(err.to_string(), "payload write is outside the buffer");
        let err = put(&mut buf, 10, 12, &[1, 2, 3]).unwrap_err();
        assert_eq!(err.to_string(), "payload write is outside the buffer");
        put(&mut buf, 10, 10, &[1, 2, 3, 4]).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
    }

    fn image_with(code: &[u8]) -> PeImage {
        pe::PeImage {
            image_base: crate::pe::IMAGE_BASE,
            entry_rva: 0x1000,
            sections: vec![pe::Section {
                name: ".text".into(),
                rva: 0x1000,
                bytes: code.to_vec(),
                characteristics: crate::pe::CH_TEXT,
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
        }
    }
}
