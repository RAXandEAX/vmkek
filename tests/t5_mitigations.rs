use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic};
use vmkek::stub::{self, Trampoline};

#[test]
fn trampoline_uses_jumps_instead_of_push_return_transfers() {
    let origin = 0x4000;
    let bytes = stub::assemble_trampoline(&Trampoline {
        origin,
        frame: 0x8000,
        runtime: 0xa000,
        entry: 0,
        dispatch: 0x6000,
        image_base: 0x1000,
        chains: 0xc000,
    })
    .unwrap();
    let mut prior = None;
    let mut indirect_jumps = 0;
    for insn in Decoder::with_ip(64, &bytes, origin, DecoderOptions::NONE) {
        assert!(!insn.is_invalid());
        assert!(prior != Some(Mnemonic::Push) || insn.mnemonic() != Mnemonic::Ret);
        indirect_jumps += usize::from(insn.flow_control() == FlowControl::IndirectBranch);
        prior = Some(insn.mnemonic());
    }
    assert!(indirect_jumps > 0);
}

#[test]
fn protected_pe_separates_executable_code_from_writable_state() {
    use vmkek::{crypto, pe};

    const EXECUTE: u32 = 0x2000_0000;
    const WRITE: u32 = 0x8000_0000;
    let protected = protected_sample();
    let image = pe::parse(&protected.bytes).unwrap();
    assert!(image
        .sections
        .iter()
        .all(|s| { s.characteristics & (EXECUTE | WRITE) != EXECUTE | WRITE }));
    let code = image
        .sections
        .iter()
        .find(|s| s.bytes.starts_with(crypto::MAGIC))
        .unwrap();
    let state = image
        .sections
        .iter()
        .find(|s| s.rva == code.rva + code.bytes.len() as u32)
        .unwrap();
    assert_eq!(code.characteristics & (EXECUTE | WRITE), EXECUTE);
    assert_eq!(state.characteristics & (EXECUTE | WRITE), WRITE);
    assert_eq!(state.rva % 0x1000, 0);
}

fn protected_sample() -> vmkek::protect::Protected {
    use vmkek::{protect, sample};

    let input = sample::build().unwrap();
    protect::protect(&input.bytes, &options()).unwrap()
}

fn options() -> vmkek::protect::Options {
    vmkek::protect::Options {
        virtualize: Default::default(),
        mutate: Default::default(),
        virtualize_all: true,
        mutate_all: false,
        seed: 17,
        random_key: false,
        debug_seed: false,
    }
}

#[test]
fn guard_configuration_is_not_discarded_when_header_bit_is_clear() {
    use vmkek::{pe, sample};

    let mut input = sample::build().unwrap().bytes;
    let section = pe::section_file_offset(&input, ".rdata").unwrap();
    let load_config_rva = 0x2600u32;
    let load_config_size = 0x94u32;
    let base = section + 0x600;
    input[0x158..0x15c].copy_from_slice(&load_config_rva.to_le_bytes());
    input[0x15c..0x160].copy_from_slice(&load_config_size.to_le_bytes());
    input[base..base + 4].copy_from_slice(&load_config_size.to_le_bytes());
    input[base + 0x90..base + 0x94].copy_from_slice(&0x100u32.to_le_bytes());
    let error = rewrite_error(&input);
    assert!(error.to_string().contains("guard configuration"), "{error}");
}

#[test]
fn rejects_existing_rwx_and_unsupported_section_alignment() {
    use vmkek::sample;

    let input = sample::build().unwrap().bytes;
    let mut low_alignment = input.clone();
    low_alignment[0xb8..0xbc].copy_from_slice(&0x200u32.to_le_bytes());
    let error = rewrite_error(&low_alignment);
    assert!(
        error.to_string().contains("page-aligned permissions"),
        "{error}"
    );

    let mut rwx = input;
    rwx[0x188 + 39] |= 0x80;
    let error = rewrite_error(&rwx);
    assert!(
        error.to_string().contains("writable executable section"),
        "{error}"
    );
}

#[test]
fn rejects_section_tables_that_would_extend_into_first_page() {
    use vmkek::{pe, sample};

    let input = sample::build().unwrap().bytes;
    let mut image = pe::parse(&input).unwrap();
    for index in 0..89 {
        image.sections.push(pe::Section {
            name: format!(".s{index}"),
            rva: 0x3000 + index * 0x1000,
            bytes: vec![0],
            characteristics: pe::CH_RDATA,
        });
    }
    let input = pe::emit(&image).unwrap();
    let error = rewrite_error(&input);
    assert!(
        error.to_string().contains("page-aligned permissions"),
        "{error}"
    );
}

#[test]
fn generated_pe_code_starts_after_grown_unwind_section() {
    use vmkek::{pe, protect};

    let image = image_with_page_sized_unwind();
    let input = pe::emit(&image).unwrap();
    let protected = protect::protect(&input, &options()).unwrap();
    let image = pe::parse(&protected.bytes).expect("non-overlapping sections");
    assert!(image.entry_rva >= 0x5000);
}

#[test]
fn rejects_unwind_growth_into_an_existing_section() {
    use vmkek::pe;

    let mut image = image_with_page_sized_unwind();
    image.sections.push(pe::Section {
        name: ".after".into(),
        rva: 0x4000,
        bytes: vec![0],
        characteristics: pe::CH_RDATA,
    });
    let input = pe::emit(&image).unwrap();
    let error = rewrite_error(&input);
    assert!(
        error
            .to_string()
            .contains("unwind info does not fit before the next section"),
        "{error}"
    );
}

fn image_with_page_sized_unwind() -> vmkek::pe::PeImage {
    use vmkek::{pe, sample};

    let sample = sample::build().unwrap();
    let mut image = pe::parse(&sample.bytes).unwrap();
    let mix = sample
        .symbols
        .iter()
        .find(|symbol| symbol.name == "mix")
        .unwrap();
    let mut pdata = vec![0; 0x1000];
    for (slot, field) in pdata
        .chunks_exact_mut(4)
        .zip([mix.rva, mix.rva + mix.size, 0x3010])
    {
        slot.copy_from_slice(&field.to_le_bytes());
    }
    pdata[0x10] = 1;
    image.sections.push(pe::Section {
        name: ".pdata".into(),
        rva: 0x3000,
        bytes: pdata,
        characteristics: pe::CH_RDATA,
    });
    image.exception_rva = 0x3000;
    image.exception_size = 12;
    image
}

fn rewrite_error(input: &[u8]) -> vmkek::error::Error {
    let Err(error) = vmkek::protect::protect(input, &options()) else {
        panic!("expected the PE rewrite to reject the input");
    };
    error
}

#[test]
fn native_pe_retains_supported_cet_and_os_directories() {
    use vmkek::{pe, protect};

    let input = native_metadata_input();
    let source = pe::parse(&input).unwrap();
    let protected = protect::protect_windows_native(&input, &options()).unwrap();
    let output = pe::parse(&protected.bytes).unwrap();
    assert_eq!(pe::image_kind(&input).unwrap().characteristics & 1, 0);
    assert_eq!(
        pe::image_kind(&protected.bytes).unwrap().characteristics & 1,
        1
    );
    assert_eq!(source.imports, output.imports);
    assert_eq!(
        (output.import_rva, output.iat_rva),
        (source.import_rva, source.iat_rva)
    );
    assert_eq!(directory(&protected.bytes, 10), (0x2600, 0x94));
    assert_eq!(
        pe::read_rva(&output, 0x2600, 0x94).unwrap(),
        pe::read_rva(&source, 0x2600, 0x94).unwrap(),
    );
    assert_eq!(directory(&protected.bytes, 2), (0x2700, 16));
    assert_eq!(pe::read_rva(&output, 0x2700, 16).unwrap(), &[0xA7; 16]);
    assert_eq!(pe::read_rva(&output, 0x2800, 56).unwrap(), &[0; 56]);
    assert_eq!(pe::read_rva(&output, 0x2880, 32).unwrap(), &[0; 32]);

    let (debug, len) = directory(&protected.bytes, 6);
    assert_eq!(len, 28);
    let entry = pe::read_rva(&output, debug, 28).unwrap();
    assert_eq!(u32_at(entry, 12), 20);
    assert_eq!(u32_at(entry, 16), 4);
    let cet_rva = u32_at(entry, 20);
    let cet_raw = u32_at(entry, 24) as usize;
    assert_eq!(cet_rva, debug + 28);
    assert_eq!(
        pe::read_rva(&output, cet_rva, 4).unwrap(),
        &1u32.to_le_bytes()
    );
    assert_eq!(&protected.bytes[cet_raw..cet_raw + 4], &1u32.to_le_bytes());
}

#[test]
fn native_pe_refuses_unsupported_relocs_cfg_and_extended_cfi() {
    use vmkek::pe;

    let input = native_metadata_input();
    let mut unaligned = input.clone();
    unaligned[0xb0..0xb8].copy_from_slice(&0x0001_4000_0001u64.to_le_bytes());
    assert_native_rejection(&unaligned, "64-KiB aligned");

    let mut overflowing = input.clone();
    overflowing[0xb0..0xb8].copy_from_slice(&0xffff_ffff_ffff_0000u64.to_le_bytes());
    assert_native_rejection(&overflowing, "in range");

    let mut aslr = input.clone();
    let mut kind = pe::image_kind(&aslr).unwrap();
    kind.dll_characteristics |= 0x0040;
    pe::set_image_kind(&mut aslr, &kind).unwrap();
    assert_native_rejection(&aslr, "base relocation");

    let mut reloc = input.clone();
    put_directory(&mut reloc, 5, 0x2770, 12);
    assert_native_rejection(&reloc, "base relocation");

    let mut cfg = input.clone();
    let mut kind = pe::image_kind(&cfg).unwrap();
    kind.dll_characteristics |= 0x4000;
    pe::set_image_kind(&mut cfg, &kind).unwrap();
    assert_native_rejection(&cfg, "CFG image");

    let mut hidden_cfg = input.clone();
    let raw = pe::section_file_offset(&hidden_cfg, ".rdata").unwrap();
    put32_at(&mut hidden_cfg, raw + 0x690, 0x100);
    assert_native_rejection(&hidden_cfg, "guard configuration");

    let mut forward = input;
    let raw = pe::section_file_offset(&forward, ".rdata").unwrap();
    put32_at(&mut forward, raw + 0x870, 0x41);
    assert_native_rejection(&forward, "forward-CFI");
}

#[test]
fn native_pe_keeps_other_unwind_and_refuses_unsupported_rewritten_frames() {
    use vmkek::{pe, protect};

    let input = pe::emit(&image_with_page_sized_unwind()).unwrap();
    assert_native_rejection(&input, "unsupported unwind records");
    let mut options = options();
    options.virtualize_all = false;
    options.virtualize.insert("start".into());
    let protected = protect::protect_windows_native(&input, &options).unwrap();
    let image = pe::parse(&protected.bytes).unwrap();
    assert_eq!((image.exception_rva, image.exception_size), (0x3000, 12));
    assert_eq!(
        pe::read_rva(&image, 0x3000, 0x1000).unwrap(),
        pe::read_rva(&pe::parse(&input).unwrap(), 0x3000, 0x1000).unwrap(),
    );
}

#[test]
fn native_debug_cleanup_refuses_os_metadata_aliases() {
    let mut input = native_metadata_input();
    let raw = vmkek::pe::section_file_offset(&input, ".rdata").unwrap();
    let entry = raw + 0x800 + 28;
    let mut inconsistent = input.clone();
    put32_at(&mut inconsistent, entry + 24, (raw + 0x881) as u32);
    assert_native_rejection(&inconsistent, "mapped debug record offset");

    put32_at(&mut input, entry + 20, 0x2600);
    put32_at(&mut input, entry + 24, (raw + 0x600) as u32);
    assert_native_rejection(&input, "overlaps OS-owned image data");
}

fn native_metadata_input() -> Vec<u8> {
    use vmkek::{pe, sample};

    let sample = sample::build().unwrap();
    let mut image = pe::parse(&sample.bytes).unwrap();
    let rdata = image
        .sections
        .iter_mut()
        .find(|item| item.rva == 0x2000)
        .unwrap();
    rdata.bytes.resize(0x900, 0);
    put32_at(&mut rdata.bytes, 0x600, 0x94);
    rdata.bytes[0x658..0x660].copy_from_slice(&(image.image_base + 0x3000).to_le_bytes());
    rdata.bytes[0x700..0x710].fill(0xA7);
    image.sections.push(pe::Section {
        name: ".data".into(),
        rva: 0x3000,
        bytes: vec![0x53; 8],
        characteristics: pe::CH_DATA,
    });
    let mut input = pe::emit(&image).unwrap();
    put_directory(&mut input, 2, 0x2700, 16);
    put_directory(&mut input, 6, 0x2800, 56);
    put_directory(&mut input, 10, 0x2600, 0x94);
    let raw = pe::section_file_offset(&input, ".rdata").unwrap();
    add_debug_entry(&mut input, raw, 0x800, 20, 0x870, 4);
    put32_at(&mut input, raw + 0x870, 1);
    add_debug_entry(&mut input, raw, 0x81c, 2, 0x880, 32);
    input[raw + 0x880..raw + 0x884].copy_from_slice(b"RSDS");
    input
}

fn add_debug_entry(bytes: &mut [u8], raw: usize, at: usize, kind: u32, data: usize, size: u32) {
    let record = raw + at;
    put32_at(bytes, record + 12, kind);
    put32_at(bytes, record + 16, size);
    put32_at(bytes, record + 20, 0x2000 + data as u32);
    put32_at(bytes, record + 24, (raw + data) as u32);
}

fn directory(bytes: &[u8], index: usize) -> (u32, u32) {
    let at = 0x108 + index * 8;
    (u32_at(bytes, at), u32_at(bytes, at + 4))
}

fn put_directory(bytes: &mut [u8], index: usize, rva: u32, size: u32) {
    let at = 0x108 + index * 8;
    put32_at(bytes, at, rva);
    put32_at(bytes, at + 4, size);
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn put32_at(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn assert_native_rejection(input: &[u8], expected: &str) {
    let Err(error) = vmkek::protect::protect_windows_native(input, &options()) else {
        panic!("expected native PE rewrite to reject the input");
    };
    assert!(error.to_string().contains(expected), "{error}");
}
