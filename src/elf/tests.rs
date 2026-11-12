use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use super::*;

macro_rules! shdr_bytes {
    ($name:expr, $kind:expr, $flags:expr, $addr:expr, $offset:expr, $size:expr, $link:expr, $info:expr, $align:expr, $entsize:expr $(,)?) => {
        shdr_spec(ShdrSpec {
            name: $name,
            kind: $kind,
            flags: $flags,
            addr: $addr,
            offset: $offset,
            size: $size,
            link: $link,
            info: $info,
            align: $align,
            entsize: $entsize,
        })
    };
}

const TEXT_VA: u64 = 0x390;
const DATA_VA: u64 = 0x2200;
const GOT_VA: u64 = 0x2210;
const GOT_PLT_VA: u64 = 0x2220;
const PUTS_GOT: u64 = GOT_PLT_VA + 24;
const PLT_VA: u64 = 0x360;
const PLT_LAZY: u64 = 0x370;
const PLT_SEC: u64 = 0x380;
const DYN_VA: u64 = 0x2000;
const HASH_VA: u64 = 0x200;
const DYNSYM_VA: u64 = 0x240;
const DYNSTR_VA: u64 = 0x2A0;
const VERSYM_VA: u64 = 0x2E0;
const VERNEED_VA: u64 = 0x2E8;
const RELA_VA: u64 = 0x310;
const JMPREL_VA: u64 = 0x340;
const TEXT: [u8; 6] = [0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3];

#[test]
fn synthetic_shared_object_matches_authored_fields() {
    let bytes = shared_object();
    let image = parse(&bytes).unwrap();
    assert_shared(&image);
    let frozen = include_bytes!("testdata/reference.elf");
    assert_eq!(bytes, frozen.as_slice());
    assert_shared(&parse(frozen).unwrap());
    assert_readelf_or_authored(frozen, &image);
}

#[test]
fn synthetic_object_matches_relocations() {
    let image = parse(&object_file()).unwrap();
    assert_object(&image);
}

#[test]
fn implicit_rel_addend_comes_from_the_instruction() {
    let image = parse(&rel_object()).unwrap();
    let abs = image
        .relocations
        .iter()
        .find(|reloc| reloc.kind == RelocKind::Abs32)
        .unwrap();
    let pc = image
        .relocations
        .iter()
        .find(|reloc| reloc.kind == RelocKind::Pc32)
        .unwrap();
    assert_eq!(abs.offset, 0);
    assert_eq!(abs.addend, 0x1234_5678);
    assert_eq!(pc.offset, 4);
    assert_eq!(pc.addend, -4);
    assert_eq!(abs.section, ".rel.text");
    assert_eq!(abs.target, ".text");
}

#[test]
fn relr_bitmap_expands_to_relative_slots() {
    let image = parse(&relr_file()).unwrap();
    let relocs: Vec<_> = image
        .relocations
        .iter()
        .filter(|reloc| reloc.kind == RelocKind::Relative)
        .collect();
    assert_eq!(relocs.len(), 2);
    assert_eq!(relocs[0].offset, 0x100);
    assert_eq!(relocs[0].addend, 0x1111);
    assert_eq!(relocs[1].offset, 0x108);
    assert_eq!(relocs[1].addend, 0x2222);
    assert_eq!(relocs[0].section, ".relr.dyn");
}

#[test]
fn sectionless_dynamic_uses_hash_and_program_headers() {
    let image = parse(&sectionless_shared()).unwrap();
    assert!(image.sections.is_empty());
    assert_eq!(image.dynamic_symbols.len(), 4);
    assert_shared_symbols(&image);
    let puts = import(&image, "puts");
    assert_eq!(puts.got, Some(PUTS_GOT));
    assert_eq!(puts.plt, Some(PLT_SEC));
    assert!(image.plt.iter().any(|entry| entry.resolver));
    assert_eq!(image.got.plt_addr, GOT_PLT_VA);
    assert_eq!(image.got.addr, GOT_VA);
}

#[test]
fn gnu_hash_counts_dynamic_symbols_without_sections() {
    let image = parse(&gnu_hash_image()).unwrap();
    assert!(image.sections.is_empty());
    assert_eq!(image.dynamic_symbols.len(), 2);
    assert_eq!(image.dynamic_symbols[1].name, "answer");
    assert_eq!(image.exports.len(), 1);
    assert_eq!(image.exports[0].name, "answer");
    assert_eq!(image.exports[0].kind, SymbolKind::Func);
    assert!(image.dynamic_value(DynamicTag::GnuHash).is_some());
}

#[test]
fn minimal_executable_without_sections() {
    let image = parse(&carrier()).unwrap();
    assert_eq!(image.kind, ElfKind::Executable);
    assert_eq!(image.entry, 0x400100);
    assert_eq!(image.image_base, 0x400000);
    assert_eq!(image.segments.len(), 1);
    assert_eq!(image.segments[0].kind, SegmentKind::Load);
    assert_eq!(image.segments[0].flags, 7);
    assert!(image.sections.is_empty());
    assert!(image.dynamic.is_empty());
    assert!(image.exports.is_empty());
    assert!(image.plt.is_empty());
}

#[test]
fn extended_header_counts_match_the_plain_image() {
    let plain = object_file();
    let image = parse(&plain).unwrap();
    let extended = with_extended_section_count(&plain);
    assert_eq!(parse(&extended).unwrap().symbols, image.symbols);
    let xindex = with_extended_shstrndx(&plain);
    assert_eq!(parse(&xindex).unwrap().sections.len(), image.sections.len());
    assert_eq!(
        parse(&xindex).unwrap().section(".text").unwrap().bytes,
        image.section(".text").unwrap().bytes
    );

    let shared = shared_object();
    let parsed = parse(&shared).unwrap();
    let phnum = with_extended_phnum(&shared);
    let again = parse(&phnum).unwrap();
    assert_eq!(again.segments.len(), parsed.segments.len());
    assert_eq!(again.entry, parsed.entry);
    assert_eq!(again.sections[0].size, 0);
    assert_eq!(again.sections[0].link, 0);
    assert_eq!(again.sections[0].info, 0);
}

#[test]
fn format_errors_are_explicit() {
    assert_eq!(parse(&[]).unwrap_err().to_string(), "not an ELF image");
    assert_eq!(
        parse(&[0x7f, b'E', b'L', b'F']).unwrap_err().to_string(),
        "elf header is truncated"
    );
    let mut class = header_only(2, 0);
    class[4] = 1;
    assert_eq!(
        parse(&class).unwrap_err().to_string(),
        "only ELF64 is supported"
    );
    let mut data = header_only(2, 0);
    data[5] = 2;
    assert_eq!(
        parse(&data).unwrap_err().to_string(),
        "only little-endian ELF is supported"
    );
    let mut machine = header_only(2, 0);
    machine[18..20].copy_from_slice(&183u16.to_le_bytes());
    assert_eq!(
        parse(&machine).unwrap_err().to_string(),
        "only x86-64 ELF is supported"
    );
    let mut kind = header_only(4, 0);
    kind[16..18].copy_from_slice(&4u16.to_le_bytes());
    assert_eq!(
        parse(&kind).unwrap_err().to_string(),
        "unsupported ELF type"
    );

    let mut many = header_only(2, 64);
    many[56..58].copy_from_slice(&600u16.to_le_bytes());
    assert_eq!(
        parse(&many).unwrap_err().to_string(),
        "too many program headers"
    );
    let mut short = header_only(2, 64);
    short[56..58].copy_from_slice(&1u16.to_le_bytes());
    short.truncate(64);
    assert_eq!(
        parse(&short).unwrap_err().to_string(),
        "program headers are outside the file"
    );

    let mut sections = shared_object();
    sections[60..62].copy_from_slice(&5000u16.to_le_bytes());
    assert_eq!(
        parse(&sections).unwrap_err().to_string(),
        "too many sections"
    );

    let mut reloc = shared_object();
    let info = (99u64 << 32) | 6;
    reloc[0x330..0x338].copy_from_slice(&info.to_le_bytes());
    assert_eq!(
        parse(&reloc).unwrap_err().to_string(),
        "relocation symbol index is out of range"
    );

    let mut syment = shared_object();
    syment[0x1068..0x1070].copy_from_slice(&16u64.to_le_bytes());
    assert_eq!(
        parse(&syment).unwrap_err().to_string(),
        "dynamic symbol entry size is not 24"
    );
}

#[test]
fn virtual_read_stops_at_load_filesz() {
    let parsed = parse(&symtab_past_filesz());
    if let Ok(image) = &parsed {
        let value = image.dynamic_symbols.get(1).map(|symbol| symbol.value);
        panic!("read past p_filesz, dynamic symbol value {value:?}");
    }
    let err = parsed.unwrap_err().to_string();
    assert!(
        err.contains("load segment") || err.contains("virtual address"),
        "{err}"
    );
}

#[test]
fn unmapped_relocation_is_rejected() {
    let parsed = parse(&unmapped_rel());
    if let Ok(image) = &parsed {
        panic!(
            "unmapped place became addend {}",
            image
                .relocations
                .first()
                .map(|reloc| reloc.addend)
                .unwrap_or(-1)
        );
    }
    let err = parsed.unwrap_err().to_string();
    assert!(err.contains("relocation place"), "{err}");
}

#[test]
fn relocation_split_across_file_and_bss_is_rejected() {
    let err = parse(&split_file_bss_rel()).unwrap_err().to_string();
    assert!(err.contains("bss") || err.contains("cross"), "{err}");
}

#[test]
fn relocation_entirely_in_bss_keeps_zero_addend() {
    let image = parse(&bss_rel()).unwrap();
    assert_eq!(image.relocations.len(), 1);
    assert_eq!(image.relocations[0].offset, 0x1020);
    assert_eq!(image.relocations[0].addend, 0);
}

#[test]
fn got_virtual_address_overflow_is_an_error() {
    let err = parse(&got_address_overflow()).unwrap_err().to_string();
    assert!(err.contains("overflow"), "{err}");
}

#[test]
fn plt_virtual_address_overflow_is_an_error() {
    let err = parse(&plt_address_overflow()).unwrap_err().to_string();
    assert!(err.contains("overflow"), "{err}");
}

#[test]
fn plt_rip_relative_displacement_wraps() {
    let image = parse(&plt_rip_relative_wrap()).unwrap();
    assert_eq!(image.plt.len(), 1);
    assert_eq!(image.plt[0].addr, u64::MAX - 5);
    assert_eq!(image.plt[0].got, Some(8));
}

#[test]
fn got_reloc_matching_stays_linear() {
    let _ = median_got_parse(2_000);
    let small = median_got_parse(8_000);
    let large = median_got_parse(16_000);
    assert!(
        large < small.saturating_mul(3) || large < Duration::from_millis(250),
        "got/reloc matching scaled quadratically: {small:?} -> {large:?}"
    );
}

#[test]
fn non_utf8_symbol_names_stay_distinct_bytes() {
    let image = parse(&non_utf8_exports()).unwrap();
    assert_eq!(image.exports.len(), 2);
    assert_eq!(image.exports[0].name.as_bytes(), &[0xff, 0xfe]);
    assert_eq!(image.exports[1].name.as_bytes(), &[0xfe, 0xff]);
    assert_ne!(image.exports[0].name.as_bytes(), "\u{FFFD}".as_bytes());
}

#[test]
fn section_address_zero_must_match_strtab() {
    let err = parse(&strtab_at_zero_disagrees()).unwrap_err().to_string();
    assert!(err.contains("address disagrees"), "{err}");
}

#[test]
fn section_address_zero_must_match_symtab() {
    let err = parse(&symtab_at_zero_disagrees()).unwrap_err().to_string();
    assert!(err.contains("address disagrees"), "{err}");
}

#[test]
fn section_address_zero_must_match_pltgot() {
    let err = parse(&pltgot_at_zero_disagrees()).unwrap_err().to_string();
    assert!(err.contains("DT_PLTGOT"), "{err}");
}

#[test]
fn dynamic_address_zero_is_legal_when_it_matches() {
    let image = parse(&symtab_at_zero_agrees()).unwrap();
    assert_eq!(image.dynamic_symbols[1].name, "answer");
    assert_eq!(image.dynamic_value(DynamicTag::SymTab), Some(0));
    assert_eq!(image.exports[0].name, "answer");
}

#[test]
fn version_chain_beyond_essential_window_is_rejected() {
    let err = parse(&version_chain_past_window()).unwrap_err().to_string();
    assert!(
        err.contains("version") || err.contains("too large") || err.contains("truncated"),
        "{err}"
    );
}

#[test]
fn relr_base_overflow_is_an_error() {
    let err = parse(&relr_overflow()).unwrap_err().to_string();
    assert!(err.contains("overflow"), "{err}");
}

#[test]
fn plt_entry_count_is_capped() {
    let err = parse(&plt_over_cap()).unwrap_err().to_string();
    assert!(err.contains("too many PLT"), "{err}");
}

#[test]
fn system_image_and_compiler_output_match() {
    let path = std::env::current_exe().unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let image = parse(&bytes).expect("running test binary");
    assert!(matches!(image.kind, ElfKind::Executable | ElfKind::Shared));
    assert_ne!(image.entry, 0);
    assert!(image.segments.iter().any(|segment| {
        segment.kind == SegmentKind::Load
            && image.entry >= segment.vaddr
            && image.entry < segment.vaddr + segment.memsz
    }));
    assert!(
        image
            .needed
            .iter()
            .any(|name| name.contains("libc") || name.contains("ld-")),
        "{:?}",
        image.needed
    );
    assert!(!image.dynamic_symbols.is_empty());
    assert!(!image.relocations.is_empty());
    assert!(image
        .interp
        .as_ref()
        .is_some_and(|path| path.contains("ld")));
    assert_readelf_or_authored(&bytes, &image);

    match compile_shared() {
        None => assert_shared(&parse(&shared_object()).unwrap()),
        Some(bytes) => {
            let image = parse(&bytes).expect("gcc shared object");
            assert_gcc_shared(&image);
            assert_readelf_or_authored(&bytes, &image);
        }
    }
    match compile_executable() {
        None => assert_eq!(parse(&carrier()).unwrap().kind, ElfKind::Executable),
        Some(bytes) => {
            let image = parse(&bytes).expect("gcc executable");
            assert_eq!(image.kind, ElfKind::Executable);
            assert_ne!(image.entry, 0);
            assert_ne!(image.image_base, 0);
            assert!(image.needed.iter().any(|name| name.contains("libc")));
            assert!(image
                .interp
                .as_ref()
                .is_some_and(|path| path.contains("ld")));
            assert_readelf_or_authored(&bytes, &image);
        }
    }
    match assemble_object() {
        None => assert_object(&parse(&object_file()).unwrap()),
        Some(bytes) => {
            let image = parse(&bytes).expect("assembler object");
            assert_eq!(image.kind, ElfKind::Relocatable);
            assert!(image.symbols.iter().any(|symbol| symbol.name == "foo"));
            assert!(image.symbols.iter().any(|symbol| symbol.name == "bar"));
            assert!(image.symbols.iter().any(|symbol| symbol.name == "ext"));
            assert!(image.relocations.iter().any(|reloc| reloc.symbol == "bar"));
            assert!(image.relocations.iter().any(|reloc| reloc.symbol == "ext"));
        }
    }
}

fn assert_shared(image: &ElfImage) {
    assert_eq!(image.kind, ElfKind::Shared);
    assert_eq!(image.entry, TEXT_VA);
    assert_eq!(image.image_base, 0);
    assert_eq!(image.os_abi, 0);
    assert_eq!(image.needed, vec!["libc.so.6".to_owned()]);
    assert_eq!(
        image.soname.as_ref().and_then(ElfBytes::as_str),
        Some("libe1.so")
    );
    assert!(!image.pie);
    assert!(!image.bind_now);
    assert!(image.interp.is_none());
    assert_eq!(image.segments.len(), 4);
    assert_eq!(image.segments[0].kind, SegmentKind::Load);
    assert_eq!(image.segments[0].flags, 5);
    assert_eq!(image.segments[0].vaddr, 0);
    assert_eq!(image.segments[1].kind, SegmentKind::Load);
    assert_eq!(image.segments[1].flags, 6);
    assert_eq!(image.segments[1].vaddr, 0x2000);
    assert_eq!(image.segments[2].kind, SegmentKind::Dynamic);
    assert_eq!(image.segments[2].vaddr, DYN_VA);
    assert_eq!(image.segments[3].kind, SegmentKind::GnuStack);

    let text = image.section(".text").unwrap();
    assert_eq!(text.bytes, TEXT);
    assert_eq!(text.addr, TEXT_VA);
    assert_eq!(text.flags & 4, 4);
    assert_eq!(image.section(".dynsym").unwrap().addr, DYNSYM_VA);
    assert_eq!(image.section(".dynstr").unwrap().addr, DYNSTR_VA);
    assert_eq!(
        image.dynamic_value(DynamicTag::StrSize),
        Some(image.section(".dynstr").unwrap().size)
    );
    assert_eq!(image.dynamic_value(DynamicTag::Hash), Some(HASH_VA));
    assert_eq!(image.dynamic_value(DynamicTag::SymTab), Some(DYNSYM_VA));
    assert_eq!(image.dynamic_value(DynamicTag::JmpRel), Some(JMPREL_VA));
    assert_eq!(image.dynamic_value(DynamicTag::Rela), Some(RELA_VA));
    assert_eq!(image.dynamic_value(DynamicTag::PltGot), Some(GOT_PLT_VA));
    assert_eq!(image.dynamic_value(DynamicTag::VerSym), Some(VERSYM_VA));
    assert_eq!(image.dynamic_value(DynamicTag::VerNeed), Some(VERNEED_VA));
    assert!(image
        .dynamic
        .iter()
        .any(|entry| entry.tag == DynamicTag::Null));

    assert_shared_symbols(image);
    let text_index = image
        .sections
        .iter()
        .position(|section| section.name == ".text")
        .unwrap() as u32;
    let exported = image
        .dynamic_symbols
        .iter()
        .find(|symbol| symbol.name == "exported")
        .unwrap();
    assert_eq!(exported.value, TEXT_VA);
    assert_eq!(exported.size, TEXT.len() as u64);
    assert_eq!(exported.section, SymbolSection::Index(text_index));
    assert_eq!(exported.bind, SymbolBind::Global);
    assert_eq!(exported.kind, SymbolKind::Func);
    assert!(image.symbols.iter().any(|symbol| symbol.name == "secret"));

    let relative = image
        .relocations
        .iter()
        .find(|reloc| reloc.kind == RelocKind::Relative)
        .unwrap();
    assert_eq!(relative.offset, DATA_VA);
    assert_eq!(relative.addend, TEXT_VA as i64);
    assert_eq!(relative.symbol_index, 0);
    let glob = image
        .relocations
        .iter()
        .find(|reloc| reloc.kind == RelocKind::GlobDat)
        .unwrap();
    assert_eq!(glob.offset, GOT_VA);
    assert_eq!(glob.symbol, "extra");
    assert_eq!(glob.addend, 0);
    let jump = image
        .relocations
        .iter()
        .find(|reloc| reloc.kind == RelocKind::JumpSlot)
        .unwrap();
    assert_eq!(jump.offset, PUTS_GOT);
    assert_eq!(jump.symbol, "puts");
    assert_eq!(jump.section, ".rela.plt");

    assert_eq!(image.got.addr, GOT_VA);
    assert_eq!(image.got.slots.len(), 1);
    assert_eq!(
        image.got.slots[0]
            .symbol
            .as_ref()
            .and_then(ElfBytes::as_str),
        Some("extra")
    );
    assert_eq!(image.got.plt_addr, GOT_PLT_VA);
    assert_eq!(image.got.plt_slots.len(), 4);
    assert_eq!(image.got.plt_slots[0].value, DYN_VA);
    assert_eq!(image.got.plt_slots[3].addr, PUTS_GOT);
    assert_eq!(
        image.got.plt_slots[3]
            .symbol
            .as_ref()
            .and_then(ElfBytes::as_str),
        Some("puts")
    );
    assert_eq!(image.got.plt_slots[3].reloc, Some(RelocKind::JumpSlot));

    let resolver = image.plt.iter().find(|entry| entry.resolver).unwrap();
    assert_eq!(resolver.addr, PLT_VA);
    assert_eq!(resolver.section, ".plt");
    let lazy = image
        .plt
        .iter()
        .find(|entry| entry.addr == PLT_LAZY)
        .unwrap();
    assert_eq!(
        lazy.symbol.as_ref().and_then(ElfBytes::as_str),
        Some("puts")
    );
    assert!(!lazy.resolver);
    let stub = image
        .plt
        .iter()
        .find(|entry| entry.section == ".plt.sec")
        .unwrap();
    assert_eq!(stub.addr, PLT_SEC);
    assert_eq!(
        stub.symbol.as_ref().and_then(ElfBytes::as_str),
        Some("puts")
    );
    assert_eq!(stub.got, Some(PUTS_GOT));
    assert_eq!(stub.bytes[0], 0xf3);
}

fn assert_shared_symbols(image: &ElfImage) {
    assert_eq!(image.dynamic_symbols.len(), 4);
    assert_eq!(image.exports.len(), 1);
    assert_eq!(image.exports[0].name, "exported");
    assert_eq!(image.exports[0].value, TEXT_VA);
    assert_eq!(image.exports[0].size, TEXT.len() as u64);
    let puts = import(image, "puts");
    assert_eq!(puts.bind, SymbolBind::Global);
    assert_eq!(puts.kind, SymbolKind::Func);
    assert_eq!(
        puts.version.as_ref().and_then(ElfBytes::as_str),
        Some("GLIBC_2.2.5")
    );
    assert_eq!(
        puts.library.as_ref().and_then(ElfBytes::as_str),
        Some("libc.so.6")
    );
    assert_eq!(puts.got, Some(PUTS_GOT));
    assert_eq!(puts.plt, Some(PLT_SEC));
    let extra = import(image, "extra");
    assert_eq!(extra.bind, SymbolBind::Weak);
    assert_eq!(extra.got, Some(GOT_VA));
    assert!(extra.plt.is_none());
    assert!(extra.version.is_none());
}

fn assert_object(image: &ElfImage) {
    assert_eq!(image.kind, ElfKind::Relocatable);
    assert_eq!(image.entry, 0);
    assert!(image.segments.is_empty());
    assert!(image.dynamic.is_empty());
    assert_eq!(image.section(".text").unwrap().bytes.len(), 13);
    let foo = image
        .symbols
        .iter()
        .find(|symbol| symbol.name == "foo")
        .unwrap();
    assert_eq!(foo.bind, SymbolBind::Global);
    assert_eq!(foo.kind, SymbolKind::Func);
    assert_eq!(foo.size, 13);
    assert!(foo.section.defined());
    let bar = image
        .symbols
        .iter()
        .find(|symbol| symbol.name == "bar")
        .unwrap();
    assert_eq!(bar.kind, SymbolKind::Object);
    assert_eq!(bar.size, 8);
    let ext = image
        .symbols
        .iter()
        .find(|symbol| symbol.name == "ext")
        .unwrap();
    assert_eq!(ext.section, SymbolSection::Undefined);
    assert!(image.exports.iter().any(|export| export.name == "foo"));
    assert!(image.exports.iter().any(|export| export.name == "bar"));
    assert!(image.imports.iter().any(|import| import.name == "ext"));
    let pc = image
        .relocations
        .iter()
        .find(|reloc| reloc.kind == RelocKind::Pc32)
        .unwrap();
    assert_eq!(pc.offset, 3);
    assert_eq!(pc.symbol, "bar");
    assert_eq!(pc.addend, -4);
    assert_eq!(pc.target, ".text");
    assert_eq!(pc.table, SymbolTableId::Symtab);
    let plt = image
        .relocations
        .iter()
        .find(|reloc| reloc.kind == RelocKind::Plt32)
        .unwrap();
    assert_eq!(plt.offset, 8);
    assert_eq!(plt.symbol, "ext");
    assert_eq!(plt.addend, -4);
}

fn assert_gcc_shared(image: &ElfImage) {
    assert_eq!(image.kind, ElfKind::Shared);
    assert!(image.exports.iter().any(|export| export.name == "exported"));
    let puts = import(image, "puts");
    assert!(puts
        .version
        .as_ref()
        .is_some_and(|version| version.contains("GLIBC")));
    assert_eq!(
        puts.library.as_ref().and_then(ElfBytes::as_str),
        Some("libc.so.6")
    );
    assert!(puts.got.is_some());
    assert!(puts.plt.is_some());
    assert!(image.needed.iter().any(|name| name == "libc.so.6"));
    assert!(image
        .relocations
        .iter()
        .any(|reloc| { reloc.kind == RelocKind::JumpSlot && reloc.symbol == "puts" }));
    assert!(image.section(".text").is_some());
    assert!(image.section(".dynsym").is_some());
    assert!(image.section(".dynamic").is_some());
    assert!(image.got.plt_addr != 0 || !image.got.plt_slots.is_empty());
    assert!(!image.plt.is_empty());
}

fn import<'a>(image: &'a ElfImage, name: &str) -> &'a Import {
    image
        .imports
        .iter()
        .find(|import| import.name == name)
        .unwrap_or_else(|| panic!("missing import {name}"))
}

fn assert_readelf_or_authored(bytes: &[u8], image: &ElfImage) {
    let path = std::env::temp_dir().join(format!("vmkek-e1-readelf-{}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let output = Command::new("readelf")
        .args(["-h", "-S", "-s", "-r", "-d", "-W", "-V"])
        .arg(&path)
        .output();
    let _ = std::fs::remove_file(&path);
    match output {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            assert_ne!(image.kind, ElfKind::Relocatable);
            assert!(image.entry == TEXT_VA || image.entry != 0 || image.kind == ElfKind::Shared);
            assert!(!image.segments.is_empty() || image.kind == ElfKind::Relocatable);
        }
        Err(err) => panic!("readelf failed to start: {err}"),
        Ok(output) => {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(
                text.contains("X86-64") || text.contains("Advanced Micro Devices"),
                "{text}"
            );
            let entry = format!("{:#x}", image.entry);
            assert!(text.contains(&entry), "missing {entry} in {text}");
            if image.exports.iter().any(|export| export.name == "exported") {
                assert!(text.contains("exported"));
            }
            if image.imports.iter().any(|import| import.name == "puts") {
                assert!(text.contains("puts"));
                assert!(text.contains("R_X86_64_JUMP_SLOT") || text.contains("R_X86_64_GLOB_DAT"));
            }
            if image.needed.iter().any(|name| name == "libc.so.6") {
                assert!(text.contains("libc.so.6"));
            }
        }
    }
}

fn header_only(kind: u16, phoff: u64) -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    data[16..18].copy_from_slice(&kind.to_le_bytes());
    data[18..20].copy_from_slice(&62u16.to_le_bytes());
    data[20..24].copy_from_slice(&1u32.to_le_bytes());
    data[32..40].copy_from_slice(&phoff.to_le_bytes());
    data[52..54].copy_from_slice(&64u16.to_le_bytes());
    data[54..56].copy_from_slice(&56u16.to_le_bytes());
    data
}

fn with_extended_section_count(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(bytes[60..62].try_into().unwrap());
    bytes[60..62].copy_from_slice(&0u16.to_le_bytes());
    bytes[shoff + 32..shoff + 40].copy_from_slice(&u64::from(shnum).to_le_bytes());
    bytes
}

fn with_extended_shstrndx(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let shstr = u16::from_le_bytes(bytes[62..64].try_into().unwrap());
    bytes[62..64].copy_from_slice(&0xffffu16.to_le_bytes());
    bytes[shoff + 40..shoff + 44].copy_from_slice(&u32::from(shstr).to_le_bytes());
    bytes
}

fn with_extended_phnum(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap());
    bytes[56..58].copy_from_slice(&0xffffu16.to_le_bytes());
    bytes[shoff + 44..shoff + 48].copy_from_slice(&u32::from(phnum).to_le_bytes());
    bytes
}

fn compile_shared() -> Option<Vec<u8>> {
    let dir = temp_dir("shared");
    let source = dir.join("lib.c");
    std::fs::write(
        &source,
        r#"
        __attribute__((visibility("default")))
        int exported(int x) { return x + 42; }
        extern int puts(const char *s);
        int call_puts(void) { return puts("e1"); }
        "#,
    )
    .unwrap();
    let out = dir.join("lib.so");
    if !gcc(&[
        "-shared",
        "-fPIC",
        "-Wl,--build-id=none",
        "-o",
        out.to_str().unwrap(),
        source.to_str().unwrap(),
    ]) {
        return None;
    }
    Some(std::fs::read(out).unwrap())
}

fn compile_executable() -> Option<Vec<u8>> {
    let dir = temp_dir("exec");
    let source = dir.join("main.c");
    std::fs::write(
        &source,
        r#"
        extern int puts(const char *s);
        int main(void) { puts("e1"); return 0; }
        "#,
    )
    .unwrap();
    let out = dir.join("main");
    if !gcc(&[
        "-no-pie",
        "-Wl,--build-id=none",
        "-o",
        out.to_str().unwrap(),
        source.to_str().unwrap(),
    ]) {
        return None;
    }
    Some(std::fs::read(out).unwrap())
}

fn assemble_object() -> Option<Vec<u8>> {
    if !command_ok("as") {
        return None;
    }
    let dir = temp_dir("asm");
    let source = dir.join("obj.s");
    std::fs::write(
        &source,
        r#"
        .globl foo
        .globl bar
        .type foo, @function
        foo:
            movq bar(%rip), %rax
            call ext
            ret
        .data
        bar:
            .quad 42
        "#,
    )
    .unwrap();
    let out = dir.join("obj.o");
    let status = Command::new("as")
        .args(["--64", "-o"])
        .arg(&out)
        .arg(&source)
        .status()
        .expect("as");
    assert!(status.success(), "as failed");
    Some(std::fs::read(out).unwrap())
}

fn gcc(args: &[&str]) -> bool {
    if !command_ok("gcc") {
        return false;
    }
    let status = Command::new("gcc").args(args).status().expect("gcc");
    assert!(status.success(), "gcc failed");
    true
}

fn command_ok(name: &str) -> bool {
    match Command::new(name).arg("--version").output() {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => panic!("{name} failed to start: {err}"),
        Ok(output) => output.status.success(),
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("vmkek-e1-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn shared_object() -> Vec<u8> {
    let (dynstr, name) = cstrings(&[
        "",
        "puts",
        "extra",
        "exported",
        "libc.so.6",
        "libe1.so",
        "GLIBC_2.2.5",
    ]);
    let hash = hash_table(&["", "puts", "extra", "exported"]);
    let dynsym = dynsym_bytes(&name);
    let versym = [0u16, 2, 1, 1]
        .into_iter()
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<_>>();
    let verneed = verneed_bytes(name[4], name[6], elf_hash(b"GLIBC_2.2.5"));
    let rela_dyn = [rela(DATA_VA, 0, 8, TEXT_VA as i64), rela(GOT_VA, 2, 6, 0)].concat();
    let jmprel = rela(PUTS_GOT, 1, 7, 0);
    let (plt, plt_sec) = plt_bytes();
    let dynamic = dynamic_bytes(name[4], name[5], dynstr.len() as u64);
    let (strtab, local) = cstrings(&["", "secret", "puts", "extra", "exported"]);
    let symtab = symtab_bytes(&local);
    let gotplt = got_plt_bytes();

    let mut file = vec![0u8; 0x2000];
    poke(&mut file, 0, &elf_ident(3, TEXT_VA));
    file[56..58].copy_from_slice(&4u16.to_le_bytes());
    poke(&mut file, 0x40, &program_headers(dynamic.len() as u64));
    poke(&mut file, HASH_VA as usize, &hash);
    poke(&mut file, DYNSYM_VA as usize, &dynsym);
    poke(&mut file, DYNSTR_VA as usize, &dynstr);
    poke(&mut file, VERSYM_VA as usize, &versym);
    poke(&mut file, VERNEED_VA as usize, &verneed);
    poke(&mut file, RELA_VA as usize, &rela_dyn);
    poke(&mut file, JMPREL_VA as usize, &jmprel);
    poke(&mut file, PLT_VA as usize, &plt);
    poke(&mut file, PLT_SEC as usize, &plt_sec);
    poke(&mut file, TEXT_VA as usize, &TEXT);
    poke(&mut file, 0x1000, &dynamic);
    poke(&mut file, 0x1210, &[0; 8]);
    poke(&mut file, 0x1220, &gotplt);

    let sym_off = 0x2000usize;
    poke(&mut file, sym_off, &symtab);
    let str_off = sym_off + symtab.len();
    poke(&mut file, str_off, &strtab);
    let names = [
        "",
        ".hash",
        ".dynsym",
        ".dynstr",
        ".gnu.version",
        ".gnu.version_r",
        ".rela.dyn",
        ".rela.plt",
        ".plt",
        ".plt.sec",
        ".text",
        ".dynamic",
        ".data",
        ".got",
        ".got.plt",
        ".symtab",
        ".strtab",
        ".shstrtab",
    ];
    let (shstr, sh_name) = cstrings(&names);
    let shstr_off = str_off + strtab.len();
    poke(&mut file, shstr_off, &shstr);
    let shoff = align_up(shstr_off + shstr.len(), 8);
    let headers = section_headers(
        &sh_name,
        &TailLayout {
            dynstr: dynstr.len() as u64,
            verneed: verneed.len() as u64,
            dynamic: dynamic.len() as u64,
            sym_off: sym_off as u64,
            sym_len: symtab.len() as u64,
            str_off: str_off as u64,
            str_len: strtab.len() as u64,
            shstr_off: shstr_off as u64,
            shstr_len: shstr.len() as u64,
        },
    );
    poke(&mut file, shoff, &headers);
    poke(&mut file, 40, &(shoff as u64).to_le_bytes());
    file[58..60].copy_from_slice(&64u16.to_le_bytes());
    file[60..62].copy_from_slice(&18u16.to_le_bytes());
    file[62..64].copy_from_slice(&17u16.to_le_bytes());
    file
}

fn sectionless_shared() -> Vec<u8> {
    let mut file = shared_object();
    file[40..48].fill(0);
    file[58..64].fill(0);
    file
}

fn object_file() -> Vec<u8> {
    let text = [
        0x48, 0x8b, 0x05, 0xfc, 0xff, 0xff, 0xff, 0xe8, 0xfc, 0xff, 0xff, 0xff, 0xc3,
    ];
    let data = 42u64.to_le_bytes();
    let (strtab, name) = cstrings(&["", "foo", "bar", "ext"]);
    let (shstr, sh_name) = cstrings(&[
        "",
        ".text",
        ".rela.text",
        ".data",
        ".symtab",
        ".strtab",
        ".shstrtab",
    ]);
    let symtab = [
        symbol(0, 0, 0, 0, 0),
        symbol(name[1], 0x12, 1, 0, 13),
        symbol(name[2], 0x11, 3, 0, 8),
        symbol(name[3], 0x10, 0, 0, 0),
    ]
    .concat();
    let rela = [rela(3, 2, 2, -4), rela(8, 3, 4, -4)].concat();
    let mut file = elf_ident(1, 0);
    file[54..56].fill(0);
    let text_off = append(&mut file, &text);
    let data_off = append(&mut file, &data);
    let sym_off = append(&mut file, &symtab);
    let str_off = append(&mut file, &strtab);
    let rela_off = append(&mut file, &rela);
    let shstr_off = append(&mut file, &shstr);
    let shoff = align_len(&mut file, 8);
    let headers = [
        shdr_bytes!(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr_bytes!(sh_name[1], 1, 6, 0, text_off, text.len() as u64, 0, 0, 1, 0),
        shdr_bytes!(
            sh_name[2],
            4,
            0x40,
            0,
            rela_off,
            rela.len() as u64,
            4,
            1,
            8,
            24,
        ),
        shdr_bytes!(sh_name[3], 1, 3, 0, data_off, 8, 0, 0, 1, 0),
        shdr_bytes!(
            sh_name[4],
            2,
            0,
            0,
            sym_off,
            symtab.len() as u64,
            5,
            1,
            8,
            24,
        ),
        shdr_bytes!(
            sh_name[5],
            3,
            0,
            0,
            str_off,
            strtab.len() as u64,
            0,
            0,
            1,
            0,
        ),
        shdr_bytes!(
            sh_name[6],
            3,
            0,
            0,
            shstr_off,
            shstr.len() as u64,
            0,
            0,
            1,
            0,
        ),
    ]
    .concat();
    append(&mut file, &headers);
    poke(&mut file, 40, &(shoff as u64).to_le_bytes());
    file[58..60].copy_from_slice(&64u16.to_le_bytes());
    file[60..62].copy_from_slice(&7u16.to_le_bytes());
    file[62..64].copy_from_slice(&6u16.to_le_bytes());
    file
}

fn rel_object() -> Vec<u8> {
    let text = [0x78, 0x56, 0x34, 0x12, 0xfc, 0xff, 0xff, 0xff];
    let relocs = [rel_entry(0, 10), rel_entry(4, 2)].concat();
    let (shstr, name) = cstrings(&["", ".text", ".rel.text", ".shstrtab"]);
    let mut file = elf_ident(1, 0);
    file[54..56].fill(0);
    let text_off = append(&mut file, &text);
    let rel_off = append(&mut file, &relocs);
    let shstr_off = append(&mut file, &shstr);
    let shoff = align_len(&mut file, 8);
    let headers = [
        shdr_bytes!(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr_bytes!(name[1], 1, 6, 0, text_off, text.len() as u64, 0, 0, 1, 0),
        shdr_bytes!(name[2], 9, 0, 0, rel_off, relocs.len() as u64, 0, 1, 8, 16),
        shdr_bytes!(name[3], 3, 0, 0, shstr_off, shstr.len() as u64, 0, 0, 1, 0),
    ]
    .concat();
    append(&mut file, &headers);
    poke(&mut file, 40, &(shoff as u64).to_le_bytes());
    file[58..60].copy_from_slice(&64u16.to_le_bytes());
    file[60..62].copy_from_slice(&4u16.to_le_bytes());
    file[62..64].copy_from_slice(&3u16.to_le_bytes());
    file
}

fn relr_file() -> Vec<u8> {
    let mut data = [0u8; 16];
    data[0..8].copy_from_slice(&0x1111u64.to_le_bytes());
    data[8..16].copy_from_slice(&0x2222u64.to_le_bytes());
    let relr = [0x100u64.to_le_bytes(), 3u64.to_le_bytes()].concat();
    let (shstr, name) = cstrings(&["", ".data", ".relr.dyn", ".shstrtab"]);
    let mut file = vec![0u8; 0x180];
    poke(&mut file, 0, &elf_ident(3, 0));
    poke(&mut file, 32, &64u64.to_le_bytes());
    poke(&mut file, 54, &56u16.to_le_bytes());
    poke(&mut file, 56, &1u16.to_le_bytes());
    poke(&mut file, 64, &phdr(1, 6, 0, 0, 0x120, 0x120, 0x1000));
    poke(&mut file, 0x100, &data);
    poke(&mut file, 0x120, &relr);
    poke(&mut file, 0x140, &shstr);
    let shoff = 0x180usize;
    file.resize(shoff + 4 * 64, 0);
    let headers = [
        shdr_bytes!(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr_bytes!(name[1], 1, 3, 0x100, 0x100, 16, 0, 0, 8, 0),
        shdr_bytes!(name[2], 19, 2, 0, 0x120, relr.len() as u64, 0, 0, 8, 8),
        shdr_bytes!(name[3], 3, 0, 0, 0x140, shstr.len() as u64, 0, 0, 1, 0),
    ]
    .concat();
    poke(&mut file, shoff, &headers);
    poke(&mut file, 40, &(shoff as u64).to_le_bytes());
    poke(&mut file, 58, &64u16.to_le_bytes());
    poke(&mut file, 60, &4u16.to_le_bytes());
    poke(&mut file, 62, &3u16.to_le_bytes());
    // The load must cover the data words. 0x120 ends at the relr bytes.
    let len = file.len() as u64;
    poke(&mut file, 64, &phdr(1, 6, 0, 0, len, len, 8));
    file
}

fn gnu_hash_image() -> Vec<u8> {
    let hash = gnu_hash_table();
    let dynsym = [symbol(0, 0, 0, 0, 0), symbol(1, 0x12, 1, 0, 1)].concat();
    let dynstr = cstrings(&["", "answer"]).0;
    let mut dynamic = Vec::new();
    // Filled after addresses are known.
    let mut file = vec![0u8; 0x100];
    poke(&mut file, 0, &elf_ident(3, 0));
    let hash_off = 0x100usize;
    poke(&mut file, hash_off, &hash);
    let sym_off = hash_off + hash.len();
    poke(&mut file, sym_off, &dynsym);
    let str_off = align_up(sym_off + dynsym.len(), 8);
    poke(&mut file, str_off, &dynstr);
    let dyn_off = align_up(str_off + dynstr.len(), 8);
    dynamic.extend(dyn_entry(0x6fff_fef5, hash_off as u64));
    dynamic.extend(dyn_entry(6, sym_off as u64));
    dynamic.extend(dyn_entry(5, str_off as u64));
    dynamic.extend(dyn_entry(10, dynstr.len() as u64));
    dynamic.extend(dyn_entry(11, 24));
    dynamic.extend(dyn_entry(0, 0));
    poke(&mut file, dyn_off, &dynamic);
    let end = dyn_off + dynamic.len();
    file.resize(end, 0);
    poke(&mut file, 32, &64u64.to_le_bytes());
    poke(&mut file, 54, &56u16.to_le_bytes());
    poke(&mut file, 56, &2u16.to_le_bytes());
    let len = file.len() as u64;
    poke(&mut file, 64, &phdr(1, 7, 0, 0, len, len, 8));
    poke(
        &mut file,
        64 + 56,
        &phdr(
            2,
            6,
            dyn_off as u64,
            dyn_off as u64,
            dynamic.len() as u64,
            dynamic.len() as u64,
            8,
        ),
    );
    file
}

fn carrier() -> Vec<u8> {
    let code = [0xc3];
    let mut file = vec![0u8; 0x100 + code.len()];
    file[0x100..].copy_from_slice(&code);
    file[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&2u16.to_le_bytes());
    file[18..20].copy_from_slice(&62u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
    file[32..40].copy_from_slice(&64u64.to_le_bytes());
    file[52..54].copy_from_slice(&64u16.to_le_bytes());
    file[54..56].copy_from_slice(&56u16.to_le_bytes());
    file[56..58].copy_from_slice(&1u16.to_le_bytes());
    let ph = 64;
    file[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    file[ph + 4..ph + 8].copy_from_slice(&7u32.to_le_bytes());
    file[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    file[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes());
    let filesz = file.len() as u64;
    file[ph + 32..ph + 40].copy_from_slice(&filesz.to_le_bytes());
    file[ph + 40..ph + 48].copy_from_slice(&0x5000u64.to_le_bytes());
    file[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    file
}

fn elf_ident(kind: u16, entry: u64) -> Vec<u8> {
    let mut file = vec![0u8; 64];
    file[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&kind.to_le_bytes());
    file[18..20].copy_from_slice(&62u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[24..32].copy_from_slice(&entry.to_le_bytes());
    file[32..40].copy_from_slice(&64u64.to_le_bytes());
    file[52..54].copy_from_slice(&64u16.to_le_bytes());
    file[54..56].copy_from_slice(&56u16.to_le_bytes());
    file
}

fn program_headers(dynamic_size: u64) -> Vec<u8> {
    [
        phdr(1, 5, 0, 0, 0x1000, 0x1000, 0x1000),
        phdr(1, 6, 0x1000, 0x2000, 0x1000, 0x1000, 0x1000),
        phdr(2, 6, 0x1000, DYN_VA, dynamic_size, dynamic_size, 8),
        phdr(0x6474_e551, 6, 0, 0, 0, 0, 0x10),
    ]
    .concat()
}

struct TailLayout {
    dynstr: u64,
    verneed: u64,
    dynamic: u64,
    sym_off: u64,
    sym_len: u64,
    str_off: u64,
    str_len: u64,
    shstr_off: u64,
    shstr_len: u64,
}

struct ShdrSpec {
    name: u32,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
}

fn section_headers(name: &[u32], tail: &TailLayout) -> Vec<u8> {
    [
        shdr_bytes!(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr_bytes!(name[1], 5, 2, HASH_VA, HASH_VA, 40, 2, 0, 8, 0),
        shdr_bytes!(name[2], 11, 2, DYNSYM_VA, DYNSYM_VA, 96, 3, 1, 8, 24),
        shdr_bytes!(name[3], 3, 2, DYNSTR_VA, DYNSTR_VA, tail.dynstr, 0, 0, 1, 0),
        shdr_bytes!(name[4], 0x6fff_ffff, 2, VERSYM_VA, VERSYM_VA, 8, 2, 0, 2, 2),
        shdr_bytes!(
            name[5],
            0x6fff_fffe,
            2,
            VERNEED_VA,
            VERNEED_VA,
            tail.verneed,
            3,
            1,
            8,
            0,
        ),
        shdr_bytes!(name[6], 4, 2, RELA_VA, RELA_VA, 48, 2, 0, 8, 24),
        shdr_bytes!(name[7], 4, 0x42, JMPREL_VA, JMPREL_VA, 24, 2, 14, 8, 24),
        shdr_bytes!(name[8], 1, 6, PLT_VA, PLT_VA, 32, 0, 0, 16, 16),
        shdr_bytes!(name[9], 1, 6, PLT_SEC, PLT_SEC, 16, 0, 0, 16, 16),
        shdr_bytes!(
            name[10],
            1,
            6,
            TEXT_VA,
            TEXT_VA,
            TEXT.len() as u64,
            0,
            0,
            16,
            0,
        ),
        shdr_bytes!(name[11], 6, 3, DYN_VA, 0x1000, tail.dynamic, 3, 0, 8, 16),
        shdr_bytes!(name[12], 1, 3, DATA_VA, 0x1200, 8, 0, 0, 8, 0),
        shdr_bytes!(name[13], 1, 3, GOT_VA, 0x1210, 8, 0, 0, 8, 0),
        shdr_bytes!(name[14], 1, 3, GOT_PLT_VA, 0x1220, 32, 0, 0, 8, 8),
        shdr_bytes!(name[15], 2, 0, 0, tail.sym_off, tail.sym_len, 16, 2, 8, 24),
        shdr_bytes!(name[16], 3, 0, 0, tail.str_off, tail.str_len, 0, 0, 1, 0),
        shdr_bytes!(
            name[17],
            3,
            0,
            0,
            tail.shstr_off,
            tail.shstr_len,
            0,
            0,
            1,
            0,
        ),
    ]
    .concat()
}

fn dynsym_bytes(name: &[u32]) -> Vec<u8> {
    [
        symbol(0, 0, 0, 0, 0),
        symbol(name[1], 0x12, 0, 0, 0),
        symbol(name[2], 0x20, 0, 0, 0),
        symbol(name[3], 0x12, 10, TEXT_VA, TEXT.len() as u64),
    ]
    .concat()
}

fn symtab_bytes(name: &[u32]) -> Vec<u8> {
    [
        symbol(0, 0, 0, 0, 0),
        symbol(name[1], 0x02, 10, TEXT_VA, 0),
        symbol(name[2], 0x12, 0, 0, 0),
        symbol(name[3], 0x20, 0, 0, 0),
        symbol(name[4], 0x12, 10, TEXT_VA, TEXT.len() as u64),
    ]
    .concat()
}

fn dynamic_bytes(needed: u32, soname: u32, strsz: u64) -> Vec<u8> {
    [
        dyn_entry(1, u64::from(needed)),
        dyn_entry(14, u64::from(soname)),
        dyn_entry(4, HASH_VA),
        dyn_entry(5, DYNSTR_VA),
        dyn_entry(6, DYNSYM_VA),
        dyn_entry(10, strsz),
        dyn_entry(11, 24),
        dyn_entry(3, GOT_PLT_VA),
        dyn_entry(2, 24),
        dyn_entry(20, 7),
        dyn_entry(23, JMPREL_VA),
        dyn_entry(7, RELA_VA),
        dyn_entry(8, 48),
        dyn_entry(9, 24),
        dyn_entry(0x6fff_fff0, VERSYM_VA),
        dyn_entry(0x6fff_fffe, VERNEED_VA),
        dyn_entry(0x6fff_ffff, 1),
        dyn_entry(0, 0),
    ]
    .concat()
}

fn hash_table(names: &[&str]) -> Vec<u8> {
    let buckets = names.len();
    let mut bucket = vec![0u32; buckets];
    let mut chain = vec![0u32; names.len()];
    for (index, name) in names.iter().enumerate().skip(1) {
        let slot = elf_hash(name.as_bytes()) as usize % buckets;
        chain[index] = bucket[slot];
        bucket[slot] = index as u32;
    }
    let mut out = Vec::new();
    out.extend((buckets as u32).to_le_bytes());
    out.extend((names.len() as u32).to_le_bytes());
    for value in bucket {
        out.extend(value.to_le_bytes());
    }
    for value in chain {
        out.extend(value.to_le_bytes());
    }
    assert_eq!(out.len(), 40);
    out
}

fn gnu_hash_table() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(1u32.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    out.extend(6u32.to_le_bytes());
    out.extend(0u64.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    out
}

fn elf_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for &byte in name {
        hash = (hash << 4).wrapping_add(u32::from(byte));
        let high = hash & 0xf000_0000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}

fn verneed_bytes(file: u32, name: u32, hash: u32) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[0..2].copy_from_slice(&1u16.to_le_bytes());
    out[2..4].copy_from_slice(&1u16.to_le_bytes());
    out[4..8].copy_from_slice(&file.to_le_bytes());
    out[8..12].copy_from_slice(&16u32.to_le_bytes());
    out[16..20].copy_from_slice(&hash.to_le_bytes());
    out[22..24].copy_from_slice(&2u16.to_le_bytes());
    out[24..28].copy_from_slice(&name.to_le_bytes());
    out
}

fn plt_bytes() -> (Vec<u8>, Vec<u8>) {
    let mut plt = vec![0u8; 32];
    plt[0] = 0xff;
    plt[1] = 0x35;
    plt[2..6].copy_from_slice(&disp32(0x366, GOT_PLT_VA + 8));
    plt[6] = 0xff;
    plt[7] = 0x25;
    plt[8..12].copy_from_slice(&disp32(0x36c, GOT_PLT_VA + 16));
    plt[12..16].copy_from_slice(&[0x0f, 0x1f, 0x40, 0x00]);
    plt[16..20].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]);
    plt[20] = 0x68;
    plt[25] = 0xe9;
    plt[26..30].copy_from_slice(&disp32(0x37e, PLT_VA));
    plt[30] = 0x66;
    plt[31] = 0x90;
    let mut sec = vec![0u8; 16];
    sec[0..4].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]);
    sec[4] = 0xff;
    sec[5] = 0x25;
    sec[6..10].copy_from_slice(&disp32(0x38a, PUTS_GOT));
    sec[10..16].copy_from_slice(&[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00]);
    (plt, sec)
}

fn got_plt_bytes() -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[0..8].copy_from_slice(&DYN_VA.to_le_bytes());
    out[24..32].copy_from_slice(&PLT_LAZY.to_le_bytes());
    out
}

fn disp32(next: u64, target: u64) -> [u8; 4] {
    let value = i32::try_from(target as i64 - next as i64).unwrap();
    value.to_le_bytes()
}

fn symbol(name: u32, info: u8, shndx: u16, value: u64, size: u64) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[0..4].copy_from_slice(&name.to_le_bytes());
    out[4] = info;
    out[6..8].copy_from_slice(&shndx.to_le_bytes());
    out[8..16].copy_from_slice(&value.to_le_bytes());
    out[16..24].copy_from_slice(&size.to_le_bytes());
    out
}

fn rela(offset: u64, sym: u32, kind: u32, addend: i64) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[0..8].copy_from_slice(&offset.to_le_bytes());
    let info = (u64::from(sym) << 32) | u64::from(kind);
    out[8..16].copy_from_slice(&info.to_le_bytes());
    out[16..24].copy_from_slice(&addend.to_le_bytes());
    out
}

fn rel_entry(offset: u64, kind: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&offset.to_le_bytes());
    out[8..16].copy_from_slice(&u64::from(kind).to_le_bytes());
    out
}

fn dyn_entry(tag: u64, value: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&tag.to_le_bytes());
    out[8..16].copy_from_slice(&value.to_le_bytes());
    out
}

fn phdr(
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
) -> [u8; 56] {
    let mut out = [0u8; 56];
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    out[4..8].copy_from_slice(&flags.to_le_bytes());
    out[8..16].copy_from_slice(&offset.to_le_bytes());
    out[16..24].copy_from_slice(&vaddr.to_le_bytes());
    out[24..32].copy_from_slice(&vaddr.to_le_bytes());
    out[32..40].copy_from_slice(&filesz.to_le_bytes());
    out[40..48].copy_from_slice(&memsz.to_le_bytes());
    out[48..56].copy_from_slice(&align.to_le_bytes());
    out
}

fn shdr_spec(spec: ShdrSpec) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..4].copy_from_slice(&spec.name.to_le_bytes());
    out[4..8].copy_from_slice(&spec.kind.to_le_bytes());
    out[8..16].copy_from_slice(&spec.flags.to_le_bytes());
    out[16..24].copy_from_slice(&spec.addr.to_le_bytes());
    out[24..32].copy_from_slice(&spec.offset.to_le_bytes());
    out[32..40].copy_from_slice(&spec.size.to_le_bytes());
    out[40..44].copy_from_slice(&spec.link.to_le_bytes());
    out[44..48].copy_from_slice(&spec.info.to_le_bytes());
    out[48..56].copy_from_slice(&spec.align.to_le_bytes());
    out[56..64].copy_from_slice(&spec.entsize.to_le_bytes());
    out
}

fn cstrings(items: &[&str]) -> (Vec<u8>, Vec<u32>) {
    let mut bytes = Vec::new();
    let mut offs = Vec::new();
    for item in items {
        offs.push(u32::try_from(bytes.len()).unwrap());
        bytes.extend(item.as_bytes());
        bytes.push(0);
    }
    (bytes, offs)
}

fn poke(buf: &mut Vec<u8>, off: usize, bytes: &[u8]) {
    let end = off + bytes.len();
    if buf.len() < end {
        buf.resize(end, 0);
    }
    buf[off..end].copy_from_slice(bytes);
}

fn append(buf: &mut Vec<u8>, bytes: &[u8]) -> u64 {
    let off = buf.len();
    buf.extend_from_slice(bytes);
    off as u64
}

fn align_len(buf: &mut Vec<u8>, align: usize) -> usize {
    let off = align_up(buf.len(), align);
    buf.resize(off, 0);
    off
}

fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn symtab_past_filesz() -> Vec<u8> {
    let mut file = vec![0u8; 0x1c0];
    poke(&mut file, 0, &elf_ident(3, 0));
    poke(&mut file, 56, &2u16.to_le_bytes());
    poke(&mut file, 64, &phdr(1, 5, 0, 0, 0x180, 0x180, 0x1000));
    let dynamic = [
        dyn_entry(4, 0x120),
        dyn_entry(6, 0x160),
        dyn_entry(5, 0x140),
        dyn_entry(10, 1),
        dyn_entry(11, 24),
        dyn_entry(0, 0),
    ]
    .concat();
    let dyn_off = 0xB0u64;
    poke(&mut file, dyn_off as usize, &dynamic);
    poke(
        &mut file,
        64 + 56,
        &phdr(
            2,
            6,
            dyn_off,
            dyn_off,
            dynamic.len() as u64,
            dynamic.len() as u64,
            8,
        ),
    );
    let mut hash = Vec::new();
    hash.extend(1u32.to_le_bytes());
    hash.extend(4u32.to_le_bytes());
    hash.extend(0u32.to_le_bytes());
    hash.extend([0u8; 16]);
    poke(&mut file, 0x120, &hash);
    poke(&mut file, 0x140, &[0]);
    poke(&mut file, 0x180, &0x1122_3344_5566_7788u64.to_le_bytes());
    file
}

fn reloc_image(place: u64, load_vaddr: u64, filesz: u64, memsz: u64) -> Vec<u8> {
    let relocs = rel_entry(place, 1);
    let (shstr, name) = cstrings(&["", ".rel.dyn", ".shstrtab"]);
    let mut file = elf_ident(3, 0);
    poke(&mut file, 56, &1u16.to_le_bytes());
    file.resize(64 + 56, 0);
    let rel_off = append(&mut file, &relocs);
    let shstr_off = append(&mut file, &shstr);
    let shoff = align_len(&mut file, 8);
    let headers = [
        shdr_bytes!(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr_bytes!(name[1], 9, 2, 0, rel_off, relocs.len() as u64, 0, 0, 8, 16),
        shdr_bytes!(name[2], 3, 0, 0, shstr_off, shstr.len() as u64, 0, 0, 1, 0),
    ]
    .concat();
    append(&mut file, &headers);
    poke(&mut file, 40, &(shoff as u64).to_le_bytes());
    poke(&mut file, 58, &64u16.to_le_bytes());
    poke(&mut file, 60, &3u16.to_le_bytes());
    poke(&mut file, 62, &2u16.to_le_bytes());
    poke(
        &mut file,
        64,
        &phdr(1, 6, 0, load_vaddr, filesz, memsz, 0x1000),
    );
    file
}

fn unmapped_rel() -> Vec<u8> {
    reloc_image(0xdead_beef, 0x400000, 0x20, 0x20)
}

fn split_file_bss_rel() -> Vec<u8> {
    reloc_image(0x101c, 0x1000, 0x20, 0x40)
}

fn bss_rel() -> Vec<u8> {
    reloc_image(0x1020, 0x1000, 0x20, 0x40)
}

fn section_file(
    name: &str,
    kind: u32,
    flags: u64,
    addr: u64,
    body: &[u8],
    entsize: u64,
) -> Vec<u8> {
    let (shstr, names) = cstrings(&["", name, ".shstrtab"]);
    let mut file = elf_ident(3, 0);
    file[54..56].fill(0);
    let body_off = append(&mut file, body);
    let shstr_off = append(&mut file, &shstr);
    let shoff = align_len(&mut file, 8);
    let headers = [
        shdr_bytes!(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr_bytes!(
            names[1],
            kind,
            flags,
            addr,
            body_off,
            body.len() as u64,
            0,
            0,
            8,
            entsize,
        ),
        shdr_bytes!(names[2], 3, 0, 0, shstr_off, shstr.len() as u64, 0, 0, 1, 0,),
    ]
    .concat();
    append(&mut file, &headers);
    poke(&mut file, 40, &(shoff as u64).to_le_bytes());
    poke(&mut file, 58, &64u16.to_le_bytes());
    poke(&mut file, 60, &3u16.to_le_bytes());
    poke(&mut file, 62, &2u16.to_le_bytes());
    file
}

fn got_address_overflow() -> Vec<u8> {
    section_file(".got", 1, 3, u64::MAX - 7, &[0; 16], 8)
}

fn plt_address_overflow() -> Vec<u8> {
    section_file(".plt", 1, 6, u64::MAX - 4, &[0; 32], 16)
}

fn plt_rip_relative_wrap() -> Vec<u8> {
    let mut body = [0u8; 16];
    body[0] = 0xff;
    body[1] = 0x25;
    body[2..6].copy_from_slice(&8i32.to_le_bytes());
    section_file(".plt", 1, 6, u64::MAX - 5, &body, 16)
}

fn mismatched_got_relocs(count: usize) -> Vec<u8> {
    let got_va = 0x10_0000u64;
    let got = vec![0u8; count * 8];
    let mut rela_bytes = Vec::with_capacity(count * 24);
    for index in 0..count {
        let offset = if index == 0 {
            got_va
        } else {
            0x8000_0000 + index as u64 * 8
        };
        rela_bytes.extend(rela(offset, 0, 8, 1));
    }
    let (shstr, name) = cstrings(&["", ".got", ".rela.dyn", ".shstrtab"]);
    let mut file = elf_ident(3, 0);
    poke(&mut file, 56, &1u16.to_le_bytes());
    file.resize(64 + 56, 0);
    let got_off = append(&mut file, &got);
    let rela_off = append(&mut file, &rela_bytes);
    let shstr_off = append(&mut file, &shstr);
    let shoff = align_len(&mut file, 8);
    let headers = [
        shdr_bytes!(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr_bytes!(name[1], 1, 3, got_va, got_off, got.len() as u64, 0, 0, 8, 8,),
        shdr_bytes!(
            name[2],
            4,
            2,
            0,
            rela_off,
            rela_bytes.len() as u64,
            0,
            0,
            8,
            24,
        ),
        shdr_bytes!(name[3], 3, 0, 0, shstr_off, shstr.len() as u64, 0, 0, 1, 0),
    ]
    .concat();
    append(&mut file, &headers);
    poke(&mut file, 40, &(shoff as u64).to_le_bytes());
    poke(&mut file, 58, &64u16.to_le_bytes());
    poke(&mut file, 60, &4u16.to_le_bytes());
    poke(&mut file, 62, &3u16.to_le_bytes());
    poke(
        &mut file,
        64,
        &phdr(1, 6, got_off, got_va, got.len() as u64, got.len() as u64, 8),
    );
    file
}

fn median_got_parse(count: usize) -> Duration {
    let bytes = mismatched_got_relocs(count);
    let mut samples = Vec::with_capacity(3);
    for _ in 0..3 {
        let start = Instant::now();
        let image = parse(&bytes).expect("synthetic got image");
        samples.push(start.elapsed());
        assert_eq!(image.got.slots.len(), count);
        assert_eq!(image.relocations.len(), count);
        assert_eq!(image.got.slots[0].reloc, Some(RelocKind::Relative));
        assert!(image.got.slots[1].reloc.is_none());
    }
    samples.sort();
    samples[1]
}

fn non_utf8_exports() -> Vec<u8> {
    let mut strtab = vec![0];
    strtab.extend_from_slice(&[0xff, 0xfe, 0, 0xfe, 0xff, 0]);
    let text = [0xc3];
    let symtab = [
        symbol(0, 0, 0, 0, 0),
        symbol(1, 0x12, 1, 0, 1),
        symbol(4, 0x12, 1, 1, 1),
    ]
    .concat();
    let (shstr, name) = cstrings(&["", ".text", ".symtab", ".strtab", ".shstrtab"]);
    let mut file = elf_ident(1, 0);
    file[54..56].fill(0);
    let text_off = append(&mut file, &text);
    let sym_off = append(&mut file, &symtab);
    let str_off = append(&mut file, &strtab);
    let shstr_off = append(&mut file, &shstr);
    let shoff = align_len(&mut file, 8);
    let headers = [
        shdr_bytes!(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr_bytes!(name[1], 1, 6, 0, text_off, text.len() as u64, 0, 0, 1, 0),
        shdr_bytes!(name[2], 2, 0, 0, sym_off, symtab.len() as u64, 3, 1, 8, 24,),
        shdr_bytes!(name[3], 3, 0, 0, str_off, strtab.len() as u64, 0, 0, 1, 0),
        shdr_bytes!(name[4], 3, 0, 0, shstr_off, shstr.len() as u64, 0, 0, 1, 0),
    ]
    .concat();
    append(&mut file, &headers);
    poke(&mut file, 40, &(shoff as u64).to_le_bytes());
    poke(&mut file, 58, &64u16.to_le_bytes());
    poke(&mut file, 60, &5u16.to_le_bytes());
    poke(&mut file, 62, &4u16.to_le_bytes());
    file
}

fn linked_dyn_image(
    dynsym_addr: u64,
    dynstr_addr: u64,
    strtab_tag: u64,
    symtab_tag: u64,
    dynstr: &[u8],
    extra: &[[u8; 16]],
) -> Vec<u8> {
    let dynsym = [symbol(0, 0, 0, 0, 0), symbol(1, 0x12, 0xfff1, 0, 1)].concat();
    let mut dynamic = Vec::new();
    dynamic.extend(dyn_entry(6, symtab_tag));
    dynamic.extend(dyn_entry(5, strtab_tag));
    dynamic.extend(dyn_entry(10, dynstr.len() as u64));
    dynamic.extend(dyn_entry(11, 24));
    for entry in extra {
        dynamic.extend_from_slice(entry);
    }
    dynamic.extend(dyn_entry(0, 0));
    let (shstr, name) = cstrings(&["", ".dynsym", ".dynstr", ".dynamic", ".shstrtab"]);
    let mut file = elf_ident(3, 0);
    file[54..56].fill(0);
    let sym_off = append(&mut file, &dynsym);
    let str_off = append(&mut file, dynstr);
    let dyn_off = append(&mut file, &dynamic);
    let shstr_off = append(&mut file, &shstr);
    let shoff = align_len(&mut file, 8);
    let headers = [
        shdr_bytes!(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr_bytes!(
            name[1],
            11,
            2,
            dynsym_addr,
            sym_off,
            dynsym.len() as u64,
            2,
            1,
            8,
            24,
        ),
        shdr_bytes!(
            name[2],
            3,
            2,
            dynstr_addr,
            str_off,
            dynstr.len() as u64,
            0,
            0,
            1,
            0,
        ),
        shdr_bytes!(
            name[3],
            6,
            3,
            dyn_off,
            dyn_off,
            dynamic.len() as u64,
            2,
            0,
            8,
            16,
        ),
        shdr_bytes!(name[4], 3, 0, 0, shstr_off, shstr.len() as u64, 0, 0, 1, 0),
    ]
    .concat();
    append(&mut file, &headers);
    poke(&mut file, 40, &(shoff as u64).to_le_bytes());
    poke(&mut file, 58, &64u16.to_le_bytes());
    poke(&mut file, 60, &5u16.to_le_bytes());
    poke(&mut file, 62, &4u16.to_le_bytes());
    file
}

fn strtab_at_zero_disagrees() -> Vec<u8> {
    linked_dyn_image(0x300, 0, 0x120, 0x300, b"\0SEC\0", &[])
}

fn symtab_at_zero_disagrees() -> Vec<u8> {
    linked_dyn_image(0, 0x200, 0x200, 0x400, b"\0answer\0", &[])
}

fn symtab_at_zero_agrees() -> Vec<u8> {
    linked_dyn_image(0, 0x200, 0x200, 0, b"\0answer\0", &[])
}

fn pltgot_at_zero_disagrees() -> Vec<u8> {
    let body = [0u8; 8];
    let dynamic = [dyn_entry(3, 0x500), dyn_entry(0, 0)].concat();
    let (shstr, name) = cstrings(&["", ".got.plt", ".dynamic", ".shstrtab"]);
    let mut file = elf_ident(3, 0);
    file[54..56].fill(0);
    let got_off = append(&mut file, &body);
    let dyn_off = append(&mut file, &dynamic);
    let shstr_off = append(&mut file, &shstr);
    let shoff = align_len(&mut file, 8);
    let headers = [
        shdr_bytes!(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr_bytes!(name[1], 1, 3, 0, got_off, body.len() as u64, 0, 0, 8, 8),
        shdr_bytes!(
            name[2],
            6,
            3,
            dyn_off,
            dyn_off,
            dynamic.len() as u64,
            0,
            0,
            8,
            16,
        ),
        shdr_bytes!(name[3], 3, 0, 0, shstr_off, shstr.len() as u64, 0, 0, 1, 0),
    ]
    .concat();
    append(&mut file, &headers);
    poke(&mut file, 40, &(shoff as u64).to_le_bytes());
    poke(&mut file, 58, &64u16.to_le_bytes());
    poke(&mut file, 60, &4u16.to_le_bytes());
    poke(&mut file, 62, &3u16.to_le_bytes());
    file
}

fn version_chain_past_window() -> Vec<u8> {
    let verneed_at = 0x400u64;
    let second = verneed_at + super::MAX_ESSENTIAL;
    let end = usize::try_from(second).unwrap() + 32;
    let mut file = vec![0u8; end];
    poke(&mut file, 0, &elf_ident(3, 0));
    poke(&mut file, 56, &2u16.to_le_bytes());
    let hash_at = 0x160u64;
    let sym_at = 0x180u64;
    let str_at = 0x1A0u64;
    let versym_at = 0x300u64;
    let mut dynamic = Vec::new();
    dynamic.extend(dyn_entry(4, hash_at));
    dynamic.extend(dyn_entry(6, sym_at));
    dynamic.extend(dyn_entry(5, str_at));
    dynamic.extend(dyn_entry(10, 1));
    dynamic.extend(dyn_entry(11, 24));
    dynamic.extend(dyn_entry(0x6fff_fff0, versym_at));
    dynamic.extend(dyn_entry(0x6fff_fffe, verneed_at));
    dynamic.extend(dyn_entry(0x6fff_ffff, 2));
    dynamic.extend(dyn_entry(0, 0));
    let dyn_off = 0xB0usize;
    poke(&mut file, dyn_off, &dynamic);
    poke(&mut file, 64, &phdr(1, 7, 0, 0, end as u64, end as u64, 8));
    poke(
        &mut file,
        64 + 56,
        &phdr(
            2,
            6,
            dyn_off as u64,
            dyn_off as u64,
            dynamic.len() as u64,
            dynamic.len() as u64,
            8,
        ),
    );
    let mut hash = Vec::new();
    hash.extend(1u32.to_le_bytes());
    hash.extend(1u32.to_le_bytes());
    hash.extend(0u32.to_le_bytes());
    hash.extend(0u32.to_le_bytes());
    poke(&mut file, hash_at as usize, &hash);
    poke(&mut file, str_at as usize, &[0]);
    let mut first = vec![0u8; 16];
    first[0..2].copy_from_slice(&1u16.to_le_bytes());
    first[12..16].copy_from_slice(&(super::MAX_ESSENTIAL as u32).to_le_bytes());
    poke(&mut file, verneed_at as usize, &first);
    let mut next = vec![0u8; 16];
    next[0..2].copy_from_slice(&1u16.to_le_bytes());
    poke(&mut file, second as usize, &next);
    file
}

fn relr_overflow() -> Vec<u8> {
    // Last 8-aligned address whose 8-byte place still fits in a load segment.
    let high = u64::MAX - 15;
    let mut place = [0u8; 8];
    place.copy_from_slice(&0x1111u64.to_le_bytes());
    let relr = [high.to_le_bytes(), 1u64.to_le_bytes()].concat();
    let (shstr, name) = cstrings(&["", ".data", ".relr.dyn", ".shstrtab"]);
    let mut file = elf_ident(3, 0);
    poke(&mut file, 56, &2u16.to_le_bytes());
    file.resize(64 + 112, 0);
    let data_off = append(&mut file, &place);
    let relr_off = append(&mut file, &relr);
    let shstr_off = append(&mut file, &shstr);
    let shoff = align_len(&mut file, 8);
    let headers = [
        shdr_bytes!(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr_bytes!(name[1], 1, 3, high, data_off, 8, 0, 0, 8, 0),
        shdr_bytes!(name[2], 19, 2, 0, relr_off, relr.len() as u64, 0, 0, 8, 8),
        shdr_bytes!(name[3], 3, 0, 0, shstr_off, shstr.len() as u64, 0, 0, 1, 0),
    ]
    .concat();
    append(&mut file, &headers);
    let len = file.len() as u64;
    poke(&mut file, 64, &phdr(1, 6, 0, 0, len, len, 8));
    poke(&mut file, 64 + 56, &phdr(1, 6, data_off, high, 8, 8, 8));
    poke(&mut file, 40, &(shoff as u64).to_le_bytes());
    poke(&mut file, 58, &64u16.to_le_bytes());
    poke(&mut file, 60, &4u16.to_le_bytes());
    poke(&mut file, 62, &3u16.to_le_bytes());
    file
}

fn plt_over_cap() -> Vec<u8> {
    let count = super::MAX_RELOCS + 1;
    let body = vec![0u8; count * 16];
    section_file(".plt", 1, 6, 0x400000, &body, 16)
}
