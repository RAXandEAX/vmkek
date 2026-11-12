//! ELF64 x86-64 image parser.
//!
//! Reads headers, segments, sections, symbol tables, relocations, the dynamic
//! table, GOT, and PLT. Format problems are errors. The parser does not apply
//! relocations or load the image. `protect` consumes this parse for an
//! executable; it does not grow a second lifter.

mod dynamic;
mod header;
mod plt;
mod read;
mod reloc;
pub mod sample;

pub use read::ElfBytes;

use crate::error::{msg, Result};

const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 1;
const DF_1_PIE: u64 = 0x0800_0000;

const MAX_SEGMENTS: usize = 512;
const MAX_SECTIONS: usize = 4096;
const MAX_SYMBOLS: usize = 1_048_576;
const MAX_RELOCS: usize = 1_048_576;
const MAX_DYNAMIC: usize = 65_536;
const MAX_ESSENTIAL: u64 = 64 * 1024 * 1024;
const MAX_ALLOC_COPY: u64 = 64 * 1024;
const MAX_OTHER_COPY: u64 = 256 * 1024;
const MAX_TOTAL_COPY: usize = 96 * 1024 * 1024;
const MAX_STRING: usize = 4096;

/// ELF file type that this parser accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfKind {
    Relocatable,
    Executable,
    Shared,
}

/// Program-header type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentKind {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    Shlib,
    Phdr,
    Tls,
    GnuEhFrame,
    GnuStack,
    GnuRelro,
    GnuProperty,
    GnuSFrame,
    Other(u32),
}

impl SegmentKind {
    fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Null,
            1 => Self::Load,
            2 => Self::Dynamic,
            3 => Self::Interp,
            4 => Self::Note,
            5 => Self::Shlib,
            6 => Self::Phdr,
            7 => Self::Tls,
            0x6474_e550 => Self::GnuEhFrame,
            0x6474_e551 => Self::GnuStack,
            0x6474_e552 => Self::GnuRelro,
            0x6474_e553 => Self::GnuProperty,
            0x6474_e554 => Self::GnuSFrame,
            other => Self::Other(other),
        }
    }
}

/// Section type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKind {
    Null,
    Progbits,
    Symtab,
    Strtab,
    Rela,
    Hash,
    Dynamic,
    Note,
    Nobits,
    Rel,
    Dynsym,
    InitArray,
    FiniArray,
    PreinitArray,
    Group,
    SymtabShndx,
    Relr,
    GnuHash,
    GnuVerdef,
    GnuVerneed,
    GnuVersym,
    Other(u32),
}

impl SectionKind {
    fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Null,
            1 => Self::Progbits,
            2 => Self::Symtab,
            3 => Self::Strtab,
            4 => Self::Rela,
            5 => Self::Hash,
            6 => Self::Dynamic,
            7 => Self::Note,
            8 => Self::Nobits,
            9 => Self::Rel,
            11 => Self::Dynsym,
            14 => Self::InitArray,
            15 => Self::FiniArray,
            16 => Self::PreinitArray,
            17 => Self::Group,
            18 => Self::SymtabShndx,
            19 => Self::Relr,
            0x6fff_fff6 => Self::GnuHash,
            0x6fff_fffd => Self::GnuVerdef,
            0x6fff_fffe => Self::GnuVerneed,
            0x6fff_ffff => Self::GnuVersym,
            other => Self::Other(other),
        }
    }

    fn essential(self) -> bool {
        matches!(
            self,
            Self::Symtab
                | Self::Strtab
                | Self::Rela
                | Self::Hash
                | Self::Dynamic
                | Self::Rel
                | Self::Dynsym
                | Self::SymtabShndx
                | Self::Relr
                | Self::GnuHash
                | Self::GnuVerdef
                | Self::GnuVerneed
                | Self::GnuVersym
        )
    }
}

/// Dynamic-table tag. The terminating `DT_NULL` entry is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DynamicTag {
    Null,
    Needed,
    PltRelSize,
    PltGot,
    Hash,
    StrTab,
    SymTab,
    Rela,
    RelaSize,
    RelaEnt,
    StrSize,
    SymEnt,
    Init,
    Fini,
    SoName,
    RPath,
    Symbolic,
    Rel,
    RelSize,
    RelEnt,
    PltRel,
    Debug,
    TextRel,
    JmpRel,
    BindNow,
    InitArray,
    FiniArray,
    InitArraySize,
    FiniArraySize,
    RunPath,
    Flags,
    PreinitArray,
    PreinitArraySize,
    RelrSize,
    Relr,
    RelrEnt,
    GnuHash,
    VerSym,
    RelaCount,
    RelCount,
    Flags1,
    VerDef,
    VerDefNum,
    VerNeed,
    VerNeedNum,
    Other(i64),
}

impl DynamicTag {
    fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Null,
            1 => Self::Needed,
            2 => Self::PltRelSize,
            3 => Self::PltGot,
            4 => Self::Hash,
            5 => Self::StrTab,
            6 => Self::SymTab,
            7 => Self::Rela,
            8 => Self::RelaSize,
            9 => Self::RelaEnt,
            10 => Self::StrSize,
            11 => Self::SymEnt,
            12 => Self::Init,
            13 => Self::Fini,
            14 => Self::SoName,
            15 => Self::RPath,
            16 => Self::Symbolic,
            17 => Self::Rel,
            18 => Self::RelSize,
            19 => Self::RelEnt,
            20 => Self::PltRel,
            21 => Self::Debug,
            22 => Self::TextRel,
            23 => Self::JmpRel,
            24 => Self::BindNow,
            25 => Self::InitArray,
            26 => Self::FiniArray,
            27 => Self::InitArraySize,
            28 => Self::FiniArraySize,
            29 => Self::RunPath,
            30 => Self::Flags,
            32 => Self::PreinitArray,
            33 => Self::PreinitArraySize,
            35 => Self::RelrSize,
            36 => Self::Relr,
            37 => Self::RelrEnt,
            0x6fff_fef5 => Self::GnuHash,
            0x6fff_fff0 => Self::VerSym,
            0x6fff_fff9 => Self::RelaCount,
            0x6fff_fffa => Self::RelCount,
            0x6fff_fffb => Self::Flags1,
            0x6fff_fffc => Self::VerDef,
            0x6fff_fffd => Self::VerDefNum,
            0x6fff_fffe => Self::VerNeed,
            0x6fff_ffff => Self::VerNeedNum,
            other => Self::Other(other),
        }
    }
}

/// `R_X86_64_*` relocation. Unknown numbers stay as [`RelocKind::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocKind {
    None,
    Abs64,
    Pc32,
    Got32,
    Plt32,
    Copy,
    GlobDat,
    JumpSlot,
    Relative,
    GotPcRel,
    Abs32,
    Abs32S,
    Abs16,
    Pc16,
    Abs8,
    Pc8,
    DtpMod64,
    DtpOff64,
    TpOff64,
    TlsGd,
    TlsLd,
    DtpOff32,
    GotTpOff,
    TpOff32,
    Pc64,
    GotOff64,
    GotPc32,
    Got64,
    GotPcRel64,
    GotPc64,
    GotPlt64,
    PltOff64,
    Size32,
    Size64,
    GotPc32TlsDesc,
    TlsDescCall,
    TlsDesc,
    Irelative,
    Relative64,
    GotPcRelX,
    RexGotPcRelX,
    Other(u32),
}

impl RelocKind {
    fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Abs64,
            2 => Self::Pc32,
            3 => Self::Got32,
            4 => Self::Plt32,
            5 => Self::Copy,
            6 => Self::GlobDat,
            7 => Self::JumpSlot,
            8 => Self::Relative,
            9 => Self::GotPcRel,
            10 => Self::Abs32,
            11 => Self::Abs32S,
            12 => Self::Abs16,
            13 => Self::Pc16,
            14 => Self::Abs8,
            15 => Self::Pc8,
            16 => Self::DtpMod64,
            17 => Self::DtpOff64,
            18 => Self::TpOff64,
            19 => Self::TlsGd,
            20 => Self::TlsLd,
            21 => Self::DtpOff32,
            22 => Self::GotTpOff,
            23 => Self::TpOff32,
            24 => Self::Pc64,
            25 => Self::GotOff64,
            26 => Self::GotPc32,
            27 => Self::Got64,
            28 => Self::GotPcRel64,
            29 => Self::GotPc64,
            30 => Self::GotPlt64,
            31 => Self::PltOff64,
            32 => Self::Size32,
            33 => Self::Size64,
            34 => Self::GotPc32TlsDesc,
            35 => Self::TlsDescCall,
            36 => Self::TlsDesc,
            37 => Self::Irelative,
            38 => Self::Relative64,
            41 => Self::GotPcRelX,
            42 => Self::RexGotPcRelX,
            other => Self::Other(other),
        }
    }

    fn place_width(self) -> usize {
        match self {
            Self::None | Self::Other(_) => 0,
            Self::Abs64
            | Self::Pc64
            | Self::Got64
            | Self::GotPcRel64
            | Self::GotPc64
            | Self::GotPlt64
            | Self::PltOff64
            | Self::GotOff64
            | Self::Size64
            | Self::Relative
            | Self::Relative64
            | Self::Irelative
            | Self::JumpSlot
            | Self::GlobDat
            | Self::Copy
            | Self::DtpMod64
            | Self::DtpOff64
            | Self::TpOff64 => 8,
            Self::Pc32
            | Self::Got32
            | Self::Plt32
            | Self::Abs32
            | Self::Abs32S
            | Self::GotPcRel
            | Self::GotPcRelX
            | Self::RexGotPcRelX
            | Self::GotPc32
            | Self::Size32
            | Self::TlsGd
            | Self::TlsLd
            | Self::DtpOff32
            | Self::GotTpOff
            | Self::TpOff32
            | Self::GotPc32TlsDesc
            | Self::TlsDesc => 4,
            Self::Abs16 | Self::Pc16 => 2,
            Self::Abs8 | Self::Pc8 | Self::TlsDescCall => 1,
        }
    }
}

/// Symbol binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolBind {
    Local,
    Global,
    Weak,
    GnuUnique,
    Other(u8),
}

impl SymbolBind {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Local,
            1 => Self::Global,
            2 => Self::Weak,
            10 => Self::GnuUnique,
            other => Self::Other(other),
        }
    }

    fn exported(self) -> bool {
        matches!(self, Self::Global | Self::Weak | Self::GnuUnique)
    }
}

/// Symbol type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolKind {
    NoType,
    Object,
    Func,
    Section,
    File,
    Common,
    Tls,
    Ifunc,
    Other(u8),
}

impl SymbolKind {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::NoType,
            1 => Self::Object,
            2 => Self::Func,
            3 => Self::Section,
            4 => Self::File,
            5 => Self::Common,
            6 => Self::Tls,
            10 => Self::Ifunc,
            other => Self::Other(other),
        }
    }

    fn named_object(self) -> bool {
        !matches!(self, Self::Section | Self::File)
    }
}

/// Symbol visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Default,
    Internal,
    Hidden,
    Protected,
}

impl Visibility {
    fn from_u8(value: u8) -> Self {
        match value & 3 {
            0 => Self::Default,
            1 => Self::Internal,
            2 => Self::Hidden,
            _ => Self::Protected,
        }
    }

    fn is_dynamic(self) -> bool {
        matches!(self, Self::Default | Self::Protected)
    }
}

/// Section a symbol is defined in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolSection {
    Undefined,
    Absolute,
    Common,
    Index(u32),
    Reserved(u16),
}

impl SymbolSection {
    fn defined(self) -> bool {
        matches!(self, Self::Absolute | Self::Common | Self::Index(_))
    }
}

/// Which symbol table a relocation indexes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolTableId {
    None,
    Symtab,
    Dynsym,
}

/// One program header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub kind: SegmentKind,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// One section header plus the file bytes that fit in the parse budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: ElfBytes,
    pub kind: SectionKind,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
    pub bytes: Vec<u8>,
    /// `bytes` was left empty because the section is larger than the copy budget.
    pub bytes_omitted: bool,
}

/// One symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub name: ElfBytes,
    pub value: u64,
    pub size: u64,
    pub bind: SymbolBind,
    pub kind: SymbolKind,
    pub visibility: Visibility,
    pub section: SymbolSection,
    pub version: Option<ElfBytes>,
    pub version_file: Option<ElfBytes>,
}

/// One relocation from a section or from the dynamic table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relocation {
    pub offset: u64,
    pub kind: RelocKind,
    pub symbol_index: u32,
    pub symbol: ElfBytes,
    pub addend: i64,
    /// Section that contains this relocation record, or the dynamic tag name.
    pub section: ElfBytes,
    /// Section the relocation applies to, when the reloc section says so.
    pub target: ElfBytes,
    pub table: SymbolTableId,
}

/// One dynamic-table entry, including the terminating null.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub value: u64,
}

/// Address and byte length of an init/fini array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArraySpan {
    pub addr: u64,
    pub size: u64,
}

/// One GOT slot, annotated from the relocation that fills it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GotSlot {
    pub addr: u64,
    pub value: u64,
    pub symbol: Option<ElfBytes>,
    pub reloc: Option<RelocKind>,
}

/// `.got` and `.got.plt` / `DT_PLTGOT`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Got {
    pub addr: u64,
    pub slots: Vec<GotSlot>,
    pub plt_addr: u64,
    pub plt_slots: Vec<GotSlot>,
}

/// One decoded PLT stub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PltEntry {
    pub addr: u64,
    pub size: u64,
    pub section: ElfBytes,
    pub got: Option<u64>,
    pub symbol: Option<ElfBytes>,
    pub symbol_index: Option<u32>,
    /// The resolver stub (`push GOT+8` / `jmp GOT+16`), not a per-symbol entry.
    pub resolver: bool,
    pub bytes: Vec<u8>,
}

/// Defined global dynamic symbol, or a static symbol when there is no dynsym.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub name: ElfBytes,
    pub value: u64,
    pub size: u64,
    pub kind: SymbolKind,
    pub bind: SymbolBind,
    pub version: Option<ElfBytes>,
}

/// Undefined dynamic symbol, or a copy relocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    pub name: ElfBytes,
    pub bind: SymbolBind,
    pub kind: SymbolKind,
    pub library: Option<ElfBytes>,
    pub version: Option<ElfBytes>,
    pub got: Option<u64>,
    pub plt: Option<u64>,
}

/// Parsed ELF64 x86-64 image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfImage {
    pub kind: ElfKind,
    pub os_abi: u8,
    pub abi_version: u8,
    pub entry: u64,
    pub image_base: u64,
    pub flags: u32,
    pub pie: bool,
    pub bind_now: bool,
    pub interp: Option<ElfBytes>,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub dynamic_symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub dynamic: Vec<DynamicEntry>,
    pub needed: Vec<ElfBytes>,
    pub soname: Option<ElfBytes>,
    pub rpath: Option<ElfBytes>,
    pub runpath: Option<ElfBytes>,
    pub init: Option<u64>,
    pub fini: Option<u64>,
    pub init_array: Option<ArraySpan>,
    pub fini_array: Option<ArraySpan>,
    pub preinit_array: Option<ArraySpan>,
    pub got: Got,
    pub plt: Vec<PltEntry>,
    pub exports: Vec<Export>,
    pub imports: Vec<Import>,
}

impl ElfImage {
    /// Returns the section whose name is `name`.
    #[must_use]
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|section| section.name == name)
    }

    /// Returns the value of the first dynamic entry with `tag`.
    #[must_use]
    pub fn dynamic_value(&self, tag: DynamicTag) -> Option<u64> {
        self.dynamic
            .iter()
            .find(|entry| entry.tag == tag)
            .map(|entry| entry.value)
    }
}

struct Parsed {
    header: header::Header,
    segments: Vec<Segment>,
    sections: Vec<Section>,
    interp: Option<ElfBytes>,
    dynamic: Vec<DynamicEntry>,
    linked: dynamic::Linked,
}

/// `true` when `data` begins with the ELF magic.
#[must_use]
pub fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x7f && &data[1..4] == b"ELF"
}

/// Parse an ELF64 little-endian x86-64 object, executable, or shared object.
///
/// # Errors
///
/// Returns an error when the file is not ELF64 x86-64 or a table is truncated,
/// inconsistent, or larger than the parser limits.
pub fn parse(data: &[u8]) -> Result<ElfImage> {
    let parsed = read_image(data)?;
    let relocations = reloc::collect(
        data,
        parsed.header.kind,
        &parsed.segments,
        &parsed.sections,
        &parsed.dynamic,
        &parsed.linked,
    )?;
    let got = plt::got(
        data,
        &parsed.segments,
        &parsed.sections,
        &parsed.dynamic,
        &relocations,
    )?;
    let plt_entries = plt::entries(
        data,
        &parsed.segments,
        &parsed.sections,
        &parsed.dynamic,
        &relocations,
    )?;
    let (exports, imports) = dynamic::bind(&parsed.linked, &relocations, &plt_entries);
    assemble(parsed, relocations, got, plt_entries, exports, imports)
}

fn read_image(data: &[u8]) -> Result<Parsed> {
    let header = header::header(data)?;
    let segments = header::segments(data, &header)?;
    let sections = header::sections(data, &header)?;
    let interp = header::interpreter(data, &segments)?;
    let dynamic = dynamic::entries(data, &segments, &sections)?;
    let linked = dynamic::link(data, &segments, &sections, &dynamic)?;
    Ok(Parsed {
        header,
        segments,
        sections,
        interp,
        dynamic,
        linked,
    })
}

fn assemble(
    parsed: Parsed,
    relocations: Vec<Relocation>,
    got: Got,
    plt_entries: Vec<PltEntry>,
    exports: Vec<Export>,
    imports: Vec<Import>,
) -> Result<ElfImage> {
    check_entry(parsed.header.kind, parsed.header.entry, &parsed.segments)?;
    Ok(elf_image(
        parsed,
        relocations,
        got,
        plt_entries,
        exports,
        imports,
    ))
}

fn elf_image(
    parsed: Parsed,
    relocations: Vec<Relocation>,
    got: Got,
    plt: Vec<PltEntry>,
    exports: Vec<Export>,
    imports: Vec<Import>,
) -> ElfImage {
    let facts = image_facts(&parsed);
    ElfImage {
        kind: parsed.header.kind,
        os_abi: parsed.header.os_abi,
        abi_version: parsed.header.abi_version,
        entry: parsed.header.entry,
        image_base: facts.image_base,
        flags: parsed.header.flags,
        pie: facts.pie,
        bind_now: facts.bind_now,
        interp: parsed.interp,
        segments: parsed.segments,
        sections: parsed.sections,
        symbols: parsed.linked.symbols,
        dynamic_symbols: parsed.linked.dynamic_symbols,
        relocations,
        dynamic: parsed.dynamic,
        needed: parsed.linked.needed,
        soname: parsed.linked.soname,
        rpath: parsed.linked.rpath,
        runpath: parsed.linked.runpath,
        init: facts.init,
        fini: facts.fini,
        init_array: facts.init_array,
        fini_array: facts.fini_array,
        preinit_array: facts.preinit_array,
        got,
        plt,
        exports,
        imports,
    }
}

struct ImageFacts {
    image_base: u64,
    pie: bool,
    bind_now: bool,
    init: Option<u64>,
    fini: Option<u64>,
    init_array: Option<ArraySpan>,
    fini_array: Option<ArraySpan>,
    preinit_array: Option<ArraySpan>,
}

fn image_facts(parsed: &Parsed) -> ImageFacts {
    let dynamic = &parsed.dynamic;
    ImageFacts {
        image_base: image_base(&parsed.segments),
        pie: flag_set(dynamic, DynamicTag::Flags1, DF_1_PIE),
        bind_now: bind_now(dynamic),
        init: positive(tag_value(dynamic, DynamicTag::Init)),
        fini: positive(tag_value(dynamic, DynamicTag::Fini)),
        init_array: span(dynamic, DynamicTag::InitArray, DynamicTag::InitArraySize),
        fini_array: span(dynamic, DynamicTag::FiniArray, DynamicTag::FiniArraySize),
        preinit_array: span(
            dynamic,
            DynamicTag::PreinitArray,
            DynamicTag::PreinitArraySize,
        ),
    }
}

fn check_entry(kind: ElfKind, entry: u64, segments: &[Segment]) -> Result<()> {
    if kind == ElfKind::Relocatable || entry == 0 {
        return Ok(());
    }
    let inside = segments.iter().any(|segment| {
        segment.kind == SegmentKind::Load
            && segment.memsz > 0
            && entry >= segment.vaddr
            && entry < segment.vaddr + segment.memsz
    });
    if inside {
        Ok(())
    } else {
        Err(msg("entry point is not in a load segment"))
    }
}

fn image_base(segments: &[Segment]) -> u64 {
    segments
        .iter()
        .filter(|segment| segment.kind == SegmentKind::Load)
        .map(|segment| segment.vaddr)
        .min()
        .unwrap_or(0)
}

fn flag_set(dynamic: &[DynamicEntry], tag: DynamicTag, bit: u64) -> bool {
    tag_value(dynamic, tag).unwrap_or(0) & bit != 0
}

fn bind_now(dynamic: &[DynamicEntry]) -> bool {
    dynamic.iter().any(|entry| entry.tag == DynamicTag::BindNow)
        || flag_set(dynamic, DynamicTag::Flags, DF_BIND_NOW)
        || flag_set(dynamic, DynamicTag::Flags1, DF_1_NOW)
}

fn tag_value(dynamic: &[DynamicEntry], tag: DynamicTag) -> Option<u64> {
    dynamic
        .iter()
        .find(|entry| entry.tag == tag)
        .map(|entry| entry.value)
}

fn positive(value: Option<u64>) -> Option<u64> {
    value.filter(|addr| *addr != 0)
}

fn span(dynamic: &[DynamicEntry], addr: DynamicTag, size: DynamicTag) -> Option<ArraySpan> {
    let addr = positive(tag_value(dynamic, addr))?;
    let size = tag_value(dynamic, size).unwrap_or(0);
    Some(ArraySpan { addr, size })
}

#[cfg(test)]
mod tests;
