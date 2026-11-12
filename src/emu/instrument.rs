//! Instrumentation of the own image inside the emulator.
//!
//! Each sign has its own switch on [`super::Policy`]. A hit xors the poison byte
//! into the C1 chain of this thread and stops. Another thread's chain is not
//! written. The page snapshot is a hash, not a second copy of plaintext.

use crate::error::{msg, Result};
use crate::pe::PeImage;

use super::{Machine, Region};

/// Exit used when a sign poisons this thread's chain.
pub const FAIL_CLOSED: u32 = 0xDEB6;

const PAGE: usize = 0x1000;
/// `gettid` in the emulator returns 1. That is this thread.
const CURRENT_TID: u64 = 1;
const FOREIGN_TID: u64 = 2;
const FOREIGN_CHAIN: u64 = 0x6f00_0000;
const FOREIGN_FILL: u8 = 0x3C;

/// One instrumentation check. [`super::Policy::arm_instrument`] enables it alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instrument {
    /// A store into an executable page whose writer is outside this image.
    ForeignExecWrite,
    /// An executable page no longer matches the hash taken when it was mapped.
    CodePageHash,
    /// Another thread of this process is the writer of an executable page.
    ForeignThreadWrite,
}

/// Which writer a page-map substitution records for one executable page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageMap {
    /// The writer is not code of this image.
    ForeignWrite,
    /// The writer is another thread of this process.
    ForeignThread,
}

/// System proof row for one sign. The machine is M-EMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstrumentClaim {
    /// Short name of the sign.
    pub pass: &'static str,
    /// Proof channel. These rows are System.
    pub channel: &'static str,
    /// `M-EMU`.
    pub machine: &'static str,
    /// Test that runs the sign on its own.
    pub anchor: &'static str,
}

/// The three signs, each proved on M-EMU by its own test.
#[must_use]
pub fn claims() -> [InstrumentClaim; 3] {
    [
        row(
            "foreign-exec-write",
            "foreign_exec_write_alone_fails_closed",
        ),
        row("code-page-hash", "code_page_hash_alone_fails_closed"),
        row(
            "foreign-thread-write",
            "foreign_thread_write_alone_fails_closed",
        ),
    ]
}

fn row(pass: &'static str, anchor: &'static str) -> InstrumentClaim {
    InstrumentClaim {
        pass,
        channel: "System",
        machine: "M-EMU",
        anchor,
    }
}

pub(crate) struct ImageMap {
    base: u64,
    end: u64,
    pages: Vec<CodePage>,
    threads: Vec<ThreadView>,
    hashed: bool,
    /// `true` after the first look. Later steps read [`Self::hit`].
    seen: bool,
    hit: bool,
}

struct CodePage {
    base: u64,
    len: usize,
    hash: u64,
    hooked: bool,
    outside: bool,
    writer: u64,
}

struct ThreadView {
    id: u64,
    chain: u64,
    current: bool,
}

impl ImageMap {
    pub(super) fn empty() -> Self {
        Self {
            base: 0,
            end: 0,
            pages: Vec::new(),
            threads: vec![current_thread()],
            hashed: false,
            seen: false,
            hit: false,
        }
    }
}

fn current_thread() -> ThreadView {
    ThreadView {
        id: CURRENT_TID,
        chain: 0,
        current: true,
    }
}

fn armed(policy: &super::Policy) -> bool {
    policy.foreign_exec_write || policy.code_page_hash || policy.foreign_thread_write
}

fn page_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

pub(super) fn capture(machine: &mut Machine, image: &PeImage) -> Result<()> {
    let base = image.image_base;
    let mut pages = Vec::new();
    for section in &image.sections {
        if !crate::pe::executable(section) {
            continue;
        }
        let va = base.wrapping_add(u64::from(section.rva));
        push_pages(&mut pages, va, section.bytes.len());
    }
    hash_pages(machine, &mut pages)?;
    machine.image = ImageMap {
        base,
        end: image_end(machine, base)?,
        pages,
        threads: vec![current_thread()],
        hashed: false,
        seen: false,
        hit: false,
    };
    Ok(())
}

fn image_end(machine: &Machine, base: u64) -> Result<u64> {
    let region = machine
        .regions
        .iter()
        .find(|region| region.base == base)
        .ok_or_else(|| msg("own image is not mapped"))?;
    let len = u64::try_from(region.data.len()).map_err(|_| msg("own image is too large"))?;
    base.checked_add(len)
        .ok_or_else(|| msg("own image is too large"))
}

fn push_pages(pages: &mut Vec<CodePage>, va: u64, len: usize) {
    let mut off = 0usize;
    while off < len {
        let size = (len - off).min(PAGE);
        pages.push(CodePage {
            base: va + off as u64,
            len: size,
            hash: 0,
            hooked: false,
            outside: false,
            writer: CURRENT_TID,
        });
        off += size;
    }
}

fn hash_pages(machine: &Machine, pages: &mut [CodePage]) -> Result<()> {
    for page in pages.iter_mut() {
        let live = machine.read(page.base, page.len)?;
        page.hash = page_hash(&live);
    }
    Ok(())
}

pub(super) fn note_store(machine: &mut Machine, addr: u64, data: &[u8]) {
    if !armed(&machine.policy) || data.is_empty() || machine.image.pages.is_empty() {
        return;
    }
    let Some(end) = addr.checked_add(data.len() as u64) else {
        return;
    };
    if end <= machine.image.base || addr >= machine.image.end || rip_in_image(machine) {
        return;
    }
    mark_outside(machine, addr, end);
}

fn rip_in_image(machine: &Machine) -> bool {
    machine.rip >= machine.image.base && machine.rip < machine.image.end
}

fn mark_outside(machine: &mut Machine, addr: u64, end: u64) {
    let mut touched = false;
    for page in &mut machine.image.pages {
        let page_end = page.base + page.len as u64;
        if addr < page_end && page.base < end {
            page.outside = true;
            touched = true;
        }
    }
    if touched && machine.policy.foreign_exec_write {
        machine.image.hit = true;
        machine.image.seen = true;
    }
}

pub(super) fn trip(machine: &mut Machine) -> Result<bool> {
    if !armed(&machine.policy) || !sign_visible(machine)? {
        return Ok(false);
    }
    poison(machine)
}

fn sign_visible(machine: &mut Machine) -> Result<bool> {
    if machine.image.seen {
        return Ok(machine.image.hit);
    }
    let hit = fresh_sign(machine)?;
    machine.image.seen = true;
    machine.image.hit = hit;
    Ok(hit)
}

fn fresh_sign(machine: &mut Machine) -> Result<bool> {
    if machine.policy.code_page_hash && hash_mismatch(machine)? {
        return Ok(true);
    }
    if machine.policy.foreign_exec_write && machine.image.pages.iter().any(|page| page.outside) {
        return Ok(true);
    }
    Ok(machine.policy.foreign_thread_write && foreign_thread(&machine.image))
}

fn hash_mismatch(machine: &mut Machine) -> Result<bool> {
    if machine.image.hashed {
        return Ok(machine.image.pages.iter().any(|page| page.hooked));
    }
    let snap: Vec<(u64, usize, u64)> = machine
        .image
        .pages
        .iter()
        .map(|page| (page.base, page.len, page.hash))
        .collect();
    let found = mismatched(machine, &snap)?;
    for index in &found {
        machine.image.pages[*index].hooked = true;
    }
    machine.image.hashed = true;
    Ok(!found.is_empty())
}

fn mismatched(machine: &Machine, snap: &[(u64, usize, u64)]) -> Result<Vec<usize>> {
    let mut found = Vec::new();
    for (index, (base, len, hash)) in snap.iter().enumerate() {
        let live = machine.read(*base, *len)?;
        if page_hash(&live) != *hash {
            found.push(index);
        }
    }
    Ok(found)
}

fn foreign_thread(image: &ImageMap) -> bool {
    image.pages.iter().any(|page| {
        image
            .threads
            .iter()
            .any(|thread| !thread.current && thread.id == page.writer)
    })
}

fn foreign_chain(machine: &Machine, ptr: u64) -> bool {
    machine
        .image
        .threads
        .iter()
        .any(|thread| !thread.current && thread.chain == ptr)
}

fn poison(machine: &mut Machine) -> Result<bool> {
    let ptr = chain_ptr(machine)?;
    if ptr == 0 || foreign_chain(machine, ptr) {
        return Ok(false);
    }
    let key = machine.read(ptr, 32)?;
    if !key_ready(&key) || !master_elsewhere(machine, ptr, &key) {
        return Ok(false);
    }
    // Only this thread's chain. The master in the image and any other chain stay.
    let byte = [key[0] ^ crate::antidebug::KEY_POISON];
    machine.store(ptr, &byte)?;
    machine.exit_code = Some(FAIL_CLOSED);
    Ok(true)
}

fn key_ready(key: &[u8]) -> bool {
    key.iter().any(|byte| *byte != 0) && key.iter().any(|byte| *byte != 0xA5)
}

fn chain_ptr(machine: &Machine) -> Result<u64> {
    machine.context_chain_ptr()
}

fn master_elsewhere(machine: &Machine, chain: u64, key: &[u8]) -> bool {
    if key.len() != 32 {
        return false;
    }
    let Some(region) = machine
        .regions
        .iter()
        .find(|region| region.base == machine.image.base)
    else {
        return false;
    };
    if region.data.len() < 32 {
        return false;
    }
    region
        .data
        .windows(32)
        .enumerate()
        .any(|(off, window)| window == key && region.base.wrapping_add(off as u64) != chain)
}

fn page_index(machine: &Machine, addr: u64) -> Result<usize> {
    machine
        .image
        .pages
        .iter()
        .position(|page| addr >= page.base && addr < page.base + page.len as u64)
        .ok_or_else(|| {
            msg(format!(
                "executable page of the own image does not cover {addr:#x}"
            ))
        })
}

impl Machine {
    /// Replace one byte of an executable page without treating it as this image's store.
    pub fn substitute_code_byte(&mut self, addr: u64, value: u8) -> Result<()> {
        page_index(self, addr)?;
        self.store(addr, &[value])
    }

    /// Record a different writer for the executable page that contains `addr`.
    pub fn substitute_page_map(&mut self, addr: u64, map: PageMap) -> Result<()> {
        let index = page_index(self, addr)?;
        match map {
            PageMap::ForeignWrite => self.image.pages[index].outside = true,
            PageMap::ForeignThread => assign_foreign(self, index)?,
        }
        Ok(())
    }
}

fn assign_foreign(machine: &mut Machine, index: usize) -> Result<()> {
    plant_foreign(machine)?;
    machine.image.pages[index].writer = FOREIGN_TID;
    Ok(())
}

fn plant_foreign(machine: &mut Machine) -> Result<()> {
    if machine
        .image
        .threads
        .iter()
        .any(|thread| thread.id == FOREIGN_TID)
    {
        return Ok(());
    }
    machine.regions.push(Region {
        base: FOREIGN_CHAIN,
        data: vec![FOREIGN_FILL; 32],
    });
    machine.image.threads.push(ThreadView {
        id: FOREIGN_TID,
        chain: FOREIGN_CHAIN,
        current: false,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::OnceLock;

    use super::*;
    use crate::emu::{bare, load, Policy, GS_BASE};
    use crate::vm::GS_CHAIN_AT;

    fn load_sample(policy: Policy) -> Machine {
        let built = crate::sample::build().expect("sample");
        let image = crate::pe::parse(&built.bytes).expect("pe");
        load(&image, policy).expect("load")
    }

    fn code_byte(machine: &Machine) -> u64 {
        machine.image.pages[0].base
    }

    #[test]
    fn arm_instrument_sets_one_switch() {
        let policy = Policy::arm_instrument(Instrument::CodePageHash);
        assert!(policy.code_page_hash);
        assert!(!policy.foreign_exec_write);
        assert!(!policy.foreign_thread_write);
        assert!(!policy.int2d);
        assert_eq!(policy.debug_flags, 1);
    }

    #[test]
    fn hash_miss_is_not_a_foreign_write() {
        let mut hashed = load_sample(Policy::arm_instrument(Instrument::CodePageHash));
        let addr = code_byte(&hashed);
        let old = hashed.read(addr, 1).unwrap()[0] ^ 0xff;
        hashed.substitute_code_byte(addr, old).unwrap();
        assert!(sign_visible(&mut hashed).unwrap());
        let mut foreign = load_sample(Policy::arm_instrument(Instrument::ForeignExecWrite));
        foreign.substitute_code_byte(addr, old).unwrap();
        assert!(!sign_visible(&mut foreign).unwrap());
    }

    #[test]
    fn foreign_write_is_not_a_hash_miss() {
        let mut machine = load_sample(Policy::arm_instrument(Instrument::CodePageHash));
        let addr = code_byte(&machine);
        machine
            .substitute_page_map(addr, PageMap::ForeignWrite)
            .unwrap();
        assert!(!sign_visible(&mut machine).unwrap());
        let mut armed = load_sample(Policy::arm_instrument(Instrument::ForeignExecWrite));
        armed
            .substitute_page_map(addr, PageMap::ForeignWrite)
            .unwrap();
        assert!(sign_visible(&mut armed).unwrap());
    }

    #[test]
    fn foreign_thread_is_a_different_thread() {
        let mut machine = load_sample(Policy::arm_instrument(Instrument::ForeignThreadWrite));
        machine
            .substitute_page_map(code_byte(&machine), PageMap::ForeignThread)
            .unwrap();
        assert!(sign_visible(&mut machine).unwrap());
        let thread = machine
            .image
            .threads
            .iter()
            .find(|item| item.id == FOREIGN_TID)
            .unwrap();
        assert!(!thread.current);
        assert_eq!(thread.chain, FOREIGN_CHAIN);
        let fill = machine.read(FOREIGN_CHAIN, 32).unwrap();
        assert!(fill.iter().all(|byte| *byte == FOREIGN_FILL));
    }

    #[test]
    fn data_byte_is_not_an_executable_page() {
        let mut machine = load_sample(Policy::default());
        let addr = crate::pe::IMAGE_BASE + 0x2000;
        let err = machine.substitute_code_byte(addr, 0xcc).unwrap_err();
        assert!(err.to_string().contains("executable page"));
        let err = machine
            .substitute_page_map(addr, PageMap::ForeignWrite)
            .unwrap_err();
        assert!(err.to_string().contains("executable page"));
    }

    #[test]
    fn own_store_after_the_snapshot_is_not_a_hash_miss() {
        let mut machine = load_sample(Policy::arm_instrument(Instrument::CodePageHash));
        assert!(!sign_visible(&mut machine).unwrap());
        let addr = code_byte(&machine);
        machine.write(addr, &[0x90]).unwrap();
        assert!(!sign_visible(&mut machine).unwrap());
        assert!(!machine.image.pages[0].outside);
    }

    #[test]
    fn outside_store_marks_a_foreign_write() {
        let mut machine = load_sample(Policy::arm_instrument(Instrument::ForeignExecWrite));
        machine.rip = 0;
        let addr = code_byte(&machine);
        machine.write(addr, &[0x90]).unwrap();
        assert!(machine.image.pages[0].outside);
        assert!(sign_visible(&mut machine).unwrap());
    }

    fn synth_chain() -> Machine {
        let mut machine = bare(Policy::arm_instrument(Instrument::CodePageHash)).unwrap();
        let base = 0x1400_0000u64;
        let mut data = vec![0u8; 0x200];
        data[0x100..0x120].fill(0x11);
        machine.regions.push(Region { base, data });
        let chain = GS_BASE + GS_CHAIN_AT as u64;
        machine.store(chain, &[0x11; 32]).unwrap();
        machine.image.base = base;
        machine.image.end = base + 0x200;
        machine.image.hashed = true;
        machine.image.pages.push(CodePage {
            base,
            len: 0x200,
            hash: 0,
            hooked: true,
            outside: false,
            writer: CURRENT_TID,
        });
        machine.regions.push(Region {
            base: FOREIGN_CHAIN,
            data: vec![FOREIGN_FILL; 32],
        });
        machine.image.threads.push(ThreadView {
            id: FOREIGN_TID,
            chain: FOREIGN_CHAIN,
            current: false,
        });
        machine
    }

    #[test]
    fn poison_touches_only_this_chain() {
        let mut machine = synth_chain();
        assert!(trip(&mut machine).unwrap());
        assert_eq!(machine.exit_code, Some(FAIL_CLOSED));
        let ptr = chain_ptr(&machine).unwrap();
        let key = machine.read(ptr, 32).unwrap();
        assert_eq!(key[0], 0x11 ^ crate::antidebug::KEY_POISON);
        assert!(key[1..].iter().all(|byte| *byte == 0x11));
        let master = machine.read(0x1400_0000 + 0x100, 32).unwrap();
        assert!(master.iter().all(|byte| *byte == 0x11));
        let foreign = machine.read(FOREIGN_CHAIN, 32).unwrap();
        assert!(foreign.iter().all(|byte| *byte == FOREIGN_FILL));
        assert_ne!(ptr, FOREIGN_CHAIN);
    }

    const PADDING_RVA: u32 = 0x3000;

    fn protected() -> &'static [u8] {
        static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
        BYTES.get_or_init(|| {
            let built = crate::sample::build().expect("sample");
            let mut image = crate::pe::parse(&built.bytes).expect("sample PE");
            image.sections.push(crate::pe::Section {
                name: ".c9pad".into(),
                rva: PADDING_RVA,
                bytes: vec![0x90; 32],
                characteristics: crate::pe::CH_TEXT,
            });
            let input = crate::pe::emit(&image).expect("add unused executable page");
            let options = crate::protect::Options {
                virtualize: BTreeSet::new(),
                mutate: BTreeSet::new(),
                virtualize_all: true,
                mutate_all: false,
                seed: 1,
                random_key: false,
                debug_seed: false,
            };
            crate::protect::protect(&input, &options)
                .expect("protect")
                .bytes
        })
    }

    fn load_protected(policy: Policy) -> Machine {
        let image = crate::pe::parse(protected()).expect("pe");
        load(&image, policy).expect("load")
    }

    fn patch_padding(machine: &mut Machine) {
        let addr = crate::pe::IMAGE_BASE + u64::from(PADDING_RVA);
        assert_eq!(machine.read(addr, 1).unwrap(), [0x90]);
        machine.substitute_code_byte(addr, 0xcc).expect("patch");
    }

    fn map_write(machine: &mut Machine) {
        let addr = machine.image.pages[0].base;
        machine
            .substitute_page_map(addr, PageMap::ForeignWrite)
            .expect("map");
    }

    fn map_thread(machine: &mut Machine) {
        let addr = machine.image.pages[0].base;
        machine
            .substitute_page_map(addr, PageMap::ForeignThread)
            .expect("map");
    }

    fn assert_sample(machine: &Machine) {
        assert_eq!(
            machine.exit_code,
            Some(0),
            "{}",
            String::from_utf8_lossy(&machine.stdout)
        );
        assert_eq!(machine.stdout, crate::sample::line().into_bytes());
    }

    fn assert_closed(machine: &Machine) {
        assert_ne!(machine.stdout, crate::sample::line().into_bytes());
        assert_eq!(
            machine.exit_code,
            Some(FAIL_CLOSED),
            "{}",
            String::from_utf8_lossy(&machine.stdout)
        );
        assert_this_chain_poisoned(machine);
    }

    fn assert_this_chain_poisoned(machine: &Machine) {
        let ptr = chain_ptr(machine).expect("chain");
        assert_ne!(ptr, 0);
        assert_ne!(ptr, FOREIGN_CHAIN);
        let key = machine.read(ptr, 32).expect("key");
        let mut plain = key.clone();
        plain[0] ^= crate::antidebug::KEY_POISON;
        assert!(
            master_elsewhere(machine, ptr, &plain),
            "chain is not the poisoned master"
        );
        assert_ne!(key[0], plain[0]);
    }

    #[test]
    fn clean_run_prints_the_sample_line() {
        let mut machine = load_protected(Policy::default());
        machine.run().expect("run");
        assert_sample(&machine);
    }

    #[test]
    fn switches_without_a_sign_print_the_sample_line() {
        let policy = Policy {
            foreign_exec_write: true,
            code_page_hash: true,
            foreign_thread_write: true,
            ..Policy::default()
        };
        let mut machine = load_protected(policy);
        machine.run().expect("run");
        assert_sample(&machine);
    }

    #[test]
    fn substituted_byte_without_the_switch_prints_the_sample_line() {
        let mut machine = load_protected(Policy::default());
        patch_padding(&mut machine);
        machine.run().expect("run");
        assert_sample(&machine);
    }

    #[test]
    fn code_page_hash_alone_fails_closed() {
        let mut machine = load_protected(Policy::arm_instrument(Instrument::CodePageHash));
        patch_padding(&mut machine);
        machine.run().expect("run");
        assert_closed(&machine);
    }

    #[test]
    fn foreign_exec_write_alone_fails_closed() {
        let mut machine = load_protected(Policy::arm_instrument(Instrument::ForeignExecWrite));
        map_write(&mut machine);
        machine.run().expect("run");
        assert_closed(&machine);
    }

    #[test]
    fn foreign_thread_write_alone_fails_closed() {
        let mut machine = load_protected(Policy::arm_instrument(Instrument::ForeignThreadWrite));
        map_thread(&mut machine);
        let foreign = machine.read(FOREIGN_CHAIN, 32).expect("sentinel");
        machine.run().expect("run");
        assert_closed(&machine);
        assert_eq!(machine.read(FOREIGN_CHAIN, 32).expect("sentinel"), foreign);
        let thread = machine
            .image
            .threads
            .iter()
            .find(|item| item.id == FOREIGN_TID);
        assert!(thread.is_some_and(|item| !item.current && item.chain == FOREIGN_CHAIN));
    }

    #[test]
    fn claims_are_system_on_m_emu() {
        let rows = claims();
        assert_eq!(rows.len(), 3);
        let mut anchors = Vec::new();
        for row in rows {
            assert_eq!(row.channel, "System");
            assert_eq!(row.machine, "M-EMU");
            assert!(!row.pass.is_empty());
            assert!(!row.anchor.is_empty());
            anchors.push(row.anchor);
        }
        anchors.sort_unstable();
        anchors.dedup();
        assert_eq!(anchors.len(), 3);
    }

    #[test]
    fn new_functions_stay_within_fifty_lines() {
        for (name, span) in fn_spans("src/emu/instrument.rs") {
            assert!(span <= 50, "src/emu/instrument.rs {name} is {span}");
        }
        for name in [
            "guest_machine",
            "bare",
            "map_sections",
            "load",
            "write",
            "store",
            "arm_instrument",
            "default",
        ] {
            let span = span_named("src/emu/mod.rs", name);
            assert!(span <= 50, "src/emu/mod.rs {name} is {span}");
        }
        let step = span_named("src/emu/cpu.rs", "step");
        assert!(step <= 50, "src/emu/cpu.rs step is {step}");
    }

    fn span_named(path: &str, name: &str) -> usize {
        fn_spans(path)
            .into_iter()
            .find(|(item, _)| item == name)
            .unwrap_or_else(|| panic!("missing {path} {name}"))
            .1
    }

    fn fn_spans(path: &str) -> Vec<(String, usize)> {
        let text = read_src(path);
        let mut spans = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            let Some(name) = fn_name(line) else {
                continue;
            };
            spans.push((name, close_line(&text, idx) + 1));
        }
        spans
    }

    fn read_src(path: &str) -> String {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(root.join(path)).unwrap_or_else(|err| panic!("read {path}: {err}"))
    }

    fn fn_name(line: &str) -> Option<String> {
        let mut trimmed = line.trim();
        for prefix in ["pub(crate) ", "pub(super) ", "pub "] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                trimmed = rest;
                break;
            }
        }
        for prefix in ["const ", "async ", "unsafe "] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                trimmed = rest;
            }
        }
        let rest = trimmed.strip_prefix("fn ")?;
        let end = rest.find(['(', '<']).unwrap_or(rest.len());
        let name = &rest[..end];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        Some(name.to_string())
    }

    fn close_line(text: &str, start: usize) -> usize {
        let offset: usize = text.lines().take(start).map(|line| line.len() + 1).sum();
        scan_close(&text[offset..])
    }

    fn scan_close(rest: &str) -> usize {
        let mut line = 0usize;
        let mut depth = 0i32;
        let mut started = false;
        let mut chars = rest.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\n' => line += 1,
                '/' => line += skip_slash(&mut chars),
                '"' => line += skip_string(&mut chars),
                '\'' => skip_tick(&mut chars),
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => {
                    depth -= 1;
                    if started && depth == 0 {
                        return line;
                    }
                }
                _ => {}
            }
        }
        panic!("unclosed function");
    }

    type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

    fn skip_slash(chars: &mut Chars<'_>) -> usize {
        match chars.peek().copied() {
            Some('/') => skip_line_comment(chars),
            Some('*') => skip_block_comment(chars),
            _ => 0,
        }
    }

    fn skip_line_comment(chars: &mut Chars<'_>) -> usize {
        chars.next();
        for c in chars.by_ref() {
            if c == '\n' {
                return 1;
            }
        }
        0
    }

    fn skip_block_comment(chars: &mut Chars<'_>) -> usize {
        chars.next();
        let mut lines = 0;
        while let Some(c) = chars.next() {
            if c == '\n' {
                lines += 1;
            }
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                break;
            }
        }
        lines
    }

    fn skip_string(chars: &mut Chars<'_>) -> usize {
        let mut lines = 0;
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => return lines,
                '\n' => lines += 1,
                _ => {}
            }
        }
        lines
    }

    fn skip_tick(chars: &mut Chars<'_>) {
        let Some(first) = chars.peek().copied() else {
            return;
        };
        if first.is_ascii_alphabetic() || first == '_' {
            skip_lifetime(chars);
            return;
        }
        if first == '\\' {
            chars.next();
            chars.next();
            return;
        }
        chars.next();
        if chars.peek() == Some(&'\'') {
            chars.next();
        }
    }

    fn skip_lifetime(chars: &mut Chars<'_>) {
        while chars
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
        {
            chars.next();
        }
        if chars.peek() == Some(&'\'') {
            chars.next();
        }
    }
}
