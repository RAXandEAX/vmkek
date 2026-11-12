//! C6 proof: early checks run before the original entry.
//!
//! PE is System on M-EMU. ELF is System on M-LINUX.

use std::path::Path;
use std::process::Command;

use vmkek::elf::SegmentKind;
use vmkek::emu::{self, Policy};
use vmkek::pe::{self, PeImage};
use vmkek::proof::Claim;
use vmkek::protect::{self, Options, Protected};
use vmkek::report::Report;
use vmkek::{crypto, elf, sample};

#[test]
fn early_tls_runs_before_the_original_entry() {
    let protected = protect_pe();
    let image = pe::parse(&protected.bytes).unwrap();
    let header = header_of(&protected);
    let original = image.image_base + u64::from(header.original_entry);
    let callbacks = pe::tls_callbacks(&image).unwrap();
    assert_eq!(callbacks.len(), 1);
    assert_ne!(callbacks[0], original);
    let mut policy = Policy::default();
    policy.watch.push(original);
    let mut machine = emu::load(&image, policy).unwrap();
    machine.run().unwrap();
    assert_eq!(machine.exit_code, Some(0));
    assert_eq!(machine.stdout, sample::line().into_bytes());
    let early_at = at(&machine.trace, callbacks[0]);
    let entry_at = at(&machine.trace, original);
    assert!(early_at < entry_at, "{:x?}", machine.trace);
    assert_system(&protected.report, "early-tls", "M-EMU");
}

#[test]
fn excising_the_original_entry_fails_closed() {
    let protected = protect_pe();
    let header = header_of(&protected);
    let mut bytes = protected.bytes.clone();
    poke_pe(
        &mut bytes,
        header.original_entry,
        span_of(&protected.report, header.original_entry),
    );
    let image = pe::parse(&bytes).unwrap();
    let original = image.image_base + u64::from(header.original_entry);
    let mut machine = emu::load(&image, Policy::default()).unwrap();
    machine.run().unwrap();
    assert_eq!(machine.exit_code, Some(0xdeb6));
    assert_ne!(machine.stdout, sample::line().into_bytes());
    let early = pe::tls_callbacks(&image).unwrap()[0];
    assert_eq!(machine.trace.first().copied(), Some(early));
    assert!(!machine.trace.contains(&original));
}

#[test]
fn early_init_runs_before_the_original_entry() {
    let protected = protect_elf();
    let parsed = elf::parse(&protected.bytes).unwrap();
    assert!(parsed.init_array.is_some());
    let ran = run_elf(&protected.bytes, "order");
    assert_eq!(ran.status.code(), Some(0), "{}", stderr(&ran));
    assert_eq!(ran.stdout, sample::line().into_bytes());
    let err = stderr(&ran);
    let early = err.find("early\n").expect("early marker");
    let entry = err.find("entry\n").expect("entry marker");
    assert!(early < entry, "{err}");
    assert_system(&protected.report, "early-init", "M-LINUX");
}

#[test]
fn excising_the_elf_entry_fails_closed() {
    let protected = protect_elf();
    let header = header_of(&protected);
    let mut bytes = protected.bytes.clone();
    let va = header.image_base + u64::from(header.original_entry);
    poke_elf(
        &mut bytes,
        va,
        span_of(&protected.report, header.original_entry),
    );
    let ran = run_elf(&bytes, "excised");
    assert_eq!(ran.status.code(), Some(0xb6), "{}", stderr(&ran));
    assert_ne!(ran.stdout, sample::line().into_bytes());
    let err = stderr(&ran);
    assert!(err.contains("early\n"), "{err}");
    assert!(!err.contains("entry\n"), "{err}");
}

fn protect_pe() -> Protected {
    let built = sample::build().unwrap();
    protect::protect(&built.bytes, &opts(0xC6_0001)).unwrap()
}

fn protect_elf() -> Protected {
    let plain = elf::sample::build().unwrap();
    protect::protect(&plain, &opts(0xC6_0002)).unwrap()
}

fn opts(seed: u64) -> Options {
    Options {
        virtualize: Default::default(),
        mutate: Default::default(),
        virtualize_all: true,
        mutate_all: false,
        seed,
        random_key: false,
        debug_seed: false,
    }
}

fn header_of(protected: &Protected) -> crypto::Header {
    let bytes = hex::decode(&protected.report.public_key).unwrap();
    let key: [u8; 65] = bytes.try_into().unwrap();
    protect::inspect(&protected.bytes, &key).unwrap()
}

fn span_of(report: &Report, rva: u32) -> usize {
    let size = report
        .virtualized
        .iter()
        .find(|item| item.rva == rva)
        .map(|item| item.size)
        .unwrap_or(16);
    (size as usize).clamp(5, 64)
}

fn assert_system(report: &Report, pass: &str, machine: &str) {
    let claim = report
        .claims
        .iter()
        .find(|item| item.pass == pass)
        .unwrap_or_else(|| panic!("missing {pass}"));
    assert_eq!(claim.channel, "System");
    assert_eq!(claim.machine, machine);
    assert_eq!(claim.claim, Claim::Proven);
}

fn at(trace: &[u64], addr: u64) -> usize {
    trace
        .iter()
        .position(|item| *item == addr)
        .unwrap_or_else(|| panic!("{addr:#x} missing from {trace:x?}"))
}

fn poke_pe(file: &mut [u8], rva: u32, len: usize) {
    let image = pe::parse(file).unwrap();
    let section = section_of(&image, rva, len);
    let base = pe::section_file_offset(file, &section.name).unwrap();
    let at = base + (rva - section.rva) as usize;
    file[at..at + len].fill(0);
}

fn section_of(image: &PeImage, rva: u32, len: usize) -> &pe::Section {
    image
        .sections
        .iter()
        .find(|item| rva >= item.rva && (rva - item.rva) as usize + len <= item.bytes.len())
        .unwrap()
}

fn poke_elf(file: &mut [u8], va: u64, len: usize) {
    let image = elf::parse(file).unwrap();
    let segment = image
        .segments
        .iter()
        .find(|item| {
            item.kind == SegmentKind::Load
                && va >= item.vaddr
                && va + len as u64 <= item.vaddr + item.filesz
        })
        .unwrap();
    let at = (segment.offset + (va - segment.vaddr)) as usize;
    file[at..at + len].fill(0);
}

fn run_elf(bytes: &[u8], name: &str) -> std::process::Output {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("c6-elf-{name}"));
    std::fs::write(&path, bytes).unwrap();
    chmod(&path);
    Command::new(&path).output().unwrap()
}

fn chmod(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut mode = std::fs::metadata(path).unwrap().permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(path, mode).unwrap();
}

fn stderr(ran: &std::process::Output) -> String {
    String::from_utf8_lossy(&ran.stderr).into_owned()
}
