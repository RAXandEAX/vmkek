//! C7 on channel System.
//!
//! The protected sample reaches its kernel call through a direct `syscall`.
//! M-EMU runs the PE image. M-LINUX runs the ELF image. Both match the
//! ordinary import, and the sample's API name strings are absent from the file.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use vmkek::elf::sample as elf_sample;
use vmkek::emu::{self, Api, Policy, Region};
use vmkek::pe;
use vmkek::proof::{self, Claim};
use vmkek::protect::{self, Options};
use vmkek::sample;
use vmkek::syscall::{self, StubImage};

const CODE: u64 = 0x400000;
const STUB: u64 = 0x400200;
const BUF: u64 = 0x401000;
const WROTE: u64 = 0x401800;

#[test]
fn direct_syscall_matches_the_import() {
    let built = sample::build().expect("sample");
    let imported = emu::run_pe(&built.bytes, Policy::default()).expect("import path");
    let protected = protect::protect(&built.bytes, &opts(0xC7_0001)).expect("protect");
    let direct = emu::run_pe(&protected.bytes, Policy::default()).expect("direct path");
    assert_eq!(direct.exit_code, imported.exit_code);
    assert_eq!(direct.stdout, imported.stdout);
    assert_eq!(direct.stdout, sample::line().into_bytes());
    assert_names_absent(&built.bytes, &protected.bytes);
    assert_system(&protected.report, "direct-syscall", "M-EMU");
    let stubs = syscall::pe_stubs().expect("pe stubs");
    assert_distinct_stubs(&protected.bytes, &stubs);
    assert_write_matches(b"vmkek-ok:1\n");
    assert_handle_matches(0xffff_fff5);
    assert_handle_matches(0xffff_fff6);
    assert_handle_matches(0);
}

#[test]
fn linux_direct_syscall_matches_the_import() {
    let plain = elf_sample::build().expect("carrier");
    let imported = run_elf(&plain);
    let protected = protect::protect(&plain, &opts(0xC7_0002)).expect("protect");
    let direct = run_elf(&protected.bytes);
    assert_eq!(
        direct.code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&direct.stderr)
    );
    assert_eq!(imported.code, Some(0));
    assert_eq!(direct.stdout, imported.stdout);
    assert_eq!(direct.stdout, sample::line().into_bytes());
    assert_elf_names_absent(&plain, &protected.bytes);
    assert_system(&protected.report, "direct-syscall-linux", "M-LINUX");
    let stubs = syscall::linux_stubs().expect("linux stubs");
    assert_distinct_stubs(&protected.bytes, &stubs);
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

fn assert_names_absent(plain: &[u8], protected: &[u8]) {
    let image = pe::parse(plain).expect("pe");
    for import in &image.imports {
        refute(protected, import.name.as_bytes());
    }
}

fn assert_elf_names_absent(plain: &[u8], protected: &[u8]) {
    let image = vmkek::elf::parse(plain).expect("elf");
    for import in &image.imports {
        if !import.name.is_empty() {
            refute(protected, import.name.as_bytes());
        }
    }
}

fn refute(bytes: &[u8], name: &[u8]) {
    assert!(
        bytes.windows(name.len()).all(|window| window != name),
        "{}",
        String::from_utf8_lossy(name)
    );
}

fn assert_system(report: &vmkek::report::Report, pass: &str, machine: &str) {
    let claim = report
        .claims
        .iter()
        .find(|item| item.pass == pass)
        .unwrap_or_else(|| panic!("missing {pass}"));
    let row = proof::registry()
        .into_iter()
        .find(|item| item.pass == pass)
        .unwrap_or_else(|| panic!("missing row {pass}"));
    assert_eq!(*claim, row);
    assert_eq!(claim.channel, "System");
    assert_eq!(claim.machine, machine);
    assert_eq!(claim.claim, Claim::Proven);
}

fn assert_distinct_stubs(image: &[u8], stubs: &StubImage) {
    let write = syscall::stub_body(stubs, stubs.write);
    let other = syscall::stub_body(stubs, stubs.other);
    assert_ne!(write, other);
    assert!(has_syscall(write) && has_syscall(other));
    assert!(!write.contains(&0xe8) && !other.contains(&0xe8));
    assert_ne!(find(image, write), find(image, other));
}

fn has_syscall(bytes: &[u8]) -> bool {
    bytes.windows(2).any(|word| word == [0x0f, 0x05])
}

fn find(image: &[u8], needle: &[u8]) -> usize {
    image
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("stub missing from the image")
}

fn assert_write_matches(bytes: &[u8]) {
    let imported = observe_write(false, bytes);
    let direct = observe_write(true, bytes);
    assert_eq!(direct.stdout, bytes);
    assert_eq!(direct.stdout, imported.stdout);
    assert_eq!(direct.written, bytes.len() as u32);
    assert_eq!(direct.written, imported.written);
    assert_eq!(direct.rax, 1);
    assert_eq!(direct.rax, imported.rax);
}

fn assert_handle_matches(id: u64) {
    assert_eq!(observe_handle(true, id), observe_handle(false, id));
}

struct Seen {
    stdout: Vec<u8>,
    written: u32,
    rax: u64,
}

fn observe_write(direct: bool, bytes: &[u8]) -> Seen {
    let mut machine = guest();
    machine.write(BUF, bytes).unwrap();
    machine.write(WROTE, &0u32.to_le_bytes()).unwrap();
    let target = if direct {
        plant_stub(&mut machine).0
    } else {
        hook(&mut machine, Api::WriteFile)
    };
    machine.regs[0] = target;
    machine.regs[1] = 1;
    machine.regs[2] = BUF;
    machine.regs[8] = bytes.len() as u64;
    machine.regs[9] = WROTE;
    call_target(&mut machine);
    let raw = machine.read(WROTE, 4).unwrap();
    Seen {
        stdout: machine.stdout,
        written: u32::from_le_bytes(raw.try_into().unwrap()),
        rax: machine.regs[0],
    }
}

fn observe_handle(direct: bool, id: u64) -> u64 {
    let mut machine = guest();
    let target = if direct {
        plant_stub(&mut machine).1
    } else {
        hook(&mut machine, Api::GetStdHandle)
    };
    machine.regs[0] = target;
    machine.regs[1] = id;
    call_target(&mut machine);
    machine.regs[0]
}

fn guest() -> emu::Machine {
    let mut machine = emu::bare(Policy {
        max_steps: 1_000,
        ..Policy::default()
    })
    .unwrap();
    machine.regions.push(Region {
        base: CODE,
        data: vec![0; 0x2000],
    });
    machine
}

fn call_target(machine: &mut emu::Machine) {
    machine.write(CODE, &[0xff, 0xd0, 0xc3]).unwrap();
    machine.rip = CODE;
    machine.run().unwrap();
}

fn hook(machine: &mut emu::Machine, api: Api) -> u64 {
    let at = 0x1800_01000;
    machine.hooks.insert(at, api);
    at
}

fn plant_stub(machine: &mut emu::Machine) -> (u64, u64) {
    let image = syscall::pe_stubs().unwrap();
    machine.write(STUB, &image.bytes).unwrap();
    (STUB + image.write as u64, STUB + image.other as u64)
}

struct Ran {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_elf(bytes: &[u8]) -> Ran {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("c7-elf-{id}"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let output = spawn(&path);
    if output.status.success() {
        let _ = fs::remove_file(&path);
    }
    Ran {
        code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn spawn(path: &Path) -> std::process::Output {
    for _ in 0..8 {
        match Command::new("timeout").arg("5").arg(path).output() {
            Ok(output) => return output,
            Err(err) if err.raw_os_error() == Some(26) => thread::sleep(Duration::from_millis(20)),
            Err(err) => panic!("spawn {}: {err}", path.display()),
        }
    }
    panic!("spawn {}: text file busy", path.display())
}
