//! M-LINUX proof that `protect` emits a runnable ELF64 image.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use vmkek::crypto;
use vmkek::elf;
use vmkek::elf::sample;
use vmkek::proof::{self, Claim};
use vmkek::protect::{self, Options};
use vmkek::report::{self, Report};
use vmkek::sample as carrier;

#[test]
fn protected_elf_matches_the_carrier_on_linux() {
    let plain = sample::build().expect("carrier");
    assert_carrier(&run(&plain));

    let left = protect::protect(&plain, &opts(0xE2_0001)).expect("protect seed a");
    let right = protect::protect(&plain, &opts(0xE2_0002)).expect("protect seed b");
    let again = protect::protect(&plain, &opts(0xE2_0001)).expect("protect seed a again");
    assert_eq!(left.bytes, again.bytes);
    assert!(report::report_hides_seed(&left.report, 0xE2_0001));
    assert_carrier(&run(&left.bytes));
    assert_carrier(&run(&right.bytes));

    let difference =
        report::section_difference_percent(&section(&left.bytes), &section(&right.bytes));
    assert!(difference >= 25, "section difference {difference}");
    assert_names_hidden(&left.bytes);
    assert_ne!(payload_name(&left.bytes), payload_name(&right.bytes));
    assert!(!payload_name(&left.bytes).contains("vmkek"));

    assert_claims(&left.report);
    assert_claims(&right.report);
    let key = public_key(&left.report);
    protect::inspect(&left.bytes, &key).expect("inspect");
    assert_tamper_fails(&left.bytes, &key);
}

fn assert_carrier(ran: &Ran) {
    assert_eq!(ran.code, Some(0), "{}", ran.detail());
    assert_eq!(ran.stdout, carrier::line().into_bytes());
}

fn assert_names_hidden(bytes: &[u8]) {
    assert!(!bytes
        .windows(b"vmkek-ok:".len())
        .any(|window| window == b"vmkek-ok:"));
    assert!(!has_cstr(bytes, b"write"));
    assert!(!has_cstr(bytes, b"exit"));
    assert!(bytes
        .windows(b"libc.so.6".len())
        .any(|window| window == b"libc.so.6"));
}

fn assert_tamper_fails(bytes: &[u8], key: &[u8; 65]) {
    let mut tampered = bytes.to_vec();
    flip_payload(&mut tampered);
    let broken = run(&tampered);
    assert_ne!(broken.stdout, carrier::line().into_bytes());
    assert_ne!(
        broken.code,
        Some(0),
        "tamper still exited 0: {}",
        broken.detail()
    );
    assert!(protect::inspect(&tampered, key).is_err());
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

fn assert_claims(report: &Report) {
    for claim in &report.claims {
        let row = proof::registry()
            .into_iter()
            .find(|item| item.pass == claim.pass)
            .unwrap_or_else(|| panic!("missing registry row {}", claim.pass));
        assert_eq!(*claim, row);
    }
    for pass in ["bytecode-encrypt", "aead-inspect", "ecdsa-p256"] {
        let claim = report
            .claims
            .iter()
            .find(|item| item.pass == pass)
            .unwrap_or_else(|| panic!("missing {pass}"));
        assert_eq!(claim.channel, "Crypto");
        assert_eq!(claim.claim, Claim::Proven);
    }
    for pass in [
        "trampoline",
        "import-hash",
        "string-encrypt",
        "peb-being-debugged",
        "heap-flags",
    ] {
        assert!(
            report.passes.iter().any(|item| item == pass),
            "missing {pass}"
        );
    }
    for absent in [
        "is-debugger-present",
        "nt-global-flag",
        "int-2d",
        "parent-debugger",
    ] {
        assert!(
            !report.passes.iter().any(|item| item == absent),
            "{absent} is a windows loader pass"
        );
    }
}

fn public_key(report: &Report) -> [u8; 65] {
    let bytes = hex::decode(&report.public_key).expect("public key hex");
    bytes.try_into().expect("p256 public key")
}

fn section(bytes: &[u8]) -> Vec<u8> {
    let image = elf::parse(bytes).expect("parse protected elf");
    let section = payload(&image, bytes);
    let off = usize::try_from(section.offset).expect("offset");
    let len = usize::try_from(section.size).expect("size");
    bytes[off..off + len].to_vec()
}

fn payload<'a>(image: &'a elf::ElfImage, bytes: &[u8]) -> &'a elf::Section {
    image
        .sections
        .iter()
        .find(|section| {
            let off = usize::try_from(section.offset).unwrap_or(usize::MAX);
            bytes.get(off..off + 8) == Some(crypto::MAGIC)
        })
        .expect("payload section")
}

fn payload_name(bytes: &[u8]) -> String {
    let image = elf::parse(bytes).expect("parse protected elf");
    payload(&image, bytes)
        .name
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn flip_payload(bytes: &mut [u8]) {
    let at = crypto::find_header(bytes).expect("header");
    let header = crypto::Header::parse(&bytes[at..]).expect("parse header");
    let pos = at + header.payload_off as usize + 8;
    bytes[pos] ^= 0xff;
}

fn has_cstr(bytes: &[u8], name: &[u8]) -> bool {
    bytes
        .windows(name.len() + 1)
        .any(|window| window[..name.len()] == *name && window[name.len()] == 0)
}

struct Ran {
    code: Option<i32>,
    signal: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    path: std::path::PathBuf,
}

impl Ran {
    fn detail(&self) -> String {
        format!(
            "code {:?} signal {:?} stderr {} path {}",
            self.code,
            self.signal,
            String::from_utf8_lossy(&self.stderr),
            self.path.display()
        )
    }
}

fn run(bytes: &[u8]) -> Ran {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("e2-elf-{id}"));
    fs::create_dir_all(path.parent().expect("target")).expect("target dir");
    fs::write(&path, bytes).expect("write carrier");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
    let mut output = None;
    for _ in 0..8 {
        match Command::new("timeout").arg("5").arg(&path).output() {
            Ok(spawned) => {
                output = Some(spawned);
                break;
            }
            Err(err) if err.raw_os_error() == Some(26) => thread::sleep(Duration::from_millis(20)),
            Err(err) => panic!("spawn {}: {err}", path.display()),
        }
    }
    let output = output.unwrap_or_else(|| panic!("spawn {}: text file busy", path.display()));
    if output.status.success() {
        let _ = fs::remove_file(&path);
    }
    Ran {
        code: output.status.code(),
        signal: output.status.signal(),
        stdout: output.stdout,
        stderr: output.stderr,
        path,
    }
}
