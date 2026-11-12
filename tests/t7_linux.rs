//! Live Linux coverage of the opt-in trusted startup policy.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use vmkek::{crypto, elf, protect, sample};

struct Fixture {
    dir: PathBuf,
    path: PathBuf,
    digest: String,
}

impl Fixture {
    fn new() -> Self {
        static PROTECTED: OnceLock<protect::Protected> = OnceLock::new();
        let protected = PROTECTED.get_or_init(|| {
            let input = elf::sample::build().expect("ELF carrier");
            let options = protect::Options {
                virtualize: Default::default(),
                mutate: Default::default(),
                virtualize_all: true,
                mutate_all: false,
                seed: 0x7001,
                random_key: false,
                debug_seed: false,
            };
            protect::protect(&input, &options).expect("protect the carrier")
        });
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("vmkek-t7-{}", rand::random::<u128>()));
        fs::create_dir_all(dir.parent().unwrap()).expect("create target tmp directory");
        fs::create_dir(&dir).expect("create fixture directory");
        let path = dir.join("carrier");
        fs::write(&path, &protected.bytes).expect("write fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod fixture");
        Self {
            dir,
            path,
            digest: hex::encode(crypto::sha256(&protected.bytes)),
        }
    }

    fn guarded(&self, digest: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vmkek"));
        command
            .env_clear()
            .arg("run-native")
            .arg(&self.path)
            .arg("--sha256")
            .arg(digest);
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn output(command: &mut Command) -> Output {
    command.output().expect("run native ELF")
}

fn assert_carrier(run: Output) {
    assert!(run.status.success(), "{run:?}");
    assert_eq!(run.stdout, sample::line().as_bytes());
}

fn assert_rejected(run: Output, reason: &str) {
    assert_eq!(run.status.code(), Some(1), "{run:?}");
    assert!(run.stdout.is_empty(), "{run:?}");
    assert!(
        String::from_utf8_lossy(&run.stderr).contains(reason),
        "{run:?}"
    );
}

#[test]
fn native_startup_is_opt_in_and_runs_the_pinned_elf() {
    let fixture = Fixture::new();
    assert_carrier(output(Command::new(&fixture.path).env_clear()));
    assert_carrier(output(&mut fixture.guarded(&fixture.digest)));
}

#[test]
fn native_startup_rejects_loader_overrides_before_executing_target() {
    let fixture = Fixture::new();
    let library = compile_test_library(&fixture.dir);
    let direct = output(
        Command::new(&fixture.path)
            .env_clear()
            .env("LD_PRELOAD", &library)
            .env("LD_DEBUG", "libs"),
    );
    let trace = String::from_utf8_lossy(&direct.stderr);
    assert!(
        trace
            .lines()
            .any(|line| line.contains("calling init:") && line.contains("unexpected.so")),
        "{trace}"
    );
    assert_carrier(direct);
    let variants: [(&str, &Path); 3] = [
        ("LD_PRELOAD", &library),
        ("LD_AUDIT", &library),
        ("LD_LIBRARY_PATH", &fixture.dir),
    ];
    for (name, path) in variants {
        let run = output(fixture.guarded(&fixture.digest).env(name, path));
        assert_rejected(run, &format!("rejected loader override {name}"));
    }
}

fn compile_test_library(dir: &Path) -> PathBuf {
    let source = dir.join("unexpected.c");
    let library = dir.join("unexpected.so");
    fs::write(&source, "int vmkek_test_module(void) { return 7; }\n").expect("write DSO source");
    let build = output(
        Command::new("cc")
            .args(["-shared", "-fPIC"])
            .arg(&source)
            .arg("-o")
            .arg(&library),
    );
    assert!(build.status.success(), "{build:?}");
    library
}

#[test]
fn native_startup_rejects_digest_mismatch_and_shared_write_access() {
    let fixture = Fixture::new();
    assert_rejected(
        output(&mut fixture.guarded(&"00".repeat(32))),
        "rejected executable digest mismatch",
    );
    use std::io::Write;
    fs::OpenOptions::new()
        .append(true)
        .open(&fixture.path)
        .and_then(|mut file| file.write_all(b"extra unsigned bytes"))
        .expect("modify fixture");
    assert_rejected(
        output(&mut fixture.guarded(&fixture.digest)),
        "rejected executable digest mismatch",
    );
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o720)).expect("chmod fixture");
    assert_rejected(
        output(&mut fixture.guarded(&fixture.digest)),
        "without shared writes",
    );
}
