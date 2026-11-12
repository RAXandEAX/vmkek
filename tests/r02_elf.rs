#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::Value;
use vmkek::crypto::authenticated::{
    BOOTSTRAP_MAGIC, BOOTSTRAP_SIGNATURE_DOMAIN, BOOTSTRAP_SIGNATURE_OFFSET, BOOTSTRAP_TAG_OFFSET,
    ELF_LAB_ENTRY_AFTER_MANIFEST, ELF_LAB_HELPER_VA,
};
use vmkek::elf::{self, DynamicTag, SegmentKind, SymbolSection};

const TEST_SCALAR: [u8; 32] = [0x91; 32];

#[test]
#[ignore = "requires the trusted helper built by tools/elf-auth-helper/build.sh"]
fn cli_authenticated_elf_runs_directly_and_fails_closed() {
    let helper = std::env::var_os("VMKEK_R02_ELF_HELPER").expect("set VMKEK_R02_ELF_HELPER");
    let fixture = Fixture::new();
    fixture.rejects_exported_input(Path::new(&helper));
    fixture.rejects_startup_hooks(Path::new(&helper));
    let first = fixture.protect(Path::new(&helper), "protected.elf");
    let second = fixture.protect(Path::new(&helper), "same-seed.elf");
    let bytes = fs::read(&first).unwrap();
    let other = fs::read(&second).unwrap();
    let locations = artifact_locations(&bytes);
    let other_locations = artifact_locations(&other);
    assert_ne!(
        &bytes[locations.payload.clone()],
        &other[other_locations.payload]
    );
    assert_lab_report(&first, &bytes);
    let original = fs::read(fixture.dir.join("sample.elf")).unwrap();
    assert_eq!(
        elf::parse(&bytes).unwrap().dynamic,
        elf::parse(&original).unwrap().dynamic
    );
    for path in [&first, &second, &first] {
        let ran = direct(path);
        assert_eq!(ran.status.code(), Some(0), "{:?}", ran.stderr);
        assert_eq!(ran.stdout, b"vmkek-ok:783\n");
    }
    assert_tampering_refused(&fixture, &bytes, &locations);
    for command in ["inspect", "run"] {
        let rejected = cli().arg(command).arg(&first).output().unwrap();
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("native ELF lab loader"));
    }
}

#[test]
#[ignore = "requires the trusted helper built by tools/elf-auth-helper/build.sh"]
fn cli_authenticated_elf_calls_unselected_native_function() {
    let helper = std::env::var_os("VMKEK_R02_ELF_HELPER").expect("set VMKEK_R02_ELF_HELPER");
    let fixture = Fixture::new();
    let original = fixture.dir.join("sample.elf");
    let protected = fixture.dir.join("native-calls.elf");
    let built = fixture
        .protect_cmd(Path::new(&helper), &original, &protected, "compute")
        .output()
        .unwrap();
    assert!(built.status.success(), "{:?}", built.stderr);
    assert_native_call_output(&original, &protected);
}

#[test]
fn cli_legacy_elf_calls_unselected_native_function() {
    let fixture = Fixture::new();
    let original = fixture.dir.join("legacy-original.elf");
    fs::write(&original, elf::sample::build().unwrap()).unwrap();
    let protected = fixture.dir.join("legacy-native-calls.elf");
    let built = cli()
        .arg("protect")
        .arg(&original)
        .arg("-o")
        .arg(&protected)
        .args(["--virtualize", "compute", "--seed", "4660"])
        .output()
        .unwrap();
    assert!(built.status.success(), "{:?}", built.stderr);
    assert_native_call_output(&original, &protected);
}

fn assert_native_call_output(original: &Path, protected: &Path) {
    let expected = direct(original);
    assert_eq!(expected.status.code(), Some(0));
    assert_eq!(expected.stdout, b"vmkek-ok:783\n");
    let actual = direct(protected);
    assert_eq!(actual.status.code(), expected.status.code());
    assert_eq!(actual.stdout, expected.stdout);
}

fn assert_tampering_refused(fixture: &Fixture, bytes: &[u8], locations: &Locations) {
    let manifest = locations.manifest;
    for (name, offset) in [
        ("version", manifest + 16),
        ("scope", manifest + 31),
        ("extent", manifest + 98),
        ("ciphertext", locations.payload.start),
        ("signature", manifest + BOOTSTRAP_SIGNATURE_OFFSET),
    ] {
        let mut changed = bytes.to_vec();
        changed[offset] ^= 1;
        assert_closed(fixture, name, &changed);
    }

    let mut bad_tag = bytes.to_vec();
    bad_tag[manifest + BOOTSTRAP_TAG_OFFSET] ^= 1;
    let mut transcript = BOOTSTRAP_SIGNATURE_DOMAIN.to_vec();
    transcript.extend_from_slice(&bad_tag[manifest..manifest + BOOTSTRAP_SIGNATURE_OFFSET]);
    let signature: Signature = fixture.signing.sign(&transcript);
    let sig_at = manifest + BOOTSTRAP_SIGNATURE_OFFSET;
    bad_tag[sig_at..sig_at + 64].copy_from_slice(&signature.to_bytes());
    assert_closed(fixture, "resigned-tag", &bad_tag);

    let mut with_marker = bytes.to_vec();
    assert_eq!(with_marker[locations.data_padding], 0);
    with_marker[locations.data_padding] = 1;
    with_marker[locations.payload.start] ^= 1;
    assert_closed(fixture, "data-marker-and-bad-ciphertext", &with_marker);
}

fn assert_closed(fixture: &Fixture, name: &str, bytes: &[u8]) {
    let path = fixture.dir.join(name);
    fs::write(&path, bytes).unwrap();
    let ran = direct(&path);
    assert_eq!(ran.status.code(), Some(209), "{name}: {:?}", ran.stderr);
    assert!(ran.stdout.is_empty(), "{name}");
}

fn assert_lab_report(path: &Path, bytes: &[u8]) {
    let report_bytes = fs::read(path.with_extension("elf.report.json")).unwrap();
    let report: Value = serde_json::from_slice(&report_bytes).unwrap();
    assert_eq!(report["report_version"], 2);
    assert_eq!(report["profile"], "lab");
    assert_eq!(
        report["artifact_sha256"],
        hex::encode(vmkek::crypto::sha256(bytes))
    );
    assert_eq!(report["virtualized"][0]["name"], "mix");
    assert!(!bytes
        .windows(TEST_SCALAR.len())
        .any(|value| value == TEST_SCALAR));
    assert!(!String::from_utf8_lossy(&report_bytes).contains(&hex::encode(TEST_SCALAR)));
}

struct Locations {
    manifest: usize,
    payload: std::ops::Range<usize>,
    data_padding: usize,
}

fn artifact_locations(bytes: &[u8]) -> Locations {
    let image = elf::parse(bytes).unwrap();
    assert!(image
        .segments
        .iter()
        .filter(|item| item.kind == SegmentKind::Load)
        .all(|item| item.flags & 3 != 3));
    let code = image
        .segments
        .iter()
        .find(|item| item.kind == SegmentKind::Load && item.vaddr == ELF_LAB_HELPER_VA)
        .unwrap();
    assert_eq!(code.flags, 5);
    let manifest = (code.offset + image.entry - code.vaddr) as usize - ELF_LAB_ENTRY_AFTER_MANIFEST;
    assert_eq!(&bytes[manifest..manifest + 16], BOOTSTRAP_MAGIC);
    let payload =
        u64::from_le_bytes(bytes[manifest + 90..manifest + 98].try_into().unwrap()) as usize;
    let len = u32::from_le_bytes(bytes[manifest + 98..manifest + 102].try_into().unwrap()) as usize;
    let data = image
        .segments
        .iter()
        .find(|item| {
            item.kind == SegmentKind::Load
                && item.flags == 6
                && payload as u64 >= item.offset
                && (payload + len) as u64 <= item.offset + item.filesz
        })
        .unwrap();
    assert!(image.preinit_array.is_none());
    Locations {
        manifest,
        payload: payload..payload + len,
        data_padding: (data.offset + data.filesz - 1) as usize,
    }
}

struct Fixture {
    dir: PathBuf,
    signing: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("vmkek-r02-elf-{}-{stamp}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let signing = SigningKey::from_slice(&TEST_SCALAR).unwrap();
        fs::write(dir.join("signing"), TEST_SCALAR).unwrap();
        fs::write(
            dir.join("pin"),
            signing.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap();
        fs::write(dir.join("sample.elf"), local_symbol_sample()).unwrap();
        Self { dir, signing }
    }

    fn protect(&self, helper: &Path, name: &str) -> PathBuf {
        let output = self.dir.join(name);
        let run = self
            .protect_cmd(helper, &self.dir.join("sample.elf"), &output, "mix")
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        output
    }

    fn rejects_exported_input(&self, helper: &Path) {
        let input_path = self.dir.join("exported.elf");
        let output_path = self.dir.join("exported-output.elf");
        fs::write(&input_path, elf::sample::build().unwrap()).unwrap();
        let rejected = self
            .protect_cmd(helper, &input_path, &output_path, "mix")
            .output()
            .unwrap();
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("rejects executable exports"));
        assert!(!output_path.exists());
    }

    fn rejects_startup_hooks(&self, helper: &Path) {
        let input = fs::read(self.dir.join("sample.elf")).unwrap();
        let image = elf::parse(&input).unwrap();
        let dynamic = image
            .segments
            .iter()
            .find(|item| item.kind == SegmentKind::Dynamic)
            .unwrap();
        let start = dynamic.offset as usize;
        let end = start + dynamic.filesz as usize;
        let index = input[start..end]
            .chunks_exact(16)
            .position(|entry| entry[..8] == 21u64.to_le_bytes())
            .unwrap();
        let tag_at = start + index * 16;
        let input_path = self.dir.join("unsupported.elf");
        let output_path = self.dir.join("unsupported-output.elf");
        for tag in [12u64, 25, 27, 32, 33, 0x7fff_fffd, 0x7fff_ffff] {
            let mut changed = input.clone();
            changed[tag_at..tag_at + 8].copy_from_slice(&tag.to_le_bytes());
            fs::write(&input_path, changed).unwrap();
            let rejected = self
                .protect_cmd(helper, &input_path, &output_path, "mix")
                .output()
                .unwrap();
            assert!(!rejected.status.success(), "startup tag {tag:#x}");
            assert!(!output_path.exists(), "startup tag {tag:#x}");
        }
    }

    fn protect_cmd(&self, helper: &Path, input: &Path, output: &Path, function: &str) -> Command {
        let mut command = cli();
        command
            .arg("protect")
            .arg(input)
            .arg("-o")
            .arg(output)
            .args([
                "--virtualize",
                function,
                "--seed",
                "4660",
                "--authenticated-lab",
            ])
            .arg("--elf-auth-helper")
            .arg(helper)
            .arg("--manufacturer-signing-key")
            .arg(self.dir.join("signing"))
            .arg("--manufacturer-public-key")
            .arg(self.dir.join("pin"))
            .args(["--application-id", "0102030405060708090a0b0c0d0e0f10"]);
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn local_symbol_sample() -> Vec<u8> {
    let mut bytes = elf::sample::build().unwrap();
    let image = elf::parse(&bytes).unwrap();
    let symtab = image.dynamic_value(DynamicTag::SymTab).unwrap();
    let segment = image
        .segments
        .iter()
        .find(|item| {
            item.kind == SegmentKind::Load
                && item.vaddr <= symtab
                && symtab < item.vaddr + item.filesz
        })
        .unwrap();
    let symbols = (segment.offset + symtab - segment.vaddr) as usize;
    for (index, symbol) in image.dynamic_symbols.iter().enumerate() {
        if matches!(symbol.section, SymbolSection::Index(_)) {
            bytes[symbols + index * 24 + 5] = 2; // STV_HIDDEN
        }
    }
    assert!(elf::parse(&bytes).unwrap().exports.is_empty());
    bytes
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vmkek"))
}

fn direct(path: &Path) -> Output {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    Command::new(path).env_clear().output().unwrap()
}
