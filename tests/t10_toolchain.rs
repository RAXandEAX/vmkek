//! Defensive toolchain regressions over synthetic fixtures owned by the project.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn truncated_or_inconsistent_executable_headers_are_rejected() {
    let pe = vmkek::sample::build().unwrap().bytes;
    let elf = vmkek::elf::sample::build().unwrap();
    for end in [0, 4, 32, 63, 96, 256] {
        assert!(vmkek::pe::parse(&pe[..end]).is_err(), "PE cutoff {end}");
    }
    for end in [0, 4, 16, 63, 64] {
        assert!(vmkek::elf::parse(&elf[..end]).is_err(), "ELF cutoff {end}");
    }
    let mut overlapping = pe;
    let first_rva = overlapping[0x194..0x198].to_vec();
    overlapping[0x1bc..0x1c0].copy_from_slice(&first_rva);
    let err = vmkek::pe::parse(&overlapping).unwrap_err();
    assert!(err.to_string().contains("sections overlap"));
}

#[test]
fn excessive_elf_program_header_count_is_rejected() {
    const PROGRAM_HEADER_COUNT: usize = 56;
    let mut elf = vmkek::elf::sample::build().unwrap();
    assert!(vmkek::elf::parse(&elf).is_ok());
    elf[PROGRAM_HEADER_COUNT..][..2].copy_from_slice(&513u16.to_le_bytes());
    let err = vmkek::elf::parse(&elf).unwrap_err();
    assert!(err.to_string().contains("too many program headers"));
}

#[test]
fn emitted_loader_does_not_embed_build_paths() {
    let stub = vmkek::stub::assemble_vm_seeded(0x1000, 7).unwrap();
    for marker in [
        b"src/stub/".as_slice(),
        b"src\\stub\\",
        b"panicked at",
        b"/home/",
    ] {
        assert!(!stub
            .bytes
            .windows(marker.len())
            .any(|window| window == marker));
    }
}

#[test]
fn protect_cli_output_keeps_build_paths_and_secrets_out() {
    const SEED: u64 = 1_489_751_483_552_621_037;

    let dir = ArtifactDir::new();
    let input = dir.0.join("sample input.exe");
    let output = dir.0.join("protected output.exe");
    fs::write(&input, vmkek::sample::build().unwrap().bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_vmkek"))
        .arg("protect")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .arg("--virtualize-all")
        .arg("--seed")
        .arg(SEED.to_string())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );

    let bytes = fs::read(output).unwrap();
    let image = vmkek::pe::parse(&bytes).unwrap();
    let entry = image
        .sections
        .iter()
        .find(|section| {
            image.entry_rva >= section.rva
                && ((image.entry_rva - section.rva) as usize) < section.bytes.len()
        })
        .expect("loader entry section");
    let vm = vmkek::stub::assemble_vm_seeded(0x1000, SEED).unwrap();
    assert!(entry
        .bytes
        .windows(vm.dispatcher().len())
        .any(|window| window == vm.dispatcher()));
    for marker in [
        env!("CARGO_MANIFEST_DIR").as_bytes(),
        b"src/stub/",
        br"src\stub\",
        b"src/loader",
        br"src\loader",
        b"panicked at",
    ] {
        assert!(
            !entry
                .bytes
                .windows(marker.len())
                .any(|window| window == marker),
            "loader entry section contains {:?}",
            String::from_utf8_lossy(marker)
        );
    }

    let report = fs::read_to_string(dir.0.join("protected output.exe.report.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&report).unwrap();
    let fields = value.as_object().unwrap();
    assert!(fields
        .keys()
        .all(|field| vmkek::report::REPORT_FIELDS.contains(&field.as_str())));
    assert!(!fields.contains_key("seed"));
    assert!(!report.contains(&SEED.to_string()));
    let scalar = vmkek::crypto::deterministic_signing_scalar(SEED).unwrap();
    assert!(!report.contains(&hex::encode(scalar)));
}

struct ArtifactDir(PathBuf);

impl ArtifactDir {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(root).unwrap();
        let path = root.join(format!("vmkek-t10-{}", rand::random::<u128>()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for ArtifactDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn build_secret_buffer_is_zeroed() {
    let mut buffer = std::hint::black_box([0x5a_u8; 257]);
    vmkek::secret::wipe(&mut buffer);
    assert_eq!(std::hint::black_box(buffer), [0; 257]);
}

#[test]
fn oversized_sparse_input_is_rejected() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(dir).unwrap();
    let path = dir.join(format!("t10-oversize-{}", rand::random::<u128>()));
    let file = fs::File::create_new(&path).unwrap();
    file.set_len(128 * 1024 * 1024 + 1).unwrap();
    drop(file);
    let result = vmkek::protect::read_input(&path);
    fs::remove_file(path).unwrap();
    assert!(result.unwrap_err().to_string().contains("exceeds"));
}
