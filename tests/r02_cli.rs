use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use p256::ecdsa::SigningKey;
use serde_json::Value;
use vmkek::{crypto, pe, sample};

const APP: &str = "0102030405060708090a0b0c0d0e0f10";
const IMPORTS: [&str; 6] = [
    "BCryptHash",
    "BCryptImportKeyPair",
    "BCryptVerifySignature",
    "BCryptGenerateSymmetricKey",
    "BCryptDecrypt",
    "BCryptDestroyKey",
];

struct Fixture {
    dir: PathBuf,
    signer: PathBuf,
    pin: PathBuf,
    input: PathBuf,
    output: PathBuf,
}

impl Fixture {
    fn new(input: &[u8]) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("vmkek-r02-cli-{}-{stamp}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let fixture = Self {
            signer: dir.join("signer.bin"),
            pin: dir.join("pin.bin"),
            input: dir.join("sample.exe"),
            output: dir.join("protected.exe"),
            dir,
        };
        fs::write(&fixture.signer, [0x4a; 32]).unwrap();
        let signing = SigningKey::from_slice(&[0x4a; 32]).unwrap();
        fs::write(
            &fixture.pin,
            signing.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap();
        fs::write(&fixture.input, input).unwrap();
        fixture
    }

    fn protect(&self) -> Command {
        let mut command = cli();
        command
            .arg("protect")
            .arg(&self.input)
            .arg("-o")
            .arg(&self.output)
            .args(["--windows-native", "--virtualize-all", "--seed", "17"]);
        command
    }

    fn authenticated(&self) -> Command {
        let mut command = self.protect();
        command
            .args(["--authenticated-lab", "--manufacturer-signing-key"])
            .arg(&self.signer)
            .arg("--manufacturer-public-key")
            .arg(&self.pin)
            .args(["--application-id", APP]);
        command
    }

    fn report(&self) -> PathBuf {
        self.dir.join("protected.exe.report.json")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vmkek"))
}

fn rejects(result: Output, reason: &str) {
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains(reason), "{stderr}");
}

#[test]
fn opt_in_requires_exact_external_credentials_and_cng_imports() {
    let fixture = Fixture::new(&sample::build().unwrap().bytes);
    rejects(
        fixture
            .protect()
            .arg("--authenticated-lab")
            .output()
            .unwrap(),
        "--manufacturer-signing-key",
    );
    fs::write(&fixture.signer, [0x4a; 33]).unwrap();
    rejects(
        fixture.authenticated().output().unwrap(),
        "32-byte raw P-256 scalar",
    );
    fs::write(&fixture.signer, [0x4a; 32]).unwrap();
    rejects(
        fixture.authenticated().output().unwrap(),
        "bcrypt.dll!BCryptHash",
    );
    assert!(!fixture.output.exists());
    assert!(!fixture.report().exists());
}

#[test]
fn cli_writes_a_lab_report_and_legacy_readers_refuse_the_bootstrap() {
    let fixture = Fixture::new(&pe_with_cng_imports());
    let output = fixture.authenticated().output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let protected = fs::read(&fixture.output).unwrap();
    let report = fs::read_to_string(fixture.report()).unwrap();
    let parsed: Value = serde_json::from_str(&report).unwrap();
    assert_lab_report(&parsed, &protected);
    assert!(!protected.windows(32).any(|part| part == [0x4a; 32]));
    assert!(!report.contains(&hex::encode([0x4a; 32])));
    assert_legacy_readers_reject(&fixture.output);
}

fn assert_lab_report(report: &Value, protected: &[u8]) {
    assert_eq!(report["report_version"], 2);
    assert_eq!(report["profile"], "lab");
    assert_eq!(
        report["artifact_sha256"],
        hex::encode(crypto::sha256(protected))
    );
    let passes = report["passes"].as_array().unwrap();
    assert!(passes.iter().any(|pass| pass == "authenticated-bootstrap"));
    for legacy in [
        "offline-key",
        "aead-runtime",
        "aead-inspect",
        "crc32",
        "ecdsa-p256",
    ] {
        assert!(!passes.iter().any(|pass| pass == legacy), "{legacy}");
    }
    let claims = report["claims"].as_array().unwrap();
    assert!(claims
        .iter()
        .any(|claim| claim["pass"] == "authenticated-bootstrap"
            && claim["property"] == "authenticity"
            && claim["status"] == "pending"));
    assert!(claims
        .iter()
        .any(|claim| claim["pass"] == "authenticated-bootstrap"
            && claim["property"] == "compatibility"
            && claim["status"] == "not-run"));
}

fn assert_legacy_readers_reject(path: &Path) {
    for command in ["inspect", "run"] {
        rejects(
            cli().arg(command).arg(path).output().unwrap(),
            "authenticated bootstrap",
        );
    }
}

fn pe_with_cng_imports() -> Vec<u8> {
    const RVA: u32 = 0x3000;
    const CNG_IAT: u32 = 0x2138;
    let sample = sample::build().unwrap();
    let mut image = pe::parse(&sample.bytes).unwrap();
    let existing = pe::read_rva(&image, image.import_rva, 20).unwrap();
    let original_ilt = u32::from_le_bytes(existing[..4].try_into().unwrap());
    let mut imports = vec![0; 0x200];
    imports[..20].copy_from_slice(existing);
    imports[..4].copy_from_slice(&(RVA + 0x180).to_le_bytes());
    imports[0x180..0x1b8].copy_from_slice(pe::read_rva(&image, original_ilt, 0x38).unwrap());
    imports[20..24].copy_from_slice(&(RVA + 0x50).to_le_bytes());
    imports[32..36].copy_from_slice(&(RVA + 0x40).to_le_bytes());
    imports[36..40].copy_from_slice(&CNG_IAT.to_le_bytes());
    imports[0x40..0x4b].copy_from_slice(b"bcrypt.dll\0");
    let rdata = pe::section_mut(&mut image, ".rdata").unwrap();
    let iat_at = (CNG_IAT - rdata.rva) as usize;
    rdata.bytes[iat_at..iat_at + 0x38].fill(0);
    let mut name_at = 0xd0;
    for (index, name) in IMPORTS.iter().enumerate() {
        let thunk = (u64::from(RVA) + name_at as u64).to_le_bytes();
        let ilt = 0x50 + index * 8;
        imports[ilt..ilt + 8].copy_from_slice(&thunk);
        let iat = iat_at + index * 8;
        rdata.bytes[iat..iat + 8].copy_from_slice(&thunk);
        imports[name_at + 2..name_at + 2 + name.len()].copy_from_slice(name.as_bytes());
        name_at += name.len() + 3;
    }
    image.import_rva = RVA;
    image.import_size = 60;
    image.iat_size = CNG_IAT - image.iat_rva + 0x38;
    image.sections.push(pe::Section {
        name: ".cng".into(),
        rva: RVA,
        bytes: imports,
        characteristics: pe::CH_DATA,
    });
    pe::emit(&image).unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn legacy_inspect_without_a_key_does_not_open_a_fifo() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let fixture = Fixture::new(&[]);
    let fifo = fixture.dir.join("input.fifo");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let mut child = cli()
        .arg("inspect")
        .arg(fifo)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait().unwrap().is_some() {
            rejects(child.wait_with_output().unwrap(), "public key");
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("inspect blocked on FIFO without a key");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
