//! T4: image hygiene on synthetic files and on the sample. M-EMU runs the sample.
//! Sealed unwind stays red: the handler proof is not claimed.

use vmkek::emu::{self, Policy};
use vmkek::pe::{self, PeImage, Section, CH_RDATA, CH_TEXT, IMAGE_BASE};
use vmkek::proof::Claim;
use vmkek::protect::{self, Options};
use vmkek::report::{Report, REPORT_FIELDS};
use vmkek::unwind::{self, ChannelColor};
use vmkek::{crypto, sample};

const POOL: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
const CLASS: &[u8] = b".?AVSecretClass@@";

#[test]
fn pe_rewrite_refuses_unsupported_cfi_and_reports_resigning() {
    let mut cfg = marked_image(0);
    let mut kind = pe::image_kind(&cfg).unwrap();
    kind.dll_characteristics |= 0x4000;
    pe::set_image_kind(&mut cfg, &kind).unwrap();
    assert!(err(&cfg).contains("CFG image"));

    let mut cet = marked_image(0);
    let rdata = pe::section_file_offset(&cet, ".rdata").unwrap();
    put32(&mut cet, rdata + 0x480 + 12, 20);
    cet[rdata + 0x4b0..rdata + 0x4b2].copy_from_slice(&1u16.to_le_bytes());
    assert!(err(&cet).contains("CET/forward-CFI"));

    let mut signed = marked_image(0);
    let cert = signed.len() as u32;
    signed.extend_from_slice(&[8, 0, 0, 0, 0, 2, 2, 0]);
    put32(&mut signed, 0x128, cert);
    put32(&mut signed, 0x12c, 8);
    let protected = protect::protect(&signed, &opts(1)).expect("protect signed image");
    assert!(protected.report.authenticode_resign_required);
    assert_eq!(&protected.bytes[0x128..0x130], &[0; 8]);
}

#[test]
fn synthetic_and_sample_drop_fixed_metadata() {
    assert_rejections();
    assert_metadata_is_gone();
    assert_sample_channel();
    assert_names_follow_the_seed();
    assert_elf_maps_are_sealed();
    assert_sealed_unwind_stays_red();
}

#[test]
fn virtualized_pools_and_rtti_are_sealed() {
    let protected = protect::protect(&marked_image(0x1111_1111), &opts(1)).expect("protect");
    let image = pe::parse(&protected.bytes).expect("parse");
    assert!(claim_is(&protected.report, "sealed-maps"));
    assert_sealed(&image, 0x2000, &POOL, 1);
    assert_sealed(&image, 0x2020, &table_bytes(), 1);
    assert_sealed(&image, 0x2220, &rel_bytes(), 1);
    assert_no_cleartext(&protected.bytes, b"SecretClass");
    assert_no_cleartext(&protected.bytes, &utf16(b"SecretClass"));
    assert!(unwind::pe_row_at(&image, 0x1000).is_err());
    let mut opened = image.clone();
    open_pdata(&mut opened, 1);
    assert_eq!(
        unwind::pe_row_at(&opened, 0x1000).expect("row"),
        unwind::entry_row()
    );
    let mut machine = emu::load(&image, Policy::default()).expect("load");
    machine.run().expect("run");
    let pool = machine.read(IMAGE_BASE + 0x2000, POOL.len()).expect("pool");
    assert_eq!(pool, POOL);
    let rel = machine.read(IMAGE_BASE + 0x2220, 16).expect("rel");
    assert_eq!(rel, rel_bytes());
}

fn assert_rejections() {
    let image = marked_image(0x1111_1111);
    assert_eq!(
        err(&patch_machine(&image, 0xaa64)),
        "arm images are rejected"
    );
    assert_eq!(
        err(&patch_machine(&image, 0x014c)),
        "pe32 x86 images are rejected"
    );
    assert_eq!(err(&patch_magic(&image)), "pe32 x86 images are rejected");
    assert_eq!(err(&patch_clr(&image)), "clr/.net images are rejected");
    assert_eq!(
        err(&patch_upx(&image)),
        "foreign packer images are rejected"
    );
    assert_seed_name_is_not_foreign(2_941_772);
    assert_seed_name_is_not_foreign(17_016_167);
    let mut elf = [0u8; 64];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[18..20].copy_from_slice(&183u16.to_le_bytes());
    assert_eq!(err(&elf), "arm images are rejected");
    elf[18..20].copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(err(&elf), "pe32 x86 images are rejected");
}

fn assert_metadata_is_gone() {
    let protected = protect::protect(&marked_image(0x1111_1111), &opts(4)).expect("protect");
    assert_no_cleartext(&protected.bytes, b"Rich");
    assert_no_cleartext(&protected.bytes, b"DanS");
    assert_no_cleartext(&protected.bytes, b"panicked at");
    assert_no_cleartext(&protected.bytes, b"src/stub");
    assert_no_cleartext(&protected.bytes, b".pdb");
    assert_no_cleartext(&protected.bytes, b"RSDS");
    assert_ne!(timestamp(&protected.bytes), 0x1111_1111);
    assert_ne!(timestamp(&protected.bytes), 0);
    assert_eq!(debug_dir(&protected.bytes), (0, 0));
    let parsed = pe::parse(&protected.bytes).expect("parse");
    let body = pe::read_rva(&parsed, 0x2480, 28).expect("debug body");
    assert_eq!(body, &[0; 28]);
    assert!(!protected
        .bytes
        .windows(4)
        .any(|word| word == 0xA1B2C3D4u32.to_le_bytes()));
    assert!(!protected
        .bytes
        .windows(4)
        .any(|word| word == 0xDEAD_BEEFu32.to_le_bytes()));
    assert!(claim_is(&protected.report, "image-hygiene"));
    assert_whitelist(&protected.report);
}

fn assert_sample_channel() {
    let built = sample::build().expect("sample");
    let protected = protect::protect(&built.bytes, &opts(7)).expect("sample protect");
    let image = pe::parse(&protected.bytes).expect("parse");
    let payload = image
        .sections
        .iter()
        .find(|section| section.bytes.starts_with(crypto::MAGIC))
        .expect("payload");
    assert_eq!(payload.name, protect::section_name(7));
    assert!(image
        .sections
        .iter()
        .all(|section| section.name != ".vmkek"));
    assert_no_cleartext(&protected.bytes, b".pdb");
    assert_no_cleartext(&protected.bytes, b"panicked at");
    assert_no_cleartext(&protected.bytes, b"src/stub");
    let ran = emu::run_pe(&protected.bytes, Policy::default()).expect("run");
    assert_eq!(ran.exit_code, 0, "{}", String::from_utf8_lossy(&ran.stdout));
    assert_eq!(ran.stdout, sample::line().into_bytes());
    assert!(claim_is(&protected.report, "image-hygiene"));
    assert_whitelist(&protected.report);
}

fn assert_names_follow_the_seed() {
    let image = marked_image(1);
    let left = protect::protect(&image, &opts(1)).expect("seed 1");
    let right = protect::protect(&image, &opts(2)).expect("seed 2");
    let third = protect::protect(&image, &opts(3)).expect("seed 3");
    let names = [
        name_of(&left.bytes),
        name_of(&right.bytes),
        name_of(&third.bytes),
    ];
    assert_ne!(names[0], names[1]);
    assert_ne!(names[1], names[2]);
    assert!(names.iter().all(|item| item != ".vmkek" && item.len() == 8));
    assert_ne!(timestamp(&left.bytes), timestamp(&right.bytes));
}

fn assert_elf_maps_are_sealed() {
    let mut file = vmkek::elf::sample::build().expect("elf");
    graft_maps(&mut file);
    let protected = protect::protect(&file, &opts(11)).expect("elf protect");
    assert_elf_disk_roundtrip(&protected.bytes);
    assert_loader_restores(&protected.bytes);
    let mut wiped = protected.bytes.clone();
    let off = crypto::find_header(&wiped).expect("header");
    wiped[off..off + 8].fill(0);
    let err = crypto::find_header(&wiped).expect_err("corrupt");
    assert!(err.to_string().contains("corrupt"), "{err}");
}

fn assert_elf_disk_roundtrip(bytes: &[u8]) {
    assert_ne!(&bytes[0x1F00..0x1F04], &[0, 0, 0, 0]);
    assert_ne!(&bytes[0x2E40..0x2E50], &rel_bytes());
    assert_no_cleartext(bytes, b"ElfClass");
    assert_no_cleartext(bytes, &utf16(b"ElfClass"));
    assert_no_cleartext(bytes, b"EHFRAMECLEARTEXT");
    let mut frame = bytes[0x1F00..0x1F30].to_vec();
    protect::mask_span(&mut frame, 11, 0x1F00);
    assert_eq!(&frame[..4], &[0, 0, 0, 0]);
    assert_eq!(&frame[0x10..0x20], b"EHFRAMECLEARTEXT");
    let mut rel = bytes[0x2E40..0x2E50].to_vec();
    protect::mask_span(&mut rel, 11, 0x2E40);
    assert_eq!(rel.as_slice(), &rel_bytes());
}

fn assert_loader_restores(bytes: &[u8]) {
    let path = write_elf(bytes, "maps");
    let child = std::process::Command::new(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let restored = guest_is_plain(child.id());
    let out = child.wait_with_output().expect("wait");
    assert!(restored, "sysv loader left the elf maps sealed");
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert_eq!(out.stdout, sample::line().into_bytes());
}

fn guest_is_plain(pid: u32) -> bool {
    for _ in 0..400_000 {
        if mapped_plain(pid) {
            return true;
        }
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return false;
        }
    }
    false
}

fn mapped_plain(pid: u32) -> bool {
    let Some(frame) = read_guest(pid, 0x401F00, 0x20) else {
        return false;
    };
    let Some(rel) = read_guest(pid, 0x402E40, 16) else {
        return false;
    };
    frame[..4] == [0, 0, 0, 0]
        && &frame[0x10..0x20] == b"EHFRAMECLEARTEXT"
        && rel.as_slice() == rel_bytes()
}

fn read_guest(pid: u32, addr: u64, len: usize) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    file.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn write_elf(bytes: &[u8], name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    std::fs::create_dir_all(&dir).expect("target");
    let path = dir.join(format!("t4-elf-{name}"));
    std::fs::write(&path, bytes).expect("write");
    let mut mode = std::fs::metadata(&path).expect("meta").permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        mode.set_mode(0o755);
    }
    std::fs::set_permissions(&path, mode).expect("chmod");
    path
}

fn stderr_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_seed_name_is_not_foreign(seed: u64) {
    let name = protect::section_name(seed);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(name.as_bytes());
    let outcome = protect::protect(&patch_name(&marked_image(0x1111_1111), &bytes), &opts(1));
    if let Err(err) = outcome {
        assert!(
            !err.to_string().contains("foreign packer"),
            "seed {seed} section {name}: {err}"
        );
    }
}

fn graft_maps(file: &mut Vec<u8>) {
    file[0x1F00..0x1F30].fill(0);
    file[0x1F10..0x1F20].copy_from_slice(b"EHFRAMECLEARTEXT");
    let class = b".?AVElfClass@@";
    file[0x2E00..0x2E00 + class.len()].copy_from_slice(class);
    let wide = utf16(b"ElfClass");
    file[0x2E20..0x2E20 + wide.len()].copy_from_slice(&wide);
    file[0x2E40..0x2E50].copy_from_slice(&rel_bytes());
    let mut names = vec![0u8];
    let eh = names.len() as u32;
    names.extend_from_slice(b".eh_frame\0");
    let data = names.len() as u32;
    names.extend_from_slice(b".rodata\0");
    let strtab = names.len() as u32;
    names.extend_from_slice(b".shstrtab\0");
    let str_off = file.len() as u64;
    file.extend_from_slice(&names);
    let shoff = (file.len() as u64 + 7) & !7;
    file.resize(shoff as usize, 0);
    file.extend_from_slice(&shdr(0, 0, 0, 0, 0, 0));
    file.extend_from_slice(&shdr(eh, 1, 2, 0x401F00, 0x1F00, 0x30));
    file.extend_from_slice(&shdr(data, 1, 2, 0x402E00, 0x2E00, 0x60));
    file.extend_from_slice(&shdr(strtab, 3, 0, 0, str_off, names.len() as u64));
    file[40..48].copy_from_slice(&shoff.to_le_bytes());
    file[58..60].copy_from_slice(&64u16.to_le_bytes());
    file[60..62].copy_from_slice(&4u16.to_le_bytes());
    file[62..64].copy_from_slice(&3u16.to_le_bytes());
}

fn shdr(name: u32, kind: u32, flags: u64, addr: u64, off: u64, size: u64) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..4].copy_from_slice(&name.to_le_bytes());
    out[4..8].copy_from_slice(&kind.to_le_bytes());
    out[8..16].copy_from_slice(&flags.to_le_bytes());
    out[16..24].copy_from_slice(&addr.to_le_bytes());
    out[24..32].copy_from_slice(&off.to_le_bytes());
    out[32..40].copy_from_slice(&size.to_le_bytes());
    out[48..56].copy_from_slice(&1u64.to_le_bytes());
    out
}

fn assert_sealed_unwind_stays_red() {
    let row = unwind::claims()
        .iter()
        .find(|item| item.id == "sealed-unwind")
        .expect("sealed-unwind");
    assert_eq!(row.color, ChannelColor::Red);
    assert_eq!(row.channel, "Math");
    assert_eq!(row.machine, "M-LINUX");
    assert!(row.anchor.contains("red"));
}

fn assert_sealed(image: &PeImage, rva: u32, plain: &[u8], seed: u64) {
    let got = pe::read_rva(image, rva, plain.len())
        .expect("span")
        .to_vec();
    assert_ne!(got, plain, "{rva:#x} is cleartext");
    let mut opened = got;
    protect::mask_span(&mut opened, seed, rva);
    assert_eq!(opened, plain);
}

fn assert_whitelist(report: &Report) {
    let value = serde_json::to_value(report).expect("json");
    let obj = value.as_object().expect("object");
    for key in obj.keys() {
        assert!(REPORT_FIELDS.contains(&key.as_str()), "{key}");
    }
    let text = serde_json::to_string(report).expect("text");
    for banned in [
        "\"inv\"",
        "opcode_map",
        "FuncIr",
        "aead_key",
        "\"key\"",
        "\"ir\"",
    ] {
        assert!(!text.contains(banned), "{banned} in {text}");
    }
    assert_eq!(value["report_version"], 2);
    let claims = value["claims"].as_array().expect("claims");
    assert!(!claims.is_empty());
    for claim in claims {
        assert_v2_claim(claim, &value["artifact_sha256"]);
    }
}

fn assert_v2_claim(claim: &serde_json::Value, artifact_sha256: &serde_json::Value) {
    let fields = claim.as_object().expect("claim");
    let required = [
        "pass",
        "property",
        "evidence",
        "status",
        "scope",
        "assumptions",
        "attacker",
        "subject_sha256",
        "commit",
        "artifact",
    ];
    for key in fields.keys() {
        assert!(required.contains(&key.as_str()) || key == "anchor", "{key}");
    }
    for key in required {
        assert!(fields.contains_key(key), "missing {key}");
    }
    assert_eq!(&claim["subject_sha256"], artifact_sha256);
    if !claim["artifact"].is_null() {
        let artifact = claim["artifact"].as_object().expect("evidence artifact");
        for key in artifact.keys() {
            assert!(
                ["sha256", "tool", "bounds"].contains(&key.as_str()),
                "{key}"
            );
        }
    }
}

fn claim_is(report: &Report, pass: &str) -> bool {
    report.claims.iter().any(|item| {
        item.pass == pass
            && item.claim == Claim::Proven
            && item.channel == "System"
            && item.machine == "M-EMU"
    })
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

fn marked_image(stamp: u32) -> Vec<u8> {
    let mut bytes = pe::emit(&carrier()).expect("emit");
    bytes[0x40..0x80].copy_from_slice(&b"DanS".repeat(16));
    bytes[0x70..0x74].copy_from_slice(b"Rich");
    bytes[0x88..0x8c].copy_from_slice(&stamp.to_le_bytes());
    put32(&mut bytes, 0x138, 0x2480);
    put32(&mut bytes, 0x13c, 28);
    put32(&mut bytes, 0x158, 0x2300);
    put32(&mut bytes, 0x15c, 0x98);
    bytes
}

fn carrier() -> PeImage {
    PeImage {
        image_base: IMAGE_BASE,
        entry_rva: 0x1000,
        sections: vec![
            Section {
                name: ".text".into(),
                rva: 0x1000,
                bytes: code(),
                characteristics: CH_TEXT,
            },
            Section {
                name: ".rdata".into(),
                rva: 0x2000,
                bytes: rdata(),
                characteristics: CH_RDATA,
            },
            Section {
                name: ".pdata".into(),
                rva: 0x3000,
                bytes: pdata(),
                characteristics: CH_RDATA,
            },
        ],
        exports: Vec::new(),
        imports: Vec::new(),
        export_rva: 0,
        export_size: 0,
        import_rva: 0,
        import_size: 0,
        iat_rva: 0,
        iat_size: 0,
        exception_rva: 0x3000,
        exception_size: 12,
        tls_rva: 0,
        tls_size: 0,
    }
}

fn code() -> Vec<u8> {
    let disp: i32 = 0x2000 - (0x1000 + 7);
    let mut bytes = vec![0x48, 0x8b, 0x05];
    bytes.extend(disp.to_le_bytes());
    bytes.push(0xc3);
    bytes
}

fn rdata() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x500];
    bytes[..8].copy_from_slice(&POOL);
    bytes[0x20..0x30].copy_from_slice(&table_bytes());
    bytes[0x220..0x230].copy_from_slice(&rel_bytes());
    bytes[0x100..0x100 + CLASS.len()].copy_from_slice(CLASS);
    bytes[0x140..0x140 + b"SecretClass".len()].copy_from_slice(b"SecretClass");
    let wide = utf16(b"SecretClass");
    bytes[0x180..0x180 + wide.len()].copy_from_slice(&wide);
    write_guard(&mut bytes);
    bytes[0x400..0x410].copy_from_slice(&table_bytes());
    bytes[0x480..0x49c].copy_from_slice(&debug_body());
    bytes[0x4b0..0x4b4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let debug_text = br"RSDS C:\o.pdb panicked at src/stub/mod.rs";
    bytes[0x4b4..0x4b4 + debug_text.len()].copy_from_slice(debug_text);
    bytes
}

fn write_guard(bytes: &mut [u8]) {
    let table = IMAGE_BASE + 0x2400;
    bytes[0x300 + 0x80..0x300 + 0x88].copy_from_slice(&table.to_le_bytes());
    bytes[0x300 + 0x88..0x300 + 0x90].copy_from_slice(&4u64.to_le_bytes());
}

fn rel_bytes() -> [u8; 16] {
    let mut out = [0u8; 16];
    for (index, value) in [1u32, 2, 3, 4].into_iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    out
}

fn debug_body() -> [u8; 28] {
    let mut out = [0u8; 28];
    out[4..8].copy_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    out[12..16].copy_from_slice(&2u32.to_le_bytes());
    out[16..20].copy_from_slice(&64u32.to_le_bytes());
    out[20..24].copy_from_slice(&0x24B0u32.to_le_bytes());
    out
}

fn table_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for index in 0..4 {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    }
    bytes
}

fn pdata() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(0x1000u32.to_le_bytes());
    bytes.extend(0x1008u32.to_le_bytes());
    bytes.extend(0x300cu32.to_le_bytes());
    bytes.extend([0x01, 0x04, 0x01, 0x00, 0x04, 0x30]);
    bytes
}

fn utf16(text: &[u8]) -> Vec<u8> {
    text.iter().flat_map(|byte| [*byte, 0]).collect()
}

fn open_pdata(image: &mut PeImage, seed: u64) {
    let pdata = image
        .sections
        .iter_mut()
        .find(|section| section.name == ".pdata")
        .expect(".pdata");
    protect::mask_span(&mut pdata.bytes, seed, pdata.rva);
}

fn err(bytes: &[u8]) -> String {
    protect::protect(bytes, &opts(1))
        .expect_err("rejected")
        .to_string()
}

fn patch_machine(bytes: &[u8], machine: u16) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    out
}

fn patch_magic(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes());
    out
}

fn patch_clr(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    put32(&mut out, 0x178, 0x2000);
    put32(&mut out, 0x17c, 0x48);
    out
}

fn patch_upx(bytes: &[u8]) -> Vec<u8> {
    patch_name(bytes, b"UPX0\0\0\0\0")
}

fn patch_name(bytes: &[u8], name: &[u8; 8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[0x188..0x190].copy_from_slice(name);
    out
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn timestamp(bytes: &[u8]) -> u32 {
    let lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    u32::from_le_bytes(bytes[lfanew + 8..lfanew + 12].try_into().unwrap())
}

fn debug_dir(bytes: &[u8]) -> (u32, u32) {
    let lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let at = lfanew + 24 + 112 + 6 * 8;
    let rva = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
    (rva, size)
}

fn name_of(bytes: &[u8]) -> String {
    pe::parse(bytes)
        .expect("parse")
        .sections
        .into_iter()
        .find(|section| section.bytes.starts_with(crypto::MAGIC))
        .expect("payload")
        .name
}

fn assert_no_cleartext(bytes: &[u8], needle: &[u8]) {
    assert!(
        bytes.windows(needle.len()).all(|window| window != needle),
        "{}",
        String::from_utf8_lossy(needle)
    );
}
