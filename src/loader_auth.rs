//! Windows startup verification through the original image's ordinary CNG imports.

use iced_x86::code_asm::*;
use iced_x86::{BlockEncoderOptions, Code, Instruction, MemoryOperand, Register};

use crate::crypto::authenticated::{
    BOOTSTRAP_CORE_LEN, BOOTSTRAP_HASH_OFFSET, BOOTSTRAP_MAX_PAYLOAD, BOOTSTRAP_NONCE_OFFSET,
    BOOTSTRAP_SIGNATURE_DOMAIN, BOOTSTRAP_SIGNATURE_OFFSET, BOOTSTRAP_TAG_OFFSET,
};
use crate::error::{msg, Result};
use crate::pe::{self, PeImage};

use super::{emit_image_address, step};

const SHA256: u32 = 0x41;
const ECDSA_P256: u32 = 0x2e1;
const CHACHA20_POLY1305: u32 = 0x3a1;
const ECC_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;
const ECC_BLOB_LEN: usize = 72;
const DIGEST_LEN: i32 = 32;
const SIGNATURE_LEN: i32 = 64;

// Win64 outgoing argument area, followed by verifier-local storage.
const DIGEST: i32 = 0x58;
const KEY_HANDLE: i32 = 0x78;
const OUTPUT_LEN: i32 = 0x80;
const STATUS: i32 = 0x84;
const AUTH_INFO: i32 = 0x88;
const AUTH_INFO_LEN: i32 = 88;
const TRANSCRIPT: i32 = AUTH_INFO + AUTH_INFO_LEN;
const TRANSCRIPT_LEN: usize = BOOTSTRAP_SIGNATURE_DOMAIN.len() + BOOTSTRAP_SIGNATURE_OFFSET;
const FRAME_SIZE: i32 = 0x208;
const CORRUPT: u32 = 0xbad1;
const _: () = assert!(TRANSCRIPT as usize + TRANSCRIPT_LEN <= FRAME_SIZE as usize);

const IMPORTS: [&str; 6] = [
    "BCryptHash",
    "BCryptImportKeyPair",
    "BCryptVerifySignature",
    "BCryptGenerateSymmetricKey",
    "BCryptDecrypt",
    "BCryptDestroyKey",
];

/// Calls are bound to ordinary IAT slots already present in the source PE.
#[derive(Clone, Copy)]
pub(crate) struct AuthImports {
    hash: u64,
    import_key_pair: u64,
    verify_signature: u64,
    generate_symmetric_key: u64,
    decrypt: u64,
    destroy_key: u64,
}

impl AuthImports {
    pub(crate) fn read(image: &PeImage) -> Result<Self> {
        let iat_end = image
            .iat_rva
            .checked_add(image.iat_size)
            .ok_or_else(|| msg("PE IAT directory overflows"))?;
        let mut slots = [0; IMPORTS.len()];
        for (slot, name) in slots.iter_mut().zip(IMPORTS) {
            let mut matches = image
                .imports
                .iter()
                .filter(|item| item.dll.eq_ignore_ascii_case("bcrypt.dll") && item.name == name);
            let import = matches.next().ok_or_else(|| {
                msg(format!(
                    "authenticated PE startup requires bcrypt.dll!{name}"
                ))
            })?;
            let in_directory = image.iat_rva != 0
                && import.iat_rva >= image.iat_rva
                && import
                    .iat_rva
                    .checked_add(8)
                    .is_some_and(|end| end <= iat_end);
            if matches.next().is_some() || !in_directory || !import.iat_rva.is_multiple_of(8) {
                return Err(msg(format!("invalid bcrypt.dll IAT slot for {name}")));
            }
            pe::read_rva(image, import.iat_rva, 8)?;
            *slot = image
                .image_base
                .checked_add(u64::from(import.iat_rva))
                .ok_or_else(|| msg("bcrypt.dll IAT address overflows"))?;
        }
        let mut sorted = slots;
        sorted.sort_unstable();
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(msg("bcrypt.dll IAT entries overlap"));
        }
        let [hash, import_key_pair, verify_signature, generate_symmetric_key, decrypt, destroy_key] =
            slots;
        Ok(Self {
            hash,
            import_key_pair,
            verify_signature,
            generate_symmetric_key,
            decrypt,
            destroy_key,
        })
    }
}

/// Addresses come from the validated PE layout. No manifest field supplies a pointer.
pub(crate) struct StartupAuth<'a> {
    pub(crate) origin: u64,
    pub(crate) manifest: u64,
    pub(crate) payload: u64,
    pub(crate) payload_len: u32,
    pub(crate) key: u64,
    pub(crate) imports: AuthImports,
    pub(crate) expected_core: &'a [u8; BOOTSTRAP_CORE_LEN],
    pub(crate) trusted_public: &'a [u8; 65],
}

pub(crate) struct AuthCode {
    pub(crate) bytes: Vec<u8>,
    pub(crate) executable_len: u32,
    pub(crate) unwind: [u8; 8],
}

/// Assemble a Win64 function returning zero on success and CORRUPT on rejection.
/// The caller must provide 32 bytes of shadow space and publish the unwind record.
pub(crate) fn assemble(plan: &StartupAuth<'_>) -> Result<AuthCode> {
    if plan.payload_len == 0 || plan.payload_len as usize > BOOTSTRAP_MAX_PAYLOAD {
        return Err(msg("invalid authenticated PE startup payload extent"));
    }
    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut reject = a.create_label();
    let mut prologue = a.create_label();
    let mut end = a.create_label();
    let mut expected = a.create_label();
    let mut domain = a.create_label();
    let mut blob_type = a.create_label();
    let mut public = a.create_label();

    step(a.sub(rsp, FRAME_SIZE))?;
    step(a.set_label(&mut prologue))?;
    emit_image_address(&mut a, Register::R10, plan.manifest)?;
    step(a.lea(r11, qword_ptr(expected)))?;
    compare(&mut a, BOOTSTRAP_CORE_LEN, reject)?;
    signature(&mut a, plan, domain, blob_type, public, reject)?;
    ciphertext_hash(&mut a, plan, reject)?;
    open(&mut a, plan, reject)?;
    step(a.xor(eax, eax))?;
    step(a.add(rsp, FRAME_SIZE))?;
    step(a.ret())?;
    step(a.set_label(&mut reject))?;
    step(a.mov(eax, CORRUPT))?;
    step(a.add(rsp, FRAME_SIZE))?;
    step(a.ret())?;

    step(a.set_label(&mut end))?;
    step(a.db(&[0]))?;
    step(a.set_label(&mut expected))?;
    step(a.db(plan.expected_core))?;
    step(a.set_label(&mut domain))?;
    step(a.db(BOOTSTRAP_SIGNATURE_DOMAIN))?;
    step(a.set_label(&mut blob_type))?;
    for unit in "ECCPUBLICBLOB\0".encode_utf16() {
        step(a.dw(&[unit]))?;
    }
    step(a.set_label(&mut public))?;
    let mut blob = [0; ECC_BLOB_LEN];
    blob[..4].copy_from_slice(&ECC_PUBLIC_P256_MAGIC.to_le_bytes());
    blob[4..8].copy_from_slice(&(DIGEST_LEN as u32).to_le_bytes());
    blob[8..].copy_from_slice(&plan.trusted_public[1..]);
    step(a.db(&blob))?;
    let encoded = a
        .assemble_options(
            plan.origin,
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )
        .map_err(|err| msg(err.to_string()))?;
    let offset = |label| -> Result<u64> {
        encoded
            .label_ip(label)
            .map(|ip| ip - plan.origin)
            .map_err(|err| msg(err.to_string()))
    };
    let prologue = u8::try_from(offset(&prologue)?).map_err(|_| msg("PE prologue too large"))?;
    let executable_len =
        u32::try_from(offset(&end)?).map_err(|_| msg("PE verifier code too large"))?;
    // Version 1, UWOP_ALLOC_LARGE opinfo 0, with one following 8-byte count slot.
    let [lo, hi] = ((FRAME_SIZE / 8) as u16).to_le_bytes();
    Ok(AuthCode {
        bytes: encoded.inner.code_buffer,
        executable_len,
        unwind: [1, prologue, 2, 0, prologue, 1, lo, hi],
    })
}

fn compare(a: &mut CodeAssembler, count: usize, reject: CodeLabel) -> Result<()> {
    let mut next = a.create_label();
    step(a.mov(eax, count as u32))?;
    step(a.set_label(&mut next))?;
    step(a.mov(dl, byte_ptr(r10)))?;
    step(a.cmp(dl, byte_ptr(r11)))?;
    step(a.jne(reject))?;
    step(a.inc(r10))?;
    step(a.inc(r11))?;
    step(a.dec(eax))?;
    step(a.jnz(next))
}

fn copy(a: &mut CodeAssembler, count: usize) -> Result<()> {
    let mut next = a.create_label();
    step(a.mov(eax, count as u32))?;
    step(a.set_label(&mut next))?;
    step(a.mov(dl, byte_ptr(r10)))?;
    step(a.mov(byte_ptr(r11), dl))?;
    step(a.inc(r10))?;
    step(a.inc(r11))?;
    step(a.dec(eax))?;
    step(a.jnz(next))
}

fn call(a: &mut CodeAssembler, slot: u64) -> Result<()> {
    let operand = MemoryOperand::with_base_displ(Register::RIP, slot as i64);
    let instruction =
        Instruction::with1(Code::Call_rm64, operand).map_err(|err| msg(err.to_string()))?;
    step(a.add_instruction(instruction))
}

fn reject_status(a: &mut CodeAssembler, reject: CodeLabel) -> Result<()> {
    step(a.test(eax, eax))?;
    step(a.js(reject))
}

fn hash(a: &mut CodeAssembler, slot: u64, length: usize, reject: CodeLabel) -> Result<()> {
    // r9 is pbInput. SHA256 is a provider pseudo-handle.
    step(a.mov(ecx, SHA256))?;
    step(a.xor(edx, edx))?;
    step(a.xor(r8d, r8d))?;
    step(a.mov(qword_ptr(rsp + 0x20i32), length as i32))?;
    step(a.lea(rax, qword_ptr(rsp + DIGEST)))?;
    step(a.mov(qword_ptr(rsp + 0x28i32), rax))?;
    step(a.mov(qword_ptr(rsp + 0x30i32), DIGEST_LEN))?;
    call(a, slot)?;
    reject_status(a, reject)
}

fn signature(
    a: &mut CodeAssembler,
    plan: &StartupAuth<'_>,
    domain: CodeLabel,
    blob_type: CodeLabel,
    public: CodeLabel,
    reject: CodeLabel,
) -> Result<()> {
    step(a.lea(r10, qword_ptr(domain)))?;
    step(a.lea(r11, qword_ptr(rsp + TRANSCRIPT)))?;
    copy(a, BOOTSTRAP_SIGNATURE_DOMAIN.len())?;
    emit_image_address(a, Register::R10, plan.manifest)?;
    copy(a, BOOTSTRAP_SIGNATURE_OFFSET)?;
    step(a.lea(r9, qword_ptr(rsp + TRANSCRIPT)))?;
    hash(a, plan.imports.hash, TRANSCRIPT_LEN, reject)?;

    step(a.mov(ecx, ECDSA_P256))?;
    step(a.xor(edx, edx))?;
    step(a.lea(r8, qword_ptr(blob_type)))?;
    step(a.lea(r9, qword_ptr(rsp + KEY_HANDLE)))?;
    step(a.lea(rax, qword_ptr(public)))?;
    step(a.mov(qword_ptr(rsp + 0x20i32), rax))?;
    step(a.mov(qword_ptr(rsp + 0x28i32), ECC_BLOB_LEN as i32))?;
    step(a.mov(qword_ptr(rsp + 0x30i32), 0i32))?;
    call(a, plan.imports.import_key_pair)?;
    reject_status(a, reject)?;

    step(a.mov(rcx, qword_ptr(rsp + KEY_HANDLE)))?;
    step(a.xor(edx, edx))?;
    step(a.lea(r8, qword_ptr(rsp + DIGEST)))?;
    step(a.mov(r9d, DIGEST_LEN))?;
    emit_image_address(
        a,
        Register::RAX,
        plan.manifest + BOOTSTRAP_SIGNATURE_OFFSET as u64,
    )?;
    step(a.mov(qword_ptr(rsp + 0x20i32), rax))?;
    step(a.mov(qword_ptr(rsp + 0x28i32), SIGNATURE_LEN))?;
    step(a.mov(qword_ptr(rsp + 0x30i32), 0i32))?;
    call(a, plan.imports.verify_signature)?;
    destroy(a, plan.imports.destroy_key, reject)
}

fn ciphertext_hash(a: &mut CodeAssembler, plan: &StartupAuth<'_>, reject: CodeLabel) -> Result<()> {
    emit_image_address(a, Register::R9, plan.payload)?;
    hash(a, plan.imports.hash, plan.payload_len as usize, reject)?;
    step(a.lea(r10, qword_ptr(rsp + DIGEST)))?;
    emit_image_address(
        a,
        Register::R11,
        plan.manifest + BOOTSTRAP_HASH_OFFSET as u64,
    )?;
    compare(a, DIGEST_LEN as usize, reject)
}

fn open(a: &mut CodeAssembler, plan: &StartupAuth<'_>, reject: CodeLabel) -> Result<()> {
    step(a.mov(ecx, CHACHA20_POLY1305))?;
    step(a.lea(rdx, qword_ptr(rsp + KEY_HANDLE)))?;
    step(a.xor(r8d, r8d))?;
    step(a.xor(r9d, r9d))?;
    emit_image_address(a, Register::RAX, plan.key)?;
    step(a.mov(qword_ptr(rsp + 0x20i32), rax))?;
    step(a.mov(qword_ptr(rsp + 0x28i32), 32i32))?;
    step(a.mov(qword_ptr(rsp + 0x30i32), 0i32))?;
    call(a, plan.imports.generate_symmetric_key)?;
    reject_status(a, reject)?;

    auth_info(a, plan)?;
    step(a.mov(rcx, qword_ptr(rsp + KEY_HANDLE)))?;
    emit_image_address(a, Register::RDX, plan.payload)?;
    step(a.mov(r8d, plan.payload_len))?;
    step(a.lea(r9, qword_ptr(rsp + AUTH_INFO)))?;
    step(a.mov(qword_ptr(rsp + 0x20i32), 0i32))?;
    step(a.mov(qword_ptr(rsp + 0x28i32), 0i32))?;
    step(a.mov(qword_ptr(rsp + 0x30i32), rdx))?;
    step(a.mov(qword_ptr(rsp + 0x38i32), plan.payload_len as i32))?;
    step(a.lea(rax, qword_ptr(rsp + OUTPUT_LEN)))?;
    step(a.mov(qword_ptr(rsp + 0x40i32), rax))?;
    step(a.mov(qword_ptr(rsp + 0x48i32), 0i32))?;
    call(a, plan.imports.decrypt)?;
    destroy(a, plan.imports.destroy_key, reject)?;
    step(a.mov(r10d, plan.payload_len))?;
    step(a.cmp(dword_ptr(rsp + OUTPUT_LEN), r10d))?;
    step(a.jne(reject))
}

fn auth_info(a: &mut CodeAssembler, plan: &StartupAuth<'_>) -> Result<()> {
    step(a.xor(eax, eax))?;
    for offset in (0..AUTH_INFO_LEN).step_by(8) {
        step(a.mov(qword_ptr(rsp + AUTH_INFO + offset), rax))?;
    }
    step(a.mov(dword_ptr(rsp + AUTH_INFO), AUTH_INFO_LEN))?;
    step(a.mov(dword_ptr(rsp + AUTH_INFO + 4i32), 1i32))?;
    for (address, offset, length) in [
        (plan.manifest + BOOTSTRAP_NONCE_OFFSET as u64, 8, 12),
        (plan.manifest, 24, BOOTSTRAP_CORE_LEN as i32),
        (plan.manifest + BOOTSTRAP_TAG_OFFSET as u64, 40, 16),
    ] {
        emit_image_address(a, Register::RAX, address)?;
        step(a.mov(qword_ptr(rsp + AUTH_INFO + offset), rax))?;
        step(a.mov(dword_ptr(rsp + AUTH_INFO + offset + 8i32), length))?;
    }
    Ok(())
}

fn destroy(a: &mut CodeAssembler, slot: u64, reject: CodeLabel) -> Result<()> {
    step(a.mov(dword_ptr(rsp + STATUS), eax))?;
    step(a.mov(rcx, qword_ptr(rsp + KEY_HANDLE)))?;
    call(a, slot)?;
    reject_status(a, reject)?;
    step(a.mov(eax, dword_ptr(rsp + STATUS)))?;
    reject_status(a, reject)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::authenticated::BOOTSTRAP_MAGIC;
    use crate::pe::{Section, CH_DATA, CH_TEXT, IMAGE_BASE};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    const TEXT: u32 = 0x1000;
    const IMPORT: u32 = 0x2000;

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn section(name: &str, rva: u32, bytes: Vec<u8>, characteristics: u32) -> Section {
        Section {
            name: name.into(),
            rva,
            bytes,
            characteristics,
        }
    }

    fn fixture(marker: u8) -> PeImage {
        let mut idata = vec![0; 0x300];
        write_u32(&mut idata, 0, IMPORT + 0x40);
        write_u32(&mut idata, 12, IMPORT + 0xb0);
        write_u32(&mut idata, 16, IMPORT + 0x80);
        idata[0xb0..0xbb].copy_from_slice(b"bcrypt.dll\0");
        for (index, name) in IMPORTS.into_iter().enumerate() {
            let offset = 0xc0 + index * 0x30;
            write_u32(&mut idata, 0x40 + index * 8, IMPORT + offset as u32);
            write_u32(&mut idata, 0x80 + index * 8, IMPORT + offset as u32);
            idata[offset + 2..offset + 2 + name.len()].copy_from_slice(name.as_bytes());
        }
        let mut code = vec![0xb8, marker, 0, 0, 0];
        code.resize(64, 0x90);
        code.push(0xc3);
        PeImage {
            image_base: IMAGE_BASE,
            entry_rva: TEXT,
            sections: vec![
                section(".text", TEXT, code, CH_TEXT),
                section(".idata", IMPORT, idata, CH_DATA),
            ],
            exports: Vec::new(),
            imports: Vec::new(),
            export_rva: 0,
            export_size: 0,
            import_rva: IMPORT,
            import_size: 40,
            iat_rva: IMPORT + 0x80,
            iat_size: (IMPORTS.len() as u32 + 1) * 8,
            exception_rva: 0,
            exception_size: 0,
            tls_rva: 0,
            tls_size: 0,
        }
    }

    fn protect(input: &[u8], signing: &SigningKey, public: &[u8; 65]) -> crate::protect::Protected {
        let options = crate::protect::Options {
            virtualize: Default::default(),
            mutate: Default::default(),
            virtualize_all: true,
            mutate_all: false,
            seed: 0x702,
            random_key: false,
            debug_seed: true,
        };
        crate::protect::protect_windows_native_authenticated(
            input,
            &options,
            &crate::protect::NativeAuthentication {
                signing_key: signing,
                trusted_public: public,
                application_id: [1; 16],
            },
        )
        .unwrap()
    }

    fn reentry_source() -> (Vec<u8>, usize) {
        let mut image = fixture(0x11);
        let text = &mut image.sections[0].bytes;
        text.resize(0x400, 0xcc);
        // The native callback clears the recursion flag and calls the protected function again.
        text[0x220..0x227].copy_from_slice(&[0x33, 0xd2, 0xe9, 0x0d, 0, 0, 0]);
        let body = [
            0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xd9, 0x48, 0x85, 0xd2, 0x74, 0x0e,
            0x48, 0x83, 0xc1, 0x05, 0xe8, 0xd5, 0xff, 0xff, 0xff, 0x48, 0x03, 0xc3, 0xeb, 0x08,
            0x48, 0x6b, 0xc3, 0x07, 0x48, 0x83, 0xc0, 0x0b, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3,
        ];
        text[0x234..0x234 + body.len()].copy_from_slice(&body);
        image.entry_rva = 0x1300;
        let mut entry = CodeAssembler::new(64).unwrap();
        let mut fail = entry.create_label();
        entry.sub(rsp, 0x28i32).unwrap();
        for _ in 0..3 {
            entry.xor(ecx, ecx).unwrap();
            entry.mov(edx, 1u32).unwrap();
            entry.call(IMAGE_BASE + 0x1234).unwrap();
            entry.cmp(eax, 46i32).unwrap();
            entry.jne(fail).unwrap();
        }
        entry.add(rsp, 0x28i32).unwrap();
        entry.ret().unwrap();
        entry.set_label(&mut fail).unwrap();
        entry.mov(eax, 0xeeu32).unwrap();
        entry.add(rsp, 0x28i32).unwrap();
        entry.ret().unwrap();
        let code = entry.assemble(IMAGE_BASE + 0x1300).unwrap();
        text[0x300..0x300 + code.len()].copy_from_slice(&code);
        (pe::emit(&image).unwrap(), body.len())
    }

    fn write_reentry_fixture(dir: &std::path::Path, signing: &SigningKey, public: &[u8; 65]) {
        let (original, body_len) = reentry_source();
        let options = crate::protect::Options {
            virtualize: [format!("rva:1234+{body_len:x}")].into(),
            mutate: Default::default(),
            virtualize_all: false,
            mutate_all: false,
            seed: 7,
            random_key: false,
            debug_seed: false,
        };
        let protected = crate::protect::protect_windows_native_authenticated(
            &original,
            &options,
            &crate::protect::NativeAuthentication {
                signing_key: signing,
                trusted_public: public,
                application_id: [1; 16],
            },
        )
        .unwrap();
        std::fs::write(dir.join("r02-reentry-original.exe"), original).unwrap();
        std::fs::write(dir.join("r02-reentry-protected.exe"), protected.bytes).unwrap();
    }

    fn artifact_offsets(bytes: &[u8]) -> (usize, usize) {
        let image = pe::parse(bytes).unwrap();
        let manifest_rva = image.entry_rva - crate::crypto::HEADER_LEN as u32;
        let containing = |rva| {
            image
                .sections
                .iter()
                .find(|section| {
                    rva >= section.rva && rva - section.rva < section.bytes.len() as u32
                })
                .unwrap()
        };
        let manifest_section = containing(manifest_rva);
        let manifest = pe::section_file_offset(bytes, &manifest_section.name).unwrap();
        assert_eq!(&bytes[manifest..manifest + 16], BOOTSTRAP_MAGIC);
        let payload_rva =
            u64::from_le_bytes(bytes[manifest + 90..manifest + 98].try_into().unwrap()) as u32;
        let payload_section = containing(payload_rva);
        let payload = pe::section_file_offset(bytes, &payload_section.name).unwrap()
            + (payload_rva - payload_section.rva) as usize;
        assert_eq!(payload_section.characteristics, CH_DATA);
        assert_eq!(manifest_section.characteristics, CH_TEXT);
        assert!(image.exception_size >= 24);
        (manifest, payload)
    }

    #[test]
    fn authenticating_pe_fixture() {
        let original = pe::emit(&fixture(0x11)).unwrap();
        let signing = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let public: [u8; 65] = signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        let protected = protect(&original, &signing, &public);
        let alternate = protect(&pe::emit(&fixture(0x12)).unwrap(), &signing, &public);
        let clean = protected.bytes;
        let (manifest, payload) = artifact_offsets(&clean);
        let (alternate_manifest, alternate_payload) = artifact_offsets(&alternate.bytes);
        assert_ne!(
            &clean[manifest + 72..manifest + 88],
            &alternate.bytes[alternate_manifest + 72..alternate_manifest + 88]
        );
        assert_ne!(
            &clean[payload..payload + 32],
            &alternate.bytes[alternate_payload..alternate_payload + 32]
        );
        assert!(!clean.windows(32).any(|bytes| bytes == [0x42; 32]));
        assert!(!serde_json::to_string(&protected.report)
            .unwrap()
            .contains(&"42".repeat(32)));

        let Some(dir) = std::env::var_os("VMKEK_R02_WIN_LAB") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        std::fs::write(dir.join("r02-original.exe"), &original).unwrap();
        std::fs::write(dir.join("r02-clean.exe"), &clean).unwrap();
        std::fs::write(dir.join("r02-clean-alt.exe"), alternate.bytes).unwrap();
        for (name, offset) in [
            ("r02-version.exe", manifest + 16),
            ("r02-metadata.exe", manifest + 98),
            ("r02-signature.exe", manifest + BOOTSTRAP_SIGNATURE_OFFSET),
            ("r02-ciphertext.exe", payload),
            ("r02-tag.exe", manifest + BOOTSTRAP_TAG_OFFSET),
            (
                "r02-key.exe",
                manifest + crate::crypto::HEADER_LEN + super::super::LOADER_KEY_OFF,
            ),
        ] {
            let mut bytes = clean.clone();
            bytes[offset] ^= 1;
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        let mut bad_tag = clean;
        bad_tag[manifest + BOOTSTRAP_TAG_OFFSET] ^= 1;
        let mut transcript = BOOTSTRAP_SIGNATURE_DOMAIN.to_vec();
        transcript.extend_from_slice(&bad_tag[manifest..manifest + BOOTSTRAP_SIGNATURE_OFFSET]);
        let sig: Signature = signing.sign(&transcript);
        bad_tag[manifest + BOOTSTRAP_SIGNATURE_OFFSET..manifest + BOOTSTRAP_SIGNATURE_OFFSET + 64]
            .copy_from_slice(&sig.to_bytes());
        std::fs::write(dir.join("r02-signed-bad-tag.exe"), bad_tag).unwrap();
        write_reentry_fixture(&dir, &signing, &public);
    }
}
