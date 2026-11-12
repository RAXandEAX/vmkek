//! Native PE32+ driver image (`.sys`).
//!
//! `protect` accepts the owner's driver and emits the same passes it uses for a
//! console image: lift of functions the lifter already proves, a trampoline at
//! the driver entry, and `ntoskrnl` imports stored by hash with the plaintext
//! names removed. The PE subsystem stays `IMAGE_SUBSYSTEM_NATIVE`.
//!
//! This stage does not hook system tables, hide processes or threads, disable
//! kernel protection, or bypass driver signing. The System channel on M-KERN
//! stays red until that machine exists. Closing it is stage K2.

use iced_x86::code_asm::*;

use crate::error::{msg, Result};
use crate::pe::{self, ImageKind, PeImage, Section, CH_RDATA, CH_TEXT, IMAGE_BASE};

/// `IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL`.
pub const DRIVER_CHARACTERISTICS: u16 = 0x2022;
/// `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` only. `DYNAMIC_BASE` and `HIGH_ENTROPY_VA`
/// need a relocation directory this emitter does not write.
pub const DRIVER_DLL_CHARACTERISTICS: u16 = 0x0100;
/// Import DLL of a kernel driver. The protected image does not keep this text.
pub const NTOSKRNL: &str = "ntoskrnl.exe";
/// One `ntoskrnl` import the owner's image is allowed to name before protection.
pub const IMPORTED: &str = "DbgPrint";

const ENTRY_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;

/// Green means the named test passed on this machine. Red means the channel was not run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelColor {
    Green,
    Red,
}

/// One K1 proof row. Not a `proof::PassClaim`: that registry is shared with other stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverClaim {
    pub id: &'static str,
    pub channel: &'static str,
    pub machine: &'static str,
    pub color: ChannelColor,
    pub anchor: &'static str,
}

/// Local claim table for K1. The only System row is red: M-KERN is not provisioned.
#[must_use]
pub fn claims() -> &'static [DriverClaim] {
    const CLAIMS: &[DriverClaim] = &[DriverClaim {
        id: "laboratory-ioctl",
        channel: "System",
        machine: crate::isa::census::Machine::MKern.as_str(),
        color: ChannelColor::Red,
        anchor: "M-KERN is not provisioned; the laboratory IOCTL is not executed",
    }];
    CLAIMS
}

/// Minimal PE32+ native image: one liftable driver entry and one `ntoskrnl` import.
pub fn minimal_sys() -> Result<Vec<u8>> {
    let code = driver_entry()?;
    let data = rdata();
    let image = PeImage {
        image_base: IMAGE_BASE,
        entry_rva: ENTRY_RVA,
        sections: vec![
            Section {
                name: ".text".into(),
                rva: ENTRY_RVA,
                bytes: code,
                characteristics: CH_TEXT,
            },
            Section {
                name: ".rdata".into(),
                rva: RDATA_RVA,
                bytes: data.bytes,
                characteristics: CH_RDATA,
            },
        ],
        exports: Vec::new(),
        imports: vec![pe::Import {
            dll: NTOSKRNL.into(),
            name: IMPORTED.into(),
            iat_rva: data.iat_rva,
            name_rva: data.name_rva,
            dll_rva: data.dll_rva,
        }],
        export_rva: 0,
        export_size: 0,
        import_rva: data.import_rva,
        import_size: data.import_size,
        iat_rva: data.iat_rva,
        iat_size: data.iat_size,
        exception_rva: 0,
        exception_size: 0,
        tls_rva: 0,
        tls_size: 0,
    };
    let mut bytes = pe::emit(&image)?;
    pe::set_image_kind(&mut bytes, &driver_kind())?;
    Ok(bytes)
}

/// Parse and emit `bytes`, then restore the COFF identity [`pe::emit`] drops.
/// Calling this twice is the circular image test.
pub fn roundtrip(bytes: &[u8]) -> Result<Vec<u8>> {
    let kind = pe::image_kind(bytes)?;
    let image = pe::parse(bytes)?;
    let mut out = pe::emit(&image)?;
    pe::set_image_kind(&mut out, &kind)?;
    keep_stamp(bytes, &mut out);
    Ok(out)
}

fn keep_stamp(from: &[u8], to: &mut [u8]) {
    let Some(at) = coff_stamp(from) else {
        return;
    };
    if at + 4 <= to.len() {
        to[at..at + 4].copy_from_slice(&from[at..at + 4]);
    }
}

fn coff_stamp(bytes: &[u8]) -> Option<usize> {
    let lfanew = u32::from_le_bytes(bytes.get(0x3c..0x40)?.try_into().ok()?) as usize;
    let at = lfanew.checked_add(8)?;
    bytes.get(at..at + 4)?;
    Some(at)
}

fn driver_kind() -> ImageKind {
    ImageKind {
        characteristics: DRIVER_CHARACTERISTICS,
        subsystem: pe::SUBSYSTEM_NATIVE,
        dll_characteristics: DRIVER_DLL_CHARACTERISTICS,
    }
}

fn driver_entry() -> Result<Vec<u8>> {
    let mut asm = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    step(asm.xor(eax, eax))?;
    step(asm.nop())?;
    step(asm.nop())?;
    step(asm.nop())?;
    step(asm.ret())?;
    let bytes = asm
        .assemble(IMAGE_BASE + u64::from(ENTRY_RVA))
        .map_err(|err| msg(err.to_string()))?;
    if bytes.len() < 5 {
        return Err(msg("driver entry is too small for a trampoline"));
    }
    Ok(bytes)
}

struct ImportLayout {
    bytes: Vec<u8>,
    import_rva: u32,
    import_size: u32,
    iat_rva: u32,
    iat_size: u32,
    name_rva: u32,
    dll_rva: u32,
}

fn rdata() -> ImportLayout {
    let mut bytes = vec![0u8; 0x100];
    let base = RDATA_RVA;
    let desc = 0usize;
    let ilt = 0x40usize;
    let dll = 0x80usize;
    let iat = 0xa0usize;
    let hint = 0xc0usize;
    put32(&mut bytes, desc, base + ilt as u32);
    put32(&mut bytes, desc + 12, base + dll as u32);
    put32(&mut bytes, desc + 16, base + iat as u32);
    let hint_rva = base + hint as u32;
    put32(&mut bytes, ilt, hint_rva);
    put32(&mut bytes, iat, hint_rva);
    bytes[dll..dll + NTOSKRNL.len()].copy_from_slice(NTOSKRNL.as_bytes());
    bytes[hint + 2..hint + 2 + IMPORTED.len()].copy_from_slice(IMPORTED.as_bytes());
    ImportLayout {
        bytes,
        import_rva: base,
        import_size: 40,
        iat_rva: base + iat as u32,
        iat_size: 8,
        name_rva: hint_rva + 2,
        dll_rva: base + dll as u32,
    }
}

fn put32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn step(result: std::result::Result<(), IcedError>) -> Result<()> {
    result.map_err(|err| msg(err.to_string()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::protect::{self, Options};

    const PIPELINE: &[&str] = &[
        "trampoline",
        "import-hash",
        "opcode-polymorph",
        "bytecode-encrypt",
        "per-instruction-stream",
        "vm-equivalence",
        "layout-stealth",
        "integrity-cookies",
        "fail-closed-handlers",
        "anti-debug",
        "aead-runtime",
        "aead-inspect",
        "crc32",
        "sha256",
        "ecdsa-p256",
    ];

    fn options(seed: u64) -> Options {
        Options {
            virtualize: BTreeSet::new(),
            mutate: BTreeSet::new(),
            virtualize_all: true,
            mutate_all: false,
            seed,
            random_key: false,
            debug_seed: false,
        }
    }

    fn contains(bytes: &[u8], text: &str) -> bool {
        bytes
            .windows(text.len())
            .any(|window| window == text.as_bytes())
    }

    #[test]
    fn minimal_sys_roundtrip_keeps_the_driver_image() {
        let bytes = minimal_sys().unwrap();
        let kind = pe::image_kind(&bytes).unwrap();
        assert_eq!(kind, driver_kind());
        assert_eq!(kind.subsystem, pe::SUBSYSTEM_NATIVE);
        let image = pe::parse(&bytes).unwrap();
        assert_eq!(image.entry_rva, ENTRY_RVA);
        assert_eq!(image.imports.len(), 1);
        assert_eq!(image.imports[0].dll, NTOSKRNL);
        assert_eq!(image.imports[0].name, IMPORTED);
        assert!(contains(&bytes, NTOSKRNL));
        assert!(contains(&bytes, IMPORTED));
        let once = roundtrip(&bytes).unwrap();
        assert_eq!(once, bytes);
        let twice = roundtrip(&once).unwrap();
        assert_eq!(twice, once);
        let again = pe::parse(&twice).unwrap();
        assert_eq!(again.entry_rva, image.entry_rva);
        assert_eq!(again.imports, image.imports);
        assert_eq!(pe::image_kind(&twice).unwrap(), kind);
    }

    #[test]
    fn protect_hides_ntoskrnl_names_and_keeps_the_trampoline() {
        let bytes = minimal_sys().unwrap();
        let protected = protect::protect(&bytes, &options(1)).unwrap();
        assert!(!contains(&protected.bytes, NTOSKRNL));
        assert!(!contains(&protected.bytes, IMPORTED));
        let kind = pe::image_kind(&protected.bytes).unwrap();
        assert_eq!(kind, driver_kind());
        let image = pe::parse(&protected.bytes).unwrap();
        assert!(image.imports.is_empty());
        assert_eq!(image.import_rva, 0);
        assert_ne!(image.entry_rva, ENTRY_RVA);
        assert!(image
            .sections
            .iter()
            .any(|section| section.name == protect::section_name(1)));
        let symbol = protected
            .report
            .virtualized
            .iter()
            .find(|item| item.rva == ENTRY_RVA)
            .expect("driver entry");
        assert!(symbol.size >= 5);
        let site = pe::read_rva(&image, ENTRY_RVA, symbol.size as usize).unwrap();
        assert_eq!(site[0], 0xe9);
        assert!(site[5..].iter().all(|byte| *byte == 0xcc));
        let key = public_key(&protected.report.public_key);
        let header = protect::inspect(&protected.bytes, &key).unwrap();
        assert_eq!(header.original_entry, ENTRY_RVA);
        for pass in PIPELINE {
            assert!(
                protected.report.passes.iter().any(|item| item == pass),
                "{pass}"
            );
        }
        assert!(protected.report.mutated.is_empty());
        let once = roundtrip(&protected.bytes).unwrap();
        assert_eq!(once, protected.bytes);
        let twice = roundtrip(&once).unwrap();
        assert_eq!(twice, once);
        let cycled = pe::parse(&twice).unwrap();
        assert_eq!(pe::read_rva(&cycled, ENTRY_RVA, 1).unwrap(), &[0xe9]);
        assert!(!contains(&twice, NTOSKRNL));
        assert!(!contains(&twice, IMPORTED));
        assert_eq!(
            pe::image_kind(&twice).unwrap().subsystem,
            pe::SUBSYSTEM_NATIVE
        );
    }

    #[test]
    fn protect_drops_aslr_bits_the_image_cannot_honor() {
        let mut bytes = minimal_sys().unwrap();
        let mut kind = pe::image_kind(&bytes).unwrap();
        kind.dll_characteristics = 0x01e0;
        pe::set_image_kind(&mut bytes, &kind).unwrap();
        let cycled = roundtrip(&bytes).unwrap();
        assert_eq!(pe::image_kind(&cycled).unwrap().dll_characteristics, 0x01e0);
        let protected = protect::protect(&bytes, &options(1)).unwrap();
        let out = pe::image_kind(&protected.bytes).unwrap();
        assert_eq!(out, pe::without_unbacked_dll_bits(kind));
        assert_eq!(out.subsystem, pe::SUBSYSTEM_NATIVE);
        assert_eq!(out.characteristics, DRIVER_CHARACTERISTICS);
    }

    #[test]
    fn console_image_keeps_windows_cui() {
        let built = crate::sample::build().unwrap();
        assert_eq!(
            pe::image_kind(&built.bytes).unwrap().subsystem,
            pe::SUBSYSTEM_WINDOWS_CUI
        );
        let protected = protect::protect(&built.bytes, &options(1)).unwrap();
        assert_eq!(
            pe::image_kind(&protected.bytes).unwrap().subsystem,
            pe::SUBSYSTEM_WINDOWS_CUI
        );
    }

    #[test]
    fn system_channel_on_m_kern_stays_red() {
        let kern: Vec<_> = claims()
            .iter()
            .filter(|item| item.machine == crate::isa::census::Machine::MKern.as_str())
            .collect();
        assert_eq!(kern.len(), 1);
        assert_eq!(kern[0].id, "laboratory-ioctl");
        assert_eq!(kern[0].channel, "System");
        assert_eq!(kern[0].color, ChannelColor::Red);
        assert_ne!(kern[0].color, ChannelColor::Green);
        assert!(kern[0].anchor.contains("M-KERN"));
        assert!(kern[0].anchor.contains("not provisioned"));
        assert!(claims()
            .iter()
            .all(|item| item.channel != "System" || item.color == ChannelColor::Red));
        // M-KERN stays out of the proof registry. S6 records user-mode detectors
        // as System on M-EMU, and E3 records the Linux probes as System on
        // M-LINUX. Neither turns the laboratory ioctl green.
        assert!(crate::proof::registry().iter().all(|item| {
            item.pass != "laboratory-ioctl"
                && (item.channel != "System"
                    || item.machine == "M-EMU"
                    || item.machine == "M-LINUX")
        }));
    }

    fn public_key(text: &str) -> [u8; 65] {
        let bytes = hex::decode(text).expect("public key");
        bytes.try_into().expect("p256 public key")
    }
}
