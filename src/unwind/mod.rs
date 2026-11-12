//! Exception unwind for a function whose body was replaced by a VM trampoline.
//!
//! The native trampoline is a jump at offset 0, so every byte of the replaced
//! range unwinds as the original function at offset 0. The logical table keeps
//! the original row at each original offset. PE `.pdata` / `UNWIND_INFO` and
//! ELF `.eh_frame` both lower to that table.
//!
//! Claims live in this module. `src/proof` is left untouched: a parallel stage
//! owns that registry. The M-WIN native profile has a separate checked
//! host-call bridge for canonical Win64 frames.

mod eh;
mod pdata;
mod row;

use crate::elf::ElfImage;
use crate::error::Result;
use crate::pe::PeImage;

pub use row::{entry_row, Cfa, Reg, Row, Slot};

/// Green means the named test passed on this machine. Red means acceptance remains open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelColor {
    Green,
    Red,
}

/// One L7 proof row. Not a `proof::PassClaim`: that registry is shared with other stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnwindClaim {
    pub id: &'static str,
    pub channel: &'static str,
    pub machine: &'static str,
    pub color: ChannelColor,
    pub anchor: &'static str,
}

/// Local claim table for L7.
#[must_use]
pub fn claims() -> &'static [UnwindClaim] {
    const CLAIMS: &[UnwindClaim] = &[
        UnwindClaim {
            id: "pe-pdata-correspondence",
            channel: "Math",
            machine: "M-IR",
            color: ChannelColor::Green,
            anchor: "synthetic_pe_trampoline_matches_original_frame",
        },
        UnwindClaim {
            id: "elf-eh-frame-correspondence",
            channel: "Math",
            machine: "M-IR",
            color: ChannelColor::Green,
            anchor: "synthetic_eh_frame_trampoline_matches_original_frame",
        },
        UnwindClaim {
            id: "linux-fault-handler",
            channel: "System",
            machine: "M-LINUX",
            color: ChannelColor::Green,
            anchor: "panic_and_sigfpe_reach_the_same_handler",
        },
        UnwindClaim {
            id: "setjmp-longjmp",
            channel: "System",
            machine: "M-LINUX",
            color: ChannelColor::Green,
            anchor: "setjmp_longjmp_observable_state_matches_through_trampoline",
        },
        UnwindClaim {
            id: "win-seh",
            channel: "System",
            machine: "M-WIN",
            color: ChannelColor::Green,
            anchor: "tests/windows/t4_t6.ps1 -Stage T4: 64 exceptions through a canonical Win64 VM frame reach the original caller handler",
        },
        UnwindClaim {
            id: "win-seh-extended",
            channel: "System",
            machine: "M-WIN",
            color: ChannelColor::Red,
            anchor: "native SEH in rewritten functions with their own handlers, chained or other unsupported unwind records",
        },
        // Sealed unwind bytes are on disk. Reaching the previous handler through
        // that sealed table is not a green Math/System result in this stage.
        UnwindClaim {
            id: "sealed-unwind",
            channel: "Math",
            machine: "M-LINUX",
            color: ChannelColor::Red,
            anchor: "sealed unwind stays red pending the handler proof",
        },
    ];
    CLAIMS
}

/// One row of the correspondence between the original frame and the trampoline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameLink {
    /// Offset in the trampoline range, or the original offset for a logical row.
    pub trampoline_at: u32,
    /// Original offset whose row this link records. Native links use 0.
    pub original_at: u32,
    pub row: Row,
}

/// Math object: native trampoline rows and the retained logical frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Correspondence {
    pub format: &'static str,
    pub start: u64,
    pub end: u64,
    /// PE handler RVA, or the ELF personality address when it is a direct pointer.
    pub handler: Option<u64>,
    /// Chained unwind-info RVA. ELF has none.
    pub chain: Option<u64>,
    /// Windows applies the chain even at offset 0, so the native record keeps it.
    pub chain_on_native: bool,
    pub native: Vec<FrameLink>,
    pub logical: Vec<FrameLink>,
}

/// Rewrite `.pdata` for one trampoline. No exception directory yields an empty list.
pub fn preserve_pe(image: &mut PeImage, rva: u32, size: u32) -> Result<Vec<Correspondence>> {
    pdata::preserve(image, rva, size)
}

/// Rewrite `.eh_frame` for one trampoline. No `.eh_frame` section yields an empty list.
pub fn preserve_elf(image: &mut ElfImage, start: u64, end: u64) -> Result<Vec<Correspondence>> {
    eh::preserve(image, start, end)
}

/// Unwind row of the PE function that contains `pc_rva`.
pub fn pe_row_at(image: &PeImage, pc_rva: u32) -> Result<Row> {
    pdata::row_at(image, pc_rva)
}

/// Unwind row of the ELF FDE that contains `pc`.
pub fn eh_row_at(bytes: &[u8], frame_va: u64, pc: u64) -> Result<Row> {
    eh::row_at(bytes, frame_va, pc)
}

/// Observable result of `setjmp` followed by `longjmp`.
///
/// `local` is the value captured before `setjmp` and not written again.
/// `marker` is stored after `setjmp` returns 0 and before `longjmp`.
/// A `val` of 0 comes back as 1, matching the C library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetjmpObs {
    pub value: i32,
    pub local: u64,
    pub marker: u64,
}

/// Pure statement of the `setjmp` / `longjmp` contract checked on M-LINUX.
#[must_use]
pub fn setjmp_longjmp_obs(local: u64, marker: u64, val: i32) -> SetjmpObs {
    SetjmpObs {
        value: if val == 0 { 1 } else { val },
        local,
        marker,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::pe::{self, Section, CH_RDATA, CH_TEXT, IMAGE_BASE};
    use crate::proof;
    use crate::protect::{self, Options};

    #[test]
    fn win_seh_channels_preserve_the_tested_scope() {
        let win = claims().iter().find(|item| item.id == "win-seh").unwrap();
        assert_eq!(win.color, ChannelColor::Green);
        assert_eq!(win.channel, "System");
        assert_eq!(win.machine, "M-WIN");
        assert!(win.anchor.contains("-Stage T4"));
        assert!(win.anchor.contains("canonical Win64 VM frame"));
        let extended = claims()
            .iter()
            .find(|item| item.id == "win-seh-extended")
            .unwrap();
        assert_eq!(extended.color, ChannelColor::Red);
        assert_eq!(extended.machine, "M-WIN");
        assert!(proof::registry()
            .iter()
            .all(|item| item.pass != "unwind" && item.pass != "win-seh"));
    }

    #[test]
    fn green_claims_name_a_machine_and_an_anchor() {
        for item in claims()
            .iter()
            .filter(|item| item.color == ChannelColor::Green)
        {
            assert!(item.channel == "Math" || item.channel == "System");
            assert!(!item.anchor.is_empty());
            assert!(matches!(item.machine, "M-IR" | "M-LINUX" | "M-WIN"));
        }
    }

    #[test]
    fn protect_keeps_the_trampoline_on_the_entry_row() {
        let bytes = pe::emit(&trampoline_image()).unwrap();
        let parsed = pe::parse(&bytes).unwrap();
        assert_ne!(pe_row_at(&parsed, 0x1004).unwrap(), entry_row());
        let protected = protect::protect(&bytes, &virtualize_all()).unwrap();
        let mut out = pe::parse(&protected.bytes).unwrap();
        assert_eq!(out.exception_rva, 0x2000);
        assert!(pe_row_at(&out, 0x1000).is_err(), "pdata is cleartext");
        open_pdata(&mut out);
        assert_eq!(pe_row_at(&out, 0x1000).unwrap(), entry_row());
        assert_eq!(pe_row_at(&out, 0x1004).unwrap(), entry_row());
        let text = out
            .sections
            .iter()
            .find(|section| section.name == ".text")
            .unwrap();
        assert_eq!(text.bytes[0], 0xe9);
    }

    fn open_pdata(image: &mut PeImage) {
        let pdata = image
            .sections
            .iter_mut()
            .find(|section| section.name == ".pdata")
            .unwrap();
        protect::mask_span(&mut pdata.bytes, 1, pdata.rva);
    }

    fn virtualize_all() -> Options {
        Options {
            virtualize: BTreeSet::new(),
            mutate: BTreeSet::new(),
            virtualize_all: true,
            mutate_all: false,
            seed: 1,
            random_key: false,
            debug_seed: false,
        }
    }

    fn trampoline_image() -> PeImage {
        let mut pdata = Vec::new();
        pdata.extend_from_slice(&0x1000u32.to_le_bytes());
        pdata.extend_from_slice(&0x100bu32.to_le_bytes());
        pdata.extend_from_slice(&0x200cu32.to_le_bytes());
        pdata.extend_from_slice(&[0x01, 0x04, 0x01, 0x00, 0x04, 0x30]);
        let mut text = vec![0x90u8; 11];
        text[..10].copy_from_slice(&[0x48, 0xb8, 42, 0, 0, 0, 0, 0, 0, 0]);
        text[10] = 0xc3;
        PeImage {
            image_base: IMAGE_BASE,
            entry_rva: 0x1000,
            sections: vec![
                Section {
                    name: ".text".into(),
                    rva: 0x1000,
                    bytes: text,
                    characteristics: CH_TEXT,
                },
                Section {
                    name: ".pdata".into(),
                    rva: 0x2000,
                    bytes: pdata,
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
            exception_rva: 0x2000,
            exception_size: 12,
            tls_rva: 0,
            tls_size: 0,
        }
    }
}
