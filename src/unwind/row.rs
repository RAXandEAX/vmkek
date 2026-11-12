//! Canonical unwind row shared by PE `UNWIND_INFO` and ELF `.eh_frame`.
//!
//! A row is the state an unwinder restores at one program counter: where the
//! caller's stack pointer sits, which registers live in memory, and where the
//! return address is. Two encodings are the same frame when their rows compare
//! equal, including across the Windows and System V register numbers.

use std::collections::BTreeMap;

/// Architectural register. Numbering differences between PE and DWARF are resolved here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reg {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Xmm(u8),
    Other(u16),
}

/// Canonical frame address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cfa {
    /// `CFA = RSP + disp` using the RSP at this program counter.
    Sp(i64),
    /// `CFA = reg + disp`. Used once a frame pointer is established.
    Reg { reg: Reg, disp: i64 },
    /// The encoding uses an expression this model does not evaluate.
    Opaque,
}

/// Where a register's entry value lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// Memory at `CFA + disp`.
    AtCfa(i64),
    /// The register still holds the entry value.
    Same,
    /// DWARF `undefined`.
    Undefined,
    /// The value is the CFA itself plus a displacement (`DW_CFA_val_offset`).
    ValueAtCfa(i64),
    /// The value currently lives in another register.
    InReg(Reg),
    /// Expression or another rule this model does not evaluate.
    Opaque,
}

/// Unwind state at one program counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub cfa: Cfa,
    pub saved: BTreeMap<Reg, Slot>,
    pub rip: Slot,
}

/// Row at function entry, before any prologue byte has retired.
///
/// `CFA = RSP + 8` and the return address is at `CFA - 8`. No callee-saved
/// register has been stored yet.
#[must_use]
pub fn entry_row() -> Row {
    Row {
        cfa: Cfa::Sp(8),
        saved: BTreeMap::new(),
        rip: Slot::AtCfa(-8),
    }
}

/// Windows x64 unwind register number.
pub(crate) fn pe_gpr(number: u8) -> Option<Reg> {
    Some(match number {
        0 => Reg::Rax,
        1 => Reg::Rcx,
        2 => Reg::Rdx,
        3 => Reg::Rbx,
        4 => Reg::Rsp,
        5 => Reg::Rbp,
        6 => Reg::Rsi,
        7 => Reg::Rdi,
        8 => Reg::R8,
        9 => Reg::R9,
        10 => Reg::R10,
        11 => Reg::R11,
        12 => Reg::R12,
        13 => Reg::R13,
        14 => Reg::R14,
        15 => Reg::R15,
        _ => return None,
    })
}

/// DWARF register number for x86-64 (System V ABI).
pub(crate) fn dwarf_reg(number: u16) -> Reg {
    match number {
        0 => Reg::Rax,
        1 => Reg::Rdx,
        2 => Reg::Rcx,
        3 => Reg::Rbx,
        4 => Reg::Rsi,
        5 => Reg::Rdi,
        6 => Reg::Rbp,
        7 => Reg::Rsp,
        8 => Reg::R8,
        9 => Reg::R9,
        10 => Reg::R10,
        11 => Reg::R11,
        12 => Reg::R12,
        13 => Reg::R13,
        14 => Reg::R14,
        15 => Reg::R15,
        16 => Reg::Rip,
        other if (17..33).contains(&other) => Reg::Xmm((other - 17) as u8),
        other => Reg::Other(other),
    }
}
