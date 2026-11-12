//! Same-length x86-64 rewrites, then a cave move and a linear-disassembler desync.
//! A dictionary rule runs only when its flag precondition holds and the replacement
//! encodes to the same number of bytes.

pub(crate) mod cave;
pub(crate) mod desync;
mod dict;

pub use dict::rewrite;

use std::collections::{HashMap, HashSet};

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind};

const STATUS: u32 = iced_x86::RflagsBits::CF
    | iced_x86::RflagsBits::PF
    | iced_x86::RflagsBits::ZF
    | iced_x86::RflagsBits::SF
    | iced_x86::RflagsBits::OF;

/// `mask` is dead only when every path after `insns[index]` overwrites each of
/// its bits before a read. A write clears only the bits it definitely assigns,
/// so a later read of a surviving bit keeps the mask live. Both edges of a
/// conditional branch are walked, including a backward edge, when both targets
/// lie in `insns`. A jump, a call, a branch, or a fall-through that leaves the
/// fragment keeps any surviving bit live. Only `ret` ends a path with bits
/// still unobserved. A flag iced leaves undefined is not an overwrite. A
/// shift, rotate, or `rep` string op whose count can be zero does not
/// overwrite the mask, and neither does `shld`/`shrd` when the masked count
/// is greater than the operand width.
pub(crate) fn flags_dead(insns: &[Instruction], index: usize, mask: u32) -> bool {
    let by_ip = ip_index(insns);
    let mut seen = HashSet::new();
    let mut work = Vec::new();
    let Some(start) = successors(insns, &by_ip, index) else {
        return false;
    };
    work.extend(start.into_iter().map(|at| (at, mask)));
    while let Some((at, live)) = work.pop() {
        if live == 0 || !seen.insert((at, live)) {
            continue;
        }
        let insn = &insns[at];
        if reads(insn, live) {
            return false;
        }
        let still = live & !killed_bits(insn);
        if still == 0 {
            continue;
        }
        let Some(next) = successors(insns, &by_ip, at) else {
            return false;
        };
        work.extend(next.into_iter().map(|at| (at, still)));
    }
    true
}

fn ip_index(insns: &[Instruction]) -> HashMap<u64, usize> {
    insns
        .iter()
        .enumerate()
        .map(|(at, insn)| (insn.ip(), at))
        .collect()
}

fn killed_bits(insn: &Instruction) -> u32 {
    if guaranteed_write(insn) {
        definite_flags(insn)
    } else {
        0
    }
}

/// Bits assigned for every input. `rflags_modified` is written ∪ cleared ∪ set
/// ∪ undefined, and undefined bits are not a kill: `div`/`idiv` leave status
/// flags alone, and one-operand `mul`/`imul` assign only CF and OF.
fn definite_flags(insn: &Instruction) -> u32 {
    insn.rflags_modified() & !insn.rflags_undefined() | emulator_status(insn)
}

/// `imul` with two or three operands stores `flags::logic` (ZF, SF, and PF
/// included). iced marks those bits undefined on every `imul`, including the
/// one-operand form, which does not assign them.
fn emulator_status(insn: &Instruction) -> u32 {
    if insn.mnemonic() == Mnemonic::Imul && insn.op_count() >= 2 {
        STATUS
    } else {
        0
    }
}

/// A variable-count shift or rotate leaves every flag untouched when the count
/// is zero, and so does a `rep`/`repne` string op when RCX is zero. `shld` and
/// `shrd` also leave flags untouched when the masked count is greater than the
/// operand width. Those are not kills.
fn guaranteed_write(insn: &Instruction) -> bool {
    if insn.has_rep_prefix() || insn.has_repne_prefix() {
        return false;
    }
    match shift_count(insn.mnemonic()) {
        Some(count) => immediate_writes_flags(insn, count),
        None => true,
    }
}

fn shift_count(mnemonic: Mnemonic) -> Option<u32> {
    match mnemonic {
        Mnemonic::Shl
        | Mnemonic::Shr
        | Mnemonic::Sar
        | Mnemonic::Sal
        | Mnemonic::Rol
        | Mnemonic::Ror
        | Mnemonic::Rcl
        | Mnemonic::Rcr => Some(1),
        Mnemonic::Shld | Mnemonic::Shrd => Some(2),
        _ => None,
    }
}

fn immediate_writes_flags(insn: &Instruction, index: u32) -> bool {
    let Some(count) = masked_immediate(insn, index) else {
        return false;
    };
    count != 0 && in_range_double_shift(insn, count)
}

fn masked_immediate(insn: &Instruction, index: u32) -> Option<u32> {
    if insn.op_kind(index) != OpKind::Immediate8 {
        return None;
    }
    let mask = count_mask(operand_bits(insn))?;
    Some(u32::from(insn.immediate8() & mask))
}

/// Ordinary shifts write flags for every non-zero masked count. `shld`/`shrd`
/// write them only for a count in `1..=width` (`alu::double` keeps the prior
/// flags when the count is above the operand width).
fn in_range_double_shift(insn: &Instruction, count: u32) -> bool {
    if !matches!(insn.mnemonic(), Mnemonic::Shld | Mnemonic::Shrd) {
        return true;
    }
    let width = operand_bits(insn);
    (1..=width).contains(&count)
}

fn count_mask(bits: u32) -> Option<u8> {
    match bits {
        64 => Some(0x3f),
        8 | 16 | 32 => Some(0x1f),
        _ => None,
    }
}

fn operand_bits(insn: &Instruction) -> u32 {
    let bytes = match insn.op0_kind() {
        OpKind::Register => insn.op_register(0).size(),
        OpKind::Memory => insn.memory_size().size(),
        _ => return 0,
    };
    u32::try_from(bytes.saturating_mul(8)).unwrap_or(0)
}

/// `None` is an unresolved divergence. `Some` is every successor in the fragment.
fn successors(
    insns: &[Instruction],
    by_ip: &HashMap<u64, usize>,
    index: usize,
) -> Option<Vec<usize>> {
    let insn = &insns[index];
    match insn.flow_control() {
        // Missing fall-through is unresolved: code past the window may read the mask.
        FlowControl::Next => Some(vec![at_ip(by_ip, insn.next_ip())?]),
        FlowControl::Return => Some(Vec::new()),
        FlowControl::ConditionalBranch => {
            let fall = at_ip(by_ip, insn.next_ip())?;
            let taken = at_ip(by_ip, near_target(insn)?)?;
            Some(vec![fall, taken])
        }
        // Near/far jump, indirect branch, call, interrupt, exception.
        _ => None,
    }
}

fn near_target(insn: &Instruction) -> Option<u64> {
    match insn.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(insn.near_branch_target())
        }
        _ => None,
    }
}

fn at_ip(by_ip: &HashMap<u64, usize>, ip: u64) -> Option<usize> {
    by_ip.get(&ip).copied()
}

fn reads(insn: &iced_x86::Instruction, mask: u32) -> bool {
    if insn.rflags_read() & mask != 0 {
        return true;
    }
    if mask == STATUS && insn.is_jcc_short_or_near() {
        return true;
    }
    jcc_bits(insn.mnemonic()) & mask != 0
}

fn jcc_bits(mnemonic: iced_x86::Mnemonic) -> u32 {
    use iced_x86::Mnemonic::{
        Ja, Jae, Jb, Jbe, Je, Jg, Jge, Jl, Jle, Jne, Jno, Jnp, Jns, Jo, Jp, Js,
    };
    use iced_x86::RflagsBits;
    match mnemonic {
        Jo | Jno => RflagsBits::OF,
        Jb | Jae => RflagsBits::CF,
        Je | Jne => RflagsBits::ZF,
        Jbe | Ja => RflagsBits::CF | RflagsBits::ZF,
        Js | Jns => RflagsBits::SF,
        Jp | Jnp => RflagsBits::PF,
        Jl | Jge => RflagsBits::SF | RflagsBits::OF,
        Jle | Jg => RflagsBits::ZF | RflagsBits::SF | RflagsBits::OF,
        _ => 0,
    }
}
