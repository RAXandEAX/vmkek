//! Machine form and the data-dependent handler edge.
//!
//! A register machine names slots in each opcode. A stack machine pushes those
//! slots and lets the operation pop them. Images with two or more functions
//! contain both forms. The handler edge mixes the register file into a gate.
//! The stub reads the low bit of that gate when it picks the next handler entry.

use std::cell::RefCell;

use crate::ir::{Block, Exit, FuncIr, Op, V_STATE};

use super::BcFunc;

/// Which interpreter shape a function uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineForm {
    Register,
    Stack,
}

impl MachineForm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Stack => "stack",
        }
    }
}

/// One T2 proof row. Not a [`crate::proof::PassClaim`]: that registry is shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub id: &'static str,
    pub channel: &'static str,
    pub machine: &'static str,
    pub anchor: &'static str,
    pub statement: &'static str,
}

/// System rows for T2. No Math row. M-ADV does not cover a trace that already holds the key.
#[must_use]
pub fn claims() -> &'static [Claim] {
    const BOTH: &str = "Интерпретатор Rust и нативный stub на регистровой и стековой формах совпадают с ir::exec_func.";
    const DROP: &str = "Упроститель, который считает внутреннее состояние VM конкретным и не зависящим от входа и выкидывает его, не восстанавливает формулу sample в бюджете шагов. Канал не распространяется на трассу, где ключ уже лежит в памяти.";
    const ROWS: &[Claim] = &[
        Claim {
            id: "both-forms-match-ir",
            channel: "System",
            machine: "M-EMU",
            anchor: "register_and_stack_forms_match_the_ir_oracle",
            statement: BOTH,
        },
        Claim {
            id: "input-independent-vm-state",
            channel: "System",
            machine: "M-ADV",
            anchor: "input_independent_simplifier_misses_the_sample_formula",
            statement: DROP,
        },
    ];
    ROWS
}

/// Form of one function from the protect seed and the function's name and RVA.
#[must_use]
pub fn choose(seed: u64, func: &FuncIr) -> MachineForm {
    let mut mix = seed ^ u64::from(func.rva).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for byte in func.name.bytes() {
        mix = mix.wrapping_mul(0x0000_0100_0000_01B3) ^ u64::from(byte);
    }
    if mix & 1 == 0 {
        MachineForm::Register
    } else {
        MachineForm::Stack
    }
}

/// One form per function. A single function stays a register machine.
/// Two or more functions use [`choose`], then a flip so both forms are present.
#[must_use]
pub fn assign_forms(seed: u64, funcs: &[FuncIr]) -> Vec<MachineForm> {
    if funcs.len() < 2 {
        return vec![MachineForm::Register; funcs.len()];
    }
    let mut forms: Vec<MachineForm> = funcs.iter().map(|func| choose(seed, func)).collect();
    force_both(&mut forms);
    forms
}

fn force_both(forms: &mut [MachineForm]) {
    if !forms.contains(&MachineForm::Register) {
        forms[0] = MachineForm::Register;
    }
    if !forms.contains(&MachineForm::Stack) {
        let last = forms.len() - 1;
        forms[last] = MachineForm::Stack;
    }
}

/// `true` when a concrete input does not choose among semantic edges.
/// Opaque predicates and the flatten dispatcher compare state, not the argument.
#[must_use]
pub fn is_single_path(func: &FuncIr) -> bool {
    func.blocks.iter().all(|block| !input_split(block))
}

fn input_split(block: &Block) -> bool {
    if block.opaque {
        return false;
    }
    let Exit::Jcc(_, _, _) = block.exit else {
        return false;
    };
    !state_dispatch(&block.ops)
}

fn state_dispatch(ops: &[Op]) -> bool {
    let compares = ops
        .iter()
        .any(|op| matches!(op, Op::CmpRi(V_STATE, _) | Op::TestRi(V_STATE, _)));
    compares && ops.iter().all(state_op)
}

fn state_op(op: &Op) -> bool {
    matches!(
        op,
        Op::CmpRi(V_STATE, _)
            | Op::TestRi(V_STATE, _)
            | Op::StFlags(_)
            | Op::LdFlags(_)
            | Op::MovRi(V_STATE, _)
    )
}

/// Mask word for one instruction. Zero seed is the identity, used by hand-built images.
#[must_use]
pub fn sched_word(seed: u64, rva: u32, index: u32) -> u64 {
    if seed == 0 {
        return 0;
    }
    seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(u64::from(rva))
        .wrapping_add(u64::from(index).wrapping_mul(0x0100_001B))
        | 1
}

/// XOR a data immediate with [`sched_word`]. The operation is its own inverse.
pub fn mix_imm(bytes: &mut [u8], seed: u64, rva: u32, index: u32) {
    let Some((at, len)) = imm_span(bytes) else {
        return;
    };
    let mask = sched_word(seed, rva, index).to_le_bytes();
    for (offset, byte) in bytes.iter_mut().skip(at).take(len).enumerate() {
        *byte ^= mask[offset];
    }
}

fn imm_span(bytes: &[u8]) -> Option<(usize, usize)> {
    let tag = *bytes.first()?;
    let (at, len) = match tag {
        0x03 => (2, 8),
        0x35 => (1, 8),
        0x15..=0x19 | 0x21 | 0x23 | 0x2e => (2, 4),
        _ => return None,
    };
    bytes.len().checked_sub(at).filter(|rest| *rest >= len)?;
    Some((at, len))
}

pub(super) fn mask_block(plain: &mut [Vec<u8>], seed: u64, rva: u32) {
    for (index, insn) in plain.iter_mut().enumerate() {
        let index = u32::try_from(index).unwrap_or(u32::MAX);
        mix_imm(insn, seed, rva, index);
    }
}

/// Mix the live register file into the gate. The low byte is the handler edge.
#[must_use]
pub fn fold_gate(gate: u64, regs: &[u64]) -> u64 {
    let mut mixed = gate ^ 0x00D2_E400_0000_0001;
    for value in regs {
        mixed = mixed.wrapping_mul(0x9E37_79B9).wrapping_add(*value);
    }
    mixed
}

thread_local! {
    static EDGES: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// Record handler-edge bytes while `body` runs. The buffer is per thread.
pub fn collect_edges(body: impl FnOnce()) -> Vec<u8> {
    EDGES.with(|cell| *cell.borrow_mut() = Some(Vec::new()));
    body();
    EDGES.with(|cell| cell.borrow_mut().take().unwrap_or_default())
}

pub(super) fn note_edge(regs: &[u64], gate: &mut u64) {
    *gate = fold_gate(*gate, regs);
    let byte = *gate as u8;
    EDGES.with(|cell| {
        if let Some(buf) = cell.borrow_mut().as_mut() {
            buf.push(byte);
        }
    });
}

pub(super) fn stamp_meta(func: &mut BcFunc, shape: MachineForm, single_path: bool, sched: u64) {
    func.form = shape;
    func.single_path = single_path;
    func.sched = sched;
    // The stub's unmask reads the low bit of the gate and jumps to that entry.
    func.data_dependent = true;
}
