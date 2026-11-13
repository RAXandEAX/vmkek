//! Opaque predicates that are not polynomial identities.
//!
//! The branch compares a truncated multiply-xorshift value with a target. The
//! program embeds a preimage of that target. Ops the S1 catalog cannot rewrite
//! are the multiply and the shift; deleting those, and every other op the
//! catalog does not match, leaves a formula whose value is 0. The target is
//! not 0, so that simplified formula has no preimage. The original
//! computation uses an embedded public input, so the checked outcome can be
//! computed directly. The deleted-operation demonstration does not preserve
//! the semantics of the original predicate.
//!
//! Algebraic S2 predicates stay in `predicates`. Those still prove that the
//! true arm runs. They do not prove hardness. The System channel of this stage
//! stays red until the C4 adversary exists. `src/proof` is left untouched.

use crate::ir::{Op, RAX, V_LIMIT, V_OPA0, V_OPA1};
use crate::isa::census::Machine;
use crate::proof::Claim;

use super::identities;

/// Output width of the truncated hash compared by the predicate.
pub const HASH_BITS: u32 = 16;
/// Odd multiplier. Bit 31 is clear, so `ImulRi` does not sign-extend it.
const MUL0: u64 = 0x6C62_2725;
/// Second odd multiplier. Same sign-extension constraint as [`MUL0`].
const MUL1: u64 = 0x5BD1_E995;
const SHIFT_A: u32 = 16;
const SHIFT_B: u32 = 13;
const MASK: u64 = (1u64 << HASH_BITS) - 1;

/// Input the program embeds. [`trunc_hash`] of this word is [`TARGET`].
pub const PREIMAGE: u64 = 0xC30B_1500_0000_7A11;
/// Truncation of [`PREIMAGE`]. The branch compares against this word.
pub const TARGET: u64 = trunc_hash(PREIMAGE);
/// A word that is not a preimage of [`TARGET`].
pub const NON_PREIMAGE: u64 = PREIMAGE ^ 0x9E37;

/// JE / ZF. See [`crate::flags::cond_taken`].
pub const COND: u8 = 4;

const ASSUMPTION: &str = "Вход встроен в программу, длина выхода 16 бит. Результат можно вычислить; поиск скрытого прообраза и стойкость не установлены.";

const _: () = assert!(TARGET == 0xFE5D);
const _: () = assert!(TARGET != 0 && TARGET <= MASK);
const _: () = assert!(trunc_hash(NON_PREIMAGE) != TARGET);
const _: () = assert!(MUL0 <= i32::MAX as u64);
const _: () = assert!(MUL1 <= i32::MAX as u64);
const _: () = assert!(MASK <= i32::MAX as u64);

/// Green marks a supported claim. Red marks an unverified or unsupported claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelColor {
    Green,
    Red,
}

/// One C3 proof row. Not a `proof::PassClaim`: that registry is shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardClaim {
    pub id: &'static str,
    pub channel: &'static str,
    pub machine: &'static str,
    pub color: ChannelColor,
    pub level: Option<Claim>,
    /// Explanation of the assumption or limitation recorded for this row.
    pub assumption: Option<&'static str>,
    /// Supporting test, limitation test, or reason the channel was not run.
    pub anchor: &'static str,
}

/// Crypto describes the known input, without a hardness claim. System remains unverified.
#[must_use]
pub fn claims() -> &'static [HardClaim] {
    const CLAIMS: &[HardClaim] = &[
        HardClaim {
            id: "truncated-hash-preimage",
            channel: "Crypto",
            machine: "",
            color: ChannelColor::Red,
            level: None,
            assumption: Some(ASSUMPTION),
            anchor: "known_preimage_executes_and_s1_does_not_fold",
        },
        HardClaim {
            id: "hard-predicate-adversary",
            channel: "System",
            machine: Machine::MAdv.as_str(),
            color: ChannelColor::Red,
            level: None,
            assumption: None,
            anchor: "M-ADV не заведён до C4; канал System не исполнялся",
        },
    ];
    CLAIMS
}

/// Truncated multiply-xorshift. Not a polynomial identity and not SHA-256.
#[must_use]
pub const fn trunc_hash(value: u64) -> u64 {
    let mut mixed = value.wrapping_mul(MUL0);
    mixed ^= mixed >> SHIFT_A;
    mixed = mixed.wrapping_mul(MUL1);
    mixed ^= mixed >> SHIFT_B;
    mixed & MASK
}

/// IR for `trunc_hash(input)`, then a compare with [`TARGET`].
#[must_use]
pub fn predicate_ops(input: u64) -> Vec<Op> {
    let mut ops = mix_ops(input);
    ops.push(Op::CmpRi(V_OPA1, TARGET as i32));
    ops
}

/// Predicate that embeds [`PREIMAGE`], so the true arm runs.
#[must_use]
pub fn embedded_ops() -> Vec<Op> {
    predicate_ops(PREIMAGE)
}

/// Formula after deleting every op the S1 catalog does not match.
///
/// Register moves stay, because a move does not change the polynomial. Multiply,
/// shift, and the truncating `AndRi` go away: the catalog has no rule for them.
/// What remains is 0 for every input, and 0 is not [`TARGET`].
#[must_use]
pub fn simplified_ops(input: u64) -> Vec<Op> {
    mix_ops(input)
        .into_iter()
        .filter(|op| matches!(op, Op::MovRr(..)) || catalog_matches(op))
        .collect()
}

/// `Some(zf)` when S1 rewrites decide the final flag. Hash steps stay opaque:
/// the catalog is not allowed to evaluate a multiply or a shift.
#[must_use]
pub fn s1_reduces_to_constant(ops: &[Op]) -> bool {
    let env = fold(ops, false);
    !env.blocked && env.zf.is_some()
}

/// The simplified formula is 0 for a generic input, and the target is not 0.
#[must_use]
pub fn simplified_formula_misses_target() -> bool {
    let env = fold(&simplified_ops(0), true);
    !env.blocked && env.reg[usize::from(V_OPA1)] == Sym::Const(0) && TARGET != 0
}

fn mix_ops(input: u64) -> Vec<Op> {
    vec![
        Op::MovRi(V_OPA1, input),
        Op::ImulRi(V_OPA1, MUL0 as i32),
        Op::MovRr(V_OPA0, V_OPA1),
        Op::Shr(V_OPA0, SHIFT_A as u8),
        Op::XorRr(V_OPA1, V_OPA0),
        Op::ImulRi(V_OPA1, MUL1 as i32),
        Op::MovRr(V_OPA0, V_OPA1),
        Op::Shr(V_OPA0, SHIFT_B as u8),
        Op::XorRr(V_OPA1, V_OPA0),
        Op::AndRi(V_OPA1, MASK as i32),
    ]
}

fn catalog_matches(op: &Op) -> bool {
    identities::catalog()
        .iter()
        .any(|identity| (identity.matches)(op))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sym {
    Const(u64),
    Live(u32),
}

struct Env {
    reg: [Sym; V_LIMIT],
    next: u32,
    zf: Option<bool>,
    blocked: bool,
}

fn fold(ops: &[Op], generic_candidate: bool) -> Env {
    let mut env = Env::new();
    let mut generic_left = generic_candidate;
    for op in ops {
        if generic_left && matches!(op, Op::MovRi(V_OPA1, _)) {
            env.reg[usize::from(V_OPA1)] = env.live();
            generic_left = false;
            continue;
        }
        env.step(*op);
    }
    env
}

impl Env {
    fn new() -> Self {
        let mut reg = [Sym::Const(0); V_LIMIT];
        reg[usize::from(RAX)] = Sym::Live(0);
        Self {
            reg,
            next: 1,
            zf: None,
            blocked: false,
        }
    }

    fn live(&mut self) -> Sym {
        let id = self.next;
        self.next += 1;
        Sym::Live(id)
    }

    fn barrier(&mut self, dst: u16) {
        self.reg[usize::from(dst)] = self.live();
        self.zf = None;
    }

    fn step(&mut self, op: Op) {
        if self.apply_catalog(op) {
            return;
        }
        self.step_uncatalogued(op);
    }

    fn apply_catalog(&mut self, op: Op) -> bool {
        if !catalog_matches(&op) {
            return false;
        }
        match op {
            Op::MovRi(dst, imm) => self.reg[usize::from(dst)] = Sym::Const(imm),
            Op::XorRr(dst, src) => self.write_bin(dst, src, |a, b| a ^ b, true),
            Op::SubRr(dst, src) => self.write_bin(dst, src, |a, b| a.wrapping_sub(b), true),
            Op::AddRr(dst, src) => self.write_bin(dst, src, |a, b| a.wrapping_add(b), false),
            Op::AndRr(dst, src) => self.write_bin(dst, src, |a, b| a & b, false),
            Op::OrRr(dst, src) => self.write_bin(dst, src, |a, b| a | b, false),
            _ => return false,
        }
        true
    }

    fn write_bin(&mut self, dst: u16, src: u16, eval: fn(u64, u64) -> u64, cancel: bool) {
        let left = self.reg[usize::from(dst)];
        let right = self.reg[usize::from(src)];
        let sym = self.combine(left, right, eval, cancel);
        self.reg[usize::from(dst)] = sym;
        self.zf = match sym {
            Sym::Const(value) => Some(value == 0),
            Sym::Live(_) => None,
        };
    }

    fn combine(&mut self, left: Sym, right: Sym, eval: fn(u64, u64) -> u64, cancel: bool) -> Sym {
        if cancel && left == right {
            return Sym::Const(0);
        }
        match (left, right) {
            (Sym::Const(a), Sym::Const(b)) => Sym::Const(eval(a, b)),
            _ => self.live(),
        }
    }

    fn step_uncatalogued(&mut self, op: Op) {
        match op {
            Op::MovRr(dst, src) => self.reg[usize::from(dst)] = self.reg[usize::from(src)],
            Op::AddRi(dst, _)
            | Op::SubRi(dst, _)
            | Op::XorRi(dst, _)
            | Op::AndRi(dst, _)
            | Op::OrRi(dst, _)
            | Op::ImulRr(dst, _)
            | Op::ImulRi(dst, _)
            | Op::Not(dst)
            | Op::Neg(dst) => self.barrier(dst),
            Op::Shl(dst, _)
            | Op::Shr(dst, _)
            | Op::Sar(dst, _)
            | Op::Rol(dst, _)
            | Op::Ror(dst, _) => {
                self.barrier(dst);
            }
            Op::CmpRi(dst, imm) => self.zf = self.eq_imm(dst, imm as i64 as u64),
            Op::TestRi(dst, imm) => self.zf = self.mask_imm(dst, imm as i64 as u64),
            _ => self.blocked = true,
        }
    }

    fn eq_imm(&self, dst: u16, imm: u64) -> Option<bool> {
        match self.reg[usize::from(dst)] {
            Sym::Const(value) => Some(value == imm),
            Sym::Live(_) => None,
        }
    }

    fn mask_imm(&self, dst: u16, imm: u64) -> Option<bool> {
        match self.reg[usize::from(dst)] {
            Sym::Const(value) => Some(value & imm == 0),
            Sym::Live(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::Flags;
    use crate::ir::{exec_func, Block, Exit, FuncIr, MapMem, MemIo, Op, RAX, RBX};
    use crate::obf::predicates;

    const SAMPLES: &[u64] = &[
        0,
        1,
        2,
        PREIMAGE,
        NON_PREIMAGE,
        0x8000_0000_0000_0000,
        u64::MAX,
    ];

    fn exec_blocks(blocks: Vec<Block>) -> [u64; 16] {
        let func = FuncIr {
            name: "c3".into(),
            rva: 0,
            entry: 0,
            blocks,
        };
        let mut arch = [0u64; 16];
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut abs = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        exec_func(
            std::slice::from_ref(&func),
            0,
            &mut arch,
            &mut flags,
            &mut mem,
            0,
            &mut abs,
        )
        .expect("c3");
        arch
    }

    fn taken(input: u64) -> bool {
        let arch = exec_blocks(vec![
            Block {
                ops: predicate_ops(input),
                exit: Exit::Jcc(COND, 1, 2),
                opaque: true,
            },
            Block {
                ops: vec![Op::MovRi(RBX, 1)],
                exit: Exit::Ret,
                opaque: false,
            },
            Block {
                ops: vec![Op::MovRi(RBX, 0)],
                exit: Exit::Ret,
                opaque: false,
            },
        ]);
        arch[usize::from(RBX)] == 1
    }

    fn observe(ops: Vec<Op>) -> u64 {
        let mut ops = ops;
        ops.push(Op::MovRr(RAX, V_OPA1));
        let arch = exec_blocks(vec![Block {
            ops,
            exit: Exit::Ret,
            opaque: false,
        }]);
        arch[usize::from(RAX)]
    }

    fn algebraic(name: &str) -> Vec<Op> {
        let predicate = predicates::predicates()
            .iter()
            .find(|item| item.name == name)
            .unwrap_or_else(|| panic!("missing {name}"));
        (predicate.ops)()
    }

    #[test]
    fn known_preimage_executes_and_s1_does_not_fold() {
        assert_eq!(trunc_hash(PREIMAGE), TARGET);
        assert_eq!(observe(mix_ops(PREIMAGE)), TARGET);
        assert!(taken(PREIMAGE));
        assert_ne!(trunc_hash(NON_PREIMAGE), TARGET);
        assert!(!taken(NON_PREIMAGE));
        assert!(!s1_reduces_to_constant(&embedded_ops()));
        assert!(!s1_reduces_to_constant(&predicate_ops(NON_PREIMAGE)));
        assert!(s1_reduces_to_constant(&algebraic("xor_self")));
        assert!(s1_reduces_to_constant(&algebraic("sub_self")));
        assert!(!s1_reduces_to_constant(&algebraic("product_even")));
    }

    #[test]
    fn ir_hash_matches_trunc_hash() {
        for input in SAMPLES {
            assert_eq!(observe(mix_ops(*input)), trunc_hash(*input), "{input:#x}");
        }
    }

    #[test]
    fn simplified_formula_has_no_preimage() {
        assert!(simplified_formula_misses_target());
        for input in SAMPLES {
            let simplified = observe(simplified_ops(*input));
            assert_eq!(simplified, 0, "{input:#x}");
            assert_ne!(simplified, TARGET);
            assert_eq!(observe(mix_ops(*input)), trunc_hash(*input));
        }
    }

    #[test]
    fn multiply_and_shift_stay_outside_the_s1_catalog() {
        let mut saw_hash_step = false;
        for op in embedded_ops() {
            if matches!(op, Op::ImulRi(..) | Op::Shr(..)) {
                saw_hash_step = true;
                assert!(!catalog_matches(&op), "{op:?}");
            }
        }
        assert!(saw_hash_step);
    }

    #[test]
    fn algebraic_s2_predicates_stay_in_the_catalog() {
        let names: Vec<_> = predicates::predicates()
            .iter()
            .map(|item| item.name)
            .collect();
        assert_eq!(
            names,
            ["product_even", "xor_self", "sub_self", "and_complement"]
        );
        for predicate in predicates::predicates() {
            assert!(!predicate.proof.is_empty(), "{}", predicate.name);
            assert_ne!((predicate.ops)(), embedded_ops());
            assert_eq!(
                predicates::identify(&(predicate.ops)()),
                Some(predicate.name)
            );
        }
    }

    #[test]
    fn crypto_claim_records_the_known_input_limit() {
        let crypto = claims()
            .iter()
            .find(|row| row.channel == "Crypto")
            .expect("crypto");
        assert_eq!(crypto.color, ChannelColor::Red);
        assert_eq!(crypto.level, None);
        assert_eq!(
            crypto.anchor,
            "known_preimage_executes_and_s1_does_not_fold"
        );
        let assumption = crypto.assumption.expect("assumption");
        let width = format!("длина выхода {HASH_BITS} бит");
        assert!(assumption.contains(&width), "{assumption}");
        assert!(assumption.contains("Вход встроен в программу"));
        assert!(assumption.contains("стойкость не установлены"));
        assert!(!assumption.to_lowercase().contains("virtual"));
        assert!(assumption.contains(&HASH_BITS.to_string()));
    }

    #[test]
    fn system_channel_on_m_adv_stays_red() {
        let system: Vec<_> = claims()
            .iter()
            .filter(|row| row.channel == "System")
            .collect();
        assert_eq!(system.len(), 1);
        assert_eq!(system[0].machine, "M-ADV");
        assert_eq!(system[0].color, ChannelColor::Red);
        assert_eq!(system[0].level, None);
        assert!(system[0].anchor.contains("C4"));
        assert!(claims()
            .iter()
            .all(|row| row.channel != "System" || row.color == ChannelColor::Red));
    }
}
