//! Algebraic opaque predicates (S2). Each one is a polynomial tautology, so the
//! true arm is the only arm that runs. That shows the branch keeps the program's
//! meaning. It does not show the predicate is hard to remove: a solver that
//! knows the identity can fold the arm away. The false arm writes only a
//! virtual register.
//!
//! Predicates that are not polynomial identities live in `hard`.

use rand::Rng;
use rand_chacha::ChaCha20Rng;

use crate::ir::{Op, RAX, V_OPA0, V_OPA1};

/// JE / ZF. See [`crate::flags::cond_taken`].
const ZF: u8 = 4;

pub struct Predicate {
    pub name: &'static str,
    pub proof: &'static str,
    pub cond: u8,
    pub ops: fn() -> Vec<Op>,
}

pub fn predicates() -> &'static [Predicate] {
    PREDICATES
}

pub fn pick(rng: &mut ChaCha20Rng) -> &'static Predicate {
    let index = rng.gen_range(0..predicates().len());
    let predicate = &predicates()[index];
    debug_assert!(!predicate.name.is_empty());
    debug_assert!(!predicate.proof.is_empty());
    predicate
}

#[cfg(test)]
pub fn identify(ops: &[Op]) -> Option<&'static str> {
    predicates()
        .iter()
        .find(|predicate| (predicate.ops)() == ops)
        .map(|predicate| predicate.name)
}

// Proof: x and x+1 are consecutive, so one of them is even and x*(x+1) is even.
// TEST of that product with 1 sets ZF, and JE is taken.
fn product_even() -> Vec<Op> {
    vec![
        Op::MovRr(V_OPA0, RAX),
        Op::MovRr(V_OPA1, V_OPA0),
        Op::AddRi(V_OPA1, 1),
        Op::ImulRr(V_OPA1, V_OPA0),
        Op::TestRi(V_OPA1, 1),
    ]
}

// Proof: x XOR x = 0 for every x. XOR sets ZF on a zero result, so JE is taken.
fn xor_self() -> Vec<Op> {
    vec![
        Op::MovRr(V_OPA0, RAX),
        Op::MovRr(V_OPA1, V_OPA0),
        Op::XorRr(V_OPA1, V_OPA0),
    ]
}

// Proof: x - x = 0 for every x. SUB sets ZF on a zero result, so JE is taken.
fn sub_self() -> Vec<Op> {
    vec![
        Op::MovRr(V_OPA0, RAX),
        Op::MovRr(V_OPA1, V_OPA0),
        Op::SubRr(V_OPA1, V_OPA0),
    ]
}

// Proof: x AND NOT x = 0 for every x. AND sets ZF on a zero result, so JE is taken.
fn and_complement() -> Vec<Op> {
    vec![
        Op::MovRr(V_OPA0, RAX),
        Op::MovRr(V_OPA1, V_OPA0),
        Op::Not(V_OPA1),
        Op::AndRr(V_OPA1, V_OPA0),
    ]
}

static PREDICATES: &[Predicate] = &[
    Predicate {
        name: "product_even",
        proof: "x and x+1 are consecutive, so x*(x+1) is even; TEST ..., 1 sets ZF",
        cond: ZF,
        ops: product_even,
    },
    Predicate {
        name: "xor_self",
        proof: "x XOR x = 0 for every x; XOR sets ZF",
        cond: ZF,
        ops: xor_self,
    },
    Predicate {
        name: "sub_self",
        proof: "x - x = 0 for every x; SUB sets ZF",
        cond: ZF,
        ops: sub_self,
    },
    Predicate {
        name: "and_complement",
        proof: "x AND NOT x = 0 for every x; AND sets ZF",
        cond: ZF,
        ops: and_complement,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::Flags;
    use crate::ir::{exec_func, Block, Exit, FuncIr, MapMem, MemIo, Op, RBX};

    fn taken(predicate: &Predicate, value: u64) -> bool {
        let func = FuncIr {
            name: predicate.name.into(),
            rva: 0,
            entry: 0,
            blocks: vec![
                Block {
                    ops: (predicate.ops)(),
                    exit: Exit::Jcc(predicate.cond, 1, 2),
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
            ],
        };
        let mut arch = [0u64; 16];
        arch[0] = value;
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
        .expect("predicate");
        arch[RBX as usize] == 1
    }

    #[test]
    fn predicates_are_true_for_every_u8() {
        let all = predicates();
        assert!(all.len() >= 3, "{}", all.len());
        let extras = [
            0x100u64,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            0xffff_ffff_ffff_ffff,
        ];
        for predicate in all {
            assert!(!predicate.proof.is_empty(), "{}", predicate.name);
            assert_eq!(identify(&(predicate.ops)()), Some(predicate.name));
            for value in 0..=255u64 {
                assert!(taken(predicate, value), "{} {value}", predicate.name);
            }
            for value in extras {
                assert!(taken(predicate, value), "{} {value:#x}", predicate.name);
            }
        }
    }
}
