//! Bounded adversary for machine M-ADV.
//!
//! The search symbolically executes a repository fixture up to [`STEP_BUDGET`]
//! instructions and folds the resulting register with the S1 identity catalog.
//! Open `mix` IR yields the sample formula. Bytecode sealed after S2, the C3
//! predicates, and the block cipher does not, inside that budget. The C3 hash
//! is concrete and does not depend on the sample input, so that arm is taken
//! as a single path.
//!
//! The claim records a measurement of this adversary on that fixture.

#[cfg(test)]
mod decode;
#[cfg(test)]
mod expr;
#[cfg(test)]
mod machine;
#[cfg(test)]
mod mba;
#[cfg(test)]
mod search;

use crate::isa::census::Machine;

/// Instructions this adversary may execute, and the deepest path it may follow.
///
/// Straight-line `mix` finishes in a handful of steps. On the sealed fixture
/// the same search first rebuilds the formula hundreds of steps later.
pub const STEP_BUDGET: u32 = 256;

/// What the M-ADV rows claim. A reading of this adversary, not of every analyst.
pub const MEASUREMENT: &str = "Измерение против этого противника на фикстуре sample в фиксированном бюджете шагов. Не доказательство стойкости против любого аналитика.";

/// One M-ADV proof row. Not a [`crate::proof::PassClaim`]: that registry is shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub id: &'static str,
    pub channel: &'static str,
    pub machine: &'static str,
    pub anchor: &'static str,
    pub statement: &'static str,
}

/// Local claim table for C4. Both rows are this measurement on M-ADV.
#[must_use]
pub fn claims() -> &'static [Claim] {
    const CLAIMS: &[Claim] = &[
        Claim {
            id: "open-ir-formula",
            channel: "System",
            machine: Machine::MAdv.as_str(),
            anchor: "open_ir_recovers_the_sample_formula",
            statement: MEASUREMENT,
        },
        Claim {
            id: "protected-bytecode-budget",
            channel: "System",
            machine: Machine::MAdv.as_str(),
            anchor: "protected_bytecode_stays_inside_the_step_budget",
            statement: MEASUREMENT,
        },
    ];
    CLAIMS
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::ir::{FuncIr, Op, V_OPA0, V_OPA1};
    use crate::lift::lift;
    use crate::obf::obfuscate;
    use crate::vm::{self, plain_insn};
    use crate::{pe, sample};

    const FIXTURE_SEED: u64 = 0x00C4_5EED;

    #[test]
    fn open_ir_recovers_the_sample_formula() {
        let func = mix_ir();
        let got = search::run_ir(&func, STEP_BUDGET);
        let expr = got.recovered.expect("formula");
        assert!(got.steps < 16, "open mix took {} steps", got.steps);
        assert!(got.steps < STEP_BUDGET, "steps {}", got.steps);
        assert_eq!(expr::render(&expr), expr::FORMULA);
        assert_eq!(mba::simplify(&expr), expr::reference());
        for value in [0u64, 1, 2, 10, 255, u64::MAX] {
            assert_eq!(expr::eval(&expr, value), sample::mix(value), "{value}");
        }
    }

    #[test]
    fn protected_bytecode_stays_inside_the_step_budget() {
        let func = mix_ir();
        let (passes, image) = protect(&func);
        assert_s2_and_c3(&passes, &image.funcs[0].name);
        assert_block_cipher(&image);
        let got = search::run_bytecode(&image, STEP_BUDGET);
        assert!(got.recovered.is_none(), "steps {}", got.steps);
        assert_eq!(got.steps, STEP_BUDGET, "search ended before the budget");
    }

    #[test]
    fn input_independent_simplifier_misses_the_sample_formula() {
        let func = mix_ir();
        let open = search::run_ir(&func, STEP_BUDGET);
        assert_eq!(expr::render(&open.recovered.expect("ir")), expr::FORMULA);
        let mut rng = ChaCha20Rng::seed_from_u64(FIXTURE_SEED);
        let image = vm::lower_image(std::slice::from_ref(&func), &mut rng).unwrap();
        assert_eq!(image.funcs[0].form, vm::MachineForm::Register);
        assert!(image.funcs[0].single_path, "lifted mix is one path");
        assert!(image.funcs[0].data_dependent);
        let kept = search::run_bytecode(&image, STEP_BUDGET);
        let kept = kept.recovered.expect("schedule kept");
        assert_eq!(expr::render(&kept), expr::FORMULA);
        let dropped = search::run_discarding(&image, STEP_BUDGET);
        assert!(dropped.recovered.is_none(), "discarded schedule recovered");
        let (_passes, protected) = protect(&func);
        let hidden = search::run_discarding(&protected, STEP_BUDGET);
        assert!(hidden.recovered.is_none(), "protected discard recovered");
    }

    #[test]
    fn claim_measures_this_adversary_on_m_adv() {
        let rows = claims();
        assert_eq!(rows.len(), 2);
        let text = rows.iter().map(|row| row.statement).collect::<String>();
        assert!(text.contains("этого противника"));
        assert!(text.contains("Не доказательство стойкости против любого аналитика"));
        let lower = text.to_lowercase();
        assert!(!lower.contains("black-box"), "{text}");
        assert!(!lower.contains("black box"), "{text}");
        for row in rows {
            assert_eq!(row.channel, "System");
            assert_eq!(row.machine, Machine::MAdv.as_str());
            assert_eq!(row.statement, MEASUREMENT);
            assert!(!row.anchor.is_empty());
        }
    }

    fn mix_ir() -> FuncIr {
        let built = sample::build().expect("sample");
        let image = pe::parse(&built.bytes).expect("pe");
        let sym = built
            .symbols
            .iter()
            .find(|item| item.name == "mix")
            .expect("mix");
        let bytes = pe::read_rva(&image, sym.rva, sym.size as usize).expect("bytes");
        lift("mix", bytes, sym.rva, sym.size, image.image_base).expect("lift")
    }

    fn protect(func: &FuncIr) -> (Vec<&'static str>, vm::BcImage) {
        let mut rng = ChaCha20Rng::seed_from_u64(FIXTURE_SEED);
        let obf = obfuscate(func, &mut rng);
        let image = vm::lower_image(std::slice::from_ref(&obf.func), &mut rng).expect("lower");
        (obf.passes, image)
    }

    fn assert_s2_and_c3(passes: &[&str], name: &str) {
        assert_eq!(name, "mix");
        for pass in ["data-mix", "opaque-predicate", "control-flow-flatten"] {
            assert!(passes.contains(&pass), "{pass}");
        }
    }

    fn assert_block_cipher(image: &vm::BcImage) {
        let func = image
            .funcs
            .iter()
            .find(|item| item.name == "mix")
            .expect("mix");
        assert_eq!(
            func.key.bytes(),
            vm::block_key(func.key_seed, func.rva, &func.salt)
        );
        let plain = plain_insn(func, 0, &image.inv).expect("plain");
        assert_ne!(func.insns[0].bytes, plain);
        assert!(image.funcs.iter().all(|item| !item.insns.is_empty()));
    }

    #[test]
    fn protected_ir_uses_a_c3_predicate() {
        let func = mix_ir();
        let (passes, image) = protect(&func);
        assert!(passes.contains(&"opaque-predicate"));
        let mut rng = ChaCha20Rng::seed_from_u64(FIXTURE_SEED);
        let obf = obfuscate(&func, &mut rng);
        assert!(has_hard_predicate(&obf.func), "hard predicate missing");
        assert!(has_c3_predicate(&obf.func), "predicate missing");
        assert!(image.funcs.iter().any(|item| item.name == "mix"));
    }

    fn has_hard_predicate(func: &FuncIr) -> bool {
        let hard = crate::obf::hard::embedded_ops();
        func.blocks.iter().any(|block| block.ops == hard)
    }

    fn has_c3_predicate(func: &FuncIr) -> bool {
        func.blocks.iter().any(|block| {
            matches_product(&block.ops)
                || matches_xor(&block.ops)
                || matches_sub(&block.ops)
                || matches_and(&block.ops)
        })
    }

    fn matches_product(ops: &[Op]) -> bool {
        ops.windows(5).any(|window| {
            matches!(
                window,
                [
                    Op::MovRr(V_OPA0, 0),
                    Op::MovRr(V_OPA1, V_OPA0),
                    Op::AddRi(V_OPA1, 1),
                    Op::ImulRr(V_OPA1, V_OPA0),
                    Op::TestRi(V_OPA1, 1),
                ]
            )
        })
    }

    fn matches_xor(ops: &[Op]) -> bool {
        ops.windows(3).any(|window| {
            matches!(
                window,
                [
                    Op::MovRr(V_OPA0, 0),
                    Op::MovRr(V_OPA1, V_OPA0),
                    Op::XorRr(V_OPA1, V_OPA0)
                ]
            )
        })
    }

    fn matches_sub(ops: &[Op]) -> bool {
        ops.windows(3).any(|window| {
            matches!(
                window,
                [
                    Op::MovRr(V_OPA0, 0),
                    Op::MovRr(V_OPA1, V_OPA0),
                    Op::SubRr(V_OPA1, V_OPA0)
                ]
            )
        })
    }

    fn matches_and(ops: &[Op]) -> bool {
        ops.windows(4).any(|window| {
            matches!(
                window,
                [
                    Op::MovRr(V_OPA0, 0),
                    Op::MovRr(V_OPA1, V_OPA0),
                    Op::Not(V_OPA1),
                    Op::AndRr(V_OPA1, V_OPA0),
                ]
            )
        })
    }
}
