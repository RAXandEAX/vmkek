use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::r06_rules::{Rule, RULES};
use super::{Instruction, Scalar, ScalarType, VmError};
use crate::VmDescriptor;

const TARGET: u8 = 0x80;
pub(super) const WIDTH: usize = 4;

#[derive(Default)]
pub(super) struct FusionPlan {
    slots: Zeroizing<Vec<u8>>,
}

pub const fn r06_fusion_available() -> bool {
    cfg!(all(feature = "r06-experimental", r06_proved))
}

impl FusionPlan {
    pub(super) fn compile(
        descriptor: &VmDescriptor,
        code: &mut [Instruction],
    ) -> Result<Self, VmError> {
        if !descriptor.requests_r06_fusion() {
            return Ok(Self::default());
        }
        if !r06_fusion_available() {
            return Err(VmError::Incompatible);
        }
        let mut slots = Zeroizing::new(Vec::new());
        slots
            .try_reserve_exact(code.len())
            .map_err(|_| VmError::ResourceLimit)?;
        slots.resize(code.len(), 0);
        for instruction in code.iter() {
            if let Instruction::Jump(target) | Instruction::JumpIfZero(target) = *instruction {
                slots[target as usize] = TARGET;
            }
        }
        install(&scope(descriptor), code, &mut slots);
        Ok(Self { slots })
    }

    pub(super) fn get(&self, at: usize) -> Option<Rule> {
        let tag = self.slots.get(at)? & !TARGET;
        RULES.get(usize::from(tag).checked_sub(1)?).copied()
    }

    pub(super) fn memory_bytes(&self) -> usize {
        self.slots.capacity()
    }
}

fn install(scope: &Sha256, code: &mut [Instruction], slots: &mut [u8]) {
    let mut at = 0;
    while let Some(window) = code.get_mut(at..at + WIDTH) {
        if let Some((left, right)) = pair(window, &slots[at + 1..at + WIDTH]) {
            let index = rule_index(scope, at);
            let immediate = RULES[index].immediate(bits(left), bits(right));
            window[0] = Instruction::Constant(from_bits(left.kind(), immediate));
            slots[at] |= (index + 1) as u8;
            at += WIDTH;
        } else {
            at += 1;
        }
    }
}

fn pair(window: &[Instruction], interior: &[u8]) -> Option<(Scalar, Scalar)> {
    let [Instruction::Constant(left), Instruction::Add, Instruction::Constant(right), Instruction::Add] =
        window
    else {
        return None;
    };
    if left.kind() != right.kind() || interior.iter().any(|slot| *slot & TARGET != 0) {
        return None;
    }
    Some((*left, *right))
}

fn scope(descriptor: &VmDescriptor) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(b"vmkek.r06.lab.integer-fusion.v1\0");
    for id in [
        descriptor.app_id,
        descriptor.build_id,
        descriptor.function_id,
        descriptor.generation_id,
    ] {
        hash.update(id);
    }
    hash.update(descriptor.program_sha256);
    hash
}

fn rule_index(scope: &Sha256, at: usize) -> usize {
    let mut hash = scope.clone();
    hash.update((at as u64).to_le_bytes());
    usize::from(hash.finalize()[0]) % RULES.len()
}

pub(super) fn evaluate(rule: Rule, value: Scalar, immediate: Scalar) -> Result<Scalar, VmError> {
    if value.kind() != immediate.kind() {
        return Err(VmError::InvalidProgram);
    }
    Ok(from_bits(
        value.kind(),
        rule.apply(bits(value), bits(immediate)),
    ))
}

fn bits(value: Scalar) -> u64 {
    match value {
        Scalar::U64(value) => value,
        Scalar::I64(value) => u64::from_ne_bytes(value.to_ne_bytes()),
    }
}

fn from_bits(kind: ScalarType, value: u64) -> Scalar {
    match kind {
        ScalarType::U64 => Scalar::U64(value),
        ScalarType::I64 => Scalar::I64(i64::from_ne_bytes(value.to_ne_bytes())),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{Budgets, Profile, VmForm};

    use super::*;

    fn descriptor(generation: u8) -> VmDescriptor {
        VmDescriptor {
            abi_version: crate::ABI_VERSION,
            app_id: [1; 16],
            build_id: [2; 16],
            function_id: [3; 16],
            generation_id: [generation; 16],
            form: VmForm::Stack,
            depth: 2,
            capabilities: vec![],
            program_sha256: [4; 32],
            budgets: Budgets::default(),
            profile: Profile::Lab,
            extensions: vec![],
        }
    }

    #[test]
    fn rule_forms_match_an_independent_widened_oracle() {
        let edges = [0, 1, u64::MAX, i64::MAX as u64, 1 << 63, (1 << 63) + 1];
        for input in edges {
            for first in edges {
                for second in edges {
                    let oracle =
                        (u128::from(input) + u128::from(first) + u128::from(second)) as u64;
                    for rule in RULES {
                        let result = rule.apply(input, rule.immediate(first, second));
                        assert_eq!(result, oracle);
                    }
                }
            }
        }
        for ordinal in 0u64..1024 {
            let digest = Sha256::digest(ordinal.to_le_bytes());
            let word = |offset| u64::from_le_bytes(digest[offset..offset + 8].try_into().unwrap());
            let (input, first, second) = (word(0), word(8), word(16));
            let oracle = (u128::from(input) + u128::from(first) + u128::from(second)) as u64;
            for rule in RULES {
                assert_eq!(rule.apply(input, rule.immediate(first, second)), oracle);
            }
        }
    }

    #[test]
    fn rule_selection_binds_function_and_generation() {
        let selected = (1..=32)
            .map(|generation| rule_index(&scope(&descriptor(generation)), 4))
            .collect::<BTreeSet<_>>();
        assert_eq!(selected, [0, 1].into());
        let selected = (1..=32)
            .map(|function| {
                let mut descriptor = descriptor(1);
                descriptor.function_id = [function; 16];
                rule_index(&scope(&descriptor), 4)
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(selected, [0, 1].into());
    }

    #[test]
    fn fusion_never_rewrites_a_branch_target_inside_the_window() {
        use Instruction::{Add, Constant};
        let template = [
            Constant(Scalar::U64(7)),
            Add,
            Constant(Scalar::U64(11)),
            Add,
        ];
        for target in 1..WIDTH {
            let mut code = template;
            let mut slots = [0; WIDTH];
            slots[target] = TARGET;
            install(&scope(&descriptor(1)), &mut code, &mut slots);
            assert_eq!(code, template);
            assert_eq!(slots[0], 0);
        }
        let mut code = template;
        let mut slots = [TARGET, 0, 0, 0];
        install(&scope(&descriptor(1)), &mut code, &mut slots);
        assert_ne!(slots[0] & !TARGET, 0);
        assert_eq!(slots[0] & TARGET, TARGET);
    }
}
