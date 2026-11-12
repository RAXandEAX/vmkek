// The arithmetic definitions shared by the verified plan and the proof generator.

#[derive(Clone, Copy)]
pub enum Operation {
    Add,
    Subtract,
}

#[derive(Clone, Copy)]
pub struct Rule {
    pub operation: Operation,
    pub negate_sum: bool,
}

pub const RULES: [Rule; 2] = [
    Rule {
        operation: Operation::Add,
        negate_sum: false,
    },
    Rule {
        operation: Operation::Subtract,
        negate_sum: true,
    },
];

impl Rule {
    pub fn immediate(self, first: u64, second: u64) -> u64 {
        let sum = first.wrapping_add(second);
        if self.negate_sum {
            sum.wrapping_neg()
        } else {
            sum
        }
    }

    pub fn apply(self, input: u64, immediate: u64) -> u64 {
        match self.operation {
            Operation::Add => input.wrapping_add(immediate),
            Operation::Subtract => input.wrapping_sub(immediate),
        }
    }
}
