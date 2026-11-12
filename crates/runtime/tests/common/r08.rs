use vmkek_protocol::lab::{Instruction, LabModule, LabProgram, ScalarType};
use vmkek_protocol::{Budgets, Scalar, VmDescriptor};

pub fn addition(kind: ScalarType, copy: bool) -> LabModule {
    let mut instructions = vec![
        Instruction::Argument(0),
        Instruction::Argument(1),
        Instruction::Add,
    ];
    if copy {
        instructions.insert(0, Instruction::CopyInput);
    }
    instructions.push(Instruction::Return);
    LabModule {
        functions: vec![LabProgram {
            arguments: vec![kind, kind],
            result: Some(kind),
            instructions,
        }],
    }
}

pub fn recursive() -> LabModule {
    use Instruction::{Add, Argument, Call, Constant, Duplicate, JumpIfZero, Return};
    LabModule {
        functions: vec![LabProgram {
            arguments: vec![ScalarType::U64],
            result: Some(ScalarType::U64),
            instructions: vec![
                Argument(0),
                Duplicate,
                JumpIfZero(9),
                Constant(Scalar::U64(u64::MAX)),
                Add,
                Call(0),
                Constant(Scalar::U64(1)),
                Add,
                Return,
                Return,
            ],
        }],
    }
}

pub fn descriptor(program: &[u8], depth: u8, budgets: Budgets, copy: bool) -> VmDescriptor {
    let mut descriptor = crate::common::descriptor(program, budgets, copy);
    descriptor.depth = depth;
    descriptor
}
