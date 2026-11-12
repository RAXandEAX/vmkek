use vmkek_protocol::lab::{Instruction, LabModule, LabProgram, ScalarType};
use vmkek_protocol::{
    Budgets, Capability, Scalar, VmDescriptor, VmForm, R07_MIXED_REGIONS_CAPABILITY,
};

#[derive(Clone, Copy, Debug)]
pub enum Form {
    Stack,
    Register,
    Mixed,
}

impl Form {
    pub const ALL: [Self; 3] = [Self::Stack, Self::Register, Self::Mixed];

    pub fn name(self) -> &'static str {
        match self {
            Self::Stack => "stack",
            Self::Register => "register",
            Self::Mixed => "mixed",
        }
    }

    pub fn descriptor(self, bytes: &[u8], budgets: Budgets, generation: u8) -> VmDescriptor {
        let mut descriptor = crate::common::descriptor(bytes, budgets, true);
        descriptor.generation_id = [generation; 16];
        match self {
            Self::Stack => {}
            Self::Register => descriptor.form = VmForm::Register,
            Self::Mixed => {
                descriptor.form = VmForm::Register;
                descriptor.capabilities.push(Capability {
                    id: R07_MIXED_REGIONS_CAPABILITY,
                    required: false,
                });
            }
        }
        descriptor
    }
}

pub fn module() -> LabModule {
    use Instruction::{
        Add, Argument, Call, Constant, CopyInput, Duplicate, Jump, JumpIfZero, Return,
    };
    let word = |value| Constant(Scalar::U64(value));
    LabModule {
        functions: vec![
            LabProgram {
                arguments: vec![ScalarType::U64; 3],
                result: Some(ScalarType::U64),
                instructions: vec![
                    Argument(0),
                    Argument(2),
                    JumpIfZero(6),
                    word(3),
                    Add,
                    Jump(8),
                    word(8),
                    Add,
                    Argument(1),
                    Duplicate,
                    JumpIfZero(14),
                    word(u64::MAX),
                    Add,
                    Jump(9),
                    Call(1),
                    Return,
                ],
            },
            LabProgram {
                arguments: vec![ScalarType::U64; 2],
                result: Some(ScalarType::U64),
                instructions: vec![
                    Argument(0),
                    Argument(1),
                    Add,
                    word(17),
                    Add,
                    CopyInput,
                    Return,
                ],
            },
        ],
    }
}
