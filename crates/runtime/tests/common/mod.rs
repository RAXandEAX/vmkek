use sha2::{Digest as _, Sha256};
use vmkek_protocol::lab::{Instruction, LabProgram, ScalarType};
use vmkek_protocol::{
    Budgets, Capability, Profile, Scalar, VmDescriptor, VmForm, COPY_INPUT_CAPABILITY,
};

pub fn sample_program() -> LabProgram {
    use Instruction::{Add, Argument, Constant, CopyInput, JumpIfZero, Return};
    LabProgram {
        arguments: vec![ScalarType::U64, ScalarType::I64],
        result: Some(ScalarType::I64),
        instructions: vec![
            Argument(0),
            JumpIfZero(7),
            Argument(1),
            Constant(Scalar::I64(-7)),
            Add,
            CopyInput,
            Return,
            Constant(Scalar::I64(42)),
            Return,
        ],
    }
}

pub fn descriptor(program: &[u8], budgets: Budgets, copy: bool) -> VmDescriptor {
    let capabilities = copy.then_some(Capability {
        id: COPY_INPUT_CAPABILITY,
        required: true,
    });
    VmDescriptor {
        abi_version: vmkek_protocol::ABI_VERSION,
        app_id: [1; 16],
        build_id: [2; 16],
        function_id: [3; 16],
        generation_id: [4; 16],
        form: VmForm::Stack,
        depth: 2,
        capabilities: capabilities.into_iter().collect(),
        program_sha256: Sha256::digest(program).into(),
        budgets,
        profile: Profile::Lab,
        extensions: Vec::new(),
    }
}
