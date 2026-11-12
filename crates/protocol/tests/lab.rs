mod common;

use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use common::hex;
use sha2::{Digest as _, Sha256};
use vmkek_protocol::lab::{Instruction, LabProgram, ScalarType};
use vmkek_protocol::{
    Budgets, Capability, ExecutionControl, Profile, Scalar, VerifiedProgram, VmDescriptor, VmError,
    VmForm, ABI_VERSION, COPY_INPUT_CAPABILITY, MAX_BODY_BYTES,
};

fn descriptor(bytes: &[u8]) -> VmDescriptor {
    VmDescriptor {
        abi_version: ABI_VERSION,
        app_id: [1; 16],
        build_id: [2; 16],
        function_id: [3; 16],
        generation_id: [4; 16],
        form: VmForm::Stack,
        depth: 2,
        capabilities: vec![Capability {
            id: COPY_INPUT_CAPABILITY,
            required: true,
        }],
        program_sha256: Sha256::digest(bytes).into(),
        budgets: Budgets::default(),
        profile: Profile::Lab,
        extensions: Vec::new(),
    }
}

fn golden_program() -> LabProgram {
    LabProgram {
        arguments: vec![ScalarType::U64, ScalarType::I64],
        result: Some(ScalarType::I64),
        instructions: vec![
            Instruction::Argument(0),
            Instruction::JumpIfZero(7),
            Instruction::Argument(1),
            Instruction::Constant(Scalar::I64(-7)),
            Instruction::Add,
            Instruction::CopyInput,
            Instruction::Return,
            Instruction::Constant(Scalar::I64(42)),
            Instruction::Return,
        ],
    }
}

fn control(cancelled: &AtomicBool) -> ExecutionControl<'_> {
    ExecutionControl {
        cancelled,
        deadline: Instant::now() + Duration::from_secs(5),
    }
}

#[test]
fn independent_typed_program_preserves_signed_values_and_copies_only_on_the_taken_path() {
    let bytes = hex(include_str!("fixtures/lab-program-v1.hex"));
    assert_eq!(golden_program().encode().unwrap(), bytes);
    let descriptor_bytes = hex(include_str!("fixtures/descriptor-v1.hex"));
    let descriptor = VmDescriptor::decode(&descriptor_bytes).unwrap();
    let program = VerifiedProgram::verify(&descriptor, &bytes).unwrap();
    let flag = AtomicBool::new(false);
    let control = control(&flag);
    let ran = program
        .execute(&[Scalar::U64(1), Scalar::I64(-4)], b"sample", 6, &control)
        .unwrap();
    assert_eq!(ran.value, Some(Scalar::I64(-11)));
    assert_eq!(ran.output.as_slice(), b"sample");

    let alternate = program
        .execute(&[Scalar::U64(0), Scalar::I64(-4)], b"sample", 0, &control)
        .unwrap();
    assert_eq!(alternate.value, Some(Scalar::I64(42)));
    assert!(alternate.output.is_empty());
    assert_eq!(
        program
            .execute(&[Scalar::I64(1), Scalar::I64(-4)], b"sample", 6, &control)
            .err(),
        Some(VmError::InvalidInput)
    );
}

fn program(instructions: Vec<Instruction>, result: Option<ScalarType>) -> LabProgram {
    LabProgram {
        arguments: Vec::new(),
        result,
        instructions,
    }
}

fn invalid(candidate: LabProgram) {
    let bytes = candidate.encode().unwrap();
    assert_eq!(
        VerifiedProgram::verify(&descriptor(&bytes), &bytes).err(),
        Some(VmError::InvalidProgram)
    );
}

#[test]
fn verifier_rejects_bad_indices_stack_effects_joins_and_fallthrough() {
    use Instruction::*;

    for instructions in [
        vec![Argument(0), Return],
        vec![Add, Return],
        vec![Jump(100), Return],
        vec![Return, Jump(100)],
        vec![Constant(Scalar::U64(1))],
        vec![
            Constant(Scalar::U64(1)),
            Constant(Scalar::I64(2)),
            Add,
            Return,
        ],
    ] {
        invalid(program(instructions, None));
    }
    invalid(program(
        vec![
            Constant(Scalar::U64(1)),
            JumpIfZero(4),
            Constant(Scalar::U64(2)),
            Jump(5),
            Constant(Scalar::I64(2)),
            Return,
        ],
        Some(ScalarType::U64),
    ));
    let mut excessive = vec![Constant(Scalar::U64(0)); 33];
    excessive.push(Return);
    invalid(program(excessive, None));
}

#[test]
fn verifier_rejects_host_operations_undeclared_copy_and_wrong_program_digest() {
    let mut bytes = program(vec![Instruction::Return], None).encode().unwrap();
    let last = bytes.len() - 1;
    bytes[last] = 0x80;
    assert_eq!(
        VerifiedProgram::verify(&descriptor(&bytes), &bytes).err(),
        Some(VmError::InvalidProgram)
    );

    let bytes = program(vec![Instruction::CopyInput, Instruction::Return], None)
        .encode()
        .unwrap();
    let mut descriptor = descriptor(&bytes);
    descriptor.capabilities.clear();
    assert_eq!(
        VerifiedProgram::verify(&descriptor, &bytes).err(),
        Some(VmError::InvalidProgram)
    );
    descriptor.capabilities.push(Capability {
        id: COPY_INPUT_CAPABILITY,
        required: true,
    });
    descriptor.capabilities.push(Capability {
        id: 17,
        required: false,
    });
    assert!(VerifiedProgram::verify(&descriptor, &bytes).is_ok());
    descriptor.capabilities[1].required = true;
    assert_eq!(
        VerifiedProgram::verify(&descriptor, &bytes).err(),
        Some(VmError::Incompatible)
    );
    descriptor.capabilities.pop();
    descriptor.program_sha256[0] ^= 1;
    assert_eq!(
        VerifiedProgram::verify(&descriptor, &bytes).err(),
        Some(VmError::InvalidProgram)
    );
    descriptor.profile = Profile::Online;
    assert_eq!(
        VerifiedProgram::verify(&descriptor, &bytes).err(),
        Some(VmError::Incompatible)
    );
}

#[test]
fn runtime_enforces_fuel_cancel_deadline_and_staged_output_capacity() {
    use Instruction::*;

    let bytes = program(vec![CopyInput, Jump(1)], None).encode().unwrap();
    let mut desc = descriptor(&bytes);
    desc.budgets.fuel = 16;
    let loop_program = VerifiedProgram::verify(&desc, &bytes).unwrap();
    let flag = AtomicBool::new(false);
    let control = control(&flag);
    assert_eq!(
        loop_program
            .execute(&[], b"copy then exhaust", 64, &control)
            .err(),
        Some(VmError::FuelExhausted)
    );
    assert_eq!(
        loop_program.execute(&[], b"sample", 5, &control).err(),
        Some(VmError::OutputTooSmall)
    );
    assert_eq!(
        loop_program.execute(&[], b"sample", 6, &control).err(),
        Some(VmError::FuelExhausted)
    );
    let expired = ExecutionControl {
        deadline: Instant::now(),
        cancelled: &flag,
    };
    assert_eq!(
        loop_program.execute(&[], b"", 0, &expired).err(),
        Some(VmError::DeadlineExpired)
    );
    flag.store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(
        loop_program.execute(&[], b"", 0, &control).err(),
        Some(VmError::Cancelled)
    );
}

#[test]
fn zero_length_and_maximum_local_buffers_are_bounded() {
    let bytes = program(vec![Instruction::CopyInput, Instruction::Return], None)
        .encode()
        .unwrap();
    let program = VerifiedProgram::verify(&descriptor(&bytes), &bytes).unwrap();
    let flag = AtomicBool::new(false);
    let control = control(&flag);
    let empty = program.execute(&[], b"", 0, &control).unwrap();
    assert!(empty.output.is_empty());
    assert_eq!(empty.value, None);

    let input = vec![0x5a; MAX_BODY_BYTES];
    let full = program
        .execute(&[], &input, MAX_BODY_BYTES, &control)
        .unwrap();
    assert_eq!(full.output.as_slice(), input);
    assert_eq!(
        program.required_call_bytes(MAX_BODY_BYTES + 1, 0),
        Err(VmError::ResourceLimit)
    );
    assert_eq!(
        VerifiedProgram::verification_bytes(usize::MAX),
        Err(VmError::ResourceLimit)
    );
}
