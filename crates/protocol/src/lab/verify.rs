use std::mem::size_of;

use sha2::{Digest as _, Sha256};

use super::fusion::FusionPlan;
use super::layers::Layers;
use super::module::{self, Version};
use super::program::ProgramFields;
use super::regions::{RegionForm, VerifiedRegions};
use super::wipe::WipeVec;
use super::{
    Instruction, LabProgram, Scalar, ScalarType, VmError, MAX_OPERAND_STACK, MAX_SCALAR_ARGS,
};
use crate::{Budgets, Profile, VmDescriptor, VmForm, MAX_BODY_BYTES, MAX_VM_MEMORY_BYTES};

type Result<T> = std::result::Result<T, VmError>;

/// A Lab program whose bytes and typed control flow have been verified.
pub struct VerifiedProgram {
    pub(super) plan: Plan,
    pub(super) budgets: Budgets,
    pub(super) layers: Option<Box<Layers>>,
    pub(super) self_calls: bool,
}

pub(super) enum Plan {
    Stack {
        program: LabProgram,
        fusion: FusionPlan,
    },
    Regions(VerifiedRegions),
}

// Keep the historical v1 Stack descriptor budget independent of the live
// Rust layout, which also accommodates R07. Process accounting uses memory_bytes.
struct V1BudgetFootprint {
    _program: LabProgram,
    _budgets: Budgets,
    _fusion: FusionPlan,
}

// Preserve the depth-2 region budget when the host adds research layer state.
struct R07BudgetFootprint {
    _plan: Plan,
    _budgets: Budgets,
}

impl VerifiedProgram {
    /// Historical conservative reservation from a v1 Stack byte length.
    pub fn verification_bytes(program_len: usize) -> Result<usize> {
        verification_size(
            program_len,
            program_len,
            usize::from(super::r06_fusion_available()),
            size_of::<V1BudgetFootprint>(),
        )
    }

    /// Actual process reservation before allocating verifier state for this mode.
    pub fn verification_bytes_for(descriptor: &VmDescriptor, bytes: &[u8]) -> Result<usize> {
        let (version, regions) = verify_mode(descriptor, bytes)?;
        let (functions, count) = if version.is_module() {
            module::counts(bytes, version)?
        } else {
            (1, ProgramFields::read(bytes)?.count)
        };
        if regions {
            return region_verification_size(
                bytes.len(),
                functions,
                count,
                descriptor.requests_r07_mixed_regions(),
                process_footprint(descriptor),
            );
        }
        verification_size(
            bytes.len(),
            count,
            usize::from(descriptor.requests_r06_fusion()),
            size_of::<Self>(),
        )
    }

    pub fn verify(descriptor: &VmDescriptor, bytes: &[u8]) -> Result<Self> {
        let (version, regions) = verify_mode(descriptor, bytes)?;
        let plan = if regions {
            verify_regions(descriptor, bytes, version)?
        } else {
            verify_stack_plan(descriptor, bytes)?
        };
        let layers = if descriptor.depth > 2 {
            Some(Box::new(Layers::generate(descriptor)?))
        } else {
            None
        };
        Ok(Self {
            plan,
            budgets: descriptor.budgets,
            layers,
            self_calls: version.allows_self_call(),
        })
    }

    pub(super) fn entry(&self) -> &LabProgram {
        match &self.plan {
            Plan::Stack { program, .. } => program,
            Plan::Regions(regions) => regions.entry(),
        }
    }

    pub fn memory_bytes(&self) -> usize {
        let owned = match &self.plan {
            Plan::Stack { program, fusion } => program_memory(program) + fusion.memory_bytes(),
            Plan::Regions(regions) => regions.memory_bytes(),
        };
        size_of::<Self>() + owned + self.layer_bytes()
    }

    fn layer_bytes(&self) -> usize {
        self.layers.as_ref().map_or(0, |_| Layers::memory_bytes())
    }

    /// Space for caller-owned input and argument copies, VM frames and staged output.
    pub fn required_call_bytes(&self, input_len: usize, output_capacity: usize) -> Result<usize> {
        if input_len > MAX_BODY_BYTES || output_capacity > MAX_BODY_BYTES {
            return Err(VmError::ResourceLimit);
        }
        let frame_bytes = match &self.plan {
            Plan::Stack { .. } => size_of::<Scalar>() * MAX_OPERAND_STACK,
            Plan::Regions(regions) => {
                regions.call_memory_bytes(self.budgets.call_depth, self.self_calls)
            }
        };
        let layer_scratch = self
            .layers
            .as_ref()
            .map_or(0, |_| Layers::call_memory_bytes());
        let bytes = input_len
            + output_capacity
            + size_of::<Scalar>() * MAX_SCALAR_ARGS
            + frame_bytes
            + layer_scratch;
        let retained = match &self.plan {
            Plan::Stack { program, fusion } => {
                size_of::<V1BudgetFootprint>() + program_memory(program) + fusion.memory_bytes()
            }
            Plan::Regions(regions) if self.layers.is_none() => {
                size_of::<R07BudgetFootprint>() + regions.memory_bytes()
            }
            Plan::Regions(_) => self.memory_bytes(),
        };
        if retained + bytes > self.budgets.memory_bytes as usize {
            return Err(VmError::ResourceLimit);
        }
        Ok(bytes)
    }
}

fn verify_mode(descriptor: &VmDescriptor, bytes: &[u8]) -> Result<(Version, bool)> {
    descriptor.validate()?;
    if descriptor.profile != Profile::Lab {
        return Err(VmError::Incompatible);
    }
    let version = Version::read(bytes)?;
    if descriptor.depth == 2 && version.allows_self_call()
        || descriptor.depth > 2 && !version.is_module()
    {
        return Err(VmError::Incompatible);
    }
    let regions = descriptor.form == VmForm::Register || version.is_module();
    if descriptor.requests_r07_mixed_regions() && descriptor.form != VmForm::Register
        || regions && descriptor.requests_r06_fusion()
    {
        return Err(VmError::Incompatible);
    }
    Ok((version, regions))
}

fn verify_stack_plan(descriptor: &VmDescriptor, bytes: &[u8]) -> Result<Plan> {
    let fields = ProgramFields::read(bytes)?;
    let extra = usize::from(descriptor.requests_r06_fusion());
    check_package(
        descriptor,
        bytes,
        verification_size(
            bytes.len(),
            fields.count,
            extra,
            size_of::<V1BudgetFootprint>(),
        )?,
    )?;
    let mut program = fields.decode(false)?;
    validate_instructions(&program, descriptor.permits_copy_input())?;
    verify_flow(&program, 0, &[], false)?;
    let fusion = FusionPlan::compile(descriptor, &mut program.instructions)?;
    Ok(Plan::Stack { program, fusion })
}

fn verify_regions(descriptor: &VmDescriptor, bytes: &[u8], version: Version) -> Result<Plan> {
    let fields = if version.is_module() {
        module::read(bytes, version)?
    } else {
        vec![ProgramFields::read(bytes)?]
    };
    let count = fields.iter().map(|function| function.count).sum();
    let estimate = region_verification_size(
        bytes.len(),
        fields.len(),
        count,
        descriptor.requests_r07_mixed_regions(),
        if descriptor.depth == 2 {
            size_of::<R07BudgetFootprint>()
        } else {
            process_footprint(descriptor)
        },
    )?;
    check_package(descriptor, bytes, estimate)?;
    let mut programs = Vec::new();
    programs
        .try_reserve_exact(fields.len())
        .map_err(|_| VmError::ResourceLimit)?;
    for fields in fields {
        programs.push(fields.decode(version.is_module())?);
    }
    let form = match (descriptor.form, descriptor.requests_r07_mixed_regions()) {
        (VmForm::Stack, _) => RegionForm::Stack,
        (VmForm::Register, false) => RegionForm::Register,
        (VmForm::Register, true) => RegionForm::Mixed,
    };
    VerifiedRegions::new(programs, form, descriptor, version.allows_self_call()).map(Plan::Regions)
}

fn check_package(descriptor: &VmDescriptor, bytes: &[u8], estimate: usize) -> Result<()> {
    if estimate > descriptor.budgets.memory_bytes as usize {
        return Err(VmError::ResourceLimit);
    }
    if Sha256::digest(bytes).as_slice() != descriptor.program_sha256 {
        return Err(VmError::InvalidProgram);
    }
    Ok(())
}

pub(super) fn program_memory(program: &LabProgram) -> usize {
    program.arguments.capacity() * size_of::<ScalarType>()
        + program.instructions.capacity() * size_of::<Instruction>()
}

fn process_footprint(descriptor: &VmDescriptor) -> usize {
    size_of::<VerifiedProgram>()
        + if descriptor.depth > 2 {
            Layers::memory_bytes()
        } else {
            0
        }
}

fn region_verification_size(
    bytes: usize,
    functions: usize,
    count: usize,
    mixed: bool,
    footprint: usize,
) -> Result<usize> {
    verification_size(
        bytes,
        count,
        usize::from(mixed),
        footprint + VerifiedRegions::verification_overhead(functions),
    )
}

fn verification_size(bytes: usize, count: usize, extra: usize, headers: usize) -> Result<usize> {
    if bytes > MAX_BODY_BYTES {
        return Err(VmError::ResourceLimit);
    }
    let per_instruction =
        size_of::<Instruction>() + size_of::<Option<StackState>>() + size_of::<usize>() + extra;
    count
        .checked_mul(per_instruction)
        .and_then(|size| size.checked_add(bytes))
        .and_then(|size| size.checked_add(MAX_SCALAR_ARGS + headers))
        .filter(|size| *size <= MAX_VM_MEMORY_BYTES)
        .ok_or(VmError::ResourceLimit)
}

pub(super) fn validate_instructions(program: &LabProgram, permits_copy: bool) -> Result<()> {
    let count = program.instructions.len();
    for (at, instruction) in program.instructions.iter().copied().enumerate() {
        match instruction {
            Instruction::Argument(index) if usize::from(index) >= program.arguments.len() => {
                return Err(VmError::InvalidProgram);
            }
            Instruction::Jump(target) | Instruction::JumpIfZero(target)
                if target as usize >= count =>
            {
                return Err(VmError::InvalidProgram);
            }
            Instruction::CopyInput if !permits_copy => return Err(VmError::InvalidProgram),
            _ => {}
        }
        if at + 1 == count && !matches!(instruction, Instruction::Jump(_) | Instruction::Return) {
            return Err(VmError::InvalidProgram);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct StackState {
    signed: u32,
    pub(super) len: u8,
}

impl StackState {
    pub(super) fn kind(self, index: usize) -> Result<ScalarType> {
        if index >= usize::from(self.len) {
            return Err(VmError::InvalidProgram);
        }
        Ok(if self.signed & (1u32 << index) == 0 {
            ScalarType::U64
        } else {
            ScalarType::I64
        })
    }

    fn push(&mut self, kind: ScalarType) -> Result<()> {
        if usize::from(self.len) >= MAX_OPERAND_STACK {
            return Err(VmError::InvalidProgram);
        }
        if kind == ScalarType::I64 {
            self.signed |= 1u32 << self.len;
        }
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Result<ScalarType> {
        self.len = self.len.checked_sub(1).ok_or(VmError::InvalidProgram)?;
        let top = 1u32 << self.len;
        let kind = if self.signed & top == 0 {
            ScalarType::U64
        } else {
            ScalarType::I64
        };
        self.signed &= !top;
        Ok(kind)
    }

    fn verify_return(mut self, result: Option<ScalarType>) -> Result<()> {
        if self.len != u8::from(result.is_some()) {
            return Err(VmError::InvalidProgram);
        }
        if let Some(expected) = result {
            if self.pop()? != expected {
                return Err(VmError::InvalidProgram);
            }
        }
        Ok(())
    }
}

pub(super) fn verify_flow(
    program: &LabProgram,
    function: usize,
    programs: &[LabProgram],
    self_calls: bool,
) -> Result<WipeVec<Option<StackState>>> {
    let count = program.instructions.len();
    let mut states = WipeVec::new();
    states
        .try_reserve_exact(count)
        .map_err(|_| VmError::ResourceLimit)?;
    states.resize(count, None);
    let mut work = WipeVec::new();
    work.try_reserve_exact(count)
        .map_err(|_| VmError::ResourceLimit)?;
    merge(0, StackState::default(), &mut states, &mut work)?;
    while let Some(at) = work.pop() {
        let mut state = states[at].ok_or(VmError::InvalidProgram)?;
        match program.instructions[at] {
            Instruction::Jump(target) => {
                merge(target as usize, state, &mut states, &mut work)?;
                continue;
            }
            Instruction::JumpIfZero(target) => {
                state.pop()?;
                merge(target as usize, state, &mut states, &mut work)?;
            }
            Instruction::Return => {
                state.verify_return(program.result)?;
                continue;
            }
            Instruction::Call(target) => {
                apply_call(
                    &mut state,
                    function,
                    usize::from(target),
                    programs,
                    self_calls,
                )?;
            }
            instruction => apply_effect(instruction, &program.arguments, &mut state)?,
        }
        merge(at + 1, state, &mut states, &mut work)?;
    }
    if states.iter().any(Option::is_none) {
        return Err(VmError::InvalidProgram);
    }
    Ok(states)
}

fn apply_call(
    state: &mut StackState,
    source: usize,
    target: usize,
    programs: &[LabProgram],
    self_calls: bool,
) -> Result<()> {
    let callee = programs
        .get(target)
        .filter(|_| target > source || self_calls && target == source)
        .ok_or(VmError::InvalidProgram)?;
    for expected in callee.arguments.iter().rev() {
        if state.pop()? != *expected {
            return Err(VmError::InvalidProgram);
        }
    }
    if let Some(result) = callee.result {
        state.push(result)?;
    }
    Ok(())
}

fn apply_effect(
    instruction: Instruction,
    arguments: &[ScalarType],
    state: &mut StackState,
) -> Result<()> {
    match instruction {
        Instruction::Argument(index) => state.push(arguments[usize::from(index)]),
        Instruction::Constant(value) => state.push(value.kind()),
        Instruction::Add => {
            let right = state.pop()?;
            if state.pop()? != right {
                return Err(VmError::InvalidProgram);
            }
            state.push(right)
        }
        Instruction::CopyInput => Ok(()),
        Instruction::Duplicate => {
            let top = state.len.checked_sub(1).ok_or(VmError::InvalidProgram)?;
            state.push(state.kind(usize::from(top))?)
        }
        _ => Err(VmError::InvalidProgram),
    }
}

fn merge(
    at: usize,
    state: StackState,
    states: &mut [Option<StackState>],
    work: &mut Vec<usize>,
) -> Result<()> {
    let target = states.get_mut(at).ok_or(VmError::InvalidProgram)?;
    match target {
        Some(existing) if *existing != state => Err(VmError::InvalidProgram),
        Some(_) => Ok(()),
        None => {
            *target = Some(state);
            work.push(at);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::lab::{ExecutionControl, LabModule};

    fn identity() -> LabProgram {
        LabProgram {
            arguments: vec![ScalarType::U64],
            result: Some(ScalarType::U64),
            instructions: vec![Instruction::Argument(0), Instruction::Return],
        }
    }

    fn descriptor(program: &[u8], memory_bytes: usize) -> VmDescriptor {
        VmDescriptor {
            abi_version: crate::ABI_VERSION,
            app_id: [1; 16],
            build_id: [2; 16],
            function_id: [3; 16],
            generation_id: [4; 16],
            form: VmForm::Stack,
            depth: 2,
            capabilities: vec![],
            program_sha256: Sha256::digest(program).into(),
            budgets: Budgets {
                memory_bytes: memory_bytes.try_into().unwrap(),
                ..Budgets::default()
            },
            profile: Profile::Lab,
            extensions: vec![],
        }
    }

    #[test]
    fn v1_stack_keeps_its_verification_and_call_cutoffs() {
        let program = identity().encode().unwrap();
        let old_working_bytes = size_of::<V1BudgetFootprint>()
            + MAX_SCALAR_ARGS
            + program.len()
            + 2 * (size_of::<Instruction>() + size_of::<Option<StackState>>() + size_of::<usize>());
        assert!(
            VerifiedProgram::verify(&descriptor(&program, old_working_bytes), &program).is_ok()
        );
        assert!(matches!(
            VerifiedProgram::verify(&descriptor(&program, old_working_bytes - 1), &program),
            Err(VmError::ResourceLimit)
        ));
        let decoded = ProgramFields::read(&program)
            .unwrap()
            .decode(false)
            .unwrap();
        let old_call_bytes = size_of::<V1BudgetFootprint>()
            + program_memory(&decoded)
            + size_of::<Scalar>() * (MAX_SCALAR_ARGS + MAX_OPERAND_STACK);
        let old = VerifiedProgram::verify(&descriptor(&program, old_call_bytes), &program).unwrap();
        let control = ExecutionControl {
            deadline: Instant::now() + Duration::from_secs(1),
            cancelled: &AtomicBool::new(false),
        };
        assert_eq!(
            old.execute(&[Scalar::U64(9)], &[], 0, &control)
                .unwrap()
                .value,
            Some(Scalar::U64(9))
        );
        let small =
            VerifiedProgram::verify(&descriptor(&program, old_call_bytes - 1), &program).unwrap();
        assert!(matches!(
            small.execute(&[Scalar::U64(9)], &[], 0, &control),
            Err(VmError::ResourceLimit)
        ));

        let module = LabModule {
            functions: vec![identity()],
        }
        .encode()
        .unwrap();
        let new = VerifiedProgram::verify(&descriptor(&module, old_call_bytes), &module).unwrap();
        assert!(matches!(
            new.execute(&[Scalar::U64(9)], &[], 0, &control),
            Err(VmError::ResourceLimit)
        ));
    }

    #[test]
    fn v1_conservative_estimate_keeps_the_old_long_input_limit() {
        let per_byte = size_of::<Instruction>()
            + size_of::<Option<StackState>>()
            + size_of::<usize>()
            + usize::from(super::super::r06_fusion_available())
            + 1;
        let old_limit =
            (MAX_VM_MEMORY_BYTES - size_of::<V1BudgetFootprint>() - MAX_SCALAR_ARGS) / per_byte;
        assert!(VerifiedProgram::verification_bytes(old_limit).is_ok());
        assert_eq!(
            VerifiedProgram::verification_bytes(old_limit + 1),
            Err(VmError::ResourceLimit)
        );
    }
}
