use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use super::fusion::{evaluate, WIDTH};
use super::r06_rules::Rule;
use super::verify::Plan;
use super::{Instruction, LabProgram, Scalar, VerifiedProgram, VmError, MAX_OPERAND_STACK};

type Result<T> = std::result::Result<T, VmError>;

pub struct ExecutionControl<'a> {
    pub deadline: Instant,
    pub cancelled: &'a AtomicBool,
}

impl ExecutionControl<'_> {
    pub(super) fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(VmError::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(VmError::DeadlineExpired)
        } else {
            Ok(())
        }
    }
}

pub struct Execution {
    pub value: Option<Scalar>,
    pub output: Zeroizing<Vec<u8>>,
}

impl Drop for Execution {
    fn drop(&mut self) {
        if let Some(value) = &mut self.value {
            value.zeroize();
        }
    }
}

impl VerifiedProgram {
    /// Execute with staged output, which the local caller can commit after its ABI checks.
    pub fn execute(
        &self,
        args: &[Scalar],
        input: &[u8],
        output_capacity: usize,
        control: &ExecutionControl<'_>,
    ) -> Result<Execution> {
        self.required_call_bytes(input.len(), output_capacity)?;
        let entry = self.entry();
        if args.len() != entry.arguments.len()
            || args
                .iter()
                .zip(&entry.arguments)
                .any(|(value, kind)| value.kind() != *kind)
        {
            return Err(VmError::InvalidInput);
        }
        let limit = Duration::from_millis(u64::from(self.budgets.deadline_ms));
        let deadline = Instant::now()
            .checked_add(limit)
            .ok_or(VmError::DeadlineExpired)?;
        let control = ExecutionControl {
            deadline: control.deadline.min(deadline),
            cancelled: control.cancelled,
        };
        match &self.plan {
            Plan::Stack { program, fusion } => run_stack(
                program,
                fusion,
                self.budgets.fuel,
                args,
                input,
                output_capacity,
                &control,
            ),
            Plan::Regions(regions) => regions.run(
                self.budgets,
                args,
                input,
                output_capacity,
                &control,
                self.layers.as_deref(),
            ),
        }
    }
}

fn run_stack(
    program: &LabProgram,
    fusion: &super::fusion::FusionPlan,
    mut fuel: u64,
    args: &[Scalar],
    input: &[u8],
    output_capacity: usize,
    control: &ExecutionControl<'_>,
) -> Result<Execution> {
    let mut stack = OperandStack::new();
    let mut output = Zeroizing::new(Vec::new());
    let mut at = 0;
    loop {
        control.check()?;
        if let Some(rule) = fusion.get(at) {
            fused_add(rule, program.instructions[at], &mut stack, &mut fuel)?;
            at += WIDTH;
            continue;
        }
        charge(&mut fuel, 1)?;
        match program.instructions[at] {
            Instruction::Argument(index) => stack.push(args[usize::from(index)])?,
            Instruction::Constant(value) => stack.push(value)?,
            Instruction::Add => {
                let right = stack.pop()?;
                let left = stack.pop()?;
                stack.push(add(left, right)?)?;
            }
            Instruction::Jump(target) => {
                at = target as usize;
                continue;
            }
            Instruction::JumpIfZero(target) => {
                if is_zero(stack.pop()?) {
                    at = target as usize;
                    continue;
                }
            }
            Instruction::CopyInput => {
                stage_copy(input, output_capacity, &mut output, &mut fuel, control)?;
            }
            Instruction::Call(_) | Instruction::Duplicate => return Err(VmError::InvalidProgram),
            Instruction::Return => {
                control.check()?;
                let value = program.result.map(|_| stack.pop()).transpose()?;
                return Ok(Execution { value, output });
            }
        }
        at += 1;
    }
}

fn fused_add(
    rule: Rule,
    head: Instruction,
    stack: &mut OperandStack,
    fuel: &mut u64,
) -> Result<()> {
    charge(fuel, WIDTH as u64)?;
    let Instruction::Constant(immediate) = head else {
        return Err(VmError::InvalidProgram);
    };
    let value = stack.pop()?;
    stack.push(evaluate(rule, value, immediate)?)
}

pub(super) fn charge(fuel: &mut u64, cost: u64) -> Result<()> {
    *fuel = fuel.checked_sub(cost).ok_or(VmError::FuelExhausted)?;
    Ok(())
}

pub(super) fn stage_copy(
    input: &[u8],
    capacity: usize,
    output: &mut Zeroizing<Vec<u8>>,
    fuel: &mut u64,
    control: &ExecutionControl<'_>,
) -> Result<()> {
    if input.len() > capacity {
        return Err(VmError::OutputTooSmall);
    }
    charge(fuel, input.len() as u64)?;
    control.check()?;
    if output.capacity() < input.len() {
        let additional = input.len() - output.len();
        output
            .try_reserve_exact(additional)
            .map_err(|_| VmError::ResourceLimit)?;
    }
    output.clear();
    for chunk in input.chunks(1024) {
        control.check()?;
        output.extend_from_slice(chunk);
    }
    control.check()
}

pub(super) struct OperandStack {
    pub(super) values: Zeroizing<[Scalar; MAX_OPERAND_STACK]>,
    pub(super) len: usize,
}

impl OperandStack {
    pub(super) fn new() -> Self {
        Self {
            values: Zeroizing::new([Scalar::U64(0); MAX_OPERAND_STACK]),
            len: 0,
        }
    }

    pub(super) fn push(&mut self, value: Scalar) -> Result<()> {
        *self
            .values
            .get_mut(self.len)
            .ok_or(VmError::InvalidProgram)? = value;
        self.len += 1;
        Ok(())
    }

    pub(super) fn pop(&mut self) -> Result<Scalar> {
        self.len = self.len.checked_sub(1).ok_or(VmError::InvalidProgram)?;
        let value = self.values[self.len];
        self.values[self.len].zeroize();
        Ok(value)
    }
}

pub(super) fn add(left: Scalar, right: Scalar) -> Result<Scalar> {
    match (left, right) {
        (Scalar::U64(left), Scalar::U64(right)) => Ok(Scalar::U64(left.wrapping_add(right))),
        (Scalar::I64(left), Scalar::I64(right)) => Ok(Scalar::I64(left.wrapping_add(right))),
        _ => Err(VmError::InvalidProgram),
    }
}

pub(super) fn is_zero(value: Scalar) -> bool {
    match value {
        Scalar::U64(value) => value == 0,
        Scalar::I64(value) => value == 0,
    }
}
