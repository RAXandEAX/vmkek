use std::mem::size_of;

use zeroize::{Zeroize, Zeroizing};

use super::execute::{add, charge, is_zero, stage_copy, OperandStack};
use super::layers::Layers;
use super::program::ProgramFields;
use super::verify::{program_memory, validate_instructions, verify_flow, StackState};
use super::wipe::WipeVec;
use super::{
    Execution, ExecutionControl, Instruction, LabProgram, Scalar, VmError, MAX_OPERAND_STACK,
    MAX_SCALAR_ARGS,
};
use crate::{Budgets, Id, VmDescriptor};

type Result<T> = std::result::Result<T, VmError>;

#[derive(Clone, Copy)]
pub(super) enum RegionForm {
    Stack,
    Register,
    Mixed,
}

pub(super) struct VerifiedRegions {
    functions: Vec<LabProgram>,
    layouts: Vec<RegionLayout>,
    form: RegionForm,
    generation: Id,
}

struct RegionLayout {
    flow: WipeVec<Option<StackState>>,
    entries: WipeVec<bool>,
}

impl VerifiedRegions {
    pub(super) fn new(
        functions: Vec<LabProgram>,
        form: RegionForm,
        descriptor: &VmDescriptor,
        self_calls: bool,
    ) -> Result<Self> {
        let mut layouts = Vec::new();
        layouts
            .try_reserve_exact(functions.len())
            .map_err(|_| VmError::ResourceLimit)?;
        for (index, function) in functions.iter().enumerate() {
            validate_instructions(function, descriptor.permits_copy_input())?;
            let flow = verify_flow(function, index, &functions, self_calls)?;
            let entries = boundaries(function, form)?;
            layouts.push(RegionLayout { flow, entries });
        }
        Ok(Self {
            functions,
            layouts,
            form,
            generation: descriptor.generation_id,
        })
    }

    pub(super) fn verification_overhead(functions: usize) -> usize {
        functions
            * (size_of::<ProgramFields<'static>>()
                + size_of::<LabProgram>()
                + size_of::<RegionLayout>()
                + MAX_SCALAR_ARGS)
    }

    pub(super) fn memory_bytes(&self) -> usize {
        self.functions.capacity() * size_of::<LabProgram>()
            + self.layouts.capacity() * size_of::<RegionLayout>()
            + self.functions.iter().map(program_memory).sum::<usize>()
            + self
                .layouts
                .iter()
                .map(|layout| {
                    layout.flow.capacity() * size_of::<Option<StackState>>()
                        + layout.entries.capacity()
                })
                .sum::<usize>()
    }

    pub(super) fn call_memory_bytes(&self, limit: u8, self_calls: bool) -> usize {
        let frames = if self_calls {
            usize::from(limit)
        } else {
            self.functions.len().min(usize::from(limit))
        };
        frames * (size_of::<Frame>() + size_of::<[Scalar; MAX_SCALAR_ARGS]>())
    }

    pub(super) fn entry(&self) -> &LabProgram {
        &self.functions[0]
    }

    pub(super) fn run(
        &self,
        budgets: Budgets,
        args: &[Scalar],
        input: &[u8],
        output_capacity: usize,
        control: &ExecutionControl<'_>,
        layers: Option<&Layers>,
    ) -> Result<Execution> {
        let mut run = Run {
            regions: self,
            input,
            output_capacity,
            control,
            output: Zeroizing::new(Vec::new()),
            fuel: budgets.fuel,
            depth_limit: budgets.call_depth,
            layers,
        };
        let value = run.function(0, args, 1, self.generation)?;
        Ok(Execution {
            value,
            output: run.output,
        })
    }
}

fn boundaries(function: &LabProgram, form: RegionForm) -> Result<WipeVec<bool>> {
    let mut entries = WipeVec::new();
    if !matches!(form, RegionForm::Mixed) {
        return Ok(entries);
    }
    entries
        .try_reserve_exact(function.instructions.len())
        .map_err(|_| VmError::ResourceLimit)?;
    entries.resize(function.instructions.len(), false);
    entries[0] = true;
    for (at, instruction) in function.instructions.iter().copied().enumerate() {
        if let Instruction::Jump(target) | Instruction::JumpIfZero(target) = instruction {
            entries[target as usize] = true;
        }
        if matches!(
            instruction,
            Instruction::JumpIfZero(_) | Instruction::Call(_)
        ) {
            entries[at + 1] = true;
        }
    }
    Ok(entries)
}

struct Run<'a, 'b> {
    regions: &'a VerifiedRegions,
    input: &'a [u8],
    output_capacity: usize,
    control: &'a ExecutionControl<'b>,
    output: Zeroizing<Vec<u8>>,
    fuel: u64,
    depth_limit: u8,
    layers: Option<&'a Layers>,
}

impl Run<'_, '_> {
    fn function(
        &mut self,
        index: usize,
        args: &[Scalar],
        depth: u8,
        generation: Id,
    ) -> Result<Option<Scalar>> {
        let regions = self.regions;
        if depth > self.depth_limit {
            return Err(VmError::ResourceLimit);
        }
        if generation != regions.generation {
            return Err(VmError::InvalidProgram);
        }
        let program = regions
            .functions
            .get(index)
            .ok_or(VmError::InvalidProgram)?;
        let layout = regions.layouts.get(index).ok_or(VmError::InvalidProgram)?;
        let mut frame = Frame::new(regions.form, generation);
        let mut at = 0;
        loop {
            self.control.check()?;
            charge(&mut self.fuel, 1)?;
            let state = layout.flow[at].ok_or(VmError::InvalidProgram)?;
            if layout.entries.get(at) == Some(&true) {
                frame.enter(state, args, generation)?;
            }
            let top = usize::from(state.len);
            match program.instructions[at] {
                Instruction::Argument(index) => frame.put(top, args[usize::from(index)])?,
                Instruction::Constant(value) => frame.put(top, value)?,
                Instruction::Add => frame.add(top, self.layers, &mut self.fuel, self.control)?,
                Instruction::Duplicate => frame.put(top, frame.peek(previous(top)?)?)?,
                Instruction::Jump(target) => {
                    at = target as usize;
                    continue;
                }
                Instruction::JumpIfZero(target) => {
                    if is_zero(frame.take(previous(top)?)?) {
                        at = target as usize;
                        continue;
                    }
                }
                Instruction::CopyInput => self.copy()?,
                Instruction::Call(target) => {
                    self.call(&mut frame, top, usize::from(target), depth)?
                }
                Instruction::Return => {
                    self.control.check()?;
                    return program.result.map(|_| frame.take(0)).transpose();
                }
            }
            at += 1;
        }
    }

    fn copy(&mut self) -> Result<()> {
        stage_copy(
            self.input,
            self.output_capacity,
            &mut self.output,
            &mut self.fuel,
            self.control,
        )
    }

    fn call(&mut self, frame: &mut Frame, top: usize, target: usize, depth: u8) -> Result<()> {
        self.control.check()?;
        if depth >= self.depth_limit {
            return Err(VmError::ResourceLimit);
        }
        frame.check_generation(self.regions.generation)?;
        let callee = self
            .regions
            .functions
            .get(target)
            .ok_or(VmError::InvalidProgram)?;
        let count = callee.arguments.len();
        let start = top.checked_sub(count).ok_or(VmError::InvalidProgram)?;
        let mut args = Zeroizing::new([Scalar::U64(0); MAX_SCALAR_ARGS]);
        for (index, expected) in callee.arguments.iter().copied().enumerate() {
            if frame.peek(start + index)?.kind() != expected {
                return Err(VmError::InvalidProgram);
            }
        }
        for index in (0..count).rev() {
            args[index] = frame.take(start + index)?;
        }
        if let Some(value) = self.function(target, &args[..count], depth + 1, frame.generation)? {
            frame.put(start, value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Active {
    Stack,
    Registers,
}

struct Frame {
    generation: Id,
    active: Active,
    stack: OperandStack,
    registers: Zeroizing<[Scalar; MAX_OPERAND_STACK]>,
    register_live: u32,
}

impl Frame {
    fn new(form: RegionForm, generation: Id) -> Self {
        let active = if matches!(form, RegionForm::Register) {
            Active::Registers
        } else {
            Active::Stack
        };
        Self {
            generation,
            active,
            stack: OperandStack::new(),
            registers: Zeroizing::new([Scalar::U64(0); MAX_OPERAND_STACK]),
            register_live: 0,
        }
    }

    fn check_generation(&self, generation: Id) -> Result<()> {
        if self.generation != generation {
            return Err(VmError::InvalidProgram);
        }
        Ok(())
    }

    fn enter(&mut self, expected: StackState, args: &[Scalar], generation: Id) -> Result<()> {
        self.check_generation(generation)?;
        let live = usize::from(expected.len);
        self.check_live(live)?;
        for index in 0..live {
            if self.peek(index)?.kind() != expected.kind(index)? {
                return Err(VmError::InvalidProgram);
            }
        }
        let selector = if live == 0 {
            args.first().copied()
        } else {
            Some(self.peek(live - 1)?)
        };
        let next = match selector {
            Some(Scalar::U64(value)) if value & 1 != 0 => Active::Registers,
            Some(Scalar::I64(value)) if value & 1 != 0 => Active::Registers,
            _ => Active::Stack,
        };
        self.transfer(live, next)
    }

    fn check_live(&self, live: usize) -> Result<()> {
        let register_mask = (1u64 << live).wrapping_sub(1) as u32;
        let valid = match self.active {
            Active::Stack => self.stack.len == live && self.register_live == 0,
            Active::Registers => self.stack.len == 0 && self.register_live == register_mask,
        };
        if !valid {
            return Err(VmError::InvalidProgram);
        }
        Ok(())
    }

    fn transfer(&mut self, live: usize, next: Active) -> Result<()> {
        match (self.active, next) {
            (Active::Stack, Active::Registers) => {
                for index in (0..live).rev() {
                    self.registers[index] = self.stack.pop()?;
                    self.register_live |= 1u32 << index;
                }
            }
            (Active::Registers, Active::Stack) => {
                for index in 0..live {
                    self.stack.push(self.registers[index])?;
                    self.registers[index].zeroize();
                }
                self.register_live = 0;
            }
            _ => {}
        }
        self.active = next;
        Ok(())
    }

    fn peek(&self, index: usize) -> Result<Scalar> {
        let value = match self.active {
            Active::Stack => self.stack.values[..self.stack.len].get(index),
            Active::Registers if self.register_live & register_bit(index)? != 0 => {
                self.registers.get(index)
            }
            Active::Registers => None,
        };
        value.copied().ok_or(VmError::InvalidProgram)
    }

    fn take(&mut self, index: usize) -> Result<Scalar> {
        match self.active {
            Active::Stack if index + 1 == self.stack.len => self.stack.pop(),
            Active::Stack => Err(VmError::InvalidProgram),
            Active::Registers => {
                let value = self.peek(index)?;
                self.registers[index].zeroize();
                self.register_live &= !register_bit(index)?;
                Ok(value)
            }
        }
    }

    fn put(&mut self, index: usize, value: Scalar) -> Result<()> {
        match self.active {
            Active::Stack if index == self.stack.len => self.stack.push(value),
            Active::Stack => Err(VmError::InvalidProgram),
            Active::Registers => {
                let bit = register_bit(index)?;
                if self.register_live & bit != 0 {
                    return Err(VmError::InvalidProgram);
                }
                self.registers[index] = value;
                self.register_live |= bit;
                Ok(())
            }
        }
    }

    fn add(
        &mut self,
        top: usize,
        layers: Option<&Layers>,
        fuel: &mut u64,
        control: &ExecutionControl<'_>,
    ) -> Result<()> {
        let right = previous(top)?;
        let left = previous(right)?;
        let right_value = self.take(right)?;
        let left_value = self.take(left)?;
        let result = match layers {
            Some(layers) => layers.add(left_value, right_value, fuel, control)?,
            None => add(left_value, right_value)?,
        };
        self.put(left, result)
    }
}

fn register_bit(index: usize) -> Result<u32> {
    1u32.checked_shl(index as u32)
        .ok_or(VmError::InvalidProgram)
}

fn previous(index: usize) -> Result<usize> {
    index.checked_sub(1).ok_or(VmError::InvalidProgram)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::ScalarType;

    fn signed_slot() -> StackState {
        let program = LabProgram {
            arguments: vec![ScalarType::I64],
            result: Some(ScalarType::I64),
            instructions: vec![
                Instruction::Argument(0),
                Instruction::Jump(2),
                Instruction::Return,
            ],
        };
        verify_flow(&program, 0, &[], false).unwrap()[2].unwrap()
    }

    #[test]
    fn region_moves_typed_slots_and_clears_the_outgoing_storage() {
        let generation = [4; 16];
        let mut frame = Frame::new(RegionForm::Mixed, generation);
        let expected = signed_slot();
        frame.put(0, Scalar::I64(5)).unwrap();

        assert_eq!(
            frame.enter(expected, &[], [5; 16]),
            Err(VmError::InvalidProgram)
        );
        assert!(frame.active == Active::Stack);
        assert_eq!(frame.peek(0), Ok(Scalar::I64(5)));

        frame.enter(expected, &[], generation).unwrap();
        assert!(frame.active == Active::Registers);
        assert_eq!(frame.peek(0), Ok(Scalar::I64(5)));
        assert_eq!(frame.stack.len, 0);
        assert_eq!(frame.stack.values[0], Scalar::I64(0));

        frame.take(0).unwrap();
        frame.put(0, Scalar::I64(6)).unwrap();
        frame.enter(expected, &[], generation).unwrap();
        assert!(frame.active == Active::Stack);
        assert_eq!(frame.peek(0), Ok(Scalar::I64(6)));
        assert_eq!(frame.register_live, 0);
        assert_eq!(frame.registers[0], Scalar::I64(0));
    }
}
