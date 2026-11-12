use super::wipe::wipe_vec;

use super::{Scalar, ScalarType, VmError, MAX_SCALAR_ARGS};
use crate::canonical::{envelope, push_field, split_envelope, Reader, HEADER_BYTES, LAB_PROGRAM};
use crate::MAX_BODY_BYTES;

type Result<T> = std::result::Result<T, VmError>;

/// Branch destinations are instruction ordinals. CopyInput writes only staged output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instruction {
    Argument(u8),
    Constant(Scalar),
    Add,
    Jump(u32),
    JumpIfZero(u32),
    CopyInput,
    Return,
    /// Call a later function in a versioned Lab module.
    Call(u8),
    /// Duplicate the top typed value in a versioned Lab module.
    Duplicate,
}

#[derive(Debug, PartialEq, Eq)]
pub struct LabProgram {
    pub arguments: Vec<ScalarType>,
    pub result: Option<ScalarType>,
    pub instructions: Vec<Instruction>,
}

impl Drop for LabProgram {
    fn drop(&mut self) {
        wipe_vec(&mut self.instructions);
        wipe_vec(&mut self.arguments);
    }
}

impl LabProgram {
    /// Encode typed instructions. The descriptor verifier checks semantic validity.
    pub fn encode(&self) -> Result<Vec<u8>> {
        envelope(LAB_PROGRAM, self.encode_body(false)?, 0).map_err(Into::into)
    }

    pub(super) fn encode_body(&self, calls: bool) -> Result<Vec<u8>> {
        if !calls
            && self
                .instructions
                .iter()
                .any(|op| matches!(op, Instruction::Call(_) | Instruction::Duplicate))
        {
            return Err(VmError::Incompatible);
        }
        if self.arguments.len() > MAX_SCALAR_ARGS || self.instructions.is_empty() {
            return Err(VmError::InvalidProgram);
        }
        let mut body = Vec::new();
        let arguments: Vec<_> = self.arguments.iter().map(|kind| *kind as u8).collect();
        push_field(&mut body, &arguments);
        push_field(&mut body, &[self.result.map_or(0, |kind| kind as u8)]);
        let count = u32::try_from(self.instructions.len()).map_err(|_| VmError::ResourceLimit)?;
        push_field(&mut body, &count.to_le_bytes());
        let size = self
            .instructions
            .iter()
            .try_fold(0usize, |sum, item| sum.checked_add(item.encoded_len()))
            .ok_or(VmError::ResourceLimit)?;
        if size > MAX_BODY_BYTES - HEADER_BYTES - body.len() - 4 {
            return Err(VmError::ResourceLimit);
        }
        let mut code = Vec::with_capacity(size);
        for instruction in &self.instructions {
            instruction.encode(&mut code);
        }
        push_field(&mut body, &code);
        Ok(body)
    }
}

pub(super) struct ProgramFields<'a> {
    pub(super) arguments: &'a [u8],
    pub(super) result: Option<ScalarType>,
    pub(super) count: usize,
    instructions: &'a [u8],
}

impl<'a> ProgramFields<'a> {
    pub(super) fn read(bytes: &'a [u8]) -> Result<Self> {
        let (envelope, _) = split_envelope(bytes, LAB_PROGRAM, 0)?;
        Self::read_body(&envelope[HEADER_BYTES..])
    }

    pub(super) fn read_body(bytes: &'a [u8]) -> Result<Self> {
        let mut body = Reader::new(bytes);
        let arguments = body.field(MAX_SCALAR_ARGS)?;
        let result = match body.field_u8()? {
            0 => None,
            kind => Some(ScalarType::try_from(kind)?),
        };
        let count = body.field_u32()? as usize;
        let instructions = body.field(MAX_BODY_BYTES)?;
        body.finish()?;
        if count == 0 || count > instructions.len() {
            return Err(VmError::InvalidProgram);
        }
        Ok(Self {
            arguments,
            result,
            count,
            instructions,
        })
    }

    pub(super) fn decode(self, calls: bool) -> Result<LabProgram> {
        let mut program = LabProgram {
            arguments: Vec::new(),
            result: self.result,
            instructions: Vec::new(),
        };
        program
            .arguments
            .try_reserve_exact(self.arguments.len())
            .map_err(|_| VmError::ResourceLimit)?;
        for kind in self.arguments {
            program.arguments.push(ScalarType::try_from(*kind)?);
        }
        program
            .instructions
            .try_reserve_exact(self.count)
            .map_err(|_| VmError::ResourceLimit)?;
        let mut code = Reader::new(self.instructions);
        for _ in 0..self.count {
            program
                .instructions
                .push(Instruction::decode(&mut code, calls)?);
        }
        code.finish()?;
        Ok(program)
    }
}

impl Instruction {
    fn encoded_len(self) -> usize {
        match self {
            Self::Argument(_) | Self::Call(_) => 2,
            Self::Constant(_) => 9,
            Self::Jump(_) | Self::JumpIfZero(_) => 5,
            Self::Add | Self::CopyInput | Self::Return | Self::Duplicate => 1,
        }
    }

    fn encode(self, out: &mut Vec<u8>) {
        match self {
            Self::Argument(index) => out.extend_from_slice(&[1, index]),
            Self::Constant(Scalar::U64(value)) => {
                out.push(2);
                out.extend_from_slice(&value.to_le_bytes());
            }
            Self::Constant(Scalar::I64(value)) => {
                out.push(3);
                out.extend_from_slice(&value.to_le_bytes());
            }
            Self::Add => out.push(4),
            Self::Jump(target) => {
                out.push(5);
                out.extend_from_slice(&target.to_le_bytes());
            }
            Self::JumpIfZero(target) => {
                out.push(6);
                out.extend_from_slice(&target.to_le_bytes());
            }
            Self::CopyInput => out.push(7),
            Self::Return => out.push(8),
            Self::Call(target) => out.extend_from_slice(&[9, target]),
            Self::Duplicate => out.push(10),
        }
    }

    fn decode(code: &mut Reader<'_>, calls: bool) -> Result<Self> {
        match code.u8()? {
            1 => Ok(Self::Argument(code.u8()?)),
            2 => Ok(Self::Constant(Scalar::U64(code.u64()?))),
            3 => Ok(Self::Constant(Scalar::I64(i64::from_le_bytes(
                code.array()?,
            )))),
            4 => Ok(Self::Add),
            5 => Ok(Self::Jump(code.u32()?)),
            6 => Ok(Self::JumpIfZero(code.u32()?)),
            7 => Ok(Self::CopyInput),
            8 => Ok(Self::Return),
            9 if calls => Ok(Self::Call(code.u8()?)),
            10 if calls => Ok(Self::Duplicate),
            _ => Err(VmError::InvalidProgram),
        }
    }
}
