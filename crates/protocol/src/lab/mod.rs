//! Typed Lab bytecode. It has no native pointers or host-call instruction.

mod execute;
mod fusion;
mod layers;
mod module;
mod program;
mod r06_rules;
mod regions;
mod verify;
mod wipe;

use zeroize::Zeroize;

pub use execute::{Execution, ExecutionControl};
pub use fusion::r06_fusion_available;
pub use module::LabModule;
pub use program::{Instruction, LabProgram};
pub use verify::VerifiedProgram;

pub const MAX_SCALAR_ARGS: usize = 32;
const MAX_OPERAND_STACK: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ScalarType {
    U64 = 1,
    I64 = 2,
}

impl TryFrom<u8> for ScalarType {
    type Error = VmError;

    fn try_from(value: u8) -> Result<Self, VmError> {
        match value {
            1 => Ok(Self::U64),
            2 => Ok(Self::I64),
            _ => Err(VmError::InvalidProgram),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    U64(u64),
    I64(i64),
}

impl Scalar {
    pub fn kind(self) -> ScalarType {
        match self {
            Self::U64(_) => ScalarType::U64,
            Self::I64(_) => ScalarType::I64,
        }
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        match self {
            Self::U64(value) => value.zeroize(),
            Self::I64(value) => value.zeroize(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VmError {
    #[error("operating-system entropy unavailable")]
    Unavailable,
    #[error("unsupported VM profile, form or layer count")]
    Incompatible,
    #[error("invalid Lab bytecode")]
    InvalidProgram,
    #[error("invalid invocation arguments")]
    InvalidInput,
    #[error("output buffer capacity is too small")]
    OutputTooSmall,
    #[error("invocation fuel exhausted")]
    FuelExhausted,
    #[error("invocation deadline expired")]
    DeadlineExpired,
    #[error("invocation cancelled")]
    Cancelled,
    #[error("resource limit exceeded")]
    ResourceLimit,
}

impl From<crate::ProtocolError> for VmError {
    fn from(value: crate::ProtocolError) -> Self {
        use crate::ProtocolError;

        match value {
            ProtocolError::Version | ProtocolError::Type | ProtocolError::UnknownMandatory => {
                Self::Incompatible
            }
            ProtocolError::Limit => Self::ResourceLimit,
            _ => Self::InvalidProgram,
        }
    }
}
