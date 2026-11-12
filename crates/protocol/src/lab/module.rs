use super::program::ProgramFields;
use super::{LabProgram, VmError};
use crate::canonical::{push_field, Reader, HEADER_BYTES, LAB_PROGRAM};
use crate::{MAX_BODY_BYTES, MAX_CALL_DEPTH};

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u16)]
pub(super) enum Version {
    Single = 1,
    Forward = 2,
    SelfCall = 3,
}

impl Version {
    pub(super) fn read(bytes: &[u8]) -> Result<Self, VmError> {
        match Reader::new(bytes).u16()? {
            1 => Ok(Self::Single),
            2 => Ok(Self::Forward),
            3 => Ok(Self::SelfCall),
            _ => Err(VmError::Incompatible),
        }
    }

    pub(super) fn is_module(self) -> bool {
        self != Self::Single
    }

    pub(super) fn allows_self_call(self) -> bool {
        self == Self::SelfCall
    }
}

pub(super) const MAX_FUNCTIONS: usize = MAX_CALL_DEPTH as usize;

/// A bounded local Lab module. Function zero is its ABI entry.
pub struct LabModule {
    pub functions: Vec<LabProgram>,
}

impl LabModule {
    pub fn encode(&self) -> Result<Vec<u8>, VmError> {
        self.encode_version(Version::Forward)
    }

    /// Encode a research-only version 3 module that may use typed self-calls.
    pub fn encode_recursive(&self) -> Result<Vec<u8>, VmError> {
        self.encode_version(Version::SelfCall)
    }

    fn encode_version(&self, version: Version) -> Result<Vec<u8>, VmError> {
        if self.functions.is_empty() || self.functions.len() > MAX_FUNCTIONS {
            return Err(VmError::InvalidProgram);
        }
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(version as u16).to_le_bytes());
        encoded.extend_from_slice(&LAB_PROGRAM.to_le_bytes());
        encoded.extend_from_slice(&[0; 4]);
        push_field(&mut encoded, &[self.functions.len() as u8]);
        for function in &self.functions {
            let body = function.encode_body(true)?;
            if encoded.len() + 4 + body.len() > MAX_BODY_BYTES {
                return Err(VmError::ResourceLimit);
            }
            push_field(&mut encoded, &body);
        }
        let body_size = (encoded.len() - HEADER_BYTES) as u32;
        encoded[4..HEADER_BYTES].copy_from_slice(&body_size.to_le_bytes());
        Ok(encoded)
    }
}

pub(super) fn read(bytes: &[u8], version: Version) -> Result<Vec<ProgramFields<'_>>, VmError> {
    let (mut reader, count) = header(bytes, version)?;
    let mut functions = Vec::new();
    functions
        .try_reserve_exact(count)
        .map_err(|_| VmError::ResourceLimit)?;
    for _ in 0..count {
        functions.push(next(&mut reader)?);
    }
    reader.finish()?;
    Ok(functions)
}

pub(super) fn counts(bytes: &[u8], version: Version) -> Result<(usize, usize), VmError> {
    let (mut reader, count) = header(bytes, version)?;
    let mut instructions = 0;
    for _ in 0..count {
        instructions += next(&mut reader)?.count;
    }
    reader.finish()?;
    Ok((count, instructions))
}

fn header(bytes: &[u8], version: Version) -> Result<(Reader<'_>, usize), VmError> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(VmError::ResourceLimit);
    }
    let mut reader = Reader::new(bytes);
    if reader.u16()? != version as u16 || reader.u16()? != LAB_PROGRAM {
        return Err(VmError::Incompatible);
    }
    if reader.u32()? as usize != bytes.len() - HEADER_BYTES {
        return Err(VmError::InvalidProgram);
    }
    let count = usize::from(reader.field_u8()?);
    if count == 0 || count > MAX_FUNCTIONS {
        return Err(VmError::InvalidProgram);
    }
    Ok((reader, count))
}

fn next<'a>(reader: &mut Reader<'a>) -> Result<ProgramFields<'a>, VmError> {
    ProgramFields::read_body(reader.field(MAX_BODY_BYTES)?)
}
