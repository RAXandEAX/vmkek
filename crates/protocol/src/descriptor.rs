use sha2::{Digest as _, Sha256};

use crate::canonical::{
    decode_extensions, encode_extensions, envelope, flag, push_field, split_envelope,
    validate_extensions, Reader, DESCRIPTOR, HEADER_BYTES,
};
use crate::{
    Digest, Extension, Id, ProtocolError as Error, ABI_VERSION, MAX_ACTIVE_CONTEXTS,
    MAX_CALL_DEPTH, MAX_DEADLINE_MS, MAX_FUEL, MAX_VM_MEMORY_BYTES,
};

type Result<T> = std::result::Result<T, Error>;

pub const COPY_INPUT_CAPABILITY: u16 = 1;
/// Optional Lab execution hint. It does not change the encoded bytecode.
pub const R06_FUSION_CAPABILITY: u16 = 2;
/// Optional Lab execution hint for data-selected stack/register regions.
pub const R07_MIXED_REGIONS_CAPABILITY: u16 = 3;
const MAX_CAPABILITIES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Profile {
    Legacy = 1,
    Lab = 2,
    Online = 3,
}

impl TryFrom<u8> for Profile {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Legacy),
            2 => Ok(Self::Lab),
            3 => Ok(Self::Online),
            _ => Err(Error::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VmForm {
    Register = 1,
    Stack = 2,
}

impl TryFrom<u8> for VmForm {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Register),
            2 => Ok(Self::Stack),
            _ => Err(Error::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    pub id: u16,
    pub required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budgets {
    pub fuel: u64,
    pub memory_bytes: u32,
    pub deadline_ms: u32,
    pub active_contexts: u8,
    pub call_depth: u8,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            fuel: MAX_FUEL,
            memory_bytes: MAX_VM_MEMORY_BYTES as u32,
            deadline_ms: MAX_DEADLINE_MS,
            active_contexts: MAX_ACTIVE_CONTEXTS as u8,
            call_depth: MAX_CALL_DEPTH,
        }
    }
}

impl Budgets {
    fn validate(self) -> Result<()> {
        let limits = Self::default();
        if self.fuel == 0
            || self.fuel > limits.fuel
            || self.memory_bytes == 0
            || self.memory_bytes > limits.memory_bytes
            || self.deadline_ms == 0
            || self.deadline_ms > limits.deadline_ms
            || self.active_contexts == 0
            || self.active_contexts > limits.active_contexts
            || self.call_depth == 0
            || self.call_depth > limits.call_depth
        {
            Err(Error::Limit)
        } else {
            Ok(())
        }
    }

    fn encode(self, out: &mut Vec<u8>) {
        push_field(out, &self.fuel.to_le_bytes());
        push_field(out, &self.memory_bytes.to_le_bytes());
        push_field(out, &self.deadline_ms.to_le_bytes());
        push_field(out, &[self.active_contexts]);
        push_field(out, &[self.call_depth]);
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            fuel: reader.field_u64()?,
            memory_bytes: reader.field_u32()?,
            deadline_ms: reader.field_u32()?,
            active_contexts: reader.field_u8()?,
            call_depth: reader.field_u8()?,
        })
    }
}

/// Canonical VM identity and execution policy. Depth describes the VM layers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmDescriptor {
    pub abi_version: u16,
    pub app_id: Id,
    pub build_id: Id,
    pub function_id: Id,
    pub generation_id: Id,
    pub form: VmForm,
    pub depth: u8,
    pub capabilities: Vec<Capability>,
    pub program_sha256: Digest,
    pub budgets: Budgets,
    pub profile: Profile,
    pub extensions: Vec<Extension>,
}

impl VmDescriptor {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut body = Vec::new();
        push_field(&mut body, &self.abi_version.to_le_bytes());
        for id in [
            self.app_id,
            self.build_id,
            self.function_id,
            self.generation_id,
        ] {
            push_field(&mut body, &id);
        }
        push_field(&mut body, &[self.form as u8]);
        push_field(&mut body, &[self.depth]);
        encode_capabilities(&mut body, &self.capabilities);
        push_field(&mut body, &self.program_sha256);
        self.budgets.encode(&mut body);
        push_field(&mut body, &[self.profile as u8]);
        encode_extensions(&mut body, &self.extensions)?;
        envelope(DESCRIPTOR, body, 0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (envelope, _) = split_envelope(bytes, DESCRIPTOR, 0)?;
        let mut body = Reader::new(&envelope[HEADER_BYTES..]);
        let descriptor = Self {
            abi_version: body.field_u16()?,
            app_id: body.fixed()?,
            build_id: body.fixed()?,
            function_id: body.fixed()?,
            generation_id: body.fixed()?,
            form: VmForm::try_from(body.field_u8()?)?,
            depth: body.field_u8()?,
            capabilities: decode_capabilities(&mut body)?,
            program_sha256: body.fixed()?,
            budgets: Budgets::decode(&mut body)?,
            profile: Profile::try_from(body.field_u8()?)?,
            extensions: decode_extensions(&mut body)?,
        };
        body.finish()?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn sha256(&self) -> Result<Digest> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.abi_version != ABI_VERSION {
            return Err(Error::Version);
        }
        if !matches!(self.depth, 2..=4) {
            return Err(Error::Invalid);
        }
        self.budgets.validate()?;
        validate_capabilities(&self.capabilities)?;
        validate_extensions(&self.extensions)
    }

    pub fn requests_r06_fusion(&self) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.id == R06_FUSION_CAPABILITY)
    }

    pub fn requests_r07_mixed_regions(&self) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.id == R07_MIXED_REGIONS_CAPABILITY)
    }

    pub fn permits_copy_input(&self) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.id == COPY_INPUT_CAPABILITY)
    }
}

fn validate_capabilities(caps: &[Capability]) -> Result<()> {
    if caps.len() > MAX_CAPABILITIES {
        return Err(Error::Limit);
    }
    let mut previous = 0;
    for cap in caps {
        if cap.id <= previous {
            return Err(Error::Invalid);
        }
        if cap.required && cap.id != COPY_INPUT_CAPABILITY {
            return Err(Error::UnknownMandatory);
        }
        previous = cap.id;
    }
    Ok(())
}

fn encode_capabilities(out: &mut Vec<u8>, caps: &[Capability]) {
    let mut value = Vec::with_capacity(2 + caps.len() * 3);
    value.extend_from_slice(&(caps.len() as u16).to_le_bytes());
    for cap in caps {
        value.extend_from_slice(&cap.id.to_le_bytes());
        value.push(u8::from(cap.required));
    }
    push_field(out, &value);
}

fn decode_capabilities(body: &mut Reader<'_>) -> Result<Vec<Capability>> {
    let mut field = Reader::new(body.field(2 + MAX_CAPABILITIES * 3)?);
    let count = field.u16()? as usize;
    if count > MAX_CAPABILITIES {
        return Err(Error::Limit);
    }
    let mut caps = Vec::with_capacity(count);
    for _ in 0..count {
        caps.push(Capability {
            id: field.u16()?,
            required: flag(field.u8()?)?,
        });
    }
    field.finish()?;
    Ok(caps)
}
