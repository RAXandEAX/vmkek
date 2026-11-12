use crate::{Extension, ProtocolError as Error, MAX_BODY_BYTES, SCHEMA_VERSION};

type Result<T> = std::result::Result<T, Error>;

pub(super) const HEADER_BYTES: usize = 8;
pub(super) const SIGNATURE_BYTES: usize = 64;
const MAX_EXTENSIONS: usize = 32;
const MAX_EXTENSION_BYTES: usize = 4096;

pub(super) const DESCRIPTOR: u16 = 1;
pub(super) const MANIFEST: u16 = 2;
pub(super) const GRANT: u16 = 3;
pub(super) const LAB_PROGRAM: u16 = 4;

pub(super) fn envelope(kind: u16, body: Vec<u8>, trailer: usize) -> Result<Vec<u8>> {
    let mut out = envelope_prefix(kind, body.len(), trailer)?;
    out.extend(body);
    Ok(out)
}

pub(super) fn envelope_prefix(kind: u16, body_len: usize, trailer: usize) -> Result<Vec<u8>> {
    let len = HEADER_BYTES
        .checked_add(body_len)
        .and_then(|size| size.checked_add(trailer))
        .filter(|size| *size <= MAX_BODY_BYTES)
        .ok_or(Error::Limit)?;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(body_len as u32).to_le_bytes());
    Ok(out)
}

pub(super) fn split_envelope(bytes: &[u8], kind: u16, trailer: usize) -> Result<(&[u8], &[u8])> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(Error::Limit);
    }
    let mut header = Reader::new(bytes);
    if header.u16()? != SCHEMA_VERSION {
        return Err(Error::Version);
    }
    if header.u16()? != kind {
        return Err(Error::Type);
    }
    let size = header.u32()? as usize;
    let signed_len = HEADER_BYTES.checked_add(size).ok_or(Error::Limit)?;
    if bytes.len() != signed_len.checked_add(trailer).ok_or(Error::Limit)? {
        return Err(Error::Invalid);
    }
    let (signed, signature) = bytes.split_at(signed_len);
    Ok((signed, signature))
}

pub(super) struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    pub(super) fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let (value, rest) = self.input.split_at_checked(size).ok_or(Error::Invalid)?;
        self.input = rest;
        Ok(value)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    pub(super) fn finish(self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }

    pub(super) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(super) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Invalid)
    }

    pub(super) fn field(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(Error::Limit);
        }
        self.take(len)
    }

    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.field(N)?.try_into().map_err(|_| Error::Invalid)
    }

    pub(super) fn field_u8(&mut self) -> Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }

    pub(super) fn field_u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }

    pub(super) fn field_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }

    pub(super) fn field_u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
}

pub(super) fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn validate_extension(id: u16, required: bool, previous: u16, len: usize) -> Result<()> {
    if id <= previous {
        return Err(Error::Invalid);
    }
    if required {
        return Err(Error::UnknownMandatory);
    }
    if len > MAX_EXTENSION_BYTES {
        return Err(Error::Limit);
    }
    Ok(())
}

pub(super) fn validate_extensions(values: &[Extension]) -> Result<()> {
    if values.len() > MAX_EXTENSIONS {
        return Err(Error::Limit);
    }
    let mut previous = 0;
    for value in values {
        validate_extension(value.id, value.required, previous, value.bytes.len())?;
        previous = value.id;
    }
    Ok(())
}

pub(super) fn encode_extensions(out: &mut Vec<u8>, values: &[Extension]) -> Result<()> {
    validate_extensions(values)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(values.len() as u16).to_le_bytes());
    for value in values {
        bytes.extend_from_slice(&value.id.to_le_bytes());
        bytes.push(u8::from(value.required));
        push_field(&mut bytes, &value.bytes);
    }
    push_field(out, &bytes);
    Ok(())
}

pub(super) fn decode_extensions(reader: &mut Reader<'_>) -> Result<Vec<Extension>> {
    let mut encoded = Reader::new(reader.field(2 + MAX_EXTENSIONS * (7 + MAX_EXTENSION_BYTES))?);
    let count = encoded.u16()? as usize;
    if count > MAX_EXTENSIONS {
        return Err(Error::Limit);
    }
    let mut values = Vec::with_capacity(count);
    let mut previous = 0;
    for _ in 0..count {
        let id = encoded.u16()?;
        let required = flag(encoded.u8()?)?;
        let bytes = encoded.field(MAX_EXTENSION_BYTES)?;
        validate_extension(id, required, previous, bytes.len())?;
        values.push(Extension {
            id,
            required,
            bytes: bytes.to_vec(),
        });
        previous = id;
    }
    encoded.finish()?;
    Ok(values)
}

pub(super) fn flag(value: u8) -> Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Invalid),
    }
}
