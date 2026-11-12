//! Decode one plaintext bytecode instruction from a repository fixture.

use crate::vm::NEST_XOR;

use super::machine::Prim;

pub(super) enum Code {
    Prim(Prim),
    Jmp(u32),
    Jcc(u8, u32),
    Ret,
}

pub(super) fn decode(bytes: &[u8]) -> Option<Code> {
    let mut reader = Reader { data: bytes, at: 0 };
    let tag = reader.u8()?;
    let code = decode_tag(tag, &mut reader)?;
    (reader.at == bytes.len()).then_some(code)
}

fn decode_tag(tag: u8, reader: &mut Reader<'_>) -> Option<Code> {
    if tag == 0x61 {
        return decode_nest(reader);
    }
    if tag == 0x52 {
        return Some(Code::Ret);
    }
    if (0x70..0x80).contains(&tag) {
        return Some(Code::Prim(Prim::Nop));
    }
    decode_body(tag, reader)
}

fn decode_nest(reader: &mut Reader<'_>) -> Option<Code> {
    let len = usize::from(reader.u8()?);
    let raw = reader.take(len)?;
    let plain: Vec<u8> = raw.iter().map(|byte| byte ^ NEST_XOR).collect();
    decode(&plain)
}

fn decode_body(tag: u8, reader: &mut Reader<'_>) -> Option<Code> {
    let code = match tag {
        0x02 => Prim::MovRr(reader.reg()?, reader.reg()?),
        0x03 => Prim::MovRi(reader.reg()?, reader.u64()?),
        0x10..=0x14 => Prim::AluRr(tag - 0x10, reader.reg()?, reader.reg()?),
        0x15..=0x19 => Prim::AluRi(tag - 0x15, reader.reg()?, reader.i32()?),
        0x20 => Prim::CmpRr(reader.reg()?, reader.reg()?),
        0x21 => Prim::CmpRi(reader.reg()?, reader.i32()?),
        0x22 => Prim::TestRr(reader.reg()?, reader.reg()?),
        0x23 => Prim::TestRi(reader.reg()?, reader.i32()?),
        0x24..=0x27 => Prim::Unary(tag - 0x24, reader.reg()?),
        0x28 | 0x29 => Prim::Shift(tag - 0x28, reader.reg()?, reader.u8()?),
        0x2d => Prim::ImulRr(reader.reg()?, reader.reg()?),
        0x2e => Prim::ImulRi(reader.reg()?, reader.i32()?),
        0x32 => Prim::StFlags(reader.reg()?),
        0x33 => Prim::LdFlags(reader.reg()?),
        0x40 => return Some(Code::Jmp(reader.u32()?)),
        0x41 => return Some(Code::Jcc(reader.u8()?, reader.u32()?)),
        0x60 => {
            reader.u32()?;
            Prim::Nop
        }
        _ => return None,
    };
    Some(Code::Prim(code))
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn reg(&mut self) -> Option<u16> {
        self.u8().map(u16::from)
    }

    fn u8(&mut self) -> Option<u8> {
        let value = *self.data.get(self.at)?;
        self.at += 1;
        Some(value)
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        let bytes = self.take(8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    fn i32(&mut self) -> Option<u64> {
        Some(i64::from(self.u32()? as i32) as u64)
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let slice = self.data.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }
}
