//! Lower user x87 instructions onto the 80-bit IR stack.

use iced_x86::Instruction;

use crate::error::Result;
use crate::ir::{X87Insn, X87_NO_ADDR};
use crate::x87;

use super::l1::Cursor;

pub fn encode(cursor: &mut Cursor<'_>, insn: &Instruction, _image_base: u64) -> Result<()> {
    if insn.has_rep_prefix() || insn.has_repne_prefix() {
        return Err(super::bad(insn));
    }
    // Reject a form the host stub cannot replay. The stored bytes keep the
    // original address so execution uses the emulator's formula.
    let _host = x87::machine_bytes(insn).map_err(|_| super::bad(insn))?;
    let encoded = x87::original_bytes(insn).map_err(|_| super::bad(insn))?;
    if encoded.len() > 15 {
        return Err(super::bad(insn));
    }
    let mut bytes = [0u8; 15];
    bytes[..encoded.len()].copy_from_slice(&encoded);
    cursor.emit_x87(X87Insn {
        bytes,
        len: encoded.len() as u8,
        addr: X87_NO_ADDR,
        ip: insn.ip(),
    });
    Ok(())
}
