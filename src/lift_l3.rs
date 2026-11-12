//! Lower user SSE through AVX-512 onto the ZMM file.
//!
//! Legacy SSE, late XMM, VEX.128/VEX.256, and EVEX forms share one replay path.
//! XOP stays out.

use iced_x86::Instruction;

use crate::error::Result;
use crate::ir::SseInsn;
use crate::sse;

use super::l1::Cursor;

pub fn encode(cursor: &mut Cursor<'_>, insn: &Instruction, _image_base: u64) -> Result<()> {
    if insn.has_rep_prefix() || insn.has_repne_prefix() || insn.has_lock_prefix() {
        return Err(super::bad(insn));
    }
    let encoded = sse::original_bytes(insn).map_err(|_| super::bad(insn))?;
    if encoded.len() > 15 {
        return Err(super::bad(insn));
    }
    // Reject a form the host stub cannot replay before it is stored.
    sse::prepare(insn, &encoded, None).map_err(|_| super::bad(insn))?;
    let mut bytes = [0u8; 15];
    bytes[..encoded.len()].copy_from_slice(&encoded);
    cursor.emit_sse(SseInsn {
        bytes,
        len: encoded.len() as u8,
        ip: insn.ip(),
    });
    Ok(())
}
