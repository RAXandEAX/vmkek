//! Level-2 interpreter. The dispatcher jumps here with the opcode in `eax`.
//! The handler table is masked so unused slots are not a shared 16-byte run.
//! This code sits in `[cipher, frame)` and must not vary with the seed.

use iced_x86::code_asm::*;

use crate::error::{msg, Result};
use crate::vm::{
    inner, BYTECODE_OPCODES, CTX_INDEX, FRAME_DECODE, FRAME_GATE, INNER_CIPHER, INNER_LEN,
    INNER_NONCE, INNER_PLAIN, INNER_READY,
};

use super::{ice, VmLabels};

const NEST_SEED: i32 = FRAME_DECODE + 0x50;
const NEST_R12: i32 = FRAME_DECODE + 0x58;
const NEST_OPC: i32 = FRAME_DECODE + 0x60;
const NEST_TABLE: i32 = FRAME_DECODE + 0x68;
const NEST_ANCHOR: i32 = FRAME_DECODE + 0x70;
const TABLE_BYTES: usize = 256 * 4;

const _: () = assert!(NEST_ANCHOR + 8 <= super::WORK_STACK - 96);

struct Flow {
    fast: CodeLabel,
    slow: CodeLabel,
    walk: CodeLabel,
    eq: CodeLabel,
    je: CodeLabel,
    lookup: CodeLabel,
    ret_op: CodeLabel,
    reload: CodeLabel,
    done: CodeLabel,
    unmask: CodeLabel,
    skip_je: CodeLabel,
    bad: CodeLabel,
}

fn asm(step: std::result::Result<(), IcedError>) -> Result<()> {
    step.map_err(ice)
}

/// Four identical mask bytes. Seeds that differ in the low byte differ in every byte.
pub(super) fn slot_mask(seed: u64) -> u32 {
    let byte = (seed as u8).wrapping_mul(0x9d);
    u32::from(byte).wrapping_mul(0x0101_0101)
}

/// Replace the compare chain. Registers: `r8d` mask, `r10` table, `r9` anchor.
pub(super) fn emit_transfer(
    a: &mut CodeAssembler,
    morph: &mut super::morph::Morph,
    labels: &VmLabels,
) -> Result<()> {
    morph.stamp(a)?;
    asm(a.mov(r8d, slot_mask(morph.seed()) as i32))?;
    morph.stamp(a)?;
    asm(a.lea(r10, qword_ptr(labels.table)))?;
    morph.stamp(a)?;
    asm(a.lea(r9, qword_ptr(labels.handlers[labels.anchor_index])))?;
    morph.stamp(a)?;
    asm(a.jmp(labels.inner))?;
    Ok(())
}

/// Fixed interpreter. The product program is a lookup; other programs take the walk.
pub(super) fn emit_interpreter(
    a: &mut CodeAssembler,
    labels: &mut VmLabels,
    seed: u64,
) -> Result<()> {
    let mut flow = Flow {
        fast: a.create_label(),
        slow: a.create_label(),
        walk: a.create_label(),
        eq: a.create_label(),
        je: a.create_label(),
        lookup: a.create_label(),
        ret_op: a.create_label(),
        reload: a.create_label(),
        done: a.create_label(),
        unmask: a.create_label(),
        skip_je: a.create_label(),
        bad: a.create_label(),
    };
    emit_fast(a, labels, &mut flow)?;
    emit_open_stream(a, labels)?;
    emit_walk_setup(a, &mut flow)?;
    emit_walk(a, &flow)?;
    emit_eq(a, &mut flow)?;
    emit_je(a, &mut flow)?;
    emit_lookup(a, &mut flow)?;
    emit_ret(a, &mut flow)?;
    emit_reload(a, &mut flow)?;
    emit_done(a, labels, &mut flow)?;
    emit_unmask(a, labels, seed, &mut flow)?;
    emit_bad(a, labels, &mut flow)?;
    emit_wipe(a, labels)
}

fn emit_fast(a: &mut CodeAssembler, labels: &mut VmLabels, flow: &mut Flow) -> Result<()> {
    emit_enter_inner(a, labels)?;
    asm(a.set_label(&mut flow.fast))?;
    asm(a.cmp(byte_ptr(rsi), u32::from(inner::LOOKUP)))?;
    asm(a.jne(flow.slow))?;
    asm(a.cmp(dword_ptr(r13 + INNER_LEN), 257u32))?;
    asm(a.jb(flow.bad))?;
    asm(a.movzx(r11d, byte_ptr(rsi + rax + 1i32)))?;
    asm(a.cmp(r11b, u32::from(inner::REJECT)))?;
    asm(a.je(flow.bad))?;
    asm(a.mov(eax, r11d))?;
    asm(a.jmp(flow.done))?;
    Ok(())
}

/// Seal the outer block, open the level-2 program, and restore the opcode.
fn emit_enter_inner(a: &mut CodeAssembler, labels: &mut VmLabels) -> Result<()> {
    asm(a.set_label(&mut labels.inner))?;
    asm(a.mov(qword_ptr(rbx + NEST_R12), r12))?;
    emit_save_live(a)?;
    asm(a.mov(qword_ptr(rbx + super::SAVED_RSP), rsp))?;
    asm(a.lea(rsp, qword_ptr(rbx + super::WORK_STACK)))?;
    asm(a.call(labels.seal_slot))?;
    asm(a.call(labels.open_inner))?;
    asm(a.mov(rsp, qword_ptr(rbx + super::SAVED_RSP)))?;
    asm(a.mov(rax, qword_ptr(rbx + NEST_OPC)))?;
    Ok(())
}

fn emit_open_stream(a: &mut CodeAssembler, labels: &mut VmLabels) -> Result<()> {
    asm(a.set_label(&mut labels.open_inner))?;
    super::external::emit_inner_gate(a, &labels.ext)?;
    emit_save_outer(a)?;
    emit_install_inner(a)?;
    emit_call_chacha(a, labels)?;
    emit_restore_outer(a)?;
    asm(a.lea(rsi, qword_ptr(r13 + INNER_PLAIN)))?;
    asm(a.ret())?;
    Ok(())
}

fn emit_save_live(a: &mut CodeAssembler) -> Result<()> {
    asm(a.mov(qword_ptr(rbx + NEST_OPC), rax))?;
    asm(a.mov(qword_ptr(rbx + NEST_SEED), r8))?;
    asm(a.mov(qword_ptr(rbx + NEST_TABLE), r10))?;
    asm(a.mov(qword_ptr(rbx + NEST_ANCHOR), r9))?;
    Ok(())
}

fn emit_restore_live(a: &mut CodeAssembler) -> Result<()> {
    asm(a.mov(rax, qword_ptr(rbx + NEST_OPC)))?;
    asm(a.mov(r8, qword_ptr(rbx + NEST_SEED)))?;
    asm(a.mov(r10, qword_ptr(rbx + NEST_TABLE)))?;
    asm(a.mov(r9, qword_ptr(rbx + NEST_ANCHOR)))?;
    asm(a.mov(r12, qword_ptr(rbx + NEST_R12)))?;
    Ok(())
}

fn emit_save_outer(a: &mut CodeAssembler) -> Result<()> {
    super::chain::emit_load_r15(a)?;
    // Park on the stack. `CTX_NEST` stays as the caller left it, so a later
    // resume does not publish a different chain image.
    asm(a.sub(rsp, 48i32))?;
    for word in 0..4i32 {
        asm(a.mov(rax, qword_ptr(r15 + (word * 8))))?;
        asm(a.mov(qword_ptr(rsp + (word * 8)), rax))?;
    }
    for word in 0..3i32 {
        asm(a.mov(eax, dword_ptr(r15 + (CTX_INDEX + word * 4))))?;
        asm(a.mov(dword_ptr(rsp + (32 + word * 4)), eax))?;
    }
    Ok(())
}

fn emit_install_inner(a: &mut CodeAssembler) -> Result<()> {
    super::chain::emit_load_r15(a)?;
    for word in 0..4i32 {
        asm(a.mov(rax, qword_ptr(r13 + (crate::vm::INNER_KEY + word * 8))))?;
        asm(a.mov(qword_ptr(r15 + (word * 8)), rax))?;
    }
    for word in 0..3i32 {
        asm(a.mov(eax, dword_ptr(r13 + (INNER_NONCE + word * 4))))?;
        asm(a.mov(dword_ptr(r15 + (CTX_INDEX + word * 4)), eax))?;
    }
    Ok(())
}

fn emit_restore_outer(a: &mut CodeAssembler) -> Result<()> {
    super::chain::emit_load_r15(a)?;
    for word in 0..4i32 {
        asm(a.mov(rax, qword_ptr(rsp + (word * 8))))?;
        asm(a.mov(qword_ptr(r15 + (word * 8)), rax))?;
    }
    for word in 0..3i32 {
        asm(a.mov(eax, dword_ptr(rsp + (32 + word * 4))))?;
        asm(a.mov(dword_ptr(r15 + (CTX_INDEX + word * 4)), eax))?;
    }
    asm(a.add(rsp, 48i32))?;
    Ok(())
}

fn emit_call_chacha(a: &mut CodeAssembler, labels: &VmLabels) -> Result<()> {
    asm(a.mov(qword_ptr(rbx + super::CHACHA_RSP), rsp))?;
    asm(a.lea(rsp, qword_ptr(rbx + super::CHACHA_STACK)))?;
    asm(a.lea(rsi, qword_ptr(r13 + INNER_CIPHER)))?;
    asm(a.lea(rdi, qword_ptr(r13 + INNER_PLAIN)))?;
    asm(a.mov(ecx, dword_ptr(r13 + INNER_LEN)))?;
    asm(a.xor(r10d, r10d))?;
    asm(a.call(labels.chacha))?;
    asm(a.mov(rsp, qword_ptr(rbx + super::CHACHA_RSP)))?;
    Ok(())
}

fn emit_walk_setup(a: &mut CodeAssembler, flow: &mut Flow) -> Result<()> {
    asm(a.set_label(&mut flow.slow))?;
    asm(a.mov(ecx, dword_ptr(r13 + INNER_LEN)))?;
    asm(a.lea(rdx, qword_ptr(rsi + rcx)))?;
    asm(a.xor(r15d, r15d))?;
    asm(a.xor(r11d, r11d))?;
    asm(a.set_label(&mut flow.walk))?;
    Ok(())
}

fn emit_walk(a: &mut CodeAssembler, flow: &Flow) -> Result<()> {
    asm(a.cmp(rsi, rdx))?;
    asm(a.jae(flow.bad))?;
    asm(a.movzx(ecx, byte_ptr(rsi)))?;
    asm(a.cmp(cl, u32::from(inner::EQ)))?;
    asm(a.je(flow.eq))?;
    asm(a.cmp(cl, u32::from(inner::JE)))?;
    asm(a.je(flow.je))?;
    asm(a.cmp(cl, u32::from(inner::LOOKUP)))?;
    asm(a.je(flow.lookup))?;
    asm(a.cmp(cl, u32::from(inner::RET)))?;
    asm(a.je(flow.ret_op))?;
    asm(a.cmp(cl, u32::from(inner::FAIL)))?;
    asm(a.je(flow.bad))?;
    emit_junk(a, flow)
}

fn emit_junk(a: &mut CodeAssembler, flow: &Flow) -> Result<()> {
    asm(a.cmp(cl, 0x70u32))?;
    asm(a.jb(flow.bad))?;
    asm(a.cmp(cl, 0x7fu32))?;
    asm(a.ja(flow.bad))?;
    asm(a.inc(rsi))?;
    asm(a.jmp(flow.walk))?;
    Ok(())
}

fn emit_eq(a: &mut CodeAssembler, flow: &mut Flow) -> Result<()> {
    asm(a.set_label(&mut flow.eq))?;
    asm(a.lea(rax, qword_ptr(rsi + 2i32)))?;
    asm(a.cmp(rax, rdx))?;
    asm(a.ja(flow.bad))?;
    asm(a.movzx(ecx, byte_ptr(rsi + 1i32)))?;
    asm(a.movzx(eax, byte_ptr(rbx + NEST_OPC)))?;
    asm(a.cmp(al, cl))?;
    asm(a.sete(r11b))?;
    asm(a.add(rsi, 2i32))?;
    asm(a.jmp(flow.walk))?;
    Ok(())
}

fn emit_je(a: &mut CodeAssembler, flow: &mut Flow) -> Result<()> {
    asm(a.set_label(&mut flow.je))?;
    asm(a.lea(rax, qword_ptr(rsi + 2i32)))?;
    asm(a.cmp(rax, rdx))?;
    asm(a.ja(flow.bad))?;
    asm(a.cmp(r11b, 0u32))?;
    asm(a.je(flow.skip_je))?;
    asm(a.movzx(eax, byte_ptr(rsi + 1i32)))?;
    asm(a.jmp(flow.reload))?;
    asm(a.set_label(&mut flow.skip_je))?;
    asm(a.add(rsi, 2i32))?;
    asm(a.jmp(flow.walk))?;
    Ok(())
}

fn emit_lookup(a: &mut CodeAssembler, flow: &mut Flow) -> Result<()> {
    asm(a.set_label(&mut flow.lookup))?;
    asm(a.lea(rax, qword_ptr(rsi + 257i32)))?;
    asm(a.cmp(rax, rdx))?;
    asm(a.ja(flow.bad))?;
    asm(a.movzx(ecx, byte_ptr(rbx + NEST_OPC)))?;
    asm(a.lea(r10, qword_ptr(rsi + 1i32)))?;
    asm(a.movzx(r15d, byte_ptr(r10 + rcx)))?;
    asm(a.mov(rsi, rax))?;
    asm(a.jmp(flow.walk))?;
    Ok(())
}

fn emit_ret(a: &mut CodeAssembler, flow: &mut Flow) -> Result<()> {
    asm(a.set_label(&mut flow.ret_op))?;
    asm(a.cmp(r15b, u32::from(inner::REJECT)))?;
    asm(a.je(flow.bad))?;
    asm(a.movzx(eax, r15b))?;
    asm(a.jmp(flow.reload))?;
    Ok(())
}

fn emit_reload(a: &mut CodeAssembler, flow: &mut Flow) -> Result<()> {
    asm(a.set_label(&mut flow.reload))?;
    asm(a.jmp(flow.done))?;
    Ok(())
}

/// Wipe the level-2 buffer, reopen the outer block, then restore the lookup.
fn emit_done(a: &mut CodeAssembler, labels: &mut VmLabels, flow: &mut Flow) -> Result<()> {
    asm(a.set_label(&mut flow.done))?;
    asm(a.mov(qword_ptr(rbx + NEST_OPC), rax))?;
    asm(a.mov(qword_ptr(rbx + super::SAVED_RSP), rsp))?;
    asm(a.lea(rsp, qword_ptr(rbx + super::WORK_STACK)))?;
    asm(a.call(labels.wipe_inner))?;
    asm(a.call(labels.reopen_slot))?;
    asm(a.mov(rsp, qword_ptr(rbx + super::SAVED_RSP)))?;
    emit_restore_live(a)?;
    asm(a.jmp(flow.unmask))?;
    Ok(())
}

fn emit_unmask(a: &mut CodeAssembler, labels: &VmLabels, seed: u64, flow: &mut Flow) -> Result<()> {
    let mut even = a.create_label();
    let mut decode = a.create_label();
    asm(a.set_label(&mut flow.unmask))?;
    if super::chain::pe_tls_bound() {
        // Select only a byte-indexed entry in the two read-only code tables.
        // Reload the compile-time mask and RIP-relative addresses after the
        // window helpers return, so writable TLS cannot supply these values.
        asm(a.movzx(ecx, al))?;
        asm(a.mov(r8d, slot_mask(seed) as i32))?;
        asm(a.lea(r10, qword_ptr(labels.table)))?;
        asm(a.lea(r9, qword_ptr(labels.handlers[labels.anchor_index])))?;
    } else {
        asm(a.mov(ecx, eax))?;
    }
    asm(a.shl(ecx, 2u32))?;
    // The previous handler stored the gate. Bit 0 picks the entry, not the opcode.
    asm(a.test(byte_ptr(rbx + FRAME_GATE), 1u32))?;
    asm(a.jz(even))?;
    asm(a.mov(edx, dword_ptr(r10 + rcx + TABLE_BYTES as i32)))?;
    asm(a.jmp(decode))?;
    asm(a.set_label(&mut even))?;
    asm(a.mov(edx, dword_ptr(r10 + rcx)))?;
    asm(a.set_label(&mut decode))?;
    asm(a.xor(edx, r8d))?;
    asm(a.je(flow.bad))?;
    asm(a.dec(edx))?;
    asm(a.movsxd(rdx, edx))?;
    asm(a.add(r9, rdx))?;
    asm(a.jmp(r9))?;
    Ok(())
}

fn emit_bad(a: &mut CodeAssembler, labels: &mut VmLabels, flow: &mut Flow) -> Result<()> {
    asm(a.set_label(&mut flow.bad))?;
    asm(a.call(labels.wipe_inner))?;
    asm(a.jmp(labels.fail))?;
    Ok(())
}

fn emit_wipe(a: &mut CodeAssembler, labels: &mut VmLabels) -> Result<()> {
    asm(a.set_label(&mut labels.wipe_inner))?;
    if labels.window_mode == super::window::Mode::External {
        return super::external::emit_private_inner_wipe(a, &labels.ext);
    }
    asm(a.lea(rdi, qword_ptr(r13 + INNER_PLAIN)))?;
    asm(a.mov(ecx, dword_ptr(r13 + INNER_LEN)))?;
    asm(a.xor(eax, eax))?;
    asm(a.cld())?;
    asm(a.rep().stosb())?;
    asm(a.mov(byte_ptr(r13 + INNER_READY), 0u32))?;
    asm(a.ret())?;
    Ok(())
}

/// XOR the handler displacements into the masked table. Empty slots stay fail-closed.
pub(super) fn patch_table(
    bytes: &mut [u8],
    seed: u64,
    anchor: usize,
    table: usize,
    handlers: &[usize],
    odd: &[usize],
) -> Result<()> {
    fill_mask(bytes, seed, table)?;
    let odd_at = table
        .checked_add(TABLE_BYTES)
        .ok_or_else(|| msg("inner table does not fit"))?;
    fill_mask(bytes, seed, odd_at)?;
    write_handler_slots(bytes, anchor, table, handlers)?;
    write_handler_slots(bytes, anchor, odd_at, odd)
}

fn fill_mask(bytes: &mut [u8], seed: u64, table: usize) -> Result<()> {
    let end = table
        .checked_add(TABLE_BYTES)
        .ok_or_else(|| msg("inner table does not fit"))?;
    if end > bytes.len() {
        return Err(msg("inner table does not fit"));
    }
    let mask = slot_mask(seed).to_le_bytes();
    for pos in 0..TABLE_BYTES {
        bytes[table + pos] = mask[pos & 3];
    }
    Ok(())
}

fn write_handler_slots(
    bytes: &mut [u8],
    anchor: usize,
    table: usize,
    handlers: &[usize],
) -> Result<()> {
    if handlers.len() != BYTECODE_OPCODES.len() {
        return Err(msg("inner table is missing a handler"));
    }
    for (index, tag) in BYTECODE_OPCODES.iter().copied().enumerate() {
        let rel = i32::try_from(handlers[index] as i64 - anchor as i64)
            .map_err(|_| msg("handler is too far from the inner anchor"))?;
        let biased = rel
            .checked_add(1)
            .ok_or_else(|| msg("handler is too far from the inner anchor"))?;
        if biased == 0 {
            return Err(msg("handler offset collides with an empty slot"));
        }
        let at = table + usize::from(tag) * 4;
        for (lane, byte) in biased.to_le_bytes().into_iter().enumerate() {
            bytes[at + lane] ^= byte;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::slot_mask;

    #[test]
    fn slot_mask_differs_for_the_anchor_seeds() {
        for left in 1..=10u64 {
            for right in (left + 1)..=10 {
                let lhs = slot_mask(left).to_le_bytes();
                let rhs = slot_mask(right).to_le_bytes();
                assert!(
                    lhs.iter().zip(rhs.iter()).all(|(a, b)| a != b),
                    "{left} {right}: {lhs:?} vs {rhs:?}"
                );
            }
        }
    }
}
