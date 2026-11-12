use rand::Rng;
use rand_chacha::ChaCha20Rng;

use crate::error::{msg, Result};

use super::{decode_span, encode_plain, Bc, SlotMap, NEST_XOR};

pub(super) fn remap_regs(op: &mut Bc, slots: &SlotMap) -> Result<()> {
    if remap_pair(op, slots)? || remap_one(op, slots)? || bare_op(op) {
        return Ok(());
    }
    match op {
        Bc::LeaSib {
            dst, base, index, ..
        } => remap_sib(slots, dst, base, index),
        Bc::Nest(body) => remap_nest(body, slots),
        _ => Err(msg("remap missed an opcode")),
    }
}

fn remap_pair(op: &mut Bc, slots: &SlotMap) -> Result<bool> {
    let (dst, src) = match op {
        Bc::MovRr(dst, src)
        | Bc::Load8(dst, src)
        | Bc::Store8(dst, src)
        | Bc::Load64(dst, src)
        | Bc::Store64(dst, src)
        | Bc::AluRr(_, dst, src)
        | Bc::CmpRr(dst, src)
        | Bc::TestRr(dst, src)
        | Bc::ImulRr(dst, src) => (dst, src),
        _ => return Ok(false),
    };
    *dst = map_reg(slots, *dst)?;
    *src = map_reg(slots, *src)?;
    Ok(true)
}

fn remap_one(op: &mut Bc, slots: &SlotMap) -> Result<bool> {
    let Some(dst) = one_reg(op) else {
        return Ok(false);
    };
    *dst = map_reg(slots, *dst)?;
    Ok(true)
}

fn one_reg(op: &mut Bc) -> Option<&mut u8> {
    match op {
        Bc::MovRi(dst, _)
        | Bc::LeaRva(dst, _)
        | Bc::AluRi(_, dst, _)
        | Bc::CmpRi(dst, _)
        | Bc::TestRi(dst, _)
        | Bc::Unary(_, dst)
        | Bc::Shift(_, dst, _)
        | Bc::ImulRi(dst, _)
        | Bc::Div(dst)
        | Bc::Push(dst)
        | Bc::Pop(dst)
        | Bc::StFlags(dst)
        | Bc::LdFlags(dst)
        | Bc::CallReg(dst)
        | Bc::PushR(dst)
        | Bc::PopR(dst) => Some(dst),
        _ => None,
    }
}

fn bare_op(op: &Bc) -> bool {
    matches!(
        op,
        Bc::Jmp(_)
            | Bc::Jcc(..)
            | Bc::CallRva(_)
            | Bc::Ret
            | Bc::Check(_)
            | Bc::Junk
            | Bc::PushI(_)
            | Bc::StackAlu(_)
            | Bc::StackUnary(_)
            | Bc::StackCmp(_)
            | Bc::StackShift(..)
            | Bc::StackImul
    )
}

fn remap_sib(slots: &SlotMap, dst: &mut u8, base: &mut u8, index: &mut u8) -> Result<()> {
    *dst = map_reg(slots, *dst)?;
    *base = map_reg(slots, *base)?;
    *index = map_reg(slots, *index)?;
    Ok(())
}

fn map_reg(slots: &SlotMap, reg: u8) -> Result<u8> {
    if reg == 0xff {
        return Ok(0xff);
    }
    slots
        .forward
        .get(usize::from(reg))
        .copied()
        .ok_or_else(|| msg("register index out of range"))
}

fn remap_nest(body: &mut [u8], slots: &SlotMap) -> Result<()> {
    let mut plain: Vec<u8> = body.iter().map(|byte| byte ^ NEST_XOR).collect();
    let mut cursor = 0;
    while cursor < plain.len() {
        let (mut op, used) = decode_span(&plain[cursor..])?;
        if used == 0 {
            return Err(msg("nested bytecode is empty"));
        }
        remap_regs(&mut op, slots)?;
        let encoded = encode_plain(&op)?;
        if encoded.len() != used {
            return Err(msg("remapped nested bytecode changed size"));
        }
        plain[cursor..cursor + used].copy_from_slice(&encoded);
        cursor += used;
    }
    for (dst, src) in body.iter_mut().zip(plain) {
        *dst = src ^ NEST_XOR;
    }
    Ok(())
}

/// Insert neutral junk and return old instruction index → new index.
/// The entry instruction is preceded by [`Bc::Junk`], and that junk is the remap target,
/// so the following check insertion leaves junk at `entry + 1`.
pub(super) fn insert_junk(
    flat: Vec<Bc>,
    slots: &SlotMap,
    entry_at: u32,
    rng: &mut ChaCha20Rng,
) -> (Vec<Bc>, Vec<u32>) {
    let mut out = Vec::with_capacity(flat.len() + 8);
    let mut remap = Vec::with_capacity(flat.len());
    for (index, op) in flat.into_iter().enumerate() {
        let stop = matches!(op, Bc::Ret | Bc::Jmp(_));
        if index as u32 == entry_at {
            remap.push(out.len() as u32);
            out.push(Bc::Junk);
        } else {
            remap.push(out.len() as u32);
        }
        out.push(op);
        if !stop {
            sprinkle(&mut out, slots, rng);
        }
    }
    for op in &mut out {
        if let Bc::Jmp(target) | Bc::Jcc(_, target) = op {
            *target = remap[*target as usize];
        }
    }
    (out, remap)
}

fn sprinkle(out: &mut Vec<Bc>, slots: &SlotMap, rng: &mut ChaCha20Rng) {
    // Junk has to run, and it has to be flag-neutral. A one-byte nop is the
    // common case. A shadow immediate is rare: it proves the extra slots are
    // live without making the LCG decrypt loop dominate the emulator budget.
    match rng.gen_range(0..16u32) {
        0..=3 => out.push(Bc::Junk),
        4 => {
            let shadow = slots.shadows[rng.gen_range(0..slots.shadows.len())];
            out.push(Bc::MovRi(shadow, rng.gen::<u64>()));
        }
        _ => {}
    }
}
