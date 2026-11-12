use rand::Rng;
use rand_chacha::ChaCha20Rng;

use crate::ir::{ARCH, V_LIMIT};

/// Logical registers the IR can name. Architectural registers are the first [`ARCH`].
pub const LOGICAL_REGS: usize = V_LIMIT;
/// Physical slot file: every logical register plus shadow slots.
pub const SLOT_COUNT: usize = LOGICAL_REGS + ARCH;
pub const SHADOW_COUNT: usize = SLOT_COUNT - LOGICAL_REGS;

pub const RT_MIX: i32 = 0x34;
pub const RT_SLOTS: i32 = 0x38;
pub const REG_LAYOUT_LEN: usize = 4 + LOGICAL_REGS;

const fn align16(value: i32) -> i32 {
    (value + 15) & !15
}

pub const FRAME_FLAGS: i32 = (SLOT_COUNT * 8) as i32;
pub const FRAME_DEPTH: i32 = FRAME_FLAGS + 8;
pub const FRAME_IMAGE: i32 = FRAME_DEPTH + 8;
pub const FRAME_CALLS: i32 = align16(FRAME_IMAGE + 8);
pub const FRAME_DECODE: i32 = FRAME_CALLS + 32 * 16;
pub const FRAME_SAVED_R13: i32 = FRAME_DECODE + 0x200;
pub const FRAME_SAVED_R14: i32 = FRAME_SAVED_R13 + 8;
pub const FRAME_SAVED_RBX: i32 = FRAME_SAVED_R14 + 8;
pub const FRAME_SAVED_R12: i32 = FRAME_SAVED_RBX + 8;
pub const FRAME_TARGET: i32 = FRAME_SAVED_R12 + 8;
pub const FRAME_SPILL: i32 = align16(FRAME_TARGET + 8);
pub const FRAME_BYTES: usize = FRAME_SPILL as usize + ARCH * 8;
/// Nested `call_rva` records. Entry 32 would land on [`FRAME_DECODE`].
pub const CALL_DEPTH_LIMIT: u32 = 32;
/// One saved file of every physical slot that is not an architectural register.
/// That is logical registers 16..31 plus the shadows. An identity map puts them at 16..47.
pub const PRIVATE_STRIDE: i32 = ((SLOT_COUNT - ARCH) * 8) as i32;
/// Private-slot stack, just past the zeroed frame so the image does not contain a 256×8 zero table.
pub const FRAME_FILE_STACK: i32 = FRAME_BYTES as i32;
pub const FILE_STACK_BYTES: usize = CALL_DEPTH_LIMIT as usize * PRIVATE_STRIDE as usize;
/// Operand-stack pointer. Sits in the frame gap below the ChaCha scratch.
pub const FRAME_VSP: i32 = FRAME_DECODE + 0xF8;
/// Data-dependent handler edge. Updated from the register file, not the opcode counter.
pub const FRAME_GATE: i32 = FRAME_DECODE + 0x100;
/// Operand stack for the stack machine. Eight qwords, still below the ChaCha scratch.
pub const FRAME_VSTACK: i32 = FRAME_DECODE + 0x108;
pub const VSTACK_CAP: usize = 8;
/// Unmasked copy of one instruction. The cache keeps the masked plaintext.
pub const FRAME_PLAIN: i32 = FRAME_DECODE + 0x148;

const _: () = assert!(RT_SLOTS == RT_MIX + 4);
const _: () = assert!(RT_MIX + REG_LAYOUT_LEN as i32 <= 0x80);
const _: () = assert!(FRAME_FLAGS == (SLOT_COUNT as i32) * 8);
const _: () = assert!(FRAME_CALLS >= FRAME_IMAGE + 8);
const _: () = assert!(FRAME_SPILL >= FRAME_TARGET + 8);
const _: () = assert!(FRAME_BYTES < 256 * 8);
const _: () = assert!(SLOT_COUNT <= 256);
const _: () = assert!(FILE_STACK_BYTES == 32 * 256);
const _: () = assert!(FRAME_FILE_STACK as usize == FRAME_BYTES);
const _: () = assert!(FRAME_VSP + 8 == FRAME_GATE);
const _: () = assert!(FRAME_GATE + 8 == FRAME_VSTACK);
const _: () = assert!(FRAME_VSTACK + (VSTACK_CAP as i32) * 8 <= FRAME_PLAIN);
const _: () = assert!(FRAME_PLAIN + 16 <= FRAME_DECODE + 0x160);
const _: () = assert!(FRAME_DECODE + 0x160 <= FRAME_SAVED_R13);

/// Logical register → physical slot, plus the shadow slots no IR register owns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotMap {
    pub forward: [u8; LOGICAL_REGS],
    pub shadows: [u8; SHADOW_COUNT],
}

impl SlotMap {
    /// Identity map for interpreters tests that address slots directly.
    #[must_use]
    pub fn identity() -> Self {
        let mut forward = [0u8; LOGICAL_REGS];
        for (index, slot) in forward.iter_mut().enumerate() {
            *slot = u8::try_from(index).expect("logical register fits in a byte");
        }
        let mut shadows = [0u8; SHADOW_COUNT];
        for (index, slot) in shadows.iter_mut().enumerate() {
            *slot = u8::try_from(LOGICAL_REGS + index).expect("shadow slot fits in a byte");
        }
        Self { forward, shadows }
    }

    #[must_use]
    pub fn arch(&self, index: usize) -> u8 {
        self.forward[index]
    }
}

/// Handler-mix dword followed by the 32-byte logical→physical map.
#[must_use]
pub fn reg_layout_bytes(slots: &SlotMap, handler_mix: u32) -> [u8; REG_LAYOUT_LEN] {
    let mut out = [0u8; REG_LAYOUT_LEN];
    out[..4].copy_from_slice(&handler_mix.to_le_bytes());
    out[4..].copy_from_slice(&slots.forward);
    out
}

/// Permutation of the slot file. Architectural registers are never left as the identity
/// and at least one of them sits past the first 16 slots.
#[must_use]
pub fn slots_from_rng(rng: &mut ChaCha20Rng) -> SlotMap {
    let mut order: Vec<u8> = (0..SLOT_COUNT as u8).collect();
    for index in (1..order.len()).rev() {
        let swap = rng.gen_range(0..=index);
        order.swap(index, swap);
    }
    let mut forward = [0u8; LOGICAL_REGS];
    forward.copy_from_slice(&order[..LOGICAL_REGS]);
    let mut shadows = [0u8; SHADOW_COUNT];
    shadows.copy_from_slice(&order[LOGICAL_REGS..]);
    force_arch_shape(&mut forward, &mut shadows);
    SlotMap { forward, shadows }
}

fn force_arch_shape(forward: &mut [u8; LOGICAL_REGS], shadows: &mut [u8; SHADOW_COUNT]) {
    if (0..ARCH).all(|index| forward[index] == index as u8) {
        forward.swap(0, 1);
    }
    if (0..ARCH).any(|index| forward[index] >= ARCH as u8) {
        return;
    }
    if let Some(pos) = (ARCH..LOGICAL_REGS).find(|&index| forward[index] >= ARCH as u8) {
        forward.swap(0, pos);
        return;
    }
    let pos = shadows
        .iter()
        .position(|slot| *slot >= ARCH as u8)
        .unwrap_or(0);
    std::mem::swap(&mut forward[0], &mut shadows[pos]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_arch_map_is_widened_without_dropping_a_slot() {
        let mut forward = [0u8; LOGICAL_REGS];
        for (index, slot) in forward.iter_mut().enumerate() {
            *slot = index as u8;
        }
        let mut shadows = [0u8; SHADOW_COUNT];
        for (index, slot) in shadows.iter_mut().enumerate() {
            *slot = (LOGICAL_REGS + index) as u8;
        }
        force_arch_shape(&mut forward, &mut shadows);
        assert!((0..ARCH).any(|index| forward[index] != index as u8));
        assert!((0..ARCH).any(|index| forward[index] >= ARCH as u8));
        let mut all = forward.to_vec();
        all.extend(shadows);
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), SLOT_COUNT);
    }
}
