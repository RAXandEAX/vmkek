//! Seed-chosen bytes for the native dispatcher and hot handlers.
//!
//! A stamp is `mov r11, imm64`. It does not change flags, so it may sit between
//! `cmp` and a conditional branch. `r11` is dead in the dispatcher and at handler
//! entry. A stamp is not itself an interpreter; level 2 is the inner program.

use std::cell::Cell;
use std::marker::PhantomData;

use iced_x86::code_asm::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::error::Result;
use crate::vm::HOT_OPCODES;

use super::ice;

thread_local! {
    static MORPH_SEED: Cell<u64> = const { Cell::new(0) };
}

/// Restores the previous metamorphic seed when dropped.
///
/// `!Send`: [`Drop`] writes the thread-local seed of the thread that drops the
/// guard. A `PhantomData<*const ()>` keeps the guard on that thread.
#[must_use = "restores the metamorphic seed when dropped"]
pub struct SeedGuard {
    prev: u64,
    _thread: PhantomData<*const ()>,
}

/// Make [`super::assemble_vm`] emit the stub for `seed` until the guard drops.
pub fn bind_metamorphic_seed(seed: u64) -> SeedGuard {
    let prev = MORPH_SEED.with(|cell| cell.replace(seed));
    SeedGuard {
        prev,
        _thread: PhantomData,
    }
}

impl Drop for SeedGuard {
    fn drop(&mut self) {
        let prev = self.prev;
        MORPH_SEED.with(|cell| cell.set(prev));
    }
}

pub(super) fn current_seed() -> u64 {
    MORPH_SEED.with(|cell| cell.get())
}

pub(super) struct Morph {
    seed: u64,
    rng: ChaCha20Rng,
    stamp_index: u32,
}

impl Morph {
    pub(super) fn new(seed: u64) -> Self {
        Self {
            seed,
            rng: ChaCha20Rng::seed_from_u64(seed),
            stamp_index: 0,
        }
    }

    pub(super) fn seed(&self) -> u64 {
        self.seed
    }

    pub(super) fn shuffle<T>(&mut self, items: &mut [T]) {
        if items.len() < 2 {
            return;
        }
        for index in (1..items.len()).rev() {
            let swap = self.rng.gen_range(0..=index);
            items.swap(index, swap);
        }
    }

    /// `0..choices`. The choice is a pure function of the seed and the opcode.
    pub(super) fn arm(&self, tag: u8, choices: u32) -> u32 {
        debug_assert!(choices > 0);
        let mixed = self
            .seed
            .rotate_left(u32::from(tag).wrapping_mul(3))
            .wrapping_add(u64::from(tag));
        (mixed % u64::from(choices)) as u32
    }

    /// Neutral `mov r11` prefixes. Hot opcodes get a longer, seed-chosen run.
    pub(super) fn entry_stamps(&self, tag: u8) -> u32 {
        if HOT_OPCODES.contains(&tag) {
            1 + self.arm(tag, 4)
        } else {
            1
        }
    }

    pub(super) fn stamp(&mut self, a: &mut CodeAssembler) -> Result<()> {
        self.stamp_index = self.stamp_index.wrapping_add(1);
        // A real instruction, so a label set just before the stamp binds to it.
        // `db` would leave the label pending and collide with the next label.
        let imm = stamp_bits(self.seed, self.stamp_index);
        a.mov(r11, imm as i64).map_err(ice)
    }
}

/// Immediate that does not fit in `imm32`, so the assembler emits `mov r11, imm64`.
pub(super) fn stamp_bits(seed: u64, index: u32) -> u64 {
    let mut imm = u64::from_le_bytes(stamp_immediate(seed, index));
    imm |= 1 << 63;
    imm &= !(1 << 32);
    imm
}

/// Eight immediate bytes. For seeds that differ in the low byte, every byte differs
/// at the same index, so a 16-byte dispatcher window cannot be copied across seeds
/// while the surrounding instructions stay shorter than 14 bytes.
pub(super) fn stamp_immediate(seed: u64, index: u32) -> [u8; 8] {
    let seed_bytes = seed.to_le_bytes();
    let index_bytes = index.to_le_bytes();
    let mut raw = [0u8; 8];
    for byte in 0..8u8 {
        let index_part = index_bytes[usize::from(byte % 4)].wrapping_mul(0x3B);
        let seed_part = seed_bytes[usize::from(byte)].wrapping_mul(0x9D);
        let spread = seed_bytes[0].wrapping_mul(byte.wrapping_add(1));
        raw[usize::from(byte)] = seed_part
            .wrapping_add(index_part)
            .wrapping_add(spread)
            .wrapping_add(byte.wrapping_mul(17));
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::{stamp_bits, stamp_immediate};

    #[test]
    fn adjacent_seeds_change_every_immediate_byte() {
        for index in 1..64u32 {
            let left = stamp_immediate(1, index);
            let right = stamp_immediate(2, index);
            assert!(
                left.iter().zip(right).all(|(a, b)| *a != b),
                "index {index}: {left:?} vs {right:?}"
            );
            assert_ne!(stamp_immediate(1, index), stamp_immediate(1, index + 1));
            let left_bits = stamp_bits(1, index);
            let right_bits = stamp_bits(2, index);
            assert_ne!(left_bits, right_bits);
            assert!(i32::try_from(left_bits as i64).is_err());
        }
    }
}
