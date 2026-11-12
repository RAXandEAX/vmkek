use std::ops::{Deref, DerefMut};

use zeroize::Zeroize;

/// Wipe initialized slots and spare capacity without constructing a zeroed T.
/// The vector remains allocated, so its caller can inspect the wiped storage
/// before deallocation in a lifecycle test.
pub(super) fn wipe_vec<T: Copy>(values: &mut Vec<T>) {
    values.clear();
    values.spare_capacity_mut().zeroize();
}

/// Verifier scratch with stable storage and cleanup on early returns or panic.
pub(super) struct WipeVec<T: Copy>(Vec<T>);

impl<T: Copy> WipeVec<T> {
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }
}

impl<T: Copy> Deref for WipeVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Copy> DerefMut for WipeVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Copy> Drop for WipeVec<T> {
    fn drop(&mut self) {
        wipe_vec(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;
    use crate::lab::{Instruction, Scalar};

    #[test]
    fn wiped_instruction_allocation_includes_live_and_spare_slots() {
        let mut code = Vec::with_capacity(8);
        code.push(Instruction::Constant(Scalar::U64(0xe1a9_a7a1_aabb_cdef)));
        code.push(Instruction::Jump(0x2a9c_f00d));
        for slot in code.spare_capacity_mut() {
            slot.write(Instruction::Constant(Scalar::I64(-987_654_321)));
        }
        let capacity = code.capacity();
        wipe_vec(&mut code);
        assert!(code.is_empty());
        assert_eq!(code.capacity(), capacity);
        // SAFETY: wipe_vec initialized all bytes, including padding, to zero.
        // Inspect bytes within the still-live allocation, never Instruction values.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                code.as_ptr().cast::<u8>(),
                capacity * size_of::<Instruction>(),
            )
        };
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}
