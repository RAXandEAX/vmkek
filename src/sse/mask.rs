//! Element merge-masking (`{k}`) and zeroing-masking (`{k}{z}`).
//!
//! This is the M-EMU rule for an EVEX write. The host opcode applies the same
//! rule when AVX-512F and XCR0 opmask/ZMM state are enabled. A clear mask bit
//! keeps the old element under merge-masking and stores zeros under
//! zeroing-masking. `{k0}` is not a mask: every element is written.

/// Apply `mask` to `old`, writing elements from `computed` where the bit is set.
///
/// `elem` is the element width in bytes. `zeroing` selects `{k}{z}`.
/// The L6 differential is the caller; a non-test build still keeps the rule.
#[must_use]
#[allow(dead_code)]
pub(super) fn apply(old: &[u8], computed: &[u8], mask: u64, elem: usize, zeroing: bool) -> Vec<u8> {
    let mut out = old.to_vec();
    if elem == 0 || old.len() != computed.len() {
        return out;
    }
    let lanes = old.len() / elem;
    for lane in 0..lanes {
        let at = lane * elem;
        let end = at + elem;
        if (mask >> lane) & 1 == 1 {
            out[at..end].copy_from_slice(&computed[at..end]);
        } else if zeroing {
            out[at..end].fill(0);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::apply;

    #[test]
    fn merge_keeps_clear_lanes_and_zeroing_stores_zeros() {
        let old = [1u8, 2, 3, 4];
        let computed = [9u8, 9, 9, 9];
        assert_eq!(apply(&old, &computed, 0b0101, 1, false), vec![9, 2, 9, 4]);
        assert_eq!(apply(&old, &computed, 0b0101, 1, true), vec![9, 0, 9, 0]);
        assert_eq!(apply(&old, &computed, 0, 1, false), old.to_vec());
    }
}
