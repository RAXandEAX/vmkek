//! Load and store counts for one interpreter opcode class.
//!
//! The meter counts logical reads and writes to the register file, flags,
//! guest memory, and the operand stack. The tests compare total reads and
//! writes for each modeled class. Padding leaves the computed result intact.

use std::cell::Cell;

use crate::flags::Flags;

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static LOADS: Cell<u32> = const { Cell::new(0) };
    static STORES: Cell<u32> = const { Cell::new(0) };
}

#[cfg(test)]
pub(super) struct Meter;

#[cfg(test)]
impl Meter {
    pub(super) fn arm() -> Self {
        LOADS.with(|cell| cell.set(0));
        STORES.with(|cell| cell.set(0));
        ARMED.with(|cell| cell.set(true));
        Self
    }

    pub(super) fn pair(&self) -> (u32, u32) {
        (
            LOADS.with(|cell| cell.get()),
            STORES.with(|cell| cell.get()),
        )
    }
}

#[cfg(test)]
impl Drop for Meter {
    fn drop(&mut self) {
        ARMED.with(|cell| cell.set(false));
    }
}

#[inline]
pub(super) fn note_load() {
    if ARMED.with(|cell| cell.get()) {
        LOADS.with(|cell| cell.set(cell.get().saturating_add(1)));
    }
}

#[inline]
pub(super) fn note_store() {
    if ARMED.with(|cell| cell.get()) {
        STORES.with(|cell| cell.set(cell.get().saturating_add(1)));
    }
}

#[inline]
pub(super) fn read_flags(flags: &Flags) -> Flags {
    note_load();
    *flags
}

#[inline]
pub(super) fn write_flags(flags: &mut Flags, next: Flags) {
    note_store();
    *flags = next;
}

#[cfg(test)]
mod tests {
    use super::Meter;
    use crate::flags::Flags;
    use crate::ir::MapMem;
    use crate::vm::{exec::exec_bc, stack, Bc, SlotMap, SLOT_COUNT};

    #[test]
    fn opcode_class_memory_accesses_match() {
        for (name, ops) in classes() {
            let counts: Vec<_> = ops.iter().map(measure).collect();
            let first = counts[0];
            assert!(first.0 + first.1 > 0, "{name} did not touch memory");
            assert!(
                counts.iter().all(|item| *item == first),
                "{name} {counts:?}"
            );
        }
    }

    #[test]
    fn unary_not_preserves_flags() {
        let mut regs = [0u64; SLOT_COUNT];
        regs[1] = 0x0f;
        let mut flags = Flags {
            cf: true,
            pf: true,
            zf: true,
            sf: true,
            of: true,
        };
        let saved = flags;
        let mut mem = MapMem::default();
        exec_bc(
            &Bc::Unary(0, 1),
            &mut regs,
            &mut flags,
            &mut mem,
            0,
            &SlotMap::identity(),
        )
        .unwrap();
        assert_eq!(regs[1], !0x0f);
        assert_eq!(flags, saved);
    }

    #[test]
    fn lea_shapes_keep_the_address() {
        let regs = lea_regs();
        assert_eq!(run_lea(&regs, 2, 3), 0x1010);
        assert_eq!(run_lea(&regs, 0xff, 3), 0x10);
        assert_eq!(run_lea(&regs, 2, 0xff), 0x1008);
        assert_eq!(run_lea(&regs, 0xff, 0xff), 8);
    }

    fn lea_regs() -> [u64; SLOT_COUNT] {
        let mut regs = [0u64; SLOT_COUNT];
        regs[2] = 0x1000;
        regs[3] = 4;
        regs
    }

    fn run_lea(regs: &[u64; SLOT_COUNT], base: u8, index: u8) -> u64 {
        let mut regs = *regs;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        exec_bc(
            &Bc::LeaSib {
                dst: 1,
                base,
                index,
                scale: 2,
                disp: 8,
            },
            &mut regs,
            &mut flags,
            &mut mem,
            0,
            &SlotMap::identity(),
        )
        .unwrap();
        regs[1]
    }

    fn classes() -> Vec<(&'static str, Vec<Bc>)> {
        let mut out = Vec::new();
        out.extend(data_classes());
        out.extend(arith_classes());
        out.extend(stack_classes());
        out
    }

    fn data_classes() -> Vec<(&'static str, Vec<Bc>)> {
        vec![
            ("move", vec![Bc::MovRr(1, 2), Bc::MovRi(1, 3)]),
            ("load", vec![Bc::Load8(1, 2), Bc::Load64(1, 2)]),
            ("store", vec![Bc::Store8(1, 2), Bc::Store64(1, 2)]),
            (
                "lea-sib",
                vec![
                    Bc::LeaSib {
                        dst: 1,
                        base: 2,
                        index: 3,
                        scale: 2,
                        disp: 8,
                    },
                    Bc::LeaSib {
                        dst: 1,
                        base: 0xff,
                        index: 3,
                        scale: 2,
                        disp: 8,
                    },
                    Bc::LeaSib {
                        dst: 1,
                        base: 2,
                        index: 0xff,
                        scale: 2,
                        disp: 8,
                    },
                    Bc::LeaSib {
                        dst: 1,
                        base: 0xff,
                        index: 0xff,
                        scale: 2,
                        disp: 8,
                    },
                ],
            ),
        ]
    }

    fn arith_classes() -> Vec<(&'static str, Vec<Bc>)> {
        vec![
            ("alu-rr", (0..5).map(|kind| Bc::AluRr(kind, 1, 2)).collect()),
            ("alu-ri", (0..5).map(|kind| Bc::AluRi(kind, 1, 3)).collect()),
            ("cmp-rr", vec![Bc::CmpRr(1, 2), Bc::TestRr(1, 2)]),
            ("cmp-ri", vec![Bc::CmpRi(1, 4), Bc::TestRi(1, 4)]),
            ("unary", (0..4).map(|kind| Bc::Unary(kind, 1)).collect()),
            ("shift", (0..5).map(|kind| Bc::Shift(kind, 1, 3)).collect()),
            ("imul", vec![Bc::ImulRr(1, 2), Bc::ImulRi(1, 5)]),
        ]
    }

    fn stack_classes() -> Vec<(&'static str, Vec<Bc>)> {
        vec![
            ("stack-push", vec![Bc::PushR(1), Bc::PushI(9)]),
            ("stack-unary", (0..4).map(Bc::StackUnary).collect()),
            ("stack-alu", (0..5).map(Bc::StackAlu).collect()),
            ("stack-cmp", vec![Bc::StackCmp(0), Bc::StackCmp(1)]),
            (
                "stack-shift",
                (0..5).map(|kind| Bc::StackShift(kind, 3)).collect(),
            ),
        ]
    }

    fn measure(op: &Bc) -> (u32, u32) {
        let mut regs = prepared();
        let mut flags = Flags {
            cf: true,
            ..Flags::default()
        };
        let mut mem = MapMem::default();
        let mut stack = primed(op);
        let meter = Meter::arm();
        let handled = stack::apply(op, &mut regs, &mut flags, &mut stack).unwrap();
        if !handled {
            exec_bc(op, &mut regs, &mut flags, &mut mem, 0, &SlotMap::identity()).unwrap();
        }
        meter.pair()
    }

    fn prepared() -> [u64; SLOT_COUNT] {
        let mut regs = [0u64; SLOT_COUNT];
        regs[1] = 0x2000;
        regs[2] = 0x2000;
        regs[3] = 4;
        regs[4] = 0x3000;
        regs
    }

    fn primed(op: &Bc) -> Vec<u64> {
        let mut stack = Vec::new();
        let depth = match op {
            Bc::StackAlu(_) | Bc::StackCmp(_) | Bc::StackImul => 2,
            Bc::StackUnary(_) | Bc::StackShift(..) => 1,
            _ => 0,
        };
        for value in 0..depth {
            stack.push(0x10 + value);
        }
        stack
    }
}
