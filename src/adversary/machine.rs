//! Register file for the bounded symbolic machine.

use crate::flags::{self, Flags};
use crate::ir::{Op, RCX, V_LIMIT};
use crate::vm::{SlotMap, SLOT_COUNT};

use super::expr::Expr;

#[derive(Clone, Debug)]
pub(super) struct File {
    pub(super) slot: Vec<Expr>,
    pub(super) flags: Option<Flags>,
}

pub(super) enum Prim {
    MovRr(u16, u16),
    MovRi(u16, u64),
    AluRr(u8, u16, u16),
    AluRi(u8, u16, u64),
    ImulRr(u16, u16),
    ImulRi(u16, u64),
    Unary(u8, u16),
    Shift(u8, u16, u8),
    CmpRr(u16, u16),
    CmpRi(u16, u64),
    TestRr(u16, u16),
    TestRi(u16, u64),
    StFlags(u16),
    LdFlags(u16),
    Nop,
}

pub(super) fn integer_file() -> File {
    let mut file = zeros(V_LIMIT);
    file.slot[usize::from(RCX)] = Expr::Arg;
    file
}

pub(super) fn slot_file(map: &SlotMap) -> File {
    let mut file = zeros(SLOT_COUNT);
    let index = usize::from(map.forward[usize::from(RCX)]);
    file.slot[index] = Expr::Arg;
    file
}

fn zeros(len: usize) -> File {
    File {
        slot: vec![Expr::Imm(0); len],
        flags: Some(Flags::default()),
    }
}

impl File {
    pub(super) fn get(&self, index: u16) -> Option<Expr> {
        self.slot.get(usize::from(index)).cloned()
    }

    fn set(&mut self, index: u16, expr: Expr) -> bool {
        let Some(slot) = self.slot.get_mut(usize::from(index)) else {
            return false;
        };
        *slot = expr;
        true
    }
}

pub(super) fn from_op(op: Op) -> Option<Prim> {
    Some(match op {
        Op::MovRr(dst, src) => Prim::MovRr(dst, src),
        Op::MovRi(dst, value) => Prim::MovRi(dst, value),
        Op::AddRr(dst, src) => Prim::AluRr(0, dst, src),
        Op::SubRr(dst, src) => Prim::AluRr(1, dst, src),
        Op::XorRr(dst, src) => Prim::AluRr(2, dst, src),
        Op::AndRr(dst, src) => Prim::AluRr(3, dst, src),
        Op::OrRr(dst, src) => Prim::AluRr(4, dst, src),
        Op::AddRi(dst, value) => Prim::AluRi(0, dst, widen(value)),
        Op::SubRi(dst, value) => Prim::AluRi(1, dst, widen(value)),
        Op::XorRi(dst, value) => Prim::AluRi(2, dst, widen(value)),
        Op::AndRi(dst, value) => Prim::AluRi(3, dst, widen(value)),
        Op::OrRi(dst, value) => Prim::AluRi(4, dst, widen(value)),
        Op::Not(dst) => Prim::Unary(0, dst),
        Op::Neg(dst) => Prim::Unary(1, dst),
        Op::Inc(dst) => Prim::Unary(2, dst),
        Op::Dec(dst) => Prim::Unary(3, dst),
        Op::Shl(dst, count) => Prim::Shift(0, dst, count),
        Op::Shr(dst, count) => Prim::Shift(1, dst, count),
        Op::ImulRr(dst, src) => Prim::ImulRr(dst, src),
        Op::ImulRi(dst, value) => Prim::ImulRi(dst, widen(value)),
        Op::CmpRr(dst, src) => Prim::CmpRr(dst, src),
        Op::CmpRi(dst, value) => Prim::CmpRi(dst, widen(value)),
        Op::TestRr(dst, src) => Prim::TestRr(dst, src),
        Op::TestRi(dst, value) => Prim::TestRi(dst, widen(value)),
        Op::StFlags(dst) => Prim::StFlags(dst),
        Op::LdFlags(src) => Prim::LdFlags(src),
        _ => return None,
    })
}

fn widen(value: i32) -> u64 {
    i64::from(value) as u64
}

pub(super) fn apply(file: &mut File, prim: &Prim) -> bool {
    match prim {
        Prim::MovRr(dst, src) => mov_rr(file, *dst, *src),
        Prim::MovRi(dst, value) => file.set(*dst, Expr::Imm(*value)),
        Prim::AluRr(kind, dst, src) => alu_rr(file, *kind, *dst, *src),
        Prim::AluRi(kind, dst, value) => alu_ri(file, *kind, *dst, *value),
        Prim::ImulRr(dst, src) => imul_rr(file, *dst, *src),
        Prim::ImulRi(dst, value) => imul_ri(file, *dst, *value),
        Prim::Unary(kind, dst) => unary(file, *kind, *dst),
        Prim::Shift(kind, dst, count) => shift(file, *kind, *dst, *count),
        Prim::CmpRr(dst, src) => cmp_rr(file, *dst, *src, true),
        Prim::CmpRi(dst, value) => compare(file, *dst, Some(Expr::Imm(*value)), true),
        Prim::TestRr(dst, src) => cmp_rr(file, *dst, *src, false),
        Prim::TestRi(dst, value) => compare(file, *dst, Some(Expr::Imm(*value)), false),
        Prim::StFlags(dst) => store_flags(file, *dst),
        Prim::LdFlags(src) => load_flags(file, *src),
        Prim::Nop => true,
    }
}

fn mov_rr(file: &mut File, dst: u16, src: u16) -> bool {
    let Some(value) = file.get(src) else {
        return false;
    };
    file.set(dst, value)
}

fn alu_rr(file: &mut File, kind: u8, dst: u16, src: u16) -> bool {
    let Some(right) = file.get(src) else {
        return false;
    };
    alu_ri_expr(file, kind, dst, right)
}

fn alu_ri(file: &mut File, kind: u8, dst: u16, value: u64) -> bool {
    alu_ri_expr(file, kind, dst, Expr::Imm(value))
}

fn alu_ri_expr(file: &mut File, kind: u8, dst: u16, right: Expr) -> bool {
    let Some(left) = file.get(dst) else {
        return false;
    };
    match (&left, &right) {
        (Expr::Imm(lhs), Expr::Imm(rhs)) => {
            let (out, flags) = concrete(kind, *lhs, *rhs);
            file.flags = Some(flags);
            file.set(dst, Expr::Imm(out))
        }
        _ => {
            file.flags = None;
            file.set(dst, symbolic(kind, left, right))
        }
    }
}

fn concrete(kind: u8, left: u64, right: u64) -> (u64, Flags) {
    match kind {
        0 => flags::add(left, right, 64),
        1 => flags::sub(left, right, 64),
        2 => flags::logic_xor(left, right, 64),
        3 => flags::logic_and(left, right, 64),
        _ => flags::logic_or(left, right, 64),
    }
}

fn symbolic(kind: u8, left: Expr, right: Expr) -> Expr {
    match kind {
        0 => Expr::Add(Box::new(left), Box::new(right)),
        1 => Expr::Sub(Box::new(left), Box::new(right)),
        2 => Expr::Xor(Box::new(left), Box::new(right)),
        3 => Expr::And(Box::new(left), Box::new(right)),
        _ => Expr::Or(Box::new(left), Box::new(right)),
    }
}

fn imul_rr(file: &mut File, dst: u16, src: u16) -> bool {
    let Some(right) = file.get(src) else {
        return false;
    };
    imul(file, dst, right)
}

fn imul_ri(file: &mut File, dst: u16, value: u64) -> bool {
    imul(file, dst, Expr::Imm(value))
}

fn imul(file: &mut File, dst: u16, right: Expr) -> bool {
    let Some(left) = file.get(dst) else {
        return false;
    };
    match (&left, &right) {
        (Expr::Imm(lhs), Expr::Imm(rhs)) => {
            let (out, flags) = flags::imul(*lhs, *rhs);
            file.flags = Some(flags);
            file.set(dst, Expr::Imm(out))
        }
        _ => {
            file.flags = None;
            file.set(dst, Expr::Mul(Box::new(left), Box::new(right)))
        }
    }
}

fn unary(file: &mut File, kind: u8, dst: u16) -> bool {
    match kind {
        0 => bitwise_not(file, dst),
        1 => negate(file, dst),
        2 => alu_ri(file, 0, dst, 1),
        _ => alu_ri(file, 1, dst, 1),
    }
}

fn bitwise_not(file: &mut File, dst: u16) -> bool {
    let Some(value) = file.get(dst) else {
        return false;
    };
    let expr = match value {
        Expr::Imm(bits) => Expr::Imm(!bits),
        other => Expr::Not(Box::new(other)),
    };
    file.set(dst, expr)
}

fn negate(file: &mut File, dst: u16) -> bool {
    let Some(value) = file.get(dst) else {
        return false;
    };
    match value {
        Expr::Imm(bits) => {
            let (out, flags) = flags::neg(bits, 64);
            file.flags = Some(flags);
            file.set(dst, Expr::Imm(out))
        }
        other => {
            file.flags = None;
            file.set(dst, Expr::Neg(Box::new(other)))
        }
    }
}

fn shift(file: &mut File, kind: u8, dst: u16, count: u8) -> bool {
    let Some(value) = file.get(dst) else {
        return false;
    };
    match value {
        Expr::Imm(bits) => {
            let old = file.flags.unwrap_or_default();
            let (out, flags) = shift_bits(kind, bits, u32::from(count), old);
            file.flags = Some(flags);
            file.set(dst, Expr::Imm(out))
        }
        other => {
            file.flags = None;
            file.set(dst, shift_expr(kind, other, count))
        }
    }
}

fn shift_bits(kind: u8, bits: u64, count: u32, old: Flags) -> (u64, Flags) {
    if kind == 0 {
        flags::shift_left(bits, count, 64, old)
    } else {
        flags::shift_right(bits, count, 64, old)
    }
}

fn shift_expr(kind: u8, value: Expr, count: u8) -> Expr {
    if kind == 0 {
        Expr::Shl(Box::new(value), count)
    } else {
        Expr::Shr(Box::new(value), count)
    }
}

fn cmp_rr(file: &mut File, dst: u16, src: u16, subtract: bool) -> bool {
    let right = file.get(src);
    compare(file, dst, right, subtract)
}

fn compare(file: &mut File, dst: u16, right: Option<Expr>, subtract: bool) -> bool {
    let Some(left) = file.get(dst) else {
        return false;
    };
    let Some(right) = right else {
        return false;
    };
    file.flags = match (&left, &right) {
        (Expr::Imm(lhs), Expr::Imm(rhs)) if subtract => Some(flags::sub(*lhs, *rhs, 64).1),
        (Expr::Imm(lhs), Expr::Imm(rhs)) => Some(flags::logic_and(*lhs, *rhs, 64).1),
        _ => None,
    };
    true
}

fn store_flags(file: &mut File, dst: u16) -> bool {
    let expr = match file.flags {
        Some(flags) => Expr::Imm(flags.pack()),
        None => Expr::Unknown,
    };
    file.set(dst, expr)
}

fn load_flags(file: &mut File, src: u16) -> bool {
    let Some(expr) = file.get(src) else {
        return false;
    };
    file.flags = match expr {
        Expr::Imm(bits) => Some(Flags::unpack(bits)),
        _ => None,
    };
    true
}
