//! Arithmetic, logic, and shifts. Flag results come from [`crate::flags`].

use iced_x86::{Instruction, Mnemonic};

use crate::error::{msg, Result};
use crate::flags::{self, Flags};
use crate::ir::MemIo;

use super::{clear_af, mask, op_bits, read_src, set_arith, write_dst, Cpu, Fate, Touch};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alu {
    Add,
    Adc,
    Sub,
    Sbb,
    Cmp,
    And,
    Or,
    Xor,
    Test,
    Inc,
    Dec,
    Neg,
    Not,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shift {
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
    Rcl,
    Rcr,
    Shld,
    Shrd,
}

pub fn is_alu(mnemonic: Mnemonic) -> bool {
    alu_of(mnemonic).is_some() || shift_of(mnemonic).is_some()
}

pub fn alu_of(mnemonic: Mnemonic) -> Option<Alu> {
    Some(match mnemonic {
        Mnemonic::Add => Alu::Add,
        Mnemonic::Adc => Alu::Adc,
        Mnemonic::Sub => Alu::Sub,
        Mnemonic::Sbb => Alu::Sbb,
        Mnemonic::Cmp => Alu::Cmp,
        Mnemonic::And => Alu::And,
        Mnemonic::Or => Alu::Or,
        Mnemonic::Xor => Alu::Xor,
        Mnemonic::Test => Alu::Test,
        Mnemonic::Inc => Alu::Inc,
        Mnemonic::Dec => Alu::Dec,
        Mnemonic::Neg => Alu::Neg,
        Mnemonic::Not => Alu::Not,
        _ => return None,
    })
}

pub fn shift_of(mnemonic: Mnemonic) -> Option<Shift> {
    Some(match mnemonic {
        Mnemonic::Shl | Mnemonic::Sal => Shift::Shl,
        Mnemonic::Shr => Shift::Shr,
        Mnemonic::Sar => Shift::Sar,
        Mnemonic::Rol => Shift::Rol,
        Mnemonic::Ror => Shift::Ror,
        Mnemonic::Rcl => Shift::Rcl,
        Mnemonic::Rcr => Shift::Rcr,
        Mnemonic::Shld => Shift::Shld,
        Mnemonic::Shrd => Shift::Shrd,
        _ => return None,
    })
}

pub fn alu(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction, op: Alu) -> Result<Touch> {
    let width = op_bits(insn, 0);
    if !(matches!(width, 8 | 16 | 32 | 64)) {
        return Err(msg("unsupported operand width"));
    }
    let left = read_src(cpu, mem, insn, 0)?;
    let right = if matches!(op, Alu::Inc | Alu::Dec | Alu::Neg | Alu::Not) {
        0
    } else {
        read_src(cpu, mem, insn, 1)?
    };
    let old = cpu.flags;
    let (result, flags, af) = match op {
        Alu::Add => bin(flags::add(left, right, width), left, right),
        Alu::Adc => bin(flags::adc(left, right, width, old.cf), left, right),
        Alu::Sub | Alu::Cmp => bin(flags::sub(left, right, width), left, right),
        Alu::Sbb => bin(flags::sbb(left, right, width, old.cf), left, right),
        Alu::And | Alu::Test => logic(flags::logic_and(left, right, width)),
        Alu::Or => logic(flags::logic_or(left, right, width)),
        Alu::Xor => logic(flags::logic_xor(left, right, width)),
        Alu::Inc => {
            let (result, flags) = flags::inc(left, width, old);
            (result, flags, flags::aux_carry(left, 1, result))
        }
        Alu::Dec => {
            let (result, flags) = flags::dec(left, width, old);
            (result, flags, flags::aux_carry(left, 1, result))
        }
        Alu::Neg => {
            let (result, flags) = flags::neg(left, width);
            (result, flags, flags::aux_carry(0, left, result))
        }
        Alu::Not => ((!left) & mask(width), old, cpu.af),
    };
    let write = !matches!(op, Alu::Cmp | Alu::Test);
    if write {
        write_dst(cpu, mem, insn, result)?;
    }
    if op == Alu::Not {
        return Ok(Touch::keep());
    }
    set_arith(cpu, flags, af);
    Ok(match op {
        Alu::And | Alu::Or | Alu::Xor | Alu::Test => Touch::logic(),
        _ => Touch::arith(),
    })
}

fn bin(computed: (u64, Flags), left: u64, right: u64) -> (u64, Flags, bool) {
    let af = flags::aux_carry(left, right, computed.0);
    (computed.0, computed.1, af)
}

fn logic(computed: (u64, Flags)) -> (u64, Flags, bool) {
    (computed.0, computed.1, false)
}

pub fn shift(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction, op: Shift) -> Result<Touch> {
    let width = op_bits(insn, 0);
    if !(matches!(width, 8 | 16 | 32 | 64)) {
        return Err(msg("unsupported operand width"));
    }
    let value = read_src(cpu, mem, insn, 0)?;
    let count_src = if matches!(op, Shift::Shld | Shift::Shrd) {
        2
    } else {
        1
    };
    let count = read_src(cpu, mem, insn, count_src)? as u32;
    let extra = if matches!(op, Shift::Shld | Shift::Shrd) {
        read_src(cpu, mem, insn, 1)?
    } else {
        0
    };
    let old = cpu.flags;
    let masked = count & if width == 64 { 0x3f } else { 0x1f };
    if masked == 0 {
        return Ok(Touch::keep());
    }
    let (result, flags, touch) = apply_shift(op, value, extra, masked, width, old);
    write_dst(cpu, mem, insn, result)?;
    cpu.flags = flags;
    if touch.af == Fate::Undef {
        clear_af(cpu);
    }
    Ok(touch)
}

fn apply_shift(
    op: Shift,
    value: u64,
    extra: u64,
    count: u32,
    width: u32,
    old: Flags,
) -> (u64, Flags, Touch) {
    if count == 0 && !matches!(op, Shift::Shld | Shift::Shrd) {
        return (value & mask(width), old, Touch::keep());
    }
    match op {
        Shift::Shl => flagged(flags::shift_left(value, count, width, old), false, count),
        Shift::Shr => flagged(flags::shift_right(value, count, width, old), false, count),
        Shift::Sar => flagged(flags::shift_arith(value, count, width, old), false, count),
        Shift::Rol => rotate(flags::rotate_left(value, count, width, old), count),
        Shift::Ror => rotate(flags::rotate_right(value, count, width, old), count),
        Shift::Rcl => through_carry(value, count, width, old, true),
        Shift::Rcr => through_carry(value, count, width, old, false),
        Shift::Shld => double(value, extra, count, width, old, true),
        Shift::Shrd => double(value, extra, count, width, old, false),
    }
}

fn flagged(computed: (u64, Flags), rotate_only: bool, count: u32) -> (u64, Flags, Touch) {
    let _ = rotate_only;
    let mut touch = Touch::logic();
    touch.of = if count == 1 { Fate::Write } else { Fate::Undef };
    touch.af = Fate::Undef;
    (computed.0, computed.1, touch)
}

fn rotate(computed: (u64, Flags), count: u32) -> (u64, Flags, Touch) {
    let mut touch = Touch::keep();
    if count != 0 {
        touch.cf = Fate::Write;
        touch.of = if count == 1 { Fate::Write } else { Fate::Undef };
    }
    (computed.0, computed.1, touch)
}

fn through_carry(
    value: u64,
    count: u32,
    width: u32,
    old: Flags,
    left: bool,
) -> (u64, Flags, Touch) {
    let mut touch = Touch::keep();
    if count == 0 {
        return (value & mask(width), old, touch);
    }
    let amount = count % (width + 1);
    let mut result = value & mask(width);
    let mut cf = old.cf;
    for _ in 0..amount {
        if left {
            let out = (result >> (width - 1)) & 1 == 1;
            result = ((result << 1) | u64::from(cf)) & mask(width);
            cf = out;
        } else {
            let out = result & 1 == 1;
            result = ((result >> 1) | (u64::from(cf) << (width - 1))) & mask(width);
            cf = out;
        }
    }
    let mut flags = old;
    flags.cf = cf;
    if amount == 1 {
        let msb = (result >> (width - 1)) & 1 == 1;
        flags.of = if left {
            msb != cf
        } else {
            let next = width > 1 && (result >> (width - 2)) & 1 == 1;
            msb != next
        };
        touch.of = Fate::Write;
    } else {
        touch.of = Fate::Undef;
    }
    touch.cf = Fate::Write;
    (result, flags, touch)
}

fn double(
    dest: u64,
    src: u64,
    count: u32,
    width: u32,
    old: Flags,
    left: bool,
) -> (u64, Flags, Touch) {
    if count == 0 {
        return (dest & mask(width), old, Touch::keep());
    }
    if count > width {
        let mut touch = Touch::logic();
        touch.cf = Fate::Undef;
        touch.of = Fate::Undef;
        touch.pf = Fate::Undef;
        touch.zf = Fate::Undef;
        touch.sf = Fate::Undef;
        return (dest & mask(width), old, touch);
    }
    let m = mask(width);
    let dest = dest & m;
    let src = src & m;
    let result = if left {
        ((dest << count) | (src >> (width - count))) & m
    } else {
        ((dest >> count) | (src << (width - count))) & m
    };
    let cf = if left {
        (dest >> (width - count)) & 1 == 1
    } else {
        (dest >> (count - 1)) & 1 == 1
    };
    let (_, mut flags) = flags::logic_and(result, result, width);
    flags.cf = cf;
    if count == 1 {
        let sign = 1u64 << (width - 1);
        flags.of = if left {
            ((result & sign) != 0) != cf
        } else {
            ((dest ^ result) & sign) != 0
        };
    }
    let mut touch = Touch::logic();
    touch.of = if count == 1 { Fate::Write } else { Fate::Undef };
    (result, flags, touch)
}
