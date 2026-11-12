//! Moves, bit ops, multiply and divide, stack, strings, and flag transfers.

use iced_x86::{Code, Instruction, Mnemonic, OpKind, Register};

use crate::error::{msg, Result};
use crate::flags::{self, Flags};
use crate::ir::{MemIo, RAX, RBP, RBX, RCX, RDI, RDX, RSI, RSP};

use super::{
    address, clear_af, invalid, is_imm, mask, op_bits, operand_address, read_reg, read_src,
    set_arith, sign_extend, write_dst, write_op, write_reg, Cpu, Fate, Touch,
};

pub fn is_side(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Mov
            | Mnemonic::Movzx
            | Mnemonic::Movsx
            | Mnemonic::Movsxd
            | Mnemonic::Lea
            | Mnemonic::Xchg
            | Mnemonic::Xadd
            | Mnemonic::Cmpxchg
            | Mnemonic::Cmpxchg8b
            | Mnemonic::Cmpxchg16b
            | Mnemonic::Bswap
            | Mnemonic::Bsf
            | Mnemonic::Bsr
            | Mnemonic::Bt
            | Mnemonic::Bts
            | Mnemonic::Btr
            | Mnemonic::Btc
            | Mnemonic::Mul
            | Mnemonic::Imul
            | Mnemonic::Div
            | Mnemonic::Idiv
            | Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Pushf
            | Mnemonic::Pushfq
            | Mnemonic::Popf
            | Mnemonic::Popfq
            | Mnemonic::Enter
            | Mnemonic::Leave
            | Mnemonic::Lahf
            | Mnemonic::Sahf
            | Mnemonic::Cbw
            | Mnemonic::Cwde
            | Mnemonic::Cdqe
            | Mnemonic::Cwd
            | Mnemonic::Cdq
            | Mnemonic::Cqo
            | Mnemonic::Clc
            | Mnemonic::Stc
            | Mnemonic::Cmc
            | Mnemonic::Cld
            | Mnemonic::Std
            | Mnemonic::Xlatb
            | Mnemonic::Movsb
            | Mnemonic::Movsw
            | Mnemonic::Movsd
            | Mnemonic::Movsq
            | Mnemonic::Stosb
            | Mnemonic::Stosw
            | Mnemonic::Stosd
            | Mnemonic::Stosq
            | Mnemonic::Lodsb
            | Mnemonic::Lodsw
            | Mnemonic::Lodsd
            | Mnemonic::Lodsq
            | Mnemonic::Scasb
            | Mnemonic::Scasw
            | Mnemonic::Scasd
            | Mnemonic::Scasq
            | Mnemonic::Cmpsb
            | Mnemonic::Cmpsw
            | Mnemonic::Cmpsd
            | Mnemonic::Cmpsq
    )
}

pub fn side(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    match insn.mnemonic() {
        Mnemonic::Mov => mov(cpu, mem, insn),
        Mnemonic::Movzx => movx(cpu, mem, insn, false),
        Mnemonic::Movsx | Mnemonic::Movsxd => movx(cpu, mem, insn, true),
        Mnemonic::Lea => lea(cpu, insn),
        Mnemonic::Xchg => xchg(cpu, mem, insn),
        Mnemonic::Xadd => xadd(cpu, mem, insn),
        Mnemonic::Cmpxchg => cmpxchg(cpu, mem, insn),
        Mnemonic::Cmpxchg8b => cmpxchg8(cpu, mem, insn),
        Mnemonic::Cmpxchg16b => cmpxchg16(cpu, mem, insn),
        Mnemonic::Bswap => bswap(cpu, insn),
        Mnemonic::Bsf => bitscan(cpu, mem, insn, false),
        Mnemonic::Bsr => bitscan(cpu, mem, insn, true),
        Mnemonic::Bt => bit(cpu, mem, insn, 0),
        Mnemonic::Bts => bit(cpu, mem, insn, 1),
        Mnemonic::Btr => bit(cpu, mem, insn, -1),
        Mnemonic::Btc => bit(cpu, mem, insn, 2),
        Mnemonic::Mul => mul_full(cpu, mem, insn, false),
        Mnemonic::Imul => imul(cpu, mem, insn),
        Mnemonic::Div => divide(cpu, mem, insn, false),
        Mnemonic::Idiv => divide(cpu, mem, insn, true),
        Mnemonic::Push => push(cpu, mem, insn),
        Mnemonic::Pop => pop(cpu, mem, insn),
        Mnemonic::Pushf => push_flags(cpu, mem, 2),
        Mnemonic::Pushfq => push_flags(cpu, mem, 8),
        Mnemonic::Popf => pop_flags(cpu, mem, 2),
        Mnemonic::Popfq => pop_flags(cpu, mem, 8),
        Mnemonic::Enter => enter(cpu, mem, insn),
        Mnemonic::Leave => leave(cpu, mem, insn),
        Mnemonic::Lahf => lahf(cpu),
        Mnemonic::Sahf => sahf(cpu),
        Mnemonic::Cbw => cbw(cpu),
        Mnemonic::Cwde => cwde(cpu),
        Mnemonic::Cdqe => cdqe(cpu),
        Mnemonic::Cwd => cwd(cpu),
        Mnemonic::Cdq => cdq(cpu),
        Mnemonic::Cqo => cqo(cpu),
        Mnemonic::Clc => {
            cpu.flags.cf = false;
            Ok(cf_only())
        }
        Mnemonic::Stc => {
            cpu.flags.cf = true;
            Ok(cf_only())
        }
        Mnemonic::Cmc => {
            cpu.flags.cf = !cpu.flags.cf;
            Ok(cf_only())
        }
        Mnemonic::Cld => {
            cpu.df = false;
            Ok(df_only())
        }
        Mnemonic::Std => {
            cpu.df = true;
            Ok(df_only())
        }
        Mnemonic::Xlatb => xlat(cpu, mem, insn),
        other if string_width(other).is_some() => string(cpu, mem, insn),
        _ => Err(msg("integer opcode is not wired")),
    }
}

pub fn cmov(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction, cond: u8) -> Result<Touch> {
    // The source is read even when the condition is false. A 32-bit destination
    // clears its high half either way; only the low half depends on the condition.
    let value = read_src(cpu, mem, insn, 1)?;
    if flags::cond_taken(cond, cpu.flags) {
        write_dst(cpu, mem, insn, value)?;
    } else if op_bits(insn, 0) == 32 {
        let dest = insn.op_register(0);
        let current = read_reg(&cpu.regs, dest);
        write_reg(&mut cpu.regs, dest, current);
    }
    Ok(Touch::keep())
}

pub fn setcc(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction, cond: u8) -> Result<Touch> {
    let value = u64::from(flags::cond_taken(cond, cpu.flags));
    write_dst(cpu, mem, insn, value)?;
    Ok(Touch::keep())
}

fn mov(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let value = read_src(cpu, mem, insn, 1)?;
    write_dst(cpu, mem, insn, value)?;
    Ok(Touch::keep())
}

fn movx(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction, sign: bool) -> Result<Touch> {
    let src_bits = op_bits(insn, 1);
    let dst_bits = op_bits(insn, 0);
    let raw = read_src(cpu, mem, insn, 1)?;
    let value = if sign {
        sign_extend(raw, src_bits) as u64 & mask(dst_bits)
    } else {
        raw & mask(src_bits)
    };
    write_dst(cpu, mem, insn, value)?;
    Ok(Touch::keep())
}

fn lea(cpu: &mut Cpu, insn: &Instruction) -> Result<Touch> {
    let value = address(cpu, insn)?;
    write_reg(&mut cpu.regs, insn.op_register(0), value);
    Ok(Touch::keep())
}

fn xchg(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let left = read_src(cpu, mem, insn, 0)?;
    let right = read_src(cpu, mem, insn, 1)?;
    if insn.op0_kind() == OpKind::Memory {
        write_op(cpu, mem, insn, 0, right)?;
        write_op(cpu, mem, insn, 1, left)?;
    } else {
        write_op(cpu, mem, insn, 1, left)?;
        write_op(cpu, mem, insn, 0, right)?;
    }
    Ok(Touch::keep())
}

fn xadd(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let width = op_bits(insn, 0);
    let dest = read_src(cpu, mem, insn, 0)?;
    let src = read_src(cpu, mem, insn, 1)?;
    let (sum, flags) = flags::add(dest, src, width);
    if insn.op0_kind() == OpKind::Memory {
        write_dst(cpu, mem, insn, sum)?;
        write_op(cpu, mem, insn, 1, dest)?;
    } else {
        write_op(cpu, mem, insn, 1, dest)?;
        write_dst(cpu, mem, insn, sum)?;
    }
    set_arith(cpu, flags, flags::aux_carry(dest, src, sum));
    Ok(Touch::arith())
}

fn cmpxchg(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let width = op_bits(insn, 0);
    let dest = read_src(cpu, mem, insn, 0)?;
    let src = read_src(cpu, mem, insn, 1)?;
    let acc_reg = sized(RAX, width);
    let acc = read_reg(&cpu.regs, acc_reg);
    let (result, flags) = flags::sub(acc, dest, width);
    if (acc ^ dest) & mask(width) == 0 {
        write_dst(cpu, mem, insn, src)?;
    } else {
        write_reg(&mut cpu.regs, acc_reg, dest);
    }
    set_arith(cpu, flags, flags::aux_carry(acc, dest, result));
    Ok(Touch::arith())
}

fn cmpxchg8(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let addr = address(cpu, insn)?;
    if addr & 7 != 0 {
        return Err(msg("general protection"));
    }
    let mem_val = read_width(mem, addr, 8)?;
    let eax = cpu.regs[RAX as usize] & 0xffff_ffff;
    let edx = cpu.regs[RDX as usize] & 0xffff_ffff;
    let expected = edx << 32 | eax;
    let zf = mem_val == expected;
    if zf {
        let ebx = cpu.regs[RBX as usize] & 0xffff_ffff;
        let ecx = cpu.regs[RCX as usize] & 0xffff_ffff;
        mem.write(addr, &(ecx << 32 | ebx).to_le_bytes())?;
    } else {
        cpu.regs[RAX as usize] = mem_val & 0xffff_ffff;
        cpu.regs[RDX as usize] = mem_val >> 32;
    }
    cpu.flags.zf = zf;
    Ok(write_zf())
}

fn cmpxchg16(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let addr = address(cpu, insn)?;
    if addr & 15 != 0 {
        return Err(msg("general protection"));
    }
    let low = read_width(mem, addr, 8)?;
    let high = read_width(mem, addr.wrapping_add(8), 8)?;
    let zf = low == cpu.regs[RAX as usize] && high == cpu.regs[RDX as usize];
    if zf {
        mem.write(addr, &cpu.regs[RBX as usize].to_le_bytes())?;
        mem.write(addr.wrapping_add(8), &cpu.regs[RCX as usize].to_le_bytes())?;
    } else {
        cpu.regs[RAX as usize] = low;
        cpu.regs[RDX as usize] = high;
    }
    cpu.flags.zf = zf;
    Ok(write_zf())
}

fn bswap(cpu: &mut Cpu, insn: &Instruction) -> Result<Touch> {
    let reg = insn.op_register(0);
    let width = reg.size();
    if width < 4 {
        return Err(invalid());
    }
    let value = read_reg(&cpu.regs, reg);
    let swapped = if width == 4 {
        (value as u32).swap_bytes() as u64
    } else {
        value.swap_bytes()
    };
    write_reg(&mut cpu.regs, reg, swapped);
    Ok(Touch::keep())
}

fn bitscan(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction, msb: bool) -> Result<Touch> {
    let width = op_bits(insn, 1);
    let src = read_src(cpu, mem, insn, 1)? & mask(width);
    cpu.flags.zf = src == 0;
    clear_af(cpu);
    cpu.flags.cf = false;
    cpu.flags.pf = false;
    cpu.flags.sf = false;
    cpu.flags.of = false;
    if src != 0 {
        let index = if msb {
            63 - src.leading_zeros()
        } else {
            src.trailing_zeros()
        };
        write_dst(cpu, mem, insn, u64::from(index))?;
    }
    let mut touch = zf_only();
    touch.cf = Fate::Undef;
    touch.pf = Fate::Undef;
    touch.af = Fate::Undef;
    touch.sf = Fate::Undef;
    touch.of = Fate::Undef;
    Ok(touch)
}

fn bit(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction, change: i32) -> Result<Touch> {
    let width = op_bits(insn, 0);
    let offset = if is_imm(insn.op1_kind()) {
        i64::from(insn.immediate8())
    } else {
        sign_extend(read_src(cpu, mem, insn, 1)?, op_bits(insn, 1))
    };
    let old = if insn.op0_kind() == OpKind::Register {
        let bit = (offset as u32) & (width - 1);
        let value = read_reg(&cpu.regs, insn.op_register(0));
        let set = value & (1u64 << bit) != 0;
        if change != 0 {
            let updated = match change {
                1 => value | (1u64 << bit),
                -1 => value & !(1u64 << bit),
                _ => value ^ (1u64 << bit),
            };
            write_reg(&mut cpu.regs, insn.op_register(0), updated);
        }
        set
    } else {
        let ea = address(cpu, insn)?;
        let byte_addr = ea.wrapping_add((offset >> 3) as u64);
        let bit = (offset as u32) & 7;
        let mut byte = read_width(mem, byte_addr, 1)? as u8;
        let set = byte & (1u8 << bit) != 0;
        if change != 0 {
            byte = match change {
                1 => byte | (1u8 << bit),
                -1 => byte & !(1u8 << bit),
                _ => byte ^ (1u8 << bit),
            };
            mem.write(byte_addr, &[byte])?;
        }
        set
    };
    cpu.flags.cf = old;
    clear_af(cpu);
    let mut touch = Touch::keep();
    touch.cf = Fate::Write;
    touch.pf = Fate::Undef;
    touch.af = Fate::Undef;
    touch.zf = Fate::Undef;
    touch.sf = Fate::Undef;
    touch.of = Fate::Undef;
    Ok(touch)
}

fn imul(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    if insn.op_count() == 1 {
        return mul_full(cpu, mem, insn, true);
    }
    let width = op_bits(insn, 0);
    let (left, right) = if insn.op_count() == 3 {
        (read_src(cpu, mem, insn, 1)?, read_src(cpu, mem, insn, 2)?)
    } else {
        (read_src(cpu, mem, insn, 0)?, read_src(cpu, mem, insn, 1)?)
    };
    let (result, flags) = if width == 64 && insn.op_count() >= 2 {
        flags::imul(left, right)
    } else {
        trunc_mul(left, right, width)
    };
    write_dst(cpu, mem, insn, result)?;
    cpu.flags = flags;
    clear_af(cpu);
    let mut touch = Touch::keep();
    touch.cf = Fate::Write;
    touch.of = Fate::Write;
    touch.pf = Fate::Undef;
    touch.af = Fate::Undef;
    touch.zf = Fate::Undef;
    touch.sf = Fate::Undef;
    Ok(touch)
}

fn trunc_mul(left: u64, right: u64, width: u32) -> (u64, Flags) {
    let full = sign_extend(left, width) as i128 * sign_extend(right, width) as i128;
    let result = (full as u64) & mask(width);
    let fits = full == sign_extend(result, width) as i128;
    let (_, mut flags) = flags::logic_and(result, result, width);
    flags.cf = !fits;
    flags.of = !fits;
    (result, flags)
}

fn mul_full(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction, signed: bool) -> Result<Touch> {
    let width = op_bits(insn, 0);
    let src = read_src(cpu, mem, insn, 0)?;
    let wide = match width {
        8 => mul_pair(cpu.regs[RAX as usize] & 0xff, src, 8, signed),
        16 => mul_pair(cpu.regs[RAX as usize] & 0xffff, src, 16, signed),
        32 => mul_pair(cpu.regs[RAX as usize] & 0xffff_ffff, src, 32, signed),
        _ => mul_pair(cpu.regs[RAX as usize], src, 64, signed),
    };
    store_pair(cpu, wide.0, wide.1, width);
    cpu.flags.cf = wide.2;
    cpu.flags.of = wide.2;
    clear_af(cpu);
    let mut touch = Touch::keep();
    touch.cf = Fate::Write;
    touch.of = Fate::Write;
    touch.pf = Fate::Undef;
    touch.af = Fate::Undef;
    touch.zf = Fate::Undef;
    touch.sf = Fate::Undef;
    Ok(touch)
}

fn mul_pair(left: u64, right: u64, width: u32, signed: bool) -> (u64, u64, bool) {
    let low_mask = mask(width);
    if signed {
        let prod = sign_extend(left, width) as i128 * sign_extend(right, width) as i128;
        let low = (prod as u64) & low_mask;
        let high = ((prod >> width) as u64) & low_mask;
        let carry = prod != sign_extend(low, width) as i128;
        (low, high, carry)
    } else {
        let prod = (left & low_mask) as u128 * (right & low_mask) as u128;
        let low = (prod as u64) & low_mask;
        let high = ((prod >> width) as u64) & low_mask;
        (low, high, high != 0)
    }
}

fn store_pair(cpu: &mut Cpu, low: u64, high: u64, width: u32) {
    match width {
        8 => {
            cpu.regs[RAX as usize] =
                (cpu.regs[RAX as usize] & !0xffff) | ((high & 0xff) << 8) | (low & 0xff);
        }
        16 => {
            cpu.regs[RAX as usize] = (cpu.regs[RAX as usize] & !0xffff) | (low & 0xffff);
            cpu.regs[RDX as usize] = (cpu.regs[RDX as usize] & !0xffff) | (high & 0xffff);
        }
        32 => {
            cpu.regs[RAX as usize] = low & 0xffff_ffff;
            cpu.regs[RDX as usize] = high & 0xffff_ffff;
        }
        _ => {
            cpu.regs[RAX as usize] = low;
            cpu.regs[RDX as usize] = high;
        }
    }
}

fn divide(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction, signed: bool) -> Result<Touch> {
    let width = op_bits(insn, 0);
    let src = read_src(cpu, mem, insn, 0)? & mask(width);
    if src == 0 {
        return Err(msg("division by zero"));
    }
    let (low, high) = if signed {
        idiv_pair(cpu, src, width)?
    } else {
        div_pair(cpu, src, width)?
    };
    store_pair(cpu, low, high, width);
    Ok(undef_flags())
}

fn div_pair(cpu: &Cpu, src: u64, width: u32) -> Result<(u64, u64)> {
    let dividend = dividend_u(cpu, width);
    let quot = dividend / u128::from(src);
    let limit = if width >= 64 {
        u128::from(u64::MAX)
    } else {
        (1u128 << width) - 1
    };
    if quot > limit {
        return Err(msg("division overflow"));
    }
    let rem = dividend % u128::from(src);
    Ok((quot as u64, rem as u64))
}

fn idiv_pair(cpu: &Cpu, src: u64, width: u32) -> Result<(u64, u64)> {
    let dividend = dividend_i(cpu, width);
    let divisor = sign_extend(src, width) as i128;
    if divisor == 0 {
        return Err(msg("division by zero"));
    }
    if divisor == -1 && dividend == min_dividend(width) {
        return Err(msg("division overflow"));
    }
    let quot = dividend / divisor;
    let rem = dividend % divisor;
    let limit = if width >= 64 {
        i128::from(i64::MAX)
    } else {
        (1i128 << (width - 1)) - 1
    };
    let floor = if width >= 64 {
        i128::from(i64::MIN)
    } else {
        -((1i128) << (width - 1))
    };
    if quot < floor || quot > limit {
        return Err(msg("division overflow"));
    }
    Ok((quot as u64 & mask(width), rem as u64 & mask(width)))
}

fn dividend_u(cpu: &Cpu, width: u32) -> u128 {
    match width {
        8 => u128::from(cpu.regs[RAX as usize] & 0xffff),
        16 => {
            u128::from((cpu.regs[RDX as usize] & 0xffff) << 16 | (cpu.regs[RAX as usize] & 0xffff))
        }
        32 => u128::from(
            (cpu.regs[RDX as usize] & 0xffff_ffff) << 32 | (cpu.regs[RAX as usize] & 0xffff_ffff),
        ),
        _ => (u128::from(cpu.regs[RDX as usize]) << 64) | u128::from(cpu.regs[RAX as usize]),
    }
}

fn dividend_i(cpu: &Cpu, width: u32) -> i128 {
    match width {
        8 => i128::from(sign_extend(cpu.regs[RAX as usize] & 0xffff, 16)),
        16 => i128::from(sign_extend(dividend_u(cpu, 16) as u64, 32)),
        32 => i128::from(sign_extend(dividend_u(cpu, 32) as u64, 64)),
        _ => dividend_u(cpu, 64) as i128,
    }
}

fn min_dividend(width: u32) -> i128 {
    match width {
        8 => i128::from(i16::MIN),
        16 => i128::from(i32::MIN),
        32 => i128::from(i64::MIN),
        _ => i128::MIN,
    }
}

fn push(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let bytes = push_bytes(insn)?;
    let value = read_src(cpu, mem, insn, 0)?;
    push_bytes_raw(cpu, mem, value, bytes)?;
    Ok(Touch::keep())
}

fn pop(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let bytes = push_bytes(insn)?;
    let value = pop_bytes_raw(cpu, mem, bytes)?;
    write_dst(cpu, mem, insn, value)?;
    Ok(Touch::keep())
}

fn push_bytes(insn: &Instruction) -> Result<usize> {
    let size = match insn.op0_kind() {
        OpKind::Register => insn.op_register(0).size(),
        OpKind::Memory => insn.memory_size().size(),
        OpKind::Immediate16 => 2,
        kind if is_imm(kind) => 8,
        _ => return Err(msg("unsupported push")),
    };
    if size == 4 {
        return Err(invalid());
    }
    Ok(size)
}

fn push_flags(cpu: &mut Cpu, mem: &mut dyn MemIo, bytes: usize) -> Result<Touch> {
    push_bytes_raw(cpu, mem, rflags_image(cpu), bytes)?;
    Ok(Touch::keep())
}

fn pop_flags(cpu: &mut Cpu, mem: &mut dyn MemIo, bytes: usize) -> Result<Touch> {
    let value = pop_bytes_raw(cpu, mem, bytes)?;
    let bits = if bytes == 2 {
        (rflags_image(cpu) & !0xffff) | (value & 0xffff)
    } else {
        value
    };
    apply_image(cpu, bits);
    Ok(Touch {
        cf: Fate::Write,
        pf: Fate::Write,
        af: Fate::Write,
        zf: Fate::Write,
        sf: Fate::Write,
        of: Fate::Write,
        df: Fate::Write,
    })
}

fn rflags_image(cpu: &Cpu) -> u64 {
    let mut bits = 0x202u64;
    bits |= cpu.flags.pack();
    if cpu.af {
        bits |= 1 << 4;
    }
    if cpu.df {
        bits |= 1 << 10;
    }
    bits
}

fn apply_image(cpu: &mut Cpu, bits: u64) {
    cpu.flags = Flags::unpack(bits);
    cpu.af = bits & (1 << 4) != 0;
    cpu.df = bits & (1 << 10) != 0;
}

fn push_bytes_raw(cpu: &mut Cpu, mem: &mut dyn MemIo, value: u64, bytes: usize) -> Result<()> {
    let rsp = cpu.regs[RSP as usize].wrapping_sub(bytes as u64);
    cpu.regs[RSP as usize] = rsp;
    mem.write(rsp, &value.to_le_bytes()[..bytes])
}

fn pop_bytes_raw(cpu: &mut Cpu, mem: &mut dyn MemIo, bytes: usize) -> Result<u64> {
    let rsp = cpu.regs[RSP as usize];
    let data = mem.read(rsp, bytes)?;
    cpu.regs[RSP as usize] = rsp.wrapping_add(bytes as u64);
    Ok(assemble(&data))
}

fn enter(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let (width, bytes) = frame_width(insn)?;
    let alloc = u64::from(insn.immediate16());
    let level = u32::from(insn.immediate8_2nd()) & 31;
    let frame_reg = sized(RBP, width);
    let old_bp = read_reg(&cpu.regs, frame_reg);
    push_bytes_raw(cpu, mem, old_bp, bytes)?;
    let frame = cpu.regs[RSP as usize];
    if level > 0 {
        for _ in 1..level {
            let next = read_reg(&cpu.regs, frame_reg).wrapping_sub(bytes as u64);
            write_reg(&mut cpu.regs, frame_reg, next);
            let addr = read_reg(&cpu.regs, frame_reg);
            let value = read_width(mem, addr, bytes)?;
            push_bytes_raw(cpu, mem, value, bytes)?;
        }
        push_bytes_raw(cpu, mem, frame, bytes)?;
    }
    write_reg(&mut cpu.regs, frame_reg, frame);
    cpu.regs[RSP as usize] = cpu.regs[RSP as usize].wrapping_sub(alloc);
    Ok(Touch::keep())
}

fn leave(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let (width, bytes) = frame_width(insn)?;
    let frame = read_reg(&cpu.regs, sized(RBP, width));
    cpu.regs[RSP as usize] = if width == 16 {
        (cpu.regs[RSP as usize] & !0xffff) | (frame & 0xffff)
    } else {
        frame
    };
    let value = pop_bytes_raw(cpu, mem, bytes)?;
    write_reg(&mut cpu.regs, sized(RBP, width), value);
    Ok(Touch::keep())
}

fn frame_width(insn: &Instruction) -> Result<(u32, usize)> {
    match insn.code() {
        Code::Enterw_imm16_imm8 | Code::Leavew => Ok((16, 2)),
        Code::Enterd_imm16_imm8 | Code::Leaved => Err(invalid()),
        _ => Ok((64, 8)),
    }
}

fn lahf(cpu: &mut Cpu) -> Result<Touch> {
    let mut ah = 0x02u64;
    if cpu.flags.cf {
        ah |= 1;
    }
    if cpu.flags.pf {
        ah |= 1 << 2;
    }
    if cpu.af {
        ah |= 1 << 4;
    }
    if cpu.flags.zf {
        ah |= 1 << 6;
    }
    if cpu.flags.sf {
        ah |= 1 << 7;
    }
    write_reg(&mut cpu.regs, Register::AH, ah);
    Ok(Touch::keep())
}

fn sahf(cpu: &mut Cpu) -> Result<Touch> {
    let ah = read_reg(&cpu.regs, Register::AH);
    cpu.flags.cf = ah & 1 != 0;
    cpu.flags.pf = ah & (1 << 2) != 0;
    cpu.af = ah & (1 << 4) != 0;
    cpu.flags.zf = ah & (1 << 6) != 0;
    cpu.flags.sf = ah & (1 << 7) != 0;
    Ok(Touch {
        cf: Fate::Write,
        pf: Fate::Write,
        af: Fate::Write,
        zf: Fate::Write,
        sf: Fate::Write,
        of: Fate::Keep,
        df: Fate::Keep,
    })
}

fn cbw(cpu: &mut Cpu) -> Result<Touch> {
    let ax = sign_extend(cpu.regs[RAX as usize] & 0xff, 8) as u64 & 0xffff;
    cpu.regs[RAX as usize] = (cpu.regs[RAX as usize] & !0xffff) | ax;
    Ok(Touch::keep())
}

fn cwde(cpu: &mut Cpu) -> Result<Touch> {
    let eax = sign_extend(cpu.regs[RAX as usize] & 0xffff, 16) as u64 & 0xffff_ffff;
    cpu.regs[RAX as usize] = eax;
    Ok(Touch::keep())
}

fn cdqe(cpu: &mut Cpu) -> Result<Touch> {
    cpu.regs[RAX as usize] = sign_extend(cpu.regs[RAX as usize] & 0xffff_ffff, 32) as u64;
    Ok(Touch::keep())
}

fn cwd(cpu: &mut Cpu) -> Result<Touch> {
    let dx = if cpu.regs[RAX as usize] & 0x8000 != 0 {
        0xffff
    } else {
        0
    };
    cpu.regs[RDX as usize] = (cpu.regs[RDX as usize] & !0xffff) | dx;
    Ok(Touch::keep())
}

fn cdq(cpu: &mut Cpu) -> Result<Touch> {
    let edx = if cpu.regs[RAX as usize] & 0x8000_0000 != 0 {
        0xffff_ffff
    } else {
        0
    };
    cpu.regs[RDX as usize] = edx;
    Ok(Touch::keep())
}

fn cqo(cpu: &mut Cpu) -> Result<Touch> {
    cpu.regs[RDX as usize] = if cpu.regs[RAX as usize] & 0x8000_0000_0000_0000 != 0 {
        u64::MAX
    } else {
        0
    };
    Ok(Touch::keep())
}

fn xlat(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    // iced shows XLAT as `[base+al]`. The index is AL itself, so the address is
    // the base plus that byte once.
    let al = cpu.regs[RAX as usize] & 0xff;
    let base = insn.memory_base();
    let mut addr = if base == Register::None {
        0
    } else {
        read_reg(&cpu.regs, base)
    };
    addr = addr
        .wrapping_add(al)
        .wrapping_add(insn.memory_displacement64());
    let bits = base.size() * 8;
    if bits == 32 || bits == 16 {
        addr &= mask(bits as u32);
    }
    if insn.memory_segment() == Register::GS {
        addr = addr.wrapping_add(cpu.gs);
    }
    let byte = read_width(mem, addr, 1)?;
    write_reg(&mut cpu.regs, Register::AL, byte);
    Ok(Touch::keep())
}

fn string(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let width = string_width(insn.mnemonic()).ok_or_else(|| msg("string op"))?;
    let compare = is_compare(insn.mnemonic());
    let rep = insn.has_rep_prefix() || insn.has_repne_prefix();
    let addr_bits = string_addr_bits(insn);
    let mut left = if rep {
        cpu.regs[RCX as usize] & mask(addr_bits)
    } else {
        1
    };
    if rep && left == 0 {
        return Ok(Touch::keep());
    }
    let mut touch = Touch::keep();
    while left != 0 {
        touch = string_once(cpu, mem, insn, width)?;
        left = left.wrapping_sub(1);
        if rep {
            write_counter(cpu, left, addr_bits);
        }
        if compare && insn.has_repne_prefix() && cpu.flags.zf {
            break;
        }
        if compare && insn.has_rep_prefix() && !cpu.flags.zf {
            break;
        }
        if !rep {
            break;
        }
    }
    Ok(touch)
}

fn is_compare(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Scasb
            | Mnemonic::Scasw
            | Mnemonic::Scasd
            | Mnemonic::Scasq
            | Mnemonic::Cmpsb
            | Mnemonic::Cmpsw
            | Mnemonic::Cmpsd
            | Mnemonic::Cmpsq
    )
}

fn string_once(
    cpu: &mut Cpu,
    mem: &mut dyn MemIo,
    insn: &Instruction,
    width: u32,
) -> Result<Touch> {
    let bytes = (width / 8) as usize;
    let mnemonic = insn.mnemonic();
    match mnemonic {
        Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq => {
            let src = operand_address(cpu, insn, 1, true)?;
            let dst = operand_address(cpu, insn, 0, true)?;
            let value = read_width(mem, src, bytes)?;
            mem.write(dst, &value.to_le_bytes()[..bytes])?;
            step_string(cpu, insn, 1, width);
            step_string(cpu, insn, 0, width);
            Ok(Touch::keep())
        }
        Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq => {
            let dst = operand_address(cpu, insn, 0, true)?;
            let value = read_reg(&cpu.regs, sized(RAX, width));
            mem.write(dst, &value.to_le_bytes()[..bytes])?;
            step_string(cpu, insn, 0, width);
            Ok(Touch::keep())
        }
        Mnemonic::Lodsb | Mnemonic::Lodsw | Mnemonic::Lodsd | Mnemonic::Lodsq => {
            let src = operand_address(cpu, insn, 1, true)?;
            let value = read_width(mem, src, bytes)?;
            write_reg(&mut cpu.regs, sized(RAX, width), value);
            step_string(cpu, insn, 1, width);
            Ok(Touch::keep())
        }
        Mnemonic::Scasb | Mnemonic::Scasw | Mnemonic::Scasd | Mnemonic::Scasq => {
            let src = operand_address(cpu, insn, 1, true)?;
            let mem_val = read_width(mem, src, bytes)?;
            let acc = read_reg(&cpu.regs, sized(RAX, width));
            let (result, flags) = flags::sub(acc, mem_val, width);
            set_arith(cpu, flags, flags::aux_carry(acc, mem_val, result));
            step_string(cpu, insn, 1, width);
            Ok(Touch::arith())
        }
        Mnemonic::Cmpsb | Mnemonic::Cmpsw | Mnemonic::Cmpsd | Mnemonic::Cmpsq => {
            let left = read_width(mem, operand_address(cpu, insn, 0, true)?, bytes)?;
            let right = read_width(mem, operand_address(cpu, insn, 1, true)?, bytes)?;
            let (result, flags) = flags::sub(left, right, width);
            set_arith(cpu, flags, flags::aux_carry(left, right, result));
            step_string(cpu, insn, 0, width);
            step_string(cpu, insn, 1, width);
            Ok(Touch::arith())
        }
        _ => Err(msg("string op")),
    }
}

fn string_addr_bits(insn: &Instruction) -> u32 {
    (0..insn.op_count())
        .find_map(|index| pointer_reg(insn.op_kind(index)).map(|(_, bits)| bits))
        .unwrap_or(64)
}

fn step_string(cpu: &mut Cpu, insn: &Instruction, operand: u32, width: u32) {
    let Some((reg, bits)) = pointer_reg(insn.op_kind(operand)) else {
        return;
    };
    let delta = u64::from(width / 8);
    let current = cpu.regs[reg as usize] & mask(bits);
    let next = if cpu.df {
        current.wrapping_sub(delta)
    } else {
        current.wrapping_add(delta)
    };
    cpu.regs[reg as usize] = if bits >= 64 {
        next
    } else if bits == 32 {
        next & 0xffff_ffff
    } else {
        (cpu.regs[reg as usize] & !0xffff) | (next & 0xffff)
    };
}

fn pointer_reg(kind: OpKind) -> Option<(u16, u32)> {
    Some(match kind {
        OpKind::MemorySegRSI => (RSI, 64),
        OpKind::MemorySegESI => (RSI, 32),
        OpKind::MemorySegSI => (RSI, 16),
        OpKind::MemorySegRDI | OpKind::MemoryESRDI => (RDI, 64),
        OpKind::MemorySegEDI | OpKind::MemoryESEDI => (RDI, 32),
        OpKind::MemorySegDI | OpKind::MemoryESDI => (RDI, 16),
        _ => return None,
    })
}

fn write_counter(cpu: &mut Cpu, value: u64, bits: u32) {
    cpu.regs[RCX as usize] = if bits >= 64 {
        value
    } else if bits == 32 {
        value & 0xffff_ffff
    } else {
        (cpu.regs[RCX as usize] & !0xffff) | (value & 0xffff)
    };
}

fn string_width(mnemonic: Mnemonic) -> Option<u32> {
    Some(match mnemonic {
        Mnemonic::Movsb | Mnemonic::Stosb | Mnemonic::Lodsb | Mnemonic::Scasb | Mnemonic::Cmpsb => {
            8
        }
        Mnemonic::Movsw | Mnemonic::Stosw | Mnemonic::Lodsw | Mnemonic::Scasw | Mnemonic::Cmpsw => {
            16
        }
        Mnemonic::Movsd | Mnemonic::Stosd | Mnemonic::Lodsd | Mnemonic::Scasd | Mnemonic::Cmpsd => {
            32
        }
        Mnemonic::Movsq | Mnemonic::Stosq | Mnemonic::Lodsq | Mnemonic::Scasq | Mnemonic::Cmpsq => {
            64
        }
        _ => return None,
    })
}

fn sized(index: u16, width: u32) -> Register {
    let base = match index {
        RAX => 0,
        RCX => 1,
        RDX => 2,
        RBX => 3,
        RSP => 4,
        RBP => 5,
        RSI => 6,
        RDI => 7,
        _ => 0,
    };
    match width {
        8 => match base {
            0 => Register::AL,
            1 => Register::CL,
            2 => Register::DL,
            3 => Register::BL,
            _ => Register::AL,
        },
        16 => match base {
            0 => Register::AX,
            1 => Register::CX,
            2 => Register::DX,
            3 => Register::BX,
            4 => Register::SP,
            5 => Register::BP,
            6 => Register::SI,
            7 => Register::DI,
            _ => Register::AX,
        },
        32 => match base {
            0 => Register::EAX,
            1 => Register::ECX,
            2 => Register::EDX,
            3 => Register::EBX,
            4 => Register::ESP,
            5 => Register::EBP,
            6 => Register::ESI,
            7 => Register::EDI,
            _ => Register::EAX,
        },
        _ => match base {
            0 => Register::RAX,
            1 => Register::RCX,
            2 => Register::RDX,
            3 => Register::RBX,
            4 => Register::RSP,
            5 => Register::RBP,
            6 => Register::RSI,
            7 => Register::RDI,
            _ => Register::RAX,
        },
    }
}

fn read_width(mem: &mut dyn MemIo, addr: u64, bytes: usize) -> Result<u64> {
    Ok(assemble(&mem.read(addr, bytes)?))
}

fn assemble(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (8 * index);
    }
    value
}

fn cf_only() -> Touch {
    let mut touch = Touch::keep();
    touch.cf = Fate::Write;
    touch
}

fn df_only() -> Touch {
    let mut touch = Touch::keep();
    touch.df = Fate::Write;
    touch
}

fn zf_only() -> Touch {
    let mut touch = Touch::keep();
    touch.zf = Fate::Write;
    touch.cf = Fate::Undef;
    touch.pf = Fate::Undef;
    touch.af = Fate::Undef;
    touch.sf = Fate::Undef;
    touch.of = Fate::Undef;
    touch
}

fn write_zf() -> Touch {
    let mut touch = Touch::keep();
    touch.zf = Fate::Write;
    touch
}

fn undef_flags() -> Touch {
    Touch {
        cf: Fate::Undef,
        pf: Fate::Undef,
        af: Fate::Undef,
        zf: Fate::Undef,
        sf: Fate::Undef,
        of: Fate::Undef,
        df: Fate::Keep,
    }
}
