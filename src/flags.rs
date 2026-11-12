#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Flags {
    pub cf: bool,
    pub pf: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
}

impl Flags {
    pub fn pack(self) -> u64 {
        u64::from(self.cf)
            | (u64::from(self.pf) << 2)
            | (u64::from(self.zf) << 6)
            | (u64::from(self.sf) << 7)
            | (u64::from(self.of) << 11)
    }

    pub fn unpack(bits: u64) -> Self {
        Self {
            cf: bits & 1 != 0,
            pf: bits & (1 << 2) != 0,
            zf: bits & (1 << 6) != 0,
            sf: bits & (1 << 7) != 0,
            of: bits & (1 << 11) != 0,
        }
    }
}

pub fn cond_taken(cond: u8, flags: Flags) -> bool {
    match cond & 0x0f {
        0 => flags.of,
        1 => !flags.of,
        2 => flags.cf,
        3 => !flags.cf,
        4 => flags.zf,
        5 => !flags.zf,
        6 => flags.cf || flags.zf,
        7 => !flags.cf && !flags.zf,
        8 => flags.sf,
        9 => !flags.sf,
        10 => flags.pf,
        11 => !flags.pf,
        12 => flags.sf != flags.of,
        13 => flags.sf == flags.of,
        14 => flags.zf || flags.sf != flags.of,
        _ => !flags.zf && flags.sf == flags.of,
    }
}

fn parity(value: u64) -> bool {
    (value as u8).count_ones().is_multiple_of(2)
}

fn mask_of(width: u32) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

fn sign_of(width: u32) -> u64 {
    1u64 << (width - 1)
}

fn logic(result: u64, width: u32) -> Flags {
    let sign = sign_of(width);
    Flags {
        cf: false,
        of: false,
        zf: result & mask_of(width) == 0,
        sf: result & sign != 0,
        pf: parity(result),
    }
}

pub fn add(a: u64, b: u64, width: u32) -> (u64, Flags) {
    let m = mask_of(width);
    let sign = sign_of(width);
    let a = a & m;
    let b = b & m;
    let full = a.wrapping_add(b);
    let result = full & m;
    let carry = if width >= 64 {
        a.wrapping_add(b) < a
    } else {
        (a as u128) + (b as u128) > m as u128
    };
    let flags = Flags {
        cf: carry,
        zf: result == 0,
        sf: result & sign != 0,
        pf: parity(result),
        of: (a ^ result) & (b ^ result) & sign != 0,
    };
    (result, flags)
}

pub fn sub(a: u64, b: u64, width: u32) -> (u64, Flags) {
    let m = mask_of(width);
    let sign = sign_of(width);
    let a = a & m;
    let b = b & m;
    let result = a.wrapping_sub(b) & m;
    let flags = Flags {
        cf: a < b,
        zf: result == 0,
        sf: result & sign != 0,
        pf: parity(result),
        of: (a ^ b) & (a ^ result) & sign != 0,
    };
    (result, flags)
}

pub fn logic_and(a: u64, b: u64, width: u32) -> (u64, Flags) {
    let result = (a & b) & mask_of(width);
    (result, logic(result, width))
}

pub fn logic_or(a: u64, b: u64, width: u32) -> (u64, Flags) {
    let result = (a | b) & mask_of(width);
    (result, logic(result, width))
}

pub fn logic_xor(a: u64, b: u64, width: u32) -> (u64, Flags) {
    let result = (a ^ b) & mask_of(width);
    (result, logic(result, width))
}

pub fn inc(a: u64, width: u32, old: Flags) -> (u64, Flags) {
    let (result, mut flags) = add(a, 1, width);
    flags.cf = old.cf;
    (result, flags)
}

pub fn dec(a: u64, width: u32, old: Flags) -> (u64, Flags) {
    let (result, mut flags) = sub(a, 1, width);
    flags.cf = old.cf;
    (result, flags)
}

pub fn neg(a: u64, width: u32) -> (u64, Flags) {
    let (result, mut flags) = sub(0, a & mask_of(width), width);
    flags.cf = (a & mask_of(width)) != 0;
    (result, flags)
}

pub fn shift_left(a: u64, count: u32, width: u32, old: Flags) -> (u64, Flags) {
    let Some((count, m, a)) = shift_inputs(a, count, width) else {
        return (a, old);
    };
    if count == 0 {
        return (a, old);
    }
    let result = if count >= width { 0 } else { (a << count) & m };
    let cf = if count > width {
        false
    } else {
        (a >> (width - count)) & 1 != 0
    };
    let mut flags = logic(result, width);
    flags.cf = cf;
    if count == 1 {
        flags.of = ((result >> (width - 1)) & 1) != u64::from(cf);
    }
    (result, flags)
}

pub fn shift_right(a: u64, count: u32, width: u32, old: Flags) -> (u64, Flags) {
    let Some((count, _m, a)) = shift_inputs(a, count, width) else {
        return (a, old);
    };
    if count == 0 {
        return (a, old);
    }
    let result = if count >= width { 0 } else { a >> count };
    let cf = if count > width {
        false
    } else {
        (a >> (count - 1)) & 1 != 0
    };
    let mut flags = logic(result, width);
    flags.cf = cf;
    if count == 1 {
        flags.of = a & sign_of(width) != 0;
    }
    (result, flags)
}

pub fn shift_arith(a: u64, count: u32, width: u32, old: Flags) -> (u64, Flags) {
    let Some((count, m, a)) = shift_inputs(a, count, width) else {
        return (a, old);
    };
    if count == 0 {
        return (a, old);
    }
    let sign_bit = sign_of(width);
    if count >= width {
        let sign = a & sign_bit != 0;
        let result = if sign { m } else { 0 };
        let mut flags = logic(result, width);
        flags.cf = sign;
        return (result, flags);
    }
    let signed = if a & sign_bit != 0 { a | !m } else { a };
    let result = ((signed as i64) >> count) as u64 & m;
    let cf = (a >> (count - 1)) & 1 != 0;
    let mut flags = logic(result, width);
    flags.cf = cf;
    if count == 1 {
        flags.of = false;
    }
    (result, flags)
}

pub fn rotate_left(a: u64, count: u32, width: u32, old: Flags) -> (u64, Flags) {
    let Some((count, m, a)) = shift_inputs(a, count, width) else {
        return (a, old);
    };
    if count == 0 {
        return (a, old);
    }
    let result = rotate_bits(a, count % width, width, m, true);
    let mut flags = old;
    flags.cf = result & 1 != 0;
    if count == 1 {
        flags.of = ((result >> (width - 1)) & 1) != u64::from(flags.cf);
    }
    (result, flags)
}

pub fn rotate_right(a: u64, count: u32, width: u32, old: Flags) -> (u64, Flags) {
    let Some((count, m, a)) = shift_inputs(a, count, width) else {
        return (a, old);
    };
    if count == 0 {
        return (a, old);
    }
    let result = rotate_bits(a, count % width, width, m, false);
    let mut flags = old;
    flags.cf = (result >> (width - 1)) & 1 != 0;
    if count == 1 {
        let msb = (result >> (width - 1)) & 1;
        let next = (result >> (width - 2)) & 1;
        flags.of = msb != next;
    }
    (result, flags)
}

fn shift_inputs(a: u64, count: u32, width: u32) -> Option<(u32, u64, u64)> {
    if !(1..=64).contains(&width) {
        return None;
    }
    let count = count & (if width == 64 { 0x3f } else { 0x1f });
    let m = mask_of(width);
    Some((count, m, a & m))
}

fn rotate_bits(a: u64, reduced: u32, width: u32, mask: u64, left: bool) -> u64 {
    if reduced == 0 {
        return a;
    }
    let other = width - reduced;
    let result = if left {
        (a << reduced) | (a >> other)
    } else {
        (a >> reduced) | (a << other)
    };
    result & mask
}

pub fn adc(a: u64, b: u64, width: u32, carry: bool) -> (u64, Flags) {
    let (sum, first) = add(a, b, width);
    let (result, second) = add(sum, u64::from(carry), width);
    let mut flags = second;
    flags.cf = first.cf || second.cf;
    let sign = sign_of(width);
    let result = result & mask_of(width);
    flags.of = (a ^ result) & (b ^ result) & sign != 0;
    flags.zf = result == 0;
    flags.sf = result & sign != 0;
    flags.pf = parity(result);
    (result, flags)
}

pub fn sbb(a: u64, b: u64, width: u32, borrow: bool) -> (u64, Flags) {
    let (diff, first) = sub(a, b, width);
    let (result, second) = sub(diff, u64::from(borrow), width);
    let mut flags = second;
    flags.cf = first.cf || second.cf;
    let sign = sign_of(width);
    let aa = a & mask_of(width);
    flags.of = (aa ^ (b & mask_of(width))) & (aa ^ result) & sign != 0;
    flags.zf = result == 0;
    flags.sf = result & sign != 0;
    flags.pf = parity(result);
    (result, flags)
}

/// Carry out of bit 3. Defined for add, sub, adc, sbb, inc, dec, and neg.
#[must_use]
pub fn aux_carry(a: u64, b: u64, result: u64) -> bool {
    (a ^ b ^ result) & 0x10 != 0
}

pub fn imul(a: u64, b: u64) -> (u64, Flags) {
    let full = (a as i64 as i128).wrapping_mul(b as i64 as i128);
    let result = full as u64;
    let fits = full == result as i64 as i128;
    let mut flags = logic(result, 64);
    flags.cf = !fits;
    flags.of = !fits;
    (result, flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu_binop(op: &str, a: u64, b: u64) -> (u64, u64) {
        let mut result: u64;
        let mut flags: u64;
        // SAFETY: the asm only reads the two register operands and RFLAGS.
        // It does not dereference memory.
        unsafe {
            match op {
                "add" => core::arch::asm!(
                    "add {a}, {b}",
                    "pushfq",
                    "pop {f}",
                    a = inout(reg) a => result,
                    b = in(reg) b,
                    f = lateout(reg) flags,
                ),
                "sub" => core::arch::asm!(
                    "sub {a}, {b}",
                    "pushfq",
                    "pop {f}",
                    a = inout(reg) a => result,
                    b = in(reg) b,
                    f = lateout(reg) flags,
                ),
                "xor" => core::arch::asm!(
                    "xor {a}, {b}",
                    "pushfq",
                    "pop {f}",
                    a = inout(reg) a => result,
                    b = in(reg) b,
                    f = lateout(reg) flags,
                ),
                "and" => core::arch::asm!(
                    "and {a}, {b}",
                    "pushfq",
                    "pop {f}",
                    a = inout(reg) a => result,
                    b = in(reg) b,
                    f = lateout(reg) flags,
                ),
                "or" => core::arch::asm!(
                    "or {a}, {b}",
                    "pushfq",
                    "pop {f}",
                    a = inout(reg) a => result,
                    b = in(reg) b,
                    f = lateout(reg) flags,
                ),
                "imul" => core::arch::asm!(
                    "imul {a}, {b}",
                    "pushfq",
                    "pop {f}",
                    a = inout(reg) a => result,
                    b = in(reg) b,
                    f = lateout(reg) flags,
                ),
                _ => panic!("op"),
            }
        }
        (result, flags)
    }

    fn assert_flags(kind: &str, got: Flags, raw: u64) {
        let hw = Flags::unpack(raw);
        assert_eq!(got.cf, hw.cf, "{kind} cf {raw:#x}");
        assert_eq!(got.zf, hw.zf, "{kind} zf");
        assert_eq!(got.sf, hw.sf, "{kind} sf");
        assert_eq!(got.pf, hw.pf, "{kind} pf");
        assert_eq!(got.of, hw.of, "{kind} of");
    }

    #[test]
    fn arithmetic_matches_cpu() {
        let samples = [
            0u64,
            1,
            2,
            7,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            0xffff_ffff_ffff_ffff,
            0x5a,
            42,
        ];
        for a in samples {
            for b in samples {
                let (r, f) = cpu_binop("add", a, b);
                let (gr, gf) = add(a, b, 64);
                assert_eq!(gr, r, "add {a:#x} {b:#x}");
                assert_flags("add", gf, f);
                let (r, f) = cpu_binop("sub", a, b);
                let (gr, gf) = sub(a, b, 64);
                assert_eq!(gr, r);
                assert_flags("sub", gf, f);
                let (r, f) = cpu_binop("xor", a, b);
                let (gr, gf) = logic_xor(a, b, 64);
                assert_eq!(gr, r);
                assert_flags("xor", gf, f);
                let (r, f) = cpu_binop("and", a, b);
                let (gr, gf) = logic_and(a, b, 64);
                assert_eq!(gr, r);
                assert_flags("and", gf, f);
                let (r, f) = cpu_binop("imul", a, b);
                let (gr, gf) = imul(a, b);
                assert_eq!(gr, r, "imul {a:#x} {b:#x}");
                assert_eq!(gf.cf, Flags::unpack(f).cf, "imul cf");
                assert_eq!(gf.of, Flags::unpack(f).of, "imul of");
            }
        }
    }

    #[test]
    fn cond_codes_cover_jcc() {
        let flags = Flags {
            cf: true,
            pf: false,
            zf: true,
            sf: false,
            of: true,
        };
        assert!(cond_taken(2, flags));
        assert!(cond_taken(4, flags));
        assert!(cond_taken(6, flags));
        assert!(!cond_taken(7, flags));
    }

    #[test]
    fn narrow_shifts_do_not_panic_when_count_exceeds_width() {
        let old = Flags {
            cf: true,
            ..Flags::default()
        };
        let (value, flags) = shift_left(0x81, 9, 8, old);
        assert_eq!(value, 0);
        assert!(!flags.cf);
        let (value, flags) = shift_right(0x81, 9, 8, old);
        assert_eq!(value, 0);
        assert!(!flags.cf);
        let (value, flags) = shift_arith(0x80, 9, 8, old);
        assert_eq!(value, 0xff);
        assert!(flags.cf);
        let (value, flags) = rotate_left(0x81, 9, 8, old);
        assert_eq!(value, 0x03);
        assert!(flags.cf);
        assert!(!flags.of);
        let (value, _) = rotate_right(0x81, 9, 8, old);
        assert_eq!(value, 0xc0);
    }

    fn cpu_op(op: &str, a: u64, b: u64, carry: bool) -> (u64, u64) {
        let mut result = a;
        let mut raw = 0u64;
        unsafe {
            match (op, carry) {
                ("add", _) => core::arch::asm!(
                    "add {result}, {b}",
                    "pushfq",
                    "pop {raw}",
                    result = inout(reg) result,
                    b = in(reg) b,
                    raw = lateout(reg) raw,
                ),
                ("sub", _) => core::arch::asm!(
                    "sub {result}, {b}",
                    "pushfq",
                    "pop {raw}",
                    result = inout(reg) result,
                    b = in(reg) b,
                    raw = lateout(reg) raw,
                ),
                ("adc", true) => core::arch::asm!(
                    "stc",
                    "adc {result}, {b}",
                    "pushfq",
                    "pop {raw}",
                    result = inout(reg) result,
                    b = in(reg) b,
                    raw = lateout(reg) raw,
                ),
                ("adc", false) => core::arch::asm!(
                    "clc",
                    "adc {result}, {b}",
                    "pushfq",
                    "pop {raw}",
                    result = inout(reg) result,
                    b = in(reg) b,
                    raw = lateout(reg) raw,
                ),
                ("sbb", true) => core::arch::asm!(
                    "stc",
                    "sbb {result}, {b}",
                    "pushfq",
                    "pop {raw}",
                    result = inout(reg) result,
                    b = in(reg) b,
                    raw = lateout(reg) raw,
                ),
                ("sbb", false) => core::arch::asm!(
                    "clc",
                    "sbb {result}, {b}",
                    "pushfq",
                    "pop {raw}",
                    result = inout(reg) result,
                    b = in(reg) b,
                    raw = lateout(reg) raw,
                ),
                ("add32", _) => core::arch::asm!(
                    "add {result:e}, {b:e}",
                    "pushfq",
                    "pop {raw}",
                    result = inout(reg) result,
                    b = in(reg) b,
                    raw = lateout(reg) raw,
                ),
                _ => panic!("op"),
            }
        }
        (result, raw)
    }

    fn cpu_byte(op: &str, a: u8, b: u8, carry: bool) -> (u8, u64, bool) {
        let mut rax = u64::from(a);
        let mut raw = 0u64;
        let operand = u64::from(b);
        unsafe {
            match (op, carry) {
                ("add", _) => core::arch::asm!(
                    "add al, {b:l}",
                    "lahf",
                    "pushfq",
                    "pop {raw}",
                    inout("rax") rax,
                    b = in(reg) operand,
                    raw = lateout(reg) raw,
                ),
                ("sub", _) => core::arch::asm!(
                    "sub al, {b:l}",
                    "lahf",
                    "pushfq",
                    "pop {raw}",
                    inout("rax") rax,
                    b = in(reg) operand,
                    raw = lateout(reg) raw,
                ),
                ("adc", true) => core::arch::asm!(
                    "stc",
                    "adc al, {b:l}",
                    "lahf",
                    "pushfq",
                    "pop {raw}",
                    inout("rax") rax,
                    b = in(reg) operand,
                    raw = lateout(reg) raw,
                ),
                ("adc", false) => core::arch::asm!(
                    "clc",
                    "adc al, {b:l}",
                    "lahf",
                    "pushfq",
                    "pop {raw}",
                    inout("rax") rax,
                    b = in(reg) operand,
                    raw = lateout(reg) raw,
                ),
                ("sbb", true) => core::arch::asm!(
                    "stc",
                    "sbb al, {b:l}",
                    "lahf",
                    "pushfq",
                    "pop {raw}",
                    inout("rax") rax,
                    b = in(reg) operand,
                    raw = lateout(reg) raw,
                ),
                ("sbb", false) => core::arch::asm!(
                    "clc",
                    "sbb al, {b:l}",
                    "lahf",
                    "pushfq",
                    "pop {raw}",
                    inout("rax") rax,
                    b = in(reg) operand,
                    raw = lateout(reg) raw,
                ),
                ("inc", _) => core::arch::asm!(
                    "stc",
                    "inc al",
                    "lahf",
                    "pushfq",
                    "pop {raw}",
                    inout("rax") rax,
                    raw = lateout(reg) raw,
                ),
                ("dec", _) => core::arch::asm!(
                    "stc",
                    "dec al",
                    "lahf",
                    "pushfq",
                    "pop {raw}",
                    inout("rax") rax,
                    raw = lateout(reg) raw,
                ),
                ("neg", _) => core::arch::asm!(
                    "neg al",
                    "lahf",
                    "pushfq",
                    "pop {raw}",
                    inout("rax") rax,
                    raw = lateout(reg) raw,
                ),
                _ => panic!("byte op"),
            }
        }
        let ah = ((rax >> 8) & 0xff) as u8;
        ((rax & 0xff) as u8, raw, ah & 0x10 != 0)
    }

    #[test]
    fn adc_sbb_and_narrow_add_match_cpu() {
        let wide = [
            0u64,
            1,
            2,
            0x0f,
            0x10,
            0x7f,
            0x80,
            0xff,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            u64::MAX,
        ];
        for a in wide {
            for b in wide {
                for carry in [false, true] {
                    let (got, raw) = cpu_op("add", a, b, carry);
                    let (expect, flags) = add(a, b, 64);
                    assert_eq!(got, expect, "add {a:#x} {b:#x}");
                    assert_flags("add", flags, raw);
                    let (got, raw) = cpu_op("sub", a, b, carry);
                    let (expect, flags) = sub(a, b, 64);
                    assert_eq!(got, expect);
                    assert_flags("sub", flags, raw);
                    let (got, raw) = cpu_op("adc", a, b, carry);
                    let (expect, flags) = adc(a, b, 64, carry);
                    assert_eq!(got, expect, "adc {a:#x} {b:#x} {carry}");
                    assert_flags("adc", flags, raw);
                    let (got, raw) = cpu_op("sbb", a, b, carry);
                    let (expect, flags) = sbb(a, b, 64, carry);
                    assert_eq!(got, expect, "sbb {a:#x} {b:#x} {carry}");
                    assert_flags("sbb", flags, raw);
                    let (got, raw) = cpu_op("add32", a, b, false);
                    let (expect, flags) = add(a, b, 32);
                    assert_eq!(got & 0xffff_ffff, expect, "add32 {a:#x} {b:#x}");
                    assert_flags("add32", flags, raw);
                }
            }
        }
        let bytes = [0u8, 1, 0x0f, 0x10, 0x7f, 0x80, 0xff];
        for a in bytes {
            for b in bytes {
                for carry in [false, true] {
                    let (got, raw, af) = cpu_byte("add", a, b, carry);
                    let (expect, flags) = add(u64::from(a), u64::from(b), 8);
                    assert_eq!(u64::from(got), expect);
                    assert_flags("add8", flags, raw);
                    assert_eq!(af, aux_carry(u64::from(a), u64::from(b), expect), "add af");
                    let (got, raw, af) = cpu_byte("sub", a, b, carry);
                    let (expect, flags) = sub(u64::from(a), u64::from(b), 8);
                    assert_eq!(u64::from(got), expect);
                    assert_flags("sub8", flags, raw);
                    assert_eq!(af, aux_carry(u64::from(a), u64::from(b), expect), "sub af");
                    let (got, raw, af) = cpu_byte("adc", a, b, carry);
                    let (expect, flags) = adc(u64::from(a), u64::from(b), 8, carry);
                    assert_eq!(u64::from(got), expect, "adc8 {a:#x} {b:#x} {carry}");
                    assert_flags("adc8", flags, raw);
                    assert_eq!(
                        af,
                        aux_carry(u64::from(a), u64::from(b), expect),
                        "adc af {a:#x} {b:#x} {carry}"
                    );
                    let (got, raw, af) = cpu_byte("sbb", a, b, carry);
                    let (expect, flags) = sbb(u64::from(a), u64::from(b), 8, carry);
                    assert_eq!(u64::from(got), expect, "sbb8 {a:#x} {b:#x} {carry}");
                    assert_flags("sbb8", flags, raw);
                    assert_eq!(af, aux_carry(u64::from(a), u64::from(b), expect), "sbb af");
                }
                let old = Flags {
                    cf: true,
                    ..Flags::default()
                };
                let (got, raw, af) = cpu_byte("inc", a, 0, false);
                let (expect, flags) = inc(u64::from(a), 8, old);
                assert_eq!(u64::from(got), expect);
                assert_flags("inc8", flags, raw);
                assert!(Flags::unpack(raw).cf, "inc keeps cf");
                assert_eq!(af, aux_carry(u64::from(a), 1, expect));
                let (got, raw, af) = cpu_byte("dec", a, 0, false);
                let (expect, flags) = dec(u64::from(a), 8, old);
                assert_eq!(u64::from(got), expect);
                assert_flags("dec8", flags, raw);
                assert!(Flags::unpack(raw).cf, "dec keeps cf");
                assert_eq!(af, aux_carry(u64::from(a), 1, expect));
                let (got, raw, af) = cpu_byte("neg", a, 0, false);
                let (expect, flags) = neg(u64::from(a), 8);
                assert_eq!(u64::from(got), expect);
                assert_flags("neg8", flags, raw);
                assert_eq!(af, aux_carry(0, u64::from(a), expect));
            }
        }
    }
}
