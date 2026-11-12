//! Catalog of flag-aware rewrites. Each entry is algebraically the original op.
//! `FlagPrecondition::Dead` is legal only where [`crate::ir::flag_dead_map`] says
//! the original flags are unread. `Preserved` leaves those flags unchanged.

use rand::Rng;
use rand_chacha::ChaCha20Rng;

use crate::ir::{Op, V_TMP0, V_TMP1, V_TMP2};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagPrecondition {
    /// The expansion may leave different flags.
    Dead,
    /// The expansion leaves the same flags as the original op.
    Preserved,
}

pub struct Identity {
    pub name: &'static str,
    pub anchor: &'static str,
    pub precondition: FlagPrecondition,
    pub matches: fn(&Op) -> bool,
    pub expand: fn(Op, &mut ChaCha20Rng) -> Vec<Op>,
}

pub fn catalog() -> &'static [Identity] {
    CATALOG
}

pub fn choose(op: Op, flags_dead: bool, rng: &mut ChaCha20Rng) -> Option<(&'static str, Vec<Op>)> {
    let fits: Vec<&Identity> = catalog()
        .iter()
        .filter(|identity| accepts(identity, &op, flags_dead))
        .collect();
    if fits.is_empty() {
        return None;
    }
    let index = rng.gen_range(0..fits.len());
    let identity = fits[index];
    debug_assert!(!identity.anchor.is_empty());
    Some((identity.name, (identity.expand)(op, rng)))
}

fn accepts(identity: &Identity, op: &Op, flags_dead: bool) -> bool {
    (identity.matches)(op) && (flags_dead || identity.precondition == FlagPrecondition::Preserved)
}

fn is_scratch(reg: u16) -> bool {
    matches!(reg, V_TMP0 | V_TMP1 | V_TMP2)
}

fn free(dst: u16, src: u16) -> bool {
    !is_scratch(dst) && !is_scratch(src)
}

fn match_add(op: &Op) -> bool {
    matches!(*op, Op::AddRr(dst, src) if free(dst, src))
}

fn match_sub(op: &Op) -> bool {
    matches!(*op, Op::SubRr(dst, src) if free(dst, src))
}

fn match_xor(op: &Op) -> bool {
    matches!(*op, Op::XorRr(dst, src) if free(dst, src))
}

fn match_and(op: &Op) -> bool {
    matches!(*op, Op::AndRr(dst, src) if free(dst, src))
}

fn match_or(op: &Op) -> bool {
    matches!(*op, Op::OrRr(dst, src) if free(dst, src))
}

fn match_mov(op: &Op) -> bool {
    matches!(*op, Op::MovRi(dst, _) if !is_scratch(dst))
}

fn nonzero_i32(rng: &mut ChaCha20Rng) -> i32 {
    let key = rng.gen::<i32>();
    if key == 0 {
        1
    } else {
        key
    }
}

// Proof: a + b = (a XOR b) + 2*(a AND b) modulo 2^64.
// That sum's own ADD does not reproduce OF (its operands are not a and b).
// The original operands stay in temps, and a trailing ADD of those temps writes
// ADD's EFLAGS into a scratch register. Nothing after it writes flags.
fn add_xor_shl(op: Op, _rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::AddRr(dst, src) = op else {
        return vec![op];
    };
    add_xor_shl_ops(dst, src).to_vec()
}

pub(crate) fn add_xor_shl_ops(dst: u16, src: u16) -> [Op; 10] {
    [
        Op::MovRr(V_TMP0, dst),
        Op::MovRr(V_TMP1, src),
        Op::MovRr(V_TMP2, V_TMP0),
        Op::XorRr(V_TMP2, V_TMP1),
        Op::MovRr(dst, V_TMP0),
        Op::AndRr(dst, V_TMP1),
        Op::Shl(dst, 1),
        Op::AddRr(dst, V_TMP2),
        Op::MovRr(V_TMP2, V_TMP0),
        Op::AddRr(V_TMP2, V_TMP1),
    ]
}

// Proof: a + b = (a OR b) + (a AND b). Each bit set in both operands is counted twice.
// The trailing ADD of the saved operands restores CF/OF/SF/ZF/PF.
fn add_or_and(op: Op, _rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::AddRr(dst, src) = op else {
        return vec![op];
    };
    add_or_and_ops(dst, src).to_vec()
}

pub(crate) fn add_or_and_ops(dst: u16, src: u16) -> [Op; 9] {
    [
        Op::MovRr(V_TMP0, dst),
        Op::MovRr(V_TMP1, src),
        Op::MovRr(V_TMP2, V_TMP0),
        Op::OrRr(V_TMP2, V_TMP1),
        Op::MovRr(dst, V_TMP0),
        Op::AndRr(dst, V_TMP1),
        Op::AddRr(dst, V_TMP2),
        Op::MovRr(V_TMP2, V_TMP0),
        Op::AddRr(V_TMP2, V_TMP1),
    ]
}

// Proof: same sum as `add_xor_shl`, but 2*(a AND b) is (a AND b) + (a AND b).
// The trailing ADD of the saved operands restores the flags.
fn add_xor_double(op: Op, _rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::AddRr(dst, src) = op else {
        return vec![op];
    };
    add_xor_double_ops(dst, src).to_vec()
}

pub(crate) fn add_xor_double_ops(dst: u16, src: u16) -> [Op; 10] {
    [
        Op::MovRr(V_TMP0, dst),
        Op::MovRr(V_TMP1, src),
        Op::MovRr(V_TMP2, V_TMP0),
        Op::XorRr(V_TMP2, V_TMP1),
        Op::MovRr(dst, V_TMP0),
        Op::AndRr(dst, V_TMP1),
        Op::AddRr(dst, dst),
        Op::AddRr(dst, V_TMP2),
        Op::MovRr(V_TMP2, V_TMP0),
        Op::AddRr(V_TMP2, V_TMP1),
    ]
}

// Proof: (a + k) + (b - k) = a + b for every k. The final ADD's operands are not a and b,
// so CF/OF need not match. Allowed only when the original flags are dead.
fn add_split_k(op: Op, rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::AddRr(dst, src) = op else {
        return vec![op];
    };
    add_split_k_ops(dst, src, nonzero_i32(rng)).to_vec()
}

pub(crate) fn add_split_k_ops(dst: u16, src: u16, key: i32) -> [Op; 4] {
    [
        Op::MovRr(V_TMP0, src),
        Op::SubRi(V_TMP0, key),
        Op::AddRi(dst, key),
        Op::AddRr(dst, V_TMP0),
    ]
}

// Proof: (a OR b) XOR (a AND b) = a XOR b. The last flag writer is XOR of that value,
// and XOR/AND/OR share CF=0, OF=0 and logic flags of the result.
fn xor_or_and(op: Op, _rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::XorRr(dst, src) = op else {
        return vec![op];
    };
    xor_or_and_ops(dst, src).to_vec()
}

pub(crate) fn xor_or_and_ops(dst: u16, src: u16) -> [Op; 6] {
    [
        Op::MovRr(V_TMP0, dst),
        Op::OrRr(V_TMP0, src),
        Op::MovRr(V_TMP1, dst),
        Op::AndRr(V_TMP1, src),
        Op::XorRr(V_TMP0, V_TMP1),
        Op::MovRr(dst, V_TMP0),
    ]
}

// Proof: (a OR b) AND NOT (a AND b) = a XOR b. The last flag writer is AND of that value.
fn xor_demorgan(op: Op, _rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::XorRr(dst, src) = op else {
        return vec![op];
    };
    xor_demorgan_ops(dst, src).to_vec()
}

pub(crate) fn xor_demorgan_ops(dst: u16, src: u16) -> [Op; 7] {
    [
        Op::MovRr(V_TMP0, dst),
        Op::OrRr(V_TMP0, src),
        Op::MovRr(V_TMP1, dst),
        Op::AndRr(V_TMP1, src),
        Op::Not(V_TMP1),
        Op::AndRr(V_TMP0, V_TMP1),
        Op::MovRr(dst, V_TMP0),
    ]
}

// Proof: a + (-b) = a - b in two's complement. NEG/ADD flags are not SUB flags.
fn sub_neg(op: Op, _rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::SubRr(dst, src) = op else {
        return vec![op];
    };
    sub_neg_ops(dst, src).to_vec()
}

pub(crate) fn sub_neg_ops(dst: u16, src: u16) -> [Op; 3] {
    [
        Op::MovRr(V_TMP0, src),
        Op::Neg(V_TMP0),
        Op::AddRr(dst, V_TMP0),
    ]
}

// Proof: a + ~b + 1 = a - b. The final ADD does not reproduce SUB flags.
fn sub_not_plus(op: Op, _rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::SubRr(dst, src) = op else {
        return vec![op];
    };
    sub_not_plus_ops(dst, src).to_vec()
}

pub(crate) fn sub_not_plus_ops(dst: u16, src: u16) -> [Op; 4] {
    [
        Op::MovRr(V_TMP0, src),
        Op::Not(V_TMP0),
        Op::AddRi(V_TMP0, 1),
        Op::AddRr(dst, V_TMP0),
    ]
}

// Proof: ~(~a OR ~b) = a AND b. NOT does not write flags, so the leftover flags are not AND's.
fn and_demorgan(op: Op, _rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::AndRr(dst, src) = op else {
        return vec![op];
    };
    and_demorgan_ops(dst, src).to_vec()
}

pub(crate) fn and_demorgan_ops(dst: u16, src: u16) -> [Op; 7] {
    [
        Op::MovRr(V_TMP0, dst),
        Op::Not(V_TMP0),
        Op::MovRr(V_TMP1, src),
        Op::Not(V_TMP1),
        Op::OrRr(V_TMP0, V_TMP1),
        Op::Not(V_TMP0),
        Op::MovRr(dst, V_TMP0),
    ]
}

// Proof: ~(~a AND ~b) = a OR b. The flags left behind belong to the inner AND, not to OR.
fn or_demorgan(op: Op, _rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::OrRr(dst, src) = op else {
        return vec![op];
    };
    or_demorgan_ops(dst, src).to_vec()
}

pub(crate) fn or_demorgan_ops(dst: u16, src: u16) -> [Op; 7] {
    [
        Op::MovRr(V_TMP0, dst),
        Op::Not(V_TMP0),
        Op::MovRr(V_TMP1, src),
        Op::Not(V_TMP1),
        Op::AndRr(V_TMP0, V_TMP1),
        Op::Not(V_TMP0),
        Op::MovRr(dst, V_TMP0),
    ]
}

// Proof: (imm XOR k) XOR k = imm. MOV does not write flags, so they are saved and restored.
fn mov_xor(op: Op, rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::MovRi(dst, imm) = op else {
        return vec![op];
    };
    mov_xor_ops(dst, imm, rng.gen::<u64>() | 1).to_vec()
}

pub(crate) fn mov_xor_ops(dst: u16, imm: u64, mask: u64) -> [Op; 6] {
    [
        Op::StFlags(V_TMP2),
        Op::MovRi(V_TMP0, imm ^ mask),
        Op::MovRr(dst, V_TMP0),
        Op::MovRi(V_TMP1, mask),
        Op::XorRr(dst, V_TMP1),
        Op::LdFlags(V_TMP2),
    ]
}

// Proof: (imm - k) + k = imm in wrapping arithmetic. Flags are restored because MOV leaves them.
fn mov_add(op: Op, rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::MovRi(dst, imm) = op else {
        return vec![op];
    };
    mov_add_ops(dst, imm, rng.gen::<u64>() | 1).to_vec()
}

pub(crate) fn mov_add_ops(dst: u16, imm: u64, mask: u64) -> [Op; 6] {
    [
        Op::StFlags(V_TMP2),
        Op::MovRi(V_TMP0, imm.wrapping_sub(mask)),
        Op::MovRr(dst, V_TMP0),
        Op::MovRi(V_TMP1, mask),
        Op::AddRr(dst, V_TMP1),
        Op::LdFlags(V_TMP2),
    ]
}

// Proof: (imm + k) - k = imm in wrapping arithmetic. Flags are restored.
fn mov_sub(op: Op, rng: &mut ChaCha20Rng) -> Vec<Op> {
    let Op::MovRi(dst, imm) = op else {
        return vec![op];
    };
    mov_sub_ops(dst, imm, rng.gen::<u64>() | 1).to_vec()
}

pub(crate) fn mov_sub_ops(dst: u16, imm: u64, mask: u64) -> [Op; 6] {
    [
        Op::StFlags(V_TMP2),
        Op::MovRi(V_TMP0, imm.wrapping_add(mask)),
        Op::MovRr(dst, V_TMP0),
        Op::MovRi(V_TMP1, mask),
        Op::SubRr(dst, V_TMP1),
        Op::LdFlags(V_TMP2),
    ]
}

static CATALOG: &[Identity] = &[
    Identity {
        name: "add_xor_shl",
        anchor: "a+b=(a^b)+2*(a&b)",
        precondition: FlagPrecondition::Preserved,
        matches: match_add,
        expand: add_xor_shl,
    },
    Identity {
        name: "add_or_and",
        anchor: "a+b=(a|b)+(a&b)",
        precondition: FlagPrecondition::Preserved,
        matches: match_add,
        expand: add_or_and,
    },
    Identity {
        name: "add_xor_double",
        anchor: "a+b=(a^b)+((a&b)+(a&b))",
        precondition: FlagPrecondition::Preserved,
        matches: match_add,
        expand: add_xor_double,
    },
    Identity {
        name: "add_split_k",
        anchor: "a+b=(a+k)+(b-k)",
        precondition: FlagPrecondition::Dead,
        matches: match_add,
        expand: add_split_k,
    },
    Identity {
        name: "xor_or_and",
        anchor: "a^b=(a|b)^(a&b)",
        precondition: FlagPrecondition::Preserved,
        matches: match_xor,
        expand: xor_or_and,
    },
    Identity {
        name: "xor_demorgan",
        anchor: "a^b=(a|b)&~(a&b)",
        precondition: FlagPrecondition::Preserved,
        matches: match_xor,
        expand: xor_demorgan,
    },
    Identity {
        name: "sub_neg",
        anchor: "a-b=a+(-b)",
        precondition: FlagPrecondition::Dead,
        matches: match_sub,
        expand: sub_neg,
    },
    Identity {
        name: "sub_not_plus",
        anchor: "a-b=a+~b+1",
        precondition: FlagPrecondition::Dead,
        matches: match_sub,
        expand: sub_not_plus,
    },
    Identity {
        name: "and_demorgan",
        anchor: "a&b=~(~a|~b)",
        precondition: FlagPrecondition::Dead,
        matches: match_and,
        expand: and_demorgan,
    },
    Identity {
        name: "or_demorgan",
        anchor: "a|b=~(~a&~b)",
        precondition: FlagPrecondition::Dead,
        matches: match_or,
        expand: or_demorgan,
    },
    Identity {
        name: "mov_xor",
        anchor: "imm=(imm^k)^k",
        precondition: FlagPrecondition::Preserved,
        matches: match_mov,
        expand: mov_xor,
    },
    Identity {
        name: "mov_add",
        anchor: "imm=(imm-k)+k",
        precondition: FlagPrecondition::Preserved,
        matches: match_mov,
        expand: mov_add,
    },
    Identity {
        name: "mov_sub",
        anchor: "imm=(imm+k)-k",
        precondition: FlagPrecondition::Preserved,
        matches: match_mov,
        expand: mov_sub,
    },
];

/// Ops the C5 checker proves. Each catalog `expand` calls the same builder.
#[cfg(any(test, kani))]
pub(crate) fn sequence(
    name: &str,
    dst: u16,
    src: u16,
    imm: u64,
    key: i32,
    mask: u64,
) -> Option<Vec<Op>> {
    Some(match name {
        "add_xor_shl" => add_xor_shl_ops(dst, src).to_vec(),
        "add_or_and" => add_or_and_ops(dst, src).to_vec(),
        "add_xor_double" => add_xor_double_ops(dst, src).to_vec(),
        "add_split_k" => add_split_k_ops(dst, src, key).to_vec(),
        "xor_or_and" => xor_or_and_ops(dst, src).to_vec(),
        "xor_demorgan" => xor_demorgan_ops(dst, src).to_vec(),
        "sub_neg" => sub_neg_ops(dst, src).to_vec(),
        "sub_not_plus" => sub_not_plus_ops(dst, src).to_vec(),
        "and_demorgan" => and_demorgan_ops(dst, src).to_vec(),
        "or_demorgan" => or_demorgan_ops(dst, src).to_vec(),
        "mov_xor" => mov_xor_ops(dst, imm, mask).to_vec(),
        "mov_add" => mov_add_ops(dst, imm, mask).to_vec(),
        "mov_sub" => mov_sub_ops(dst, imm, mask).to_vec(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;
    use crate::flags::Flags;
    use crate::ir::{exec_func, Block, Exit, FuncIr, MapMem, MemIo, Op};

    const WIDTH8: &[u64] = &[
        0, 1, 2, 3, 7, 0x0f, 0x10, 0x7f, 0x80, 0xfe, 0xff, 0x11, 0x5a, 0xa5, 42, 255,
    ];

    const WIDE: &[u64] = &[
        0,
        1,
        2,
        0xff,
        0x100,
        0x7fff,
        0x8000,
        0xffff,
        0x1_0000,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x1_0000_0000,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        0xffff_ffff_ffff_ffff,
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0x5555_5555_5555_5555,
        0xaaaa_aaaa_aaaa_aaaa,
    ];

    fn exec(ops: Vec<Op>, arch: [u64; 16], flags: Flags) -> ([u64; 16], Flags) {
        let func = FuncIr {
            name: "id".into(),
            rva: 0,
            entry: 0,
            blocks: vec![Block {
                ops,
                exit: Exit::Ret,
                opaque: false,
            }],
        };
        let mut arch = arch;
        let mut flags = flags;
        let mut mem = MapMem::default();
        let mut abs = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        exec_func(
            std::slice::from_ref(&func),
            0,
            &mut arch,
            &mut flags,
            &mut mem,
            0,
            &mut abs,
        )
        .expect("exec");
        (arch, flags)
    }

    fn flags_in() -> Flags {
        Flags {
            cf: true,
            pf: true,
            zf: false,
            sf: true,
            of: true,
        }
    }

    fn rr_values(op: Op, a: u64, b: u64) -> (Op, [u64; 16]) {
        let mut arch = [0u64; 16];
        match op {
            Op::AddRr(dst, src)
            | Op::SubRr(dst, src)
            | Op::XorRr(dst, src)
            | Op::AndRr(dst, src)
            | Op::OrRr(dst, src) => {
                arch[dst as usize] = a;
                arch[src as usize] = b;
            }
            _ => panic!("rr op"),
        }
        (op, arch)
    }

    #[test]
    fn every_identity_has_an_anchor_and_the_families_are_populated() {
        let entries = catalog();
        assert!(entries.len() >= 11, "{}", entries.len());
        let mut add = 0;
        let mut mov = 0;
        for identity in entries {
            assert!(!identity.name.is_empty());
            assert!(!identity.anchor.is_empty(), "{}", identity.name);
            if identity.name.starts_with("add_") {
                add += 1;
            }
            if identity.name.starts_with("mov_") {
                mov += 1;
            }
        }
        assert!(add >= 3, "{add}");
        assert!(mov >= 3, "{mov}");
        assert!(entries
            .iter()
            .all(|identity| !(identity.matches)(&Op::AddRr(V_TMP0, 0))));
        assert!(entries
            .iter()
            .all(|identity| !(identity.matches)(&Op::MovRi(V_TMP2, 1))));
    }

    #[test]
    fn preserved_identities_match_the_oracle_and_dead_ones_keep_the_value() {
        for identity in catalog() {
            if (identity.matches)(&Op::MovRi(0, 0)) {
                check_mov(identity);
            } else {
                check_rr(identity);
            }
        }
    }

    fn check_mov(identity: &Identity) {
        let immediates = [
            0u64,
            1,
            2,
            0xff,
            0x100,
            0x5a,
            0x8000_0000_0000_0000,
            0xffff_ffff_ffff_ffff,
            0x0123_4567_89ab_cdef,
        ];
        for (seed, imm) in immediates.into_iter().enumerate() {
            let op = Op::MovRi(0, imm);
            let mut rng = ChaCha20Rng::seed_from_u64(seed as u64 + 9);
            let expanded = (identity.expand)(op, &mut rng);
            let mut arch = [0u64; 16];
            arch[1] = 0x1111_2222_3333_4444;
            let flags = flags_in();
            let (before, flags_before) = exec(vec![op], arch, flags);
            let (after, flags_after) = exec(expanded, arch, flags);
            assert_eq!(after[0], imm, "{}", identity.name);
            assert_eq!(after, before, "{}", identity.name);
            assert_eq!(flags_after, flags_before, "{}", identity.name);
        }
    }

    fn check_rr(identity: &Identity) {
        let sample = [
            Op::AddRr(0, 1),
            Op::SubRr(0, 1),
            Op::XorRr(0, 1),
            Op::AndRr(0, 1),
            Op::OrRr(0, 1),
        ]
        .into_iter()
        .find(|op| (identity.matches)(op))
        .unwrap_or_else(|| panic!("no sample for {}", identity.name));
        let mut saw_flag_difference = false;
        for (seed, (left, right)) in pairs().into_iter().enumerate() {
            saw_flag_difference |= eval_pair(identity, sample, left, right, seed as u64);
        }
        let alias = alias_op(sample);
        let _ = eval_pair(
            identity,
            alias,
            0x8000_0000_0000_0000,
            0x8000_0000_0000_0000,
            99,
        );
        if identity.precondition == FlagPrecondition::Dead {
            assert!(saw_flag_difference, "{}", identity.name);
        }
    }

    fn pairs() -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for left in WIDTH8 {
            for right in WIDTH8 {
                out.push((*left, *right));
            }
        }
        for left in WIDE {
            for right in WIDE {
                out.push((*left, *right));
            }
        }
        out
    }

    fn alias_op(op: Op) -> Op {
        match op {
            Op::AddRr(_, _) => Op::AddRr(0, 0),
            Op::SubRr(_, _) => Op::SubRr(0, 0),
            Op::XorRr(_, _) => Op::XorRr(0, 0),
            Op::AndRr(_, _) => Op::AndRr(0, 0),
            Op::OrRr(_, _) => Op::OrRr(0, 0),
            other => other,
        }
    }

    fn eval_pair(identity: &Identity, op: Op, left: u64, right: u64, seed: u64) -> bool {
        let (op, arch) = rr_values(op, left, right);
        let mut rng = ChaCha20Rng::seed_from_u64(seed.wrapping_mul(0x9e37) ^ left ^ right);
        let expanded = (identity.expand)(op, &mut rng);
        let flags = flags_in();
        let (before, flags_before) = exec(vec![op], arch, flags);
        let (after, flags_after) = exec(expanded, arch, flags);
        assert_eq!(after, before, "{} {left:#x} {right:#x}", identity.name);
        if identity.precondition == FlagPrecondition::Preserved {
            assert_eq!(
                flags_after, flags_before,
                "{} {left:#x} {right:#x}",
                identity.name
            );
            false
        } else {
            flags_after != flags_before
        }
    }
}
