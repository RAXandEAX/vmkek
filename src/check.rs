//! C5 machine check of the integer IR core against the S1 catalog.
//!
//! Interpreting an S1 identity in [`crate::ir::exec_integer_block`] — the straight-line
//! path [`crate::ir::exec_func`] uses for an integer block — matches the direct ALU
//! operation on every input the checker quantifies. Flag-preserving identities also
//! match those flags. x87 and AVX stay outside this check.
//!
//! Concrete samples in `cargo test` exercise the same predicate. They are not a
//! machine proof and do not turn the Math channel green. The channel follows the
//! Kani artifact named by [`claims`].

#[cfg(any(test, kani))]
use crate::error::{msg, Result};
#[cfg(any(test, kani))]
use crate::flags::{self, Flags};
#[cfg(any(test, kani))]
use crate::ir::{self, MemIo, Op, V_LIMIT};

#[cfg(kani)]
use crate::identities as s1;
#[cfg(all(test, not(kani)))]
use crate::obf::identities as s1;

/// Green only when the committed Kani artifact records a successful run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelColor {
    Green,
    Red,
}

/// One Math row for the integer core. Not a [`crate::proof::PassClaim`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreClaim {
    pub id: &'static str,
    pub channel: &'static str,
    pub machine: &'static str,
    pub color: ChannelColor,
    /// Path from the crate root of the Kani artifact this row cites.
    pub anchor: &'static str,
}

/// Crate-root path of the Kani artifact for the integer core.
pub const ANCHOR: &str = "docs/c5-kani.md";

const MATH_COLOR: ChannelColor = ChannelColor::Green;

/// Math channel for the integer core.
#[must_use]
pub fn claims() -> &'static [CoreClaim] {
    const CLAIMS: &[CoreClaim] = &[CoreClaim {
        id: "integer-core-s1",
        channel: "Math",
        machine: "M-IR",
        color: MATH_COLOR,
        anchor: ANCHOR,
    }];
    CLAIMS
}

#[cfg(any(test, kani))]
enum Kind {
    Add,
    Sub,
    Xor,
    And,
    Or,
    Mov,
}

#[cfg(any(test, kani))]
struct BlankMem;

#[cfg(any(test, kani))]
impl MemIo for BlankMem {
    fn read(&mut self, _addr: u64, _len: usize) -> Result<Vec<u8>> {
        Err(msg("integer core check does not read memory"))
    }

    fn write(&mut self, _addr: u64, _data: &[u8]) -> Result<()> {
        Err(msg("integer core check does not write memory"))
    }
}

#[cfg(any(test, kani))]
fn kind_of(name: &str) -> Option<Kind> {
    Some(match name {
        "add_xor_shl" | "add_or_and" | "add_xor_double" | "add_split_k" => Kind::Add,
        "xor_or_and" | "xor_demorgan" => Kind::Xor,
        "sub_neg" | "sub_not_plus" => Kind::Sub,
        "and_demorgan" => Kind::And,
        "or_demorgan" => Kind::Or,
        "mov_xor" | "mov_add" | "mov_sub" => Kind::Mov,
        _ => return None,
    })
}

#[cfg(any(test, kani))]
fn direct(kind: Kind, left: u64, right: u64, flags: Flags) -> (u64, Flags) {
    match kind {
        Kind::Add => flags::add(left, right, 64),
        Kind::Sub => flags::sub(left, right, 64),
        Kind::Xor => flags::logic_xor(left, right, 64),
        Kind::And => flags::logic_and(left, right, 64),
        Kind::Or => flags::logic_or(left, right, 64),
        Kind::Mov => (left, flags),
    }
}

#[cfg(any(test, kani))]
fn interpret(
    ops: &[Op],
    dst: u16,
    src: u16,
    left: u64,
    right: u64,
    mut flags: Flags,
) -> Result<(u64, Flags)> {
    let mut regs = [0u64; V_LIMIT];
    regs[usize::from(dst)] = left;
    if src != dst {
        regs[usize::from(src)] = right;
    }
    ir::exec_integer_block(ops, &mut regs, &mut flags, &mut BlankMem, 0)?;
    Ok((regs[usize::from(dst)], flags))
}

#[cfg(any(test, kani))]
fn keeps_flags(name: &str) -> bool {
    s1::catalog().iter().any(|identity| {
        identity.name == name && identity.precondition == s1::FlagPrecondition::Preserved
    })
}

#[cfg(any(test, kani))]
fn identity_holds(
    name: &str,
    left: u64,
    right: u64,
    flags: Flags,
    key: i32,
    mask: u64,
    alias: bool,
) -> bool {
    let Some(kind) = kind_of(name) else {
        return false;
    };
    let src = if alias { 0 } else { 1 };
    let right = if alias { left } else { right };
    let Some(ops) = s1::sequence(name, 0, src, left, key, mask) else {
        return false;
    };
    let Ok((value, got)) = interpret(&ops, 0, src, left, right, flags) else {
        return false;
    };
    let (expect, expect_flags) = direct(kind, left, right, flags);
    value == expect && (!keeps_flags(name) || got == expect_flags)
}

#[cfg(kani)]
fn any_flags() -> Flags {
    Flags {
        cf: kani::any(),
        pf: kani::any(),
        zf: kani::any(),
        sf: kani::any(),
        of: kani::any(),
    }
}

/// `ops` is one S1 builder. `keep` is that identity's flag precondition.
#[cfg(kani)]
fn prove(ops: &[Op], kind: Kind, left: u64, right: u64, flags: Flags, keep: bool, alias: bool) {
    let src = if alias { 0 } else { 1 };
    let right = if alias { left } else { right };
    let Ok((value, got)) = interpret(ops, 0, src, left, right, flags) else {
        assert!(false);
        return;
    };
    let (expect, expect_flags) = direct(kind, left, right, flags);
    assert_eq!(value, expect);
    if keep {
        assert_eq!(got, expect_flags);
    }
}

#[cfg(kani)]
mod proofs {
    use super::{any_flags, prove, Kind};

    macro_rules! rr {
        ($fn_name:ident, $kind:expr, $keep:expr, $build:ident) => {
            #[kani::proof]
            #[kani::unwind(16)]
            fn $fn_name() {
                let alias: bool = kani::any();
                let src = if alias { 0 } else { 1 };
                let ops = crate::identities::$build(0, src);
                prove(
                    &ops,
                    $kind,
                    kani::any(),
                    kani::any(),
                    any_flags(),
                    $keep,
                    alias,
                );
            }
        };
    }

    macro_rules! keyed {
        ($fn_name:ident, $kind:expr, $keep:expr, $build:ident) => {
            #[kani::proof]
            #[kani::unwind(16)]
            fn $fn_name() {
                let alias: bool = kani::any();
                let src = if alias { 0 } else { 1 };
                let ops = crate::identities::$build(0, src, kani::any());
                prove(
                    &ops,
                    $kind,
                    kani::any(),
                    kani::any(),
                    any_flags(),
                    $keep,
                    alias,
                );
            }
        };
    }

    macro_rules! mov {
        ($fn_name:ident, $build:ident) => {
            #[kani::proof]
            #[kani::unwind(16)]
            fn $fn_name() {
                let imm: u64 = kani::any();
                let ops = crate::identities::$build(0, imm, kani::any());
                prove(&ops, Kind::Mov, imm, 0, any_flags(), true, false);
            }
        };
    }

    rr!(s1_add_xor_shl, Kind::Add, true, add_xor_shl_ops);
    rr!(s1_add_or_and, Kind::Add, true, add_or_and_ops);
    rr!(s1_add_xor_double, Kind::Add, true, add_xor_double_ops);
    keyed!(s1_add_split_k, Kind::Add, false, add_split_k_ops);
    rr!(s1_xor_or_and, Kind::Xor, true, xor_or_and_ops);
    rr!(s1_xor_demorgan, Kind::Xor, true, xor_demorgan_ops);
    rr!(s1_sub_neg, Kind::Sub, false, sub_neg_ops);
    rr!(s1_sub_not_plus, Kind::Sub, false, sub_not_plus_ops);
    rr!(s1_and_demorgan, Kind::And, false, and_demorgan_ops);
    rr!(s1_or_demorgan, Kind::Or, false, or_demorgan_ops);
    mov!(s1_mov_xor, mov_xor_ops);
    mov!(s1_mov_add, mov_add_ops);
    mov!(s1_mov_sub, mov_sub_ops);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn math_channel_cites_the_kani_artifact() {
        let row = claims()
            .iter()
            .find(|row| row.id == "integer-core-s1")
            .expect("math row");
        assert_eq!(row.channel, "Math");
        assert_eq!(row.machine, "M-IR");
        assert_eq!(row.anchor, ANCHOR);
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(row.anchor);
        let text = std::fs::read_to_string(&path).expect("anchor");
        assert!(text.contains("cargo kani"), "{}", row.anchor);
        assert!(text.contains("src/check.rs"));
        assert!(text.contains("x87"));
        assert!(text.contains("AVX"));
        assert!(!text.to_lowercase().contains("proptest"));
        let red = text.contains("Канал Math: красный");
        let green = text.contains("Канал Math: зелёный");
        assert_ne!(red, green, "the artifact must name exactly one Math color");
        if green {
            assert!(text.contains("VERIFICATION:- SUCCESSFUL"));
            assert_eq!(row.color, ChannelColor::Green);
        } else {
            assert_eq!(row.color, ChannelColor::Red);
            assert!(text.contains("не исполн"), "{text}");
        }
    }

    #[test]
    fn obfuscation_passes_keep_an_empty_channel_string() {
        let mba = crate::proof::registry()
            .into_iter()
            .find(|item| item.pass == "mba")
            .expect("mba");
        assert_eq!(mba.channel, "");
        assert_eq!(claims()[0].channel, "Math");
        assert_ne!(claims()[0].anchor, mba.proof_anchor.unwrap_or(""));
    }

    #[test]
    fn every_s1_identity_is_in_the_checker() {
        for identity in s1::catalog() {
            assert!(kind_of(identity.name).is_some(), "{}", identity.name);
            assert!(s1::sequence(identity.name, 0, 1, 0x11, 3, 5).is_some());
        }
        assert!(kind_of("not-an-identity").is_none());
    }

    #[test]
    fn samples_match_the_direct_operation() {
        let flags = Flags {
            cf: true,
            pf: false,
            zf: true,
            sf: false,
            of: true,
        };
        let values = [0u64, 1, 2, 0xff, 0x8000_0000_0000_0000, u64::MAX];
        for identity in s1::catalog() {
            for &left in &values {
                for &right in &values {
                    assert_sample(identity.name, left, right, flags);
                }
            }
        }
    }

    fn assert_sample(name: &str, left: u64, right: u64, flags: Flags) {
        for alias in [false, true] {
            for key in [0, 1, -1, 3] {
                for mask in [0u64, 1, 5, u64::MAX] {
                    assert!(
                        identity_holds(name, left, right, flags, key, mask, alias),
                        "{name} {left:#x} {right:#x} alias={alias} key={key} mask={mask:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn sequences_match_catalog_expand() {
        for identity in s1::catalog() {
            for seed in [1u64, 7, 99] {
                for alias in [false, true] {
                    assert_expand(identity, seed, alias);
                }
            }
        }
    }

    fn assert_expand(identity: &s1::Identity, seed: u64, alias: bool) {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        let imm = 0x0123_4567_89ab_cdef;
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let op = sample_op(identity.name, imm, alias);
        let expanded = (identity.expand)(op, &mut rng);
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (key, mask) = drawn(identity.name, &mut rng);
        let src = if alias { 0 } else { 1 };
        let seq = s1::sequence(identity.name, 0, src, imm, key, mask).expect(identity.name);
        assert_eq!(expanded, seq, "{} seed {seed}", identity.name);
    }

    fn sample_op(name: &str, imm: u64, alias: bool) -> Op {
        let src = if alias { 0 } else { 1 };
        match name {
            "add_xor_shl" | "add_or_and" | "add_xor_double" | "add_split_k" => Op::AddRr(0, src),
            "sub_neg" | "sub_not_plus" => Op::SubRr(0, src),
            "xor_or_and" | "xor_demorgan" => Op::XorRr(0, src),
            "and_demorgan" => Op::AndRr(0, src),
            "or_demorgan" => Op::OrRr(0, src),
            _ => Op::MovRi(0, imm),
        }
    }

    fn drawn(name: &str, rng: &mut rand_chacha::ChaCha20Rng) -> (i32, u64) {
        use rand::Rng;
        match name {
            "add_split_k" => {
                let key = rng.gen::<i32>();
                (if key == 0 { 1 } else { key }, 1)
            }
            "mov_xor" | "mov_add" | "mov_sub" => (1, rng.gen::<u64>() | 1),
            _ => (1, 1),
        }
    }

    #[test]
    fn new_functions_stay_within_fifty_lines() {
        for (name, span) in fn_spans("src/check.rs") {
            assert!(span <= 50, "src/check.rs {name} is {span}");
        }
        for (name, span) in fn_spans("src/obf/identities.rs") {
            if name.ends_with("_ops") || name == "sequence" {
                assert!(span <= 50, "src/obf/identities.rs {name} is {span}");
            }
        }
        for name in [
            "exec_integer_block",
            "exec_x87",
            "exec_sse",
            "finish_x87",
            "finish_sse",
            "regs_fit",
        ] {
            let found = fn_spans("src/ir.rs")
                .into_iter()
                .filter(|(item, _)| item == name)
                .collect::<Vec<_>>();
            assert!(!found.is_empty(), "missing src/ir.rs {name}");
            for (_, span) in found {
                assert!(span <= 50, "src/ir.rs {name} is {span}");
            }
        }
    }

    fn fn_spans(path: &str) -> Vec<(String, usize)> {
        let text =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
                .unwrap_or_else(|err| panic!("read {path}: {err}"));
        let mut spans = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            let Some(name) = fn_name(line) else {
                continue;
            };
            spans.push((name, close_line(&text, idx) + 1));
        }
        spans
    }

    fn fn_name(line: &str) -> Option<String> {
        let mut trimmed = line.trim();
        for prefix in ["pub(crate) ", "pub(super) ", "pub "] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                trimmed = rest;
                break;
            }
        }
        let rest = trimmed.strip_prefix("fn ")?;
        let end = rest.find(['(', '<']).unwrap_or(rest.len());
        let name = &rest[..end];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        Some(name.to_string())
    }

    fn close_line(text: &str, start: usize) -> usize {
        let offset: usize = text.lines().take(start).map(|line| line.len() + 1).sum();
        let mut line = 0usize;
        let mut depth = 0i32;
        let mut started = false;
        for c in text[offset..].chars() {
            match c {
                '\n' => line += 1,
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => {
                    depth -= 1;
                    if started && depth == 0 {
                        return line;
                    }
                }
                _ => {}
            }
        }
        panic!("unclosed function");
    }
}
