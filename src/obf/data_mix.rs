//! Reversible data mixing. A register is moved into another representation and
//! immediately brought back. The pair is the identity on the architectural state,
//! including flags. Flag spill uses `V_TMP2` so the flatten channel `V_FLAGS` stays intact.

use rand::Rng;
use rand_chacha::ChaCha20Rng;

use crate::ir::{Block, FuncIr, Op, RAX, V_TMP0, V_TMP1, V_TMP2};

pub fn apply(func: &FuncIr, rng: &mut ChaCha20Rng) -> FuncIr {
    let entry = func.entry as usize;
    let blocks = func
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| {
            if index != entry {
                return block.clone();
            }
            let mut ops = pair(RAX, rng);
            ops.extend_from_slice(&block.ops);
            Block {
                ops,
                exit: block.exit,
                opaque: block.opaque,
            }
        })
        .collect();
    FuncIr {
        name: func.name.clone(),
        rva: func.rva,
        blocks,
        entry: func.entry,
    }
}

// Proof: an odd integer is invertible modulo 2^64. x * m * m^{-1} = x.
// Flags are copied out and back, so they are not part of the encoding.
fn mul_pair(reg: u16, modulus: u64) -> Vec<Op> {
    let inverse = odd_inverse(modulus);
    debug_assert_eq!(modulus.wrapping_mul(inverse), 1);
    vec![
        Op::StFlags(V_TMP2),
        Op::MovRi(V_TMP0, modulus),
        Op::MovRr(V_TMP1, reg),
        Op::ImulRr(V_TMP1, V_TMP0),
        Op::MovRr(reg, V_TMP1),
        Op::MovRi(V_TMP0, inverse),
        Op::ImulRr(reg, V_TMP0),
        Op::LdFlags(V_TMP2),
    ]
}

// Proof: x XOR k XOR k = x. Flags are restored from the copy taken before the pair.
fn xor_pair(reg: u16, key: u64) -> Vec<Op> {
    vec![
        Op::StFlags(V_TMP2),
        Op::MovRi(V_TMP0, key),
        Op::XorRr(reg, V_TMP0),
        Op::XorRr(reg, V_TMP0),
        Op::LdFlags(V_TMP2),
    ]
}

fn pair(reg: u16, rng: &mut ChaCha20Rng) -> Vec<Op> {
    let key = rng.gen::<u64>() | 1;
    if rng.gen_bool(0.5) {
        mul_pair(reg, key)
    } else {
        xor_pair(reg, key)
    }
}

pub(crate) fn odd_inverse(modulus: u64) -> u64 {
    let mut inverse = 1u64;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(modulus.wrapping_mul(inverse)));
    }
    inverse
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;
    use crate::flags::Flags;
    use crate::ir::{
        exec_func, Block, Exit, FuncIr, MapMem, MemIo, Op, RAX, RBX, RCX, RDX, RSI, RSP,
    };

    fn input_arch(rax: u64) -> [u64; 16] {
        let mut arch = [0u64; 16];
        arch[RAX as usize] = rax;
        arch[RCX as usize] = 0x2222;
        arch[RSP as usize] = 0x1000;
        arch
    }

    fn exec_arch(func: &FuncIr, mut arch: [u64; 16], mut flags: Flags) -> ([u64; 16], Flags) {
        let mut mem = MapMem::default();
        let mut abs = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        exec_func(
            std::slice::from_ref(func),
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

    fn exec(func: &FuncIr, rax: u64, flags: Flags) -> ([u64; 16], Flags) {
        exec_arch(func, input_arch(rax), flags)
    }

    fn pair_only(pair: &[Op]) -> FuncIr {
        FuncIr {
            name: "pair".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: pair.to_vec(),
                exit: Exit::Ret,
                opaque: false,
            }],
        }
    }

    /// Pair, then a copy of the restored RAX and flags, then the sample body
    /// that overwrites both. The copy is the only place the inputs survive.
    fn sample_with_probe(pair: &[Op]) -> FuncIr {
        let mut func = sample();
        let tail = func.blocks[0].ops.clone();
        let mut ops = pair.to_vec();
        ops.push(Op::MovRr(RDX, RAX));
        ops.push(Op::StFlags(RSI));
        ops.extend(tail);
        func.blocks[0].ops = ops;
        func
    }

    fn prefix_ops(original: &FuncIr, mixed: &FuncIr) -> Vec<Op> {
        let index = original.entry as usize;
        let orig = &original.blocks[index].ops;
        let now = &mixed.blocks[index].ops;
        assert!(
            now.len() >= orig.len(),
            "data-mix shortened the entry block"
        );
        let split = now.len() - orig.len();
        assert_eq!(&now[split..], orig.as_slice(), "sample body was rewritten");
        assert!(split > 0, "data-mix inserted an empty pair");
        now[..split].to_vec()
    }

    fn flag_grid() -> Vec<Flags> {
        (0..32)
            .map(|bits| Flags {
                cf: bits & 1 != 0,
                pf: bits & 2 != 0,
                zf: bits & 4 != 0,
                sf: bits & 8 != 0,
                of: bits & 16 != 0,
            })
            .collect()
    }

    fn rax_cases(rng: &mut ChaCha20Rng) -> Vec<u64> {
        let mut values = vec![0, 1, 0xff, 0x0100, 0x8000_0000_0000_0000, u64::MAX];
        values.extend((0..8).map(|_| rng.gen::<u64>()));
        values
    }

    fn odd_moduli(rng: &mut ChaCha20Rng) -> Vec<u64> {
        let mut values = vec![1, 3, 0xff, u64::MAX];
        values.extend((0..4).map(|_| rng.gen::<u64>() | 1));
        values
    }

    fn xor_keys(rng: &mut ChaCha20Rng) -> Vec<u64> {
        let mut values = vec![0, 1, 2, 0xff, u64::MAX];
        values.extend((0..4).map(|_| rng.gen::<u64>()));
        values
    }

    fn cases(rng: &mut ChaCha20Rng) -> Vec<(u64, Flags)> {
        let flags = flag_grid();
        rax_cases(rng)
            .into_iter()
            .flat_map(|rax| flags.iter().copied().map(move |flags| (rax, flags)))
            .collect()
    }

    fn check_pair(pair: &[Op], rax: u64, flags: Flags) {
        let saved_rax = rax;
        let saved_flags = flags;
        let input = input_arch(saved_rax);
        let (output, out_flags) = exec_arch(&pair_only(pair), input, saved_flags);
        assert_eq!(
            output[RAX as usize], saved_rax,
            "restored rax {saved_rax:#x}"
        );
        assert_eq!(out_flags, saved_flags, "restored flags {saved_flags:?}");
        assert_eq!(output, input, "other architectural registers");

        let (oracle, _) = exec(&sample(), saved_rax, saved_flags);
        let (probed, _) = exec_arch(&sample_with_probe(pair), input, saved_flags);
        assert_eq!(probed[RAX as usize], oracle[RAX as usize], "sample rax");
        assert_eq!(probed[RBX as usize], oracle[RBX as usize], "sample branch");
        assert_eq!(
            probed[RDX as usize], saved_rax,
            "rax copied before the sample overwrite"
        );
        assert_eq!(
            Flags::unpack(probed[RSI as usize]),
            saved_flags,
            "flags copied before the sample overwrite"
        );
    }

    fn check_all(cases: &[(u64, Flags)], pair: &[Op]) {
        for &(rax, flags) in cases {
            check_pair(pair, rax, flags);
        }
    }

    fn sample() -> FuncIr {
        FuncIr {
            name: "mix".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![
                Block {
                    ops: vec![Op::MovRi(RAX, 0xffff_ffff_ffff_ffff), Op::AddRr(RAX, RCX)],
                    exit: Exit::Jcc(2, 1, 2),
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRi(RBX, 7)],
                    exit: Exit::Jmp(3),
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRi(RBX, 9)],
                    exit: Exit::Jmp(3),
                    opaque: false,
                },
                Block {
                    ops: vec![],
                    exit: Exit::Ret,
                    opaque: false,
                },
            ],
        }
    }

    #[test]
    fn odd_multiplier_roundtrips_every_u8() {
        for modulus in (0u64..256).map(|value| value | 1) {
            let inverse = odd_inverse(modulus);
            assert_eq!(modulus.wrapping_mul(inverse), 1, "{modulus}");
            for value in 0..=255u64 {
                assert_eq!(value.wrapping_mul(modulus).wrapping_mul(inverse), value);
            }
        }
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        for _ in 0..32 {
            let modulus = rng.gen::<u64>() | 1;
            let value = rng.gen::<u64>();
            let inverse = odd_inverse(modulus);
            assert_eq!(modulus.wrapping_mul(inverse), 1);
            assert_eq!(value.wrapping_mul(modulus).wrapping_mul(inverse), value);
        }
    }

    #[test]
    fn data_mix_pairs_restore_input_rax_and_flags() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let cases = cases(&mut rng);
        for modulus in odd_moduli(&mut rng) {
            check_all(&cases, &mul_pair(RAX, modulus));
        }
        for key in xor_keys(&mut rng) {
            check_all(&cases, &xor_pair(RAX, key));
        }
        for seed in 1..=20 {
            let original = sample();
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let mixed = apply(&original, &mut rng);
            check_all(&cases, &prefix_ops(&original, &mixed));
        }
    }

    #[test]
    fn data_mix_roundtrip_matches_the_oracle() {
        let func = sample();
        let flags = Flags {
            cf: true,
            pf: false,
            zf: true,
            sf: false,
            of: true,
        };
        let before = exec(&func, 0, flags);
        assert_eq!(before.0[RBX as usize], 7);
        for seed in 1..=20 {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let mixed = apply(&func, &mut rng);
            assert_ne!(mixed.blocks, func.blocks, "{seed}");
            let after = exec(&mixed, 0, flags);
            assert_eq!(after.0, before.0, "arch {seed}");
            assert_eq!(after.1, before.1, "flags {seed}");
        }
    }
}
