use rand::Rng;
use rand_chacha::ChaCha20Rng;

use crate::error::{msg, Result};
use crate::ir::{flag_dead_map, Block, Exit, FuncIr, Op, V_DEAD, V_FLAGS, V_STATE};

mod data_mix;
pub mod hard;
pub(crate) mod identities;
mod predicates;

pub struct Obfuscated {
    pub func: FuncIr,
    pub passes: Vec<&'static str>,
}

pub fn obfuscate(func: &FuncIr, rng: &mut ChaCha20Rng) -> Obfuscated {
    let (func, passes) = prepare(func, rng);
    finish(flatten(&func), passes, rng)
}

pub(crate) fn obfuscate_for_authenticated_elf(
    func: &FuncIr,
    rng: &mut ChaCha20Rng,
) -> Result<Obfuscated> {
    let (func, passes) = prepare(func, rng);
    Ok(finish(flatten_balanced(&func)?, passes, rng))
}

fn prepare(func: &FuncIr, rng: &mut ChaCha20Rng) -> (FuncIr, Vec<&'static str>) {
    let (mut func, mut passes, _) = rewrite_ops(func, rng);
    passes.push("template-diversity");
    func = data_mix::apply(&func, rng);
    passes.push("data-mix");
    func = split_blocks(&func);
    passes.push("block-split");
    func = wrap_opaque(&func, rng);
    passes.push("opaque-predicate");
    func = add_bogus(&func, rng);
    passes.push("bogus-control-flow");
    (func, passes)
}

fn finish(func: FuncIr, mut passes: Vec<&'static str>, rng: &mut ChaCha20Rng) -> Obfuscated {
    passes.push("control-flow-flatten");
    passes.push("block-shuffle");
    Obfuscated {
        func: shuffle(&func, rng),
        passes,
    }
}

fn rewrite_ops(
    func: &FuncIr,
    rng: &mut ChaCha20Rng,
) -> (FuncIr, Vec<&'static str>, Vec<&'static str>) {
    let mut saw_mba = false;
    let mut saw_blind = false;
    let mut used = Vec::new();
    let mut blocks = Vec::with_capacity(func.blocks.len());
    for block in &func.blocks {
        let dead = flag_dead_map(block);
        let mut ops = Vec::new();
        for (index, op) in block.ops.iter().enumerate() {
            if let Some((name, expanded)) = identities::choose(*op, dead[index], rng) {
                used.push(name);
                if name.starts_with("mov_") {
                    saw_blind = true;
                } else {
                    saw_mba = true;
                }
                ops.extend(expanded);
            } else {
                ops.push(*op);
            }
        }
        blocks.push(Block {
            ops,
            exit: block.exit,
            opaque: block.opaque,
        });
    }
    let mut passes = Vec::new();
    if saw_mba {
        passes.push("mba");
    }
    if saw_blind {
        passes.push("constant-blind");
    }
    (with_blocks(func, blocks, func.entry), passes, used)
}

fn split_blocks(func: &FuncIr) -> FuncIr {
    let mut blocks = Vec::new();
    let mut start = vec![0u32; func.blocks.len()];
    for (index, block) in func.blocks.iter().enumerate() {
        start[index] = blocks.len() as u32;
        let pieces = block.ops.len().max(1);
        for piece in 0..pieces {
            let ops = if block.ops.is_empty() {
                vec![]
            } else {
                vec![block.ops[piece]]
            };
            let exit = if piece + 1 == pieces {
                Exit::Jmp(u32::MAX)
            } else {
                Exit::Jmp(u32::MAX - 1)
            };
            blocks.push(Block {
                ops,
                exit,
                opaque: false,
            });
        }
    }
    let mut cursor = 0usize;
    for block in &func.blocks {
        let pieces = block.ops.len().max(1);
        for piece in 0..pieces {
            if piece + 1 != pieces {
                blocks[cursor].exit = Exit::Jmp((cursor + 1) as u32);
            } else {
                blocks[cursor].exit = remap_exit(&block.exit, &start);
            }
            cursor += 1;
        }
    }
    with_blocks(func, blocks, start[func.entry as usize])
}

fn remap_exit(exit: &Exit, start: &[u32]) -> Exit {
    let map = |id: u32| start[id as usize];
    match *exit {
        Exit::Jmp(id) => Exit::Jmp(map(id)),
        Exit::Jcc(cond, yes, no) => Exit::Jcc(cond, map(yes), map(no)),
        Exit::CallRva { rva, next } => Exit::CallRva {
            rva,
            next: map(next),
        },
        Exit::CallAbs { reg, next } => Exit::CallAbs {
            reg,
            next: map(next),
        },
        Exit::Ret => Exit::Ret,
    }
}

fn wrap_opaque(func: &FuncIr, rng: &mut ChaCha20Rng) -> FuncIr {
    let original = func.blocks.len();
    let mut blocks = func.blocks.clone();
    for block in blocks.iter_mut().take(original) {
        block.ops.insert(0, Op::LdFlags(V_FLAGS));
    }
    let mut wrapper_of = vec![0u32; original];
    for (index, slot) in wrapper_of.iter_mut().enumerate() {
        let bogus = blocks.len() as u32;
        blocks.push(Block {
            ops: vec![Op::MovRi(V_DEAD, 0xdead_f00d), Op::XorRr(V_DEAD, V_DEAD)],
            exit: Exit::Jmp(index as u32),
            opaque: false,
        });
        let wrap = blocks.len() as u32;
        *slot = wrap;
        let (ops, cond) = predicate_arm(rng, index == func.entry as usize);
        blocks.push(Block {
            ops,
            exit: Exit::Jcc(cond, index as u32, bogus),
            opaque: true,
        });
    }
    for block in blocks.iter_mut().take(original) {
        block.exit = map_wrappers(&block.exit, &wrapper_of);
    }
    with_blocks(func, blocks, wrapper_of[func.entry as usize])
}

fn predicate_arm(rng: &mut ChaCha20Rng, hard: bool) -> (Vec<Op>, u8) {
    // The entry wrapper is the C3 hash. Every other arm stays an algebraic S2 predicate.
    // One hash block keeps the runtime window inside the driver payload budget.
    if hard {
        return (hard::embedded_ops(), hard::COND);
    }
    let predicate = predicates::pick(rng);
    ((predicate.ops)(), predicate.cond)
}

fn map_wrappers(exit: &Exit, wrapper_of: &[u32]) -> Exit {
    let map = |id: u32| wrapper_of.get(id as usize).copied().unwrap_or(id);
    match *exit {
        Exit::Jmp(id) => Exit::Jmp(map(id)),
        Exit::Jcc(cond, yes, no) => Exit::Jcc(cond, map(yes), map(no)),
        Exit::CallRva { rva, next } => Exit::CallRva {
            rva,
            next: map(next),
        },
        Exit::CallAbs { reg, next } => Exit::CallAbs {
            reg,
            next: map(next),
        },
        Exit::Ret => Exit::Ret,
    }
}

fn add_bogus(func: &FuncIr, rng: &mut ChaCha20Rng) -> FuncIr {
    let mut blocks = func.blocks.clone();
    let landing = func.entry;
    for _ in 0..3 {
        let imm = rng.gen::<u64>();
        blocks.push(Block {
            ops: vec![
                Op::MovRi(V_DEAD, imm),
                Op::XorRr(V_DEAD, V_DEAD),
                Op::AddRi(V_DEAD, 7),
            ],
            exit: Exit::Jmp(landing),
            opaque: false,
        });
    }
    with_blocks(func, blocks, func.entry)
}

fn flatten(func: &FuncIr) -> FuncIr {
    let real_len = func.blocks.len();
    let mut blocks = func.blocks.clone();
    route_real_blocks(&mut blocks, real_len);
    let dispatcher = append_dispatcher(&mut blocks, real_len);
    finish_flatten(func, blocks, dispatcher)
}

fn flatten_balanced(func: &FuncIr) -> Result<FuncIr> {
    let real_len = func.blocks.len();
    let mut blocks = func.blocks.clone();
    route_real_blocks(&mut blocks, real_len);
    let dispatcher = append_balanced_dispatcher(&mut blocks, real_len)?;
    Ok(finish_flatten(func, blocks, dispatcher))
}

fn finish_flatten(func: &FuncIr, mut blocks: Vec<Block>, dispatcher: u32) -> FuncIr {
    let entry = blocks.len() as u32;
    blocks.push(Block {
        ops: vec![Op::StFlags(V_FLAGS), Op::MovRi(V_STATE, func.entry as u64)],
        exit: Exit::Jmp(dispatcher),
        opaque: false,
    });
    with_blocks(func, blocks, entry)
}

// Bridges are appended before the dispatcher exists, so they jump to this
// sentinel and it is rewritten once the dispatcher index is known.
const TO_DISPATCH: u32 = u32::MAX;

fn route_real_blocks(blocks: &mut Vec<Block>, real_len: usize) {
    for index in 0..real_len {
        if blocks[index].opaque {
            continue;
        }
        match blocks[index].exit {
            Exit::Ret => {}
            Exit::Jmp(target) => {
                blocks[index].ops.push(Op::StFlags(V_FLAGS));
                blocks[index].ops.push(Op::MovRi(V_STATE, target as u64));
                blocks[index].exit = Exit::Jmp(TO_DISPATCH);
            }
            Exit::Jcc(cond, yes, no) => {
                blocks[index].ops.push(Op::StFlags(V_FLAGS));
                let yes_b = bridge_only_state(blocks, yes);
                let no_b = bridge_only_state(blocks, no);
                blocks[index].exit = Exit::Jcc(cond, yes_b, no_b);
            }
            Exit::CallRva { rva, next } => {
                let bridge = bridge_for(blocks, next);
                blocks[index].exit = Exit::CallRva { rva, next: bridge };
            }
            Exit::CallAbs { reg, next } => {
                let bridge = bridge_for(blocks, next);
                blocks[index].exit = Exit::CallAbs { reg, next: bridge };
            }
        }
    }
}

fn bridge_for(blocks: &mut Vec<Block>, target: u32) -> u32 {
    let id = blocks.len() as u32;
    blocks.push(Block {
        ops: vec![Op::StFlags(V_FLAGS), Op::MovRi(V_STATE, target as u64)],
        exit: Exit::Jmp(TO_DISPATCH),
        opaque: false,
    });
    id
}

fn append_dispatcher(blocks: &mut Vec<Block>, real_len: usize) -> u32 {
    let disp_start = blocks.len();
    for state in 0..real_len {
        let next = if state + 1 == real_len {
            disp_start
        } else {
            disp_start + state + 1
        };
        blocks.push(Block {
            ops: vec![Op::CmpRi(V_STATE, state as i32)],
            exit: Exit::Jcc(4, state as u32, next as u32),
            opaque: false,
        });
    }
    let dispatcher = disp_start as u32;
    resolve_dispatch_bridges(blocks, dispatcher);
    dispatcher
}

fn append_balanced_dispatcher(blocks: &mut Vec<Block>, count: usize) -> Result<u32> {
    let nodes = count
        .checked_mul(2)
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| msg("invalid authenticated ELF dispatcher extent"))?;
    // Leave room for the final entry block. No actual block ID equals TO_DISPATCH.
    if i32::try_from(count - 1).is_err()
        || blocks
            .len()
            .checked_add(nodes)
            .is_none_or(|end| end >= TO_DISPATCH as usize)
    {
        return Err(msg("authenticated ELF dispatcher exceeds state limits"));
    }
    let root = blocks.len() as u32;
    append_dispatch_subtree(blocks, 0, count, root);
    resolve_dispatch_bridges(blocks, root);
    Ok(root)
}

fn append_dispatch_subtree(blocks: &mut Vec<Block>, start: usize, end: usize, root: u32) -> u32 {
    let index = blocks.len();
    blocks.push(Block {
        ops: vec![Op::CmpRi(V_STATE, start as i32)],
        exit: Exit::Jcc(4, start as u32, root),
        opaque: false,
    });
    if end - start > 1 {
        let pivot = start + (end - start) / 2;
        let left = append_dispatch_subtree(blocks, start, pivot, root);
        let right = append_dispatch_subtree(blocks, pivot, end, root);
        blocks[index].ops[0] = Op::CmpRi(V_STATE, pivot as i32);
        // Unsigned below on internal nodes. The exact equality compare at a
        // leaf presents the same flags to a valid target as the linear scan.
        blocks[index].exit = Exit::Jcc(2, left, right);
    }
    index as u32
}

fn resolve_dispatch_bridges(blocks: &mut [Block], dispatcher: u32) {
    for block in blocks {
        if block.exit == Exit::Jmp(TO_DISPATCH) {
            block.exit = Exit::Jmp(dispatcher);
        }
    }
}

fn bridge_only_state(blocks: &mut Vec<Block>, target: u32) -> u32 {
    let id = blocks.len() as u32;
    blocks.push(Block {
        ops: vec![Op::MovRi(V_STATE, target as u64)],
        exit: Exit::Jmp(u32::MAX),
        opaque: false,
    });
    id
}

fn shuffle(func: &FuncIr, rng: &mut ChaCha20Rng) -> FuncIr {
    let len = func.blocks.len();
    let mut order: Vec<usize> = (0..len).collect();
    for index in (1..len).rev() {
        let swap = rng.gen_range(0..=index);
        order.swap(index, swap);
    }
    let mut place = vec![0u32; len];
    for (new_at, old_at) in order.iter().enumerate() {
        place[*old_at] = new_at as u32;
    }
    let mut blocks = vec![func.blocks[0].clone(); len];
    for (old_at, block) in func.blocks.iter().enumerate() {
        let mut moved = block.clone();
        moved.exit = remap_exit(&moved.exit, &place);
        blocks[place[old_at] as usize] = moved;
    }
    with_blocks(func, blocks, place[func.entry as usize])
}

fn with_blocks(func: &FuncIr, blocks: Vec<Block>, entry: u32) -> FuncIr {
    FuncIr {
        name: func.name.clone(),
        rva: func.rva,
        blocks,
        entry,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::flags::Flags;
    use crate::ir::{exec_func, Block, Exit, FuncIr, MapMem, Op, RAX, RBX, RCX, RDX};
    use identities::FlagPrecondition;
    use rand::SeedableRng;

    fn run(func: &FuncIr, rax: u64) -> [u64; 16] {
        let mut arch = [0u64; 16];
        arch[0] = rax;
        arch[4] = 0x1000;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut abs =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        exec_func(
            std::slice::from_ref(func),
            0,
            &mut arch,
            &mut flags,
            &mut mem,
            0,
            &mut abs,
        )
        .unwrap();
        arch
    }

    fn straight(rax_imm: u64) -> FuncIr {
        FuncIr {
            name: "t".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![
                    Op::MovRi(RAX, rax_imm),
                    Op::AddRi(RAX, 3),
                    Op::XorRi(RAX, 0x5a),
                ],
                exit: Exit::Ret,
                opaque: false,
            }],
        }
    }

    // This test-only pipeline keeps production's pass order and exposes one omission.
    fn research_pipeline(func: &FuncIr, rng: &mut ChaCha20Rng, omit: &str) -> FuncIr {
        let mut current = if omit == "rewrite" {
            func.clone()
        } else {
            rewrite_ops(func, rng).0
        };
        if omit != "data-mix" {
            current = data_mix::apply(&current, rng);
        }
        if omit != "block-split" {
            current = split_blocks(&current);
        }
        if omit != "opaque" {
            current = wrap_opaque(&current, rng);
        }
        if omit != "bogus" {
            current = add_bogus(&current, rng);
        }
        if omit != "flatten" {
            current = flatten(&current);
        }
        if omit != "shuffle" {
            current = shuffle(&current, rng);
        }
        current
    }

    #[test]
    fn research_pass_ablations_preserve_owned_ir_examples() {
        let variants = [
            "none",
            "rewrite",
            "data-mix",
            "block-split",
            "opaque",
            "bogus",
            "flatten",
            "shuffle",
        ];
        for fixture in [rich(), live(true), live(false)] {
            let expected = run(&fixture, 0);
            for seed in [0x401u64, 0x402, 0x403] {
                let mut default_rng = ChaCha20Rng::seed_from_u64(seed);
                let default = obfuscate(&fixture, &mut default_rng).func;
                for omit in variants {
                    let mut rng = ChaCha20Rng::seed_from_u64(seed);
                    let result = research_pipeline(&fixture, &mut rng, omit);
                    if omit == "none" {
                        assert_eq!(result, default);
                    }
                    assert_eq!(
                        run(&result, 0),
                        expected,
                        "fixture={} seed={} omit={}",
                        fixture.name,
                        seed,
                        omit
                    );
                    let operations: usize = result.blocks.iter().map(|b| b.ops.len()).sum();
                    println!(
                        "ablation fixture={} seed={} omitted={} blocks={} operations={}",
                        fixture.name,
                        seed,
                        omit,
                        result.blocks.len(),
                        operations
                    );
                }
            }
        }
    }

    #[test]
    fn authenticated_dispatch_routes_exactly_with_logarithmic_comparisons() {
        for count in [1usize, 2, 3, 7, 16, 65, 257] {
            let mut blocks = vec![
                Block {
                    ops: vec![],
                    exit: Exit::Ret,
                    opaque: false,
                };
                count
            ];
            let root = append_balanced_dispatcher(&mut blocks, count).unwrap() as usize;
            let max_comparisons = count.next_power_of_two().trailing_zeros() + 1;
            for state in (0..count as u64).chain([count as u64, u64::MAX]) {
                let mut current = root;
                for _ in 0..max_comparisons {
                    if current < count {
                        break;
                    }
                    let block = &blocks[current];
                    let [Op::CmpRi(V_STATE, immediate)] = block.ops.as_slice() else {
                        panic!("unexpected dispatcher block");
                    };
                    let Exit::Jcc(cond, yes, no) = block.exit else {
                        panic!("unexpected dispatcher branch");
                    };
                    let value = *immediate as i64 as u64;
                    let flags = Flags {
                        cf: state < value,
                        zf: state == value,
                        ..Flags::default()
                    };
                    current = if crate::flags::cond_taken(cond, flags) {
                        yes
                    } else {
                        no
                    } as usize;
                    if current == root && state >= count as u64 {
                        break;
                    }
                    if current < count {
                        assert_eq!(cond, 4);
                        assert!(flags.zf);
                    }
                }
                if state < count as u64 {
                    assert_eq!(current, state as usize, "count={count}, state={state}");
                } else {
                    assert_eq!(current, root);
                }
            }
        }
    }

    #[test]
    fn obfuscation_keeps_the_function_name_and_rva() {
        let func = straight(10);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let obf = obfuscate(&func, &mut rng).func;
        assert_eq!(obf.name, func.name);
        assert_eq!(obf.rva, func.rva);
    }

    #[test]
    fn obfuscation_preserves_straight_line() {
        let func = straight(10);
        let before = run(&func, 0);
        for seed in [1u64, 2, 99, 1000] {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let obf = obfuscate(&func, &mut rng).func;
            let after = run(&obf, 0);
            assert_eq!(after[0], before[0], "seed {seed}");
        }
    }

    #[test]
    fn obfuscation_preserves_carry_branch() {
        let func = FuncIr {
            name: "br".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![
                Block {
                    ops: vec![Op::MovRi(RAX, u64::MAX), Op::AddRi(RAX, 1)],
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
        };
        let before = run(&func, 0);
        assert_eq!(before[RBX as usize], 7);
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let after = run(&obfuscate(&func, &mut rng).func, 0);
        assert_eq!(after[RBX as usize], 7);
    }

    const SEEDS: std::ops::RangeInclusive<u64> = 1..=20;

    fn rich() -> FuncIr {
        FuncIr {
            name: "rich".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![
                    Op::MovRi(RAX, 0x1234_5678_9abc_def0),
                    Op::MovRi(RBX, 0x0fed_cba9_8765_4321),
                    Op::MovRi(RCX, 0x1111_2222_3333_4444),
                    Op::MovRi(RDX, 0x5a),
                    Op::AddRr(RAX, RBX),
                    Op::SubRr(RCX, RBX),
                    Op::XorRr(RAX, RCX),
                    Op::AndRr(RBX, RAX),
                    Op::OrRr(RCX, RBX),
                    Op::AddRr(RDX, RAX),
                    Op::MovRi(RAX, 0x100),
                    Op::AddRr(RAX, RDX),
                ],
                exit: Exit::Ret,
                opaque: false,
            }],
        }
    }

    fn live(carry: bool) -> FuncIr {
        let rax = if carry { u64::MAX } else { 10 };
        FuncIr {
            name: if carry {
                "carry".into()
            } else {
                "clear".into()
            },
            rva: 0x1000,
            entry: 0,
            blocks: vec![
                Block {
                    ops: vec![Op::MovRi(RCX, 1), Op::MovRi(RAX, rax), Op::AddRr(RAX, RCX)],
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
    fn catalog_rewrite_matches_the_oracle() {
        for func in [rich(), live(true), live(false)] {
            let before = run(&func, 0);
            if func.name == "carry" {
                assert_eq!(before[RBX as usize], 7);
            }
            if func.name == "clear" {
                assert_eq!(before[RBX as usize], 9);
            }
            for seed in SEEDS {
                let mut rng = ChaCha20Rng::seed_from_u64(seed);
                let after = run(&obfuscate(&func, &mut rng).func, 0);
                assert_eq!(after, before, "{} seed {seed}", func.name);
            }
        }
    }

    #[test]
    fn rewrite_uses_at_least_three_identities_across_seeds() {
        let mut adds = BTreeSet::new();
        let mut movs = BTreeSet::new();
        for seed in SEEDS {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let (_, _, names) = rewrite_ops(&rich(), &mut rng);
            for name in names {
                if name.starts_with("add_") {
                    adds.insert(name);
                }
                if name.starts_with("mov_") {
                    movs.insert(name);
                }
            }
        }
        assert!(adds.len() >= 3, "{adds:?}");
        assert!(movs.len() >= 3, "{movs:?}");
    }

    #[test]
    fn live_flags_only_use_preserved_add_identities() {
        for seed in SEEDS {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let (_, _, names) = rewrite_ops(&live(true), &mut rng);
            for name in names.iter().filter(|name| name.starts_with("add_")) {
                let identity = identities::catalog()
                    .iter()
                    .find(|identity| identity.name == *name)
                    .unwrap_or_else(|| panic!("missing {name}"));
                assert_eq!(identity.precondition, FlagPrecondition::Preserved, "{name}");
            }
        }
    }

    #[test]
    fn obfuscation_emits_the_hard_predicate() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let obf = obfuscate(&rich(), &mut rng).func;
        let hard = obf
            .blocks
            .iter()
            .filter(|block| block.opaque && block.ops == hard::embedded_ops())
            .count();
        assert_eq!(hard, 1);
    }

    #[test]
    fn opaque_predicates_vary_across_seeds() {
        let mut seen = BTreeSet::new();
        for seed in SEEDS {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let obf = obfuscate(&rich(), &mut rng).func;
            for block in &obf.blocks {
                if block.opaque {
                    if let Some(name) = predicates::identify(&block.ops) {
                        seen.insert(name);
                    }
                }
            }
        }
        assert!(seen.len() >= 3, "{seen:?}");
    }

    #[test]
    fn obfuscate_records_data_mix_and_template_diversity() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let passes = obfuscate(&straight(1), &mut rng).passes;
        assert!(passes.contains(&"data-mix"));
        assert!(passes.contains(&"template-diversity"));
    }
}
