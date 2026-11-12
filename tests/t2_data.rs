//! T2: the handler edge depends on computed data, and one build has both forms.

use std::collections::BTreeSet;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use vmkek::emu::{bare, Machine, Policy, Region};
use vmkek::flags::Flags;
use vmkek::ir::{exec_func, Block, Exit, FuncIr, MapMem, MemIo, Op, RAX, RCX};
use vmkek::protect::{self, Options};
use vmkek::vm::{self, collect_edges, MachineForm, FRAME_GATE};

fn mix() -> FuncIr {
    FuncIr {
        name: "mix".into(),
        rva: 0x1000,
        entry: 0,
        blocks: vec![Block {
            ops: vec![
                Op::MovRr(RAX, RCX),
                Op::ImulRi(RAX, 7),
                Op::AddRi(RAX, 3),
                Op::XorRi(RAX, 0x5a),
            ],
            exit: Exit::Ret,
            opaque: false,
        }],
    }
}

fn branched() -> FuncIr {
    FuncIr {
        name: "branched".into(),
        rva: 0x1800,
        entry: 0,
        blocks: vec![
            Block {
                ops: vec![Op::CmpRi(RCX, 2)],
                exit: Exit::Jcc(4, 1, 2),
                opaque: false,
            },
            Block {
                ops: vec![Op::MovRi(RAX, 7)],
                exit: Exit::Ret,
                opaque: false,
            },
            Block {
                ops: vec![Op::MovRi(RAX, 9)],
                exit: Exit::Ret,
                opaque: false,
            },
        ],
    }
}

fn lowered(seed: u64) -> vm::BcImage {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    vm::lower_image(&[mix(), branched()], &mut rng).unwrap()
}

fn run_ir(func: &FuncIr, arg: u64) -> u64 {
    let mut arch = [0u64; 16];
    arch[usize::from(RCX)] = arg;
    arch[4] = 0x10000;
    let mut flags = Flags::default();
    let mut mem = MapMem::default();
    let mut host = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
    exec_func(
        std::slice::from_ref(func),
        0,
        &mut arch,
        &mut flags,
        &mut mem,
        0x1400_0000,
        &mut host,
    )
    .unwrap();
    arch[usize::from(RAX)]
}

fn run_vm(image: &vm::BcImage, index: usize, arg: u64, nested: bool) -> u64 {
    let mut arch = [0u64; 16];
    arch[usize::from(RCX)] = arg;
    arch[4] = 0x10000;
    let mut flags = Flags::default();
    let mut mem = MapMem::default();
    let mut host = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
    let run = if nested {
        vm::exec_image_nested
    } else {
        vm::exec_image
    };
    run(
        image,
        index,
        &mut arch,
        &mut flags,
        &mut mem,
        0x1400_0000,
        &mut host,
    )
    .unwrap();
    arch[usize::from(RAX)]
}

fn agree(image: &vm::BcImage, index: usize, func: &FuncIr, arg: u64) {
    let ir = run_ir(func, arg);
    assert_eq!(run_vm(image, index, arg, false), ir, "{}", func.name);
    assert_eq!(run_vm(image, index, arg, true), ir, "nested {}", func.name);
    assert_eq!(native_of(image, index, arg), ir, "native {}", func.name);
}

#[test]
fn dispatch_depends_on_computed_data() {
    let image = lowered(0x72);
    let mix = mix();
    assert!(image.funcs[0].single_path);
    assert!(image.funcs[0].data_dependent);
    let left = collect_edges(|| {
        assert_eq!(run_vm(&image, 0, 1, false), run_ir(&mix, 1));
    });
    let right = collect_edges(|| {
        assert_eq!(run_vm(&image, 0, 2, false), run_ir(&mix, 2));
    });
    assert_eq!(left.len(), right.len());
    assert!(left.len() > 1);
    assert_ne!(left, right);
}

#[test]
fn register_and_stack_forms_match_the_ir_oracle() {
    let image = lowered(0x72);
    let forms: Vec<_> = image.funcs.iter().map(|func| func.form).collect();
    assert!(forms.contains(&MachineForm::Register));
    assert!(forms.contains(&MachineForm::Stack));
    let funcs = [mix(), branched()];
    for (index, func) in funcs.iter().enumerate() {
        assert_eq!(image.funcs[index].name, func.name);
        for arg in [0u64, 2, 9] {
            agree(&image, index, func, arg);
        }
    }
}

#[test]
fn handler_edge_is_not_a_constant_signature() {
    let low = vmkek::stub::assemble_vm_seeded(0x400000, 1).unwrap();
    let high = vmkek::stub::assemble_vm_seeded(0x400000, 2).unwrap();
    let prologue = low.handlers..low.handlers + 16;
    assert_ne!(&low.bytes[prologue.clone()], &high.bytes[prologue]);
    assert_eq!(gate_sites(&low.bytes), 1);
    assert_eq!(gate_sites(&high.bytes), 1);
}

fn gate_sites(bytes: &[u8]) -> usize {
    let mut site = [0xF6u8, 0x83, 0, 0, 0, 0, 0x01];
    site[2..6].copy_from_slice(&vmkek::vm::FRAME_GATE.to_le_bytes());
    bytes
        .windows(site.len())
        .filter(|word| *word == site)
        .count()
}

#[test]
fn next_handler_address_depends_on_the_input() {
    let image = lowered(0x72);
    let mut one = image.clone();
    one.funcs.truncate(1);
    let left = handler_trace(&one, 1);
    let right = handler_trace(&one, 2);
    assert!(left.len() > 8, "left {}", left.len());
    assert_ne!(left, right);
}

#[test]
fn single_path_functions_are_marked() {
    let built = vmkek::sample::build().unwrap();
    let protected = protect::protect(&built.bytes, &virt_all()).unwrap();
    let virt = &protected.report.virtualized;
    assert!(virt
        .iter()
        .any(|sym| sym.machine.as_deref() == Some("register")));
    assert!(virt
        .iter()
        .any(|sym| sym.machine.as_deref() == Some("stack")));
    let mix = virt.iter().find(|sym| sym.name == "mix").unwrap();
    assert_eq!(mix.single_path, Some(true));
    assert_eq!(mix.data_dependent, Some(true));
    let compute = virt.iter().find(|sym| sym.name == "compute").unwrap();
    assert_eq!(compute.single_path, Some(false));
    for sym in virt {
        assert!(sym.machine.is_some(), "{}", sym.name);
        if sym.single_path == Some(true) {
            assert_eq!(sym.data_dependent, Some(true), "{}", sym.name);
        }
    }
    for sym in &protected.report.mutated {
        assert!(sym.machine.is_none());
        assert!(sym.single_path.is_none());
        assert!(sym.data_dependent.is_none());
    }
}

fn virt_all() -> Options {
    Options {
        virtualize: BTreeSet::new(),
        mutate: BTreeSet::new(),
        virtualize_all: true,
        mutate_all: false,
        seed: 0x72,
        random_key: false,
        debug_seed: false,
    }
}

#[test]
fn t2_claims_name_system_channels() {
    let rows = vm::form::claims();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].channel, "System");
    assert_eq!(rows[0].machine, "M-EMU");
    assert_eq!(
        rows[0].anchor,
        "register_and_stack_forms_match_the_ir_oracle"
    );
    assert_eq!(rows[1].channel, "System");
    assert_eq!(rows[1].machine, "M-ADV");
    assert_eq!(
        rows[1].anchor,
        "input_independent_simplifier_misses_the_sample_formula"
    );
    let text = rows.iter().map(|row| row.statement).collect::<String>();
    let lower = text.to_lowercase();
    assert!(!lower.contains("black-box"), "{text}");
    assert!(!lower.contains("black box"), "{text}");
    assert!(!rows.iter().any(|row| row.machine == "M-IR"));
}

fn native_of(image: &vm::BcImage, index: usize, arg: u64) -> u64 {
    let mut one = image.clone();
    one.funcs.swap(0, index);
    one.funcs.truncate(1);
    native_rax(&one, arg).0
}

fn native_rax(image: &vm::BcImage, arg: u64) -> (u64, u64) {
    let origin = 0x400000u64;
    let vm = vmkek::stub::assemble_vm(origin).unwrap();
    let mut machine = bare(Policy::default()).unwrap();
    mount(&mut machine, origin, &vm.bytes);
    place(image, &mut machine);
    let frame = origin + vm.frame as u64;
    machine.regs[3] = frame;
    machine.regs[13] = 0x500000;
    machine.regs[14] = u64::from(image.funcs[0].entry);
    let stack = machine.regs[4];
    write_slot(&mut machine, frame, image, 1, arg);
    write_slot(&mut machine, frame, image, 4, stack);
    machine.rip = origin + vm.dispatch as u64;
    machine.run().unwrap();
    let gate = machine.read(frame + FRAME_GATE as u64, 8).unwrap();
    (
        machine.regs[0],
        u64::from_le_bytes(gate.try_into().unwrap()),
    )
}

fn handler_trace(image: &vm::BcImage, arg: u64) -> Vec<u64> {
    let origin = 0x400000u64;
    let vm = vmkek::stub::assemble_vm(origin).unwrap();
    let mut machine = bare(Policy::default()).unwrap();
    mount(&mut machine, origin, &vm.bytes);
    place(image, &mut machine);
    let frame = origin + vm.frame as u64;
    machine.regs[3] = frame;
    machine.regs[13] = 0x500000;
    machine.regs[14] = u64::from(image.funcs[0].entry);
    let stack = machine.regs[4];
    write_slot(&mut machine, frame, image, 1, arg);
    write_slot(&mut machine, frame, image, 4, stack);
    machine.rip = origin + vm.dispatch as u64;
    let lo = origin + vm.handlers as u64;
    let hi = origin + vm.cipher as u64;
    let mut seen = Vec::new();
    for _ in 0..20_000_000 {
        if machine.exit_code.is_some() {
            return seen;
        }
        let rip = machine.rip;
        if (lo..hi).contains(&rip) {
            seen.push(rip);
        }
        machine.step().unwrap();
    }
    panic!("handler trace did not return");
}

fn mount(machine: &mut Machine, origin: u64, bytes: &[u8]) {
    machine.regions.push(Region {
        base: origin,
        data: bytes.to_vec(),
    });
    machine.regions.push(Region {
        base: 0x500000,
        data: vec![0; 0x20000],
    });
}

fn place(image: &vm::BcImage, machine: &mut Machine) {
    vmkek::stub::place_runtime(
        &image.funcs[0],
        &image.inv,
        check_crc(image),
        &image.slots,
        image.handler_mix,
        machine,
        0x500000,
        0x518000,
    )
    .unwrap();
}

fn check_crc(image: &vm::BcImage) -> u32 {
    let func = &image.funcs[0];
    let mut crc = 0u32;
    for index in 0..func.insns.len() {
        let plain = vm::plain_insn(func, index, &image.inv).unwrap();
        if plain.first() == Some(&0x60) {
            crc = u32::from_le_bytes(plain[1..5].try_into().unwrap());
        }
    }
    crc
}

fn write_slot(machine: &mut Machine, frame: u64, image: &vm::BcImage, arch: usize, value: u64) {
    let slot = u64::from(image.slots.arch(arch));
    machine
        .write(frame + slot * 8, &value.to_le_bytes())
        .unwrap();
}

#[test]
fn stack_budget_keeps_a_form_for_sample_seeds() {
    let built = vmkek::sample::build().unwrap();
    let parsed = vmkek::pe::parse(&built.bytes).unwrap();
    let text = &parsed.sections[0];
    for seed in [1u64, 2, 5, 0x72] {
        let mut funcs = Vec::new();
        for symbol in &built.symbols {
            let off = (symbol.rva - text.rva) as usize;
            let func = vmkek::lift::lift(
                &symbol.name,
                &text.bytes[off..symbol.size as usize + off],
                symbol.rva,
                symbol.size,
                vmkek::pe::IMAGE_BASE,
            )
            .unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(seed ^ u64::from(symbol.rva));
            funcs.push(vmkek::obf::obfuscate(&func, &mut rng).func);
        }
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let image = vm::lower_image(&funcs, &mut rng).unwrap();
        let forms: Vec<_> = image.funcs.iter().map(|func| func.form).collect();
        assert!(
            forms.contains(&MachineForm::Register) && forms.contains(&MachineForm::Stack),
            "seed {seed}: {forms:?}"
        );
    }
}

#[test]
fn native_gate_depends_on_the_input() {
    let image = lowered(0x72);
    let mut one = image.clone();
    one.funcs.truncate(1);
    let (_left, gate_a) = native_rax(&one, 1);
    let (_right, gate_b) = native_rax(&one, 2);
    assert_ne!(gate_a, gate_b);
}
