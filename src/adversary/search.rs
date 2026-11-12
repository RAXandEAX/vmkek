//! Bounded search over open IR and sealed bytecode.

use std::collections::{HashSet, VecDeque};

use crate::flags::cond_taken;
use crate::ir::{FuncIr, RAX};
use crate::vm::{form, plain_insn, BcFunc, BcImage};

use super::decode::{self, Code};
use super::expr::{self, Expr};
use super::machine::{self, File, Prim};
use super::mba;

pub(super) struct Attempt {
    pub steps: u32,
    pub recovered: Option<Expr>,
}

#[derive(Clone)]
struct Node {
    ip: u32,
    depth: u32,
    file: File,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Stamp {
    ip: u32,
    flags: Option<u64>,
    slot: Vec<Expr>,
}

enum Out {
    Found(Expr),
    Budget,
    Next,
}

struct Job<'a> {
    queue: &'a mut VecDeque<Node>,
    seen: &'a mut HashSet<Stamp>,
    steps: &'a mut u32,
    budget: u32,
}

pub(super) fn run_ir(func: &FuncIr, budget: u32) -> Attempt {
    let start = Node {
        ip: func.entry,
        depth: 0,
        file: machine::integer_file(),
    };
    explore(budget, start, |node, job| step_ir(func, node, job))
}

pub(super) fn run_bytecode(image: &BcImage, budget: u32) -> Attempt {
    run_mix(image, budget, false)
}

pub(super) fn run_discarding(image: &BcImage, budget: u32) -> Attempt {
    run_mix(image, budget, true)
}

fn run_mix(image: &BcImage, budget: u32, discard: bool) -> Attempt {
    let Some(func) = image.funcs.iter().find(|item| item.name == "mix") else {
        return Attempt {
            steps: 0,
            recovered: None,
        };
    };
    let rax = u16::from(image.slots.forward[usize::from(RAX)]);
    let start = Node {
        ip: func.entry,
        depth: 0,
        file: machine::slot_file(&image.slots),
    };
    explore(budget, start, |node, job| {
        step_bc(func, &image.inv, rax, node, job, discard)
    })
}

fn explore(budget: u32, start: Node, mut step: impl FnMut(Node, &mut Job<'_>) -> Out) -> Attempt {
    let mut steps = 0u32;
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    seen.insert(stamp(&start));
    queue.push_back(start);
    while let Some(node) = queue.pop_front() {
        let mut job = Job {
            queue: &mut queue,
            seen: &mut seen,
            steps: &mut steps,
            budget,
        };
        match step(node, &mut job) {
            Out::Found(expr) => {
                return Attempt {
                    steps,
                    recovered: Some(expr),
                };
            }
            Out::Budget => {
                return Attempt {
                    steps,
                    recovered: None,
                };
            }
            Out::Next => {}
        }
    }
    Attempt {
        steps,
        recovered: None,
    }
}

fn step_ir(func: &FuncIr, node: Node, job: &mut Job<'_>) -> Out {
    let Some(block) = func
        .blocks
        .get(usize::try_from(node.ip).unwrap_or(usize::MAX))
    else {
        return Out::Next;
    };
    let mut file = node.file;
    for op in &block.ops {
        if !tick(job) {
            return Out::Budget;
        }
        let Some(prim) = machine::from_op(*op) else {
            return Out::Next;
        };
        if !machine::apply(&mut file, &prim) {
            return Out::Next;
        }
    }
    if !tick(job) {
        return Out::Budget;
    }
    let depth = node
        .depth
        .saturating_add(u32::try_from(block.ops.len()).unwrap_or(u32::MAX))
        .saturating_add(1);
    match block.exit {
        crate::ir::Exit::Ret => found(&file, RAX),
        crate::ir::Exit::Jmp(ip) => {
            launch(job, ip, depth, file);
            Out::Next
        }
        crate::ir::Exit::Jcc(cond, yes, no) => {
            steer(job, file, depth, cond, yes, no);
            Out::Next
        }
        _ => Out::Next,
    }
}

fn step_bc(
    func: &BcFunc,
    inv: &[u8; 256],
    rax: u16,
    node: Node,
    job: &mut Job<'_>,
    discard: bool,
) -> Out {
    if node.depth >= job.budget {
        return Out::Budget;
    }
    let ip = usize::try_from(node.ip).unwrap_or(usize::MAX);
    let Ok(mut plain) = plain_insn(func, ip, inv) else {
        return Out::Next;
    };
    if !discard {
        form::mix_imm(&mut plain, func.sched, func.rva, node.ip);
    }
    if !tick(job) {
        return Out::Budget;
    }
    let Some(code) = decode::decode(&plain) else {
        return Out::Next;
    };
    let depth = node.depth.saturating_add(1);
    match code {
        Code::Ret => found(&node.file, rax),
        Code::Jmp(ip) => {
            launch(job, ip, depth, node.file);
            Out::Next
        }
        Code::Jcc(cond, ip) => {
            steer(job, node.file, depth, cond, ip, node.ip.wrapping_add(1));
            Out::Next
        }
        Code::Prim(prim) => follow(job, node, depth, &prim),
    }
}

fn follow(job: &mut Job<'_>, node: Node, depth: u32, prim: &Prim) -> Out {
    let mut file = node.file;
    if machine::apply(&mut file, prim) {
        launch(job, node.ip.wrapping_add(1), depth, file);
    }
    Out::Next
}

fn found(file: &File, rax: u16) -> Out {
    let Some(expr) = file.get(rax) else {
        return Out::Next;
    };
    let expr = mba::simplify(&expr);
    if expr::is_reference(&expr) {
        Out::Found(expr)
    } else {
        Out::Next
    }
}

fn steer(job: &mut Job<'_>, file: File, depth: u32, cond: u8, yes: u32, no: u32) {
    match file.flags.map(|flags| cond_taken(cond, flags)) {
        Some(true) => launch(job, yes, depth, file),
        Some(false) => launch(job, no, depth, file),
        None => {
            launch(job, yes, depth, file.clone());
            launch(job, no, depth, file);
        }
    }
}

fn launch(job: &mut Job<'_>, ip: u32, depth: u32, file: File) {
    if depth > job.budget {
        return;
    }
    let node = Node { ip, depth, file };
    if job.seen.insert(stamp(&node)) {
        job.queue.push_back(node);
    }
}

fn stamp(node: &Node) -> Stamp {
    Stamp {
        ip: node.ip,
        flags: node.file.flags.map(|flags| flags.pack()),
        slot: node.file.slot.clone(),
    }
}

fn tick(job: &mut Job<'_>) -> bool {
    if *job.steps >= job.budget {
        return false;
    }
    *job.steps += 1;
    true
}
