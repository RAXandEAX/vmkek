//! Ring of taken branch targets inside the emulator.
//!
//! This is machine M-TRACE. Each entry is the target address of a taken
//! `jmp`, `jcc`, `call`, or `ret`. The buffer does not store fall-throughs,
//! register values, or memory operands. It is not an Intel Processor Trace
//! recording. A live PT protocol stays red until a laboratory exists.

use iced_x86::code_asm::*;

use crate::error::{msg, Result};
use crate::isa::census::Machine as TraceMachine;

use super::{bare, Machine, Policy, Region};

/// Retained targets. Older entries fall out, as in a last-branch ring.
pub(super) const CAP: usize = 4096;
const CODE: u64 = 0x4000_0000;
const LEFT: u64 = CODE + 0x200;
const RIGHT: u64 = CODE + 0x220;
const TAG_LEN: usize = 16;

const RING_STMT: &str = "Кольцевой буфер адресов ветвей внутри эмулятора после прогона sample не содержит полных последовательностей байтов проверенных ключей. Это модель M-TRACE.";
const CLASS_STMT: &str =
    "Опкоды каждого проверенного класса дают одинаковые суммарные счётчики загрузок и сохранений в модели интерпретатора.";
const TAG_STMT: &str = "Секретный байт не выбирает ветку в сравнении тега: цели переходов в модели M-TRACE совпадают для каждого значения одиночного отличающегося байта.";
const LIVE_STMT: &str = "Живой Intel PT не измерялся. Это не модель M-TRACE. Отдельный протокол остаётся красным, пока нет лаборатории.";

/// Green means the named test passed. Red means that channel was not run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelColor {
    Green,
    Red,
}

/// One T11 proof row. Not a [`crate::proof::PassClaim`]: that registry is shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceClaim {
    pub id: &'static str,
    pub channel: &'static str,
    pub machine: &'static str,
    pub color: ChannelColor,
    pub anchor: &'static str,
    pub statement: &'static str,
}

/// System rows on M-TRACE, plus the live PT row that was not run.
#[must_use]
pub fn claims() -> &'static [TraceClaim] {
    const ROWS: &[TraceClaim] = &[
        TraceClaim {
            id: "branch-ring-no-key",
            channel: "System",
            machine: TraceMachine::MTrace.as_str(),
            color: ChannelColor::Green,
            anchor: "sample_branch_ring_holds_no_key_bytes",
            statement: RING_STMT,
        },
        TraceClaim {
            id: "opcode-class-access",
            channel: "System",
            machine: TraceMachine::MTrace.as_str(),
            color: ChannelColor::Green,
            anchor: "opcode_class_memory_accesses_match",
            statement: CLASS_STMT,
        },
        TraceClaim {
            id: "tag-compare-branch",
            channel: "System",
            machine: TraceMachine::MTrace.as_str(),
            color: ChannelColor::Green,
            anchor: "secret_byte_does_not_select_a_tag_branch",
            statement: TAG_STMT,
        },
        TraceClaim {
            id: "live-intel-pt",
            channel: "System",
            machine: "",
            color: ChannelColor::Red,
            anchor: LIVE_STMT,
            statement: LIVE_STMT,
        },
    ];
    ROWS
}

/// Guest result of the constant-time tag compare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagRun {
    /// `true` when every tag byte matched.
    pub equal: bool,
    /// Taken branch targets, oldest first.
    pub targets: Vec<u64>,
}

pub(super) struct BranchRing {
    slots: Box<[u64]>,
    next: usize,
    len: usize,
}

impl BranchRing {
    pub(super) fn new() -> Self {
        Self {
            slots: vec![0; CAP].into_boxed_slice(),
            next: 0,
            len: 0,
        }
    }

    pub(super) fn record(&mut self, target: u64) {
        self.slots[self.next] = target;
        self.next = (self.next + 1) % CAP;
        if self.len < CAP {
            self.len += 1;
        }
    }

    pub(super) fn targets(&self) -> Vec<u64> {
        if self.len < CAP {
            return self.slots[..self.len].to_vec();
        }
        let mut out = Vec::with_capacity(CAP);
        out.extend_from_slice(&self.slots[self.next..]);
        out.extend_from_slice(&self.slots[..self.next]);
        out
    }
}

impl Machine {
    /// Taken branch targets still in the ring, oldest first.
    #[must_use]
    pub fn branch_targets(&self) -> Vec<u64> {
        self.branches.targets()
    }

    /// Little-endian bytes of [`Self::branch_targets`].
    #[must_use]
    pub fn branch_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.branches.len * 8);
        for target in self.branches.targets() {
            out.extend(target.to_le_bytes());
        }
        out
    }

    pub(super) fn note_branch(&mut self, target: u64) {
        self.branches.record(target);
    }
}

/// Compare two 16-byte tags in the emulator without a per-byte branch.
///
/// The loop counter selects `jnz`. The secret bytes only update an accumulator.
pub fn compare_tags(left: &[u8; TAG_LEN], right: &[u8; TAG_LEN]) -> Result<TagRun> {
    compare_emitted_tags(&emit_compare()?, left, right)
}

fn compare_emitted_tags(
    code: &[u8],
    left: &[u8; TAG_LEN],
    right: &[u8; TAG_LEN],
) -> Result<TagRun> {
    let policy = Policy {
        max_steps: 4_000,
        ..Policy::default()
    };
    let mut machine = bare(policy)?;
    machine.regions.push(Region {
        base: CODE,
        data: vec![0; 0x1000],
    });
    machine.write(CODE, code)?;
    machine.write(LEFT, left)?;
    machine.write(RIGHT, right)?;
    machine.rip = CODE;
    machine.run()?;
    Ok(TagRun {
        equal: machine.regs[0] == 0,
        targets: machine.branch_targets(),
    })
}

fn emit_compare() -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut head = a.create_label();
    asm(a.xor(eax, eax))?;
    asm(a.mov(ecx, TAG_LEN as i32))?;
    asm(a.mov(rsi, LEFT as i64))?;
    asm(a.mov(rdi, RIGHT as i64))?;
    asm(a.set_label(&mut head))?;
    emit_loop(&mut a, &head)?;
    asm(a.ret())?;
    let encoded = a.assemble(CODE).map_err(|err| msg(err.to_string()))?;
    Ok(encoded)
}

fn emit_loop(a: &mut CodeAssembler, head: &CodeLabel) -> Result<()> {
    asm(a.movzx(edx, byte_ptr(rsi)))?;
    asm(a.movzx(r8d, byte_ptr(rdi)))?;
    asm(a.xor(edx, r8d))?;
    asm(a.or(eax, edx))?;
    asm(a.inc(rsi))?;
    asm(a.inc(rdi))?;
    asm(a.dec(ecx))?;
    asm(a.jnz(*head))?;
    Ok(())
}

fn asm(step: std::result::Result<(), IcedError>) -> Result<()> {
    step.map_err(|err| msg(err.to_string()))
}

#[cfg(test)]
mod tests {
    use iced_x86::BlockEncoderOptions;

    use super::*;
    use crate::emu::SENTINEL;
    use crate::isa::census::Machine as TraceMachine;

    #[test]
    fn ring_keeps_the_newest_targets() {
        let mut ring = BranchRing::new();
        let extra = 3u64;
        for value in 0..CAP as u64 + extra {
            ring.record(value);
        }
        let got = ring.targets();
        assert_eq!(got.len(), CAP);
        assert_eq!(got[0], extra);
        assert_eq!(*got.last().unwrap(), CAP as u64 + extra - 1);
    }

    #[test]
    fn ring_bytes_follow_target_order() {
        let mut ring = BranchRing::new();
        ring.record(0x11);
        ring.record(0x22);
        let bytes: Vec<u8> = ring
            .targets()
            .iter()
            .flat_map(|item| item.to_le_bytes())
            .collect();
        assert_eq!(
            bytes,
            [0x11, 0, 0, 0, 0, 0, 0, 0, 0x22, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn m_trace_name_matches_the_census() {
        assert_eq!(TraceMachine::MTrace.as_str(), "M-TRACE");
        assert!(claims()
            .iter()
            .filter(|row| row.color == ChannelColor::Green)
            .all(|row| row.channel == "System" && row.machine == "M-TRACE"));
        let live = claims()
            .iter()
            .find(|row| row.id == "live-intel-pt")
            .unwrap();
        assert_eq!(live.color, ChannelColor::Red);
        assert_eq!(live.machine, "");
        assert!(live.statement.contains("не модель M-TRACE"));
    }

    #[test]
    fn an_immediate_is_not_a_branch_target() {
        let key = 0x1122_3344_5566_7788u64;
        let machine = run_plant(key);
        let targets = machine.branch_targets();
        assert_eq!(targets.len(), 2, "{targets:?}");
        assert_eq!(*targets.last().unwrap(), SENTINEL);
        assert!(!machine
            .branch_bytes()
            .windows(8)
            .any(|window| window == key.to_le_bytes()));
        assert_ne!(targets[0], key);
        assert_eq!(machine.regs[0], key);
    }

    fn run_plant(key: u64) -> Machine {
        let mut a = CodeAssembler::new(64).unwrap();
        let mut land = a.create_label();
        a.mov(rax, key as i64).unwrap();
        a.jmp(land).unwrap();
        a.set_label(&mut land).unwrap();
        a.ret().unwrap();
        let encoded = a
            .assemble_options(CODE, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();
        let land_ip = encoded.label_ip(&land).unwrap();
        let mut machine = boot(&encoded.inner.code_buffer);
        machine.run().unwrap();
        assert_eq!(machine.branch_targets()[0], land_ip);
        machine
    }

    #[test]
    fn a_not_taken_conditional_is_omitted() {
        let mut a = CodeAssembler::new(64).unwrap();
        let mut skip = a.create_label();
        let mut done = a.create_label();
        a.xor(eax, eax).unwrap();
        a.jne(skip).unwrap();
        a.mov(eax, 1i32).unwrap();
        a.jmp(done).unwrap();
        a.set_label(&mut skip).unwrap();
        a.mov(eax, 2i32).unwrap();
        a.set_label(&mut done).unwrap();
        a.ret().unwrap();
        let encoded = a
            .assemble_options(CODE, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();
        let skip_ip = encoded.label_ip(&skip).unwrap();
        let done_ip = encoded.label_ip(&done).unwrap();
        let mut machine = boot(&encoded.inner.code_buffer);
        machine.run().unwrap();
        assert_eq!(machine.regs[0], 1);
        assert_eq!(machine.branch_targets(), vec![done_ip, SENTINEL]);
        assert!(!machine.branch_targets().contains(&skip_ip));
    }

    #[test]
    fn ring_records_taken_call_conditional_jump_and_return_targets() {
        let mut a = CodeAssembler::new(64).unwrap();
        let mut callee = a.create_label();
        let mut after_call = a.create_label();
        let mut taken = a.create_label();
        let mut done = a.create_label();
        a.call(callee).unwrap();
        a.set_label(&mut after_call).unwrap();
        a.jmp(done).unwrap();
        a.set_label(&mut callee).unwrap();
        a.xor(edx, edx).unwrap();
        a.je(taken).unwrap();
        a.mov(eax, 99i32).unwrap();
        a.ret().unwrap();
        a.set_label(&mut taken).unwrap();
        a.ret().unwrap();
        a.set_label(&mut done).unwrap();
        a.ret().unwrap();

        let encoded = a
            .assemble_options(CODE, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();
        let mut machine = boot(&encoded.inner.code_buffer);
        machine.run().unwrap();
        let [callee, taken, after_call, done] =
            [callee, taken, after_call, done].map(|label| encoded.label_ip(&label).unwrap());
        assert_eq!(
            machine.branch_targets(),
            [callee, taken, after_call, done, SENTINEL]
        );
        assert_eq!(machine.exit_code, Some(0));
    }

    fn boot(code: &[u8]) -> Machine {
        let policy = Policy {
            max_steps: 1_000,
            ..Policy::default()
        };
        let mut machine = bare(policy).unwrap();
        machine.regions.push(Region {
            base: CODE,
            data: vec![0; 0x1000],
        });
        machine.write(CODE, code).unwrap();
        machine.rip = CODE;
        machine
    }

    #[test]
    fn secret_byte_does_not_select_a_tag_branch() {
        let tag = [0x5au8; TAG_LEN];
        let same = compare_tags(&tag, &tag).unwrap();
        assert!(same.equal);
        assert_eq!(same.targets.len(), TAG_LEN);
        assert_eq!(*same.targets.last().unwrap(), SENTINEL);
        assert!(same.targets[..TAG_LEN - 1]
            .windows(2)
            .all(|pair| pair[0] == pair[1]));
        let code = emit_compare().unwrap();
        for index in 0..TAG_LEN {
            for value in u8::MIN..=u8::MAX {
                let mut other = tag;
                other[index] = value;
                let run = compare_emitted_tags(&code, &tag, &other).unwrap();
                assert_eq!(run.equal, value == tag[index], "byte {index} = {value}");
                assert_eq!(run.targets, same.targets, "byte {index} = {value}");
                assert_eq!(
                    run.equal,
                    crate::crypto::tags_equal(&tag, &other),
                    "byte {index} = {value}"
                );
            }
        }
    }
}
