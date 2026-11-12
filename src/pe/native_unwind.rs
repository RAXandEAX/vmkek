//! Win64 unwind metadata for the supported native VM call bridges.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};

use super::native::{containing_data_section, overlaps, unwind_entries};
use super::*;

type RuntimeFunction = (u32, u32, u32);
const SECTION_NAME: &str = ".unwmeta";

pub(crate) struct NativeUnwind {
    original: Vec<RuntimeFunction>,
    plans: Vec<(u32, Vec<[u8; 2]>)>,
}

impl NativeUnwind {
    pub(crate) fn plan(
        image: &PeImage,
        virtualized: impl IntoIterator<Item = (u32, u32)>,
        mutated: impl IntoIterator<Item = (u32, u32)>,
        guarded: bool,
    ) -> Result<Self> {
        let original = unwind_entries(image)?;
        let mut plans = Vec::new();
        for selection in virtualized {
            for &(begin, end, record) in &original {
                if !overlaps(selection, (begin, end - begin)) {
                    continue;
                }
                if guarded {
                    return Err(msg(
                        "native CFG requires leaf selections without unwind records",
                    ));
                }
                if selection.0 != begin || selection.1 != end - begin {
                    return Err(msg(
                        "native PE selection crosses an unwind function boundary",
                    ));
                }
                plans.push((begin, source_frame(image, begin, end, record)?));
            }
        }
        for selection in mutated {
            if original
                .iter()
                .any(|&(a, b, _)| overlaps(selection, (a, b - a)))
            {
                return Err(msg(
                    "native PE cannot mutate functions covered by unwind records",
                ));
            }
        }
        Ok(Self { original, plans })
    }

    fn has_bridge(&self, rva: u32) -> bool {
        self.plans.iter().any(|plan| plan.0 == rva)
    }

    pub(crate) fn publish(
        &self,
        image: &mut PeImage,
        bridges: &[(u32, u32, u32)],
        cleanup_rva: Option<u32>,
        startup: &[crate::loader::NativeStartupUnwind],
    ) -> Result<()> {
        if self.plans.is_empty() && startup.is_empty() {
            return Ok(());
        }
        if !self.plans.is_empty() {
            let cleanup = cleanup_rva.ok_or_else(|| msg("native unwind cleanup is missing"))?;
            check_code_range(
                image,
                cleanup,
                cleanup
                    .checked_add(1)
                    .ok_or_else(|| msg("unwind RVA overflows"))?,
            )?;
        }
        let rva = image_span(image)?;
        let mut entries: Vec<_> = self
            .original
            .iter()
            .copied()
            .filter(|entry| !self.has_bridge(entry.0))
            .collect();
        let directory_len = (entries.len() + self.plans.len() + startup.len()) * 12;
        let mut bytes = vec![0; directory_len];
        for (func, codes) in &self.plans {
            let (begin, end) = bridge_range(image, bridges, *func)?;
            let record = rva
                .checked_add(bytes.len() as u32)
                .ok_or_else(|| msg("unwind RVA overflows"))?;
            entries.push((begin, end, record));
            let cleanup = cleanup_rva.ok_or_else(|| msg("native unwind cleanup is missing"))?;
            write_bridge_info(&mut bytes, codes, cleanup);
        }
        for frame in startup {
            let add = |base: u32, offset: u32| {
                base.checked_add(offset)
                    .ok_or_else(|| msg("unwind RVA overflows"))
            };
            let begin = add(image.entry_rva, frame.begin)?;
            let end = add(image.entry_rva, frame.end)?;
            check_code_range(image, begin, end)?;
            let record = add(rva, bytes.len() as u32)?;
            entries.push((begin, end, record));
            bytes.extend_from_slice(&frame.info);
        }
        entries.sort_unstable();
        if entries.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(msg("generated PE runtime functions overlap"));
        }
        for (slot, entry) in bytes[..directory_len].chunks_exact_mut(12).zip(entries) {
            put32(slot, 0, entry.0);
            put32(slot, 4, entry.1);
            put32(slot, 8, entry.2);
        }
        append_section(image, rva, bytes, directory_len as u32)
    }
}

pub(super) fn check_code_range(image: &PeImage, begin: u32, end: u32) -> Result<()> {
    if begin >= end
        || !image.sections.iter().any(|section| {
            executable(section)
                && begin >= section.rva
                && u64::from(end) <= u64::from(section.rva) + section.bytes.len() as u64
        })
    {
        return Err(msg("PE runtime function is outside an executable section"));
    }
    Ok(())
}

fn bridge_range(image: &PeImage, bridges: &[(u32, u32, u32)], func: u32) -> Result<(u32, u32)> {
    let mut matching = bridges.iter().filter(|bridge| bridge.0 == func);
    let &(_, begin, end) = matching
        .next()
        .ok_or_else(|| msg("native unwind bridge is missing"))?;
    if matching.next().is_some() {
        return Err(msg("duplicate native unwind bridge"));
    }
    check_code_range(image, begin, end)?;
    let bytes = read_rva(image, begin, (end - begin) as usize)?;
    // The CALL return PC must be the NOP, so Windows sees the established
    // unwind frame instead of treating the following JMP as an epilogue.
    if bytes.len() != 9 || bytes[..5] != [0x41, 0xff, 0xd3, 0x90, 0xe9] {
        return Err(msg("invalid native PE host-call bridge"));
    }
    let displacement = i32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
    let resume = u32::try_from(i64::from(end) + i64::from(displacement))
        .ok()
        .filter(|&target| target != u32::MAX)
        .ok_or_else(|| msg("invalid native PE host-call resume target"))?;
    check_code_range(image, resume, resume + 1)?;
    Ok((begin, end))
}

fn write_bridge_info(bytes: &mut Vec<u8>, codes: &[[u8; 2]], cleanup: u32) {
    const VERSION_ONE_UHANDLER: u8 = 1 | (2 << 3);
    // The bridge is entered after the guest prologue; every operation is active
    // from its first byte. The handler releases TLS on Windows phase-two unwind.
    bytes.extend_from_slice(&[VERSION_ONE_UHANDLER, 0, codes.len() as u8, 0]);
    for &[_offset, operation] in codes {
        bytes.extend_from_slice(&[0, operation]);
    }
    if !codes.len().is_multiple_of(2) {
        bytes.extend_from_slice(&[0, 0]);
    }
    bytes.extend_from_slice(&cleanup.to_le_bytes());
}

fn append_section(image: &mut PeImage, rva: u32, bytes: Vec<u8>, directory_len: u32) -> Result<()> {
    if image
        .sections
        .iter()
        .any(|section| section.name == SECTION_NAME)
        || image.sections.len() >= MAX_SECTIONS
    {
        return Err(msg("cannot append a PE unwind metadata section"));
    }
    image.sections.push(Section {
        name: SECTION_NAME.into(),
        rva,
        bytes,
        characteristics: CH_RDATA,
    });
    image.exception_rva = rva;
    image.exception_size = directory_len;
    Ok(())
}

fn source_frame(image: &PeImage, begin: u32, end: u32, record: u32) -> Result<Vec<[u8; 2]>> {
    check_code_range(image, begin, end)?;
    let error = || msg("native PE cannot rewrite functions covered by unsupported unwind records");
    let header = read_rva(image, record, 4)?;
    let [version, prologue, count, frame] = [header[0], header[1], header[2], header[3]];
    if version != 1 || frame != 0 || prologue == 0 || count == 0 {
        return Err(error());
    }
    let size = 4 + u32::from(count).next_multiple_of(2) * 2;
    containing_data_section(image, record, size)?;
    let data = read_rva(image, record, size as usize)?;
    let codes: Vec<_> = data[4..4 + usize::from(count) * 2]
        .chunks_exact(2)
        .map(|pair| [pair[0], pair[1]])
        .collect();
    let code = read_rva(image, begin, (end - begin) as usize)?;
    let instructions: Vec<_> = Decoder::with_ip(64, code, u64::from(begin), DecoderOptions::NONE)
        .into_iter()
        .collect();
    let frame = check_prologue(&instructions, begin, prologue, &codes).ok_or_else(error)?;
    check_body(&instructions, &frame)
        .then_some(codes)
        .ok_or_else(error)
}

struct Frame {
    first_body: usize,
    allocation: u64,
    saved: Vec<Register>,
}

fn check_prologue(
    instructions: &[Instruction],
    begin: u32,
    length: u8,
    codes: &[[u8; 2]],
) -> Option<Frame> {
    let end = u64::from(begin) + u64::from(length);
    let first_body = instructions
        .iter()
        .position(|instruction| instruction.ip() == end)?;
    let prologue = &instructions[..first_body];
    if prologue.len() != codes.len() {
        return None;
    }
    let mut saved = Vec::new();
    let mut allocation = 0;
    for (instruction, &[at, op]) in prologue.iter().zip(codes.iter().rev()) {
        if instruction.next_ip() != u64::from(begin) + u64::from(at) {
            return None;
        }
        match op & 15 {
            0 if allocation == 0 && instruction.mnemonic() == Mnemonic::Push => {
                let register = unwind_register(op >> 4)?;
                if instruction.op0_register() != register || saved.contains(&register) {
                    return None;
                }
                saved.push(register);
            }
            2 if allocation == 0 => {
                allocation = 8 * (u64::from(op >> 4) + 1);
                if !stack_adjust(instruction, Mnemonic::Sub, allocation) {
                    return None;
                }
            }
            _ => return None,
        }
    }
    if allocation < 32 || (allocation + 8 * saved.len() as u64) % 16 != 8 {
        return None;
    }
    Some(Frame {
        first_body,
        allocation,
        saved,
    })
}

fn unwind_register(number: u8) -> Option<Register> {
    Some(match number {
        3 => Register::RBX,
        5 => Register::RBP,
        6 => Register::RSI,
        7 => Register::RDI,
        12 => Register::R12,
        13 => Register::R13,
        14 => Register::R14,
        15 => Register::R15,
        _ => return None,
    })
}

fn stack_adjust(instruction: &Instruction, op: Mnemonic, amount: u64) -> bool {
    instruction.mnemonic() == op
        && instruction.op0_register() == Register::RSP
        && matches!(
            instruction.op1_kind(),
            OpKind::Immediate8to64 | OpKind::Immediate32to64
        )
        && instruction.immediate(1) == amount
}

fn check_body(instructions: &[Instruction], frame: &Frame) -> bool {
    let Some(epilogue_at) = instructions.len().checked_sub(frame.saved.len() + 2) else {
        return false;
    };
    if epilogue_at <= frame.first_body || !check_epilogue(&instructions[epilogue_at..], frame) {
        return false;
    }
    let mut info = InstructionInfoFactory::new();
    let branch_targets = &instructions[frame.first_body..=epilogue_at];
    let mut has_call = false;
    for instruction in &instructions[frame.first_body..epilogue_at] {
        match instruction.flow_control() {
            FlowControl::Call | FlowControl::IndirectCall
                if instruction.mnemonic() == Mnemonic::Call =>
            {
                has_call = true;
                continue;
            }
            FlowControl::Next => {}
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if branch_targets
                    .binary_search_by_key(&instruction.near_branch_target(), Instruction::ip)
                    .is_err()
                {
                    return false;
                }
            }
            _ => return false,
        }
        if info.info(instruction).used_registers().iter().any(|reg| {
            reg.register().full_register() == Register::RSP
                && matches!(
                    reg.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
        }) {
            return false;
        }
    }
    has_call
}

fn check_epilogue(epilogue: &[Instruction], frame: &Frame) -> bool {
    if !stack_adjust(&epilogue[0], Mnemonic::Add, frame.allocation) {
        return false;
    }
    for (instruction, &register) in epilogue[1..].iter().zip(frame.saved.iter().rev()) {
        if instruction.mnemonic() != Mnemonic::Pop || instruction.op0_register() != register {
            return false;
        }
    }
    let last = &epilogue[epilogue.len() - 1];
    last.mnemonic() == Mnemonic::Ret && last.op_count() == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> PeImage {
        let mut image = parse(&crate::sample::build().unwrap().bytes).unwrap();
        let text = &mut image.sections[0].bytes;
        // sub rsp,0x28; call +0x17; add rsp,0x28; ret
        text[..14].copy_from_slice(&[
            0x48, 0x83, 0xec, 0x28, 0xe8, 0x17, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ]);
        let mut table = vec![0; 0x40];
        for (slot, value) in table
            .chunks_exact_mut(4)
            .zip([0x1000u32, 0x100e, 0x3020, 0x1020, 0x1021, 0x3028])
        {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        table[0x20..0x28].copy_from_slice(&[1, 4, 1, 0, 4, 0x42, 0, 0]);
        table[0x28] = 1;
        image.sections.push(Section {
            name: ".pdata".into(),
            rva: 0x3000,
            bytes: table,
            characteristics: CH_RDATA,
        });
        image.exception_rva = 0x3000;
        image.exception_size = 24;
        image
    }

    #[test]
    fn native_bridge_publishes_a_sorted_table_and_keeps_unrelated_unwind() {
        let mut image = image();
        let plan = NativeUnwind::plan(&image, [(0x1000, 14)], [], false).unwrap();
        image.sections.push(Section {
            name: ".bridge".into(),
            rva: 0x4000,
            bytes: vec![0x90; 0x40],
            characteristics: CH_TEXT,
        });
        assert!(plan
            .publish(&mut image, &[(0x1000, 0x4000, 0x4009)], Some(0x4020), &[])
            .is_err());
        write_rva(
            &mut image,
            0x4000,
            &[0x41, 0xff, 0xd3, 0x90, 0xe9, 7, 0, 0, 0],
        )
        .unwrap();
        plan.publish(&mut image, &[(0x1000, 0x4000, 0x4009)], Some(0x4020), &[])
            .unwrap();
        let entries = unwind_entries(&image).unwrap();
        assert_eq!(
            entries,
            [(0x1020, 0x1021, 0x3028), (0x4000, 0x4009, 0x5018)]
        );
        assert_eq!(
            read_rva(&image, 0x5018, 12).unwrap(),
            &[0x11, 0, 1, 0, 0, 0x42, 0, 0, 0x20, 0x40, 0, 0],
        );
        assert_eq!(image.sections.last().unwrap().characteristics, CH_RDATA);
    }

    #[test]
    fn native_cfg_rejects_unwind_for_a_selected_function() {
        let image = image();
        let Err(error) = NativeUnwind::plan(&image, [(0x1000, 14)], [], true) else {
            panic!("guarded selection unexpectedly required a native unwind bridge");
        };
        assert!(
            error.to_string().contains("CFG requires leaf selections"),
            "{error}"
        );
    }

    #[test]
    fn native_bridge_refuses_source_handlers_and_forged_unwind() {
        let mut handler = image();
        write_rva(&mut handler, 0x3020, &[9]).unwrap();
        assert!(NativeUnwind::plan(&handler, [(0x1000, 14)], [], false).is_err());

        let mut changed = image();
        write_rva(&mut changed, 0x1003, &[0x20]).unwrap();
        assert!(NativeUnwind::plan(&changed, [(0x1000, 14)], [], false).is_err());
        assert!(NativeUnwind::plan(&image(), [(0x1000, 9)], [], false).is_err());
        assert!(NativeUnwind::plan(&image(), [(0x1000, 15)], [], false).is_err());
        assert!(NativeUnwind::plan(&image(), [], [(0x1000, 14)], false).is_err());
    }
}
