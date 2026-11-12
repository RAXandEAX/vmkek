//! ELF `.eh_frame` and the trampoline correspondence.
//!
//! A jump trampoline does not retire the original prologue. The FDE for the
//! replaced range keeps the instructions that apply at offset 0 and replaces
//! every later advance with `DW_CFA_nop`, so the whole range unwinds as the
//! original program counter 0. The logical table still records the original
//! row at each advance. Personality and LSDA bytes are left in place.

use std::collections::BTreeMap;

use crate::elf::{ElfImage, Section};
use crate::error::{msg, Result};

use super::row::{self, Cfa, Row, Slot};
use super::{Correspondence, FrameLink};

const DW_RSP: u16 = 7;

#[derive(Clone, Copy, Debug)]
enum Rule {
    Offset(i64),
    ValOffset(i64),
    Same,
    Undefined,
    Register(u16),
}

#[derive(Clone, Debug)]
struct Snap {
    cfa_reg: u16,
    cfa_off: i64,
    cfa_set: bool,
    cfa_opaque: bool,
    regs: BTreeMap<u16, Rule>,
}

#[derive(Clone, Debug)]
struct State {
    cfa_reg: u16,
    cfa_off: i64,
    cfa_set: bool,
    cfa_opaque: bool,
    regs: BTreeMap<u16, Rule>,
    stack: Vec<Snap>,
}

impl State {
    fn blank() -> Self {
        Self {
            cfa_reg: 0,
            cfa_off: 0,
            cfa_set: false,
            cfa_opaque: false,
            regs: BTreeMap::new(),
            stack: Vec::new(),
        }
    }

    fn snap(&self) -> Snap {
        Snap {
            cfa_reg: self.cfa_reg,
            cfa_off: self.cfa_off,
            cfa_set: self.cfa_set,
            cfa_opaque: self.cfa_opaque,
            regs: self.regs.clone(),
        }
    }

    fn restore(&mut self, snap: Snap) {
        self.cfa_reg = snap.cfa_reg;
        self.cfa_off = snap.cfa_off;
        self.cfa_set = snap.cfa_set;
        self.cfa_opaque = snap.cfa_opaque;
        self.regs = snap.regs;
    }
}

struct Cie {
    encoding: u8,
    has_z: bool,
    addr_size: usize,
    code_align: u64,
    data_align: i64,
    ret: u16,
    personality: Option<u64>,
    initial: State,
}

struct Fde {
    start: u64,
    end: u64,
    insn: usize,
    insn_end: usize,
    cie: usize,
}

struct Image {
    cies: Vec<(usize, Cie)>,
    fdes: Vec<Fde>,
}

/// Row of the FDE that covers `pc`.
pub(crate) fn row_at(bytes: &[u8], frame_va: u64, pc: u64) -> Result<Row> {
    let image = parse(bytes, frame_va)?;
    let fde = image
        .fdes
        .iter()
        .find(|fde| pc >= fde.start && pc < fde.end)
        .ok_or_else(|| msg(format!("no eh_frame fde covers {pc:#x}")))?;
    let cie = &image.cies[fde.cie].1;
    eval(bytes, frame_va, cie, fde, pc)
}

/// Hold each covered FDE at its offset-0 row across the whole function.
pub(crate) fn rewrite(
    bytes: &mut [u8],
    frame_va: u64,
    start: u64,
    end: u64,
) -> Result<Vec<Correspondence>> {
    let image = parse(bytes, frame_va)?;
    let mut chosen = Vec::new();
    for fde in &image.fdes {
        if fde.end <= start || fde.start >= end {
            continue;
        }
        if fde.start < start || fde.end > end {
            return Err(msg("eh_frame overlaps a neighbor of the trampoline"));
        }
        chosen.push(fde);
    }
    let mut plan = Vec::new();
    for fde in chosen {
        let cie = &image.cies[fde.cie].1;
        let corr = correspond(bytes, frame_va, cie, fde)?;
        let cut = first_advance(bytes, frame_va, cie, fde)?;
        plan.push((cut, fde.insn_end, corr));
    }
    for (cut, insn_end, _) in &plan {
        if let Some(cut) = cut {
            for byte in &mut bytes[*cut..*insn_end] {
                *byte = 0;
            }
        }
    }
    Ok(plan.into_iter().map(|(_, _, corr)| corr).collect())
}

/// Rewrite `.eh_frame` on a parsed image. No section means there is nothing to preserve.
pub(crate) fn preserve(image: &mut ElfImage, start: u64, end: u64) -> Result<Vec<Correspondence>> {
    let Some(index) = image
        .sections
        .iter()
        .position(|section| section.name == ".eh_frame")
    else {
        return Ok(Vec::new());
    };
    if image.sections[index].bytes_omitted {
        return Err(msg("eh_frame bytes were omitted"));
    }
    let frame_va = image.sections[index].addr;
    let bytes = &mut section_bytes(image, index)?.bytes;
    rewrite(bytes, frame_va, start, end)
}

fn section_bytes(image: &mut ElfImage, index: usize) -> Result<&mut Section> {
    image
        .sections
        .get_mut(index)
        .ok_or_else(|| msg("eh_frame section is missing"))
}

fn correspond(bytes: &[u8], frame_va: u64, cie: &Cie, fde: &Fde) -> Result<Correspondence> {
    let len = u32::try_from(fde.end - fde.start).map_err(|_| msg("eh_frame range is too large"))?;
    let mut offsets = vec![0];
    collect_moves(bytes, frame_va, cie, fde, &mut offsets)?;
    if len > 1 {
        offsets.push(len - 1);
    }
    offsets.retain(|offset| *offset < len);
    offsets.sort_unstable();
    offsets.dedup();
    let entry = eval(bytes, frame_va, cie, fde, fde.start)?;
    let mut logical = Vec::new();
    let mut native = Vec::new();
    for offset in offsets {
        let row = eval(bytes, frame_va, cie, fde, fde.start + u64::from(offset))?;
        logical.push(FrameLink {
            trampoline_at: offset,
            original_at: offset,
            row,
        });
        native.push(FrameLink {
            trampoline_at: offset,
            original_at: 0,
            row: entry.clone(),
        });
    }
    Ok(Correspondence {
        format: "elf",
        start: fde.start,
        end: fde.end,
        handler: cie.personality,
        chain: None,
        chain_on_native: false,
        native,
        logical,
    })
}

fn collect_moves(
    bytes: &[u8],
    frame_va: u64,
    cie: &Cie,
    fde: &Fde,
    offsets: &mut Vec<u32>,
) -> Result<()> {
    let mut state = cie.initial.clone();
    let mut loc = fde.start;
    let mut ip = fde.insn;
    while ip < fde.insn_end {
        if advance_op(bytes[ip]) {
            let (next_loc, next) = take_advance(bytes, frame_va, cie, loc, ip, fde.insn_end)?;
            if next_loc > fde.start {
                if let Ok(offset) = u32::try_from(next_loc - fde.start) {
                    offsets.push(offset);
                }
            }
            loc = next_loc;
            ip = next;
        } else {
            ip = apply(bytes, cie, &mut state, ip, fde.insn_end)?;
        }
    }
    Ok(())
}

fn first_advance(bytes: &[u8], _frame_va: u64, cie: &Cie, fde: &Fde) -> Result<Option<usize>> {
    let mut state = cie.initial.clone();
    let mut ip = fde.insn;
    while ip < fde.insn_end {
        if advance_op(bytes[ip]) {
            return Ok(Some(ip));
        }
        ip = apply(bytes, cie, &mut state, ip, fde.insn_end)?;
    }
    Ok(None)
}

fn eval(bytes: &[u8], frame_va: u64, cie: &Cie, fde: &Fde, pc: u64) -> Result<Row> {
    let mut state = cie.initial.clone();
    let mut loc = fde.start;
    let mut ip = fde.insn;
    while ip < fde.insn_end {
        if advance_op(bytes[ip]) {
            let (next_loc, next) = take_advance(bytes, frame_va, cie, loc, ip, fde.insn_end)?;
            if next_loc > pc {
                break;
            }
            loc = next_loc;
            ip = next;
        } else if loc > pc {
            break;
        } else {
            ip = apply(bytes, cie, &mut state, ip, fde.insn_end)?;
        }
    }
    Ok(snapshot(&state, cie.ret))
}

fn snapshot(state: &State, ret: u16) -> Row {
    let cfa = if state.cfa_opaque || !state.cfa_set {
        Cfa::Opaque
    } else if state.cfa_reg == DW_RSP {
        Cfa::Sp(state.cfa_off)
    } else {
        Cfa::Reg {
            reg: row::dwarf_reg(state.cfa_reg),
            disp: state.cfa_off,
        }
    };
    let mut saved = BTreeMap::new();
    for (reg, rule) in &state.regs {
        if *reg == ret {
            continue;
        }
        let slot = slot_of(*rule);
        if !matches!(slot, Slot::Same) {
            saved.insert(row::dwarf_reg(*reg), slot);
        }
    }
    let rip = state
        .regs
        .get(&ret)
        .copied()
        .map(slot_of)
        .unwrap_or(Slot::Same);
    Row { cfa, saved, rip }
}

fn slot_of(rule: Rule) -> Slot {
    match rule {
        Rule::Offset(disp) => Slot::AtCfa(disp),
        Rule::ValOffset(disp) => Slot::ValueAtCfa(disp),
        Rule::Same => Slot::Same,
        Rule::Undefined => Slot::Undefined,
        Rule::Register(reg) => Slot::InReg(row::dwarf_reg(reg)),
    }
}

fn parse(bytes: &[u8], frame_va: u64) -> Result<Image> {
    let mut cies = Vec::new();
    let mut fdes = Vec::new();
    let mut cursor = 0;
    while cursor + 4 <= bytes.len() {
        let (body, end, id_size) = record(bytes, cursor)?;
        if end == body {
            break;
        }
        let id = read_id(bytes, body, id_size)?;
        if id == 0 {
            cies.push((cursor, read_cie(bytes, frame_va, body + id_size, end)?));
        } else {
            let cie_at = body
                .checked_sub(
                    usize::try_from(id).map_err(|_| msg("eh_frame cie pointer is invalid"))?,
                )
                .ok_or_else(|| msg("eh_frame cie pointer is invalid"))?;
            let cie_index = cies
                .iter()
                .position(|(start, _)| *start == cie_at)
                .ok_or_else(|| msg("eh_frame fde points at a missing cie"))?;
            fdes.push(read_fde(
                bytes,
                frame_va,
                &cies[cie_index].1,
                body + id_size,
                end,
                cie_index,
            )?);
        }
        cursor = end;
    }
    Ok(Image { cies, fdes })
}

fn record(bytes: &[u8], start: usize) -> Result<(usize, usize, usize)> {
    let len32 = u32_at(bytes, start)?;
    if len32 == 0 {
        return Ok((start, start, 4));
    }
    if len32 == 0xffff_ffff {
        if start + 12 > bytes.len() {
            return Err(msg("eh_frame record is truncated"));
        }
        let len = u64_at(bytes, start + 4)?;
        let body = start + 12;
        let end = body
            .checked_add(usize::try_from(len).map_err(|_| msg("eh_frame record is too large"))?)
            .ok_or_else(|| msg("eh_frame record is too large"))?;
        if end > bytes.len() {
            return Err(msg("eh_frame record is truncated"));
        }
        return Ok((body, end, 8));
    }
    let body = start + 4;
    let end = body
        .checked_add(len32 as usize)
        .ok_or_else(|| msg("eh_frame record is too large"))?;
    if end > bytes.len() {
        return Err(msg("eh_frame record is truncated"));
    }
    Ok((body, end, 4))
}

fn read_cie(bytes: &[u8], frame_va: u64, mut ip: usize, end: usize) -> Result<Cie> {
    if ip >= end {
        return Err(msg("eh_frame cie is truncated"));
    }
    let version = bytes[ip];
    ip += 1;
    if version != 1 && version != 3 && version != 4 {
        return Err(msg("eh_frame cie version is not supported"));
    }
    let aug = cstr(bytes, &mut ip, end)?;
    let addr_size = cie_addr_size(bytes, version, &mut ip, end)?;
    let code_align = uleb(bytes, &mut ip, end)?;
    let data_align = sleb(bytes, &mut ip, end)?;
    let ret = cie_return_reg(bytes, version, &mut ip, end)?;
    let decoded = decode_aug(bytes, frame_va, &mut ip, end, aug, addr_size, true)?;
    let mut state = State::blank();
    let cie = Cie {
        encoding: decoded.encoding,
        has_z: aug.starts_with('z'),
        addr_size,
        code_align,
        data_align,
        ret,
        personality: decoded.personality,
        initial: State::blank(),
    };
    walk_cie(bytes, frame_va, &cie, &mut state, ip, end)?;
    Ok(Cie {
        initial: state,
        ..cie
    })
}

fn cie_addr_size(bytes: &[u8], version: u8, ip: &mut usize, end: usize) -> Result<usize> {
    if version < 4 {
        return Ok(8);
    }
    if *ip + 2 > end {
        return Err(msg("eh_frame cie is truncated"));
    }
    let addr_size = usize::from(bytes[*ip]);
    *ip += 2;
    if addr_size != 4 && addr_size != 8 {
        return Err(msg("eh_frame address size is not supported"));
    }
    Ok(addr_size)
}

fn cie_return_reg(bytes: &[u8], version: u8, ip: &mut usize, end: usize) -> Result<u16> {
    if version == 1 {
        if *ip >= end {
            return Err(msg("eh_frame cie is truncated"));
        }
        let reg = u16::from(bytes[*ip]);
        *ip += 1;
        return Ok(reg);
    }
    u16::try_from(uleb(bytes, ip, end)?).map_err(|_| msg("eh_frame register is too large"))
}

fn walk_cie(
    bytes: &[u8],
    frame_va: u64,
    cie: &Cie,
    state: &mut State,
    mut ip: usize,
    end: usize,
) -> Result<()> {
    while ip < end {
        if advance_op(bytes[ip]) {
            let (_, next) = take_advance(bytes, frame_va, cie, 0, ip, end)?;
            ip = next;
        } else {
            ip = apply(bytes, cie, state, ip, end)?;
        }
    }
    Ok(())
}

fn read_fde(
    bytes: &[u8],
    frame_va: u64,
    cie: &Cie,
    mut ip: usize,
    end: usize,
    cie_index: usize,
) -> Result<Fde> {
    let start = read_pointer(
        bytes,
        frame_va,
        &mut ip,
        end,
        cie.encoding,
        cie.addr_size,
        false,
    )?;
    let range = read_pointer(
        bytes,
        frame_va,
        &mut ip,
        end,
        cie.encoding & 0x0f,
        cie.addr_size,
        false,
    )?;
    if range > u64::MAX / 2 {
        return Err(msg("eh_frame range is negative"));
    }
    if cie.has_z {
        let _ = decode_aug(bytes, frame_va, &mut ip, end, "z", cie.addr_size, false)?;
    }
    Ok(Fde {
        start,
        end: start
            .checked_add(range)
            .ok_or_else(|| msg("eh_frame range overflows"))?,
        insn: ip,
        insn_end: end,
        cie: cie_index,
    })
}

struct Aug {
    encoding: u8,
    personality: Option<u64>,
}

fn decode_aug(
    bytes: &[u8],
    frame_va: u64,
    ip: &mut usize,
    end: usize,
    aug: &str,
    addr_size: usize,
    cie: bool,
) -> Result<Aug> {
    if aug.is_empty() {
        return Ok(Aug {
            encoding: 0,
            personality: None,
        });
    }
    if !aug.starts_with('z') {
        return Err(msg("eh_frame augmentation has no length"));
    }
    let len = usize::try_from(uleb(bytes, ip, end)?)
        .map_err(|_| msg("eh_frame augmentation is too large"))?;
    let stop = ip
        .checked_add(len)
        .ok_or_else(|| msg("eh_frame augmentation is too large"))?;
    if stop > end {
        return Err(msg("eh_frame augmentation is truncated"));
    }
    let mut decoded = Aug {
        encoding: 0,
        personality: None,
    };
    if cie {
        read_aug_letters(bytes, frame_va, ip, stop, aug, addr_size, &mut decoded)?;
    }
    *ip = stop;
    Ok(decoded)
}

fn read_aug_letters(
    bytes: &[u8],
    frame_va: u64,
    ip: &mut usize,
    stop: usize,
    aug: &str,
    addr_size: usize,
    decoded: &mut Aug,
) -> Result<()> {
    for ch in aug.chars().skip(1) {
        if *ip >= stop {
            break;
        }
        match ch {
            'L' => *ip += 1,
            'P' => {
                decoded.personality = Some(read_personality(bytes, frame_va, ip, stop, addr_size)?)
            }
            'R' => {
                decoded.encoding = bytes[*ip];
                *ip += 1;
            }
            'S' => {}
            _ => {
                return Err(msg(format!(
                    "eh_frame augmentation '{ch}' is not supported"
                )));
            }
        }
    }
    Ok(())
}

fn read_personality(
    bytes: &[u8],
    frame_va: u64,
    ip: &mut usize,
    stop: usize,
    addr_size: usize,
) -> Result<u64> {
    if *ip >= stop {
        return Err(msg("eh_frame personality is truncated"));
    }
    let penc = bytes[*ip];
    *ip += 1;
    read_pointer(bytes, frame_va, ip, stop, penc, addr_size, true)
}

fn advance_op(op: u8) -> bool {
    op == 0x01 || op == 0x02 || op == 0x03 || op == 0x04 || op & 0xc0 == 0x40
}

fn take_advance(
    bytes: &[u8],
    frame_va: u64,
    cie: &Cie,
    loc: u64,
    ip: usize,
    end: usize,
) -> Result<(u64, usize)> {
    let op = *bytes
        .get(ip)
        .ok_or_else(|| msg("eh_frame instruction is truncated"))?;
    if op & 0xc0 == 0x40 {
        let delta = u64::from(op & 0x3f);
        return Ok((bump(loc, delta, cie.code_align)?, ip + 1));
    }
    let mut cursor = ip + 1;
    if op == 0x01 {
        let loc = read_pointer(
            bytes,
            frame_va,
            &mut cursor,
            end,
            cie.encoding,
            cie.addr_size,
            false,
        )?;
        return Ok((loc, cursor));
    }
    let delta = advance_delta(bytes, op, &mut cursor, end)?;
    Ok((bump(loc, delta, cie.code_align)?, cursor))
}

fn advance_delta(bytes: &[u8], op: u8, cursor: &mut usize, end: usize) -> Result<u64> {
    let delta = match op {
        0x02 => {
            let value = need(bytes, *cursor, end, 1)?;
            *cursor += 1;
            u64::from(value)
        }
        0x03 => {
            let value = u16::from_le_bytes([
                need(bytes, *cursor, end, 1)?,
                need(bytes, *cursor + 1, end, 1)?,
            ]);
            *cursor += 2;
            u64::from(value)
        }
        0x04 => {
            let value = u32_at(bytes, *cursor)?;
            *cursor += 4;
            u64::from(value)
        }
        _ => return Err(msg("eh_frame advance is malformed")),
    };
    Ok(delta)
}

fn bump(loc: u64, delta: u64, align: u64) -> Result<u64> {
    let step = delta
        .checked_mul(align)
        .ok_or_else(|| msg("eh_frame advance overflows"))?;
    loc.checked_add(step)
        .ok_or_else(|| msg("eh_frame advance overflows"))
}

fn apply(bytes: &[u8], cie: &Cie, state: &mut State, ip: usize, end: usize) -> Result<usize> {
    if ip >= end || ip >= bytes.len() {
        return Err(msg("eh_frame instruction is truncated"));
    }
    let op = bytes[ip];
    let mut cursor = ip + 1;
    if op & 0xc0 == 0x80 {
        let reg = u16::from(op & 0x3f);
        let fact = uleb_i64(bytes, &mut cursor, end)?;
        state
            .regs
            .insert(reg, Rule::Offset(scale(fact, cie.data_align)?));
        return Ok(cursor);
    }
    if op & 0xc0 == 0xc0 {
        let reg = u16::from(op & 0x3f);
        state.regs.insert(reg, saved_rule(&cie.initial, reg));
        return Ok(cursor);
    }
    // An expression is a concrete frame this model does not evaluate. One
    // shared opaque row would compare different frames as equal.
    if matches!(op, 0x0f | 0x10 | 0x16) {
        return Err(msg("eh_frame expression is not supported"));
    }
    match op {
        0x00 | 0x0a | 0x0b | 0x2e => apply_stack(bytes, state, op, &mut cursor, end)?,
        0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x11 | 0x14 | 0x15 | 0x2f => {
            apply_reg(bytes, cie, state, op, &mut cursor, end)?;
        }
        0x0c | 0x0d | 0x0e | 0x12 | 0x13 => apply_cfa(bytes, cie, state, op, &mut cursor, end)?,
        other => return Err(msg(format!("eh_frame opcode {other:#x} is not supported"))),
    }
    Ok(cursor)
}

fn saved_rule(state: &State, reg: u16) -> Rule {
    state.regs.get(&reg).copied().unwrap_or(Rule::Same)
}

fn apply_reg(
    bytes: &[u8],
    cie: &Cie,
    state: &mut State,
    op: u8,
    cursor: &mut usize,
    end: usize,
) -> Result<()> {
    let reg = reg_no(bytes, cursor, end)?;
    let rule = match op {
        0x05 => Rule::Offset(scale(uleb_i64(bytes, cursor, end)?, cie.data_align)?),
        0x06 => saved_rule(&cie.initial, reg),
        0x07 => Rule::Undefined,
        0x08 => Rule::Same,
        0x09 => Rule::Register(reg_no(bytes, cursor, end)?),
        0x11 => Rule::Offset(scale(sleb(bytes, cursor, end)?, cie.data_align)?),
        0x14 => Rule::ValOffset(scale(uleb_i64(bytes, cursor, end)?, cie.data_align)?),
        0x15 => Rule::ValOffset(scale(sleb(bytes, cursor, end)?, cie.data_align)?),
        0x2f => Rule::Offset(scale(-uleb_i64(bytes, cursor, end)?, cie.data_align)?),
        other => return Err(msg(format!("eh_frame opcode {other:#x} is not supported"))),
    };
    state.regs.insert(reg, rule);
    Ok(())
}

fn apply_cfa(
    bytes: &[u8],
    cie: &Cie,
    state: &mut State,
    op: u8,
    cursor: &mut usize,
    end: usize,
) -> Result<()> {
    match op {
        0x0c => {
            state.cfa_reg = reg_no(bytes, cursor, end)?;
            state.cfa_off = uleb_i64(bytes, cursor, end)?;
            clear_cfa(state);
        }
        0x0d => {
            state.cfa_reg = reg_no(bytes, cursor, end)?;
            state.cfa_set = true;
        }
        0x0e => {
            state.cfa_off = uleb_i64(bytes, cursor, end)?;
            clear_cfa(state);
        }
        0x12 => {
            state.cfa_reg = reg_no(bytes, cursor, end)?;
            state.cfa_off = scale(sleb(bytes, cursor, end)?, cie.data_align)?;
            clear_cfa(state);
        }
        0x13 => {
            state.cfa_off = scale(sleb(bytes, cursor, end)?, cie.data_align)?;
            clear_cfa(state);
        }
        other => return Err(msg(format!("eh_frame opcode {other:#x} is not supported"))),
    }
    Ok(())
}

fn clear_cfa(state: &mut State) {
    state.cfa_set = true;
    state.cfa_opaque = false;
}

fn apply_stack(
    bytes: &[u8],
    state: &mut State,
    op: u8,
    cursor: &mut usize,
    end: usize,
) -> Result<()> {
    match op {
        0x00 => {}
        0x0a => state.stack.push(state.snap()),
        0x0b => {
            let snap = state
                .stack
                .pop()
                .ok_or_else(|| msg("eh_frame restore has no remembered state"))?;
            state.restore(snap);
        }
        0x2e => {
            let _ = uleb(bytes, cursor, end)?;
        }
        other => return Err(msg(format!("eh_frame opcode {other:#x} is not supported"))),
    }
    Ok(())
}

fn scale(fact: i64, align: i64) -> Result<i64> {
    fact.checked_mul(align)
        .ok_or_else(|| msg("eh_frame offset overflows"))
}

fn reg_no(bytes: &[u8], ip: &mut usize, end: usize) -> Result<u16> {
    u16::try_from(uleb(bytes, ip, end)?).map_err(|_| msg("eh_frame register is too large"))
}

fn read_pointer(
    bytes: &[u8],
    frame_va: u64,
    ip: &mut usize,
    end: usize,
    enc: u8,
    addr_size: usize,
    allow_indirect: bool,
) -> Result<u64> {
    if enc == 0xff {
        return Ok(0);
    }
    let indirect = enc & 0x80 != 0;
    if indirect && !allow_indirect {
        return Err(msg("eh_frame address is indirect"));
    }
    let field = frame_va + u64::try_from(*ip).map_err(|_| msg("eh_frame pointer overflows"))?;
    let fmt = enc & 0x0f;
    let app = enc & 0x70;
    let (value, signed) = match fmt {
        0x00 => (read_n(bytes, ip, end, addr_size)?, false),
        0x01 => (uleb(bytes, ip, end)?, false),
        0x02 => (u64::from(read_u16(bytes, ip, end)?), false),
        0x03 => (u64::from(read_u32(bytes, ip, end)?), false),
        0x04 => (read_n(bytes, ip, end, 8)?, false),
        0x09 => (sleb(bytes, ip, end)? as u64, true),
        0x0a => (i64::from(read_u16(bytes, ip, end)? as i16) as u64, true),
        0x0b => (i64::from(read_u32(bytes, ip, end)? as i32) as u64, true),
        0x0c => (read_n(bytes, ip, end, 8)?, true),
        _ => return Err(msg("eh_frame pointer encoding is not supported")),
    };
    let base = match app {
        0x00 => 0,
        0x10 => field,
        _ => return Err(msg("eh_frame pointer application is not supported")),
    };
    let _ = signed;
    Ok(base.wrapping_add(value))
}

fn read_n(bytes: &[u8], ip: &mut usize, end: usize, size: usize) -> Result<u64> {
    if size == 4 {
        return Ok(u64::from(read_u32(bytes, ip, end)?));
    }
    if size != 8 {
        return Err(msg("eh_frame address size is not supported"));
    }
    if *ip + 8 > end {
        return Err(msg("eh_frame pointer is truncated"));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[*ip..*ip + 8]);
    *ip += 8;
    Ok(u64::from_le_bytes(buf))
}

fn read_u16(bytes: &[u8], ip: &mut usize, end: usize) -> Result<u16> {
    if *ip + 2 > end {
        return Err(msg("eh_frame pointer is truncated"));
    }
    let value = u16::from_le_bytes([bytes[*ip], bytes[*ip + 1]]);
    *ip += 2;
    Ok(value)
}

fn read_u32(bytes: &[u8], ip: &mut usize, end: usize) -> Result<u32> {
    if *ip + 4 > end {
        return Err(msg("eh_frame pointer is truncated"));
    }
    let value = u32_at(bytes, *ip)?;
    *ip += 4;
    Ok(value)
}

fn cstr<'a>(bytes: &'a [u8], ip: &mut usize, end: usize) -> Result<&'a str> {
    let start = *ip;
    while *ip < end && bytes[*ip] != 0 {
        *ip += 1;
    }
    if *ip >= end {
        return Err(msg("eh_frame augmentation is truncated"));
    }
    let text = std::str::from_utf8(&bytes[start..*ip])
        .map_err(|_| msg("eh_frame augmentation is not utf-8"))?;
    *ip += 1;
    Ok(text)
}

fn uleb(bytes: &[u8], ip: &mut usize, end: usize) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0;
    for _ in 0..10 {
        if *ip >= end {
            return Err(msg("eh_frame uleb is truncated"));
        }
        let byte = bytes[*ip];
        *ip += 1;
        if shift == 63 && byte > 1 {
            return Err(msg("eh_frame uleb overflows"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(msg("eh_frame uleb overflows"))
}

fn uleb_i64(bytes: &[u8], ip: &mut usize, end: usize) -> Result<i64> {
    let value = uleb(bytes, ip, end)?;
    i64::try_from(value).map_err(|_| msg("eh_frame offset overflows"))
}

fn sleb(bytes: &[u8], ip: &mut usize, end: usize) -> Result<i64> {
    let mut value = 0i64;
    let mut shift = 0;
    for _ in 0..10 {
        if *ip >= end {
            return Err(msg("eh_frame sleb is truncated"));
        }
        let byte = bytes[*ip];
        *ip += 1;
        value |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                value |= !0i64 << shift;
            }
            return Ok(value);
        }
    }
    Err(msg("eh_frame sleb overflows"))
}

fn need(bytes: &[u8], ip: usize, end: usize, _n: usize) -> Result<u8> {
    bytes
        .get(ip)
        .copied()
        .filter(|_| ip < end)
        .ok_or_else(|| msg("eh_frame instruction is truncated"))
}

fn u32_at(bytes: &[u8], off: usize) -> Result<u32> {
    let chunk = bytes
        .get(off..off + 4)
        .ok_or_else(|| msg("eh_frame record is truncated"))?;
    Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

fn u64_at(bytes: &[u8], off: usize) -> Result<u64> {
    let chunk = bytes
        .get(off..off + 8)
        .ok_or_else(|| msg("eh_frame record is truncated"))?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(chunk);
    Ok(u64::from_le_bytes(buf))
}

fn read_id(bytes: &[u8], off: usize, size: usize) -> Result<u64> {
    if size == 8 {
        u64_at(bytes, off)
    } else {
        Ok(u64::from(u32_at(bytes, off)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf;
    use crate::unwind::row::{entry_row, Reg};

    fn uleb_bytes(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn sleb_bytes(mut value: i64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value as u8) & 0x7f;
            value >>= 7;
            let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
            out.push(if done { byte } else { byte | 0x80 });
            if done {
                break;
            }
        }
        out
    }

    fn fixture() -> (Vec<u8>, u64, u64, u64) {
        let frame = 0x4000u64;
        let func = 0x1000u64;
        let (cie, pers_at) = fixture_cie();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(cie.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&cie);
        plant_rel(&mut bytes, 4 + pers_at, frame, 0x3000);
        let (fde, pc_at, lsda_at) = fixture_fde(0x40);
        bytes.extend_from_slice(&(fde.len() as u32).to_le_bytes());
        let cie_ptr_at = bytes.len();
        bytes.extend_from_slice(&fde);
        bytes[cie_ptr_at..cie_ptr_at + 4].copy_from_slice(&(cie_ptr_at as u32).to_le_bytes());
        plant_rel(&mut bytes, cie_ptr_at + pc_at, frame, func);
        plant_rel(&mut bytes, cie_ptr_at + lsda_at, frame, 0x3500);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        (bytes, frame, func, func + 0x40)
    }

    fn plant_rel(bytes: &mut [u8], off: usize, frame: u64, target: u64) {
        let rel = target as i64 - (frame + off as u64) as i64;
        bytes[off..off + 4].copy_from_slice(&(rel as i32).to_le_bytes());
    }

    fn fixture_cie() -> (Vec<u8>, usize) {
        let mut cie = Vec::new();
        cie.extend_from_slice(&0u32.to_le_bytes());
        cie.push(1);
        cie.extend_from_slice(b"zLPR\0");
        cie.extend(uleb_bytes(1));
        cie.extend(sleb_bytes(-8));
        cie.push(16);
        let aug_at = cie.len();
        cie.push(0);
        cie.push(0x1b);
        cie.push(0x1b);
        let pers_at = cie.len();
        cie.extend_from_slice(&[0; 4]);
        cie.push(0x1b);
        cie[aug_at] = (cie.len() - aug_at - 1) as u8;
        cie.push(0x0c);
        cie.extend(uleb_bytes(7));
        cie.extend(uleb_bytes(8));
        cie.push(0x90);
        cie.extend(uleb_bytes(1));
        (cie, pers_at)
    }

    fn fixture_fde(func_len: u64) -> (Vec<u8>, usize, usize) {
        let mut fde = Vec::new();
        fde.extend_from_slice(&0u32.to_le_bytes());
        let pc_at = fde.len();
        fde.extend_from_slice(&0i32.to_le_bytes());
        fde.extend_from_slice(&(func_len as u32).to_le_bytes());
        fde.push(4);
        let lsda_at = fde.len();
        fde.extend_from_slice(&0i32.to_le_bytes());
        fde.push(0x0e);
        fde.extend(uleb_bytes(16));
        fde.push(0x02);
        fde.push(8);
        fde.push(0x0e);
        fde.extend(uleb_bytes(32));
        fde.push(0x86);
        fde.extend(uleb_bytes(2));
        (fde, pc_at, lsda_at)
    }

    fn push_fde_insn(bytes: &mut Vec<u8>, extra: &[u8]) {
        let cie_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let fde_len_at = 4 + cie_len;
        let fde_len = u32::from_le_bytes(bytes[fde_len_at..fde_len_at + 4].try_into().unwrap());
        let term = bytes.len() - 4;
        bytes.splice(term..term, extra.iter().copied());
        let new_len = fde_len + extra.len() as u32;
        bytes[fde_len_at..fde_len_at + 4].copy_from_slice(&new_len.to_le_bytes());
    }

    fn cie_with_aug(aug: &[u8], aug_data: &[u8]) -> Vec<u8> {
        let mut cie = Vec::new();
        cie.extend_from_slice(&0u32.to_le_bytes());
        cie.push(1);
        cie.extend_from_slice(aug);
        cie.push(0);
        cie.extend(uleb_bytes(1));
        cie.extend(sleb_bytes(-8));
        cie.push(16);
        cie.extend(uleb_bytes(aug_data.len() as u64));
        cie.extend_from_slice(aug_data);
        cie.push(0x0c);
        cie.extend(uleb_bytes(7));
        cie.extend(uleb_bytes(8));
        cie.push(0x90);
        cie.extend(uleb_bytes(1));
        cie
    }

    #[test]
    fn unknown_augmentation_letter_is_an_error() {
        let frame = 0x4000u64;
        let func = 0x1000u64;
        let cie = cie_with_aug(b"zX", &[0x11]);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(cie.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&cie);
        let mut fde = Vec::new();
        fde.extend_from_slice(&0u32.to_le_bytes());
        fde.extend_from_slice(&func.to_le_bytes());
        fde.extend_from_slice(&0x40u64.to_le_bytes());
        fde.push(0);
        bytes.extend_from_slice(&(fde.len() as u32).to_le_bytes());
        let cie_ptr_at = bytes.len();
        bytes.extend_from_slice(&fde);
        bytes[cie_ptr_at..cie_ptr_at + 4].copy_from_slice(&(cie_ptr_at as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let frozen = bytes.clone();
        let err = rewrite(&mut bytes, frame, func, func + 0x40).unwrap_err();
        assert!(
            err.to_string()
                .contains("augmentation 'X' is not supported"),
            "{err}"
        );
        assert_eq!(bytes, frozen);
    }

    #[test]
    fn eh_frame_expression_is_not_supported() {
        for op in [0x0fu8, 0x10, 0x16] {
            let (mut bytes, frame, start, end) = fixture();
            push_fde_insn(&mut bytes, &[op]);
            let frozen = bytes.clone();
            let err = rewrite(&mut bytes, frame, start, end).unwrap_err();
            assert!(
                err.to_string()
                    .contains("eh_frame expression is not supported"),
                "{op:#x} {err}"
            );
            assert_eq!(bytes, frozen);
        }
    }

    #[test]
    fn synthetic_eh_frame_trampoline_matches_original_frame() {
        let (mut bytes, frame, start, end) = fixture();
        let entry = row_at(&bytes, frame, start).unwrap();
        let body = row_at(&bytes, frame, start + 8).unwrap();
        assert_eq!(entry.cfa, Cfa::Sp(16));
        assert_eq!(entry.rip, Slot::AtCfa(-8));
        assert!(!entry.saved.contains_key(&Reg::Rbp));
        assert_ne!(entry, entry_row());
        assert_eq!(body.cfa, Cfa::Sp(32));
        assert_eq!(body.saved.get(&Reg::Rbp), Some(&Slot::AtCfa(-16)));
        assert_ne!(body, entry);
        let frozen = bytes.clone();
        let corr = rewrite(&mut bytes, frame, start, end).unwrap();
        assert_eq!(corr.len(), 1);
        assert_eq!(corr[0].format, "elf");
        assert_eq!(corr[0].handler, Some(0x3000));
        assert!(corr[0].chain.is_none());
        assert!(!corr[0].chain_on_native);
        for link in &corr[0].logical {
            assert_eq!(link.trampoline_at, link.original_at);
            let expected = if link.original_at < 8 { &entry } else { &body };
            assert_eq!(&link.row, expected);
        }
        for link in &corr[0].native {
            assert_eq!(link.original_at, 0);
            assert_eq!(link.row, entry);
            assert_eq!(
                row_at(&bytes, frame, start + u64::from(link.trampoline_at)).unwrap(),
                entry
            );
        }
        assert!(corr[0].logical.iter().any(|link| link.row != entry));
        assert_eq!(row_at(&bytes, frame, end - 1).unwrap(), entry);
        let cut = bytes
            .iter()
            .zip(&frozen)
            .position(|(now, old)| now != old)
            .unwrap();
        assert_eq!(&bytes[..cut], &frozen[..cut]);
        assert!(bytes[cut..].iter().take_while(|byte| **byte == 0).count() > 0);
    }

    #[test]
    fn host_binary_eh_frame_holds_offset_zero() {
        let file = std::fs::read("/proc/self/exe").expect("host image");
        let image = elf::parse(&file).expect("E1 parses this host binary");
        let section = image.section(".eh_frame").expect("host .eh_frame");
        let start = usize::try_from(section.offset).unwrap();
        let len = usize::try_from(section.size).unwrap();
        let bytes = file[start..start + len].to_vec();
        let frame = section.addr;
        let parsed = parse(&bytes, frame).expect("host .eh_frame");
        let fde = parsed
            .fdes
            .iter()
            .find(|fde| fde.end > fde.start + 8)
            .expect("host fde");
        let before = row_at(&bytes, frame, fde.start).unwrap();
        let mut edited = bytes;
        let corr = rewrite(&mut edited, frame, fde.start, fde.end).unwrap();
        assert_eq!(corr[0].native[0].row, before);
        assert_eq!(row_at(&edited, frame, fde.start).unwrap(), before);
        assert_eq!(row_at(&edited, frame, fde.end - 1).unwrap(), before);
    }

    #[test]
    fn preserve_elf_rewrites_the_parsed_section() {
        let (eh, frame, start, end) = fixture();
        let file = elf_with(&eh);
        let mut image = elf::parse(&file).unwrap();
        let section = image.section(".eh_frame").unwrap();
        assert_eq!(section.addr, frame);
        assert!(!section.bytes_omitted);
        let corr = preserve(&mut image, start, end).unwrap();
        assert_eq!(corr.len(), 1);
        let bytes = &image.section(".eh_frame").unwrap().bytes;
        assert_eq!(row_at(bytes, frame, start).unwrap().cfa, Cfa::Sp(16));
        assert_eq!(row_at(bytes, frame, start + 8).unwrap().cfa, Cfa::Sp(16));
    }

    fn elf_with(eh: &[u8]) -> Vec<u8> {
        let mut names = vec![0u8];
        let eh_name = names.len() as u32;
        names.extend_from_slice(b".eh_frame\0");
        let str_name = names.len() as u32;
        names.extend_from_slice(b".shstrtab\0");
        let mut file = vec![0u8; 64];
        file[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        file[4] = 2;
        file[5] = 1;
        file[6] = 1;
        file[16..18].copy_from_slice(&1u16.to_le_bytes());
        file[18..20].copy_from_slice(&62u16.to_le_bytes());
        file[20..24].copy_from_slice(&1u32.to_le_bytes());
        file[52..54].copy_from_slice(&64u16.to_le_bytes());
        file[58..60].copy_from_slice(&64u16.to_le_bytes());
        let eh_off = file.len() as u64;
        file.extend_from_slice(eh);
        let str_off = file.len() as u64;
        file.extend_from_slice(&names);
        let shoff = (file.len() + 7) & !7;
        file.resize(shoff, 0);
        file.extend_from_slice(&shdr(0, 0, 0, 0, 0, 0, 0));
        file.extend_from_slice(&shdr(eh_name, 1, 2, 0x4000, eh_off, eh.len() as u64, 1));
        file.extend_from_slice(&shdr(str_name, 3, 0, 0, str_off, names.len() as u64, 1));
        file[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        file[60..62].copy_from_slice(&3u16.to_le_bytes());
        file[62..64].copy_from_slice(&2u16.to_le_bytes());
        file
    }

    fn shdr(
        name: u32,
        kind: u32,
        flags: u64,
        addr: u64,
        off: u64,
        size: u64,
        align: u64,
    ) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..4].copy_from_slice(&name.to_le_bytes());
        out[4..8].copy_from_slice(&kind.to_le_bytes());
        out[8..16].copy_from_slice(&flags.to_le_bytes());
        out[16..24].copy_from_slice(&addr.to_le_bytes());
        out[24..32].copy_from_slice(&off.to_le_bytes());
        out[32..40].copy_from_slice(&size.to_le_bytes());
        out[48..56].copy_from_slice(&align.to_le_bytes());
        out
    }
}
