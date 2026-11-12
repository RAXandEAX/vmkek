//! PE `.pdata` / `UNWIND_INFO` and the trampoline correspondence.
//!
//! The native trampoline is a jump at offset 0, so it does not execute the
//! original prologue. Every program counter in the replaced range therefore
//! unwinds as the original function at offset 0. The logical table keeps the
//! original row at each original offset. Chained unwind info stays attached:
//! Windows applies the whole chain even at offset 0.
//!
//! `UWOP_PUSH_MACHFRAME` is rejected. A machine frame is not a trampoline row,
//! for this legacy path. Native Win64 host-call bridges use separate metadata.

use std::collections::BTreeSet;

use crate::error::{msg, Result};
use crate::pe::{self, PeImage};

use super::row::{self, Cfa, Reg, Row, Slot};
use super::{Correspondence, FrameLink};

const CHAIN: u8 = 4;
const HANDLER: u8 = 3;
const MAX_TAIL: usize = 64 * 1024;
const MAX_CHAIN: usize = 32;
const TAIL_PAD: u32 = 16;

#[derive(Clone, Debug)]
struct Code {
    at: u8,
    op: u8,
    info: u8,
    extra: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Info {
    flags: u8,
    frame_reg: u8,
    frame_scaled: u8,
    ops: Vec<Code>,
    suffix: Vec<u8>,
}

struct Rt {
    begin: u32,
    end: u32,
    unwind: u32,
    index: usize,
}

struct Plan {
    index: usize,
    section: usize,
    bytes: Vec<u8>,
    corr: Correspondence,
}

struct Cursor {
    rsp: i64,
    saved: Vec<(Reg, i64)>,
    fp: Option<(Reg, i64)>,
}

/// Read the unwind row of the function that contains `pc_rva`.
pub(crate) fn row_at(image: &PeImage, pc_rva: u32) -> Result<Row> {
    let entries = entries(image)?;
    let hit = entries
        .iter()
        .find(|entry| pc_rva >= entry.begin && pc_rva < entry.end)
        .ok_or_else(|| msg(format!("no unwind entry covers rva {pc_rva:#x}")))?;
    let frames = load_chain(image, hit.unwind, &mut BTreeSet::new())?;
    eval(&frames, pc_rva - hit.begin)
}

/// Rewrite unwind metadata for a function replaced by a jump trampoline.
///
/// An empty exception directory yields an empty list. A `.pdata` entry that
/// starts at `rva` may extend at most 16 bytes past the replaced body (compiler
/// padding). Anything wider, or an entry that starts before `rva` and still
/// overlaps it, is an error: collapsing that range would rewrite a neighbor.
pub(crate) fn preserve(image: &mut PeImage, rva: u32, size: u32) -> Result<Vec<Correspondence>> {
    if image.exception_rva == 0 || image.exception_size == 0 {
        return Ok(Vec::new());
    }
    let found = entries(image)?;
    let mut chosen = Vec::new();
    for entry in &found {
        if overlaps(entry, rva, size)? {
            chosen.push(entry.index);
        }
    }
    let mut plans = Vec::new();
    for index in chosen {
        plans.push(plan(image, &found, index)?);
    }
    let mut out = Vec::with_capacity(plans.len());
    for item in plans {
        let new_rva = append(image, item.section, &item.bytes)?;
        let slot = image
            .exception_rva
            .checked_add(u32::try_from(item.index).map_err(|_| msg("unwind index overflows"))? * 12)
            .and_then(|base| base.checked_add(8))
            .ok_or_else(|| msg("unwind entry overflows"))?;
        pe::write_rva(image, slot, &new_rva.to_le_bytes())?;
        out.push(item.corr);
    }
    Ok(out)
}

fn overlaps(entry: &Rt, start: u32, size: u32) -> Result<bool> {
    let end = start
        .checked_add(size)
        .ok_or_else(|| msg("trampoline range overflows"))?;
    if entry.end <= start || entry.begin >= end {
        return Ok(false);
    }
    if entry.begin == start {
        if entry.end.saturating_sub(end) > TAIL_PAD {
            return Err(msg("unwind range continues past the trampoline"));
        }
        return Ok(true);
    }
    if entry.begin > start && entry.end <= end {
        return Ok(true);
    }
    Err(msg("unwind range overlaps a neighbor of the trampoline"))
}

fn plan(image: &PeImage, found: &[Rt], index: usize) -> Result<Plan> {
    let entry = &found[index];
    let frames = load_chain(image, entry.unwind, &mut BTreeSet::new())?;
    if offset_zero_mach(&frames) {
        return Err(msg("machframe unwind is not a trampoline frame"));
    }
    let (section, info_off) = locate(image, entry.unwind)?;
    let later = later_offsets(image, found, section, info_off);
    let info = parse_info(&image.sections[section].bytes, info_off, Some(&later))?;
    let bytes = encode_native(&info)?;
    let len = entry.end - entry.begin;
    let corr = correspond(&frames, entry, len, &info)?;
    Ok(Plan {
        index,
        section,
        bytes,
        corr,
    })
}

fn offset_zero_mach(frames: &[Info]) -> bool {
    frames.iter().enumerate().any(|(depth, info)| {
        info.ops
            .iter()
            .any(|code| code.op == 10 && (depth > 0 || code.at == 0))
    })
}

fn correspond(frames: &[Info], entry: &Rt, len: u32, info: &Info) -> Result<Correspondence> {
    let offsets = sample_offsets(&frames[0], len);
    let entry_row = eval(frames, 0)?;
    let mut logical = Vec::new();
    let mut native = Vec::new();
    for offset in offsets {
        let row = eval(frames, offset)?;
        logical.push(FrameLink {
            trampoline_at: offset,
            original_at: offset,
            row,
        });
        native.push(FrameLink {
            trampoline_at: offset,
            original_at: 0,
            row: entry_row.clone(),
        });
    }
    Ok(Correspondence {
        format: "pe",
        start: u64::from(entry.begin),
        end: u64::from(entry.end),
        handler: handler_of(info),
        chain: chain_of(info),
        chain_on_native: info.flags & CHAIN != 0,
        native,
        logical,
    })
}

fn sample_offsets(info: &Info, len: u32) -> Vec<u32> {
    let mut offsets = vec![0];
    for code in &info.ops {
        let at = u32::from(code.at);
        if at < len {
            offsets.push(at);
        }
    }
    if len > 1 {
        offsets.push(len - 1);
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn handler_of(info: &Info) -> Option<u64> {
    if info.flags & HANDLER == 0 || info.suffix.len() < 4 {
        return None;
    }
    Some(u64::from(u32::from_le_bytes([
        info.suffix[0],
        info.suffix[1],
        info.suffix[2],
        info.suffix[3],
    ])))
}

fn chain_of(info: &Info) -> Option<u64> {
    if info.flags & CHAIN == 0 || info.suffix.len() < 12 {
        return None;
    }
    Some(u64::from(u32::from_le_bytes([
        info.suffix[8],
        info.suffix[9],
        info.suffix[10],
        info.suffix[11],
    ])))
}

fn encode_native(info: &Info) -> Result<Vec<u8>> {
    let kept: Vec<&Code> = info
        .ops
        .iter()
        .filter(|code| code.at == 0 && !matches!(code.op, 6 | 7 | 10))
        .collect();
    let mut codes = Vec::new();
    for code in &kept {
        codes.push(0);
        codes.push(code.op | (code.info << 4));
        codes.extend_from_slice(&code.extra);
    }
    if codes.len() % 2 != 0 {
        return Err(msg("unwind code width is odd"));
    }
    let slots = codes.len() / 2;
    if slots > 255 {
        return Err(msg("unwind code array is too large"));
    }
    let keep_fp = kept.iter().any(|code| code.op == 3);
    let frame = if keep_fp {
        info.frame_reg | (info.frame_scaled << 4)
    } else {
        0
    };
    // SizeOfProlog is a u8, so 255 is the last offset the system still treats
    // as inside the prolog (epilogue scan stays off). `protect` fills the
    // replaced body with int3, which is not an epilogue, before this runs.
    // A still-live body past offset 255 is outside that trampoline contract:
    // this field cannot cover it, and a smaller value would scan the jump.
    let prolog = if slots == 0 { 0 } else { 255 };
    let mut out = vec![(info.flags << 3) | 1, prolog, slots as u8, frame];
    out.extend(codes);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    if info.flags & (HANDLER | CHAIN) != 0 {
        if info.suffix.is_empty() {
            return Err(msg("unwind handler is missing"));
        }
        out.extend_from_slice(&info.suffix);
    }
    Ok(out)
}

fn eval(frames: &[Info], pc: u32) -> Result<Row> {
    let mut cursor = Cursor {
        rsp: 0,
        saved: Vec::new(),
        fp: None,
    };
    for (depth, info) in frames.iter().enumerate() {
        for code in &info.ops {
            let live = depth > 0 || u32::from(code.at) <= pc;
            if live {
                apply(&mut cursor, code, info)?;
            }
        }
    }
    Ok(finish(cursor))
}

fn apply(cursor: &mut Cursor, code: &Code, info: &Info) -> Result<()> {
    match code.op {
        0 => {
            let reg = gpr(code.info)?;
            cursor.saved.push((reg, cursor.rsp));
            cursor.rsp += 8;
        }
        1 => cursor.rsp += i64::from(alloc_large(code)?),
        2 => cursor.rsp += i64::from((u32::from(code.info) + 1) * 8),
        3 => {
            let reg = gpr(info.frame_reg)?;
            let disp = i64::from(info.frame_scaled) * 16;
            let fp = cursor.rsp + disp;
            cursor.fp = Some((reg, fp));
            cursor.rsp = fp - disp;
        }
        4 => {
            let reg = gpr(code.info)?;
            cursor
                .saved
                .push((reg, cursor.rsp + i64::from(extra_u16(code)?) * 8));
        }
        5 => {
            let reg = gpr(code.info)?;
            cursor
                .saved
                .push((reg, cursor.rsp + i64::from(extra_u32(code)?)));
        }
        6 | 7 => {}
        8 => {
            cursor.saved.push((
                Reg::Xmm(code.info),
                cursor.rsp + i64::from(extra_u16(code)?) * 16,
            ));
        }
        9 => {
            cursor.saved.push((
                Reg::Xmm(code.info),
                cursor.rsp + i64::from(extra_u32(code)?),
            ));
        }
        10 => return Err(msg("machframe unwind is not a trampoline frame")),
        other => return Err(msg(format!("unwind opcode {other} is not supported"))),
    }
    Ok(())
}

fn finish(cursor: Cursor) -> Row {
    let rip_at = cursor.rsp;
    let cfa = cursor.rsp + 8;
    let rule = match cursor.fp {
        Some((reg, fp)) => Cfa::Reg {
            reg,
            disp: cfa - fp,
        },
        None => Cfa::Sp(cfa),
    };
    let mut saved = std::collections::BTreeMap::new();
    for (reg, addr) in cursor.saved {
        saved.insert(reg, Slot::AtCfa(addr - cfa));
    }
    Row {
        cfa: rule,
        saved,
        rip: Slot::AtCfa(rip_at - cfa),
    }
}

fn gpr(number: u8) -> Result<Reg> {
    row::pe_gpr(number).ok_or_else(|| msg("unwind register is out of range"))
}

fn alloc_large(code: &Code) -> Result<u32> {
    if code.info == 0 {
        Ok(u32::from(extra_u16(code)?) * 8)
    } else if code.info == 1 {
        extra_u32(code)
    } else {
        Err(msg("unwind alloc is malformed"))
    }
}

fn extra_u16(code: &Code) -> Result<u16> {
    let bytes = code
        .extra
        .get(..2)
        .ok_or_else(|| msg("unwind code is truncated"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn extra_u32(code: &Code) -> Result<u32> {
    let bytes = code
        .extra
        .get(..4)
        .ok_or_else(|| msg("unwind code is truncated"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn load_chain(image: &PeImage, unwind: u32, seen: &mut BTreeSet<u32>) -> Result<Vec<Info>> {
    if !seen.insert(unwind) {
        return Err(msg("unwind chain loops"));
    }
    if seen.len() > MAX_CHAIN {
        return Err(msg("unwind chain is too deep"));
    }
    let (section, info_off) = locate(image, unwind)?;
    let bytes = &image.sections[section].bytes;
    // Evaluation only needs the chain head. The handler tail is copied later,
    // bounded by the next unwind info, when the trampoline record is built.
    let info = parse_info(bytes, info_off, None)?;
    let mut frames = vec![info.clone()];
    if info.flags & CHAIN != 0 {
        let next = chain_of(&info).ok_or_else(|| msg("unwind chain is truncated"))?;
        let next = u32::try_from(next).map_err(|_| msg("unwind chain is truncated"))?;
        frames.extend(load_chain(image, next, seen)?);
    }
    Ok(frames)
}

fn parse_info(section: &[u8], info_off: usize, later: Option<&[usize]>) -> Result<Info> {
    if info_off + 4 > section.len() {
        return Err(msg("unwind info is truncated"));
    }
    let version = section[info_off] & 7;
    let flags = section[info_off] >> 3;
    if version != 1 && version != 2 {
        return Err(msg("unwind version is not supported"));
    }
    if flags & CHAIN != 0 && flags & HANDLER != 0 {
        return Err(msg("unwind flags mix a handler and a chain"));
    }
    let count = usize::from(section[info_off + 2]);
    let frame = section[info_off + 3];
    let ops = parse_codes(section, info_off, count)?;
    let suffix = suffix(section, info_off, count, flags, later)?;
    Ok(Info {
        flags,
        frame_reg: frame & 0xf,
        frame_scaled: frame >> 4,
        ops,
        suffix,
    })
}

fn parse_codes(section: &[u8], info_off: usize, count: usize) -> Result<Vec<Code>> {
    let mut ops = Vec::new();
    let mut index = 0;
    while index < count {
        let slot = 4 + index * 2;
        if info_off + slot + 2 > section.len() {
            return Err(msg("unwind info is truncated"));
        }
        let at = section[info_off + slot];
        let packed = section[info_off + slot + 1];
        let op = packed & 0xf;
        let info = packed >> 4;
        let width = slot_count(op, info)?;
        if index + width > count {
            return Err(msg("unwind code walks off its array"));
        }
        let extra_at = info_off + slot + 2;
        let extra_len = (width - 1) * 2;
        if extra_at + extra_len > section.len() {
            return Err(msg("unwind info is truncated"));
        }
        ops.push(Code {
            at,
            op,
            info,
            extra: section[extra_at..extra_at + extra_len].to_vec(),
        });
        index += width;
    }
    Ok(ops)
}

fn suffix(
    section: &[u8],
    info_off: usize,
    count: usize,
    flags: u8,
    later: Option<&[usize]>,
) -> Result<Vec<u8>> {
    let start = align4(info_off + 4 + count * 2);
    if flags & (HANDLER | CHAIN) == 0 {
        return Ok(Vec::new());
    }
    let need = if flags & CHAIN != 0 { 12 } else { 4 };
    let end = match later {
        None => start + need,
        Some(offs) => offs
            .iter()
            .copied()
            .filter(|off| *off > info_off)
            .min()
            .unwrap_or(section.len()),
    };
    if end < start || end > section.len() {
        return Err(msg("unwind handler is truncated"));
    }
    if end - start > MAX_TAIL {
        return Err(msg("unwind handler data is unbounded"));
    }
    if end - start < need {
        return Err(msg("unwind handler is truncated"));
    }
    Ok(section[start..end].to_vec())
}

fn slot_count(op: u8, info: u8) -> Result<usize> {
    Ok(match op {
        0 | 2 | 3 | 10 => 1,
        1 => {
            if info > 1 {
                return Err(msg("unwind alloc is malformed"));
            }
            if info == 0 {
                2
            } else {
                3
            }
        }
        4 | 6 | 8 => 2,
        5 | 7 | 9 => 3,
        other => return Err(msg(format!("unwind opcode {other} is not supported"))),
    })
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn entries(image: &PeImage) -> Result<Vec<Rt>> {
    if image.exception_rva == 0 || image.exception_size == 0 {
        return Ok(Vec::new());
    }
    if !image.exception_size.is_multiple_of(12) {
        return Err(msg("exception directory is truncated"));
    }
    let count = usize::try_from(image.exception_size / 12)
        .map_err(|_| msg("exception directory is too large"))?;
    if count > 1_048_576 {
        return Err(msg("exception directory is too large"));
    }
    let bytes = pe::read_rva(image, image.exception_rva, image.exception_size as usize)?;
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let at = index * 12;
        let begin = u32_at(&bytes[at..])?;
        let end = u32_at(&bytes[at + 4..])?;
        let unwind = u32_at(&bytes[at + 8..])?;
        if begin >= end {
            return Err(msg("unwind range is empty"));
        }
        out.push(Rt {
            begin,
            end,
            unwind,
            index,
        });
    }
    Ok(out)
}

fn u32_at(bytes: &[u8]) -> Result<u32> {
    let chunk = bytes
        .get(..4)
        .ok_or_else(|| msg("exception directory is truncated"))?;
    Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

fn locate(image: &PeImage, rva: u32) -> Result<(usize, usize)> {
    for (index, section) in image.sections.iter().enumerate() {
        let end = section
            .rva
            .checked_add(section.bytes.len() as u32)
            .ok_or_else(|| msg("section rva overflows"))?;
        if rva >= section.rva && rva < end {
            return Ok((index, (rva - section.rva) as usize));
        }
    }
    Err(msg(format!("unwind rva {rva:#x} is not in a section")))
}

fn later_offsets(image: &PeImage, found: &[Rt], section: usize, info_off: usize) -> Vec<usize> {
    let base = image.sections[section].rva;
    let len = image.sections[section].bytes.len();
    found
        .iter()
        .filter_map(|entry| {
            let off = entry.unwind.checked_sub(base)? as usize;
            (off > info_off && off < len).then_some(off)
        })
        .collect()
}

fn append(image: &mut PeImage, section: usize, bytes: &[u8]) -> Result<u32> {
    let sec = &image.sections[section];
    let pad = (4 - sec.bytes.len() % 4) % 4;
    let extra = u32::try_from(pad + bytes.len()).map_err(|_| msg("unwind info is too large"))?;
    let new_end = sec
        .rva
        .checked_add(sec.bytes.len() as u32)
        .and_then(|end| end.checked_add(extra))
        .ok_or_else(|| msg("unwind info overflows"))?;
    if new_end > 32 * 1024 * 1024 {
        return Err(msg("unwind info overflows the image"));
    }
    for other in &image.sections {
        if other.rva > sec.rva && new_end > other.rva {
            return Err(msg("unwind info does not fit before the next section"));
        }
    }
    let sec = &mut image.sections[section];
    sec.bytes.extend(std::iter::repeat_n(0, pad));
    let off = sec.bytes.len();
    sec.bytes.extend_from_slice(bytes);
    Ok(sec.rva + off as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{Section, CH_RDATA, CH_TEXT, IMAGE_BASE};

    fn code(at: u8, op: u8, info: u8) -> [u8; 2] {
        [at, op | (info << 4)]
    }

    fn image(text_len: u32, pdata: Vec<u8>, dir_size: u32) -> PeImage {
        let mut text = vec![0x90; text_len as usize];
        if text_len >= 11 {
            text[..10].copy_from_slice(&[0x48, 0xb8, 42, 0, 0, 0, 0, 0, 0, 0]);
            text[10] = 0xc3;
        }
        PeImage {
            image_base: IMAGE_BASE,
            entry_rva: 0x1000,
            sections: vec![
                Section {
                    name: ".text".into(),
                    rva: 0x1000,
                    bytes: text,
                    characteristics: CH_TEXT,
                },
                Section {
                    name: ".pdata".into(),
                    rva: 0x2000,
                    bytes: pdata,
                    characteristics: CH_RDATA,
                },
            ],
            exports: Vec::new(),
            imports: Vec::new(),
            export_rva: 0,
            export_size: 0,
            import_rva: 0,
            import_size: 0,
            iat_rva: 0,
            iat_size: 0,
            exception_rva: 0x2000,
            exception_size: dir_size,
            tls_rva: 0,
            tls_size: 0,
        }
    }

    fn roundtrip(image: PeImage) -> PeImage {
        let bytes = pe::emit(&image).unwrap();
        pe::parse(&bytes).unwrap()
    }

    fn rt(begin: u32, end: u32, unwind: u32) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&begin.to_le_bytes());
        out[4..8].copy_from_slice(&end.to_le_bytes());
        out[8..12].copy_from_slice(&unwind.to_le_bytes());
        out
    }

    #[test]
    fn push_setfp_alloc_rows() {
        // push rbp @1, mov rbp, rsp @4, sub rsp, 0x20 @8.
        let mut pdata = rt(0x1000, 0x1020, 0x200c).to_vec();
        pdata.extend_from_slice(&[0x01, 0x08, 0x03, 0x05]);
        pdata.extend_from_slice(&code(8, 2, 3));
        pdata.extend_from_slice(&code(4, 3, 0));
        pdata.extend_from_slice(&code(1, 0, 5));
        let image = roundtrip(image(0x20, pdata, 12));
        let at = |off: u32| row_at(&image, 0x1000 + off).unwrap();
        let entry = at(0);
        assert_eq!(entry, row::entry_row());
        let pushed = at(1);
        assert_eq!(pushed.cfa, Cfa::Sp(16));
        assert_eq!(pushed.saved.get(&Reg::Rbp), Some(&Slot::AtCfa(-16)));
        let framed = at(4);
        assert_eq!(
            framed.cfa,
            Cfa::Reg {
                reg: Reg::Rbp,
                disp: 16
            }
        );
        assert_eq!(framed.saved.get(&Reg::Rbp), Some(&Slot::AtCfa(-16)));
        assert_eq!(at(8), framed);
        assert_ne!(entry, pushed);
        assert_ne!(pushed, framed);
    }

    #[test]
    fn save_nonvol_slot_is_rsp_relative() {
        // alloc 0x20 @4, then `mov [rsp+8], rbx` @8. The slot value is the
        // byte offset divided by 8, applied to RSP before the alloc is undone.
        let mut pdata = rt(0x1000, 0x1020, 0x200c).to_vec();
        pdata.extend_from_slice(&[0x01, 0x08, 0x03, 0x00]);
        pdata.extend_from_slice(&code(8, 4, 3));
        pdata.extend_from_slice(&1u16.to_le_bytes());
        pdata.extend_from_slice(&code(4, 2, 3));
        let image = roundtrip(image(0x20, pdata, 12));
        let row = row_at(&image, 0x1008).unwrap();
        assert_eq!(row.cfa, Cfa::Sp(0x28));
        assert_eq!(row.saved.get(&Reg::Rbx), Some(&Slot::AtCfa(-32)));
        assert_eq!(row_at(&image, 0x1000).unwrap(), row::entry_row());
    }

    #[test]
    fn synthetic_pe_trampoline_matches_original_frame() {
        let mut pdata = rt(0x1000, 0x100b, 0x200c).to_vec();
        // EHANDLER. push rbx @2, alloc 0x28 @6. Handler RVA 0x1500, data 0x1600.
        pdata.extend_from_slice(&[0x09, 0x06, 0x02, 0x00]);
        pdata.extend_from_slice(&code(6, 2, 4));
        pdata.extend_from_slice(&code(2, 0, 3));
        pdata.extend_from_slice(&0x1500u32.to_le_bytes());
        pdata.extend_from_slice(&0x1600u32.to_le_bytes());
        let mut image = roundtrip(image(0x20, pdata, 12));
        let before0 = row_at(&image, 0x1000).unwrap();
        let before2 = row_at(&image, 0x1002).unwrap();
        let before6 = row_at(&image, 0x1006).unwrap();
        assert_eq!(before0, row::entry_row());
        assert_ne!(before2, before0);
        assert_ne!(before6, before2);
        let corr = preserve(&mut image, 0x1000, 0x0b).unwrap();
        assert_eq!(corr.len(), 1);
        assert_eq!(corr[0].format, "pe");
        assert_eq!(corr[0].handler, Some(0x1500));
        assert!(corr[0].chain.is_none());
        assert!(!corr[0].chain_on_native);
        for link in &corr[0].logical {
            assert_eq!(link.trampoline_at, link.original_at);
            let row = row_before(link.original_at, &before0, &before2, &before6);
            assert_eq!(row, link.row);
        }
        for link in &corr[0].native {
            assert_eq!(link.original_at, 0);
            assert_eq!(link.row, before0);
            assert_eq!(
                row_at(&image, 0x1000 + link.trampoline_at).unwrap(),
                before0
            );
        }
        assert!(corr[0].logical.iter().any(|link| link.row != before0));
        assert_eq!(row_at(&image, 0x1006).unwrap(), before0);
        let handler = handler_of_pc(&image, 0x1000);
        assert_eq!(handler, Some(0x1500));
    }

    fn row_before(offset: u32, zero: &Row, mid: &Row, body: &Row) -> Row {
        if offset < 2 {
            zero.clone()
        } else if offset < 6 {
            mid.clone()
        } else {
            body.clone()
        }
    }

    fn handler_of_pc(image: &PeImage, pc: u32) -> Option<u32> {
        let entries = entries(image).unwrap();
        let hit = entries
            .iter()
            .find(|entry| pc >= entry.begin && pc < entry.end)
            .unwrap();
        let (section, off) = locate(image, hit.unwind).unwrap();
        let bytes = &image.sections[section].bytes;
        let flags = bytes[off] >> 3;
        if flags & HANDLER == 0 {
            return None;
        }
        let count = usize::from(bytes[off + 2]);
        let start = align4(off + 4 + count * 2);
        Some(u32::from_le_bytes(
            bytes[start..start + 4].try_into().unwrap(),
        ))
    }

    #[test]
    fn chain_stays_on_the_offset_zero_row() {
        // Parent push rbp @1 lives at 0x2028. Child push rbx @4 chains to it.
        let mut pdata = Vec::new();
        pdata.extend_from_slice(&rt(0x1000, 0x1010, 0x2018));
        pdata.extend_from_slice(&rt(0x1100, 0x1110, 0x202c));
        pdata.extend_from_slice(&[0x21, 0x04, 0x01, 0x00]);
        pdata.extend_from_slice(&code(4, 0, 3));
        pdata.extend_from_slice(&[0, 0]);
        pdata.extend_from_slice(&rt(0x1100, 0x1110, 0x202c));
        pdata.extend_from_slice(&[0x01, 0x01, 0x01, 0x00]);
        pdata.extend_from_slice(&code(1, 0, 5));
        let mut image = roundtrip(image(0x120, pdata, 24));
        let parent_before = image.sections[1].bytes.clone();
        let at_child = |image: &PeImage, off: u32| row_at(image, 0x1000 + off).unwrap();
        let zero = at_child(&image, 0);
        let body = at_child(&image, 4);
        assert_eq!(zero.saved.get(&Reg::Rbp), Some(&Slot::AtCfa(-16)));
        assert!(!zero.saved.contains_key(&Reg::Rbx));
        assert!(body.saved.contains_key(&Reg::Rbx));
        let corr = preserve(&mut image, 0x1000, 0x10).unwrap();
        assert!(corr[0].chain_on_native);
        assert_eq!(corr[0].chain, Some(0x202c));
        assert_eq!(at_child(&image, 0), zero);
        assert_eq!(at_child(&image, 4), zero);
        assert_eq!(
            row_at(&image, 0x1101).unwrap().saved.get(&Reg::Rbp),
            Some(&Slot::AtCfa(-16))
        );
        assert!(parent_before.windows(8).any(|window| {
            image.sections[1]
                .bytes
                .windows(8)
                .any(|item| item == window)
        }));
    }

    #[test]
    fn shared_unwind_info_is_left_for_the_other_function() {
        let mut pdata = rt(0x1000, 0x1010, 0x2018).to_vec();
        pdata.extend_from_slice(&rt(0x1100, 0x1110, 0x2018));
        pdata.extend_from_slice(&[0x01, 0x04, 0x01, 0x00]);
        pdata.extend_from_slice(&code(4, 0, 3));
        let mut image = roundtrip(image(0x120, pdata, 24));
        let other = row_at(&image, 0x1104).unwrap();
        preserve(&mut image, 0x1000, 0x10).unwrap();
        assert_eq!(row_at(&image, 0x1004).unwrap(), row::entry_row());
        assert_eq!(row_at(&image, 0x1104).unwrap(), other);
        assert_ne!(other, row::entry_row());
    }

    #[test]
    fn machframe_is_not_rewritten() {
        let mut pdata = rt(0x1000, 0x1010, 0x200c).to_vec();
        pdata.extend_from_slice(&[0x01, 0x01, 0x01, 0x00]);
        pdata.extend_from_slice(&code(0, 10, 0));
        let mut image = roundtrip(image(0x20, pdata, 12));
        let before = image.sections[1].bytes.clone();
        let err = preserve(&mut image, 0x1000, 0x10).unwrap_err();
        assert!(err.to_string().contains("machframe"));
        assert_eq!(image.sections[1].bytes, before);
    }

    #[test]
    fn unwind_range_that_overlaps_a_neighbor_is_an_error() {
        let mut pdata = rt(0x0ff0, 0x1020, 0x200c).to_vec();
        pdata.extend_from_slice(&[0x01, 0, 0, 0]);
        let mut image = roundtrip(image(0x40, pdata, 12));
        let err = preserve(&mut image, 0x1000, 0x10).unwrap_err();
        assert!(err.to_string().contains("neighbor"));
    }

    #[test]
    fn unwind_range_far_past_the_trampoline_is_an_error() {
        let mut pdata = rt(0x1000, 0x1100, 0x200c).to_vec();
        pdata.extend_from_slice(&[0x01, 0, 0, 0]);
        let mut image = roundtrip(image(0x120, pdata, 12));
        let err = preserve(&mut image, 0x1000, 0x10).unwrap_err();
        assert!(err.to_string().contains("past the trampoline"));
    }

    #[test]
    fn offset_zero_code_stays_active_across_the_trampoline() {
        let mut pdata = rt(0x1000, 0x1010, 0x200c).to_vec();
        pdata.extend_from_slice(&[0x01, 0x01, 0x01, 0x00]);
        pdata.extend_from_slice(&code(0, 0, 5));
        let mut image = roundtrip(image(0x20, pdata, 12));
        let row = row_at(&image, 0x1000).unwrap();
        assert_eq!(row.saved.get(&Reg::Rbp), Some(&Slot::AtCfa(-16)));
        assert_ne!(row, row::entry_row());
        preserve(&mut image, 0x1000, 0x10).unwrap();
        assert_eq!(row_at(&image, 0x1000).unwrap(), row);
        assert_eq!(row_at(&image, 0x100f).unwrap(), row);
    }

    #[test]
    fn absent_exception_directory_is_unchanged() {
        let mut image = image(0x20, Vec::new(), 12);
        image.exception_rva = 0;
        image.exception_size = 0;
        image.sections.pop();
        let corr = preserve(&mut image, 0x1000, 0x10).unwrap();
        assert!(corr.is_empty());
    }
}
