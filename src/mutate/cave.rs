//! Move a mutated body into an executable alignment cave.
//!
//! Internal displacements stay put because the body moves as one span. A
//! branch or a rip-relative operand whose absolute target lies outside that
//! span is rewritten so the target does not move. The rewrite decodes every
//! instruction in that span, the same bytes `reachable_size` counts into the
//! body, including the bytes after `int` / `int3`. There is no silent skip:
//! a missing cave, a short entry, or a displacement that does not fit is an
//! error naming the function.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};

use crate::error::{msg, Result};
use crate::pe::{self, PeImage};

use super::desync;

/// Relocated body, including its desync prefix, and the stub that replaces the original function.
#[derive(Debug)]
pub struct Placement {
    pub cave_rva: u32,
    pub cave: Vec<u8>,
    pub stub: Vec<u8>,
}

struct Decoded {
    insn: Instruction,
    disp: Option<(usize, usize)>,
    imm: Option<(usize, usize)>,
}

struct Fix {
    at: u64,
    target: u64,
}

/// Plan a stub at `rva` and a cave body. `body` is the mutated function.
pub fn plan(image: &PeImage, name: &str, rva: u32, body: &[u8], seed: u64) -> Result<Placement> {
    if body.len() < 5 {
        return Err(fail(name, "is too small for a code cave"));
    }
    let head = desync::prefix(seed);
    let need = len_of(name, head.len(), body.len())?;
    let cave_rva =
        pick_cave(image, need, (seed as u32) & 7).ok_or_else(|| fail(name, "has no code cave"))?;
    let old_ip = va(name, image.image_base, rva)?;
    let new_ip = body_ip(name, image, cave_rva, head.len())?;
    let moved = relocate_body(name, body, old_ip, new_ip)?;
    let stub = entry_stub(
        name,
        old_ip,
        va(name, image.image_base, cave_rva)?,
        body.len(),
    )?;
    Ok(assemble(cave_rva, head, moved, stub))
}

/// Place `body` in an executable cave behind a desync prefix.
///
/// The RVA passed to [`plan`] is only the relocation origin. This does not
/// overwrite that address with the entry stub.
pub fn plant(image: &mut PeImage, body: &[u8], seed: u64) -> Result<u32> {
    let origin = image
        .sections
        .iter()
        .find(|section| pe::executable(section))
        .map(|section| section.rva)
        .ok_or_else(|| msg("image has no executable section"))?;
    let place = plan(image, "antidebug", origin, body, seed)?;
    pe::write_cave(image, place.cave_rva, &place.cave)?;
    Ok(place.cave_rva)
}

/// Write the cave, then replace the original body at `rva` with the entry stub.
pub fn commit(image: &mut PeImage, rva: u32, place: &Placement) -> Result<()> {
    pe::write_cave(image, place.cave_rva, &place.cave)?;
    pe::write_rva(image, rva, &place.stub)
}

fn assemble(cave_rva: u32, head: Vec<u8>, moved: Vec<u8>, stub: Vec<u8>) -> Placement {
    let mut cave = head;
    cave.extend(moved);
    Placement {
        cave_rva,
        cave,
        stub,
    }
}

fn len_of(name: &str, head: usize, body: usize) -> Result<u32> {
    let sum = head
        .checked_add(body)
        .ok_or_else(|| fail(name, "cave is too large"))?;
    u32::try_from(sum).map_err(|_| fail(name, "cave is too large"))
}

fn va(name: &str, base: u64, rva: u32) -> Result<u64> {
    base.checked_add(u64::from(rva))
        .ok_or_else(|| fail(name, "address does not fit"))
}

fn body_ip(name: &str, image: &PeImage, cave_rva: u32, head: usize) -> Result<u64> {
    va(name, image.image_base, cave_rva)?
        .checked_add(head as u64)
        .ok_or_else(|| fail(name, "address does not fit"))
}

fn pick_cave(image: &PeImage, len: u32, shift: u32) -> Option<u32> {
    let mut best = None;
    for index in 0..image.sections.len() {
        let Some(rva) = cave_at(image, index, len, shift) else {
            continue;
        };
        best = Some(best.map_or(rva, |prev: u32| prev.min(rva)));
    }
    best
}

fn cave_at(image: &PeImage, index: usize, len: u32, shift: u32) -> Option<u32> {
    let section = &image.sections[index];
    if !pe::executable(section) {
        return None;
    }
    let start = section
        .rva
        .checked_add(u32::try_from(section.bytes.len()).ok()?)?;
    let slack = pe::exec_cave_limit(image, index).saturating_sub(start);
    if slack < len {
        return None;
    }
    Some(start + shift.min(slack - len))
}

fn entry_stub(name: &str, origin: u64, cave: u64, size: usize) -> Result<Vec<u8>> {
    let next = origin
        .checked_add(5)
        .ok_or_else(|| fail(name, "cave is out of range"))?;
    let rel = i64::try_from(cave).map_err(|_| fail(name, "cave is out of range"))?
        - i64::try_from(next).map_err(|_| fail(name, "cave is out of range"))?;
    let rel = i32::try_from(rel).map_err(|_| fail(name, "cave is out of range"))?;
    let mut bytes = vec![0xcc; size];
    bytes[0] = 0xe9;
    bytes[1..5].copy_from_slice(&rel.to_le_bytes());
    Ok(bytes)
}

fn relocate_body(name: &str, body: &[u8], old_ip: u64, new_ip: u64) -> Result<Vec<u8>> {
    let delta = delta_of(name, old_ip, new_ip)?;
    let mut out = body.to_vec();
    let fixes = walk_patch(name, body, &mut out, old_ip, delta)?;
    check_fixes(name, &out, new_ip, &fixes)?;
    Ok(out)
}

fn delta_of(name: &str, old_ip: u64, new_ip: u64) -> Result<i64> {
    let old = i64::try_from(old_ip).map_err(|_| fail(name, "address does not fit"))?;
    let new = i64::try_from(new_ip).map_err(|_| fail(name, "address does not fit"))?;
    new.checked_sub(old)
        .ok_or_else(|| fail(name, "address does not fit"))
}

fn walk_patch(
    name: &str,
    body: &[u8],
    out: &mut [u8],
    old_ip: u64,
    delta: i64,
) -> Result<Vec<Fix>> {
    let end = old_ip.saturating_add(body.len() as u64);
    let mut ip = old_ip;
    let mut fixes = Vec::new();
    while ip < end {
        let decoded = next_in_span(name, body, old_ip, ip, end)?;
        if let Some(fix) = patch_one(name, out, &decoded, old_ip, end, delta)? {
            fixes.push(fix);
        }
        ip = decoded.insn.next_ip();
    }
    Ok(fixes)
}

fn next_in_span(name: &str, body: &[u8], base: u64, ip: u64, end: u64) -> Result<Decoded> {
    let decoded = decode_at(body, base, ip).ok_or_else(|| fail(name, "relocation drifted"))?;
    let next = decoded.insn.next_ip();
    if next <= ip || next > end {
        return Err(fail(name, "relocation drifted"));
    }
    Ok(decoded)
}

fn patch_one(
    name: &str,
    out: &mut [u8],
    decoded: &Decoded,
    base: u64,
    end: u64,
    delta: i64,
) -> Result<Option<Fix>> {
    let Some(target) = target_of(&decoded.insn) else {
        return Ok(None);
    };
    let inside = contains(target, base, end);
    let moved = shift(target, if inside { delta } else { 0 })
        .ok_or_else(|| fail(name, "address does not fit"))?;
    let at = shift(decoded.insn.ip(), delta).ok_or_else(|| fail(name, "address does not fit"))?;
    if !inside {
        apply_disp(name, out, decoded, base, delta, target)?;
    }
    Ok(Some(Fix { at, target: moved }))
}

fn apply_disp(
    name: &str,
    out: &mut [u8],
    decoded: &Decoded,
    base: u64,
    delta: i64,
    target: u64,
) -> Result<()> {
    let next =
        shift(decoded.insn.next_ip(), delta).ok_or_else(|| fail(name, "address does not fit"))?;
    let disp = i64::try_from(target).map_err(|_| fail(name, "relocation does not fit"))?
        - i64::try_from(next).map_err(|_| fail(name, "relocation does not fit"))?;
    let (rel, size) = rel_field(decoded).ok_or_else(|| fail(name, "relocation is not encoded"))?;
    let at = byte_off(decoded.insn.ip(), base)
        .ok_or_else(|| fail(name, "relocation is not encoded"))?
        + rel;
    write_disp(name, out, at, disp, size)
}

fn check_fixes(name: &str, body: &[u8], new_ip: u64, fixes: &[Fix]) -> Result<()> {
    for fix in fixes {
        let decoded =
            decode_at(body, new_ip, fix.at).ok_or_else(|| fail(name, "relocation drifted"))?;
        let got = target_of(&decoded.insn).ok_or_else(|| fail(name, "relocation drifted"))?;
        if got != fix.target {
            return Err(fail(name, "relocation drifted"));
        }
    }
    Ok(())
}

fn write_disp(name: &str, out: &mut [u8], at: usize, disp: i64, size: usize) -> Result<()> {
    let Some(end) = at.checked_add(size) else {
        return Err(fail(name, "relocation is not encoded"));
    };
    let Some(slot) = out.get_mut(at..end) else {
        return Err(fail(name, "relocation is not encoded"));
    };
    match size {
        1 => slot[0] = fit_i8(name, disp)? as u8,
        2 => slot.copy_from_slice(&fit_i16(name, disp)?.to_le_bytes()),
        4 => slot.copy_from_slice(&fit_i32(name, disp)?.to_le_bytes()),
        _ => return Err(fail(name, "relocation is not encoded")),
    }
    Ok(())
}

fn fit_i8(name: &str, disp: i64) -> Result<i8> {
    i8::try_from(disp).map_err(|_| fail(name, "relocation does not fit"))
}

fn fit_i16(name: &str, disp: i64) -> Result<i16> {
    i16::try_from(disp).map_err(|_| fail(name, "relocation does not fit"))
}

fn fit_i32(name: &str, disp: i64) -> Result<i32> {
    i32::try_from(disp).map_err(|_| fail(name, "relocation does not fit"))
}

fn decode_at(body: &[u8], base: u64, ip: u64) -> Option<Decoded> {
    let off = byte_off(ip, base)?;
    let bytes = body.get(off..)?;
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let insn = decoder.decode();
    if insn.is_invalid() || insn.len() == 0 || bytes.len() < insn.len() {
        return None;
    }
    let offsets = decoder.get_constant_offsets(&insn);
    Some(Decoded {
        insn,
        disp: field(
            offsets.has_displacement(),
            offsets.displacement_offset(),
            offsets.displacement_size(),
        ),
        imm: field(
            offsets.has_immediate(),
            offsets.immediate_offset(),
            offsets.immediate_size(),
        ),
    })
}

fn field(on: bool, at: usize, size: usize) -> Option<(usize, usize)> {
    on.then_some((at, size))
}

fn rel_field(decoded: &Decoded) -> Option<(usize, usize)> {
    if decoded.insn.is_ip_rel_memory_operand() {
        decoded.disp
    } else {
        decoded.imm
    }
}

fn target_of(insn: &Instruction) -> Option<u64> {
    if is_direct_branch(insn) {
        return near_of(insn).or_else(|| mem_target(insn));
    }
    mem_target(insn).or_else(|| near_of(insn))
}

fn is_direct_branch(insn: &Instruction) -> bool {
    matches!(
        insn.flow_control(),
        FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch
            | FlowControl::Call
            | FlowControl::XbeginXabortXend
    )
}

fn near_of(insn: &Instruction) -> Option<u64> {
    match insn.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(insn.near_branch_target())
        }
        _ => None,
    }
}

fn mem_target(insn: &Instruction) -> Option<u64> {
    insn.is_ip_rel_memory_operand()
        .then_some(insn.ip_rel_memory_address())
}

fn contains(ip: u64, base: u64, end: u64) -> bool {
    ip >= base && ip < end
}

fn shift(ip: u64, delta: i64) -> Option<u64> {
    let sum = i64::try_from(ip).ok()?.checked_add(delta)?;
    u64::try_from(sum).ok()
}

fn byte_off(ip: u64, base: u64) -> Option<usize> {
    usize::try_from(ip.checked_sub(base)?).ok()
}

fn fail(name: &str, text: &str) -> crate::error::Error {
    msg(format!("{name} {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::Flags;
    use crate::pe::{Section, CH_RDATA, CH_TEXT, IMAGE_BASE};

    #[test]
    fn cave_move_matches_the_emulator() {
        let add = [0x48, 0x83, 0xc0, 0x01, 0xc3];
        let rewritten = super::super::rewrite(&add, IMAGE_BASE + 0x1000);
        assert_ne!(rewritten, add);
        assert_eq!(alone(&add, 41, 0), moved(&rewritten, &[], 41, 0));
        assert_eq!(alone(&rewritten, 41, 0), moved(&rewritten, &[], 41, 0));
        assert_eq!(moved(BRANCH, &[], 0, 0).0, 3);
        assert_eq!(moved(COND, &[], 0, 0).0, 2);
        assert_eq!(moved(COND, &[], 0, 1).0, 4);
        assert_eq!(moved(&call_mix(), &[helper()], 0, 0).0, 9);
        assert_eq!(
            moved(&load_rip(), &[qword()], 0, 0).0,
            0x1122_3344_5566_7788
        );
        let placed = commit_of(&load_rip(), &[qword()], 4);
        assert!(!trace_of(&placed).contains(&(cave_va(&placed) + 2)));
    }

    #[test]
    fn seeds_change_the_mutated_bytes() {
        let body = [0x48, 0x83, 0xc0, 0x01, 0x31, 0xc9, 0xc3];
        let image = text_image(&body);
        let first = plan(&image, "f", 0x1000, &body, 1).unwrap();
        let second = plan(&image, "f", 0x1000, &body, 2).unwrap();
        assert_ne!(first.cave, second.cave);
        assert_ne!(first.stub, second.stub);
        assert_eq!(finish(&image, &first, 7), finish(&image, &second, 7));
    }

    #[test]
    fn missing_cave_names_the_function() {
        let body = [0x48, 0x83, 0xc0, 0x01, 0xc3];
        let mut image = text_image(&body);
        image
            .sections
            .push(section(".rdata", 0x1005, &[0], CH_RDATA));
        let err = plan(&image, "tight", 0x1000, &body, 1).unwrap_err();
        assert_eq!(err.to_string(), "tight has no code cave");
    }

    #[test]
    fn short_function_is_an_error() {
        let image = text_image(&[0xc3, 0x90, 0x90, 0x90, 0x90]);
        let err = plan(&image, "tiny", 0x1000, &[0xc3], 1).unwrap_err();
        assert_eq!(err.to_string(), "tiny is too small for a code cave");
    }

    #[test]
    fn int3_then_rip_relative_keeps_its_absolute_target() {
        let body = [0xcc, 0x48, 0x8b, 0x05, 0xf8, 0x0f, 0x00, 0x00, 0xc3];
        let old = IMAGE_BASE + 0x1000;
        assert_eq!(mov_after_int3(&body, old), 0x1400_02000);
        let mut image = text_image(&body);
        let place = plan(&image, "f", 0x1000, &body, 0).unwrap();
        commit(&mut image, 0x1000, &place).unwrap();
        let head = super::super::desync::prefix(0).len();
        let moved = cave_body(&image, place.cave_rva, head, body.len());
        let new_ip = IMAGE_BASE + u64::from(place.cave_rva) + head as u64;
        assert_eq!(mov_after_int3(moved, new_ip), 0x1400_02000);
    }

    #[test]
    fn external_rel8_that_does_not_fit_is_an_error() {
        let body = [0xeb, 0x20, 0x90, 0x90, 0xc3];
        let mut padded = vec![0xcc; 0x300];
        padded[..body.len()].copy_from_slice(&body);
        let err = plan(&text_image(&padded), "far", 0x1000, &body, 1).unwrap_err();
        assert_eq!(err.to_string(), "far relocation does not fit");
    }

    const BRANCH: &[u8] = &[
        0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x06, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x03,
        0x00, 0x00, 0x00, 0xc3,
    ];

    const COND: &[u8] = &[
        0x83, 0xf9, 0x01, 0x74, 0x06, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x04, 0x00, 0x00,
        0x00, 0xc3,
    ];

    fn alone(body: &[u8], rax: u64, rcx: u64) -> (u64, Flags) {
        run(&text_image(body), 0x1000, rax, rcx)
    }

    fn moved(body: &[u8], extra: &[Section], rax: u64, rcx: u64) -> (u64, Flags) {
        let mut image = text_image(body);
        image.sections.extend(extra.iter().cloned());
        let before = run(&image, 0x1000, rax, rcx);
        let place = plan(&image, "f", 0x1000, body, 3).unwrap();
        commit(&mut image, 0x1000, &place).unwrap();
        let after = run(&image, 0x1000, rax, rcx);
        assert_eq!(before, after);
        after
    }

    fn commit_of(body: &[u8], extra: &[Section], seed: u64) -> PeImage {
        commit_extra(body, extra, seed)
    }

    fn commit_extra(body: &[u8], extra: &[Section], seed: u64) -> PeImage {
        let mut image = text_image(body);
        image.sections.extend(extra.iter().cloned());
        let place = plan(&image, "f", 0x1000, body, seed).unwrap();
        commit(&mut image, 0x1000, &place).unwrap();
        let parsed = pe::parse(&pe::emit(&image).unwrap()).unwrap();
        assert_eq!(parsed.sections[0].bytes, image.sections[0].bytes);
        image
    }

    fn finish(image: &PeImage, place: &Placement, rax: u64) -> (u64, Flags) {
        let mut next = image.clone();
        commit(&mut next, 0x1000, place).unwrap();
        run(&next, 0x1000, rax, 0)
    }

    fn call_mix() -> Vec<u8> {
        let mut bytes = vec![0x90, 0xe8, 0, 0, 0, 0, 0xc3];
        let disp: i32 = 0x1100 - 0x1006;
        bytes[2..6].copy_from_slice(&disp.to_le_bytes());
        bytes
    }

    fn helper() -> Section {
        section(".x", 0x1100, &[0xb8, 0x09, 0x00, 0x00, 0x00, 0xc3], CH_TEXT)
    }

    fn load_rip() -> Vec<u8> {
        let mov_ip = IMAGE_BASE + 0x1001;
        let disp = i32::try_from((IMAGE_BASE + 0x2000) as i64 - (mov_ip as i64 + 7)).unwrap();
        let mut bytes = vec![0x90, 0x48, 0x8b, 0x05];
        bytes.extend(disp.to_le_bytes());
        bytes.push(0xc3);
        bytes
    }

    fn qword() -> Section {
        section(
            ".rdata",
            0x2000,
            &0x1122_3344_5566_7788u64.to_le_bytes(),
            CH_RDATA,
        )
    }

    fn mov_after_int3(code: &[u8], ip: u64) -> u64 {
        let mut decoder = iced_x86::Decoder::with_ip(64, code, ip, iced_x86::DecoderOptions::NONE);
        let int3 = decoder.decode();
        assert_eq!(int3.mnemonic(), iced_x86::Mnemonic::Int3);
        let mov = decoder.decode();
        assert!(mov.is_ip_rel_memory_operand());
        mov.ip_rel_memory_address()
    }

    fn cave_body(image: &PeImage, cave_rva: u32, head: usize, len: usize) -> &[u8] {
        let off = (cave_rva - image.sections[0].rva) as usize;
        let bytes = &image.sections[0].bytes;
        &bytes[off + head..off + head + len]
    }

    fn cave_va(image: &PeImage) -> u64 {
        let rel = i32::from_le_bytes(image.sections[0].bytes[1..5].try_into().unwrap());
        image.image_base + (0x1005_i64 + i64::from(rel)) as u64
    }

    fn trace_of(image: &PeImage) -> Vec<u64> {
        let mut machine = boot(image, 0x1000, 0, 0);
        let mut ips = Vec::new();
        while machine.exit_code.is_none() {
            ips.push(machine.rip);
            machine.step().unwrap();
            assert!(ips.len() < 64, "runaway");
        }
        ips
    }

    fn run(image: &PeImage, rva: u32, rax: u64, rcx: u64) -> (u64, Flags) {
        let mut machine = boot(image, rva, rax, rcx);
        machine.run().unwrap();
        (machine.regs[0], machine.flags)
    }

    fn boot(image: &PeImage, rva: u32, rax: u64, rcx: u64) -> crate::emu::Machine {
        let mut machine = crate::emu::bare(crate::emu::Policy::default()).unwrap();
        let rsp = machine.regs[4];
        for section in &image.sections {
            machine.regions.push(crate::emu::Region {
                base: image.image_base + u64::from(section.rva),
                data: section.bytes.clone(),
            });
        }
        machine.rip = image.image_base + u64::from(rva);
        machine.regs[0] = rax;
        machine.regs[1] = rcx;
        machine.regs[4] = rsp;
        machine
    }

    fn text_image(bytes: &[u8]) -> PeImage {
        PeImage {
            image_base: IMAGE_BASE,
            entry_rva: 0x1000,
            sections: vec![section(".text", 0x1000, bytes, CH_TEXT)],
            exports: Vec::new(),
            imports: Vec::new(),
            export_rva: 0,
            export_size: 0,
            import_rva: 0,
            import_size: 0,
            iat_rva: 0,
            iat_size: 0,
            exception_rva: 0,
            exception_size: 0,
            tls_rva: 0,
            tls_size: 0,
        }
    }

    fn section(name: &str, rva: u32, bytes: &[u8], characteristics: u32) -> Section {
        Section {
            name: name.into(),
            rva,
            bytes: bytes.to_vec(),
            characteristics,
        }
    }
}
