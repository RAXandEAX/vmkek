use iced_x86::code_asm::*;

use crate::error::{msg, Result};
use crate::vm::{
    CALL_DEPTH_LIMIT, CHAIN_FOLD, CHAIN_SAVE, CTX_DEPTH, FRAME_CALLS, FRAME_FILE_STACK,
    FRAME_FLAGS, FRAME_IMAGE, FRAME_SAVED_R12, FRAME_SAVED_R13, FRAME_SAVED_R14, FRAME_SAVED_RBX,
    FRAME_SPILL, FRAME_TARGET, PRIVATE_STRIDE, RT_MASTER, RT_MIX, RT_SLOTS, RT_TERM, SLOT_COUNT,
    VARIANT_OPCODES, WEAVE_FRAME,
};

use super::ice;

/// Reject a bytecode register index before it is used as a slot offset.
fn bound_slot(a: &mut CodeAssembler, index: AsmRegister32, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.cmp(index, SLOT_COUNT as u32))?;
    go(a.jae(fail))?;
    Ok(())
}

pub(super) struct Anchors<'a> {
    pub dispatch: &'a mut CodeLabel,
    pub fail: &'a mut CodeLabel,
    pub calls: &'a CodeLabel,
    pub frame_hold: &'a CodeLabel,
    pub target_hold: &'a CodeLabel,
    pub close_chain: &'a CodeLabel,
    pub bind_ctx: &'a CodeLabel,
    pub leave_nest: &'a CodeLabel,
    pub pe_host_resume: &'a mut CodeLabel,
    pub linux: &'a CodeLabel,
    pub drop_window: &'a CodeLabel,
    pub agent_begin: Option<CodeLabel>,
}

pub(super) fn emit_handler(
    a: &mut CodeAssembler,
    tag: u8,
    odd: &mut CodeLabel,
    anchors: &mut Anchors<'_>,
    morph: &mut super::morph::Morph,
) -> Result<()> {
    // The caller's label is the even entry. The odd entry is the other prologue.
    emit_pair(a, morph, odd)?;
    // r11 is dead at handler entry. The stamp count is chosen from the seed.
    let stamps = morph.entry_stamps(tag);
    for _ in 0..stamps {
        morph.stamp(a)?;
    }
    match tag {
        0x34..=0x3b => super::stack::emit(a, tag, anchors.dispatch, *anchors.fail),
        0x04..=0x09 | 0x20 | 0x22 | 0x24..=0x2c | 0x2f..=0x31 => {
            emit_handler_simple(a, tag, anchors, morph)
        }
        0x02 | 0x03 | 0x10..=0x19 => emit_handler_alu(a, tag, anchors, morph),
        0x21 | 0x23 | 0x2d | 0x2e | 0x32 | 0x33 => emit_handler_state(a, tag, anchors, morph),
        _ => emit_handler_control(a, tag, anchors, morph),
    }
}

fn emit_pair(
    a: &mut CodeAssembler,
    morph: &mut super::morph::Morph,
    odd: &mut CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut body = a.create_label();
    morph.stamp(a)?;
    go(a.jmp(body))?;
    go(a.set_label(odd))?;
    morph.stamp(a)?;
    go(a.jmp(body))?;
    go(a.set_label(&mut body))?;
    Ok(())
}

fn emit_handler_simple(
    a: &mut CodeAssembler,
    tag: u8,
    anchors: &mut Anchors<'_>,
    morph: &super::morph::Morph,
) -> Result<()> {
    let fail = *anchors.fail;
    let dispatch = &mut *anchors.dispatch;
    match tag {
        0x04..=0x07 => mem_op(a, tag, dispatch, fail),
        0x08 => lea_sib(a, dispatch, fail),
        0x09 => lea_rva(a, dispatch, fail),
        0x20 | 0x22 => compare_rr(a, tag, dispatch, fail),
        0x24 => not_op(a, dispatch, morph.arm(tag, 2) == 1, fail),
        0x25 => neg_op(a, dispatch, fail),
        0x26..=0x27 => inc_dec(a, tag, dispatch, fail),
        0x28..=0x2c => shift_op(a, tag, dispatch, fail),
        0x2f => div(a, dispatch, fail),
        0x30..=0x31 => push_pop(a, tag, dispatch, fail),
        _ => Err(msg("handler not emitted")),
    }
}

fn emit_handler_alu(
    a: &mut CodeAssembler,
    tag: u8,
    anchors: &mut Anchors<'_>,
    morph: &super::morph::Morph,
) -> Result<()> {
    let fail = *anchors.fail;
    let dispatch = &mut *anchors.dispatch;
    let alt = morph.arm(tag, 2) == 1;
    match tag {
        0x02 => with_variant(
            a,
            variant_bit(tag),
            dispatch,
            |asm| mov_rr(asm, false, alt, fail),
            |asm| mov_rr(asm, true, alt, fail),
        ),
        0x03 => with_variant(
            a,
            variant_bit(tag),
            dispatch,
            |asm| mov_ri(asm, false, alt, fail),
            |asm| mov_ri(asm, true, alt, fail),
        ),
        0x10..=0x14 => {
            binary(a, tag, false, fail)?;
            finish(a, dispatch)
        }
        0x15 | 0x17 => with_variant(
            a,
            variant_bit(tag),
            dispatch,
            |asm| alu_imm(asm, tag, false, fail),
            |asm| alu_imm(asm, tag, true, fail),
        ),
        0x15..=0x19 => {
            binary(a, tag, true, fail)?;
            finish(a, dispatch)
        }
        _ => Err(msg("handler not emitted")),
    }
}

fn emit_handler_state(
    a: &mut CodeAssembler,
    tag: u8,
    anchors: &mut Anchors<'_>,
    morph: &super::morph::Morph,
) -> Result<()> {
    let fail = *anchors.fail;
    let dispatch = &mut *anchors.dispatch;
    let alt = morph.arm(tag, 2) == 1;
    match tag {
        0x21 | 0x23 => {
            compare_imm(a, tag, alt, fail)?;
            finish(a, dispatch)
        }
        0x2d | 0x2e => {
            imul(a, tag == 0x2e, fail)?;
            finish(a, dispatch)
        }
        0x32 => st_flags(a, dispatch, alt, fail),
        0x33 => ld_flags(a, dispatch, alt, fail),
        _ => Err(msg("handler not emitted")),
    }
}

fn emit_handler_control(
    a: &mut CodeAssembler,
    tag: u8,
    anchors: &mut Anchors<'_>,
    morph: &mut super::morph::Morph,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let close = *anchors.close_chain;
    let bind = *anchors.bind_ctx;
    let leave = *anchors.leave_nest;
    let linux = *anchors.linux;
    let drop_plain = *anchors.drop_window;
    let dispatch = &mut *anchors.dispatch;
    let fail = &mut *anchors.fail;
    let calls = anchors.calls;
    let frame_hold = anchors.frame_hold;
    let target_hold = anchors.target_hold;
    match tag {
        0x40 => jmp_abs(a, dispatch, morph.arm(tag, 3)),
        0x41 => jcc(a, dispatch, morph),
        0x50 | 0x51 if super::chain::pe_guarded() => go(a.jmp(*fail)),
        0x50 => call_rva(
            a,
            dispatch,
            fail,
            calls,
            bind,
            anchors.agent_begin.map(|begin| (begin, drop_plain)),
        ),
        0x51 if super::chain::pe_tls_bound() => {
            call_reg_pe(a, dispatch, bind, drop_plain, *fail, anchors.pe_host_resume)
        }
        0x51 if anchors.agent_begin.is_some() => {
            call_reg_external(a, dispatch, bind, drop_plain, *fail)
        }
        0x51 => call_reg(a, dispatch, frame_hold, target_hold, drop_plain, *fail),
        0x52 => ret_op(a, dispatch, close, bind, leave, drop_plain, *fail),
        0x60 => {
            go(a.mov(eax, dword_ptr(r12 + 1i32)))?;
            go(a.cmp(eax, dword_ptr(r13 + 0x30i32)))?;
            go(a.jne(*fail))?;
            // BeingDebugged rides on this entry check. Linux probes follow it.
            emit_probe(a, dispatch, fail, linux)
        }
        0x61 => nest_mov(a, dispatch, fail),
        0x70 => junk_op(a, dispatch, morph.arm(tag, 3)),
        _ => Err(msg("handler not emitted")),
    }
}

fn emit_probe(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    fail: &mut CodeLabel,
    linux: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut clean = a.create_label();
    let mut poison = a.create_label();
    go(a.db(&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]))?;
    go(a.mov(al, byte_ptr(rax + 2i32)))?;
    go(a.test(al, al))?;
    go(a.jnz(poison))?;
    if !super::chain::pe_tls_bound() {
        emit_heap_probe(a, &mut poison, &mut clean)?;
        go(a.set_label(&mut clean))?;
        crate::antidebug::emit_linux_gate(a, linux, &mut poison)?;
    }
    finish(a, dispatch)?;
    go(a.set_label(&mut poison))?;
    poison_key(a)?;
    go(a.jmp(*fail))?;
    Ok(())
}

fn emit_heap_probe(
    a: &mut CodeAssembler,
    poison: &mut CodeLabel,
    clean: &mut CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(rcx, qword_ptr(rax + 0x30i32)))?;
    go(a.test(rcx, rcx))?;
    go(a.jz(*clean))?;
    go(a.mov(edx, dword_ptr(rcx + crate::antidebug::HEAP_FLAGS)))?;
    go(a.mov(eax, dword_ptr(rcx + crate::antidebug::HEAP_FORCE)))?;
    go(a.and(edx, !crate::antidebug::HEAP_GROWABLE))?;
    go(a.or(edx, eax))?;
    go(a.test(edx, edx))?;
    go(a.jnz(*poison))?;
    Ok(())
}

fn poison_key(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let poison = i32::from(crate::antidebug::KEY_POISON);
    super::chain::emit_load_rax(a)?;
    go(a.xor(byte_ptr(rax), poison))?;
    go(a.xor(byte_ptr(r13 + RT_TERM), poison))?;
    Ok(())
}

fn binary(a: &mut CodeAssembler, tag: u8, immediate: bool, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, r9d, fail)?;
    go(a.mov(rax, qword_ptr(rbx + r9 * 8)))?;
    if immediate {
        go(a.movsxd(r8, dword_ptr(r12 + 2i32)))?;
    } else {
        go(a.movzx(edx, byte_ptr(r12 + 2i32)))?;
        bound_slot(a, edx, fail)?;
        go(a.mov(r8, qword_ptr(rbx + rdx * 8)))?;
    }
    match tag {
        0x10 | 0x15 => go(a.add(rax, r8))?,
        0x11 | 0x16 => go(a.sub(rax, r8))?,
        0x12 | 0x17 => go(a.xor(rax, r8))?,
        0x13 | 0x18 => go(a.and(rax, r8))?,
        0x14 | 0x19 => go(a.or(rax, r8))?,
        _ => {}
    }
    if matches!(tag, 0x10..=0x19) {
        go(a.mov(qword_ptr(rbx + r9 * 8), rax))?;
    }
    store_flags(a)
}

fn compare_imm(a: &mut CodeAssembler, tag: u8, alt: bool, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    if alt {
        go(a.movzx(r15d, byte_ptr(r12 + 1i32)))?;
        bound_slot(a, r15d, fail)?;
        go(a.mov(rax, qword_ptr(rbx + r15 * 8)))?;
    } else {
        go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
        bound_slot(a, r9d, fail)?;
        go(a.mov(rax, qword_ptr(rbx + r9 * 8)))?;
    }
    go(a.movsxd(r8, dword_ptr(r12 + 2i32)))?;
    if tag == 0x21 {
        go(a.cmp(rax, r8))?;
    } else {
        go(a.test(rax, r8))?;
    }
    store_flags(a)
}

fn imul(a: &mut CodeAssembler, immediate: bool, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, r9d, fail)?;
    go(a.mov(rax, qword_ptr(rbx + r9 * 8)))?;
    if immediate {
        go(a.movsxd(r8, dword_ptr(r12 + 2i32)))?;
    } else {
        go(a.movzx(edx, byte_ptr(r12 + 2i32)))?;
        bound_slot(a, edx, fail)?;
        go(a.mov(r8, qword_ptr(rbx + rdx * 8)))?;
    }
    go(a.imul_2(rax, r8))?;
    go(a.mov(qword_ptr(rbx + r9 * 8), rax))?;
    store_flags(a)
}

fn nest_mov(a: &mut CodeAssembler, dispatch: &mut CodeLabel, fail: &mut CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(al, byte_ptr(r12 + 2i32)))?;
    go(a.xor(al, 0xa5u32))?;
    go(a.cmp(al, 2u32))?;
    go(a.jne(*fail))?;
    go(a.mov(al, byte_ptr(r12 + 3i32)))?;
    go(a.xor(al, 0xa5u32))?;
    go(a.movzx(ecx, al))?;
    bound_slot(a, ecx, *fail)?;
    go(a.mov(al, byte_ptr(r12 + 4i32)))?;
    go(a.xor(al, 0xa5u32))?;
    go(a.movzx(edx, al))?;
    bound_slot(a, edx, *fail)?;
    go(a.mov(rax, qword_ptr(rbx + rdx * 8)))?;
    go(a.mov(qword_ptr(rbx + rcx * 8), rax))?;
    finish(a, dispatch)
}

#[cfg(test)]
pub const JCC_CONDITIONS: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

fn jcc(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    morph: &mut super::morph::Morph,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut taken = a.create_label();
    let mut skip = a.create_label();
    go(a.mov(r8d, dword_ptr(r12 + 2i32)))?;
    go(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    go(a.and(ecx, 0x0fi32))?;
    go(a.mov(rax, qword_ptr(rbx + FRAME_FLAGS)))?;
    // Each condition reads `cl` and the flags in `rax` and exits to `taken` or `skip`.
    // The seed picks the test order. ZF is not required to be first.
    let mut order = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    morph.shuffle(&mut order);
    for step in order {
        emit_jcc_step(a, step, &mut taken, &mut skip)?;
    }
    go(a.jmp(skip))?;
    go(a.set_label(&mut taken))?;
    go(a.mov(r14d, r8d))?;
    super::edge::goto(a, dispatch)?;
    go(a.set_label(&mut skip))?;
    finish(a, dispatch)
}

fn emit_jcc_step(
    a: &mut CodeAssembler,
    step: u8,
    taken: &mut CodeLabel,
    skip: &mut CodeLabel,
) -> Result<()> {
    match step {
        0 => emit_cond(a, 4, 0x40, true, taken, skip),
        1 => emit_cond(a, 5, 0x40, false, taken, skip),
        2 => emit_cond(a, 0, 0x800, true, taken, skip),
        3 => emit_cond(a, 1, 0x800, false, taken, skip),
        4 => emit_cond(a, 2, 1, true, taken, skip),
        5 => emit_cond(a, 3, 1, false, taken, skip),
        6 => emit_cond(a, 8, 0x80, true, taken, skip),
        7 => emit_cond(a, 9, 0x80, false, taken, skip),
        8 => emit_cond(a, 10, 4, true, taken, skip),
        9 => emit_cond(a, 11, 4, false, taken, skip),
        10 => emit_either(a, 6, taken, skip),
        11 => emit_neither(a, 7, taken, skip),
        12 => emit_sign_overflow(a, 12, false, taken, skip),
        13 => emit_sign_overflow(a, 13, true, taken, skip),
        14 => emit_le(a, taken, skip),
        15 => emit_g(a, taken, skip),
        _ => Err(msg("condition step is missing")),
    }
}

fn junk_op(a: &mut CodeAssembler, dispatch: &mut CodeLabel, arm: u32) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    match arm {
        0 => {}
        1 => go(a.xor(r15d, r15d))?,
        _ => go(a.mov(r15, r15))?,
    }
    finish(a, dispatch)
}

fn jmp_abs(a: &mut CodeAssembler, dispatch: &mut CodeLabel, arm: u32) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    match arm {
        0 => go(a.mov(r14d, dword_ptr(r12 + 1i32)))?,
        1 => {
            go(a.mov(r15d, dword_ptr(r12 + 1i32)))?;
            go(a.mov(r14d, r15d))?;
        }
        _ => {
            go(a.mov(eax, dword_ptr(r12 + 1i32)))?;
            go(a.mov(r14d, eax))?;
        }
    }
    super::edge::goto(a, dispatch)
}

fn st_flags(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    alt: bool,
    fail: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, ecx, fail)?;
    if alt {
        go(a.mov(r15, qword_ptr(rbx + FRAME_FLAGS)))?;
        go(a.mov(qword_ptr(rbx + rcx * 8), r15))?;
    } else {
        go(a.mov(rax, qword_ptr(rbx + FRAME_FLAGS)))?;
        go(a.mov(qword_ptr(rbx + rcx * 8), rax))?;
    }
    finish(a, dispatch)
}

fn ld_flags(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    alt: bool,
    fail: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, ecx, fail)?;
    if alt {
        go(a.mov(r15, qword_ptr(rbx + rcx * 8)))?;
        go(a.mov(qword_ptr(rbx + FRAME_FLAGS), r15))?;
    } else {
        go(a.mov(rax, qword_ptr(rbx + rcx * 8)))?;
        go(a.mov(qword_ptr(rbx + FRAME_FLAGS), rax))?;
    }
    finish(a, dispatch)
}

fn emit_cond(
    a: &mut CodeAssembler,
    cond: u8,
    mask: u32,
    want_set: bool,
    taken: &mut CodeLabel,
    skip: &mut CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut next = a.create_label();
    go(a.cmp(cl, u32::from(cond)))?;
    go(a.jne(next))?;
    go(a.test(rax, mask as i32))?;
    if want_set {
        go(a.jnz(*taken))?;
    } else {
        go(a.jz(*taken))?;
    }
    go(a.jmp(*skip))?;
    go(a.set_label(&mut next))?;
    Ok(())
}

fn emit_either(
    a: &mut CodeAssembler,
    cond: u8,
    taken: &mut CodeLabel,
    skip: &mut CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut next = a.create_label();
    go(a.cmp(cl, u32::from(cond)))?;
    go(a.jne(next))?;
    go(a.test(rax, 1i32))?;
    go(a.jnz(*taken))?;
    go(a.test(rax, 0x40i32))?;
    go(a.jnz(*taken))?;
    go(a.jmp(*skip))?;
    go(a.set_label(&mut next))?;
    Ok(())
}

fn emit_neither(
    a: &mut CodeAssembler,
    cond: u8,
    taken: &mut CodeLabel,
    skip: &mut CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut next = a.create_label();
    go(a.cmp(cl, u32::from(cond)))?;
    go(a.jne(next))?;
    go(a.test(rax, 1i32))?;
    go(a.jnz(*skip))?;
    go(a.test(rax, 0x40i32))?;
    go(a.jnz(*skip))?;
    go(a.jmp(*taken))?;
    go(a.set_label(&mut next))?;
    Ok(())
}

fn split_sign_overflow(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(rdx, rax))?;
    go(a.shr(rdx, 7u32))?;
    go(a.and(rdx, 1i32))?;
    go(a.mov(r11, rax))?;
    go(a.shr(r11, 11u32))?;
    go(a.and(r11, 1i32))?;
    go(a.cmp(rdx, r11))?;
    Ok(())
}

fn emit_sign_overflow(
    a: &mut CodeAssembler,
    cond: u8,
    equal: bool,
    taken: &mut CodeLabel,
    skip: &mut CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut next = a.create_label();
    go(a.cmp(cl, u32::from(cond)))?;
    go(a.jne(next))?;
    split_sign_overflow(a)?;
    if equal {
        go(a.je(*taken))?;
    } else {
        go(a.jne(*taken))?;
    }
    go(a.jmp(*skip))?;
    go(a.set_label(&mut next))?;
    Ok(())
}

fn emit_le(a: &mut CodeAssembler, taken: &mut CodeLabel, skip: &mut CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut next = a.create_label();
    go(a.cmp(cl, 14u32))?;
    go(a.jne(next))?;
    go(a.test(rax, 0x40i32))?;
    go(a.jnz(*taken))?;
    split_sign_overflow(a)?;
    go(a.jne(*taken))?;
    go(a.jmp(*skip))?;
    go(a.set_label(&mut next))?;
    Ok(())
}

fn emit_g(a: &mut CodeAssembler, taken: &mut CodeLabel, skip: &mut CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut next = a.create_label();
    go(a.cmp(cl, 15u32))?;
    go(a.jne(next))?;
    go(a.test(rax, 0x40i32))?;
    go(a.jnz(*skip))?;
    split_sign_overflow(a)?;
    go(a.je(*taken))?;
    go(a.jmp(*skip))?;
    go(a.set_label(&mut next))?;
    Ok(())
}

pub(super) fn store_flags(a: &mut CodeAssembler) -> Result<()> {
    if super::chain::pe_tls_bound() {
        on_work_stack(a)?;
    }
    a.pushfq().map_err(ice)?;
    a.pop(rax).map_err(ice)?;
    if super::chain::pe_tls_bound() {
        off_work_stack(a)?;
    }
    a.mov(qword_ptr(rbx + FRAME_FLAGS), rax).map_err(ice)?;
    Ok(())
}

fn restore_flags(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    if super::chain::pe_tls_bound() {
        on_work_stack(a)?;
    }
    go(a.mov(r10, qword_ptr(rbx + FRAME_FLAGS)))?;
    go(a.push(r10))?;
    go(a.popfq())?;
    if super::chain::pe_tls_bound() {
        off_work_stack(a)?;
    }
    Ok(())
}

pub(super) fn finish(a: &mut CodeAssembler, dispatch: &mut CodeLabel) -> Result<()> {
    a.inc(r14).map_err(ice)?;
    super::edge::goto(a, dispatch)
}

fn mem_op(a: &mut CodeAssembler, tag: u8, dispatch: &mut CodeLabel, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    go(a.movzx(edx, byte_ptr(r12 + 2i32)))?;
    bound_slot(a, r9d, fail)?;
    bound_slot(a, edx, fail)?;
    match tag {
        0x04 | 0x06 => {
            go(a.mov(rax, qword_ptr(rbx + rdx * 8)))?;
            if tag == 0x04 {
                go(a.movzx(eax, byte_ptr(rax)))?;
            } else {
                go(a.mov(rax, qword_ptr(rax)))?;
            }
            go(a.mov(qword_ptr(rbx + r9 * 8), rax))?;
        }
        _ => {
            go(a.mov(rax, qword_ptr(rbx + r9 * 8)))?;
            go(a.mov(rcx, qword_ptr(rbx + rdx * 8)))?;
            if tag == 0x05 {
                go(a.mov(byte_ptr(rax), cl))?;
            } else {
                go(a.mov(qword_ptr(rax), rcx))?;
            }
        }
    }
    finish(a, dispatch)
}

fn lea_sib(a: &mut CodeAssembler, dispatch: &mut CodeLabel, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut no_base = a.create_label();
    let mut no_index = a.create_label();
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, r9d, fail)?;
    go(a.movzx(ecx, byte_ptr(r12 + 2i32)))?;
    go(a.movsxd(r8, dword_ptr(r12 + 5i32)))?;
    go(a.cmp(cl, 0xffu32))?;
    go(a.je(no_base))?;
    bound_slot(a, ecx, fail)?;
    go(a.add(r8, qword_ptr(rbx + rcx * 8)))?;
    go(a.set_label(&mut no_base))?;
    go(a.movzx(ecx, byte_ptr(r12 + 3i32)))?;
    go(a.cmp(cl, 0xffu32))?;
    go(a.je(no_index))?;
    bound_slot(a, ecx, fail)?;
    go(a.mov(rax, qword_ptr(rbx + rcx * 8)))?;
    go(a.movzx(ecx, byte_ptr(r12 + 4i32)))?;
    go(a.imul_2(rax, rcx))?;
    go(a.add(r8, rax))?;
    go(a.set_label(&mut no_index))?;
    go(a.mov(qword_ptr(rbx + r9 * 8), r8))?;
    finish(a, dispatch)
}

fn not_op(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    alt: bool,
    fail: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, ecx, fail)?;
    if alt {
        go(a.mov(r15, qword_ptr(rbx + rcx * 8)))?;
        go(a.not(r15))?;
        go(a.mov(rax, r15))?;
        go(a.mov(qword_ptr(rbx + rcx * 8), rax))?;
    } else {
        go(a.mov(rax, qword_ptr(rbx + rcx * 8)))?;
        go(a.not(rax))?;
        go(a.mov(qword_ptr(rbx + rcx * 8), rax))?;
    }
    finish(a, dispatch)
}

fn neg_op(a: &mut CodeAssembler, dispatch: &mut CodeLabel, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, ecx, fail)?;
    go(a.mov(rax, qword_ptr(rbx + rcx * 8)))?;
    go(a.neg(rax))?;
    go(a.mov(qword_ptr(rbx + rcx * 8), rax))?;
    store_flags(a)?;
    finish(a, dispatch)
}

fn shift_op(
    a: &mut CodeAssembler,
    tag: u8,
    dispatch: &mut CodeLabel,
    fail: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut nonzero = a.create_label();
    let mut done = a.create_label();
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, r9d, fail)?;
    go(a.movzx(ecx, byte_ptr(r12 + 2i32)))?;
    go(a.and(ecx, 0x3fi32))?;
    go(a.test(ecx, ecx))?;
    go(a.jnz(nonzero))?;
    go(a.jmp(done))?;
    go(a.set_label(&mut nonzero))?;
    if tag >= 0x2b {
        restore_flags(a)?;
    }
    go(a.mov(rax, qword_ptr(rbx + r9 * 8)))?;
    match tag {
        0x28 => go(a.shl(rax, cl))?,
        0x29 => go(a.shr(rax, cl))?,
        0x2a => go(a.sar(rax, cl))?,
        0x2b => go(a.rol(rax, cl))?,
        0x2c => go(a.ror(rax, cl))?,
        _ => return Err(msg("shift handler is missing")),
    }
    go(a.mov(qword_ptr(rbx + r9 * 8), rax))?;
    store_flags(a)?;
    go(a.set_label(&mut done))?;
    finish(a, dispatch)
}

fn lea_rva(a: &mut CodeAssembler, dispatch: &mut CodeLabel, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, r9d, fail)?;
    go(a.mov(eax, dword_ptr(r12 + 2i32)))?;
    go(a.add(rax, qword_ptr(rbx + FRAME_IMAGE)))?;
    go(a.mov(qword_ptr(rbx + r9 * 8), rax))?;
    finish(a, dispatch)
}

fn compare_rr(
    a: &mut CodeAssembler,
    tag: u8,
    dispatch: &mut CodeLabel,
    fail: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    go(a.movzx(edx, byte_ptr(r12 + 2i32)))?;
    bound_slot(a, r9d, fail)?;
    bound_slot(a, edx, fail)?;
    go(a.mov(rax, qword_ptr(rbx + r9 * 8)))?;
    go(a.mov(r8, qword_ptr(rbx + rdx * 8)))?;
    if tag == 0x20 {
        go(a.cmp(rax, r8))?;
    } else {
        go(a.test(rax, r8))?;
    }
    store_flags(a)?;
    finish(a, dispatch)
}

fn inc_dec(
    a: &mut CodeAssembler,
    tag: u8,
    dispatch: &mut CodeLabel,
    fail: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    restore_flags(a)?;
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, r9d, fail)?;
    go(a.mov(rax, qword_ptr(rbx + r9 * 8)))?;
    if tag == 0x26 {
        go(a.inc(rax))?;
    } else {
        go(a.dec(rax))?;
    }
    go(a.mov(qword_ptr(rbx + r9 * 8), rax))?;
    store_flags(a)?;
    finish(a, dispatch)
}

fn div(a: &mut CodeAssembler, dispatch: &mut CodeLabel, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, ecx, fail)?;
    go(a.mov(r8, qword_ptr(rbx + rcx * 8)))?;
    load_arch(a, 0, rax)?;
    load_arch(a, 2, rdx)?;
    go(a.div(r8))?;
    go(a.mov(r10, rax))?;
    load_arch_index(a, 0, r11d)?;
    go(a.mov(qword_ptr(rbx + r11 * 8), r10))?;
    go(a.mov(r10, rdx))?;
    load_arch_index(a, 2, r11d)?;
    go(a.mov(qword_ptr(rbx + r11 * 8), r10))?;
    finish(a, dispatch)
}

fn push_pop(
    a: &mut CodeAssembler,
    tag: u8,
    dispatch: &mut CodeLabel,
    fail: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, ecx, fail)?;
    load_arch_index(a, 4, r11d)?;
    if tag == 0x30 {
        // Update rsp first so `push rsp` stores the new stack pointer, matching bc_push.
        go(a.mov(rax, qword_ptr(rbx + r11 * 8)))?;
        go(a.sub(rax, 8i32))?;
        go(a.mov(qword_ptr(rbx + r11 * 8), rax))?;
        go(a.mov(r8, qword_ptr(rbx + rcx * 8)))?;
        go(a.mov(qword_ptr(rax), r8))?;
    } else {
        // Write the destination before rsp so `pop rsp` keeps sp+8, matching bc_pop.
        go(a.mov(rax, qword_ptr(rbx + r11 * 8)))?;
        go(a.mov(r8, qword_ptr(rax)))?;
        go(a.mov(qword_ptr(rbx + rcx * 8), r8))?;
        go(a.add(rax, 8i32))?;
        go(a.mov(qword_ptr(rbx + r11 * 8), rax))?;
    }
    finish(a, dispatch)
}

fn call_rva(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    fail: &mut CodeLabel,
    calls: &CodeLabel,
    bind_ctx: CodeLabel,
    agent_begin: Option<(CodeLabel, CodeLabel)>,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut scan = a.create_label();
    let mut found = a.create_label();
    go(a.mov(eax, dword_ptr(r12 + 1i32)))?;
    go(a.lea(r11, qword_ptr(*calls)))?;
    go(a.mov(r11, qword_ptr(r11)))?;
    go(a.mov(ecx, dword_ptr(r11)))?;
    go(a.add(r11, 4i32))?;
    go(a.set_label(&mut scan))?;
    go(a.cmp(dword_ptr(r11), eax))?;
    go(a.je(found))?;
    go(a.add(r11, 16i32))?;
    go(a.dec(ecx))?;
    go(a.jnz(scan))?;
    go(a.jmp(*fail))?;
    go(a.set_label(&mut found))?;
    load_depth(a)?;
    // exec_depth rejects a callee whose depth is above 32, so the caller stops at 31.
    go(a.cmp(rdx, CALL_DEPTH_LIMIT as i32))?;
    go(a.jae(*fail))?;
    go(a.inc(r14))?;
    go(a.imul_3(r10, rdx, 16i32))?;
    go(a.lea(rax, qword_ptr(rbx + FRAME_CALLS)))?;
    go(a.add(rax, r10))?;
    go(a.mov(qword_ptr(rax), r14))?;
    go(a.mov(qword_ptr(rax + 8i32), r13))?;
    // The callee reuses this runtime when it calls itself. Park the caller's key
    // and fold, then start the callee from the block-0 key.
    save_weave(a)?;
    // Fresh private file for the callee. Architectural slots stay, as in exec_image.
    move_private_slots(a, false)?;
    go(a.inc(rdx))?;
    store_depth(a)?;
    enter_callee(a, dispatch, bind_ctx, agent_begin, *fail)?;
    Ok(())
}

fn enter_callee(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    bind_ctx: CodeLabel,
    agent_begin: Option<(CodeLabel, CodeLabel)>,
    fail: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    // `r11` still addresses the call-table record.
    go(a.mov(r14d, dword_ptr(r11 + 4i32)))?;
    go(a.mov(r13, qword_ptr(r11 + 8i32)))?;
    call_bind_context(a, bind_ctx, fail)?;
    if let Some((begin, drop_window)) = agent_begin {
        go(a.call(drop_window))?;
        on_work_stack(a)?;
        go(a.call(begin))?;
        off_work_stack(a)?;
    }
    reset_weave(a, None)?;
    super::edge::goto(a, dispatch)
}

fn call_reg(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    frame_hold: &CodeLabel,
    target_hold: &CodeLabel,
    drop_window: CodeLabel,
    fail: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, r9d, fail)?;
    go(a.mov(rax, qword_ptr(rbx + r9 * 8)))?;
    // Indirect call keeps guest rax. The frame pointer is parked beside the target because
    // the callee may overwrite rbx.
    go(a.mov(qword_ptr(*target_hold), rax))?;
    go(a.mov(qword_ptr(*frame_hold), rbx))?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_R12), r12))?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_R13), r13))?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_R14), r14))?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_RBX), rbx))?;
    spill_arch(a)?;
    // The plaintext is still in the cache. Seal it before the guest runs.
    go(a.call(drop_window))?;
    load_spill(a)?;
    go(a.call(qword_ptr(*target_hold)))?;
    save_spill(a, frame_hold, target_hold)?;
    restore_vm(a)?;
    finish(a, dispatch)
}

fn call_reg_external(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    bind_ctx: CodeLabel,
    drop_window: CodeLabel,
    fail: CodeLabel,
) -> Result<()> {
    const TARGET: i32 = 0x1a0;
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, r9d, fail)?;
    go(a.mov(rax, qword_ptr(rbx + r9 * 8)))?;
    // mov gs:[TARGET], rax
    emit_gs_absolute(a, &[0x65, 0x48, 0x89, 0x04, 0x25], TARGET)?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_R12), r12))?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_R13), r13))?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_R14), r14))?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_RBX), rbx))?;
    spill_arch(a)?;
    go(a.call(drop_window))?;
    load_spill(a)?;
    // call qword ptr gs:[TARGET]
    emit_gs_absolute(a, &[0x65, 0xff, 0x14, 0x25], TARGET)?;
    go(a.push(rax))?;
    // mov rax, gs:[GS_FRAME_PTR]
    emit_gs_absolute(a, &[0x65, 0x48, 0x8b, 0x04, 0x25], crate::vm::GS_FRAME_PTR)?;
    save_host_spill(a)?;
    restore_vm(a)?;
    call_bind_context(a, bind_ctx, fail)?;
    finish(a, dispatch)
}

fn emit_gs_absolute(a: &mut CodeAssembler, opcode: &[u8], disp: i32) -> Result<()> {
    let mut instruction = opcode.to_vec();
    instruction.extend_from_slice(&disp.to_le_bytes());
    a.db(&instruction).map_err(ice)
}

fn call_reg_pe(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    bind_ctx: CodeLabel,
    drop_window: CodeLabel,
    fail: CodeLabel,
    resume: &mut CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, r9d, fail)?;
    go(a.mov(rax, qword_ptr(rbx + r9 * 8)))?;
    go(a.mov(qword_ptr(rbx + FRAME_TARGET), rax))?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_R12), r12))?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_R13), r13))?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_R14), r14))?;
    go(a.mov(qword_ptr(rbx + FRAME_SAVED_RBX), rbx))?;
    spill_arch(a)?;
    on_work_stack(a)?;
    go(a.call(drop_window))?;
    off_work_stack(a)?;
    // Both transfer registers are Win64 caller-volatile. The bridge's call
    // uses the input function's established stack and shadow space.
    super::pe_unwind::emit_select_bridge(a, fail)?;
    go(a.mov(r11, qword_ptr(rbx + FRAME_TARGET)))?;
    load_spill(a)?;
    go(a.jmp(r10))?;
    go(a.set_label(resume))?;
    save_spill_pe(a)?;
    restore_vm(a)?;
    call_bind_context(a, bind_ctx, fail)?;
    finish(a, dispatch)
}

fn save_spill_pe(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.push(rax))?;
    super::chain::emit_load_active_pe_frame(a)?;
    save_host_spill(a)
}

fn save_host_spill(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    save_spill_registers(a)?;
    go(a.lea(rcx, qword_ptr(rsp + 8i32)))?;
    go(a.mov(qword_ptr(rax + (FRAME_SPILL + 32)), rcx))?;
    go(a.pop(rcx))?;
    go(a.mov(qword_ptr(rax + FRAME_SPILL), rcx))?;
    go(a.mov(rbx, rax))?;
    Ok(())
}

fn load_spill(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    for (reg, offset) in [
        (rax, 0),
        (rcx, 8),
        (rdx, 16),
        (rbp, 40),
        (rsi, 48),
        (rdi, 56),
        (r8, 64),
        (r9, 72),
        (r10, 80),
        (r11, 88),
        (r12, 96),
        (r13, 104),
        (r14, 112),
        (r15, 120),
        (rsp, 32),
    ] {
        if (reg != r10 && reg != r11) || !super::chain::pe_tls_bound() {
            go(a.mov(reg, qword_ptr(rbx + (FRAME_SPILL + offset))))?;
        }
    }
    go(a.mov(rbx, qword_ptr(rbx + (FRAME_SPILL + 24))))?;
    Ok(())
}

fn save_spill(
    a: &mut CodeAssembler,
    frame_hold: &CodeLabel,
    target_hold: &CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(qword_ptr(*target_hold), rax))?;
    go(a.mov(rax, qword_ptr(*frame_hold)))?;
    save_spill_registers(a)?;
    go(a.mov(qword_ptr(rax + (FRAME_SPILL + 32)), rsp))?;
    go(a.mov(rcx, qword_ptr(*target_hold)))?;
    go(a.mov(qword_ptr(rax + FRAME_SPILL), rcx))?;
    go(a.mov(rbx, rax))?;
    Ok(())
}

fn save_spill_registers(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    for (reg, offset) in [
        (rcx, 8),
        (rdx, 16),
        (rbx, 24),
        (rbp, 40),
        (rsi, 48),
        (rdi, 56),
        (r8, 64),
        (r9, 72),
        (r10, 80),
        (r11, 88),
        (r12, 96),
        (r13, 104),
        (r14, 112),
        (r15, 120),
    ] {
        go(a.mov(qword_ptr(rax + (FRAME_SPILL + offset)), reg))?;
    }
    Ok(())
}

fn restore_vm(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(r12, qword_ptr(rbx + FRAME_SAVED_R12)))?;
    go(a.mov(r13, qword_ptr(rbx + FRAME_SAVED_R13)))?;
    go(a.mov(r14, qword_ptr(rbx + FRAME_SAVED_R14)))?;
    fill_arch(a)?;
    go(a.mov(rbx, qword_ptr(rbx + FRAME_SAVED_RBX)))?;
    Ok(())
}

fn ret_op(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    close_chain: CodeLabel,
    bind_ctx: CodeLabel,
    leave_nest: CodeLabel,
    drop_window: CodeLabel,
    fail: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut nested = a.create_label();
    // Close this function's weave before either epilogue publishes a result.
    // The call runs on the private stack so it does not overwrite a guest push.
    on_work_stack(a)?;
    go(a.call(close_chain))?;
    off_work_stack(a)?;
    check_native_status(a, fail)?;
    go(a.call(drop_window))?;
    load_depth(a)?;
    go(a.test(rdx, rdx))?;
    go(a.jnz(nested))?;
    go(a.call(leave_nest))?;
    gather_and_retire(a)?;
    go(a.set_label(&mut nested))?;
    resume_caller(a, dispatch, bind_ctx, fail)?;
    Ok(())
}

fn gather_and_retire(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut gather = a.create_label();
    let mut gathered = a.create_label();
    go(a.xor(ecx, ecx))?;
    go(a.set_label(&mut gather))?;
    go(a.cmp(ecx, 16u32))?;
    go(a.jae(gathered))?;
    go(a.movzx(eax, byte_ptr(r13 + rcx + RT_SLOTS)))?;
    go(a.mov(rdx, qword_ptr(rbx + rax * 8)))?;
    go(a.mov(qword_ptr(rbx + rcx * 8 + FRAME_SPILL), rdx))?;
    go(a.inc(ecx))?;
    go(a.jmp(gather))?;
    go(a.set_label(&mut gathered))?;
    retire_guest(a)
}

fn resume_caller(
    a: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    bind_ctx: CodeLabel,
    fail: CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.dec(rdx))?;
    store_depth(a)?;
    go(a.imul_3(r10, rdx, 16i32))?;
    go(a.lea(rax, qword_ptr(rbx + FRAME_CALLS)))?;
    go(a.add(rax, r10))?;
    go(a.mov(qword_ptr(rbx + FRAME_TARGET), rax))?;
    move_private_slots(a, true)?;
    go(a.mov(rax, qword_ptr(rbx + FRAME_TARGET)))?;
    go(a.mov(r14, qword_ptr(rax)))?;
    go(a.mov(r13, qword_ptr(rax + 8i32)))?;
    call_bind_context(a, bind_ctx, fail)?;
    restore_weave(a)?;
    super::edge::goto(a, dispatch)
}

fn load_depth(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    super::chain::emit_load_r8(a)?;
    go(a.mov(rdx, qword_ptr(r8 + CTX_DEPTH)))?;
    Ok(())
}

fn store_depth(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    super::chain::emit_load_r8(a)?;
    go(a.mov(qword_ptr(r8 + CTX_DEPTH), rdx))?;
    Ok(())
}

fn call_bind_context(a: &mut CodeAssembler, bind: CodeLabel, fail: CodeLabel) -> Result<()> {
    on_work_stack(a)?;
    a.call(bind).map_err(ice)?;
    off_work_stack(a)?;
    check_native_status(a, fail)
}

fn check_native_status(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    if super::chain::pe_tls_bound() {
        a.test(eax, eax).map_err(ice)?;
        a.jnz(fail).map_err(ice)?;
    }
    Ok(())
}

fn on_work_stack(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(qword_ptr(rbx + super::SAVED_RSP), rsp))?;
    go(a.lea(rsp, qword_ptr(rbx + super::WORK_STACK)))?;
    Ok(())
}

fn off_work_stack(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(rsp, qword_ptr(rbx + super::SAVED_RSP)))?;
    Ok(())
}

/// Return `0xbad1` without abandoning the caller's callee-saved registers.
///
/// `rbx` is the frame and `r13` is still the runtime. The spill holds the
/// registers saved at entry; the rsp slot is the guest stack.
pub(super) fn emit_fail_return(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(eax, 0xbad1u32))?;
    go(a.movzx(ecx, byte_ptr(r13 + (RT_SLOTS + 4))))?;
    go(a.mov(rdx, qword_ptr(rbx + rcx * 8)))?;
    go(a.mov(rbp, qword_ptr(rbx + (FRAME_SPILL + 40))))?;
    if super::chain::pe_tls_bound() {
        go(a.mov(rsi, qword_ptr(rbx + (FRAME_SPILL + 48))))?;
        go(a.mov(rdi, qword_ptr(rbx + (FRAME_SPILL + 56))))?;
    }
    go(a.mov(r12, qword_ptr(rbx + (FRAME_SPILL + 96))))?;
    go(a.mov(r13, qword_ptr(rbx + (FRAME_SPILL + 104))))?;
    go(a.mov(r14, qword_ptr(rbx + (FRAME_SPILL + 112))))?;
    go(a.mov(r15, qword_ptr(rbx + (FRAME_SPILL + 120))))?;
    go(a.mov(rsp, rdx))?;
    go(a.mov(rbx, qword_ptr(rbx + (FRAME_SPILL + 24))))?;
    go(a.ret())?;
    Ok(())
}

fn retire_guest(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.mov(rax, qword_ptr(rbx + FRAME_SPILL)))?;
    go(a.mov(rcx, qword_ptr(rbx + (FRAME_SPILL + 8))))?;
    go(a.mov(rdx, qword_ptr(rbx + (FRAME_SPILL + 16))))?;
    go(a.mov(rbp, qword_ptr(rbx + (FRAME_SPILL + 40))))?;
    go(a.mov(rsi, qword_ptr(rbx + (FRAME_SPILL + 48))))?;
    go(a.mov(rdi, qword_ptr(rbx + (FRAME_SPILL + 56))))?;
    go(a.mov(r8, qword_ptr(rbx + (FRAME_SPILL + 64))))?;
    go(a.mov(r9, qword_ptr(rbx + (FRAME_SPILL + 72))))?;
    go(a.mov(r10, qword_ptr(rbx + (FRAME_SPILL + 80))))?;
    go(a.mov(r11, qword_ptr(rbx + (FRAME_SPILL + 88))))?;
    go(a.mov(r12, qword_ptr(rbx + (FRAME_SPILL + 96))))?;
    go(a.mov(r13, qword_ptr(rbx + (FRAME_SPILL + 104))))?;
    go(a.mov(r14, qword_ptr(rbx + (FRAME_SPILL + 112))))?;
    go(a.mov(r15, qword_ptr(rbx + (FRAME_SPILL + 120))))?;
    go(a.mov(rsp, qword_ptr(rbx + (FRAME_SPILL + 32))))?;
    go(a.mov(rbx, qword_ptr(rbx + (FRAME_SPILL + 24))))?;
    go(a.ret())?;
    Ok(())
}

/// Save or restore the caller's private slots at depth `rdx`.
///
/// A slot is private when the runtime map does not name it as an architectural register.
/// `restore == false` copies those slots aside and zeroes them for the callee.
fn save_weave(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.imul_3(r10, rdx, WEAVE_FRAME))?;
    super::chain::emit_load_r8(a)?;
    go(a.lea(rax, qword_ptr(r8 + CHAIN_SAVE)))?;
    go(a.add(rax, r10))?;
    for word in 0..4i32 {
        go(a.mov(rcx, qword_ptr(r8 + (word * 8))))?;
        go(a.mov(qword_ptr(rax + (word * 8)), rcx))?;
    }
    go(a.mov(ecx, dword_ptr(r8 + CHAIN_FOLD)))?;
    go(a.mov(dword_ptr(rax + CHAIN_FOLD), ecx))?;
    Ok(())
}

pub(super) fn reset_weave(
    a: &mut CodeAssembler,
    mut morph: Option<&mut super::morph::Morph>,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    // Running::start begins every call at the block-0 key, including a second
    // entry after close_chain left the terminal key and fold == block count.
    // Keeping that cursor replays an arm close_chain never stored a key for.
    // Stamps are only for the external entry: r11 is dead there. The trampoline
    // still holds the frame in r11, so it passes None. rax holds the chain.
    super::chain::emit_load_rax(a)?;
    for word in 0..4i32 {
        stamp_reset(a, &mut morph)?;
        go(a.mov(rcx, qword_ptr(r13 + (RT_MASTER + word * 8))))?;
        stamp_reset(a, &mut morph)?;
        go(a.mov(qword_ptr(rax + (word * 8)), rcx))?;
    }
    stamp_reset(a, &mut morph)?;
    go(a.mov(dword_ptr(rax + CHAIN_FOLD), 0u32))?;
    Ok(())
}

fn stamp_reset(a: &mut CodeAssembler, morph: &mut Option<&mut super::morph::Morph>) -> Result<()> {
    if let Some(morph) = morph {
        morph.stamp(a)?;
    }
    Ok(())
}

fn restore_weave(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.imul_3(r10, rdx, WEAVE_FRAME))?;
    super::chain::emit_load_r8(a)?;
    go(a.lea(rax, qword_ptr(r8 + CHAIN_SAVE)))?;
    go(a.add(rax, r10))?;
    for word in 0..4i32 {
        go(a.mov(rcx, qword_ptr(rax + (word * 8))))?;
        go(a.mov(qword_ptr(r8 + (word * 8)), rcx))?;
    }
    go(a.mov(ecx, dword_ptr(rax + CHAIN_FOLD)))?;
    go(a.mov(dword_ptr(r8 + CHAIN_FOLD), ecx))?;
    Ok(())
}

fn move_private_slots(a: &mut CodeAssembler, restore: bool) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut mask = a.create_label();
    let mut slots = a.create_label();
    let mut slots_done = a.create_label();
    let mut advance = a.create_label();
    go(a.imul_3(r10, rdx, PRIVATE_STRIDE))?;
    go(a.lea(rdi, qword_ptr(rbx + FRAME_FILE_STACK)))?;
    go(a.add(rdi, r10))?;
    // One bit per physical slot. Architectural registers stay put; the other 32 are private.
    go(a.xor(r10d, r10d))?;
    go(a.xor(ecx, ecx))?;
    go(a.set_label(&mut mask))?;
    go(a.cmp(ecx, 16u32))?;
    go(a.jae(slots))?;
    go(a.movzx(eax, byte_ptr(r13 + rcx + RT_SLOTS)))?;
    go(a.bts(r10, rax))?;
    go(a.inc(ecx))?;
    go(a.jmp(mask))?;
    go(a.set_label(&mut slots))?;
    go(a.xor(ecx, ecx))?;
    go(a.xor(r8d, r8d))?;
    let mut next = a.create_label();
    go(a.set_label(&mut next))?;
    go(a.cmp(ecx, SLOT_COUNT as u32))?;
    go(a.jae(slots_done))?;
    go(a.bt(r10, rcx))?;
    go(a.jc(advance))?;
    if restore {
        go(a.mov(rax, qword_ptr(rdi + r8 * 8)))?;
        go(a.mov(qword_ptr(rbx + rcx * 8), rax))?;
    } else {
        go(a.mov(rax, qword_ptr(rbx + rcx * 8)))?;
        go(a.mov(qword_ptr(rdi + r8 * 8), rax))?;
        go(a.xor(eax, eax))?;
        go(a.mov(qword_ptr(rbx + rcx * 8), rax))?;
    }
    go(a.inc(r8d))?;
    go(a.set_label(&mut advance))?;
    go(a.inc(ecx))?;
    go(a.jmp(next))?;
    go(a.set_label(&mut slots_done))?;
    Ok(())
}

fn spill_arch(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut gather = a.create_label();
    let mut gathered = a.create_label();
    go(a.xor(ecx, ecx))?;
    go(a.set_label(&mut gather))?;
    go(a.cmp(ecx, 16u32))?;
    go(a.jae(gathered))?;
    go(a.movzx(eax, byte_ptr(r13 + rcx + RT_SLOTS)))?;
    go(a.mov(rdx, qword_ptr(rbx + rax * 8)))?;
    go(a.mov(qword_ptr(rbx + rcx * 8 + FRAME_SPILL), rdx))?;
    go(a.inc(ecx))?;
    go(a.jmp(gather))?;
    go(a.set_label(&mut gathered))?;
    Ok(())
}

fn fill_arch(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut scatter = a.create_label();
    let mut scattered = a.create_label();
    go(a.xor(ecx, ecx))?;
    go(a.set_label(&mut scatter))?;
    go(a.cmp(ecx, 16u32))?;
    go(a.jae(scattered))?;
    go(a.mov(rdx, qword_ptr(rbx + rcx * 8 + FRAME_SPILL)))?;
    go(a.movzx(eax, byte_ptr(r13 + rcx + RT_SLOTS)))?;
    go(a.mov(qword_ptr(rbx + rax * 8), rdx))?;
    go(a.inc(ecx))?;
    go(a.jmp(scatter))?;
    go(a.set_label(&mut scattered))?;
    Ok(())
}

fn variant_bit(tag: u8) -> u32 {
    VARIANT_OPCODES
        .iter()
        .position(|item| *item == tag)
        .expect("variant opcode") as u32
}

fn with_variant(
    a: &mut CodeAssembler,
    bit: u32,
    dispatch: &mut CodeLabel,
    v0: impl FnOnce(&mut CodeAssembler) -> Result<()>,
    v1: impl FnOnce(&mut CodeAssembler) -> Result<()>,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut alt = a.create_label();
    let mut join = a.create_label();
    go(a.mov(eax, dword_ptr(r13 + RT_MIX)))?;
    if bit > 0 {
        go(a.shr(eax, bit))?;
    }
    go(a.test(al, 1u32))?;
    go(a.jnz(alt))?;
    v0(a)?;
    go(a.jmp(join))?;
    go(a.set_label(&mut alt))?;
    v1(a)?;
    go(a.set_label(&mut join))?;
    finish(a, dispatch)
}

fn mov_rr(a: &mut CodeAssembler, wide: bool, alt: bool, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    go(a.movzx(edx, byte_ptr(r12 + 2i32)))?;
    bound_slot(a, ecx, fail)?;
    bound_slot(a, edx, fail)?;
    if wide {
        go(a.mov(r10, qword_ptr(rbx + rdx * 8)))?;
        go(a.mov(r11, r10))?;
        go(a.mov(rax, r11))?;
        go(a.mov(r11, rax))?;
        if alt {
            go(a.mov(r15, r11))?;
            go(a.mov(r11, r15))?;
        }
        go(a.mov(qword_ptr(rbx + rcx * 8), r11))?;
    } else if alt {
        go(a.mov(r15, qword_ptr(rbx + rdx * 8)))?;
        go(a.mov(rax, r15))?;
        go(a.mov(qword_ptr(rbx + rcx * 8), rax))?;
    } else {
        go(a.mov(rax, qword_ptr(rbx + rdx * 8)))?;
        go(a.mov(qword_ptr(rbx + rcx * 8), rax))?;
    }
    Ok(())
}

fn mov_ri(a: &mut CodeAssembler, wide: bool, alt: bool, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(ecx, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, ecx, fail)?;
    if wide {
        go(a.lea(r10, qword_ptr(r12 + 2i32)))?;
        go(a.mov(rax, qword_ptr(r10)))?;
        go(a.mov(r11, rax))?;
        go(a.mov(rax, r11))?;
        go(a.mov(r10, rax))?;
    } else if alt {
        go(a.mov(r15, qword_ptr(r12 + 2i32)))?;
        go(a.mov(rax, r15))?;
    } else {
        go(a.mov(rax, qword_ptr(r12 + 2i32)))?;
    }
    if alt && wide {
        go(a.mov(r15, rax))?;
        go(a.mov(rax, r15))?;
    }
    go(a.mov(qword_ptr(rbx + rcx * 8), rax))?;
    Ok(())
}

fn alu_imm(a: &mut CodeAssembler, tag: u8, wide: bool, fail: CodeLabel) -> Result<()> {
    if !wide {
        return binary(a, tag, true, fail);
    }
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.movzx(r9d, byte_ptr(r12 + 1i32)))?;
    bound_slot(a, r9d, fail)?;
    go(a.mov(r11, qword_ptr(rbx + r9 * 8)))?;
    go(a.mov(r10, r11))?;
    go(a.mov(r11, r10))?;
    go(a.movsxd(r8, dword_ptr(r12 + 2i32)))?;
    if tag == 0x15 {
        go(a.add(r11, r8))?;
    } else {
        go(a.xor(r11, r8))?;
    }
    go(a.mov(r10, r11))?;
    go(a.mov(r11, r10))?;
    store_flags(a)?;
    go(a.mov(qword_ptr(rbx + r9 * 8), r11))?;
    Ok(())
}

fn load_arch(a: &mut CodeAssembler, arch: i32, dest: AsmRegister64) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    load_arch_index(a, arch, r11d)?;
    go(a.mov(dest, qword_ptr(rbx + r11 * 8)))?;
    Ok(())
}

fn load_arch_index(a: &mut CodeAssembler, arch: i32, dest: AsmRegister32) -> Result<()> {
    a.movzx(dest, byte_ptr(r13 + (RT_SLOTS + arch)))
        .map_err(ice)
}
