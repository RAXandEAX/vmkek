//! Native host-call PCs for the Windows x64 unwind table.
use iced_x86::code_asm::*;

use crate::error::{msg, Result};
use crate::vm::{
    CTX_LEVEL, FILE_STACK_BYTES, FRAME_BYTES, FRAME_SPILL, RUNTIME_WINDOW, TRAMP_SLOTS,
};

use super::{chain, ice};

pub(crate) const HOST_BRIDGE_LEN: usize = 9;

const ENTRY_SAVE_AT: i32 = (FRAME_BYTES + FILE_STACK_BYTES) as i32;
// Rbx comes first so its restore can be delayed until every frame read is done.
const ENTRY_REGS: [(AsmRegister64, i32); 9] = [
    (rbx, 24),
    (rsp, 32),
    (rbp, 40),
    (rsi, 48),
    (rdi, 56),
    (r12, 96),
    (r13, 104),
    (r14, 112),
    (r15, 120),
];
pub(super) const ENTRY_SAVE_BYTES: usize = ENTRY_REGS.len() * 8;

pub(super) fn emit_save_entry(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    for (index, &(_, spill)) in ENTRY_REGS.iter().enumerate() {
        go(a.mov(rax, qword_ptr(r11 + FRAME_SPILL + spill)))?;
        go(a.mov(qword_ptr(r11 + ENTRY_SAVE_AT + index as i32 * 8), rax))?;
    }
    Ok(())
}

pub(super) fn emit_fail_return(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    for (index, &(reg, _)) in ENTRY_REGS.iter().enumerate().skip(1) {
        go(a.mov(reg, qword_ptr(rbx + ENTRY_SAVE_AT + index as i32 * 8)))?;
    }
    go(a.mov(rbx, qword_ptr(rbx + ENTRY_SAVE_AT)))?;
    go(a.mov(eax, 0xbad1u32))?;
    go(a.ret())
}

pub(crate) fn host_bridge(origin: u64, resume: u64) -> Result<[u8; HOST_BRIDGE_LEN]> {
    let next = i128::from(origin) + HOST_BRIDGE_LEN as i128;
    let relative = i32::try_from(i128::from(resume) - next)
        .map_err(|_| msg("native host-call bridge target is out of range"))?;
    // call r11; nop; jmp rel32. The NOP is the precise native return PC and
    // keeps Windows from treating it as the start of an epilogue.
    let mut bytes = [0x41, 0xff, 0xd3, 0x90, 0xe9, 0, 0, 0, 0];
    bytes[5..].copy_from_slice(&relative.to_le_bytes());
    Ok(bytes)
}

pub(super) fn emit_select_bridge(a: &mut CodeAssembler, fail: CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let layout = chain::pe_bridges()?;
    let mut done = a.create_label();
    // Match the exact runtime address. Bridge targets come only from the
    // immutable code, never from an opened runtime or cache.
    for index in 0..layout.count as u64 {
        let mut next = a.create_label();
        let runtime = layout.runtime + index * RUNTIME_WINDOW;
        let bridge = layout.base + index * HOST_BRIDGE_LEN as u64;
        crate::loader::emit_image_address(a, iced_x86::Register::RAX, runtime)?;
        go(a.cmp(r13, rax))?;
        go(a.jne(next))?;
        crate::loader::emit_image_address(a, iced_x86::Register::R10, bridge)?;
        go(a.jmp(done))?;
        go(a.set_label(&mut next))?;
    }
    go(a.jmp(fail))?;
    go(a.set_label(&mut done))
}

pub(super) fn emit_cleanup(a: &mut CodeAssembler, label: &mut CodeLabel) -> Result<()> {
    const EXCEPTION_UNWIND_MASK: i32 = 0x06;
    const EXCEPTION_CONTINUE_SEARCH: u32 = 1;

    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut done = a.create_label();
    go(a.set_label(label))?;
    go(a.test(dword_ptr(rcx + 4i32), EXCEPTION_UNWIND_MASK))?;
    go(a.jz(done))?;
    chain::emit_load_rax(a)?;
    go(a.test(rax, rax))?;
    go(a.jz(done))?;
    go(a.cmp(dword_ptr(rax + CTX_LEVEL), 0i32))?;
    go(a.je(done))?;
    go(a.cmp(dword_ptr(rax + CTX_LEVEL), (TRAMP_SLOTS + 1) as u32))?;
    go(a.ja(done))?;
    // The callback's EstablisherFrame must match this suspended host call.
    chain::emit_load_active_pe_frame(a)?;
    go(a.cmp(qword_ptr(rax + (FRAME_SPILL + 32)), rdx))?;
    go(a.jne(done))?;
    // Keep RSI intact for the OS caller. The emitted leave helper uses only
    // RSI and volatile registers, and does not call a subroutine.
    go(a.mov(r9, rsi))?;
    chain::emit_leave_nest(a)?;
    go(a.mov(rsi, r9))?;
    chain::emit_clear_idle_key(a)?;
    go(a.set_label(&mut done))?;
    go(a.mov(eax, EXCEPTION_CONTINUE_SEARCH))?;
    go(a.ret())
}

#[cfg(test)]
mod tests {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, Register};

    use super::*;
    use crate::emu::{bare, Policy, Region};

    #[test]
    fn bridge_has_a_precise_non_epilogue_return_pc() {
        let origin = 0x1400_01000;
        let resume = 0x1400_18000;
        let code = host_bridge(origin, resume).unwrap();
        let rows: Vec<_> = Decoder::with_ip(64, &code, origin, DecoderOptions::NONE)
            .into_iter()
            .collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].mnemonic(), Mnemonic::Call);
        assert_eq!(rows[0].op0_register(), Register::R11);
        assert_eq!(rows[1].mnemonic(), Mnemonic::Nop);
        assert_eq!(rows[1].ip(), rows[0].next_ip());
        assert_eq!(rows[2].near_branch_target(), resume);
    }

    #[test]
    fn failure_returns_to_the_native_caller_after_a_guest_prologue() {
        const CODE: u64 = 0x400000;
        const FRAME: u64 = 0x500000;
        let mut a = CodeAssembler::new(64).unwrap();
        emit_save_entry(&mut a).unwrap();
        a.mov(rbx, r11).unwrap();
        a.sub(rsp, 0x28i32).unwrap();
        a.mov(qword_ptr(r11 + (FRAME_SPILL + 32)), rsp).unwrap();
        a.mov(qword_ptr(r11 + (FRAME_SPILL + 24)), rsp).unwrap();
        emit_fail_return(&mut a).unwrap();
        let mut model = bare(Policy::default()).unwrap();
        let entry_rsp = model.regs[4];
        model.regions.extend([
            Region {
                base: CODE,
                data: a.assemble(CODE).unwrap(),
            },
            Region {
                base: FRAME,
                data: vec![0; chain::PE_FRAME_STRIDE as usize],
            },
        ]);
        let nonvolatile = [
            (3, 24),
            (5, 40),
            (6, 48),
            (7, 56),
            (12, 96),
            (13, 104),
            (14, 112),
            (15, 120),
        ];
        model
            .write(FRAME + (FRAME_SPILL + 32) as u64, &entry_rsp.to_le_bytes())
            .unwrap();
        for (reg, spill) in nonvolatile {
            let value = (0x1111_0000u64 + reg as u64).to_le_bytes();
            model
                .write(FRAME + FRAME_SPILL as u64 + spill, &value)
                .unwrap();
        }
        model.regs[11] = FRAME;
        model.rip = CODE;
        model.run().unwrap();
        assert_eq!(model.exit_code, Some(0xbad1));
        assert_eq!(model.regs[4], entry_rsp + 8);
        for (reg, _) in nonvolatile {
            assert_eq!(model.regs[reg], 0x1111_0000 + reg as u64);
        }
    }

    #[test]
    fn cleanup_only_drops_the_tls_frame_during_phase_two() {
        assert_cleanup(0, true, 1, 1, [0xA5; 32]);
        assert_cleanup(2, false, 1, 1, [0xA5; 32]);
        assert_cleanup(2, true, 1, 0, [0; 32]);
        assert_cleanup(2, true, 2, 1, [0xC3; 32]);
    }

    fn assert_cleanup(flags: u32, matching: bool, prior: u32, level: u32, key: [u8; 32]) {
        const CODE: u64 = 0x400000;
        const TLS: u64 = 0x500000;
        const VECTOR: u64 = 0x510000;
        const INDEX: u64 = CODE + 0x400;
        const RECORD: u64 = CODE + 0x410;
        const ESTABLISHER: u64 = 0x1_0000;
        let frame = TLS
            + chain::PE_FRAME_BASE as u64
            + u64::from(prior - 1) * chain::PE_FRAME_STRIDE as u64;
        let _tls = chain::bind_pe_tls(INDEX, 0x10000);
        let mut a = CodeAssembler::new(64).unwrap();
        let mut cleanup = a.create_label();
        emit_cleanup(&mut a, &mut cleanup).unwrap();
        let mut bytes = a.assemble(CODE).unwrap();
        bytes.resize(0x500, 0);
        let mut model = bare(Policy::default()).unwrap();
        model.regions.extend([
            Region {
                base: CODE,
                data: bytes,
            },
            Region {
                base: TLS,
                data: vec![0; 0x10000],
            },
            Region {
                base: VECTOR,
                data: vec![0; 0x100],
            },
        ]);
        model.write(INDEX, &3u32.to_le_bytes()).unwrap();
        model.write(VECTOR + 24, &TLS.to_le_bytes()).unwrap();
        model
            .write(
                model.gs + chain::PE_TLS_VECTOR as u64,
                &VECTOR.to_le_bytes(),
            )
            .unwrap();
        model.write(RECORD + 4, &flags.to_le_bytes()).unwrap();
        model
            .write(TLS + CTX_LEVEL as u64, &prior.to_le_bytes())
            .unwrap();
        model.write(TLS, &[0xA5; 32]).unwrap();
        model
            .write(TLS + crate::vm::TRAMP_SAVE as u64, &[0xC3; 32])
            .unwrap();
        model
            .write(
                frame + (FRAME_SPILL + 32) as u64,
                &ESTABLISHER.to_le_bytes(),
            )
            .unwrap();
        model.regs[1] = RECORD;
        model.regs[2] = if matching { ESTABLISHER } else { 0x20_000 };
        model.regs[6] = 0x1234;
        model.rip = CODE;
        model.run().unwrap();
        assert_eq!(model.exit_code, Some(1));
        assert_eq!(model.regs[6], 0x1234);
        assert_eq!(
            model.read(TLS + CTX_LEVEL as u64, 4).unwrap(),
            level.to_le_bytes()
        );
        assert_eq!(model.read(TLS, 32).unwrap(), key);
    }
}
