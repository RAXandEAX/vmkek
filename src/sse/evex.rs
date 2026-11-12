//! EVEX moves of ZMM0–ZMM31 and k0–k7.
//!
//! The host stub saves the process ZMM file and opmask file, loads the guest
//! copies, runs one opcode, then writes the guest results back and restores
//! the host copies. Merge-masking and zeroing-masking stay in the opcode's
//! EVEX prefix; these moves are unmasked. Opmask moves are `kmovq` when
//! AVX512BW is present and `kmovw` otherwise. `kmovq` is not an AVX-512F
//! opcode, so an F-only host would `#UD` in the save and never retire a
//! legal ZMM instruction.

use iced_x86::{Code, Encoder, Instruction, OpKind, Register};

use crate::error::{msg, Result};

/// Bytes of one ZMM register.
pub(super) const ZMM_WIDTH: usize = 64;
/// ZMM0–ZMM31.
pub(super) const ZMM_COUNT: usize = 32;
/// Packed ZMM file: 32 × 64.
pub(super) const ZMM_BYTES: usize = ZMM_COUNT * ZMM_WIDTH;
/// Guest ZMM file sits after the host save on the ZMM page.
pub(super) const ZMM_GUEST: usize = ZMM_BYTES;
/// k0–k7, 8 bytes each.
pub(super) const K_BYTES: usize = 64;
/// Host opmask save on the tail page, after the ZMM result.
pub(super) const K_SAVE: usize = ZMM_BYTES;
/// Guest opmask image.
pub(super) const K_GUEST: usize = K_SAVE + K_BYTES;
/// Opmask image after the opcode.
pub(super) const K_RESULT: usize = K_GUEST + K_BYTES;
/// Set only after every host ZMM and opmask store has retired.
pub(super) const ZMM_MARK: u32 = 0x7C1;

pub(super) fn append_zmm(
    code: &mut Vec<u8>,
    store: bool,
    zmm: usize,
    base: usize,
    disp: u32,
) -> Result<()> {
    code.extend_from_slice(&encode_zmm(store, zmm, base, disp)?);
    Ok(())
}

pub(super) fn append_k(
    code: &mut Vec<u8>,
    store: bool,
    mask: usize,
    base: usize,
    disp: u32,
) -> Result<()> {
    code.extend_from_slice(&encode_k(store, mask, base, disp)?);
    Ok(())
}

/// Reload host ZMM from `rdi` and k0–k7 from `rsi`.
pub(super) fn append_reload(code: &mut Vec<u8>) -> Result<()> {
    move_zmms(code, 7, false, 0)?;
    move_ks(code, 6, false, 0)?;
    code.push(0xC3);
    Ok(())
}

pub(super) fn save_host(
    code: &mut Vec<u8>,
    anchor: usize,
    data: u64,
    zmm: u64,
    tail: u64,
) -> Result<()> {
    mov_abs(code, anchor, zmm);
    move_zmms(code, anchor, true, 0)?;
    mov_abs(code, anchor, tail);
    move_ks(code, anchor, true, K_SAVE as u32)?;
    mov_abs(code, anchor, data);
    mark(code, anchor, ZMM_MARK);
    Ok(())
}

pub(super) fn load_guest(
    code: &mut Vec<u8>,
    anchor: usize,
    data: u64,
    zmm: u64,
    tail: u64,
) -> Result<()> {
    mov_abs(code, anchor, zmm);
    move_zmms(code, anchor, false, ZMM_GUEST as u32)?;
    mov_abs(code, anchor, tail);
    move_ks(code, anchor, false, K_GUEST as u32)?;
    mov_abs(code, anchor, data);
    Ok(())
}

pub(super) fn store_result(code: &mut Vec<u8>, anchor: usize, data: u64, tail: u64) -> Result<()> {
    mov_abs(code, anchor, tail);
    move_zmms(code, anchor, true, 0)?;
    move_ks(code, anchor, true, K_RESULT as u32)?;
    mov_abs(code, anchor, data);
    Ok(())
}

pub(super) fn restore_host(
    code: &mut Vec<u8>,
    anchor: usize,
    data: u64,
    zmm: u64,
    tail: u64,
) -> Result<()> {
    mov_abs(code, anchor, zmm);
    move_zmms(code, anchor, false, 0)?;
    mov_abs(code, anchor, tail);
    move_ks(code, anchor, false, K_SAVE as u32)?;
    mov_abs(code, anchor, data);
    Ok(())
}

fn move_zmms(code: &mut Vec<u8>, base: usize, store: bool, disp: u32) -> Result<()> {
    for index in 0..ZMM_COUNT {
        let at = disp + (index as u32) * ZMM_WIDTH as u32;
        append_zmm(code, store, index, base, at)?;
    }
    Ok(())
}

fn move_ks(code: &mut Vec<u8>, base: usize, store: bool, disp: u32) -> Result<()> {
    for index in 0..8 {
        append_k(code, store, index, base, disp + (index as u32) * 8)?;
    }
    Ok(())
}

fn encode_zmm(store: bool, zmm: usize, base: usize, disp: u32) -> Result<Vec<u8>> {
    let mut insn = mem_insn(base, disp);
    let reg = zmm_register(zmm);
    if store {
        insn.set_code(Code::EVEX_Vmovdqu64_zmmm512_k1z_zmm);
        insn.set_op0_kind(OpKind::Memory);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(reg);
    } else {
        insn.set_code(Code::EVEX_Vmovdqu64_zmm_k1z_zmmm512);
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(reg);
        insn.set_op1_kind(OpKind::Memory);
    }
    encode(&insn)
}

/// `kmovq` moves 64 mask bits and needs AVX512BW. AVX-512F only guarantees `kmovw`.
pub(super) fn mask_is_qword() -> bool {
    super::claim::avx512bw()
}

fn encode_k(store: bool, mask: usize, base: usize, disp: u32) -> Result<Vec<u8>> {
    encode_k_width(store, mask, base, disp, mask_is_qword())
}

fn encode_k_width(
    store: bool,
    mask: usize,
    base: usize,
    disp: u32,
    qword: bool,
) -> Result<Vec<u8>> {
    let mut insn = mem_insn(base, disp);
    let reg = k_register(mask);
    insn.set_code(k_move(store, qword));
    if store {
        insn.set_op0_kind(OpKind::Memory);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(reg);
    } else {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(reg);
        insn.set_op1_kind(OpKind::Memory);
    }
    encode(&insn)
}

fn k_move(store: bool, qword: bool) -> Code {
    match (qword, store) {
        (true, true) => Code::VEX_Kmovq_m64_kr,
        (true, false) => Code::VEX_Kmovq_kr_km64,
        (false, true) => Code::VEX_Kmovw_m16_kr,
        (false, false) => Code::VEX_Kmovw_kr_km16,
    }
}

fn mem_insn(base: usize, disp: u32) -> Instruction {
    let mut insn = Instruction::default();
    insn.set_memory_base(gpr_register(base));
    insn.set_memory_index(Register::None);
    insn.set_memory_index_scale(1);
    // `1` lets the encoder pick disp8 or disp32. EVEX rejects a forced disp32.
    insn.set_memory_displ_size(1);
    insn.set_memory_displacement64(u64::from(disp));
    insn
}

fn encode(insn: &Instruction) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(64);
    encoder.encode(insn, 0).map_err(|_| msg("evex encode"))?;
    let buf = encoder.take_buffer();
    if buf.is_empty() || buf.len() > 15 {
        return Err(msg("evex encode"));
    }
    Ok(buf)
}

fn mov_abs(code: &mut Vec<u8>, reg: usize, value: u64) {
    code.push(0x48 | u8::from(reg >= 8));
    code.push(0xB8 + (reg as u8 & 7));
    code.extend_from_slice(&value.to_le_bytes());
}

fn mark(code: &mut Vec<u8>, base: usize, disp: u32) {
    if base >= 8 {
        code.push(0x41);
    }
    code.push(0xC6);
    code.push(0x80 | (base as u8 & 7));
    code.extend_from_slice(&disp.to_le_bytes());
    code.push(1);
}

fn zmm_register(index: usize) -> Register {
    const REGS: [Register; 32] = [
        Register::ZMM0,
        Register::ZMM1,
        Register::ZMM2,
        Register::ZMM3,
        Register::ZMM4,
        Register::ZMM5,
        Register::ZMM6,
        Register::ZMM7,
        Register::ZMM8,
        Register::ZMM9,
        Register::ZMM10,
        Register::ZMM11,
        Register::ZMM12,
        Register::ZMM13,
        Register::ZMM14,
        Register::ZMM15,
        Register::ZMM16,
        Register::ZMM17,
        Register::ZMM18,
        Register::ZMM19,
        Register::ZMM20,
        Register::ZMM21,
        Register::ZMM22,
        Register::ZMM23,
        Register::ZMM24,
        Register::ZMM25,
        Register::ZMM26,
        Register::ZMM27,
        Register::ZMM28,
        Register::ZMM29,
        Register::ZMM30,
        Register::ZMM31,
    ];
    REGS[index]
}

fn k_register(index: usize) -> Register {
    const REGS: [Register; 8] = [
        Register::K0,
        Register::K1,
        Register::K2,
        Register::K3,
        Register::K4,
        Register::K5,
        Register::K6,
        Register::K7,
    ];
    REGS[index]
}

fn gpr_register(index: usize) -> Register {
    const REGS: [Register; 16] = [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RBX,
        Register::RSP,
        Register::RBP,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ];
    REGS[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zmm_and_mask_moves_decode() {
        let mut code = Vec::new();
        append_zmm(&mut code, true, 31, 15, 1984).expect("store zmm31");
        let stored = crate::sse::decode(&code, 0).expect("decode store");
        assert_eq!(stored.op1_register(), Register::ZMM31);
        assert_eq!(stored.memory_base(), Register::R15);
        assert_eq!(stored.memory_displacement64(), 1984);
        code.clear();
        append_k(&mut code, false, 7, 7, 0x840).expect("load k7");
        let loaded = crate::sse::decode(&code, 0).expect("decode k");
        assert_eq!(loaded.op0_register(), Register::K7);
        assert_eq!(loaded.memory_displacement64(), 0x840);
    }

    #[test]
    fn mask_save_width_follows_avx512bw() {
        let word = mask_move(false);
        let qword = mask_move(true);
        assert_eq!(word.mnemonic(), iced_x86::Mnemonic::Kmovw);
        assert_eq!(qword.mnemonic(), iced_x86::Mnemonic::Kmovq);
        assert!(word
            .code()
            .cpuid_features()
            .contains(&iced_x86::CpuidFeature::AVX512F));
        assert!(!word
            .code()
            .cpuid_features()
            .contains(&iced_x86::CpuidFeature::AVX512BW));
        assert!(qword
            .code()
            .cpuid_features()
            .contains(&iced_x86::CpuidFeature::AVX512BW));
        let live = if super::super::claim::avx512bw() {
            iced_x86::Mnemonic::Kmovq
        } else {
            iced_x86::Mnemonic::Kmovw
        };
        assert_eq!(live_store().mnemonic(), live);
    }

    #[test]
    fn f_only_kmovw_save_lets_vaddps_retire() {
        if crate::sse::claim::l6_skip_reason(iced_x86::Mnemonic::Vaddps).is_some() {
            return;
        }
        let mut data = [0u8; 256];
        data[..8].copy_from_slice(&0xFFFF_FFFF_FFFF_A5A5u64.to_le_bytes());
        splat(&mut data[64..128], 1.0);
        splat(&mut data[128..192], 2.0);
        let stub = kmovw_vaddps_stub();
        let head = crate::sse::decode(&stub, 0).expect("kmovw");
        assert_eq!(head.mnemonic(), iced_x86::Mnemonic::Kmovw);
        run_rx(&stub, &mut data);
        assert_eq!(u16::from_le_bytes([data[0], data[1]]), 0xA5A5);
        for lane in 0..16 {
            let at = 192 + lane * 4;
            assert_eq!(&data[at..at + 4], &3.0f32.to_le_bytes(), "lane {lane}");
        }
    }

    fn mask_move(qword: bool) -> Instruction {
        let bytes = encode_k_width(true, 1, 7, 0, qword).expect("mask move");
        crate::sse::decode(&bytes, 0).expect("decode mask")
    }

    fn live_store() -> Instruction {
        let mut code = Vec::new();
        append_k(&mut code, true, 1, 7, 0).expect("live");
        crate::sse::decode(&code, 0).expect("decode live")
    }

    fn splat(dst: &mut [u8], value: f32) {
        let bytes = value.to_le_bytes();
        for lane in 0..16 {
            let at = lane * 4;
            dst[at..at + 4].copy_from_slice(&bytes);
        }
    }

    fn kmovw_vaddps_stub() -> Vec<u8> {
        let mut code = Vec::new();
        code.extend(encode_k_width(false, 1, 7, 0, false).expect("load k"));
        append_zmm(&mut code, false, 0, 7, 64).expect("zmm0");
        append_zmm(&mut code, false, 1, 7, 128).expect("zmm1");
        code.extend(vaddps_zmm());
        code.extend(encode_k_width(true, 1, 7, 0, false).expect("store k"));
        append_zmm(&mut code, true, 0, 7, 192).expect("store zmm");
        code.push(0xC3);
        code
    }

    fn vaddps_zmm() -> Vec<u8> {
        let mut insn = Instruction::default();
        insn.set_code(Code::EVEX_Vaddps_zmm_k1z_zmm_zmmm512b32_er);
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::ZMM0);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(Register::ZMM0);
        insn.set_op2_kind(OpKind::Register);
        insn.set_op2_register(Register::ZMM1);
        encode(&insn).expect("vaddps")
    }

    fn run_rx(code: &[u8], data: &mut [u8]) {
        assert!(code.len() < 4096, "stub {}", code.len());
        let page = map_rw();
        // SAFETY: `page` is one fresh read/write page and `code` is shorter than it.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), page, code.len()) };
        protect(page, 5);
        // SAFETY: `page` is now executable and holds `code`, which ends in `ret`.
        // The stub only touches `data` through `rdi` plus the AVX-512F moves it contains.
        let entry: extern "C" fn(*mut u8) = unsafe { std::mem::transmute(page) };
        entry(data.as_mut_ptr());
        unmap(page);
    }

    fn map_rw() -> *mut u8 {
        let page = raw_map(3);
        assert!((page as isize) > 0, "mmap");
        page
    }

    fn raw_map(prot: usize) -> *mut u8 {
        let ptr: usize;
        // SAFETY: the syscall is mmap(NULL, 4096, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0).
        unsafe {
            std::arch::asm!(
                "syscall",
                in("rax") 9usize,
                in("rdi") 0usize,
                in("rsi") 4096usize,
                in("rdx") prot,
                in("r10") 0x22usize,
                in("r8") usize::MAX,
                in("r9") 0usize,
                lateout("rax") ptr,
                out("rcx") _,
                out("r11") _,
            );
        }
        ptr as *mut u8
    }

    fn protect(page: *mut u8, prot: usize) {
        let rc: usize;
        // SAFETY: `page` is the mapping from `map_rw`. `prot` is a Linux protection bitmask.
        unsafe {
            std::arch::asm!(
                "syscall",
                in("rax") 10usize,
                in("rdi") page,
                in("rsi") 4096usize,
                in("rdx") prot,
                lateout("rax") rc,
                out("rcx") _,
                out("r11") _,
            );
        }
        assert!((rc as isize) >= 0, "mprotect {rc}");
    }

    fn unmap(page: *mut u8) {
        let rc: usize;
        // SAFETY: `page` is the mapping from `map_rw`. munmap releases that one page.
        unsafe {
            std::arch::asm!(
                "syscall",
                in("rax") 11usize,
                in("rdi") page,
                in("rsi") 4096usize,
                lateout("rax") rc,
                out("rcx") _,
                out("r11") _,
            );
        }
        assert!((rc as isize) >= 0, "munmap {rc}");
    }
}
