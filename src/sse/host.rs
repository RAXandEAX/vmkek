//! Replay one SSE/SSE2 instruction on the host SSE unit.
//!
//! The architectural XMM file and MXCSR stay in [`Sse`]. For the duration of
//! the instruction the unit is loaded from that file, the opcode runs, and the
//! unit is saved back. The host x87/SSE image is restored before the function
//! returns, including when the opcode raises `#XM`, `#GP`, or `#UD`.
//!
//! The stub lives on its own page. That page is writable only while the stub is
//! patched and executable only for the call. [`crate::x87::lock_unit`]
//! serializes this with x87 replay. It is not async-signal-safe.
//!
//! A VEX opcode that writes an XMM register zeroes bits [255:128] of that YMM.
//! The stub saves the host YMM file, loads the guest 256-bit file, runs the
//! opcode, stores the guest file back, and restores the host file. Legacy SSE
//! does not enter that path, so a legacy write leaves the guest upper bits
//! unchanged. The host YMM reload runs only after that save has stored its
//! marker. A `#UD` on the save itself leaves the host registers unmodified;
//! the executor returns `sse fault` and does not issue another `vmovdqu`. A
//! fault later in the stub still reloads the saved file.
//!
//! An EVEX or opmask opcode does the same for ZMM0–ZMM31 and k0–k7. The host
//! file is restored only after the save marker is stored. A fault on the save
//! does not reload. A later fault reloads both the ZMM file and the masks.
//! Mask stores use `kmovq` when AVX512BW is present and `kmovw` otherwise, so
//! the save itself is an AVX-512F instruction on an F-only host.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use crate::error::{msg, Result};
use crate::flags::Flags;
use crate::ir::{Sse, X87};

use super::Replay;

const PAGE: usize = 4096;
const HOST_IMG: u32 = 0x000;
const GUEST: u32 = 0x200;
const RESULT: u32 = 0x400;
const GPR_IN: u32 = 0x600;
const GPR_OUT: u32 = 0x680;
const FLAG_IN: u32 = 0x700;
const FLAG_OUT: u32 = 0x708;
const STUB_RSP: u32 = 0x710;
pub(super) const MEM: u32 = 0x720;
const YMM_SAVE: u32 = 0x800;
const YMM_GUEST: u32 = 0xA00;
const YMM_RESULT: u32 = 0xC00;
pub(super) const MEM_CAP: usize = 128;
const PROT_RW: usize = 3;
const PROT_RX: usize = 5;

const _: () = assert!(HOST_IMG + 512 <= GUEST);
const _: () = assert!(GUEST + 512 <= RESULT);
const _: () = assert!(RESULT + 512 <= GPR_IN);
const _: () = assert!(GPR_IN + 128 <= GPR_OUT);
const _: () = assert!(GPR_OUT + 128 <= FLAG_IN);
const _: () = assert!(FLAG_IN + 8 <= FLAG_OUT);
const _: () = assert!(FLAG_OUT + 8 <= STUB_RSP);
const _: () = assert!(STUB_RSP + 8 <= MEM);
/// Bytes scrubbed for one operand: 32-byte alignment slack plus [`MEM_CAP`].
const OPERAND_SPAN: usize = 32 + MEM_CAP;
/// Set to 1 only after the host-YMM save `vmovdqu`s retire. Sits at 0x7C0.
const SAVE_MARK: u32 = MEM + OPERAND_SPAN as u32;
const _: () = assert!(MEM as usize + 31 + MEM_CAP <= YMM_SAVE as usize);
const _: () = assert!(MEM as usize + OPERAND_SPAN == SAVE_MARK as usize);
const _: () = assert!(SAVE_MARK == 0x7C0);
const _: () = assert!(MEM as usize + OPERAND_SPAN - 1 == 0x7BF);
const _: () = assert!((SAVE_MARK as usize) < YMM_SAVE as usize);
const _: () = assert!(YMM_SAVE as usize + 16 * 32 <= YMM_GUEST as usize);
const _: () = assert!(YMM_GUEST as usize + 16 * 32 <= YMM_RESULT as usize);
const _: () = assert!(YMM_RESULT as usize + 16 * 32 <= PAGE);

const SIGILL: i32 = 4;
const SIGBUS: i32 = 7;
const SIGFPE: i32 = 8;
const SIGSEGV: i32 = 11;
const SIGNALS: [i32; 4] = [SIGILL, SIGBUS, SIGFPE, SIGSEGV];
const SA_NODEFER: i32 = 0x4000_0000;
const SA_SIGINFO: i32 = 4;

struct Mapping {
    code: *mut u8,
    data: *mut u8,
    zmm: *mut u8,
    tail: *mut u8,
    reload: *mut u8,
}

#[derive(Clone, Copy)]
struct PageIds {
    code: usize,
    data: usize,
    zmm: usize,
    tail: usize,
    reload: usize,
}

fn mapping() -> Result<Mapping> {
    static SLOT: std::sync::Mutex<Option<PageIds>> = std::sync::Mutex::new(None);
    let mut slot = SLOT.lock().unwrap_or_else(|err| err.into_inner());
    if let Some(raw) = *slot {
        return Ok(mapping_from(raw));
    }
    let map = Mapping {
        code: map_page()?,
        data: map_page()?,
        zmm: map_page()?,
        tail: map_page()?,
        reload: map_page()?,
    };
    fill_reload(map.reload)?;
    *slot = Some(PageIds {
        code: map.code as usize,
        data: map.data as usize,
        zmm: map.zmm as usize,
        tail: map.tail as usize,
        reload: map.reload as usize,
    });
    Ok(map)
}

fn mapping_from(raw: PageIds) -> Mapping {
    Mapping {
        code: raw.code as *mut u8,
        data: raw.data as *mut u8,
        zmm: raw.zmm as *mut u8,
        tail: raw.tail as *mut u8,
        reload: raw.reload as *mut u8,
    }
}

fn fill_reload(page: *mut u8) -> Result<()> {
    let mut blob = Vec::new();
    super::evex::append_reload(&mut blob)?;
    if blob.len() >= PAGE {
        return Err(msg("zmm reload stub overlaps the page"));
    }
    // SAFETY: `page` is a fresh writable mapping. `blob` is shorter than the page.
    unsafe {
        std::ptr::copy_nonoverlapping(blob.as_ptr(), page, blob.len());
    }
    protect(page, PROT_RX)?;
    RELOAD.store(page, Ordering::Release);
    Ok(())
}

fn map_page() -> Result<*mut u8> {
    // SAFETY: `mmap` returns a fresh anonymous page or a negative errno.
    // The pointer is kept only after that check.
    let mapped = unsafe { mmap(PROT_RW) };
    if (mapped as isize) < 0 {
        return Err(msg("sse page allocation failed"));
    }
    Ok(mapped)
}

/// # Safety
/// `prot` is the Linux protection of one fresh anonymous page. The result is
/// that page or a negative errno.
unsafe fn mmap(prot: usize) -> *mut u8 {
    let ptr: usize;
    std::arch::asm!(
        "syscall",
        in("rax") 9usize,
        in("rdi") 0usize,
        in("rsi") PAGE,
        in("rdx") prot,
        in("r10") 0x22usize,
        in("r8") usize::MAX,
        in("r9") 0usize,
        lateout("rax") ptr,
        out("rcx") _,
        out("r11") _,
    );
    ptr as *mut u8
}

/// # Safety
/// `addr` is one live page from `mmap`, and `prot` is a Linux protection
/// bitmask. The result is zero or a negative errno.
unsafe fn mprotect(addr: *mut u8, prot: usize) -> isize {
    let rc: usize;
    std::arch::asm!(
        "syscall",
        in("rax") 10usize,
        in("rdi") addr,
        in("rsi") PAGE,
        in("rdx") prot,
        lateout("rax") rc,
        out("rcx") _,
        out("r11") _,
    );
    rc as isize
}

fn protect(page: *mut u8, prot: usize) -> Result<()> {
    // SAFETY: `page` is a live one-page mapping from `mmap`. `prot` is
    // read/write or read/execute. A negative errno is rejected below.
    let rc = unsafe { mprotect(page, prot) };
    if rc < 0 {
        return Err(msg("sse page protection failed"));
    }
    Ok(())
}

#[repr(C, align(16))]
struct Align16([u8; 512]);

fn capture_template_unlocked() -> [u8; 512] {
    let mut image = Align16([0u8; 512]);
    // SAFETY: `image` is 16-byte aligned and 512 bytes long. `fxsave64` writes
    // the current x87/SSE image into that buffer and leaves the unit unchanged.
    unsafe {
        std::arch::asm!(
            "fxsave64 [{ptr}]",
            ptr = in(reg) image.0.as_mut_ptr(),
        );
    }
    image.0
}

#[cfg(test)]
pub(in crate::sse) fn capture_template() -> [u8; 512] {
    let _guard = crate::x87::lock_unit();
    capture_template_unlocked()
}

fn mxcsr_legal(mxcsr: u32, mask: u32) -> bool {
    // A zero mask means the Pentium III default, 0xFFBF.
    let mask = if mask == 0 { 0x0000_FFBF } else { mask };
    mxcsr & !mask == 0
}

#[allow(
    clippy::too_many_arguments,
    reason = "the host stub takes XMM, x87, flags, and the memory operand as separate inputs"
)]
pub(super) fn run(
    sse: &mut Sse,
    x87: &mut X87,
    regs: &mut [u64; 16],
    flags: &mut Flags,
    af: &mut bool,
    df: bool,
    mem: &mut [u8],
    replay: &Replay,
    writes_flags: bool,
) -> Result<()> {
    if replay.bytes.is_empty() || replay.bytes.len() > 15 {
        return Err(msg("sse encoding does not fit"));
    }
    if !operand_fits(replay, mem.len()) {
        return Err(msg("sse memory operand is too large"));
    }
    let map = mapping()?;
    let _guard = crate::x87::lock_unit();
    let template = capture_template_unlocked();
    let mask = u32::from_le_bytes([template[28], template[29], template[30], template[31]]);
    if !mxcsr_legal(sse.mxcsr, mask) {
        return Err(msg("sse fault"));
    }
    let mut guest = template;
    super::store_image(x87, sse, &mut guest);
    if replay.save_ymm {
        let packed = super::ymm_image(sse);
        write_block(map.data, YMM_GUEST, &packed);
    }
    stage_zmm(&map, sse, replay);
    stage(&map, &guest, &template, regs, *flags, *af, df, mem, replay)?;
    let entry = entry_fn(map.code);
    // SAFETY: `map.data` is the live anonymous data page from `mmap`, page
    // aligned. `HOST_IMG` is 0, so this is that page, and the host FXSAVE
    // image occupies its first 512 bytes.
    let host = unsafe { map.data.add(HOST_IMG as usize) };
    #[cfg(test)]
    paint_zmm31_canary(replay.save_zmm);
    let ok = catch_fault(host, entry, replay.save_ymm, replay.save_zmm)?;
    #[cfg(test)]
    snap_zmm31(replay.save_zmm);
    if !ok {
        return Err(msg("sse fault"));
    }
    harvest(&map, sse, x87, regs, flags, af, mem, replay, writes_flags);
    Ok(())
}

fn entry_fn(code: *mut u8) -> extern "C" fn() {
    // SAFETY: `code` is the live mapping. The caller makes it executable
    // before the pointer is called, and the bytes are the leaf stub below.
    unsafe { std::mem::transmute(code) }
}

#[allow(
    clippy::too_many_arguments,
    reason = "staging copies XMM, x87, GPRs, flags, and the memory operand into distinct data-page slots"
)]
fn stage(
    map: &Mapping,
    guest: &[u8; 512],
    host: &[u8; 512],
    regs: &[u64; 16],
    flags: Flags,
    af: bool,
    df: bool,
    mem: &[u8],
    replay: &Replay,
) -> Result<()> {
    write_block(map.data, HOST_IMG, host);
    write_block(map.data, GUEST, guest);
    for (index, reg) in regs.iter().enumerate() {
        write_u64(map.data, GPR_IN + (index * 8) as u32, *reg);
    }
    write_u64(map.data, FLAG_IN, rflags(flags, af, df));
    #[cfg(test)]
    if ymm_probe() == Probe::SaveUd {
        force_save_mark(map.data);
    }
    clear_operand(map.data);
    reset_save_mark(map.data);
    reset_zmm_mark(map.data);
    #[cfg(test)]
    paint_host_canary(map.data);
    if !mem.is_empty() {
        copy_operand_in(map.data, replay.mem_at as usize + replay.align, mem);
    }
    let code = stub(map, replay)?;
    protect(map.code, PROT_RW)?;
    write_stub(map.code, &code)?;
    protect(map.code, PROT_RX)
}

#[allow(
    clippy::too_many_arguments,
    reason = "harvest reads XMM, x87, GPRs, flags, and the memory operand back from distinct data-page slots"
)]
fn harvest(
    map: &Mapping,
    sse: &mut Sse,
    x87: &mut X87,
    regs: &mut [u64; 16],
    flags: &mut Flags,
    af: &mut bool,
    mem: &mut [u8],
    replay: &Replay,
    writes_flags: bool,
) {
    if !mem.is_empty() {
        copy_operand_out(map.data, replay.mem_at as usize + replay.align, mem);
    }
    for reg in regs.iter_mut().enumerate() {
        *reg.1 = read_u64(map.data, GPR_OUT + (reg.0 * 8) as u32);
    }
    if writes_flags {
        apply_flags(read_u64(map.data, FLAG_OUT), flags, af);
    }
    let result = read_block(map.data, RESULT);
    super::load_image(x87, sse, &result);
    if replay.save_ymm {
        let packed = read_block(map.data, YMM_RESULT);
        super::apply_ymm(sse, &packed);
    }
    harvest_zmm(map, sse, replay);
}

fn stub(map: &Mapping, replay: &Replay) -> Result<Vec<u8>> {
    let anchor = replay.anchor;
    if anchor == 4 || anchor == 12 || anchor >= 16 {
        return Err(msg("sse anchor register unavailable"));
    }
    let mut code = Vec::with_capacity(400);
    push_frame(&mut code);
    mov_reg_imm64(&mut code, anchor, map.data as u64);
    store_reg(&mut code, 4, anchor, STUB_RSP);
    load_guest(&mut code, anchor, replay, map)?;
    #[cfg(test)]
    if ymm_probe() == Probe::GuestUd {
        ud2(&mut code);
    }
    code.extend_from_slice(&replay.bytes);
    save_guest(&mut code, anchor, replay, map)?;
    pop_frame(&mut code);
    if code.len() >= PAGE {
        return Err(msg("sse stub overlaps the save area"));
    }
    Ok(code)
}

fn push_frame(code: &mut Vec<u8>) {
    code.push(0x53); // push rbx
    code.push(0x55); // push rbp
    code.extend_from_slice(&[0x41, 0x54]); // push r12
    code.extend_from_slice(&[0x41, 0x55]); // push r13
    code.extend_from_slice(&[0x41, 0x56]); // push r14
    code.extend_from_slice(&[0x41, 0x57]); // push r15
    code.push(0x9C); // pushfq
}

fn load_guest(code: &mut Vec<u8>, anchor: usize, replay: &Replay, map: &Mapping) -> Result<()> {
    if replay.save_ymm {
        save_host_ymm(code, anchor);
    }
    if replay.save_zmm {
        save_host_zmm(code, anchor, map)?;
    }
    fxsave(code, anchor, HOST_IMG);
    fxrstor(code, anchor, GUEST);
    if replay.save_ymm {
        move_ymms(code, anchor, false, YMM_GUEST);
    }
    if replay.save_zmm {
        load_guest_zmm(code, anchor, map)?;
    }
    push_mem(code, anchor, FLAG_IN);
    code.push(0x9D); // popfq
    load_gprs(code, anchor, replay);
    Ok(())
}

fn load_gprs(code: &mut Vec<u8>, anchor: usize, replay: &Replay) {
    for index in 0..16 {
        if index == anchor || index == 4 {
            continue;
        }
        load_reg(code, index, anchor, GPR_IN + (index * 8) as u32);
    }
    if let Some(addr) = replay.addr {
        lea(code, addr, anchor, replay.mem_at + replay.align as u32);
    }
    if replay.load_rsp {
        load_reg(code, 4, anchor, GPR_IN + 32);
    }
}

fn save_guest(code: &mut Vec<u8>, anchor: usize, replay: &Replay, map: &Mapping) -> Result<()> {
    for index in 0..16 {
        if index == anchor {
            continue;
        }
        store_reg(code, index, anchor, GPR_OUT + (index * 8) as u32);
    }
    load_reg(code, 4, anchor, STUB_RSP);
    code.push(0x9C); // pushfq
    pop_mem(code, anchor, FLAG_OUT);
    if replay.save_zmm {
        super::evex::store_result(code, anchor, map.data as u64, map.tail as u64)?;
    }
    if replay.save_ymm {
        move_ymms(code, anchor, true, YMM_RESULT);
    }
    fxsave(code, anchor, RESULT);
    fxrstor(code, anchor, HOST_IMG);
    if replay.save_ymm {
        move_ymms(code, anchor, false, YMM_SAVE);
    }
    if replay.save_zmm {
        restore_host_zmm(code, anchor, map)?;
    }
    code.push(0x9D); // popfq
    Ok(())
}

fn save_host_zmm(code: &mut Vec<u8>, anchor: usize, map: &Mapping) -> Result<()> {
    super::evex::save_host(
        code,
        anchor,
        map.data as u64,
        map.zmm as u64,
        map.tail as u64,
    )
}

fn load_guest_zmm(code: &mut Vec<u8>, anchor: usize, map: &Mapping) -> Result<()> {
    super::evex::load_guest(
        code,
        anchor,
        map.data as u64,
        map.zmm as u64,
        map.tail as u64,
    )
}

fn restore_host_zmm(code: &mut Vec<u8>, anchor: usize, map: &Mapping) -> Result<()> {
    super::evex::restore_host(
        code,
        anchor,
        map.data as u64,
        map.zmm as u64,
        map.tail as u64,
    )
}

fn operand_fits(replay: &Replay, len: usize) -> bool {
    if len > MEM_CAP {
        return false;
    }
    let end = replay.mem_at as usize + replay.align + len;
    if replay.mem_at == MEM {
        end <= YMM_SAVE as usize
    } else {
        end <= PAGE
    }
}

fn stage_zmm(map: &Mapping, sse: &Sse, replay: &Replay) {
    if !replay.save_zmm {
        return;
    }
    let packed = super::zmm_image(sse);
    write_bytes(map.zmm, super::evex::ZMM_GUEST, &packed);
    let masks = super::mask_image(sse);
    write_bytes(map.tail, super::evex::K_GUEST, &masks);
    arm_zmm(map);
}

fn arm_zmm(map: &Mapping) {
    ZMM_SAVE.store(map.zmm, Ordering::Release);
    // SAFETY: `map.tail` is the live tail page from `mmap`. `K_SAVE` plus the
    // 64 mask bytes stays inside that 4096-byte page.
    let mask = unsafe { map.tail.add(super::evex::K_SAVE) };
    K_SAVE_PTR.store(mask, Ordering::Release);
}

fn harvest_zmm(map: &Mapping, sse: &mut Sse, replay: &Replay) {
    if !replay.save_zmm {
        return;
    }
    let mut packed = [0u8; super::evex::ZMM_BYTES];
    read_bytes(map.tail, 0, &mut packed);
    super::apply_zmm(sse, &packed);
    let mut masks = [0u8; super::evex::K_BYTES];
    read_bytes(map.tail, super::evex::K_RESULT, &mut masks);
    super::apply_mask(sse, &masks);
}

/// Save the host YMM file, then set the save marker.
///
/// The marker instruction is after every save `vmovdqu`. A fault on those
/// stores leaves the marker clear, and `catch_fault` does not reload.
fn save_host_ymm(code: &mut Vec<u8>, anchor: usize) {
    #[cfg(test)]
    if ymm_probe() == Probe::SaveUd {
        ud2(code);
    }
    #[cfg(test)]
    if paints() {
        ymm_move(code, false, 15, anchor, YMM_PAINT);
    }
    move_ymms(code, anchor, true, YMM_SAVE);
    mark_ymm_saved(code, anchor);
}

fn mark_ymm_saved(code: &mut Vec<u8>, base: usize) {
    if base >= 8 {
        code.push(0x41);
    }
    code.push(0xC6);
    code.push(0x80 | (base as u8 & 7));
    code.extend_from_slice(&SAVE_MARK.to_le_bytes());
    code.push(1);
}

fn move_ymms(code: &mut Vec<u8>, base: usize, store: bool, slot: u32) {
    for index in 0..16 {
        ymm_move(code, store, index, base, slot + (index * 32) as u32);
    }
}

#[cfg(test)]
pub(super) fn append_ymm(code: &mut Vec<u8>, store: bool, ymm: usize, base: usize, disp: u32) {
    ymm_move(code, store, ymm, base, disp);
}

fn ymm_move(code: &mut Vec<u8>, store: bool, ymm: usize, base: usize, disp: u32) {
    code.push(0xC4);
    code.push(vex_rxb(ymm, base));
    code.push(0x7E);
    code.push(if store { 0x7F } else { 0x6F });
    code.push(0x80 | ((ymm as u8 & 7) << 3) | (base as u8 & 7));
    code.extend_from_slice(&disp.to_le_bytes());
}

fn vex_rxb(ymm: usize, base: usize) -> u8 {
    let mut rxb = 0xE1;
    if ymm >= 8 {
        rxb &= !0x80;
    }
    if base >= 8 {
        rxb &= !0x20;
    }
    rxb
}

fn pop_frame(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0x41, 0x5F]); // pop r15
    code.extend_from_slice(&[0x41, 0x5E]); // pop r14
    code.extend_from_slice(&[0x41, 0x5D]); // pop r13
    code.extend_from_slice(&[0x41, 0x5C]); // pop r12
    code.push(0x5D); // pop rbp
    code.push(0x5B); // pop rbx
    code.push(0xC3); // ret
}

fn mov_reg_imm64(code: &mut Vec<u8>, reg: usize, value: u64) {
    code.push(0x48 | u8::from(reg >= 8));
    code.push(0xB8 + (reg as u8 & 7));
    code.extend_from_slice(&value.to_le_bytes());
}

fn load_reg(code: &mut Vec<u8>, reg: usize, base: usize, disp: u32) {
    op_rm(code, 0x8B, reg, base, disp, true);
}

fn store_reg(code: &mut Vec<u8>, reg: usize, base: usize, disp: u32) {
    op_rm(code, 0x89, reg, base, disp, true);
}

fn lea(code: &mut Vec<u8>, reg: usize, base: usize, disp: u32) {
    op_rm(code, 0x8D, reg, base, disp, true);
}

fn push_mem(code: &mut Vec<u8>, base: usize, disp: u32) {
    op_rm(code, 0xFF, 6, base, disp, false);
}

fn pop_mem(code: &mut Vec<u8>, base: usize, disp: u32) {
    op_rm(code, 0x8F, 0, base, disp, false);
}

fn fxsave(code: &mut Vec<u8>, base: usize, disp: u32) {
    op_0f(code, 0xAE, 0, base, disp);
}

fn fxrstor(code: &mut Vec<u8>, base: usize, disp: u32) {
    op_0f(code, 0xAE, 1, base, disp);
}

fn op_rm(code: &mut Vec<u8>, opcode: u8, reg: usize, base: usize, disp: u32, wide: bool) {
    emit_rex(code, wide, reg >= 8, base >= 8);
    code.push(opcode);
    code.push(0x80 | ((reg as u8 & 7) << 3) | (base as u8 & 7));
    code.extend_from_slice(&disp.to_le_bytes());
}

fn op_0f(code: &mut Vec<u8>, opcode: u8, reg: usize, base: usize, disp: u32) {
    emit_rex(code, true, reg >= 8, base >= 8);
    code.push(0x0F);
    code.push(opcode);
    code.push(0x80 | ((reg as u8 & 7) << 3) | (base as u8 & 7));
    code.extend_from_slice(&disp.to_le_bytes());
}

fn emit_rex(code: &mut Vec<u8>, w: bool, r: bool, b: bool) {
    if w || r || b {
        let mut rex = 0x40;
        if w {
            rex |= 0x08;
        }
        if r {
            rex |= 0x04;
        }
        if b {
            rex |= 0x01;
        }
        code.push(rex);
    }
}

fn clear_operand(data: *mut u8) {
    // SAFETY: `data` is the live data mapping. MEM plus the 32-byte alignment
    // slack and MEM_CAP ends at 0x7C0, before SAVE_MARK and YMM_SAVE, inside
    // the 4096-byte page.
    unsafe {
        std::ptr::write_bytes(data.add(MEM as usize), 0, OPERAND_SPAN);
    }
}

fn reset_zmm_mark(data: *mut u8) {
    // SAFETY: `data` is the live data mapping. `ZMM_MARK` is one byte at
    // 0x7C1, after the operand window and before the YMM save.
    unsafe {
        std::ptr::write_volatile(data.add(super::evex::ZMM_MARK as usize), 0u8);
    }
}

fn reset_save_mark(data: *mut u8) {
    // SAFETY: `data` is the live data mapping. `SAVE_MARK` is one byte at
    // 0x7C0, after the operand window and before `YMM_SAVE`.
    unsafe {
        std::ptr::write_volatile(data.add(SAVE_MARK as usize), 0u8);
    }
}

fn copy_operand_in(data: *mut u8, off: usize, mem: &[u8]) {
    // SAFETY: `off + mem.len()` was checked against the 4096-byte page.
    unsafe {
        std::ptr::copy_nonoverlapping(mem.as_ptr(), data.add(off), mem.len());
    }
}

fn copy_operand_out(data: *mut u8, off: usize, mem: &mut [u8]) {
    // SAFETY: `off + mem.len()` was checked against the 4096-byte page.
    unsafe {
        std::ptr::copy_nonoverlapping(data.add(off), mem.as_mut_ptr(), mem.len());
    }
}

fn write_stub(code: *mut u8, bytes: &[u8]) -> Result<()> {
    if bytes.len() >= PAGE {
        return Err(msg("sse stub overlaps the save area"));
    }
    // SAFETY: `code` is the live code page, write permission was just
    // restored, and `bytes.len()` is less than the 4096-byte page.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), code, bytes.len());
    }
    Ok(())
}

fn write_bytes(page: *mut u8, off: usize, bytes: &[u8]) {
    // SAFETY: callers pass an offset and length that stay inside the mapped
    // page: the ZMM file is 2048 bytes and the opmask image is 64 bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), page.add(off), bytes.len());
    }
}

fn read_bytes(page: *mut u8, off: usize, bytes: &mut [u8]) {
    // SAFETY: callers pass an offset and length that stay inside the mapped
    // page. The ZMM result occupies the first 2048 bytes of the tail page.
    unsafe {
        std::ptr::copy_nonoverlapping(page.add(off), bytes.as_mut_ptr(), bytes.len());
    }
}

fn write_block(page: *mut u8, off: u32, bytes: &[u8; 512]) {
    // SAFETY: `page` is the live data mapping, and `off + 512` stays inside
    // that 4096-byte page. HOST, GUEST, and RESULT each occupy 512 bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), page.add(off as usize), 512);
    }
}

fn read_block(page: *mut u8, off: u32) -> [u8; 512] {
    let mut out = [0u8; 512];
    // SAFETY: `page` is the live data mapping, and `off + 512` stays inside
    // that 4096-byte page.
    unsafe {
        std::ptr::copy_nonoverlapping(page.add(off as usize), out.as_mut_ptr(), 512);
    }
    out
}

fn write_u64(page: *mut u8, off: u32, value: u64) {
    // SAFETY: `page` is the live data mapping. GPR and flag slots plus 8 bytes
    // stay inside the 4096-byte page.
    unsafe {
        std::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), page.add(off as usize), 8);
    }
}

fn read_u64(page: *mut u8, off: u32) -> u64 {
    let mut raw = [0u8; 8];
    // SAFETY: `page` is the live data mapping. The slot plus 8 bytes stays
    // inside the 4096-byte page.
    unsafe {
        std::ptr::copy_nonoverlapping(page.add(off as usize), raw.as_mut_ptr(), 8);
    }
    u64::from_le_bytes(raw)
}

fn apply_flags(bits: u64, flags: &mut Flags, af: &mut bool) {
    *flags = Flags {
        cf: bits & 1 != 0,
        pf: bits & (1 << 2) != 0,
        zf: bits & (1 << 6) != 0,
        sf: bits & (1 << 7) != 0,
        of: bits & (1 << 11) != 0,
    };
    *af = bits & (1 << 4) != 0;
}

fn rflags(flags: Flags, af: bool, df: bool) -> u64 {
    let mut bits = 0x202 | flags.pack();
    if af {
        bits |= 1 << 4;
    }
    if df {
        bits |= 1 << 10;
    }
    bits
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SigAction {
    handler: usize,
    mask: [u64; 16],
    flags: i32,
    _pad: i32,
    restorer: usize,
}

impl SigAction {
    const fn zero() -> Self {
        Self {
            handler: 0,
            mask: [0; 16],
            flags: 0,
            _pad: 0,
            restorer: 0,
        }
    }
}

/// One slot shared by the fault handler and the thread that owns the FPU lock.
struct Shared<T>(UnsafeCell<T>);

impl<T> Shared<T> {
    const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// SAFETY: the FPU lock admits one `run` at a time. The handler reads these
// slots only while that thread is inside the stub.
unsafe impl<T> Sync for Shared<T> {}

struct Trap {
    jmp: Shared<[u8; 256]>,
    host: AtomicPtr<u8>,
    armed: AtomicBool,
    owner: AtomicU64,
    previous: [AtomicUsize; 4],
    previous_flags: [AtomicI32; 4],
    saved: Shared<[SigAction; 4]>,
}

static RELOAD: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static ZMM_SAVE: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static K_SAVE_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());

static TRAP: Trap = Trap {
    jmp: Shared::new([0; 256]),
    host: AtomicPtr::new(std::ptr::null_mut()),
    armed: AtomicBool::new(false),
    owner: AtomicU64::new(0),
    previous: [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ],
    previous_flags: [
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
    ],
    saved: Shared::new([SigAction::zero(); 4]),
};

extern "C" {
    #[link_name = "__sigsetjmp"]
    fn sigsetjmp(env: *mut u8, savemask: i32) -> i32;
    fn siglongjmp(env: *mut u8, val: i32) -> !;
    fn sigaction(sig: i32, act: *const SigAction, old: *mut SigAction) -> i32;
    fn raise(sig: i32) -> i32;
}

fn catch_fault(
    host: *mut u8,
    entry: extern "C" fn(),
    reload_y: bool,
    reload_z: bool,
) -> Result<bool> {
    install()?;
    let _restore = Restore;
    TRAP.host.store(host, Ordering::Release);
    // SAFETY: `install` armed the fault handler on this thread, and `run`
    // holds the FPU lock. `entry` is the executable stub page. `invoke`
    // returns true only when that handler restored the host FXSAVE image and
    // long-jumped out of the stub.
    let faulted = unsafe { invoke(entry) };
    // A fault at the save leaves the marker clear: those vmovdqu stores never
    // retired, so the host YMM file was not modified and must not be reloaded.
    if reload_y && host_ymm_saved(host) {
        reload_ymm(host);
    }
    if reload_z && host_zmm_saved(host) {
        reload_zmm_file();
    }
    #[cfg(test)]
    {
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
        snap_ymm15_for_probe();
    }
    TRAP.armed.store(false, Ordering::Release);
    Ok(!faulted)
}

fn host_zmm_saved(page: *mut u8) -> bool {
    // SAFETY: `page` is the live data page. `ZMM_MARK` is one byte at 0x7C1.
    // The stub stores 1 only after the host ZMM and opmask saves retire.
    unsafe { std::ptr::read_volatile(page.add(super::evex::ZMM_MARK as usize)) == 1 }
}

fn reload_zmm_file() {
    let entry = RELOAD.load(Ordering::Acquire);
    let zmm = ZMM_SAVE.load(Ordering::Acquire);
    let mask = K_SAVE_PTR.load(Ordering::Acquire);
    if entry.is_null() || zmm.is_null() || mask.is_null() {
        return;
    }
    // SAFETY: `entry` is the RX reload stub built in `fill_reload`. `zmm` is
    // the saved host ZMM file and `mask` is the saved k0–k7. The stub only
    // reads those bytes and writes the matching registers.
    unsafe {
        let reload: extern "C" fn(*mut u8, *mut u8) = std::mem::transmute(entry);
        reload(zmm, mask);
    }
}

fn host_ymm_saved(page: *mut u8) -> bool {
    // SAFETY: `page` is the live data page (`HOST_IMG` is 0). `SAVE_MARK` is
    // one byte inside that page. The stub stores 1 only after the host-YMM
    // save completes; a fault on that save still reads 0.
    unsafe { std::ptr::read_volatile(page.add(SAVE_MARK as usize)) == 1 }
}

fn reload_ymm(page: *mut u8) {
    #[cfg(test)]
    fault_if_save_would_ud();
    // SAFETY: `page` is the live data page. `YMM_SAVE` is 32-byte aligned at
    // 0x800 and the next 512 bytes stay inside that page. The loads put the
    // host YMM file, saved before the guest opcode, back into the registers.
    unsafe {
        let base = page.add(YMM_SAVE as usize);
        std::arch::asm!(
            "vmovdqu ymm0, [r10]",
            "vmovdqu ymm1, [r10+32]",
            "vmovdqu ymm2, [r10+64]",
            "vmovdqu ymm3, [r10+96]",
            "vmovdqu ymm4, [r10+128]",
            "vmovdqu ymm5, [r10+160]",
            "vmovdqu ymm6, [r10+192]",
            "vmovdqu ymm7, [r10+224]",
            "vmovdqu ymm8, [r10+256]",
            "vmovdqu ymm9, [r10+288]",
            "vmovdqu ymm10, [r10+320]",
            "vmovdqu ymm11, [r10+352]",
            "vmovdqu ymm12, [r10+384]",
            "vmovdqu ymm13, [r10+416]",
            "vmovdqu ymm14, [r10+448]",
            "vmovdqu ymm15, [r10+480]",
            in("r10") base,
            out("ymm0") _,
            out("ymm1") _,
            out("ymm2") _,
            out("ymm3") _,
            out("ymm4") _,
            out("ymm5") _,
            out("ymm6") _,
            out("ymm7") _,
            out("ymm8") _,
            out("ymm9") _,
            out("ymm10") _,
            out("ymm11") _,
            out("ymm12") _,
            out("ymm13") _,
            out("ymm14") _,
            out("ymm15") _,
            options(nostack, preserves_flags),
        );
    }
}

struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        restore_signals();
    }
}

/// # Safety
/// The caller installed the fault handler and holds the FPU lock. `entry` is
/// the executable stub page.
#[inline(never)]
unsafe fn invoke(entry: extern "C" fn()) -> bool {
    let buf = TRAP.jmp.get() as *mut u8;
    let rc = sigsetjmp(buf, 1);
    if std::hint::black_box(rc) != 0 {
        return true;
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
    TRAP.owner.store(gettid(), Ordering::Release);
    TRAP.armed.store(true, Ordering::Release);
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
    entry();
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
    TRAP.armed.store(false, Ordering::Release);
    false
}

fn install() -> Result<()> {
    let action = SigAction {
        handler: on_fault as *const () as usize,
        mask: [0; 16],
        flags: SA_NODEFER | SA_SIGINFO,
        _pad: 0,
        restorer: 0,
    };
    for (index, sig) in SIGNALS.iter().enumerate() {
        let mut old = SigAction::zero();
        // SAFETY: `action` and `old` are the libc sigaction layout. A negative
        // errno is rejected below and handlers installed so far are restored.
        let rc = unsafe { sigaction(*sig, &action, &mut old) };
        if rc != 0 {
            restore_signals();
            return Err(msg("sse signal handler failed"));
        }
        TRAP.previous_flags[index].store(old.flags, Ordering::Release);
        TRAP.previous[index].store(old.handler, Ordering::Release);
        // SAFETY: the FPU lock keeps this slot single-owner. The handler only
        // reads `previous`, which was stored above.
        unsafe {
            (*TRAP.saved.get())[index] = old;
        }
    }
    Ok(())
}

fn restore_signals() {
    for (index, sig) in SIGNALS.iter().enumerate() {
        // SAFETY: `saved` was written by `install` on this thread, which holds
        // the FPU lock. The slot is not read by the fault handler.
        let old = unsafe { (*TRAP.saved.get())[index] };
        // SAFETY: `old` is the disposition `sigaction` returned for this signal
        // in `install`. Writing it back is the matching restore. The return
        // value is ignored because this also runs while dropping the guard.
        unsafe {
            sigaction(*sig, &old, std::ptr::null_mut());
        }
    }
}

extern "C" fn on_fault(sig: i32, info: *mut u8, ctx: *mut u8) {
    let tid = gettid();
    if TRAP.armed.load(Ordering::Acquire) && TRAP.owner.load(Ordering::Acquire) == tid {
        TRAP.armed.store(false, Ordering::Release);
        let host = TRAP.host.load(Ordering::Acquire);
        if !host.is_null() {
            // SAFETY: `host` is the 16-byte-aligned FXSAVE image captured
            // before the guest `fxrstor`. Restoring it returns the unit to the
            // host process before the long jump leaves the stub.
            unsafe {
                std::arch::asm!(
                    "fxrstor64 [{host}]",
                    host = in(reg) host,
                    options(nostack),
                );
            }
        }
        // SAFETY: `sigsetjmp` on this thread saved `TRAP.jmp` before `armed`
        // was set. This is the matching `siglongjmp` from the fault handler.
        unsafe { siglongjmp(TRAP.jmp.get() as *mut u8, 1) };
    }
    chain(sig, info, ctx);
}

fn chain(sig: i32, info: *mut u8, ctx: *mut u8) {
    let slot = SIGNALS.iter().position(|item| *item == sig);
    let prev = slot
        .map(|index| TRAP.previous[index].load(Ordering::Acquire))
        .unwrap_or(0);
    let flags = slot
        .map(|index| TRAP.previous_flags[index].load(Ordering::Acquire))
        .unwrap_or(0);
    if prev == 0 || prev == on_fault as *const () as usize {
        deliver_default(sig);
        return;
    }
    if prev == 1 {
        return;
    }
    if flags & SA_SIGINFO != 0 {
        call_sigaction(prev, sig, info, ctx);
        return;
    }
    call_handler(prev, sig);
}

fn deliver_default(sig: i32) {
    let default = SigAction::zero();
    // SAFETY: a zero `SigAction` is `SIG_DFL` (`sa_handler` null, flags clear).
    // Installing it and then `raise` delivers the default action. `sig` is one
    // of SIGILL, SIGBUS, SIGFPE, or SIGSEGV, and both calls are the libc ones.
    unsafe {
        sigaction(sig, &default, std::ptr::null_mut());
        raise(sig);
    }
}

fn call_sigaction(prev: usize, sig: i32, info: *mut u8, ctx: *mut u8) {
    // SAFETY: `SA_SIGINFO` was set on the saved disposition, so `prev` is
    // `sa_sigaction`: `extern "C" fn(i32, *mut siginfo_t, *mut ucontext_t)`,
    // not a one-argument `sa_handler`. `info` and `ctx` are the pointers the
    // kernel passed to this delivery. `SIG_DFL` (0) and `SIG_IGN` (1) were
    // rejected by `chain`.
    let sa_sigaction: extern "C" fn(i32, *mut u8, *mut u8) = unsafe { std::mem::transmute(prev) };
    sa_sigaction(sig, info, ctx);
}

fn call_handler(prev: usize, sig: i32) {
    // SAFETY: `SA_SIGINFO` was clear on the saved disposition, so `prev` is the
    // one-argument `sa_handler`: `extern "C" fn(i32)`. `SIG_DFL` (0) and
    // `SIG_IGN` (1) were rejected by `chain`.
    let sa_handler: extern "C" fn(i32) = unsafe { std::mem::transmute(prev) };
    sa_handler(sig);
}

fn gettid() -> u64 {
    let tid: u64;
    // SAFETY: `gettid` is syscall 186 and only writes the result register.
    unsafe {
        std::arch::asm!(
            "syscall",
            in("rax") 186u64,
            lateout("rax") tid,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    tid
}

#[cfg(test)]
pub(super) fn page_perms() -> Result<(String, String)> {
    let map = mapping()?;
    let _guard = crate::x87::lock_unit();
    let text =
        std::fs::read_to_string("/proc/self/maps").map_err(|_| msg("sse map read failed"))?;
    Ok((
        perm_at(&text, map.code as usize)?,
        perm_at(&text, map.data as usize)?,
    ))
}

#[cfg(test)]
fn perm_at(text: &str, addr: usize) -> Result<String> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else { continue };
        let Some(perms) = parts.next() else { continue };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let start = usize::from_str_radix(start, 16).unwrap_or(0);
        let end = usize::from_str_radix(end, 16).unwrap_or(0);
        if addr >= start && addr < end {
            return Ok(perms.to_string());
        }
    }
    Err(msg("sse page is not mapped"))
}

#[cfg(test)]
const YMM_PAINT: u32 = 0x7E0;

#[cfg(test)]
const _: () = assert!(SAVE_MARK < YMM_PAINT && YMM_PAINT as usize + 32 <= YMM_SAVE as usize);

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Probe {
    Off,
    SaveUd,
    Keep,
    GuestUd,
}

#[cfg(test)]
thread_local! {
    static YMM_PROBE: std::cell::Cell<Probe> = const { std::cell::Cell::new(Probe::Off) };
    static YMM15_SNAP: std::cell::Cell<[u8; 32]> = const { std::cell::Cell::new([0; 32]) };
    static ZMM_PROBE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static ZMM31_SNAP: std::cell::Cell<[u8; 64]> = const { std::cell::Cell::new([0; 64]) };
}

#[cfg(test)]
fn ymm_probe() -> Probe {
    YMM_PROBE.with(std::cell::Cell::get)
}

#[cfg(test)]
struct ProbeGuard;

#[cfg(test)]
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        YMM_PROBE.with(|cell| cell.set(Probe::Off));
    }
}

#[cfg(test)]
fn arm_probe(probe: Probe) -> ProbeGuard {
    YMM_PROBE.with(|cell| cell.set(probe));
    ProbeGuard
}

#[cfg(test)]
fn paints() -> bool {
    matches!(ymm_probe(), Probe::Keep | Probe::GuestUd)
}

#[cfg(test)]
fn ud2(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0x0F, 0x0B]);
}

#[cfg(test)]
fn force_save_mark(data: *mut u8) {
    // SAFETY: `data` is the live data mapping. `SAVE_MARK` is one byte at
    // 0x7C0, inside that 4096-byte page. The following reset must clear it.
    unsafe {
        std::ptr::write_volatile(data.add(SAVE_MARK as usize), 1u8);
    }
}

#[cfg(test)]
fn paint_host_canary(data: *mut u8) {
    if !paints() {
        return;
    }
    let bytes = [0x5Au8; 32];
    // SAFETY: `data` is the live data page. `YMM_PAINT` is 32 bytes at 0x7E0,
    // after the save marker and before `YMM_SAVE`, inside the 4096-byte page.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), data.add(YMM_PAINT as usize), bytes.len());
    }
}

#[cfg(test)]
fn fault_if_save_would_ud() {
    if ymm_probe() != Probe::SaveUd {
        return;
    }
    // SAFETY: SaveUd stands in for a host whose `vmovdqu` raises `#UD`. The
    // fault handler has already cleared `TRAP.armed`, so reaching this reload
    // must kill the process instead of returning `sse fault`.
    unsafe {
        std::arch::asm!("ud2", options(nostack, noreturn));
    }
}

#[cfg(test)]
#[inline(never)]
fn snap_ymm15_for_probe() {
    if !paints() {
        return;
    }
    let mut buf = [0u8; 32];
    // SAFETY: Keep and GuestUd run only when the host can execute `vmovdqu`.
    // The store records ymm15 after the reload decision and does not write a
    // register.
    unsafe {
        std::arch::asm!(
            "vmovdqu [{buf}], ymm15",
            buf = in(reg) buf.as_mut_ptr(),
            options(nostack, preserves_flags),
        );
    }
    YMM15_SNAP.with(|cell| cell.set(buf));
}

#[cfg(test)]
fn clear_ymm_snap() {
    YMM15_SNAP.with(|cell| cell.set([0; 32]));
}

#[cfg(test)]
fn paint_zmm31_canary(save_zmm: bool) {
    if !save_zmm || !ZMM_PROBE.with(std::cell::Cell::get) {
        return;
    }
    let bytes = [0x5Au8; 64];
    // SAFETY: the caller armed the probe only when AVX-512F and XCR0 ZMM state
    // are enabled, so `vmovdqu64` does not fault. The store is the canary the
    // stub must restore. Flags are unchanged.
    unsafe {
        std::arch::asm!(
            "vmovdqu64 zmm31, [{ptr}]",
            ptr = in(reg) bytes.as_ptr(),
            out("zmm31") _,
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(test)]
fn snap_zmm31(save_zmm: bool) {
    if !save_zmm || !ZMM_PROBE.with(std::cell::Cell::get) {
        return;
    }
    let mut buf = [0u8; 64];
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
    // SAFETY: the same probe precondition as `paint_zmm31_canary`. The store
    // records zmm31 after the stub's host reload and does not write a register
    // other than the output buffer.
    unsafe {
        std::arch::asm!(
            "vmovdqu64 [{buf}], zmm31",
            buf = in(reg) buf.as_mut_ptr(),
            options(nostack, preserves_flags),
        );
    }
    ZMM31_SNAP.with(|cell| cell.set(buf));
}

#[cfg(test)]
struct ZmmProbe;

#[cfg(test)]
impl Drop for ZmmProbe {
    fn drop(&mut self) {
        ZMM_PROBE.with(|cell| cell.set(false));
    }
}

#[cfg(test)]
fn arm_zmm_probe() -> ZmmProbe {
    ZMM_PROBE.with(|cell| cell.set(true));
    ZmmProbe
}

#[cfg(test)]
fn ymm_snap() -> [u8; 32] {
    YMM15_SNAP.with(std::cell::Cell::get)
}

#[cfg(test)]
fn run_probed(probe: Probe, upper: u8) -> Result<()> {
    let _guard = arm_probe(probe);
    run_vaddps(upper)
}

#[cfg(test)]
fn run_vaddps(upper: u8) -> Result<()> {
    let bytes = vaddps_ymm();
    let mut sse = Sse::default();
    sse.xmm.fill([0x3C; 16]);
    sse.upper.fill([upper; 16]);
    let mut x87 = X87::default();
    let mut regs = [0u64; 16];
    let mut flags = Flags::default();
    let mut af = false;
    let mut mem = crate::ir::MapMem::default();
    super::execute(
        &mut sse, &mut x87, &mut regs, &mut flags, &mut af, false, &mut mem, &bytes, 0x1000, 0,
    )
}

#[cfg(test)]
fn vaddps_ymm() -> Vec<u8> {
    use iced_x86::{Code, Encoder, Instruction, OpKind, Register};
    let mut insn = Instruction::default();
    insn.set_code(Code::VEX_Vaddps_ymm_ymm_ymmm256);
    insn.set_op0_kind(OpKind::Register);
    insn.set_op0_register(Register::YMM0);
    insn.set_op1_kind(OpKind::Register);
    insn.set_op1_register(Register::YMM1);
    insn.set_op2_kind(OpKind::Register);
    insn.set_op2_register(Register::YMM2);
    let mut encoder = Encoder::new(64);
    encoder.encode(&insn, 0x1000).expect("vaddps");
    encoder.take_buffer()
}

#[cfg(test)]
fn host_can_vmovdqu() -> bool {
    let one = std::arch::x86_64::__cpuid(1);
    if one.ecx & (1 << 28) == 0 || one.ecx & (1 << 27) == 0 {
        return false;
    }
    let eax: u32;
    let edx: u32;
    // SAFETY: CPUID.01H:ECX[27] OSXSAVE is set, so `xgetbv` with ecx 0 reads
    // XCR0 and does not fault. It only writes eax and edx.
    unsafe {
        std::arch::asm!(
            "xgetbv",
            in("ecx") 0u32,
            lateout("eax") eax,
            lateout("edx") edx,
            options(nomem, nostack, preserves_flags),
        );
    }
    let xcr0 = u64::from(eax) | (u64::from(edx) << 32);
    xcr0 & 6 == 6
}

#[cfg(test)]
fn vzeroupper() {
    // SAFETY: `host_can_vmovdqu` is true, so `vzeroupper` clears bits 255:128
    // and does not fault. Flags are unchanged.
    unsafe {
        std::arch::asm!("vzeroupper", options(nostack, preserves_flags));
    }
}

#[cfg(test)]
#[test]
fn clear_operand_covers_the_aligned_ymm_tail() {
    let map = mapping().expect("sse page");
    let _guard = crate::x87::lock_unit();
    let page = map.data;
    let before = MEM as usize - 1;
    let first_new = MEM as usize + 16 + MEM_CAP;
    let last = MEM as usize + OPERAND_SPAN - 1;
    poke(page, before, 0x11);
    poke(page, first_new, 0x22);
    poke(page, last, 0x33);
    poke(page, SAVE_MARK as usize, 0x44);
    poke(page, YMM_SAVE as usize, 0x55);
    clear_operand(page);
    assert_eq!(peek(page, before), 0x11, "byte before MEM");
    assert_eq!(peek(page, MEM as usize), 0, "start of the operand window");
    assert_eq!(peek(page, first_new), 0, "byte past the old 16-byte window");
    assert_eq!(peek(page, last), 0, "last byte of the 32-byte aligned span");
    assert_eq!(peek(page, SAVE_MARK as usize), 0x44, "marker is not tail");
    assert_eq!(peek(page, YMM_SAVE as usize), 0x55, "YMM save stays put");
    poke(page, before, 0);
    poke(page, SAVE_MARK as usize, 0);
    poke(page, YMM_SAVE as usize, 0);
}

#[cfg(test)]
fn poke(page: *mut u8, off: usize, value: u8) {
    // SAFETY: `page` is the live data mapping and `off` is inside that page.
    unsafe { page.add(off).write(value) }
}

#[cfg(test)]
fn peek(page: *mut u8, off: usize) -> u8 {
    // SAFETY: `page` is the live data mapping and `off` is inside that page.
    unsafe { page.add(off).read() }
}

#[cfg(test)]
#[test]
fn ymm_save_ud_returns_sse_fault_and_guest_ud_restores_uppers() {
    if host_can_vmovdqu() {
        assert_keep_restores_ymm15();
        assert_guest_ud_restores_ymm15();
    }
    assert_save_ud_is_sse_fault();
    if host_can_vmovdqu() {
        vzeroupper();
    }
}

#[cfg(test)]
fn assert_keep_restores_ymm15() {
    clear_ymm_snap();
    let err = run_probed(Probe::Keep, 0xEE);
    assert!(err.is_ok(), "vaddps should retire, got {err:?}");
    assert_eq!(ymm_snap(), [0x5A; 32], "success path reloads host ymm15");
}

#[cfg(test)]
fn assert_guest_ud_restores_ymm15() {
    clear_ymm_snap();
    let err = run_probed(Probe::GuestUd, 0xEE).expect_err("guest #UD must not retire");
    assert!(
        err.to_string().contains("sse fault"),
        "guest #UD must be sse fault, got {err}"
    );
    assert_eq!(
        ymm_snap(),
        [0x5A; 32],
        "guest #UD after the save must reload host ymm15, got {:02x?}",
        ymm_snap()
    );
}

#[cfg(test)]
fn assert_save_ud_is_sse_fault() {
    let err = run_probed(Probe::SaveUd, 0xEE).expect_err("save #UD must not retire");
    assert!(
        err.to_string().contains("sse fault"),
        "save-time #UD must be sse fault, got {err}"
    );
}

#[cfg(test)]
#[test]
fn ymm_encoding_matches_the_assembler() {
    let store = ymm_bytes(true, 3, 11, 0x860);
    let load = ymm_bytes(false, 8, 11, 0x800);
    assert_eq!(
        store,
        assembler_ymm(
            true,
            iced_x86::Register::YMM3,
            iced_x86::Register::R11,
            0x860
        )
    );
    assert_eq!(
        load,
        assembler_ymm(
            false,
            iced_x86::Register::YMM8,
            iced_x86::Register::R11,
            0x800
        )
    );
}

#[cfg(test)]
#[test]
fn save_mark_matches_the_assembler() {
    assert_eq!(mark_bytes(3), assembler_mark(iced_x86::Register::RBX));
    assert_eq!(mark_bytes(11), assembler_mark(iced_x86::Register::R11));
    assert_eq!(mark_bytes(13), assembler_mark(iced_x86::Register::R13));
}

#[cfg(test)]
fn mark_bytes(base: usize) -> Vec<u8> {
    let mut code = Vec::new();
    mark_ymm_saved(&mut code, base);
    code
}

#[cfg(test)]
fn ymm_bytes(store: bool, ymm: usize, base: usize, disp: u32) -> Vec<u8> {
    let mut code = Vec::new();
    ymm_move(&mut code, store, ymm, base, disp);
    code
}

#[cfg(test)]
fn assembler_ymm(
    store: bool,
    ymm: iced_x86::Register,
    base: iced_x86::Register,
    disp: u64,
) -> Vec<u8> {
    use iced_x86::{Code, Encoder, Instruction, OpKind};
    let code = if store {
        Code::VEX_Vmovdqu_ymmm256_ymm
    } else {
        Code::VEX_Vmovdqu_ymm_ymmm256
    };
    let mut insn = Instruction::default();
    insn.set_code(code);
    insn.set_memory_base(base);
    insn.set_memory_displ_size(1);
    insn.set_memory_displacement64(disp);
    if store {
        insn.set_op0_kind(OpKind::Memory);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(ymm);
    } else {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(ymm);
        insn.set_op1_kind(OpKind::Memory);
    }
    let mut encoder = Encoder::new(64);
    encoder.encode(&insn, 0).expect("vmovdqu");
    encoder.take_buffer()
}

#[cfg(test)]
fn assembler_mark(base: iced_x86::Register) -> Vec<u8> {
    use iced_x86::{Code, Encoder, Instruction, OpKind};
    let mut insn = Instruction::default();
    insn.set_code(Code::Mov_rm8_imm8);
    insn.set_op0_kind(OpKind::Memory);
    insn.set_memory_base(base);
    insn.set_memory_displ_size(1);
    insn.set_memory_displacement64(u64::from(SAVE_MARK));
    insn.set_op1_kind(OpKind::Immediate8);
    insn.set_immediate8(1);
    let mut encoder = Encoder::new(64);
    encoder.encode(&insn, 0).expect("mov byte");
    encoder.take_buffer()
}

#[cfg(test)]
#[test]
fn evex_replay_restores_host_zmm31() {
    if crate::sse::claim::l6_skip_reason(iced_x86::Mnemonic::Vaddps).is_some() {
        return;
    }
    let _guard = arm_zmm_probe();
    ZMM31_SNAP.with(|cell| cell.set([0; 64]));
    run_evex(evex_vaddps()).expect("vaddps zmm");
    assert_eq!(ZMM31_SNAP.with(std::cell::Cell::get), [0x5A; 64]);
    let err = run_evex_div().expect_err("unmasked div must not retire");
    assert!(err.to_string().contains("sse fault"), "{err}");
    assert_eq!(
        ZMM31_SNAP.with(std::cell::Cell::get),
        [0x5A; 64],
        "fault after the ZMM save must reload host zmm31"
    );
}

#[cfg(test)]
fn run_evex(bytes: Vec<u8>) -> Result<()> {
    let mut sse = Sse::default();
    sse.xmm[0] = [0x3C; 16];
    sse.xmm[1] = [0x3C; 16];
    let mut x87 = X87::default();
    let mut regs = [0u64; 16];
    let mut flags = Flags::default();
    let mut af = false;
    let mut mem = crate::ir::MapMem::default();
    super::execute(
        &mut sse, &mut x87, &mut regs, &mut flags, &mut af, false, &mut mem, &bytes, 0x1000, 0,
    )
}

#[cfg(test)]
fn run_evex_div() -> Result<()> {
    let mut sse = Sse {
        mxcsr: 0x1d80,
        ..Sse::default()
    };
    sse.xmm[0][..4].copy_from_slice(&1.0f32.to_le_bytes());
    let mut x87 = X87::default();
    let mut regs = [0u64; 16];
    let mut flags = Flags::default();
    let mut af = false;
    let mut mem = crate::ir::MapMem::default();
    super::execute(
        &mut sse,
        &mut x87,
        &mut regs,
        &mut flags,
        &mut af,
        false,
        &mut mem,
        &evex_vdivps(),
        0x1000,
        0,
    )
}

#[cfg(test)]
fn evex_vaddps() -> Vec<u8> {
    evex_op(iced_x86::Code::EVEX_Vaddps_zmm_k1z_zmm_zmmm512b32_er)
}

#[cfg(test)]
fn evex_vdivps() -> Vec<u8> {
    evex_op(iced_x86::Code::EVEX_Vdivps_zmm_k1z_zmm_zmmm512b32_er)
}

#[cfg(test)]
fn evex_op(code: iced_x86::Code) -> Vec<u8> {
    use iced_x86::{Encoder, Instruction, OpKind, Register};
    let mut insn = Instruction::default();
    insn.set_code(code);
    insn.set_op0_kind(OpKind::Register);
    insn.set_op0_register(Register::ZMM0);
    insn.set_op1_kind(OpKind::Register);
    insn.set_op1_register(Register::ZMM0);
    insn.set_op2_kind(OpKind::Register);
    insn.set_op2_register(Register::ZMM1);
    let mut encoder = Encoder::new(64);
    encoder.encode(&insn, 0x1000).expect("evex");
    encoder.take_buffer()
}
