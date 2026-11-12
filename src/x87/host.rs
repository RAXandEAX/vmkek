//! Replay one x87 instruction on the host x87 unit.
//!
//! The architectural stack stays in [`X87`]. For the duration of the
//! instruction the unit is loaded from that stack, the opcode runs, and the
//! unit is saved back. SSE state is restored before the function returns.
//! Rounding follows the control word because that word is loaded into the unit.
//!
//! The stub code lives on its own page. That page is writable only while the
//! stub is patched and executable only for the call. [`execution`] serializes
//! threads. It is not async-signal-safe: a signal between the guest `fxrstor`
//! and the host `fxrstor` observes the guest x87 unit, and a handler that
//! enters `run` can deadlock on the same mutex.

use std::sync::Mutex;

use crate::error::{msg, Result};
use crate::flags::Flags;
use crate::ir::X87;

const PAGE: usize = 4096;
const HOST: u32 = 0x100;
const GUEST: u32 = 0x300;
const RESULT: u32 = 0x500;
const MEM: u32 = 0x700;
const MEM_CAP: usize = 512;
const FLAGS_IN: u32 = 0x900;
const FLAGS_OUT: u32 = 0x908;
const RAX_IN: u32 = 0x910;
const RAX_OUT: u32 = 0x918;
const PROT_RW: usize = 3;
const PROT_RX: usize = 5;

const _: () = assert!(HOST + 512 <= GUEST);
const _: () = assert!(GUEST + 512 <= RESULT);
const _: () = assert!(RESULT + 512 <= MEM);
const _: () = assert!(MEM as usize + MEM_CAP <= FLAGS_IN as usize);
const _: () = assert!(RAX_OUT + 8 <= PAGE as u32);

struct Mapping {
    code: *mut u8,
    data: *mut u8,
}

fn mapping() -> Result<Mapping> {
    static SLOT: Mutex<Option<(usize, usize)>> = Mutex::new(None);
    let mut slot = SLOT.lock().unwrap_or_else(|err| err.into_inner());
    if let Some((code, data)) = *slot {
        return Ok(Mapping {
            code: code as *mut u8,
            data: data as *mut u8,
        });
    }
    let code = map_page()?;
    let data = map_page()?;
    *slot = Some((code as usize, data as usize));
    Ok(Mapping { code, data })
}

fn map_page() -> Result<*mut u8> {
    // SAFETY: `mmap` returns a fresh anonymous page or a negative errno.
    // The pointer is kept only after that check.
    let mapped = unsafe { mmap(PROT_RW) };
    if (mapped as isize) < 0 {
        return Err(msg("x87 page allocation failed"));
    }
    Ok(mapped)
}

/// Serializes host x87 use across threads.
///
/// The mutex is not async-signal-safe. It only keeps two threads out of `run`
/// at once. A signal delivered after the stub's guest `fxrstor` and before
/// its host `fxrstor` observes the guest x87 unit. Calling `run` from that
/// handler sees the guest stack and can deadlock on this lock.
fn execution() -> &'static Mutex<()> {
    static EXEC: Mutex<()> = Mutex::new(());
    &EXEC
}

/// Serializes host x87 and SSE use. SSE replay takes the same lock: both load
/// the FPU/SSE unit with `fxrstor`.
pub(crate) fn lock_unit() -> std::sync::MutexGuard<'static, ()> {
    execution().lock().unwrap_or_else(|err| err.into_inner())
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
        return Err(msg("x87 page protection failed"));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn capture_template() -> [u8; 512] {
    let _guard = execution().lock().unwrap_or_else(|err| err.into_inner());
    capture_template_unlocked()
}

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

#[repr(C, align(16))]
struct Align16([u8; 512]);

#[allow(
    clippy::too_many_arguments,
    reason = "the host stub takes the x87 stack, flags, memory, and guest pointers as separate inputs"
)]
pub(super) fn run(
    state: &mut X87,
    rax: &mut u64,
    flags: &mut Flags,
    af: &mut bool,
    df: bool,
    mem: &mut [u8],
    insn: &[u8],
    guest_ip: u64,
    guest_ea: Option<u64>,
    writes_flags: bool,
) -> Result<()> {
    if insn.is_empty() || insn.len() > 15 {
        return Err(msg("x87 encoding does not fit"));
    }
    if mem.len() > MEM_CAP {
        return Err(msg("x87 memory operand is too large"));
    }
    let map = mapping()?;
    let _guard = execution().lock().unwrap_or_else(|err| err.into_inner());
    stage_stub(
        &map,
        &GuestIn {
            state,
            mem,
            flags: *flags,
            af: *af,
            df,
            rax: *rax,
            insn,
        },
    )?;
    call_stub(map.code);
    harvest(
        &map,
        GuestOut {
            state,
            mem,
            rax,
            flags,
            af,
            writes_flags,
            guest_ip,
            guest_ea,
        },
    );
    Ok(())
}

struct GuestIn<'a> {
    state: &'a X87,
    mem: &'a [u8],
    flags: Flags,
    af: bool,
    df: bool,
    rax: u64,
    insn: &'a [u8],
}

struct GuestOut<'a> {
    state: &'a mut X87,
    mem: &'a mut [u8],
    rax: &'a mut u64,
    flags: &'a mut Flags,
    af: &'a mut bool,
    writes_flags: bool,
    guest_ip: u64,
    guest_ea: Option<u64>,
}

fn stage_stub(map: &Mapping, guest: &GuestIn<'_>) -> Result<()> {
    write_block(map.data, GUEST, &guest_image(guest.state));
    write_inputs(
        map.data,
        guest.mem,
        guest.flags,
        guest.af,
        guest.df,
        guest.rax,
    );
    let code = stub(map.data as u64, guest.insn);
    protect(map.code, PROT_RW)?;
    write_stub(map.code, &code)?;
    protect(map.code, PROT_RX)
}

fn harvest(map: &Mapping, guest: GuestOut<'_>) {
    read_outputs(
        map.data,
        guest.mem,
        guest.rax,
        guest.flags,
        guest.af,
        guest.writes_flags,
    );
    let result = read_block(map.data, RESULT);
    crate::x87::import_image(guest.state, &result);
    rewrite_pointers(
        guest.state,
        map.code as u64,
        map.data as u64,
        guest.guest_ip,
        guest.guest_ea,
    );
}

fn guest_image(state: &X87) -> [u8; 512] {
    // Seed MXCSR from the live unit. The stub copies the live XMM image over
    // this buffer before `fxrstor`, so SSE state is not replaced by the template.
    let mut guest = capture_template_unlocked();
    crate::x87::export_image(state, &mut guest);
    guest
}

fn write_inputs(data: *mut u8, mem: &[u8], flags: Flags, af: bool, df: bool, rax: u64) {
    clear_operand(data);
    if !mem.is_empty() {
        copy_operand_in(data, mem);
    }
    write_u64(data, FLAGS_IN, rflags(flags, af, df));
    write_u64(data, RAX_IN, rax);
}

fn clear_operand(data: *mut u8) {
    // SAFETY: `data` is the live data mapping. MEM + MEM_CAP (0x700 + 512)
    // stays inside that 4096-byte page.
    unsafe {
        std::ptr::write_bytes(data.add(MEM as usize), 0, MEM_CAP);
    }
}

fn copy_operand_in(data: *mut u8, mem: &[u8]) {
    // SAFETY: `data` is the live data mapping, and `mem.len()` is at most
    // MEM_CAP, so the write stays inside the 4096-byte page.
    unsafe {
        std::ptr::copy_nonoverlapping(mem.as_ptr(), data.add(MEM as usize), mem.len());
    }
}

fn write_stub(code: *mut u8, bytes: &[u8]) -> Result<()> {
    if bytes.len() >= PAGE {
        return Err(msg("x87 stub overlaps the save area"));
    }
    // SAFETY: `code` is the live code page, write permission was just
    // restored, and `bytes.len()` is less than the 4096-byte page.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), code, bytes.len());
    }
    Ok(())
}

fn call_stub(code: *mut u8) {
    // SAFETY: `code` is the live mapping with write permission dropped. The
    // bytes just copied are a leaf: it saves the host x87/SSE state, executes
    // one instruction, and restores that state before returning.
    let entry: extern "C" fn() = unsafe { std::mem::transmute(code) };
    entry();
}

fn read_outputs(
    data: *mut u8,
    mem: &mut [u8],
    rax: &mut u64,
    flags: &mut Flags,
    af: &mut bool,
    writes_flags: bool,
) {
    if !mem.is_empty() {
        // SAFETY: `data` is the live data mapping and `mem.len()` was checked
        // against MEM_CAP, so the copy stays inside the 4096-byte page.
        unsafe {
            std::ptr::copy_nonoverlapping(data.add(MEM as usize), mem.as_mut_ptr(), mem.len());
        }
    }
    *rax = read_u64(data, RAX_OUT);
    if writes_flags {
        apply_flags(read_u64(data, FLAGS_OUT), flags, af);
    }
}

fn rewrite_pointers(state: &mut X87, code: u64, data: u64, guest_ip: u64, guest_ea: Option<u64>) {
    if state.fip >= code && state.fip < code + PAGE as u64 {
        state.fip = guest_ip;
    }
    let mem_addr = data + u64::from(MEM);
    if state.fdp >= mem_addr && state.fdp < mem_addr + MEM_CAP as u64 {
        if let Some(ea) = guest_ea {
            state.fdp = ea + (state.fdp - mem_addr);
        }
    }
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

fn read_block(page: *mut u8, off: u32) -> [u8; 512] {
    let mut out = [0u8; 512];
    // SAFETY: `page` is the live data mapping, and `off + 512` stays inside
    // that 4096-byte page. HOST, GUEST, and RESULT (0x100, 0x300, 0x500)
    // each end 512 bytes before the next region.
    unsafe {
        std::ptr::copy_nonoverlapping(page.add(off as usize), out.as_mut_ptr(), 512);
    }
    out
}

fn write_block(page: *mut u8, off: u32, bytes: &[u8; 512]) {
    // SAFETY: `page` is the live data mapping, and `off + 512` stays inside
    // that 4096-byte page. HOST, GUEST, and RESULT (0x100, 0x300, 0x500)
    // each end 512 bytes before the next region.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), page.add(off as usize), 512);
    }
}

fn write_u64(page: *mut u8, off: u32, value: u64) {
    // SAFETY: `page` is the live data mapping. FLAGS_IN, FLAGS_OUT, RAX_IN,
    // and RAX_OUT are the only offsets, and each `off + 8` stays inside the
    // 4096-byte page.
    unsafe {
        std::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), page.add(off as usize), 8);
    }
}

fn read_u64(page: *mut u8, off: u32) -> u64 {
    let mut raw = [0u8; 8];
    // SAFETY: `page` is the live data mapping. FLAGS_OUT and RAX_OUT plus 8
    // bytes stay inside the 4096-byte page.
    unsafe {
        std::ptr::copy_nonoverlapping(page.add(off as usize), raw.as_mut_ptr(), 8);
    }
    u64::from_le_bytes(raw)
}

fn stub(page: u64, insn: &[u8]) -> Vec<u8> {
    let mut code = Vec::with_capacity(180 + insn.len());
    code.push(0x53); // push rbx
    code.push(0x56); // push rsi
    code.push(0x57); // push rdi
    code.extend_from_slice(&[0x41, 0x57]); // push r15
    code.push(0x9c); // pushfq
    code.extend_from_slice(&[0x48, 0xbb]); // mov rbx, data page
    code.extend_from_slice(&page.to_le_bytes());
    code.push(0xfc); // cld
    fxsave(&mut code, HOST);
    copy_range(&mut code, HOST + 24, GUEST + 24, 8);
    copy_range(&mut code, HOST + 160, GUEST + 160, 352);
    fxrstor(&mut code, GUEST);
    code.extend_from_slice(&[0x48, 0x8b, 0x83]); // mov rax, [rbx+RAX_IN]
    code.extend_from_slice(&RAX_IN.to_le_bytes());
    code.extend_from_slice(&[0xff, 0xb3]); // push qword [rbx+FLAGS_IN]
    code.extend_from_slice(&FLAGS_IN.to_le_bytes());
    code.push(0x9d); // popfq
    code.extend_from_slice(&[0x4c, 0x8d, 0xbb]); // lea r15, [rbx+MEM]
    code.extend_from_slice(&MEM.to_le_bytes());
    code.extend_from_slice(insn);
    code.extend_from_slice(&[0x48, 0x89, 0x83]); // mov [rbx+RAX_OUT], rax
    code.extend_from_slice(&RAX_OUT.to_le_bytes());
    code.push(0x9c); // pushfq
    code.extend_from_slice(&[0x8f, 0x83]); // pop qword [rbx+FLAGS_OUT]
    code.extend_from_slice(&FLAGS_OUT.to_le_bytes());
    fxsave(&mut code, RESULT);
    fxrstor(&mut code, HOST);
    code.push(0x9d); // popfq
    code.extend_from_slice(&[0x41, 0x5f]); // pop r15
    code.push(0x5f); // pop rdi
    code.push(0x5e); // pop rsi
    code.push(0x5b); // pop rbx
    code.push(0xc3); // ret
    code
}

fn fxsave(code: &mut Vec<u8>, disp: u32) {
    code.extend_from_slice(&[0x48, 0x0f, 0xae, 0x83]);
    code.extend_from_slice(&disp.to_le_bytes());
}

fn fxrstor(code: &mut Vec<u8>, disp: u32) {
    code.extend_from_slice(&[0x48, 0x0f, 0xae, 0x8b]);
    code.extend_from_slice(&disp.to_le_bytes());
}

fn copy_range(code: &mut Vec<u8>, src: u32, dst: u32, len: u32) {
    code.extend_from_slice(&[0x48, 0x89, 0xde]); // mov rsi, rbx
    code.extend_from_slice(&[0x48, 0x81, 0xc6]); // add rsi, src
    code.extend_from_slice(&src.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0xdf]); // mov rdi, rbx
    code.extend_from_slice(&[0x48, 0x81, 0xc7]); // add rdi, dst
    code.extend_from_slice(&dst.to_le_bytes());
    code.push(0xb9); // mov ecx, len
    code.extend_from_slice(&len.to_le_bytes());
    code.extend_from_slice(&[0xf3, 0xa4]); // rep movsb
}

#[cfg(test)]
pub(super) fn page_perms() -> Result<(String, String)> {
    let map = mapping()?;
    let _guard = execution().lock().unwrap_or_else(|err| err.into_inner());
    let text =
        std::fs::read_to_string("/proc/self/maps").map_err(|_| msg("x87 map read failed"))?;
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
    Err(msg("x87 page is not mapped"))
}
