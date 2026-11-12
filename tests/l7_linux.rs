//! M-LINUX system channel for L7. This process does not run the SSE host tests,
//! so the SIGFPE disposition here does not race them.

use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use vmkek::ir::Exit;
use vmkek::unwind::{setjmp_longjmp_obs, SetjmpObs};

const PAGE: usize = 4096;
const SIGFPE: i32 = 8;
const SA_NODEFER: i32 = 0x4000_0000;

static HITS: AtomicUsize = AtomicUsize::new(0);
static LAST_SIG: AtomicI32 = AtomicI32::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);
static MARKER: AtomicU64 = AtomicU64::new(0);
static JMP: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());

#[repr(C)]
struct SigAction {
    handler: usize,
    mask: [u64; 16],
    flags: i32,
    _pad: i32,
    restorer: usize,
}

extern "C" {
    #[link_name = "__sigsetjmp"]
    fn sigsetjmp(env: *mut u8, savemask: i32) -> i32;
    fn siglongjmp(env: *mut u8, val: i32) -> !;
    fn sigaction(sig: i32, act: *const SigAction, old: *mut SigAction) -> i32;
}

extern "C" fn on_sigfpe(sig: i32) {
    HITS.fetch_add(1, Ordering::Relaxed);
    LAST_SIG.store(sig, Ordering::Relaxed);
    SEEN.store(on_sigfpe as *const () as usize, Ordering::Relaxed);
    let buf = JMP.load(Ordering::Acquire);
    // SAFETY: `raise_sigfpe` stored `JMP` to a live `sigsetjmp` buffer on this
    // thread before the fault. This is the matching `siglongjmp`.
    unsafe { siglongjmp(buf, 1) }
}

#[inline(never)]
extern "C" fn div_zero() {
    // SAFETY: the divisor is zero. The installed SIGFPE handler long-jumps out
    // before this function returns.
    unsafe {
        std::arch::asm!(
            "xor ecx, ecx",
            "mov eax, 1",
            "cdq",
            "div ecx",
            out("eax") _,
            out("edx") _,
            out("ecx") _,
            options(nostack),
        );
    }
}

#[inline(never)]
extern "C" fn leave(buf: *mut u8) {
    MARKER.store(0x3333, Ordering::SeqCst);
    // SAFETY: `buf` is the `sigsetjmp` buffer of the caller on this thread.
    unsafe { siglongjmp(buf, 7) }
}

#[inline(never)]
extern "C-unwind" fn boom() {
    panic!("l7-unwind");
}

struct Restore(SigAction);

impl Drop for Restore {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the disposition `sigaction` returned for SIGFPE.
        unsafe {
            sigaction(SIGFPE, &self.0, std::ptr::null_mut());
        }
    }
}

fn install() -> Restore {
    let action = SigAction {
        handler: on_sigfpe as *const () as usize,
        mask: [0; 16],
        flags: SA_NODEFER,
        _pad: 0,
        restorer: 0,
    };
    let mut old = SigAction {
        handler: 0,
        mask: [0; 16],
        flags: 0,
        _pad: 0,
        restorer: 0,
    };
    // SAFETY: `action` and `old` match the libc `sigaction` layout used by the
    // SSE host. A non-zero return fails the test below.
    let rc = unsafe { sigaction(SIGFPE, &action, &mut old) };
    assert_eq!(rc, 0, "sigaction SIGFPE failed");
    Restore(old)
}

/// # Safety
/// `prot` is a Linux protection bitmask. The result is a fresh page or a
/// negative errno.
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
/// `page` is a live anonymous page from [`mmap`].
unsafe fn mprotect(page: *mut u8, prot: usize) -> isize {
    let rc: usize;
    std::arch::asm!(
        "syscall",
        in("rax") 10usize,
        in("rdi") page,
        in("rsi") PAGE,
        in("rdx") prot,
        lateout("rax") rc,
        out("rcx") _,
        out("r11") _,
    );
    rc as isize
}

fn map_jump(target: usize) -> *mut u8 {
    // SAFETY: `mmap` asks for one private anonymous page. The write happens
    // before the page is switched to read/execute.
    let page = unsafe { mmap(3) };
    assert!((page as isize) >= 0, "mmap failed");
    let mut insn = [0u8; 12];
    insn[0] = 0x48;
    insn[1] = 0xb8;
    insn[2..10].copy_from_slice(&target.to_le_bytes());
    insn[10] = 0xff;
    insn[11] = 0xe0;
    // SAFETY: `page` is the fresh writable mapping. Twelve bytes fit in it.
    unsafe { std::ptr::copy_nonoverlapping(insn.as_ptr(), page, insn.len()) };
    // SAFETY: `page` is that mapping. Protection 5 is read/execute.
    let rc = unsafe { mprotect(page, 5) };
    assert!(rc >= 0, "mprotect failed");
    page
}

fn jump_to(target: usize) {
    let page = map_jump(target);
    // SAFETY: `page` is the RX trampoline from `map_jump`. Its first bytes are
    // `movabs rax, imm64; jmp rax` to `target`. The tail jump adds no frame.
    // C-unwind lets the panic in `boom` propagate to the Rust caller.
    let call: extern "C-unwind" fn() = unsafe { std::mem::transmute(page) };
    call();
}

fn raise_sigfpe(via: bool) -> i32 {
    let mut buf = [0u8; 256];
    JMP.store(buf.as_mut_ptr(), Ordering::Release);
    // SAFETY: `buf` is a 256-byte `jmp_buf`. The handler long-jumps here.
    let rc = unsafe { sigsetjmp(buf.as_mut_ptr(), 1) };
    if std::hint::black_box(rc) == 0 {
        if via {
            jump_to(div_zero as *const () as usize);
        } else {
            div_zero();
        }
    }
    rc
}

fn run_longjmp(via: bool) -> SetjmpObs {
    let local = 0x1111u64;
    let mut slot = local;
    std::hint::black_box(&mut slot);
    let mut buf = [0u8; 256];
    MARKER.store(0, Ordering::SeqCst);
    // SAFETY: `buf` is a 256-byte `jmp_buf` for this frame.
    let rc = unsafe { sigsetjmp(buf.as_mut_ptr(), 0) };
    if std::hint::black_box(rc) == 0 {
        if via {
            let page = map_jump(leave as *const () as usize);
            // SAFETY: `page` is the RX trampoline from `map_jump`. Its first
            // bytes are `movabs rax, imm64; jmp rax` to `leave`, so this
            // transmute is `extern "C" fn(*mut u8)` and receives the `jmp_buf`.
            let call: extern "C" fn(*mut u8) = unsafe { std::mem::transmute(page) };
            call(buf.as_mut_ptr());
        } else {
            leave(buf.as_mut_ptr());
        }
    }
    // SAFETY: `slot` is this frame's live local. `read_volatile` reloads it
    // after `siglongjmp` returns here, instead of reusing a pre-jump register.
    let seen = unsafe { std::ptr::read_volatile(&slot) };
    SetjmpObs {
        value: rc,
        local: seen,
        marker: MARKER.load(Ordering::SeqCst),
    }
}

#[test]
fn panic_and_sigfpe_reach_the_same_handler() {
    let direct = std::panic::catch_unwind(|| boom());
    let via = std::panic::catch_unwind(|| jump_to(boom as *const () as usize));
    assert_eq!(payload(direct.unwrap_err()), "l7-unwind");
    assert_eq!(payload(via.unwrap_err()), "l7-unwind");

    let _restore = install();
    HITS.store(0, Ordering::Relaxed);
    let direct = raise_sigfpe(false);
    let via = raise_sigfpe(true);
    assert_eq!(direct, 1);
    assert_eq!(via, 1);
    assert_eq!(HITS.load(Ordering::Relaxed), 2);
    assert_eq!(LAST_SIG.load(Ordering::Relaxed), SIGFPE);
    assert_eq!(
        SEEN.load(Ordering::Relaxed),
        on_sigfpe as *const () as usize
    );
}

#[test]
fn setjmp_longjmp_observable_state_matches_through_trampoline() {
    let direct = run_longjmp(false);
    let via = run_longjmp(true);
    let model = setjmp_longjmp_obs(0x1111, 0x3333, 7);
    assert_eq!(direct, model);
    assert_eq!(via, model);

    let base = vmkek::pe::IMAGE_BASE;
    let rva = 0x1000u32;
    let target = 0x2000u32;
    let next = base + u64::from(rva) + 5;
    let dest = base + u64::from(target);
    let rel = i32::try_from(dest as i64 - next as i64).unwrap();
    let mut code = vec![0xe8];
    code.extend_from_slice(&rel.to_le_bytes());
    code.push(0xc3);
    let func = vmkek::lift::lift("setjmp", &code, rva, code.len() as u32, base).unwrap();
    match func.blocks[0].exit {
        Exit::CallRva { rva, .. } => assert_eq!(rva, target),
        other => panic!("lift dropped the setjmp call: {other:?}"),
    }
}

fn payload(err: Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = err.downcast_ref::<&str>() {
        return (*text).to_string();
    }
    if let Some(text) = err.downcast_ref::<String>() {
        return text.clone();
    }
    "other".into()
}
