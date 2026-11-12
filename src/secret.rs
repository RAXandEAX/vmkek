//! Key material that must not outlive the operation that used it.
//!
//! Stack buffers are wiped with volatile stores. A key page is allocated
//! separately, marked `MADV_DONTDUMP`, and cleared in the `pthread_atfork`
//! child handler so a forked child does not keep the parent's secret.

use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::sync::Once;

use crate::error::{msg, Result};

const PAGE: usize = 4096;
const CHUNK_LEN: usize = 32;
const SYS_MADVISE: i64 = 28;
const MADV_DONTDUMP: i64 = 16;

static HOOK_ONCE: Once = Once::new();
static HOOK_OK: AtomicBool = AtomicBool::new(false);
static HEAD: AtomicPtr<Chunk> = AtomicPtr::new(std::ptr::null_mut());

struct Chunk {
    slots: [AtomicUsize; CHUNK_LEN],
    next: AtomicPtr<Chunk>,
}

impl Chunk {
    fn blank() -> Self {
        Self {
            slots: std::array::from_fn(|_| AtomicUsize::new(0)),
            next: AtomicPtr::new(std::ptr::null_mut()),
        }
    }
}

extern "C" {
    fn pthread_atfork(
        prepare: Option<unsafe extern "C" fn()>,
        parent: Option<unsafe extern "C" fn()>,
        child: Option<unsafe extern "C" fn()>,
    ) -> i32;
}

/// Disable Linux process core dumps for the standalone protection command.
pub(crate) fn disable_process_dumps() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        const PR_SET_DUMPABLE: i32 = 4;
        extern "C" {
            fn prctl(option: i32, ...) -> i32;
        }
        // SAFETY: PR_SET_DUMPABLE takes one unsigned-long value and no pointers.
        let rc = unsafe { prctl(PR_SET_DUMPABLE, 0usize, 0usize, 0usize, 0usize) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

/// Zero `buf` so the compiler cannot drop the stores.
pub fn wipe(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid `u8` in `buf` for this store.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// Wipe the allocation and empty a vector of values that have no destructors.
pub(crate) fn wipe_copy_vec<T: Copy>(values: &mut Vec<T>) {
    values.clear();
    let bytes = values.capacity() * std::mem::size_of::<T>();
    let ptr = values.spare_capacity_mut().as_mut_ptr().cast::<u8>();
    // SAFETY: no initialized typed elements remain. The allocation covers
    // `bytes` bytes, which the volatile stores initialize without reading.
    unsafe { wipe_raw(ptr, bytes) };
}

/// Build-time bytes that may contain runtime key material.
pub(crate) struct WipeBuffer(pub Vec<u8>);

impl Drop for WipeBuffer {
    fn drop(&mut self) {
        wipe_copy_vec(&mut self.0);
    }
}

/// Clear volatile argument registers after a routine that held key bytes.
pub fn wipe_volatile_regs() {
    // SAFETY: the xors write only the named registers. The compiler treats
    // them as outputs, so it reloads anything it still needs afterwards.
    unsafe {
        std::arch::asm!(
            "xor eax, eax",
            "xor ecx, ecx",
            "xor edx, edx",
            "xor esi, esi",
            "xor edi, edi",
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            out("rsi") _,
            out("rdi") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack),
        );
    }
}

fn page_layout() -> std::alloc::Layout {
    std::alloc::Layout::from_size_align(PAGE, PAGE).expect("page layout")
}

fn alloc_page() -> Result<*mut u8> {
    let layout = page_layout();
    // SAFETY: `layout` is non-zero and page-aligned. Null means allocation failed.
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        return Err(msg("key page alloc failed"));
    }
    Ok(ptr)
}

unsafe fn wipe_raw(ptr: *mut u8, len: usize) {
    for offset in 0..len {
        // SAFETY: callers supply a writable allocation covering `len` bytes.
        unsafe { std::ptr::write_volatile(ptr.add(offset), 0) };
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

unsafe extern "C" fn wipe_child() {
    let mut cur = HEAD.load(Ordering::Acquire);
    while !cur.is_null() {
        // SAFETY: published chunks are never freed. Fork copied this pointer.
        let chunk = unsafe { &*cur };
        for slot in &chunk.slots {
            let addr = slot.swap(0, Ordering::AcqRel);
            if addr != 0 {
                // SAFETY: the fork snapshot only contains live registered key pages.
                unsafe { wipe_raw(addr as *mut u8, PAGE) };
            }
        }
        cur = chunk.next.load(Ordering::Acquire);
    }
    wipe_volatile_regs();
}

fn install_fork_hook() -> Result<()> {
    HOOK_ONCE.call_once(|| {
        // SAFETY: `wipe_child` only volatile-writes pages this process registered.
        let rc = unsafe { pthread_atfork(None, None, Some(wipe_child)) };
        HOOK_OK.store(rc == 0, Ordering::Release);
    });
    if HOOK_OK.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(msg("pthread_atfork failed"))
    }
}

fn head_chunk() -> *mut Chunk {
    let existing = HEAD.load(Ordering::Acquire);
    if !existing.is_null() {
        return existing;
    }
    let created = Box::into_raw(Box::new(Chunk::blank()));
    match HEAD.compare_exchange(
        std::ptr::null_mut(),
        created,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => created,
        Err(current) => {
            // SAFETY: `created` was never published, so this thread still owns it.
            unsafe { drop(Box::from_raw(created)) };
            current
        }
    }
}

fn claim_slot(chunk: &Chunk, addr: usize) -> bool {
    chunk.slots.iter().any(|slot| {
        slot.compare_exchange(0, addr, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    })
}

fn append_chunk(tail: &Chunk) -> bool {
    let created = Box::into_raw(Box::new(Chunk::blank()));
    if tail
        .next
        .compare_exchange(
            std::ptr::null_mut(),
            created,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        // SAFETY: `created` lost the race and was never published.
        unsafe { drop(Box::from_raw(created)) };
        return false;
    }
    true
}

fn register_page(addr: usize) -> Result<()> {
    loop {
        let mut cur = head_chunk();
        loop {
            // SAFETY: `cur` addresses a chunk that stays allocated for process life.
            let chunk = unsafe { &*cur };
            if claim_slot(chunk, addr) {
                return Ok(());
            }
            let next = chunk.next.load(Ordering::Acquire);
            if !next.is_null() {
                cur = next;
                continue;
            }
            if append_chunk(chunk) {
                break;
            }
        }
    }
}

fn unregister_page(addr: usize) {
    let mut cur = HEAD.load(Ordering::Acquire);
    while !cur.is_null() {
        // SAFETY: published chunks are never freed.
        let chunk = unsafe { &*cur };
        for slot in &chunk.slots {
            if slot
                .compare_exchange(addr, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
        cur = chunk.next.load(Ordering::Acquire);
    }
}

fn dont_dump(ptr: *mut u8) -> Result<()> {
    let rc = madvise_dont_dump(ptr);
    if rc != 0 {
        return Err(msg("madvise MADV_DONTDUMP failed"));
    }
    Ok(())
}

fn madvise_dont_dump(ptr: *mut u8) -> i64 {
    let rc: i64;
    // SAFETY: `ptr` is a page this process allocated. The call is `madvise`
    // with `MADV_DONTDUMP` and does not read the page.
    unsafe {
        std::arch::asm!(
            "syscall",
            in("rax") SYS_MADVISE,
            in("rdi") ptr,
            in("rsi") PAGE,
            in("rdx") MADV_DONTDUMP,
            lateout("rax") rc,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    rc
}

/// One page that holds a 32-byte key. The rest of the page stays zero.
pub struct KeyPage {
    ptr: *mut u8,
}

// SAFETY: the page is exclusively owned. The fork registry shares only the
// address, through atomics, and never aliases the bytes.
unsafe impl Send for KeyPage {}

impl KeyPage {
    /// Copy `key` into a fresh page, hide it from core dumps, and arm the fork hook.
    pub fn hold(key: &[u8; 32]) -> Result<Self> {
        install_fork_hook()?;
        let ptr = alloc_page()?;
        fill_key(ptr, key);
        if let Err(err) = dont_dump(ptr) {
            free_page(ptr);
            return Err(err);
        }
        if let Err(err) = register_page(ptr as usize) {
            free_page(ptr);
            return Err(err);
        }
        Ok(Self { ptr })
    }

    /// Bytes currently stored in the page.
    #[must_use]
    pub fn bytes(&self) -> [u8; 32] {
        read_key(self.ptr)
    }

    /// Overwrite the key in place. The page stays non-dumpable and registered.
    pub fn store(&mut self, key: &[u8; 32]) {
        for (offset, byte) in key.iter().enumerate() {
            // SAFETY: `offset` is below 32 and `ptr` is a live key page.
            unsafe { std::ptr::write_volatile(self.ptr.add(offset), *byte) };
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
    }

    /// Address of the page, used to find its `VmFlags`.
    #[must_use]
    pub fn addr(&self) -> usize {
        self.ptr as usize
    }
}

impl Clone for KeyPage {
    fn clone(&self) -> Self {
        let mut bytes = self.bytes();
        let page = Self::hold(&bytes).unwrap_or_else(|err| panic!("key page clone: {err}"));
        wipe(&mut bytes);
        page
    }
}

impl std::fmt::Debug for KeyPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyPage")
    }
}

fn fill_key(ptr: *mut u8, key: &[u8; 32]) {
    // SAFETY: `ptr` is a fresh page and `key` is 32 bytes.
    unsafe { std::ptr::copy_nonoverlapping(key.as_ptr(), ptr, 32) };
}

fn read_key(ptr: *mut u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: `ptr` is a live key page and `out` has room for 32 bytes.
    unsafe { std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), 32) };
    out
}

fn free_page(ptr: *mut u8) {
    // SAFETY: the caller owns a live key page.
    unsafe { wipe_raw(ptr, PAGE) };
    // SAFETY: `ptr` was allocated with [`page_layout`] and is not used again.
    unsafe { std::alloc::dealloc(ptr, page_layout()) };
}

impl Drop for KeyPage {
    fn drop(&mut self) {
        unregister_page(self.ptr as usize);
        free_page(self.ptr);
    }
}

/// Clears volatile registers when it is dropped.
pub struct RegWipe;

impl Drop for RegWipe {
    fn drop(&mut self) {
        wipe_volatile_regs();
    }
}

#[cfg(test)]
pub(crate) fn page_is_dont_dump(addr: usize) -> bool {
    vm_flags_line(addr)
        .ok()
        .is_some_and(|line| line.split_whitespace().any(|flag| flag == "dd"))
}

/// `VmFlags` line of the mapping that contains `addr`.
///
/// Adjacent `MADV_DONTDUMP` pages are one VMA. The header is `start-end`, and
/// only that range carries `dd`.
#[cfg(test)]
fn vm_flags_line(addr: usize) -> Result<String> {
    let text = std::fs::read_to_string("/proc/self/smaps").map_err(|_| msg("smaps"))?;
    flags_in_smaps(&text, addr)
}

#[cfg(test)]
fn flags_in_smaps(text: &str, addr: usize) -> Result<String> {
    let mut open: Option<(usize, usize, Option<String>)> = None;
    for line in text.lines() {
        if let Some(bounds) = vma_bounds(line) {
            if let Some(found) = flags_of(open, addr) {
                return found;
            }
            open = Some((bounds.0, bounds.1, None));
            continue;
        }
        if line.starts_with("VmFlags:") {
            if let Some((_, _, flags)) = open.as_mut() {
                *flags = Some(line.to_string());
            }
        }
    }
    flags_of(open, addr).unwrap_or_else(|| Err(msg("page mapping")))
}

#[cfg(test)]
fn flags_of(open: Option<(usize, usize, Option<String>)>, addr: usize) -> Option<Result<String>> {
    let (start, end, flags) = open?;
    if start <= addr && addr < end {
        return Some(flags.ok_or_else(|| msg("VmFlags")));
    }
    None
}

#[cfg(test)]
fn vma_bounds(line: &str) -> Option<(usize, usize)> {
    let head = line.split_whitespace().next()?;
    let (raw_start, raw_end) = head.split_once('-')?;
    if !hex_addr(raw_start) || !hex_addr(raw_end) {
        return None;
    }
    let start = usize::from_str_radix(raw_start, 16).ok()?;
    let end = usize::from_str_radix(raw_end, 16).ok()?;
    Some((start, end))
}

#[cfg(test)]
fn hex_addr(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
pub(crate) fn child_page_is_zero(addr: usize) -> bool {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a writable pair of ints, as `pipe` requires.
    let opened = unsafe { pipe(fds.as_mut_ptr()) };
    assert_eq!(opened, 0, "pipe");
    // SAFETY: `fork` takes no arguments.
    let pid = unsafe { fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        report_child(addr, fds[1]);
    }
    collect_child(pid, fds)
}

#[cfg(test)]
fn report_child(addr: usize, fd: i32) -> ! {
    let leaked = child_leaked(addr);
    // SAFETY: `fd` is the write end of the pipe. `_exit` skips destructors.
    unsafe {
        let _ = write(fd, std::ptr::from_ref(&leaked).cast(), 1);
        _exit(0);
    }
}

#[cfg(test)]
fn child_leaked(addr: usize) -> u8 {
    let mut buf = [0u8; 32];
    // SAFETY: `addr` is a key page in this address space. The child reads its copy.
    unsafe { std::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), 32) };
    u8::from(buf != [0u8; 32])
}

#[cfg(test)]
fn collect_child(pid: i32, fds: [i32; 2]) -> bool {
    let mut status = 0i32;
    let mut leaked = 1u8;
    // SAFETY: the read end and the child pid belong to this test.
    unsafe {
        let _ = close(fds[1]);
        let n = read(fds[0], std::ptr::from_mut(&mut leaked).cast(), 1);
        let _ = close(fds[0]);
        let waited = waitpid(pid, &mut status, 0);
        assert_eq!(waited, pid, "waitpid");
        assert_eq!(n, 1, "child status byte");
    }
    leaked == 0
}

#[cfg(test)]
extern "C" {
    fn fork() -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn write(fd: i32, buf: *const std::ffi::c_void, count: usize) -> isize;
    fn read(fd: i32, buf: *mut std::ffi::c_void, count: usize) -> isize;
    fn close(fd: i32) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_vector_wipe_zeroes_its_backing_storage() {
        let mut words = std::hint::black_box(vec![0x8765_4321_u32; 7]);
        let len = words.len();
        wipe_copy_vec(&mut words);
        assert!(words.is_empty());
        for index in 0..len {
            // SAFETY: these slots were initialized before clearing and the
            // allocation remains live. wipe_copy_vec initialized every byte.
            let word = unsafe { words.as_ptr().add(index).read_volatile() };
            assert_eq!(word, 0);
        }
    }

    #[test]
    fn key_page_is_marked_dont_dump() {
        let key = [0x5au8; 32];
        let page = KeyPage::hold(&key).expect("page");
        assert_eq!(page.bytes(), key);
        let flags = vm_flags_line(page.addr());
        let marked = flags
            .as_ref()
            .ok()
            .is_some_and(|line| line.split_whitespace().any(|flag| flag == "dd"));
        assert!(marked, "missing MADV_DONTDUMP in {flags:?}");
    }

    #[test]
    fn merged_vma_uses_the_containing_range() {
        let text = "\
1000-3000 rw-p 00000000 00:00 0
Size: 8 kB
VmFlags: rd wr dd
3000-4000 rw-p 00000000 00:00 0
VmFlags: rd wr
";
        let covered = flags_in_smaps(text, 0x2000).expect("containing range");
        assert!(covered.split_whitespace().any(|flag| flag == "dd"));
        let next = flags_in_smaps(text, 0x3000).expect("next range");
        assert!(!next.split_whitespace().any(|flag| flag == "dd"));
        assert!(flags_in_smaps(text, 0x4000).is_err());
    }

    #[test]
    fn key_page_tail_stays_zero() {
        let key = [0x5au8; 32];
        let page = KeyPage::hold(&key).expect("page");
        let mut tail = [0xffu8; 64];
        // SAFETY: the page is 4096 bytes. This reads the tail after the 32-byte key.
        unsafe {
            std::ptr::copy_nonoverlapping(page.ptr.add(32), tail.as_mut_ptr(), tail.len());
        }
        assert_eq!(tail, [0u8; 64]);
    }

    #[test]
    fn fork_child_does_not_inherit_the_key() {
        let key = [0xabu8; 32];
        let page = KeyPage::hold(&key).expect("page");
        assert!(child_page_is_zero(page.addr()), "child still held the key");
        assert_eq!(page.bytes(), key, "parent key");
    }

    #[test]
    fn wipe_volatile_regs_clears_rsi_and_rdi() {
        let rsi: u64;
        let rdi: u64;
        // SAFETY: the call clobbers caller-saved registers. `lateout` captures
        // rsi and rdi after `wipe_volatile_regs` returns.
        unsafe {
            std::arch::asm!(
                "mov rsi, 0x1111",
                "mov rdi, 0x2222",
                "call {wipe}",
                wipe = sym wipe_volatile_regs,
                lateout("rsi") rsi,
                lateout("rdi") rdi,
                lateout("rax") _,
                lateout("rcx") _,
                lateout("rdx") _,
                lateout("r8") _,
                lateout("r9") _,
                lateout("r10") _,
                lateout("r11") _,
            );
        }
        assert_eq!(rsi, 0);
        assert_eq!(rdi, 0);
    }
}
