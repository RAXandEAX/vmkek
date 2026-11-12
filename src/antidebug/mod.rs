//! User-mode anti-debug. Each detector can fail closed on its own.
//!
//! `PEB.BeingDebugged` and `NtGlobalFlag & 0x70` stay in the loader. The VM's
//! entry check reads BeingDebugged and the heap flags again and poisons the
//! woven key from S5b. `NtGlobalFlag` also runs from a mutated code cave.
//! `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, and a `GetTickCount64`
//! delta run after the loader has resolved kernel32.
//!
//! Hardware DR0–DR7, `NtQueryInformationProcess` (debug port, debug object,
//! debug flags), heap flags, `int 2d`, a protected-handle close, and a
//! debugger parent run after the payload decrypt. A hit there xors the first
//! function's woven key, then returns `0xDEB6`.
//!
//! Trap flag, an `int3` in the loader's own page, `ThreadHideFromDebugger`,
//! kernel-debugger information, a substituted `DbgUiRemoteBreakin`, and a
//! non-zero instrumentation callback run after decrypt. Each one xors the
//! per-thread chain key. A hit then returns `0xDEB6`.
//!
//! Old kernel-debugger module names are compared and discarded. A match does
//! not xor the key and is not a System claim. A kernel debugger on M-KERN and
//! waves K and H stay outside this stage. Live Windows stays open until M-WIN
//! exists.
//!
//! ELF adds three Linux probes. Each bit of the runtime mask arms one of them.
//! A hit in the open loader poisons the block key and returns `0xDEB6`. The
//! same probes run again from the bytecode check and xor the thread chain, so
//! nopping only the loader does not keep a traced run alive.

mod emit;
mod linux;
mod woven;

pub(crate) use linux::{
    emit_early_tracer, emit_linux_body, emit_linux_exit, emit_linux_gate, emit_linux_loader,
    linux_arm, EARLY_END, EARLY_MARK,
};
pub use linux::{
    neutralize_loader_linux, with_linux_detectors, LINUX_CLOCK, LINUX_PTRACE, LINUX_TRACER,
};

use iced_x86::code_asm::*;

use crate::error::{msg, Result};
use crate::ir::MemIo;
use crate::pe::{self, PeImage};

/// `GetTickCount64` delta above this many ticks is treated as a debugger.
/// The emulator's default step is 1, which stays under the limit.
pub const TICK_LIMIT: u64 = 0x100;
const TICK_CMP: i32 = 0x100;
const _: () = assert!(TICK_LIMIT == TICK_CMP as u64);

/// Byte mixed into the woven key when a probe trips.
pub const KEY_POISON: u8 = 0xA5;

/// `CloseHandle` sentinel marked protect-from-close.
pub const PROTECTED_HANDLE: u64 = 0xDEC1;

/// Heap `Flags` dword. Windows 10 x64.
pub const HEAP_FLAGS: i32 = 0x70;
/// Heap `ForceFlags` dword.
pub const HEAP_FORCE: i32 = 0x74;
/// `HEAP_GROWABLE`. Bits outside this in `Flags` are a debugger fill.
pub const HEAP_GROWABLE: i32 = 2;

/// `ProcessBasicInformation`.
pub const PROCESS_BASIC: u32 = 0;
/// `ProcessDebugPort`.
pub const PROCESS_DEBUG_PORT: u32 = 7;
/// `ProcessDebugObjectHandle`.
pub const PROCESS_DEBUG_OBJECT: u32 = 0x1e;
/// `ProcessDebugFlags`.
pub const PROCESS_DEBUG_FLAGS: u32 = 0x1f;
/// `ProcessImageFileName`.
pub const PROCESS_IMAGE: u32 = 27;
/// `ThreadHideFromDebugger`. The check reads the byte. It does not set the class.
pub const THREAD_HIDE: u32 = 0x11;
/// `SystemKernelDebuggerInformation`.
pub const SYSTEM_KERNEL_DEBUGGER: u32 = 0x23;
/// `SystemModuleInformation`. The name compare is a weak signal.
pub const SYSTEM_MODULE_INFORMATION: u32 = 11;
/// `PEB.InstrumentationCallback` on the Windows 10 x64 layout this emulator publishes.
pub const PEB_INSTRUMENTATION: i32 = 0x3D8;
/// First byte of an unsubstituted `DbgUiRemoteBreakin`.
pub const BREAKIN_CLEAN: u8 = 0x48;
/// First byte when `DbgUiRemoteBreakin` has been replaced.
pub const BREAKIN_SUBSTITUTED: u8 = 0xE9;
/// Marker ahead of the one-byte slot the int3 scan reads. The slot itself starts clear.
pub const INT3_MARK: [u8; 3] = [0xA5, 0x5A, 0xE3];

/// Old kernel-debugger driver names. A match is recorded and then discarded.
/// It does not change the thread key and it is not a System claim.
pub const LEGACY_KERNEL_MODULES: &[&str] = &[
    "ntice.sys",
    "ntice64.sys",
    "sice.sys",
    "syser.sys",
    "winice.sys",
];

/// `true` when `name` is on [`LEGACY_KERNEL_MODULES`].
#[must_use]
pub fn legacy_kernel_module(name: &str) -> bool {
    LEGACY_KERNEL_MODULES.contains(&name)
}

/// Parent image with no debugger in the path. The base name is `explorer.exe`.
pub const CLEAN_PARENT: &str = "C:\\Windows\\explorer.exe";
/// Parent image whose base name is on [`DEBUGGER_IMAGES`].
pub const DEBUGGER_PARENT: &str = "C:\\tools\\x64dbg.exe";

/// Base names treated as a user-mode debugger parent.
pub const DEBUGGER_IMAGES: &[&str] = &[
    "x64dbg.exe",
    "ollydbg.exe",
    "windbg.exe",
    "ida.exe",
    "ida64.exe",
    "devenv.exe",
];

const BEING_PREFIX: &[u8] = &[0x8a, 0x50, 0x02, 0x84, 0xd2];
const NT_PREFIX: &[u8] = &[0xf7, 0xc1, 0x70, 0x00, 0x00, 0x00];
const LOADER_PEB_WINDOW: usize = 48;
pub(super) const GS_PEB: [u8; 9] = [0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];

/// M-WIN row for the individually isolated user-mode detectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveWindows {
    /// Proof channel. This row is not a [`crate::proof`] claim.
    pub channel: &'static str,
    /// Machine id from the lab table.
    pub machine: &'static str,
    /// `false` while acceptance of the complete live matrix is open.
    pub closed: bool,
    /// Why the row is still open.
    pub note: &'static str,
}

/// Live Windows protocol for the per-signal matrix.
#[must_use]
pub fn live_windows() -> LiveWindows {
    LiveWindows {
        channel: "System",
        machine: "M-WIN",
        closed: false,
        note: "M-WIN debugger-launch smoke passed; the isolated signal matrix remains open",
    }
}

/// Loader prefix: BeingDebugged, NtGlobalFlag, image base in `r15`, then the cave.
pub(crate) fn emit_peb(a: &mut CodeAssembler, bad: &mut CodeLabel, cave: u64) -> Result<()> {
    emit_process_peb(a, bad)?;
    step(a.mov(r15, qword_ptr(rax + 0x10i32)))?;
    emit_cave_call(a, bad, cave)
}

/// The startup checks shared by both PE loader profiles.
pub(crate) fn emit_process_peb(a: &mut CodeAssembler, bad: &mut CodeLabel) -> Result<()> {
    emit_being(a, bad)?;
    emit_nt(a, bad)
}

/// API detectors. `r12` is kernel32 and `resolve` is the export resolver.
///
/// `bad` is the pre-decrypt fail-closed path. `poison` runs only after decrypt
/// and mixes the woven key before the same `0xDEB6` return.
pub(crate) fn emit_apis(
    a: &mut CodeAssembler,
    resolve: u64,
    bad: &mut CodeLabel,
    poison: &mut CodeLabel,
    runtime: u64,
) -> Result<()> {
    emit_present(a, resolve, bad)?;
    emit_remote(a, resolve, bad)?;
    emit_ticks(a, resolve, bad)?;
    emit::later(a, resolve, bad, poison, runtime)
}

pub(crate) use emit::emit_poison;

/// `true` when the mapped PEB says a user-mode debugger is attached.
/// A missing GS slot or PEB reads as clean so interpreters without a PEB keep running.
#[must_use]
pub fn peb_being_debugged(mem: &mut dyn MemIo) -> bool {
    let Some(peb) = peb_addr(mem) else {
        return false;
    };
    let Ok(flag) = mem.read(peb.wrapping_add(2), 1) else {
        return false;
    };
    flag.first().copied().unwrap_or(0) != 0
}

/// `true` when BeingDebugged is set or the process heap carries debugger flags.
/// A missing heap reads as clean.
#[must_use]
pub fn probe_tripped(mem: &mut dyn MemIo) -> bool {
    peb_being_debugged(mem) || heap_marked(mem)
}

fn peb_addr(mem: &mut dyn MemIo) -> Option<u64> {
    let ptr = mem.read(crate::emu::GS_BASE + 0x60, 8).ok()?;
    let bytes = <[u8; 8]>::try_from(ptr.as_slice()).ok()?;
    let peb = u64::from_le_bytes(bytes);
    (peb != 0).then_some(peb)
}

fn heap_marked(mem: &mut dyn MemIo) -> bool {
    let Some(peb) = peb_addr(mem) else {
        return false;
    };
    let Ok(ptr) = mem.read(peb.wrapping_add(0x30), 8) else {
        return false;
    };
    let Ok(bytes) = <[u8; 8]>::try_from(ptr.as_slice()) else {
        return false;
    };
    let heap = u64::from_le_bytes(bytes);
    if heap == 0 {
        return false;
    }
    heap_dirty(mem, heap)
}

fn heap_dirty(mem: &mut dyn MemIo, heap: u64) -> bool {
    let Ok(flags) = dword_at(mem, heap.wrapping_add(HEAP_FLAGS as u64)) else {
        return false;
    };
    let Ok(force) = dword_at(mem, heap.wrapping_add(HEAP_FORCE as u64)) else {
        return false;
    };
    force != 0 || flags & !HEAP_GROWABLE != 0
}

fn dword_at(mem: &mut dyn MemIo, addr: u64) -> Result<i32> {
    let bytes = mem.read(addr, 4)?;
    let raw = <[u8; 4]>::try_from(bytes.as_slice()).map_err(|_| msg("short heap read"))?;
    Ok(i32::from_le_bytes(raw))
}

/// Native NtGlobalFlag check. Returns `0` when the flag is clear and `0xDEB6` when it is set.
pub(crate) fn nt_global_body() -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut clean = a.create_label();
    step(a.db(&GS_PEB))?;
    step(a.mov(ecx, dword_ptr(rax + 0xbci32)))?;
    step(a.test(ecx, 0x70i32))?;
    step(a.mov(eax, 0u32))?;
    step(a.jz(clean))?;
    step(a.mov(eax, 0xdeb6u32))?;
    step(a.set_label(&mut clean))?;
    step(a.ret())?;
    a.assemble(0).map_err(|err| msg(err.to_string()))
}

/// Plant the NtGlobalFlag check in an executable cave, behind a desync prefix.
pub(crate) fn plant_cave(image: &mut PeImage, seed: u64) -> Result<u32> {
    crate::mutate::cave::plant(image, &nt_global_body()?, seed)
}

/// Nop the loader's own BeingDebugged and NtGlobalFlag branches.
///
/// The VM bytecode probe and the mutated cave are outside this window, so they
/// still run.
pub fn neutralize_loader_peb(file: &mut [u8]) -> Result<()> {
    let off = loader_code_off(file)?;
    let end = off
        .checked_add(LOADER_PEB_WINDOW)
        .ok_or_else(|| msg("loader peb window overflows"))?;
    let window = file
        .get_mut(off..end)
        .ok_or_else(|| msg("loader peb window is short"))?;
    nop_prefixed(window, BEING_PREFIX, "BeingDebugged")?;
    nop_prefixed(window, NT_PREFIX, "NtGlobalFlag")
}

fn emit_being(a: &mut CodeAssembler, bad: &mut CodeLabel) -> Result<()> {
    step(a.db(&GS_PEB))?;
    step(a.mov(dl, byte_ptr(rax + 2i32)))?;
    step(a.test(dl, dl))?;
    step(a.jnz(*bad))?;
    Ok(())
}

fn emit_nt(a: &mut CodeAssembler, bad: &mut CodeLabel) -> Result<()> {
    step(a.mov(ecx, dword_ptr(rax + 0xbci32)))?;
    step(a.test(ecx, 0x70i32))?;
    step(a.jnz(*bad))?;
    Ok(())
}

fn emit_cave_call(a: &mut CodeAssembler, bad: &mut CodeLabel, cave: u64) -> Result<()> {
    step(a.mov(rax, cave as i64))?;
    step(a.call(rax))?;
    step(a.test(eax, eax))?;
    step(a.jnz(*bad))?;
    Ok(())
}

fn emit_present(a: &mut CodeAssembler, resolve: u64, bad: &mut CodeLabel) -> Result<()> {
    emit_resolve(a, resolve, "IsDebuggerPresent")?;
    step(a.call(rax))?;
    step(a.test(eax, eax))?;
    step(a.jnz(*bad))?;
    Ok(())
}

fn emit_remote(a: &mut CodeAssembler, resolve: u64, bad: &mut CodeLabel) -> Result<()> {
    emit_resolve(a, resolve, "CheckRemoteDebuggerPresent")?;
    step(a.mov(r10, rax))?;
    step(a.sub(rsp, 0x30i32))?;
    step(a.mov(dword_ptr(rsp + 0x20i32), 0u32))?;
    step(a.mov(rcx, -1i64))?;
    step(a.lea(rdx, qword_ptr(rsp + 0x20i32)))?;
    step(a.call(r10))?;
    step(a.xor(r10, r10))?;
    step(a.mov(eax, dword_ptr(rsp + 0x20i32)))?;
    step(a.add(rsp, 0x30i32))?;
    step(a.test(eax, eax))?;
    step(a.jnz(*bad))?;
    Ok(())
}

fn emit_ticks(a: &mut CodeAssembler, resolve: u64, bad: &mut CodeLabel) -> Result<()> {
    emit_resolve(a, resolve, "GetTickCount64")?;
    step(a.call(rax))?;
    // `r13` survives the second resolve. `r11` does not.
    step(a.mov(r13, rax))?;
    emit_resolve(a, resolve, "GetTickCount64")?;
    step(a.call(rax))?;
    step(a.sub(rax, r13))?;
    step(a.cmp(rax, TICK_CMP))?;
    step(a.ja(*bad))?;
    Ok(())
}

pub(super) fn emit_resolve(a: &mut CodeAssembler, resolve: u64, name: &str) -> Result<()> {
    emit_resolve_reg(a, resolve, r12, name)
}

pub(super) fn emit_resolve_reg(
    a: &mut CodeAssembler,
    resolve: u64,
    module: AsmRegister64,
    name: &str,
) -> Result<()> {
    step(a.mov(rcx, module))?;
    step(a.mov(edx, crate::trace::import_hash(name.as_bytes()) as i32))?;
    step(a.mov(rax, resolve as i64))?;
    step(a.call(rax))?;
    Ok(())
}

pub(super) fn step(result: std::result::Result<(), IcedError>) -> Result<()> {
    result.map_err(|err| msg(err.to_string()))
}

fn loader_code_off(file: &[u8]) -> Result<usize> {
    let image = pe::parse(file)?;
    let entry = rva_off(file, &image, image.entry_rva)?;
    let code = &file[entry..];
    if !crate::loader::is_loader_prologue(code) {
        return Err(msg("entry is not the loader"));
    }
    let skip = crate::loader::LOADER_NONCE_OFF + crate::loader::AEAD_NONCE_LEN;
    entry
        .checked_add(skip)
        .ok_or_else(|| msg("loader code offset overflows"))
}

fn rva_off(file: &[u8], image: &PeImage, rva: u32) -> Result<usize> {
    let section = image
        .sections
        .iter()
        .find(|item| rva >= item.rva && u64::from(rva - item.rva) < item.bytes.len() as u64)
        .ok_or_else(|| msg("entry rva is not in a section"))?;
    let base = pe::section_file_offset(file, &section.name)?;
    base.checked_add((rva - section.rva) as usize)
        .ok_or_else(|| msg("entry file offset overflows"))
}

fn nop_prefixed(window: &mut [u8], prefix: &[u8], name: &str) -> Result<()> {
    let at = window
        .windows(prefix.len())
        .position(|item| item == prefix)
        .ok_or_else(|| msg(format!("loader {name} site missing")))?;
    let branch = at + prefix.len();
    let slot = window
        .get_mut(branch..)
        .ok_or_else(|| msg(format!("loader {name} branch is truncated")))?;
    if !nop_jnz(slot) {
        return Err(msg(format!("loader {name} branch is not jnz")));
    }
    Ok(())
}

/// Short `75 rel8` or near `0F 85 rel32`. The bad target sits at the end of the loader.
fn nop_jnz(slot: &mut [u8]) -> bool {
    if slot.first() == Some(&0x75) && slot.len() >= 2 {
        slot[0] = 0x90;
        slot[1] = 0x90;
        return true;
    }
    if slot.len() >= 6 && slot[0] == 0x0f && slot[1] == 0x85 {
        slot[..6].fill(0x90);
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::emu::{self, Detector, Policy};
    use crate::error::Error;
    use crate::flags::Flags;
    use crate::ir::{Block, Exit, FuncIr, MemIo, Op};
    use crate::protect::{self, Options};
    use crate::sample::{self, build};
    use crate::vm::{self, exec_image};

    fn options(seed: u64) -> Options {
        Options {
            virtualize: BTreeSet::new(),
            mutate: BTreeSet::new(),
            virtualize_all: true,
            mutate_all: false,
            seed,
            random_key: false,
            debug_seed: false,
        }
    }

    fn protected() -> Vec<u8> {
        let built = build().expect("sample");
        protect::protect(&built.bytes, &options(1))
            .expect("protect")
            .bytes
    }

    fn assert_closed(policy: Policy) {
        let ran = emu::run_pe(&protected(), policy).expect("run");
        assert_ne!(ran.stdout, sample::line().into_bytes());
        assert_eq!(
            ran.exit_code,
            0xdeb6,
            "stdout {}",
            String::from_utf8_lossy(&ran.stdout)
        );
    }

    #[test]
    fn detectors_off_print_the_sample_line() {
        let ran = emu::run_pe(&protected(), Policy::default()).unwrap();
        assert_eq!(ran.exit_code, 0);
        assert_eq!(ran.stdout, sample::line().into_bytes());
    }

    #[test]
    fn being_debugged_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::BeingDebugged));
    }

    #[test]
    fn nt_global_flag_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::NtGlobalFlag));
    }

    #[test]
    fn is_debugger_present_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::IsDebuggerPresent));
    }

    #[test]
    fn remote_debugger_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::RemoteDebugger));
    }

    #[test]
    fn tick_jump_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::TickDelta));
    }

    #[test]
    fn tick_delta_without_a_jump_prints_the_sample_line() {
        let policy = Policy {
            tick_jump: 0,
            ..Policy::default()
        };
        let ran = emu::run_pe(&protected(), policy).unwrap();
        assert_eq!(ran.exit_code, 0);
        assert_eq!(ran.stdout, sample::line().into_bytes());
    }

    #[test]
    fn armed_tick_jump_crosses_the_limit() {
        let policy = Policy::arm(Detector::TickDelta);
        let delta = policy.tick_step.wrapping_add(policy.tick_jump);
        assert!(delta > TICK_LIMIT);
    }

    #[test]
    fn loader_copies_do_not_silence_vm_or_cave() {
        let mut bytes = protected();
        neutralize_loader_peb(&mut bytes).unwrap();
        crate::early::neutralize_early_pe(&mut bytes).unwrap();
        let quiet = emu::run_pe(&bytes, Policy::default()).unwrap();
        assert_eq!(
            quiet.exit_code,
            0,
            "{}",
            String::from_utf8_lossy(&quiet.stdout)
        );
        assert_eq!(quiet.stdout, sample::line().into_bytes());
        let vm = emu::run_pe(&bytes, Policy::arm(Detector::BeingDebugged)).unwrap();
        assert_ne!(vm.stdout, sample::line().into_bytes());
        assert_eq!(vm.exit_code, 0xbad1);
        let cave = emu::run_pe(&bytes, Policy::arm(Detector::NtGlobalFlag)).unwrap();
        assert!(cave.stdout.is_empty());
        assert_eq!(cave.exit_code, 0xdeb6);
    }

    #[test]
    fn vm_probe_fails_closed_when_the_peb_is_set() {
        let func = FuncIr {
            name: "ret".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![Op::MovRi(0, 1)],
                exit: Exit::Ret,
                opaque: false,
            }],
        };
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let image = vm::lower_image(std::slice::from_ref(&func), &mut rng).unwrap();
        let mut arch = [0u64; 16];
        let mut flags = Flags::default();
        let mut mem = crate::ir::MapMem::default();
        let mut host = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        exec_image(&image, 0, &mut arch, &mut flags, &mut mem, 0, &mut host).unwrap();
        assert_eq!(arch[0], 1);
        let peb = emu::PEB;
        mem.write(emu::GS_BASE + 0x60, &peb.to_le_bytes()).unwrap();
        mem.write(peb + 2, &[1]).unwrap();
        arch = [0; 16];
        let err = exec_image(&image, 0, &mut arch, &mut flags, &mut mem, 0, &mut host).unwrap_err();
        assert!(matches!(err, Error::Debugger));
    }

    #[test]
    fn hardware_dr_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::HardwareDr));
    }

    #[test]
    fn debug_port_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::DebugPort));
    }

    #[test]
    fn debug_object_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::DebugObject));
    }

    #[test]
    fn process_debug_flags_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::ProcessDebugFlags));
    }

    #[test]
    fn heap_flags_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::HeapFlags));
    }

    #[test]
    fn int2d_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::Int2d));
    }

    #[test]
    fn protected_handle_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::ProtectedHandle));
    }

    #[test]
    fn parent_debugger_alone_fails_closed() {
        assert_closed(Policy::arm(Detector::ParentDebugger));
    }

    #[test]
    fn armed_detector_poisons_the_block_key() {
        let bytes = protected();
        let image = pe::parse(&bytes).unwrap();
        let mut machine = emu::load(&image, Policy::arm(Detector::DebugPort)).unwrap();
        machine.run().unwrap();
        assert_eq!(machine.exit_code, Some(0xdeb6));
        assert!(
            machine
                .regions
                .iter()
                .any(|region| key_poisoned(&region.data)),
            "woven key was not poisoned"
        );
    }

    #[test]
    fn vm_probe_poisons_the_key_when_heap_force_flags_are_set() {
        let (image, mut arch, mut flags, mut mem) = ret_image();
        let mut host = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        exec_image(&image, 0, &mut arch, &mut flags, &mut mem, 0, &mut host).unwrap();
        let peb = emu::PEB;
        let heap = 0x2000u64;
        mem.write(emu::GS_BASE + 0x60, &peb.to_le_bytes()).unwrap();
        mem.write(peb + 0x30, &heap.to_le_bytes()).unwrap();
        mem.write(heap + HEAP_FORCE as u64, &0x20u32.to_le_bytes())
            .unwrap();
        arch = [0; 16];
        let err = exec_image(&image, 0, &mut arch, &mut flags, &mut mem, 0, &mut host).unwrap_err();
        assert!(matches!(err, Error::Debugger));
    }

    #[test]
    fn live_windows_protocol_stays_open() {
        let live = live_windows();
        assert!(!live.closed);
        assert_eq!(live.channel, "System");
        assert_eq!(live.machine, "M-WIN");
        assert!(live.note.contains("signal matrix remains open"));
        assert!(crate::proof::registry()
            .iter()
            .all(|item| item.machine != "M-WIN"));
        let protocol = include_str!("../../tests/fixtures/labs/win.md");
        assert!(protocol.contains("- [ ]"));
        assert!(!protocol.contains("- [x]") && !protocol.contains("- [X]"));
        assert!(protocol.contains("M-WIN"));
    }

    fn ret_image() -> (crate::vm::BcImage, [u64; 16], Flags, crate::ir::MapMem) {
        let func = FuncIr {
            name: "ret".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![Op::MovRi(0, 1)],
                exit: Exit::Ret,
                opaque: false,
            }],
        };
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let image = vm::lower_image(std::slice::from_ref(&func), &mut rng).unwrap();
        (
            image,
            [0; 16],
            Flags::default(),
            crate::ir::MapMem::default(),
        )
    }

    fn woven_image() -> &'static [u8] {
        use std::sync::OnceLock;
        static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
        IMAGE.get_or_init(protected)
    }

    fn assert_chain_closed(policy: Policy) {
        let image = pe::parse(woven_image()).unwrap();
        let mut machine = emu::load(&image, policy).unwrap();
        machine.run().unwrap();
        assert_ne!(machine.stdout, sample::line().into_bytes());
        assert_eq!(machine.exit_code, Some(0xdeb6));
        let chain = emu::GS_BASE + vm::GS_CHAIN_AT as u64;
        let byte = machine.read(chain, 1).unwrap();
        assert_eq!(byte[0], KEY_POISON, "thread chain key was not poisoned");
    }

    #[test]
    fn trap_flag_alone_fails_closed() {
        assert_chain_closed(Policy::arm(Detector::TrapFlag));
    }

    #[test]
    fn int3_page_alone_fails_closed() {
        assert_chain_closed(Policy::arm(Detector::Int3Page));
    }

    #[test]
    fn thread_hide_alone_fails_closed() {
        assert_chain_closed(Policy::arm(Detector::ThreadHide));
    }

    #[test]
    fn kernel_debugger_alone_fails_closed() {
        assert_chain_closed(Policy::arm(Detector::KernelDebugger));
    }

    #[test]
    fn remote_breakin_alone_fails_closed() {
        assert_chain_closed(Policy::arm(Detector::RemoteBreakin));
    }

    #[test]
    fn instrumentation_callback_alone_fails_closed() {
        assert_chain_closed(Policy::arm(Detector::InstrumentationCallback));
    }

    #[test]
    fn substituted_api_and_peb_still_fail_closed() {
        let clean = Policy::default();
        let observed = Policy {
            is_debugger_present: 1,
            thread_hidden: 1,
            being_debugged: 1,
            instrumentation: 0x20,
            int3_page: true,
            ..clean.clone()
        };
        // Substitute only API and PEB observations. The own-page signal is
        // identical in both policies.
        let substituted = Policy {
            is_debugger_present: clean.is_debugger_present,
            thread_hidden: clean.thread_hidden,
            being_debugged: clean.being_debugged,
            instrumentation: clean.instrumentation,
            ..observed
        };
        assert_eq!(substituted.thread_hidden, 0, "thread API must report clean");
        assert_eq!(
            substituted.instrumentation, 0,
            "PEB callback must report clean"
        );
        let control = Policy {
            int3_page: false,
            ..substituted.clone()
        };
        assert_chain_closed(substituted);
        let ran = emu::run_pe(woven_image(), control).unwrap();
        assert_eq!(ran.exit_code, 0);
        assert_eq!(ran.stdout, sample::line().into_bytes());
    }

    #[test]
    fn legacy_kernel_module_does_not_color_the_channel() {
        let policy = Policy {
            kernel_module: "ntice.sys".into(),
            ..Policy::default()
        };
        let image = pe::parse(woven_image()).unwrap();
        let mut machine = emu::load(&image, policy).unwrap();
        machine.run().unwrap();
        assert_eq!(machine.exit_code, Some(0));
        assert_eq!(machine.stdout, sample::line().into_bytes());
        assert!(machine.saw_weak_module);
        assert!(legacy_kernel_module("ntice.sys"));
        assert!(!legacy_kernel_module("explorer.exe"));
        assert!(crate::proof::registry()
            .iter()
            .all(|item| { !item.pass.contains("legacy") && item.pass != "kernel-module" }));
    }

    fn key_poisoned(data: &[u8]) -> bool {
        let need = 0xb0 + 32;
        if data.len() < need {
            return false;
        }
        data.windows(need).any(|window| {
            let key = &window[0x60..0x80];
            let master = &window[0xb0..0xd0];
            master.iter().any(|byte| *byte != 0)
                && key[1..] == master[1..]
                && key[0] == master[0] ^ KEY_POISON
        })
    }
}
