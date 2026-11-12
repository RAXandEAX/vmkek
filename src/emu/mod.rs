use std::collections::HashMap;

mod branch;
mod startup;
pub use startup::{StartupManifest, StartupObservation};
mod cpu;
mod instrument;

pub use branch::{claims as trace_claims, compare_tags, ChannelColor, TagRun, TraceClaim};

pub use instrument::{
    claims as instrument_claims, Instrument, InstrumentClaim, PageMap, FAIL_CLOSED,
};

use crate::error::{exact_bytes, msg, Result};
use crate::flags::Flags;
use crate::pe::{parse, PeImage};

pub const SENTINEL: u64 = 0xffff_ffff_ffff_fff0;
/// Return address used while a TLS callback is running. Not a process exit.
const TLS_RETURN: u64 = 0xffff_ffff_ffff_ffe0;
const STACK: u64 = 0x600000;
const STACK_SIZE: usize = 0x200000;
pub(crate) const GS_BASE: u64 = 0x7ffe_0000;
pub(crate) const PEB: u64 = 0x7ffe_1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Api {
    GetStdHandle,
    WriteFile,
    ExitProcess,
    IsDebuggerPresent,
    CheckRemoteDebuggerPresent,
    GetTickCount64,
    GetThreadContext,
    CloseHandle,
    SetHandleInformation,
    NtQueryInformationProcess,
    NtQueryInformationThread,
    NtQuerySystemInformation,
    LoadLibraryA,
    GetProcAddress,
}

/// One user-mode detector. [`Policy::arm`] turns that detector's signal on and leaves the others clean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detector {
    BeingDebugged,
    NtGlobalFlag,
    IsDebuggerPresent,
    RemoteDebugger,
    TickDelta,
    /// DR0–DR7 via `GetThreadContext`.
    HardwareDr,
    /// `ProcessDebugPort`.
    DebugPort,
    /// `ProcessDebugObjectHandle`.
    DebugObject,
    /// `ProcessDebugFlags` clear.
    ProcessDebugFlags,
    /// Heap `Flags` / `ForceFlags`.
    HeapFlags,
    /// `int 2d` swallowed by a debugger.
    Int2d,
    /// `CloseHandle` on a protect-from-close handle.
    ProtectedHandle,
    /// Parent image base name is a debugger.
    ParentDebugger,
    /// Trap flag in the `pushfq` image.
    TrapFlag,
    /// `int3` in the process page the loader scans.
    Int3Page,
    /// `NtQueryInformationThread` `ThreadHideFromDebugger` byte.
    ThreadHide,
    /// `SystemKernelDebuggerInformation.KernelDebuggerEnabled`.
    KernelDebugger,
    /// `DbgUiRemoteBreakin` first byte replaced.
    RemoteBreakin,
    /// Non-zero `PEB.InstrumentationCallback`.
    InstrumentationCallback,
}

#[derive(Clone, Debug)]
pub struct Policy {
    /// Optional trusted startup manifest and modeled observations.
    pub startup: Option<StartupObservation>,
    pub being_debugged: u8,
    pub nt_global: u32,
    /// Return value of `IsDebuggerPresent`. Independent of [`Self::being_debugged`].
    pub is_debugger_present: u32,
    pub remote: u32,
    pub tick: u64,
    pub tick_step: u64,
    /// Added once after the next `GetTickCount64`, so it falls between two samples.
    pub tick_jump: u64,
    /// Native steps before the emulator stops. A direct VM mount of the sample
    /// finishes in about 135e6 steps when the ChaCha helper runs natively:
    /// each instruction seals the open block, opens the level-2 program, and
    /// reopens the block. The protected image also runs the loader.
    pub max_steps: u64,
    /// Step the ChaCha20 helper instead of evaluating its keystream in one call.
    pub interpret_cipher: bool,
    /// A store into an executable page of this image came from outside the image.
    pub foreign_exec_write: bool,
    /// Hash executable pages of this image and compare them with the load snapshot.
    pub code_page_hash: bool,
    /// Another thread in the process model wrote an executable page of this image.
    pub foreign_thread_write: bool,
    /// DR0. Zero means that slot is empty.
    pub dr0: u64,
    /// DR1.
    pub dr1: u64,
    /// DR2.
    pub dr2: u64,
    /// DR3.
    pub dr3: u64,
    /// DR6 status. The default is zero so a clean run does not trip.
    pub dr6: u64,
    /// DR7 local and global enables, plus the other DR7 bits.
    pub dr7: u64,
    /// `ProcessDebugPort`. Zero means no debug port.
    pub debug_port: u64,
    /// `ProcessDebugObjectHandle`. Zero means no debug object.
    pub debug_object: u64,
    /// `ProcessDebugFlags`. `1` is inherit-debug with no debugger attached.
    pub debug_flags: u32,
    /// Heap `Flags`. Default is `HEAP_GROWABLE` only.
    pub heap_flags: u32,
    /// Heap `ForceFlags`. Zero means the heap was not debug-filled.
    pub heap_force: u32,
    /// `int 2d` is swallowed and the following byte is skipped.
    pub int2d: bool,
    /// Closing [`crate::antidebug::PROTECTED_HANDLE`] is reported as a trap.
    pub protected_handle: bool,
    /// Parent image path, as `ProcessImageFileName` would return it.
    pub parent_image: String,
    /// Addresses recorded the first time execution reaches them, in order.
    pub watch: Vec<u64>,
    /// Trap flag mixed into the flags image `pushfq` stores.
    pub trap_flag: bool,
    /// Plant one `int3` in the loader page that the scan reads.
    pub int3_page: bool,
    /// Byte `NtQueryInformationThread(ThreadHideFromDebugger)` returns. The check only reads it.
    pub thread_hidden: u8,
    /// `KernelDebuggerEnabled` in `SystemKernelDebuggerInformation`.
    pub kernel_debugger: bool,
    /// Name hashed for the weak kernel-module compare. A match does not fail the run.
    pub kernel_module: String,
    /// `DbgUiRemoteBreakin` starts with a substituted byte.
    pub breakin_substituted: bool,
    /// `PEB.InstrumentationCallback`. Zero is a clean process.
    pub instrumentation: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            startup: None,
            being_debugged: 0,
            nt_global: 0,
            is_debugger_present: 0,
            remote: 0,
            tick: 1_000,
            tick_step: 1,
            tick_jump: 0,
            max_steps: 180_000_000,
            interpret_cipher: false,
            foreign_exec_write: false,
            code_page_hash: false,
            foreign_thread_write: false,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            debug_port: 0,
            debug_object: 0,
            debug_flags: 1,
            heap_flags: 2,
            heap_force: 0,
            int2d: false,
            protected_handle: false,
            parent_image: crate::antidebug::CLEAN_PARENT.into(),
            watch: Vec::new(),
            trap_flag: false,
            int3_page: false,
            thread_hidden: 0,
            kernel_debugger: false,
            kernel_module: String::new(),
            breakin_substituted: false,
            instrumentation: 0,
        }
    }
}

impl Policy {
    /// Policy with exactly one detector's signal set. The others stay at [`Default`].
    #[must_use]
    pub fn arm(detector: Detector) -> Self {
        let mut policy = Self::default();
        match detector {
            Detector::BeingDebugged => policy.being_debugged = 1,
            Detector::NtGlobalFlag => policy.nt_global = 0x70,
            Detector::IsDebuggerPresent => policy.is_debugger_present = 1,
            Detector::RemoteDebugger => policy.remote = 1,
            // Default `tick_step` is 1, so the delta is one past [`crate::antidebug::TICK_LIMIT`].
            Detector::TickDelta => policy.tick_jump = crate::antidebug::TICK_LIMIT,
            Detector::HardwareDr => {
                policy.dr0 = 0x1000;
                policy.dr7 = 1;
            }
            Detector::DebugPort => policy.debug_port = 1,
            Detector::DebugObject => policy.debug_object = 0x10,
            Detector::ProcessDebugFlags => policy.debug_flags = 0,
            Detector::HeapFlags => {
                policy.heap_flags = 0x4000_0062;
                policy.heap_force = 0x4000_0060;
            }
            Detector::Int2d => policy.int2d = true,
            Detector::ProtectedHandle => policy.protected_handle = true,
            Detector::ParentDebugger => {
                policy.parent_image = crate::antidebug::DEBUGGER_PARENT.into();
            }
            Detector::TrapFlag => policy.trap_flag = true,
            Detector::Int3Page => policy.int3_page = true,
            Detector::ThreadHide => policy.thread_hidden = 1,
            Detector::KernelDebugger => policy.kernel_debugger = true,
            Detector::RemoteBreakin => policy.breakin_substituted = true,
            Detector::InstrumentationCallback => policy.instrumentation = 0x20,
        }
        policy
    }

    /// Policy with exactly one instrumentation check enabled.
    ///
    /// The other checks stay off. A clean image still prints the sample line;
    /// the test supplies the sign by substituting a byte or a page map.
    #[must_use]
    pub fn arm_instrument(sign: Instrument) -> Self {
        let mut policy = Self::default();
        match sign {
            Instrument::ForeignExecWrite => policy.foreign_exec_write = true,
            Instrument::CodePageHash => policy.code_page_hash = true,
            Instrument::ForeignThreadWrite => policy.foreign_thread_write = true,
        }
        policy
    }
}

#[derive(Clone, Debug)]
pub struct Outcome {
    pub stdout: Vec<u8>,
    pub exit_code: u32,
}

pub struct Machine {
    pub regs: [u64; 16],
    pub flags: Flags,
    /// Auxiliary carry. Kept beside [`Flags`] so the five architectural status bits stay stable.
    pub af: bool,
    /// Direction flag for string operations.
    pub df: bool,
    /// x87 stack. Eighty-bit registers, control word, and status word.
    pub x87: crate::ir::X87,
    /// SSE/SSE2 file. Sixteen raw XMM registers and MXCSR.
    pub sse: crate::ir::Sse,
    pub rip: u64,
    pub regions: Vec<Region>,
    pub hooks: HashMap<u64, Api>,
    pub stdout: Vec<u8>,
    pub exit_code: Option<u32>,
    pub policy: Policy,
    pub gs: u64,
    pub steps: u64,
    /// TLS callbacks, then any [`Policy::watch`] hits, in execution order.
    pub trace: Vec<u64>,
    /// Taken jump, call, and return targets. M-TRACE, not Intel Processor Trace.
    branches: branch::BranchRing,
    /// The weak kernel-module query ran. A hit does not by itself change the exit.
    pub saw_weak_module: bool,
    tls: Vec<u64>,
    pe_tls: Option<u64>,
    image: instrument::ImageMap,
}

#[derive(Clone, Debug)]
pub struct Region {
    pub base: u64,
    pub data: Vec<u8>,
}

impl Machine {
    fn context_chain_ptr(&self) -> Result<u64> {
        if let Some(base) = self.pe_tls {
            return Ok(base);
        }
        let at = self.gs.wrapping_add(crate::vm::GS_CHAIN_PTR as u64);
        Ok(u64::from_le_bytes(exact_bytes(&self.read(at, 8)?)?))
    }

    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let region = self.region(addr, len)?;
        let off = (addr - region.base) as usize;
        Ok(region.data[off..off + len].to_vec())
    }

    pub fn write(&mut self, addr: u64, bytes: &[u8]) -> Result<()> {
        self.store(addr, bytes)?;
        instrument::note_store(self, addr, bytes);
        Ok(())
    }

    fn store(&mut self, addr: u64, bytes: &[u8]) -> Result<()> {
        let region = self.region_mut(addr, bytes.len())?;
        let off = (addr - region.base) as usize;
        region.data[off..off + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn region(&self, addr: u64, len: usize) -> Result<&Region> {
        self.regions
            .iter()
            .find(|region| mapped(region, addr, len))
            .ok_or_else(|| msg(format!("unmapped read {addr:#x}+{len}")))
    }

    fn region_mut(&mut self, addr: u64, len: usize) -> Result<&mut Region> {
        self.regions
            .iter_mut()
            .find(|region| mapped(region, addr, len))
            .ok_or_else(|| msg(format!("unmapped write {addr:#x}+{len}")))
    }
}

fn mapped(region: &Region, addr: u64, len: usize) -> bool {
    let Ok(len) = u64::try_from(len) else {
        return false;
    };
    let Ok(size) = u64::try_from(region.data.len()) else {
        return false;
    };
    if addr < region.base {
        return false;
    }
    let Some(end) = (addr - region.base).checked_add(len) else {
        return false;
    };
    end <= size && (len == 0 || addr.checked_add(len - 1).is_some())
}

fn guest_machine(policy: Policy, rip: u64, regions: Vec<Region>) -> Machine {
    Machine {
        regs: [0; 16],
        flags: Flags::default(),
        af: false,
        df: false,
        x87: crate::ir::X87::default(),
        sse: crate::ir::Sse::default(),
        rip,
        regions,
        hooks: HashMap::new(),
        stdout: Vec::new(),
        exit_code: None,
        policy,
        gs: GS_BASE,
        steps: 0,
        trace: Vec::new(),
        branches: branch::BranchRing::new(),
        saw_weak_module: false,
        tls: Vec::new(),
        pe_tls: None,
        image: instrument::ImageMap::empty(),
    }
}

pub fn bare(policy: Policy) -> Result<Machine> {
    let mut machine = guest_machine(
        policy,
        0,
        vec![
            Region {
                base: STACK,
                data: vec![0; STACK_SIZE],
            },
            Region {
                base: GS_BASE,
                data: vec![0; 0x2000],
            },
        ],
    );
    machine.write(GS_BASE + 0x60, &PEB.to_le_bytes())?;
    plant_chain(&mut machine)?;
    let mut rsp = (STACK + STACK_SIZE as u64 - 0x1000) & !0xfu64;
    rsp -= 8;
    machine.write(rsp, &SENTINEL.to_le_bytes())?;
    machine.regs[4] = rsp;
    Ok(machine)
}

fn plant_chain(machine: &mut Machine) -> Result<()> {
    let chain = GS_BASE + crate::vm::GS_CHAIN_AT as u64;
    machine.write(
        GS_BASE + crate::vm::GS_CHAIN_PTR as u64,
        &chain.to_le_bytes(),
    )
}

pub fn run_pe(bytes: &[u8], policy: Policy) -> Result<Outcome> {
    let image = parse(bytes)?;
    let mut machine = load(&image, policy)?;
    machine.run()?;
    Ok(Outcome {
        stdout: machine.stdout,
        exit_code: machine.exit_code.unwrap_or(0),
    })
}

fn map_sections(image: &PeImage) -> Result<Vec<u8>> {
    if image.sections.is_empty() {
        return Err(msg("image has no sections"));
    }
    let mut span = 0x1000usize;
    for section in &image.sections {
        let end = (section.rva as usize)
            .checked_add(section.bytes.len())
            .ok_or_else(|| msg("section is too large to map"))?;
        span = span.max(end);
    }
    if span > 32 * 1024 * 1024 {
        return Err(msg("image is too large to map"));
    }
    let mut mapped = vec![0u8; span.next_multiple_of(0x1000)];
    for section in &image.sections {
        let off = section.rva as usize;
        mapped[off..off + section.bytes.len()].copy_from_slice(&section.bytes);
    }
    Ok(mapped)
}

pub fn load(image: &PeImage, policy: Policy) -> Result<Machine> {
    let mapped = map_sections(image)?;
    let entry = image.image_base.wrapping_add(u64::from(image.entry_rva));
    let mut machine = guest_machine(
        policy,
        entry,
        vec![
            Region {
                base: image.image_base,
                data: mapped,
            },
            Region {
                base: STACK,
                data: vec![0; STACK_SIZE],
            },
            Region {
                base: GS_BASE,
                data: vec![0; 0x2000],
            },
        ],
    );
    publish_peb(&mut machine, image.image_base)?;
    plant_chain(&mut machine)?;
    let mut rsp = (STACK + STACK_SIZE as u64 - 0x1000) & !0xfu64;
    rsp -= 8;
    machine.write(rsp, &SENTINEL.to_le_bytes())?;
    machine.regs[4] = rsp;
    bind_imports(&mut machine, image)?;
    install_kernel32(&mut machine)?;
    plant_int3(&mut machine)?;
    instrument::capture(&mut machine, image)?;
    machine.tls = crate::pe::tls_callbacks(image)?;
    plant_pe_tls(&mut machine, image)?;
    Ok(machine)
}

fn plant_pe_tls(machine: &mut Machine, image: &PeImage) -> Result<()> {
    const VECTOR: u64 = 0x7ffe_8000;
    const BLOCK: u64 = 0x3_7000_0000;
    // A nonzero index catches a code generator that assumes slot zero.
    const INDEX: u32 = 3;

    if image.tls_rva == 0 || image.tls_size == 0 {
        return Ok(());
    }
    let dir = crate::pe::read_rva(image, image.tls_rva, 40)?;
    let start = u64::from_le_bytes(exact_bytes(&dir[..8])?);
    let end = u64::from_le_bytes(exact_bytes(&dir[8..16])?);
    let index = u64::from_le_bytes(exact_bytes(&dir[16..24])?);
    let zero = u32::from_le_bytes(exact_bytes(&dir[32..36])?) as usize;
    if start == 0 && end == 0 && zero == 0 {
        return Ok(());
    }
    let raw = usize::try_from(
        end.checked_sub(start)
            .ok_or_else(|| msg("invalid TLS template"))?,
    )
    .map_err(|_| msg("invalid TLS template"))?;
    let len = raw
        .checked_add(zero)
        .ok_or_else(|| msg("TLS size overflows"))?;
    if len == 0 || len > crate::stub::PE_TLS_LIMIT {
        return Err(msg("PE TLS size is outside the emulator limit"));
    }
    let mut data = vec![0; len];
    if raw != 0 {
        data[..raw].copy_from_slice(&machine.read(start, raw)?);
    }
    machine.regions.push(Region { base: BLOCK, data });
    machine.regions.push(Region {
        base: VECTOR,
        data: vec![0; 0x100],
    });
    machine.write(VECTOR + u64::from(INDEX) * 8, &BLOCK.to_le_bytes())?;
    machine.write(
        machine.gs + crate::stub::PE_TLS_VECTOR as u64,
        &VECTOR.to_le_bytes(),
    )?;
    machine.write(index, &INDEX.to_le_bytes())?;
    machine.pe_tls = Some(BLOCK);
    Ok(())
}

pub const K32_BASE: u64 = 0x1_8000_0000;
pub(crate) const NTDLL_BASE: u64 = 0x1_7FF0_0000;
const NTDLL_EXPORTS: &[&str] = &[
    "NtQueryInformationProcess",
    "NtQueryInformationThread",
    "NtQuerySystemInformation",
    "DbgUiRemoteBreakin",
];
const HEAP: u64 = 0x2000_0000;

fn publish_peb(machine: &mut Machine, image_base: u64) -> Result<()> {
    machine.write(GS_BASE + 0x60, &PEB.to_le_bytes())?;
    machine.write(PEB + 0x02, &[machine.policy.being_debugged])?;
    machine.write(PEB + 0x10, &image_base.to_le_bytes())?;
    machine.write(PEB + 0xbc, &machine.policy.nt_global.to_le_bytes())?;
    let callback = machine.policy.instrumentation.to_le_bytes();
    machine.write(
        PEB + crate::antidebug::PEB_INSTRUMENTATION as u64,
        &callback,
    )?;
    publish_heap(machine)
}

fn publish_heap(machine: &mut Machine) -> Result<()> {
    machine.regions.push(Region {
        base: HEAP,
        data: vec![0; 0x100],
    });
    machine.write(PEB + 0x30, &HEAP.to_le_bytes())?;
    machine.write(HEAP + 0x70, &machine.policy.heap_flags.to_le_bytes())?;
    machine.write(HEAP + 0x74, &machine.policy.heap_force.to_le_bytes())?;
    Ok(())
}

pub fn install_kernel32(machine: &mut Machine) -> Result<()> {
    install_exports(
        machine,
        K32_BASE,
        &[
            "GetStdHandle",
            "WriteFile",
            "ExitProcess",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "GetTickCount64",
            "LoadLibraryA",
            "GetProcAddress",
            "GetThreadContext",
            "CloseHandle",
            "SetHandleInformation",
        ],
    )?;
    install_exports(machine, NTDLL_BASE, NTDLL_EXPORTS)?;
    plant_breakin(machine)?;
    link_user_modules(machine)
}

fn plant_breakin(machine: &mut Machine) -> Result<()> {
    let index = NTDLL_EXPORTS
        .iter()
        .position(|name| *name == "DbgUiRemoteBreakin")
        .ok_or_else(|| msg("DbgUiRemoteBreakin export missing"))?;
    let at = NTDLL_BASE + 0x1000 + index as u64 * 0x10;
    let byte = if machine.policy.breakin_substituted {
        crate::antidebug::BREAKIN_SUBSTITUTED
    } else {
        crate::antidebug::BREAKIN_CLEAN
    };
    machine.write(at, &[byte])
}

fn plant_int3(machine: &mut Machine) -> Result<()> {
    if !machine.policy.int3_page {
        return Ok(());
    }
    let mark = crate::antidebug::INT3_MARK;
    for region in &mut machine.regions {
        let Some(at) = region
            .data
            .windows(mark.len())
            .position(|item| item == mark)
        else {
            continue;
        };
        let slot = at + mark.len();
        if slot < region.data.len() {
            region.data[slot] = 0xcc;
            return Ok(());
        }
    }
    Err(msg("int3 page mark is missing"))
}

fn install_exports(machine: &mut Machine, base: u64, names: &[&str]) -> Result<()> {
    let image = export_image(names)?;
    for (index, name) in names.iter().enumerate() {
        let hook = base + 0x1000 + index as u64 * 0x10;
        machine.hooks.insert(hook, hooked(name));
    }
    machine.regions.push(Region { base, data: image });
    Ok(())
}

fn export_image(names: &[&str]) -> Result<Vec<u8>> {
    let mut image = vec![0u8; 0x2000];
    image[0] = b'M';
    image[1] = b'Z';
    image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    image[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    let export_rva = 0x200u32;
    image[0x80 + 24 + 112..0x80 + 24 + 116].copy_from_slice(&export_rva.to_le_bytes());
    let count = u32::try_from(names.len()).map_err(|_| msg("too many exports"))?;
    let dir = 0x200usize;
    image[dir + 0x18..dir + 0x1c].copy_from_slice(&count.to_le_bytes());
    image[dir + 0x1c..dir + 0x20].copy_from_slice(&0x300u32.to_le_bytes());
    image[dir + 0x20..dir + 0x24].copy_from_slice(&0x400u32.to_le_bytes());
    image[dir + 0x24..dir + 0x28].copy_from_slice(&0x500u32.to_le_bytes());
    write_export_names(&mut image, names)?;
    Ok(image)
}

fn write_export_names(image: &mut [u8], names: &[&str]) -> Result<()> {
    let mut cursor = 0x600usize;
    for (index, name) in names.iter().enumerate() {
        let hook_rva = 0x1000 + index as u32 * 0x10;
        let at = 0x300 + index * 4;
        image[at..at + 4].copy_from_slice(&hook_rva.to_le_bytes());
        image[0x400 + index * 4..0x404 + index * 4].copy_from_slice(&(cursor as u32).to_le_bytes());
        image[0x500 + index * 2..0x502 + index * 2].copy_from_slice(&(index as u16).to_le_bytes());
        let end = cursor + name.len();
        image
            .get_mut(cursor..end)
            .ok_or_else(|| msg("export names overflow"))?
            .copy_from_slice(name.as_bytes());
        cursor = end + 1;
    }
    Ok(())
}

fn link_user_modules(machine: &mut Machine) -> Result<()> {
    let ldr = 0x7ffe_2000u64;
    let ntdll = 0x7ffe_3200u64;
    let k32 = 0x7ffe_3000u64;
    machine.regions.push(Region {
        base: ldr,
        data: vec![0; 0x2000],
    });
    machine.write(PEB + 0x18, &ldr.to_le_bytes())?;
    let head = ldr + 0x20;
    let ntdll_links = ntdll + 0x10;
    let k32_links = k32 + 0x10;
    machine.write(head, &ntdll_links.to_le_bytes())?;
    machine.write(ntdll_links, &k32_links.to_le_bytes())?;
    machine.write(k32_links, &head.to_le_bytes())?;
    write_ldr(machine, ntdll, NTDLL_BASE, "ntdll.dll")?;
    write_ldr(machine, k32, K32_BASE, "kernel32.dll")
}

fn write_ldr(machine: &mut Machine, entry: u64, base: u64, name: &str) -> Result<()> {
    machine.write(entry + 0x30, &base.to_le_bytes())?;
    let wide: Vec<u8> = name
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let name_at = entry + 0x80;
    machine.write(entry + 0x58, &(wide.len() as u16).to_le_bytes())?;
    machine.write(entry + 0x60, &name_at.to_le_bytes())?;
    machine.write(name_at, &wide)
}

fn hooked(name: &str) -> Api {
    match name {
        "GetStdHandle" => Api::GetStdHandle,
        "WriteFile" => Api::WriteFile,
        "ExitProcess" => Api::ExitProcess,
        "IsDebuggerPresent" => Api::IsDebuggerPresent,
        "CheckRemoteDebuggerPresent" => Api::CheckRemoteDebuggerPresent,
        "GetTickCount64" => Api::GetTickCount64,
        "LoadLibraryA" => Api::LoadLibraryA,
        "GetProcAddress" => Api::GetProcAddress,
        "GetThreadContext" => Api::GetThreadContext,
        "CloseHandle" => Api::CloseHandle,
        "SetHandleInformation" => Api::SetHandleInformation,
        "NtQueryInformationProcess" => Api::NtQueryInformationProcess,
        "NtQueryInformationThread" => Api::NtQueryInformationThread,
        "NtQuerySystemInformation" => Api::NtQuerySystemInformation,
        _ => Api::GetProcAddress,
    }
}

#[must_use]
pub fn djb2(bytes: &[u8]) -> u32 {
    let mut hash = 5381u32;
    for byte in bytes {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(*byte));
    }
    hash
}

fn bind_imports(machine: &mut Machine, image: &PeImage) -> Result<()> {
    for (index, import) in image.imports.iter().enumerate() {
        let api = match import.name.as_str() {
            "GetStdHandle" => Api::GetStdHandle,
            "WriteFile" => Api::WriteFile,
            "ExitProcess" => Api::ExitProcess,
            "IsDebuggerPresent" => Api::IsDebuggerPresent,
            "CheckRemoteDebuggerPresent" => Api::CheckRemoteDebuggerPresent,
            "GetTickCount64" => Api::GetTickCount64,
            "LoadLibraryA" => Api::LoadLibraryA,
            "GetProcAddress" => Api::GetProcAddress,
            other => return Err(msg(format!("sample import {other} is not emulated"))),
        };
        let hook = 0x1800_01000 + index as u64 * 0x10;
        machine.hooks.insert(hook, api);
        machine.write(
            image.image_base.wrapping_add(u64::from(import.iat_rva)),
            &hook.to_le_bytes(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::{self, build};

    #[test]
    fn unprotected_sample_prints_the_reference_line() {
        let built = build().unwrap();
        let outcome = run_pe(&built.bytes, Policy::default()).unwrap();
        assert_eq!(
            outcome.exit_code,
            0,
            "stdout {}",
            String::from_utf8_lossy(&outcome.stdout)
        );
        assert_eq!(outcome.stdout, sample::line().into_bytes());
    }

    fn machine_at(base: u64, data: Vec<u8>) -> Machine {
        let mut machine = bare(Policy::default()).unwrap();
        machine.regions.push(Region { base, data });
        machine
    }

    #[test]
    fn read_and_write_near_the_top_of_the_address_space_are_unmapped() {
        let mut machine = bare(Policy::default()).unwrap();
        let addr = u64::MAX - 1;
        let read_err = machine.read(addr, 4).unwrap_err();
        assert_eq!(read_err.to_string(), format!("unmapped read {addr:#x}+4"));
        let write_err = machine.write(addr, &[1, 2, 3, 4]).unwrap_err();
        assert_eq!(write_err.to_string(), format!("unmapped write {addr:#x}+4"));
    }

    #[test]
    fn reads_and_writes_honor_the_end_of_a_region() {
        let mut machine = machine_at(0x1000, vec![0; 0x100]);
        machine.write(0x1010, &[9, 8, 7, 6]).unwrap();
        assert_eq!(machine.read(0x1010, 4).unwrap(), vec![9, 8, 7, 6]);
        machine.write(0x10fc, &[1, 2, 3, 4]).unwrap();
        assert_eq!(machine.read(0x10fc, 4).unwrap(), vec![1, 2, 3, 4]);
        let err = machine.read(0x10fd, 4).unwrap_err();
        assert_eq!(err.to_string(), "unmapped read 0x10fd+4");
        let err = machine.write(0x10fd, &[1, 2, 3, 4]).unwrap_err();
        assert_eq!(err.to_string(), "unmapped write 0x10fd+4");
        assert_eq!(machine.read(0x1100, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn the_last_representable_address_stays_readable() {
        let mut machine = machine_at(u64::MAX, vec![0xab]);
        assert_eq!(machine.read(u64::MAX, 1).unwrap(), vec![0xab]);
        machine.write(u64::MAX, &[0xcd]).unwrap();
        assert_eq!(machine.read(u64::MAX, 1).unwrap(), vec![0xcd]);
        let err = machine.read(u64::MAX, 2).unwrap_err();
        assert_eq!(err.to_string(), format!("unmapped read {:#x}+2", u64::MAX));
    }
}
