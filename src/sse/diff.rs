//! SSE/SSE2 blocks against this Linux process. The carrier reports the raw 16
//! bytes of every XMM register and MXCSR.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use iced_x86::code_asm::{
    byte_ptr, dword_ptr, eax, ecx, edi, qword_ptr, r10, r11, r12, r12d, r13, r14, r15, r8, r9, rax,
    rbp, rbx, rcx, rdi, rdx, rsi, rsp, CodeAssembler, CodeLabel,
};
use iced_x86::{
    BlockEncoderOptions, Code, Decoder, DecoderOptions, Encoder, Formatter, Instruction,
    IntelFormatter, Mnemonic, OpCodeOperandKind, OpKind, Register,
};

use crate::flags::Flags;
use crate::gp::Cpu;
use crate::ir::{exec_program, MemIo, Sse, X87};
use crate::isa::census::{self, Group, Status};

use super::{host, load_image, store_image};

const ENTRY: u64 = 0x400100;
const GUEST: u64 = 0x401000;
const DATA: u64 = 0x402000;
const SAVE: u64 = 0x403000;
const SCRATCH: u64 = 0x403200;
const XSTATE: u64 = 0x404000;
const STACK: u64 = 0x405f00;
const DATA_LEN: usize = 0x1000;
const MAX_CODE: usize = 256;
const XSTATE_LEN: usize = 512;
const YMM_STATE: u64 = 0x404200;
const YMM_LEN: usize = 512;
const RESULT: usize = 136 + XSTATE_LEN + YMM_LEN + DATA_LEN;
const MAGIC: u64 = 0x1122_3344_5566_7788;

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

// SAFETY: the call is local, one PollFd on the stack, timeout 5s.
unsafe extern "C" {
    fn poll(fds: *mut PollFd, nfds: usize, timeout: i32) -> i32;
}

struct Case {
    code: Vec<u8>,
    regs: [u64; 16],
    rflags: u64,
    x87: X87,
    sse: Sse,
    data: Vec<u8>,
}

#[derive(Debug)]
struct Observed {
    regs: [u64; 16],
    rflags: u64,
    x87: X87,
    sse: Sse,
    data: Vec<u8>,
}

struct Page {
    bytes: Vec<u8>,
}

fn page_offset(addr: u64, len: usize) -> crate::error::Result<usize> {
    let start = addr
        .checked_sub(DATA)
        .ok_or_else(|| crate::error::msg(format!("unmapped {addr:#x}")))?;
    let start = usize::try_from(start).map_err(|_| crate::error::msg("address"))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| crate::error::msg("length"))?;
    if end > DATA_LEN {
        return Err(crate::error::msg(format!("unmapped {addr:#x}+{len}")));
    }
    Ok(start)
}

impl MemIo for Page {
    fn read(&mut self, addr: u64, len: usize) -> crate::error::Result<Vec<u8>> {
        let start = page_offset(addr, len)?;
        Ok(self.bytes[start..start + len].to_vec())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> crate::error::Result<()> {
        let start = page_offset(addr, data.len())?;
        self.bytes[start..start + data.len()].copy_from_slice(data);
        Ok(())
    }
}

fn fresh() -> Case {
    let mut regs = [0u64; 16];
    regs[4] = STACK;
    regs[7] = DATA;
    regs[15] = DATA;
    regs[0] = 0x3f80_0000;
    regs[1] = 0x0A02;
    regs[2] = 0x0123_4567_89AB_CDEF;
    regs[8] = 0x1020_3040_5060_7080;
    let mut sse = Sse::default();
    for (index, xmm) in sse.xmm.iter_mut().enumerate() {
        let lane0 = 0x3f80_0000u32.wrapping_add(index as u32);
        xmm[0..4].copy_from_slice(&lane0.to_le_bytes());
        xmm[4..8].copy_from_slice(&0x4000_0000u32.to_le_bytes());
        xmm[8..12].copy_from_slice(&0x4040_0000u32.to_le_bytes());
        xmm[12..16].copy_from_slice(&(0xA5A5_0000 | index as u32).to_le_bytes());
    }
    let mut data = vec![0; DATA_LEN];
    data[0..4].copy_from_slice(&0x3f80u32.to_le_bytes());
    for (index, byte) in data.iter_mut().enumerate().skip(4) {
        *byte = (index.wrapping_mul(17).wrapping_add(3)) as u8;
    }
    Case {
        code: Vec::new(),
        regs,
        rflags: 0x202,
        x87: X87::default(),
        sse,
        data,
    }
}

fn asm_ok(result: std::result::Result<(), iced_x86::IcedError>) {
    result.expect("harness instruction");
}

fn gprs() -> [iced_x86::code_asm::AsmRegister64; 16] {
    [
        rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    ]
}

fn harness_bytes() -> Vec<u8> {
    let mut asm = CodeAssembler::new(64).expect("assembler");
    asm.set_prefer_short_branch(false);
    let mut top = asm.create_label();
    let mut read_exact = asm.create_label();
    let mut read_done = asm.create_label();
    let fail = asm.create_label();
    let mut done = asm.create_label();
    let mut epilogue = asm.create_label();
    harness_load(&mut asm, &mut top, read_exact, fail, done);
    harness_enter(&mut asm, &mut epilogue);
    harness_save(&mut asm);
    harness_report(&mut asm, top);
    harness_io(&mut asm, &mut read_exact, &mut read_done, fail, &mut done);
    finish_harness(asm, &epilogue)
}

fn harness_load(
    asm: &mut CodeAssembler,
    top: &mut CodeLabel,
    read_exact: CodeLabel,
    fail: CodeLabel,
    done: CodeLabel,
) {
    asm_ok(asm.mov(rsp, STACK));
    asm_ok(asm.set_label(top));
    asm_ok(asm.mov(r15, SCRATCH));
    asm_ok(asm.mov(rsi, r15));
    asm_ok(asm.mov(rdx, 4u64));
    asm_ok(asm.call(read_exact));
    asm_ok(asm.mov(eax, dword_ptr(r15)));
    asm_ok(asm.test(eax, eax));
    asm_ok(asm.jz(done));
    asm_ok(asm.cmp(eax, MAX_CODE as i32));
    asm_ok(asm.ja(fail));
    asm_ok(asm.mov(r12d, eax));
    asm_ok(asm.mov(rsi, GUEST));
    asm_ok(asm.mov(rdx, r12));
    asm_ok(asm.call(read_exact));
    asm_ok(asm.mov(r15, SAVE));
    asm_ok(asm.mov(rsi, r15));
    asm_ok(asm.mov(rdx, 128u64));
    asm_ok(asm.call(read_exact));
    asm_ok(asm.lea(rsi, qword_ptr(r15 + 128i32)));
    asm_ok(asm.mov(rdx, 8u64));
    asm_ok(asm.call(read_exact));
    asm_ok(asm.mov(rsi, XSTATE));
    asm_ok(asm.mov(rdx, XSTATE_LEN as u64));
    asm_ok(asm.call(read_exact));
    asm_ok(asm.mov(rsi, YMM_STATE));
    asm_ok(asm.mov(rdx, YMM_LEN as u64));
    asm_ok(asm.call(read_exact));
    asm_ok(asm.mov(rsi, DATA));
    asm_ok(asm.mov(rdx, DATA_LEN as u64));
    asm_ok(asm.call(read_exact));
}

fn harness_enter(asm: &mut CodeAssembler, epilogue: &mut CodeLabel) {
    asm_ok(asm.mov(rax, GUEST));
    asm_ok(asm.add(rax, r12));
    asm_ok(asm.mov(byte_ptr(rax), 0xE9i32));
    asm_ok(asm.mov(rcx, MAGIC));
    asm_ok(asm.lea(rdx, qword_ptr(rax + 5i32)));
    asm_ok(asm.sub(rcx, rdx));
    asm_ok(asm.mov(dword_ptr(rax + 1i32), ecx));
    asm_ok(asm.mov(rsp, STACK));
    asm_ok(asm.mov(rax, XSTATE));
    asm_ok(asm.db(&[0x48, 0x0f, 0xae, 0x08])); // fxrstor64 [rax]
    asm_ok(asm.mov(rax, YMM_STATE));
    emit_ymm(asm, false, 0);
    asm_ok(asm.mov(rax, qword_ptr(r15 + 128i32)));
    asm_ok(asm.push(rax));
    asm_ok(asm.popfq());
    for (index, reg) in gprs().into_iter().enumerate() {
        if index == 4 || index == 15 {
            continue;
        }
        asm_ok(asm.mov(reg, qword_ptr(r15 + (index * 8) as i32)));
    }
    asm_ok(asm.mov(rsp, qword_ptr(r15 + 32i32)));
    asm_ok(asm.mov(r15, qword_ptr(r15 + 120i32)));
    asm_ok(asm.jmp(GUEST));
    asm_ok(asm.set_label(epilogue));
}

fn harness_save(asm: &mut CodeAssembler) {
    asm_ok(asm.db(&[0xA6; 7])); // mov [rip], r15
    asm_ok(asm.mov(r15, YMM_STATE));
    emit_ymm(asm, true, 15);
    asm_ok(asm.mov(r15, XSTATE));
    asm_ok(asm.db(&[0x49, 0x0f, 0xae, 0x07])); // fxsave64 [r15]
    asm_ok(asm.mov(r15, SAVE));
    for (index, reg) in gprs().into_iter().enumerate() {
        if index == 4 || index == 15 {
            continue;
        }
        asm_ok(asm.mov(qword_ptr(r15 + (index * 8) as i32), reg));
    }
    asm_ok(asm.db(&[0xA7; 7])); // mov rax, [rip]
    asm_ok(asm.mov(qword_ptr(r15 + 120i32), rax));
    asm_ok(asm.mov(rax, rsp));
    asm_ok(asm.mov(qword_ptr(r15 + 32i32), rax));
}

fn harness_report(asm: &mut CodeAssembler, top: CodeLabel) {
    asm_ok(asm.mov(rsp, STACK));
    asm_ok(asm.pushfq());
    asm_ok(asm.pop(rax));
    asm_ok(asm.mov(qword_ptr(r15 + 128i32), rax));
    asm_ok(asm.mov(eax, 1i32));
    asm_ok(asm.mov(edi, 1i32));
    asm_ok(asm.mov(rsi, SAVE));
    asm_ok(asm.mov(rdx, 136u64));
    asm_ok(asm.syscall());
    asm_ok(asm.mov(eax, 1i32));
    asm_ok(asm.mov(edi, 1i32));
    asm_ok(asm.mov(rsi, XSTATE));
    asm_ok(asm.mov(rdx, XSTATE_LEN as u64));
    asm_ok(asm.syscall());
    asm_ok(asm.mov(eax, 1i32));
    asm_ok(asm.mov(edi, 1i32));
    asm_ok(asm.mov(rsi, YMM_STATE));
    asm_ok(asm.mov(rdx, YMM_LEN as u64));
    asm_ok(asm.syscall());
    asm_ok(asm.mov(eax, 1i32));
    asm_ok(asm.mov(edi, 1i32));
    asm_ok(asm.mov(rsi, DATA));
    asm_ok(asm.mov(rdx, DATA_LEN as u64));
    asm_ok(asm.syscall());
    asm_ok(asm.jmp(top));
}

fn harness_io(
    asm: &mut CodeAssembler,
    read_exact: &mut CodeLabel,
    read_done: &mut CodeLabel,
    fail: CodeLabel,
    done: &mut CodeLabel,
) {
    asm_ok(asm.set_label(read_exact));
    asm_ok(asm.test(rdx, rdx));
    asm_ok(asm.jz(*read_done));
    asm_ok(asm.xor(eax, eax));
    asm_ok(asm.xor(edi, edi));
    asm_ok(asm.syscall());
    asm_ok(asm.cmp(rax, 1i32));
    asm_ok(asm.jl(fail));
    asm_ok(asm.add(rsi, rax));
    asm_ok(asm.sub(rdx, rax));
    asm_ok(asm.jmp(*read_exact));
    asm_ok(asm.set_label(read_done));
    asm_ok(asm.ret());
    let mut fail = fail;
    asm_ok(asm.set_label(&mut fail));
    asm_ok(asm.mov(eax, 60i32));
    asm_ok(asm.mov(edi, 3i32));
    asm_ok(asm.syscall());
    asm_ok(asm.set_label(done));
    asm_ok(asm.mov(eax, 60i32));
    asm_ok(asm.xor(edi, edi));
    asm_ok(asm.syscall());
}

fn finish_harness(mut asm: CodeAssembler, epilogue: &CodeLabel) -> Vec<u8> {
    let result = asm
        .assemble_options(ENTRY, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .expect("assemble harness");
    let epi = result.label_ip(epilogue).expect("epilogue address");
    let mut code = result.inner.code_buffer;
    let needle = MAGIC.to_le_bytes();
    let mut hits = Vec::new();
    for (index, window) in code.windows(8).enumerate() {
        if window == needle {
            hits.push(index);
        }
    }
    assert_eq!(hits.len(), 1, "epilogue immediate");
    code[hits[0]..hits[0] + 8].copy_from_slice(&epi.to_le_bytes());
    patch_rip(&mut code, &[0xA6; 7], 0x4C, 0x89, 0x3D);
    patch_rip(&mut code, &[0xA7; 7], 0x48, 0x8B, 0x05);
    code
}

fn patch_rip(code: &mut [u8], marker: &[u8], rex: u8, opcode: u8, modrm: u8) {
    let at = code
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("scratch marker");
    let next = ENTRY + at as u64 + 7;
    let disp = i32::try_from(SCRATCH as i64 - next as i64).expect("scratch disp");
    code[at] = rex;
    code[at + 1] = opcode;
    code[at + 2] = modrm;
    code[at + 3..at + 7].copy_from_slice(&disp.to_le_bytes());
}

fn elf_image(code: &[u8]) -> Vec<u8> {
    let mut file = vec![0u8; 0x100 + code.len()];
    file[0x100..].copy_from_slice(code);
    file[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&2u16.to_le_bytes());
    file[18..20].copy_from_slice(&62u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[24..32].copy_from_slice(&ENTRY.to_le_bytes());
    file[32..40].copy_from_slice(&64u64.to_le_bytes());
    file[52..54].copy_from_slice(&64u16.to_le_bytes());
    file[54..56].copy_from_slice(&56u16.to_le_bytes());
    file[56..58].copy_from_slice(&1u16.to_le_bytes());
    let ph = 64;
    file[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    file[ph + 4..ph + 8].copy_from_slice(&7u32.to_le_bytes());
    file[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    file[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes());
    let filesz = file.len() as u64;
    file[ph + 32..ph + 40].copy_from_slice(&filesz.to_le_bytes());
    file[ph + 40..ph + 48].copy_from_slice(&0x8000u64.to_le_bytes());
    file[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    file
}

struct Host {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
}

impl Host {
    fn spawn(tag: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("l3-carrier-{tag}-{id}"));
        std::fs::create_dir_all(path.parent().expect("target parent")).expect("target dir");
        std::fs::write(&path, elf_image(&harness_bytes()))
            .unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let mut child = None;
        for _ in 0..8 {
            match Command::new(&path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(spawned) => {
                    child = Some(spawned);
                    break;
                }
                Err(err) if err.raw_os_error() == Some(26) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(err) => panic!("spawn {}: {err}", path.display()),
            }
        }
        let mut child = child.unwrap_or_else(|| panic!("spawn {}: text file busy", path.display()));
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        Self {
            child: Some(child),
            stdin: Some(stdin),
            stdout,
        }
    }

    fn send(&mut self, case: &Case) -> std::io::Result<()> {
        let stdin = self.stdin.as_mut().expect("stdin");
        let image = image_of(&case.x87, &case.sse);
        stdin.write_all(&(u32::try_from(case.code.len()).expect("len")).to_le_bytes())?;
        stdin.write_all(&case.code)?;
        for reg in case.regs {
            stdin.write_all(&reg.to_le_bytes())?;
        }
        stdin.write_all(&case.rflags.to_le_bytes())?;
        stdin.write_all(&image)?;
        stdin.write_all(&super::ymm_image(&case.sse))?;
        stdin.write_all(&case.data)?;
        Ok(())
    }

    fn roundtrip(&mut self, case: &Case) -> std::result::Result<Observed, String> {
        if let Err(err) = self.send(case) {
            return Err(self.fail(err.to_string()));
        }
        let mut buf = vec![0u8; RESULT];
        if let Err(err) = read_full(&mut self.stdout, &mut buf) {
            return Err(self.fail(err.to_string()));
        }
        Ok(parse_observed(&buf))
    }

    fn fail(&mut self, why: String) -> String {
        let status = self.child.take().map(|mut child| {
            let _ = child.kill();
            child.wait().ok()
        });
        let signal = status
            .as_ref()
            .and_then(|ready| ready.as_ref())
            .and_then(|status| status.signal());
        format!("{why}; status={status:?}; signal={signal:?}")
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = stdin.write_all(&0u32.to_le_bytes());
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }
}

fn image_of(x87: &X87, sse: &Sse) -> [u8; 512] {
    let mut image = host::capture_template();
    store_image(x87, sse, &mut image);
    image
}

fn read_full(source: &mut (impl Read + AsRawFd), buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let mut poll_fd = PollFd {
            fd: source.as_raw_fd(),
            events: 1,
            revents: 0,
        };
        loop {
            // SAFETY: one PollFd on the stack, timeout 5s.
            let ready = unsafe { poll(&mut poll_fd, 1, 5_000) };
            if ready < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if ready == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "carrier timed out",
                ));
            }
            break;
        }
        let n = source.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "carrier closed",
            ));
        }
        filled += n;
    }
    Ok(())
}

fn parse_observed(buf: &[u8]) -> Observed {
    let mut regs = [0u64; 16];
    for (index, reg) in regs.iter_mut().enumerate() {
        let start = index * 8;
        let raw: [u8; 8] = buf[start..start + 8].try_into().expect("reg");
        *reg = u64::from_le_bytes(raw);
    }
    let flags = u64::from_le_bytes(buf[128..136].try_into().expect("flags"));
    let mut image = [0u8; 512];
    image.copy_from_slice(&buf[136..136 + XSTATE_LEN]);
    let mut x87 = X87::default();
    let mut sse = Sse::default();
    load_image(&mut x87, &mut sse, &image);
    let mut ymm = [0u8; YMM_LEN];
    let ymm_at = 136 + XSTATE_LEN;
    ymm.copy_from_slice(&buf[ymm_at..ymm_at + YMM_LEN]);
    super::apply_ymm(&mut sse, &ymm);
    Observed {
        regs,
        rflags: flags,
        x87,
        sse,
        data: buf[ymm_at + YMM_LEN..].to_vec(),
    }
}

fn emit_ymm(asm: &mut CodeAssembler, store: bool, base: usize) {
    for index in 0..16 {
        let mut bytes = Vec::new();
        super::host::append_ymm(&mut bytes, store, index, base, (index * 32) as u32);
        asm_ok(asm.db(&bytes));
    }
}

fn split(bits: u64) -> (Flags, bool, bool) {
    (
        Flags::unpack(bits),
        bits & (1 << 4) != 0,
        bits & (1 << 10) != 0,
    )
}

fn join(flags: Flags, af: bool, df: bool) -> u64 {
    let mut bits = 0x202 | flags.pack();
    if af {
        bits |= 1 << 4;
    }
    if df {
        bits |= 1 << 10;
    }
    bits
}

struct Sim {
    regs: [u64; 16],
    flags: Flags,
    af: bool,
    df: bool,
    x87: X87,
    sse: Sse,
    page: Page,
}

impl Sim {
    fn new(case: &Case) -> Self {
        let (flags, af, df) = split(case.rflags);
        Self {
            regs: case.regs,
            flags,
            af,
            df,
            x87: case.x87,
            sse: case.sse,
            page: Page {
                bytes: case.data.clone(),
            },
        }
    }

    fn observed(self) -> Observed {
        Observed {
            regs: self.regs,
            rflags: join(self.flags, self.af, self.df),
            x87: self.x87,
            sse: self.sse,
            data: self.page.bytes,
        }
    }
}

fn emulate(case: &Case) -> std::result::Result<Observed, String> {
    let (result, observed) = run_direct(case);
    result?;
    Ok(observed)
}

fn run_direct(case: &Case) -> (std::result::Result<(), String>, Observed) {
    let mut sim = Sim::new(case);
    let result = step_direct(case, &mut sim);
    (result, sim.observed())
}

fn step_direct(case: &Case, sim: &mut Sim) -> std::result::Result<(), String> {
    let mut decoder = Decoder::with_ip(64, &case.code, GUEST, DecoderOptions::NONE);
    let end = GUEST + case.code.len() as u64;
    while decoder.ip() < end {
        let insn = decoder.decode();
        if insn.is_invalid() || insn.len() == 0 {
            return Err(format!("invalid encoding {}", hex(&case.code)));
        }
        apply_one(case, sim, &insn)?;
    }
    Ok(())
}

fn apply_one(case: &Case, sim: &mut Sim, insn: &Instruction) -> std::result::Result<(), String> {
    let off = usize::try_from(insn.ip() - GUEST).map_err(|_| "ip".to_string())?;
    let raw = case
        .code
        .get(off..off + insn.len())
        .ok_or_else(|| "truncated instruction".to_string())?;
    let mut cpu = Cpu {
        regs: sim.regs,
        flags: sim.flags,
        af: sim.af,
        df: sim.df,
        gs: 0,
    };
    if super::accepts(insn) {
        super::apply(
            &mut sim.sse,
            &mut sim.x87,
            &mut cpu,
            &mut sim.page,
            insn,
            raw,
        )
        .map_err(|err| err.to_string())?;
    } else if crate::x87::is_x87(insn.mnemonic()) {
        crate::x87::apply(&mut sim.x87, &mut cpu, &mut sim.page, insn, raw)
            .map_err(|err| err.to_string())?;
    } else {
        match crate::gp::apply(&mut cpu, &mut sim.page, insn).map_err(|err| err.to_string())? {
            Some(_) => {}
            None => return Err(format!("outside the lifted set: {:?}", insn.mnemonic())),
        }
    }
    sim.regs = cpu.regs;
    sim.flags = cpu.flags;
    sim.af = cpu.af;
    sim.df = cpu.df;
    Ok(())
}

fn emulate_ir(case: &Case) -> std::result::Result<Observed, String> {
    let (result, observed) = run_ir(case);
    result?;
    Ok(observed)
}

fn run_ir(case: &Case) -> (std::result::Result<(), String>, Observed) {
    let mut sim = Sim::new(case);
    let result = exec_ir(case, &mut sim);
    (result, sim.observed())
}

fn exec_ir(case: &Case, sim: &mut Sim) -> std::result::Result<(), String> {
    let program = crate::lift::program("sse", &case.code, GUEST as u32, case.code.len() as u32, 0)
        .map_err(|err| err.to_string())?;
    let mut absent = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
    exec_program(
        &[program],
        0,
        &mut sim.regs,
        &mut sim.flags,
        &mut sim.af,
        &mut sim.df,
        &mut sim.x87,
        &mut sim.sse,
        0,
        &mut sim.page,
        0,
        &mut absent,
    )
    .map_err(|err| err.to_string())
}

fn signal_of(err: &str) -> Option<i32> {
    let rest = err.split("signal=Some(").nth(1)?;
    rest.split(')').next()?.parse().ok()
}

fn assert_same(left: &Observed, right: &Observed, text: &str) {
    assert_eq!(left.regs, right.regs, "regs {text}");
    assert_eq!(left.data, right.data, "data {text}");
    for index in 0..16 {
        assert_eq!(
            left.sse.xmm[index], right.sse.xmm[index],
            "xmm{index} raw {text}\n left {:02x?}\nright {:02x?}",
            left.sse.xmm[index], right.sse.xmm[index]
        );
    }
    for index in 0..16 {
        assert_eq!(
            left.sse.upper[index], right.sse.upper[index],
            "ymm{index} high {text}\n left {:02x?}\nright {:02x?}",
            left.sse.upper[index], right.sse.upper[index]
        );
    }
    assert_eq!(left.sse.mxcsr, right.sse.mxcsr, "mxcsr {text}");
    for index in 0..8 {
        assert_eq!(left.x87.st[index], right.x87.st[index], "st{index} {text}");
    }
    assert_eq!(left.x87.sw, right.x87.sw, "x87 status {text}");
    assert_eq!(left.x87.cw, right.x87.cw, "x87 control {text}");
    assert_eq!(left.x87.tw, right.x87.tw, "x87 tags {text}");
    let (lf, laf, ldf) = split(left.rflags);
    let (rf, raf, rdf) = split(right.rflags);
    assert_eq!(lf, rf, "flags {text}");
    assert_eq!(laf, raf, "af {text}");
    assert_eq!(ldf, rdf, "df {text}");
}

fn check(host: &mut Host, case: &Case) {
    let text = render(&case.code);
    let linux = host
        .roundtrip(case)
        .unwrap_or_else(|err| panic!("linux: {err}\n{text}\n{}", hex(&case.code)));
    let vm = emulate(case).unwrap_or_else(|err| panic!("emu: {err}\n{text}"));
    let ir = emulate_ir(case).unwrap_or_else(|err| panic!("ir: {err}\n{text}"));
    assert_same(&vm, &linux, &text);
    assert_same(&ir, &linux, &format!("ir {text}"));
}

fn expect_fault(host: &mut Host, case: &Case) {
    let text = render(&case.code);
    let err = host
        .roundtrip(case)
        .expect_err(&format!("linux retired {text}"));
    let signal = signal_of(&err);
    assert!(
        matches!(signal, Some(4 | 7 | 8 | 11)),
        "linux {err}\n{text}"
    );
    let (vm_result, vm) = run_direct(case);
    let vm_err = vm_result.expect_err(&format!("emu retired {text}"));
    let (ir_result, ir) = run_ir(case);
    let ir_err = ir_result.expect_err(&format!("ir retired {text}"));
    for (name, got) in [("emu", vm_err), ("ir", ir_err)] {
        assert!(
            got.contains("sse fault") || got.contains("invalid") || got.contains("unmapped"),
            "{name} {got} linux {err}"
        );
    }
    assert_uncommitted("emu", &vm, case, &text);
    assert_uncommitted("ir", &ir, case, &text);
    *host = Host::spawn("fault");
}

fn assert_uncommitted(name: &str, got: &Observed, case: &Case, text: &str) {
    assert_eq!(
        got.sse.xmm, case.sse.xmm,
        "{name} xmm changed across fault {text}"
    );
    assert_eq!(
        got.sse.mxcsr, case.sse.mxcsr,
        "{name} mxcsr changed across fault {text}"
    );
    assert_eq!(
        got.sse.upper, case.sse.upper,
        "{name} ymm high changed across fault {text}"
    );
}

fn build(code: Code, finish: impl FnOnce(&mut Instruction)) -> Vec<u8> {
    let mut insn = Instruction::default();
    insn.set_code(code);
    finish(&mut insn);
    let mut encoder = Encoder::new(64);
    encoder
        .encode(&insn, GUEST)
        .unwrap_or_else(|err| panic!("{code:?}: {err}"));
    encoder.take_buffer()
}

fn regs2(code: Code, a: Register, b: Register) -> Vec<u8> {
    build(code, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(a);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(b);
    })
}

fn xmm_f32(low: f32, high: [u8; 12]) -> [u8; 16] {
    let mut xmm = [0; 16];
    xmm[0..4].copy_from_slice(&low.to_le_bytes());
    xmm[4..].copy_from_slice(&high);
    xmm
}

fn xmm_ps(lanes: [f32; 4]) -> [u8; 16] {
    let mut xmm = [0; 16];
    for (index, lane) in lanes.iter().enumerate() {
        let start = index * 4;
        xmm[start..start + 4].copy_from_slice(&lane.to_le_bytes());
    }
    xmm
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn render(code: &[u8]) -> String {
    let mut out = String::new();
    let mut decoder = Decoder::with_ip(64, code, GUEST, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let end = GUEST + code.len() as u64;
    while decoder.ip() < end {
        let insn = decoder.decode();
        if insn.len() == 0 {
            break;
        }
        if !out.is_empty() {
            out.push_str("; ");
        }
        let mut line = String::new();
        formatter.format(&insn, &mut line);
        out.push_str(&line);
    }
    out
}

#[test]
fn scalar_keeps_upper_bytes_and_packed_writes_every_lane() {
    let high = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
    ];
    let mut scalar = fresh();
    scalar.sse.xmm[0] = xmm_f32(1.0, high);
    scalar.sse.xmm[1] = xmm_f32(2.0, [0xAB; 12]);
    scalar.code = regs2(Code::Addss_xmm_xmmm32, Register::XMM0, Register::XMM1);
    let mut packed = scalar.clone();
    packed.sse.xmm[0] = xmm_ps([1.0, 4.0, 5.0, 6.0]);
    packed.sse.xmm[1] = xmm_ps([2.0, 3.0, 7.0, 8.0]);
    packed.code = regs2(Code::Addps_xmm_xmmm128, Register::XMM0, Register::XMM1);
    let mut host = Host::spawn("add");
    check(&mut host, &scalar);
    check(&mut host, &packed);
    let scalar_xmm = emulate(&scalar).expect("addss").sse.xmm[0];
    let packed_xmm = emulate(&packed).expect("addps").sse.xmm[0];
    assert_eq!(&scalar_xmm[0..4], &3.0f32.to_le_bytes());
    assert_eq!(
        &scalar_xmm[4..],
        &high,
        "addss must leave the upper 96 bits"
    );
    assert_eq!(packed_xmm, xmm_ps([3.0, 7.0, 12.0, 14.0]));
    assert_ne!(scalar_xmm, packed_xmm);
}

#[test]
fn rounding_mode_changes_scalar_and_packed_raw_bytes() {
    let mut nearest = fresh();
    nearest.sse.mxcsr = 0x1f80;
    nearest.sse.xmm[0] = xmm_ps([1.0, 1.0, 1.0, 1.0]);
    nearest.sse.xmm[1] = xmm_ps([3.0, 3.0, 3.0, 3.0]);
    nearest.code = regs2(Code::Divss_xmm_xmmm32, Register::XMM0, Register::XMM1);
    let mut down = nearest.clone();
    down.sse.mxcsr = 0x3f80;
    let mut up = nearest.clone();
    up.sse.mxcsr = 0x5f80;
    let mut packed_near = nearest.clone();
    packed_near.code = regs2(Code::Divps_xmm_xmmm128, Register::XMM0, Register::XMM1);
    let mut packed_down = packed_near.clone();
    packed_down.sse.mxcsr = 0x3f80;
    let mut host = Host::spawn("round");
    check(&mut host, &nearest);
    check(&mut host, &down);
    check(&mut host, &up);
    check(&mut host, &packed_near);
    check(&mut host, &packed_down);
    let near = emulate(&nearest).unwrap();
    let down_obs = emulate(&down).unwrap();
    let up_obs = emulate(&up).unwrap();
    let packed_near_obs = emulate(&packed_near).unwrap();
    let packed_down_obs = emulate(&packed_down).unwrap();
    assert_ne!(
        &near.sse.xmm[0][0..4],
        &down_obs.sse.xmm[0][0..4],
        "scalar rounding must change the raw 32-bit lane"
    );
    assert_ne!(&down_obs.sse.xmm[0][0..4], &up_obs.sse.xmm[0][0..4]);
    assert_eq!(&near.sse.xmm[0][4..], &nearest.sse.xmm[0][4..]);
    assert_ne!(packed_near_obs.sse.xmm[0], packed_down_obs.sse.xmm[0]);
    assert_ne!(
        &packed_near_obs.sse.xmm[0][4..8],
        &packed_down_obs.sse.xmm[0][4..8],
        "a packed lane follows MXCSR rounding"
    );
    assert_eq!(near.sse.mxcsr & 0x20, 0x20, "precision flag");
    assert_eq!(down_obs.sse.mxcsr & 0x6000, 0x2000);
    assert_eq!(up_obs.sse.mxcsr & 0x6000, 0x4000);
}

#[test]
fn mxcsr_flags_record_invalid_and_precision() {
    let mut invalid = fresh();
    invalid.sse.xmm[0] = xmm_f32(0.0, [0; 12]);
    invalid.sse.xmm[1] = xmm_f32(0.0, [0; 12]);
    invalid.code = regs2(Code::Divss_xmm_xmmm32, Register::XMM0, Register::XMM1);
    let mut inexact = fresh();
    inexact.sse.xmm[0] = xmm_ps([1.0, 1.0, 1.0, 1.0]);
    inexact.sse.xmm[1] = xmm_ps([3.0, 3.0, 3.0, 3.0]);
    inexact.code = regs2(Code::Divps_xmm_xmmm128, Register::XMM0, Register::XMM1);
    let mut host = Host::spawn("flags");
    check(&mut host, &invalid);
    check(&mut host, &inexact);
    let invalid = emulate(&invalid).unwrap();
    let inexact = emulate(&inexact).unwrap();
    assert_eq!(invalid.sse.mxcsr & 1, 1, "invalid-operation flag");
    assert_ne!(&invalid.sse.xmm[0][0..4], &0.0f32.to_le_bytes());
    assert_eq!(inexact.sse.mxcsr & 0x20, 0x20, "precision flag");
}

#[test]
fn unmasked_precision_faults_on_linux_and_both_interpreters() {
    let mut case = fresh();
    case.sse.mxcsr = 0x0f80;
    case.sse.xmm[0] = xmm_f32(1.0, [0; 12]);
    case.sse.xmm[1] = xmm_f32(3.0, [0; 12]);
    case.code = regs2(Code::Divss_xmm_xmmm32, Register::XMM0, Register::XMM1);
    let mut host = Host::spawn("unmasked");
    expect_fault(&mut host, &case);
}

#[test]
fn prefetch_unmapped_is_a_nop_and_clflush_faults() {
    let mut prefetch = fresh();
    prefetch.regs[15] = 0x5000;
    prefetch.code = build(Code::Prefetcht0_m8, |insn| {
        insn.set_op0_kind(OpKind::Memory);
        insn.set_memory_base(Register::R15);
    });
    let before_xmm = prefetch.sse.xmm;
    let before_mxcsr = prefetch.sse.mxcsr;
    let before_regs = prefetch.regs;
    let before_data = prefetch.data.clone();
    let mut host = Host::spawn("prefetch");
    check(&mut host, &prefetch);
    let after = emulate(&prefetch).expect("prefetch");
    assert_eq!(after.sse.xmm, before_xmm);
    assert_eq!(after.sse.mxcsr, before_mxcsr);
    assert_eq!(after.regs, before_regs);
    assert_eq!(after.data, before_data);
    let mut flush = prefetch.clone();
    flush.code = build(Code::Clflush_m8, |insn| {
        insn.set_op0_kind(OpKind::Memory);
        insn.set_memory_base(Register::R15);
    });
    expect_fault(&mut host, &flush);
}

#[test]
fn misaligned_movaps_faults() {
    let mut case = fresh();
    case.regs[0] = DATA + 1;
    case.code = build(Code::Movaps_xmm_xmmm128, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::XMM0);
        insn.set_op1_kind(OpKind::Memory);
        insn.set_memory_base(Register::RAX);
    });
    let mut host = Host::spawn("align");
    expect_fault(&mut host, &case);
}

#[test]
fn gpr_moves_and_comiss_update_the_visible_state() {
    let mut movd = fresh();
    movd.regs[0] = u64::MAX;
    movd.sse.xmm[0] = xmm_f32(1.0, [0x5A; 12]);
    movd.code = build(Code::Movd_rm32_xmm, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::EAX);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(Register::XMM0);
    });
    let mut movq = fresh();
    movq.regs[0] = 0;
    movq.sse.xmm[0][0..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    movq.code = build(Code::Movq_rm64_xmm, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::RAX);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(Register::XMM0);
    });
    let mut compare = fresh();
    compare.sse.xmm[0] = xmm_f32(1.0, [0; 12]);
    compare.sse.xmm[1] = xmm_f32(2.0, [0; 12]);
    compare.code = regs2(Code::Comiss_xmm_xmmm32, Register::XMM0, Register::XMM1);
    let mut host = Host::spawn("gpr");
    check(&mut host, &movd);
    check(&mut host, &movq);
    check(&mut host, &compare);
    assert_eq!(emulate(&movd).unwrap().regs[0], 0x3f80_0000);
    assert_eq!(emulate(&movq).unwrap().regs[0], 0x1122_3344_5566_7788);
    let flags = emulate(&compare).unwrap();
    assert!(flags.rflags & 1 != 0, "comiss below sets CF");
    assert_eq!(&flags.sse.xmm[0][4..], &[0; 12]);
}

#[test]
fn high_xmm_registers_round_trip() {
    let mut case = fresh();
    case.sse.xmm[15] = xmm_f32(1.0, [0x7E; 12]);
    case.sse.xmm[14] = xmm_f32(2.0, [0x7E; 12]);
    case.code = regs2(Code::Addss_xmm_xmmm32, Register::XMM15, Register::XMM14);
    let mut host = Host::spawn("xmm15");
    check(&mut host, &case);
    let xmm = emulate(&case).unwrap().sse.xmm[15];
    assert_eq!(&xmm[0..4], &3.0f32.to_le_bytes());
    assert_eq!(&xmm[4..], &[0x7E; 12]);
}

#[test]
fn address_forms_match_linux() {
    let mut narrow = fresh();
    narrow.regs[0] = DATA | (1 << 32);
    narrow.data[0..4].copy_from_slice(&1.0f32.to_le_bytes());
    narrow.code = build(Code::Movss_xmm_xmmm32, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::XMM0);
        insn.set_op1_kind(OpKind::Memory);
        insn.set_memory_base(Register::EAX);
    });
    let mut scaled = fresh();
    scaled.regs[0] = (DATA + 0x40) | (1 << 32);
    scaled.regs[1] = 0x10 | (1 << 32);
    let off = 0x40 + 0x10 * 4 + 8;
    scaled.data[off..off + 4].copy_from_slice(&2.0f32.to_le_bytes());
    scaled.code = build(Code::Movss_xmm_xmmm32, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::XMM0);
        insn.set_op1_kind(OpKind::Memory);
        insn.set_memory_base(Register::EAX);
        insn.set_memory_index(Register::ECX);
        insn.set_memory_index_scale(4);
        insn.set_memory_displ_size(1);
        insn.set_memory_displacement64(8);
    });
    let mut rip = fresh();
    rip.code = build(Code::Movss_xmm_xmmm32, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::XMM0);
        insn.set_op1_kind(OpKind::Memory);
        insn.set_memory_base(Register::RIP);
        insn.set_memory_displ_size(4);
        insn.set_memory_displacement64(DATA);
    });
    rip.data[0..4].copy_from_slice(&1.0f32.to_le_bytes());
    let mut host = Host::spawn("addr");
    check(&mut host, &narrow);
    check(&mut host, &scaled);
    check(&mut host, &rip);
    assert_eq!(
        &emulate(&narrow).unwrap().sse.xmm[0][0..4],
        &1.0f32.to_le_bytes()
    );
    assert_eq!(
        &emulate(&scaled).unwrap().sse.xmm[0][0..4],
        &2.0f32.to_le_bytes()
    );
}

#[test]
fn ldmxcsr_and_stmxcsr_move_the_control_register() {
    let mut load = fresh();
    load.data[0..4].copy_from_slice(&0x3f80u32.to_le_bytes());
    load.code = build(Code::Ldmxcsr_m32, |insn| {
        insn.set_op0_kind(OpKind::Memory);
        insn.set_memory_base(Register::R15);
    });
    let mut store = fresh();
    store.sse.mxcsr = 0x5f80 | 0x20;
    store.code = build(Code::Stmxcsr_m32, |insn| {
        insn.set_op0_kind(OpKind::Memory);
        insn.set_memory_base(Register::R15);
    });
    let mut host = Host::spawn("mxcsr");
    check(&mut host, &load);
    check(&mut host, &store);
    assert_eq!(emulate(&load).unwrap().sse.mxcsr, 0x3f80);
    let stored = emulate(&store).unwrap();
    assert_eq!(&stored.data[0..4], &(0x5f80u32 | 0x20).to_le_bytes());
}

#[test]
fn mixed_integer_and_sse_block_matches_linux() {
    let mut case = fresh();
    let mut code = vec![0xB8];
    code.extend_from_slice(&0x3f80_0000u32.to_le_bytes());
    code.extend(build(Code::Movd_xmm_rm32, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::XMM0);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(Register::EAX);
    }));
    code.extend_from_slice(&[0xB8]);
    code.extend_from_slice(&0x4000_0000u32.to_le_bytes());
    code.extend(build(Code::Movd_xmm_rm32, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::XMM1);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(Register::EAX);
    }));
    code.extend(regs2(
        Code::Addss_xmm_xmmm32,
        Register::XMM0,
        Register::XMM1,
    ));
    code.extend(build(Code::Movd_rm32_xmm, |insn| {
        insn.set_op0_kind(OpKind::Register);
        insn.set_op0_register(Register::EAX);
        insn.set_op1_kind(OpKind::Register);
        insn.set_op1_register(Register::XMM0);
    }));
    case.code = code;
    let mut host = Host::spawn("mixed");
    check(&mut host, &case);
    let got = emulate(&case).unwrap();
    assert_eq!(got.regs[0], 0x4040_0000);
    assert_eq!(&got.sse.xmm[0][0..4], &3.0f32.to_le_bytes());
}

#[test]
fn every_l3_mnemonic_matches_linux() {
    let mut host = Host::spawn("census");
    let mut matched = 0usize;
    for mnemonic in Mnemonic::values() {
        matched += census_mnemonic(&mut host, mnemonic);
    }
    assert!(matched > 40, "census matched only {matched} mnemonics");
}

fn census_mnemonic(host: &mut Host, mnemonic: Mnemonic) -> usize {
    let row = census::entry(mnemonic);
    if row.group != Group::L3Sse || row.status != Status::Lift {
        return 0;
    }
    assert!(row.proven, "{mnemonic:?}");
    let mut reasons = Vec::new();
    for code in Code::values() {
        if code == Code::INVALID || code.mnemonic() != mnemonic || code.is_privileged() {
            continue;
        }
        if census_code(host, mnemonic, code, &mut reasons, false) {
            return 1;
        }
    }
    panic!("{mnemonic:?}: {}", reasons.join(" | "));
}

fn census_code(
    host: &mut Host,
    mnemonic: Mnemonic,
    code: Code,
    reasons: &mut Vec<String>,
    vex: bool,
) -> bool {
    let bytes = match encode_for(code, vex) {
        Ok(bytes) => bytes,
        Err(err) => {
            reasons.push(format!("{code:?} {err}"));
            return false;
        }
    };
    let mut case = fresh();
    case.code = bytes;
    match host.roundtrip(&case) {
        Err(err) => census_fault(host, mnemonic, code, &case, &err, reasons),
        Ok(linux) => {
            agree(mnemonic, &case, &linux);
            true
        }
    }
}

fn census_fault(
    host: &mut Host,
    mnemonic: Mnemonic,
    code: Code,
    case: &Case,
    err: &str,
    reasons: &mut Vec<String>,
) -> bool {
    let signal = signal_of(err);
    reasons.push(format!("{code:?} sig={signal:?} {}", hex(&case.code)));
    *host = Host::spawn("census");
    if matches!(signal, Some(4 | 7 | 8 | 11)) {
        let vm = emulate(case);
        let ir = emulate_ir(case);
        assert!(
            vm.is_err() && ir.is_err(),
            "{mnemonic:?} {code:?} retired after linux fault {err}"
        );
        return false;
    }
    panic!("{mnemonic:?} {code:?}: {err}");
}

fn agree(mnemonic: Mnemonic, case: &Case, linux: &Observed) {
    let vm =
        emulate(case).unwrap_or_else(|err| panic!("{mnemonic:?} emu {err}\n{}", hex(&case.code)));
    let ir =
        emulate_ir(case).unwrap_or_else(|err| panic!("{mnemonic:?} ir {err}\n{}", hex(&case.code)));
    let text = format!("{mnemonic:?} {}", render(&case.code));
    assert_same(&vm, linux, &text);
    assert_same(&ir, linux, &text);
}

fn encode_for(code: Code, vex: bool) -> std::result::Result<Vec<u8>, String> {
    let info = code.op_code();
    if !allowed_encoding(info.encoding(), vex) {
        return Err("encoding".into());
    }
    if !info.is_available_in_mode(64) {
        return Err("not long mode".into());
    }
    if crate::sse::claim::code_is_wide(code) {
        return Err("wide vector".into());
    }
    let mut errors = Vec::new();
    for memory in [false, true] {
        match fill_code(code, memory) {
            Ok(bytes) => return Ok(bytes),
            Err(err) => errors.push(err),
        }
    }
    Err(errors.join("; "))
}

fn allowed_encoding(encoding: iced_x86::EncodingKind, vex: bool) -> bool {
    encoding == iced_x86::EncodingKind::Legacy || (vex && encoding == iced_x86::EncodingKind::VEX)
}

fn fill_code(code: Code, memory: bool) -> std::result::Result<Vec<u8>, String> {
    let mut insn = Instruction::default();
    insn.set_code(code);
    if code.op_code().encoding() == iced_x86::EncodingKind::EVEX && evex_needs_mask(code) {
        insn.set_op_mask(Register::K1);
    }
    let info = code.op_code();
    for index in 0..info.op_count() {
        fill_operand(&mut insn, index, info.op_kind(index), memory)?;
    }
    let mut encoder = Encoder::new(64);
    encoder
        .encode(&insn, GUEST)
        .map_err(|err| err.to_string())?;
    let buf = encoder.take_buffer();
    if buf.is_empty() || buf.len() > 15 {
        return Err("empty".into());
    }
    Ok(buf)
}

fn fill_operand(
    insn: &mut Instruction,
    index: u32,
    kind: OpCodeOperandKind,
    memory: bool,
) -> std::result::Result<(), String> {
    match kind {
        OpCodeOperandKind::None => Ok(()),
        OpCodeOperandKind::mem | OpCodeOperandKind::mem_offs => fill_mem_only(insn, index, memory),
        OpCodeOperandKind::seg_rDI => fill_rdi(insn, index, memory),
        OpCodeOperandKind::xmm_or_mem
        | OpCodeOperandKind::ymm_or_mem
        | OpCodeOperandKind::zmm_or_mem
        | OpCodeOperandKind::k_or_mem
        | OpCodeOperandKind::mm_or_mem
        | OpCodeOperandKind::r32_or_mem
        | OpCodeOperandKind::r64_or_mem
        | OpCodeOperandKind::r16_or_mem
        | OpCodeOperandKind::r8_or_mem => fill_rm(insn, index, kind, memory),
        OpCodeOperandKind::mem_vsib32x
        | OpCodeOperandKind::mem_vsib32y
        | OpCodeOperandKind::mem_vsib32z
        | OpCodeOperandKind::mem_vsib64x
        | OpCodeOperandKind::mem_vsib64y
        | OpCodeOperandKind::mem_vsib64z => fill_vsib(insn, index, kind, memory),
        OpCodeOperandKind::imm8
        | OpCodeOperandKind::imm8_const_1
        | OpCodeOperandKind::imm8sex16
        | OpCodeOperandKind::imm8sex32
        | OpCodeOperandKind::imm8sex64
        | OpCodeOperandKind::imm16
        | OpCodeOperandKind::imm32
        | OpCodeOperandKind::imm32sex64 => fill_imm(insn, index, kind),
        other => fill_fixed(insn, index, other),
    }
}

fn fill_fixed(
    insn: &mut Instruction,
    index: u32,
    kind: OpCodeOperandKind,
) -> std::result::Result<(), String> {
    let reg = fixed_reg(kind, index)?;
    set_reg(insn, index, reg)
}

fn fixed_reg(kind: OpCodeOperandKind, index: u32) -> std::result::Result<Register, String> {
    let xmm = xmm_at(index);
    let mm = if index == 0 {
        Register::MM0
    } else {
        Register::MM1
    };
    match kind {
        OpCodeOperandKind::xmm_reg
        | OpCodeOperandKind::xmm_rm
        | OpCodeOperandKind::xmm_vvvv
        | OpCodeOperandKind::xmm_is4
        | OpCodeOperandKind::xmm_is5 => Ok(xmm),
        OpCodeOperandKind::ymm_reg
        | OpCodeOperandKind::ymm_rm
        | OpCodeOperandKind::ymm_vvvv
        | OpCodeOperandKind::ymm_is4
        | OpCodeOperandKind::ymm_is5 => Ok(ymm_at(index)),
        OpCodeOperandKind::zmm_reg | OpCodeOperandKind::zmm_rm | OpCodeOperandKind::zmm_vvvv => {
            Ok(zmm_at(index))
        }
        OpCodeOperandKind::zmmp3_vvvv => Ok(Register::ZMM3),
        OpCodeOperandKind::xmmp3_vvvv => Ok(Register::XMM3),
        OpCodeOperandKind::k_reg | OpCodeOperandKind::k_rm | OpCodeOperandKind::k_vvvv => {
            Ok(k_at(index))
        }
        OpCodeOperandKind::kp1_reg => Ok(Register::K1),
        OpCodeOperandKind::mm_reg | OpCodeOperandKind::mm_rm => Ok(mm),
        OpCodeOperandKind::r32_reg | OpCodeOperandKind::r32_rm | OpCodeOperandKind::r32_opcode => {
            Ok(Register::EAX)
        }
        OpCodeOperandKind::r64_reg | OpCodeOperandKind::r64_rm | OpCodeOperandKind::r64_opcode => {
            Ok(Register::RAX)
        }
        OpCodeOperandKind::r16_reg | OpCodeOperandKind::r16_rm | OpCodeOperandKind::r16_opcode => {
            Ok(Register::AX)
        }
        OpCodeOperandKind::r32_vvvv => Ok(Register::ECX),
        OpCodeOperandKind::r64_vvvv => Ok(Register::RCX),
        OpCodeOperandKind::eax => Ok(Register::EAX),
        OpCodeOperandKind::rax => Ok(Register::RAX),
        OpCodeOperandKind::ax => Ok(Register::AX),
        OpCodeOperandKind::al => Ok(Register::AL),
        other => Err(format!("operand {other:?}")),
    }
}

fn xmm_at(index: u32) -> Register {
    match index {
        0 => Register::XMM0,
        1 => Register::XMM1,
        2 => Register::XMM2,
        _ => Register::XMM3,
    }
}

fn ymm_at(index: u32) -> Register {
    match index {
        0 => Register::YMM0,
        1 => Register::YMM1,
        2 => Register::YMM2,
        _ => Register::YMM3,
    }
}

fn zmm_at(index: u32) -> Register {
    match index {
        0 => Register::ZMM0,
        1 => Register::ZMM1,
        2 => Register::ZMM2,
        _ => Register::ZMM16,
    }
}

fn k_at(index: u32) -> Register {
    match index {
        0 => Register::K1,
        1 => Register::K2,
        2 => Register::K3,
        _ => Register::K4,
    }
}

fn fill_rm(
    insn: &mut Instruction,
    index: u32,
    kind: OpCodeOperandKind,
    memory: bool,
) -> std::result::Result<(), String> {
    let reg = match kind {
        OpCodeOperandKind::xmm_or_mem => xmm_at(index),
        OpCodeOperandKind::ymm_or_mem => ymm_at(index),
        OpCodeOperandKind::zmm_or_mem => zmm_at(index),
        OpCodeOperandKind::k_or_mem => k_at(index),
        OpCodeOperandKind::mm_or_mem => {
            if index == 0 {
                Register::MM0
            } else {
                Register::MM1
            }
        }
        OpCodeOperandKind::r32_or_mem => Register::EAX,
        OpCodeOperandKind::r64_or_mem => Register::RAX,
        OpCodeOperandKind::r16_or_mem => Register::AX,
        OpCodeOperandKind::r8_or_mem => Register::AL,
        other => return Err(format!("operand {other:?}")),
    };
    if memory {
        set_mem(insn, index)
    } else {
        set_reg(insn, index, reg)
    }
}

fn fill_vsib(
    insn: &mut Instruction,
    index: u32,
    kind: OpCodeOperandKind,
    memory: bool,
) -> std::result::Result<(), String> {
    if !memory {
        return Err("needs vsib".into());
    }
    insn.try_set_op_kind(index, OpKind::Memory)
        .map_err(|err| err.to_string())?;
    let idx = match kind {
        OpCodeOperandKind::mem_vsib32z | OpCodeOperandKind::mem_vsib64z => Register::ZMM4,
        OpCodeOperandKind::mem_vsib32y | OpCodeOperandKind::mem_vsib64y => Register::YMM4,
        _ => Register::XMM4,
    };
    insn.set_memory_base(Register::R15);
    insn.set_memory_index(idx);
    insn.set_memory_index_scale(1);
    insn.set_memory_displ_size(0);
    insn.set_memory_displacement64(0);
    Ok(())
}

fn fill_mem_only(
    insn: &mut Instruction,
    index: u32,
    memory: bool,
) -> std::result::Result<(), String> {
    if !memory {
        return Err("needs memory".into());
    }
    set_mem(insn, index)
}

fn fill_rdi(insn: &mut Instruction, index: u32, memory: bool) -> std::result::Result<(), String> {
    if !memory {
        return Err("needs memory".into());
    }
    insn.try_set_op_kind(index, OpKind::MemorySegRDI)
        .map_err(|err| err.to_string())
}

fn fill_imm(
    insn: &mut Instruction,
    index: u32,
    kind: OpCodeOperandKind,
) -> std::result::Result<(), String> {
    let fail = |err: iced_x86::IcedError| err.to_string();
    match kind {
        OpCodeOperandKind::imm8 | OpCodeOperandKind::imm8_const_1 => {
            insn.try_set_op_kind(index, OpKind::Immediate8)
                .map_err(fail)?;
            insn.set_immediate8(1);
        }
        OpCodeOperandKind::imm8sex16 => {
            insn.try_set_op_kind(index, OpKind::Immediate8to16)
                .map_err(fail)?;
            insn.set_immediate8to16(1);
        }
        OpCodeOperandKind::imm8sex32 => {
            insn.try_set_op_kind(index, OpKind::Immediate8to32)
                .map_err(fail)?;
            insn.set_immediate8to32(1);
        }
        OpCodeOperandKind::imm8sex64 => {
            insn.try_set_op_kind(index, OpKind::Immediate8to64)
                .map_err(fail)?;
            insn.set_immediate8to64(1);
        }
        OpCodeOperandKind::imm16 => {
            insn.try_set_op_kind(index, OpKind::Immediate16)
                .map_err(fail)?;
            insn.set_immediate16(1);
        }
        OpCodeOperandKind::imm32 => {
            insn.try_set_op_kind(index, OpKind::Immediate32)
                .map_err(fail)?;
            insn.set_immediate32(1);
        }
        OpCodeOperandKind::imm32sex64 => {
            insn.try_set_op_kind(index, OpKind::Immediate32to64)
                .map_err(fail)?;
            insn.set_immediate32to64(1);
        }
        OpCodeOperandKind::imm64 => set_imm64(insn, index)?,
        other => return Err(format!("operand {other:?}")),
    }
    Ok(())
}

fn set_imm64(insn: &mut Instruction, index: u32) -> std::result::Result<(), String> {
    insn.try_set_op_kind(index, OpKind::Immediate64)
        .map_err(|err| err.to_string())?;
    insn.set_immediate64(1);
    Ok(())
}

fn set_reg(
    insn: &mut Instruction,
    index: u32,
    register: Register,
) -> std::result::Result<(), String> {
    insn.try_set_op_kind(index, OpKind::Register)
        .map_err(|err| err.to_string())?;
    insn.set_op_register(index, register);
    Ok(())
}

fn set_mem(insn: &mut Instruction, index: u32) -> std::result::Result<(), String> {
    insn.try_set_op_kind(index, OpKind::Memory)
        .map_err(|err| err.to_string())?;
    insn.set_memory_base(Register::R15);
    insn.set_memory_index(Register::None);
    insn.set_memory_index_scale(1);
    insn.set_memory_displ_size(0);
    insn.set_memory_displacement64(0);
    Ok(())
}

fn encode_avx(code: Code) -> std::result::Result<Vec<u8>, String> {
    let info = code.op_code();
    if info.encoding() != iced_x86::EncodingKind::VEX {
        return Err("encoding".into());
    }
    if !info.is_available_in_mode(64) {
        return Err("not long mode".into());
    }
    if avx_forbidden(code) {
        return Err("wide vector".into());
    }
    let mut errors = Vec::new();
    for memory in [false, true] {
        match fill_code(code, memory) {
            Ok(bytes) => return Ok(bytes),
            Err(err) => errors.push(err),
        }
    }
    Err(errors.join("; "))
}

fn evex_needs_mask(code: Code) -> bool {
    let name = format!("{code:?}");
    name.contains("vm32") || name.contains("vm64")
}

fn encode_evex(code: Code) -> std::result::Result<Vec<u8>, String> {
    let info = code.op_code();
    if !matches!(
        info.encoding(),
        iced_x86::EncodingKind::EVEX | iced_x86::EncodingKind::VEX
    ) {
        return Err("encoding".into());
    }
    if !info.is_available_in_mode(64) || crate::isa::encoding_outside_user_x64(code) {
        return Err("not long mode".into());
    }
    let mut errors = Vec::new();
    for memory in [false, true] {
        match fill_code(code, memory) {
            Ok(bytes) => return Ok(bytes),
            Err(err) => errors.push(err),
        }
    }
    Err(errors.join("; "))
}

/// Lower ranks are proved first: ZMM register, ZMM memory, opmask, then narrow.
pub(super) fn wide_rank(code: Code) -> u8 {
    let info = code.op_code();
    let mut best = 4u8;
    let mut mem_only = false;
    for index in 0..info.op_count() {
        let name = format!("{:?}", info.op_kind(index));
        let head = name.split('_').next().unwrap_or("");
        let score = if head == "zmm" || name.contains("vsib32z") || name.contains("vsib64z") {
            0
        } else if head == "k" || head == "kp1" {
            2
        } else {
            4
        };
        best = best.min(score);
        if head == "mem" {
            mem_only = true;
        }
    }
    best + u8::from(mem_only && best < 4)
}

fn avx_forbidden(code: Code) -> bool {
    let info = code.op_code();
    (0..info.op_count()).any(|index| {
        let name = format!("{:?}", info.op_kind(index));
        let head = name.split('_').next().unwrap_or("");
        matches!(head, "zmm" | "tmm" | "k")
    })
}

#[path = "diff_l4.rs"]
mod l4_proof;

#[path = "diff_l5.rs"]
mod l5_proof;

#[path = "diff_l6.rs"]
mod l6_proof;

impl Clone for Case {
    fn clone(&self) -> Self {
        Self {
            code: self.code.clone(),
            regs: self.regs,
            rflags: self.rflags,
            x87: self.x87,
            sse: self.sse,
            data: self.data.clone(),
        }
    }
}
