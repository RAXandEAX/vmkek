//! Integer blocks against this Linux process. One long-lived RWX ELF executes
//! each guest block and reports the registers, flags, and data page.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use iced_x86::{
    BlockEncoderOptions, Code, Decoder, DecoderOptions, Encoder, Formatter, Instruction,
    IntelFormatter, MemoryOperand, OpKind, Register, RepPrefixKind,
};

use crate::error::{msg, Result};
use crate::flags::Flags;
use crate::ir::MemIo;

use super::{apply, classify, Class, Cpu, Fate, Touch};

const ENTRY: u64 = 0x400100;
const GUEST: u64 = 0x401000;
const DATA: u64 = 0x402000;
const SAVE: u64 = 0x403000;
const SCRATCH: u64 = 0x403200;
const STACK: u64 = 0x404f00;
const DATA_LEN: usize = 0x1000;
const MAX_CODE: usize = 128;
const RESULT: usize = 136 + DATA_LEN;
const MAGIC: u64 = 0x1122_3344_5566_7788;
const CASES: usize = 10_000;

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

// SAFETY: вызов локальный, один PollFd на стеке, таймаут 5 с.
unsafe extern "C" {
    fn poll(fds: *mut PollFd, nfds: usize, timeout: i32) -> i32;
}

struct Case {
    code: Vec<u8>,
    regs: [u64; 16],
    rflags: u64,
    data: Vec<u8>,
}

#[derive(Debug)]
struct Observed {
    regs: [u64; 16],
    rflags: u64,
    data: Vec<u8>,
}

#[derive(Debug)]
struct Emulated {
    regs: [u64; 16],
    rflags: u64,
    data: Vec<u8>,
    defined: Defined,
}

#[derive(Clone, Copy, Debug)]
struct Defined {
    cf: bool,
    pf: bool,
    af: bool,
    zf: bool,
    sf: bool,
    of: bool,
    df: bool,
}

impl Defined {
    fn all() -> Self {
        Self {
            cf: true,
            pf: true,
            af: true,
            zf: true,
            sf: true,
            of: true,
            df: true,
        }
    }

    fn update(&mut self, touch: Touch) {
        self.cf = fate(self.cf, touch.cf);
        self.pf = fate(self.pf, touch.pf);
        self.af = fate(self.af, touch.af);
        self.zf = fate(self.zf, touch.zf);
        self.sf = fate(self.sf, touch.sf);
        self.of = fate(self.of, touch.of);
        self.df = fate(self.df, touch.df);
    }
}

fn fate(previous: bool, next: Fate) -> bool {
    match next {
        Fate::Keep => previous,
        Fate::Write => true,
        Fate::Undef => false,
    }
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

fn split(bits: u64) -> (Flags, bool, bool) {
    (
        Flags::unpack(bits),
        bits & (1 << 4) != 0,
        bits & (1 << 10) != 0,
    )
}

struct Page {
    bytes: Vec<u8>,
}

fn page_offset(addr: u64, len: usize) -> Result<usize> {
    let start = addr
        .checked_sub(DATA)
        .ok_or_else(|| msg(format!("unmapped {addr:#x}")))?;
    let start = usize::try_from(start).map_err(|_| msg("address"))?;
    let end = start.checked_add(len).ok_or_else(|| msg("length"))?;
    if end > DATA_LEN {
        return Err(msg(format!("unmapped {addr:#x}+{len}")));
    }
    Ok(start)
}

impl MemIo for Page {
    fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let start = page_offset(addr, len)?;
        Ok(self.bytes[start..start + len].to_vec())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        let start = page_offset(addr, data.len())?;
        self.bytes[start..start + data.len()].copy_from_slice(data);
        Ok(())
    }
}

fn harness_bytes() -> Vec<u8> {
    use iced_x86::code_asm::{
        byte_ptr, dword_ptr, eax, ecx, edi, qword_ptr, r10, r11, r12, r12d, r13, r14, r15, r8, r9,
        rax, rbp, rbx, rcx, rdi, rdx, rsi, rsp, CodeAssembler,
    };
    let mut asm = CodeAssembler::new(64).expect("assembler");
    asm.set_prefer_short_branch(false);
    let mut top = asm.create_label();
    let mut read_exact = asm.create_label();
    let mut read_done = asm.create_label();
    let mut fail = asm.create_label();
    let mut done = asm.create_label();
    let mut epilogue = asm.create_label();
    let asm_ok = |result: std::result::Result<(), iced_x86::IcedError>| {
        result.expect("harness instruction");
    };
    let regs = [
        rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    ];
    let stored = regs;
    asm_ok(asm.mov(rsp, STACK));
    asm_ok(asm.set_label(&mut top));
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
    asm_ok(asm.mov(rsi, DATA));
    asm_ok(asm.mov(rdx, DATA_LEN as u64));
    asm_ok(asm.call(read_exact));
    asm_ok(asm.mov(rax, GUEST));
    asm_ok(asm.add(rax, r12));
    asm_ok(asm.mov(byte_ptr(rax), 0xE9i32));
    asm_ok(asm.mov(rcx, MAGIC));
    asm_ok(asm.lea(rdx, qword_ptr(rax + 5i32)));
    asm_ok(asm.sub(rcx, rdx));
    asm_ok(asm.mov(dword_ptr(rax + 1i32), ecx));
    asm_ok(asm.mov(rsp, STACK));
    asm_ok(asm.mov(rax, qword_ptr(r15 + 128i32)));
    asm_ok(asm.push(rax));
    asm_ok(asm.popfq());
    for (index, reg) in regs.into_iter().enumerate() {
        if index == 4 || index == 15 {
            continue;
        }
        asm_ok(asm.mov(reg, qword_ptr(r15 + (index * 8) as i32)));
    }
    asm_ok(asm.mov(rsp, qword_ptr(r15 + 32i32)));
    asm_ok(asm.mov(r15, qword_ptr(r15 + 120i32)));
    asm_ok(asm.jmp(GUEST));
    asm_ok(asm.set_label(&mut epilogue));
    asm_ok(asm.db(&[0xA6; 7]));
    asm_ok(asm.mov(r15, SAVE));
    for (index, reg) in stored.into_iter().enumerate() {
        if index == 4 || index == 15 {
            continue;
        }
        asm_ok(asm.mov(qword_ptr(r15 + (index * 8) as i32), reg));
    }
    asm_ok(asm.db(&[0xA7; 7]));
    asm_ok(asm.mov(qword_ptr(r15 + 120i32), rax));
    asm_ok(asm.mov(rax, rsp));
    asm_ok(asm.mov(qword_ptr(r15 + 32i32), rax));
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
    asm_ok(asm.mov(rsi, DATA));
    asm_ok(asm.mov(rdx, DATA_LEN as u64));
    asm_ok(asm.syscall());
    asm_ok(asm.jmp(top));
    asm_ok(asm.set_label(&mut read_exact));
    asm_ok(asm.test(rdx, rdx));
    asm_ok(asm.jz(read_done));
    asm_ok(asm.xor(eax, eax));
    asm_ok(asm.xor(edi, edi));
    asm_ok(asm.syscall());
    asm_ok(asm.cmp(rax, 1i32));
    asm_ok(asm.jl(fail));
    asm_ok(asm.add(rsi, rax));
    asm_ok(asm.sub(rdx, rax));
    asm_ok(asm.jmp(read_exact));
    asm_ok(asm.set_label(&mut read_done));
    asm_ok(asm.ret());
    asm_ok(asm.set_label(&mut fail));
    asm_ok(asm.mov(eax, 60i32));
    asm_ok(asm.mov(edi, 3i32));
    asm_ok(asm.syscall());
    asm_ok(asm.set_label(&mut done));
    asm_ok(asm.mov(eax, 60i32));
    asm_ok(asm.xor(edi, edi));
    asm_ok(asm.syscall());
    let result = asm
        .assemble_options(ENTRY, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .expect("assemble harness");
    let epi = result.label_ip(&epilogue).expect("epilogue address");
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
    file[ph + 40..ph + 48].copy_from_slice(&0x5000u64.to_le_bytes());
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
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("l1-carrier-{tag}"));
        std::fs::create_dir_all(path.parent().expect("target parent")).expect("target dir");
        std::fs::write(&path, elf_image(&harness_bytes()))
            .unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let mut child = Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|err| panic!("spawn {}: {err}", path.display()));
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
        stdin.write_all(&(u32::try_from(case.code.len()).expect("len")).to_le_bytes())?;
        stdin.write_all(&case.code)?;
        for reg in case.regs {
            stdin.write_all(&reg.to_le_bytes())?;
        }
        stdin.write_all(&case.rflags.to_le_bytes())?;
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

fn read_full(source: &mut (impl Read + AsRawFd), buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let mut poll_fd = PollFd {
            fd: source.as_raw_fd(),
            events: 1,
            revents: 0,
        };
        loop {
            // SAFETY: вызов локальный, один PollFd на стеке, таймаут 5 с.
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
    let raw: [u8; 8] = buf[128..136].try_into().expect("flags");
    Observed {
        regs,
        rflags: u64::from_le_bytes(raw),
        data: buf[136..].to_vec(),
    }
}

fn emulate(case: &Case) -> std::result::Result<Emulated, String> {
    let (flags, af, df) = split(case.rflags);
    let mut cpu = Cpu {
        regs: case.regs,
        flags,
        af,
        df,
        gs: 0,
    };
    let mut page = Page {
        bytes: case.data.clone(),
    };
    let mut defined = Defined::all();
    let mut decoder = Decoder::with_ip(64, &case.code, GUEST, DecoderOptions::NONE);
    let end = GUEST + case.code.len() as u64;
    while decoder.ip() < end {
        let insn = decoder.decode();
        if insn.is_invalid() || insn.len() == 0 {
            return Err(format!("invalid encoding {}", hex(&case.code)));
        }
        match apply(&mut cpu, &mut page, &insn) {
            Ok(Some(touch)) => defined.update(touch),
            Ok(None) => return Err(format!("outside the integer group: {:?}", insn.mnemonic())),
            Err(err) => return Err(err.to_string()),
        }
    }
    Ok(Emulated {
        regs: cpu.regs,
        rflags: join(cpu.flags, cpu.af, cpu.df),
        data: page.bytes,
        defined,
    })
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

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn first_diff(left: &[u8], right: &[u8]) -> Option<(usize, u8, u8)> {
    left.iter()
        .zip(right)
        .enumerate()
        .find(|(_, (lhs, rhs))| lhs != rhs)
        .map(|(index, (lhs, rhs))| (index, *lhs, *rhs))
}

fn check(host: &mut Host, index: usize, case: &Case) {
    let text = render(&case.code);
    let emulated = emulate(case).unwrap_or_else(|err| panic!("case {index} emu: {err}\n{text}"));
    let actual = host
        .roundtrip(case)
        .unwrap_or_else(|err| panic!("case {index} linux: {err}\n{text}\n{}", hex(&case.code)));
    assert_eq!(
        emulated.regs,
        actual.regs,
        "case {index} regs {text}\n{}",
        hex(&case.code)
    );
    if let Some((at, lhs, rhs)) = first_diff(&emulated.data, &actual.data) {
        panic!("case {index} data[{at:#x}] emu={lhs:#x} linux={rhs:#x} {text}");
    }
    let (ef, eaf, edf) = split(emulated.rflags);
    let (cf, caf, cdf) = split(actual.rflags);
    let defined = emulated.defined;
    assert_bit(index, "cf", defined.cf, ef.cf, cf.cf, &text);
    assert_bit(index, "pf", defined.pf, ef.pf, cf.pf, &text);
    assert_bit(index, "zf", defined.zf, ef.zf, cf.zf, &text);
    assert_bit(index, "sf", defined.sf, ef.sf, cf.sf, &text);
    assert_bit(index, "of", defined.of, ef.of, cf.of, &text);
    assert_bit(index, "af", defined.af, eaf, caf, &text);
    assert_bit(index, "df", defined.df, edf, cdf, &text);
}

fn assert_bit(index: usize, name: &str, defined: bool, left: bool, right: bool, text: &str) {
    if defined {
        assert_eq!(left, right, "case {index} {name} {text}");
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn idx(&mut self, len: usize) -> usize {
        (self.next() as usize) % len
    }

    fn bit(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

struct State {
    regs: [u64; 16],
    rflags: u64,
    data: Vec<u8>,
}

const SAMPLES: [u64; 12] = [
    0,
    1,
    0x7f,
    0x80,
    0xff,
    0x7fff,
    0x8000,
    0xffff,
    0x7fff_ffff,
    0x8000_0000,
    u64::MAX,
    0x0123_4567_89ab_cdef,
];

const R64: [Register; 12] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RBP,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
];
const R32: [Register; 12] = [
    Register::EAX,
    Register::ECX,
    Register::EDX,
    Register::EBX,
    Register::EBP,
    Register::R8D,
    Register::R9D,
    Register::R10D,
    Register::R11D,
    Register::R12D,
    Register::R13D,
    Register::R14D,
];
const R16: [Register; 12] = [
    Register::AX,
    Register::CX,
    Register::DX,
    Register::BX,
    Register::BP,
    Register::R8W,
    Register::R9W,
    Register::R10W,
    Register::R11W,
    Register::R12W,
    Register::R13W,
    Register::R14W,
];
const R8S: [Register; 12] = [
    Register::AL,
    Register::CL,
    Register::DL,
    Register::BL,
    Register::BPL,
    Register::R8L,
    Register::R9L,
    Register::R10L,
    Register::R11L,
    Register::R12L,
    Register::R13L,
    Register::R14L,
];

fn part(index: usize, bits: u32) -> Register {
    match bits {
        8 => R8S[index],
        16 => R16[index],
        32 => R32[index],
        _ => R64[index],
    }
}

fn pick(rng: &mut Rng, bits: u32) -> Register {
    let index = rng.idx(R64.len());
    if bits == 8 && index < 4 && rng.bit() {
        return [Register::AH, Register::CH, Register::DH, Register::BH][index];
    }
    part(index, bits)
}

fn width(rng: &mut Rng) -> u32 {
    [8, 16, 32, 64][rng.idx(4)]
}

fn windex(bits: u32) -> usize {
    match bits {
        8 => 0,
        16 => 1,
        32 => 2,
        _ => 3,
    }
}

fn disp(rng: &mut Rng) -> i64 {
    rng.idx(96) as i64 - 48
}

fn imm8(rng: &mut Rng) -> i32 {
    i32::from(rng.next() as i8)
}

fn imm16(rng: &mut Rng) -> i32 {
    i32::from(rng.next() as i16)
}

fn image(rng: &mut Rng) -> u64 {
    let mut bits = 0x202u64;
    for shift in [0, 2, 4, 6, 7, 10, 11] {
        if rng.bit() {
            bits |= 1 << shift;
        }
    }
    bits
}

fn fresh(rng: &mut Rng) -> State {
    let mut regs = [0u64; 16];
    for reg in &mut regs {
        let base = SAMPLES[rng.idx(SAMPLES.len())];
        *reg = if rng.bit() {
            base
        } else {
            base ^ (rng.next() & 0xff)
        };
    }
    regs[3] = DATA + 0x100;
    regs[5] = DATA + 0x400;
    regs[6] = DATA + 0x500;
    regs[7] = DATA + 0x580;
    regs[15] = DATA + 0x800;
    regs[4] = DATA + 0xC00;
    let mix = (rng.next() & 0xff) as u8;
    let data = (0..DATA_LEN)
        .map(|index| (index as u8).wrapping_mul(17).wrapping_add(mix))
        .collect();
    State {
        regs,
        rflags: image(rng),
        data,
    }
}

fn plant(state: &mut State, at: usize, bytes: &[u8]) {
    state.data[at..at + bytes.len()].copy_from_slice(bytes);
}

fn write_disp(state: &mut State, displacement: i64, bytes: &[u8]) {
    let index = usize::try_from(0x800 + displacement).expect("disp");
    plant(state, index, bytes);
}

macro_rules! codes {
    ($($name:ident),+ $(,)?) => {
        [$(Code::$name),+]
    };
}

fn built(insn: std::result::Result<Instruction, iced_x86::IcedError>) -> Instruction {
    insn.unwrap_or_else(|err| panic!("operands: {err}"))
}

fn high8(reg: Register) -> bool {
    matches!(
        reg,
        Register::AH | Register::CH | Register::DH | Register::BH
    )
}

fn low8(reg: Register) -> Register {
    match reg {
        Register::AH => Register::AL,
        Register::CH => Register::CL,
        Register::DH => Register::DL,
        Register::BH => Register::BL,
        other => other,
    }
}

fn rex_reg(reg: Register) -> bool {
    matches!(
        reg,
        Register::SPL | Register::BPL | Register::SIL | Register::DIL
    ) || reg.full_register().number() >= 8
        || reg.size() == 8
}

fn settle(a: Register, b: Register) -> (Register, Register) {
    if high8(a) && rex_reg(b) {
        (low8(a), b)
    } else if high8(b) && rex_reg(a) {
        (a, low8(b))
    } else {
        (a, b)
    }
}

fn legacy_mem(op: MemoryOperand) -> MemoryOperand {
    let mut op = op;
    let base_rex = op.base != Register::None && op.base.full_register().number() >= 8;
    let index_rex = op.index != Register::None && op.index.full_register().number() >= 8;
    if base_rex || index_rex {
        op.base = Register::RBX;
        op.index = Register::None;
        op.scale = 1;
    }
    op
}

fn reg_reg(code: Code, a: Register, b: Register) -> Instruction {
    let (a, b) = settle(a, b);
    built(Instruction::with2(code, a, b))
}

fn reg_mem(code: Code, reg: Register, mem: MemoryOperand) -> Instruction {
    let mem = if high8(reg) { legacy_mem(mem) } else { mem };
    built(Instruction::with2(code, reg, mem))
}

fn mem_reg(code: Code, mem: MemoryOperand, reg: Register) -> Instruction {
    let mem = if high8(reg) { legacy_mem(mem) } else { mem };
    built(Instruction::with2(code, mem, reg))
}

fn reg_imm(code: Code, reg: Register, imm: i32) -> Instruction {
    built(Instruction::with2(code, reg, imm))
}

fn mem_imm(code: Code, mem: MemoryOperand, imm: i32) -> Instruction {
    built(Instruction::with2(code, mem, imm))
}

fn reg_only(code: Code, reg: Register) -> Instruction {
    built(Instruction::with1(code, reg))
}

fn mem_only(code: Code, mem: MemoryOperand) -> Instruction {
    built(Instruction::with1(code, mem))
}

fn imm_only(code: Code, imm: i32) -> Instruction {
    built(Instruction::with1(code, imm))
}

fn reg_reg_imm(code: Code, a: Register, b: Register, imm: i32) -> Instruction {
    let (a, b) = settle(a, b);
    built(Instruction::with3(code, a, b, imm))
}

fn reg_mem_imm(code: Code, reg: Register, mem: MemoryOperand, imm: i32) -> Instruction {
    let mem = if high8(reg) { legacy_mem(mem) } else { mem };
    built(Instruction::with3(code, reg, mem, imm))
}

fn mem_reg_imm(code: Code, mem: MemoryOperand, reg: Register, imm: i32) -> Instruction {
    let mem = if high8(reg) { legacy_mem(mem) } else { mem };
    built(Instruction::with3(code, mem, reg, imm))
}

fn mem(displacement: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ_size_bcst_seg(
        Register::R15,
        displacement,
        1,
        false,
        Register::None,
    )
}

fn encode(insns: &[Instruction]) -> Vec<u8> {
    let mut encoder = Encoder::new(64);
    let mut ip = GUEST;
    for insn in insns {
        let len = encoder
            .encode(insn, ip)
            .unwrap_or_else(|err| panic!("{insn:?}: {err}"));
        ip += u64::from(u32::try_from(len).expect("len"));
    }
    let bytes = encoder.take_buffer();
    assert!(
        bytes.len() <= MAX_CODE,
        "{} bytes {}",
        bytes.len(),
        hex(&bytes)
    );
    bytes
}

fn build_case(rng: &mut Rng, builder: fn(&mut Rng, &mut State) -> Vec<Instruction>) -> Case {
    let mut state = fresh(rng);
    let insns = builder(rng, &mut state);
    Case {
        code: encode(&insns),
        regs: state.regs,
        rflags: state.rflags,
        data: state.data,
    }
}

fn binary(op: usize, bits: u32) -> (Code, Code, Code) {
    let index = windex(bits);
    let mr = match op {
        0 => codes!(Add_rm8_r8, Add_rm16_r16, Add_rm32_r32, Add_rm64_r64),
        1 => codes!(Adc_rm8_r8, Adc_rm16_r16, Adc_rm32_r32, Adc_rm64_r64),
        2 => codes!(Sub_rm8_r8, Sub_rm16_r16, Sub_rm32_r32, Sub_rm64_r64),
        3 => codes!(Sbb_rm8_r8, Sbb_rm16_r16, Sbb_rm32_r32, Sbb_rm64_r64),
        4 => codes!(And_rm8_r8, And_rm16_r16, And_rm32_r32, And_rm64_r64),
        5 => codes!(Or_rm8_r8, Or_rm16_r16, Or_rm32_r32, Or_rm64_r64),
        6 => codes!(Xor_rm8_r8, Xor_rm16_r16, Xor_rm32_r32, Xor_rm64_r64),
        7 => codes!(Cmp_rm8_r8, Cmp_rm16_r16, Cmp_rm32_r32, Cmp_rm64_r64),
        _ => codes!(Test_rm8_r8, Test_rm16_r16, Test_rm32_r32, Test_rm64_r64),
    };
    let rm = match op {
        0 => codes!(Add_r8_rm8, Add_r16_rm16, Add_r32_rm32, Add_r64_rm64),
        1 => codes!(Adc_r8_rm8, Adc_r16_rm16, Adc_r32_rm32, Adc_r64_rm64),
        2 => codes!(Sub_r8_rm8, Sub_r16_rm16, Sub_r32_rm32, Sub_r64_rm64),
        3 => codes!(Sbb_r8_rm8, Sbb_r16_rm16, Sbb_r32_rm32, Sbb_r64_rm64),
        4 => codes!(And_r8_rm8, And_r16_rm16, And_r32_rm32, And_r64_rm64),
        5 => codes!(Or_r8_rm8, Or_r16_rm16, Or_r32_rm32, Or_r64_rm64),
        6 => codes!(Xor_r8_rm8, Xor_r16_rm16, Xor_r32_rm32, Xor_r64_rm64),
        7 => codes!(Cmp_r8_rm8, Cmp_r16_rm16, Cmp_r32_rm32, Cmp_r64_rm64),
        _ => mr,
    };
    let imm = match op {
        0 => codes!(Add_rm8_imm8, Add_rm16_imm8, Add_rm32_imm8, Add_rm64_imm8),
        1 => codes!(Adc_rm8_imm8, Adc_rm16_imm8, Adc_rm32_imm8, Adc_rm64_imm8),
        2 => codes!(Sub_rm8_imm8, Sub_rm16_imm8, Sub_rm32_imm8, Sub_rm64_imm8),
        3 => codes!(Sbb_rm8_imm8, Sbb_rm16_imm8, Sbb_rm32_imm8, Sbb_rm64_imm8),
        4 => codes!(And_rm8_imm8, And_rm16_imm8, And_rm32_imm8, And_rm64_imm8),
        5 => codes!(Or_rm8_imm8, Or_rm16_imm8, Or_rm32_imm8, Or_rm64_imm8),
        6 => codes!(Xor_rm8_imm8, Xor_rm16_imm8, Xor_rm32_imm8, Xor_rm64_imm8),
        7 => codes!(Cmp_rm8_imm8, Cmp_rm16_imm8, Cmp_rm32_imm8, Cmp_rm64_imm8),
        _ => codes!(
            Test_rm8_imm8,
            Test_rm16_imm16,
            Test_rm32_imm32,
            Test_rm64_imm32
        ),
    };
    (mr[index], rm[index], imm[index])
}

fn alu_reg(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    let bits = width(rng);
    let (code, _, _) = binary(rng.idx(9), bits);
    vec![reg_reg(code, pick(rng, bits), pick(rng, bits))]
}

fn alu_mem(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    let op = rng.idx(9);
    let bits = width(rng);
    let (mr, rm, _) = binary(op, bits);
    let operand = mem(disp(rng));
    let reg = pick(rng, bits);
    if op == 8 || rng.bit() {
        vec![mem_reg(mr, operand, reg)]
    } else {
        vec![reg_mem(rm, reg, operand)]
    }
}

fn alu_imm(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    let op = rng.idx(9);
    let bits = width(rng);
    let (_, _, code) = binary(op, bits);
    let value = if op == 8 && bits >= 32 {
        rng.next() as i32
    } else if op == 8 && bits == 16 {
        imm16(rng)
    } else {
        imm8(rng)
    };
    if rng.bit() {
        vec![reg_imm(code, pick(rng, bits), value)]
    } else {
        vec![mem_imm(code, mem(disp(rng)), value)]
    }
}

fn unary(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    let bits = width(rng);
    let index = windex(bits);
    let table = match rng.idx(4) {
        0 => codes!(Inc_rm8, Inc_rm16, Inc_rm32, Inc_rm64),
        1 => codes!(Dec_rm8, Dec_rm16, Dec_rm32, Dec_rm64),
        2 => codes!(Neg_rm8, Neg_rm16, Neg_rm32, Neg_rm64),
        _ => codes!(Not_rm8, Not_rm16, Not_rm32, Not_rm64),
    };
    let code = table[index];
    if rng.bit() {
        vec![reg_only(code, pick(rng, bits))]
    } else {
        vec![mem_only(code, mem(disp(rng)))]
    }
}

fn shift_triple(kind: usize, bits: u32) -> [Code; 3] {
    let index = windex(bits);
    let rows: [[Code; 12]; 8] = [
        codes!(
            Shl_rm8_imm8,
            Shl_rm8_CL,
            Shl_rm8_1,
            Shl_rm16_imm8,
            Shl_rm16_CL,
            Shl_rm16_1,
            Shl_rm32_imm8,
            Shl_rm32_CL,
            Shl_rm32_1,
            Shl_rm64_imm8,
            Shl_rm64_CL,
            Shl_rm64_1
        ),
        codes!(
            Shr_rm8_imm8,
            Shr_rm8_CL,
            Shr_rm8_1,
            Shr_rm16_imm8,
            Shr_rm16_CL,
            Shr_rm16_1,
            Shr_rm32_imm8,
            Shr_rm32_CL,
            Shr_rm32_1,
            Shr_rm64_imm8,
            Shr_rm64_CL,
            Shr_rm64_1
        ),
        codes!(
            Sar_rm8_imm8,
            Sar_rm8_CL,
            Sar_rm8_1,
            Sar_rm16_imm8,
            Sar_rm16_CL,
            Sar_rm16_1,
            Sar_rm32_imm8,
            Sar_rm32_CL,
            Sar_rm32_1,
            Sar_rm64_imm8,
            Sar_rm64_CL,
            Sar_rm64_1
        ),
        codes!(
            Sal_rm8_imm8,
            Sal_rm8_CL,
            Sal_rm8_1,
            Sal_rm16_imm8,
            Sal_rm16_CL,
            Sal_rm16_1,
            Sal_rm32_imm8,
            Sal_rm32_CL,
            Sal_rm32_1,
            Sal_rm64_imm8,
            Sal_rm64_CL,
            Sal_rm64_1
        ),
        codes!(
            Rol_rm8_imm8,
            Rol_rm8_CL,
            Rol_rm8_1,
            Rol_rm16_imm8,
            Rol_rm16_CL,
            Rol_rm16_1,
            Rol_rm32_imm8,
            Rol_rm32_CL,
            Rol_rm32_1,
            Rol_rm64_imm8,
            Rol_rm64_CL,
            Rol_rm64_1
        ),
        codes!(
            Ror_rm8_imm8,
            Ror_rm8_CL,
            Ror_rm8_1,
            Ror_rm16_imm8,
            Ror_rm16_CL,
            Ror_rm16_1,
            Ror_rm32_imm8,
            Ror_rm32_CL,
            Ror_rm32_1,
            Ror_rm64_imm8,
            Ror_rm64_CL,
            Ror_rm64_1
        ),
        codes!(
            Rcl_rm8_imm8,
            Rcl_rm8_CL,
            Rcl_rm8_1,
            Rcl_rm16_imm8,
            Rcl_rm16_CL,
            Rcl_rm16_1,
            Rcl_rm32_imm8,
            Rcl_rm32_CL,
            Rcl_rm32_1,
            Rcl_rm64_imm8,
            Rcl_rm64_CL,
            Rcl_rm64_1
        ),
        codes!(
            Rcr_rm8_imm8,
            Rcr_rm8_CL,
            Rcr_rm8_1,
            Rcr_rm16_imm8,
            Rcr_rm16_CL,
            Rcr_rm16_1,
            Rcr_rm32_imm8,
            Rcr_rm32_CL,
            Rcr_rm32_1,
            Rcr_rm64_imm8,
            Rcr_rm64_CL,
            Rcr_rm64_1
        ),
    ];
    let base = index * 3;
    [rows[kind][base], rows[kind][base + 1], rows[kind][base + 2]]
}

fn shifts(rng: &mut Rng, state: &mut State) -> Vec<Instruction> {
    let bits = width(rng);
    let form = rng.idx(3);
    let [imm, cl, one] = shift_triple(rng.idx(8), bits);
    let code = [imm, cl, one][form];
    let memory = rng.bit();
    if form == 1 {
        state.regs[1] = u64::from(rng.idx(32) as u8);
    }
    let count = if bits == 64 { rng.idx(64) } else { rng.idx(32) } as i32;
    let extra = if form == 1 {
        Register::CL
    } else {
        Register::None
    };
    if memory {
        let operand = mem(disp(rng));
        if form == 0 {
            vec![mem_imm(code, operand, count)]
        } else if form == 1 {
            vec![mem_reg(code, operand, extra)]
        } else {
            vec![mem_imm(code, operand, 1)]
        }
    } else {
        let dest = pick(rng, bits);
        if form == 0 {
            vec![reg_imm(code, dest, count)]
        } else if form == 1 {
            vec![reg_reg(code, dest, extra)]
        } else {
            vec![reg_imm(code, dest, 1)]
        }
    }
}

fn double_shift(rng: &mut Rng, state: &mut State) -> Vec<Instruction> {
    let bits = [16u32, 32, 64][rng.idx(3)];
    let count = rng.idx(bits as usize) as i32;
    let use_cl = rng.bit();
    let left = rng.bit();
    let code = match (left, bits, use_cl) {
        (true, 16, false) => Code::Shld_rm16_r16_imm8,
        (true, 32, false) => Code::Shld_rm32_r32_imm8,
        (true, _, false) => Code::Shld_rm64_r64_imm8,
        (true, 16, true) => Code::Shld_rm16_r16_CL,
        (true, 32, true) => Code::Shld_rm32_r32_CL,
        (true, _, true) => Code::Shld_rm64_r64_CL,
        (false, 16, false) => Code::Shrd_rm16_r16_imm8,
        (false, 32, false) => Code::Shrd_rm32_r32_imm8,
        (false, _, false) => Code::Shrd_rm64_r64_imm8,
        (false, 16, true) => Code::Shrd_rm16_r16_CL,
        (false, 32, true) => Code::Shrd_rm32_r32_CL,
        (false, _, true) => Code::Shrd_rm64_r64_CL,
    };
    if use_cl {
        state.regs[1] = u64::from(count as u32);
    }
    let src = pick(rng, bits);
    if rng.bit() {
        let dest = pick(rng, bits);
        if use_cl {
            vec![reg_reg_imm_reg(code, dest, src)]
        } else {
            vec![reg_reg_imm(code, dest, src, count)]
        }
    } else {
        let operand = mem(disp(rng));
        if use_cl {
            vec![mem_reg_cl(code, operand, src)]
        } else {
            vec![mem_reg_imm(code, operand, src, count)]
        }
    }
}

fn reg_reg_imm_reg(code: Code, dest: Register, src: Register) -> Instruction {
    built(Instruction::with3(code, dest, src, Register::CL))
}

fn mem_reg_cl(code: Code, operand: MemoryOperand, src: Register) -> Instruction {
    built(Instruction::with3(code, operand, src, Register::CL))
}

fn moves(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    let kind = rng.idx(6);
    if kind == 0 {
        let bits = width(rng);
        let (code, _, _) = match bits {
            8 => (Code::Mov_rm8_r8, Code::Mov_r8_rm8, 0),
            16 => (Code::Mov_rm16_r16, Code::Mov_r16_rm16, 0),
            32 => (Code::Mov_rm32_r32, Code::Mov_r32_rm32, 0),
            _ => (Code::Mov_rm64_r64, Code::Mov_r64_rm64, 0),
        };
        return if rng.bit() {
            vec![reg_reg(code, pick(rng, bits), pick(rng, bits))]
        } else {
            let load = match bits {
                8 => Code::Mov_r8_rm8,
                16 => Code::Mov_r16_rm16,
                32 => Code::Mov_r32_rm32,
                _ => Code::Mov_r64_rm64,
            };
            if rng.bit() {
                vec![reg_mem(load, pick(rng, bits), mem(disp(rng)))]
            } else {
                vec![mem_reg(code, mem(disp(rng)), pick(rng, bits))]
            }
        };
    }
    if kind == 1 {
        return match rng.idx(4) {
            0 => vec![reg_imm(Code::Mov_r8_imm8, pick(rng, 8), imm8(rng))],
            1 => vec![reg_imm(Code::Mov_r16_imm16, pick(rng, 16), imm16(rng))],
            2 => vec![reg_imm(
                Code::Mov_r32_imm32,
                pick(rng, 32),
                rng.next() as i32,
            )],
            _ => vec![built(Instruction::with2(
                Code::Mov_r64_imm64,
                pick(rng, 64),
                rng.next(),
            ))],
        };
    }
    if kind == 2 {
        let code = [
            Code::Movzx_r16_rm8,
            Code::Movzx_r32_rm8,
            Code::Movzx_r64_rm8,
            Code::Movzx_r32_rm16,
            Code::Movzx_r64_rm16,
        ][rng.idx(5)];
        let (dest_bits, src_bits) = if matches!(code, Code::Movzx_r32_rm16 | Code::Movzx_r64_rm16) {
            (if code == Code::Movzx_r32_rm16 { 32 } else { 64 }, 16)
        } else if code == Code::Movzx_r16_rm8 {
            (16, 8)
        } else if code == Code::Movzx_r32_rm8 {
            (32, 8)
        } else {
            (64, 8)
        };
        return if rng.bit() {
            vec![reg_reg(code, pick(rng, dest_bits), pick(rng, src_bits))]
        } else {
            vec![reg_mem(code, pick(rng, dest_bits), mem(disp(rng)))]
        };
    }
    if kind == 3 {
        let code = [
            Code::Movsx_r16_rm8,
            Code::Movsx_r32_rm8,
            Code::Movsx_r64_rm8,
            Code::Movsx_r32_rm16,
            Code::Movsx_r64_rm16,
            Code::Movsxd_r64_rm32,
        ][rng.idx(6)];
        let (dest_bits, src_bits) = match code {
            Code::Movsx_r16_rm8 => (16, 8),
            Code::Movsx_r32_rm8 => (32, 8),
            Code::Movsx_r64_rm8 => (64, 8),
            Code::Movsx_r32_rm16 => (32, 16),
            Code::Movsx_r64_rm16 => (64, 16),
            _ => (64, 32),
        };
        return if rng.bit() {
            vec![reg_reg(code, pick(rng, dest_bits), pick(rng, src_bits))]
        } else {
            vec![reg_mem(code, pick(rng, dest_bits), mem(disp(rng)))]
        };
    }
    if kind == 4 {
        let code = match width(rng) {
            8 => Code::Mov_rm8_imm8,
            16 => Code::Mov_rm16_imm16,
            32 => Code::Mov_rm32_imm32,
            _ => Code::Mov_rm64_imm32,
        };
        let value = if code == Code::Mov_rm8_imm8 {
            imm8(rng)
        } else if code == Code::Mov_rm16_imm16 {
            imm16(rng)
        } else {
            rng.next() as i32
        };
        return vec![mem_imm(code, mem(disp(rng)), value)];
    }
    vec![reg_reg(Code::Mov_rm64_r64, pick(rng, 64), pick(rng, 64))]
}

fn lea(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    let bits = if rng.bit() { 64 } else { 32 };
    let dest = pick(rng, bits);
    let code = if dest.size() == 4 {
        Code::Lea_r32_m
    } else {
        Code::Lea_r64_m
    };
    let displacement = disp(rng);
    let operand = match rng.idx(3) {
        0 => mem(displacement),
        1 => MemoryOperand::with_base_index_scale_displ_size(
            Register::R15,
            pick(rng, 64),
            [1, 2, 4, 8][rng.idx(4)],
            displacement,
            1,
        ),
        _ => MemoryOperand::with_base_displ_size_bcst_seg(
            Register::RIP,
            displacement,
            1,
            false,
            Register::None,
        ),
    };
    vec![reg_mem(code, dest, operand)]
}

fn exchange(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    let kind = rng.idx(5);
    if kind == 3 {
        return vec![mem_only(Code::Cmpxchg8b_m64, mem(0))];
    }
    if kind == 4 {
        if has_cx16() {
            return vec![mem_only(Code::Cmpxchg16b_m128, mem(0))];
        }
        return vec![mem_only(Code::Cmpxchg8b_m64, mem(0))];
    }
    let bits = width(rng);
    let index = windex(bits);
    let table = match kind {
        0 => codes!(Xchg_rm8_r8, Xchg_rm16_r16, Xchg_rm32_r32, Xchg_rm64_r64),
        1 => codes!(Xadd_rm8_r8, Xadd_rm16_r16, Xadd_rm32_r32, Xadd_rm64_r64),
        _ => codes!(
            Cmpxchg_rm8_r8,
            Cmpxchg_rm16_r16,
            Cmpxchg_rm32_r32,
            Cmpxchg_rm64_r64
        ),
    };
    let code = table[index];
    if rng.bit() {
        vec![reg_reg(code, pick(rng, bits), pick(rng, bits))]
    } else {
        vec![mem_reg(code, mem(disp(rng)), pick(rng, bits))]
    }
}

fn has_cx16() -> bool {
    std::fs::read_to_string("/proc/cpuinfo")
        .map(|text| text.contains("cx16"))
        .unwrap_or(false)
}

fn bits(rng: &mut Rng, state: &mut State) -> Vec<Instruction> {
    let kind = rng.idx(6);
    if kind == 0 {
        let reg = if rng.bit() {
            pick(rng, 32)
        } else {
            pick(rng, 64)
        };
        let code = if reg.size() == 4 {
            Code::Bswap_r32
        } else {
            Code::Bswap_r64
        };
        return vec![reg_only(code, reg)];
    }
    if kind == 1 || kind == 2 {
        let bits = [16u32, 32, 64][rng.idx(3)];
        let code = match (kind == 2, bits) {
            (false, 16) => Code::Bsf_r16_rm16,
            (false, 32) => Code::Bsf_r32_rm32,
            (false, _) => Code::Bsf_r64_rm64,
            (true, 16) => Code::Bsr_r16_rm16,
            (true, 32) => Code::Bsr_r32_rm32,
            (true, _) => Code::Bsr_r64_rm64,
        };
        let src = pick(rng, bits);
        if rng.bit() {
            state.regs[src.full_register().number()] = 0;
        }
        return if rng.bit() {
            vec![reg_reg(code, pick(rng, bits), src)]
        } else {
            let displacement = disp(rng);
            if rng.bit() {
                write_disp(
                    state,
                    displacement,
                    &0u64.to_le_bytes()[..(bits / 8) as usize],
                );
            }
            vec![reg_mem(code, pick(rng, bits), mem(displacement))]
        };
    }
    let op = rng.idx(4);
    let bits = [16u32, 32, 64][rng.idx(3)];
    let immediate = rng.bit();
    let code = match (op, bits, immediate) {
        (0, 16, true) => Code::Bt_rm16_imm8,
        (0, 32, true) => Code::Bt_rm32_imm8,
        (0, _, true) => Code::Bt_rm64_imm8,
        (0, 16, false) => Code::Bt_rm16_r16,
        (0, 32, false) => Code::Bt_rm32_r32,
        (0, _, false) => Code::Bt_rm64_r64,
        (1, 16, true) => Code::Bts_rm16_imm8,
        (1, 32, true) => Code::Bts_rm32_imm8,
        (1, _, true) => Code::Bts_rm64_imm8,
        (1, 16, false) => Code::Bts_rm16_r16,
        (1, 32, false) => Code::Bts_rm32_r32,
        (1, _, false) => Code::Bts_rm64_r64,
        (2, 16, true) => Code::Btr_rm16_imm8,
        (2, 32, true) => Code::Btr_rm32_imm8,
        (2, _, true) => Code::Btr_rm64_imm8,
        (2, 16, false) => Code::Btr_rm16_r16,
        (2, 32, false) => Code::Btr_rm32_r32,
        (2, _, false) => Code::Btr_rm64_r64,
        (3, 16, true) => Code::Btc_rm16_imm8,
        (3, 32, true) => Code::Btc_rm32_imm8,
        (3, _, true) => Code::Btc_rm64_imm8,
        (3, 16, false) => Code::Btc_rm16_r16,
        (3, 32, false) => Code::Btc_rm32_r32,
        (3, _, false) => Code::Btc_rm64_r64,
        _ => Code::Bt_rm64_imm8,
    };
    if immediate {
        let bit = rng.idx(8) as i32;
        return if rng.bit() {
            vec![reg_imm(code, pick(rng, bits), bit)]
        } else {
            vec![mem_imm(code, mem(disp(rng)), bit)]
        };
    }
    let offset = pick(rng, bits);
    if rng.bit() {
        vec![reg_reg(code, pick(rng, bits), offset)]
    } else {
        state.regs[offset.full_register().number()] = u64::from(rng.idx(16) as u8);
        vec![mem_reg(code, mem(disp(rng)), offset)]
    }
}

fn condition(cond: usize, bits: u32) -> Code {
    let index = match bits {
        16 => 0,
        32 => 1,
        _ => 2,
    };
    let rows: [[Code; 3]; 16] = [
        codes!(Cmovo_r16_rm16, Cmovo_r32_rm32, Cmovo_r64_rm64),
        codes!(Cmovno_r16_rm16, Cmovno_r32_rm32, Cmovno_r64_rm64),
        codes!(Cmovb_r16_rm16, Cmovb_r32_rm32, Cmovb_r64_rm64),
        codes!(Cmovae_r16_rm16, Cmovae_r32_rm32, Cmovae_r64_rm64),
        codes!(Cmove_r16_rm16, Cmove_r32_rm32, Cmove_r64_rm64),
        codes!(Cmovne_r16_rm16, Cmovne_r32_rm32, Cmovne_r64_rm64),
        codes!(Cmovbe_r16_rm16, Cmovbe_r32_rm32, Cmovbe_r64_rm64),
        codes!(Cmova_r16_rm16, Cmova_r32_rm32, Cmova_r64_rm64),
        codes!(Cmovs_r16_rm16, Cmovs_r32_rm32, Cmovs_r64_rm64),
        codes!(Cmovns_r16_rm16, Cmovns_r32_rm32, Cmovns_r64_rm64),
        codes!(Cmovp_r16_rm16, Cmovp_r32_rm32, Cmovp_r64_rm64),
        codes!(Cmovnp_r16_rm16, Cmovnp_r32_rm32, Cmovnp_r64_rm64),
        codes!(Cmovl_r16_rm16, Cmovl_r32_rm32, Cmovl_r64_rm64),
        codes!(Cmovge_r16_rm16, Cmovge_r32_rm32, Cmovge_r64_rm64),
        codes!(Cmovle_r16_rm16, Cmovle_r32_rm32, Cmovle_r64_rm64),
        codes!(Cmovg_r16_rm16, Cmovg_r32_rm32, Cmovg_r64_rm64),
    ];
    rows[cond][index]
}

fn set_code(cond: usize) -> Code {
    [
        Code::Seto_rm8,
        Code::Setno_rm8,
        Code::Setb_rm8,
        Code::Setae_rm8,
        Code::Sete_rm8,
        Code::Setne_rm8,
        Code::Setbe_rm8,
        Code::Seta_rm8,
        Code::Sets_rm8,
        Code::Setns_rm8,
        Code::Setp_rm8,
        Code::Setnp_rm8,
        Code::Setl_rm8,
        Code::Setge_rm8,
        Code::Setle_rm8,
        Code::Setg_rm8,
    ][cond]
}

fn conditional(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    let cond = rng.idx(16);
    if rng.bit() {
        let bits = [16u32, 32, 64][rng.idx(3)];
        let code = condition(cond, bits);
        if rng.bit() {
            vec![reg_reg(code, pick(rng, bits), pick(rng, bits))]
        } else {
            vec![reg_mem(code, pick(rng, bits), mem(disp(rng)))]
        }
    } else {
        let code = set_code(cond);
        if rng.bit() {
            vec![reg_only(code, pick(rng, 8))]
        } else {
            vec![mem_only(code, mem(disp(rng)))]
        }
    }
}

fn stack(rng: &mut Rng, state: &mut State) -> Vec<Instruction> {
    match rng.idx(8) {
        0 => vec![reg_only(Code::Push_r64, pick(rng, 64))],
        1 => vec![reg_only(Code::Pop_r64, pick(rng, 64))],
        2 => vec![reg_only(Code::Push_r16, pick(rng, 16))],
        3 => vec![reg_only(Code::Pop_r16, pick(rng, 16))],
        4 => vec![mem_only(Code::Push_rm64, mem(disp(rng)))],
        5 => vec![mem_only(Code::Pop_rm64, mem(disp(rng)))],
        6 => {
            plant(state, 0xC00, &image(rng).to_le_bytes());
            if rng.bit() {
                vec![Instruction::with(Code::Popfq)]
            } else {
                vec![Instruction::with(Code::Popfw)]
            }
        }
        _ => {
            if rng.bit() {
                vec![Instruction::with(Code::Pushfq)]
            } else if rng.bit() {
                vec![Instruction::with(Code::Pushfw)]
            } else {
                vec![imm_only(Code::Pushq_imm8, imm8(rng))]
            }
        }
    }
}

fn flag_ops(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    if rng.bit() {
        let bits = [16u32, 32, 64][rng.idx(3)];
        let code = match bits {
            16 => Code::Reservednop_rm16_r16_0F1F,
            32 => Code::Reservednop_rm32_r32_0F1F,
            _ => Code::Reservednop_rm64_r64_0F1F,
        };
        let reg = pick(rng, bits);
        return if rng.bit() {
            vec![reg_reg(code, reg, pick(rng, bits))]
        } else {
            vec![mem_reg(code, mem(disp(rng)), reg)]
        };
    }
    let code = [
        Code::Lahf,
        Code::Sahf,
        Code::Clc,
        Code::Stc,
        Code::Cmc,
        Code::Cld,
        Code::Std,
        Code::Nopd,
        Code::Pause,
    ][rng.idx(9)];
    vec![Instruction::with(code)]
}

fn convert(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    let code = [
        Code::Cbw,
        Code::Cwde,
        Code::Cdqe,
        Code::Cwd,
        Code::Cdq,
        Code::Cqo,
    ][rng.idx(6)];
    vec![Instruction::with(code)]
}

fn string_insn(code: Code, rep: RepPrefixKind) -> Instruction {
    let none = Register::None;
    let created = match code {
        Code::Movsb_m8_m8 => Instruction::with_movsb(64, none, rep),
        Code::Movsw_m16_m16 => Instruction::with_movsw(64, none, rep),
        Code::Movsd_m32_m32 => Instruction::with_movsd(64, none, rep),
        Code::Movsq_m64_m64 => Instruction::with_movsq(64, none, rep),
        Code::Lodsb_AL_m8 => Instruction::with_lodsb(64, none, rep),
        Code::Lodsw_AX_m16 => Instruction::with_lodsw(64, none, rep),
        Code::Lodsd_EAX_m32 => Instruction::with_lodsd(64, none, rep),
        Code::Lodsq_RAX_m64 => Instruction::with_lodsq(64, none, rep),
        Code::Cmpsb_m8_m8 => Instruction::with_cmpsb(64, none, rep),
        Code::Cmpsw_m16_m16 => Instruction::with_cmpsw(64, none, rep),
        Code::Cmpsd_m32_m32 => Instruction::with_cmpsd(64, none, rep),
        Code::Cmpsq_m64_m64 => Instruction::with_cmpsq(64, none, rep),
        Code::Stosb_m8_AL => Instruction::with_stosb(64, rep),
        Code::Stosw_m16_AX => Instruction::with_stosw(64, rep),
        Code::Stosd_m32_EAX => Instruction::with_stosd(64, rep),
        Code::Stosq_m64_RAX => Instruction::with_stosq(64, rep),
        Code::Scasb_AL_m8 => Instruction::with_scasb(64, rep),
        Code::Scasw_AX_m16 => Instruction::with_scasw(64, rep),
        Code::Scasd_EAX_m32 => Instruction::with_scasd(64, rep),
        Code::Scasq_RAX_m64 => Instruction::with_scasq(64, rep),
        _ => panic!("not a string op"),
    };
    built(created)
}

fn strings(rng: &mut Rng, state: &mut State) -> Vec<Instruction> {
    let ops = [
        (Code::Movsb_m8_m8, 1u32),
        (Code::Movsw_m16_m16, 2),
        (Code::Movsd_m32_m32, 4),
        (Code::Movsq_m64_m64, 8),
        (Code::Stosb_m8_AL, 1),
        (Code::Stosw_m16_AX, 2),
        (Code::Stosd_m32_EAX, 4),
        (Code::Stosq_m64_RAX, 8),
        (Code::Lodsb_AL_m8, 1),
        (Code::Lodsw_AX_m16, 2),
        (Code::Lodsd_EAX_m32, 4),
        (Code::Lodsq_RAX_m64, 8),
        (Code::Scasb_AL_m8, 1),
        (Code::Scasw_AX_m16, 2),
        (Code::Scasd_EAX_m32, 4),
        (Code::Scasq_RAX_m64, 8),
        (Code::Cmpsb_m8_m8, 1),
        (Code::Cmpsw_m16_m16, 2),
        (Code::Cmpsd_m32_m32, 4),
        (Code::Cmpsq_m64_m64, 8),
    ];
    let (code, _) = ops[rng.idx(ops.len())];
    let rep = match rng.idx(3) {
        1 => RepPrefixKind::Repe,
        2 => RepPrefixKind::Repne,
        _ => RepPrefixKind::None,
    };
    let insn = string_insn(code, rep);
    state.regs[1] = u64::from(rng.idx(4) as u8);
    if rng.bit() {
        state.rflags |= 1 << 10;
    } else {
        state.rflags &= !(1 << 10);
    }
    vec![insn]
}

fn multiply(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    let kind = rng.idx(4);
    if kind == 0 {
        let bits = width(rng);
        let code = codes!(Mul_rm8, Mul_rm16, Mul_rm32, Mul_rm64)[windex(bits)];
        return if rng.bit() {
            vec![reg_only(code, pick(rng, bits))]
        } else {
            vec![mem_only(code, mem(disp(rng)))]
        };
    }
    if kind == 1 {
        let bits = width(rng);
        let code = codes!(Imul_rm8, Imul_rm16, Imul_rm32, Imul_rm64)[windex(bits)];
        return if rng.bit() {
            vec![reg_only(code, pick(rng, bits))]
        } else {
            vec![mem_only(code, mem(disp(rng)))]
        };
    }
    if kind == 2 {
        let bits = [16u32, 32, 64][rng.idx(3)];
        let code = match bits {
            16 => Code::Imul_r16_rm16,
            32 => Code::Imul_r32_rm32,
            _ => Code::Imul_r64_rm64,
        };
        return if rng.bit() {
            vec![reg_reg(code, pick(rng, bits), pick(rng, bits))]
        } else {
            vec![reg_mem(code, pick(rng, bits), mem(disp(rng)))]
        };
    }
    let bits = [16u32, 32, 64][rng.idx(3)];
    let wide = bits != 16 && rng.bit();
    let code = match (bits, wide) {
        (16, _) => Code::Imul_r16_rm16_imm8,
        (32, false) => Code::Imul_r32_rm32_imm8,
        (32, true) => Code::Imul_r32_rm32_imm32,
        (_, false) => Code::Imul_r64_rm64_imm8,
        (_, true) => Code::Imul_r64_rm64_imm32,
    };
    let value = if wide { rng.next() as i32 } else { imm8(rng) };
    let dest = pick(rng, bits);
    if rng.bit() {
        vec![reg_reg_imm(code, dest, pick(rng, bits), value)]
    } else {
        vec![reg_mem_imm(code, dest, mem(disp(rng)), value)]
    }
}

fn arm_div(state: &mut State, bits: u32, negative: bool) {
    let divisor = 3u64;
    let (low, high) = if negative {
        match bits {
            8 => (0xfffdu64, 0),
            16 => (0xfffdu64, 0xffff),
            32 => (0xffff_fffdu64, 0xffff_ffff),
            _ => (u64::MAX - 2, u64::MAX),
        }
    } else {
        (divisor, 0)
    };
    match bits {
        8 => {
            state.regs[0] = (state.regs[0] & !0xffff) | (low & 0xffff);
            state.regs[1] = (state.regs[1] & !0xff) | divisor;
        }
        16 => {
            state.regs[0] = (state.regs[0] & !0xffff) | (low & 0xffff);
            state.regs[2] = (state.regs[2] & !0xffff) | (high & 0xffff);
            state.regs[1] = (state.regs[1] & !0xffff) | divisor;
        }
        32 => {
            state.regs[0] = low & 0xffff_ffff;
            state.regs[2] = high & 0xffff_ffff;
            state.regs[1] = divisor;
        }
        _ => {
            state.regs[0] = low;
            state.regs[2] = high;
            state.regs[1] = divisor;
        }
    }
    let raw = divisor.to_le_bytes();
    write_disp(state, 0, &raw[..(bits / 8) as usize]);
}

fn divide(rng: &mut Rng, state: &mut State) -> Vec<Instruction> {
    let signed = rng.bit();
    let bits = width(rng);
    arm_div(state, bits, signed && rng.bit());
    let code = if signed {
        codes!(Idiv_rm8, Idiv_rm16, Idiv_rm32, Idiv_rm64)[windex(bits)]
    } else {
        codes!(Div_rm8, Div_rm16, Div_rm32, Div_rm64)[windex(bits)]
    };
    if rng.bit() {
        vec![reg_only(code, part(1, bits))]
    } else {
        vec![mem_only(code, mem(0))]
    }
}

fn frame(rng: &mut Rng, state: &mut State) -> Vec<Instruction> {
    match rng.idx(5) {
        0 => vec![built(Instruction::with2(
            Code::Enterq_imm16_imm8,
            16i32,
            rng.idx(2) as i32,
        ))],
        1 => vec![Instruction::with(Code::Leaveq)],
        2 => vec![built(Instruction::with2(
            Code::Enterw_imm16_imm8,
            8i32,
            rng.idx(2) as i32,
        ))],
        3 => vec![Instruction::with(Code::Leavew)],
        _ => {
            state.regs[0] = (state.regs[0] & !0xff) | u64::from(rng.idx(16) as u8);
            vec![mem_only(
                Code::Xlat_m8,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::RBX,
                    Register::AL,
                    1,
                    0,
                    0,
                ),
            )]
        }
    }
}

fn locked(rng: &mut Rng, _: &mut State) -> Vec<Instruction> {
    let bits = width(rng);
    let index = windex(bits);
    let choice = rng.idx(7);
    let mut insn = if choice == 0 {
        mem_reg(
            codes!(Add_rm8_r8, Add_rm16_r16, Add_rm32_r32, Add_rm64_r64)[index],
            mem(disp(rng)),
            pick(rng, bits),
        )
    } else if choice == 1 {
        mem_reg(
            codes!(Xadd_rm8_r8, Xadd_rm16_r16, Xadd_rm32_r32, Xadd_rm64_r64)[index],
            mem(disp(rng)),
            pick(rng, bits),
        )
    } else if choice == 2 {
        mem_reg(
            codes!(
                Cmpxchg_rm8_r8,
                Cmpxchg_rm16_r16,
                Cmpxchg_rm32_r32,
                Cmpxchg_rm64_r64
            )[index],
            mem(disp(rng)),
            pick(rng, bits),
        )
    } else if choice == 3 {
        let bits = [16u32, 32, 64][rng.idx(3)];
        mem_imm(
            match bits {
                16 => Code::Btc_rm16_imm8,
                32 => Code::Btc_rm32_imm8,
                _ => Code::Btc_rm64_imm8,
            },
            mem(disp(rng)),
            rng.idx(8) as i32,
        )
    } else if choice == 4 {
        mem_only(
            codes!(Inc_rm8, Inc_rm16, Inc_rm32, Inc_rm64)[index],
            mem(disp(rng)),
        )
    } else if choice == 5 {
        mem_only(
            codes!(Not_rm8, Not_rm16, Not_rm32, Not_rm64)[index],
            mem(disp(rng)),
        )
    } else {
        mem_reg(
            codes!(Xchg_rm8_r8, Xchg_rm16_r16, Xchg_rm32_r32, Xchg_rm64_r64)[index],
            mem(disp(rng)),
            pick(rng, bits),
        )
    };
    insn.set_has_lock_prefix(true);
    vec![insn]
}

fn chains(rng: &mut Rng, state: &mut State) -> Vec<Instruction> {
    match rng.idx(4) {
        0 => {
            let bits = if rng.bit() { 32 } else { 64 };
            vec![
                reg_reg(
                    if bits == 32 {
                        Code::Add_rm32_r32
                    } else {
                        Code::Add_rm64_r64
                    },
                    pick(rng, bits),
                    pick(rng, bits),
                ),
                reg_reg(
                    condition(rng.idx(16), bits),
                    pick(rng, bits),
                    pick(rng, bits),
                ),
            ]
        }
        1 => vec![
            reg_reg(Code::Cmp_rm64_r64, pick(rng, 64), pick(rng, 64)),
            if rng.bit() {
                reg_only(set_code(rng.idx(16)), pick(rng, 8))
            } else {
                mem_only(set_code(rng.idx(16)), mem(disp(rng)))
            },
        ],
        2 => vec![
            reg_reg(Code::Sub_rm32_r32, pick(rng, 32), pick(rng, 32)),
            reg_reg(Code::Sbb_rm32_r32, pick(rng, 32), pick(rng, 32)),
            reg_reg(Code::Adc_rm64_r64, pick(rng, 64), pick(rng, 64)),
        ],
        _ => {
            state.regs[1] = 1;
            vec![
                reg_reg(Code::Shl_rm64_CL, pick(rng, 64), Register::CL),
                reg_reg(Code::Xor_rm64_r64, pick(rng, 64), pick(rng, 64)),
            ]
        }
    }
}

fn builders() -> [fn(&mut Rng, &mut State) -> Vec<Instruction>; 20] {
    [
        alu_reg,
        alu_mem,
        alu_imm,
        unary,
        shifts,
        double_shift,
        moves,
        lea,
        exchange,
        bits,
        conditional,
        stack,
        flag_ops,
        convert,
        strings,
        multiply,
        divide,
        frame,
        locked,
        chains,
    ]
}

fn mov_eax_one() -> Case {
    let mut state = fresh(&mut Rng(0x6c31_0001));
    state.regs[0] = u64::MAX;
    state.rflags = 0x202 | 1 | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    Case {
        code: encode(&[reg_imm(Code::Mov_r32_imm32, Register::EAX, 1)]),
        regs: state.regs,
        rflags: state.rflags,
        data: state.data,
    }
}

#[test]
fn every_l1_mnemonic_is_run_or_ud() {
    use crate::isa::census::{entry, Group, Status};
    use iced_x86::Mnemonic;
    let mut missing = Vec::new();
    for mnemonic in Mnemonic::values() {
        let row = entry(mnemonic);
        if row.group != Group::L1Integer || row.status != Status::Lift {
            continue;
        }
        assert!(row.proven, "{mnemonic:?}");
        let class = classify(mnemonic);
        if class != Class::Run && class != Class::Ud {
            missing.push(format!("{mnemonic:?}"));
        }
    }
    assert!(
        missing.is_empty(),
        "L1 without a class: {}",
        missing.join(", ")
    );
}

#[test]
fn carrier_mov_matches_linux() {
    let mut host = Host::spawn("mov");
    check(&mut host, 0, &mov_eax_one());
}

#[test]
fn undefined_opcodes_match_sigill() {
    // Long mode has no encoding of 32-bit ENTER. These bytes are #UD there.
    for code in [vec![0x37u8], vec![0xd6], vec![0x60], vec![0x06]] {
        let mut state = fresh(&mut Rng(0x6c31_0001));
        state.rflags = 0x202;
        let case = Case {
            code,
            regs: state.regs,
            rflags: state.rflags,
            data: state.data,
        };
        let err = emulate(&case).expect_err("emulator accepts a #UD opcode");
        assert!(
            err.contains("invalid opcode") || err.contains("invalid encoding"),
            "{err} {}",
            hex(&case.code)
        );
        let mut host = Host::spawn("ud");
        let err = host
            .roundtrip(&case)
            .expect_err("linux executed a #UD opcode");
        assert!(err.contains("signal=Some(4)"), "{err} {}", hex(&case.code));
    }
}

fn with_lock(mut insn: Instruction) -> Instruction {
    insn.set_has_lock_prefix(true);
    insn
}

fn locked_case(insn: Instruction) -> Case {
    let mut state = fresh(&mut Rng(0x10C0_0001));
    state.rflags = 0x202 | (1 << 4) | 1 | (1 << 2) | (1 << 6) | (1 << 7) | (1 << 11);
    Case {
        code: encode(&[insn]),
        regs: state.regs,
        rflags: state.rflags,
        data: state.data,
    }
}

fn reject_lock(insn: &Instruction) {
    let mut cpu = Cpu {
        regs: [0; 16],
        flags: Flags::default(),
        af: true,
        df: false,
        gs: 0,
    };
    cpu.regs[15] = DATA + 0x800;
    let mut page = Page {
        bytes: vec![0; DATA_LEN],
    };
    let err = apply(&mut cpu, &mut page, insn).expect_err("lock with a register destination");
    assert!(
        err.to_string().contains("invalid opcode"),
        "{err} {:?}",
        insn.mnemonic()
    );
}

fn cmpxchg_case(wide: bool, equal: bool, tail: Option<Code>) -> Case {
    let mut state = fresh(&mut Rng(0xC3A5_0001));
    state.rflags = 0x202 | 1 | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 10) | (1 << 11);
    state.regs[0] = 0x0123_4567_89ab_cdef;
    state.regs[1] = 0x1111_2222_3333_4444;
    state.regs[2] = 0xfedc_ba98_7654_3210;
    state.regs[3] = 0x5555_6666_7777_8888;
    let low = if wide {
        if equal {
            state.regs[0]
        } else {
            state.regs[0] ^ 0xff
        }
    } else if equal {
        (state.regs[2] & 0xffff_ffff) << 32 | (state.regs[0] & 0xffff_ffff)
    } else {
        0x0bad_f00d_dead_beef
    };
    let low_bytes = low.to_le_bytes();
    plant(&mut state, 0x800, &low_bytes);
    if wide {
        let high_bytes = state.regs[2].to_le_bytes();
        plant(&mut state, 0x808, &high_bytes);
    }
    let mut insns = vec![mem_only(
        if wide {
            Code::Cmpxchg16b_m128
        } else {
            Code::Cmpxchg8b_m64
        },
        mem(0),
    )];
    if let Some(code) = tail {
        insns.push(Instruction::with(code));
    }
    Case {
        code: encode(&insns),
        regs: state.regs,
        rflags: state.rflags,
        data: state.data,
    }
}

fn assert_status(host: &mut Host, case: &Case) {
    let text = render(&case.code);
    let emulated = emulate(case).unwrap_or_else(|err| panic!("emu: {err}\n{text}"));
    let actual = host
        .roundtrip(case)
        .unwrap_or_else(|err| panic!("linux: {err}\n{text}\n{}", hex(&case.code)));
    assert_eq!(emulated.regs, actual.regs, "regs {text}");
    if let Some((at, lhs, rhs)) = first_diff(&emulated.data, &actual.data) {
        panic!("data[{at:#x}] emu={lhs:#x} linux={rhs:#x} {text}");
    }
    let (ef, eaf, edf) = split(emulated.rflags);
    let (cf, caf, cdf) = split(actual.rflags);
    assert_eq!(ef, cf, "flags {text}");
    assert_eq!(eaf, caf, "af {text}");
    assert_eq!(edf, cdf, "df {text}");
}

#[test]
fn cmpxchg_wide_keeps_flags_except_zf() {
    let mut host = Host::spawn("cmpxchg-flags");
    for wide in [false, true] {
        if wide && !has_cx16() {
            continue;
        }
        for equal in [true, false] {
            for tail in [None, Some(Code::Lahf), Some(Code::Pushfq)] {
                assert_status(&mut host, &cmpxchg_case(wide, equal, tail));
            }
        }
    }
}

#[test]
fn lock_prefix_requires_memory_destination() {
    let legal = [
        with_lock(mem_reg(Code::Add_rm64_r64, mem(0), Register::RAX)),
        with_lock(mem_reg(Code::Xadd_rm64_r64, mem(0), Register::RAX)),
        with_lock(mem_reg(Code::Xchg_rm64_r64, mem(0), Register::RAX)),
    ];
    let mut host = Host::spawn("lock-ok");
    for insn in legal {
        let case = locked_case(insn);
        check(&mut host, 0, &case);
        crate::lift::lift("lock", &case.code, 0, case.code.len() as u32, 0)
            .expect("legal lock lifts");
    }
    drop(host);

    let illegal = [
        with_lock(reg_mem(Code::Add_r64_rm64, Register::RAX, mem(0))),
        with_lock(reg_reg(Code::Add_rm64_r64, Register::RAX, Register::RCX)),
        with_lock(reg_reg(Code::Xadd_rm64_r64, Register::RAX, Register::RCX)),
    ];
    for insn in illegal {
        reject_lock(&insn);
        let case = locked_case(insn);
        let text = render(&case.code);
        let err = emulate(&case).expect_err("emulator accepts a locked register destination");
        assert!(
            err.contains("invalid opcode") || err.contains("invalid encoding"),
            "{err} {text}"
        );
        assert!(
            crate::lift::lift("lock", &case.code, 0, case.code.len() as u32, 0).is_err(),
            "lifted {text}"
        );
        let mut host = Host::spawn("lock-ud");
        let err = host
            .roundtrip(&case)
            .expect_err("linux executed a locked register destination");
        assert!(err.contains("signal=Some(4)"), "{err} {text}");
    }

    let mut xadd_mem_src = reg_reg(Code::Xadd_rm64_r64, Register::RAX, Register::RCX);
    xadd_mem_src.set_op1_kind(OpKind::Memory);
    xadd_mem_src.set_memory_base(Register::R15);
    xadd_mem_src.set_has_lock_prefix(true);
    reject_lock(&xadd_mem_src);
}

pub(crate) struct L1Block {
    pub code: Vec<u8>,
    pub regs: [u64; 16],
    pub rflags: u64,
    pub data: Vec<u8>,
    pub base: u64,
    pub ip: u64,
}

pub(crate) fn l1_blocks() -> Vec<L1Block> {
    let mut rng = Rng(0x6c31_0001);
    let built = builders();
    let mut out = Vec::with_capacity(32);
    let mut index = 0usize;
    while out.len() < 32 {
        let case = build_case(&mut rng, built[index % built.len()]);
        index += 1;
        out.push(L1Block {
            code: case.code,
            regs: case.regs,
            rflags: case.rflags,
            data: case.data,
            base: DATA,
            ip: GUEST,
        });
    }
    out
}

#[test]
fn linux_matches_ten_thousand_integer_blocks() {
    let mut host = Host::spawn("blocks");
    check(&mut host, 0, &mov_eax_one());
    let mut rng = Rng(0x6c31_0001);
    let builders = builders();
    for index in 0..CASES {
        let builder = if index < builders.len() {
            builders[index]
        } else {
            builders[rng.idx(builders.len())]
        };
        check(&mut host, index, &build_case(&mut rng, builder));
    }
}
