//! x87 blocks against this Linux process. The carrier reports the raw 10 bytes
//! of each stack register, the control word, the status word, and the tag word.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use iced_x86::{
    BlockEncoderOptions, Code, Decoder, DecoderOptions, Encoder, Formatter, Instruction,
    IntelFormatter, Mnemonic, OpKind, Register,
};

use crate::flags::Flags;
use crate::gp::Cpu;
use crate::ir::{exec_program, MemIo, X87};
use crate::isa::census::{self, Group, Status};

use super::{export_image, host};

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
const RESULT: usize = 136 + XSTATE_LEN + DATA_LEN;
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
    data: Vec<u8>,
}

#[derive(Debug)]
struct Observed {
    regs: [u64; 16],
    rflags: u64,
    x87: X87,
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
    regs[15] = DATA;
    regs[4] = STACK;
    Case {
        code: Vec::new(),
        regs,
        rflags: 0x202,
        x87: X87::default(),
        data: vec![0; DATA_LEN],
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
    asm_ok(asm.mov(rsi, XSTATE));
    asm_ok(asm.mov(rdx, XSTATE_LEN as u64));
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
    asm_ok(asm.mov(rax, XSTATE));
    asm_ok(asm.db(&[0x48, 0x0f, 0xae, 0x08])); // fxrstor64 [rax]
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
    asm_ok(asm.db(&[0xA6; 7])); // mov [rip], r15
    asm_ok(asm.mov(r15, XSTATE));
    asm_ok(asm.db(&[0x49, 0x0f, 0xae, 0x07])); // fxsave64 [r15]
    asm_ok(asm.mov(r15, SAVE));
    for (index, reg) in regs.into_iter().enumerate() {
        if index == 4 || index == 15 {
            continue;
        }
        asm_ok(asm.mov(qword_ptr(r15 + (index * 8) as i32), reg));
    }
    asm_ok(asm.db(&[0xA7; 7])); // mov rax, [rip]
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
    asm_ok(asm.mov(rsi, XSTATE));
    asm_ok(asm.mov(rdx, XSTATE_LEN as u64));
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
            .join(format!("l2-carrier-{tag}-{id}"));
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
        let image = image_of(&case.x87);
        stdin.write_all(&(u32::try_from(case.code.len()).expect("len")).to_le_bytes())?;
        stdin.write_all(&case.code)?;
        for reg in case.regs {
            stdin.write_all(&reg.to_le_bytes())?;
        }
        stdin.write_all(&case.rflags.to_le_bytes())?;
        stdin.write_all(&image)?;
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

fn image_of(state: &X87) -> [u8; 512] {
    let mut image = host::capture_template();
    export_image(state, &mut image);
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
    super::import_image(&mut x87, &image);
    Observed {
        regs,
        rflags: flags,
        x87,
        data: buf[136 + XSTATE_LEN..].to_vec(),
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

fn emulate(case: &Case) -> std::result::Result<Observed, String> {
    let (mut flags, mut af, mut df) = split(case.rflags);
    let mut state = case.x87;
    let mut regs = case.regs;
    let mut page = Page {
        bytes: case.data.clone(),
    };
    let mut decoder = Decoder::with_ip(64, &case.code, GUEST, DecoderOptions::NONE);
    let end = GUEST + case.code.len() as u64;
    while decoder.ip() < end {
        let insn = decoder.decode();
        if insn.is_invalid() || insn.len() == 0 {
            return Err(format!("invalid encoding {}", hex(&case.code)));
        }
        let off = usize::try_from(insn.ip() - GUEST).map_err(|_| "ip".to_string())?;
        let raw = case
            .code
            .get(off..off + insn.len())
            .ok_or_else(|| "truncated instruction".to_string())?;
        let mut cpu = Cpu {
            regs,
            flags,
            af,
            df,
            gs: 0,
        };
        if super::is_x87(insn.mnemonic()) {
            super::apply(&mut state, &mut cpu, &mut page, &insn, raw)
                .map_err(|err| err.to_string())?;
        } else {
            match crate::gp::apply(&mut cpu, &mut page, &insn).map_err(|err| err.to_string())? {
                Some(_) => {}
                None => return Err(format!("outside the lifted set: {:?}", insn.mnemonic())),
            }
        }
        regs = cpu.regs;
        flags = cpu.flags;
        af = cpu.af;
        df = cpu.df;
    }
    Ok(Observed {
        regs,
        rflags: join(flags, af, df),
        x87: state,
        data: page.bytes,
    })
}

fn emulate_ir(case: &Case) -> std::result::Result<Observed, String> {
    let program = crate::lift::program("x87", &case.code, GUEST as u32, case.code.len() as u32, 0)
        .map_err(|err| err.to_string())?;
    let (mut flags, mut af, mut df) = split(case.rflags);
    let mut regs = case.regs;
    let mut state = case.x87;
    let mut sse = crate::ir::Sse::default();
    let mut page = Page {
        bytes: case.data.clone(),
    };
    let mut absent = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
    exec_program(
        &[program],
        0,
        &mut regs,
        &mut flags,
        &mut af,
        &mut df,
        &mut state,
        &mut sse,
        0,
        &mut page,
        0,
        &mut absent,
    )
    .map_err(|err| err.to_string())?;
    Ok(Observed {
        regs,
        rflags: join(flags, af, df),
        x87: state,
        data: page.bytes,
    })
}

fn signal_of(err: &str) -> Option<i32> {
    let rest = err.split("signal=Some(").nth(1)?;
    rest.split(')').next()?.parse().ok()
}

fn encode_parts(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flat_map(|part| part.iter().copied()).collect()
}

fn encode_code(code: Code, disp: i64) -> std::result::Result<Vec<u8>, String> {
    encode_sti(code, disp, Register::ST1)
}

fn encode_sti(code: Code, disp: i64, sti: Register) -> std::result::Result<Vec<u8>, String> {
    let mut insn = Instruction::default();
    insn.set_code(code);
    let info = code.op_code();
    for index in 0..info.op_count() {
        match info.op_kind(index) {
            iced_x86::OpCodeOperandKind::mem | iced_x86::OpCodeOperandKind::mem_offs => {
                insn.set_op_kind(index, OpKind::Memory);
                insn.set_memory_base(Register::R15);
                if disp == 0 {
                    insn.set_memory_displ_size(0);
                    insn.set_memory_displacement64(0);
                } else {
                    insn.set_memory_displ_size(1);
                    insn.set_memory_displacement64(disp as u64);
                }
            }
            iced_x86::OpCodeOperandKind::st0 => {
                insn.set_op_kind(index, OpKind::Register);
                insn.set_op_register(index, Register::ST0);
            }
            iced_x86::OpCodeOperandKind::sti_opcode => {
                insn.set_op_kind(index, OpKind::Register);
                insn.set_op_register(index, sti);
            }
            iced_x86::OpCodeOperandKind::ax => {
                insn.set_op_kind(index, OpKind::Register);
                insn.set_op_register(index, Register::AX);
            }
            _ => {}
        }
    }
    let mut encoder = Encoder::new(64);
    encoder
        .encode(&insn, GUEST)
        .map_err(|err| err.to_string())?;
    let buf = encoder.take_buffer();
    if buf.is_empty() || buf.len() > 15 {
        return Err(format!("bad encoding {code:?}"));
    }
    Ok(buf)
}

fn must(code: Code) -> Vec<u8> {
    encode_code(code, 0).unwrap_or_else(|err| panic!("{code:?}: {err}"))
}

fn must_disp(code: Code, disp: i64) -> Vec<u8> {
    encode_code(code, disp).unwrap_or_else(|err| panic!("{code:?} disp {disp}: {err}"))
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

fn assert_same(left: &Observed, right: &Observed, text: &str) {
    assert_eq!(left.regs, right.regs, "regs {text}");
    assert_eq!(left.data, right.data, "data {text}");
    for index in 0..8 {
        assert_eq!(
            left.x87.st[index], right.x87.st[index],
            "st{index} raw {text}\n left {:02x?}\nright {:02x?}",
            left.x87.st[index], right.x87.st[index]
        );
    }
    assert_eq!(left.x87.sw, right.x87.sw, "status {text}");
    assert_eq!(left.x87.cw, right.x87.cw, "control {text}");
    assert_eq!(left.x87.tw, right.x87.tw, "tags {text}");
    assert_eq!(left.x87.fip, right.x87.fip, "fip {text}");
    assert_eq!(left.x87.fdp, right.x87.fdp, "fdp {text}");
    assert_eq!(left.x87.fop, right.x87.fop, "fop {text}");
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

const ONE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f];
const TINY: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xe1, 0x3f];
const THREE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0xc0, 0x00, 0x40];
const INDEFINITE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0xff];

fn fld_addr(base: Register, index: Register, scale: u32, disp: i64) -> Vec<u8> {
    let mut insn = Instruction::default();
    insn.set_code(Code::Fld_m32fp);
    insn.set_op0_kind(OpKind::Memory);
    insn.set_memory_base(base);
    if index != Register::None {
        insn.set_memory_index(index);
        insn.set_memory_index_scale(scale);
    }
    if disp != 0 {
        insn.set_memory_displ_size(1);
        insn.set_memory_displacement64(disp as u64);
    }
    let mut encoder = Encoder::new(64);
    encoder
        .encode(&insn, GUEST)
        .unwrap_or_else(|err| panic!("encode fld: {err}"));
    encoder.take_buffer()
}

#[test]
fn address_size_override_matches_linux() {
    let mut host = Host::spawn("addr32");
    let mut base = fresh();
    base.regs[0] = DATA | (1u64 << 32);
    base.data[..4].copy_from_slice(&1.0f32.to_le_bytes());
    base.code = fld_addr(Register::EAX, Register::None, 1, 0);
    check(&mut host, &base);
    assert_eq!(emulate(&base).expect("eax").x87.st[0], ONE);

    let mut scaled = fresh();
    scaled.regs[0] = (DATA + 0x40) | (1u64 << 32);
    scaled.regs[1] = 0x10 | (1u64 << 32);
    let off = 0x40 + 0x10 * 4 + 8;
    scaled.data[off..off + 4].copy_from_slice(&1.0f32.to_le_bytes());
    scaled.code = fld_addr(Register::EAX, Register::ECX, 4, 8);
    check(&mut host, &scaled);
    assert_eq!(emulate(&scaled).expect("scaled").x87.st[0], ONE);
}

#[test]
fn fld1_keeps_the_eighty_bit_encoding() {
    let mut case = fresh();
    case.code = must(Code::Fld1);
    let mut host = Host::spawn("fld1");
    check(&mut host, &case);
    let got = emulate(&case).expect("fld1");
    assert_eq!(got.x87.st[0], ONE);
    assert_eq!(got.x87.top(), 7);
    assert_ne!(got.x87.st[0], [0; 10]);
}

#[test]
fn stack_overflow_sets_invalid_and_c1() {
    let mut case = fresh();
    let mut code = Vec::new();
    for _ in 0..8 {
        code.extend(must(Code::Fldz));
    }
    code.extend(must(Code::Fld1));
    case.code = code;
    let mut host = Host::spawn("overflow");
    check(&mut host, &case);
    let got = emulate(&case).expect("overflow");
    assert_eq!(got.x87.sw & 0x41, 0x41, "IE and SF {:#x}", got.x87.sw);
    assert_ne!(got.x87.sw & (1 << 9), 0, "C1 overflow {:#x}", got.x87.sw);
    assert_eq!(got.x87.st[0], INDEFINITE);
}

#[test]
fn stack_underflow_sets_invalid_and_clears_c1() {
    let mut case = fresh();
    case.code = must(Code::Fstp_sti);
    let mut host = Host::spawn("underflow");
    check(&mut host, &case);
    let got = emulate(&case).expect("underflow");
    assert_eq!(got.x87.sw & 0x41, 0x41, "IE and SF {:#x}", got.x87.sw);
    assert_eq!(got.x87.sw & (1 << 9), 0, "C1 clear {:#x}", got.x87.sw);

    let mut empty_add = fresh();
    empty_add.code = must(Code::Fadd_st0_sti);
    check(&mut host, &empty_add);
    let got = emulate(&empty_add).expect("empty add");
    assert_eq!(got.x87.sw & 0x41, 0x41, "add IE/SF {:#x}", got.x87.sw);
}

#[test]
fn control_word_selects_precision_and_rounding() {
    let mut narrow = fresh();
    narrow.data[..2].copy_from_slice(&0x007fu16.to_le_bytes());
    narrow.data[16..26].copy_from_slice(&TINY);
    narrow.data[32..42].copy_from_slice(&ONE);
    narrow.code = encode_parts(&[
        must(Code::Fldcw_m2byte),
        must_disp(Code::Fld_m80fp, 16),
        must_disp(Code::Fld_m80fp, 32),
        must(Code::Faddp_sti_st0),
    ]);
    let mut wide = narrow.clone_case();
    wide.data[..2].copy_from_slice(&0x037fu16.to_le_bytes());
    let mut down = narrow.clone_case();
    down.data[..2].copy_from_slice(&0x077fu16.to_le_bytes());
    down.data[16..26].copy_from_slice(&ONE);
    down.data[32..42].copy_from_slice(&THREE);
    down.code = encode_parts(&[
        must(Code::Fldcw_m2byte),
        must_disp(Code::Fld_m80fp, 16),
        must_disp(Code::Fld_m80fp, 32),
        must(Code::Fdivp_sti_st0),
    ]);
    let mut nearest = down.clone_case();
    nearest.data[..2].copy_from_slice(&0x037fu16.to_le_bytes());

    let mut host = Host::spawn("round");
    check(&mut host, &narrow);
    check(&mut host, &wide);
    check(&mut host, &down);
    check(&mut host, &nearest);
    let narrow_st = emulate(&narrow).unwrap().x87.st[0];
    let wide_st = emulate(&wide).unwrap().x87.st[0];
    let down_st = emulate(&down).unwrap().x87.st[0];
    let near_st = emulate(&nearest).unwrap().x87.st[0];
    assert_ne!(
        narrow_st, wide_st,
        "precision must change the raw 80-bit result"
    );
    assert_ne!(
        down_st, near_st,
        "rounding mode must change the raw 80-bit result"
    );
    assert_eq!(narrow_st, ONE, "24-bit 1 + 2^-30 collapses to 1");
}

#[test]
fn ffree_keeps_the_raw_register_bytes() {
    let mut case = fresh();
    case.code = encode_parts(&[
        must(Code::Fldpi),
        encode_sti(Code::Ffree_sti, 0, Register::ST0).expect("ffree st0"),
    ]);
    let mut host = Host::spawn("ffree");
    check(&mut host, &case);
    let got = emulate(&case).expect("ffree");
    assert_ne!(got.x87.st[0], [0; 10], "empty tag still holds the payload");
    assert_eq!(got.x87.tw, 0xffff);
}

/// 16/32-bit x87 opcodes that the long-mode decoder rejects. The host raises `#UD`.
fn assert_not_in_long_mode(mnemonic: Mnemonic, host: &mut Host) {
    let mut saw = false;
    for code in Code::values() {
        if code == Code::INVALID || code.mnemonic() != mnemonic {
            continue;
        }
        saw = true;
        let err = encode_code(code, 0).expect_err("long mode encoded a legacy opcode");
        assert!(err.contains("16/32-bit"), "{mnemonic:?} {code:?} {err}");
        let mut insn = Instruction::default();
        insn.set_code(code);
        if code.op_code().op_count() > 0
            && matches!(code.op_code().op0_kind(), iced_x86::OpCodeOperandKind::ax)
        {
            insn.set_op0_kind(OpKind::Register);
            insn.set_op0_register(Register::AX);
        }
        let mut encoder = Encoder::new(32);
        encoder
            .encode(&insn, 0)
            .unwrap_or_else(|err| panic!("{code:?} {err}"));
        let bytes = encoder.take_buffer();
        let mut decoder = Decoder::with_ip(64, &bytes, GUEST, DecoderOptions::NONE);
        while decoder.ip() < GUEST + bytes.len() as u64 {
            let decoded = decoder.decode();
            if decoded.len() == 0 {
                break;
            }
            assert!(
                decoded.is_invalid() || decoded.mnemonic() != mnemonic,
                "{mnemonic:?} decodes in long mode"
            );
        }
        let mut case = fresh();
        case.code = bytes;
        let err = host
            .roundtrip(&case)
            .expect_err("linux executed a legacy x87 opcode");
        assert_eq!(signal_of(&err), Some(4), "{mnemonic:?} {err}");
        *host = Host::spawn("legacy");
    }
    assert!(saw, "{mnemonic:?} has no encodings");
}

#[test]
fn every_l2_mnemonic_matches_linux() {
    let mut host = Host::spawn("census");
    for mnemonic in Mnemonic::values() {
        let row = census::entry(mnemonic);
        if row.group != Group::L2X87 || row.status != Status::Lift {
            continue;
        }
        assert!(row.proven, "{mnemonic:?}");
        let mut ran = false;
        let mut reasons = Vec::new();
        for code in Code::values() {
            if code == Code::INVALID || code.mnemonic() != mnemonic || code.is_privileged() {
                continue;
            }
            let bytes = match encode_code(code, 0) {
                Ok(bytes) => bytes,
                Err(err) => {
                    reasons.push(format!("{code:?} encode {err}"));
                    continue;
                }
            };
            let mut case = fresh();
            case.code = bytes;
            match host.roundtrip(&case) {
                Err(err) => {
                    let signal = signal_of(&err);
                    reasons.push(format!("{code:?} sig={signal:?} {}", hex(&case.code)));
                    host = Host::spawn("census");
                    if matches!(signal, Some(4 | 11)) {
                        continue;
                    }
                    panic!("{mnemonic:?} {code:?}: {err}");
                }
                Ok(linux) => {
                    let vm = emulate(&case).unwrap_or_else(|err| {
                        panic!("{mnemonic:?} emu {err}\n{}", hex(&case.code))
                    });
                    let ir = emulate_ir(&case)
                        .unwrap_or_else(|err| panic!("{mnemonic:?} ir {err}\n{}", hex(&case.code)));
                    let text = format!("{mnemonic:?} {}", render(&case.code));
                    assert_same(&vm, &linux, &text);
                    assert_same(&ir, &linux, &text);
                    ran = true;
                    break;
                }
            }
        }
        if !ran {
            assert!(
                reasons.iter().all(|reason| reason.contains("16/32-bit")),
                "{mnemonic:?}: {}",
                reasons.join(" | ")
            );
            assert_not_in_long_mode(mnemonic, &mut host);
        }
    }
}

#[test]
fn linux_matches_mixed_x87_blocks() {
    let pool = [
        Code::Fld1,
        Code::Fldz,
        Code::Fldpi,
        Code::Fldl2e,
        Code::Fadd_st0_sti,
        Code::Fmul_st0_sti,
        Code::Fsub_st0_sti,
        Code::Fdiv_st0_sti,
        Code::Faddp_sti_st0,
        Code::Fmulp_sti_st0,
        Code::Fsubp_sti_st0,
        Code::Fdivp_sti_st0,
        Code::Fxch_st0_sti,
        Code::Fcom_st0_sti,
        Code::Fcomp_st0_sti,
        Code::Fcompp,
        Code::Fucom_st0_sti,
        Code::Fcomi_st0_sti,
        Code::Fcomip_st0_sti,
        Code::Fabs,
        Code::Fchs,
        Code::Fsqrt,
        Code::Ftst,
        Code::Fxam,
        Code::Fprem,
        Code::Frndint,
        Code::F2xm1,
        Code::Fyl2x,
        Code::Fptan,
        Code::Fpatan,
        Code::Fsin,
        Code::Fcos,
        Code::Ffree_sti,
        Code::Fincstp,
        Code::Fdecstp,
        Code::Fnop,
        Code::Wait,
        Code::Fcmovb_st0_sti,
        Code::Fcmove_st0_sti,
        Code::Fcmovbe_st0_sti,
        Code::Fcmovu_st0_sti,
        Code::Fnstsw_AX,
        Code::Fld_m64fp,
        Code::Fstp_m64fp,
        Code::Fld_m32fp,
        Code::Fild_m32int,
        Code::Fistp_m32int,
        Code::Fisttp_m32int,
        Code::Fninit,
        Code::Fnclex,
    ];
    let mut host = Host::spawn("blocks");
    let mut rng = 0x6c32_0001u64;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for index in 0..400 {
        let mut case = fresh();
        let len = 1 + (next() as usize % 5);
        for _ in 0..len {
            let code = pool[(next() as usize) % pool.len()];
            case.code.extend(must(code));
        }
        // Keep a defined memory operand. Integer moves share the block with x87.
        if index % 17 == 0 {
            let mut mixed = vec![0xb8, 0x01, 0x00, 0x00, 0x00];
            mixed.extend(must(Code::Fld1));
            mixed.extend(must(Code::Fnstsw_AX));
            case.code = mixed;
        }
        let text = render(&case.code);
        match host.roundtrip(&case) {
            Ok(linux) => {
                let vm =
                    emulate(&case).unwrap_or_else(|err| panic!("case {index} emu {err}\n{text}"));
                let ir =
                    emulate_ir(&case).unwrap_or_else(|err| panic!("case {index} ir {err}\n{text}"));
                assert_same(&vm, &linux, &format!("case {index} {text}"));
                assert_same(&ir, &linux, &format!("case {index} ir {text}"));
            }
            Err(err) => {
                host = Host::spawn("blocks");
                let signal = signal_of(&err);
                if matches!(signal, Some(4 | 8 | 11)) {
                    let vm_err = emulate(&case).expect_err("vm accepted a faulting block");
                    assert!(
                        vm_err.contains("x87 fault")
                            || vm_err.contains("invalid")
                            || vm_err.contains("unmapped"),
                        "case {index} {vm_err} linux {err}"
                    );
                } else {
                    panic!("case {index} {err}\n{text}");
                }
            }
        }
    }
}

impl Case {
    fn clone_case(&self) -> Self {
        Self {
            code: self.code.clone(),
            regs: self.regs,
            rflags: self.rflags,
            x87: self.x87,
            data: self.data.clone(),
        }
    }
}
