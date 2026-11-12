#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs::{self, DirBuilder, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use vmkek::agent;
use vmkek::protect::{self, Options};

struct Lab(PathBuf);

impl Lab {
    fn new() -> Self {
        let name = format!(
            "vmkek-r03-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        );
        let dir = std::env::temp_dir().join(name);
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Self(dir)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("agent.sock")
    }

    fn executable(&self, bytes: &[u8]) -> PathBuf {
        let path = self.0.join("protected");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
        path
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn options(select: Option<&str>) -> Options {
    Options {
        virtualize: select.map(str::to_owned).into_iter().collect(),
        mutate: Default::default(),
        virtualize_all: select.is_none(),
        mutate_all: false,
        seed: 0x3307,
        random_key: false,
        debug_seed: false,
    }
}

fn direct(path: &Path) -> Output {
    Command::new("timeout")
        .args(["20s"])
        .arg(path)
        .output()
        .unwrap()
}

#[derive(Clone, Copy, Debug)]
enum ReplyFault {
    Short,
    Long,
    Disconnect,
    Slow,
}

#[test]
fn external_native_rejects_bad_reply_length_and_disconnect() {
    for (fault, expected) in [
        (ReplyFault::Short, 5),
        (ReplyFault::Long, 5),
        (ReplyFault::Disconnect, 3),
        (ReplyFault::Slow, 6),
    ] {
        let lab = Lab::new();
        let socket = lab.socket();
        let carrier = vmkek::elf::sample::build().unwrap();
        let protected =
            protect::protect_external(&carrier, &options(None), socket.to_str().unwrap()).unwrap();
        let path = lab.executable(&protected.bytes);
        let listener = UnixListener::bind(socket).unwrap();
        let peer = thread::spawn(move || faulty_peer(listener, fault));
        let started = Instant::now();
        let result = direct(&path);
        let elapsed = started.elapsed();
        peer.join().unwrap();
        if matches!(fault, ReplyFault::Slow) {
            assert!(elapsed < Duration::from_secs(7), "{elapsed:?}");
        }
        assert_eq!(result.status.code(), Some(expected), "{fault:?} {result:?}");
        assert!(result.stdout.is_empty(), "{result:?}");
    }
}

fn faulty_peer(listener: UnixListener, fault: ReplyFault) {
    let mut stream = accept_bounded(&listener);
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let mut hello = [0; agent::HDR];
    stream.read_exact(&mut hello).unwrap();
    assert_eq!(hello, agent::HELLO);
    let ticket = [1; agent::TICKET_LEN];
    let next_ticket = [2; agent::TICKET_LEN];
    stream.write_all(&[0, 16, 0, 0, 0]).unwrap();
    stream.write_all(&ticket).unwrap();
    let begin = read_operation(&mut stream, &ticket, agent::OP_BEGIN);
    assert_eq!(begin, 0);
    stream.write_all(&[0; 5]).unwrap();
    stream.write_all(&next_ticket).unwrap();
    let len = read_operation(&mut stream, &next_ticket, agent::OP_OPEN);
    assert!(len > 0);
    let bad = match fault {
        ReplyFault::Short => len - 1,
        ReplyFault::Long => len + 1,
        ReplyFault::Disconnect => return,
        ReplyFault::Slow => {
            send_slow_header(&mut stream, len);
            return;
        }
    };
    let mut header = [0; 5];
    header[1..].copy_from_slice(&bad.to_le_bytes());
    stream.write_all(&header).unwrap();
    let mut extra = [0u8; 1];
    assert_eq!(stream.read(&mut extra).unwrap(), 0);
}

fn send_slow_header(stream: &mut UnixStream, len: u32) {
    let mut header = [0; 5];
    header[1..].copy_from_slice(&len.to_le_bytes());
    for (index, byte) in header.iter().enumerate() {
        if index != 0 {
            thread::sleep(Duration::from_millis(1_400));
        }
        if let Err(error) = stream.write_all(&[*byte]) {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
            return;
        }
    }
    panic!("native client accepted a header past its deadline");
}

fn read_operation(stream: &mut UnixStream, ticket: &[u8; agent::TICKET_LEN], op: u8) -> u32 {
    let mut presented = [0; agent::TICKET_LEN];
    stream.read_exact(&mut presented).unwrap();
    assert_eq!(&presented, ticket);
    let mut header = [0; agent::HDR];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header[..5], agent::HELLO[..5]);
    assert_eq!(header[5], op);
    let len = u32::from_le_bytes(
        header[agent::OFF_LEN..agent::OFF_LEN + 4]
            .try_into()
            .unwrap(),
    );
    assert!(len as usize <= agent::MAX_BODY);
    stream.read_exact(&mut vec![0; len as usize]).unwrap();
    len
}

fn accept_bounded(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        match listener.accept() {
            Ok((socket, _)) => return socket,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("lab peer did not connect: {error}"),
        }
    }
}

#[test]
fn external_native_selected_function_repeats_cleanly() {
    let lab = Lab::new();
    let socket = lab.socket();
    let carrier = vmkek::elf::sample::build().unwrap();
    let settings = options(Some("mix"));
    let protected =
        protect::protect_external(&carrier, &settings, socket.to_str().unwrap()).unwrap();
    let path = lab.executable(&protected.bytes);
    let _agent = agent::Agent::listen(
        socket.to_str().unwrap(),
        &protected.bytes,
        protected.custody.unwrap(),
    )
    .unwrap();
    let started = Instant::now();
    let result = direct(&path);
    eprintln!(
        "selected native sample completed in {:.3}s",
        started.elapsed().as_secs_f64()
    );
    assert!(result.status.success(), "{result:?}");
    assert_eq!(result.stdout, vmkek::sample::line().into_bytes());
}

#[test]
#[ignore = "manual native workload timing for whole-image Lab virtualization"]
fn external_native_full_carrier_budget_probe() {
    let lab = Lab::new();
    let socket = lab.socket();
    let carrier = vmkek::elf::sample::build().unwrap();
    let protected =
        protect::protect_external(&carrier, &options(None), socket.to_str().unwrap()).unwrap();
    let path = lab.executable(&protected.bytes);
    let _agent = agent::Agent::listen(
        socket.to_str().unwrap(),
        &protected.bytes,
        protected.custody.unwrap(),
    )
    .unwrap();
    let started = Instant::now();
    let result = direct(&path);
    eprintln!(
        "whole-image native sample completed in {:.3}s with exit {:?}",
        started.elapsed().as_secs_f64(),
        result.status.code()
    );
    if result.status.success() {
        assert_eq!(result.stdout, vmkek::sample::line().into_bytes());
    } else {
        assert_eq!(result.status.code(), Some(6), "{result:?}");
        assert!(result.stdout.is_empty(), "{result:?}");
    }
}

#[test]
fn external_native_nested_vm_calls() {
    let lab = Lab::new();
    let original = short_nested_carrier();
    let socket = lab.socket();
    let mut settings = options(Some("mix"));
    settings.virtualize.insert("compute".into());
    settings.seed = 0xC8_0002;
    let protected =
        protect::protect_external(&original, &settings, socket.to_str().unwrap()).unwrap();
    let path = lab.executable(&protected.bytes);
    let _agent = agent::Agent::listen(
        socket.to_str().unwrap(),
        &protected.bytes,
        protected.custody.unwrap(),
    )
    .unwrap();
    let result = direct(&path);
    assert!(result.status.success(), "{result:?}");
    let expected = format!(
        "vmkek-ok:{}
",
        vmkek::sample::compute(1)
    );
    assert_eq!(result.stdout, expected.into_bytes());
}

fn short_nested_carrier() -> Vec<u8> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
    let mut file = vmkek::elf::sample::build().unwrap();
    let image = vmkek::elf::parse(&file).unwrap();
    let start = image
        .exports
        .iter()
        .find(|symbol| symbol.name.as_bytes() == b"start")
        .unwrap();
    let segment = image
        .segments
        .iter()
        .find(|segment| {
            segment.kind == vmkek::elf::SegmentKind::Load
                && (segment.vaddr..segment.vaddr + segment.filesz).contains(&start.value)
        })
        .unwrap();
    let begin = (segment.offset + start.value - segment.vaddr) as usize;
    let end = begin + start.size as usize;
    let mut decoder = Decoder::with_ip(64, &file[begin..end], start.value, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_register() == Register::RDI
            && matches!(
                instruction.op1_kind(),
                OpKind::Immediate32to64 | OpKind::Immediate64
            )
            && instruction.immediate(1) == 10
        {
            let immediate = decoder
                .get_constant_offsets(&instruction)
                .immediate_offset();
            let offset = begin + (instruction.ip() - start.value) as usize + immediate;
            file[offset] = 1;
            return file;
        }
    }
    panic!("nested fixture input argument missing");
}

#[test]
fn external_native_two_thread_leaf_calls() {
    let lab = Lab::new();
    let input = threaded_carrier();
    let original = lab.executable(&input);
    let original_run = direct(&original);
    assert!(original_run.status.success(), "{original_run:?}");
    assert_eq!(original_run.stdout, b"r03-workers-ok\n");
    let socket = lab.socket();
    let settings = options(Some("mix"));
    let protected = protect::protect_external(&input, &settings, socket.to_str().unwrap()).unwrap();
    let path = lab.executable(&protected.bytes);
    let _agent = agent::Agent::listen(
        socket.to_str().unwrap(),
        &protected.bytes,
        protected.custody.unwrap(),
    )
    .unwrap();
    let started = Instant::now();
    let result = direct(&path);
    eprintln!(
        "two-thread native sample completed in {:.3}s",
        started.elapsed().as_secs_f64()
    );
    assert!(result.status.success(), "{result:?}");
    assert_eq!(result.stdout, b"r03-workers-ok\n");
}

fn threaded_carrier() -> Vec<u8> {
    use iced_x86::code_asm::*;
    const BASE: u64 = vmkek::elf::sample::IMAGE_BASE;
    const ENTRY: u64 = BASE + 0x1600;

    let mut bytes = vmkek::elf::sample::build().unwrap();
    let image = vmkek::elf::parse(&bytes).unwrap();
    let mix = image
        .exports
        .iter()
        .find(|symbol| symbol.name.as_bytes() == b"mix")
        .unwrap()
        .value;
    let mut code = CodeAssembler::new(64).unwrap();
    let mut child = code.create_label();
    let mut worker = code.create_label();
    let fail = code.create_label();
    emit_fixture_clone(&mut code, child, fail);
    code.mov(r13d, 1u32).unwrap();
    code.jmp(worker).unwrap();
    code.set_label(&mut child).unwrap();
    code.mov(r13d, 2u32).unwrap();
    code.set_label(&mut worker).unwrap();
    emit_fixture_worker(&mut code, mix, fail);
    emit_fixture_worker_exit(&mut code, fail);
    let code = code.assemble(ENTRY).unwrap();
    let offset = (ENTRY - BASE) as usize;
    assert!(offset + code.len() < 0x2000);
    assert!(bytes[offset..offset + code.len()]
        .iter()
        .all(|byte| *byte == 0));
    bytes[offset..offset + code.len()].copy_from_slice(&code);

    let mut jump = CodeAssembler::new(64).unwrap();
    jump.jmp(ENTRY).unwrap();
    let jump = jump.assemble(image.entry).unwrap();
    let start = (image.entry - BASE) as usize;
    bytes[start..start + jump.len()].copy_from_slice(&jump);
    bytes
}

fn emit_fixture_clone(
    a: &mut iced_x86::code_asm::CodeAssembler,
    child: iced_x86::code_asm::CodeLabel,
    fail: iced_x86::code_asm::CodeLabel,
) {
    use iced_x86::code_asm::*;
    // Anonymous RW memory holds the barrier, results, and the second thread's stack.
    a.mov(eax, 9u32).unwrap();
    a.xor(edi, edi).unwrap();
    a.mov(esi, 0x12000u32).unwrap();
    a.mov(edx, 3u32).unwrap();
    a.mov(r10d, 0x22u32).unwrap();
    a.mov(r8, -1i64).unwrap();
    a.xor(r9d, r9d).unwrap();
    a.syscall().unwrap();
    a.test(rax, rax).unwrap();
    a.js(fail).unwrap();
    a.mov(r12, rax).unwrap();
    a.lea(rsi, qword_ptr(r12 + 0x11000i32)).unwrap();
    // Linux clone creates a thread sharing memory and descriptor table.
    a.mov(eax, 56u32).unwrap();
    a.mov(edi, 0x10f00u32).unwrap();
    a.xor(edx, edx).unwrap();
    a.xor(r10d, r10d).unwrap();
    a.xor(r8d, r8d).unwrap();
    a.syscall().unwrap();
    a.test(rax, rax).unwrap();
    a.js(fail).unwrap();
    a.jz(child).unwrap();
}

fn emit_fixture_worker(
    a: &mut iced_x86::code_asm::CodeAssembler,
    mix: u64,
    fail: iced_x86::code_asm::CodeLabel,
) {
    use iced_x86::code_asm::*;
    let mut ready = a.create_label();
    let mut call = a.create_label();
    a.lock().inc(dword_ptr(r12)).unwrap();
    a.set_label(&mut ready).unwrap();
    a.pause().unwrap();
    a.cmp(dword_ptr(r12), 2i32).unwrap();
    a.jne(ready).unwrap();
    a.mov(r14d, 2u32).unwrap();
    a.set_label(&mut call).unwrap();
    a.mov(edi, r13d).unwrap();
    a.call(mix).unwrap();
    a.imul_3(rcx, r13, 7i32).unwrap();
    a.add(rcx, 3i32).unwrap();
    a.xor(rcx, 0x5ai32).unwrap();
    a.cmp(rax, rcx).unwrap();
    a.jne(fail).unwrap();
    a.dec(r14d).unwrap();
    a.jnz(call).unwrap();
    a.lock().inc(dword_ptr(r12 + 8i32)).unwrap();
}

fn emit_fixture_worker_exit(
    a: &mut iced_x86::code_asm::CodeAssembler,
    mut fail: iced_x86::code_asm::CodeLabel,
) {
    use iced_x86::code_asm::*;
    let mut main = a.create_label();
    let mut message = a.create_label();
    let mut exit = a.create_label();
    const LINE: &[u8] = b"r03-workers-ok\n";
    a.cmp(r13d, 1u32).unwrap();
    a.je(main).unwrap();
    a.mov(eax, 60u32).unwrap();
    a.xor(edi, edi).unwrap();
    a.syscall().unwrap();
    a.ud2().unwrap();
    a.set_label(&mut main).unwrap();
    a.pause().unwrap();
    a.cmp(dword_ptr(r12 + 8i32), 2i32).unwrap();
    a.jne(main).unwrap();
    a.mov(eax, 1u32).unwrap();
    a.mov(edi, 1u32).unwrap();
    a.lea(rsi, qword_ptr(message)).unwrap();
    a.mov(edx, LINE.len() as u32).unwrap();
    a.syscall().unwrap();
    a.cmp(eax, LINE.len() as u32).unwrap();
    a.jne(fail).unwrap();
    a.xor(edi, edi).unwrap();
    a.jmp(exit).unwrap();
    a.set_label(&mut fail).unwrap();
    a.mov(edi, 1u32).unwrap();
    a.set_label(&mut exit).unwrap();
    a.mov(eax, 231u32).unwrap();
    a.syscall().unwrap();
    a.ud2().unwrap();
    a.set_label(&mut message).unwrap();
    a.db(LINE).unwrap();
}
