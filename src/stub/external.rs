//! External-key client. The raw ChaCha20 key never enters this image.
//!
//! A flag byte selects the mode. Zero keeps the S3b chain. One asks a local
//! agent for a single plaintext block after sending the SHA-256 of the image.
//! That hash is a software measurement on M-LINUX, not a TPM, SEV-SNP, or TDX quote.

use iced_x86::code_asm::*;

use crate::agent::{self, HDR, MAX_BODY, PATH_CAP};
use crate::error::Result;
use crate::vm::{
    CACHE_OPEN, CTX_BOUND, CTX_CACHE, CTX_KEYS, CTX_LEVEL, INNER_CAP, INNER_CIPHER, INNER_LEN,
    RT_FOLD, RT_SALT, RUNTIME_WINDOW, TABLES_AT, WEAVE_SAVE,
};

use super::ice;

const DIE_HASH: u32 = 0xC801;
const DIE_SOCKET: u32 = 0xC802;
const DIE_IO: u32 = 0xC803;
const DIE_DENY: u32 = 0xC804;
const DIE_LEN: u32 = 0xC805;
const DIE_DEADLINE: u32 = 0xC806;
const GS_AGENT_STATE: i32 = 0x198;
const FD: i32 = 0;
const HASH_FD: i32 = 4;
const REQUEST_LEN: i32 = 8;
const EXPECTED_LEN: i32 = 12;
const THREAD_ID: i32 = 16;
const DEPTH: i32 = 20;
const SEQUENCE: i32 = 24;
const NEXT_CALL: i32 = 32;
const CALLS: i32 = 40;
const MAX_CALLS: u32 = crate::vm::CALL_DEPTH_LIMIT;
const DESTINATION: i32 = 0x128;
const HASH: i32 = 0x130;
const HASH_STATE: i32 = 0x150;
const HASH_CHUNK: i32 = 0x170;
const HASH_FILLED: i32 = 0x1b0;
const HASH_TOTAL: i32 = 0x1b8;
const HASH_WORK: i32 = 0x1c0;
const HASH_WORDS: i32 = 0x1e0;
const SHOT_RESIDENT: i32 = 0x2e0;
const CLOCK: i32 = 0x2e8;
const FRAME_DEADLINE: i32 = 0x2f8;
const CALL_DEADLINE: i32 = 0x300;
const POLL: i32 = 0x308;
const REMAINING: i32 = 0x310;
const TICKET: i32 = 0x340;
const NANOS_PER_SECOND: u64 = 1_000_000_000;
const REQUEST: i32 = TICKET + agent::TICKET_LEN as i32;
const RESPONSE: i32 = REQUEST + (HDR + MAX_BODY) as i32;
const INNER_BUFFER: i32 = RESPONSE + (5 + MAX_BODY + agent::TICKET_LEN) as i32;
const STATE_BYTES: i32 = 0x5000;
const _: () = assert!(CALLS + MAX_CALLS as i32 * 8 <= HASH);
const _: () = assert!(INNER_BUFFER + INNER_CAP <= STATE_BYTES);

const SHA_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SHA_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Bytes that `install_socket` finds. The flag and the path follow them.
pub(super) const SOCKET_MARK: &[u8] = b"VMK8SOCK";
/// Flag offset from the mark. The next two bytes are the `AF_UNIX` family.
pub(super) const FLAG_AT: usize = SOCKET_MARK.len();
/// Path offset from the mark.
pub(super) const PATH_AT: usize = FLAG_AT + 1 + 2;

pub(super) struct Slots {
    flag: CodeLabel,
    k: CodeLabel,
    hello: CodeLabel,
    addr: CodeLabel,
    exe: CodeLabel,
    pub(super) fetch: CodeLabel,
    pub(super) begin_gate: CodeLabel,
    begin: CodeLabel,
    commit: CodeLabel,
    inner: CodeLabel,
    hash_file: CodeLabel,
    init: CodeLabel,
    absorb: CodeLabel,
    block: CodeLabel,
    finish: CodeLabel,
    connect: CodeLabel,
    now: CodeLabel,
    remaining: CodeLabel,
    wait_io: CodeLabel,
    check_reply: CodeLabel,
    write_all: CodeLabel,
    read_all: CodeLabel,
    copy: CodeLabel,
    zero: CodeLabel,
    fill: CodeLabel,
    exchange: CodeLabel,
    cleanup: CodeLabel,
    die: CodeLabel,
}

impl Slots {
    pub(super) fn new(a: &mut CodeAssembler) -> Self {
        Self {
            flag: a.create_label(),
            k: a.create_label(),
            hello: a.create_label(),
            addr: a.create_label(),
            exe: a.create_label(),
            fetch: a.create_label(),
            begin_gate: a.create_label(),
            begin: a.create_label(),
            commit: a.create_label(),
            inner: a.create_label(),
            hash_file: a.create_label(),
            init: a.create_label(),
            absorb: a.create_label(),
            block: a.create_label(),
            finish: a.create_label(),
            connect: a.create_label(),
            now: a.create_label(),
            remaining: a.create_label(),
            wait_io: a.create_label(),
            check_reply: a.create_label(),
            write_all: a.create_label(),
            read_all: a.create_label(),
            copy: a.create_label(),
            zero: a.create_label(),
            fill: a.create_label(),
            exchange: a.create_label(),
            cleanup: a.create_label(),
            die: a.create_label(),
        }
    }
}

fn go(step: std::result::Result<(), iced_x86::IcedError>) -> Result<()> {
    step.map_err(ice)
}

/// When the flag is set, replace the in-process decrypt and return.
pub(super) fn emit_fetch_gate(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    if super::chain::pe_tls_bound() {
        return Ok(());
    }
    let mut offline = a.create_label();
    go(a.cmp(byte_ptr(slots.flag), 0i32))?;
    go(a.je(offline))?;
    go(a.call(slots.fetch))?;
    go(a.ret())?;
    go(a.set_label(&mut offline))?;
    Ok(())
}

/// When the flag is set, the agent checks the woven terminal.
pub(super) fn emit_commit_gate(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    if super::chain::pe_tls_bound() {
        return Ok(());
    }
    let mut offline = a.create_label();
    go(a.cmp(byte_ptr(slots.flag), 0i32))?;
    go(a.je(offline))?;
    go(a.call(slots.commit))?;
    go(a.ret())?;
    go(a.set_label(&mut offline))?;
    Ok(())
}

/// When the flag is set, read this call's level-2 program into private scratch.
pub(super) fn emit_inner_gate(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    if super::chain::pe_tls_bound() {
        return Ok(());
    }
    let mut offline = a.create_label();
    go(a.cmp(byte_ptr(slots.flag), 0i32))?;
    go(a.je(offline))?;
    go(a.call(slots.inner))?;
    go(a.ret())?;
    go(a.set_label(&mut offline))?;
    Ok(())
}

pub(super) fn emit_code(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    emit_begin(a, slots)?;
    emit_fetch(a, slots)?;
    emit_commit(a, slots)?;
    emit_inner(a, slots)?;
    emit_hash_file(a, slots)?;
    emit_init(a, slots)?;
    emit_absorb(a, slots)?;
    emit_block(a, slots)?;
    emit_finish(a, slots)?;
    emit_connect(a, slots)?;
    emit_clock(a, slots)?;
    emit_io_wait(a, slots)?;
    emit_check_reply(a, slots)?;
    emit_write_all(a, slots)?;
    emit_read_all(a, slots)?;
    emit_copy(a, slots)?;
    emit_zero(a, slots)?;
    emit_fill(a, slots)?;
    emit_exchange(a, slots)?;
    emit_cleanup(a, slots)?;
    emit_die(a, slots)
}

pub(super) fn emit_data(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.db(SOCKET_MARK))?;
    go(a.set_label(&mut slots.flag))?;
    go(a.db(&[0]))?;
    go(a.set_label(&mut slots.addr))?;
    go(a.db(&1u16.to_le_bytes()))?;
    go(a.db(&[0u8; PATH_CAP]))?;
    go(a.set_label(&mut slots.exe))?;
    go(a.db(b"/proc/self/exe\0"))?;
    go(a.set_label(&mut slots.k))?;
    let table: Vec<u8> = SHA_K.iter().flat_map(|word| word.to_le_bytes()).collect();
    go(a.db(&table))?;
    go(a.set_label(&mut slots.hello))?;
    go(a.db(&agent::HELLO))
}

fn emit_begin(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    let mut active = a.create_label();
    go(a.set_label(&mut slots.begin_gate))?;
    go(a.cmp(byte_ptr(slots.flag), 0i32))?;
    go(a.jne(slots.begin))?;
    go(a.ret())?;
    go(a.set_label(&mut slots.begin))?;
    emit_save(a)?;
    state_load(a)?;
    // The Linux frame has one native entry slot. Direct VM recursion uses its
    // own frame stack without increasing the native trampoline nesting level.
    super::chain::emit_load_r11(a)?;
    go(a.mov(edi, DIE_DENY))?;
    go(a.cmp(dword_ptr(r11 + CTX_LEVEL), 1i32))?;
    go(a.ja(slots.die))?;
    go(a.test(r12, r12))?;
    go(a.jnz(active))?;
    emit_new_state(a, slots)?;
    go(a.call(slots.hash_file))?;
    go(a.call(slots.connect))?;
    go(a.call(slots.now))?;
    emit_deadline_add(a, slots, agent::CALL_LIFETIME_SECS)?;
    go(a.mov(qword_ptr(r12 + CALL_DEADLINE), rax))?;
    go(a.set_label(&mut active))?;
    emit_push_call(a, slots)?;
    emit_empty(a, slots, agent::OP_BEGIN)?;
    emit_restore(a)?;
    go(a.ret())
}

fn emit_new_state(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.mov(eax, 9u32))?;
    go(a.xor(edi, edi))?;
    go(a.mov(esi, STATE_BYTES))?;
    go(a.mov(edx, 3u32))?;
    go(a.mov(r10d, 0x22u32))?;
    go(a.mov(r8, -1i64))?;
    go(a.xor(r9d, r9d))?;
    go(a.syscall())?;
    go(a.test(rax, rax))?;
    go(a.mov(edi, DIE_SOCKET))?;
    go(a.js(slots.die))?;
    go(a.mov(r12, rax))?;
    state_store(a)?;
    go(a.mov(dword_ptr(r12 + FD), -1i32))?;
    go(a.mov(dword_ptr(r12 + HASH_FD), -1i32))?;
    go(a.mov(eax, 186u32))?;
    go(a.syscall())?;
    go(a.test(eax, eax))?;
    go(a.mov(edi, DIE_SOCKET))?;
    go(a.jle(slots.die))?;
    go(a.mov(dword_ptr(r12 + THREAD_ID), eax))
}

fn emit_push_call(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.mov(ecx, dword_ptr(r12 + DEPTH)))?;
    go(a.mov(edi, DIE_LEN))?;
    go(a.cmp(ecx, MAX_CALLS))?;
    go(a.jae(slots.die))?;
    go(a.add(qword_ptr(r12 + NEXT_CALL), 1i32))?;
    go(a.jc(slots.die))?;
    go(a.mov(rax, qword_ptr(r12 + NEXT_CALL)))?;
    go(a.mov(qword_ptr(r12 + rcx * 8 + CALLS), rax))?;
    go(a.inc(dword_ptr(r12 + DEPTH)))
}

fn emit_fetch(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.fetch))?;
    emit_save(a)?;
    require_state(a, slots)?;
    emit_open_body(a, slots)?;
    go(a.mov(r15d, u32::from(agent::OP_OPEN)))?;
    go(a.call(slots.fill))?;
    go(a.call(slots.exchange))?;
    emit_install(a, slots)?;
    emit_resident_once(a, slots)?;
    emit_restore(a)?;
    go(a.ret())
}

fn emit_resident_once(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    let mut done = a.create_label();
    go(a.cmp(byte_ptr(r12 + SHOT_RESIDENT), 0i32))?;
    go(a.jne(done))?;
    go(a.cmp(dword_ptr(r12 + EXPECTED_LEN), 8i32))?;
    go(a.jb(done))?;
    emit_empty(a, slots, agent::OP_RESIDENT)?;
    go(a.mov(byte_ptr(r12 + SHOT_RESIDENT), 1u32))?;
    go(a.set_label(&mut done))?;
    go(a.nop())
}

fn require_state(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    state_load(a)?;
    go(a.mov(edi, DIE_DENY))?;
    go(a.test(r12, r12))?;
    go(a.jz(slots.die))?;
    go(a.mov(eax, dword_ptr(r12 + DEPTH)))?;
    go(a.test(eax, eax))?;
    go(a.jz(slots.die))?;
    go(a.cmp(eax, MAX_CALLS))?;
    go(a.ja(slots.die))
}

fn emit_save(a: &mut CodeAssembler) -> Result<()> {
    go(a.push(rbx))?;
    go(a.push(r12))?;
    go(a.push(r13))?;
    go(a.push(r14))
}

fn emit_restore(a: &mut CodeAssembler) -> Result<()> {
    go(a.pop(r14))?;
    go(a.pop(r13))?;
    go(a.pop(r12))?;
    go(a.pop(rbx))
}

fn state_load(a: &mut CodeAssembler) -> Result<()> {
    let mut instruction = vec![0x65, 0x4c, 0x8b, 0x24, 0x25];
    instruction.extend_from_slice(&GS_AGENT_STATE.to_le_bytes());
    go(a.db(&instruction))
}

fn state_store(a: &mut CodeAssembler) -> Result<()> {
    let mut instruction = vec![0x65, 0x4c, 0x89, 0x24, 0x25];
    instruction.extend_from_slice(&GS_AGENT_STATE.to_le_bytes());
    go(a.db(&instruction))
}

fn emit_open_body(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.mov(edi, DIE_LEN))?;
    go(a.mov(r9, qword_ptr(r13)))?;
    go(a.cmp(r9, 0x10000i32))?;
    go(a.ja(slots.die))?;
    go(a.cmp(r14, r9))?;
    go(a.jae(slots.die))?;
    go(a.mov(r8, r13))?;
    go(a.add(r8, RUNTIME_WINDOW as i32))?;
    go(a.jc(slots.die))?;
    emit_table_value(a, slots, 32)?;
    go(a.mov(ecx, eax))?;
    go(a.test(ecx, ecx))?;
    go(a.jz(slots.die))?;
    go(a.cmp(ecx, MAX_BODY as u32))?;
    go(a.ja(slots.die))?;
    go(a.mov(dword_ptr(r12 + REQUEST_LEN), ecx))?;
    go(a.mov(dword_ptr(r12 + EXPECTED_LEN), ecx))?;
    emit_table_value(a, slots, 16)?;
    emit_copy_block(a, slots)
}

fn emit_table_value(a: &mut CodeAssembler, slots: &Slots, field: i32) -> Result<()> {
    go(a.mov(rax, qword_ptr(r13 + field)))?;
    go(a.lea(rsi, qword_ptr(r13 + TABLES_AT)))?;
    go(a.cmp(rax, rsi))?;
    go(a.jb(slots.die))?;
    go(a.lea(rsi, qword_ptr(r14 * 4 + 4i32)))?;
    go(a.add(rsi, rax))?;
    go(a.jc(slots.die))?;
    go(a.cmp(rsi, r8))?;
    go(a.ja(slots.die))?;
    go(a.mov(eax, dword_ptr(rsi - 4i32)))
}

fn emit_copy_block(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.mov(edx, dword_ptr(r13 + RT_FOLD)))?;
    go(a.lea(rsi, qword_ptr(rax + rcx)))?;
    go(a.cmp(rsi, rdx))?;
    go(a.ja(slots.die))?;
    go(a.mov(rsi, qword_ptr(r13 + 24i32)))?;
    go(a.lea(r10, qword_ptr(r13 + TABLES_AT)))?;
    go(a.cmp(rsi, r10))?;
    go(a.jb(slots.die))?;
    go(a.add(rdx, rsi))?;
    go(a.jc(slots.die))?;
    go(a.cmp(rdx, r8))?;
    go(a.ja(slots.die))?;
    go(a.add(rsi, rax))?;
    emit_cache_target(a, slots)?;
    go(a.lea(rdi, qword_ptr(r12 + REQUEST + HDR as i32)))?;
    go(a.call(slots.copy))
}

fn emit_cache_target(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    super::chain::emit_load_r11(a)?;
    go(a.cmp(qword_ptr(r11 + CTX_BOUND), r13))?;
    go(a.jne(slots.die))?;
    go(a.mov(r8, qword_ptr(r11 + CTX_KEYS)))?;
    go(a.test(r8, r8))?;
    go(a.jz(slots.die))?;
    go(a.mov(rdx, r9))?;
    go(a.add(rdx, rax))?;
    go(a.jc(slots.die))?;
    go(a.add(rdx, rcx))?;
    go(a.jc(slots.die))?;
    go(a.cmp(rdx, qword_ptr(r8 - 8i32)))?;
    go(a.ja(slots.die))?;
    go(a.mov(r10, qword_ptr(r11 + CTX_CACHE)))?;
    go(a.test(r10, r10))?;
    go(a.jz(slots.die))?;
    go(a.add(r10, r9))?;
    go(a.jc(slots.die))?;
    go(a.add(r10, rax))?;
    go(a.jc(slots.die))?;
    go(a.mov(rdx, r10))?;
    go(a.add(rdx, rcx))?;
    go(a.jc(slots.die))?;
    go(a.mov(qword_ptr(r12 + DESTINATION), r10))
}

fn emit_commit(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    let mut nested = a.create_label();
    go(a.set_label(&mut slots.commit))?;
    emit_save(a)?;
    require_state(a, slots)?;
    emit_empty(a, slots, agent::OP_COMMIT)?;
    go(a.dec(dword_ptr(r12 + DEPTH)))?;
    go(a.mov(ecx, dword_ptr(r12 + DEPTH)))?;
    go(a.mov(qword_ptr(r12 + rcx * 8 + CALLS), 0i32))?;
    go(a.test(ecx, ecx))?;
    go(a.jnz(nested))?;
    go(a.call(slots.cleanup))?;
    go(a.set_label(&mut nested))?;
    emit_restore(a)?;
    go(a.ret())
}

fn emit_inner(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.inner))?;
    emit_save(a)?;
    require_state(a, slots)?;
    go(a.mov(ecx, dword_ptr(r13 + INNER_LEN)))?;
    go(a.mov(edi, DIE_LEN))?;
    go(a.test(ecx, ecx))?;
    go(a.jz(slots.die))?;
    go(a.cmp(ecx, INNER_CAP))?;
    go(a.ja(slots.die))?;
    go(a.mov(dword_ptr(r12 + REQUEST_LEN), ecx))?;
    go(a.mov(dword_ptr(r12 + EXPECTED_LEN), ecx))?;
    go(a.lea(rsi, qword_ptr(r13 + INNER_CIPHER)))?;
    go(a.lea(rdi, qword_ptr(r12 + REQUEST + HDR as i32)))?;
    go(a.call(slots.copy))?;
    go(a.mov(r15d, u32::from(agent::OP_INNER)))?;
    go(a.call(slots.fill))?;
    go(a.call(slots.exchange))?;
    go(a.mov(ecx, dword_ptr(r12 + EXPECTED_LEN)))?;
    go(a.lea(rsi, qword_ptr(r12 + RESPONSE + 5i32)))?;
    go(a.lea(rdi, qword_ptr(r12 + INNER_BUFFER)))?;
    go(a.call(slots.copy))?;
    emit_clear_response(a, slots)?;
    go(a.lea(rsi, qword_ptr(r12 + INNER_BUFFER)))?;
    emit_restore(a)?;
    go(a.ret())
}

pub(super) fn emit_private_inner_wipe(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.push(r12))?;
    require_state(a, slots)?;
    go(a.lea(rdi, qword_ptr(r12 + INNER_BUFFER)))?;
    go(a.mov(ecx, INNER_CAP))?;
    go(a.call(slots.zero))?;
    go(a.pop(r12))?;
    go(a.ret())
}

fn emit_empty(a: &mut CodeAssembler, slots: &Slots, op: u8) -> Result<()> {
    go(a.mov(dword_ptr(r12 + REQUEST_LEN), 0i32))?;
    go(a.mov(dword_ptr(r12 + EXPECTED_LEN), 0i32))?;
    go(a.mov(r15d, u32::from(op)))?;
    go(a.call(slots.fill))?;
    go(a.call(slots.exchange))?;
    emit_clear_response(a, slots)
}

fn emit_hash_file(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.hash_file))?;
    go(a.call(slots.init))?;
    emit_hash_read(a, slots)?;
    go(a.call(slots.finish))?;
    go(a.ret())
}

fn emit_hash_read(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    let mut step = a.create_label();
    let mut eof = a.create_label();
    open_exe(a, slots)?;
    go(a.set_label(&mut step))?;
    go(a.mov(edi, dword_ptr(r12 + HASH_FD)))?;
    go(a.lea(rsi, qword_ptr(r12 + REQUEST)))?;
    go(a.mov(edx, 4096u32))?;
    go(a.xor(eax, eax))?;
    go(a.syscall())?;
    go(a.cmp(eax, -4i32))?;
    go(a.je(step))?;
    go(a.test(rax, rax))?;
    go(a.jz(eof))?;
    go(a.mov(edi, DIE_HASH))?;
    go(a.js(slots.die))?;
    go(a.mov(rdx, rax))?;
    go(a.lea(rsi, qword_ptr(r12 + REQUEST)))?;
    go(a.call(slots.absorb))?;
    go(a.jmp(step))?;
    go(a.set_label(&mut eof))?;
    close_fd(a)?;
    Ok(())
}

fn open_exe(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.mov(eax, 257u32))?;
    go(a.mov(rdi, -100i64))?;
    go(a.lea(rsi, qword_ptr(slots.exe)))?;
    go(a.mov(edx, 0x80000u32))?;
    go(a.xor(r10, r10))?;
    go(a.syscall())?;
    go(a.test(rax, rax))?;
    go(a.mov(edi, DIE_HASH))?;
    go(a.js(slots.die))?;
    go(a.mov(dword_ptr(r12 + HASH_FD), eax))?;
    Ok(())
}

fn close_fd(a: &mut CodeAssembler) -> Result<()> {
    close_slot(a, HASH_FD)
}

fn emit_init(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.init))?;
    go(a.lea(r8, qword_ptr(r12 + HASH_STATE)))?;
    for (index, word) in SHA_IV.iter().enumerate() {
        go(a.mov(eax, *word))?;
        go(a.mov(dword_ptr(r8 + (index as i32) * 4), eax))?;
    }
    go(a.mov(qword_ptr(r12 + HASH_TOTAL), 0i32))?;
    go(a.mov(dword_ptr(r12 + HASH_FILLED), 0i32))?;
    go(a.ret())?;
    Ok(())
}

fn emit_absorb(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.absorb))?;
    emit_absorb_step(a, slots)?;
    go(a.ret())?;
    Ok(())
}

fn emit_absorb_step(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    let mut done = a.create_label();
    let mut copy = a.create_label();
    let mut copied = a.create_label();
    go(a.test(rdx, rdx))?;
    go(a.jz(done))?;
    go(a.mov(r9d, dword_ptr(r12 + HASH_FILLED)))?;
    go(a.mov(r10d, 64u32))?;
    go(a.sub(r10d, r9d))?;
    go(a.cmp(rdx, r10))?;
    go(a.jae(copy))?;
    go(a.mov(r10, rdx))?;
    go(a.set_label(&mut copy))?;
    emit_absorb_copy(a, &copied)?;
    go(a.set_label(&mut copied))?;
    go(a.add(rsi, r10))?;
    go(a.sub(rdx, r10))?;
    go(a.add(qword_ptr(r12 + HASH_TOTAL), r10))?;
    go(a.add(dword_ptr(r12 + HASH_FILLED), r10d))?;
    go(a.cmp(dword_ptr(r12 + HASH_FILLED), 64u32))?;
    go(a.jb(slots.absorb))?;
    go(a.push(rsi))?;
    go(a.push(rdx))?;
    go(a.call(slots.block))?;
    go(a.pop(rdx))?;
    go(a.pop(rsi))?;
    go(a.mov(dword_ptr(r12 + HASH_FILLED), 0i32))?;
    go(a.jmp(slots.absorb))?;
    go(a.set_label(&mut done))?;
    Ok(())
}

fn emit_absorb_copy(a: &mut CodeAssembler, copied: &CodeLabel) -> Result<()> {
    let mut next = a.create_label();
    go(a.lea(r11, qword_ptr(r12 + HASH_CHUNK)))?;
    go(a.add(r11, r9))?;
    go(a.xor(ecx, ecx))?;
    go(a.set_label(&mut next))?;
    go(a.cmp(rcx, r10))?;
    go(a.jae(*copied))?;
    go(a.mov(al, byte_ptr(rsi + rcx)))?;
    go(a.mov(byte_ptr(r11 + rcx), al))?;
    go(a.inc(ecx))?;
    go(a.jmp(next))?;
    Ok(())
}

fn emit_block(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.block))?;
    emit_load_words(a)?;
    emit_expand(a)?;
    emit_rounds(a, slots)?;
    emit_add_state(a)?;
    go(a.ret())?;
    Ok(())
}

fn emit_load_words(a: &mut CodeAssembler) -> Result<()> {
    let mut next = a.create_label();
    let mut done = a.create_label();
    go(a.lea(r8, qword_ptr(r12 + HASH_WORDS)))?;
    go(a.lea(r9, qword_ptr(r12 + HASH_CHUNK)))?;
    go(a.xor(r15d, r15d))?;
    go(a.set_label(&mut next))?;
    go(a.cmp(r15d, 16u32))?;
    go(a.jae(done))?;
    go(a.mov(eax, dword_ptr(r9 + r15 * 4)))?;
    go(a.bswap(eax))?;
    go(a.mov(dword_ptr(r8 + r15 * 4), eax))?;
    go(a.inc(r15d))?;
    go(a.jmp(next))?;
    go(a.set_label(&mut done))?;
    Ok(())
}

fn emit_expand(a: &mut CodeAssembler) -> Result<()> {
    let mut next = a.create_label();
    let mut done = a.create_label();
    go(a.lea(r8, qword_ptr(r12 + HASH_WORDS)))?;
    go(a.mov(r15d, 16u32))?;
    go(a.set_label(&mut next))?;
    go(a.cmp(r15d, 64u32))?;
    go(a.jae(done))?;
    emit_sched(a)?;
    go(a.inc(r15d))?;
    go(a.jmp(next))?;
    go(a.set_label(&mut done))?;
    Ok(())
}

fn emit_sched(a: &mut CodeAssembler) -> Result<()> {
    go(a.mov(r10d, r15d))?;
    go(a.sub(r10d, 15u32))?;
    go(a.mov(eax, dword_ptr(r8 + r10 * 4)))?;
    emit_small0(a)?;
    go(a.mov(r11d, ecx))?;
    go(a.mov(r10d, r15d))?;
    go(a.sub(r10d, 2u32))?;
    go(a.mov(eax, dword_ptr(r8 + r10 * 4)))?;
    emit_small1(a)?;
    emit_sched_store(a)?;
    Ok(())
}

fn emit_sched_store(a: &mut CodeAssembler) -> Result<()> {
    go(a.mov(r10d, r15d))?;
    go(a.sub(r10d, 16u32))?;
    go(a.mov(eax, dword_ptr(r8 + r10 * 4)))?;
    go(a.add(eax, r11d))?;
    go(a.mov(r10d, r15d))?;
    go(a.sub(r10d, 7u32))?;
    go(a.add(eax, dword_ptr(r8 + r10 * 4)))?;
    go(a.add(eax, ecx))?;
    go(a.mov(dword_ptr(r8 + r15 * 4), eax))?;
    Ok(())
}

fn emit_small0(a: &mut CodeAssembler) -> Result<()> {
    go(a.mov(ecx, eax))?;
    go(a.ror(ecx, 7u32))?;
    go(a.mov(edx, eax))?;
    go(a.ror(edx, 18u32))?;
    go(a.xor(ecx, edx))?;
    go(a.mov(edx, eax))?;
    go(a.shr(edx, 3u32))?;
    go(a.xor(ecx, edx))?;
    Ok(())
}

fn emit_small1(a: &mut CodeAssembler) -> Result<()> {
    go(a.mov(ecx, eax))?;
    go(a.ror(ecx, 17u32))?;
    go(a.mov(edx, eax))?;
    go(a.ror(edx, 19u32))?;
    go(a.xor(ecx, edx))?;
    go(a.mov(edx, eax))?;
    go(a.shr(edx, 10u32))?;
    go(a.xor(ecx, edx))?;
    Ok(())
}

fn emit_rounds(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    let mut next = a.create_label();
    let mut done = a.create_label();
    emit_copy_state(a)?;
    go(a.xor(r15d, r15d))?;
    go(a.set_label(&mut next))?;
    go(a.cmp(r15d, 64u32))?;
    go(a.jae(done))?;
    emit_round(a, slots)?;
    go(a.inc(r15d))?;
    go(a.jmp(next))?;
    go(a.set_label(&mut done))?;
    Ok(())
}

fn emit_copy_state(a: &mut CodeAssembler) -> Result<()> {
    let mut next = a.create_label();
    let mut done = a.create_label();
    go(a.lea(r8, qword_ptr(r12 + HASH_STATE)))?;
    go(a.lea(r9, qword_ptr(r12 + HASH_WORK)))?;
    go(a.xor(ecx, ecx))?;
    go(a.set_label(&mut next))?;
    go(a.cmp(ecx, 8u32))?;
    go(a.jae(done))?;
    go(a.mov(eax, dword_ptr(r8 + rcx * 4)))?;
    go(a.mov(dword_ptr(r9 + rcx * 4), eax))?;
    go(a.inc(ecx))?;
    go(a.jmp(next))?;
    go(a.set_label(&mut done))?;
    Ok(())
}

fn emit_round(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.lea(r8, qword_ptr(r12 + HASH_WORK)))?;
    go(a.mov(eax, dword_ptr(r8 + 16i32)))?;
    emit_sigma(a, 6, 11, 25)?;
    go(a.mov(r11d, ecx))?;
    emit_ch(a)?;
    go(a.mov(r10d, dword_ptr(r8 + 28i32)))?;
    go(a.add(r10d, r11d))?;
    go(a.add(r10d, eax))?;
    go(a.lea(r9, qword_ptr(slots.k)))?;
    go(a.add(r10d, dword_ptr(r9 + r15 * 4)))?;
    go(a.lea(r9, qword_ptr(r12 + HASH_WORDS)))?;
    go(a.add(r10d, dword_ptr(r9 + r15 * 4)))?;
    emit_round_t2(a)?;
    Ok(())
}

fn emit_round_t2(a: &mut CodeAssembler) -> Result<()> {
    go(a.mov(eax, dword_ptr(r8)))?;
    emit_sigma(a, 2, 13, 22)?;
    go(a.mov(r11d, ecx))?;
    emit_maj(a)?;
    go(a.add(r11d, eax))?;
    emit_rotate_work(a)?;
    Ok(())
}

fn emit_sigma(a: &mut CodeAssembler, first: u32, second: u32, third: u32) -> Result<()> {
    go(a.mov(ecx, eax))?;
    go(a.ror(ecx, first))?;
    go(a.mov(edx, eax))?;
    go(a.ror(edx, second))?;
    go(a.xor(ecx, edx))?;
    go(a.mov(edx, eax))?;
    go(a.ror(edx, third))?;
    go(a.xor(ecx, edx))?;
    Ok(())
}

fn emit_ch(a: &mut CodeAssembler) -> Result<()> {
    go(a.mov(eax, dword_ptr(r8 + 16i32)))?;
    go(a.mov(ecx, eax))?;
    go(a.not(ecx))?;
    go(a.and(eax, dword_ptr(r8 + 20i32)))?;
    go(a.and(ecx, dword_ptr(r8 + 24i32)))?;
    go(a.xor(eax, ecx))?;
    Ok(())
}

fn emit_maj(a: &mut CodeAssembler) -> Result<()> {
    go(a.mov(eax, dword_ptr(r8)))?;
    go(a.mov(ecx, eax))?;
    go(a.and(ecx, dword_ptr(r8 + 4i32)))?;
    go(a.mov(edx, eax))?;
    go(a.and(edx, dword_ptr(r8 + 8i32)))?;
    go(a.xor(ecx, edx))?;
    go(a.mov(eax, dword_ptr(r8 + 4i32)))?;
    go(a.and(eax, dword_ptr(r8 + 8i32)))?;
    go(a.xor(eax, ecx))?;
    Ok(())
}

fn emit_rotate_work(a: &mut CodeAssembler) -> Result<()> {
    go(a.mov(eax, dword_ptr(r8 + 24i32)))?;
    go(a.mov(dword_ptr(r8 + 28i32), eax))?;
    go(a.mov(eax, dword_ptr(r8 + 20i32)))?;
    go(a.mov(dword_ptr(r8 + 24i32), eax))?;
    go(a.mov(eax, dword_ptr(r8 + 16i32)))?;
    go(a.mov(dword_ptr(r8 + 20i32), eax))?;
    go(a.mov(eax, dword_ptr(r8 + 12i32)))?;
    go(a.add(eax, r10d))?;
    go(a.mov(dword_ptr(r8 + 16i32), eax))?;
    go(a.mov(eax, dword_ptr(r8 + 8i32)))?;
    go(a.mov(dword_ptr(r8 + 12i32), eax))?;
    go(a.mov(eax, dword_ptr(r8 + 4i32)))?;
    go(a.mov(dword_ptr(r8 + 8i32), eax))?;
    go(a.mov(eax, dword_ptr(r8)))?;
    go(a.mov(dword_ptr(r8 + 4i32), eax))?;
    go(a.mov(eax, r10d))?;
    go(a.add(eax, r11d))?;
    go(a.mov(dword_ptr(r8), eax))?;
    Ok(())
}

fn emit_add_state(a: &mut CodeAssembler) -> Result<()> {
    let mut next = a.create_label();
    let mut done = a.create_label();
    go(a.lea(r8, qword_ptr(r12 + HASH_STATE)))?;
    go(a.lea(r9, qword_ptr(r12 + HASH_WORK)))?;
    go(a.xor(ecx, ecx))?;
    go(a.set_label(&mut next))?;
    go(a.cmp(ecx, 8u32))?;
    go(a.jae(done))?;
    go(a.mov(eax, dword_ptr(r8 + rcx * 4)))?;
    go(a.add(eax, dword_ptr(r9 + rcx * 4)))?;
    go(a.mov(dword_ptr(r8 + rcx * 4), eax))?;
    go(a.inc(ecx))?;
    go(a.jmp(next))?;
    go(a.set_label(&mut done))?;
    Ok(())
}

fn emit_finish(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    let mut one = a.create_label();
    let mut pad = a.create_label();
    go(a.set_label(&mut slots.finish))?;
    go(a.lea(r10, qword_ptr(r12 + HASH_CHUNK)))?;
    go(a.mov(ecx, dword_ptr(r12 + HASH_FILLED)))?;
    go(a.mov(byte_ptr(r10 + rcx), 0x80u32))?;
    go(a.inc(ecx))?;
    go(a.cmp(ecx, 56u32))?;
    go(a.jbe(pad))?;
    emit_finish_extra(a, slots, &mut one)?;
    go(a.set_label(&mut pad))?;
    emit_finish_length(a, slots, &pad)?;
    emit_store_digest(a)?;
    go(a.ret())?;
    Ok(())
}

fn emit_finish_extra(a: &mut CodeAssembler, slots: &Slots, fresh: &mut CodeLabel) -> Result<()> {
    let mut tail = a.create_label();
    go(a.set_label(&mut tail))?;
    go(a.cmp(ecx, 64u32))?;
    go(a.jae(*fresh))?;
    go(a.mov(byte_ptr(r10 + rcx), 0u32))?;
    go(a.inc(ecx))?;
    go(a.jmp(tail))?;
    go(a.set_label(fresh))?;
    go(a.call(slots.block))?;
    go(a.xor(ecx, ecx))?;
    go(a.lea(r10, qword_ptr(r12 + HASH_CHUNK)))?;
    Ok(())
}

fn emit_finish_length(a: &mut CodeAssembler, slots: &Slots, pad: &CodeLabel) -> Result<()> {
    let mut ready = a.create_label();
    go(a.cmp(ecx, 56u32))?;
    go(a.jae(ready))?;
    go(a.mov(byte_ptr(r10 + rcx), 0u32))?;
    go(a.inc(ecx))?;
    go(a.jmp(*pad))?;
    go(a.set_label(&mut ready))?;
    go(a.mov(rax, qword_ptr(r12 + HASH_TOTAL)))?;
    go(a.shl(rax, 3u32))?;
    go(a.bswap(rax))?;
    go(a.mov(qword_ptr(r10 + 56i32), rax))?;
    go(a.call(slots.block))?;
    Ok(())
}

fn emit_store_digest(a: &mut CodeAssembler) -> Result<()> {
    let mut next = a.create_label();
    let mut done = a.create_label();
    go(a.lea(r8, qword_ptr(r12 + HASH_STATE)))?;
    go(a.lea(r9, qword_ptr(r12 + HASH)))?;
    go(a.xor(ecx, ecx))?;
    go(a.set_label(&mut next))?;
    go(a.cmp(ecx, 8u32))?;
    go(a.jae(done))?;
    go(a.mov(eax, dword_ptr(r8 + rcx * 4)))?;
    go(a.bswap(eax))?;
    go(a.mov(dword_ptr(r9 + rcx * 4), eax))?;
    go(a.inc(ecx))?;
    go(a.jmp(next))?;
    go(a.set_label(&mut done))?;
    Ok(())
}

fn emit_connect(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.connect))?;
    go(a.mov(eax, 41u32))?;
    go(a.mov(edi, 1u32))?;
    go(a.mov(esi, 0x80001u32))?;
    go(a.xor(edx, edx))?;
    go(a.syscall())?;
    go(a.test(rax, rax))?;
    go(a.mov(edi, DIE_SOCKET))?;
    go(a.js(slots.die))?;
    go(a.mov(dword_ptr(r12 + FD), eax))?;
    emit_socket_timeout(a, slots)?;
    go(a.mov(edi, dword_ptr(r12 + FD)))?;
    go(a.lea(rsi, qword_ptr(slots.addr)))?;
    go(a.mov(edx, (2 + PATH_CAP) as u32))?;
    go(a.mov(eax, 42u32))?;
    go(a.syscall())?;
    go(a.test(eax, eax))?;
    go(a.mov(edi, DIE_SOCKET))?;
    go(a.jnz(slots.die))?;
    emit_greeting(a, slots)?;
    go(a.ret())
}

fn emit_deadline_add(a: &mut CodeAssembler, slots: &Slots, seconds: u64) -> Result<()> {
    go(a.mov(rdx, (seconds * NANOS_PER_SECOND) as i64))?;
    go(a.add(rax, rdx))?;
    go(a.mov(edi, DIE_IO))?;
    go(a.jc(slots.die))
}

fn emit_start_frame(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    let mut ready = a.create_label();
    go(a.call(slots.now))?;
    emit_deadline_add(a, slots, agent::FRAME_TIMEOUT_SECS)?;
    go(a.mov(rdx, qword_ptr(r12 + CALL_DEADLINE)))?;
    go(a.test(rdx, rdx))?;
    go(a.jz(ready))?;
    go(a.cmp(rax, rdx))?;
    go(a.cmova(rax, rdx))?;
    go(a.set_label(&mut ready))?;
    go(a.mov(qword_ptr(r12 + FRAME_DEADLINE), rax))
}

fn emit_clock(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.now))?;
    go(a.push(rsi))?;
    go(a.mov(eax, 228u32))?;
    go(a.mov(edi, 1u32))?;
    go(a.lea(rsi, qword_ptr(r12 + CLOCK)))?;
    go(a.syscall())?;
    go(a.pop(rsi))?;
    go(a.test(eax, eax))?;
    go(a.mov(edi, DIE_IO))?;
    go(a.jnz(slots.die))?;
    go(a.mov(rax, qword_ptr(r12 + CLOCK)))?;
    go(a.imul_3(rax, rax, NANOS_PER_SECOND as i32))?;
    go(a.jo(slots.die))?;
    go(a.add(rax, qword_ptr(r12 + CLOCK + 8i32)))?;
    go(a.jc(slots.die))?;
    go(a.ret())?;
    go(a.set_label(&mut slots.remaining))?;
    go(a.call(slots.now))?;
    go(a.mov(r11, qword_ptr(r12 + FRAME_DEADLINE)))?;
    go(a.sub(r11, rax))?;
    go(a.mov(edi, DIE_DEADLINE))?;
    go(a.jbe(slots.die))?;
    go(a.mov(rax, r11))?;
    go(a.ret())
}

fn emit_io_wait(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.wait_io))?;
    go(a.mov(eax, dword_ptr(r12 + FD)))?;
    go(a.mov(dword_ptr(r12 + POLL), eax))?;
    go(a.mov(dword_ptr(r12 + POLL + 4i32), edx))?;
    go(a.call(slots.remaining))?;
    go(a.xor(edx, edx))?;
    go(a.mov(ecx, NANOS_PER_SECOND as u32))?;
    go(a.div(rcx))?;
    go(a.mov(qword_ptr(r12 + REMAINING), rax))?;
    go(a.mov(qword_ptr(r12 + REMAINING + 8i32), rdx))?;
    go(a.push(rsi))?;
    go(a.mov(eax, 271u32))?;
    go(a.lea(rdi, qword_ptr(r12 + POLL)))?;
    go(a.mov(esi, 1u32))?;
    go(a.lea(rdx, qword_ptr(r12 + REMAINING)))?;
    go(a.xor(r10d, r10d))?;
    go(a.xor(r8d, r8d))?;
    go(a.syscall())?;
    go(a.pop(rsi))?;
    go(a.mov(edi, DIE_IO))?;
    go(a.cmp(eax, -4i32))?;
    let mut retry = a.create_label();
    go(a.je(retry))?;
    go(a.test(eax, eax))?;
    go(a.js(slots.die))?;
    go(a.mov(edi, DIE_DEADLINE))?;
    go(a.jz(slots.die))?;
    go(a.set_label(&mut retry))?;
    go(a.ret())
}

fn emit_socket_timeout(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    // The Unix connect uses the send timeout. Data I/O is nonblocking.
    go(a.sub(rsp, 16i32))?;
    go(a.mov(qword_ptr(rsp), agent::FRAME_TIMEOUT_SECS as i32))?;
    go(a.mov(qword_ptr(rsp + 8i32), 0i32))?;
    go(a.mov(eax, 54u32))?;
    go(a.mov(edi, dword_ptr(r12 + FD)))?;
    go(a.mov(esi, 1u32))?;
    go(a.mov(edx, 21u32))?;
    go(a.mov(r10, rsp))?;
    go(a.mov(r8d, 16u32))?;
    go(a.syscall())?;
    go(a.test(eax, eax))?;
    go(a.mov(edi, DIE_SOCKET))?;
    go(a.jnz(slots.die))?;
    go(a.add(rsp, 16i32))
}

fn emit_greeting(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    emit_start_frame(a, slots)?;
    go(a.lea(rsi, qword_ptr(slots.hello)))?;
    go(a.mov(edx, HDR as u32))?;
    go(a.call(slots.write_all))?;
    go(a.mov(dword_ptr(r12 + EXPECTED_LEN), agent::TICKET_LEN as i32))?;
    emit_receive_frame(a, slots, 0)?;
    go(a.lea(rsi, qword_ptr(r12 + RESPONSE + 5i32)))?;
    copy_ticket(a, slots)?;
    emit_clear_response(a, slots)
}

fn emit_receive_frame(a: &mut CodeAssembler, slots: &Slots, trailer: usize) -> Result<()> {
    go(a.mov(ecx, dword_ptr(r12 + EXPECTED_LEN)))?;
    go(a.mov(edi, DIE_LEN))?;
    go(a.cmp(ecx, MAX_BODY as u32))?;
    go(a.ja(slots.die))?;
    go(a.add(ecx, (5 + trailer) as i32))?;
    go(a.lea(rsi, qword_ptr(r12 + RESPONSE)))?;
    go(a.call(slots.read_all))
}

fn copy_ticket(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.lea(rdi, qword_ptr(r12 + TICKET)))?;
    go(a.mov(ecx, agent::TICKET_LEN as u32))?;
    go(a.call(slots.copy))
}

fn emit_check_reply(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.check_reply))?;
    go(a.mov(edi, DIE_DENY))?;
    go(a.cmp(byte_ptr(r12 + RESPONSE), u32::from(agent::STATUS_OK)))?;
    go(a.jne(slots.die))?;
    go(a.mov(eax, dword_ptr(r12 + RESPONSE + 1i32)))?;
    go(a.mov(edi, DIE_LEN))?;
    go(a.cmp(eax, dword_ptr(r12 + EXPECTED_LEN)))?;
    go(a.jne(slots.die))?;
    go(a.ret())
}

fn emit_write_all(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.write_all))?;
    go(a.mov(r15, rdx))?;
    emit_io_loop(a, slots, true)
}

fn emit_read_all(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.read_all))?;
    go(a.mov(r15, rcx))?;
    emit_io_loop(a, slots, false)
}

fn emit_io_loop(a: &mut CodeAssembler, slots: &Slots, write: bool) -> Result<()> {
    let mut step = a.create_label();
    let mut wait = a.create_label();
    let mut done = a.create_label();
    go(a.set_label(&mut step))?;
    go(a.call(slots.remaining))?;
    go(a.test(r15, r15))?;
    go(a.jz(done))?;
    emit_socket_io(a, write)?;
    go(a.cmp(eax, -4i32))?;
    go(a.je(step))?;
    go(a.cmp(eax, -11i32))?;
    go(a.je(wait))?;
    go(a.test(rax, rax))?;
    go(a.mov(edi, DIE_IO))?;
    go(a.jle(slots.die))?;
    go(a.add(rsi, rax))?;
    go(a.sub(r15, rax))?;
    if !write {
        go(a.lea(rax, qword_ptr(r12 + RESPONSE + 5i32)))?;
        go(a.cmp(rsi, rax))?;
        go(a.jb(step))?;
        go(a.call(slots.check_reply))?;
    }
    go(a.jmp(step))?;
    go(a.set_label(&mut wait))?;
    go(a.mov(edx, if write { 4u32 } else { 1u32 }))?;
    go(a.call(slots.wait_io))?;
    go(a.jmp(step))?;
    go(a.set_label(&mut done))?;
    go(a.ret())
}

fn emit_socket_io(a: &mut CodeAssembler, write: bool) -> Result<()> {
    // MSG_DONTWAIT keeps I/O subject to the absolute ppoll deadline.
    // A send adds MSG_NOSIGNAL to allow the normal disconnect cleanup.
    go(a.mov(eax, if write { 44u32 } else { 45u32 }))?;
    go(a.mov(edi, dword_ptr(r12 + FD)))?;
    go(a.mov(rdx, r15))?;
    go(a.mov(r10d, if write { 0x4040u32 } else { 0x40u32 }))?;
    go(a.xor(r8d, r8d))?;
    go(a.xor(r9d, r9d))?;
    go(a.syscall())
}

fn emit_copy(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    let mut next = a.create_label();
    let mut done = a.create_label();
    go(a.set_label(&mut slots.copy))?;
    go(a.xor(eax, eax))?;
    go(a.set_label(&mut next))?;
    go(a.cmp(rax, rcx))?;
    go(a.jae(done))?;
    go(a.mov(dl, byte_ptr(rsi + rax)))?;
    go(a.mov(byte_ptr(rdi + rax), dl))?;
    go(a.inc(rax))?;
    go(a.jmp(next))?;
    go(a.set_label(&mut done))?;
    go(a.ret())?;
    Ok(())
}

fn emit_zero(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    let mut next = a.create_label();
    let mut done = a.create_label();
    go(a.set_label(&mut slots.zero))?;
    go(a.xor(eax, eax))?;
    go(a.set_label(&mut next))?;
    go(a.cmp(rax, rcx))?;
    go(a.jae(done))?;
    go(a.mov(byte_ptr(rdi + rax), 0u32))?;
    go(a.inc(rax))?;
    go(a.jmp(next))?;
    go(a.set_label(&mut done))?;
    go(a.ret())?;
    Ok(())
}

fn emit_fill(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.fill))?;
    go(a.lea(r8, qword_ptr(r12 + REQUEST)))?;
    go(a.mov(dword_ptr(r8), agent::MAGIC as i32))?;
    go(a.mov(byte_ptr(r8 + 4i32), u32::from(agent::VER)))?;
    go(a.mov(byte_ptr(r8 + 5i32), r15d))?;
    emit_fill_hash(a, slots)?;
    emit_fill_tail(a, slots)?;
    go(a.ret())?;
    Ok(())
}

fn emit_fill_hash(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.lea(rsi, qword_ptr(r12 + HASH)))?;
    go(a.lea(rdi, qword_ptr(r12 + REQUEST)))?;
    go(a.add(rdi, 6i32))?;
    go(a.mov(ecx, 32u32))?;
    go(a.call(slots.copy))?;
    go(a.lea(rsi, qword_ptr(r13 + RT_SALT)))?;
    go(a.lea(rdi, qword_ptr(r12 + REQUEST)))?;
    go(a.add(rdi, 38i32))?;
    go(a.mov(ecx, 8u32))?;
    go(a.call(slots.copy))?;
    Ok(())
}

fn emit_fill_tail(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    let mut indexed = a.create_label();
    let mut ready = a.create_label();
    go(a.lea(r8, qword_ptr(r12 + REQUEST)))?;
    go(a.xor(eax, eax))?;
    go(a.cmp(byte_ptr(r8 + 5i32), u32::from(agent::OP_OPEN)))?;
    go(a.je(indexed))?;
    go(a.cmp(byte_ptr(r8 + 5i32), u32::from(agent::OP_RESIDENT)))?;
    go(a.jne(ready))?;
    go(a.set_label(&mut indexed))?;
    go(a.mov(eax, r14d))?;
    go(a.set_label(&mut ready))?;
    go(a.mov(dword_ptr(r8 + agent::OFF_INDEX as i32), eax))?;
    go(a.mov(eax, dword_ptr(r13 + WEAVE_SAVE)))?;
    go(a.mov(dword_ptr(r8 + agent::OFF_RVA as i32), eax))?;
    go(a.mov(eax, dword_ptr(r12 + REQUEST_LEN)))?;
    go(a.mov(dword_ptr(r8 + agent::OFF_LEN as i32), eax))?;
    emit_fill_binding(a, slots)
}

fn emit_fill_binding(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.mov(eax, dword_ptr(r12 + THREAD_ID)))?;
    go(a.mov(dword_ptr(r8 + agent::OFF_TID as i32), eax))?;
    go(a.mov(ecx, dword_ptr(r12 + DEPTH)))?;
    go(a.mov(rax, qword_ptr(r12 + rcx * 8 + (CALLS - 8))))?;
    go(a.mov(qword_ptr(r8 + agent::OFF_CALL as i32), rax))?;
    go(a.mov(edi, DIE_LEN))?;
    go(a.add(qword_ptr(r12 + SEQUENCE), 1i32))?;
    go(a.jc(slots.die))?;
    go(a.mov(rax, qword_ptr(r12 + SEQUENCE)))?;
    go(a.mov(qword_ptr(r8 + agent::OFF_SEQ as i32), rax))
}

fn emit_exchange(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.exchange))?;
    emit_start_frame(a, slots)?;
    go(a.lea(rsi, qword_ptr(r12 + TICKET)))?;
    go(a.mov(edx, (agent::TICKET_LEN + HDR) as u32))?;
    go(a.add(edx, dword_ptr(r12 + REQUEST_LEN)))?;
    go(a.call(slots.write_all))?;
    emit_receive_frame(a, slots, agent::TICKET_LEN)?;
    go(a.mov(eax, dword_ptr(r12 + EXPECTED_LEN)))?;
    go(a.lea(rsi, qword_ptr(r12 + rax + RESPONSE + 5i32)))?;
    copy_ticket(a, slots)?;
    go(a.lea(rdi, qword_ptr(r12 + REQUEST)))?;
    go(a.mov(ecx, dword_ptr(r12 + REQUEST_LEN)))?;
    go(a.add(ecx, HDR as i32))?;
    go(a.call(slots.zero))?;
    go(a.ret())
}

fn emit_cleanup(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    let mut done = a.create_label();
    go(a.set_label(&mut slots.cleanup))?;
    go(a.test(r12, r12))?;
    go(a.jz(done))?;
    go(a.push(r12))?;
    go(a.xor(r12d, r12d))?;
    state_store(a)?;
    go(a.pop(r12))?;
    close_slot(a, FD)?;
    close_slot(a, HASH_FD)?;
    go(a.mov(rdi, r12))?;
    go(a.mov(ecx, STATE_BYTES))?;
    go(a.call(slots.zero))?;
    go(a.mov(eax, 11u32))?;
    go(a.mov(rdi, r12))?;
    go(a.mov(esi, STATE_BYTES))?;
    go(a.syscall())?;
    go(a.xor(r12d, r12d))?;
    go(a.set_label(&mut done))?;
    go(a.ret())
}

fn close_slot(a: &mut CodeAssembler, field: i32) -> Result<()> {
    let mut done = a.create_label();
    go(a.mov(edi, dword_ptr(r12 + field)))?;
    go(a.test(edi, edi))?;
    go(a.js(done))?;
    go(a.mov(eax, 3u32))?;
    go(a.syscall())?;
    go(a.mov(dword_ptr(r12 + field), -1i32))?;
    go(a.set_label(&mut done))?;
    go(a.nop())
}

fn emit_die(a: &mut CodeAssembler, slots: &mut Slots) -> Result<()> {
    go(a.set_label(&mut slots.die))?;
    go(a.push(rdi))?;
    go(a.call(slots.cleanup))?;
    go(a.pop(rdi))?;
    go(a.mov(eax, 231u32))?;
    go(a.syscall())?;
    go(a.ud2())
}

pub(super) fn emit_failure_gate(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    state_load(a)?;
    go(a.mov(edi, DIE_DENY))?;
    go(a.jmp(slots.die))
}

fn emit_install(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.mov(ecx, dword_ptr(r12 + EXPECTED_LEN)))?;
    go(a.lea(rsi, qword_ptr(r12 + RESPONSE + 5i32)))?;
    go(a.mov(rdi, qword_ptr(r12 + DESTINATION)))?;
    go(a.call(slots.copy))?;
    emit_clear_response(a, slots)?;
    go(a.mov(qword_ptr(r12 + DESTINATION), 0i32))?;
    super::chain::emit_load_r11(a)?;
    go(a.mov(r10, qword_ptr(r11 + CTX_CACHE)))?;
    go(a.mov(byte_ptr(r10 + r14), u32::from(CACHE_OPEN)))?;
    super::window::emit_note_open(a)
}

fn emit_clear_response(a: &mut CodeAssembler, slots: &Slots) -> Result<()> {
    go(a.mov(ecx, dword_ptr(r12 + EXPECTED_LEN)))?;
    go(a.add(ecx, (5 + agent::TICKET_LEN) as i32))?;
    go(a.lea(rdi, qword_ptr(r12 + RESPONSE)))?;
    go(a.call(slots.zero))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_crate_digest() {
        for message in [Vec::new(), b"abc".to_vec(), vec![0x5au8; 200]] {
            let digest = hash_message(&message);
            assert_eq!(digest, crate::crypto::sha256(&message));
        }
    }

    #[test]
    fn external_block_bounds_reject_before_writing_a_destination() {
        for (index, lens, count, cap) in [
            (1, 0x4000, 1, 16),
            (0, 0x1000, 1, 16),
            (0, 0x4000, 0x10001, 16),
            (0, 0x4000, 1, 4),
        ] {
            let mut machine = bounds_machine(index, lens, count, cap);
            machine.run().unwrap();
            assert_eq!(machine.regs[0], u64::from(DIE_LEN));
            assert_eq!(machine.read(0x900028, 8).unwrap(), [0x5a; 8]);
        }
    }

    #[test]
    fn external_bind_rejects_zero_extent_before_reading_the_length_table() {
        use crate::emu::{bare, Policy, Region};
        use crate::stub::assemble_vm_for_external_lab;
        use crate::vm::{CHAIN_BYTES, GS_CHAIN_PTR};

        let origin = 0x400000;
        let runtime = 0x600000;
        let chain = 0x800000u64;
        let vm = assemble_vm_for_external_lab(origin).unwrap();
        let mut machine = bare(Policy::default()).unwrap();
        machine.rip = origin + vm.dispatch as u64;
        machine.regs[3] = origin + vm.frame as u64;
        machine.regs[13] = runtime;
        for (base, data) in [
            (origin, vm.bytes),
            (runtime, vec![0; RUNTIME_WINDOW as usize]),
            (chain, vec![0; CHAIN_BYTES]),
        ] {
            machine.regions.push(Region { base, data });
        }
        machine.write(runtime, &1u64.to_le_bytes()).unwrap();
        machine
            .write(runtime + 32, &0xdead_0000u64.to_le_bytes())
            .unwrap();
        machine
            .write(machine.gs + GS_CHAIN_PTR as u64, &chain.to_le_bytes())
            .unwrap();

        // The model stops at the Linux exit_group syscall. Check the exact
        // native refusal status and distinguish it from an invalid memory read.
        assert_eq!(
            machine.run().unwrap_err().to_string(),
            "emulator syscall 231"
        );
        assert_eq!(machine.regs[7], u64::from(DIE_DENY));
    }

    fn bounds_machine(index: u32, lens: i32, count: u64, cap: u64) -> crate::emu::Machine {
        use crate::emu::{bare, Policy, Region};
        use crate::vm::{CHAIN_BYTES, GS_CHAIN_PTR};

        let mut machine = bare(Policy::default()).unwrap();
        let origin = 0x400000;
        let runtime = 0x600000u64;
        let state = 0x700000u64;
        let chain = 0x800000u64;
        let cache = 0x900000u64;
        for (base, data) in [
            (
                origin,
                assemble_bounds(origin, state, runtime, index).unwrap(),
            ),
            (runtime, vec![0; RUNTIME_WINDOW as usize]),
            (state, vec![0; STATE_BYTES as usize]),
            (chain, vec![0; CHAIN_BYTES]),
            (cache, vec![0x5a; 128]),
        ] {
            machine.regions.push(Region { base, data });
        }
        for (at, value) in [
            (runtime, count),
            (runtime + 16, runtime + 0x4010),
            (runtime + 24, runtime + 0x4100),
            (runtime + 32, runtime + lens as u64),
            (chain + CTX_BOUND as u64, runtime),
            (chain + CTX_CACHE as u64, cache + 40),
            (chain + CTX_KEYS as u64, cache + 8),
            (machine.gs + GS_CHAIN_PTR as u64, chain),
            (cache, cap),
        ] {
            machine.write(at, &value.to_le_bytes()).unwrap();
        }
        machine
            .write(runtime + 0x4000, &4u32.to_le_bytes())
            .unwrap();
        machine
            .write(runtime + RT_FOLD as u64, &4u32.to_le_bytes())
            .unwrap();
        machine.rip = origin;
        machine
    }

    fn assemble_bounds(origin: u64, state: u64, runtime: u64, index: u32) -> Result<Vec<u8>> {
        let mut a = CodeAssembler::new(64).map_err(ice)?;
        let mut slots = Slots::new(&mut a);
        go(a.mov(r12, state))?;
        go(a.mov(r13, runtime))?;
        go(a.mov(r14d, index))?;
        emit_open_body(&mut a, &slots)?;
        go(a.xor(eax, eax))?;
        go(a.ret())?;
        go(a.set_label(&mut slots.die))?;
        go(a.mov(eax, edi))?;
        go(a.ret())?;
        emit_copy(&mut a, &mut slots)?;
        a.assemble(origin).map_err(ice)
    }

    fn hash_message(message: &[u8]) -> Vec<u8> {
        let origin = 0x400000u64;
        let (code, digest_at) = assemble_hasher(origin, message).expect("hash");
        let mut machine = crate::emu::bare(crate::emu::Policy::default()).expect("machine");
        machine.regions.push(crate::emu::Region {
            base: origin,
            data: code,
        });
        machine.rip = origin;
        machine.run().expect("run");
        machine.read(origin + digest_at as u64, 32).expect("digest")
    }

    fn assemble_hasher(origin: u64, message: &[u8]) -> Result<(Vec<u8>, usize)> {
        let mut a = CodeAssembler::new(64).map_err(ice)?;
        let mut slots = Slots::new(&mut a);
        let mut msg = a.create_label();
        let mut scratch = a.create_label();
        go(a.lea(r12, qword_ptr(scratch)))?;
        go(a.lea(rsi, qword_ptr(msg)))?;
        go(a.mov(edx, u32::try_from(message.len()).unwrap_or(0)))?;
        go(a.call(slots.init))?;
        go(a.call(slots.absorb))?;
        go(a.call(slots.finish))?;
        go(a.ret())?;
        emit_code(&mut a, &mut slots)?;
        emit_data(&mut a, &mut slots)?;
        go(a.set_label(&mut scratch))?;
        go(a.db(&[0; HASH_WORDS as usize + 256]))?;
        go(a.set_label(&mut msg))?;
        if message.is_empty() {
            go(a.nop())?;
        } else {
            go(a.db(message))?;
        }
        let encoded = a
            .assemble_options(
                origin,
                iced_x86::BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
            )
            .map_err(ice)?;
        let digest = (encoded.label_ip(&scratch).map_err(ice)? - origin) as usize + HASH as usize;
        Ok((encoded.inner.code_buffer, digest))
    }
}
