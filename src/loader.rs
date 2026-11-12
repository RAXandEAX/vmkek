use iced_x86::code_asm::*;
use iced_x86::{BlockEncoderOptions, Code, Instruction, MemoryOperand, Register};

use crate::error::{exact_bytes, msg, Result};

#[path = "loader_auth.rs"]
mod auth;
pub(crate) use auth::AuthImports;

#[path = "loader_sysv.rs"]
mod sysv;
pub use sysv::{assemble as assemble_sysv, Plan as SysvPlan};
pub(crate) use sysv::{assemble_elf_auth, ElfAuthPlan};

/// AEAD key embedded in the loader image, immediately after the entry jump.
pub const AEAD_KEY_LEN: usize = 32;
/// AEAD nonce embedded beside the key. The header carries the same nonce.
pub const AEAD_NONCE_LEN: usize = 12;
pub const LOADER_KEY_OFF: usize = 2;
pub const LOADER_NONCE_OFF: usize = LOADER_KEY_OFF + AEAD_KEY_LEN;
const LOADER_BLOB_LEN: usize = AEAD_KEY_LEN + AEAD_NONCE_LEN;

pub struct LoaderPlan {
    pub origin: u64,
    pub payload: u64,
    pub payload_len: u32,
    pub checksum: u32,
    pub aead_key: [u8; AEAD_KEY_LEN],
    pub aead_nonce: [u8; AEAD_NONCE_LEN],
    pub strings: u64,
    pub imports: u64,
    pub table: u64,
    pub calls: u64,
    /// Writable slot holding the resolved module base.
    pub module: u64,
    pub resolve: u64,
    pub original: u64,
    /// Absolute address of the mutated NtGlobalFlag cave. `0` is only for size checks.
    pub cave: u64,
    /// Absolute address of the first function runtime. Detectors that trip after
    /// decrypt xor the woven key stored there.
    pub runtime: u64,
    /// Name-hash key. All zeros selects plain djb2. The bytes live in the sealed payload.
    pub name_key: [u8; crate::trace::NAME_KEY_LEN],
}

impl Drop for LoaderPlan {
    fn drop(&mut self) {
        crate::secret::wipe(&mut self.aead_key);
    }
}

/// Assembled loader image. `stubs` is the file offset of the first import gate.
pub struct Image {
    pub bytes: Vec<u8>,
    pub stubs: usize,
}

pub fn assemble(plan: &LoaderPlan) -> Result<Vec<u8>> {
    Ok(assemble_image(plan)?.bytes)
}

/// Assemble the loader and record where the import gates were planted.
pub fn assemble_image(plan: &LoaderPlan) -> Result<Image> {
    let prev = crate::trace::set_name_key(plan.name_key);
    let image = assemble_unlocked(plan);
    crate::trace::set_name_key(prev);
    image
}

/// Emit a reference within the same PE image. The displacement survives ASLR.
pub(crate) fn emit_image_address(
    a: &mut CodeAssembler,
    dest: Register,
    address: u64,
) -> Result<()> {
    let operand = MemoryOperand::with_base_displ(Register::RIP, address as i64);
    let instruction =
        Instruction::with2(Code::Lea_r64_m, dest, operand).map_err(|err| msg(err.to_string()))?;
    step(a.add_instruction(instruction))
}

pub(crate) struct NativeLoader {
    pub startup_status: u64,
    pub preferred_base: u64,
    pub functions: u32,
}

/// Assemble the Windows entry loader for a PE whose IAT is populated by the OS.
pub(crate) fn assemble_windows_native(plan: &LoaderPlan, native: NativeLoader) -> Result<Vec<u8>> {
    const SAVED: [AsmRegister64; 12] = [rcx, rdx, r8, r9, rbx, rbp, rsi, rdi, r12, r13, r14, r15];

    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut bad = a.create_label();
    let mut corrupt = a.create_label();
    let mut fail = a.create_label();
    emit_loader_prefix(&mut a, plan)?;
    for reg in SAVED {
        step(a.push(reg))?;
    }
    crate::antidebug::emit_process_peb(&mut a, &mut bad)?;
    step(a.mov(rbp, qword_ptr(rax + 0x10i32)))?;
    emit_image_address(&mut a, Register::R11, native.startup_status)?;
    step(a.cmp(dword_ptr(r11), 1i32))?;
    step(a.jne(bad))?;
    emit_checksum(&mut a, plan, &mut corrupt, true)?;
    emit_aead_decrypt(&mut a, plan, true)?;
    emit_native_payload_addresses(&mut a, plan, &native)?;
    emit_image_address(&mut a, Register::RAX, plan.table)?;
    emit_image_address(&mut a, Register::R11, plan.calls)?;
    step(a.mov(qword_ptr(r11), rax))?;
    for reg in SAVED.into_iter().rev() {
        step(a.pop(reg))?;
    }
    emit_image_address(&mut a, Register::RAX, plan.original)?;
    step(a.jmp(rax))?;
    step(a.set_label(&mut bad))?;
    step(a.mov(eax, 0xdeb6u32))?;
    step(a.jmp(fail))?;
    step(a.set_label(&mut corrupt))?;
    step(a.mov(eax, 0xbad1u32))?;
    step(a.set_label(&mut fail))?;
    for reg in SAVED.into_iter().rev() {
        step(a.pop(reg))?;
    }
    step(a.ret())?;
    let bytes = a
        .assemble(plan.origin)
        .map_err(|err| msg(err.to_string()))?;
    ensure_embedded_key(&bytes, plan)?;
    Ok(bytes)
}

pub(crate) struct NativeAuthLoader<'a> {
    pub(crate) imports: AuthImports,
    pub(crate) expected_core: &'a [u8; crate::crypto::authenticated::BOOTSTRAP_CORE_LEN],
    pub(crate) trusted_public: &'a [u8; 65],
}

pub(crate) struct NativeAuthImage {
    pub(crate) bytes: Vec<u8>,
    pub(crate) unwind: [NativeStartupUnwind; 2],
}

pub(crate) struct NativeStartupUnwind {
    pub(crate) begin: u32,
    pub(crate) end: u32,
    pub(crate) info: Vec<u8>,
}

/// Build the authenticated entry and a separately unwindable CNG verifier.
/// Both functions use direct image-relative branches. CNG calls use the OS IAT.
pub(crate) fn assemble_windows_native_authenticated(
    plan: &LoaderPlan,
    native: NativeLoader,
    auth: &NativeAuthLoader<'_>,
) -> Result<NativeAuthImage> {
    let probe = plan
        .origin
        .checked_add(0x1000)
        .ok_or_else(|| msg("authenticated PE entry address overflows"))?;
    let (probe_bytes, _) = emit_authenticated_entry(plan, &native, probe)?;
    let verifier_origin = plan
        .origin
        .checked_add(probe_bytes.len() as u64)
        .ok_or_else(|| msg("authenticated PE verifier address overflows"))?;
    let (mut bytes, entry_unwind) = emit_authenticated_entry(plan, &native, verifier_origin)?;
    if bytes.len() != probe_bytes.len() {
        return Err(msg("authenticated PE entry size changed between passes"));
    }
    let manifest = plan
        .origin
        .checked_sub(crate::crypto::HEADER_LEN as u64)
        .ok_or_else(|| msg("authenticated PE manifest address overflows"))?;
    let key = plan
        .origin
        .checked_add(LOADER_KEY_OFF as u64)
        .ok_or_else(|| msg("authenticated PE key address overflows"))?;
    let verifier = auth::assemble(&auth::StartupAuth {
        origin: verifier_origin,
        manifest,
        payload: plan.payload,
        payload_len: plan.payload_len,
        key,
        imports: auth.imports,
        expected_core: auth.expected_core,
        trusted_public: auth.trusted_public,
    })?;
    let begin = u32::try_from(bytes.len()).map_err(|_| msg("PE entry length overflows"))?;
    let end = begin
        .checked_add(verifier.executable_len)
        .ok_or_else(|| msg("PE verifier length overflows"))?;
    bytes.extend_from_slice(&verifier.bytes);
    ensure_embedded_key(&bytes, plan)?;
    Ok(NativeAuthImage {
        bytes,
        unwind: [
            entry_unwind,
            NativeStartupUnwind {
                begin,
                end,
                info: verifier.unwind.to_vec(),
            },
        ],
    })
}

fn emit_authenticated_entry(
    plan: &LoaderPlan,
    native: &NativeLoader,
    verifier: u64,
) -> Result<(Vec<u8>, NativeStartupUnwind)> {
    const PRESERVED: [(AsmRegister64, u8); 8] = [
        (rbx, 3),
        (rbp, 5),
        (rsi, 6),
        (rdi, 7),
        (r12, 12),
        (r13, 13),
        (r14, 14),
        (r15, 15),
    ];
    const ARGS: [AsmRegister64; 4] = [rcx, rdx, r8, r9];
    const STACK: i32 = 0x48;

    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut bad = a.create_label();
    let mut corrupt = a.create_label();
    let mut begin = a.create_label();
    let mut alloc = a.create_label();
    let mut pushes = Vec::with_capacity(PRESERVED.len());
    emit_loader_prefix(&mut a, plan)?;
    step(a.set_label(&mut begin))?;
    for (register, id) in PRESERVED {
        step(a.push(register))?;
        let mut after = a.create_label();
        step(a.set_label(&mut after))?;
        pushes.push((after, id));
    }
    step(a.sub(rsp, STACK))?;
    step(a.set_label(&mut alloc))?;
    for (index, register) in ARGS.into_iter().enumerate() {
        step(a.mov(qword_ptr(rsp + 0x20i32 + index as i32 * 8), register))?;
    }
    crate::antidebug::emit_process_peb(&mut a, &mut bad)?;
    step(a.mov(rbp, qword_ptr(rax + 0x10i32)))?;
    emit_image_address(&mut a, Register::R11, native.startup_status)?;
    step(a.cmp(dword_ptr(r11), 1i32))?;
    step(a.jne(bad))?;
    step(a.call(verifier))?;
    step(a.test(eax, eax))?;
    step(a.jne(corrupt))?;
    emit_native_payload_addresses(&mut a, plan, native)?;
    emit_image_address(&mut a, Register::RAX, plan.table)?;
    emit_image_address(&mut a, Register::R11, plan.calls)?;
    step(a.mov(qword_ptr(r11), rax))?;
    for (index, register) in ARGS.into_iter().enumerate() {
        step(a.mov(register, qword_ptr(rsp + 0x20i32 + index as i32 * 8)))?;
    }
    step(a.add(rsp, STACK))?;
    for (register, _) in PRESERVED.into_iter().rev() {
        step(a.pop(register))?;
    }
    step(a.jmp(plan.original))?;
    step(a.set_label(&mut bad))?;
    step(a.mov(eax, 0xdeb6u32))?;
    step(a.set_label(&mut corrupt))?;
    step(a.add(rsp, STACK))?;
    for (register, _) in PRESERVED.into_iter().rev() {
        step(a.pop(register))?;
    }
    step(a.ret())?;

    let encoded = a
        .assemble_options(
            plan.origin,
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )
        .map_err(|err| msg(err.to_string()))?;
    let offset = |label| -> Result<u32> {
        let ip = encoded
            .label_ip(label)
            .map_err(|err| msg(err.to_string()))?;
        u32::try_from(ip - plan.origin).map_err(|_| msg("PE entry offset overflows"))
    };
    let begin = offset(&begin)?;
    let code_offset = |label| -> Result<u8> {
        u8::try_from(offset(label)? - begin).map_err(|_| msg("PE entry prologue too large"))
    };
    let prologue = code_offset(&alloc)?;
    let slots = (1 + pushes.len()) as u8;
    let mut info = vec![
        1,
        prologue,
        slots,
        0,
        prologue,
        (((STACK - 8) / 8) << 4 | 2) as u8,
    ];
    for (label, id) in pushes.iter().rev() {
        info.extend_from_slice(&[code_offset(label)?, id << 4]);
    }
    info.extend_from_slice(&[0, 0]);
    let bytes = encoded.inner.code_buffer;
    let end = u32::try_from(bytes.len()).map_err(|_| msg("PE entry length overflows"))?;
    Ok((bytes, NativeStartupUnwind { begin, end, info }))
}

fn emit_native_payload_addresses(
    a: &mut CodeAssembler,
    plan: &LoaderPlan,
    native: &NativeLoader,
) -> Result<()> {
    let mut top = a.create_label();
    let mut done = a.create_label();
    // The PE loader can relocate only mapped plaintext. The VM table and
    // runtime windows are sealed, so adjust their address fields after opening.
    step(a.mov(r12, native.preferred_base as i64))?;
    step(a.sub(rbp, r12))?;
    step(a.jz(done))?;
    emit_image_address(a, Register::R11, plan.table)?;
    emit_image_address(a, Register::RDX, plan.runtime)?;
    step(a.add(r11, 4i32))?;
    step(a.mov(ecx, native.functions))?;
    step(a.set_label(&mut top))?;
    step(a.test(ecx, ecx))?;
    step(a.jz(done))?;
    step(a.mov(qword_ptr(r11 + 8i32), rdx))?;
    for offset in [8, 16, 24, 32, 40, crate::vm::RT_KEYS] {
        step(a.add(qword_ptr(rdx + offset), rbp))?;
    }
    step(a.add(r11, 16i32))?;
    step(a.add(rdx, crate::vm::RUNTIME_WINDOW as i32))?;
    step(a.dec(ecx))?;
    step(a.jmp(top))?;
    step(a.set_label(&mut done))?;
    Ok(())
}

fn assemble_unlocked(plan: &LoaderPlan) -> Result<Image> {
    let mut a = CodeAssembler::new(64).map_err(|err| msg(err.to_string()))?;
    let mut labs = loader_labels(&mut a);
    emit_loader_body(&mut a, plan, &mut labs)?;
    finish_image(&mut a, plan, &labs.stubs, &labs.gate)
}

struct LoaderLabels {
    bad: CodeLabel,
    corrupt: CodeLabel,
    find: CodeLabel,
    write: CodeLabel,
    std_handle: CodeLabel,
    stubs: CodeLabel,
    gate: CodeLabel,
}

fn loader_labels(a: &mut CodeAssembler) -> LoaderLabels {
    LoaderLabels {
        bad: a.create_label(),
        corrupt: a.create_label(),
        find: a.create_label(),
        write: a.create_label(),
        std_handle: a.create_label(),
        stubs: a.create_label(),
        gate: a.create_label(),
    }
}

fn emit_loader_body(
    a: &mut CodeAssembler,
    plan: &LoaderPlan,
    labs: &mut LoaderLabels,
) -> Result<()> {
    emit_loader_prefix(a, plan)?;
    crate::antidebug::emit_peb(a, &mut labs.bad, plan.cave)?;
    emit_checksum(a, plan, &mut labs.corrupt, false)?;
    emit_aead_decrypt(a, plan, false)?;
    emit_pe_base(a)?;
    emit_map_restore(a, plan)?;
    emit_module_walk(a, &mut labs.find, &mut labs.corrupt)?;
    crate::trace::emit_plant(a, plan, labs.stubs, labs.corrupt)?;
    emit_loader_tail(a, plan, &mut labs.bad, &mut labs.corrupt)?;
    crate::syscall::emit_pe_stubs(a, &mut labs.write, &mut labs.std_handle)?;
    crate::trace::emit_gates(
        a,
        plan,
        &mut labs.stubs,
        &mut labs.gate,
        labs.write,
        labs.std_handle,
    )
}

fn finish_image(
    a: &mut CodeAssembler,
    plan: &LoaderPlan,
    stubs: &CodeLabel,
    gate: &CodeLabel,
) -> Result<Image> {
    let encoded = a
        .assemble_options(
            plan.origin,
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )
        .map_err(|err| msg(err.to_string()))?;
    let stubs_ip = encoded
        .label_ip(stubs)
        .map_err(|err| msg(err.to_string()))?;
    let gate_ip = encoded.label_ip(gate).map_err(|err| msg(err.to_string()))?;
    if gate_ip.wrapping_sub(stubs_ip) != crate::trace::stub_block_len() as u64 {
        return Err(msg("gate is not adjacent to the index stubs"));
    }
    let bytes = encoded.inner.code_buffer;
    ensure_embedded_key(&bytes, plan)?;
    let stubs = usize::try_from(stubs_ip.wrapping_sub(plan.origin))
        .map_err(|_| msg("stub offset does not fit"))?;
    Ok(Image { bytes, stubs })
}

fn step(result: std::result::Result<(), IcedError>) -> Result<()> {
    result.map_err(|err| msg(err.to_string()))
}

fn emit_loader_prefix(a: &mut CodeAssembler, plan: &LoaderPlan) -> Result<()> {
    // Entry skips the AEAD key and nonce. Poly1305 is not checked here.
    step(a.db(&[0xeb, LOADER_BLOB_LEN as u8]))?;
    step(a.db(&plan.aead_key))?;
    step(a.db(&plan.aead_nonce))?;
    Ok(())
}

fn emit_checksum(
    a: &mut CodeAssembler,
    plan: &LoaderPlan,
    corrupt: &mut CodeLabel,
    native: bool,
) -> Result<()> {
    let mut sum_loop = a.create_label();
    let mut dec_loop = a.create_label();
    if native {
        emit_image_address(a, Register::RSI, plan.payload)?;
    } else {
        step(a.mov(rsi, plan.payload as i64))?;
    }
    step(a.mov(ecx, plan.payload_len))?;
    step(a.xor(eax, eax))?;
    step(a.set_label(&mut sum_loop))?;
    step(a.test(ecx, ecx))?;
    step(a.jz(dec_loop))?;
    step(a.movzx(edx, byte_ptr(rsi)))?;
    step(a.xor(eax, edx))?;
    step(a.inc(rsi))?;
    step(a.dec(ecx))?;
    step(a.jmp(sum_loop))?;
    step(a.set_label(&mut dec_loop))?;
    // XOR checksum is a fast reject. It is not cryptographic integrity.
    step(a.cmp(eax, plan.checksum as i32))?;
    step(a.jne(*corrupt))?;
    Ok(())
}

fn emit_pe_base(a: &mut CodeAssembler) -> Result<()> {
    step(a.db(&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]))?;
    step(a.mov(r15, qword_ptr(rax + 0x10i32)))?;
    Ok(())
}

fn emit_map_restore(a: &mut CodeAssembler, plan: &LoaderPlan) -> Result<()> {
    let mut top = a.create_label();
    let mut bytes = a.create_label();
    let mut next = a.create_label();
    let mut done = a.create_label();
    step(a.mov(rsi, plan.strings as i64))?;
    step(a.mov(ecx, dword_ptr(rsi)))?;
    step(a.add(rsi, 4i32))?;
    step(a.imul_3(ecx, ecx, 12i32))?;
    step(a.add(rsi, rcx))?;
    step(a.mov(ecx, dword_ptr(rsi)))?;
    step(a.add(rsi, 4i32))?;
    emit_map_loop(a, &mut top, &mut bytes, &mut next, &mut done)?;
    Ok(())
}

fn emit_map_loop(
    a: &mut CodeAssembler,
    top: &mut CodeLabel,
    bytes: &mut CodeLabel,
    next: &mut CodeLabel,
    done: &mut CodeLabel,
) -> Result<()> {
    step(a.set_label(top))?;
    step(a.test(ecx, ecx))?;
    step(a.jz(*done))?;
    step(a.mov(eax, dword_ptr(rsi)))?;
    step(a.mov(edx, dword_ptr(rsi + 4i32)))?;
    step(a.mov(r8d, dword_ptr(rsi + 8i32)))?;
    step(a.lea(r9, qword_ptr(r15 + rax)))?;
    step(a.set_label(bytes))?;
    step(a.test(edx, edx))?;
    step(a.jz(*next))?;
    step(a.xor(byte_ptr(r9), r8b))?;
    step(a.inc(r8))?;
    step(a.inc(r9))?;
    step(a.dec(edx))?;
    step(a.jmp(*bytes))?;
    step(a.set_label(next))?;
    step(a.add(rsi, 12i32))?;
    step(a.dec(ecx))?;
    step(a.jmp(*top))?;
    step(a.set_label(done))?;
    step(a.nop())?;
    Ok(())
}

fn emit_strings(a: &mut CodeAssembler, plan: &LoaderPlan) -> Result<()> {
    let mut str_top = a.create_label();
    let mut str_bytes = a.create_label();
    let mut str_next = a.create_label();
    let mut done = a.create_label();
    step(a.mov(rsi, plan.strings as i64))?;
    step(a.mov(ecx, dword_ptr(rsi)))?;
    step(a.add(rsi, 4i32))?;
    step(a.set_label(&mut str_top))?;
    step(a.test(ecx, ecx))?;
    step(a.jz(done))?;
    step(a.mov(eax, dword_ptr(rsi)))?;
    step(a.mov(edx, dword_ptr(rsi + 4i32)))?;
    step(a.mov(r8d, dword_ptr(rsi + 8i32)))?;
    step(a.lea(r9, qword_ptr(r15 + rax)))?;
    step(a.set_label(&mut str_bytes))?;
    step(a.test(edx, edx))?;
    step(a.jz(str_next))?;
    step(a.xor(byte_ptr(r9), r8b))?;
    step(a.inc(r8))?;
    step(a.inc(r9))?;
    step(a.dec(edx))?;
    step(a.jmp(str_bytes))?;
    step(a.set_label(&mut str_next))?;
    step(a.add(rsi, 12i32))?;
    step(a.dec(ecx))?;
    step(a.jmp(str_top))?;
    // The next instruction is the map restore. A jump to `find` skipped it.
    step(a.set_label(&mut done))?;
    Ok(())
}

fn emit_module_walk(
    a: &mut CodeAssembler,
    find: &mut CodeLabel,
    corrupt: &mut CodeLabel,
) -> Result<()> {
    let mut walk = a.create_label();
    let mut found = a.create_label();
    step(a.set_label(find))?;
    step(a.db(&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]))?;
    step(a.mov(rax, qword_ptr(rax + 0x18i32)))?;
    step(a.lea(rbx, qword_ptr(rax + 0x20i32)))?;
    step(a.mov(rcx, qword_ptr(rbx)))?;
    step(a.set_label(&mut walk))?;
    step(a.cmp(rcx, rbx))?;
    step(a.je(*corrupt))?;
    step(a.mov(rdx, qword_ptr(rcx + 0x20i32)))?;
    step(a.mov(r8, qword_ptr(rcx + 0x50i32)))?;
    step(a.cmp(word_ptr(r8), 0x6bi32))?;
    step(a.je(found))?;
    step(a.mov(rcx, qword_ptr(rcx)))?;
    step(a.jmp(walk))?;
    step(a.set_label(&mut found))?;
    step(a.mov(r12, rdx))?;
    Ok(())
}

fn emit_loader_tail(
    a: &mut CodeAssembler,
    plan: &LoaderPlan,
    bad: &mut CodeLabel,
    corrupt: &mut CodeLabel,
) -> Result<()> {
    let mut poison = a.create_label();
    crate::antidebug::emit_apis(a, plan.resolve, bad, &mut poison, plan.runtime)?;
    crate::trace::emit_scrub_volatiles(a)?;
    step(a.mov(rax, plan.table as i64))?;
    step(a.mov(r11, plan.calls as i64))?;
    step(a.mov(qword_ptr(r11), rax))?;
    step(a.mov(rax, plan.original as i64))?;
    step(a.jmp(rax))?;
    step(a.set_label(&mut poison))?;
    crate::antidebug::emit_poison(a, plan.runtime)?;
    step(a.set_label(bad))?;
    step(a.mov(eax, 0xdeb6u32))?;
    step(a.ret())?;
    step(a.set_label(corrupt))?;
    step(a.mov(eax, 0xbad1u32))?;
    step(a.ret())?;
    Ok(())
}

fn ensure_embedded_key(bytes: &[u8], plan: &LoaderPlan) -> Result<()> {
    let nonce_end = LOADER_NONCE_OFF + AEAD_NONCE_LEN;
    if bytes.len() < nonce_end
        || bytes[LOADER_KEY_OFF..LOADER_KEY_OFF + AEAD_KEY_LEN] != plan.aead_key
        || bytes[LOADER_NONCE_OFF..nonce_end] != plan.aead_nonce
    {
        return Err(msg("loader key prefix moved"));
    }
    Ok(())
}

/// True when `code` begins with the loader entry jump over the embedded AEAD key and nonce.
#[must_use]
pub fn is_loader_prologue(code: &[u8]) -> bool {
    code.len() >= 2 && code[0] == 0xeb && usize::from(code[1]) == LOADER_BLOB_LEN
}

/// Read the AEAD key and nonce the loader embeds for ChaCha20. The Poly1305 tag is not here.
pub fn read_embedded_aead(loader: &[u8]) -> Result<([u8; AEAD_KEY_LEN], [u8; AEAD_NONCE_LEN])> {
    let nonce_end = LOADER_NONCE_OFF + AEAD_NONCE_LEN;
    if loader.len() < nonce_end {
        return Err(msg("loader is missing the aead key"));
    }
    if !is_loader_prologue(loader) {
        return Err(msg("loader key prefix is not the expected jump"));
    }
    Ok((
        exact_bytes(&loader[LOADER_KEY_OFF..LOADER_KEY_OFF + AEAD_KEY_LEN])?,
        exact_bytes(&loader[LOADER_NONCE_OFF..nonce_end])?,
    ))
}

/// In-place ChaCha20 of the payload. Counter starts at 1, matching ChaCha20-Poly1305.
/// The tag is left for `inspect` / `run`.
fn emit_aead_decrypt(a: &mut CodeAssembler, plan: &LoaderPlan, native: bool) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(|err| msg(err.to_string()));
    let mut done = a.create_label();
    let mut block = a.create_label();
    let mut chunk_ready = a.create_label();
    let mut rounds = a.create_label();
    let mut xor_loop = a.create_label();
    let mut xor_done = a.create_label();

    go(a.push(r15))?;
    let key = plan.origin + LOADER_KEY_OFF as u64;
    if native {
        emit_image_address(a, Register::RSI, plan.payload)?;
    } else {
        go(a.mov(rsi, plan.payload as i64))?;
    }
    go(a.mov(rdi, rsi))?;
    go(a.mov(r9d, plan.payload_len))?;
    if native {
        emit_image_address(a, Register::R13, key)?;
    } else {
        go(a.mov(r13, key as i64))?;
    }
    go(a.mov(r10d, 1u32))?;
    go(a.test(r9, r9))?;
    go(a.jz(done))?;
    go(a.set_label(&mut block))?;
    go(a.mov(r12, 64u64))?;
    go(a.cmp(r9, 64i32))?;
    go(a.jae(chunk_ready))?;
    go(a.mov(r12, r9))?;
    go(a.set_label(&mut chunk_ready))?;
    go(a.sub(rsp, 128i32))?;
    go(a.mov(r11, rsp))?;
    emit_chacha_state(a)?;
    emit_chacha_rounds(a, &mut rounds)?;
    emit_chacha_xor(a, &mut xor_loop, &mut xor_done)?;
    go(a.add(rsp, 128i32))?;
    go(a.add(rsi, r12))?;
    go(a.add(rdi, r12))?;
    go(a.sub(r9, r12))?;
    go(a.inc(r10d))?;
    go(a.test(r9, r9))?;
    go(a.jnz(block))?;
    go(a.set_label(&mut done))?;
    go(a.pop(r15))?;
    Ok(())
}

fn emit_chacha_state(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(|err| msg(err.to_string()));
    for (index, word) in [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]
        .into_iter()
        .enumerate()
    {
        go(a.mov(eax, word))?;
        go(a.mov(dword_ptr(r11 + (index as i32 * 4)), eax))?;
    }
    for index in 0..8i32 {
        go(a.mov(eax, dword_ptr(r13 + (index * 4))))?;
        go(a.mov(dword_ptr(r11 + (16 + index * 4)), eax))?;
    }
    go(a.mov(dword_ptr(r11 + 48i32), r10d))?;
    for word in 0..3i32 {
        go(a.mov(eax, dword_ptr(r13 + (AEAD_KEY_LEN as i32 + word * 4))))?;
        go(a.mov(dword_ptr(r11 + (52 + word * 4)), eax))?;
    }
    for index in 0..8i32 {
        go(a.mov(rax, qword_ptr(r11 + (index * 8))))?;
        go(a.mov(qword_ptr(r11 + (64 + index * 8)), rax))?;
    }
    Ok(())
}

fn emit_chacha_rounds(a: &mut CodeAssembler, rounds: &mut CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(|err| msg(err.to_string()));
    go(a.mov(r15d, 10u32))?;
    go(a.set_label(rounds))?;
    emit_quarter(a, 0, 4, 8, 12)?;
    emit_quarter(a, 1, 5, 9, 13)?;
    emit_quarter(a, 2, 6, 10, 14)?;
    emit_quarter(a, 3, 7, 11, 15)?;
    emit_quarter(a, 0, 5, 10, 15)?;
    emit_quarter(a, 1, 6, 11, 12)?;
    emit_quarter(a, 2, 7, 8, 13)?;
    emit_quarter(a, 3, 4, 9, 14)?;
    go(a.dec(r15d))?;
    go(a.jnz(*rounds))?;
    for index in 0..16i32 {
        let at = index * 4;
        go(a.mov(eax, dword_ptr(r11 + at)))?;
        go(a.add(eax, dword_ptr(r11 + (64 + at))))?;
        go(a.mov(dword_ptr(r11 + (64 + at)), eax))?;
    }
    Ok(())
}

fn emit_chacha_xor(
    a: &mut CodeAssembler,
    xor_loop: &mut CodeLabel,
    xor_done: &mut CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(|err| msg(err.to_string()));
    go(a.lea(r8, qword_ptr(r11 + 64i32)))?;
    go(a.xor(edx, edx))?;
    go(a.set_label(xor_loop))?;
    go(a.cmp(rdx, r12))?;
    go(a.jae(*xor_done))?;
    go(a.mov(al, byte_ptr(rsi + rdx)))?;
    go(a.mov(cl, byte_ptr(r8 + rdx)))?;
    go(a.xor(al, cl))?;
    go(a.mov(byte_ptr(rdi + rdx), al))?;
    go(a.inc(rdx))?;
    go(a.jmp(*xor_loop))?;
    go(a.set_label(xor_done))?;
    Ok(())
}

fn emit_quarter(a: &mut CodeAssembler, a_i: i32, b_i: i32, c_i: i32, d_i: i32) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(|err| msg(err.to_string()));
    let word = |index: i32| dword_ptr(r11 + (64 + index * 4));
    go(a.mov(eax, word(a_i)))?;
    go(a.mov(ecx, word(b_i)))?;
    go(a.mov(edx, word(c_i)))?;
    go(a.mov(r8d, word(d_i)))?;
    go(a.add(eax, ecx))?;
    go(a.xor(r8d, eax))?;
    go(a.rol(r8d, 16u32))?;
    go(a.add(edx, r8d))?;
    go(a.xor(ecx, edx))?;
    go(a.rol(ecx, 12u32))?;
    go(a.add(eax, ecx))?;
    go(a.xor(r8d, eax))?;
    go(a.rol(r8d, 8u32))?;
    go(a.add(edx, r8d))?;
    go(a.xor(ecx, edx))?;
    go(a.rol(ecx, 7u32))?;
    go(a.mov(word(a_i), eax))?;
    go(a.mov(word(b_i), ecx))?;
    go(a.mov(word(c_i), edx))?;
    go(a.mov(word(d_i), r8d))?;
    Ok(())
}

#[must_use]
pub fn checksum(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |acc, byte| acc ^ u32::from(*byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(origin: u64, key: [u8; 32], nonce: [u8; 12]) -> LoaderPlan {
        LoaderPlan {
            origin,
            payload: 0x1400_3000,
            payload_len: 32,
            checksum: 0,
            aead_key: key,
            aead_nonce: nonce,
            strings: 0x1400_3000,
            imports: 0x1400_3100,
            table: 0x1400_3200,
            calls: 0x1400_2100,
            module: 0x1400_3300,
            resolve: 0x1400_1800,
            original: 0x1400_01000,
            cave: 0,
            runtime: 0,
            name_key: [0; 16],
        }
    }

    #[test]
    fn native_entry_preserves_the_windows_call_frame() {
        use crate::emu::{self, Detector, Policy, Region};

        let source = crate::sample::build().unwrap();
        let image = crate::pe::parse(&source.bytes).unwrap();
        let mut plan = plan(image.image_base + 0x10_0000, [1; 32], [2; 12]);
        plan.payload_len = 0;
        plan.payload = plan.origin + 0x1_0000;
        plan.table = plan.payload + 0x1000;
        plan.calls = plan.table + 0x1000;
        plan.runtime = plan.calls + 0x1000;
        let status_at = plan.calls + 8;
        let code = assemble_windows_native(
            &plan,
            NativeLoader {
                startup_status: status_at,
                preferred_base: image.image_base,
                functions: 0,
            },
        )
        .unwrap();
        let cases = [
            (Policy::default(), 1u32, None),
            (Policy::default(), 0, Some(0xdeb6)),
            (Policy::arm(Detector::BeingDebugged), 1, Some(0xdeb6)),
        ];
        for (policy, startup_status, expected) in cases {
            let mut machine = emu::load(&image, policy).unwrap();
            machine.regions.push(Region {
                base: plan.origin,
                data: code.clone(),
            });
            machine.regions.push(Region {
                base: plan.calls,
                data: vec![0; 12],
            });
            machine
                .write(status_at, &startup_status.to_le_bytes())
                .unwrap();
            machine.rip = plan.origin;
            let observed = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15];
            for reg in observed.into_iter().filter(|&reg| reg != 4) {
                machine.regs[reg] = 0xb000 + reg as u64;
            }
            let before = machine.regs;
            let original = machine.drive(|state| state.rip == plan.original).unwrap();
            assert_eq!(original, expected.is_none());
            assert_eq!(machine.exit_code, expected);
            for reg in observed {
                let value = if reg == 4 && expected.is_some() {
                    before[reg] + 8
                } else {
                    before[reg]
                };
                assert_eq!(machine.regs[reg], value, "register {reg}");
            }
            let calls = machine.read(plan.calls, 8).unwrap();
            assert_eq!(calls, expected.map_or(plan.table, |_| 0).to_le_bytes());
        }
    }

    #[test]
    fn native_loader_rebases_decrypted_runtime_fields() {
        use crate::emu::{self, Policy, Region};

        let source = crate::sample::build().unwrap();
        let mut image = crate::pe::parse(&source.bytes).unwrap();
        let base = image.image_base;
        let slide = 0x6000_0000;
        image.image_base += slide;
        let mut plan = plan(base + 0x10_0000, [3; 32], [5; 12]);
        plan.payload = plan.origin + 0x2000;
        plan.table = plan.payload + 0x10;
        plan.runtime = plan.payload + 0x80;
        plan.calls = plan.payload + 0x1000;
        let status = plan.calls + 8;
        let mut body = vec![0u8; 0x200];
        let fields = [8, 16, 24, 32, 40, crate::vm::RT_KEYS];
        for (i, field) in fields.iter().enumerate() {
            let at = 0x80 + *field as usize;
            body[at..at + 8].copy_from_slice(&(plan.payload + i as u64 * 8).to_le_bytes());
        }
        crate::crypto::aead_keystream(&plan.aead_key, &plan.aead_nonce, &mut body);
        plan.payload_len = body.len() as u32;
        plan.checksum = checksum(&body);
        let native = NativeLoader {
            startup_status: status,
            preferred_base: base,
            functions: 1,
        };
        let code = assemble_windows_native(&plan, native).unwrap();
        let mut machine = emu::load(&image, Policy::default()).unwrap();
        for (base, data) in [
            (plan.origin, code),
            (plan.payload, body),
            (plan.calls, vec![0; 12]),
        ] {
            machine.regions.push(Region {
                base: base + slide,
                data,
            });
        }
        machine.write(status + slide, &1u32.to_le_bytes()).unwrap();
        machine.rip = plan.origin + slide;
        assert!(machine
            .drive(|state| state.rip == plan.original + slide)
            .unwrap());
        let read = |addr| u64::from_le_bytes(machine.read(addr, 8).unwrap().try_into().unwrap());
        assert_eq!(read(plan.calls + slide), plan.table + slide);
        assert_eq!(read(plan.table + slide + 12), plan.runtime + slide);
        for (i, field) in fields.iter().enumerate() {
            assert_eq!(
                read(plan.runtime + slide + *field as u64),
                plan.payload + slide + i as u64 * 8
            );
        }
    }

    #[test]
    fn loader_embeds_the_aead_key_at_a_fixed_offset() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let bytes = assemble(&plan(0x1000, key, nonce)).unwrap();
        let zeros = assemble(&plan(0x1000, [0; 32], [0; 12])).unwrap();
        assert_eq!(bytes.len(), zeros.len());
        assert_ne!(bytes, zeros);
        assert_eq!(bytes[0], 0xeb);
        assert_eq!(usize::from(bytes[1]), LOADER_BLOB_LEN);
        assert!(is_loader_prologue(&bytes));
        assert!(!is_loader_prologue(&[0xeb, 0x2b]));
        let (read_key, read_nonce) = read_embedded_aead(&bytes).unwrap();
        assert_eq!(read_key, key);
        assert_eq!(read_nonce, nonce);
        assert!(read_embedded_aead(&[0, 1, 2]).is_err());
    }
}
