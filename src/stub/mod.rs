use iced_x86::code_asm::*;

mod chain;
mod dispatch;
mod edge;
mod external;
mod handlers;
mod morph;
mod pe_unwind;
mod stack;
mod window;

pub(crate) use chain::{
    bind_pe_bridges, bind_pe_guarded, bind_pe_tls, PE_TLS_CACHE_BASE, PE_TLS_INDEX_BYTES,
    PE_TLS_LIMIT, PE_TLS_PROBE_INDEX, PE_TLS_VECTOR, PE_VM_PROBE_BASE,
};
pub use morph::bind_metamorphic_seed;
pub(crate) use pe_unwind::{host_bridge, HOST_BRIDGE_LEN};

use crate::error::{msg, Result};
use crate::vm::{
    reg_layout_bytes, runtime_fits, BYTECODE_OPCODES, CACHE_OPEN, CHAIN_BYTES, CHAIN_FOLD,
    CHAIN_SLOTS, CTX_CACHE, CTX_SAVED, FILE_STACK_BYTES, FRAME_BYTES, FRAME_DECODE, FRAME_FLAGS,
    FRAME_IMAGE, FRAME_SPILL, GS_FRAME_AT, GS_MAP_BYTES, RT_FOLD, RT_INDEX, RT_KEY, RT_KEYS,
    RT_MASTER, RT_MIX, RT_SALT, RT_SCHED, RT_SLOTS, RT_TERM, SLOT_COUNT,
};

/// Host stack for ChaCha20. The guest `rsp` aliases the emulator stack, so the
/// cipher must not `call` or `push` on that pointer.
pub(super) const CHACHA_STACK: i32 = FRAME_DECODE + 0x1F0;
pub(super) const CHACHA_RSP: i32 = FRAME_DECODE + 0x1F8;
/// Return address, saved `rdi`, and the 128-byte ChaCha state sit below [`CHACHA_STACK`].
const CHACHA_SCRATCH: i32 = 8 + 8 + 128;
/// Machine `rsp` while the dispatcher uses [`WORK_STACK`]. The guest stack is that register.
const SAVED_RSP: i32 = FRAME_DECODE + 0xF0;
/// Private stack for the opener, the weave, and the closing-key check.
const WORK_STACK: i32 = FRAME_DECODE + 0xE0;

const _: () = assert!(WORK_STACK < SAVED_RSP);
const _: () = assert!(SAVED_RSP + 8 <= CHACHA_STACK - CHACHA_SCRATCH);
const _: () = assert!(GS_FRAME_AT + FRAME_BYTES as u64 + FILE_STACK_BYTES as u64 <= GS_MAP_BYTES);

pub struct NativeVm {
    pub bytes: Vec<u8>,
    /// External entry. Copies `RT_MASTER` into this thread's chain and clears the fold.
    pub dispatch: usize,
    /// Instruction loop. Entering here does not reset the thread chain.
    pub resume: usize,
    /// First byte of the handler region.
    pub handlers: usize,
    /// First byte of the ChaCha helper. The handler window ends here.
    pub cipher: usize,
    pub frame: usize,
    pub calls: usize,
    /// Image pool of chain blocks. The first qword is the next slot index.
    pub chains: usize,
    pub(crate) pe_host_resume: Option<usize>,
    pub(crate) pe_unwind_cleanup: Option<usize>,
}

impl NativeVm {
    /// Handler bodies. The difference percent is computed on this slice.
    #[must_use]
    pub fn handler_window(&self) -> &[u8] {
        &self.bytes[self.handlers..self.cipher]
    }

    /// Fetch prologue. The 16-byte anchor check uses this slice.
    #[must_use]
    pub fn dispatcher(&self) -> &[u8] {
        &self.bytes[self.dispatch..self.handlers]
    }
}

/// Handler window named by the diversity report and the S7 tests.
pub const HANDLER_WINDOW: &str =
    "окно хендлеров [handlers, cipher): байты хендлеров до ChaCha, процент от более длинного окна";

/// Dispatcher prefix of the interpreter. Anchor checks name this slice.
pub const DISPATCH_WINDOW: &str =
    "диспетчер [dispatch, handlers): байты от метки dispatch до первого хендлера";

/// Patch the external-key socket into an assembled image. `None` leaves offline mode.
pub(crate) fn install_socket(bytes: &mut [u8], path: Option<&str>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    crate::agent::check_path(path)?;
    let at = socket_mark(bytes)?;
    bytes[at + external::FLAG_AT] = 1;
    let dest = at + external::PATH_AT;
    bytes[dest..dest + crate::agent::PATH_CAP].fill(0);
    bytes[dest..dest + path.len()].copy_from_slice(path.as_bytes());
    Ok(())
}

fn socket_mark(bytes: &[u8]) -> Result<usize> {
    let mark = external::SOCKET_MARK;
    let mut found = None;
    for (index, window) in bytes.windows(mark.len()).enumerate() {
        if window != mark {
            continue;
        }
        if found.is_some() {
            return Err(msg("socket mark is not unique"));
        }
        found = Some(index);
    }
    found.ok_or_else(|| msg("socket mark is missing"))
}

pub fn assemble_vm(origin: u64) -> Result<NativeVm> {
    assemble_vm_seeded(origin, morph::current_seed())
}

/// Assembles one native interpreter at `origin`.
///
/// The fetch prologue and the handler bodies are chosen by `seed`. The compare
/// that used to pick a handler is a level-2 program: the stub jumps into one
/// fixed interpreter, and that interpreter runs the sealed dispatcher bytecode.
/// One seed keeps the same bytes at every origin. The process-gate offset is a
/// multiple of 8. External entry copies `RT_MASTER` into the thread chain and
/// clears its fold.
pub fn assemble_vm_seeded(origin: u64, seed: u64) -> Result<NativeVm> {
    assemble_vm_with_window(origin, seed, window::Mode::Legacy)
}

pub(crate) fn assemble_vm_for_authenticated_lab(origin: u64) -> Result<NativeVm> {
    assemble_vm_seeded_for_authenticated_lab(origin, morph::current_seed())
}

pub(crate) fn assemble_vm_seeded_for_authenticated_lab(origin: u64, seed: u64) -> Result<NativeVm> {
    assemble_vm_with_window(origin, seed, window::Mode::Immutable)
}

pub(crate) fn assemble_vm_for_external_lab(origin: u64) -> Result<NativeVm> {
    assemble_vm_with_window(origin, morph::current_seed(), window::Mode::External)
}

fn assemble_vm_with_window(origin: u64, seed: u64, mode: window::Mode) -> Result<NativeVm> {
    let probe = encode_vm(origin, seed, 0, mode)?;
    let first = gate_ip(&probe.encoded, &probe.labels.gate)?;
    let off = first
        .checked_sub(origin)
        .ok_or_else(|| msg("process gate is below the image"))?;
    let ready = padded_vm(origin, seed, align_pad(off), first, probe, mode)?;
    let ip = gate_ip(&ready.encoded, &ready.labels.gate)?;
    if !(ip - origin).is_multiple_of(8) {
        return Err(msg("process gate is not 8-byte aligned"));
    }
    gate_qword(&ready.encoded, origin, ip)?;
    let EncodedVm {
        encoded,
        labels,
        seed,
    } = ready;
    image_offsets(encoded, origin, seed, &labels)
}

/// Bytes that put `addr + pad` on an 8-byte boundary. The result is `0..8`.
pub(crate) fn align_pad(addr: u64) -> usize {
    (8 - (addr & 7) as usize) & 7
}

struct EncodedVm {
    encoded: CodeAssemblerResult,
    labels: VmLabels,
    seed: u64,
}

fn encode_vm(origin: u64, seed: u64, gate_pad: usize, mode: window::Mode) -> Result<EncodedVm> {
    let mut morph = morph::Morph::new(seed);
    let mut a = CodeAssembler::new(64).map_err(ice)?;
    let mut labels = create_vm_labels(&mut a, mode);
    emit_seeded_image(&mut a, &mut morph, &mut labels, gate_pad)?;
    let encoded = a
        .assemble_options(
            origin,
            iced_x86::BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )
        .map_err(ice)?;
    Ok(EncodedVm {
        encoded,
        labels,
        seed: morph.seed(),
    })
}

fn padded_vm(
    origin: u64,
    seed: u64,
    pad: usize,
    first: u64,
    probe: EncodedVm,
    mode: window::Mode,
) -> Result<EncodedVm> {
    if pad == 0 {
        return Ok(probe);
    }
    let again = encode_vm(origin, seed, pad, mode)?;
    let ip = gate_ip(&again.encoded, &again.labels.gate)?;
    if ip != first + pad as u64 {
        return Err(msg("process gate pad moved a branch"));
    }
    Ok(again)
}

fn gate_ip(encoded: &CodeAssemblerResult, gate: &CodeLabel) -> Result<u64> {
    encoded.label_ip(gate).map_err(ice)
}

fn gate_qword(encoded: &CodeAssemblerResult, origin: u64, ip: u64) -> Result<()> {
    let at = usize::try_from(ip - origin).map_err(|_| msg("process gate offset"))?;
    let bytes = encoded
        .inner
        .code_buffer
        .get(at..at + 8)
        .ok_or_else(|| msg("process gate is outside the image"))?;
    if bytes != [0; 8] {
        return Err(msg("process gate is not a zero qword"));
    }
    Ok(())
}

struct VmLabels {
    enter: CodeLabel,
    dispatch: CodeLabel,
    fail: CodeLabel,
    cached: CodeLabel,
    ready: CodeLabel,
    chacha: CodeLabel,
    open_one: CodeLabel,
    open_replay: CodeLabel,
    window_mode: window::Mode,
    weave: CodeLabel,
    decrypt: CodeLabel,
    close_chain: CodeLabel,
    frame: CodeLabel,
    calls: CodeLabel,
    frame_hold: CodeLabel,
    target_hold: CodeLabel,
    table: CodeLabel,
    inner: CodeLabel,
    chains: CodeLabel,
    bind_ctx: CodeLabel,
    leave_nest: CodeLabel,
    pe_host_resume: CodeLabel,
    pe_unwind_cleanup: CodeLabel,
    linux: CodeLabel,
    gate: CodeLabel,
    drop_window: CodeLabel,
    mix: CodeLabel,
    seal_slot: CodeLabel,
    reopen_slot: CodeLabel,
    open_inner: CodeLabel,
    wipe_inner: CodeLabel,
    ext: external::Slots,
    /// Handler emitted first. Its address is the jump-table anchor.
    anchor_index: usize,
    handlers: Vec<CodeLabel>,
    /// Second entry of each handler. Same body, different seed-varying prologue.
    odd: Vec<CodeLabel>,
}

fn create_vm_labels(a: &mut CodeAssembler, window_mode: window::Mode) -> VmLabels {
    let handlers = fresh_labels(a);
    let odd = fresh_labels(a);
    VmLabels {
        enter: a.create_label(),
        dispatch: a.create_label(),
        fail: a.create_label(),
        cached: a.create_label(),
        ready: a.create_label(),
        chacha: a.create_label(),
        open_one: a.create_label(),
        open_replay: a.create_label(),
        window_mode,
        weave: a.create_label(),
        decrypt: a.create_label(),
        close_chain: a.create_label(),
        frame: a.create_label(),
        calls: a.create_label(),
        frame_hold: a.create_label(),
        target_hold: a.create_label(),
        table: a.create_label(),
        inner: a.create_label(),
        chains: a.create_label(),
        bind_ctx: a.create_label(),
        leave_nest: a.create_label(),
        pe_host_resume: a.create_label(),
        pe_unwind_cleanup: a.create_label(),
        linux: a.create_label(),
        gate: a.create_label(),
        drop_window: a.create_label(),
        mix: a.create_label(),
        seal_slot: a.create_label(),
        reopen_slot: a.create_label(),
        open_inner: a.create_label(),
        wipe_inner: a.create_label(),
        ext: external::Slots::new(a),
        anchor_index: 0,
        handlers,
        odd,
    }
}

fn fresh_labels(a: &mut CodeAssembler) -> Vec<CodeLabel> {
    let mut labels = Vec::with_capacity(BYTECODE_OPCODES.len());
    for _ in BYTECODE_OPCODES {
        labels.push(a.create_label());
    }
    labels
}

fn emit_seeded_image(
    a: &mut CodeAssembler,
    morph: &mut morph::Morph,
    labels: &mut VmLabels,
    gate_pad: usize,
) -> Result<()> {
    emit_gate_pad(a, gate_pad)?;
    let mut emit_order: Vec<usize> = (0..BYTECODE_OPCODES.len()).collect();
    morph.shuffle(&mut emit_order);
    labels.anchor_index = emit_order[0];
    emit_entry(a, morph, labels)?;
    emit_handler_labels(a, morph, labels, &emit_order)?;
    emit_epilogue(a, labels, morph.seed())
}

fn emit_entry(
    a: &mut CodeAssembler,
    morph: &mut morph::Morph,
    labels: &mut VmLabels,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    // Trampoline and direct dispatch land here. Handlers jump to `dispatch`.
    go(a.set_label(&mut labels.enter))?;
    // Direct entry never reaches the trampoline's bind. Without a table owned by
    // this function, a later call would replay into an empty key map.
    // The call is five constant bytes and the GS load after it is nine more, so
    // a stamp sits on each side. Otherwise two seeds with the same stub length
    // share the first 16 bytes of the dispatcher.
    morph.stamp(a)?;
    go(a.call(labels.bind_ctx))?;
    morph.stamp(a)?;
    if labels.window_mode == window::Mode::External {
        go(a.call(labels.ext.begin_gate))?;
    }
    handlers::reset_weave(a, Some(morph))?;
    go(a.set_label(&mut labels.dispatch))?;
    emit_cache_check(a, morph, labels)?;
    emit_cached_ready(a, morph, labels)?;
    dispatch::emit_transfer(a, morph, labels)
}

fn emit_active_cache(a: &mut CodeAssembler, morph: &mut morph::Morph) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut have = a.create_label();
    // Stamps sit between the gs load and the shared-cache fallback. A 16-byte
    // dispatcher window then always includes a seed byte.
    morph.stamp(a)?;
    chain::emit_load_r8(a)?;
    morph.stamp(a)?;
    go(a.mov(r10, qword_ptr(r8 + CTX_CACHE)))?;
    morph.stamp(a)?;
    go(a.test(r10, r10))?;
    go(a.jnz(have))?;
    morph.stamp(a)?;
    go(a.mov(r10, qword_ptr(r13 + 8i32)))?;
    morph.stamp(a)?;
    go(a.mov(qword_ptr(r8 + CTX_CACHE), r10))?;
    go(a.set_label(&mut have))?;
    morph.stamp(a)?;
    Ok(())
}

fn emit_cache_check(
    a: &mut CodeAssembler,
    morph: &mut morph::Morph,
    labels: &mut VmLabels,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    // Stamps are flag-neutral `mov r11`. A pair of real instructions stays under
    // 14 bytes, so no 16-byte dispatcher run is shared across seeds.
    morph.stamp(a)?;
    go(a.mov(rax, r14))?;
    go(a.cmp(rax, qword_ptr(r13)))?;
    morph.stamp(a)?;
    go(a.jae(labels.fail))?;
    emit_active_cache(a, morph)?;
    go(a.cmp(byte_ptr(r10 + r14), u32::from(CACHE_OPEN)))?;
    go(a.je(labels.cached))?;
    // Internal calls must not push on the guest stack: `push rsp` reads that memory.
    // Each of these two is 7 bytes, so a stamp has to sit between them.
    morph.stamp(a)?;
    go(a.mov(qword_ptr(rbx + SAVED_RSP), rsp))?;
    morph.stamp(a)?;
    go(a.lea(rsp, qword_ptr(rbx + WORK_STACK)))?;
    morph.stamp(a)?;
    go(a.call(labels.open_one))?;
    go(a.mov(rsp, qword_ptr(rbx + SAVED_RSP)))?;
    morph.stamp(a)?;
    go(a.jmp(labels.cached))?;
    Ok(())
}

fn emit_cached_ready(
    a: &mut CodeAssembler,
    morph: &mut morph::Morph,
    labels: &mut VmLabels,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.set_label(&mut labels.cached))?;
    emit_active_cache(a, morph)?;
    go(a.mov(rcx, qword_ptr(r13 + 16i32)))?;
    go(a.mov(eax, dword_ptr(rcx + r14 * 4)))?;
    morph.stamp(a)?;
    go(a.mov(r12, r10))?;
    go(a.add(r12, qword_ptr(r13)))?;
    go(a.add(r12, rax))?;
    go(a.set_label(&mut labels.ready))?;
    morph.stamp(a)?;
    go(a.mov(qword_ptr(rbx + SAVED_RSP), rsp))?;
    morph.stamp(a)?;
    go(a.lea(rsp, qword_ptr(rbx + WORK_STACK)))?;
    morph.stamp(a)?;
    go(a.call(labels.mix))?;
    morph.stamp(a)?;
    go(a.mov(rsp, qword_ptr(rbx + SAVED_RSP)))?;
    morph.stamp(a)?;
    go(a.movzx(eax, byte_ptr(r12)))?;
    Ok(())
}

fn emit_handler_labels(
    a: &mut CodeAssembler,
    morph: &mut morph::Morph,
    labels: &mut VmLabels,
    emit_order: &[usize],
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let tags = BYTECODE_OPCODES;
    for index in emit_order.iter().copied() {
        // `set_label` writes the instruction index into this label. `label_ip`
        // reads that field, so the vector element itself has to be the one we set.
        go(a.set_label(&mut labels.handlers[index]))?;
        handlers::emit_handler(
            a,
            tags[index],
            &mut labels.odd[index],
            &mut handlers::Anchors {
                dispatch: &mut labels.dispatch,
                fail: &mut labels.fail,
                calls: &labels.calls,
                frame_hold: &labels.frame_hold,
                target_hold: &labels.target_hold,
                close_chain: &labels.close_chain,
                bind_ctx: &labels.bind_ctx,
                leave_nest: &labels.leave_nest,
                pe_host_resume: &mut labels.pe_host_resume,
                linux: &labels.linux,
                drop_window: &labels.drop_window,
                agent_begin: (labels.window_mode == window::Mode::External)
                    .then_some(labels.ext.begin_gate),
            },
            morph,
        )?;
    }
    go(a.set_label(&mut labels.table))?;
    go(a.db(&[0u8; 256 * 4]))?;
    // Odd handler entries. The level-2 tail adds [`dispatch::TABLE_BYTES`].
    go(a.db(&[0u8; 256 * 4]))?;
    Ok(())
}

fn emit_epilogue(a: &mut CodeAssembler, labels: &mut VmLabels, seed: u64) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    emit_chacha(a, &mut labels.chacha)?;
    edge::emit_mix(a, &mut labels.mix)?;
    if !chain::pe_tls_bound() {
        external::emit_code(a, &mut labels.ext)?;
        crate::antidebug::emit_linux_body(a, &mut labels.linux)?;
    }
    emit_weave(a, &mut labels.weave)?;
    emit_decrypt(a, &mut labels.decrypt, &labels.chacha)?;
    emit_open_one(a, labels)?;
    emit_close_chain(
        a,
        &mut labels.close_chain,
        &labels.weave,
        &labels.fail,
        &labels.ext,
    )?;
    emit_window_stubs(a, labels)?;
    dispatch::emit_interpreter(a, labels, seed)?;
    emit_context_calls(a, labels)?;
    go(a.set_label(&mut labels.fail))?;
    if chain::pe_tls_bound() {
        // Native helper failures return before reaching here, balancing
        // hardware and shadow-stack CALL frames. Cleanup uses the VM stack.
        go(a.lea(rsp, qword_ptr(rbx + WORK_STACK)))?;
    }
    go(a.call(labels.drop_window))?;
    if labels.window_mode == window::Mode::External {
        external::emit_failure_gate(a, &labels.ext)?;
        return emit_epilogue_data(a, labels);
    }
    go(a.call(labels.leave_nest))?;
    if chain::pe_tls_bound() {
        pe_unwind::emit_fail_return(a)?;
    } else {
        handlers::emit_fail_return(a)?;
    }
    emit_epilogue_data(a, labels)
}

fn emit_epilogue_data(a: &mut CodeAssembler, labels: &mut VmLabels) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    if chain::pe_tls_bound() {
        go(a.db(&[0; PE_TLS_INDEX_BYTES]))?;
    }
    go(a.set_label(&mut labels.frame))?;
    go(a.db(&[0u8; FRAME_BYTES]))?;
    // Private-slot stack. A non-zero fill keeps it from looking like a handler pointer table.
    for _ in 0..(FILE_STACK_BYTES / 64) {
        go(a.db(&[0xA5u8; 64]))?;
    }
    go(a.set_label(&mut labels.calls))?;
    go(a.dq(&[0u64]))?;
    go(a.set_label(&mut labels.frame_hold))?;
    go(a.dq(&[0u64]))?;
    go(a.set_label(&mut labels.target_hold))?;
    go(a.dq(&[0u64]))?;
    go(a.set_label(&mut labels.gate))?;
    go(a.dq(&[0u64]))?;
    go(a.set_label(&mut labels.chains))?;
    go(a.dq(&[0u64]))?;
    // Non-zero fill so the pool is not a 256×8 zero pointer table.
    for _ in 0..CHAIN_SLOTS {
        go(a.db(&[0xA5u8; CHAIN_BYTES]))?;
    }
    if !chain::pe_tls_bound() {
        external::emit_data(a, &mut labels.ext)?;
    }
    Ok(())
}

/// Prefix nops shift every label equally. The gate offset becomes a multiple of
/// 8, and rip-relative bytes in the helper tail stay the same for every seed.
fn emit_gate_pad(a: &mut CodeAssembler, pad: usize) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    for _ in 0..pad {
        go(a.nop())?;
    }
    Ok(())
}

fn emit_window_stubs(a: &mut CodeAssembler, labels: &mut VmLabels) -> Result<()> {
    let mode = labels.window_mode;
    window::emit_seal_slot(a, &mut labels.seal_slot, &labels.chacha, mode)?;
    window::emit_reopen_slot(
        a,
        &mut labels.reopen_slot,
        &labels.chacha,
        &labels.open_replay,
        &labels.ext.fetch,
        mode,
    )?;
    window::emit_drop(
        a,
        &mut labels.drop_window,
        &labels.gate,
        &labels.chacha,
        mode,
    )
}

fn emit_context_calls(a: &mut CodeAssembler, labels: &mut VmLabels) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.set_label(&mut labels.bind_ctx))?;
    emit_bind_context(
        a,
        &labels.fail,
        labels.window_mode == window::Mode::External,
    )?;
    go(a.set_label(&mut labels.leave_nest))?;
    chain::emit_leave_nest(a)?;
    go(a.ret())?;
    if chain::pe_tls_bound() && !chain::pe_guarded() {
        pe_unwind::emit_cleanup(a, &mut labels.pe_unwind_cleanup)?;
    }
    Ok(())
}

fn emit_bind_context(a: &mut CodeAssembler, fail: &CodeLabel, external: bool) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    if !chain::pe_tls_bound() {
        chain::emit_bind_fn(a, fail, external)?;
        return go(a.ret());
    }
    let mut bad = a.create_label();
    chain::emit_bind_fn(a, &bad, false)?;
    go(a.xor(eax, eax))?;
    go(a.ret())?;
    go(a.set_label(&mut bad))?;
    go(a.mov(eax, 1u32))?;
    go(a.ret())
}

fn image_offsets(
    encoded: CodeAssemblerResult,
    origin: u64,
    seed: u64,
    labels: &VmLabels,
) -> Result<NativeVm> {
    let dispatch_at = label_offset(&encoded, origin, &labels.enter)?;
    let mut handlers_at = usize::MAX;
    let mut handler_offs = Vec::with_capacity(labels.handlers.len());
    for label in &labels.handlers {
        let off = label_offset(&encoded, origin, label)?;
        handlers_at = handlers_at.min(off);
        handler_offs.push(off);
    }
    let anchor_at = handler_offs[labels.anchor_index];
    let odd_offs = label_list(&encoded, origin, &labels.odd)?;
    let table_at = label_offset(&encoded, origin, &labels.table)?;
    if anchor_at != handlers_at {
        return Err(msg("inner anchor is not the first handler"));
    }
    let cipher_at = label_offset(&encoded, origin, &labels.chacha)?;
    let frame_at = label_offset(&encoded, origin, &labels.frame)?;
    let calls_at = label_offset(&encoded, origin, &labels.calls)?;
    let resume_at = label_offset(&encoded, origin, &labels.dispatch)?;
    let chains_at = label_offset(&encoded, origin, &labels.chains)?;
    let pe_offset = |label| {
        (chain::pe_tls_bound() && !chain::pe_guarded())
            .then(|| label_offset(&encoded, origin, label))
            .transpose()
    };
    let pe_host_resume = pe_offset(&labels.pe_host_resume)?;
    let pe_unwind_cleanup = pe_offset(&labels.pe_unwind_cleanup)?;
    let mut bytes = encoded.inner.code_buffer;
    dispatch::patch_table(
        &mut bytes,
        seed,
        anchor_at,
        table_at,
        &handler_offs,
        &odd_offs,
    )?;
    Ok(NativeVm {
        bytes,
        dispatch: dispatch_at,
        resume: resume_at,
        handlers: handlers_at,
        cipher: cipher_at,
        frame: frame_at,
        calls: calls_at,
        chains: chains_at,
        pe_host_resume,
        pe_unwind_cleanup,
    })
}

fn label_list(
    encoded: &CodeAssemblerResult,
    origin: u64,
    labels: &[CodeLabel],
) -> Result<Vec<usize>> {
    let mut offs = Vec::with_capacity(labels.len());
    for label in labels {
        offs.push(label_offset(encoded, origin, label)?);
    }
    Ok(offs)
}

fn label_offset(encoded: &CodeAssemblerResult, origin: u64, label: &CodeLabel) -> Result<usize> {
    Ok((encoded.label_ip(label).map_err(ice)? - origin) as usize)
}

/// Measured byte difference of one handler window against the next seed.
///
/// The percent is `different_bytes * 100 / window_len`.
pub struct HandlerDiff {
    /// Name of the compared handler window.
    pub window: &'static str,
    /// Longer of the two windows, in bytes. [`Self::difference_percent`] divides by this.
    pub window_len: u32,
    /// Bytes that differ, including the tail that exists only on the longer window.
    pub different_bytes: u32,
    /// Integer percent `different_bytes * 100 / window_len`.
    pub difference_percent: u32,
}

/// Handler-window difference of `seed` against `seed + 1`.
///
/// [`HandlerDiff::window_len`] is the longer window, and the percent divides by it.
pub fn measure_handler_difference(seed: u64) -> Result<HandlerDiff> {
    let left = assemble_vm_seeded(0x1000, seed)?;
    let right = assemble_vm_seeded(0x1000, seed.wrapping_add(1))?;
    let left_window = left.handler_window();
    let right_window = right.handler_window();
    if left_window.is_empty() || right_window.is_empty() {
        return Err(msg("handler window is empty"));
    }
    let (different_bytes, difference_percent) = window_difference(left_window, right_window);
    Ok(HandlerDiff {
        window: HANDLER_WINDOW,
        window_len: u32::try_from(compared_len(left_window, right_window)).unwrap_or(u32::MAX),
        different_bytes,
        difference_percent,
    })
}

/// Length the difference percent divides by: the longer of the two windows.
fn compared_len(left: &[u8], right: &[u8]) -> usize {
    left.len().max(right.len())
}

/// Positional difference. Extra bytes in the longer slice count as different.
///
/// The percent divides by the longer length, which [`HandlerDiff::window_len`] stores.
#[must_use]
pub fn window_difference(left: &[u8], right: &[u8]) -> (u32, u32) {
    let compared = compared_len(left, right);
    let mut different = left.len().abs_diff(right.len());
    for (a, b) in left.iter().zip(right.iter()) {
        if a != b {
            different += 1;
        }
    }
    let percent = different
        .saturating_mul(100)
        .checked_div(compared)
        .unwrap_or(0);
    (
        u32::try_from(different).unwrap_or(u32::MAX),
        u32::try_from(percent).unwrap_or(u32::MAX),
    )
}

pub(super) fn ice(err: IcedError) -> crate::error::Error {
    msg(err.to_string())
}

fn load_fold(a: &mut CodeAssembler) -> Result<()> {
    chain::emit_load_r11(a)?;
    a.mov(eax, dword_ptr(r11 + CHAIN_FOLD)).map_err(ice)
}

fn copy_chain_key(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    for word in 0..4i32 {
        go(a.mov(rcx, qword_ptr(r11 + (word * 8))))?;
        go(a.mov(qword_ptr(r8 + (word * 8)), rcx))?;
    }
    Ok(())
}

fn advance_fold(a: &mut CodeAssembler) -> Result<()> {
    chain::emit_load_r11(a)?;
    a.inc(dword_ptr(r11 + CHAIN_FOLD)).map_err(ice)
}

fn emit_open_one(a: &mut CodeAssembler, labels: &mut VmLabels) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut absorb = a.create_label();
    let mut do_decrypt = a.create_label();
    let mut fresh = a.create_label();
    go(a.set_label(&mut labels.open_one))?;
    window::emit_acquire(a, &labels.gate)?;
    window::emit_before_open(a, &labels.chacha, &mut fresh, labels.window_mode)?;
    external::emit_fetch_gate(a, &labels.ext)?;
    load_fold(a)?;
    go(a.cmp(eax, r14d))?;
    go(a.ja(labels.open_replay))?;
    go(a.set_label(&mut absorb))?;
    load_fold(a)?;
    go(a.cmp(eax, r14d))?;
    go(a.ja(labels.open_replay))?;
    // The key before this block's bytes are folded decrypts the block.
    go(a.mov(r15d, eax))?;
    go(a.shl(r15d, 5u32))?;
    chain::emit_keys_r8(a)?;
    go(a.add(r8, r15))?;
    copy_chain_key(a)?;
    go(a.cmp(eax, r14d))?;
    go(a.je(do_decrypt))?;
    go(a.mov(r15d, eax))?;
    go(a.call(labels.weave))?;
    advance_fold(a)?;
    go(a.jmp(absorb))?;
    go(a.set_label(&mut do_decrypt))?;
    go(a.call(labels.decrypt))?;
    go(a.ret())?;
    emit_open_replay(a, &mut labels.open_replay, &labels.decrypt)?;
    Ok(())
}

fn emit_open_replay(
    a: &mut CodeAssembler,
    replay: &mut CodeLabel,
    decrypt: &CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.set_label(replay))?;
    chain::emit_load_r11(a)?;
    for word in 0..4i32 {
        go(a.mov(rax, qword_ptr(r11 + (word * 8))))?;
        go(a.mov(qword_ptr(r11 + (CTX_SAVED + word * 8)), rax))?;
    }
    go(a.mov(r15d, r14d))?;
    go(a.shl(r15d, 5u32))?;
    chain::emit_keys_r8(a)?;
    go(a.add(r8, r15))?;
    for word in 0..4i32 {
        go(a.mov(rax, qword_ptr(r8 + (word * 8))))?;
        go(a.mov(qword_ptr(r11 + (word * 8)), rax))?;
    }
    go(a.call(*decrypt))?;
    chain::emit_load_r11(a)?;
    for word in 0..4i32 {
        go(a.mov(rax, qword_ptr(r11 + (CTX_SAVED + word * 8))))?;
        go(a.mov(qword_ptr(r11 + (word * 8)), rax))?;
    }
    go(a.ret())?;
    Ok(())
}

fn emit_decrypt(a: &mut CodeAssembler, decrypt: &mut CodeLabel, chacha: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.set_label(decrypt))?;
    chain::emit_nonce(a, true)?;
    go(a.mov(rcx, qword_ptr(r13 + 16i32)))?;
    go(a.mov(eax, dword_ptr(rcx + r14 * 4)))?;
    go(a.mov(rsi, qword_ptr(r13 + 24i32)))?;
    go(a.add(rsi, rax))?;
    go(a.mov(rcx, qword_ptr(r13 + 32i32)))?;
    go(a.mov(ecx, dword_ptr(rcx + r14 * 4)))?;
    chain::emit_cache_r10(a)?;
    go(a.mov(rdi, r10))?;
    go(a.add(rdi, qword_ptr(r13)))?;
    go(a.add(rdi, rax))?;
    go(a.xor(r10d, r10d))?;
    go(a.mov(qword_ptr(rbx + CHACHA_RSP), rsp))?;
    go(a.lea(rsp, qword_ptr(rbx + CHACHA_STACK)))?;
    go(a.call(*chacha))?;
    go(a.mov(rsp, qword_ptr(rbx + CHACHA_RSP)))?;
    go(a.movzx(eax, byte_ptr(rdi)))?;
    go(a.mov(rcx, qword_ptr(r13 + 0x28i32)))?;
    go(a.movzx(eax, byte_ptr(rcx + rax)))?;
    go(a.mov(byte_ptr(rdi), al))?;
    chain::emit_cache_r10(a)?;
    go(a.mov(byte_ptr(r10 + r14), u32::from(CACHE_OPEN)))?;
    window::emit_note_open(a)?;
    go(a.ret())?;
    Ok(())
}

fn emit_weave(a: &mut CodeAssembler, weave: &mut CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut diffuse = a.create_label();
    go(a.set_label(weave))?;
    go(a.push(r14))?;
    go(a.push(r15))?;
    emit_weave_absorb(a)?;
    emit_weave_bytes(a, &diffuse)?;
    emit_weave_diffuse(a, &mut diffuse)?;
    emit_weave_commit(a)
}

fn emit_weave_absorb(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut mix_len = a.create_label();
    go(a.mov(r12d, r15d))?;
    go(a.mov(rcx, qword_ptr(r13 + 32i32)))?;
    go(a.mov(ecx, dword_ptr(rcx + r15 * 4)))?;
    go(a.mov(rax, qword_ptr(r13 + 16i32)))?;
    go(a.mov(eax, dword_ptr(rax + r15 * 4)))?;
    go(a.mov(rsi, qword_ptr(r13 + 24i32)))?;
    go(a.add(rsi, rax))?;
    go(a.sub(rsp, 64i32))?;
    chain::emit_load_r11(a)?;
    for word in 0..4i32 {
        go(a.mov(rax, qword_ptr(r11 + (word * 8))))?;
        go(a.mov(qword_ptr(rsp + word * 8), rax))?;
    }
    go(a.mov(eax, r12d))?;
    for shift in 0..4i32 {
        go(a.mov(r8b, al))?;
        go(a.xor(byte_ptr(rsp + shift), r8b))?;
        if shift != 3 {
            go(a.shr(eax, 8u32))?;
        }
    }
    go(a.mov(eax, ecx))?;
    go(a.set_label(&mut mix_len))?;
    for shift in 0..4i32 {
        go(a.mov(r8b, al))?;
        go(a.xor(byte_ptr(rsp + (4 + shift)), r8b))?;
        if shift != 3 {
            go(a.shr(eax, 8u32))?;
        }
    }
    Ok(())
}

fn emit_weave_bytes(a: &mut CodeAssembler, diffuse: &CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut byte_loop = a.create_label();
    go(a.xor(edx, edx))?;
    go(a.set_label(&mut byte_loop))?;
    go(a.cmp(rdx, rcx))?;
    go(a.jae(*diffuse))?;
    go(a.mov(al, byte_ptr(rsi + rdx)))?;
    go(a.mov(r8d, edx))?;
    go(a.and(r8d, 31u32))?;
    go(a.mov(r9b, byte_ptr(rsp + r8)))?;
    go(a.add(r9b, al))?;
    go(a.rol(r9b, 1u32))?;
    go(a.mov(r10d, r8d))?;
    go(a.add(r10d, 7u32))?;
    go(a.and(r10d, 31u32))?;
    go(a.xor(r9b, byte_ptr(rsp + r10)))?;
    go(a.mov(byte_ptr(rsp + r8), r9b))?;
    go(a.mov(r10d, r8d))?;
    go(a.add(r10d, 3u32))?;
    go(a.and(r10d, 31u32))?;
    go(a.movzx(r11d, dl))?;
    go(a.imul_3(r11d, r11d, 0x1di32))?;
    go(a.add(r11b, al))?;
    go(a.xor(byte_ptr(rsp + r10), r11b))?;
    go(a.inc(rdx))?;
    go(a.jmp(byte_loop))?;
    Ok(())
}

fn emit_weave_diffuse(a: &mut CodeAssembler, diffuse: &mut CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut round = a.create_label();
    let mut copy_snap = a.create_label();
    let mut mix_slot = a.create_label();
    let mut rounds_done = a.create_label();
    go(a.set_label(diffuse))?;
    go(a.mov(r11d, 1u32))?;
    go(a.set_label(&mut round))?;
    go(a.xor(edx, edx))?;
    go(a.set_label(&mut copy_snap))?;
    go(a.cmp(edx, 32u32))?;
    go(a.jae(mix_slot))?;
    go(a.mov(al, byte_ptr(rsp + rdx)))?;
    go(a.mov(byte_ptr(rsp + rdx + 32), al))?;
    go(a.inc(edx))?;
    go(a.jmp(copy_snap))?;
    go(a.set_label(&mut mix_slot))?;
    go(a.xor(edx, edx))?;
    let mut mix_one = a.create_label();
    let mut mix_done = a.create_label();
    go(a.set_label(&mut mix_one))?;
    go(a.cmp(edx, 32u32))?;
    go(a.jae(mix_done))?;
    go(a.mov(al, byte_ptr(rsp + rdx + 32)))?;
    go(a.mov(r8d, edx))?;
    go(a.inc(r8d))?;
    go(a.and(r8d, 31u32))?;
    go(a.add(al, byte_ptr(rsp + r8 + 32)))?;
    go(a.rol(al, 1u32))?;
    go(a.mov(r8d, edx))?;
    go(a.add(r8d, 13u32))?;
    go(a.and(r8d, 31u32))?;
    go(a.xor(al, byte_ptr(rsp + r8 + 32)))?;
    go(a.mov(byte_ptr(rsp + rdx), al))?;
    go(a.inc(edx))?;
    go(a.jmp(mix_one))?;
    go(a.set_label(&mut mix_done))?;
    go(a.dec(r11d))?;
    go(a.jnz(round))?;
    go(a.set_label(&mut rounds_done))?;
    Ok(())
}

fn emit_weave_commit(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut store = a.create_label();
    let mut stored = a.create_label();
    chain::emit_load_r11(a)?;
    go(a.xor(edx, edx))?;
    go(a.set_label(&mut store))?;
    go(a.cmp(edx, 32u32))?;
    go(a.jae(stored))?;
    go(a.mov(al, byte_ptr(rsp + rdx)))?;
    go(a.mov(byte_ptr(r11 + rdx), al))?;
    go(a.inc(edx))?;
    go(a.jmp(store))?;
    go(a.set_label(&mut stored))?;
    go(a.add(rsp, 64i32))?;
    go(a.pop(r15))?;
    go(a.pop(r14))?;
    go(a.ret())?;
    Ok(())
}

fn emit_close_chain(
    a: &mut CodeAssembler,
    close_chain: &mut CodeLabel,
    weave: &CodeLabel,
    fail: &CodeLabel,
    ext: &external::Slots,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut compare = a.create_label();
    let mut cmp_loop = a.create_label();
    let mut ok = a.create_label();
    let mut bad = a.create_label();
    let mismatch = if chain::pe_tls_bound() { bad } else { *fail };
    go(a.set_label(close_chain))?;
    external::emit_commit_gate(a, ext)?;
    load_fold(a)?;
    go(a.cmp(rax, qword_ptr(r13)))?;
    go(a.jae(compare))?;
    go(a.mov(r15d, eax))?;
    go(a.call(*weave))?;
    advance_fold(a)?;
    go(a.jmp(*close_chain))?;
    go(a.set_label(&mut compare))?;
    go(a.xor(ecx, ecx))?;
    chain::emit_load_r11(a)?;
    go(a.set_label(&mut cmp_loop))?;
    go(a.cmp(ecx, 32u32))?;
    go(a.jae(ok))?;
    go(a.mov(al, byte_ptr(r11 + rcx)))?;
    go(a.cmp(al, byte_ptr(r13 + rcx + RT_TERM)))?;
    go(a.jne(mismatch))?;
    go(a.inc(ecx))?;
    go(a.jmp(cmp_loop))?;
    go(a.set_label(&mut ok))?;
    if chain::pe_tls_bound() {
        go(a.xor(eax, eax))?;
        go(a.ret())?;
        go(a.set_label(&mut bad))?;
        go(a.mov(eax, 1u32))?;
    }
    go(a.ret())
}

fn emit_chacha(a: &mut CodeAssembler, chacha: &mut CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut done = a.create_label();
    let mut block = a.create_label();
    let mut chunk_ready = a.create_label();
    let mut rounds = a.create_label();
    let mut xor_loop = a.create_label();
    let mut xor_done = a.create_label();

    go(a.set_label(chacha))?;
    // The caller reads the buffer through the original rdi after we return.
    go(a.push(rdi))?;
    go(a.test(rcx, rcx))?;
    go(a.jz(done))?;
    go(a.mov(r9, rcx))?;
    // emit_decrypt clears r10, so the first chunk uses counter 0. Later chunks
    // increment r10. The weave mix does not call ChaCha.
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
    go(a.pop(rdi))?;
    go(a.ret())?;
    Ok(())
}

fn emit_chacha_state(a: &mut CodeAssembler) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    for (index, word) in [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]
        .into_iter()
        .enumerate()
    {
        go(a.mov(eax, word))?;
        go(a.mov(dword_ptr(r11 + (index as i32 * 4)), eax))?;
    }
    chain::emit_load_r15(a)?;
    for index in 0..8i32 {
        go(a.mov(eax, dword_ptr(r15 + (index * 4))))?;
        go(a.mov(dword_ptr(r11 + (16 + index * 4)), eax))?;
    }
    go(a.mov(dword_ptr(r11 + 48i32), r10d))?;
    go(a.mov(eax, dword_ptr(r15 + crate::vm::CTX_INDEX)))?;
    go(a.mov(dword_ptr(r11 + 52i32), eax))?;
    go(a.mov(eax, dword_ptr(r15 + crate::vm::CTX_SALT)))?;
    go(a.mov(dword_ptr(r11 + 56i32), eax))?;
    go(a.mov(eax, dword_ptr(r15 + (crate::vm::CTX_SALT + 4))))?;
    go(a.mov(dword_ptr(r11 + 60i32), eax))?;
    for index in 0..8i32 {
        go(a.mov(rax, qword_ptr(r11 + (index * 8))))?;
        go(a.mov(qword_ptr(r11 + (64 + index * 8)), rax))?;
    }
    Ok(())
}

fn emit_chacha_rounds(a: &mut CodeAssembler, rounds: &mut CodeLabel) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
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
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut wide = a.create_label();
    // The callers provide disjoint buffers or identical source/destination.
    // Each unaligned qword stays inside the complete eight-byte prefix.
    go(a.lea(r8, qword_ptr(r11 + 64i32)))?;
    go(a.xor(edx, edx))?;
    go(a.mov(rcx, r12))?;
    go(a.and(rcx, -8i32))?;
    go(a.jz(*xor_loop))?;
    go(a.set_label(&mut wide))?;
    go(a.mov(rax, qword_ptr(rsi + rdx)))?;
    go(a.xor(rax, qword_ptr(r8 + rdx)))?;
    go(a.mov(qword_ptr(rdi + rdx), rax))?;
    go(a.add(rdx, 8i32))?;
    go(a.cmp(rdx, rcx))?;
    go(a.jb(wide))?;
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
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
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

fn write_held_key(
    mem: &mut crate::emu::Machine,
    at: u64,
    key: &crate::secret::KeyPage,
) -> Result<()> {
    let mut bytes = key.bytes();
    let stored = mem.write(at, &bytes);
    crate::secret::wipe(&mut bytes);
    stored
}

// Eight independent fields of the native runtime window. Grouping them would
// only rename this list; each store below writes one address.
#[allow(clippy::too_many_arguments)]
pub fn place_runtime(
    func: &crate::vm::BcFunc,
    inv: &[u8; 256],
    crc: u32,
    slots: &crate::vm::SlotMap,
    handler_mix: u32,
    mem: &mut crate::emu::Machine,
    at: u64,
    keys: u64,
) -> Result<()> {
    let mut blob = Vec::new();
    let mut offs = Vec::new();
    let mut lens = Vec::new();
    for insn in &func.insns {
        offs.extend((blob.len() as u32).to_le_bytes());
        lens.extend((insn.bytes.len() as u32).to_le_bytes());
        blob.extend(&insn.bytes);
    }
    let tables = runtime_fits(at, func.insns.len(), blob.len())?;
    mem.write(at, &(func.insns.len() as u64).to_le_bytes())?;
    mem.write(at + 8, &tables.cache.to_le_bytes())?;
    mem.write(at + 16, &tables.offs.to_le_bytes())?;
    mem.write(at + 24, &tables.blob.to_le_bytes())?;
    mem.write(at + 32, &tables.lens.to_le_bytes())?;
    mem.write(at + 0x28, &tables.inv.to_le_bytes())?;
    mem.write(at + 0x30, &crc.to_le_bytes())?;
    mem.write(at + RT_MIX as u64, &reg_layout_bytes(slots, handler_mix))?;
    mem.write(at + RT_SALT as u64, &func.salt)?;
    write_func_words(mem, at, func)?;
    write_held_key(mem, at + RT_KEY as u64, &func.key)?;
    write_held_key(mem, at + RT_MASTER as u64, &func.key)?;
    mem.write(at + RT_KEYS as u64, &keys.to_le_bytes())?;
    mem.write(at + RT_FOLD as u64, &0u32.to_le_bytes())?;
    mem.write(at + RT_TERM as u64, &func.terminal)?;
    mem.write(tables.offs, &offs)?;
    mem.write(tables.lens, &lens)?;
    mem.write(tables.inv, inv)?;
    mem.write(tables.blob, &blob)?;
    place_inner(func, mem, at)?;
    Ok(())
}

fn write_func_words(
    mem: &mut crate::emu::Machine,
    at: u64,
    func: &crate::vm::BcFunc,
) -> Result<()> {
    mem.write(at + RT_INDEX as u64, &func.rva.to_le_bytes())?;
    mem.write(at + RT_SCHED as u64, &func.sched.to_le_bytes())?;
    Ok(())
}

fn place_inner(func: &crate::vm::BcFunc, mem: &mut crate::emu::Machine, at: u64) -> Result<()> {
    let sealed = func.dispatcher()?;
    mem.write(at + crate::vm::INNER_KEY as u64, &sealed.key)?;
    mem.write(at + crate::vm::INNER_NONCE as u64, &sealed.nonce)?;
    mem.write(
        at + crate::vm::INNER_LEN as u64,
        &(sealed.bytes.len() as u32).to_le_bytes(),
    )?;
    mem.write(at + crate::vm::INNER_READY as u64, &[0])?;
    mem.write(at + crate::vm::INNER_CIPHER as u64, &sealed.bytes)?;
    Ok(())
}

pub fn assemble_resolve(origin: u64) -> Result<Vec<u8>> {
    crate::trace::assemble_resolver(origin, 0)
}

pub struct Trampoline {
    pub origin: u64,
    pub frame: u64,
    pub runtime: u64,
    pub entry: u32,
    pub dispatch: u64,
    pub image_base: u64,
    /// Absolute address of the chain pool in the VM image.
    pub chains: u64,
}

pub fn assemble_trampoline(spec: &Trampoline) -> Result<Vec<u8>> {
    assemble_trampoline_mode(spec, false)
}

pub(crate) fn assemble_trampoline_mode(spec: &Trampoline, external: bool) -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(64).map_err(ice)?;
    let mut plain = a.create_label();
    let mut unwind = a.create_label();
    emit_trampoline_body(&mut a, spec, &plain, &unwind, external)?;
    emit_trampoline_fail(&mut a, &mut plain, &mut unwind)?;
    a.assemble(spec.origin).map_err(ice)
}

fn emit_trampoline_body(
    a: &mut CodeAssembler,
    spec: &Trampoline,
    plain: &CodeLabel,
    unwind: &CodeLabel,
    external: bool,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    chain::emit_claim_gs(a, plain)?;
    chain::emit_bind_chain(a, spec.chains)?;
    save_guest(a, spec.frame as i64)?;
    if chain::pe_tls_bound() {
        pe_unwind::emit_save_entry(a)?;
    }
    chain::emit_enter_nest(a, plain)?;
    emit_guest_frame(a, spec)?;
    // External entry binds in the dispatcher, where invalid metadata takes
    // the C8 failure path before the first BEGIN.
    if !external {
        chain::emit_bind_fn(a, unwind, false)?;
    }
    go(a.mov(r14d, spec.entry))?;
    handlers::reset_weave(a, None)?;
    if chain::pe_tls_bound() {
        crate::loader::emit_image_address(a, iced_x86::Register::RAX, spec.dispatch)?;
    } else {
        go(a.mov(rax, spec.dispatch as i64))?;
    }
    go(a.mov(rbx, r11))?;
    go(a.jmp(rax))?;
    Ok(())
}

fn emit_trampoline_fail(
    a: &mut CodeAssembler,
    plain: &mut CodeLabel,
    unwind: &mut CodeLabel,
) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    go(a.set_label(plain))?;
    go(a.mov(eax, 0xbad1u32))?;
    go(a.ret())?;
    go(a.set_label(unwind))?;
    if chain::pe_tls_bound() {
        go(a.mov(rbx, r11))?;
        chain::emit_leave_nest(a)?;
        return pe_unwind::emit_fail_return(a);
    }
    chain::emit_leave_nest(a)?;
    go(a.mov(eax, 0xbad1u32))?;
    go(a.ret())?;
    Ok(())
}

fn emit_guest_frame(a: &mut CodeAssembler, spec: &Trampoline) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    let mut zero = a.create_label();
    let mut zeroed = a.create_label();
    let mut scatter = a.create_label();
    let mut scattered = a.create_label();
    go(a.xor(eax, eax))?;
    go(a.xor(ecx, ecx))?;
    go(a.set_label(&mut zero))?;
    go(a.cmp(ecx, SLOT_COUNT as u32))?;
    go(a.jae(zeroed))?;
    go(a.mov(qword_ptr(r11 + rcx * 8), rax))?;
    go(a.inc(ecx))?;
    go(a.jmp(zero))?;
    go(a.set_label(&mut zeroed))?;
    if chain::pe_tls_bound() {
        crate::loader::emit_image_address(a, iced_x86::Register::R13, spec.runtime)?;
    } else {
        go(a.mov(r13, spec.runtime as i64))?;
    }
    go(a.xor(ecx, ecx))?;
    go(a.set_label(&mut scatter))?;
    go(a.cmp(ecx, 16u32))?;
    go(a.jae(scattered))?;
    go(a.movzx(eax, byte_ptr(r13 + rcx + RT_SLOTS)))?;
    go(a.mov(rdx, qword_ptr(r11 + rcx * 8 + FRAME_SPILL)))?;
    go(a.mov(qword_ptr(r11 + rax * 8), rdx))?;
    go(a.inc(ecx))?;
    go(a.jmp(scatter))?;
    go(a.set_label(&mut scattered))?;
    if chain::pe_tls_bound() {
        crate::loader::emit_image_address(a, iced_x86::Register::RAX, spec.image_base)?;
    } else {
        go(a.mov(rax, spec.image_base as i64))?;
    }
    go(a.mov(qword_ptr(r11 + FRAME_IMAGE), rax))?;
    Ok(())
}

/// Resume one thread at `dispatch` without restarting its chain.
///
/// `dispatch` is the instruction loop (`NativeVm::resume`), not the external entry.
pub struct Resume {
    pub origin: u64,
    pub frame: u64,
    pub runtime: u64,
    pub entry: u32,
    pub dispatch: u64,
}

pub fn assemble_resume(spec: &Resume) -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(64).map_err(ice)?;
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    save_guest(&mut a, spec.frame as i64)?;
    go(a.mov(r13, spec.runtime as i64))?;
    go(a.mov(r14d, spec.entry))?;
    go(a.mov(rbx, r11))?;
    go(a.mov(rax, spec.dispatch as i64))?;
    go(a.jmp(rax))?;
    a.assemble(spec.origin).map_err(ice)
}

fn save_guest(a: &mut CodeAssembler, frame: i64) -> Result<()> {
    let go = |step: std::result::Result<(), IcedError>| step.map_err(ice);
    // Flags are saved before the frame load, which tests `r11`.
    go(a.pushfq())?;
    go(a.push(r11))?;
    chain::emit_load_frame(a, frame as u64)?;
    go(a.mov(qword_ptr(r11 + FRAME_SPILL), rax))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 8)), rcx))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 16)), rdx))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 24)), rbx))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 40)), rbp))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 48)), rsi))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 56)), rdi))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 64)), r8))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 72)), r9))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 80)), r10))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 96)), r12))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 104)), r13))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 112)), r14))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 120)), r15))?;
    go(a.pop(rax))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 88)), rax))?;
    go(a.pop(rax))?;
    go(a.mov(qword_ptr(r11 + FRAME_FLAGS), rax))?;
    go(a.mov(qword_ptr(r11 + (FRAME_SPILL + 32)), rsp))?;
    Ok(())
}

pub fn trampoline_len() -> Result<usize> {
    trampoline_len_mode(false)
}

pub(crate) fn trampoline_len_mode(external: bool) -> Result<usize> {
    if chain::pe_tls_bound() {
        return pe_trampoline_len();
    }
    let first = assemble_trampoline_mode(
        &Trampoline {
            origin: 0x1000,
            frame: 0x2000,
            runtime: 0x3000,
            entry: 1,
            dispatch: 0x4000,
            image_base: 0x140000000,
            chains: 0x5000,
        },
        external,
    )?;
    let second = assemble_trampoline_mode(
        &Trampoline {
            origin: 0x180000,
            frame: 0x140002200,
            runtime: 0x140030000,
            entry: 0x400,
            dispatch: 0x140002000,
            image_base: 0x140000000,
            chains: 0x140040000,
        },
        external,
    )?;
    if first.len() != second.len() {
        return Err(msg("trampoline size depends on its address"));
    }
    Ok(first.len())
}

fn pe_trampoline_len() -> Result<usize> {
    let base = PE_VM_PROBE_BASE;
    let measure = |origin| {
        assemble_trampoline(&Trampoline {
            origin,
            frame: base + 0x2000,
            runtime: base + 0x3000,
            entry: 1,
            dispatch: base + 0x4000,
            image_base: base,
            chains: base + 0x5000,
        })
        .map(|code| code.len())
    };
    let first = measure(base + 0x1000)?;
    if first != measure(base + 0x180000)? {
        return Err(msg("native trampoline size depends on its address"));
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emu::{bare, Policy, Region};
    use crate::ir::{Block, Exit, FuncIr, Op};
    use crate::obf::obfuscate;
    use crate::vm::{lower_image, plain_insn, SlotMap, VARIANT_OPCODES};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn mix_ir() -> FuncIr {
        FuncIr {
            name: "mix".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![
                    Op::MovRr(0, 1),
                    Op::ImulRi(0, 7),
                    Op::AddRi(0, 3),
                    Op::XorRi(0, 0x5a),
                ],
                exit: Exit::Ret,
                opaque: false,
            }],
        }
    }

    fn write_arch(
        machine: &mut crate::emu::Machine,
        frame: u64,
        slots: &SlotMap,
        arch: usize,
        value: u64,
    ) {
        let slot = u64::from(slots.arch(arch));
        machine
            .write(frame + slot * 8, &value.to_le_bytes())
            .unwrap();
    }

    fn run_native(func: &FuncIr, arg: u64) -> u64 {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let image = lower_image(std::slice::from_ref(func), &mut rng).unwrap();
        let func_bc = &image.funcs[0];
        let origin = 0x400000u64;
        let vm = assemble_vm(origin).unwrap();
        let mut machine = bare(Policy::default()).unwrap();
        machine.regions.push(Region {
            base: origin,
            data: vm.bytes,
        });
        machine.regions.push(Region {
            base: 0x500000,
            data: vec![0; 0x20000],
        });
        let mut crc = 0u32;
        for index in 0..func_bc.insns.len() {
            let plain = plain_insn(func_bc, index, &image.inv).unwrap();
            if plain.first() == Some(&0x60) {
                crc = u32::from_le_bytes(plain[1..5].try_into().unwrap());
            }
        }
        place_runtime(
            func_bc,
            &image.inv,
            crc,
            &image.slots,
            image.handler_mix,
            &mut machine,
            0x500000,
            0x518000,
        )
        .unwrap();
        let frame = origin + vm.frame as u64;
        machine.regs[3] = frame;
        machine.regs[13] = 0x500000;
        machine.regs[14] = u64::from(func_bc.entry);
        let stack = machine.regs[4];
        write_arch(&mut machine, frame, &image.slots, 1, arg);
        write_arch(&mut machine, frame, &image.slots, 4, stack);
        machine.rip = origin + vm.dispatch as u64;
        machine.run().unwrap();
        machine.regs[0]
    }

    #[test]
    fn native_vm_runs_plain_and_obfuscated_mix() {
        let plain = mix_ir();
        assert_eq!(
            run_native(&plain, 10),
            (10u64.wrapping_mul(7).wrapping_add(3)) ^ 0x5a
        );
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let obf = obfuscate(&plain, &mut rng).func;
        assert_eq!(
            run_native(&obf, 10),
            (10u64.wrapping_mul(7).wrapping_add(3)) ^ 0x5a
        );
    }

    fn prepare_lifted_sample() -> (crate::pe::PeImage, crate::vm::BcImage) {
        use crate::lift::lift;
        use crate::pe::{parse, IMAGE_BASE};
        use crate::sample::build;

        let built = build().unwrap();
        let parsed = parse(&built.bytes).unwrap();
        let text = &parsed.sections[0];
        let mut funcs = Vec::new();
        for symbol in &built.symbols {
            let off = (symbol.rva - text.rva) as usize;
            let mut func = lift(
                &symbol.name,
                &text.bytes[off..],
                symbol.rva,
                symbol.size,
                IMAGE_BASE,
            )
            .unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(symbol.rva as u64);
            func = obfuscate(&func, &mut rng).func;
            funcs.push(func);
        }
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        (parsed, lower_image(&funcs, &mut rng).unwrap())
    }

    fn mount_sample(
        parsed: &crate::pe::PeImage,
        lowered: &crate::vm::BcImage,
        origin: u64,
        vm: &NativeVm,
    ) -> crate::emu::Machine {
        use crate::pe::IMAGE_BASE;
        let mut machine = bare(Policy {
            // Each instruction seals, opens the level-2 program, and reopens.
            // With the native ChaCha helper the sample finishes in about 135e6 steps.
            max_steps: 180_000_000,
            ..Policy::default()
        })
        .unwrap();
        let span = parsed
            .sections
            .iter()
            .map(|sec| sec.rva as usize + sec.bytes.len())
            .max()
            .unwrap();
        let mut image = vec![0u8; span];
        for section in &parsed.sections {
            image[section.rva as usize..section.rva as usize + section.bytes.len()]
                .copy_from_slice(&section.bytes);
        }
        machine.regions.push(Region {
            base: IMAGE_BASE,
            data: image,
        });
        machine.regions.push(Region {
            base: origin,
            data: vm.bytes.clone(),
        });
        let windows = lowered.funcs.len() as u64 * crate::vm::RUNTIME_WINDOW;
        let key_bytes: usize = lowered.funcs.iter().map(|func| func.insns.len() * 32).sum();
        machine.regions.push(Region {
            base: 0x500000,
            data: vec![0; windows as usize + 0x1000 + key_bytes],
        });
        machine
    }

    fn place_sample_table(
        machine: &mut crate::emu::Machine,
        lowered: &crate::vm::BcImage,
        origin: u64,
        vm: &NativeVm,
    ) {
        let windows = lowered.funcs.len() as u64 * crate::vm::RUNTIME_WINDOW;
        let table_at = 0x500000 + windows;
        let mut table = Vec::new();
        table.extend((lowered.funcs.len() as u32).to_le_bytes());
        let mut keys_at = table_at + 0x1000;
        for (index, func) in lowered.funcs.iter().enumerate() {
            let runtime = 0x500000 + index as u64 * crate::vm::RUNTIME_WINDOW;
            place_runtime(
                func,
                &lowered.inv,
                check_crc(lowered, func),
                &lowered.slots,
                lowered.handler_mix,
                machine,
                runtime,
                keys_at,
            )
            .unwrap();
            keys_at += func.insns.len() as u64 * 32;
            table.extend(func.rva.to_le_bytes());
            table.extend(func.entry.to_le_bytes());
            table.extend(runtime.to_le_bytes());
        }
        machine.write(table_at, &table).unwrap();
        machine
            .write(origin + vm.calls as u64, &table_at.to_le_bytes())
            .unwrap();
    }

    fn hook_sample_imports(machine: &mut crate::emu::Machine, parsed: &crate::pe::PeImage) {
        use crate::pe::IMAGE_BASE;
        for (index, import) in parsed.imports.iter().enumerate() {
            let hook = 0x1800_01000 + index as u64 * 0x10;
            let api = match import.name.as_str() {
                "GetStdHandle" => crate::emu::Api::GetStdHandle,
                "WriteFile" => crate::emu::Api::WriteFile,
                "ExitProcess" => crate::emu::Api::ExitProcess,
                "IsDebuggerPresent" => crate::emu::Api::IsDebuggerPresent,
                "CheckRemoteDebuggerPresent" => crate::emu::Api::CheckRemoteDebuggerPresent,
                "GetTickCount64" => crate::emu::Api::GetTickCount64,
                _ => panic!("{}", import.name),
            };
            machine.hooks.insert(hook, api);
            machine
                .write(IMAGE_BASE + u64::from(import.iat_rva), &hook.to_le_bytes())
                .unwrap();
        }
    }

    fn launch_sample(
        machine: &mut crate::emu::Machine,
        lowered: &crate::vm::BcImage,
        origin: u64,
        vm: &NativeVm,
    ) {
        use crate::pe::IMAGE_BASE;
        let start = lowered
            .funcs
            .iter()
            .find(|func| func.name == "start")
            .unwrap();
        let frame = origin + vm.frame as u64;
        let stack = machine.regs[4];
        write_arch(machine, frame, &lowered.slots, 4, stack);
        machine
            .write(frame + FRAME_IMAGE as u64, &IMAGE_BASE.to_le_bytes())
            .unwrap();
        machine.regs[3] = frame;
        machine.regs[13] = 0x500000
            + lowered
                .funcs
                .iter()
                .position(|func| func.name == "start")
                .unwrap() as u64
                * crate::vm::RUNTIME_WINDOW;
        machine.regs[14] = u64::from(start.entry);
        machine.rip = origin + vm.dispatch as u64;
        machine.run().unwrap();
    }

    #[test]
    fn native_vm_runs_the_lifted_sample() {
        use crate::sample;
        let (parsed, lowered) = prepare_lifted_sample();
        let origin = 0x400000u64;
        let vm = assemble_vm(origin).unwrap();
        let mut machine = mount_sample(&parsed, &lowered, origin, &vm);
        place_sample_table(&mut machine, &lowered, origin, &vm);
        hook_sample_imports(&mut machine, &parsed);
        launch_sample(&mut machine, &lowered, origin, &vm);
        assert_eq!(machine.stdout, sample::line().into_bytes());
    }

    #[test]
    fn runtime_holds_the_sealed_inner_dispatcher() {
        use crate::vm::{seal_dispatcher, INNER_CIPHER, INNER_READY};
        let (_, lowered) = prepare_lifted_sample();
        let func = &lowered.funcs[0];
        let mut machine = bare(Policy::default()).unwrap();
        machine.regions.push(Region {
            base: 0x500000,
            data: vec![0; crate::vm::RUNTIME_WINDOW as usize],
        });
        place_runtime(
            func,
            &lowered.inv,
            0,
            &lowered.slots,
            lowered.handler_mix,
            &mut machine,
            0x500000,
            0x510000,
        )
        .unwrap();
        let sealed = seal_dispatcher(func.key_seed, &func.salt).unwrap();
        let got = machine
            .read(0x500000 + INNER_CIPHER as u64, sealed.bytes.len())
            .unwrap();
        assert_eq!(got, sealed.bytes);
        let plain = crate::vm::open_dispatcher(func.key_seed, &func.salt).unwrap();
        assert_ne!(got, plain);
        let ready = machine.read(0x500000 + INNER_READY as u64, 1).unwrap();
        assert_eq!(ready, [0]);
    }

    #[test]
    fn cleared_inner_stream_stops_the_sample() {
        use crate::pe::IMAGE_BASE;
        let (parsed, lowered) = prepare_lifted_sample();
        let origin = 0x400000u64;
        let vm = assemble_vm(origin).unwrap();
        let mut machine = mount_sample(&parsed, &lowered, origin, &vm);
        place_sample_table(&mut machine, &lowered, origin, &vm);
        let start = lowered
            .funcs
            .iter()
            .position(|func| func.name == "start")
            .unwrap();
        let runtime = 0x500000 + start as u64 * crate::vm::RUNTIME_WINDOW;
        machine
            .write(runtime + crate::vm::INNER_LEN as u64, &0u32.to_le_bytes())
            .unwrap();
        hook_sample_imports(&mut machine, &parsed);
        let frame = origin + vm.frame as u64;
        let stack = machine.regs[4];
        write_arch(&mut machine, frame, &lowered.slots, 4, stack);
        machine
            .write(frame + FRAME_IMAGE as u64, &IMAGE_BASE.to_le_bytes())
            .unwrap();
        machine.regs[3] = frame;
        machine.regs[13] = runtime;
        machine.regs[14] = u64::from(lowered.funcs[start].entry);
        machine.rip = origin + vm.dispatch as u64;
        machine.run().unwrap();
        assert_eq!(machine.regs[0], 0xbad1);
        assert!(machine.stdout.is_empty());
    }

    #[test]
    fn resolver_finds_write_file() {
        use crate::emu::{bare, djb2, install_kernel32, Policy, Region, K32_BASE};
        let origin = 0x300000u64;
        let code = assemble_resolve(origin).unwrap();
        let mut machine = bare(Policy::default()).unwrap();
        install_kernel32(&mut machine).unwrap();
        machine.regions.push(Region {
            base: origin,
            data: code.clone(),
        });
        machine.regs[1] = K32_BASE;
        machine.regs[2] = u64::from(djb2(b"WriteFile"));
        machine.rip = origin;
        machine.run().unwrap();
        assert_eq!(machine.regs[0], K32_BASE + 0x1000 + 0x10);
    }

    #[test]
    fn handlers_cover_lifter_opcodes_and_every_condition() {
        assemble_vm(0x400000).unwrap();
        for tag in [0x24u8, 0x25, 0x29, 0x2a, 0x2b, 0x2c] {
            assert!(BYTECODE_OPCODES.contains(&tag));
        }
        for cond in 0..16u8 {
            assert!(super::handlers::JCC_CONDITIONS.contains(&cond));
            let flags = crate::flags::Flags {
                cf: cond % 2 == 0,
                pf: cond % 3 == 0,
                zf: cond % 4 == 0,
                sf: cond % 5 == 0,
                of: cond % 6 == 0,
            };
            let _ = crate::flags::cond_taken(cond, flags);
        }
        let cases = [
            FuncIr {
                name: "shr".into(),
                rva: 0x1000,
                entry: 0,
                blocks: vec![Block {
                    ops: vec![Op::MovRi(0, 0x8000_0000_0000_0000), Op::Shr(0, 1)],
                    exit: Exit::Ret,
                    opaque: false,
                }],
            },
            FuncIr {
                name: "neg".into(),
                rva: 0x1000,
                entry: 0,
                blocks: vec![Block {
                    ops: vec![Op::MovRi(0, 5), Op::Neg(0)],
                    exit: Exit::Ret,
                    opaque: false,
                }],
            },
            FuncIr {
                name: "not".into(),
                rva: 0x1000,
                entry: 0,
                blocks: vec![Block {
                    ops: vec![Op::MovRi(0, 0), Op::Not(0)],
                    exit: Exit::Ret,
                    opaque: false,
                }],
            },
            FuncIr {
                name: "lea".into(),
                rva: 0x1000,
                entry: 0,
                blocks: vec![Block {
                    ops: vec![
                        Op::MovRi(1, 10),
                        Op::MovRi(2, 3),
                        Op::Lea(
                            0,
                            crate::ir::Address::Sib {
                                base: Some(1),
                                index: Some(2),
                                scale: 4,
                                disp: 8,
                            },
                        ),
                    ],
                    exit: Exit::Ret,
                    opaque: false,
                }],
            },
        ];
        for func in cases {
            assert_eq!(ir_rax(&func), run_native(&func, 0), "{}", func.name);
        }
        for cond in super::handlers::JCC_CONDITIONS {
            for (left, right) in [(1u64, 2u64), (5, 5), (0, 1)] {
                let func = FuncIr {
                    name: format!("jcc-{cond}"),
                    rva: 0x1000,
                    entry: 0,
                    blocks: vec![
                        Block {
                            ops: vec![Op::MovRi(0, left), Op::CmpRi(0, right as i32)],
                            exit: Exit::Jcc(cond, 1, 2),
                            opaque: false,
                        },
                        Block {
                            ops: vec![Op::MovRi(0, 7)],
                            exit: Exit::Ret,
                            opaque: false,
                        },
                        Block {
                            ops: vec![Op::MovRi(0, 9)],
                            exit: Exit::Ret,
                            opaque: false,
                        },
                    ],
                };
                assert_eq!(
                    ir_rax(&func),
                    run_native(&func, 0),
                    "cond {cond} {left} {right}"
                );
            }
        }
    }

    fn ir_rax(func: &FuncIr) -> u64 {
        use crate::flags::Flags;
        use crate::ir::{exec_func, MapMem};
        let mut arch = [0u64; 16];
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut absent =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        exec_func(
            std::slice::from_ref(func),
            0,
            &mut arch,
            &mut flags,
            &mut mem,
            0x140000000,
            &mut absent,
        )
        .unwrap();
        arch[0]
    }

    fn ir_with(func: &FuncIr, arg: u64) -> u64 {
        use crate::flags::Flags;
        use crate::ir::{exec_func, MapMem};
        let mut arch = [0u64; 16];
        arch[1] = arg;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut absent =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        exec_func(
            std::slice::from_ref(func),
            0,
            &mut arch,
            &mut flags,
            &mut mem,
            0,
            &mut absent,
        )
        .unwrap();
        arch[0]
    }

    fn vm_with(func: &FuncIr, arg: u64) -> u64 {
        use crate::flags::Flags;
        use crate::ir::MapMem;
        use crate::vm::exec_image;
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let image = lower_image(std::slice::from_ref(func), &mut rng).unwrap();
        let mut arch = [0u64; 16];
        arch[1] = arg;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut absent =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        exec_image(&image, 0, &mut arch, &mut flags, &mut mem, 0, &mut absent).unwrap();
        arch[0]
    }

    #[test]
    fn both_interpreters_match_ir() {
        let plain = mix_ir();
        let ir = ir_with(&plain, 10);
        assert_eq!(vm_with(&plain, 10), ir);
        assert_eq!(run_native(&plain, 10), ir);
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let obf = obfuscate(&plain, &mut rng).func;
        let ir = ir_with(&obf, 10);
        assert_eq!(vm_with(&obf, 10), ir);
        assert_eq!(run_native(&obf, 10), ir);

        let arch = call_arch();
        for seed in [3u64, 11] {
            let (ir, vm, native) = run_three(&private_slot_funcs(), seed, arch, &mut no_host);
            assert_eq!(ir[0], 1, "caller temp seed {seed}");
            assert_eq!(ir[1], 0x99, "callee rcx seed {seed}");
            assert_eq!(ir[2], 2, "mid temp seed {seed}");
            assert_eq!(vm, ir, "vm seed {seed}");
            assert_eq!(native, ir, "native seed {seed}");
        }
        let mut obf_funcs = Vec::new();
        for func in private_slot_funcs() {
            let mut rng = ChaCha20Rng::seed_from_u64(9);
            obf_funcs.push(obfuscate(&func, &mut rng).func);
        }
        let (ir, vm, native) = run_three(&obf_funcs, 4, arch, &mut no_host);
        assert_eq!(vm, ir);
        assert_eq!(native, ir);
    }

    fn call_arch() -> [u64; 16] {
        let mut arch = [0u64; 16];
        arch[4] = bare_rsp();
        arch
    }

    fn bare_rsp() -> u64 {
        bare(Policy::default()).unwrap().regs[4]
    }

    fn private_slot_funcs() -> Vec<FuncIr> {
        use crate::ir::{RAX, RCX, RDX, V_TMP0};
        vec![
            FuncIr {
                name: "caller".into(),
                rva: 0x1000,
                entry: 0,
                blocks: vec![
                    Block {
                        ops: vec![Op::MovRi(V_TMP0, 1), Op::MovRi(RCX, 0x42)],
                        exit: Exit::CallRva {
                            rva: 0x2000,
                            next: 1,
                        },
                        opaque: false,
                    },
                    Block {
                        ops: vec![Op::MovRr(RAX, V_TMP0)],
                        exit: Exit::Ret,
                        opaque: false,
                    },
                ],
            },
            FuncIr {
                name: "mid".into(),
                rva: 0x2000,
                entry: 0,
                blocks: vec![
                    Block {
                        ops: vec![Op::MovRi(V_TMP0, 2)],
                        exit: Exit::CallRva {
                            rva: 0x3000,
                            next: 1,
                        },
                        opaque: false,
                    },
                    Block {
                        ops: vec![Op::MovRr(RDX, V_TMP0)],
                        exit: Exit::Ret,
                        opaque: false,
                    },
                ],
            },
            FuncIr {
                name: "leaf".into(),
                rva: 0x3000,
                entry: 0,
                blocks: vec![Block {
                    ops: vec![Op::MovRi(V_TMP0, 3), Op::MovRi(RCX, 0x99)],
                    exit: Exit::Ret,
                    opaque: false,
                }],
            },
        ]
    }

    fn no_host(
        _arch: &mut [u64; 16],
        _flags: &mut crate::flags::Flags,
        _mem: &mut dyn crate::ir::MemIo,
        target: u64,
    ) -> crate::error::Result<()> {
        panic!("unexpected absolute call to {target:#x}")
    }

    fn run_ir(
        funcs: &[FuncIr],
        mut arch: [u64; 16],
        abs_call: &mut crate::ir::HostCall<'_>,
    ) -> [u64; 16] {
        use crate::flags::Flags;
        use crate::ir::{exec_func, MapMem};
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        exec_func(funcs, 0, &mut arch, &mut flags, &mut mem, 0, abs_call).unwrap();
        arch
    }

    fn run_vm(
        image: &crate::vm::BcImage,
        mut arch: [u64; 16],
        abs_call: &mut crate::ir::HostCall<'_>,
    ) -> [u64; 16] {
        use crate::flags::Flags;
        use crate::ir::MapMem;
        use crate::vm::exec_image;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        exec_image(image, 0, &mut arch, &mut flags, &mut mem, 0, abs_call).unwrap();
        arch
    }

    fn check_crc(image: &crate::vm::BcImage, func: &crate::vm::BcFunc) -> u32 {
        let mut crc = 0u32;
        for index in 0..func.insns.len() {
            let plain = plain_insn(func, index, &image.inv).unwrap();
            if plain.first() == Some(&0x60) {
                crc = u32::from_le_bytes(plain[1..5].try_into().unwrap());
            }
        }
        crc
    }

    fn install_native_table(
        machine: &mut crate::emu::Machine,
        image: &crate::vm::BcImage,
        base: u64,
        table_at: u64,
        stride: u64,
    ) {
        let mut table = Vec::new();
        table.extend((image.funcs.len() as u32).to_le_bytes());
        let mut keys_at = table_at + 0x1000;
        for (index, func) in image.funcs.iter().enumerate() {
            let runtime = base + index as u64 * stride;
            place_runtime(
                func,
                &image.inv,
                check_crc(image, func),
                &image.slots,
                image.handler_mix,
                machine,
                runtime,
                keys_at,
            )
            .unwrap();
            keys_at += func.insns.len() as u64 * 32;
            table.extend(func.rva.to_le_bytes());
            table.extend(func.entry.to_le_bytes());
            table.extend(runtime.to_le_bytes());
        }
        machine.write(table_at, &table).unwrap();
    }

    fn native_machine(
        image: &crate::vm::BcImage,
        origin: u64,
        vm: &NativeVm,
        host: Option<(u64, Vec<u8>)>,
        base: u64,
    ) -> crate::emu::Machine {
        let stride = crate::vm::RUNTIME_WINDOW;
        let table_at = base + stride * image.funcs.len() as u64;
        let key_bytes: usize = image.funcs.iter().map(|func| func.insns.len() * 32).sum();
        let mut machine = bare(Policy::default()).unwrap();
        machine.regions.push(Region {
            base: origin,
            data: vm.bytes.clone(),
        });
        machine.regions.push(Region {
            base,
            data: vec![0; (table_at - base) as usize + 0x1000 + key_bytes],
        });
        if let Some((at, bytes)) = host {
            machine.regions.push(Region {
                base: at,
                data: bytes,
            });
        }
        install_native_table(&mut machine, image, base, table_at, stride);
        machine
            .write(origin + vm.calls as u64, &table_at.to_le_bytes())
            .unwrap();
        machine
    }

    fn launch_native(
        machine: &mut crate::emu::Machine,
        image: &crate::vm::BcImage,
        origin: u64,
        vm: &NativeVm,
        arch: [u64; 16],
        base: u64,
    ) {
        let frame = origin + vm.frame as u64;
        for (reg, value) in arch.iter().enumerate() {
            write_arch(machine, frame, &image.slots, reg, *value);
        }
        machine.regs[3] = frame;
        machine.regs[4] = arch[4];
        machine.regs[13] = base;
        machine.regs[14] = u64::from(image.funcs[0].entry);
        machine.rip = origin + vm.dispatch as u64;
        machine.run().unwrap();
    }

    fn run_native_image(
        image: &crate::vm::BcImage,
        arch: [u64; 16],
        host: Option<(u64, Vec<u8>)>,
    ) -> [u64; 16] {
        let origin = 0x400000u64;
        let base = 0x500000u64;
        let vm = assemble_vm(origin).unwrap();
        let mut machine = native_machine(image, origin, &vm, host, base);
        launch_native(&mut machine, image, origin, &vm, arch, base);
        let mut out = machine.regs;
        out[4] = out[4].wrapping_sub(8);
        out
    }

    fn run_three(
        funcs: &[FuncIr],
        seed: u64,
        arch: [u64; 16],
        abs_call: &mut crate::ir::HostCall<'_>,
    ) -> ([u64; 16], [u64; 16], [u64; 16]) {
        let ir = run_ir(funcs, arch, abs_call);
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let image = lower_image(funcs, &mut rng).unwrap();
        let vm = run_vm(&image, arch, abs_call);
        let native = run_native_image(&image, arch, None);
        (ir, vm, native)
    }

    fn crossed_private_slots() -> SlotMap {
        let mut slots = SlotMap::identity();
        slots.forward.swap(2, 18);
        std::mem::swap(&mut slots.forward[5], &mut slots.shadows[0]);
        let mut all = slots.forward.to_vec();
        all.extend(slots.shadows);
        let mut unique = all.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), all.len());
        assert!(
            slots.forward[18] < 16,
            "temp must sit in a low physical slot"
        );
        assert!(
            slots.shadows[0] < 16,
            "shadow must sit in a low physical slot"
        );
        assert!(slots.forward[2] >= 16 && slots.forward[5] >= 16);
        slots
    }

    fn identity_codec() -> ([u8; 256], [u8; 256]) {
        let mut perm = [0u8; 256];
        let mut inv = [0u8; 256];
        for (index, byte) in perm.iter_mut().enumerate() {
            *byte = index as u8;
            inv[index] = index as u8;
        }
        (perm, inv)
    }

    fn mov_imm(slot: u8, imm: u64) -> Vec<u8> {
        let mut bytes = vec![0x03, slot];
        bytes.extend(imm.to_le_bytes());
        bytes
    }

    fn caller_plains(slots: &SlotMap) -> Vec<Vec<u8>> {
        let tmp = slots.forward[18];
        let shadow = slots.shadows[0];
        vec![
            mov_imm(tmp, 0x1111),
            mov_imm(shadow, 0x3333),
            mov_imm(slots.forward[2], 0x55),
            mov_imm(slots.forward[5], 0x66),
            vec![0x50, 0x00, 0x20, 0x00, 0x00],
            vec![0x02, slots.forward[0], tmp],
            vec![0x02, slots.forward[1], shadow],
            vec![0x52],
        ]
    }

    fn callee_plains(slots: &SlotMap) -> Vec<Vec<u8>> {
        let tmp = slots.forward[18];
        let shadow = slots.shadows[0];
        vec![
            mov_imm(tmp, 0x2222),
            mov_imm(shadow, 0x4444),
            mov_imm(slots.forward[2], 0x99),
            mov_imm(slots.forward[5], 0x77),
            vec![0x52],
        ]
    }

    fn hold_chain(
        rva: u32,
        salt: &[u8; 8],
        plains: &[Vec<u8>],
    ) -> (
        Vec<crate::vm::EncodedInsn>,
        crate::secret::KeyPage,
        [u8; 32],
    ) {
        let (insns, mut key, terminal) = crate::vm::seal_chain(1, rva, salt, plains).unwrap();
        let page = crate::secret::KeyPage::hold(&key).unwrap();
        crate::secret::wipe(&mut key);
        (insns, page, terminal)
    }

    fn private_call_image(slots: &SlotMap) -> crate::vm::BcImage {
        use crate::vm::BcImage;
        let (perm, inv) = identity_codec();
        let salt = [0x42u8; 8];
        let callee_salt = [0x43u8; 8];
        let (caller, caller_key, caller_terminal) =
            hold_chain(0x1000, &salt, &caller_plains(slots));
        let (callee, callee_key, callee_terminal) =
            hold_chain(0x2000, &callee_salt, &callee_plains(slots));
        BcImage {
            perm,
            inv,
            slots: slots.clone(),
            handler_mix: 0,
            funcs: vec![
                sealed_func("caller", 0x1000, salt, caller_key, caller_terminal, caller),
                sealed_func(
                    "callee",
                    0x2000,
                    callee_salt,
                    callee_key,
                    callee_terminal,
                    callee,
                ),
            ],
        }
    }

    fn sealed_func(
        name: &str,
        rva: u32,
        salt: [u8; 8],
        key: crate::secret::KeyPage,
        terminal: [u8; 32],
        insns: Vec<crate::vm::EncodedInsn>,
    ) -> crate::vm::BcFunc {
        crate::vm::bare_func(name, rva, 0, insns, salt, 1, key, terminal)
    }

    #[test]
    fn call_rva_private_slots_follow_the_arch_map() {
        let slots = crossed_private_slots();
        let image = private_call_image(&slots);
        let arch = call_arch();
        let vm = run_vm(&image, arch, &mut no_host);
        let native = run_native_image(&image, arch, None);
        assert_eq!(vm[0], 0x1111, "caller temp");
        assert_eq!(vm[1], 0x3333, "caller shadow");
        assert_eq!(vm[2], 0x99, "callee rdx");
        assert_eq!(vm[5], 0x77, "callee rbp");
        assert_eq!(native, vm);
    }

    #[test]
    fn push_rsp_and_pop_rsp_match_both_interpreters() {
        use crate::ir::{RAX, RSP};
        let arch = call_arch();
        let stack = arch[4];
        let push = FuncIr {
            name: "push-rsp".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![Op::Push(RSP), Op::Pop(RAX)],
                exit: Exit::Ret,
                opaque: false,
            }],
        };
        let (ir, vm, native) = run_three(std::slice::from_ref(&push), 3, arch, &mut no_host);
        assert_eq!(ir[0], stack.wrapping_sub(8));
        assert_eq!(vm, ir);
        assert_eq!(native, ir);
        let pop = FuncIr {
            name: "pop-rsp".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![
                    Op::MovRi(RAX, 0x1111),
                    Op::Push(RAX),
                    Op::Pop(RSP),
                    Op::MovRr(RAX, RSP),
                ],
                exit: Exit::Ret,
                opaque: false,
            }],
        };
        let (ir, vm, native) = run_three(std::slice::from_ref(&pop), 5, arch, &mut no_host);
        assert_eq!(ir[0], stack);
        assert_eq!(vm, ir);
        assert_eq!(native, ir);
    }

    #[test]
    fn call_rva_leaves_rsp_unchanged_for_the_callee() {
        use crate::ir::{RAX, RSP};
        let arch = call_arch();
        let funcs = vec![
            FuncIr {
                name: "caller".into(),
                rva: 0x1000,
                entry: 0,
                blocks: vec![
                    Block {
                        ops: vec![],
                        exit: Exit::CallRva {
                            rva: 0x2000,
                            next: 1,
                        },
                        opaque: false,
                    },
                    Block {
                        ops: vec![],
                        exit: Exit::Ret,
                        opaque: false,
                    },
                ],
            },
            FuncIr {
                name: "callee".into(),
                rva: 0x2000,
                entry: 0,
                blocks: vec![Block {
                    ops: vec![Op::MovRr(RAX, RSP)],
                    exit: Exit::Ret,
                    opaque: false,
                }],
            },
        ];
        let (ir, vm, native) = run_three(&funcs, 3, arch, &mut no_host);
        assert_eq!(ir[0], arch[4]);
        assert_eq!(ir[4], arch[4]);
        assert_eq!(vm, ir);
        assert_eq!(native, ir);
    }

    #[test]
    fn call_reg_returns_every_architectural_register() {
        use crate::ir::RCX;
        const HOST: u64 = 0x1800_02000;
        let mut arch = call_arch();
        let mut ops = Vec::new();
        for reg in 0..16u16 {
            if reg != 4 {
                ops.push(Op::MovRi(reg, 0x100 + u64::from(reg)));
            }
        }
        ops.push(Op::MovRi(RCX, HOST));
        let func = FuncIr {
            name: "caller".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![
                Block {
                    ops,
                    exit: Exit::CallAbs { reg: RCX, next: 1 },
                    opaque: false,
                },
                Block {
                    ops: vec![],
                    exit: Exit::Ret,
                    opaque: false,
                },
            ],
        };
        let mut bump = |regs: &mut [u64; 16],
                        _: &mut crate::flags::Flags,
                        _: &mut dyn crate::ir::MemIo,
                        target: u64| {
            assert_eq!(target, HOST);
            for (index, reg) in regs.iter_mut().enumerate() {
                if index != 4 {
                    *reg = reg.wrapping_add(1);
                }
            }
            Ok(())
        };
        let ir = run_ir(std::slice::from_ref(&func), arch, &mut bump);
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let image = lower_image(std::slice::from_ref(&func), &mut rng).unwrap();
        let mut bump_vm = |regs: &mut [u64; 16],
                           _: &mut crate::flags::Flags,
                           _: &mut dyn crate::ir::MemIo,
                           target: u64| {
            assert_eq!(target, HOST);
            for (index, reg) in regs.iter_mut().enumerate() {
                if index != 4 {
                    *reg = reg.wrapping_add(1);
                }
            }
            Ok(())
        };
        let vm = run_vm(&image, arch, &mut bump_vm);
        let host = host_increments(HOST);
        let native = run_native_image(&image, arch, Some((HOST, host)));
        for index in 0..16 {
            let expect = if index == 4 {
                arch[4]
            } else if index == 1 {
                HOST.wrapping_add(1)
            } else {
                0x100 + index as u64 + 1
            };
            arch[index] = expect;
        }
        assert_eq!(ir, arch);
        assert_eq!(vm, arch);
        assert_eq!(native, arch);
    }

    fn host_increments(origin: u64) -> Vec<u8> {
        use iced_x86::code_asm::{
            r10, r11, r12, r13, r14, r15, r8, r9, rax, rbp, rbx, rcx, rdi, rdx, rsi, CodeAssembler,
        };
        let mut asm = CodeAssembler::new(64).unwrap();
        for reg in [
            rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
        ] {
            asm.inc(reg).unwrap();
        }
        asm.ret().unwrap();
        asm.assemble(origin).unwrap()
    }

    #[test]
    fn call_depth_stops_at_the_same_limit_as_exec_image() {
        use crate::flags::Flags;
        use crate::ir::{exec_func, MapMem, RAX, RCX};
        use crate::vm::exec_image;
        let func = FuncIr {
            name: "nest".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![
                Block {
                    ops: vec![Op::CmpRi(RCX, 0)],
                    exit: Exit::Jcc(4, 1, 2),
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRi(RAX, 7)],
                    exit: Exit::Ret,
                    opaque: false,
                },
                Block {
                    ops: vec![Op::SubRi(RCX, 1)],
                    exit: Exit::CallRva {
                        rva: 0x1000,
                        next: 1,
                    },
                    opaque: false,
                },
            ],
        };
        let mut within = call_arch();
        within[1] = 32;
        let (ir, vm, native) = run_three(std::slice::from_ref(&func), 3, within, &mut no_host);
        assert_eq!(ir[0], 7);
        assert_eq!(vm, ir);
        assert_eq!(native, ir);

        let mut past = call_arch();
        past[1] = 33;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut absent = no_host;
        let ir_err = exec_func(
            std::slice::from_ref(&func),
            0,
            &mut past,
            &mut flags,
            &mut mem,
            0,
            &mut absent,
        )
        .unwrap_err()
        .to_string();
        assert!(ir_err.contains("call depth"), "{ir_err}");
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let image = lower_image(std::slice::from_ref(&func), &mut rng).unwrap();
        let mut past = call_arch();
        past[1] = 33;
        let vm_err = exec_image(&image, 0, &mut past, &mut flags, &mut mem, 0, &mut absent)
            .unwrap_err()
            .to_string();
        assert!(vm_err.contains("call depth"), "{vm_err}");
        let mut failed = call_arch();
        failed[1] = 33;
        let native = run_native_image(&image, failed, None);
        assert_eq!(native[0], 0xbad1);
    }

    #[test]
    fn process_gate_is_aligned_after_placement() {
        let pe = pe_places();
        let elf = elf_places();
        for seed in 0..64u64 {
            check_direct(seed);
            check_places(seed, &pe);
            check_places(seed, &elf);
        }
    }

    #[test]
    fn protected_gate_matches_the_image_address() {
        let pe = crate::sample::build().unwrap();
        let elf = crate::elf::sample::build().unwrap();
        for seed in [0u64, 2, 11, 12, 15, 26, 28, 36, 50, 55, 60, 63] {
            check_pe_file(&pe.bytes, seed);
            check_elf_file(&elf, seed);
        }
    }

    fn check_direct(seed: u64) {
        for origin in [0x1000u64, 0x400000, 0x1400_02000, 0x404000, 0x180008] {
            let vm = assemble_vm_seeded(origin, seed).unwrap();
            assert_gate(&vm.bytes, vm.frame, origin, &vm.bytes, origin, seed);
        }
    }

    fn check_places(seed: u64, places: &[Place]) {
        for place in places {
            let origin = place.section_va + place.prefix as u64;
            assert!(
                origin.is_multiple_of(8),
                "seed {seed} {:#x}",
                place.section_va
            );
            let vm = assemble_vm_seeded(origin, seed).unwrap();
            let mut image = vec![0u8; place.prefix + vm.bytes.len()];
            image[place.prefix..].copy_from_slice(&vm.bytes);
            assert_gate(&vm.bytes, vm.frame, origin, &image, place.section_va, seed);
        }
    }

    fn check_pe_file(plain: &[u8], seed: u64) {
        let protected = crate::protect::protect(plain, &protect_opts(seed)).unwrap();
        let image = crate::pe::parse(&protected.bytes).unwrap();
        let section = image
            .sections
            .iter()
            .find(|item| item.name == crate::protect::section_name(seed))
            .unwrap();
        let state = image
            .sections
            .iter()
            .find(|item| item.rva == section.rva + section.bytes.len() as u32)
            .expect("adjacent VM state");
        let state_va = image.image_base + u64::from(state.rva);
        let frame = assemble_vm_seeded(0x1000, seed).unwrap().frame;
        let origin = state_va - frame as u64;
        let vm = assemble_vm_seeded(origin, seed).unwrap();
        let (code, data) = vm.bytes.split_at(frame);
        let placed_code = &section.bytes[section.bytes.len() - frame..];
        assert_eq!(placed_code, code, "pe code seed {seed}");
        assert_eq!(&state.bytes[..data.len()], data, "pe state seed {seed}");
        assert_gate(&vm.bytes, frame, origin, &state.bytes, state_va, seed);
    }

    fn check_elf_file(plain: &[u8], seed: u64) {
        let protected = crate::protect::protect(plain, &protect_opts(seed)).unwrap();
        let parsed = crate::elf::parse(&protected.bytes).unwrap();
        let segment = parsed
            .segments
            .iter()
            .filter(|item| item.kind == crate::elf::SegmentKind::Load)
            .max_by_key(|item| item.vaddr)
            .unwrap();
        let loader = crate::loader::assemble_sysv(&elf_size_plan())
            .unwrap()
            .len();
        let head = crate::crypto::HEADER_LEN + loader;
        let raw = segment.vaddr + head as u64;
        let origin = raw + align_pad(raw) as u64;
        let vm = assemble_vm_seeded(origin, seed).unwrap();
        let at = segment.offset as usize + (origin - segment.vaddr) as usize;
        let placed = &protected.bytes[at..at + vm.bytes.len()];
        assert_eq!(placed, vm.bytes.as_slice(), "elf seed {seed}");
        let body = &protected.bytes[segment.offset as usize..];
        assert_gate(placed, vm.frame, origin, body, segment.vaddr, seed);
    }

    fn protect_opts(seed: u64) -> crate::protect::Options {
        crate::protect::Options {
            virtualize: Default::default(),
            mutate: Default::default(),
            virtualize_all: true,
            mutate_all: false,
            seed,
            random_key: false,
            debug_seed: false,
        }
    }

    struct Place {
        section_va: u64,
        prefix: usize,
    }

    fn pe_places() -> Vec<Place> {
        let loader = crate::loader::assemble(&pe_size_plan()).unwrap().len();
        let resolve = assemble_resolve(0x1000).unwrap().len();
        let head = crate::crypto::HEADER_LEN + loader + resolve;
        [0x1400_03000u64, 0x1400_01000, 0x1400_05000]
            .into_iter()
            .map(|section| place_after(section, head))
            .collect()
    }

    fn elf_places() -> Vec<Place> {
        let loader = crate::loader::assemble_sysv(&elf_size_plan())
            .unwrap()
            .len();
        let head = crate::crypto::HEADER_LEN + loader;
        [0x404000u64, 0x500000, 0x600000]
            .into_iter()
            .map(|section| place_after(section, head))
            .collect()
    }

    fn place_after(section_va: u64, head: usize) -> Place {
        let raw = section_va + head as u64;
        Place {
            section_va,
            prefix: head + align_pad(raw),
        }
    }

    fn pe_size_plan() -> crate::loader::LoaderPlan {
        crate::loader::LoaderPlan {
            origin: 0x2000,
            payload: 0x1400_3000,
            payload_len: 32,
            checksum: 0,
            aead_key: [0; 32],
            aead_nonce: [0; 12],
            strings: 0x1400_3000,
            imports: 0x1400_3100,
            table: 0x1400_3200,
            calls: 0x1400_2100,
            module: 0x1400_3300,
            resolve: 0x1400_1800,
            original: 0x140001000,
            cave: 0x1400_4000,
            runtime: 0x1400_5000,
            name_key: [0; 16],
        }
    }

    fn elf_size_plan() -> crate::loader::SysvPlan {
        crate::loader::SysvPlan {
            origin: 0x403200,
            payload: 0x405200,
            payload_len: 32,
            checksum: 0,
            aead_key: [0; 32],
            aead_nonce: [0; 12],
            strings: 0x405200,
            imports: 0x405300,
            table: 0x405400,
            calls: 0x404a00,
            image_base: 0x400000,
            dynamic: 0x402010,
            original: 0x401000,
            gs: 0x406200,
            runtime: 0x407200,
        }
    }

    fn assert_gate(
        bytes: &[u8],
        frame: usize,
        origin: u64,
        image: &[u8],
        image_va: u64,
        seed: u64,
    ) {
        let ops = gate_ops(&bytes[..frame], origin);
        assert_eq!(ops.locks.len(), 1, "seed {seed} origin {origin:#x}");
        let addr = ops.locks[0];
        let place = format!("seed {seed} origin {origin:#x} gate {addr:#x}");
        let stores = ops.stores.iter().filter(|item| **item == addr).count();
        assert_eq!(stores, 1, "{place}");
        assert!(ops.loads.contains(&addr), "{place}");
        assert!(addr.is_multiple_of(8), "{place}");
        assert!(addr % 64 + 8 <= 64, "{place}");
        assert!(addr % 4096 + 8 <= 4096, "{place}");
        let end = origin + bytes.len() as u64;
        assert!(addr >= origin && addr + 8 <= end, "{place}");
        let at = usize::try_from(addr - image_va).unwrap();
        assert!(at + 8 <= image.len(), "{place}");
        assert_eq!(&image[at..at + 8], &[0u8; 8], "{place}");
    }

    fn gate_ops(code: &[u8], origin: u64) -> GateOps {
        use iced_x86::{Decoder, DecoderOptions, MemorySize, Mnemonic, OpKind};
        // Data islands make a linear decode stop before the gate. `lock` and REX.W
        // are the prefixes of the atomic and of the release `mov`.
        let mut ops = GateOps::default();
        for (off, byte) in code.iter().enumerate() {
            if *byte != 0xF0 && *byte != 0x48 {
                continue;
            }
            let mut decoder =
                Decoder::with_ip(64, &code[off..], origin + off as u64, DecoderOptions::NONE);
            let insn = decoder.decode();
            if insn.is_invalid() || !insn.is_ip_rel_memory_operand() {
                continue;
            }
            if insn.memory_size() != MemorySize::UInt64 {
                continue;
            }
            let addr = insn.ip_rel_memory_address();
            let locked = insn.has_lock_prefix();
            if insn.mnemonic() == Mnemonic::Cmpxchg && locked {
                ops.locks.push(addr);
            } else if insn.mnemonic() == Mnemonic::Mov
                && insn.op0_kind() == OpKind::Memory
                && !locked
            {
                ops.stores.push(addr);
            } else if insn.mnemonic() == Mnemonic::Mov && !locked {
                ops.loads.push(addr);
            }
        }
        ops
    }

    #[derive(Default)]
    struct GateOps {
        locks: Vec<u64>,
        stores: Vec<u64>,
        loads: Vec<u64>,
    }

    #[test]
    fn stub_size_is_stable_across_origins() {
        let low = assemble_vm(0x1000).unwrap();
        let high = assemble_vm(0x1400_02000).unwrap();
        assert_eq!(low.bytes.len(), high.bytes.len());
        assert_eq!(low.frame, high.frame);
        assert_eq!(low.dispatch, high.dispatch);
        assert_eq!(low.handlers, high.handlers);
        assert_eq!(low.cipher, high.cipher);
        assert_eq!(low.calls, high.calls);
    }

    #[test]
    fn code_layout_offsets_stay_stable_within_a_seed() {
        for seed in [1u64, 2, 9] {
            let low = assemble_vm_seeded(0x1000, seed).unwrap();
            let high = assemble_vm_seeded(0x1400_02000, seed).unwrap();
            assert_eq!(low.bytes.len(), high.bytes.len(), "seed {seed}");
            assert_eq!(low.bytes, high.bytes, "seed {seed}");
            assert_eq!(low.dispatch, high.dispatch, "seed {seed}");
            assert_eq!(low.handlers, high.handlers, "seed {seed}");
            assert_eq!(low.cipher, high.cipher, "seed {seed}");
            assert_eq!(low.frame, high.frame, "seed {seed}");
            assert_eq!(low.calls, high.calls, "seed {seed}");
        }
    }

    #[test]
    fn handler_window_differs_and_dispatcher_has_no_shared_anchor() {
        for tag in crate::vm::HOT_OPCODES {
            assert!(BYTECODE_OPCODES.contains(tag), "hot opcode {tag:#x}");
        }
        let mut images = Vec::new();
        for seed in 1..=10u64 {
            images.push(assemble_vm_seeded(0x1000, seed).unwrap());
        }
        assert_handler_window_differs(&images);
        assert_dispatchers_share_no_anchor(&images);
        assert_dispatcher_block_similarity(&images);
        let again = assemble_vm_seeded(0x1000, 1).unwrap();
        assert_eq!(images[0].bytes, again.bytes);
    }

    fn assert_handler_window_differs(images: &[NativeVm]) {
        let measured = measure_handler_difference(1).unwrap();
        let left = images[0].handler_window();
        let right = images[1].handler_window();
        let (different, percent) = window_difference(left, right);
        assert_eq!(measured.difference_percent, percent);
        assert_eq!(
            measured.window_len,
            u32::try_from(left.len().max(right.len())).unwrap()
        );
        assert_eq!(measured.window, HANDLER_WINDOW);
        assert!(
            left.len() < images[0].bytes.len(),
            "{HANDLER_WINDOW} must be shorter than the stub"
        );
        assert!(
            percent >= 25,
            "{HANDLER_WINDOW}: seeds 1 and 2 differ by {percent}% ({different} bytes, lengths {} and {})",
            left.len(),
            right.len()
        );
    }

    fn assert_dispatchers_share_no_anchor(images: &[NativeVm]) {
        for i in 0..images.len() {
            for j in (i + 1)..images.len() {
                let dispatcher_a = images[i].dispatcher();
                let dispatcher_b = images[j].dispatcher();
                assert!(
                    dispatcher_a.len() >= 16 && dispatcher_b.len() >= 16,
                    "{DISPATCH_WINDOW} is shorter than 16 bytes"
                );
                assert!(
                    !shares_anchor(dispatcher_a, dispatcher_b),
                    "{DISPATCH_WINDOW}: seeds {} and {} share a 16-byte dispatcher anchor",
                    i + 1,
                    j + 1
                );
            }
        }
    }

    // Byte hashes over control-transfer-delimited blocks in the dispatcher
    // window. This is a batch metric, not a structural normalization claim.
    fn dispatcher_block_hashes(bytes: &[u8]) -> std::collections::HashSet<[u8; 32]> {
        use iced_x86::{Decoder, DecoderOptions, FlowControl};
        let mut decoder = Decoder::new(64, bytes, DecoderOptions::NONE);
        let mut start = 0;
        let mut hashes = std::collections::HashSet::new();
        while decoder.can_decode() {
            let insn = decoder.decode();
            let end = decoder.position();
            if insn.is_invalid() {
                start = end;
            } else if insn.flow_control() != FlowControl::Next || end == bytes.len() {
                hashes.insert(crate::crypto::sha256(&bytes[start..end]));
                start = end;
            }
        }
        hashes
    }

    fn assert_dispatcher_block_similarity(images: &[NativeVm]) {
        const MAX_JACCARD_PERCENT: usize = 75;
        let sets: Vec<_> = images
            .iter()
            .map(|vm| dispatcher_block_hashes(vm.dispatcher()))
            .collect();
        for (i, left) in sets.iter().enumerate() {
            for (j, right) in sets.iter().enumerate().skip(i + 1) {
                let shared = left.intersection(right).count();
                let total = left.union(right).count();
                assert!(total > 0);
                assert!(
                    shared * 100 < total * MAX_JACCARD_PERCENT,
                    "seeds {} and {} share {shared}/{total} dispatcher block hashes",
                    i + 1,
                    j + 1
                );
            }
        }
    }

    fn shares_anchor(left: &[u8], right: &[u8]) -> bool {
        use std::collections::HashSet;

        let mut seen = HashSet::<[u8; 16]>::new();
        for window in left.windows(16) {
            let mut key = [0u8; 16];
            key.copy_from_slice(window);
            seen.insert(key);
        }
        right.windows(16).any(|window| {
            let mut key = [0u8; 16];
            key.copy_from_slice(window);
            seen.contains(&key)
        })
    }

    #[test]
    fn window_len_is_the_percent_denominator() {
        let mut saw_unequal = false;
        for seed in 1..=10u64 {
            let measured = measure_handler_difference(seed).unwrap();
            let left = assemble_vm_seeded(0x1000, seed)
                .unwrap()
                .handler_window()
                .len();
            let right = assemble_vm_seeded(0x1000, seed.wrapping_add(1))
                .unwrap()
                .handler_window()
                .len();
            saw_unequal |= left != right;
            let compared = u32::try_from(left.max(right)).unwrap();
            assert_eq!(measured.window_len, compared, "seed {seed}");
            assert_eq!(
                u64::from(measured.difference_percent),
                u64::from(measured.different_bytes) * 100 / u64::from(measured.window_len),
                "seed {seed}"
            );
            if seed == 1 {
                assert!(measured.difference_percent >= 25);
            }
        }
        assert!(
            saw_unequal,
            "a seed pair must differ in handler-window length"
        );
    }

    #[test]
    fn metamorphic_seeds_match_the_oracle() {
        let plain = mix_ir();
        let expect = (10u64.wrapping_mul(7).wrapping_add(3)) ^ 0x5a;
        for seed in [0u64, 1, 2, 3, 4, 5, 8, 9, 15, 42] {
            let _guard = bind_metamorphic_seed(seed);
            assert_eq!(run_native(&plain, 10), expect, "seed {seed}");
        }
    }

    #[test]
    fn handler_selection_is_computed_without_a_pointer_table() {
        let origin = 0x400000u64;
        let vm = assemble_vm(origin).unwrap();
        assert!(
            vm.bytes
                .windows(256 * 8)
                .all(|window| window.iter().any(|byte| *byte != 0)),
            "stub still contains a contiguous 256×8 zero table"
        );
        assert_eq!(scaled_memory_jumps(&vm.bytes, origin), 0);
        let inner = origin + vm.cipher as u64;
        assert!(
            register_jumps(&vm.bytes[vm.cipher..vm.frame], inner) >= 1,
            "level-2 unmask does not jump through a register"
        );
        let fetch = origin + vm.dispatch as u64;
        assert_eq!(
            opcode_compares(&vm.bytes[vm.dispatch..vm.handlers], fetch),
            0,
            "the compare chain is back in the dispatcher"
        );
    }

    fn scaled_memory_jumps(bytes: &[u8], origin: u64) -> u32 {
        use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
        let mut decoder = Decoder::with_ip(64, bytes, origin, DecoderOptions::NONE);
        let mut count = 0u32;
        while decoder.can_decode() {
            let ip = decoder.ip();
            let insn = decoder.decode();
            if decoder.ip() == ip {
                break;
            }
            if insn.mnemonic() == Mnemonic::Jmp
                && insn.op0_kind() == OpKind::Memory
                && insn.memory_index_scale() > 1
            {
                count += 1;
            }
        }
        count
    }

    fn register_jumps(bytes: &[u8], origin: u64) -> u32 {
        use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
        let mut decoder = Decoder::with_ip(64, bytes, origin, DecoderOptions::NONE);
        let mut count = 0u32;
        while decoder.can_decode() {
            let insn = decoder.decode();
            if insn.is_invalid() {
                break;
            }
            if insn.mnemonic() == Mnemonic::Jmp && insn.op0_kind() == OpKind::Register {
                count += 1;
            }
        }
        count
    }

    fn opcode_compares(bytes: &[u8], origin: u64) -> u32 {
        use iced_x86::{Decoder, DecoderOptions, Mnemonic};
        let mut decoder = Decoder::with_ip(64, bytes, origin, DecoderOptions::NONE);
        let mut count = 0u32;
        while decoder.can_decode() {
            let insn = decoder.decode();
            if insn.is_invalid() {
                break;
            }
            if insn.mnemonic() == Mnemonic::Cmp
                && cmp_immediate(&insn)
                    .is_some_and(|value| value < 256 && BYTECODE_OPCODES.contains(&(value as u8)))
            {
                count += 1;
            }
        }
        count
    }

    fn cmp_immediate(insn: &iced_x86::Instruction) -> Option<u64> {
        use iced_x86::OpKind;
        match insn.op1_kind() {
            OpKind::Immediate8 => Some(u64::from(insn.immediate8())),
            OpKind::Immediate8to32 => Some(insn.immediate8to32() as u32 as u64),
            OpKind::Immediate8to64 => Some(insn.immediate8to64() as u64),
            OpKind::Immediate32 => Some(u64::from(insn.immediate32())),
            OpKind::Immediate32to64 => Some(insn.immediate32to64() as u64),
            _ => None,
        }
    }

    #[test]
    fn each_handler_variant_matches_the_oracle() {
        assert!(VARIANT_OPCODES.len() >= 4);
        let straight = variant_image(false);
        let branched = variant_image(true);
        let oracle = exec_rax(&straight);
        let branch = exec_rax(&branched);
        assert_eq!(oracle, 25);
        assert_eq!(branch, 42);
        let base = run_image(&straight, 0);
        assert_eq!(base.0, oracle);
        for bit in 0..VARIANT_OPCODES.len() {
            let alt = run_image(&straight, 1u32 << bit);
            assert_eq!(alt.0, oracle, "variant bit {bit}");
            assert_ne!(alt.1, base.1, "variant bit {bit} did not execute");
            assert_eq!(run_image(&branched, 1u32 << bit).0, branch);
        }
        assert_eq!(run_image(&straight, 0x0f).0, oracle);
        assert_eq!(run_image(&branched, 0x0f).0, branch);
    }

    fn exec_rax(image: &crate::vm::BcImage) -> u64 {
        use crate::flags::Flags;
        use crate::ir::MapMem;
        use crate::vm::exec_image;
        let mut arch = [0u64; 16];
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut absent =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        exec_image(image, 0, &mut arch, &mut flags, &mut mem, 0, &mut absent).unwrap();
        arch[0]
    }

    fn run_image(image: &crate::vm::BcImage, mix: u32) -> (u64, u64) {
        let origin = 0x400000u64;
        let vm = assemble_vm(origin).unwrap();
        let mut machine = bare(Policy::default()).unwrap();
        machine.regions.push(Region {
            base: origin,
            data: vm.bytes,
        });
        machine.regions.push(Region {
            base: 0x500000,
            data: vec![0; 0x20000],
        });
        place_runtime(
            &image.funcs[0],
            &image.inv,
            0,
            &image.slots,
            mix,
            &mut machine,
            0x500000,
            0x518000,
        )
        .unwrap();
        let frame = origin + vm.frame as u64;
        machine.regs[3] = frame;
        machine.regs[13] = 0x500000;
        machine.regs[14] = u64::from(image.funcs[0].entry);
        let stack = machine.regs[4];
        write_arch(&mut machine, frame, &image.slots, 4, stack);
        machine.rip = origin + vm.dispatch as u64;
        machine.run().unwrap();
        (machine.regs[0], machine.steps)
    }

    #[test]
    fn emit_chacha_helpers_keep_the_stub_image() {
        let first = assemble_vm_seeded(0x400000, 0).unwrap();
        let second = assemble_vm_seeded(0x400000, 0).unwrap();
        assert_eq!(first.bytes, second.bytes);
        let other = assemble_vm_seeded(0x400000, 1).unwrap();
        assert_ne!(first.bytes, other.bytes);
        assert_eq!(
            &first.bytes[first.cipher..first.frame],
            &other.bytes[other.cipher..other.frame],
            "ChaCha helper stays fixed while the dispatcher and handlers move"
        );
    }

    #[test]
    fn chacha_xor_uses_bounded_steps_for_a_full_chunk() {
        let origin = 0x400000;
        let mut assembler = CodeAssembler::new(64).unwrap();
        let mut xor_loop = assembler.create_label();
        let mut xor_done = assembler.create_label();
        emit_chacha_xor(&mut assembler, &mut xor_loop, &mut xor_done).unwrap();
        assembler.ret().unwrap();
        let mut machine = bare(Policy::default()).unwrap();
        machine.regions.extend([
            Region {
                base: origin,
                data: assembler.assemble(origin).unwrap(),
            },
            Region {
                base: 0x900001,
                data: vec![0xa5; 64],
            },
            Region {
                base: 0xa00003,
                data: vec![0x5a; 64],
            },
            Region {
                base: 0xb00005,
                data: vec![0; 64],
            },
        ]);
        machine.regs[6] = 0x900001;
        machine.regs[7] = 0xb00005;
        machine.regs[11] = 0xa00003 - 64;
        machine.regs[12] = 64;
        machine.rip = origin;
        machine.run().unwrap();
        assert_eq!(machine.read(0xb00005, 64).unwrap(), [0xff; 64]);
        assert!(
            machine.steps < 128,
            "full chunk took {} instructions",
            machine.steps
        );
    }

    #[test]
    fn stub_chacha_checks_unaligned_edges_in_place_and_disjoint() {
        let origin = 0x400000;
        let stub = assemble_vm(origin).unwrap();
        for len in [0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 65, 129] {
            for in_place in [false, true] {
                assert_chacha_range(origin, &stub, len, in_place);
            }
        }
    }

    fn assert_chacha_range(origin: u64, stub: &NativeVm, len: usize, in_place: bool) {
        let src = 0x900001;
        let dst = if in_place { src } else { 0xa00003 };
        let input: Vec<_> = (0..len).map(|index| index as u8 ^ 0x5a).collect();
        let key = std::array::from_fn(|index| index as u8);
        let nonce = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut expected = input.clone();
        crate::vm::apply_keystream(&key, &nonce, 1, &mut expected);
        let mut machine = bare(Policy::default()).unwrap();
        machine.regions.extend([
            Region {
                base: origin,
                data: stub.bytes.clone(),
            },
            Region {
                base: src,
                data: input.clone(),
            },
        ]);
        if !in_place {
            machine.regions.push(Region {
                base: dst,
                data: vec![0; len],
            });
        }
        let chain = machine.gs + crate::vm::GS_CHAIN_AT as u64;
        machine.write(chain, &key).unwrap();
        machine
            .write(chain + crate::vm::CTX_INDEX as u64, &nonce)
            .unwrap();
        machine.regs[1] = len as u64;
        machine.regs[6] = src;
        machine.regs[7] = dst;
        machine.regs[10] = 1;
        machine.rip = origin + stub.cipher as u64;
        machine.run().unwrap();
        assert_eq!(machine.read(dst, len).unwrap(), expected, "length {len}");
        if !in_place {
            assert_eq!(machine.read(src, len).unwrap(), input);
        }
        assert_eq!(machine.regs[6], src + len as u64);
        assert_eq!(machine.regs[7], dst);
        assert_eq!(machine.regs[10], 1 + len.div_ceil(64) as u64);
    }

    #[test]
    fn stub_chacha_matches_rust_across_a_block_boundary() {
        let plain = wide_plain();
        let image = wide_image(&plain);
        let mut machine = prepare_wide(&image);
        open_wide(&mut machine, &plain);
        assert_private_plaintext(&machine, &plain);
        machine.run().unwrap();
        assert_private_sealed(&machine, &image, &plain);
    }

    fn wide_plain() -> Vec<u8> {
        let mut plain = vec![0x52u8];
        plain.extend((0..79u8).map(|byte| byte.wrapping_add(0x20)));
        assert!(plain.len() > 64);
        plain
    }

    fn wide_image(plain: &[u8]) -> crate::vm::BcImage {
        use crate::vm::BcImage;
        let salt = [0x91u8; 8];
        let key_seed = 0x0a0b_0c0d;
        let rva = 0x1000u32;
        let mut perm = [0u8; 256];
        let mut inv = [0u8; 256];
        for (index, byte) in perm.iter_mut().enumerate() {
            *byte = index as u8;
            inv[index] = index as u8;
        }
        let (insns, mut key, terminal) =
            crate::vm::seal_chain(key_seed, rva, &salt, &[plain.to_vec()]).unwrap();
        let page = crate::secret::KeyPage::hold(&key).unwrap();
        crate::secret::wipe(&mut key);
        BcImage {
            perm,
            inv,
            slots: SlotMap::identity(),
            handler_mix: 0,
            funcs: vec![crate::vm::bare_func(
                "wide", rva, 0, insns, salt, key_seed, page, terminal,
            )],
        }
    }

    fn prepare_wide(image: &crate::vm::BcImage) -> crate::emu::Machine {
        let origin = 0x400000u64;
        let vm = assemble_vm(origin).unwrap();
        let mut machine = bare(Policy::default()).unwrap();
        machine.policy.interpret_cipher = true;
        machine.regions.push(Region {
            base: origin,
            data: vm.bytes,
        });
        machine.regions.push(Region {
            base: 0x500000,
            data: vec![0; 0x20000],
        });
        place_wide(&mut machine, image, origin + vm.frame as u64);
        machine.regs[13] = 0x500000;
        machine.regs[14] = 0;
        machine.rip = origin + vm.dispatch as u64;
        machine
    }

    fn open_wide(machine: &mut crate::emu::Machine, plain: &[u8]) {
        for _ in 0..2_000_000 {
            if private_holds(machine, plain) {
                return;
            }
            machine.steps += 1;
            machine.step().unwrap();
        }
        panic!("private cache never held the block");
    }

    fn place_wide(machine: &mut crate::emu::Machine, image: &crate::vm::BcImage, frame: u64) {
        place_runtime(
            &image.funcs[0],
            &image.inv,
            0,
            &image.slots,
            0,
            machine,
            0x500000,
            0x518000,
        )
        .unwrap();
        let stack = machine.regs[4];
        write_arch(machine, frame, &image.slots, 4, stack);
        machine.regs[3] = frame;
    }

    fn assert_private_plaintext(machine: &crate::emu::Machine, plain: &[u8]) {
        let cache = private_cache(machine);
        assert_eq!(machine.read(cache, 1).unwrap(), vec![1]);
        assert_eq!(machine.read(cache + 1, plain.len()).unwrap(), plain);
        assert_eq!(shared_flag(machine, plain), vec![0]);
    }

    fn assert_private_sealed(
        machine: &crate::emu::Machine,
        image: &crate::vm::BcImage,
        plain: &[u8],
    ) {
        use crate::vm::reseal_block;
        let func = &image.funcs[0];
        let cache = private_cache(machine);
        assert_eq!(machine.read(cache, 1).unwrap(), vec![2]);
        let key = func.key.bytes();
        let sealed = reseal_block(&key, 0, func.rva, &func.salt, plain).unwrap();
        assert_eq!(machine.read(cache + 1, plain.len()).unwrap(), sealed);
        assert_eq!(shared_flag(machine, plain), vec![0]);
    }

    fn private_holds(machine: &crate::emu::Machine, plain: &[u8]) -> bool {
        let cache = private_cache(machine);
        cache != 0
            && machine.read(cache, 1).ok().as_deref() == Some(&[1])
            && machine.read(cache + 1, plain.len()).ok().as_deref() == Some(plain)
    }

    fn private_cache(machine: &crate::emu::Machine) -> u64 {
        use crate::emu::GS_BASE;
        use crate::vm::{CTX_CACHE, GS_CHAIN_PTR};
        let chain = read_qword(machine, GS_BASE + GS_CHAIN_PTR as u64);
        if chain == 0 {
            return 0;
        }
        read_qword(machine, chain + CTX_CACHE as u64)
    }

    fn shared_flag(machine: &crate::emu::Machine, plain: &[u8]) -> Vec<u8> {
        use crate::vm::runtime_fits;
        let shared = runtime_fits(0x500000, 1, plain.len()).unwrap();
        machine.read(shared.cache, 1).unwrap()
    }

    fn read_qword(machine: &crate::emu::Machine, at: u64) -> u64 {
        let bytes = machine.read(at, 8).unwrap();
        u64::from_le_bytes(bytes.try_into().unwrap())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Outcome {
        Value(u64),
        Failed,
    }

    fn branch_ir() -> FuncIr {
        FuncIr {
            name: "branch".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![
                Block {
                    ops: vec![Op::MovRi(0, 1), Op::CmpRi(0, 1)],
                    exit: Exit::Jcc(4, 1, 2),
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRi(0, 7)],
                    exit: Exit::Ret,
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRi(0, 9)],
                    exit: Exit::Ret,
                    opaque: false,
                },
            ],
        }
    }

    fn rust_outcome(image: &crate::vm::BcImage, arg: u64, force_crc: bool) -> Outcome {
        use crate::flags::Flags;
        use crate::ir::MapMem;
        use crate::vm::{exec_image, exec_image_crc_forced_ok};
        let mut arch = [0u64; 16];
        arch[1] = arg;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut absent =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        let result = if force_crc {
            exec_image_crc_forced_ok(image, 0, &mut arch, &mut flags, &mut mem, 0, &mut absent)
        } else {
            exec_image(image, 0, &mut arch, &mut flags, &mut mem, 0, &mut absent)
        };
        match result {
            Ok(()) => Outcome::Value(arch[0]),
            Err(_) => Outcome::Failed,
        }
    }

    fn relax_stub_crc(machine: &mut crate::emu::Machine, image: &crate::vm::BcImage, runtime: u64) {
        let func = &image.funcs[0];
        for index in 0..func.insns.len() {
            let Ok(plain) = plain_insn(func, index, &image.inv) else {
                continue;
            };
            if plain.first() == Some(&0x60) && plain.len() >= 5 {
                let immediate = u32::from_le_bytes(plain[1..5].try_into().expect("crc immediate"));
                machine
                    .write(runtime + 0x30, &immediate.to_le_bytes())
                    .expect("crc slot");
            }
        }
    }

    fn stub_outcome(
        vm: &NativeVm,
        image: &crate::vm::BcImage,
        arg: u64,
        baseline_crc: u32,
        relax_crc: bool,
        max_steps: u64,
    ) -> Outcome {
        let origin = 0x400000u64;
        let mut machine = bare(Policy {
            max_steps,
            ..Policy::default()
        })
        .unwrap();
        machine.regions.push(Region {
            base: origin,
            data: vm.bytes.clone(),
        });
        machine.regions.push(Region {
            base: 0x500000,
            data: vec![0; 0x20000],
        });
        place_runtime(
            &image.funcs[0],
            &image.inv,
            baseline_crc,
            &image.slots,
            image.handler_mix,
            &mut machine,
            0x500000,
            0x518000,
        )
        .unwrap();
        if relax_crc {
            relax_stub_crc(&mut machine, image, 0x500000);
        }
        let frame = origin + vm.frame as u64;
        machine.regs[3] = frame;
        machine.regs[13] = 0x500000;
        machine.regs[14] = u64::from(image.funcs[0].entry);
        let stack = machine.regs[4];
        write_arch(&mut machine, frame, &image.slots, 1, arg);
        write_arch(&mut machine, frame, &image.slots, 4, stack);
        machine.rip = origin + vm.dispatch as u64;
        match machine.run() {
            Ok(()) if machine.regs[0] == 0xbad1 => Outcome::Failed,
            Ok(()) => Outcome::Value(machine.regs[0]),
            Err(_) => Outcome::Failed,
        }
    }

    fn assert_not_honest(outcome: Outcome, honest: u64) {
        match outcome {
            Outcome::Failed => {}
            Outcome::Value(value) => assert_ne!(value, honest),
        }
    }

    fn check_flips(func: &FuncIr, seed: u64, arg: u64, honest: u64) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let image = lower_image(std::slice::from_ref(func), &mut rng).unwrap();
        let origin = 0x400000u64;
        let vm = assemble_vm(origin).unwrap();
        let crc = check_crc(&image, &image.funcs[0]);
        assert_eq!(
            rust_outcome(&image, arg, false),
            Outcome::Value(honest),
            "rust seed {seed} {}",
            func.name
        );
        assert_eq!(
            stub_outcome(&vm, &image, arg, crc, false, 2_000_000),
            Outcome::Value(honest),
            "stub seed {seed} {}",
            func.name
        );
        for block in 0..image.funcs[0].insns.len() {
            for offset in 0..image.funcs[0].insns[block].bytes.len() {
                let mut flipped = image.clone();
                flipped.funcs[0].insns[block].bytes[offset] ^= 1;
                let forced = rust_outcome(&flipped, arg, true);
                let enforced = rust_outcome(&flipped, arg, false);
                assert_not_honest(forced, honest);
                assert_not_honest(enforced, honest);
                let budget = if matches!(forced, Outcome::Value(_)) {
                    2_000_000
                } else {
                    250_000
                };
                let stub_forced = stub_outcome(&vm, &flipped, arg, crc, true, budget);
                let stub_enforced = stub_outcome(&vm, &flipped, arg, crc, false, budget);
                assert_eq!(
                    forced, stub_forced,
                    "seed {seed} {} block {block} byte {offset} with the crc branch forced",
                    func.name
                );
                assert_eq!(
                    enforced, stub_enforced,
                    "seed {seed} {} block {block} byte {offset}",
                    func.name
                );
                assert_not_honest(stub_forced, honest);
            }
        }
    }

    fn pick_ir() -> FuncIr {
        use crate::ir::{RAX, RCX};
        FuncIr {
            name: "pick".into(),
            rva: 0x2000,
            entry: 0,
            blocks: vec![
                Block {
                    ops: vec![Op::CmpRi(RCX, 0)],
                    exit: Exit::Jcc(4, 1, 2),
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRi(RAX, 7)],
                    exit: Exit::Ret,
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRi(RAX, 9)],
                    exit: Exit::Ret,
                    opaque: false,
                },
            ],
        }
    }

    fn call_pick_twice(first: u64, second: u64) -> Vec<FuncIr> {
        use crate::ir::{RAX, RBX, RCX};
        vec![
            FuncIr {
                name: "caller".into(),
                rva: 0x1000,
                entry: 0,
                blocks: vec![
                    Block {
                        ops: vec![Op::MovRi(RCX, first)],
                        exit: Exit::CallRva {
                            rva: 0x2000,
                            next: 1,
                        },
                        opaque: false,
                    },
                    Block {
                        ops: vec![Op::MovRr(RBX, RAX), Op::MovRi(RCX, second)],
                        exit: Exit::CallRva {
                            rva: 0x2000,
                            next: 2,
                        },
                        opaque: false,
                    },
                    Block {
                        ops: vec![],
                        exit: Exit::Ret,
                        opaque: false,
                    },
                ],
            },
            pick_ir(),
        ]
    }

    fn assert_pick_reentry(first: u64, second: u64, second_rax: u64, first_rbx: u64) {
        let funcs = call_pick_twice(first, second);
        let (ir, vm, native) = run_three(&funcs, 3, call_arch(), &mut no_host);
        assert_eq!(ir[0], second_rax, "pick({second})");
        assert_eq!(ir[3], first_rbx, "pick({first})");
        assert_eq!(vm, ir, "rust interpreter {first} then {second}");
        assert_eq!(native, vm, "stub {first} then {second}");
    }

    #[test]
    fn second_call_on_the_other_jcc_arm_matches_the_interpreter() {
        assert_pick_reentry(0, 1, 9, 7);
        assert_pick_reentry(1, 0, 7, 9);
        assert_pick_reentry(0, 0, 7, 7);
    }

    fn external_pick_pair(arg: u64) -> (u64, u64) {
        let func = pick_ir();
        let ir = ir_with(&func, arg);
        let image = vm_with(&func, arg);
        assert_eq!(image, ir, "exec_image pick({arg})");
        (ir, image)
    }

    fn mount_pick(
        tramp: Option<(u64, Vec<u8>)>,
    ) -> (NativeVm, crate::vm::BcImage, crate::emu::Machine) {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let image = lower_image(std::slice::from_ref(&pick_ir()), &mut rng).unwrap();
        let origin = 0x400000u64;
        let vm = assemble_vm(origin).unwrap();
        let mut machine = bare(Policy::default()).unwrap();
        machine.regions.push(Region {
            base: origin,
            data: vm.bytes.clone(),
        });
        machine.regions.push(Region {
            base: 0x500000,
            data: vec![0; 0x20000],
        });
        if let Some((at, bytes)) = tramp {
            machine.regions.push(Region {
                base: at,
                data: bytes,
            });
        }
        place_runtime(
            &image.funcs[0],
            &image.inv,
            check_crc(&image, &image.funcs[0]),
            &image.slots,
            image.handler_mix,
            &mut machine,
            0x500000,
            0x518000,
        )
        .unwrap();
        (vm, image, machine)
    }

    fn call_direct(
        machine: &mut crate::emu::Machine,
        vm: &NativeVm,
        image: &crate::vm::BcImage,
        arg: u64,
        stack: u64,
    ) -> u64 {
        let origin = 0x400000u64;
        let frame = origin + vm.frame as u64;
        machine.exit_code = None;
        machine.regs[3] = frame;
        machine.regs[4] = stack;
        machine.regs[13] = 0x500000;
        machine.regs[14] = u64::from(image.funcs[0].entry);
        write_arch(machine, frame, &image.slots, 1, arg);
        write_arch(machine, frame, &image.slots, 4, stack);
        machine.rip = origin + vm.dispatch as u64;
        machine
            .run()
            .unwrap_or_else(|err| panic!("direct {arg}: {err}"));
        machine.regs[0]
    }

    fn call_trampoline(machine: &mut crate::emu::Machine, at: u64, arg: u64, stack: u64) -> u64 {
        machine.exit_code = None;
        machine.regs[1] = arg;
        machine.regs[4] = stack;
        machine.rip = at;
        match machine.run() {
            Ok(()) => machine.regs[0],
            Err(err) => panic!(
                "trampoline {arg}: {err}; rip={:#x} rax={:#x}",
                machine.rip, machine.regs[0]
            ),
        }
    }

    fn assert_external_arms(first: u64, second: u64) {
        let (ir_first, _) = external_pick_pair(first);
        let (ir_second, _) = external_pick_pair(second);
        let (vm, image, mut direct) = mount_pick(None);
        let stack = direct.regs[4];
        assert_eq!(
            call_direct(&mut direct, &vm, &image, first, stack),
            ir_first,
            "direct pick({first})"
        );
        assert_eq!(
            call_direct(&mut direct, &vm, &image, second, stack),
            ir_second,
            "direct pick({first}) then pick({second})"
        );
        let at = 0x480000u64;
        let bytes = assemble_trampoline(&Trampoline {
            origin: at,
            frame: 0x400000 + vm.frame as u64,
            runtime: 0x500000,
            entry: image.funcs[0].entry,
            dispatch: 0x400000 + vm.dispatch as u64,
            image_base: 0,
            chains: 0x400000 + vm.chains as u64,
        })
        .unwrap();
        let (_, _, mut via) = mount_pick(Some((at, bytes)));
        let stack = via.regs[4];
        assert_eq!(
            call_trampoline(&mut via, at, first, stack),
            ir_first,
            "trampoline pick({first})"
        );
        assert_eq!(
            call_trampoline(&mut via, at, second, stack),
            ir_second,
            "trampoline pick({first}) then pick({second})"
        );
    }

    #[test]
    fn second_external_entry_on_the_other_arm_matches_the_interpreter() {
        // Two fresh entries share one runtime. CallRva inside one run does not.
        assert_external_arms(0, 1);
        assert_external_arms(1, 0);
        assert_external_arms(0, 0);
        assert_external_arms(1, 1);
    }

    #[test]
    fn woven_flip_of_every_block_byte_fails_closed_across_ten_seeds() {
        let branch = branch_ir();
        let branch_honest = ir_rax(&branch);
        for seed in 0..10u64 {
            check_flips(
                &mix_ir(),
                seed,
                10,
                (10u64.wrapping_mul(7).wrapping_add(3)) ^ 0x5a,
            );
            check_flips(&branch, seed, 0, branch_honest);
        }
    }

    fn variant_image(branch: bool) -> crate::vm::BcImage {
        use crate::vm::BcImage;
        let mut perm = [0u8; 256];
        let mut inv = [0u8; 256];
        for (index, byte) in perm.iter_mut().enumerate() {
            *byte = index as u8;
            inv[index] = index as u8;
        }
        let mut salt = [0x62u8; 8];
        salt[7] = u8::from(branch);
        let (insns, page, terminal) = hold_chain(0x1000, &salt, &variant_plains(branch));
        BcImage {
            perm,
            inv,
            slots: SlotMap::identity(),
            handler_mix: 0,
            funcs: vec![sealed_func("variants", 0x1000, salt, page, terminal, insns)],
        }
    }

    fn variant_plains(branch: bool) -> Vec<Vec<u8>> {
        if branch {
            return vec![
                vec![0x03, 0, 1, 0, 0, 0, 0, 0, 0, 0],
                vec![0x15, 0, 0xff, 0xff, 0xff, 0xff],
                vec![0x17, 0, 0, 0, 0, 0],
                vec![0x41, 4, 5, 0, 0, 0],
                vec![0x40, 7, 0, 0, 0],
                vec![0x03, 0, 42, 0, 0, 0, 0, 0, 0, 0],
                vec![0x52],
                vec![0x03, 0, 7, 0, 0, 0, 0, 0, 0, 0],
                vec![0x52],
            ];
        }
        vec![
            vec![0x03, 0, 11, 0, 0, 0, 0, 0, 0, 0],
            vec![0x02, 1, 0],
            vec![0x15, 1, 5, 0, 0, 0],
            vec![0x17, 1, 9, 0, 0, 0],
            vec![0x02, 0, 1],
            vec![0x52],
        ]
    }
}
