use std::cell::Cell;

use crate::error::{exact_bytes, msg, Result};
use crate::flags::{self, Flags};
use crate::ir::{MemIo, ARCH};

use super::{
    cipher, decode, decode_span, decrypt_at, form, stack, Bc, BcFunc, BcImage, HostCall, SlotMap,
    NEST_XOR, SLOT_COUNT,
};

pub fn exec_image(
    image: &BcImage,
    index: usize,
    arch: &mut [u64; ARCH],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
    abs_call: &mut HostCall<'_>,
) -> Result<()> {
    exec_depth(
        image, index, arch, flags, mem, image_base, abs_call, 0, true, false,
    )
}

/// Run `image` with the level-2 dispatcher selecting each handler tag.
///
/// Level 1 is [`exec_image`]. Both agree with M-IR when the inner program
/// maps every known opcode to itself.
pub fn exec_image_nested(
    image: &BcImage,
    index: usize,
    arch: &mut [u64; ARCH],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
    abs_call: &mut HostCall<'_>,
) -> Result<()> {
    exec_depth(
        image, index, arch, flags, mem, image_base, abs_call, 0, true, true,
    )
}

/// Run with the `Bc::Check` compare treated as success.
///
/// The woven key still has to close. Tests use this to show a patched block
/// is not saved by neutralizing the CRC branch.
#[cfg(test)]
pub fn exec_image_crc_forced_ok(
    image: &BcImage,
    index: usize,
    arch: &mut [u64; ARCH],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
    abs_call: &mut HostCall<'_>,
) -> Result<()> {
    exec_depth(
        image, index, arch, flags, mem, image_base, abs_call, 0, false, false,
    )
}

/// Keyed state of bytecode opened so far, in index order.
///
/// The value sits on the `exec_depth` frame. A second call, including a nested
/// one, gets its own copy and cannot read or reset this one. The native stub
/// keeps the same state at `gs:[GS_CHAIN_PTR]`.
struct Running {
    key: crate::secret::KeyPage,
    folded: usize,
    held: Option<usize>,
    plain: Vec<u8>,
}

impl Running {
    fn start(func: &BcFunc) -> Result<Self> {
        let mut bytes = func.key.bytes();
        let key = crate::secret::KeyPage::hold(&bytes);
        crate::secret::wipe(&mut bytes);
        let key = key?;
        publish_running(key.addr());
        Ok(Self {
            key,
            folded: 0,
            held: None,
            plain: Vec::new(),
        })
    }

    fn key_before(&self, func: &BcFunc, index: usize) -> Result<[u8; cipher::KEY_LEN]> {
        if self.folded <= index {
            return Ok(self.key.bytes());
        }
        // The cursor already passed this block without decrypting it.
        let mut key = func.key.bytes();
        for at in 0..index {
            let block = u32::try_from(at).map_err(|_| msg("vm ip out of range"))?;
            let next = cipher::weave_next(&key, block, &func.insns[at].bytes);
            crate::secret::wipe(&mut key);
            key = next;
        }
        Ok(key)
    }

    fn open(&mut self, func: &BcFunc, inv: &[u8; 256], index: usize) -> Result<OpenBuf> {
        if self.held == Some(index) {
            return Ok(OpenBuf::new(self.plain.clone()));
        }
        self.advance_to(func, index)?;
        let mut key = self.key_before(func, index)?;
        let plain = self.take_plain(func, inv, index, &key);
        crate::secret::wipe(&mut key);
        plain
    }

    fn advance_to(&mut self, func: &BcFunc, index: usize) -> Result<()> {
        if index >= func.insns.len() {
            return Err(msg("vm ip out of range"));
        }
        while self.folded < index {
            self.fold_block(func)?;
        }
        Ok(())
    }

    fn fold_block(&mut self, func: &BcFunc) -> Result<()> {
        let block = u32::try_from(self.folded).map_err(|_| msg("vm ip out of range"))?;
        let mut cur = self.key.bytes();
        let mut next = cipher::weave_next(&cur, block, &func.insns[self.folded].bytes);
        self.key.store(&next);
        crate::secret::wipe(&mut cur);
        crate::secret::wipe(&mut next);
        self.folded += 1;
        Ok(())
    }

    fn take_plain(
        &mut self,
        func: &BcFunc,
        inv: &[u8; 256],
        index: usize,
        key: &[u8; cipher::KEY_LEN],
    ) -> Result<OpenBuf> {
        self.wipe_plain();
        let plain = decrypt_at(func, index, inv, key)?;
        self.plain = plain.clone();
        self.held = Some(index);
        enter_plain();
        Ok(OpenBuf::new(plain))
    }

    fn wipe_plain(&mut self) {
        let open = self.held.take().is_some();
        crate::secret::wipe(&mut self.plain);
        self.plain.clear();
        if open {
            leave_plain();
        }
    }

    /// Absorb any sealed block the cursor has not folded yet.
    fn finish(&mut self, func: &BcFunc, _inv: &[u8; 256]) -> Result<()> {
        while self.folded < func.insns.len() {
            self.fold_block(func)?;
        }
        let mut got = self.key.bytes();
        let closed = got == func.terminal;
        crate::secret::wipe(&mut got);
        if !closed {
            return Err(crate::error::Error::Integrity);
        }
        Ok(())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let addr = self.key.addr();
        self.wipe_plain();
        clear_running(addr);
    }
}

/// Plaintext returned by [`Running::open`]. Drop wipes the bytes.
struct OpenBuf {
    bytes: Vec<u8>,
}

impl OpenBuf {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl Drop for OpenBuf {
    fn drop(&mut self) {
        crate::secret::wipe(&mut self.bytes);
    }
}

impl std::ops::Deref for OpenBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::ops::DerefMut for OpenBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

struct ExecCtx<'a> {
    flags: &'a mut Flags,
    mem: &'a mut dyn MemIo,
    abs_call: &'a mut HostCall<'a>,
    image_base: u64,
    depth: u32,
    enforce_crc: bool,
    nested: bool,
    stack: Vec<u64>,
    gate: u64,
}

fn exec_call_rva(image: &BcImage, regs: &mut [u64], rva: u32, ctx: &mut ExecCtx<'_>) -> Result<()> {
    let callee = image
        .funcs
        .iter()
        .position(|item| item.rva == rva)
        .ok_or_else(|| msg(format!("vm call to unknown rva {rva:#x}")))?;
    let mut child = [0u64; ARCH];
    gather_arch(&mut child, regs, &image.slots)?;
    exec_depth(
        image,
        callee,
        &mut child,
        ctx.flags,
        ctx.mem,
        ctx.image_base,
        ctx.abs_call,
        ctx.depth + 1,
        ctx.enforce_crc,
        ctx.nested,
    )?;
    scatter_arch(regs, &child, &image.slots);
    Ok(())
}

fn exec_call_reg(image: &BcImage, regs: &mut [u64], reg: u8, ctx: &mut ExecCtx<'_>) -> Result<()> {
    let target = regs
        .get(reg as usize)
        .copied()
        .ok_or_else(|| msg("register index out of range"))?;
    let mut child = [0u64; ARCH];
    gather_arch(&mut child, regs, &image.slots)?;
    (ctx.abs_call)(&mut child, ctx.flags, ctx.mem, target)?;
    scatter_arch(regs, &child, &image.slots);
    Ok(())
}

fn opened_insn(
    image: &BcImage,
    func: &BcFunc,
    weave: &mut Running,
    ip: u32,
    ctx: &ExecCtx<'_>,
) -> Result<OpenBuf> {
    if ctx.nested {
        return nested_plain(func, weave, &image.inv, ip as usize);
    }
    weave.open(func, &image.inv, ip as usize)
}

fn nested_plain(
    func: &BcFunc,
    weave: &mut Running,
    inv: &[u8; 256],
    index: usize,
) -> Result<OpenBuf> {
    let opcode = read_opcode(weave, func, inv, index)?;
    weave.wipe_plain();
    let tag = dispatcher_tag(func, opcode)?;
    let mut plain = weave.open(func, inv, index)?;
    plain[0] = tag;
    if let Some(slot) = weave.plain.get_mut(0) {
        *slot = tag;
    }
    Ok(plain)
}

fn read_opcode(weave: &mut Running, func: &BcFunc, inv: &[u8; 256], index: usize) -> Result<u8> {
    let plain = weave.open(func, inv, index)?;
    plain.first().copied().ok_or_else(|| msg("empty bytecode"))
}

fn dispatcher_tag(func: &BcFunc, opcode: u8) -> Result<u8> {
    let _guard = Resident::enter();
    let mut program = func.open_dispatcher()?;
    let mut byte = [opcode];
    let applied = super::inner::apply_dispatcher(&program, &mut byte);
    crate::secret::wipe(&mut program);
    applied?;
    Ok(byte[0])
}

/// `true` means `Ret` closed the chain. The caller publishes registers after that.
fn exec_insn(
    image: &BcImage,
    func: &BcFunc,
    weave: &mut Running,
    regs: &mut [u64],
    ip: &mut u32,
    ctx: &mut ExecCtx<'_>,
) -> Result<bool> {
    let op = open_op(image, func, weave, *ip, ctx)?;
    let done = enter_handler(image, func, weave, regs, ip, ctx, op)?;
    form::note_edge(regs, &mut ctx.gate);
    Ok(done)
}

/// Low bit of the gate picks the handler entry. Both entries run [`apply_op`].
fn enter_handler<'a>(
    image: &BcImage,
    func: &BcFunc,
    weave: &mut Running,
    regs: &mut [u64],
    ip: &mut u32,
    ctx: &mut ExecCtx<'a>,
    op: Bc,
) -> Result<bool> {
    if ctx.gate & 1 == 0 {
        apply_op(image, func, weave, regs, ip, ctx, op)
    } else {
        apply_odd(image, func, weave, regs, ip, ctx, op)
    }
}

fn apply_odd<'a>(
    image: &BcImage,
    func: &BcFunc,
    weave: &mut Running,
    regs: &mut [u64],
    ip: &mut u32,
    ctx: &mut ExecCtx<'a>,
    op: Bc,
) -> Result<bool> {
    apply_op(image, func, weave, regs, ip, ctx, op)
}

fn open_op(
    image: &BcImage,
    func: &BcFunc,
    weave: &mut Running,
    ip: u32,
    ctx: &ExecCtx<'_>,
) -> Result<Bc> {
    let mut plain = opened_insn(image, func, weave, ip, ctx)?;
    form::mix_imm(&mut plain, func.sched, func.rva, ip);
    let op = decode(&plain)?;
    crate::secret::wipe(&mut plain);
    Ok(op)
}

fn apply_op(
    image: &BcImage,
    func: &BcFunc,
    weave: &mut Running,
    regs: &mut [u64],
    ip: &mut u32,
    ctx: &mut ExecCtx<'_>,
    op: Bc,
) -> Result<bool> {
    ensure_regs(&op, regs.len())?;
    note_probe(&op, weave, ctx.mem)?;
    match op {
        Bc::Jmp(target) => *ip = target,
        Bc::Jcc(cond, target) => {
            *ip = if flags::cond_taken(cond, *ctx.flags) {
                target
            } else {
                *ip + 1
            };
        }
        Bc::Ret => {
            // A patched block must not publish the pre-patch registers.
            weave.finish(func, &image.inv)?;
            return Ok(true);
        }
        Bc::CallRva(rva) => {
            weave.wipe_plain();
            exec_call_rva(image, regs, rva, ctx)?;
            *ip += 1;
        }
        Bc::CallReg(reg) => {
            exec_call_reg(image, regs, reg, ctx)?;
            *ip += 1;
        }
        other => {
            step_data(image, regs, ctx, &other)?;
            *ip += 1;
        }
    }
    Ok(false)
}

fn step_data(image: &BcImage, regs: &mut [u64], ctx: &mut ExecCtx<'_>, op: &Bc) -> Result<()> {
    if stack::apply(op, regs, ctx.flags, &mut ctx.stack)? {
        return Ok(());
    }
    exec_bc(op, regs, ctx.flags, ctx.mem, ctx.image_base, &image.slots)
}

// Depth travels with the interpreter context so a recursive call can be refused.
#[allow(clippy::too_many_arguments)]
fn exec_depth(
    image: &BcImage,
    index: usize,
    arch: &mut [u64; ARCH],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
    abs_call: &mut HostCall<'_>,
    depth: u32,
    enforce_crc: bool,
    nested: bool,
) -> Result<()> {
    if depth > 32 {
        return Err(msg("vm call depth exceeded"));
    }
    let func = image
        .funcs
        .get(index)
        .ok_or_else(|| msg("missing vm function"))?;
    if enforce_crc {
        verify_checks(func, &image.inv)?;
    }
    let mut regs = vec![0u64; SLOT_COUNT];
    scatter_arch(&mut regs, arch, &image.slots);
    let _reg_wipe = crate::secret::RegWipe;
    let mut weave = Running::start(func)?;
    let mut ip = func.entry;
    let mut ctx = ExecCtx {
        flags,
        mem,
        abs_call,
        image_base,
        depth,
        enforce_crc,
        nested,
        stack: Vec::new(),
        gate: 0,
    };
    for _ in 0..2_000_000 {
        if exec_insn(image, func, &mut weave, &mut regs, &mut ip, &mut ctx)? {
            gather_arch(arch, &regs, &image.slots)?;
            return Ok(());
        }
    }
    Err(msg(format!("vm step limit in {}", func.name)))
}

fn verify_checks(func: &BcFunc, inv: &[u8; 256]) -> Result<()> {
    let mut weave = Running::start(func)?;
    let mut crc = 0xffff_ffffu32;
    let mut checks = Vec::new();
    for index in 0..func.insns.len() {
        let plain = weave.open(func, inv, index)?;
        crc = super::fold_insn_crc(crc, &plain);
        if plain.first() == Some(&0x60) {
            checks.push(u32::from_le_bytes(exact_bytes(
                plain.get(1..5).ok_or_else(|| msg("truncated check"))?,
            )?));
        }
    }
    // The closing key covers every sealed block, including ones execution can skip.
    weave.finish(func, inv)?;
    let expect = !crc;
    if checks.iter().any(|got| *got != expect) {
        return Err(crate::error::Error::Integrity);
    }
    Ok(())
}

fn ensure_regs(op: &Bc, len: usize) -> Result<()> {
    for index in bc_indexes(op) {
        if index as usize >= len {
            return Err(msg("register index out of range"));
        }
    }
    Ok(())
}

fn bc_indexes(op: &Bc) -> Vec<u8> {
    let mut out = Vec::new();
    if !pair_indexes(op, &mut out) {
        single_index(op, &mut out);
    }
    out
}

fn pair_indexes(op: &Bc, out: &mut Vec<u8>) -> bool {
    let Some((d, s)) = pair_regs(op) else {
        return false;
    };
    out.push(d);
    out.push(s);
    true
}

fn pair_regs(op: &Bc) -> Option<(u8, u8)> {
    match *op {
        Bc::MovRr(d, s)
        | Bc::Load8(d, s)
        | Bc::Store8(d, s)
        | Bc::Load64(d, s)
        | Bc::Store64(d, s)
        | Bc::AluRr(_, d, s)
        | Bc::CmpRr(d, s)
        | Bc::TestRr(d, s)
        | Bc::ImulRr(d, s) => Some((d, s)),
        _ => None,
    }
}

fn single_index(op: &Bc, out: &mut Vec<u8>) {
    let mut add = |index: u8| out.push(index);
    match *op {
        Bc::MovRi(d, _)
        | Bc::AluRi(_, d, _)
        | Bc::CmpRi(d, _)
        | Bc::TestRi(d, _)
        | Bc::Unary(_, d)
        | Bc::Shift(_, d, _)
        | Bc::ImulRi(d, _)
        | Bc::Div(d)
        | Bc::Push(d)
        | Bc::Pop(d)
        | Bc::StFlags(d)
        | Bc::LdFlags(d)
        | Bc::CallReg(d)
        | Bc::LeaRva(d, _)
        | Bc::PushR(d)
        | Bc::PopR(d) => add(d),
        Bc::LeaSib {
            dst, base, index, ..
        } => sib_indexes(out, dst, base, index),
        Bc::MovRr(..)
        | Bc::Load8(..)
        | Bc::Store8(..)
        | Bc::Load64(..)
        | Bc::Store64(..)
        | Bc::AluRr(..)
        | Bc::CmpRr(..)
        | Bc::TestRr(..)
        | Bc::ImulRr(..)
        | Bc::Jmp(_)
        | Bc::Jcc(..)
        | Bc::CallRva(_)
        | Bc::Ret
        | Bc::Check(_)
        | Bc::Junk
        | Bc::Nest(_)
        | Bc::PushI(_)
        | Bc::StackAlu(_)
        | Bc::StackUnary(_)
        | Bc::StackCmp(_)
        | Bc::StackShift(..)
        | Bc::StackImul => {}
    }
}

fn sib_indexes(out: &mut Vec<u8>, dst: u8, base: u8, index: u8) {
    out.push(dst);
    if base != 0xff {
        out.push(base);
    }
    if index != 0xff {
        out.push(index);
    }
}

fn note_probe(op: &Bc, weave: &mut Running, mem: &mut dyn MemIo) -> Result<()> {
    if !matches!(op, Bc::Check(_)) || !crate::antidebug::probe_tripped(mem) {
        return Ok(());
    }
    let mut key = weave.key.bytes();
    key[0] ^= crate::antidebug::KEY_POISON;
    weave.key.store(&key);
    crate::secret::wipe(&mut key);
    Err(crate::error::Error::Debugger)
}

fn scatter_arch(regs: &mut [u64], arch: &[u64; ARCH], slots: &SlotMap) {
    for index in 0..ARCH {
        regs[slots.arch(index) as usize] = arch[index];
    }
}

fn gather_arch(arch: &mut [u64; ARCH], regs: &[u64], slots: &SlotMap) -> Result<()> {
    for (index, cell) in arch.iter_mut().enumerate() {
        let slot = slots.arch(index) as usize;
        *cell = regs
            .get(slot)
            .copied()
            .ok_or_else(|| msg("register index out of range"))?;
    }
    Ok(())
}

pub(super) fn exec_bc(
    op: &Bc,
    regs: &mut [u64],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
    slots: &SlotMap,
) -> Result<()> {
    ensure_regs(op, regs.len())?;
    match *op {
        Bc::MovRr(d, s) => assign(regs, d as usize, bc_reg(regs, s)?),
        Bc::MovRi(d, imm) => {
            let _pad = bc_reg(regs, d)?;
            assign(regs, d as usize, imm);
        }
        Bc::Load8(d, a) => load_width(regs, mem, d, a, 1)?,
        Bc::Store8(a, s) => store_width(regs, mem, a, s, 1)?,
        Bc::Load64(d, a) => load_width(regs, mem, d, a, 8)?,
        Bc::Store64(a, s) => store_width(regs, mem, a, s, 8)?,
        Bc::LeaSib {
            dst,
            base,
            index,
            scale,
            disp,
        } => assign(
            regs,
            usize::from(dst),
            lea_sib(regs, base, index, scale, disp)?,
        ),
        Bc::LeaRva(d, rva) => {
            assign(
                regs,
                usize::from(d),
                image_base.wrapping_add(u64::from(rva)),
            );
        }
        Bc::AluRr(kind, d, s) => {
            bc_store(
                regs,
                flags,
                d,
                alu_rr(kind, bc_reg(regs, d)?, bc_reg(regs, s)?)?,
            );
        }
        Bc::AluRi(kind, d, imm) => bc_store(regs, flags, d, alu_ri(kind, bc_reg(regs, d)?, imm)?),
        Bc::CmpRr(..) | Bc::CmpRi(..) | Bc::TestRr(..) | Bc::TestRi(..) => {
            compare(op, regs, flags)?;
        }
        _ => return exec_bc_more(op, regs, flags, mem, image_base, slots),
    }
    Ok(())
}

fn exec_bc_more(
    op: &Bc,
    regs: &mut [u64],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
    slots: &SlotMap,
) -> Result<()> {
    if exec_bc_arith(op, regs, flags)? {
        return Ok(());
    }
    exec_bc_rest(op, regs, flags, mem, image_base, slots)
}

fn exec_bc_arith(op: &Bc, regs: &mut [u64], flags: &mut Flags) -> Result<bool> {
    match op {
        Bc::Unary(kind, d) => bc_unary(regs, flags, *kind, *d)?,
        Bc::Shift(kind, d, count) => {
            let old = super::balance::read_flags(flags);
            bc_store(
                regs,
                flags,
                *d,
                shift(*kind, bc_reg(regs, *d)?, *count, old)?,
            );
        }
        Bc::ImulRr(d, s) => {
            bc_store(
                regs,
                flags,
                *d,
                flags::imul(bc_reg(regs, *d)?, bc_reg(regs, *s)?),
            );
        }
        Bc::ImulRi(d, imm) => {
            let left = bc_reg(regs, *d)?;
            let _pad = bc_reg(regs, *d)?;
            bc_store(regs, flags, *d, flags::imul(left, i64::from(*imm) as u64));
        }
        Bc::StFlags(d) => assign(
            regs,
            usize::from(*d),
            super::balance::read_flags(flags).pack(),
        ),
        Bc::LdFlags(s) => {
            super::balance::write_flags(flags, Flags::unpack(bc_reg(regs, *s)?));
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn exec_bc_rest(
    op: &Bc,
    regs: &mut [u64],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
    slots: &SlotMap,
) -> Result<()> {
    match op {
        Bc::Div(s) => bc_div(regs, *s, slots)?,
        Bc::Push(s) => bc_push(regs, mem, *s, slots)?,
        Bc::Pop(d) => bc_pop(regs, mem, *d, slots)?,
        Bc::Nest(body) => exec_nest(body, regs, flags, mem, image_base, slots)?,
        Bc::Check(_) | Bc::Junk | Bc::Jmp(_) | Bc::Jcc(..) => {}
        Bc::CallRva(_) | Bc::CallReg(_) | Bc::Ret => {}
        _ => return Err(msg("bytecode op was already dispatched")),
    }
    Ok(())
}

fn compare(op: &Bc, regs: &mut [u64], flags: &mut Flags) -> Result<()> {
    let next = match *op {
        Bc::CmpRr(d, s) => flags::sub(bc_reg(regs, d)?, bc_reg(regs, s)?, 64).1,
        Bc::CmpRi(d, imm) => flags::sub(bc_reg(regs, d)?, imm as i64 as u64, 64).1,
        Bc::TestRr(d, s) => flags::logic_and(bc_reg(regs, d)?, bc_reg(regs, s)?, 64).1,
        Bc::TestRi(d, imm) => flags::logic_and(bc_reg(regs, d)?, imm as i64 as u64, 64).1,
        _ => return Err(msg("bytecode op was already dispatched")),
    };
    super::balance::write_flags(flags, next);
    Ok(())
}

fn load_width(
    regs: &mut [u64],
    mem: &mut dyn MemIo,
    dst: u8,
    addr: u8,
    width: usize,
) -> Result<()> {
    let value = bc_read(mem, bc_reg(regs, addr)?, width)?;
    assign(regs, usize::from(dst), value);
    Ok(())
}

fn store_width(regs: &[u64], mem: &mut dyn MemIo, addr: u8, src: u8, width: usize) -> Result<()> {
    let bytes = bc_reg(regs, src)?.to_le_bytes();
    let data = if width == 1 { &bytes[..1] } else { &bytes[..] };
    guest_store(mem, bc_reg(regs, addr)?, data)
}

fn bc_reg(regs: &[u64], index: u8) -> Result<u64> {
    let value = regs
        .get(usize::from(index))
        .copied()
        .ok_or_else(|| msg("register index out of range"))?;
    super::balance::note_load();
    Ok(value)
}

fn assign(regs: &mut [u64], index: usize, value: u64) {
    super::balance::note_store();
    regs[index] = value;
}

fn bc_store(regs: &mut [u64], flags: &mut Flags, dst: u8, computed: (u64, Flags)) {
    assign(regs, usize::from(dst), computed.0);
    super::balance::write_flags(flags, computed.1);
}

fn guest_store(mem: &mut dyn MemIo, addr: u64, data: &[u8]) -> Result<()> {
    super::guard::admit_guest(addr, data.len())?;
    mem.write(addr, data)?;
    super::balance::note_store();
    Ok(())
}

fn bc_read(mem: &mut dyn MemIo, addr: u64, width: usize) -> Result<u64> {
    super::guard::admit_guest(addr, width)?;
    let buf = mem.read(addr, width)?;
    super::balance::note_load();
    if width == 1 {
        return Ok(u64::from(*buf.first().ok_or_else(|| msg("short read"))?));
    }
    Ok(u64::from_le_bytes(exact_bytes(buf.as_slice())?))
}

fn lea_sib(regs: &[u64], base: u8, index: u8, scale: u8, disp: i32) -> Result<u64> {
    let mut acc = i64::from(disp);
    acc = acc.wrapping_add(sib_term(regs, base, 1)?);
    acc = acc.wrapping_add(sib_term(regs, index, scale)?);
    Ok(acc as u64)
}

fn sib_term(regs: &[u64], slot: u8, scale: u8) -> Result<i64> {
    if slot == 0xff {
        let _pad = bc_reg(regs, 0)?;
        return Ok(0);
    }
    let value = bc_reg(regs, slot)? as i64;
    Ok(value.wrapping_mul(i64::from(scale)))
}

fn bc_unary(regs: &mut [u64], flags: &mut Flags, kind: u8, dst: u8) -> Result<()> {
    let value = bc_reg(regs, dst)?;
    let old = super::balance::read_flags(flags);
    let (bits, next) = unary_bits(kind, value, old)?;
    assign(regs, usize::from(dst), bits);
    super::balance::write_flags(flags, next);
    Ok(())
}

fn unary_bits(kind: u8, value: u64, old: Flags) -> Result<(u64, Flags)> {
    Ok(match kind {
        0 => (!value, old),
        1 => flags::neg(value, 64),
        2 => flags::inc(value, 64, old),
        3 => flags::dec(value, 64, old),
        _ => return Err(msg("unknown unary bytecode")),
    })
}

fn arch_at(regs: &[u64], slots: &SlotMap, arch: usize) -> Result<usize> {
    let index = slots.arch(arch) as usize;
    if index >= regs.len() {
        return Err(msg("register index out of range"));
    }
    Ok(index)
}

fn bc_div(regs: &mut [u64], src: u8, slots: &SlotMap) -> Result<()> {
    let divisor = bc_reg(regs, src)?;
    if divisor == 0 {
        return Err(msg("division by zero"));
    }
    let rax = arch_at(regs, slots, 0)?;
    let rdx = arch_at(regs, slots, 2)?;
    let dividend = (u128::from(regs[rdx]) << 64) | u128::from(regs[rax]);
    let quot = dividend / u128::from(divisor);
    if quot > u128::from(u64::MAX) {
        return Err(msg("division overflow"));
    }
    regs[rax] = quot as u64;
    regs[rdx] = (dividend % u128::from(divisor)) as u64;
    Ok(())
}

fn bc_push(regs: &mut [u64], mem: &mut dyn MemIo, src: u8, slots: &SlotMap) -> Result<()> {
    let sp_at = arch_at(regs, slots, 4)?;
    let sp = regs[sp_at].wrapping_sub(8);
    regs[sp_at] = sp;
    guest_store(mem, sp, &bc_reg(regs, src)?.to_le_bytes())
}

fn bc_pop(regs: &mut [u64], mem: &mut dyn MemIo, dst: u8, slots: &SlotMap) -> Result<()> {
    let sp_at = arch_at(regs, slots, 4)?;
    let sp = regs[sp_at];
    super::guard::admit_guest(sp, 8)?;
    let buf = mem.read(sp, 8)?;
    regs[dst as usize] = u64::from_le_bytes(exact_bytes(buf.as_slice())?);
    regs[sp_at] = sp.wrapping_add(8);
    Ok(())
}

thread_local! {
    static OPEN_NOW: Cell<usize> = const { Cell::new(0) };
    static OPEN_MAX: Cell<usize> = const { Cell::new(0) };
}

fn enter_plain() {
    OPEN_NOW.with(|cell| {
        let live = cell.get().saturating_add(1);
        cell.set(live);
        OPEN_MAX.with(|max| max.set(max.get().max(live)));
    });
}

fn leave_plain() {
    OPEN_NOW.with(|cell| cell.set(cell.get().saturating_sub(1)));
}

struct Resident;

impl Resident {
    fn enter() -> Self {
        enter_plain();
        Self
    }
}

impl Drop for Resident {
    fn drop(&mut self) {
        leave_plain();
    }
}

#[cfg(test)]
thread_local! {
    static RUNNING_ADDRS: std::cell::RefCell<Vec<usize>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn publish_running(addr: usize) {
    #[cfg(test)]
    RUNNING_ADDRS.with(|cell| cell.borrow_mut().push(addr));
    #[cfg(not(test))]
    let _ = addr;
}

fn clear_running(addr: usize) {
    #[cfg(test)]
    RUNNING_ADDRS.with(|cell| {
        let mut stack = cell.borrow_mut();
        if stack.last() == Some(&addr) {
            stack.pop();
        }
    });
    #[cfg(not(test))]
    let _ = addr;
}

#[cfg(test)]
pub(crate) fn running_key_addr() -> usize {
    RUNNING_ADDRS.with(|cell| cell.borrow().last().copied().unwrap_or(0))
}

#[cfg(test)]
pub(crate) fn reset_open_window() {
    OPEN_NOW.with(|cell| cell.set(0));
    OPEN_MAX.with(|cell| cell.set(0));
}

#[cfg(test)]
pub(crate) fn open_high_water() -> usize {
    OPEN_MAX.with(|cell| cell.get())
}

#[cfg(test)]
pub(crate) fn probe_store64(
    regs: &mut [u64],
    mem: &mut dyn MemIo,
    addr: u8,
    src: u8,
) -> Result<()> {
    let mut flags = Flags::default();
    exec_bc(
        &Bc::Store64(addr, src),
        regs,
        &mut flags,
        mem,
        0,
        &SlotMap::identity(),
    )
}

#[cfg(test)]
thread_local! {
    static NEST_FRAME_BUFFERS: Cell<usize> = const { Cell::new(0) };
}

fn exec_nest(
    body: &[u8],
    regs: &mut [u64],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
    slots: &SlotMap,
) -> Result<()> {
    let saved = *flags;
    #[cfg(test)]
    NEST_FRAME_BUFFERS.with(|count| count.set(count.get() + 1));
    let mut plain = Vec::with_capacity(body.len());
    plain.extend(body.iter().map(|byte| byte ^ NEST_XOR));
    let mut cursor = 0;
    while cursor < plain.len() {
        let (op, used) = decode_span(&plain[cursor..])?;
        // Reader rejects a span past the slice. An empty span would not move the cursor.
        debug_assert!(used > 0, "decode_span returned an empty window");
        exec_bc(&op, regs, flags, mem, image_base, slots)?;
        cursor += used;
    }
    *flags = saved;
    Ok(())
}

fn alu_rr(kind: u8, a: u64, b: u64) -> Result<(u64, Flags)> {
    Ok(match kind {
        0 => flags::add(a, b, 64),
        1 => flags::sub(a, b, 64),
        2 => flags::logic_xor(a, b, 64),
        3 => flags::logic_and(a, b, 64),
        4 => flags::logic_or(a, b, 64),
        _ => return Err(msg("unknown alu bytecode")),
    })
}

fn alu_ri(kind: u8, a: u64, imm: i32) -> Result<(u64, Flags)> {
    alu_rr(kind, a, imm as i64 as u64)
}

fn shift(kind: u8, a: u64, count: u8, old: Flags) -> Result<(u64, Flags)> {
    let count = u32::from(count);
    Ok(match kind {
        0 => flags::shift_left(a, count, 64, old),
        1 => flags::shift_right(a, count, 64, old),
        2 => flags::shift_arith(a, count, 64, old),
        3 => flags::rotate_left(a, count, 64, old),
        4 => flags::rotate_right(a, count, 64, old),
        _ => return Err(msg("unknown shift bytecode")),
    })
}

#[cfg(test)]
mod tests {
    use super::super::encode_plain;
    use super::{decode_span, exec_nest, Bc, NEST_FRAME_BUFFERS, NEST_XOR};
    use crate::flags::Flags;
    use crate::ir::MapMem;

    fn xor_insn(op: &Bc) -> Vec<u8> {
        encode_plain(op)
            .expect("encode")
            .into_iter()
            .map(|byte| byte ^ NEST_XOR)
            .collect()
    }

    #[test]
    fn nest_uses_one_frame_buffer_and_the_span_decode_read() {
        let first = Bc::MovRi(0, 0x1111);
        let second = Bc::MovRi(1, 0x2222);
        let first_window = xor_insn(&first);
        let first_len = first_window.len();
        let mut body = first_window;
        body.extend(xor_insn(&second));
        let plain: Vec<u8> = body.iter().map(|byte| byte ^ NEST_XOR).collect();
        let (op, used) = decode_span(&plain).expect("span");
        assert_eq!(op, first);
        assert_eq!(used, first_len);

        NEST_FRAME_BUFFERS.with(|count| count.set(0));
        let mut regs = [0u64; 16];
        let mut flags = Flags {
            cf: true,
            ..Flags::default()
        };
        let mut mem = MapMem::default();
        exec_nest(
            &body,
            &mut regs,
            &mut flags,
            &mut mem,
            0,
            &super::SlotMap::identity(),
        )
        .expect("nest");
        assert_eq!(regs[0], 0x1111);
        assert_eq!(regs[1], 0x2222);
        assert!(flags.cf);
        assert_eq!(NEST_FRAME_BUFFERS.with(|count| count.get()), 1);
    }

    fn ret_image(imm: u64) -> super::BcImage {
        use crate::ir::{Block, Exit, FuncIr, Op};
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        let func = FuncIr {
            name: "ret".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![Op::MovRi(0, imm)],
                exit: Exit::Ret,
                opaque: false,
            }],
        };
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        super::super::lower_image(std::slice::from_ref(&func), &mut rng).unwrap()
    }

    fn run_rax(image: &super::BcImage) -> crate::Result<u64> {
        let mut arch = [0u64; 16];
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut host =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        super::exec_image(image, 0, &mut arch, &mut flags, &mut mem, 0, &mut host)?;
        Ok(arch[0])
    }

    #[test]
    fn two_open_blocks_raise_the_high_water() {
        let image = ret_image(1);
        let func = &image.funcs[0];
        super::reset_open_window();
        let mut first = super::Running::start(func).unwrap();
        let mut second = super::Running::start(func).unwrap();
        let index = func.entry as usize;
        let _kept = first.open(func, &image.inv, index).unwrap();
        let _also = second.open(func, &image.inv, index).unwrap();
        assert!(
            super::open_high_water() >= 2,
            "high water {}",
            super::open_high_water()
        );
    }

    #[test]
    fn exec_pins_the_interpreter_key_on_a_nondumpable_page() {
        let image = abs_image();
        let boot = image.funcs[0].key.addr();
        let boot_key = image.funcs[0].key.bytes();
        assert!(crate::secret::page_is_dont_dump(boot), "image key page");
        assert!(
            crate::secret::child_page_is_zero(boot),
            "fork copied the image key"
        );
        let arch = run_abs(&image, boot);
        assert_eq!(arch, 9);
        assert_eq!(image.funcs[0].key.bytes(), boot_key);
    }

    fn abs_image() -> super::BcImage {
        use crate::ir::{Block, Exit, FuncIr, Op};
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        let func = FuncIr {
            name: "abs".into(),
            rva: 0x1400,
            entry: 0,
            blocks: vec![
                Block {
                    ops: vec![Op::MovRi(1, 0x2222)],
                    exit: Exit::CallAbs { reg: 1, next: 1 },
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRi(0, 9)],
                    exit: Exit::Ret,
                    opaque: false,
                },
            ],
        };
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        super::super::lower_image(std::slice::from_ref(&func), &mut rng).unwrap()
    }

    fn run_abs(image: &super::BcImage, boot: usize) -> u64 {
        let mut arch = [0u64; 16];
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut host =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, target: u64| {
                assert_eq!(target, 0x2222);
                let live = super::running_key_addr();
                assert_ne!(live, 0);
                assert_ne!(live, boot);
                assert!(crate::secret::page_is_dont_dump(live), "running key page");
                assert!(
                    crate::secret::child_page_is_zero(live),
                    "fork copied the running key"
                );
                assert!(
                    crate::secret::child_page_is_zero(boot),
                    "fork copied the image key during exec"
                );
                Ok(())
            };
        super::exec_image(image, 0, &mut arch, &mut flags, &mut mem, 0, &mut host).unwrap();
        arch[0]
    }

    #[test]
    fn a_failed_run_does_not_stick_to_the_next_call() {
        let image = ret_image(3);
        assert_eq!(run_rax(&image).unwrap(), 3);
        let mut bad = image.clone();
        bad.funcs[0].insns[0].bytes[0] ^= 1;
        assert!(run_rax(&bad).is_err());
        assert_eq!(run_rax(&image).unwrap(), 3);
    }
}
