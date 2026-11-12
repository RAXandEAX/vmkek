use crate::error::{exact_bytes, msg, Result};
use crate::flags::{self, Flags};

pub const ARCH: usize = 16;
pub const V_STATE: u16 = 16;
pub const V_FLAGS: u16 = 17;
pub const V_TMP0: u16 = 18;
pub const V_TMP1: u16 = 19;
pub const V_TMP2: u16 = 20;
pub const V_OPA0: u16 = 21;
pub const V_OPA1: u16 = 22;
pub const V_DEAD: u16 = 23;
/// Auxiliary carry as 0 or 1 in bit 0. `lahf` and `pushfq` read this register.
pub const AF: u16 = 30;
pub const V_LIMIT: usize = 32;

pub const RAX: u16 = 0;
pub const RCX: u16 = 1;
pub const RDX: u16 = 2;
pub const RBX: u16 = 3;
pub const RSP: u16 = 4;
pub const RBP: u16 = 5;
pub const RSI: u16 = 6;
pub const RDI: u16 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address {
    Sib {
        base: Option<u16>,
        index: Option<u16>,
        scale: u8,
        disp: i64,
    },
    Rva(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    MovRr(u16, u16),
    MovRi(u16, u64),
    Load8(u16, u16),
    Store8(u16, u16),
    Load64(u16, u16),
    Store64(u16, u16),
    Lea(u16, Address),
    AddRr(u16, u16),
    SubRr(u16, u16),
    XorRr(u16, u16),
    AndRr(u16, u16),
    OrRr(u16, u16),
    AddRi(u16, i32),
    SubRi(u16, i32),
    XorRi(u16, i32),
    AndRi(u16, i32),
    OrRi(u16, i32),
    CmpRr(u16, u16),
    CmpRi(u16, i32),
    TestRr(u16, u16),
    TestRi(u16, i32),
    Not(u16),
    Neg(u16),
    Inc(u16),
    Dec(u16),
    Shl(u16, u8),
    Shr(u16, u8),
    Sar(u16, u8),
    Rol(u16, u8),
    Ror(u16, u8),
    ImulRr(u16, u16),
    ImulRi(u16, i32),
    Div(u16),
    Push(u16),
    Pop(u16),
    StFlags(u16),
    LdFlags(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Jmp(u32),
    Jcc(u8, u32, u32),
    CallRva { rva: u32, next: u32 },
    CallAbs { reg: u16, next: u32 },
    Ret,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub ops: Vec<Op>,
    pub exit: Exit,
    /// Opaque-predicate block. Flattening must leave its branch alone:
    /// the predicate uses the CPU flags, while `V_FLAGS` already holds the
    /// program flags the real block will reload.
    pub opaque: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuncIr {
    pub name: String,
    pub rva: u32,
    pub blocks: Vec<Block>,
    pub entry: u32,
}

#[cfg(not(kani))]
impl FuncIr {
    pub(crate) fn wipe(&mut self) {
        // SAFETY: the wipe leaves the string empty and therefore valid UTF-8.
        crate::secret::wipe_copy_vec(unsafe { self.name.as_mut_vec() });
        overwrite(&mut self.rva, 0);
        overwrite(&mut self.entry, 0);
        for block in &mut self.blocks {
            crate::secret::wipe_copy_vec(&mut block.ops);
            overwrite(&mut block.opaque, false);
            block.exit.wipe();
        }
    }
}

#[cfg(not(kani))]
impl Exit {
    fn wipe(&mut self) {
        match self {
            Self::Jmp(target) => overwrite(target, 0),
            Self::Jcc(cond, taken, fallthrough) => {
                overwrite(cond, 0);
                overwrite(taken, 0);
                overwrite(fallthrough, 0);
            }
            Self::CallRva { rva, next } => {
                overwrite(rva, 0);
                overwrite(next, 0);
            }
            Self::CallAbs { reg, next } => {
                overwrite(reg, 0);
                overwrite(next, 0);
            }
            Self::Ret => {}
        }
    }
}

#[cfg(not(kani))]
fn overwrite<T: Copy>(field: &mut T, value: T) {
    // SAFETY: the reference is exclusive and value is valid for its field.
    unsafe { std::ptr::write_volatile(field, value) };
}

/// No address register on an [`X87Insn`]. The operation does not touch memory.
pub const X87_NO_ADDR: u16 = u16::MAX;

/// x87 stack in the IR.
///
/// Eight logical registers `ST(0)`…`ST(7)`, each stored as the raw 10-byte
/// extended-real (significand, then the biased exponent). `ST(i)` is `st[i]`.
/// The stack top lives in [`X87::sw`] bits 11..13 and selects the physical
/// register: physical(`ST(i)`) = (`top` + i) mod 8. The tag word is in that
/// physical order, two bits each: 00 valid, 01 zero, 10 special, 11 empty.
/// A push into a non-empty slot is stack overflow; a read or pop of an empty
/// slot is stack underflow. Both raise the invalid-operation and stack-fault
/// bits. When invalid is masked, overflow still pushes the indefinite QNaN
/// and underflow still adjusts the top; `C1` is set for overflow and clear
/// for underflow.
///
/// Precision (control bits 8..9) and rounding (bits 10..11) come from the
/// control word. Results are the 80-bit values the x87 unit produces for that
/// word, not Rust `f64` rounding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X87 {
    pub st: [[u8; 10]; 8],
    pub cw: u16,
    pub sw: u16,
    pub tw: u16,
    pub fip: u64,
    pub fdp: u64,
    pub fop: u16,
}

impl Default for X87 {
    fn default() -> Self {
        // `FNINIT`: masked exceptions, 64-bit precision, round to nearest, empty stack.
        Self {
            st: [[0; 10]; 8],
            cw: 0x037f,
            sw: 0,
            tw: 0xffff,
            fip: 0,
            fdp: 0,
            fop: 0,
        }
    }
}

impl X87 {
    #[must_use]
    pub fn top(self) -> u8 {
        ((self.sw >> 11) & 7) as u8
    }
}

/// One x87 instruction lowered into the IR.
///
/// `bytes` is the original encoding. Execution rewrites a memory operand to
/// `[r15]` and computes the effective address with the emulator's formula,
/// including a 32-bit address size and the GS base. `addr` is [`X87_NO_ADDR`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X87Insn {
    pub bytes: [u8; 15],
    pub len: u8,
    pub addr: u16,
    pub ip: u64,
}

/// SSE through AVX-512 state in the IR.
///
/// [`Sse::xmm`] is ZMM bits [127:0] and [`Sse::upper`] is bits [255:128] of
/// ZMM0–ZMM15. [`Sse::zmm_hi256`] is bits [511:256] of those registers.
/// [`Sse::zmm_hi16`] is ZMM16–ZMM31, 64 bytes each. [`Sse::opmask`] is k0–k7.
/// MXCSR selects rounding and exception masks. Sticky flags are the low six
/// bits of MXCSR. An unmasked exception is a fault rather than a Rust
/// `f32`/`f64` rounding of the lane.
///
/// A legacy SSE write of XMM `i` leaves `upper[i]` and `zmm_hi256[i]`
/// unchanged. A VEX write of XMM `i` zeroes `upper[i]` and `zmm_hi256[i]`.
/// A VEX write of YMM `i` replaces both 128-bit halves and zeroes
/// `zmm_hi256[i]`. An EVEX write replaces the bytes the mask selects:
/// merge-masking (`{k}`) keeps the old element where the mask bit is clear,
/// and zeroing-masking (`{k}{z}`) stores zeros there. `VZEROUPPER` clears
/// every YMM upper lane and every `zmm_hi256` lane. `VZEROALL` clears the
/// XMM halves as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sse {
    pub xmm: [[u8; 16]; 16],
    /// Bits [255:128] of ZMM0–ZMM15.
    pub upper: [[u8; 16]; 16],
    /// Bits [511:256] of ZMM0–ZMM15.
    pub zmm_hi256: [[u8; 32]; 16],
    /// ZMM16–ZMM31.
    pub zmm_hi16: [[u8; 64]; 16],
    /// k0–k7. Narrow mask ops use the low bits.
    pub opmask: [u64; 8],
    pub mxcsr: u32,
}

impl Default for Sse {
    fn default() -> Self {
        // Power-up / `INIT`: ZMM and k cleared, exceptions masked, round to nearest.
        Self {
            xmm: [[0; 16]; 16],
            upper: [[0; 16]; 16],
            zmm_hi256: [[0; 32]; 16],
            zmm_hi16: [[0; 64]; 16],
            opmask: [0; 8],
            mxcsr: 0x1f80,
        }
    }
}

/// One SSE or SSE2 instruction lowered into the IR.
///
/// `bytes` is the original encoding. Execution rewrites an explicit memory
/// operand and computes the effective address with the emulator's formula,
/// including a 32-bit address size and the GS base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SseInsn {
    pub bytes: [u8; 15],
    pub len: u8,
    pub ip: u64,
}

/// One step of a program that may mix integer ops with x87 and SSE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Gp(Op),
    X87(X87Insn),
    Sse(SseInsn),
}

/// A block in [`Program`]. Integer-only programs lower to [`FuncIr`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XBlock {
    pub ops: Vec<Step>,
    pub exit: Exit,
    pub opaque: bool,
}

/// Lifted function. x87 and SSE are not GPRs: [`exec_program`] threads an [`X87`] and an [`Sse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub name: String,
    pub rva: u32,
    pub blocks: Vec<XBlock>,
    pub entry: u32,
}

impl Program {
    /// Lower to the integer IR.
    ///
    /// An x87 or SSE step has no integer opcode. That is [`crate::error::Error::Unsupported`]
    /// at this function's RVA.
    pub fn into_integer(self) -> Result<FuncIr> {
        let mut blocks = Vec::with_capacity(self.blocks.len());
        for block in self.blocks {
            let mut ops = Vec::with_capacity(block.ops.len());
            for step in block.ops {
                match step {
                    Step::Gp(op) => ops.push(op),
                    Step::X87(_) => {
                        return Err(crate::error::Error::Unsupported {
                            rva: u64::from(self.rva),
                            text: "x87 instruction is outside the integer ir".to_string(),
                        });
                    }
                    Step::Sse(_) => {
                        return Err(crate::error::Error::Unsupported {
                            rva: u64::from(self.rva),
                            text: "sse instruction is outside the integer ir".to_string(),
                        });
                    }
                }
            }
            blocks.push(Block {
                ops,
                exit: block.exit,
                opaque: block.opaque,
            });
        }
        Ok(FuncIr {
            name: self.name,
            rva: self.rva,
            blocks,
            entry: self.entry,
        })
    }
}

pub trait MemIo {
    fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>>;
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()>;
}

#[derive(Default)]
pub struct MapMem {
    pub bytes: std::collections::BTreeMap<u64, u8>,
}

impl MemIo for MapMem {
    fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self
                .bytes
                .get(&(addr.wrapping_add(i as u64)))
                .copied()
                .unwrap_or(0);
        }
        Ok(out)
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        for (i, byte) in data.iter().enumerate() {
            self.bytes.insert(addr.wrapping_add(i as u64), *byte);
        }
        Ok(())
    }
}

pub type HostCall<'a> =
    dyn FnMut(&mut [u64; ARCH], &mut Flags, &mut dyn MemIo, u64) -> Result<()> + 'a;

pub fn exec_func(
    funcs: &[FuncIr],
    index: usize,
    arch: &mut [u64; ARCH],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
    abs_call: &mut HostCall<'_>,
) -> Result<()> {
    exec_depth(funcs, index, arch, flags, mem, image_base, abs_call, 0)
}

// Depth travels with the interpreter context so a recursive call can be refused.
#[allow(clippy::too_many_arguments)]
fn exec_depth(
    funcs: &[FuncIr],
    index: usize,
    arch: &mut [u64; ARCH],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
    abs_call: &mut HostCall<'_>,
    depth: u32,
) -> Result<()> {
    if depth > 32 {
        return Err(msg("ir call depth exceeded"));
    }
    let func = funcs.get(index).ok_or_else(|| msg("missing ir function"))?;
    let mut regs = vec![0u64; V_LIMIT];
    regs[..ARCH].copy_from_slice(arch);
    let mut ip = func.entry;
    for _ in 0..200_000 {
        let block = func
            .blocks
            .get(ip as usize)
            .ok_or_else(|| msg("bad ir block"))?;
        exec_integer_block(&block.ops, &mut regs, flags, mem, image_base)?;
        match block.exit {
            Exit::Jmp(next) => ip = next,
            Exit::Jcc(cond, yes, no) => {
                ip = if flags::cond_taken(cond, *flags) {
                    yes
                } else {
                    no
                };
            }
            Exit::Ret => {
                arch.copy_from_slice(&regs[..ARCH]);
                return Ok(());
            }
            Exit::CallRva { rva, next } => {
                let callee = funcs
                    .iter()
                    .position(|item| item.rva == rva)
                    .ok_or_else(|| msg(format!("call to unknown rva {rva:#x}")))?;
                let mut child = [0u64; ARCH];
                child.copy_from_slice(&regs[..ARCH]);
                exec_depth(
                    funcs,
                    callee,
                    &mut child,
                    flags,
                    mem,
                    image_base,
                    abs_call,
                    depth + 1,
                )?;
                regs[..ARCH].copy_from_slice(&child);
                ip = next;
            }
            Exit::CallAbs { reg, next } => {
                let target = *regs
                    .get(reg as usize)
                    .ok_or_else(|| msg("register index out of range"))?;
                let mut child = [0u64; ARCH];
                child.copy_from_slice(&regs[..ARCH]);
                abs_call(&mut child, flags, mem, target)?;
                regs[..ARCH].copy_from_slice(&child);
                ip = next;
            }
        }
    }
    Err(msg(format!("ir step limit in {}", func.name)))
}

/// Run a program that may contain x87 and SSE steps. General registers and flags
/// move the same way as [`exec_func`]. `af` is the auxiliary carry (IR register 30)
/// and `df` is the direction flag (IR register 31). The x87 stack is `x87` and the
/// XMM file is `sse`. `gs` is the base added by a memory operand with a GS override.
#[allow(
    clippy::too_many_arguments,
    reason = "GPR, flags, AF, DF, the x87 stack, the XMM file, GS, and memory are separate interpreter inputs"
)]
pub fn exec_program(
    funcs: &[Program],
    index: usize,
    arch: &mut [u64; ARCH],
    flags: &mut Flags,
    af: &mut bool,
    df: &mut bool,
    x87: &mut X87,
    sse: &mut Sse,
    gs: u64,
    mem: &mut dyn MemIo,
    image_base: u64,
    abs_call: &mut HostCall<'_>,
) -> Result<()> {
    exec_program_depth(
        funcs, index, arch, flags, af, df, x87, sse, gs, mem, image_base, abs_call, 0,
    )
}

struct ProgCtx<'a> {
    funcs: &'a [Program],
    arch: &'a mut [u64; ARCH],
    flags: &'a mut Flags,
    af: &'a mut bool,
    df: &'a mut bool,
    x87: &'a mut X87,
    sse: &'a mut Sse,
    gs: u64,
    mem: &'a mut dyn MemIo,
    image_base: u64,
    abs_call: &'a mut HostCall<'a>,
    depth: u32,
}

#[allow(
    clippy::too_many_arguments,
    reason = "recursion adds the depth limit to the state threaded by exec_program"
)]
fn exec_program_depth(
    funcs: &[Program],
    index: usize,
    arch: &mut [u64; ARCH],
    flags: &mut Flags,
    af: &mut bool,
    df: &mut bool,
    x87: &mut X87,
    sse: &mut Sse,
    gs: u64,
    mem: &mut dyn MemIo,
    image_base: u64,
    abs_call: &mut HostCall<'_>,
    depth: u32,
) -> Result<()> {
    let mut ctx = ProgCtx {
        funcs,
        arch,
        flags,
        af,
        df,
        x87,
        sse,
        gs,
        mem,
        image_base,
        abs_call,
        depth,
    };
    run_program(index, &mut ctx)
}

fn run_program(index: usize, ctx: &mut ProgCtx<'_>) -> Result<()> {
    if ctx.depth > 32 {
        return Err(msg("ir call depth exceeded"));
    }
    let func = ctx
        .funcs
        .get(index)
        .ok_or_else(|| msg("missing ir function"))?;
    let entry = func.entry;
    let mut regs = vec![0u64; V_LIMIT];
    regs[..ARCH].copy_from_slice(ctx.arch);
    write_aux(&mut regs, *ctx.af, *ctx.df);
    let mut ip = entry;
    for _ in 0..200_000 {
        if step_block(index, &mut ip, &mut regs, ctx)? {
            return Ok(());
        }
    }
    Err(msg(format!("ir step limit in {}", ctx.funcs[index].name)))
}

fn step_block(index: usize, ip: &mut u32, regs: &mut [u64], ctx: &mut ProgCtx<'_>) -> Result<bool> {
    let len = ctx
        .funcs
        .get(index)
        .and_then(|func| func.blocks.get(*ip as usize))
        .ok_or_else(|| msg("bad ir block"))?
        .ops
        .len();
    for slot in 0..len {
        let step = ctx.funcs[index].blocks[*ip as usize].ops[slot];
        exec_step(step, regs, ctx)?;
    }
    let exit = ctx.funcs[index].blocks[*ip as usize].exit;
    apply_exit(exit, ip, regs, ctx)
}

fn exec_step(step: Step, regs: &mut [u64], ctx: &mut ProgCtx<'_>) -> Result<()> {
    match step {
        Step::Gp(op) => exec_op(&op, regs, ctx.flags, ctx.mem, ctx.image_base),
        Step::X87(insn) => exec_x87(&insn, regs, ctx.flags, ctx.x87, ctx.mem, ctx.gs),
        Step::Sse(insn) => exec_sse(&insn, regs, ctx.flags, ctx.x87, ctx.sse, ctx.mem, ctx.gs),
    }
}

fn apply_exit(exit: Exit, ip: &mut u32, regs: &mut [u64], ctx: &mut ProgCtx<'_>) -> Result<bool> {
    match exit {
        Exit::Jmp(next) => *ip = next,
        Exit::Jcc(cond, yes, no) => {
            *ip = if flags::cond_taken(cond, *ctx.flags) {
                yes
            } else {
                no
            };
        }
        Exit::Ret => {
            finish_return(regs, ctx);
            return Ok(true);
        }
        Exit::CallRva { rva, next } => {
            call_rva(rva, regs, ctx)?;
            *ip = next;
        }
        Exit::CallAbs { reg, next } => {
            call_abs(regs, reg, ctx)?;
            *ip = next;
        }
    }
    Ok(false)
}

fn finish_return(regs: &[u64], ctx: &mut ProgCtx<'_>) {
    ctx.arch.copy_from_slice(&regs[..ARCH]);
    let (af, df) = read_aux(regs);
    *ctx.af = af;
    *ctx.df = df;
}

fn call_rva(rva: u32, regs: &mut [u64], ctx: &mut ProgCtx<'_>) -> Result<()> {
    let callee = ctx
        .funcs
        .iter()
        .position(|item| item.rva == rva)
        .ok_or_else(|| msg(format!("call to unknown rva {rva:#x}")))?;
    let mut child = [0u64; ARCH];
    child.copy_from_slice(&regs[..ARCH]);
    let (child_af, child_df) = read_aux(regs);
    let parent_arch = *ctx.arch;
    let parent_af = *ctx.af;
    let parent_df = *ctx.df;
    let parent_depth = ctx.depth;
    *ctx.arch = child;
    *ctx.af = child_af;
    *ctx.df = child_df;
    ctx.depth = parent_depth + 1;
    let result = run_program(callee, ctx);
    child = *ctx.arch;
    let returned_af = *ctx.af;
    let returned_df = *ctx.df;
    *ctx.arch = parent_arch;
    *ctx.af = parent_af;
    *ctx.df = parent_df;
    ctx.depth = parent_depth;
    result?;
    regs[..ARCH].copy_from_slice(&child);
    write_aux(regs, returned_af, returned_df);
    Ok(())
}

fn call_abs(regs: &mut [u64], reg: u16, ctx: &mut ProgCtx<'_>) -> Result<()> {
    let target = *regs
        .get(reg as usize)
        .ok_or_else(|| msg("register index out of range"))?;
    let mut child = [0u64; ARCH];
    child.copy_from_slice(&regs[..ARCH]);
    let ProgCtx {
        flags,
        mem,
        abs_call,
        ..
    } = ctx;
    abs_call(&mut child, flags, &mut **mem, target)?;
    regs[..ARCH].copy_from_slice(&child);
    Ok(())
}

fn write_aux(regs: &mut [u64], af: bool, df: bool) {
    if let Some(slot) = regs.get_mut(usize::from(AF)) {
        *slot = u64::from(af);
    }
    if let Some(slot) = regs.get_mut(31) {
        *slot = u64::from(df);
    }
}

fn read_aux(regs: &[u64]) -> (bool, bool) {
    let af = regs.get(usize::from(AF)).copied().unwrap_or(0) & 1 == 1;
    let df = regs.get(31).copied().unwrap_or(0) & 1 == 1;
    (af, df)
}

fn exec_x87(
    insn: &X87Insn,
    regs: &mut [u64],
    flags: &mut Flags,
    x87: &mut X87,
    mem: &mut dyn MemIo,
    gs: u64,
) -> Result<()> {
    let len = usize::from(insn.len);
    let bytes = insn
        .bytes
        .get(..len)
        .ok_or_else(|| msg("x87 encoding is empty"))?;
    let mut gp = [0u64; ARCH];
    gp.copy_from_slice(
        regs.get(..ARCH)
            .ok_or_else(|| msg("register index out of range"))?,
    );
    let mut af = regs.get(usize::from(AF)).copied().unwrap_or(0) & 1 == 1;
    let df = regs.get(31).copied().unwrap_or(0) & 1 == 1;
    finish_x87(insn, bytes, &mut gp, flags, x87, &mut af, df, mem, gs)?;
    regs[..ARCH].copy_from_slice(&gp);
    if let Some(slot) = regs.get_mut(usize::from(AF)) {
        *slot = u64::from(af);
    }
    Ok(())
}

#[cfg(not(kani))]
#[allow(
    clippy::too_many_arguments,
    reason = "the host x87 step takes the same separate inputs as exec_x87"
)]
fn finish_x87(
    insn: &X87Insn,
    bytes: &[u8],
    gp: &mut [u64; ARCH],
    flags: &mut Flags,
    x87: &mut X87,
    af: &mut bool,
    df: bool,
    mem: &mut dyn MemIo,
    gs: u64,
) -> Result<()> {
    let (run, ea) = crate::x87::machine_step(bytes, insn.ip, gp, gs)?;
    crate::x87::execute(x87, gp, flags, af, df, mem, &run, insn.ip, ea)
}

#[cfg(kani)]
#[allow(
    clippy::too_many_arguments,
    reason = "the host x87 step takes the same separate inputs as exec_x87"
)]
fn finish_x87(
    insn: &X87Insn,
    bytes: &[u8],
    gp: &mut [u64; ARCH],
    flags: &mut Flags,
    x87: &mut X87,
    af: &mut bool,
    df: bool,
    mem: &mut dyn MemIo,
    gs: u64,
) -> Result<()> {
    let _ = (insn, bytes, gp, flags, x87, af, df, mem, gs);
    Err(msg("x87 is outside the integer core"))
}

fn exec_sse(
    insn: &SseInsn,
    regs: &mut [u64],
    flags: &mut Flags,
    x87: &mut X87,
    sse: &mut Sse,
    mem: &mut dyn MemIo,
    gs: u64,
) -> Result<()> {
    let len = usize::from(insn.len);
    let bytes = insn
        .bytes
        .get(..len)
        .ok_or_else(|| msg("sse encoding is empty"))?;
    let mut gp = [0u64; ARCH];
    gp.copy_from_slice(
        regs.get(..ARCH)
            .ok_or_else(|| msg("register index out of range"))?,
    );
    let mut af = regs.get(usize::from(AF)).copied().unwrap_or(0) & 1 == 1;
    let df = regs.get(31).copied().unwrap_or(0) & 1 == 1;
    finish_sse(insn, bytes, &mut gp, flags, x87, sse, &mut af, df, mem, gs)?;
    regs[..ARCH].copy_from_slice(&gp);
    if let Some(slot) = regs.get_mut(usize::from(AF)) {
        *slot = u64::from(af);
    }
    Ok(())
}

#[cfg(not(kani))]
#[allow(
    clippy::too_many_arguments,
    reason = "the host SSE step takes the same separate inputs as exec_sse"
)]
fn finish_sse(
    insn: &SseInsn,
    bytes: &[u8],
    gp: &mut [u64; ARCH],
    flags: &mut Flags,
    x87: &mut X87,
    sse: &mut Sse,
    af: &mut bool,
    df: bool,
    mem: &mut dyn MemIo,
    gs: u64,
) -> Result<()> {
    crate::sse::execute(sse, x87, gp, flags, af, df, mem, bytes, insn.ip, gs)
}

#[cfg(kani)]
#[allow(
    clippy::too_many_arguments,
    reason = "the host SSE step takes the same separate inputs as exec_sse"
)]
fn finish_sse(
    insn: &SseInsn,
    bytes: &[u8],
    gp: &mut [u64; ARCH],
    flags: &mut Flags,
    x87: &mut X87,
    sse: &mut Sse,
    af: &mut bool,
    df: bool,
    mem: &mut dyn MemIo,
    gs: u64,
) -> Result<()> {
    let _ = (insn, bytes, gp, flags, x87, sse, af, df, mem, gs);
    Err(msg("sse is outside the integer core"))
}

fn regs_fit(op: &Op, len: usize) -> bool {
    let ok = |reg: u16| (reg as usize) < len;
    match *op {
        Op::MovRr(a, b)
        | Op::Load8(a, b)
        | Op::Store8(a, b)
        | Op::Load64(a, b)
        | Op::Store64(a, b)
        | Op::AddRr(a, b)
        | Op::SubRr(a, b)
        | Op::XorRr(a, b)
        | Op::AndRr(a, b)
        | Op::OrRr(a, b)
        | Op::CmpRr(a, b)
        | Op::TestRr(a, b)
        | Op::ImulRr(a, b) => ok(a) && ok(b),
        Op::MovRi(a, _)
        | Op::AddRi(a, _)
        | Op::SubRi(a, _)
        | Op::XorRi(a, _)
        | Op::AndRi(a, _)
        | Op::OrRi(a, _)
        | Op::CmpRi(a, _)
        | Op::TestRi(a, _)
        | Op::Not(a)
        | Op::Neg(a)
        | Op::Inc(a)
        | Op::Dec(a)
        | Op::Shl(a, _)
        | Op::Shr(a, _)
        | Op::Sar(a, _)
        | Op::Rol(a, _)
        | Op::Ror(a, _)
        | Op::ImulRi(a, _)
        | Op::Div(a)
        | Op::Push(a)
        | Op::Pop(a)
        | Op::StFlags(a)
        | Op::LdFlags(a) => ok(a),
        Op::Lea(dst, Address::Rva(_)) => ok(dst),
        Op::Lea(dst, Address::Sib { base, index, .. }) => {
            ok(dst) && base.is_none_or(ok) && index.is_none_or(ok)
        }
    }
}

/// Straight-line integer ops. [`exec_func`] runs every block through this path.
/// x87 and SSE do not enter it.
pub(crate) fn exec_integer_block(
    ops: &[Op],
    regs: &mut [u64],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
) -> Result<()> {
    for op in ops {
        exec_op(op, regs, flags, mem, image_base)?;
    }
    Ok(())
}

fn exec_op(
    op: &Op,
    regs: &mut [u64],
    flags: &mut Flags,
    mem: &mut dyn MemIo,
    image_base: u64,
) -> Result<()> {
    if !regs_fit(op, regs.len()) {
        return Err(msg("register index out of range"));
    }
    match *op {
        Op::MovRr(d, s) => regs[d as usize] = regs[s as usize],
        Op::MovRi(d, imm) => regs[d as usize] = imm,
        Op::Load8(d, a) => regs[d as usize] = read_width(mem, regs[a as usize], 1)?,
        Op::Store8(a, s) => mem.write(regs[a as usize], &[regs[s as usize] as u8])?,
        Op::Load64(d, a) => regs[d as usize] = read_width(mem, regs[a as usize], 8)?,
        Op::Store64(a, s) => mem.write(regs[a as usize], &regs[s as usize].to_le_bytes())?,
        Op::Lea(d, address) => regs[d as usize] = eval_addr(&address, regs, image_base),
        other => exec_compute(other, regs, flags, mem)?,
    }
    Ok(())
}

fn exec_compute(op: Op, regs: &mut [u64], flags: &mut Flags, mem: &mut dyn MemIo) -> Result<()> {
    match op {
        Op::AddRr(d, s) => arith(regs, flags, d, reg(regs, d), reg(regs, s), flags::add),
        Op::SubRr(d, s) => arith(regs, flags, d, reg(regs, d), reg(regs, s), flags::sub),
        Op::XorRr(d, s) => apply(
            regs,
            flags,
            d,
            flags::logic_xor(reg(regs, d), reg(regs, s), 64),
        ),
        Op::AndRr(d, s) => apply(
            regs,
            flags,
            d,
            flags::logic_and(reg(regs, d), reg(regs, s), 64),
        ),
        Op::OrRr(d, s) => apply(
            regs,
            flags,
            d,
            flags::logic_or(reg(regs, d), reg(regs, s), 64),
        ),
        Op::AddRi(d, imm) => arith(regs, flags, d, reg(regs, d), imm as i64 as u64, flags::add),
        Op::SubRi(d, imm) => arith(regs, flags, d, reg(regs, d), imm as i64 as u64, flags::sub),
        Op::XorRi(d, imm) => apply(
            regs,
            flags,
            d,
            flags::logic_xor(reg(regs, d), imm as i64 as u64, 64),
        ),
        Op::AndRi(d, imm) => apply(
            regs,
            flags,
            d,
            flags::logic_and(reg(regs, d), imm as i64 as u64, 64),
        ),
        Op::OrRi(d, imm) => apply(
            regs,
            flags,
            d,
            flags::logic_or(reg(regs, d), imm as i64 as u64, 64),
        ),
        Op::CmpRr(d, s) => cmp_af(regs, flags, reg(regs, d), reg(regs, s)),
        Op::CmpRi(d, imm) => cmp_af(regs, flags, reg(regs, d), imm as i64 as u64),
        Op::TestRr(d, s) => *flags = flags::logic_and(reg(regs, d), reg(regs, s), 64).1,
        Op::TestRi(d, imm) => *flags = flags::logic_and(reg(regs, d), imm as i64 as u64, 64).1,
        other => return exec_scalar(other, regs, flags, mem),
    }
    Ok(())
}

fn exec_scalar(op: Op, regs: &mut [u64], flags: &mut Flags, mem: &mut dyn MemIo) -> Result<()> {
    match op {
        Op::Not(d) => regs[d as usize] = !reg(regs, d),
        Op::Neg(d) => {
            let left = reg(regs, d);
            let computed = flags::neg(left, 64);
            apply(regs, flags, d, computed);
            // `neg` is `0 - value`: AF uses that minuend, not the original as the left addend.
            write_af(regs, 0, left, computed.0);
        }
        Op::Inc(d) => step_af(regs, flags, d, flags::inc),
        Op::Dec(d) => step_af(regs, flags, d, flags::dec),
        Op::Shl(d, c) => shift(regs, flags, d, c, flags::shift_left),
        Op::Shr(d, c) => shift(regs, flags, d, c, flags::shift_right),
        Op::Sar(d, c) => shift(regs, flags, d, c, flags::shift_arith),
        Op::Rol(d, c) => shift(regs, flags, d, c, flags::rotate_left),
        Op::Ror(d, c) => shift(regs, flags, d, c, flags::rotate_right),
        Op::ImulRr(d, s) => apply(regs, flags, d, flags::imul(reg(regs, d), reg(regs, s))),
        Op::ImulRi(d, imm) => apply(regs, flags, d, flags::imul(reg(regs, d), imm as i64 as u64)),
        Op::Div(s) => divide(regs, s)?,
        Op::Push(s) => push(regs, mem, s)?,
        Op::Pop(d) => pop(regs, mem, d)?,
        Op::StFlags(d) => regs[d as usize] = flags.pack(),
        Op::LdFlags(s) => *flags = Flags::unpack(reg(regs, s)),
        Op::AddRr(..)
        | Op::SubRr(..)
        | Op::XorRr(..)
        | Op::AndRr(..)
        | Op::OrRr(..)
        | Op::AddRi(..)
        | Op::SubRi(..)
        | Op::XorRi(..)
        | Op::AndRi(..)
        | Op::OrRi(..)
        | Op::CmpRr(..)
        | Op::CmpRi(..)
        | Op::TestRr(..)
        | Op::TestRi(..)
        | Op::MovRr(..)
        | Op::MovRi(..)
        | Op::Load8(..)
        | Op::Store8(..)
        | Op::Load64(..)
        | Op::Store64(..)
        | Op::Lea(..) => return Err(msg("ir op was already dispatched")),
    }
    Ok(())
}

fn reg(regs: &[u64], index: u16) -> u64 {
    regs[index as usize]
}

fn shift(
    regs: &mut [u64],
    flags: &mut Flags,
    dst: u16,
    count: u8,
    op: fn(u64, u32, u32, Flags) -> (u64, Flags),
) {
    let value = reg(regs, dst);
    apply(regs, flags, dst, op(value, u32::from(count), 64, *flags));
}

fn apply(regs: &mut [u64], flags: &mut Flags, dst: u16, computed: (u64, Flags)) {
    regs[dst as usize] = computed.0;
    *flags = computed.1;
}

/// Fast-path add/sub/cmp/inc/dec/neg are one IR op. AF lives in register 30,
/// which those ops write with the same nibble-carry formula as `flags::aux_carry`.
fn arith(
    regs: &mut [u64],
    flags: &mut Flags,
    dst: u16,
    left: u64,
    right: u64,
    op: fn(u64, u64, u32) -> (u64, Flags),
) {
    let computed = op(left, right, 64);
    apply(regs, flags, dst, computed);
    write_af(regs, left, right, computed.0);
}

fn cmp_af(regs: &mut [u64], flags: &mut Flags, left: u64, right: u64) {
    let (result, next) = flags::sub(left, right, 64);
    *flags = next;
    write_af(regs, left, right, result);
}

fn step_af(regs: &mut [u64], flags: &mut Flags, dst: u16, op: fn(u64, u32, Flags) -> (u64, Flags)) {
    let left = reg(regs, dst);
    let computed = op(left, 64, *flags);
    apply(regs, flags, dst, computed);
    write_af(regs, left, 1, computed.0);
}

fn write_af(regs: &mut [u64], left: u64, right: u64, result: u64) {
    if let Some(slot) = regs.get_mut(usize::from(AF)) {
        *slot = u64::from(flags::aux_carry(left, right, result));
    }
}

fn read_width(mem: &mut dyn MemIo, addr: u64, width: usize) -> Result<u64> {
    let buf = mem.read(addr, width)?;
    if width == 1 {
        return Ok(u64::from(*buf.first().ok_or_else(|| msg("short read"))?));
    }
    Ok(u64::from_le_bytes(exact_bytes(buf.as_slice())?))
}

fn divide(regs: &mut [u64], src: u16) -> Result<()> {
    let divisor = regs[src as usize];
    if divisor == 0 {
        return Err(msg("division by zero"));
    }
    let dividend = (u128::from(regs[RDX as usize]) << 64) | u128::from(regs[RAX as usize]);
    let quot = dividend / u128::from(divisor);
    if quot > u128::from(u64::MAX) {
        return Err(msg("division overflow"));
    }
    regs[RAX as usize] = quot as u64;
    regs[RDX as usize] = (dividend % u128::from(divisor)) as u64;
    Ok(())
}

fn push(regs: &mut [u64], mem: &mut dyn MemIo, src: u16) -> Result<()> {
    let sp = regs[RSP as usize].wrapping_sub(8);
    regs[RSP as usize] = sp;
    mem.write(sp, &regs[src as usize].to_le_bytes())
}

fn pop(regs: &mut [u64], mem: &mut dyn MemIo, dst: u16) -> Result<()> {
    let sp = regs[RSP as usize];
    let buf = mem.read(sp, 8)?;
    regs[dst as usize] = u64::from_le_bytes(exact_bytes(buf.as_slice())?);
    regs[RSP as usize] = sp.wrapping_add(8);
    Ok(())
}

pub fn eval_addr(address: &Address, regs: &[u64], image_base: u64) -> u64 {
    match address {
        Address::Rva(rva) => image_base.wrapping_add(*rva as u64),
        Address::Sib {
            base,
            index,
            scale,
            disp,
        } => {
            let mut acc = *disp;
            if let Some(base) = base {
                acc = acc.wrapping_add(regs[*base as usize] as i64);
            }
            if let Some(index) = index {
                acc = acc.wrapping_add((regs[*index as usize] as i64).wrapping_mul(*scale as i64));
            }
            acc as u64
        }
    }
}

pub fn kills_all_flags(op: &Op) -> bool {
    matches!(
        op,
        Op::AddRr(..)
            | Op::SubRr(..)
            | Op::XorRr(..)
            | Op::AndRr(..)
            | Op::OrRr(..)
            | Op::AddRi(..)
            | Op::SubRi(..)
            | Op::XorRi(..)
            | Op::AndRi(..)
            | Op::OrRi(..)
            | Op::CmpRr(..)
            | Op::CmpRi(..)
            | Op::TestRr(..)
            | Op::TestRi(..)
            | Op::Neg(_)
            | Op::Shl(..)
            | Op::Shr(..)
            | Op::Sar(..)
            | Op::ImulRr(..)
            | Op::ImulRi(..)
            | Op::LdFlags(_)
    )
}

pub fn flag_dead_map(block: &Block) -> Vec<bool> {
    let mut live = matches!(block.exit, Exit::Jcc(..));
    let mut dead = vec![false; block.ops.len()];
    for index in (0..block.ops.len()).rev() {
        dead[index] = !live;
        if kills_all_flags(&block.ops[index]) {
            live = false;
        } else if matches!(block.ops[index], Op::StFlags(_)) {
            live = true;
        }
    }
    dead
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(kani))]
    #[test]
    fn build_ir_wipe_clears_control_flow_payloads() {
        let variants = [
            (Exit::Jmp(0x1234), Exit::Jmp(0)),
            (Exit::Jcc(7, 0x2345, 0x3456), Exit::Jcc(0, 0, 0)),
            (
                Exit::CallRva {
                    rva: 0x4567,
                    next: 0x5678,
                },
                Exit::CallRva { rva: 0, next: 0 },
            ),
            (
                Exit::CallAbs {
                    reg: 3,
                    next: 0x6789,
                },
                Exit::CallAbs { reg: 0, next: 0 },
            ),
            (Exit::Ret, Exit::Ret),
        ];
        let mut func = FuncIr {
            name: "fixture".into(),
            rva: 0x789a,
            blocks: variants
                .iter()
                .map(|&(exit, _)| Block {
                    ops: vec![Op::MovRi(5, 0x1122_3344_5566_7788)],
                    exit,
                    opaque: true,
                })
                .collect(),
            entry: 1,
        };
        func.wipe();
        assert!(func.name.is_empty());
        assert_eq!((func.rva, func.entry), (0, 0));
        for (block, (_, wiped)) in func.blocks.iter().zip(variants) {
            assert!(block.ops.is_empty());
            assert!(!block.opaque);
            assert_eq!(block.exit, wiped);
        }
    }

    struct ShortMem;

    impl MemIo for ShortMem {
        fn read(&mut self, _addr: u64, _len: usize) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }

        fn write(&mut self, _addr: u64, _data: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn integer_view_reports_x87_at_the_function_rva() {
        let err = crate::lift::lift("fld", &[0xd9, 0xe8], 0x42, 2, 0).unwrap_err();
        match err {
            crate::error::Error::Unsupported { rva, text } => {
                assert_eq!(rva, 0x42);
                assert!(
                    text.contains("x87"),
                    "foreign mnemonic text should name x87, got {text}"
                );
            }
            other => panic!("expected Unsupported, got {other}"),
        }
    }

    fn run_prog(
        funcs: &[Program],
        index: usize,
        arch: &mut [u64; ARCH],
        af: &mut bool,
        df: &mut bool,
    ) {
        let mut flags = Flags::default();
        let mut x87 = X87::default();
        let mut sse = Sse::default();
        let mut mem = MapMem::default();
        let mut absent = |_: &mut [u64; ARCH], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        exec_program(
            funcs,
            index,
            arch,
            &mut flags,
            af,
            df,
            &mut x87,
            &mut sse,
            0,
            &mut mem,
            0,
            &mut absent,
        )
        .unwrap();
    }

    #[test]
    fn program_call_returns_registers_and_auxiliary_flags() {
        let callee = Program {
            name: "callee".into(),
            rva: 0x2000,
            entry: 0,
            blocks: vec![XBlock {
                ops: vec![Step::Gp(Op::MovRi(RAX, 0x0f)), Step::Gp(Op::AddRi(RAX, 1))],
                exit: Exit::Ret,
                opaque: false,
            }],
        };
        let caller = Program {
            name: "caller".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![
                XBlock {
                    ops: vec![Step::Gp(Op::MovRi(RBX, 5))],
                    exit: Exit::CallRva {
                        rva: 0x2000,
                        next: 1,
                    },
                    opaque: false,
                },
                XBlock {
                    ops: Vec::new(),
                    exit: Exit::Ret,
                    opaque: false,
                },
            ],
        };
        let mut arch = [0u64; ARCH];
        let mut af = false;
        let mut df = false;
        run_prog(&[caller, callee], 0, &mut arch, &mut af, &mut df);
        assert_eq!(arch[RAX as usize], 0x10);
        assert_eq!(arch[RBX as usize], 5);
        assert!(af, "callee auxiliary carry returns to the caller");
        assert!(!df);
    }

    #[test]
    fn program_call_depth_is_refused() {
        let rec = Program {
            name: "rec".into(),
            rva: 1,
            entry: 0,
            blocks: vec![XBlock {
                ops: vec![Step::Gp(Op::AddRi(RAX, 1))],
                exit: Exit::CallRva { rva: 1, next: 0 },
                opaque: false,
            }],
        };
        let mut arch = [0u64; ARCH];
        let mut flags = Flags::default();
        let mut af = false;
        let mut df = false;
        let mut x87 = X87::default();
        let mut sse = Sse::default();
        let mut mem = MapMem::default();
        let mut absent = |_: &mut [u64; ARCH], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        let err = exec_program(
            &[rec],
            0,
            &mut arch,
            &mut flags,
            &mut af,
            &mut df,
            &mut x87,
            &mut sse,
            0,
            &mut mem,
            0,
            &mut absent,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "ir call depth exceeded");
    }

    #[test]
    fn program_indirect_call_updates_registers_only() {
        let caller = Program {
            name: "abs".into(),
            rva: 1,
            entry: 0,
            blocks: vec![
                XBlock {
                    ops: Vec::new(),
                    exit: Exit::CallAbs { reg: RAX, next: 1 },
                    opaque: false,
                },
                XBlock {
                    ops: Vec::new(),
                    exit: Exit::Ret,
                    opaque: false,
                },
            ],
        };
        let mut arch = [0u64; ARCH];
        arch[RAX as usize] = 0x55;
        let mut flags = Flags::default();
        let mut af = true;
        let mut df = false;
        let mut x87 = X87::default();
        let mut sse = Sse::default();
        let mut mem = MapMem::default();
        let mut callback =
            |regs: &mut [u64; ARCH], _: &mut Flags, _: &mut dyn MemIo, target: u64| {
                assert_eq!(target, 0x55);
                regs[RAX as usize] = 7;
                Ok(())
            };
        exec_program(
            &[caller],
            0,
            &mut arch,
            &mut flags,
            &mut af,
            &mut df,
            &mut x87,
            &mut sse,
            0,
            &mut mem,
            0,
            &mut callback,
        )
        .unwrap();
        assert_eq!(arch[RAX as usize], 7);
        assert!(af, "an indirect call does not rewrite auxiliary carry");
    }

    #[test]
    fn short_memory_read_is_an_error() {
        let mut regs = [0u64; ARCH];
        regs[1] = 0x1000;
        let mut flags = Flags::default();
        let err = exec_op(&Op::Load64(0, 1), &mut regs, &mut flags, &mut ShortMem, 0).unwrap_err();
        assert_eq!(err.to_string(), "short read");
    }

    #[test]
    fn data_ops_that_reach_scalar_dispatch_are_rejected() {
        let mut regs = [0u64; V_LIMIT];
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let ops = [
            Op::MovRr(0, 1),
            Op::MovRi(0, 1),
            Op::Load8(0, 1),
            Op::Store8(0, 1),
            Op::Load64(0, 1),
            Op::Store64(0, 1),
            Op::Lea(0, Address::Rva(0)),
        ];
        for op in ops {
            let err = exec_scalar(op, &mut regs, &mut flags, &mut mem).unwrap_err();
            assert_eq!(err.to_string(), "ir op was already dispatched");
        }
    }
}
