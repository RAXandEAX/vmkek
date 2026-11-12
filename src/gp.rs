//! User-mode integer x86-64. One step here is the semantic contract shared by the
//! emulator. The lifter lowers the same contract onto the existing IR ops so both
//! interpreters execute it without a new bytecode opcode.

mod alu;
mod ops;

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::error::{msg, Result};
use crate::flags::Flags;
use crate::ir::MemIo;

/// Architectural state touched by general-purpose instructions.
pub struct Cpu {
    pub regs: [u64; 16],
    pub flags: Flags,
    pub af: bool,
    pub df: bool,
    pub gs: u64,
}

/// What one instruction does to a flag bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fate {
    Keep,
    /// The manual defines the bit. The new value is observable.
    Write,
    /// The manual leaves the bit undefined.
    Undef,
}

/// Observable flag contract for one executed instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Touch {
    pub cf: Fate,
    pub pf: Fate,
    pub af: Fate,
    pub zf: Fate,
    pub sf: Fate,
    pub of: Fate,
    pub df: Fate,
}

impl Touch {
    const fn keep() -> Self {
        Self {
            cf: Fate::Keep,
            pf: Fate::Keep,
            af: Fate::Keep,
            zf: Fate::Keep,
            sf: Fate::Keep,
            of: Fate::Keep,
            df: Fate::Keep,
        }
    }

    fn arith() -> Self {
        Self {
            cf: Fate::Write,
            pf: Fate::Write,
            af: Fate::Write,
            zf: Fate::Write,
            sf: Fate::Write,
            of: Fate::Write,
            df: Fate::Keep,
        }
    }

    fn logic() -> Self {
        Self {
            cf: Fate::Write,
            pf: Fate::Write,
            af: Fate::Undef,
            zf: Fate::Write,
            sf: Fate::Write,
            of: Fate::Write,
            df: Fate::Keep,
        }
    }
}

/// How the census group is executed. `Foreign` is not an L1 integer opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Run,
    /// Encoded by iced-x86 and `#UD` in long mode.
    Ud,
    Foreign,
}

/// Executes one user integer instruction.
///
/// `Ok(None)` means the mnemonic is not part of this integer core (control
/// transfer, x87, vectors). `Ok(Some(touch))` updates `cpu` and memory and
/// reports which flag bits are architecturally defined.
pub fn apply(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Option<Touch>> {
    if vector(insn) {
        return Ok(None);
    }
    if insn.has_lock_prefix() && !lock_ok(insn) {
        return Err(invalid());
    }
    match classify(insn.mnemonic()) {
        Class::Foreign => Ok(None),
        Class::Ud => Err(invalid()),
        Class::Run => Ok(Some(dispatch(cpu, mem, insn)?)),
    }
}

pub fn classify(mnemonic: Mnemonic) -> Class {
    if alu::is_alu(mnemonic)
        || ops::is_side(mnemonic)
        || matches!(
            mnemonic,
            Mnemonic::Nop
                | Mnemonic::Pause
                | Mnemonic::Reservednop
                | Mnemonic::Zero_bytes
                | Mnemonic::Mov
                | Mnemonic::Movzx
                | Mnemonic::Movsx
                | Mnemonic::Movsxd
                | Mnemonic::Lea
                | Mnemonic::Xchg
                | Mnemonic::Xadd
                | Mnemonic::Cmpxchg
                | Mnemonic::Cmpxchg8b
                | Mnemonic::Cmpxchg16b
                | Mnemonic::Bswap
                | Mnemonic::Bsf
                | Mnemonic::Bsr
                | Mnemonic::Bt
                | Mnemonic::Bts
                | Mnemonic::Btr
                | Mnemonic::Btc
                | Mnemonic::Mul
                | Mnemonic::Imul
                | Mnemonic::Div
                | Mnemonic::Idiv
                | Mnemonic::Push
                | Mnemonic::Pop
                | Mnemonic::Pushf
                | Mnemonic::Pushfq
                | Mnemonic::Popf
                | Mnemonic::Popfq
                | Mnemonic::Enter
                | Mnemonic::Leave
                | Mnemonic::Lahf
                | Mnemonic::Sahf
                | Mnemonic::Sal
                | Mnemonic::Shl
                | Mnemonic::Shr
                | Mnemonic::Sar
                | Mnemonic::Rol
                | Mnemonic::Ror
                | Mnemonic::Rcl
                | Mnemonic::Rcr
                | Mnemonic::Shld
                | Mnemonic::Shrd
                | Mnemonic::Cbw
                | Mnemonic::Cwde
                | Mnemonic::Cdqe
                | Mnemonic::Cwd
                | Mnemonic::Cdq
                | Mnemonic::Cqo
                | Mnemonic::Clc
                | Mnemonic::Stc
                | Mnemonic::Cmc
                | Mnemonic::Cld
                | Mnemonic::Std
                | Mnemonic::Xlatb
                | Mnemonic::Movsb
                | Mnemonic::Movsw
                | Mnemonic::Movsd
                | Mnemonic::Movsq
                | Mnemonic::Stosb
                | Mnemonic::Stosw
                | Mnemonic::Stosd
                | Mnemonic::Stosq
                | Mnemonic::Lodsb
                | Mnemonic::Lodsw
                | Mnemonic::Lodsd
                | Mnemonic::Lodsq
                | Mnemonic::Scasb
                | Mnemonic::Scasw
                | Mnemonic::Scasd
                | Mnemonic::Scasq
                | Mnemonic::Cmpsb
                | Mnemonic::Cmpsw
                | Mnemonic::Cmpsd
                | Mnemonic::Cmpsq
        )
        || cond(mnemonic).is_some()
    {
        Class::Run
    } else if matches!(
        mnemonic,
        Mnemonic::Aaa
            | Mnemonic::Aad
            | Mnemonic::Aam
            | Mnemonic::Aas
            | Mnemonic::Daa
            | Mnemonic::Das
            | Mnemonic::Pusha
            | Mnemonic::Pushad
            | Mnemonic::Popa
            | Mnemonic::Popad
            | Mnemonic::Bound
            | Mnemonic::Salc
            | Mnemonic::Ibts
            | Mnemonic::Xbts
            | Mnemonic::Umov
            | Mnemonic::Pushfd
            | Mnemonic::Popfd
    ) {
        Class::Ud
    } else {
        Class::Foreign
    }
}

fn dispatch(cpu: &mut Cpu, mem: &mut dyn MemIo, insn: &Instruction) -> Result<Touch> {
    let mnemonic = insn.mnemonic();
    if matches!(
        mnemonic,
        Mnemonic::Nop | Mnemonic::Pause | Mnemonic::Reservednop | Mnemonic::Zero_bytes
    ) {
        return Ok(Touch::keep());
    }
    if let Some(op) = alu::alu_of(mnemonic) {
        return alu::alu(cpu, mem, insn, op);
    }
    if let Some(op) = alu::shift_of(mnemonic) {
        return alu::shift(cpu, mem, insn, op);
    }
    if let Some(code) = cond(mnemonic) {
        return if is_setcc(mnemonic) {
            ops::setcc(cpu, mem, insn, code)
        } else {
            ops::cmov(cpu, mem, insn, code)
        };
    }
    ops::side(cpu, mem, insn)
}

pub(crate) fn cond(mnemonic: Mnemonic) -> Option<u8> {
    Some(match mnemonic {
        Mnemonic::Cmovo | Mnemonic::Seto => 0,
        Mnemonic::Cmovno | Mnemonic::Setno => 1,
        Mnemonic::Cmovb | Mnemonic::Setb => 2,
        Mnemonic::Cmovae | Mnemonic::Setae => 3,
        Mnemonic::Cmove | Mnemonic::Sete => 4,
        Mnemonic::Cmovne | Mnemonic::Setne => 5,
        Mnemonic::Cmovbe | Mnemonic::Setbe => 6,
        Mnemonic::Cmova | Mnemonic::Seta => 7,
        Mnemonic::Cmovs | Mnemonic::Sets => 8,
        Mnemonic::Cmovns | Mnemonic::Setns => 9,
        Mnemonic::Cmovp | Mnemonic::Setp => 10,
        Mnemonic::Cmovnp | Mnemonic::Setnp => 11,
        Mnemonic::Cmovl | Mnemonic::Setl => 12,
        Mnemonic::Cmovge | Mnemonic::Setge => 13,
        Mnemonic::Cmovle | Mnemonic::Setle => 14,
        Mnemonic::Cmovg | Mnemonic::Setg => 15,
        _ => return None,
    })
}

pub(crate) fn is_setcc(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Seto
            | Mnemonic::Setno
            | Mnemonic::Setb
            | Mnemonic::Setae
            | Mnemonic::Sete
            | Mnemonic::Setne
            | Mnemonic::Setbe
            | Mnemonic::Seta
            | Mnemonic::Sets
            | Mnemonic::Setns
            | Mnemonic::Setp
            | Mnemonic::Setnp
            | Mnemonic::Setl
            | Mnemonic::Setge
            | Mnemonic::Setle
            | Mnemonic::Setg
    )
}

fn vector(insn: &Instruction) -> bool {
    (0..insn.op_count()).any(|index| {
        insn.op_kind(index) == OpKind::Register && {
            let reg = insn.op_register(index);
            reg.is_xmm() || reg.is_ymm() || reg.is_zmm()
        }
    })
}

pub(crate) fn lock_ok(insn: &Instruction) -> bool {
    matches!(
        insn.mnemonic(),
        Mnemonic::Add
            | Mnemonic::Adc
            | Mnemonic::And
            | Mnemonic::Btc
            | Mnemonic::Btr
            | Mnemonic::Bts
            | Mnemonic::Cmpxchg
            | Mnemonic::Cmpxchg8b
            | Mnemonic::Cmpxchg16b
            | Mnemonic::Dec
            | Mnemonic::Inc
            | Mnemonic::Neg
            | Mnemonic::Not
            | Mnemonic::Or
            | Mnemonic::Sbb
            | Mnemonic::Sub
            | Mnemonic::Xadd
            | Mnemonic::Xchg
            | Mnemonic::Xor
    ) && memory_destination(insn)
}

fn memory_destination(insn: &Instruction) -> bool {
    if insn.mnemonic() == Mnemonic::Xchg {
        return (0..insn.op_count()).any(|index| insn.op_kind(index) == OpKind::Memory);
    }
    insn.op0_kind() == OpKind::Memory
}

pub(crate) fn invalid() -> crate::error::Error {
    msg("invalid opcode")
}

pub(crate) fn mask(width: u32) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

pub(crate) fn high_byte(reg: Register) -> bool {
    matches!(
        reg,
        Register::AH | Register::CH | Register::DH | Register::BH
    )
}

pub(crate) fn read_reg(regs: &[u64; 16], reg: Register) -> u64 {
    let full = regs[reg.full_register().number()];
    if high_byte(reg) {
        return (full >> 8) & 0xff;
    }
    full & mask(reg.size() as u32 * 8)
}

pub(crate) fn write_reg(regs: &mut [u64; 16], reg: Register, value: u64) {
    let index = reg.full_register().number();
    if high_byte(reg) {
        regs[index] = (regs[index] & !0xff00) | ((value & 0xff) << 8);
        return;
    }
    let bits = reg.size() as u32 * 8;
    if bits >= 32 {
        regs[index] = value & mask(bits);
        return;
    }
    let keep = !mask(bits);
    regs[index] = (regs[index] & keep) | (value & mask(bits));
}

pub(crate) fn op_bits(insn: &Instruction, index: u32) -> u32 {
    match insn.op_kind(index) {
        OpKind::Register => insn.op_register(index).size() as u32 * 8,
        OpKind::Memory => insn.memory_size().size() as u32 * 8,
        _ => 64,
    }
}

pub(crate) fn read_imm(insn: &Instruction, index: u32) -> u64 {
    match insn.op_kind(index) {
        OpKind::Immediate8 => u64::from(insn.immediate8()),
        OpKind::Immediate16 => u64::from(insn.immediate16()),
        OpKind::Immediate32 => u64::from(insn.immediate32()),
        OpKind::Immediate64 => insn.immediate64(),
        OpKind::Immediate8to16 => insn.immediate8to16() as u16 as u64,
        OpKind::Immediate8to32 => insn.immediate8to32() as u32 as u64,
        OpKind::Immediate8to64 => insn.immediate8to64() as u64,
        OpKind::Immediate32to64 => insn.immediate32to64() as u64,
        _ => 0,
    }
}

pub(crate) fn read_src(
    cpu: &Cpu,
    mem: &mut dyn MemIo,
    insn: &Instruction,
    index: u32,
) -> Result<u64> {
    match insn.op_kind(index) {
        OpKind::Register => {
            let reg = insn.op_register(index);
            if !reg.is_gpr() {
                return Err(msg("unsupported register"));
            }
            Ok(read_reg(&cpu.regs, reg))
        }
        OpKind::Memory => read_mem(cpu, mem, insn, op_bits(insn, index)),
        kind if is_imm(kind) => Ok(read_imm(insn, index)),
        _ => Err(msg("unsupported operand")),
    }
}

pub(crate) fn write_dst(
    cpu: &mut Cpu,
    mem: &mut dyn MemIo,
    insn: &Instruction,
    value: u64,
) -> Result<()> {
    write_op(cpu, mem, insn, 0, value)
}

pub(crate) fn write_op(
    cpu: &mut Cpu,
    mem: &mut dyn MemIo,
    insn: &Instruction,
    index: u32,
    value: u64,
) -> Result<()> {
    match insn.op_kind(index) {
        OpKind::Register => {
            let reg = insn.op_register(index);
            if !reg.is_gpr() {
                return Err(msg("unsupported register"));
            }
            write_reg(&mut cpu.regs, reg, value);
            Ok(())
        }
        OpKind::Memory => write_mem(cpu, mem, insn, value, op_bits(insn, index)),
        _ => Err(msg("destination is not writable")),
    }
}

pub(crate) fn read_mem(
    cpu: &Cpu,
    mem: &mut dyn MemIo,
    insn: &Instruction,
    bits: u32,
) -> Result<u64> {
    let width = (bits / 8) as usize;
    let bytes = mem.read(address(cpu, insn)?, width)?;
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (8 * index);
    }
    Ok(value)
}

pub(crate) fn write_mem(
    cpu: &Cpu,
    mem: &mut dyn MemIo,
    insn: &Instruction,
    value: u64,
    bits: u32,
) -> Result<()> {
    let width = (bits / 8) as usize;
    mem.write(address(cpu, insn)?, &value.to_le_bytes()[..width])
}

pub(crate) fn address(cpu: &Cpu, insn: &Instruction) -> Result<u64> {
    operand_address(
        cpu,
        insn,
        memory_operand(insn),
        insn.mnemonic() != Mnemonic::Lea,
    )
}

pub(crate) fn operand_address(
    cpu: &Cpu,
    insn: &Instruction,
    operand: u32,
    segments: bool,
) -> Result<u64> {
    insn.virtual_address(operand, 0, |reg, _, _| register_base(cpu, reg, segments))
        .ok_or_else(|| msg("could not compute a memory address"))
}

fn memory_operand(insn: &Instruction) -> u32 {
    (0..insn.op_count())
        .find(|index| is_memory(insn.op_kind(*index)))
        .unwrap_or(0)
}

pub(crate) fn is_memory(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Memory
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI
    )
}

fn register_base(cpu: &Cpu, reg: Register, segments: bool) -> Option<u64> {
    if reg.is_segment_register() {
        if segments && reg == Register::GS {
            Some(cpu.gs)
        } else {
            Some(0)
        }
    } else if reg.is_gpr() {
        Some(cpu.regs[reg.full_register().number()])
    } else if reg == Register::None || reg == Register::RIP || reg == Register::EIP {
        Some(0)
    } else {
        None
    }
}

pub(crate) fn is_imm(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64
    )
}

pub(crate) fn sign_extend(value: u64, width: u32) -> i64 {
    if width >= 64 {
        value as i64
    } else {
        let shift = 64 - width;
        ((value as i64) << shift) >> shift
    }
}

pub(crate) fn set_arith(cpu: &mut Cpu, flags: Flags, af: bool) {
    cpu.flags = flags;
    cpu.af = af;
}

pub(crate) fn clear_af(cpu: &mut Cpu) {
    cpu.af = false;
}

#[cfg(test)]
#[path = "diff_l1.rs"]
mod diff_l1;

#[cfg(test)]
pub(crate) use diff_l1::{l1_blocks, L1Block};
