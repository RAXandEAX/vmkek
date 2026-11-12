//! Lower the rest of the user integer group onto the existing IR ops.

use iced_x86::{Code, Instruction, Mnemonic, OpKind, Register};

use crate::error::{msg, Result};
use crate::gp::{self, Class};
use crate::ir::{Address, Exit, Op, Step, XBlock, RAX, RBP, RBX, RCX, RDI, RDX, RSI, RSP};

pub(super) const T0: u16 = 24;
pub(super) const T1: u16 = 25;
pub(super) const T2: u16 = 26;
const T3: u16 = 27;
pub(super) const ADDR: u16 = 28;
const IMM: u16 = 29;
pub(super) const AF: u16 = 30;
const DF: u16 = 31;
pub(super) const SAVE: u16 = 23;

pub struct Cursor<'a> {
    blocks: &'a mut Vec<XBlock>,
    block: u32,
    ops: Vec<Step>,
}

impl<'a> Cursor<'a> {
    pub fn new(blocks: &'a mut Vec<XBlock>, block: u32) -> Self {
        Self {
            blocks,
            block,
            ops: Vec::new(),
        }
    }

    pub fn emit(&mut self, op: Op) {
        self.ops.push(Step::Gp(op));
    }

    pub fn emit_x87(&mut self, insn: crate::ir::X87Insn) {
        self.ops.push(Step::X87(insn));
    }

    pub fn emit_sse(&mut self, insn: crate::ir::SseInsn) {
        self.ops.push(Step::Sse(insn));
    }

    pub fn extend(&mut self, ops: impl IntoIterator<Item = Op>) {
        self.ops.extend(ops.into_iter().map(Step::Gp));
    }

    pub fn seal(mut self, exit: Exit) {
        let block = self.block;
        let ops = std::mem::take(&mut self.ops);
        self.seal_at(block, ops, exit);
    }

    fn alloc(&mut self) -> u32 {
        let id = self.blocks.len() as u32;
        self.blocks.push(XBlock {
            ops: Vec::new(),
            exit: Exit::Ret,
            opaque: false,
        });
        id
    }

    fn seal_at(&mut self, id: u32, ops: Vec<Step>, exit: Exit) {
        let block = &mut self.blocks[id as usize];
        block.ops = ops;
        block.exit = exit;
    }

    fn cbranch<Y, N>(&mut self, cond: u8, yes: Y, no: N)
    where
        Y: FnOnce(&mut Self),
        N: FnOnce(&mut Self),
    {
        let yes_id = self.alloc();
        let no_id = self.alloc();
        let join = self.alloc();
        let ops = std::mem::take(&mut self.ops);
        self.seal_at(self.block, ops, Exit::Jcc(cond, yes_id, no_id));
        self.block = yes_id;
        yes(self);
        let ops = std::mem::take(&mut self.ops);
        self.seal_at(self.block, ops, Exit::Jmp(join));
        self.block = no_id;
        no(self);
        let ops = std::mem::take(&mut self.ops);
        self.seal_at(self.block, ops, Exit::Jmp(join));
        self.block = join;
    }
}

pub fn encode(cursor: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    if gp::classify(insn.mnemonic()) == Class::Ud {
        return Err(super::bad(insn));
    }
    if let Some(cond) = gp::cond(insn.mnemonic()) {
        return if gp::is_setcc(insn.mnemonic()) {
            setcc(cursor, insn, image_base, cond)
        } else {
            cmov(cursor, insn, image_base, cond)
        };
    }
    match insn.mnemonic() {
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => {
            mov(cursor, insn, image_base)
        }
        Mnemonic::Lea => lea(cursor, insn, image_base),
        Mnemonic::Nop | Mnemonic::Pause | Mnemonic::Reservednop | Mnemonic::Zero_bytes => {
            cursor.emit(Op::MovRr(RAX, RAX));
            Ok(())
        }
        Mnemonic::Add
        | Mnemonic::Adc
        | Mnemonic::Sub
        | Mnemonic::Sbb
        | Mnemonic::Cmp
        | Mnemonic::And
        | Mnemonic::Or
        | Mnemonic::Xor
        | Mnemonic::Test
        | Mnemonic::Inc
        | Mnemonic::Dec
        | Mnemonic::Neg
        | Mnemonic::Not => alu(cursor, insn, image_base),
        Mnemonic::Shl
        | Mnemonic::Shr
        | Mnemonic::Sar
        | Mnemonic::Sal
        | Mnemonic::Rol
        | Mnemonic::Ror
        | Mnemonic::Rcl
        | Mnemonic::Rcr
        | Mnemonic::Shld
        | Mnemonic::Shrd => shift(cursor, insn, image_base),
        Mnemonic::Imul | Mnemonic::Mul => mul(cursor, insn, image_base),
        Mnemonic::Div | Mnemonic::Idiv => div(cursor, insn, image_base),
        Mnemonic::Push | Mnemonic::Pop => push_pop(cursor, insn, image_base),
        Mnemonic::Pushf | Mnemonic::Pushfq | Mnemonic::Popf | Mnemonic::Popfq => {
            push_pop_flags(cursor, insn)
        }
        Mnemonic::Xchg => xchg(cursor, insn, image_base),
        Mnemonic::Xadd => xadd(cursor, insn, image_base),
        Mnemonic::Cmpxchg => cmpxchg(cursor, insn, image_base),
        Mnemonic::Cmpxchg8b | Mnemonic::Cmpxchg16b => cmpxchg_wide(cursor, insn, image_base),
        Mnemonic::Bswap => bswap(cursor, insn),
        Mnemonic::Bsf | Mnemonic::Bsr => bitscan(cursor, insn, image_base),
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => {
            bit(cursor, insn, image_base)
        }
        Mnemonic::Cbw
        | Mnemonic::Cwde
        | Mnemonic::Cdqe
        | Mnemonic::Cwd
        | Mnemonic::Cdq
        | Mnemonic::Cqo => convert(cursor, insn),
        Mnemonic::Clc | Mnemonic::Stc | Mnemonic::Cmc | Mnemonic::Cld | Mnemonic::Std => {
            flag_op(cursor, insn)
        }
        Mnemonic::Lahf | Mnemonic::Sahf => lahf_sahf(cursor, insn),
        Mnemonic::Enter | Mnemonic::Leave => frame(cursor, insn, image_base),
        Mnemonic::Xlatb => xlat(cursor, insn, image_base),
        mnemonic if string_width(mnemonic).is_some() => string(cursor, insn, image_base),
        _ => Err(super::bad(insn)),
    }
}

fn mov(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let extend = match insn.mnemonic() {
        Mnemonic::Movzx => Extend::Zero,
        Mnemonic::Movsx | Mnemonic::Movsxd => Extend::Sign,
        _ => Extend::Merge,
    };
    preserve(c, |c| {
        if insn.op0_kind() == OpKind::Memory {
            read_value(c, insn, 1, T0, image_base)?;
            materialize(c, insn, image_base)?;
            store_width(c, T0, width_bytes(insn, 0))?;
            return Ok(());
        }
        let dest = insn.op_register(0);
        read_value(c, insn, 1, T0, image_base)?;
        if extend != Extend::Merge {
            let from = operand_bits(insn, 1);
            let to = operand_bits(insn, 0);
            if extend == Extend::Sign {
                sign_to(c, T0, from);
            } else {
                mask_reg(c, T0, from);
            }
            if to == 32 {
                mask_reg(c, T0, 32);
            }
        }
        write_reg(c, dest, T0)
    })
}

fn lea(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    preserve(c, |c| {
        materialize(c, insn, image_base)?;
        write_reg(c, insn.op_register(0), ADDR)
    })
}

fn alu(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let width = operand_bits(insn, 0);
    if !matches!(width, 8 | 16 | 32 | 64) {
        return Err(super::bad(insn));
    }
    c.emit(Op::StFlags(SAVE));
    let op = insn.mnemonic();
    if op == Mnemonic::Not {
        return alu_not(c, insn, image_base, width);
    }
    let unary = matches!(op, Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg);
    read_value(c, insn, 0, T0, image_base)?;
    mask_reg(c, T0, width);
    if !unary {
        read_value(c, insn, 1, T1, image_base)?;
        mask_reg(c, T1, width);
        c.emit(Op::MovRr(T2, T1));
    }
    c.emit(Op::MovRr(ADDR, T0));
    align(c, T0, width);
    if !unary {
        align(c, T1, width);
    }
    perform(c, op, width);
    unalign(c, T0, width);
    if matches!(op, Mnemonic::Adc | Mnemonic::Sbb) {
        patch_of(c, width, op == Mnemonic::Sbb);
    }
    fix_parity(c, T0, T1);
    set_af(c, op);
    c.emit(Op::MovRr(crate::ir::V_TMP1, AF));
    c.emit(Op::MovRr(SAVE, T1));
    if !matches!(op, Mnemonic::Cmp | Mnemonic::Test) {
        write_dest(c, insn, image_base, width)?;
    }
    c.emit(Op::LdFlags(SAVE));
    c.emit(Op::MovRr(AF, crate::ir::V_TMP1));
    Ok(())
}

fn alu_not(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64, width: u32) -> Result<()> {
    read_value(c, insn, 0, T0, image_base)?;
    mask_reg(c, T0, width);
    c.emit(Op::Not(T0));
    mask_reg(c, T0, width);
    write_dest(c, insn, image_base, width)?;
    c.emit(Op::LdFlags(SAVE));
    Ok(())
}

fn align(c: &mut Cursor<'_>, reg: u16, width: u32) {
    if width < 64 {
        c.emit(Op::Shl(reg, (64 - width) as u8));
    }
}

fn unalign(c: &mut Cursor<'_>, reg: u16, width: u32) {
    if width < 64 {
        c.emit(Op::Shr(reg, (64 - width) as u8));
        mask_reg(c, reg, width);
    }
}

fn perform(c: &mut Cursor<'_>, op: Mnemonic, width: u32) {
    match op {
        Mnemonic::Add => {
            c.emit(Op::AddRr(T0, T1));
            c.emit(Op::StFlags(T1));
        }
        Mnemonic::Adc => add_carry(c, width, true),
        Mnemonic::Sub | Mnemonic::Cmp => {
            c.emit(Op::SubRr(T0, T1));
            c.emit(Op::StFlags(T1));
        }
        Mnemonic::Sbb => add_carry(c, width, false),
        Mnemonic::And | Mnemonic::Test => {
            c.emit(Op::AndRr(T0, T1));
            c.emit(Op::StFlags(T1));
        }
        Mnemonic::Or => {
            c.emit(Op::OrRr(T0, T1));
            c.emit(Op::StFlags(T1));
        }
        Mnemonic::Xor => {
            c.emit(Op::XorRr(T0, T1));
            c.emit(Op::StFlags(T1));
        }
        Mnemonic::Inc => add_one(c, width, true),
        Mnemonic::Dec => add_one(c, width, false),
        Mnemonic::Neg => {
            c.emit(Op::Neg(T0));
            c.emit(Op::StFlags(T1));
        }
        _ => {}
    }
}

fn add_carry(c: &mut Cursor<'_>, width: u32, add: bool) {
    if add {
        c.emit(Op::AddRr(T0, T1));
    } else {
        c.emit(Op::SubRr(T0, T1));
    }
    c.emit(Op::StFlags(IMM));
    c.emit(Op::MovRr(T3, SAVE));
    c.emit(Op::AndRi(T3, 1));
    if width < 64 {
        c.emit(Op::Shl(T3, (64 - width) as u8));
    }
    if add {
        c.emit(Op::AddRr(T0, T3));
    } else {
        c.emit(Op::SubRr(T0, T3));
    }
    c.emit(Op::StFlags(T1));
    c.emit(Op::MovRr(T3, IMM));
    c.emit(Op::AndRi(T3, 1));
    c.emit(Op::OrRr(T1, T3));
}

fn add_one(c: &mut Cursor<'_>, width: u32, add: bool) {
    let bit = if width < 64 { 1u64 << (64 - width) } else { 1 };
    c.emit(Op::MovRi(T1, bit));
    if add {
        c.emit(Op::AddRr(T0, T1));
    } else {
        c.emit(Op::SubRr(T0, T1));
    }
    c.emit(Op::StFlags(T1));
    c.emit(Op::MovRr(T3, SAVE));
    c.emit(Op::AndRi(T3, 1));
    c.emit(Op::AndRi(T1, !1));
    c.emit(Op::OrRr(T1, T3));
}

fn patch_of(c: &mut Cursor<'_>, width: u32, sub: bool) {
    c.emit(Op::MovRr(T3, ADDR));
    if sub {
        c.emit(Op::XorRr(T3, T2));
        c.emit(Op::MovRr(IMM, ADDR));
    } else {
        c.emit(Op::XorRr(T3, T0));
        c.emit(Op::MovRr(IMM, T2));
    }
    c.emit(Op::XorRr(IMM, T0));
    c.emit(Op::AndRr(T3, IMM));
    c.emit(Op::MovRi(IMM, 1u64 << (width - 1)));
    c.emit(Op::AndRr(T3, IMM));
    c.emit(Op::Shr(T3, (width - 1) as u8));
    c.emit(Op::Shl(T3, 11));
    c.emit(Op::AndRi(T1, !0x800));
    c.emit(Op::OrRr(T1, T3));
}

fn set_af(c: &mut Cursor<'_>, op: Mnemonic) {
    match op {
        Mnemonic::And | Mnemonic::Or | Mnemonic::Xor | Mnemonic::Test => c.emit(Op::MovRi(AF, 0)),
        Mnemonic::Inc | Mnemonic::Dec => {
            c.emit(Op::MovRi(T2, 1));
            aux(c, ADDR, T2, T0);
        }
        Mnemonic::Neg => {
            c.emit(Op::MovRi(T2, 0));
            aux(c, T2, ADDR, T0);
        }
        _ => aux(c, ADDR, T2, T0),
    }
}

fn shift(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let width = operand_bits(insn, 0);
    if !matches!(width, 8 | 16 | 32 | 64) {
        return Err(super::bad(insn));
    }
    let kind = insn.mnemonic();
    c.emit(Op::StFlags(SAVE));
    read_value(c, insn, 0, T0, image_base)?;
    mask_reg(c, T0, width);
    let count_at = if matches!(kind, Mnemonic::Shld | Mnemonic::Shrd) {
        read_value(c, insn, 1, T1, image_base)?;
        mask_reg(c, T1, width);
        2
    } else {
        1
    };
    read_value(c, insn, count_at, T2, image_base)?;
    c.emit(Op::MovRi(IMM, if width == 64 { 63 } else { 31 }));
    c.emit(Op::AndRr(T2, IMM));
    c.emit(Op::TestRr(T2, T2));
    c.cbranch(
        4,
        |_| {},
        |c| {
            do_shift(c, kind, width);
            let _ = write_dest(c, insn, image_base, width);
        },
    );
    c.emit(Op::LdFlags(SAVE));
    Ok(())
}

fn do_shift(c: &mut Cursor<'_>, kind: Mnemonic, width: u32) {
    c.emit(Op::MovRr(ADDR, T0));
    match kind {
        Mnemonic::Shl | Mnemonic::Sal => logical(c, width, true),
        Mnemonic::Shr => logical(c, width, false),
        Mnemonic::Sar => step_count(c, width, OfKind::Sar, false, |c| sar_step(c, width)),
        Mnemonic::Rol => step_count(c, width, OfKind::Shl, true, |c| rol_step(c, width)),
        Mnemonic::Ror => step_count(c, width, OfKind::Ror, true, |c| ror_step(c, width)),
        Mnemonic::Rcl => through(c, width, true),
        Mnemonic::Rcr => through(c, width, false),
        Mnemonic::Shld => guarded(c, width, true),
        Mnemonic::Shrd => guarded(c, width, false),
        _ => {}
    }
}

#[derive(Clone, Copy)]
enum OfKind {
    Shl,
    Shr,
    Sar,
    Ror,
    Shrd,
}

fn logical(c: &mut Cursor<'_>, width: u32, left: bool) {
    if left {
        step_count(c, width, OfKind::Shl, false, |c| shl_step(c, width));
    } else {
        step_count(c, width, OfKind::Shr, false, |c| shr_step(c, width));
    }
}

fn through(c: &mut Cursor<'_>, width: u32, left: bool) {
    c.emit(Op::MovRr(IMM, SAVE));
    c.emit(Op::AndRi(IMM, 1));
    if left {
        step_count(c, width, OfKind::Shl, true, |c| rcl_step(c, width));
    } else {
        step_count(c, width, OfKind::Ror, true, |c| rcr_step(c, width));
    }
}

fn guarded(c: &mut Cursor<'_>, width: u32, left: bool) {
    if width >= 64 {
        run_double(c, width, left);
        return;
    }
    c.emit(Op::CmpRi(T2, width as i32));
    c.cbranch(7, |_| {}, |c| run_double(c, width, left));
}

fn run_double(c: &mut Cursor<'_>, width: u32, left: bool) {
    if left {
        step_count(c, width, OfKind::Shl, false, |c| shld_step(c, width));
    } else {
        step_count(c, width, OfKind::Shrd, false, |c| shrd_step(c, width));
    }
}

fn step_count<F>(c: &mut Cursor<'_>, width: u32, of: OfKind, rotate: bool, step: F)
where
    F: FnOnce(&mut Cursor<'_>),
{
    repeat(c, T2, step);
    finish(c, width, of, rotate);
}

fn repeat<F>(c: &mut Cursor<'_>, counter: u16, body: F)
where
    F: FnOnce(&mut Cursor<'_>),
{
    let head = c.alloc();
    let body_id = c.alloc();
    let after = c.alloc();
    let ops = std::mem::take(&mut c.ops);
    c.seal_at(c.block, ops, Exit::Jmp(head));
    c.seal_at(
        head,
        vec![Step::Gp(Op::TestRr(counter, counter))],
        Exit::Jcc(4, after, body_id),
    );
    c.block = body_id;
    body(c);
    // The trip count is not an architectural add. Keep the AF that `body` left.
    c.emit(Op::MovRr(crate::ir::V_TMP0, AF));
    c.emit(Op::AddRi(counter, -1));
    c.emit(Op::MovRr(AF, crate::ir::V_TMP0));
    let ops = std::mem::take(&mut c.ops);
    c.seal_at(c.block, ops, Exit::Jmp(head));
    c.block = after;
}

fn finish(c: &mut Cursor<'_>, width: u32, of: OfKind, rotate: bool) {
    c.emit(Op::MovRr(T2, IMM));
    c.emit(Op::AndRi(T2, 1));
    if rotate {
        c.emit(Op::MovRr(T1, SAVE));
    } else {
        flags_from_result(c, T0, T1, width);
    }
    c.emit(Op::AndRi(T1, !1));
    c.emit(Op::OrRr(T1, T2));
    overflow_bit(c, width, of);
    c.emit(Op::Shl(T3, 11));
    c.emit(Op::AndRi(T1, !0x800));
    c.emit(Op::OrRr(T1, T3));
    c.emit(Op::MovRr(SAVE, T1));
    if !rotate {
        c.emit(Op::MovRi(AF, 0));
    }
}

fn flags_from_result(c: &mut Cursor<'_>, value: u16, flags: u16, width: u32) {
    c.emit(Op::MovRr(T3, value));
    if width < 64 {
        c.emit(Op::Shl(T3, (64 - width) as u8));
    }
    c.emit(Op::TestRr(T3, T3));
    c.emit(Op::StFlags(flags));
    fix_parity(c, value, flags);
}

fn overflow_bit(c: &mut Cursor<'_>, width: u32, kind: OfKind) {
    let sign = (width - 1) as u8;
    match kind {
        OfKind::Shl => {
            bit_at(c, T0, sign);
            c.emit(Op::XorRr(T3, T2));
            c.emit(Op::AndRi(T3, 1));
        }
        OfKind::Shr => bit_at(c, ADDR, sign),
        OfKind::Sar => c.emit(Op::MovRi(T3, 0)),
        OfKind::Ror => {
            bit_at(c, T0, sign);
            c.emit(Op::MovRr(IMM, T0));
            c.emit(Op::Shr(IMM, sign - 1));
            c.emit(Op::AndRi(IMM, 1));
            c.emit(Op::XorRr(T3, IMM));
            c.emit(Op::AndRi(T3, 1));
        }
        OfKind::Shrd => {
            c.emit(Op::MovRr(T3, ADDR));
            c.emit(Op::XorRr(T3, T0));
            c.emit(Op::MovRi(IMM, 1u64 << (width - 1)));
            c.emit(Op::AndRr(T3, IMM));
            c.emit(Op::Shr(T3, sign));
        }
    }
}

fn bit_at(c: &mut Cursor<'_>, src: u16, shift: u8) {
    c.emit(Op::MovRr(T3, src));
    if shift > 0 {
        c.emit(Op::Shr(T3, shift));
    }
    c.emit(Op::AndRi(T3, 1));
}

fn shl_step(c: &mut Cursor<'_>, width: u32) {
    bit_at(c, T0, (width - 1) as u8);
    c.emit(Op::Shl(T0, 1));
    mask_reg(c, T0, width);
    c.emit(Op::MovRr(IMM, T3));
}

fn shr_step(c: &mut Cursor<'_>, width: u32) {
    bit_at(c, T0, 0);
    c.emit(Op::Shr(T0, 1));
    mask_reg(c, T0, width);
    c.emit(Op::MovRr(IMM, T3));
}

fn sar_step(c: &mut Cursor<'_>, width: u32) {
    bit_at(c, T0, 0);
    c.emit(Op::MovRr(T1, T3));
    bit_at(c, T0, (width - 1) as u8);
    c.emit(Op::Shr(T0, 1));
    c.emit(Op::Shl(T3, (width - 1) as u8));
    c.emit(Op::OrRr(T0, T3));
    mask_reg(c, T0, width);
    c.emit(Op::MovRr(IMM, T1));
}

fn rol_step(c: &mut Cursor<'_>, width: u32) {
    bit_at(c, T0, (width - 1) as u8);
    c.emit(Op::Shl(T0, 1));
    c.emit(Op::OrRr(T0, T3));
    mask_reg(c, T0, width);
    c.emit(Op::MovRr(IMM, T3));
}

fn ror_step(c: &mut Cursor<'_>, width: u32) {
    bit_at(c, T0, 0);
    c.emit(Op::MovRr(T1, T3));
    c.emit(Op::Shr(T0, 1));
    c.emit(Op::Shl(T1, (width - 1) as u8));
    c.emit(Op::OrRr(T0, T1));
    mask_reg(c, T0, width);
    c.emit(Op::MovRr(IMM, T3));
}

fn rcl_step(c: &mut Cursor<'_>, width: u32) {
    bit_at(c, T0, (width - 1) as u8);
    c.emit(Op::Shl(T0, 1));
    c.emit(Op::OrRr(T0, IMM));
    mask_reg(c, T0, width);
    c.emit(Op::MovRr(IMM, T3));
}

fn rcr_step(c: &mut Cursor<'_>, width: u32) {
    bit_at(c, T0, 0);
    c.emit(Op::Shr(T0, 1));
    c.emit(Op::MovRr(T1, IMM));
    c.emit(Op::Shl(T1, (width - 1) as u8));
    c.emit(Op::OrRr(T0, T1));
    mask_reg(c, T0, width);
    c.emit(Op::MovRr(IMM, T3));
}

fn shld_step(c: &mut Cursor<'_>, width: u32) {
    bit_at(c, T0, (width - 1) as u8);
    c.emit(Op::Shl(T0, 1));
    c.emit(Op::MovRr(IMM, T1));
    c.emit(Op::Shr(IMM, (width - 1) as u8));
    c.emit(Op::AndRi(IMM, 1));
    c.emit(Op::OrRr(T0, IMM));
    mask_reg(c, T0, width);
    c.emit(Op::Shl(T1, 1));
    mask_reg(c, T1, width);
    c.emit(Op::MovRr(IMM, T3));
}

fn shrd_step(c: &mut Cursor<'_>, width: u32) {
    bit_at(c, T0, 0);
    c.emit(Op::Shr(T0, 1));
    c.emit(Op::MovRr(IMM, T1));
    c.emit(Op::AndRi(IMM, 1));
    c.emit(Op::Shl(IMM, (width - 1) as u8));
    c.emit(Op::OrRr(T0, IMM));
    mask_reg(c, T0, width);
    c.emit(Op::Shr(T1, 1));
    mask_reg(c, T1, width);
    c.emit(Op::MovRr(IMM, T3));
}

fn write_dest(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64, width: u32) -> Result<()> {
    if insn.op0_kind() == OpKind::Register {
        write_reg(c, insn.op_register(0), T0)
    } else {
        materialize(c, insn, image_base)?;
        store_width(c, T0, (width / 8) as usize)
    }
}

fn mul(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    if insn.mnemonic() == Mnemonic::Mul || insn.op_count() == 1 {
        return mul_wide(c, insn, image_base);
    }
    let width = operand_bits(insn, 0);
    if insn.op_count() == 3 {
        read_value(c, insn, 1, T0, image_base)?;
        read_value(c, insn, 2, T1, image_base)?;
    } else {
        read_value(c, insn, 0, T0, image_base)?;
        read_value(c, insn, 1, T1, image_base)?;
    }
    mask_reg(c, T0, width);
    mask_reg(c, T1, width);
    if width < 64 {
        sign_to(c, T0, width);
        sign_to(c, T1, width);
    }
    c.emit(Op::ImulRr(T0, T1));
    if width < 64 {
        c.emit(Op::MovRr(T2, T0));
        mask_reg(c, T2, width);
        c.emit(Op::MovRr(T3, T2));
        sign_to(c, T3, width);
        c.emit(Op::CmpRr(T0, T3));
        c.emit(Op::StFlags(T1));
        c.emit(Op::MovRr(T3, T1));
        c.emit(Op::Shr(T3, 6));
        c.emit(Op::AndRi(T3, 1));
        c.emit(Op::XorRi(T3, 1));
        c.emit(Op::MovRr(T0, T2));
    } else {
        c.emit(Op::StFlags(SAVE));
        c.emit(Op::MovRr(T3, SAVE));
        c.emit(Op::AndRi(T3, 1));
    }
    carry_flags(c);
    c.emit(Op::MovRi(AF, 0));
    if insn.op0_kind() == OpKind::Register {
        write_reg(c, insn.op_register(0), T0)?;
    }
    c.emit(Op::LdFlags(SAVE));
    Ok(())
}

fn mul_wide(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let width = operand_bits(insn, 0);
    let signed = insn.mnemonic() == Mnemonic::Imul;
    read_value(c, insn, 0, T1, image_base)?;
    mask_reg(c, T1, width);
    copy_masked_index(c, T0, RAX, width);
    if width >= 64 {
        widen64(c);
        mul_carry64(c, signed);
        c.emit(Op::MovRi(AF, 0));
        c.emit(Op::LdFlags(SAVE));
        return Ok(());
    }
    if signed {
        sign_to(c, T0, width);
        sign_to(c, T1, width);
    }
    c.emit(Op::ImulRr(T0, T1));
    c.emit(Op::MovRr(T2, T0));
    mask_reg(c, T2, width);
    c.emit(Op::MovRr(ADDR, T0));
    c.emit(Op::Shr(ADDR, width as u8));
    mask_reg(c, ADDR, width);
    if signed {
        c.emit(Op::MovRr(T3, T2));
        sign_to(c, T3, width);
        c.emit(Op::CmpRr(T0, T3));
        c.emit(Op::StFlags(T1));
        c.emit(Op::MovRr(T3, T1));
        c.emit(Op::Shr(T3, 6));
        c.emit(Op::AndRi(T3, 1));
        c.emit(Op::XorRi(T3, 1));
    } else {
        c.emit(Op::TestRr(ADDR, ADDR));
        c.emit(Op::StFlags(T1));
        c.emit(Op::MovRr(T3, T1));
        c.emit(Op::Shr(T3, 6));
        c.emit(Op::AndRi(T3, 1));
        c.emit(Op::XorRi(T3, 1));
    }
    carry_flags(c);
    c.emit(Op::MovRi(AF, 0));
    store_pair(c, T2, ADDR, width);
    c.emit(Op::LdFlags(SAVE));
    Ok(())
}

fn carry_flags(c: &mut Cursor<'_>) {
    c.emit(Op::MovRi(SAVE, 0));
    c.emit(Op::OrRr(SAVE, T3));
    c.emit(Op::Shl(T3, 11));
    c.emit(Op::OrRr(SAVE, T3));
}

fn widen64(c: &mut Cursor<'_>) {
    c.emit(Op::MovRr(ADDR, T0));
    c.emit(Op::MovRr(IMM, T1));
    mul32(c, false, false);
    c.emit(Op::MovRr(RAX, T0));
    mask32(c, RAX);
    c.emit(Op::MovRr(RDX, T0));
    c.emit(Op::Shr(RDX, 32));
    mul32(c, false, true);
    fold_low(c, true);
    mul32(c, true, false);
    fold_low(c, false);
    mul32(c, true, true);
    c.emit(Op::MovRr(T1, T0));
    mask32(c, T1);
    c.emit(Op::AddRr(T2, T1));
    c.emit(Op::Shr(T0, 32));
    c.emit(Op::MovRr(T1, RDX));
    c.emit(Op::Shr(T1, 32));
    c.emit(Op::AddRr(T2, T1));
    mask32(c, RDX);
    c.emit(Op::Shl(RDX, 32));
    c.emit(Op::OrRr(RAX, RDX));
    c.emit(Op::MovRr(T1, T2));
    c.emit(Op::Shr(T1, 32));
    c.emit(Op::AddRr(T0, T1));
    c.emit(Op::Shl(T0, 32));
    mask32(c, T2);
    c.emit(Op::OrRr(T0, T2));
    c.emit(Op::MovRr(RDX, T0));
}

fn fold_low(c: &mut Cursor<'_>, first: bool) {
    c.emit(Op::MovRr(T1, T0));
    mask32(c, T1);
    c.emit(Op::AddRr(RDX, T1));
    c.emit(Op::Shr(T0, 32));
    if first {
        c.emit(Op::MovRr(T2, T0));
    } else {
        c.emit(Op::AddRr(T2, T0));
    }
}

fn mul32(c: &mut Cursor<'_>, a_hi: bool, b_hi: bool) {
    c.emit(Op::MovRr(T0, ADDR));
    if a_hi {
        c.emit(Op::Shr(T0, 32));
    }
    mask32(c, T0);
    c.emit(Op::MovRr(T3, IMM));
    if b_hi {
        c.emit(Op::Shr(T3, 32));
    }
    mask32(c, T3);
    c.emit(Op::ImulRr(T0, T3));
}

fn mask32(c: &mut Cursor<'_>, reg: u16) {
    c.emit(Op::Shl(reg, 32));
    c.emit(Op::Shr(reg, 32));
}

fn mul_carry64(c: &mut Cursor<'_>, signed: bool) {
    if signed {
        c.emit(Op::MovRr(T1, RAX));
        c.emit(Op::Sar(T1, 63));
        c.emit(Op::CmpRr(T1, RDX));
    } else {
        c.emit(Op::TestRr(RDX, RDX));
    }
    c.emit(Op::StFlags(T1));
    c.emit(Op::MovRr(T3, T1));
    c.emit(Op::Shr(T3, 6));
    c.emit(Op::AndRi(T3, 1));
    c.emit(Op::XorRi(T3, 1));
    carry_flags(c);
}

fn div(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let width = operand_bits(insn, 0);
    let signed = insn.mnemonic() == Mnemonic::Idiv;
    read_value(c, insn, 0, T1, image_base)?;
    mask_reg(c, T1, width);
    c.emit(Op::TestRr(T1, T1));
    c.cbranch(
        4,
        |c| {
            c.emit(Op::MovRi(T0, 0));
            c.emit(Op::Div(T0));
        },
        |c| divide_value(c, width, signed),
    );
    Ok(())
}

fn divide_value(c: &mut Cursor<'_>, width: u32, signed: bool) {
    if width >= 64 {
        if signed {
            idiv64(c);
        } else {
            c.emit(Op::Div(T1));
        }
        return;
    }
    assemble_dividend(c, T0, width, signed);
    if signed {
        c.emit(Op::MovRi(SAVE, 0));
        park_sign(c, T0, width * 2, 0);
        park_sign(c, T1, width, 1);
        absolute(c, T0, width * 2);
        absolute(c, T1, width);
    }
    let bits = width * 2;
    if bits < 64 {
        c.emit(Op::Shl(T0, (64 - bits) as u8));
    }
    c.emit(Op::MovRi(T2, 0));
    c.emit(Op::MovRi(T3, 0));
    c.emit(Op::MovRi(ADDR, u64::from(bits)));
    repeat(c, ADDR, div_step);
    if signed {
        signed_range(c, width);
        apply_signs(c, width);
    } else {
        unsigned_range(c, width);
    }
    store_pair(c, T3, T2, width);
}

fn park_sign(c: &mut Cursor<'_>, reg: u16, width: u32, bit: u8) {
    c.emit(Op::MovRr(IMM, reg));
    c.emit(Op::Shr(IMM, (width - 1) as u8));
    c.emit(Op::AndRi(IMM, 1));
    if bit > 0 {
        c.emit(Op::Shl(IMM, bit));
    }
    c.emit(Op::OrRr(SAVE, IMM));
}

fn absolute(c: &mut Cursor<'_>, reg: u16, width: u32) {
    c.emit(Op::MovRr(IMM, reg));
    c.emit(Op::Shr(IMM, (width - 1) as u8));
    c.emit(Op::AndRi(IMM, 1));
    c.emit(Op::TestRr(IMM, IMM));
    c.cbranch(
        4,
        |_| {},
        |c| {
            c.emit(Op::Neg(reg));
            mask_reg(c, reg, width);
        },
    );
}

fn div_step(c: &mut Cursor<'_>) {
    c.emit(Op::MovRr(IMM, T0));
    c.emit(Op::Shr(IMM, 63));
    c.emit(Op::Shl(T0, 1));
    c.emit(Op::Shl(T2, 1));
    c.emit(Op::OrRr(T2, IMM));
    c.emit(Op::CmpRr(T2, T1));
    c.cbranch(
        2,
        |c| c.emit(Op::Shl(T3, 1)),
        |c| {
            c.emit(Op::SubRr(T2, T1));
            c.emit(Op::Shl(T3, 1));
            c.emit(Op::OrRi(T3, 1));
        },
    );
}

fn unsigned_range(c: &mut Cursor<'_>, width: u32) {
    c.emit(Op::MovRi(IMM, (1u64 << width) - 1));
    c.emit(Op::CmpRr(T3, IMM));
    c.cbranch(7, |c| force_overflow(c), |_| {});
}

fn signed_range(c: &mut Cursor<'_>, width: u32) {
    let negative = 1u64 << (width - 1);
    let positive = negative - 1;
    negative_quotient(c);
    c.cbranch(
        4,
        |c| range_above(c, positive),
        |c| range_above(c, negative),
    );
}

fn negative_quotient(c: &mut Cursor<'_>) {
    c.emit(Op::MovRr(ADDR, SAVE));
    c.emit(Op::AndRi(ADDR, 1));
    c.emit(Op::MovRr(IMM, SAVE));
    c.emit(Op::Shr(IMM, 1));
    c.emit(Op::AndRi(IMM, 1));
    c.emit(Op::XorRr(IMM, ADDR));
    c.emit(Op::TestRr(IMM, IMM));
}

fn range_above(c: &mut Cursor<'_>, limit: u64) {
    c.emit(Op::MovRi(IMM, limit));
    c.emit(Op::CmpRr(T3, IMM));
    c.cbranch(7, |c| force_overflow(c), |_| {});
}

fn apply_signs(c: &mut Cursor<'_>, width: u32) {
    negative_quotient(c);
    c.cbranch(
        4,
        |_| {},
        |c| {
            c.emit(Op::Neg(T3));
            mask_reg(c, T3, width);
        },
    );
    c.emit(Op::MovRr(IMM, SAVE));
    c.emit(Op::AndRi(IMM, 1));
    c.emit(Op::TestRr(IMM, IMM));
    c.cbranch(
        4,
        |_| {},
        |c| {
            c.emit(Op::Neg(T2));
            mask_reg(c, T2, width);
        },
    );
}

fn idiv64(c: &mut Cursor<'_>) {
    c.emit(Op::MovRi(IMM, 1u64 << 63));
    c.emit(Op::CmpRr(RDX, IMM));
    c.cbranch(
        4,
        |c| {
            c.emit(Op::TestRr(RAX, RAX));
            c.cbranch(4, |c| force_overflow(c), |_| {});
        },
        |_| {},
    );
    c.emit(Op::MovRr(T2, RDX));
    c.emit(Op::Shr(T2, 63));
    c.emit(Op::MovRr(T3, T1));
    c.emit(Op::Shr(T3, 63));
    c.emit(Op::Shl(T3, 1));
    c.emit(Op::OrRr(T2, T3));
    c.emit(Op::MovRr(SAVE, T2));
    c.emit(Op::TestRr(T1, T1));
    c.cbranch(8, |c| c.emit(Op::Neg(T1)), |_| {});
    c.emit(Op::TestRr(RDX, RDX));
    c.cbranch(8, |c| neg128(c), |_| {});
    c.emit(Op::CmpRr(RDX, T1));
    c.cbranch(3, |c| force_overflow(c), |_| {});
    c.emit(Op::Div(T1));
    negative_quotient(c);
    c.cbranch(
        4,
        |c| {
            c.emit(Op::MovRi(IMM, i64::MAX as u64));
            c.emit(Op::CmpRr(RAX, IMM));
            c.cbranch(7, |c| force_overflow(c), |_| {});
        },
        |c| {
            c.emit(Op::MovRi(IMM, 1u64 << 63));
            c.emit(Op::CmpRr(RAX, IMM));
            c.cbranch(7, |c| force_overflow(c), |_| {});
            c.emit(Op::Neg(RAX));
        },
    );
    c.emit(Op::MovRr(IMM, SAVE));
    c.emit(Op::AndRi(IMM, 1));
    c.emit(Op::TestRr(IMM, IMM));
    c.cbranch(4, |_| {}, |c| c.emit(Op::Neg(RDX)));
}

fn neg128(c: &mut Cursor<'_>) {
    c.emit(Op::Not(RAX));
    c.emit(Op::Not(RDX));
    c.emit(Op::AddRi(RAX, 1));
    c.emit(Op::StFlags(T0));
    c.emit(Op::AndRi(T0, 1));
    c.emit(Op::AddRr(RDX, T0));
}

fn force_overflow(c: &mut Cursor<'_>) {
    c.emit(Op::MovRi(RAX, u64::MAX));
    c.emit(Op::MovRi(RDX, 1));
    c.emit(Op::MovRi(T0, 1));
    c.emit(Op::Div(T0));
}
fn xchg(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    preserve(c, |c| {
        read_value(c, insn, 0, T0, image_base)?;
        read_value(c, insn, 1, T1, image_base)?;
        if insn.op0_kind() == OpKind::Memory {
            materialize(c, insn, image_base)?;
            store_width(c, T1, width_bytes(insn, 0))?;
        } else {
            write_reg(c, insn.op_register(0), T1)?;
        }
        if insn.op1_kind() == OpKind::Register {
            write_reg(c, insn.op_register(1), T0)?;
        }
        Ok(())
    })
}

fn xadd(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let width = operand_bits(insn, 0);
    read_value(c, insn, 0, T0, image_base)?;
    read_value(c, insn, 1, T1, image_base)?;
    mask_reg(c, T0, width);
    mask_reg(c, T1, width);
    arith_keep(c, true, width);
    c.emit(Op::MovRr(SAVE, T1));
    c.emit(Op::MovRr(T1, ADDR));
    if insn.op0_kind() == OpKind::Memory {
        materialize(c, insn, image_base)?;
        store_width(c, T0, (width / 8) as usize)?;
        write_reg(c, insn.op_register(1), T1)?;
    } else {
        write_reg(c, insn.op_register(1), T1)?;
        write_reg(c, insn.op_register(0), T0)?;
    }
    c.emit(Op::LdFlags(SAVE));
    Ok(())
}

/// `T0` is the left operand and `T1` the right one. The sum or difference
/// stays in `T0`, the flag image in `T1`, and the original operands in
/// `ADDR` and `T2`. `SAVE` is left untouched.
fn arith_keep(c: &mut Cursor<'_>, add: bool, width: u32) {
    c.emit(Op::MovRr(T2, T1));
    c.emit(Op::MovRr(ADDR, T0));
    align(c, T0, width);
    align(c, T1, width);
    if add {
        c.emit(Op::AddRr(T0, T1));
    } else {
        c.emit(Op::SubRr(T0, T1));
    }
    c.emit(Op::StFlags(T1));
    unalign(c, T0, width);
    fix_parity(c, T0, T1);
    aux(c, ADDR, T2, T0);
}

fn cmpxchg(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let width = operand_bits(insn, 0);
    read_value(c, insn, 0, T0, image_base)?;
    read_value(c, insn, 1, T1, image_base)?;
    mask_reg(c, T0, width);
    mask_reg(c, T1, width);
    c.emit(Op::MovRr(SAVE, T1));
    c.emit(Op::MovRr(T1, T0));
    copy_reg(c, T0, acc_reg(width))?;
    arith_keep(c, false, width);
    c.emit(Op::MovRr(T0, SAVE));
    c.emit(Op::MovRr(SAVE, T1));
    c.emit(Op::LdFlags(SAVE));
    let dest = insn.op_register(0);
    let memory = insn.op0_kind() == OpKind::Memory;
    c.cbranch(
        4,
        |c| {
            if memory {
                let _ = materialize(c, insn, image_base);
                let _ = store_width(c, T0, (width / 8) as usize);
            } else {
                let _ = write_reg(c, dest, T0);
            }
        },
        |c| {
            let _ = write_reg(c, acc_reg(width), T2);
        },
    );
    c.emit(Op::LdFlags(SAVE));
    Ok(())
}

fn cmpxchg_wide(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    // Original status flags stay in SAVE. Only ZF is replaced afterwards.
    // Compares and address arithmetic also write the AF register; put it back.
    c.emit(Op::MovRr(crate::ir::V_TMP0, AF));
    c.emit(Op::StFlags(SAVE));
    materialize(c, insn, image_base)?;
    if insn.mnemonic() == Mnemonic::Cmpxchg8b {
        c.emit(Op::Load64(T0, ADDR));
        c.emit(Op::MovRr(T1, RAX));
        mask_reg(c, T1, 32);
        c.emit(Op::MovRr(T2, RDX));
        mask_reg(c, T2, 32);
        c.emit(Op::Shl(T2, 32));
        c.emit(Op::OrRr(T1, T2));
        c.emit(Op::CmpRr(T0, T1));
        c.emit(Op::StFlags(T3));
        c.cbranch(
            4,
            |c| {
                c.emit(Op::MovRr(T1, RBX));
                mask_reg(c, T1, 32);
                c.emit(Op::MovRr(T2, RCX));
                mask_reg(c, T2, 32);
                c.emit(Op::Shl(T2, 32));
                c.emit(Op::OrRr(T1, T2));
                c.emit(Op::Store64(ADDR, T1));
            },
            |c| {
                c.emit(Op::MovRr(RAX, T0));
                mask_reg(c, RAX, 32);
                c.emit(Op::MovRr(RDX, T0));
                c.emit(Op::Shr(RDX, 32));
            },
        );
        c.emit(Op::MovRr(IMM, T3));
        c.emit(Op::Shr(IMM, 6));
    } else {
        c.emit(Op::Load64(T0, ADDR));
        c.emit(Op::MovRr(T2, ADDR));
        c.emit(Op::AddRi(T2, 8));
        c.emit(Op::Load64(T1, T2));
        c.emit(Op::CmpRr(T0, RAX));
        c.cbranch(
            5,
            |c| {
                c.emit(Op::MovRr(RAX, T0));
                c.emit(Op::MovRr(RDX, T1));
                c.emit(Op::MovRi(IMM, 0));
            },
            |c| {
                c.emit(Op::CmpRr(T1, RDX));
                c.cbranch(
                    5,
                    |c| {
                        c.emit(Op::MovRr(RAX, T0));
                        c.emit(Op::MovRr(RDX, T1));
                        c.emit(Op::MovRi(IMM, 0));
                    },
                    |c| {
                        c.emit(Op::Store64(ADDR, RBX));
                        c.emit(Op::Store64(T2, RCX));
                        c.emit(Op::MovRi(IMM, 1));
                    },
                );
            },
        );
    }
    merge_zf(c);
    c.emit(Op::MovRr(AF, crate::ir::V_TMP0));
    Ok(())
}

fn merge_zf(c: &mut Cursor<'_>) {
    c.emit(Op::AndRi(IMM, 1));
    c.emit(Op::Shl(IMM, 6));
    c.emit(Op::AndRi(SAVE, !0x40));
    c.emit(Op::OrRr(SAVE, IMM));
    c.emit(Op::LdFlags(SAVE));
}

fn bswap(c: &mut Cursor<'_>, insn: &Instruction) -> Result<()> {
    let reg = insn.op_register(0);
    let bytes = reg.size();
    if bytes < 4 {
        return Err(super::bad(insn));
    }
    preserve(c, |c| {
        c.emit(Op::MovRr(T0, super::gpr_index(reg)?));
        c.emit(Op::MovRi(T1, 0));
        for index in 0..bytes {
            c.emit(Op::MovRr(T2, T0));
            if index > 0 {
                c.emit(Op::Shr(T2, (index * 8) as u8));
            }
            c.emit(Op::AndRi(T2, 0xff));
            let place = (bytes - 1 - index) * 8;
            if place > 0 {
                c.emit(Op::Shl(T2, place as u8));
            }
            c.emit(Op::OrRr(T1, T2));
        }
        c.emit(Op::MovRr(super::gpr_index(reg)?, T1));
        if bytes == 4 {
            mask_reg(c, super::gpr_index(reg)?, 32);
        }
        Ok(())
    })
}

fn bitscan(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let width = operand_bits(insn, 1);
    let msb = insn.mnemonic() == Mnemonic::Bsr;
    read_value(c, insn, 1, T0, image_base)?;
    mask_reg(c, T0, width);
    c.emit(Op::MovRi(T2, 0));
    let order: Vec<u32> = if msb {
        (0..width).rev().collect()
    } else {
        (0..width).collect()
    };
    for bit in order {
        c.emit(Op::MovRr(T1, T0));
        if bit > 0 {
            c.emit(Op::Shr(T1, bit as u8));
        }
        c.emit(Op::AndRi(T1, 1));
        c.emit(Op::TestRr(T1, T1));
        let dest = insn.op_register(0);
        let kind = insn.op0_kind();
        c.cbranch(
            5,
            |c| {
                c.emit(Op::TestRr(T2, T2));
                c.cbranch(
                    4,
                    |c| {
                        c.emit(Op::MovRi(T1, u64::from(bit)));
                        if kind == OpKind::Register {
                            let _ = write_reg(c, dest, T1);
                        }
                        c.emit(Op::MovRi(T2, 1));
                    },
                    |_| {},
                );
            },
            |_| {},
        );
    }
    c.emit(Op::TestRr(T2, T2));
    c.emit(Op::MovRi(AF, 0));
    Ok(())
}

fn bit(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let width = operand_bits(insn, 0);
    c.emit(Op::StFlags(SAVE));
    if insn.op0_kind() == OpKind::Register {
        read_value(c, insn, 0, T0, image_base)?;
        read_bit_offset(c, insn, image_base)?;
        c.emit(Op::MovRi(IMM, u64::from(width - 1)));
        c.emit(Op::AndRr(T1, IMM));
        extract_bit(c);
        c.emit(Op::AndRi(SAVE, !1));
        c.emit(Op::OrRr(SAVE, T3));
        modify_bit(c, insn.mnemonic(), width);
        if insn.mnemonic() != Mnemonic::Bt {
            write_reg(c, insn.op_register(0), T0)?;
        }
    } else {
        materialize(c, insn, image_base)?;
        read_bit_offset(c, insn, image_base)?;
        c.emit(Op::MovRr(T2, T1));
        c.emit(Op::Sar(T2, 3));
        c.emit(Op::AddRr(ADDR, T2));
        c.emit(Op::AndRi(T1, 7));
        c.emit(Op::Load8(T0, ADDR));
        extract_bit(c);
        c.emit(Op::AndRi(SAVE, !1));
        c.emit(Op::OrRr(SAVE, T3));
        modify_bit(c, insn.mnemonic(), 8);
        if insn.mnemonic() != Mnemonic::Bt {
            c.emit(Op::Store8(ADDR, T0));
        }
    }
    c.emit(Op::LdFlags(SAVE));
    c.emit(Op::MovRi(AF, 0));
    Ok(())
}

fn convert(c: &mut Cursor<'_>, insn: &Instruction) -> Result<()> {
    preserve(c, |c| {
        match insn.mnemonic() {
            Mnemonic::Cbw => {
                copy_masked_index(c, T0, RAX, 8);
                sign_to(c, T0, 8);
                merge_low(c, RAX, T0, 16);
            }
            Mnemonic::Cwde => {
                copy_masked_index(c, T0, RAX, 16);
                sign_to(c, T0, 16);
                mask_reg(c, T0, 32);
                c.emit(Op::MovRr(RAX, T0));
            }
            Mnemonic::Cdqe => {
                copy_masked_index(c, T0, RAX, 32);
                sign_to(c, T0, 32);
                c.emit(Op::MovRr(RAX, T0));
            }
            Mnemonic::Cwd => {
                copy_masked_index(c, T0, RAX, 16);
                c.emit(Op::Shr(T0, 15));
                c.emit(Op::AndRi(T0, 1));
                c.emit(Op::Neg(T0));
                mask_reg(c, T0, 16);
                merge_low(c, RDX, T0, 16);
            }
            Mnemonic::Cdq => {
                copy_masked_index(c, T0, RAX, 32);
                c.emit(Op::Shr(T0, 31));
                c.emit(Op::AndRi(T0, 1));
                c.emit(Op::Neg(T0));
                mask_reg(c, T0, 32);
                c.emit(Op::MovRr(RDX, T0));
            }
            Mnemonic::Cqo => {
                c.emit(Op::MovRr(RDX, RAX));
                c.emit(Op::Sar(RDX, 63));
            }
            _ => {}
        }
        Ok(())
    })
}

fn flag_op(c: &mut Cursor<'_>, insn: &Instruction) -> Result<()> {
    match insn.mnemonic() {
        Mnemonic::Cld => c.emit(Op::MovRi(DF, 0)),
        Mnemonic::Std => c.emit(Op::MovRi(DF, 1)),
        Mnemonic::Clc => {
            c.emit(Op::StFlags(SAVE));
            c.emit(Op::AndRi(SAVE, !1));
            c.emit(Op::LdFlags(SAVE));
        }
        Mnemonic::Stc => {
            c.emit(Op::StFlags(SAVE));
            c.emit(Op::OrRi(SAVE, 1));
            c.emit(Op::LdFlags(SAVE));
        }
        Mnemonic::Cmc => {
            c.emit(Op::StFlags(SAVE));
            c.emit(Op::MovRr(T0, SAVE));
            c.emit(Op::AndRi(T0, 1));
            c.emit(Op::XorRi(T0, 1));
            c.emit(Op::AndRi(SAVE, !1));
            c.emit(Op::OrRr(SAVE, T0));
            c.emit(Op::LdFlags(SAVE));
        }
        _ => {}
    }
    Ok(())
}

fn lahf_sahf(c: &mut Cursor<'_>, insn: &Instruction) -> Result<()> {
    if insn.mnemonic() == Mnemonic::Lahf {
        c.emit(Op::StFlags(SAVE));
        c.emit(Op::MovRi(T0, 2));
        for (flag_bit, dest_bit) in [(0u8, 0u8), (2, 2), (6, 6), (7, 7)] {
            c.emit(Op::MovRr(T1, SAVE));
            c.emit(Op::Shr(T1, flag_bit));
            c.emit(Op::AndRi(T1, 1));
            if dest_bit > 0 {
                c.emit(Op::Shl(T1, dest_bit));
            }
            c.emit(Op::OrRr(T0, T1));
        }
        c.emit(Op::MovRr(T1, AF));
        c.emit(Op::AndRi(T1, 1));
        c.emit(Op::Shl(T1, 4));
        c.emit(Op::OrRr(T0, T1));
        c.emit(Op::Shl(T0, 8));
        c.emit(Op::MovRi(IMM, !0xff00u64));
        c.emit(Op::AndRr(RAX, IMM));
        c.emit(Op::OrRr(RAX, T0));
        c.emit(Op::LdFlags(SAVE));
        return Ok(());
    }
    c.emit(Op::MovRr(T0, RAX));
    c.emit(Op::Shr(T0, 8));
    c.emit(Op::AndRi(T0, 0xff));
    c.emit(Op::StFlags(SAVE));
    c.emit(Op::AndRi(SAVE, !0xc5));
    for (src_bit, flag_bit) in [(0u8, 0u8), (2, 2), (6, 6), (7, 7)] {
        c.emit(Op::MovRr(T1, T0));
        if src_bit > 0 {
            c.emit(Op::Shr(T1, src_bit));
        }
        c.emit(Op::AndRi(T1, 1));
        if flag_bit > 0 {
            c.emit(Op::Shl(T1, flag_bit));
        }
        c.emit(Op::OrRr(SAVE, T1));
    }
    c.emit(Op::MovRr(T1, T0));
    c.emit(Op::Shr(T1, 4));
    c.emit(Op::AndRi(T1, 1));
    c.emit(Op::MovRr(AF, T1));
    c.emit(Op::LdFlags(SAVE));
    Ok(())
}

fn frame(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let _ = image_base;
    let narrow = match insn.code() {
        Code::Enterd_imm16_imm8 | Code::Leaved => return Err(super::bad(insn)),
        Code::Enterw_imm16_imm8 | Code::Leavew => true,
        _ => false,
    };
    if narrow {
        return frame16(c, insn);
    }
    if insn.mnemonic() == Mnemonic::Leave {
        preserve(c, |c| {
            c.emit(Op::MovRr(RSP, RBP));
            c.emit(Op::Pop(RBP));
            Ok(())
        })?;
        return Ok(());
    }
    let alloc = i32::from(insn.immediate16());
    let level = u32::from(insn.immediate8_2nd()) & 31;
    preserve(c, |c| {
        c.emit(Op::Push(RBP));
        c.emit(Op::MovRr(T0, RSP));
        for _ in 1..level {
            c.emit(Op::AddRi(RBP, -8));
            c.emit(Op::Load64(T1, RBP));
            c.emit(Op::Push(T1));
        }
        if level > 0 {
            c.emit(Op::Push(T0));
        }
        c.emit(Op::MovRr(RBP, T0));
        if alloc != 0 {
            c.emit(Op::SubRi(RSP, alloc));
        }
        Ok(())
    })
}

fn frame16(c: &mut Cursor<'_>, insn: &Instruction) -> Result<()> {
    if insn.mnemonic() == Mnemonic::Leave {
        return preserve(c, |c| {
            c.emit(Op::MovRr(T0, RBP));
            c.emit(Op::AndRi(T0, 0xffff));
            c.emit(Op::MovRi(IMM, !0xffffu64));
            c.emit(Op::AndRr(RSP, IMM));
            c.emit(Op::OrRr(RSP, T0));
            c.emit(Op::MovRr(ADDR, RSP));
            load_width(c, T0, 2)?;
            c.emit(Op::AddRi(RSP, 2));
            merge_low(c, RBP, T0, 16);
            Ok(())
        });
    }
    let alloc = i32::from(insn.immediate16());
    let level = u32::from(insn.immediate8_2nd()) & 31;
    preserve(c, |c| {
        c.emit(Op::MovRr(T0, RBP));
        c.emit(Op::AndRi(T0, 0xffff));
        push_low(c, T0, 2)?;
        c.emit(Op::MovRr(T0, RSP));
        for _ in 1..level {
            c.emit(Op::MovRr(T1, RBP));
            c.emit(Op::AndRi(T1, 0xffff));
            c.emit(Op::AddRi(T1, -2));
            c.emit(Op::AndRi(T1, 0xffff));
            merge_low(c, RBP, T1, 16);
            c.emit(Op::MovRr(ADDR, T1));
            load_width(c, T2, 2)?;
            push_low(c, T2, 2)?;
        }
        if level > 0 {
            push_low(c, T0, 2)?;
        }
        merge_low(c, RBP, T0, 16);
        if alloc != 0 {
            c.emit(Op::SubRi(RSP, alloc));
        }
        Ok(())
    })
}

fn push_low(c: &mut Cursor<'_>, src: u16, bytes: usize) -> Result<()> {
    c.emit(Op::SubRi(RSP, bytes as i32));
    c.emit(Op::MovRr(ADDR, RSP));
    store_width(c, src, bytes)
}

fn xlat(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let _ = image_base;
    preserve(c, |c| {
        // The displayed index is AL. Add that byte once, on top of the base.
        c.emit(Op::MovRi(ADDR, insn.memory_displacement64()));
        let base = insn.memory_base();
        if base != Register::None && base != Register::RIP && base != Register::EIP {
            copy_reg(c, T3, base)?;
            c.emit(Op::AddRr(ADDR, T3));
        }
        copy_masked_index(c, T0, RAX, 8);
        c.emit(Op::AddRr(ADDR, T0));
        let bits = base.size() * 8;
        if bits == 16 || bits == 32 {
            c.emit(Op::MovRi(IMM, (1u64 << bits) - 1));
            c.emit(Op::AndRr(ADDR, IMM));
        }
        c.emit(Op::Load8(T0, ADDR));
        merge_low(c, RAX, T0, 8);
        Ok(())
    })
}

fn string(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let _ = image_base;
    let width = string_width(insn.mnemonic()).ok_or_else(|| super::bad(insn))?;
    let rep = insn.has_rep_prefix() || insn.has_repne_prefix();
    if !rep {
        return string_once(c, insn, width, false);
    }
    c.emit(Op::StFlags(SAVE));
    let head = c.alloc();
    let body = c.alloc();
    let after = c.alloc();
    let ops = std::mem::take(&mut c.ops);
    c.seal_at(c.block, ops, Exit::Jmp(head));
    c.seal_at(
        head,
        vec![Step::Gp(Op::TestRr(RCX, RCX))],
        Exit::Jcc(4, after, body),
    );
    c.block = body;
    string_once(c, insn, width, true)?;
    c.emit(Op::MovRr(crate::ir::V_TMP0, AF));
    c.emit(Op::AddRi(RCX, -1));
    c.emit(Op::MovRr(AF, crate::ir::V_TMP0));
    if is_string_compare(insn.mnemonic()) {
        c.emit(Op::TestRr(RCX, RCX));
        let check = c.alloc();
        let ops = std::mem::take(&mut c.ops);
        c.seal_at(c.block, ops, Exit::Jcc(4, after, check));
        c.block = check;
        c.emit(Op::LdFlags(SAVE));
        let again = if insn.has_repne_prefix() { 5 } else { 4 };
        let ops = std::mem::take(&mut c.ops);
        c.seal_at(c.block, ops, Exit::Jcc(again, head, after));
    } else {
        let ops = std::mem::take(&mut c.ops);
        c.seal_at(c.block, ops, Exit::Jmp(head));
    }
    c.block = after;
    c.emit(Op::LdFlags(SAVE));
    Ok(())
}

fn string_once(c: &mut Cursor<'_>, insn: &Instruction, width: u32, rep: bool) -> Result<()> {
    let bytes = width / 8;
    let keep = !rep && !is_string_compare(insn.mnemonic());
    if keep {
        c.emit(Op::StFlags(SAVE));
    }
    match insn.mnemonic() {
        Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq => {
            load_index(c, T0, RSI, bytes);
            store_index(c, T0, RDI, bytes);
            step_index(c, RSI, bytes);
            step_index(c, RDI, bytes);
        }
        Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq => {
            copy_masked_index(c, T0, RAX, width);
            store_index(c, T0, RDI, bytes);
            step_index(c, RDI, bytes);
        }
        Mnemonic::Lodsb | Mnemonic::Lodsw | Mnemonic::Lodsd | Mnemonic::Lodsq => {
            load_index(c, T0, RSI, bytes);
            if width >= 32 {
                c.emit(Op::MovRr(RAX, T0));
                mask_reg(c, RAX, width);
            } else {
                merge_low(c, RAX, T0, width);
            }
            step_index(c, RSI, bytes);
        }
        Mnemonic::Scasb | Mnemonic::Scasw | Mnemonic::Scasd | Mnemonic::Scasq => {
            load_index(c, T1, RDI, bytes);
            copy_masked_index(c, T0, RAX, width);
            arith_keep(c, false, width);
            c.emit(Op::MovRr(SAVE, T1));
            step_index(c, RDI, bytes);
        }
        Mnemonic::Cmpsb | Mnemonic::Cmpsw | Mnemonic::Cmpsd | Mnemonic::Cmpsq => {
            load_index(c, T0, RSI, bytes);
            load_index(c, T1, RDI, bytes);
            arith_keep(c, false, width);
            c.emit(Op::MovRr(SAVE, T1));
            step_index(c, RSI, bytes);
            step_index(c, RDI, bytes);
        }
        _ => return Err(super::bad(insn)),
    }
    if keep || !rep {
        c.emit(Op::LdFlags(SAVE));
    }
    Ok(())
}

fn cmov(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64, cond: u8) -> Result<()> {
    let dest = insn.op_register(0);
    c.cbranch(
        cond,
        |c| {
            let _ = preserve(c, |c| {
                read_value(c, insn, 1, T0, image_base)?;
                if insn.op0_kind() == OpKind::Register {
                    write_reg(c, insn.op_register(0), T0)
                } else {
                    materialize(c, insn, image_base)?;
                    store_width(c, T0, width_bytes(insn, 0))
                }
            });
        },
        |c| {
            let _ = preserve(c, |c| {
                read_value(c, insn, 1, T0, image_base)?;
                if dest.size() == 4 {
                    copy_reg(c, T0, dest)?;
                    write_reg(c, dest, T0)?;
                }
                Ok(())
            });
        },
    );
    Ok(())
}

fn setcc(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64, cond: u8) -> Result<()> {
    c.cbranch(
        cond,
        |c| {
            let _ = write_flag_byte(c, insn, image_base, 1);
        },
        |c| {
            let _ = write_flag_byte(c, insn, image_base, 0);
        },
    );
    Ok(())
}

fn write_flag_byte(
    c: &mut Cursor<'_>,
    insn: &Instruction,
    image_base: u64,
    value: u64,
) -> Result<()> {
    preserve(c, |c| {
        c.emit(Op::MovRi(T0, value));
        if insn.op0_kind() == OpKind::Register {
            write_reg(c, insn.op_register(0), T0)
        } else {
            materialize(c, insn, image_base)?;
            c.emit(Op::Store8(ADDR, T0));
            Ok(())
        }
    })
}

fn push_pop(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    let bytes = push_size(insn)?;
    if insn.mnemonic() == Mnemonic::Push && bytes == 8 && insn.op0_kind() == OpKind::Register {
        c.emit(Op::Push(super::gpr_index(insn.op_register(0))?));
        return Ok(());
    }
    if insn.mnemonic() == Mnemonic::Pop && bytes == 8 && insn.op0_kind() == OpKind::Register {
        c.emit(Op::Pop(super::gpr_index(insn.op_register(0))?));
        return Ok(());
    }
    preserve(c, |c| {
        if insn.mnemonic() == Mnemonic::Push {
            read_value(c, insn, 0, T0, image_base)?;
            c.emit(Op::SubRi(RSP, bytes as i32));
            c.emit(Op::MovRr(ADDR, RSP));
            store_width(c, T0, bytes)?;
        } else {
            c.emit(Op::MovRr(ADDR, RSP));
            load_width(c, T0, bytes)?;
            c.emit(Op::AddRi(RSP, bytes as i32));
            if insn.op0_kind() == OpKind::Register {
                write_reg(c, insn.op_register(0), T0)?;
            } else {
                materialize(c, insn, image_base)?;
                store_width(c, T0, bytes)?;
            }
        }
        Ok(())
    })
}

fn push_pop_flags(c: &mut Cursor<'_>, insn: &Instruction) -> Result<()> {
    let bytes = if matches!(insn.mnemonic(), Mnemonic::Pushf | Mnemonic::Popf) {
        2
    } else {
        8
    };
    if insn.mnemonic() == Mnemonic::Pushfq || insn.mnemonic() == Mnemonic::Pushf {
        c.emit(Op::StFlags(SAVE));
        c.emit(Op::MovRr(T0, SAVE));
        c.emit(Op::MovRi(T1, 0x202));
        c.emit(Op::OrRr(T0, T1));
        c.emit(Op::MovRr(T1, AF));
        c.emit(Op::AndRi(T1, 1));
        c.emit(Op::Shl(T1, 4));
        c.emit(Op::OrRr(T0, T1));
        c.emit(Op::MovRr(T1, DF));
        c.emit(Op::AndRi(T1, 1));
        c.emit(Op::Shl(T1, 10));
        c.emit(Op::OrRr(T0, T1));
        c.emit(Op::MovRr(crate::ir::V_TMP0, AF));
        c.emit(Op::SubRi(RSP, bytes as i32));
        c.emit(Op::MovRr(ADDR, RSP));
        store_width(c, T0, bytes)?;
        c.emit(Op::LdFlags(SAVE));
        c.emit(Op::MovRr(AF, crate::ir::V_TMP0));
    } else {
        c.emit(Op::MovRr(ADDR, RSP));
        load_width(c, T0, bytes)?;
        c.emit(Op::AddRi(RSP, bytes as i32));
        c.emit(Op::MovRr(T1, T0));
        c.emit(Op::Shr(T1, 4));
        c.emit(Op::AndRi(T1, 1));
        c.emit(Op::MovRr(AF, T1));
        c.emit(Op::MovRr(T1, T0));
        c.emit(Op::Shr(T1, 10));
        c.emit(Op::AndRi(T1, 1));
        c.emit(Op::MovRr(DF, T1));
        c.emit(Op::MovRr(SAVE, T0));
        c.emit(Op::LdFlags(SAVE));
    }
    Ok(())
}

fn preserve<F>(c: &mut Cursor<'_>, body: F) -> Result<()>
where
    F: FnOnce(&mut Cursor<'_>) -> Result<()>,
{
    c.emit(Op::StFlags(SAVE));
    c.emit(Op::MovRr(crate::ir::V_TMP1, AF));
    body(c)?;
    c.emit(Op::LdFlags(SAVE));
    c.emit(Op::MovRr(AF, crate::ir::V_TMP1));
    Ok(())
}

fn read_value(
    c: &mut Cursor<'_>,
    insn: &Instruction,
    index: u32,
    dst: u16,
    image_base: u64,
) -> Result<()> {
    match insn.op_kind(index) {
        OpKind::Register => copy_reg(c, dst, insn.op_register(index)),
        OpKind::Memory => {
            materialize(c, insn, image_base)?;
            load_width(c, dst, width_bytes(insn, index))
        }
        kind if super::is_imm(kind) => {
            c.emit(Op::MovRi(dst, super::imm64(insn, index)));
            Ok(())
        }
        _ => Err(super::bad(insn)),
    }
}

fn copy_reg(c: &mut Cursor<'_>, dst: u16, reg: Register) -> Result<()> {
    c.emit(Op::MovRr(dst, super::gpr_index(reg)?));
    if gp::high_byte(reg) {
        c.emit(Op::Shr(dst, 8));
        c.emit(Op::AndRi(dst, 0xff));
    } else {
        mask_reg(c, dst, reg.size() as u32 * 8);
    }
    Ok(())
}

fn copy_masked_index(c: &mut Cursor<'_>, dst: u16, index: u16, bits: u32) {
    c.emit(Op::MovRr(dst, index));
    mask_reg(c, dst, bits);
}

fn write_reg(c: &mut Cursor<'_>, reg: Register, src: u16) -> Result<()> {
    let index = super::gpr_index(reg)?;
    if gp::high_byte(reg) {
        c.emit(Op::MovRr(T3, src));
        c.emit(Op::AndRi(T3, 0xff));
        c.emit(Op::Shl(T3, 8));
        c.emit(Op::MovRi(IMM, !0xff00u64));
        c.emit(Op::AndRr(index, IMM));
        c.emit(Op::OrRr(index, T3));
        return Ok(());
    }
    let bits = reg.size() as u32 * 8;
    if bits >= 32 {
        c.emit(Op::MovRr(index, src));
        mask_reg(c, index, bits);
        return Ok(());
    }
    merge_low(c, index, src, bits);
    Ok(())
}

fn merge_low(c: &mut Cursor<'_>, dest: u16, src: u16, bits: u32) {
    c.emit(Op::MovRr(T3, src));
    mask_reg(c, T3, bits);
    let clear = !((1u64 << bits) - 1);
    c.emit(Op::MovRi(IMM, clear));
    c.emit(Op::AndRr(dest, IMM));
    c.emit(Op::OrRr(dest, T3));
}

fn mask_reg(c: &mut Cursor<'_>, reg: u16, bits: u32) {
    if bits >= 64 {
        return;
    }
    if bits < 31 {
        let mask = (1i32 << bits) - 1;
        c.emit(Op::AndRi(reg, mask));
        return;
    }
    c.emit(Op::MovRi(IMM, (1u64 << bits) - 1));
    c.emit(Op::AndRr(reg, IMM));
}

fn materialize(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    if insn.is_ip_rel_memory_operand() {
        let target = insn.ip_rel_memory_address();
        let rva = u32::try_from(target.wrapping_sub(image_base)).map_err(|_| super::bad(insn))?;
        c.emit(Op::Lea(ADDR, Address::Rva(rva)));
        return Ok(());
    }
    // Fold the effective address with Lea. AddRr writes AF, and LdFlags does not restore it.
    let disp = insn.memory_displacement64() as i64;
    let base = insn.memory_base();
    if is_address_reg(base) {
        let placed = place_address(c, base)?;
        lea_sum(c, ADDR, Some(placed), None, 1, disp);
    } else {
        lea_sum(c, ADDR, None, None, 1, disp);
    }
    let index = insn.memory_index();
    if is_address_reg(index) {
        let scale = insn.memory_index_scale() as u8;
        let placed = place_address(c, index)?;
        lea_sum(c, ADDR, Some(ADDR), Some(placed), scale, 0);
    }
    if address_is_32(insn) {
        c.emit(Op::MovRi(IMM, 0xffff_ffff));
        c.emit(Op::AndRr(ADDR, IMM));
    }
    Ok(())
}

fn is_address_reg(reg: Register) -> bool {
    reg != Register::None && reg != Register::RIP && reg != Register::EIP
}

/// A 64-bit address register is used as-is. A narrower one is zero-extended into `T3`
/// first, matching the previous `copy_reg` mask. `T3` is then free for the other component.
fn place_address(c: &mut Cursor<'_>, reg: Register) -> Result<u16> {
    if reg.size() >= 8 {
        return super::gpr_index(reg);
    }
    copy_reg(c, T3, reg)?;
    Ok(T3)
}

fn lea_sum(
    c: &mut Cursor<'_>,
    dst: u16,
    base: Option<u16>,
    index: Option<u16>,
    scale: u8,
    disp: i64,
) {
    c.emit(Op::Lea(
        dst,
        Address::Sib {
            base,
            index,
            scale,
            disp,
        },
    ));
}

fn address_is_32(insn: &Instruction) -> bool {
    let base = insn.memory_base();
    let index = insn.memory_index();
    (base != Register::None && base != Register::RIP && base.size() == 4)
        || (index != Register::None && index.size() == 4)
}

fn load_width(c: &mut Cursor<'_>, dst: u16, bytes: usize) -> Result<()> {
    match bytes {
        1 => c.emit(Op::Load8(dst, ADDR)),
        8 => c.emit(Op::Load64(dst, ADDR)),
        2 | 4 => {
            c.emit(Op::Load8(dst, ADDR));
            for byte in 1..bytes {
                // Byte steps are addresses. AddRi would replace AF, which LdFlags does not restore.
                lea_sum(c, T3, Some(ADDR), None, 1, byte as i64);
                c.emit(Op::Load8(IMM, T3));
                c.emit(Op::Shl(IMM, (byte * 8) as u8));
                c.emit(Op::OrRr(dst, IMM));
            }
        }
        _ => return Err(msg("unsupported memory width")),
    }
    Ok(())
}

fn store_width(c: &mut Cursor<'_>, src: u16, bytes: usize) -> Result<()> {
    match bytes {
        1 => c.emit(Op::Store8(ADDR, src)),
        8 => c.emit(Op::Store64(ADDR, src)),
        2 | 4 => {
            for byte in 0..bytes {
                c.emit(Op::MovRr(T3, src));
                if byte > 0 {
                    c.emit(Op::Shr(T3, (byte * 8) as u8));
                }
                // Same as the load: the byte address is not an architectural add.
                lea_sum(c, IMM, Some(ADDR), None, 1, byte as i64);
                c.emit(Op::Store8(IMM, T3));
            }
        }
        _ => return Err(msg("unsupported memory width")),
    }
    Ok(())
}

fn load_index(c: &mut Cursor<'_>, dst: u16, reg: u16, bytes: u32) {
    c.emit(Op::MovRr(ADDR, reg));
    let _ = load_width(c, dst, bytes as usize);
}

fn store_index(c: &mut Cursor<'_>, src: u16, reg: u16, bytes: u32) {
    c.emit(Op::MovRr(ADDR, reg));
    let _ = store_width(c, src, bytes as usize);
}

fn step_index(c: &mut Cursor<'_>, reg: u16, bytes: u32) {
    c.emit(Op::MovRr(crate::ir::V_TMP0, AF));
    c.emit(Op::MovRi(T3, u64::from(bytes)));
    c.emit(Op::TestRr(DF, DF));
    c.cbranch(
        5,
        |c| c.emit(Op::SubRr(reg, T3)),
        |c| c.emit(Op::AddRr(reg, T3)),
    );
    c.emit(Op::MovRr(AF, crate::ir::V_TMP0));
}

pub(super) fn aux_ops(left: u16, right: u16, result: u16) -> [Op; 7] {
    [
        Op::MovRr(T3, left),
        Op::XorRr(T3, right),
        Op::XorRr(T3, result),
        Op::MovRi(IMM, 0x10),
        Op::AndRr(T3, IMM),
        Op::Shr(T3, 4),
        Op::MovRr(AF, T3),
    ]
}

fn aux(c: &mut Cursor<'_>, left: u16, right: u16, result: u16) {
    for op in aux_ops(left, right, result) {
        c.emit(op);
    }
}

fn fix_parity(c: &mut Cursor<'_>, value: u16, flags: u16) {
    c.emit(Op::MovRr(IMM, value));
    c.emit(Op::Shr(IMM, 4));
    c.emit(Op::XorRr(IMM, value));
    c.emit(Op::MovRr(T3, IMM));
    c.emit(Op::Shr(T3, 2));
    c.emit(Op::XorRr(IMM, T3));
    c.emit(Op::MovRr(T3, IMM));
    c.emit(Op::Shr(T3, 1));
    c.emit(Op::XorRr(IMM, T3));
    c.emit(Op::AndRi(IMM, 1));
    c.emit(Op::MovRi(T3, 1));
    c.emit(Op::SubRr(T3, IMM));
    c.emit(Op::Shl(T3, 2));
    c.emit(Op::AndRi(flags, !4));
    c.emit(Op::OrRr(flags, T3));
}

fn sign_to(c: &mut Cursor<'_>, reg: u16, bits: u32) {
    if bits >= 64 {
        return;
    }
    let shift = (64 - bits) as u8;
    c.emit(Op::Shl(reg, shift));
    c.emit(Op::Sar(reg, shift));
}

fn operand_bits(insn: &Instruction, index: u32) -> u32 {
    match insn.op_kind(index) {
        OpKind::Register => insn.op_register(index).size() as u32 * 8,
        OpKind::Memory => insn.memory_size().size() as u32 * 8,
        _ => 64,
    }
}

fn width_bytes(insn: &Instruction, index: u32) -> usize {
    (operand_bits(insn, index) / 8) as usize
}

fn acc_reg(bits: u32) -> Register {
    match bits {
        8 => Register::AL,
        16 => Register::AX,
        32 => Register::EAX,
        _ => Register::RAX,
    }
}

fn store_pair(c: &mut Cursor<'_>, low: u16, high: u16, width: u32) {
    match width {
        8 => {
            c.emit(Op::AndRi(low, 0xff));
            c.emit(Op::AndRi(high, 0xff));
            c.emit(Op::Shl(high, 8));
            c.emit(Op::OrRr(low, high));
            merge_low(c, RAX, low, 16);
        }
        16 => {
            merge_low(c, RAX, low, 16);
            merge_low(c, RDX, high, 16);
        }
        32 => {
            c.emit(Op::MovRr(RAX, low));
            mask_reg(c, RAX, 32);
            c.emit(Op::MovRr(RDX, high));
            mask_reg(c, RDX, 32);
        }
        _ => {
            c.emit(Op::MovRr(RAX, low));
            c.emit(Op::MovRr(RDX, high));
        }
    }
}

fn assemble_dividend(c: &mut Cursor<'_>, dest: u16, width: u32, _signed: bool) {
    match width {
        8 => copy_masked_index(c, dest, RAX, 16),
        16 => {
            copy_masked_index(c, dest, RDX, 16);
            c.emit(Op::Shl(dest, 16));
            copy_masked_index(c, T3, RAX, 16);
            c.emit(Op::OrRr(dest, T3));
        }
        32 => {
            copy_masked_index(c, dest, RDX, 32);
            c.emit(Op::Shl(dest, 32));
            copy_masked_index(c, T3, RAX, 32);
            c.emit(Op::OrRr(dest, T3));
        }
        _ => c.emit(Op::MovRr(dest, RAX)),
    }
}

fn push_size(insn: &Instruction) -> Result<usize> {
    let size = match insn.op0_kind() {
        OpKind::Register => insn.op_register(0).size(),
        OpKind::Memory => insn.memory_size().size(),
        OpKind::Immediate16 => 2,
        kind if super::is_imm(kind) => 8,
        _ => return Err(super::bad(insn)),
    };
    if size == 4 {
        return Err(super::bad(insn));
    }
    Ok(size)
}

fn read_bit_offset(c: &mut Cursor<'_>, insn: &Instruction, image_base: u64) -> Result<()> {
    if super::is_imm(insn.op1_kind()) {
        c.emit(Op::MovRi(T1, u64::from(insn.immediate8())));
        Ok(())
    } else {
        read_value(c, insn, 1, T1, image_base)
    }
}

fn extract_bit(c: &mut Cursor<'_>) {
    c.emit(Op::MovRr(T3, T0));
    c.emit(Op::MovRr(IMM, T1));
    let head = c.alloc();
    let body = c.alloc();
    let after = c.alloc();
    let ops = std::mem::take(&mut c.ops);
    c.seal_at(c.block, ops, Exit::Jmp(head));
    c.seal_at(
        head,
        vec![Step::Gp(Op::TestRr(IMM, IMM))],
        Exit::Jcc(4, after, body),
    );
    c.block = body;
    c.emit(Op::Shr(T3, 1));
    c.emit(Op::AddRi(IMM, -1));
    let ops = std::mem::take(&mut c.ops);
    c.seal_at(c.block, ops, Exit::Jmp(head));
    c.block = after;
    c.emit(Op::AndRi(T3, 1));
}

fn modify_bit(c: &mut Cursor<'_>, kind: Mnemonic, width: u32) {
    if kind == Mnemonic::Bt {
        return;
    }
    c.emit(Op::MovRi(IMM, 1));
    c.emit(Op::MovRr(T2, T1));
    let head = c.alloc();
    let body = c.alloc();
    let after = c.alloc();
    let ops = std::mem::take(&mut c.ops);
    c.seal_at(c.block, ops, Exit::Jmp(head));
    c.seal_at(
        head,
        vec![Step::Gp(Op::TestRr(T2, T2))],
        Exit::Jcc(4, after, body),
    );
    c.block = body;
    c.emit(Op::Shl(IMM, 1));
    c.emit(Op::AddRi(T2, -1));
    let ops = std::mem::take(&mut c.ops);
    c.seal_at(c.block, ops, Exit::Jmp(head));
    c.block = after;
    if width < 64 {
        mask_reg(c, IMM, width);
    }
    match kind {
        Mnemonic::Bts => c.emit(Op::OrRr(T0, IMM)),
        Mnemonic::Btr => {
            c.emit(Op::Not(IMM));
            c.emit(Op::AndRr(T0, IMM));
        }
        Mnemonic::Btc => c.emit(Op::XorRr(T0, IMM)),
        _ => {}
    }
}

fn string_width(mnemonic: Mnemonic) -> Option<u32> {
    Some(match mnemonic {
        Mnemonic::Movsb | Mnemonic::Stosb | Mnemonic::Lodsb | Mnemonic::Scasb | Mnemonic::Cmpsb => {
            8
        }
        Mnemonic::Movsw | Mnemonic::Stosw | Mnemonic::Lodsw | Mnemonic::Scasw | Mnemonic::Cmpsw => {
            16
        }
        Mnemonic::Movsd | Mnemonic::Stosd | Mnemonic::Lodsd | Mnemonic::Scasd | Mnemonic::Cmpsd => {
            32
        }
        Mnemonic::Movsq | Mnemonic::Stosq | Mnemonic::Lodsq | Mnemonic::Scasq | Mnemonic::Cmpsq => {
            64
        }
        _ => return None,
    })
}

fn is_string_compare(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Scasb
            | Mnemonic::Scasw
            | Mnemonic::Scasd
            | Mnemonic::Scasq
            | Mnemonic::Cmpsb
            | Mnemonic::Cmpsw
            | Mnemonic::Cmpsd
            | Mnemonic::Cmpsq
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Extend {
    Merge,
    Zero,
    Sign,
}

#[cfg(test)]
mod tests {
    use iced_x86::code_asm::*;
    use iced_x86::{Decoder, DecoderOptions, Formatter};

    use crate::flags::Flags;
    use crate::gp::{self, Fate};
    use crate::ir::{exec_func, Exit, MapMem, Op};

    const AF_SLOT: u64 = 0x6EAF;

    const DATA: u64 = 0x2000;

    fn assemble(build: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>) -> Vec<u8> {
        let mut asm = CodeAssembler::new(64).unwrap();
        build(&mut asm).unwrap();
        asm.assemble(0).unwrap()
    }

    fn encode_one(insn: &iced_x86::Instruction) -> Vec<u8> {
        let mut encoder = iced_x86::Encoder::new(64);
        encoder.encode(insn, 0).expect("encode");
        encoder.take_buffer()
    }

    fn run(
        build: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>,
        regs: [u64; 16],
        flags: Flags,
        af: bool,
    ) {
        run_df(build, regs, flags, af, false);
    }

    fn run_df(
        build: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>,
        regs: [u64; 16],
        flags: Flags,
        af: bool,
        df: bool,
    ) {
        run_bytes(&assemble(build), regs, flags, af, df);
    }

    fn run_bytes(bytes: &[u8], regs: [u64; 16], flags: Flags, af: bool, df: bool) {
        let head = regs[2].to_le_bytes();
        run_image(bytes, regs, flags, af, df, &head);
    }

    fn run_image(bytes: &[u8], mut regs: [u64; 16], flags: Flags, af: bool, df: bool, head: &[u8]) {
        let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
        let mut formatter = iced_x86::IntelFormatter::new();
        let mut text = String::new();
        let mut cpu = gp::Cpu {
            regs,
            flags,
            af,
            df,
            gs: 0,
        };
        let mut reference = memory(head);
        let mut touch = None;
        while decoder.ip() < bytes.len() as u64 {
            let insn = decoder.decode();
            if insn.is_invalid() || insn.len() == 0 {
                break;
            }
            if touch.is_some() {
                text.push_str("; ");
            }
            let mut line = String::new();
            formatter.format(&insn, &mut line);
            text.push_str(&line);
            touch = Some(
                gp::apply(&mut cpu, &mut reference, &insn)
                    .unwrap_or_else(|err| panic!("{text}: {err}"))
                    .unwrap_or_else(|| panic!("{text} is outside the integer group")),
            );
        }
        let touch = touch.expect("empty encoding");
        let mut func = crate::lift::lift("case", bytes, 0, bytes.len() as u32, 0)
            .unwrap_or_else(|err| panic!("{text} did not lift: {err}"));
        let entry = func.entry as usize;
        func.blocks[entry]
            .ops
            .insert(0, Op::MovRi(31, u64::from(df)));
        func.blocks[entry]
            .ops
            .insert(0, Op::MovRi(30, u64::from(af)));
        for block in &mut func.blocks {
            if matches!(block.exit, Exit::Ret) {
                block.ops.push(Op::MovRi(28, AF_SLOT));
                block.ops.push(Op::Store8(28, 30));
            }
        }
        let mut out_flags = flags;
        let mut actual = memory(head);
        let mut absent =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        exec_func(
            &[func],
            0,
            &mut regs,
            &mut out_flags,
            &mut actual,
            0,
            &mut absent,
        )
        .unwrap_or_else(|err| panic!("{text} ir: {err}"));
        let ir_af = actual.bytes.remove(&AF_SLOT).unwrap_or(0) & 1 == 1;
        assert_eq!(regs, cpu.regs, "{text}");
        assert_eq!(actual.bytes, reference.bytes, "{text} memory");
        same_flags(&text, touch, out_flags, cpu.flags, ir_af, cpu.af);
    }

    fn memory(head: &[u8]) -> MapMem {
        let mut mem = MapMem::default();
        let bytes = std::array::from_fn::<u8, 64, _>(|index| {
            head.get(index)
                .copied()
                .unwrap_or_else(|| (index as u8).wrapping_mul(17))
        });
        for (index, byte) in bytes.into_iter().enumerate() {
            mem.bytes.insert(DATA + index as u64, byte);
        }
        mem
    }

    fn same_flags(
        text: &str,
        touch: gp::Touch,
        ir: Flags,
        reference: Flags,
        ir_af: bool,
        reference_af: bool,
    ) {
        for (name, fate, left, right) in [
            ("cf", touch.cf, ir.cf, reference.cf),
            ("pf", touch.pf, ir.pf, reference.pf),
            ("zf", touch.zf, ir.zf, reference.zf),
            ("sf", touch.sf, ir.sf, reference.sf),
            ("of", touch.of, ir.of, reference.of),
            ("af", touch.af, ir_af, reference_af),
        ] {
            if fate != Fate::Undef {
                assert_eq!(
                    left, right,
                    "{text} {name} ir={ir:?} af={ir_af} reference={reference:?} af={reference_af}"
                );
            }
        }
    }

    fn state(a: u64, b: u64, carry: bool) -> ([u64; 16], Flags) {
        let mut regs = [0u64; 16];
        regs[0] = a;
        regs[1] = b;
        regs[2] = b;
        regs[3] = DATA;
        let flags = Flags {
            cf: carry,
            pf: a.count_ones().is_multiple_of(2),
            zf: a == 0,
            sf: (a as i64) < 0,
            of: carry,
        };
        (regs, flags)
    }

    #[test]
    fn arithmetic_and_shifts_match_gp() {
        let values = [
            0u64,
            1,
            0x0f,
            0x10,
            0x7f,
            0x80,
            0xff,
            0x7fff,
            0x8000,
            0xffff,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_ffff,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            u64::MAX,
            0x5a5a_a5a5_5a5a_a5a5,
        ];
        for (i, &a) in values.iter().enumerate() {
            for (j, &b) in values.iter().enumerate() {
                if (i * 3 + j) % 5 != 0 {
                    continue;
                }
                let (regs, flags) = state(a, b, i % 2 == 0);
                run(|asm| asm.add(al, cl), regs, flags, j % 2 == 0);
                run(|asm| asm.add(ax, cx), regs, flags, false);
                run(|asm| asm.add(eax, ecx), regs, flags, true);
                run(|asm| asm.add(rax, rcx), regs, flags, false);
                run(|asm| asm.adc(al, cl), regs, flags, true);
                run(|asm| asm.adc(eax, ecx), regs, flags, false);
                run(|asm| asm.adc(rax, rcx), regs, flags, true);
                run(|asm| asm.sub(al, cl), regs, flags, false);
                run(|asm| asm.sbb(ax, cx), regs, flags, true);
                run(|asm| asm.sbb(rax, rcx), regs, flags, false);
                run(|asm| asm.and(al, cl), regs, flags, true);
                run(|asm| asm.or(eax, ecx), regs, flags, false);
                run(|asm| asm.xor(rax, rcx), regs, flags, true);
                run(|asm| asm.cmp(al, cl), regs, flags, false);
                run(|asm| asm.test(eax, ecx), regs, flags, true);
                run(|asm| asm.inc(al), regs, flags, false);
                run(|asm| asm.dec(ax), regs, flags, true);
                run(|asm| asm.neg(eax), regs, flags, false);
                run(|asm| asm.not(rax), regs, flags, true);
                run(|asm| asm.add(byte_ptr(rbx), al), regs, flags, false);
                run(|asm| asm.adc(dword_ptr(rbx), eax), regs, flags, true);
                run(|asm| asm.sub(qword_ptr(rbx), rax), regs, flags, false);
                run(|asm| asm.add(eax, dword_ptr(rbx)), regs, flags, true);
                let (mut shifted, shift_flags) = state(a, b, i % 2 == 0);
                shifted[1] = u64::from((j % 9) as u8);
                run(|asm| asm.shl(al, 1u32), shifted, shift_flags, false);
                run(|asm| asm.shl(ax, cl), shifted, shift_flags, true);
                run(|asm| asm.shr(eax, 7u32), shifted, shift_flags, false);
                run(|asm| asm.sar(rax, cl), shifted, shift_flags, true);
                run(|asm| asm.rol(al, 3u32), shifted, shift_flags, false);
                run(|asm| asm.ror(eax, cl), shifted, shift_flags, true);
                run(|asm| asm.rcl(ax, 1u32), shifted, shift_flags, false);
                run(|asm| asm.rcr(rax, cl), shifted, shift_flags, true);
                run(|asm| asm.shld(ax, dx, 4u32), shifted, shift_flags, false);
                run(|asm| asm.shrd(eax, edx, cl), shifted, shift_flags, true);
                run(
                    |asm| asm.shl(byte_ptr(rbx), 1u32),
                    shifted,
                    shift_flags,
                    false,
                );
            }
        }
    }

    #[test]
    fn multiply_and_divide_match_gp() {
        let values = [
            0u64, 1, 2, 3, 7, 9, 0x10, 0x7f, 0x80, 0xff, 0x1234, 0x7fff, 0x8000,
        ];
        for &a in &values {
            for &b in &values {
                let (mut regs, flags) = state(a, b | 1, false);
                run(|asm| asm.imul_2(eax, ecx), regs, flags, false);
                run(|asm| asm.imul_2(rax, rcx), regs, flags, true);
                run(|asm| asm.imul_3(eax, ecx, 9i32), regs, flags, false);
                run(|asm| asm.mul(cl), regs, flags, true);
                run(|asm| asm.imul(cx), regs, flags, false);
                run(|asm| asm.mul(rcx), regs, flags, true);
                regs[0] = a & 0x3f;
                regs[2] = 0;
                regs[1] = (b % 5) + 1;
                let (safe, safe_flags) = {
                    let mut copy = regs;
                    copy[3] = DATA;
                    (copy, flags)
                };
                run(|asm| asm.div(cl), safe, safe_flags, false);
                run(|asm| asm.idiv(cl), safe, safe_flags, true);
                run(|asm| asm.div(cx), safe, safe_flags, false);
                run(|asm| asm.idiv(ecx), safe, safe_flags, true);
                run(|asm| asm.div(rcx), safe, safe_flags, false);
                let mut neg = safe;
                neg[0] = 0u64.wrapping_sub((a % 9) + 1);
                neg[2] = u64::MAX;
                run(|asm| asm.idiv(rcx), neg, safe_flags, false);
            }
        }
        let (mut regs, flags) = state(0, 0, false);
        regs[1] = 0;
        expect_fault(|asm| asm.div(cl), regs, flags, "division by zero");
        regs[0] = 0x100;
        regs[1] = 1;
        expect_fault(|asm| asm.div(cl), regs, flags, "division overflow");
    }

    fn expect_fault(
        build: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>,
        mut regs: [u64; 16],
        flags: Flags,
        needle: &str,
    ) {
        let bytes = assemble(build);
        let mut decoder = Decoder::with_ip(64, &bytes, 0, DecoderOptions::NONE);
        let insn = decoder.decode();
        let mut cpu = gp::Cpu {
            regs,
            flags,
            af: false,
            df: false,
            gs: 0,
        };
        let data = [0u8; 8];
        let gp_err = gp::apply(&mut cpu, &mut memory(&data), &insn).unwrap_err();
        assert!(gp_err.to_string().contains(needle), "{gp_err}");
        let mut func = crate::lift::lift("fault", &bytes, 0, bytes.len() as u32, 0).unwrap();
        func.blocks[func.entry as usize]
            .ops
            .insert(0, Op::MovRi(30, 0));
        let mut out_flags = flags;
        let mut absent =
            |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn crate::ir::MemIo, _: u64| Ok(());
        let ir_err = exec_func(
            &[func],
            0,
            &mut regs,
            &mut out_flags,
            &mut memory(&data),
            0,
            &mut absent,
        )
        .unwrap_err();
        assert!(ir_err.to_string().contains(needle), "{ir_err}");
    }

    #[test]
    fn data_motion_and_string_ops_match_gp() {
        let (mut regs, flags) = state(0x11_22_33_44_55_66_77_88, 0xaabb, true);
        regs[4] = DATA + 40;
        regs[6] = DATA;
        regs[7] = DATA + 16;
        run(|asm| asm.mov(al, cl), regs, flags, false);
        run(|asm| asm.mov(eax, 0x7fi32), regs, flags, true);
        run(|asm| asm.movzx(eax, cl), regs, flags, false);
        run(|asm| asm.movsx(rax, ax), regs, flags, true);
        run(|asm| asm.movsxd(rax, eax), regs, flags, false);
        run(
            |asm| asm.lea(rax, qword_ptr(rbx + rcx * 2 + 8)),
            regs,
            flags,
            true,
        );
        run(|asm| asm.xchg(al, cl), regs, flags, false);
        run(|asm| asm.xadd(eax, ecx), regs, flags, true);
        run(|asm| asm.cmpxchg(al, cl), regs, flags, false);
        run(|asm| asm.bswap(eax), regs, flags, true);
        run(|asm| asm.bswap(rax), regs, flags, false);
        run(|asm| asm.bsf(eax, ecx), regs, flags, true);
        run(|asm| asm.bsr(rax, rcx), regs, flags, false);
        run(|asm| asm.bt(eax, ecx), regs, flags, true);
        run(|asm| asm.bts(rax, 3u32), regs, flags, false);
        run(|asm| asm.btr(ax, cx), regs, flags, true);
        run(|asm| asm.btc(qword_ptr(rbx), 1u32), regs, flags, false);
        run(|asm| asm.cmove(eax, ecx), regs, flags, true);
        run(|asm| asm.cmovb(rax, rcx), regs, flags, false);
        run(|asm| asm.sete(al), regs, flags, true);
        run(|asm| asm.setb(byte_ptr(rbx)), regs, flags, false);
        run(|asm| asm.push(rax), regs, flags, true);
        run(|asm| asm.pop(rcx), regs, flags, false);
        run(|asm| asm.pushfq(), regs, flags, true);
        run(|asm| asm.lahf(), regs, flags, false);
        run(|asm| asm.cbw(), regs, flags, true);
        run(|asm| asm.cwde(), regs, flags, false);
        run(|asm| asm.cdqe(), regs, flags, true);
        run(|asm| asm.cqo(), regs, flags, false);
        run(|asm| asm.clc(), regs, flags, true);
        run(|asm| asm.stc(), regs, flags, false);
        run(|asm| asm.cmc(), regs, flags, true);
        run(|asm| asm.movsb(), regs, flags, false);
        regs[1] = 3;
        run(|asm| asm.rep().stosb(), regs, flags, true);
        run(|asm| asm.repe().cmpsb(), regs, flags, false);
        run(|asm| asm.repne().scasb(), regs, flags, true);
        run(|asm| asm.lodsq(), regs, flags, false);
        let mut backward = regs;
        backward[6] = DATA + 8;
        backward[7] = DATA + 24;
        backward[1] = 2;
        run_df(|asm| asm.rep().movsb(), backward, flags, false, true);
        run_df(|asm| asm.std(), backward, flags, true, false);
        run_df(|asm| asm.cld(), backward, flags, false, true);
        run(|asm| asm.enter(8u32, 0u32), regs, flags, true);
        run(|asm| asm.leave(), regs, flags, false);
        let enterw = iced_x86::Instruction::with2(iced_x86::Code::Enterw_imm16_imm8, 8i32, 0i32)
            .expect("enterw");
        run_bytes(&encode_one(&enterw), regs, flags, false, false);
        let leavew = iced_x86::Instruction::with(iced_x86::Code::Leavew);
        run_bytes(&encode_one(&leavew), regs, flags, true, false);
        let enter_nested =
            iced_x86::Instruction::with2(iced_x86::Code::Enterq_imm16_imm8, 8i32, 1i32)
                .expect("enterq");
        run_bytes(&encode_one(&enter_nested), regs, flags, false, false);
        regs[3] = DATA;
        regs[0] = 4;
        run(|asm| asm.xlatb(), regs, flags, true);
    }

    #[test]
    fn fast_alu_af_reaches_lahf_and_pushfq() {
        let samples = [
            (0u64, 0u64),
            (0x0f, 1),
            (0x10, 0x10),
            (0xff, 1),
            (0x7fff_ffff_ffff_ffff, 1),
            (u64::MAX, 1),
        ];
        for (a, b) in samples {
            for incoming in [false, true] {
                let (mut regs, flags) = state(a, b, true);
                regs[4] = DATA + 40;
                run(
                    |asm| {
                        asm.add(rax, rcx)?;
                        asm.lahf()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
                run(
                    |asm| {
                        asm.add(rax, rcx)?;
                        asm.pushfq()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
                run(
                    |asm| {
                        asm.add(rax, 1i32)?;
                        asm.lahf()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
                run(
                    |asm| {
                        asm.add(rax, -1i32)?;
                        asm.pushfq()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
                run(
                    |asm| {
                        asm.sub(rax, rcx)?;
                        asm.lahf()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
                run(
                    |asm| {
                        asm.sub(rax, 1i32)?;
                        asm.pushfq()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
                run(
                    |asm| {
                        asm.cmp(rax, rcx)?;
                        asm.lahf()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
                run(
                    |asm| {
                        asm.cmp(rax, -1i32)?;
                        asm.pushfq()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
                run(
                    |asm| {
                        asm.inc(rax)?;
                        asm.lahf()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
                run(
                    |asm| {
                        asm.dec(rax)?;
                        asm.pushfq()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
                run(
                    |asm| {
                        asm.neg(rax)?;
                        asm.lahf()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
                run(
                    |asm| {
                        asm.neg(rax)?;
                        asm.pushfq()?;
                        Ok(())
                    },
                    regs,
                    flags,
                    incoming,
                );
            }
        }
    }

    #[test]
    fn cmpxchg_wide_af_reaches_lahf_and_pushfq() {
        let eax_image = 0x0123_4567_89ab_cdefu64;
        let edx_image = 0xfedc_ba98_7654_3210u64;
        let ecx_image = 0x1111_2222_3333_4444u64;
        let flags = Flags {
            cf: true,
            pf: true,
            zf: true,
            sf: true,
            of: true,
        };
        for equal in [true, false] {
            for af in [false, true] {
                let mut regs = [0u64; 16];
                regs[0] = eax_image;
                regs[1] = ecx_image;
                regs[2] = edx_image;
                regs[3] = DATA;
                regs[4] = DATA + 48;
                let mem8 = if equal {
                    (edx_image & 0xffff_ffff) << 32 | (eax_image & 0xffff_ffff)
                } else {
                    0x0bad_f00d_dead_beef
                };
                let head8 = mem8.to_le_bytes();
                run_image(
                    &assemble(|asm| {
                        asm.cmpxchg8b(qword_ptr(rbx))?;
                        Ok(())
                    }),
                    regs,
                    flags,
                    af,
                    true,
                    &head8,
                );
                run_image(
                    &assemble(|asm| {
                        asm.cmpxchg8b(qword_ptr(rbx))?;
                        asm.lahf()?;
                        Ok(())
                    }),
                    regs,
                    flags,
                    af,
                    true,
                    &head8,
                );
                run_image(
                    &assemble(|asm| {
                        asm.cmpxchg8b(qword_ptr(rbx))?;
                        asm.pushfq()?;
                        Ok(())
                    }),
                    regs,
                    flags,
                    af,
                    true,
                    &head8,
                );
                let mut head16 = [0u8; 16];
                let low = if equal { eax_image } else { eax_image ^ 1 };
                head16[..8].copy_from_slice(&low.to_le_bytes());
                head16[8..].copy_from_slice(&edx_image.to_le_bytes());
                run_image(
                    &assemble(|asm| {
                        asm.cmpxchg16b(xmmword_ptr(rbx))?;
                        Ok(())
                    }),
                    regs,
                    flags,
                    af,
                    true,
                    &head16,
                );
                run_image(
                    &assemble(|asm| {
                        asm.cmpxchg16b(xmmword_ptr(rbx))?;
                        asm.lahf()?;
                        Ok(())
                    }),
                    regs,
                    flags,
                    af,
                    true,
                    &head16,
                );
                run_image(
                    &assemble(|asm| {
                        asm.cmpxchg16b(xmmword_ptr(rbx))?;
                        asm.pushfq()?;
                        Ok(())
                    }),
                    regs,
                    flags,
                    af,
                    true,
                    &head16,
                );
            }
        }
    }

    /// Address sums inside memory operands are not architectural adds. AF that
    /// the instruction already produced, or that it must keep, survives them.
    #[test]
    fn memory_address_math_keeps_auxiliary_carry() {
        let flags = Flags {
            cf: true,
            pf: false,
            zf: false,
            sf: false,
            of: false,
        };

        // xadd qword [rbx], rax: 0x0f + 1 sets AF. [rbx] = 0 + 0x2000 does not.
        let mut regs = [0u64; 16];
        regs[0] = 1;
        regs[2] = 0x0f;
        regs[3] = DATA;
        regs[4] = DATA + 48;
        run(|asm| asm.xadd(qword_ptr(rbx), rax), regs, flags, false);

        // Equal cmpxchg [rbx+1], rcx. Compare AF is 0; 1 + 0x200f carries out of bit 3.
        let mut equal = [0u64; 16];
        let matched = 0x1111_2222_3333_4444u64;
        equal[0] = matched;
        equal[1] = 0x99;
        equal[3] = DATA + 0x0f;
        equal[4] = DATA + 48;
        let mut head = [0u8; 64];
        head[0x10..0x18].copy_from_slice(&matched.to_le_bytes());
        run_image(
            &assemble(|asm| asm.cmpxchg(qword_ptr(rbx + 1i32), rcx)),
            equal,
            flags,
            false,
            false,
            &head,
        );
        let mut unequal = equal;
        unequal[0] ^= 0xff;
        run_image(
            &assemble(|asm| asm.cmpxchg(qword_ptr(rbx + 1i32), rcx)),
            unequal,
            flags,
            true,
            false,
            &head,
        );

        // NOT keeps flags. [rbx] address math would clear an incoming AF of 1.
        let mut kept = [0u64; 16];
        kept[2] = 0x81;
        kept[3] = DATA;
        kept[4] = DATA + 48;
        run(|asm| asm.not(byte_ptr(rbx)), kept, flags, true);

        // movsb has no address add. 16- and 32-bit forms add the extra bytes.
        let mut string = kept;
        string[0] = 0x1122_3344_5566_7788;
        string[6] = DATA;
        string[7] = DATA + 16;
        run(|asm| asm.movsb(), string, flags, true);
        run(|asm| asm.movsw(), string, flags, true);
        run(|asm| asm.movsd(), string, flags, true);
        run(|asm| asm.stosw(), string, flags, true);
        run(|asm| asm.stosd(), string, flags, true);
        run(|asm| asm.lodsw(), string, flags, true);
        run(|asm| asm.lodsd(), string, flags, true);

        // Rotate AF is keep. finish does not rewrite it; the memory write must not either.
        run(|asm| asm.rol(byte_ptr(rbx), 1u32), kept, flags, true);
        run(|asm| asm.ror(byte_ptr(rbx), 1u32), kept, flags, true);
        run(|asm| asm.rcl(byte_ptr(rbx), 1u32), kept, flags, true);
        run(|asm| asm.rcr(byte_ptr(rbx), 1u32), kept, flags, true);
    }
}
