use p256::elliptic_curve::zeroize::Zeroizing;
use rand::Rng;
use rand_chacha::ChaCha20Rng;

mod balance;
mod cipher;
mod exec;
pub mod form;
pub(crate) mod guard;
pub(crate) mod inner;
mod shape;
mod slots;
mod stack;
#[cfg(test)]
pub(crate) use cipher::xor_keystream;
pub use cipher::{
    apply_block, block_key, block_nonce, note_nonce, reseal_block, reseal_nonce, runtime_fits,
    weave_next, window_proofs, RuntimeTables, WindowProof, CACHE_OPEN, CACHE_SEALED, CHAIN_BYTES,
    CHAIN_FOLD, CHAIN_SAVE, CHAIN_SLOTS, CHANNEL, GS_CHAIN_AT, GS_CHAIN_PTR, INNER_AT, INNER_CAP,
    INNER_CIPHER, INNER_KEY, INNER_LEN, INNER_LOCK, INNER_NONCE, INNER_PLAIN, INNER_READY,
    INNER_REGION, RESEAL_MARK, RT_CLOCK_NS, RT_FOLD, RT_INDEX, RT_KEY, RT_KEYS, RT_LINUX,
    RT_MASTER, RT_SALT, RT_SCHED, RT_TERM, RUNTIME_WINDOW, TABLES_AT, TRAMP_DEPTH, TRAMP_SAVE,
    TRAMP_SLOTS, TRAMP_STRIDE, WEAVE_FRAME, WEAVE_SAVE,
};
pub(crate) use cipher::{apply_keystream, runtime_tables, NATIVE_MAX_RUNTIME_INSNS};
pub use cipher::{
    CTX_BOUND, CTX_CACHE, CTX_DEPTH, CTX_INDEX, CTX_KEYS, CTX_LEVEL, CTX_MAP, CTX_MAP_SLOTS,
    CTX_MAP_STRIDE, CTX_NEST, CTX_OPEN_CACHE, CTX_OPEN_INDEX, CTX_OPEN_KEYS, CTX_OPEN_RUNTIME,
    CTX_SALT, CTX_SAVED, GS_FRAME_AT, GS_FRAME_PTR, GS_MAP_BYTES, GS_TID,
};
pub use cipher::{KEY_LEN, SALT_LEN};
#[cfg(test)]
pub use exec::exec_image_crc_forced_ok;
pub use exec::{exec_image, exec_image_nested};
#[cfg(test)]
pub(crate) use exec::{open_high_water, probe_store64, reset_open_window};
pub use form::{collect_edges, MachineForm};
pub use guard::{admit_window, proofs, ContainProof, GuestMem};
pub use inner::{claims, open_dispatcher, seal_dispatcher, Claim, Sealed, LEVELS};
pub use slots::{
    reg_layout_bytes, slots_from_rng, SlotMap, CALL_DEPTH_LIMIT, FILE_STACK_BYTES, FRAME_BYTES,
    FRAME_CALLS, FRAME_DECODE, FRAME_DEPTH, FRAME_FILE_STACK, FRAME_FLAGS, FRAME_GATE, FRAME_IMAGE,
    FRAME_PLAIN, FRAME_SAVED_R12, FRAME_SAVED_R13, FRAME_SAVED_R14, FRAME_SAVED_RBX, FRAME_SPILL,
    FRAME_TARGET, FRAME_VSP, FRAME_VSTACK, LOGICAL_REGS, PRIVATE_STRIDE, REG_LAYOUT_LEN, RT_MIX,
    RT_SLOTS, SHADOW_COUNT, SLOT_COUNT, VSTACK_CAP,
};

use crate::crypto::authenticated::{BlockPurpose, BlockScope, MasterSecret};
use crate::error::{msg, Result};
use crate::ir::{Address, Exit, FuncIr, Op};

pub const NEST_XOR: u8 = 0xA5;

/// Opcodes the lifter lowers and both interpreters must execute.
/// The native stub selects a handler by running the level-2 program, not by
/// comparing these tags. Hot opcodes stay at the front of this slice for the
/// reports that name them. Handler bodies are still shuffled with the seed.
pub const BYTECODE_OPCODES: &[u8] = &[
    // Hot opcodes are listed first. The stub does not keep this exact order.
    0x41, 0x40, 0x21, 0x70, 0x03, 0x24, 0x32, 0x33, 0x61, 0x15, 0x17, 0x02, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x16, 0x18, 0x19, 0x20, 0x22, 0x23, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x50, 0x51, 0x52, 0x60, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
];

/// Opcodes with two native handler bodies. The bit in the runtime mix selects the body.
pub const VARIANT_OPCODES: [u8; 4] = [0x02, 0x03, 0x15, 0x17];

/// Opcodes on the hot path. The stub emits a seed-chosen prologue for each of them.
pub const HOT_OPCODES: &[u8] = &[
    0x41, 0x40, 0x21, 0x70, 0x03, 0x24, 0x32, 0x33, 0x61, 0x15, 0x17, 0x02,
];

/// Build choices that move with the protect seed. S7 reports this list next to the
/// measured stub difference. Equivalence with the oracle stays a separate claim.
pub const VARYING_ELEMENTS: &[&str] = &[
    "перестановка слотов",
    "варианты хендлеров",
    "соль шифра",
    "порядок junk",
    "форма машины",
    "переход между хендлерами",
];

/// Payload mask shared with the loader. Bytecode uses [`cipher`], not this LCG.
pub fn stream(mut seed: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for byte in data {
        out.push(byte ^ seed as u8);
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    }
    out
}

pub fn opcode_map(rng: &mut ChaCha20Rng) -> ([u8; 256], [u8; 256]) {
    let mut perm: Vec<u8> = (0..=255).collect();
    for index in (1..256).rev() {
        let swap = rng.gen_range(0..=index);
        perm.swap(index, swap);
    }
    let mut inv = [0u8; 256];
    for (index, value) in perm.iter().copied().enumerate() {
        inv[value as usize] = index as u8;
    }
    (perm.try_into().expect("256"), inv)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Bc {
    MovRr(u8, u8),
    MovRi(u8, u64),
    Load8(u8, u8),
    Store8(u8, u8),
    Load64(u8, u8),
    Store64(u8, u8),
    LeaSib {
        dst: u8,
        base: u8,
        index: u8,
        scale: u8,
        disp: i32,
    },
    LeaRva(u8, u32),
    AluRr(u8, u8, u8),
    AluRi(u8, u8, i32),
    CmpRr(u8, u8),
    CmpRi(u8, i32),
    TestRr(u8, u8),
    TestRi(u8, i32),
    Unary(u8, u8),
    Shift(u8, u8, u8),
    ImulRr(u8, u8),
    ImulRi(u8, i32),
    Div(u8),
    Push(u8),
    Pop(u8),
    StFlags(u8),
    LdFlags(u8),
    Jmp(u32),
    Jcc(u8, u32),
    CallRva(u32),
    CallReg(u8),
    Ret,
    Check(u32),
    Nest(Vec<u8>),
    Junk,
    PushR(u8),
    PushI(u64),
    StackAlu(u8),
    PopR(u8),
    StackUnary(u8),
    StackCmp(u8),
    StackShift(u8, u8),
    StackImul,
}

#[derive(Clone, Debug)]
pub struct EncodedInsn {
    /// Per-instruction tag from the build rng. It is not part of the ChaCha20 key.
    pub seed: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct BcFunc {
    pub name: String,
    pub rva: u32,
    pub entry: u32,
    pub insns: Vec<EncodedInsn>,
    /// Build salt mixed into every block nonce.
    pub salt: [u8; cipher::SALT_LEN],
    /// Legacy stream input. Scoped lab functions use their stored dispatcher and key page.
    pub key_seed: u32,
    scoped_dispatcher: Option<inner::ScopedDispatcher>,
    /// ChaCha20 key of block 0. Later blocks replace it with [`cipher::weave_next`].
    /// The bytes live on a non-dumpable page wiped in the fork child.
    pub key: crate::secret::KeyPage,
    /// Running key after every block has been absorbed in index order.
    pub terminal: [u8; cipher::KEY_LEN],
    /// Register or stack shape chosen from the protect seed and this function.
    pub form: form::MachineForm,
    /// No concrete input chooses among semantic edges.
    pub single_path: bool,
    /// Immediate schedule. Zero keeps hand-built images identical.
    pub sched: u64,
    /// The stub selects the next handler entry from the gate, including single-path functions.
    pub data_dependent: bool,
}

impl BcFunc {
    pub(crate) fn dispatcher(&self) -> Result<Sealed> {
        match &self.scoped_dispatcher {
            Some(dispatcher) => Ok(dispatcher.sealed()),
            None => inner::seal_dispatcher(self.key_seed, &self.salt),
        }
    }

    pub(crate) fn open_dispatcher(&self) -> Result<Vec<u8>> {
        match &self.scoped_dispatcher {
            Some(dispatcher) => Ok(dispatcher.open()),
            None => inner::open_dispatcher(self.key_seed, &self.salt),
        }
    }
}

impl std::fmt::Debug for BcFunc {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BcFunc")
            .field("name", &self.name)
            .field("rva", &self.rva)
            .field("entry", &self.entry)
            .field("instruction_count", &self.insns.len())
            .field("form", &self.form)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct BcImage {
    pub perm: [u8; 256],
    pub inv: [u8; 256],
    pub slots: SlotMap,
    pub handler_mix: u32,
    pub funcs: Vec<BcFunc>,
}

pub fn lower_image(funcs: &[FuncIr], rng: &mut ChaCha20Rng) -> Result<BcImage> {
    lower_image_with_scopes(funcs, rng, None)
}

/// Lower the lab VM representation using function-scoped material from a full build master.
///
/// Use each fresh artifact scope for a single lowering. The enclosing bootstrap
/// authenticates the encoded VM, which keeps its legacy runtime ABI.
pub(crate) fn lower_image_scoped(
    funcs: &[FuncIr],
    layout_rng: &mut ChaCha20Rng,
    master: &MasterSecret,
    artifact_scope: BlockScope,
) -> Result<BcImage> {
    use std::collections::BTreeSet;

    if funcs
        .iter()
        .map(|func| func.rva)
        .collect::<BTreeSet<_>>()
        .len()
        != funcs.len()
    {
        return Err(msg("duplicate function RVA in scoped VM build"));
    }
    lower_image_with_scopes(funcs, layout_rng, Some((master, artifact_scope)))
}

fn lower_image_with_scopes(
    funcs: &[FuncIr],
    rng: &mut ChaCha20Rng,
    scoped: Option<(&MasterSecret, BlockScope)>,
) -> Result<BcImage> {
    // Keep the historical layout RNG draw order in both modes.
    let base_salt = program_salt(rng.gen::<u64>().to_le_bytes(), funcs);
    let key_seed = rng.gen::<u32>() | 1;
    let (perm, inv) = opcode_map(rng);
    let slots = slots_from_rng(rng);
    let handler_mix = rng.gen::<u32>();
    let forms = form::assign_forms(u64::from(handler_mix), funcs);
    let sched = u64::from(handler_mix) | 1;
    let planned = plan_funcs(funcs, &slots, &forms, sched, rng)?;
    let out = seal_plans(planned, &perm, &base_salt, key_seed, scoped, rng)?;
    Ok(BcImage {
        perm,
        inv,
        slots,
        handler_mix,
        funcs: out,
    })
}

struct Planned {
    name: String,
    rva: u32,
    entry: u32,
    plain: Vec<Vec<u8>>,
    shape: form::MachineForm,
    single_path: bool,
    sched: u64,
}

fn plan_funcs(
    funcs: &[FuncIr],
    slots: &SlotMap,
    forms: &[form::MachineForm],
    sched: u64,
    rng: &mut ChaCha20Rng,
) -> Result<Vec<Planned>> {
    let mut planned = Vec::with_capacity(funcs.len());
    for (func, shape) in funcs.iter().zip(forms) {
        planned.push(plan_one(func, slots, *shape, sched, rng, STACK_BUDGET)?);
    }
    keep_stack(&mut planned, funcs, slots, sched, rng)?;
    Ok(planned)
}

fn plan_one(
    func: &FuncIr,
    slots: &SlotMap,
    shape: form::MachineForm,
    sched: u64,
    rng: &mut ChaCha20Rng,
    budget: usize,
) -> Result<Planned> {
    let flat = flatten_ops(func, slots)?;
    let (ops, junk_at) = shape::insert_junk(flat.ops, slots, flat.entry, rng);
    let (ops, entry) = place_check(ops, junk_at[flat.entry as usize]);
    let (ops, entry, shape) = fit_shape(ops, entry, shape, budget)?;
    Ok(Planned {
        name: func.name.clone(),
        rva: func.rva,
        entry,
        plain: encode_checked(&ops, entry, sched, func.rva)?,
        shape,
        single_path: form::is_single_path(func),
        sched,
    })
}

/// Re-plan the smallest function as a stack machine when every first choice was demoted.
/// Planning does not seal, so a rejected attempt does not reuse a ChaCha20 nonce.
fn keep_stack(
    planned: &mut [Planned],
    funcs: &[FuncIr],
    slots: &SlotMap,
    sched: u64,
    rng: &mut ChaCha20Rng,
) -> Result<()> {
    if funcs.len() < 2
        || planned
            .iter()
            .any(|row| row.shape == form::MachineForm::Stack)
    {
        return Ok(());
    }
    if install_stack(planned, funcs, slots, sched, rng, STACK_BUDGET)? {
        return Ok(());
    }
    // No body is under the step budget. Still keep one stack form when it fits
    // the runtime window, so a build of only large functions has both machines.
    if install_stack(planned, funcs, slots, sched, rng, usize::MAX)? {
        return Ok(());
    }
    Err(msg("stack form does not fit any function"))
}

fn install_stack(
    planned: &mut [Planned],
    funcs: &[FuncIr],
    slots: &SlotMap,
    sched: u64,
    rng: &mut ChaCha20Rng,
    budget: usize,
) -> Result<bool> {
    let mut order: Vec<usize> = (0..funcs.len()).collect();
    order.sort_by_key(|&index| ir_ops(&funcs[index]));
    for index in order {
        let row = plan_one(
            &funcs[index],
            slots,
            form::MachineForm::Stack,
            sched,
            rng,
            budget,
        )?;
        if row.shape == form::MachineForm::Stack {
            planned[index] = row;
            return Ok(true);
        }
    }
    Ok(false)
}

fn ir_ops(func: &FuncIr) -> usize {
    func.blocks.iter().map(|block| block.ops.len() + 1).sum()
}

fn seal_plans(
    planned: Vec<Planned>,
    perm: &[u8; 256],
    salt: &[u8; cipher::SALT_LEN],
    key_seed: u32,
    scoped: Option<(&MasterSecret, BlockScope)>,
    rng: &mut ChaCha20Rng,
) -> Result<Vec<BcFunc>> {
    let mut out = Vec::with_capacity(planned.len());
    for row in planned {
        out.push(seal_plan(row, perm, salt, key_seed, scoped, rng)?);
    }
    Ok(out)
}

fn seal_plan(
    row: Planned,
    perm: &[u8; 256],
    salt: &[u8; cipher::SALT_LEN],
    key_seed: u32,
    scoped: Option<(&MasterSecret, BlockScope)>,
    rng: &mut ChaCha20Rng,
) -> Result<BcFunc> {
    let (mut raw, salt, dispatcher) = match scoped {
        Some((master, artifact)) => {
            let mut function = [0; 16];
            function[..4].copy_from_slice(&row.rva.to_le_bytes());
            let scope = BlockScope {
                function,
                level: 1,
                purpose: BlockPurpose::Bytecode,
                ..artifact
            };
            let (key, salt) = master.scope(scope)?.vm_encoding_material()?;
            let (inner_key, nonce) = master
                .scope(BlockScope {
                    level: 2,
                    purpose: BlockPurpose::Dispatcher,
                    ..scope
                })?
                .vm_encoding_material()?;
            (
                key,
                salt,
                Some(inner::ScopedDispatcher::encode(&inner_key, nonce)?),
            )
        }
        None => (
            Zeroizing::new(cipher::block_key(key_seed, row.rva, salt)),
            *salt,
            None,
        ),
    };
    let sealed = seal_with_perm(
        &raw,
        row.rva,
        &salt,
        perm,
        &row.plain,
        rng,
        scoped.is_some(),
    );
    let key = hold_key(&mut raw);
    let (insns, terminal) = sealed?;
    let key_seed = if scoped.is_some() { 0 } else { key_seed };
    let mut func = bare_func(
        &row.name, row.rva, row.entry, insns, salt, key_seed, key?, terminal,
    );
    func.scoped_dispatcher = dispatcher;
    form::stamp_meta(&mut func, row.shape, row.single_path, row.sched);
    Ok(func)
}

/// Expanded stack bodies above this many ops push the protected sample past the
/// emulator step budget: every bytecode op opens the level-2 program with ChaCha.
const STACK_BUDGET: usize = 1_000;

fn fit_shape(
    ops: Vec<Bc>,
    entry: u32,
    shape: form::MachineForm,
    budget: usize,
) -> Result<(Vec<Bc>, u32, form::MachineForm)> {
    if shape != form::MachineForm::Stack {
        return Ok((ops, entry, shape));
    }
    let (grown, at) = stack::shape_ops(ops.clone(), entry, shape)?;
    if grown.len() <= budget && ops_fit(&grown)? {
        return Ok((grown, at, shape));
    }
    Ok((ops, entry, form::MachineForm::Register))
}

fn ops_fit(ops: &[Bc]) -> Result<bool> {
    let mut blob = 0usize;
    for op in ops {
        blob += encode_plain(op)?.len();
    }
    Ok(runtime_fits(0, ops.len(), blob).is_ok())
}

fn place_check(mut ops: Vec<Bc>, entry: u32) -> (Vec<Bc>, u32) {
    ops.insert(entry as usize, Bc::Check(0));
    bump_targets_at(&mut ops, entry);
    (ops, entry)
}

struct FlatOps {
    ops: Vec<Bc>,
    entry: u32,
}

fn flatten_ops(func: &FuncIr, slots: &SlotMap) -> Result<FlatOps> {
    let mut blocks = Vec::with_capacity(func.blocks.len());
    for block in &func.blocks {
        blocks.push(lower_block(block)?);
    }
    let mut start = vec![0u32; blocks.len()];
    let mut flat = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        start[index] = flat.len() as u32;
        flat.extend(block.iter().cloned());
    }
    retarget_blocks(&mut flat, &start);
    for op in &mut flat {
        shape::remap_regs(op, slots)?;
    }
    Ok(FlatOps {
        entry: start[func.entry as usize],
        ops: flat,
    })
}

fn lower_block(block: &crate::ir::Block) -> Result<Vec<Bc>> {
    let mut ops = Vec::new();
    for op in &block.ops {
        ops.push(lower_op(op)?);
    }
    match block.exit {
        Exit::Jmp(target) => ops.push(Bc::Jmp(target)),
        Exit::Jcc(cond, yes, no) => {
            ops.push(Bc::Jcc(cond, yes));
            ops.push(Bc::Jmp(no));
        }
        Exit::CallRva { rva, next } => {
            ops.push(Bc::CallRva(rva));
            ops.push(Bc::Jmp(next));
        }
        Exit::CallAbs { reg, next } => push_call_abs(&mut ops, reg, next)?,
        Exit::Ret => ops.push(Bc::Ret),
    }
    Ok(ops)
}

fn push_call_abs(ops: &mut Vec<Bc>, reg: u16, next: u32) -> Result<()> {
    let index = u8::try_from(reg).map_err(|_| msg("register index out of range"))?;
    if usize::from(index) >= LOGICAL_REGS {
        return Err(msg("register index out of range"));
    }
    ops.push(Bc::CallReg(index));
    ops.push(Bc::Jmp(next));
    Ok(())
}

fn retarget_blocks(flat: &mut [Bc], start: &[u32]) {
    for op in flat {
        match op {
            Bc::Jmp(target) => *target = start[*target as usize],
            Bc::Jcc(_, target) => *target = start[*target as usize],
            _ => {}
        }
    }
}

fn bump_targets_at(flat: &mut [Bc], entry: u32) {
    for op in flat {
        match op {
            Bc::Jmp(target) | Bc::Jcc(_, target) if *target >= entry => *target += 1,
            _ => {}
        }
    }
}

fn encode_checked(flat: &[Bc], entry: u32, sched: u64, rva: u32) -> Result<Vec<Vec<u8>>> {
    let mut plain = Vec::with_capacity(flat.len());
    for op in flat {
        plain.push(encode_plain(op)?);
    }
    form::mask_block(&mut plain, sched, rva);
    let crc = crc_insns(&plain);
    if let Bc::Check(_) = &flat[entry as usize] {
        plain[entry as usize] = encode_plain(&Bc::Check(crc))?;
    }
    Ok(plain)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn bare_func(
    name: &str,
    rva: u32,
    entry: u32,
    insns: Vec<EncodedInsn>,
    salt: [u8; cipher::SALT_LEN],
    key_seed: u32,
    key: crate::secret::KeyPage,
    terminal: [u8; cipher::KEY_LEN],
) -> BcFunc {
    BcFunc {
        name: name.to_string(),
        rva,
        entry,
        insns,
        salt,
        key_seed,
        scoped_dispatcher: None,
        key,
        terminal,
        form: form::MachineForm::Register,
        single_path: false,
        sched: 0,
        data_dependent: false,
    }
}

fn hold_key(raw: &mut [u8; cipher::KEY_LEN]) -> Result<crate::secret::KeyPage> {
    let key = crate::secret::KeyPage::hold(raw);
    crate::secret::wipe(raw);
    key
}

/// Permute byte 0, seal the block with ChaCha20, and fold that ciphertext into the key.
fn seal_with_perm(
    key: &[u8; cipher::KEY_LEN],
    rva: u32,
    salt: &[u8; cipher::SALT_LEN],
    perm: &[u8; 256],
    plains: &[Vec<u8>],
    rng: &mut ChaCha20Rng,
    scoped: bool,
) -> Result<(Vec<EncodedInsn>, [u8; cipher::KEY_LEN])> {
    let mut running = *key;
    let mut insns = Vec::with_capacity(plains.len());
    for (index, canonical) in plains.iter().enumerate() {
        let mut bytes = canonical.clone();
        bytes[0] = perm[bytes[0] as usize];
        let seed = rng.gen::<u32>() | 1;
        let block = u32::try_from(index).map_err(|_| msg("instruction index fits in u32"))?;
        let nonce = cipher::block_nonce(block, salt, rva);
        if scoped {
            if block >= cipher::RESEAL_MARK {
                return Err(msg("scoped VM block index exhausted"));
            }
            crate::crypto::chacha20(&running, &nonce, &mut bytes);
        } else {
            cipher::xor_keystream(&running, &nonce, 0, &mut bytes)?;
        }
        running = cipher::weave_next(&running, block, &bytes);
        insns.push(EncodedInsn { seed, bytes });
    }
    Ok((insns, running))
}

/// Seal identity-mapped plaintext and return the ciphertext, the block-0 key, and the closing key.
pub fn seal_chain(
    key_seed: u32,
    rva: u32,
    salt: &[u8; cipher::SALT_LEN],
    plains: &[Vec<u8>],
) -> Result<(
    Vec<EncodedInsn>,
    [u8; cipher::KEY_LEN],
    [u8; cipher::KEY_LEN],
)> {
    let key = cipher::block_key(key_seed, rva, salt);
    let mut running = key;
    let mut insns = Vec::with_capacity(plains.len());
    for (index, plain) in plains.iter().enumerate() {
        let mut bytes = plain.clone();
        let block = u32::try_from(index).map_err(|_| msg("instruction index fits in u32"))?;
        cipher::xor_keystream(
            &running,
            &cipher::block_nonce(block, salt, rva),
            0,
            &mut bytes,
        )?;
        running = cipher::weave_next(&running, block, &bytes);
        insns.push(EncodedInsn {
            seed: key_seed,
            bytes,
        });
    }
    Ok((insns, key, running))
}

fn lower_op(op: &Op) -> Result<Bc> {
    let r = |reg: u16| -> Result<u8> {
        let index = u8::try_from(reg)
            .map_err(|_| msg("virtual register does not fit in a bytecode index"))?;
        if usize::from(index) >= LOGICAL_REGS {
            return Err(msg("register index out of range"));
        }
        Ok(index)
    };
    Ok(match *op {
        Op::MovRr(d, s) => {
            let mut body = Vec::new();
            encode_into(&Bc::MovRr(r(d)?, r(s)?), &mut body)?;
            for byte in &mut body {
                *byte ^= NEST_XOR;
            }
            Bc::Nest(body)
        }
        Op::MovRi(d, imm) => Bc::MovRi(r(d)?, imm),
        Op::Load8(d, a) => Bc::Load8(r(d)?, r(a)?),
        Op::Store8(a, s) => Bc::Store8(r(a)?, r(s)?),
        Op::Load64(d, a) => Bc::Load64(r(d)?, r(a)?),
        Op::Store64(a, s) => Bc::Store64(r(a)?, r(s)?),
        Op::Lea(d, Address::Rva(rva)) => Bc::LeaRva(r(d)?, rva),
        Op::Lea(
            d,
            Address::Sib {
                base,
                index,
                scale,
                disp,
            },
        ) => {
            let disp =
                i32::try_from(disp).map_err(|_| msg("lea displacement does not fit in i32"))?;
            Bc::LeaSib {
                dst: r(d)?,
                base: base.map(r).transpose()?.unwrap_or(0xff),
                index: index.map(r).transpose()?.unwrap_or(0xff),
                scale,
                disp,
            }
        }
        Op::AddRr(d, s) => Bc::AluRr(0, r(d)?, r(s)?),
        Op::SubRr(d, s) => Bc::AluRr(1, r(d)?, r(s)?),
        Op::XorRr(d, s) => Bc::AluRr(2, r(d)?, r(s)?),
        Op::AndRr(d, s) => Bc::AluRr(3, r(d)?, r(s)?),
        Op::OrRr(d, s) => Bc::AluRr(4, r(d)?, r(s)?),
        Op::AddRi(d, imm) => Bc::AluRi(0, r(d)?, imm),
        Op::SubRi(d, imm) => Bc::AluRi(1, r(d)?, imm),
        Op::XorRi(d, imm) => Bc::AluRi(2, r(d)?, imm),
        Op::AndRi(d, imm) => Bc::AluRi(3, r(d)?, imm),
        Op::OrRi(d, imm) => Bc::AluRi(4, r(d)?, imm),
        Op::CmpRr(d, s) => Bc::CmpRr(r(d)?, r(s)?),
        Op::CmpRi(d, imm) => Bc::CmpRi(r(d)?, imm),
        Op::TestRr(d, s) => Bc::TestRr(r(d)?, r(s)?),
        Op::TestRi(d, imm) => Bc::TestRi(r(d)?, imm),
        Op::Not(d) => Bc::Unary(0, r(d)?),
        Op::Neg(d) => Bc::Unary(1, r(d)?),
        Op::Inc(d) => Bc::Unary(2, r(d)?),
        Op::Dec(d) => Bc::Unary(3, r(d)?),
        Op::Shl(d, c) => Bc::Shift(0, r(d)?, c),
        Op::Shr(d, c) => Bc::Shift(1, r(d)?, c),
        Op::Sar(d, c) => Bc::Shift(2, r(d)?, c),
        Op::Rol(d, c) => Bc::Shift(3, r(d)?, c),
        Op::Ror(d, c) => Bc::Shift(4, r(d)?, c),
        Op::ImulRr(d, s) => Bc::ImulRr(r(d)?, r(s)?),
        Op::ImulRi(d, imm) => Bc::ImulRi(r(d)?, imm),
        Op::Div(s) => Bc::Div(r(s)?),
        Op::Push(s) => Bc::Push(r(s)?),
        Op::Pop(d) => Bc::Pop(r(d)?),
        Op::StFlags(d) => Bc::StFlags(r(d)?),
        Op::LdFlags(s) => Bc::LdFlags(r(s)?),
    })
}

fn encode_plain(op: &Bc) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_into(op, &mut out)?;
    Ok(out)
}

fn encode_into(op: &Bc, out: &mut Vec<u8>) -> Result<()> {
    if stack::put(op, out) || encode_move(op, out) || encode_alu(op, out) {
        return Ok(());
    }
    encode_flow(op, out)
}

fn encode_move(op: &Bc, out: &mut Vec<u8>) -> bool {
    match op {
        Bc::MovRr(d, s) => out.extend([0x02, *d, *s]),
        Bc::MovRi(d, imm) => {
            out.extend([0x03, *d]);
            out.extend(imm.to_le_bytes());
        }
        Bc::Load8(d, a) => out.extend([0x04, *d, *a]),
        Bc::Store8(a, s) => out.extend([0x05, *a, *s]),
        Bc::Load64(d, a) => out.extend([0x06, *d, *a]),
        Bc::Store64(a, s) => out.extend([0x07, *a, *s]),
        Bc::LeaSib {
            dst,
            base,
            index,
            scale,
            disp,
        } => {
            out.extend([0x08, *dst, *base, *index, *scale]);
            out.extend(disp.to_le_bytes());
        }
        Bc::LeaRva(d, rva) => {
            out.extend([0x09, *d]);
            out.extend(rva.to_le_bytes());
        }
        _ => return false,
    }
    true
}

fn encode_alu(op: &Bc, out: &mut Vec<u8>) -> bool {
    match op {
        Bc::AluRr(k, d, s) => out.extend([0x10 + k, *d, *s]),
        Bc::AluRi(k, d, imm) => {
            out.extend([0x15 + k, *d]);
            out.extend(imm.to_le_bytes());
        }
        Bc::CmpRr(d, s) => out.extend([0x20, *d, *s]),
        Bc::CmpRi(d, imm) => {
            out.extend([0x21, *d]);
            out.extend(imm.to_le_bytes());
        }
        Bc::TestRr(d, s) => out.extend([0x22, *d, *s]),
        Bc::TestRi(d, imm) => {
            out.extend([0x23, *d]);
            out.extend(imm.to_le_bytes());
        }
        Bc::Unary(k, d) => out.extend([0x24 + k, *d]),
        Bc::Shift(k, d, c) => out.extend([0x28 + k, *d, *c]),
        Bc::ImulRr(d, s) => out.extend([0x2d, *d, *s]),
        Bc::ImulRi(d, imm) => {
            out.extend([0x2e, *d]);
            out.extend(imm.to_le_bytes());
        }
        Bc::Div(s) => out.extend([0x2f, *s]),
        Bc::Push(s) => out.extend([0x30, *s]),
        Bc::Pop(d) => out.extend([0x31, *d]),
        Bc::StFlags(d) => out.extend([0x32, *d]),
        Bc::LdFlags(s) => out.extend([0x33, *s]),
        _ => return false,
    }
    true
}

fn encode_flow(op: &Bc, out: &mut Vec<u8>) -> Result<()> {
    match op {
        Bc::Jmp(t) => {
            out.push(0x40);
            out.extend(t.to_le_bytes());
        }
        Bc::Jcc(c, t) => {
            out.extend([0x41, *c]);
            out.extend(t.to_le_bytes());
        }
        Bc::CallRva(rva) => {
            out.push(0x50);
            out.extend(rva.to_le_bytes());
        }
        Bc::CallReg(reg) => out.extend([0x51, *reg]),
        Bc::Ret => out.push(0x52),
        Bc::Check(v) => {
            out.push(0x60);
            out.extend(v.to_le_bytes());
        }
        Bc::Nest(body) => {
            let len =
                u8::try_from(body.len()).map_err(|_| msg("nested bytecode exceeds 255 bytes"))?;
            out.push(0x61);
            out.push(len);
            out.extend(body);
        }
        Bc::Junk => out.push(0x70),
        _ => return Err(msg("bytecode encoder missed an opcode")),
    }
    Ok(())
}

fn crc_insns(insns: &[Vec<u8>]) -> u32 {
    !crc_prefix(insns)
}

/// Running CRC over one instruction at a time. The caller inverts the result.
pub(super) fn crc_prefix(insns: &[Vec<u8>]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for insn in insns {
        crc = fold_insn_crc(crc, insn);
    }
    crc
}

pub(super) fn fold_insn_crc(mut crc: u32, insn: &[u8]) -> u32 {
    for (index, byte) in insn.iter().enumerate() {
        let value = if insn.first() == Some(&0x60) && insn.len() >= 5 && (1..5).contains(&index) {
            0
        } else {
            *byte
        };
        crc = crc_step(crc, value);
    }
    crc
}

fn crc_step(mut crc: u32, byte: u8) -> u32 {
    crc ^= u32::from(byte);
    for _ in 0..8 {
        let mask = 0u32.wrapping_sub(crc & 1);
        crc = (crc >> 1) ^ (0xedb8_8320 & mask);
    }
    crc
}

#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc = crc_step(crc, *byte);
    }
    !crc
}

/// Mix the program into `base` so two programs lowered in one process do not
/// share a ChaCha20 nonce. The same program and the same `base` stay put.
fn program_salt(mut salt: [u8; cipher::SALT_LEN], funcs: &[FuncIr]) -> [u8; cipher::SALT_LEN] {
    for func in funcs {
        mix_salt(&mut salt, func.name.as_bytes());
        mix_salt(&mut salt, &func.rva.to_le_bytes());
        mix_salt(&mut salt, &func.entry.to_le_bytes());
        for block in &func.blocks {
            mix_salt(&mut salt, &[u8::from(block.opaque)]);
            mix_salt(&mut salt, format!("{:?}", block.exit).as_bytes());
            for op in &block.ops {
                mix_salt(&mut salt, format!("{op:?}").as_bytes());
            }
        }
    }
    salt
}

fn mix_salt(salt: &mut [u8; cipher::SALT_LEN], bytes: &[u8]) {
    for byte in bytes {
        let mixed = crc_step(
            u32::from_le_bytes([salt[0], salt[1], salt[2], salt[3]]),
            *byte,
        );
        let fold = mixed.to_le_bytes();
        salt[0] ^= fold[0];
        salt[1] ^= fold[1];
        salt[2] ^= fold[2];
        salt[3] ^= fold[3];
        salt[4] = salt[4].wrapping_add(fold[0]).wrapping_add(*byte);
        salt[5] ^= fold[1].wrapping_add(*byte);
        salt[6] = salt[6].wrapping_add(fold[2]);
        salt[7] ^= fold[3].rotate_left(1);
    }
}

/// Distinct salt for a caller that must not share `base`. An image's functions
/// keep one salt; their nonces diverge by RVA instead.
#[cfg(test)]
fn salt_for_func(base: [u8; cipher::SALT_LEN], nth: usize) -> [u8; cipher::SALT_LEN] {
    if nth == 0 {
        return base;
    }
    let mut salt = base;
    let raw = nth.to_le_bytes();
    for (index, byte) in raw.iter().enumerate() {
        salt[index % cipher::SALT_LEN] ^= *byte;
    }
    if salt == base {
        salt[7] ^= 1;
    }
    salt
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8> {
        let value = *self
            .data
            .get(self.at)
            .ok_or_else(|| msg("bytecode ended early"))?;
        self.at += 1;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(buf))
    }
    fn u64(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(buf))
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| msg("bytecode length overflow"))?;
        let slice = self
            .data
            .get(self.at..end)
            .ok_or_else(|| msg("bytecode ended early"))?;
        self.at = end;
        Ok(slice)
    }
}

fn decode(plain: &[u8]) -> Result<Bc> {
    Ok(decode_span(plain)?.0)
}

fn decode_span(plain: &[u8]) -> Result<(Bc, usize)> {
    let mut r = Reader { data: plain, at: 0 };
    let tag = r.byte()?;
    let op = decode_op(&mut r, tag)?;
    Ok((op, r.at))
}

fn decode_op(r: &mut Reader<'_>, tag: u8) -> Result<Bc> {
    if let Some(op) = decode_stack(r, tag)? {
        return Ok(op);
    }
    if let Some(op) = decode_data(r, tag)? {
        return Ok(op);
    }
    decode_flow(r, tag)
}

fn decode_stack(r: &mut Reader<'_>, tag: u8) -> Result<Option<Bc>> {
    let op = match tag {
        0x34 => Bc::PushR(r.byte()?),
        0x35 => Bc::PushI(r.u64()?),
        0x36 => Bc::StackAlu(r.byte()?),
        0x37 => Bc::PopR(r.byte()?),
        0x38 => Bc::StackUnary(r.byte()?),
        0x39 => Bc::StackCmp(r.byte()?),
        0x3a => Bc::StackShift(r.byte()?, r.byte()?),
        0x3b => Bc::StackImul,
        _ => return Ok(None),
    };
    Ok(Some(op))
}

fn decode_data(r: &mut Reader<'_>, tag: u8) -> Result<Option<Bc>> {
    let op = match tag {
        0x02 => Bc::MovRr(r.byte()?, r.byte()?),
        0x03 => Bc::MovRi(r.byte()?, r.u64()?),
        0x04 => Bc::Load8(r.byte()?, r.byte()?),
        0x05 => Bc::Store8(r.byte()?, r.byte()?),
        0x06 => Bc::Load64(r.byte()?, r.byte()?),
        0x07 => Bc::Store64(r.byte()?, r.byte()?),
        0x08 => Bc::LeaSib {
            dst: r.byte()?,
            base: r.byte()?,
            index: r.byte()?,
            scale: r.byte()?,
            disp: r.i32()?,
        },
        0x09 => Bc::LeaRva(r.byte()?, r.u32()?),
        0x10..=0x14 => Bc::AluRr(tag - 0x10, r.byte()?, r.byte()?),
        0x15..=0x19 => Bc::AluRi(tag - 0x15, r.byte()?, r.i32()?),
        0x20 => Bc::CmpRr(r.byte()?, r.byte()?),
        0x21 => Bc::CmpRi(r.byte()?, r.i32()?),
        0x22 => Bc::TestRr(r.byte()?, r.byte()?),
        0x23 => Bc::TestRi(r.byte()?, r.i32()?),
        _ => return Ok(None),
    };
    Ok(Some(op))
}

fn decode_flow(r: &mut Reader<'_>, tag: u8) -> Result<Bc> {
    Ok(match tag {
        0x24..=0x27 => Bc::Unary(tag - 0x24, r.byte()?),
        0x28..=0x2c => Bc::Shift(tag - 0x28, r.byte()?, r.byte()?),
        0x2d => Bc::ImulRr(r.byte()?, r.byte()?),
        0x2e => Bc::ImulRi(r.byte()?, r.i32()?),
        0x2f => Bc::Div(r.byte()?),
        0x30 => Bc::Push(r.byte()?),
        0x31 => Bc::Pop(r.byte()?),
        0x32 => Bc::StFlags(r.byte()?),
        0x33 => Bc::LdFlags(r.byte()?),
        0x40 => Bc::Jmp(r.u32()?),
        0x41 => Bc::Jcc(r.byte()?, r.u32()?),
        0x50 => Bc::CallRva(r.u32()?),
        0x51 => Bc::CallReg(r.byte()?),
        0x52 => Bc::Ret,
        0x60 => Bc::Check(r.u32()?),
        0x61 => {
            let len = r.byte()? as usize;
            Bc::Nest(r.take(len)?.to_vec())
        }
        0x70..=0x7f => Bc::Junk,
        other => return Err(msg(format!("unknown bytecode tag {other:#x}"))),
    })
}

/// Decrypt block `index` under `key` and restore the canonical opcode byte.
pub(super) fn decrypt_at(
    func: &BcFunc,
    index: usize,
    inv: &[u8; 256],
    key: &[u8; cipher::KEY_LEN],
) -> Result<Vec<u8>> {
    let insn = func
        .insns
        .get(index)
        .ok_or_else(|| msg("vm ip out of range"))?;
    let block = u32::try_from(index).map_err(|_| msg("vm ip out of range"))?;
    let mut plain = insn.bytes.clone();
    let nonce = cipher::block_nonce(block, &func.salt, func.rva);
    if func.scoped_dispatcher.is_some() {
        crate::crypto::chacha20(key, &nonce, &mut plain);
    } else {
        cipher::xor_keystream(key, &nonce, 0, &mut plain)?;
    }
    if plain.is_empty() {
        return Err(msg("empty bytecode instruction"));
    }
    plain[0] = inv[plain[0] as usize];
    Ok(plain)
}

/// Open one instruction. Its key is the weave of every block below it.
///
/// Data immediates stay masked. Execution and a search that keeps the schedule
/// call [`form::mix_imm`] on this buffer.
pub fn plain_insn(func: &BcFunc, index: usize, inv: &[u8; 256]) -> Result<Vec<u8>> {
    masked_insn(func, index, inv)
}

/// Open one instruction and leave the immediate schedule in place.
pub fn masked_insn(func: &BcFunc, index: usize, inv: &[u8; 256]) -> Result<Vec<u8>> {
    if index >= func.insns.len() {
        return Err(msg("vm ip out of range"));
    }
    let mut key = func.key.bytes();
    for at in 0..index {
        let block = u32::try_from(at).map_err(|_| msg("vm ip out of range"))?;
        let next = cipher::weave_next(&key, block, &func.insns[at].bytes);
        crate::secret::wipe(&mut key);
        key = next;
    }
    let plain = decrypt_at(func, index, inv, &key);
    crate::secret::wipe(&mut key);
    plain
}

pub type HostCall<'a> = crate::ir::HostCall<'a>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::Flags;
    use crate::ir::{exec_func, Address, Block, Exit, FuncIr, MapMem, MemIo, Op};
    use crate::obf::obfuscate;
    use rand::SeedableRng;

    fn sample() -> FuncIr {
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

    fn run_both(func: &FuncIr, arg: u64, seed: u64) -> (u64, u64) {
        let mut arch = [0u64; 16];
        arch[1] = arg;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut abs = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        exec_func(
            std::slice::from_ref(func),
            0,
            &mut arch,
            &mut flags,
            &mut mem,
            0x140000000,
            &mut abs,
        )
        .unwrap();
        let ir_rax = arch[0];
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let image = lower_image(std::slice::from_ref(func), &mut rng).unwrap();
        arch[1] = arg;
        arch[0] = 0;
        exec_image(
            &image,
            0,
            &mut arch,
            &mut flags,
            &mut mem,
            0x140000000,
            &mut abs,
        )
        .unwrap();
        (ir_rax, arch[0])
    }

    fn linear_opcodes(bytes: &[u8]) -> crate::error::Result<Vec<u8>> {
        let mut tags = Vec::new();
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            let (_, used) = decode_span(&bytes[cursor..])?;
            if used == 0 {
                return Err(crate::error::msg("empty bytecode window"));
            }
            tags.push(bytes[cursor]);
            cursor += used;
        }
        Ok(tags)
    }

    fn linear_opcodes_with_inv(bytes: &[u8], inv: &[u8; 256]) -> crate::error::Result<Vec<u8>> {
        let mut tags = Vec::new();
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            let mut window = bytes[cursor..].to_vec();
            window[0] = inv[window[0] as usize];
            let (_, used) = decode_span(&window)?;
            if used == 0 {
                return Err(crate::error::msg("empty bytecode window"));
            }
            tags.push(window[0]);
            cursor += used;
        }
        Ok(tags)
    }

    fn assert_permutation_decodes_and_cipher_does_not(func: &BcFunc, inv: &[u8; 256]) -> Vec<u8> {
        assert_eq!(
            func.key.bytes(),
            block_key(func.key_seed, func.rva, &func.salt)
        );
        let wrong = block_key(func.key_seed ^ 0x00ff_ffff, func.rva, &func.salt);
        assert_ne!(func.key.bytes(), wrong);
        let mut permuted = Vec::new();
        let mut sealed = Vec::new();
        let mut running = func.key.bytes();
        for (index, insn) in func.insns.iter().enumerate() {
            let block = u32::try_from(index).expect("instruction index");
            let nonce = cipher::block_nonce(block, &func.salt, func.rva);
            let mut opened = insn.bytes.clone();
            cipher::xor_keystream(&running, &nonce, 0, &mut opened).unwrap();
            if index == 0 {
                assert_eq!(
                    opened,
                    apply_block(func.key_seed, func.rva, &func.salt, block, &insn.bytes).unwrap()
                );
            }
            let mut canonical = opened.clone();
            canonical[0] = inv[opened[0] as usize];
            assert_eq!(plain_insn(func, index, inv).unwrap(), canonical);
            permuted.extend_from_slice(&opened);
            sealed.extend_from_slice(&insn.bytes);
            let mut bad = insn.bytes.clone();
            assert!(
                cipher::xor_keystream(&wrong, &nonce, 0, &mut bad).is_err(),
                "nonce reused under another key"
            );
            running = weave_next(&running, block, &insn.bytes);
        }
        assert_eq!(running, func.terminal);
        assert_ne!(permuted, sealed);
        let tags =
            linear_opcodes_with_inv(&permuted, inv).expect("permuted plaintext decodes with inv");
        assert!(linear_opcodes(&sealed).is_err(), "{}", func.name);
        assert!(
            linear_opcodes_with_inv(&sealed, inv).is_err(),
            "{}",
            func.name
        );
        tags
    }

    #[test]
    fn sample_ciphertext_is_not_a_linear_opcode_sequence() {
        use crate::lift::lift;
        use crate::obf::obfuscate;
        use crate::pe;
        use crate::sample;
        let built = sample::build().unwrap();
        let image = pe::parse(&built.bytes).unwrap();
        let mut funcs = Vec::new();
        for sym in &built.symbols {
            let bytes = pe::read_rva(&image, sym.rva, sym.size as usize).unwrap();
            let func = lift(&sym.name, bytes, sym.rva, sym.size, image.image_base).unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(1 ^ u64::from(sym.rva));
            funcs.push(obfuscate(&func, &mut rng).func);
        }
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let lowered = lower_image(&funcs, &mut rng).unwrap();
        for func in &lowered.funcs {
            let tags = assert_permutation_decodes_and_cipher_does_not(func, &lowered.inv);
            assert!(tags.len() > 4, "{}", func.name);
        }
    }

    #[test]
    fn permuted_plaintext_decodes_with_inv_without_chacha() {
        let mut perm = [0u8; 256];
        for (index, slot) in perm.iter_mut().enumerate() {
            *slot = index as u8;
        }
        perm.swap(0x03, 0x00);
        perm.swap(0x52, 0x01);
        let mut inv = [0u8; 256];
        for (index, value) in perm.iter().copied().enumerate() {
            inv[value as usize] = index as u8;
        }
        let salt = [0x11u8; 8];
        let key_seed = 1u32;
        let rva = 0x1000u32;
        let plains = [vec![0x03u8, 0, 1, 0, 0, 0, 0, 0, 0, 0], vec![0x52u8]];
        let mut preimage = Vec::new();
        let mut running = block_key(key_seed, rva, &salt);
        let mut insns = Vec::new();
        for (index, plain) in plains.iter().enumerate() {
            let mut bytes = plain.clone();
            bytes[0] = perm[bytes[0] as usize];
            preimage.extend_from_slice(&bytes);
            let block = index as u32;
            let nonce = cipher::block_nonce(block, &salt, rva);
            cipher::xor_keystream(&running, &nonce, 0, &mut bytes).unwrap();
            insns.push(EncodedInsn {
                seed: key_seed,
                bytes: bytes.clone(),
            });
            running = weave_next(&running, block, &bytes);
        }
        let terminal = running;
        assert!(linear_opcodes(&preimage).is_err());
        assert_eq!(
            linear_opcodes_with_inv(&preimage, &inv).unwrap(),
            vec![0x03, 0x52]
        );
        let func = super::bare_func(
            "separated",
            rva,
            0,
            insns,
            salt,
            key_seed,
            crate::secret::KeyPage::hold(&block_key(key_seed, rva, &salt)).unwrap(),
            terminal,
        );
        let tags = assert_permutation_decodes_and_cipher_does_not(&func, &inv);
        assert_eq!(tags, vec![0x03, 0x52]);
    }

    #[test]
    fn vm_matches_ir_and_changes_with_seed() {
        let func = sample();
        let (ir, vm) = run_both(&func, 10, 1);
        assert_eq!(ir, (10u64.wrapping_mul(7).wrapping_add(3)) ^ 0x5a);
        assert_eq!(vm, ir);
        let mut a = ChaCha20Rng::seed_from_u64(1);
        let mut b = ChaCha20Rng::seed_from_u64(2);
        let left = lower_image(std::slice::from_ref(&func), &mut a).unwrap();
        let right = lower_image(std::slice::from_ref(&func), &mut b).unwrap();
        let lb: Vec<u8> = left.funcs[0]
            .insns
            .iter()
            .flat_map(|insn| insn.bytes.clone())
            .collect();
        let rb: Vec<u8> = right.funcs[0]
            .insns
            .iter()
            .flat_map(|insn| insn.bytes.clone())
            .collect();
        assert_ne!(lb, rb);
    }

    #[test]
    fn obfuscated_bytecode_matches_and_tamper_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let obf = obfuscate(&sample(), &mut rng).func;
        let (ir, vm) = run_both(&obf, 4, 8);
        assert_eq!(ir, vm);
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let mut image = lower_image(std::slice::from_ref(&obf), &mut rng).unwrap();
        let entry = image.funcs[0].entry as usize;
        let junk = plain_insn(&image.funcs[0], entry + 1, &image.inv).unwrap();
        assert_eq!(junk[0], 0x70);
        image.funcs[0].insns[3].bytes[0] ^= 0xff;
        let mut arch = [0u64; 16];
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut abs = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        let err = exec_image(&image, 0, &mut arch, &mut flags, &mut mem, 0, &mut abs).unwrap_err();
        let failed_closed = match &err {
            crate::error::Error::Integrity => true,
            crate::error::Error::Msg(text) => text.contains("chacha20 nonce"),
            _ => false,
        };
        assert!(failed_closed, "{err}");
    }

    #[test]
    fn crc32_known_answer() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn every_ir_op_lowers_to_a_handled_opcode() {
        let ops = [
            Op::MovRr(1, 2),
            Op::MovRi(0, 1),
            Op::Load8(0, 1),
            Op::Store8(1, 0),
            Op::Load64(0, 1),
            Op::Store64(1, 0),
            Op::Lea(0, Address::Rva(0x1000)),
            Op::Lea(
                0,
                Address::Sib {
                    base: Some(1),
                    index: Some(2),
                    scale: 4,
                    disp: 8,
                },
            ),
            Op::AddRr(0, 1),
            Op::SubRr(0, 1),
            Op::XorRr(0, 1),
            Op::AndRr(0, 1),
            Op::OrRr(0, 1),
            Op::AddRi(0, 1),
            Op::SubRi(0, 1),
            Op::XorRi(0, 1),
            Op::AndRi(0, 1),
            Op::OrRi(0, 1),
            Op::CmpRr(0, 1),
            Op::CmpRi(0, 1),
            Op::TestRr(0, 1),
            Op::TestRi(0, 1),
            Op::Not(0),
            Op::Neg(0),
            Op::Inc(0),
            Op::Dec(0),
            Op::Shl(0, 1),
            Op::Shr(0, 1),
            Op::Sar(0, 1),
            Op::Rol(0, 1),
            Op::Ror(0, 1),
            Op::ImulRr(0, 1),
            Op::ImulRi(0, 3),
            Op::Div(1),
            Op::Push(0),
            Op::Pop(0),
            Op::StFlags(0),
            Op::LdFlags(0),
        ];
        for op in ops {
            let encoded = encode_plain(&lower_op(&op).unwrap()).unwrap();
            assert!(
                BYTECODE_OPCODES.contains(&encoded[0]),
                "{op:?} -> {:#x}",
                encoded[0]
            );
            if encoded[0] == 0x61 {
                let mut inner = encoded[2..].to_vec();
                for byte in &mut inner {
                    *byte ^= NEST_XOR;
                }
                assert!(BYTECODE_OPCODES.contains(&inner[0]));
            }
        }
    }

    #[test]
    fn register_index_past_the_file_is_an_error() {
        let mut perm = [0u8; 256];
        let mut inv = [0u8; 256];
        for (index, slot) in perm.iter_mut().enumerate() {
            *slot = index as u8;
            inv[index] = index as u8;
        }
        let plain = vec![0x03, 240, 1, 0, 0, 0, 0, 0, 0, 0];
        let salt = [0x93u8; 8];
        let mut raw = block_key(1, 0x1000, &salt);
        let sealed = apply_block(1, 0x1000, &salt, 0, &plain).unwrap();
        let terminal = weave_next(&raw, 0, &sealed);
        let key = crate::secret::KeyPage::hold(&raw).unwrap();
        crate::secret::wipe(&mut raw);
        let image = BcImage {
            perm,
            inv,
            slots: SlotMap::identity(),
            handler_mix: 0,
            funcs: vec![super::bare_func(
                "bad",
                0x1000,
                0,
                vec![EncodedInsn {
                    seed: 1,
                    bytes: sealed,
                }],
                salt,
                1,
                key,
                terminal,
            )],
        };
        let mut arch = [0u64; 16];
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut absent = |_: &mut [u64; 16], _: &mut Flags, _: &mut dyn MemIo, _: u64| Ok(());
        let err =
            exec_image(&image, 0, &mut arch, &mut flags, &mut mem, 0, &mut absent).unwrap_err();
        assert!(err.to_string().contains("register index"));
    }

    struct ShortMem;

    impl MemIo for ShortMem {
        fn read(&mut self, _addr: u64, _len: usize) -> Result<Vec<u8>> {
            Ok(vec![1, 2])
        }

        fn write(&mut self, _addr: u64, _data: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn short_memory_read_is_an_error() {
        let mut regs = [0u64; 16];
        regs[1] = 0x1000;
        let mut flags = Flags::default();
        let err = super::exec::exec_bc(
            &Bc::Load64(0, 1),
            &mut regs,
            &mut flags,
            &mut ShortMem,
            0,
            &SlotMap::identity(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "short read");
    }

    #[test]
    fn nest_longer_than_255_bytes_is_an_error() {
        let err = encode_plain(&Bc::Nest(vec![0x11; 256])).unwrap_err();
        assert_eq!(err.to_string(), "nested bytecode exceeds 255 bytes");
    }

    #[test]
    fn lowered_bytecode_contains_neutral_junk_on_the_entry_path() {
        let func = sample();
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let image = lower_image(std::slice::from_ref(&func), &mut rng).unwrap();
        let bc = &image.funcs[0];
        let entry = bc.entry as usize;
        let junk = plain_insn(bc, entry + 1, &image.inv).unwrap();
        assert_eq!(junk, vec![0x70]);
        let (ir, vm) = run_both(&func, 10, 1);
        assert_eq!(vm, ir);
    }

    #[test]
    fn arch_slots_differ_across_seeds_and_leave_the_identity() {
        let func = sample();
        let mut maps = Vec::new();
        for seed in 0..10u64 {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let image = lower_image(std::slice::from_ref(&func), &mut rng).unwrap();
            let arch = image.slots.forward[..16].to_vec();
            assert!(
                arch.iter()
                    .enumerate()
                    .any(|(index, slot)| *slot != index as u8),
                "seed {seed} kept the identity map"
            );
            assert!(
                arch.iter().any(|slot| *slot >= 16),
                "seed {seed} did not use a slot past the architectural file"
            );
            let mut seen = image.slots.forward.to_vec();
            seen.extend(image.slots.shadows);
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), SLOT_COUNT);
            maps.push(arch);
        }
        assert!(maps.iter().any(|map| map != &maps[0]));
    }

    #[test]
    fn nest_of_255_bytes_roundtrips() {
        let body = vec![0x11u8; 255];
        let encoded = encode_plain(&Bc::Nest(body.clone())).unwrap();
        assert_eq!(encoded[1], 255);
        assert_eq!(decode(&encoded).unwrap(), Bc::Nest(body));
    }

    #[test]
    fn salt_for_func_mixes_the_full_index() {
        let base = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_ne!(salt_for_func(base, 1), salt_for_func(base, 65537));
    }
}
