//! Level-2 dispatcher. The outer VM still fetches and decrypts each block.
//! Choosing the handler is this bytecode, sealed with its own ChaCha20 nonce.
//! There is no third level: nothing in this program starts another interpreter.

use crate::crypto;
use crate::error::{msg, Result};
use crate::vm::cipher::{self, KEY_LEN, NONCE_LEN, SALT_LEN};

/// How many interpreters run a guest instruction. Two: the outer VM, then this one.
pub const LEVELS: u8 = 2;

/// `zf = (opcode == tag)`.
pub(crate) const EQ: u8 = 0x20;
/// Return `id` when `zf` is set.
pub(crate) const JE: u8 = 0x21;
/// Reject the opcode.
pub(crate) const FAIL: u8 = 0x31;
/// `acc = map[opcode]`, then skip the 256-byte map.
pub(crate) const LOOKUP: u8 = 0x40;
/// Return `acc`, or reject when `acc` is [`REJECT`].
pub(crate) const RET: u8 = 0x41;
/// Map value that [`RET`] refuses. Unknown outer opcodes use it.
pub(crate) const REJECT: u8 = 0xFF;

const INFO: &[u8] = b"vmkek.vm.inner";

/// One proof row for the nested dispatcher. The anchors are test names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    /// Short name of the claim.
    pub name: &'static str,
    /// `Math`, `System`, or `Crypto`.
    pub channel: &'static str,
    /// `M-IR`, `M-EMU`, or empty when the channel is a known-answer test.
    pub machine: &'static str,
    /// Test that locks the claim.
    pub anchor: &'static str,
}

/// Math, system, and crypto claims for this level. Crypto reuses the S3b ChaCha20 KAT.
#[must_use]
pub fn claims() -> [Claim; 3] {
    [
        Claim {
            name: "nested-vm-bisim",
            channel: "Math",
            machine: "M-IR",
            anchor: "ir_level1_and_level2_agree_on_sample_and_l1",
        },
        Claim {
            name: "nested-vm-sample",
            channel: "System",
            machine: "M-EMU",
            anchor: "native_vm_runs_the_lifted_sample",
        },
        Claim {
            name: "nested-vm-cipher",
            channel: "Crypto",
            machine: "",
            anchor: "rfc8439_chacha20_block",
        },
    ]
}

/// Sealed level-2 program installed in one function runtime.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    /// ChaCha20 key. HKDF info is `vmkek.vm.inner`, so this is not a block key.
    pub key: [u8; KEY_LEN],
    /// Nonce disjoint from every outer `index || salt` nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext. Opening it yields [`product_program`].
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Sealed").finish_non_exhaustive()
    }
}

impl Drop for Sealed {
    fn drop(&mut self) {
        crate::secret::wipe(&mut self.key);
    }
}

#[derive(Clone)]
pub(super) struct ScopedDispatcher {
    key: crate::secret::KeyPage,
    nonce: [u8; NONCE_LEN],
    bytes: Vec<u8>,
}

impl ScopedDispatcher {
    pub(super) fn encode(key: &[u8; KEY_LEN], nonce: [u8; NONCE_LEN]) -> Result<Self> {
        let mut bytes = product_program();
        if bytes.len() > cipher::INNER_CAP as usize {
            return Err(msg("inner dispatcher does not fit"));
        }
        crypto::chacha20(key, &nonce, &mut bytes);
        Ok(Self {
            key: crate::secret::KeyPage::hold(key)?,
            nonce,
            bytes,
        })
    }

    pub(super) fn sealed(&self) -> Sealed {
        Sealed {
            key: self.key.bytes(),
            nonce: self.nonce,
            bytes: self.bytes.clone(),
        }
    }

    pub(super) fn open(&self) -> Vec<u8> {
        let key = p256::elliptic_curve::zeroize::Zeroizing::new(self.key.bytes());
        let mut bytes = self.bytes.clone();
        crypto::chacha20(&key, &self.nonce, &mut bytes);
        bytes
    }
}

/// Product dispatcher: one lookup, then return. Unknown tags are [`REJECT`].
#[must_use]
pub(crate) fn product_program() -> Vec<u8> {
    let mut map = [REJECT; 256];
    for tag in crate::vm::BYTECODE_OPCODES {
        map[usize::from(*tag)] = *tag;
    }
    let mut program = Vec::with_capacity(258);
    program.push(LOOKUP);
    program.extend(map);
    program.push(RET);
    program
}

/// Compare chain in the same ISA, used to show the lookup is not a special case.
#[cfg(test)]
fn compare_program(tags: &[u8]) -> Vec<u8> {
    let mut program = Vec::with_capacity(tags.len() * 4 + 1);
    for tag in tags {
        program.extend([EQ, *tag, JE, *tag]);
    }
    program.push(FAIL);
    program
}

/// Key for the inner stream. The info string differs from `vmkek.vm.bytecode`.
pub(crate) fn dispatcher_key(key_seed: u32, salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    crypto::hkdf_sha256(&key_seed.to_le_bytes(), salt, INFO, &mut key)?;
    Ok(key)
}

/// Nonce = salt || `N1` marker. The tail is flipped when it would equal `salt`.
#[must_use]
pub(crate) fn dispatcher_nonce(salt: &[u8; SALT_LEN]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..SALT_LEN].copy_from_slice(salt);
    nonce[8] = b'N';
    nonce[9] = b'1';
    nonce[10] = 0;
    nonce[11] = 1;
    // Outer nonces are `index || salt`. Flip the marker when that tail matches.
    if nonce[4..] == salt[..] {
        nonce[11] ^= 1;
    }
    nonce
}

/// Seal [`product_program`] under the inner key and nonce.
pub fn seal_dispatcher(key_seed: u32, salt: &[u8; SALT_LEN]) -> Result<Sealed> {
    let key = dispatcher_key(key_seed, salt)?;
    let nonce = dispatcher_nonce(salt);
    let mut bytes = product_program();
    if bytes.len() > usize::try_from(cipher::INNER_CAP).unwrap_or(0) {
        return Err(msg("inner dispatcher does not fit"));
    }
    cipher::xor_keystream(&key, &nonce, 0, &mut bytes)?;
    Ok(Sealed { key, nonce, bytes })
}

/// Plaintext of [`seal_dispatcher`]. ChaCha20 is its own inverse.
pub fn open_dispatcher(key_seed: u32, salt: &[u8; SALT_LEN]) -> Result<Vec<u8>> {
    let mut sealed = seal_dispatcher(key_seed, salt)?;
    let opened = cipher::xor_keystream(&sealed.key, &sealed.nonce, 0, &mut sealed.bytes);
    crate::secret::wipe(&mut sealed.key);
    opened?;
    Ok(std::mem::take(&mut sealed.bytes))
}

/// Run `program` on one outer opcode and return the handler tag.
pub(crate) fn select(program: &[u8], opcode: u8) -> Result<u8> {
    let mut walk = Walk {
        program,
        ip: 0,
        opcode,
        acc: 0,
        zf: false,
    };
    for _ in 0..=program.len() {
        if let Some(tag) = step(&mut walk)? {
            return Ok(tag);
        }
    }
    Err(msg("inner dispatcher stopped"))
}

/// Replace the opcode byte with the tag [`select`] returns.
pub(crate) fn apply_dispatcher(program: &[u8], plain: &mut [u8]) -> Result<()> {
    let opcode = *plain.first().ok_or_else(|| msg("empty bytecode"))?;
    plain[0] = select(program, opcode)?;
    Ok(())
}

struct Walk<'a> {
    program: &'a [u8],
    ip: usize,
    opcode: u8,
    acc: u8,
    zf: bool,
}

fn step(walk: &mut Walk<'_>) -> Result<Option<u8>> {
    let op = *walk
        .program
        .get(walk.ip)
        .ok_or_else(|| msg("inner dispatcher stopped"))?;
    match op {
        EQ => eq_op(walk),
        JE => je_op(walk),
        LOOKUP => lookup_op(walk),
        RET => ret_op(walk),
        FAIL => Err(msg("inner dispatcher rejected the opcode")),
        0x70..=0x7f => {
            walk.ip += 1;
            Ok(None)
        }
        _ => Err(msg("inner dispatcher rejected the opcode")),
    }
}

fn need(walk: &Walk<'_>, len: usize) -> Result<()> {
    let end = walk
        .ip
        .checked_add(len)
        .ok_or_else(|| msg("inner dispatcher stopped"))?;
    if end > walk.program.len() {
        return Err(msg("inner dispatcher stopped"));
    }
    Ok(())
}

fn eq_op(walk: &mut Walk<'_>) -> Result<Option<u8>> {
    need(walk, 2)?;
    walk.zf = walk.opcode == walk.program[walk.ip + 1];
    walk.ip += 2;
    Ok(None)
}

fn je_op(walk: &mut Walk<'_>) -> Result<Option<u8>> {
    need(walk, 2)?;
    let id = walk.program[walk.ip + 1];
    if walk.zf {
        return Ok(Some(id));
    }
    walk.ip += 2;
    Ok(None)
}

fn lookup_op(walk: &mut Walk<'_>) -> Result<Option<u8>> {
    need(walk, 257)?;
    let at = walk.ip + 1 + usize::from(walk.opcode);
    walk.acc = walk.program[at];
    walk.ip += 257;
    Ok(None)
}

fn ret_op(walk: &mut Walk<'_>) -> Result<Option<u8>> {
    if walk.acc == REJECT {
        return Err(msg("inner dispatcher rejected the opcode"));
    }
    walk.ip += 1;
    Ok(Some(walk.acc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::Flags;
    use crate::ir::{exec_func, Block, Exit, FuncIr, MapMem, MemIo, Op, ARCH, RAX, RCX};
    use crate::lift::lift;
    use crate::obf::obfuscate;
    use crate::vm::{exec_image, lower_image};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn second_level_does_not_add_a_third() {
        assert_eq!(LEVELS, 2);
        // Nest stays an outer tag. Nothing in this ISA starts another interpreter.
        assert!(!matches!(0x61, EQ | JE | FAIL | LOOKUP | RET));
        let program = product_program();
        assert_eq!(program.len(), 258);
        assert_eq!(program[0], LOOKUP);
        assert_eq!(*program.last().unwrap(), RET);
        assert_eq!(select(&program, 0x61).unwrap(), 0x61);
    }

    #[test]
    fn lookup_and_compare_agree_on_every_outer_tag() {
        let tags = crate::vm::BYTECODE_OPCODES;
        let lookup = product_program();
        let compare = compare_program(tags);
        for tag in tags {
            assert_eq!(select(&lookup, *tag).unwrap(), *tag);
            assert_eq!(select(&compare, *tag).unwrap(), *tag);
        }
        for unknown in [0x00u8, 0xFE] {
            assert!(select(&lookup, unknown).is_err());
            assert!(select(&compare, unknown).is_err());
        }
        let mut junk = vec![0x70];
        junk.extend(compare_program(&[0x02]));
        assert_eq!(select(&junk, 0x02).unwrap(), 0x02);
        let mut tampered = lookup;
        tampered[1 + usize::from(0x02u8)] = 0x03;
        assert_eq!(select(&tampered, 0x02).unwrap(), 0x03);
    }

    #[test]
    fn inner_stream_opens_under_the_s3b_primitive() {
        let salt = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let sealed = seal_dispatcher(0x0a0b_0c0d, &salt).unwrap();
        let mut opened = sealed.bytes.clone();
        cipher::xor_keystream(&sealed.key, &sealed.nonce, 0, &mut opened).unwrap();
        assert_eq!(opened, product_program());
        let block = cipher::chacha20_block(&sealed.key, 0, &sealed.nonce);
        let mut head = sealed.bytes[..64].to_vec();
        for (dst, src) in head.iter_mut().zip(block) {
            *dst ^= src;
        }
        assert_eq!(head, opened[..64]);
        assert_ne!(sealed.key, cipher::block_key(0x0a0b_0c0d, 0x1000, &salt));
        assert_ne!(sealed.nonce, cipher::block_nonce(0, &salt, 0));
        assert_ne!(&sealed.nonce[4..], &salt[..]);
        let collide = [b'N', b'1', 0, 1, b'N', b'1', 0, 1];
        let flipped = dispatcher_nonce(&collide);
        assert_ne!(&flipped[4..], &collide[..]);
        assert_eq!(flipped[11], 0);
        for index in [0u32, 1, 0x0100_314e, u32::MAX] {
            assert_ne!(flipped, cipher::block_nonce(index, &collide, 0));
            assert_ne!(sealed.nonce, cipher::block_nonce(index, &salt, 0));
        }
    }

    #[test]
    fn n1_claims_name_the_three_channels() {
        let rows = claims();
        assert_eq!(rows[0].channel, "Math");
        assert_eq!(rows[0].machine, "M-IR");
        assert_eq!(rows[1].channel, "System");
        assert_eq!(rows[1].machine, "M-EMU");
        assert_eq!(rows[2].channel, "Crypto");
        assert_eq!(rows[2].anchor, "rfc8439_chacha20_block");
    }

    #[test]
    fn ir_level1_and_level2_agree_on_sample_and_l1() {
        prove_sample(false);
        prove_sample(true);
        prove_synth();
        prove_l1();
    }

    fn prove_sample(obfuscate_it: bool) {
        let funcs = sample_funcs(obfuscate_it);
        let mix = crate::sample::mix(10);
        let folded = crate::sample::compute(10);
        prove_named(&funcs, "mix", 10, mix);
        prove_named(&funcs, "compute", 10, folded);
    }

    fn prove_synth() {
        let mix = mix_ir();
        prove_named(
            std::slice::from_ref(&mix),
            "mix",
            10,
            crate::sample::mix(10),
        );
        let clamp = clamp_ir();
        prove_named(std::slice::from_ref(&clamp), "clamp", 3, 3);
        prove_named(std::slice::from_ref(&clamp), "clamp", 4, 4);
    }

    fn prove_named(funcs: &[FuncIr], name: &str, arg: u64, expect: u64) {
        let index = funcs.iter().position(|func| func.name == name).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let image = lower_image(funcs, &mut rng).unwrap();
        let ir = run_arg(funcs, None, index, arg).unwrap();
        let level1 = run_arg(funcs, Some(&image), index, arg).unwrap();
        let level2 = run_nested(&image, index, arg).unwrap();
        assert_eq!(ir.regs[0], expect, "{name}");
        assert_eq!(level1, ir, "level 1 {name}");
        assert_eq!(level2, ir, "level 2 {name}");
    }

    fn prove_l1() {
        let mut matched = 0u32;
        for (index, block) in crate::gp::l1_blocks().into_iter().enumerate() {
            let Ok(func) = lift("l1", &block.code, 0, block.code.len() as u32, block.ip) else {
                continue;
            };
            let ir = eval_ir(&func, &block);
            let image = lower_image(
                std::slice::from_ref(&func),
                &mut ChaCha20Rng::seed_from_u64(3),
            );
            let (level1, level2) = match image {
                Ok(image) => (
                    eval_vm(&image, &block, false),
                    eval_vm(&image, &block, true),
                ),
                Err(err) => (Err(err.to_string()), Err(err.to_string())),
            };
            match (ir, level1, level2) {
                (Ok(ir), Ok(level1), Ok(level2)) => {
                    assert_eq!(level1, ir, "level 1 L1 block {index}");
                    assert_eq!(level2, ir, "level 2 L1 block {index}");
                    matched += 1;
                }
                (Err(_), Err(_), Err(_)) => {}
                (ir, level1, level2) => panic!(
                    "L1 block {index} split ir={ir:?} l1={level1:?} l2={level2:?} code={:02x?}",
                    block.code
                ),
            }
        }
        assert!(matched >= 12, "only {matched} L1 blocks matched M-IR");
    }

    fn sample_funcs(obfuscate_it: bool) -> Vec<FuncIr> {
        let built = crate::sample::build().unwrap();
        let image = crate::pe::parse(&built.bytes).unwrap();
        let mut funcs = Vec::new();
        for sym in &built.symbols {
            if sym.name == "start" {
                continue;
            }
            let bytes = crate::pe::read_rva(&image, sym.rva, sym.size as usize).unwrap();
            let mut func = lift(&sym.name, bytes, sym.rva, sym.size, image.image_base).unwrap();
            if obfuscate_it {
                let mut rng = ChaCha20Rng::seed_from_u64(u64::from(sym.rva));
                func = obfuscate(&func, &mut rng).func;
            }
            funcs.push(func);
        }
        funcs
    }

    fn mix_ir() -> FuncIr {
        FuncIr {
            name: "mix".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![
                    Op::MovRr(RAX, RCX),
                    Op::ImulRi(RAX, 7),
                    Op::AddRi(RAX, 3),
                    Op::XorRi(RAX, 0x5a),
                ],
                exit: Exit::Ret,
                opaque: false,
            }],
        }
    }

    fn clamp_ir() -> FuncIr {
        FuncIr {
            name: "clamp".into(),
            rva: 0x2000,
            entry: 0,
            blocks: vec![
                Block {
                    ops: vec![Op::CmpRi(RCX, 4)],
                    exit: Exit::Jcc(2, 1, 2),
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRr(RAX, RCX)],
                    exit: Exit::Ret,
                    opaque: false,
                },
                Block {
                    ops: vec![Op::MovRi(RAX, 4)],
                    exit: Exit::Ret,
                    opaque: false,
                },
            ],
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct View {
        regs: [u64; ARCH],
        flags: Flags,
        mem: Vec<(u64, u8)>,
    }

    fn view_of(regs: [u64; ARCH], flags: Flags, mem: &MapMem) -> View {
        View {
            regs,
            flags,
            mem: mem
                .bytes
                .iter()
                .map(|(addr, byte)| (*addr, *byte))
                .collect(),
        }
    }

    fn host_reject(
        _arch: &mut [u64; ARCH],
        _flags: &mut Flags,
        _mem: &mut dyn MemIo,
        _target: u64,
    ) -> Result<()> {
        Err(msg("nested bisim host"))
    }

    fn run_arg(
        funcs: &[FuncIr],
        image: Option<&crate::vm::BcImage>,
        index: usize,
        arg: u64,
    ) -> std::result::Result<View, String> {
        let mut arch = [0u64; ARCH];
        arch[usize::from(RCX)] = arg;
        arch[4] = 0x7000_0000;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut host = host_reject;
        let base = crate::pe::IMAGE_BASE;
        match image {
            None => exec_func(
                funcs, index, &mut arch, &mut flags, &mut mem, base, &mut host,
            ),
            Some(image) => exec_image(
                image, index, &mut arch, &mut flags, &mut mem, base, &mut host,
            ),
        }
        .map_err(|err| err.to_string())?;
        Ok(view_of(arch, flags, &mem))
    }

    fn run_nested(
        image: &crate::vm::BcImage,
        index: usize,
        arg: u64,
    ) -> std::result::Result<View, String> {
        let mut arch = [0u64; ARCH];
        arch[usize::from(RCX)] = arg;
        arch[4] = 0x7000_0000;
        let mut flags = Flags::default();
        let mut mem = MapMem::default();
        let mut host = host_reject;
        crate::vm::exec_image_nested(
            image,
            index,
            &mut arch,
            &mut flags,
            &mut mem,
            crate::pe::IMAGE_BASE,
            &mut host,
        )
        .map_err(|err| err.to_string())?;
        Ok(view_of(arch, flags, &mem))
    }

    fn mem_of(block: &crate::gp::L1Block) -> MapMem {
        let mut mem = MapMem::default();
        for (index, byte) in block.data.iter().enumerate() {
            mem.bytes.insert(block.base + index as u64, *byte);
        }
        mem
    }

    fn eval_ir(func: &FuncIr, block: &crate::gp::L1Block) -> std::result::Result<View, String> {
        let mut arch = block.regs;
        let mut flags = Flags::unpack(block.rflags);
        let mut mem = mem_of(block);
        let mut host = host_reject;
        exec_func(
            std::slice::from_ref(func),
            0,
            &mut arch,
            &mut flags,
            &mut mem,
            block.ip,
            &mut host,
        )
        .map_err(|err| err.to_string())?;
        Ok(view_of(arch, flags, &mem))
    }

    fn eval_vm(
        image: &crate::vm::BcImage,
        block: &crate::gp::L1Block,
        nested: bool,
    ) -> std::result::Result<View, String> {
        let mut arch = block.regs;
        let mut flags = Flags::unpack(block.rflags);
        let mut mem = mem_of(block);
        let mut host = host_reject;
        let run = if nested {
            crate::vm::exec_image_nested(
                image, 0, &mut arch, &mut flags, &mut mem, block.ip, &mut host,
            )
        } else {
            exec_image(
                image, 0, &mut arch, &mut flags, &mut mem, block.ip, &mut host,
            )
        };
        run.map_err(|err| err.to_string())?;
        Ok(view_of(arch, flags, &mem))
    }
}
