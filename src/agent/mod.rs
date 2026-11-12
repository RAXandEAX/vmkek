//! External-key custody. The ChaCha20 key stays in this process.
//!
//! The protected process sends a software measurement, the SHA-256 of its
//! image, and receives one plaintext bytecode block. A mismatch is a refusal.
//! That hash is not a TPM quote and it is not an SEV-SNP or TDX attestation.
//! It also does not make a homemade hypervisor (H1) succeed.

mod serve;
mod session;
mod wire;

use crate::crypto;
use crate::error::{msg, Result};
use crate::secret::{wipe, WipeBuffer};
use crate::vm::{self, apply_keystream, block_nonce, weave_next, BcImage, KEY_LEN, SALT_LEN};

pub use serve::Agent;
pub use wire::{
    decode, encode, Request, CALL_LIFETIME_SECS, FRAME_TIMEOUT_SECS, HDR, HELLO, MAGIC, MAX_BODY,
    OFF_CALL, OFF_INDEX, OFF_LEN, OFF_RVA, OFF_SEQ, OFF_TID, OP_BEGIN, OP_COMMIT, OP_INNER,
    OP_OPEN, OP_RESIDENT, PATH_CAP, STATUS_DENY, STATUS_OK, TICKET_LEN, VER,
};

const MEMORY_BUDGET: usize = 64 * 1024 * 1024;

/// One function's sealed blocks and the key that opens them.
///
/// The key bytes are for the agent only. `protect_external` does not write
/// them into the image.
#[derive(Clone)]
pub struct FuncPack {
    /// Build salt. The stub sends it instead of a runtime address.
    pub salt: [u8; SALT_LEN],
    /// Function RVA. Every function of one image shares `salt`.
    pub rva: u32,
    /// Block-0 ChaCha20 key.
    pub key: [u8; KEY_LEN],
    /// Key after every sealed block has been absorbed.
    pub terminal: [u8; KEY_LEN],
    /// Sealed bytecode, index order.
    pub sealed: Vec<Vec<u8>>,
    /// Sealed level-2 program and its agent-only key.
    pub inner: vm::Sealed,
}

/// Key material for one protected image, held by the agent.
#[derive(Clone, Debug)]
pub struct Package {
    /// Inverse opcode map. The same map covers every function of the build.
    pub inv: [u8; 256],
    /// Virtualized functions.
    pub funcs: Vec<FuncPack>,
}

impl std::fmt::Debug for FuncPack {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FuncPack")
            .field("rva", &self.rva)
            .finish_non_exhaustive()
    }
}

impl Drop for FuncPack {
    fn drop(&mut self) {
        wipe(&mut self.key);
        wipe(&mut self.terminal);
    }
}

/// One validated guest snapshot. The expected plaintext is wiped after the scan.
struct GuestSnap {
    plain: WipeBuffer,
    resident: bool,
}

/// Immutable agent data shared by the Unix connection handlers.
pub struct Core {
    image_hash: [u8; 32],
    package: Package,
    needles: Vec<[u8; KEY_LEN]>,
    key_offsets: Vec<usize>,
}

impl Package {
    /// Copy the keys out of `image`. The image in the file can then drop them.
    pub fn from_image(image: &BcImage) -> Result<Self> {
        let mut funcs = Vec::with_capacity(image.funcs.len());
        for func in &image.funcs {
            funcs.push(pack_func(func)?);
        }
        Ok(Self {
            inv: image.inv,
            funcs,
        })
    }
}

fn pack_func(func: &vm::BcFunc) -> Result<FuncPack> {
    let sealed = func.insns.iter().map(|insn| insn.bytes.clone()).collect();
    let inner = func.dispatcher()?;
    Ok(FuncPack {
        salt: func.salt,
        rva: func.rva,
        key: func.key.bytes(),
        terminal: func.terminal,
        sealed,
        inner,
    })
}

impl Core {
    /// Construct immutable custody for one measured ELF and validate package limits.
    pub fn new(elf: &[u8], package: Package) -> Result<Self> {
        let PackageKeys {
            needles,
            offsets: key_offsets,
        } = checked_needles(&package)?;
        Ok(Self {
            image_hash: crypto::sha256(elf),
            package,
            needles,
            key_offsets,
        })
    }

    /// Expected software measurement of the image.
    #[must_use]
    pub fn measurement(&self) -> [u8; 32] {
        self.image_hash
    }

    fn function(&self, salt: &[u8; SALT_LEN], rva: u32) -> Option<usize> {
        self.package
            .funcs
            .iter()
            .position(|func| func.rva == rva && &func.salt == salt)
    }

    fn open(&self, function: usize, index: u32, sealed: &[u8]) -> Option<WipeBuffer> {
        let func = self.package.funcs.get(function)?;
        if func.sealed.get(index as usize)? != sealed {
            return None;
        }
        let key = self
            .needles
            .get(self.key_offsets[function] + index as usize)?;
        let mut plain = WipeBuffer(sealed.to_vec());
        apply_keystream(
            key,
            &block_nonce(index, &func.salt, func.rva),
            0,
            &mut plain.0,
        );
        let first = plain.0.first_mut()?;
        *first = self.package.inv[usize::from(*first)];
        Some(plain)
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        for needle in &mut self.needles {
            wipe(needle);
        }
    }
}

fn key_before(func: &FuncPack, index: u32) -> [u8; KEY_LEN] {
    let mut key = func.key;
    for (index, block) in func.sealed.iter().take(index as usize).enumerate() {
        let next = weave_next(&key, index as u32, block);
        wipe(&mut key);
        key = next;
    }
    key
}

struct PackageKeys {
    needles: Vec<[u8; KEY_LEN]>,
    offsets: Vec<usize>,
}

fn checked_needles(package: &Package) -> Result<PackageKeys> {
    use std::collections::HashSet;

    if package.funcs.is_empty()
        || package.funcs.len() as u64 > MEMORY_BUDGET as u64 / vm::RUNTIME_WINDOW
    {
        return Err(msg("agent package exceeds the VM memory budget"));
    }
    let mut identities = HashSet::new();
    for func in &package.funcs {
        if !identities.insert((func.salt, func.rva)) || !valid_function(func) {
            return Err(msg("invalid agent function package"));
        }
    }

    let count = package.funcs.iter().map(|func| func.sealed.len() + 2).sum();
    let mut keys = PackageKeys {
        needles: Vec::with_capacity(count),
        offsets: Vec::with_capacity(package.funcs.len()),
    };
    for func in &package.funcs {
        keys.offsets.push(keys.needles.len());
        let mut key = func.key;
        for (index, block) in func.sealed.iter().enumerate() {
            keys.needles.push(key);
            let next = weave_next(&key, index as u32, block);
            wipe(&mut key);
            key = next;
        }
        keys.needles.extend([key, func.inner.key]);
        wipe(&mut key);
    }
    Ok(keys)
}

fn valid_function(func: &FuncPack) -> bool {
    if func.sealed.is_empty()
        || func.inner.bytes.is_empty()
        || func.inner.bytes.len() > vm::INNER_CAP as usize
        || func
            .sealed
            .iter()
            .any(|block| block.is_empty() || block.len() > wire::MAX_BODY)
    {
        return false;
    }
    let Some(len) = func
        .sealed
        .iter()
        .try_fold(0usize, |len, block| len.checked_add(block.len()))
    else {
        return false;
    };
    if vm::runtime_fits(0, func.sealed.len(), len).is_err() {
        return false;
    }
    let mut terminal = key_before(func, func.sealed.len() as u32);
    let valid = terminal == func.terminal;
    wipe(&mut terminal);
    valid
}

/// `true` when `needle` occurs in `hay`.
#[must_use]
pub fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|window| window == needle)
}

/// Refuse to embed a socket path the stub cannot pass to `connect`.
pub fn check_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() + 1 > PATH_CAP || path.contains('\0') {
        return Err(msg("agent socket path does not fit"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Block, Exit, FuncIr, Op};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn image() -> BcImage {
        let func = FuncIr {
            name: "mix".into(),
            rva: 0x1000,
            entry: 0,
            blocks: vec![Block {
                ops: vec![Op::MovRi(0, 7), Op::AddRi(0, 1)],
                exit: Exit::Ret,
                opaque: false,
            }],
        };
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        vm::lower_image(&[func], &mut rng).unwrap()
    }

    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Instant;

    use super::session::{Session, CALL_TIMEOUT, MAX_CONTEXTS};

    #[test]
    fn a_wrong_measurement_releases_nothing() {
        let image = image();
        let core = core(&image);
        let mut session = session();
        let now = Instant::now();
        let mut begin = request(&core, &image, 0, OP_BEGIN, 1, 1, 0);
        begin.measurement[0] ^= 1;
        assert!(session.answer(&core, &begin, now).is_none());
        assert!(session.deadline().is_none());
    }

    #[test]
    fn the_open_matches_plain_insn_and_a_modified_block_is_refused_before_release() {
        let image = image();
        let core = core(&image);
        let mut session = session();
        let now = Instant::now();
        let begin = request(&core, &image, 0, OP_BEGIN, 1, 1, 0);
        assert!(session.answer(&core, &begin, now).is_some());
        let mut open = request(&core, &image, 0, OP_OPEN, 2, 1, 0);
        let accepted = session.answer(&core, &open, now).unwrap();
        assert_eq!(
            &accepted.bytes.0[5..],
            vm::plain_insn(&image.funcs[0], 0, &image.inv).unwrap()
        );
        open.seq = 3;
        open.body[0] ^= 0xff;
        assert!(session.answer(&core, &open, now).is_none());
        assert!(session.deadline().is_none());
        let resident = request(&core, &image, 0, OP_RESIDENT, 4, 1, 0);
        assert!(session.answer(&core, &resident, now).is_none());
    }

    #[test]
    fn a_block_from_another_build_is_refused_without_plaintext() {
        let image = image();
        let mut rng = ChaCha20Rng::seed_from_u64(91);
        let other = vm::lower_image(&[ir(0x1000, 7)], &mut rng).unwrap();
        let core = core(&image);
        let mut session = session();
        let now = Instant::now();
        let begin = request(&core, &image, 0, OP_BEGIN, 1, 1, 0);
        assert!(session.answer(&core, &begin, now).is_some());
        let mut open = request(&core, &image, 0, OP_OPEN, 2, 1, 0);
        let replacement = &other.funcs[0].insns[0].bytes;
        assert_ne!(&open.body, replacement);
        open.body.clone_from(replacement);
        assert!(session.answer(&core, &open, now).is_none());
        assert!(session.deadline().is_none());
    }

    #[test]
    fn shared_salt_selects_the_function_by_rva() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let image = vm::lower_image(&[ir(0x1000, 7), ir(0x2000, 3)], &mut rng).unwrap();
        assert_eq!(image.funcs[0].salt, image.funcs[1].salt);
        let core = core(&image);
        let mut session = session();
        let now = Instant::now();
        let begin = request(&core, &image, 1, OP_BEGIN, 1, 1, 0);
        assert!(session.answer(&core, &begin, now).is_some());
        let open = request(&core, &image, 1, OP_OPEN, 2, 1, 0);
        let reply = session.answer(&core, &open, now).unwrap();
        assert_eq!(
            &reply.bytes.0[5..],
            vm::plain_insn(&image.funcs[1], 0, &image.inv).unwrap()
        );
    }

    #[test]
    fn recursive_calls_share_sequence_but_own_their_active_frame() {
        let image = image();
        let core = core(&image);
        let mut session = session();
        let now = Instant::now();
        for (seq, op, call) in [
            (1, OP_BEGIN, 1),
            (2, OP_OPEN, 1),
            (3, OP_BEGIN, 2),
            (4, OP_OPEN, 2),
            (5, OP_COMMIT, 2),
            (6, OP_OPEN, 1),
            (7, OP_RESIDENT, 1),
            (8, OP_COMMIT, 1),
        ] {
            let request = request(&core, &image, 0, op, seq, call, 0);
            assert!(
                session.answer(&core, &request, now).is_some(),
                "sequence {seq}"
            );
        }
        assert!(session.deadline().is_none());
    }

    #[test]
    fn a_nested_call_cannot_extend_the_outer_deadline() {
        let image = image();
        let core = core(&image);
        let mut session = session();
        let start = Instant::now();
        let outer = request(&core, &image, 0, OP_BEGIN, 1, 1, 0);
        assert!(session.answer(&core, &outer, start).is_some());
        let deadline = start + CALL_TIMEOUT;

        let nested = request(&core, &image, 0, OP_BEGIN, 2, 2, 0);
        assert!(session
            .answer(&core, &nested, start + CALL_TIMEOUT / 2)
            .is_some());
        assert_eq!(session.deadline(), Some(deadline));

        let mut open = request(&core, &image, 0, OP_OPEN, 3, 2, 0);
        assert!(session
            .answer(&core, &open, deadline - std::time::Duration::from_millis(1))
            .is_some());
        open.seq = 4;
        assert!(session.answer(&core, &open, deadline).is_none());
        assert!(session.deadline().is_none());
    }

    #[test]
    fn rejection_and_drop_release_the_shared_context_quota() {
        let image = image();
        let core = core(&image);
        let quota = Arc::new(AtomicUsize::new(0));
        let mut first = Session::new(Arc::clone(&quota));
        let mut second = Session::new(Arc::clone(&quota));
        let now = Instant::now();
        for seq in 1..=MAX_CONTEXTS as u64 {
            let begin = request(&core, &image, 0, OP_BEGIN, seq, seq, 0);
            assert!(first.answer(&core, &begin, now).is_some());
        }
        let begin = request(&core, &image, 0, OP_BEGIN, 1, 1, 0);
        assert!(second.answer(&core, &begin, now).is_none());
        assert_eq!(quota.load(Ordering::Relaxed), MAX_CONTEXTS);
        drop(first);
        assert_eq!(quota.load(Ordering::Relaxed), 0);
        let mut fresh = Session::new(Arc::clone(&quota));
        assert!(fresh.answer(&core, &begin, now).is_some());
        let open = request(&core, &image, 0, OP_OPEN, 2, 1, 0);
        assert!(fresh.answer(&core, &open, now + CALL_TIMEOUT).is_none());
        assert_eq!(quota.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_invalid_terminal_prevents_the_package_from_opening() {
        let mut package = Package::from_image(&image()).unwrap();
        package.funcs[0].terminal[0] ^= 1;
        assert!(Core::new(b"image", package).is_err());
    }

    fn core(image: &BcImage) -> Core {
        Core::new(b"image", Package::from_image(image).unwrap()).unwrap()
    }

    fn session() -> Session {
        Session::new(Arc::new(AtomicUsize::new(0)))
    }

    fn ir(rva: u32, imm: u64) -> FuncIr {
        FuncIr {
            name: format!("f{rva:x}"),
            rva,
            entry: 0,
            blocks: vec![Block {
                ops: vec![Op::MovRi(0, imm), Op::AddRi(0, 1)],
                exit: Exit::Ret,
                opaque: false,
            }],
        }
    }

    fn request(
        core: &Core,
        image: &BcImage,
        function: usize,
        op: u8,
        seq: u64,
        call_id: u64,
        index: u32,
    ) -> Request {
        let func = &image.funcs[function];
        let body = match op {
            OP_OPEN => func.insns[index as usize].bytes.clone(),
            OP_INNER => func.dispatcher().unwrap().bytes.clone(),
            _ => Vec::new(),
        };
        Request {
            op,
            measurement: core.measurement(),
            salt: func.salt,
            index,
            rva: func.rva,
            tid: 1,
            call_id,
            seq,
            body,
        }
    }
}
