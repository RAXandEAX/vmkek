//! Crypto channel: IETF ChaCha20 (RFC 8439) seals each bytecode block.
//!
//! Block 0 uses an HKDF-SHA256 key from the function seed. The nonce is the
//! block index followed by the build salt. Each later block's key is the keyed
//! state after the sealed bytes of the blocks below it, in index order, have
//! been absorbed. A patched byte therefore changes every later keystream, not
//! only the `Bc::Check` compare. On return the closing key must match the value
//! stored beside the block metadata; otherwise the result is discarded.
//!
//! The running key and the fold cursor belong to the thread. They live in the
//! block addressed by `gs:[GS_CHAIN_PTR]`. Each thread has its own `gs` base, so
//! that cell is not a process-wide word. The same block holds the replay key,
//! the inner-dispatcher save, the call depth, and the private decrypt cache.
//! A second thread cannot read or reset the first. The runtime window keeps the
//! block-0 key and the terminal only.
//!
//! The process holds at most one plaintext block, in any thread's cache or in a
//! level-2 buffer. Before the next block is opened, that plaintext is sealed
//! again with ChaCha20 under [`reseal_nonce`]. The blob ciphertext is left in
//! place, so the woven key still absorbs it.
//!
//! The claim is `ReducedToAssumption`: the chain holds while the running key
//! has not been lifted out of the process. Payload AEAD and the external
//! ECDSA signature are a separate channel and are not involved here.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::crypto;
use crate::error::{msg, Result};

/// Claim channel for the bytecode cipher.
pub const CHANNEL: &str = "Crypto";

/// Build salt mixed into each block nonce, in bytes.
pub const SALT_LEN: usize = 8;
/// ChaCha20 key length, in bytes.
pub const KEY_LEN: usize = 32;
/// ChaCha20 nonce length, in bytes: block index, then the build salt.
pub const NONCE_LEN: usize = 12;
/// Bytes reserved for one function's runtime block.
///
/// The window holds a 32-byte decrypt key per bytecode block, so it is larger
/// than the cipher state alone.
pub const RUNTIME_WINDOW: u64 = 0x18000;
/// Native cache allocation rejects functions above this instruction count.
pub(crate) const NATIVE_MAX_RUNTIME_INSNS: usize = 0x10000;
/// Build salt, immediately after the slot map.
pub const RT_SALT: i32 = 0x58;
/// Initial ChaCha20 key. The loader can poison this copy. Execution copies
/// [`RT_MASTER`] into the thread chain and does not write this field again.
pub const RT_KEY: i32 = 0x60;
/// Function RVA mixed into the ChaCha nonce. Functions of one image share a
/// salt, so this word is what keeps their nonces apart.
pub const RT_INDEX: i32 = 0x80;
/// Reserved. The fold cursor lives in the thread chain, not in this window.
pub const RT_FOLD: i32 = 0x84;
/// Linux detector mask for this function. Zero skips the probes.
pub const RT_LINUX: i32 = 0x88;
/// Nanosecond ceiling for one `clock_gettime` delta. A zero limit trips on any increase.
pub const RT_CLOCK_NS: i32 = 0x8C;
/// Key after every block has been absorbed. Checked before a result is published.
pub const RT_TERM: i32 = 0x90;
/// Immutable copy of the block-0 key, used to reopen a block the cursor already passed.
pub const RT_MASTER: i32 = 0xB0;
/// Absolute address of this function's decrypt-key table. The table is outside
/// the encrypted payload so the loader does not walk one key per block.
pub const RT_KEYS: i32 = 0xD0;
/// Reserved padding. Nested entries save the chain in the thread block so
/// [`INNER_AT`] can stay put. Runs leave these bytes zero.
pub const WEAVE_SAVE: i32 = 0xD8;
/// Bytes in one saved weave record: the 32-byte key, then the fold index.
pub const WEAVE_FRAME: i32 = 40;
/// `gs` offset of this thread's id. A child that inherited `gs` fails the compare.
pub const GS_TID: i32 = 0x180;
/// `gs` offset of this thread's VM frame. Zero means the page is not claimed.
pub const GS_FRAME_PTR: i32 = 0x188;
/// `gs` offset of the pointer to this thread's chain block.
pub const GS_CHAIN_PTR: i32 = 0x190;
/// Bytes in one `mmap` of a thread GS page, including its private frame.
pub const GS_MAP_BYTES: u64 = 0x5000;
/// Frame offset inside that mapping.
pub const GS_FRAME_AT: u64 = 0x2000;
/// Chain block planted for direct emulator entry, relative to the `gs` base.
pub const GS_CHAIN_AT: i32 = 0x400;
/// Fold cursor inside a chain block or a saved frame.
pub const CHAIN_FOLD: i32 = 32;
/// First saved frame inside a chain block.
pub const CHAIN_SAVE: i32 = 40;
/// Active trampoline entries. Zero means this thread is between calls.
pub const CTX_LEVEL: i32 = CHAIN_SAVE + 32 * WEAVE_FRAME;
/// Call depth for `CallRva`. It is not the shared VM frame.
pub const CTX_DEPTH: i32 = CTX_LEVEL + 8;
/// Key parked while a block the cursor already passed is replayed.
pub const CTX_SAVED: i32 = CTX_DEPTH + 8;
/// Key and nonce parked while the inner dispatcher is opened.
pub const CTX_NEST: i32 = CTX_SAVED + 32;
/// Live ChaCha block index for this thread. The runtime copy stays immutable.
pub const CTX_INDEX: i32 = CTX_NEST + 44;
/// Live ChaCha salt for this thread.
pub const CTX_SALT: i32 = CTX_INDEX + 4;
/// Private instruction cache. Zero selects the runtime cache.
pub const CTX_CACHE: i32 = CTX_SALT + 8;
/// Private decrypt-key table. Zero selects [`RT_KEYS`].
pub const CTX_KEYS: i32 = CTX_CACHE + 8;
/// Runtime address the active cache belongs to.
pub const CTX_BOUND: i32 = CTX_KEYS + 8;
/// Map of `(runtime, cache, keys)` for this thread. Eight functions.
pub const CTX_MAP: i32 = CTX_BOUND + 8;
/// Slots in [`CTX_MAP`].
pub const CTX_MAP_SLOTS: usize = 8;
/// Bytes in one [`CTX_MAP`] record.
pub const CTX_MAP_STRIDE: i32 = 24;
/// Saved outer keys for trampoline re-entry, past the function map.
pub const TRAMP_SAVE: i32 = CTX_MAP + (CTX_MAP_SLOTS as i32) * CTX_MAP_STRIDE;
/// Records in [`TRAMP_SAVE`].
pub const TRAMP_SLOTS: usize = 8;
/// Bytes in one trampoline save: key, fold, pad, depth.
pub const TRAMP_STRIDE: i32 = 48;
/// Depth field inside a trampoline save.
pub const TRAMP_DEPTH: i32 = 40;
/// Cache flag: the slot holds one block of canonical plaintext.
pub const CACHE_OPEN: u8 = 1;
/// Cache flag: the slot holds ChaCha20(`plaintext`, block key, [`reseal_nonce`]).
pub const CACHE_SEALED: u8 = 2;
/// High bit mixed into the block index so a reseal nonce is not an open nonce.
pub const RESEAL_MARK: u32 = 0x8000_0000;
/// Private cache that currently holds plaintext. Zero means every block is sealed.
pub const CTX_OPEN_CACHE: i32 = TRAMP_SAVE + (TRAMP_SLOTS as i32) * TRAMP_STRIDE;
/// Key table that owns [`CTX_OPEN_CACHE`].
pub const CTX_OPEN_KEYS: i32 = CTX_OPEN_CACHE + 8;
/// Runtime whose block is open.
pub const CTX_OPEN_RUNTIME: i32 = CTX_OPEN_KEYS + 8;
/// Index of the open block inside [`CTX_OPEN_RUNTIME`].
pub const CTX_OPEN_INDEX: i32 = CTX_OPEN_RUNTIME + 8;
/// Bytes in one chain block, including the per-thread keyed cells.
pub const CHAIN_BYTES: usize = CTX_OPEN_INDEX as usize + 8;
/// Slots in the image pool. A thread claims one when `gs:[GS_CHAIN_PTR]` is null.
pub const CHAIN_SLOTS: usize = 4;
/// Level-2 dispatcher. The offset tables used to start here; they follow this region.
pub const INNER_AT: i32 = WEAVE_SAVE + 32 * WEAVE_FRAME;
/// ChaCha20 key of the inner dispatcher. It is not an outer block key.
pub const INNER_KEY: i32 = INNER_AT;
/// Inner nonce, 12 bytes. The stub copies it into this thread's nonce, not the runtime.
pub const INNER_NONCE: i32 = INNER_AT + 32;
/// Little-endian length of the sealed inner program.
pub const INNER_LEN: i32 = INNER_AT + 44;
/// Nonzero after this runtime has opened the inner program.
pub const INNER_READY: i32 = INNER_AT + 48;
/// Former one-time inner lock. The process gate now serializes opens.
pub const INNER_LOCK: i32 = INNER_AT + 52;
/// Immediate schedule for this function. Zero leaves hand-built plaintext alone.
/// The word occupies the gap between the inner lock and the inner ciphertext.
pub const RT_SCHED: i32 = INNER_LOCK + 4;
/// Ciphertext of the inner dispatcher.
pub const INNER_CIPHER: i32 = INNER_AT + 64;
/// Plaintext capacity of one inner program, in bytes.
pub const INNER_CAP: i32 = 512;
/// Plaintext of the inner dispatcher, after the ciphertext.
pub const INNER_PLAIN: i32 = INNER_CIPHER + INNER_CAP;
/// Bytes from [`INNER_AT`] through the end of the plaintext buffer.
pub const INNER_REGION: i32 = INNER_PLAIN + INNER_CAP - INNER_AT;
/// First byte of the per-function offset table.
pub const TABLES_AT: i32 = INNER_AT + INNER_REGION;

const INFO: &[u8] = b"vmkek.vm.bytecode";
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

const _: () = assert!(RT_SALT == 0x58);
const _: () = assert!(RT_KEY == RT_SALT + SALT_LEN as i32);
const _: () = assert!(RT_KEY + KEY_LEN as i32 == RT_INDEX);
const _: () = assert!(RT_INDEX == 0x80);
const _: () = assert!(RT_FOLD == RT_INDEX + 4);
const _: () = assert!(RT_LINUX == RT_FOLD + 4);
const _: () = assert!(RT_CLOCK_NS == RT_LINUX + 4);
const _: () = assert!(RT_TERM == RT_CLOCK_NS + 4);
const _: () = assert!(RT_TERM == 0x90);
const _: () = assert!(RT_MASTER == RT_TERM + KEY_LEN as i32);
const _: () = assert!(RT_KEYS == RT_MASTER + KEY_LEN as i32);
const _: () = assert!(WEAVE_SAVE == RT_KEYS + 8);
const _: () = assert!(INNER_AT == WEAVE_SAVE + 32 * WEAVE_FRAME);
const _: () = assert!(GS_TID == 0x180);
const _: () = assert!(GS_FRAME_PTR == GS_TID + 8);
const _: () = assert!(GS_CHAIN_PTR == GS_FRAME_PTR + 8);
const _: () = assert!(GS_CHAIN_PTR >= 0x68);
const _: () = assert!(GS_CHAIN_PTR + 8 <= 0x200);
const _: () = assert!(GS_FRAME_AT + 0x2650 <= GS_MAP_BYTES);
const _: () = assert!(CHAIN_FOLD == KEY_LEN as i32);
const _: () = assert!(CHAIN_SAVE == WEAVE_FRAME);
const _: () = assert!(CTX_LEVEL == 1320);
const _: () = assert!(CTX_DEPTH == CTX_LEVEL + 8);
const _: () = assert!(CTX_NEST == CTX_SAVED + 32);
const _: () = assert!(CTX_INDEX == CTX_NEST + 44);
const _: () = assert!(CTX_SALT == CTX_INDEX + 4);
const _: () = assert!(TRAMP_SAVE == 1640);
const _: () = assert!(CTX_OPEN_CACHE == 2024);
const _: () = assert!(CTX_OPEN_INDEX == CTX_OPEN_CACHE + 24);
const _: () = assert!(CHAIN_BYTES == 2056);
const _: () = assert!(CHAIN_BYTES.is_multiple_of(8));
const _: () = assert!((GS_CHAIN_AT as usize) + 2 * CHAIN_BYTES <= 0x2000);
const _: () = assert!(INNER_NONCE == INNER_KEY + KEY_LEN as i32);
const _: () = assert!(INNER_LEN == INNER_NONCE + NONCE_LEN as i32);
const _: () = assert!(INNER_READY == INNER_LEN + 4);
const _: () = assert!(INNER_LOCK == INNER_READY + 4);
const _: () = assert!(INNER_LOCK + 4 <= INNER_CIPHER);
const _: () = assert!(RT_SCHED + 8 == INNER_CIPHER);
const _: () = assert!(INNER_CIPHER == INNER_AT + 64);
const _: () = assert!(INNER_PLAIN == INNER_CIPHER + INNER_CAP);
const _: () = assert!(INNER_REGION == 0x440);
const _: () = assert!(TABLES_AT == INNER_AT + INNER_REGION);

/// Pointers inside one function runtime. The cache holds a flag byte per
/// instruction and then plaintext laid out like the ciphertext blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeTables {
    pub offs: u64,
    pub lens: u64,
    pub inv: u64,
    pub blob: u64,
    pub cache: u64,
    pub end: u64,
}

/// Checked offsets of one function's tables inside its fixed runtime window.
pub fn runtime_fits(at: u64, count: usize, blob_len: usize) -> Result<RuntimeTables> {
    let tables = runtime_tables(at, count, blob_len)?;
    let extent = tables.end - at;
    if extent > RUNTIME_WINDOW {
        return Err(msg(format!(
            "unsupported runtime layout: requires {extent} bytes per function; limit is {RUNTIME_WINDOW} bytes"
        )));
    }
    Ok(tables)
}

/// Checked runtime offsets before applying a profile's capacity limit.
pub(crate) fn runtime_tables(at: u64, count: usize, blob_len: usize) -> Result<RuntimeTables> {
    let overflow = || msg("unsupported runtime layout: extent overflows");
    let count = u64::try_from(count).map_err(|_| overflow())?;
    let blob_len = u64::try_from(blob_len).map_err(|_| overflow())?;
    let lengths = count
        .checked_mul(4)
        .and_then(|value| value.checked_add(16))
        .ok_or_else(overflow)?;
    let offs = TABLES_AT as u64;
    let lens = offs.checked_add(lengths).ok_or_else(overflow)?;
    let inv = lens.checked_add(lengths).ok_or_else(overflow)?;
    let blob = inv.checked_add(256).ok_or_else(overflow)?;
    let cache = blob.checked_add(blob_len).ok_or_else(overflow)?;
    let end = cache
        .checked_add(count)
        .and_then(|value| value.checked_add(blob_len))
        .ok_or_else(overflow)?;
    let end = at.checked_add(end).ok_or_else(overflow)?;
    Ok(RuntimeTables {
        offs: at + offs,
        lens: at + lens,
        inv: at + inv,
        blob: at + blob,
        cache: at + cache,
        end,
    })
}

#[cfg(test)]
#[test]
fn runtime_extent_enforces_the_exact_window_and_address_bounds() {
    let count = 2;
    let fixed = runtime_fits(0, count, 0).unwrap().end;
    let blob = ((RUNTIME_WINDOW - fixed) / 2) as usize;
    let at = 0x500000;
    let fitting = runtime_fits(at, count, blob).unwrap();
    assert_eq!(fitting.end, at + RUNTIME_WINDOW);
    assert_eq!(fitting.cache - fitting.blob, blob as u64);
    let oversized = runtime_fits(at, count, blob + 1).unwrap_err();
    assert_eq!(
        oversized.to_string(),
        "unsupported runtime layout: requires 98306 bytes per function; limit is 98304 bytes"
    );
    assert!(runtime_fits(u64::MAX, count, 0).is_err());
    assert!(runtime_fits(at, usize::MAX, 0).is_err());
    assert!(runtime_fits(at, count, usize::MAX).is_err());
}

/// 32-byte ChaCha20 key. `rva` separates functions that share a seed.
#[must_use]
pub fn block_key(key_seed: u32, rva: u32, salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    let mut info = Vec::with_capacity(INFO.len() + 4);
    info.extend_from_slice(INFO);
    info.extend_from_slice(&rva.to_le_bytes());
    let mut key = [0u8; KEY_LEN];
    crypto::hkdf_sha256(&key_seed.to_le_bytes(), salt, &info, &mut key)
        .expect("bytecode key is 32 bytes");
    key
}

/// Nonce = block index || (build salt with the function RVA mixed in).
#[must_use]
pub fn block_nonce(index: u32, salt: &[u8; SALT_LEN], rva: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..4].copy_from_slice(&index.to_le_bytes());
    nonce[4..].copy_from_slice(salt);
    let mix = rva.to_le_bytes();
    for (slot, byte) in mix.iter().enumerate() {
        nonce[4 + slot] ^= *byte;
    }
    nonce
}

/// Nonce that seals a block after it has been executed. Not [`block_nonce`].
#[must_use]
pub fn reseal_nonce(index: u32, salt: &[u8; SALT_LEN], rva: u32) -> [u8; NONCE_LEN] {
    debug_assert!(index < RESEAL_MARK);
    block_nonce(index | RESEAL_MARK, salt, rva)
}

/// Seal `plain` with the block key and [`reseal_nonce`]. The same call opens it.
pub fn reseal_block(
    key: &[u8; KEY_LEN],
    index: u32,
    rva: u32,
    salt: &[u8; SALT_LEN],
    plain: &[u8],
) -> Result<Vec<u8>> {
    let nonce = reseal_nonce(index, salt, rva);
    let mut out = plain.to_vec();
    xor_keystream(key, &nonce, 0, &mut out)?;
    Ok(out)
}

struct NonceUse {
    key_hash: [u8; 32],
    counter: u32,
    left: [u8; 32],
    right: [u8; 32],
}

/// Record `(key, nonce, counter)` and the message for this process.
///
/// The same key may XOR that message again, or its keystream image (seal then
/// open). A different key, counter, or plaintext is rejected.
pub fn note_nonce(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    counter: u32,
    data: &[u8],
) -> Result<()> {
    static LEDGER: Mutex<BTreeMap<[u8; NONCE_LEN], NonceUse>> = Mutex::new(BTreeMap::new());
    let left = crypto::sha256(data);
    let mut ledger = LEDGER.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(prev) = ledger.get(nonce) {
        return same_message(prev, key, counter, left);
    }
    let right = xored_digest(key, nonce, counter, data);
    ledger.insert(
        *nonce,
        NonceUse {
            key_hash: crypto::sha256(key),
            counter,
            left,
            right,
        },
    );
    Ok(())
}

fn same_message(prev: &NonceUse, key: &[u8; KEY_LEN], counter: u32, left: [u8; 32]) -> Result<()> {
    if prev.key_hash != crypto::sha256(key) || prev.counter != counter {
        return Err(msg("chacha20 nonce repeated"));
    }
    if left != prev.left && left != prev.right {
        return Err(msg("chacha20 nonce repeated"));
    }
    Ok(())
}

fn xored_digest(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    counter: u32,
    data: &[u8],
) -> [u8; 32] {
    let mut mixed = data.to_vec();
    apply_keystream(key, nonce, counter, &mut mixed);
    let digest = crypto::sha256(&mixed);
    crate::secret::wipe(&mut mixed);
    digest
}

/// Channels that lock the one-block window.
#[must_use]
pub fn window_proofs() -> [WindowProof; 2] {
    [
        WindowProof {
            channel: "System",
            machine: "M-EMU",
            anchor: "one_open_block_at_each_boundary",
        },
        WindowProof {
            channel: "Crypto",
            machine: "",
            anchor: "reseal_is_chacha20_with_a_new_block_nonce",
        },
    ]
}

/// One proof row for the sliding window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowProof {
    /// `System` or `Crypto`.
    pub channel: &'static str,
    /// `M-EMU`, or empty when the row is a known-answer test.
    pub machine: &'static str,
    /// Test that locks the row.
    pub anchor: &'static str,
}

/// Next running key after sealed block `block`.
///
/// Block `i` is decrypted under the state of sealed blocks `0..i`. The mix is
/// a keyed byte permutation: ChaCha20 still seals the block, and this step only
/// carries that block's bytes into the next key. One changed byte moves the
/// whole next key. Rust and the stub share this step.
#[must_use]
pub fn weave_next(key: &[u8; KEY_LEN], index: u32, block: &[u8]) -> [u8; KEY_LEN] {
    let mut next = *key;
    let len = u32::try_from(block.len()).expect("bytecode block fits in u32");
    next[0] ^= index as u8;
    next[1] ^= (index >> 8) as u8;
    next[2] ^= (index >> 16) as u8;
    next[3] ^= (index >> 24) as u8;
    next[4] ^= len as u8;
    next[5] ^= (len >> 8) as u8;
    next[6] ^= (len >> 16) as u8;
    next[7] ^= (len >> 24) as u8;
    for (offset, byte) in block.iter().enumerate() {
        let slot = offset % KEY_LEN;
        let mixed = next[slot].wrapping_add(*byte);
        next[slot] = mixed.rotate_left(1) ^ next[(slot + 7) % KEY_LEN];
        let twist = byte.wrapping_add((offset as u8).wrapping_mul(0x1d));
        next[(slot + 3) % KEY_LEN] ^= twist;
    }
    let prev = next;
    for slot in 0..KEY_LEN {
        next[slot] = prev[slot]
            .wrapping_add(prev[(slot + 1) % KEY_LEN])
            .rotate_left(1)
            ^ prev[(slot + 13) % KEY_LEN];
    }
    next
}

/// XOR `data` with the ChaCha20 keystream. The same call seals and opens.
pub fn apply_block(
    key_seed: u32,
    rva: u32,
    salt: &[u8; SALT_LEN],
    index: u32,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut out = data.to_vec();
    let mut key = block_key(key_seed, rva, salt);
    xor_keystream(&key, &block_nonce(index, salt, rva), 0, &mut out)?;
    crate::secret::wipe(&mut key);
    Ok(out)
}

/// One IETF ChaCha20 block (RFC 8439): 20 rounds, then the little-endian state.
#[must_use]
pub fn chacha20_block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&SIGMA);
    for word in 0..8 {
        let at = word * 4;
        state[4 + word] = u32::from_le_bytes(key[at..at + 4].try_into().expect("key word"));
    }
    state[12] = counter;
    for word in 0..3 {
        let at = word * 4;
        state[13 + word] = u32::from_le_bytes(nonce[at..at + 4].try_into().expect("nonce word"));
    }
    let initial = state;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    for index in 0..16 {
        state[index] = state[index].wrapping_add(initial[index]);
    }
    let mut out = [0u8; 64];
    for (index, word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// XOR `data` with the ChaCha20 keystream, starting at `counter`.
///
/// Every call records `(key, nonce, counter)` and the message. The same bytes,
/// or those bytes already XORed with this keystream, may be used again. A
/// different key or a different plaintext is rejected.
pub fn xor_keystream(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    counter: u32,
    data: &mut [u8],
) -> Result<()> {
    note_nonce(key, nonce, counter, data)?;
    apply_keystream(key, nonce, counter, data);
    Ok(())
}

/// XOR without the nonce journal. The native helper has no ledger of its own.
pub(crate) fn apply_keystream(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    mut counter: u32,
    data: &mut [u8],
) {
    let mut offset = 0usize;
    while offset < data.len() {
        let block = chacha20_block(key, counter, nonce);
        let take = (data.len() - offset).min(block.len());
        for (dst, src) in data[offset..offset + take].iter_mut().zip(block) {
            *dst ^= src;
        }
        offset += take;
        counter = counter.wrapping_add(1);
    }
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarter_round_matches_rfc8439() {
        let mut state = [0u32; 16];
        state[0] = 0x1111_1111;
        state[1] = 0x0102_0304;
        state[2] = 0x9b8d_6f43;
        state[3] = 0x0123_4567;
        quarter_round(&mut state, 0, 1, 2, 3);
        assert_eq!(state[0], 0xea2a_92f4);
        assert_eq!(state[1], 0xcb1c_f8ce);
        assert_eq!(state[2], 0x4581_472e);
        assert_eq!(state[3], 0x5881_c4bb);
    }

    #[test]
    fn rfc8439_chacha20_block() {
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let nonce = [
            0x00u8, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let block = chacha20_block(&key, 1, &nonce);
        assert_eq!(
            block,
            [
                0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
                0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
                0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
                0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
                0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
            ]
        );
    }

    #[test]
    fn keystream_matches_the_crate_across_a_block_boundary() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let mut data: Vec<u8> = (0..100u8).collect();
        let mut via_crate = data.clone();
        crypto::chacha20(&key, &nonce, &mut via_crate);
        xor_keystream(&key, &nonce, 0, &mut data).unwrap();
        assert_eq!(data, via_crate);
    }

    #[test]
    fn block_index_and_seed_change_the_ciphertext() {
        let plain = [0x03u8, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        let salt = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let other_salt = [0x12u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89];
        let first = apply_block(0x1000_0001, 0x1000, &salt, 0, &plain).unwrap();
        let other_index = apply_block(0x1000_0001, 0x1000, &salt, 1, &plain).unwrap();
        let other_seed = apply_block(0x1000_0003, 0x1000, &other_salt, 0, &plain).unwrap();
        assert_ne!(first, other_index);
        assert_ne!(first, other_seed);
        assert_eq!(
            apply_block(0x1000_0001, 0x1000, &salt, 0, &first).unwrap(),
            plain
        );
    }

    #[test]
    fn channel_name_is_crypto() {
        assert_eq!(CHANNEL, "Crypto");
    }

    #[test]
    fn weave_next_moves_when_any_plaintext_byte_changes() {
        let key = [0x11u8; KEY_LEN];
        let plain = vec![0x03u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let next = weave_next(&key, 3, &plain);
        assert_ne!(next, key);
        for offset in 0..plain.len() {
            let mut tweaked = plain.clone();
            tweaked[offset] ^= 0xff;
            assert_ne!(
                weave_next(&key, 3, &tweaked),
                next,
                "offset {offset} left the next key unchanged"
            );
        }
    }

    #[test]
    fn second_block_opens_with_the_woven_key_not_the_master_key() {
        let salt = [0x61u8; SALT_LEN];
        let key = block_key(1, 0x1000, &salt);
        let first = vec![0x70u8];
        let second = vec![0x52u8];
        let next = weave_next(&key, 0, &first);
        assert_ne!(next, key);
        let mut sealed = second.clone();
        xor_keystream(&next, &block_nonce(1, &salt, 0x1000), 0, &mut sealed).unwrap();
        let mut under_master = sealed.clone();
        assert!(xor_keystream(&key, &block_nonce(1, &salt, 0x1000), 0, &mut under_master).is_err());
        let mut opened = sealed;
        xor_keystream(&next, &block_nonce(1, &salt, 0x1000), 0, &mut opened).unwrap();
        assert_eq!(opened, second);
    }

    #[test]
    fn reseal_is_chacha20_with_a_new_block_nonce() {
        let salt = [0x24u8; SALT_LEN];
        let index = 3u32;
        let open = block_nonce(index, &salt, 0);
        let nonce = reseal_nonce(index, &salt, 0);
        assert_ne!(nonce, open);
        assert_eq!(&nonce[..4], &(index | RESEAL_MARK).to_le_bytes());
        let inner = crate::vm::inner::dispatcher_nonce(&salt);
        assert_ne!(nonce, inner);
        let key = [0x42u8; KEY_LEN];
        let plain = [0x03u8, 0, 7, 0, 0, 0, 0, 0, 0, 0];
        let sealed = reseal_block(&key, index, 0, &salt, &plain).unwrap();
        let mut via_crate = plain.to_vec();
        crate::crypto::chacha20(&key, &nonce, &mut via_crate);
        assert_eq!(sealed, via_crate);
        assert_ne!(sealed, plain);
        let mut via_open = plain.to_vec();
        xor_keystream(&key, &open, 0, &mut via_open).unwrap();
        assert_ne!(sealed, via_open);
        assert_eq!(reseal_block(&key, index, 0, &salt, &sealed).unwrap(), plain);
    }

    #[test]
    fn window_proofs_name_system_and_crypto() {
        let rows = window_proofs();
        assert_eq!(rows[0].channel, "System");
        assert_eq!(rows[0].machine, "M-EMU");
        assert_eq!(rows[0].anchor, "one_open_block_at_each_boundary");
        assert_eq!(rows[1].channel, "Crypto");
        assert_eq!(rows[1].machine, "");
        assert_eq!(rows[1].anchor, "reseal_is_chacha20_with_a_new_block_nonce");
    }

    #[test]
    fn block_nonce_does_not_repeat_for_the_process() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use std::collections::BTreeSet;
        let funcs = [nonce_func("a", 0x1000), nonce_func("b", 0x2000)];
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let image = crate::vm::lower_image(&funcs, &mut rng).unwrap();
        assert_eq!(image.funcs[0].salt, image.funcs[1].salt);
        let mut seen = BTreeSet::new();
        let inner = crate::vm::inner::dispatcher_nonce(&image.funcs[0].salt);
        assert!(seen.insert(inner));
        for func in &image.funcs {
            for index in 0..func.insns.len() {
                assert!(seen.insert(block_nonce(index as u32, &func.salt, func.rva)));
                assert!(seen.insert(reseal_nonce(index as u32, &func.salt, func.rva)));
            }
        }
        let fresh = [
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C,
        ];
        let mut sample = [0u8; 1];
        xor_keystream(&[1u8; KEY_LEN], &fresh, 0, &mut sample).unwrap();
        assert!(xor_keystream(&[2u8; KEY_LEN], &fresh, 0, &mut sample).is_err());
        assert!(xor_keystream(&[1u8; KEY_LEN], &fresh, 0, &mut sample).is_ok());
    }

    #[test]
    fn xor_keystream_rejects_a_different_key_for_the_same_nonce() {
        let nonce = [
            0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28, 0x19, 0x0a, 0x5a, 0x6b,
        ];
        let mut data = [1u8, 2, 3, 4];
        xor_keystream(&[0x11; KEY_LEN], &nonce, 0, &mut data).unwrap();
        assert!(xor_keystream(&[0x22; KEY_LEN], &nonce, 0, &mut data).is_err());
        xor_keystream(&[0x11; KEY_LEN], &nonce, 0, &mut data).unwrap();
    }

    #[test]
    fn xor_keystream_rejects_a_different_plaintext_for_the_same_nonce() {
        let key = [0x31u8; KEY_LEN];
        let nonce = [
            0x41, 0x52, 0x63, 0x74, 0x85, 0x96, 0xa7, 0xb8, 0xc9, 0xda, 0xeb, 0xfc,
        ];
        let mut first = [0x10u8, 0x20, 0x30, 0x40];
        let original = first;
        let mut other = [0x11u8, 0x20, 0x30, 0x40];
        xor_keystream(&key, &nonce, 0, &mut first).unwrap();
        assert!(xor_keystream(&key, &nonce, 0, &mut other).is_err());
        let mut again = original;
        xor_keystream(&key, &nonce, 0, &mut again).unwrap();
        xor_keystream(&key, &nonce, 0, &mut first).unwrap();
        assert_eq!(first, original);
    }

    fn nonce_func(name: &str, rva: u32) -> crate::ir::FuncIr {
        crate::ir::FuncIr {
            name: name.into(),
            rva,
            entry: 0,
            blocks: vec![crate::ir::Block {
                ops: vec![crate::ir::Op::MovRi(0, 1), crate::ir::Op::AddRi(0, 2)],
                exit: crate::ir::Exit::Ret,
                opaque: false,
            }],
        }
    }
}
