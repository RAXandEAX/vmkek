pub mod authenticated;

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::zeroize::Zeroizing;
use p256::EncodedPoint;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{exact_bytes, msg, Result};

/// HKDF-SHA256 (RFC 5869). Empty `salt` is the HashLen string of zeros.
///
/// Accepts an `okm` of 1 through `255 * 32` bytes. The counter increments only
/// when more output bytes are still required, so the RFC maximum does not wrap
/// the `u8` block counter. S3b calls it with the block seed and info
/// `vmkek.vm.bytecode`. S5a calls the same function for the payload key, nonce,
/// and signing scalar, with salt `vmkek.payload` and distinct info labels.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    if okm.is_empty() || okm.len() > 255 * 32 {
        return Err(msg("hkdf length is out of range"));
    }
    let prk = Zeroizing::new(hkdf_extract(salt, ikm));
    let mut previous = Zeroizing::new(Vec::new());
    let mut written = 0usize;
    let mut counter = 1u8;
    while written < okm.len() {
        let mut message = Zeroizing::new(Vec::with_capacity(previous.len() + info.len() + 1));
        message.extend_from_slice(&previous);
        message.extend_from_slice(info);
        message.push(counter);
        let next = Zeroizing::new(hmac_sha256(prk.as_ref(), &message));
        previous = Zeroizing::new(next.to_vec());
        let take = (okm.len() - written).min(previous.len());
        okm[written..written + take].copy_from_slice(&previous[..take]);
        written += take;
        if written < okm.len() {
            counter = counter
                .checked_add(1)
                .ok_or_else(|| msg("hkdf counter wrapped"))?;
        }
    }
    Ok(())
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    if salt.is_empty() {
        hmac_sha256(&[0u8; 32], ikm)
    } else {
        hmac_sha256(salt, ikm)
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for index in 0..64 {
        inner[index] ^= block[index];
        outer[index] ^= block[index];
    }
    let mut body = Vec::with_capacity(64 + message.len());
    body.extend_from_slice(&inner);
    body.extend_from_slice(message);
    let digest = Zeroizing::new(sha256(&body));
    crate::secret::wipe(&mut body);
    body.clear();
    body.extend_from_slice(&outer);
    body.extend_from_slice(digest.as_ref());
    let out = sha256(&body);
    crate::secret::wipe(&mut body);
    crate::secret::wipe(&mut block);
    crate::secret::wipe(&mut inner);
    crate::secret::wipe(&mut outer);
    out
}

pub fn chacha20(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(data);
}

#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn lzss_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < data.len() {
        let flag_at = out.len();
        out.push(0);
        let mut flags = 0u8;
        for bit in 0..8 {
            if cursor >= data.len() {
                break;
            }
            let window = cursor.saturating_sub(4095);
            let mut best_len = 0usize;
            let mut best_off = 0usize;
            let max_len = (data.len() - cursor).min(18);
            if max_len >= 3 {
                for start in window..cursor {
                    let mut len = 0;
                    while len < max_len && data[start + len] == data[cursor + len] {
                        len += 1;
                    }
                    if len > best_len {
                        best_len = len;
                        best_off = cursor - start;
                    }
                }
            }
            if best_len >= 3 {
                let word = ((best_off - 1) as u16) | (((best_len - 3) as u16) << 12);
                out.push(word as u8);
                out.push((word >> 8) as u8);
                cursor += best_len;
            } else {
                flags |= 1 << bit;
                out.push(data[cursor]);
                cursor += 1;
            }
        }
        out[flag_at] = flags;
    }
    out
}

const MAX_LZSS_OUTPUT: usize = 32 * 1024 * 1024;

/// Decode exactly one LZSS stream with a bounded declared output length.
pub fn lzss_decompress(src: &[u8], out_len: usize) -> Result<Vec<u8>> {
    if out_len > MAX_LZSS_OUTPUT || out_len > src.len().saturating_mul(18) {
        return Err(msg("lzss output exceeds the decode limit"));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(out_len)
        .map_err(|_| msg("could not reserve lzss output"))?;
    let mut cursor = 0usize;
    while out.len() < out_len {
        if cursor >= src.len() {
            return Err(msg("lzss stream ended early"));
        }
        let flags = src[cursor];
        cursor += 1;
        for bit in 0..8 {
            if out.len() >= out_len {
                break;
            }
            if flags & (1 << bit) != 0 {
                let literal = *src.get(cursor).ok_or_else(|| msg("lzss literal missing"))?;
                cursor += 1;
                out.push(literal);
            } else {
                if cursor + 1 >= src.len() {
                    return Err(msg("lzss match truncated"));
                }
                let word = u16::from(src[cursor]) | (u16::from(src[cursor + 1]) << 8);
                cursor += 2;
                let length = usize::from(word >> 12) + 3;
                let offset = usize::from(word & 0x0fff) + 1;
                if offset > out.len() {
                    return Err(msg("lzss offset out of range"));
                }
                if length > out_len - out.len() {
                    return Err(msg("lzss match exceeds the declared output"));
                }
                let start = out.len() - offset;
                for index in 0..length {
                    out.push(out[start + index]);
                }
            }
        }
    }
    if cursor != src.len() {
        return Err(msg("trailing bytes in lzss stream"));
    }
    Ok(out)
}

/// Salt for payload HKDF. The VM cipher uses a per-build salt and another info label.
const PAYLOAD_SALT: &[u8] = b"vmkek.payload";
const INFO_AEAD_KEY: &[u8] = b"aead-key";
const INFO_AEAD_NONCE: &[u8] = b"aead-nonce";
const INFO_SIGN: &[u8] = b"ecdsa-p256";
const SIGN_DOMAIN: &[u8] = b"vmkek.payload.sig.v2";
const AEAD_DOMAIN: &[u8] = b"vmkek.payload.v2";
/// First ChaCha20 block is the Poly1305 one-time key. Payload bytes start at counter 1.
const AEAD_KEYSTREAM_OFFSET: u64 = 64;

pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;

/// ChaCha20-Poly1305 payload seal. `key` is the AEAD key embedded in the loader, not a header field.
#[derive(Clone)]
pub struct PayloadSeal {
    pub key: [u8; AEAD_KEY_LEN],
    pub nonce: [u8; AEAD_NONCE_LEN],
    pub tag: [u8; AEAD_TAG_LEN],
    pub ciphertext: Vec<u8>,
    pub public: [u8; 65],
    pub signature: [u8; 64],
}

impl Drop for PayloadSeal {
    fn drop(&mut self) {
        crate::secret::wipe(&mut self.key);
    }
}

impl std::fmt::Debug for PayloadSeal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PayloadSeal")
            .field("public", &self.public)
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

/// IETF ChaCha20 keystream used by ChaCha20-Poly1305, starting at block counter 1.
pub fn aead_keystream(key: &[u8; AEAD_KEY_LEN], nonce: &[u8; AEAD_NONCE_LEN], data: &mut [u8]) {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.seek(AEAD_KEYSTREAM_OFFSET);
    cipher.apply_keystream(data);
}

/// Seal `plaintext` with ChaCha20-Poly1305. The tag is returned separately from the ciphertext.
pub fn aead_seal(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; AEAD_TAG_LEN])> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| msg("aead key rejected"))?;
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| msg("aead seal failed"))?;
    if sealed.len() < AEAD_TAG_LEN {
        return Err(msg("aead tag missing"));
    }
    let split = sealed.len() - AEAD_TAG_LEN;
    let mut tag = [0u8; AEAD_TAG_LEN];
    tag.copy_from_slice(&sealed[split..]);
    Ok((sealed[..split].to_vec(), tag))
}

/// Compare two tags without returning on the first differing byte.
#[must_use]
pub fn tags_equal(left: &[u8; AEAD_TAG_LEN], right: &[u8; AEAD_TAG_LEN]) -> bool {
    let mut diff = 0u8;
    let mut index = 0usize;
    while index < AEAD_TAG_LEN {
        diff |= left[index] ^ right[index];
        index += 1;
    }
    diff == 0
}

/// Open a ChaCha20-Poly1305 ciphertext. A wrong tag or AAD is an integrity failure.
///
/// The tag check is [`tags_equal`]: one accumulator, not a branch per byte.
pub fn aead_open(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    tag: &[u8; AEAD_TAG_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut local = *key;
    let opened = open_checked(&local, nonce, tag, aad, ciphertext);
    crate::secret::wipe(&mut local);
    crate::secret::wipe_volatile_regs();
    opened
}

fn open_checked(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    tag: &[u8; AEAD_TAG_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut plain = decrypt_aead(key, nonce, tag, aad, ciphertext)?;
    let (_body, got) = aead_seal(key, nonce, aad, &plain)?;
    if !tags_equal(&got, tag) {
        crate::secret::wipe(&mut plain);
        return Err(crate::error::Error::Integrity);
    }
    Ok(plain)
}

fn decrypt_aead(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    tag: &[u8; AEAD_TAG_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| msg("aead key rejected"))?;
    let mut body = Vec::with_capacity(ciphertext.len() + AEAD_TAG_LEN);
    body.extend_from_slice(ciphertext);
    body.extend_from_slice(tag);
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: &body, aad })
        .map_err(|_| crate::error::Error::Integrity)
}

/// Associated data for the payload AEAD.
///
/// Binds the domain, public key, nonce, lengths, `original_entry`, and `image_base`,
/// so a substituted entry RVA fails the tag check.
#[must_use]
pub fn payload_aad(
    public: &[u8; 65],
    nonce: &[u8; AEAD_NONCE_LEN],
    raw_len: u32,
    payload_len: u32,
    original_entry: u32,
    image_base: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AEAD_DOMAIN.len() + public.len() + nonce.len() + 20);
    aad.extend_from_slice(AEAD_DOMAIN);
    aad.extend_from_slice(public);
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(&raw_len.to_le_bytes());
    aad.extend_from_slice(&payload_len.to_le_bytes());
    aad.extend_from_slice(&original_entry.to_le_bytes());
    aad.extend_from_slice(&image_base.to_le_bytes());
    aad
}

/// Bytes covered by the external P-256 signature.
///
/// Binds the domain, AEAD key, nonce, tag, ciphertext, `original_entry`, and `image_base`.
#[must_use]
pub fn signed_message(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    tag: &[u8; AEAD_TAG_LEN],
    ciphertext: &[u8],
    original_entry: u32,
    image_base: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SIGN_DOMAIN.len() + key.len() + nonce.len() + tag.len() + ciphertext.len() + 12,
    );
    message.extend_from_slice(SIGN_DOMAIN);
    message.extend_from_slice(key);
    message.extend_from_slice(nonce);
    message.extend_from_slice(tag);
    message.extend_from_slice(ciphertext);
    message.extend_from_slice(&original_entry.to_le_bytes());
    message.extend_from_slice(&image_base.to_le_bytes());
    message
}

/// Seal `plaintext`. `random_key` draws the AEAD and signing keys from `OsRng`.
/// Otherwise they are HKDF-SHA256 of `seed` through [`hkdf_sha256`].
///
/// `original_entry` and `image_base` are bound into the AEAD AAD and the signature.
pub fn seal_payload(
    plaintext: &[u8],
    seed: u64,
    random_key: bool,
    original_entry: u32,
    image_base: u64,
) -> Result<PayloadSeal> {
    let (key, nonce, signing) = if random_key {
        random_material()
    } else {
        deterministic_material(seed)?
    };
    finish_seal(plaintext, key, nonce, signing, original_entry, image_base)
}

/// Re-encrypt with an existing AEAD key and a fresh P-256 signing key.
///
/// `original_entry` and `image_base` are bound into the AEAD AAD and the signature.
pub fn seal_with(
    plaintext: &[u8],
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    original_entry: u32,
    image_base: u64,
) -> Result<PayloadSeal> {
    let signing = SigningKey::random(&mut OsRng);
    finish_seal(plaintext, *key, *nonce, signing, original_entry, image_base)
}

/// Open a sealed payload. The caller must not ignore the result: a bad tag is an error.
#[must_use = "ignoring the opened payload skips the Poly1305 tag check"]
pub fn open_payload(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    tag: &[u8; AEAD_TAG_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    aead_open(key, nonce, tag, aad, ciphertext)
}

/// Verify a P-256 signature over `message` with the uncompressed `public` point.
///
/// The result must be checked. Ignoring it accepts a forged signature.
#[must_use = "ignoring the result accepts a forged signature"]
pub fn verify_signature(public: &[u8; 65], signature: &[u8; 64], message: &[u8]) -> Result<()> {
    let point = EncodedPoint::from_bytes(public.as_slice()).map_err(|_| msg("bad p256 point"))?;
    let verifying =
        VerifyingKey::from_encoded_point(&point).map_err(|_| msg("bad verifying key"))?;
    let sig = Signature::from_bytes(signature.into()).map_err(|_| msg("bad signature encoding"))?;
    verifying
        .verify(message, &sig)
        .map_err(|_| crate::error::Error::BadSignature)
}

/// P-256 scalar HKDF would derive for `seed`. It is never written into the image.
pub fn deterministic_signing_scalar(seed: u64) -> Result<[u8; AEAD_KEY_LEN]> {
    let signing = deterministic_signing_key(seed)?;
    let bytes = signing.to_bytes();
    let mut scalar = [0u8; AEAD_KEY_LEN];
    scalar.copy_from_slice(bytes.as_slice());
    Ok(scalar)
}

/// True when `header` holds `key` or two windows whose XOR is `key`.
#[must_use]
pub fn header_exposes_key(header: &[u8], key: &[u8; AEAD_KEY_LEN]) -> bool {
    if header.windows(AEAD_KEY_LEN).any(|window| window == key) {
        return true;
    }
    let windows = header.len().saturating_sub(AEAD_KEY_LEN - 1);
    for left in 0..windows {
        for right in (left + 1)..windows {
            if (0..AEAD_KEY_LEN).all(|byte| header[left + byte] ^ header[right + byte] == key[byte])
            {
                return true;
            }
        }
    }
    false
}

fn finish_seal(
    plaintext: &[u8],
    key: [u8; AEAD_KEY_LEN],
    nonce: [u8; AEAD_NONCE_LEN],
    signing: SigningKey,
    original_entry: u32,
    image_base: u64,
) -> Result<PayloadSeal> {
    let public = public_bytes(&signing);
    let raw_len = u32::try_from(plaintext.len()).map_err(|_| msg("payload does not fit"))?;
    let aad = payload_aad(
        &public,
        &nonce,
        raw_len,
        raw_len,
        original_entry,
        image_base,
    );
    let (ciphertext, tag) = aead_seal(&key, &nonce, &aad, plaintext)?;
    let signature = signature_bytes(
        &signing,
        &signed_message(&key, &nonce, &tag, &ciphertext, original_entry, image_base),
    );
    Ok(PayloadSeal {
        key,
        nonce,
        tag,
        ciphertext,
        public,
        signature,
    })
}

fn deterministic_material(
    seed: u64,
) -> Result<([u8; AEAD_KEY_LEN], [u8; AEAD_NONCE_LEN], SigningKey)> {
    let ikm = seed.to_le_bytes();
    let mut key = [0u8; AEAD_KEY_LEN];
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    hkdf_sha256(&ikm, PAYLOAD_SALT, INFO_AEAD_KEY, &mut key)?;
    hkdf_sha256(&ikm, PAYLOAD_SALT, INFO_AEAD_NONCE, &mut nonce)?;
    Ok((key, nonce, deterministic_signing_key(seed)?))
}

fn random_material() -> ([u8; AEAD_KEY_LEN], [u8; AEAD_NONCE_LEN], SigningKey) {
    let mut key = [0u8; AEAD_KEY_LEN];
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce);
    let signing = SigningKey::random(&mut rng);
    (key, nonce, signing)
}

fn deterministic_signing_key(seed: u64) -> Result<SigningKey> {
    let ikm = seed.to_le_bytes();
    for counter in 0u8..32 {
        let mut scalar = [0u8; AEAD_KEY_LEN];
        hkdf_sha256(&ikm, PAYLOAD_SALT, &signing_info(counter), &mut scalar)?;
        if let Ok(key) = SigningKey::from_slice(&scalar) {
            return Ok(key);
        }
    }
    Err(msg("signing scalar was rejected"))
}

/// First attempt uses the bare label `ecdsa-p256`. A counter byte is appended only after
/// [`SigningKey::from_slice`] rejects the scalar.
fn signing_info(counter: u8) -> Vec<u8> {
    let mut info = Vec::with_capacity(INFO_SIGN.len() + usize::from(counter > 0));
    info.extend_from_slice(INFO_SIGN);
    if counter > 0 {
        info.push(counter);
    }
    info
}

fn public_bytes(signing: &SigningKey) -> [u8; 65] {
    let point = VerifyingKey::from(signing).to_encoded_point(false);
    let mut public = [0u8; 65];
    public.copy_from_slice(point.as_bytes());
    public
}

fn signature_bytes(signing: &SigningKey, message: &[u8]) -> [u8; 64] {
    let signature: Signature = signing.sign(message);
    let mut encoded = [0u8; 64];
    encoded.copy_from_slice(signature.to_bytes().as_slice());
    encoded
}

pub const HEADER_LEN: usize = 0x200;
pub const HEADER_VERSION: u32 = 2;
pub const MAGIC: &[u8; 8] = b"VMKEK64\0";

const OFF_TAG: usize = 76;
const OFF_PUBLIC: usize = 92;
const OFF_SIGNATURE: usize = 160;
const OFF_ORIGINAL_ENTRY: usize = 224;
const OFF_IMAGE_BASE: usize = 228;

/// Parsed `.vmkek` header. The AEAD key is not stored here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub payload_off: u32,
    pub payload_len: u32,
    pub raw_len: u32,
    /// Fast checksum of the ciphertext. Not cryptographic integrity.
    pub crc32: u32,
    /// Unkeyed fingerprint of the ciphertext. Not cryptographic integrity.
    pub sha256: [u8; 32],
    pub nonce: [u8; AEAD_NONCE_LEN],
    pub tag: [u8; AEAD_TAG_LEN],
    pub public: [u8; 65],
    pub signature: [u8; 64],
    pub original_entry: u32,
    pub image_base: u64,
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8..12].copy_from_slice(&HEADER_VERSION.to_le_bytes());
        out[12..16].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        out[16..20].copy_from_slice(&self.payload_off.to_le_bytes());
        out[20..24].copy_from_slice(&self.payload_len.to_le_bytes());
        out[24..28].copy_from_slice(&self.raw_len.to_le_bytes());
        out[28..32].copy_from_slice(&self.crc32.to_le_bytes());
        out[32..64].copy_from_slice(&self.sha256);
        out[64..OFF_TAG].copy_from_slice(&self.nonce);
        out[OFF_TAG..OFF_TAG + AEAD_TAG_LEN].copy_from_slice(&self.tag);
        out[OFF_PUBLIC..OFF_PUBLIC + 65].copy_from_slice(&self.public);
        out[OFF_SIGNATURE..OFF_SIGNATURE + 64].copy_from_slice(&self.signature);
        out[OFF_ORIGINAL_ENTRY..OFF_ORIGINAL_ENTRY + 4]
            .copy_from_slice(&self.original_entry.to_le_bytes());
        out[OFF_IMAGE_BASE..OFF_IMAGE_BASE + 8].copy_from_slice(&self.image_base.to_le_bytes());
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
            return Err(msg("vmkek header missing"));
        }
        let u32_at = |off: usize| -> Result<u32> {
            Ok(u32::from_le_bytes(exact_bytes(&bytes[off..off + 4])?))
        };
        let version = u32_at(8)?;
        let header_len = u32_at(12)?;
        if version != HEADER_VERSION || header_len != HEADER_LEN as u32 {
            return Err(msg("vmkek header version"));
        }
        Ok(Self {
            payload_off: u32_at(16)?,
            payload_len: u32_at(20)?,
            raw_len: u32_at(24)?,
            crc32: u32_at(28)?,
            sha256: exact_bytes(&bytes[32..64])?,
            nonce: exact_bytes(&bytes[64..OFF_TAG])?,
            tag: exact_bytes(&bytes[OFF_TAG..OFF_TAG + AEAD_TAG_LEN])?,
            public: exact_bytes(&bytes[OFF_PUBLIC..OFF_PUBLIC + 65])?,
            signature: exact_bytes(&bytes[OFF_SIGNATURE..OFF_SIGNATURE + 64])?,
            original_entry: u32_at(OFF_ORIGINAL_ENTRY)?,
            image_base: u64::from_le_bytes(exact_bytes(
                &bytes[OFF_IMAGE_BASE..OFF_IMAGE_BASE + 8],
            )?),
        })
    }
}

/// Where the payload section header sits. The section name is not fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmkekHeader {
    /// No section starts with [`MAGIC`], and the entry is not a loader.
    Absent,
    /// A section begins at this file offset and starts with [`MAGIC`].
    At(usize),
}

/// Locate a payload header. The section name comes from the protect seed, so
/// the lookup is the magic at the start of a section.
///
/// A missing section is [`VmkekHeader::Absent`]. A loader prologue whose magic
/// was overwritten is an error, not an unprotected image.
pub fn locate_header(file: &[u8]) -> Result<VmkekHeader> {
    if crate::elf::is_elf(file) {
        return locate_elf_header(file);
    }
    let image = crate::pe::parse(file)?;
    if let Some(off) = magic_section(file, &image) {
        return Ok(VmkekHeader::At(off));
    }
    if entry_is_loader(&image) {
        return Err(msg("vmkek header is corrupt"));
    }
    Ok(VmkekHeader::Absent)
}

fn magic_section(file: &[u8], image: &crate::pe::PeImage) -> Option<usize> {
    image.sections.iter().find_map(|section| {
        let off = crate::pe::section_file_offset(file, &section.name).ok()?;
        if file.get(off..off + MAGIC.len()) == Some(MAGIC) {
            Some(off)
        } else {
            None
        }
    })
}

fn entry_is_loader(image: &crate::pe::PeImage) -> bool {
    let Some(section) = image.sections.iter().find(|section| {
        let start = section.rva as usize;
        let end = start + section.bytes.len();
        (image.entry_rva as usize) >= start && (image.entry_rva as usize) < end
    }) else {
        return false;
    };
    let off = (image.entry_rva - section.rva) as usize;
    crate::loader::is_loader_prologue(&section.bytes[off..])
}

fn locate_elf_header(file: &[u8]) -> Result<VmkekHeader> {
    let image = crate::elf::parse(file)?;
    for section in &image.sections {
        let off = usize::try_from(section.offset).unwrap_or(usize::MAX);
        if file.get(off..off.saturating_add(MAGIC.len())) == Some(MAGIC) {
            return Ok(VmkekHeader::At(off));
        }
    }
    if elf_entry_is_loader(file, &image) {
        return Err(msg("vmkek header is corrupt"));
    }
    Ok(VmkekHeader::Absent)
}

fn elf_entry_is_loader(file: &[u8], image: &crate::elf::ElfImage) -> bool {
    if elf_entry_off(image).is_some_and(|off| prologue_at(file, off)) {
        return true;
    }
    // Early init moves the ELF entry off the loader. The loader still sits
    // immediately after the header inside the payload section.
    image.sections.iter().any(|section| {
        section.size > HEADER_LEN as u64 && prologue_at(file, section_loader(section))
    })
}

fn prologue_at(file: &[u8], off: usize) -> bool {
    file.get(off..)
        .is_some_and(crate::loader::is_loader_prologue)
}

fn section_loader(section: &crate::elf::Section) -> usize {
    usize::try_from(section.offset)
        .unwrap_or(usize::MAX)
        .saturating_add(HEADER_LEN)
}

fn elf_entry_off(image: &crate::elf::ElfImage) -> Option<usize> {
    let entry = image.entry;
    if let Some(section) = image
        .sections
        .iter()
        .find(|section| entry >= section.addr && entry < section.addr.saturating_add(section.size))
    {
        let delta = entry - section.addr;
        return usize::try_from(section.offset.saturating_add(delta)).ok();
    }
    let segment = image.segments.iter().find(|segment| {
        segment.kind == crate::elf::SegmentKind::Load
            && entry >= segment.vaddr
            && entry < segment.vaddr.saturating_add(segment.filesz)
    })?;
    usize::try_from(segment.offset.saturating_add(entry - segment.vaddr)).ok()
}

/// File offset of a `.vmkek` header with matching magic.
///
/// A missing section and a corrupt section produce different errors. See [`locate_header`].
pub fn find_header(file: &[u8]) -> Result<usize> {
    match locate_header(file)? {
        VmkekHeader::At(off) => Ok(off),
        VmkekHeader::Absent => Err(msg("protected image has no vmkek header")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_sha256_matches_rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut okm = [0u8; 42];
        hkdf_sha256(&ikm, &salt, &info, &mut okm).unwrap();
        assert_eq!(
            okm,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
    }

    #[test]
    fn hkdf_sha256_accepts_the_rfc5869_maximum_and_rejects_one_more_byte() {
        let ikm = b"vmkek-s3b";
        let salt = b"salt";
        let info = b"vmkek.vm.bytecode";
        let mut max = vec![0u8; 255 * 32];
        hkdf_sha256(ikm, salt, info, &mut max).unwrap();
        let mut key = [0u8; 32];
        hkdf_sha256(ikm, salt, info, &mut key).unwrap();
        assert_eq!(
            key.as_slice(),
            &max[..32],
            "32-byte S3b key is the first block"
        );
        let mut too_long = vec![0u8; 255 * 32 + 1];
        let err = hkdf_sha256(ikm, salt, info, &mut too_long).unwrap_err();
        assert_eq!(err.to_string(), "hkdf length is out of range");
    }

    #[test]
    fn chacha_matches_documented_vector() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let mut data = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        chacha20(&key, &nonce, &mut data);
        assert_eq!(
            data,
            [
                0xe4, 0x05, 0x62, 0x6e, 0x4f, 0x12, 0x36, 0xb3, 0x67, 0x0e, 0xe4, 0x28, 0x33, 0x2e,
                0xa2, 0x0e
            ]
        );
    }

    #[test]
    fn lzss_rejects_oversized_and_inconsistent_output() {
        assert!(lzss_decompress(&[], usize::MAX).is_err());
        let match_after_literal = [1, b'a', 0, 0];
        assert!(lzss_decompress(&match_after_literal, 2).is_err());
        assert_eq!(lzss_decompress(&match_after_literal, 4).unwrap(), b"aaaa");
        assert!(lzss_decompress(&[1, b'a', 0], 1).is_err());
    }

    #[test]
    fn lzss_roundtrip() {
        let data = b"vmkek-ok:775\n--repeated-vmkek-ok:775\n--repeated-vmkek-ok:775\n".repeat(4);
        let packed = lzss_compress(&data);
        assert!(packed.len() < data.len());
        assert_eq!(lzss_decompress(&packed, data.len()).unwrap(), data);
    }

    #[test]
    fn aead_matches_rfc8439_vector() {
        let key: [u8; 32] =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = unhex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        );
        let expect_ct = unhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let expect_tag: [u8; 16] = unhex("1ae10b594f09e26a7e902ecbd0600691")
            .try_into()
            .unwrap();
        let (ciphertext, tag) = aead_seal(&key, &nonce, &aad, &plaintext).unwrap();
        assert_eq!(ciphertext, expect_ct);
        assert_eq!(tag, expect_tag);
        let mut stream = ciphertext.clone();
        aead_keystream(&key, &nonce, &mut stream);
        assert_eq!(stream, plaintext);
        let mut counter_zero = ciphertext.clone();
        chacha20(&key, &nonce, &mut counter_zero);
        assert_ne!(counter_zero, plaintext);
        assert_eq!(
            aead_open(&key, &nonce, &tag, &aad, &ciphertext).unwrap(),
            plaintext
        );
    }

    fn bound_aad(seal: &PayloadSeal, raw: u32, len: u32) -> Vec<u8> {
        payload_aad(&seal.public, &seal.nonce, raw, len, 0, 0)
    }

    fn bound_message(seal: &PayloadSeal, tag: &[u8; AEAD_TAG_LEN], body: &[u8]) -> Vec<u8> {
        signed_message(&seal.key, &seal.nonce, tag, body, 0, 0)
    }

    #[test]
    fn aead_roundtrip_rejects_a_flipped_byte() {
        let plain = b"vmkek payload";
        let seal = seal_payload(plain, 0x11, false, 0, 0).unwrap();
        let raw = plain.len() as u32;
        let aad = bound_aad(&seal, raw, seal.ciphertext.len() as u32);
        assert_eq!(
            open_payload(&seal.key, &seal.nonce, &seal.tag, &seal.ciphertext, &aad).unwrap(),
            plain
        );
        verify_signature(
            &seal.public,
            &seal.signature,
            &bound_message(&seal, &seal.tag, &seal.ciphertext),
        )
        .unwrap();
        let mut flipped = seal.ciphertext.clone();
        flipped[0] ^= 0xff;
        assert!(open_payload(&seal.key, &seal.nonce, &seal.tag, &flipped, &aad).is_err());
        assert!(verify_signature(
            &seal.public,
            &seal.signature,
            &bound_message(&seal, &seal.tag, &flipped),
        )
        .is_err());
        let mut bad_tag = seal.tag;
        bad_tag[0] ^= 0xff;
        assert!(open_payload(&seal.key, &seal.nonce, &bad_tag, &seal.ciphertext, &aad).is_err());
        assert!(verify_signature(
            &seal.public,
            &seal.signature,
            &bound_message(&seal, &bad_tag, &seal.ciphertext),
        )
        .is_err());
    }

    #[test]
    fn aead_binding_rejects_a_substituted_entry_or_base() {
        let plain = b"bind";
        let entry = 0x1000u32;
        let base = 0x1400_00000u64;
        let seal = seal_payload(plain, 5, false, entry, base).unwrap();
        let raw = plain.len() as u32;
        let len = seal.ciphertext.len() as u32;
        let aad = payload_aad(&seal.public, &seal.nonce, raw, len, entry, base);
        let message = signed_message(
            &seal.key,
            &seal.nonce,
            &seal.tag,
            &seal.ciphertext,
            entry,
            base,
        );
        open_payload(&seal.key, &seal.nonce, &seal.tag, &seal.ciphertext, &aad).unwrap();
        verify_signature(&seal.public, &seal.signature, &message).unwrap();
        let bad_entry = payload_aad(&seal.public, &seal.nonce, raw, len, entry ^ 1, base);
        assert!(open_payload(
            &seal.key,
            &seal.nonce,
            &seal.tag,
            &seal.ciphertext,
            &bad_entry
        )
        .is_err());
        let bad_base = payload_aad(&seal.public, &seal.nonce, raw, len, entry, base ^ 1);
        assert!(open_payload(
            &seal.key,
            &seal.nonce,
            &seal.tag,
            &seal.ciphertext,
            &bad_base
        )
        .is_err());
        let bad_msg = signed_message(
            &seal.key,
            &seal.nonce,
            &seal.tag,
            &seal.ciphertext,
            entry ^ 1,
            base,
        );
        assert!(verify_signature(&seal.public, &seal.signature, &bad_msg).is_err());
    }

    #[test]
    fn payload_key_reuses_hkdf_sha256() {
        let seed = 99u64;
        let seal = seal_payload(b"same", seed, false, 0, 0).unwrap();
        let again = seal_payload(b"same", seed, false, 0, 0).unwrap();
        assert_eq!(seal.ciphertext, again.ciphertext);
        assert_eq!(seal.tag, again.tag);
        assert_eq!(seal.signature, again.signature);
        assert_eq!(seal.public, again.public);
        let mut key = [0u8; 32];
        hkdf_sha256(&seed.to_le_bytes(), PAYLOAD_SALT, INFO_AEAD_KEY, &mut key).unwrap();
        assert_eq!(seal.key, key);
        let mut vm_info = [0u8; 32];
        hkdf_sha256(
            &seed.to_le_bytes(),
            PAYLOAD_SALT,
            b"vmkek.vm.bytecode",
            &mut vm_info,
        )
        .unwrap();
        assert_ne!(seal.key, vm_info);
        let scalar = deterministic_signing_scalar(seed).unwrap();
        assert_ne!(scalar, seal.key);
        let mut bare = [0u8; 32];
        hkdf_sha256(&seed.to_le_bytes(), PAYLOAD_SALT, INFO_SIGN, &mut bare).unwrap();
        assert_eq!(
            scalar, bare,
            "first signing attempt uses the bare ecdsa-p256 label"
        );
        let mut suffixed = INFO_SIGN.to_vec();
        suffixed.push(0);
        let mut with_zero = [0u8; 32];
        hkdf_sha256(&seed.to_le_bytes(), PAYLOAD_SALT, &suffixed, &mut with_zero).unwrap();
        assert_ne!(scalar, with_zero);
        assert_eq!(signing_info(0), b"ecdsa-p256");
        assert_eq!(signing_info(1), b"ecdsa-p256\x01");
        let random_a = seal_payload(b"same", seed, true, 0, 0).unwrap();
        let random_b = seal_payload(b"same", seed, true, 0, 0).unwrap();
        assert_ne!(random_a.public, random_b.public);
        assert_ne!(random_a.ciphertext, random_b.ciphertext);
    }

    #[test]
    fn header_roundtrip_has_no_key_halves() {
        let seal = seal_payload(b"header", 7, false, 0, 0).unwrap();
        let header = Header {
            payload_off: 0x400,
            payload_len: seal.ciphertext.len() as u32,
            raw_len: 6,
            crc32: 1,
            sha256: [2; 32],
            nonce: seal.nonce,
            tag: seal.tag,
            public: seal.public,
            signature: seal.signature,
            original_entry: 0x1000,
            image_base: 0x1400_00000,
        };
        let bytes = header.to_bytes();
        assert_eq!(Header::parse(&bytes).unwrap(), header);
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            HEADER_VERSION
        );
        assert!(!header_exposes_key(&bytes, &seal.key));
        let mut split = [0u8; HEADER_LEN];
        let masks = [0x11u8; 32];
        let mut stored = [0u8; 32];
        for index in 0..32 {
            stored[index] = seal.key[index] ^ masks[index];
        }
        split[..32].copy_from_slice(&stored);
        split[32..64].copy_from_slice(&masks);
        assert!(header_exposes_key(&split, &seal.key));
        let mut legacy = bytes;
        legacy[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            Header::parse(&legacy).unwrap_err().to_string(),
            "vmkek header version"
        );
    }

    #[test]
    fn tag_compare_does_not_depend_on_the_first_byte() {
        let tag = [0x11u8; AEAD_TAG_LEN];
        assert!(tags_equal(&tag, &tag));
        let mut first = tag;
        first[0] ^= 1;
        assert!(!tags_equal(&tag, &first));
        let mut last = tag;
        last[AEAD_TAG_LEN - 1] ^= 0x80;
        assert!(!tags_equal(&tag, &last));
        let mut mid = tag;
        mid[7] ^= 0xff;
        assert!(!tags_equal(&tag, &mid));
    }

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).unwrap()
    }
}
