#![no_std]
#![no_main]

use core::{panic::PanicInfo, ptr, slice};

use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[allow(dead_code)]
#[path = "../../../src/crypto/authenticated/bootstrap/wire.rs"]
mod wire;
use wire::*;

/// Verify and open the bounded ELF lab payload in place.
///
/// # Safety
/// All pointers must refer to mapped, valid ranges of their declared lengths.
/// The writable key and payload ranges must be disjoint from all other arguments.
#[no_mangle]
pub unsafe extern "C" fn vmk_verify_elf_bootstrap(
    manifest: *const [u8; wire::BOOTSTRAP_MANIFEST_LEN],
    expected: *const [u8; wire::BOOTSTRAP_CORE_LEN],
    trusted_public: *const [u8; 65],
    key: *mut [u8; 32],
    payload: *mut u8,
    len: usize,
) -> u32 {
    if len == 0 || len > wire::BOOTSTRAP_MAX_PAYLOAD {
        return 0;
    }
    // The fixed-layout caller supplies disjoint, mapped manifest, key and payload ranges.
    let (manifest, expected, trusted_public, key, payload) = unsafe {
        (
            &*manifest,
            &*expected,
            &*trusted_public,
            &mut *key,
            slice::from_raw_parts_mut(payload, len),
        )
    };
    let result = verify_elf_lab(expected, manifest, trusted_public, key, payload);
    key.zeroize();
    u32::from(result)
}

fn verify_elf_lab(
    expected: &[u8; BOOTSTRAP_CORE_LEN],
    manifest: &[u8; BOOTSTRAP_MANIFEST_LEN],
    trusted_public: &[u8; 65],
    key: &[u8; 32],
    payload: &mut [u8],
) -> bool {
    if manifest[..BOOTSTRAP_CORE_LEN] != *expected
        || &manifest[..16] != BOOTSTRAP_MAGIC
        || manifest[16..18] != BOOTSTRAP_VERSION.to_le_bytes()
        || manifest[18..20] != BOOTSTRAP_TYPE.to_le_bytes()
        || manifest[20..22] != (BOOTSTRAP_CORE_LEN as u16).to_le_bytes()
        || manifest[22..24] != [BOOTSTRAP_PLATFORM_ELF64, BOOTSTRAP_PROFILE_LAB]
        || manifest[BOOTSTRAP_KEY_ID_OFFSET..BOOTSTRAP_SALT_OFFSET]
            != Sha256::digest(trusted_public)[..]
        || manifest[BOOTSTRAP_HASH_OFFSET..BOOTSTRAP_TAG_OFFSET] != Sha256::digest(&*payload)[..]
    {
        return false;
    }
    let Ok(pin) = VerifyingKey::from_sec1_bytes(trusted_public) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&manifest[BOOTSTRAP_SIGNATURE_OFFSET..]) else {
        return false;
    };
    if pin
        .verify(&signature_transcript(manifest), &signature)
        .is_err()
    {
        return false;
    }
    ChaCha20Poly1305::new(key.into())
        .decrypt_in_place_detached(
            Nonce::from_slice(&manifest[BOOTSTRAP_NONCE_OFFSET..BOOTSTRAP_CORE_LEN]),
            expected,
            payload,
            Tag::from_slice(&manifest[BOOTSTRAP_TAG_OFFSET..BOOTSTRAP_SIGNATURE_OFFSET]),
        )
        .is_ok()
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

#[no_mangle]
unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for index in 0..n {
        unsafe {
            ptr::write_volatile(dst.add(index), ptr::read_volatile(src.add(index)));
        }
    }
    dst
}

#[no_mangle]
unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
    for index in 0..n {
        unsafe {
            ptr::write_volatile(dst.add(index), val as u8);
        }
    }
    dst
}

#[no_mangle]
unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for index in 0..n {
        let x = unsafe { ptr::read_volatile(a.add(index)) };
        let y = unsafe { ptr::read_volatile(b.add(index)) };
        if x != y {
            return i32::from(x) - i32::from(y);
        }
    }
    0
}

#[no_mangle]
unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    unsafe { memcmp(a, b, n) }
}
