pub const BOOTSTRAP_MAGIC: &[u8; 16] = b"VMK_AUTH_BOOT_V2";
pub const BOOTSTRAP_SIGNATURE_DOMAIN: &[u8] = b"vmkek.auth.bootstrap.signature.v2\0";
pub const BOOTSTRAP_VERSION: u16 = 2;
pub const BOOTSTRAP_TYPE: u16 = 1;
pub const BOOTSTRAP_PLATFORM_ELF64: u8 = 2;
pub const BOOTSTRAP_PROFILE_LAB: u8 = 1;
pub const BOOTSTRAP_CORE_LEN: usize = 202;
pub const BOOTSTRAP_KEY_ID_OFFSET: usize = 118;
pub const BOOTSTRAP_SALT_OFFSET: usize = 150;
pub const BOOTSTRAP_SEQUENCE_OFFSET: usize = 182;
pub const BOOTSTRAP_NONCE_OFFSET: usize = 190;
pub const BOOTSTRAP_HASH_OFFSET: usize = BOOTSTRAP_CORE_LEN;
pub const BOOTSTRAP_TAG_OFFSET: usize = BOOTSTRAP_HASH_OFFSET + 32;
pub const BOOTSTRAP_SIGNATURE_OFFSET: usize = BOOTSTRAP_TAG_OFFSET + 16;
pub const BOOTSTRAP_MANIFEST_LEN: usize = BOOTSTRAP_SIGNATURE_OFFSET + 64;
/// Bound for the bootstrap payload. This format carries the raw plaintext without compression.
pub const BOOTSTRAP_MAX_PAYLOAD: usize = 4 * 1024 * 1024;

pub const ELF_LAB_HELPER_VA: u64 = 0x2000_0000;
pub const ELF_LAB_ENTRY_AFTER_MANIFEST: usize =
    (BOOTSTRAP_MANIFEST_LEN + BOOTSTRAP_CORE_LEN + 65).next_multiple_of(16);

pub(super) fn signature_transcript(
    manifest: &[u8; BOOTSTRAP_MANIFEST_LEN],
) -> [u8; BOOTSTRAP_SIGNATURE_DOMAIN.len() + BOOTSTRAP_SIGNATURE_OFFSET] {
    let mut bytes = [0; BOOTSTRAP_SIGNATURE_DOMAIN.len() + BOOTSTRAP_SIGNATURE_OFFSET];
    let prefix = BOOTSTRAP_SIGNATURE_DOMAIN.len();
    bytes[..prefix].copy_from_slice(BOOTSTRAP_SIGNATURE_DOMAIN);
    bytes[prefix..].copy_from_slice(&manifest[..BOOTSTRAP_SIGNATURE_OFFSET]);
    bytes
}
