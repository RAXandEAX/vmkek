use std::fmt;

use crate::error::{msg, Result};

/// ELF name stored as the bytes up to the terminating NUL.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ElfBytes {
    bytes: Vec<u8>,
}

impl ElfBytes {
    #[must_use]
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[must_use]
    pub fn contains(&self, needle: &str) -> bool {
        let needle = needle.as_bytes();
        needle.is_empty()
            || self
                .bytes
                .windows(needle.len())
                .any(|window| window == needle)
    }

    #[must_use]
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.bytes.starts_with(prefix.as_bytes())
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }

    pub(super) fn from_slice(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }
}

impl fmt::Debug for ElfBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "\"{}\"", self.bytes.escape_ascii())
    }
}

impl fmt::Display for ElfBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.bytes.escape_ascii())
    }
}

impl PartialEq<str> for ElfBytes {
    fn eq(&self, other: &str) -> bool {
        self.bytes == other.as_bytes()
    }
}

impl PartialEq<&str> for ElfBytes {
    fn eq(&self, other: &&str) -> bool {
        self.bytes == other.as_bytes()
    }
}

impl PartialEq<String> for ElfBytes {
    fn eq(&self, other: &String) -> bool {
        self.bytes == other.as_bytes()
    }
}

impl From<&str> for ElfBytes {
    fn from(value: &str) -> Self {
        Self::from_slice(value.as_bytes())
    }
}

pub(super) fn at<'a>(data: &'a [u8], off: u64, len: usize, what: &str) -> Result<&'a [u8]> {
    let start = usize::try_from(off).map_err(|_| msg(format!("{what} is outside the file")))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| msg(format!("{what} is outside the file")))?;
    data.get(start..end)
        .ok_or_else(|| msg(format!("{what} is outside the file")))
}

pub(super) fn u16(data: &[u8], off: usize) -> Result<u16> {
    let bytes = data.get(off..off + 2).ok_or_else(|| msg("elf truncated"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(super) fn u32_at(data: &[u8], off: usize) -> Result<u32> {
    let bytes = data.get(off..off + 4).ok_or_else(|| msg("elf truncated"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(super) fn u64_at(data: &[u8], off: usize) -> Result<u64> {
    let bytes = at(data, off as u64, 8, "elf field")?;
    Ok(le_u64(bytes))
}

pub(super) fn le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

pub(super) fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub(super) fn le_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(buf)
}

pub(super) fn le_i32(bytes: &[u8]) -> i32 {
    i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub(super) fn le_i64(bytes: &[u8]) -> i64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    i64::from_le_bytes(buf)
}

pub(super) fn cstr(bytes: &[u8], off: usize, what: &str) -> Result<ElfBytes> {
    if off >= bytes.len() {
        return Err(msg(format!("{what} is out of range")));
    }
    let tail = &bytes[off..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| msg(format!("{what} is not terminated")))?;
    if end > 1024 * 1024 {
        return Err(msg(format!("{what} is too long")));
    }
    Ok(ElfBytes::from_slice(&tail[..end]))
}

pub(super) fn table_len(off: u64, count: u64, entsize: u64, what: &str) -> Result<u64> {
    let bytes = count
        .checked_mul(entsize)
        .ok_or_else(|| msg(format!("{what} is too large")))?;
    off.checked_add(bytes)
        .ok_or_else(|| msg(format!("{what} is too large")))
}
