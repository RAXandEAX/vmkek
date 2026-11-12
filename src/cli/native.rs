//! Opt-in Linux launch policy for an executable installed by a trusted deployment.
//!
//! The supervisor supplies the digest and starts this launcher in a trusted
//! environment. The installed file and system loader configuration must be
//! protected from writes by untrusted principals, including during launch.
//! System preload configuration and installed libraries are part of that
//! boundary. A dynamically linked launcher itself must start with a clean
//! loader environment, because its linker runs before this policy.

use std::env;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::Command;

use crate::error::{msg, Result};

const O_NONBLOCK: i32 = 0o4000;

extern "C" {
    fn geteuid() -> u32;
}

pub(super) fn run(path: &Path, sha256: &str, args: &[String]) -> Result<i32> {
    check_loader_environment()?;
    let expected = decode_digest(sha256)?;
    let file = open_executable(path)?;
    // Use the opened inode for verification and execution even if the path is replaced.
    let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    verify_image(Path::new(&fd_path), expected)?;
    let status = Command::new(fd_path)
        .arg0(path)
        .args(args)
        .env_clear()
        .status()?;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
}

fn check_loader_environment() -> Result<()> {
    for name in ["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"] {
        if env::var_os(name).is_some_and(|value| !value.is_empty()) {
            return Err(msg(format!(
                "native launch rejected loader override {name}"
            )));
        }
    }
    Ok(())
}

fn decode_digest(text: &str) -> Result<[u8; 32]> {
    let mut expected = [0; 32];
    hex::decode_to_slice(text, &mut expected)
        .map_err(|_| msg("native launch requires a 64-digit hexadecimal SHA-256 digest"))?;
    Ok(expected)
}

fn open_executable(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid takes no arguments and returns the calling user's ID.
    let user = unsafe { geteuid() };
    if !metadata.is_file()
        || (metadata.uid() != 0 && metadata.uid() != user)
        || metadata.mode() & 0o6022 != 0
    {
        return Err(msg("native launch requires an administrator- or launcher-owned regular ELF without shared writes or set-ID bits"));
    }
    Ok(file)
}

fn verify_image(path: &Path, expected: [u8; 32]) -> Result<()> {
    let bytes = crate::protect::read_input(path)?;
    if crate::crypto::sha256(&bytes) != expected {
        return Err(msg("native launch rejected executable digest mismatch"));
    }
    let image = crate::elf::parse(&bytes)?;
    if image.kind != crate::elf::ElfKind::Executable || image.entry == 0 {
        return Err(msg(
            "native launch requires an ELF64 x86-64 executable with an entry point",
        ));
    }
    Ok(())
}
