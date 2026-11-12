use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Args;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::zeroize::Zeroizing;

use crate::crypto::authenticated::{
    BOOTSTRAP_MAGIC, ELF_LAB_ENTRY_AFTER_MANIFEST, ELF_LAB_HELPER_VA,
};
use crate::error::{msg, Result};
use crate::protect::{self, NativeAuthentication, Options, Protected};

#[derive(Args)]
pub(super) struct NativeAuthArgs {
    /// Authenticate native PE or ELF startup with separately provisioned keys (lab).
    #[arg(
        long,
        requires_all = [
            "manufacturer_signing_key",
            "manufacturer_public_key",
            "application_id"
        ],
        conflicts_with_all = ["random_key", "deterministic"]
    )]
    pub(super) authenticated_lab: bool,
    /// Trusted verifier built by tools/elf-auth-helper/build.sh for ELF64 lab input.
    #[arg(
        long,
        requires = "authenticated_lab",
        conflicts_with = "windows_native",
        value_name = "FILE"
    )]
    elf_auth_helper: Option<PathBuf>,
    /// Path to a file containing the raw 32-byte P-256 signing scalar.
    #[arg(long, requires = "authenticated_lab", value_name = "FILE")]
    manufacturer_signing_key: Option<PathBuf>,
    /// Path to a separate file containing the 65-byte uncompressed SEC1 public point.
    #[arg(long, requires = "authenticated_lab", value_name = "FILE")]
    manufacturer_public_key: Option<PathBuf>,
    /// A 16-byte application identifier encoded as 32 hexadecimal digits.
    #[arg(long, requires = "authenticated_lab", value_name = "HEX")]
    application_id: Option<String>,
}

impl NativeAuthArgs {
    pub(super) fn protect(
        &self,
        bytes: &[u8],
        options: &Options,
        windows_native: bool,
    ) -> Result<Protected> {
        if !windows_native && self.elf_auth_helper.is_none() {
            return Err(msg(
                "authenticated lab requires --windows-native or --elf-auth-helper",
            ));
        }
        let signing_path = self
            .manufacturer_signing_key
            .as_deref()
            .ok_or_else(|| msg("manufacturer signing key is required"))?;
        let public_path = self
            .manufacturer_public_key
            .as_deref()
            .ok_or_else(|| msg("manufacturer public key is required"))?;
        let application = self
            .application_id
            .as_deref()
            .ok_or_else(|| msg("application ID is required"))?;
        let mut application_id = [0; 16];
        hex::decode_to_slice(application, &mut application_id)
            .map_err(|_| msg("application ID must be 32 hexadecimal digits"))?;
        let trusted_public = read_key(
            public_path,
            "manufacturer public key must be a 65-byte SEC1 point file",
        )?;
        let scalar = read_key::<32>(
            signing_path,
            "manufacturer signing key must be a 32-byte raw P-256 scalar file",
        )?;
        let signing_key = SigningKey::from_slice(scalar.as_ref())
            .map_err(|_| msg("invalid manufacturer P-256 signing scalar"))?;
        drop(scalar);
        let authentication = NativeAuthentication {
            signing_key: &signing_key,
            trusted_public: &trusted_public,
            application_id,
        };
        if let Some(path) = &self.elf_auth_helper {
            let helper = read_elf_helper(path)?;
            protect::protect_elf_authenticated(bytes, options, &authentication, &helper)
        } else {
            protect::protect_windows_native_authenticated(bytes, options, &authentication)
        }
    }
}

fn read_elf_helper(path: &Path) -> Result<Vec<u8>> {
    const MAX_LEN: u64 = 128 * 1024;
    let invalid = "trusted ELF verifier must be a regular file within 128 KiB";
    if !path.metadata()?.is_file() {
        return Err(msg(invalid));
    }
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_LEN {
        return Err(msg(invalid));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_LEN + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LEN {
        return Err(msg(invalid));
    }
    Ok(bytes)
}

fn read_key<const N: usize>(path: &Path, invalid: &str) -> Result<Zeroizing<[u8; N]>> {
    if !path.metadata()?.is_file() {
        return Err(msg(invalid));
    }
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != N as u64 {
        return Err(msg(invalid));
    }
    let mut bytes = Zeroizing::new([0; N]);
    file.read_exact(bytes.as_mut())?;
    if file.read(&mut [0])? != 0 {
        return Err(msg(invalid));
    }
    Ok(bytes)
}

pub(super) fn reject_for_legacy_reader(file: &[u8]) -> Result<()> {
    if has_pe_bootstrap(file) {
        return Err(msg("authenticated bootstrap requires the native PE lab loader; legacy inspect and run are unavailable"));
    }
    if has_elf_bootstrap(file) {
        return Err(msg("authenticated bootstrap requires the native ELF lab loader; legacy inspect and run are unavailable"));
    }
    Ok(())
}

fn has_pe_bootstrap(file: &[u8]) -> bool {
    let Ok(image) = crate::pe::parse(file) else {
        return false;
    };
    let Some(header) = image
        .entry_rva
        .checked_sub(crate::crypto::HEADER_LEN as u32)
    else {
        return false;
    };
    crate::pe::read_rva(&image, header, BOOTSTRAP_MAGIC.len())
        .is_ok_and(|magic| magic == BOOTSTRAP_MAGIC)
}

fn has_elf_bootstrap(file: &[u8]) -> bool {
    let Ok(image) = crate::elf::parse(file) else {
        return false;
    };
    let Some(load) = image.segments.iter().find(|item| {
        item.kind == crate::elf::SegmentKind::Load
            && item.vaddr == ELF_LAB_HELPER_VA
            && item.flags == 5
    }) else {
        return false;
    };
    let Some(offset) = image.entry.checked_sub(load.vaddr) else {
        return false;
    };
    if offset >= load.filesz {
        return false;
    }
    let Some(at) = offset
        .checked_sub(ELF_LAB_ENTRY_AFTER_MANIFEST as u64)
        .and_then(|offset| offset.checked_add(load.offset))
        .and_then(|offset| usize::try_from(offset).ok())
    else {
        return false;
    };
    file.get(at..at.saturating_add(BOOTSTRAP_MAGIC.len())) == Some(BOOTSTRAP_MAGIC)
}
