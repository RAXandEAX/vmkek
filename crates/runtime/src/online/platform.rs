use std::path::Path;

use p256::ecdsa::SigningKey;
use zeroize::Zeroizing;

use crate::Status;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux;
#[cfg(windows)]
mod windows;

pub(super) type ConfigurationBytes = (Zeroizing<Vec<u8>>, Option<SigningKey>);

pub(super) fn read(path: &Path) -> Result<ConfigurationBytes, Status> {
    #[cfg(windows)]
    return windows::read(path);

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    linux::read(path)
}
