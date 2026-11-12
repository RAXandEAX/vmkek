use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Component, Path};

use p256::ecdsa::SigningKey;
use zeroize::Zeroizing;

use super::ConfigurationBytes;
use crate::{online::CONFIG_MAX, Status};

const KEY: &CStr = c"device.key";

pub(super) fn read(path: &Path) -> Result<ConfigurationBytes, Status> {
    let (directory, name) = trusted_parent(path)?;
    if name.as_c_str() == KEY {
        return Err(Status::InvalidArgument);
    }
    let bytes = read_private(&directory, &name, CONFIG_MAX)?;
    if !bytes.starts_with(b"VMKR21\0\0") {
        return Err(Status::Incompatible);
    }
    let key = read_private(&directory, KEY, 32)?;
    if key.len() != 32 {
        return Err(Status::InvalidArgument);
    }
    let key = SigningKey::from_slice(&key).map_err(|_| Status::InvalidArgument)?;
    Ok((bytes, Some(key)))
}

fn trusted_parent(path: &Path) -> Result<(File, CString), Status> {
    let mut parts = path.components().peekable();
    if parts.next() != Some(Component::RootDir) {
        return Err(Status::InvalidArgument);
    }
    // SAFETY: geteuid reads the process credentials and accepts no arguments.
    let uid = unsafe { libc::geteuid() };
    let mut directory = open_at(libc::AT_FDCWD, c"/", libc::O_DIRECTORY)?;
    loop {
        check_directory(&directory, uid)?;
        let Some(Component::Normal(part)) = parts.next() else {
            return Err(Status::InvalidArgument);
        };
        let part = component(part)?;
        if parts.peek().is_none() {
            return Ok((directory, part));
        }
        directory = open_at(directory.as_raw_fd(), &part, libc::O_DIRECTORY)?;
    }
}

fn component(part: &OsStr) -> Result<CString, Status> {
    CString::new(part.as_bytes()).map_err(|_| Status::InvalidArgument)
}

fn check_directory(directory: &File, uid: u32) -> Result<(), Status> {
    let metadata = directory.metadata().map_err(|_| Status::Unavailable)?;
    if !metadata.is_dir()
        || metadata.uid() != 0 && metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(Status::InvalidArgument);
    }
    Ok(())
}

fn read_private(directory: &File, name: &CStr, limit: usize) -> Result<Zeroizing<Vec<u8>>, Status> {
    let file = open_at(directory.as_raw_fd(), name, 0)?;
    let metadata = file.metadata().map_err(|_| Status::Unavailable)?;
    // SAFETY: geteuid reads the process credentials and accepts no arguments.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > limit as u64
    {
        return Err(Status::InvalidArgument);
    }
    let mut bytes = Zeroizing::new(vec![0; metadata.len() as usize]);
    let mut file = file;
    file.read_exact(&mut bytes)
        .map_err(|_| Status::Unavailable)?;
    let mut extra = Zeroizing::new([0; 1]);
    if file.read(extra.as_mut()).map_err(|_| Status::Unavailable)? != 0 {
        return Err(Status::InvalidArgument);
    }
    Ok(bytes)
}

fn open_at(parent: libc::c_int, name: &CStr, flags: libc::c_int) -> Result<File, Status> {
    // SAFETY: name is NUL-terminated, parent is an open directory or AT_FDCWD,
    // and no creation flag is set, so openat requires no mode argument.
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | flags,
        )
    };
    if fd < 0 {
        return Err(Status::Unavailable);
    }
    // SAFETY: openat returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::{fs, io::Write};

    #[test]
    fn linux_key_requires_exact_owner_only_regular_storage_without_aliases() {
        let home = std::env::var_os("HOME").unwrap();
        let directory =
            Path::new(&home).join(format!(".vmkek-r21-key-test-{}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for name in ["config.bin", "device.key", "linked.key", "dir-link"] {
                    let _ = fs::remove_file(self.0.join(name));
                }
                let _ = fs::remove_dir(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let write = |name: &str, bytes: &[u8]| {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join(name))
                .unwrap()
                .write_all(bytes)
                .unwrap();
        };
        write("config.bin", b"VMKR21\0\0");
        let config = directory.join("config.bin");
        let key = directory.join("device.key");
        write("device.key", &[7]);
        assert!(matches!(read(&config), Err(Status::InvalidArgument)));
        fs::remove_file(&key).unwrap();
        write("device.key", &[0; 32]);
        assert!(matches!(read(&config), Err(Status::InvalidArgument)));
        fs::remove_file(&key).unwrap();
        write("device.key", &[7; 32]);
        assert!(read(&config).is_ok());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(read(&config), Err(Status::InvalidArgument)));
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let linked = directory.join("linked.key");
        fs::hard_link(&key, &linked).unwrap();
        assert!(matches!(read(&config), Err(Status::InvalidArgument)));
        fs::remove_file(&key).unwrap();
        symlink(&linked, &key).unwrap();
        assert!(read(&config).is_err());
        fs::remove_file(&key).unwrap();
        fs::rename(linked, key).unwrap();
        symlink(&directory, directory.join("dir-link")).unwrap();
        assert!(read(&directory.join("dir-link/config.bin")).is_err());
    }
}
