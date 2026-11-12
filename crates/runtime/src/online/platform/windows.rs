use std::fs::OpenOptions;
use std::io::Read;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, Prefix};

use zeroize::Zeroizing;

use super::ConfigurationBytes;
use crate::{online::CONFIG_MAX, Status};

const FILE_SHARE_READ: u32 = 1;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

pub(super) fn read(path: &Path) -> Result<ConfigurationBytes, Status> {
    if !path.is_absolute()
        || !matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)))
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(Status::InvalidArgument);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| Status::Unavailable)?;
    let metadata = file.metadata().map_err(|_| Status::Unavailable)?;
    if !metadata.is_file()
        || metadata.len() > CONFIG_MAX as u64
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(Status::InvalidArgument);
    }
    let mut bytes = Zeroizing::new(vec![0; metadata.len() as usize]);
    file.read_exact(&mut bytes)
        .map_err(|_| Status::Unavailable)?;
    Ok((bytes, None))
}
