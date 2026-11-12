use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io::{self, Read},
    mem::{size_of, MaybeUninit},
    os::windows::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, PathBuf, Prefix},
    ptr,
};

use sha2::{Digest as _, Sha256};
use vmkek_protocol::{
    detection::{ImagePurpose, VerifiedPolicy},
    Digest, ProtocolError,
};

use super::Observation;

const AMD64: u16 = 0x8664;
const MODULE_FROM_ADDRESS: u32 = 4;
const FILE_SHARE_READ: u32 = 1;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const MEM_COMMIT: u32 = 0x1000;
const MEM_IMAGE: u32 = 0x1000000;
const PAGE_EXECUTE_READ: u32 = 0x20;
const MAX_IMAGE_BYTES: u64 = 128 * 1024 * 1024;
const CHUNK_BYTES: usize = 4096;
type Handle = *mut c_void;

#[repr(C)]
struct ModuleInfo {
    base: *mut c_void,
    size: u32,
    entry: *mut c_void,
}

#[repr(C)]
struct MemoryInfo {
    base: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: u32,
    partition_id: u16,
    size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}

#[repr(C)]
struct VersionInfo {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    service_pack: [u16; 128],
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn IsDebuggerPresent() -> i32;
    fn CheckRemoteDebuggerPresent(process: Handle, present: *mut i32) -> i32;
    fn IsWow64Process2(process: Handle, process_machine: *mut u16, native_machine: *mut u16)
        -> i32;
    fn GetModuleHandleExW(flags: u32, address: *const u16, out: *mut Handle) -> i32;
    fn FreeLibrary(module: Handle) -> i32;
    fn GetModuleFileNameW(module: Handle, out: *mut u16, size: u32) -> u32;
    fn K32GetModuleInformation(
        process: Handle,
        module: Handle,
        out: *mut ModuleInfo,
        size: u32,
    ) -> i32;
    fn VirtualQuery(address: *const c_void, out: *mut MemoryInfo, size: usize) -> usize;
    fn ReadProcessMemory(
        process: Handle,
        address: *const c_void,
        out: *mut c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;
}

#[link(name = "ntdll")]
extern "system" {
    fn RtlGetVersion(out: *mut VersionInfo) -> i32;
}

/// Returns the native x64 Windows build used to bind a verified policy.
pub fn native_windows_build() -> io::Result<u32> {
    let (mut process, mut native) = (0, 0);
    if unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if process != 0 || native != AMD64 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native x64 Windows required",
        ));
    }
    let mut info = VersionInfo {
        size: size_of::<VersionInfo>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        service_pack: [0; 128],
    };
    if unsafe { RtlGetVersion(&mut info) } < 0 || info.build == 0 {
        return Err(io::Error::other("Windows version unavailable"));
    }
    Ok(info.build)
}

/// Samples documented debugger attachment state for the current process.
pub fn debugger_attachment() -> Observation {
    let mut corroborated = 0;
    let local = unsafe { IsDebuggerPresent() } != 0;
    let available =
        unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut corroborated) } != 0;
    if !available || local != (corroborated != 0) {
        Observation::Inconclusive
    } else if local {
        Observation::Observed
    } else {
        Observation::NotObservedWithinScope
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeObservation {
    MatchesSignedBytes,
    DiffersFromSignedBytes,
    Inconclusive,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageObservation {
    pub rule_id: u16,
    pub file: Observation,
    pub code: CodeObservation,
    pub instrumentation: Observation,
}

/// A held module of the current process. The launcher supplies an address of a
/// known static or routine and trusts the module's installation and load path.
pub struct OwnedModule(Handle);

impl Drop for OwnedModule {
    fn drop(&mut self) {
        // A successful acquisition holds one normal loader reference.
        unsafe { FreeLibrary(self.0) };
    }
}

impl OwnedModule {
    pub fn from_address(address: usize) -> io::Result<Self> {
        let mut module = ptr::null_mut();
        if unsafe { GetModuleHandleExW(MODULE_FROM_ADDRESS, address as *const u16, &mut module) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(module))
    }

    /// Observes only policy-listed exact files and bounded code ranges. Build
    /// tooling must select relocation-free immutable RX ranges. An expected
    /// file digest applies to the held file at the loader-reported path.
    pub fn observe(
        &self,
        policy: &VerifiedPolicy<'_>,
        now_ms: u64,
    ) -> Result<Vec<ImageObservation>, ProtocolError> {
        policy.check_time(now_ms)?;
        match native_windows_build() {
            Ok(build) if build == policy.windows_build() => {}
            Ok(_) => return Err(ProtocolError::Binding),
            Err(error) => return Ok(unavailable_image_observations(policy, &error)),
        }
        let image = self.path().and_then(open_image);
        let digest = image.as_ref().ok().and_then(|file| hash_file(file).ok());
        let bounds = self.bounds();
        Ok(policy
            .image_rules()
            .iter()
            .map(|rule| {
                let (file, code) = match digest {
                    None => (Observation::Inconclusive, CodeObservation::Inconclusive),
                    Some(value) if value != rule.file_digest => (
                        Observation::NotObservedWithinScope,
                        CodeObservation::Unsupported,
                    ),
                    Some(_) => (
                        Observation::Observed,
                        compare_code(bounds, rule.code_rva, rule.code_len, &rule.code_digest),
                    ),
                };
                let instrumentation = match (rule.purpose, file, code) {
                    (ImagePurpose::CodeIntegrity, _, _) => Observation::Unsupported,
                    (_, Observation::NotObservedWithinScope, _) => file,
                    (_, _, CodeObservation::MatchesSignedBytes) => Observation::Observed,
                    _ => Observation::Inconclusive,
                };
                ImageObservation {
                    rule_id: rule.id,
                    file,
                    code,
                    instrumentation,
                }
            })
            .collect())
    }

    fn path(&self) -> io::Result<PathBuf> {
        let mut path = vec![0; 32768];
        let count = unsafe { GetModuleFileNameW(self.0, path.as_mut_ptr(), path.len() as u32) };
        if count == 0 || count as usize == path.len() {
            return Err(io::Error::last_os_error());
        }
        Ok(std::ffi::OsString::from_wide(&path[..count as usize]).into())
    }

    fn bounds(&self) -> Option<ImageBounds> {
        let mut info = MaybeUninit::<ModuleInfo>::uninit();
        let size = size_of::<ModuleInfo>() as u32;
        if unsafe { K32GetModuleInformation(GetCurrentProcess(), self.0, info.as_mut_ptr(), size) }
            == 0
        {
            return None;
        }
        let info = unsafe { info.assume_init() };
        Some(ImageBounds {
            base: info.base as usize,
            size: info.size as usize,
        })
    }
}

fn unavailable_image_observations(
    policy: &VerifiedPolicy<'_>,
    error: &io::Error,
) -> Vec<ImageObservation> {
    let (file, code) = if error.kind() == io::ErrorKind::Unsupported {
        (Observation::Unsupported, CodeObservation::Unsupported)
    } else {
        (Observation::Inconclusive, CodeObservation::Inconclusive)
    };
    policy
        .image_rules()
        .iter()
        .map(|rule| ImageObservation {
            rule_id: rule.id,
            file,
            code,
            instrumentation: file,
        })
        .collect()
}

fn open_image(path: PathBuf) -> io::Result<File> {
    if !path.is_absolute()
        || !matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ordinary drive path required",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "image reparse point",
        ));
    }
    Ok(file)
}

fn hash_file(mut file: &File) -> io::Result<Digest> {
    let size = file.metadata()?.len();
    if !(1..=MAX_IMAGE_BYTES).contains(&size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "image size outside scope",
        ));
    }
    let mut hash = Sha256::new();
    let mut scratch = [0; CHUNK_BYTES];
    let mut remaining = size;
    while remaining != 0 {
        let count = remaining.min(CHUNK_BYTES as u64) as usize;
        file.read_exact(&mut scratch[..count])?;
        hash.update(&scratch[..count]);
        remaining -= count as u64;
    }
    Ok(hash.finalize().into())
}

#[derive(Clone, Copy)]
struct ImageBounds {
    base: usize,
    size: usize,
}

fn compare_code(
    bounds: Option<ImageBounds>,
    rva: u32,
    len: u32,
    expected: &Digest,
) -> CodeObservation {
    let Some(bounds) = bounds else {
        return CodeObservation::Inconclusive;
    };
    let Some(first) = hash_code(bounds, rva as usize, len as usize) else {
        return CodeObservation::Inconclusive;
    };
    if hash_code(bounds, rva as usize, len as usize) != Some(first) {
        return CodeObservation::Inconclusive;
    }
    if &first == expected {
        CodeObservation::MatchesSignedBytes
    } else {
        CodeObservation::DiffersFromSignedBytes
    }
}

fn hash_code(bounds: ImageBounds, rva: usize, len: usize) -> Option<Digest> {
    let end = rva.checked_add(len)?;
    if end > bounds.size {
        return None;
    }
    let mut address = bounds.base.checked_add(rva)?;
    let end = bounds.base.checked_add(end)?;
    let mut hash = Sha256::new();
    let mut scratch = [0; CHUNK_BYTES];
    while address < end {
        let next = readable_code_end(bounds.base, address)?.min(end);
        let count = (next - address).min(scratch.len());
        let mut read = 0;
        let ok = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                address as *const c_void,
                scratch.as_mut_ptr().cast(),
                count,
                &mut read,
            )
        };
        if ok == 0 || read != count {
            return None;
        }
        hash.update(&scratch[..count]);
        address += count;
    }
    Some(hash.finalize().into())
}

fn readable_code_end(base: usize, address: usize) -> Option<usize> {
    let mut info = MaybeUninit::<MemoryInfo>::uninit();
    let size = size_of::<MemoryInfo>();
    if unsafe { VirtualQuery(address as *const c_void, info.as_mut_ptr(), size) } != size {
        return None;
    }
    let info = unsafe { info.assume_init() };
    if info.allocation_base as usize != base
        || info.state != MEM_COMMIT
        || info.kind != MEM_IMAGE
        || info.protect != PAGE_EXECUTE_READ
    {
        return None;
    }
    let start = info.base as usize;
    let end = start.checked_add(info.size)?;
    (start..end).contains(&address).then_some(end)
}
