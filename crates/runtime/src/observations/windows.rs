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
    time::{Duration, Instant},
};

use sha2::{Digest as _, Sha256};
use vmkek_protocol::{
    detection::{ImagePurpose, PolicyRevision, VerifiedPolicy, MAX_CODE_BYTES},
    session_observation::{
        ObservationFinding, ObservationKind, ObservationPlatform, ObservationReason,
        ObservationRecord, ObservationSample,
    },
    Digest, ProtocolError,
};

use super::{Observation, SampleWindow};

mod pe_scope;

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
const MAX_HEADER_BYTES: u32 = 64 * 1024;
const FULL_READ_BUDGET: Duration = Duration::from_millis(500);
const LIVE_READ_BUDGET: Duration = Duration::from_millis(100);
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
    sample_debugger().0
}

pub fn debugger_attachment_sample(
    window: SampleWindow,
) -> Result<ObservationSample, ProtocolError> {
    if !matches!(window.platform, ObservationPlatform::Windows { build: 1.. }) {
        return Err(ProtocolError::Binding);
    }
    let (outcome, reason) = sample_debugger();
    Ok(window.attachment(outcome, reason))
}

fn sample_debugger() -> (Observation, ObservationReason) {
    let mut corroborated = 0;
    let local = unsafe { IsDebuggerPresent() } != 0;
    let available =
        unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut corroborated) } != 0;
    if !available {
        (Observation::Inconclusive, ObservationReason::ApiFailure)
    } else if local != (corroborated != 0) {
        (
            Observation::Inconclusive,
            ObservationReason::SourcesDisagree,
        )
    } else if local {
        (Observation::Observed, ObservationReason::None)
    } else {
        (Observation::NotObservedWithinScope, ObservationReason::None)
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

struct ImageMeasurement {
    observation: ImageObservation,
    reason: ObservationReason,
    purpose: ImagePurpose,
}

impl ImageMeasurement {
    fn sample(self, window: SampleWindow) -> ObservationSample {
        use ObservationFinding as Finding;
        let (kind, finding) = match self.purpose {
            ImagePurpose::CodeIntegrity => (
                ObservationKind::CodeIntegrity,
                match self.observation.code {
                    CodeObservation::MatchesSignedBytes => Finding::NotObservedWithinScope,
                    CodeObservation::DiffersFromSignedBytes => Finding::SignedMismatch,
                    CodeObservation::Inconclusive => Finding::Inconclusive,
                    CodeObservation::Unsupported => Finding::Unsupported,
                },
            ),
            ImagePurpose::RegisteredInstrumentation => (
                ObservationKind::RegisteredProvider,
                match self.observation.instrumentation {
                    Observation::Observed => Finding::Observed,
                    Observation::NotObservedWithinScope => Finding::NotObservedWithinScope,
                    Observation::Inconclusive => Finding::Inconclusive,
                    Observation::Unsupported => Finding::Unsupported,
                },
            ),
        };
        let reason = match finding {
            Finding::SignedMismatch => ObservationReason::SignedMismatch,
            Finding::Observed | Finding::NotObservedWithinScope => ObservationReason::None,
            Finding::Inconclusive if self.reason == ObservationReason::None => {
                ObservationReason::InvalidData
            }
            _ => self.reason,
        };
        window.sample(
            ObservationRecord {
                kind,
                rule_id: self.observation.rule_id,
                finding,
            },
            reason,
        )
    }
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
        self.prepare_integrity(policy, now_ms)?
            .observe(policy, now_ms)
            .map(|(rows, _)| rows)
    }

    pub fn observe_samples(
        &self,
        policy: &VerifiedPolicy<'_>,
        now_ms: u64,
        window: SampleWindow,
    ) -> Result<Vec<ObservationSample>, ProtocolError> {
        window.check_policy(policy)?;
        self.prepare_integrity(policy, now_ms)?
            .observe_samples(policy, now_ms, window)
            .map(|(rows, _)| rows)
    }

    /// Hash and validate the loader-path file once for an exact signed policy.
    /// The launcher must coordinate replacement with module unload/reload.
    /// A prepared pass keeps the module reference and file handle live.
    pub fn prepare_integrity(
        &self,
        policy: &VerifiedPolicy<'_>,
        now_ms: u64,
    ) -> Result<PreparedIntegrity<'_>, ProtocolError> {
        policy.check_time(now_ms)?;
        let mut stats = IntegrityReadStats::default();
        let image = match native_windows_build() {
            Ok(build) if build == policy.windows_build() => self.prepare_image(policy, &mut stats),
            Ok(_) => return Err(ProtocolError::Binding),
            Err(error) => Err(if error.kind() == io::ErrorKind::Unsupported {
                ObservationReason::PlatformUnsupported
            } else {
                ObservationReason::ApiFailure
            }),
        };
        Ok(PreparedIntegrity {
            module: self,
            revision: policy.revision(),
            build: policy.windows_build(),
            image,
            stats,
        })
    }

    fn prepare_image(
        &self,
        policy: &VerifiedPolicy<'_>,
        stats: &mut IntegrityReadStats,
    ) -> Result<PreparedImage, ObservationReason> {
        let deadline = Instant::now() + FULL_READ_BUDGET;
        let mut file = self.path().and_then(open_image).map_err(read_reason)?;
        let digest = hash_file(&file, deadline, &mut stats.file_bytes).map_err(read_reason)?;
        let layout = if policy
            .image_rules()
            .iter()
            .any(|rule| rule.file_digest == digest)
        {
            pe_scope::validate(&mut file, stats.file_bytes, policy.image_rules(), deadline)
                .and_then(|(layout, bytes)| {
                    stats.layout_bytes = bytes;
                    let mut header = [0u8; CHUNK_BYTES];
                    let mut remaining = layout.header_size;
                    let mut preferred = [0; 8];
                    let mut hash = Sha256::new();
                    use io::{Seek, SeekFrom};
                    file.seek(SeekFrom::Start(0))?;
                    while remaining != 0 {
                        within_deadline(deadline)?;
                        let count = remaining.min(CHUNK_BYTES);
                        file.read_exact(&mut header[..count])?;
                        stats.layout_bytes += count as u64;
                        normalize_base(
                            &mut header[..count],
                            layout.header_size - remaining,
                            layout.image_base_offset,
                            &mut preferred,
                        );
                        hash.update(&header[..count]);
                        remaining -= count;
                    }
                    within_deadline(deadline)?;
                    Ok((layout, Digest::from(hash.finalize())))
                })
                .map_err(read_reason)
        } else {
            Err(ObservationReason::OutsideScope)
        };
        Ok(PreparedImage {
            _file: file,
            digest,
            layout,
        })
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

/// Bytes successfully read during a full file pass or an incremental memory pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IntegrityReadStats {
    pub file_bytes: u64,
    pub layout_bytes: u64,
    pub memory_bytes: u64,
}

struct PreparedImage {
    _file: File,
    digest: Digest,
    layout: Result<(pe_scope::Layout, Digest), ObservationReason>,
}

pub struct PreparedIntegrity<'a> {
    module: &'a OwnedModule,
    revision: PolicyRevision,
    build: u32,
    image: Result<PreparedImage, ObservationReason>,
    stats: IntegrityReadStats,
}

impl PreparedIntegrity<'_> {
    pub fn preparation_reads(&self) -> IntegrityReadStats {
        self.stats
    }

    pub(crate) fn retryable(&self) -> bool {
        match &self.image {
            Err(ObservationReason::ReadFailure | ObservationReason::ApiFailure) => true,
            Ok(image) => matches!(image.layout, Err(ObservationReason::ReadFailure)),
            _ => false,
        }
    }

    pub fn preferred_base(&self) -> Option<u64> {
        self.image
            .as_ref()
            .ok()?
            .layout
            .as_ref()
            .ok()
            .map(|(layout, _)| layout.preferred_base)
    }

    pub fn observe(
        &self,
        policy: &VerifiedPolicy<'_>,
        now_ms: u64,
    ) -> Result<(Vec<ImageObservation>, IntegrityReadStats), ProtocolError> {
        self.measure(policy, now_ms).map(|(measurements, stats)| {
            (
                measurements
                    .into_iter()
                    .map(|item| item.observation)
                    .collect(),
                stats,
            )
        })
    }

    /// Sample using the already held file and the exact prepared policy.
    pub fn observe_samples(
        &self,
        policy: &VerifiedPolicy<'_>,
        now_ms: u64,
        window: SampleWindow,
    ) -> Result<(Vec<ObservationSample>, IntegrityReadStats), ProtocolError> {
        window.check_policy(policy)?;
        self.measure(policy, now_ms).map(|(rows, stats)| {
            (
                rows.into_iter().map(|row| row.sample(window)).collect(),
                stats,
            )
        })
    }

    fn measure(
        &self,
        policy: &VerifiedPolicy<'_>,
        now_ms: u64,
    ) -> Result<(Vec<ImageMeasurement>, IntegrityReadStats), ProtocolError> {
        policy.check_time(now_ms)?;
        if self.build != policy.windows_build() || self.revision != policy.revision() {
            return Err(ProtocolError::Binding);
        }
        let deadline = Instant::now() + LIVE_READ_BUDGET;
        let mut stats = IntegrityReadStats::default();
        let measured = self
            .image
            .as_ref()
            .ok()
            .and_then(|image| image.layout.as_ref().ok());
        let bounds = self.module.bounds();
        let header_matches = |bytes: &mut u64| {
            measured
                .zip(bounds)
                .is_some_and(|((layout, expected), bounds)| {
                    layout.image_size as usize == bounds.size
                        && hash_memory(
                            bounds,
                            0,
                            layout.header_size,
                            PageScope::Headers {
                                image_base_offset: layout.image_base_offset,
                                preferred_base: layout.preferred_base,
                            },
                            deadline,
                            bytes,
                        )
                        .as_ref()
                            == Some(expected)
                })
        };
        let identity = header_matches(&mut stats.memory_bytes);
        let mut rows: Vec<_> = policy
            .image_rules()
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                let (file, code, reason) = match &self.image {
                    Err(ObservationReason::PlatformUnsupported) => (
                        Observation::Unsupported,
                        CodeObservation::Unsupported,
                        ObservationReason::PlatformUnsupported,
                    ),
                    Err(reason) => (
                        Observation::Inconclusive,
                        CodeObservation::Inconclusive,
                        *reason,
                    ),
                    Ok(image) if image.digest != rule.file_digest => (
                        Observation::NotObservedWithinScope,
                        CodeObservation::Unsupported,
                        ObservationReason::OutsideScope,
                    ),
                    Ok(image) => {
                        let (code, reason) = match &image.layout {
                            Err(reason) => (CodeObservation::Inconclusive, *reason),
                            Ok(_) if bounds.is_none() => {
                                (CodeObservation::Inconclusive, ObservationReason::ApiFailure)
                            }
                            Ok(_) if !identity => (
                                CodeObservation::Inconclusive,
                                ObservationReason::ReadFailure,
                            ),
                            Ok((layout, _)) if !layout.allowed[index] => (
                                CodeObservation::Inconclusive,
                                ObservationReason::InvalidData,
                            ),
                            Ok(_) => {
                                let code = compare_code(
                                    bounds.unwrap(),
                                    rule.code_rva,
                                    rule.code_len,
                                    &rule.code_digest,
                                    deadline,
                                    &mut stats.memory_bytes,
                                );
                                let reason = if code == CodeObservation::Inconclusive {
                                    ObservationReason::ReadFailure
                                } else {
                                    ObservationReason::None
                                };
                                (code, reason)
                            }
                        };
                        (Observation::Observed, code, reason)
                    }
                };
                let instrumentation = match (rule.purpose, file, code) {
                    (ImagePurpose::CodeIntegrity, _, _) => Observation::Unsupported,
                    (_, Observation::NotObservedWithinScope, _) => file,
                    (_, _, CodeObservation::MatchesSignedBytes) => Observation::Observed,
                    _ => Observation::Inconclusive,
                };
                ImageMeasurement {
                    observation: ImageObservation {
                        rule_id: rule.id,
                        file,
                        code,
                        instrumentation,
                    },
                    reason,
                    purpose: rule.purpose,
                }
            })
            .collect();
        if identity && !header_matches(&mut stats.memory_bytes) {
            for row in &mut rows {
                if matches!(
                    row.observation.code,
                    CodeObservation::MatchesSignedBytes | CodeObservation::DiffersFromSignedBytes
                ) {
                    row.observation.code = CodeObservation::Inconclusive;
                    if row.purpose == ImagePurpose::RegisteredInstrumentation {
                        row.observation.instrumentation = Observation::Inconclusive;
                    }
                    row.reason = ObservationReason::ReadFailure;
                }
            }
        }
        Ok((rows, stats))
    }
}

fn read_reason(error: io::Error) -> ObservationReason {
    if error.kind() == io::ErrorKind::InvalidData {
        ObservationReason::InvalidData
    } else {
        ObservationReason::ReadFailure
    }
}

fn within_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "integrity pass deadline",
        ))
    } else {
        Ok(())
    }
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

fn hash_file(mut file: &File, deadline: Instant, bytes: &mut u64) -> io::Result<Digest> {
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
        within_deadline(deadline)?;
        let count = remaining.min(CHUNK_BYTES as u64) as usize;
        file.read_exact(&mut scratch[..count])?;
        hash.update(&scratch[..count]);
        *bytes += count as u64;
        remaining -= count as u64;
    }
    within_deadline(deadline)?;
    Ok(hash.finalize().into())
}

#[derive(Clone, Copy)]
struct ImageBounds {
    base: usize,
    size: usize,
}

fn compare_code(
    bounds: ImageBounds,
    rva: u32,
    len: u32,
    expected: &Digest,
    deadline: Instant,
    bytes: &mut u64,
) -> CodeObservation {
    if !(1..=MAX_CODE_BYTES).contains(&len) {
        return CodeObservation::Inconclusive;
    }
    let mut read = || {
        hash_memory(
            bounds,
            rva as usize,
            len as usize,
            PageScope::Code,
            deadline,
            bytes,
        )
    };
    classify_snapshots(&mut read, expected)
}

fn classify_snapshots(
    read: &mut impl FnMut() -> Option<Digest>,
    expected: &Digest,
) -> CodeObservation {
    match read() {
        Some(first) if read() == Some(first) => {
            if &first == expected {
                CodeObservation::MatchesSignedBytes
            } else {
                CodeObservation::DiffersFromSignedBytes
            }
        }
        _ => CodeObservation::Inconclusive,
    }
}

#[derive(Clone, Copy)]
enum PageScope {
    Headers {
        image_base_offset: usize,
        preferred_base: u64,
    },
    Code,
}

fn hash_memory(
    bounds: ImageBounds,
    rva: usize,
    len: usize,
    scope: PageScope,
    deadline: Instant,
    bytes: &mut u64,
) -> Option<Digest> {
    let end = rva.checked_add(len)?;
    if len == 0 || end > bounds.size {
        return None;
    }
    let mut address = bounds.base.checked_add(rva)?;
    let end = bounds.base.checked_add(end)?;
    let mut hash = Sha256::new();
    let mut scratch = [0; CHUNK_BYTES];
    let mut image_base = [0; 8];
    while address < end {
        within_deadline(deadline).ok()?;
        let region_end = readable_image_end(bounds.base, address, scope)?;
        let count = (region_end.min(end) - address).min(scratch.len());
        let mut read = 0;
        // SAFETY: The output buffer holds count bytes and read is a live
        // out-parameter. Windows handles inaccessible own-process addresses.
        let ok = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                address as *const c_void,
                scratch.as_mut_ptr().cast(),
                count,
                &mut read,
            )
        };
        *bytes += read.min(count) as u64;
        if ok == 0
            || read != count
            || readable_image_end(bounds.base, address, scope)? != region_end
        {
            return None;
        }
        if let PageScope::Headers {
            image_base_offset, ..
        } = scope
        {
            normalize_base(
                &mut scratch[..count],
                address - bounds.base,
                image_base_offset,
                &mut image_base,
            );
        }
        hash.update(&scratch[..count]);
        address += count;
    }
    if let PageScope::Headers { preferred_base, .. } = scope {
        let observed = u64::from_le_bytes(image_base);
        if observed != preferred_base && observed != bounds.base as u64 {
            return None;
        }
    }
    within_deadline(deadline).ok()?;
    Some(hash.finalize().into())
}

fn normalize_base(bytes: &mut [u8], offset: usize, image_base_offset: usize, value: &mut [u8; 8]) {
    // Windows can rewrite the optional header's ImageBase when rebasing a
    // DLL. All other mapped header bytes must match the held file exactly.
    let start = offset.max(image_base_offset);
    let end = (offset + bytes.len()).min(image_base_offset + value.len());
    if start < end {
        let field = &mut bytes[start - offset..end - offset];
        value[start - image_base_offset..end - image_base_offset].copy_from_slice(field);
        field.fill(0);
    }
}

fn readable_image_end(base: usize, address: usize, scope: PageScope) -> Option<usize> {
    let mut info = MaybeUninit::<MemoryInfo>::uninit();
    let size = size_of::<MemoryInfo>();
    // SAFETY: Windows accepts the address as a query value and the output is writable.
    if unsafe { VirtualQuery(address as *const c_void, info.as_mut_ptr(), size) } != size {
        return None;
    }
    // SAFETY: VirtualQuery returned the full size of the output structure.
    let info = unsafe { info.assume_init() };
    let permitted = match scope {
        PageScope::Code => info.protect == PAGE_EXECUTE_READ,
        PageScope::Headers { .. } => matches!(info.protect, 0x02 | PAGE_EXECUTE_READ),
    };
    if info.allocation_base as usize != base
        || info.state != MEM_COMMIT
        || info.kind != MEM_IMAGE
        || !permitted
    {
        return None;
    }
    let start = info.base as usize;
    let end = start.checked_add(info.size)?;
    (start..end).contains(&address).then_some(end)
}

#[cfg(test)]
mod integrity_tests {
    use super::*;

    #[repr(align(4096))]
    struct FixturePage([u8; 4096]);

    #[link_section = ".text$zzA04"]
    static FIXTURE_PAGE: FixturePage = FixturePage([0x3c; 4096]);

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualProtect(base: Handle, size: usize, protect: u32, old: *mut u32) -> i32;
    }

    #[test]
    fn native_page_loss_between_reads_is_inconclusive() {
        let address = std::hint::black_box(FIXTURE_PAGE.0.as_ptr());
        let owned = OwnedModule::from_address(address as usize).unwrap();
        let bounds = owned.bounds().unwrap();
        let rva = address as usize - bounds.base;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut bytes = 0;
        let mut old = 0;
        let mut calls = 0;
        let mut read = || {
            calls += 1;
            if calls == 2 {
                // SAFETY: This page-aligned static has its own full image page.
                assert_ne!(
                    unsafe { VirtualProtect(address.cast_mut().cast(), 4096, 1, &mut old) },
                    0
                );
            }
            hash_memory(bounds, rva, 16, PageScope::Code, deadline, &mut bytes)
        };
        let expected = Sha256::digest([0x3c; 16]).into();
        let result = classify_snapshots(&mut read, &expected);
        if calls == 2 {
            let mut ignored = 0;
            // SAFETY: Restore the original protection on the same held fixture page.
            assert_ne!(
                unsafe { VirtualProtect(address.cast_mut().cast(), 4096, old, &mut ignored) },
                0
            );
        }
        assert_eq!(calls, 2);
        assert_eq!(old, PAGE_EXECUTE_READ);
        assert_eq!(bytes, 16);
        assert_eq!(result, CodeObservation::Inconclusive);
    }

    #[test]
    fn changing_or_partial_snapshots_are_inconclusive() {
        for snapshots in [[Some([1; 32]), Some([2; 32])], [Some([1; 32]), None]] {
            let mut reads = snapshots.into_iter();
            assert_eq!(
                classify_snapshots(&mut || reads.next().unwrap(), &[1; 32]),
                CodeObservation::Inconclusive
            );
        }
    }
}
