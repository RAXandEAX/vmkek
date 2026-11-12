//! Signed, file-backed RX ranges of the current ELF executable.
use std::{
    fs::{File, Metadata},
    io::Read,
    os::unix::fs::{FileExt, MetadataExt},
    time::Duration,
};

use sha2::{Digest as _, Sha256};
use vmkek_protocol::{
    detection::{ImagePurpose, ImageRule, PolicyRevision, VerifiedPolicy},
    session_observation::{
        ObservationFinding as Finding, ObservationKind, ObservationReason as Reason,
        ObservationRecord, ObservationSample,
    },
    Digest, ProtocolError,
};

use super::{boottime, proc_file, SampleWindow};

const FILE_MAX: u64 = 128 * 1024 * 1024;
const MAPS_MAX: usize = 256 * 1024;
const PROGRAMS_MAX: usize = 128;
const DYNAMIC_MAX: u64 = 64 * 1024;
const COLD_MAX: Duration = Duration::from_millis(500);
const HOT_MAX: Duration = Duration::from_millis(100);

#[derive(Default)]
pub struct IntegrityMetrics {
    pub file_bytes: u64,
    pub memory_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    dev: u64,
    inode: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl From<Metadata> for FileIdentity {
    fn from(meta: Metadata) -> Self {
        Self {
            dev: meta.dev(),
            inode: meta.ino(),
            size: meta.len(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

#[derive(Clone, Copy)]
struct Load {
    flags: u32,
    offset: u64,
    vaddr: u64,
    file_len: u64,
    memory_len: u64,
}

#[derive(Clone, Copy)]
struct BoundRange {
    offset: u64,
    address: u64,
    length: u32,
}

#[derive(Clone, Copy)]
enum Range {
    Eligible(BoundRange),
    OutsideScope,
}

pub struct PreparedElfIntegrity {
    file: File,
    identity: FileIdentity,
    revision: PolicyRevision,
    ranges: Vec<(ImageRule, Range)>,
}

impl PreparedElfIntegrity {
    pub fn prepare(
        policy: &VerifiedPolicy<'_>,
        now_ms: u64,
    ) -> Result<(Self, IntegrityMetrics), ProtocolError> {
        policy.check_time(now_ms)?;
        if !matches!(
            policy.platform(),
            vmkek_protocol::session_observation::ObservationPlatform::Linux { .. }
        ) {
            return Err(ProtocolError::Binding);
        }
        let deadline = deadline(COLD_MAX)?;
        let mut file = File::open("/proc/self/exe").map_err(|_| ProtocolError::Invalid)?;
        let meta = file.metadata().map_err(|_| ProtocolError::Invalid)?;
        if !meta.is_file() || meta.len() < 64 || meta.len() > FILE_MAX {
            return Err(ProtocolError::Limit);
        }
        let identity = FileIdentity::from(meta);
        let mut hash = Sha256::new();
        let mut count = 0;
        let mut chunk = vec![0; 64 * 1024];
        loop {
            check_deadline(deadline)?;
            let read = file.read(&mut chunk).map_err(|_| ProtocolError::Invalid)?;
            if read == 0 {
                break;
            }
            count += read as u64;
            if count > identity.size {
                return Err(ProtocolError::Invalid);
            }
            hash.update(&chunk[..read]);
        }
        if count != identity.size {
            return Err(ProtocolError::Invalid);
        }
        let digest: Digest = hash.finalize().into();
        let mut metrics = IntegrityMetrics {
            file_bytes: count,
            memory_bytes: 0,
        };
        let selected: Vec<_> = policy
            .image_rules()
            .iter()
            .copied()
            .filter(|rule| rule.purpose == ImagePurpose::CodeIntegrity)
            .collect();
        let (loads, bias) = if selected.iter().any(|rule| rule.file_digest == digest) {
            parse_elf(&file, identity.size, &mut metrics)?
        } else {
            (Vec::new(), 0)
        };
        let mut ranges = Vec::with_capacity(selected.len());
        for rule in selected {
            let mut scope = if rule.file_digest == digest {
                eligible_range(&loads, bias, rule)
            } else {
                Range::OutsideScope
            };
            if let Range::Eligible(BoundRange { offset, length, .. }) = scope {
                let mut bytes = vec![0; length as usize];
                read_file(&file, offset, &mut bytes, identity.size, &mut metrics)?;
                if Digest::from(Sha256::digest(bytes)) != rule.code_digest {
                    scope = Range::OutsideScope;
                }
            }
            ranges.push((rule, scope));
        }
        check_deadline(deadline)?;
        if FileIdentity::from(file.metadata().map_err(|_| ProtocolError::Invalid)?) != identity {
            return Err(ProtocolError::Invalid);
        }
        Ok((
            Self {
                file,
                identity,
                revision: policy.revision(),
                ranges,
            },
            metrics,
        ))
    }

    pub fn observe(
        &self,
        policy: &VerifiedPolicy<'_>,
        now_ms: u64,
        window: SampleWindow,
    ) -> Result<(Vec<ObservationSample>, IntegrityMetrics), ProtocolError> {
        policy.check_time(now_ms)?;
        window.check_policy(policy)?;
        if self.revision != policy.revision() {
            return Err(ProtocolError::Binding);
        }
        let deadline = deadline(HOT_MAX)?;
        let mut metrics = IntegrityMetrics::default();
        let available = self
            .file
            .metadata()
            .is_ok_and(|meta| FileIdentity::from(meta) == self.identity);
        let memory = if available
            && self
                .ranges
                .iter()
                .any(|(_, range)| matches!(range, Range::Eligible(_)))
        {
            proc_file("/proc/self/mem").ok()
        } else {
            None
        };
        let rows = self
            .ranges
            .iter()
            .map(|(rule, range)| {
                let (finding, reason) = match (range, memory.as_ref()) {
                    (Range::OutsideScope, _) => (Finding::Unsupported, Reason::OutsideScope),
                    (Range::Eligible(range), Some(memory)) => {
                        self.measure(memory, *range, rule.code_digest, deadline, &mut metrics)
                    }
                    _ => (Finding::Inconclusive, Reason::ReadFailure),
                };
                window.sample(
                    ObservationRecord {
                        kind: ObservationKind::CodeIntegrity,
                        rule_id: rule.id,
                        finding,
                    },
                    reason,
                )
            })
            .collect();
        Ok((rows, metrics))
    }

    fn measure(
        &self,
        memory: &File,
        range: BoundRange,
        expected: Digest,
        deadline: Duration,
        metrics: &mut IntegrityMetrics,
    ) -> (Finding, Reason) {
        let BoundRange {
            offset,
            address,
            length,
        } = range;
        let inconclusive = (Finding::Inconclusive, Reason::ReadFailure);
        let read = || -> Result<(u64, Digest), ProtocolError> {
            check_deadline(deadline)?;
            if mapping(self.identity, offset, length)? != Some(address) {
                return Err(ProtocolError::Binding);
            }
            let mut bytes = vec![0; length as usize];
            memory
                .read_exact_at(&mut bytes, address)
                .map_err(|_| ProtocolError::Invalid)?;
            if mapping(self.identity, offset, length)? != Some(address) {
                return Err(ProtocolError::Invalid);
            }
            check_deadline(deadline)?;
            Ok((address, Sha256::digest(bytes).into()))
        };
        let Ok(first) = read() else {
            return inconclusive;
        };
        metrics.memory_bytes += u64::from(length);
        let Ok(second) = read() else {
            return inconclusive;
        };
        metrics.memory_bytes += u64::from(length);
        if first != second
            || !self
                .file
                .metadata()
                .is_ok_and(|meta| FileIdentity::from(meta) == self.identity)
        {
            return inconclusive;
        }
        if first.1 == expected {
            (Finding::NotObservedWithinScope, Reason::None)
        } else {
            (Finding::SignedMismatch, Reason::SignedMismatch)
        }
    }
}

fn deadline(limit: Duration) -> Result<Duration, ProtocolError> {
    Ok(boottime()?.saturating_add(limit))
}

fn check_deadline(deadline: Duration) -> Result<(), ProtocolError> {
    if boottime()? >= deadline {
        Err(ProtocolError::Limit)
    } else {
        Ok(())
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn read_file(
    file: &File,
    offset: u64,
    output: &mut [u8],
    size: u64,
    metrics: &mut IntegrityMetrics,
) -> Result<(), ProtocolError> {
    if offset
        .checked_add(output.len() as u64)
        .is_none_or(|end| end > size)
    {
        return Err(ProtocolError::Invalid);
    }
    file.read_exact_at(output, offset)
        .map_err(|_| ProtocolError::Invalid)?;
    metrics.file_bytes += output.len() as u64;
    Ok(())
}

fn parse_elf(
    file: &File,
    size: u64,
    metrics: &mut IntegrityMetrics,
) -> Result<(Vec<Load>, u64), ProtocolError> {
    let mut header = [0; 64];
    read_file(file, 0, &mut header, size, metrics)?;
    if &header[..7] != b"\x7fELF\x02\x01\x01"
        || !matches!(u16_at(&header, 16), 2 | 3)
        || u16_at(&header, 18) != 62
        || u32_at(&header, 20) != 1
        || u16_at(&header, 52) != 64
        || u16_at(&header, 54) != 56
    {
        return Ok((Vec::new(), 0));
    }
    let count = usize::from(u16_at(&header, 56));
    if count == 0 || count > PROGRAMS_MAX {
        return Ok((Vec::new(), 0));
    }
    let table_offset = u64_at(&header, 32);
    if table_offset < 64 {
        return Ok((Vec::new(), 0));
    }
    let mut table = vec![0; count * 56];
    read_file(file, table_offset, &mut table, size, metrics)?;
    let mut loads = Vec::new();
    let mut dynamic = None;
    for entry in table.chunks_exact(56) {
        let kind = u32_at(entry, 0);
        let load = Load {
            flags: u32_at(entry, 4),
            offset: u64_at(entry, 8),
            vaddr: u64_at(entry, 16),
            file_len: u64_at(entry, 32),
            memory_len: u64_at(entry, 40),
        };
        if kind == 1 {
            if load.file_len > load.memory_len
                || load
                    .offset
                    .checked_add(load.file_len)
                    .is_none_or(|end| end > size)
                || load.vaddr.checked_add(load.memory_len).is_none()
                || load.flags & 3 == 3
                || load.vaddr % 4096 != load.offset % 4096
            {
                return Ok((Vec::new(), 0));
            }
            loads.push(load);
        } else if kind == 2 && dynamic.replace(load).is_some() {
            return Ok((Vec::new(), 0));
        }
    }
    if let Some(dynamic) = dynamic {
        let mut owners = loads.iter().filter(|load| {
            dynamic
                .offset
                .checked_sub(load.offset)
                .is_some_and(|offset| {
                    load.vaddr.checked_add(offset) == Some(dynamic.vaddr)
                        && offset
                            .checked_add(dynamic.file_len)
                            .is_some_and(|end| end <= load.file_len)
                })
        });
        if owners.next().is_none()
            || owners.next().is_some()
            || !valid_dynamic(file, dynamic, size, metrics)?
        {
            return Ok((Vec::new(), 0));
        }
    }
    // SAFETY: getauxval returns the kernel's fixed main-image loader metadata.
    let (phdr, phnum, phent) = unsafe {
        (
            libc::getauxval(libc::AT_PHDR),
            libc::getauxval(libc::AT_PHNUM),
            libc::getauxval(libc::AT_PHENT),
        )
    };
    if phnum != count as u64 || phent != 56 {
        return Ok((Vec::new(), 0));
    }
    let table_end = table_offset + table.len() as u64;
    let owner: Vec<_> = loads
        .iter()
        .filter(|load| load.offset <= table_offset && table_end <= load.offset + load.file_len)
        .collect();
    let [owner] = owner.as_slice() else {
        return Ok((Vec::new(), 0));
    };
    let Some(table_vaddr) = owner.vaddr.checked_add(table_offset - owner.offset) else {
        return Ok((Vec::new(), 0));
    };
    let Some(bias) = phdr.checked_sub(table_vaddr) else {
        return Ok((Vec::new(), 0));
    };
    if u16_at(&header, 16) == 2 && bias != 0 {
        return Ok((Vec::new(), 0));
    }
    Ok((loads, bias))
}

fn valid_dynamic(
    file: &File,
    dynamic: Load,
    size: u64,
    metrics: &mut IntegrityMetrics,
) -> Result<bool, ProtocolError> {
    if dynamic.file_len == 0
        || dynamic.file_len > DYNAMIC_MAX
        || !dynamic.file_len.is_multiple_of(16)
    {
        return Ok(false);
    }
    let mut bytes = vec![0; dynamic.file_len as usize];
    read_file(file, dynamic.offset, &mut bytes, size, metrics)?;
    for entry in bytes.chunks_exact(16) {
        match u64_at(entry, 0) {
            0 => return Ok(true),
            22 => return Ok(false),                              // DT_TEXTREL
            30 if u64_at(entry, 8) & 4 != 0 => return Ok(false), // DF_TEXTREL
            _ => {}
        }
    }
    Ok(false)
}

fn eligible_range(loads: &[Load], bias: u64, rule: ImageRule) -> Range {
    let start = u64::from(rule.code_rva);
    let end = start + u64::from(rule.code_len);
    let overlaps: Vec<_> = loads
        .iter()
        .filter(|load| start < load.vaddr + load.memory_len && load.vaddr < end)
        .collect();
    let [load] = overlaps.as_slice() else {
        return Range::OutsideScope;
    };
    let page_start = start & !4095;
    let Some(page_end) = end.checked_add(4095).map(|value| value & !4095) else {
        return Range::OutsideScope;
    };
    if load.flags != 5
        || start < load.vaddr
        || end > load.vaddr + load.file_len
        || loads.iter().any(|other| {
            !std::ptr::eq(*load, other)
                && page_start < other.vaddr + other.memory_len
                && other.vaddr < page_end
        })
    {
        return Range::OutsideScope;
    }
    let Some(address) = bias.checked_add(start) else {
        return Range::OutsideScope;
    };
    Range::Eligible(BoundRange {
        offset: load.offset + (start - load.vaddr),
        address,
        length: rule.code_len,
    })
}

fn mapping(identity: FileIdentity, offset: u64, length: u32) -> Result<Option<u64>, ProtocolError> {
    let mut maps = Vec::new();
    proc_file("/proc/self/maps")
        .map_err(|_| ProtocolError::Invalid)?
        .take((MAPS_MAX + 1) as u64)
        .read_to_end(&mut maps)
        .map_err(|_| ProtocolError::Invalid)?;
    if maps.len() > MAPS_MAX {
        return Err(ProtocolError::Limit);
    }
    let mut result = None;
    for line in maps
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mut fields = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty());
        let addresses = fields.next().ok_or(ProtocolError::Invalid)?;
        let perms = fields.next().ok_or(ProtocolError::Invalid)?;
        let file_offset = hex(fields.next().ok_or(ProtocolError::Invalid)?)?;
        let device = pair(fields.next().ok_or(ProtocolError::Invalid)?, b':')?;
        let inode = std::str::from_utf8(fields.next().ok_or(ProtocolError::Invalid)?)
            .map_err(|_| ProtocolError::Invalid)?
            .parse::<u64>()
            .map_err(|_| ProtocolError::Invalid)?;
        if inode != identity.inode
            || device
                != (
                    u64::from(libc::major(identity.dev)),
                    u64::from(libc::minor(identity.dev)),
                )
        {
            continue;
        }
        let (start, end) = pair(addresses, b'-')?;
        let Some(address) = offset
            .checked_sub(file_offset)
            .and_then(|delta| start.checked_add(delta))
        else {
            continue;
        };
        if address
            .checked_add(u64::from(length))
            .is_none_or(|limit| limit > end)
        {
            continue;
        }
        if perms != b"r-xp" || result.replace(address).is_some() {
            return Ok(None);
        }
    }
    Ok(result)
}

fn pair(field: &[u8], separator: u8) -> Result<(u64, u64), ProtocolError> {
    let split = field
        .iter()
        .position(|byte| *byte == separator)
        .ok_or(ProtocolError::Invalid)?;
    Ok((hex(&field[..split])?, hex(&field[split + 1..])?))
}

fn hex(value: &[u8]) -> Result<u64, ProtocolError> {
    u64::from_str_radix(
        std::str::from_utf8(value).map_err(|_| ProtocolError::Invalid)?,
        16,
    )
    .map_err(|_| ProtocolError::Invalid)
}
