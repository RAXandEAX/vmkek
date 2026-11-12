//! Advisory observation of this process only.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vmkek_protocol::{
    detection::{LinuxProfileContext, LinuxRelease, ObservationProfile, SignedDetectionPolicy},
    session_observation::{ObservationPlatform, ObservationReason, ObservationSample},
    ProtocolError,
};

use super::{Observation, SampleWindow};

const STATUS_MAX: usize = 16 * 1024;

mod integrity;
pub use integrity::{IntegrityMetrics, PreparedElfIntegrity};

pub fn native_release() -> Result<LinuxRelease, ProtocolError> {
    let mut value = std::mem::MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: uname writes a complete utsname into the live output on success.
    if unsafe { libc::uname(value.as_mut_ptr()) } != 0 {
        return Err(ProtocolError::Binding);
    }
    // SAFETY: The preceding successful call initialized this structure.
    let value = unsafe { value.assume_init() };
    let mut release = [0; 65];
    let mut length = 0;
    for (out, byte) in release.iter_mut().zip(value.release) {
        if byte == 0 {
            break;
        }
        *out = byte as u8;
        length += 1;
    }
    LinuxRelease::from_uname(&release[..length])
}

pub(crate) fn boottime() -> Result<Duration, ProtocolError> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes a timespec into this live output.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(ProtocolError::Binding);
    }
    let sec = u64::try_from(value.tv_sec).map_err(|_| ProtocolError::Invalid)?;
    let ns = u32::try_from(value.tv_nsec).map_err(|_| ProtocolError::Invalid)?;
    if ns >= 1_000_000_000 {
        return Err(ProtocolError::Invalid);
    }
    Ok(Duration::new(sec, ns))
}

pub(crate) fn wall_ms() -> Result<u64, crate::Status> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| crate::Status::Unavailable)?
        .as_millis();
    u64::try_from(ms).map_err(|_| crate::Status::Unavailable)
}

pub(crate) fn proc_file(path: &str) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: The live file descriptor and valid output are held by this call.
    if unsafe { libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fstatfs initialized the output on success.
    if unsafe { fs.assume_init() }.f_type != libc::PROC_SUPER_MAGIC {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(file)
}

/// A bounded shutdown can leave a worker in an OS call. Mark a dynamically
/// loaded runtime module non-unloadable before starting that worker so both
/// the worker and its Rust epilogue remain mapped. The main image needs no pin.
pub(crate) fn pin_observer_module() -> Result<(), crate::Status> {
    let address = pin_observer_module as *const () as usize;
    // SAFETY: getauxval reads the current process's loader-provided auxiliary data.
    let (phdr, phnum, phent) = unsafe {
        (
            libc::getauxval(libc::AT_PHDR),
            libc::getauxval(libc::AT_PHNUM),
            libc::getauxval(libc::AT_PHENT),
        )
    };
    if phdr == 0
        || phnum == 0
        || phnum > 128
        || phent as usize != std::mem::size_of::<libc::Elf64_Phdr>()
    {
        return Err(crate::Status::Incompatible);
    }
    // SAFETY: The kernel keeps the main executable program headers mapped for the
    // life of the process. The ABI size and bounded kernel-supplied count are checked.
    let headers =
        unsafe { std::slice::from_raw_parts(phdr as *const libc::Elf64_Phdr, phnum as usize) };
    let main = headers
        .iter()
        .find(|header| header.p_type == libc::PT_PHDR)
        .and_then(|header| phdr.checked_sub(header.p_vaddr))
        .is_some_and(|bias| {
            headers
                .iter()
                .filter(|header| header.p_type == libc::PT_LOAD)
                .any(|header| {
                    bias.checked_add(header.p_vaddr)
                        .and_then(|start| start.checked_add(header.p_memsz).map(|end| (start, end)))
                        .is_some_and(|(start, end)| (start..end).contains(&(address as u64)))
                })
        });
    if main {
        return Ok(());
    }
    let mut info = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
    // SAFETY: The address belongs to executing code and info is a live output.
    if unsafe { libc::dladdr(address as *const _, info.as_mut_ptr()) } == 0 {
        return Err(crate::Status::Incompatible);
    }
    // SAFETY: Successful dladdr initialized info and returned a loader-owned C string.
    let info = unsafe { info.assume_init() };
    if info.dli_fname.is_null() {
        return Err(crate::Status::Incompatible);
    }
    // SAFETY: NOLOAD limits lookup to loaded modules. NODELETE pins the existing
    // module after dlclose; the worker does not retain an additional loader handle.
    let handle = unsafe {
        libc::dlopen(
            info.dli_fname,
            libc::RTLD_NOW | libc::RTLD_NOLOAD | libc::RTLD_NODELETE,
        )
    };
    if handle.is_null() {
        return Err(crate::Status::Incompatible);
    }
    // SAFETY: handle is the reference acquired by the successful dlopen above.
    if unsafe { libc::dlclose(handle) } != 0 {
        return Err(crate::Status::Incompatible);
    }
    Ok(())
}

/// Activates a signed offline policy using this kernel's exact release and a
/// process clock that includes time spent suspended.
pub fn activate_offline(
    signed: &SignedDetectionPolicy,
    pin: &p256::ecdsa::VerifyingKey,
    app_id: vmkek_protocol::Id,
    build_id: vmkek_protocol::Id,
    epoch_floor: u64,
    previous: Option<vmkek_protocol::detection::PolicyRevision>,
) -> Result<super::ObservationGate, crate::Status> {
    let release = native_release().map_err(|_| crate::Status::Incompatible)?;
    let anchor = boottime().map_err(|_| crate::Status::Unavailable)?;
    let verified = signed
        .verify_for_linux_profile(
            pin,
            LinuxProfileContext {
                app_id,
                build_id,
                epoch_floor,
                release,
                now_ms: wall_ms()?,
                profile: ObservationProfile::Offline,
                supported: &[
                    vmkek_protocol::session_observation::ObservationKind::DebuggerAttachment,
                    vmkek_protocol::session_observation::ObservationKind::CodeIntegrity,
                ],
                previous,
            },
        )
        .map_err(policy_error)?;
    Ok(super::ObservationGate::new_at(
        verified
            .observation_policy()
            .ok_or(crate::Status::Incompatible)?,
        anchor,
    ))
}

pub(crate) fn policy_error(error: ProtocolError) -> crate::Status {
    match error {
        ProtocolError::UnknownMandatory | ProtocolError::Version => crate::Status::Incompatible,
        _ => crate::Status::InvalidPackage,
    }
}

pub fn tracer_attachment() -> Observation {
    sample_tracer().0
}

/// Uses the process-local clock and Linux kernel build supplied by the caller.
pub fn tracer_attachment_sample(window: SampleWindow) -> Result<ObservationSample, ProtocolError> {
    if !matches!(
        window.platform,
        ObservationPlatform::Linux { major: 1.., .. }
    ) {
        return Err(ProtocolError::Binding);
    }
    let (outcome, reason) = sample_tracer();
    Ok(window.attachment(outcome, reason))
}

fn sample_tracer() -> (Observation, ObservationReason) {
    let Ok(file) = proc_file("/proc/self/status") else {
        return (Observation::Inconclusive, ObservationReason::ReadFailure);
    };
    let mut status = Vec::new();
    if file
        .take(STATUS_MAX as u64 + 1)
        .read_to_end(&mut status)
        .is_err()
    {
        return (Observation::Inconclusive, ObservationReason::ReadFailure);
    }
    if status.len() > STATUS_MAX {
        return (Observation::Inconclusive, ObservationReason::InvalidData);
    }
    parse(&status)
}

fn parse(status: &[u8]) -> (Observation, ObservationReason) {
    let mut tracer = status
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(b"TracerPid:"));
    let invalid = (Observation::Inconclusive, ObservationReason::InvalidData);
    let Some(value) = tracer.next() else {
        return invalid;
    };
    if tracer.next().is_some() {
        return invalid;
    }
    let value = value.trim_ascii();
    let number = (!value.is_empty() && value.iter().all(u8::is_ascii_digit))
        .then(|| {
            std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.parse::<i32>().ok())
        })
        .flatten();
    match number {
        Some(0) => (Observation::NotObservedWithinScope, ObservationReason::None),
        Some(_) => (Observation::Observed, ObservationReason::None),
        None => invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_status_uses_one_exact_tracer_field() {
        assert_eq!(
            parse(b"Name:\tvmk\nTracerPid:\t0\n"),
            (Observation::NotObservedWithinScope, ObservationReason::None)
        );
        assert_eq!(
            parse(b"TracerPid:\t12\n"),
            (Observation::Observed, ObservationReason::None)
        );
        for status in [
            b"TracerPid:\t0\nTracerPid:\t12\n".as_slice(),
            b"TracerPid:\tx\n",
            b"TracerPidx: 12\n",
            b"TracerPid: +12\n",
            b"TracerPid: 2147483648\n",
            b"TracerPid: \xc2\xa012\n",
        ] {
            assert_eq!(
                parse(status),
                (Observation::Inconclusive, ObservationReason::InvalidData)
            );
        }
    }
}
