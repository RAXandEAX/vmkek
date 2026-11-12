use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::ptr;

use vmkek_runtime::{
    vmk_cancel, vmk_initialize, vmk_invoke, vmk_shutdown, Status, VmkRequestId, VmkRuntime,
};

pub(super) fn fork_exec(handle: VmkRuntime, arguments: [&OsStr; 3]) -> Result<(), String> {
    let image = std::env::current_exe().map_err(|_| "cannot resolve sample ELF")?;
    let image = CString::new(image.as_os_str().as_bytes()).map_err(|_| "invalid sample path")?;
    let args: Vec<_> = arguments
        .iter()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| "invalid sample argument")?;
    let argv = [
        image.as_ptr(),
        args[0].as_ptr(),
        args[1].as_ptr(),
        args[2].as_ptr(),
        ptr::null(),
    ];
    // SAFETY: all exec inputs are prepared before fork. The inherited child
    // runs only the runtime's atomic PID fence and async-signal-safe calls.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err("fork failed".into());
    }
    if child == 0 {
        // SAFETY: the PID fence rejects each call before reading pointers or
        // touching inherited runtime state. write/execv/_exit are child-safe.
        unsafe {
            let denied = Status::Unavailable as u32;
            if vmk_initialize(ptr::null(), ptr::null_mut()) != denied
                || vmk_invoke(handle, ptr::null(), ptr::null_mut()) != denied
                || vmk_cancel(handle, VmkRequestId { bytes: [1; 16] }) != denied
                || vmk_shutdown(handle) != denied
            {
                libc::_exit(71);
            }
            let marker = b"r21 inherited runtime denied before exec\n";
            if libc::write(libc::STDOUT_FILENO, marker.as_ptr().cast(), marker.len())
                != marker.len() as isize
            {
                libc::_exit(72);
            }
            libc::execv(image.as_ptr(), argv.as_ptr());
            libc::_exit(73);
        }
    }
    let mut status = 0;
    // SAFETY: child is our own fork result and status is writable.
    if unsafe { libc::waitpid(child, &mut status, 0) } != child
        || !libc::WIFEXITED(status)
        || libc::WEXITSTATUS(status) != 0
    {
        return Err("fork child did not complete fresh Online exec".into());
    }
    Ok(())
}

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static SIGNALLED: AtomicBool = AtomicBool::new(false);

extern "C" fn flag_signal(_: libc::c_int) {
    SIGNALLED.store(true, Ordering::Release);
}

struct SignalGuard(libc::sigaction);

impl SignalGuard {
    fn install() -> Result<Self, String> {
        SIGNALLED.store(false, Ordering::Release);
        // SAFETY: zero is a valid starting representation for sigaction.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut previous = action;
        action.sa_sigaction = flag_signal as *const () as usize;
        // SAFETY: both action structures are live; handler only sets an atomic.
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
            || unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut previous) } != 0
        {
            return Err("could not install sample signal handler".into());
        }
        Ok(Self(previous))
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        // SAFETY: restore the action recorded at installation.
        unsafe { libc::sigaction(libc::SIGUSR1, &self.0, ptr::null_mut()) };
    }
}

pub(super) fn cancel_signal(
    handle: VmkRuntime,
    request: VmkRequestId,
    control: &Path,
    invoke: impl FnOnce() -> Result<(), String> + Send,
) -> Result<(), String> {
    if !control.is_absolute() || !control.is_dir() {
        return Err("signal control requires an absolute private directory".into());
    }
    let _signal = SignalGuard::install()?;
    std::fs::write(control.join("authorized"), []).map_err(|_| "cannot publish signal marker")?;
    let until = Instant::now() + Duration::from_secs(8);
    while !control.join("go").is_file() {
        if Instant::now() >= until {
            return Err("signal control timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    std::thread::scope(|scope| {
        let call = scope.spawn(invoke);
        std::fs::write(control.join("invoking"), []).map_err(|_| "cannot publish signal marker")?;
        let until = Instant::now() + Duration::from_secs(4);
        while !call.is_finished() && Instant::now() < until {
            if SIGNALLED.load(Ordering::Acquire) && vmk_cancel(handle, request) == Status::Ok as u32
            {
                return match call.join() {
                    Ok(Err(error)) if error == "online-vm status=8" => Ok(()),
                    _ => Err("signal did not cancel the exact Online call".into()),
                };
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Err("no active Online call was cancelled after SIGUSR1".into())
    })
}
