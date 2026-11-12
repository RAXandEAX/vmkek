//! E3 proof on M-LINUX: each Linux detector fail-closes on its own.

use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use vmkek::antidebug::{
    neutralize_loader_linux, with_linux_detectors, LINUX_CLOCK, LINUX_PTRACE, LINUX_TRACER,
};
use vmkek::protect::Options;

const LOADER_EXIT: i32 = 0xB6;
/// `0xbad1` from the bytecode fail path, truncated to a Unix status.
const VM_EXIT: i32 = 0xD1;
const CLOCK_LIMIT: u32 = 1_000_000_000;

// A concurrent fork can inherit a fixture's write descriptor and cause ETXTBSY.
static FIXTURE_IO: Mutex<()> = Mutex::new(());

#[test]
fn clean_run_prints_the_sample_line() {
    let path = write_bin(&protect(None), "clean");
    let ran = run(&path);
    assert_eq!(ran.status.code(), Some(0));
    assert_eq!(ran.stdout, vmkek::sample::line().into_bytes());
    let built = vmkek::protect::protect(&plain(), &opts()).unwrap();
    for pass in ["linux-tracer-pid", "linux-ptrace", "linux-clock"] {
        assert!(
            built.report.passes.iter().any(|item| item == pass),
            "{pass} missing"
        );
    }
}

#[test]
fn traced_child_fails_closed() {
    let path = write_bin(&protect(None), "traced");
    assert_closed(&trace(&path), LOADER_EXIT);
}

#[test]
fn tracer_pid_alone_fails_closed() {
    let path = write_bin(&protect(Some((LINUX_TRACER, CLOCK_LIMIT))), "tracer");
    assert_closed(&trace(&path), LOADER_EXIT);
}

#[test]
fn ptrace_alone_fails_closed() {
    let path = write_bin(&protect(Some((LINUX_PTRACE, CLOCK_LIMIT))), "ptrace");
    assert_closed(&trace(&path), VM_EXIT);
}

#[test]
fn clock_delta_alone_fails_closed() {
    let path = write_bin(&protect(Some((LINUX_CLOCK, 0))), "clock");
    let ran = run(&path);
    assert_closed(&ran, LOADER_EXIT);
}

#[test]
fn ptrace_alone_prints_when_clean() {
    let path = write_bin(&protect(Some((LINUX_PTRACE, CLOCK_LIMIT))), "ptrace-clean");
    let ran = run(&path);
    assert_eq!(ran.status.code(), Some(0));
    assert_eq!(ran.stdout, vmkek::sample::line().into_bytes());
}

#[test]
fn clock_alone_under_a_tracer_prints() {
    let path = write_bin(&protect(Some((LINUX_CLOCK, CLOCK_LIMIT))), "clock-traced");
    let ran = trace(&path);
    assert_eq!(
        ran.status.code(),
        Some(0),
        "{:?}",
        String::from_utf8_lossy(&ran.stderr)
    );
    assert_eq!(ran.stdout, vmkek::sample::line().into_bytes());
}

#[test]
fn loader_stub_does_not_keep_the_traced_result() {
    let mut bytes = protect(None);
    neutralize_loader_linux(&mut bytes).unwrap();
    vmkek::early::neutralize_early_elf(&mut bytes).unwrap();
    let path = write_bin(&bytes, "stub-traced");
    assert_closed(&trace(&path), VM_EXIT);
}

#[test]
fn loader_stub_still_prints_when_clean() {
    let mut bytes = protect(None);
    neutralize_loader_linux(&mut bytes).unwrap();
    let path = write_bin(&bytes, "stub-clean");
    let ran = run(&path);
    assert_eq!(ran.status.code(), Some(0));
    assert_eq!(ran.stdout, vmkek::sample::line().into_bytes());
}

#[test]
fn loader_stub_does_not_hide_a_clock_hit() {
    let mut bytes = protect(Some((LINUX_CLOCK, 0)));
    neutralize_loader_linux(&mut bytes).unwrap();
    let path = write_bin(&bytes, "stub-clock");
    let ran = run(&path);
    assert_closed(&ran, VM_EXIT);
}

fn protect(arm: Option<(u32, u32)>) -> Vec<u8> {
    let plain = plain();
    let built = match arm {
        Some((mask, limit)) => with_linux_detectors(mask, limit, || protect_plain(&plain)),
        None => protect_plain(&plain),
    };
    built.unwrap()
}

fn protect_plain(plain: &[u8]) -> Result<Vec<u8>, vmkek::Error> {
    Ok(vmkek::protect::protect(plain, &opts())?.bytes)
}

fn plain() -> Vec<u8> {
    vmkek::elf::sample::build().unwrap()
}

fn opts() -> Options {
    Options {
        virtualize: Default::default(),
        mutate: Default::default(),
        virtualize_all: true,
        mutate_all: false,
        seed: 0xE3_0001,
        random_key: false,
        debug_seed: false,
    }
}

fn assert_closed(ran: &std::process::Output, code: i32) {
    assert_eq!(ran.status.code(), Some(code), "{}", stderr(ran));
    assert_ne!(ran.stdout, vmkek::sample::line().into_bytes());
}

fn stderr(ran: &std::process::Output) -> String {
    String::from_utf8_lossy(&ran.stderr).into_owned()
}

fn write_bin(bytes: &[u8], name: &str) -> std::path::PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("e3-elf-{}-{name}", std::process::id()));
    let written = {
        let _guard = FIXTURE_IO.lock().unwrap();
        std::fs::write(&path, bytes)
    };
    written.unwrap();
    chmod(&path);
    path
}

fn chmod(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut mode = std::fs::metadata(path).unwrap().permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(path, mode).unwrap();
}

fn run(path: &Path) -> std::process::Output {
    let child = {
        let _guard = FIXTURE_IO.lock().unwrap();
        Command::new(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    };
    child.unwrap().wait_with_output().unwrap()
}

struct Run {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn trace(path: &Path) -> std::process::Output {
    let ran = launch(path);
    std::process::Output {
        status: ran.status,
        stdout: ran.stdout,
        stderr: ran.stderr,
    }
}

fn launch(path: &Path) -> Run {
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let argv = [path_c.as_ptr(), std::ptr::null()];
    let env = env_block();
    let mut env_ptrs: Vec<*const i8> = env.iter().map(|item| item.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    let mut pipe = [0i32; 2];
    // SAFETY: `pipe` is a two-word buffer for the pipe syscall.
    let opened = unsafe { raw(22, pipe.as_mut_ptr() as i64, 0, 0, 0) };
    assert!(opened >= 0, "pipe {opened}");
    let child = {
        let _guard = FIXTURE_IO.lock().unwrap();
        // SAFETY: fork takes no arguments.
        let child = unsafe { raw(57, 0, 0, 0, 0) };
        if child == 0 {
            child_exec(pipe, path_c.as_ptr(), argv.as_ptr(), env_ptrs.as_ptr());
        }
        child
    };
    assert!(child >= 0, "fork {child}");
    // SAFETY: `pipe[1]` is the write end this process opened.
    let _ = unsafe { raw(3, i64::from(pipe[1]), 0, 0, 0) };
    let (code, signal) = wait_traced(child as i32);
    let stdout = read_pipe(pipe[0]);
    Run {
        status: status_of(code, signal),
        stdout,
        stderr: Vec::new(),
    }
}

fn env_block() -> Vec<std::ffi::CString> {
    std::env::vars()
        .filter_map(|(key, value)| std::ffi::CString::new(format!("{key}={value}")).ok())
        .collect()
}

fn child_exec(
    pipe: [i32; 2],
    path: *const i8,
    argv: *const *const i8,
    envp: *const *const i8,
) -> ! {
    // SAFETY: this child uses only raw syscalls until execve replaces it.
    unsafe {
        raw(3, i64::from(pipe[0]), 0, 0, 0);
        raw(33, i64::from(pipe[1]), 1, 0, 0);
        if pipe[1] != 1 {
            raw(3, i64::from(pipe[1]), 0, 0, 0);
        }
        if raw(101, 0, 0, 0, 0) < 0 {
            die(126);
        }
        raw(59, path as i64, argv as i64, envp as i64, 0);
    }
    die(127);
}

fn wait_traced(pid: i32) -> (Option<i32>, Option<i32>) {
    for _ in 0..250 {
        let mut status = 0i32;
        // SAFETY: `status` is a live i32 and wait4 may read it.
        let rc = unsafe { raw(61, i64::from(pid), (&mut status as *mut i32) as i64, 3, 0) };
        match classify(rc, status) {
            Wait::Again => std::thread::sleep(Duration::from_millis(40)),
            Wait::Exit(code) => return (Some(code), None),
            Wait::Dead(signal) => return (None, Some(signal)),
            Wait::Stop(sig) => {
                let data = i64::from(if sig == 5 { 0 } else { sig });
                // SAFETY: PTRACE_CONT resumes the child this process is tracing.
                let cont = unsafe { raw(101, 7, i64::from(pid), 0, data) };
                if cont < 0 {
                    return (None, Some((-cont) as i32));
                }
            }
        }
    }
    // SAFETY: SIGKILL is delivered to the child this process forked.
    let _ = unsafe { raw(62, i64::from(pid), 9, 0, 0) };
    (None, Some(9))
}

enum Wait {
    Again,
    Exit(i32),
    Dead(i32),
    Stop(i32),
}

fn classify(rc: i64, status: i32) -> Wait {
    if rc == 0 {
        return Wait::Again;
    }
    if rc < 0 {
        return Wait::Dead((-rc) as i32);
    }
    if status & 0x7f == 0 {
        return Wait::Exit((status >> 8) & 0xff);
    }
    if status & 0xff == 0x7f {
        return Wait::Stop((status >> 8) & 0xff);
    }
    Wait::Dead(status & 0x7f)
}

fn status_of(code: Option<i32>, signal: Option<i32>) -> std::process::ExitStatus {
    let raw = match (code, signal) {
        (Some(code), _) => code << 8,
        (_, Some(signal)) => signal,
        _ => 0,
    };
    ExitStatusExt::from_raw(raw)
}

fn read_pipe(fd: i32) -> Vec<u8> {
    use std::os::unix::io::FromRawFd;
    // SAFETY: `fd` is the read end this process opened and still owns.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut out = Vec::new();
    file.read_to_end(&mut out).unwrap();
    out
}

fn die(code: i32) -> ! {
    // SAFETY: `exit_group` does not return. The hint covers that fact for the type checker.
    unsafe {
        raw(231, i64::from(code), 0, 0, 0);
        std::hint::unreachable_unchecked()
    }
}

/// `n` is a Linux syscall. `a`..`d` are its first four arguments.
///
/// # Safety
/// The caller picks a real syscall and arguments that process may use.
unsafe fn raw(n: i64, a: i64, b: i64, c: i64, d: i64) -> i64 {
    let rc: i64;
    std::arch::asm!(
        "syscall",
        in("rax") n,
        in("rdi") a,
        in("rsi") b,
        in("rdx") c,
        in("r10") d,
        lateout("rax") rc,
        out("rcx") _,
        out("r11") _,
    );
    rc
}
