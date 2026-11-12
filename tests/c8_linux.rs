//! M-LINUX proof that external-key keeps the ChaCha20 key out of the guest.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use vmkek::agent::{
    self, Agent, Request, OP_BEGIN, OP_COMMIT, OP_INNER, OP_OPEN, OP_RESIDENT, TICKET_LEN,
};
use vmkek::elf::sample;
use vmkek::proof::{self, Claim};
use vmkek::protect::{self, Options};
use vmkek::sample as carrier;

#[test]
fn offline_and_external_print_one_sample_line() {
    let plain = sample::build().expect("carrier");
    let offline = protect::protect(&plain, &opts(0xC8_0001)).expect("offline");
    assert!(offline.custody.is_none());
    assert!(offline
        .report
        .passes
        .iter()
        .any(|pass| pass == "offline-key"));
    assert!(!offline
        .report
        .passes
        .iter()
        .any(|pass| pass == "external-key"));
    let weaker = claim_of(&offline.report, "offline-key");
    assert_eq!(weaker.claim, Claim::ReducedToAssumption);
    assert!(weaker.proof_anchor.unwrap().contains("слабее"));
    let ran = run(&offline.bytes, "30");
    assert_one_line(&ran);

    let path = socket_path();
    let external =
        protect::protect_external(&plain, &selected_opts(0xC8_0002), &path).expect("external");
    assert!(external
        .report
        .passes
        .iter()
        .any(|pass| pass == "external-key"));
    assert!(external
        .report
        .passes
        .iter()
        .any(|pass| pass == "external-sample"));
    assert!(!external
        .report
        .passes
        .iter()
        .any(|pass| pass == "offline-key"));
    let anchor = claim_of(&external.report, "external-key")
        .proof_anchor
        .unwrap();
    assert!(anchor.contains("программное измерение"));
    assert!(anchor.contains("не аппаратная аттестация"));
    let package = external.custody.clone().expect("custody");
    let agent = Agent::listen(&path, &external.bytes, package).expect("agent");
    assert_eq!(mode(&path) & 0o777, 0o600);
    let ran = run(&external.bytes, "60");
    assert_one_line(&ran);
    drop(agent);
}

#[test]
fn guest_snapshot_misses_the_key_and_finds_the_sample() {
    let plain = sample::build().expect("carrier");
    let path = socket_path();
    let protected =
        protect::protect_external(&plain, &selected_opts(0xC8_0003), &path).expect("external");
    let package = protected.custody.clone().expect("custody");
    assert_file_hides_keys(&protected.bytes, &package);
    let agent = Agent::listen(&path, &protected.bytes, package).expect("agent");
    let ran = run(&protected.bytes, "60");
    assert_one_line(&ran);
    let snaps = agent.snapshots();
    assert!(
        snaps
            .iter()
            .any(|snap| snap.resident && snap.plain_hit && !snap.key_hit),
        "no resident plaintext: {snaps:?} {ran:?}"
    );
    assert!(snaps.iter().all(|snap| !snap.key_hit), "{snaps:?}");
}

#[test]
fn a_consumed_ticket_cannot_release_another_block() {
    let path = socket_path();
    let plain = sample::build().unwrap();
    let protected = protect::protect_external(&plain, &opts(0xC8_0004), &path).unwrap();
    let other = protect::protect_external(&plain, &opts(0xC8_0005), &path).unwrap();
    let package = protected.custody.unwrap();
    let foreign = other.custody.unwrap();
    let request = first_request(&protected.bytes, &package);
    let replacement = foreign
        .funcs
        .iter()
        .find(|item| item.rva == request.rva)
        .unwrap();
    let mut splice = request.clone();
    assert_ne!(splice.body, replacement.sealed[0]);
    splice.body.clone_from(&replacement.sealed[0]);
    let _agent = Agent::listen(&path, &protected.bytes, package).unwrap();

    let (mut socket, first) = begin_call(&path, &request);
    let second = send_ok(&mut socket, &first, &request, request.body.len());
    assert_ne!(first, second);
    socket.write_all(&first).unwrap();
    assert_empty_denial(socket);

    let (mut reconnect, fresh) = connect_ticketed(&path);
    assert_ne!(first, fresh);
    reconnect.write_all(&first).unwrap();
    assert_empty_denial(reconnect);

    let (mut socket, ticket) = begin_call(&path, &request);
    send_request(&mut socket, &ticket, &splice);
    assert_empty_denial(socket);
    assert_old_versions_denied(&path);
}

#[test]
fn concurrent_sessions_survive_a_stalled_peer_and_reject_fresh_ticket_replay() {
    let path = socket_path();
    let protected =
        protect::protect_external(&sample::build().unwrap(), &opts(0xC8_0006), &path).unwrap();
    let package = protected.custody.unwrap();
    let request = first_request(&protected.bytes, &package);
    let _agent = Agent::listen(&path, &protected.bytes, package).unwrap();
    let (mut stalled, ticket) = begin_call(&path, &request);
    stalled.write_all(&ticket).unwrap();
    stalled.write_all(&[0]).unwrap();

    thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut request = request.clone();
                request.tid = thread_id();
                let (mut socket, first) = begin_call(&path, &request);
                let fresh = send_ok(&mut socket, &first, &request, request.body.len());
                send_request(&mut socket, &fresh, &request);
                assert_empty_denial(socket);
            })
            .join()
            .unwrap();
    });
    assert_trickle_does_not_extend_call(stalled);

    let (mut clean, ticket) = begin_call(&path, &request);
    let next = send_ok(&mut clean, &ticket, &request, request.body.len());
    let commit = control(&request, OP_COMMIT, 3, 1);
    send_ok(&mut clean, &next, &commit, 0);
}

fn assert_trickle_does_not_extend_call(mut stalled: UnixStream) {
    thread::sleep(Duration::from_secs(4));
    let _ = stalled.write_all(&[0]);
    stalled
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    match stalled.read(&mut [0]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("stalled call remained open: {other:?}"),
    }
}

#[test]
fn recursive_socket_calls_resume_the_parent_and_refuse_a_foreign_inner_block() {
    let path = socket_path();
    let protected =
        protect::protect_external(&sample::build().unwrap(), &opts(0xC8_0007), &path).unwrap();
    let package = protected.custody.unwrap();
    let request = first_request(&protected.bytes, &package);
    let mut inner = control(&request, OP_INNER, 5, 1);
    inner.body.clone_from(&package.funcs[0].inner.bytes);
    let _agent = Agent::listen(&path, &protected.bytes, package).unwrap();
    let (mut socket, mut ticket) = begin_call(&path, &request);

    for (op, seq, call) in [(OP_BEGIN, 2, 2), (OP_OPEN, 3, 2), (OP_COMMIT, 4, 2)] {
        let mut nested = control(&request, op, seq, call);
        if op == OP_OPEN {
            nested.body.clone_from(&request.body);
        }
        ticket = send_ok(&mut socket, &ticket, &nested, nested.body.len());
    }
    ticket = send_ok(&mut socket, &ticket, &inner, inner.body.len());
    inner.seq = 6;
    inner.body[0] ^= 1;
    send_request(&mut socket, &ticket, &inner);
    assert_empty_denial(socket);
}

#[test]
fn oversized_requests_and_wrong_thread_or_call_never_release_a_body() {
    let path = socket_path();
    let protected =
        protect::protect_external(&sample::build().unwrap(), &opts(0xC8_0008), &path).unwrap();
    let package = protected.custody.unwrap();
    let request = first_request(&protected.bytes, &package);
    let _agent = Agent::listen(&path, &protected.bytes, package).unwrap();

    for altered in [
        Request {
            call_id: 2,
            ..request.clone()
        },
        Request {
            tid: u32::MAX,
            ..request.clone()
        },
        Request {
            index: u32::MAX,
            ..request.clone()
        },
        control(&request, OP_RESIDENT, 2, 1),
    ] {
        let (mut socket, ticket) = begin_call(&path, &request);
        send_request(&mut socket, &ticket, &altered);
        assert_empty_denial(socket);
    }
    let (mut socket, ticket) = begin_call(&path, &request);
    let mut header = agent::encode(&request)[..agent::HDR].to_vec();
    header[agent::OFF_LEN..agent::OFF_LEN + 4]
        .copy_from_slice(&((agent::MAX_BODY + 1) as u32).to_le_bytes());
    socket.write_all(&ticket).unwrap();
    socket.write_all(&header).unwrap();
    assert_empty_denial(socket);
}

#[test]
fn a_connection_from_an_exited_thread_cannot_resume_its_call() {
    let path = socket_path();
    let protected =
        protect::protect_external(&sample::build().unwrap(), &opts(0xC8_0009), &path).unwrap();
    let package = protected.custody.unwrap();
    let mut request = first_request(&protected.bytes, &package);
    let _agent = Agent::listen(&path, &protected.bytes, package).unwrap();
    let (mut socket, ticket) = thread::scope(|scope| {
        scope
            .spawn(|| {
                request.tid = thread_id();
                begin_call(&path, &request)
            })
            .join()
            .unwrap()
    });
    assert_ne!(request.tid, thread_id());
    send_request(&mut socket, &ticket, &request);
    assert_empty_denial(socket);
}

#[test]
fn agent_does_not_remove_existing_or_replacement_socket_paths() {
    let path = socket_path();
    let protected =
        protect::protect_external(&sample::build().unwrap(), &opts(0xC8_000A), &path).unwrap();
    let package = protected.custody.unwrap();
    fs::write(&*path, b"existing file").unwrap();
    assert!(Agent::listen(&path, &protected.bytes, package.clone()).is_err());
    assert_eq!(fs::read(&*path).unwrap(), b"existing file");
    fs::remove_file(&*path).unwrap();

    let listener = UnixListener::bind(&*path).unwrap();
    let old_ino = fs::metadata(&*path).unwrap().ino();
    assert!(Agent::listen(&path, &protected.bytes, package.clone()).is_err());
    assert_eq!(fs::metadata(&*path).unwrap().ino(), old_ino);
    drop(listener);
    fs::remove_file(&*path).unwrap();

    let agent = Agent::listen(&path, &protected.bytes, package.clone()).unwrap();
    fs::remove_file(&*path).unwrap();
    fs::write(&*path, b"replacement file").unwrap();
    drop(agent);
    assert_eq!(fs::read(&*path).unwrap(), b"replacement file");
    fs::remove_file(&*path).unwrap();

    let agent = Agent::listen(&path, &protected.bytes, package.clone()).unwrap();
    fs::remove_file(&*path).unwrap();
    let listener = UnixListener::bind(&*path).unwrap();
    let replacement = fs::metadata(&*path).unwrap().ino();
    drop(agent);
    assert_eq!(fs::metadata(&*path).unwrap().ino(), replacement);
    drop(listener);
    fs::remove_file(&*path).unwrap();

    fs::set_permissions(&path.directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Agent::listen(&path, &protected.bytes, package).is_err());
    assert!(!PathBuf::from(&*path).exists());
}

fn assert_old_versions_denied(path: &str) {
    for version in [1, 2, agent::VER + 1] {
        let mut legacy = connect_agent(path);
        let mut old = agent::HELLO;
        old[4] = version;
        legacy.write_all(&old[..58]).unwrap();
        assert_empty_denial(legacy);
    }
}

fn first_request(protected: &[u8], package: &agent::Package) -> Request {
    let func = &package.funcs[0];
    Request {
        op: OP_OPEN,
        measurement: vmkek::crypto::sha256(protected),
        salt: func.salt,
        index: 0,
        rva: func.rva,
        tid: thread_id(),
        call_id: 1,
        seq: 2,
        body: func.sealed[0].clone(),
    }
}

fn thread_id() -> u32 {
    fs::read_link("/proc/thread-self")
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap()
}

fn control(open: &Request, op: u8, seq: u64, call_id: u64) -> Request {
    Request {
        op,
        seq,
        call_id,
        body: Vec::new(),
        ..open.clone()
    }
}

fn begin_call(path: &str, open: &Request) -> (UnixStream, [u8; TICKET_LEN]) {
    let (mut socket, hello) = connect_ticketed(path);
    let ticket = send_ok(&mut socket, &hello, &control(open, OP_BEGIN, 1, 1), 0);
    (socket, ticket)
}

fn send_request(socket: &mut UnixStream, ticket: &[u8; TICKET_LEN], request: &Request) {
    socket.write_all(ticket).unwrap();
    socket.write_all(&agent::encode(request)).unwrap();
}

fn send_ok(
    socket: &mut UnixStream,
    ticket: &[u8; TICKET_LEN],
    request: &Request,
    expected: usize,
) -> [u8; TICKET_LEN] {
    send_request(socket, ticket, request);
    let mut header = [0; 5];
    socket.read_exact(&mut header).unwrap();
    assert_eq!(header[0], agent::STATUS_OK);
    let len = u32::from_le_bytes(header[1..].try_into().unwrap()) as usize;
    assert_eq!(len, expected);
    socket.read_exact(&mut vec![0; len]).unwrap();
    let mut next = [0; TICKET_LEN];
    socket.read_exact(&mut next).unwrap();
    next
}

fn connect_agent(path: &str) -> UnixStream {
    let socket = UnixStream::connect(path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
}

fn connect_ticketed(path: &str) -> (UnixStream, [u8; vmkek::agent::TICKET_LEN]) {
    use vmkek::agent::{HELLO, STATUS_OK, TICKET_LEN};

    let mut socket = connect_agent(path);
    let mut greeting = [0; 5];
    let mut ticket = [0; TICKET_LEN];
    socket.write_all(&HELLO).unwrap();
    socket.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [STATUS_OK, TICKET_LEN as u8, 0, 0, 0]);
    socket.read_exact(&mut ticket).unwrap();
    (socket, ticket)
}

fn assert_empty_denial(mut socket: UnixStream) {
    let mut header = [0; 5];
    socket.read_exact(&mut header).unwrap();
    assert_eq!(header, [vmkek::agent::STATUS_DENY, 0, 0, 0, 0]);
    match socket.read(&mut [0]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("unexpected denial body: {other:?}"),
    }
}

fn assert_one_line(ran: &Ran) {
    assert_eq!(ran.code, Some(0), "{}", ran.detail());
    assert_eq!(ran.stdout, carrier::line().into_bytes());
    assert_eq!(ran.stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
}

fn assert_file_hides_keys(bytes: &[u8], package: &vmkek::agent::Package) {
    for func in &package.funcs {
        assert!(!vmkek::agent::contains_bytes(bytes, &func.key));
        assert!(!vmkek::agent::contains_bytes(bytes, &func.terminal));
        assert!(!vmkek::agent::contains_bytes(bytes, &func.inner.key));
    }
}

fn claim_of(report: &vmkek::report::Report, pass: &str) -> proof::PassClaim {
    let claim = report
        .claims
        .iter()
        .find(|item| item.pass == pass)
        .unwrap_or_else(|| panic!("missing {pass}"));
    let row = proof::registry()
        .into_iter()
        .find(|item| item.pass == pass)
        .unwrap_or_else(|| panic!("missing registry {pass}"));
    assert_eq!(*claim, row);
    row
}

fn selected_opts(seed: u64) -> Options {
    Options {
        virtualize: ["mix".into()].into_iter().collect(),
        virtualize_all: false,
        ..opts(seed)
    }
}

fn opts(seed: u64) -> Options {
    Options {
        virtualize: Default::default(),
        mutate: Default::default(),
        virtualize_all: true,
        mutate_all: false,
        seed,
        random_key: false,
        debug_seed: false,
    }
}

fn mode(path: &str) -> u32 {
    fs::metadata(path).expect("socket").permissions().mode()
}

struct SocketPath {
    directory: PathBuf,
    socket: String,
}

impl std::ops::Deref for SocketPath {
    type Target = str;

    fn deref(&self) -> &str {
        &self.socket
    }
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.directory);
    }
}

fn socket_path() -> SocketPath {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = PathBuf::from(format!("/tmp/vmkek-c8-{}-{stamp}-{id}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let socket = directory
        .join("agent.sock")
        .into_os_string()
        .into_string()
        .unwrap();
    SocketPath { directory, socket }
}

#[derive(Debug)]
struct Ran {
    code: Option<i32>,
    stdout: Vec<u8>,
    detail: String,
}

impl Ran {
    fn detail(&self) -> &str {
        &self.detail
    }
}

fn run(bytes: &[u8], seconds: &str) -> Ran {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("target/c8-elf-{}-{id}", std::process::id()));
    fs::create_dir_all(path.parent().expect("target")).expect("target dir");
    fs::write(&path, bytes).expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
    let output = spawn(&path, seconds);
    if output.status.success() {
        let _ = fs::remove_file(&path);
    }
    Ran {
        code: output.status.code(),
        stdout: output.stdout,
        detail: format!(
            "code {:?} signal {:?} stderr {} path {}",
            output.status.code(),
            output.status.signal(),
            String::from_utf8_lossy(&output.stderr),
            path.display()
        ),
    }
}

fn spawn(path: &PathBuf, seconds: &str) -> std::process::Output {
    let mut output = None;
    for _ in 0..8 {
        match Command::new("timeout").arg(seconds).arg(path).output() {
            Ok(spawned) => {
                output = Some(spawned);
                break;
            }
            Err(err) if err.raw_os_error() == Some(26) => thread::sleep(Duration::from_millis(20)),
            Err(err) => panic!("spawn {}: {err}", path.display()),
        }
    }
    output.unwrap_or_else(|| panic!("spawn {}: text file busy", path.display()))
}
