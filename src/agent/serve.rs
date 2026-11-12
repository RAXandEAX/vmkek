//! Owner-only Unix socket. The key stays in this process; the guest gets plaintext.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::error::{msg, Result};

use super::session::{Session, MAX_CONTEXTS};
use super::{contains_bytes, wire, Core, GuestSnap, Package, MEMORY_BUDGET};
use crate::secret::WipeBuffer;

const SOL_SOCKET: i32 = 1;
const SO_PEERCRED: i32 = 17;
const O_DIRECTORY: i32 = 0o200000;
const O_NOFOLLOW: i32 = 0o400000;
const O_PATH: i32 = 0o10000000;
const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const FRAME_TIMEOUT: Duration = Duration::from_secs(wire::FRAME_TIMEOUT_SECS);

#[repr(C)]
struct Ucred {
    pid: i32,
    uid: u32,
    gid: u32,
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

extern "C" {
    fn getsockopt(fd: i32, level: i32, name: i32, value: *mut u8, len: *mut u32) -> i32;
    fn geteuid() -> u32;
    fn poll(fds: *mut PollFd, count: usize, timeout: i32) -> i32;
}

/// One look at the guest while it is blocked in the protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snap {
    /// The guest had just installed a bytecode block.
    pub resident: bool,
    /// A raw ChaCha20 key was visible in the guest.
    pub key_hit: bool,
    /// The released plaintext was visible in the guest.
    pub plain_hit: bool,
}

/// Local attestation agent. Dropping it stops the thread and removes the socket.
pub struct Agent {
    _socket: BoundSocket,
    snaps: Arc<Mutex<Vec<Snap>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Agent {
    /// Bind `path` as mode `0600` and serve `package` for the measured `elf`.
    pub fn listen(path: &str, elf: &[u8], package: Package) -> Result<Self> {
        super::check_path(path)?;
        let core = Arc::new(Core::new(elf, package)?);
        let (listener, socket) = BoundSocket::bind(Path::new(path))?;
        let snaps = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let join = spawn(
            listener,
            Arc::clone(&core),
            Arc::clone(&snaps),
            Arc::clone(&stop),
        );
        Ok(Self {
            _socket: socket,
            snaps,
            stop,
            join: Some(join),
        })
    }

    /// Snapshots taken so far, in protocol order.
    pub fn snapshots(&self) -> Vec<Snap> {
        match self.snaps.lock() {
            Ok(guard) => guard.clone(),
            Err(poison) => poison.into_inner().clone(),
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct BoundSocket {
    _directory: File,
    inode: File,
    path: PathBuf,
    identity: (u64, u64),
}

impl BoundSocket {
    fn bind(path: &Path) -> Result<(UnixListener, Self)> {
        let name = path
            .file_name()
            .ok_or_else(|| msg("agent socket path needs a file name"))?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(parent)?;
        let metadata = directory.metadata()?;
        // SAFETY: geteuid takes no pointers and only reads the process uid.
        let uid = unsafe { geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
            return Err(msg("agent socket directory must be owner-controlled"));
        }
        let pinned = relative_to(&directory, Path::new(name));
        let listener = UnixListener::bind(&pinned)?;
        let inode = OpenOptions::new()
            .read(true)
            .custom_flags(O_PATH | O_NOFOLLOW)
            .open(&pinned)?;
        let metadata = inode.metadata()?;
        let socket = Self {
            _directory: directory,
            path: pinned,
            identity: (metadata.dev(), metadata.ino()),
            inode,
        };
        if !metadata.file_type().is_socket() || metadata.uid() != uid {
            return Err(msg("agent socket identity changed after bind"));
        }
        fs::set_permissions(proc_fd(&socket.inode), fs::Permissions::from_mode(0o600))?;
        if socket.inode.metadata()?.mode() & 0o077 != 0 {
            return Err(msg("agent socket is not owner-only"));
        }
        Ok((listener, socket))
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket() && (metadata.dev(), metadata.ino()) == self.identity
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn proc_fd(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn relative_to(file: &File, child: &Path) -> PathBuf {
    proc_fd(file).join(child)
}

struct Peer {
    pid: i32,
    proc_dir: File,
    thread: Option<PeerThread>,
}

struct PeerThread {
    tid: u32,
    path: PathBuf,
    identity: (u64, u64),
    _descriptor: File,
}

impl Peer {
    fn attach(stream: &UnixStream) -> Result<Self> {
        let pid = peer_pid(stream)?;
        let proc_dir = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(format!("/proc/{pid}"))?;
        Ok(Self {
            pid,
            proc_dir,
            thread: None,
        })
    }

    fn has_thread(&mut self, tid: u32) -> bool {
        if let Some(thread) = &self.thread {
            return tid == thread.tid
                && fs::metadata(&thread.path)
                    .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == thread.identity);
        }
        if tid == 0 || tid > i32::MAX as u32 {
            return false;
        }
        let path = relative_to(&self.proc_dir, Path::new(&format!("task/{tid}")));
        let Ok(descriptor) = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(&path)
        else {
            return false;
        };
        let Ok(metadata) = descriptor.metadata() else {
            return false;
        };
        self.thread = Some(PeerThread {
            tid,
            path,
            identity: (metadata.dev(), metadata.ino()),
            _descriptor: descriptor,
        });
        true
    }
}

fn spawn(
    listener: UnixListener,
    core: Arc<Core>,
    snaps: Arc<Mutex<Vec<Snap>>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || accept_loop(listener, &core, &snaps, &stop))
}

fn accept_loop(
    listener: UnixListener,
    core: &Arc<Core>,
    snaps: &Arc<Mutex<Vec<Snap>>>,
    stop: &Arc<AtomicBool>,
) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let mut peers: HashMap<i32, Weak<AtomicUsize>> = HashMap::new();
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    while !stop.load(Ordering::Relaxed) {
        reap_workers(&mut workers);
        peers.retain(|_, quota| quota.strong_count() != 0);
        match listener.accept() {
            Ok((mut stream, _)) if !stop.load(Ordering::Relaxed) => {
                if stream.set_nonblocking(true).is_err() {
                    continue;
                }
                let Ok(mut peer) = Peer::attach(&stream) else {
                    continue;
                };
                if workers.len() >= MAX_CONTEXTS {
                    let _ = deny(&mut stream, Instant::now() + FRAME_TIMEOUT);
                    continue;
                }
                let quota = peer_quota(&mut peers, peer.pid);
                let (core, snaps, stop) = (Arc::clone(core), Arc::clone(snaps), Arc::clone(stop));
                workers.push(thread::spawn(move || {
                    let _ = serve_ticketed(&mut stream, &core, &snaps, &stop, &mut peer, quota);
                }));
            }
            Ok(_) => break,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
}

fn reap_workers(workers: &mut Vec<JoinHandle<()>>) {
    while let Some(index) = workers.iter().position(JoinHandle::is_finished) {
        let _ = workers.swap_remove(index).join();
    }
}

fn peer_quota(peers: &mut HashMap<i32, Weak<AtomicUsize>>, pid: i32) -> Arc<AtomicUsize> {
    if let Some(quota) = peers.get(&pid).and_then(Weak::upgrade) {
        return quota;
    }
    let quota = Arc::new(AtomicUsize::new(0));
    peers.insert(pid, Arc::downgrade(&quota));
    quota
}

fn serve_ticketed(
    stream: &mut UnixStream,
    core: &Core,
    snaps: &Mutex<Vec<Snap>>,
    stop: &AtomicBool,
    peer: &mut Peer,
    quota: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    let Some(mut ticket) = greet(stream)? else {
        return Ok(());
    };
    let mut session = Session::new(quota);
    while !stop.load(Ordering::Relaxed) {
        let limit = Instant::now() + FRAME_TIMEOUT;
        let deadline = session
            .deadline()
            .map_or(limit, |deadline| deadline.min(limit));
        let Some(req) = read_request(stream, &ticket, deadline)? else {
            return deny(stream, deadline);
        };
        if !peer.has_thread(req.tid) {
            return deny(stream, deadline);
        }
        let Some(mut reply) = session.answer(core, &req, Instant::now()) else {
            return deny(stream, deadline);
        };
        if let Some(job) = reply.snapshot {
            push_snap(snaps, scan(peer, &job, &core.needles, deadline));
        }
        let next = fresh_ticket()?;
        reply.bytes.0.extend_from_slice(&next);
        write_until(stream, &reply.bytes.0, deadline)?;
        ticket = next;
    }
    Ok(())
}

fn greet(stream: &mut UnixStream) -> std::io::Result<Option<[u8; wire::TICKET_LEN]>> {
    let deadline = Instant::now() + FRAME_TIMEOUT;
    let mut hello = [0; wire::HDR];
    let (preface, remainder) = hello.split_at_mut(6);
    read_until(stream, preface, deadline)?;
    if preface != &wire::HELLO[..6] {
        deny(stream, deadline)?;
        return Ok(None);
    }
    read_until(stream, remainder, deadline)?;
    if hello != wire::HELLO {
        deny(stream, deadline)?;
        return Ok(None);
    }
    let ticket = fresh_ticket()?;
    let mut greeting = [wire::STATUS_OK; 5];
    greeting[1..].copy_from_slice(&(wire::TICKET_LEN as u32).to_le_bytes());
    write_until(stream, &greeting, deadline)?;
    write_until(stream, &ticket, deadline)?;
    Ok(Some(ticket))
}

fn fresh_ticket() -> std::io::Result<[u8; wire::TICKET_LEN]> {
    use rand::RngCore;

    let mut ticket = [0u8; wire::TICKET_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut ticket)
        .map_err(std::io::Error::other)?;
    Ok(ticket)
}

fn deny(stream: &mut UnixStream, deadline: Instant) -> std::io::Result<()> {
    write_until(stream, &[wire::STATUS_DENY, 0, 0, 0, 0], deadline)
}

fn push_snap(snaps: &Mutex<Vec<Snap>>, snap: Snap) {
    if let Ok(mut guard) = snaps.lock() {
        if guard.len() == MAX_CONTEXTS * 2 {
            guard.remove(0);
        }
        guard.push(snap);
    }
}

fn read_request(
    stream: &mut UnixStream,
    ticket: &[u8; wire::TICKET_LEN],
    deadline: Instant,
) -> std::io::Result<Option<wire::Request>> {
    let mut prefix = [0; wire::TICKET_LEN + wire::HDR];
    let received = read_some(stream, &mut prefix, deadline)?;
    if received < wire::TICKET_LEN {
        read_until(stream, &mut prefix[received..wire::TICKET_LEN], deadline)?;
    }
    let presented: &[u8; wire::TICKET_LEN] = prefix[..wire::TICKET_LEN].try_into().expect("ticket");
    if !crate::crypto::tags_equal(presented, ticket) {
        return Ok(None);
    }
    let rest = received.max(wire::TICKET_LEN);
    read_until(stream, &mut prefix[rest..], deadline)?;
    let header = &prefix[wire::TICKET_LEN..];
    let len = u32::from_le_bytes(
        header[wire::OFF_LEN..wire::OFF_LEN + 4]
            .try_into()
            .expect("4"),
    ) as usize;
    if header[..5] != wire::HELLO[..5] || !wire::valid_shape(header[5], len) {
        return Ok(None);
    }
    let mut body = vec![0u8; len];
    read_until(stream, &mut body, deadline)?;
    Ok(Some(wire::decode_fields(header, body)))
}

fn read_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let count = read_some(stream, bytes, deadline)?;
        bytes = &mut bytes[count..];
    }
    Ok(())
}

fn read_some(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> std::io::Result<usize> {
    use std::io::{Error, ErrorKind};

    loop {
        remaining(deadline)?;
        match stream.read(bytes) {
            Ok(0) => return Err(Error::from(ErrorKind::UnexpectedEof)),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                wait_ready(stream, POLLIN, deadline)?
            }
            result => return result,
        }
    }
}

fn write_until(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};

    while !bytes.is_empty() {
        remaining(deadline)?;
        match stream.write(bytes) {
            Ok(0) => return Err(Error::from(ErrorKind::WriteZero)),
            Ok(count) => bytes = &bytes[count..],
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                wait_ready(stream, POLLOUT, deadline)?
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn wait_ready(stream: &UnixStream, events: i16, deadline: Instant) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};

    let mut fd = PollFd {
        fd: stream.as_raw_fd(),
        events,
        revents: 0,
    };
    loop {
        let left = remaining(deadline)?.as_nanos().div_ceil(1_000_000);
        let timeout = i32::try_from(left).unwrap_or(i32::MAX);
        // SAFETY: the live stream owns this fd and poll may write one PollFd.
        match unsafe { poll(&mut fd, 1, timeout) } {
            0 => return Err(Error::from(ErrorKind::TimedOut)),
            rc if rc > 0 => return Ok(()),
            _ => {
                let err = Error::last_os_error();
                if err.kind() != ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }
}

fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))
}

fn peer_pid(stream: &UnixStream) -> Result<i32> {
    let mut cred = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = u32::try_from(std::mem::size_of::<Ucred>()).unwrap_or(0);
    // SAFETY: `cred` is a `Ucred` and `len` is its size. `getsockopt` writes that object.
    let rc = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut cred as *mut Ucred).cast(),
            &mut len,
        )
    };
    // SAFETY: `geteuid` takes no pointers and only reads the process uid.
    let uid = unsafe { geteuid() };
    if rc != 0 || len as usize != std::mem::size_of::<Ucred>() || cred.pid <= 0 || cred.uid != uid {
        return Err(msg("agent peer is not the owner"));
    }
    Ok(cred.pid)
}

fn scan(peer: &Peer, job: &GuestSnap, needles: &[[u8; super::KEY_LEN]], deadline: Instant) -> Snap {
    let fail = Snap {
        resident: job.resident,
        key_hit: true,
        plain_hit: false,
    };
    let Some(regions) = map_regions(peer) else {
        return fail;
    };
    let Ok(mut mem) = File::open(relative_to(&peer.proc_dir, Path::new("mem"))) else {
        return fail;
    };
    search_regions(&mut mem, &regions, job, needles, deadline).unwrap_or(fail)
}

fn search_regions(
    mem: &mut File,
    regions: &[(u64, usize)],
    job: &GuestSnap,
    needles: &[[u8; super::KEY_LEN]],
    deadline: Instant,
) -> Option<Snap> {
    let mut key_hit = false;
    let mut plain_hit = false;
    let mut saw = false;
    let mut budget = MEMORY_BUDGET;
    let heads = needle_heads(needles);
    for &(start, len) in regions {
        if Instant::now() >= deadline || len > budget {
            return None;
        }
        budget -= len;
        let mut buf = WipeBuffer(vec![0u8; len]);
        if read_at(mem, start, &mut buf.0).is_err() {
            continue;
        }
        saw = true;
        key_hit = key_hit || scan_heads(&buf.0, needles, &heads);
        plain_hit = plain_hit || (!job.plain.0.is_empty() && contains_bytes(&buf.0, &job.plain.0));
    }
    if !saw {
        return None;
    }
    Some(Snap {
        resident: job.resident,
        key_hit,
        plain_hit,
    })
}

fn needle_heads(needles: &[[u8; super::KEY_LEN]]) -> HashMap<u64, Vec<usize>> {
    let mut heads: HashMap<u64, Vec<usize>> = HashMap::new();
    for (index, needle) in needles.iter().enumerate() {
        let head = u64::from_le_bytes(needle[..8].try_into().unwrap_or([0; 8]));
        heads.entry(head).or_default().push(index);
    }
    heads
}

fn scan_heads(
    hay: &[u8],
    needles: &[[u8; super::KEY_LEN]],
    heads: &HashMap<u64, Vec<usize>>,
) -> bool {
    if hay.len() < super::KEY_LEN {
        return false;
    }
    let last = hay.len() - super::KEY_LEN;
    for at in 0..=last {
        let head = u64::from_le_bytes(hay[at..at + 8].try_into().unwrap_or([0; 8]));
        let Some(hits) = heads.get(&head) else {
            continue;
        };
        if hits
            .iter()
            .any(|&index| hay[at..at + super::KEY_LEN] == needles[index])
        {
            return true;
        }
    }
    false
}

fn map_regions(peer: &Peer) -> Option<Vec<(u64, usize)>> {
    let mut text = String::new();
    File::open(relative_to(&peer.proc_dir, Path::new("maps")))
        .ok()?
        .take(1024 * 1024 + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() > 1024 * 1024 {
        return None;
    }
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(region) = parse_region(line) {
            out.push(region);
        }
    }
    Some(out)
}

fn parse_region(line: &str) -> Option<(u64, usize)> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?;
    if !perms.starts_with('r') {
        return None;
    }
    let (lo, hi) = range.split_once('-')?;
    let start = u64::from_str_radix(lo, 16).ok()?;
    let end = u64::from_str_radix(hi, 16).ok()?;
    let len = usize::try_from(end.checked_sub(start)?).ok()?;
    if len == 0 || len > 32 * 1024 * 1024 {
        return None;
    }
    Some((start, len))
}

fn read_at(file: &mut File, addr: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, addr)
}
