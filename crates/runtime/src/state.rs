use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::Instant;

use vmkek_protocol::{Id, VerifiedProgram, VmForm, MAX_ACTIVE_CONTEXTS, MAX_VM_MEMORY_BYTES};

use crate::{Status, VmkRequestId, VmkRuntime};

static QUOTA: Mutex<Quota> = Mutex::new(Quota {
    active: 0,
    bytes: 0,
});
static RUNTIMES: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    Mutex::new(Registry {
        next: 1,
        live: HashMap::new(),
    })
});

struct Quota {
    active: usize,
    bytes: usize,
}

pub(crate) struct Reservation {
    bytes: usize,
    active: bool,
}

impl Reservation {
    pub(crate) fn new(bytes: usize, active: bool) -> Result<Self, Status> {
        let mut quota = lock(&QUOTA);
        let total = quota
            .bytes
            .checked_add(bytes)
            .ok_or(Status::ResourceLimit)?;
        if total > MAX_VM_MEMORY_BYTES || active && quota.active >= MAX_ACTIVE_CONTEXTS {
            return Err(Status::ResourceLimit);
        }
        quota.bytes = total;
        quota.active += usize::from(active);
        Ok(Self { bytes, active })
    }

    pub(crate) fn shrink(&mut self, bytes: usize) -> Result<(), Status> {
        let delta = self.bytes.checked_sub(bytes).ok_or(Status::Internal)?;
        lock(&QUOTA).bytes -= delta;
        self.bytes = bytes;
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut quota = lock(&QUOTA);
        quota.bytes -= self.bytes;
        quota.active -= usize::from(self.active);
    }
}

struct Registry {
    next: VmkRuntime,
    live: HashMap<VmkRuntime, Arc<Runtime>>,
}

pub(crate) struct Runtime {
    state: Mutex<RuntimeState>,
    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    worker: Mutex<Option<crate::online::Worker>>,
}

pub(crate) struct Generation {
    identity: (Id, VmForm),
    pub code: GenerationCode,
    pub deadline_ms: u32,
    active_limit: usize,
    _reservation: Reservation,
}

pub(crate) enum GenerationCode {
    Lab(VerifiedProgram),
    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    Online(Box<crate::online::CiphertextFrame>),
}

impl Generation {
    fn id(&self) -> Id {
        self.identity.0
    }

    #[cfg(all(any(windows, all(target_os = "linux", target_arch = "x86_64")), test))]
    pub(crate) fn identity(&self) -> (Id, VmForm) {
        self.identity
    }

    pub(crate) fn new(
        id: Id,
        form: VmForm,
        program: VerifiedProgram,
        deadline_ms: u32,
        active_limit: usize,
        reservation: Reservation,
    ) -> Self {
        Self {
            identity: (id, form),
            code: GenerationCode::Lab(program),
            deadline_ms,
            active_limit,
            _reservation: reservation,
        }
    }
    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn online(
        id: Id,
        form: VmForm,
        code: crate::online::CiphertextFrame,
        deadline_ms: u32,
        active_limit: usize,
        reservation: Reservation,
    ) -> Self {
        Self {
            identity: (id, form),
            code: GenerationCode::Online(Box::new(code)),
            deadline_ms,
            active_limit,
            _reservation: reservation,
        }
    }
}

struct ActiveGeneration {
    generation: Arc<Generation>,
    lease: Option<LeaseAuthority>,
}

#[derive(Clone, Copy)]
pub(crate) struct LeaseAuthority {
    expires: Instant,
    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    token: Option<vmkek_client::LeaseToken>,
}

#[cfg(test)]
impl From<Instant> for LeaseAuthority {
    fn from(expires: Instant) -> Self {
        Self {
            expires,
            #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
            token: None,
        }
    }
}

#[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
impl From<vmkek_client::LeaseToken> for LeaseAuthority {
    fn from(token: vmkek_client::LeaseToken) -> Self {
        Self {
            expires: token.expires(),
            token: Some(token),
        }
    }
}

struct ActiveCall {
    generation: Id,
    cancelled: Arc<AtomicBool>,
    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    signal: Arc<tokio::sync::Notify>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SwapTicket(u64);

struct RuntimeState {
    closed: bool,
    terminal: Option<Status>,
    active: Option<ActiveGeneration>,
    pending: Option<SwapTicket>,
    #[cfg(any(windows, test, all(target_os = "linux", target_arch = "x86_64")))]
    next_ticket: u64,
    draining: HashSet<Id>,
    calls: HashMap<VmkRequestId, ActiveCall>,
}

impl Runtime {
    pub(crate) fn from_generation(generation: Generation, lease: Option<LeaseAuthority>) -> Self {
        Self {
            state: Mutex::new(RuntimeState {
                closed: false,
                terminal: None,
                active: Some(ActiveGeneration {
                    generation: Arc::new(generation),
                    lease,
                }),
                pending: None,
                #[cfg(any(windows, test, all(target_os = "linux", target_arch = "x86_64")))]
                next_ticket: 1,
                draining: HashSet::new(),
                calls: HashMap::new(),
            }),
            #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
            worker: Mutex::new(None),
        }
    }

    pub(crate) fn begin(self: &Arc<Self>, id: VmkRequestId) -> Result<Call, Status> {
        let mut state = lock(&self.state);
        if state.closed {
            return Err(Status::NotFound);
        }
        state.authority()?;
        if state.pending.is_some() {
            return Err(Status::Unavailable);
        }
        let active = state.active.as_ref().ok_or(Status::Internal)?;
        let generation = active.generation.clone();
        let lease = active.lease;
        if state.calls.contains_key(&id) {
            return Err(Status::InvalidArgument);
        }
        if state
            .calls
            .values()
            .filter(|call| call.generation == generation.id())
            .count()
            >= generation.active_limit
        {
            return Err(Status::ResourceLimit);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
        let signal = Arc::new(tokio::sync::Notify::new());
        state.calls.insert(
            id,
            ActiveCall {
                generation: generation.id(),
                cancelled: cancelled.clone(),
                #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
                signal: signal.clone(),
            },
        );
        Ok(Call {
            id,
            cancelled,
            generation,
            lease: lease.map(|authority| authority.expires),
            #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
            key_token: lease.and_then(|authority| authority.token),
            #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
            signal,
            runtime: Arc::clone(self),
        })
    }

    pub(crate) fn cancel(&self, id: VmkRequestId) -> Result<(), Status> {
        let state = lock(&self.state);
        let call = state
            .calls
            .get(&id)
            .filter(|_| !state.closed)
            .ok_or(Status::NotFound)?;
        call.cancelled.store(true, Ordering::Release);
        #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
        call.signal.notify_one();
        Ok(())
    }

    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn attach_worker(&self, worker: crate::online::Worker) {
        *lock(&self.worker) = Some(worker);
    }

    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn send_key_request(
        &self,
        request: crate::online::KeyRequest,
    ) -> Result<(), Status> {
        lock(&self.worker)
            .as_ref()
            .ok_or(Status::Unavailable)?
            .send_key_request(request)
    }

    #[cfg(windows)]
    pub(crate) fn stop_for_observation(&self, notify: impl FnOnce(vmkek_client::LeaseToken)) {
        self.stop_local(|authority| {
            if let Some(token) = authority.token {
                notify(token);
            }
        });
    }

    #[cfg(any(windows, test))]
    fn stop_local(&self, notify: impl FnOnce(LeaseAuthority)) -> bool {
        let mut state = lock(&self.state);
        if state.closed || state.authority().is_err() {
            return false;
        }
        let Some(authority) = state.active.as_ref().and_then(|active| active.lease) else {
            return false;
        };
        state.invalidate(Status::Denied);
        // The callback only sends a nonblocking one-shot notification. No I/O
        // occurs while holding the runtime state lock.
        notify(authority);
        true
    }

    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn send_receipt_request(
        &self,
        request: crate::online::ReceiptRequest,
    ) -> Result<(), Status> {
        lock(&self.worker)
            .as_ref()
            .ok_or(Status::Unavailable)?
            .send_receipt_request(request)
    }

    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn invalidate_receipt_authority(
        &self,
        token: vmkek_client::LeaseToken,
        status: Status,
    ) -> bool {
        let mut state = lock(&self.state);
        if state
            .active
            .as_ref()
            .and_then(|active| active.lease)
            .and_then(|lease| lease.token)
            == Some(token)
        {
            state.invalidate(status);
            true
        } else {
            false
        }
    }

    #[cfg(any(windows, test, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn set_lease(&self, authority: impl Into<LeaseAuthority>) -> Result<(), Status> {
        let mut state = lock(&self.state);
        state.require_active()?;
        if state.pending.is_some() {
            return Err(Status::Unavailable);
        }
        state.update_lease(authority.into())
    }

    #[cfg(any(windows, test, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn start_swap(&self) -> Result<SwapTicket, Status> {
        let mut state = lock(&self.state);
        state.require_active()?;
        if state.pending.is_some() {
            return Err(Status::Unavailable);
        }
        let ticket = SwapTicket(state.next_ticket);
        state.next_ticket = state
            .next_ticket
            .checked_add(1)
            .ok_or(Status::ResourceLimit)?;
        state.pending = Some(ticket);
        Ok(ticket)
    }

    #[cfg(any(windows, test, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn continue_generation(
        &self,
        ticket: SwapTicket,
        authority: impl Into<LeaseAuthority>,
    ) -> Result<(), Status> {
        let authority = authority.into();
        let mut state = lock(&self.state);
        state.check_pending(ticket, authority.expires)?;
        state.update_lease(authority)?;
        state.pending = None;
        Ok(())
    }

    #[cfg(any(windows, test, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn install_generation(
        &self,
        ticket: SwapTicket,
        generation: Generation,
        authority: impl Into<LeaseAuthority>,
    ) -> Result<(), Status> {
        let authority = authority.into();
        let mut state = lock(&self.state);
        state.check_pending(ticket, authority.expires)?;
        let active = state.active.as_ref().ok_or(Status::Internal)?;
        let old_id = active.generation.id();
        if generation.id() == [0; 16]
            || generation.id() == old_id
            || state.draining.contains(&generation.id())
        {
            return Err(Status::InvalidPackage);
        }
        if state.calls.values().any(|call| call.generation == old_id) {
            state.draining.insert(old_id);
        }
        state.active = Some(ActiveGeneration {
            generation: Arc::new(generation),
            lease: Some(authority),
        });
        state.pending = None;
        Ok(())
    }

    #[cfg(any(windows, test, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn invalidate(&self, status: Status) {
        lock(&self.state).invalidate(status);
    }

    fn close(&self) {
        let mut state = lock(&self.state);
        state.closed = true;
        state.invalidate(Status::Cancelled);
    }
}

impl RuntimeState {
    fn authority(&mut self) -> Result<(), Status> {
        if let Some(status) = self.terminal {
            return Err(status);
        }
        if self
            .active
            .as_ref()
            .and_then(|active| active.lease)
            .is_some_and(|authority| Instant::now() >= authority.expires)
        {
            self.invalidate(Status::Expired);
            return Err(Status::Expired);
        }
        Ok(())
    }

    #[cfg(any(windows, test, all(target_os = "linux", target_arch = "x86_64")))]
    fn require_active(&mut self) -> Result<(), Status> {
        if self.closed {
            return Err(Status::Cancelled);
        }
        self.authority()
    }

    #[cfg(any(windows, test, all(target_os = "linux", target_arch = "x86_64")))]
    fn check_pending(&mut self, ticket: SwapTicket, expires: Instant) -> Result<(), Status> {
        self.require_active()?;
        if self.pending != Some(ticket) {
            return Err(Status::Cancelled);
        }
        if Instant::now() >= expires {
            self.invalidate(Status::Expired);
            return Err(Status::Expired);
        }
        Ok(())
    }

    #[cfg(any(windows, test, all(target_os = "linux", target_arch = "x86_64")))]
    fn update_lease(&mut self, authority: LeaseAuthority) -> Result<(), Status> {
        if Instant::now() >= authority.expires {
            self.invalidate(Status::Expired);
            return Err(Status::Expired);
        }
        self.active.as_mut().ok_or(Status::Internal)?.lease = Some(authority);
        Ok(())
    }

    fn remove_call(&mut self, id: VmkRequestId, generation: Id) {
        self.calls.remove(&id);
        if self.draining.contains(&generation)
            && !self
                .calls
                .values()
                .any(|call| call.generation == generation)
        {
            self.draining.remove(&generation);
        }
    }

    fn invalidate(&mut self, status: Status) {
        self.terminal.get_or_insert(status);
        self.pending = None;
        self.active = None;
        self.draining.clear();
        for call in self.calls.values() {
            call.cancelled.store(true, Ordering::Release);
            #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
            call.signal.notify_one();
        }
    }
}

pub(crate) struct Call {
    id: VmkRequestId,
    pub cancelled: Arc<AtomicBool>,
    pub generation: Arc<Generation>,
    pub lease: Option<Instant>,
    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    pub key_token: Option<vmkek_client::LeaseToken>,
    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    pub signal: Arc<tokio::sync::Notify>,
    runtime: Arc<Runtime>,
}

impl Call {
    pub(crate) fn commit(
        &self,
        publish: impl FnOnce() -> Result<(), Status>,
    ) -> Result<(), Status> {
        self.commit_checked(|_| publish())
    }

    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn commit_receipt(
        &self,
        deadline: Instant,
        receipt: vmkek_protocol::OperationReceipt,
    ) -> Result<vmkek_protocol::OperationReceipt, Status> {
        self.commit_checked(|state| {
            let token = state
                .active
                .as_ref()
                .and_then(|active| active.lease)
                .and_then(|lease| lease.token);
            if state.pending.is_some() || token.is_none() || token != self.key_token {
                return Err(Status::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(Status::ResourceLimit);
            }
            Ok(receipt)
        })
    }

    fn commit_checked<T>(
        &self,
        publish: impl FnOnce(&RuntimeState) -> Result<T, Status>,
    ) -> Result<T, Status> {
        let mut state = lock(&self.runtime.state);
        if state.closed {
            return Err(Status::Cancelled);
        }
        state.authority()?;
        if self.lease.is_some_and(|expires| Instant::now() >= expires) {
            return Err(Status::Expired);
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Err(Status::Cancelled);
        }
        let result = publish(&state)?;
        state.remove_call(self.id, self.generation.id());
        Ok(result)
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        let mut state = lock(&self.runtime.state);
        if state
            .calls
            .get(&self.id)
            .is_some_and(|call| Arc::ptr_eq(&call.cancelled, &self.cancelled))
        {
            #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
            self.signal.notify_one();
            state.remove_call(self.id, self.generation.id());
        }
    }
}

pub(crate) fn insert(runtime: impl Into<Arc<Runtime>>) -> Result<VmkRuntime, Status> {
    let mut registry = lock(&RUNTIMES);
    if registry.live.len() >= MAX_ACTIVE_CONTEXTS {
        return Err(Status::ResourceLimit);
    }
    let handle = registry.next;
    registry.next = handle.checked_add(1).ok_or(Status::ResourceLimit)?;
    registry.live.insert(handle, runtime.into());
    Ok(handle)
}

pub(crate) fn get(handle: VmkRuntime) -> Result<Arc<Runtime>, Status> {
    lock(&RUNTIMES)
        .live
        .get(&handle)
        .cloned()
        .ok_or(Status::NotFound)
}

pub(crate) fn shutdown(handle: VmkRuntime) -> Result<(), Status> {
    let mut registry = lock(&RUNTIMES);
    let runtime = registry.live.get(&handle).ok_or(Status::NotFound)?;
    // Registry-to-state lock order keeps NotFound behind the point at which
    // the runtime forbids publication, including for calls with a cloned Arc.
    runtime.close();
    let retired = registry.live.remove(&handle).ok_or(Status::Internal)?;
    drop(registry);
    #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
    drop(lock(&retired.worker).take());
    drop(retired);
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // RAII restores active-call accounting while unwinding. A Rust panic may
    // poison a mutex, but its protected mutations keep valid Rust state.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::TryLockError;
    use std::thread;
    use std::time::{Duration, Instant};

    use sha2::{Digest as _, Sha256};
    use vmkek_protocol::lab::{Instruction, LabProgram};
    use vmkek_protocol::{Budgets, Profile, VmDescriptor, VmForm};

    use super::*;

    fn fixture_generation(id: Id) -> Generation {
        let program = LabProgram {
            arguments: vec![],
            result: None,
            instructions: vec![Instruction::Return],
        }
        .encode()
        .unwrap();
        let descriptor = VmDescriptor {
            abi_version: vmkek_protocol::ABI_VERSION,
            app_id: [1; 16],
            build_id: [2; 16],
            function_id: [3; 16],
            generation_id: [4; 16],
            form: VmForm::Stack,
            depth: 2,
            capabilities: vec![],
            program_sha256: Sha256::digest(&program).into(),
            budgets: Budgets::default(),
            profile: Profile::Lab,
            extensions: vec![],
        };
        let verified = VerifiedProgram::verify(&descriptor, &program).unwrap();
        let reserved = Reservation::new(verified.memory_bytes(), false).unwrap();
        Generation::new(id, descriptor.form, verified, 5_000, 1, reserved)
    }

    fn fixture() -> Runtime {
        Runtime::from_generation(fixture_generation([0; 16]), None)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn fork_child_returns_before_the_inherited_registry_lock() {
        crate::process_fence().unwrap();
        let _locked = lock(&RUNTIMES);
        // SAFETY: the child calls only the atomic PID fence and _exit.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let result = crate::vmk_cancel(1, VmkRequestId { bytes: [1; 16] });
            unsafe { libc::_exit(i32::from(result != Status::Unavailable as u32)) }
        }
        let until = Instant::now() + Duration::from_secs(2);
        let mut status = 0;
        loop {
            // SAFETY: child is the owned fork result; status is writable.
            let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
            if waited == child {
                assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
                break;
            }
            assert_eq!(waited, 0);
            if Instant::now() >= until {
                // SAFETY: child is our still-running owned test process.
                unsafe {
                    libc::kill(child, libc::SIGKILL);
                    libc::waitpid(child, &mut status, 0);
                }
                panic!("fork child touched the inherited registry lock");
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn planned_swap_pins_old_frame_and_retires_after_drain() {
        let old_id = [1; 16];
        let new_id = [2; 16];
        let old_deadline = Instant::now() + Duration::from_secs(10);
        let new_deadline = old_deadline + Duration::from_secs(10);
        let runtime = Arc::new(Runtime::from_generation(
            fixture_generation(old_id),
            Some(old_deadline.into()),
        ));
        let old = runtime.begin(VmkRequestId { bytes: [1; 16] }).unwrap();
        let retired = Arc::downgrade(&old.generation);
        let ticket = runtime.start_swap().unwrap();
        let racer = runtime.clone();
        let attempt = thread::spawn(move || {
            assert!(matches!(
                racer.begin(VmkRequestId { bytes: [2; 16] }),
                Err(Status::Unavailable)
            ));
        });
        attempt.join().unwrap();
        runtime
            .install_generation(ticket, fixture_generation(new_id), new_deadline)
            .unwrap();
        let next = runtime.begin(VmkRequestId { bytes: [2; 16] }).unwrap();
        assert_eq!(
            (old.generation.id(), old.lease),
            (old_id, Some(old_deadline))
        );
        assert_eq!(
            (next.generation.id(), next.lease),
            (new_id, Some(new_deadline))
        );
        assert!(lock(&runtime.state).draining.contains(&old_id));
        old.commit(|| Ok(())).unwrap();
        drop(old);
        assert!(retired.upgrade().is_none());
        assert!(!lock(&runtime.state).draining.contains(&old_id));
    }

    #[test]
    fn cancelled_old_frame_and_network_failure_cannot_publish_or_install() {
        let deadline = Instant::now() + Duration::from_secs(10);
        let runtime = Arc::new(Runtime::from_generation(
            fixture_generation([1; 16]),
            Some(deadline.into()),
        ));
        let id = VmkRequestId { bytes: [1; 16] };
        let old = runtime.begin(id).unwrap();
        let ticket = runtime.start_swap().unwrap();
        let racer = runtime.clone();
        thread::spawn(move || racer.cancel(id).unwrap())
            .join()
            .unwrap();
        assert_eq!(
            old.commit(|| panic!("cancelled frame cannot publish")),
            Err(Status::Cancelled)
        );
        let racer = runtime.clone();
        thread::spawn(move || racer.invalidate(Status::Unavailable))
            .join()
            .unwrap();
        assert_eq!(
            runtime.install_generation(ticket, fixture_generation([2; 16]), deadline),
            Err(Status::Unavailable)
        );
        assert!(matches!(
            runtime.begin(VmkRequestId { bytes: [2; 16] }),
            Err(Status::Unavailable)
        ));
        let state = lock(&runtime.state);
        assert!(state.pending.is_none());
        assert!(state.active.is_none());
        assert!(state.draining.is_empty());
    }

    #[test]
    fn no_choice_resumes_original_generation_after_renewal() {
        let deadline = Instant::now() + Duration::from_secs(10);
        let next = deadline + Duration::from_secs(10);
        let runtime = Arc::new(Runtime::from_generation(
            fixture_generation([1; 16]),
            Some(deadline.into()),
        ));
        let ticket = runtime.start_swap().unwrap();
        assert_eq!(runtime.set_lease(next), Err(Status::Unavailable));
        runtime.continue_generation(ticket, next).unwrap();
        let call = runtime.begin(VmkRequestId { bytes: [1; 16] }).unwrap();
        assert_eq!((call.generation.id(), call.lease), ([1; 16], Some(next)));
        assert_eq!(
            runtime.install_generation(ticket, fixture_generation([2; 16]), next),
            Err(Status::Cancelled)
        );
    }

    #[test]
    fn local_observation_stops_pending_swap_and_cancels_held_call_before_notification() {
        let runtime = Arc::new(fixture());
        runtime
            .set_lease(Instant::now() + Duration::from_secs(3))
            .unwrap();
        let id = VmkRequestId { bytes: [63; 16] };
        let call = runtime.begin(id).unwrap();
        let ticket = runtime.start_swap().unwrap();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let observer = runtime.clone();
        thread::spawn(move || assert!(observer.stop_local(|_| send.try_send(()).unwrap())))
            .join()
            .unwrap();
        receive.try_recv().unwrap();
        assert!(call.cancelled.load(Ordering::Acquire));
        assert_eq!(
            call.commit(|| panic!("stopped output must remain unpublished")),
            Err(Status::Denied)
        );
        assert_eq!(
            runtime.continue_generation(ticket, Instant::now() + Duration::from_secs(3)),
            Err(Status::Denied)
        );
        assert!(matches!(
            runtime.begin(VmkRequestId { bytes: [64; 16] }),
            Err(Status::Denied)
        ));
        assert!(!runtime.stop_local(|_| panic!("local stop is one-shot")));
    }

    #[test]
    fn expired_online_lease_cancels_active_calls_and_forbids_publication() {
        let runtime = Arc::new(fixture());
        let expires = Instant::now() + Duration::from_secs(10);
        lock(&runtime.state).active.as_mut().unwrap().lease = Some(expires.into());
        let call = runtime.begin(VmkRequestId { bytes: [1; 16] }).unwrap();
        assert_eq!(call.lease, Some(expires));
        lock(&runtime.state).active.as_mut().unwrap().lease = Some(Instant::now().into());
        assert_eq!(
            call.commit(|| panic!("expired authority cannot publish")),
            Err(Status::Expired)
        );
        assert!(call.cancelled.load(Ordering::Acquire));
        assert!(lock(&runtime.state).active.is_none());
        assert!(matches!(
            runtime.begin(VmkRequestId { bytes: [2; 16] }),
            Err(Status::Expired)
        ));
    }

    #[test]
    fn shutdown_closes_before_other_lookups_can_see_a_missing_handle() {
        let handle = insert(fixture()).unwrap();
        let runtime = get(handle).unwrap();
        let id = VmkRequestId { bytes: [1; 16] };
        let call = runtime.begin(id).unwrap();
        assert!(matches!(
            runtime.begin(VmkRequestId { bytes: [2; 16] }),
            Err(Status::ResourceLimit)
        ));
        let state = lock(&runtime.state);
        let shutdown = thread::spawn(move || super::shutdown(handle));
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match RUNTIMES.try_lock() {
                Ok(registry) => assert!(registry.live.contains_key(&handle)),
                Err(TryLockError::WouldBlock) => break,
                Err(TryLockError::Poisoned(_)) => panic!("runtime registry poisoned"),
            }
            assert!(
                Instant::now() < deadline,
                "shutdown did not lock the registry"
            );
            thread::yield_now();
        }
        drop(state);
        shutdown.join().unwrap().unwrap();
        assert!(matches!(get(handle), Err(Status::NotFound)));
        assert_eq!(
            call.commit(|| panic!("closed runtime cannot publish")),
            Err(Status::Cancelled)
        );
    }
}
