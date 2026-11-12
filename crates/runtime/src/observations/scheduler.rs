use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};

use crate::Status;

pub const DEBUGGER_INTERVAL: Duration = Duration::from_millis(250);
pub const INTEGRITY_INTERVAL: Duration = Duration::from_millis(500);
pub const SHUTDOWN_WAIT: Duration = Duration::from_millis(100);
pub const MAX_WORKERS: usize = 16;
#[cfg(not(windows))]
const WORKER_STACK_BYTES: usize = 256 * 1024;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

struct Slot;

impl Slot {
    fn acquire() -> Result<Self, Status> {
        ACTIVE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < MAX_WORKERS).then_some(count + 1)
            })
            .map(|_| Self)
            .map_err(|_| Status::ResourceLimit)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct IntegritySchedule {
    next: Duration,
}

impl IntegritySchedule {
    pub fn due(&mut self, now: Duration) -> bool {
        if now < self.next {
            return false;
        }
        self.next = now.saturating_add(INTEGRITY_INTERVAL);
        true
    }
}

/// An observer worker with bounded shutdown. A call that is already blocked
/// in the OS retains its slot until the work actually returns.
pub struct ObservationWorker {
    stop: mpsc::SyncSender<()>,
    done: mpsc::Receiver<()>,
    thread_id: Arc<Mutex<Option<thread::ThreadId>>>,
    cancelled: Arc<AtomicBool>,
}

pub struct WorkerControl {
    stop: mpsc::Receiver<()>,
    cancelled: Arc<AtomicBool>,
}

impl WorkerControl {
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// False when cancellation interrupts the wait.
    pub fn wait(&self, duration: Duration) -> bool {
        !self.is_cancelled()
            && matches!(
                self.stop.recv_timeout(duration),
                Err(mpsc::RecvTimeoutError::Timeout)
            )
            && !self.is_cancelled()
    }
}

impl ObservationWorker {
    pub fn start(work: impl FnOnce(WorkerControl) + Send + 'static) -> Result<Self, Status> {
        let slot = Slot::acquire()?;
        let (stop, stopped) = mpsc::sync_channel(1);
        let (finished, done) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let thread_id = Arc::new(Mutex::new(None));
        let worker_id = Arc::clone(&thread_id);
        launch(move || {
            // Disconnection also wakes the owner on an unwind.
            let completion = finished;
            let active = slot;
            *crate::state::lock(&worker_id) = Some(thread::current().id());
            work(WorkerControl {
                stop: stopped,
                cancelled: worker_cancelled,
            });
            drop(active);
            let _ = completion.try_send(());
        })?;
        Ok(Self {
            stop,
            done,
            thread_id,
            cancelled,
        })
    }
}

impl Drop for ObservationWorker {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.stop.try_send(());
        if *crate::state::lock(&self.thread_id) != Some(thread::current().id()) {
            let _ = self.done.recv_timeout(SHUTDOWN_WAIT);
        }
    }
}

#[cfg(not(windows))]
fn launch(work: impl FnOnce() + Send + 'static) -> Result<(), Status> {
    thread::Builder::new()
        .name("vmkek-observation".into())
        .stack_size(WORKER_STACK_BYTES)
        .spawn(work)
        .map(|_| ())
        .map_err(|_| Status::ResourceLimit)
}

#[cfg(windows)]
fn launch(work: impl FnOnce() + Send + 'static) -> Result<(), Status> {
    windows_worker::submit(Box::new(work))
}

#[cfg(windows)]
mod windows_worker {
    use std::{
        ffi::c_void,
        panic::{catch_unwind, AssertUnwindSafe},
        ptr,
    };

    use crate::Status;

    type Handle = *mut c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleExW(flags: u32, address: *const u16, module: *mut Handle) -> i32;
        fn FreeLibrary(module: Handle) -> i32;
        fn TrySubmitThreadpoolCallback(
            callback: unsafe extern "system" fn(Handle, Handle),
            context: Handle,
            environment: Handle,
        ) -> i32;
        fn CallbackMayRunLong(instance: Handle) -> i32;
        fn FreeLibraryWhenCallbackReturns(instance: Handle, module: Handle);
    }

    struct Task {
        module: Handle,
        work: Box<dyn FnOnce() + Send>,
    }

    pub(super) fn submit(work: Box<dyn FnOnce() + Send>) -> Result<(), Status> {
        const FROM_ADDRESS: u32 = 4;
        let mut module = ptr::null_mut();
        // SAFETY: The callback address is in this currently loaded module,
        // and Windows writes its held reference into module.
        if unsafe { GetModuleHandleExW(FROM_ADDRESS, callback as *const u16, &mut module) } == 0 {
            return Err(Status::Unavailable);
        }
        let task = Box::into_raw(Box::new(Task { module, work }));
        // SAFETY: On success exactly one callback owns task. On failure no
        // callback can run, so this thread releases both owned resources.
        if unsafe { TrySubmitThreadpoolCallback(callback, task.cast(), ptr::null_mut()) } == 0 {
            unsafe {
                drop(Box::from_raw(task));
                FreeLibrary(module);
            }
            return Err(Status::ResourceLimit);
        }
        Ok(())
    }

    unsafe extern "system" fn callback(instance: Handle, context: Handle) {
        // SAFETY: A successful submission transfers the Box and loader
        // reference to this one callback. Windows releases the reference
        // after the callback epilogue, even if the Rust owner timed out.
        let task = unsafe { Box::from_raw(context.cast::<Task>()) };
        unsafe {
            FreeLibraryWhenCallbackReturns(instance, task.module);
            CallbackMayRunLong(instance);
        }
        let _ = catch_unwind(AssertUnwindSafe(task.work)).map_err(std::mem::forget);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    static WORKER_TEST: Mutex<()> = Mutex::new(());

    #[test]
    fn elapsed_gap_is_one_due_scan_without_catch_up() {
        let mut schedule = IntegritySchedule::default();
        assert!(schedule.due(Duration::ZERO));
        assert!(!schedule.due(Duration::from_millis(499)));
        let resumed = Duration::from_secs(300);
        assert!(schedule.due(resumed));
        assert!(!schedule.due(resumed));
        assert!(!schedule.due(resumed + Duration::from_millis(499)));
        assert!(schedule.due(resumed + INTEGRITY_INTERVAL));
    }

    #[test]
    fn cancellation_wakes_idle_worker_and_bounds_blocked_worker() {
        let _serial = crate::state::lock(&WORKER_TEST);
        let (ready, started) = mpsc::sync_channel(1);
        let (send, completed) = mpsc::sync_channel(1);
        let idle = ObservationWorker::start(move |control| {
            ready.send(()).unwrap();
            assert!(!control.wait(Duration::from_secs(60)));
            send.send(()).unwrap();
        })
        .unwrap();
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(idle);
        completed.recv_timeout(Duration::from_secs(1)).unwrap();

        let (ready, started) = mpsc::sync_channel(1);
        let (release, blocked) = mpsc::sync_channel(1);
        let (send, completed) = mpsc::sync_channel(1);
        let active = ObservationWorker::start(move |control| {
            ready.send(()).unwrap();
            blocked.recv().unwrap();
            send.send(control.is_cancelled()).unwrap();
        })
        .unwrap();
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        let before = Instant::now();
        drop(active);
        assert!(before.elapsed() < Duration::from_millis(500));
        release.send(()).unwrap();
        assert!(completed.recv_timeout(Duration::from_secs(1)).unwrap());
    }

    #[test]
    fn cancelled_blocking_work_retains_the_last_process_slot() {
        let _serial = crate::state::lock(&WORKER_TEST);
        let other_slots: Vec<_> = (1..MAX_WORKERS).map(|_| Slot::acquire().unwrap()).collect();
        let (ready, started) = mpsc::sync_channel(1);
        let (release, blocked) = mpsc::sync_channel(1);
        let worker = ObservationWorker::start(move |control| {
            ready.send(()).unwrap();
            blocked.recv().unwrap();
            assert!(control.is_cancelled());
        })
        .unwrap();
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(worker);
        for _ in 0..3 {
            assert!(matches!(
                ObservationWorker::start(|_| {}),
                Err(Status::ResourceLimit)
            ));
        }
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while ACTIVE.load(Ordering::Relaxed) == MAX_WORKERS {
            assert!(Instant::now() < deadline, "worker slot not reclaimed");
            thread::sleep(Duration::from_millis(1));
        }
        assert!(Slot::acquire().is_ok());
        drop(other_slots);
    }
}
