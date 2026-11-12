use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{wire, Core, FuncPack, GuestSnap};
use crate::secret::WipeBuffer;
use crate::vm;

pub(super) const CALL_TIMEOUT: Duration = Duration::from_secs(wire::CALL_LIFETIME_SECS);
pub(super) const MAX_CONTEXTS: usize = 32;

pub(super) struct Session {
    tid: Option<u32>,
    next_seq: u64,
    next_call: u64,
    calls: Vec<Call>,
    quota: Arc<AtomicUsize>,
    closed: bool,
    shot_resident: bool,
}

struct Call {
    id: u64,
    function: usize,
    deadline: Instant,
    awaiting_resident: Option<u32>,
    _permit: Permit,
}

struct Permit(Arc<AtomicUsize>);

impl Permit {
    fn reserve(quota: &Arc<AtomicUsize>) -> Option<Self> {
        quota
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < MAX_CONTEXTS).then_some(count + 1)
            })
            .ok()?;
        Some(Self(Arc::clone(quota)))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(super) struct Reply {
    pub(super) bytes: WipeBuffer,
    pub(super) snapshot: Option<GuestSnap>,
}

impl Reply {
    fn ok(body: &[u8], snapshot: Option<GuestSnap>) -> Self {
        Self {
            bytes: WipeBuffer(wire::encode_reply(wire::STATUS_OK, body)),
            snapshot,
        }
    }

    fn empty() -> Self {
        Self::ok(&[], None)
    }
}

impl Session {
    pub(super) fn new(quota: Arc<AtomicUsize>) -> Self {
        Self {
            tid: None,
            next_seq: 1,
            next_call: 1,
            calls: Vec::new(),
            quota,
            closed: false,
            shot_resident: false,
        }
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.calls.first().map(|call| call.deadline)
    }

    pub(super) fn answer(
        &mut self,
        core: &Core,
        req: &wire::Request,
        now: Instant,
    ) -> Option<Reply> {
        let result = self.try_answer(core, req, now);
        if result.is_none() {
            self.calls.clear();
            self.closed = true;
        }
        result
    }

    fn try_answer(&mut self, core: &Core, req: &wire::Request, now: Instant) -> Option<Reply> {
        if self.closed
            || req.measurement != core.measurement()
            || req.tid == 0
            || self.tid.is_some_and(|tid| tid != req.tid)
            || req.seq != self.next_seq
            || self.deadline().is_some_and(|deadline| now >= deadline)
        {
            return None;
        }
        let next_seq = self.next_seq.checked_add(1)?;
        let reply = if req.op == wire::OP_BEGIN {
            self.begin(core, req, now)?
        } else {
            self.active(core, req)?
        };
        self.tid = Some(req.tid);
        self.next_seq = next_seq;
        Some(reply)
    }

    fn begin(&mut self, core: &Core, req: &wire::Request, now: Instant) -> Option<Reply> {
        if !empty_control(req)
            || req.call_id != self.next_call
            || self.calls.len() >= vm::CALL_DEPTH_LIMIT as usize
        {
            return None;
        }
        let function = core.function(&req.salt, req.rva)?;
        let next_call = self.next_call.checked_add(1)?;
        let permit = Permit::reserve(&self.quota)?;
        if let Some(parent) = self.calls.last_mut() {
            parent.awaiting_resident = None;
        }
        self.calls.push(Call {
            id: req.call_id,
            function,
            deadline: now.checked_add(CALL_TIMEOUT)?,
            awaiting_resident: None,
            _permit: permit,
        });
        self.next_call = next_call;
        Some(Reply::empty())
    }

    fn active(&mut self, core: &Core, req: &wire::Request) -> Option<Reply> {
        let call = self.calls.last_mut()?;
        let function = call.function;
        let func = &core.package.funcs[function];
        if req.call_id != call.id || req.salt != func.salt || req.rva != func.rva {
            return None;
        }
        let previous = call.awaiting_resident.take();
        match req.op {
            wire::OP_OPEN => {
                let plain = core.open(function, req.index, &req.body)?;
                let reply = Reply::ok(&plain.0, None);
                call.awaiting_resident = Some(req.index);
                Some(reply)
            }
            wire::OP_INNER => inner(func, req),
            wire::OP_RESIDENT if req.body.is_empty() && previous == Some(req.index) => {
                self.resident(core, function, func, req.index)
            }
            wire::OP_COMMIT if empty_control(req) => Some(self.commit()),
            _ => None,
        }
    }

    fn resident(
        &mut self,
        core: &Core,
        function: usize,
        func: &FuncPack,
        index: u32,
    ) -> Option<Reply> {
        let sealed = func.sealed.get(index as usize)?;
        if self.shot_resident || sealed.len() < 8 {
            return Some(Reply::empty());
        }
        let plain = core.open(function, index, sealed)?;
        self.shot_resident = true;
        Some(Reply::ok(
            &[],
            Some(GuestSnap {
                resident: true,
                plain,
            }),
        ))
    }

    fn commit(&mut self) -> Reply {
        self.calls.pop();
        Reply::empty()
    }
}

fn empty_control(req: &wire::Request) -> bool {
    req.index == 0 && req.body.is_empty()
}

fn inner(func: &FuncPack, req: &wire::Request) -> Option<Reply> {
    if req.index != 0 || req.body != func.inner.bytes {
        return None;
    }
    let mut plain = WipeBuffer(func.inner.bytes.clone());
    vm::apply_keystream(&func.inner.key, &func.inner.nonce, 0, &mut plain.0);
    Some(Reply::ok(&plain.0, None))
}
