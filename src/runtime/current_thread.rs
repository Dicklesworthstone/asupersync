//! Current-thread `block_on` driver (GH#58, br-asupersync-94jh37).
//!
//! On a [`RuntimeBuilder::current_thread`](crate::runtime::RuntimeBuilder::current_thread)
//! runtime the thread that calls [`Runtime::block_on`](crate::runtime::Runtime::block_on)
//! becomes the runtime's single scheduler worker for the life of that call.
//!
//! # Topology
//!
//! - The runtime owns exactly one [`ThreeLaneWorker`]. Outside `block_on` it
//!   runs on the runtime's background worker thread as before, so work
//!   spawned through a [`RuntimeHandle`](crate::runtime::RuntimeHandle)
//!   keeps making progress between `block_on` calls. When `block_on` starts,
//!   the caller borrows the worker ([`CurrentThreadDriver::acquire`]): the
//!   background thread leaves its dispatch loop at the next dispatch
//!   boundary, hands the worker over, and parks until it is returned. While
//!   the worker is on loan every spawned task, admission turn, wheel timer
//!   and reactor turn of the runtime runs on the calling thread.
//! - The root future is polled in place on the calling thread (it need not
//!   be `Send` or `'static`), interleaved with the worker's dispatch loop:
//!   the driver polls the root whenever the root waker fired, gives the
//!   worker one dispatch turn, and otherwise runs
//!   [`ThreeLaneWorker::run_loop_until`] — dispatch, spawn admission, timers,
//!   reactor turns and parking exactly as a worker thread would — until the
//!   root waker fires again. The root waker unparks the worker's parker and
//!   wakes the reactor so a wake from any thread ends the park promptly.
//! - The root is a real task for the life of the call: a `!Send` root stub
//!   task is admitted through the worker's local lane into the root region.
//!   Its admission-minted [`Cx`] is installed as the ambient
//!   `Cx::current()` of the root future, so the root carries a registered
//!   task id, spawn and `spawn_local` authority, and observes root-region
//!   cancellation through its checkpoints. The stub stays live until the
//!   root future completes, so
//!   [`Runtime::is_quiescent`](crate::runtime::Runtime::is_quiescent) is
//!   false while the root runs; it completes and its record retires before
//!   `block_on` returns.
//! - A root panic is caught around the poll; the stub is retired, the
//!   worker is returned, and the original payload is re-raised on the caller
//!   (`block_on` propagates root panics exactly as before).
//!
//! The driver falls back to the pre-existing caller-polled path when the
//! worker cannot be borrowed: a nested `block_on` on the driving thread, a
//! `block_on` on the background worker thread itself, a concurrent
//! `block_on` on another thread, or a runtime that is shutting down.
//! Multi-thread runtimes never construct a driver.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::ThreadId;
use std::time::Duration;

use crate::cx::Cx;
use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::scheduler::three_lane::{ScopedWorkerId, ThreeLaneScheduler, ThreeLaneWorker};
use crate::runtime::scheduler::worker::Parker;
use crate::runtime::spawn_mailbox::{self, LocalSpawnRequest, ScopedLocalSpawnLaneOwner};
use crate::runtime::state::SpawnError;
use crate::runtime::task_handle::TaskHandle;

/// Sleep slice for the parked background thread between re-checks of the
/// scheduler shutdown flag while its worker is on loan. The shutdown hooks
/// notify the thread directly; this bounds the wait for a shutdown signal
/// that bypasses them.
const BACKGROUND_WAIT_SLICE: Duration = Duration::from_millis(100);

/// Park slice of the degraded root loop after a shutdown signal, when no
/// worker dispatch is possible and only wheel timers are pumped.
const SHUTDOWN_ROOT_PARK_SLICE: Duration = Duration::from_millis(1);

/// Where the runtime's single worker currently is.
enum WorkerSlot {
    /// The background thread is running the worker.
    Background,
    /// A `block_on` caller asked the background thread to yield the worker.
    Requested,
    /// The background thread stopped and left the worker for the requester.
    Offered(ThreeLaneWorker),
    /// A `block_on` caller is driving the worker.
    Loaned,
    /// The caller handed the worker back; the background thread resumes it.
    Returned(ThreeLaneWorker),
    /// Shutdown was signalled; the worker is never offered again.
    Closed,
}

/// Loan protocol between the background worker thread and `block_on`.
pub(crate) struct CurrentThreadDriver {
    slot: Mutex<WorkerSlot>,
    changed: Condvar,
    /// Raised while a `block_on` caller waits for the worker; the background
    /// thread's dispatch loop stops at its next boundary when it sees it.
    handover_requested: AtomicBool,
    /// Identity of the background worker thread, for the nested-`block_on`
    /// fallback (that thread can never wait for itself to yield the worker).
    background_thread: Mutex<Option<ThreadId>>,
}

impl CurrentThreadDriver {
    pub(crate) fn new() -> Self {
        Self {
            slot: Mutex::new(WorkerSlot::Background),
            changed: Condvar::new(),
            handover_requested: AtomicBool::new(false),
            background_thread: Mutex::new(None),
        }
    }

    fn lock_slot(&self) -> MutexGuard<'_, WorkerSlot> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn on_background_thread(&self) -> bool {
        self.background_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some_and(|id| id == std::thread::current().id())
    }

    /// Marks the driver closed and wakes every waiter. Called from the
    /// runtime's shutdown paths next to `ThreeLaneScheduler::shutdown`; a
    /// worker still held by the driver is dropped here, one on loan is
    /// dropped when the borrower returns it.
    pub(crate) fn shutdown(&self) {
        let mut slot = self.lock_slot();
        *slot = WorkerSlot::Closed;
        self.changed.notify_all();
    }

    /// Body of the runtime's background worker thread: runs the worker until
    /// a `block_on` caller asks for it, offers it, waits for it to come back,
    /// and repeats; exits once the scheduler shutdown flag is set.
    pub(crate) fn run_background(&self, worker: ThreeLaneWorker) {
        *self
            .background_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(std::thread::current().id());
        let shutdown = Arc::clone(&worker.shutdown);
        let mut worker = worker;
        loop {
            worker.run_loop_until(&mut || self.handover_requested.load(Ordering::Acquire));
            if shutdown.load(Ordering::Acquire) {
                self.shutdown();
                return;
            }

            let mut slot = self.lock_slot();
            match *slot {
                WorkerSlot::Requested => {
                    *slot = WorkerSlot::Offered(worker);
                    self.changed.notify_all();
                }
                WorkerSlot::Closed => return,
                // Only a requester holding `Requested` raises the flag; a
                // stale flag means the requester already went away.
                _ => {
                    self.handover_requested.store(false, Ordering::Release);
                    continue;
                }
            }

            loop {
                match std::mem::replace(&mut *slot, WorkerSlot::Loaned) {
                    WorkerSlot::Returned(returned) => {
                        *slot = WorkerSlot::Background;
                        worker = returned;
                        break;
                    }
                    WorkerSlot::Closed => {
                        *slot = WorkerSlot::Closed;
                        return;
                    }
                    other => *slot = other,
                }
                if shutdown.load(Ordering::Acquire) {
                    *slot = WorkerSlot::Closed;
                    self.changed.notify_all();
                    return;
                }
                let (guard, _) = self
                    .changed
                    .wait_timeout(slot, BACKGROUND_WAIT_SLICE)
                    .unwrap_or_else(PoisonError::into_inner);
                slot = guard;
            }
            drop(slot);
        }
    }

    /// Borrows the worker for the calling thread, or returns `None` when it
    /// cannot be borrowed (nested drive, background thread, concurrent
    /// borrower, or shutdown).
    fn acquire(&self, scheduler: &ThreeLaneScheduler) -> Option<ThreeLaneWorker> {
        if self.on_background_thread() {
            return None;
        }
        let mut slot = self.lock_slot();
        match std::mem::replace(&mut *slot, WorkerSlot::Loaned) {
            // Fast path: the previous borrower handed the worker back and the
            // background thread has not resumed it yet.
            WorkerSlot::Returned(worker) => return Some(worker),
            WorkerSlot::Background => *slot = WorkerSlot::Requested,
            other => {
                *slot = other;
                return None;
            }
        }
        self.handover_requested.store(true, Ordering::Release);
        // The background thread may be parked or blocked in the reactor.
        scheduler.wake_all();
        loop {
            match std::mem::replace(&mut *slot, WorkerSlot::Loaned) {
                WorkerSlot::Offered(worker) => {
                    self.handover_requested.store(false, Ordering::Release);
                    return Some(worker);
                }
                WorkerSlot::Closed => {
                    *slot = WorkerSlot::Closed;
                    self.handover_requested.store(false, Ordering::Release);
                    return None;
                }
                other => *slot = other,
            }
            slot = self
                .changed
                .wait(slot)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Hands the worker back to the background thread.
    fn release(&self, worker: ThreeLaneWorker) {
        let mut slot = self.lock_slot();
        if matches!(*slot, WorkerSlot::Closed) {
            drop(worker);
        } else {
            *slot = WorkerSlot::Returned(worker);
        }
        self.changed.notify_all();
    }

    /// Drives `future` to completion on the calling thread as the runtime's
    /// worker. Returns `Err(future)` untouched when the worker cannot be
    /// borrowed, so the caller can fall back to polling it directly.
    ///
    /// `request_cx` is the runtime-wired ambient context `block_on` built;
    /// it is the parent of the root stub task and the fallback ambient `Cx`
    /// when the stub cannot be admitted.
    ///
    /// # Panics
    ///
    /// Re-raises a panic of the root future after the worker has been
    /// returned to the background thread.
    pub(crate) fn drive<F: Future>(
        &self,
        scheduler: &ThreeLaneScheduler,
        request_cx: &Cx,
        future: F,
    ) -> Result<F::Output, F> {
        let Some(worker) = self.acquire(scheduler) else {
            return Err(future);
        };
        let mut loan = WorkerLoan {
            driver: self,
            worker: Some(worker),
        };
        let outcome = loan.drive_root(request_cx, future);
        drop(loan);
        match outcome {
            Ok(output) => Ok(output),
            Err(payload) => resume_unwind(payload),
        }
    }
}

/// Returns the borrowed worker on every exit path, including unwinds.
struct WorkerLoan<'a> {
    driver: &'a CurrentThreadDriver,
    worker: Option<ThreeLaneWorker>,
}

impl WorkerLoan<'_> {
    fn drive_root<F: Future>(
        &mut self,
        request_cx: &Cx,
        future: F,
    ) -> std::thread::Result<F::Output> {
        let worker = self
            .worker
            .as_mut()
            .expect("worker stays on loan for the whole drive");
        // Make this thread the worker for lane routing, so `Cx::spawn_local`
        // from the root parks its request on this thread's lane and the
        // worker admits it on its next dispatch turn.
        let _worker_id = ScopedWorkerId::new(worker.id);
        let _lane_owner = worker
            .spawn_mailbox
            .as_ref()
            .map(|mailbox| ScopedLocalSpawnLaneOwner::new(Arc::clone(mailbox)));
        // Nested drive: local spawns parked by an outer runtime's task on
        // this thread belong to that runtime and must not be admitted here.
        let mut stashed = Vec::new();
        spawn_mailbox::drain_local_spawn_lane(usize::MAX, &mut stashed);

        let result = drive_root_on(worker, request_cx, future);

        // The loop leaves the lane empty unless shutdown cut it short; a
        // request left behind then can never be admitted by this runtime.
        let mut orphaned = Vec::new();
        spawn_mailbox::drain_local_spawn_lane(usize::MAX, &mut orphaned);
        for request in orphaned {
            request.resolve_failed(SpawnError::RuntimeUnavailable);
        }
        restore_local_spawn_lane(stashed);
        result
    }
}

impl Drop for WorkerLoan<'_> {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.driver.release(worker);
        }
    }
}

fn restore_local_spawn_lane(stashed: Vec<LocalSpawnRequest>) {
    for request in stashed {
        spawn_mailbox::enqueue_local_spawn(request);
    }
}

/// Polls the root in place, interleaved with the worker loop, until it
/// completes; the root stub task brackets the root's lifetime in accounting.
fn drive_root_on<F: Future>(
    worker: &mut ThreeLaneWorker,
    request_cx: &Cx,
    future: F,
) -> std::thread::Result<F::Output> {
    let root_waker = Arc::new(RootWaker {
        woken: AtomicBool::new(true),
        parker: worker.parker.clone(),
        io: worker.io_driver.clone(),
    });
    let waker = Waker::from(Arc::clone(&root_waker));
    let mut ctx = Context::from_waker(&waker);
    let mut future = pin!(future);

    // Phase 1: admit the root stub and take its admission-minted Cx. The
    // first dispatch turn drains the lane, admits the stub on this worker
    // and polls it once; the stub publishes its Cx on that poll.
    let stub = RootStub::spawn(request_cx);
    if let Ok(stub) = stub.as_ref() {
        worker.run_loop_until(&mut || stub.cx_available() || stub.is_finished());
    }
    let root_cx = stub
        .as_ref()
        .ok()
        .and_then(RootStub::take_cx)
        .unwrap_or_else(|| request_cx.clone());
    let root_cx_guard = Cx::set_current(Some(root_cx));

    // Phase 2: poll the root whenever its waker fired; run the worker
    // (dispatch, admission, timers, reactor, park) in between.
    let result = loop {
        if worker.shutdown.load(Ordering::Acquire) {
            break drive_root_after_shutdown(worker, &root_waker, &mut ctx, future.as_mut());
        }
        if root_waker.take_woken() {
            match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(&mut ctx))) {
                Ok(Poll::Ready(output)) => break Ok(output),
                Ok(Poll::Pending) => {}
                Err(payload) => break Err(payload),
            }
            // One dispatch turn between root polls keeps a self-waking root
            // from starving spawned work.
            worker.run_once();
            continue;
        }
        worker.run_loop_until(&mut || root_waker.is_woken());
    };
    drop(root_cx_guard);

    // Phase 3: retire the stub so the root leaves task accounting before
    // `block_on` returns (a shutdown cuts this short like any other task).
    if let Ok(stub) = stub {
        stub.finish();
        worker.run_loop_until(&mut || stub.is_finished());
    }
    result
}

/// Degraded root loop once the scheduler is shut down while the root is
/// still pending: no worker dispatch is possible, so only wheel timers are
/// pumped between polls, matching the caller-polled fallback path.
fn drive_root_after_shutdown<F: Future>(
    worker: &ThreeLaneWorker,
    root_waker: &Arc<RootWaker>,
    ctx: &mut Context<'_>,
    mut future: Pin<&mut F>,
) -> std::thread::Result<F::Output> {
    loop {
        if let Some(timer) = worker.timer_driver.as_ref() {
            let _ = timer.process_timers();
        }
        if root_waker.take_woken() {
            match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(ctx))) {
                Ok(Poll::Ready(output)) => return Ok(output),
                Ok(Poll::Pending) => {}
                Err(payload) => return Err(payload),
            }
        }
        worker.parker.park_timeout(SHUTDOWN_ROOT_PARK_SLICE);
    }
}

/// Waker of the in-place root future: records the wake and ends whatever
/// idle wait the driving thread is in (worker park or reactor turn).
struct RootWaker {
    woken: AtomicBool,
    parker: Parker,
    io: Option<IoDriverHandle>,
}

impl RootWaker {
    fn take_woken(&self) -> bool {
        self.woken.swap(false, Ordering::AcqRel)
    }

    fn is_woken(&self) -> bool {
        self.woken.load(Ordering::Acquire)
    }
}

impl Wake for RootWaker {
    fn wake(self: Arc<Self>) {
        Self::wake_by_ref(&self);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.woken.swap(true, Ordering::AcqRel) {
            return;
        }
        self.parker.unpark();
        if let Some(io) = self.io.as_ref() {
            let _ = io.wake();
        }
    }
}

/// State shared between the driver and the root stub task on the driving
/// thread (the stub is a `!Send` local task, so `Rc` is sufficient).
struct RootStubShared {
    /// The stub's admission-minted Cx, published on its first poll.
    cx: RefCell<Option<Cx>>,
    /// Set by the driver once the root future completed.
    done: Cell<bool>,
    /// The stub's task waker, used to schedule its completing poll.
    waker: RefCell<Option<Waker>>,
}

/// The root's task record: a local task in the root region that stays
/// pending until the driver marks the root complete.
struct RootStub {
    shared: Rc<RootStubShared>,
    handle: TaskHandle<()>,
}

impl RootStub {
    fn spawn(parent: &Cx) -> Result<Self, SpawnError> {
        let shared = Rc::new(RootStubShared {
            cx: RefCell::new(None),
            done: Cell::new(false),
            waker: RefCell::new(None),
        });
        let task_shared = Rc::clone(&shared);
        let handle = parent.spawn_local(move |cx: Cx| async move {
            *task_shared.cx.borrow_mut() = Some(cx);
            std::future::poll_fn(|ctx| {
                if task_shared.done.get() {
                    Poll::Ready(())
                } else {
                    *task_shared.waker.borrow_mut() = Some(ctx.waker().clone());
                    Poll::Pending
                }
            })
            .await;
        })?;
        Ok(Self { shared, handle })
    }

    fn cx_available(&self) -> bool {
        self.shared.cx.borrow().is_some()
    }

    fn take_cx(&self) -> Option<Cx> {
        self.shared.cx.borrow_mut().take()
    }

    fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    fn finish(&self) {
        self.shared.done.set(true);
        if let Some(waker) = self.shared.waker.borrow_mut().take() {
            waker.wake();
        }
    }
}
