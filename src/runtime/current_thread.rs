//! Current-thread `block_on` driver (GH#58, br-asupersync-94jh37).
//!
//! On a [`RuntimeBuilder::current_thread`](crate::runtime::RuntimeBuilder::current_thread)
//! runtime the thread that calls [`Runtime::block_on`](crate::runtime::Runtime::block_on)
//! becomes the runtime's single scheduler worker for the life of that call.
//!
//! # Topology
//!
//! - The runtime owns exactly one [`ThreeLaneWorker`]. Outside `block_on` it
//!   runs on the runtime's background worker thread, so work spawned through
//!   a [`RuntimeHandle`](crate::runtime::RuntimeHandle) keeps making progress
//!   between `block_on` calls. When `block_on` starts, the caller borrows the
//!   worker ([`CurrentThreadDriver::acquire`]): the background thread leaves
//!   its dispatch loop at the next dispatch boundary, hands the worker over,
//!   and parks until it is returned. While the worker is on loan every
//!   spawned task, admission turn, wheel timer and reactor turn of the
//!   runtime runs on the calling thread.
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
//!   false while the root runs.
//! - After the root completes, `block_on` retires the stub (one direct poll
//!   of its record, independent of queue order) and then drains runnable
//!   work with a bounded policy: dispatch turns continue until nothing is
//!   runnable (no dispatchable task, ready finalizer, queued command, or
//!   already-arrived reactor readiness) or [`POST_ROOT_DRAIN_TURNS`] turns
//!   were spent, never waiting on timers or I/O. A cancellation-blind
//!   self-waking task therefore cannot keep `block_on` from returning; work
//!   still runnable or parked afterwards continues on the background thread
//!   once it resumes the worker.
//! - A root panic is caught around the poll; the stub is retired, the
//!   worker is returned, and the original payload is re-raised on the caller
//!   (`block_on` propagates root panics exactly as before).
//!
//! # `!Send` tasks and thread affinity
//!
//! A local task's future lives in the thread-local store of the thread that
//! admitted it (keyed per runtime, see [`crate::runtime::local`]) and can
//! only be polled there. The loan protocol therefore never moves the worker
//! away from a thread that still holds live local tasks of this runtime: the
//! background thread refuses a handover while its store or lane is
//! non-empty (that `block_on` call falls back to the caller-polled path), and
//! a local task admitted on a `block_on` caller that is woken while the
//! worker runs elsewhere is recorded by the worker — every such wake, no cap
//! — and re-scheduled the next time its owning thread drives the worker
//! (another `block_on`, or the root-region drain of the entry macros, which
//! also drives from the caller). On runtime shutdown the calling thread's
//! store of this runtime is retired (abort-by-drop of whatever is parked).
//!
//! # Nesting
//!
//! A root may call `block_on` again on its own runtime: while the driver
//! polls the root in place it parks the worker in a per-thread re-entrancy
//! slot, so the nested call drives the same worker on the same thread (its
//! own stub, its own bounded drain) and hands it back before the outer poll
//! resumes; this nests to any depth. Distinct runtimes nest the same way on
//! one thread. Every piece of thread-local worker state is a scoped guard
//! (scheduler, fast queue, local-ready queue, worker id, lane owner,
//! local-store key, ambient `Cx`) restored when the inner drive ends, each
//! runtime's `!Send` futures live in their own per-runtime store, and
//! local-spawn requests parked by an outer root of a different runtime are
//! set aside for the duration of the inner drive. Same-runtime re-entry
//! keeps those requests available so the nested root can join them.
//! A `block_on` from inside a task poll (the worker is busy executing), from
//! the background thread, or
//! concurrently from another thread cannot borrow the worker; it polls its
//! future directly, as before.
//!
//! The worker is stored type-erased while it is handed around. `RuntimeInner`
//! owns the driver, and every future that captures a `RuntimeHandle` must
//! prove `RuntimeInner: Send + Sync`; keeping `ThreeLaneWorker` out of that
//! type keeps those auto-trait proofs shallow (the `Send` bound on the
//! worker is proven once, at the erasure). Its allocation is retained across
//! handovers and root polls.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use crate::cx::Cx;
use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::local::ScopedLocalStoreKey;
use crate::runtime::scheduler::three_lane::{ScopedWorkerId, ThreeLaneScheduler, ThreeLaneWorker};
use crate::runtime::scheduler::worker::Parker;
use crate::runtime::spawn_mailbox::{
    self, LocalSpawnRequest, ScopedLocalSpawnLaneOwner, SpawnGateway, SpawnMailbox,
};
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

/// Observation cadence of the caller-driven root-region drain between idle
/// dispatch turns (matches the background observation loop it replaces).
const DRAIN_IDLE_SLICE: Duration = Duration::from_millis(1);

/// Dispatch-turn budget of the post-root drain: `block_on` returns once
/// nothing is runnable or this many turns were spent, whichever is first.
pub const POST_ROOT_DRAIN_TURNS: u32 = 64;

/// How often (in dispatch turns) the caller-driven root-region drain
/// re-checks its deadline while runnable work keeps it busy.
const DRAIN_DEADLINE_CHECK_TURNS: u32 = 16;

/// The worker while it is handed between threads or parked for re-entry;
/// see the module docs for why it is type-erased.
type ErasedWorker = Box<dyn Any + Send>;

fn erase_worker(worker: Box<ThreeLaneWorker>) -> ErasedWorker {
    worker
}

fn recover_worker(erased: ErasedWorker) -> Box<ThreeLaneWorker> {
    erased
        .downcast::<ThreeLaneWorker>()
        .expect("worker slots only ever hold a ThreeLaneWorker")
}

/// Where the runtime's single worker currently is.
enum WorkerSlot {
    /// The background thread is running the worker.
    Background,
    /// A `block_on` caller asked the background thread to yield the worker.
    Requested,
    /// The background thread stopped and left the worker for the requester.
    Offered(ErasedWorker),
    /// A `block_on` caller is driving the worker.
    Loaned,
    /// The caller handed the worker back; the background thread resumes it.
    Returned(ErasedWorker),
    /// Shutdown was signalled; the worker is never offered again.
    Closed,
}

/// Loan protocol between the background worker thread and `block_on`.
pub struct CurrentThreadDriver {
    slot: Mutex<WorkerSlot>,
    changed: Condvar,
    /// Raised while a `block_on` caller waits for the worker; the background
    /// thread's dispatch loop stops at its next boundary when it sees it.
    handover_requested: AtomicBool,
    /// Identity of the background worker thread, for the nested-`block_on`
    /// fallback (that thread can never wait for itself to yield the worker).
    background_thread: Mutex<Option<ThreadId>>,
    /// Worker parked by a drive while it polls its root in place, so a
    /// nested `block_on` of this runtime from that root (same thread) can
    /// drive it too; tagged with the driving thread.
    reentrant: Mutex<Option<(ThreadId, ErasedWorker)>>,
    /// This runtime's spawn gateway: identifies the runtime whose worker is
    /// active on a thread (the thread's local-spawn lane owner).
    gateway: Option<Arc<SpawnGateway>>,
    /// Key of this runtime's per-thread local-task stores (the worker's
    /// [`ThreeLaneWorker::local_store_key`]), retired on shutdown.
    store_key: usize,
}

impl CurrentThreadDriver {
    pub fn new(gateway: Option<Arc<SpawnGateway>>, store_key: usize) -> Self {
        Self {
            slot: Mutex::new(WorkerSlot::Background),
            changed: Condvar::new(),
            handover_requested: AtomicBool::new(false),
            background_thread: Mutex::new(None),
            reentrant: Mutex::new(None),
            gateway,
            store_key,
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

    /// True while this runtime's worker is active on the calling thread
    /// (its dispatch loop or a drive owns the thread's local-spawn lane).
    fn worker_active_on_this_thread(&self) -> bool {
        self.gateway
            .as_deref()
            .is_some_and(spawn_mailbox::local_spawn_lane_is_owned_by)
    }

    /// Marks the driver closed and wakes every waiter. Called from the
    /// runtime's shutdown paths next to `ThreeLaneScheduler::shutdown`; a
    /// worker still held by the driver is dropped here, one on loan is
    /// dropped when the borrower returns it. Also retires the calling
    /// thread's store of this runtime's `!Send` tasks (abort-by-drop of
    /// whatever is still parked there); stores held by other threads are
    /// released when those threads exit.
    pub fn shutdown(&self) {
        {
            let mut slot = self.lock_slot();
            *slot = WorkerSlot::Closed;
            self.changed.notify_all();
        }
        crate::runtime::local::retire_local_store(self.store_key);
    }

    /// Body of the runtime's background worker thread: runs the worker until
    /// a `block_on` caller asks for it, offers it (unless this thread still
    /// owns live local tasks, which must be polled here), waits for it to
    /// come back, and repeats; exits once the scheduler shutdown flag is set.
    pub fn run_background(&self, worker: ThreeLaneWorker) {
        *self
            .background_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(std::thread::current().id());
        let shutdown = Arc::clone(&worker.shutdown);
        let _store_key = ScopedLocalStoreKey::new(worker.local_store_key());
        let mut worker = Box::new(worker);
        loop {
            worker.run_loop_until(
                &mut || self.handover_requested.load(Ordering::Acquire),
                false,
            );
            if shutdown.load(Ordering::Acquire) {
                self.shutdown();
                return;
            }

            // A `!Send` task admitted on this thread can only be polled here:
            // the worker cannot leave until every such task has finished.
            let can_offer = crate::runtime::local::local_task_count() == 0
                && spawn_mailbox::local_spawn_lane_is_empty();
            let mut slot = self.lock_slot();
            match *slot {
                WorkerSlot::Requested if can_offer => {
                    *slot = WorkerSlot::Offered(erase_worker(worker));
                    self.changed.notify_all();
                }
                WorkerSlot::Requested => {
                    // Refused: the requester falls back to polling its root
                    // on its own thread while this worker keeps running.
                    *slot = WorkerSlot::Background;
                    self.handover_requested.store(false, Ordering::Release);
                    self.changed.notify_all();
                    continue;
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
                        worker = recover_worker(returned);
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

    /// Borrows the worker from the background thread for the calling
    /// thread, or returns `None` when it cannot be borrowed (the background
    /// thread itself, a concurrent borrower, a refused handover, or
    /// shutdown).
    fn acquire(&self, scheduler: &ThreeLaneScheduler) -> Option<Box<ThreeLaneWorker>> {
        if self.on_background_thread() {
            return None;
        }
        let mut slot = self.lock_slot();
        match std::mem::replace(&mut *slot, WorkerSlot::Loaned) {
            // Fast path: the previous borrower handed the worker back and the
            // background thread has not resumed it yet.
            WorkerSlot::Returned(worker) => return Some(recover_worker(worker)),
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
                    return Some(recover_worker(worker));
                }
                // The background thread refused the handover (it owns live
                // local tasks) and cleared the flag itself.
                WorkerSlot::Background => {
                    *slot = WorkerSlot::Background;
                    return None;
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
    fn release(&self, worker: Box<ThreeLaneWorker>) {
        let mut slot = self.lock_slot();
        if matches!(*slot, WorkerSlot::Closed) {
            drop(worker);
        } else {
            *slot = WorkerSlot::Returned(erase_worker(worker));
        }
        self.changed.notify_all();
    }

    /// Parks the worker for a nested `block_on` from the root being polled
    /// on this thread.
    fn park_reentrant(&self, worker: Box<ThreeLaneWorker>) {
        let mut parked = self
            .reentrant
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        debug_assert!(parked.is_none(), "re-entrancy slot already holds a worker");
        *parked = Some((std::thread::current().id(), erase_worker(worker)));
    }

    /// Takes the worker parked for re-entry by a drive on this thread, if any.
    fn take_reentrant(&self) -> Option<Box<ThreeLaneWorker>> {
        let mut parked = self
            .reentrant
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let owned_here = parked
            .as_ref()
            .is_some_and(|(owner, _)| *owner == std::thread::current().id());
        if !owned_here {
            return None;
        }
        parked.take().map(|(_, worker)| recover_worker(worker))
    }

    /// Obtains the worker for a drive on the calling thread: re-entrantly
    /// from a root of this runtime being polled here, otherwise from the
    /// background thread. `None` means the caller must poll directly.
    fn borrow_for_drive(&self, scheduler: &ThreeLaneScheduler) -> Option<WorkerLoan<'_>> {
        if self.worker_active_on_this_thread() {
            let worker = self.take_reentrant()?;
            return Some(WorkerLoan {
                driver: self,
                worker: Some(worker),
                return_to: LoanReturn::Reentrant,
            });
        }
        let worker = self.acquire(scheduler)?;
        Some(WorkerLoan {
            driver: self,
            worker: Some(worker),
            return_to: LoanReturn::Background,
        })
    }

    /// Drives `future` to completion on the calling thread as the runtime's
    /// worker, then drains runnable work under the bounded policy. Returns
    /// `Err(future)` untouched when the worker cannot be borrowed, so the
    /// caller can fall back to polling it directly.
    ///
    /// `request_cx` is the runtime-wired ambient context `block_on` built;
    /// it is the parent of the root stub task and the fallback ambient `Cx`
    /// when the stub cannot be admitted.
    ///
    /// # Panics
    ///
    /// Re-raises a panic of the root future after the worker has been
    /// returned.
    pub fn drive<F: Future>(
        &self,
        scheduler: &ThreeLaneScheduler,
        request_cx: &Cx,
        future: F,
    ) -> Result<F::Output, F> {
        let Some(mut loan) = self.borrow_for_drive(scheduler) else {
            return Err(future);
        };
        let outcome = loan.with_thread_context(|driver, worker| {
            drive_root_on(driver, worker, request_cx, future)
        });
        drop(loan);
        match outcome {
            Ok(output) => Ok(output),
            Err(payload) => resume_unwind(payload),
        }
    }

    /// Caller-driven root-region drain: runs the worker on this thread in
    /// idle-returning turns until `drained` holds (`Some(true)`) or `bound`
    /// elapses since `started` (`Some(false)`), re-checking the deadline
    /// inside busy dispatch runs and observing `drained` between turns at
    /// the same cadence as the background observation loop. Returns `None`
    /// when the worker cannot be borrowed, in which case the caller's own
    /// observation loop applies.
    pub fn drain_until(
        &self,
        scheduler: &ThreeLaneScheduler,
        started: Instant,
        bound: Duration,
        drained: &mut dyn FnMut() -> bool,
    ) -> Option<bool> {
        if self.worker_active_on_this_thread() {
            return None;
        }
        let worker = self.acquire(scheduler)?;
        let mut loan = WorkerLoan {
            driver: self,
            worker: Some(worker),
            return_to: LoanReturn::Background,
        };
        Some(loan.with_thread_context(|_, worker| {
            let worker = worker
                .as_mut()
                .expect("worker stays on loan for the whole drain");
            loop {
                let mut turns = 0_u32;
                worker.run_loop_until(
                    &mut || {
                        turns = turns.wrapping_add(1);
                        turns % DRAIN_DEADLINE_CHECK_TURNS == 0 && started.elapsed() >= bound
                    },
                    true,
                );
                if drained() {
                    return true;
                }
                if started.elapsed() >= bound {
                    return false;
                }
                std::thread::sleep(DRAIN_IDLE_SLICE);
            }
        }))
    }
}

/// Where a loaned worker goes back when the loan ends.
enum LoanReturn {
    /// To the background thread (the ordinary `block_on`).
    Background,
    /// To the re-entrancy slot of the outer drive on this thread.
    Reentrant,
}

/// Returns the borrowed worker on every exit path, including unwinds.
struct WorkerLoan<'a> {
    driver: &'a CurrentThreadDriver,
    worker: Option<Box<ThreeLaneWorker>>,
    return_to: LoanReturn,
}

impl WorkerLoan<'_> {
    /// Runs `f` with this thread set up as the worker's thread: worker id
    /// and lane owner (so `Cx::spawn_local` from the root parks on this
    /// thread's lane), the runtime's local-store key, and the thread's lane
    /// contents of a different runtime's outer drive set aside and restored
    /// afterwards. Same-runtime re-entry keeps the lane available. `f`
    /// receives the loan's worker slot; it may take the worker out
    /// temporarily (re-entrancy) but must put it back.
    fn with_thread_context<R>(
        &mut self,
        f: impl FnOnce(&CurrentThreadDriver, &mut Option<Box<ThreeLaneWorker>>) -> R,
    ) -> R {
        let (worker_id, mailbox, store_key): (usize, Option<Arc<SpawnMailbox>>, usize) = {
            let worker = self
                .worker
                .as_ref()
                .expect("worker stays on loan for the whole drive");
            (
                worker.id,
                worker.spawn_mailbox.clone(),
                worker.local_store_key(),
            )
        };
        let _store_key = ScopedLocalStoreKey::new(store_key);
        let _worker_id = ScopedWorkerId::new(worker_id);
        let _lane_owner = mailbox.map(ScopedLocalSpawnLaneOwner::new);
        // A nested root of this runtime can join a local request queued by
        // its outer root, so it must be able to admit that request. Only
        // isolate the lane when borrowing a different runtime's worker.
        let isolate_lane = !matches!(self.return_to, LoanReturn::Reentrant);
        let mut outer_requests = Vec::new();
        if isolate_lane {
            spawn_mailbox::drain_local_spawn_lane(usize::MAX, &mut outer_requests);
        }

        let result = f(self.driver, &mut self.worker);

        if isolate_lane {
            // The loop leaves the lane empty unless shutdown cut it short;
            // a request left behind then can never be admitted by this
            // runtime. A same-runtime outer drive can still admit requests
            // left by its nested drive and must retain them.
            let mut orphaned = Vec::new();
            spawn_mailbox::drain_local_spawn_lane(usize::MAX, &mut orphaned);
            for request in orphaned {
                request.resolve_failed(SpawnError::RuntimeUnavailable);
            }
            restore_local_spawn_lane(outer_requests);
        }
        result
    }
}

impl Drop for WorkerLoan<'_> {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            match self.return_to {
                LoanReturn::Background => self.driver.release(worker),
                LoanReturn::Reentrant => self.driver.park_reentrant(worker),
            }
        }
    }
}

fn restore_local_spawn_lane(requests: Vec<LocalSpawnRequest>) {
    for request in requests {
        spawn_mailbox::enqueue_local_spawn(request);
    }
}

/// Polls the root in place, interleaved with the worker loop, until it
/// completes; the root stub task brackets the root's lifetime in accounting.
/// Then retires the stub and drains runnable work under the bounded policy.
/// While the root is being polled the worker sits in the driver's
/// re-entrancy slot so a nested `block_on` from the root can drive it.
fn drive_root_on<F: Future>(
    driver: &CurrentThreadDriver,
    slot: &mut Option<Box<ThreeLaneWorker>>,
    request_cx: &Cx,
    future: F,
) -> std::thread::Result<F::Output> {
    let root_waker = {
        let worker = slot
            .as_ref()
            .expect("worker stays on loan for the whole drive");
        Arc::new(RootWaker {
            woken: AtomicBool::new(true),
            parker: worker.parker.clone(),
            io: worker.io_driver.clone(),
        })
    };
    let waker = Waker::from(Arc::clone(&root_waker));
    let mut ctx = Context::from_waker(&waker);
    let mut future = pin!(future);

    // Phase 1: admit the root stub and take its admission-minted Cx. The
    // first dispatch turn drains the lane, admits the stub on this worker
    // and polls it once; the stub publishes its Cx on that poll.
    let stub = RootStub::spawn(request_cx);
    if let Ok(stub) = stub.as_ref() {
        loaned(slot).run_loop_until(&mut || stub.cx_available() || stub.is_finished(), false);
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
        if loaned(slot).shutdown.load(Ordering::Acquire) {
            break drive_root_after_shutdown(loaned(slot), &root_waker, &mut ctx, future.as_mut());
        }
        if root_waker.take_woken() {
            let parked = slot
                .take()
                .expect("worker stays on loan for the whole drive");
            driver.park_reentrant(parked);
            let polled = catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(&mut ctx)));
            *slot = Some(
                driver
                    .take_reentrant()
                    .expect("a nested drive hands the worker back before the root poll returns"),
            );
            match polled {
                Ok(Poll::Ready(output)) => break Ok(output),
                Ok(Poll::Pending) => {}
                Err(payload) => break Err(payload),
            }
            // One dispatch turn between root polls keeps a self-waking root
            // from starving spawned work.
            loaned(slot).run_once();
        } else {
            loaned(slot).run_loop_until(&mut || root_waker.is_woken(), false);
        }
    };
    drop(root_cx_guard);

    // Phase 3: retire the stub with one direct poll of its record (so the
    // root leaves task accounting regardless of queue order), then drain
    // runnable work: until idle or the turn budget is spent, never waiting
    // on timers or I/O. A shutdown cuts this short like any other task.
    if let Ok(stub) = stub.as_ref() {
        stub.finish_now(loaned(slot));
    }
    let mut turns = 0_u32;
    loaned(slot).run_loop_until(
        &mut || {
            turns = turns.saturating_add(1);
            turns > POST_ROOT_DRAIN_TURNS
        },
        true,
    );
    result
}

/// The loaned worker; it is only ever absent while the root is being polled.
fn loaned(slot: &mut Option<Box<ThreeLaneWorker>>) -> &mut ThreeLaneWorker {
    slot.as_deref_mut()
        .expect("worker stays on loan for the whole drive")
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
    /// Set by the driver once the root future completed; the stub's next
    /// poll then completes it.
    done: Cell<bool>,
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
        });
        let task_shared = Rc::clone(&shared);
        let handle = parent.spawn_local(move |cx: Cx| async move {
            *task_shared.cx.borrow_mut() = Some(cx);
            // No waker registration: the driver polls this record directly
            // once the root completed (`finish_now`).
            std::future::poll_fn(|_| {
                if task_shared.done.get() {
                    Poll::Ready(())
                } else {
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

    /// Completes the stub's record now: marks it done and dispatches it
    /// through the worker's ordinary execute path on this thread.
    fn finish_now(&self, worker: &mut ThreeLaneWorker) {
        self.shared.done.set(true);
        if !self.is_finished() {
            worker.execute(self.handle.task_id());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduce the state visible to R1 when its handover was refused and
    /// R2 has already borrowed the worker before R1 reacquires the mutex.
    /// The refused caller must not wait for a foreign loan to finish.
    #[test]
    fn refused_request_does_not_wait_for_a_foreign_loan() {
        use crate::runtime::RuntimeState;
        use crate::sync::ContendedMutex;
        use std::sync::mpsc;

        let state = Arc::new(ContendedMutex::new("request_race", RuntimeState::new()));
        let scheduler = Arc::new(ThreeLaneScheduler::new(1, &state));
        let driver = Arc::new(CurrentThreadDriver::new(None, 0x5eec));
        let caller_driver = Arc::clone(&driver);
        let (sent, received) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            let refused = caller_driver.acquire(&scheduler).is_none();
            let _ = sent.send(refused);
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut request_seen = false;
        while Instant::now() < deadline {
            let mut slot = driver.lock_slot();
            if driver.handover_requested.load(Ordering::Acquire) {
                request_seen = true;
                // The background refusal and R2 acquisition happen while
                // R1 is asleep; only their final state is observable to R1.
                *slot = WorkerSlot::Loaned;
                driver.changed.notify_all();
                break;
            }
            drop(slot);
            std::thread::yield_now();
        }
        let result = received.recv_timeout(Duration::from_secs(2));
        driver.shutdown();
        caller.join().expect("requester exits after cleanup");
        assert!(
            request_seen,
            "requester must actually enter the handover wait"
        );
        assert!(result.expect("refused requester waited on a foreign loan"));
    }

    /// `ScopedLocalStoreKey` restores the key of the thread that created it,
    /// so it must not be movable to another thread. The call below is
    /// ambiguous, and fails to compile, if the type ever becomes `Send`.
    #[test]
    fn scoped_local_store_key_is_not_send() {
        trait AmbiguousIfSend<A> {
            fn check() {}
        }
        impl<T> AmbiguousIfSend<()> for T {}
        impl<T: Send> AmbiguousIfSend<u8> for T {}
        <ScopedLocalStoreKey as AmbiguousIfSend<_>>::check();
    }

    /// The loan protocol object is shared between the background thread and
    /// `block_on` callers through an `Arc`, so it must stay `Send + Sync`.
    #[test]
    fn current_thread_driver_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CurrentThreadDriver>();
    }

    /// Shutdown retires the calling thread's keyed store for this runtime
    /// (and only that one).
    #[test]
    fn shutdown_retires_the_calling_threads_keyed_store() {
        use crate::runtime::local::{
            ScopedLocalStoreKey, keyed_local_store_count, local_task_count,
        };
        let before = keyed_local_store_count();
        let driver = CurrentThreadDriver::new(None, 0x5eed);
        let other = CurrentThreadDriver::new(None, 0x5eee);
        {
            let _key = ScopedLocalStoreKey::new(0x5eed);
            // Touching the store materializes this runtime's entry.
            assert_eq!(local_task_count(), 0);
        }
        {
            let _key = ScopedLocalStoreKey::new(0x5eee);
            assert_eq!(local_task_count(), 0);
        }
        assert_eq!(keyed_local_store_count(), before + 2);
        driver.shutdown();
        assert_eq!(keyed_local_store_count(), before + 1);
        other.shutdown();
        assert_eq!(keyed_local_store_count(), before);
    }
}
