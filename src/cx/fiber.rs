//! Fibers: borrow-friendly concurrent child futures inside one task.
//!
//! A fiber is a future that runs concurrently with its siblings *inside the
//! task that started it*. Unlike a spawned task it needs no runtime task
//! record, no scheduler admission, and no `'static` bound: fibers may borrow
//! data from the caller's stack frame. [`scope`] does not return until every
//! fiber started in it has completed, so nothing outlives the data it borrows
//! (the [`std::thread::scope`] contract, for futures).
//!
//! ```
//! use asupersync::cx::fiber;
//!
//! # asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
//! let words = vec!["structured", "concurrency"];
//! let words = &words;
//! let total = fiber::scope(|scope| async move {
//!     let first = scope.spawn(async move { words[0].len() });
//!     let second = scope.spawn(async move { words[1].len() });
//!     first.await.unwrap() + second.await.unwrap()
//! })
//! .await;
//! assert_eq!(total, 21);
//! # });
//! ```
//!
//! The body receives its [`FiberScope`] by value. The handle is a cheap
//! clone, so a fiber can carry one and start siblings of its own.
//!
//! # Semantics
//!
//! - **Ownership.** Fibers belong to the scope, the scope belongs to the
//!   calling task, and the task belongs to its region, so region close still
//!   waits for every fiber (transitively, through the task).
//! - **Completion.** When the body returns, [`scope`] keeps polling the
//!   remaining fibers, including any they start, and resolves only once all
//!   of them have finished. Starting a fiber after that panics: it could
//!   never run.
//! - **Cancellation.** A scope started inside a task gives each fiber its
//!   own context, derived from the task's: while a fiber runs,
//!   [`Cx::current`](crate::cx::Cx::current) is that context. It shares the
//!   task's identity, region, drivers and budget, but has its own
//!   cancellation state. The task's cancellation reaches every fiber (unless
//!   the task is inside a masked section), [`FiberHandle::cancel`] cancels
//!   one fiber, and neither cancels the task. Fibers observe cancellation at
//!   their own cancellation points, finish their cleanup, and the scope
//!   drains. Nothing is dropped mid-flight unless the scope future itself is
//!   dropped, which drops its fibers with it; a handle that outlived it then
//!   resolves as [`JoinError::Cancelled`]. Code in a fiber that passes the
//!   task's `Cx` (captured from outside) to a cancel-aware call observes the
//!   task's cancellation only; use `Cx::current()` inside the fiber to
//!   observe the fiber's own.
//! - **Panics.** A panicking fiber is caught, and its sibling fibers are
//!   cancelled (fail-fast: their contexts report a `FailFast`
//!   cancellation); the scope's body keeps running. Awaiting the panicked
//!   fiber's handle yields [`JoinError::Panicked`]; a panic no handle
//!   observed is re-raised when the scope finishes, so it cannot vanish
//!   silently. If the scope future is dropped before it finishes (a timeout,
//!   a lost race), its fibers are dropped with it, and so are the panics no
//!   handle observed.
//! - **Scheduling.** Each poll of the scope polls the body and every ready
//!   fiber once. A fiber that wakes itself is polled again on the task's next
//!   turn, so a busy fiber cannot monopolize the worker.
//! - **Not parallel.** Fibers interleave on the calling task's thread. Use
//!   `Cx::spawn` or a `JoinSet` for parallelism; use fibers for cheap
//!   fine-grained concurrency (I/O fan-out, timeouts on parts of the work,
//!   pipelines over borrowed data).
//!
//! # What the compiler enforces
//!
//! Fibers borrow under the ordinary borrow rules. The scope future cannot
//! outlive the data its fibers borrow:
//!
//! ```compile_fail,E0597
//! use asupersync::cx::fiber;
//!
//! let pending = {
//!     let words = vec!["short-lived"];
//!     let words = &words;
//!     fiber::scope(move |scope| async move {
//!         scope.spawn(async move { words.len() }).await.unwrap()
//!     })
//! };
//! drop(pending);
//! ```
//!
//! Two fibers cannot hold the same `&mut`. Split the data instead, for
//! example with `split_at_mut`:
//!
//! ```compile_fail,E0382
//! use asupersync::cx::fiber;
//!
//! let mut total = 0;
//! let total = &mut total;
//! drop(fiber::scope(|scope| async move {
//!     let first = scope.spawn(async move { *total += 1 });
//!     let second = scope.spawn(async move { *total += 1 });
//!     first.await.unwrap();
//!     second.await.unwrap();
//! }));
//! ```
//!
//! A fiber's future must be `Send`, so that a scope can run inside a spawned
//! task. A `!Send` value such as an `Rc` may be used between awaits, but not
//! held across one:
//!
//! ```compile_fail
//! use asupersync::cx::fiber;
//!
//! drop(fiber::scope(|scope| async move {
//!     let fiber = scope.spawn(async {
//!         let shared = std::rc::Rc::new(1);
//!         asupersync::runtime::yield_now().await;
//!         *shared
//!     });
//!     fiber.await.unwrap()
//! }));
//! ```
//!
//! A [`FiberHandle`] has no lifetime, so it may leave the body. Awaiting it
//! after the scope finished still yields the fiber's result, because the
//! scope waited for that fiber. Starting a fiber through an escaped
//! [`FiberScope`] after the scope finished panics instead.
//!
//! # Cost
//!
//! Starting a fiber costs one boxed future and one shared completion cell,
//! plus a small context cell when the scope runs inside a task. The fiber's
//! own context is derived from the task's the first time the fiber reads it
//! ([`Cx::current`](crate::cx::Cx::current)); a cancellation sent before then
//! is applied when it does. A wake handle
//! is allocated only when no finished fiber's slot can be reused. It never
//! touches runtime-global state. A poll of the scope takes the
//! fiber table lock twice however many fibers are ready, and wakes raised
//! inside that poll on the polling thread re-wake the task at most once.
//! That makes fibers the cheapest structured concurrency in the runtime
//! (br-asupersync-issue65-criticisms-kpmoy5.3.2).

use crate::cx::Cx;
use crate::cx::cx::LazyCurrentCx;
use crate::runtime::JoinError;
use crate::types::outcome::PanicPayload;
use crate::types::{CancelKind, CancelReason};
use parking_lot::Mutex;
use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::{Arc, OnceLock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, Wake, Waker};

type FiberFuture<'env> = Pin<Box<dyn Future<Output = ()> + Send + 'env>>;

std::thread_local! {
    /// Address of the [`ReadyQueue`] of the scope this thread is polling
    /// right now, or 0.
    static POLLING_SCOPE: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
std::thread_local! {
    /// Calls of `FiberCtx::inherit_cancel` on this thread, for the test that
    /// the task's cancellation is passed to each fiber once.
    static INHERIT_CALLS: Cell<usize> = const { Cell::new(0) };
}

/// Fibers that need polling, plus the waker of the task polling the scope.
#[derive(Default)]
struct ReadyQueue {
    ready: Mutex<Vec<usize>>,
    parent: Mutex<Option<Waker>>,
}

impl ReadyQueue {
    fn address(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }

    /// Whether this thread is inside a poll of this queue's scope, which
    /// re-wakes its task itself if work is left over.
    fn polled_on_this_thread(&self) -> bool {
        POLLING_SCOPE.with(|scope| scope.get() == self.address())
    }

    fn wake_parent(&self) {
        let parent = self.parent.lock().clone();
        if let Some(parent) = parent {
            parent.wake();
        }
    }

    /// Marks fiber `index` ready and makes sure the scope is polled again.
    fn schedule(&self, index: usize) {
        self.ready.lock().push(index);
        if !self.polled_on_this_thread() {
            self.wake_parent();
        }
    }
}

/// Marks the current thread as polling one scope; restores the previous
/// mark (an enclosing scope's) when dropped.
struct PollingHere {
    previous: usize,
}

impl PollingHere {
    fn enter(queue: &ReadyQueue) -> Self {
        Self {
            previous: POLLING_SCOPE.replace(queue.address()),
        }
    }
}

impl Drop for PollingHere {
    fn drop(&mut self) {
        POLLING_SCOPE.set(self.previous);
    }
}

/// The waker handed to one fiber slot: marks it ready and wakes the parent
/// task. A slot keeps its wake handle when its fiber finishes, for the next
/// fiber started in it; a late wake from the old fiber only causes one
/// spurious poll of the new one.
struct FiberWake {
    index: usize,
    queued: AtomicBool,
    queue: Arc<ReadyQueue>,
}

impl Wake for FiberWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.queued.swap(true, Ordering::AcqRel) {
            if !self.queue.polled_on_this_thread() {
                self.queue.wake_parent();
            }
        } else {
            self.queue.schedule(self.index);
        }
    }
}

/// The message of a cancellation through [`FiberHandle::cancel`].
const HANDLE_CANCEL_MESSAGE: &str = "fiber cancelled through its handle";

/// A fiber's own context, derived from its task's the first time the fiber
/// reads it ([`Cx::current`]), copying the task's budget as it is then.
/// Cancellations sent before then are kept and applied when it is built. A
/// full context kept per live fiber made a fan-out of trivial fibers cost
/// about 2.5x a tokio task (br-asupersync-98569u), and most fibers use the
/// task's `Cx` they borrow.
#[derive(Debug)]
struct FiberCtx {
    task_cx: Arc<Cx>,
    /// The derived context, once built: set only under `pending`'s lock,
    /// after the replay, and read without a lock from then on.
    cx: OnceLock<Cx>,
    /// Cancellations that arrived before the context was built, replayed in
    /// order when it is, to the same effect they would have had on it.
    pending: Mutex<Vec<PendingCancel>>,
    /// The fiber's waker. Once the context is built it is the context's
    /// cancel waker, as the scheduler's waker is a task's, so a cancellation
    /// polls the fiber again even when it waits on something that registers
    /// no cancel waker of its own (a semaphore, an RwLock, a nested scope).
    wake: Waker,
}

#[derive(Debug)]
enum PendingCancel {
    /// The task's cancellation, or a sibling's fail-fast (`inherit_cancel`).
    Inherit(CancelReason),
    /// [`FiberHandle::cancel`], with the reason stamped when it was called.
    Handle(CancelReason),
}

impl FiberCtx {
    fn new(task_cx: Arc<Cx>, wake: Waker) -> Self {
        Self {
            task_cx,
            cx: OnceLock::new(),
            pending: Mutex::new(Vec::new()),
            wake,
        }
    }

    /// The built context, or `None` after `record` noted a cancellation for
    /// it. A context built meanwhile (on another thread) gets it directly.
    fn built_or_record(&self, record: impl FnOnce(&mut Vec<PendingCancel>)) -> Option<&Cx> {
        if let Some(cx) = self.cx.get() {
            return Some(cx);
        }
        let mut pending = self.pending.lock();
        if let Some(cx) = self.cx.get() {
            return Some(cx);
        }
        record(&mut pending);
        None
    }

    /// Passes the task's or a sibling's cancellation on. Like
    /// `Cx::inherit_cancel`, it does nothing once the fiber has one.
    fn inherit_cancel(&self, reason: &CancelReason) {
        #[cfg(test)]
        INHERIT_CALLS.with(|calls| calls.set(calls.get() + 1));
        let mut recorded = false;
        let built = self.built_or_record(|pending| {
            if pending.is_empty() {
                pending.push(PendingCancel::Inherit(reason.clone()));
                recorded = true;
            }
        });
        if let Some(cx) = built {
            cx.inherit_cancel(reason);
        } else if recorded {
            // No context of the fiber's own can wake it yet: poll it once, so
            // a wait on the task's context sees the task's cancellation.
            self.wake.wake_by_ref();
        }
    }

    /// [`FiberHandle::cancel`].
    fn cancel_from_handle(&self) {
        let mut recorded = false;
        let built = self.built_or_record(|pending| {
            if !pending
                .iter()
                .any(|cancel| matches!(cancel, PendingCancel::Handle(_)))
            {
                let task = &self.task_cx;
                let reason = CancelReason::with_origin(
                    CancelKind::User,
                    task.region_id(),
                    task.now_for_observability(),
                )
                .with_task(task.task_id())
                .with_message(HANDLE_CANCEL_MESSAGE);
                pending.push(PendingCancel::Handle(reason));
                recorded = true;
            }
        });
        if let Some(cx) = built {
            cx.cancel_with(CancelKind::User, Some(HANDLE_CANCEL_MESSAGE));
        } else if recorded {
            self.wake.wake_by_ref();
        }
    }
}

impl LazyCurrentCx for FiberCtx {
    fn materialize(&self) -> &Cx {
        if let Some(cx) = self.cx.get() {
            return cx;
        }
        // This runs under the ambient-context borrow and holds `pending`,
        // neither of which re-enters: nothing below may read or install the
        // ambient context or emit an event a subscriber could answer so. A
        // fresh context has no cancel wakers, so the replay wakes nothing.
        let mut pending = self.pending.lock();
        if let Some(cx) = self.cx.get() {
            return cx;
        }
        let cx = self.task_cx.derive_cancel_scope();
        for cancel in pending.drain(..) {
            match cancel {
                PendingCancel::Inherit(reason) => {
                    cx.inherit_cancel(&reason);
                }
                PendingCancel::Handle(reason) => cx.cancel_with_reason(reason),
            }
        }
        // Installed after the replay, which the fiber being polled sees
        // directly. From now on a cancellation of this context polls the
        // fiber again, as the scheduler's cancel waker does for a task.
        let cancel_waker = Arc::new(crate::types::task_context::CancelWaker::new(
            self.wake.clone(),
        ));
        cx.inner.write().cancel_waker = Some(cancel_waker);
        self.cx.get_or_init(|| cx)
    }
}

struct FiberSlot<'env> {
    /// The fiber, or `None` while it is being polled or the slot is free.
    future: Option<FiberFuture<'env>>,
    /// `None` only while the fiber is being polled.
    waker: Option<Waker>,
    wake: Arc<FiberWake>,
    /// The fiber's own context, built on first use; `None` while the fiber
    /// is being polled, when the slot is free, or when the scope runs
    /// outside any task.
    ctx: Option<Arc<FiberCtx>>,
}

#[derive(Default)]
struct FiberSet<'env> {
    slots: Vec<FiberSlot<'env>>,
    free: Vec<usize>,
    live: usize,
    /// No fiber may start any more.
    closed: bool,
}

/// One fiber taken out of its slot for the duration of a poll pass.
struct Running<'env> {
    index: usize,
    future: Option<FiberFuture<'env>>,
    waker: Option<Waker>,
    ctx: Option<Arc<FiberCtx>>,
    finished: bool,
}

/// The panics of the scope that no handle has observed yet, keyed by the
/// panicking fiber's id, in the order they happened.
type UnobservedPanics = Arc<Mutex<Vec<(u64, PanicPayload)>>>;

/// State shared by every handle to one scope.
struct ScopeState<'env> {
    set: Mutex<FiberSet<'env>>,
    queue: Arc<ReadyQueue>,
    next_fiber_id: AtomicU64,
    unobserved_panics: UnobservedPanics,
    /// The context of the task running the scope (`Cx::current()` when it
    /// started), from which each fiber derives its own on first use.
    task_cx: Option<Arc<Cx>>,
    /// Raised when a fiber panics; the scope then cancels its siblings.
    fiber_panicked: Arc<AtomicBool>,
    /// The task's cancellation has been passed to the fibers live then;
    /// fibers started since get it when they start.
    task_cancel_passed: AtomicBool,
}

/// Handle to the fibers of one [`scope`], given to the scope's body.
///
/// Cloning is a reference-count increment. A clone may be moved into a
/// fiber so that the fiber can start siblings; they belong to the same scope.
#[derive(Clone)]
pub struct FiberScope<'env> {
    state: Arc<ScopeState<'env>>,
}

impl std::fmt::Debug for FiberScope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FiberScope")
            .field("live", &self.live())
            .finish()
    }
}

enum HandleState<T> {
    Running(Option<Waker>),
    Finished(Result<T, PanicPayload>),
    /// The fiber was dropped unfinished, with its scope future.
    Abandoned,
    Taken,
}

/// Result cell shared by a fiber and its handle.
struct Completion<T> {
    id: u64,
    state: Mutex<HandleState<T>>,
    unobserved_panics: UnobservedPanics,
}

impl<T> Completion<T> {
    fn finish(&self, result: Result<T, PanicPayload>) {
        if let Err(payload) = &result {
            self.unobserved_panics
                .lock()
                .push((self.id, payload.clone()));
        }
        let waiter = {
            let mut state = self.state.lock();
            match std::mem::replace(&mut *state, HandleState::Finished(result)) {
                HandleState::Running(waiter) => waiter,
                HandleState::Finished(_) | HandleState::Abandoned | HandleState::Taken => None,
            }
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    /// Marks a fiber that will never finish and wakes its handle. A no-op
    /// once the fiber has finished.
    fn abandon(&self) {
        let waiter = {
            let mut state = self.state.lock();
            match &mut *state {
                HandleState::Running(waiter) => {
                    let waiter = waiter.take();
                    *state = HandleState::Abandoned;
                    waiter
                }
                HandleState::Finished(_) | HandleState::Abandoned | HandleState::Taken => None,
            }
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}

/// A fiber's hold on its completion. If the fiber future is dropped before
/// it finishes (its scope future was dropped), the fiber is marked abandoned,
/// so a handle that escaped the scope does not wait forever.
struct FiberCompletion<T>(Arc<Completion<T>>);

impl<T> Drop for FiberCompletion<T> {
    fn drop(&mut self) {
        self.0.abandon();
    }
}

/// Awaitable result of one fiber.
///
/// Awaiting yields `Ok(value)`, or [`JoinError::Panicked`] if the fiber
/// panicked, or [`JoinError::Cancelled`] if the scope future was dropped
/// before the fiber finished. Dropping the handle does not stop the fiber:
/// the scope still waits for it. [`cancel`](Self::cancel) asks it to stop.
#[must_use = "a fiber keeps running even if its handle is dropped; await it to observe its result"]
pub struct FiberHandle<T> {
    completion: Arc<Completion<T>>,
    ctx: Option<Arc<FiberCtx>>,
}

impl<T> FiberHandle<T> {
    /// Requests cancellation of this fiber alone.
    ///
    /// The fiber's context (its [`Cx::current`]) then reports cancellation
    /// at its next checkpoint, and cancel-aware waits registered on it wake.
    /// Cancellation is cooperative: the fiber still runs to completion, and
    /// the scope still waits for it. The calling task and the other fibers
    /// are not cancelled. A scope started outside any task has no fiber
    /// contexts, and then this does nothing.
    pub fn cancel(&self) {
        if let Some(ctx) = &self.ctx {
            ctx.cancel_from_handle();
        }
    }
}

impl<T> std::fmt::Debug for FiberHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let finished = !matches!(*self.completion.state.lock(), HandleState::Running(_));
        f.debug_struct("FiberHandle")
            .field("id", &self.completion.id)
            .field("finished", &finished)
            .finish()
    }
}

impl<T> Future for FiberHandle<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let completion = &self.completion;
        let mut state = completion.state.lock();
        match std::mem::replace(&mut *state, HandleState::Taken) {
            HandleState::Running(waker) => {
                let waker = match waker {
                    Some(waker) if waker.will_wake(cx.waker()) => waker,
                    _ => cx.waker().clone(),
                };
                *state = HandleState::Running(Some(waker));
                Poll::Pending
            }
            HandleState::Finished(result) => {
                drop(state);
                Poll::Ready(result.map_err(|payload| {
                    // This handle observed its fiber's panic; others stay.
                    completion
                        .unobserved_panics
                        .lock()
                        .retain(|(id, _)| *id != completion.id);
                    JoinError::Panicked(payload)
                }))
            }
            HandleState::Abandoned => {
                Poll::Ready(Err(JoinError::Cancelled(crate::types::CancelReason::user(
                    "the fiber scope was dropped before the fiber finished",
                ))))
            }
            HandleState::Taken => Poll::Ready(Err(JoinError::PolledAfterCompletion)),
        }
    }
}

/// Runs one fiber to completion, catching a panic, and publishes the result.
/// A panic raises `panicked`, so the scope cancels the fiber's siblings.
/// `completion` is dropped with this future, which marks the fiber abandoned
/// if it never finished, even when it was never polled.
async fn run_fiber<F: Future>(
    future: F,
    completion: FiberCompletion<F::Output>,
    panicked: Arc<AtomicBool>,
) {
    let mut future = pin!(future);
    let result = poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) => {
                let message = crate::cx::scope::payload_to_string(&payload);
                drop(payload);
                Poll::Ready(Err(PanicPayload::new(message)))
            }
        }
    })
    .await;
    if result.is_err() {
        panicked.store(true, Ordering::Release);
    }
    completion.0.finish(result);
}

impl<'env> FiberScope<'env> {
    fn new() -> Self {
        Self {
            state: Arc::new(ScopeState {
                set: Mutex::new(FiberSet::default()),
                queue: Arc::new(ReadyQueue::default()),
                next_fiber_id: AtomicU64::new(0),
                unobserved_panics: Arc::new(Mutex::new(Vec::new())),
                task_cx: Cx::current().map(Arc::new),
                fiber_panicked: Arc::new(AtomicBool::new(false)),
                task_cancel_passed: AtomicBool::new(false),
            }),
        }
    }

    /// Starts `future` as a fiber of this scope and returns its handle.
    ///
    /// The fiber first runs on the scope's next poll, interleaved with the
    /// body and its siblings. It may borrow anything that outlives the
    /// [`scope`] call.
    ///
    /// # Panics
    ///
    /// Panics if the scope has already finished (a handle that escaped the
    /// body), because the fiber could never run.
    pub fn spawn<F>(&self, future: F) -> FiberHandle<F::Output>
    where
        F: Future + Send + 'env,
        F::Output: Send + 'env,
    {
        let completion = Arc::new(Completion {
            id: self.state.next_fiber_id.fetch_add(1, Ordering::Relaxed),
            state: Mutex::new(HandleState::Running(None)),
            unobserved_panics: Arc::clone(&self.state.unobserved_panics),
        });
        let fiber: FiberFuture<'env> = Box::pin(run_fiber(
            future,
            FiberCompletion(Arc::clone(&completion)),
            Arc::clone(&self.state.fiber_panicked),
        ));
        let (index, fiber_ctx) = {
            let mut guard = self.state.set.lock();
            let set = &mut *guard;
            assert!(
                !set.closed,
                "FiberScope::spawn called after its scope finished; the fiber could never run"
            );
            let index = if let Some(index) = set.free.pop() {
                let slot = &mut set.slots[index];
                slot.wake.queued.store(true, Ordering::Release);
                slot.future = Some(fiber);
                index
            } else {
                let index = set.slots.len();
                let wake = Arc::new(FiberWake {
                    index,
                    queued: AtomicBool::new(true),
                    queue: Arc::clone(&self.state.queue),
                });
                set.slots.push(FiberSlot {
                    future: Some(fiber),
                    waker: Some(Waker::from(Arc::clone(&wake))),
                    wake,
                    ctx: None,
                });
                index
            };
            // The fiber's context wakes the fiber through its slot's waker.
            let slot = &mut set.slots[index];
            let fiber_ctx = self.state.task_cx.as_ref().map(|task_cx| {
                Arc::new(FiberCtx::new(
                    Arc::clone(task_cx),
                    Waker::from(Arc::clone(&slot.wake)),
                ))
            });
            slot.ctx.clone_from(&fiber_ctx);
            set.live += 1;
            (index, fiber_ctx)
        };
        // The task's cancellation was passed only to the fibers live then
        // (`ScopeState::propagate_cancellation`); this one gets it now.
        if self.state.task_cancel_passed.load(Ordering::Acquire)
            && let (Some(ctx), Some(task_cx)) = (&fiber_ctx, &self.state.task_cx)
            && let Some(reason) = task_cx.observable_cancel_reason()
        {
            ctx.inherit_cancel(&reason);
        }
        self.state.queue.schedule(index);
        FiberHandle {
            completion,
            ctx: fiber_ctx,
        }
    }

    /// Number of fibers started in this scope that have not finished.
    #[must_use]
    pub fn live(&self) -> usize {
        self.state.set.lock().live
    }
}

impl ScopeState<'_> {
    /// Records the polling task's waker and marks this thread as polling the
    /// scope until the returned guard drops.
    fn enter_poll(&self, cx: &Context<'_>) -> PollingHere {
        {
            let mut parent = self.queue.parent.lock();
            if !parent.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                *parent = Some(cx.waker().clone());
            }
        }
        PollingHere::enter(&self.queue)
    }

    /// Wakes the polling task if fibers became ready during its poll: wakes
    /// raised on the polling thread inside the poll skip the task's waker.
    fn rewake_if_ready(&self, cx: &Context<'_>) {
        if !self.queue.ready.lock().is_empty() {
            cx.waker().wake_by_ref();
        }
    }

    /// Passes cancellation on to the live fibers' contexts: the task's own,
    /// once, when it first becomes observable (requested and not masked),
    /// and a fail-fast cancellation after a fiber panicked. Cancelling a
    /// fiber's context wakes the fiber (its cancel waker), so it is polled in
    /// this pass or the next. A fiber that has not read its context yet gets
    /// the cancellation when it does, and is woken once now.
    fn propagate_cancellation(&self) {
        let panicked = self.fiber_panicked.swap(false, Ordering::AcqRel);
        let from_task = self.task_cancel_to_pass();
        if !panicked && from_task.is_none() {
            return;
        }
        let contexts: Vec<Arc<FiberCtx>> = self
            .set
            .lock()
            .slots
            .iter()
            .filter_map(|slot| slot.ctx.clone())
            .collect();
        let fail_fast = panicked.then(|| {
            CancelReason::new(CancelKind::FailFast).with_message("a sibling fiber panicked")
        });
        for ctx in &contexts {
            if let Some(reason) = &from_task {
                ctx.inherit_cancel(reason);
            }
            if let Some(reason) = &fail_fast {
                ctx.inherit_cancel(reason);
            }
        }
    }

    /// The task's cancellation reason the first time it is observable, and
    /// `None` after that: it is passed on once, and fibers started later get
    /// it when they start. Passing it again on every poll made draining N
    /// cancelled fibers cost O(N²).
    fn task_cancel_to_pass(&self) -> Option<CancelReason> {
        if self.task_cancel_passed.load(Ordering::Acquire) {
            return None;
        }
        let reason = self.task_cx.as_ref()?.observable_cancel_reason()?;
        self.task_cancel_passed.store(true, Ordering::Release);
        Some(reason)
    }

    /// Polls every ready fiber once. Returns whether any fiber is still live.
    fn poll_fibers(&self) -> bool {
        self.propagate_cancellation();
        let ready = std::mem::take(&mut *self.queue.ready.lock());
        if ready.is_empty() {
            return self.set.lock().live > 0;
        }
        // Take the ready fibers out in one lock acquisition, so polling never
        // holds the table lock (a fiber may wake itself, or start a sibling,
        // while it is polled).
        let mut running = Vec::with_capacity(ready.len());
        {
            let mut set = self.set.lock();
            for index in ready {
                let Some(slot) = set.slots.get_mut(index) else {
                    continue;
                };
                slot.wake.queued.store(false, Ordering::Release);
                if let Some(future) = slot.future.take() {
                    // Cancellation is passed on only between passes, so the
                    // context leaves with the fiber and comes back after.
                    running.push(Running {
                        index,
                        future: Some(future),
                        waker: slot.waker.take(),
                        ctx: slot.ctx.take(),
                        finished: false,
                    });
                }
            }
        }
        for fiber in &mut running {
            if let (Some(future), Some(waker)) = (fiber.future.as_mut(), fiber.waker.as_ref()) {
                // Inside the fiber, the ambient context is the fiber's own,
                // derived the first time the fiber reads it.
                let current = fiber.ctx.as_ref().map(|ctx| {
                    let mask = ctx.task_cx.runtime_mask;
                    Cx::set_current_lazy(Arc::clone(ctx) as Arc<dyn LazyCurrentCx>, mask)
                });
                fiber.finished = future
                    .as_mut()
                    .poll(&mut Context::from_waker(waker))
                    .is_ready();
                drop(current);
            }
        }
        let live = {
            let mut guard = self.set.lock();
            let set = &mut *guard;
            for fiber in &mut running {
                let slot = &mut set.slots[fiber.index];
                slot.waker = fiber.waker.take();
                if fiber.finished {
                    set.free.push(fiber.index);
                    set.live -= 1;
                } else {
                    slot.future = fiber.future.take();
                    slot.ctx = fiber.ctx.take();
                }
            }
            set.live > 0
        };
        // `running` still owns the finished fibers, dropped here unlocked.
        drop(running);
        // A fiber that panicked in this pass cancels its siblings now, so a
        // sibling parked on cancellation wakes even if nothing else does.
        if self.fiber_panicked.load(Ordering::Acquire) {
            self.propagate_cancellation();
        }
        live
    }

    /// Closes the scope if no fiber is live.
    fn try_close(&self) -> bool {
        let mut set = self.set.lock();
        if set.live > 0 {
            return false;
        }
        set.closed = true;
        true
    }

    /// Closes the scope and drops every fiber it still holds.
    fn close_and_drop_fibers(&self) {
        let slots = {
            let mut set = self.set.lock();
            set.closed = true;
            set.live = 0;
            set.free.clear();
            std::mem::take(&mut set.slots)
        };
        // Fiber futures are dropped outside the lock: their destructors may
        // touch the scope through a captured handle.
        drop(slots);
    }
}

/// Drops the scope's remaining fibers when the [`scope`] future is dropped
/// before it finishes, so that a handle that escaped the body cannot keep
/// them (or a reference cycle through them) alive.
struct CloseOnDrop<'a, 'env>(&'a ScopeState<'env>);

impl Drop for CloseOnDrop<'_, '_> {
    fn drop(&mut self) {
        self.0.close_and_drop_fibers();
    }
}

/// Runs `body` with a [`FiberScope`] and waits for every fiber it starts.
///
/// See the [module documentation](self) for the semantics. The future this
/// returns is `Send` when `body`'s future is, including inside a spawned
/// `'static` task.
///
/// # Panics
///
/// Re-raises a fiber panic that no handle observed, after every fiber has
/// finished. A scope future dropped before then drops those panics with its
/// fibers.
pub async fn scope<'env, B, Fut>(body: B) -> Fut::Output
where
    B: FnOnce(FiberScope<'env>) -> Fut,
    Fut: Future,
{
    let scope = FiberScope::new();
    let close_on_drop = CloseOnDrop(&scope.state);
    let state = close_on_drop.0;
    let result = {
        let mut body = pin!(body(scope.clone()));
        poll_fn(|cx| {
            let polling = state.enter_poll(cx);
            // Poll the body first so fibers it starts run in this same pass.
            let outcome = body.as_mut().poll(cx);
            state.poll_fibers();
            drop(polling);
            if outcome.is_pending() {
                state.rewake_if_ready(cx);
            }
            outcome
        })
        .await
    };
    poll_fn(|cx| {
        let polling = state.enter_poll(cx);
        let live = state.poll_fibers();
        drop(polling);
        if live || !state.try_close() {
            state.rewake_if_ready(cx);
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    let unobserved = std::mem::take(&mut *state.unobserved_panics.lock());
    if let Some((_, payload)) = unobserved.first() {
        let more = match unobserved.len() - 1 {
            0 => String::new(),
            others => format!(" ({others} more unobserved fiber panics)"),
        };
        panic!(
            "a fiber panicked and no handle observed it: {}{more}",
            payload.message()
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use std::sync::atomic::AtomicUsize;

    fn block_on<F: Future>(future: F) -> F::Output {
        RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime")
            .block_on(future)
    }

    /// A task waker that counts its wakes.
    #[derive(Default)]
    struct CountingWake(AtomicUsize);

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl CountingWake {
        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn fibers_borrow_the_callers_stack_and_return_results() {
        let words = vec!["structured".to_string(), "concurrency".to_string()];
        let words = &words;
        let total = block_on(scope(|s| async move {
            let a = s.spawn(async move { words[0].len() });
            let b = s.spawn(async move { words[1].len() });
            a.await.expect("a") + b.await.expect("b")
        }));
        assert_eq!(total, 21);
    }

    #[test]
    fn scope_waits_for_fibers_whose_handles_were_dropped() {
        let finished = AtomicUsize::new(0);
        let finished_ref = &finished;
        block_on(scope(|s| async move {
            for _ in 0..100 {
                drop(s.spawn(async move {
                    crate::runtime::yield_now().await;
                    finished_ref.fetch_add(1, Ordering::SeqCst);
                }));
            }
        }));
        assert_eq!(finished.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn fibers_interleave_rather_than_run_to_completion_one_by_one() {
        let log = Mutex::new(Vec::new());
        let log_ref = &log;
        block_on(scope(|s| async move {
            for id in 0..3 {
                drop(s.spawn(async move {
                    log_ref.lock().push((id, 0));
                    crate::runtime::yield_now().await;
                    log_ref.lock().push((id, 1));
                }));
            }
        }));
        let log = log.into_inner();
        let first_round: Vec<_> = log[..3].iter().map(|(_, step)| *step).collect();
        assert_eq!(
            first_round,
            vec![0, 0, 0],
            "every fiber starts before any resumes: {log:?}"
        );
        assert_eq!(log.len(), 6);
    }

    #[test]
    fn a_self_waking_fiber_does_not_monopolize_the_scope_poll() {
        // A fiber that yields forever would hang a scope that re-polled
        // self-woken fibers within one poll; here the sibling still finishes
        // and the scope stops the spinner through a flag.
        let stop = AtomicBool::new(false);
        let spins = AtomicUsize::new(0);
        let (stop_ref, spins_ref) = (&stop, &spins);
        block_on(scope(|s| async move {
            drop(s.spawn(async move {
                while !stop_ref.load(Ordering::SeqCst) {
                    spins_ref.fetch_add(1, Ordering::SeqCst);
                    crate::runtime::yield_now().await;
                }
            }));
            let worker = s.spawn(async move {
                for _ in 0..10 {
                    crate::runtime::yield_now().await;
                }
                stop_ref.store(true, Ordering::SeqCst);
            });
            worker.await.expect("worker fiber");
        }));
        assert!(spins.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn a_fiber_panic_is_reported_through_its_handle() {
        let result = block_on(scope(|s| async move {
            let handle = s.spawn(async {
                let fail = std::hint::black_box(true);
                assert!(!fail, "boom");
                1
            });
            handle.await
        }));
        match result {
            Err(JoinError::Panicked(payload)) => assert!(payload.message().contains("boom")),
            other => panic!("expected a panicked join, got {other:?}"),
        }
    }

    #[test]
    fn an_unobserved_fiber_panic_is_raised_when_the_scope_finishes() {
        let raised = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(scope(|s| async move {
                drop(s.spawn(async {
                    let fail = std::hint::black_box(true);
                    assert!(!fail, "unobserved");
                }));
            }));
        }));
        let payload = raised.expect_err("the unobserved panic must surface");
        let message = crate::cx::scope::payload_to_string(&payload);
        assert!(message.contains("unobserved"), "{message}");
    }

    /// Two fibers panic in the same pass and the body observes only the
    /// first: the second panic must still surface when the scope finishes.
    #[test]
    fn a_second_unobserved_panic_is_raised_after_the_first_is_observed() {
        let raised = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(scope(|s| async move {
                let first = s.spawn(async {
                    let fail = std::hint::black_box(true);
                    assert!(!fail, "first");
                });
                let second = s.spawn(async {
                    let fail = std::hint::black_box(true);
                    assert!(!fail, "second");
                });
                assert!(matches!(first.await, Err(JoinError::Panicked(_))));
                drop(second);
            }));
        }));
        let payload = raised.expect_err("the second, unobserved panic must surface");
        let message = crate::cx::scope::payload_to_string(&payload);
        assert!(message.contains("second"), "{message}");
    }

    #[test]
    fn many_fibers_complete_with_slot_reuse() {
        let sum = block_on(scope(|s| async move {
            let mut total = 0usize;
            for round in 0..10 {
                let handles: Vec<_> = (0..100)
                    .map(|i| s.spawn(async move { round * 100 + i }))
                    .collect();
                for handle in handles {
                    total += handle.await.expect("fiber");
                }
            }
            total
        }));
        assert_eq!(sum, (0..1000).sum::<usize>());
    }

    #[test]
    fn a_finished_fibers_slot_and_wake_handle_are_reused() {
        let slots = block_on(scope(|s| async move {
            for i in 0..100 {
                assert_eq!(s.spawn(async move { i }).await.expect("fiber"), i);
            }
            s.state.set.lock().slots.len()
        }));
        assert_eq!(slots, 1, "sequential fibers keep reusing one slot");
    }

    #[test]
    fn a_fiber_can_start_siblings_and_the_scope_waits_for_them() {
        let finished = AtomicUsize::new(0);
        let finished_ref = &finished;
        let observed = block_on(scope(|s| async move {
            let spawner = s.clone();
            let parent = s.spawn(async move {
                crate::runtime::yield_now().await;
                for _ in 0..5 {
                    drop(spawner.spawn(async move {
                        crate::runtime::yield_now().await;
                        finished_ref.fetch_add(1, Ordering::SeqCst);
                    }));
                }
            });
            parent.await.expect("parent fiber");
            // The siblings were started but have not run to completion yet.
            s.live()
        }));
        assert_eq!(observed, 5, "the body returned while siblings were live");
        assert_eq!(finished.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn wakes_inside_the_scope_poll_rewake_the_task_once() {
        let wakes = Arc::new(CountingWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!(scope(|s| async move {
            for _ in 0..10 {
                drop(s.spawn(crate::runtime::yield_now()));
            }
            std::future::pending::<()>().await;
        }));
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            wakes.count(),
            1,
            "ten fibers that woke themselves during the pass re-wake the task once"
        );
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(wakes.count(), 1, "the second pass finished every fiber");
    }

    #[test]
    fn a_spawn_from_outside_the_scope_poll_wakes_the_task() {
        let wakes = Arc::new(CountingWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let escaped = Mutex::new(None);
        let escaped_ref = &escaped;
        let mut future = pin!(scope(|s| async move {
            *escaped_ref.lock() = Some(s);
            std::future::pending::<()>().await;
        }));
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(wakes.count(), 0);
        let outside = escaped.lock().take().expect("escaped handle");
        let mut handle = pin!(outside.spawn(async { 5 }));
        assert_eq!(wakes.count(), 1, "the task must learn about the new fiber");
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(outside.live(), 0, "the woken scope ran the fiber");
        match handle.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(value)) => assert_eq!(value, 5),
            other => panic!("expected the fiber's value, got {other:?}"),
        }
    }

    #[test]
    fn spawning_through_a_handle_that_escaped_the_scope_panics() {
        let escaped = block_on(scope(|s| async move { s }));
        assert_eq!(escaped.live(), 0);
        let raised = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(escaped.spawn(async {}));
        }));
        let payload = raised.expect_err("a finished scope must refuse new fibers");
        let message = crate::cx::scope::payload_to_string(&payload);
        assert!(message.contains("after its scope finished"), "{message}");
        assert_eq!(escaped.live(), 0, "the refused fiber was not queued");
    }

    #[test]
    fn dropping_an_unfinished_scope_drops_its_fibers() {
        struct SetOnDrop<'a>(&'a AtomicBool);
        impl Drop for SetOnDrop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = AtomicBool::new(false);
        let dropped_ref = &dropped;
        let escaped = Mutex::new(None);
        let escaped_ref = &escaped;
        {
            let mut future = pin!(scope(|s| async move {
                *escaped_ref.lock() = Some(s.clone());
                drop(s.spawn(async move {
                    let _guard = SetOnDrop(dropped_ref);
                    std::future::pending::<()>().await;
                }));
                std::future::pending::<()>().await;
            }));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut cx).is_pending());
            assert!(!dropped.load(Ordering::SeqCst), "the fiber is parked");
        }
        assert!(
            dropped.load(Ordering::SeqCst),
            "dropping the scope future must drop its fibers even though a handle escaped"
        );
        let escaped = escaped.into_inner().expect("escaped handle");
        assert_eq!(escaped.live(), 0);
    }

    /// A handle that outlives its scope future must not wait forever: when
    /// the scope future is dropped, the fiber's handle is woken and resolves
    /// as cancelled, whether the fiber had started or not.
    #[test]
    fn handles_that_outlive_a_dropped_scope_are_woken_and_cancelled() {
        let escaped = Mutex::new(None);
        let escaped_ref = &escaped;
        let wakes = Arc::new(CountingWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let (mut started, mut unstarted) = {
            let mut future = pin!(scope(|s| async move {
                let started = s.spawn(std::future::pending::<u32>());
                *escaped_ref.lock() = Some((s.clone(), started));
                std::future::pending::<()>().await;
            }));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut cx).is_pending());
            let (scope_handle, mut started) = escaped_ref.lock().take().expect("escaped");
            assert!(
                Pin::new(&mut started)
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending(),
                "the started fiber is parked"
            );
            // Spawned from outside the scope's poll: never polled.
            let unstarted = scope_handle.spawn(async { 7u32 });
            (started, unstarted)
        };
        assert_eq!(
            wakes.count(),
            1,
            "dropping the scope wakes the waiting handle"
        );
        for (name, handle) in [("started", &mut started), ("unstarted", &mut unstarted)] {
            match Pin::new(handle).poll(&mut Context::from_waker(&waker)) {
                Poll::Ready(Err(JoinError::Cancelled(_))) => {}
                other => panic!("{name}: expected a cancelled join, got {other:?}"),
            }
        }
    }

    #[test]
    fn scope_future_is_send_for_send_fibers() {
        fn assert_send<T: Send>(_: &T) {}
        let data = [1u32, 2, 3];
        let data = &data;
        let future = scope(|s| async move {
            let h = s.spawn(async move { data.iter().sum::<u32>() });
            h.await.expect("sum")
        });
        assert_send(&future);
        assert_eq!(block_on(future), 6);
    }

    #[test]
    fn scope_runs_inside_a_send_static_task_over_task_local_borrows() {
        // The shape of a spawned task: the future owns its data, is `Send +
        // 'static`, and its fibers borrow that data. A higher-ranked body
        // bound fails to compile here (rust-lang/rust#100013).
        fn require_send_static<F: Future + Send + 'static>(future: F) -> F {
            future
        }
        let task = require_send_static(async move {
            let inputs: Vec<usize> = (0..64).collect();
            let inputs = &inputs;
            scope(|s| async move {
                let handles: Vec<_> = (0..inputs.len())
                    .map(|i| s.spawn(async move { inputs[i] * 2 }))
                    .collect();
                let mut total = 0;
                for handle in handles {
                    total += handle.await.expect("fiber");
                }
                total
            })
            .await
        });
        assert_eq!(block_on(task), (0..64).map(|i| i * 2).sum::<usize>());
    }

    // --- Per-fiber cancellation (br-asupersync-issue65-criticisms-kpmoy5.3.1/.3.2) ---

    /// Runs `future` with `task_cx` as the ambient context, outside any
    /// runtime: the scope takes it as its task's context.
    fn block_on_in<F: Future>(task_cx: &Cx, future: F) -> F::Output {
        let _current = Cx::set_current(Some(task_cx.clone()));
        futures_lite::future::block_on(future)
    }

    /// Runs `test` on a scratch thread and fails, instead of hanging, if a
    /// cancellation it waits for never arrives.
    fn within_watchdog<T: Send + 'static>(test: impl FnOnce() -> T + Send + 'static) -> T {
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(test());
        });
        match result.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(value) => value,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("a fiber waited 10 s for a cancellation that never reached it")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("the test thread panicked")
            }
        }
    }

    /// Resolves with the ambient context's cancellation reason (inside a
    /// fiber, the fiber's own), parking on its cancel waker until then.
    fn until_cancelled() -> impl Future<Output = CancelReason> {
        poll_fn(|task_cx| {
            let cx = Cx::current().expect("an ambient context");
            if !cx.is_cancel_requested() {
                cx.register_cancel_waker(task_cx.waker());
                if !cx.is_cancel_requested() {
                    return Poll::Pending;
                }
            }
            Poll::Ready(
                cx.cancel_reason()
                    .expect("a cancelled context has a reason"),
            )
        })
    }

    #[test]
    fn inside_a_fiber_the_ambient_context_is_the_fibers_own() {
        let task_cx = Cx::for_testing();
        let task_ref = &task_cx;
        block_on_in(&task_cx, async {
            scope(|s| async move {
                s.spawn(async move {
                    let fiber_cx = Cx::current().expect("the fiber's context");
                    assert_eq!(fiber_cx.task_id(), task_ref.task_id(), "same task");
                    assert_eq!(fiber_cx.region_id(), task_ref.region_id(), "same region");
                    fiber_cx.cancel_with(CancelKind::User, Some("the fiber's own"));
                    assert!(fiber_cx.is_cancel_requested());
                })
                .await
                .expect("fiber");
            })
            .await;
        });
        assert!(
            !task_cx.is_cancel_requested(),
            "cancelling a fiber's context does not cancel the task"
        );
    }

    #[test]
    fn a_fiber_handle_cancels_only_its_fiber() {
        let (first, second, task_cancelled) = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let (first, second) = block_on_in(&task_cx, async {
                scope(|s| async move {
                    let a = s.spawn(until_cancelled());
                    let b = s.spawn(until_cancelled());
                    a.cancel();
                    let first = a.await.expect("a");
                    assert_eq!(s.live(), 1, "b is still waiting");
                    b.cancel();
                    (first, b.await.expect("b"))
                })
                .await
            });
            (first, second, task_cx.is_cancel_requested())
        });
        assert_eq!(first.kind, CancelKind::User);
        assert_eq!(second.kind, CancelKind::User);
        assert!(!task_cancelled, "the task is not cancelled");
    }

    #[test]
    fn the_tasks_cancellation_reaches_every_fiber() {
        let reasons = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let waiting: Vec<_> = (0..3).map(|_| s.spawn(until_cancelled())).collect();
                    crate::runtime::yield_now().await;
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    let mut reasons = Vec::new();
                    for handle in waiting {
                        reasons.push(handle.await.expect("fiber"));
                    }
                    reasons
                })
                .await
            })
        });
        assert_eq!(reasons.len(), 3);
        for reason in reasons {
            assert_eq!(reason.kind, CancelKind::Shutdown, "the task's own reason");
        }
    }

    #[test]
    fn a_fiber_started_after_the_task_was_cancelled_starts_cancelled() {
        let reason = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            task_cx.cancel_with(CancelKind::User, Some("cancelled before the fiber"));
            block_on_in(&task_cx, async {
                scope(|s| async move { s.spawn(until_cancelled()).await.expect("fiber") }).await
            })
        });
        assert_eq!(reason.kind, CancelKind::User);
    }

    #[test]
    fn a_panicking_fiber_cancels_its_siblings() {
        let (panicked, sibling, task_cancelled) = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let (panicked, sibling) = block_on_in(&task_cx, async {
                scope(|s| async move {
                    let sibling = s.spawn(until_cancelled());
                    let failing = s.spawn(async {
                        crate::runtime::yield_now().await;
                        panic!("this fiber fails");
                    });
                    let panicked = failing.await.is_err();
                    (panicked, sibling.await.expect("sibling"))
                })
                .await
            });
            (panicked, sibling, task_cx.is_cancel_requested())
        });
        assert!(panicked, "the failing fiber's handle reports its panic");
        assert_eq!(
            sibling.kind,
            CancelKind::FailFast,
            "fail-fast sibling cancel"
        );
        assert!(!task_cancelled, "the task is not cancelled");
    }

    // --- Contexts built on first use (br-asupersync-98569u) ---

    /// Yields twice without reading the ambient context, then waits on the
    /// fiber's own context until it is cancelled.
    async fn read_context_late() -> CancelReason {
        crate::runtime::yield_now().await;
        crate::runtime::yield_now().await;
        until_cancelled().await
    }

    #[test]
    fn a_fiber_that_never_reads_its_context_derives_none() {
        let task_cx = Cx::for_testing();
        let (silent_built, reader_built) = block_on_in(&task_cx, async {
            scope(|s| async move {
                let silent = s.spawn(async { 1 });
                let reader = s.spawn(async { Cx::current().is_some() });
                let silent_ctx = Arc::clone(silent.ctx.as_ref().expect("a task scope's cell"));
                let reader_ctx = Arc::clone(reader.ctx.as_ref().expect("a task scope's cell"));
                assert_eq!(silent.await.expect("silent"), 1);
                assert!(reader.await.expect("reader"), "the fiber has a context");
                let built = |ctx: &FiberCtx| ctx.cx.get().is_some();
                (built(&silent_ctx), built(&reader_ctx))
            })
            .await
        });
        assert!(
            !silent_built,
            "a fiber that never read its context has none"
        );
        assert!(
            reader_built,
            "reading Cx::current() built the fiber's context"
        );
    }

    #[test]
    fn every_read_in_a_fiber_sees_the_same_context() {
        let task_cx = Cx::for_testing();
        let (same, task_cancelled) = block_on_in(&task_cx, async {
            let same = scope(|s| async move {
                s.spawn(async {
                    let first = Cx::current().expect("the fiber's context");
                    crate::runtime::yield_now().await;
                    let later = Cx::current().expect("the fiber's context");
                    first.cancel_fast(CancelKind::User);
                    later.is_cancel_requested()
                })
                .await
                .expect("fiber")
            })
            .await;
            (same, Cx::current().expect("task").is_cancel_requested())
        });
        assert!(same, "both reads see one context, across polls");
        assert!(!task_cancelled, "and it is not the task's");
    }

    #[test]
    fn with_current_in_a_fiber_borrows_the_fibers_own_context() {
        let task_cx = Cx::for_testing();
        let (cancelled_inside, task_cancelled) = block_on_in(&task_cx, async {
            let inside = scope(|s| async move {
                s.spawn(async {
                    Cx::with_current(|cx| cx.cancel_fast(CancelKind::User))
                        .expect("the fiber's context");
                    Cx::current()
                        .expect("the fiber's context")
                        .is_cancel_requested()
                })
                .await
                .expect("fiber")
            })
            .await;
            (inside, Cx::current().expect("task").is_cancel_requested())
        });
        assert!(cancelled_inside, "with_current reached the fiber's context");
        assert!(!task_cancelled, "not the task's");
    }

    /// The task is cancelled, then the fiber's handle, both before the fiber
    /// reads its context. Replayed in that order the task's `Shutdown` stays
    /// (the handle's weaker `User` cannot replace it), as on a context built
    /// at spawn. Replayed the other way, `User` would stick: a cancelled
    /// context ignores a later inherit.
    #[test]
    fn cancellations_before_the_first_read_apply_in_order() {
        let reason = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let fiber = s.spawn(read_context_late());
                    crate::runtime::yield_now().await;
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    crate::runtime::yield_now().await;
                    fiber.cancel();
                    fiber.await.expect("fiber")
                })
                .await
            })
        });
        assert_eq!(reason.kind, CancelKind::Shutdown, "the first cancellation");
    }

    #[test]
    fn a_handle_cancel_before_the_fiber_reads_its_context_reaches_it() {
        let (reason, task_cancelled) = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let reason = block_on_in(&task_cx, async {
                scope(|s| async move {
                    let fiber = s.spawn(read_context_late());
                    fiber.cancel();
                    fiber.await.expect("fiber")
                })
                .await
            });
            (reason, task_cx.is_cancel_requested())
        });
        assert_eq!(reason.kind, CancelKind::User, "the handle's cancellation");
        assert!(
            !task_cancelled,
            "cancelling a fiber does not cancel the task"
        );
    }

    #[test]
    fn the_tasks_cancellation_reaches_a_fiber_that_reads_its_context_later() {
        let reason = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let fiber = s.spawn(read_context_late());
                    crate::runtime::yield_now().await;
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    fiber.await.expect("fiber")
                })
                .await
            })
        });
        assert_eq!(reason.kind, CancelKind::Shutdown, "the task's own reason");
    }

    #[test]
    fn a_panic_cancels_a_sibling_that_reads_its_context_later() {
        let (panicked, sibling) = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let sibling = s.spawn(read_context_late());
                    let failing = s.spawn(async {
                        let fail = std::hint::black_box(true);
                        assert!(!fail, "this fiber fails");
                    });
                    let panicked = failing.await.is_err();
                    (panicked, sibling.await.expect("sibling"))
                })
                .await
            })
        });
        assert!(panicked, "the failing fiber's handle reports its panic");
        assert_eq!(
            sibling.kind,
            CancelKind::FailFast,
            "the sibling read its context after the panic and saw the fail-fast"
        );
    }

    #[test]
    fn without_a_task_context_fibers_run_without_one() {
        let ran = futures_lite::future::block_on(scope(|s| async move {
            let handle = s.spawn(async { Cx::current().is_none() });
            handle.cancel();
            handle.await.expect("fiber")
        }));
        assert!(ran, "no ambient context, and cancel() is a no-op");
    }

    // --- Native task abort (br-asupersync-issue65-criticisms-kpmoy5.3.3) ---

    /// Parks on the ambient (fiber) context's cancel waker, counting itself
    /// in `parked` once it is parked, and records the cancellation kind it
    /// then observes in `seen`.
    fn parked_until_cancelled(
        parked: Arc<AtomicUsize>,
        seen: Arc<Mutex<Vec<CancelKind>>>,
    ) -> impl Future<Output = ()> {
        let mut counted = false;
        poll_fn(move |task_cx| {
            let cx = Cx::current().expect("the fiber's context");
            if !cx.is_cancel_requested() {
                cx.register_cancel_waker(task_cx.waker());
                if !cx.is_cancel_requested() {
                    if !counted {
                        counted = true;
                        parked.fetch_add(1, Ordering::SeqCst);
                    }
                    return Poll::Pending;
                }
            }
            let reason = cx
                .cancel_reason()
                .expect("a cancelled context has a reason");
            seen.lock().push(reason.kind);
            Poll::Ready(())
        })
    }

    /// Spawns a task whose body runs a scope with two fibers parked on their
    /// own contexts, proves both are parked, aborts the task, and returns
    /// the cancellation kinds the fibers observed.
    fn abort_a_task_with_parked_fibers(builder: RuntimeBuilder) -> Vec<CancelKind> {
        let runtime = builder.build().expect("runtime");
        let parked = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (parked_in_task, seen_in_task) = (Arc::clone(&parked), Arc::clone(&seen));
        runtime.block_on(async move {
            let cx = Cx::current().expect("the root context");
            let mut handle = cx
                .spawn(move |_task_cx| async move {
                    scope(|s| async move {
                        let waits: Vec<_> = (0..2)
                            .map(|_| {
                                s.spawn(parked_until_cancelled(
                                    Arc::clone(&parked_in_task),
                                    Arc::clone(&seen_in_task),
                                ))
                            })
                            .collect();
                        for wait in waits {
                            wait.await.expect("fiber");
                        }
                    })
                    .await;
                })
                .expect("spawn the task");
            while parked.load(Ordering::SeqCst) < 2 {
                crate::runtime::yield_now().await;
            }
            handle.abort_with_reason(
                CancelReason::new(CancelKind::Shutdown).with_message("abort the scope's task"),
            );
            // Cancelled or Ok: either way the task finishes after its fibers drain.
            let _ = handle.join(&cx).await;
        });
        seen.lock().clone()
    }

    #[test]
    fn aborting_the_task_reaches_its_parked_fibers_current_thread() {
        let seen =
            within_watchdog(|| abort_a_task_with_parked_fibers(RuntimeBuilder::current_thread()));
        assert_eq!(
            seen,
            vec![CancelKind::Shutdown; 2],
            "both fibers see the task's reason"
        );
    }

    #[test]
    fn aborting_the_task_reaches_its_parked_fibers_four_workers() {
        let seen = within_watchdog(|| {
            abort_a_task_with_parked_fibers(RuntimeBuilder::new().worker_threads(4))
        });
        assert_eq!(
            seen,
            vec![CancelKind::Shutdown; 2],
            "both fibers see the task's reason"
        );
    }

    // --- Borrowing, forgetting and lab determinism (kpmoy5.3.3) ---

    #[test]
    fn fibers_mutate_disjoint_borrows_and_use_non_send_values_between_awaits() {
        let mut data = vec![0_u32; 4];
        let mut total = 0_usize;
        {
            let (left, right) = data.split_at_mut(2);
            let total = &mut total;
            block_on(scope(|s| async move {
                let a = s.spawn(async move {
                    for value in left.iter_mut() {
                        *value += 1;
                        crate::runtime::yield_now().await;
                    }
                });
                let b = s.spawn(async move {
                    for value in right.iter_mut() {
                        *value += 2;
                        crate::runtime::yield_now().await;
                    }
                    // A !Send value is fine while no await holds it.
                    let local = std::rc::Rc::new(5_usize);
                    *local
                });
                a.await.expect("left half");
                *total += b.await.expect("right half");
            }));
        }
        assert_eq!(data, [1, 1, 2, 2]);
        assert_eq!(total, 5);
    }

    #[test]
    fn forgetting_a_started_scope_future_is_sound_and_ends_its_borrow() {
        let mut data = vec![1, 2, 3];
        {
            let borrowed = &data;
            let mut started = Box::pin(scope(|s| async move {
                s.spawn(async move {
                    std::future::pending::<()>().await;
                    borrowed.len()
                })
                .await
                .expect("never resolves")
            }));
            let mut task = Context::from_waker(Waker::noop());
            assert!(
                started.as_mut().poll(&mut task).is_pending(),
                "the fiber is parked"
            );
            // Leaks the scope and its parked fiber: nothing runs again, and
            // nothing panics.
            std::mem::forget(started);
        }
        // The borrow ended with the forgotten future.
        data.push(4);
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    // The body returns the fiber's handle on purpose: the test is about a
    // handle that leaves the scope body.
    #[allow(clippy::async_yields_async)]
    fn a_handle_that_leaves_the_body_still_yields_its_result() {
        let handle = block_on(scope(|s| async move { s.spawn(async { 7_u8 }) }));
        assert_eq!(block_on(handle).expect("the scope waited for the fiber"), 7);
    }

    /// Logs each name, yielding after each one.
    async fn logged_steps(log: Arc<Mutex<Vec<&'static str>>>, names: &'static [&'static str]) {
        for &name in names {
            log.lock().push(name);
            crate::runtime::yield_now().await;
        }
    }

    /// One lab run: a task runs a scope whose fibers interleave while a third
    /// parks until cancelled, and the owner aborts the task once that fiber
    /// is parked. Returns the trace fingerprint, the fibers' step log and the
    /// cancellation kind the parked fiber saw.
    fn lab_fiber_run(seed: u64) -> (u64, Vec<&'static str>, Vec<CancelKind>) {
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::Budget;

        let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let log = Arc::new(Mutex::new(Vec::new()));
        let parked = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (log_in_task, parked_in_task, seen_in_task) =
            (Arc::clone(&log), Arc::clone(&parked), Arc::clone(&seen));
        let (owner, _join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task context");
                let (log_in_scope, parked_in_scope) =
                    (Arc::clone(&log_in_task), Arc::clone(&parked_in_task));
                let mut worker = cx
                    .spawn(move |task_cx| async move {
                        scope(|s| async move {
                            let a = s.spawn(logged_steps(
                                Arc::clone(&log_in_scope),
                                &["a0", "a1", "a2"],
                            ));
                            let b = s.spawn(logged_steps(Arc::clone(&log_in_scope), &["b0", "b1"]));
                            let c = s.spawn(parked_until_cancelled(parked_in_scope, seen_in_task));
                            for handle in [a, b, c] {
                                handle.await.expect("fiber");
                            }
                        })
                        .await;
                        // Acknowledge the abort, as a cooperative task does.
                        let _ = task_cx.checkpoint();
                    })
                    .expect("spawn the worker");
                while parked_in_task.load(Ordering::SeqCst) < 1 || log_in_task.lock().len() < 5 {
                    crate::runtime::yield_now().await;
                }
                worker.abort_with_reason(CancelReason::new(CancelKind::Shutdown));
                let _ = worker.join(&cx).await;
            })
            .expect("create the owner");
        lab.scheduler.lock().schedule(owner, 0);
        let report = lab.run_until_quiescent_with_report();
        assert!(report.lab_test_passed(), "seed {seed:#x}: {report:?}");
        assert_eq!(lab.state.live_task_count(), 0, "seed {seed:#x}");
        let steps = log.lock().clone();
        let kinds = seen.lock().clone();
        (report.trace_fingerprint, steps, kinds)
    }

    #[test]
    fn lab_fiber_runs_replay_identically_per_seed() {
        let mut step_logs = Vec::new();
        for seed in [0xF1BE_0001_u64, 0xF1BE_0002] {
            let first = lab_fiber_run(seed);
            let second = lab_fiber_run(seed);
            assert_eq!(first, second, "seed {seed:#x} replays identically");
            assert_eq!(first.2, [CancelKind::Shutdown], "seed {seed:#x}");
            step_logs.push(first.1);
        }
        // The interleaving inside one task belongs to the scope, not to the
        // scheduler: it is the same under every seed.
        assert_eq!(step_logs[0], ["a0", "b0", "a1", "b1", "a2"]);
        assert_eq!(step_logs[0], step_logs[1]);
    }

    #[test]
    fn an_obligation_held_by_a_parked_fiber_is_a_futurelock_of_its_task() {
        use crate::lab::runtime::InvariantViolation;
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::Budget;

        let mut lab = LabRuntime::new(
            LabConfig::new(0xF1BE_0F17)
                .futurelock_max_idle_steps(64)
                .panic_on_futurelock(false)
                .max_steps(100_000),
        );
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (release, mut released) = crate::channel::oneshot::channel::<()>();
        let (holder, _holder_join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let (tx, _rx) = crate::channel::mpsc::channel::<u8>(1);
                scope(|s| async move {
                    s.spawn(async move {
                        let cx = Cx::current().expect("the fiber's context");
                        let permit = tx.reserve(&cx).await.expect("capacity");
                        // Parked while the permit's obligation is pending.
                        released.recv(&cx).await.expect("released");
                        permit.try_send(7).expect("the receiver is alive");
                    })
                    .await
                    .expect("fiber");
                })
                .await;
            })
            .expect("create the holder");
        let (ticker, _ticker_join) = lab
            .state
            .create_task(root, Budget::INFINITE, async {
                for _ in 0..256 {
                    crate::runtime::yield_now().await;
                }
            })
            .expect("create the ticker");
        lab.scheduler.lock().schedule(holder, 0);
        lab.scheduler.lock().schedule(ticker, 0);
        lab.run_until_idle();
        let futurelocks: Vec<_> = lab
            .check_invariants()
            .into_iter()
            .filter_map(|violation| match violation {
                InvariantViolation::Futurelock { task, held, .. } => Some((task, held.len())),
                _ => None,
            })
            .collect();
        assert_eq!(
            futurelocks,
            [(holder, 1)],
            "the fiber's obligation is held by its task, which the detector names"
        );
        release.send_blocking(()).expect("the fiber still waits");
        let report = lab.run_until_quiescent_with_report();
        assert!(report.lab_test_passed(), "{report:?}");
    }

    // --- A cancellation polls the fiber again (br-asupersync-tc55xq) ---

    /// Waits as a semaphore or RwLock acquire does: it registers no cancel
    /// waker and sees cancellation only when it is polled again. It checks
    /// `waited_on`, or else the ambient context (the fiber's own).
    fn sees_cancel_only_when_polled(waited_on: Option<Cx>) -> impl Future<Output = CancelKind> {
        poll_fn(move |_| {
            let cx = waited_on
                .clone()
                .unwrap_or_else(|| Cx::current().expect("an ambient context"));
            if cx.checkpoint().is_err() {
                let reason = cx
                    .cancel_reason()
                    .expect("a cancelled context has a reason");
                Poll::Ready(reason.kind)
            } else {
                Poll::Pending
            }
        })
    }

    #[test]
    fn a_handle_cancel_polls_a_fiber_whose_wait_registered_no_cancel_waker() {
        let kind = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let wait = s.spawn(sees_cancel_only_when_polled(None));
                    crate::runtime::yield_now().await;
                    wait.cancel();
                    wait.await.expect("fiber")
                })
                .await
            })
        });
        assert_eq!(kind, CancelKind::User);
    }

    #[test]
    fn cancelling_a_fiber_reaches_the_fibers_of_a_scope_nested_in_it() {
        let reason = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let outer = s.spawn(async {
                        scope(|inner| async move {
                            inner.spawn(until_cancelled()).await.expect("inner fiber")
                        })
                        .await
                    });
                    crate::runtime::yield_now().await;
                    outer.cancel();
                    outer.await.expect("outer fiber")
                })
                .await
            })
        });
        assert_eq!(reason.kind, CancelKind::User);
    }

    #[test]
    fn the_tasks_cancellation_polls_a_fiber_waiting_on_the_tasks_context() {
        let kind = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let wait = s.spawn(sees_cancel_only_when_polled(Some(task_ref.clone())));
                    crate::runtime::yield_now().await;
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    wait.await.expect("fiber")
                })
                .await
            })
        });
        assert_eq!(kind, CancelKind::Shutdown);
    }

    // --- The task's cancellation is passed on once ---

    #[test]
    fn the_tasks_cancellation_is_passed_to_each_fiber_once() {
        let calls = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let fibers: Vec<_> = (0..3)
                        .map(|_| {
                            s.spawn(async {
                                let _ = until_cancelled().await;
                                // A cleanup that takes several polls.
                                for _ in 0..5 {
                                    crate::runtime::yield_now().await;
                                }
                            })
                        })
                        .collect();
                    crate::runtime::yield_now().await;
                    INHERIT_CALLS.with(|calls| calls.set(0));
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    for fiber in fibers {
                        fiber.await.expect("fiber");
                    }
                })
                .await;
                INHERIT_CALLS.with(Cell::get)
            })
        });
        assert_eq!(
            calls, 3,
            "one inherit per live fiber, not one per scope poll"
        );
    }

    #[test]
    fn a_fiber_started_after_the_task_was_cancelled_sees_the_cancellation() {
        let reason = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let first = s.spawn(until_cancelled());
                    crate::runtime::yield_now().await;
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    first.await.expect("first fiber");
                    // The cancellation has been passed to the live fibers
                    // already; a fiber started now still gets it.
                    s.spawn(until_cancelled()).await.expect("late fiber")
                })
                .await
            })
        });
        assert_eq!(reason.kind, CancelKind::Shutdown);
    }
}
