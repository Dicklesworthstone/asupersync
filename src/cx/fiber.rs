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
#[path = "fiber_inline_tests.rs"]
mod tests;
