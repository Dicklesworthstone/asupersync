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
//! - **Cancellation** is the calling task's: fibers observe it through the
//!   task's `Cx` at their own cancellation points, finish their cleanup, and
//!   the scope drains. Nothing is dropped mid-flight unless the scope future
//!   itself is dropped, which drops its fibers with it; a handle that
//!   outlived it then resolves as [`JoinError::Cancelled`].
//! - **Panics.** A panicking fiber is caught. Awaiting its handle yields
//!   [`JoinError::Panicked`]; a panic no handle observed is re-raised when the
//!   scope finishes, so it cannot vanish silently.
//! - **Scheduling.** Each poll of the scope polls the body and every ready
//!   fiber once. A fiber that wakes itself is polled again on the task's next
//!   turn, so a busy fiber cannot monopolize the worker.
//! - **Not parallel.** Fibers interleave on the calling task's thread. Use
//!   `Cx::spawn` or a `JoinSet` for parallelism; use fibers for cheap
//!   fine-grained concurrency (I/O fan-out, timeouts on parts of the work,
//!   pipelines over borrowed data).
//!
//! # Cost
//!
//! Starting a fiber costs one boxed future and one shared completion cell; a
//! wake handle is allocated only when no finished fiber's slot can be reused.
//! It never touches runtime-global state. A poll of the scope takes the
//! fiber table lock twice however many fibers are ready, and wakes raised
//! inside that poll on the polling thread re-wake the task at most once.
//! That makes fibers the cheapest structured concurrency in the runtime
//! (br-asupersync-issue65-criticisms-kpmoy5.3.2).

use crate::runtime::JoinError;
use crate::types::outcome::PanicPayload;
use parking_lot::Mutex;
use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, Wake, Waker};

type FiberFuture<'env> = Pin<Box<dyn Future<Output = ()> + Send + 'env>>;

std::thread_local! {
    /// Address of the [`ReadyQueue`] of the scope this thread is polling
    /// right now, or 0.
    static POLLING_SCOPE: Cell<usize> = const { Cell::new(0) };
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

struct FiberSlot<'env> {
    /// The fiber, or `None` while it is being polled or the slot is free.
    future: Option<FiberFuture<'env>>,
    /// `None` only while the fiber is being polled.
    waker: Option<Waker>,
    wake: Arc<FiberWake>,
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
/// the scope still waits for it.
#[must_use = "a fiber keeps running even if its handle is dropped; await it to observe its result"]
pub struct FiberHandle<T> {
    completion: Arc<Completion<T>>,
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
/// `completion` is dropped with this future, which marks the fiber abandoned
/// if it never finished, even when it was never polled.
async fn run_fiber<F: Future>(future: F, completion: FiberCompletion<F::Output>) {
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
        let fiber: FiberFuture<'env> =
            Box::pin(run_fiber(future, FiberCompletion(Arc::clone(&completion))));
        let index = {
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
                });
                index
            };
            set.live += 1;
            index
        };
        self.state.queue.schedule(index);
        FiberHandle { completion }
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

    /// Polls every ready fiber once. Returns whether any fiber is still live.
    fn poll_fibers(&self) -> bool {
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
                    running.push(Running {
                        index,
                        future: Some(future),
                        waker: slot.waker.take(),
                        finished: false,
                    });
                }
            }
        }
        for fiber in &mut running {
            if let (Some(future), Some(waker)) = (fiber.future.as_mut(), fiber.waker.as_ref()) {
                fiber.finished = future
                    .as_mut()
                    .poll(&mut Context::from_waker(waker))
                    .is_ready();
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
                }
            }
            set.live > 0
        };
        // `running` still owns the finished fibers, dropped here unlocked.
        drop(running);
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
/// finished.
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
}
