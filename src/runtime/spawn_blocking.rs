//! Async wrapper for blocking pool operations.
//!
//! This module provides `spawn_blocking` helpers that run blocking closures on a
//! runtime blocking pool when available, or a dedicated thread as a fallback.
//!
//! # Cancellation Safety
//!
//! When the returned future is dropped (cancelled), the blocking operation
//! continues to run to completion on the background thread, but its result is
//! discarded. This is the standard "soft cancellation" model for blocking
//! operations.
//!
//! # Example
//!
//! ```
//! use asupersync::runtime::spawn_blocking;
//! use std::io;
//!
//! async fn read_file(path: &str) -> io::Result<String> {
//!     let path = path.to_string();
//!     spawn_blocking(move || std::fs::read_to_string(&path)).await
//! }
//! ```

use crate::cx::Cx;
use crate::runtime::blocking_pool::{BlockingPoolHandle, BlockingTaskHandle};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::thread;

mod fallback_admission;
use fallback_admission::FallbackAdmission;

/// A blocking operation whose runtime task retains ownership until the pool
/// has finished the closure and destroyed its captures.
///
/// Created by [`Cx::spawn_blocking_drained`]. Cancellation fences a queued
/// closure and requests cancellation through the closure's own `Cx`; an
/// already claimed closure must return cooperatively. Dropping this handle
/// before the closure finishes requests cancellation while its region
/// continues to own the operation; dropping it afterwards cancels nothing.
/// A completed result belongs to the handle, like an ordinary task result.
#[must_use = "join to observe the blocking operation's result and retirement"]
pub struct DrainedBlockingHandle<T> {
    task: crate::runtime::TaskHandle<()>,
    state: Arc<DrainedBlockingState<T>>,
}

impl<T> std::fmt::Debug for DrainedBlockingHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DrainedBlockingHandle")
            .field("task", &self.task.task_id())
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

impl<T> DrainedBlockingHandle<T> {
    pub(crate) fn new(
        task: crate::runtime::TaskHandle<()>,
        state: Arc<DrainedBlockingState<T>>,
    ) -> Self {
        Self { task, state }
    }

    /// Actual task identity after the runtime admits the operation.
    #[must_use]
    pub fn task_id(&self) -> crate::types::TaskId {
        self.task.task_id()
    }

    /// True only after the owning runtime task has retired.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Request cancellation without discarding a result already produced.
    pub fn abort(&self) {
        self.abort_with_reason(crate::types::CancelReason::user("abort"));
    }

    /// Request attributed cancellation. A queued closure cannot pass the claim
    /// gate after this call; a running closure observes its own cancelled Cx.
    pub fn abort_with_reason(&self, reason: crate::types::CancelReason) {
        self.state.cancel(reason.clone());
        self.task.abort_with_reason(reason);
    }

    /// Join actual closure retirement without a cancellation shortcut.
    ///
    /// Dropping this borrowing wait preserves the result and may be resumed.
    /// A running closure's exact returned value survives later cancellation,
    /// including a domain-level cancellation result. A closure cancelled before
    /// execution returns `JoinError::Cancelled`; a panic remains `Panicked`.
    pub async fn join(&mut self) -> Result<T, crate::runtime::JoinError> {
        let terminal = std::future::poll_fn(|cx| self.task.poll_join(cx)).await;
        if matches!(terminal, Err(crate::runtime::JoinError::PolledAfterCompletion)) {
            return Err(crate::runtime::JoinError::PolledAfterCompletion);
        }
        if let Some(result) = self.state.inner.lock().result.take() {
            return result;
        }
        match terminal {
            Err(error) => Err(error),
            Ok(()) => Err(crate::runtime::JoinError::Panicked(
                crate::types::PanicPayload::new("drained blocking task omitted its result"),
            )),
        }
    }
}

impl<T> Drop for DrainedBlockingHandle<T> {
    fn drop(&mut self) {
        let (finished, completed) = {
            let mut state = self.state.inner.lock();
            state.abandoned = true;
            let finished = state.finished;
            (finished, if finished { state.result.take() } else { None })
        };
        // A finished operation has nothing left to cancel. Aborting it would
        // mark a Cx clone the closure returned as cancelled and queue a cancel
        // for a retired task (asupersync-67tsr5).
        if !finished {
            self.abort();
        }
        // A result already published to this handle is caller-owned. Before
        // publication, the pool worker destroys abandoned results and only then
        // releases the runtime task's retirement wait.
        drop(completed);
    }
}

struct DrainedBlockingInner<T> {
    cancel: Option<crate::types::CancelReason>,
    finished: bool,
    abandoned: bool,
    result: Option<Result<T, crate::runtime::JoinError>>,
    panic: Option<crate::types::PanicPayload>,
    waiter: Option<Waker>,
}

pub(crate) struct DrainedBlockingState<T> {
    inner: Mutex<DrainedBlockingInner<T>>,
}

impl<T> DrainedBlockingState<T> {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(DrainedBlockingInner {
                cancel: None,
                finished: false,
                abandoned: false,
                result: None,
                panic: None,
                waiter: None,
            }),
        })
    }

    fn cancel(&self, reason: crate::types::CancelReason) {
        let mut state = self.inner.lock();
        if let Some(current) = state.cancel.as_mut() {
            current.strengthen(&reason);
        } else {
            state.cancel = Some(reason);
        }
    }

    fn finish(&self, result: Result<T, crate::runtime::JoinError>) {
        let mut state = self.inner.lock();
        debug_assert!(!state.finished, "one pool retirement per operation");
        let panic = match &result {
            Err(crate::runtime::JoinError::Panicked(panic)) => Some(panic.clone()),
            _ => None,
        };
        if state.abandoned {
            drop(state);
            // T may own a native resource with a blocking or panicking Drop.
            // The admitted task stays alive across this entire destructor.
            let retirement = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(result)));
            let panic = retirement.err().map(drained_panic).or(panic);
            let wake = {
                let mut state = self.inner.lock();
                state.panic = panic;
                state.finished = true;
                state.waiter.take()
            };
            if let Some(wake) = wake { wake.wake(); }
        } else {
            state.panic = panic;
            state.result = Some(result);
            state.finished = true;
            let wake = state.waiter.take();
            drop(state);
            if let Some(wake) = wake { wake.wake(); }
        }
    }

    fn poll_finished(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let incoming = cx.waker().clone();
        let mut state = self.inner.lock();
        if state.finished {
            drop(state);
            drop(incoming);
            return std::task::Poll::Ready(());
        }
        let old = state.waiter.replace(incoming);
        drop(state);
        drop(old);
        std::task::Poll::Pending
    }
}

fn drained_panic(payload: Box<dyn std::any::Any + Send>) -> crate::types::PanicPayload {
    let message = crate::cx::scope::payload_to_string(&payload);
    // An arbitrary panic payload may panic again in Drop. The task keeps the
    // stable diagnostic, matching other runtime panic-isolation boundaries.
    std::mem::forget(payload);
    crate::types::PanicPayload::new(message)
}

/// Owns every closure capture even when the pool skips or rejects the job.
/// Pool `is_done()` can precede task.work destruction, so it is deliberately
/// not the retirement signal for this API.
struct DrainedPoolWork<F, T> {
    work: Option<F>,
    cx: Cx,
    state: Arc<DrainedBlockingState<T>>,
    result: Option<Result<T, crate::runtime::JoinError>>,
}

impl<F: FnOnce() -> T, T> DrainedPoolWork<F, T> {
    fn run(mut self) {
        if self.cx.checkpoint().is_err() {
            self.state.cancel(self.cx.cancel_reason().unwrap_or_else(
                crate::types::CancelReason::shutdown,
            ));
        }
        let claimed = {
            self.state.inner.lock().cancel.is_none()
        };
        if claimed {
            let work = self.work.take().expect("one claimed blocking closure");
            self.result = Some(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                    .map_err(|payload| crate::runtime::JoinError::Panicked(drained_panic(payload))),
            );
        }
        // Drop destroys any uninvoked closure before publishing retirement.
    }
}

impl<F, T> Drop for DrainedPoolWork<F, T> {
    fn drop(&mut self) {
        let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(self.work.take());
        }));
        let result = if let Err(payload) = retired {
            Err(crate::runtime::JoinError::Panicked(drained_panic(payload)))
        } else if let Some(result) = self.result.take() {
            result
        } else {
            let requested = self.state.inner.lock().cancel.clone();
            let observed = self.cx.cancel_reason();
            let reason = match (requested, observed) {
                (Some(mut requested), Some(observed)) => {
                    requested.strengthen(&observed);
                    requested
                }
                (Some(reason), None) | (None, Some(reason)) => reason,
                (None, None) => crate::types::CancelReason::shutdown(),
            };
            Err(crate::runtime::JoinError::Cancelled(reason))
        };
        self.state.finish(result);
    }
}

struct DrainedBlockingWait<T> {
    cx: Cx,
    state: Arc<DrainedBlockingState<T>>,
    task: Option<BlockingTaskHandle>,
    cancel_waker: Option<crate::cx::CancelWakerToken>,
    cancellation_observed: bool,
    done: bool,
}

impl<T> Drop for DrainedBlockingWait<T> {
    fn drop(&mut self) {
        if let Some(token) = self.cancel_waker.take() {
            self.cx.clear_cancel_waker(token);
        }
        let waiter = self.state.inner.lock().waiter.take();
        drop(waiter);
        if !self.done {
            self.state.cancel(self.cx.cancel_reason().unwrap_or_else(
                crate::types::CancelReason::shutdown,
            ));
            if let Some(task) = self.task.as_ref() {
                task.cancel();
            }
        }
    }
}

pub(crate) async fn drive_drained_blocking<Caps, F, T>(
    cx: Cx<Caps>,
    pool: BlockingPoolHandle,
    work: F,
    state: Arc<DrainedBlockingState<T>>,
) where
    Caps: Send + Sync + 'static,
    F: FnOnce(Cx<Caps>) -> T + Send + 'static,
    T: Send + 'static,
{
    let control = cx.retype::<crate::cx::cap::All>();
    let envelope = DrainedPoolWork {
        work: Some(move || work(cx)),
        cx: control.clone(),
        state: Arc::clone(&state),
        result: None,
    };
    if control.checkpoint().is_err() {
        // Close the claim gate, but still hand the envelope to the pool: its
        // captures may block when destroyed, and this is an executor thread.
        // A worker skips or declines the closure and destroys them, and the
        // wait below then reports any capture panic (br-asupersync-q1pr9n).
        state.cancel(control.cancel_reason().unwrap_or_else(crate::types::CancelReason::shutdown));
    }
    let priority = control.budget().priority;
    let mut admission = pool.submit_with_priority(move || envelope.run(), priority);
    let mut admission_done = false;
    let mut wait = DrainedBlockingWait {
        cx: control,
        state,
        task: None,
        cancel_waker: None,
        cancellation_observed: false,
        done: false,
    };
    std::future::poll_fn(|poll_cx| {
        if !wait.cancellation_observed {
            wait.cancel_waker = Some(wait.cx.refresh_cancel_waker(wait.cancel_waker, poll_cx.waker()));
            if wait.cx.checkpoint().is_err() {
                wait.cancellation_observed = true;
                wait.state.cancel(wait.cx.cancel_reason().unwrap_or_else(
                    crate::types::CancelReason::shutdown,
                ));
                if let Some(task) = wait.task.as_ref() {
                    task.cancel();
                }
                if let Some(token) = wait.cancel_waker.take() {
                    wait.cx.clear_cancel_waker(token);
                }
            }
        }
        if !admission_done {
            // Cancellation closes the claim gate above but does not drop the
            // envelope: even an uninvoked closure can have blocking captures.
            // Keep ownership until a pool worker can retire them. Saturation
            // must neither run nor destroy them on this executor worker.
            match std::future::Future::poll(std::pin::Pin::new(&mut admission), poll_cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(task)) => {
                    if wait.cancellation_observed {
                        task.cancel();
                    }
                    wait.task = Some(task);
                }
                Poll::Ready(Err(refused)) => {
                    // Only shutdown ends asynchronous admission without a
                    // worker. Preserve the existing closed-pool retirement
                    // path; capacity pressure never reaches this branch.
                    drop(refused);
                }
            }
            admission_done = true;
        }
        wait.state.poll_finished(poll_cx)
    }).await;
    wait.done = true;
    let panic = wait.state.inner.lock().panic.clone();
    if let Some(panic) = panic {
        // Keep the pool diagnostic in the public handle while the ordinary
        // runtime panic boundary records the same failed task outcome.
        panic!("drained blocking operation panicked: {panic}");
    }
}

/// Maximum number of concurrent fallback blocking threads (when no pool exists).
/// Prevents unbounded thread creation under load.
const MAX_FALLBACK_THREADS: usize = 256;

/// Current number of active fallback blocking threads.
static FALLBACK_THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Tasks waiting for a fallback thread while all of them are busy.
static FALLBACK_WAITERS: Mutex<VecDeque<Waker>> = Mutex::new(VecDeque::new());

/// Fallback threads whose waiter was dropped or unwound before the thread
/// finished. They are joined once finished and never detached (GitHub #80).
static UNJOINED_FALLBACK_THREADS: Mutex<Vec<thread::JoinHandle<()>>> = Mutex::new(Vec::new());

/// Claims a fallback thread slot, or parks the caller until one is released.
///
/// A waiter used to yield and re-poll itself while the cap was full, so every
/// executor worker kept spinning for as long as the fallback threads stayed
/// busy (a DNS outage with every resolver thread blocked). It now parks its
/// waker and a released slot wakes it.
fn poll_claim_fallback_slot(
    count: &AtomicUsize,
    cap: usize,
    waiters: &Mutex<VecDeque<Waker>>,
    context: &Context<'_>,
) -> Poll<()> {
    if try_claim_fallback_slot(count, cap) {
        return Poll::Ready(());
    }
    // RawWaker clone/drop callbacks may reenter this queue. Prepare outside
    // the mutex and also retire a duplicate outside it.
    let mut incoming = Some(context.waker().clone());
    {
        let mut waiters = waiters.lock();
        if !waiters
            .iter()
            .any(|waiter| waiter.will_wake(context.waker()))
        {
            waiters.push_back(incoming.take().expect("prepared fallback waker"));
        }
    }
    drop(incoming);
    // A slot released between the first claim and the registration woke the
    // waiters before this one joined them: claim again.
    if try_claim_fallback_slot(count, cap) {
        Poll::Ready(())
    } else {
        Poll::Pending
    }
}

fn try_claim_fallback_slot(count: &AtomicUsize, cap: usize) -> bool {
    let mut current = count.load(Ordering::Relaxed);
    while current < cap {
        match count.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
    false
}

/// Releases a fallback slot and wakes every parked waiter. They race for the
/// slot and the losers park again; waking all of them, not one, keeps a
/// waiter whose future was dropped from stranding the free slot.
fn release_fallback_slot(count: &AtomicUsize, waiters: &Mutex<VecDeque<Waker>>) {
    count.fetch_sub(1, Ordering::Release);
    let woken = std::mem::take(&mut *waiters.lock());
    // The taken waiters are no longer queued, so a panicking task waker must
    // not drop the rest unwoken. Re-raise the first panic after the fanout,
    // as OnceCell's and the semaphore's wakes do.
    let already_unwinding = std::thread::panicking();
    let mut first_panic = None;
    for waker in woken {
        if let Err(payload) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()))
        {
            if !already_unwinding && first_panic.is_none() {
                first_panic = Some(payload);
            } else {
                // An opaque payload can itself panic on drop.
                std::mem::forget(payload);
            }
        }
    }
    if let Some(payload) = first_panic {
        std::panic::resume_unwind(payload);
    }
}

struct CancelOnDrop {
    handle: BlockingTaskHandle,
    done: bool,
}

impl CancelOnDrop {
    fn new(handle: BlockingTaskHandle) -> Self {
        Self {
            handle,
            done: false,
        }
    }

    fn mark_done(&mut self) {
        self.done = true;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.done {
            self.handle.cancel();
        }
    }
}

struct BlockingOneshotState<T> {
    result: Option<std::thread::Result<T>>,
    waker: Option<Waker>,
    done: bool,
    closed_without_result: bool,
}

struct BlockingOneshot<T> {
    state: Arc<Mutex<BlockingOneshotState<T>>>,
    sent: bool,
}

impl<T> BlockingOneshot<T> {
    fn new() -> (Self, BlockingOneshotReceiver<T>) {
        let state = Arc::new(Mutex::new(BlockingOneshotState {
            result: None,
            waker: None,
            done: false,
            closed_without_result: false,
        }));
        (
            Self {
                state: state.clone(),
                sent: false,
            },
            BlockingOneshotReceiver {
                state,
                completed: false,
                closed_fallback: None,
            },
        )
    }

    fn send(mut self, val: std::thread::Result<T>) {
        let waker = {
            let mut guard = self.state.lock();
            guard.result = Some(val);
            guard.done = true;
            guard.closed_without_result = false;
            guard.waker.take()
        };
        self.sent = true;
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<T> Drop for BlockingOneshot<T> {
    fn drop(&mut self) {
        if self.sent {
            return;
        }

        let waker = {
            let mut guard = self.state.lock();
            if guard.done {
                return;
            }
            guard.done = true;
            guard.closed_without_result = true;
            guard.waker.take()
        };

        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct BlockingOneshotReceiver<T> {
    state: Arc<Mutex<BlockingOneshotState<T>>>,
    completed: bool,
    closed_fallback: Option<Box<dyn FnOnce() -> T + Send + 'static>>,
}

impl<T> BlockingOneshotReceiver<T> {
    fn with_closed_fallback(mut self, fallback: impl FnOnce() -> T + Send + 'static) -> Self {
        self.closed_fallback = Some(Box::new(fallback));
        self
    }
}

impl<T> Drop for BlockingOneshotReceiver<T> {
    fn drop(&mut self) {
        let waker = self.state.lock().waker.take();
        drop(waker);
    }
}

impl<T> std::future::Future for BlockingOneshotReceiver<T> {
    type Output = T;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        assert!(
            !this.completed,
            "blocking operation polled after completion"
        );

        let mut incoming_waker = None;
        loop {
            let mut guard = this.state.lock();
            if guard.done {
                this.completed = true;
                let result = guard.result.take();
                let closed_without_result = guard.closed_without_result;
                drop(guard);
                drop(incoming_waker);

                return result.map_or_else(
                    || {
                        if closed_without_result {
                            if let Some(fallback) = this.closed_fallback.take() {
                                return std::task::Poll::Ready(fallback());
                            }
                            panic!("blocking operation ended without producing a result"); // ubs:ignore - invariant violation
                        } else {
                            panic!("blocking operation polled after completion"); // ubs:ignore - invariant violation
                        }
                    },
                    |result| match result {
                        Ok(val) => std::task::Poll::Ready(val),
                        Err(payload) => std::panic::resume_unwind(payload),
                    },
                );
            }
            if guard
                .waker
                .as_ref()
                .is_some_and(|w| w.will_wake(cx.waker()))
            {
                drop(guard);
                return std::task::Poll::Pending;
            }
            if let Some(waker) = incoming_waker.take() {
                let retired_waker = guard.waker.replace(waker);
                drop(guard);
                drop(retired_waker);
                return std::task::Poll::Pending;
            }

            // Both clone and drop may invoke custom Waker callbacks. Prepare
            // ownership outside the mutex, then recheck completion so a sender
            // racing this unlocked interval cannot leave an unwoken waiter.
            drop(guard);
            incoming_waker = Some(cx.waker().clone());
        }
    }
}

/// Spawns a blocking operation and returns a Future that yields until completion.
///
/// This function runs the provided closure on the current context's assigned
/// blocking pool, including when the context has restricted capabilities.
/// A context without a pool runs the closure inline; without a current context,
/// the closure runs on a dedicated thread. Pool workers do not inherit a `Cx`.
///
/// # Type Bounds
///
/// - `F: FnOnce() -> T + Send + 'static` - The closure must be sendable to another thread
/// - `T: Send + 'static` - The return value must be sendable back
///
/// # Cancel Safety
///
/// If this future is dropped before completion, the blocking operation continues
/// to run but its result is discarded.
///
/// # Panics
///
/// If the blocking operation panics, the panic is captured and re-raised when
/// the future is awaited.
pub async fn spawn_blocking<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    if let Some(cx) = Cx::current() {
        // This helper already accepts the work without a SPAWN capability.
        // Preserve its assigned execution location even when the public pool
        // getter is restricted; hiding the handle must not move blocking work
        // onto the caller's runtime thread.
        if let Some(pool) = cx.blocking_pool_handle_for_inheritance() {
            return spawn_blocking_on_pool(pool, f).await;
        }
        // Deterministic fallback when running inside a runtime without a pool.
        return f();
    }

    spawn_blocking_on_thread(f).await
}

/// Spawns a blocking I/O operation and returns a Future.
///
/// Convenience wrapper around [`spawn_blocking`] for I/O operations.
pub async fn spawn_blocking_io<F, T>(f: F) -> std::io::Result<T>
where
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    spawn_blocking(f).await
}

pub(crate) async fn spawn_blocking_on_pool<F, T>(pool: BlockingPoolHandle, f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    // Keep the user closure recoverable until a pool worker actually claims it.
    // A pool may reject the task because shutdown won the submission race, or
    // cancel a queued task after its last worker failed to start. Both paths
    // drop the task closure (and therefore `tx`) without running it. Treat that
    // as the same deterministic inline fallback used when a runtime has no
    // blocking pool, rather than turning ordinary shutdown/resource pressure
    // into the internal "ended without producing a result" panic.
    let work = Arc::new(Mutex::new(Some(f)));
    let pool_work = Arc::clone(&work);
    let (tx, rx) = BlockingOneshot::new();
    let rx = rx.with_closed_fallback(move || {
        let f = work
            .lock()
            .take()
            .expect("rejected blocking operation must retain its closure");
        f()
    });
    let priority = Cx::current().map_or(128, |cx| cx.budget().priority);
    let admission = pool.submit_with_priority(
        move || {
            let f = pool_work
                .lock()
                .take()
                .expect("blocking operation closure claimed exactly once");
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            tx.send(result);
        },
        priority,
    );
    let handle = match admission.await {
        Ok(handle) => handle,
        Err(refused) => {
            // Saturation remains parked in admission. Only a closed pool
            // returns the closure, preserving the existing shutdown fallback.
            drop(refused);
            return rx.await;
        }
    };

    let mut guard = CancelOnDrop::new(handle);
    let result = rx.await;
    guard.mark_done();
    result
}

struct FallbackGuard;

impl Drop for FallbackGuard {
    fn drop(&mut self) {
        release_fallback_slot(&FALLBACK_THREAD_COUNT, &FALLBACK_WAITERS);
    }
}

/// Owns a fallback thread's handle so the thread is joined, never detached.
///
/// Dropping a `JoinHandle` detaches its thread, and detaching a thread that is
/// exiting at that moment can fault inside `pthread_detach` on glibc before
/// 2.43 (BZ19951, GitHub #80). When the waiter finishes, unwinds or is dropped,
/// a finished thread (its closure has returned) is joined at once; the join
/// only waits out its thread-local destructors. One still running its closure
/// is parked rather than waited for, so no caller (including an executor
/// thread) waits on user work. A later fallback spawn joins it once finished.
struct FallbackThread(Option<thread::JoinHandle<()>>);

impl Drop for FallbackThread {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            reap_thread(handle);
        }
    }
}

/// Releases helper threads the caller no longer owns without detaching any
/// (GitHub #80): first joins the parked threads that have finished, then joins
/// each given thread that has finished and parks the rest. It never waits on
/// a thread still running its closure (a join only waits out a finished
/// thread's thread-local destructors), so executor threads may call it. Timer
/// fallback threads (`time::sleep`) use it too.
pub(crate) fn reap_threads(handles: impl IntoIterator<Item = thread::JoinHandle<()>>) {
    join_finished_fallback_threads();
    for handle in handles {
        reap_thread(handle);
    }
}

/// [`reap_threads`] for one thread, at a spawn site that does not wait for its
/// short-lived thread. Dropping the handle at spawn instead would detach a
/// thread that may already be exiting.
pub(crate) fn reap_spawned_thread(handle: thread::JoinHandle<()>) {
    reap_threads([handle]);
}

/// Whether a thread with this name is parked here and, if so, whether every
/// such thread has finished.
#[cfg(test)]
pub(crate) fn parked_thread_named(name: &str) -> Option<bool> {
    let parked = UNJOINED_FALLBACK_THREADS.lock();
    let mut named = parked
        .iter()
        .filter(|handle| handle.thread().name() == Some(name))
        .peekable();
    named.peek()?;
    Some(named.all(thread::JoinHandle::is_finished))
}

/// Whether a thread is parked here and, if so, whether it has finished.
#[cfg(test)]
pub(crate) fn parked_thread(id: thread::ThreadId) -> Option<bool> {
    UNJOINED_FALLBACK_THREADS
        .lock()
        .iter()
        .find(|handle| handle.thread().id() == id)
        .map(thread::JoinHandle::is_finished)
}

fn reap_thread(handle: thread::JoinHandle<()>) {
    if handle.is_finished() {
        let _ = handle.join();
    } else {
        UNJOINED_FALLBACK_THREADS.lock().push(handle);
    }
}

/// Joins the parked fallback threads that have finished.
fn join_finished_fallback_threads() {
    let finished: Vec<thread::JoinHandle<()>> = {
        let mut parked = UNJOINED_FALLBACK_THREADS.lock();
        if parked.is_empty() {
            return;
        }
        let (finished, running) = std::mem::take(&mut *parked)
            .into_iter()
            .partition(|handle| handle.is_finished());
        *parked = running;
        finished
    };
    for handle in finished {
        let _ = handle.join();
    }
}

pub(crate) async fn spawn_blocking_on_thread<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    join_finished_fallback_threads();
    // Wait until we are under the fallback thread limit to prevent unbounded
    // thread creation when no blocking pool is available.
    // The admission owns its queue registration: cancellation while the cap
    // is full must not leave a global waker keeping the abandoned task alive.
    FallbackAdmission::new(
        &FALLBACK_THREAD_COUNT,
        MAX_FALLBACK_THREADS,
        &FALLBACK_WAITERS,
    )
    .await;

    let (tx, rx) = BlockingOneshot::new();

    // If thread spawn fails, run the closure inline instead of panicking.
    // This keeps `spawn_blocking` usable under resource pressure.
    let f_cell = Arc::new(Mutex::new(Some(f)));
    let f_for_thread = Arc::clone(&f_cell);
    let thread_result = thread::Builder::new()
        .name("asupersync-blocking".to_string())
        .spawn(move || {
            let _guard = FallbackGuard;
            let f = f_for_thread
                .lock()
                .take()
                .expect("spawn_blocking_on_thread fn missing");
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            tx.send(result);
        });

    match thread_result {
        Ok(handle) => {
            let worker = FallbackThread(Some(handle));
            let value = rx.await;
            drop(worker);
            value
        }
        Err(_err) => {
            release_fallback_slot(&FALLBACK_THREAD_COUNT, &FALLBACK_WAITERS);
            let f = f_cell
                .lock()
                .take()
                .expect("spawn_blocking_on_thread fn missing");
            f()
        }
    }
}

#[cfg(test)]
#[path = "spawn_blocking_inline_tests.rs"]
mod tests;
