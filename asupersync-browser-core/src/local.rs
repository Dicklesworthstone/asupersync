//! Bounded, scope-owned execution of local Rust futures at the browser boundary.
//!
//! Unlike the v1 JS task ledger, [`spawn_local_future`] owns and polls an actual
//! pinned Rust future. Futures need not be `Send` or `Unpin`. Their handle is
//! allocated by the canonical dispatcher and cannot be completed by a caller's
//! `task_join` payload. [`LocalTask`] returns the executor's actual outcome.
//!
//! On wasm32 a single local driver is scheduled through wasm-bindgen-futures.
//! Ready tasks are visited round-robin, with a finite poll quantum and a host
//! task-queue yield between busy turns. Native hosts explicitly drive
//! `poll_local_tasks`, which is also useful for deterministic tests.
//!
//! Cancellation follows the existing browser ABI's synchronous **drop** policy:
//! cancellation or owner close destroys the Rust future before publishing its
//! terminal outcome. This is not asynchronous finalizer drain, native `Cx`
//! execution, cross-thread future polling, or preemption of a blocking `poll`.
//! A dropped join handle does not detach its future from its owning scope.
//! Dropping a Rust future does not abort an arbitrary JavaScript Promise or
//! undo effects already performed by the host. Such operations still need an
//! adapter-owned abort/cleanup guard; independently spawned host work is outside
//! this executor's ownership boundary. Panic capture applies only to unwinding
//! builds: an aborting wasm panic terminates execution rather than yielding an
//! outcome.

use crate::{cancelled_outcome, dispatcher_handle_is_live, with_dispatcher};
use asupersync::types::{
    WasmAbiOutcomeEnvelope, WasmAbiVersion, WasmHandleRef, WasmTaskCancelRequest,
    WasmTaskSpawnRequest,
};
use std::any::Any;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::future::Future;
use std::ops::Bound::{Excluded, Unbounded};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Wake, Waker};

#[cfg(target_arch = "wasm32")]
mod host;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

/// Limits for one thread/JavaScript realm, shared across its browser runtimes.
/// These bound executor bookkeeping and delivered polls, not a future's own
/// memory, synchronous work, or host I/O buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalExecutorConfig {
    /// Maximum live Rust futures, including futures currently being destroyed.
    pub max_tasks: usize,
    /// Maximum future polls in one driver turn. Must be nonzero.
    pub polls_per_turn: usize,
}

impl Default for LocalExecutorConfig {
    fn default() -> Self {
        Self { max_tasks: 1024, polls_per_turn: 64 }
    }
}

/// Actual execution outcome, with independent boundary-publication diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct LocalTaskCompletion {
    /// Value/error returned by the future, or observed cancellation/panic.
    pub outcome: WasmAbiOutcomeEnvelope,
    /// Unexpected dispatcher refusal while publishing an otherwise real result.
    /// An owner that has already closed is expected, not a publication failure.
    pub publication_error: Option<String>,
}

#[derive(Default)]
struct JoinState {
    completion: Option<LocalTaskCompletion>,
    waiter: Option<Waker>,
}

/// Join capability for an actual Rust future owned by a browser scope.
///
/// Dropping this handle abandons observation, not ownership. The executor still
/// retires the future on completion, cancellation, or closure of its owner.
#[must_use = "await the task to observe its actual execution outcome"]
pub struct LocalTask {
    handle: WasmHandleRef,
    join: Rc<RefCell<JoinState>>,
    consumer_version: Option<WasmAbiVersion>,
    completed: bool,
}

impl fmt::Debug for LocalTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalTask")
            .field("handle", &self.handle)
            .field("completed", &self.completed)
            .finish_non_exhaustive()
    }
}

impl LocalTask {
    /// Canonical generation-checked browser task handle.
    #[must_use]
    pub const fn handle(&self) -> WasmHandleRef { self.handle }

    /// Request drop-cancellation. A future being polled is retired when that
    /// poll returns; a parked future is retired immediately. Already completed
    /// tasks need no further cancellation and return successfully.
    pub fn cancel(&self, kind: impl Into<String>, message: Option<String>) -> Result<(), String> {
        if self.completed || self.join.borrow().completion.is_some() { return Ok(()); }
        let request = WasmTaskCancelRequest { task: self.handle, kind: kind.into(), message };
        ensure_cancellable(&request.task)?;
        with_dispatcher(|dispatcher| dispatcher.task_cancel(&request, self.consumer_version))?;
        cancel_registered(&request);
        Ok(())
    }
}

impl Future for LocalTask {
    type Output = LocalTaskCompletion;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        assert!(!self.completed, "local task joined after completion");
        // RawWaker clone/drop are user code; never run them inside RefCell.
        let mut incoming = Some(cx.waker().clone());
        let (completion, retired) = {
            let mut join = self.join.borrow_mut();
            if let Some(completion) = join.completion.take() {
                (Some(completion), join.waiter.take())
            } else {
                (None, std::mem::replace(&mut join.waiter, incoming.take()))
            }
        };
        if completion.is_some() { self.completed = true; }
        drop(retired);
        drop(incoming);
        if let Some(completion) = completion {
            Poll::Ready(completion)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for LocalTask {
    fn drop(&mut self) {
        let retired = self.join.borrow_mut().waiter.take();
        drop(retired);
    }
}

#[derive(Default)]
struct DriverSignal { waiter: Mutex<Option<Arc<Waker>>> }

impl DriverSignal {
    fn register(&self, waker: &Waker) {
        let incoming = Arc::new(waker.clone());
        let retired = self.waiter.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(incoming);
        drop(retired);
    }

    fn notify(&self) {
        // Only Arc cloning occurs under this lock, never RawWaker callbacks.
        let waiter = self.waiter.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        if let Some(waiter) = waiter { waiter.wake_by_ref(); }
    }

    fn clear(&self) {
        let retired = self.waiter.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        drop(retired);
    }
}

struct TaskWake {
    ready: AtomicBool,
    retired: AtomicBool,
    signal: Weak<DriverSignal>,
}

impl Wake for TaskWake {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) {
        if !self.retired.load(Ordering::Acquire)
            && !self.ready.swap(true, Ordering::AcqRel)
            && let Some(signal) = self.signal.upgrade()
        {
            signal.notify();
        }
    }
}

type LocalFuture = Pin<Box<dyn Future<Output = WasmAbiOutcomeEnvelope>>>;
type Panic = Box<dyn Any + Send>;

struct Task {
    handle: WasmHandleRef,
    future: Option<LocalFuture>,
    wake: Arc<TaskWake>,
    join: Rc<RefCell<JoinState>>,
    consumer_version: Option<WasmAbiVersion>,
    cancellation: Option<WasmAbiOutcomeEnvelope>,
}

struct Executor {
    tasks: BTreeMap<u64, Task>,
    // Retiring tasks still occupy admission and cannot be forged through the
    // JS join entry point while arbitrary future destructors execute.
    finishing: HashSet<WasmHandleRef>,
    next_id: u64,
    cursor: u64,
    polling: bool,
    failure: Option<&'static str>,
    config: LocalExecutorConfig,
    signal: Arc<DriverSignal>,
    #[cfg(target_arch = "wasm32")]
    driver_running: bool,
    #[cfg(target_arch = "wasm32")]
    driver_epoch: u64,
}

impl Default for Executor {
    fn default() -> Self {
        Self {
            tasks: BTreeMap::new(), finishing: HashSet::new(), next_id: 0,
            cursor: 0, polling: false, failure: None, config: LocalExecutorConfig::default(),
            signal: Arc::new(DriverSignal::default()),
            #[cfg(target_arch = "wasm32")]
            driver_running: false,
            #[cfg(target_arch = "wasm32")]
            driver_epoch: 0,
        }
    }
}

thread_local! { static EXECUTOR: Rc<RefCell<Executor>> = Rc::new(RefCell::new(Executor::default())); }

fn executor() -> Rc<RefCell<Executor>> { EXECUTOR.with(Rc::clone) }

/// Configure this realm while it has no live or retiring Rust futures.
/// This does not change the JS ledger, other realms, or any native runtime.
pub fn configure_local_executor(config: LocalExecutorConfig) -> Result<(), String> {
    if config.max_tasks == 0 || config.polls_per_turn == 0 {
        return Err("local executor limits must be nonzero".into());
    }
    let executor = executor();
    let mut state = executor.borrow_mut();
    if state.polling || !state.tasks.is_empty() || !state.finishing.is_empty() {
        return Err("cannot reconfigure a live local executor".into());
    }
    #[cfg(target_arch = "wasm32")]
    if state.driver_running {
        return Err("cannot reconfigure a scheduled browser driver".into());
    }
    state.config = config;
    state.failure = None;
    Ok(())
}

/// Admit a real pinned Rust future under an existing browser scope/runtime.
///
/// This function does not poll the future itself. A wasm host schedules the
/// shared executor; native hosts call `poll_local_tasks`. Admission validates the canonical handle and
/// ABI version, and refuses saturation before allocating a dispatcher task.
/// The caller's future is returned to ordinary Rust destruction on refusal.
///
/// The future may own `Rc`, JS handles, and pinned state, but must not borrow
/// from a caller stack that can disappear before the owning scope closes.
pub fn spawn_local_future<F>(
    request: WasmTaskSpawnRequest,
    future: F,
    consumer_version: Option<WasmAbiVersion>,
) -> Result<LocalTask, String>
where F: Future<Output = WasmAbiOutcomeEnvelope> + 'static {
    let executor = executor();
    let (id, signal) = {
        let state = executor.borrow();
        if let Some(failure) = state.failure { return Err(failure.to_string()); }
        if state.tasks.len() + state.finishing.len() >= state.config.max_tasks {
            return Err("local Rust future capacity exhausted".into());
        }
        let id = state.next_id.checked_add(1)
            .ok_or_else(|| "local Rust future identity space exhausted".to_string())?;
        (id, Arc::clone(&state.signal))
    };
    // Allocate before publishing a dispatcher handle. None of this runs a
    // user future, a user destructor, or a waker beneath the dispatcher borrow.
    let future: LocalFuture = Box::pin(future);
    let join = Rc::new(RefCell::new(JoinState::default()));
    let wake = Arc::new(TaskWake {
        ready: AtomicBool::new(true), retired: AtomicBool::new(false),
        signal: Arc::downgrade(&signal),
    });
    let handle = with_dispatcher(|dispatcher| dispatcher.task_spawn(&request, consumer_version))?;
    {
        let mut state = executor.borrow_mut();
        state.next_id = id;
        state.tasks.insert(id, Task {
            handle, future: Some(future), wake, join: Rc::clone(&join),
            consumer_version, cancellation: None,
        });
    }
    #[cfg(target_arch = "wasm32")]
    host::ensure_driver(&executor);
    signal.notify();
    Ok(LocalTask { handle, join, consumer_version, completed: false })
}

/// Current live plus retiring Rust futures in this realm (not JS-only handles).
#[must_use]
pub fn active_local_tasks() -> usize {
    let executor = executor();
    let state = executor.borrow();
    state.tasks.len() + state.finishing.len()
}

pub(crate) fn reject_external_join(handle: &WasmHandleRef) -> Result<(), String> {
    let executor = executor();
    let state = executor.borrow();
    if state.finishing.contains(handle) || state.tasks.values().any(|task| task.handle == *handle) {
        Err("Rust-owned task results must be joined through LocalTask".into())
    } else { Ok(()) }
}

pub(crate) fn ensure_cancellable(handle: &WasmHandleRef) -> Result<(), String> {
    if executor().borrow().finishing.contains(handle) {
        Err("Rust-owned task is already retiring".into())
    } else { Ok(()) }
}

pub(crate) fn ensure_reset_allowed() -> Result<(), String> {
    ensure_close_allowed()?;
    if active_local_tasks() != 0 {
        return Err("close Rust future owners before resetting the dispatcher".into());
    }
    Ok(())
}

pub(crate) fn ensure_close_allowed() -> Result<(), String> {
    let executor = executor();
    let state = executor.borrow();
    if state.polling || !state.finishing.is_empty() {
        Err("cannot synchronously close browser ownership during a Rust driver turn or destructor".into())
    } else { Ok(()) }
}

fn cancellation(kind: &str, message: Option<String>, handle: WasmHandleRef) -> WasmAbiOutcomeEnvelope {
    cancelled_outcome(kind, "completed", message, Some(format!("{handle:?}")))
}

fn extract_task(state: &mut Executor, id: u64) -> Task {
    let task = state.tasks.remove(&id).expect("selected local task exists");
    state.finishing.insert(task.handle);
    task.wake.retired.store(true, Ordering::Release);
    task
}

struct Retirement { executor: Rc<RefCell<Executor>>, handle: WasmHandleRef }
impl Drop for Retirement {
    fn drop(&mut self) { self.executor.borrow_mut().finishing.remove(&self.handle); }
}

fn panic_outcome(payload: &(dyn Any + Send), stage: &str) -> WasmAbiOutcomeEnvelope {
    let detail = payload.downcast_ref::<&str>().copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload");
    let detail: String = detail.chars().take(512).collect();
    WasmAbiOutcomeEnvelope::Panicked { message: format!("local Rust task {stage}: {detail}") }
}

// Retain panic payloads until state publication and all selected retirements
// complete. A payload's destructor is arbitrary code, just like a Waker's.
fn finish_task(executor: &Rc<RefCell<Executor>>, mut task: Task,
    mut outcome: WasmAbiOutcomeEnvelope, payloads: &mut Vec<Panic>, wakes: &mut Vec<Waker>) {
    let _retirement = Retirement { executor: Rc::clone(executor), handle: task.handle };
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(task.future.take()))) {
        if !matches!(outcome, WasmAbiOutcomeEnvelope::Panicked { .. }) {
            outcome = panic_outcome(payload.as_ref(), "cleanup panicked");
        }
        payloads.push(payload);
    }
    let publication_error = if dispatcher_handle_is_live(&task.handle) {
        with_dispatcher(|dispatcher| dispatcher.task_join(
            &task.handle, outcome.clone(), task.consumer_version,
        )).err()
    } else { None };
    let waiter = {
        let mut join = task.join.borrow_mut();
        join.completion = Some(LocalTaskCompletion { outcome, publication_error });
        join.waiter.take()
    };
    if let Some(waiter) = waiter { wakes.push(waiter); }
}

fn dispatch_join_wakes(wakes: Vec<Waker>, signal: Option<&DriverSignal>) {
    let mut panics = Vec::new();
    if let Some(signal) = signal
        && let Err(payload) = catch_unwind(AssertUnwindSafe(|| signal.notify()))
    {
        panics.push(payload);
    }
    for waker in wakes {
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| waker.wake())) {
            panics.push(payload);
        }
    }
    // All joiners have been notified before a user wake panic is propagated.
    if !panics.is_empty() {
        let first = panics.remove(0);
        drop(panics);
        std::panic::resume_unwind(first);
    }
}

pub(crate) fn cancel_registered(request: &WasmTaskCancelRequest) {
    let executor = executor();
    let outcome = cancellation(&request.kind, request.message.clone(), request.task);
    let task = {
        let mut state = executor.borrow_mut();
        let id = state.tasks.iter().find_map(|(id, task)|
            (task.handle == request.task).then_some(*id));
        let Some(id) = id else { return; };
        let task = state.tasks.get_mut(&id).expect("owned cancellation target");
        if task.future.is_none() {
            task.cancellation = Some(outcome);
            return;
        }
        extract_task(&mut state, id)
    };
    let mut payloads = Vec::new();
    let mut wakes = Vec::new();
    finish_task(&executor, task, outcome, &mut payloads, &mut wakes);
    let signal = Arc::clone(&executor.borrow().signal);
    dispatch_join_wakes(wakes, Some(&signal));
    drop(payloads);
}

/// Retire actual Rust work whose canonical owner has been closed.
pub(crate) fn cleanup_released() {
    let executor = executor();
    let candidates: Vec<_> = executor.borrow().tasks.iter()
        .map(|(id, task)| (*id, task.handle)).collect();
    let retired: Vec<_> = candidates.into_iter()
        .filter(|(_, handle)| !dispatcher_handle_is_live(handle)).collect();
    let mut tasks = Vec::new();
    {
        let mut state = executor.borrow_mut();
        for (id, handle) in retired {
            let Some(task) = state.tasks.get_mut(&id) else { continue; };
            let outcome = cancellation("owner_closed", None, handle);
            if task.future.is_none() {
                task.cancellation = Some(outcome);
            } else {
                tasks.push((extract_task(&mut state, id), outcome));
            }
        }
    }
    let changed = !tasks.is_empty();
    let mut payloads = Vec::new();
    let mut wakes = Vec::new();
    for (task, outcome) in tasks {
        finish_task(&executor, task, outcome, &mut payloads, &mut wakes);
    }
    let signal = changed.then(|| Arc::clone(&executor.borrow().signal));
    dispatch_join_wakes(wakes, signal.as_deref());
    drop(payloads);
}

struct PollGuard(Rc<RefCell<Executor>>);
impl Drop for PollGuard {
    fn drop(&mut self) { self.0.borrow_mut().polling = false; }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DriveState { Empty, Parked, Runnable }

fn poll_executor(executor: &Rc<RefCell<Executor>>, cx: &mut Context<'_>) -> DriveState {
    let (signal, budget) = {
        let mut state = executor.borrow_mut();
        assert!(!state.polling, "local executor cannot be polled recursively");
        state.polling = true;
        (Arc::clone(&state.signal), state.config.polls_per_turn)
    };
    let guard = PollGuard(Rc::clone(executor));
    signal.register(cx.waker());
    let mut payloads = Vec::new();
    let mut wakes = Vec::new();
    for _ in 0..budget {
        let selected = {
            let mut state = executor.borrow_mut();
            let id = state.tasks.range((Excluded(state.cursor), Unbounded))
                .chain(state.tasks.range(..=state.cursor))
                .find_map(|(id, task)| (task.future.is_some()
                    && task.wake.ready.load(Ordering::Acquire)).then_some(*id));
            id.map(|id| {
                state.cursor = id;
                let task = state.tasks.get_mut(&id).expect("selected ready task");
                // Acquire the latest wake publication before polling. A wake
                // racing this exchange either precedes this poll or leaves
                // ready=true for a subsequent turn.
                let _ = task.wake.ready.swap(false, Ordering::AcqRel);
                (id, task.future.take().expect("ready future"), Arc::clone(&task.wake), task.handle)
            })
        };
        let Some((id, mut future, wake, handle)) = selected else { break; };
        let waker = Waker::from(wake);
        let result = if dispatcher_handle_is_live(&handle) {
            catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(&mut Context::from_waker(&waker))))
        } else {
            Ok(Poll::Ready(cancellation("owner_closed", None, handle)))
        };
        let (task, outcome) = {
            let mut state = executor.borrow_mut();
            let task = state.tasks.get_mut(&id).expect("polled task retains ownership");
            task.future = Some(future);
            let outcome = match result {
                Err(payload) => {
                    let outcome = panic_outcome(payload.as_ref(), "poll panicked");
                    payloads.push(payload);
                    Some(outcome)
                }
                Ok(Poll::Ready(outcome)) => Some(if matches!(outcome, WasmAbiOutcomeEnvelope::Panicked { .. }) {
                    outcome
                } else { task.cancellation.take().unwrap_or(outcome) }),
                Ok(Poll::Pending) => task.cancellation.take(),
            };
            if let Some(outcome) = outcome {
                (Some(extract_task(&mut state, id)), Some(outcome))
            } else { (None, None) }
        };
        if let (Some(task), Some(outcome)) = (task, outcome) {
            finish_task(executor, task, outcome, &mut payloads, &mut wakes);
        }
    }
    // Keep the driver-turn guard through callbacks: a custom join waker may
    // admit work, but cannot recursively poll an unbounded number of quanta.
    dispatch_join_wakes(wakes, None);
    drop(payloads);
    drop(guard);
    // Join wakes and panic-payload destructors may have spawned more work.
    let state = executor.borrow();
    if state.tasks.is_empty() { DriveState::Empty }
    else if state.tasks.values().any(|task| task.wake.ready.load(Ordering::Acquire)) {
        DriveState::Runnable
    } else { DriveState::Parked }

}

/// Drive at most one configured quantum on a native host, parking when no task
/// is ready. `Ready(())` means no retained Rust futures, not that every task
/// succeeded. Inspect the individual [`LocalTaskCompletion`] values.
#[cfg(not(target_arch = "wasm32"))]
pub fn poll_local_tasks(cx: &mut Context<'_>) -> Poll<()> {
    let executor = executor();
    match poll_executor(&executor, cx) {
        DriveState::Empty => {
            let signal = Arc::clone(&executor.borrow().signal);
            signal.clear();
            // Waker destruction is another reentrant callback boundary.
            if executor.borrow().tasks.is_empty() { Poll::Ready(()) }
            else { signal.register(cx.waker()); cx.waker().wake_by_ref(); Poll::Pending }
        },
        DriveState::Parked => Poll::Pending,
        DriveState::Runnable => { cx.waker().wake_by_ref(); Poll::Pending }
    }
}

#[cfg(target_arch = "wasm32")]
fn fail_all(executor: &Rc<RefCell<Executor>>, message: &'static str) {
    let tasks = {
        let mut state = executor.borrow_mut();
        state.failure = Some(message);
        let ids: Vec<_> = state.tasks.keys().copied().collect();
        ids.into_iter().map(|id| extract_task(&mut state, id)).collect::<Vec<_>>()
    };
    let mut payloads = Vec::new();
    let mut wakes = Vec::new();
    for task in tasks {
        let outcome = WasmAbiOutcomeEnvelope::Err {
            failure: asupersync::types::WasmAbiFailure {
                code: asupersync::types::WasmAbiErrorCode::InternalFailure,
                recoverability: asupersync::types::WasmAbiRecoverability::Permanent,
                message: message.to_string(),
            },
        };
        finish_task(executor, task, outcome, &mut payloads, &mut wakes);
    }
    dispatch_join_wakes(wakes, None);
    drop(payloads);
}
