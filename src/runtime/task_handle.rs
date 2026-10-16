//! TaskHandle for awaiting spawned task results.
//!
//! `TaskHandle<T>` is returned by spawn operations and allows the spawner
//! to await the task's result. Similar to join handles in other runtimes.

use crate::channel::oneshot;
use crate::cx::Cx;
use crate::types::{CancelReason, CxInner, PanicPayload, TaskId};
use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

/// Retirement barrier gating terminal-result visibility to a task's consumers.
///
/// A runtime-minted task publishes its terminal result into the join oneshot
/// from inside the task future, *before* the scheduler commits the task's
/// authoritative record to a terminal state and retires it. A consumer that
/// observes that early result (via `poll_join`/`join`/`try_join`) can act on
/// completion — a joined owner closing its child region, for instance — before
/// the record is committed, and that close then cancels the still-finishing
/// record, flipping an already-successful outcome to cancelled
/// (br-asupersync-yhueis).
///
/// The barrier lets consumers *see* a received terminal result only once the
/// scheduler has opened it in the post-lock completion dispatch, after the
/// record terminal transition. It gates the DATA, not merely a wake: while the
/// barrier is closed a join handle does not poll its oneshot receiver at all,
/// so an early terminal is never consumed or surfaced. A parked consumer
/// registers its waker here (register-before-recheck to avoid a lost wake
/// against a concurrent open) and the scheduler wakes it when the barrier
/// opens, at which point it consumes the receiver normally.
///
/// Tasks with no record to retire — admission denial (the sender publishes an
/// `Err` value rather than closing the channel) and the standalone public
/// [`TaskHandle::new`] constructor — are created already open, so their results
/// surface immediately and never wait for a retirement that will not happen.
pub(crate) struct RetirementBarrier {
    open: AtomicBool,
    shutdown: AtomicBool,
    waker: Mutex<Option<std::task::Waker>>,
}

impl std::fmt::Debug for RetirementBarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetirementBarrier")
            .field("open", &self.open.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl RetirementBarrier {
    /// A runtime-minted, record-backed task: terminal results stay gated until
    /// the scheduler retires the record.
    pub(crate) fn pending() -> Arc<Self> {
        Arc::new(Self {
            open: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            waker: Mutex::new(None),
        })
    }

    /// A task with no record to retire (admission denial / standalone handle):
    /// terminal results surface immediately.
    pub(crate) fn open_now() -> Arc<Self> {
        Arc::new(Self {
            open: AtomicBool::new(true),
            shutdown: AtomicBool::new(false),
            waker: Mutex::new(None),
        })
    }

    #[inline]
    pub(crate) fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// Releases a task destroyed during teardown. The shutdown attribution
    /// outlives its CxInner, so a closed result channel still has a reason.
    /// Call only after retiring task storage, outside runtime and shard locks.
    pub(crate) fn open_after_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.open_and_wake();
    }

    fn strengthen_shutdown_reason(&self, mut reason: CancelReason) -> CancelReason {
        if self.shutdown.load(Ordering::Acquire) {
            reason.strengthen(&CancelReason::shutdown());
        }
        reason
    }

    /// Opens the barrier and wakes any parked consumer. Called by the scheduler
    /// in the post-lock completion dispatch, after the record terminal is
    /// committed. Idempotent and cheap on the already-open path.
    pub(crate) fn open_and_wake(&self) {
        // Publish `open` before taking the waker so a consumer that registered
        // its waker before this store is either observed as open by its own
        // recheck or has its registered waker taken and woken here.
        if self.open.swap(true, Ordering::Release) {
            return;
        }
        // Take the waker out under the lock, then drop the guard BEFORE waking:
        // `Waker::wake` is a foreign callback and must not run while the barrier
        // mutex is held (br-asupersync-yhueis).
        let waker = self.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Registers `waker` to be woken when the barrier opens, then reports the
    /// current open state. The waker store happens before the state load, so a
    /// caller that parks on a `false` return still receives a wake if the
    /// barrier opens concurrently.
    pub(crate) fn register_and_is_open(&self, waker: &std::task::Waker) -> bool {
        // Clone the incoming waker BEFORE locking and retire any displaced waker
        // AFTER unlocking, so no foreign `Waker` clone or `Drop` runs under the
        // barrier mutex (`will_wake` is a cheap pointer comparison, lock-safe).
        let candidate = waker.clone();
        let displaced = {
            let mut slot = self.waker.lock();
            // Never store once the barrier is open: `open_and_wake` takes the
            // slot for the last time after publishing `open`, so a waker
            // stored after that would stay parked until the barrier drops.
            if self.is_open()
                || slot
                    .as_ref()
                    .is_some_and(|existing| existing.will_wake(waker))
            {
                None
            } else {
                slot.replace(candidate)
            }
        };
        drop(displaced);
        self.is_open()
    }

    /// Clears any registered waker without opening the barrier or waking it.
    /// Called when the waiting handle or future is dropped. An open barrier
    /// holds no waker (see `register_and_is_open`), so the common case takes
    /// no lock. The displaced waker is a foreign value dropped on the
    /// caller's `Drop` path: a panicking destructor is contained, and its
    /// payload leaked, instead of unwinding through the caller.
    pub(crate) fn clear_waker(&self) {
        if self.is_open() {
            return;
        }
        let displaced = self.waker.lock().take();
        if let Some(waker) = displaced {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(waker)))
            {
                std::mem::forget(payload);
            }
        }
    }

    /// Returns true if a waker is currently registered on this barrier.
    #[cfg(test)]
    pub(crate) fn has_waker(&self) -> bool {
        self.waker.lock().is_some()
    }
}

/// Error returned when joining a spawned task fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinError {
    /// The task was cancelled before completion.
    Cancelled(CancelReason),
    /// The task panicked.
    Panicked(PanicPayload),
    /// The join future was polled after it had already completed.
    PolledAfterCompletion,
}

/// Decides how a spawned task's returned value interacts with cancellation.
///
/// Ordinary Cx spawn APIs preserve a value only after user code has explicitly
/// acknowledged cancellation. Structured combinators, blocking wrappers, and
/// low-level state tasks retain task-level cancellation attribution even if
/// their inner work later returns. The legacy state-threaded
/// [`Scope`](crate::cx::Scope) path needs no policy value because it preserves
/// returned values unconditionally and bypasses cancellation observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpawnCompletionPolicy {
    /// Preserve a returned value only when attributed cancellation arrived
    /// after the first user-future poll and user code acknowledged it through
    /// the cancellation protocol. This is the narrow corrective policy for
    /// ordinary `Cx::spawn*` APIs: typed cancellation/cleanup results survive,
    /// while cancellation-blind or reasonless late values retain v0.4.3
    /// task-level attribution.
    PreserveAcknowledgedCancellationResult,
    CancellationDominant,
}

/// Classifies a successfully returned user value before terminal publication.
///
/// Keeping this decision beside [`publish_terminal_result`] prevents the
/// different `TaskHandle` producers from silently acquiring different abort
/// semantics. Panics are classified by the producer before calling this
/// helper and therefore continue to outrank cancellation.
pub(crate) fn classify_spawn_completion<T>(
    policy: SpawnCompletionPolicy,
    cancelled_before_first_poll: bool,
    cancellation_acknowledged: bool,
    cancellation_requested_at_completion: bool,
    cancel_reason: Option<CancelReason>,
    value: T,
) -> Result<T, JoinError> {
    if cancellation_requested_at_completion || cancel_reason.is_some() {
        let cancellation_is_attributed = cancel_reason.is_some();
        let cancellation_dominates = match policy {
            SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult => {
                cancelled_before_first_poll
                    || !cancellation_acknowledged
                    || !cancellation_is_attributed
            }
            SpawnCompletionPolicy::CancellationDominant => true,
        };
        if cancellation_dominates {
            // v0.4.3 reported a closed result channel when its public
            // compatibility `fast_cancel` handle carried a reasonless request
            // that suppressed terminal publication. Preserve that externally
            // visible fallback instead of inventing a new attributed reason or
            // allowing a late value to escape.
            let reason = cancel_reason.unwrap_or_else(|| CancelReason::user("join channel closed"));
            return Err(JoinError::Cancelled(reason));
        }
    }
    Ok(value)
}

/// A user future's returned value plus the cancellation facts observed at its
/// polling boundary.
///
/// Cancellation state is always sampled at the terminal user-future poll. For
/// the ordinary-spawn acknowledgement policy it is also sampled at the first
/// poll and after cancellation-bearing pending polls. The first sample
/// distinguishes cancellation-before-start from a request observed after
/// ordinary user code began; the terminal sample establishes the
/// classification boundary immediately after `Poll::Ready`, so an abort
/// observed before that sample participates in classification while a later
/// abort cannot rewrite it.
pub(crate) struct ObservedSpawnCompletion<T> {
    value: T,
    policy: SpawnCompletionPolicy,
    cancel_reason_at_completion: Option<CancelReason>,
    cancelled_before_first_poll: bool,
    cancellation_acknowledged: bool,
    cancellation_requested_at_completion: bool,
}

impl<T> ObservedSpawnCompletion<T> {
    /// Applies the producer's explicit cancellation policy to the observed
    /// value. Cancellation is intentionally snapshotted immediately after the
    /// user future's terminal poll. Once that snapshot is taken, a later abort
    /// cannot overwrite the already-classified value.
    pub(crate) fn classify(self) -> Result<T, JoinError> {
        classify_spawn_completion(
            self.policy,
            self.cancelled_before_first_poll,
            self.cancellation_acknowledged,
            self.cancellation_requested_at_completion,
            self.cancel_reason_at_completion,
            self.value,
        )
    }
}

/// Polls one spawned user future while retaining its cancellation receipt.
///
/// This helper deliberately does not catch panics or publish a result. Each
/// producer wraps it in its existing panic boundary, then applies its own
/// [`SpawnCompletionPolicy`] before calling [`publish_terminal_result`]. The
/// cancellation reason is sampled immediately after the terminal user poll so
/// a later abort cannot rewrite an already-observed completion.
pub(crate) fn observe_spawn_completion<F, T>(
    future: F,
    completion_cx: Cx,
    policy: SpawnCompletionPolicy,
) -> SpawnCompletionObserver<F>
where
    F: std::future::Future<Output = T>,
{
    SpawnCompletionObserver {
        future: Some(future),
        completion_cx,
        policy,
        cancelled_before_first_poll: None,
        cancellation_acknowledged: false,
    }
}

// A named future keeps Send checking proportional to the user future's
// structure instead of adding an async witness, PollFn closure, and borrowed
// pin at every nested spawn boundary. Pin projection needs no allocation and
// also supports the non-Send futures accepted by local spawn APIs.
#[pin_project::pin_project]
pub(crate) struct SpawnCompletionObserver<F> {
    #[pin]
    future: Option<F>,
    completion_cx: Cx,
    policy: SpawnCompletionPolicy,
    cancelled_before_first_poll: Option<bool>,
    cancellation_acknowledged: bool,
}

impl<F: std::future::Future> std::future::Future for SpawnCompletionObserver<F> {
    type Output = ObservedSpawnCompletion<F::Output>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        poll_cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut this = self.project();
        let track_cancellation_acknowledgement = matches!(
            this.policy,
            SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult
        );
        if track_cancellation_acknowledgement && this.cancelled_before_first_poll.is_none() {
            *this.cancelled_before_first_poll =
                Some(this.completion_cx.inner.read().is_cancel_requested());
        }
        let poll = this
            .future
            .as_mut()
            .as_pin_mut()
            .expect("spawn completion observer polled after completion")
            .poll(poll_cx);
        let mut cancellation_requested_at_completion = false;
        let mut cancel_reason_at_completion = None;
        // Healthy tasks pay one stable atomic load rather than acquiring the
        // context lock after every Pending poll. A checkpoint that
        // acknowledges cancellation also publishes this stable bit. Terminal
        // polls always take the lock so direct v0.4.3 `fast_cancel` handle
        // replacement remains observable even when user code never
        // checkpointed.
        if poll.is_ready()
            || (track_cancellation_acknowledgement
                && this.completion_cx.has_published_cancellation())
        {
            // The scheduler consumes and clears the per-poll acknowledgement
            // after `Poll::Pending`, so retain whether any user poll observed
            // it before control returns to the scheduler.
            let inner = this.completion_cx.inner.read();
            if track_cancellation_acknowledgement {
                *this.cancellation_acknowledged |= inner.cancel_acknowledged;
            }
            if poll.is_ready() {
                cancellation_requested_at_completion = inner.is_cancel_requested();
                cancel_reason_at_completion.clone_from(&inner.cancel_reason);
            }
        }
        if poll.is_ready() {
            // The async observer also dropped the completed user future before
            // returning Ready. Keep its destructor inside the producer's poll
            // panic boundary, after freezing the terminal cancellation facts.
            // Pin::set drops in place and supports !Unpin user futures.
            this.future.set(None);
        }
        poll.map(|value| ObservedSpawnCompletion {
            value,
            policy: *this.policy,
            cancel_reason_at_completion,
            cancelled_before_first_poll: this.cancelled_before_first_poll.unwrap_or(false),
            cancellation_acknowledged: *this.cancellation_acknowledged,
            cancellation_requested_at_completion,
        })
    }
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled(reason) => write!(f, "task was cancelled: {reason}"),
            Self::Panicked(payload) => write!(f, "task panicked: {payload}"),
            Self::PolledAfterCompletion => write!(f, "join future polled after completion"),
        }
    }
}

impl std::error::Error for JoinError {}

/// Capability-restricted sender for a [`TaskHandle`] terminal result.
///
/// Spawn adapters deliberately receive this wrapper instead of the raw
/// [`oneshot::Sender`]. It exposes no cancellation-aware `send` operation, so
/// routing terminal bookkeeping back through the completed task's cancelled
/// [`Cx`] is not representable at those call sites.
pub(crate) struct TaskResultSender<T> {
    sender: oneshot::Sender<Result<T, JoinError>>,
}

/// Creates the result channel behind one [`TaskHandle`].
fn task_result_channel<T>() -> (TaskResultSender<T>, oneshot::Receiver<Result<T, JoinError>>) {
    let (sender, receiver) = oneshot::channel();
    (TaskResultSender { sender }, receiver)
}

/// Publishes a task's terminal result without consulting task cancellation.
///
/// Terminal-result delivery is runtime bookkeeping performed after a spawn
/// adapter has already classified the completion as a returned value, task
/// cancellation, or panic. It must not itself be routed through the completed
/// task's [`Cx`], because doing so can discard that classification merely
/// because the task observed cancellation during its final user-code poll.
pub(crate) fn publish_terminal_result<T>(
    sender: TaskResultSender<T>,
    result: Result<T, JoinError>,
) {
    let _ = sender.sender.send_blocking(result);
}

/// A handle to a spawned task that can be used to await its result.
///
/// `TaskHandle<T>` is returned by `Cx::spawn`, `Cx::spawn_in`,
/// `Scope::spawn_registered`, and related methods.
/// It provides:
/// - The task ID for identification and debugging
/// - A way to await the task's result via `join()`
///
/// # Ownership
///
/// The TaskHandle does not own the task - the task is owned by its region.
/// If the TaskHandle is dropped, the task continues running. The handle
/// is just a way to observe the result.
///
/// # Cancel Safety
///
/// If `join()` is cancelled (the future is dropped before completion), the task
/// is automatically aborted. This prevents orphan tasks in races and timeouts.
/// The handle can be retried to await the cancellation result.
///
/// # Example
///
/// ```ignore
/// let handle = cx.spawn(|cx| async move { 42 })?;
/// let result = handle.join(&cx).await?;
/// assert_eq!(result, 42);
/// ```
#[derive(Debug)]
pub struct TaskHandle<T> {
    /// The ID of the spawned task.
    task_id: TaskId,
    /// Receiver for the task's result.
    receiver: oneshot::Receiver<Result<T, JoinError>>,
    /// Weak reference to the task's context state for cancellation.
    inner: Weak<RwLock<CxInner>>,
    /// Late-bound identity for mailbox spawns (br-asupersync-hwjqyo /
    /// A2.2): admission fills this with the canonical arena id and a live
    /// Cx weak handle. `task_id`/`inner` above hold the provisional values
    /// until then.
    admitted: Option<Arc<crate::runtime::spawn_mailbox::AdmittedTaskSlot>>,
    /// Strongest cancellation reason requested through this handle. This
    /// outlives the task context so a closed join channel retains attribution.
    requested_cancel_reason: Arc<RwLock<Option<CancelReason>>>,
    /// Whether this handle already consumed a terminal join result.
    terminal_consumed: bool,
    /// Retirement barrier gating terminal-result visibility until the scheduler
    /// commits this task's authoritative record (br-asupersync-yhueis).
    /// Runtime-minted, record-backed handles are wired to a `pending` barrier
    /// the scheduler opens post-retirement; standalone and admission-denied
    /// handles start open, so their results surface immediately as before.
    /// While the barrier is closed the consumer paths never poll the oneshot,
    /// so an early terminal stays in the channel — unconsumed and unobservable
    /// — until the scheduler opens the barrier.
    barrier: Arc<RetirementBarrier>,
}

/// Creates the inseparable result-publication capability and handle pair for
/// one admitted runtime task.
///
/// Runtime spawn adapters must use this factory instead of pairing a raw
/// [`oneshot::Sender`] with [`TaskHandle::new`]. Keeping the only sender they
/// receive capability-restricted makes cancellation-aware terminal
/// publication unrepresentable in those adapters while preserving the
/// existing low-level public constructor for compatibility.
pub(crate) fn task_handle_channel<T>(
    task_id: TaskId,
    inner: Weak<RwLock<CxInner>>,
) -> (TaskResultSender<T>, TaskHandle<T>) {
    let (sender, receiver) = task_result_channel();
    (sender, TaskHandle::new(task_id, receiver, inner))
}

/// Creates the result-publication capability and pending handle pair for one
/// mailbox-admitted runtime task.
pub(crate) fn pending_task_handle_channel<T>(
    provisional_task_id: TaskId,
    admitted: Arc<crate::runtime::spawn_mailbox::AdmittedTaskSlot>,
) -> (TaskResultSender<T>, TaskHandle<T>) {
    let (sender, receiver) = task_result_channel();
    (
        sender,
        TaskHandle::new_pending(provisional_task_id, receiver, admitted),
    )
}

fn apply_or_defer_cancel_reason(
    fallback_task_id: TaskId,
    admitted: Option<&Arc<crate::runtime::spawn_mailbox::AdmittedTaskSlot>>,
    fallback_inner: &Weak<RwLock<CxInner>>,
    requested: &RwLock<Option<CancelReason>>,
    reason: &CancelReason,
) {
    // The reason-cache write lock is the admission-publication linearization
    // point. Admission holds the same lock while replaying cached cancellation
    // and marking the canonical task runnable-published.
    let mut cached = requested.write();
    let changed = if let Some(existing) = cached.as_mut() {
        existing.strengthen(reason)
    } else {
        *cached = Some(reason.clone());
        true
    };
    let strongest_requested = cached
        .as_ref()
        .expect("a cancellation cache contains its strongest reason")
        .clone();

    let (task_id, inner, slot_gateway, admitted_slot) = if let Some(slot) = admitted {
        let Some(admitted) = slot.get().filter(|task| task.is_published()) else {
            // Admission will replay the cache and own the initial cancel-lane
            // publication. Never enqueue a provisional identity.
            return;
        };
        let Some(inner) = admitted.cx_inner.upgrade() else {
            return;
        };
        (
            admitted.task_id,
            inner,
            slot.cancel_gateway(),
            Some(Arc::clone(slot)),
        )
    } else {
        let Some(inner) = fallback_inner.upgrade() else {
            return;
        };
        (fallback_task_id, inner, None, None)
    };

    // Checkpoints observe cancellation immediately, but the caller/Drop stack
    // must never snapshot or invoke Wakers. The runtime-owned command consumer
    // performs the authoritative TaskRecord transition, publishes the cancel
    // lane, and only then dispatches Wakers.
    let (gateway, effective_reason, should_enqueue) = {
        let mut lock = inner.write();
        strengthen_cancel_reason_locked(&mut lock, &strongest_requested);
        let gateway = slot_gateway.or_else(|| lock.cancel_gateway.clone());
        let effective_reason = lock.cancel_reason.clone().unwrap_or(strongest_requested);
        // A structurally invalid delegated route is not self-requeued by the
        // consumer. Once an operator repairs the route, an explicit repeat of
        // the same abort reason is therefore a fresh retry trigger. Published
        // tasks retain the ordinary same-reason coalescing behavior.
        let should_enqueue = changed || lock.runnable_publication.is_delegated_cancel();
        (gateway, effective_reason, should_enqueue)
    };
    drop(cached);
    if should_enqueue && let Some(gateway) = gateway {
        if let Some(admitted_slot) = admitted_slot {
            let _ = gateway.enqueue_handle_cancel_with_admitted_slot(
                task_id,
                effective_reason,
                admitted_slot,
            );
        } else {
            let _ = gateway.enqueue_handle_cancel(task_id, effective_reason);
        }
    }
}

fn strengthen_cancelled_result<T>(
    mut result: Result<T, JoinError>,
    requested: &RwLock<Option<CancelReason>>,
) -> Result<T, JoinError> {
    if let Err(JoinError::Cancelled(reason)) = &mut result {
        if let Some(requested) = requested.read().as_ref() {
            reason.strengthen(requested);
        }
    }
    result
}

fn strengthen_cancel_reason_locked(lock: &mut CxInner, reason: &CancelReason) {
    let newly_requested = !lock.cancel_requested;
    lock.set_cancel_requested(true);
    let reason_changed = if let Some(existing) = &mut lock.cancel_reason {
        existing.strengthen(reason)
    } else {
        lock.cancel_reason = Some(reason.clone());
        true
    };
    let changed = newly_requested || reason_changed;
    if changed && !lock.cancel_waker_registry_closed {
        lock.cancel_wakers_pending = true;
    }
}

/// Applies a cached pre-admission abort, snapshots the task's effective
/// cancellation priority, and publishes its first runnable lane while the Cx
/// state is still locked. A concurrent region/task cancellation therefore
/// linearizes either before the snapshot (and selects the cancel lane) or
/// after runnable publication (and performs an ordinary post-publication
/// cancel transition).
pub(crate) fn publish_admitted_cancel_state(
    inner: &RwLock<CxInner>,
    cached_reason: Option<&CancelReason>,
    publish_lane: impl FnOnce(Option<u8>),
) -> crate::types::task_context::CancelWakeEffects {
    let mut lock = inner.write();
    if let Some(reason) = cached_reason {
        strengthen_cancel_reason_locked(&mut lock, reason);
    }
    let effective_priority = lock.cancel_requested.then(|| {
        lock.cancel_reason
            .as_ref()
            .map_or(u8::MAX, |reason| reason.cleanup_budget().priority)
    });
    publish_lane(effective_priority);
    lock.runnable_publication.mark_published();
    let wakes = if lock.cancel_requested && lock.cancel_wakers_pending {
        let wakes = lock.cancel_waker_snapshot();
        lock.cancel_wakers_pending = false;
        crate::types::task_context::CancelWakeEffects::new(wakes)
    } else {
        crate::types::task_context::CancelWakeEffects::empty()
    };
    #[cfg(feature = "tracing-integration")]
    let pending_trace = lock.pending_task_cancel_trace.take();
    drop(lock);
    #[cfg(feature = "tracing-integration")]
    let wakes = {
        let mut wakes = wakes;
        if let Some(trace) = pending_trace {
            trace.append_to(&mut wakes);
        }
        wakes
    };
    wakes
}

/// Replays a managed pre-admission handle abort without exposing the task to
/// a runnable lane or snapshotting Wakers. The admission handoff enqueues an
/// authoritative cancellation command immediately afterward; its runtime-side
/// consumer transitions the TaskRecord before publishing the first cancel
/// lane and dispatching any Waker.
pub(crate) fn prepare_admitted_handle_cancel_state(
    inner: &RwLock<CxInner>,
    cached_reason: &CancelReason,
) -> CancelReason {
    let mut lock = inner.write();
    strengthen_cancel_reason_locked(&mut lock, cached_reason);
    lock.runnable_publication.delegate_cancel();
    lock.cancel_reason
        .clone()
        .unwrap_or_else(|| cached_reason.clone())
}

impl<T> TaskHandle<T> {
    /// Creates a low-level `TaskHandle` from an existing result receiver.
    ///
    /// This constructor remains public for compatibility with existing test
    /// harnesses and custom runtimes. Asupersync's own runtime spawn adapters
    /// use the capability-restricted `task_handle_channel` factory so their
    /// terminal publisher cannot accidentally become cancellation-aware.
    #[inline]
    #[doc(hidden)]
    pub fn new(
        task_id: TaskId,
        receiver: oneshot::Receiver<Result<T, JoinError>>,
        inner: Weak<RwLock<CxInner>>,
    ) -> Self {
        Self {
            task_id,
            receiver,
            inner,
            admitted: None,
            requested_cancel_reason: Arc::new(RwLock::new(None)),
            terminal_consumed: false,
            // Standalone public constructor: no runtime record to retire, so
            // the barrier is open and terminal results surface immediately.
            barrier: RetirementBarrier::open_now(),
        }
    }

    /// Creates a handle for a mailbox spawn whose canonical identity is
    /// filled in by admission (br-asupersync-hwjqyo / A2.2). Until the
    /// slot is set, `task_id()` reports the provisional mailbox id and
    /// abort is recorded in the shared admission slot and replayed against
    /// the canonical task context as soon as admission publishes it.
    #[inline]
    #[doc(hidden)]
    pub(crate) fn new_pending(
        provisional_task_id: TaskId,
        receiver: oneshot::Receiver<Result<T, JoinError>>,
        admitted: std::sync::Arc<crate::runtime::spawn_mailbox::AdmittedTaskSlot>,
    ) -> Self {
        let requested_cancel_reason = admitted.pending_handle_cancel_reason();
        // The barrier for a record-backed spawn is created by admission and
        // shared through the admitted slot, so the scheduler and this handle
        // observe the same gate. Before the slot publishes one (or for paths
        // not yet wired), an open barrier preserves immediate delivery.
        let barrier = admitted
            .retirement_barrier()
            .unwrap_or_else(RetirementBarrier::open_now);
        Self {
            task_id: provisional_task_id,
            receiver,
            inner: Weak::new(),
            admitted: Some(admitted),
            requested_cancel_reason,
            terminal_consumed: false,
            barrier,
        }
    }

    /// Resolves the live `CxInner` weak handle: the admission-filled one
    /// for mailbox spawns, the construction-time one otherwise.
    fn live_inner(&self) -> Option<std::sync::Arc<RwLock<CxInner>>> {
        if let Some(slot) = &self.admitted {
            if let Some(admitted) = slot.get() {
                return admitted.cx_inner.upgrade();
            }
        }
        self.inner.upgrade()
    }

    /// Returns the task ID of the spawned task.
    ///
    /// For mailbox spawns this is the canonical arena id once admission
    /// has run, and the provisional mailbox id before that.
    #[inline]
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        if let Some(slot) = &self.admitted {
            if let Some(admitted) = slot.get() {
                return admitted.task_id;
            }
        }
        self.task_id
    }

    /// Returns true if the task has reached a terminal join state.
    ///
    /// This is true when either:
    /// - the result value is ready, or
    /// - the join channel is already closed.
    ///
    /// The closed-channel case matters for drop semantics: dropping an
    /// unpolled join future should not stamp an abort reason onto a task
    /// that has already terminated and closed its join channel.
    #[inline]
    #[must_use]
    pub fn is_finished(&self) -> bool {
        // A record-backed task is only observably finished once its retirement
        // barrier has opened: a terminal buffered in the join channel before
        // the record commits must not report completion, or a caller could act
        // on it before retirement. Peeks only; never consumes or mutates the
        // receiver.
        self.terminal_consumed
            || (self.barrier.is_open() && (self.receiver.is_ready() || self.receiver.is_closed()))
    }

    /// Returns true once the task has published its terminal result (or closed
    /// its join channel), whether or not its retirement barrier has opened.
    ///
    /// Implicit ownership cleanup (a dropped set or race) uses this, not
    /// [`Self::is_finished`], to decide whether a member still needs a
    /// cancellation request. Between publication and record retirement the
    /// task has already finished, and an abort would only stamp a cancellation
    /// onto its context (br-asupersync-yhueis applied the same rule to
    /// `JoinFuture::drop`).
    #[inline]
    #[must_use]
    pub(crate) fn terminal_published(&self) -> bool {
        self.terminal_consumed || self.receiver.is_ready() || self.receiver.is_closed()
    }

    /// A handle whose retirement barrier is `barrier`, as a runtime spawn
    /// creates it, for tests that need a published but unretired member.
    #[cfg(test)]
    pub(crate) fn with_retirement_barrier_for_test(
        task_id: TaskId,
        receiver: oneshot::Receiver<Result<T, JoinError>>,
        inner: Weak<RwLock<CxInner>>,
        barrier: Arc<RetirementBarrier>,
    ) -> Self {
        Self {
            task_id,
            receiver,
            inner,
            admitted: None,
            requested_cancel_reason: Arc::new(RwLock::new(None)),
            terminal_consumed: false,
            barrier,
        }
    }

    /// Waits for the task to complete and returns its result.
    ///
    /// This method yields until the spawned task completes, then returns its output value.
    ///
    /// # Errors
    ///
    /// Returns `Err(JoinError::Cancelled)` if the task was cancelled.
    /// Returns `Err(JoinError::Panicked)` if the task panicked.
    ///
    /// # Cancel Safety
    ///
    /// If this method is cancelled (the returned future is dropped), the task
    /// is automatically aborted. This ensures that "stopping waiting" translates
    /// to "stopping the task", preventing orphan tasks in races and timeouts.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut handle = cx.spawn(|cx| async move { 42 })?;
    /// match handle.join(&cx).await {
    ///     Ok(value) => println!("Task returned: {value}"),
    ///     Err(JoinError::Cancelled(r)) => println!("Task was cancelled: {r}"),
    ///     Err(JoinError::Panicked(p)) => println!("Task panicked: {p}"),
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn join<'a>(&'a mut self, _cx: &'a Cx) -> JoinFuture<'a, T> {
        // Resolve the live linkage at join time: mailbox spawns start with a
        // dangling weak that admission supersedes via the admitted slot.
        let cx_inner = self
            .live_inner()
            .map_or_else(Weak::new, |arc| std::sync::Arc::downgrade(&arc));
        let receiver = &mut self.receiver;
        let terminal_state = &mut self.terminal_consumed;
        let barrier = std::sync::Arc::clone(&self.barrier);
        JoinFuture {
            inner: receiver.recv_uninterruptible(),
            fallback_task_id: self.task_id,
            cx_inner,
            admitted: self.admitted.as_ref(),
            requested_cancel_reason: self.requested_cancel_reason.as_ref(),
            terminal_state,
            barrier,
            registered: false,
            drop_abort_defused: false,
            drop_reason: None,
        }
    }

    /// Waits for the task to complete, aborting with a specific reason if dropped.
    ///
    /// This is like `join()`, but allows specifying the cancellation reason that
    /// should be used if the join future is dropped before completion. This is
    /// useful for combinators like `race` that want to attribute cancellation
    /// to "losing the race".
    #[inline]
    #[must_use]
    pub fn join_with_drop_reason<'a>(
        &'a mut self,
        _cx: &'a Cx,
        reason: CancelReason,
    ) -> JoinFuture<'a, T> {
        // Resolve the live linkage at join time, exactly like `join`: mailbox
        // spawns start with a dangling `self.inner` weak that admission
        // supersedes via the admitted slot. Cloning `self.inner` directly
        // would leave the drop-abort path with a permanently-dangling weak, so
        // dropping the loser in `Scope::race`/`Scope::hedge` would never
        // request cancellation and the loser would never drain (hang +
        // quiescence violation).
        let cx_inner = self
            .live_inner()
            .map_or_else(Weak::new, |arc| std::sync::Arc::downgrade(&arc));
        let receiver = &mut self.receiver;
        let terminal_state = &mut self.terminal_consumed;
        let barrier = std::sync::Arc::clone(&self.barrier);
        JoinFuture {
            inner: receiver.recv_uninterruptible(),
            fallback_task_id: self.task_id,
            cx_inner,
            admitted: self.admitted.as_ref(),
            requested_cancel_reason: self.requested_cancel_reason.as_ref(),
            terminal_state,
            barrier,
            registered: false,
            drop_abort_defused: false,
            drop_reason: Some(reason),
        }
    }

    /// Attempts to get the task's result without waiting.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(result))` if the task has completed
    /// - `Ok(None)` if the task is still running
    /// - `Err(JoinError)` if the task was cancelled or panicked
    /// - `Err(JoinError::PolledAfterCompletion)` if a terminal result was already consumed
    #[inline]
    pub fn try_join(&mut self) -> Result<Option<T>, JoinError> {
        if self.terminal_consumed {
            return Err(JoinError::PolledAfterCompletion);
        }
        // Gate on the retirement barrier BEFORE touching the oneshot, and
        // registration-free: while the barrier is closed, report not-ready
        // (`Ok(None)`) without consuming the receiver, so an early terminal is
        // never surfaced before the record commits. The unconsumed value stays
        // in the channel until a later call observes the opened barrier.
        if !self.barrier.is_open() {
            return Ok(None);
        }
        match self.receiver.try_recv() {
            Ok(result) => {
                self.terminal_consumed = true;
                strengthen_cancelled_result(result, &self.requested_cancel_reason).map(Some)
            }
            Err(oneshot::TryRecvError::Empty) => Ok(None),
            Err(oneshot::TryRecvError::Closed) => {
                self.terminal_consumed = true;
                Err(JoinError::Cancelled(self.closed_reason()))
            }
        }
    }

    /// Polls for the task's terminal result, keeping the wake registration
    /// alive on this handle.
    ///
    /// This is the poll-based counterpart to [`join`](Self::join), for callers
    /// that cannot hold a [`JoinFuture`] across polls — a combinator scanning
    /// many handles within a single poll, for example. The waiter identity
    /// lives on this handle's own receiver, so a [`Poll::Pending`] result
    /// leaves the handle registered for wakeup. Constructing a fresh `join`
    /// future per poll instead registers a waiter and then retires it again
    /// when that future drops, which parks the caller with no wake source at
    /// all (br-asupersync-tncxj9).
    ///
    /// [`Poll::Pending`]: std::task::Poll::Pending
    ///
    /// The registration is retired when the task's result is consumed or when
    /// this handle is dropped, whichever comes first. A caller that stops
    /// polling but keeps the handle alive therefore keeps one waiter slot per
    /// handle and may observe a spurious wake once the task completes, which is
    /// the ordinary cost of a wake registration outliving a single poll.
    ///
    /// # Cancel Safety
    ///
    /// Unlike [`join`](Self::join), this does **not** abort the task when the
    /// caller stops polling: there is no future whose drop could carry that
    /// meaning. A caller that wants "stop waiting implies stop the task" calls
    /// [`abort`](Self::abort) or [`abort_with_reason`](Self::abort_with_reason)
    /// explicitly. The owning region remains the quiescence backstop either
    /// way, so a handle that is simply never polled again cannot orphan its
    /// task.
    ///
    /// # Errors
    ///
    /// Mirrors [`join`](Self::join): [`JoinError::Cancelled`] if the task was
    /// cancelled, [`JoinError::Panicked`] if it panicked, and
    /// [`JoinError::PolledAfterCompletion`] once a terminal result has already
    /// been consumed through this handle.
    #[inline]
    pub fn poll_join(
        &mut self,
        ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<T, JoinError>> {
        if self.terminal_consumed {
            return std::task::Poll::Ready(Err(JoinError::PolledAfterCompletion));
        }
        // Gate on the retirement barrier BEFORE consuming the oneshot: while
        // the barrier is closed, register for its open-wake (register-then-
        // recheck closes the lost-wake race) and park WITHOUT polling the
        // receiver, so an early terminal is never surfaced before the record
        // commits (br-asupersync-yhueis). The value stays in the channel; only
        // once the barrier opens do we consume it. Standalone and denial
        // handles start open, so this gate is a no-op for them.
        if !self.barrier.is_open() && !self.barrier.register_and_is_open(ctx.waker()) {
            return std::task::Poll::Pending;
        }
        match self.receiver.poll_recv_uninterruptible(ctx) {
            std::task::Poll::Ready(Ok(result)) => {
                self.terminal_consumed = true;
                std::task::Poll::Ready(strengthen_cancelled_result(
                    result,
                    &self.requested_cancel_reason,
                ))
            }
            std::task::Poll::Ready(Err(oneshot::RecvError::Closed)) => {
                self.terminal_consumed = true;
                std::task::Poll::Ready(Err(JoinError::Cancelled(self.closed_reason())))
            }
            std::task::Poll::Ready(Err(oneshot::RecvError::Cancelled)) => {
                unreachable!("an uninterruptible receive cannot return Cancelled");
            }
            std::task::Poll::Ready(Err(oneshot::RecvError::PolledAfterCompletion)) => {
                unreachable!(
                    "poll_recv_uninterruptible tracks no per-future completion state; \
                     terminal repolls are guarded by TaskHandle::terminal_consumed"
                );
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    #[cfg(test)]
    fn terminal_consumed_for_test(&self) -> bool {
        self.terminal_consumed
    }

    /// Aborts the task (requests cancellation).
    ///
    /// This is cooperative cancellation, not forced future destruction: the
    /// task may not stop immediately and observes the request at its next
    /// cancellation-aware checkpoint or parked-operation repoll. For ordinary
    /// [`Cx::spawn`](crate::cx::Cx::spawn) tasks that already started, a value
    /// returned after user code acknowledges cancellation is preserved inside
    /// the outer successful join result. This includes a typed operation-level
    /// cancellation value returned after protocol cleanup. Cancellation
    /// requested before the first user-future poll, or ignored by
    /// cancellation-blind work, joins as [`JoinError::Cancelled`].
    /// The legacy state-threaded [`Scope`](crate::cx::Scope) API intentionally
    /// preserves any value its user future actually returns. Cancellation-
    /// dominant combinators and blocking wrappers document their stricter
    /// result policy on the spawning API.
    #[inline]
    pub fn abort(&self) {
        self.abort_with_reason(CancelReason::user("abort"));
    }

    /// Aborts the task (requests cancellation) with an explicit reason.
    ///
    /// If a reason is already present, this request strengthens it using
    /// [`CancelReason::strengthen`], preserving deterministic attribution.
    /// Result classification follows [`Self::abort`]; this method changes the
    /// reason, not the cooperative cancellation protocol.
    /// Runtime-managed handles enqueue a callback-free command so cancel-lane
    /// publication and Waker dispatch occur on the runtime side. A manually
    /// constructed handle whose `CxInner` has no spawn gateway updates
    /// checkpoint-visible cancellation state only; it does not promise to
    /// wake a parked task, and its owner must drive authoritative
    /// [`crate::runtime::RuntimeState`] cancellation explicitly.
    #[inline]
    pub fn abort_with_reason(&self, reason: CancelReason) {
        apply_or_defer_cancel_reason(
            self.task_id,
            self.admitted.as_ref(),
            &self.inner,
            &self.requested_cancel_reason,
            &reason,
        );
    }

    #[inline]
    fn closed_reason(&self) -> CancelReason {
        let reason = self
            .live_inner()
            .and_then(|inner| inner.read().cancel_reason.clone())
            .or_else(|| self.requested_cancel_reason.read().clone())
            .unwrap_or_else(|| CancelReason::user("join channel closed"));
        self.barrier.strengthen_shutdown_reason(reason)
    }
}

impl<T> Drop for TaskHandle<T> {
    fn drop(&mut self) {
        self.barrier.clear_waker();
    }
}

/// Future returned by [`TaskHandle::join`].
///
/// This future aborts the task if dropped before completion, ensuring correct
/// cleanup in races and timeouts.
pub struct JoinFuture<'a, T> {
    inner: oneshot::RecvUninterruptibleFuture<'a, Result<T, JoinError>>,
    fallback_task_id: TaskId,
    cx_inner: Weak<RwLock<CxInner>>,
    admitted: Option<&'a Arc<crate::runtime::spawn_mailbox::AdmittedTaskSlot>>,
    requested_cancel_reason: &'a RwLock<Option<CancelReason>>,
    terminal_state: &'a mut bool,
    /// Retirement barrier shared with the originating handle: while it is
    /// closed this future does not poll the receiver, so an early terminal is
    /// never consumed or surfaced until the scheduler opens it post-retirement.
    barrier: Arc<RetirementBarrier>,
    /// Whether this future stored its waker on the barrier. Only then does
    /// dropping it clear the slot: a waker the handle's own `poll_join`
    /// registered is not this future's to drop.
    registered: bool,
    drop_abort_defused: bool,
    drop_reason: Option<CancelReason>,
}

impl<T> JoinFuture<'_, T> {
    fn live_inner(&self) -> Option<Arc<RwLock<CxInner>>> {
        if let Some(admitted) = self.admitted.and_then(|slot| slot.get()) {
            return admitted.cx_inner.upgrade();
        }
        self.cx_inner.upgrade()
    }

    #[inline]
    fn closed_reason(&self) -> CancelReason {
        let reason = self
            .live_inner()
            .and_then(|inner| inner.read().cancel_reason.clone())
            .or_else(|| self.requested_cancel_reason.read().clone())
            .unwrap_or_else(|| CancelReason::user("join channel closed"));
        self.barrier.strengthen_shutdown_reason(reason)
    }

    fn abort_with_reason(&self, reason: CancelReason) {
        apply_or_defer_cancel_reason(
            self.fallback_task_id,
            self.admitted,
            &self.cx_inner,
            self.requested_cancel_reason,
            &reason,
        );
    }

    /// Prevents drop-triggered abort for internal combinator control flow.
    #[inline]
    pub(crate) fn defuse_drop_abort(&mut self) {
        self.drop_abort_defused = true;
    }
}

impl<T> std::future::Future for JoinFuture<'_, T> {
    type Output = Result<T, JoinError>;

    #[inline]
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = &mut *self;
        if *this.terminal_state {
            return std::task::Poll::Ready(Err(JoinError::PolledAfterCompletion));
        }
        // Gate on the retirement barrier BEFORE polling the inner oneshot recv:
        // while the barrier is closed, register for its open-wake (register-
        // then-recheck closes the lost-wake race) and park WITHOUT consuming
        // the receiver, so an early terminal is never surfaced before the
        // record commits (br-asupersync-yhueis). The value stays in the
        // channel, so the unpolled-ready drop fast path still observes it.
        if !this.barrier.is_open() {
            this.registered = true;
            if !this.barrier.register_and_is_open(cx.waker()) {
                return std::task::Poll::Pending;
            }
        }
        // JoinError needs to be mapped if recv fails with RecvError
        match std::pin::Pin::new(&mut this.inner).poll(cx) {
            std::task::Poll::Ready(Ok(res)) => {
                *this.terminal_state = true;
                std::task::Poll::Ready(strengthen_cancelled_result(
                    res,
                    this.requested_cancel_reason,
                ))
            }
            std::task::Poll::Ready(Err(crate::channel::oneshot::RecvError::Closed)) => {
                *this.terminal_state = true;
                std::task::Poll::Ready(Err(JoinError::Cancelled(this.closed_reason())))
            }
            std::task::Poll::Ready(Err(crate::channel::oneshot::RecvError::Cancelled)) => {
                unreachable!("RecvUninterruptibleFuture cannot return Cancelled");
            }
            std::task::Poll::Ready(Err(
                crate::channel::oneshot::RecvError::PolledAfterCompletion,
            )) => {
                unreachable!(
                    "JoinFuture guards repolls before polling the inner oneshot recv future"
                );
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<T> Drop for JoinFuture<'_, T> {
    fn drop(&mut self) {
        // Abort the task if we stop waiting for it.
        // This makes TaskHandle::join cancel-safe and race-safe.
        // Completion already happened if the oneshot is already ready (or
        // closed) — even if this future never polled it because the barrier
        // was still closed. Gate-first never consumes the value while gated,
        // so the receiver still reflects readiness here; dropping must not
        // stamp cancellation between producer publication and record
        // retirement (br-asupersync-yhueis / 6976).
        if !*self.terminal_state && !self.drop_abort_defused && !self.inner.receiver_finished() {
            if let Some(reason) = self.drop_reason.take() {
                self.abort_with_reason(reason);
            } else {
                self.abort_with_reason(CancelReason::user("abort"));
            }
        }
        // After the abort, so a foreign waker destructor cannot skip it.
        if self.registered {
            self.barrier.clear_waker();
        }
    }
}

#[cfg(test)]
#[path = "task_handle_inline_tests.rs"]
mod tests;

// Monitor and link targets (br-asupersync-issue65-criticisms-kpmoy5.6.1).
impl<T> TaskHandle<T> {
    /// The id this handle reports now and, for a mailbox spawn, the slot that
    /// admission fills with the canonical id. A monitor or link made right
    /// after the spawn resolves the canonical id through the slot.
    pub(crate) fn watch_target_parts(
        &self,
    ) -> (
        TaskId,
        Option<Arc<crate::runtime::spawn_mailbox::AdmittedTaskSlot>>,
    ) {
        (self.task_id(), self.admitted.clone())
    }
}
