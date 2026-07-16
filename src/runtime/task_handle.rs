//! TaskHandle for awaiting spawned task results.
//!
//! `TaskHandle<T>` is returned by spawn operations and allows the spawner
//! to await the task's result. Similar to join handles in other runtimes.

use crate::channel::oneshot;
use crate::cx::Cx;
use crate::types::{CancelReason, CxInner, PanicPayload, TaskId};
use parking_lot::RwLock;
use std::sync::{Arc, Weak};

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
    lock.cancel_requested = true;
    lock.fast_cancel
        .store(true, std::sync::atomic::Ordering::Release);
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
    /// Creates a new TaskHandle (internal use).
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
        let requested_cancel_reason =
            crate::runtime::spawn_mailbox::register_pending_cancel_rendezvous(&admitted);
        Self {
            task_id: provisional_task_id,
            receiver,
            inner: Weak::new(),
            admitted: Some(admitted),
            requested_cancel_reason,
            terminal_consumed: false,
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
        self.terminal_consumed || self.receiver.is_ready() || self.receiver.is_closed()
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
        JoinFuture {
            inner: receiver.recv_uninterruptible(),
            fallback_task_id: self.task_id,
            cx_inner,
            admitted: self.admitted.as_ref(),
            requested_cancel_reason: self.requested_cancel_reason.as_ref(),
            terminal_state,
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
        JoinFuture {
            inner: receiver.recv_uninterruptible(),
            fallback_task_id: self.task_id,
            cx_inner,
            admitted: self.admitted.as_ref(),
            requested_cancel_reason: self.requested_cancel_reason.as_ref(),
            terminal_state,
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

    #[cfg(test)]
    fn terminal_consumed_for_test(&self) -> bool {
        self.terminal_consumed
    }

    /// Aborts the task (requests cancellation).
    ///
    /// This is a request - the task may not stop immediately. The task
    /// will observe the cancellation at its next checkpoint.
    #[inline]
    pub fn abort(&self) {
        self.abort_with_reason(CancelReason::user("abort"));
    }

    /// Aborts the task (requests cancellation) with an explicit reason.
    ///
    /// If a reason is already present, this request strengthens it using
    /// [`CancelReason::strengthen`], preserving deterministic attribution.
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
        self.live_inner()
            .and_then(|inner| inner.read().cancel_reason.clone())
            .or_else(|| self.requested_cancel_reason.read().clone())
            .unwrap_or_else(|| CancelReason::user("join channel closed"))
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
        self.live_inner()
            .and_then(|inner| inner.read().cancel_reason.clone())
            .or_else(|| self.requested_cancel_reason.read().clone())
            .unwrap_or_else(|| CancelReason::user("join channel closed"))
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
                let reason = this.closed_reason();
                std::task::Poll::Ready(Err(JoinError::Cancelled(reason)))
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
        if !*self.terminal_state && !self.drop_abort_defused {
            // If a result is already ready, don't stamp a spurious cancel
            // reason when dropping an unpolled join future.
            if self.inner.receiver_finished() {
                return;
            }
            if let Some(reason) = self.drop_reason.take() {
                self.abort_with_reason(reason);
            } else {
                self.abort_with_reason(CancelReason::user("abort"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::cap;
    use crate::test_utils::init_test_logging;
    use crate::types::CancelKind;
    use crate::util::ArenaIndex;
    use serde_json::{Value, json};
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn task_handle_snapshot<T>(handle: &TaskHandle<T>) -> Value {
        json!({
            "task_id": handle.task_id(),
            "is_finished": handle.is_finished(),
            "terminal_consumed": handle.terminal_consumed_for_test(),
        })
    }

    fn scrub_task_handle_ids(value: Value) -> Value {
        let mut scrubbed = value;

        if let Some(task_id) = scrubbed.pointer_mut("/pending/task_id") {
            *task_id = json!("[TASK_ID]");
        }

        if let Some(task_id) = scrubbed.pointer_mut("/consumed/task_id") {
            *task_id = json!("[TASK_ID]");
        }

        scrubbed
    }

    #[test]
    fn task_handle_basic() {
        init_test("task_handle_basic");
        crate::test_section!("setup");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        crate::assert_with_log!(
            handle.task_id() == task_id,
            "task id matches",
            task_id,
            handle.task_id()
        );
        crate::assert_with_log!(
            !handle.is_finished(),
            "handle not finished",
            false,
            handle.is_finished()
        );

        // Send the result
        crate::test_section!("send");
        tx.send(&cx, Ok::<i32, JoinError>(42)).expect("send failed");

        // Join should succeed
        crate::test_section!("join");
        let result = block_on(handle.join(&cx));
        let expected: Result<i32, JoinError> = Ok(42);
        crate::assert_with_log!(result == expected, "join result", expected, result);
        crate::test_complete!("task_handle_basic");
    }

    #[test]
    fn task_handle_cancelled() {
        init_test("task_handle_cancelled");
        crate::test_section!("setup");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        // Send a cancelled result
        crate::test_section!("send");
        tx.send(
            &cx,
            Err::<i32, JoinError>(JoinError::Cancelled(CancelReason::race_loser())),
        )
        .expect("send failed");

        crate::test_section!("join");
        let result = block_on(handle.join(&cx));
        match result {
            Err(JoinError::Cancelled(r)) => {
                crate::assert_with_log!(
                    matches!(r.kind, crate::types::CancelKind::RaceLost),
                    "cancel kind is race lost",
                    crate::types::CancelKind::RaceLost,
                    r.kind
                );
            }
            _ => unreachable!("expected Cancelled"),
        }
        crate::test_complete!("task_handle_cancelled");
    }

    #[test]
    fn join_closed_uses_cancel_reason() {
        init_test("join_closed_uses_cancel_reason");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        {
            let mut lock = cx.inner.write();
            lock.cancel_requested = true;
            lock.fast_cancel
                .store(true, std::sync::atomic::Ordering::Release);
            lock.cancel_reason = Some(CancelReason::timeout());
        }

        drop(tx);
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));

        let result = block_on(handle.join(&cx));
        match result {
            Err(JoinError::Cancelled(r)) => {
                crate::assert_with_log!(
                    r.kind == CancelKind::Timeout,
                    "cancel kind is timeout",
                    CancelKind::Timeout,
                    r.kind
                );
            }
            _ => unreachable!("expected Cancelled"),
        }
        crate::test_complete!("join_closed_uses_cancel_reason");
    }

    #[test]
    fn task_handle_panicked() {
        init_test("task_handle_panicked");
        crate::test_section!("setup");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        crate::test_section!("send");
        tx.send(
            &cx,
            Err::<i32, JoinError>(JoinError::Panicked(PanicPayload::new("boom"))),
        )
        .expect("send failed");

        crate::test_section!("join");
        let result = block_on(handle.join(&cx));
        match result {
            Err(JoinError::Panicked(p)) => {
                let payload = p.to_string();
                crate::assert_with_log!(
                    payload.contains("boom"),
                    "panic payload contains boom",
                    true,
                    payload
                );
            }
            _ => unreachable!("expected Panicked"),
        }
        crate::test_complete!("task_handle_panicked");
    }

    #[test]
    fn join_error_display() {
        init_test("join_error_display");
        let cancelled = JoinError::Cancelled(CancelReason::user("stop"));
        let cancelled_text = cancelled.to_string();
        crate::assert_with_log!(
            cancelled_text.contains("task was cancelled"),
            "cancelled display mentions cancelled",
            true,
            cancelled_text
        );
        crate::assert_with_log!(
            cancelled_text.contains("stop"),
            "cancelled display includes reason",
            true,
            cancelled_text
        );

        let panicked = JoinError::Panicked(PanicPayload::new("crash"));
        let panicked_text = panicked.to_string();
        crate::assert_with_log!(
            panicked_text.contains("task panicked"),
            "panicked display mentions panic",
            true,
            panicked_text
        );
        crate::assert_with_log!(
            panicked_text.contains("crash"),
            "panicked display includes payload",
            true,
            panicked_text
        );

        let terminal = JoinError::PolledAfterCompletion;
        let terminal_text = terminal.to_string();
        crate::assert_with_log!(
            terminal_text.contains("polled after completion"),
            "terminal repoll display mentions completion",
            true,
            terminal_text
        );
        crate::test_complete!("join_error_display");
    }

    #[test]
    fn drop_join_does_not_abort_if_result_already_ready() {
        init_test("drop_join_does_not_abort_if_result_already_ready");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(9, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        tx.send(&cx, Ok::<i32, JoinError>(7))
            .expect("send should succeed");

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));
        drop(handle.join(&cx));

        let (cancel_requested, cancel_reason_is_none) = {
            let guard = cx.inner.read();
            (guard.cancel_requested, guard.cancel_reason.is_none())
        };
        crate::assert_with_log!(
            !cancel_requested,
            "dropping a ready join must not request cancellation",
            false,
            cancel_requested
        );
        crate::assert_with_log!(
            cancel_reason_is_none,
            "dropping a ready join must not overwrite cancel reason",
            true,
            cancel_reason_is_none
        );
        crate::test_complete!("drop_join_does_not_abort_if_result_already_ready");
    }

    #[test]
    fn drop_join_does_not_abort_if_channel_already_closed() {
        init_test("drop_join_does_not_abort_if_channel_already_closed");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        drop(tx);

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));
        drop(handle.join(&cx));

        let (cancel_requested, cancel_reason_is_none) = {
            let guard = cx.inner.read();
            (guard.cancel_requested, guard.cancel_reason.is_none())
        };
        crate::assert_with_log!(
            !cancel_requested,
            "dropping a closed join must not request cancellation",
            false,
            cancel_requested
        );
        crate::assert_with_log!(
            cancel_reason_is_none,
            "dropping a closed join must not overwrite cancel reason",
            true,
            cancel_reason_is_none
        );
        crate::test_complete!("drop_join_does_not_abort_if_channel_already_closed");
    }

    #[test]
    fn drop_task_handle_detaches_without_requesting_cancel() {
        init_test("drop_task_handle_detaches_without_requesting_cancel");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 1));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));
        drop(handle);

        let (cancel_requested, cancel_reason_is_none) = {
            let guard = cx.inner.read();
            (guard.cancel_requested, guard.cancel_reason.is_none())
        };
        crate::assert_with_log!(
            !cancel_requested,
            "dropping TaskHandle itself must detach rather than request cancellation",
            false,
            cancel_requested
        );
        crate::assert_with_log!(
            cancel_reason_is_none,
            "detaching by dropping TaskHandle must not stamp a cancel reason",
            true,
            cancel_reason_is_none
        );
        crate::test_complete!("drop_task_handle_detaches_without_requesting_cancel");
    }

    #[test]
    fn abort_then_join_closed_channel_preserves_abort_reason() {
        init_test("abort_then_join_closed_channel_preserves_abort_reason");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 2));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));
        handle.abort_with_reason(CancelReason::timeout());
        drop(tx);

        let result = block_on(handle.join(&cx));
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::Timeout,
                    ..
                }))
            ),
            "join after explicit abort preserves the stronger timeout reason",
            "Err(JoinError::Cancelled(Timeout))",
            format!("{result:?}")
        );
        crate::test_complete!("abort_then_join_closed_channel_preserves_abort_reason");
    }

    #[test]
    fn late_abort_cannot_reopen_completed_cancel_waker_registry() {
        init_test("late_abort_cannot_reopen_completed_cancel_waker_registry");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 20));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let handle = TaskHandle::new(task_id, rx, Arc::downgrade(&cx.inner));

        let retired = cx.inner.write().take_cancel_wakers();
        drop(retired);
        handle.abort_with_reason(CancelReason::shutdown());

        let inner = cx.inner.read();
        assert!(inner.cancel_requested);
        assert!(
            inner
                .cancel_reason
                .as_ref()
                .is_some_and(|reason| reason.is_kind(CancelKind::Shutdown))
        );
        assert!(inner.cancel_waker_registry_closed);
        assert!(
            !inner.cancel_wakers_pending,
            "a terminal context cannot acquire new Waker publication debt"
        );
        crate::test_complete!("late_abort_cannot_reopen_completed_cancel_waker_registry");
    }

    #[test]
    fn abort_reason_survives_task_context_teardown() {
        init_test("abort_reason_survives_task_context_teardown");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 3));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        handle.abort_with_reason(CancelReason::race_loser());
        drop(tx);

        let result = block_on(handle.join(&cx));
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::RaceLost,
                    ..
                }))
            ),
            "closed join retains explicit reason after task context teardown",
            "Err(JoinError::Cancelled(RaceLost))",
            format!("{result:?}")
        );
        crate::test_complete!("abort_reason_survives_task_context_teardown");
    }

    #[test]
    fn pending_try_join_uses_admitted_context_cancel_reason() {
        init_test("pending_try_join_uses_admitted_context_cancel_reason");
        let cx = test_cx();
        let provisional = TaskId::from_arena(ArenaIndex::new(10, 4));
        let canonical = TaskId::from_arena(ArenaIndex::new(10, 5));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let admitted = Arc::new(crate::runtime::spawn_mailbox::AdmittedTaskSlot::new());
        let mut handle = TaskHandle::new_pending(provisional, rx, Arc::clone(&admitted));

        admitted
            .set(crate::runtime::spawn_mailbox::AdmittedTask::published(
                canonical,
                Arc::downgrade(&cx.inner),
            ))
            .expect("admitted identity publishes");
        cx.set_cancel_reason(CancelReason::shutdown());
        drop(tx);

        let result = handle.try_join();
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::Shutdown,
                    ..
                }))
            ),
            "try_join resolves the admitted mailbox context dynamically",
            "Err(JoinError::Cancelled(Shutdown))",
            format!("{result:?}")
        );
        crate::test_complete!("pending_try_join_uses_admitted_context_cancel_reason");
    }

    #[test]
    fn pending_join_resolves_admission_after_future_construction() {
        init_test("pending_join_resolves_admission_after_future_construction");
        let cx = test_cx();
        let provisional = TaskId::from_arena(ArenaIndex::new(10, 6));
        let canonical = TaskId::from_arena(ArenaIndex::new(10, 7));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let admitted = Arc::new(crate::runtime::spawn_mailbox::AdmittedTaskSlot::new());
        let mut handle = TaskHandle::new_pending(provisional, rx, Arc::clone(&admitted));

        let join = handle.join(&cx);
        admitted
            .set(crate::runtime::spawn_mailbox::AdmittedTask::published(
                canonical,
                Arc::downgrade(&cx.inner),
            ))
            .expect("late admitted identity publishes");
        cx.set_cancel_reason(CancelReason::timeout());
        drop(tx);

        let result = block_on(join);
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::Timeout,
                    ..
                }))
            ),
            "join future resolves admission published after construction",
            "Err(JoinError::Cancelled(Timeout))",
            format!("{result:?}")
        );
        crate::test_complete!("pending_join_resolves_admission_after_future_construction");
    }

    #[test]
    fn pending_requested_reason_strengthens_queued_denial() {
        init_test("pending_requested_reason_strengthens_queued_denial");
        let cx = test_cx();
        let provisional = TaskId::from_arena(ArenaIndex::new(10, 8));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let admitted = Arc::new(crate::runtime::spawn_mailbox::AdmittedTaskSlot::new());
        let mut handle = TaskHandle::new_pending(provisional, rx, admitted);

        tx.send(
            &cx,
            Err(JoinError::Cancelled(CancelReason::user(
                "spawn admission failed",
            ))),
        )
        .expect("denial result queues");
        handle.abort_with_reason(CancelReason::race_loser());

        let result = block_on(handle.join(&cx));
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::RaceLost,
                    ..
                }))
            ),
            "queued weaker denial is strengthened by pending RaceLost request",
            "Err(JoinError::Cancelled(RaceLost))",
            format!("{result:?}")
        );

        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let admitted = Arc::new(crate::runtime::spawn_mailbox::AdmittedTaskSlot::new());
        let mut handle = TaskHandle::new_pending(provisional, rx, admitted);
        tx.send(
            &cx,
            Err(JoinError::Cancelled(CancelReason::user(
                "spawn admission failed",
            ))),
        )
        .expect("second denial result queues");
        handle.abort_with_reason(CancelReason::race_loser());
        let try_result = handle.try_join();
        crate::assert_with_log!(
            matches!(
                try_result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::RaceLost,
                    ..
                }))
            ),
            "try_join also strengthens a queued weaker denial",
            "Err(JoinError::Cancelled(RaceLost))",
            format!("{try_result:?}")
        );
        crate::test_complete!("pending_requested_reason_strengthens_queued_denial");
    }

    #[test]
    fn concurrent_pending_abort_requests_keep_strongest_reason() {
        init_test("concurrent_pending_abort_requests_keep_strongest_reason");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 9));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let handle = Arc::new(TaskHandle::new(task_id, rx, Weak::new()));
        let barrier = Arc::new(std::sync::Barrier::new(3));

        let race_handle = Arc::clone(&handle);
        let race_barrier = Arc::clone(&barrier);
        let race = std::thread::spawn(move || {
            race_barrier.wait();
            for _ in 0..128 {
                race_handle.abort_with_reason(CancelReason::race_loser());
            }
        });
        let shutdown_handle = Arc::clone(&handle);
        let shutdown_barrier = Arc::clone(&barrier);
        let shutdown = std::thread::spawn(move || {
            shutdown_barrier.wait();
            for _ in 0..128 {
                shutdown_handle.abort_with_reason(CancelReason::shutdown());
            }
        });
        barrier.wait();
        race.join().expect("RaceLost abort thread completes");
        shutdown.join().expect("Shutdown abort thread completes");

        let mut handle = Arc::try_unwrap(handle).expect("abort threads release handle");
        drop(tx);
        let result = block_on(handle.join(&cx));
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::Shutdown,
                    ..
                }))
            ),
            "concurrent abort requests retain the strongest reason",
            "Err(JoinError::Cancelled(Shutdown))",
            format!("{result:?}")
        );
        crate::test_complete!("concurrent_pending_abort_requests_keep_strongest_reason");
    }

    #[test]
    fn join_future_repoll_after_success_fails_closed() {
        init_test("join_future_repoll_after_success_fails_closed");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(11, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        tx.send(&cx, Ok::<i32, JoinError>(7))
            .expect("send should succeed");

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let mut join = Box::pin(handle.join(&cx));
        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);

        let first = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(7))),
            "first poll yields successful join result",
            "Poll::Ready(Ok(7))",
            format!("{first:?}")
        );

        let second = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(JoinError::PolledAfterCompletion))),
            "terminal join repoll fails closed",
            "Poll::Ready(Err(JoinError::PolledAfterCompletion))",
            format!("{second:?}")
        );
        crate::test_complete!("join_future_repoll_after_success_fails_closed");
    }

    #[test]
    fn join_future_repoll_after_cancelled_result_fails_closed() {
        init_test("join_future_repoll_after_cancelled_result_fails_closed");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(12, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        tx.send(
            &cx,
            Err::<i32, JoinError>(JoinError::Cancelled(CancelReason::race_loser())),
        )
        .expect("send should succeed");

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let mut join = Box::pin(handle.join(&cx));
        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);

        let first = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(
                first,
                Poll::Ready(Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::RaceLost,
                    ..
                })))
            ),
            "first poll preserves task cancellation result",
            "Poll::Ready(Err(JoinError::Cancelled(RaceLost)))",
            format!("{first:?}")
        );

        let second = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(JoinError::PolledAfterCompletion))),
            "cancelled join repoll fails closed",
            "Poll::Ready(Err(JoinError::PolledAfterCompletion))",
            format!("{second:?}")
        );
        crate::test_complete!("join_future_repoll_after_cancelled_result_fails_closed");
    }

    #[test]
    fn join_future_repoll_after_closed_channel_fails_closed() {
        init_test("join_future_repoll_after_closed_channel_fails_closed");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(13, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        drop(tx);

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));
        let mut join = Box::pin(handle.join(&cx));
        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);

        let first = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Err(JoinError::Cancelled(_)))),
            "closed join still maps to cancelled on first poll",
            "Poll::Ready(Err(JoinError::Cancelled(_)))",
            format!("{first:?}")
        );

        let second = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(JoinError::PolledAfterCompletion))),
            "closed join repoll fails closed",
            "Poll::Ready(Err(JoinError::PolledAfterCompletion))",
            format!("{second:?}")
        );
        crate::test_complete!("join_future_repoll_after_closed_channel_fails_closed");
    }

    #[test]
    fn defuse_drop_abort_skips_pending_join_abort() {
        init_test("defuse_drop_abort_skips_pending_join_abort");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(14, 0));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));

        let mut join = handle.join(&cx);
        join.defuse_drop_abort();
        drop(join);

        let (cancel_requested, cancel_reason_is_none) = {
            let guard = cx.inner.read();
            (guard.cancel_requested, guard.cancel_reason.is_none())
        };
        crate::assert_with_log!(
            !cancel_requested,
            "defused pending join drop must not request cancellation",
            false,
            cancel_requested
        );
        crate::assert_with_log!(
            cancel_reason_is_none,
            "defused pending join drop must not stamp cancel reason",
            true,
            cancel_reason_is_none
        );
        crate::test_complete!("defuse_drop_abort_skips_pending_join_abort");
    }

    #[test]
    fn drop_join_with_weaker_reason_preserves_stronger_existing_cancel_reason() {
        init_test("drop_join_with_weaker_reason_preserves_stronger_existing_cancel_reason");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(14, 1));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));

        handle.abort_with_reason(CancelReason::timeout());
        drop(handle.join_with_drop_reason(&cx, CancelReason::user("race cleanup")));

        let guard = cx.inner.read();
        let reason = guard
            .cancel_reason
            .clone()
            .expect("drop join should leave existing cancel reason intact");
        crate::assert_with_log!(
            guard.cancel_requested,
            "drop join still marks cancellation requested",
            true,
            guard.cancel_requested
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "weaker drop reason must not downgrade existing timeout cancel reason",
            CancelKind::Timeout,
            reason.kind
        );

        crate::test_complete!(
            "drop_join_with_weaker_reason_preserves_stronger_existing_cancel_reason"
        );
    }

    #[test]
    fn drop_join_with_stronger_reason_strengthens_existing_cancel_reason() {
        init_test("drop_join_with_stronger_reason_strengthens_existing_cancel_reason");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(14, 2));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));

        handle.abort_with_reason(CancelReason::user("soft stop"));
        drop(handle.join_with_drop_reason(&cx, CancelReason::timeout()));

        let guard = cx.inner.read();
        let reason = guard
            .cancel_reason
            .clone()
            .expect("drop join should strengthen existing cancel reason");
        crate::assert_with_log!(
            guard.cancel_requested,
            "drop join marks cancellation requested",
            true,
            guard.cancel_requested
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "stronger drop reason must upgrade existing cancel reason",
            CancelKind::Timeout,
            reason.kind
        );

        crate::test_complete!("drop_join_with_stronger_reason_strengthens_existing_cancel_reason");
    }

    // =========================================================================
    // Wave 27: Data-type trait coverage
    // =========================================================================

    #[test]
    fn join_error_debug_cancelled() {
        let err = JoinError::Cancelled(CancelReason::user("test"));
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Cancelled"));
    }

    #[test]
    fn join_error_debug_panicked() {
        let err = JoinError::Panicked(PanicPayload::new("oops"));
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Panicked"));
    }

    #[test]
    fn join_error_debug_polled_after_completion() {
        let err = JoinError::PolledAfterCompletion;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PolledAfterCompletion"));
    }

    #[test]
    fn join_error_clone() {
        let err = JoinError::Cancelled(CancelReason::timeout());
        let err2 = err.clone();
        assert_eq!(err, err2);
    }

    #[test]
    fn join_error_eq() {
        let a = JoinError::Cancelled(CancelReason::user("a"));
        let b = JoinError::Cancelled(CancelReason::user("a"));
        assert_eq!(a, b);

        let c = JoinError::Panicked(PanicPayload::new("x"));
        assert_ne!(a, c);
    }

    #[test]
    fn join_error_is_std_error() {
        let err: &dyn std::error::Error = &JoinError::Cancelled(CancelReason::user("e"));
        // std::error::Error requires Display + Debug
        let _ = format!("{err}");
        let _ = format!("{err:?}");
    }

    #[test]
    fn task_handle_debug() {
        let task_id = TaskId::from_arena(ArenaIndex::new(5, 0));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let dbg = format!("{handle:?}");
        assert!(dbg.contains("TaskHandle"));
    }

    #[test]
    fn try_join_not_ready() {
        let task_id = TaskId::from_arena(ArenaIndex::new(20, 0));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let result = handle.try_join();
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn try_join_ready() {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(21, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        tx.send(&cx, Ok(99)).expect("send");
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let first = handle.try_join();
        assert_eq!(first.unwrap(), Some(99));
        assert!(handle.terminal_consumed_for_test());

        let second = handle.try_join();
        assert!(matches!(second, Err(JoinError::PolledAfterCompletion)));
    }

    #[test]
    fn try_join_closed_channel() {
        let task_id = TaskId::from_arena(ArenaIndex::new(22, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        drop(tx);
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let first = handle.try_join();
        assert!(matches!(first, Err(JoinError::Cancelled(_))));
        assert!(handle.terminal_consumed_for_test());

        let second = handle.try_join();
        assert!(matches!(second, Err(JoinError::PolledAfterCompletion)));
    }

    #[test]
    fn try_join_after_join_completion_fails_closed() {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(23, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        tx.send(&cx, Ok(123)).expect("send");
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        let result = block_on(handle.join(&cx));
        assert_eq!(result.unwrap(), 123);
        assert!(handle.terminal_consumed_for_test());

        let second = handle.try_join();
        assert!(matches!(second, Err(JoinError::PolledAfterCompletion)));
    }

    #[test]
    fn task_handle_snapshot_scrubs_ids() {
        init_test("task_handle_snapshot_scrubs_ids");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(24, 4));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        let pending = task_handle_snapshot(&handle);
        tx.send(&cx, Ok(7)).expect("send");
        let joined = handle.try_join();
        assert_eq!(joined, Ok(Some(7)));
        let consumed = task_handle_snapshot(&handle);

        insta::assert_json_snapshot!(
            "task_handle_scrubbed_ids",
            scrub_task_handle_ids(json!({
                "pending": pending,
                "consumed": consumed,
            }))
        );
        crate::test_complete!("task_handle_snapshot_scrubs_ids");
    }
}
