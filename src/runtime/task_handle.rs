//! TaskHandle for awaiting spawned task results.
//!
//! `TaskHandle<T>` is returned by spawn operations and allows the spawner
//! to await the task's result. Similar to join handles in other runtimes.

use crate::channel::oneshot;
use crate::cx::Cx;
use crate::types::{CancelReason, CxInner, PanicPayload, TaskId};
use parking_lot::RwLock;
use std::sync::Weak;

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
/// `TaskHandle<T>` is returned by `Scope::spawn()` and related methods.
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
/// let handle = scope.spawn(&mut state, cx, async { 42 });
/// let result = handle.join(cx).await?;
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
    /// Whether this handle already consumed a terminal join result.
    terminal_consumed: bool,
}

impl<T> TaskHandle<T> {
    /// Creates a new TaskHandle (internal use).
    pub(crate) fn new(
        task_id: TaskId,
        receiver: oneshot::Receiver<Result<T, JoinError>>,
        inner: Weak<RwLock<CxInner>>,
    ) -> Self {
        Self {
            task_id,
            receiver,
            inner,
            terminal_consumed: false,
        }
    }

    /// Returns the task ID of the spawned task.
    #[inline]
    #[must_use]
    pub fn task_id(&self) -> TaskId {
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
    /// let mut handle = scope.spawn(&mut state, cx, async { 42 });
    /// match handle.join(cx).await {
    ///     Ok(value) => println!("Task returned: {value}"),
    ///     Err(JoinError::Cancelled(r)) => println!("Task was cancelled: {r}"),
    ///     Err(JoinError::Panicked(p)) => println!("Task panicked: {p}"),
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn join<'a>(&'a mut self, _cx: &'a Cx) -> JoinFuture<'a, T> {
        let cx_inner = self.inner.clone();
        let receiver = &mut self.receiver;
        let terminal_state = &mut self.terminal_consumed;
        JoinFuture {
            inner: receiver.recv_uninterruptible(),
            cx_inner,
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
        let cx_inner = self.inner.clone();
        let receiver = &mut self.receiver;
        let terminal_state = &mut self.terminal_consumed;
        JoinFuture {
            inner: receiver.recv_uninterruptible(),
            cx_inner,
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
                result.map(Some)
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
    #[inline]
    pub fn abort_with_reason(&self, reason: CancelReason) {
        if let Some(inner) = self.inner.upgrade() {
            let cancel_waker = {
                let mut lock = inner.write();
                lock.cancel_requested = true;
                lock.fast_cancel
                    .store(true, std::sync::atomic::Ordering::Release);
                if let Some(existing) = &mut lock.cancel_reason {
                    existing.strengthen(&reason);
                } else {
                    lock.cancel_reason = Some(reason);
                }
                lock.cancel_waker.clone()
            };
            if let Some(waker) = cancel_waker {
                waker.wake_by_ref();
            }
        }
    }

    #[inline]
    fn closed_reason(&self) -> CancelReason {
        self.inner
            .upgrade()
            .and_then(|inner| inner.read().cancel_reason.clone())
            .unwrap_or_else(|| CancelReason::user("join channel closed"))
    }
}

/// Future returned by [`TaskHandle::join`].
///
/// This future aborts the task if dropped before completion, ensuring correct
/// cleanup in races and timeouts.
pub struct JoinFuture<'a, T> {
    inner: oneshot::RecvUninterruptibleFuture<'a, Result<T, JoinError>>,
    cx_inner: Weak<RwLock<CxInner>>,
    terminal_state: &'a mut bool,
    drop_abort_defused: bool,
    drop_reason: Option<CancelReason>,
}

impl<T> JoinFuture<'_, T> {
    fn closed_reason(&self) -> CancelReason {
        self.cx_inner
            .upgrade()
            .and_then(|inner| inner.read().cancel_reason.clone())
            .unwrap_or_else(|| CancelReason::user("join channel closed"))
    }

    fn abort_with_reason(&self, reason: CancelReason) {
        if let Some(inner) = self.cx_inner.upgrade() {
            let cancel_waker = {
                let mut lock = inner.write();
                lock.cancel_requested = true;
                lock.fast_cancel
                    .store(true, std::sync::atomic::Ordering::Release);
                if let Some(existing) = &mut lock.cancel_reason {
                    existing.strengthen(&reason);
                } else {
                    lock.cancel_reason = Some(reason);
                }
                lock.cancel_waker.clone()
            };
            if let Some(waker) = cancel_waker {
                waker.wake_by_ref();
            }
        }
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
                std::task::Poll::Ready(res)
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
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::types::{Budget, CancelKind};
    use crate::util::ArenaIndex;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx() -> Cx {
        Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = Waker::from(std::sync::Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
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
}
