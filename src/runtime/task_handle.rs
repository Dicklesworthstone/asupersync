//! TaskHandle for awaiting spawned task results.
//!
//! `TaskHandle<T>` is returned by spawn operations and allows the spawner
//! to await the task's result. Similar to tokio's `JoinHandle`.

use crate::channel::oneshot;
use crate::cx::Cx;
use crate::types::{CancelReason, CxInner, PanicPayload, TaskId};
use std::sync::{RwLock, Weak};

/// Error returned when joining a spawned task fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinError {
    /// The task was cancelled before completion.
    Cancelled(CancelReason),
    /// The task panicked.
    Panicked(PanicPayload),
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled(reason) => write!(f, "task was cancelled: {reason}"),
            Self::Panicked(payload) => write!(f, "task panicked: {payload}"),
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
/// If `join()` is cancelled, the handle can be retried. The task's result
/// will be available once the task completes.
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
        }
    }

    /// Returns the task ID of the spawned task.
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Returns true if the task's result is ready.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.receiver.is_ready()
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
    /// let handle = scope.spawn(&mut state, cx, async { 42 });
    /// match handle.join(cx).await {
    ///     Ok(value) => println!("Task returned: {value}"),
    ///     Err(JoinError::Cancelled(r)) => println!("Task was cancelled: {r}"),
    ///     Err(JoinError::Panicked(p)) => println!("Task panicked: {p}"),
    /// }
    /// ```
    #[must_use]
    pub fn join<'a>(&'a self, cx: &'a Cx) -> JoinFuture<'a, T> {
        JoinFuture {
            handle: self,
            inner: self.receiver.recv(cx),
        }
    }

    /// Attempts to get the task's result without waiting.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(result))` if the task has completed
    /// - `Ok(None)` if the task is still running
    /// - `Err(JoinError)` if the task was cancelled or panicked
    pub fn try_join(&self) -> Result<Option<T>, JoinError> {
        match self.receiver.try_recv() {
            Ok(result) => Ok(Some(result?)),
            Err(oneshot::TryRecvError::Empty) => Ok(None),
            Err(oneshot::TryRecvError::Closed) => {
                Err(JoinError::Cancelled(CancelReason::race_loser()))
            }
        }
    }

    /// Aborts the task (requests cancellation).
    ///
    /// This is a request - the task may not stop immediately. The task
    /// will observe the cancellation at its next checkpoint.
    pub fn abort(&self) {
        if let Some(inner) = self.inner.upgrade() {
            if let Ok(mut lock) = inner.write() {
                lock.cancel_requested = true;
            }
        }
    }
}

/// Future returned by [`TaskHandle::join`].
///
/// This future aborts the task if dropped before completion, ensuring correct
/// cleanup in races and timeouts.
pub struct JoinFuture<'a, T> {
    handle: &'a TaskHandle<T>,
    inner: oneshot::RecvFuture<'a, Result<T, JoinError>>,
}

impl<T> std::future::Future for JoinFuture<'_, T> {
    type Output = Result<T, JoinError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // JoinError needs to be mapped if recv fails with RecvError
        match std::pin::Pin::new(&mut self.inner).poll(cx) {
            std::task::Poll::Ready(Ok(res)) => std::task::Poll::Ready(res),
            std::task::Poll::Ready(Err(_)) => {
                std::task::Poll::Ready(Err(JoinError::Cancelled(CancelReason::race_loser())))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<T> Drop for JoinFuture<'_, T> {
    fn drop(&mut self) {
        // Abort the task if we stop waiting for it.
        // This makes TaskHandle::join cancel-safe and race-safe.
        self.handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::types::Budget;
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

        let handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
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

        let handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

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
            _ => panic!("expected Cancelled"),
        }
        crate::test_complete!("task_handle_cancelled");
    }

    #[test]
    fn task_handle_panicked() {
        init_test("task_handle_panicked");
        crate::test_section!("setup");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

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
            _ => panic!("expected Panicked"),
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
        crate::test_complete!("join_error_display");
    }
}
