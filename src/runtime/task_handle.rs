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
    /// If this method is cancelled while waiting, the handle can be retried.
    /// The spawned task continues executing regardless.
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
    pub async fn join(&self, cx: &Cx) -> Result<T, JoinError> {
        self.receiver
            .recv(cx)
            .await
            .unwrap_or_else(|_| Err(JoinError::Cancelled(CancelReason::race_loser())))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

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
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        assert_eq!(handle.task_id(), task_id);
        assert!(!handle.is_finished());

        // Send the result
        tx.send(&cx, Ok::<i32, JoinError>(42)).expect("send failed");

        // Join should succeed
        let result = block_on(handle.join(&cx));
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn task_handle_cancelled() {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        // Send a cancelled result
        tx.send(
            &cx,
            Err::<i32, JoinError>(JoinError::Cancelled(CancelReason::race_loser())),
        )
        .expect("send failed");

        let result = block_on(handle.join(&cx));
        match result {
            Err(JoinError::Cancelled(r)) => {
                assert!(matches!(r.kind, crate::types::CancelKind::RaceLost));
            }
            _ => panic!("expected Cancelled"),
        }
    }

    #[test]
    fn task_handle_panicked() {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        tx.send(
            &cx,
            Err::<i32, JoinError>(JoinError::Panicked(PanicPayload::new("boom"))),
        )
        .expect("send failed");

        let result = block_on(handle.join(&cx));
        match result {
            Err(JoinError::Panicked(p)) => {
                assert!(p.to_string().contains("boom"));
            }
            _ => panic!("expected Panicked"),
        }
    }

    #[test]
    fn join_error_display() {
        let cancelled = JoinError::Cancelled(CancelReason::user("stop"));
        assert!(cancelled.to_string().contains("task was cancelled"));
        assert!(cancelled.to_string().contains("stop"));

        let panicked = JoinError::Panicked(PanicPayload::new("crash"));
        assert!(panicked.to_string().contains("task panicked"));
        assert!(panicked.to_string().contains("crash"));
    }
}
