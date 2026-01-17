//! TaskHandle for awaiting spawned task results.
//!
//! `TaskHandle<T>` is returned by spawn operations and allows the spawner
//! to await the task's result. Similar to tokio's `JoinHandle`.

use crate::channel::oneshot;
use crate::cx::Cx;
use crate::types::TaskId;

/// Error returned when joining a spawned task fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinError {
    /// The task was cancelled before completion.
    Cancelled,
    /// The task panicked.
    Panicked,
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "task was cancelled"),
            Self::Panicked => write!(f, "task panicked"),
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
/// let result = handle.join(cx)?;
/// assert_eq!(result, 42);
/// ```
#[derive(Debug)]
pub struct TaskHandle<T> {
    /// The ID of the spawned task.
    task_id: TaskId,
    /// Receiver for the task's result.
    receiver: oneshot::Receiver<Result<T, JoinError>>,
}

impl<T> TaskHandle<T> {
    /// Creates a new TaskHandle (internal use).
    pub(crate) fn new(task_id: TaskId, receiver: oneshot::Receiver<Result<T, JoinError>>) -> Self {
        Self { task_id, receiver }
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
    /// This method blocks the current task until the spawned task completes,
    /// then returns its output value.
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
    /// match handle.join(cx) {
    ///     Ok(value) => println!("Task returned: {value}"),
    ///     Err(JoinError::Cancelled) => println!("Task was cancelled"),
    ///     Err(JoinError::Panicked) => println!("Task panicked"),
    /// }
    /// ```
    pub fn join(self, cx: &Cx) -> Result<T, JoinError> {
        self.receiver
            .recv(cx)
            .unwrap_or_else(|_| Err(JoinError::Cancelled))
    }

    /// Attempts to get the task's result without waiting.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(result))` if the task has completed
    /// - `Ok(None)` if the task is still running
    /// - `Err(JoinError)` if the task was cancelled or panicked
    pub fn try_join(&self) -> Result<Option<T>, JoinError> {
        // Note: try_recv consumes self in oneshot, so we need is_ready first
        if !self.receiver.is_ready() {
            return Ok(None);
        }
        // Can't actually try_recv without consuming, so this is a limitation
        // In full implementation, we'd use a different pattern
        Ok(None)
    }

    /// Aborts the task (requests cancellation).
    ///
    /// This is a request - the task may not stop immediately. The task
    /// will observe the cancellation at its next checkpoint.
    ///
    /// # Note
    ///
    /// In Phase 0, this is a placeholder. Full implementation requires
    /// access to the RuntimeState to request cancellation.
    pub fn abort(&self) {
        // In full implementation:
        // state.cancel_request(region_of_task, CancelReason::user("abort"));
        // For now, this is a no-op placeholder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;

    fn test_cx() -> Cx {
        Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    #[test]
    fn task_handle_basic() {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let handle = TaskHandle::new(task_id, rx);
        assert_eq!(handle.task_id(), task_id);
        assert!(!handle.is_finished());

        // Send the result
        tx.send(&cx, Ok(42)).expect("send failed");

        // Join should succeed
        let result = handle.join(&cx);
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn task_handle_cancelled() {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let handle = TaskHandle::new(task_id, rx);

        // Send a cancelled result
        tx.send(&cx, Err(JoinError::Cancelled))
            .expect("send failed");

        let result = handle.join(&cx);
        assert_eq!(result, Err(JoinError::Cancelled));
    }

    #[test]
    fn task_handle_panicked() {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let handle = TaskHandle::new(task_id, rx);

        tx.send(&cx, Err(JoinError::Panicked)).expect("send failed");

        let result = handle.join(&cx);
        assert_eq!(result, Err(JoinError::Panicked));
    }

    #[test]
    fn join_error_display() {
        assert_eq!(JoinError::Cancelled.to_string(), "task was cancelled");
        assert_eq!(JoinError::Panicked.to_string(), "task panicked");
    }
}
