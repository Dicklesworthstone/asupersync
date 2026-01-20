//! Stored task type for runtime future storage.
//!
//! `StoredTask` wraps a type-erased future that can be polled by the executor.
//! Each stored task is associated with a `TaskId` and can be polled to completion.

use crate::tracing_compat::trace;
use crate::types::TaskId;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A type-erased future stored in the runtime.
///
/// This type holds a boxed future that has been wrapped to send its result
/// through a oneshot channel. The actual output type is erased to allow
/// storing heterogeneous futures in a single collection.
pub struct StoredTask {
    /// The pinned, boxed future to poll.
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
    /// The task ID (for tracing).
    task_id: Option<TaskId>,
    /// Poll counter (for tracing).
    poll_count: u64,
}

impl StoredTask {
    /// Creates a new stored task from a future.
    ///
    /// The future should already be wrapped to handle its result (typically
    /// by sending through a oneshot channel).
    pub fn new<F>(future: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Self {
            future: Box::pin(future),
            task_id: None,
            poll_count: 0,
        }
    }

    /// Creates a new stored task from a future with a task ID.
    ///
    /// The task ID is used for tracing poll events.
    pub fn new_with_id<F>(future: F, task_id: TaskId) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Self {
            future: Box::pin(future),
            task_id: Some(task_id),
            poll_count: 0,
        }
    }

    /// Sets the task ID for tracing.
    pub fn set_task_id(&mut self, task_id: TaskId) {
        self.task_id = Some(task_id);
    }

    /// Polls the stored task.
    ///
    /// Returns `Poll::Ready(())` when the task is complete, or `Poll::Pending`
    /// if it needs to be polled again.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.poll_count += 1;
        let _poll_number = self.poll_count;

        if let Some(_task_id) = self.task_id {
            trace!(
                task_id = ?_task_id,
                poll_number = _poll_number,
                "task poll started"
            );
        }

        let result = self.future.as_mut().poll(cx);

        if let Some(_task_id) = self.task_id {
            let _poll_result = match &result {
                Poll::Ready(()) => "Ready",
                Poll::Pending => "Pending",
            };
            trace!(
                task_id = ?_task_id,
                poll_number = _poll_number,
                poll_result = _poll_result,
                "task poll completed"
            );
        }

        result
    }

    /// Returns the number of times this task has been polled.
    #[must_use]
    pub fn poll_count(&self) -> u64 {
        self.poll_count
    }
}

impl std::fmt::Debug for StoredTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredTask").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn init_test(test_name: &str) {
        init_test_logging();
        crate::test_phase!(test_name);
    }

    #[test]
    fn stored_task_polls_to_completion() {
        init_test("stored_task_polls_to_completion");
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        let task = StoredTask::new(async move {
            completed_clone.store(true, Ordering::SeqCst);
        });

        let mut task = task;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Simple async block should complete immediately
        crate::test_section!("poll");
        let result = task.poll(&mut cx);
        let ready = matches!(result, Poll::Ready(()));
        crate::assert_with_log!(ready, "poll should complete immediately", true, ready);
        let completed_value = completed.load(Ordering::SeqCst);
        crate::assert_with_log!(
            completed_value,
            "completion flag should be set",
            true,
            completed_value
        );
        crate::test_complete!("stored_task_polls_to_completion");
    }

    #[test]
    fn stored_task_debug() {
        init_test("stored_task_debug");
        let task = StoredTask::new(async {});
        let debug = format!("{task:?}");
        let contains = debug.contains("StoredTask");
        crate::assert_with_log!(
            contains,
            "debug output should mention StoredTask",
            true,
            contains
        );
        crate::test_complete!("stored_task_debug");
    }
}
