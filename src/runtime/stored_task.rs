//! Stored task type for runtime future storage.
//!
//! `StoredTask` wraps a type-erased future that can be polled by the executor.
//! Each stored task is associated with a `TaskId` and can be polled to completion.

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
        }
    }

    /// Polls the stored task.
    ///
    /// Returns `Poll::Ready(())` when the task is complete, or `Poll::Pending`
    /// if it needs to be polled again.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.future.as_mut().poll(cx)
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

    #[test]
    fn stored_task_polls_to_completion() {
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        let task = StoredTask::new(async move {
            completed_clone.store(true, Ordering::SeqCst);
        });

        let mut task = task;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Simple async block should complete immediately
        let result = task.poll(&mut cx);
        assert!(matches!(result, Poll::Ready(())));
        assert!(completed.load(Ordering::SeqCst));
    }

    #[test]
    fn stored_task_debug() {
        let task = StoredTask::new(async {});
        let debug = format!("{task:?}");
        assert!(debug.contains("StoredTask"));
    }
}
