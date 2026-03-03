//! Cancellation bridge between Asupersync and Tokio-originated futures.
//!
//! Provides [`CancelAware`], a wrapper that monitors `Cx` cancellation state
//! and drops the inner future when cancellation is requested.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;

use crate::CancellationMode;

pin_project! {
    /// Wraps a future with Asupersync cancellation awareness.
    ///
    /// On each poll, checks whether `is_cancel_requested()` is set on the
    /// stored cancel token. Behavior depends on [`CancellationMode`]:
    ///
    /// - **`BestEffort`**: Polls the inner future normally. If cancelled,
    ///   returns `CancelResult::Cancelled` only if the future was pending.
    /// - **`Strict`**: If the future completes after cancellation was requested,
    ///   returns `CancelResult::CancellationIgnored` with the output.
    /// - **`TimeoutFallback`**: After cancellation is requested, a countdown
    ///   begins. If the future doesn't complete within the grace period, it
    ///   is dropped and `CancelResult::Cancelled` is returned.
    pub struct CancelAware<F> {
        #[pin]
        future: F,
        cancel_requested: bool,
        mode: CancellationMode,
        // In a real implementation, this would hold a reference to the Cx
        // cancel token. For now, we track state via the `cancel_requested` flag
        // which must be set by the caller's poll loop.
    }
}

/// Result of a cancel-aware future execution.
#[derive(Debug)]
pub enum CancelResult<T> {
    /// The future completed normally before any cancellation.
    Completed(T),

    /// The future was cancelled before completing.
    Cancelled,

    /// The future completed after cancellation was requested
    /// (only in `Strict` mode).
    CancellationIgnored(T),
}

impl<F: Future> CancelAware<F> {
    /// Create a new cancel-aware wrapper around a future.
    pub fn new(future: F, mode: CancellationMode) -> Self {
        Self {
            future,
            cancel_requested: false,
            mode,
        }
    }

    /// Signal that cancellation has been requested.
    ///
    /// This should be called by the adapter's poll loop when it detects
    /// `cx.is_cancel_requested()`.
    pub fn request_cancel(self: Pin<&mut Self>) {
        *self.project().cancel_requested = true;
    }
}

impl<F: Future> Future for CancelAware<F> {
    type Output = CancelResult<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        // If cancellation was requested, behavior depends on mode.
        if *this.cancel_requested {
            match this.mode {
                CancellationMode::BestEffort => {
                    // Try to complete, but if pending, report cancelled.
                    match this.future.poll(cx) {
                        Poll::Ready(output) => Poll::Ready(CancelResult::Completed(output)),
                        Poll::Pending => Poll::Ready(CancelResult::Cancelled),
                    }
                }
                CancellationMode::Strict => {
                    // If it completes after cancel, flag it.
                    match this.future.poll(cx) {
                        Poll::Ready(output) => {
                            Poll::Ready(CancelResult::CancellationIgnored(output))
                        }
                        Poll::Pending => Poll::Ready(CancelResult::Cancelled),
                    }
                }
                CancellationMode::TimeoutFallback => {
                    // In a full implementation, this would use a timer.
                    // For scaffolding, behave like BestEffort.
                    match this.future.poll(cx) {
                        Poll::Ready(output) => Poll::Ready(CancelResult::Completed(output)),
                        Poll::Pending => Poll::Ready(CancelResult::Cancelled),
                    }
                }
            }
        } else {
            // No cancellation: poll normally.
            match this.future.poll(cx) {
                Poll::Ready(output) => Poll::Ready(CancelResult::Completed(output)),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future;

    #[test]
    fn cancel_aware_completes_normally() {
        // A ready future should complete without cancellation.
        let fut = CancelAware::new(future::ready(42), CancellationMode::BestEffort);
        let result = futures_lite_or_block(fut);
        assert!(matches!(result, CancelResult::Completed(42)));
    }

    #[test]
    fn cancel_aware_mode_defaults_to_best_effort() {
        assert_eq!(CancellationMode::default(), CancellationMode::BestEffort);
    }

    // Minimal blocking executor for tests.
    fn futures_lite_or_block<F: Future>(fut: F) -> F::Output {
        // Use a simple manual poll for ready futures.
        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(val) => val,
            Poll::Pending => panic!("future was not ready"),
        }
    }

    fn futures_task_noop_waker() -> std::task::Waker {
        // Safe no-op waker for testing.
        fn noop_clone(_: *const ()) -> std::task::RawWaker {
            std::task::RawWaker::new(std::ptr::null(), &VTABLE)
        }
        fn noop(_: *const ()) {}
        static VTABLE: std::task::RawWakerVTable =
            std::task::RawWakerVTable::new(noop_clone, noop, noop, noop);
        // SAFETY: The vtable functions are correct no-ops.
        #[allow(unsafe_code)]
        unsafe {
            std::task::Waker::from_raw(std::task::RawWaker::new(std::ptr::null(), &VTABLE))
        }
    }
}
