//! Stream adapter for watch receivers.

use crate::channel::watch;
use crate::cx::Cx;
use crate::stream::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream that yields when watch value changes.
#[derive(Debug)]
pub struct WatchStream<T> {
    inner: watch::Receiver<T>,
    cx: Cx,
    has_seen_initial: bool,
    terminated: bool,
}

impl<T: Clone> WatchStream<T> {
    /// Create from watch receiver.
    #[must_use]
    pub fn new(cx: Cx, recv: watch::Receiver<T>) -> Self {
        Self {
            inner: recv,
            cx,
            has_seen_initial: false,
            terminated: false,
        }
    }

    /// Create, skipping the initial value.
    #[must_use]
    pub fn from_changes(cx: Cx, recv: watch::Receiver<T>) -> Self {
        let mut stream = Self::new(cx, recv);
        // Skip whatever value/version is current at construction time.
        stream.inner.mark_seen();
        stream.has_seen_initial = true;
        stream
    }
}

impl<T: Clone + Send + Sync> Stream for WatchStream<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.terminated {
            return Poll::Ready(None);
        }

        // First poll: return current value immediately
        if !this.has_seen_initial {
            this.has_seen_initial = true;
            // The initial snapshot counts as observed by this stream.
            this.inner.mark_seen();
            return Poll::Ready(Some(this.inner.borrow_and_clone()));
        }

        // Poll the changed future (non-blocking, waker-based)
        let runtime_cx = this.cx.clone();
        let result = {
            let mut future = this.inner.changed(&runtime_cx);
            Pin::new(&mut future).poll(context)
        };
        match result {
            Poll::Ready(Ok(())) => Poll::Ready(Some(this.inner.borrow_and_clone())),
            Poll::Ready(Err(_)) => {
                this.terminated = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Context, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn watch_stream_none_is_terminal_after_cancel() {
        init_test("watch_stream_none_is_terminal_after_cancel");
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let (tx, rx) = watch::channel(0);
        let mut stream = WatchStream::from_changes(cx.clone(), rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let first_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(first_none, "first poll none", true, first_none);

        cx.set_cancel_requested(false);
        let send_result = tx.send(1);
        crate::assert_with_log!(
            send_result.is_ok(),
            "send after cancel clear succeeds",
            true,
            send_result.is_ok()
        );

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let still_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(still_none, "stream remains terminated", true, still_none);
        crate::test_complete!("watch_stream_none_is_terminal_after_cancel");
    }

    #[test]
    fn watch_stream_initial_snapshot_does_not_duplicate_pending_update() {
        init_test("watch_stream_initial_snapshot_does_not_duplicate_pending_update");
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = watch::channel(0);
        let send_result = tx.send(1);
        crate::assert_with_log!(
            send_result.is_ok(),
            "pre-send should succeed",
            true,
            send_result.is_ok()
        );

        let mut stream = WatchStream::new(cx, rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut task_cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Some(1))),
            "first poll returns latest snapshot once",
            "Ready(Some(1))",
            format!("{first:?}")
        );

        let second = Pin::new(&mut stream).poll_next(&mut task_cx);
        crate::assert_with_log!(
            second.is_pending(),
            "second poll waits for a new change",
            true,
            second.is_pending()
        );
        crate::test_complete!("watch_stream_initial_snapshot_does_not_duplicate_pending_update");
    }

    #[test]
    fn watch_stream_from_changes_skips_current_value() {
        init_test("watch_stream_from_changes_skips_current_value");
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = watch::channel(0);
        let send_result = tx.send(1);
        crate::assert_with_log!(
            send_result.is_ok(),
            "pre-send should succeed",
            true,
            send_result.is_ok()
        );

        let mut stream = WatchStream::from_changes(cx, rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut task_cx);
        crate::assert_with_log!(
            first.is_pending(),
            "from_changes skips current value",
            true,
            first.is_pending()
        );

        let send_result = tx.send(2);
        crate::assert_with_log!(
            send_result.is_ok(),
            "second send should succeed",
            true,
            send_result.is_ok()
        );
        let second = Pin::new(&mut stream).poll_next(&mut task_cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Some(2))),
            "next change is yielded",
            "Ready(Some(2))",
            format!("{second:?}")
        );
        crate::test_complete!("watch_stream_from_changes_skips_current_value");
    }
}
