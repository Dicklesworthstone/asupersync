//! Stream adapter for broadcast receivers.

use crate::channel::broadcast;
use crate::cx::Cx;
use crate::stream::Stream;
use crate::util::ArenaIndex;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream wrapper for broadcast receiver.
#[derive(Debug)]
pub struct BroadcastStream<T> {
    inner: broadcast::Receiver<T>,
    cx: Cx,
    terminated: bool,
    waiter: Option<ArenaIndex>,
}

impl<T: Clone> BroadcastStream<T> {
    /// Creates a new broadcast stream from the receiver.
    #[must_use]
    pub fn new(cx: Cx, recv: broadcast::Receiver<T>) -> Self {
        Self {
            inner: recv,
            cx,
            terminated: false,
            waiter: None,
        }
    }
}

/// Error from broadcast stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastStreamRecvError {
    /// Lagged behind, some messages missed.
    Lagged(u64),
}

impl std::fmt::Display for BroadcastStreamRecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lagged(n) => write!(f, "lagged by {n} messages"),
        }
    }
}

impl std::error::Error for BroadcastStreamRecvError {}

impl<T: Clone + Send> Stream for BroadcastStream<T> {
    type Item = Result<T, BroadcastStreamRecvError>;

    fn poll_next(mut self: Pin<&mut Self>, poll_cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.as_ref().get_ref().terminated {
            return Poll::Ready(None);
        }

        let this = self.as_mut().get_mut();
        match this
            .inner
            .poll_recv_with_waiter(&this.cx, poll_cx, &mut this.waiter)
        {
            Poll::Ready(Ok(item)) => Poll::Ready(Some(Ok(item))),
            Poll::Ready(Err(broadcast::RecvError::Lagged(n))) => {
                Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(n))))
            }
            Poll::Ready(Err(
                broadcast::RecvError::Closed
                | broadcast::RecvError::Cancelled
                | broadcast::RecvError::PolledAfterCompletion,
            )) => {
                this.terminated = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> Drop for BroadcastStream<T> {
    fn drop(&mut self) {
        self.inner.clear_waiter_registration(&mut self.waiter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    struct CountWaker(Arc<AtomicUsize>);

    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker(counter: Arc<AtomicUsize>) -> Waker {
        Waker::from(Arc::new(CountWaker(counter)))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn broadcast_stream_none_is_terminal_after_cancel() {
        init_test("broadcast_stream_none_is_terminal_after_cancel");
        let cx_recv: Cx = Cx::for_testing();
        cx_recv.set_cancel_requested(true);
        let cx_send: Cx = Cx::for_testing();

        let (tx, rx) = broadcast::channel(4);
        let mut stream = BroadcastStream::new(cx_recv.clone(), rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let first_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(first_none, "first poll none", true, first_none);

        cx_recv.set_cancel_requested(false);
        tx.send(&cx_send, 11).expect("send after cancel clear");

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let still_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(still_none, "stream remains terminated", true, still_none);
        crate::test_complete!("broadcast_stream_none_is_terminal_after_cancel");
    }

    /// Invariant: broadcast stream delivers pre-sent messages via poll_next.
    #[test]
    fn broadcast_stream_receives_prefilled_messages() {
        init_test("broadcast_stream_receives_prefilled_messages");
        let cx_send: Cx = Cx::for_testing();
        let cx_recv: Cx = Cx::for_testing();

        let (tx, rx) = broadcast::channel(8);
        tx.send(&cx_send, 10).expect("send 10");
        tx.send(&cx_send, 20).expect("send 20");

        let mut stream = BroadcastStream::new(cx_recv, rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let got_10 = matches!(poll, Poll::Ready(Some(Ok(10))));
        crate::assert_with_log!(got_10, "received 10", true, got_10);

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let got_20 = matches!(poll, Poll::Ready(Some(Ok(20))));
        crate::assert_with_log!(got_20, "received 20", true, got_20);

        crate::test_complete!("broadcast_stream_receives_prefilled_messages");
    }

    /// Invariant: stream yields None after all senders are dropped.
    #[test]
    fn broadcast_stream_terminated_after_sender_drop() {
        init_test("broadcast_stream_terminated_after_sender_drop");
        let cx_send: Cx = Cx::for_testing();
        let cx_recv: Cx = Cx::for_testing();

        let (tx, rx) = broadcast::channel(4);
        tx.send(&cx_send, 42).expect("send");
        drop(tx);

        let mut stream = BroadcastStream::new(cx_recv, rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // First poll: should get the message.
        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let got_42 = matches!(poll, Poll::Ready(Some(Ok(42))));
        crate::assert_with_log!(got_42, "received 42", true, got_42);

        // Second poll: sender dropped, should terminate.
        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let is_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(is_none, "terminated after sender drop", true, is_none);

        crate::test_complete!("broadcast_stream_terminated_after_sender_drop");
    }

    #[test]
    fn broadcast_stream_pending_poll_keeps_waker_registration() {
        init_test("broadcast_stream_pending_poll_keeps_waker_registration");
        let cx_send: Cx = Cx::for_testing();
        let cx_recv: Cx = Cx::for_testing();
        let (tx, rx) = broadcast::channel::<i32>(4);
        let mut stream = BroadcastStream::new(cx_recv, rx);

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut task_cx);
        let first_pending = matches!(first, Poll::Pending);
        crate::assert_with_log!(first_pending, "first poll pending", true, first_pending);

        tx.send(&cx_send, 33).expect("send");
        let wake_total = wake_count.load(Ordering::SeqCst);
        crate::assert_with_log!(wake_total == 1, "single wake after send", 1, wake_total);

        let second = Pin::new(&mut stream).poll_next(&mut task_cx);
        let second_ready = matches!(second, Poll::Ready(Some(Ok(33))));
        crate::assert_with_log!(second_ready, "second poll has item", true, second_ready);

        crate::test_complete!("broadcast_stream_pending_poll_keeps_waker_registration");
    }

    /// Invariant: BroadcastStreamRecvError::Lagged preserves the count and implements Display/Error.
    #[test]
    fn broadcast_stream_recv_error_lagged_preserves_count() {
        init_test("broadcast_stream_recv_error_lagged_preserves_count");

        let err = BroadcastStreamRecvError::Lagged(42);
        let is_lagged = matches!(err, BroadcastStreamRecvError::Lagged(42));
        crate::assert_with_log!(is_lagged, "lagged(42)", true, is_lagged);

        // Clone and Eq
        let cloned = err.clone();
        let eq = err == cloned;
        crate::assert_with_log!(eq, "clone eq", true, eq);

        // Debug
        let dbg = format!("{err:?}");
        let has_42 = dbg.contains("42");
        crate::assert_with_log!(has_42, "debug contains count", true, has_42);

        // Display
        let disp = format!("{err}");
        let disp_has_42 = disp.contains("lagged by 42 messages");
        crate::assert_with_log!(disp_has_42, "display contains message", true, disp_has_42);

        // Error trait
        let e: &dyn std::error::Error = &err;
        crate::assert_with_log!(
            e.source().is_none(),
            "no source",
            true,
            e.source().is_none()
        );

        crate::test_complete!("broadcast_stream_recv_error_lagged_preserves_count");
    }
}
