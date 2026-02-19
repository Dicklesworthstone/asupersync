//! Stream adapter for broadcast receivers.

use crate::channel::broadcast;
use crate::cx::Cx;
use crate::stream::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream wrapper for broadcast receiver.
#[derive(Debug)]
pub struct BroadcastStream<T> {
    inner: broadcast::Receiver<T>,
    cx: Cx,
    terminated: bool,
}

impl<T: Clone> BroadcastStream<T> {
    /// Creates a new broadcast stream from the receiver.
    #[must_use]
    pub fn new(cx: Cx, recv: broadcast::Receiver<T>) -> Self {
        Self {
            inner: recv,
            cx,
            terminated: false,
        }
    }
}

/// Error from broadcast stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastStreamRecvError {
    /// Lagged behind, some messages missed.
    Lagged(u64),
}

impl<T: Clone + Send> Stream for BroadcastStream<T> {
    type Item = Result<T, BroadcastStreamRecvError>;

    fn poll_next(mut self: Pin<&mut Self>, poll_cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.as_ref().get_ref().terminated {
            return Poll::Ready(None);
        }

        let this = self.as_mut().get_mut();
        // Poll within an inner scope so the borrow from recv() is released
        // before we potentially update termination state.
        let poll = {
            let recv_future = this.inner.recv(&this.cx);
            let mut pinned = std::pin::pin!(recv_future);
            pinned.as_mut().poll(poll_cx)
        };
        match poll {
            Poll::Ready(Ok(item)) => Poll::Ready(Some(Ok(item))),
            Poll::Ready(Err(broadcast::RecvError::Lagged(n))) => {
                Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(n))))
            }
            Poll::Ready(Err(broadcast::RecvError::Closed | broadcast::RecvError::Cancelled)) => {
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

    /// Invariant: BroadcastStreamRecvError::Lagged preserves the count.
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

        crate::test_complete!("broadcast_stream_recv_error_lagged_preserves_count");
    }
}
