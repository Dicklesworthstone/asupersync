//! Stream adapters for channel receivers.
//!
//! These adapters provide a `Stream` view over channel receivers while
//! preserving Asupersync's explicit-capability model. A `Cx` is required
//! to perform receive operations.
//!
//! Phase 0 note: channel receive operations are currently blocking. These
//! adapters therefore block inside `poll_next` until a message arrives or
//! the channel closes. This will be replaced by non-blocking waker-based
//! integration in a later phase.

use crate::channel::mpsc;
use crate::channel::mpsc::RecvError;
use crate::cx::Cx;
use crate::stream::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream wrapper for `mpsc::Receiver`.
#[derive(Debug)]
pub struct ReceiverStream<T> {
    inner: mpsc::Receiver<T>,
    cx: Cx,
}

impl<T> ReceiverStream<T> {
    /// Creates a new stream wrapper with an explicit capability context.
    #[must_use]
    pub fn new(cx: Cx, inner: mpsc::Receiver<T>) -> Self {
        cx.trace("stream::ReceiverStream created");
        Self { inner, cx }
    }

    /// Returns a reference to the inner receiver.
    #[must_use]
    pub fn get_ref(&self) -> &mpsc::Receiver<T> {
        &self.inner
    }

    /// Returns a mutable reference to the inner receiver.
    pub fn get_mut(&mut self) -> &mut mpsc::Receiver<T> {
        &mut self.inner
    }

    /// Returns a reference to the capability context.
    #[must_use]
    pub fn cx(&self) -> &Cx {
        &self.cx
    }

    /// Unwraps the stream into the inner receiver.
    #[must_use]
    pub fn into_inner(self) -> mpsc::Receiver<T> {
        self.inner
    }
}

impl<T> Stream for ReceiverStream<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, poll_cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        // Poll the recv future using std::pin::pin! for safe pinning
        let recv_future = this.inner.recv(&this.cx);
        let mut pinned = std::pin::pin!(recv_future);
        match pinned.as_mut().poll(poll_cx) {
            Poll::Ready(Ok(item)) => {
                this.cx.trace("stream::ReceiverStream yielded item");
                Poll::Ready(Some(item))
            }
            Poll::Ready(Err(RecvError::Disconnected | RecvError::Cancelled)) => Poll::Ready(None),
            Poll::Ready(Err(RecvError::Empty)) | Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

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
    fn receiver_stream_reads_messages() {
        init_test("receiver_stream_reads_messages");
        let _cx_send = Cx::for_testing();
        let cx_recv = Cx::for_testing();
        let (tx, rx) = mpsc::channel(4);

        tx.try_send(1).expect("send 1");
        tx.try_send(2).expect("send 2");
        tx.try_send(3).expect("send 3");
        drop(tx);

        let mut stream = ReceiverStream::new(cx_recv, rx);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(1))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(3)));
        crate::assert_with_log!(ok, "poll 3", "Poll::Ready(Some(3))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("receiver_stream_reads_messages");
    }
}
