//! Stream adapters for channel receivers.
//!
//! These adapters provide a `Stream` view over channel receivers while
//! preserving Asupersync's explicit-capability model. A `Cx` is required
//! to perform receive operations.
//!
//! `poll_next` never blocks the thread: it registers the task's waker with
//! the receiver and returns `Pending` until a message arrives. The stream
//! ends (`None`) when the channel is closed and drained, and also when the
//! adapter's `Cx` is cancelled. A consumer that must tell the two apart
//! checks `cx.is_cancel_requested()` after the stream ends; on cancellation
//! the messages still queued stay in the receiver, which
//! [`ReceiverStream::into_inner`] returns.

use crate::channel::mpsc::RecvError;
use crate::channel::{OwnedCancelRegistration, mpsc};
use crate::cx::Cx;
use crate::stream::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream wrapper for `mpsc::Receiver`.
#[derive(Debug)]
pub struct ReceiverStream<T> {
    inner: mpsc::Receiver<T>,
    cx: OwnedCancelRegistration,
    terminated: bool,
}

impl<T> ReceiverStream<T> {
    /// Creates a new stream wrapper with an explicit capability context.
    #[inline]
    #[must_use]
    pub fn new(cx: Cx, inner: mpsc::Receiver<T>) -> Self {
        cx.trace("stream::ReceiverStream created");
        Self {
            inner,
            cx: OwnedCancelRegistration::new(cx),
            terminated: false,
        }
    }

    /// Returns a reference to the inner receiver.
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &mpsc::Receiver<T> {
        &self.inner
    }

    /// Returns a mutable reference to the inner receiver.
    #[inline]
    pub fn get_mut(&mut self) -> &mut mpsc::Receiver<T> {
        self.inner.clear_recv_waker();
        self.cx.clear();
        &mut self.inner
    }

    /// Returns a reference to the capability context.
    #[inline]
    #[must_use]
    pub fn cx(&self) -> &Cx {
        self.cx.cx()
    }

    /// Unwraps the stream into the inner receiver.
    #[inline]
    #[must_use]
    pub fn into_inner(mut self) -> mpsc::Receiver<T> {
        self.inner.clear_recv_waker();
        self.cx.clear();
        self.inner
    }
}

impl<T> Stream for ReceiverStream<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, poll_cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.terminated {
            return Poll::Ready(None);
        }

        let mut result = this.inner.poll_recv(this.cx.cx(), poll_cx);
        if matches!(&result, Poll::Pending | Poll::Ready(Err(RecvError::Empty))) {
            this.cx.refresh(poll_cx.waker());
            if this.cx.cx().is_cancel_requested() {
                result = this.inner.poll_recv(this.cx.cx(), poll_cx);
            }
        }
        match result {
            Poll::Ready(Ok(item)) => {
                this.cx.clear();
                this.cx.cx().trace("stream::ReceiverStream yielded item");
                Poll::Ready(Some(item))
            }
            Poll::Ready(Err(RecvError::Disconnected | RecvError::Cancelled)) => {
                this.terminated = true;
                this.cx.clear();
                Poll::Ready(None)
            }
            Poll::Ready(Err(RecvError::Empty)) | Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
#[path = "receiver_stream_inline_tests.rs"]
mod tests;
