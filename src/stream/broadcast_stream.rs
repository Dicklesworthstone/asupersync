//! Stream adapter for broadcast receivers.

use crate::channel::broadcast;
use crate::cx::Cx;
use crate::stream::Stream;
use crate::util::ArenaIndex;
use std::pin::Pin;
use std::ptr;
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
    #[inline]
    #[must_use]
    pub fn new(cx: Cx, recv: broadcast::Receiver<T>) -> Self {
        Self {
            inner: recv,
            cx,
            terminated: false,
            waiter: None,
        }
    }

    /// Returns a reference to the underlying broadcast receiver.
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &broadcast::Receiver<T> {
        &self.inner
    }

    /// Returns a mutable reference to the underlying broadcast receiver.
    #[inline]
    pub fn get_mut(&mut self) -> &mut broadcast::Receiver<T> {
        self.receiver_for_mutation()
    }

    /// Returns a reference to the capability context.
    #[inline]
    #[must_use]
    pub fn cx(&self) -> &Cx {
        &self.cx
    }

    /// Consumes the stream, returning the underlying broadcast receiver.
    #[inline]
    #[must_use]
    #[allow(unsafe_code)]
    pub fn into_inner(mut self) -> broadcast::Receiver<T> {
        // Manually clear waiter registration before moving out inner receiver
        self.inner.clear_waiter_registration(&mut self.waiter);

        let mut md = std::mem::ManuallyDrop::new(self);

        // Use ptr::read to extract inner without running Drop.
        // SAFETY: We've wrapped in ManuallyDrop, so the outer Drop will never run,
        // preventing double-frees even if cx drop panics.
        let inner = unsafe { ptr::read(&raw const md.inner) };
        unsafe { ptr::drop_in_place(&raw mut md.cx) };

        inner
    }

    /// Hands out the receiver for mutation. The caller may replace it with a
    /// receiver of another channel, and this stream's waiter registration is
    /// a token into the current channel's waker arena: used against another
    /// channel it would evict an unrelated receiver's waker. So the
    /// registration is cleared first; the next poll registers afresh
    /// (br-asupersync-lh4z78).
    fn receiver_for_mutation(&mut self) -> &mut broadcast::Receiver<T> {
        self.inner.clear_waiter_registration(&mut self.waiter);
        &mut self.inner
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

impl<T: Clone> Stream for BroadcastStream<T> {
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
#[path = "broadcast_stream_inline_tests.rs"]
mod tests;
