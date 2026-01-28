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
}

impl<T: Clone> BroadcastStream<T> {
    /// Creates a new broadcast stream from the receiver.
    #[must_use]
    pub fn new(cx: Cx, recv: broadcast::Receiver<T>) -> Self {
        Self { inner: recv, cx }
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
        let Self { inner, cx } = &mut *self;
        // Poll the recv future using std::pin::pin! for safe pinning
        let recv_future = inner.recv(cx);
        let mut pinned = std::pin::pin!(recv_future);
        match pinned.as_mut().poll(poll_cx) {
            Poll::Ready(Ok(item)) => Poll::Ready(Some(Ok(item))),
            Poll::Ready(Err(broadcast::RecvError::Lagged(n))) => {
                Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(n))))
            }
            Poll::Ready(Err(broadcast::RecvError::Closed | broadcast::RecvError::Cancelled)) => {
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
