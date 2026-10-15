//! QUIC connection type.
//!
//! Provides cancel-correct connection handling with stream management.

use super::error::QuicError;
use super::stream::{RecvStream, SendStream, StreamTracker};
use crate::cx::Cx;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

/// A QUIC connection with cancel-correct stream management.
///
/// The connection tracks all open streams and ensures proper cleanup
/// on cancellation or connection close.
#[derive(Debug)]
pub struct QuicConnection {
    inner: quinn::Connection,
    tracker: Arc<StreamTracker>,
}

impl QuicConnection {
    /// Create a new connection wrapper.
    pub(crate) fn new(inner: quinn::Connection) -> Self {
        Self {
            inner,
            tracker: StreamTracker::new(),
        }
    }

    /// Get the remote address of the peer.
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// Get the stable connection ID.
    #[must_use]
    pub fn stable_id(&self) -> usize {
        self.inner.stable_id()
    }

    /// Get the negotiated ALPN protocol, if any.
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        self.inner.handshake_data().and_then(|data| {
            data.downcast::<quinn::crypto::rustls::HandshakeData>()
                .ok()
                .and_then(|hs| hs.protocol.clone())
        })
    }

    /// Open a bidirectional stream.
    ///
    /// Returns both send and receive halves of the stream.
    pub async fn open_bi(&self, cx: &Cx) -> Result<(SendStream, RecvStream), QuicError> {
        let (send, recv) = wait_with_cx(cx, self.inner.open_bi()).await??;

        Ok((
            SendStream::new(send, &self.tracker),
            RecvStream::new(recv, &self.tracker),
        ))
    }

    /// Open a unidirectional stream for sending.
    pub async fn open_uni(&self, cx: &Cx) -> Result<SendStream, QuicError> {
        let send = wait_with_cx(cx, self.inner.open_uni()).await??;
        Ok(SendStream::new(send, &self.tracker))
    }

    /// Accept an incoming bidirectional stream from the peer.
    pub async fn accept_bi(&self, cx: &Cx) -> Result<(SendStream, RecvStream), QuicError> {
        let (send, recv) = wait_with_cx(cx, self.inner.accept_bi()).await??;

        Ok((
            SendStream::new(send, &self.tracker),
            RecvStream::new(recv, &self.tracker),
        ))
    }

    /// Accept an incoming unidirectional stream from the peer.
    pub async fn accept_uni(&self, cx: &Cx) -> Result<RecvStream, QuicError> {
        let recv = wait_with_cx(cx, self.inner.accept_uni()).await??;
        Ok(RecvStream::new(recv, &self.tracker))
    }

    /// Close the connection gracefully.
    ///
    /// Sends a close frame to the peer and waits for acknowledgement.
    pub async fn close(&self, cx: &Cx, code: u32, reason: &[u8]) -> Result<(), QuicError> {
        // Mark all streams for cleanup
        self.tracker.mark_closing();

        // Close the connection
        self.inner.close(code.into(), reason);

        // Wait for the connection to fully close
        let _ = wait_with_cx(cx, self.inner.closed()).await?;

        Ok(())
    }

    /// Close the connection immediately without waiting.
    pub fn close_immediately(&self, code: u32, reason: &[u8]) {
        self.tracker.mark_closing();
        self.inner.close(code.into(), reason);
    }

    /// Check if the connection is still open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.tracker.is_closing() && self.inner.close_reason().is_none()
    }

    /// Wait for the connection to close (for any reason).
    pub async fn closed(&self, cx: &Cx) -> Result<(), QuicError> {
        let _ = wait_with_cx(cx, self.inner.closed()).await?;
        Ok(())
    }

    /// Get the maximum datagram size that can be sent.
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    /// Send an unreliable datagram.
    ///
    /// Datagrams are not guaranteed to be delivered or arrive in order.
    pub fn send_datagram(&self, data: &[u8]) -> Result<(), QuicError> {
        self.inner.send_datagram(data.to_vec().into())?;
        Ok(())
    }

    /// Receive an unreliable datagram.
    ///
    /// Returns the datagram payload as a byte vector.
    pub async fn read_datagram(&self, cx: &Cx) -> Result<Vec<u8>, QuicError> {
        let data = wait_with_cx(cx, self.inner.read_datagram()).await??;
        Ok(data.to_vec())
    }

    /// Get RTT (round-trip time) estimate.
    #[must_use]
    pub fn rtt(&self) -> std::time::Duration {
        self.inner.rtt()
    }

    /// Get a reference to the inner quinn connection.
    #[must_use]
    pub fn inner(&self) -> &quinn::Connection {
        &self.inner
    }
}

impl Drop for QuicConnection {
    fn drop(&mut self) {
        // Ensure streams are marked for cleanup
        self.tracker.mark_closing();
    }
}

async fn wait_with_cx<T, F>(cx: &Cx, future: F) -> Result<T, QuicError>
where
    F: Future<Output = T>,
{
    let mut future = std::pin::pin!(future);
    poll_fn(|poll_cx| {
        if let Err(err) = cx.checkpoint() {
            return Poll::Ready(Err(QuicError::from(err)));
        }
        future.as_mut().poll(poll_cx).map(Ok)
    })
    .await
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]

    use super::*;
    use std::pin::Pin;
    use std::task::Context;

    fn noop_waker() -> std::task::Waker {
        std::task::Waker::noop().clone()
    }

    struct PendingOnce {
        polled: bool,
    }

    impl Future for PendingOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.polled {
                Poll::Ready(())
            } else {
                self.polled = true;
                Poll::Pending
            }
        }
    }

    #[test]
    fn wait_with_cx_returns_cancelled_when_context_is_cancelled_between_polls() {
        let cx = Cx::for_testing();
        let mut future = std::pin::pin!(wait_with_cx(&cx, PendingOnce { polled: false }));
        let waker = noop_waker();
        let mut poll_cx = Context::from_waker(&waker);

        assert!(matches!(future.as_mut().poll(&mut poll_cx), Poll::Pending));

        cx.set_cancel_requested(true);

        let cancelled = matches!(
            future.as_mut().poll(&mut poll_cx),
            Poll::Ready(Err(QuicError::Cancelled))
        );
        assert!(
            cancelled,
            "future should return cancelled after Cx cancellation"
        );
    }
}
