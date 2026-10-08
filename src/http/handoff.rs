//! Connections handed from one accept loop to a listener's serve path.
//!
//! [`HttpAutoListener`](super::auto::HttpAutoListener) accepts each
//! connection once, decides its protocol, and pushes it into the queue of the
//! HTTP/1.1 or HTTP/2 listener that serves it. The receiving listener's
//! accept loop takes connections from the queue instead of a socket, so its
//! connection limits, drain and statistics apply unchanged.

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::sync::Notify;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A transport a listener can serve: TCP, TLS over TCP, or a stream that
/// replays bytes read during protocol detection.
pub trait HandoffIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> HandoffIo for T {}

/// A handed-off connection.
pub type HandoffStream = Box<dyn HandoffIo>;

/// Connections waiting for a listener's accept loop.
#[derive(Default)]
pub struct HandoffQueue {
    connections: parking_lot::Mutex<VecDeque<(HandoffStream, Option<SocketAddr>)>>,
    // `notify_one` stores a permit when no task waits, so a push between the
    // accept loop's empty check and its wait is never lost.
    arrived: Notify,
}

impl HandoffQueue {
    pub fn push(&self, stream: HandoffStream, peer: Option<SocketAddr>) {
        self.connections.lock().push_back((stream, peer));
        self.arrived.notify_one();
    }

    /// The next handed-off connection; waits until one arrives.
    pub async fn accept(&self) -> io::Result<(HandoffStream, Option<SocketAddr>)> {
        loop {
            if let Some(connection) = self.connections.lock().pop_front() {
                return Ok(connection);
            }
            self.arrived.notified().await;
        }
    }
}

/// Bytes read from a connection to identify its protocol, served again
/// before the rest of the stream.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub const fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let pending = &this.prefix[this.offset..];
        if !pending.is_empty() {
            let take = pending.len().min(buf.remaining());
            buf.put_slice(&pending[..take]);
            this.offset += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
