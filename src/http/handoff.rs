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
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A transport a listener can serve: TCP, TLS over TCP, or a stream that
/// replays bytes read during protocol detection.
pub trait HandoffIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> HandoffIo for T {}

/// Wraps an underlying I/O stream (such as a [`TcpStream`]) and counts the
/// bytes written to it beneath TLS or other layered wrappers.
#[allow(dead_code)]
pub struct SocketByteCounter<S> {
    stream: S,
    written: Arc<AtomicU64>,
}

impl<S> SocketByteCounter<S> {
    #[allow(dead_code)]
    pub fn new(stream: S, written: Arc<AtomicU64>) -> Self {
        Self { stream, written }
    }

    #[allow(dead_code)]
    pub fn into_inner(self) -> S {
        self.stream
    }

    #[allow(dead_code)]
    pub(crate) fn counter(&self) -> &Arc<AtomicU64> {
        &self.written
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SocketByteCounter<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SocketByteCounter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.written.fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &result {
            self.written.fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// A handed-off connection.
pub struct HandoffStream {
    stream: Box<dyn HandoffIo>,
    socket_bytes_written: Option<Arc<AtomicU64>>,
}

impl HandoffStream {
    /// Creates a new handed-off connection without underlying socket tracking.
    #[must_use]
    pub fn new(stream: Box<dyn HandoffIo>) -> Self {
        Self {
            stream,
            socket_bytes_written: None,
        }
    }

    /// Creates a new handed-off connection with an underlying socket byte counter.
    #[must_use]
    #[allow(dead_code)]
    pub fn with_socket_counter(
        stream: Box<dyn HandoffIo>,
        socket_bytes_written: Arc<AtomicU64>,
    ) -> Self {
        Self {
            stream,
            socket_bytes_written: Some(socket_bytes_written),
        }
    }

    /// Returns the underlying socket write progress counter, if tracked.
    #[must_use]
    pub fn socket_bytes_written_counter(&self) -> Option<&Arc<AtomicU64>> {
        self.socket_bytes_written.as_ref()
    }
}

impl From<Box<dyn HandoffIo>> for HandoffStream {
    fn from(stream: Box<dyn HandoffIo>) -> Self {
        Self::new(stream)
    }
}

impl AsyncRead for HandoffStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for HandoffStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Connections waiting for a listener's accept loop.
#[derive(Default)]
pub struct HandoffQueue {
    state: parking_lot::Mutex<HandoffState>,
    // `notify_one` stores a permit when no task waits, so a push between the
    // accept loop's empty check and its wait is never lost.
    arrived: Notify,
}

#[derive(Default)]
struct HandoffState {
    connections: VecDeque<(HandoffStream, Option<SocketAddr>)>,
    closed: bool,
}

impl HandoffQueue {
    pub fn push(&self, stream: HandoffStream, peer: Option<SocketAddr>) {
        let mut state = self.state.lock();
        if state.closed {
            // Transport destructors may re-enter the queue. Never run them
            // while holding its gate, including on a rejected handoff.
            drop(state);
            return;
        }
        state.connections.push_back((stream, peer));
        drop(state);
        self.arrived.notify_one();
    }

    /// Refuses further handoffs and closes connections not yet accepted.
    /// Admission and close share a gate, so a racing push cannot strand a
    /// transport in a queue whose listener has stopped accepting.
    pub fn close(&self) {
        let pending = {
            let mut state = self.state.lock();
            state.closed = true;
            std::mem::take(&mut state.connections)
        };
        self.arrived.notify_waiters();
        drop(pending);
    }

    /// The next handed-off connection; waits until one arrives, or returns
    /// `BrokenPipe` once the queue is closed.
    pub async fn accept(&self) -> io::Result<(HandoffStream, Option<SocketAddr>)> {
        loop {
            let mut notified = std::pin::pin!(self.arrived.notified());
            let result = std::future::poll_fn(|cx| {
                // Register before checking state: notify_waiters does not
                // retain a permit for an acceptor that has not polled yet.
                let notified_ready = notified.as_mut().poll(cx).is_ready();
                let mut state = self.state.lock();
                if state.closed {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "HTTP handoff queue is closed",
                    ))));
                }
                if let Some(connection) = state.connections.pop_front() {
                    return Poll::Ready(Some(Ok(connection)));
                }
                if notified_ready {
                    // Another acceptor may have taken the connection. Create
                    // a fresh notification future rather than repolling one
                    // that has already completed.
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                }
            })
            .await;
            if let Some(result) = result {
                return result;
            }
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

#[cfg(test)]
#[path = "handoff_inline_tests.rs"]
mod tests;
