//! Unix stream splitting.
//!
//! This module provides borrowed and owned halves for splitting a
//! [`UnixStream`](super::UnixStream) into separate read and write handles.

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Borrowed read half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::split`](super::UnixStream::split).
#[derive(Debug)]
pub struct ReadHalf<'a> {
    inner: &'a net::UnixStream,
}

impl<'a> ReadHalf<'a> {
    pub(crate) fn new(inner: &'a net::UnixStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for ReadHalf<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.inner;
        match inner.read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// Borrowed write half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::split`](super::UnixStream::split).
#[derive(Debug)]
pub struct WriteHalf<'a> {
    inner: &'a net::UnixStream,
}

impl<'a> WriteHalf<'a> {
    pub(crate) fn new(inner: &'a net::UnixStream) -> Self {
        Self { inner }
    }
}

impl AsyncWrite for WriteHalf<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner;
        match inner.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner;
        match inner.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.shutdown(Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}

/// Owned read half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::into_split`](super::UnixStream::into_split).
/// Can be reunited with [`OwnedWriteHalf`] using [`reunite`](Self::reunite).
#[derive(Debug)]
pub struct OwnedReadHalf {
    pub(crate) inner: Arc<net::UnixStream>,
}

impl OwnedReadHalf {
    pub(crate) fn new(inner: Arc<net::UnixStream>) -> Self {
        Self { inner }
    }

    /// Attempts to reunite with a write half to reform a [`UnixStream`](super::UnixStream).
    ///
    /// # Errors
    ///
    /// Returns an error containing both halves if they originated from
    /// different streams.
    pub fn reunite(self, other: OwnedWriteHalf) -> Result<super::UnixStream, ReuniteError> {
        if Arc::ptr_eq(&self.inner, &other.inner) {
            drop(other);
            // Note: Original registration is lost when splitting; reunited stream has no registration
            Ok(super::UnixStream::from_parts(self.inner, None))
        } else {
            Err(ReuniteError(self, other))
        }
    }
}

impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = &*self.inner;
        match inner.read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// Owned write half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::into_split`](super::UnixStream::into_split).
/// Can be reunited with [`OwnedReadHalf`] using
/// [`OwnedReadHalf::reunite`](OwnedReadHalf::reunite).
#[derive(Debug)]
pub struct OwnedWriteHalf {
    pub(crate) inner: Arc<net::UnixStream>,
}

impl OwnedWriteHalf {
    pub(crate) fn new(inner: Arc<net::UnixStream>) -> Self {
        Self { inner }
    }

    /// Shuts down the write side of the stream.
    ///
    /// This is equivalent to calling `shutdown(Shutdown::Write)` on the
    /// original stream.
    pub fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown(Shutdown::Write)
    }
}

impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = &*self.inner;
        match inner.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = &*self.inner;
        match inner.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.shutdown(Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}

/// Error returned when trying to reunite halves from different streams.
#[derive(Debug)]
pub struct ReuniteError(pub OwnedReadHalf, pub OwnedWriteHalf);

impl std::fmt::Display for ReuniteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tried to reunite halves that are not from the same socket"
        )
    }
}

impl std::error::Error for ReuniteError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_borrowed_halves() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let _read = ReadHalf::new(&s1);
        let _write = WriteHalf::new(&s1);
    }

    #[test]
    fn test_owned_halves() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let arc1 = Arc::new(s1);
        let _read = OwnedReadHalf::new(arc1.clone());
        let _write = OwnedWriteHalf::new(arc1);
    }

    #[test]
    fn test_reunite_success() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let stream = super::super::UnixStream::from_std(s1);
        let (read, write) = stream.into_split();

        // Should succeed - same stream
        let _reunited = read.reunite(write).expect("reunite should succeed");
    }

    #[test]
    fn test_reunite_failure() {
        let (s1, _s2a) = net::UnixStream::pair().expect("pair failed");
        let (s2, _s2b) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");
        s2.set_nonblocking(true).expect("set_nonblocking failed");

        let stream1 = super::super::UnixStream::from_std(s1);
        let stream2 = super::super::UnixStream::from_std(s2);

        let (read1, _write1) = stream1.into_split();
        let (_read2, write2) = stream2.into_split();

        // Should fail - different streams
        let err = read1.reunite(write2).expect_err("reunite should fail");
        assert!(err.to_string().contains("not from the same socket"));
    }
}
