//! TCP stream splitting.

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::io::{self, Read, Write};
use std::net::{self, Shutdown};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Borrowed read half.
#[derive(Debug)]
pub struct ReadHalf<'a> {
    inner: &'a net::TcpStream,
}

impl<'a> ReadHalf<'a> {
    pub(crate) fn new(inner: &'a net::TcpStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for ReadHalf<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.inner;
        match inner.read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// Borrowed write half.
#[derive(Debug)]
pub struct WriteHalf<'a> {
    inner: &'a net::TcpStream,
}

impl<'a> WriteHalf<'a> {
    pub(crate) fn new(inner: &'a net::TcpStream) -> Self {
        Self { inner }
    }
}

impl AsyncWrite for WriteHalf<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner;
        match inner.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner;
        match inner.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.shutdown(Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}

/// Owned read half.
#[derive(Debug)]
pub struct OwnedReadHalf {
    inner: Arc<net::TcpStream>,
}

impl OwnedReadHalf {
    pub(crate) fn new(inner: Arc<net::TcpStream>) -> Self {
        Self { inner }
    }
}

impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = &*self.inner;
        match inner.read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// Owned write half.
#[derive(Debug)]
pub struct OwnedWriteHalf {
    inner: Arc<net::TcpStream>,
}

impl OwnedWriteHalf {
    pub(crate) fn new(inner: Arc<net::TcpStream>) -> Self {
        Self { inner }
    }
}

impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = &*self.inner;
        match inner.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = &*self.inner;
        match inner.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.shutdown(Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}
