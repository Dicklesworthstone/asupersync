//! TCP stream implementation.

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::tcp::split::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf};
use std::io;
use std::net::{self, Shutdown, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// A TCP stream.
#[derive(Debug)]
pub struct TcpStream {
    inner: Arc<net::TcpStream>,
}

impl TcpStream {
    pub(crate) fn from_std(stream: net::TcpStream) -> Self {
        Self {
            inner: Arc::new(stream),
        }
    }

    /// Connect to address.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        // TODO: Async connect
        // 1. Create socket
        // 2. Set non-blocking
        // 3. Connect (EINPROGRESS)
        // 4. Wait for writable
        let stream = net::TcpStream::connect(addr)?;
        stream.set_nonblocking(true)?;
        Ok(Self::from_std(stream))
    }

    /// Connect with timeout.
    pub async fn connect_timeout(addr: SocketAddr, timeout: Duration) -> io::Result<Self> {
        let stream = net::TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_nonblocking(true)?;
        Ok(Self::from_std(stream))
    }

    /// Get peer address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Get local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Shutdown.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    /// Set TCP_NODELAY.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    /// Set keepalive.
    pub fn set_keepalive(&self, _keepalive: Option<Duration>) -> io::Result<()> {
        // Not supported in std
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "set_keepalive not supported",
        ))
    }

    /// Split into borrowed halves.
    #[must_use]
    pub fn split(&self) -> (ReadHalf<'_>, WriteHalf<'_>) {
        (ReadHalf::new(&self.inner), WriteHalf::new(&self.inner))
    }

    /// Split into owned halves.
    #[must_use]
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        (
            OwnedReadHalf::new(self.inner.clone()),
            OwnedWriteHalf::new(self.inner),
        )
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use std::io::Read;
        // TODO: check readiness
        let mut inner = &*self.inner;
        // This fails because inner is Arc and we need &mut for Read trait?
        // std::net::TcpStream implement Read for &TcpStream.
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

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use std::io::Write;
        let mut inner = &*self.inner;
        match inner.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::io::Write;
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
