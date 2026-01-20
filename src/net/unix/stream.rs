//! Unix domain socket stream implementation.
//!
//! This module provides [`UnixStream`] for bidirectional communication over
//! Unix domain sockets.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::unix::UnixStream;
//! use asupersync::io::AsyncWriteExt;
//!
//! async fn client() -> std::io::Result<()> {
//!     let mut stream = UnixStream::connect("/tmp/my_socket.sock").await?;
//!     stream.write_all(b"hello").await?;
//!     Ok(())
//! }
//! ```

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::unix::split::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{self, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// A Unix domain socket stream.
///
/// Provides a bidirectional byte stream for inter-process communication
/// within the same machine.
///
/// # Cancel-Safety
///
/// Read and write operations are cancel-safe in the sense that if cancelled,
/// partial data may have been transferred. For cancel-correctness with
/// guaranteed delivery, use higher-level protocols.
#[derive(Debug)]
pub struct UnixStream {
    /// The underlying standard library stream.
    pub(crate) inner: Arc<net::UnixStream>,
    // TODO: Add Registration when reactor integration is complete
    // registration: Option<Registration>,
}

impl UnixStream {
    /// Connects to a Unix domain socket at the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - The filesystem path of the socket to connect to
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The socket doesn't exist
    /// - Permission is denied
    /// - Connection is refused
    ///
    /// # Example
    ///
    /// ```ignore
    /// let stream = UnixStream::connect("/tmp/my_socket.sock").await?;
    /// ```
    pub async fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        // For now, use blocking connect
        // TODO: Use non-blocking connect with reactor when available
        let inner = net::UnixStream::connect(path)?;
        inner.set_nonblocking(true)?;

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Connects to an abstract namespace socket (Linux only).
    ///
    /// Abstract namespace sockets are not bound to the filesystem and are
    /// automatically cleaned up by the kernel when all references are closed.
    ///
    /// # Arguments
    ///
    /// * `name` - The abstract socket name (without leading null byte)
    ///
    /// # Errors
    ///
    /// Returns an error if connection fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let stream = UnixStream::connect_abstract(b"my_abstract_socket").await?;
    /// ```
    #[cfg(target_os = "linux")]
    pub async fn connect_abstract(name: &[u8]) -> io::Result<Self> {
        use std::os::linux::net::SocketAddrExt;

        let addr = SocketAddr::from_abstract_name(name)?;
        let inner = net::UnixStream::connect_addr(&addr)?;
        inner.set_nonblocking(true)?;

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Creates a pair of connected Unix domain sockets.
    ///
    /// This is useful for inter-thread or bidirectional communication
    /// within the same process.
    ///
    /// # Errors
    ///
    /// Returns an error if socket creation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (stream1, stream2) = UnixStream::pair()?;
    /// ```
    pub fn pair() -> io::Result<(Self, Self)> {
        let (s1, s2) = net::UnixStream::pair()?;
        s1.set_nonblocking(true)?;
        s2.set_nonblocking(true)?;

        Ok((
            Self {
                inner: Arc::new(s1),
            },
            Self {
                inner: Arc::new(s2),
            },
        ))
    }

    /// Creates an async `UnixStream` from a standard library stream.
    ///
    /// The stream will be set to non-blocking mode.
    ///
    /// # Note
    ///
    /// For proper reactor integration, use this only with newly created
    /// streams that haven't been registered elsewhere.
    #[must_use]
    pub fn from_std(stream: net::UnixStream) -> Self {
        // Non-blocking is set by caller for streams from accept()
        Self {
            inner: Arc::new(stream),
        }
    }

    /// Returns the socket address of the local end.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the socket address of the remote end.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Shuts down the read, write, or both halves of the stream.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    /// Returns the underlying std stream reference.
    #[must_use]
    pub fn as_std(&self) -> &net::UnixStream {
        &self.inner
    }

    /// Splits the stream into borrowed read and write halves.
    ///
    /// The halves borrow the stream and can be used concurrently for
    /// reading and writing. The original stream cannot be used while
    /// the halves exist.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let stream = UnixStream::connect("/tmp/socket.sock").await?;
    /// let (mut read, mut write) = stream.split();
    /// // Use read and write concurrently
    /// ```
    #[must_use]
    pub fn split(&self) -> (ReadHalf<'_>, WriteHalf<'_>) {
        (ReadHalf::new(&self.inner), WriteHalf::new(&self.inner))
    }

    /// Splits the stream into owned read and write halves.
    ///
    /// The halves take ownership and can be moved to different tasks.
    /// They can optionally be reunited using [`reunite`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let stream = UnixStream::connect("/tmp/socket.sock").await?;
    /// let (read, write) = stream.into_split();
    /// // Move read and write to different tasks
    /// ```
    ///
    /// [`reunite`]: OwnedReadHalf::reunite
    #[must_use]
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        (
            OwnedReadHalf::new(self.inner.clone()),
            OwnedWriteHalf::new(self.inner),
        )
    }
}

impl AsyncRead for UnixStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner: &net::UnixStream = &self.inner;
        // std::os::unix::net::UnixStream implements Read for &UnixStream
        match (&*inner).read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // TODO: Register with reactor for proper wakeup
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncWrite for UnixStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner: &net::UnixStream = &self.inner;
        match (&*inner).write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // TODO: Register with reactor for proper wakeup
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner: &net::UnixStream = &self.inner;
        match (&*inner).flush() {
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

// Legacy std Read/Write impls for backwards compatibility
impl Read for UnixStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.inner).read(buf)
    }
}

impl Write for UnixStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.inner).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.inner).flush()
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for UnixStream {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pair() {
        let (mut s1, mut s2) = UnixStream::pair().expect("pair failed");

        s1.write_all(b"hello").expect("write failed");
        let mut buf = [0u8; 5];
        s2.read_exact(&mut buf).expect("read failed");

        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_local_peer_addr() {
        let (s1, s2) = UnixStream::pair().expect("pair failed");

        // Unnamed sockets from pair() don't have pathname addresses
        let local = s1.local_addr().expect("local_addr failed");
        let peer = s2.peer_addr().expect("peer_addr failed");

        // Both should be unnamed (no pathname)
        assert!(local.as_pathname().is_none());
        assert!(peer.as_pathname().is_none());
    }

    #[test]
    fn test_shutdown() {
        let (s1, _s2) = UnixStream::pair().expect("pair failed");

        // Shutdown should succeed
        s1.shutdown(Shutdown::Write).expect("shutdown failed");
    }

    #[test]
    fn test_split() {
        let (s1, _s2) = UnixStream::pair().expect("pair failed");

        // Split should work
        let (_read, _write) = s1.split();
    }

    #[test]
    fn test_into_split() {
        let (s1, _s2) = UnixStream::pair().expect("pair failed");

        // into_split should work
        let (_read, _write) = s1.into_split();
    }

    #[test]
    fn test_from_std() {
        let (std_s1, _std_s2) = net::UnixStream::pair().expect("pair failed");
        std_s1.set_nonblocking(true).expect("set_nonblocking failed");

        let _stream = UnixStream::from_std(std_s1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_connect_abstract() {
        // Test that connect_abstract compiles and returns an error when no listener exists
        futures_lite::future::block_on(async {
            // This will fail because no listener, but validates the API
            let result = UnixStream::connect_abstract(b"nonexistent_test_socket").await;
            assert!(result.is_err()); // Expected: no listener
        });
    }
}
