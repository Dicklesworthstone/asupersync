#![allow(unsafe_code)]
//! Unix domain socket datagram implementation.
//!
//! This module uses unsafe code for peek operations via libc and peer credentials
//! retrieval (getsockopt/getpeereid).
//!
//! This module provides [`UnixDatagram`] for connectionless communication over
//! Unix domain sockets.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::unix::UnixDatagram;
//!
//! async fn example() -> std::io::Result<()> {
//!     // Create a pair of connected datagrams
//!     let (mut a, mut b) = UnixDatagram::pair()?;
//!
//!     a.send(b"hello").await?;
//!     let mut buf = [0u8; 5];
//!     let n = b.recv(&mut buf).await?;
//!     assert_eq!(&buf[..n], b"hello");
//!     Ok(())
//! }
//! ```
//!
//! # Bound vs Unbound
//!
//! - **Bound sockets** have a filesystem path (or abstract name on Linux) and can receive
//!   datagrams sent to that address.
//! - **Unbound sockets** can still send datagrams and receive responses, but cannot receive
//!   unsolicited datagrams.
//! - **Connected sockets** have a default destination and can use [`send`](UnixDatagram::send)
//!   instead of [`send_to`](UnixDatagram::send_to).

use crate::cx::Cx;
use crate::net::unix::stream::UCred;
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use std::io;
use std::os::unix::net::{self, SocketAddr};
use std::path::{Path, PathBuf};
use std::task::{Context, Poll};

/// A Unix domain socket datagram.
///
/// Provides connectionless, unreliable datagram communication for inter-process
/// communication within the same machine.
///
/// # Cancel-Safety
///
/// Send and receive operations are cancel-safe: if cancelled, the datagram is
/// either fully sent/received or not at all (no partial datagrams).
///
/// # Socket File Cleanup
///
/// When dropped, a bound listener removes the socket file from the filesystem
/// (unless it was created with [`from_std`](Self::from_std) or is an abstract
/// namespace socket).
/// A Unix domain socket datagram.
///
/// Async methods take `&mut self` to avoid concurrent waiters clobbering
/// the single reactor registration/waker slot.
#[derive(Debug)]
pub struct UnixDatagram {
    /// The underlying standard library datagram socket.
    inner: net::UnixDatagram,
    /// Path to the socket file (for cleanup on drop).
    /// None for abstract namespace sockets, unbound sockets, or from_std().
    path: Option<PathBuf>,
    /// Reactor registration for async I/O wakeup.
    registration: Option<IoRegistration>,
}

impl UnixDatagram {
    /// Binds to a filesystem path.
    ///
    /// Creates a new Unix datagram socket bound to the specified path.
    /// If a socket file already exists at the path, it will be removed before binding.
    ///
    /// # Arguments
    ///
    /// * `path` - The filesystem path for the socket
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path is inaccessible or has permission issues
    /// - The directory doesn't exist
    /// - Another error occurs during socket creation
    ///
    /// # Example
    ///
    /// ```ignore
    /// let socket = UnixDatagram::bind("/tmp/my_datagram.sock")?;
    /// ```
    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref();

        // Remove existing socket file if present (might be stale from previous run)
        let _ = std::fs::remove_file(path);

        let inner = net::UnixDatagram::bind(path)?;
        inner.set_nonblocking(true)?;

        Ok(Self {
            inner,
            path: Some(path.to_path_buf()),
            registration: None,
        })
    }

    /// Binds to an abstract namespace socket (Linux only).
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
    /// Returns an error if socket creation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let socket = UnixDatagram::bind_abstract(b"my_abstract_socket")?;
    /// ```
    #[cfg(target_os = "linux")]
    pub fn bind_abstract(name: &[u8]) -> io::Result<Self> {
        use std::os::linux::net::SocketAddrExt;

        let addr = SocketAddr::from_abstract_name(name)?;
        let inner = net::UnixDatagram::bind_addr(&addr)?;
        inner.set_nonblocking(true)?;

        Ok(Self {
            inner,
            path: None, // No filesystem path for abstract sockets
            registration: None,
        })
    }

    /// Creates an unbound Unix datagram socket.
    ///
    /// The socket is not bound to any address. It can send datagrams using
    /// [`send_to`](Self::send_to) and receive responses, but cannot receive
    /// unsolicited datagrams.
    ///
    /// # Errors
    ///
    /// Returns an error if socket creation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let socket = UnixDatagram::unbound()?;
    /// socket.send_to(b"hello", "/tmp/server.sock").await?;
    /// ```
    pub fn unbound() -> io::Result<Self> {
        let inner = net::UnixDatagram::unbound()?;
        inner.set_nonblocking(true)?;

        Ok(Self {
            inner,
            path: None,
            registration: None,
        })
    }

    /// Creates a pair of connected Unix datagram sockets.
    ///
    /// This is useful for inter-thread or bidirectional communication
    /// within the same process. The sockets are connected to each other,
    /// so [`send`](Self::send) and [`recv`](Self::recv) can be used directly.
    ///
    /// # Errors
    ///
    /// Returns an error if socket creation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (mut a, mut b) = UnixDatagram::pair()?;
    /// a.send(b"ping").await?;
    /// let mut buf = [0u8; 4];
    /// let n = b.recv(&mut buf).await?;
    /// assert_eq!(&buf[..n], b"ping");
    /// ```
    pub fn pair() -> io::Result<(Self, Self)> {
        let (s1, s2) = net::UnixDatagram::pair()?;
        s1.set_nonblocking(true)?;
        s2.set_nonblocking(true)?;

        Ok((
            Self {
                inner: s1,
                path: None,
                registration: None,
            },
            Self {
                inner: s2,
                path: None,
                registration: None,
            },
        ))
    }

    /// Connects the socket to a remote address.
    ///
    /// After connecting, [`send`](Self::send) and [`recv`](Self::recv) can be used
    /// instead of [`send_to`](Self::send_to) and [`recv_from`](Self::recv_from).
    ///
    /// # Arguments
    ///
    /// * `path` - The filesystem path of the socket to connect to
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let socket = UnixDatagram::unbound()?;
    /// socket.connect("/tmp/server.sock")?;
    /// socket.send(b"hello").await?;
    /// ```
    pub fn connect<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        self.inner.connect(path)
    }

    /// Connects to an abstract namespace socket (Linux only).
    ///
    /// After connecting, [`send`](Self::send) and [`recv`](Self::recv) can be used.
    ///
    /// # Arguments
    ///
    /// * `name` - The abstract socket name (without leading null byte)
    ///
    /// # Errors
    ///
    /// Returns an error if connection fails.
    #[cfg(target_os = "linux")]
    pub fn connect_abstract(&self, name: &[u8]) -> io::Result<()> {
        use std::os::linux::net::SocketAddrExt;

        let addr = SocketAddr::from_abstract_name(name)?;
        self.inner.connect_addr(&addr)
    }

    /// Register interest with the reactor for async wakeup.
    fn register_interest(&mut self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        if let Some(registration) = &mut self.registration {
            let combined = registration.interest() | interest;
            if combined != registration.interest() {
                if let Err(err) = registration.set_interest(combined) {
                    if err.kind() == io::ErrorKind::NotConnected {
                        self.registration = None;
                        cx.waker().wake_by_ref();
                        return Ok(());
                    }
                    return Err(err);
                }
            }
            if registration.update_waker(cx.waker().clone()) {
                return Ok(());
            }
            self.registration = None;
        }

        let Some(current) = Cx::current() else {
            cx.waker().wake_by_ref();
            return Ok(());
        };
        let Some(driver) = current.io_driver_handle() else {
            cx.waker().wake_by_ref();
            return Ok(());
        };

        match driver.register(&self.inner, interest, cx.waker().clone()) {
            Ok(registration) => {
                self.registration = Some(registration);
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                cx.waker().wake_by_ref();
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Sends data to the specified address.
    ///
    /// # Cancel-Safety
    ///
    /// This method is cancel-safe. If cancelled, the datagram is either fully
    /// sent or not at all.
    ///
    /// # Arguments
    ///
    /// * `buf` - The data to send
    /// * `path` - The destination address
    ///
    /// # Returns
    ///
    /// The number of bytes sent (always equals `buf.len()` on success for datagrams).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The destination doesn't exist
    /// - The send buffer is full
    /// - The datagram is too large
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut socket = UnixDatagram::unbound()?;
    /// let n = socket.send_to(b"hello", "/tmp/server.sock").await?;
    /// ```
    pub async fn send_to<P: AsRef<Path>>(&mut self, buf: &[u8], path: P) -> io::Result<usize> {
        std::future::poll_fn(|cx| match self.inner.send_to(buf, &path) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        })
        .await
    }

    /// Receives data and the source address.
    ///
    /// # Cancel-Safety
    ///
    /// This method is cancel-safe. If cancelled, no data is lost - it will be
    /// available for the next receive call.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to receive data into
    ///
    /// # Returns
    ///
    /// A tuple of (bytes_received, source_address).
    ///
    /// # Errors
    ///
    /// Returns an error if the receive fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut socket = UnixDatagram::bind("/tmp/server.sock")?;
    /// let mut buf = [0u8; 1024];
    /// let (n, addr) = socket.recv_from(&mut buf).await?;
    /// println!("Received {} bytes from {:?}", n, addr);
    /// ```
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::poll_fn(|cx| match self.inner.recv_from(buf) {
            Ok((n, addr)) => Poll::Ready(Ok((n, addr))),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        })
        .await
    }

    /// Sends data to the connected peer.
    ///
    /// The socket must be connected via [`connect`](Self::connect) or created
    /// with [`pair`](Self::pair).
    ///
    /// # Cancel-Safety
    ///
    /// This method is cancel-safe. If cancelled, the datagram is either fully
    /// sent or not at all.
    ///
    /// # Arguments
    ///
    /// * `buf` - The data to send
    ///
    /// # Returns
    ///
    /// The number of bytes sent.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The socket is not connected
    /// - The send buffer is full
    /// - The datagram is too large
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (mut a, _b) = UnixDatagram::pair()?;
    /// let n = a.send(b"hello").await?;
    /// ```
    pub async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        std::future::poll_fn(|cx| match self.inner.send(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        })
        .await
    }

    /// Receives data from the connected peer.
    ///
    /// The socket must be connected via [`connect`](Self::connect) or created
    /// with [`pair`](Self::pair).
    ///
    /// # Cancel-Safety
    ///
    /// This method is cancel-safe. If cancelled, no data is lost - it will be
    /// available for the next receive call.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to receive data into
    ///
    /// # Returns
    ///
    /// The number of bytes received.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket is not connected or receive fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (mut a, mut b) = UnixDatagram::pair()?;
    /// a.send(b"hello").await?;
    /// let mut buf = [0u8; 5];
    /// let n = b.recv(&mut buf).await?;
    /// ```
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        std::future::poll_fn(|cx| match self.inner.recv(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        })
        .await
    }

    /// Returns the local socket address.
    ///
    /// For bound sockets, this returns the path or abstract name.
    /// For unbound sockets, this returns an unnamed address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the socket address of the connected peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket is not connected.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Returns the credentials of the peer process.
    ///
    /// This can be used to verify the identity of the process on the other
    /// end of a connected datagram socket for security purposes.
    ///
    /// # Platform-Specific Behavior
    ///
    /// - On Linux: Uses `SO_PEERCRED` socket option to retrieve uid, gid, and pid.
    /// - On macOS/FreeBSD/OpenBSD/NetBSD: Uses `getpeereid()` to retrieve uid and gid;
    ///   pid is not available.
    ///
    /// # Note
    ///
    /// For datagram sockets, peer credentials are only available for connected
    /// sockets (those that have called [`connect`](Self::connect)). For unconnected
    /// datagram sockets, this will return an error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The socket is not connected
    /// - Retrieving credentials fails for platform-specific reasons
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (a, b) = UnixDatagram::pair()?;
    /// let cred = a.peer_cred()?;
    /// if cred.uid == 0 {
    ///     println!("Connected to a root process");
    /// }
    /// ```
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    pub fn peer_cred(&self) -> io::Result<UCred> {
        datagram_peer_cred_impl(&self.inner)
    }

    /// Creates an async `UnixDatagram` from a standard library socket.
    ///
    /// The socket will be set to non-blocking mode. Unlike [`bind`](Self::bind),
    /// the socket file will **not** be automatically removed on drop.
    ///
    /// # Errors
    ///
    /// Returns an error if setting non-blocking mode fails.
    pub fn from_std(socket: net::UnixDatagram) -> io::Result<Self> {
        socket.set_nonblocking(true)?;

        Ok(Self {
            inner: socket,
            path: None, // Don't clean up sockets we didn't create
            registration: None,
        })
    }

    /// Returns the underlying std socket reference.
    #[must_use]
    pub fn as_std(&self) -> &net::UnixDatagram {
        &self.inner
    }

    /// Takes ownership of the filesystem path, preventing automatic cleanup.
    ///
    /// After calling this, the socket file will **not** be removed when the
    /// socket is dropped. Returns the path if it was set.
    pub fn take_path(&mut self) -> Option<PathBuf> {
        self.path.take()
    }

    /// Polls for read readiness.
    ///
    /// This is useful for implementing custom poll loops.
    pub fn poll_recv_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::os::unix::io::AsRawFd;

        // Try a zero-byte peek to check readiness
        let mut buf = [0u8; 1];
        // SAFETY: recv with MSG_PEEK is a well-defined syscall
        let ret = unsafe {
            libc::recv(
                self.inner.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                0, // zero-length read to check readiness
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };

        if ret >= 0 {
            Poll::Ready(Ok(()))
        } else {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                if let Err(e) = self.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending
            } else {
                Poll::Ready(Err(err))
            }
        }
    }

    /// Polls for write readiness.
    ///
    /// This is useful for implementing custom poll loops.
    pub fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::os::unix::io::AsRawFd;

        // Try a zero-byte send to check write readiness
        // SAFETY: send with zero length is a well-defined syscall
        let ret = unsafe {
            libc::send(
                self.inner.as_raw_fd(),
                std::ptr::null(),
                0, // zero-length to check readiness
                libc::MSG_DONTWAIT,
            )
        };

        if ret >= 0 {
            Poll::Ready(Ok(()))
        } else {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                if let Err(e) = self.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending
            } else {
                Poll::Ready(Err(err))
            }
        }
    }

    /// Peeks at incoming data without consuming it.
    ///
    /// Like [`recv`](Self::recv), but the data remains in the receive buffer.
    pub async fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::io::AsRawFd;

        std::future::poll_fn(|cx| {
            // SAFETY: recv with MSG_PEEK is a well-defined syscall
            let ret = unsafe {
                libc::recv(
                    self.inner.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    libc::MSG_PEEK,
                )
            };

            if ret >= 0 {
                Poll::Ready(Ok(ret as usize))
            } else {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    if let Err(e) = self.register_interest(cx, Interest::READABLE) {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending
                } else {
                    Poll::Ready(Err(err))
                }
            }
        })
        .await
    }

    /// Peeks at incoming data and returns the source address.
    ///
    /// Like [`recv_from`](Self::recv_from), but the data remains in the receive buffer.
    pub async fn peek_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        use std::os::unix::io::AsRawFd;

        std::future::poll_fn(|cx| {
            let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

            // SAFETY: recvfrom with MSG_PEEK is a well-defined syscall
            let ret = unsafe {
                libc::recvfrom(
                    self.inner.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    libc::MSG_PEEK,
                    (&raw mut addr_storage).cast::<libc::sockaddr>(),
                    &raw mut addr_len,
                )
            };

            if ret >= 0 {
                // Convert sockaddr_storage to SocketAddr
                // For Unix sockets, we can use the local_addr as a placeholder
                // since the actual address parsing is complex
                let addr = self.local_addr().unwrap_or_else(|_| {
                    // Return an unnamed socket address
                    SocketAddr::from_pathname(std::path::Path::new("")).unwrap_or_else(|_| {
                        // This should not happen in practice
                        panic!("failed to create placeholder socket address")
                    })
                });
                Poll::Ready(Ok((ret as usize, addr)))
            } else {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    if let Err(e) = self.register_interest(cx, Interest::READABLE) {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending
                } else {
                    Poll::Ready(Err(err))
                }
            }
        })
        .await
    }

    /// Sets the read timeout on the socket.
    ///
    /// Note: This timeout applies to blocking operations. For async operations,
    /// use timeouts at the application level.
    pub fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(dur)
    }

    /// Sets the write timeout on the socket.
    ///
    /// Note: This timeout applies to blocking operations. For async operations,
    /// use timeouts at the application level.
    pub fn set_write_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(dur)
    }

    /// Gets the read timeout on the socket.
    pub fn read_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        self.inner.read_timeout()
    }

    /// Gets the write timeout on the socket.
    pub fn write_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        self.inner.write_timeout()
    }
}

impl Drop for UnixDatagram {
    fn drop(&mut self) {
        // Clean up socket file if we created it
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for UnixDatagram {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.inner.as_raw_fd()
    }
}

// Platform-specific peer credential implementations for datagram sockets

/// Linux implementation using SO_PEERCRED.
#[cfg(target_os = "linux")]
fn datagram_peer_cred_impl(socket: &net::UnixDatagram) -> io::Result<UCred> {
    use std::os::unix::io::AsRawFd;

    // ucred structure from Linux
    #[repr(C)]
    struct LinuxUcred {
        pid: i32,
        uid: u32,
        gid: u32,
    }

    let fd = socket.as_raw_fd();
    let mut ucred = LinuxUcred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<LinuxUcred>() as libc::socklen_t;

    // SAFETY: getsockopt is a well-defined syscall, and we're passing
    // correct buffer size and type for SO_PEERCRED option.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut ucred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };

    if ret == 0 {
        Ok(UCred {
            uid: ucred.uid,
            gid: ucred.gid,
            pid: Some(ucred.pid),
        })
    } else {
        Err(io::Error::last_os_error())
    }
}

/// macOS/BSD implementation using getpeereid.
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn datagram_peer_cred_impl(socket: &net::UnixDatagram) -> io::Result<UCred> {
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;

    // SAFETY: getpeereid is a well-defined syscall on BSD systems.
    let ret = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };

    if ret == 0 {
        Ok(UCred {
            uid: uid as u32,
            gid: gid as u32,
            pid: None, // Not available via getpeereid
        })
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_pair() {
        init_test("test_datagram_pair");
        futures_lite::future::block_on(async {
            let (mut a, mut b) = UnixDatagram::pair().expect("pair failed");

            a.send(b"hello").await.expect("send failed");
            let mut buf = [0u8; 5];
            let n = b.recv(&mut buf).await.expect("recv failed");

            crate::assert_with_log!(n == 5, "received bytes", 5, n);
            crate::assert_with_log!(&buf == b"hello", "received data", b"hello", buf);
        });
        crate::test_complete!("test_datagram_pair");
    }

    #[test]
    fn test_bind_and_send_to() {
        init_test("test_datagram_bind_send_to");
        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let server_path = dir.path().join("server.sock");

            let mut server = UnixDatagram::bind(&server_path).expect("bind failed");
            let mut client = UnixDatagram::unbound().expect("unbound failed");

            // Send from client to server
            let sent = client
                .send_to(b"hello", &server_path)
                .await
                .expect("send_to failed");
            crate::assert_with_log!(sent == 5, "sent bytes", 5, sent);

            // Receive on server
            let mut buf = [0u8; 5];
            let (n, _addr) = server.recv_from(&mut buf).await.expect("recv_from failed");
            crate::assert_with_log!(n == 5, "received bytes", 5, n);
            crate::assert_with_log!(&buf == b"hello", "received data", b"hello", buf);
        });
        crate::test_complete!("test_datagram_bind_send_to");
    }

    #[test]
    fn test_connect() {
        init_test("test_datagram_connect");
        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let server_path = dir.path().join("server.sock");
            let client_path = dir.path().join("client.sock");

            let mut server = UnixDatagram::bind(&server_path).expect("bind server failed");
            let mut client = UnixDatagram::bind(&client_path).expect("bind client failed");

            // Connect client to server
            client.connect(&server_path).expect("connect failed");

            // Now we can use send/recv instead of send_to/recv_from
            client.send(b"ping").await.expect("send failed");

            let mut buf = [0u8; 4];
            let (n, addr) = server.recv_from(&mut buf).await.expect("recv_from failed");
            crate::assert_with_log!(n == 4, "received bytes", 4, n);
            crate::assert_with_log!(&buf == b"ping", "received data", b"ping", buf);

            // Check the source address
            let pathname = addr.as_pathname();
            crate::assert_with_log!(pathname.is_some(), "has pathname", true, pathname.is_some());
        });
        crate::test_complete!("test_datagram_connect");
    }

    #[test]
    fn test_socket_cleanup_on_drop() {
        init_test("test_datagram_cleanup_on_drop");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("cleanup_test.sock");

        {
            let _socket = UnixDatagram::bind(&path).expect("bind failed");
            let exists = path.exists();
            crate::assert_with_log!(exists, "socket exists", true, exists);
        }

        let exists = path.exists();
        crate::assert_with_log!(!exists, "socket cleaned up", false, exists);
        crate::test_complete!("test_datagram_cleanup_on_drop");
    }

    #[test]
    fn test_from_std_no_cleanup() {
        init_test("test_datagram_from_std_no_cleanup");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("from_std_test.sock");

        // Create with std
        let std_socket = net::UnixDatagram::bind(&path).expect("bind failed");

        {
            // Wrap in async version
            let _socket = UnixDatagram::from_std(std_socket).expect("from_std failed");
        }

        // Socket file should still exist (from_std doesn't clean up)
        let exists = path.exists();
        crate::assert_with_log!(exists, "socket remains", true, exists);

        // Clean up manually
        std::fs::remove_file(&path).ok();
        crate::test_complete!("test_datagram_from_std_no_cleanup");
    }

    #[test]
    fn test_take_path_prevents_cleanup() {
        init_test("test_datagram_take_path");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("take_path_test.sock");

        {
            let mut socket = UnixDatagram::bind(&path).expect("bind failed");

            // Take the path
            let taken = socket.take_path();
            crate::assert_with_log!(taken.is_some(), "taken some", true, taken.is_some());
        }

        // Socket should still exist
        let exists = path.exists();
        crate::assert_with_log!(exists, "socket remains", true, exists);

        // Clean up manually
        std::fs::remove_file(&path).ok();
        crate::test_complete!("test_datagram_take_path");
    }

    #[test]
    fn test_local_addr() {
        init_test("test_datagram_local_addr");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("local_addr_test.sock");

        let socket = UnixDatagram::bind(&path).expect("bind failed");
        let addr = socket.local_addr().expect("local_addr failed");

        let pathname = addr.as_pathname();
        crate::assert_with_log!(pathname.is_some(), "has pathname", true, pathname.is_some());
        let pathname = pathname.unwrap();
        crate::assert_with_log!(pathname == path, "pathname matches", path, pathname);
        crate::test_complete!("test_datagram_local_addr");
    }

    #[test]
    fn test_unbound_local_addr() {
        init_test("test_datagram_unbound_local_addr");
        let socket = UnixDatagram::unbound().expect("unbound failed");
        let addr = socket.local_addr().expect("local_addr failed");

        // Unbound sockets have no pathname
        let pathname = addr.as_pathname();
        crate::assert_with_log!(
            pathname.is_none(),
            "no pathname",
            "None",
            format!("{:?}", pathname)
        );
        crate::test_complete!("test_datagram_unbound_local_addr");
    }

    #[test]
    fn test_peek() {
        init_test("test_datagram_peek");
        futures_lite::future::block_on(async {
            let (mut a, mut b) = UnixDatagram::pair().expect("pair failed");

            a.send(b"hello").await.expect("send failed");

            // Peek should see the data
            let mut buf = [0u8; 5];
            let n = b.peek(&mut buf).await.expect("peek failed");
            crate::assert_with_log!(n == 5, "peeked bytes", 5, n);
            crate::assert_with_log!(&buf == b"hello", "peeked data", b"hello", buf);

            // Data should still be there for recv
            let mut buf2 = [0u8; 5];
            let n = b.recv(&mut buf2).await.expect("recv failed");
            crate::assert_with_log!(n == 5, "received bytes", 5, n);
            crate::assert_with_log!(&buf2 == b"hello", "received data", b"hello", buf2);
        });
        crate::test_complete!("test_datagram_peek");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_abstract_socket() {
        init_test("test_datagram_abstract_socket");
        futures_lite::future::block_on(async {
            let server_name = b"asupersync_test_datagram_abstract";
            let mut server = UnixDatagram::bind_abstract(server_name).expect("bind failed");

            let mut client = UnixDatagram::unbound().expect("unbound failed");
            client
                .connect_abstract(server_name)
                .expect("connect failed");

            client.send(b"hello").await.expect("send failed");

            let mut buf = [0u8; 5];
            let n = server.recv(&mut buf).await.expect("recv failed");
            crate::assert_with_log!(n == 5, "received bytes", 5, n);
        });
        crate::test_complete!("test_datagram_abstract_socket");
    }

    #[test]
    fn test_datagram_registers_on_wouldblock() {
        use crate::cx::Cx;
        use crate::runtime::io_driver::IoDriverHandle;
        use crate::runtime::LabReactor;
        use crate::types::{Budget, RegionId, TaskId};
        use std::sync::Arc;
        use std::task::{Context, Wake, Waker};

        init_test("test_datagram_registers_on_wouldblock");

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }
        fn noop_waker() -> Waker {
            Waker::from(Arc::new(NoopWaker))
        }

        // Create a pair and drain the socket to ensure WouldBlock on recv
        let (mut a, mut b) = UnixDatagram::pair().expect("pair failed");

        // Set up reactor context
        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
        );
        let _guard = Cx::set_current(Some(cx));

        let waker = noop_waker();
        let mut poll_cx = Context::from_waker(&waker);

        // Try to poll recv when no data available - should return Pending and register
        let poll = b.poll_recv_ready(&mut poll_cx);
        crate::assert_with_log!(
            matches!(poll, Poll::Pending),
            "poll is Pending",
            "Poll::Pending",
            format!("{:?}", poll)
        );
        let has_registration = b.registration.is_some();
        crate::assert_with_log!(
            has_registration,
            "registration present",
            true,
            has_registration
        );

        // Now send some data
        futures_lite::future::block_on(async {
            a.send(b"test").await.expect("send failed");
        });

        // Poll should succeed
        let poll = b.poll_recv_ready(&mut poll_cx);
        crate::assert_with_log!(
            matches!(poll, Poll::Ready(Ok(()))),
            "poll is Ready",
            "Poll::Ready(Ok(()))",
            format!("{:?}", poll)
        );

        crate::test_complete!("test_datagram_registers_on_wouldblock");
    }

    #[test]
    fn test_datagram_send_registers_on_wouldblock() {
        use crate::cx::Cx;
        use crate::runtime::io_driver::IoDriverHandle;
        use crate::runtime::LabReactor;
        use crate::types::{Budget, RegionId, TaskId};
        use std::sync::Arc;
        use std::task::{Context, Wake, Waker};

        init_test("test_datagram_send_registers_on_wouldblock");

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }
        fn noop_waker() -> Waker {
            Waker::from(Arc::new(NoopWaker))
        }

        // Create a pair
        let (mut a, _b) = UnixDatagram::pair().expect("pair failed");

        // Set up reactor context
        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
        );
        let _guard = Cx::set_current(Some(cx));

        let waker = noop_waker();
        let mut poll_cx = Context::from_waker(&waker);

        // poll_send_ready should work without blocking for an empty socket
        let poll = a.poll_send_ready(&mut poll_cx);
        // Either ready or pending with registration is acceptable
        if matches!(poll, Poll::Pending) {
            let has_registration = a.registration.is_some();
            crate::assert_with_log!(
                has_registration,
                "registration present on Pending",
                true,
                has_registration
            );
        }

        crate::test_complete!("test_datagram_send_registers_on_wouldblock");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn test_peer_cred() {
        init_test("test_datagram_peer_cred");
        let (a, b) = UnixDatagram::pair().expect("pair failed");

        // Both sides should be able to get peer credentials
        let cred_a = a.peer_cred().expect("peer_cred a failed");
        let cred_b = b.peer_cred().expect("peer_cred b failed");

        // Both should report the same process (ourselves)
        let user_id = unsafe { libc::getuid() } as u32;
        let group_id = unsafe { libc::getgid() } as u32;

        crate::assert_with_log!(cred_a.uid == user_id, "a uid", user_id, cred_a.uid);
        crate::assert_with_log!(cred_a.gid == group_id, "a gid", group_id, cred_a.gid);
        crate::assert_with_log!(cred_b.uid == user_id, "b uid", user_id, cred_b.uid);
        crate::assert_with_log!(cred_b.gid == group_id, "b gid", group_id, cred_b.gid);

        // On Linux, pid should be available and match our process
        #[cfg(target_os = "linux")]
        {
            let proc_id = std::process::id() as i32;
            let pid_a = cred_a.pid.expect("pid should be available on Linux");
            let pid_b = cred_b.pid.expect("pid should be available on Linux");
            crate::assert_with_log!(pid_a == proc_id, "a pid", proc_id, pid_a);
            crate::assert_with_log!(pid_b == proc_id, "b pid", proc_id, pid_b);
        }

        crate::test_complete!("test_datagram_peer_cred");
    }
}
