//! Unix domain socket datagram implementation.
//!
//! This module provides [`UnixDatagram`] for connectionless communication over
//! Unix domain sockets.
//!
//! # Example
//!
//! ```
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

use crate::net::udp::{Armed, ReactorRegistration};
use crate::net::unix::stream::UCred;
use crate::runtime::reactor::Interest;
use nix::errno::Errno;
use nix::sys::socket::{self, MsgFlags, SockaddrLike};
use std::io;
use std::os::unix::net::{self, SocketAddr};
use std::path::{Path, PathBuf};
use std::task::{Context, Poll};

#[inline]
fn cancelled_poll<T>() -> Poll<io::Result<T>> {
    Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")))
}

#[inline]
fn empty_datagram_recv_from_buffer_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "UnixDatagram::recv_from requires a non-empty buffer",
    )
}

#[inline]
fn would_block_errno(errno: Errno) -> bool {
    errno == Errno::EAGAIN || errno == Errno::EWOULDBLOCK
}

#[inline]
fn errno_poll_error<T>(errno: Errno) -> Poll<io::Result<T>> {
    Poll::Ready(Err(io::Error::from_raw_os_error(errno as i32)))
}

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
/// When dropped, a bound datagram socket removes the socket file from the
/// filesystem
/// (unless it was created with [`from_std`](Self::from_std) or is an abstract
/// namespace socket).
///
/// Async methods take `&mut self` to avoid concurrent waiters clobbering
/// the single reactor registration/waker slot.
#[derive(Debug)]
pub struct UnixDatagram {
    /// Reactor registration for async I/O wakeup, aware of the process-global
    /// fallback I/O driver (GH#67, tx9j0f).
    registration: ReactorRegistration,
    /// The underlying standard library datagram socket.
    inner: net::UnixDatagram,
    /// Path to the socket file (for cleanup on drop).
    /// None for abstract namespace sockets, unbound sockets, or from_std().
    path: Option<PathBuf>,
    /// Device/inode identity captured at bind time for safe cleanup.
    cleanup_identity: Option<super::listener::SocketFileIdentity>,
}

impl UnixDatagram {
    fn from_bound_with<F>(path: &Path, inner: net::UnixDatagram, configure: F) -> io::Result<Self>
    where
        F: FnOnce(&net::UnixDatagram) -> io::Result<()>,
    {
        let (inner, cleanup_identity) =
            super::listener::finalize_bound_socket(path, inner, configure)?;

        Ok(Self {
            inner,
            path: Some(path.to_path_buf()),
            cleanup_identity,
            registration: ReactorRegistration::new(),
        })
    }

    /// Binds to a filesystem path.
    ///
    /// Creates a new Unix datagram socket bound to the specified path.
    /// If the path already exists, bind fails rather than deleting the existing entry.
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
        crate::cx::io_gate::require_ambient_io("net::UnixDatagram::bind")?;
        let path = path.as_ref();

        super::listener::reject_non_socket_bind_path(path)?;
        let inner = net::UnixDatagram::bind(path)?;
        Self::from_bound_with(path, inner, |socket| socket.set_nonblocking(true))
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

        crate::cx::io_gate::require_ambient_io("net::UnixDatagram::bind_abstract")?;
        let addr = SocketAddr::from_abstract_name(name)?;
        let inner = net::UnixDatagram::bind_addr(&addr)?;
        inner.set_nonblocking(true)?;

        Ok(Self {
            inner,
            path: None, // No filesystem path for abstract sockets
            cleanup_identity: None,
            registration: ReactorRegistration::new(),
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
            cleanup_identity: None,
            registration: ReactorRegistration::new(),
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
                cleanup_identity: None,
                registration: ReactorRegistration::new(),
            },
            Self {
                inner: s2,
                path: None,
                cleanup_identity: None,
                registration: ReactorRegistration::new(),
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
        crate::cx::io_gate::require_ambient_io("net::UnixDatagram::connect")?;
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

        crate::cx::io_gate::require_ambient_io("net::UnixDatagram::connect_abstract")?;
        let addr = SocketAddr::from_abstract_name(name)?;
        self.inner.connect_addr(&addr)
    }

    /// Register interest with the reactor for async wakeup.
    ///
    /// With no ambient I/O driver the fd parks on the process-global fallback
    /// driver instead of self-waking into a hot loop (GH#67,
    /// asupersync-tx9j0f); see [`ReactorRegistration::arm`].
    fn register_interest(&mut self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        if self.registration.arm(&self.inner, interest, cx.waker())? == Armed::SelfWake {
            crate::net::tcp::stream::fallback_rewake(cx);
        }
        Ok(())
    }

    fn pending_on_interest<T>(
        &mut self,
        cx: &Context<'_>,
        interest: Interest,
    ) -> Poll<io::Result<T>> {
        match self.register_interest(cx, interest) {
            Ok(()) => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
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
        crate::cx::io_gate::require_ambient_io("net::UnixDatagram::send_to")?;
        let path_ref = path.as_ref();
        std::future::poll_fn(|cx| {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return cancelled_poll();
            }
            match self.inner.send_to(buf, path_ref) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.pending_on_interest(cx, Interest::WRITABLE)
                }
                Err(e) => Poll::Ready(Err(e)),
            }
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
        if buf.is_empty() {
            return Err(empty_datagram_recv_from_buffer_error());
        }

        std::future::poll_fn(|cx| {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return cancelled_poll();
            }
            match self.inner.recv_from(buf) {
                Ok((n, addr)) => Poll::Ready(Ok((n, addr))),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.pending_on_interest(cx, Interest::READABLE)
                }
                Err(e) => Poll::Ready(Err(e)),
            }
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
        std::future::poll_fn(|cx| {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return cancelled_poll();
            }
            match self.inner.send(buf) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.pending_on_interest(cx, Interest::WRITABLE)
                }
                Err(e) => Poll::Ready(Err(e)),
            }
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
        std::future::poll_fn(|cx| {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return cancelled_poll();
            }
            match self.inner.recv(buf) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.pending_on_interest(cx, Interest::READABLE)
                }
                Err(e) => Poll::Ready(Err(e)),
            }
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
    /// For datagram sockets, Linux records peer credentials only for a socket
    /// pair created by [`pair`](Self::pair). An unconnected socket, or one
    /// connected with [`connect`](Self::connect), has none, and this returns an
    /// [`io::ErrorKind::NotConnected`] error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The kernel holds no peer credentials for this socket (see above)
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
            cleanup_identity: None,
            registration: ReactorRegistration::new(),
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
        self.cleanup_identity = None;
        self.path.take()
    }

    /// Polls for read readiness.
    ///
    /// This is useful for implementing custom poll loops.
    pub fn poll_recv_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::os::unix::io::AsRawFd;

        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }

        // For datagrams, a 1-byte MSG_PEEK probe checks readiness without consuming data.
        let mut buf = [0u8; 1];
        match socket::recv(
            self.inner.as_raw_fd(),
            &mut buf,
            MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(errno) if would_block_errno(errno) => {
                self.pending_on_interest(cx, Interest::READABLE)
            }
            Err(errno) => errno_poll_error(errno),
        }
    }

    /// Polls for write readiness.
    ///
    /// This is useful for implementing custom poll loops.
    pub fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::os::unix::io::AsFd;

        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }

        let mut fds = [PollFd::new(self.inner.as_fd(), PollFlags::POLLOUT)];
        match poll(&mut fds, PollTimeout::ZERO) {
            Ok(0) => self.pending_on_interest(cx, Interest::WRITABLE),
            Ok(_) => {
                let Some(revents) = fds[0].revents() else {
                    return Poll::Ready(Err(io::Error::other("poll returned unknown event bits")));
                };

                if revents.contains(PollFlags::POLLOUT) {
                    Poll::Ready(Ok(()))
                } else if revents
                    .intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                {
                    if let Ok(Some(err)) = self.inner.take_error() {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Err(io::Error::other(format!(
                        "poll indicates socket error: {revents:?}"
                    ))))
                } else {
                    self.pending_on_interest(cx, Interest::WRITABLE)
                }
            }
            Err(errno) => errno_poll_error(errno),
        }
    }

    /// Peeks at incoming data without consuming it.
    ///
    /// Like [`recv`](Self::recv), but the data remains in the receive buffer.
    pub async fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::io::AsRawFd;

        std::future::poll_fn(|cx| {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return cancelled_poll();
            }
            match socket::recv(
                self.inner.as_raw_fd(),
                buf,
                MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(errno) if would_block_errno(errno) => {
                    self.pending_on_interest(cx, Interest::READABLE)
                }
                Err(errno) => errno_poll_error(errno),
            }
        })
        .await
    }

    fn socket_addr_from_unix_addr(addr: &socket::UnixAddr) -> io::Result<SocketAddr> {
        fn get_unnamed() -> io::Result<SocketAddr> {
            static UNNAMED: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
            if let Some(addr) = UNNAMED.get() {
                return Ok(addr.clone());
            }
            let addr = net::UnixDatagram::unbound()?.local_addr()?;
            let _ = UNNAMED.set(addr.clone());
            Ok(addr)
        }

        if addr.len() as usize <= std::mem::offset_of!(libc::sockaddr_un, sun_path) {
            return get_unnamed();
        }

        if let Some(path) = addr.path() {
            // macOS/BSD report an unbound sender as a zero-filled sun_path
            // with a non-zero length; std would refuse the interior NULs.
            // That is the unnamed address (br-asupersync-bi2462.21.4).
            let bytes = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str());
            if bytes.iter().all(|byte| *byte == 0) {
                return get_unnamed();
            }
            return SocketAddr::from_pathname(path)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        }

        #[cfg(target_os = "linux")]
        if let Some(name) = addr.as_abstract() {
            use std::os::linux::net::SocketAddrExt;
            return <SocketAddr as SocketAddrExt>::from_abstract_name(name)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        }

        // std does not expose a public constructor for unnamed unix socket
        // addresses, so synthesize one through a temporary unbound socket.
        get_unnamed()
    }

    /// Peeks at incoming data and returns the source address.
    ///
    /// Like [`recv_from`](Self::recv_from), but the data remains in the receive buffer.
    pub async fn peek_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        use std::io::IoSliceMut;
        use std::os::unix::io::AsRawFd;

        std::future::poll_fn(|cx| {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return cancelled_poll();
            }
            let mut iov = [IoSliceMut::new(buf)];
            match socket::recvmsg::<socket::UnixAddr>(
                self.inner.as_raw_fd(),
                &mut iov,
                None,
                MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(msg) => {
                    let Some(addr) = msg.address else {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unix datagram recvmsg missing source address",
                        )));
                    };
                    let addr = Self::socket_addr_from_unix_addr(&addr)?;
                    Poll::Ready(Ok((msg.bytes, addr)))
                }
                Err(errno) if would_block_errno(errno) => {
                    self.pending_on_interest(cx, Interest::READABLE)
                }
                Err(errno) => errno_poll_error(errno),
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
        // Clean up only the socket file we originally created.
        if let (Some(path), Some(identity)) = (&self.path, self.cleanup_identity) {
            let _ = super::listener::remove_socket_file_if_same_inode(path, identity);
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
    use nix::sys::socket::sockopt;
    let cred = socket::getsockopt(socket, sockopt::PeerCredentials)
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    // SO_PEERCRED also succeeds on a datagram socket the kernel holds no peer
    // credentials for (an unconnected socket, or one connected with connect()
    // rather than created by pair()). It then reports uid and gid -1, which
    // must not be handed out as a peer identity
    // (br-asupersync-unix-socket-audit-alx18f). pid 0 alone is no signal: it
    // also appears for a peer in another PID namespace.
    if cred.uid() as u32 == u32::MAX && cred.gid() as u32 == u32::MAX {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "peer credentials are not available: the kernel records them only for a \
             unix datagram socket pair created by pair()",
        ));
    }
    Ok(UCred {
        uid: cred.uid() as u32,
        gid: cred.gid() as u32,
        pid: Some(cred.pid()),
    })
}

/// macOS/BSD implementation using getpeereid.
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn datagram_peer_cred_impl(socket: &net::UnixDatagram) -> io::Result<UCred> {
    let (uid, gid) = nix::unistd::getpeereid(socket).map_err(|e| match e {
        // LOCAL_PEERCRED (what getpeereid reads) is defined for connected
        // stream sockets; a datagram socket pair answers EINVAL on macOS.
        // That is a typed capability gap, not a transient failure
        // (br-asupersync-bi2462.21.4).
        nix::errno::Errno::EINVAL | nix::errno::Errno::ENOTCONN | nix::errno::Errno::EOPNOTSUPP => {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "peer credentials are not available for unix datagram sockets on this \
                 platform (LOCAL_PEERCRED requires a connected stream socket)",
            )
        }
        other => io::Error::from_raw_os_error(other as i32),
    })?;
    Ok(UCred {
        uid: uid.as_raw(),
        gid: gid.as_raw(),
        pid: None, // Not available via getpeereid
    })
}

#[cfg(test)]
#[path = "datagram_inline_tests.rs"]
mod tests;
