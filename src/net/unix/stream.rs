//! Unix domain socket stream implementation.
//!
//! This module provides [`UnixStream`] for bidirectional communication over
//! Unix domain sockets.
//!
//! # Example
//!
//! ```
//! use asupersync::net::unix::UnixStream;
//! use asupersync::io::AsyncWriteExt;
//!
//! async fn client() -> std::io::Result<()> {
//!     let mut stream = UnixStream::connect("/tmp/my_socket.sock").await?;
//!     stream.write_all(b"hello").await?;
//!     Ok(())
//! }
//! ```

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncReadVectored, AsyncWrite, ReadBuf};
use crate::net::udp::{Armed, ReactorRegistration};
use crate::net::unix::split::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf};
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use nix::sys::socket::{self, ControlMessage, MsgFlags};
use parking_lot::Mutex;
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::Shutdown;
use std::os::unix::io::RawFd;
use std::os::unix::net::{self, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

fn connect_in_progress(err: &io::Error) -> bool {
    // A full AF_UNIX backlog returns EAGAIN and abandons the attempt, so it is
    // returned as WouldBlock, as tokio does; waiting for writability waited,
    // spinning, for a connection that would never be made.
    err.kind() == io::ErrorKind::Interrupted || err.raw_os_error() == Some(libc::EINPROGRESS)
}

fn cancelled_poll<T>() -> Poll<io::Result<T>> {
    Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")))
}

async fn wait_for_connect(socket: &Socket) -> io::Result<Option<IoRegistration>> {
    if !crate::net::udp::ambient_io_driver_present() {
        wait_for_connect_fallback(socket).await?;
        return Ok(None);
    }

    let mut registration: Option<IoRegistration> = None;
    let mut fallback = false;
    std::future::poll_fn(|cx| {
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }

        if let Some(err) = socket.take_error()? {
            return Poll::Ready(Err(err));
        }

        match socket.peer_addr() {
            Ok(_) => Poll::Ready(Ok(())),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                if let Err(err) = rearm_connect_registration(&mut registration, cx) {
                    return Poll::Ready(Err(err));
                }

                if registration.is_none() {
                    // Resolve the polling executor's driver here. A connect
                    // future must not retain its original dispatcher across
                    // await or register on a live but idle old runtime (GH#85).
                    let Some(driver) = Cx::current().and_then(|cx| cx.io_driver_handle()) else {
                        fallback = true;
                        return Poll::Ready(Ok(()));
                    };
                    match driver.register(socket, Interest::WRITABLE, cx.waker().clone()) {
                        Ok(new_reg) => registration = Some(new_reg),
                        Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                            fallback = true;
                            return Poll::Ready(Ok(()));
                        }
                        Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                            fallback = true;
                            return Poll::Ready(Ok(()));
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    }
                }

                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    })
    .await?;

    if fallback {
        wait_for_connect_fallback(socket).await?;
        return Ok(None);
    }

    Ok(registration)
}

fn rearm_connect_registration(
    registration: &mut Option<IoRegistration>,
    cx: &Context<'_>,
) -> io::Result<()> {
    if registration
        .as_ref()
        .is_some_and(|existing| crate::net::udp::registration_needs_migration(existing, false))
    {
        *registration = None;
        return Ok(());
    }
    let Some(existing) = registration.as_mut() else {
        return Ok(());
    };

    match existing.rearm(Interest::WRITABLE, cx.waker()) {
        Ok(true) => Ok(()),
        Ok(false) => {
            *registration = None;
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotConnected => {
            *registration = None;
            crate::net::tcp::stream::fallback_rewake(cx);
            Ok(())
        }
        Err(err) => Err(err),
    }
}

async fn wait_for_connect_fallback(socket: &Socket) -> io::Result<()> {
    std::future::poll_fn(|cx| {
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }

        if let Some(err) = socket.take_error()? {
            return Poll::Ready(Err(err));
        }

        match socket.peer_addr() {
            Ok(_) => Poll::Ready(Ok(())),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    })
    .await
}

fn nix_to_io(err: nix::Error) -> io::Error {
    // nix::Error is a type alias to nix::errno::Errno (Copy + Eq, etc).
    io::Error::from_raw_os_error(err as i32)
}

/// Credentials of the peer process.
///
/// This struct contains the user ID, group ID, and optionally the process ID
/// of the process on the other end of a Unix domain socket connection.
///
/// # Platform-Specific Behavior
///
/// - On Linux: All fields are populated using `SO_PEERCRED`.
/// - On macOS/BSD: `uid` and `gid` are populated using `getpeereid()`;
///   `pid` is `None` as it's not available through this API.
///
/// # Example
///
/// ```ignore
/// let stream = UnixStream::connect("/tmp/my_socket.sock").await?;
/// let cred = stream.peer_cred()?;
/// println!("Peer: uid={}, gid={}, pid={:?}", cred.uid, cred.gid, cred.pid);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UCred {
    /// User ID of the peer process.
    pub uid: u32,
    /// Group ID of the peer process.
    pub gid: u32,
    /// Process ID of the peer process.
    ///
    /// This is `None` on platforms where it's not available (e.g., macOS/BSD).
    pub pid: Option<i32>,
}

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
    /// Reactor registration for I/O events (lazily initialized), aware of
    /// the process-global fallback I/O driver (GH#67, tx9j0f).
    registration: Mutex<ReactorRegistration>,
    /// The underlying standard library stream.
    pub(crate) inner: Arc<net::UnixStream>,
}

impl UnixStream {
    /// Creates a UnixStream from raw parts (internal use).
    #[must_use]
    pub(crate) fn from_parts(
        inner: Arc<net::UnixStream>,
        registration: (Option<IoRegistration>, bool),
    ) -> Self {
        Self {
            inner,
            registration: Mutex::new(ReactorRegistration::from_parts(registration)),
        }
    }

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
        crate::cx::io_gate::require_ambient_io("net::UnixStream::connect")?;
        let domain = Domain::UNIX;
        let socket = Socket::new(domain, Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        let sock_addr = SockAddr::unix(path)?;
        let registration = match socket.connect(&sock_addr) {
            Ok(()) => None,
            Err(err) if connect_in_progress(&err) => wait_for_connect(&socket).await?,
            Err(err) => return Err(err),
        };

        let inner: net::UnixStream = socket.into();
        Ok(Self {
            inner: Arc::new(inner),
            registration: Mutex::new(ReactorRegistration::from_registration(registration)),
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
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::path::PathBuf;
        crate::cx::io_gate::require_ambient_io("net::UnixStream::connect_abstract")?;
        // `socket2::SockAddr` can represent Linux abstract namespace addresses
        // by encoding a leading NUL byte in the AF_UNIX path bytes.
        let mut path_bytes = Vec::with_capacity(name.len() + 1);
        path_bytes.push(0);
        path_bytes.extend_from_slice(name);

        let abstract_path = PathBuf::from(OsString::from_vec(path_bytes));
        let domain = Domain::UNIX;
        let socket = Socket::new(domain, Type::STREAM, None)?;
        socket.set_nonblocking(true)?;

        let sock_addr = SockAddr::unix(abstract_path)?;
        let registration = match socket.connect(&sock_addr) {
            Ok(()) => None,
            Err(err) if connect_in_progress(&err) => wait_for_connect(&socket).await?,
            Err(err) => return Err(err),
        };

        let inner: net::UnixStream = socket.into();
        Ok(Self {
            inner: Arc::new(inner),
            registration: Mutex::new(ReactorRegistration::from_registration(registration)),
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
                registration: Mutex::new(ReactorRegistration::new()),
            },
            Self {
                inner: Arc::new(s2),
                registration: Mutex::new(ReactorRegistration::new()),
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
    ///
    /// # Errors
    ///
    /// Returns an error if setting non-blocking mode fails.
    pub fn from_std(stream: net::UnixStream) -> io::Result<Self> {
        // Ensure async poll paths do not inherit blocking sockets.
        stream.set_nonblocking(true)?;
        Ok(Self {
            inner: Arc::new(stream),
            registration: Mutex::new(ReactorRegistration::new()),
        })
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

    fn pending_on_interest<T>(&self, cx: &Context<'_>, interest: Interest) -> Poll<io::Result<T>> {
        match self.register_interest(cx, interest) {
            Ok(()) => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    /// Registers interest with the I/O driver.
    ///
    /// With no ambient I/O driver the fd parks on the process-global fallback
    /// driver instead of self-waking into a hot loop (GH#67,
    /// asupersync-tx9j0f); see [`ReactorRegistration::arm`]. The lock is
    /// released before any self-wake so a re-poll cannot contend on it.
    fn register_interest(&self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        let armed = self
            .registration
            .lock()
            .arm(&*self.inner, interest, cx.waker())?;
        if armed == Armed::SelfWake {
            crate::net::tcp::stream::fallback_rewake(cx);
        }
        Ok(())
    }

    /// Returns the credentials of the peer process.
    ///
    /// This can be used to verify the identity of the process on the other
    /// end of the connection for security purposes.
    ///
    /// # Platform-Specific Behavior
    ///
    /// - On Linux: Uses `SO_PEERCRED` socket option to retrieve uid, gid, and pid.
    /// - On macOS/FreeBSD/OpenBSD/NetBSD: Uses `getpeereid()` to retrieve uid and gid;
    ///   pid is not available.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieving credentials fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let stream = UnixStream::connect("/tmp/my_socket.sock").await?;
    /// let cred = stream.peer_cred()?;
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
        peer_cred_impl(&self.inner)
    }

    /// Sends data along with ancillary data (control messages).
    ///
    /// This method is primarily used for passing file descriptors between
    /// processes using `SCM_RIGHTS`.
    ///
    /// # Arguments
    ///
    /// * `buf` - The data to send
    /// * `ancillary` - The ancillary data to send with the message
    ///
    /// # Returns
    ///
    /// The number of bytes from `buf` that were sent.
    ///
    /// # Errors
    ///
    /// Returns an error if the send fails, or if `buf` is empty while file
    /// descriptors are queued in `ancillary`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::net::unix::{UnixStream, SocketAncillary};
    /// use std::os::unix::io::AsRawFd;
    ///
    /// let (tx, rx) = UnixStream::pair()?;
    /// let file = std::fs::File::open("/etc/passwd")?;
    ///
    /// let mut ancillary = SocketAncillary::new(128);
    /// ancillary.add_fds(&[file.as_raw_fd()]);
    ///
    /// let n = tx.send_with_ancillary(b"file attached", &mut ancillary).await?;
    /// ```
    #[allow(clippy::future_not_send)]
    pub async fn send_with_ancillary(
        &self,
        buf: &[u8],
        ancillary: &mut crate::net::unix::SocketAncillary,
    ) -> io::Result<usize> {
        use std::os::unix::io::AsRawFd;
        let waiter = SharedWaiterEntry::new(self);
        std::future::poll_fn(|cx| {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return cancelled_poll();
            }

            match send_with_ancillary_impl(self.inner.as_raw_fd(), buf, ancillary) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    waiter.pending(cx, Interest::WRITABLE)
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        })
        .await
    }

    /// Receives data along with ancillary data (control messages).
    ///
    /// This method is primarily used for receiving file descriptors passed
    /// between processes using `SCM_RIGHTS`.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to receive data into
    /// * `ancillary` - Buffer to receive ancillary data into
    ///
    /// # Returns
    ///
    /// The number of bytes received into `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error if the receive fails.
    ///
    /// # Safety
    ///
    /// When file descriptors are received, the caller is responsible for
    /// managing their lifetimes. See [`SocketAncillary::messages`] for details.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::net::unix::{UnixStream, SocketAncillary, AncillaryMessage};
    /// use nix::unistd;
    ///
    /// let mut buf = [0u8; 64];
    /// let mut ancillary = SocketAncillary::new(128);
    ///
    /// let n = rx.recv_with_ancillary(&mut buf, &mut ancillary).await?;
    ///
    /// for msg in ancillary.messages() {
    ///     if let AncillaryMessage::ScmRights(fds) = msg {
    ///         for fd in fds {
    ///             // Use the fd, then close it (or wrap it in an owned type).
    ///             let _ = unistd::close(fd);
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// [`SocketAncillary::messages`]: crate::net::unix::SocketAncillary::messages
    #[allow(clippy::future_not_send)]
    pub async fn recv_with_ancillary(
        &self,
        buf: &mut [u8],
        ancillary: &mut crate::net::unix::SocketAncillary,
    ) -> io::Result<usize> {
        use std::os::unix::io::AsRawFd;
        let waiter = SharedWaiterEntry::new(self);
        std::future::poll_fn(|cx| {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return cancelled_poll();
            }

            match recv_with_ancillary_impl(self.inner.as_raw_fd(), buf, ancillary) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    waiter.pending(cx, Interest::READABLE)
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        })
        .await
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
        let (registration, registration_on_fallback) = self.registration.lock().take_parts();
        OwnedReadHalf::new_pair_with_fallback_flag(
            self.inner,
            registration,
            registration_on_fallback,
        )
    }
}

impl AsyncRead for UnixStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        let inner: &net::UnixStream = &self.inner;
        // std::os::unix::net::UnixStream implements Read for &UnixStream
        match (&*inner).read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.pending_on_interest(cx, Interest::READABLE)
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncReadVectored for UnixStream {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        let inner: &net::UnixStream = &self.inner;
        match (&*inner).read_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.pending_on_interest(cx, Interest::READABLE)
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
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        let inner: &net::UnixStream = &self.inner;
        match (&*inner).write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.pending_on_interest(cx, Interest::WRITABLE)
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        let inner: &net::UnixStream = &self.inner;
        match (&*inner).write_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.pending_on_interest(cx, Interest::WRITABLE)
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        let inner: &net::UnixStream = &self.inner;
        match (&*inner).flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.pending_on_interest(cx, Interest::WRITABLE)
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        match self.inner.shutdown(Shutdown::Write) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
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

// Platform-specific peer credential implementations

/// Linux implementation using SO_PEERCRED.
#[cfg(target_os = "linux")]
fn peer_cred_impl(stream: &net::UnixStream) -> io::Result<UCred> {
    let creds = socket::getsockopt(stream, socket::sockopt::PeerCredentials).map_err(nix_to_io)?;
    Ok(UCred {
        uid: creds.uid() as u32,
        gid: creds.gid() as u32,
        pid: Some(creds.pid() as i32),
    })
}

/// macOS/BSD implementation using getpeereid.
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn peer_cred_impl(stream: &net::UnixStream) -> io::Result<UCred> {
    let (uid, gid) = nix::unistd::getpeereid(stream).map_err(nix_to_io)?;
    Ok(UCred {
        uid: uid.as_raw(),
        gid: gid.as_raw(),
        pid: None,
    })
}

// Ancillary data send/receive implementations using sendmsg/recvmsg

/// Sends data with ancillary data using sendmsg.
fn send_with_ancillary_impl(
    fd: std::os::unix::io::RawFd,
    buf: &[u8],
    ancillary: &mut crate::net::unix::SocketAncillary,
) -> io::Result<usize> {
    if buf.is_empty() && !ancillary.send_fds().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot send file descriptors with an empty buffer on a stream socket",
        ));
    }

    let iov = [IoSlice::new(buf)];

    let cmsgs_storage;
    let cmsgs: &[ControlMessage<'_>] = if ancillary.send_fds().is_empty() {
        &[]
    } else {
        cmsgs_storage = [ControlMessage::ScmRights(ancillary.send_fds())];
        &cmsgs_storage
    };

    let n = socket::sendmsg::<()>(fd, &iov, cmsgs, MsgFlags::empty(), None).map_err(nix_to_io)?;
    ancillary.clear_send_fds();
    Ok(n)
}

/// Receives data with ancillary data using recvmsg.
fn recv_with_ancillary_impl(
    fd: RawFd,
    buf: &mut [u8],
    ancillary: &mut crate::net::unix::SocketAncillary,
) -> io::Result<usize> {
    let (bytes, received_fds, truncated) = {
        let cmsg_buf = ancillary.prepare_for_recv();
        recvmsg_with_raw_ancillary(fd, buf, cmsg_buf)
    }?;

    if !received_fds.is_empty() {
        ancillary.push_received_fds(&received_fds);
    }
    if truncated {
        ancillary.mark_truncated();
    }

    Ok(bytes)
}

#[allow(unsafe_code)]
fn recvmsg_with_raw_ancillary(
    fd: RawFd,
    buf: &mut [u8],
    cmsg_buf: &mut [u8],
) -> io::Result<(usize, Vec<RawFd>, bool)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let (control_ptr, control_len) = if cmsg_buf.is_empty() {
        (std::ptr::null_mut(), 0)
    } else {
        (cmsg_buf.as_mut_ptr().cast(), cmsg_buf.len())
    };

    // SAFETY: `iov` points at the caller-provided mutable data buffer for the
    // duration of the syscall, `cmsg_buf` is initialized and writable for
    // `control_len` bytes, and parsing walks only headers accepted by libc's
    // CMSG_* helpers bounded by the kernel-written `msg_controllen`.
    let (bytes, received_fds, truncated) = unsafe {
        let mut msg = std::mem::zeroed::<libc::msghdr>();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control_ptr;
        // `msg_controllen` is `size_t` on glibc but `socklen_t` (u32) on musl,
        // so a plain `usize` assignment fails to compile under
        // `*-unknown-linux-musl`. Use a checked conversion on every target;
        // it is a no-op widening on glibc and a safe narrowing on musl.
        msg.msg_controllen = control_len.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ancillary buffer length exceeds msg_controllen",
            )
        })?;

        // Received descriptors are close-on-exec, as std makes them, so they
        // do not leak into every child process the receiver spawns.
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly",
        ))]
        let flags = libc::MSG_CMSG_CLOEXEC;
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly",
        )))]
        let flags = 0;
        let bytes = loop {
            let rc = libc::recvmsg(fd, &mut msg, flags);
            if rc >= 0 {
                break usize::try_from(rc).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "recvmsg byte count overflow")
                })?;
            }

            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        };

        let mut received_fds = Vec::new();
        // End of the control bytes the kernel actually wrote.
        let control_end = msg
            .msg_control
            .addr()
            .saturating_add(usize::try_from(msg.msg_controllen).unwrap_or(0));
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            // The control buffer is a byte buffer: read the header unaligned.
            let header = std::ptr::read_unaligned(cmsg);
            if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
                let header_len = libc::CMSG_LEN(0) as usize;
                let cmsg_len = header.cmsg_len as usize;
                if cmsg_len >= header_len {
                    let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                    let fd_count = scm_rights_fd_count(
                        cmsg_len - header_len,
                        control_end.saturating_sub(data.addr()),
                    );
                    for index in 0..fd_count {
                        let received_fd = std::ptr::read_unaligned(data.add(index));
                        if received_fd >= 0 {
                            // No MSG_CMSG_CLOEXEC here (macOS): set the flag
                            // on each descriptor instead.
                            #[cfg(not(any(
                                target_os = "linux",
                                target_os = "android",
                                target_os = "freebsd",
                                target_os = "netbsd",
                                target_os = "openbsd",
                                target_os = "dragonfly",
                            )))]
                            libc::fcntl(received_fd, libc::F_SETFD, libc::FD_CLOEXEC);
                            received_fds.push(received_fd);
                        }
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }

        let truncated = (msg.msg_flags & libc::MSG_CTRUNC) != 0;
        (bytes, received_fds, truncated)
    };

    Ok((bytes, received_fds, truncated))
}

/// Descriptors an SCM_RIGHTS message carries within the control bytes the
/// kernel copied: `payload_len` is what its header claims, `available` the
/// bytes from its payload to the kernel-written end of the control buffer.
/// XNU and FreeBSD keep the sender's `cmsg_len` when MSG_CTRUNC cut the
/// payload, so counting from the header alone read past the buffer and
/// returned garbage as descriptors (br-asupersync-8vrx8q).
fn scm_rights_fd_count(payload_len: usize, available: usize) -> usize {
    payload_len.min(available) / std::mem::size_of::<RawFd>()
}

impl UnixStream {
    /// `Pending` for the `&self` ancillary methods, which several tasks can
    /// wait in at once through a shared stream. Each caller joins the
    /// registration's shared waiter list instead of replacing its waker, so
    /// a reader parked before a writer is still woken when data arrives
    /// (br-asupersync-unix-socket-audit-alx18f).
    fn pending_on_shared_interest<T>(
        &self,
        cx: &Context<'_>,
        interest: Interest,
        owner: u64,
    ) -> Poll<io::Result<T>> {
        let (armed, stranded, displaced) =
            self.registration
                .lock()
                .arm_shared(&*self.inner, interest, owner, cx.waker());
        // The registration lock was released at the end of the statement
        // above; the waker this call replaced drops only now.
        drop(displaced);
        for waiter in stranded {
            waiter.wake();
        }
        match armed {
            Ok(Armed::Parked) => Poll::Pending,
            Ok(Armed::SelfWake) => {
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

/// One `&self` ancillary call's entry in the stream's shared waiter list.
/// The call future owns it: a re-poll updates the entry in place, and
/// dropping the future removes it. So any number of calls can wait at once,
/// and none is evicted to make room for another, which with 33 or more
/// waiting calls had them wake each other forever
/// (br-asupersync-reactor-audit-dofi11).
struct SharedWaiterEntry<'a> {
    stream: &'a UnixStream,
    owner: u64,
}

impl<'a> SharedWaiterEntry<'a> {
    fn new(stream: &'a UnixStream) -> Self {
        Self {
            stream,
            owner: crate::net::udp::next_shared_waiter_owner(),
        }
    }

    fn pending<T>(&self, cx: &Context<'_>, interest: Interest) -> Poll<io::Result<T>> {
        self.stream
            .pending_on_shared_interest(cx, interest, self.owner)
    }
}

impl Drop for SharedWaiterEntry<'_> {
    fn drop(&mut self) {
        // A surviving call may need to move the registration away from this
        // call's now-idle runtime. Drop and wake only after both the waiter
        // list and registration locks are released (GH#85).
        let (removed, survivors) = self.stream.registration.lock().forget_shared(self.owner);
        drop(removed);
        for waiter in survivors {
            waiter.wake();
        }
    }
}

#[cfg(test)]
#[path = "stream_inline_tests.rs"]
mod tests;
