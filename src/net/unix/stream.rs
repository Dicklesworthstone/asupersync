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

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncReadVectored, AsyncWrite, ReadBuf};
use crate::net::unix::split::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf};
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use nix::errno::Errno;
use nix::sys::socket::{self, ControlMessage, ControlMessageOwned, MsgFlags};
use parking_lot::Mutex;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{self, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use socket2::{Domain, SockAddr, Socket, Type};

fn connect_in_progress(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) || err.raw_os_error() == Some(libc::EINPROGRESS)
}

async fn wait_for_connect(socket: &Socket) -> io::Result<Option<IoRegistration>> {
    let Some(driver) = Cx::current().and_then(|cx| cx.io_driver_handle()) else {
        wait_for_connect_fallback(socket).await?;
        return Ok(None);
    };

    let mut registration: Option<IoRegistration> = None;
    let mut fallback = false;
    std::future::poll_fn(|cx| {
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
                    match driver.register(socket, Interest::WRITABLE, cx.waker().clone()) {
                        Ok(new_reg) => registration = Some(new_reg),
                        Err(err) if err.kind() == io::ErrorKind::Unsupported => {
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
            cx.waker().wake_by_ref();
            Ok(())
        }
        Err(err) => Err(err),
    }
}

async fn wait_for_connect_fallback(socket: &Socket) -> io::Result<()> {
    loop {
        if let Some(err) = socket.take_error()? {
            return Err(err);
        }

        match socket.peer_addr() {
            Ok(_) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                std::thread::sleep(Duration::from_millis(1));
                crate::runtime::yield_now().await;
            }
            Err(err) => return Err(err),
        }
    }
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
    /// The underlying standard library stream.
    pub(crate) inner: Arc<net::UnixStream>,
    /// Reactor registration for I/O events (lazily initialized).
    registration: Mutex<Option<IoRegistration>>,
}

impl UnixStream {
    /// Creates a UnixStream from raw parts (internal use).
    #[must_use]
    pub(crate) fn from_parts(
        inner: Arc<net::UnixStream>,
        registration: Option<IoRegistration>,
    ) -> Self {
        Self {
            inner,
            registration: Mutex::new(registration), // Lazy registration on first I/O
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
            registration: Mutex::new(registration),
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

        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
        let domain = Domain::UNIX;
        let socket = Socket::new(domain, Type::STREAM, None)?;
        socket.set_nonblocking(true)?;

        let sock_addr = SockAddr::from(addr);
        let registration = match socket.connect(&sock_addr) {
            Ok(()) => None,
            Err(err) if connect_in_progress(&err) => wait_for_connect(&socket).await?,
            Err(err) => return Err(err),
        };

        let inner: net::UnixStream = socket.into();
        Ok(Self {
            inner: Arc::new(inner),
            registration: Mutex::new(registration),
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
                registration: Mutex::new(None), // Lazy registration on first I/O
            },
            Self {
                inner: Arc::new(s2),
                registration: Mutex::new(None), // Lazy registration on first I/O
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
            registration: Mutex::new(None), // Lazy registration on first I/O
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

    /// Registers interest with the I/O driver for read events.
    fn register_interest_for_read(&self, cx: &Context<'_>) -> io::Result<()> {
        self.register_interest(cx, Interest::READABLE)
    }

    /// Registers interest with the I/O driver for write events.
    fn register_interest_for_write(&self, cx: &Context<'_>) -> io::Result<()> {
        self.register_interest(cx, Interest::WRITABLE)
    }

    /// Registers interest with the I/O driver.
    fn register_interest(&self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        let mut registration = self.registration.lock();

        if let Some(existing) = registration.as_mut() {
            let merged = existing.interest() | interest;
            // Re-arm reactor interest and conditionally update the waker in a
            // single lock acquisition (will_wake guard skips the clone).
            match existing.rearm(merged, cx.waker()) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    *registration = None;
                }
                Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                    *registration = None;
                    cx.waker().wake_by_ref();
                    return Ok(());
                }
                Err(err) => return Err(err),
            }
        }

        let Some(current) = Cx::current() else {
            drop(registration);
            cx.waker().wake_by_ref();
            return Ok(());
        };
        let Some(driver) = current.io_driver_handle() else {
            drop(registration);
            cx.waker().wake_by_ref();
            return Ok(());
        };

        match driver.register(&*self.inner, interest, cx.waker().clone()) {
            Ok(new_reg) => {
                *registration = Some(new_reg);
                drop(registration);
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                drop(registration);
                cx.waker().wake_by_ref();
                Ok(())
            }
            Err(err) => {
                drop(registration);
                Err(err)
            }
        }
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
    /// Returns an error if the send fails.
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

        std::future::poll_fn(|cx| {
            match send_with_ancillary_impl(self.inner.as_raw_fd(), buf, ancillary) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(e) = self.register_interest_for_write(cx) {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending
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

        std::future::poll_fn(|cx| {
            match recv_with_ancillary_impl(self.inner.as_raw_fd(), buf, ancillary) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(e) = self.register_interest_for_read(cx) {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending
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
        let registration = self.registration.lock().take();
        OwnedReadHalf::new_pair(self.inner, registration)
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
                if let Err(e) = self.register_interest_for_read(cx) {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending
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
        let inner: &net::UnixStream = &self.inner;
        match (&*inner).read_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(e) = self.register_interest_for_read(cx) {
                    return Poll::Ready(Err(e));
                }
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
                if let Err(e) = self.register_interest_for_write(cx) {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let inner: &net::UnixStream = &self.inner;
        match (&*inner).write_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(e) = self.register_interest_for_write(cx) {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner: &net::UnixStream = &self.inner;
        match (&*inner).flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(e) = self.register_interest_for_write(cx) {
                    return Poll::Ready(Err(e));
                }
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
        uid: uid.as_raw() as u32,
        gid: gid.as_raw() as u32,
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
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
    ancillary: &mut crate::net::unix::SocketAncillary,
) -> io::Result<usize> {
    let mut iov = [IoSliceMut::new(buf)];

    // `recvmsg` returns a value that borrows the control-message buffer. Keep that borrow
    // scoped so we can update `ancillary` after parsing the received control messages.
    let (bytes, received_fds, truncated) = {
        let cmsg_buf = ancillary.prepare_for_recv();
        let msg = socket::recvmsg::<()>(fd, &mut iov, Some(cmsg_buf), MsgFlags::empty())
            .map_err(nix_to_io)?;

        let mut received_fds: Vec<std::os::unix::io::RawFd> = Vec::new();
        let mut truncated = false;

        match msg.cmsgs() {
            Ok(iter) => {
                for cmsg in iter {
                    if let ControlMessageOwned::ScmRights(fds) = cmsg {
                        received_fds.extend_from_slice(&fds);
                    }
                }
            }
            Err(Errno::ENOBUFS) => {
                truncated = true;
            }
            Err(errno) => {
                return Err(io::Error::from_raw_os_error(errno as i32));
            }
        }

        Ok::<_, io::Error>((msg.bytes, received_fds, truncated))
    }?;

    if !received_fds.is_empty() {
        ancillary.push_received_fds(&received_fds);
    }
    if truncated {
        ancillary.mark_truncated();
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use std::io::{self, IoSlice, IoSliceMut, Read};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_pair() {
        init_test("test_pair");
        let (mut s1, mut s2) = UnixStream::pair().expect("pair failed");

        std::io::Write::write_all(&mut s1, b"hello").expect("write failed");
        let mut buf = [0u8; 5];
        s2.read_exact(&mut buf).expect("read failed");

        crate::assert_with_log!(&buf == b"hello", "buf", b"hello", buf);
        crate::test_complete!("test_pair");
    }

    #[test]
    fn test_local_peer_addr() {
        init_test("test_local_peer_addr");
        let (s1, s2) = UnixStream::pair().expect("pair failed");

        // Unnamed sockets from pair() don't have pathname addresses
        let local = s1.local_addr().expect("local_addr failed");
        let peer = s2.peer_addr().expect("peer_addr failed");

        // Both should be unnamed (no pathname)
        let local_path = local.as_pathname();
        crate::assert_with_log!(
            local_path.is_none(),
            "local no pathname",
            "None",
            format!("{:?}", local_path)
        );
        let peer_path = peer.as_pathname();
        crate::assert_with_log!(
            peer_path.is_none(),
            "peer no pathname",
            "None",
            format!("{:?}", peer_path)
        );
        crate::test_complete!("test_local_peer_addr");
    }

    #[test]
    fn test_shutdown() {
        init_test("test_shutdown");
        let (s1, _s2) = UnixStream::pair().expect("pair failed");

        // Shutdown should succeed
        s1.shutdown(Shutdown::Write).expect("shutdown failed");
        crate::test_complete!("test_shutdown");
    }

    #[test]
    fn test_split() {
        init_test("test_split");
        let (s1, _s2) = UnixStream::pair().expect("pair failed");

        // Split should work
        let (_read, _write) = s1.split();
        crate::test_complete!("test_split");
    }

    #[test]
    fn test_into_split() {
        init_test("test_into_split");
        let (s1, _s2) = UnixStream::pair().expect("pair failed");

        // into_split should work
        let (_read, _write) = s1.into_split();
        crate::test_complete!("test_into_split");
    }

    #[test]
    fn owned_write_half_shutdown_on_drop() {
        init_test("owned_write_half_shutdown_on_drop");
        let (s1, mut s2) = UnixStream::pair().expect("pair failed");

        let (_read, write) = s1.into_split();
        drop(write);

        let mut buf = [0u8; 1];
        let mut is_shutdown = false;
        for _ in 0..64 {
            match s2.read(&mut buf) {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::yield_now();
                }
                Ok(_) | Err(_) => {
                    is_shutdown = true;
                    break;
                }
            }
        }

        crate::assert_with_log!(
            is_shutdown,
            "write half shutdown on drop",
            true,
            is_shutdown
        );
        crate::test_complete!("owned_write_half_shutdown_on_drop");
    }

    #[test]
    fn test_from_std() {
        init_test("test_from_std");
        let (std_s1, _std_s2) = net::UnixStream::pair().expect("pair failed");
        let stream = UnixStream::from_std(std_s1).expect("wrap stream");
        let flags = fcntl(stream.inner.as_ref(), FcntlArg::F_GETFL).expect("read stream flags");
        let is_nonblocking = OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK);
        crate::assert_with_log!(
            is_nonblocking,
            "from_std should force nonblocking mode",
            true,
            is_nonblocking
        );
        crate::test_complete!("test_from_std");
    }

    #[test]
    fn test_vectored_io() {
        init_test("test_vectored_io");
        futures_lite::future::block_on(async {
            let (mut tx, mut rx) = UnixStream::pair().expect("pair failed");
            let header = b"hi";
            let body = b"there";
            let bufs = [IoSlice::new(header), IoSlice::new(body)];

            let wrote = crate::io::AsyncWriteExt::write_vectored(&mut tx, &bufs)
                .await
                .expect("write_vectored failed");
            let expected_len = header.len() + body.len();
            crate::assert_with_log!(wrote == expected_len, "wrote", expected_len, wrote);
            let vectored = crate::io::AsyncWrite::is_write_vectored(&tx);
            crate::assert_with_log!(vectored, "is_write_vectored", true, vectored);

            let mut out = Vec::new();
            while out.len() < wrote {
                let mut a = [0u8; 2];
                let mut b = [0u8; 8];
                let mut rbufs = [IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)];

                let n = crate::io::AsyncReadVectoredExt::read_vectored(&mut rx, &mut rbufs)
                    .await
                    .expect("read_vectored failed");
                if n == 0 {
                    break;
                }

                let first = n.min(a.len());
                out.extend_from_slice(&a[..first]);
                if n > a.len() {
                    out.extend_from_slice(&b[..n - a.len()]);
                }
            }

            let mut expected = Vec::new();
            expected.extend_from_slice(header);
            expected.extend_from_slice(body);
            crate::assert_with_log!(out == expected, "out", expected, out);
        });
        crate::test_complete!("test_vectored_io");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_connect_abstract() {
        init_test("test_connect_abstract");
        // Test that connect_abstract compiles and returns an error when no listener exists
        futures_lite::future::block_on(async {
            // This will fail because no listener, but validates the API
            let result = UnixStream::connect_abstract(b"nonexistent_test_socket").await;
            crate::assert_with_log!(result.is_err(), "result err", true, result.is_err());
        });
        crate::test_complete!("test_connect_abstract");
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
        init_test("test_peer_cred");
        let (s1, s2) = UnixStream::pair().expect("pair failed");

        // Both sides should be able to get peer credentials
        let cred1 = s1.peer_cred().expect("peer_cred s1 failed");
        let cred2 = s2.peer_cred().expect("peer_cred s2 failed");

        // Both should report the same process (ourselves)
        let user_id = nix::unistd::getuid().as_raw() as u32;
        let group_id = nix::unistd::getgid().as_raw() as u32;

        crate::assert_with_log!(cred1.uid == user_id, "s1 uid", user_id, cred1.uid);
        crate::assert_with_log!(cred1.gid == group_id, "s1 gid", group_id, cred1.gid);
        crate::assert_with_log!(cred2.uid == user_id, "s2 uid", user_id, cred2.uid);
        crate::assert_with_log!(cred2.gid == group_id, "s2 gid", group_id, cred2.gid);

        // On Linux, pid should be available and match our process
        #[cfg(target_os = "linux")]
        {
            let proc_id = i32::try_from(std::process::id()).expect("process id fits in i32");
            let pid1 = cred1.pid.expect("pid should be available on Linux");
            let pid2 = cred2.pid.expect("pid should be available on Linux");
            crate::assert_with_log!(pid1 == proc_id, "s1 pid", proc_id, pid1);
            crate::assert_with_log!(pid2 == proc_id, "s2 pid", proc_id, pid2);
        }

        crate::test_complete!("test_peer_cred");
    }

    #[test]
    fn test_send_recv_with_ancillary() {
        use crate::net::unix::{AncillaryMessage, SocketAncillary};
        use std::os::unix::io::AsRawFd;

        init_test("test_send_recv_with_ancillary");
        futures_lite::future::block_on(async {
            let (tx, rx) = UnixStream::pair().expect("pair failed");

            // Create a pipe to get a file descriptor to pass
            let (pipe_read, pipe_write) = nix::unistd::pipe().expect("pipe failed");
            let pipe_read_raw = pipe_read.as_raw_fd();
            let _pipe_write_raw = pipe_write.as_raw_fd();

            // Write something to the pipe so we can verify the fd works
            nix::unistd::write(&pipe_write, b"test data").expect("write to pipe failed");

            // Send the read end of the pipe
            let mut send_ancillary = SocketAncillary::new(128);
            let added = send_ancillary.add_fds(&[pipe_read_raw]);
            crate::assert_with_log!(added, "add_fds", true, added);

            let sent = tx
                .send_with_ancillary(b"file descriptor attached", &mut send_ancillary)
                .await
                .expect("send_with_ancillary failed");
            crate::assert_with_log!(sent == 24, "sent bytes", 24, sent);

            // Close the original fd (the receiver now owns it)
            // Dropping the OwnedFd will close it
            drop(pipe_read);

            // Receive the data and file descriptor
            let mut recv_buf = [0u8; 64];
            let mut recv_ancillary = SocketAncillary::new(128);

            let received = rx
                .recv_with_ancillary(&mut recv_buf, &mut recv_ancillary)
                .await
                .expect("recv_with_ancillary failed");
            crate::assert_with_log!(received == 24, "received bytes", 24, received);
            crate::assert_with_log!(
                &recv_buf[..received] == b"file descriptor attached",
                "received data",
                b"file descriptor attached",
                &recv_buf[..received]
            );

            // Extract the file descriptor
            let mut received_fd = None;
            for msg in recv_ancillary.messages() {
                let AncillaryMessage::ScmRights(fds) = msg;
                for fd in fds {
                    received_fd = Some(fd);
                }
            }

            let fd = received_fd.expect("should have received a file descriptor");
            drop(pipe_write);
            nix::unistd::close(fd).expect("close received fd");
        });
        crate::test_complete!("test_send_recv_with_ancillary");
    }

    #[test]
    fn ucred_debug_clone_copy_eq() {
        let c = UCred {
            uid: 1000,
            gid: 1000,
            pid: Some(42),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("1000"), "{dbg}");
        let copied: UCred = c;
        let cloned = c;
        assert_eq!(copied, cloned);
        assert_ne!(
            c,
            UCred {
                uid: 0,
                gid: 0,
                pid: None
            }
        );
    }
}
