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
    /// let mut ancillary_buf = [0u8; 128];
    /// let mut ancillary = SocketAncillary::new(&mut ancillary_buf);
    /// ancillary.add_fds(&[file.as_raw_fd()]);
    ///
    /// let n = tx.send_with_ancillary(b"file attached", &mut ancillary).await?;
    /// ```
    pub async fn send_with_ancillary(
        &self,
        buf: &[u8],
        ancillary: &mut crate::net::unix::SocketAncillary<'_>,
    ) -> io::Result<usize> {
        use std::os::unix::io::AsRawFd;

        loop {
            let result = send_with_ancillary_impl(self.inner.as_raw_fd(), buf, ancillary);
            match result {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // TODO: Replace with proper reactor wait when integration is complete
                    crate::runtime::yield_now().await;
                }
                Err(e) => return Err(e),
            }
        }
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
    /// use std::os::unix::io::FromRawFd;
    ///
    /// let mut buf = [0u8; 64];
    /// let mut ancillary_buf = [0u8; 128];
    /// let mut ancillary = SocketAncillary::new(&mut ancillary_buf);
    ///
    /// let n = rx.recv_with_ancillary(&mut buf, &mut ancillary).await?;
    ///
    /// for msg in ancillary.messages() {
    ///     if let AncillaryMessage::ScmRights(fds) = msg {
    ///         for fd in fds {
    ///             let file = unsafe { std::fs::File::from_raw_fd(fd) };
    ///             // Use the file...
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// [`SocketAncillary::messages`]: crate::net::unix::SocketAncillary::messages
    pub async fn recv_with_ancillary(
        &self,
        buf: &mut [u8],
        ancillary: &mut crate::net::unix::SocketAncillary<'_>,
    ) -> io::Result<usize> {
        use std::os::unix::io::AsRawFd;

        loop {
            let result = recv_with_ancillary_impl(self.inner.as_raw_fd(), buf, ancillary);
            match result {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // TODO: Replace with proper reactor wait when integration is complete
                    crate::runtime::yield_now().await;
                }
                Err(e) => return Err(e),
            }
        }
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

// Platform-specific peer credential implementations

/// Linux implementation using SO_PEERCRED.
#[cfg(target_os = "linux")]
fn peer_cred_impl(stream: &net::UnixStream) -> io::Result<UCred> {
    use std::os::unix::io::AsRawFd;

    // ucred structure from Linux
    #[repr(C)]
    struct LinuxUcred {
        pid: i32,
        uid: u32,
        gid: u32,
    }

    let fd = stream.as_raw_fd();
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
            &mut ucred as *mut LinuxUcred as *mut libc::c_void,
            &mut len,
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
fn peer_cred_impl(stream: &net::UnixStream) -> io::Result<UCred> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
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

// Ancillary data send/receive implementations using sendmsg/recvmsg

/// Sends data with ancillary data using sendmsg.
fn send_with_ancillary_impl(
    fd: std::os::unix::io::RawFd,
    buf: &[u8],
    ancillary: &mut crate::net::unix::SocketAncillary<'_>,
) -> io::Result<usize> {
    use std::mem::MaybeUninit;

    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut msg: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    if ancillary.len() > 0 {
        msg.msg_control = ancillary.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = ancillary.len();
    }

    // SAFETY: sendmsg is a well-defined syscall and we've set up the
    // msghdr correctly with valid pointers and lengths.
    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };

    if ret >= 0 {
        // Clear the ancillary data after successful send
        ancillary.clear();
        Ok(ret as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Receives data with ancillary data using recvmsg.
fn recv_with_ancillary_impl(
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
    ancillary: &mut crate::net::unix::SocketAncillary<'_>,
) -> io::Result<usize> {
    use std::mem::MaybeUninit;

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut msg: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ancillary.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = ancillary.capacity();

    // SAFETY: recvmsg is a well-defined syscall and we've set up the
    // msghdr correctly with valid pointers and lengths.
    let ret = unsafe { libc::recvmsg(fd, &mut msg, 0) };

    if ret >= 0 {
        let truncated = (msg.msg_flags & libc::MSG_CTRUNC) != 0;
        // SAFETY: recvmsg has written msg_controllen bytes of valid
        // control message data to the buffer.
        unsafe {
            ancillary.set_len(msg.msg_controllen, truncated);
        }
        Ok(ret as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_pair() {
        init_test("test_pair");
        let (mut s1, mut s2) = UnixStream::pair().expect("pair failed");

        s1.write_all(b"hello").expect("write failed");
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
    fn test_from_std() {
        init_test("test_from_std");
        let (std_s1, _std_s2) = net::UnixStream::pair().expect("pair failed");
        std_s1
            .set_nonblocking(true)
            .expect("set_nonblocking failed");

        let _stream = UnixStream::from_std(std_s1);
        crate::test_complete!("test_from_std");
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
        let our_uid = unsafe { libc::getuid() } as u32;
        let our_gid = unsafe { libc::getgid() } as u32;

        crate::assert_with_log!(cred1.uid == our_uid, "s1 uid", our_uid, cred1.uid);
        crate::assert_with_log!(cred1.gid == our_gid, "s1 gid", our_gid, cred1.gid);
        crate::assert_with_log!(cred2.uid == our_uid, "s2 uid", our_uid, cred2.uid);
        crate::assert_with_log!(cred2.gid == our_gid, "s2 gid", our_gid, cred2.gid);

        // On Linux, pid should be available and match our process
        #[cfg(target_os = "linux")]
        {
            let our_pid = std::process::id() as i32;
            let pid1 = cred1.pid.expect("pid should be available on Linux");
            let pid2 = cred2.pid.expect("pid should be available on Linux");
            crate::assert_with_log!(pid1 == our_pid, "s1 pid", our_pid, pid1);
            crate::assert_with_log!(pid2 == our_pid, "s2 pid", our_pid, pid2);
        }

        crate::test_complete!("test_peer_cred");
    }
}
