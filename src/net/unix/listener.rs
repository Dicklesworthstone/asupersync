//! Unix domain socket listener implementation.
//!
//! This module provides [`UnixListener`] for accepting Unix domain socket connections,
//! integrated with the reactor for efficient event-driven I/O.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::unix::UnixListener;
//!
//! async fn server() -> std::io::Result<()> {
//!     let listener = UnixListener::bind("/tmp/my_socket.sock").await?;
//!
//!     loop {
//!         let (stream, addr) = listener.accept().await?;
//!         // Handle connection...
//!     }
//! }
//! ```
//!
//! # Socket Cleanup
//!
//! Unix socket files persist after process exit. This listener handles cleanup:
//! - Before bind: removes existing stale socket file if present
//! - On drop: removes the socket file created by this listener
//!
//! For abstract namespace sockets (Linux only), no cleanup is needed as the
//! kernel handles it automatically.

use crate::cx::Cx;
use crate::net::unix::stream::UnixStream;
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use crate::stream::Stream;
use std::future::poll_fn;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{self, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

pub(crate) fn remove_stale_socket_file(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "refusing to remove non-socket path before bind: {}",
                path.display()
            ),
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// A Unix domain socket listener.
///
/// Creates a socket bound to a filesystem path or abstract namespace (Linux),
/// and listens for incoming connections.
///
/// # Cancel-Safety
///
/// The [`accept`](Self::accept) method is cancel-safe: if cancelled, no connection
/// is lost. The connection will be available for the next `accept` call.
///
/// # Socket File Cleanup
///
/// When dropped, the listener removes the socket file from the filesystem
/// (unless it was created with [`from_std`](Self::from_std) or is an abstract
/// namespace socket).
#[derive(Debug)]
pub struct UnixListener {
    /// The underlying standard library listener.
    inner: net::UnixListener,
    /// Path to the socket file (for cleanup on drop).
    /// None for abstract namespace sockets or from_std().
    path: Option<PathBuf>,
    /// Reactor registration for I/O events (lazily initialized).
    registration: Mutex<Option<IoRegistration>>,
}

impl UnixListener {
    /// Binds to a filesystem path.
    ///
    /// Creates a new Unix domain socket listener bound to the specified path.
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
    /// let listener = UnixListener::bind("/tmp/my_socket.sock").await?;
    /// ```
    pub async fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref();

        // Remove only stale socket files. Refuse to delete non-socket paths.
        remove_stale_socket_file(path)?;

        let inner = net::UnixListener::bind(path)?;
        inner.set_nonblocking(true)?;

        Ok(Self {
            inner,
            path: Some(path.to_path_buf()),
            registration: Mutex::new(None), // Lazy registration on first poll
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
    /// let listener = UnixListener::bind_abstract(b"my_abstract_socket").await?;
    /// ```
    #[cfg(target_os = "linux")]
    pub async fn bind_abstract(name: &[u8]) -> io::Result<Self> {
        use std::os::linux::net::SocketAddrExt;

        let addr = SocketAddr::from_abstract_name(name)?;
        let inner = net::UnixListener::bind_addr(&addr)?;
        inner.set_nonblocking(true)?;

        Ok(Self {
            inner,
            path: None,                     // No filesystem path for abstract sockets
            registration: Mutex::new(None), // Lazy registration on first poll
        })
    }

    /// Accepts a new incoming connection.
    ///
    /// This method waits for a new connection and returns a tuple of the
    /// connected [`UnixStream`] and the peer's socket address.
    ///
    /// # Cancel-Safety
    ///
    /// This method is cancel-safe. If the future is dropped before completion,
    /// no connection is lost - it will be available for the next accept call.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting fails (e.g., too many open files).
    ///
    /// # Example
    ///
    /// ```ignore
    /// loop {
    ///     let (stream, addr) = listener.accept().await?;
    ///     println!("New connection from {:?}", addr);
    /// }
    /// ```
    pub async fn accept(&self) -> io::Result<(UnixStream, SocketAddr)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }

    /// Polls for an incoming connection using reactor wakeups.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(UnixStream, SocketAddr)>> {
        match self.inner.accept() {
            Ok((stream, addr)) => {
                Poll::Ready(UnixStream::from_std(stream).map(|stream| (stream, addr)))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.register_interest(cx) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Registers interest with the I/O driver for READABLE events.
    fn register_interest(&self, cx: &Context<'_>) -> io::Result<()> {
        let mut registration = self
            .registration
            .lock()
            .map_err(|_| io::Error::other("unix listener registration lock poisoned"))?;

        if let Some(existing) = registration.as_mut() {
            // Re-arm reactor interest and conditionally update the waker in a
            // single lock acquisition (will_wake guard skips the clone).
            match existing.rearm(Interest::READABLE, cx.waker()) {
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

        match driver.register(&self.inner, Interest::READABLE, cx.waker().clone()) {
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

    /// Returns the local socket address.
    ///
    /// For filesystem sockets, this returns the path. For abstract namespace
    /// sockets, this returns the abstract name.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let listener = UnixListener::bind("/tmp/my_socket.sock").await?;
    /// println!("Listening on {:?}", listener.local_addr()?);
    /// ```
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Creates an async `UnixListener` from a standard library listener.
    ///
    /// The listener will be set to non-blocking mode. Unlike [`bind`](Self::bind),
    /// the socket file will **not** be automatically removed on drop.
    ///
    /// # Errors
    ///
    /// Returns an error if setting non-blocking mode fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let std_listener = std::os::unix::net::UnixListener::bind("/tmp/socket.sock")?;
    /// let listener = UnixListener::from_std(std_listener)?;
    /// ```
    pub fn from_std(listener: net::UnixListener) -> io::Result<Self> {
        listener.set_nonblocking(true)?;

        Ok(Self {
            inner: listener,
            path: None,                     // Don't clean up sockets we didn't create
            registration: Mutex::new(None), // Lazy registration on first poll
        })
    }

    /// Returns a stream of incoming connections.
    ///
    /// Each item yielded by the stream is an `io::Result<UnixStream>`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use futures::StreamExt;
    ///
    /// let listener = UnixListener::bind("/tmp/socket.sock").await?;
    /// let mut incoming = listener.incoming();
    ///
    /// while let Some(stream) = incoming.next().await {
    ///     let stream = stream?;
    ///     // Handle connection...
    /// }
    /// ```
    #[must_use]
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }

    /// Returns the underlying std listener.
    ///
    /// This can be used for operations not directly exposed by this wrapper.
    #[must_use]
    pub fn as_std(&self) -> &net::UnixListener {
        &self.inner
    }

    /// Takes ownership of the filesystem path, preventing automatic cleanup.
    ///
    /// After calling this, the socket file will **not** be removed when the
    /// listener is dropped. Returns the path if it was set.
    pub fn take_path(&mut self) -> Option<PathBuf> {
        self.path.take()
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        // Clean up socket file if we created it
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
        // Registration (when added) will auto-deregister via RAII
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for UnixListener {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.inner.as_raw_fd()
    }
}

/// Stream of incoming Unix domain socket connections.
///
/// This struct is created by [`UnixListener::incoming`]. See its documentation
/// for more details.
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a UnixListener,
}

impl Stream for Incoming<'_> {
    type Item = io::Result<UnixStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.listener.poll_accept(cx) {
            Poll::Ready(Ok((stream, _addr))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::io::AsyncReadExt;
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId};
    use std::io::Write;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    #[test]
    fn test_bind_and_local_addr() {
        init_test("test_bind_and_local_addr");
        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let path = dir.path().join("test.sock");

            let listener = UnixListener::bind(&path).await.expect("bind failed");
            let addr = listener.local_addr().expect("local_addr failed");

            // Should be a pathname socket
            let pathname = addr.as_pathname();
            crate::assert_with_log!(
                pathname.is_some(),
                "pathname exists",
                true,
                pathname.is_some()
            );
            let pathname = pathname.unwrap();
            crate::assert_with_log!(pathname == path, "pathname", path, pathname);
        });
        crate::test_complete!("test_bind_and_local_addr");
    }

    #[test]
    fn test_bind_refuses_non_socket_path() {
        init_test("test_bind_refuses_non_socket_path");
        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let path = dir.path().join("non_socket_target");
            std::fs::write(&path, b"not a socket").expect("write file");

            let err = UnixListener::bind(&path)
                .await
                .expect_err("bind should reject non-socket path");
            crate::assert_with_log!(
                err.kind() == std::io::ErrorKind::AlreadyExists,
                "error kind",
                std::io::ErrorKind::AlreadyExists,
                err.kind()
            );

            let contents = std::fs::read(&path).expect("read file");
            let unchanged = contents == b"not a socket";
            crate::assert_with_log!(unchanged, "file unchanged", true, unchanged);
        });
        crate::test_complete!("test_bind_refuses_non_socket_path");
    }

    #[test]
    fn test_bind_replaces_stale_socket_file() {
        init_test("test_bind_replaces_stale_socket_file");
        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let path = dir.path().join("stale_socket.sock");

            let stale = net::UnixListener::bind(&path).expect("create stale socket");
            drop(stale);

            let exists = path.exists();
            crate::assert_with_log!(exists, "stale socket exists", true, exists);

            let listener = UnixListener::bind(&path)
                .await
                .expect("bind should replace stale socket");
            let exists = path.exists();
            crate::assert_with_log!(exists, "socket exists after rebind", true, exists);
            drop(listener);

            let exists = path.exists();
            crate::assert_with_log!(!exists, "socket cleaned after drop", false, exists);
        });
        crate::test_complete!("test_bind_replaces_stale_socket_file");
    }

    #[test]
    fn test_accept() {
        init_test("test_accept");
        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let path = dir.path().join("accept_test.sock");

            let listener = UnixListener::bind(&path).await.expect("bind failed");

            // Connect from another thread
            let path_clone = path.clone();
            let handle = std::thread::spawn(move || {
                let mut stream = net::UnixStream::connect(&path_clone).expect("connect failed");
                stream.write_all(b"hello").expect("write failed");
            });

            // Accept the connection
            let (mut stream, _addr) = listener.accept().await.expect("accept failed");

            // Read the data using async read
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.expect("read failed");
            crate::assert_with_log!(&buf == b"hello", "buf", b"hello", buf);

            handle.join().expect("thread failed");
        });
        crate::test_complete!("test_accept");
    }

    #[test]
    fn incoming_registers_on_wouldblock() {
        init_test("incoming_registers_on_wouldblock");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("incoming_register.sock");

        let std_listener = net::UnixListener::bind(&path).expect("bind failed");
        std_listener
            .set_nonblocking(true)
            .expect("nonblocking failed");

        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let listener = UnixListener::from_std(std_listener).expect("from_std failed");
        let mut incoming = listener.incoming();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut incoming).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Pending));

        assert!(
            listener
                .registration
                .lock()
                .expect("lock poisoned")
                .is_some(),
            "incoming should register interest"
        );
        crate::test_complete!("incoming_registers_on_wouldblock");
    }

    #[test]
    fn incoming_handles_poisoned_registration_lock() {
        init_test("incoming_handles_poisoned_registration_lock");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("incoming_poisoned_lock.sock");

        let std_listener = net::UnixListener::bind(&path).expect("bind failed");
        std_listener
            .set_nonblocking(true)
            .expect("nonblocking failed");

        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx_cap = Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx_cap));

        let listener = UnixListener::from_std(std_listener).expect("from_std failed");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = listener.registration.lock().expect("lock acquired");
            panic!("poison registration lock");
        }));

        let mut incoming = listener.incoming();
        let waker = noop_waker();
        let mut poll_cx = Context::from_waker(&waker);

        let poll_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Pin::new(&mut incoming).poll_next(&mut poll_cx)
        }));
        assert!(
            poll_result.is_ok(),
            "poll_next should not panic on poisoned registration lock"
        );

        match poll_result.expect("poll result available") {
            Poll::Ready(Some(Err(err))) => {
                crate::assert_with_log!(
                    err.kind() == io::ErrorKind::Other,
                    "error kind",
                    io::ErrorKind::Other,
                    err.kind()
                );
            }
            other => panic!("expected Poll::Ready(Some(Err(_))), got {other:?}"),
        }

        crate::test_complete!("incoming_handles_poisoned_registration_lock");
    }

    #[test]
    fn test_socket_cleanup_on_drop() {
        init_test("test_socket_cleanup_on_drop");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("cleanup_test.sock");

        futures_lite::future::block_on(async {
            let listener = UnixListener::bind(&path).await.expect("bind failed");
            let exists = path.exists();
            crate::assert_with_log!(exists, "socket exists", true, exists);
            drop(listener);
        });

        let exists = path.exists();
        crate::assert_with_log!(!exists, "socket cleaned up", false, exists);
        crate::test_complete!("test_socket_cleanup_on_drop");
    }

    #[test]
    fn test_from_std_no_cleanup() {
        init_test("test_from_std_no_cleanup");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("from_std_test.sock");

        // Create with std
        let std_listener = net::UnixListener::bind(&path).expect("bind failed");

        // Wrap in async version
        let listener = UnixListener::from_std(std_listener).expect("from_std failed");
        let exists = path.exists();
        crate::assert_with_log!(exists, "socket exists", true, exists);

        // Drop async listener
        drop(listener);

        // Socket file should still exist (from_std doesn't clean up)
        let exists = path.exists();
        crate::assert_with_log!(exists, "socket remains", true, exists);

        // Clean up manually
        std::fs::remove_file(&path).ok();
        crate::test_complete!("test_from_std_no_cleanup");
    }

    #[test]
    fn test_take_path_prevents_cleanup() {
        init_test("test_take_path_prevents_cleanup");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("take_path_test.sock");

        futures_lite::future::block_on(async {
            let mut listener = UnixListener::bind(&path).await.expect("bind failed");

            // Take the path
            let taken = listener.take_path();
            crate::assert_with_log!(taken.is_some(), "taken some", true, taken.is_some());
            let taken = taken.unwrap();
            crate::assert_with_log!(taken == path, "taken path", path, taken);

            drop(listener);
        });

        // Socket should still exist
        let exists = path.exists();
        crate::assert_with_log!(exists, "socket remains", true, exists);

        // Clean up manually
        std::fs::remove_file(&path).ok();
        crate::test_complete!("test_take_path_prevents_cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_abstract_socket() {
        init_test("test_abstract_socket");
        futures_lite::future::block_on(async {
            let name = b"asupersync_test_abstract_socket";
            let listener = UnixListener::bind_abstract(name)
                .await
                .expect("bind failed");
            let addr = listener.local_addr().expect("local_addr failed");

            // Should be an abstract socket
            let pathname = addr.as_pathname();
            crate::assert_with_log!(
                pathname.is_none(),
                "no pathname",
                "None",
                format!("{:?}", pathname)
            );
        });
        crate::test_complete!("test_abstract_socket");
    }
}
