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
use parking_lot::Mutex;
use std::future::poll_fn;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{self, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

const FALLBACK_ACCEPT_BACKOFF: Duration = Duration::from_millis(1);

#[derive(Debug, Default)]
struct AcceptWaiters {
    waiters: Mutex<Vec<Waker>>,
}

impl AcceptWaiters {
    fn register(&self, waker: &Waker) {
        let mut waiters = self.waiters.lock();
        if waiters.iter().any(|existing| existing.will_wake(waker)) {
            return;
        }
        waiters.push(waker.clone());
    }

    fn wake_all(&self) {
        let waiters = {
            let mut guard = self.waiters.lock();
            std::mem::take(&mut *guard)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn wake_others(&self, current: &Waker) {
        let waiters = {
            let mut guard = self.waiters.lock();
            std::mem::take(&mut *guard)
        };
        for waiter in waiters {
            if !waiter.will_wake(current) {
                waiter.wake();
            }
        }
    }
}

impl Wake for AcceptWaiters {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SocketFileIdentity {
    dev: u64,
    ino: u64,
}

pub(crate) fn socket_file_identity(path: &Path) -> io::Result<Option<SocketFileIdentity>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(Some(SocketFileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })),
        Ok(_) => Ok(None),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

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

pub(crate) fn remove_socket_file_if_same_inode(
    path: &Path,
    identity: SocketFileIdentity,
) -> io::Result<()> {
    let Some(current_identity) = socket_file_identity(path)? else {
        return Ok(());
    };

    if current_identity != identity {
        return Ok(());
    }

    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

pub(crate) fn finalize_bound_socket<T, F>(
    path: &Path,
    inner: T,
    configure: F,
) -> io::Result<(T, Option<SocketFileIdentity>)>
where
    F: FnOnce(&T) -> io::Result<()>,
{
    // Capture the inode identity before returning the wrapper so cleanup can
    // safely target only the socket file created by this bind.
    let cleanup_identity = socket_file_identity(path).ok().flatten();

    if let Err(err) = configure(&inner) {
        drop(inner);
        if let Some(identity) = cleanup_identity {
            let _ = remove_socket_file_if_same_inode(path, identity);
        }
        return Err(err);
    }

    Ok((inner, cleanup_identity))
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
    /// Reactor registration for I/O events (lazily initialized).
    registration: Mutex<Option<IoRegistration>>,
    /// Fanout waiter list for concurrent accept futures.
    accept_waiters: Arc<AcceptWaiters>,
    /// The underlying standard library listener.
    inner: net::UnixListener,
    /// Path to the socket file (for cleanup on drop).
    /// None for abstract namespace sockets or from_std().
    path: Option<PathBuf>,
    /// Device/inode identity captured at bind time for safe cleanup.
    cleanup_identity: Option<SocketFileIdentity>,
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
            accept_waiters: Arc::new(AcceptWaiters::default()),
            path: None, // No filesystem path for abstract sockets
            cleanup_identity: None,
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
                self.accept_waiters.wake_others(cx.waker());
                Poll::Ready(UnixStream::from_std(stream).map(|stream| (stream, addr)))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.accept_waiters.register(cx.waker());
                if let Err(err) = self.register_interest() {
                    self.accept_waiters.wake_others(cx.waker());
                    return Poll::Ready(Err(err));
                }

                // Close the re-arm race for edge-triggered readiness backends.
                // If a connection arrived between the first `accept()` returning WouldBlock
                // and the registration, we might miss the edge-triggered wakeup.
                match self.inner.accept() {
                    Ok((stream, addr)) => {
                        self.accept_waiters.wake_others(cx.waker());
                        Poll::Ready(UnixStream::from_std(stream).map(|stream| (stream, addr)))
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
                    Err(err) => {
                        self.accept_waiters.wake_others(cx.waker());
                        Poll::Ready(Err(err))
                    }
                }
            }
            Err(e) => {
                self.accept_waiters.wake_others(cx.waker());
                Poll::Ready(Err(e))
            }
        }
    }

    /// Registers interest with the I/O driver for READABLE events.
    fn register_interest(&self) -> io::Result<()> {
        let mut registration = self.registration.lock();
        let accept_waker = Waker::from(Arc::clone(&self.accept_waiters));

        if let Some(existing) = registration.as_mut() {
            // Re-arm reactor interest and conditionally update the waker in a
            // single lock acquisition (will_wake guard skips the clone).
            match existing.rearm(Interest::READABLE, &accept_waker) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    *registration = None;
                }
                Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                    *registration = None;
                    drop(registration);
                    fallback_rewake_waiters(&self.accept_waiters);
                    return Ok(());
                }
                Err(err) => return Err(err),
            }
        }

        let Some(current) = Cx::current() else {
            drop(registration);
            fallback_rewake_waiters(&self.accept_waiters);
            return Ok(());
        };
        let Some(driver) = current.io_driver_handle() else {
            drop(registration);
            fallback_rewake_waiters(&self.accept_waiters);
            return Ok(());
        };

        match driver.register(&self.inner, Interest::READABLE, accept_waker) {
            Ok(new_reg) => {
                *registration = Some(new_reg);
                drop(registration);
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                drop(registration);
                fallback_rewake_waiters(&self.accept_waiters);
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                drop(registration);
                fallback_rewake_waiters(&self.accept_waiters);
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
            accept_waiters: Arc::new(AcceptWaiters::default()),
            inner: listener,
            path: None, // Don't clean up sockets we didn't create
            cleanup_identity: None,
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
        self.cleanup_identity = None;
        self.path.take()
    }

    fn from_bound_with<F>(path: &Path, inner: net::UnixListener, configure: F) -> io::Result<Self>
    where
        F: FnOnce(&net::UnixListener) -> io::Result<()>,
    {
        let (inner, cleanup_identity) = finalize_bound_socket(path, inner, configure)?;

        Ok(Self {
            accept_waiters: Arc::new(AcceptWaiters::default()),
            inner,
            path: Some(path.to_path_buf()),
            cleanup_identity,
            registration: Mutex::new(None), // Lazy registration on first poll
        })
    }
}

fn fallback_rewake_waiters(accept_waiters: &Arc<AcceptWaiters>) {
    if let Some(timer) = Cx::current().and_then(|current| current.timer_driver()) {
        let deadline = timer.now() + FALLBACK_ACCEPT_BACKOFF;
        let _ = timer.register(deadline, Waker::from(Arc::clone(accept_waiters)));
    } else {
        accept_waiters.wake_all();
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        // Clean up only the socket file we originally created.
        if let (Some(path), Some(identity)) = (&self.path, self.cleanup_identity) {
            let _ = remove_socket_file_if_same_inode(path, identity);
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
    use std::sync::atomic::{AtomicUsize, Ordering};
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

    struct CountingWaker {
        hits: Arc<AtomicUsize>,
    }

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
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
            listener.registration.lock().is_some(),
            "incoming should register interest"
        );
        crate::test_complete!("incoming_registers_on_wouldblock");
    }

    #[test]
    fn listener_fanout_wakes_all_pending_accept_waiters() {
        init_test("listener_fanout_wakes_all_pending_accept_waiters");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("listener_fanout.sock");

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
        let hits1 = Arc::new(AtomicUsize::new(0));
        let hits2 = Arc::new(AtomicUsize::new(0));
        let waker1 = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits1),
        }));
        let waker2 = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits2),
        }));
        let mut cx1 = Context::from_waker(&waker1);
        let mut cx2 = Context::from_waker(&waker2);

        assert!(matches!(listener.poll_accept(&mut cx1), Poll::Pending));
        assert!(matches!(listener.poll_accept(&mut cx2), Poll::Pending));

        let _client1 = net::UnixStream::connect(&path).expect("connect first client");
        listener.accept_waiters.wake_all();

        assert_eq!(hits1.load(Ordering::SeqCst), 1);
        assert_eq!(hits2.load(Ordering::SeqCst), 1);

        assert!(matches!(listener.poll_accept(&mut cx2), Poll::Ready(Ok(_))));
        assert!(matches!(listener.poll_accept(&mut cx1), Poll::Pending));

        let _client2 = net::UnixStream::connect(&path).expect("connect second client");
        listener.accept_waiters.wake_all();

        assert_eq!(hits1.load(Ordering::SeqCst), 2);
        assert!(matches!(listener.poll_accept(&mut cx1), Poll::Ready(Ok(_))));

        crate::test_complete!("listener_fanout_wakes_all_pending_accept_waiters");
    }

    #[test]
    fn incoming_recovers_after_registration_lock_panic() {
        init_test("incoming_recovers_after_registration_lock_panic");
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
            let _guard = listener.registration.lock();
            panic!("panic while holding registration lock");
        }));

        let mut incoming = listener.incoming();
        let waker = noop_waker();
        let mut poll_cx = Context::from_waker(&waker);

        let poll_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Pin::new(&mut incoming).poll_next(&mut poll_cx)
        }));
        assert!(
            poll_result.is_ok(),
            "poll_next should not panic after a registration-lock panic"
        );

        match poll_result.expect("poll result available") {
            Poll::Pending => {}
            other @ Poll::Ready(_) => {
                panic!("expected Poll::Pending after re-registration path, got {other:?}")
            }
        }

        crate::test_complete!("incoming_recovers_after_registration_lock_panic");
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

    #[test]
    fn replacement_socket_path_survives_old_listener_drop() {
        init_test("replacement_socket_path_survives_old_listener_drop");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("listener_rebind.sock");

        let original =
            futures_lite::future::block_on(UnixListener::bind(&path)).expect("bind failed");
        crate::assert_with_log!(path.exists(), "socket exists", true, path.exists());

        std::fs::remove_file(&path).expect("unlink original path");
        let replacement = net::UnixListener::bind(&path).expect("bind replacement failed");
        crate::assert_with_log!(path.exists(), "replacement exists", true, path.exists());

        drop(original);

        crate::assert_with_log!(
            path.exists(),
            "old listener drop preserved replacement path",
            true,
            path.exists()
        );

        drop(replacement);
        std::fs::remove_file(&path).ok();
        crate::test_complete!("replacement_socket_path_survives_old_listener_drop");
    }

    #[test]
    fn test_bind_cleanup_on_post_bind_init_failure() {
        init_test("test_listener_bind_cleanup_on_post_bind_init_failure");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("listener_init_failure.sock");

        remove_stale_socket_file(&path).expect("clear stale socket");
        let inner = net::UnixListener::bind(&path).expect("bind failed");
        let err = UnixListener::from_bound_with(&path, inner, |_socket| {
            Err(io::Error::other("injected listener init failure"))
        })
        .expect_err("post-bind init should fail");

        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Other,
            "init error kind",
            io::ErrorKind::Other,
            err.kind()
        );
        crate::assert_with_log!(
            !path.exists(),
            "socket path cleaned after init failure",
            false,
            path.exists()
        );

        crate::test_complete!("test_listener_bind_cleanup_on_post_bind_init_failure");
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
