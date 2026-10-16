//! Unix domain socket listener implementation.
//!
//! This module provides [`UnixListener`] for accepting Unix domain socket connections,
//! integrated with the reactor for efficient event-driven I/O.
//!
//! # Example
//!
//! ```
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
//! - Bind is fail-closed: existing paths are not removed automatically
//! - On drop: removes the socket file created by this listener
//!
//! For abstract namespace sockets (Linux only), no cleanup is needed as the
//! kernel handles it automatically.

use crate::cx::Cx;
use crate::net::udp::{Armed, ReactorRegistration};
use crate::net::unix::stream::UnixStream;
use crate::runtime::reactor::Interest;
use crate::stream::Stream;
use parking_lot::Mutex;
use std::future::Future;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{self, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

#[cfg(test)]
use socket2::{Domain, SockAddr, Type};

const FALLBACK_ACCEPT_BACKOFF: Duration = Duration::from_millis(1);

#[derive(Debug, Default)]
struct AcceptWaiters {
    waiters: Mutex<Vec<AcceptWaiter>>,
    next_owner: AtomicU64,
}

/// One task waiting for a connection. `owner` identifies an `accept()`
/// future, which removes its own entry when it is dropped; entries without an
/// owner come from direct `poll_accept` callers.
#[derive(Debug)]
struct AcceptWaiter {
    owner: Option<u64>,
    waker: Waker,
}

impl AcceptWaiters {
    fn next_owner(&self) -> u64 {
        self.next_owner.fetch_add(1, AtomicOrdering::Relaxed)
    }

    fn register(&self, owner: Option<u64>, waker: &Waker) {
        let mut waiters = self.waiters.lock();
        if owner.is_some() {
            // An accept() future keeps one entry, updated in place and removed
            // when the future is dropped, so it never has to be evicted.
            if let Some(entry) = waiters.iter_mut().find(|entry| entry.owner == owner) {
                entry.waker.clone_from(waker);
            } else {
                waiters.push(AcceptWaiter {
                    owner,
                    waker: waker.clone(),
                });
            }
            return;
        }
        if waiters
            .iter()
            .any(|existing| existing.owner.is_none() && existing.waker.will_wake(waker))
        {
            return;
        }
        // A direct poll_accept caller cannot be told apart from an abandoned
        // one, so those entries stay capped. Evicting live accept() futures
        // instead made each evicted waiter evict the next: with 33 tasks
        // accepting on one listener they woke each other forever.
        if waiters.iter().filter(|entry| entry.owner.is_none()).count() >= 32 {
            if let Some(index) = waiters.iter().position(|entry| entry.owner.is_none()) {
                // Wake the evicted waiter so its task can re-register
                // rather than hang forever with a lost wakeup.
                waiters.remove(index).waker.wake();
            }
        }
        waiters.push(AcceptWaiter {
            owner: None,
            waker: waker.clone(),
        });
    }

    fn remove(&self, owner: u64) {
        self.waiters
            .lock()
            .retain(|entry| entry.owner != Some(owner));
    }

    fn wake_all(&self) {
        let waiters = {
            let mut guard = self.waiters.lock();
            std::mem::take(&mut *guard)
        };
        for waiter in waiters {
            waiter.waker.wake();
        }
    }

    fn wake_others(&self, current: &Waker) {
        let waiters = {
            let mut guard = self.waiters.lock();
            std::mem::take(&mut *guard)
        };
        for waiter in waiters {
            if !waiter.waker.will_wake(current) {
                waiter.waker.wake();
            }
        }
    }
}

/// The future `accept()` returns. It owns one entry in the listener's waiter
/// list and removes it when dropped, so any number of tasks can wait on one
/// listener without evicting one another.
struct AcceptFuture<'a> {
    listener: &'a UnixListener,
    owner: u64,
}

impl Future for AcceptFuture<'_> {
    type Output = io::Result<(UnixStream, SocketAddr)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.listener.poll_accept_as(cx, Some(self.owner))
    }
}

impl Drop for AcceptFuture<'_> {
    fn drop(&mut self) {
        self.listener.accept_waiters.remove(self.owner);
    }
}

use std::task::Wake;
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
        Ok(metadata) if FileTypeExt::is_socket(&metadata.file_type()) => {
            Ok(Some(SocketFileIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            }))
        }
        Ok(_) => Ok(None),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub(crate) fn reject_non_socket_bind_path(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if FileTypeExt::is_socket(&metadata.file_type()) => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to bind over non-socket path: {}", path.display()),
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
pub(crate) fn remove_stale_socket_file(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if FileTypeExt::is_socket(&metadata.file_type()) => {
            if !socket_path_looks_stale(path)? {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "refusing to remove socket path that may still be live: {}",
                        path.display()
                    ),
                ));
            }

            match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err),
            }
        }
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

#[cfg(test)]
fn connect_in_progress(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) || err.raw_os_error() == Some(libc::EINPROGRESS)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
enum SocketLivenessProbe {
    Live,
    Stale,
    WrongType,
    Uncertain,
}

#[cfg(test)]
fn probe_socket_liveness(path: &Path, socket_type: Type) -> io::Result<SocketLivenessProbe> {
    let socket = socket2::Socket::new(Domain::UNIX, socket_type, None)?;
    socket.set_nonblocking(true)?;

    let addr = SockAddr::unix(path)?;
    let verdict = match socket.connect(&addr) {
        Ok(()) => SocketLivenessProbe::Live,
        Err(err) if connect_in_progress(&err) => SocketLivenessProbe::Live,
        Err(err)
            if err.kind() == io::ErrorKind::ConnectionRefused
                || err.kind() == io::ErrorKind::NotFound =>
        {
            SocketLivenessProbe::Stale
        }
        Err(err)
            if matches!(
                err.raw_os_error(),
                Some(
                    libc::EPROTOTYPE
                        | libc::EOPNOTSUPP
                        | libc::ESOCKTNOSUPPORT
                        | libc::EPROTONOSUPPORT
                )
            ) =>
        {
            SocketLivenessProbe::WrongType
        }
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => SocketLivenessProbe::Uncertain,
        Err(_) => SocketLivenessProbe::Uncertain,
    };

    Ok(verdict)
}

#[cfg(test)]
fn socket_path_looks_stale(path: &Path) -> io::Result<bool> {
    let stream_probe = probe_socket_liveness(path, Type::STREAM)?;
    if matches!(
        stream_probe,
        SocketLivenessProbe::Live | SocketLivenessProbe::Uncertain
    ) {
        return Ok(false);
    }

    let datagram_probe = probe_socket_liveness(path, Type::DGRAM)?;
    if matches!(
        datagram_probe,
        SocketLivenessProbe::Live | SocketLivenessProbe::Uncertain
    ) {
        return Ok(false);
    }

    Ok(matches!(stream_probe, SocketLivenessProbe::Stale)
        || matches!(datagram_probe, SocketLivenessProbe::Stale))
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
    /// Reactor registration for I/O events (lazily initialized), aware of
    /// the process-global fallback I/O driver (GH#67, tx9j0f).
    registration: Mutex<ReactorRegistration>,
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
    /// let listener = UnixListener::bind("/tmp/my_socket.sock").await?;
    /// ```
    ///
    /// Refuses with [`IoCapabilityDenied`](crate::cx::IoCapabilityDenied)
    /// when the calling task's `Cx` lacks the IO capability.
    pub async fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        crate::cx::io_gate::require_ambient_io("net::UnixListener::bind")?;
        let path = path.as_ref();

        reject_non_socket_bind_path(path)?;
        let inner = net::UnixListener::bind(path)?;
        Self::from_bound_with(path, inner, |socket| socket.set_nonblocking(true))
    }

    /// Binds to an abstract namespace socket (Linux only).
    ///
    /// Abstract namespace sockets are not bound to the filesystem and are
    /// automatically cleaned up by the kernel when all references are closed.
    ///
    /// No file permissions guard one: any process in the same network
    /// namespace can connect. Bind a filesystem path when access control
    /// matters, or check each accepted stream's [`UnixStream::peer_cred`].
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

        crate::cx::io_gate::require_ambient_io("net::UnixListener::bind_abstract")?;
        let addr = SocketAddr::from_abstract_name(name)?;
        let inner = net::UnixListener::bind_addr(&addr)?;
        inner.set_nonblocking(true)?;

        Ok(Self {
            inner,
            accept_waiters: Arc::new(AcceptWaiters::default()),
            path: None, // No filesystem path for abstract sockets
            cleanup_identity: None,
            registration: Mutex::new(ReactorRegistration::new()), // Lazy registration on first poll
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
        self.accept_future().await
    }

    fn accept_future(&self) -> AcceptFuture<'_> {
        AcceptFuture {
            listener: self,
            owner: self.accept_waiters.next_owner(),
        }
    }

    /// Polls for an incoming connection using reactor wakeups.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(UnixStream, SocketAddr)>> {
        self.poll_accept_as(cx, None)
    }

    fn poll_accept_as(
        &self,
        cx: &mut Context<'_>,
        owner: Option<u64>,
    ) -> Poll<io::Result<(UnixStream, SocketAddr)>> {
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        match self.inner.accept() {
            Ok((stream, addr)) => {
                self.accept_waiters.wake_others(cx.waker());
                Poll::Ready(UnixStream::from_std(stream).map(|stream| (stream, addr)))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.accept_waiters.register(owner, cx.waker());
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
    ///
    /// With no ambient I/O driver the fd parks on the process-global fallback
    /// driver instead of re-waking the accept waiters into a hot loop (GH#67,
    /// asupersync-tx9j0f); see [`ReactorRegistration::arm`]. The lock is
    /// released before any self-wake so a re-poll cannot contend on it.
    fn register_interest(&self) -> io::Result<()> {
        let accept_waker = Waker::from(Arc::clone(&self.accept_waiters));
        let armed = self
            .registration
            .lock()
            .arm(&self.inner, Interest::READABLE, &accept_waker)?;
        if armed == Armed::SelfWake {
            fallback_rewake_waiters(&self.accept_waiters);
        }
        Ok(())
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
            registration: Mutex::new(ReactorRegistration::new()), // Lazy registration on first poll
        })
    }

    /// Returns a stream of incoming connections.
    ///
    /// Each item yielded by the stream is an `io::Result<UnixStream>`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use asupersync::net::unix::UnixListener;
    /// use asupersync::stream::StreamExt;
    ///
    /// async fn serve() -> std::io::Result<()> {
    ///     let listener = UnixListener::bind("/tmp/socket.sock").await?;
    ///     let mut incoming = listener.incoming();
    ///
    ///     while let Some(stream) = incoming.next().await {
    ///         let stream = stream?;
    ///         // Handle connection...
    ///         # let _ = stream;
    ///     }
    ///     Ok(())
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
            registration: Mutex::new(ReactorRegistration::new()), // Lazy registration on first poll
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
#[path = "listener_inline_tests.rs"]
mod tests;
