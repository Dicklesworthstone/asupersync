//! Readiness for arbitrary Unix file descriptors ([`AsyncFd`]).
//!
//! The runtime's own sockets wait for readiness internally. `AsyncFd` exposes
//! the same reactor wait for a descriptor the runtime does not wrap: an
//! `inotify`, `eventfd`, `timerfd` or `signalfd` descriptor, a pipe, a serial
//! port, or the socket of a C library that does its own I/O.
//!
//! The wrapped descriptor must be in non-blocking mode; `AsyncFd` does not
//! change it. Readiness is a hint: a wake can be spurious, so I/O goes through
//! [`AsyncFdReadyGuard::try_io`] (or [`AsyncFd::async_io`]), which clears the
//! readiness when the operation reports `WouldBlock` and waits again.
//!
//! ```no_run
//! use asupersync::io::unix::AsyncFd;
//! use asupersync::runtime::reactor::Interest;
//! use std::io::Read;
//! use std::os::unix::net::UnixStream;
//!
//! # async fn demo() -> std::io::Result<()> {
//! let (local, _peer) = UnixStream::pair()?;
//! local.set_nonblocking(true)?;
//! let fd = AsyncFd::new(local)?;
//! let mut buf = [0_u8; 64];
//! let n = fd
//!     .async_io(Interest::READABLE, |stream| (&*stream).read(&mut buf))
//!     .await?;
//! # let _ = n;
//! # Ok(())
//! # }
//! ```

use crate::net::{Armed, ReactorRegistration};
use crate::runtime::reactor::Interest;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll, Wake, Waker};

const READ: u8 = 1;
const WRITE: u8 = 1 << 1;

/// A descriptor registered with the reactor for readiness waits.
///
/// `AsyncFd` owns the wrapped value `T` and registers its descriptor lazily, on
/// the first wait. Dropping it (or [`into_inner`](Self::into_inner))
/// deregisters the descriptor before `T` is dropped or returned; `T` is never
/// closed by `AsyncFd` itself.
///
/// Several tasks can wait on one `AsyncFd` at once: every waiter parked on a
/// direction is woken by its readiness.
pub struct AsyncFd<T: AsRawFd> {
    // Declared before `inner` so the registration goes first on drop.
    registration: parking_lot::Mutex<ReactorRegistration>,
    readiness: Arc<FdReadiness>,
    inner: Option<T>,
}

/// The descriptor as the reactor sees it. The registration keeps only the
/// number; `AsyncFd` keeps the owner alive for as long as it is registered.
struct RawSource(RawFd);

impl AsRawFd for RawSource {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Readiness bits and the parked waiters, shared with the reactor as the
/// registration's waker.
#[derive(Default)]
struct FdReadiness {
    /// Directions reported ready since a guard last cleared them.
    ready: AtomicU8,
    /// Directions armed with the reactor since its last event. The reactor
    /// reports an event without its direction, so an event marks every armed
    /// direction ready (a spurious direction is cleared by the next
    /// `WouldBlock`).
    armed: AtomicU8,
    waiters: parking_lot::Mutex<Vec<Waker>>,
}

impl FdReadiness {
    /// Adds `waker` unless it is already listed. A waiter whose future was
    /// dropped stays listed until the next event; past 32 entries the oldest
    /// is woken and evicted, so a live one re-registers and a stale one goes.
    fn register(&self, waker: &Waker) {
        let mut waiters = self.waiters.lock();
        if waiters.iter().any(|existing| existing.will_wake(waker)) {
            return;
        }
        if waiters.len() >= 32 {
            let evicted = waiters.remove(0);
            drop(waiters);
            evicted.wake();
            waiters = self.waiters.lock();
        }
        waiters.push(waker.clone());
    }

    /// Wakes every listed waiter but `current`, for a wait the reactor will
    /// not complete: each re-polls and sees the readiness or the error itself.
    fn wake_others(&self, current: &Waker) {
        let mut waiters = std::mem::take(&mut *self.waiters.lock());
        waiters.retain(|waiter| !waiter.will_wake(current));
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn fire(&self) {
        let fired = self.armed.swap(0, Ordering::AcqRel);
        self.ready.fetch_or(fired, Ordering::AcqRel);
        let waiters = std::mem::take(&mut *self.waiters.lock());
        for waiter in waiters {
            waiter.wake();
        }
    }
}

impl Wake for FdReadiness {
    fn wake(self: Arc<Self>) {
        self.fire();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.fire();
    }
}

const fn interest_bits(interest: Interest) -> u8 {
    let mut bits = 0;
    if interest.is_readable() {
        bits |= READ;
    }
    if interest.is_writable() {
        bits |= WRITE;
    }
    bits
}

const fn bits_interest(bits: u8) -> Interest {
    match (bits & READ != 0, bits & WRITE != 0) {
        (true, true) => Interest::both(),
        (false, true) => Interest::WRITABLE,
        _ => Interest::READABLE,
    }
}

impl<T: AsRawFd> AsyncFd<T> {
    /// Wraps `inner`, whose descriptor must already be in non-blocking mode.
    ///
    /// The descriptor is registered with the current task's reactor (or the
    /// process-wide fallback reactor) on the first wait. A descriptor the
    /// reactor refuses, such as a regular file, is treated as always ready:
    /// waits on it re-poll after a short backoff instead of failing.
    ///
    /// # Errors
    ///
    /// None today; the `Result` matches `tokio::io::unix::AsyncFd::new`.
    pub fn new(inner: T) -> io::Result<Self> {
        Ok(Self {
            registration: parking_lot::Mutex::new(ReactorRegistration::new()),
            readiness: Arc::new(FdReadiness::default()),
            inner: Some(inner),
        })
    }

    /// The wrapped value.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        self.inner
            .as_ref()
            .expect("AsyncFd holds its value until dropped")
    }

    /// The wrapped value, mutably.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner
            .as_mut()
            .expect("AsyncFd holds its value until dropped")
    }

    /// Deregisters the descriptor and returns the wrapped value.
    #[must_use]
    pub fn into_inner(mut self) -> T {
        self.registration.get_mut().clear();
        self.inner
            .take()
            .expect("AsyncFd holds its value until dropped")
    }

    /// Polls for read readiness.
    ///
    /// # Errors
    ///
    /// Fails when the reactor reports an error for the registration, or with
    /// `Interrupted` when the current task has been cancelled.
    pub fn poll_read_ready<'a>(
        &'a self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<AsyncFdReadyGuard<'a, T>>> {
        self.poll_ready_bits(cx, READ)
            .map_ok(|ready| AsyncFdReadyGuard {
                async_fd: self,
                ready,
            })
    }

    /// Polls for write readiness.
    ///
    /// # Errors
    ///
    /// As for [`poll_read_ready`](Self::poll_read_ready).
    pub fn poll_write_ready<'a>(
        &'a self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<AsyncFdReadyGuard<'a, T>>> {
        self.poll_ready_bits(cx, WRITE)
            .map_ok(|ready| AsyncFdReadyGuard {
                async_fd: self,
                ready,
            })
    }

    /// Waits until the descriptor may be readable.
    ///
    /// # Errors
    ///
    /// As for [`poll_read_ready`](Self::poll_read_ready).
    pub async fn readable(&self) -> io::Result<AsyncFdReadyGuard<'_, T>> {
        self.ready(Interest::READABLE).await
    }

    /// Waits until the descriptor may be writable.
    ///
    /// # Errors
    ///
    /// As for [`poll_read_ready`](Self::poll_read_ready).
    pub async fn writable(&self) -> io::Result<AsyncFdReadyGuard<'_, T>> {
        self.ready(Interest::WRITABLE).await
    }

    /// Waits until the descriptor may be ready for either direction in
    /// `interest`; the guard says which.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when `interest` names neither direction, otherwise as
    /// for [`poll_read_ready`](Self::poll_read_ready).
    pub async fn ready(&self, interest: Interest) -> io::Result<AsyncFdReadyGuard<'_, T>> {
        let wanted = checked_bits(interest)?;
        let ready = std::future::poll_fn(|cx| self.poll_ready_bits(cx, wanted)).await?;
        Ok(AsyncFdReadyGuard {
            async_fd: self,
            ready,
        })
    }

    /// Like [`readable`](Self::readable), with a guard that gives mutable
    /// access to the wrapped value.
    ///
    /// # Errors
    ///
    /// As for [`poll_read_ready`](Self::poll_read_ready).
    pub async fn readable_mut(&mut self) -> io::Result<AsyncFdReadyMutGuard<'_, T>> {
        self.ready_mut(Interest::READABLE).await
    }

    /// Like [`writable`](Self::writable), with a guard that gives mutable
    /// access to the wrapped value.
    ///
    /// # Errors
    ///
    /// As for [`poll_read_ready`](Self::poll_read_ready).
    pub async fn writable_mut(&mut self) -> io::Result<AsyncFdReadyMutGuard<'_, T>> {
        self.ready_mut(Interest::WRITABLE).await
    }

    /// Like [`ready`](Self::ready), with a guard that gives mutable access to
    /// the wrapped value.
    ///
    /// # Errors
    ///
    /// As for [`ready`](Self::ready).
    pub async fn ready_mut(
        &mut self,
        interest: Interest,
    ) -> io::Result<AsyncFdReadyMutGuard<'_, T>> {
        let wanted = checked_bits(interest)?;
        let ready = std::future::poll_fn(|cx| self.poll_ready_bits(cx, wanted)).await?;
        Ok(AsyncFdReadyMutGuard {
            async_fd: self,
            ready,
        })
    }

    /// Runs `io` once the descriptor may be ready for `interest`, waiting
    /// again each time it reports `WouldBlock`, and returns its first other
    /// result.
    ///
    /// # Errors
    ///
    /// The first error of `io` other than `WouldBlock`, or an error of the
    /// wait itself (see [`ready`](Self::ready)).
    pub async fn async_io<R>(
        &self,
        interest: Interest,
        mut io: impl FnMut(&T) -> io::Result<R>,
    ) -> io::Result<R> {
        loop {
            let mut guard = self.ready(interest).await?;
            if let Ok(result) = guard.try_io(|fd| io(fd.get_ref())) {
                return result;
            }
        }
    }

    /// Like [`async_io`](Self::async_io), with mutable access to the wrapped
    /// value.
    ///
    /// # Errors
    ///
    /// As for [`async_io`](Self::async_io).
    pub async fn async_io_mut<R>(
        &mut self,
        interest: Interest,
        mut io: impl FnMut(&mut T) -> io::Result<R>,
    ) -> io::Result<R> {
        loop {
            let mut guard = self.ready_mut(interest).await?;
            if let Ok(result) = guard.try_io(|fd| io(fd.get_mut())) {
                return result;
            }
        }
    }

    /// Ready when a direction in `wanted` is marked ready; otherwise parks the
    /// task on the reactor for those directions.
    fn poll_ready_bits(&self, cx: &Context<'_>, wanted: u8) -> Poll<io::Result<u8>> {
        if crate::cx::Cx::with_current(|current| current.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let ready = self.readiness.ready.load(Ordering::Acquire) & wanted;
        if ready != 0 {
            return Poll::Ready(Ok(ready));
        }

        // Listed and armed before the reactor sees the interest, so an event
        // that fires at once still finds this waiter.
        self.readiness.register(cx.waker());
        self.readiness.armed.fetch_or(wanted, Ordering::AcqRel);
        let dispatch = Waker::from(Arc::clone(&self.readiness));
        let source = RawSource(self.get_ref().as_raw_fd());
        let armed = self
            .registration
            .lock()
            .arm(&source, bits_interest(wanted), &dispatch);
        match armed {
            Ok(Armed::Parked) => {
                // An event may have landed between the first check and arming.
                let ready = self.readiness.ready.load(Ordering::Acquire) & wanted;
                if ready == 0 {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(ready))
                }
            }
            Ok(Armed::SelfWake) => {
                // No reactor takes this descriptor: report it ready after a
                // short backoff, and let the caller's `WouldBlock` clear it.
                self.readiness.armed.fetch_and(!wanted, Ordering::AcqRel);
                self.readiness.ready.fetch_or(wanted, Ordering::AcqRel);
                self.readiness.wake_others(cx.waker());
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(err) => {
                self.readiness.wake_others(cx.waker());
                Poll::Ready(Err(err))
            }
        }
    }

    fn clear_bits(&self, bits: u8) {
        self.readiness.ready.fetch_and(!bits, Ordering::AcqRel);
    }
}

fn checked_bits(interest: Interest) -> io::Result<u8> {
    match interest_bits(interest) {
        0 => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AsyncFd readiness needs READABLE or WRITABLE interest",
        )),
        bits => Ok(bits),
    }
}

impl<T: AsRawFd> Drop for AsyncFd<T> {
    fn drop(&mut self) {
        self.registration.get_mut().clear();
    }
}

impl<T: AsRawFd> AsRawFd for AsyncFd<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.get_ref().as_raw_fd()
    }
}

impl<T: AsRawFd + fmt::Debug> fmt::Debug for AsyncFd<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncFd")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

/// The `WouldBlock` outcome of [`AsyncFdReadyGuard::try_io`]: the readiness
/// was spurious and has been cleared, so wait again.
#[derive(Debug)]
pub struct TryIoError(());

impl fmt::Display for TryIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operation would block; readiness cleared")
    }
}

impl std::error::Error for TryIoError {}

/// Readiness returned by [`AsyncFd::readable`], [`AsyncFd::writable`] and
/// [`AsyncFd::ready`].
///
/// Dropping the guard keeps the readiness, so the next wait returns at once;
/// [`clear_ready`](Self::clear_ready) (or a `WouldBlock` through
/// [`try_io`](Self::try_io)) makes the next wait park until the reactor
/// reports the descriptor again.
pub struct AsyncFdReadyGuard<'a, T: AsRawFd> {
    async_fd: &'a AsyncFd<T>,
    ready: u8,
}

impl<'a, T: AsRawFd> AsyncFdReadyGuard<'a, T> {
    /// The `AsyncFd` this guard came from.
    #[must_use]
    pub const fn get_ref(&self) -> &'a AsyncFd<T> {
        self.async_fd
    }

    /// The wrapped value.
    #[must_use]
    pub fn get_inner(&self) -> &'a T {
        self.async_fd.get_ref()
    }

    /// Whether the guard reports read readiness.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.ready & READ != 0
    }

    /// Whether the guard reports write readiness.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.ready & WRITE != 0
    }

    /// Marks the guard's directions not ready, so the next wait parks until
    /// the reactor reports the descriptor again. Call it after an operation
    /// returned `WouldBlock`.
    pub fn clear_ready(&mut self) {
        self.async_fd.clear_bits(self.ready);
    }

    /// Keeps the readiness (what dropping the guard does).
    pub const fn retain_ready(&mut self) {}

    /// Runs `io`; on `WouldBlock` clears the readiness and returns
    /// `Err(TryIoError)`, otherwise returns its result.
    ///
    /// # Errors
    ///
    /// `Err(TryIoError)` when `io` reported `WouldBlock`.
    pub fn try_io<R>(
        &mut self,
        io: impl FnOnce(&'a AsyncFd<T>) -> io::Result<R>,
    ) -> Result<io::Result<R>, TryIoError> {
        match io(self.async_fd) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                self.clear_ready();
                Err(TryIoError(()))
            }
            result => Ok(result),
        }
    }
}

impl<T: AsRawFd + fmt::Debug> fmt::Debug for AsyncFdReadyGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncFdReadyGuard")
            .field("async_fd", self.async_fd)
            .field("readable", &self.is_readable())
            .field("writable", &self.is_writable())
            .finish()
    }
}

/// Readiness with mutable access, returned by [`AsyncFd::readable_mut`],
/// [`AsyncFd::writable_mut`] and [`AsyncFd::ready_mut`]. Behaves as
/// [`AsyncFdReadyGuard`].
pub struct AsyncFdReadyMutGuard<'a, T: AsRawFd> {
    async_fd: &'a mut AsyncFd<T>,
    ready: u8,
}

impl<T: AsRawFd> AsyncFdReadyMutGuard<'_, T> {
    /// The `AsyncFd` this guard came from.
    #[must_use]
    pub fn get_ref(&self) -> &AsyncFd<T> {
        self.async_fd
    }

    /// The `AsyncFd` this guard came from, mutably.
    pub fn get_mut(&mut self) -> &mut AsyncFd<T> {
        self.async_fd
    }

    /// The wrapped value.
    #[must_use]
    pub fn get_inner(&self) -> &T {
        self.async_fd.get_ref()
    }

    /// The wrapped value, mutably.
    pub fn get_inner_mut(&mut self) -> &mut T {
        self.async_fd.get_mut()
    }

    /// Whether the guard reports read readiness.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.ready & READ != 0
    }

    /// Whether the guard reports write readiness.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.ready & WRITE != 0
    }

    /// As [`AsyncFdReadyGuard::clear_ready`].
    pub fn clear_ready(&mut self) {
        self.async_fd.clear_bits(self.ready);
    }

    /// Keeps the readiness (what dropping the guard does).
    pub const fn retain_ready(&mut self) {}

    /// As [`AsyncFdReadyGuard::try_io`], with mutable access.
    ///
    /// # Errors
    ///
    /// `Err(TryIoError)` when `io` reported `WouldBlock`.
    pub fn try_io<R>(
        &mut self,
        io: impl FnOnce(&mut AsyncFd<T>) -> io::Result<R>,
    ) -> Result<io::Result<R>, TryIoError> {
        match io(self.async_fd) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                self.clear_ready();
                Err(TryIoError(()))
            }
            result => Ok(result),
        }
    }
}

impl<T: AsRawFd + fmt::Debug> fmt::Debug for AsyncFdReadyMutGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncFdReadyMutGuard")
            .field("async_fd", &*self.async_fd)
            .field("readable", &self.is_readable())
            .field("writable", &self.is_writable())
            .finish()
    }
}
