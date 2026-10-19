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
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
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
    waiters: parking_lot::Mutex<Vec<FdWaiter>>,
    next_owner: AtomicU64,
}

/// One task waiting on the descriptor. `owner` identifies a `ready` future,
/// which removes its own entry when it is dropped; entries without an owner
/// come from direct `poll_read_ready`/`poll_write_ready` callers.
struct FdWaiter {
    owner: Option<u64>,
    waker: Waker,
}

impl FdReadiness {
    fn next_owner(&self) -> u64 {
        self.next_owner.fetch_add(1, Ordering::Relaxed)
    }

    /// Lists `waker` for the next event. A `ready` future keeps one entry,
    /// updated in place and removed when the future is dropped, so it is
    /// never evicted. A direct poller cannot be told apart from an abandoned
    /// one, so those entries stay capped at 32: past that the oldest is woken
    /// and evicted. Evicting `ready` futures too made each evicted waiter
    /// evict the next, so 33 tasks waiting on one descriptor woke each other
    /// forever (br-asupersync-68jvck, as for the listeners in dofi11).
    fn register(&self, owner: Option<u64>, waker: &Waker) {
        // Keep unchanged pollers cheap. will_wake only compares waker
        // identity; cloning or dropping a user waker can run arbitrary code.
        {
            let waiters = self.waiters.lock();
            if waiters
                .iter()
                .any(|entry| entry.owner == owner && entry.waker.will_wake(waker))
            {
                return;
            }
        }

        let incoming = waker.clone();
        let (retired, evicted) = {
            let mut waiters = self.waiters.lock();
            // The clone above may reenter, and another poller may have
            // changed the list. Recheck identity before replacing/inserting.
            let existing = waiters.iter_mut().find(|entry| {
                entry.owner == owner && (owner.is_some() || entry.waker.will_wake(&incoming))
            });
            if let Some(entry) = existing {
                let retired = if entry.waker.will_wake(&incoming) {
                    incoming
                } else {
                    std::mem::replace(&mut entry.waker, incoming)
                };
                (Some(retired), None)
            } else {
                let evicted = if owner.is_none()
                    && waiters.iter().filter(|entry| entry.owner.is_none()).count() >= 32
                    && let Some(index) = waiters.iter().position(|entry| entry.owner.is_none())
                {
                    Some(waiters.remove(index))
                } else {
                    None
                };
                // Publish the insertion before waking an evicted poller. If
                // its callback registers again, it must see the full list so
                // it cannot refill a vacancy and let this insertion exceed 32.
                waiters.push(FdWaiter {
                    owner,
                    waker: incoming,
                });
                (None, evicted)
            }
        };
        drop(retired);
        if let Some(evicted) = evicted {
            evicted.waker.wake();
        }
    }

    fn remove(&self, owner: u64) {
        let (retired, survivors) = {
            let mut waiters = self.waiters.lock();
            let Some(index) = waiters.iter().position(|entry| entry.owner == Some(owner)) else {
                return;
            };
            let retired = waiters.remove(index);
            (retired, std::mem::take(&mut *waiters))
        };
        // A shared registration can have moved to this owner's runtime.
        // Wake survivors so they rehome it if that runtime becomes idle.
        // This is a scheduling hint, not an I/O event: do not modify ready or
        // armed bits, and run all user waker hooks outside the list lock.
        drop(retired);
        for survivor in survivors {
            survivor.waker.wake();
        }
    }

    /// Wakes every listed waiter but `current`, for a wait the reactor will
    /// not complete: each re-polls and sees the readiness or the error itself.
    fn wake_others(&self, current: &Waker) {
        let mut waiters = std::mem::take(&mut *self.waiters.lock());
        waiters.retain(|waiter| !waiter.waker.will_wake(current));
        for waiter in waiters {
            waiter.waker.wake();
        }
    }

    fn fire(&self) {
        let fired = self.armed.swap(0, Ordering::AcqRel);
        self.ready.fetch_or(fired, Ordering::AcqRel);
        let waiters = std::mem::take(&mut *self.waiters.lock());
        for waiter in waiters {
            waiter.waker.wake();
        }
    }
}

/// Removes a `ready` future's waiter entry when the future ends or is
/// dropped.
struct OwnedWait {
    readiness: Arc<FdReadiness>,
    owner: u64,
}

impl Drop for OwnedWait {
    fn drop(&mut self) {
        self.readiness.remove(self.owner);
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
    /// reactor refuses fails that wait with the reactor's error: a regular
    /// file or `/dev/null` under Linux epoll gives `PermissionDenied`
    /// (`EPERM`), as tokio refuses one in `new`. Only a reactor that reports
    /// registration unsupported makes waits re-poll after a short backoff
    /// (br-asupersync-68jvck).
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
        self.poll_ready_bits(cx, READ, None)
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
        self.poll_ready_bits(cx, WRITE, None)
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
        let wait = self.owned_wait();
        let owner = Some(wait.owner);
        let ready = std::future::poll_fn(|cx| self.poll_ready_bits(cx, wanted, owner)).await?;
        drop(wait);
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
        let wait = self.owned_wait();
        let owner = Some(wait.owner);
        let ready = std::future::poll_fn(|cx| self.poll_ready_bits(cx, wanted, owner)).await?;
        drop(wait);
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
    fn poll_ready_bits(
        &self,
        cx: &Context<'_>,
        wanted: u8,
        owner: Option<u64>,
    ) -> Poll<io::Result<u8>> {
        if crate::cx::Cx::with_current(|current| current.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let ready = self.readiness.ready.load(Ordering::Acquire) & wanted;
        if ready != 0 {
            return Poll::Ready(Ok(ready));
        }

        // Listed and armed before the reactor sees the interest, so an event
        // that fires at once still finds this waiter.
        self.readiness.register(owner, cx.waker());
        let dispatch = Waker::from(Arc::clone(&self.readiness));
        let source = RawSource(self.get_ref().as_raw_fd());
        let armed = {
            let mut registration = self.registration.lock();
            // A different poller can move this registration to another
            // runtime. Preserve every direction still waiting for an event,
            // including the opposite direction requested by an earlier poll.
            // Update and snapshot under the registration lock so serialized
            // arm calls cannot overwrite a newer poll's interest union.
            let pending = self.readiness.armed.fetch_or(wanted, Ordering::AcqRel) | wanted;
            // A concurrent fire may consume this snapshot, but it publishes
            // those bits to ready and wakes the waiters. Re-arming that older
            // union can only produce another readiness hint.
            registration.arm(&source, bits_interest(pending), &dispatch)
        };
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

    /// A waiter identity for one `ready` future, removed when it is dropped.
    fn owned_wait(&self) -> OwnedWait {
        OwnedWait {
            readiness: Arc::clone(&self.readiness),
            owner: self.readiness.next_owner(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::runtime::IoDriverHandle;
    use crate::runtime::reactor::{Event, LabReactor, Reactor, Token};
    use crate::types::{Budget, RegionId, TaskId};
    use std::future::Future;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counted_waker() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        (count, waker)
    }

    fn lab_driver() -> (Arc<LabReactor>, IoDriverHandle) {
        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor.clone());
        (reactor, driver)
    }

    fn ambient(driver: &IoDriverHandle) -> Cx {
        Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver.clone()),
            None,
        )
    }

    fn with_driver<T>(driver: &IoDriverHandle, poll: impl FnOnce() -> T) -> T {
        let _current = Cx::set_current(Some(ambient(driver)));
        poll()
    }

    fn nonblocking_pair() -> (AsyncFd<UnixStream>, UnixStream) {
        let (local, peer) = UnixStream::pair().expect("socket pair");
        local.set_nonblocking(true).expect("nonblocking local");
        peer.set_nonblocking(true).expect("nonblocking peer");
        (AsyncFd::new(local).expect("wrap descriptor"), peer)
    }

    fn registered_token(fd: &AsyncFd<UnixStream>, driver: &IoDriverHandle, expected: u8) -> Token {
        let registration = fd.registration.lock();
        let registration = registration.as_ref().expect("live registration");
        assert!(registration.belongs_to(driver));
        assert_eq!(interest_bits(registration.interest()), expected);
        registration.token()
    }

    fn dispatch(reactor: &LabReactor, driver: &IoDriverHandle, token: Token, ready: u8) -> usize {
        reactor.set_ready(token, Event::new(token, bits_interest(ready)));
        driver
            .turn_with(Some(Duration::ZERO), |_, _| {})
            .expect("dispatch readiness")
    }

    #[test]
    fn opposite_direction_migration_preserves_pending_interests() {
        for first in [READ, WRITE] {
            let second = (READ | WRITE) ^ first;
            let (fd, mut peer) = nonblocking_pair();
            let raw = fd.as_raw_fd();
            let (reactor_a, driver_a) = lab_driver();
            let (reactor_b, driver_b) = lab_driver();
            let (first_count, first_waker) = counted_waker();
            let (second_count, second_waker) = counted_waker();
            let mut first_cx = Context::from_waker(&first_waker);
            let mut second_cx = Context::from_waker(&second_waker);
            {
                let mut first_wait = Box::pin(fd.ready(bits_interest(first)));
                let mut second_wait = Box::pin(fd.ready(bits_interest(second)));
                assert!(
                    with_driver(&driver_a, || { first_wait.as_mut().poll(&mut first_cx) })
                        .is_pending()
                );
                let old_token = registered_token(&fd, &driver_a, first);
                assert!(
                    with_driver(&driver_b, || { second_wait.as_mut().poll(&mut second_cx) })
                        .is_pending()
                );
                let new_token = registered_token(&fd, &driver_b, READ | WRITE);
                assert_eq!(reactor_a.registration_count(), 0);
                assert_eq!(driver_a.waker_count(), 0);
                assert_eq!(reactor_b.registration_count(), 1);
                assert_eq!(fd.readiness.armed.load(Ordering::SeqCst), READ | WRITE);
                assert_eq!(fd.readiness.ready.load(Ordering::SeqCst), 0);
                assert_eq!(first_count.0.load(Ordering::SeqCst), 0);
                assert_eq!(second_count.0.load(Ordering::SeqCst), 0);

                // A retired token cannot satisfy the wait. The only event on
                // B is for A's original direction: arming only `second`
                // filters this event out and leaves both callers asleep.
                assert_eq!(dispatch(&reactor_a, &driver_a, old_token, first), 0);
                assert_eq!(dispatch(&reactor_b, &driver_b, new_token, first), 1);
                assert_eq!(first_count.0.load(Ordering::SeqCst), 1);
                assert_eq!(second_count.0.load(Ordering::SeqCst), 1);
                assert_eq!(fd.readiness.armed.load(Ordering::SeqCst), 0);
                // The dispatcher has always reported all armed directions
                // as hints; each guard still returns only its requested bit.
                assert_eq!(fd.readiness.ready.load(Ordering::SeqCst), READ | WRITE);
                let Poll::Ready(Ok(mut first_guard)) =
                    with_driver(&driver_a, || first_wait.as_mut().poll(&mut first_cx))
                else {
                    panic!("original direction must be ready after migration");
                };
                assert_eq!(first_guard.ready, first);
                first_guard.clear_ready();
                assert_eq!(fd.readiness.ready.load(Ordering::SeqCst), second);
                let Poll::Ready(Ok(mut second_guard)) =
                    with_driver(&driver_b, || second_wait.as_mut().poll(&mut second_cx))
                else {
                    panic!("opposite direction retains its readiness hint");
                };
                assert_eq!(second_guard.ready, second);
                second_guard.clear_ready();
                assert_eq!(fd.readiness.ready.load(Ordering::SeqCst), 0);
            }
            let mut local = fd.into_inner();
            assert_eq!(local.as_raw_fd(), raw);
            assert_eq!(reactor_b.registration_count(), 0);
            assert_eq!(driver_b.waker_count(), 0);
            peer.write_all(b"owned").expect("peer write");
            let mut bytes = [0; 5];
            local.read_exact(&mut bytes).expect("descriptor survives");
            assert_eq!(&bytes, b"owned");
        }
    }

    #[test]
    fn departing_migrator_preserves_the_opposite_waiter_and_readiness_bits() {
        for first in [READ, WRITE] {
            for cancel in [false, true] {
                let second = (READ | WRITE) ^ first;
                let (fd, _peer) = nonblocking_pair();
                let (reactor_a, driver_a) = lab_driver();
                let (reactor_b, driver_b) = lab_driver();
                let (first_count, first_waker) = counted_waker();
                let (second_count, second_waker) = counted_waker();
                let mut first_cx = Context::from_waker(&first_waker);
                let mut second_cx = Context::from_waker(&second_waker);
                let mut first_wait = Box::pin(fd.ready(bits_interest(first)));
                let mut second_wait = Box::pin(fd.ready(bits_interest(second)));
                assert!(
                    with_driver(&driver_a, || { first_wait.as_mut().poll(&mut first_cx) })
                        .is_pending()
                );
                assert!(
                    with_driver(&driver_b, || { second_wait.as_mut().poll(&mut second_cx) })
                        .is_pending()
                );
                registered_token(&fd, &driver_b, READ | WRITE);

                if cancel {
                    let cancelled = ambient(&driver_b);
                    cancelled.set_cancel_requested(true);
                    let _current = Cx::set_current(Some(cancelled));
                    let Poll::Ready(Err(error)) = second_wait.as_mut().poll(&mut second_cx) else {
                        panic!("cancelled migrating wait must finish");
                    };
                    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                }
                drop(second_wait);
                assert_eq!(first_count.0.load(Ordering::SeqCst), 1);
                assert_eq!(second_count.0.load(Ordering::SeqCst), 0);
                assert_eq!(fd.readiness.ready.load(Ordering::SeqCst), 0);
                assert_eq!(fd.readiness.armed.load(Ordering::SeqCst), READ | WRITE);

                // B can now remain alive and idle. The departure wake lets
                // A rehome the surviving wait without claiming I/O occurred.
                assert!(
                    with_driver(&driver_a, || { first_wait.as_mut().poll(&mut first_cx) })
                        .is_pending()
                );
                let token = registered_token(&fd, &driver_a, READ | WRITE);
                assert_eq!(reactor_b.registration_count(), 0);
                assert_eq!(driver_b.waker_count(), 0);
                assert_eq!(dispatch(&reactor_a, &driver_a, token, first), 1);
                assert_eq!(first_count.0.load(Ordering::SeqCst), 2);
                assert_eq!(second_count.0.load(Ordering::SeqCst), 0);
                {
                    let Poll::Ready(Ok(guard)) =
                        with_driver(&driver_a, || first_wait.as_mut().poll(&mut first_cx))
                    else {
                        panic!("surviving waiter must receive its event");
                    };
                    assert_eq!(guard.ready, first);
                }
                drop(first_wait);
                drop(fd);
                assert_eq!(reactor_a.registration_count(), 0);
                assert_eq!(driver_a.waker_count(), 0);
            }
        }
    }

    #[test]
    fn extracted_readiness_survives_migration_and_directional_clear() {
        for first in [READ, WRITE] {
            let second = (READ | WRITE) ^ first;
            let (fd, _peer) = nonblocking_pair();
            let (reactor_a, driver_a) = lab_driver();
            let (reactor_b, driver_b) = lab_driver();
            let (first_count, first_waker) = counted_waker();
            let (second_count, second_waker) = counted_waker();
            let mut first_cx = Context::from_waker(&first_waker);
            let mut second_cx = Context::from_waker(&second_waker);
            let mut first_wait = Box::pin(fd.ready(bits_interest(first)));
            let mut second_wait = Box::pin(fd.ready(bits_interest(second)));
            assert!(
                with_driver(&driver_a, || { first_wait.as_mut().poll(&mut first_cx) }).is_pending()
            );
            let token = registered_token(&fd, &driver_a, first);
            reactor_a.set_ready(token, Event::new(token, bits_interest(first)));
            // The driver has extracted its dispatch waker before this
            // callback. Retire its token and migrate, then deliver the old
            // waker afterward: this is a deterministic concurrent-event cut.
            assert_eq!(
                driver_a
                    .turn_with(Some(Duration::ZERO), |_, _| {
                        assert!(
                            with_driver(&driver_b, || {
                                second_wait.as_mut().poll(&mut second_cx)
                            })
                            .is_pending()
                        );
                        registered_token(&fd, &driver_b, READ | WRITE);
                        assert_eq!(reactor_a.registration_count(), 0);
                        assert_eq!(fd.readiness.ready.load(Ordering::SeqCst), 0);
                        assert_eq!(fd.readiness.armed.load(Ordering::SeqCst), READ | WRITE);
                    })
                    .expect("dispatch extracted event"),
                1
            );
            assert_eq!(first_count.0.load(Ordering::SeqCst), 1);
            assert_eq!(second_count.0.load(Ordering::SeqCst), 1);
            assert_eq!(fd.readiness.armed.load(Ordering::SeqCst), 0);
            assert_eq!(fd.readiness.ready.load(Ordering::SeqCst), READ | WRITE);
            {
                let Poll::Ready(Ok(mut guard)) =
                    with_driver(&driver_a, || first_wait.as_mut().poll(&mut first_cx))
                else {
                    panic!("extracted event must reach the original waiter");
                };
                guard.clear_ready();
            }
            drop(first_wait);
            assert_eq!(fd.readiness.ready.load(Ordering::SeqCst), second);

            let mut first_again = Box::pin(fd.ready(bits_interest(first)));
            assert!(
                with_driver(&driver_b, || { first_again.as_mut().poll(&mut first_cx) })
                    .is_pending()
            );
            assert_eq!(fd.readiness.armed.load(Ordering::SeqCst), first);
            assert_eq!(fd.readiness.ready.load(Ordering::SeqCst), second);
            let token = registered_token(&fd, &driver_b, READ | WRITE);
            assert_eq!(dispatch(&reactor_b, &driver_b, token, first), 1);
            assert_eq!(first_count.0.load(Ordering::SeqCst), 2);
            assert_eq!(second_count.0.load(Ordering::SeqCst), 1);
            assert_eq!(fd.readiness.ready.load(Ordering::SeqCst), READ | WRITE);
            let Poll::Ready(Ok(first_guard)) =
                with_driver(&driver_b, || first_again.as_mut().poll(&mut first_cx))
            else {
                panic!("cleared direction must receive a later event");
            };
            let Poll::Ready(Ok(second_guard)) =
                with_driver(&driver_b, || second_wait.as_mut().poll(&mut second_cx))
            else {
                panic!("clearing one direction must retain the other hint");
            };
            assert_eq!(first_guard.ready, first);
            assert_eq!(second_guard.ready, second);
        }
    }

    #[test]
    fn replacing_owned_waker_runs_its_destructor_after_publishing_and_unlocking() {
        struct Replaced {
            readiness: std::sync::Weak<FdReadiness>,
            replacement: Waker,
            drops: Arc<AtomicUsize>,
        }
        impl Wake for Replaced {
            fn wake(self: Arc<Self>) {
                panic!("a replaced waiter must not be woken");
            }
        }
        impl Drop for Replaced {
            fn drop(&mut self) {
                if let Some(readiness) = self.readiness.upgrade() {
                    {
                        let waiters = readiness
                            .waiters
                            .try_lock()
                            .expect("replacement destructor must run outside the gate");
                        assert_eq!(waiters.len(), 1);
                        assert_eq!(waiters[0].owner, Some(0));
                        assert!(waiters[0].waker.will_wake(&self.replacement));
                    }
                    readiness.register(Some(1), Waker::noop());
                }
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        let readiness = Arc::new(FdReadiness::default());
        let (count, replacement) = counted_waker();
        let drops = Arc::new(AtomicUsize::new(0));
        let old = Waker::from(Arc::new(Replaced {
            readiness: Arc::downgrade(&readiness),
            replacement: replacement.clone(),
            drops: Arc::clone(&drops),
        }));
        readiness.ready.store(WRITE, Ordering::SeqCst);
        readiness.armed.store(READ, Ordering::SeqCst);
        readiness.register(Some(0), &old);
        drop(old);
        readiness.register(Some(0), &replacement);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(readiness.waiters.lock().len(), 2);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);

        // An unchanged owner is a no-op, but another owner with the same
        // waker still needs its own entry. Direct pollers deduplicate only
        // against other direct pollers, never against owned futures.
        readiness.register(Some(0), &replacement);
        assert_eq!(readiness.waiters.lock().len(), 2);
        readiness.register(Some(2), &replacement);
        assert_eq!(readiness.waiters.lock().len(), 3);
        readiness.register(None, &replacement);
        readiness.register(None, &replacement);
        assert_eq!(readiness.waiters.lock().len(), 4);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(readiness.ready.load(Ordering::SeqCst), WRITE);
        assert_eq!(readiness.armed.load(Ordering::SeqCst), READ);
    }

    #[test]
    fn reentrant_eviction_preserves_the_direct_poller_cap_and_owned_waiters() {
        struct Evicted {
            readiness: std::sync::Weak<FdReadiness>,
            reentrant: Waker,
            wakes: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
        }
        impl Wake for Evicted {
            fn wake(self: Arc<Self>) {
                let readiness = self.readiness.upgrade().expect("live waiter list");
                assert!(readiness.waiters.try_lock().is_some(), "wake outside gate");
                self.wakes.fetch_add(1, Ordering::SeqCst);
                readiness.register(None, &self.reentrant);
            }
        }
        impl Drop for Evicted {
            fn drop(&mut self) {
                if let Some(readiness) = self.readiness.upgrade() {
                    assert!(readiness.waiters.try_lock().is_some(), "drop outside gate");
                }
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        let readiness = Arc::new(FdReadiness::default());
        let wakes = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let (reentrant_count, reentrant) = counted_waker();
        let oldest = Waker::from(Arc::new(Evicted {
            readiness: Arc::downgrade(&readiness),
            reentrant: reentrant.clone(),
            wakes: Arc::clone(&wakes),
            drops: Arc::clone(&drops),
        }));
        for owner in 0..40 {
            readiness.register(Some(owner), Waker::noop());
        }
        readiness.register(None, &oldest);
        drop(oldest);
        let later: Vec<_> = (0..31).map(|_| counted_waker()).collect();
        for (_, waker) in &later {
            readiness.register(None, waker);
        }
        readiness.ready.store(WRITE, Ordering::SeqCst);
        readiness.armed.store(READ, Ordering::SeqCst);
        let (incoming_count, incoming) = counted_waker();
        readiness.register(None, &incoming);

        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let (next_evicted, _) = &later[0];
        assert_eq!(next_evicted.0.load(Ordering::SeqCst), 1);
        assert!(
            later[1..]
                .iter()
                .all(|(count, _)| count.0.load(Ordering::SeqCst) == 0)
        );
        assert_eq!(incoming_count.0.load(Ordering::SeqCst), 0);
        assert_eq!(reentrant_count.0.load(Ordering::SeqCst), 0);
        {
            let waiters = readiness.waiters.lock();
            assert_eq!(
                waiters.iter().filter(|entry| entry.owner.is_none()).count(),
                32
            );
            assert_eq!(
                waiters.iter().filter(|entry| entry.owner.is_some()).count(),
                40
            );
            assert!(waiters.iter().any(|entry| entry.waker.will_wake(&incoming)));
            assert!(
                waiters
                    .iter()
                    .any(|entry| entry.waker.will_wake(&reentrant))
            );
        }
        assert_eq!(readiness.ready.load(Ordering::SeqCst), WRITE);
        assert_eq!(readiness.armed.load(Ordering::SeqCst), READ);
    }

    #[test]
    fn owner_departure_rehomes_survivors_without_fabricating_readiness() {
        struct Retired {
            readiness: std::sync::Weak<FdReadiness>,
            dropped: Arc<AtomicUsize>,
        }
        impl Wake for Retired {
            fn wake(self: Arc<Self>) {
                panic!("a departed descriptor owner must not be woken");
            }
        }
        impl Drop for Retired {
            fn drop(&mut self) {
                if let Some(readiness) = self.readiness.upgrade() {
                    assert!(readiness.waiters.try_lock().is_some(), "drop outside gate");
                }
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
        struct Survivor {
            readiness: std::sync::Weak<FdReadiness>,
            hits: Arc<AtomicUsize>,
        }
        impl Wake for Survivor {
            fn wake(self: Arc<Self>) {
                let readiness = self.readiness.upgrade().expect("live waiter list");
                assert!(readiness.waiters.try_lock().is_some(), "wake outside gate");
                readiness.register(Some(100), Waker::noop());
                self.hits.fetch_add(1, Ordering::SeqCst);
            }
        }

        let readiness = Arc::new(FdReadiness::default());
        let dropped = Arc::new(AtomicUsize::new(0));
        let hits = Arc::new(AtomicUsize::new(0));
        let retired_owner = readiness.next_owner();
        let survivor_owner = readiness.next_owner();
        let retired = Waker::from(Arc::new(Retired {
            readiness: Arc::downgrade(&readiness),
            dropped: Arc::clone(&dropped),
        }));
        let survivor = Waker::from(Arc::new(Survivor {
            readiness: Arc::downgrade(&readiness),
            hits: Arc::clone(&hits),
        }));
        readiness.register(Some(retired_owner), &retired);
        readiness.register(Some(survivor_owner), &survivor);
        readiness.ready.store(WRITE, Ordering::SeqCst);
        readiness.armed.store(READ, Ordering::SeqCst);
        drop(retired);
        readiness.remove(retired_owner);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(readiness.waiters.lock()[0].owner, Some(100));
        assert_eq!(readiness.ready.load(Ordering::SeqCst), WRITE);
        assert_eq!(readiness.armed.load(Ordering::SeqCst), READ);

        readiness.remove(retired_owner);
        readiness.remove(survivor_owner);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "stale departures do not wake"
        );
        assert_eq!(readiness.waiters.lock().len(), 1);
        assert_eq!(readiness.ready.load(Ordering::SeqCst), WRITE);
        assert_eq!(readiness.armed.load(Ordering::SeqCst), READ);
        readiness.fire();
        assert_eq!(readiness.ready.load(Ordering::SeqCst), READ | WRITE);
        assert_eq!(readiness.armed.load(Ordering::SeqCst), 0);
        readiness.register(Some(101), &survivor);
        readiness.remove(100);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "fired ticket is a no-op");
        assert_eq!(readiness.waiters.lock()[0].owner, Some(101));
        assert_eq!(readiness.ready.load(Ordering::SeqCst), READ | WRITE);
        assert_eq!(readiness.armed.load(Ordering::SeqCst), 0);
    }
}
