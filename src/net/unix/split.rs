//! Unix stream splitting.
//!
//! This module provides borrowed and owned halves for splitting a
//! [`UnixStream`](super::UnixStream) into separate read and write handles.

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncReadVectored, AsyncWrite, ReadBuf};
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use parking_lot::Mutex;
use std::io::{self, IoSliceMut, Read, Write};
use std::net::Shutdown;
use std::os::unix::net;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};

fn cancelled_poll<T>() -> Poll<io::Result<T>> {
    Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")))
}

fn fallback_pending<T>(cx: &Context<'_>) -> Poll<io::Result<T>> {
    crate::net::tcp::stream::fallback_rewake(cx);
    Poll::Pending
}

/// Borrowed read half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::split`](super::UnixStream::split).
///
/// This half does not participate in reactor registration - it busy-loops on
/// `WouldBlock` by waking immediately. For proper async I/O with reactor
/// integration, use the owned split via [`UnixStream::into_split`].
#[derive(Debug)]
pub struct ReadHalf<'a> {
    inner: &'a net::UnixStream,
}

impl<'a> ReadHalf<'a> {
    pub(crate) fn new(inner: &'a net::UnixStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for ReadHalf<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        let mut inner = self.inner;
        match inner.read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => fallback_pending(cx),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncReadVectored for ReadHalf<'_> {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        let mut inner = self.inner;
        match inner.read_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => fallback_pending(cx),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// Borrowed write half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::split`](super::UnixStream::split).
///
/// This half does not participate in reactor registration - it busy-loops on
/// `WouldBlock` by waking immediately. For proper async I/O with reactor
/// integration, use the owned split via [`UnixStream::into_split`].
#[derive(Debug)]
pub struct WriteHalf<'a> {
    inner: &'a net::UnixStream,
}

impl<'a> WriteHalf<'a> {
    pub(crate) fn new(inner: &'a net::UnixStream) -> Self {
        Self { inner }
    }
}

impl AsyncWrite for WriteHalf<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        let mut inner = self.inner;
        match inner.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => fallback_pending(cx),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        let mut inner = self.inner;
        match inner.write_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => fallback_pending(cx),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        let mut inner = self.inner;
        match inner.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => fallback_pending(cx),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return cancelled_poll();
        }
        match self.inner.shutdown(Shutdown::Write) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Combined waker for split halves
// ---------------------------------------------------------------------------

/// Allocation-free generation snapshot for the two direction waiters.
#[derive(Clone, Copy, Debug, Default)]
struct WaiterTokens {
    read: Option<u64>,
    write: Option<u64>,
}

/// A direction waiter that is valid for exactly one registration epoch.
struct DirectionWaiter {
    token: u64,
    waker: Waker,
}

type DirectionWakers = (Option<Waker>, Option<Waker>);

/// Waker that atomically consumes matching per-direction waiters.
///
/// The snapshot retains only numeric tokens and a weak state reference. It
/// never retains task wakers, so replacing a waiter immediately releases the
/// stale task even if the I/O driver still holds an older snapshot.
struct CombinedWaker {
    state: Weak<Mutex<SplitIoState>>,
    tokens: WaiterTokens,
}

impl CombinedWaker {
    fn dispatch(&self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let wakers = {
            let mut guard = state.lock();
            take_matching_waiters(&mut guard, self.tokens)
        };
        wake_waiters(wakers);
    }
}

use std::task::Wake;
impl Wake for CombinedWaker {
    fn wake(self: Arc<Self>) {
        self.dispatch();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.dispatch();
    }
}

fn combined_waker(state: &Arc<Mutex<SplitIoState>>, guard: &SplitIoState) -> Waker {
    Waker::from(Arc::new(CombinedWaker {
        state: Arc::downgrade(state),
        tokens: waiter_tokens(guard),
    }))
}

fn waiter_tokens(state: &SplitIoState) -> WaiterTokens {
    WaiterTokens {
        read: state.read_waiter.as_ref().map(|waiter| waiter.token),
        write: state.write_waiter.as_ref().map(|waiter| waiter.token),
    }
}

fn next_waiter_token(state: &mut SplitIoState) -> io::Result<u64> {
    let token = state.next_waiter_token;
    if token == u64::MAX {
        return Err(io::Error::other(
            "owned Unix split waiter token space exhausted",
        ));
    }
    state.next_waiter_token = token + 1;
    Ok(token)
}

fn prepare_waiters(interest: Interest, waker: &Waker) -> DirectionWakers {
    (
        interest.is_readable().then(|| waker.clone()),
        interest.is_writable().then(|| waker.clone()),
    )
}

fn install_waiters(
    state: &mut SplitIoState,
    interest: Interest,
    prepared: &mut DirectionWakers,
) -> io::Result<(WaiterTokens, DirectionWakers)> {
    let read_token = if interest.is_readable() {
        Some(next_waiter_token(state)?)
    } else {
        None
    };
    let write_token = if interest.is_writable() {
        Some(next_waiter_token(state)?)
    } else {
        None
    };

    let replaced_read = read_token.and_then(|token| {
        state
            .read_waiter
            .replace(DirectionWaiter {
                token,
                waker: prepared.0.take().expect("prepared readable waiter"),
            })
            .map(|waiter| waiter.waker)
    });
    let replaced_write = write_token.and_then(|token| {
        state
            .write_waiter
            .replace(DirectionWaiter {
                token,
                waker: prepared.1.take().expect("prepared writable waiter"),
            })
            .map(|waiter| waiter.waker)
    });

    Ok((
        WaiterTokens {
            read: read_token,
            write: write_token,
        },
        (replaced_read, replaced_write),
    ))
}

fn take_matching_waiter(slot: &mut Option<DirectionWaiter>, token: Option<u64>) -> Option<Waker> {
    let token = token?;
    if slot.as_ref().is_some_and(|waiter| waiter.token == token) {
        slot.take().map(|waiter| waiter.waker)
    } else {
        None
    }
}

fn take_matching_waiters(state: &mut SplitIoState, tokens: WaiterTokens) -> DirectionWakers {
    (
        take_matching_waiter(&mut state.read_waiter, tokens.read),
        take_matching_waiter(&mut state.write_waiter, tokens.write),
    )
}

fn take_all_waiters(state: &mut SplitIoState) -> DirectionWakers {
    (
        state.read_waiter.take().map(|waiter| waiter.waker),
        state.write_waiter.take().map(|waiter| waiter.waker),
    )
}

fn wake_waiters((read, write): DirectionWakers) {
    if let Some(waker) = read {
        waker.wake();
    }
    if let Some(waker) = write {
        waker.wake();
    }
}

fn wake_other_waiters((read, write): DirectionWakers, current: &Waker) {
    for waker in read.into_iter().chain(write) {
        if !waker.will_wake(current) {
            waker.wake();
        }
    }
}

#[inline]
fn registration_interest(read_waiter: bool, write_waiter: bool, fallback: Interest) -> Interest {
    let mut interest = Interest::empty();
    if read_waiter {
        interest |= Interest::READABLE;
    }
    if write_waiter {
        interest |= Interest::WRITABLE;
    }
    if interest.is_empty() {
        fallback
    } else {
        interest
    }
}

// ---------------------------------------------------------------------------
// Owned split halves
// ---------------------------------------------------------------------------

/// Per-direction waker state for owned split halves.
struct SplitIoState {
    registration: Option<IoRegistration>,
    /// The previous registration is being physically dropped outside this
    /// mutex. Waiters may install generations, but must leave reactor ADD to
    /// the transition owner while this is set.
    registration_transition: bool,
    read_waiter: Option<DirectionWaiter>,
    write_waiter: Option<DirectionWaiter>,
    next_waiter_token: u64,
}

fn split_io_state(registration: Option<IoRegistration>) -> SplitIoState {
    SplitIoState {
        registration,
        registration_transition: false,
        read_waiter: None,
        write_waiter: None,
        // Zero remains available for debugging/sentinel use. Tokens 1 through
        // MAX - 1 are issued; MAX is permanently reserved as exhaustion.
        next_waiter_token: 1,
    }
}

fn adopt_inherited_registration(
    state: &Arc<Mutex<SplitIoState>>,
    registration: Option<IoRegistration>,
) {
    let Some(mut registration) = registration else {
        return;
    };

    // Replace the unsplit task waker without holding the split-state mutex.
    // Keeping the same interest preserves the live reactor registration; the
    // first owned-half WouldBlock poll will install a direction generation and
    // narrow/re-arm it normally. If the inherited slab slot is already gone or
    // the reactor rejects the re-arm, dropping the invalid handle here is the
    // fail-closed path.
    let interest = registration.interest();
    let waker = {
        let guard = state.lock();
        combined_waker(state, &guard)
    };
    if matches!(registration.rearm(interest, &waker), Ok(true)) {
        state.lock().registration = Some(registration);
    }
}

/// Shared state for owned split halves.
///
/// Both owned halves share the same reactor registration. Each half stores
/// its own waker in [`SplitIoState`]; the `IoRegistration` receives a
/// combined waker that dispatches to both, preventing lost wakeups when
/// halves are polled from different tasks.
pub(crate) struct UnixStreamInner {
    state: Arc<Mutex<SplitIoState>>,
    stream: Arc<net::UnixStream>,
}

impl std::fmt::Debug for UnixStreamInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixStreamInner")
            .field("stream", &self.stream)
            .field("state", &"...")
            .finish()
    }
}

impl UnixStreamInner {
    /// Completes a registration-removal transition by consuming every waiter
    /// that arrived while the old registration was being physically dropped.
    /// The returned wakers must be invoked after this method releases the lock.
    fn drain_registration_transition(&self) -> DirectionWakers {
        let mut guard = self.state.lock();
        debug_assert!(guard.registration_transition);
        debug_assert!(guard.registration.is_none());
        let waiters = take_all_waiters(&mut guard);
        guard.registration_transition = false;
        drop(guard);
        waiters
    }

    #[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
    fn register_interest(&self, cx: &Context<'_>, interest: Interest) -> io::Result<WaiterTokens> {
        // RawWaker::clone is arbitrary user code. Clone before taking the
        // split-state lock so a custom waker cannot re-enter this state.
        let mut prepared_waiters = prepare_waiters(interest, cx.waker());
        let mut guard = self.state.lock();
        let (installed, replaced_waiters) =
            install_waiters(&mut guard, interest, &mut prepared_waiters)?;

        // A transition owner has removed the old registration from state and
        // is dropping it without the state lock. Publish this generation, but
        // never race the owner with another reactor ADD. The owner will either
        // register the current waiter union or consume and wake it.
        if guard.registration_transition {
            drop(guard);
            drop(replaced_waiters);
            return Ok(installed);
        }

        let rearm_result = if guard.registration.is_some() {
            let desired_interest = registration_interest(
                guard.read_waiter.is_some(),
                guard.write_waiter.is_some(),
                interest,
            );
            let waker = combined_waker(&self.state, &guard);
            guard
                .registration
                .as_mut()
                .map(|registration| registration.rearm(desired_interest, &waker))
        } else {
            None
        };
        if let Some(rearm_result) = rearm_result {
            match rearm_result {
                Ok(true) => {
                    drop(guard);
                    drop(replaced_waiters);
                    return Ok(installed);
                }
                Ok(false) => {
                    let old_registration = guard.registration.take();
                    debug_assert!(old_registration.is_some());
                    guard.registration_transition = true;
                    drop(guard);
                    drop(old_registration);
                    guard = self.state.lock();
                    debug_assert!(guard.registration_transition);
                    debug_assert!(guard.registration.is_none());
                }
                Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                    let old_registration = guard.registration.take();
                    debug_assert!(old_registration.is_some());
                    guard.registration_transition = true;
                    drop(guard);
                    drop(old_registration);
                    let waiters_to_wake = self.drain_registration_transition();
                    drop(replaced_waiters);
                    wake_waiters(waiters_to_wake);
                    return Ok(installed);
                }
                Err(err) => {
                    let old_registration = guard.registration.take();
                    debug_assert!(old_registration.is_some());
                    guard.registration_transition = true;
                    drop(guard);
                    drop(old_registration);
                    let (failed_waiters, surviving_waiters) = {
                        let mut guard = self.state.lock();
                        debug_assert!(guard.registration_transition);
                        debug_assert!(guard.registration.is_none());
                        let failed_waiters = take_matching_waiters(&mut guard, installed);
                        let surviving_waiters = take_all_waiters(&mut guard);
                        guard.registration_transition = false;
                        (failed_waiters, surviving_waiters)
                    };
                    drop(replaced_waiters);
                    drop(failed_waiters);
                    wake_waiters(surviving_waiters);
                    return Err(err);
                }
            }
        }

        // There was no registration, or `rearm` found a missing driver-waker
        // slot and the old registration has now been fully deregistered. Build
        // the ADD from the latest union because other halves may have installed
        // generations while `registration_transition` was set.
        let desired_interest = registration_interest(
            guard.read_waiter.is_some(),
            guard.write_waiter.is_some(),
            Interest::empty(),
        );
        if desired_interest.is_empty() {
            guard.registration_transition = false;
            drop(guard);
            drop(replaced_waiters);
            return Ok(installed);
        }
        let waker = combined_waker(&self.state, &guard);

        let Some(current) = Cx::current() else {
            let fallback_waiters = take_all_waiters(&mut guard);
            guard.registration_transition = false;
            drop(guard);
            drop(replaced_waiters);
            wake_other_waiters(fallback_waiters, cx.waker());
            crate::net::tcp::stream::fallback_rewake(cx);
            return Ok(installed);
        };
        let Some(driver) = current.io_driver_handle() else {
            let fallback_waiters = take_all_waiters(&mut guard);
            guard.registration_transition = false;
            drop(guard);
            drop(replaced_waiters);
            wake_other_waiters(fallback_waiters, cx.waker());
            crate::net::tcp::stream::fallback_rewake(cx);
            return Ok(installed);
        };

        // Keep the state lock across fresh registration so concurrent halves
        // cannot both issue reactor ADD for the same socket.
        match driver.register(&*self.stream, desired_interest, waker) {
            Ok(registration) => {
                guard.registration = Some(registration);
                guard.registration_transition = false;
                drop(guard);
                drop(replaced_waiters);
                Ok(installed)
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::Unsupported | io::ErrorKind::NotConnected
                ) =>
            {
                let fallback_waiters = take_all_waiters(&mut guard);
                guard.registration_transition = false;
                drop(guard);
                drop(replaced_waiters);
                wake_other_waiters(fallback_waiters, cx.waker());
                crate::net::tcp::stream::fallback_rewake(cx);
                Ok(installed)
            }
            Err(err) => {
                let failed_waiters = take_matching_waiters(&mut guard, installed);
                let surviving_waiters = take_all_waiters(&mut guard);
                guard.registration_transition = false;
                drop(guard);
                drop(replaced_waiters);
                drop(failed_waiters);
                wake_waiters(surviving_waiters);
                Err(err)
            }
        }
    }

    fn retire_waiter(&self, interest: Interest, token: Option<u64>) {
        let Some(token) = token else {
            return;
        };

        let mut guard = self.state.lock();
        let installed = WaiterTokens {
            read: interest.is_readable().then_some(token),
            write: interest.is_writable().then_some(token),
        };
        let has_newer_waiter = (interest.is_readable()
            && guard
                .read_waiter
                .as_ref()
                .is_some_and(|waiter| waiter.token != token))
            || (interest.is_writable()
                && guard
                    .write_waiter
                    .as_ref()
                    .is_some_and(|waiter| waiter.token != token));
        if has_newer_waiter {
            return;
        }
        let retired_waiters = take_matching_waiters(&mut guard, installed);

        // The transition owner will observe this retirement before it either
        // installs the latest union or drains all remaining waiters.
        if guard.registration_transition {
            drop(guard);
            drop(retired_waiters);
            return;
        }

        let desired_interest = registration_interest(
            guard.read_waiter.is_some(),
            guard.write_waiter.is_some(),
            Interest::empty(),
        );
        if desired_interest.is_empty() {
            let old_registration = guard.registration.take();
            let owns_transition = old_registration.is_some();
            if owns_transition {
                guard.registration_transition = true;
            }
            drop(guard);
            drop(old_registration);
            let surviving_waiters = if owns_transition {
                self.drain_registration_transition()
            } else {
                (None, None)
            };
            drop(retired_waiters);
            wake_waiters(surviving_waiters);
            return;
        }

        let combined = combined_waker(&self.state, &guard);
        let rearm_ok = guard.registration.as_mut().is_some_and(|registration| {
            matches!(registration.rearm(desired_interest, &combined), Ok(true))
        });
        if rearm_ok {
            drop(guard);
            drop(retired_waiters);
            return;
        }

        let old_registration = guard.registration.take();
        if old_registration.is_some() {
            guard.registration_transition = true;
            drop(guard);
            drop(old_registration);
            let surviving_waiters = self.drain_registration_transition();
            drop(retired_waiters);
            wake_waiters(surviving_waiters);
            return;
        }

        let surviving_waiters = take_all_waiters(&mut guard);
        drop(guard);
        drop(retired_waiters);
        wake_waiters(surviving_waiters);
    }
}

/// Owned read half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::into_split`](super::UnixStream::into_split).
/// Can be reunited with [`OwnedWriteHalf`] using [`reunite`](Self::reunite).
#[derive(Debug)]
pub struct OwnedReadHalf {
    inner: Arc<UnixStreamInner>,
    last_waiter: Option<u64>,
}

impl OwnedReadHalf {
    pub(crate) fn new_pair(
        stream: Arc<net::UnixStream>,
        registration: Option<IoRegistration>,
    ) -> (Self, OwnedWriteHalf) {
        let state = Arc::new(Mutex::new(split_io_state(None)));
        adopt_inherited_registration(&state, registration);
        let inner = Arc::new(UnixStreamInner { state, stream });
        (
            Self {
                inner: inner.clone(),
                last_waiter: None,
            },
            OwnedWriteHalf {
                inner,
                shutdown_on_drop: true,
                last_waiter: None,
            },
        )
    }

    fn pending_on_interest<T>(&mut self, cx: &Context<'_>) -> Poll<io::Result<T>> {
        match self.inner.register_interest(cx, Interest::READABLE) {
            Ok(tokens) => {
                self.last_waiter = tokens.read;
                Poll::Pending
            }
            Err(err) => self.finish_poll(Err(err)),
        }
    }

    fn finish_poll<T>(&mut self, result: io::Result<T>) -> Poll<io::Result<T>> {
        self.inner
            .retire_waiter(Interest::READABLE, self.last_waiter.take());
        Poll::Ready(result)
    }

    /// Attempts to reunite with a write half to reform a [`UnixStream`](super::UnixStream).
    ///
    /// # Errors
    ///
    /// Returns an error containing both halves if they originated from
    /// different streams.
    pub fn reunite(mut self, mut other: OwnedWriteHalf) -> Result<super::UnixStream, ReuniteError> {
        if Arc::ptr_eq(&self.inner, &other.inner) {
            self.last_waiter = None;
            other.last_waiter = None;
            other.shutdown_on_drop = false;

            let (registration, waiters) = {
                let mut state = self.inner.state.lock();
                let waiters = take_all_waiters(&mut state);
                (state.registration.take(), waiters)
            };
            drop(waiters);
            Ok(super::UnixStream::from_parts(
                self.inner.stream.clone(),
                registration,
            ))
        } else {
            Err(ReuniteError(self, other))
        }
    }
}

impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return this.finish_poll(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let result = (&*this.inner.stream).read(buf.unfilled());
        match result {
            Ok(n) => {
                buf.advance(n);
                this.finish_poll(Ok(()))
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => this.pending_on_interest(cx),
            Err(err) => this.finish_poll(Err(err)),
        }
    }
}

impl AsyncReadVectored for OwnedReadHalf {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return this.finish_poll(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let result = (&*this.inner.stream).read_vectored(bufs);
        match result {
            Ok(n) => this.finish_poll(Ok(n)),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => this.pending_on_interest(cx),
            Err(err) => this.finish_poll(Err(err)),
        }
    }
}

/// Owned write half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::into_split`](super::UnixStream::into_split).
/// Can be reunited with [`OwnedReadHalf`] using
/// [`OwnedReadHalf::reunite`](OwnedReadHalf::reunite).
///
/// By default, the stream's write direction is shut down when this half
/// is dropped. Use [`set_shutdown_on_drop(false)`][Self::set_shutdown_on_drop]
/// to disable this behavior.
#[derive(Debug)]
pub struct OwnedWriteHalf {
    inner: Arc<UnixStreamInner>,
    shutdown_on_drop: bool,
    last_waiter: Option<u64>,
}

impl OwnedWriteHalf {
    /// Shuts down the write side of the stream.
    ///
    /// This is equivalent to calling `shutdown(Shutdown::Write)` on the
    /// original stream.
    pub fn shutdown(&self) -> io::Result<()> {
        let result = self.inner.stream.shutdown(Shutdown::Write);
        self.inner
            .retire_waiter(Interest::WRITABLE, self.last_waiter);
        result
    }

    /// Controls whether the write direction is shut down when dropped.
    ///
    /// Default is `true`.
    pub fn set_shutdown_on_drop(&mut self, shutdown: bool) {
        self.shutdown_on_drop = shutdown;
    }

    fn pending_on_interest<T>(&mut self, cx: &Context<'_>) -> Poll<io::Result<T>> {
        match self.inner.register_interest(cx, Interest::WRITABLE) {
            Ok(tokens) => {
                self.last_waiter = tokens.write;
                Poll::Pending
            }
            Err(err) => self.finish_poll(Err(err)),
        }
    }

    fn finish_poll<T>(&mut self, result: io::Result<T>) -> Poll<io::Result<T>> {
        self.inner
            .retire_waiter(Interest::WRITABLE, self.last_waiter.take());
        Poll::Ready(result)
    }
}

impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return this.finish_poll(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let result = (&*this.inner.stream).write(buf);
        match result {
            Ok(n) => this.finish_poll(Ok(n)),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => this.pending_on_interest(cx),
            Err(err) => this.finish_poll(Err(err)),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return this.finish_poll(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let result = (&*this.inner.stream).write_vectored(bufs);
        match result {
            Ok(n) => this.finish_poll(Ok(n)),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => this.pending_on_interest(cx),
            Err(err) => this.finish_poll(Err(err)),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return this.finish_poll(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let result = (&*this.inner.stream).flush();
        match result {
            Ok(()) => this.finish_poll(Ok(())),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => this.pending_on_interest(cx),
            Err(err) => this.finish_poll(Err(err)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return this.finish_poll(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        match this.inner.stream.shutdown(Shutdown::Write) {
            Ok(()) => this.finish_poll(Ok(())),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => this.finish_poll(Ok(())),
            Err(err) => this.finish_poll(Err(err)),
        }
    }
}

impl Drop for OwnedWriteHalf {
    fn drop(&mut self) {
        self.inner
            .retire_waiter(Interest::WRITABLE, self.last_waiter.take());
        if self.shutdown_on_drop {
            let _ = self.inner.stream.shutdown(Shutdown::Write);
        }
    }
}

impl Drop for OwnedReadHalf {
    fn drop(&mut self) {
        self.inner
            .retire_waiter(Interest::READABLE, self.last_waiter.take());
    }
}

/// Error returned when trying to reunite halves from different streams.
#[derive(Debug)]
pub struct ReuniteError(pub OwnedReadHalf, pub OwnedWriteHalf);

impl std::fmt::Display for ReuniteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tried to reunite halves that are not from the same socket"
        )
    }
}

impl std::error::Error for ReuniteError {}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::Cx;
    use crate::runtime::reactor::{Events, Reactor, Source, Token};
    use crate::runtime::{Event, IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId};

    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
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

    fn counting_waker() -> (Waker, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        (waker, hits)
    }

    fn install_snapshot(
        state: &Arc<Mutex<SplitIoState>>,
        interest: Interest,
        waker: &Waker,
    ) -> (WaiterTokens, Waker) {
        let mut prepared = prepare_waiters(interest, waker);
        let mut guard = state.lock();
        let (tokens, replaced) =
            install_waiters(&mut guard, interest, &mut prepared).expect("install waiter");
        let snapshot = combined_waker(state, &guard);
        drop(guard);
        drop(replaced);
        (tokens, snapshot)
    }

    struct LockProbeWaker {
        state: Weak<Mutex<SplitIoState>>,
        observed_unlocked: Arc<AtomicBool>,
        hits: Arc<AtomicUsize>,
    }

    impl Wake for LockProbeWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let unlocked = self
                .state
                .upgrade()
                .is_some_and(|state| state.try_lock().is_some());
            self.observed_unlocked.store(unlocked, Ordering::SeqCst);
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Default)]
    struct SourceExclusiveState {
        source_to_token: HashMap<i32, Token>,
        token_to_source: HashMap<Token, i32>,
    }

    /// Minimal reactor that rejects a second live registration for one fd.
    /// This models epoll's ADD-before-DEL `EEXIST` behavior deterministically.
    #[derive(Default)]
    struct SourceExclusiveReactor {
        state: Mutex<SourceExclusiveState>,
    }

    impl Reactor for SourceExclusiveReactor {
        fn register(
            &self,
            source: &dyn Source,
            token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            let fd = source.raw_fd();
            let mut state = self.state.lock();
            if state.source_to_token.contains_key(&fd) || state.token_to_source.contains_key(&token)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "source or token already registered",
                ));
            }
            state.source_to_token.insert(fd, token);
            state.token_to_source.insert(token, fd);
            Ok(())
        }

        fn modify(&self, token: Token, _interest: Interest) -> io::Result<()> {
            if self.state.lock().token_to_source.contains_key(&token) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ))
            }
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            let mut state = self.state.lock();
            let Some(fd) = state.token_to_source.remove(&token) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            };
            state.source_to_token.remove(&fd);
            Ok(())
        }

        fn poll(&self, events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
            events.clear();
            Ok(0)
        }

        fn wake(&self) -> io::Result<()> {
            Ok(())
        }

        fn registration_count(&self) -> usize {
            self.state.lock().token_to_source.len()
        }
    }

    #[test]
    fn test_borrowed_halves() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let _read = ReadHalf::new(&s1);
        let _write = WriteHalf::new(&s1);
    }

    #[test]
    fn test_owned_halves() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let stream = super::super::UnixStream::from_std(s1).expect("wrap stream");
        let (_read, _write) = stream.into_split();
    }

    #[test]
    fn test_reunite_success() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let stream = super::super::UnixStream::from_std(s1).expect("wrap stream");
        let (read, write) = stream.into_split();

        // Should succeed - same stream
        let _reunited = read.reunite(write).expect("reunite should succeed");
    }

    #[test]
    fn test_reunite_failure() {
        let (s1, _s2a) = net::UnixStream::pair().expect("pair failed");
        let (s2, _s2b) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");
        s2.set_nonblocking(true).expect("set_nonblocking failed");

        let stream1 = super::super::UnixStream::from_std(s1).expect("wrap stream1");
        let stream2 = super::super::UnixStream::from_std(s2).expect("wrap stream2");

        let (read1, _write1) = stream1.into_split();
        let (_read2, write2) = stream2.into_split();

        // Should fail - different streams
        let err = read1.reunite(write2).expect_err("reunite should fail");
        assert!(err.to_string().contains("not from the same socket"));
    }

    #[test]
    fn registration_interest_prefers_waiter_union() {
        let both = registration_interest(true, true, Interest::READABLE);
        assert_eq!(both, Interest::READABLE | Interest::WRITABLE);

        let write_only = registration_interest(false, true, Interest::READABLE);
        assert_eq!(write_only, Interest::WRITABLE);

        let fallback = registration_interest(false, false, Interest::READABLE);
        assert_eq!(fallback, Interest::READABLE);
    }

    #[test]
    fn stale_combined_waker_does_not_consume_new_generation() {
        let state = Arc::new(Mutex::new(split_io_state(None)));
        let (old_waker, old_hits) = counting_waker();
        let (new_waker, new_hits) = counting_waker();

        let (old_tokens, old_snapshot) = install_snapshot(&state, Interest::READABLE, &old_waker);
        let (new_tokens, new_snapshot) = install_snapshot(&state, Interest::READABLE, &new_waker);
        assert_ne!(old_tokens.read, new_tokens.read);

        old_snapshot.wake_by_ref();
        assert_eq!(old_hits.load(Ordering::SeqCst), 0);
        assert_eq!(new_hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            state.lock().read_waiter.as_ref().map(|waiter| waiter.token),
            new_tokens.read
        );

        new_snapshot.wake_by_ref();
        new_snapshot.wake_by_ref();
        assert_eq!(new_hits.load(Ordering::SeqCst), 1);
        assert!(state.lock().read_waiter.is_none());
    }

    #[test]
    fn inherited_registration_is_adopted_in_place_across_reunite() {
        let (stream, mut peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let stream = Arc::new(stream);
        let reactor = Arc::new(SourceExclusiveReactor::default());
        let driver = IoDriverHandle::new(reactor.clone());
        let registration = driver
            .register(&*stream, Interest::READABLE, noop_waker())
            .expect("register unsplit stream");
        let original_token = registration.token();

        let (read_half, write_half) =
            OwnedReadHalf::new_pair(Arc::clone(&stream), Some(registration));
        assert_eq!(reactor.registration_count(), 1);
        assert_eq!(
            read_half
                .inner
                .state
                .lock()
                .registration
                .as_ref()
                .expect("adopted registration")
                .token(),
            original_token
        );

        let reunited = read_half.reunite(write_half).expect("reunite");
        let (mut read_half, write_half) = reunited.into_split();
        assert_eq!(reactor.registration_count(), 1);
        assert_eq!(
            read_half
                .inner
                .state
                .lock()
                .registration
                .as_ref()
                .expect("re-adopted registration")
                .token(),
            original_token
        );

        peer.write_all(b"x").expect("write byte");
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut bytes = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut bytes);
        let ready = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(matches!(ready, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"x");

        drop(read_half);
        drop(write_half);
        assert_eq!(reactor.registration_count(), 0);
    }

    #[test]
    fn combined_waker_consumes_each_direction_once() {
        let state = Arc::new(Mutex::new(split_io_state(None)));
        let (read_waker, read_hits) = counting_waker();
        let (write_waker, write_hits) = counting_waker();

        let _ = install_snapshot(&state, Interest::READABLE, &read_waker);
        let (_, snapshot) = install_snapshot(&state, Interest::WRITABLE, &write_waker);
        snapshot.wake_by_ref();
        snapshot.wake_by_ref();

        assert_eq!(read_hits.load(Ordering::SeqCst), 1);
        assert_eq!(write_hits.load(Ordering::SeqCst), 1);
        let state = state.lock();
        assert!(state.read_waiter.is_none());
        assert!(state.write_waiter.is_none());
    }

    #[test]
    fn reactor_readiness_consumes_union_then_rearms_only_current_waiter() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (mut read_half, mut write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor.clone());
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver.clone()),
            None,
        );
        let _current = Cx::set_current(Some(cx));
        let (read_waker, read_hits) = counting_waker();
        let (write_waker, write_hits) = counting_waker();

        let read_tokens = read_half
            .inner
            .register_interest(&Context::from_waker(&read_waker), Interest::READABLE)
            .expect("register read");
        read_half.last_waiter = read_tokens.read;
        let write_tokens = write_half
            .inner
            .register_interest(&Context::from_waker(&write_waker), Interest::WRITABLE)
            .expect("register write");
        write_half.last_waiter = write_tokens.write;
        let token = {
            let state = read_half.inner.state.lock();
            let registration = state.registration.as_ref().expect("registration");
            assert_eq!(
                registration.interest(),
                Interest::READABLE | Interest::WRITABLE
            );
            registration.token()
        };

        reactor.set_ready(token, Event::readable(token));
        assert_eq!(
            driver
                .turn_with(Some(Duration::ZERO), |_, _| {})
                .expect("driver turn"),
            1
        );
        assert_eq!(read_hits.load(Ordering::SeqCst), 1);
        assert_eq!(write_hits.load(Ordering::SeqCst), 1);
        {
            let state = read_half.inner.state.lock();
            assert!(state.read_waiter.is_none());
            assert!(state.write_waiter.is_none());
        }

        let (next_write_waker, _) = counting_waker();
        let next_write_tokens = write_half
            .inner
            .register_interest(&Context::from_waker(&next_write_waker), Interest::WRITABLE)
            .expect("re-register write");
        write_half.last_waiter = next_write_tokens.write;
        let state = write_half.inner.state.lock();
        assert!(state.read_waiter.is_none());
        assert!(state.write_waiter.is_some());
        assert_eq!(
            state
                .registration
                .as_ref()
                .expect("registration")
                .interest(),
            Interest::WRITABLE
        );
    }

    #[test]
    fn missing_driver_waker_deregisters_before_fresh_registration() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let reactor = Arc::new(SourceExclusiveReactor::default());
        let driver = IoDriverHandle::new(reactor.clone());
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver.clone()),
            None,
        );
        let _current = Cx::set_current(Some(cx));
        let read_waker = noop_waker();
        read_half
            .inner
            .register_interest(&Context::from_waker(&read_waker), Interest::READABLE)
            .expect("initial read registration");
        let old_token = read_half
            .inner
            .state
            .lock()
            .registration
            .as_ref()
            .expect("initial registration")
            .token();

        // Leave the reactor registration live while removing only the driver's
        // waker slot. The next rearm must return Ok(false), transition through
        // a complete DEL, and only then issue the replacement ADD.
        driver.lock().deregister_waker(old_token);

        let write_waker = noop_waker();
        write_half
            .inner
            .register_interest(&Context::from_waker(&write_waker), Interest::WRITABLE)
            .expect("fresh registration after missing driver waker");

        let state = read_half.inner.state.lock();
        assert!(!state.registration_transition);
        assert!(state.read_waiter.is_some());
        assert!(state.write_waiter.is_some());
        assert_eq!(
            state
                .registration
                .as_ref()
                .expect("replacement registration")
                .interest(),
            Interest::READABLE | Interest::WRITABLE
        );
        assert_eq!(reactor.registration_count(), 1);
    }

    #[test]
    fn waiter_token_exhaustion_is_permanent_and_nonwrapping() {
        let mut state = split_io_state(None);
        state.next_waiter_token = u64::MAX - 1;
        let waker = noop_waker();

        let mut prepared = prepare_waiters(Interest::READABLE, &waker);
        let (tokens, replaced) = install_waiters(&mut state, Interest::READABLE, &mut prepared)
            .expect("last waiter token should be issued");
        drop(replaced);
        assert_eq!(tokens.read, Some(u64::MAX - 1));
        assert_eq!(state.next_waiter_token, u64::MAX);

        for interest in [Interest::WRITABLE, Interest::READABLE] {
            let mut prepared = prepare_waiters(interest, &waker);
            let err = install_waiters(&mut state, interest, &mut prepared)
                .expect_err("exhausted token space must remain fail-closed");
            assert_eq!(err.kind(), io::ErrorKind::Other);
            assert_eq!(state.next_waiter_token, u64::MAX);
            assert_eq!(
                state.read_waiter.as_ref().map(|waiter| waiter.token),
                tokens.read
            );
            assert!(state.write_waiter.is_none());
        }
    }

    #[test]
    fn exact_retirement_does_not_remove_newer_waiter() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let (old_waker, _old_hits) = counting_waker();
        let (new_waker, _new_hits) = counting_waker();

        let (old_tokens, _) =
            install_snapshot(&read_half.inner.state, Interest::READABLE, &old_waker);
        let (new_tokens, _) =
            install_snapshot(&read_half.inner.state, Interest::READABLE, &new_waker);
        read_half
            .inner
            .retire_waiter(Interest::READABLE, old_tokens.read);
        assert_eq!(
            read_half
                .inner
                .state
                .lock()
                .read_waiter
                .as_ref()
                .map(|waiter| waiter.token),
            new_tokens.read
        );
    }

    #[test]
    fn fallback_wake_runs_after_state_unlock() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let observed_unlocked = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(LockProbeWaker {
            state: Arc::downgrade(&read_half.inner.state),
            observed_unlocked: Arc::clone(&observed_unlocked),
            hits: Arc::clone(&hits),
        }));
        let task_cx = Context::from_waker(&waker);
        let _current = Cx::set_current(None);

        let tokens = read_half
            .inner
            .register_interest(&task_cx, Interest::READABLE)
            .expect("fallback registration");
        assert!(tokens.read.is_some());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(observed_unlocked.load(Ordering::SeqCst));
        assert!(read_half.inner.state.lock().read_waiter.is_none());
    }

    #[test]
    fn owned_read_ready_retires_waiter() {
        let (stream, mut peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (mut read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let waker = noop_waker();
        let tokens = {
            let mut prepared = prepare_waiters(Interest::READABLE, &waker);
            let mut state = read_half.inner.state.lock();
            let (tokens, replaced) = install_waiters(&mut state, Interest::READABLE, &mut prepared)
                .expect("install read");
            drop(state);
            drop(replaced);
            tokens
        };
        read_half.last_waiter = tokens.read;
        peer.write_all(b"x").expect("write byte");

        let mut task_cx = Context::from_waker(&waker);
        let mut bytes = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut bytes);
        let ready = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(matches!(ready, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"x");
        assert!(read_half.last_waiter.is_none());
        assert!(read_half.inner.state.lock().read_waiter.is_none());
    }

    #[test]
    fn owned_read_cancellation_retires_waiter() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (mut read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let waker = noop_waker();
        let tokens = {
            let mut prepared = prepare_waiters(Interest::READABLE, &waker);
            let mut state = read_half.inner.state.lock();
            let (tokens, replaced) = install_waiters(&mut state, Interest::READABLE, &mut prepared)
                .expect("install read");
            drop(state);
            drop(replaced);
            tokens
        };
        read_half.last_waiter = tokens.read;

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _current = Cx::set_current(Some(cx));
        let mut task_cx = Context::from_waker(&waker);
        let mut bytes = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut bytes);
        let cancelled = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(matches!(
            cancelled,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));
        assert!(read_half.last_waiter.is_none());
        assert!(read_half.inner.state.lock().read_waiter.is_none());
    }

    #[test]
    fn synchronous_shutdown_retires_write_waiter() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (_read_half, mut write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let waker = noop_waker();
        let tokens = {
            let mut prepared = prepare_waiters(Interest::WRITABLE, &waker);
            let mut state = write_half.inner.state.lock();
            let (tokens, replaced) = install_waiters(&mut state, Interest::WRITABLE, &mut prepared)
                .expect("install write");
            drop(state);
            drop(replaced);
            tokens
        };
        write_half.last_waiter = tokens.write;

        write_half.shutdown().expect("shutdown write");
        assert!(write_half.inner.state.lock().write_waiter.is_none());
    }

    #[test]
    fn borrowed_split_halves_return_interrupted_when_cancel_requested() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let mut read_half = ReadHalf::new(&s1);
        let mut write_half = WriteHalf::new(&s1);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        let mut read_buf = crate::io::ReadBuf::new(&mut buf);

        let read =
            crate::io::AsyncRead::poll_read(Pin::new(&mut read_half), &mut task_cx, &mut read_buf);
        assert!(matches!(
            read,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let write =
            crate::io::AsyncWrite::poll_write(Pin::new(&mut write_half), &mut task_cx, b"hello");
        assert!(matches!(
            write,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let flush = crate::io::AsyncWrite::poll_flush(Pin::new(&mut write_half), &mut task_cx);
        assert!(matches!(
            flush,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let shutdown =
            crate::io::AsyncWrite::poll_shutdown(Pin::new(&mut write_half), &mut task_cx);
        assert!(matches!(
            shutdown,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));
    }

    #[test]
    fn owned_split_halves_return_interrupted_when_cancel_requested() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let stream = super::super::UnixStream::from_std(s1).expect("wrap stream");
        let (mut read_half, mut write_half) = stream.into_split();
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        let mut read_buf = crate::io::ReadBuf::new(&mut buf);

        let read =
            crate::io::AsyncRead::poll_read(Pin::new(&mut read_half), &mut task_cx, &mut read_buf);
        assert!(matches!(
            read,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let write =
            crate::io::AsyncWrite::poll_write(Pin::new(&mut write_half), &mut task_cx, b"hello");
        assert!(matches!(
            write,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let flush = crate::io::AsyncWrite::poll_flush(Pin::new(&mut write_half), &mut task_cx);
        assert!(matches!(
            flush,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let shutdown =
            crate::io::AsyncWrite::poll_shutdown(Pin::new(&mut write_half), &mut task_cx);
        assert!(matches!(
            shutdown,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));
    }
}
