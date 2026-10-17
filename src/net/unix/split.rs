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
/// integration, use the owned split via
/// [`UnixStream::into_split`](crate::net::unix::UnixStream::into_split).
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
/// integration, use the owned split via
/// [`UnixStream::into_split`](crate::net::unix::UnixStream::into_split).
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
    /// Whether `registration` sits on the process-global fallback I/O driver
    /// (GH#67): such a registration is retired through the ordinary
    /// transition path and re-made on the ambient driver as soon as one is
    /// present (asupersync-9e6a28).
    registration_on_fallback: bool,
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
        registration_on_fallback: false,
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
    on_fallback: bool,
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
        let mut guard = state.lock();
        guard.registration = Some(registration);
        guard.registration_on_fallback = on_fallback;
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

impl Drop for UnixStreamInner {
    fn drop(&mut self) {
        // Deregister before the `stream` field closes the fd. The reactor may
        // still hold the shared state while it dispatches a wake; dropping the
        // registration with the last state Arc then ran after the close, and
        // a socket that reused the fd number hit AlreadyExists on its first
        // registration (br-asupersync-8vrx8q).
        let registration = self.state.lock().registration.take();
        drop(registration);
    }
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

        // A registration parked on the fallback driver retires through the
        // ordinary transition path once an ambient driver is present, so the
        // fresh registration below lands on that driver (GH#67,
        // asupersync-9e6a28).
        let rearm_result = if guard.registration.is_some()
            && guard.registration_on_fallback
            && crate::net::udp::ambient_io_driver_present()
        {
            Some(Ok(false))
        } else if guard.registration.is_some() {
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

        // Keep the state lock across fresh registration so concurrent halves
        // cannot both issue reactor ADD for the same socket. Ambient driver
        // first, else the process-global fallback driver (GH#67,
        // asupersync-9e6a28); only when no reactor takes the fd do the waiters
        // fall back to the legacy self-wake.
        match crate::net::udp::fresh_reactor_registration(&*self.stream, desired_interest, waker) {
            Ok(crate::net::udp::FreshRegistration::Registered {
                registration,
                on_fallback,
            }) => {
                guard.registration = Some(registration);
                guard.registration_on_fallback = on_fallback;
                guard.registration_transition = false;
                drop(guard);
                drop(replaced_waiters);
                Ok(installed)
            }
            Ok(crate::net::udp::FreshRegistration::SelfWake) => {
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
    /// Test constructor: an inherited registration is assumed to sit on an
    /// ambient driver (`into_split` passes the real flag).
    #[cfg(test)]
    pub(crate) fn new_pair(
        stream: Arc<net::UnixStream>,
        registration: Option<IoRegistration>,
    ) -> (Self, OwnedWriteHalf) {
        Self::new_pair_with_fallback_flag(stream, registration, false)
    }

    /// Like [`Self::new_pair`], recording whether the inherited registration
    /// sits on the process-global fallback I/O driver so the halves migrate
    /// it to an ambient driver later (GH#67, asupersync-9e6a28).
    pub(crate) fn new_pair_with_fallback_flag(
        stream: Arc<net::UnixStream>,
        registration: Option<IoRegistration>,
        registration_on_fallback: bool,
    ) -> (Self, OwnedWriteHalf) {
        let state = Arc::new(Mutex::new(split_io_state(None)));
        adopt_inherited_registration(&state, registration, registration_on_fallback);
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

            // The fallback flag travels with the registration, so one the halves
            // made on the fallback driver still migrates (br-asupersync-8vrx8q).
            let (registration, on_fallback, waiters) = {
                let mut state = self.inner.state.lock();
                let waiters = take_all_waiters(&mut state);
                let on_fallback = std::mem::replace(&mut state.registration_on_fallback, false);
                (state.registration.take(), on_fallback, waiters)
            };
            drop(waiters);
            Ok(super::UnixStream::from_parts(
                self.inner.stream.clone(),
                (registration, on_fallback),
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
#[path = "split_inline_tests.rs"]
mod tests;
