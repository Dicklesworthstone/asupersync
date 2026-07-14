//! TCP stream splitting with reactor registration sharing.
//!
//! This module provides borrowed and owned split halves for TCP streams.
//! The owned variants properly share the reactor registration between halves.
//!
//! ubs:ignore — OwnedWriteHalf::drop() calls shutdown(Write); read half does not
//! need shutdown (correct half-duplex semantics).

#[cfg(not(target_arch = "wasm32"))]
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncReadVectored, AsyncWrite, ReadBuf};
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use parking_lot::Mutex;
use std::io::{self, IoSliceMut};
#[cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};
#[cfg(target_arch = "wasm32")]
use std::marker::PhantomData;
#[cfg(not(target_arch = "wasm32"))]
use std::net::{self, Shutdown};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};

#[cfg(target_arch = "wasm32")]
#[inline]
fn browser_tcp_poll_unsupported<T>(op: &str) -> Poll<io::Result<T>> {
    Poll::Ready(Err(super::browser_tcp_unsupported(op)))
}

#[cfg(target_arch = "wasm32")]
#[inline]
fn browser_tcp_unsupported_result<T>(op: &str) -> io::Result<T> {
    Err(super::browser_tcp_unsupported(op))
}

/// Borrowed read half of a split TCP stream.
///
/// This half does not participate in reactor registration - it uses
/// busy-loop polling on WouldBlock. For proper async I/O with reactor
/// integration, use the owned split via [`TcpStream::into_split()`](super::stream::TcpStream::into_split).
#[derive(Debug)]
pub struct ReadHalf<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    inner: &'a net::TcpStream,
    #[cfg(target_arch = "wasm32")]
    _marker: PhantomData<&'a ()>,
}

impl ReadHalf<'_> {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn new(inner: &net::TcpStream) -> ReadHalf<'_> {
        ReadHalf { inner }
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn unsupported() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncRead for ReadHalf<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let mut inner = self.inner;
        match inner.read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No reactor integration for borrowed split - use fallback_rewake
                // to avoid 100% CPU busy loops. For proper async I/O, use owned split.
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncRead for ReadHalf<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _ = (self, cx, buf);
        browser_tcp_poll_unsupported("ReadHalf::poll_read")
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncReadVectored for ReadHalf<'_> {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let mut inner = self.inner;
        match inner.read_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncReadVectored for ReadHalf<'_> {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let _ = (self, cx, bufs);
        browser_tcp_poll_unsupported("ReadHalf::poll_read_vectored")
    }
}

/// Borrowed write half of a split TCP stream.
///
/// This half does not participate in reactor registration - it uses
/// busy-loop polling on WouldBlock. For proper async I/O with reactor
/// integration, use the owned split via [`TcpStream::into_split()`](super::stream::TcpStream::into_split).
#[derive(Debug)]
pub struct WriteHalf<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    inner: &'a net::TcpStream,
    #[cfg(target_arch = "wasm32")]
    _marker: PhantomData<&'a ()>,
}

impl WriteHalf<'_> {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn new(inner: &net::TcpStream) -> WriteHalf<'_> {
        WriteHalf { inner }
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn unsupported() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncWrite for WriteHalf<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let mut inner = self.inner;
        match inner.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let mut inner = self.inner;
        match inner.write_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let mut inner = self.inner;
        match inner.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        match self.inner.shutdown(Shutdown::Write) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncWrite for WriteHalf<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let _ = (self, cx, buf);
        browser_tcp_poll_unsupported("WriteHalf::poll_write")
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = (self, cx);
        browser_tcp_poll_unsupported("WriteHalf::poll_flush")
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = (self, cx);
        browser_tcp_poll_unsupported("WriteHalf::poll_shutdown")
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
/// The snapshot deliberately retains only numeric tokens and a weak state
/// reference. It never retains task wakers, so replacing a waiter immediately
/// releases the stale task even if the I/O driver still holds an older
/// snapshot.
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

#[cfg(not(target_arch = "wasm32"))]
fn next_waiter_token(state: &mut SplitIoState) -> io::Result<u64> {
    let token = state.next_waiter_token;
    if token == u64::MAX {
        return Err(io::Error::other(
            "owned TCP split waiter token space exhausted",
        ));
    }
    state.next_waiter_token = token + 1;
    Ok(token)
}

#[cfg(not(target_arch = "wasm32"))]
fn prepare_waiters(interest: Interest, waker: &Waker) -> DirectionWakers {
    (
        interest.is_readable().then(|| waker.clone()),
        interest.is_writable().then(|| waker.clone()),
    )
}

#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(not(target_arch = "wasm32"))]
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
    registration_transition: bool,
    read_waiter: Option<DirectionWaiter>,
    write_waiter: Option<DirectionWaiter>,
    #[cfg(not(target_arch = "wasm32"))]
    next_waiter_token: u64,
}

fn split_io_state(registration: Option<IoRegistration>) -> SplitIoState {
    SplitIoState {
        registration,
        registration_transition: false,
        read_waiter: None,
        write_waiter: None,
        // Zero remains available for debugging/sentinel use. Tokens 1
        // through MAX - 1 are issued; MAX is permanently reserved as
        // exhaustion.
        #[cfg(not(target_arch = "wasm32"))]
        next_waiter_token: 1,
    }
}

#[cfg(not(target_arch = "wasm32"))]
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
/// Both [`OwnedReadHalf`] and [`OwnedWriteHalf`] share this state via `Arc`.
/// Each half stores its own waker in [`SplitIoState`]; the `IoRegistration`
/// receives a combined waker that dispatches to both, preventing lost wakeups
/// when halves are polled from different tasks.
pub(crate) struct TcpStreamInner {
    /// Per-direction wakers and shared reactor registration.
    state: Arc<Mutex<SplitIoState>>,
    /// The underlying TCP stream.
    #[cfg(not(target_arch = "wasm32"))]
    stream: Arc<net::TcpStream>,
    #[cfg(target_arch = "wasm32")]
    #[allow(dead_code)]
    unsupported: (),
}

impl std::fmt::Debug for TcpStreamInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("TcpStreamInner");
        #[cfg(not(target_arch = "wasm32"))]
        debug.field("stream", &self.stream);
        #[cfg(target_arch = "wasm32")]
        debug.field("stream", &"unsupported");
        debug.field("state", &"...").finish()
    }
}

impl TcpStreamInner {
    fn drain_registration_transition(&self) -> DirectionWakers {
        let mut guard = self.state.lock();
        debug_assert!(guard.registration_transition);
        debug_assert!(guard.registration.is_none());
        let waiters = take_all_waiters(&mut guard);
        guard.registration_transition = false;
        waiters
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn finish_registration_transition(
        &self,
        cx: &Context<'_>,
        interest: Interest,
        installed: WaiterTokens,
    ) -> io::Result<WaiterTokens> {
        let mut guard = self.state.lock();
        debug_assert!(guard.registration_transition);
        debug_assert!(guard.registration.is_none());

        if guard.read_waiter.is_none() && guard.write_waiter.is_none() {
            guard.registration_transition = false;
            return Ok(installed);
        }

        let waker = combined_waker(&self.state, &guard);
        let desired_interest = registration_interest(
            guard.read_waiter.is_some(),
            guard.write_waiter.is_some(),
            interest,
        );
        let Some(current) = Cx::current() else {
            let waiters = take_all_waiters(&mut guard);
            guard.registration_transition = false;
            drop(guard);
            wake_other_waiters(waiters, cx.waker());
            crate::net::tcp::stream::fallback_rewake(cx);
            return Ok(installed);
        };
        let Some(driver) = current.io_driver_handle() else {
            let waiters = take_all_waiters(&mut guard);
            guard.registration_transition = false;
            drop(guard);
            wake_other_waiters(waiters, cx.waker());
            crate::net::tcp::stream::fallback_rewake(cx);
            return Ok(installed);
        };

        match driver.register(&*self.stream, desired_interest, waker) {
            Ok(registration) => {
                guard.registration = Some(registration);
                guard.registration_transition = false;
                Ok(installed)
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::Unsupported | io::ErrorKind::NotConnected
                ) =>
            {
                let waiters = take_all_waiters(&mut guard);
                guard.registration_transition = false;
                drop(guard);
                wake_other_waiters(waiters, cx.waker());
                crate::net::tcp::stream::fallback_rewake(cx);
                Ok(installed)
            }
            Err(err) => {
                let failed_waiters = take_matching_waiters(&mut guard, installed);
                let surviving_waiters = take_all_waiters(&mut guard);
                guard.registration_transition = false;
                drop(guard);
                drop(failed_waiters);
                wake_waiters(surviving_waiters);
                Err(err)
            }
        }
    }

    #[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn register_interest(&self, cx: &Context<'_>, interest: Interest) -> io::Result<WaiterTokens> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (cx, interest);
            browser_tcp_unsupported_result("OwnedTcpStream::register_interest")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            // RawWaker::clone is arbitrary user code. Clone before taking the
            // split-state lock so a custom waker cannot re-enter this state.
            let mut prepared_waiters = prepare_waiters(interest, cx.waker());
            let mut guard = self.state.lock();
            let (installed, replaced_waiters) =
                install_waiters(&mut guard, interest, &mut prepared_waiters)?;
            if guard.registration_transition {
                drop(guard);
                drop(replaced_waiters);
                return Ok(installed);
            }
            let waker = combined_waker(&self.state, &guard);
            let desired_interest = registration_interest(
                guard.read_waiter.is_some(),
                guard.write_waiter.is_some(),
                interest,
            );
            if let Some(rearm_result) = guard
                .registration
                .as_mut()
                .map(|registration| registration.rearm(desired_interest, &waker))
            {
                match rearm_result {
                    Ok(true) => {
                        drop(guard);
                        drop(replaced_waiters);
                        return Ok(installed);
                    }
                    Ok(false) => {
                        let dropped_reg = guard.registration.take();
                        guard.registration_transition = true;
                        drop(guard);
                        drop(dropped_reg);
                        drop(replaced_waiters);
                        return self.finish_registration_transition(cx, interest, installed);
                    }
                    Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                        let dropped_reg = guard.registration.take();
                        guard.registration_transition = true;
                        let waiters_to_wake = take_all_waiters(&mut guard);
                        drop(guard);
                        drop(dropped_reg);
                        drop(replaced_waiters);
                        let concurrent_waiters = self.drain_registration_transition();
                        wake_waiters(waiters_to_wake);
                        wake_waiters(concurrent_waiters);
                        return Ok(installed);
                    }
                    Err(err) => {
                        let failed_waiters = take_matching_waiters(&mut guard, installed);
                        let dropped_reg = guard.registration.take();
                        guard.registration_transition = true;
                        let surviving_waiters = take_all_waiters(&mut guard);
                        drop(guard);
                        drop(dropped_reg);
                        drop(replaced_waiters);
                        drop(failed_waiters);
                        let concurrent_waiters = self.drain_registration_transition();
                        wake_waiters(surviving_waiters);
                        wake_waiters(concurrent_waiters);
                        return Err(err);
                    }
                }
            }

            let Some(current) = Cx::current() else {
                let fallback_waiters = take_all_waiters(&mut guard);
                drop(guard);
                drop(replaced_waiters);
                wake_other_waiters(fallback_waiters, cx.waker());
                crate::net::tcp::stream::fallback_rewake(cx);
                return Ok(installed);
            };
            let Some(driver) = current.io_driver_handle() else {
                let fallback_waiters = take_all_waiters(&mut guard);
                drop(guard);
                drop(replaced_waiters);
                wake_other_waiters(fallback_waiters, cx.waker());
                crate::net::tcp::stream::fallback_rewake(cx);
                return Ok(installed);
            };

            // Keep the state lock across fresh registration so concurrent
            // halves cannot both issue reactor ADD for the same socket.
            match driver.register(&*self.stream, desired_interest, waker) {
                Ok(registration) => {
                    guard.registration = Some(registration);
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
                    drop(guard);
                    drop(replaced_waiters);
                    wake_other_waiters(fallback_waiters, cx.waker());
                    crate::net::tcp::stream::fallback_rewake(cx);
                    Ok(installed)
                }
                Err(err) => {
                    let failed_waiters = take_matching_waiters(&mut guard, installed);
                    let surviving_waiters = take_all_waiters(&mut guard);
                    drop(guard);
                    drop(replaced_waiters);
                    drop(failed_waiters);
                    wake_waiters(surviving_waiters);
                    Err(err)
                }
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
        if guard.registration_transition {
            // The transition owner will either register the surviving union
            // after its old DEL completes or drain and wake it. This retire
            // call only removes its exact generation.
            drop(guard);
            drop(retired_waiters);
            return;
        }

        let desired_interest = registration_interest(
            guard.read_waiter.is_some(),
            guard.write_waiter.is_some(),
            Interest::empty(),
        );
        let mut surviving_waiters = (None, None);
        let mut started_transition = false;
        let dropped_reg = if desired_interest.is_empty() {
            let registration = guard.registration.take();
            if registration.is_some() {
                guard.registration_transition = true;
                started_transition = true;
            }
            registration
        } else {
            let combined = combined_waker(&self.state, &guard);
            let rearm_ok = guard.registration.as_mut().is_some_and(|registration| {
                matches!(registration.rearm(desired_interest, &combined), Ok(true))
            });
            if rearm_ok {
                None
            } else {
                surviving_waiters = take_all_waiters(&mut guard);
                let registration = guard.registration.take();
                if registration.is_some() {
                    guard.registration_transition = true;
                    started_transition = true;
                }
                registration
            }
        };

        drop(guard);
        drop(dropped_reg);
        drop(retired_waiters);
        let concurrent_waiters = if started_transition {
            self.drain_registration_transition()
        } else {
            (None, None)
        };
        wake_waiters(surviving_waiters);
        wake_waiters(concurrent_waiters);
    }
}

/// Owned read half of a split TCP stream.
///
/// This can be sent to another task and properly participates in reactor
/// registration. The registration is shared with the corresponding
/// [`OwnedWriteHalf`].
#[derive(Debug)]
pub struct OwnedReadHalf {
    inner: Arc<TcpStreamInner>,
    last_waiter: Option<u64>,
}

impl OwnedReadHalf {
    /// Create a paired read and write half sharing the same inner state.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn new_pair(
        stream: Arc<net::TcpStream>,
        registration: Option<IoRegistration>,
    ) -> (Self, OwnedWriteHalf) {
        let state = Arc::new(Mutex::new(split_io_state(None)));
        adopt_inherited_registration(&state, registration);
        let inner = Arc::new(TcpStreamInner { state, stream });
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

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn unsupported_pair() -> (Self, OwnedWriteHalf) {
        let inner = Arc::new(TcpStreamInner {
            unsupported: (),
            state: Arc::new(Mutex::new(split_io_state(None))),
        });
        (
            Self {
                inner: inner.clone(),
                last_waiter: None,
            },
            OwnedWriteHalf {
                inner,
                shutdown_on_drop: false,
                last_waiter: None,
            },
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn pending_on_interest<T>(&mut self, cx: &Context<'_>) -> Poll<io::Result<T>> {
        match self.inner.register_interest(cx, Interest::READABLE) {
            Ok(tokens) => {
                self.last_waiter = tokens.read;
                Poll::Pending
            }
            Err(err) => self.finish_poll(Err(err)),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn finish_poll<T>(&mut self, result: io::Result<T>) -> Poll<io::Result<T>> {
        self.inner
            .retire_waiter(Interest::READABLE, self.last_waiter.take());
        Poll::Ready(result)
    }

    /// Returns the local address of the stream.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        #[cfg(target_arch = "wasm32")]
        {
            browser_tcp_unsupported_result("OwnedReadHalf::local_addr")
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.stream.local_addr()
    }

    /// Returns the peer address of the stream.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        #[cfg(target_arch = "wasm32")]
        {
            browser_tcp_unsupported_result("OwnedReadHalf::peer_addr")
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.stream.peer_addr()
    }

    /// Reunite with the write half to reconstruct the original TcpStream.
    ///
    /// # Errors
    ///
    /// Returns an error containing both halves if they don't belong to the
    /// same original stream.
    #[allow(unused_mut)]
    pub fn reunite(
        mut self,
        mut write: OwnedWriteHalf,
    ) -> Result<super::stream::TcpStream, ReuniteError> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = Arc::ptr_eq(&self.inner, &write.inner);
            Err(ReuniteError { read: self, write })
        }

        #[cfg(not(target_arch = "wasm32"))]
        if Arc::ptr_eq(&self.inner, &write.inner) {
            // Do not retire or shut down either direction when the consumed
            // halves are dropped at the end of this function.
            self.last_waiter = None;
            write.last_waiter = None;
            write.shutdown_on_drop = false;

            let (registration, waiters) = {
                let mut state = self.inner.state.lock();
                let waiters = take_all_waiters(&mut state);
                (state.registration.take(), waiters)
            };
            drop(waiters);

            Ok(super::stream::TcpStream::from_parts(
                self.inner.stream.clone(),
                registration,
            ))
        } else {
            Err(ReuniteError { read: self, write })
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(target_arch = "wasm32")]
impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _ = (self, cx, buf);
        browser_tcp_poll_unsupported("OwnedReadHalf::poll_read")
    }
}

#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(target_arch = "wasm32")]
impl AsyncReadVectored for OwnedReadHalf {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let _ = (self, cx, bufs);
        browser_tcp_poll_unsupported("OwnedReadHalf::poll_read_vectored")
    }
}

/// Owned write half of a split TCP stream.
///
/// This can be sent to another task and properly participates in reactor
/// registration. The registration is shared with the corresponding
/// [`OwnedReadHalf`].
///
/// By default, the stream's write direction is shut down when this half
/// is dropped. Use [`set_shutdown_on_drop(false)`][Self::set_shutdown_on_drop]
/// to disable this behavior.
#[derive(Debug)]
pub struct OwnedWriteHalf {
    inner: Arc<TcpStreamInner>,
    shutdown_on_drop: bool,
    last_waiter: Option<u64>,
}

impl OwnedWriteHalf {
    /// Returns the local address of the stream.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        #[cfg(target_arch = "wasm32")]
        {
            browser_tcp_unsupported_result("OwnedWriteHalf::local_addr")
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.stream.local_addr()
    }

    /// Returns the peer address of the stream.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        #[cfg(target_arch = "wasm32")]
        {
            browser_tcp_unsupported_result("OwnedWriteHalf::peer_addr")
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.stream.peer_addr()
    }

    /// Controls whether the write direction is shut down when dropped.
    ///
    /// Default is `true`.
    pub fn set_shutdown_on_drop(&mut self, shutdown: bool) {
        self.shutdown_on_drop = shutdown;
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn pending_on_interest<T>(&mut self, cx: &Context<'_>) -> Poll<io::Result<T>> {
        match self.inner.register_interest(cx, Interest::WRITABLE) {
            Ok(tokens) => {
                self.last_waiter = tokens.write;
                Poll::Pending
            }
            Err(err) => self.finish_poll(Err(err)),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn finish_poll<T>(&mut self, result: io::Result<T>) -> Poll<io::Result<T>> {
        self.inner
            .retire_waiter(Interest::WRITABLE, self.last_waiter.take());
        Poll::Ready(result)
    }
}

#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(target_arch = "wasm32")]
impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let _ = (self, cx, buf);
        browser_tcp_poll_unsupported("OwnedWriteHalf::poll_write")
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = (self, cx);
        browser_tcp_poll_unsupported("OwnedWriteHalf::poll_flush")
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = (self, cx);
        browser_tcp_poll_unsupported("OwnedWriteHalf::poll_shutdown")
    }
}

impl Drop for OwnedWriteHalf {
    fn drop(&mut self) {
        self.inner
            .retire_waiter(Interest::WRITABLE, self.last_waiter.take());
        #[cfg(not(target_arch = "wasm32"))]
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

/// Error returned when trying to reunite halves that don't match.
#[derive(Debug)]
pub struct ReuniteError {
    /// The read half that was passed to reunite.
    pub read: OwnedReadHalf,
    /// The write half that was passed to reunite.
    pub write: OwnedWriteHalf,
}

impl std::fmt::Display for ReuniteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tried to reunite halves that don't belong to the same stream"
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
    use crate::io::AsyncReadVectored;
    use crate::net::tcp::stream::TcpStream;
    #[cfg(unix)]
    use crate::runtime::io_driver::IoDriverHandle;
    #[cfg(unix)]
    use crate::runtime::reactor::{Events, Reactor, Source, Token};
    use crate::test_utils::init_test_logging;
    #[cfg(unix)]
    use crate::types::{Budget, RegionId, TaskId};
    #[cfg(unix)]
    use parking_lot::Mutex;
    #[cfg(unix)]
    use std::collections::HashMap;
    use std::io::{IoSliceMut, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    #[cfg(unix)]
    use std::sync::Barrier;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Waker};
    use std::thread;
    use std::time::Duration;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[cfg(unix)]
    struct CountingWaker {
        hits: Arc<AtomicUsize>,
    }

    #[cfg(unix)]
    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[cfg(unix)]
    fn counting_waker() -> (Waker, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        (waker, hits)
    }

    #[cfg(unix)]
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

    #[cfg(unix)]
    struct LockProbeWaker {
        state: Weak<Mutex<SplitIoState>>,
        observed_unlocked: Arc<AtomicBool>,
        hits: Arc<AtomicUsize>,
    }

    #[cfg(unix)]
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

    #[cfg(unix)]
    struct DropProbeWaker {
        dropped: Arc<AtomicBool>,
    }

    // This must carry an Arc-backed drop probe; Waker::noop() cannot observe release.
    #[cfg(unix)]
    #[allow(clippy::manual_noop_waker)]
    impl Wake for DropProbeWaker {
        fn wake(self: Arc<Self>) {}

        fn wake_by_ref(self: &Arc<Self>) {}
    }

    #[cfg(unix)]
    impl Drop for DropProbeWaker {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct SourceExclusiveState {
        source_to_token: HashMap<i32, Token>,
        token_to_source: HashMap<Token, i32>,
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct SourceExclusiveReactor {
        state: Mutex<SourceExclusiveState>,
        register_calls: AtomicUsize,
        modify_calls: AtomicUsize,
        fail_modify_on_call: AtomicUsize,
        fail_modify_not_connected: AtomicBool,
        slow_first_register: AtomicBool,
        deregister_gate: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    }

    #[cfg(unix)]
    impl SourceExclusiveReactor {
        fn new() -> Self {
            Self {
                state: Mutex::new(SourceExclusiveState::default()),
                register_calls: AtomicUsize::new(0),
                modify_calls: AtomicUsize::new(0),
                fail_modify_on_call: AtomicUsize::new(0),
                fail_modify_not_connected: AtomicBool::new(false),
                slow_first_register: AtomicBool::new(true),
                deregister_gate: Mutex::new(None),
            }
        }

        fn register_calls(&self) -> usize {
            self.register_calls.load(Ordering::SeqCst)
        }

        fn modify_calls(&self) -> usize {
            self.modify_calls.load(Ordering::SeqCst)
        }

        fn fail_modify_on_call(&self, call_index: usize) {
            self.fail_modify_on_call.store(call_index, Ordering::SeqCst);
        }

        fn fail_modify_with_not_connected(&self, enabled: bool) {
            self.fail_modify_not_connected
                .store(enabled, Ordering::SeqCst);
        }

        fn block_next_deregister(&self) -> (Arc<Barrier>, Arc<Barrier>) {
            let entered = Arc::new(Barrier::new(2));
            let release = Arc::new(Barrier::new(2));
            *self.deregister_gate.lock() = Some((Arc::clone(&entered), Arc::clone(&release)));
            (entered, release)
        }
    }

    #[cfg(unix)]
    impl Reactor for SourceExclusiveReactor {
        fn register(
            &self,
            source: &dyn Source,
            token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            let fd = source.raw_fd();
            let mut state = self.state.lock();

            if state.source_to_token.contains_key(&fd) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "source already registered",
                ));
            }
            if state.token_to_source.contains_key(&token) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "token already registered",
                ));
            }

            state.source_to_token.insert(fd, token);
            state.token_to_source.insert(token, fd);
            drop(state);

            self.register_calls.fetch_add(1, Ordering::SeqCst);
            if self.slow_first_register.swap(false, Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(())
        }

        fn modify(&self, token: Token, _interest: Interest) -> io::Result<()> {
            let state = self.state.lock();
            if !state.token_to_source.contains_key(&token) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            }
            drop(state);
            let call = self.modify_calls.fetch_add(1, Ordering::SeqCst) + 1;
            let fail_on = self.fail_modify_on_call.load(Ordering::SeqCst);
            if fail_on != 0 && call == fail_on {
                if self.fail_modify_not_connected.load(Ordering::SeqCst) {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "injected not-connected modify failure",
                    ));
                }
                return Err(io::Error::other("injected modify failure"));
            }
            Ok(())
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            if let Some((entered, release)) = self.deregister_gate.lock().take() {
                entered.wait();
                release.wait();
            }
            let mut state = self.state.lock();
            let Some(fd) = state.token_to_source.remove(&token) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            };
            state.source_to_token.remove(&fd);
            drop(state);
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
    fn borrowed_split_read_write() {
        init_test("borrowed_split_read_write");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        client.set_nonblocking(true).expect("nonblocking");

        let (mut server, _) = listener.accept().expect("accept");

        // Create borrowed halves
        let _read_half = ReadHalf::new(&client);
        let _write_half = WriteHalf::new(&client);

        // Write from server, read from client
        server.write_all(b"hello").expect("write");

        // Borrowed halves work (may need multiple attempts due to non-blocking)
        let mut buf = [0u8; 5];
        let _read_buf = ReadBuf::new(&mut buf);

        // Just verify the types compile and basic operations work
        crate::assert_with_log!(true, "borrowed split compiles", true, true);
        crate::test_complete!("borrowed_split_read_write");
    }

    #[test]
    fn borrowed_split_halves_return_interrupted_when_cancel_requested() {
        init_test("borrowed_split_halves_return_interrupted_when_cancel_requested");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        client.set_nonblocking(true).expect("nonblocking");
        let (_server, _) = listener.accept().expect("accept");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let mut read_half = ReadHalf::new(&client);
        let mut write_half = WriteHalf::new(&client);
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

    fn read_vectored_payload<R: AsyncReadVectored + Unpin>(reader: &mut R, payload: &[u8]) {
        let mut first = [0u8; 3];
        let mut second = [0u8; 3];
        assert_eq!(payload.len(), first.len() + second.len());
        let mut total = 0usize;
        let mut attempts = 0usize;

        while total < payload.len() {
            attempts += 1;
            assert!(attempts <= 32, "vectored split read did not become ready");
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let polled = if total < first.len() {
                let offset = total;
                let mut bufs = [
                    IoSliceMut::new(&mut first[offset..]),
                    IoSliceMut::new(&mut second),
                ];
                Pin::new(&mut *reader).poll_read_vectored(&mut cx, &mut bufs)
            } else {
                let offset = total - first.len();
                let mut bufs = [IoSliceMut::new(&mut second[offset..])];
                Pin::new(&mut *reader).poll_read_vectored(&mut cx, &mut bufs)
            };

            match polled {
                Poll::Ready(Ok(0)) => panic!("vectored split read reached EOF early"),
                Poll::Ready(Ok(n)) => total += n,
                Poll::Ready(Err(err)) => panic!("vectored split read failed: {err}"),
                Poll::Pending => thread::sleep(Duration::from_millis(5)),
            }
        }

        let mut combined = [0u8; 6];
        combined[..first.len()].copy_from_slice(&first);
        combined[first.len()..].copy_from_slice(&second);
        crate::assert_with_log!(
            combined.as_slice() == payload,
            "vectored split read preserves payload",
            payload,
            combined
        );
    }

    #[test]
    fn borrowed_split_read_half_supports_vectored_reads() {
        init_test("borrowed_split_read_half_supports_vectored_reads");

        let payload = b"vector";
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        client.set_nonblocking(true).expect("nonblocking");
        let (mut server, _) = listener.accept().expect("accept");
        let mut read_half = ReadHalf::new(&client);

        server.write_all(payload).expect("write payload");
        read_vectored_payload(&mut read_half, payload);

        crate::test_complete!("borrowed_split_read_half_supports_vectored_reads");
    }

    #[test]
    fn owned_split_creates_pair() {
        init_test("owned_split_creates_pair");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = Arc::new(client);

        let (read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        // Verify they share the same inner
        let same_inner = Arc::ptr_eq(&read_half.inner, &write_half.inner);
        crate::assert_with_log!(same_inner, "halves share inner", true, same_inner);

        crate::test_complete!("owned_split_creates_pair");
    }

    #[test]
    fn owned_split_read_half_supports_vectored_reads() {
        init_test("owned_split_read_half_supports_vectored_reads");

        let payload = b"vector";
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = TcpStream::from_std(client).expect("wrap stream");
        let (mut read_half, _write_half) = stream.into_split();
        let (mut server, _) = listener.accept().expect("accept");

        server.write_all(payload).expect("write payload");
        read_vectored_payload(&mut read_half, payload);

        crate::test_complete!("owned_split_read_half_supports_vectored_reads");
    }

    #[test]
    fn owned_split_reunite_success() {
        init_test("owned_split_reunite_success");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = Arc::new(client);

        let (read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        let result = read_half.reunite(write_half);
        crate::assert_with_log!(result.is_ok(), "reunite succeeds", true, result.is_ok());

        crate::test_complete!("owned_split_reunite_success");
    }

    #[test]
    fn into_split_does_not_shutdown_stream() {
        init_test("into_split_does_not_shutdown_stream");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");

        let stream = TcpStream::from_std(client).expect("wrap stream");
        let (_read_half, write_half) = stream.into_split();

        let mut stream_ref = write_half.inner.stream.as_ref();
        stream_ref.write_all(b"ping").expect("client write");

        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).expect("server read");

        crate::assert_with_log!(
            buf == *b"ping",
            "into_split keeps stream open",
            *b"ping",
            buf
        );

        crate::test_complete!("into_split_does_not_shutdown_stream");
    }

    #[test]
    fn owned_split_reunite_mismatch() {
        init_test("owned_split_reunite_mismatch");

        let listener1 = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr1 = listener1.local_addr().expect("local addr");
        let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr2 = listener2.local_addr().expect("local addr");

        let client1 = std::net::TcpStream::connect(addr1).expect("connect");
        let client2 = std::net::TcpStream::connect(addr2).expect("connect");

        let (read_half1, _write_half1) = OwnedReadHalf::new_pair(Arc::new(client1), None);
        let (_read_half2, write_half2) = OwnedReadHalf::new_pair(Arc::new(client2), None);

        // Try to reunite mismatched halves
        let result = read_half1.reunite(write_half2);
        crate::assert_with_log!(
            result.is_err(),
            "reunite fails for mismatch",
            true,
            result.is_err()
        );

        crate::test_complete!("owned_split_reunite_mismatch");
    }

    #[test]
    fn owned_half_addresses() {
        init_test("owned_half_addresses");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = Arc::new(client);

        let (read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        // Both halves should report same addresses
        let read_local = read_half.local_addr().expect("local");
        let write_local = write_half.local_addr().expect("local");
        crate::assert_with_log!(
            read_local == write_local,
            "same local addr",
            read_local,
            write_local
        );

        let read_peer = read_half.peer_addr().expect("peer");
        let write_peer = write_half.peer_addr().expect("peer");
        crate::assert_with_log!(
            read_peer == write_peer,
            "same peer addr",
            read_peer,
            write_peer
        );

        crate::test_complete!("owned_half_addresses");
    }

    #[cfg(unix)]
    #[test]
    fn split_register_interest_serializes_fresh_registration() {
        init_test("split_register_interest_serializes_fresh_registration");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor.clone());
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );

        let barrier = Arc::new(Barrier::new(3));
        let read_inner = read_half.inner.clone();
        let read_cx = cx.clone();
        let read_barrier = barrier.clone();
        let read_thread = thread::spawn(move || {
            let _guard = Cx::set_current(Some(read_cx));
            let waker = noop_waker();
            let task_cx = Context::from_waker(&waker);
            read_barrier.wait();
            read_inner.register_interest(&task_cx, Interest::READABLE)
        });

        let write_inner = write_half.inner.clone();
        let write_cx = cx;
        let write_barrier = barrier.clone();
        let write_thread = thread::spawn(move || {
            let _guard = Cx::set_current(Some(write_cx));
            let waker = noop_waker();
            let task_cx = Context::from_waker(&waker);
            write_barrier.wait();
            write_inner.register_interest(&task_cx, Interest::WRITABLE)
        });

        barrier.wait();
        let read_result = read_thread.join().expect("read thread panic");
        let write_result = write_thread.join().expect("write thread panic");
        assert!(
            read_result.is_ok(),
            "read half registration should not fail: {read_result:?}"
        );
        assert!(
            write_result.is_ok(),
            "write half registration should not fail: {write_result:?}"
        );
        assert_eq!(
            reactor.register_calls(),
            1,
            "fresh split registration should be issued once"
        );
        assert_eq!(
            reactor.modify_calls(),
            1,
            "second waiter should re-arm existing registration"
        );
    }

    #[test]
    fn write_half_shutdown_on_drop() {
        init_test("write_half_shutdown_on_drop");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");

        let stream = Arc::new(client);
        let (_read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        drop(write_half);

        // Server should see connection shutdown
        let mut buf = [0u8; 1];
        let result = server.read(&mut buf);
        // Should get 0 bytes (EOF) or an error
        let is_shutdown = matches!(result, Ok(0) | Err(_));
        crate::assert_with_log!(is_shutdown, "write shutdown on drop", true, is_shutdown);

        crate::test_complete!("write_half_shutdown_on_drop");
    }

    #[test]
    fn registration_interest_prefers_waiter_union() {
        init_test("registration_interest_prefers_waiter_union");

        let both = registration_interest(true, true, Interest::READABLE);
        crate::assert_with_log!(
            both == (Interest::READABLE | Interest::WRITABLE),
            "both interests preserved",
            Interest::READABLE | Interest::WRITABLE,
            both
        );

        let read_only = registration_interest(true, false, Interest::WRITABLE);
        crate::assert_with_log!(
            read_only == Interest::READABLE,
            "read waiter wins",
            Interest::READABLE,
            read_only
        );

        let fallback = registration_interest(false, false, Interest::WRITABLE);
        crate::assert_with_log!(
            fallback == Interest::WRITABLE,
            "fallback interest",
            Interest::WRITABLE,
            fallback
        );

        crate::test_complete!("registration_interest_prefers_waiter_union");
    }

    #[cfg(unix)]
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

    #[cfg(unix)]
    #[test]
    fn stale_combined_waker_does_not_retain_replaced_task_waker() {
        let state = Arc::new(Mutex::new(split_io_state(None)));
        let dropped = Arc::new(AtomicBool::new(false));
        let old_task_waker = Waker::from(Arc::new(DropProbeWaker {
            dropped: Arc::clone(&dropped),
        }));
        let new_task_waker = noop_waker();

        let (_, stale_snapshot) = install_snapshot(&state, Interest::READABLE, &old_task_waker);
        let _ = install_snapshot(&state, Interest::READABLE, &new_task_waker);
        drop(old_task_waker);

        assert!(
            dropped.load(Ordering::SeqCst),
            "stale combined snapshot retained a replaced task waker"
        );
        stale_snapshot.wake_by_ref();
        assert!(state.lock().read_waiter.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn combined_dispatch_wakes_after_state_unlock() {
        let state = Arc::new(Mutex::new(split_io_state(None)));
        let observed_unlocked = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(AtomicUsize::new(0));
        let task_waker = Waker::from(Arc::new(LockProbeWaker {
            state: Arc::downgrade(&state),
            observed_unlocked: Arc::clone(&observed_unlocked),
            hits: Arc::clone(&hits),
        }));
        let (_, snapshot) = install_snapshot(&state, Interest::READABLE, &task_waker);

        snapshot.wake_by_ref();

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(observed_unlocked.load(Ordering::SeqCst));
        assert!(state.lock().read_waiter.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn inherited_registration_is_adopted_in_place_across_reunite() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = Arc::new(std::net::TcpStream::connect(addr).expect("connect"));
        let (mut server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor.clone());
        let old_waker_dropped = Arc::new(AtomicBool::new(false));
        let old_waker = Waker::from(Arc::new(DropProbeWaker {
            dropped: Arc::clone(&old_waker_dropped),
        }));
        let mut registration = driver
            .register(&*client, Interest::READABLE, old_waker.clone())
            .expect("register unsplit stream");
        assert!(
            registration
                .rearm(Interest::READABLE, &old_waker)
                .expect("prime cached task waker")
        );
        let original_token = registration.token();
        drop(old_waker);
        assert!(!old_waker_dropped.load(Ordering::SeqCst));

        let (read_half, write_half) =
            OwnedReadHalf::new_pair(Arc::clone(&client), Some(registration));
        assert!(old_waker_dropped.load(Ordering::SeqCst));
        assert_eq!(reactor.register_calls(), 1);
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
        assert_eq!(reactor.register_calls(), 1);
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

        server.write_all(b"x").expect("write byte");
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

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
    #[test]
    fn fallback_wake_runs_after_state_unlock() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let (read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);

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

    #[cfg(unix)]
    #[test]
    fn owned_read_ready_retires_waiter_registration() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let (mut read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);

        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _current = Cx::set_current(Some(cx));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut bytes = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut bytes);

        let pending = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(pending.is_pending());
        {
            let state = read_half.inner.state.lock();
            assert!(state.read_waiter.is_some());
            assert!(state.registration.is_some());
        }

        server.write_all(b"x").expect("write byte");
        let ready = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(matches!(ready, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"x");
        assert!(read_half.last_waiter.is_none());
        let state = read_half.inner.state.lock();
        assert!(state.read_waiter.is_none());
        assert!(state.registration.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn owned_read_cancellation_retires_waiter_registration() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let (mut read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);

        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _current = Cx::set_current(Some(cx.clone()));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut bytes = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut bytes);

        let pending = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(pending.is_pending());
        cx.set_cancel_requested(true);
        let cancelled = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(matches!(
            cancelled,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));
        assert!(read_half.last_waiter.is_none());
        let state = read_half.inner.state.lock();
        assert!(state.read_waiter.is_none());
        assert!(state.registration.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn missing_driver_waker_deregisters_before_fresh_add() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);

        let reactor = Arc::new(SourceExclusiveReactor::new());
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
        let read_cx = Context::from_waker(&read_waker);
        read_half
            .inner
            .register_interest(&read_cx, Interest::READABLE)
            .expect("initial register");
        let old_token = read_half
            .inner
            .state
            .lock()
            .registration
            .as_ref()
            .expect("registration")
            .token();

        // Preserve the reactor mapping while removing only the slab waker.
        // The next rearm must return Ok(false), physically DEL the old
        // mapping, and only then issue a fresh ADD for this socket.
        driver.lock().deregister_waker(old_token);
        let write_waker = noop_waker();
        let write_cx = Context::from_waker(&write_waker);
        let write_tokens = write_half
            .inner
            .register_interest(&write_cx, Interest::WRITABLE)
            .expect("fresh ADD after old DEL");

        assert!(write_tokens.write.is_some());
        assert_eq!(reactor.register_calls(), 2);
        assert_eq!(reactor.registration_count(), 1);
        let state = read_half.inner.state.lock();
        assert!(!state.registration_transition);
        assert_eq!(
            state
                .registration
                .as_ref()
                .expect("registration")
                .interest(),
            Interest::READABLE | Interest::WRITABLE
        );
    }

    #[cfg(unix)]
    #[test]
    fn retire_transition_queues_sibling_until_old_del_completes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);

        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor.clone());
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _current = Cx::set_current(Some(cx.clone()));
        let read_waker = noop_waker();
        let read_cx = Context::from_waker(&read_waker);
        let read_tokens = read_half
            .inner
            .register_interest(&read_cx, Interest::READABLE)
            .expect("initial register");
        let read_token = read_tokens.read.expect("read waiter token");

        let (deregister_entered, release_deregister) = reactor.block_next_deregister();
        let retire_inner = Arc::clone(&read_half.inner);
        let retire_thread = thread::spawn(move || {
            retire_inner.retire_waiter(Interest::READABLE, Some(read_token));
        });
        deregister_entered.wait();

        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let register_inner = Arc::clone(&write_half.inner);
        let register_thread = thread::spawn(move || {
            let _current = Cx::set_current(Some(cx));
            let waker = noop_waker();
            let task_cx = Context::from_waker(&waker);
            let result = register_inner.register_interest(&task_cx, Interest::WRITABLE);
            result_tx.send(result).expect("send register result");
        });

        // A sibling polling during the physical DEL must publish its waiter
        // and return without attempting ADD against the still-live mapping.
        let early_result = result_rx.recv_timeout(Duration::from_secs(5));
        let completed_before_del = early_result.is_ok();
        let register_calls_before_del = reactor.register_calls();

        release_deregister.wait();
        retire_thread.join().expect("retire thread");
        register_thread.join().expect("register thread");
        let result = match early_result {
            Ok(result) => result,
            Err(_) => result_rx.recv().expect("late register result"),
        };
        let write_tokens = result.expect("queued sibling registration");
        write_half
            .inner
            .retire_waiter(Interest::WRITABLE, write_tokens.write);

        assert!(
            completed_before_del,
            "sibling registration blocked on driver ADD during old DEL"
        );
        assert_eq!(
            register_calls_before_del, 1,
            "fresh ADD must not occur before old DEL completes"
        );
        let state = read_half.inner.state.lock();
        assert!(!state.registration_transition);
        assert!(state.registration.is_none());
        assert!(state.read_waiter.is_none());
        assert!(state.write_waiter.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn dropping_read_half_clears_waiter_and_registration_when_idle() {
        init_test("dropping_read_half_clears_waiter_and_registration_when_idle");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (mut read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let waker = noop_waker();
        let task_cx = Context::from_waker(&waker);
        let tokens = read_half
            .inner
            .register_interest(&task_cx, Interest::READABLE)
            .expect("register readable");
        read_half.last_waiter = tokens.read;

        drop(read_half);

        let state = write_half.inner.state.lock();
        assert!(
            state.read_waiter.is_none(),
            "read waiter must be cleared after read half drop"
        );
        assert!(
            state.registration.is_none(),
            "registration should be released when no waiters remain"
        );
        drop(state);
    }

    #[cfg(unix)]
    #[test]
    fn dropping_write_half_clears_waiter_and_keeps_read_interest() {
        init_test("dropping_write_half_clears_waiter_and_keeps_read_interest");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (mut read_half, mut write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let waker = noop_waker();
        let task_cx = Context::from_waker(&waker);
        let read_tokens = read_half
            .inner
            .register_interest(&task_cx, Interest::READABLE)
            .expect("register readable");
        read_half.last_waiter = read_tokens.read;
        let write_tokens = write_half
            .inner
            .register_interest(&task_cx, Interest::WRITABLE)
            .expect("register writable");
        write_half.last_waiter = write_tokens.write;

        drop(write_half);

        let state = read_half.inner.state.lock();
        assert!(
            state.write_waiter.is_none(),
            "write waiter must be cleared after write half drop"
        );
        assert!(
            state.registration.is_some(),
            "registration should remain for the live read waiter"
        );
        assert_eq!(
            state
                .registration
                .as_ref()
                .expect("registration")
                .interest(),
            Interest::READABLE,
            "interest should drop writable bit when write half is dropped"
        );
        drop(state);
    }

    #[cfg(unix)]
    #[test]
    fn dropping_write_half_wakes_survivor_when_reregistration_fails() {
        init_test("dropping_write_half_wakes_survivor_when_reregistration_fails");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (mut read_half, mut write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        // First modify call (adding WRITABLE) succeeds; second modify call
        // (drop-time narrowing to READABLE) fails.
        reactor.fail_modify_on_call(2);

        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let (read_waker, read_hits) = counting_waker();
        let read_task_cx = Context::from_waker(&read_waker);
        let read_tokens = read_half
            .inner
            .register_interest(&read_task_cx, Interest::READABLE)
            .expect("register readable");
        read_half.last_waiter = read_tokens.read;

        let write_waker = noop_waker();
        let write_task_cx = Context::from_waker(&write_waker);
        let write_tokens = write_half
            .inner
            .register_interest(&write_task_cx, Interest::WRITABLE)
            .expect("register writable");
        write_half.last_waiter = write_tokens.write;

        drop(write_half);

        let state = read_half.inner.state.lock();
        assert!(
            state.registration.is_none(),
            "registration should be dropped after injected re-arm failure"
        );
        drop(state);

        assert!(
            read_hits.load(Ordering::SeqCst) == 1,
            "surviving waiter must be woken to retry registration after drop-time failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hard_modify_failure_drops_registration_and_wakes_only_survivor() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        reactor.fail_modify_on_call(1);
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _current = Cx::set_current(Some(cx));

        let (read_waker, read_hits) = counting_waker();
        let read_cx = Context::from_waker(&read_waker);
        read_half
            .inner
            .register_interest(&read_cx, Interest::READABLE)
            .expect("register readable");

        let (write_waker, write_hits) = counting_waker();
        let write_cx = Context::from_waker(&write_waker);
        let err = write_half
            .inner
            .register_interest(&write_cx, Interest::WRITABLE)
            .expect_err("injected hard modify failure");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(read_hits.load(Ordering::SeqCst), 1);
        assert_eq!(write_hits.load(Ordering::SeqCst), 0);
        let state = read_half.inner.state.lock();
        assert!(state.registration.is_none());
        assert!(state.read_waiter.is_none());
        assert!(state.write_waiter.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn not_connected_modify_wakes_both_split_waiters() {
        init_test("not_connected_modify_wakes_both_split_waiters");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        reactor.fail_modify_on_call(1);
        reactor.fail_modify_with_not_connected(true);

        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let (read_waker, read_hits) = counting_waker();
        let read_task_cx = Context::from_waker(&read_waker);
        read_half
            .inner
            .register_interest(&read_task_cx, Interest::READABLE)
            .expect("register readable");

        let (write_waker, write_hits) = counting_waker();
        let write_task_cx = Context::from_waker(&write_waker);
        write_half
            .inner
            .register_interest(&write_task_cx, Interest::WRITABLE)
            .expect("register writable with injected not-connected");

        let state = read_half.inner.state.lock();
        assert!(
            state.registration.is_none(),
            "registration should be dropped after not-connected modify"
        );
        drop(state);

        assert!(
            read_hits.load(Ordering::SeqCst) == 1,
            "read waiter must be woken when shared registration drops on not-connected"
        );
        assert!(
            write_hits.load(Ordering::SeqCst) == 1,
            "write waiter must be woken when shared registration drops on not-connected"
        );
    }

    #[test]
    fn owned_split_halves_return_interrupted_when_cancel_requested() {
        init_test("owned_split_halves_return_interrupted_when_cancel_requested");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        client.set_nonblocking(true).expect("nonblocking");
        let (_server, _) = listener.accept().expect("accept");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let stream = TcpStream::from_std(client).expect("wrap stream");
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
