//! TCP listener implementation.
//!
//! This module provides a TCP listener for accepting incoming connections.
//! The listener implements [`TcpListenerApi`] for use with generic code and frameworks.

use crate::cx::Cx;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::lookup_all;
use crate::net::tcp::stream::TcpStream;
use crate::net::tcp::traits::TcpListenerApi;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::udp::Armed;
use crate::net::udp::ReactorRegistration;
#[cfg(not(target_arch = "wasm32"))]
use crate::runtime::reactor::Interest;
use crate::stream::Stream;
use crate::types::Time;
use parking_lot::Mutex;
use std::future::Future;
use std::io;
use std::net::{self, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

const FALLBACK_ACCEPT_BACKOFF: Duration = Duration::from_millis(4);
const REARMED_ACCEPT_BACKOFF_BASE: Duration = Duration::from_millis(2);
const REARMED_ACCEPT_BACKOFF_CAP: Duration = Duration::from_millis(32);
const ACCEPT_STORM_WINDOW: Duration = Duration::from_millis(50);

/// Resource shortages that can recover while a listener remains open.
///
/// Inspect native codes because descriptor exhaustion has no stable
/// `ErrorKind` variant. Callers must delay retries to avoid busy-spinning.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn is_accept_resource_exhaustion(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::OutOfMemory {
        return true;
    }

    #[cfg(unix)]
    {
        matches!(
            error.raw_os_error(),
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
        )
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
        matches!(error.raw_os_error(), Some(WSAEMFILE | WSAENOBUFS))
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
fn listener_now() -> Time {
    Cx::current()
        .and_then(|current| current.timer_driver())
        .map_or_else(crate::time::wall_now, |driver| driver.now())
}

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
        {
            let waiters = self.waiters.lock();
            if waiters
                .iter()
                .any(|entry| entry.owner == owner && entry.waker.will_wake(waker))
            {
                return;
            }
        }
        // User waker clone/drop/wake hooks may re-enter this list. Clone
        // outside the gate, then recheck any state its hook could change.
        // An unchanged waker takes the no-clone path above.
        let waker = waker.clone();
        let mut waiters = self.waiters.lock();
        if owner.is_some() {
            // An accept() future keeps one entry, updated in place and removed
            // when the future is dropped, so it never has to be evicted.
            let retired = if let Some(entry) = waiters.iter_mut().find(|entry| entry.owner == owner)
            {
                Some(if entry.waker.will_wake(&waker) {
                    waker
                } else {
                    std::mem::replace(&mut entry.waker, waker)
                })
            } else {
                waiters.push(AcceptWaiter { owner, waker });
                None
            };
            drop(waiters);
            drop(retired);
            return;
        }
        if waiters
            .iter()
            .any(|existing| existing.owner.is_none() && existing.waker.will_wake(&waker))
        {
            drop(waiters);
            drop(waker);
            return;
        }
        // A direct poll_accept caller cannot be told apart from an abandoned
        // one, so those entries stay capped. Evicting live accept() futures
        // instead made each evicted waiter evict the next: with 33 tasks
        // accepting on one listener they woke each other forever.
        let mut evicted = None;
        if waiters.iter().filter(|entry| entry.owner.is_none()).count() >= 32 {
            if let Some(index) = waiters.iter().position(|entry| entry.owner.is_none()) {
                evicted = Some(waiters.remove(index).waker);
            }
        }
        waiters.push(AcceptWaiter { owner: None, waker });
        drop(waiters);
        // Publish the newcomer before waking the displaced direct poller:
        // reentrant registration must see a complete, capped waiter list.
        if let Some(evicted) = evicted {
            evicted.wake();
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
        // This owner may have moved the shared registration onto its reactor.
        // Survivors must re-poll on their own runtimes if that reactor stops
        // being serviced. Move entries out: user waker clone/drop/wake hooks
        // can re-enter this list and must never run under its lock.
        drop(retired);
        for survivor in survivors {
            survivor.waker.wake();
        }
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
    listener: &'a TcpListener,
    owner: u64,
}

impl Future for AcceptFuture<'_> {
    type Output = io::Result<(TcpStream, SocketAddr)>;

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

/// A TCP listener.
#[derive(Debug)]
pub struct TcpListener {
    /// Reactor registration for accept readiness, aware of the process-global
    /// fallback I/O driver (GH#67, asupersync-2rb75p).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    // wasm-browser-minimal: reactor paths are cfg-gated off on wasm32
    registration: Mutex<ReactorRegistration>,
    pub(crate) inner: net::TcpListener,
    accept_storm: Mutex<AcceptStormState>,
    accept_waiters: Arc<AcceptWaiters>,
    time_getter: fn() -> Time,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterestRegistrationMode {
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    // wasm-browser-minimal: reactor paths are cfg-gated off on wasm32
    ReactorArmed,
    FallbackPoll,
}

#[derive(Debug, Default)]
struct AcceptStormState {
    consecutive_would_block: u32,
    last_would_block_at: Option<Time>,
}

impl TcpListener {
    /// Wrap a bound, listening standard-library TCP listener, for example one
    /// inherited through systemd socket activation (`listenfd`) or configured
    /// with `socket2` (`SO_REUSEPORT`, a custom backlog) before `listen`.
    ///
    /// The listener is switched to non-blocking mode and registers with the
    /// reactor on its first accept, like one from [`Self::bind`].
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub fn from_std(inner: net::TcpListener) -> io::Result<Self> {
        Self::from_std_with_time_getter(inner, listener_now)
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn from_std_with_time_getter(
        inner: net::TcpListener,
        time_getter: fn() -> Time,
    ) -> io::Result<Self> {
        // Ensure accept polling never blocks when callers pass a default
        // blocking std listener.
        inner.set_nonblocking(true)?;
        Ok(Self {
            inner,
            registration: Mutex::new(ReactorRegistration::new()),
            accept_storm: Mutex::new(AcceptStormState::default()),
            accept_waiters: Arc::new(AcceptWaiters::default()),
            time_getter,
        })
    }

    /// Bind to address.
    ///
    /// Refuses with [`IoCapabilityDenied`](crate::cx::IoCapabilityDenied)
    /// when the calling task's `Cx` lacks the IO capability.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(addr: A) -> io::Result<Self> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = addr;
            Err(super::browser_tcp_unsupported("TcpListener::bind"))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::cx::io_gate::require_ambient_io("net::TcpListener::bind")?;
            let addrs = lookup_all(addr).await?;
            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no socket addresses found",
                ));
            }

            let mut last_err = None;
            for addr in addrs {
                match net::TcpListener::bind(addr) {
                    Ok(inner) => {
                        inner.set_nonblocking(true)?;
                        return Self::from_std(inner);
                    }
                    Err(err) => last_err = Some(err),
                }
            }

            Err(last_err.unwrap_or_else(|| io::Error::other("failed to bind any address")))
        }
    }

    /// Accept connection.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.accept_future().await
    }

    fn accept_future(&self) -> AcceptFuture<'_> {
        AcceptFuture {
            listener: self,
            owner: self.accept_waiters.next_owner(),
        }
    }

    /// Polls for an incoming connection using reactor wakeups.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        self.poll_accept_as(cx, None)
    }

    fn poll_accept_as(
        &self,
        cx: &mut Context<'_>,
        owner: Option<u64>,
    ) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        match self.inner.accept() {
            Ok((stream, addr)) => {
                self.reset_accept_storm();
                self.accept_waiters.wake_others(cx.waker());
                Poll::Ready(TcpStream::from_std(stream).map(|stream| (stream, addr)))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.accept_waiters.register(owner, cx.waker());
                let storm_backoff = self.note_accept_would_block();
                let mode = match self.register_interest() {
                    Ok(mode) => mode,
                    Err(err) => {
                        self.accept_waiters.wake_others(cx.waker());
                        return Poll::Ready(Err(err));
                    }
                };

                // Close the re-arm race for readiness backends that can miss a
                // listener wake when a connection lands between the initial
                // `accept()` returning WouldBlock and the fresh poll
                // registration becoming effective. If a client arrived during
                // that window, consume it immediately instead of sleeping until
                // another connection retriggers readiness.
                match self.inner.accept() {
                    Ok((stream, addr)) => {
                        self.reset_accept_storm();
                        self.accept_waiters.wake_others(cx.waker());
                        return Poll::Ready(
                            TcpStream::from_std(stream).map(|stream| (stream, addr)),
                        );
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    Err(err) => {
                        self.accept_waiters.wake_others(cx.waker());
                        return Poll::Ready(Err(err));
                    }
                }

                let delay = if mode == InterestRegistrationMode::FallbackPoll {
                    FALLBACK_ACCEPT_BACKOFF.max(storm_backoff)
                } else if storm_backoff > REARMED_ACCEPT_BACKOFF_BASE {
                    storm_backoff
                } else {
                    Duration::ZERO
                };

                schedule_accept_retry(mode, delay, &self.accept_waiters);
                // ReactorArmed: the reactor is re-armed and will wake us on
                // actual readiness; no sleep needed (unless an accept storm triggered a delay).
                Poll::Pending
            }
            Err(e) => {
                self.accept_waiters.wake_others(cx.waker());
                Poll::Ready(Err(e))
            }
        }
    }

    fn note_accept_would_block(&self) -> Duration {
        let mut state = self.accept_storm.lock();
        let now = (self.time_getter)();

        if let Some(last) = state.last_would_block_at {
            if Duration::from_nanos(now.duration_since(last)) <= ACCEPT_STORM_WINDOW {
                state.consecutive_would_block = state.consecutive_would_block.saturating_add(1);
            } else {
                state.consecutive_would_block = 1;
            }
        } else {
            state.consecutive_would_block = 1;
        }
        state.last_would_block_at = Some(now);

        let exponent = (state.consecutive_would_block.saturating_sub(1) / 64).min(4);
        drop(state);
        let backoff = REARMED_ACCEPT_BACKOFF_BASE.saturating_mul(1u32 << exponent);
        backoff.min(REARMED_ACCEPT_BACKOFF_CAP)
    }

    fn reset_accept_storm(&self) {
        let mut state = self.accept_storm.lock();
        state.consecutive_would_block = 0;
        state.last_would_block_at = None;
    }

    /// Get local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Set TTL.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Incoming connections as stream.
    #[must_use]
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }

    /// Arms accept readiness on the ambient `Cx` driver, else on the
    /// process-global fallback driver (GH#67, asupersync-2rb75p); see
    /// [`ReactorRegistration::arm`]. Only when no reactor can take the fd
    /// does the caller fall back to the timer-clocked accept retry.
    #[cfg(not(target_arch = "wasm32"))]
    fn register_interest(&self) -> io::Result<InterestRegistrationMode> {
        let accept_waker = Waker::from(Arc::clone(&self.accept_waiters));
        let armed = self
            .registration
            .lock()
            .arm(&self.inner, Interest::READABLE, &accept_waker)?;
        Ok(match armed {
            Armed::Parked => InterestRegistrationMode::ReactorArmed,
            Armed::SelfWake => InterestRegistrationMode::FallbackPoll,
        })
    }

    /// The browser target has no reactor: every accept poll is a fallback
    /// retry (and `poll_accept` itself reports the platform as unsupported).
    #[cfg(target_arch = "wasm32")]
    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    fn register_interest(&self) -> io::Result<InterestRegistrationMode> {
        Ok(InterestRegistrationMode::FallbackPoll)
    }
}

fn schedule_accept_retry(
    mode: InterestRegistrationMode,
    delay: Duration,
    accept_waiters: &Arc<AcceptWaiters>,
) {
    if delay == Duration::ZERO {
        return;
    }

    if let Some(timer) = Cx::current().and_then(|current| current.timer_driver()) {
        let deadline = timer.now() + delay;
        let _ = timer.register(deadline, Waker::from(Arc::clone(accept_waiters)));
        return;
    }

    if mode == InterestRegistrationMode::FallbackPoll {
        // `poll_accept` must never block the executor thread. Without a timer
        // driver, fall back to an immediate retry just like the Unix listener.
        accept_waiters.wake_all();
    }
}

/// Stream of incoming connections.
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a TcpListener,
}

impl Stream for Incoming<'_> {
    type Item = io::Result<TcpStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.listener.poll_accept(cx) {
            Poll::Ready(Ok((stream, _addr))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Implement the TcpListenerApi trait for TcpListener
impl TcpListenerApi for TcpListener {
    type Stream = TcpStream;

    fn bind<A: ToSocketAddrs + Send + 'static>(
        addr: A,
    ) -> impl std::future::Future<Output = io::Result<Self>> + Send {
        Self::bind(addr)
    }

    fn accept(
        &self,
    ) -> impl std::future::Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send {
        self.accept_future()
    }

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(Self::Stream, SocketAddr)>> {
        TcpListener::poll_accept(self, cx)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }

    fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        Self::set_ttl(self, ttl)
    }
}

/// Same as [`TcpListener::from_std`].
impl TryFrom<net::TcpListener> for TcpListener {
    type Error = io::Error;

    fn try_from(inner: net::TcpListener) -> io::Result<Self> {
        Self::from_std(inner)
    }
}

/// The raw socket, for socket options this API does not cover. Accepting on
/// it directly bypasses the reactor's readiness tracking.
#[cfg(unix)]
impl std::os::fd::AsRawFd for TcpListener {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.inner)
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for TcpListener {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.inner)
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawSocket for TcpListener {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        std::os::windows::io::AsRawSocket::as_raw_socket(&self.inner)
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for TcpListener {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        std::os::windows::io::AsSocket::as_socket(&self.inner)
    }
}

#[cfg(test)]
#[path = "listener_inline_tests.rs"]
mod tests;
