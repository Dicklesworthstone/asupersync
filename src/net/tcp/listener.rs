//! TCP listener implementation.
//!
//! This module provides a TCP listener for accepting incoming connections.
//! The listener implements [`TcpListenerApi`] for use with generic code and frameworks.

use crate::cx::Cx;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::lookup_all;
use crate::net::tcp::stream::TcpStream;
use crate::net::tcp::traits::TcpListenerApi;
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use crate::stream::Stream;
use crate::types::Time;
use parking_lot::Mutex;
use std::future::poll_fn;
use std::io;
use std::net::{self, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

const FALLBACK_ACCEPT_BACKOFF: Duration = Duration::from_millis(4);
const REARMED_ACCEPT_BACKOFF_BASE: Duration = Duration::from_millis(2);
const REARMED_ACCEPT_BACKOFF_CAP: Duration = Duration::from_millis(32);
const ACCEPT_STORM_WINDOW: Duration = Duration::from_millis(50);

fn listener_now() -> Time {
    Cx::current()
        .and_then(|current| current.timer_driver())
        .map_or_else(crate::time::wall_now, |driver| driver.now())
}

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

/// A TCP listener.
#[derive(Debug)]
pub struct TcpListener {
    registration: Mutex<Option<IoRegistration>>,
    pub(crate) inner: net::TcpListener,
    accept_storm: Mutex<AcceptStormState>,
    accept_waiters: Arc<AcceptWaiters>,
    time_getter: fn() -> Time,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterestRegistrationMode {
    ReactorArmed,
    FallbackPoll,
}

#[derive(Debug, Default)]
struct AcceptStormState {
    consecutive_would_block: u32,
    last_would_block_at: Option<Time>,
}

impl TcpListener {
    pub(crate) fn from_std(inner: net::TcpListener) -> io::Result<Self> {
        Self::from_std_with_time_getter(inner, listener_now)
    }

    pub(crate) fn from_std_with_time_getter(
        inner: net::TcpListener,
        time_getter: fn() -> Time,
    ) -> io::Result<Self> {
        // Ensure accept polling never blocks when callers pass a default
        // blocking std listener.
        inner.set_nonblocking(true)?;
        Ok(Self {
            inner,
            registration: Mutex::new(None),
            accept_storm: Mutex::new(AcceptStormState::default()),
            accept_waiters: Arc::new(AcceptWaiters::default()),
            time_getter,
        })
    }

    /// Bind to address.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(addr: A) -> io::Result<Self> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = addr;
            Err(super::browser_tcp_unsupported("TcpListener::bind"))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
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
        poll_fn(|cx| self.poll_accept(cx)).await
    }

    /// Polls for an incoming connection using reactor wakeups.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        match self.inner.accept() {
            Ok((stream, addr)) => {
                self.reset_accept_storm();
                self.accept_waiters.wake_others(cx.waker());
                Poll::Ready(TcpStream::from_std(stream).map(|stream| (stream, addr)))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.accept_waiters.register(cx.waker());
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

    fn register_interest(&self) -> io::Result<InterestRegistrationMode> {
        enum RearmDecision {
            ReactorArmed,
            ClearAndContinue,
            ClearAndFallback,
            Error(io::Error),
        }

        let mut registration = self.registration.lock();
        let accept_waker = Waker::from(Arc::clone(&self.accept_waiters));
        let decision = registration.as_mut().map(|existing| {
            // Re-arm reactor interest and conditionally update the waker in a
            // single lock acquisition (will_wake guard skips the clone).
            match existing.rearm(Interest::READABLE, &accept_waker) {
                Ok(true) => RearmDecision::ReactorArmed,
                Ok(false) => RearmDecision::ClearAndContinue,
                Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                    RearmDecision::ClearAndFallback
                }
                Err(err) => RearmDecision::Error(err),
            }
        });

        match decision {
            Some(RearmDecision::ReactorArmed) => {
                return Ok(InterestRegistrationMode::ReactorArmed);
            }
            Some(RearmDecision::ClearAndContinue) => {
                *registration = None;
            }
            Some(RearmDecision::ClearAndFallback) => {
                *registration = None;
                return Ok(InterestRegistrationMode::FallbackPoll);
            }
            Some(RearmDecision::Error(err)) => return Err(err),
            None => {}
        }

        let Some(current) = Cx::current() else {
            return Ok(InterestRegistrationMode::FallbackPoll);
        };
        let Some(driver) = current.io_driver_handle() else {
            return Ok(InterestRegistrationMode::FallbackPoll);
        };

        match driver.register(&self.inner, Interest::READABLE, accept_waker) {
            Ok(new_reg) => {
                *registration = Some(new_reg);
                drop(registration);
                Ok(InterestRegistrationMode::ReactorArmed)
            }
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                Ok(InterestRegistrationMode::FallbackPoll)
            }
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                Ok(InterestRegistrationMode::FallbackPoll)
            }
            Err(err) => Err(err),
        }
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
        std::future::poll_fn(|cx| self.poll_accept(cx))
    }

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(Self::Stream, SocketAddr)>> {
        self.poll_accept(cx)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }

    fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        Self::set_ttl(self, ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::reactor::{Events, Reactor, Source, Token};
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId};
    #[cfg(unix)]
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use std::cell::Cell;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};
    use std::time::Instant;

    thread_local! {
        static TEST_NOW_NANOS: Cell<u64> = const { Cell::new(0) };
    }

    #[test]
    fn test_bind() {
        // We can't await in a sync test without a runtime, but we can check if bind returns a future.
        // Or we can use `futures_lite::future::block_on`.

        futures_lite::future::block_on(async {
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = TcpListener::bind(addr).await.expect("bind failed");
            assert!(listener.local_addr().is_ok());
        });
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn set_test_time(nanos: u64) {
        TEST_NOW_NANOS.with(|t| t.set(nanos));
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW_NANOS.with(std::cell::Cell::get))
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
    fn listener_registers_on_wouldblock() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        raw.set_nonblocking(true).expect("nonblocking");

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

        let listener = TcpListener::from_std(raw).expect("wrap listener");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = listener.poll_accept(&mut cx);
        assert!(matches!(poll, Poll::Pending));
        let registered = listener.registration.lock().is_some();
        assert!(registered);
    }

    struct HookReactor {
        on_register: Arc<dyn Fn() + Send + Sync>,
        registrations: AtomicUsize,
    }

    impl std::fmt::Debug for HookReactor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HookReactor")
                .field("registrations", &self.registrations.load(Ordering::SeqCst))
                .finish_non_exhaustive()
        }
    }

    impl Reactor for HookReactor {
        fn register(
            &self,
            _source: &dyn Source,
            _token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            self.registrations.fetch_add(1, Ordering::SeqCst);
            (self.on_register)();
            Ok(())
        }

        fn modify(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }

        fn deregister(&self, _token: Token) -> io::Result<()> {
            self.registrations
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    current.checked_sub(1)
                })
                .ok();
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
            self.registrations.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn listener_accepts_connection_that_arrives_during_register_window() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = raw.local_addr().expect("local addr");
        raw.set_nonblocking(true).expect("nonblocking");

        let listener = TcpListener::from_std(raw).expect("wrap listener");
        let reactor = Arc::new(HookReactor {
            on_register: Arc::new(move || {
                let _client = net::TcpStream::connect(addr).expect("client connect");
            }),
            registrations: AtomicUsize::new(0),
        });
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

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = listener.poll_accept(&mut cx);
        let Poll::Ready(Ok((_stream, peer_addr))) = poll else {
            panic!("post-register accept recheck should catch the queued connection");
        };

        assert_eq!(peer_addr.ip(), std::net::Ipv4Addr::LOCALHOST);
    }

    #[cfg(unix)]
    #[test]
    fn listener_from_std_forces_nonblocking_mode() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let listener = TcpListener::from_std(raw).expect("wrap listener");
        let flags = fcntl(&listener.inner, FcntlArg::F_GETFL).expect("read listener flags");
        let is_nonblocking = OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK);
        assert!(
            is_nonblocking,
            "TcpListener::from_std should force nonblocking mode"
        );
    }

    #[test]
    fn fallback_accept_retry_without_timer_wakes_immediately() {
        assert!(
            Cx::current().is_none(),
            "test must run without an active Cx"
        );

        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        let waiters = Arc::new(AcceptWaiters::default());
        waiters.register(&waker);
        let started = Instant::now();

        schedule_accept_retry(
            InterestRegistrationMode::FallbackPoll,
            Duration::from_millis(20),
            &waiters,
        );

        assert!(
            started.elapsed() < Duration::from_millis(10),
            "fallback accept retry must not sleep inline when no timer driver exists"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "fallback accept retry should self-wake when no timer driver exists"
        );
    }

    #[test]
    fn reactor_armed_accept_retry_without_timer_does_not_self_wake() {
        assert!(
            Cx::current().is_none(),
            "test must run without an active Cx"
        );

        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        let waiters = Arc::new(AcceptWaiters::default());
        waiters.register(&waker);
        let started = Instant::now();

        schedule_accept_retry(
            InterestRegistrationMode::ReactorArmed,
            Duration::from_millis(20),
            &waiters,
        );

        assert!(
            started.elapsed() < Duration::from_millis(10),
            "reactor-armed accept retry must not sleep inline when no timer driver exists"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "reactor-armed accept retry should rely on the reactor instead of self-waking"
        );
    }

    #[test]
    fn listener_fanout_wakes_all_pending_accept_waiters() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        raw.set_nonblocking(true).expect("nonblocking");

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

        let listener = TcpListener::from_std(raw).expect("wrap listener");
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

        listener.accept_waiters.wake_all();

        assert_eq!(hits1.load(Ordering::SeqCst), 1);
        assert_eq!(hits2.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn accept_storm_window_respects_custom_time_getter() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        set_test_time(0);
        let listener = TcpListener::from_std_with_time_getter(raw, test_time).expect("wrap");

        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            1,
            "first would-block should start the storm counter"
        );

        set_test_time(
            Duration::from_millis(5)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            2,
            "within-window would-block should increment the storm counter"
        );

        set_test_time(
            Duration::from_millis(60)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            1,
            "outside-window would-block should reset the storm counter"
        );
    }

    #[test]
    fn accept_storm_window_from_std_uses_runtime_timer_driver() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let clock = Arc::new(crate::time::VirtualClock::new());
        let timer = crate::time::TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer),
            None,
        );
        let _guard = Cx::set_current(Some(cx));
        let listener = TcpListener::from_std(raw).expect("wrap");

        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );

        clock.advance(
            Duration::from_millis(5)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            2,
            "from_std should use Cx timer-driver time when available"
        );

        clock.advance(
            Duration::from_millis(60)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            1,
            "from_std should reset outside the storm window using runtime time"
        );
    }

    #[test]
    fn accept_storm_backoff_escalates_without_sleep() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        set_test_time(0);
        let listener = TcpListener::from_std_with_time_getter(raw, test_time).expect("wrap");

        let mut backoff = Duration::ZERO;
        for idx in 0..65 {
            set_test_time(
                Duration::from_millis(idx)
                    .as_nanos()
                    .min(u128::from(u64::MAX)) as u64,
            );
            backoff = listener.note_accept_would_block();
        }

        assert_eq!(
            backoff,
            REARMED_ACCEPT_BACKOFF_BASE.saturating_mul(2),
            "65 consecutive would-blocks inside the storm window should double the backoff"
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            65,
            "storm counter should track the deterministic sequence length"
        );
    }
}
