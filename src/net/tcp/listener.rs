//! TCP listener implementation.
//!
//! This module provides a TCP listener for accepting incoming connections.
//! The listener implements [`TcpListenerApi`] for use with generic code and frameworks.

use crate::cx::Cx;
use crate::net::lookup_all;
use crate::net::tcp::stream::TcpStream;
use crate::net::tcp::traits::TcpListenerApi;
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use crate::stream::Stream;
use parking_lot::Mutex;
use std::future::poll_fn;
use std::io;
use std::net::{self, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const FALLBACK_ACCEPT_BACKOFF: Duration = Duration::from_millis(4);
const REARMED_ACCEPT_BACKOFF_BASE: Duration = Duration::from_millis(2);
const REARMED_ACCEPT_BACKOFF_CAP: Duration = Duration::from_millis(32);
const ACCEPT_STORM_WINDOW: Duration = Duration::from_millis(25);

/// A TCP listener.
#[derive(Debug)]
pub struct TcpListener {
    pub(crate) inner: net::TcpListener,
    registration: Mutex<Option<IoRegistration>>,
    accept_storm: Mutex<AcceptStormState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterestRegistrationMode {
    ReactorArmed,
    FallbackPoll,
}

#[derive(Debug, Default)]
struct AcceptStormState {
    consecutive_would_block: u32,
    last_would_block_at: Option<Instant>,
}

impl TcpListener {
    pub(crate) fn from_std(inner: net::TcpListener) -> io::Result<Self> {
        // Ensure accept polling never blocks when callers pass a default
        // blocking std listener.
        inner.set_nonblocking(true)?;
        Ok(Self {
            inner,
            registration: Mutex::new(None),
            accept_storm: Mutex::new(AcceptStormState::default()),
        })
    }

    /// Bind to address.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(addr: A) -> io::Result<Self> {
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

    /// Accept connection.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }

    /// Polls for an incoming connection using reactor wakeups.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        match self.inner.accept() {
            Ok((stream, addr)) => {
                self.reset_accept_storm();
                Poll::Ready(TcpStream::from_std(stream).map(|stream| (stream, addr)))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.note_accept_would_block();
                let mode = match self.register_interest(cx) {
                    Ok(mode) => mode,
                    Err(err) => return Poll::Ready(Err(err)),
                };
                if mode == InterestRegistrationMode::FallbackPoll {
                    // No reactor-backed readiness available for this task context.
                    // Schedule a delayed wakeup on a background thread to avoid
                    // blocking the runtime worker.
                    let waker = cx.waker().clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(FALLBACK_ACCEPT_BACKOFF);
                        waker.wake();
                    });
                }
                // ReactorArmed: the reactor is re-armed and will wake us on
                // actual readiness; no sleep needed.
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn note_accept_would_block(&self) -> Duration {
        let mut state = self.accept_storm.lock();
        let now = Instant::now();

        if let Some(last) = state.last_would_block_at {
            if now.saturating_duration_since(last) <= ACCEPT_STORM_WINDOW {
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

    fn register_interest(&self, cx: &Context<'_>) -> io::Result<InterestRegistrationMode> {
        let rearm_result = {
            enum RearmDecision {
                ReactorArmed,
                ClearAndContinue,
                ClearAndFallback,
                Error(io::Error),
            }

            let mut registration = self.registration.lock();
            let decision = registration.as_mut().map(|existing| {
                // Re-arm reactor interest and conditionally update the waker in a
                // single lock acquisition (will_wake guard skips the clone).
                match existing.rearm(Interest::READABLE, cx.waker()) {
                    Ok(true) => RearmDecision::ReactorArmed,
                    Ok(false) => RearmDecision::ClearAndContinue,
                    Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                        RearmDecision::ClearAndFallback
                    }
                    Err(err) => RearmDecision::Error(err),
                }
            });

            let result = match decision {
                Some(RearmDecision::ReactorArmed) => {
                    Some(Ok(InterestRegistrationMode::ReactorArmed))
                }
                Some(RearmDecision::ClearAndContinue) => {
                    *registration = None;
                    None
                }
                Some(RearmDecision::ClearAndFallback) => {
                    *registration = None;
                    Some(Ok(InterestRegistrationMode::FallbackPoll))
                }
                Some(RearmDecision::Error(err)) => Some(Err(err)),
                None => None,
            };
            drop(registration);
            result
        };

        if let Some(result) = rearm_result {
            return result;
        }

        let Some(current) = Cx::current() else {
            return Ok(InterestRegistrationMode::FallbackPoll);
        };
        let Some(driver) = current.io_driver_handle() else {
            return Ok(InterestRegistrationMode::FallbackPoll);
        };

        match driver.register(&self.inner, Interest::READABLE, cx.waker().clone()) {
            Ok(new_reg) => {
                let mut registration = self.registration.lock();
                *registration = Some(new_reg);
                drop(registration);
                Ok(InterestRegistrationMode::ReactorArmed)
            }
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                Ok(InterestRegistrationMode::FallbackPoll)
            }
            Err(err) => Err(err),
        }
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
        // Use poll_fn which is Send since TcpListener is not Send due to Mutex
        // We need to wrap in an async block that captures self
        let accept_fn = move || poll_fn(|cx| self.poll_accept(cx));
        async move { accept_fn().await }
    }

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(Self::Stream, SocketAddr)>> {
        Self::poll_accept(self, cx)
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
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId};
    #[cfg(unix)]
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::task::{Context, Wake, Waker};

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
}
