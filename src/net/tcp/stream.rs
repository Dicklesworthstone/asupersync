//! TCP stream implementation.
//!
//! This module provides a TCP stream for reading and writing data over a connection.
//! The stream implements [`TcpStreamApi`] for use with generic code and frameworks.

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncReadVectored, AsyncWrite, ReadBuf};
#[cfg(not(target_arch = "wasm32"))]
use crate::net::lookup_all;
use crate::net::tcp::split::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf};
use crate::net::tcp::traits::TcpStreamApi;
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
#[cfg(not(target_arch = "wasm32"))]
use crate::time::TimeoutFuture;
use crate::types::Time;
#[cfg(not(target_arch = "wasm32"))]
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
#[cfg(not(target_arch = "wasm32"))]
use std::future::Future;
use std::io::{self, IoSlice, IoSliceMut};
use std::net::{self, Shutdown, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

const FALLBACK_IO_BACKOFF: Duration = Duration::from_millis(1);

#[cfg(target_arch = "wasm32")]
#[inline]
fn browser_tcp_unsupported_result<T>(op: &str) -> io::Result<T> {
    Err(super::browser_tcp_unsupported(op))
}

#[cfg(target_arch = "wasm32")]
#[inline]
fn browser_tcp_poll_unsupported<T>(op: &str) -> Poll<io::Result<T>> {
    Poll::Ready(Err(super::browser_tcp_unsupported(op)))
}

/// A TCP stream.
#[derive(Debug)]
pub struct TcpStream {
    registration: Option<IoRegistration>,
    inner: Arc<net::TcpStream>,
    shutdown_on_drop: bool,
}

/// Configuration for TCP Keepalive behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeepaliveConfig {
    /// Keepalive behavior is not explicitly configured, deferring to OS defaults.
    #[default]
    Default,
    /// Explicitly disable TCP keepalive.
    Disabled,
    /// Explicitly enable TCP keepalive with the given duration.
    Enabled(Duration),
}

/// Builder for configuring TCP stream options before connecting.
///
/// This mirrors [`TcpListenerBuilder`](super::traits::TcpListenerBuilder) for client connections.
/// Options are applied after a successful connect.
#[derive(Debug, Clone)]
pub struct TcpStreamBuilder<A> {
    addr: A,
    connect_timeout: Option<Duration>,
    nodelay: Option<bool>,
    keepalive: KeepaliveConfig,
}

impl<A> TcpStreamBuilder<A>
where
    A: ToSocketAddrs + Send + 'static,
{
    /// Create a new builder for the given address.
    #[must_use]
    pub fn new(addr: A) -> Self {
        Self {
            addr,
            connect_timeout: None,
            nodelay: None,
            keepalive: KeepaliveConfig::Default,
        }
    }

    /// Set a connection timeout.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Enable or disable TCP_NODELAY.
    #[must_use]
    pub fn nodelay(mut self, enable: bool) -> Self {
        self.nodelay = Some(enable);
        self
    }

    /// Configure TCP keepalive.
    ///
    /// Note: Phase 0 does not support keepalive on all platforms; enabling
    /// this may return `io::ErrorKind::Unsupported`.
    #[must_use]
    pub fn keepalive(mut self, keepalive: Option<Duration>) -> Self {
        self.keepalive = keepalive.map_or(KeepaliveConfig::Disabled, KeepaliveConfig::Enabled);
        self
    }

    /// Connect using the configured options.
    pub async fn connect(self) -> io::Result<TcpStream> {
        let Self {
            addr,
            connect_timeout,
            nodelay,
            keepalive,
        } = self;

        let stream = if let Some(timeout) = connect_timeout {
            TcpStream::connect_timeout(addr, timeout).await?
        } else {
            TcpStream::connect(addr).await?
        };

        if let Some(enable) = nodelay {
            stream.set_nodelay(enable)?;
        }

        match keepalive {
            KeepaliveConfig::Enabled(duration) => stream.set_keepalive(Some(duration))?,
            KeepaliveConfig::Disabled => stream.set_keepalive(None)?,
            KeepaliveConfig::Default => {} // Do nothing, let OS decide
        }

        Ok(stream)
    }
}

impl TcpStream {
    /// Create a TcpStream from a standard library TcpStream.
    ///
    /// This is used for testing to wrap a synchronous stream into an async one.
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) fn from_std(stream: net::TcpStream) -> io::Result<Self> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = stream;
            return browser_tcp_unsupported_result("TcpStream::from_std");
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            // Ensure async poll paths do not inherit blocking sockets.
            stream.set_nonblocking(true)?;
            Ok(Self {
                inner: Arc::new(stream),
                registration: None,
                shutdown_on_drop: true,
            })
        }
    }

    /// Reconstruct a TcpStream from its parts (used by reunite).
    pub(crate) fn from_parts(
        inner: Arc<net::TcpStream>,
        registration: Option<IoRegistration>,
    ) -> Self {
        Self {
            inner,
            registration,
            shutdown_on_drop: true,
        }
    }

    /// Connect to address.
    pub async fn connect<A: ToSocketAddrs + Send + 'static>(addr: A) -> io::Result<Self> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = addr;
            Err(super::browser_tcp_unsupported("TcpStream::connect"))
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
                let domain = if addr.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                };

                let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
                    Ok(s) => s,
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                };

                match Self::connect_from_socket(socket, addr).await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => {
                        last_err = Some(e);
                    }
                }
            }

            Err(last_err.unwrap_or_else(|| io::Error::other("failed to connect to any address")))
        }
    }

    /// Connect directly to a concrete socket address without DNS resolution.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn connect_socket_addr(addr: SocketAddr) -> io::Result<Self> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        Self::connect_from_socket(socket, addr).await
    }

    /// Connect directly to a concrete socket address without DNS resolution.
    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn connect_socket_addr(_addr: SocketAddr) -> io::Result<Self> {
        Err(super::browser_tcp_unsupported(
            "TcpStream::connect_socket_addr",
        ))
    }

    /// Connects using an existing configured socket.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn connect_from_socket(socket: Socket, addr: SocketAddr) -> io::Result<Self> {
        socket.set_nonblocking(true)?;

        // 2. Attempt connect (non-blocking)
        let sock_addr = SockAddr::from(addr);
        let registration = match socket.connect(&sock_addr) {
            Ok(()) => None,
            Err(err) if connect_in_progress(&err) => wait_for_connect(&socket).await?,
            Err(err) => return Err(err),
        };

        // socket.into() preserves the nonblocking flag set above; no need to set again.
        let stream: net::TcpStream = socket.into();
        Ok(Self::from_parts(Arc::new(stream), registration))
    }

    /// Connect with timeout.
    pub async fn connect_timeout<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        timeout_duration: Duration,
    ) -> io::Result<Self> {
        Self::connect_timeout_with_time_getter(addr, timeout_duration, timeout_now).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn connect_timeout_with_time_getter<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        timeout_duration: Duration,
        time_getter: fn() -> Time,
    ) -> io::Result<Self> {
        let addrs = lookup_all(addr).await?;
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no socket addresses found",
            ));
        }

        let deadline = time_getter() + timeout_duration;
        let mut last_err = None;

        for addr in addrs {
            let now = time_getter();
            if now >= deadline {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tcp connect timeout",
                ));
                break;
            }
            let remaining = std::time::Duration::from_nanos(deadline.duration_since(now));

            let domain = if addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };

            let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let connect_future = Box::pin(Self::connect_from_socket(socket, addr));
            match future_with_timeout(connect_future, remaining, time_getter).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(err)) => last_err = Some(err),
                Err(_) => {
                    last_err = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "tcp connect timeout",
                    ));
                    break; // Timed out waiting, so no time left for subsequent attempts
                }
            }
        }

        Err(last_err.unwrap_or_else(|| io::Error::other("failed to connect to any address")))
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn connect_timeout_with_time_getter<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        timeout_duration: Duration,
        _time_getter: fn() -> Time,
    ) -> io::Result<Self> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = timeout_duration;
            Self::connect(addr).await
        }
    }

    /// Get peer address.
    #[inline]
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        #[cfg(target_arch = "wasm32")]
        {
            return browser_tcp_unsupported_result("TcpStream::peer_addr");
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.peer_addr()
    }

    /// Get local address.
    #[inline]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        #[cfg(target_arch = "wasm32")]
        {
            return browser_tcp_unsupported_result("TcpStream::local_addr");
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.local_addr()
    }

    /// Shutdown.
    #[inline]
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = how;
            return browser_tcp_unsupported_result("TcpStream::shutdown");
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.shutdown(how)
    }

    /// Set TCP_NODELAY.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = nodelay;
            return browser_tcp_unsupported_result("TcpStream::set_nodelay");
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.set_nodelay(nodelay)
    }

    /// Set keepalive.
    ///
    /// Uses `socket2` to configure `SO_KEEPALIVE` and platform-specific
    /// keepalive idle time. Pass `None` to disable keepalive.
    pub fn set_keepalive(&self, keepalive: Option<Duration>) -> io::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = keepalive;
            Err(super::browser_tcp_unsupported("TcpStream::set_keepalive"))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let socket = socket2::SockRef::from(&*self.inner);
            match keepalive {
                Some(interval) => {
                    let params = socket2::TcpKeepalive::new().with_time(interval);
                    socket.set_tcp_keepalive(&params)?;
                }
                None => {
                    socket.set_keepalive(false)?;
                }
            }
            Ok(())
        }
    }

    /// Split into borrowed halves.
    #[must_use]
    pub fn split(&self) -> (ReadHalf<'_>, WriteHalf<'_>) {
        #[cfg(target_arch = "wasm32")]
        {
            (ReadHalf::unsupported(), WriteHalf::unsupported())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            (ReadHalf::new(&self.inner), WriteHalf::new(&self.inner))
        }
    }

    /// Split into owned halves.
    ///
    /// The owned halves share the reactor registration, allowing proper
    /// async I/O with wakeup notifications. Use [`reunite`] to reconstruct
    /// the original stream.
    ///
    /// [`reunite`]: OwnedReadHalf::reunite
    #[must_use]
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = self;
            OwnedReadHalf::unsupported_pair()
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut this = self;
            this.shutdown_on_drop = false;
            let registration = this.registration.take();
            let inner = this.inner.clone();
            OwnedReadHalf::new_pair(inner, registration)
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[inline]
    fn register_interest(&self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        let _ = (cx, interest);
        browser_tcp_unsupported_result("TcpStream::register_interest")
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[inline]
    fn register_interest(&mut self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        // A plain `TcpStream` has a single waiter. Re-arm only the caller's
        // current interest instead of sticky-unioning historical bits, which
        // otherwise keeps stale WRITABLE polls alive during later read waits.
        let target_interest = interest;
        if let Some(registration) = &mut self.registration {
            // Re-arm reactor interest and conditionally update the waker in a
            // single lock acquisition.  The waker clone is skipped when the
            // task's waker hasn't changed (will_wake guard).
            match registration.rearm(target_interest, cx.waker()) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    // Slab slot gone — fall through to fresh registration.
                    self.registration = None;
                }
                Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                    self.registration = None;
                    fallback_rewake(cx);
                    return Ok(());
                }
                Err(err) => return Err(err),
            }
        }

        let Some(current) = Cx::current() else {
            fallback_rewake(cx);
            return Ok(());
        };
        let Some(driver) = current.io_driver_handle() else {
            fallback_rewake(cx);
            return Ok(());
        };

        match driver.register(&*self.inner, target_interest, cx.waker().clone()) {
            Ok(registration) => {
                self.registration = Some(registration);
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                fallback_rewake(cx);
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                fallback_rewake(cx);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

#[inline]
pub(crate) fn fallback_rewake(cx: &Context<'_>) {
    if let Some(timer) = Cx::current().and_then(|c| c.timer_driver()) {
        let deadline = timer.now() + FALLBACK_IO_BACKOFF;
        let _ = timer.register(deadline, cx.waker().clone());
    } else {
        // `poll_read`/`poll_write` must never block the executor thread.
        // Mirror the Unix stream fallback and request an immediate retry when
        // no timer driver is available.
        cx.waker().wake_by_ref();
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn timeout_now() -> Time {
    timeout_now_with_fallback(crate::time::wall_now)
}

#[cfg(target_arch = "wasm32")]
fn timeout_now() -> Time {
    crate::time::wall_now()
}

#[cfg(not(target_arch = "wasm32"))]
fn timeout_now_with_fallback(fallback_now: fn() -> Time) -> Time {
    Cx::current()
        .and_then(|current| current.timer_driver())
        // Outside an active runtime context we still want timeouts to behave
        // correctly using wall time. Using `Time::ZERO` here is subtly wrong
        // because `Sleep`'s fallback clock is `wall_now()` (module-relative),
        // so a zero "now" can cause premature timeouts if `wall_now()` has
        // already advanced due to prior time ops in the same process.
        .map_or_else(fallback_now, |driver| driver.now())
}

#[cfg(not(target_arch = "wasm32"))]
fn duration_to_nanos_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(not(target_arch = "wasm32"))]
async fn future_with_timeout<F>(
    future: F,
    timeout_duration: Duration,
    time_getter: fn() -> Time,
) -> Result<F::Output, crate::time::Elapsed>
where
    F: Future + Unpin,
{
    let deadline =
        time_getter().saturating_add_nanos(duration_to_nanos_saturating(timeout_duration));
    TimeoutFuture::with_time_getter(future, deadline, time_getter).await
}

#[cfg(not(target_arch = "wasm32"))]
fn connect_in_progress(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) || err.raw_os_error() == Some(libc::EINPROGRESS)
}

#[cfg(not(target_arch = "wasm32"))]
async fn wait_for_connect(socket: &Socket) -> io::Result<Option<IoRegistration>> {
    let Some(driver) = Cx::current().and_then(|cx| cx.io_driver_handle()) else {
        wait_for_connect_fallback(socket).await?;
        return Ok(None);
    };

    let mut registration: Option<IoRegistration> = None;
    let mut fallback = false;
    std::future::poll_fn(|cx| {
        if let Some(err) = socket.take_error()? {
            return Poll::Ready(Err(err));
        }

        match socket.peer_addr() {
            Ok(_) => Poll::Ready(Ok(())),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                if let Err(err) = rearm_connect_registration(&mut registration, cx) {
                    return Poll::Ready(Err(err));
                }

                if registration.is_none() {
                    match driver.register(socket, Interest::WRITABLE, cx.waker().clone()) {
                        Ok(new_reg) => registration = Some(new_reg),
                        Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                            fallback = true;
                            return Poll::Ready(Ok(()));
                        }
                        Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                            fallback = true;
                            return Poll::Ready(Ok(()));
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    }
                }

                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    })
    .await?;

    if fallback {
        wait_for_connect_fallback(socket).await?;
        return Ok(None);
    }

    Ok(registration)
}

/// Re-arm a pending connect registration that uses oneshot reactor semantics.
///
/// The polling backend disarms registrations after each readiness event. Even
/// when the interest flags are unchanged (`WRITABLE` during connect), we must
/// call `set_interest` again to ensure subsequent connect progress events are
/// delivered.
#[cfg(not(target_arch = "wasm32"))]
fn rearm_connect_registration(
    registration: &mut Option<IoRegistration>,
    cx: &Context<'_>,
) -> io::Result<()> {
    let Some(existing) = registration.as_mut() else {
        return Ok(());
    };

    match existing.rearm(Interest::WRITABLE, cx.waker()) {
        Ok(true) => Ok(()),
        Ok(false) => {
            *registration = None;
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotConnected => {
            *registration = None;
            fallback_rewake(cx);
            Ok(())
        }
        Err(err) => Err(err),
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn wait_for_connect_fallback(socket: &Socket) -> io::Result<()> {
    loop {
        if let Some(err) = socket.take_error()? {
            return Err(err);
        }

        match socket.peer_addr() {
            Ok(_) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                // Sleep briefly to avoid busy loop when no reactor is available.
                let now = Cx::current().map_or_else(crate::time::wall_now, |c| {
                    c.timer_driver()
                        .map_or_else(crate::time::wall_now, |d| d.now())
                });
                crate::time::sleep(now, Duration::from_millis(1)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncRead for TcpStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use std::io::Read;
        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        // std::net::TcpStream implements Read for &TcpStream
        match (&*inner).read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncRead for TcpStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _ = (self, cx, buf);
        browser_tcp_poll_unsupported("TcpStream::poll_read")
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncReadVectored for TcpStream {
    #[inline]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        use std::io::Read;

        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        match (&*inner).read_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncReadVectored for TcpStream {
    #[inline]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let _ = (self, cx, bufs);
        browser_tcp_poll_unsupported("TcpStream::poll_read_vectored")
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncWrite for TcpStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use std::io::Write;
        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        match (&*inner).write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        use std::io::Write;

        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        match (&*inner).write_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::io::Write;
        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        match (&*inner).flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.shutdown(Shutdown::Write) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncWrite for TcpStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let _ = (self, cx, buf);
        browser_tcp_poll_unsupported("TcpStream::poll_write")
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let _ = (self, cx, bufs);
        browser_tcp_poll_unsupported("TcpStream::poll_write_vectored")
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        false
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = (self, cx);
        browser_tcp_poll_unsupported("TcpStream::poll_flush")
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = (self, cx);
        browser_tcp_poll_unsupported("TcpStream::poll_shutdown")
    }
}

// ubs:ignore — TcpStream performs a best-effort shutdown on drop for deterministic teardown.
// into_split() disables shutdown_on_drop to avoid closing the shared stream; callers should
// still prefer explicit shutdown() for protocol-aware half-close behavior.

impl Drop for TcpStream {
    fn drop(&mut self) {
        #[cfg(not(target_arch = "wasm32"))]
        if self.shutdown_on_drop {
            let _ = self.inner.shutdown(Shutdown::Both);
        }
    }
}

// Implement the TcpStreamApi trait for TcpStream
impl TcpStreamApi for TcpStream {
    fn connect<A: ToSocketAddrs + Send + 'static>(
        addr: A,
    ) -> impl std::future::Future<Output = io::Result<Self>> + Send {
        Self::connect(addr)
    }

    #[inline]
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Self::peer_addr(self)
    }

    #[inline]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }

    #[inline]
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        Self::shutdown(self, how)
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        Self::set_nodelay(self, nodelay)
    }

    fn nodelay(&self) -> io::Result<bool> {
        #[cfg(target_arch = "wasm32")]
        {
            return browser_tcp_unsupported_result("TcpStream::nodelay");
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.nodelay()
    }

    fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = ttl;
            return browser_tcp_unsupported_result("TcpStream::set_ttl");
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.set_ttl(ttl)
    }

    fn ttl(&self) -> io::Result<u32> {
        #[cfg(target_arch = "wasm32")]
        {
            return browser_tcp_unsupported_result("TcpStream::ttl");
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.ttl()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::reactor::{Events, Reactor, Token};
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId, Time};
    use futures_lite::future;
    #[cfg(unix)]
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use std::future::Future;
    use std::future::poll_fn;
    use std::io;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
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

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    struct CountingReactor {
        inner: LabReactor,
        modify_calls: AtomicUsize,
        last_interest_bits: AtomicUsize,
    }

    impl CountingReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: LabReactor::new(),
                modify_calls: AtomicUsize::new(0),
                last_interest_bits: AtomicUsize::new(Interest::empty().bits() as usize),
            })
        }

        fn modify_calls(&self) -> usize {
            self.modify_calls.load(Ordering::SeqCst)
        }

        fn last_interest(&self) -> Interest {
            Interest::from_bits(self.last_interest_bits.load(Ordering::SeqCst) as u8)
        }
    }

    impl Reactor for CountingReactor {
        fn register(
            &self,
            source: &dyn crate::runtime::reactor::Source,
            token: Token,
            interest: Interest,
        ) -> io::Result<()> {
            self.last_interest_bits
                .store(interest.bits() as usize, Ordering::SeqCst);
            self.inner.register(source, token, interest)
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            self.modify_calls.fetch_add(1, Ordering::SeqCst);
            self.last_interest_bits
                .store(interest.bits() as usize, Ordering::SeqCst);
            self.inner.modify(token, interest)
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            self.inner.deregister(token)
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            self.inner.poll(events, timeout)
        }

        fn wake(&self) -> io::Result<()> {
            self.inner.wake()
        }

        fn registration_count(&self) -> usize {
            self.inner.registration_count()
        }
    }

    struct RegisterNotConnectedReactor {
        inner: LabReactor,
    }

    impl RegisterNotConnectedReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: LabReactor::new(),
            })
        }
    }

    impl Reactor for RegisterNotConnectedReactor {
        fn register(
            &self,
            _source: &dyn crate::runtime::reactor::Source,
            _token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "injected not connected register failure",
            ))
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            self.inner.modify(token, interest)
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            self.inner.deregister(token)
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            self.inner.poll(events, timeout)
        }

        fn wake(&self) -> io::Result<()> {
            self.inner.wake()
        }

        fn registration_count(&self) -> usize {
            self.inner.registration_count()
        }
    }

    #[test]
    fn tcp_stream_builder_defaults() {
        let builder = TcpStreamBuilder::new("127.0.0.1:0");
        assert!(builder.connect_timeout.is_none());
        assert!(builder.nodelay.is_none());
        assert_eq!(builder.keepalive, KeepaliveConfig::Default);
    }

    #[test]
    fn tcp_stream_builder_chain() {
        let builder = TcpStreamBuilder::new("127.0.0.1:0")
            .connect_timeout(Duration::from_secs(1))
            .nodelay(true)
            .keepalive(Some(Duration::from_secs(30)));

        assert_eq!(builder.connect_timeout, Some(Duration::from_secs(1)));
        assert_eq!(builder.nodelay, Some(true));
        assert_eq!(
            builder.keepalive,
            KeepaliveConfig::Enabled(Duration::from_secs(30))
        );
    }

    #[test]
    fn timeout_now_uses_injected_fallback_when_no_runtime_is_active() {
        static FALLBACK_NOW: AtomicU64 = AtomicU64::new(0);

        fn deterministic_now() -> Time {
            Time::from_nanos(FALLBACK_NOW.load(Ordering::SeqCst))
        }

        assert!(
            Cx::current().is_none(),
            "test must run without an active Cx"
        );

        FALLBACK_NOW.store(123_456, Ordering::SeqCst);
        assert_eq!(
            super::timeout_now_with_fallback(deterministic_now),
            Time::from_nanos(123_456),
            "no-runtime timeout path should delegate to injected fallback clock"
        );

        FALLBACK_NOW.store(789_000, Ordering::SeqCst);
        assert_eq!(
            super::timeout_now_with_fallback(deterministic_now),
            Time::from_nanos(789_000),
            "fallback clock should be consulted on every call"
        );
    }

    #[test]
    fn future_with_timeout_honors_custom_clock() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let mut future = Box::pin(super::future_with_timeout(
            std::future::pending::<()>(),
            Duration::from_nanos(500),
            test_time,
        ));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Future::poll(future.as_mut(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        assert!(matches!(
            Future::poll(future.as_mut(), &mut cx),
            Poll::Ready(Err(_))
        ));
    }

    #[test]
    fn future_with_timeout_completes_before_deadline() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let mut future = Box::pin(super::future_with_timeout(
            std::future::ready(Ok::<u8, io::Error>(7)),
            Duration::from_nanos(500),
            test_time,
        ));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Future::poll(future.as_mut(), &mut cx),
            Poll::Ready(Ok(Ok(7)))
        ));
    }

    #[test]
    fn connect_timeout_with_time_getter_times_out_before_first_attempt() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            let now = TEST_NOW.load(Ordering::SeqCst);
            TEST_NOW.store(50, Ordering::SeqCst);
            Time::from_nanos(now)
        }

        TEST_NOW.store(0, Ordering::SeqCst);
        let err = future::block_on(TcpStream::connect_timeout_with_time_getter(
            "127.0.0.1:1".parse::<SocketAddr>().expect("socket addr"),
            Duration::from_nanos(10),
            test_time,
        ))
        .expect_err("deadline should expire before the first socket attempt");

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn tcp_connect_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let handle = std::thread::spawn(move || future::block_on(TcpStream::connect(addr)));

        let _ = listener.accept().expect("accept");
        let stream = handle.join().expect("join").expect("connect");
        assert!(stream.peer_addr().is_ok());
    }

    #[test]
    fn tcp_connect_refused() {
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("local addr")
        };

        let result = future::block_on(TcpStream::connect(addr));
        assert!(result.is_err());
    }

    #[test]
    fn tcp_connect_cancel_does_not_deadlock() {
        let addr: SocketAddr = "192.0.2.1:81".parse().expect("addr");
        let mut fut = Box::pin(TcpStream::connect(addr));

        future::block_on(poll_fn(|cx| match fut.as_mut().poll(cx) {
            Poll::Pending | Poll::Ready(_) => Poll::Ready(()),
        }));

        drop(fut);
    }

    #[test]
    fn tcp_stream_registers_on_wouldblock() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        server.set_nonblocking(true).expect("nonblocking");

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

        let mut stream = TcpStream::from_std(client).expect("wrap stream");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Pending));
        assert!(stream.registration.is_some());
    }

    #[test]
    fn tcp_stream_register_notconnected_falls_back_to_pending() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        server.set_nonblocking(true).expect("nonblocking");

        let reactor = RegisterNotConnectedReactor::new();
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

        let mut stream = TcpStream::from_std(client).expect("wrap stream");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(
            matches!(poll, Poll::Pending),
            "register NotConnected should use fallback wake path instead of returning an error"
        );
        assert!(
            stream.registration.is_none(),
            "fallback path should not keep a stale registration"
        );
    }

    #[cfg(unix)]
    #[test]
    fn tcp_stream_from_std_forces_nonblocking_mode() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");

        let stream = TcpStream::from_std(client).expect("wrap stream");
        let flags = fcntl(stream.inner.as_ref(), FcntlArg::F_GETFL).expect("read stream flags");
        let is_nonblocking = OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK);
        assert!(
            is_nonblocking,
            "TcpStream::from_std should force nonblocking mode"
        );
    }

    #[test]
    fn connect_waiter_rearms_existing_registration_with_unchanged_interest() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let reactor = CountingReactor::new();
        let driver = IoDriverHandle::new(reactor.clone());
        let registration = driver
            .register(&client, Interest::WRITABLE, noop_waker())
            .expect("register");
        let mut registration = Some(registration);

        let waker = noop_waker();
        let cx = Context::from_waker(&waker);

        rearm_connect_registration(&mut registration, &cx).expect("re-arm once");
        rearm_connect_registration(&mut registration, &cx).expect("re-arm twice");

        assert_eq!(
            reactor.modify_calls(),
            2,
            "connect waiter must re-arm on every poll, even when interest is unchanged"
        );
        assert!(registration.is_some(), "registration should remain active");
    }

    #[test]
    fn stream_rearm_replaces_stale_writable_interest() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let reactor = CountingReactor::new();
        let driver = IoDriverHandle::new(reactor.clone());
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut stream = TcpStream::from_std(client).expect("wrap stream");
        let waker = noop_waker();
        let task_cx = Context::from_waker(&waker);

        stream
            .register_interest(&task_cx, Interest::WRITABLE)
            .expect("register writable");
        assert_eq!(
            stream
                .registration
                .as_ref()
                .expect("registration after writable wait")
                .interest(),
            Interest::WRITABLE,
            "initial wait should arm writability only"
        );

        stream
            .register_interest(&task_cx, Interest::READABLE)
            .expect("rearm readable");
        assert_eq!(
            reactor.last_interest(),
            Interest::READABLE,
            "subsequent read wait must drop the stale writable bit"
        );
        assert_eq!(
            stream
                .registration
                .as_ref()
                .expect("registration after readable wait")
                .interest(),
            Interest::READABLE,
            "registration should track the live caller interest"
        );
    }

    #[test]
    fn connect_waiter_clears_registration_when_driver_drops() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let reactor = CountingReactor::new();
        let driver = IoDriverHandle::new(reactor);
        let registration = driver
            .register(&client, Interest::WRITABLE, noop_waker())
            .expect("register");
        let mut registration = Some(registration);
        drop(driver);

        let waker = noop_waker();
        let cx = Context::from_waker(&waker);
        rearm_connect_registration(&mut registration, &cx).expect("re-arm with dropped driver");

        assert!(
            registration.is_none(),
            "stale connect registration should be cleared when driver is gone"
        );
    }

    #[test]
    fn fallback_rewake_without_timer_is_immediate() {
        assert!(
            Cx::current().is_none(),
            "test must run without an active Cx"
        );

        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        let cx = Context::from_waker(&waker);

        fallback_rewake(&cx);

        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "fallback re-wake should immediately schedule another poll without a timer driver"
        );
    }
}
