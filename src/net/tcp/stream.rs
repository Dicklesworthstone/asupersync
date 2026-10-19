//! TCP stream implementation.
//!
//! This module provides a TCP stream for reading and writing data over a connection.
//! The stream implements [`TcpStreamApi`] for use with generic code and frameworks.

#![allow(unsafe_code)]

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncReadVectored, AsyncWrite, ReadBuf};
#[cfg(not(target_arch = "wasm32"))]
use crate::net::lookup_all;
use crate::net::tcp::split::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf};
use crate::net::tcp::traits::TcpStreamApi;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::udp::Armed;
use crate::net::udp::ReactorRegistration;
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
#[cfg(not(target_arch = "wasm32"))]
use crate::runtime::reactor::{Events, Reactor, Token, create_reactor};
#[cfg(not(target_arch = "wasm32"))]
use crate::time::TimeoutFuture;
use crate::types::Time;
#[cfg(not(target_arch = "wasm32"))]
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
#[cfg(not(target_arch = "wasm32"))]
use std::future::Future;
use std::io::{self, IoSlice, IoSliceMut};
#[cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};
use std::net::{self, Shutdown, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
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
    /// Reactor registration, fallback-driver aware (GH#67, tx9j0f).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    registration: ReactorRegistration,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    inner: Arc<net::TcpStream>,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    shutdown_on_drop: bool,
    /// Windows-only retry budget for a transient post-connect `WSAENOTCONN`
    /// (os error 10057). Connect completion is readiness-gated, but Winsock
    /// providers can still briefly reject the first `send` or `recv`. The poll
    /// paths treat that as retryable (like `WouldBlock`) until the connection
    /// settles, bounded by this counter so a genuinely unusable socket still
    /// surfaces the error.
    #[cfg(target_os = "windows")]
    connect_settle_retries: u32,
    /// Wall-clock start of the current post-connect settling window. This
    /// prevents a driverless executor from exhausting the poll-count budget in
    /// microseconds through immediate self-wakes.
    #[cfg(target_os = "windows")]
    connect_settle_started_at: Option<Time>,
}

/// Maximum number of poll-path retries of a transient post-connect
/// `WSAENOTCONN` before it is surfaced as a hard error
/// (see [`TcpStream::connect_settle_retries`]). A genuinely settling connection
/// becomes send-ready well within this budget. Both this count and the minimum
/// real-time settling window must be exhausted before the error is surfaced.
#[cfg(target_os = "windows")]
const MAX_CONNECT_SETTLE_RETRIES: u32 = 4096;

/// Minimum real time allowed for a Windows socket to settle after its first
/// transient post-connect `WSAENOTCONN`, even if a driverless executor burns
/// through the poll-count budget via immediate self-wakes.
#[cfg(target_os = "windows")]
const MIN_CONNECT_SETTLE_TIME: Duration = Duration::from_millis(100);

/// Configuration for TCP Keepalive behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeepaliveConfig {
    /// Keepalive behavior is not explicitly configured, deferring to OS defaults.
    #[default]
    Default,
    /// Explicitly disable TCP keepalive.
    Disabled,
    /// Explicitly enable TCP keepalive with the given parameters.
    Enabled(TcpKeepaliveConfig),
}

/// Explicit TCP keepalive parameters.
///
/// `idle` is the duration before the first keepalive probe on an idle
/// connection. `interval` and `retries` are optional because operating-system
/// support differs; when requested on an unsupported target, applying the
/// config returns `io::ErrorKind::Unsupported`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpKeepaliveConfig {
    idle: Duration,
    interval: Option<Duration>,
    retries: Option<u32>,
}

impl TcpKeepaliveConfig {
    /// Create keepalive parameters with an explicit idle duration.
    #[inline]
    #[must_use]
    pub const fn new(idle: Duration) -> Self {
        Self {
            idle,
            interval: None,
            retries: None,
        }
    }

    /// Set the interval between keepalive probes.
    #[inline]
    #[must_use]
    pub const fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = Some(interval);
        self
    }

    /// Set the maximum number of keepalive probes before dropping the connection.
    #[inline]
    #[must_use]
    pub const fn with_retries(mut self, retries: u32) -> Self {
        self.retries = Some(retries);
        self
    }

    /// Duration before the first keepalive probe on an idle connection.
    #[inline]
    #[must_use]
    pub const fn idle(&self) -> Duration {
        self.idle
    }

    /// Optional interval between keepalive probes.
    #[inline]
    #[must_use]
    pub const fn interval(&self) -> Option<Duration> {
        self.interval
    }

    /// Optional keepalive probe count before dropping the connection.
    #[inline]
    #[must_use]
    pub const fn retries(&self) -> Option<u32> {
        self.retries
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn to_socket2(self) -> io::Result<socket2::TcpKeepalive> {
        let mut params = socket2::TcpKeepalive::new().with_time(self.idle);

        if let Some(interval) = self.interval {
            params = tcp_keepalive_with_interval(params, interval)?;
        }

        if let Some(retries) = self.retries {
            params = tcp_keepalive_with_retries(params, retries)?;
        }

        Ok(params)
    }
}

impl KeepaliveConfig {
    #[inline]
    #[must_use]
    pub(crate) const fn enabled(idle: Duration) -> Self {
        Self::Enabled(TcpKeepaliveConfig::new(idle))
    }
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
    #[inline]
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
    #[inline]
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Enable or disable TCP_NODELAY.
    #[inline]
    #[must_use]
    pub fn nodelay(mut self, enable: bool) -> Self {
        self.nodelay = Some(enable);
        self
    }

    /// Configure TCP keepalive.
    ///
    /// Note: Phase 0 does not support keepalive on all platforms; enabling
    /// this may return `io::ErrorKind::Unsupported`.
    #[inline]
    #[must_use]
    pub fn keepalive(mut self, keepalive: Option<Duration>) -> Self {
        self.keepalive = keepalive.map_or(KeepaliveConfig::Disabled, KeepaliveConfig::enabled);
        self
    }

    /// Configure TCP keepalive with explicit idle, interval, and retry parameters.
    #[inline]
    #[must_use]
    pub fn keepalive_config(mut self, keepalive: Option<TcpKeepaliveConfig>) -> Self {
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
            KeepaliveConfig::Enabled(config) => stream.set_keepalive_config(Some(config))?,
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
            browser_tcp_unsupported_result("TcpStream::from_std")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            // Ensure async poll paths do not inherit blocking sockets.
            stream.set_nonblocking(true)?;
            Ok(Self {
                inner: Arc::new(stream),
                registration: ReactorRegistration::new(),
                shutdown_on_drop: true,
                #[cfg(target_os = "windows")]
                connect_settle_retries: 0,
                #[cfg(target_os = "windows")]
                connect_settle_started_at: None,
            })
        }
    }

    /// Reconstruct a TcpStream from its parts (used by reunite).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn from_parts(
        inner: Arc<net::TcpStream>,
        registration: (Option<IoRegistration>, bool),
    ) -> Self {
        Self {
            inner,
            registration: ReactorRegistration::from_parts(registration),
            shutdown_on_drop: true,
            #[cfg(target_os = "windows")]
            connect_settle_retries: 0,
            #[cfg(target_os = "windows")]
            connect_settle_started_at: None,
        }
    }

    #[cfg(target_os = "windows")]
    fn clear_connect_settle_retry(&mut self) {
        self.connect_settle_retries = 0;
        self.connect_settle_started_at = None;
    }

    #[cfg(target_os = "windows")]
    fn should_retry_connect_settle(&mut self) -> bool {
        let now = crate::time::wall_now();
        let started = *self.connect_settle_started_at.get_or_insert(now);
        let count_budget_remains = self.connect_settle_retries < MAX_CONNECT_SETTLE_RETRIES;
        let time_floor_remains =
            now.duration_since(started) < duration_to_nanos_saturating(MIN_CONNECT_SETTLE_TIME);

        if count_budget_remains || time_floor_remains {
            self.connect_settle_retries = self.connect_settle_retries.saturating_add(1);
            true
        } else {
            false
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
            connect_resolved_addrs(lookup_all(addr).await?, |addr| async move {
                let domain = if addr.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                };
                let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
                Self::connect_from_socket(socket, addr).await
            })
            .await
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
        crate::cx::io_gate::require_ambient_io("net::TcpStream::connect")?;
        socket.set_nonblocking(true)?;
        // 2. Attempt connect (non-blocking)
        let sock_addr = SockAddr::from(addr);
        let registration = match socket.connect(&sock_addr) {
            Ok(()) => {
                // On Windows, `connect()` and `getpeername()` can both report
                // success before some network providers make the socket
                // send-ready. Kernel writable readiness is the authoritative
                // completion signal, including for the immediate-Ok branch.
                #[cfg(target_os = "windows")]
                {
                    wait_for_connect(&socket).await?
                }
                #[cfg(not(target_os = "windows"))]
                {
                    None
                }
            }
            Err(err) if connect_in_progress(&err) => wait_for_connect(&socket).await?,
            Err(err) => return Err(err),
        };

        // On non-Windows targets, retain the defensive peer check for an
        // immediate-Ok connect. Windows has already passed through writable
        // readiness above; `getpeername()` is not used there as a completion
        // oracle because some Winsock providers report it prematurely (#62).
        #[cfg(not(target_os = "windows"))]
        let registration = if registration.is_none() {
            match socket.peer_addr() {
                Ok(_) => None,
                Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                    wait_for_connect(&socket).await?
                }
                Err(err) => return Err(err),
            }
        } else {
            registration
        };

        // socket.into() preserves the nonblocking flag set above; no need to set again.
        let stream: net::TcpStream = socket.into();
        Ok(Self::from_parts(Arc::new(stream), (registration, false)))
    }

    /// Connect with timeout.
    ///
    /// Resolves `addr` first; resolution observes cancellation but is not
    /// counted against `timeout_duration`. The resolved addresses are then
    /// tried one after another, and they share one `timeout_duration` budget.
    /// An address that never answers, such as a black-holed route, can use the
    /// whole budget before a later working address is tried. For hosts with
    /// several addresses prefer [`crate::net::happy_eyeballs_connect`], which
    /// races attempts with a per-attempt timeout and an overall deadline
    /// (RFC 8305).
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
        connect_resolved_addrs_with_timeout(
            lookup_all(addr).await?,
            timeout_duration,
            time_getter,
            |addr| async move {
                let domain = if addr.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                };
                let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
                Self::connect_from_socket(socket, addr).await
            },
        )
        .await
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
            browser_tcp_unsupported_result("TcpStream::peer_addr")
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.peer_addr()
    }

    /// Get local address.
    #[inline]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        #[cfg(target_arch = "wasm32")]
        {
            browser_tcp_unsupported_result("TcpStream::local_addr")
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
            browser_tcp_unsupported_result("TcpStream::shutdown")
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.shutdown(how)
    }

    /// br-asupersync-1wygbs: returns a reference to the underlying
    /// `std::net::TcpStream` for callers that need a synchronous,
    /// non-blocking write directly on the OS socket — the only known
    /// caller is `database/postgres.rs::PgStream::try_send_terminate_frame`,
    /// which writes the 5-byte PostgreSQL Terminate frame from inside
    /// `Drop` (where async I/O is unreachable) so the server can reclaim
    /// session-scoped state immediately rather than waiting for
    /// idle_session_timeout. Returns `None` on platforms where the
    /// stream has no `std::net` backing (wasm32 browser TCP).
    ///
    /// `#[allow(dead_code)]` because the postgres callsite is gated
    /// behind the `postgres` cargo feature; under the default feature
    /// set this method has no caller, but it is part of the public
    /// (crate-internal) API surface.
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn try_as_std(&self) -> Option<&net::TcpStream> {
        #[cfg(target_arch = "wasm32")]
        {
            None
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Some(&self.inner)
        }
    }

    /// Set TCP_NODELAY.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = nodelay;
            browser_tcp_unsupported_result("TcpStream::set_nodelay")
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.set_nodelay(nodelay)
    }

    /// Set keepalive.
    ///
    /// Uses `socket2` to configure `SO_KEEPALIVE` and platform-specific
    /// keepalive idle time. Pass `None` to disable keepalive.
    pub fn set_keepalive(&self, keepalive: Option<Duration>) -> io::Result<()> {
        self.set_keepalive_config(keepalive.map(TcpKeepaliveConfig::new))
    }

    /// Set keepalive with explicit idle, interval, and retry parameters.
    ///
    /// Pass `None` to disable keepalive. Unsupported interval or retry-count
    /// parameters return `io::ErrorKind::Unsupported` instead of becoming
    /// ambient no-ops.
    pub fn set_keepalive_config(&self, keepalive: Option<TcpKeepaliveConfig>) -> io::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = keepalive;
            Err(super::browser_tcp_unsupported(
                "TcpStream::set_keepalive_config",
            ))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let socket = socket2::SockRef::from(&*self.inner);
            match keepalive {
                Some(config) => {
                    let params = config.to_socket2()?;
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
    ///
    /// Borrowed halves do not register with the reactor; each `WouldBlock`
    /// arms a 1 ms timer. For zero-overhead parking on the reactor, use
    /// [`into_split()`](Self::into_split) instead.
    #[must_use]
    pub fn split(&self) -> (ReadHalf<'_>, WriteHalf<'_>) {
        #[cfg(target_arch = "wasm32")]
        { (ReadHalf::unsupported(), WriteHalf::unsupported()) }

        #[cfg(not(target_arch = "wasm32"))]
        { (ReadHalf::new(&self.inner), WriteHalf::new(&self.inner)) }
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
            let (registration, registration_on_fallback) = this.registration.take_parts();
            let inner = this.inner.clone();
            OwnedReadHalf::new_pair_with_fallback_flag(
                inner,
                registration,
                registration_on_fallback,
            )
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[inline]
    #[allow(dead_code)]
    fn register_interest(&self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        let _ = (cx, interest);
        browser_tcp_unsupported_result("TcpStream::register_interest")
    }

    /// Registers readiness interest for the caller's current poll.
    ///
    /// A plain `TcpStream` has a single waiter, so only the caller's current
    /// interest is armed (no sticky union of historical bits, which kept stale
    /// WRITABLE polls alive during later read waits). With no ambient I/O
    /// driver the fd parks on the process-global fallback driver instead of
    /// self-waking into a hot loop (GH#67, asupersync-tx9j0f); see
    /// [`ReactorRegistration::arm`].
    #[cfg(not(target_arch = "wasm32"))]
    #[inline]
    fn register_interest(&mut self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        if self.registration.arm(&*self.inner, interest, cx.waker())? == Armed::SelfWake {
            fallback_rewake(cx);
        }
        Ok(())
    }
}

/// Readiness, peeking and non-blocking I/O, for protocol code that sniffs a
/// connection before choosing a handler, or drives the socket itself.
#[cfg(not(target_arch = "wasm32"))]
impl TcpStream {
    /// Receives bytes into `buf` without removing them from the socket's
    /// receive queue: the next read returns them again. Waits until at least
    /// one byte arrives; returns `0` at end-of-stream.
    ///
    /// A listener can peek at the first bytes of a connection to tell, say,
    /// a TLS `ClientHello` from plaintext, then hand the untouched stream to
    /// the matching protocol.
    pub async fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        std::future::poll_fn(|cx| self.poll_peek(cx, &mut ReadBuf::new(buf))).await
    }

    /// Poll form of [`Self::peek`]: fills `buf` with queued bytes without
    /// consuming them and returns how many.
    pub fn poll_peek(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<usize>> {
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        match self.inner.peek(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(n))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.register_interest(cx, Interest::READABLE)?;
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Waits until the stream may be readable, for use with
    /// [`Self::try_read`].
    ///
    /// Readiness can be spurious: `try_read` may still return
    /// [`io::ErrorKind::WouldBlock`], and the caller waits again.
    pub async fn readable(&mut self) -> io::Result<()> {
        self.ready_for(Interest::READABLE).await
    }

    /// Waits until the stream may be writable, for use with
    /// [`Self::try_write`]. Readiness can be spurious, as with
    /// [`Self::readable`].
    pub async fn writable(&mut self) -> io::Result<()> {
        self.ready_for(Interest::WRITABLE).await
    }

    /// Reads what is available without waiting, or fails with
    /// [`io::ErrorKind::WouldBlock`]. Returns `0` at end-of-stream.
    pub fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.inner).read(buf)
    }

    /// Vectored form of [`Self::try_read`].
    pub fn try_read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (&*self.inner).read_vectored(bufs)
    }

    /// Writes what the socket accepts without waiting, or fails with
    /// [`io::ErrorKind::WouldBlock`].
    pub fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
        (&*self.inner).write(buf)
    }

    /// Vectored form of [`Self::try_write`].
    pub fn try_write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (&*self.inner).write_vectored(bufs)
    }

    /// `SO_LINGER`: `None` (the default) closes gracefully in the background;
    /// `Some(Duration::ZERO)` resets the connection on close.
    pub fn linger(&self) -> io::Result<Option<Duration>> {
        socket2::SockRef::from(&*self.inner).linger()
    }

    /// Sets `SO_LINGER` to `None` or `Some(Duration::ZERO)` (the same as
    /// [`Self::set_zero_linger`]).
    ///
    /// Any other duration is refused with [`io::ErrorKind::InvalidInput`]: a
    /// non-zero linger makes the close in `Drop` block the runtime thread
    /// until the peer acknowledges the unsent data, which a peer that stops
    /// reading can delay for the whole duration (tokio deprecated it for the
    /// same reason). Only whole seconds would count, too.
    pub fn set_linger(&self, linger: Option<Duration>) -> io::Result<()> {
        match linger {
            None => socket2::SockRef::from(&*self.inner).set_linger(None),
            Some(duration) if duration.is_zero() => self.set_zero_linger(),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a non-zero SO_LINGER blocks the runtime thread on close; \
                 use set_zero_linger or None",
            )),
        }
    }

    /// Sets `SO_LINGER` to zero: dropping the stream discards unsent data and
    /// resets the connection, so the peer's next read fails with
    /// [`io::ErrorKind::ConnectionReset`] instead of seeing end-of-stream.
    pub fn set_zero_linger(&self) -> io::Result<()> {
        ZERO_LINGER_SET.store(true, std::sync::atomic::Ordering::Relaxed);
        socket2::SockRef::from(&*self.inner).set_linger(Some(Duration::ZERO))
    }

    /// Takes the socket's pending error (`SO_ERROR`), if any.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    /// Resolves once a readiness event for `interest` arrives (or, with no
    /// reactor for the socket, after a short backoff).
    async fn ready_for(&mut self, interest: Interest) -> io::Result<()> {
        let flag = Arc::new(ReadinessFlag::default());
        std::future::poll_fn(|cx| {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
            }
            if flag.ready.swap(false, std::sync::atomic::Ordering::AcqRel) {
                return Poll::Ready(Ok(()));
            }
            *flag.task.lock() = Some(cx.waker().clone());
            let waker = std::task::Waker::from(Arc::clone(&flag));
            if self.registration.arm(&*self.inner, interest, &waker)? == Armed::SelfWake {
                // No reactor reports readiness: report it after a backoff and
                // let `try_read` / `try_write` find out.
                flag.ready.store(true, std::sync::atomic::Ordering::Release);
                fallback_rewake(cx);
            }
            Poll::Pending
        })
        .await
    }
}

/// The waker `ready_for` arms the registration with: it records the event,
/// then wakes the waiting task.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
struct ReadinessFlag {
    ready: std::sync::atomic::AtomicBool,
    task: parking_lot::Mutex<Option<std::task::Waker>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl std::task::Wake for ReadinessFlag {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.store(true, std::sync::atomic::Ordering::Release);
        let task = self.task.lock().take();
        if let Some(task) = task {
            task.wake();
        }
    }
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "windows",
    target_os = "cygwin",
    all(target_os = "wasi", not(target_env = "p1")),
))]
#[cfg(not(target_arch = "wasm32"))]
fn tcp_keepalive_with_interval(
    params: socket2::TcpKeepalive,
    interval: Duration,
) -> io::Result<socket2::TcpKeepalive> {
    Ok(params.with_interval(interval))
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "windows",
    target_os = "cygwin",
    all(target_os = "wasi", not(target_env = "p1")),
)))]
#[cfg(not(target_arch = "wasm32"))]
fn tcp_keepalive_with_interval(
    params: socket2::TcpKeepalive,
    interval: Duration,
) -> io::Result<socket2::TcpKeepalive> {
    let _ = params;
    let _ = interval;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP keepalive interval is unsupported on this platform",
    ))
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "windows",
    target_os = "cygwin",
    all(target_os = "wasi", not(target_env = "p1")),
))]
#[cfg(not(target_arch = "wasm32"))]
fn tcp_keepalive_with_retries(
    params: socket2::TcpKeepalive,
    retries: u32,
) -> io::Result<socket2::TcpKeepalive> {
    Ok(params.with_retries(retries))
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "windows",
    target_os = "cygwin",
    all(target_os = "wasi", not(target_env = "p1")),
)))]
#[cfg(not(target_arch = "wasm32"))]
fn tcp_keepalive_with_retries(
    params: socket2::TcpKeepalive,
    retries: u32,
) -> io::Result<socket2::TcpKeepalive> {
    let _ = params;
    let _ = retries;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP keepalive retry count is unsupported on this platform",
    ))
}

#[cfg(not(target_arch = "wasm32"))]
#[inline]
fn connect_error_is_cancellation(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
        && Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false)
}

#[cfg(not(target_arch = "wasm32"))]
async fn connect_resolved_addrs<F, Fut>(
    addrs: Vec<SocketAddr>,
    mut connect_one: F,
) -> io::Result<TcpStream>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<TcpStream>>,
{
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no socket addresses found",
        ));
    }

    let mut last_err = None;
    for addr in addrs {
        match connect_one(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) if connect_error_is_cancellation(&err) => return Err(err),
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| io::Error::other("failed to connect to any address")))
}

#[cfg(not(target_arch = "wasm32"))]
async fn connect_resolved_addrs_with_timeout<F, Fut>(
    addrs: Vec<SocketAddr>,
    timeout_duration: Duration,
    time_getter: fn() -> Time,
    mut connect_one: F,
) -> io::Result<TcpStream>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<TcpStream>> + 'static,
{
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
        let remaining = Duration::from_nanos(deadline.duration_since(now));

        match future_with_timeout(Box::pin(connect_one(addr)), remaining, time_getter).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) if connect_error_is_cancellation(&err) => return Err(err),
            Ok(Err(err)) => last_err = Some(err),
            Err(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tcp connect timeout",
                ));
                break;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| io::Error::other("failed to connect to any address")))
}

#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
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
#[inline]
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
#[inline]
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
    // The normal driver registration is waker-oriented: a task wake does not
    // identify which source woke it. On Windows that is insufficient because
    // `getpeername()` can report success before the connect is send-ready.
    // Use the same platform reactor abstraction as the runtime, but observe
    // its concrete writable event directly.
    if cfg!(target_os = "windows") {
        wait_for_connect_fallback(socket).await?;
        return Ok(None);
    }

    if !crate::net::udp::ambient_io_driver_present() {
        wait_for_connect_fallback(socket).await?;
        return Ok(None);
    }

    let mut registration: Option<IoRegistration> = None;
    let mut fallback = false;
    std::future::poll_fn(|cx| {
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }

        match poll_connect_complete(socket) {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => {
                if let Err(err) = rearm_connect_registration(&mut registration, cx) {
                    return Poll::Ready(Err(err));
                }
                if registration.is_some() {
                    match poll_connect_complete(socket) {
                        Ok(true) => return Poll::Ready(Ok(())),
                        Ok(false) => {}
                        Err(err) => return Poll::Ready(Err(err)),
                    }
                }

                if registration.is_none() {
                    // Resolve the polling executor's driver here. A connect
                    // future must not retain its original dispatcher across
                    // await or register on a live but idle old runtime (GH#85).
                    let Some(driver) = Cx::current().and_then(|cx| cx.io_driver_handle()) else {
                        fallback = true;
                        return Poll::Ready(Ok(()));
                    };
                    match driver.register(socket, Interest::WRITABLE, cx.waker().clone()) {
                        Ok(new_reg) => {
                            registration = Some(new_reg);
                            match poll_connect_complete(socket) {
                                Ok(true) => return Poll::Ready(Ok(())),
                                Ok(false) => {}
                                Err(err) => return Poll::Ready(Err(err)),
                            }
                        }
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

                // Registered: its WRITABLE event wakes us (no 1 ms rewake).
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

#[cfg(not(target_arch = "wasm32"))]
fn poll_connect_complete(socket: &Socket) -> io::Result<bool> {
    if let Some(err) = socket.take_error()? {
        return Err(err);
    }

    match socket.peer_addr() {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotConnected => Ok(false),
        Err(err) => Err(err),
    }
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
    if registration
        .as_ref()
        .is_some_and(|existing| crate::net::udp::registration_needs_migration(existing, false))
    {
        *registration = None;
        return Ok(());
    }
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
    const CONNECT_TOKEN: Token = Token::new(0);

    let reactor = create_reactor()?;
    reactor.register(socket, CONNECT_TOKEN, Interest::WRITABLE)?;
    let mut events = Events::with_capacity(1);

    let result = std::future::poll_fn(|cx| {
        poll_connect_fallback_ready(socket, reactor.as_ref(), &mut events, CONNECT_TOKEN, cx)
    })
    .await;

    // The private reactor is dropped with this future, so cleanup is already
    // bounded on cancellation. Explicit deregistration keeps successful and
    // ordinary error paths tidy without masking the connect result.
    drop(reactor.deregister(CONNECT_TOKEN));
    result
}

#[cfg(not(target_arch = "wasm32"))]
fn poll_connect_fallback_ready(
    socket: &Socket,
    reactor: &dyn Reactor,
    events: &mut Events,
    token: Token,
    cx: &Context<'_>,
) -> Poll<io::Result<()>> {
    if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
        return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
    }

    if let Some(err) = socket.take_error()? {
        return Poll::Ready(Err(err));
    }

    match reactor.poll(events, Some(FALLBACK_IO_BACKOFF)) {
        Ok(_) if events.iter().any(|event| event.token == token) => {
            if let Some(err) = socket.take_error()? {
                Poll::Ready(Err(err))
            } else {
                Poll::Ready(Ok(()))
            }
        }
        Ok(_) => {
            fallback_rewake(cx);
            Poll::Pending
        }
        Err(err) if err.kind() == io::ErrorKind::Interrupted => {
            fallback_rewake(cx);
            Poll::Pending
        }
        Err(err) => Poll::Ready(Err(err)),
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
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        // std::net::TcpStream implements Read for &TcpStream
        match (&*inner).read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                #[cfg(target_os = "windows")]
                {
                    this.clear_connect_settle_retry();
                }
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            // Windows: tolerate the transient post-connect `WSAENOTCONN` on the
            // first recv (see `connect_settle_retries`) — wait for readiness and
            // retry instead of failing, bounded so a dead socket still errors.
            #[cfg(target_os = "windows")]
            Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                if !this.should_retry_connect_settle() {
                    return Poll::Ready(Err(e));
                }
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
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }

        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        match (&*inner).read_vectored(bufs) {
            Ok(n) => {
                #[cfg(target_os = "windows")]
                {
                    this.clear_connect_settle_retry();
                }
                Poll::Ready(Ok(n))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            // Windows: tolerate the transient post-connect `WSAENOTCONN`
            // (see `connect_settle_retries`); retry until the socket settles.
            #[cfg(target_os = "windows")]
            Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                if !this.should_retry_connect_settle() {
                    return Poll::Ready(Err(e));
                }
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
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }

        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        match (&*inner).write(buf) {
            Ok(n) => {
                #[cfg(target_os = "windows")]
                {
                    this.clear_connect_settle_retry();
                }
                Poll::Ready(Ok(n))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            // Windows: a freshly-connected socket can momentarily report
            // `WSAENOTCONN` (os error 10057) on the first send even after the
            // connect readiness event. Treat it as "connect still settling":
            // wait for writable and retry instead of failing the (e.g. TLS)
            // handshake, bounded by both poll count and real elapsed time.
            #[cfg(target_os = "windows")]
            Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                if !this.should_retry_connect_settle() {
                    return Poll::Ready(Err(e));
                }
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
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }

        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        match (&*inner).write_vectored(bufs) {
            Ok(n) => {
                #[cfg(target_os = "windows")]
                {
                    this.clear_connect_settle_retry();
                }
                Poll::Ready(Ok(n))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            // Windows: tolerate the transient post-connect `WSAENOTCONN`
            // (see `connect_settle_retries`); retry until the socket settles.
            #[cfg(target_os = "windows")]
            Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                if !this.should_retry_connect_settle() {
                    return Poll::Ready(Err(e));
                }
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
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
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
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
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
        if self.shutdown_on_drop && !closes_abortively(&self.inner) {
            let _ = self.inner.shutdown(Shutdown::Both);
        }
    }
}

/// Whether some stream in this process was given a zero `SO_LINGER` through
/// [`TcpStream::set_linger`] or [`TcpStream::set_zero_linger`]; until then,
/// drops skip the `SO_LINGER` query.
#[cfg(not(target_arch = "wasm32"))]
static ZERO_LINGER_SET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether closing `stream` resets the connection (`SO_LINGER` of zero).
/// Such a close must not be preceded by a `shutdown`, whose FIN would reach
/// the peer first and make it read a clean end-of-stream instead of the
/// reset (br-asupersync-7u9x9b).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn closes_abortively(stream: &net::TcpStream) -> bool {
    ZERO_LINGER_SET.load(std::sync::atomic::Ordering::Relaxed)
        && socket2::SockRef::from(stream).linger().ok().flatten() == Some(Duration::ZERO)
}

/// Wraps a connected standard-library TCP stream, for example one inherited
/// through systemd socket activation or configured with `socket2` before it
/// connected. The socket is switched to non-blocking mode and registers with
/// the reactor on first use, like a stream from [`TcpStream::connect`].
/// Dropping the wrapper shuts the connection down.
impl TryFrom<net::TcpStream> for TcpStream {
    type Error = io::Error;

    fn try_from(stream: net::TcpStream) -> io::Result<Self> {
        Self::from_std(stream)
    }
}

/// The raw socket, for socket options this API does not cover (through
/// `socket2::SockRef`, for example). Reading or writing it directly bypasses
/// the reactor's readiness tracking.
#[cfg(unix)]
impl std::os::fd::AsRawFd for TcpStream {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&*self.inner)
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for TcpStream {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&*self.inner)
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawSocket for TcpStream {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        std::os::windows::io::AsRawSocket::as_raw_socket(&*self.inner)
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for TcpStream {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        std::os::windows::io::AsSocket::as_socket(&*self.inner)
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
            browser_tcp_unsupported_result("TcpStream::nodelay")
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.nodelay()
    }

    fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = ttl;
            browser_tcp_unsupported_result("TcpStream::set_ttl")
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.set_ttl(ttl)
    }

    fn ttl(&self) -> io::Result<u32> {
        #[cfg(target_arch = "wasm32")]
        {
            browser_tcp_unsupported_result("TcpStream::ttl")
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.ttl()
    }
}

#[cfg(test)]
#[path = "stream_inline_tests.rs"]
mod tests;
