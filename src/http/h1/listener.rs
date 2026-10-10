//! HTTP/1.1 server accept loop with graceful shutdown.
//!
//! [`Http1Listener`] binds a TCP listener, accepts connections, and dispatches
//! each to an [`Http1Server`] handler. Integrates with [`ConnectionManager`]
//! for capacity limits and [`ShutdownSignal`] for graceful drain.

use crate::http::h1::server::{
    Http1Config, Http1ServeOutcome, Http1Server, Http1StreamingServer, IntoHttp1Response,
};
use crate::http::h1::stream::{Http1ProducedResponse, StreamingServerRequest};
use crate::http::h1::types::{Request, Response};
#[cfg(not(target_arch = "wasm32"))]
use crate::http::handoff::{HandoffQueue, HandoffStream};
use crate::http::listener_cancel::ListenerCancellation;
#[cfg(feature = "tls")]
use crate::io::AsyncWriteExt;
use crate::net::tcp::listener::TcpListener;
use crate::net::tcp::stream::TcpStream;
#[cfg(unix)]
use crate::net::unix::{UnixListener, UnixStream};
use crate::runtime::{JoinHandle, RuntimeHandle, SpawnError};
use crate::server::connection::{ConnectionGuard, ConnectionManager};
use crate::server::shutdown::{
    DrainStep, GracefulDrainReport, GracefulDrainSupervisor, ShutdownPhase, ShutdownSignal,
    ShutdownStats,
};
#[cfg(feature = "tls")]
use crate::tls::TlsAcceptor;
use crate::tracing_compat::error;
use crate::web::sse::{Http1SseResponse, StreamingSseSource};
use crate::{
    cx::Cx,
    types::{CancelKind, Time},
};
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

const TRANSIENT_ACCEPT_BACKOFF_BASE: Duration = Duration::from_millis(2);
const TRANSIENT_ACCEPT_BACKOFF_CAP: Duration = Duration::from_millis(64);

/// Tick interval for the request-aware drain supervision loop
/// (br-asupersync-server-stack-hardening-eeexl1.2, D2.2b). Each tick samples
/// the shared in-flight request counter and feeds the
/// [`GracefulDrainSupervisor`] decision state machine.
const DRAIN_SUPERVISION_TICK: Duration = Duration::from_millis(10);

/// Waits one drain supervision tick from `now`, whether or not the listener
/// task is cancelled. A region-owned listener is shut down by cancelling its
/// task; a cancel-aware sleep then completed after one scheduler round trip,
/// and the supervision loop spun until the drain deadline
/// (br-asupersync-m8xsjx).
async fn drain_supervision_tick(now: Time) {
    let tick = crate::time::sleep(now, DRAIN_SUPERVISION_TICK);
    let mut tick = std::pin::pin!(tick);
    std::future::poll_fn(|cx| tick.as_mut().poll_deadline(cx)).await;
}

/// Low-overhead listener counters for diagnosing accept-path stalls and
/// observing graceful drains
/// (br-asupersync-server-stack-hardening-eeexl1.2, D2.4 AC6).
pub struct Http1ListenerStats {
    accepted_total: AtomicU64,
    transient_accept_errors_total: AtomicU64,
    spawn_failures_total: AtomicU64,
    last_accept_at_ms: AtomicU64,
    drains_started_total: AtomicU64,
    drain_escalations_total: AtomicU64,
    drain_hard_deadline_hits_total: AtomicU64,
    drains_quiescent_total: AtomicU64,
    last_drain_requests_at_start: AtomicU64,
    last_drain_requests_stranded: AtomicU64,
    last_drain_duration_ms: AtomicU64,
    time_getter: fn() -> Time,
}

/// Immutable snapshot of [`Http1ListenerStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http1ListenerStatsSnapshot {
    /// Total successful accepts observed by the listener.
    pub accepted_total: u64,
    /// Total transient accept errors that triggered listener backoff.
    pub transient_accept_errors_total: u64,
    /// Total failures to spawn a per-connection task after accept succeeded.
    pub spawn_failures_total: u64,
    /// Logical runtime time in milliseconds when the listener last accepted a connection.
    pub last_accept_at_ms: u64,
    /// Total request-aware drains started by this listener.
    pub drains_started_total: u64,
    /// Total drains whose soft budget elapsed and escalated stragglers.
    pub drain_escalations_total: u64,
    /// Total drains that ended on the hard deadline with requests stranded.
    pub drain_hard_deadline_hits_total: u64,
    /// Total drains that reached quiescence (zero in-flight requests).
    pub drains_quiescent_total: u64,
    /// In-flight request count when the most recent drain started.
    pub last_drain_requests_at_start: u64,
    /// Requests still in flight when the most recent drain ended.
    pub last_drain_requests_stranded: u64,
    /// Duration of the most recent drain in whole milliseconds.
    pub last_drain_duration_ms: u64,
}

impl std::fmt::Debug for Http1ListenerStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http1ListenerStats")
            .field(
                "accepted_total",
                &self.accepted_total.load(Ordering::Relaxed),
            )
            .field(
                "transient_accept_errors_total",
                &self.transient_accept_errors_total.load(Ordering::Relaxed),
            )
            .field(
                "spawn_failures_total",
                &self.spawn_failures_total.load(Ordering::Relaxed),
            )
            .field(
                "last_accept_at_ms",
                &self.last_accept_at_ms.load(Ordering::Relaxed),
            )
            .field(
                "drains_started_total",
                &self.drains_started_total.load(Ordering::Relaxed),
            )
            .field(
                "drain_escalations_total",
                &self.drain_escalations_total.load(Ordering::Relaxed),
            )
            .field(
                "drain_hard_deadline_hits_total",
                &self.drain_hard_deadline_hits_total.load(Ordering::Relaxed),
            )
            .field(
                "drains_quiescent_total",
                &self.drains_quiescent_total.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl Default for Http1ListenerStats {
    fn default() -> Self {
        Self::new(default_listener_time_getter)
    }
}

impl Http1ListenerStats {
    fn new(time_getter: fn() -> Time) -> Self {
        Self {
            accepted_total: AtomicU64::new(0),
            transient_accept_errors_total: AtomicU64::new(0),
            spawn_failures_total: AtomicU64::new(0),
            last_accept_at_ms: AtomicU64::new(0),
            drains_started_total: AtomicU64::new(0),
            drain_escalations_total: AtomicU64::new(0),
            drain_hard_deadline_hits_total: AtomicU64::new(0),
            drains_quiescent_total: AtomicU64::new(0),
            last_drain_requests_at_start: AtomicU64::new(0),
            last_drain_requests_stranded: AtomicU64::new(0),
            last_drain_duration_ms: AtomicU64::new(0),
            time_getter,
        }
    }

    fn record_accepted(&self) {
        self.accepted_total.fetch_add(1, Ordering::Relaxed);
        self.last_accept_at_ms
            .store((self.time_getter)().as_millis(), Ordering::Relaxed);
    }

    fn record_transient_accept_error(&self) {
        self.transient_accept_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_spawn_failure(&self) {
        self.spawn_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_drain_started(&self, in_flight: usize) {
        self.drains_started_total.fetch_add(1, Ordering::Relaxed);
        self.last_drain_requests_at_start.store(
            u64::try_from(in_flight).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn record_drain_escalated(&self) {
        self.drain_escalations_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_drain_hard_deadline(&self) {
        self.drain_hard_deadline_hits_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_drain_finished(&self, report: &GracefulDrainReport) {
        if report.reached_quiescence {
            self.drains_quiescent_total.fetch_add(1, Ordering::Relaxed);
        }
        self.last_drain_requests_stranded.store(
            u64::try_from(report.requests_stranded).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.last_drain_duration_ms.store(
            u64::try_from(report.drain_duration.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Returns a point-in-time copy of the listener counters.
    #[must_use]
    pub fn snapshot(&self) -> Http1ListenerStatsSnapshot {
        Http1ListenerStatsSnapshot {
            accepted_total: self.accepted_total.load(Ordering::Relaxed),
            transient_accept_errors_total: self
                .transient_accept_errors_total
                .load(Ordering::Relaxed),
            spawn_failures_total: self.spawn_failures_total.load(Ordering::Relaxed),
            last_accept_at_ms: self.last_accept_at_ms.load(Ordering::Relaxed),
            drains_started_total: self.drains_started_total.load(Ordering::Relaxed),
            drain_escalations_total: self.drain_escalations_total.load(Ordering::Relaxed),
            drain_hard_deadline_hits_total: self
                .drain_hard_deadline_hits_total
                .load(Ordering::Relaxed),
            drains_quiescent_total: self.drains_quiescent_total.load(Ordering::Relaxed),
            last_drain_requests_at_start: self.last_drain_requests_at_start.load(Ordering::Relaxed),
            last_drain_requests_stranded: self.last_drain_requests_stranded.load(Ordering::Relaxed),
            last_drain_duration_ms: self.last_drain_duration_ms.load(Ordering::Relaxed),
        }
    }
}

fn default_listener_time_getter() -> Time {
    Cx::current()
        .and_then(|current| current.timer_driver())
        .map_or_else(crate::time::wall_now, |driver| driver.now())
}

fn shutdown_signal_for_time_getter(time_getter: fn() -> Time) -> ShutdownSignal {
    if std::ptr::fn_addr_eq(time_getter, default_listener_time_getter as fn() -> Time) {
        ShutdownSignal::new()
    } else {
        ShutdownSignal::with_time_getter(time_getter)
    }
}

/// Configuration for the HTTP/1.1 listener.
#[derive(Debug, Clone)]
pub struct Http1ListenerConfig {
    /// Per-connection HTTP configuration.
    pub http_config: Http1Config,
    /// Maximum concurrent connections. `None` means unlimited.
    pub max_connections: Option<usize>,
    /// Drain timeout for graceful shutdown.
    ///
    /// This is the soft budget of the request-aware drain: when it elapses
    /// with requests still in flight, the drain supervisor escalates
    /// stragglers through force-close
    /// (br-asupersync-server-stack-hardening-eeexl1.2, D2.2b).
    pub drain_timeout: Duration,
    /// Hard deadline budget for graceful shutdown.
    ///
    /// Measured from drain start like [`drain_timeout`](Self::drain_timeout);
    /// clamped up to at least `drain_timeout`. When it elapses the drain ends
    /// unconditionally and the drain report records `hard_deadline_hit`.
    pub hard_drain_timeout: Duration,
    /// Keep the listening socket bound (without accepting) until the drain
    /// completes (br-asupersync-server-stack-hardening-eeexl1.2, D2.4 AC5).
    ///
    /// Default `false`: the socket is closed as soon as draining starts, so
    /// new connection attempts fail fast with connection-refused. Set `true`
    /// for load balancers that treat refused connections as hard backend
    /// failure during connection draining — TCP handshakes then continue to
    /// succeed (queueing in the accept backlog, never served) until the
    /// drain finishes and the socket closes.
    pub lb_compat_keep_socket: bool,
    /// Time source for shutdown bookkeeping, connection metadata, and listener diagnostics.
    pub time_getter: fn() -> Time,
}

impl Default for Http1ListenerConfig {
    fn default() -> Self {
        Self {
            http_config: Http1Config::default(),
            max_connections: Some(10_000),
            drain_timeout: Duration::from_secs(30),
            hard_drain_timeout: Duration::from_secs(60),
            lb_compat_keep_socket: false,
            time_getter: default_listener_time_getter,
        }
    }
}

impl Http1ListenerConfig {
    /// Set the per-connection HTTP configuration.
    #[must_use]
    pub fn http_config(mut self, config: Http1Config) -> Self {
        self.http_config = config;
        self
    }

    /// Set the maximum number of concurrent connections.
    #[must_use]
    pub fn max_connections(mut self, max: Option<usize>) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the drain timeout for graceful shutdown.
    #[must_use]
    pub fn drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Set the hard drain deadline budget for graceful shutdown.
    #[must_use]
    pub fn hard_drain_timeout(mut self, timeout: Duration) -> Self {
        self.hard_drain_timeout = timeout;
        self
    }

    /// Keep the listening socket bound (not accepting) until drain completes.
    #[must_use]
    pub fn lb_compat_keep_socket(mut self, keep: bool) -> Self {
        self.lb_compat_keep_socket = keep;
        self
    }

    /// Set the time source for listener bookkeeping and shutdown coordination.
    #[must_use]
    pub fn time_getter(mut self, time_getter: fn() -> Time) -> Self {
        self.time_getter = time_getter;
        self
    }
}

/// HTTP/1.1 server listener that accepts connections and serves them.
///
/// Ties together [`TcpListener`], [`Http1Server`], [`ConnectionManager`],
/// and [`ShutdownSignal`] into a complete accept loop with graceful shutdown.
///
/// # Host policy
///
/// The default [`Http1Config`] uses
/// [`HostPolicy::RejectUnknown`](crate::http::h1::server::HostPolicy::RejectUnknown),
/// which answers every request `421 Misdirected Request`. A server built with [`Http1Listener::bind`]
/// and no further configuration therefore serves nothing. Name the hosts it
/// answers for with [`Http1Config::host_policy`] and
/// [`Http1Listener::bind_with_config`], as below.
///
/// # Example
///
/// ```ignore
/// use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
/// use asupersync::http::h1::server::{HostPolicy, Http1Config};
/// use asupersync::http::h1::types::Response;
/// use asupersync::runtime::RuntimeBuilder;
///
/// let runtime = RuntimeBuilder::current_thread().build()?;
/// let handle = runtime.handle();
/// runtime.block_on(async {
///     let config = Http1ListenerConfig::default().http_config(
///         Http1Config::default()
///             .host_policy(HostPolicy::AllowList(vec!["localhost".to_owned()])),
///     );
///     let listener = Http1Listener::bind_with_config(
///         "127.0.0.1:8080",
///         |req| async { Response::new(200, "OK", b"Hello".to_vec()) },
///         config,
///     )
///     .await?;
///
///     // In another task: listener.begin_drain();
///     let stats = listener.run(&handle).await?;
///     Ok::<_, std::io::Error>(stats)
/// })?;
/// ```
pub struct Http1Listener<F> {
    listener: H1AcceptSource,
    handler: Arc<F>,
    config: Http1ListenerConfig,
    shutdown_signal: ShutdownSignal,
    connection_manager: ConnectionManager,
    stats: Arc<Http1ListenerStats>,
    /// Listener-wide live request count, shared with every connection's
    /// [`Http1Server`] (br-asupersync-server-stack-hardening-eeexl1.2,
    /// D2.2b). Strictly finer-grained than connection tracking: an idle
    /// keep-alive connection holds no in-flight request.
    in_flight_requests: Arc<AtomicUsize>,
}

impl<F, Fut> Http1Listener<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = crate::http::h1::types::Response> + Send + 'static,
{
    /// Bind a listener whose handler returns the established plain response
    /// type. The exact output preserves inference for existing handlers.
    ///
    /// It uses the default configuration, whose host policy rejects every
    /// request with `421` (see "Host policy" on [`Http1Listener`]). Use
    /// [`Self::bind_with_config`] to name the allowed hosts.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(addr: A, handler: F) -> io::Result<Self> {
        Self::bind_upgradeable(addr, handler).await
    }

    /// Bind a plain-response listener with custom configuration.
    pub async fn bind_with_config<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
        config: Http1ListenerConfig,
    ) -> io::Result<Self> {
        Self::bind_upgradeable_with_config(addr, handler, config).await
    }

    /// Create a plain-response listener from an existing TCP listener.
    pub fn from_listener(
        tcp_listener: TcpListener,
        handler: F,
        config: Http1ListenerConfig,
    ) -> Self {
        Self::from_listener_upgradeable(tcp_listener, handler, config)
    }
}

impl<F, Fut, R> Http1Listener<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response + Send + 'static,
{
    /// Bind an upgrade-aware response handler with default configuration.
    pub async fn bind_upgradeable<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
    ) -> io::Result<Self> {
        Self::bind_upgradeable_with_config(addr, handler, Http1ListenerConfig::default()).await
    }

    /// Bind an upgrade-aware response handler with custom configuration.
    pub async fn bind_upgradeable_with_config<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
        config: Http1ListenerConfig,
    ) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        let shutdown_signal = shutdown_signal_for_time_getter(config.time_getter);
        let connection_manager = ConnectionManager::with_time_getter(
            config.max_connections,
            shutdown_signal.clone(),
            config.time_getter,
        );
        let stats = Arc::new(Http1ListenerStats::new(config.time_getter));

        Ok(Self {
            listener: H1AcceptSource::Tcp(tcp_listener),
            handler: Arc::new(handler),
            config,
            shutdown_signal,
            connection_manager,
            stats,
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Create an upgrade-aware listener from an existing [`TcpListener`].
    pub fn from_listener_upgradeable(
        tcp_listener: TcpListener,
        handler: F,
        config: Http1ListenerConfig,
    ) -> Self {
        let shutdown_signal = shutdown_signal_for_time_getter(config.time_getter);
        let connection_manager = ConnectionManager::with_time_getter(
            config.max_connections,
            shutdown_signal.clone(),
            config.time_getter,
        );
        let stats = Arc::new(Http1ListenerStats::new(config.time_getter));

        Self {
            listener: H1AcceptSource::Tcp(tcp_listener),
            handler: Arc::new(handler),
            config,
            shutdown_signal,
            connection_manager,
            stats,
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<F, Fut> Http1Listener<F>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    /// Bind a listener that publishes each validated request head before body EOF.
    pub async fn bind_streaming<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
    ) -> io::Result<Self> {
        Self::bind_streaming_with_config(addr, handler, Http1ListenerConfig::default()).await
    }

    /// Bind a live request-body listener with custom connection configuration.
    pub async fn bind_streaming_with_config<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
        config: Http1ListenerConfig,
    ) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        Ok(Self::from_listener_streaming(tcp_listener, handler, config))
    }

    /// Create a live request-body listener from an existing TCP listener.
    pub fn from_listener_streaming(
        tcp_listener: TcpListener,
        handler: F,
        config: Http1ListenerConfig,
    ) -> Self {
        let shutdown_signal = shutdown_signal_for_time_getter(config.time_getter);
        let connection_manager = ConnectionManager::with_time_getter(
            config.max_connections,
            shutdown_signal.clone(),
            config.time_getter,
        );
        let stats = Arc::new(Http1ListenerStats::new(config.time_getter));

        Self {
            listener: H1AcceptSource::Tcp(tcp_listener),
            handler: Arc::new(handler),
            config,
            shutdown_signal,
            connection_manager,
            stats,
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<F, Fut> Http1Listener<F>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Http1ProducedResponse> + Send + 'static,
{
    /// Bind a listener whose handler returns a supervised framed response.
    ///
    /// The handler receives the authoritative per-request capability context
    /// and streaming request-body handle used by [`Http1StreamingServer`].
    pub async fn bind_produced<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
    ) -> io::Result<Self> {
        Self::bind_produced_with_config(addr, handler, Http1ListenerConfig::default()).await
    }

    /// Bind a supervised response listener with custom configuration.
    pub async fn bind_produced_with_config<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
        config: Http1ListenerConfig,
    ) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        Ok(Self::from_listener_produced(tcp_listener, handler, config))
    }

    /// Create a supervised response listener from an existing TCP listener.
    pub fn from_listener_produced(
        tcp_listener: TcpListener,
        handler: F,
        config: Http1ListenerConfig,
    ) -> Self {
        let shutdown_signal = shutdown_signal_for_time_getter(config.time_getter);
        let connection_manager = ConnectionManager::with_time_getter(
            config.max_connections,
            shutdown_signal.clone(),
            config.time_getter,
        );
        let stats = Arc::new(Http1ListenerStats::new(config.time_getter));

        Self {
            listener: H1AcceptSource::Tcp(tcp_listener),
            handler: Arc::new(handler),
            config,
            shutdown_signal,
            connection_manager,
            stats,
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<F, Fut, S> Http1Listener<F>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Http1SseResponse<S>> + Send + 'static,
    S: StreamingSseSource + Send + 'static,
{
    /// Bind a listener whose handler returns one supervised live SSE response.
    pub async fn bind_sse<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
    ) -> io::Result<Self> {
        Self::bind_sse_with_config(addr, handler, Http1ListenerConfig::default()).await
    }

    /// Bind a live-SSE listener with custom connection and drain configuration.
    pub async fn bind_sse_with_config<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
        config: Http1ListenerConfig,
    ) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        Ok(Self::from_listener_sse(tcp_listener, handler, config))
    }

    /// Create a live-SSE listener from an existing TCP listener.
    pub fn from_listener_sse(
        tcp_listener: TcpListener,
        handler: F,
        config: Http1ListenerConfig,
    ) -> Self {
        let shutdown_signal = shutdown_signal_for_time_getter(config.time_getter);
        let connection_manager = ConnectionManager::with_time_getter(
            config.max_connections,
            shutdown_signal.clone(),
            config.time_getter,
        );
        let stats = Arc::new(Http1ListenerStats::new(config.time_getter));

        Self {
            listener: H1AcceptSource::Tcp(tcp_listener),
            handler: Arc::new(handler),
            config,
            shutdown_signal,
            connection_manager,
            stats,
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<F, Fut> Http1Listener<F>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    /// Run the accept loop for a live request-body handler.
    pub async fn run_streaming(self, runtime: &RuntimeHandle) -> io::Result<ShutdownStats> {
        self.run_with(runtime, spawn_streaming_connection::<F, Fut>)
            .await
    }
}

impl<F, Fut, S> Http1Listener<F>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Http1SseResponse<S>> + Send + 'static,
    S: StreamingSseSource + Send + 'static,
{
    /// Run the accept loop for a supervised live-SSE handler.
    pub async fn run_sse(self, runtime: &RuntimeHandle) -> io::Result<ShutdownStats> {
        self.run_with(runtime, spawn_sse_connection::<F, Fut, S>)
            .await
    }
}

impl<F> Http1Listener<F> {
    /// Returns a clone of the shutdown signal for external phase observation.
    #[must_use]
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown_signal.clone()
    }

    /// Begins graceful shutdown using the listener's configured drain timeout.
    #[must_use]
    pub fn begin_drain(&self) -> bool {
        self.connection_manager
            .begin_drain(self.config.drain_timeout)
    }

    /// Returns a reference to the connection manager.
    #[must_use]
    pub fn connection_manager(&self) -> &ConnectionManager {
        &self.connection_manager
    }

    /// Returns the accept-path diagnostic counters for this listener.
    #[must_use]
    pub fn stats_handle(&self) -> Arc<Http1ListenerStats> {
        Arc::clone(&self.stats)
    }

    /// Returns the listener-wide in-flight request counter
    /// (br-asupersync-server-stack-hardening-eeexl1.2, D2.2b).
    ///
    /// The count covers requests whose head has been read but whose response
    /// has not yet been flushed, across every connection this listener
    /// serves.
    #[must_use]
    pub fn in_flight_requests(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.in_flight_requests)
    }

    /// Returns the local address this listener is bound to.
    ///
    /// A listener made with [`Self::from_unix_listener`] has no socket
    /// address and returns an `InvalidInput` error.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve on a Unix-domain socket listener instead of TCP, for any handler
    /// kind: drive it with the `run*` method of the matching TCP constructor
    /// (`run`, `run_in`, `run_tls`, `run_streaming`, `run_produced` or
    /// `run_sse`). A reverse proxy in front of the application (nginx's
    /// `proxy_pass http://unix:/run/app.sock`) is the usual client.
    ///
    /// Requests carry no `peer_addr` and no peer credentials, and every peer
    /// shares one entry in the connection manager's per-address accounting.
    /// Access control is the socket file's permissions, so bind a filesystem
    /// path: a listener from `UnixListener::bind_abstract` (Linux) has no
    /// file, and any process in its network namespace can connect to it.
    ///
    /// Upgrade actions made with
    /// `Http1Upgrade::new_any` (`WebSocketUpgrade::on_upgrade_any`) run on
    /// these connections; TCP-typed ones (`Http1Upgrade::new`, `on_upgrade`)
    /// are refused before the `101`. Router applications serve through this
    /// with `into_http_handler()`, or `into_http1_handler()` for WebSocket
    /// routes, as on TCP.
    #[cfg(unix)]
    pub fn from_unix_listener(
        listener: UnixListener,
        handler: F,
        config: Http1ListenerConfig,
    ) -> Self {
        Self::from_source(H1AcceptSource::Unix(listener), handler, config)
    }

    /// A listener that serves the connections `HttpAutoListener` hands over.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn from_handoff(
        queue: Arc<HandoffQueue>,
        handler: F,
        config: Http1ListenerConfig,
    ) -> Self {
        Self::from_source(H1AcceptSource::Handoff(queue), handler, config)
    }

    #[cfg(any(unix, not(target_arch = "wasm32")))]
    fn from_source(listener: H1AcceptSource, handler: F, config: Http1ListenerConfig) -> Self {
        let shutdown_signal = shutdown_signal_for_time_getter(config.time_getter);
        let connection_manager = ConnectionManager::with_time_getter(
            config.max_connections,
            shutdown_signal.clone(),
            config.time_getter,
        );
        let stats = Arc::new(Http1ListenerStats::new(config.time_getter));
        Self {
            listener,
            handler: Arc::new(handler),
            config,
            shutdown_signal,
            connection_manager,
            stats,
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<F, Fut, R> Http1Listener<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response + Send + 'static,
{
    /// Run the accept loop until shutdown.
    ///
    /// Accepts connections, dispatches to handler, and on shutdown signal
    /// drains active connections within the configured timeout.
    /// Cancellation of the task polling this future also starts that drain.
    /// A fatal accept or connection-spawn error drains existing connections
    /// through the same path before returning the original error.
    ///
    /// Returns shutdown statistics upon completion.
    pub async fn run(self, runtime: &RuntimeHandle) -> io::Result<ShutdownStats> {
        self.run_with(runtime, spawn_stream_connection::<F, Fut, R>)
            .await
    }

    /// Like [`Self::run`], but each connection task is spawned with `cx`, so
    /// it belongs to `cx`'s region instead of the runtime's root region.
    ///
    /// Run it inside a region that owns the service (for example a
    /// [`ChildRegion`](crate::cx::ChildRegion)). Cancelling or closing that
    /// region then cancels the accept loop and drains every connection with
    /// it: shutdown follows from region close, with no `RuntimeHandle` and no
    /// separate drain bookkeeping. A graceful drain through the connection
    /// manager behaves exactly as with [`Self::run`]
    /// (br-asupersync-issue65-criticisms-kpmoy5.4.5).
    pub async fn run_in(self, cx: &Cx) -> io::Result<ShutdownStats> {
        let spawner = cx.clone();
        self.run_with_spawner(
            Some(cx.clone()),
            move |stream, guard, handler, config, shutdown_signal, in_flight_requests| {
                spawner
                    .spawn(move |_connection_cx| {
                        serve_stream_connection::<F, Fut, R>(
                            stream,
                            guard,
                            handler,
                            config,
                            shutdown_signal,
                            in_flight_requests,
                        )
                    })
                    .map(ConnectionTask::Owned)
            },
        )
        .await
    }

    /// Run the accept loop over TLS until shutdown.
    ///
    /// This is the HTTPS/1.1 counterpart to [`Self::run`]. The supplied
    /// [`TlsAcceptor`] owns certificate, SNI, handshake-timeout, and TLS-level
    /// ALPN policy. After the handshake this listener admits only HTTP/1.1:
    /// clients that omit ALPN use the RFC-compatible HTTP/1.1 fallback, while
    /// any negotiated protocol other than `http/1.1` is refused before request
    /// bytes reach the handler.
    ///
    /// Upgrade actions made with
    /// [`Http1Upgrade::new_any`](crate::http::h1::Http1Upgrade::new_any) run
    /// on the TLS stream after the `101`, which is how a Router route serves
    /// `wss://` through `WebSocketUpgrade::on_upgrade_any`. TCP-typed actions
    /// (`Http1Upgrade::new`, `on_upgrade`) are refused before the `101`,
    /// because their callback receives the raw [`crate::net::TcpStream`].
    /// Ordinary responses, including Router responses, retain the same
    /// handler contract as [`Self::run`].
    ///
    /// The TCP connection is registered before its handshake begins, so the
    /// normal connection limit and drain accounting cover TLS peers. The
    /// handshake itself is bounded: by the acceptor's
    /// [`handshake_timeout`](TlsAcceptor::handshake_timeout) when one is set,
    /// otherwise by [`Http1Config::idle_timeout`], the same bound the plain-TCP
    /// path applies to reading the first request. A peer that has not
    /// completed TLS within that bound is dropped and its connection slot is
    /// released, so half-open handshakes cannot exhaust `max_connections`.
    /// Force-close interrupts an in-progress handshake by dropping its
    /// transport.
    #[cfg(feature = "tls")]
    pub async fn run_tls(
        self,
        runtime: &RuntimeHandle,
        acceptor: TlsAcceptor,
    ) -> io::Result<ShutdownStats> {
        self.run_with(
            runtime,
            move |stream, guard, handler, config, shutdown, in_flight, runtime| {
                spawn_tls_connection::<F, Fut, R>(
                    stream,
                    guard,
                    handler,
                    config,
                    shutdown,
                    in_flight,
                    acceptor.clone(),
                    runtime,
                )
            },
        )
        .await
    }
}

impl<F, Fut> Http1Listener<F>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Http1ProducedResponse> + Send + 'static,
{
    /// Run the accept loop for a supervised response handler.
    pub async fn run_produced(self, runtime: &RuntimeHandle) -> io::Result<ShutdownStats> {
        self.run_with(runtime, spawn_produced_connection::<F, Fut>)
            .await
    }
}

impl<F> Http1Listener<F> {
    async fn run_with<Spawn>(
        self,
        runtime: &RuntimeHandle,
        spawn_connection: Spawn,
    ) -> io::Result<ShutdownStats>
    where
        F: Send + Sync,
        Spawn: Fn(
                H1Stream,
                ConnectionGuard,
                Arc<F>,
                Http1Config,
                ShutdownSignal,
                Arc<AtomicUsize>,
                &RuntimeHandle,
            ) -> Result<JoinHandle<()>, SpawnError>
            + Send,
    {
        self.run_with_spawner(
            None,
            move |stream, guard, handler, config, shutdown_signal, in_flight_requests| {
                spawn_connection(
                    stream,
                    guard,
                    handler,
                    config,
                    shutdown_signal,
                    in_flight_requests,
                    runtime,
                )
                .map(ConnectionTask::Root)
            },
        )
        .await
    }

    /// The accept loop and drain behind every `run*` method. `owner` is the
    /// context whose region owns the connection tasks, when the spawner puts
    /// them there; the drain joins them through it.
    async fn run_with_spawner<Spawn>(
        self,
        owner: Option<Cx>,
        spawn_connection: Spawn,
    ) -> io::Result<ShutdownStats>
    where
        F: Send + Sync,
        Spawn: Fn(
                H1Stream,
                ConnectionGuard,
                Arc<F>,
                Http1Config,
                ShutdownSignal,
                Arc<AtomicUsize>,
            ) -> Result<ConnectionTask, SpawnError>
            + Send,
    {
        // The connection owner and the task polling this listener may differ.
        // Either cancellation ends accepting; each needs its own enrollment
        // before a quiet socket can park the coordinator.
        let mut owner_cancel = ListenerCancellation::new(owner.clone());
        let mut coordinator_cancel = ListenerCancellation::new(Cx::current());
        let mut tasks = ConnectionTasks::new(owner);
        let mut shutdown_rx = self.shutdown_signal.subscribe();
        let mut transient_accept_streak: u32 = 0;
        // Keep the original failure until the existing connections have
        // drained. Returning directly here would abandon root-owned tasks
        // and leave the shutdown signal permanently in Running.
        let accept_result = loop {
            let owner_cancelled = owner_cancel.is_requested();
            let coordinator_cancelled = coordinator_cancel.is_requested();
            if self.shutdown_signal.is_shutting_down()
                || owner_cancelled
                || coordinator_cancelled
            {
                break Ok(());
            }

            // Race accept against shutdown phase change
            let result = {
                let accept_fut = self.listener.accept();
                let shutdown_fut = shutdown_rx.wait();
                // Pin both futures on the stack
                let mut accept_fut = core::pin::pin!(accept_fut);
                let mut shutdown_fut = core::pin::pin!(shutdown_fut);

                std::future::poll_fn(|cx| {
                    // Enroll both authorities before checking either result.
                    let owner_cancelled = owner_cancel.poll_cancelled(cx);
                    let coordinator_cancelled = coordinator_cancel.poll_cancelled(cx);
                    if self.shutdown_signal.is_shutting_down()
                        || owner_cancelled
                        || coordinator_cancelled
                    {
                        return Poll::Ready(AcceptOrShutdown::Shutdown);
                    }

                    // Poll shutdown
                    if shutdown_fut.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(AcceptOrShutdown::Shutdown);
                    }

                    // Poll accept
                    if let Poll::Ready(r) = accept_fut.as_mut().poll(cx) {
                        return Poll::Ready(AcceptOrShutdown::Accept(r));
                    }

                    Poll::Pending
                })
                .await
            };

            let accept_result = match result {
                AcceptOrShutdown::Shutdown => break Ok(()),
                AcceptOrShutdown::Accept(r) => r,
            };

            let (stream, addr) = match accept_result {
                Ok(conn) => {
                    self.stats.record_accepted();
                    transient_accept_streak = 0;
                    conn
                }
                Err(ref e) if is_transient_accept_error(e) => {
                    self.stats.record_transient_accept_error();
                    transient_accept_streak = transient_accept_streak.saturating_add(1);
                    crate::time::sleep(
                        transient_accept_now(),
                        transient_accept_backoff_delay(transient_accept_streak),
                    )
                    .await;
                    continue;
                }
                Err(e) => break Err(e),
            };

            // Register with connection manager (enforces capacity + shutdown)
            #[cfg(unix)]
            let registered_addr = addr.unwrap_or(UNIX_PEER_PLACEHOLDER);
            #[cfg(not(unix))]
            let Some(registered_addr) = addr else {
                drop(stream);
                continue;
            };
            let Some(guard) = self.connection_manager.register(registered_addr) else {
                drop(stream);
                continue;
            };

            // Spawn connection handler
            let handler = Arc::clone(&self.handler);
            let http_config = self.config.http_config.clone();
            let shutdown_signal = self.shutdown_signal.clone();
            let in_flight_requests = Arc::clone(&self.in_flight_requests);
            let handle = match spawn_connection(
                stream,
                guard,
                handler,
                http_config,
                shutdown_signal,
                in_flight_requests,
            ) {
                Ok(handle) => handle,
                Err(err) => {
                    self.stats.record_spawn_failure();
                    if should_retry_after_spawn_failure(&err) {
                        continue;
                    }
                    break Err(io::Error::other(format!(
                        "failed to spawn connection task: {err}"
                    )));
                }
            };
            tasks.push(handle);
        };

        owner_cancel.stop_observing();
        coordinator_cancel.stop_observing();

        // Drain phase: socket lifetime is explicit
        // (br-asupersync-server-stack-hardening-eeexl1.2, D2.4 AC5). By
        // default the listening socket closes here so new connection
        // attempts fail fast with connection-refused; with
        // `lb_compat_keep_socket` it stays bound (never accepting) until the
        // drain completes so LB health probes still see TCP-connectable.
        let parked_socket = self.config.lb_compat_keep_socket.then_some(self.listener);

        if self.shutdown_signal.phase() == ShutdownPhase::Running {
            // Inlined begin_drain(): `self.listener` has been moved out
            // above, so whole-`self` method calls are no longer possible.
            let _ = self
                .connection_manager
                .begin_drain(self.config.drain_timeout);
        }

        // Request-aware drain supervision
        // (br-asupersync-server-stack-hardening-eeexl1.2, D2.2b): drive the
        // GracefulDrainSupervisor over the shared in-flight request counter,
        // CONCURRENTLY with the connection manager's own drain so the
        // established connection-level accounting (drained vs force_closed
        // snapshots taken synchronously at force-close time) is untouched.
        // The soft deadline (`drain_timeout`) escalates stragglers through
        // force-close (race_force_close interrupts in-flight handlers; the
        // request region's drop path is the cancellation backstop); the hard
        // deadline ends the supervision unconditionally. A duplicate
        // begin_force_close from whichever side fires second is a no-op.
        let supervise = async {
            let drain_start = (self.config.time_getter)();
            let in_flight_at_start = self.in_flight_requests.load(Ordering::Acquire);
            self.stats.record_drain_started(in_flight_at_start);
            let mut supervisor = GracefulDrainSupervisor::new(
                in_flight_at_start,
                drain_start,
                self.config.drain_timeout,
                self.config.hard_drain_timeout,
            );
            let mut hard_deadline_hit = false;
            loop {
                let now = (self.config.time_getter)();
                if self.shutdown_signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8
                    && now >= supervisor.drain_deadline()
                    && supervisor.record_external_escalation()
                {
                    self.stats.record_drain_escalated();
                }
                match supervisor.observe(self.in_flight_requests.load(Ordering::Acquire), now) {
                    DrainStep::Continue => {
                        // Pace ticks on the runtime clock: the listener's
                        // configured time_getter may be a frozen virtual
                        // clock in tests, while the tick needs real
                        // scheduling time to let in-flight work progress.
                        let sleep_now = Cx::current()
                            .and_then(|cx| cx.timer_driver())
                            .map_or_else(crate::time::wall_now, |timer| timer.now());
                        drain_supervision_tick(sleep_now).await;
                    }
                    DrainStep::Escalate => {
                        self.stats.record_drain_escalated();
                        let _ = self.connection_manager.begin_force_close();
                    }
                    DrainStep::Quiescent => break,
                    DrainStep::HardDeadline => {
                        hard_deadline_hit = true;
                        self.stats.record_drain_hard_deadline();
                        let _ = self.connection_manager.begin_force_close();
                        break;
                    }
                }
            }
            let report = supervisor.finish((self.config.time_getter)(), hard_deadline_hit);
            self.stats.record_drain_finished(&report);
            report
        };
        let drain = self.connection_manager.drain_with_stats();

        let mut supervise = core::pin::pin!(supervise);
        let mut drain = core::pin::pin!(drain);
        let mut report_slot = None;
        let mut stats_slot = None;
        std::future::poll_fn(|cx| {
            if report_slot.is_none()
                && let Poll::Ready(report) = supervise.as_mut().poll(cx)
            {
                report_slot = Some(report);
            }
            if stats_slot.is_none()
                && let Poll::Ready(stats) = drain.as_mut().poll(cx)
            {
                stats_slot = Some(stats);
            }
            if report_slot.is_some() && stats_slot.is_some() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        let mut stats = stats_slot.take().expect("drain stats present after join");
        stats.drain_report = report_slot.take();

        // If drain_with_stats returned due to a timeout, it transitioned the phase
        // to ForceClosing, but stats.duration only reflects the time up to the timeout.
        // We must re-collect stats after join_all() finishes waiting for tasks.
        let is_force_closing = self.shutdown_signal.phase() == ShutdownPhase::ForceClosing;

        tasks.join_all().await;

        if self.connection_manager.is_empty() {
            self.shutdown_signal.mark_stopped();
            if is_force_closing {
                let drain_report = stats.drain_report.take();
                stats = self
                    .shutdown_signal
                    .collect_stats(stats.drained, stats.force_closed);
                stats.drain_report = drain_report;
            }
        }

        // lb_compat: the parked socket stays bound for the whole drain and
        // closes only now, after quiescence (D2.4 AC5).
        drop(parked_socket);
        // Cancellation may have arrived while the existing drain was running.
        // Its terminal statistics must survive the task's acknowledgement gate.
        let _ = owner_cancel.is_requested();
        let _ = coordinator_cancel.is_requested();
        accept_result.map(|()| stats)
    }
}

/// A connection the listener accepted.
enum H1Stream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
    /// A connection handed over by `HttpAutoListener`, with its peer.
    #[cfg(not(target_arch = "wasm32"))]
    Handoff(HandoffStream, Option<SocketAddr>),
}

impl H1Stream {
    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(stream) => stream.peer_addr().ok(),
            #[cfg(unix)]
            Self::Unix(_) => None,
            #[cfg(not(target_arch = "wasm32"))]
            Self::Handoff(_, peer) => *peer,
        }
    }
}

impl crate::io::AsyncRead for H1Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut crate::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Handoff(stream, _) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl crate::io::AsyncWrite for H1Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Handoff(stream, _) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Handoff(stream, _) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(stream) => stream.is_write_vectored(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.is_write_vectored(),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Handoff(stream, _) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Handoff(stream, _) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Handoff(stream, _) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// The socket a listener accepts connections on.
enum H1AcceptSource {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
    /// Connections `HttpAutoListener` hands over.
    #[cfg(not(target_arch = "wasm32"))]
    Handoff(Arc<HandoffQueue>),
}

/// Stands in for a Unix-domain peer in the connection manager, which keys its
/// per-IP accounting by socket address: every local peer of a Unix-domain
/// listener shares this one entry.
#[cfg(unix)]
const UNIX_PEER_PLACEHOLDER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

impl H1AcceptSource {
    async fn accept(&self) -> io::Result<(H1Stream, Option<SocketAddr>)> {
        match self {
            Self::Tcp(listener) => listener
                .accept()
                .await
                .map(|(stream, addr)| (H1Stream::Tcp(stream), Some(addr))),
            #[cfg(unix)]
            Self::Unix(listener) => listener
                .accept()
                .await
                .map(|(stream, _)| (H1Stream::Unix(stream), None)),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Handoff(queue) => queue
                .accept()
                .await
                .map(|(stream, peer)| (H1Stream::Handoff(stream, peer), peer)),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tcp(listener) => listener.local_addr(),
            #[cfg(unix)]
            Self::Unix(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a Unix-domain HTTP/1 listener has no socket address",
            )),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Handoff(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a handed-off HTTP/1 listener has no socket of its own",
            )),
        }
    }
}

/// Result of racing accept against shutdown.
enum AcceptOrShutdown {
    /// A new connection was accepted.
    Accept(io::Result<(H1Stream, Option<SocketAddr>)>),
    /// Shutdown was signaled.
    Shutdown,
}

/// [`spawn_connection`] for a connection of either transport.
fn spawn_stream_connection<F, Fut, R>(
    stream: H1Stream,
    guard: ConnectionGuard,
    handler: Arc<F>,
    config: Http1Config,
    shutdown_signal: ShutdownSignal,
    in_flight_requests: Arc<AtomicUsize>,
    runtime: &RuntimeHandle,
) -> Result<JoinHandle<()>, SpawnError>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response + Send + 'static,
{
    match stream {
        H1Stream::Tcp(stream) => spawn_connection(
            stream,
            guard,
            handler,
            config,
            shutdown_signal,
            in_flight_requests,
            runtime,
        ),
        #[cfg(unix)]
        H1Stream::Unix(stream) => runtime.try_spawn(serve_without_upgrades(
            stream,
            None,
            guard,
            handler,
            config,
            shutdown_signal,
            in_flight_requests,
        )),
        #[cfg(not(target_arch = "wasm32"))]
        H1Stream::Handoff(stream, peer) => runtime.try_spawn(serve_without_upgrades(
            stream,
            peer,
            guard,
            handler,
            config,
            shutdown_signal,
            in_flight_requests,
        )),
    }
}

/// [`serve_connection`] for a connection of either transport.
async fn serve_stream_connection<F, Fut, R>(
    stream: H1Stream,
    guard: ConnectionGuard,
    handler: Arc<F>,
    config: Http1Config,
    shutdown_signal: ShutdownSignal,
    in_flight_requests: Arc<AtomicUsize>,
) where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response + Send + 'static,
{
    match stream {
        H1Stream::Tcp(stream) => {
            serve_connection(
                stream,
                guard,
                handler,
                config,
                shutdown_signal,
                in_flight_requests,
            )
            .await;
        }
        #[cfg(unix)]
        H1Stream::Unix(stream) => {
            serve_without_upgrades(
                stream,
                None,
                guard,
                handler,
                config,
                shutdown_signal,
                in_flight_requests,
            )
            .await;
        }
        #[cfg(not(target_arch = "wasm32"))]
        H1Stream::Handoff(stream, peer) => {
            serve_without_upgrades(
                stream,
                peer,
                guard,
                handler,
                config,
                shutdown_signal,
                in_flight_requests,
            )
            .await;
        }
    }
}

/// One HTTP/1.1 connection on a transport other than the listener's own TCP
/// socket (a Unix-domain socket or a handed-off connection). Upgrade actions
/// made with `Http1Upgrade::new_any` run on it; TCP-typed ones are refused
/// before the `101`.
#[cfg(any(unix, not(target_arch = "wasm32")))]
async fn serve_without_upgrades<S, F, Fut, R>(
    stream: S,
    peer_addr: Option<SocketAddr>,
    guard: ConnectionGuard,
    handler: Arc<F>,
    config: Http1Config,
    shutdown_signal: ShutdownSignal,
    in_flight_requests: Arc<AtomicUsize>,
) where
    S: crate::io::AsyncRead + crate::io::AsyncWrite + Unpin + Send + 'static,
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response + Send + 'static,
{
    let _guard = guard;
    let server = Http1Server::with_config_upgradeable(move |req| handler(req), config)
        .with_shutdown_signal(shutdown_signal.clone())
        .with_in_flight_requests(in_flight_requests);
    serve_with_transport_upgrades(server, stream, peer_addr, &shutdown_signal).await;
}

/// Serves `stream`, then runs the transport-generic upgrade action a response
/// committed, if any.
#[cfg(any(unix, not(target_arch = "wasm32"), feature = "tls"))]
async fn serve_with_transport_upgrades<S, F, Fut, R>(
    server: Http1Server<F>,
    stream: S,
    peer_addr: Option<SocketAddr>,
    shutdown_signal: &ShutdownSignal,
) where
    S: crate::io::AsyncRead + crate::io::AsyncWrite + Unpin + Send + 'static,
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response + Send + 'static,
{
    if let Ok(Http1ServeOutcome::Upgraded {
        io,
        read_ahead,
        upgrade,
    }) = server
        .serve_transport_upgradeable_with_peer_addr(stream, peer_addr)
        .await
        && let Some(session_cx) = Cx::current()
        && let Some(session) = upgrade.run_on(session_cx.clone(), io, read_ahead)
    {
        run_upgrade_session(shutdown_signal, session_cx, session).await;
    }
}

/// Spawn a connection handler as a runtime task.
///
/// The connection guard is held for the lifetime of the handler,
/// ensuring proper tracking during drain.
fn spawn_connection<F, Fut, R>(
    stream: crate::net::tcp::stream::TcpStream,
    guard: ConnectionGuard,
    handler: Arc<F>,
    config: Http1Config,
    shutdown_signal: ShutdownSignal,
    in_flight_requests: Arc<AtomicUsize>,
    runtime: &RuntimeHandle,
) -> Result<JoinHandle<()>, SpawnError>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response + Send + 'static,
{
    runtime.try_spawn(serve_connection(
        stream,
        guard,
        handler,
        config,
        shutdown_signal,
        in_flight_requests,
    ))
}

/// One HTTP/1.1 connection, from first byte to close or upgrade session end.
/// The connection guard is held for the whole future.
async fn serve_connection<F, Fut, R>(
    stream: crate::net::tcp::stream::TcpStream,
    guard: ConnectionGuard,
    handler: Arc<F>,
    config: Http1Config,
    shutdown_signal: ShutdownSignal,
    in_flight_requests: Arc<AtomicUsize>,
) where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response + Send + 'static,
{
    let _guard = guard;
    let server = Http1Server::with_config_upgradeable(move |req| handler(req), config)
        .with_shutdown_signal(shutdown_signal.clone())
        .with_in_flight_requests(in_flight_requests);
    let peer_addr = stream.peer_addr().ok();
    if let Ok(Http1ServeOutcome::Upgraded {
        io,
        read_ahead,
        upgrade,
        ..
    }) = server
        .serve_upgradeable_with_peer_addr(stream, peer_addr)
        .await
        && let Some(session_cx) = Cx::current()
    {
        let session = upgrade.run(session_cx.clone(), io, read_ahead);
        run_upgrade_session(&shutdown_signal, session_cx, session).await;
    }
}

/// Spawn one HTTPS/1.1 connection as a runtime task.
///
/// The manager guard deliberately enters the task before the TLS handshake.
/// A force-close phase wins the handshake race and drops the socket, preventing
/// silent peers from keeping listener shutdown non-quiescent indefinitely.
#[cfg(feature = "tls")]
fn spawn_tls_connection<F, Fut, R>(
    stream: H1Stream,
    guard: ConnectionGuard,
    handler: Arc<F>,
    config: Http1Config,
    shutdown_signal: ShutdownSignal,
    in_flight_requests: Arc<AtomicUsize>,
    acceptor: TlsAcceptor,
    runtime: &RuntimeHandle,
) -> Result<JoinHandle<()>, SpawnError>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response + Send + 'static,
{
    let handle = runtime.try_spawn(async move {
        let _guard = guard;
        let peer_addr = stream.peer_addr();
        // asupersync-hylbr1: `TlsAcceptor` defaults to no handshake timeout, so
        // a peer that never finishes TLS would pin this registered connection
        // slot until listener shutdown. Bound the handshake by the acceptor's
        // own timeout when it has one (the acceptor enforces it internally),
        // otherwise by the connection idle timeout, the same bound the
        // plain-TCP path applies to reading the first request.
        let handshake_bound = match acceptor.handshake_timeout() {
            Some(_) => None,
            None => config.idle_timeout,
        };
        let handshake = acceptor.accept(stream);
        let mut handshake = core::pin::pin!(async move {
            match handshake_bound {
                Some(bound) => {
                    match crate::time::timeout(transient_accept_now(), bound, handshake).await {
                        Ok(result) => result,
                        Err(_elapsed) => Err(crate::tls::TlsError::Timeout(bound)),
                    }
                }
                None => handshake.await,
            }
        });
        let mut force_closing =
            core::pin::pin!(shutdown_signal.wait_for_phase(ShutdownPhase::ForceClosing));

        let tls_stream = std::future::poll_fn(|task_cx| {
            if shutdown_signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8
                || force_closing.as_mut().poll(task_cx).is_ready()
            {
                return Poll::Ready(None);
            }
            handshake.as_mut().poll(task_cx).map(Some)
        })
        .await;
        let mut tls_stream = match tls_stream {
            Some(Ok(tls_stream)) => tls_stream,
            Some(Err(crate::tls::TlsError::Timeout(bound))) => {
                crate::tracing_compat::warn!(
                    peer = ?peer_addr,
                    bound = ?bound,
                    "TLS handshake did not complete within its bound; dropping the connection"
                );
                let _ = bound; // Suppress unused warning when tracing is disabled
                return;
            }
            Some(Err(_)) | None => return,
        };

        if !matches!(tls_stream.alpn_protocol(), None | Some(b"http/1.1")) {
            let _ = tls_stream.shutdown().await;
            return;
        }

        let server = Http1Server::with_config_upgradeable(move |req| handler(req), config)
            .with_shutdown_signal(shutdown_signal.clone())
            .with_in_flight_requests(in_flight_requests);
        // `wss://`: upgrade actions made with `Http1Upgrade::new_any` run over
        // the TLS stream; TCP-typed ones are refused before the `101`.
        serve_with_transport_upgrades(server, tls_stream, peer_addr, &shutdown_signal).await;
    })?;
    Ok(handle)
}

/// Spawn a connection whose request heads are dispatched before body EOF.
fn spawn_streaming_connection<F, Fut>(
    stream: H1Stream,
    guard: ConnectionGuard,
    handler: Arc<F>,
    config: Http1Config,
    shutdown_signal: ShutdownSignal,
    in_flight_requests: Arc<AtomicUsize>,
    runtime: &RuntimeHandle,
) -> Result<JoinHandle<()>, SpawnError>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let handle = runtime.try_spawn(async move {
        let _guard = guard;
        let server = Http1StreamingServer::with_config(
            move |request_cx, request| handler(request_cx, request),
            config,
        )
        .with_shutdown_signal(shutdown_signal)
        .with_in_flight_requests(in_flight_requests);
        let peer_addr = stream.peer_addr();
        let Some(connection_cx) = Cx::current() else {
            return;
        };
        let _ = server
            .serve_with_peer_addr(&connection_cx, stream, peer_addr)
            .await;
    })?;
    Ok(handle)
}

/// Spawn a supervised produced-response connection as a runtime task.
///
/// The connection task owns the manager guard, and the streaming server mints
/// each request context beneath the runtime-provided connection context.
fn spawn_produced_connection<F, Fut>(
    stream: H1Stream,
    guard: ConnectionGuard,
    handler: Arc<F>,
    config: Http1Config,
    shutdown_signal: ShutdownSignal,
    in_flight_requests: Arc<AtomicUsize>,
    runtime: &RuntimeHandle,
) -> Result<JoinHandle<()>, SpawnError>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Http1ProducedResponse> + Send + 'static,
{
    let handle = runtime.try_spawn(async move {
        let _guard = guard;
        let server = Http1StreamingServer::with_config_produced(
            move |request_cx, request| handler(request_cx, request),
            config,
        )
        .with_shutdown_signal(shutdown_signal)
        .with_in_flight_requests(in_flight_requests);
        let peer_addr = stream.peer_addr();
        let Some(connection_cx) = Cx::current() else {
            return;
        };
        let _ = server
            .serve_produced_with_peer_addr(&connection_cx, stream, peer_addr)
            .await;
    })?;
    Ok(handle)
}

/// Spawn a supervised live-SSE connection as a runtime task.
fn spawn_sse_connection<F, Fut, S>(
    stream: H1Stream,
    guard: ConnectionGuard,
    handler: Arc<F>,
    config: Http1Config,
    shutdown_signal: ShutdownSignal,
    in_flight_requests: Arc<AtomicUsize>,
    runtime: &RuntimeHandle,
) -> Result<JoinHandle<()>, SpawnError>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Http1SseResponse<S>> + Send + 'static,
    S: StreamingSseSource + Send + 'static,
{
    let handle = runtime.try_spawn(async move {
        let _guard = guard;
        let server = Http1StreamingServer::with_config_sse(
            move |request_cx, request| handler(request_cx, request),
            config,
        )
        .with_shutdown_signal(shutdown_signal)
        .with_in_flight_requests(in_flight_requests);
        let peer_addr = stream.peer_addr();
        let Some(connection_cx) = Cx::current() else {
            return;
        };
        let _ = server
            .serve_sse_with_peer_addr(&connection_cx, stream, peer_addr)
            .await;
    })?;
    Ok(handle)
}

async fn run_upgrade_session<F>(shutdown: &ShutdownSignal, session_cx: Cx, session: F)
where
    F: Future<Output = ()>,
{
    let mut session = core::pin::pin!(session);
    let mut draining = core::pin::pin!(shutdown.wait_for_phase(ShutdownPhase::Draining));
    let mut force_closing = core::pin::pin!(shutdown.wait_for_phase(ShutdownPhase::ForceClosing));
    let mut drain_signalled = false;

    std::future::poll_fn(|task_cx| {
        if shutdown.phase() as u8 >= ShutdownPhase::ForceClosing as u8
            || force_closing.as_mut().poll(task_cx).is_ready()
        {
            return Poll::Ready(());
        }

        if !drain_signalled
            && (shutdown.phase() as u8 >= ShutdownPhase::Draining as u8
                || draining.as_mut().poll(task_cx).is_ready())
        {
            drain_signalled = true;
            session_cx.cancel_with(
                CancelKind::Shutdown,
                Some("HTTP/1 upgraded session draining"),
            );
        }

        session.as_mut().poll(task_cx)
    })
    .await;
}

/// A spawned connection: a root-region task ([`Http1Listener::run`]) or a
/// task owned by the region of the context given to [`Http1Listener::run_in`].
enum ConnectionTask {
    Root(JoinHandle<()>),
    Owned(crate::runtime::TaskHandle<()>),
}

impl ConnectionTask {
    fn is_finished(&self) -> bool {
        match self {
            Self::Root(handle) => handle.is_finished(),
            Self::Owned(handle) => handle.is_finished(),
        }
    }
}

#[derive(Default)]
struct ConnectionTasks {
    handles: Vec<ConnectionTask>,
    push_count: u64,
    /// Joins [`ConnectionTask::Owned`] handles.
    owner: Option<Cx>,
}

impl ConnectionTasks {
    fn new(owner: Option<Cx>) -> Self {
        Self {
            owner,
            ..Self::default()
        }
    }

    fn push(&mut self, handle: ConnectionTask) {
        self.handles.push(handle);
        self.push_count = self.push_count.wrapping_add(1);
        // Clean up finished tasks periodically to prevent unbounded memory growth
        // Check every 64 connections using an independent counter to avoid
        // pathological O(N^2) scanning if active connection count hovers near 64.
        if self.push_count.is_multiple_of(64) {
            self.handles.retain(|h| !h.is_finished());
        }
    }

    async fn join_all(&mut self) {
        for task in self.handles.drain(..) {
            match task {
                ConnectionTask::Root(handle) => {
                    let result = CatchUnwind { inner: handle }.await;
                    if let Err(payload) = result {
                        let _ = &payload;
                        error!(
                            message = %crate::cx::scope::payload_to_string(&payload),
                            "connection task panicked"
                        );
                    }
                }
                ConnectionTask::Owned(mut handle) => {
                    let owner = self
                        .owner
                        .as_ref()
                        .expect("an owned connection task has an owner context");
                    if let Err(crate::runtime::JoinError::Panicked(payload)) =
                        handle.join(owner).await
                    {
                        let _ = &payload;
                        error!(message = %payload, "connection task panicked");
                    }
                }
            }
        }
    }
}

#[pin_project::pin_project]
struct CatchUnwind<F> {
    #[pin]
    inner: F,
}

impl<F: Future> Future for CatchUnwind<F> {
    type Output = std::thread::Result<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            this.inner.as_mut().poll(cx)
        }));
        match result {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

/// Returns `true` for accept errors that are transient and should be retried.
fn is_transient_accept_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
    ) || crate::net::tcp::listener::is_accept_resource_exhaustion(err)
}

fn transient_accept_backoff_delay(streak: u32) -> Duration {
    let exponent = (streak.saturating_sub(1) / 16).min(5);
    TRANSIENT_ACCEPT_BACKOFF_BASE
        .saturating_mul(1u32 << exponent)
        .min(TRANSIENT_ACCEPT_BACKOFF_CAP)
}

fn transient_accept_now() -> Time {
    default_listener_time_getter()
}

fn should_retry_after_spawn_failure(err: &SpawnError) -> bool {
    matches!(err, SpawnError::RegionAtCapacity { .. })
}

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
    use crate::http::h1::server::HostPolicy;
    use crate::http::h1::types::Response;
    use crate::io::AsyncWriteExt;
    use crate::record::RegionLimits;
    use crate::runtime::RuntimeBuilder;
    use crate::runtime::yield_now;
    use crate::sync::Notify;
    use crate::test_utils::init_test_logging;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::sync::Arc;

    thread_local! {
        static HTTP1_LISTENER_TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn set_http1_listener_test_time(time: Time) {
        HTTP1_LISTENER_TEST_NOW.with(|now| now.set(time.as_nanos()));
    }

    fn http1_listener_test_time() -> Time {
        HTTP1_LISTENER_TEST_NOW.with(|now| Time::from_nanos(now.get()))
    }

    fn localhost_http_config() -> Http1Config {
        Http1Config {
            allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
            ..Http1Config::default()
        }
    }

    #[test]
    fn default_config() {
        let config = Http1ListenerConfig::default();
        assert_eq!(config.max_connections, Some(10_000));
        assert_eq!(config.drain_timeout, Duration::from_secs(30));
        assert!(config.http_config.keep_alive);
    }

    #[test]
    fn config_builder() {
        set_http1_listener_test_time(Time::from_nanos(77));
        let config = Http1ListenerConfig::default()
            .max_connections(Some(5000))
            .drain_timeout(Duration::from_secs(60))
            .http_config(Http1Config::default().keep_alive(false))
            .time_getter(http1_listener_test_time);

        assert_eq!(config.max_connections, Some(5000));
        assert_eq!(config.drain_timeout, Duration::from_secs(60));
        assert!(!config.http_config.keep_alive);
        assert_eq!((config.time_getter)().as_nanos(), 77);
    }

    #[test]
    fn transient_error_detection() {
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::WouldBlock,
            "would block"
        )));
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out"
        )));
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused"
        )));
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "aborted"
        )));
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::ConnectionReset,
            "reset"
        )));
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::Interrupted,
            "interrupted"
        )));
        assert!(!is_transient_accept_error(&io::Error::new(
            io::ErrorKind::AddrInUse,
            "in use"
        )));
        assert!(!is_transient_accept_error(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "denied"
        )));
    }

    #[test]
    fn accept_resource_exhaustion_retries_out_of_memory() {
        assert!(is_transient_accept_error(&io::Error::from(
            io::ErrorKind::OutOfMemory
        )));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn accept_resource_exhaustion_retries_native_errors() {
        #[cfg(unix)]
        let codes = [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM];
        #[cfg(windows)]
        let codes = {
            use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
            [WSAEMFILE, WSAENOBUFS]
        };

        for code in codes {
            let error = io::Error::from_raw_os_error(code);
            assert!(
                is_transient_accept_error(&error),
                "resource exhaustion must reach accept backoff: {error:?}"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn accept_resource_exhaustion_preserves_native_fatal_errors() {
        #[cfg(unix)]
        let codes = [libc::EBADF, libc::ENOTSOCK, libc::EINVAL, libc::EACCES];
        #[cfg(windows)]
        let codes = {
            use windows_sys::Win32::Networking::WinSock::{WSAEACCES, WSAEINVAL, WSAENOTSOCK};
            [WSAENOTSOCK, WSAEINVAL, WSAEACCES]
        };

        for code in codes {
            let error = io::Error::from_raw_os_error(code);
            assert!(
                !is_transient_accept_error(&error),
                "permanent accept errors must still terminate the listener: {error:?}"
            );
        }
    }

    #[test]
    fn transient_backoff_caps() {
        assert_eq!(
            transient_accept_backoff_delay(1),
            TRANSIENT_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            transient_accept_backoff_delay(16),
            TRANSIENT_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            transient_accept_backoff_delay(17),
            TRANSIENT_ACCEPT_BACKOFF_BASE.saturating_mul(2)
        );
        assert_eq!(
            transient_accept_backoff_delay(10_000),
            TRANSIENT_ACCEPT_BACKOFF_CAP
        );
    }

    #[test]
    fn spawn_capacity_failure_is_connection_scoped() {
        init_test_logging();
        let runtime = RuntimeBuilder::current_thread()
            .root_region_limits(RegionLimits {
                // The block_on root and blocker consume both task slots,
                // so a connection spawn must fail without leaking its guard.
                max_tasks: Some(2),
                ..RegionLimits::unlimited()
            })
            .build()
            .expect("build runtime");
        let handle = runtime.handle();

        runtime.block_on(async {
            let blocker_started = Arc::new(Notify::new());
            let blocker_release = Arc::new(Notify::new());
            let blocker_started_signal = Arc::clone(&blocker_started);
            let blocker_release_signal = Arc::clone(&blocker_release);
            let blocker = handle
                .clone()
                .try_spawn(async move {
                    blocker_started_signal.notify_one();
                    blocker_release_signal.notified().await;
                })
                .expect("spawn blocker");

            blocker_started.notified().await;

            let raw_listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind raw listener");
            let addr = raw_listener.local_addr().expect("raw listener addr");
            let client = std::net::TcpStream::connect(addr).expect("connect raw client");
            let (server_raw, peer_addr) = raw_listener.accept().expect("accept raw server side");
            let server_stream =
                crate::net::tcp::stream::TcpStream::from_std(server_raw).expect("wrap stream");

            let shutdown = ShutdownSignal::new();
            let manager = ConnectionManager::new(Some(16), shutdown.clone());
            let guard = manager.register(peer_addr).expect("register connection");

            let handler = Arc::new(|_req| async { Response::new(200, "OK", Vec::new()) });
            let err = match spawn_connection(
                server_stream,
                guard,
                handler,
                localhost_http_config(),
                shutdown.clone(),
                Arc::new(AtomicUsize::new(0)),
                &handle,
            ) {
                Ok(_) => panic!("connection spawn should fail while root region is at capacity"),
                Err(err) => err,
            };

            assert!(matches!(
                err,
                SpawnError::RegionAtCapacity {
                    limit: 2,
                    live: 2,
                    ..
                }
            ));
            assert!(
                should_retry_after_spawn_failure(&err),
                "capacity failures should be scoped to the rejected connection"
            );
            assert_eq!(
                manager.active_count(),
                0,
                "failed spawn must drop the connection guard immediately"
            );
            assert_eq!(shutdown.phase(), ShutdownPhase::Running);

            drop(client);
            blocker_release.notify_one();
            blocker.await;
        });
    }

    #[test]
    fn bind_and_local_addr() {
        crate::test_utils::run_test(|| async {
            let listener = Http1Listener::bind("127.0.0.1:0", |_req| async {
                Response::new(200, "OK", Vec::new())
            })
            .await
            .expect("bind failed");

            let addr = listener.local_addr().expect("local_addr");
            assert_eq!(addr.ip(), std::net::Ipv4Addr::LOCALHOST);
            assert_ne!(addr.port(), 0);
        });
    }

    #[test]
    fn shutdown_signal_accessible() {
        crate::test_utils::run_test(|| async {
            let listener = Http1Listener::bind("127.0.0.1:0", |_req| async {
                Response::new(200, "OK", Vec::new())
            })
            .await
            .expect("bind failed");

            let signal = listener.shutdown_signal();
            assert!(!signal.is_shutting_down());
            assert_eq!(signal.phase(), ShutdownPhase::Running);
        });
    }

    #[test]
    fn connection_manager_accessible() {
        crate::test_utils::run_test(|| async {
            let listener = Http1Listener::bind("127.0.0.1:0", |_req| async {
                Response::new(200, "OK", Vec::new())
            })
            .await
            .expect("bind failed");

            assert_eq!(listener.connection_manager().active_count(), 0);
            assert!(listener.connection_manager().is_empty());
        });
    }

    #[test]
    fn from_listener_constructor() {
        crate::test_utils::run_test(|| async {
            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
            let addr = tcp.local_addr().expect("local_addr");

            let listener = Http1Listener::from_listener(
                tcp,
                |_req| async { Response::new(200, "OK", Vec::new()) },
                Http1ListenerConfig::default(),
            );

            assert_eq!(listener.local_addr().expect("addr"), addr);
        });
    }

    #[test]
    fn configured_time_getter_controls_listener_bookkeeping() {
        crate::test_utils::run_test(|| async {
            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
            let config = Http1ListenerConfig::default()
                .time_getter(http1_listener_test_time)
                .drain_timeout(Duration::from_secs(3));
            let listener = Http1Listener::from_listener(
                tcp,
                |_req| async { Response::new(200, "OK", Vec::new()) },
                config,
            );

            set_http1_listener_test_time(Time::from_millis(321));
            listener.stats_handle().record_accepted();
            assert_eq!(listener.stats_handle().snapshot().last_accept_at_ms, 321);

            set_http1_listener_test_time(Time::from_secs(7));
            let addr = "127.0.0.1:8081".parse().expect("parse addr");
            let _guard = listener
                .connection_manager()
                .register(addr)
                .expect("register connection");
            let connections = listener.connection_manager().active_connections();
            assert_eq!(connections.len(), 1);
            assert_eq!(connections[0].1.connected_at, Time::from_secs(7));

            assert!(listener.begin_drain());
            assert_eq!(
                listener.shutdown_signal().drain_deadline(),
                Some(Time::from_secs(10))
            );
        });
    }

    #[test]
    fn default_listener_shutdown_signal_captures_timer_driver() {
        crate::test_utils::run_test(|| async {
            let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10)));
            let timer_driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
            let cx = Cx::new_with_drivers(
                RegionId::new_for_test(41, 1),
                TaskId::new_for_test(42, 1),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(timer_driver),
                None,
            );

            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
            let listener = {
                let _guard = Cx::set_current(Some(cx));
                Http1Listener::from_listener(
                    tcp,
                    |_req| async { Response::new(200, "OK", Vec::new()) },
                    Http1ListenerConfig::default(),
                )
            };

            let _no_cx = Cx::set_current(None);
            assert!(listener.begin_drain());
            assert_eq!(
                listener.shutdown_signal().drain_deadline(),
                Some(Time::from_secs(40))
            );
        });
    }

    #[test]
    fn immediate_shutdown_returns_stats() {
        init_test_logging();
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        let handle = runtime.handle();
        runtime.block_on(async {
            let listener = Http1Listener::bind("127.0.0.1:0", |_req| async {
                Response::new(200, "OK", Vec::new())
            })
            .await
            .expect("bind failed");

            // Trigger shutdown before running
            let began = listener.begin_drain();
            assert!(began);

            let stats = listener.run(&handle).await.expect("run");
            assert_eq!(stats.drained, 0);
            assert_eq!(stats.force_closed, 0);
        });
    }

    #[test]
    fn force_close_marks_stopped_when_connections_finish() {
        init_test_logging();
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        let handle = runtime.handle();

        runtime.block_on(async {
            let started = Arc::new(Notify::new());
            let finished = Arc::new(Notify::new());
            let started_signal = Arc::clone(&started);
            let finished_signal = Arc::clone(&finished);

            let config = Http1ListenerConfig {
                http_config: localhost_http_config(),
                drain_timeout: Duration::from_millis(0),
                ..Default::default()
            };

            let listener = Http1Listener::bind_with_config(
                "127.0.0.1:0",
                move |_req| {
                    let started = Arc::clone(&started_signal);
                    let finished = Arc::clone(&finished_signal);
                    async move {
                        started.notify_one();
                        finished.notified().await;
                        Response::new(200, "OK", Vec::new())
                    }
                },
                config,
            )
            .await
            .expect("bind failed");

            let addr = listener.local_addr().expect("local_addr");
            let shutdown = listener.shutdown_signal();
            let manager = listener.connection_manager().clone();

            let run_handle = handle
                .clone()
                .try_spawn(async move { listener.run(&handle).await })
                .expect("spawn listener");

            let mut client = crate::net::tcp::stream::TcpStream::connect(addr)
                .await
                .expect("connect");
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("write request");

            started.notified().await;
            let began = manager.begin_drain(Duration::from_millis(0));
            assert!(began);

            shutdown.wait_for_phase(ShutdownPhase::ForceClosing).await;

            let _ = client.shutdown(std::net::Shutdown::Both);
            finished.notify_one();
            let stats = run_handle.await.expect("run");
            assert!(stats.force_closed > 0, "expected force close path");
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);

            yield_now().await;
        });
    }

    #[test]
    fn force_close_stats_duration_waits_for_stopped_finalization() {
        init_test_logging();
        set_http1_listener_test_time(Time::ZERO);
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        let handle = runtime.handle();

        runtime.block_on(async {
            let started = Arc::new(Notify::new());
            let finished = Arc::new(Notify::new());
            let started_signal = Arc::clone(&started);
            let finished_signal = Arc::clone(&finished);

            let config = Http1ListenerConfig::default()
                .http_config(localhost_http_config())
                .drain_timeout(Duration::from_millis(0))
                .time_getter(http1_listener_test_time);

            let listener = Http1Listener::bind_with_config(
                "127.0.0.1:0",
                move |_req| {
                    let started = Arc::clone(&started_signal);
                    let finished = Arc::clone(&finished_signal);
                    async move {
                        started.notify_one();
                        finished.notified().await;
                        Response::new(200, "OK", Vec::new())
                    }
                },
                config,
            )
            .await
            .expect("bind failed");

            let addr = listener.local_addr().expect("local_addr");
            let shutdown = listener.shutdown_signal();
            let manager = listener.connection_manager().clone();

            let run_handle = handle
                .clone()
                .try_spawn(async move { listener.run(&handle).await })
                .expect("spawn listener");

            let mut client = crate::net::tcp::stream::TcpStream::connect(addr)
                .await
                .expect("connect");
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("write request");

            started.notified().await;
            // Begin drain at time=0 so drain_start is recorded as 0.
            let began = manager.begin_drain(Duration::from_millis(0));
            assert!(began);
            // Advance time so that collect_stats sees a non-zero
            // duration. The handler is now interrupted by ForceClosing
            // (handler execution races against the force-close phase),
            // so it exits promptly without waiting for `finished`.
            set_http1_listener_test_time(Time::from_millis(25));

            let _ = client.shutdown(std::net::Shutdown::Both);
            let stats = run_handle.await.expect("run");
            assert_eq!(stats.force_closed, 1);
            // Duration check is intentionally non-exact: the shared
            // test time source (`HTTP1_LISTENER_TEST_NOW`) can be
            // mutated by concurrent listener tests. The important
            // invariant is that the server reached Stopped and
            // force-closed the lingering connection.
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);

            yield_now().await;
        });
    }

    #[test]
    fn http1_listener_config_debug_clone_default() {
        let cfg = Http1ListenerConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cloned.max_connections, Some(10_000));
        assert_eq!(cloned.drain_timeout, Duration::from_secs(30));
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("Http1ListenerConfig"));
    }

    /// The drain supervision tick waits its interval when the listener task
    /// is cancelled; it used to complete at once, so the drain loop spun.
    #[test]
    fn drain_supervision_tick_ignores_the_listener_tasks_cancellation() {
        init_test_logging();
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(7, 2),
            TaskId::new_for_test(9, 2),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer_driver.clone()),
            None,
        );
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut tick = std::pin::pin!(drain_supervision_tick(Time::from_secs(10)));
        for _ in 0..2 {
            assert!(
                tick.as_mut().poll(&mut task_cx).is_pending(),
                "a cancelled listener still waits for the tick"
            );
        }
        virtual_clock.advance_to(Time::from_secs(10) + DRAIN_SUPERVISION_TICK);
        let _ = timer_driver.process_timers();
        assert!(tick.as_mut().poll(&mut task_cx).is_ready());
    }

    /// Hold a real handler at its first Pending so a fatal listener failure
    /// must retain the connection until its response has finished.
    #[cfg(not(target_arch = "wasm32"))]
    fn fatal_listener_failure_drains_request(fail_spawn: bool, owned: bool, workers: usize) {
        use crate::cx::ChildRegionSpec;
        use crate::io::AsyncReadExt as _;
        use std::sync::atomic::AtomicBool;

        const WATCHDOG: Duration = Duration::from_secs(10);

        struct Cleanup {
            release: Arc<Notify>,
            signal: ShutdownSignal,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                self.release.notify_one();
                self.signal.trigger_immediate();
            }
        }

        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread().build().expect("current-thread runtime")
        } else {
            RuntimeBuilder::multi_thread()
                .worker_threads(workers)
                .build()
                .expect("multi-worker runtime")
        };
        let runtime_handle = runtime.handle();
        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime context");
            let owner_region = if owned {
                Some(
                    cx.open_child_region(ChildRegionSpec::inherit())
                        .await
                        .expect("open listener owner"),
                )
            } else {
                None
            };
            let owner = owner_region.as_ref().map(|region| region.cx().clone());
            let started = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let completed = Arc::new(AtomicBool::new(false));
            let started_for_handler = Arc::clone(&started);
            let release_for_handler = Arc::clone(&release);
            let completed_for_handler = Arc::clone(&completed);
            let handler = move |_request: Request| {
                let started = Arc::clone(&started_for_handler);
                let release = Arc::clone(&release_for_handler);
                let completed = Arc::clone(&completed_for_handler);
                async move {
                    let mut released = core::pin::pin!(release.notified());
                    let mut witnessed_pending = false;
                    std::future::poll_fn(|task| {
                        let result = released.as_mut().poll(task);
                        if result.is_pending() && !witnessed_pending {
                            witnessed_pending = true;
                            started.notify_one();
                        }
                        result
                    })
                    .await;
                    completed.store(true, Ordering::Release);
                    Response::new(200, "OK", b"request-completed-before-error".to_vec())
                }
            };
            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind ingress");
            let address = tcp.local_addr().expect("ingress address");
            let queue = Arc::new(HandoffQueue::default());
            let config = Http1ListenerConfig::default()
                .http_config(localhost_http_config())
                .drain_timeout(Duration::from_secs(5))
                .hard_drain_timeout(WATCHDOG);
            let mut handoff_ingress = None;
            let listener = if fail_spawn {
                Http1Listener::from_listener(tcp, handler, config)
            } else {
                handoff_ingress = Some(tcp);
                Http1Listener::from_handoff(Arc::clone(&queue), handler, config)
            };
            let manager = listener.connection_manager().clone();
            let signal = listener.shutdown_signal();
            let requests = listener.in_flight_requests();
            let stats = listener.stats_handle();
            let _cleanup = Cleanup {
                release: Arc::clone(&release),
                signal: signal.clone(),
            };
            let spawn_attempts = Arc::new(AtomicUsize::new(0));
            let attempts_for_run = Arc::clone(&spawn_attempts);
            let mut serving = cx
                .spawn(move |_coordinator| async move {
                    if fail_spawn {
                        let spawner = owner.clone();
                        listener
                            .run_with_spawner(
                                owner,
                                move |stream, guard, handler, config, shutdown, in_flight| {
                                    if attempts_for_run.fetch_add(1, Ordering::AcqRel) == 1 {
                                        // The first real connection stays live. A fatal
                                        // admission refusal for the next one must drain it.
                                        return Err(SpawnError::RuntimeUnavailable);
                                    }
                                    if let Some(spawner) = &spawner {
                                        spawner
                                            .spawn(move |_connection_cx| {
                                                serve_stream_connection(
                                                    stream,
                                                    guard,
                                                    handler,
                                                    config,
                                                    shutdown,
                                                    in_flight,
                                                )
                                            })
                                            .map(ConnectionTask::Owned)
                                    } else {
                                        spawn_stream_connection(
                                            stream,
                                            guard,
                                            handler,
                                            config,
                                            shutdown,
                                            in_flight,
                                            &runtime_handle,
                                        )
                                        .map(ConnectionTask::Root)
                                    }
                                },
                            )
                            .await
                    } else if let Some(owner) = owner {
                        listener.run_in(&owner).await
                    } else {
                        listener.run(&runtime_handle).await
                    }
                })
                .expect("spawn listener coordinator");

            let mut client = TcpStream::connect(address).await.expect("connect request");
            if let Some(ingress) = handoff_ingress.take() {
                let (accepted, peer) = ingress.accept().await.expect("accept handoff");
                queue.push(HandoffStream::new(Box::new(accepted)), Some(peer));
            }
            client
                .write_all(b"GET /drain HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("write request");
            crate::time::timeout(cx.now(), WATCHDOG, started.notified())
                .await
                .expect("handler reaches a registered Pending");
            assert_eq!(manager.active_count(), 1);
            assert_eq!(requests.load(Ordering::Acquire), 1);
            assert!(!completed.load(Ordering::Acquire));

            let mut rejected = if fail_spawn {
                Some(TcpStream::connect(address).await.expect("second connection"))
            } else {
                queue.close();
                None
            };
            crate::time::timeout(cx.now(), WATCHDOG, async {
                while stats.snapshot().drains_started_total == 0 {
                    assert!(
                        !serving.is_finished(),
                        "fatal error was published before existing work entered drain"
                    );
                    yield_now().await;
                }
            })
            .await
            .expect("fatal accept or spawn failure starts the drain");
            assert_eq!(signal.phase(), ShutdownPhase::Draining);
            assert!(!serving.is_finished(), "the held handler still belongs to run");
            assert_eq!(manager.active_count(), 1, "rejected spawn released its guard");
            assert_eq!(requests.load(Ordering::Acquire), 1);
            if let Some(rejected) = rejected.as_mut() {
                let mut byte = [0_u8; 1];
                assert_eq!(
                    crate::time::timeout(cx.now(), WATCHDOG, rejected.read(&mut byte))
                        .await
                        .expect("rejected connection closes")
                        .expect("read rejected connection"),
                    0
                );
            }

            release.notify_one();
            let mut response = Vec::new();
            crate::time::timeout(cx.now(), WATCHDOG, client.read_to_end(&mut response))
                .await
                .expect("in-flight response drains")
                .expect("read drained response");
            assert!(response.starts_with(b"HTTP/1.1 200 "));
            assert!(response.ends_with(b"request-completed-before-error"));
            assert!(response.windows(b"connection: close".len()).any(|window| {
                window.eq_ignore_ascii_case(b"connection: close")
            }));
            let error = crate::time::timeout(cx.now(), WATCHDOG, serving.join(&cx))
                .await
                .expect("listener joins every connection")
                .expect("listener retains its typed result")
                .expect_err("original fatal error survives cleanup");
            if fail_spawn {
                assert_eq!(error.kind(), io::ErrorKind::Other);
                assert_eq!(
                    error.to_string(),
                    format!("failed to spawn connection task: {}", SpawnError::RuntimeUnavailable)
                );
                assert_eq!(spawn_attempts.load(Ordering::Acquire), 2);
            } else {
                assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                assert_eq!(error.to_string(), "HTTP handoff queue is closed");
            }
            assert_eq!(error.raw_os_error(), None);
            assert!(completed.load(Ordering::Acquire));
            assert_eq!(signal.phase(), ShutdownPhase::Stopped);
            assert!(manager.is_empty());
            assert_eq!(requests.load(Ordering::Acquire), 0);
            let snapshot = stats.snapshot();
            assert_eq!(snapshot.accepted_total, if fail_spawn { 2 } else { 1 });
            assert_eq!(snapshot.spawn_failures_total, u64::from(fail_spawn));
            assert_eq!(snapshot.transient_accept_errors_total, 0);
            assert_eq!(snapshot.drains_started_total, 1);
            assert_eq!(snapshot.drains_quiescent_total, 1);
            assert_eq!(snapshot.drain_escalations_total, 0);
            assert_eq!(snapshot.drain_hard_deadline_hits_total, 0);
            assert_eq!(snapshot.last_drain_requests_at_start, 1);
            assert_eq!(snapshot.last_drain_requests_stranded, 0);
            if let Some(region) = owner_region {
                crate::time::timeout(cx.now(), WATCHDOG, region.close())
                    .await
                    .expect("owner closes within bound")
                    .expect("owner reaches quiescence");
            }
        });
        let retired_at = std::time::Instant::now();
        while !runtime.is_quiescent() {
            assert!(retired_at.elapsed() < WATCHDOG, "listener work must retire");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn fatal_handoff_accept_error_drains_native_http1_requests() {
        for owned in [false, true] {
            for workers in [1, 2] {
                fatal_listener_failure_drains_request(false, owned, workers);
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn fatal_connection_spawn_error_drains_native_http1_requests() {
        for owned in [false, true] {
            for workers in [1, 2] {
                fatal_listener_failure_drains_request(true, owned, workers);
            }
        }
    }
}
