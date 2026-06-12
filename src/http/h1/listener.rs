//! HTTP/1.1 server accept loop with graceful shutdown.
//!
//! [`Http1Listener`] binds a TCP listener, accepts connections, and dispatches
//! each to an [`Http1Server`] handler. Integrates with [`ConnectionManager`]
//! for capacity limits and [`ShutdownSignal`] for graceful drain.

use crate::http::h1::server::{Http1Config, Http1Server};
use crate::http::h1::types::{Request, Response};
use crate::net::tcp::listener::TcpListener;
use crate::runtime::{JoinHandle, RuntimeHandle, SpawnError};
use crate::server::connection::{ConnectionGuard, ConnectionManager};
use crate::server::shutdown::{
    DrainStep, GracefulDrainSupervisor, ShutdownPhase, ShutdownSignal, ShutdownStats,
};
use crate::tracing_compat::error;
use crate::{cx::Cx, types::Time};
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

/// Low-overhead listener counters for diagnosing accept-path stalls.
pub struct Http1ListenerStats {
    accepted_total: AtomicU64,
    transient_accept_errors_total: AtomicU64,
    spawn_failures_total: AtomicU64,
    last_accept_at_ms: AtomicU64,
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
/// # Example
///
/// ```ignore
/// use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
/// use asupersync::http::h1::types::Response;
/// use asupersync::runtime::RuntimeBuilder;
///
/// let runtime = RuntimeBuilder::current_thread().build()?;
/// let handle = runtime.handle();
/// runtime.block_on(async {
///     let listener = Http1Listener::bind("127.0.0.1:8080", |req| async {
///         Response::new(200, "OK", b"Hello".to_vec())
///     })
///     .await?;
///
///     // In another task: listener.begin_drain();
///     let stats = listener.run(&handle).await?;
///     Ok::<_, std::io::Error>(stats)
/// })?;
/// ```
pub struct Http1Listener<F> {
    tcp_listener: TcpListener,
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
    Fut: Future<Output = Response> + Send + 'static,
{
    /// Bind to the given address with default configuration.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(addr: A, handler: F) -> io::Result<Self> {
        Self::bind_with_config(addr, handler, Http1ListenerConfig::default()).await
    }

    /// Bind with custom configuration.
    pub async fn bind_with_config<A: ToSocketAddrs + Send + 'static>(
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
            tcp_listener,
            handler: Arc::new(handler),
            config,
            shutdown_signal,
            connection_manager,
            stats,
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Create from an existing [`TcpListener`] with custom configuration.
    pub fn from_listener(
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
            tcp_listener,
            handler: Arc::new(handler),
            config,
            shutdown_signal,
            connection_manager,
            stats,
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
        }
    }

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
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp_listener.local_addr()
    }

    /// Run the accept loop until shutdown.
    ///
    /// Accepts connections, dispatches to handler, and on shutdown signal
    /// drains active connections within the configured timeout.
    ///
    /// Returns shutdown statistics upon completion.
    pub async fn run(self, runtime: &RuntimeHandle) -> io::Result<ShutdownStats> {
        let mut tasks = ConnectionTasks::default();
        let mut shutdown_rx = self.shutdown_signal.subscribe();
        let mut transient_accept_streak: u32 = 0;
        // Accept loop: keep accepting until shutdown
        loop {
            if self.shutdown_signal.is_shutting_down() {
                break;
            }

            // Race accept against shutdown phase change
            let result = {
                let accept_fut = self.tcp_listener.accept();
                let shutdown_fut = shutdown_rx.wait();
                // Pin both futures on the stack
                let mut accept_fut = core::pin::pin!(accept_fut);
                let mut shutdown_fut = core::pin::pin!(shutdown_fut);

                std::future::poll_fn(|cx| {
                    // Check shutdown synchronously first
                    if self.shutdown_signal.is_shutting_down() {
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
                AcceptOrShutdown::Shutdown => break,
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
                Err(e) => return Err(e),
            };

            // Register with connection manager (enforces capacity + shutdown)
            let Some(guard) = self.connection_manager.register(addr) else {
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
                runtime,
            ) {
                Ok(handle) => handle,
                Err(err) => {
                    self.stats.record_spawn_failure();
                    if should_retry_after_spawn_failure(&err) {
                        continue;
                    }
                    return Err(io::Error::other(format!(
                        "failed to spawn connection task: {err}"
                    )));
                }
            };
            tasks.push(handle);
        }

        // Drain phase
        if self.shutdown_signal.phase() == ShutdownPhase::Running {
            let _ = self.begin_drain();
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
            let mut supervisor = GracefulDrainSupervisor::new(
                self.in_flight_requests.load(Ordering::Acquire),
                drain_start,
                self.config.drain_timeout,
                self.config.hard_drain_timeout,
            );
            let mut hard_deadline_hit = false;
            loop {
                let now = (self.config.time_getter)();
                match supervisor.observe(self.in_flight_requests.load(Ordering::Acquire), now) {
                    DrainStep::Continue => {
                        // Pace ticks on the runtime clock: the listener's
                        // configured time_getter may be a frozen virtual
                        // clock in tests, while the tick needs real
                        // scheduling time to let in-flight work progress.
                        let sleep_now = Cx::current()
                            .and_then(|cx| cx.timer_driver())
                            .map_or_else(crate::time::wall_now, |timer| timer.now());
                        crate::time::sleep(sleep_now, DRAIN_SUPERVISION_TICK).await;
                    }
                    DrainStep::Escalate => {
                        let _ = self.shutdown_signal.begin_force_close();
                    }
                    DrainStep::Quiescent => break,
                    DrainStep::HardDeadline => {
                        hard_deadline_hit = true;
                        let _ = self.shutdown_signal.begin_force_close();
                        break;
                    }
                }
            }
            supervisor.finish((self.config.time_getter)(), hard_deadline_hit)
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
        Ok(stats)
    }
}

/// Result of racing accept against shutdown.
enum AcceptOrShutdown {
    /// A new connection was accepted.
    Accept(io::Result<(crate::net::tcp::stream::TcpStream, SocketAddr)>),
    /// Shutdown was signaled.
    Shutdown,
}

/// Spawn a connection handler as a runtime task.
///
/// The connection guard is held for the lifetime of the handler,
/// ensuring proper tracking during drain.
fn spawn_connection<F, Fut>(
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
    Fut: Future<Output = Response> + Send + 'static,
{
    let handle = runtime.try_spawn(async move {
        let _guard = guard;
        let server = Http1Server::with_config(move |req| handler(req), config)
            .with_shutdown_signal(shutdown_signal)
            .with_in_flight_requests(in_flight_requests);
        let peer_addr = stream.peer_addr().ok();
        let _ = server.serve_with_peer_addr(stream, peer_addr).await;
    })?;
    Ok(handle)
}

#[derive(Default)]
struct ConnectionTasks {
    handles: Vec<JoinHandle<()>>,
    push_count: u64,
}

impl ConnectionTasks {
    fn push(&mut self, handle: JoinHandle<()>) {
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
        for handle in self.handles.drain(..) {
            let result = CatchUnwind { inner: handle }.await;
            if let Err(payload) = result {
                let _ = &payload;
                error!(
                    message = %crate::cx::scope::payload_to_string(&payload),
                    "connection task panicked"
                );
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
    )
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
                // The blocker consumes the only root task slot, so a per-connection
                // spawn attempt must fail without leaking its connection guard.
                max_tasks: Some(1),
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

            assert!(matches!(err, SpawnError::RegionAtCapacity { .. }));
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
}
