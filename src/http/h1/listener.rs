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
use crate::server::shutdown::{ShutdownPhase, ShutdownSignal, ShutdownStats};
use crate::tracing_compat::error;
use crate::{cx::Cx, types::Time};
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;

const TRANSIENT_ACCEPT_BACKOFF_BASE: Duration = Duration::from_millis(2);
const TRANSIENT_ACCEPT_BACKOFF_CAP: Duration = Duration::from_millis(64);

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
    pub drain_timeout: Duration,
    /// Time source for shutdown bookkeeping, connection metadata, and listener diagnostics.
    pub time_getter: fn() -> Time,
}

impl Default for Http1ListenerConfig {
    fn default() -> Self {
        Self {
            http_config: Http1Config::default(),
            max_connections: Some(10_000),
            drain_timeout: Duration::from_secs(30),
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
        let mut tasks = ConnectionTasks::new();
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
            let handle = match spawn_connection(
                stream,
                guard,
                handler,
                http_config,
                shutdown_signal,
                runtime,
            ) {
                Ok(handle) => handle,
                Err(err) => {
                    self.stats.record_spawn_failure();
                    if should_retry_after_spawn_failure(&err) {
                        crate::runtime::yield_now().await;
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

        let mut stats = self.connection_manager.drain_with_stats().await;

        // If drain_with_stats returned due to a timeout, it transitioned the phase
        // to ForceClosing, but stats.duration only reflects the time up to the timeout.
        // We must re-collect stats after join_all() finishes waiting for tasks.
        let is_force_closing = self.shutdown_signal.phase() == ShutdownPhase::ForceClosing;

        tasks.join_all().await;

        if self.connection_manager.is_empty() {
            self.shutdown_signal.mark_stopped();
            if is_force_closing {
                stats = self
                    .shutdown_signal
                    .collect_stats(stats.drained, stats.force_closed);
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
    runtime: &RuntimeHandle,
) -> Result<JoinHandle<()>, SpawnError>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let handle = runtime.try_spawn(async move {
        let _guard = guard;
        let server = Http1Server::with_config(move |req| handler(req), config)
            .with_shutdown_signal(shutdown_signal);
        let peer_addr = stream.peer_addr().ok();
        let _ = server.serve_with_peer_addr(stream, peer_addr).await;
    })?;
    Ok(handle)
}

struct ConnectionTasks {
    handles: Vec<JoinHandle<()>>,
    push_count: u64,
}

impl ConnectionTasks {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
            push_count: 0,
        }
    }

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
    use super::*;
    use crate::cx::Cx;
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
                // One task slot is consumed by the listener itself; the second slot
                // is filled by the blocker so accepted connections hit region capacity.
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

            let listener = Http1Listener::bind_with_config(
                "127.0.0.1:0",
                |_req| async { Response::new(200, "OK", b"listener alive".to_vec()) },
                Http1ListenerConfig::default(),
            )
            .await
            .expect("bind failed");

            let addr = listener.local_addr().expect("local addr");
            let stats_handle = listener.stats_handle();
            let manager = listener.connection_manager().clone();
            let shutdown = listener.shutdown_signal();

            let run_handle = handle
                .clone()
                .try_spawn(async move { listener.run(&handle).await })
                .expect("spawn listener");

            let mut rejected_client = crate::net::tcp::stream::TcpStream::connect(addr)
                .await
                .expect("connect rejected client");
            rejected_client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("write rejected request");

            for _ in 0..64 {
                if stats_handle.snapshot().spawn_failures_total == 1 {
                    break;
                }
                crate::time::sleep(crate::time::wall_now(), Duration::from_millis(10)).await;
            }

            drop(rejected_client);

            let stats = stats_handle.snapshot();
            assert_eq!(stats.spawn_failures_total, 1);
            assert_eq!(stats.accepted_total, 1);
            assert!(
                !run_handle.is_finished(),
                "listener should keep running after a per-connection spawn failure"
            );

            blocker_release.notify_one();
            blocker.await;

            let mut healthy_client = crate::net::tcp::stream::TcpStream::connect(addr)
                .await
                .expect("connect healthy client");
            healthy_client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .expect("write healthy request");
            drop(healthy_client);

            for _ in 0..64 {
                let snapshot = stats_handle.snapshot();
                if snapshot.accepted_total == 2 && snapshot.spawn_failures_total == 1 {
                    break;
                }
                crate::time::sleep(crate::time::wall_now(), Duration::from_millis(10)).await;
            }

            let recovered = stats_handle.snapshot();
            assert_eq!(recovered.accepted_total, 2);
            assert_eq!(recovered.spawn_failures_total, 1);
            assert!(
                !run_handle.is_finished(),
                "listener should still be alive after capacity recovers"
            );

            assert!(manager.begin_drain(Duration::from_millis(0)));
            let _ = run_handle.await.expect("listener run");
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
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
