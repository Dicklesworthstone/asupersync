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
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

/// Configuration for the HTTP/1.1 listener.
#[derive(Debug, Clone)]
pub struct Http1ListenerConfig {
    /// Per-connection HTTP configuration.
    pub http_config: Http1Config,
    /// Maximum concurrent connections. `None` means unlimited.
    pub max_connections: Option<usize>,
    /// Drain timeout for graceful shutdown.
    pub drain_timeout: Duration,
}

impl Default for Http1ListenerConfig {
    fn default() -> Self {
        Self {
            http_config: Http1Config::default(),
            max_connections: Some(10_000),
            drain_timeout: Duration::from_secs(30),
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
///     // In another task: listener.shutdown_signal().begin_drain(Duration::from_secs(30));
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
        let shutdown_signal = ShutdownSignal::new();
        let connection_manager =
            ConnectionManager::new(config.max_connections, shutdown_signal.clone());

        Ok(Self {
            tcp_listener,
            handler: Arc::new(handler),
            config,
            shutdown_signal,
            connection_manager,
        })
    }

    /// Create from an existing [`TcpListener`] with custom configuration.
    pub fn from_listener(
        tcp_listener: TcpListener,
        handler: F,
        config: Http1ListenerConfig,
    ) -> Self {
        let shutdown_signal = ShutdownSignal::new();
        let connection_manager =
            ConnectionManager::new(config.max_connections, shutdown_signal.clone());

        Self {
            tcp_listener,
            handler: Arc::new(handler),
            config,
            shutdown_signal,
            connection_manager,
        }
    }

    /// Returns a clone of the shutdown signal for external shutdown triggering.
    #[must_use]
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown_signal.clone()
    }

    /// Returns a reference to the connection manager.
    #[must_use]
    pub fn connection_manager(&self) -> &ConnectionManager {
        &self.connection_manager
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
                Ok(conn) => conn,
                Err(ref e) if is_transient_accept_error(e) => {
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
            let handle = spawn_connection(
                stream,
                guard,
                handler,
                http_config,
                shutdown_signal,
                runtime,
            )
            .map_err(|err| io::Error::other(format!("failed to spawn connection task: {err}")))?;
            tasks.push(handle);
        }

        // Drain phase
        let drain_timeout = self.config.drain_timeout;
        if self.shutdown_signal.phase() == ShutdownPhase::Running {
            let _ = self.shutdown_signal.begin_drain(drain_timeout);
        }

        let stats = self.connection_manager.drain_with_stats().await;
        tasks.join_all().await;
        if self.connection_manager.is_empty() {
            self.shutdown_signal.mark_stopped();
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
}

impl ConnectionTasks {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    fn push(&mut self, handle: JoinHandle<()>) {
        self.handles.push(handle);
    }

    async fn join_all(&mut self) {
        for handle in self.handles.drain(..) {
            let result = CatchUnwind(Box::pin(handle)).await;
            if let Err(payload) = result {
                let _ = &payload;
                error!(
                    message = %payload_to_string(&payload),
                    "connection task panicked"
                );
            }
        }
    }
}

struct CatchUnwind<F>(Pin<Box<F>>);

impl<F: Future> Future for CatchUnwind<F> {
    type Output = std::thread::Result<F::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let inner = self.0.as_mut();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.poll(cx)));
        match result {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

fn payload_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(ToString::to_string)
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}

/// Returns `true` for accept errors that are transient and should be retried.
fn is_transient_accept_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::h1::types::Response;
    use crate::io::AsyncWriteExt;
    use crate::runtime::RuntimeBuilder;
    use crate::runtime::yield_now;
    use crate::sync::Notify;
    use crate::test_utils::init_test_logging;
    use std::sync::Arc;

    #[test]
    fn default_config() {
        let config = Http1ListenerConfig::default();
        assert_eq!(config.max_connections, Some(10_000));
        assert_eq!(config.drain_timeout, Duration::from_secs(30));
        assert!(config.http_config.keep_alive);
    }

    #[test]
    fn config_builder() {
        let config = Http1ListenerConfig::default()
            .max_connections(Some(5000))
            .drain_timeout(Duration::from_mins(1))
            .http_config(Http1Config::default().keep_alive(false));

        assert_eq!(config.max_connections, Some(5000));
        assert_eq!(config.drain_timeout, Duration::from_mins(1));
        assert!(!config.http_config.keep_alive);
    }

    #[test]
    fn transient_error_detection() {
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
            let signal = listener.shutdown_signal();
            let _ = signal.begin_drain(Duration::from_millis(100));

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
            let began = shutdown.begin_drain(Duration::from_millis(0));
            assert!(began);

            loop {
                if shutdown.phase() == ShutdownPhase::ForceClosing {
                    break;
                }
                shutdown.phase_changed().await;
            }

            finished.notify_one();
            let stats = run_handle.await.expect("run");
            assert!(stats.force_closed > 0, "expected force close path");
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);

            yield_now().await;
        });
    }
}
