//! HTTP/1.1 server accept loop with graceful shutdown.
//!
//! [`Http1Listener`] binds a TCP listener, accepts connections, and dispatches
//! each to an [`Http1Server`] handler. Integrates with [`ConnectionManager`]
//! for capacity limits and [`ShutdownSignal`] for graceful drain.

use crate::http::h1::server::{Http1Config, Http1Server};
use crate::http::h1::types::{Request, Response};
use crate::net::tcp::listener::TcpListener;
use crate::server::connection::{ConnectionGuard, ConnectionManager};
use crate::server::shutdown::{ShutdownPhase, ShutdownSignal, ShutdownStats};
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
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
///
/// let listener = Http1Listener::bind("127.0.0.1:8080", |req| async {
///     Response::new(200, "OK", b"Hello".to_vec())
/// }).await?;
///
/// // In another task: listener.shutdown_signal().begin_drain(Duration::from_secs(30));
/// let stats = listener.run().await?;
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
    Fut: Future<Output = Response> + Send,
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
    pub async fn run(self) -> io::Result<ShutdownStats> {
        // Accept loop: keep accepting until shutdown
        loop {
            if self.shutdown_signal.is_shutting_down() {
                break;
            }

            // Race accept against shutdown phase change
            let result = {
                let accept_fut = self.tcp_listener.accept();
                let shutdown_fut = self.shutdown_signal.phase_changed();
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
            spawn_connection(stream, guard, handler, http_config, shutdown_signal);
        }

        // Drain phase
        let drain_timeout = self.config.drain_timeout;
        if self.shutdown_signal.phase() == ShutdownPhase::Running {
            let _ = self.shutdown_signal.begin_drain(drain_timeout);
        }

        let stats = self.connection_manager.drain_with_stats().await;
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

/// Spawn a connection handler on a new thread.
///
/// The connection guard is held for the lifetime of the handler,
/// ensuring proper tracking during drain.
fn spawn_connection<F, Fut>(
    stream: crate::net::tcp::stream::TcpStream,
    guard: ConnectionGuard,
    handler: Arc<F>,
    config: Http1Config,
    shutdown_signal: ShutdownSignal,
) where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send,
{
    // ubs:ignore — intentional per-connection thread; ConnectionGuard tracks lifetime
    std::thread::spawn(move || {
        let _guard = guard;
        let server = Http1Server::with_config(move |req| handler(req), config)
            .with_shutdown_signal(shutdown_signal);
        let peer_addr = stream.peer_addr().ok();
        // Drive the server future to completion using a thread-parking waker
        let mut fut = Box::pin(server.serve_with_peer_addr(stream, peer_addr));
        let thread = std::thread::current();
        let waker = Arc::new(ThreadWaker(thread)).into();
        let mut cx = std::task::Context::from_waker(&waker);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(_result) => break,
                Poll::Pending => std::thread::park(),
            }
        }
    });
}

/// Waker that unparks a thread when woken.
struct ThreadWaker(std::thread::Thread);

impl std::task::Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
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
            .drain_timeout(Duration::from_secs(60))
            .http_config(Http1Config::default().keep_alive(false));

        assert_eq!(config.max_connections, Some(5000));
        assert_eq!(config.drain_timeout, Duration::from_secs(60));
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
        crate::test_utils::run_test(|| async {
            let listener = Http1Listener::bind("127.0.0.1:0", |_req| async {
                Response::new(200, "OK", Vec::new())
            })
            .await
            .expect("bind failed");

            // Trigger shutdown before running
            let signal = listener.shutdown_signal();
            let _ = signal.begin_drain(Duration::from_millis(100));

            let stats = listener.run().await.expect("run");
            assert_eq!(stats.drained, 0);
            assert_eq!(stats.force_closed, 0);
        });
    }
}
