//! HTTP/1.1 server connection handler.
//!
//! [`Http1Server`] wraps a service and drives an HTTP/1.1 connection,
//! reading requests and writing responses using [`Http1Codec`] over a
//! framed transport. Supports keep-alive, request limits, idle timeouts,
//! and graceful shutdown.

use crate::codec::Framed;
use crate::cx::Cx;
use crate::http::h1::codec::{Http1Codec, HttpError};
use crate::http::h1::types::{Request, Response, Version};
use crate::io::{AsyncRead, AsyncWrite};
use crate::server::shutdown::ShutdownSignal;
use crate::stream::Stream;
use crate::time::{timeout, wall_now};
use std::future::{poll_fn, Future};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, Instant};

/// Configuration for HTTP/1.1 server connections.
#[derive(Debug, Clone)]
pub struct Http1Config {
    /// Maximum header block size in bytes.
    pub max_headers_size: usize,
    /// Maximum body size in bytes.
    pub max_body_size: usize,
    /// Whether to support HTTP/1.1 keep-alive.
    pub keep_alive: bool,
    /// Maximum requests allowed on a single keep-alive connection.
    /// `None` means unlimited.
    pub max_requests_per_connection: Option<u64>,
    /// Idle timeout between requests on a keep-alive connection.
    /// `None` means no timeout (wait forever).
    pub idle_timeout: Option<Duration>,
}

impl Default for Http1Config {
    fn default() -> Self {
        Self {
            max_headers_size: 64 * 1024,
            max_body_size: 16 * 1024 * 1024,
            keep_alive: true,
            max_requests_per_connection: Some(1000),
            idle_timeout: Some(Duration::from_secs(60)),
        }
    }
}

impl Http1Config {
    /// Set the maximum header block size.
    #[must_use]
    pub fn max_headers_size(mut self, size: usize) -> Self {
        self.max_headers_size = size;
        self
    }

    /// Set the maximum body size.
    #[must_use]
    pub fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    /// Enable or disable keep-alive.
    #[must_use]
    pub fn keep_alive(mut self, enabled: bool) -> Self {
        self.keep_alive = enabled;
        self
    }

    /// Set the maximum number of requests per connection.
    #[must_use]
    pub fn max_requests(mut self, max: Option<u64>) -> Self {
        self.max_requests_per_connection = max;
        self
    }

    /// Set the idle timeout between requests.
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.idle_timeout = timeout;
        self
    }
}

/// Per-connection state tracking for HTTP/1.1 lifecycle.
#[derive(Debug)]
pub struct ConnectionState {
    /// Number of requests processed on this connection.
    pub requests_served: u64,
    /// When the connection was established.
    pub connected_at: Instant,
    /// When the last request completed.
    pub last_request_at: Instant,
    /// Current phase of the connection.
    pub phase: ConnectionPhase,
}

/// Connection lifecycle phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPhase {
    /// Waiting for the first or next request.
    Idle,
    /// Currently reading a request.
    Reading,
    /// Executing the handler.
    Processing,
    /// Writing the response.
    Writing,
    /// Connection is shutting down gracefully.
    Closing,
}

#[derive(Debug)]
enum ReadOutcome {
    Read(Option<Result<Request, HttpError>>),
    Shutdown,
}

impl ConnectionState {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            requests_served: 0,
            connected_at: now,
            last_request_at: now,
            phase: ConnectionPhase::Idle,
        }
    }

    /// Returns the duration since the last request completed (or since connect).
    #[must_use]
    pub fn idle_duration(&self) -> Duration {
        self.last_request_at.elapsed()
    }

    /// Returns the total connection lifetime.
    #[must_use]
    pub fn connection_age(&self) -> Duration {
        self.connected_at.elapsed()
    }

    /// Returns whether the connection has exceeded the request limit.
    fn exceeded_request_limit(&self, max: Option<u64>) -> bool {
        max.is_some_and(|max| self.requests_served >= max)
    }

    /// Returns whether the connection has exceeded the idle timeout.
    fn exceeded_idle_timeout(&self, timeout: Option<Duration>) -> bool {
        timeout.is_some_and(|timeout| self.idle_duration() > timeout)
    }
}

/// HTTP/1.1 server that processes requests using a service function.
///
/// Reads requests from the transport, passes them to the service, and
/// writes responses back. Tracks connection lifecycle with configurable
/// keep-alive, request limits, and idle timeouts.
///
/// # Example
///
/// ```ignore
/// let server = Http1Server::new(|req| async move {
///     Response::new(200, "OK", b"Hello".to_vec())
/// });
/// server.serve(tcp_stream).await?;
/// ```
pub struct Http1Server<F> {
    handler: F,
    config: Http1Config,
    shutdown_signal: Option<ShutdownSignal>,
}

impl<F, Fut> Http1Server<F>
where
    F: Fn(Request) -> Fut + Send + Sync,
    Fut: Future<Output = Response> + Send,
{
    /// Create a new server with the given handler function.
    pub fn new(handler: F) -> Self {
        Self {
            handler,
            config: Http1Config::default(),
            shutdown_signal: None,
        }
    }

    /// Create a new server with custom configuration.
    pub fn with_config(handler: F, config: Http1Config) -> Self {
        Self {
            handler,
            config,
            shutdown_signal: None,
        }
    }

    /// Attach a shutdown signal for graceful drain / force-close coordination.
    #[must_use]
    pub fn with_shutdown_signal(mut self, signal: ShutdownSignal) -> Self {
        self.shutdown_signal = Some(signal);
        self
    }

    async fn read_next<T>(
        &self,
        framed: &mut Framed<T, Http1Codec>,
        state: &ConnectionState,
    ) -> Option<ReadOutcome>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let read_future = Box::pin(async {
            if let Some(signal) = &self.shutdown_signal {
                if signal.is_shutting_down() {
                    return ReadOutcome::Shutdown;
                }

                let mut read_fut = std::pin::pin!(framed.poll_next_ready());
                let mut shutdown_fut = std::pin::pin!(signal.phase_changed());

                poll_fn(|cx| {
                    if signal.is_shutting_down() {
                        return Poll::Ready(ReadOutcome::Shutdown);
                    }
                    if shutdown_fut.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(ReadOutcome::Shutdown);
                    }
                    if let Poll::Ready(r) = read_fut.as_mut().poll(cx) {
                        return Poll::Ready(ReadOutcome::Read(r));
                    }
                    Poll::Pending
                })
                .await
            } else {
                ReadOutcome::Read(framed.poll_next_ready().await)
            }
        });

        if state.requests_served > 0 {
            if let Some(idle_timeout) = self.config.idle_timeout {
                let now = Cx::current()
                    .and_then(|cx| cx.timer_driver())
                    .map_or_else(wall_now, |timer| timer.now());
                timeout(now, idle_timeout, read_future).await.ok()
            } else {
                Some(read_future.await)
            }
        } else {
            Some(read_future.await)
        }
    }

    /// Serve a single connection, processing requests until the connection
    /// closes, an error occurs, or a lifecycle limit is reached.
    ///
    /// Returns the final connection state along with the result.
    pub async fn serve<T>(self, io: T) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.serve_with_peer_addr(io, None).await
    }

    /// Serve a single connection with an optional peer address.
    ///
    /// When provided, the peer address is attached to each request.
    pub async fn serve_with_peer_addr<T>(
        self,
        io: T,
        peer_addr: Option<SocketAddr>,
    ) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let codec = Http1Codec::new()
            .max_headers_size(self.config.max_headers_size)
            .max_body_size(self.config.max_body_size);
        let mut framed = Framed::new(io, codec);
        let mut state = ConnectionState::new();

        loop {
            state.phase = ConnectionPhase::Idle;

            if self
                .shutdown_signal
                .as_ref()
                .is_some_and(ShutdownSignal::is_shutting_down)
            {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            // Check request limit before reading next request
            if state.exceeded_request_limit(self.config.max_requests_per_connection) {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            // Check idle timeout
            if state.requests_served > 0 && state.exceeded_idle_timeout(self.config.idle_timeout) {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            state.phase = ConnectionPhase::Reading;

            let Some(read_outcome) = self.read_next(&mut framed, &state).await else {
                state.phase = ConnectionPhase::Closing;
                break;
            };

            let req = match read_outcome {
                ReadOutcome::Shutdown => {
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
                ReadOutcome::Read(r) => r,
            };

            // Read next request
            let mut req = match req {
                Some(Ok(req)) => req,
                Some(Err(e)) => return Err(e),
                None => {
                    // Clean EOF - connection closed by client
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
            };
            req.peer_addr = peer_addr;

            // Determine if we should close after this request
            let close_after = should_close_connection(&req, &self.config, &state);

            state.phase = ConnectionPhase::Processing;

            // Process request through handler
            let mut resp = (self.handler)(req).await;

            // Add Connection header to response if closing
            if close_after {
                add_connection_close(&mut resp);
            }

            state.phase = ConnectionPhase::Writing;

            // Write response
            framed.send(resp)?;
            // `Framed::send` only encodes into the internal write buffer; flush to the socket.
            poll_fn(|cx| framed.poll_flush(cx))
                .await
                .map_err(HttpError::Io)?;

            state.requests_served += 1;
            state.last_request_at = Instant::now();

            if close_after {
                state.phase = ConnectionPhase::Closing;
                break;
            }
        }

        Ok(state)
    }
}

/// Determine whether the connection should close after this request.
///
/// Considers: explicit Connection header, HTTP version defaults,
/// server keep-alive config, and request limits.
fn should_close_connection(req: &Request, config: &Http1Config, state: &ConnectionState) -> bool {
    // If keep-alive is disabled server-wide, always close
    if !config.keep_alive {
        return true;
    }

    // If we'll hit the request limit after this request, close
    if let Some(max) = config.max_requests_per_connection {
        if state.requests_served + 1 >= max {
            return true;
        }
    }

    // Check explicit Connection header from client
    for (name, value) in &req.headers {
        if name.eq_ignore_ascii_case("connection") {
            if value.eq_ignore_ascii_case("close") {
                return true;
            }
            if value.eq_ignore_ascii_case("keep-alive") {
                return false;
            }
        }
    }

    // HTTP/1.0 defaults to close; HTTP/1.1 defaults to keep-alive
    req.version == Version::Http10
}

/// Add a `Connection: close` header to the response if not already present.
fn add_connection_close(resp: &mut Response) {
    let has_connection = resp
        .headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("connection"));
    if !has_connection {
        resp.headers
            .push(("Connection".to_owned(), "close".to_owned()));
    }
}

/// Helper trait to await the next item from a `Stream` (since `Stream`
/// provides `poll_next`, not an async method).
trait StreamNextExt: Stream {
    async fn poll_next_ready(&mut self) -> Option<Self::Item>
    where
        Self: Unpin,
    {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }
}

impl<T: Stream + Unpin> StreamNextExt for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::h1::types::Method;

    fn make_request(version: Version, headers: Vec<(String, String)>) -> Request {
        Request {
            method: Method::Get,
            uri: "/".into(),
            version,
            headers,
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        }
    }

    #[test]
    fn should_close_connection_header_close() {
        let config = Http1Config::default();
        let state = ConnectionState::new();
        let req = make_request(Version::Http11, vec![("Connection".into(), "close".into())]);
        assert!(should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_connection_header_keepalive() {
        let config = Http1Config::default();
        let state = ConnectionState::new();
        let req = make_request(
            Version::Http11,
            vec![("Connection".into(), "keep-alive".into())],
        );
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_http10_default() {
        let config = Http1Config::default();
        let state = ConnectionState::new();
        let req = make_request(Version::Http10, vec![]);
        assert!(should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_http10_with_keepalive() {
        let config = Http1Config::default();
        let state = ConnectionState::new();
        let req = make_request(
            Version::Http10,
            vec![("Connection".into(), "keep-alive".into())],
        );
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_http11_default() {
        let config = Http1Config::default();
        let state = ConnectionState::new();
        let req = make_request(Version::Http11, vec![]);
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_keepalive_disabled() {
        let config = Http1Config {
            keep_alive: false,
            ..Default::default()
        };
        let state = ConnectionState::new();
        let req = make_request(Version::Http11, vec![]);
        assert!(should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_at_request_limit() {
        let config = Http1Config {
            max_requests_per_connection: Some(5),
            ..Default::default()
        };
        let mut state = ConnectionState::new();
        let req = make_request(Version::Http11, vec![]);

        // At 4 served (next will be 5th = limit), should close
        state.requests_served = 4;
        assert!(should_close_connection(&req, &config, &state));

        // At 3 served, should not close
        state.requests_served = 3;
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_unlimited_requests() {
        let config = Http1Config {
            max_requests_per_connection: None,
            ..Default::default()
        };
        let mut state = ConnectionState::new();
        let req = make_request(Version::Http11, vec![]);

        state.requests_served = 1_000_000;
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn connection_state_tracking() {
        let state = ConnectionState::new();
        assert_eq!(state.requests_served, 0);
        assert_eq!(state.phase, ConnectionPhase::Idle);
        assert!(!state.exceeded_request_limit(Some(10)));
        assert!(!state.exceeded_request_limit(None));
    }

    #[test]
    fn connection_state_request_limit() {
        let mut state = ConnectionState::new();
        state.requests_served = 10;
        assert!(state.exceeded_request_limit(Some(10)));
        assert!(state.exceeded_request_limit(Some(5)));
        assert!(!state.exceeded_request_limit(Some(11)));
        assert!(!state.exceeded_request_limit(None));
    }

    #[test]
    fn add_connection_close_header() {
        let mut resp = Response::new(200, "OK", Vec::new());
        assert!(resp.headers.is_empty());
        add_connection_close(&mut resp);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn add_connection_close_header_already_present() {
        let mut resp = Response::new(200, "OK", Vec::new());
        resp.headers
            .push(("Connection".to_owned(), "keep-alive".to_owned()));
        add_connection_close(&mut resp);
        // Should not add duplicate
        assert_eq!(resp.headers.len(), 1);
    }

    #[test]
    fn config_builder() {
        let config = Http1Config::default()
            .max_headers_size(1024)
            .max_body_size(2048)
            .keep_alive(false)
            .max_requests(Some(50))
            .idle_timeout(Some(Duration::from_secs(30)));

        assert_eq!(config.max_headers_size, 1024);
        assert_eq!(config.max_body_size, 2048);
        assert!(!config.keep_alive);
        assert_eq!(config.max_requests_per_connection, Some(50));
        assert_eq!(config.idle_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn connection_phase_equality() {
        assert_eq!(ConnectionPhase::Idle, ConnectionPhase::Idle);
        assert_ne!(ConnectionPhase::Idle, ConnectionPhase::Reading);
        assert_ne!(ConnectionPhase::Processing, ConnectionPhase::Writing);
    }
}
