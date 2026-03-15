//! HTTP/1.1 server connection handler.
//!
//! [`Http1Server`] wraps a service and drives an HTTP/1.1 connection,
//! reading requests and writing responses using [`Http1Codec`] over a
//! framed transport. Supports keep-alive, request limits, idle timeouts,
//! and graceful shutdown.

use crate::codec::Framed;
use crate::cx::Cx;
use crate::http::h1::codec::{Http1Codec, HttpError, preview_request_head};
use crate::http::h1::types::{Method, Request, Response, Version, default_reason};
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use crate::server::shutdown::{ShutdownPhase, ShutdownSignal};
use crate::stream::Stream;
use crate::time::{timeout, wall_now};
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

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
            idle_timeout: Some(Duration::from_mins(1)),
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
    pub connected_at: crate::types::Time,
    /// When the last request completed.
    pub last_request_at: crate::types::Time,
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
    Read {
        item: Option<Result<Request, HttpError>>,
        continue_sent: bool,
    },
    ExpectationRejected,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectationAction {
    None,
    Continue,
    Reject,
}

type ShutdownWaitFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

#[derive(Debug)]
enum ExpectationStep {
    ContinueLoop,
    Return(Poll<ReadOutcome>),
}

impl ConnectionState {
    fn new(now: crate::types::Time) -> Self {
        Self {
            requests_served: 0,
            connected_at: now,
            last_request_at: now,
            phase: ConnectionPhase::Idle,
        }
    }

    /// Returns the duration since the last request completed (or since connect).
    #[must_use]
    pub fn idle_duration(&self, now: crate::types::Time) -> Duration {
        Duration::from_nanos(
            now.as_nanos()
                .saturating_sub(self.last_request_at.as_nanos()),
        )
    }

    /// Returns the total connection lifetime.
    #[must_use]
    pub fn connection_age(&self, now: crate::types::Time) -> Duration {
        Duration::from_nanos(now.as_nanos().saturating_sub(self.connected_at.as_nanos()))
    }

    /// Returns whether the connection has exceeded the request limit.
    fn exceeded_request_limit(&self, max: Option<u64>) -> bool {
        max.is_some_and(|max| self.requests_served >= max)
    }

    /// Returns whether the connection has exceeded the idle timeout.
    fn exceeded_idle_timeout(&self, timeout: Option<Duration>, now: crate::types::Time) -> bool {
        timeout.is_some_and(|timeout| self.idle_duration(now) > timeout)
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
        _state: &ConnectionState,
    ) -> Option<ReadOutcome>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let read_future = Box::pin(async {
            let mut pending_expectation_flush = None;
            let mut handled_expectation = false;
            let mut shutdown_fut: Option<ShutdownWaitFuture<'_>> =
                self.shutdown_signal.as_ref().map(|signal| {
                    Box::pin(
                        signal.wait_for_phase(crate::server::shutdown::ShutdownPhase::Draining),
                    ) as ShutdownWaitFuture<'_>
                });

            poll_fn(|cx| {
                loop {
                    if self.should_stop_reading(cx, shutdown_fut.as_mut()) {
                        return Poll::Ready(ReadOutcome::Shutdown);
                    }

                    if let Some(outcome) = poll_pending_expectation_flush(
                        cx,
                        framed,
                        &mut pending_expectation_flush,
                        handled_expectation,
                    ) {
                        return outcome;
                    }

                    match Pin::new(&mut *framed).poll_next(cx) {
                        Poll::Ready(item) => {
                            return Poll::Ready(ReadOutcome::Read {
                                item,
                                continue_sent: handled_expectation,
                            });
                        }
                        Poll::Pending => {}
                    }

                    if let Some(step) = poll_request_expectation(
                        cx,
                        framed,
                        &mut pending_expectation_flush,
                        &mut handled_expectation,
                    ) {
                        match step {
                            ExpectationStep::ContinueLoop => continue,
                            ExpectationStep::Return(outcome) => {
                                return outcome;
                            }
                        }
                    }

                    return Poll::Pending;
                }
            })
            .await
        });

        if let Some(idle_timeout) = self.config.idle_timeout {
            let now = Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map_or_else(wall_now, |timer| timer.now());
            timeout(now, idle_timeout, read_future).await.ok()
        } else {
            Some(read_future.await)
        }
    }

    fn should_stop_reading(
        &self,
        cx: &mut Context<'_>,
        mut shutdown_fut: Option<&mut ShutdownWaitFuture<'_>>,
    ) -> bool {
        Cx::current().is_some_and(|current| current.checkpoint().is_err())
            || self
                .shutdown_signal
                .as_ref()
                .is_some_and(ShutdownSignal::is_shutting_down)
            || shutdown_fut
                .as_mut()
                .is_some_and(|future| future.as_mut().poll(cx).is_ready())
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
    #[allow(clippy::too_many_lines)]
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
        let mut state = ConnectionState::new(
            Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map_or_else(wall_now, |timer| timer.now()),
        );

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

            if Cx::current().is_some_and(|cx| cx.is_cancel_requested()) {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            // Check request limit before reading next request
            if state.exceeded_request_limit(self.config.max_requests_per_connection) {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            let now = Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map_or_else(wall_now, |timer| timer.now());

            // Check idle timeout
            if state.exceeded_idle_timeout(self.config.idle_timeout, now) {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            state.phase = ConnectionPhase::Reading;

            let Some(read_outcome) = self.read_next(&mut framed, &state).await else {
                state.phase = ConnectionPhase::Closing;
                break;
            };

            let (req, continue_sent) = match read_outcome {
                ReadOutcome::ExpectationRejected => {
                    state.requests_served += 1;
                    state.last_request_at = Cx::current()
                        .and_then(|cx| cx.timer_driver())
                        .map_or_else(wall_now, |timer| timer.now());
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
                ReadOutcome::Shutdown => {
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
                ReadOutcome::Read {
                    item,
                    continue_sent,
                } => (item, continue_sent),
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

            let expectation_action = classify_expectation(&req);
            if expectation_action == ExpectationAction::Reject {
                state.phase = ConnectionPhase::Writing;
                let reject = expectation_response(req.version, ExpectationAction::Reject)
                    .expect("reject expectation should build a response");
                framed.send(reject)?;
                poll_fn(|cx| {
                    if Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
                        return Poll::Ready(Err(HttpError::Io(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "connection cancelled",
                        ))));
                    }
                    framed.poll_flush(cx).map_err(HttpError::Io)
                })
                .await?;
                state.requests_served += 1;
                state.last_request_at = Cx::current()
                    .and_then(|cx| cx.timer_driver())
                    .map_or_else(wall_now, |timer| timer.now());
                state.phase = ConnectionPhase::Closing;
                break;
            }
            if expectation_action == ExpectationAction::Continue
                && request_expects_body(&req)
                && !continue_sent
            {
                state.phase = ConnectionPhase::Writing;
                let interim = expectation_response(req.version, ExpectationAction::Continue)
                    .expect("continue expectation should build a response");
                framed.send(interim)?;
                poll_fn(|cx| {
                    if Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
                        return Poll::Ready(Err(HttpError::Io(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "connection cancelled",
                        ))));
                    }
                    framed.poll_flush(cx).map_err(HttpError::Io)
                })
                .await?;
            }

            // Determine if we should close after this request
            let close_after = should_close_connection(&req, &self.config, &state);
            let request_version = req.version;
            let request_method = req.method.clone();

            state.phase = ConnectionPhase::Processing;

            // Process request through handler.
            // Race against ForceClosing so slow handlers don't block shutdown.
            let mut resp = if let Some(signal) = &self.shutdown_signal {
                let mut handler_fut = std::pin::pin!((self.handler)(req));
                let mut force_close_fut =
                    std::pin::pin!(signal.wait_for_phase(ShutdownPhase::ForceClosing));

                let result = poll_fn(|cx| {
                    // If already force-closing, bail immediately
                    if signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8 {
                        return Poll::Ready(None);
                    }
                    // Check if force-close arrived
                    if force_close_fut.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(None);
                    }
                    // Drive the handler
                    handler_fut.as_mut().poll(cx).map(Some)
                })
                .await;

                if let Some(resp) = result {
                    resp
                } else {
                    // Force-close interrupted the handler
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
            } else {
                (self.handler)(req).await
            };

            if request_method == Method::Head {
                suppress_response_body_for_head(&mut resp);
            }

            let close_after =
                finalize_response_persistence(request_version, &mut resp, close_after);

            state.phase = ConnectionPhase::Writing;

            // Write response
            framed.send(resp)?;
            // `Framed::send` only encodes into the internal write buffer; flush to the socket.
            poll_fn(|cx| {
                if Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
                    return Poll::Ready(Err(HttpError::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "connection cancelled",
                    ))));
                }
                framed.poll_flush(cx).map_err(HttpError::Io)
            })
            .await?;

            state.requests_served += 1;
            state.last_request_at = Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map_or_else(wall_now, |timer| timer.now());

            if close_after {
                state.phase = ConnectionPhase::Closing;
                break;
            }
        }

        // Gracefully shutdown the connection
        let mut io = framed.into_inner();
        let _ = io.shutdown().await;

        Ok(state)
    }
}

fn read_error(err: HttpError, continue_sent: bool) -> ReadOutcome {
    ReadOutcome::Read {
        item: Some(Err(err)),
        continue_sent,
    }
}

fn poll_pending_expectation_flush<T>(
    cx: &mut Context<'_>,
    framed: &mut Framed<T, Http1Codec>,
    pending_expectation_flush: &mut Option<ExpectationAction>,
    continue_sent: bool,
) -> Option<Poll<ReadOutcome>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let action = (*pending_expectation_flush)?;
    match framed.poll_flush(cx).map_err(HttpError::Io) {
        Poll::Pending => Some(Poll::Pending),
        Poll::Ready(Err(err)) => Some(Poll::Ready(read_error(err, continue_sent))),
        Poll::Ready(Ok(())) => {
            *pending_expectation_flush = None;
            if action == ExpectationAction::Reject {
                Some(Poll::Ready(ReadOutcome::ExpectationRejected))
            } else {
                None
            }
        }
    }
}

fn poll_request_expectation<T>(
    cx: &mut Context<'_>,
    framed: &mut Framed<T, Http1Codec>,
    pending_expectation_flush: &mut Option<ExpectationAction>,
    handled_expectation: &mut bool,
) -> Option<ExpectationStep>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    if *handled_expectation {
        return None;
    }

    let preview = match preview_request_head(framed.codec(), framed.read_buffer()) {
        Ok(preview) => preview,
        Err(err) => {
            return Some(ExpectationStep::Return(Poll::Ready(read_error(
                err,
                *handled_expectation,
            ))));
        }
    }?;

    let action = classify_expectation_from_parts(preview.version, &preview.headers);
    if action == ExpectationAction::None || !request_expects_body_headers(&preview.headers) {
        return None;
    }

    let response = expectation_response(preview.version, action)
        .expect("expectation action should build a response");
    if let Err(err) = framed.send(response) {
        return Some(ExpectationStep::Return(Poll::Ready(read_error(
            err,
            *handled_expectation,
        ))));
    }
    *handled_expectation = true;

    Some(match framed.poll_flush(cx).map_err(HttpError::Io) {
        Poll::Pending => {
            *pending_expectation_flush = Some(action);
            ExpectationStep::Return(Poll::Pending)
        }
        Poll::Ready(Err(err)) => {
            ExpectationStep::Return(Poll::Ready(read_error(err, *handled_expectation)))
        }
        Poll::Ready(Ok(())) => {
            if action == ExpectationAction::Reject {
                ExpectationStep::Return(Poll::Ready(ReadOutcome::ExpectationRejected))
            } else {
                ExpectationStep::ContinueLoop
            }
        }
    })
}

fn classify_expectation(req: &Request) -> ExpectationAction {
    classify_expectation_from_parts(req.version, &req.headers)
}

fn classify_expectation_from_parts(
    version: Version,
    headers: &[(String, String)],
) -> ExpectationAction {
    let mut saw_expect = false;
    let mut saw_continue = false;
    let mut saw_unsupported = false;

    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("expect") {
            continue;
        }
        saw_expect = true;
        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if token.eq_ignore_ascii_case("100-continue") {
                saw_continue = true;
            } else {
                saw_unsupported = true;
            }
        }
    }

    if !saw_expect {
        return ExpectationAction::None;
    }

    if saw_unsupported || version != Version::Http11 {
        return ExpectationAction::Reject;
    }

    if saw_continue {
        return ExpectationAction::Continue;
    }

    // Expect header present but no token content: treat as unsupported.
    ExpectationAction::Reject
}

fn request_expects_body(req: &Request) -> bool {
    request_expects_body_headers(&req.headers) || !req.body.is_empty()
}

fn request_expects_body_headers(headers: &[(String, String)]) -> bool {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            if let Ok(len) = value.trim().parse::<usize>() {
                if len > 0 {
                    return true;
                }
            }
            continue;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return value
                .split(',')
                .map(str::trim)
                .any(|token| token.eq_ignore_ascii_case("chunked"));
        }
    }
    false
}

fn expectation_response(version: Version, action: ExpectationAction) -> Option<Response> {
    let mut response = match action {
        ExpectationAction::None => return None,
        ExpectationAction::Continue => Response::new(100, default_reason(100), Vec::new()),
        ExpectationAction::Reject => Response::new(417, default_reason(417), Vec::new()),
    };
    finalize_response_persistence(version, &mut response, action == ExpectationAction::Reject);
    Some(response)
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

    let mut has_keep_alive = false;
    let mut has_close = false;

    // Check explicit Connection header from client (RFC 9110 §7.6.1: comma-separated tokens)
    for (name, value) in &req.headers {
        if name.eq_ignore_ascii_case("connection") {
            for token in value.split(',').map(str::trim) {
                if token.eq_ignore_ascii_case("close") {
                    has_close = true;
                } else if token.eq_ignore_ascii_case("keep-alive") {
                    has_keep_alive = true;
                }
            }
        }
    }

    if has_close {
        return true;
    }

    if has_keep_alive {
        return false;
    }

    // HTTP/1.0 defaults to close; HTTP/1.1 defaults to keep-alive
    req.version == Version::Http10
}

/// Add a `Connection: close` header to the response if not already present.
fn add_connection_close(resp: &mut Response) {
    let mut replaced = false;
    resp.headers.retain_mut(|(name, value)| {
        if name.eq_ignore_ascii_case("connection") {
            if replaced {
                false
            } else {
                "close".clone_into(value);
                replaced = true;
                true
            }
        } else {
            true
        }
    });
    if !replaced {
        resp.headers
            .push(("Connection".to_owned(), "close".to_owned()));
    }
}

/// Add a `Connection: keep-alive` header to the response if not already present.
fn add_connection_keep_alive(resp: &mut Response) {
    let mut replaced = false;
    resp.headers.retain_mut(|(name, value)| {
        if name.eq_ignore_ascii_case("connection") {
            if replaced {
                false
            } else {
                "keep-alive".clone_into(value);
                replaced = true;
                true
            }
        } else {
            true
        }
    });
    if !replaced {
        resp.headers
            .push(("Connection".to_owned(), "keep-alive".to_owned()));
    }
}

/// Check if the response explicitly requests closing the connection.
fn response_requests_close(resp: &Response) -> bool {
    for (name, value) in &resp.headers {
        if name.eq_ignore_ascii_case("connection") {
            for token in value.split(',').map(str::trim) {
                if token.eq_ignore_ascii_case("close") {
                    return true;
                }
            }
        }
    }
    false
}

fn replace_or_insert_header(resp: &mut Response, header_name: &str, header_value: String) {
    let mut replaced = false;
    resp.headers.retain_mut(|(name, value)| {
        if name.eq_ignore_ascii_case(header_name) {
            if replaced {
                false
            } else {
                header_value.clone_into(value);
                replaced = true;
                true
            }
        } else {
            true
        }
    });
    if !replaced {
        resp.headers.push((header_name.to_owned(), header_value));
    }
}

fn remove_header(resp: &mut Response, header_name: &str) -> bool {
    let before = resp.headers.len();
    resp.headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case(header_name));
    resp.headers.len() != before
}

fn suppress_response_body_for_head(resp: &mut Response) {
    let body_len = resp.body.len();
    let has_content_length = resp
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    let had_transfer_encoding = remove_header(resp, "transfer-encoding");
    let _ = remove_header(resp, "trailer");

    if body_len != 0 || (!has_content_length && had_transfer_encoding) {
        replace_or_insert_header(resp, "Content-Length", body_len.to_string());
    }

    resp.trailers.clear();
    resp.body.clear();
}

/// Align the response version/connection headers with the actual socket policy.
fn finalize_response_persistence(
    request_version: Version,
    resp: &mut Response,
    close_after: bool,
) -> bool {
    if request_version == Version::Http10 {
        resp.version = Version::Http10;
    }

    let close_after = close_after || response_requests_close(resp);
    if close_after {
        add_connection_close(resp);
        return true;
    }

    if request_version == Version::Http10 {
        add_connection_keep_alive(resp);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::h1::types::Method;
    use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
    use crate::runtime::RuntimeBuilder;
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    struct TestIo {
        read_data: Vec<u8>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl TestIo {
        fn new(read_data: Vec<u8>, written: Arc<Mutex<Vec<u8>>>) -> Self {
            Self { read_data, written }
        }
    }

    impl AsyncRead for TestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.read_data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = std::cmp::min(buf.remaining(), self.read_data.len());
            buf.put_slice(&self.read_data[..n]);
            self.read_data.drain(..n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct GatedBodyIo {
        head: Vec<u8>,
        body: Vec<u8>,
        release_marker: Vec<u8>,
        gated_polls: usize,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl GatedBodyIo {
        fn new(
            head: Vec<u8>,
            body: Vec<u8>,
            release_marker: Vec<u8>,
            written: Arc<Mutex<Vec<u8>>>,
        ) -> Self {
            Self {
                head,
                body,
                release_marker,
                gated_polls: 0,
                written,
            }
        }

        fn body_release_seen(&self) -> bool {
            let written = self.written.lock().unwrap();
            written
                .windows(self.release_marker.len())
                .any(|window| window == self.release_marker.as_slice())
        }
    }

    impl AsyncRead for GatedBodyIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.head.is_empty() {
                let n = std::cmp::min(buf.remaining(), self.head.len());
                buf.put_slice(&self.head[..n]);
                self.head.drain(..n);
                return Poll::Ready(Ok(()));
            }

            if self.body.is_empty() {
                return Poll::Ready(Ok(()));
            }

            if self.body_release_seen() {
                let n = std::cmp::min(buf.remaining(), self.body.len());
                buf.put_slice(&self.body[..n]);
                self.body.drain(..n);
                return Poll::Ready(Ok(()));
            }

            self.gated_polls += 1;
            let written_so_far = self.written.lock().unwrap().clone();
            assert!(
                self.gated_polls < 8,
                "request body stayed gated because the server never emitted the expected interim response; wrote so far: {:?}",
                String::from_utf8_lossy(&written_so_far)
            );
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    impl AsyncWrite for GatedBodyIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

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
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![("Connection".into(), "close".into())]);
        assert!(should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_connection_header_keepalive() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(
            Version::Http11,
            vec![("Connection".into(), "keep-alive".into())],
        );
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_http10_default() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http10, vec![]);
        assert!(should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_http10_with_keepalive() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(
            Version::Http10,
            vec![("Connection".into(), "keep-alive".into())],
        );
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_http11_default() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![]);
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_keepalive_disabled() {
        let config = Http1Config {
            keep_alive: false,
            ..Default::default()
        };
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![]);
        assert!(should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_at_request_limit() {
        let config = Http1Config {
            max_requests_per_connection: Some(5),
            ..Default::default()
        };
        let mut state = ConnectionState::new(crate::types::Time::ZERO);
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
        let mut state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![]);

        state.requests_served = 1_000_000;
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn connection_state_tracking() {
        let state = ConnectionState::new(crate::types::Time::ZERO);
        assert_eq!(state.requests_served, 0);
        assert_eq!(state.phase, ConnectionPhase::Idle);
        assert!(!state.exceeded_request_limit(Some(10)));
        assert!(!state.exceeded_request_limit(None));
    }

    #[test]
    fn connection_state_request_limit() {
        let mut state = ConnectionState::new(crate::types::Time::ZERO);
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
        // Should not add duplicate and should overwrite to close
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn add_connection_keep_alive_header() {
        let mut resp = Response::new(200, "OK", Vec::new());
        assert!(resp.headers.is_empty());
        add_connection_keep_alive(&mut resp);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "keep-alive");
    }

    #[test]
    fn add_connection_keep_alive_header_already_present() {
        let mut resp = Response::new(200, "OK", Vec::new());
        resp.headers
            .push(("Connection".to_owned(), "close".to_owned()));
        add_connection_keep_alive(&mut resp);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "keep-alive");
    }

    #[test]
    fn finalize_response_persistence_http10_keepalive_normalizes_version_and_header() {
        let mut resp = Response::new(200, "OK", Vec::new());

        let close_after = finalize_response_persistence(Version::Http10, &mut resp, false);

        assert!(!close_after);
        assert_eq!(resp.version, Version::Http10);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "keep-alive");
    }

    #[test]
    fn finalize_response_persistence_http10_close_normalizes_version_and_header() {
        let mut resp = Response::new(200, "OK", Vec::new());

        let close_after = finalize_response_persistence(Version::Http10, &mut resp, true);

        assert!(close_after);
        assert_eq!(resp.version, Version::Http10);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn finalize_response_persistence_preserves_handler_requested_close() {
        let mut resp = Response::new(200, "OK", Vec::new()).with_header("Connection", "close");

        let close_after = finalize_response_persistence(Version::Http11, &mut resp, false);

        assert!(close_after);
        assert_eq!(resp.version, Version::Http11);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn suppress_response_body_for_head_replaces_chunked_framing() {
        let mut resp = Response::new(200, "OK", b"hello".to_vec())
            .with_header("Trailer", "X-Trace")
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("X-Trace", "abc123");

        suppress_response_body_for_head(&mut resp);

        assert!(resp.body.is_empty());
        assert!(resp.trailers.is_empty());
        assert_eq!(resp.header_value("trailer"), None);
        assert_eq!(resp.header_value("transfer-encoding"), None);
        assert_eq!(resp.header_value("content-length"), Some("5"));
    }

    #[test]
    fn suppress_response_body_for_head_normalizes_stale_content_length() {
        let mut resp =
            Response::new(200, "OK", b"hello".to_vec()).with_header("Content-Length", "999");

        suppress_response_body_for_head(&mut resp);

        assert!(resp.body.is_empty());
        assert_eq!(resp.header_value("content-length"), Some("5"));
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
    fn classify_expectation_none_when_absent() {
        let req = make_request(Version::Http11, vec![]);
        assert_eq!(classify_expectation(&req), ExpectationAction::None);
    }

    #[test]
    fn classify_expectation_continue_for_http11() {
        let req = make_request(
            Version::Http11,
            vec![("Expect".into(), "100-continue".into())],
        );
        assert_eq!(classify_expectation(&req), ExpectationAction::Continue);
    }

    #[test]
    fn classify_expectation_rejects_http10_continue() {
        let req = make_request(
            Version::Http10,
            vec![("Expect".into(), "100-continue".into())],
        );
        assert_eq!(classify_expectation(&req), ExpectationAction::Reject);
    }

    #[test]
    fn classify_expectation_rejects_unsupported_expectation() {
        let req = make_request(Version::Http11, vec![("Expect".into(), "foo".into())]);
        assert_eq!(classify_expectation(&req), ExpectationAction::Reject);
    }

    #[test]
    fn classify_expectation_rejects_mixed_tokens() {
        let req = make_request(
            Version::Http11,
            vec![("Expect".into(), "100-continue, foo".into())],
        );
        assert_eq!(classify_expectation(&req), ExpectationAction::Reject);
    }

    #[test]
    fn request_expects_body_content_length_positive() {
        let req = make_request(Version::Http11, vec![("Content-Length".into(), "5".into())]);
        assert!(request_expects_body(&req));
    }

    #[test]
    fn request_expects_body_content_length_zero() {
        let req = make_request(Version::Http11, vec![("Content-Length".into(), "0".into())]);
        assert!(!request_expects_body(&req));
    }

    #[test]
    fn request_expects_body_chunked_encoding() {
        let req = make_request(
            Version::Http11,
            vec![("Transfer-Encoding".into(), "chunked".into())],
        );
        assert!(request_expects_body(&req));
    }

    #[test]
    fn serve_head_request_omits_response_body_bytes() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::new(|_req| async move { Response::new(200, "OK", b"hello") });
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve head request");

        assert_eq!(state.requests_served, 1);

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(written.contains("Content-Length: 5\r\n"));
        assert!(written.contains("Connection: close\r\n"));
        assert!(written.ends_with("\r\n\r\n"));
        assert!(!written.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn serve_expect_continue_unblocks_body_waiting_client() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let seen_body = Arc::new(Mutex::new(Vec::new()));
        let io = GatedBodyIo::new(
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
            b"hello".to_vec(),
            b"HTTP/1.1 100 Continue\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let seen_body_for_handler = Arc::clone(&seen_body);
        let server = Http1Server::new(move |req| {
            let seen_body_for_handler = Arc::clone(&seen_body_for_handler);
            async move {
                *seen_body_for_handler.lock().unwrap() = req.body.clone();
                Response::new(200, "OK", b"done")
            }
        });
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve expect-continue request");

        assert_eq!(state.requests_served, 1);
        assert_eq!(&*seen_body.lock().unwrap(), b"hello");

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"));
        assert!(written.contains("Content-Length: 4\r\n"));
    }

    #[test]
    fn serve_expect_continue_when_body_arrives_eagerly() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let seen_body = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_vec(),
            Arc::clone(&written),
        );
        let seen_body_for_handler = Arc::clone(&seen_body);
        let server = Http1Server::new(move |req| {
            let seen_body_for_handler = Arc::clone(&seen_body_for_handler);
            async move {
                *seen_body_for_handler.lock().unwrap() = req.body.clone();
                Response::new(200, "OK", b"done")
            }
        });
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve eager expect-continue request");

        assert_eq!(state.requests_served, 1);
        assert_eq!(&*seen_body.lock().unwrap(), b"hello");

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"));
        assert!(written.contains("Content-Length: 4\r\n"));
    }

    #[test]
    fn serve_rejects_unsupported_expectation_before_body_arrives() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let handler_called = Arc::new(AtomicBool::new(false));
        let io = GatedBodyIo::new(
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nExpect: fancy-feature\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
            b"hello".to_vec(),
            b"HTTP/1.1 417 Expectation Failed\r\n".to_vec(),
            Arc::clone(&written),
        );
        let handler_called_for_handler = Arc::clone(&handler_called);
        let server = Http1Server::new(move |_req| {
            handler_called_for_handler.store(true, Ordering::SeqCst);
            async move { Response::new(200, "OK", b"nope") }
        });
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve unsupported expect request");

        assert_eq!(state.requests_served, 1);
        assert!(!handler_called.load(Ordering::SeqCst));

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 417 Expectation Failed\r\n"));
        assert!(written.contains("Connection: close\r\n"));
        assert!(!written.contains("200 OK"));
    }

    #[test]
    fn connection_phase_equality() {
        assert_eq!(ConnectionPhase::Idle, ConnectionPhase::Idle);
        assert_ne!(ConnectionPhase::Idle, ConnectionPhase::Reading);
        assert_ne!(ConnectionPhase::Processing, ConnectionPhase::Writing);
    }

    #[test]
    fn connection_phase_debug_clone_copy() {
        let p = ConnectionPhase::Closing;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Closing"));

        let p2 = p;
        assert_eq!(p, p2);

        // Copy
        let p3 = p;
        assert_eq!(p, p3);
    }

    #[test]
    fn http1_config_debug_clone() {
        let c = Http1Config::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Http1Config"));

        let c2 = c;
        assert_eq!(c2.max_headers_size, 64 * 1024);
        assert!(c2.keep_alive);
    }
}
