//! Bounded native HTTP/2 requests over an owned transport.
//!
//! Each request drives its connection in the calling task. No background task,
//! redirect, or retry is implicit. Cleartext URLs use HTTP/2 prior knowledge;
//! HTTPS requires a caller-supplied TLS connector and `h2` ALPN. Both upload
//! and download advance while the other direction is blocked by flow control.
//! The connection is closed when the response finishes, the request fails, or
//! the request future is dropped, unless the client opted into keeping idle
//! connections for reuse ([`Http2Client::reuse_connections`]).
//!
//! ```no_run
//! # async fn example(cx: &asupersync::Cx) -> Result<(), Box<dyn std::error::Error>> {
//! use asupersync::http::h2::Http2Client;
//! let response = Http2Client::new()
//!     .post("http://127.0.0.1:8080/echo")
//!     .header("content-type", "application/octet-stream")
//!     .body(vec![42; 200_000])
//!     .send(cx)
//!     .await?;
//! assert_eq!(response.status, 200);
//! assert_eq!(response.body.len(), 200_000);
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, Waker};
use std::time::Duration;

use crate::bytes::Bytes;
use crate::codec::Framed;
use crate::cx::{CancelWakerToken, Cx};
use crate::http::h1::codec::validate_header_field;
use crate::http::{Method, ParsedUrl, Scheme};
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use crate::net::TcpStream;
use crate::stream::Stream;
use crate::time::Sleep;
use crate::types::{CancelReason, Time};
use parking_lot::Mutex;

use super::connection::{CLIENT_PREFACE, ReceivedFrame};
use super::{Connection, ConnectionState, ErrorCode, Frame, FrameCodec, H2Error, Header, Settings};

const DEFAULT_BODY_LIMIT: usize = 16 * 1024 * 1024;
const HEADER_LIMIT: usize = 64 * 1024;
const DATA_CHUNK: usize = 16 * 1024;
const POLL_STEPS: usize = 32;
/// Default number of overhead frames (PING, unsolicited SETTINGS, PRIORITY,
/// unknown extension frames, and empty or padding-only DATA without
/// END_STREAM) a server may send during one use of a connection; one more
/// fails the request with a connection error `ENHANCE_YOUR_CALM` and drops
/// the connection. See `is_overhead_frame`.
const DEFAULT_MAX_OVERHEAD_FRAMES: usize = 10_000;
/// Advertised receive-window bounds (RFC 9113 §6.9.2). The response body is
/// buffered up to its limit anyway, so the windows track that limit within
/// these bounds instead of granting 64 KiB of credit per round trip.
const MIN_RECEIVE_WINDOW: u32 = 65_535;
const MAX_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;

/// Failure of a bounded HTTP/2 request.
#[derive(Debug)]
pub enum Http2ClientError {
    /// Invalid URL, method, request header, or framing declaration.
    InvalidRequest(String),
    /// Native I/O authority is unavailable or restricted.
    MissingIoCapability,
    /// DNS, TCP, or transport I/O failed.
    Io(io::Error),
    /// TLS configuration, certificate verification, handshake, or ALPN failed.
    Tls(String),
    /// A peer violated HTTP/2 or HTTP message semantics.
    Protocol(H2Error),
    /// The peer reset this request stream.
    Reset(ErrorCode),
    /// GOAWAY refused the request or terminated the connection with an error.
    GoAway {
        /// Last request stream the peer might have processed.
        last_stream_id: u32,
        /// Peer's connection error code.
        error_code: ErrorCode,
    },
    /// An upload or response exceeded its configured byte limit.
    BodyTooLarge {
        /// Whether the limit was applied to the request body.
        request: bool,
        /// Configured maximum number of bytes.
        limit: usize,
    },
    /// The total request deadline or an inherited budget deadline expired.
    DeadlineExceeded,
    /// Cancellation of either the caller or the task driving the transport.
    Cancelled(CancelReason),
}

impl fmt::Display for Http2ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => write!(f, "invalid HTTP/2 request: {reason}"),
            Self::MissingIoCapability => f.write_str("HTTP/2 requires native I/O authority"),
            Self::Io(error) => write!(f, "HTTP/2 transport: {error}"),
            Self::Tls(error) => write!(f, "HTTP/2 TLS: {error}"),
            Self::Protocol(error) => error.fmt(f),
            Self::Reset(code) => write!(f, "HTTP/2 peer reset request: {code}"),
            Self::GoAway {
                last_stream_id,
                error_code,
            } => {
                write!(
                    f,
                    "HTTP/2 GOAWAY after stream {last_stream_id}: {error_code}"
                )
            }
            Self::BodyTooLarge { request, limit } => write!(
                f,
                "HTTP/2 {} body exceeds {limit} bytes",
                if *request { "request" } else { "response" },
            ),
            Self::DeadlineExceeded => f.write_str("HTTP/2 total request deadline exceeded"),
            Self::Cancelled(reason) => write!(f, "HTTP/2 request cancelled: {reason:?}"),
        }
    }
}

impl std::error::Error for Http2ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Http2ClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<H2Error> for Http2ClientError {
    fn from(error: H2Error) -> Self {
        Self::Protocol(error)
    }
}

/// Complete HTTP/2 response, including trailers and a bounded buffered body.
#[derive(Debug, Clone)]
pub struct Http2Response {
    /// Final response status. Informational responses are consumed internally.
    pub status: u16,
    /// Final response fields, excluding the `:status` pseudo-header.
    pub headers: Vec<Header>,
    /// Response trailers. Never merged into the initial headers.
    pub trailers: Vec<Header>,
    /// Complete response payload.
    pub body: Bytes,
}

impl Http2Response {
    /// Return the first final response field with this case-insensitive name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    /// Borrow the body as UTF-8 text without changing its bytes.
    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }
}

/// Native HTTP/2 client configuration, cheaply cloned for independent calls.
///
/// Defaults are a 30-second total timeout and 16 MiB each for upload and
/// response. Header sections, including informational responses and trailers,
/// share a 64 KiB decoded limit. A request owns one connection (by default a
/// fresh one; see [`Self::reuse_connections`]); concurrent calls have
/// independent transports and cannot cancel one another.
#[derive(Clone)]
pub struct Http2Client {
    timeout: Duration,
    max_request_body: usize,
    max_response_body: usize,
    max_overhead_frames: usize,
    #[cfg(feature = "tls")]
    tls_connector: Option<crate::tls::TlsConnector>,
    /// Idle connections kept for reuse ([`Self::reuse_connections`]).
    pool: Option<Arc<ConnectionPool>>,
}

impl fmt::Debug for Http2Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http2Client")
            .field("timeout", &self.timeout)
            .field("max_request_body", &self.max_request_body)
            .field("max_response_body", &self.max_response_body)
            .field("max_overhead_frames", &self.max_overhead_frames)
            .finish_non_exhaustive()
    }
}

impl Default for Http2Client {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_request_body: DEFAULT_BODY_LIMIT,
            max_response_body: DEFAULT_BODY_LIMIT,
            max_overhead_frames: DEFAULT_MAX_OVERHEAD_FRAMES,
            #[cfg(feature = "tls")]
            tls_connector: None,
            pool: None,
        }
    }
}

impl Http2Client {
    /// Construct a client with bounded defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the total deadline covering resolution, connection, TLS, and body.
    /// A per-request timeout or inherited context budget can only shorten it.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the largest accepted upload. Zero accepts only an empty body.
    #[must_use]
    pub fn max_request_body(mut self, bytes: usize) -> Self {
        self.max_request_body = bytes;
        self
    }

    /// Set the largest buffered response. Zero accepts only an empty body.
    #[must_use]
    pub fn max_response_body(mut self, bytes: usize) -> Self {
        self.max_response_body = bytes;
        self
    }

    /// Set how many overhead frames the server may send during one use of a
    /// connection: PING, SETTINGS other than the server's connection-preface
    /// SETTINGS, PRIORITY, unknown extension frames, and empty or
    /// padding-only DATA without END_STREAM. One more fails the request with
    /// a connection error `ENHANCE_YOUR_CALM` and drops the connection.
    /// Acknowledgements of the client's own SETTINGS are not counted, nor is
    /// WINDOW_UPDATE, which an upload legitimately receives many of.
    ///
    /// The budget covers one use of the connection, not its lifetime: a
    /// request, plus, on a reused pooled connection
    /// ([`Self::reuse_connections`]), what the server sent while the
    /// connection sat idle before it. A pooled connection that used its whole
    /// budget is not reused. `0` admits no overhead frame at all. Defaults to
    /// 10,000.
    #[must_use]
    pub fn max_overhead_frames(mut self, limit: usize) -> Self {
        self.max_overhead_frames = limit;
        self
    }

    /// Supply certificate trust and TLS configuration for HTTPS. The
    /// connector must offer `h2`; a different negotiated ALPN is rejected.
    ///
    /// With [`Self::reuse_connections`] on, the client gets its own empty
    /// pool here, with the same limit. A clone given another connector, that
    /// is another client identity or trust policy, so never reuses a
    /// connection that was authenticated under this one's
    /// (br-asupersync-mu5yhv).
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls_connector(mut self, connector: crate::tls::TlsConnector) -> Self {
        self.tls_connector = Some(connector);
        if let Some(pool) = &self.pool {
            self.pool = Some(Arc::new(ConnectionPool {
                max_idle: pool.max_idle,
                idle: Mutex::new(HashMap::new()),
            }));
        }
        self
    }

    /// Keep up to `max_idle` connections per origin (scheme, host and port)
    /// open after [`Http2RequestBuilder::send`] completes a request, so later
    /// requests from this client, or a clone of it, reuse them instead of
    /// dialing (and TLS-handshaking) again. A clone later given its own
    /// `tls_connector` stops sharing. `0`, the default, keeps the
    /// original behavior: each request owns a fresh connection.
    ///
    /// A pooled connection carries one request at a time; concurrent requests
    /// use separate connections, and at most `max_idle` per origin are kept
    /// between requests. Before reuse, whatever the server sent while the
    /// connection was idle is processed: one the server closed or sent GOAWAY
    /// on, or one idle for over 30 seconds, is dropped instead. If a reused
    /// connection turns out to be gone before the server could act on the
    /// request (the stream could not be opened, was refused, or GOAWAY
    /// excludes it), the request is retried once on a fresh connection. A
    /// connection whose request ended early (an error, or a response before
    /// the upload finished) is not reused. [`Http2RequestBuilder::send_on`]
    /// never pools its caller-supplied transport.
    #[must_use]
    pub fn reuse_connections(mut self, max_idle: usize) -> Self {
        self.pool = (max_idle > 0).then(|| {
            Arc::new(ConnectionPool {
                max_idle,
                idle: Mutex::new(HashMap::new()),
            })
        });
        self
    }

    /// Begin a request with an explicit method and absolute HTTP(S) URL.
    #[must_use]
    pub fn request(&self, method: Method, url: impl Into<String>) -> Http2RequestBuilder {
        Http2RequestBuilder {
            client: self.clone(),
            method,
            url: url.into(),
            headers: Vec::new(),
            body: Bytes::new(),
            timeout: None,
        }
    }

    /// Begin a GET request.
    #[must_use]
    pub fn get(&self, url: impl Into<String>) -> Http2RequestBuilder {
        self.request(Method::Get, url)
    }

    /// Begin a POST request.
    #[must_use]
    pub fn post(&self, url: impl Into<String>) -> Http2RequestBuilder {
        self.request(Method::Post, url)
    }
}

/// Fluent builder for one owned HTTP/2 exchange.
#[derive(Debug)]
pub struct Http2RequestBuilder {
    client: Http2Client,
    method: Method,
    url: String,
    headers: Vec<Header>,
    body: Bytes,
    timeout: Option<Duration>,
}

impl Http2RequestBuilder {
    /// Append a regular field. Names are normalized to lowercase; pseudo-fields,
    /// connection-specific fields, conflicting Host, invalid bytes, and values
    /// with leading or trailing whitespace fail before opening a socket.
    /// Repeated ordinary fields are preserved.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .push(Header::new(name.into().to_ascii_lowercase(), value));
        self
    }

    /// Set the buffered request body, subject to the client's upload limit.
    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Further shorten this request's total timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Override, for this request, how many overhead frames the server may
    /// send during this use of its connection
    /// ([`Http2Client::max_overhead_frames`]). The budget is per use, not per
    /// connection lifetime: a reused pooled connection starts this request
    /// with a fresh budget, which also covers what the server sent while the
    /// connection sat idle.
    #[must_use]
    pub fn max_overhead_frames(mut self, limit: usize) -> Self {
        self.client.max_overhead_frames = limit;
        self
    }

    /// Connect and execute in the caller's task. DNS, TLS, blocked flow control,
    /// and response collection share the same deadline and cancellation guard.
    pub async fn send(self, cx: &Cx) -> Result<Http2Response, Http2ClientError> {
        let request = self.prepare()?;
        let timeout = self
            .timeout
            .unwrap_or(self.client.timeout)
            .min(self.client.timeout);
        drive(cx, timeout, async {
            require_native_io(cx)?;
            let host = request.url.host.trim_matches(['[', ']']).to_owned();
            if request.url.scheme == Scheme::Https {
                #[cfg(feature = "tls")]
                if self.client.tls_connector.is_none() {
                    return Err(Http2ClientError::Tls(
                        "HTTPS requires a TLS connector".into(),
                    ));
                }
                #[cfg(not(feature = "tls"))]
                return Err(Http2ClientError::Tls("TLS support is disabled".into()));
            }
            let limit = self.client.max_response_body;
            let origin: Origin = (
                request.url.scheme == Scheme::Https,
                host.clone(),
                request.url.port,
            );
            if let Some(pool) = &self.client.pool {
                // Stale idle connections are dropped; a request the server
                // provably did not process on a reused connection is retried
                // once, on a fresh one.
                while let Some(mut conn) = pool.take(&origin, pool_now(cx)) {
                    conn.max_overhead_frames = self.client.max_overhead_frames;
                    if conn.refresh().await.is_err() {
                        continue;
                    }
                    match conn
                        .request(request.clone(), self.body.clone(), limit)
                        .await
                    {
                        Ok((response, closed)) => {
                            if closed && conn.reusable() {
                                pool.put(origin, conn, pool_now(cx));
                            }
                            return Ok(response);
                        }
                        Err(failure) if failure.unprocessed => break,
                        Err(failure) => return Err(failure.error),
                    }
                }
            }
            let tcp = if let Ok(ip) = host.parse::<IpAddr>() {
                TcpStream::connect(SocketAddr::new(ip, request.url.port)).await?
            } else {
                crate::net::happy_eyeballs::connect_resolved((host.clone(), request.url.port), None)
                    .await?
            };
            let transport = DialedTransport::Plain(tcp);
            #[cfg(feature = "tls")]
            let transport = if request.url.scheme == Scheme::Https {
                let DialedTransport::Plain(tcp) = transport else {
                    unreachable!("dialed above")
                };
                let connector = self.client.tls_connector.as_ref().ok_or_else(|| {
                    Http2ClientError::Tls("HTTPS requires a TLS connector".into())
                })?;
                let tls = connector
                    .connect(&host, tcp)
                    .await
                    .map_err(|error| Http2ClientError::Tls(error.to_string()))?;
                if tls.alpn_protocol() != Some(b"h2".as_slice()) {
                    return Err(Http2ClientError::Tls(
                        "peer did not negotiate h2 ALPN".into(),
                    ));
                }
                DialedTransport::Tls(tls)
            } else {
                transport
            };
            let mut conn =
                Http2Conn::start(transport, limit, self.client.max_overhead_frames).await?;
            let (response, closed) = conn
                .request(request, self.body, limit)
                .await
                .map_err(|failure| failure.error)?;
            if let Some(pool) = &self.client.pool
                && closed
                && conn.reusable()
            {
                pool.put(origin, conn, pool_now(cx));
            }
            Ok(response)
        })
        .await
    }

    /// Execute on a transport supplied by the caller, starting with the HTTP/2
    /// client preface. This takes ownership of `transport`, including on error
    /// and cancellation; dropping the request drops the transport. A caller
    /// supplying TLS is responsible for certificate and `h2` ALPN validation.
    /// The URL supplies HTTP routing information and is not dialed here.
    pub async fn send_on<T>(self, cx: &Cx, transport: T) -> Result<Http2Response, Http2ClientError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let request = self.prepare()?;
        let timeout = self
            .timeout
            .unwrap_or(self.client.timeout)
            .min(self.client.timeout);
        drive(
            cx,
            timeout,
            exchange(
                transport,
                request,
                self.body,
                self.client.max_response_body,
                self.client.max_overhead_frames,
            ),
        )
        .await
    }

    fn prepare(&self) -> Result<PreparedRequest, Http2ClientError> {
        if self.body.len() > self.client.max_request_body {
            return Err(Http2ClientError::BodyTooLarge {
                request: true,
                limit: self.client.max_request_body,
            });
        }
        if Method::from_bytes(self.method.as_str().as_bytes()).is_none() {
            return Err(invalid("method is not an HTTP token"));
        }
        if self.method.as_str() == "CONNECT" {
            return Err(invalid(
                "CONNECT tunnels require an owned duplex stream API",
            ));
        }
        let mut url = ParsedUrl::parse(&self.url).map_err(|error| invalid(error.to_string()))?;
        url.path
            .truncate(url.path.find('#').unwrap_or(url.path.len()));
        if !url.path.starts_with('/') {
            url.path.insert(0, '/');
        }
        if url
            .path
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(invalid(
                "request target contains whitespace or control bytes",
            ));
        }
        // ParsedUrl accepts bare IPv6 literals for H1 compatibility; HTTP/2
        // authority always brackets them, including on the default port.
        if url.host.contains(':') && !url.host.starts_with('[') {
            if url.host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(invalid("invalid IPv6 host"));
            }
            url.host = format!("[{}]", url.host);
        }
        let authority = url.authority();
        let mut headers = vec![
            Header::new(":method", self.method.as_str()),
            Header::new(
                ":scheme",
                if url.scheme == Scheme::Https {
                    "https"
                } else {
                    "http"
                },
            ),
            Header::new(":authority", &authority),
            Header::new(":path", &url.path),
        ];
        let mut content_length = None;
        for header in &self.headers {
            validate_header_field(&header.name, &header.value)
                .map_err(|error| invalid(error.to_string()))?;
            // RFC 9113 §8.2.1: such a field is malformed, and strict peers
            // reset the stream after I/O. Refuse it before a socket opens.
            if header.value.starts_with([' ', '\t']) || header.value.ends_with([' ', '\t']) {
                return Err(invalid(
                    "field value has leading or trailing whitespace (RFC 9113 8.2.1)",
                ));
            }
            match header.name.as_str() {
                "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding"
                | "upgrade" => {
                    return Err(invalid("connection-specific field is forbidden in HTTP/2"));
                }
                "te" if header.value != "trailers" => return Err(invalid("TE must be trailers")),
                "host" if !header.value.eq_ignore_ascii_case(&authority) => {
                    return Err(invalid("Host conflicts with URL authority"));
                }
                "host" => continue,
                "content-length" => {
                    if content_length.is_some() {
                        return Err(invalid("duplicate content-length"));
                    }
                    content_length = Some(parse_length(&header.value).map_err(invalid)?);
                }
                _ => {}
            }
            headers.push(header.clone());
        }
        if content_length.is_some_and(|length| length != self.body.len() as u64) {
            return Err(invalid("content-length does not match request body"));
        }
        if content_length.is_none()
            && (!self.body.is_empty() || self.method == Method::Post || self.method == Method::Put)
        {
            headers.push(Header::new("content-length", self.body.len().to_string()));
        }
        if header_size(&headers) > HEADER_LIMIT {
            return Err(invalid("request headers exceed 64 KiB"));
        }
        Ok(PreparedRequest {
            url,
            headers,
            head: self.method.as_str() == "HEAD",
        })
    }
}

fn invalid(reason: impl Into<String>) -> Http2ClientError {
    Http2ClientError::InvalidRequest(reason.into())
}

fn protocol(reason: impl Into<String>) -> Http2ClientError {
    H2Error::protocol(reason).into()
}

fn parse_length(value: &str) -> Result<u64, &'static str> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid content-length");
    }
    value.parse().map_err(|_| "content-length overflows u64")
}

fn header_size(headers: &[Header]) -> usize {
    headers.iter().fold(0usize, |size, header| {
        size.saturating_add(header.name.len())
            .saturating_add(header.value.len())
            .saturating_add(32)
    })
}

fn require_native_io(cx: &Cx) -> Result<(), Http2ClientError> {
    let ambient = Cx::current().ok_or(Http2ClientError::MissingIoCapability)?;
    if [cx, &ambient].into_iter().any(|context| {
        !context.runtime_mask.has(crate::cx::cap::CapMask::IO)
            || context.io_driver_handle().is_none()
    }) {
        return Err(Http2ClientError::MissingIoCapability);
    }
    Ok(())
}

struct Cancellation {
    cx: Cx,
    token: Option<CancelWakerToken>,
}

impl Cancellation {
    fn new(cx: Cx) -> Self {
        Self { cx, token: None }
    }

    fn register(&mut self, waker: &Waker) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token, waker));
    }

    fn check(&self) -> Result<(), Http2ClientError> {
        self.cx.checkpoint().map_err(|_| {
            Http2ClientError::Cancelled(
                self.cx
                    .cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("HTTP/2 caller cancelled")),
            )
        })
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

async fn drive<T>(
    cx: &Cx,
    timeout: Duration,
    future: impl Future<Output = Result<T, Http2ClientError>>,
) -> Result<T, Http2ClientError> {
    let mut caller = Cancellation::new(cx.clone());
    let mut ambient = Cx::current().map(Cancellation::new);
    let driver = cx
        .timer_driver()
        .or_else(|| ambient.as_ref().and_then(|guard| guard.cx.timer_driver()));
    let now = driver
        .as_ref()
        .map_or_else(crate::time::wall_now, |driver| driver.now());
    let nanos = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
    let mut deadline = now.saturating_add_nanos(nanos);
    for context in std::iter::once(cx).chain(ambient.as_ref().map(|guard| &guard.cx)) {
        if let Some(budget) = context.budget().deadline {
            deadline = deadline.min(budget);
        }
    }
    let mut sleep = driver.as_ref().map_or_else(
        || Sleep::new(deadline),
        |driver| Sleep::with_timer_driver(deadline, driver.clone()),
    );
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        // Registration precedes checkpoint: cancellation can occur during a
        // custom Waker's clone callback, before its registry entry is visible.
        caller.register(task.waker());
        if let Some(ambient) = &mut ambient {
            ambient.register(task.waker());
        }
        let now = driver
            .as_ref()
            .map_or_else(crate::time::wall_now, |driver| driver.now());
        if now >= deadline {
            return Poll::Ready(Err(Http2ClientError::DeadlineExceeded));
        }
        caller.check()?;
        if let Some(ambient) = &ambient {
            ambient.check()?;
        }
        if Pin::new(&mut sleep).poll_deadline(task).is_ready() {
            // An early timer wake must never cause polling a completed Sleep.
            sleep.reset(deadline);
            task.waker().wake_by_ref();
        }
        future.as_mut().poll(task)
    })
    .await
}

#[derive(Clone)]
struct PreparedRequest {
    url: ParsedUrl,
    headers: Vec<Header>,
    head: bool,
}

struct ResponseState {
    response: Http2Response,
    header_bytes: usize,
    content_length: Option<u64>,
    body: Vec<u8>,
    head: bool,
    limit: usize,
}

impl ResponseState {
    fn new(head: bool, limit: usize) -> Self {
        Self {
            response: Http2Response {
                status: 0,
                headers: Vec::new(),
                trailers: Vec::new(),
                body: Bytes::new(),
            },
            header_bytes: 0,
            content_length: None,
            body: Vec::new(),
            head,
            limit,
        }
    }

    fn headers(&mut self, headers: Vec<Header>, end: bool) -> Result<bool, Http2ClientError> {
        self.header_bytes = self.header_bytes.saturating_add(header_size(&headers));
        if self.header_bytes > HEADER_LIMIT {
            return Err(protocol("response headers exceed 64 KiB"));
        }
        for header in &headers {
            if !header.name.starts_with(':') {
                validate_header_field(&header.name, &header.value)
                    .map_err(|error| protocol(error.to_string()))?;
            }
            // RFC 9113 §8.2.1: field values MUST NOT start or end with SP or HTAB.
            if header.value.starts_with([' ', '\t']) || header.value.ends_with([' ', '\t']) {
                return Err(protocol(
                    "response field value has leading or trailing whitespace (RFC 9113 8.2.1)",
                ));
            }
        }
        if self.response.status != 0 {
            if !end
                || headers
                    .iter()
                    .any(|header| header.name == "content-length" || header.name.starts_with(':'))
            {
                return Err(protocol("invalid response trailers"));
            }
            self.response.trailers = headers;
            return self.finish();
        }
        let status = headers
            .iter()
            .find(|header| header.name == ":status")
            .ok_or_else(|| protocol("response has no :status"))?
            .value
            .as_str();
        if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(protocol("invalid response status"));
        }
        let status: u16 = status
            .parse()
            .map_err(|_| protocol("invalid response status"))?;
        if !(100..=599).contains(&status) || status == 101 {
            return Err(protocol("invalid HTTP/2 response status"));
        }
        if status < 200 {
            if end || headers.iter().any(|header| header.name == "content-length") {
                return Err(protocol(
                    "informational response ends stream or declares a body",
                ));
            }
            return Ok(false);
        }
        for header in &headers {
            if header.name == "content-length" {
                if self.content_length.is_some() {
                    return Err(protocol("duplicate response content-length"));
                }
                self.content_length = Some(parse_length(&header.value).map_err(protocol)?);
            }
        }
        if status == 204 && self.content_length.is_some() {
            return Err(protocol("204 response has content-length"));
        }
        self.response.status = status;
        self.response.headers = headers
            .into_iter()
            .filter(|header| !header.name.starts_with(':'))
            .collect();
        if !self.bodyless()
            && self
                .content_length
                .is_some_and(|length| length > self.limit as u64)
        {
            return Err(Http2ClientError::BodyTooLarge {
                request: false,
                limit: self.limit,
            });
        }
        if end { self.finish() } else { Ok(false) }
    }

    fn bodyless(&self) -> bool {
        self.head || self.response.status == 204 || self.response.status == 304
    }

    fn data(&mut self, data: &[u8], end: bool) -> Result<bool, Http2ClientError> {
        if self.response.status == 0 {
            return Err(protocol("DATA precedes final response headers"));
        }
        if self.bodyless() && !data.is_empty() {
            return Err(protocol("DATA on a bodyless response"));
        }
        if data.len() > self.limit.saturating_sub(self.body.len()) {
            return Err(Http2ClientError::BodyTooLarge {
                request: false,
                limit: self.limit,
            });
        }
        self.body.extend_from_slice(data);
        if !self.bodyless()
            && self
                .content_length
                .is_some_and(|length| self.body.len() as u64 > length)
        {
            return Err(protocol("response exceeds content-length"));
        }
        if end { self.finish() } else { Ok(false) }
    }

    fn finish(&mut self) -> Result<bool, Http2ClientError> {
        if !self.bodyless()
            && self
                .content_length
                .is_some_and(|length| length != self.body.len() as u64)
        {
            return Err(protocol("response ends before content-length"));
        }
        self.response.body = Bytes::from(std::mem::take(&mut self.body));
        Ok(true)
    }
}

/// The transport under the frame codec. The codec reports a failed read as a
/// protocol error, so this keeps the read error, which the client then
/// reports as the I/O failure it is (br-asupersync-h2-client-audit-6hvls9).
struct ReadErrorTap<T> {
    inner: T,
    read_error: Option<io::Error>,
}

impl<T: AsyncRead + Unpin> AsyncRead for ReadErrorTap<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        task: &mut std::task::Context<'_>,
        buf: &mut crate::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_read(task, buf);
        if let Poll::Ready(Err(error)) = &poll {
            this.read_error = Some(io::Error::new(error.kind(), error.to_string()));
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ReadErrorTap<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        task: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(task, bytes)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        task: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(task, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, task: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(task)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        task: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(task)
    }
}

async fn exchange<T>(
    transport: T,
    request: PreparedRequest,
    body: Bytes,
    limit: usize,
    max_overhead_frames: usize,
) -> Result<Http2Response, Http2ClientError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = Http2Conn::start(transport, limit, max_overhead_frames).await?;
    conn.request(request, body, limit)
        .await
        .map(|(response, _)| response)
        .map_err(|failure| failure.error)
}

/// A request attempt that failed. `unprocessed` means the server provably did
/// not act on it: the stream could not be opened, was refused, or GOAWAY
/// excluded it. Only such a request is retried on another connection.
struct AttemptFailure {
    error: Http2ClientError,
    unprocessed: bool,
}

impl From<Http2ClientError> for AttemptFailure {
    fn from(error: Http2ClientError) -> Self {
        Self {
            error,
            unprocessed: false,
        }
    }
}

impl From<H2Error> for AttemptFailure {
    fn from(error: H2Error) -> Self {
        Http2ClientError::from(error).into()
    }
}

impl From<io::Error> for AttemptFailure {
    fn from(error: io::Error) -> Self {
        Http2ClientError::from(error).into()
    }
}

/// Whether an incoming frame counts against the per-use frame overhead budget
/// ([`Http2Client::max_overhead_frames`]): a frame that costs the client work
/// without carrying the response (CVE-2019-9512 PING flood, CVE-2019-9515
/// SETTINGS flood, and the empty-DATA form of the CVE-2019-9518 empty-frame
/// flood). `connection` is the state before the frame is processed.
///
/// A SETTINGS that is not an ACK forces the client to queue an ACK, so each
/// unsolicited one counts. The exception is the server's connection-preface
/// SETTINGS: the connection stays `Handshaking` until it has processed the
/// first non-ACK SETTINGS, so exactly that one is exempt. A SETTINGS ACK is
/// the server's mandatory reply to the client's own SETTINGS and does not
/// count. WINDOW_UPDATE does not count either: a client uploading a large
/// body legitimately receives thousands. RST_STREAM floods (CVE-2019-9514)
/// are bounded by the connection's peer-reset rate limit, not by this budget.
fn is_overhead_frame(frame: &Frame, connection: &Connection) -> bool {
    match frame {
        Frame::Ping(_) => true,
        Frame::Settings(s) if !s.ack => connection.state() != ConnectionState::Handshaking,
        Frame::Unknown { .. } => true,
        Frame::Priority(_) => true,
        Frame::Data(d) if d.data.is_empty() && !d.end_stream => true,
        _ => false,
    }
}

/// One client HTTP/2 connection, carrying one request at a time.
struct Http2Conn<T> {
    wire: Framed<ReadErrorTap<T>, FrameCodec>,
    connection: Connection,
    /// Overhead frames received during the current use of the connection:
    /// since it was started, or since `refresh` prepared it for reuse.
    overhead_frames: usize,
    max_overhead_frames: usize,
}

impl<T> Http2Conn<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Write the client preface and queue SETTINGS (sent with the request).
    async fn start(
        mut transport: T,
        limit: usize,
        max_overhead_frames: usize,
    ) -> Result<Self, Http2ClientError> {
        transport.write_all(CLIENT_PREFACE).await?;
        let receive_window = u32::try_from(limit)
            .unwrap_or(u32::MAX)
            .clamp(MIN_RECEIVE_WINDOW, MAX_RECEIVE_WINDOW);
        let settings = Settings {
            max_header_list_size: HEADER_LIMIT as u32,
            initial_window_size: receive_window,
            ..Settings::client()
        };
        let mut connection = Connection::client(settings);
        connection.queue_initial_settings();
        // SETTINGS must be the first frame; the connection WINDOW_UPDATE follows it.
        connection.set_initial_connection_recv_window(receive_window)?;
        let transport = ReadErrorTap {
            inner: transport,
            read_error: None,
        };
        let wire =
            Framed::new(transport, FrameCodec::new()).with_max_buffer_len(DATA_CHUNK + 8192 + 9);
        Ok(Self {
            wire,
            connection,
            overhead_frames: 0,
            max_overhead_frames,
        })
    }

    /// Whether another request may open a stream on this connection. A
    /// server that lowered SETTINGS_MAX_CONCURRENT_STREAMS to 0 admits none
    /// for now; a request would wait out its timeout there, so a fresh
    /// connection serves it instead. One that used its whole overhead budget
    /// during its current use is retired.
    fn reusable(&self) -> bool {
        self.connection.state() == ConnectionState::Open
            && !self.connection.goaway_received()
            && !self.connection.goaway_sent()
            && self.connection.remote_settings().max_concurrent_streams != 0
            && self.overhead_frames < self.max_overhead_frames
    }

    /// Before reuse: take in what the server sent while the connection sat
    /// idle, without waiting, and queue the answers (PING, SETTINGS). Fails
    /// when the server closed the connection or sent GOAWAY.
    ///
    /// Starts a new use of the connection, so a fresh overhead budget: it
    /// covers what arrived while idle plus the request that follows. The
    /// pool reuses a connection only through here (br-asupersync-r96ybl).
    async fn refresh(&mut self) -> Result<(), Http2ClientError> {
        self.overhead_frames = 0;
        poll_fn(|task| {
            loop {
                match Pin::new(&mut self.wire).poll_next(task) {
                    Poll::Ready(Some(Ok(frame))) => {
                        if is_overhead_frame(&frame, &self.connection) {
                            if self.overhead_frames >= self.max_overhead_frames {
                                return Poll::Ready(Err(H2Error::connection(
                                    ErrorCode::EnhanceYourCalm,
                                    "HTTP/2 connection frame overhead limit exceeded",
                                )
                                .into()));
                            }
                            self.overhead_frames = self.overhead_frames.saturating_add(1);
                        }
                        self.connection.process_frame(frame)?;
                    }
                    Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error.into())),
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(Http2ClientError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "pooled HTTP/2 connection closed",
                        ))));
                    }
                    Poll::Pending => break,
                }
            }
            if self.reusable() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(protocol("pooled HTTP/2 connection is draining")))
            }
        })
        .await
    }

    /// Run one request on a new stream. On success, also reports whether the
    /// stream is closed in both directions, so the connection may carry
    /// another request.
    async fn request(
        &mut self,
        request: PreparedRequest,
        body: Bytes,
        limit: usize,
    ) -> Result<(Http2Response, bool), AttemptFailure> {
        let Self {
            wire,
            connection,
            overhead_frames,
            max_overhead_frames,
        } = self;
        let mut headers = Some(request.headers);
        let mut stream_id = None;
        let mut sent = 0;
        let mut response = ResponseState::new(request.head, limit);
        poll_fn(|task| -> Poll<Result<(), AttemptFailure>> {
            for _ in 0..POLL_STEPS {
                let mut progress = false;
                // Always read, including while upload writes or flow control are
                // parked. An early final response can terminate a rejected upload.
                match Pin::new(&mut *wire).poll_next(task) {
                    Poll::Ready(Some(Ok(frame))) => {
                        progress = true;
                        if is_overhead_frame(&frame, connection) {
                            if *overhead_frames >= *max_overhead_frames {
                                return Poll::Ready(Err(H2Error::connection(
                                    ErrorCode::EnhanceYourCalm,
                                    "HTTP/2 connection frame overhead limit exceeded",
                                )
                                .into()));
                            }
                            *overhead_frames = overhead_frames.saturating_add(1);
                        }
                        match connection.process_frame(frame)? {
                            Some(ReceivedFrame::Headers {
                                stream_id: id,
                                headers,
                                end_stream,
                            }) if Some(id) == stream_id => {
                                if response.headers(headers, end_stream)? {
                                    return Poll::Ready(Ok(()));
                                }
                            }
                            Some(ReceivedFrame::Data {
                                stream_id: id,
                                data,
                                end_stream,
                            }) if Some(id) == stream_id => {
                                if response.data(&data, end_stream)? {
                                    return Poll::Ready(Ok(()));
                                }
                            }
                            Some(ReceivedFrame::Reset {
                                stream_id: id,
                                error_code,
                            }) if Some(id) == stream_id => {
                                return Poll::Ready(Err(AttemptFailure {
                                    error: Http2ClientError::Reset(error_code),
                                    unprocessed: error_code == ErrorCode::RefusedStream,
                                }));
                            }
                            Some(ReceivedFrame::GoAway {
                                last_stream_id,
                                error_code,
                                ..
                            }) => {
                                let excluded = stream_id.is_none_or(|id| id > last_stream_id);
                                if error_code != ErrorCode::NoError || excluded {
                                    return Poll::Ready(Err(AttemptFailure {
                                        error: Http2ClientError::GoAway {
                                            last_stream_id,
                                            error_code,
                                        },
                                        unprocessed: excluded,
                                    }));
                                }
                            }
                            // A late frame for an earlier request on a reused
                            // connection (a reset after its response, say).
                            Some(
                                ReceivedFrame::Headers { stream_id: id, .. }
                                | ReceivedFrame::Data { stream_id: id, .. }
                                | ReceivedFrame::Reset { stream_id: id, .. },
                            ) if stream_id.is_some_and(|current| id < current) => {}
                            Some(_) => {
                                return Poll::Ready(Err(protocol(
                                    "unexpected HTTP/2 response stream",
                                )
                                .into()));
                            }
                            None => {}
                        }
                    }
                    Poll::Ready(Some(Err(error))) => {
                        let error = wire
                            .get_mut()
                            .read_error
                            .take()
                            .map_or_else(|| error.into(), Http2ClientError::Io);
                        return Poll::Ready(Err(error.into()));
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(Http2ClientError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "peer closed before response completed",
                        ))
                        .into()));
                    }
                    Poll::Pending => {}
                }
                // RFC 9113 §6.5.2: a peer may set SETTINGS_MAX_CONCURRENT_STREAMS
                // to zero, and is expected to raise it again shortly. This
                // connection carries one request, so it waits, within the
                // request's deadline, for a SETTINGS that admits a stream instead
                // of reporting a legal setting as a protocol error.
                if stream_id.is_none()
                    && connection.state() == ConnectionState::Open
                    && connection.remote_settings().max_concurrent_streams != 0
                {
                    let request_headers = headers
                        .take()
                        .ok_or_else(|| protocol("request headers already consumed"))?;
                    // A stream refused locally (GOAWAY seen, identifiers
                    // exhausted) never reached the server.
                    let id = connection
                        .open_stream(request_headers, body.is_empty())
                        .map_err(|error| AttemptFailure {
                            error: error.into(),
                            unprocessed: true,
                        })?;
                    stream_id = Some(id);
                    progress = true;
                }
                if let Some(id) = stream_id
                    && sent < body.len()
                    && !connection.has_pending_frames()
                {
                    let length = connection
                        .available_send_capacity(id)
                        .min(DATA_CHUNK)
                        .min(body.len() - sent);
                    if length != 0 {
                        let end = sent + length;
                        connection.send_data(id, body.slice(sent..end), end == body.len())?;
                        sent = end;
                        progress = true;
                    }
                }
                // Queue at most one bounded frame before returning to the read
                // half. Framed retains partial writes and applies backpressure.
                if connection.has_pending_frames() {
                    match wire.poll_ready(task) {
                        Poll::Ready(Ok(())) => {
                            if let Some(frame) = connection.next_frame() {
                                wire.start_send(frame)?;
                                progress = true;
                            }
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Pending => {}
                    }
                }
                let buffered = !wire.write_buffer().is_empty();
                match wire.poll_flush(task) {
                    Poll::Ready(Ok(())) => progress |= buffered,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => {}
                }
                if !progress {
                    return Poll::Pending;
                }
            }
            task.waker().wake_by_ref();
            Poll::Pending
        })
        .await?;
        let closed_both_ways = sent == body.len()
            && stream_id.is_some_and(|id| !connection.has_pending_frames_for_stream(id));
        Ok((response.response, closed_both_ways))
    }
}

/// The clock pooled connections age on: the context's timer, else wall time.
fn pool_now(cx: &Cx) -> Time {
    cx.timer_driver()
        .map_or_else(crate::time::wall_now, |driver| driver.now())
}

/// How long an idle pooled connection is kept. Shorter than common proxy and
/// load-balancer idle timeouts (60 s and up).
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// A connection [`Http2Client::send`] dialed: plain TCP, or TLS over it.
enum DialedTransport {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(crate::tls::TlsStream<TcpStream>),
}

impl AsyncRead for DialedTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        task: &mut std::task::Context<'_>,
        buf: &mut crate::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(task, buf),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_read(task, buf),
        }
    }
}

impl AsyncWrite for DialedTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        task: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(task, bytes),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_write(task, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, task: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(task),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_flush(task),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        task: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(task),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(task),
        }
    }
}

/// Idle connections an [`Http2Client`] keeps per origin
/// ([`Http2Client::reuse_connections`]); shared by the client's clones.
/// Generic only so its bookkeeping can be tested without sockets.
struct ConnectionPool<C = Http2Conn<DialedTransport>> {
    max_idle: usize,
    idle: Mutex<HashMap<Origin, Vec<(Time, C)>>>,
}

/// Scheme, host and port: what one pooled connection can serve.
type Origin = (bool, String, u16);

/// Whether a connection idle since `since` has outlived [`POOL_IDLE_TIMEOUT`].
fn idle_expired(since: Time, now: Time) -> bool {
    let idle_nanos = now.as_nanos().saturating_sub(since.as_nanos());
    u128::from(idle_nanos) > POOL_IDLE_TIMEOUT.as_nanos()
}

impl<C> ConnectionPool<C> {
    /// The most recently used connection to `origin` that has not idled too
    /// long; expired ones are closed.
    fn take(&self, origin: &Origin, now: Time) -> Option<C> {
        let mut expired = Vec::new();
        let taken = {
            let mut idle = self.idle.lock();
            let conns = idle.get_mut(origin)?;
            let taken = loop {
                let Some((since, conn)) = conns.pop() else {
                    break None;
                };
                if !idle_expired(since, now) {
                    break Some(conn);
                }
                expired.push(conn);
            };
            if conns.is_empty() {
                idle.remove(origin);
            }
            taken
        };
        drop(expired);
        taken
    }

    /// Keep `conn` for reuse, and close the expired idle connections of
    /// every origin: a client that reaches many hosts would otherwise keep a
    /// socket to each until a request to that same host came along.
    fn put(&self, origin: Origin, conn: C, now: Time) {
        let mut expired = Vec::new();
        {
            let mut idle = self.idle.lock();
            idle.retain(|_, conns| {
                let mut index = 0;
                while index < conns.len() {
                    if idle_expired(conns[index].0, now) {
                        expired.push(conns.remove(index).1);
                    } else {
                        index += 1;
                    }
                }
                !conns.is_empty()
            });
            let conns = idle.entry(origin).or_default();
            if conns.len() < self.max_idle {
                conns.push((now, conn));
            }
        }
        drop(expired);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake};

    /// mu5yhv finding 1: clones share the pool, keyed by scheme, host and
    /// port only. A clone given another connector (another client identity
    /// or trust policy) took connections authenticated under the first one.
    #[cfg(feature = "tls")]
    #[test]
    fn a_clone_given_another_tls_connector_gets_its_own_pool() {
        let connector = || {
            let certs = crate::tls::Certificate::from_pem(include_bytes!(
                "../../../tests/fixtures/tls/server.crt"
            ))
            .expect("test certificate");
            crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_h2()
                .build()
                .expect("test connector")
        };
        let pool = |client: &Http2Client| Arc::clone(client.pool.as_ref().expect("reuse is on"));

        let base = Http2Client::new().reuse_connections(2);
        let a = base.clone().tls_connector(connector());
        let b = base.clone().tls_connector(connector());
        assert!(
            !Arc::ptr_eq(&pool(&a), &pool(&b)),
            "clones with different connectors must not share idle connections"
        );
        assert!(!Arc::ptr_eq(&pool(&base), &pool(&a)));
        assert_eq!(pool(&a).max_idle, 2);

        let a_again = a.clone();
        assert!(
            Arc::ptr_eq(&pool(&a), &pool(&a_again)),
            "a clone that keeps its connector still shares"
        );
        assert!(Http2Client::new().tls_connector(connector()).pool.is_none());
    }

    #[derive(Default)]
    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct SilentTransport(Arc<AtomicUsize>);

    impl Drop for SilentTransport {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl AsyncRead for SilentTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for SilentTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A transport that accepts writes and whose reads fail with the given
    /// kind, or end the stream (`None`).
    struct FailingReadTransport(Option<io::ErrorKind>);

    impl AsyncRead for FailingReadTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(match self.0 {
                Some(kind) => Err(io::Error::new(kind, "transport read failed")),
                None => Ok(()),
            })
        }
    }

    impl AsyncWrite for FailingReadTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// br-asupersync-h2-client-audit-6hvls9 LOW 3: a failed transport read
    /// came back as Protocol(INTERNAL_ERROR), and a peer that closed the
    /// connection mid-response as Protocol too. Io is documented as the
    /// transport failure, so a retry policy keyed on it misread both.
    #[test]
    fn transport_read_failure_and_eof_are_reported_as_io() {
        for (transport, expected) in [
            (
                FailingReadTransport(Some(io::ErrorKind::ConnectionReset)),
                io::ErrorKind::ConnectionReset,
            ),
            (FailingReadTransport(None), io::ErrorKind::UnexpectedEof),
        ] {
            let caller = Cx::for_testing();
            let waker = Waker::from(Arc::new(CountWake::default()));
            let mut task = Context::from_waker(&waker);
            let mut future = Box::pin(
                Http2Client::new()
                    .get("http://localhost/")
                    .send_on(&caller, transport),
            );
            match future.as_mut().poll(&mut task) {
                Poll::Ready(Err(Http2ClientError::Io(error))) => {
                    assert_eq!(error.kind(), expected);
                }
                other => panic!("expected an I/O error of kind {expected:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn explicit_caller_cancellation_wakes_and_drops_owned_transport() {
        let caller = Cx::for_testing();
        let ambient = Cx::for_testing();
        let _current = Cx::set_current(Some(ambient.clone()));
        let dropped = Arc::new(AtomicUsize::new(0));
        let wake = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(
            Http2Client::new()
                .get("http://localhost/")
                .send_on(&caller, SilentTransport(Arc::clone(&dropped))),
        );
        assert!(future.as_mut().poll(&mut task).is_pending());
        let before = wake.0.load(Ordering::SeqCst);
        let reason =
            CancelReason::deadline().with_cause(CancelReason::user("HTTP ingress stopped"));
        caller.cancel_with_reason(reason.clone());
        assert!(wake.0.load(Ordering::SeqCst) > before);
        match future.as_mut().poll(&mut task) {
            Poll::Ready(Err(Http2ClientError::Cancelled(actual))) => assert_eq!(actual, reason),
            other => panic!("caller cancellation was not returned: {other:?}"),
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(ambient.checkpoint().is_ok());
        let before = wake.0.load(Ordering::SeqCst);
        ambient.cancel_with_reason(CancelReason::shutdown());
        assert_eq!(
            wake.0.load(Ordering::SeqCst),
            before,
            "completed request retained its ambient registration"
        );
    }

    #[test]
    fn masked_ambient_cancellation_does_not_self_wake_a_parked_request() {
        let caller = Cx::for_testing();
        let ambient = Cx::for_testing();
        let _current = Cx::set_current(Some(ambient.clone()));
        let dropped = Arc::new(AtomicUsize::new(0));
        let wake = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(
            Http2Client::new()
                .get("http://localhost/")
                .send_on(&caller, SilentTransport(Arc::clone(&dropped))),
        );
        ambient.cancel_with_reason(CancelReason::shutdown());
        ambient.masked(|| {
            let before = wake.0.load(Ordering::SeqCst);
            assert!(future.as_mut().poll(&mut task).is_pending());
            assert!(future.as_mut().poll(&mut task).is_pending());
            assert_eq!(
                wake.0.load(Ordering::SeqCst),
                before,
                "masked cancellation turned the deadline timer into a busy loop"
            );
        });
        assert!(matches!(
            future.as_mut().poll(&mut task),
            Poll::Ready(Err(Http2ClientError::Cancelled(_)))
        ));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn request_validation_and_authority_are_applied_before_io() {
        let client = Http2Client::new();
        for builder in [
            client.get("http://localhost/").header(":path", "/override"),
            client
                .get("http://localhost/")
                .header("connection", "close"),
            client
                .get("http://localhost/")
                .header("host", "attacker.invalid"),
            client
                .post("http://localhost/")
                .header("content-length", "2")
                .body("x"),
            client
                .post("http://localhost/")
                .header("content-length", "0")
                .header("content-length", "0"),
            client.get("http://localhost/a\rb"),
            // asupersync-e427ys: RFC 9113 §8.2.1 malformed field values.
            client.get("http://localhost/").header("x-pad", " leading"),
            client
                .get("http://localhost/")
                .header("x-pad", "trailing\t"),
            client.request(Method::Extension("G ET".into()), "http://localhost/"),
            client.request(Method::Connect, "http://localhost/"),
        ] {
            assert!(matches!(
                builder.prepare(),
                Err(Http2ClientError::InvalidRequest(_))
            ));
        }
        let request = client.get("http://[::1]?x=1#secret").prepare().unwrap();
        assert_eq!(request.url.path, "/?x=1");
        assert_eq!(request.url.authority(), "[::1]");
        assert!(
            client
                .clone()
                .max_request_body(0)
                .post("http://localhost/")
                .body("x")
                .prepare()
                .is_err()
        );
    }

    #[test]
    fn response_metadata_and_framing_are_bounded() {
        let mut state = ResponseState::new(false, 3);
        assert!(
            !state
                .headers(
                    vec![Header::new(":status", "103"), Header::new("link", "</a>")],
                    false
                )
                .unwrap()
        );
        assert!(
            !state
                .headers(
                    vec![
                        Header::new(":status", "200"),
                        Header::new("content-length", "3")
                    ],
                    false
                )
                .unwrap()
        );
        assert!(!state.data(b"abc", false).unwrap());
        assert!(
            state
                .headers(vec![Header::new("x-checksum", "yes")], true)
                .unwrap()
        );
        assert_eq!(state.response.body.as_ref(), b"abc");
        assert_eq!(state.response.trailers[0].value, "yes");
        let mut head = ResponseState::new(true, 0);
        assert!(
            head.headers(
                vec![
                    Header::new(":status", "200"),
                    Header::new("content-length", "900000")
                ],
                true
            )
            .unwrap()
        );
        let mut truncated = ResponseState::new(false, 10);
        truncated
            .headers(
                vec![
                    Header::new(":status", "200"),
                    Header::new("content-length", "3"),
                ],
                false,
            )
            .unwrap();
        assert!(truncated.data(b"ab", true).is_err());
        let mut metadata = ResponseState::new(false, 10);
        let information = vec![
            Header::new(":status", "103"),
            Header::new("link", "x".repeat(HEADER_LIMIT / 2)),
        ];
        assert!(metadata.headers(information.clone(), false).is_ok());
        assert!(metadata.headers(information, false).is_err());
    }

    /// asupersync-mu5yhv (d0's LOW 1): an idle connection was closed only
    /// when a later request went to its own origin, so a client that reached
    /// many hosts kept a socket to each. Putting any connection back now
    /// closes the expired ones of every origin.
    #[test]
    fn putting_a_connection_back_closes_the_expired_idle_ones_of_every_origin() {
        let pool = ConnectionPool::<u32> {
            max_idle: 4,
            idle: Mutex::new(HashMap::new()),
        };
        let origin = |host: &str| -> Origin { (false, host.to_owned(), 80) };
        let entry = |host: &str, conn: u32| (host.to_owned(), conn);
        let pooled = |pool: &ConnectionPool<u32>| {
            let mut pooled: Vec<(String, u32)> = pool
                .idle
                .lock()
                .iter()
                .flat_map(|((_, host, _), conns)| conns.iter().map(|(_, c)| (host.clone(), *c)))
                .collect();
            pooled.sort();
            pooled
        };
        pool.put(origin("a"), 1, Time::from_secs(0));
        pool.put(origin("b"), 2, Time::from_secs(10));
        // 30 s idle is the limit itself: "a" is still kept.
        pool.put(origin("c"), 3, Time::from_secs(30));
        assert_eq!(
            pooled(&pool),
            vec![entry("a", 1), entry("b", 2), entry("c", 3)]
        );
        // 31 s idle: "a" is closed and its origin dropped, though no request
        // went to "a" again.
        pool.put(origin("c"), 4, Time::from_secs(31));
        assert_eq!(
            pooled(&pool),
            vec![entry("b", 2), entry("c", 3), entry("c", 4)]
        );
        assert!(!pool.idle.lock().contains_key(&origin("a")));
        pool.put(origin("d"), 5, Time::from_secs(62));
        assert_eq!(pooled(&pool), vec![entry("d", 5)]);
        // take still answers with the newest live connection of its origin.
        pool.put(origin("d"), 6, Time::from_secs(63));
        assert_eq!(pool.take(&origin("d"), Time::from_secs(63)), Some(6));
    }

    struct ScriptedTransport {
        incoming: crate::bytes::BytesMut,
    }

    impl ScriptedTransport {
        fn new(incoming: crate::bytes::BytesMut) -> Self {
            Self { incoming }
        }
    }

    impl AsyncRead for ScriptedTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.incoming.is_empty() {
                return Poll::Pending;
            }
            let n = buf.remaining().min(this.incoming.len());
            let chunk = this.incoming.split_to(n);
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn drive_exchange(
        builder: Http2RequestBuilder,
        incoming: crate::bytes::BytesMut,
    ) -> Result<Http2Response, Http2ClientError> {
        let caller = Cx::for_testing();
        let waker = Waker::from(Arc::new(CountWake::default()));
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(builder.send_on(&caller, ScriptedTransport::new(incoming)));
        for _ in 0..100 {
            if let Poll::Ready(result) = future.as_mut().poll(&mut task) {
                return result;
            }
        }
        panic!("scripted exchange did not complete in bounded poll steps");
    }

    /// The bytes a scripted server sends: `frames`, encoded in order.
    fn server_frames(frames: impl IntoIterator<Item = Frame>) -> crate::bytes::BytesMut {
        let mut incoming = crate::bytes::BytesMut::new();
        for frame in frames {
            frame
                .encode(&mut incoming)
                .expect("encode a scripted frame");
        }
        incoming
    }

    /// A complete bodyless `:status 200` response on `stream_id` (HPACK
    /// static index 8 is (:status, 200), encoded as 0x88).
    fn ok_response(stream_id: u32) -> Frame {
        Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
            stream_id,
            Bytes::from_static(&[0x88]),
            true,
            true,
        ))
    }

    /// `count` PINGs, as a server sending keepalives would.
    fn pings(count: usize) -> Vec<Frame> {
        vec![Frame::Ping(crate::http::h2::frame::PingFrame::new([7; 8])); count]
    }

    /// Queue `frames` on a scripted connection's transport, after whatever it
    /// has not read yet.
    fn feed(conn: &mut Http2Conn<ScriptedTransport>, frames: impl IntoIterator<Item = Frame>) {
        let bytes = server_frames(frames);
        conn.wire.get_mut().inner.incoming.extend_from_slice(&bytes);
    }

    /// Poll `future` to completion in bounded steps. A scripted transport
    /// answers Pending only once its queued bytes are used up, so a step that
    /// still needs more of them never completes.
    fn complete<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(CountWake::default()));
        let mut task = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        for _ in 0..100 {
            if let Poll::Ready(output) = future.as_mut().poll(&mut task) {
                return output;
            }
        }
        panic!("scripted connection step did not complete in bounded poll steps");
    }

    #[test]
    fn max_overhead_frames_enforces_empty_data_flood() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{DataFrame, HeadersFrame, SettingsFrame};

        let mut incoming = BytesMut::new();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        // Response headers must precede DATA frames
        Frame::Headers(HeadersFrame::new(
            1,
            Bytes::from_static(&[0x88]),
            false,
            true,
        ))
        .encode(&mut incoming)
        .unwrap();
        for _ in 0..3 {
            Frame::Data(DataFrame::new(1, Bytes::new(), false))
                .encode(&mut incoming)
                .unwrap();
        }

        let client = Http2Client::new();
        let res = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(2),
            incoming,
        );
        match res {
            Err(Http2ClientError::Protocol(err)) => {
                assert_eq!(err.code, ErrorCode::EnhanceYourCalm);
                assert!(err.message.contains("overhead limit exceeded"));
            }
            other => panic!("expected EnhanceYourCalm protocol error, got {other:?}"),
        }
    }

    #[test]
    fn max_overhead_frames_enforces_ping_flood() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{PingFrame, SettingsFrame};

        let mut incoming = BytesMut::new();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        for i in 0..4 {
            Frame::Ping(PingFrame::new([i as u8; 8]))
                .encode(&mut incoming)
                .unwrap();
        }

        let client = Http2Client::new();
        let res = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(3),
            incoming,
        );
        match res {
            Err(Http2ClientError::Protocol(err)) => {
                assert_eq!(err.code, ErrorCode::EnhanceYourCalm);
                assert!(err.message.contains("overhead limit exceeded"));
            }
            other => panic!("expected EnhanceYourCalm protocol error, got {other:?}"),
        }
    }

    /// Unsolicited SETTINGS (each forces a queued ACK) and PRIORITY share the
    /// budget. Until review r31-e8 of 3ba51cd7e (br-asupersync-r96ybl) this
    /// test flooded SETTINGS ACKs, which are the server's mandatory reply to
    /// the client's own SETTINGS and are no longer counted.
    #[test]
    fn max_overhead_frames_enforces_unsolicited_settings_and_priority_flood() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{PriorityFrame, PrioritySpec, SettingsFrame};

        let mut incoming = BytesMut::new();
        // The connection-preface SETTINGS is exempt.
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        Frame::Priority(PriorityFrame {
            stream_id: 1,
            priority: PrioritySpec {
                exclusive: false,
                dependency: 0,
                weight: 16,
            },
        })
        .encode(&mut incoming)
        .unwrap();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();

        let client = Http2Client::new();
        let res = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(2),
            incoming,
        );
        match res {
            Err(Http2ClientError::Protocol(err)) => {
                assert_eq!(err.code, ErrorCode::EnhanceYourCalm);
                assert!(err.message.contains("overhead limit exceeded"));
            }
            other => panic!("expected EnhanceYourCalm protocol error, got {other:?}"),
        }
    }

    #[test]
    fn overhead_frames_within_budget_succeed() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{DataFrame, HeadersFrame, PingFrame, SettingsFrame};

        let mut incoming = BytesMut::new();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        Frame::Ping(PingFrame::new([1; 8]))
            .encode(&mut incoming)
            .unwrap();
        // HPACK static index 8 is (:status, 200), encoded as 0x88.
        Frame::Headers(HeadersFrame::new(
            1,
            Bytes::from_static(&[0x88]),
            false,
            true,
        ))
        .encode(&mut incoming)
        .unwrap();
        Frame::Data(DataFrame::new(1, Bytes::new(), false))
            .encode(&mut incoming)
            .unwrap();
        Frame::Data(DataFrame::new(1, Bytes::from_static(b"ok"), true))
            .encode(&mut incoming)
            .unwrap();

        let client = Http2Client::new();
        let response = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(5),
            incoming,
        )
        .expect("request should succeed when overhead is within budget");

        assert_eq!(response.status, 200);
        assert_eq!(response.body.as_ref(), b"ok");
    }

    #[test]
    fn terminal_empty_data_is_not_counted_as_overhead() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{DataFrame, HeadersFrame, SettingsFrame};

        let mut incoming = BytesMut::new();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        // Response headers without end_stream
        Frame::Headers(HeadersFrame::new(
            1,
            Bytes::from_static(&[0x88]),
            false,
            true,
        ))
        .encode(&mut incoming)
        .unwrap();
        // Terminal empty DATA frame (end_stream: true)
        Frame::Data(DataFrame::new(1, Bytes::new(), true))
            .encode(&mut incoming)
            .unwrap();

        let client = Http2Client::new();
        // Even with max_overhead_frames = 0, a terminal empty DATA frame is not overhead.
        let response = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(0),
            incoming,
        )
        .expect("terminal empty DATA frame must not be charged as overhead");

        assert_eq!(response.status, 200);
    }

    #[test]
    fn non_terminal_empty_data_with_zero_budget_fails() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{DataFrame, SettingsFrame};

        let mut incoming = BytesMut::new();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        Frame::Data(DataFrame::new(1, Bytes::new(), false))
            .encode(&mut incoming)
            .unwrap();

        let client = Http2Client::new();
        let res = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(0),
            incoming,
        );
        match res {
            Err(Http2ClientError::Protocol(err)) => {
                assert_eq!(err.code, ErrorCode::EnhanceYourCalm);
                assert!(err.message.contains("overhead limit exceeded"));
            }
            other => panic!("expected EnhanceYourCalm protocol error, got {other:?}"),
        }
    }

    #[test]
    fn client_default_max_overhead_frames() {
        let client = Http2Client::new();
        assert_eq!(client.max_overhead_frames, DEFAULT_MAX_OVERHEAD_FRAMES);
        assert_eq!(DEFAULT_MAX_OVERHEAD_FRAMES, 10_000);

        let custom = client.max_overhead_frames(500);
        assert_eq!(custom.max_overhead_frames, 500);
    }

    /// Review r31-e8 of 3ba51cd7e (br-asupersync-r96ybl) MEDIUM-1: the
    /// overhead budget counted over the connection's whole life, so a pooled
    /// connection to a server that sends a few PINGs per request (keepalive)
    /// eventually failed a healthy request with ENHANCE_YOUR_CALM, which is
    /// not retried. This drives one connection the way the pool does (start
    /// and request; then refresh and request for each reuse) with `LIMIT - 1`
    /// PINGs in every use. On the old code the second request fails with
    /// ENHANCE_YOUR_CALM, since 2 * (LIMIT - 1) >= LIMIT. The last two uses
    /// show that frames received while idle count toward the next use, and
    /// that a use which takes the whole budget retires the connection.
    #[test]
    fn overhead_budget_is_per_use_not_per_connection_lifetime() {
        use crate::http::h2::frame::SettingsFrame;

        const LIMIT: usize = 3;
        let request = Http2Client::new()
            .get("http://localhost/")
            .prepare()
            .expect("valid request");
        let run = |conn: &mut Http2Conn<ScriptedTransport>| {
            complete(conn.request(request.clone(), Bytes::new(), DEFAULT_BODY_LIMIT))
                .map(|(response, _)| response.status)
                .map_err(|failure| failure.error)
        };
        let mut conn = complete(Http2Conn::start(
            ScriptedTransport::new(crate::bytes::BytesMut::new()),
            DEFAULT_BODY_LIMIT,
            LIMIT,
        ))
        .expect("client preface");

        // Use 1, a fresh connection: the preface SETTINGS (exempt), LIMIT - 1
        // PINGs, and the response.
        feed(&mut conn, [Frame::Settings(SettingsFrame::new(vec![]))]);
        feed(&mut conn, pings(LIMIT - 1));
        feed(&mut conn, [ok_response(1)]);
        assert_eq!(run(&mut conn).expect("first use within budget"), 200);
        assert!(conn.reusable());

        // Use 2, reused: nothing arrived while idle, LIMIT - 1 PINGs during
        // the request.
        complete(conn.refresh()).expect("nothing arrived while idle");
        feed(&mut conn, pings(LIMIT - 1));
        feed(&mut conn, [ok_response(3)]);
        assert_eq!(
            run(&mut conn).expect("a reused connection starts a fresh budget"),
            200
        );
        assert!(conn.reusable());

        // Use 3: one keepalive PING while idle and LIMIT - 2 during the
        // request, LIMIT - 1 in all.
        feed(&mut conn, pings(1));
        complete(conn.refresh()).expect("an idle PING within budget");
        feed(&mut conn, pings(LIMIT - 2));
        feed(&mut conn, [ok_response(5)]);
        assert_eq!(run(&mut conn).expect("third use within budget"), 200);
        assert!(conn.reusable());

        // Use 4: one PING while idle and LIMIT - 1 during the request take the
        // whole budget. The request still succeeds, but the connection is not
        // reused; had refresh not charged the idle PING to this use, it would
        // be.
        feed(&mut conn, pings(1));
        complete(conn.refresh()).expect("an idle PING within budget");
        feed(&mut conn, pings(LIMIT - 1));
        feed(&mut conn, [ok_response(7)]);
        assert_eq!(run(&mut conn).expect("the budget admits its limit"), 200);
        assert!(
            !conn.reusable(),
            "a connection that used its whole budget must be retired"
        );
    }

    /// Review r31-e8 of 3ba51cd7e (br-asupersync-r96ybl) MEDIUM-2: the budget
    /// counted the SETTINGS ACK, the server's mandatory reply to the client's
    /// own SETTINGS, but not an unsolicited SETTINGS, each of which forces
    /// the client to queue an ACK (CVE-2019-9515). On the old code the first
    /// exchange fails with ENHANCE_YOUR_CALM (a conforming server's ACK
    /// breached a limit of 0), and the flood below completes with 200
    /// instead of being stopped.
    #[test]
    fn settings_ack_is_not_overhead_but_unsolicited_settings_are() {
        use crate::http::h2::frame::SettingsFrame;

        let settings = || Frame::Settings(SettingsFrame::new(vec![]));
        let ack = || Frame::Settings(SettingsFrame::ack());
        let client = Http2Client::new();

        // A conforming server: its preface SETTINGS, the ACK of the client's
        // SETTINGS, and the response. Neither counts, so even 0 admits it.
        let response = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(0),
            server_frames([settings(), ack(), ok_response(1)]),
        )
        .expect("the preface SETTINGS and the SETTINGS ACK are not overhead");
        assert_eq!(response.status, 200);

        // After the preface, a limit of 2 admits two unsolicited SETTINGS...
        let response = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(2),
            server_frames([settings(), settings(), settings(), ack(), ok_response(1)]),
        )
        .expect("two unsolicited SETTINGS are within a limit of 2");
        assert_eq!(response.status, 200);

        // ...and the third fails the request before its response is read.
        match drive_exchange(
            client.get("http://localhost/").max_overhead_frames(2),
            server_frames([
                settings(),
                settings(),
                settings(),
                settings(),
                ok_response(1),
            ]),
        ) {
            Err(Http2ClientError::Protocol(error)) => {
                assert_eq!(error.code, ErrorCode::EnhanceYourCalm);
                assert!(error.message.contains("overhead limit exceeded"));
            }
            other => panic!("an unsolicited SETTINGS flood must be stopped, got {other:?}"),
        }
    }
}
