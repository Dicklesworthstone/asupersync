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
use crate::time::{Sleep, TimerDriverHandle};
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
/// the connection (on an idle pooled connection, it only drops the
/// connection). See `is_overhead_frame`.
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
    /// a connection error `ENHANCE_YOUR_CALM` and drops the connection; if it
    /// arrived while a pooled connection sat idle, only that connection is
    /// dropped and the request goes to another one. The acknowledgement of
    /// the client's own SETTINGS is not counted (a repeated one is), nor is
    /// WINDOW_UPDATE, which an upload legitimately receives many of.
    ///
    /// The budget covers one use of the connection, not its lifetime: a
    /// request, plus, on a reused pooled connection
    /// ([`Self::reuse_connections`]), what the server sent while the
    /// connection sat idle before it. A pooled connection that used its whole
    /// budget is not reused. `0` admits no overhead frame at all; a connection
    /// that received none is still reused. Defaults to 10,000.
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

    fn validate_native_target(&self, cx: &Cx, url: &ParsedUrl) -> Result<(), Http2ClientError> {
        require_native_io(cx)?;
        if url.scheme == Scheme::Https {
            #[cfg(feature = "tls")]
            if self.tls_connector.is_none() {
                return Err(Http2ClientError::Tls("HTTPS requires a TLS connector".into()));
            }
            #[cfg(not(feature = "tls"))]
            return Err(Http2ClientError::Tls("TLS support is disabled".into()));
        }
        Ok(())
    }

    async fn connect_transport(&self, url: &ParsedUrl) -> Result<Http2ClientIo, Http2ClientError> {
        let host = url.host.trim_matches(['[', ']']);
        let tcp = if let Ok(ip) = host.parse::<IpAddr>() {
            TcpStream::connect(SocketAddr::new(ip, url.port)).await?
        } else {
            crate::net::happy_eyeballs::connect_resolved((host.to_owned(), url.port), None).await?
        };
        #[cfg(feature = "tls")]
        if url.scheme == Scheme::Https {
            let connector = self.tls_connector.as_ref().ok_or_else(|| {
                Http2ClientError::Tls("HTTPS requires a TLS connector".into())
            })?;
            let tls = connector
                .connect(host, tcp)
                .await
                .map_err(|error| Http2ClientError::Tls(error.to_string()))?;
            if tls.alpn_protocol() != Some(b"h2".as_slice()) {
                return Err(Http2ClientError::Tls("peer did not negotiate h2 ALPN".into()));
            }
            return Ok(Http2ClientIo::Tls(tls));
        }
        Ok(Http2ClientIo::Plain(tcp))
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
            self.client.validate_native_target(cx, &request.url)?;
            let host = request.url.host.trim_matches(['[', ']']).to_owned();
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
            let transport = self.client.connect_transport(&request.url).await?;
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
        self.prepare_for_length(Some(self.body.len() as u64))
    }

    fn prepare_for_length(
        &self,
        exact_length: Option<u64>,
    ) -> Result<PreparedRequest, Http2ClientError> {
        if exact_length.is_some_and(|length| length > self.client.max_request_body as u64) {
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
        if content_length.zip(exact_length).is_some_and(|(declared, exact)| declared != exact) {
            return Err(invalid("content-length does not match request body"));
        }
        if content_length.is_some_and(|length| length > self.client.max_request_body as u64) {
            return Err(Http2ClientError::BodyTooLarge {
                request: true,
                limit: self.client.max_request_body,
            });
        }
        if content_length.is_none()
            && let Some(length) = exact_length
            && (length != 0 || self.method == Method::Post || self.method == Method::Put)
        {
            headers.push(Header::new("content-length", length.to_string()));
        }
        if header_size(&headers) > HEADER_LIMIT {
            return Err(invalid("request headers exceed 64 KiB"));
        }
        Ok(PreparedRequest {
            url,
            headers,
            head: self.method.as_str() == "HEAD",
            #[cfg(feature = "http2-streaming")]
            content_length: content_length.or(exact_length),
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
    RequestControl::new(cx, timeout).drive(future).await
}

/// One absolute deadline and its cancellation registrations, retained when a
/// streaming response takes over driving the connection from its send future.
struct RequestControl {
    caller: Cancellation,
    ambient: Option<Cancellation>,
    driver: Option<TimerDriverHandle>,
    deadline: Time,
    sleep: Sleep,
}

impl RequestControl {
    fn new(cx: &Cx, timeout: Duration) -> Self {
        let caller = Cancellation::new(cx.clone());
        let ambient = Cx::current().map(Cancellation::new);
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
                let context_now = context
                    .timer_driver()
                    .map_or_else(crate::time::wall_now, |driver| driver.now());
                let remaining = budget.as_nanos().saturating_sub(context_now.as_nanos());
                deadline = deadline.min(now.saturating_add_nanos(remaining));
            }
        }
        let sleep = driver.as_ref().map_or_else(
            || Sleep::new(deadline),
            |driver| Sleep::with_timer_driver(deadline, driver.clone()),
        );
        Self {
            caller,
            ambient,
            driver,
            deadline,
            sleep,
        }
    }

    fn check(&mut self, task: &mut std::task::Context<'_>) -> Result<(), Http2ClientError> {
        // Registration precedes checkpoint: cancellation can occur during a
        // custom Waker's clone callback, before its registry entry is visible.
        self.caller.register(task.waker());
        if let Some(ambient) = &mut self.ambient {
            ambient.register(task.waker());
        }
        let now = self
            .driver
            .as_ref()
            .map_or_else(crate::time::wall_now, |driver| driver.now());
        if now >= self.deadline {
            return Err(Http2ClientError::DeadlineExceeded);
        }
        self.caller.check()?;
        if let Some(ambient) = &self.ambient {
            ambient.check()?;
        }
        let timer_ready = {
            // A response can move to another task. A wall-clock deadline must
            // not acquire that task's unrelated virtual or native timer.
            let _ambient = self
                .driver
                .is_none()
                .then(|| self.caller.cx.clone().set_current_restricted());
            Pin::new(&mut self.sleep).poll_deadline(task).is_ready()
        };
        if timer_ready {
            // An early timer wake must never cause polling a completed Sleep.
            self.sleep.reset(self.deadline);
            task.waker().wake_by_ref();
        }
        Ok(())
    }

    async fn drive<T>(
        &mut self,
        future: impl Future<Output = Result<T, Http2ClientError>>,
    ) -> Result<T, Http2ClientError> {
        let mut future = std::pin::pin!(future);
        poll_fn(|task| {
            self.check(task)?;
            future.as_mut().poll(task)
        })
        .await
    }
}

#[derive(Clone)]
struct PreparedRequest {
    url: ParsedUrl,
    headers: Vec<Header>,
    head: bool,
    #[cfg(feature = "http2-streaming")]
    content_length: Option<u64>,
}

struct ResponseState {
    response: Http2Response,
    header_bytes: usize,
    content_length: Option<u64>,
    body: Vec<u8>,
    received: usize,
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
            received: 0,
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
        self.record_data(data.len())?;
        self.body.extend_from_slice(data);
        if end { self.finish() } else { Ok(false) }
    }

    fn record_data(&mut self, length: usize) -> Result<(), Http2ClientError> {
        if self.response.status == 0 {
            return Err(protocol("DATA precedes final response headers"));
        }
        if self.bodyless() && length != 0 {
            return Err(protocol("DATA on a bodyless response"));
        }
        if length > self.limit.saturating_sub(self.received) {
            return Err(Http2ClientError::BodyTooLarge {
                request: false,
                limit: self.limit,
            });
        }
        self.received += length;
        if !self.bodyless()
            && self
                .content_length
                .is_some_and(|length| self.received as u64 > length)
        {
            return Err(protocol("response exceeds content-length"));
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<bool, Http2ClientError> {
        if !self.bodyless()
            && self
                .content_length
                .is_some_and(|length| length != self.received as u64)
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
/// first non-ACK SETTINGS, so exactly that one is exempt. The first SETTINGS
/// ACK is the server's mandatory reply to the client's only SETTINGS and does
/// not count; `settings_acked` records it, and any later ACK counts.
/// WINDOW_UPDATE does not count: a client uploading a large body
/// legitimately receives thousands. RST_STREAM floods (CVE-2019-9514) are
/// bounded by the connection's peer-reset rate limit, not by this budget.
fn is_overhead_frame(frame: &Frame, connection: &Connection, settings_acked: &mut bool) -> bool {
    match frame {
        Frame::Ping(_) => true,
        Frame::Settings(s) if s.ack => std::mem::replace(settings_acked, true),
        Frame::Settings(_) => connection.state() != ConnectionState::Handshaking,
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
    /// Whether the server acknowledged the client's SETTINGS. The client sends
    /// SETTINGS once, so only the first ACK is free (`is_overhead_frame`).
    settings_acked: bool,
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
            settings_acked: false,
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
            && (self.overhead_frames == 0 || self.overhead_frames < self.max_overhead_frames)
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
            for _ in 0..POLL_STEPS {
                match Pin::new(&mut self.wire).poll_next(task) {
                    Poll::Ready(Some(Ok(frame))) => {
                        if is_overhead_frame(&frame, &self.connection, &mut self.settings_acked) {
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
                    Poll::Pending => {
                        return if self.reusable() {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(protocol("pooled HTTP/2 connection is draining")))
                        };
                    }
                }
            }
            // WINDOW_UPDATE is legitimate upload progress and does not spend
            // the overhead-frame budget. A readable idle peer must still
            // yield so the owning request can observe cancellation/deadline.
            task.waker().wake_by_ref();
            Poll::Pending
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
            settings_acked,
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
                        if is_overhead_frame(&frame, connection, settings_acked) {
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

/// Owned native transport used by the HTTP/2 client.
///
/// Streaming responses retain this transport until their body is consumed or
/// dropped. HTTPS is authenticated and checked for `h2` ALPN before it is
/// exposed through a response.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http2ClientIo {
    /// Cleartext HTTP/2 with prior knowledge over TCP.
    Plain(TcpStream),
    /// HTTP/2 over a verified TLS connection.
    #[cfg(feature = "tls")]
    Tls(crate::tls::TlsStream<TcpStream>),
}

impl AsyncRead for Http2ClientIo {
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

impl AsyncWrite for Http2ClientIo {
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
struct ConnectionPool<C = Http2Conn<Http2ClientIo>> {
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

#[cfg(feature = "http2-streaming")]
pub use streaming::{Http2IncomingBody, Http2StreamingResponse};

#[cfg(feature = "http2-streaming")]
mod streaming {
    use super::*;
    use crate::bytes::{Buf, BytesCursor};
    use crate::http::body::{
        Body, Frame as BodyFrame, Full, HeaderMap, HeaderName, HeaderValue, SizeHint,
    };
    use std::task::Context;

    /// Final HTTP/2 response headers and an owned, incremental response body.
    ///
    /// Polling `body` drives both directions of the exchange. An upload can
    /// continue after the peer sends its final response headers; response
    /// END_STREAM stops an unfinished upload. No detached driver is spawned.
    #[must_use = "the response body drives the exchange and must be consumed or dropped"]
    #[non_exhaustive]
    pub struct Http2StreamingResponse<T, B: Body> {
        /// Final response status, after any informational responses.
        pub status: u16,
        /// Final response fields, excluding `:status`.
        pub headers: Vec<Header>,
        /// DATA and trailers, retaining the original deadline and cancellation.
        pub body: Http2IncomingBody<T, B>,
    }

    impl<T, B: Body> fmt::Debug for Http2StreamingResponse<T, B> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Http2StreamingResponse")
                .field("status", &self.status)
                .field("headers", &self.headers)
                .field("body", &self.body)
                .finish()
        }
    }

    impl<T, B: Body> Http2StreamingResponse<T, B> {
        /// Return the first final response field with this case-insensitive name.
        #[must_use]
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case(name))
                .map(|header| header.value.as_str())
        }
    }

    /// An HTTP/2 response body that owns its connection and request producer.
    ///
    /// One upload frame is retained at a time and split by the peer's stream
    /// and connection credit. Response DATA is delivered one frame at a time;
    /// its stream credit is returned only when the caller polls for the next
    /// frame. Trailers are a separate [`BodyFrame::Trailers`] frame. The total
    /// response byte limit still applies, without collecting those bytes.
    ///
    /// Draining to EOF can return a healthy native connection to the client's
    /// opt-in pool, after the upload reaches EOF and all queued writes flush.
    /// Dropping an unfinished body closes its connection before dropping the
    /// producer. Cancellation and the original total deadline also close it;
    /// no background task continues reading or draining.
    #[must_use = "a streaming body makes progress only while polled"]
    pub struct Http2IncomingBody<T, B: Body> {
        // Field drop order is deliberate: user producer/data destructors may
        // panic or re-enter the client, after the socket has been retired.
        conn: Option<Http2Conn<T>>,
        control: Option<RequestControl>,
        upload: Option<Upload<B>>,
        owner: Cx,
        pool: Option<(Arc<ConnectionPool<Http2Conn<T>>>, Origin)>,
        response: ResponseState,
        request_headers: Option<Vec<Header>>,
        stream_id: Option<u32>,
        credit_due: u32,
        response_done: bool,
        done: bool,
        poisoned: bool,
        native: bool,
        poller: Option<Cancellation>,
    }

    impl<T, B: Body> fmt::Debug for Http2IncomingBody<T, B> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Http2IncomingBody")
                .field("stream_id", &self.stream_id)
                .field("received", &self.response.received)
                .field("response_done", &self.response_done)
                .field("done", &self.done)
                .finish_non_exhaustive()
        }
    }

    impl<T, B: Body> Drop for Http2IncomingBody<T, B> {
        fn drop(&mut self) {
            let _ambient = self.owner.clone().set_current_restricted();
            drop(self.conn.take());
            drop(self.upload.take());
            drop(self.control.take());
            drop(self.poller.take());
        }
    }

    struct UploadData<D> {
        // The buffer is owned and is never structurally pinned. Boxing keeps
        // the response body Unpin without requiring D: Unpin.
        data: Box<D>,
        remaining: usize,
    }

    /// Retain the explicit authority even if a send future is dropped before
    /// its first poll. Producer destruction must not inherit the dropping task.
    struct SourceOwner<B> {
        owner: Cx,
        source: Option<Pin<Box<B>>>,
    }

    impl<B: Body> SourceOwner<B> {
        fn new(owner: &Cx, source: B) -> Self {
            Self {
                owner: owner.clone(),
                source: Some(Box::pin(source)),
            }
        }

        fn size_hint(&self) -> SizeHint {
            let _ambient = self.owner.clone().set_current_restricted();
            self.source.as_ref().expect("live producer").size_hint()
        }

        fn poll_frame(
            &mut self,
            task: &mut Context<'_>,
        ) -> Poll<Option<Result<BodyFrame<B::Data>, B::Error>>> {
            let _ambient = self.owner.clone().set_current_restricted();
            self.source
                .as_mut()
                .expect("live producer")
                .as_mut()
                .poll_frame(task)
        }
    }

    impl<B> Drop for SourceOwner<B> {
        fn drop(&mut self) {
            let _ambient = self.owner.clone().set_current_restricted();
            drop(self.source.take());
        }
    }

    /// Preflight and unpolled-drop ordering for caller-supplied transports.
    struct SuppliedUpload<T, B> {
        transport: Option<T>,
        source: Option<SourceOwner<B>>,
    }

    impl<T, B> Drop for SuppliedUpload<T, B> {
        fn drop(&mut self) {
            let _ambient = self
                .source
                .as_ref()
                .map(|source| source.owner.clone().set_current_restricted());
            drop(self.transport.take());
            drop(self.source.take());
        }
    }

    struct Upload<B: Body> {
        source: SourceOwner<B>,
        data: Option<UploadData<B::Data>>,
        produced: u64,
        expected: Option<u64>,
        limit: usize,
        header_bytes: usize,
        trailers: Option<Vec<Header>>,
        saw_trailers: bool,
        eof: bool,
    }

    impl<B: Body> Drop for Upload<B> {
        fn drop(&mut self) {
            let _ambient = self.source.owner.clone().set_current_restricted();
            drop(self.data.take());
            // SourceOwner independently scopes its own field destruction,
            // including unwinding if the retained data's destructor panics.
        }
    }

    impl Http2RequestBuilder {
        /// Send the builder's buffered upload and stream the response.
        ///
        /// Unlike [`Self::send`], this returns after the final response headers.
        /// The response body owns the connection, deadline, and cancellation
        /// registrations. This is a one-shot exchange with no implicit replay.
        pub fn send_streaming(
            mut self,
            cx: &Cx,
        ) -> impl Future<
            Output = Result<
                Http2StreamingResponse<Http2ClientIo, Full<BytesCursor>>,
                Http2ClientError,
            >,
        > + use<> {
            let body = Full::new(BytesCursor::new(std::mem::take(&mut self.body)));
            self.send_with_body(cx, body)
        }

        /// Stream both directions using a caller-supplied transport.
        ///
        /// Transport ownership and TLS responsibility are the same as for
        /// [`Self::send_on`]. Borrowed transports are accepted; no `Send`,
        /// `'static`, or background executor requirement is introduced.
        pub fn send_streaming_on<T>(
            mut self,
            cx: &Cx,
            transport: T,
        ) -> impl Future<
            Output = Result<Http2StreamingResponse<T, Full<BytesCursor>>, Http2ClientError>,
        > + use<T>
        where
            T: AsyncRead + AsyncWrite + Unpin,
        {
            let body = Full::new(BytesCursor::new(std::mem::take(&mut self.body)));
            self.send_with_body_on(cx, transport, body)
        }

        /// Stream an arbitrary [`Body`] upload and return a streaming response.
        ///
        /// [`crate::http::ReaderBody`] and [`crate::http::MultipartBody`] can
        /// feed this method without collecting their payloads. An exact size
        /// hint supplies Content-Length; an explicit length is checked against
        /// the actual producer EOF. Unknown-length bodies use DATA and
        /// END_STREAM, without HTTP/1 transfer encoding. A single final trailer
        /// frame is supported. Producer errors become [`Http2ClientError::Io`].
        ///
        /// A builder with a nonempty buffered body is rejected. The producer
        /// needs neither `Unpin` nor `Send`. It is consumed once: unlike the
        /// buffered API, no failed request is retried, even on a reused socket.
        pub fn send_with_body<B>(
            self,
            cx: &Cx,
            source: B,
        ) -> impl Future<Output = Result<Http2StreamingResponse<Http2ClientIo, B>, Http2ClientError>>
        + use<B>
        where
            B: Body,
            B::Error: fmt::Display,
        {
            let source = SourceOwner::new(cx, source);
            let cx = cx.clone();
            async move {
                if !self.body.is_empty() {
                    return Err(invalid("streaming request also has a buffered body"));
                }
                // Check the original poller's authority before invoking producer
                // code under the explicit request owner's restricted context.
                require_native_io(&cx)?;
                let request = self.prepare_for_length(source.size_hint().exact())?;
                let timeout = self
                    .timeout
                    .unwrap_or(self.client.timeout)
                    .min(self.client.timeout);
                let mut control = RequestControl::new(&cx, timeout);
                let origin = (
                    request.url.scheme == Scheme::Https,
                    request.url.host.trim_matches(['[', ']']).to_owned(),
                    request.url.port,
                );
                let conn = control
                    .drive(async {
                        self.client.validate_native_target(&cx, &request.url)?;
                        if let Some(pool) = &self.client.pool {
                            while let Some(mut conn) = pool.take(&origin, pool_now(&cx)) {
                                conn.max_overhead_frames = self.client.max_overhead_frames;
                                if conn.refresh().await.is_ok() {
                                    return Ok(conn);
                                }
                            }
                        }
                        let transport = self.client.connect_transport(&request.url).await?;
                        // Streaming does not need the buffered client's large
                        // initial receive window.
                        Http2Conn::start(
                            transport,
                            MIN_RECEIVE_WINDOW as usize,
                            self.client.max_overhead_frames,
                        )
                        .await
                    })
                    .await?;
                let pool = self.client.pool.map(|pool| (pool, origin));
                Http2IncomingBody::new(
                    conn,
                    control,
                    request,
                    source,
                    self.client.max_request_body,
                    self.client.max_response_body,
                    pool,
                    true,
                )
                .response().await
            }
        }

        /// Stream a [`Body`] on an owned transport, starting with the H2 preface.
        ///
        /// This has the framing, deadline and one-shot rules of
        /// [`Self::send_with_body`] and never pools the supplied transport.
        /// A TLS transport's certificate and `h2` ALPN checks remain the
        /// caller's responsibility, as for [`Self::send_on`].
        pub fn send_with_body_on<T, B>(
            self,
            cx: &Cx,
            transport: T,
            source: B,
        ) -> impl Future<Output = Result<Http2StreamingResponse<T, B>, Http2ClientError>>
        + use<T, B>
        where
            T: AsyncRead + AsyncWrite + Unpin,
            B: Body,
            B::Error: fmt::Display,
        {
            let mut supplied = SuppliedUpload {
                transport: Some(transport),
                source: Some(SourceOwner::new(cx, source)),
            };
            let cx = cx.clone();
            async move {
                if !self.body.is_empty() {
                    return Err(invalid("streaming request also has a buffered body"));
                }
                let request = self.prepare_for_length(
                    supplied.source.as_ref().expect("owned source").size_hint().exact(),
                )?;
                let timeout = self
                    .timeout
                    .unwrap_or(self.client.timeout)
                    .min(self.client.timeout);
                let mut control = RequestControl::new(&cx, timeout);
                let conn = control
                    .drive(cx.with_ambient(Http2Conn::start(
                        supplied.transport.take().expect("owned transport"),
                        MIN_RECEIVE_WINDOW as usize,
                        self.client.max_overhead_frames,
                    )))
                    .await?;
                Http2IncomingBody::new(
                    conn,
                    control,
                    request,
                    supplied.source.take().expect("owned source"),
                    self.client.max_request_body,
                    self.client.max_response_body,
                    None,
                    false,
                )
                .response()
                .await
            }
        }
    }

    impl<T, B> Http2IncomingBody<T, B>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        B: Body,
        B::Error: fmt::Display,
    {
        #[allow(clippy::too_many_arguments)]
        fn new(
            conn: Http2Conn<T>,
            control: RequestControl,
            request: PreparedRequest,
            source: SourceOwner<B>,
            request_limit: usize,
            response_limit: usize,
            pool: Option<(Arc<ConnectionPool<Http2Conn<T>>>, Origin)>,
            native: bool,
        ) -> Self {
            let owner = source.owner.clone();
            let upload = Upload {
                source,
                data: None,
                produced: 0,
                expected: request.content_length,
                limit: request_limit,
                header_bytes: header_size(&request.headers),
                trailers: None,
                saw_trailers: false,
                eof: false,
            };
            Self {
                conn: Some(conn), control: Some(control), upload: Some(upload), owner, pool,
                response: ResponseState::new(request.head, response_limit),
                request_headers: Some(request.headers), stream_id: None,
                credit_due: 0, response_done: false, done: false, poisoned: false,
                native, poller: None,
            }
        }

        async fn response(mut self) -> Result<Http2StreamingResponse<T, B>, Http2ClientError> {
            poll_fn(|task| self.poll_exchange(task, true)).await?;
            Ok(Http2StreamingResponse {
                status: self.response.response.status,
                headers: std::mem::take(&mut self.response.response.headers),
                body: self,
            })
        }

        fn check_owner(&mut self, task: &mut Context<'_>) -> Result<(), Http2ClientError> {
            let control = self.control.as_mut().ok_or_else(|| protocol("retired streaming owner"))?;
            if self.native {
                require_native_io(&control.caller.cx)?;
            }
            let current = Cx::current().filter(|current| {
                !Arc::ptr_eq(&current.inner, &control.caller.cx.inner)
                    && !control.ambient.as_ref().is_some_and(|ambient| {
                        Arc::ptr_eq(&current.inner, &ambient.cx.inner)
                    })
            });
            if let Some(current) = current {
                if self.poller.as_ref().is_none_or(|poller| !Arc::ptr_eq(&poller.cx.inner, &current.inner)) {
                    self.poller = Some(Cancellation::new(current));
                }
            } else {
                self.poller = None;
            }
            if let Some(poller) = &mut self.poller {
                poller.register(task.waker());
                poller.check()?;
                if let Some(deadline) = poller.cx.budget().deadline {
                    // Budget deadlines belong to their context's clock. A
                    // body transferred across runtimes can only shorten its
                    // original allowance by the new poller's remaining time.
                    let poller_now = poller.cx.timer_driver()
                        .map_or_else(crate::time::wall_now, |driver| driver.now());
                    let now = control.driver.as_ref()
                        .map_or_else(crate::time::wall_now, |driver| driver.now());
                    let remaining = deadline.as_nanos().saturating_sub(poller_now.as_nanos());
                    let deadline = now.saturating_add_nanos(remaining);
                    if deadline < control.deadline {
                        control.deadline = deadline;
                        control.sleep.reset(deadline);
                    }
                }
            }
            control.check(task)
        }

        fn retire(&mut self, reuse: bool) {
            let _ambient = self.owner.clone().set_current_restricted();
            self.done = true;
            self.credit_due = 0;
            let conn = self.conn.take();
            let pool = self.pool.take();
            let upload = self.upload.take();
            let control = self.control.take();
            let poller = self.poller.take();
            let now = control.as_ref().map(|control| pool_now(&control.caller.cx));
            match (conn, pool) {
                (Some(conn), Some((pool, origin))) if reuse && conn.reusable() => {
                    // A producer destructor that panics cannot publish a
                    // reusable connection: the local connection drops while
                    // unwinding, after all ownership has left the body.
                    drop(upload);
                    drop(poller);
                    drop(control);
                    pool.put(origin, conn, now.unwrap_or(Time::ZERO));
                }
                (conn, _) => {
                    drop(conn);
                    drop(upload);
                    drop(poller);
                    drop(control);
                }
            }
        }

        fn poll_exchange(
            &mut self,
            task: &mut Context<'_>,
            head_only: bool,
        ) -> Poll<Result<Option<BodyFrame<BytesCursor>>, Http2ClientError>> {
            if self.done {
                return Poll::Ready(Ok(None));
            }
            if std::mem::replace(&mut self.poisoned, true) {
                self.retire(false);
                return Poll::Ready(Err(Http2ClientError::Io(io::Error::new(
                    io::ErrorKind::InvalidData, "streaming HTTP/2 owner resumed after a panic",
                ))));
            }
            let result = match self.check_owner(task) {
                Ok(()) => {
                    let _ambient = self.owner.clone().set_current_restricted();
                    self.poll_inner(task, head_only)
                }
                Err(error) => Poll::Ready(Err(error)),
            };
            if matches!(&result, Poll::Ready(Err(_))) {
                self.retire(false);
            }
            self.poisoned = false;
            result
        }

        fn poll_inner(
            &mut self,
            task: &mut Context<'_>,
            head_only: bool,
        ) -> Poll<Result<Option<BodyFrame<BytesCursor>>, Http2ClientError>> {
            if self.credit_due != 0 {
                if let (Some(conn), Some(id)) = (&mut self.conn, self.stream_id) {
                    conn.connection.release_stream_receive_capacity(id, self.credit_due)?;
                }
                self.credit_due = 0;
            }
            for _ in 0..POLL_STEPS {
                let mut progress = false;
                let mut delivery = None;
                if !self.response_done {
                    let conn = self.conn.as_mut().ok_or_else(|| protocol("missing streaming connection"))?;
                    match Pin::new(&mut conn.wire).poll_next(task) {
                        Poll::Ready(Some(Ok(frame))) => {
                            progress = true;
                            if is_overhead_frame(&frame, &conn.connection, &mut conn.settings_acked) {
                                if conn.overhead_frames >= conn.max_overhead_frames {
                                    return Poll::Ready(Err(H2Error::connection(
                                        ErrorCode::EnhanceYourCalm,
                                        "HTTP/2 connection frame overhead limit exceeded",
                                    ).into()));
                                }
                                conn.overhead_frames = conn.overhead_frames.saturating_add(1);
                            }
                            match conn.connection.process_frame(frame)? {
                                Some(ReceivedFrame::Headers { stream_id: id, headers, end_stream })
                                    if Some(id) == self.stream_id =>
                                {
                                    let had_final_headers = self.response.response.status != 0;
                                    self.response_done = self.response.headers(headers, end_stream)?;
                                    if !had_final_headers && self.response.response.status != 0 && !end_stream {
                                        // Informational HEADERS do not initialize the
                                        // stream's receive body. Defer only after final
                                        // headers, and before processing any DATA.
                                        conn.connection.defer_stream_receive_window(id)?;
                                    }
                                    if had_final_headers {
                                        let mut trailers = HeaderMap::new();
                                        for header in std::mem::take(&mut self.response.response.trailers) {
                                            trailers.append(HeaderName::from_string(&header.name),
                                                HeaderValue::from_string(header.value));
                                        }
                                        delivery = Some(BodyFrame::Trailers(trailers));
                                    }
                                }
                                Some(ReceivedFrame::Data { stream_id: id, data, end_stream })
                                    if Some(id) == self.stream_id =>
                                {
                                    self.response.record_data(data.len())?;
                                    if end_stream {
                                        self.response_done = self.response.finish()?;
                                    }
                                    if !data.is_empty() {
                                        self.credit_due = u32::try_from(data.len())
                                            .map_err(|_| protocol("response DATA length exceeds u32"))?;
                                        delivery = Some(BodyFrame::Data(BytesCursor::new(data)));
                                    }
                                }
                                Some(ReceivedFrame::Reset { stream_id: id, error_code })
                                    if Some(id) == self.stream_id =>
                                {
                                    return Poll::Ready(Err(Http2ClientError::Reset(error_code)));
                                }
                                Some(ReceivedFrame::GoAway { last_stream_id, error_code, .. }) => {
                                    if error_code != ErrorCode::NoError
                                        || self.stream_id.is_none_or(|id| id > last_stream_id)
                                    {
                                        return Poll::Ready(Err(Http2ClientError::GoAway { last_stream_id, error_code }));
                                    }
                                }
                                Some(ReceivedFrame::Headers { stream_id: id, .. }
                                    | ReceivedFrame::Data { stream_id: id, .. }
                                    | ReceivedFrame::Reset { stream_id: id, .. })
                                    if self.stream_id.is_some_and(|current| id < current) => {}
                                Some(_) => return Poll::Ready(Err(protocol("unexpected HTTP/2 response stream"))),
                                None => {}
                            }
                        }
                        Poll::Ready(Some(Err(error))) => {
                            let error = conn.wire.get_mut().read_error.take()
                                .map_or_else(|| error.into(), Http2ClientError::Io);
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(None) => {
                            return Poll::Ready(Err(Http2ClientError::Io(io::Error::new(
                                io::ErrorKind::UnexpectedEof, "peer closed before response completed",
                            ))));
                        }
                        Poll::Pending => {}
                    }
                }

                // A completed response is authoritative even if the upload
                // producer is parked. Never await its EOF after an early
                // rejection, and never pool that half-finished connection.
                if self.response_done && self.upload.as_ref().is_some_and(|upload| !upload.eof) {
                    self.retire(false);
                    return Poll::Ready(Ok(delivery));
                }
                if head_only && self.response.response.status != 0 {
                    return Poll::Ready(Ok(None));
                }

                {
                    let conn = self.conn.as_mut().ok_or_else(|| protocol("missing streaming connection"))?;
                    if self.stream_id.is_none()
                        && conn.connection.state() == ConnectionState::Open
                        && conn.connection.remote_settings().max_concurrent_streams != 0
                    {
                        let headers = self.request_headers.take()
                            .ok_or_else(|| protocol("request headers already consumed"))?;
                        // Even an exact zero hint must be checked at producer
                        // EOF; END_STREAM is not inferred from a hint.
                        self.stream_id = Some(conn.connection.open_stream(headers, false)?);
                        progress = true;
                    }
                }
                if !self.response_done {
                    // Consumption queues stream credit before each new read.
                    // Flush that credit before admitting another upload chunk:
                    // otherwise continuously ready response DATA can leave a
                    // WINDOW_UPDATE queued on every poll and starve uploads.
                    for _ in 0..POLL_STEPS {
                        let (wrote, flushed) = self.poll_outbound(task)?;
                        progress |= wrote;
                        if !flushed
                            || !self.conn.as_ref().expect("live connection")
                                .connection.has_pending_frames()
                        {
                            break;
                        }
                    }
                    match self.poll_upload(task) {
                        Poll::Ready(Ok(changed)) => progress |= changed,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {}
                    }
                }
                let (wrote, flushed) = self.poll_outbound(task)?;
                progress |= wrote;
                if self.response_done && flushed {
                    let conn = self.conn.as_ref().ok_or_else(|| protocol("missing streaming connection"))?;
                    if !conn.connection.has_pending_frames() && conn.wire.write_buffer().is_empty() {
                        if self.credit_due != 0 {
                            if let Some(id) = self.stream_id {
                                self.conn.as_mut().expect("connection checked above").connection
                                    .release_stream_receive_capacity(id, self.credit_due)?;
                            }
                            self.credit_due = 0;
                        }
                        self.retire(true);
                        return Poll::Ready(Ok(delivery));
                    }
                }
                if delivery.is_some() {
                    return Poll::Ready(Ok(delivery));
                }
                if !progress {
                    return Poll::Pending;
                }
            }
            task.waker().wake_by_ref();
            Poll::Pending
        }

        fn poll_upload(&mut self, task: &mut Context<'_>) -> Poll<Result<bool, Http2ClientError>> {
            let Some(id) = self.stream_id else { return Poll::Ready(Ok(false)); };
            let conn = self.conn.as_mut().ok_or_else(|| protocol("missing streaming connection"))?;
            let upload = self.upload.as_mut().ok_or_else(|| protocol("missing upload owner"))?;
            if upload.eof || conn.connection.has_pending_frames() || !conn.wire.write_buffer().is_empty() {
                return Poll::Ready(Ok(false));
            }
            if let Some(data) = &mut upload.data {
                let capacity = conn.connection.available_send_capacity(id).min(DATA_CHUNK);
                if capacity == 0 {
                    return Poll::Pending;
                }
                if data.data.remaining() != data.remaining || data.data.chunk().is_empty() {
                    return Poll::Ready(Err(invalid("request body buffer violated its remaining/chunk contract")));
                }
                let length = capacity.min(data.remaining).min(data.data.chunk().len());
                let bytes = data.data.copy_to_bytes(length);
                let remaining = data.remaining - length;
                if bytes.len() != length || data.data.remaining() != remaining {
                    return Poll::Ready(Err(invalid("request body buffer did not advance by the emitted length")));
                }
                data.remaining = remaining;
                conn.connection.send_data(id, bytes, false)?;
                if remaining == 0 {
                    upload.data = None;
                }
                return Poll::Ready(Ok(true));
            }
            match upload.source.poll_frame(task) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Some(Err(error))) => {
                    // Error formatting and destruction are user code too.
                    // Retire the transport before either can panic or re-enter.
                    self.retire(false);
                    Poll::Ready(Err(Http2ClientError::Io(io::Error::other(
                        format!("HTTP/2 request body failed: {error}"),
                    ))))
                }
                Poll::Ready(Some(Ok(BodyFrame::Data(data)))) => {
                    upload.data = Some(UploadData { data: Box::new(data), remaining: 0 });
                    if upload.saw_trailers {
                        return Poll::Ready(Err(invalid("request DATA follows trailers")));
                    }
                    let data = upload.data.as_mut().expect("stored above");
                    let length = data.data.remaining();
                    if length as u64 > (upload.limit as u64).saturating_sub(upload.produced) {
                        return Poll::Ready(Err(Http2ClientError::BodyTooLarge { request: true, limit: upload.limit }));
                    }
                    if upload.expected.is_some_and(|expected| length as u64 > expected.saturating_sub(upload.produced)) {
                        return Poll::Ready(Err(invalid("request body exceeds content-length")));
                    }
                    upload.produced += length as u64;
                    data.remaining = length;
                    if length == 0 { upload.data = None; }
                    Poll::Ready(Ok(true))
                }
                Poll::Ready(Some(Ok(BodyFrame::Trailers(trailers)))) => {
                    if upload.saw_trailers {
                        return Poll::Ready(Err(invalid("multiple request trailer frames")));
                    }
                    upload.trailers = Some(request_trailers(trailers, upload.header_bytes)?);
                    upload.saw_trailers = true;
                    Poll::Ready(Ok(true))
                }
                Poll::Ready(None) => {
                    if upload.expected.is_some_and(|expected| expected != upload.produced) {
                        return Poll::Ready(Err(invalid("request body ends before content-length")));
                    }
                    upload.eof = true;
                    if let Some(trailers) = upload.trailers.take() {
                        conn.connection.send_headers(id, trailers, true)?;
                    } else {
                        conn.connection.send_data(id, Bytes::new(), true)?;
                    }
                    Poll::Ready(Ok(true))
                }
            }
        }

        /// Progress at most one queued protocol frame, then flush. A frame
        /// removed from Connection is still owned by Framed until flush ends.
        fn poll_outbound(&mut self, task: &mut Context<'_>) -> Result<(bool, bool), Http2ClientError> {
            let conn = self.conn.as_mut().ok_or_else(|| protocol("missing streaming connection"))?;
            let mut progress = false;
            if conn.connection.has_pending_frames() {
                match conn.wire.poll_ready(task) {
                    Poll::Ready(Ok(())) => {
                        if let Some(frame) = conn.connection.next_frame() {
                            conn.wire.start_send(frame)?;
                            progress = true;
                        }
                    }
                    Poll::Ready(Err(error)) => return Err(error.into()),
                    Poll::Pending => {}
                }
            }
            let buffered = !conn.wire.write_buffer().is_empty();
            match conn.wire.poll_flush(task) {
                Poll::Ready(Ok(())) => Ok((progress || buffered, true)),
                Poll::Ready(Err(error)) => Err(error.into()),
                Poll::Pending => Ok((progress, false)),
            }
        }
    }

    fn request_trailers(trailers: HeaderMap, mut size: usize) -> Result<Vec<Header>, Http2ClientError> {
        let mut headers = Vec::new();
        for (name, value) in trailers.iter() {
            size = size.saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len()).saturating_add(32);
            if size > HEADER_LIMIT {
                return Err(invalid("request headers and trailers exceed 64 KiB"));
            }
            if name.as_str().starts_with(':')
                || crate::http::h1::codec::is_forbidden_trailer(name.as_str())
            {
                return Err(invalid("forbidden request trailer field"));
            }
            let value = value.to_str().map_err(|_| invalid("request trailer is not UTF-8"))?;
            validate_header_field(name.as_str(), value).map_err(|error| invalid(error.to_string()))?;
            if value.starts_with([' ', '\t']) || value.ends_with([' ', '\t']) {
                return Err(invalid("trailer value has leading or trailing whitespace"));
            }
            headers.push(Header::new(name.as_str(), value));
        }
        Ok(headers)
    }

    impl<T, B> Body for Http2IncomingBody<T, B>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        B: Body,
        B::Error: fmt::Display,
    {
        type Data = BytesCursor;
        type Error = Http2ClientError;

        fn poll_frame(
            self: Pin<&mut Self>,
            task: &mut Context<'_>,
        ) -> Poll<Option<Result<BodyFrame<Self::Data>, Self::Error>>> {
            match self.get_mut().poll_exchange(task, false) {
                Poll::Ready(Ok(frame)) => Poll::Ready(frame.map(Ok)),
                Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
                Poll::Pending => Poll::Pending,
            }
        }

        fn is_end_stream(&self) -> bool { self.done }

        fn size_hint(&self) -> SizeHint {
            if self.done || self.response.bodyless() {
                return SizeHint::with_exact(0);
            }
            if let Some(length) = self.response.content_length {
                return SizeHint::with_exact(length.saturating_sub(self.response.received as u64));
            }
            let mut hint = SizeHint::new();
            hint.set_upper(self.response.limit.saturating_sub(self.response.received) as u64);
            hint
        }
    }
}

#[cfg(test)]
#[path = "client_inline_tests.rs"]
mod tests;
