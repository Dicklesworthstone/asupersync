//! Bounded native HTTP/2 requests over an owned transport.
//!
//! Each request drives its connection in the calling task. No background task,
//! connection pool, redirect, or retry is implicit. Cleartext URLs use HTTP/2
//! prior knowledge; HTTPS requires a caller-supplied TLS connector and `h2`
//! ALPN. Both upload and download advance while the other direction is blocked
//! by flow control. The connection is closed when the response finishes, the
//! request fails, or the request future is dropped.
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

use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
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
use crate::types::CancelReason;

use super::connection::{CLIENT_PREFACE, ReceivedFrame};
use super::{Connection, ConnectionState, ErrorCode, FrameCodec, H2Error, Header, Settings};

const DEFAULT_BODY_LIMIT: usize = 16 * 1024 * 1024;
const HEADER_LIMIT: usize = 64 * 1024;
const DATA_CHUNK: usize = 16 * 1024;
const POLL_STEPS: usize = 32;

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
/// share a 64 KiB decoded limit. A request owns one connection; concurrent
/// calls have independent transports and cannot cancel one another.
#[derive(Clone)]
pub struct Http2Client {
    timeout: Duration,
    max_request_body: usize,
    max_response_body: usize,
    #[cfg(feature = "tls")]
    tls_connector: Option<crate::tls::TlsConnector>,
}

impl fmt::Debug for Http2Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http2Client")
            .field("timeout", &self.timeout)
            .field("max_request_body", &self.max_request_body)
            .field("max_response_body", &self.max_response_body)
            .finish_non_exhaustive()
    }
}

impl Default for Http2Client {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_request_body: DEFAULT_BODY_LIMIT,
            max_response_body: DEFAULT_BODY_LIMIT,
            #[cfg(feature = "tls")]
            tls_connector: None,
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

    /// Supply certificate trust and TLS configuration for HTTPS. The
    /// connector must offer `h2`; a different negotiated ALPN is rejected.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls_connector(mut self, connector: crate::tls::TlsConnector) -> Self {
        self.tls_connector = Some(connector);
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
    /// connection-specific fields, conflicting Host, and invalid bytes fail
    /// before opening a socket. Repeated ordinary fields are preserved.
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
            let host = request.url.host.trim_matches(['[', ']']);
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
            let tcp = if let Ok(ip) = host.parse::<IpAddr>() {
                TcpStream::connect(SocketAddr::new(ip, request.url.port)).await?
            } else {
                TcpStream::connect((host.to_owned(), request.url.port)).await?
            };
            #[cfg(feature = "tls")]
            if request.url.scheme == Scheme::Https {
                let connector = self.client.tls_connector.as_ref().ok_or_else(|| {
                    Http2ClientError::Tls("HTTPS requires a TLS connector".into())
                })?;
                let tls = connector
                    .connect(host, tcp)
                    .await
                    .map_err(|error| Http2ClientError::Tls(error.to_string()))?;
                if tls.alpn_protocol() != Some(b"h2".as_slice()) {
                    return Err(Http2ClientError::Tls(
                        "peer did not negotiate h2 ALPN".into(),
                    ));
                }
                return exchange(tls, request, self.body, self.client.max_response_body).await;
            }
            exchange(tcp, request, self.body, self.client.max_response_body).await
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
            exchange(transport, request, self.body, self.client.max_response_body),
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

async fn exchange<T>(
    mut transport: T,
    request: PreparedRequest,
    body: Bytes,
    limit: usize,
) -> Result<Http2Response, Http2ClientError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    transport.write_all(CLIENT_PREFACE).await?;
    let settings = Settings {
        max_header_list_size: HEADER_LIMIT as u32,
        ..Settings::client()
    };
    let mut connection = Connection::client(settings);
    connection.queue_initial_settings();
    let mut wire =
        Framed::new(transport, FrameCodec::new()).with_max_buffer_len(DATA_CHUNK + 8192 + 9);
    let mut headers = Some(request.headers);
    let mut stream_id = None;
    let mut sent = 0;
    let mut response = ResponseState::new(request.head, limit);
    poll_fn(|task| {
        for _ in 0..POLL_STEPS {
            let mut progress = false;
            // Always read, including while upload writes or flow control are
            // parked. An early final response can terminate a rejected upload.
            match Pin::new(&mut wire).poll_next(task) {
                Poll::Ready(Some(Ok(frame))) => {
                    progress = true;
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
                            return Poll::Ready(Err(Http2ClientError::Reset(error_code)));
                        }
                        Some(ReceivedFrame::GoAway {
                            last_stream_id,
                            error_code,
                            ..
                        }) => {
                            if error_code != ErrorCode::NoError
                                || stream_id.is_none_or(|id| id > last_stream_id)
                            {
                                return Poll::Ready(Err(Http2ClientError::GoAway {
                                    last_stream_id,
                                    error_code,
                                }));
                            }
                        }
                        Some(_) => {
                            return Poll::Ready(Err(protocol("unexpected HTTP/2 response stream")));
                        }
                        None => {}
                    }
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error.into())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(protocol("peer closed before response completed")));
                }
                Poll::Pending => {}
            }
            if stream_id.is_none() && connection.state() == ConnectionState::Open {
                let request_headers = headers
                    .take()
                    .ok_or_else(|| protocol("request headers already consumed"))?;
                stream_id = Some(connection.open_stream(request_headers, body.is_empty())?);
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
    Ok(response.response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake};

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
}
