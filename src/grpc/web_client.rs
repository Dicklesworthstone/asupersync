//! Native, pull-driven gRPC-Web unary and server-streaming calls.
//!
//! This client owns HTTP/1 connections through the native HTTP client's pool.
//! Binary and independently padded text response streams are decoded as bytes
//! arrive. No background reader or browser runtime is required. HTTPS uses the
//! HTTP client's configured trust roots. Message and HTTP content compression
//! are deliberately not negotiated by this additive, identity-only transport.

use super::codec::{Codec, FramedCodec};
use super::server::{format_grpc_timeout, parse_grpc_timeout};
use super::status::{Code, GrpcError, Status};
use super::streaming::{Metadata, MetadataValue, Request, Streaming};
use super::web::{Base64StreamDecoder, ContentType, TrailerFrame, WebFrame, WebFrameCodec};
use crate::bytes::{Buf, BytesMut};
use crate::cx::{CancelWakerToken, Cx};
use crate::http::body::{Body, Frame};
use crate::http::h1::{
    ClientError, HttpClient, HttpClientConfig, HttpError, Method, PooledClientIncomingBody,
    RedirectPolicy, ResponseHead, RetryPolicy,
};
use crate::time::Sleep;
use crate::types::{CancelKind, Time};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

const POLL_STEPS: usize = 16;

/// Bounds and wire mode for a native gRPC-Web client.
///
/// Limits count encoded message bytes, HTTP body bytes (including base64
/// padding in text mode), and HTTP metadata bytes respectively. A custom
/// serialization codec can allocate internally before returning its bytes.
#[derive(Debug, Clone)]
pub struct GrpcWebClientConfig {
    /// Request and preferred response representation. Binary is the default.
    pub content_type: ContentType,
    /// Maximum serialized request message size, before framing or base64.
    pub max_send_message_size: usize,
    /// Maximum serialized response message size, after base64 decoding.
    pub max_recv_message_size: usize,
    /// Aggregate HTTP body limit, independently applied to request and response.
    pub max_body_size: usize,
    /// Maximum request headers, response headers, or body trailer block.
    pub max_metadata_size: usize,
    /// Total call timeout, including encoding, connect, headers and body.
    /// The caller's deadline and request's grpc-timeout can only shorten it.
    pub timeout: Duration,
}

impl Default for GrpcWebClientConfig {
    fn default() -> Self {
        Self {
            content_type: ContentType::GrpcWeb,
            max_send_message_size: super::DEFAULT_MAX_MESSAGE_SIZE,
            max_recv_message_size: super::DEFAULT_MAX_MESSAGE_SIZE,
            max_body_size: 16 * 1024 * 1024,
            max_metadata_size: 16 * 1024,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Native gRPC-Web transport. Clones share the HTTP connection pool.
///
/// Calls send exactly one request message and receive either one unary result
/// or an owned response stream. Automatic HTTP redirects and retries are
/// disabled, including when supplying a custom HTTP configuration. TLS roots,
/// DNS, pool admission and stricter HTTP body/timeout bounds are preserved.
#[derive(Clone)]
pub struct GrpcWebClient {
    http: HttpClient,
    config: GrpcWebClientConfig,
    default_header_bytes: usize,
}

impl fmt::Debug for GrpcWebClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcWebClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Default for GrpcWebClient {
    fn default() -> Self {
        Self::with_config(GrpcWebClientConfig::default())
            .expect("default gRPC-Web limits are valid")
    }
}

impl GrpcWebClient {
    /// Construct a client with finite default limits and a 30 second timeout.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a client with explicit gRPC-Web bounds.
    pub fn with_config(config: GrpcWebClientConfig) -> Result<Self, Status> {
        Self::with_http_config(HttpClientConfig::default(), config)
    }

    /// Configure native HTTP connectivity, TLS trust, DNS and pool admission.
    ///
    /// Transport headers cannot be supplied through default_headers. Supply
    /// application metadata there or on each Request. A proxy is rejected:
    /// the owned pooled streaming HTTP transport currently uses direct
    /// HTTP/HTTPS connections. Automatic redirects and retries are disabled.
    pub fn with_http_config(
        mut http: HttpClientConfig,
        mut config: GrpcWebClientConfig,
    ) -> Result<Self, Status> {
        if config.max_send_message_size > u32::MAX as usize
            || config.max_recv_message_size > u32::MAX as usize
            || config.max_metadata_size == 0
            || config.max_metadata_size > u32::MAX as usize
            || config.max_body_size < 5
            || config.timeout.is_zero()
        {
            return Err(Status::invalid_argument("invalid gRPC-Web limits"));
        }
        if http.proxy_url.is_some() {
            return Err(Status::unimplemented(
                "native gRPC-Web pooled streaming requires a direct connection",
            ));
        }
        let mut default_header_bytes = 0;
        for (name, value) in &http.default_headers {
            if reserved_request_header(name) {
                return Err(Status::invalid_argument(
                    "transport-reserved gRPC-Web default header",
                ));
            }
            let mut metadata = Metadata::new();
            if !metadata.insert(name, value) {
                return Err(Status::invalid_argument("invalid gRPC-Web default header"));
            }
            charge_metadata(
                &mut default_header_bytes,
                name.len(),
                value.len(),
                config.max_metadata_size,
            )?;
        }
        if let Some(limit) = http.max_body_size {
            config.max_body_size = config.max_body_size.min(limit);
        }
        if let Some(timeout) = http.request_timeout {
            config.timeout = config.timeout.min(timeout);
        }
        if config.max_body_size < 5 || config.timeout.is_zero() {
            return Err(Status::invalid_argument("invalid gRPC-Web HTTP bounds"));
        }
        http.max_body_size = Some(config.max_body_size);
        http.request_timeout = Some(config.timeout);
        http.redirect_policy = RedirectPolicy::None;
        http.retry_policy = RetryPolicy::None;
        http.user_agent = None;
        Ok(Self {
            http: HttpClient::with_config(http),
            config,
            default_header_bytes,
        })
    }

    /// Send one request and receive exactly one response with terminal status.
    ///
    /// The URL includes the full method path, for example
    /// http://localhost:8080/package.Service/Method. A response is successful
    /// only after HTTP EOF and a valid OK gRPC status. Extra response messages
    /// fail the unary call; a late remote error is never hidden by the first
    /// message.
    pub async fn unary<C: Codec>(
        &self,
        cx: &Cx,
        url: &str,
        request: Request<C::Encode>,
        codec: C,
    ) -> Result<GrpcWebUnaryResponse<C::Decode>, Status> {
        let mut stream = self.server_streaming(cx, url, request, codec).await?;
        let message = stream.message().await?;
        if stream.message().await?.is_some() {
            return Err(Status::internal(
                "gRPC-Web unary response contained multiple messages",
            ));
        }
        let message = message
            .ok_or_else(|| Status::internal("gRPC-Web unary response contained no message"))?;
        Ok(GrpcWebUnaryResponse {
            message,
            initial_metadata: stream.initial_metadata,
            trailing_metadata: stream
                .trailers
                .take()
                .expect("successful EOF has trailers")
                .metadata,
        })
    }

    /// Start an owned server-streaming call without collecting its response.
    ///
    /// Dropping this dispatch future closes any connection it owns. Once
    /// returned, the stream retains the original Cx and absolute deadline;
    /// dropping a borrowing message wait preserves partial decode progress.
    pub async fn server_streaming<C: Codec>(
        &self,
        cx: &Cx,
        url: &str,
        request: Request<C::Encode>,
        codec: C,
    ) -> Result<GrpcWebResponseStream<C>, Status> {
        let mut control = CallControl::new(cx, request.metadata(), self.config.timeout)?;
        control.check_now()?;
        let mut codec = FramedCodec::with_message_size_limits(
            codec,
            self.config.max_send_message_size,
            self.config.max_recv_message_size,
        );
        let mut framed = BytesMut::new();
        codec
            .encode_message(request.get_ref(), &mut framed)
            .map_err(GrpcError::into_status)?;
        let body = if self.config.content_type.is_text_mode() {
            let encoded_len = framed
                .len()
                .checked_add(2)
                .and_then(|n| n.checked_div(3))
                .and_then(|n| n.checked_mul(4))
                .ok_or_else(|| Status::resource_exhausted("gRPC-Web request length overflow"))?;
            if encoded_len > self.config.max_body_size {
                return Err(Status::resource_exhausted(
                    "gRPC-Web request body limit exceeded",
                ));
            }
            super::web::base64_encode(&framed).into_bytes()
        } else {
            if framed.len() > self.config.max_body_size {
                return Err(Status::resource_exhausted(
                    "gRPC-Web request body limit exceeded",
                ));
            }
            framed.to_vec()
        };
        control.check_now()?;
        let headers = request_headers(
            request.metadata(),
            &self.config,
            self.default_header_bytes,
            &control,
        )?;
        let mut dispatch = std::pin::pin!(self.http.request_streaming_pooled(
            cx,
            Method::Post,
            url,
            headers,
            body,
        ));
        let response = poll_fn(|task| {
            if let Err(status) = control.poll_stop(task) {
                return Poll::Ready(Err(status));
            }
            let _ambient = Cx::set_current(Some(control.cx.clone()));
            dispatch
                .as_mut()
                .poll(task)
                .map(|result| result.map_err(transport_status))
        })
        .await?;
        let (content_type, initial_metadata, trailers) =
            response_headers(&response.head, self.config.max_metadata_size)?;
        Ok(GrpcWebResponseStream {
            body: Some(response.body),
            codec,
            frames: WebFrameCodec::with_max_size(
                self.config
                    .max_recv_message_size
                    .max(self.config.max_metadata_size),
            ),
            base64: content_type
                .is_text_mode()
                .then(Base64StreamDecoder::new_chunked),
            pending: BytesMut::new(),
            control,
            initial_metadata,
            headers_only: trailers.is_some(),
            trailers,
            trailers_validated: false,
            http_status: response.head.status,
            max_message_size: self.config.max_recv_message_size,
            max_metadata_size: self.config.max_metadata_size,
            max_body_size: self.config.max_body_size,
            received_body_bytes: 0,
            eof: false,
            terminal: None,
        })
    }
}

/// A completed unary result with initial and trailing metadata kept separate.
#[derive(Debug)]
pub struct GrpcWebUnaryResponse<T> {
    message: T,
    initial_metadata: Metadata,
    trailing_metadata: Metadata,
}

impl<T> GrpcWebUnaryResponse<T> {
    /// The decoded response message.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.message
    }

    /// Initial response metadata.
    #[must_use]
    pub fn initial_metadata(&self) -> &Metadata {
        &self.initial_metadata
    }

    /// Validated terminal metadata.
    #[must_use]
    pub fn trailing_metadata(&self) -> &Metadata {
        &self.trailing_metadata
    }

    /// Consume the result, returning its message.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.message
    }
}

/// A bounded, pull-driven gRPC-Web response and its owned HTTP body.
///
/// Each message is delivered before source EOF. Terminal status is accepted
/// only after the final trailer frame and HTTP EOF. Protocol and transport
/// errors are returned once, followed by Ok(None); terminal_status retains
/// their classification. Missing status never becomes successful EOF.
///
/// Dropping or cancelling an unfinished stream closes its HTTP connection
/// synchronously and releases pool admission. A complete HTTP body may reuse
/// its connection. No task is spawned to drain an abandoned body. An unpolled
/// owner retains its resources; cancellation and timeouts are observed on
/// polling. Read-ahead is bounded by one message plus a native HTTP body chunk,
/// bounded headers/trailers, and transport buffers.
pub struct GrpcWebResponseStream<C: Codec> {
    body: Option<PooledClientIncomingBody>,
    codec: FramedCodec<C>,
    frames: WebFrameCodec,
    base64: Option<Base64StreamDecoder>,
    pending: BytesMut,
    control: CallControl,
    initial_metadata: Metadata,
    headers_only: bool,
    trailers: Option<TrailerFrame>,
    trailers_validated: bool,
    http_status: u16,
    max_message_size: usize,
    max_metadata_size: usize,
    max_body_size: usize,
    received_body_bytes: usize,
    eof: bool,
    terminal: Option<Status>,
}

impl<C: Codec> fmt::Debug for GrpcWebResponseStream<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcWebResponseStream")
            .field("buffered_bytes", &self.pending.len())
            .field("received_body_bytes", &self.received_body_bytes)
            .field("terminal_code", &self.terminal.as_ref().map(Status::code))
            .finish_non_exhaustive()
    }
}

impl<C: Codec> GrpcWebResponseStream<C> {
    /// Initial response metadata, separate from terminal trailers.
    #[must_use]
    pub fn initial_metadata(&self) -> &Metadata {
        &self.initial_metadata
    }

    /// Trailer metadata after a complete, validated HTTP EOF.
    #[must_use]
    pub fn trailing_metadata(&self) -> Option<&Metadata> {
        self.trailers_validated
            .then(|| &self.trailers.as_ref().expect("validated trailers").metadata)
    }

    /// Final observed remote or local status. None means the call is live.
    #[must_use]
    pub fn terminal_status(&self) -> Option<&Status> {
        self.terminal.as_ref()
    }

    /// Receive one message without collecting the remaining response.
    pub async fn message(&mut self) -> Result<Option<C::Decode>, Status> {
        poll_fn(|task| self.poll_message(task)).await
    }

    /// Immediately close an unfinished body without cancelling its parent Cx.
    /// Subsequent reads return Ok(None); terminal_status records Cancelled.
    pub fn cancel(&mut self) {
        if self.terminal.is_none() {
            self.retire(Status::cancelled(
                "gRPC-Web stream cancelled by its consumer",
            ));
        }
    }

    /// Poll one message. The original Cx and deadline apply even to already
    /// buffered messages; a foreign ambient task cannot replace their owner.
    pub fn poll_message(
        &mut self,
        task: &mut Context<'_>,
    ) -> Poll<Result<Option<C::Decode>, Status>> {
        if self.terminal.is_some() {
            return Poll::Ready(Ok(None));
        }
        let _ambient = Cx::set_current(Some(self.control.cx.clone()));
        let result = self.poll_progress(task);
        if let Poll::Ready(Err(status)) = &result {
            self.retire(status.clone());
        }
        result
    }

    fn poll_progress(&mut self, task: &mut Context<'_>) -> Poll<Result<Option<C::Decode>, Status>> {
        self.control.poll_stop(task)?;
        for _ in 0..POLL_STEPS {
            if self.pending.len() >= 5 {
                let flag = self.pending[0];
                let len = u32::from_be_bytes([
                    self.pending[1],
                    self.pending[2],
                    self.pending[3],
                    self.pending[4],
                ]) as usize;
                let limit = if flag & 0x80 != 0 {
                    self.max_metadata_size
                } else {
                    self.max_message_size
                };
                if len > limit {
                    return Poll::Ready(Err(Status::resource_exhausted(
                        "gRPC-Web frame limit exceeded",
                    )));
                }
                if flag & 1 != 0 {
                    return Poll::Ready(Err(Status::unimplemented(
                        "compressed gRPC-Web frames were not negotiated",
                    )));
                }
                if flag & 0x80 != 0 && self.pending.len().saturating_sub(5) >= len {
                    require_status(&self.pending[5..5 + len])?;
                }
            }
            match self
                .frames
                .decode(&mut self.pending)
                .map_err(GrpcError::into_status)?
            {
                Some(WebFrame::Data { compressed, data }) => {
                    if compressed {
                        return Poll::Ready(Err(Status::unimplemented(
                            "compressed gRPC-Web message",
                        )));
                    }
                    let decoded = self
                        .codec
                        .inner_mut()
                        .decode(&data)
                        .map_err(|error| C::map_decode_error(error).into_status())?;
                    return Poll::Ready(Ok(Some(decoded)));
                }
                Some(WebFrame::Trailers(trailers)) => {
                    self.trailers = Some(trailers);
                    continue;
                }
                None => {}
            }
            if self.eof {
                if !self.pending.is_empty() {
                    return Poll::Ready(Err(Status::internal(
                        "truncated gRPC-Web frame at HTTP EOF",
                    )));
                }
                let status = self
                    .trailers
                    .as_ref()
                    .map(|trailers| trailers.status.clone())
                    .ok_or_else(|| http_fallback(self.http_status))?;
                self.trailers_validated = true;
                self.retire(status.clone());
                return Poll::Ready(if status.is_ok() {
                    Ok(None)
                } else {
                    Err(status)
                });
            }
            let body = self.body.as_mut().expect("live HTTP body before EOF");
            match Pin::new(body).poll_frame(task) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(transport_status(error))),
                Poll::Ready(Some(Ok(Frame::Data(data)))) => {
                    let bytes = data.chunk();
                    self.received_body_bytes = self
                        .received_body_bytes
                        .checked_add(bytes.len())
                        .filter(|n| *n <= self.max_body_size)
                        .ok_or_else(|| {
                            Status::resource_exhausted("gRPC-Web response body limit exceeded")
                        })?;
                    if self.headers_only && !bytes.is_empty() {
                        return Poll::Ready(Err(Status::internal(
                            "body bytes after gRPC-Web trailers-only headers",
                        )));
                    }
                    if let Some(base64) = &mut self.base64 {
                        self.pending.extend_from_slice(
                            &base64.push(bytes).map_err(GrpcError::into_status)?,
                        );
                    } else {
                        self.pending.extend_from_slice(bytes);
                    }
                }
                Poll::Ready(Some(Ok(Frame::Trailers(trailers)))) => {
                    // HTTP trailers do not carry gRPC-Web status. Proxies may
                    // add transport metadata; bound it without letting it
                    // replace the required body trailer or trailers-only head.
                    let mut bytes = 0;
                    for (name, value) in trailers.iter() {
                        charge_metadata(
                            &mut bytes,
                            name.as_str().len(),
                            value.as_bytes().len(),
                            self.max_metadata_size,
                        )?;
                    }
                }
                Poll::Ready(None) => {
                    self.eof = true;
                    drop(self.body.take());
                    if let Some(mut base64) = self.base64.take() {
                        self.pending
                            .extend_from_slice(&base64.finish().map_err(GrpcError::into_status)?);
                    }
                }
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }

    fn retire(&mut self, status: Status) {
        if self.terminal.is_some() {
            return;
        }
        self.terminal = Some(status);
        drop(self.body.take());
        self.pending = BytesMut::new();
        self.base64 = None;
        self.control.retire();
    }
}

impl<C: Codec + Unpin> Streaming for GrpcWebResponseStream<C> {
    type Message = C::Decode;

    fn poll_next(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Message, Status>>> {
        self.get_mut()
            .poll_message(task)
            .map(|result| match result {
                Ok(message) => message.map(Ok),
                Err(status) => Some(Err(status)),
            })
    }
}

struct CallControl {
    cx: Cx,
    cancel_waker: Option<CancelWakerToken>,
    deadline: Time,
    timer: Option<Sleep>,
    standalone_clock: bool,
}

impl CallControl {
    fn new(cx: &Cx, metadata: &Metadata, timeout: Duration) -> Result<Self, Status> {
        let clock = cx.timer_driver();
        let now = clock
            .as_ref()
            .map_or_else(crate::time::wall_now, |clock| clock.now());
        let mut deadline = now + timeout;
        if let Some(at) = cx.budget().deadline {
            deadline = deadline.min(at);
        }
        let mut requested = metadata.iter().filter(|(name, _)| *name == "grpc-timeout");
        if let Some((_, value)) = requested.next() {
            let MetadataValue::Ascii(value) = value else {
                return Err(Status::invalid_argument("binary grpc-timeout"));
            };
            let timeout = parse_grpc_timeout(value)
                .ok_or_else(|| Status::invalid_argument("malformed grpc-timeout"))?;
            deadline = deadline.min(now + timeout);
        }
        if requested.next().is_some() {
            return Err(Status::invalid_argument("duplicate grpc-timeout"));
        }
        let standalone_clock = clock.is_none();
        let timer = match clock {
            Some(clock) => Sleep::with_timer_driver(deadline, clock),
            None => {
                let _ambient = Cx::set_current(None);
                Sleep::new(deadline)
            }
        };
        Ok(Self {
            cx: cx.clone(),
            cancel_waker: None,
            deadline,
            timer: Some(timer),
            standalone_clock,
        })
    }

    fn now(&self) -> Time {
        self.cx
            .timer_driver()
            .as_ref()
            .map_or_else(crate::time::wall_now, |clock| clock.now())
    }

    fn check_now(&self) -> Result<(), Status> {
        if self.now() >= self.deadline {
            return Err(Status::deadline_exceeded("gRPC-Web call deadline exceeded"));
        }
        self.cx.checkpoint().map_err(
            |_| match self.cx.cancel_reason().map(|reason| reason.kind) {
                Some(CancelKind::Timeout | CancelKind::Deadline) => {
                    Status::deadline_exceeded("gRPC-Web caller deadline exceeded")
                }
                Some(CancelKind::PollQuota | CancelKind::CostBudget) => {
                    Status::resource_exhausted("gRPC-Web caller budget exhausted")
                }
                _ => Status::cancelled("gRPC-Web caller cancelled"),
            },
        )
    }

    fn poll_stop(&mut self, task: &mut Context<'_>) -> Result<(), Status> {
        self.cancel_waker = Some(
            self.cx
                .refresh_cancel_waker(self.cancel_waker, task.waker()),
        );
        let _ambient = self.standalone_clock.then(|| Cx::set_current(None));
        if self
            .timer
            .as_mut()
            .is_some_and(|timer| Pin::new(timer).poll_deadline(task).is_ready())
        {
            return Err(Status::deadline_exceeded("gRPC-Web call deadline exceeded"));
        }
        self.check_now()
    }

    fn retire(&mut self) {
        if let Some(token) = self.cancel_waker.take() {
            self.cx.clear_cancel_waker(token);
        }
        self.timer = None;
    }
}

impl Drop for CallControl {
    fn drop(&mut self) {
        self.retire();
    }
}

fn reserved_request_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("grpc-")
        || name.starts_with(':')
        || matches!(
            name.as_str(),
            "accept"
                | "accept-encoding"
                | "content-type"
                | "content-length"
                | "content-encoding"
                | "transfer-encoding"
                | "content-transfer-encoding"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "upgrade"
                | "host"
                | "te"
                | "trailer"
                | "expect"
                | "x-grpc-web"
                | "x-user-agent"
                | "user-agent"
        )
}

fn charge_metadata(
    bytes: &mut usize,
    name: usize,
    value: usize,
    limit: usize,
) -> Result<(), Status> {
    *bytes = bytes
        .checked_add(name)
        .and_then(|n| n.checked_add(value))
        .and_then(|n| n.checked_add(4))
        .filter(|n| *n <= limit)
        .ok_or_else(|| Status::resource_exhausted("gRPC-Web metadata limit exceeded"))?;
    Ok(())
}

fn request_headers(
    metadata: &Metadata,
    config: &GrpcWebClientConfig,
    mut bytes: usize,
    control: &CallControl,
) -> Result<Vec<(String, String)>, Status> {
    let now = control.now();
    if now >= control.deadline {
        return Err(Status::deadline_exceeded(
            "gRPC-Web deadline expired before headers",
        ));
    }
    let mut headers = vec![
        (
            "content-type".to_owned(),
            config.content_type.as_header_value().to_owned(),
        ),
        (
            "accept".to_owned(),
            config.content_type.as_header_value().to_owned(),
        ),
        ("accept-encoding".to_owned(), "identity".to_owned()),
        ("grpc-accept-encoding".to_owned(), "identity".to_owned()),
        ("x-grpc-web".to_owned(), "1".to_owned()),
        (
            "x-user-agent".to_owned(),
            "asupersync-grpc-web/0.1".to_owned(),
        ),
        (
            "grpc-timeout".to_owned(),
            format_grpc_timeout(Duration::from_nanos(control.deadline.duration_since(now))),
        ),
    ];
    for (name, value) in &headers {
        charge_metadata(
            &mut bytes,
            name.len(),
            value.len(),
            config.max_metadata_size,
        )?;
    }
    for (name, value) in metadata.iter() {
        if name == "grpc-timeout" {
            continue;
        }
        if reserved_request_header(name) {
            return Err(Status::invalid_argument(
                "transport-reserved gRPC-Web request metadata",
            ));
        }
        let length = match value {
            MetadataValue::Ascii(value) => value.len(),
            MetadataValue::Binary(value) => value
                .len()
                .checked_add(2)
                .and_then(|n| n.checked_div(3))
                .and_then(|n| n.checked_mul(4))
                .ok_or_else(|| Status::resource_exhausted("gRPC-Web metadata length overflow"))?,
        };
        charge_metadata(&mut bytes, name.len(), length, config.max_metadata_size)?;
        let value = match value {
            MetadataValue::Ascii(value) => value.clone(),
            MetadataValue::Binary(value) => super::web::base64_encode(value),
        };
        headers.push((name.to_owned(), value));
    }
    Ok(headers)
}

fn one_header<'a>(headers: &'a [(String, String)], name: &str) -> Result<Option<&'a str>, Status> {
    let mut values = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name));
    let value = values.next().map(|(_, value)| value.as_str());
    if values.next().is_some() {
        return Err(Status::internal(format!(
            "duplicate gRPC-Web response {name}"
        )));
    }
    Ok(value)
}

fn response_headers(
    head: &ResponseHead,
    limit: usize,
) -> Result<(ContentType, Metadata, Option<TrailerFrame>), Status> {
    let mut bytes = 0;
    for (name, value) in &head.headers {
        charge_metadata(&mut bytes, name.len(), value.len(), limit)?;
    }
    let status = one_header(&head.headers, "grpc-status")?;
    let content_type = one_header(&head.headers, "content-type")?.and_then(|value| {
        match value
            .split(';')
            .next()?
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "application/grpc-web" | "application/grpc-web+proto" => Some(ContentType::GrpcWeb),
            "application/grpc-web-text" | "application/grpc-web-text+proto" => {
                Some(ContentType::GrpcWebText)
            }
            _ => None,
        }
    });
    let content_type = content_type.ok_or_else(|| {
        if head.status != 200 && status.is_none() {
            http_fallback(head.status)
        } else {
            Status::internal("missing or unsupported gRPC-Web content-type")
        }
    })?;
    for name in ["content-encoding", "grpc-encoding"] {
        if one_header(&head.headers, name)?
            .is_some_and(|value| !value.trim().eq_ignore_ascii_case("identity"))
        {
            return Err(Status::unimplemented(
                "gRPC-Web response compression was not negotiated",
            ));
        }
    }
    let mut block = Vec::with_capacity(bytes);
    for (name, value) in &head.headers {
        let lower = name.to_ascii_lowercase();
        if reserved_request_header(&lower)
            && !matches!(
                lower.as_str(),
                "grpc-status" | "grpc-message" | "grpc-status-details-bin"
            )
        {
            continue;
        }
        block.extend_from_slice(lower.as_bytes());
        block.extend_from_slice(b": ");
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(b"\r\n");
    }
    if status.is_some() {
        require_status(&block)?;
        let trailers = super::web::decode_trailers(&block).map_err(GrpcError::into_status)?;
        Ok((content_type, Metadata::new(), Some(trailers)))
    } else {
        if one_header(&head.headers, "grpc-message")?.is_some() {
            return Err(Status::internal(
                "grpc-message without grpc-status in response headers",
            ));
        }
        block.extend_from_slice(b"grpc-status: 0\r\n");
        let parsed = super::web::decode_trailers(&block).map_err(GrpcError::into_status)?;
        Ok((content_type, parsed.metadata, None))
    }
}

fn require_status(block: &[u8]) -> Result<(), Status> {
    let text = std::str::from_utf8(block)
        .map_err(|_| Status::internal("invalid gRPC-Web trailer UTF-8"))?;
    let mut statuses = text
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("grpc-status"));
    let (_, value) = statuses
        .next()
        .ok_or_else(|| Status::internal("gRPC-Web trailers lack grpc-status"))?;
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || statuses.next().is_some()
    {
        return Err(Status::internal(
            "invalid or duplicate gRPC-Web grpc-status",
        ));
    }
    Ok(())
}

fn http_fallback(status: u16) -> Status {
    let code = match status {
        400 => Code::Internal,
        401 => Code::Unauthenticated,
        403 => Code::PermissionDenied,
        404 => Code::Unimplemented,
        429 | 502 | 503 | 504 => Code::Unavailable,
        _ => Code::Unknown,
    };
    Status::new(
        code,
        format!("gRPC-Web response has no grpc-status (HTTP {status})"),
    )
}

fn transport_status(error: ClientError) -> Status {
    match error {
        ClientError::Cancelled => Status::cancelled("gRPC-Web HTTP operation cancelled"),
        ClientError::DeadlineExceeded => {
            Status::deadline_exceeded("gRPC-Web HTTP deadline exceeded")
        }
        ClientError::InvalidUrl(_) | ClientError::InvalidConnectInput(_) => {
            Status::invalid_argument(error.to_string())
        }
        ClientError::HttpError(
            HttpError::BodyTooLarge
            | HttpError::BodyTooLargeDetailed { .. }
            | HttpError::HeadersTooLarge
            | HttpError::TooManyHeaders,
        ) => Status::resource_exhausted(error.to_string()),
        ClientError::HttpError(HttpError::Io(_)) => Status::unavailable(error.to_string()),
        ClientError::HttpError(_) => Status::internal(error.to_string()),
        ClientError::PoolExhausted { .. } => {
            Status::resource_exhausted("gRPC-Web HTTP connection pool exhausted")
        }
        _ => Status::unavailable(error.to_string()),
    }
}

#[cfg(test)]
mod tests;
