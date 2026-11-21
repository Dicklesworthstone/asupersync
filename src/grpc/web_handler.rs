//! Native gRPC-Web dispatch with buffered unary and HTTP/1.1 server streaming.
//!
//! This is a protocol adapter, not a second RPC executor: registered services,
//! interceptors, compression, decoded-message limits, and deadlines still run
//! through [`Server::registered_unary_handler`]. The owning HTTP listener must
//! install its request-region `Cx` and enforce its host policy and body limit.
//! No task, runtime, or network connection is created by the adapter.
//!
//! The unary adapter retains its existing admission policy. The separately
//! selected produced-response adapter admits protobuf unary and server-streaming
//! methods; client streaming and bidirectional methods remain unsupported.
//! Cross-origin policy belongs to the caller; this adapter does not implicitly
//! grant CORS access.

use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

use crate::bytes::{Buf, Bytes, BytesMut};
use crate::cx::Cx;
use crate::http::body::{Body, Frame, HeaderMap};
use crate::http::decode::{
    ContentDecodeError, ContentDecodeLimits, ContentDecodePlan, ContentDecodedBody, ContentDecoder,
    invalidated_field, is_limit_error,
};
use crate::http::h1::types::{Method, Request as HttpRequest, Response as HttpResponse, Version};
use crate::http::h1::{
    Http1ProducedResponse, HttpError, IncomingBodyError, OutgoingBodySender, StreamingServerRequest,
};
use crate::types::CancelKind;

use super::server::server_streaming::{ServerStreamSink, ServerStreamingConfig};

use super::Server;
use super::status::Status;
use super::streaming::Metadata;
use super::web::{ContentType, base64_encode, encode_trailers};

/// Additional wire-retention limits for buffered unary gRPC-Web requests.
///
/// These are checked after the HTTP listener has collected the request body;
/// configure that listener's body limit as well. Native server limits remain
/// authoritative for decoded (including decompressed) messages. Zero is a
/// literal zero-byte limit, not an unlimited sentinel. Small, transport-owned
/// error responses are exempt from response limits so failure remains legible.
#[derive(Debug, Clone)]
pub struct GrpcWebConfig {
    /// Maximum decoded request framing bytes, including the five-byte prefix.
    /// Text input is additionally capped at four times this value, allowing
    /// independently padded base64 chunks without unbounded amplification.
    pub max_request_bytes: usize,
    /// Maximum native response framing bytes, before adding the trailer frame
    /// or expanding the complete response into base64. The separately selected
    /// streaming handler applies this limit to each complete gRPC message frame,
    /// so an unbounded number of bounded messages can be delivered incrementally.
    pub max_response_bytes: usize,
    /// Maximum serialized terminal trailer block, excluding its five-byte prefix.
    pub max_trailer_bytes: usize,
}

impl Default for GrpcWebConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: super::DEFAULT_MAX_MESSAGE_SIZE + 5,
            max_response_bytes: super::DEFAULT_MAX_MESSAGE_SIZE + 5,
            max_trailer_bytes: 8 * 1024,
        }
    }
}

/// Owned response future returned by the native gRPC-Web unary handler.
pub type GrpcWebHandlerFuture = Pin<Box<dyn Future<Output = HttpResponse> + Send>>;

/// Owned future returned by the HTTP/1.1 gRPC-Web produced-response handler.
pub type GrpcWebStreamingHandlerFuture =
    Pin<Box<dyn Future<Output = Http1ProducedResponse> + Send>>;

impl Server {
    /// Adapt registered protobuf unary RPCs to binary and text gRPC-Web.
    ///
    /// The closure can be served by an HTTP/1 listener or combined with REST
    /// and native gRPC handlers on an auto-negotiating listener. It accepts
    /// only the gRPC-Web media types, never changes the native handler's
    /// HTTP/2-only admission policy, and preserves the listener's request `Cx`.
    /// `Accept` negotiates binary/text independently of the request encoding.
    /// Responses carry terminal gRPC status and metadata in a final `0x80`
    /// body frame; HTTP trailers are not required by browser clients.
    ///
    /// The caller must configure the listener's host/origin policy and body
    /// limit. This buffered unary adapter does not grant cross-origin access
    /// or claim server/client/bidirectional streaming support.
    ///
    /// # Errors
    /// Returns the registered native handler's configuration error, including
    /// a server without services or invalid HTTP/2 transport settings.
    pub fn registered_grpc_web_unary_handler(
        self: &Arc<Self>,
        config: GrpcWebConfig,
    ) -> io::Result<impl Fn(HttpRequest) -> GrpcWebHandlerFuture + Clone + Send + Sync + 'static>
    {
        self.grpc_web_unary_handler(config, None)
    }

    /// Opt a registered unary gRPC-Web handler into HTTP content decoding.
    ///
    /// HTTP `Content-Encoding` is decoded before text base64 and gRPC message
    /// framing. This is independent of message-level `grpc-encoding`, which
    /// still requires the server's existing compression policy. Identity works
    /// without codec features; gzip, deflate, and Brotli require `compression`,
    /// and zstd requires `zstd`.
    ///
    /// The mandatory encoded-input and per-stage decoded-output limits are
    /// tightened to the request's binary/text wire allowance in `config`.
    /// The listener has already collected the encoded body; its receive limit
    /// must also be configured. Decoding moves that input into the decoder
    /// without copying it, and collects one bounded decoded representation.
    /// See [`ContentDecodeLimits`] for retained codec output bounds.
    ///
    /// Every codec must finish successfully before the registered service is
    /// invoked. Malformed data and HTTP trailers are refused, size refusals
    /// become RESOURCE_EXHAUSTED, and missing codecs become UNIMPLEMENTED.
    /// Original HTTP fields are bounded before transformed length/coding/digest
    /// fields are removed. The listener's current request `Cx` is required and
    /// remains the cancellation authority throughout decoding and dispatch.
    ///
    /// # Errors
    /// Returns the same installation errors as
    /// [`Self::registered_grpc_web_unary_handler`].
    pub fn registered_grpc_web_unary_handler_with_http_decoding(
        self: &Arc<Self>,
        config: GrpcWebConfig,
        limits: ContentDecodeLimits,
    ) -> io::Result<impl Fn(HttpRequest) -> GrpcWebHandlerFuture + Clone + Send + Sync + 'static>
    {
        self.grpc_web_unary_handler(config, Some(limits))
    }

    fn grpc_web_unary_handler(
        self: &Arc<Self>,
        config: GrpcWebConfig,
        decoding: Option<ContentDecodeLimits>,
    ) -> io::Result<impl Fn(HttpRequest) -> GrpcWebHandlerFuture + Clone + Send + Sync + 'static>
    {
        let native = self.registered_unary_handler()?;
        let metadata_limit = self.config().max_metadata_size;
        Ok(move |request: HttpRequest| -> GrpcWebHandlerFuture {
            let native = native.clone();
            let config = config.clone();
            Box::pin(async move {
                let version = request.version;
                let request = if let Some(limits) = decoding {
                    let mode = match request_modes(&request) {
                        Ok((_, mode)) => mode,
                        Err(response) => return response,
                    };
                    let Some(cx) = Cx::current() else {
                        return error_response(
                            &Status::internal("gRPC-Web HTTP decoding requires a runtime Cx"),
                            mode,
                            version,
                        );
                    };
                    let mut request = request;
                    let source = Bytes::from(std::mem::take(&mut request.body));
                    match decode_request_body(
                        &cx,
                        request,
                        source,
                        |never| match never {},
                        &config,
                        limits,
                        metadata_limit,
                    )
                    .await
                    {
                        Ok(request) => request,
                        Err(response) => return response,
                    }
                } else {
                    request
                };
                let (request, mode) = match prepare_request(request, &config) {
                    Ok(prepared) => prepared,
                    Err(response) => return response,
                };
                let response = native(request).await;
                match encode_response(response, mode, version, &config) {
                    Ok(response) => response,
                    Err(status) => error_response(&status, mode, version),
                }
            })
        })
    }
}

impl Server {
    /// Adapt registered unary and server-streaming protobuf RPCs to HTTP/1.1.
    ///
    /// Install this handler with
    /// [`Http1Listener::bind_produced`](crate::http::h1::Http1Listener::bind_produced)
    /// and drive the listener with `run_produced`. The explicit request `Cx`
    /// and the later producer `Cx` come from that listener's request region.
    /// The listener remains responsible for host/origin admission, request-body
    /// limits, transport deadlines, and disconnect/shutdown cleanup.
    ///
    /// A single bounded request message is collected before dispatch. Unary
    /// methods use the established unary pipeline. Server streams use the same
    /// service resolution, interceptors, codec, absolute deadline, cancellation,
    /// and source destruction as the native HTTP/2 streaming lane. Application
    /// code starts only when the listener admits the response producer.
    /// Methods opting into `ServiceHandler::defer_response_headers` can supply
    /// initial metadata, validated and sent in the HTTP response head before
    /// the first message. It remains separate from the terminal trailer frame,
    /// with the same encoded metadata limits as H2. Existing registrations
    /// retain eager headers.
    ///
    /// Binary responses carry incremental gRPC DATA frames followed by exactly
    /// one `0x80` trailer frame in the body. Text responses encode bounded
    /// chunks independently; base64 padding can occur before the body ends.
    /// A client must decode the stream incrementally rather than treating the
    /// complete response as a single base64 entity. No HTTP trailers are needed.
    ///
    /// `wire.max_response_bytes` bounds each complete encoded message before
    /// its prefix is queued; it does not cap the total stream length. Native
    /// decoded-message limits still apply. Both native trailer-field limits
    /// and `wire.max_trailer_bytes` (including colon/CRLF syntax) are enforced.
    /// Oversize terminal metadata becomes a bounded RESOURCE_EXHAUSTED trailer.
    ///
    /// The HTTP body channel retains `streaming.frame_capacity` frames, each
    /// at most `streaming.max_frame_bytes` after text expansion. In addition to
    /// the transport's own bound, the producer retains one encoded gRPC message
    /// and one text-encoding chunk. Slow readers therefore stop source polling
    /// after bounded prefetch. Application-owned backing memory is excluded.
    /// Cancellation during a partly queued message fails the HTTP producer;
    /// it cannot append apparently successful trailers to truncated framing.
    ///
    /// # Errors
    /// Refuses invalid native streaming/transport settings, an empty server,
    /// unavailable configured compression, or a trailer-byte cap below 17
    /// (the space needed for a bare two-digit terminal status).
    pub fn registered_grpc_web_streaming_handler(
        self: &Arc<Self>,
        wire: GrpcWebConfig,
        streaming: ServerStreamingConfig,
    ) -> io::Result<
        impl Fn(Cx, StreamingServerRequest) -> GrpcWebStreamingHandlerFuture
        + Clone
        + Send
        + Sync
        + 'static,
    > {
        self.grpc_web_streaming_handler(wire, streaming, None)
    }

    /// Decode HTTP request content before native gRPC-Web unary/server streaming.
    ///
    /// This opt-in uses the same decoding, metadata, and error policy as
    /// [`Self::registered_grpc_web_unary_handler_with_http_decoding`], but pulls
    /// directly from the listener's bounded incoming body. It does not collect
    /// an encoded upload, spawn a driver, or create another body queue. It
    /// retains one bounded decoded request plus the source/codec storage
    /// described by [`ContentDecodeLimits`].
    ///
    /// The explicit request `Cx` controls decoding even when a different task
    /// polls the handler. No service is called and no response producer is
    /// admitted until the HTTP body and all codec checksums/footers reach clean
    /// EOF. Dropping or cancelling the handler drops its incoming-body owner;
    /// the listener remains responsible for its bounded drain-or-close policy.
    /// Response streaming, backpressure, and message compression keep the
    /// semantics of [`Self::registered_grpc_web_streaming_handler`].
    ///
    /// # Errors
    /// Returns the same installation errors as
    /// [`Self::registered_grpc_web_streaming_handler`].
    pub fn registered_grpc_web_streaming_handler_with_http_decoding(
        self: &Arc<Self>,
        wire: GrpcWebConfig,
        streaming: ServerStreamingConfig,
        limits: ContentDecodeLimits,
    ) -> io::Result<
        impl Fn(Cx, StreamingServerRequest) -> GrpcWebStreamingHandlerFuture
        + Clone
        + Send
        + Sync
        + 'static,
    > {
        self.grpc_web_streaming_handler(wire, streaming, Some(limits))
    }

    fn grpc_web_streaming_handler(
        self: &Arc<Self>,
        wire: GrpcWebConfig,
        streaming: ServerStreamingConfig,
        decoding: Option<ContentDecodeLimits>,
    ) -> io::Result<
        impl Fn(Cx, StreamingServerRequest) -> GrpcWebStreamingHandlerFuture
        + Clone
        + Send
        + Sync
        + 'static,
    > {
        self.validate_registered_streaming(streaming)?;
        if wire.max_trailer_bytes < 17 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gRPC-Web streaming trailer limit must be at least 17 bytes",
            ));
        }
        let native_unary = self.registered_unary_handler()?;
        let server = Arc::clone(self);
        Ok(move |cx, request| -> GrpcWebStreamingHandlerFuture {
            let server = Arc::clone(&server);
            let native_unary = native_unary.clone();
            let wire = wire.clone();
            Box::pin(async move {
                let collected = if let Some(limits) = decoding {
                    let StreamingServerRequest {
                        head,
                        peer_addr,
                        body,
                        ..
                    } = request;
                    let request = HttpRequest {
                        method: head.method,
                        uri: head.uri,
                        version: head.version,
                        headers: head.headers,
                        body: Vec::new(),
                        trailers: Vec::new(),
                        peer_addr,
                    };
                    decode_request_body(
                        &cx,
                        request,
                        body,
                        incoming_body_status,
                        &wire,
                        limits,
                        server.config().max_metadata_size,
                    )
                    .await
                } else {
                    collect_streaming_request(&cx, request, &wire).await
                };
                let request = match collected {
                    Ok(request) => request,
                    Err(response) => return produced_buffered(response, streaming),
                };
                let version = request.version;
                let (request, mode) = match prepare_request(request, &wire) {
                    Ok(prepared) => prepared,
                    Err(response) => return produced_buffered(response, streaming),
                };
                if !server.is_registered_server_stream(&request.uri) {
                    // The explicit request context also makes direct handler
                    // invocation obey the same unary authority as a listener.
                    let mut call = std::pin::pin!(native_unary(request));
                    let response = poll_fn(|task| {
                        let _current = Cx::set_current(Some(cx.clone()));
                        call.as_mut().poll(task)
                    })
                    .await;
                    let response = encode_response(response, mode, version, &wire)
                        .unwrap_or_else(|status| error_response(&status, mode, version));
                    return produced_buffered(response, streaming);
                }
                let prepared = match server.prepare_registered_server_stream(request, Some(&cx)) {
                    Ok(prepared) => prepared,
                    Err(status) => {
                        let response = server
                            .advertise_request_compression(error_response(&status, mode, version));
                        return produced_buffered(response, streaming);
                    }
                };
                let mut head = prepared.head();
                let defer_headers = prepared.defer_response_headers();
                strip_transport_headers(&mut head.headers);
                let mut response = Http1ProducedResponse::chunked_with_max_frame_bytes(
                    streaming.frame_capacity,
                    streaming.max_frame_bytes,
                    head.status,
                    head.reason,
                    move |producer_cx, sender| async move {
                        let sender = WebBodySender {
                            sender,
                            mode,
                            max_frame_bytes: streaming.max_frame_bytes.get(),
                            max_message_bytes: wire.max_response_bytes,
                            max_trailer_bytes: wire.max_trailer_bytes,
                        };
                        prepared
                            .run(producer_cx, sender, streaming)
                            .await
                            .map(|sender| sender.sender)
                    },
                )
                .with_header("content-type", mode.as_header_value())
                .with_header("vary", "Accept");
                if defer_headers {
                    response = response.defer_initial_headers();
                }
                for (name, value) in head.headers {
                    response = response.with_header(name, value);
                }
                response
            })
        })
    }
}

async fn collect_streaming_request(
    cx: &Cx,
    request: StreamingServerRequest,
    config: &GrpcWebConfig,
) -> Result<HttpRequest, HttpResponse> {
    let StreamingServerRequest {
        head,
        peer_addr,
        mut body,
        ..
    } = request;
    let mut request = HttpRequest {
        method: head.method,
        uri: head.uri,
        version: head.version,
        headers: head.headers,
        body: Vec::new(),
        trailers: Vec::new(),
        peer_addr,
    };
    let input_mode = request
        .header_value("content-type")
        .and_then(media_type)
        .unwrap_or(ContentType::GrpcWeb);
    let output_mode = negotiate(&request, input_mode).unwrap_or(input_mode);
    let limit = if input_mode.is_text_mode() {
        config.max_request_bytes.saturating_mul(4)
    } else {
        config.max_request_bytes
    };
    let reject = |status| error_response(&status, output_mode, request.version);
    loop {
        let frame = poll_fn(|task| Pin::new(&mut body).poll_frame(task)).await;
        let Some(frame) = frame else {
            break;
        };
        let frame = frame.map_err(|_| {
            let status = if cx.is_cancel_requested() {
                match cx.cancel_reason().map(|reason| reason.kind) {
                    Some(
                        crate::types::CancelKind::Timeout | crate::types::CancelKind::Deadline,
                    ) => Status::deadline_exceeded("gRPC-Web request deadline exceeded"),
                    _ => Status::cancelled("gRPC-Web request cancelled"),
                }
            } else {
                Status::invalid_argument("invalid gRPC-Web request body")
            };
            reject(status)
        })?;
        match frame {
            Frame::Data(data) => {
                if data.remaining() > limit.saturating_sub(request.body.len()) {
                    return Err(reject(Status::resource_exhausted(
                        "gRPC-Web request exceeds wire limit",
                    )));
                }
                request.body.extend_from_slice(data.chunk());
            }
            Frame::Trailers(_) => {
                return Err(reject(Status::invalid_argument(
                    "gRPC-Web unary request trailers are unsupported",
                )));
            }
        }
    }
    Ok(request)
}

fn request_metadata_remaining(
    fields: impl IntoIterator<Item = (usize, usize)>,
    remaining: Option<usize>,
) -> Result<Option<usize>, Status> {
    let Some(mut remaining) = remaining else {
        return Ok(None);
    };
    for (name, value) in fields {
        // Match the native gRPC field allowance, including its per-field
        // overhead, but count original HTTP bytes before decoding erases any.
        remaining = name
            .checked_add(value)
            .and_then(|bytes| bytes.checked_add(32))
            .and_then(|bytes| remaining.checked_sub(bytes))
            .ok_or_else(|| Status::resource_exhausted("gRPC-Web request metadata exceeds limit"))?;
    }
    Ok(Some(remaining))
}

// Reject original HTTP trailers before a content transform can remove their
// fields. The gRPC-Web request contract admits exactly one DATA message, with
// no HTTP or gRPC-Web trailer block, for unary and server-streaming calls.
struct RequestContentSource<B: Body> {
    body: B,
    map_error: fn(B::Error) -> Status,
    metadata_remaining: Option<usize>,
}

impl<B: Body + Unpin> Body for RequestContentSource<B> {
    type Data = B::Data;
    type Error = Status;

    fn poll_frame(
        self: Pin<&mut Self>,
        task: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        Pin::new(&mut this.body).poll_frame(task).map(|frame| {
            frame.map(|frame| match frame {
                Ok(Frame::Data(data)) => Ok(Frame::Data(data)),
                Ok(Frame::Trailers(trailers)) => {
                    request_metadata_remaining(
                        trailers
                            .iter()
                            .map(|(name, value)| (name.as_str().len(), value.as_bytes().len())),
                        this.metadata_remaining,
                    )?;
                    Err(Status::invalid_argument(
                        "gRPC-Web unary request trailers are unsupported",
                    ))
                }
                Err(error) => Err((this.map_error)(error)),
            })
        })
    }
}

fn request_cancellation_status(kind: CancelKind) -> Status {
    match kind {
        CancelKind::Timeout | CancelKind::Deadline => {
            Status::deadline_exceeded("gRPC-Web request decoding deadline exceeded")
        }
        CancelKind::PollQuota | CancelKind::CostBudget => {
            Status::resource_exhausted("gRPC-Web request decoding budget exhausted")
        }
        _ => Status::cancelled("gRPC-Web request decoding cancelled"),
    }
}

fn incoming_body_status(error: IncomingBodyError) -> Status {
    match error {
        IncomingBodyError::Cancelled { kind } => request_cancellation_status(kind),
        IncomingBodyError::BodyTooLarge { .. }
        | IncomingBodyError::QueueFrameTooLarge { .. }
        | IncomingBodyError::TrailersTooLarge
        | IncomingBodyError::AccountingOverflow
        | IncomingBodyError::DrainLimitExceeded { .. } => {
            Status::resource_exhausted("gRPC-Web HTTP request body exceeds limit")
        }
        IncomingBodyError::DrainTimeout => {
            Status::deadline_exceeded("gRPC-Web HTTP request body timed out")
        }
        _ => Status::invalid_argument("invalid gRPC-Web HTTP request body"),
    }
}

fn request_decoding_io_status(error: &io::Error) -> Status {
    if is_limit_error(error) {
        Status::resource_exhausted("gRPC-Web decoded HTTP request exceeds limit")
    } else if error.kind() == io::ErrorKind::Unsupported {
        Status::unimplemented("gRPC-Web HTTP request content codec is unavailable")
    } else {
        Status::invalid_argument("invalid gRPC-Web HTTP request content encoding")
    }
}

fn request_decoding_status(error: ContentDecodeError<Status>) -> Status {
    match error {
        ContentDecodeError::Body(status) => status,
        ContentDecodeError::Decode(error) => request_decoding_io_status(&error),
        ContentDecodeError::EncodedLimit { .. } => {
            Status::resource_exhausted("gRPC-Web encoded HTTP request exceeds limit")
        }
        ContentDecodeError::Cancelled { kind } => request_cancellation_status(kind),
    }
}

async fn decode_request_body<B: Body + Unpin>(
    cx: &Cx,
    mut request: HttpRequest,
    source: B,
    map_error: fn(B::Error) -> Status,
    config: &GrpcWebConfig,
    limits: ContentDecodeLimits,
    metadata_limit: usize,
) -> Result<HttpRequest, HttpResponse> {
    let (input_mode, output_mode) = request_modes(&request)?;
    let version = request.version;
    let reject = |status| error_response(&status, output_mode, version);
    let metadata_remaining = request_metadata_remaining(
        request
            .headers
            .iter()
            .chain(&request.trailers)
            .map(|(name, value)| (name.len(), value.len())),
        (metadata_limit != 0).then_some(metadata_limit),
    )
    .map_err(reject)?;
    if !request.trailers.is_empty() {
        return Err(reject(Status::invalid_argument(
            "gRPC-Web unary request trailers are unsupported",
        )));
    }
    let limit = if input_mode.is_text_mode() {
        config.max_request_bytes.saturating_mul(4)
    } else {
        config.max_request_bytes
    };
    let coding =
        ContentDecoder::from_request_fields(request.headers.iter().filter_map(|(key, value)| {
            key.eq_ignore_ascii_case("content-encoding")
                .then_some(value.as_str())
        }))
        .map_err(|error| reject(request_decoding_io_status(&error)))?;
    let transformed = !coding.is_identity();
    let plan = ContentDecodePlan::new(coding, limits.tightened(limit))
        .map_err(|error| reject(request_decoding_io_status(&error)))?;
    let source = RequestContentSource {
        body: source,
        map_error,
        metadata_remaining,
    };
    let mut decoded = ContentDecodedBody::from_plan(source, plan).with_cx(cx);
    let mut deadline = cx.budget_deadline_sleep();
    while let Some(frame) = poll_fn(|task| {
        // Preserve the explicit owner's budget wake even when another native
        // task drives this handler. Once a masked deadline fires, retire the
        // spent timer; the decoder keeps its cancellation token through unmask.
        if deadline
            .as_mut()
            .is_some_and(|sleep| Pin::new(sleep).poll_deadline(task).is_ready())
        {
            deadline = None;
        }
        Pin::new(&mut decoded).poll_frame(task)
    })
    .await
    {
        match frame.map_err(|error| reject(request_decoding_status(error)))? {
            Frame::Data(data) => request.body.extend_from_slice(data.chunk()),
            Frame::Trailers(_) => {
                return Err(reject(Status::invalid_argument(
                    "gRPC-Web unary request trailers are unsupported",
                )));
            }
        }
    }
    cx.checkpoint().map_err(|_| {
        reject(request_cancellation_status(
            cx.cancel_reason()
                .map_or(CancelKind::User, |reason| reason.kind),
        ))
    })?;
    if transformed {
        request.headers.retain(|(name, _)| !invalidated_field(name));
    }
    Ok(request)
}

fn produced_buffered(
    response: HttpResponse,
    config: ServerStreamingConfig,
) -> Http1ProducedResponse {
    let HttpResponse {
        status,
        reason,
        headers,
        body,
        ..
    } = response;
    let mut produced = Http1ProducedResponse::with_content_length_and_max_frame_bytes(
        config.frame_capacity,
        config.max_frame_bytes,
        status,
        reason,
        u64::try_from(body.len()).unwrap_or(u64::MAX),
        move |cx, mut sender| async move {
            for chunk in body.chunks(config.max_frame_bytes.get()) {
                sender.send_chunk(&cx, chunk).await?;
            }
            sender.finish(&cx)?;
            Ok(sender)
        },
    );
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("content-length") && !hop_by_hop(&name) {
            produced = produced.with_header(name, value);
        }
    }
    produced
}

struct WebBodySender {
    sender: OutgoingBodySender,
    mode: ContentType,
    max_frame_bytes: usize,
    max_message_bytes: usize,
    max_trailer_bytes: usize,
}

impl ServerStreamSink for WebBodySender {
    const REGION_NAME: &'static str = "h1-grpc-web-stream";

    fn initial_headers_pending(&self) -> bool {
        self.sender.initial_headers_pending()
    }

    fn send_initial_headers(&mut self, headers: HeaderMap) -> Result<(), HttpError> {
        self.sender.send_initial_headers(headers)
    }

    fn message_limit(&self) -> Option<usize> {
        Some(self.max_message_bytes)
    }

    async fn send_chunk(&mut self, cx: &Cx, data: &[u8]) -> Result<(), HttpError> {
        if self.mode.is_text_mode() {
            data.len()
                .checked_add(2)
                .and_then(|length| (length / 3).checked_mul(4))
                .ok_or(HttpError::BodyTooLarge)?;
            let encoded = STANDARD.encode(data);
            for chunk in encoded.as_bytes().chunks(self.max_frame_bytes) {
                self.sender.send_chunk(cx, chunk).await?;
            }
        } else {
            for chunk in data.chunks(self.max_frame_bytes) {
                self.sender.send_chunk(cx, chunk).await?;
            }
        }
        Ok(())
    }

    async fn send_trailers(&mut self, cx: &Cx, trailers: HeaderMap) -> Result<(), HttpError> {
        let mut response = HttpResponse::new(200, "OK", Vec::new());
        for (name, value) in trailers.iter() {
            let value = value.to_str().map_err(|_| HttpError::InvalidHeaderValue)?;
            response
                .trailers
                .push((name.as_str().to_owned(), value.to_owned()));
        }
        let block = trailer_block(&response, self.max_trailer_bytes).unwrap_or_else(|status| {
            // Preserve a clean, bounded terminal frame after complete messages.
            // The constructor reserves enough room for every bare status code.
            format!("grpc-status: {}\r\n", status.code().as_i32()).into_bytes()
        });
        let length = u32::try_from(block.len()).map_err(|_| HttpError::BodyTooLarge)?;
        let capacity = block.len().checked_add(5).ok_or(HttpError::BodyTooLarge)?;
        let mut frame = Vec::with_capacity(capacity);
        frame.push(0x80);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&block);
        self.send_chunk(cx, &frame).await?;
        self.sender.finish(cx)
    }
}

fn media_type(value: &str) -> Option<ContentType> {
    let media = value.split(';').next()?.trim();
    if media.eq_ignore_ascii_case("application/grpc-web")
        || media.eq_ignore_ascii_case("application/grpc-web+proto")
    {
        Some(ContentType::GrpcWeb)
    } else if media.eq_ignore_ascii_case("application/grpc-web-text")
        || media.eq_ignore_ascii_case("application/grpc-web-text+proto")
    {
        Some(ContentType::GrpcWebText)
    } else {
        None
    }
}

fn quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => {
            let mut result = 0;
            for (index, byte) in fraction.bytes().enumerate() {
                result += u16::from(byte - b'0') * [100, 10, 1][index];
            }
            Some(result)
        }
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1000),
        _ => None,
    }
}

fn negotiate(request: &HttpRequest, default: ContentType) -> Option<ContentType> {
    // A more specific range overrides a wildcard, including an explicit q=0.
    let mut candidates: [Option<(u8, u16)>; 2] = [None, None];
    let mut has_accept = false;
    for (_, value) in request
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("accept"))
    {
        has_accept = true;
        for range in value.split(',') {
            let mut parts = range.split(';');
            let media = parts.next()?.trim();
            let mut weight = 1000;
            let mut seen_quality = false;
            for parameter in parts {
                let (key, value) = parameter.trim().split_once('=')?;
                if key.trim().eq_ignore_ascii_case("q") {
                    if seen_quality {
                        return None;
                    }
                    seen_quality = true;
                    weight = quality(value.trim())?;
                }
            }
            let matching = match media_type(media) {
                Some(ContentType::GrpcWeb) => [(true, 2), (false, 2)],
                Some(ContentType::GrpcWebText) => [(false, 2), (true, 2)],
                None if media.eq_ignore_ascii_case("application/*") => [(true, 1); 2],
                None if media == "*/*" => [(true, 0); 2],
                None => [(false, 0); 2],
            };
            for (candidate, (matches, specificity)) in candidates.iter_mut().zip(matching) {
                if matches && candidate.is_none_or(|old| (specificity, weight) > old) {
                    *candidate = Some((specificity, weight));
                }
            }
        }
    }
    if !has_accept {
        return Some(default);
    }
    let binary = candidates[0].map_or(0, |(_, weight)| weight);
    let text = candidates[1].map_or(0, |(_, weight)| weight);
    match binary.cmp(&text) {
        std::cmp::Ordering::Greater => Some(ContentType::GrpcWeb),
        std::cmp::Ordering::Less => Some(ContentType::GrpcWebText),
        std::cmp::Ordering::Equal if binary > 0 => Some(default),
        std::cmp::Ordering::Equal => None,
    }
}

fn http_error(status: u16, reason: &str, version: Version) -> HttpResponse {
    let mut response =
        HttpResponse::new(status, reason, Vec::new()).with_header("content-length", "0");
    response.version = version;
    response
}

fn hop_by_hop(key: &str) -> bool {
    [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "te",
        "trailer",
    ]
    .iter()
    .any(|reserved| key.eq_ignore_ascii_case(reserved))
}

fn strip_transport_headers(headers: &mut Vec<(String, String)>) {
    let nominated: Vec<String> = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect();
    headers.retain(|(key, _)| {
        !hop_by_hop(key)
            && !key.eq_ignore_ascii_case("content-type")
            && !key.eq_ignore_ascii_case("content-length")
            && !nominated.iter().any(|name| key.eq_ignore_ascii_case(name))
    });
}

fn decode_text(input: &[u8], limit: usize) -> Result<Vec<u8>, Status> {
    if input.len() > limit.saturating_mul(4) {
        return Err(Status::resource_exhausted(
            "gRPC-Web text request exceeds wire limit",
        ));
    }
    let mut output = Vec::with_capacity(limit.min(input.len() / 4 * 3));
    // Padding ends a base64 chunk, NOT the RPC. gRPC-Web permits independently
    // padded chunks even when a boundary falls inside a message frame.
    for quartet in input.chunks(4) {
        let engine = if quartet.len() == 4 {
            &STANDARD
        } else {
            &STANDARD_NO_PAD
        };
        let mut decoded = [0_u8; 3];
        let count = engine
            .decode_slice(quartet, &mut decoded)
            .map_err(|_| Status::invalid_argument("invalid gRPC-Web base64 request"))?;
        if count > limit.saturating_sub(output.len()) {
            return Err(Status::resource_exhausted(
                "gRPC-Web request exceeds wire limit",
            ));
        }
        output.extend_from_slice(&decoded[..count]);
    }
    Ok(output)
}

fn request_modes(request: &HttpRequest) -> Result<(ContentType, ContentType), HttpResponse> {
    let version = request.version;
    if request.method != Method::Post {
        return Err(http_error(405, "Method Not Allowed", version).with_header("allow", "POST"));
    }
    let mut content_types = request
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("content-type"));
    let Some((_, content_type)) = content_types.next() else {
        return Err(http_error(415, "Unsupported Media Type", version));
    };
    if content_types.next().is_some() {
        return Err(http_error(400, "Bad Request", version));
    }
    let Some(input_mode) = media_type(content_type) else {
        return Err(http_error(415, "Unsupported Media Type", version));
    };
    let Some(output_mode) = negotiate(request, input_mode) else {
        return Err(http_error(406, "Not Acceptable", version));
    };
    Ok((input_mode, output_mode))
}

fn prepare_request(
    mut request: HttpRequest,
    config: &GrpcWebConfig,
) -> Result<(HttpRequest, ContentType), HttpResponse> {
    let version = request.version;
    let (input_mode, output_mode) = request_modes(&request)?;
    let reject = |status| error_response(&status, output_mode, version);
    if !request.trailers.is_empty() {
        return Err(reject(Status::invalid_argument(
            "gRPC-Web unary request trailers are unsupported",
        )));
    }
    if input_mode.is_text_mode() {
        request.body = decode_text(&request.body, config.max_request_bytes).map_err(reject)?;
    } else if request.body.len() > config.max_request_bytes {
        return Err(reject(Status::resource_exhausted(
            "gRPC-Web request exceeds wire limit",
        )));
    }
    // Do not upgrade gRPC-Web trailer frames or multi-message uploads into a
    // native unary call. This also bounds framing before user code is invoked.
    if request.body.len() < 5 || request.body[0] > 1 {
        return Err(reject(Status::invalid_argument(
            "invalid gRPC-Web unary data frame",
        )));
    }
    let length = u32::from_be_bytes([
        request.body[1],
        request.body[2],
        request.body[3],
        request.body[4],
    ]);
    if usize::try_from(length).ok() != Some(request.body.len() - 5) {
        return Err(reject(Status::invalid_argument(
            "gRPC-Web unary requires exactly one complete message",
        )));
    }
    strip_transport_headers(&mut request.headers);
    request.headers.push((
        "content-type".to_owned(),
        "application/grpc+proto".to_owned(),
    ));
    request
        .headers
        .push(("content-length".to_owned(), request.body.len().to_string()));
    request
        .headers
        .push(("te".to_owned(), "trailers".to_owned()));
    // Internal representation only: the public native handler still rejects
    // non-H2 requests, and the outgoing response restores the actual version.
    request.version = Version::Http2;
    Ok((request, output_mode))
}

fn status_header(key: &str) -> bool {
    ["grpc-status", "grpc-message", "grpc-status-details-bin"]
        .iter()
        .any(|reserved| key.eq_ignore_ascii_case(reserved))
}

fn trailer_block(response: &HttpResponse, limit: usize) -> Result<Vec<u8>, Status> {
    let mut block = Vec::new();
    let mut seen_status = false;
    let mut seen_message = false;
    let mut seen_details = false;
    for (key, value) in response
        .headers
        .iter()
        .filter(|(key, _)| status_header(key))
        .chain(response.trailers.iter())
    {
        let key = key.to_ascii_lowercase();
        if key.is_empty()
            || !key.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            })
            || hop_by_hop(&key)
            || key == "content-length"
            || key == "content-type"
            || !value
                .bytes()
                .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
        {
            return Err(Status::internal("invalid gRPC-Web response trailer"));
        }
        let seen = match key.as_str() {
            "grpc-status" => {
                if value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || !matches!(value.parse::<u8>(), Ok(0..=16))
                {
                    return Err(Status::internal("invalid gRPC-Web response status"));
                }
                Some(&mut seen_status)
            }
            "grpc-message" => Some(&mut seen_message),
            "grpc-status-details-bin" => Some(&mut seen_details),
            _ => None,
        };
        if let Some(seen) = seen {
            if *seen {
                return Err(Status::internal(
                    "duplicate gRPC-Web response status metadata",
                ));
            }
            *seen = true;
        }
        let required = block
            .len()
            .checked_add(key.len())
            .and_then(|length| length.checked_add(value.len()))
            .and_then(|length| length.checked_add(4));
        if required.is_none_or(|length| length > limit || u32::try_from(length).is_err()) {
            return Err(Status::resource_exhausted(
                "gRPC-Web response trailers exceed wire limit",
            ));
        }
        block.extend_from_slice(key.as_bytes());
        block.extend_from_slice(b": ");
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(b"\r\n");
    }
    if !seen_status {
        return Err(Status::internal("missing gRPC-Web response status"));
    }
    Ok(block)
}

fn encode_response(
    mut response: HttpResponse,
    mode: ContentType,
    version: Version,
    config: &GrpcWebConfig,
) -> Result<HttpResponse, Status> {
    if response.status != 200 {
        return Err(Status::internal(
            "native gRPC dispatcher returned a non-gRPC response",
        ));
    }
    if response.body.len() > config.max_response_bytes {
        return Err(Status::resource_exhausted(
            "gRPC-Web response exceeds wire limit",
        ));
    }
    let trailers = trailer_block(&response, config.max_trailer_bytes)?;
    let length = u32::try_from(trailers.len())
        .map_err(|_| Status::resource_exhausted("gRPC-Web trailers exceed framing limit"))?;
    response.body.push(0x80);
    response.body.extend_from_slice(&length.to_be_bytes());
    response.body.extend_from_slice(&trailers);
    response.trailers.clear();
    strip_transport_headers(&mut response.headers);
    response.headers.retain(|(key, _)| !status_header(key));
    finish_response(response, mode, version)
}

fn finish_response(
    mut response: HttpResponse,
    mode: ContentType,
    version: Version,
) -> Result<HttpResponse, Status> {
    if mode.is_text_mode() {
        // Check the expansion before base64's capacity calculation can overflow.
        response
            .body
            .len()
            .checked_add(2)
            .and_then(|length| (length / 3).checked_mul(4))
            .ok_or_else(|| {
                Status::resource_exhausted("gRPC-Web text response exceeds framing limit")
            })?;
        response.body = base64_encode(&response.body).into_bytes();
    }
    response.version = version;
    response
        .headers
        .push(("content-type".to_owned(), mode.as_header_value().to_owned()));
    response
        .headers
        .push(("content-length".to_owned(), response.body.len().to_string()));
    response
        .headers
        .push(("vary".to_owned(), "Accept".to_owned()));
    Ok(response)
}

fn error_response(status: &Status, mode: ContentType, version: Version) -> HttpResponse {
    let mut body = BytesMut::new();
    encode_trailers(status, &Metadata::new(), &mut body);
    // Transport-owned errors have bounded constant messages and no metadata.
    // Their size cannot overflow the text encoder's checked arithmetic.
    finish_response(HttpResponse::new(200, "OK", body.to_vec()), mode, version)
        .unwrap_or_else(|_| http_error(500, "Internal Server Error", version))
}

#[cfg(test)]
#[path = "web_handler_tests.rs"]
mod tests;
