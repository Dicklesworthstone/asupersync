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

use crate::bytes::{Buf, BytesMut};
use crate::cx::Cx;
use crate::http::body::{Body, Frame, HeaderMap};
use crate::http::h1::types::{Method, Request as HttpRequest, Response as HttpResponse, Version};
use crate::http::h1::{Http1ProducedResponse, HttpError, OutgoingBodySender, StreamingServerRequest};

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
    ) -> io::Result<impl Fn(HttpRequest) -> GrpcWebHandlerFuture + Clone + Send + Sync + 'static> {
        let native = self.registered_unary_handler()?;
        Ok(move |request: HttpRequest| -> GrpcWebHandlerFuture {
            let native = native.clone();
            let config = config.clone();
            Box::pin(async move {
                let version = request.version;
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
                let request = match collect_streaming_request(&cx, request, &wire).await {
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
                        return produced_buffered(error_response(&status, mode, version), streaming);
                    }
                };
                let mut head = prepared.head();
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
    let StreamingServerRequest { head, peer_addr, mut body } = request;
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
                    Some(crate::types::CancelKind::Timeout | crate::types::CancelKind::Deadline) => {
                        Status::deadline_exceeded("gRPC-Web request deadline exceeded")
                    }
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

fn produced_buffered(
    response: HttpResponse,
    config: ServerStreamingConfig,
) -> Http1ProducedResponse {
    let HttpResponse { status, reason, headers, body, .. } = response;
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
            response.trailers.push((name.as_str().to_owned(), value.to_owned()));
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

fn prepare_request(
    mut request: HttpRequest,
    config: &GrpcWebConfig,
) -> Result<(HttpRequest, ContentType), HttpResponse> {
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
    let Some(output_mode) = negotiate(&request, input_mode) else {
        return Err(http_error(406, "Not Acceptable", version));
    };
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
    response.headers.push((
        "content-type".to_owned(),
        mode.as_header_value().to_owned(),
    ));
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
