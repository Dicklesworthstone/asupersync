//! Opt-in request decoding over the shared bounded HTTP content decoder.

use super::{Cx, Handler, Layer, Request, Response, StatusCode};
use crate::bytes::Bytes;
use crate::http::compress::DecompressionLimit;
use crate::http::decode::{ContentDecoder, invalidated_field, is_limit_error};
use std::future::Future;
use std::io;
use std::pin::Pin;

/// Ordered wire fields retained only when Content-Encoding was repeated.
/// Keeping a shared body snapshot permits an O(1) identity check: an earlier
/// middleware's replacement body cannot inherit stale wire codings, even if
/// its allocation has the same size. Bytes are immutable and never copied.
#[derive(Debug)]
pub struct RequestContentCodings {
    fields: Vec<String>,
    body: Bytes,
}

impl RequestContentCodings {
    pub(crate) fn new(fields: Vec<String>, body: Bytes) -> Self {
        Self { fields, body }
    }

    fn unchanged(&self, request: &Request, current: &str) -> bool {
        self.fields.last().is_some_and(|last| last == current)
            && self.body.len() == request.body.len()
            && std::ptr::eq(self.body.as_ptr(), request.body.as_ptr())
    }
}

/// Resolve the public header projection and any still-authoritative repeated
/// wire fields once, for buffered middleware and explicit streaming extraction.
pub fn request_content_decoder(request: &Request) -> io::Result<ContentDecoder> {
    let mut fields = request.headers.iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"));
    let current = fields.next().map(|(_, value)| value.as_str());
    if fields.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ambiguous request content encoding order"));
    }
    match (current, request.extensions.get_typed::<RequestContentCodings>()) {
        (Some(current), Some(original)) if original.unchanged(request, current) => {
            ContentDecoder::from_request_fields(original.fields.iter().map(String::as_str))
        }
        _ => ContentDecoder::from_request_fields(current),
    }
}

/// Configure explicitly decoded live uploads for [`crate::web::DecodedStreamingBody`].
///
/// This layer only installs limits. It leaves the encoded headers and raw
/// body untouched, so a [`crate::web::StreamingRawBody`] extractor still sees
/// the original wire bytes. The dedicated decoded extractor parses coding
/// fields, checks availability, and takes the single body consumer. Its
/// effective encoded and decoded limits also meet the router's body policy.
/// No decoding is enabled merely by installing this configuration.
///
/// Use this on streaming routes in place of [`RequestDecompressionLayer`],
/// whose existing buffered-body contract continues to reject encoded streams.
/// Decoded bytes are provisional until successful EOF; the handler must
/// observe all terminal errors before committing upload side effects.
///
/// # Example
///
/// ```no_run
/// use asupersync::bytes::Buf;
/// use asupersync::http::body::{Body, ContentDecodeError, ContentDecodeLimits};
/// use asupersync::http::h1::stream::IncomingBodyError;
/// use asupersync::web::{AsyncCxFnHandler1, DecodedStreamingBody, Response, Router, StatusCode, post};
/// use asupersync::web::middleware::StreamingRequestDecompressionLayer;
/// use std::future::poll_fn;
/// use std::pin::Pin;
///
/// let upload = AsyncCxFnHandler1::new(|_cx, mut body: DecodedStreamingBody| async move {
///     let mut total = 0;
///     while let Some(frame) = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
///         match frame {
///             Ok(frame) => if let Some(data) = frame.data_ref() { total += data.remaining(); },
///             Err(error) => return Response::new(
///                 if error.is_limit_exceeded() || matches!(error,
///                     ContentDecodeError::Body(IncomingBodyError::BodyTooLarge { .. }
///                         | IncomingBodyError::QueueFrameTooLarge { .. }))
///                 { StatusCode::PAYLOAD_TOO_LARGE } else { StatusCode::BAD_REQUEST },
///                 "upload rejected",
///             ),
///         }
///     }
///     Response::new(StatusCode::OK, format!("accepted {total} decoded bytes"))
/// });
/// let app = Router::new().route("/upload", post(upload))
///     .layer(StreamingRequestDecompressionLayer::new(ContentDecodeLimits::new(1024 * 1024, 4 * 1024 * 1024)));
/// # let _ = app;
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy)]
pub struct StreamingRequestDecompressionLayer {
    limits: crate::http::body::ContentDecodeLimits,
}

#[cfg(not(target_arch = "wasm32"))]
impl StreamingRequestDecompressionLayer {
    /// Install mandatory input/output bounds without transforming the request.
    #[must_use]
    pub const fn new(limits: crate::http::body::ContentDecodeLimits) -> Self {
        Self { limits }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<H: Handler> Layer<H> for StreamingRequestDecompressionLayer {
    type Service = StreamingRequestDecompressionMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        StreamingRequestDecompressionMiddleware { inner, limits: self.limits }
    }
}

/// Handler adapter installing [`StreamingRequestDecompressionLayer`] limits.
#[cfg(not(target_arch = "wasm32"))]
pub struct StreamingRequestDecompressionMiddleware<H> {
    inner: H,
    limits: crate::http::body::ContentDecodeLimits,
}

#[cfg(not(target_arch = "wasm32"))]
impl<H: Handler> Handler for StreamingRequestDecompressionMiddleware<H> {
    fn call(&self, cx: &Cx, mut request: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        request.extensions.insert_typed(self.limits);
        self.inner.call(cx, request)
    }
}

/// Decode bounded, buffered request bodies before invoking a handler.
///
/// The encoded body must fit `max_encoded_bytes`; every decoded stage and
/// final body must fit `max_decoded_bytes`. Both limits also meet the router's
/// effective total-body policy. At most eight content codings are accepted,
/// decoded in reverse order, including repeated wire Content-Encoding fields.
/// Gzip, deflate, and Brotli require `compression`; zstd requires `zstd` and
/// retains its 8 MiB window limit. No decoding is enabled by default.
///
/// Unsupported codings or encoded streaming/partial requests return 415;
/// malformed or truncated input returns 400; size/window refusals return 413.
/// The handler is never called on rejection. Streaming bodies with identity
/// encoding remain live and have their byte limit tightened without being
/// consumed. Encoded streaming bodies are rejected before extraction.
///
/// On successful decoding, Content-Encoding, original framing, and payload
/// digest fields are removed, and Content-Length becomes the decoded length.
/// Authentication or signatures over the encoded representation must run
/// outside this layer. Duplicate wire fields are used only while the current
/// header and body still match their original projection; replacing either
/// makes the current header authoritative. Manually constructed requests with
/// multiple differently-cased Content-Encoding keys are rejected because a
/// HashMap cannot express their application order.
///
/// # Example
///
/// ```
/// use asupersync::web::{FnHandler, Router, post};
/// use asupersync::web::middleware::RequestDecompressionLayer;
///
/// let app = Router::new()
///     .route("/upload", post(FnHandler::new(|| "accepted")))
///     .layer(RequestDecompressionLayer::new(1024 * 1024, 4 * 1024 * 1024));
/// # let _ = app;
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RequestDecompressionLayer {
    max_encoded_bytes: usize,
    max_decoded_bytes: usize,
}

impl RequestDecompressionLayer {
    /// Set independent encoded-input and per-stage decoded-output ceilings.
    /// A zero-byte limit is valid; neither bound can be disabled.
    #[must_use]
    pub const fn new(max_encoded_bytes: usize, max_decoded_bytes: usize) -> Self {
        Self { max_encoded_bytes, max_decoded_bytes }
    }
}

impl<H: Handler> Layer<H> for RequestDecompressionLayer {
    type Service = RequestDecompressionMiddleware<H>;

    fn layer(&self, inner: H) -> Self::Service {
        RequestDecompressionMiddleware { inner, limits: *self }
    }
}

/// Handler adapter for [`RequestDecompressionLayer`].
pub struct RequestDecompressionMiddleware<H> {
    inner: H,
    limits: RequestDecompressionLayer,
}

impl<H: Handler> RequestDecompressionMiddleware<H> {
    /// Wrap a handler with explicit encoded and decoded request-body limits.
    #[must_use]
    pub const fn new(inner: H, max_encoded_bytes: usize, max_decoded_bytes: usize) -> Self {
        Self { inner, limits: RequestDecompressionLayer::new(max_encoded_bytes, max_decoded_bytes) }
    }
}

impl<H: Handler> Handler for RequestDecompressionMiddleware<H> {
    fn call(&self, cx: &Cx, mut request: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            if cx.checkpoint().is_err() {
                return refused(StatusCode::CLIENT_CLOSED_REQUEST, "request cancelled");
            }
            if let Err(response) = decode_request(&mut request, self.limits) {
                return response;
            }
            if cx.checkpoint().is_err() {
                return refused(StatusCode::CLIENT_CLOSED_REQUEST, "request cancelled");
            }
            self.inner.call(&cx, request).await
        })
    }
}

fn decode_request(request: &mut Request, limits: RequestDecompressionLayer) -> Result<(), Response> {
    let policy_limit = request.body_policy().map_or(usize::MAX, |policy| policy.max_total_body_size);
    let encoded_limit = limits.max_encoded_bytes.min(policy_limit);
    let decoded_limit = limits.max_decoded_bytes.min(policy_limit);
    if request.body.len() > encoded_limit {
        return Err(refused(StatusCode::PAYLOAD_TOO_LARGE, "encoded request body exceeds limit"));
    }
    // Apply the wire bound to every spelling, not only a HashMap's first hit.
    let mut content_length = None;
    for (_, value) in request.headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("content-length")) {
        let declared = crate::web::extract::parse_content_length(value)
            .map_err(|_| refused(StatusCode::BAD_REQUEST, "invalid request content length"))?;
        if content_length.replace(declared).is_some_and(|previous| previous != declared) {
            return Err(refused(StatusCode::BAD_REQUEST, "conflicting request content length"));
        }
        if declared > encoded_limit {
            return Err(refused(StatusCode::PAYLOAD_TOO_LARGE, "encoded request body exceeds limit"));
        }
    }
    let decoder = request_content_decoder(request).map_err(decode_refusal)?;
    // The decoder owns the resolved coding sequence. Release the original
    // encoded allocation now, including when prior middleware replaced it.
    request.extensions.remove_typed::<RequestContentCodings>();

    if decoder.is_identity() && content_length.is_some_and(|length| length > decoded_limit) {
        return Err(refused(StatusCode::PAYLOAD_TOO_LARGE, "decoded request body exceeds resource limit"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    if request.extensions.get_typed::<crate::web::extract::StreamingRawBodySlot>().is_some() {
        if !decoder.is_identity() {
            return Err(refused(StatusCode::UNSUPPORTED_MEDIA_TYPE, "encoded streaming request bodies are unsupported")
                .header("accept-encoding", "identity"));
        }
        crate::web::extract::tighten_streaming_raw_body(request, encoded_limit.min(decoded_limit));
        return Ok(());
    }

    if !decoder.is_identity() && request.header("content-range").is_some() {
        return Err(refused(StatusCode::UNSUPPORTED_MEDIA_TYPE, "encoded partial request bodies are unsupported"));
    }
    let decoded = decoder.decode(&request.body, DecompressionLimit::new(decoded_limit))
        .map_err(decode_refusal)?;
    if decoder.is_identity() {
        return Ok(());
    }
    let body = decoded.into_owned();
    request.headers.retain(|name, _| {
        !invalidated_field(name)
            && !name.eq_ignore_ascii_case("transfer-encoding")
            && !name.eq_ignore_ascii_case("trailer")
    });
    request.headers.insert("content-length".to_owned(), body.len().to_string());
    request.body = body.into();
    Ok(())
}

fn decode_refusal(error: io::Error) -> Response {
    if is_limit_error(&error) {
        refused(StatusCode::PAYLOAD_TOO_LARGE, "decoded request body exceeds resource limit")
    } else if error.kind() == io::ErrorKind::Unsupported {
        let mut supported = Vec::new();
        if cfg!(feature = "compression") {
            supported.extend(["gzip", "deflate", "br"]);
        }
        if cfg!(feature = "zstd") {
            supported.push("zstd");
        }
        supported.push("identity");
        refused(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported request content encoding")
            .header("accept-encoding", supported.join(", "))
    } else {
        refused(StatusCode::BAD_REQUEST, "malformed encoded request body")
    }
}

fn refused(status: StatusCode, message: &'static str) -> Response {
    Response::new(status, message.as_bytes().to_vec())
}
