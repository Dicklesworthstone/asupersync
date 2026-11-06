//! Explicit live request decoding while preserving the raw request contract.

use super::{ExtractionError, FromRequest, Request, StreamingRawBody, parse_content_length};
use crate::Cx;
use crate::bytes::BytesCursor;
use crate::http::body::{Body, ContentDecodeError, ContentDecodeLimits, ContentDecodedBody, Frame, SizeHint};
use crate::http::decode::{ContentDecodePlan, is_limit_error};
use crate::http::h1::stream::IncomingBodyError;
use crate::web::middleware::{RequestContentCodings, request_content_decoder};
use crate::web::response::StatusCode;
use parking_lot::Mutex;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Extract a live request body with explicit, bounded content decoding.
///
/// Configure [`crate::web::middleware::StreamingRequestDecompressionLayer`]
/// and use this extractor in an async handler, or call
/// [`Self::from_request_with_limits`] with a context and limits directly.
/// There is no default decoding policy. The extractor requires a live body;
/// buffered routes use the separate request decompression middleware.
///
/// Original request headers keep their **encoded** meaning. Other extractors
/// can still inspect Content-Encoding, wire Content-Length, and signatures;
/// this body yields decoded bytes, and its size hint never claims that the
/// encoded Content-Length is the decoded length. A raw streaming extractor
/// continues to see the unchanged wire stream if selected instead.
///
/// Codings are decoded in reverse order, including repeated wire fields.
/// Encoded partial representations and unavailable codecs are rejected before
/// the single body slot is taken. Limits meet the router's protected policy.
/// Dropping this body releases the original consumer and retains the driver's
/// existing bounded drain-or-close behavior; no decoder task is spawned.
///
/// Decoded data is provisional until successful EOF. Trailers are exposed
/// only after every stage and the source finish successfully, with stale
/// encoded payload metadata removed. A later checksum/truncation/source error
/// invalidates completion even after earlier data was delivered.
///
/// Async extraction retains the explicitly supplied handler context and
/// observes its cancellation even when decoded output is already buffered.
/// Synchronous [`FromRequest::from_request`] requires an installed current
/// context; use the explicit context form when no ambient context is present.
#[derive(Debug)]
pub struct DecodedStreamingBody {
    // Existing function handlers require Sync extractors. Codec traits are
    // Send-only, so use a narrow Mutex without changing their public bounds.
    // Polling has exclusive access and uses get_mut, taking no lock.
    inner: Mutex<ContentDecodedBody<StreamingRawBody>>,
}

impl DecodedStreamingBody {
    /// Extract with a mandatory context and limits, without a configuration layer.
    pub fn from_request_with_limits(
        cx: &Cx,
        mut request: Request,
        limits: ContentDecodeLimits,
    ) -> Result<Self, ExtractionError> {
        if cx.checkpoint().is_err() {
            return Err(ExtractionError::new(StatusCode::CLIENT_CLOSED_REQUEST, "request cancelled"));
        }
        let limits = limits.tightened(request.body_policy().map_or(usize::MAX, |policy| policy.max_total_body_size));
        let decoder = request_content_decoder(&request).map_err(decoding_extraction_error)?;
        let identity = decoder.is_identity();
        if !identity && request.header("content-range").is_some() {
            return Err(ExtractionError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "encoded partial request bodies are unsupported"));
        }

        let mut length = None;
        for (_, value) in request.headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("content-length")) {
            let declared = parse_content_length(value).map_err(|_| {
                ExtractionError::new(StatusCode::BAD_REQUEST, "invalid encoded request content length")
            })?;
            if length.replace(declared).is_some_and(|previous| previous != declared) {
                return Err(ExtractionError::new(StatusCode::BAD_REQUEST, "conflicting encoded request content length"));
            }
            if declared > limits.max_encoded_bytes() || (identity && declared > limits.max_decoded_bytes()) {
                return Err(ExtractionError::new(StatusCode::PAYLOAD_TOO_LARGE, "request body exceeds content decoding limits"));
            }
        }

        // Parsing and feature preflight precede taking the one live consumer.
        let plan = ContentDecodePlan::new(decoder, limits).map_err(decoding_extraction_error)?;
        request.extensions.remove_typed::<RequestContentCodings>();
        let raw = StreamingRawBody::take_from_request(&request)?;
        raw.inner.tighten_max_body_size(u64::try_from(limits.max_encoded_bytes()).unwrap_or(u64::MAX));
        Ok(Self { inner: Mutex::new(ContentDecodedBody::from_plan(raw, plan).with_cx(cx)) })
    }

    /// Return the effective encoded and per-stage decoded ceilings.
    #[must_use]
    pub fn limits(&self) -> ContentDecodeLimits {
        self.inner.lock().limits()
    }

    /// Consume the extractor wrapper for use with generic HTTP body combinators.
    #[must_use]
    pub fn into_body(self) -> ContentDecodedBody<StreamingRawBody> {
        self.inner.into_inner()
    }

    fn configured_limits(request: &Request) -> Result<ContentDecodeLimits, ExtractionError> {
        request.extensions.get_typed::<ContentDecodeLimits>().copied().ok_or_else(|| {
            ExtractionError::new(StatusCode::INTERNAL_SERVER_ERROR, "decoded streaming body requires explicit content decoding limits")
        })
    }
}

impl FromRequest for DecodedStreamingBody {
    fn from_request(request: Request) -> Result<Self, ExtractionError> {
        let limits = Self::configured_limits(&request)?;
        let cx = Cx::current().ok_or_else(|| {
            ExtractionError::new(StatusCode::INTERNAL_SERVER_ERROR, "decoded streaming body requires an explicit or current context")
        })?;
        Self::from_request_with_limits(&cx, request, limits)
    }

    fn from_request_with_cx<'a>(
        cx: &'a Cx,
        request: Request,
    ) -> impl std::future::Future<Output = Result<Self, ExtractionError>> + Send + 'a {
        std::future::ready(Self::configured_limits(&request)
            .and_then(|limits| Self::from_request_with_limits(cx, request, limits)))
    }
}

impl Body for DecodedStreamingBody {
    type Data = BytesCursor;
    type Error = ContentDecodeError<IncomingBodyError>;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(self.get_mut().inner.get_mut()).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.lock().is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.lock().size_hint()
    }
}

fn decoding_extraction_error(error: io::Error) -> ExtractionError {
    if is_limit_error(&error) {
        ExtractionError::new(StatusCode::PAYLOAD_TOO_LARGE, "decoded request body exceeds resource limit")
    } else if error.kind() == io::ErrorKind::Unsupported {
        ExtractionError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported request content encoding")
    } else {
        ExtractionError::new(StatusCode::BAD_REQUEST, "malformed request content encoding")
    }
}
