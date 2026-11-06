//! Explicit streaming response negotiation, independent of buffered middleware.

use super::{
    RequestCompressionSensitivity, append_vary_token, compression_oracle_sensitive,
    content_coding_available, is_partial_content, weaken_etag,
};
use crate::http::body::{Body, ContentEncodeLimits, ContentEncodedBody};
use crate::http::compress::{ContentCoding, negotiate_coding};
use crate::web::extract::{ExtractionError, FromRequestParts, Request, parse_content_length};
use crate::web::{Response, StatusCode};

/// Explicit limits and representation policy for a produced response.
///
/// Known-small bodies use identity when acceptable; unknown lengths begin
/// compression without buffering to discover their size. Once headers are
/// published, a codec/source/limit failure aborts the response: it cannot fall
/// back to identity or replace the status after sending encoded bytes.
#[derive(Debug, Clone)]
pub struct StreamingCompressionConfig {
    limits: ContentEncodeLimits,
    supported: Vec<ContentCoding>,
    min_body_size: usize,
    compress_sensitive: bool,
}

impl StreamingCompressionConfig {
    /// Require explicit source and encoded limits, with the buffered policy's
    /// Brotli/gzip/deflate/identity preference and 256-byte known-size threshold.
    #[must_use]
    pub fn new(limits: ContentEncodeLimits) -> Self {
        Self {
            limits,
            supported: vec![ContentCoding::Brotli, ContentCoding::Gzip, ContentCoding::Deflate, ContentCoding::Identity],
            min_body_size: 256,
            compress_sensitive: false,
        }
    }

    /// Set server preference order. Unavailable codecs are excluded before
    /// negotiation; an empty set cannot satisfy an ordinary body response.
    #[must_use]
    pub fn with_codings(mut self, supported: Vec<ContentCoding>) -> Self {
        self.supported = supported;
        self
    }

    /// Skip known-small bodies when identity is acceptable, without prebuffering.
    #[must_use]
    pub const fn with_min_body_size(mut self, bytes: usize) -> Self {
        self.min_body_size = bytes;
        self
    }

    /// Explicitly allow credentialed, cookie-setting, or private responses.
    /// Enable only when bodies do not mix secrets and attacker-controlled input.
    #[must_use]
    pub const fn allow_sensitive_response_compression(mut self) -> Self {
        self.compress_sensitive = true;
        self
    }

    /// The source, encoded, and frame ceilings supplied at construction.
    #[must_use]
    pub const fn limits(&self) -> ContentEncodeLimits { self.limits }
}

/// Request-parts extractor preparing explicitly compressed streaming responses.
///
/// This additive surface leaves both buffered compression middlewares and
/// existing callback-based produced responders unchanged. It only transforms
/// the body passed to [`Self::encode_response`]. The head must have an empty
/// buffered body; supply representation headers before preparing it.
///
/// HEAD, bodyless status codes, successful CONNECT, partial/range responses,
/// `no-transform`, already encoded content, and known-empty bodies are not
/// transformed. Credentialed/private responses retain the existing sensitivity
/// guard. Already compressed media, event streams, multipart ranges, and gRPC
/// message streams use identity; their specialized protocols own compression.
/// If a body must remain identity but the client excludes it, preparation
/// returns 406 without polling the source. Existing encoded representations
/// retain their authoritative Content-Encoding unchanged.
///
/// Compression removes source Content-Length and payload digest headers,
/// weakens ETag, and updates Vary. The produced transport owns HTTP framing.
/// Identity keeps authored Content-Length: the H1 Body bridge adopts and
/// enforces it, while H2 retains its existing produced-head framing policy.
///
/// ```no_run
/// use asupersync::bytes::Bytes;
/// use asupersync::http::body::ContentEncodeLimits;
/// use asupersync::web::{
///     Http1StreamResponder, Response, StatusCode,
///     StreamingCompression, StreamingCompressionConfig,
/// };
/// use std::num::NonZeroUsize;
///
/// fn response(responder: Http1StreamResponder, compression: StreamingCompression) -> Response {
///     let head = Response::empty(StatusCode::OK).header("content-type", "text/plain");
///     let config = StreamingCompressionConfig::new(ContentEncodeLimits::new(1 << 20, 1 << 20));
///     let (head, body) = match compression.encode_response(head, Bytes::from_static(b"hello"), config) {
///         Ok(prepared) => prepared,
///         Err(response) => return response,
///     };
///     responder.body(head, NonZeroUsize::new(2).unwrap(), NonZeroUsize::new(16 * 1024).unwrap(), body)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct StreamingCompression {
    method: String,
    accept_encoding: Option<String>,
    range: bool,
    no_transform: bool,
    sensitivity: RequestCompressionSensitivity,
}

impl FromRequestParts for StreamingCompression {
    fn from_request_parts(request: &Request) -> Result<Self, ExtractionError> {
        Ok(Self {
            method: request.method.clone(),
            accept_encoding: request.header("accept-encoding").map(str::to_owned),
            range: request.header("range").is_some(),
            no_transform: request.header("cache-control").is_some_and(no_transform),
            sensitivity: RequestCompressionSensitivity::from_request(request),
        })
    }
}

impl StreamingCompression {
    /// Prepare encoded headers and a bounded source adapter without polling it.
    ///
    /// Add all representation/security headers before this call. Later
    /// middleware must not replace its encoding/framing or change eligibility
    /// without also replacing the prepared body. Source errors after dispatch
    /// remain terminal producer failures, not new HTTP error responses.
    pub fn encode_response<B: Body>(
        &self,
        mut head: Response,
        source: B,
        config: StreamingCompressionConfig,
    ) -> Result<(Response, ContentEncodedBody<B>), Response> {
        if !head.body.is_empty() || head.has_header("transfer-encoding") {
            return Err(refusal(StatusCode::INTERNAL_SERVER_ERROR, "streamed response requires a body-free head without transfer framing"));
        }
        let length = declared_length(&head)?;
        let exact = source.size_hint().exact();
        let bodyless = self.method == "HEAD"
            || (self.method == "CONNECT" && (200..300).contains(&head.status.as_u16()))
            || matches!(head.status.as_u16(), 100..=199 | 204 | 205 | 304);
        if !bodyless
            && let (Some(length), Some(exact)) = (length, exact)
            && length != exact
        {
            return Err(refusal(StatusCode::INTERNAL_SERVER_ERROR, "streamed source size conflicts with Content-Length"));
        }
        let known = length.or(exact);
        if !bodyless && source.size_hint().lower() > u64::try_from(config.limits.max_source_bytes()).unwrap_or(u64::MAX) {
            return Err(refusal(StatusCode::INTERNAL_SERVER_ERROR, "streamed source exceeds configured response limit"));
        }
        let already_encoded = head.has_header("content-encoding");
        let identity = negotiate_coding(self.accept_encoding.as_deref(), &[ContentCoding::Identity]).is_some();
        let sensitive = !config.compress_sensitive && compression_oracle_sensitive(self.sensitivity, &head);
        let must_preserve = self.range || self.no_transform || is_partial_content(&head)
            || head.header_value("cache-control").is_some_and(no_transform)
            || head.header_value("content-type").is_some_and(specialized_content_type)
            || sensitive;

        let coding = if bodyless || known == Some(0) || already_encoded {
            ContentCoding::Identity
        } else if must_preserve {
            if !identity { return Err(refusal(StatusCode::from_u16(406), "No acceptable response encoding")); }
            vary(&mut head);
            if sensitive && !wildcard_vary(&head) { self.sensitivity.append_vary_tokens(&mut head); }
            ContentCoding::Identity
        } else {
            let below_minimum = known.is_some_and(|size| size < config.min_body_size as u64);
            let coding = if below_minimum && identity {
                ContentCoding::Identity
            } else {
                let available = config.supported.iter().copied()
                    .filter(|coding| content_coding_available(*coding)).collect::<Vec<_>>();
                negotiate_coding(self.accept_encoding.as_deref(), &available)
                    .ok_or_else(|| refusal(StatusCode::from_u16(406), "No acceptable response encoding"))?
            };
            vary(&mut head);
            coding
        };
        let encoded = ContentEncodedBody::new(source, coding, config.limits)
            .map_err(|_| refusal(StatusCode::INTERNAL_SERVER_ERROR, "failed to initialize streamed response encoding"))?;
        if coding != ContentCoding::Identity {
            head.headers.retain(|name, _| !crate::http::decode::invalidated_field(name));
            head.set_header("content-encoding", coding.as_token());
            weaken_etag(&mut head);
        } else if head.status == StatusCode::NOT_MODIFIED {
            vary(&mut head);
        }
        Ok((head, encoded))
    }
}

fn declared_length(head: &Response) -> Result<Option<u64>, Response> {
    let mut length = None;
    for (_, value) in head.headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("content-length")) {
        let parsed = parse_content_length(value)
            .map_err(|_| refusal(StatusCode::INTERNAL_SERVER_ERROR, "invalid streamed response Content-Length"))? as u64;
        if length.replace(parsed).is_some_and(|previous| previous != parsed) {
            return Err(refusal(StatusCode::INTERNAL_SERVER_ERROR, "conflicting streamed response Content-Length"));
        }
    }
    Ok(length)
}

fn no_transform(value: &str) -> bool {
    value.split(',').any(|part| part.split('=').next().is_some_and(|name| name.trim().eq_ignore_ascii_case("no-transform")))
}

fn specialized_content_type(value: &str) -> bool {
    let mime = value.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    (mime.starts_with("image/") && mime != "image/svg+xml")
        || mime.starts_with("audio/") || mime.starts_with("video/")
        || mime.starts_with("application/grpc")
        || matches!(mime.as_str(), "text/event-stream" | "multipart/byteranges"
            | "application/zip" | "application/gzip" | "application/x-gzip"
            | "application/zstd" | "application/x-7z-compressed" | "application/pdf")
}

fn wildcard_vary(head: &Response) -> bool {
    head.header_value("vary").is_some_and(|value| value.split(',').any(|token| token.trim() == "*"))
}

fn vary(head: &mut Response) {
    if !wildcard_vary(head) { append_vary_token(head, "accept-encoding"); }
}

fn refusal(status: StatusCode, message: &'static str) -> Response {
    Response::new(status, message)
}
