//! Response compression middleware.
//!
//! Provides [`CompressionMiddleware`] which negotiates content encoding
//! with the client via `Accept-Encoding` and compresses response bodies
//! using the best available algorithm.
//!
//! # Design
//!
//! Compression is applied as a post-processing step after the inner handler
//! produces a response. The middleware:
//!
//! 1. Reads the `accept-encoding` request header.
//! 2. Negotiates the best encoding against the configured supported set.
//! 3. Compresses the response body if profitable (above minimum size).
//! 4. Sets `content-encoding` and `vary` response headers.
//!
//! # Skip Conditions
//!
//! Compression is skipped when:
//! - The response already has a `content-encoding` header.
//! - The response body is empty or below the minimum size threshold.
//! - The response status is 204 No Content or 304 Not Modified.
//! - No acceptable encoding is negotiated.
//! - The negotiated encoding is `identity`.

use crate::http::compress::{ContentEncoding, make_compressor, negotiate_encoding};

use super::extract::Request;
use super::handler::Handler;
use super::response::{Response, StatusCode};

/// Policy governing response compression behavior.
#[derive(Debug, Clone)]
pub struct CompressionPolicy {
    /// Encodings this server supports, in preference order.
    ///
    /// The negotiation algorithm uses this ordering as a tiebreaker when
    /// client quality values are equal.
    pub supported_encodings: Vec<ContentEncoding>,

    /// Minimum response body size (in bytes) to consider for compression.
    ///
    /// Bodies smaller than this threshold are sent uncompressed because the
    /// compression overhead (headers, framing) may exceed the size savings.
    pub min_body_size: usize,
}

impl Default for CompressionPolicy {
    fn default() -> Self {
        Self {
            supported_encodings: vec![
                ContentEncoding::Brotli,
                ContentEncoding::Gzip,
                ContentEncoding::Deflate,
                ContentEncoding::Identity,
            ],
            min_body_size: 256,
        }
    }
}

impl CompressionPolicy {
    /// Create a policy that only supports gzip.
    #[must_use]
    pub fn gzip_only() -> Self {
        Self {
            supported_encodings: vec![ContentEncoding::Gzip, ContentEncoding::Identity],
            ..Self::default()
        }
    }

    /// Set the minimum body size for compression.
    #[must_use]
    pub fn with_min_body_size(mut self, size: usize) -> Self {
        self.min_body_size = size;
        self
    }
}

/// Middleware that compresses response bodies based on `Accept-Encoding`.
///
/// Wraps an inner [`Handler`] and applies content-encoding negotiation
/// and body compression to responses that meet the policy criteria.
///
/// # Example
///
/// ```ignore
/// use asupersync::web::compress::{CompressionMiddleware, CompressionPolicy};
/// use asupersync::web::handler::FnHandler;
///
/// let handler = FnHandler::new(|| "hello world".repeat(100));
/// let compressed = CompressionMiddleware::new(handler, CompressionPolicy::default());
/// ```
pub struct CompressionMiddleware<H> {
    inner: H,
    policy: CompressionPolicy,
}

impl<H: Handler> CompressionMiddleware<H> {
    /// Wrap a handler with response compression.
    #[must_use]
    pub fn new(inner: H, policy: CompressionPolicy) -> Self {
        Self { inner, policy }
    }
}

impl<H: Handler> Handler for CompressionMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        // Extract accept-encoding before passing the request.
        let accept_encoding = req.header("accept-encoding").map(str::to_owned);

        let mut resp = self.inner.call(req);

        // Skip compression for special status codes.
        if resp.status == StatusCode::NO_CONTENT || resp.status == StatusCode::NOT_MODIFIED {
            return resp;
        }

        // Skip if the response already has content-encoding.
        if let Some(existing_encoding) = resp.remove_header("content-encoding") {
            resp.set_header("content-encoding", existing_encoding);
            return resp;
        }

        // Skip if body is below minimum size.
        if resp.body.len() < self.policy.min_body_size {
            return resp;
        }

        // Only negotiate encodings we can actually serve in this build.
        let available_encodings: Vec<_> = self
            .policy
            .supported_encodings
            .iter()
            .copied()
            .filter(|encoding| content_encoding_available(*encoding))
            .collect();

        // Negotiate encoding.
        let Some(encoding) = negotiate_encoding(accept_encoding.as_deref(), &available_encodings)
        else {
            if accept_encoding.is_some() {
                return Response::new(
                    StatusCode::from_u16(406),
                    b"No acceptable response encoding".to_vec(),
                );
            }
            return resp;
        };

        // Identity means no compression needed.
        if encoding == ContentEncoding::Identity {
            append_vary_token(&mut resp, "accept-encoding");
            return resp;
        }

        // Get a compressor for the negotiated encoding.
        let Some(mut compressor) = make_compressor(encoding) else {
            return resp;
        };

        // Compress the body.
        let mut compressed = Vec::new();
        if compressor.compress(&resp.body, &mut compressed).is_err() {
            return resp;
        }
        if compressor.finish(&mut compressed).is_err() {
            return resp;
        }

        // Only use compressed version if it's actually smaller.
        if compressed.len() >= resp.body.len() {
            append_vary_token(&mut resp, "accept-encoding");
            return resp;
        }

        // Apply compression.
        resp.body = compressed.into();
        resp.remove_header("content-length");
        resp.set_header("content-encoding", encoding.as_token().to_string());
        append_vary_token(&mut resp, "accept-encoding");

        resp
    }
}

fn content_encoding_available(encoding: ContentEncoding) -> bool {
    match encoding {
        ContentEncoding::Identity => true,
        #[cfg(feature = "compression")]
        ContentEncoding::Brotli | ContentEncoding::Gzip | ContentEncoding::Deflate => true,
        #[cfg(not(feature = "compression"))]
        ContentEncoding::Brotli | ContentEncoding::Gzip | ContentEncoding::Deflate => false,
    }
}

/// Appends a token to the Vary header without clobbering existing values.
fn append_vary_token(resp: &mut Response, token: &str) {
    let existing = resp.header_value("vary").unwrap_or_default().to_string();
    if existing
        .split(',')
        .any(|v| v.trim().eq_ignore_ascii_case(token))
    {
        return;
    }
    let updated = if existing.is_empty() {
        token.to_string()
    } else {
        format!("{existing}, {token}")
    };
    resp.set_header("vary", updated);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::handler::FnHandler;
    use crate::web::response::StatusCode;

    fn make_request_with_encoding(encoding: &str) -> Request {
        Request::new("GET", "/test").with_header("accept-encoding", encoding)
    }

    fn large_body_handler() -> Response {
        let body = "Hello, World! ".repeat(100);
        Response::new(StatusCode::OK, body.into_bytes())
            .header("content-type", "text/plain; charset=utf-8")
    }

    fn small_body_handler() -> &'static str {
        "tiny"
    }

    fn no_content_handler() -> Response {
        Response::empty(StatusCode::NO_CONTENT)
    }

    fn already_compressed_handler() -> Response {
        Response::new(StatusCode::OK, b"already-compressed".to_vec())
            .header("content-encoding", "gzip")
    }

    fn mixed_case_already_compressed_handler() -> Response {
        let mut resp = Response::new(StatusCode::OK, b"already-compressed".to_vec());
        resp.headers
            .insert("Content-Encoding".to_string(), "gzip".to_string());
        resp
    }

    fn handler_with_mixed_case_vary() -> Response {
        let body = "Hello, World! ".repeat(100);
        let mut resp = Response::new(StatusCode::OK, body.into_bytes());
        resp.headers
            .insert("Vary".to_string(), "origin".to_string());
        resp
    }

    // --- Basic behavior ---

    #[test]
    fn skips_compression_for_small_body() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(small_body_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[test]
    fn skips_compression_for_no_content() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(no_content_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[test]
    fn skips_compression_when_already_compressed() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(already_compressed_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("content-encoding").unwrap(),
            "gzip",
            "original content-encoding preserved"
        );
    }

    #[test]
    fn skips_compression_when_no_accept_encoding() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = Request::new("GET", "/test");
        let resp = mw.call(req);
        // With no Accept-Encoding header, the middleware preserves the
        // existing preference for identity when it is available.
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[test]
    fn empty_accept_encoding_header_is_not_treated_as_absent() {
        let policy = CompressionPolicy {
            supported_encodings: vec![ContentEncoding::Gzip],
            min_body_size: 0,
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("");
        let resp = mw.call(req);
        assert_eq!(resp.status.as_u16(), 406);
        assert_eq!(resp.body.as_ref(), b"No acceptable response encoding");
    }

    #[test]
    fn adds_vary_header() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("identity");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("vary").unwrap(),
            "accept-encoding",
            "vary header should always be set for compressible responses"
        );
    }

    #[test]
    fn honors_mixed_case_accept_encoding_inserted_directly() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let mut req = Request::new("GET", "/test");
        req.headers
            .insert("Accept-Encoding".to_string(), "identity".to_string());

        let resp = mw.call(req);

        assert_eq!(
            resp.headers.get("vary").unwrap(),
            "accept-encoding",
            "mixed-case direct header insert should still negotiate"
        );
    }

    #[test]
    fn skips_mixed_case_existing_content_encoding_and_canonicalizes_name() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(
            FnHandler::new(mixed_case_already_compressed_handler),
            policy,
        );
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);

        assert_eq!(
            resp.headers.get("content-encoding"),
            Some(&"gzip".to_string())
        );
        assert!(!resp.headers.contains_key("Content-Encoding"));
        assert!(!resp.headers.contains_key("vary"));
    }

    #[test]
    fn append_vary_token_canonicalizes_mixed_case_vary_header() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(handler_with_mixed_case_vary), policy);
        let req = make_request_with_encoding("identity");
        let resp = mw.call(req);

        assert_eq!(
            resp.headers.get("vary"),
            Some(&"origin, accept-encoding".to_string())
        );
        assert!(!resp.headers.contains_key("Vary"));
    }

    #[test]
    fn identity_encoding_no_compression() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("identity");
        let resp = mw.call(req);
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[test]
    fn rejects_explicitly_unacceptable_encodings() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip;q=0, deflate;q=0, identity;q=0, *;q=0");
        let resp = mw.call(req);
        assert_eq!(resp.status.as_u16(), 406);
        assert_eq!(resp.body.as_ref(), b"No acceptable response encoding");
    }

    #[cfg(not(feature = "compression"))]
    #[test]
    fn falls_back_to_identity_when_non_identity_codecs_are_unavailable() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
        assert_eq!(
            resp.headers.get("vary"),
            Some(&"accept-encoding".to_string())
        );
    }

    // --- Feature-gated compression tests ---

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_compresses_large_body() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "gzip");
        assert_eq!(resp.headers.get("vary").unwrap(), "accept-encoding");

        // Verify compressed body is smaller.
        let original_size = "Hello, World! ".repeat(100).len();
        assert!(
            resp.body.len() < original_size,
            "compressed body ({}) should be smaller than original ({})",
            resp.body.len(),
            original_size,
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn deflate_compresses_large_body() {
        let policy = CompressionPolicy {
            supported_encodings: vec![ContentEncoding::Deflate, ContentEncoding::Identity],
            min_body_size: 0,
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("deflate");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "deflate");
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_preferred_over_deflate() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip, deflate");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "gzip");
    }

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_preferred_over_gzip_by_default() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("br, gzip");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "br");
    }

    #[cfg(feature = "compression")]
    #[test]
    fn respects_client_quality_preference() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip;q=0.5, deflate;q=1.0");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "deflate");
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_roundtrip_body_integrity() {
        use crate::http::compress::Decompressor;
        use crate::http::compress::GzipDecompressor;

        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);

        // Decompress and verify body integrity.
        let mut dec = GzipDecompressor::new(None);
        let mut decompressed = Vec::new();
        dec.decompress(&resp.body, &mut decompressed).unwrap();
        let expected = "Hello, World! ".repeat(100);
        assert_eq!(
            String::from_utf8(decompressed).unwrap(),
            expected,
            "decompressed body should match original"
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_roundtrip_body_integrity() {
        use crate::http::compress::BrotliDecompressor;
        use crate::http::compress::Decompressor;

        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("br");
        let resp = mw.call(req);

        let mut dec = BrotliDecompressor::new(None);
        let mut decompressed = Vec::new();
        dec.decompress(&resp.body, &mut decompressed).unwrap();
        dec.finish(&mut decompressed).unwrap();
        let expected = "Hello, World! ".repeat(100);
        assert_eq!(
            String::from_utf8(decompressed).unwrap(),
            expected,
            "decompressed body should match original"
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn min_body_size_threshold() {
        let policy = CompressionPolicy::default().with_min_body_size(10_000);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        // "Hello, World! ".repeat(100) = 1400 bytes, below 10K threshold.
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[test]
    fn gzip_only_policy() {
        let policy = CompressionPolicy::gzip_only();
        assert_eq!(policy.supported_encodings.len(), 2);
        assert_eq!(policy.supported_encodings[0], ContentEncoding::Gzip);
        assert_eq!(policy.supported_encodings[1], ContentEncoding::Identity);
    }

    #[test]
    fn compression_policy_default() {
        let policy = CompressionPolicy::default();
        assert_eq!(policy.min_body_size, 256);
        assert_eq!(policy.supported_encodings.len(), 4);
        assert_eq!(policy.supported_encodings[0], ContentEncoding::Brotli);
    }

    /// Regression: compression must not clobber a pre-existing Vary header
    /// set by the inner handler.
    #[cfg(feature = "compression")]
    #[test]
    fn compression_preserves_existing_vary_header() {
        fn handler_with_vary() -> Response {
            let body = "Hello, World! ".repeat(100);
            Response::new(StatusCode::OK, body.into_bytes())
                .header("content-type", "text/plain; charset=utf-8")
                .header("vary", "origin")
        }

        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(handler_with_vary), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "gzip");
        let vary = resp.headers.get("vary").unwrap();
        assert!(
            vary.contains("origin"),
            "existing Vary value must be preserved, got: {vary}"
        );
        assert!(
            vary.contains("accept-encoding"),
            "accept-encoding must be appended to Vary, got: {vary}"
        );
    }
}
