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
//! - The request or response is credential-bearing/sensitive and the policy
//!   does not explicitly allow sensitive response compression.
//! - No acceptable encoding is negotiated.
//! - The negotiated encoding is `identity`.

use std::future::Future;
use std::pin::Pin;

use crate::Cx;
use crate::http::compress::{
    ContentCoding, ContentEncoding, DEFAULT_MAX_COMPRESSED_SIZE, compress_body, negotiate_coding,
    negotiate_encoding,
};

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

    /// Maximum compressed response body size (in bytes).
    ///
    /// Compression errors once the codec would exceed this cap, before the
    /// underlying compression buffer grows past it.
    pub max_compressed_size: usize,

    /// Whether to compress responses that could expose secrets through a
    /// BREACH-style size oracle.
    ///
    /// Disabled by default. Operators may opt in for responses whose bodies do
    /// not reflect attacker-controlled input next to secrets.
    pub compress_sensitive_responses: bool,
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
            max_compressed_size: DEFAULT_MAX_COMPRESSED_SIZE,
            compress_sensitive_responses: false,
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

    /// Set the maximum compressed response body size.
    #[must_use]
    pub fn with_max_compressed_size(mut self, size: usize) -> Self {
        self.max_compressed_size = size;
        self
    }

    /// Allow compression for credentialed or otherwise sensitive responses.
    #[must_use]
    pub const fn allow_sensitive_response_compression(mut self) -> Self {
        self.compress_sensitive_responses = true;
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
/// ```
/// use asupersync::web::compress::{CompressionMiddleware, CompressionPolicy};
/// use asupersync::web::handler::FnHandler;
///
/// let handler = FnHandler::new(|| "hello world".repeat(100));
/// let compressed = CompressionMiddleware::new(handler, CompressionPolicy::default());
/// ```
pub struct CompressionMiddleware<H> {
    inner: H,
    policy: CompressionPolicy,
    /// Offer zstd ahead of the policy's encodings (see `with_zstd`).
    zstd: bool,
}

impl<H: Handler> CompressionMiddleware<H> {
    /// Wrap a handler with response compression.
    #[must_use]
    pub fn new(inner: H, policy: CompressionPolicy) -> Self {
        Self {
            inner,
            policy,
            zstd: false,
        }
    }

    /// Also offer `zstd` (RFC 8878 §7.2), ahead of the policy's encodings, so
    /// it wins a tie in client quality. Bodies go out as frames of at most
    /// 1 MiB, far below the 8 MiB window RFC 9659 lets decoders require,
    /// within the policy's `max_compressed_size`.
    #[cfg(feature = "zstd")]
    #[must_use]
    pub fn with_zstd(mut self) -> Self {
        self.zstd = true;
        self
    }
}

impl<H: Handler> Handler for CompressionMiddleware<H> {
    fn call(&self, cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            // Extract accept-encoding before passing the request.
            let accept_encoding = req.header("accept-encoding").map(str::to_owned);
            let request_sensitivity = RequestCompressionSensitivity::from_request(&req);

            let mut resp = self.inner.call(&cx, req).await;

            // Skip compression for special status codes.
            if resp.status == StatusCode::NO_CONTENT {
                return resp;
            }
            if resp.status == StatusCode::NOT_MODIFIED {
                // A 304 carries the Vary of the response it validates.
                append_vary_token(&mut resp, "accept-encoding");
                return resp;
            }
            if is_partial_content(&resp) {
                return resp;
            }

            // Skip if the response already has content-encoding.
            if let Some(existing_encoding) = resp.remove_header("content-encoding") {
                resp.set_header("content-encoding", existing_encoding);
                return resp;
            }

            // Nothing to encode: gzipping an empty body broke streamed routes
            // (their head may not carry bytes) and HEAD's Content-Length.
            if resp.body.is_empty() {
                return resp;
            }

            let identity_acceptable =
                negotiate_encoding(accept_encoding.as_deref(), &[ContentEncoding::Identity])
                    == Some(ContentEncoding::Identity);

            if !self.policy.compress_sensitive_responses
                && compression_oracle_sensitive(request_sensitivity, &resp)
            {
                if !identity_acceptable {
                    return Response::new(
                        StatusCode::from_u16(406),
                        b"No acceptable response encoding".to_vec(),
                    );
                }
                append_vary_token(&mut resp, "accept-encoding");
                request_sensitivity.append_vary_tokens(&mut resp);
                return resp;
            }

            // Only negotiate encodings we can actually serve in this build.
            let available_encodings: Vec<_> = self
                .zstd
                .then_some(ContentCoding::Zstd)
                .into_iter()
                .chain(
                    self.policy
                        .supported_encodings
                        .iter()
                        .map(|&encoding| ContentCoding::from(encoding)),
                )
                .filter(|coding| content_coding_available(*coding))
                .collect();

            let body_below_minimum = resp.body.len() < self.policy.min_body_size;
            if body_below_minimum && identity_acceptable {
                return resp;
            }

            let candidate_encodings = if body_below_minimum {
                available_encodings
                    .iter()
                    .copied()
                    .filter(|coding| *coding != ContentCoding::Identity)
                    .collect::<Vec<_>>()
            } else {
                available_encodings
            };

            // Negotiate encoding.
            let Some(encoding) = negotiate_coding(accept_encoding.as_deref(), &candidate_encodings)
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
            if encoding == ContentCoding::Identity {
                append_vary_token(&mut resp, "accept-encoding");
                return resp;
            }

            // Compress the body with the negotiated encoding.
            let Some(compressed) =
                compress_body(encoding, &resp.body, self.policy.max_compressed_size)
            else {
                if !identity_acceptable {
                    return Response::new(
                        StatusCode::from_u16(406),
                        b"No acceptable response encoding".to_vec(),
                    );
                }
                return resp;
            };
            let Ok(compressed) = compressed else {
                if !identity_acceptable {
                    return Response::new(
                        StatusCode::from_u16(406),
                        b"No acceptable response encoding".to_vec(),
                    );
                }
                append_vary_token(&mut resp, "accept-encoding");
                return resp;
            };

            // Only use compressed version if it's actually smaller.
            if compressed.len() >= resp.body.len() && identity_acceptable {
                append_vary_token(&mut resp, "accept-encoding");
                return resp;
            }

            // Apply compression.
            resp.body = compressed.into();
            resp.remove_header("content-length");
            resp.set_header("content-encoding", encoding.as_token().to_string());
            weaken_etag(&mut resp);
            append_vary_token(&mut resp, "accept-encoding");

            resp
        })
    }
}

fn content_coding_available(coding: ContentCoding) -> bool {
    match coding {
        ContentCoding::Identity => true,
        ContentCoding::Brotli | ContentCoding::Gzip | ContentCoding::Deflate => {
            cfg!(feature = "compression")
        }
        ContentCoding::Zstd => cfg!(feature = "zstd"),
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RequestCompressionSensitivity {
    cookie: bool,
    authorization: bool,
    csrf_token: bool,
    xsrf_token: bool,
}

impl RequestCompressionSensitivity {
    pub(super) fn from_request(req: &Request) -> Self {
        Self {
            cookie: req.header("cookie").is_some(),
            authorization: req.header("authorization").is_some(),
            csrf_token: req.header("x-csrf-token").is_some(),
            xsrf_token: req.header("x-xsrf-token").is_some(),
        }
    }

    const fn any(self) -> bool {
        self.cookie || self.authorization || self.csrf_token || self.xsrf_token
    }

    pub(super) fn append_vary_tokens(self, resp: &mut Response) {
        if self.cookie {
            append_vary_token(resp, "cookie");
        }
        if self.authorization {
            append_vary_token(resp, "authorization");
        }
        if self.csrf_token {
            append_vary_token(resp, "x-csrf-token");
        }
        if self.xsrf_token {
            append_vary_token(resp, "x-xsrf-token");
        }
    }
}

/// A 206 body and its Content-Range (and strong ETag) describe bytes of the
/// selected representation (RFC 9110 sections 8.8.3 and 14.4); compressing
/// the body would leave both describing bytes the client never receives.
pub(super) fn is_partial_content(resp: &Response) -> bool {
    resp.status == StatusCode::PARTIAL_CONTENT || resp.has_header("content-range")
}

/// A strong ETag names exact bytes, and the compressed body is other bytes:
/// it may only carry a weak validator (RFC 9110 section 8.8.3). Kept strong,
/// a resumed download whose If-Range matched spliced identity bytes from the
/// 206 onto its compressed prefix (br-asupersync-a1q12q).
pub(super) fn weaken_etag(resp: &mut Response) {
    if let Some(etag) = resp.remove_header("etag") {
        if etag.starts_with("W/") {
            resp.set_header("etag", etag);
        } else {
            resp.set_header("etag", format!("W/{etag}"));
        }
    }
}

pub(super) fn compression_oracle_sensitive(
    request: RequestCompressionSensitivity,
    resp: &Response,
) -> bool {
    request.any()
        || resp.has_header("set-cookie")
        || resp
            .header_value("cache-control")
            .is_some_and(cache_control_marks_sensitive)
}

fn cache_control_marks_sensitive(value: &str) -> bool {
    value.split(',').any(|directive| {
        let directive = directive.trim();
        let name = directive
            .split_once('=')
            .map_or(directive, |(name, _)| name)
            .trim();
        name.eq_ignore_ascii_case("private")
            || name.eq_ignore_ascii_case("no-store")
            || name.eq_ignore_ascii_case("no-cache")
    })
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
#[path = "compress_inline_tests.rs"]
mod tests;
