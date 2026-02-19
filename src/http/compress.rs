//! HTTP body compression and content-encoding negotiation.
//!
//! Provides [`ContentEncoding`] for representing transfer encodings,
//! [`negotiate_encoding`] for Accept-Encoding negotiation, and a
//! [`Compressor`] trait for pluggable compression algorithms.
//!
//! # Design
//!
//! Compression is **explicit opt-in** — no ambient compression is applied.
//! Callers choose when to compress and which algorithm to use. The
//! [`negotiate_encoding`] function selects the best encoding from a client's
//! Accept-Encoding header against a server's supported set.
//!
//! The [`Compressor`] and [`Decompressor`] traits define the streaming
//! interface for compression algorithms. The [`IdentityCompressor`] passes
//! data through unchanged (for testing and fallback).

use std::fmt;
use std::io;

/// Supported content encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentEncoding {
    /// No encoding (pass-through).
    Identity,
    /// gzip (RFC 1952).
    Gzip,
    /// deflate (RFC 1951 wrapped in zlib).
    Deflate,
    /// Brotli (RFC 7932).
    Brotli,
}

impl ContentEncoding {
    /// Parse from the encoding token used in HTTP headers.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "identity" => Some(Self::Identity),
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            _ => None,
        }
    }

    /// Returns the HTTP header token for this encoding.
    #[must_use]
    pub const fn as_token(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Brotli => "br",
        }
    }
}

impl fmt::Display for ContentEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_token())
    }
}

/// A parsed quality value from Accept-Encoding.
#[derive(Debug, Clone, PartialEq)]
struct QualityValue {
    encoding: String,
    quality: f32,
}

/// Parse an Accept-Encoding header into (encoding, quality) pairs.
///
/// Format: `gzip;q=1.0, deflate;q=0.5, identity;q=0.1, *;q=0`
fn parse_accept_encoding(header: &str) -> Vec<QualityValue> {
    header
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }

            let mut pieces = part.splitn(2, ';');
            let encoding = pieces.next()?.trim().to_ascii_lowercase();

            let quality = pieces
                .next()
                .and_then(|q_part| {
                    let q_part = q_part.trim();
                    q_part
                        .strip_prefix("q=")
                        .or_else(|| q_part.strip_prefix("Q="))
                })
                .and_then(|q_str| q_str.trim().parse::<f32>().ok())
                .unwrap_or(1.0);

            Some(QualityValue { encoding, quality })
        })
        .collect()
}

/// Negotiate the best content encoding from an Accept-Encoding header
/// against the server's supported encodings.
///
/// Returns `None` if no acceptable encoding is found (the client explicitly
/// rejected all available encodings with q=0).
///
/// # Algorithm
///
/// 1. Parse Accept-Encoding into (token, quality) pairs.
/// 2. For each server-supported encoding, find its quality:
///    - Exact match on encoding token.
///    - Wildcard `*` match if no exact match.
///    - Default quality of 1.0 if not mentioned (except identity which
///      defaults to acceptable).
/// 3. Filter out q=0 (explicitly rejected).
/// 4. Return the encoding with highest quality (ties broken by server
///    preference order).
///
/// # Examples
///
/// ```
/// # use asupersync::http::compress::{ContentEncoding, negotiate_encoding};
/// let supported = &[ContentEncoding::Gzip, ContentEncoding::Deflate, ContentEncoding::Identity];
/// let best = negotiate_encoding("gzip;q=1.0, deflate;q=0.5", supported);
/// assert_eq!(best, Some(ContentEncoding::Gzip));
/// ```
#[must_use]
pub fn negotiate_encoding(
    accept_encoding: &str,
    supported: &[ContentEncoding],
) -> Option<ContentEncoding> {
    if accept_encoding.is_empty() {
        // No Accept-Encoding header: identity is acceptable
        return if supported.contains(&ContentEncoding::Identity) {
            Some(ContentEncoding::Identity)
        } else {
            supported.first().copied()
        };
    }

    let preferences = parse_accept_encoding(accept_encoding);

    // Find wildcard quality if present
    let wildcard_quality = preferences
        .iter()
        .find(|q| q.encoding == "*")
        .map(|q| q.quality);

    let mut best: Option<(ContentEncoding, f32)> = None;

    for &encoding in supported {
        let token = encoding.as_token();

        // Find explicit quality for this encoding
        let quality = preferences
            .iter()
            .find(|q| q.encoding == token)
            .map(|q| q.quality)
            .or(wildcard_quality)
            .unwrap_or_else(|| {
                // Not mentioned and no wildcard: identity is implicitly acceptable
                if encoding == ContentEncoding::Identity {
                    1.0
                } else {
                    0.0
                }
            });

        // q=0 means explicitly rejected
        if quality <= 0.0 {
            continue;
        }

        match best {
            Some((_, best_q)) if quality <= best_q => {}
            _ => best = Some((encoding, quality)),
        }
    }

    best.map(|(enc, _)| enc)
}

/// Trait for streaming compression.
///
/// Implementors compress data incrementally, supporting backpressure
/// through the `io::Write`-like interface.
pub trait Compressor: Send {
    /// Compress a chunk of input data, appending compressed bytes to `output`.
    fn compress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()>;

    /// Flush any buffered data and write the compression trailer.
    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()>;

    /// Returns the content encoding this compressor produces.
    fn encoding(&self) -> ContentEncoding;
}

/// Trait for streaming decompression.
///
/// Implementors decompress data incrementally with configurable limits
/// to prevent decompression bombs.
pub trait Decompressor: Send {
    /// Decompress a chunk of input data, appending decompressed bytes to `output`.
    ///
    /// Returns `Err` if the decompressed size would exceed the configured limit.
    fn decompress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()>;

    /// Signal that all input has been provided; flush remaining data.
    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()>;

    /// Returns the content encoding this decompressor handles.
    fn encoding(&self) -> ContentEncoding;
}

/// Identity compressor that passes data through unchanged.
#[derive(Debug, Default)]
pub struct IdentityCompressor;

impl Compressor for IdentityCompressor {
    fn compress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        output.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, _output: &mut Vec<u8>) -> io::Result<()> {
        Ok(())
    }

    fn encoding(&self) -> ContentEncoding {
        ContentEncoding::Identity
    }
}

/// Identity decompressor that passes data through unchanged.
#[derive(Debug, Default)]
pub struct IdentityDecompressor {
    max_size: Option<usize>,
    total: usize,
}

impl IdentityDecompressor {
    /// Create a new identity decompressor with an optional size limit.
    #[must_use]
    pub const fn new(max_size: Option<usize>) -> Self {
        Self { max_size, total: 0 }
    }
}

impl Decompressor for IdentityDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        self.total += input.len();
        if let Some(max) = self.max_size {
            if self.total > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decompressed size exceeds limit",
                ));
            }
        }
        output.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, _output: &mut Vec<u8>) -> io::Result<()> {
        Ok(())
    }

    fn encoding(&self) -> ContentEncoding {
        ContentEncoding::Identity
    }
}

/// Extracts the Content-Encoding value from a list of headers.
#[must_use]
pub fn content_encoding_from_headers(headers: &[(String, String)]) -> Option<ContentEncoding> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .and_then(|(_, value)| ContentEncoding::from_token(value))
}

/// Extracts the Accept-Encoding value from a list of headers.
#[must_use]
pub fn accept_encoding_from_headers(headers: &[(String, String)]) -> Option<&str> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
        .map(|(_, value)| value.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_quality(actual: f32, expected: f32) {
        let delta = (actual - expected).abs();
        assert!(
            delta <= f32::EPSILON,
            "quality mismatch: expected {expected}, got {actual}"
        );
    }

    // ====================================================================
    // ContentEncoding tests
    // ====================================================================

    #[test]
    fn encoding_from_token() {
        assert_eq!(
            ContentEncoding::from_token("gzip"),
            Some(ContentEncoding::Gzip)
        );
        assert_eq!(
            ContentEncoding::from_token("x-gzip"),
            Some(ContentEncoding::Gzip)
        );
        assert_eq!(
            ContentEncoding::from_token("GZIP"),
            Some(ContentEncoding::Gzip)
        );
        assert_eq!(
            ContentEncoding::from_token("deflate"),
            Some(ContentEncoding::Deflate)
        );
        assert_eq!(
            ContentEncoding::from_token("br"),
            Some(ContentEncoding::Brotli)
        );
        assert_eq!(
            ContentEncoding::from_token("identity"),
            Some(ContentEncoding::Identity)
        );
        assert_eq!(ContentEncoding::from_token("unknown"), None);
    }

    #[test]
    fn encoding_roundtrip() {
        for enc in [
            ContentEncoding::Identity,
            ContentEncoding::Gzip,
            ContentEncoding::Deflate,
            ContentEncoding::Brotli,
        ] {
            let token = enc.as_token();
            assert_eq!(ContentEncoding::from_token(token), Some(enc));
        }
    }

    #[test]
    fn encoding_display() {
        assert_eq!(ContentEncoding::Gzip.to_string(), "gzip");
        assert_eq!(ContentEncoding::Brotli.to_string(), "br");
    }

    // ====================================================================
    // Accept-Encoding parsing tests
    // ====================================================================

    #[test]
    fn parse_simple_accept_encoding() {
        let parsed = parse_accept_encoding("gzip, deflate");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].encoding, "gzip");
        assert_quality(parsed[0].quality, 1.0);
        assert_eq!(parsed[1].encoding, "deflate");
        assert_quality(parsed[1].quality, 1.0);
    }

    #[test]
    fn parse_accept_encoding_with_quality() {
        let parsed = parse_accept_encoding("gzip;q=1.0, deflate;q=0.5, *;q=0");
        assert_eq!(parsed.len(), 3);
        assert_quality(parsed[0].quality, 1.0);
        assert_quality(parsed[1].quality, 0.5);
        assert_eq!(parsed[2].encoding, "*");
        assert_quality(parsed[2].quality, 0.0);
    }

    #[test]
    fn parse_accept_encoding_empty() {
        let parsed = parse_accept_encoding("");
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_accept_encoding_whitespace() {
        let parsed = parse_accept_encoding("  gzip  ;  q=0.8  ,  br  ");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].encoding, "gzip");
        assert_quality(parsed[0].quality, 0.8);
        assert_eq!(parsed[1].encoding, "br");
        assert_quality(parsed[1].quality, 1.0);
    }

    // ====================================================================
    // Negotiation tests
    // ====================================================================

    #[test]
    fn negotiate_prefers_highest_quality() {
        let supported = &[
            ContentEncoding::Gzip,
            ContentEncoding::Deflate,
            ContentEncoding::Identity,
        ];
        let best = negotiate_encoding("gzip;q=0.5, deflate;q=1.0", supported);
        assert_eq!(best, Some(ContentEncoding::Deflate));
    }

    #[test]
    fn negotiate_server_order_breaks_ties() {
        let supported = &[ContentEncoding::Gzip, ContentEncoding::Deflate];
        let best = negotiate_encoding("gzip, deflate", supported);
        // Both have q=1.0, server prefers gzip (listed first)
        assert_eq!(best, Some(ContentEncoding::Gzip));
    }

    #[test]
    fn negotiate_wildcard() {
        let supported = &[ContentEncoding::Brotli, ContentEncoding::Identity];
        let best = negotiate_encoding("*", supported);
        assert_eq!(best, Some(ContentEncoding::Brotli));
    }

    #[test]
    fn negotiate_wildcard_with_explicit_reject() {
        let supported = &[
            ContentEncoding::Gzip,
            ContentEncoding::Deflate,
            ContentEncoding::Identity,
        ];
        let best = negotiate_encoding("gzip;q=0, *;q=0.5", supported);
        // gzip is explicitly rejected, deflate and identity get wildcard q=0.5
        assert_eq!(best, Some(ContentEncoding::Deflate));
    }

    #[test]
    fn negotiate_all_rejected() {
        let supported = &[ContentEncoding::Gzip];
        let best = negotiate_encoding("gzip;q=0, *;q=0", supported);
        assert_eq!(best, None);
    }

    #[test]
    fn negotiate_empty_accept_encoding() {
        let supported = &[ContentEncoding::Gzip, ContentEncoding::Identity];
        let best = negotiate_encoding("", supported);
        assert_eq!(best, Some(ContentEncoding::Identity));
    }

    #[test]
    fn negotiate_empty_accept_no_identity() {
        let supported = &[ContentEncoding::Gzip];
        let best = negotiate_encoding("", supported);
        assert_eq!(best, Some(ContentEncoding::Gzip));
    }

    #[test]
    fn negotiate_identity_implicit_acceptable() {
        let supported = &[ContentEncoding::Identity, ContentEncoding::Gzip];
        // Only gzip mentioned; identity is implicitly acceptable
        let best = negotiate_encoding("gzip;q=0.5", supported);
        // Identity gets implicit q=1.0, gzip gets q=0.5
        assert_eq!(best, Some(ContentEncoding::Identity));
    }

    #[test]
    fn negotiate_identity_explicitly_rejected() {
        let supported = &[ContentEncoding::Identity, ContentEncoding::Gzip];
        let best = negotiate_encoding("identity;q=0, gzip;q=1.0", supported);
        assert_eq!(best, Some(ContentEncoding::Gzip));
    }

    // ====================================================================
    // Identity compressor tests
    // ====================================================================

    #[test]
    fn identity_compressor_passthrough() {
        let mut comp = IdentityCompressor;
        let mut output = Vec::new();
        comp.compress(b"hello", &mut output).unwrap();
        comp.compress(b" world", &mut output).unwrap();
        comp.finish(&mut output).unwrap();
        assert_eq!(output, b"hello world");
        assert_eq!(comp.encoding(), ContentEncoding::Identity);
    }

    #[test]
    fn identity_decompressor_passthrough() {
        let mut dec = IdentityDecompressor::new(None);
        let mut output = Vec::new();
        dec.decompress(b"hello", &mut output).unwrap();
        dec.decompress(b" world", &mut output).unwrap();
        dec.finish(&mut output).unwrap();
        assert_eq!(output, b"hello world");
        assert_eq!(dec.encoding(), ContentEncoding::Identity);
    }

    #[test]
    fn identity_decompressor_size_limit() {
        let mut dec = IdentityDecompressor::new(Some(10));
        let mut output = Vec::new();
        dec.decompress(b"hello", &mut output).unwrap();
        let result = dec.decompress(b"123456", &mut output);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn identity_decompressor_exact_limit() {
        let mut dec = IdentityDecompressor::new(Some(10));
        let mut output = Vec::new();
        dec.decompress(b"1234567890", &mut output).unwrap();
        // Exactly at limit is fine
        assert_eq!(output.len(), 10);
        // One more byte exceeds
        let result = dec.decompress(b"x", &mut output);
        assert!(result.is_err());
    }

    // ====================================================================
    // Header helpers tests
    // ====================================================================

    #[test]
    fn content_encoding_header_extraction() {
        let headers = vec![
            ("Content-Type".to_owned(), "text/html".to_owned()),
            ("Content-Encoding".to_owned(), "gzip".to_owned()),
        ];
        assert_eq!(
            content_encoding_from_headers(&headers),
            Some(ContentEncoding::Gzip)
        );
    }

    #[test]
    fn content_encoding_header_case_insensitive() {
        let headers = vec![("content-encoding".to_owned(), "BR".to_owned())];
        assert_eq!(
            content_encoding_from_headers(&headers),
            Some(ContentEncoding::Brotli)
        );
    }

    #[test]
    fn content_encoding_header_missing() {
        let headers: Vec<(String, String)> = vec![];
        assert_eq!(content_encoding_from_headers(&headers), None);
    }

    #[test]
    fn accept_encoding_header_extraction() {
        let headers = vec![("Accept-Encoding".to_owned(), "gzip, deflate, br".to_owned())];
        assert_eq!(
            accept_encoding_from_headers(&headers),
            Some("gzip, deflate, br")
        );
    }

    #[test]
    fn accept_encoding_header_missing() {
        let headers: Vec<(String, String)> = vec![];
        assert_eq!(accept_encoding_from_headers(&headers), None);
    }

    #[test]
    fn content_encoding_debug_clone_copy_hash_eq() {
        use std::collections::HashSet;
        let gz = ContentEncoding::Gzip;
        let dbg = format!("{gz:?}");
        assert!(dbg.contains("Gzip"), "{dbg}");

        let copied: ContentEncoding = gz;
        let cloned = gz.clone();
        assert_eq!(copied, cloned);
        assert_eq!(gz, ContentEncoding::Gzip);
        assert_ne!(gz, ContentEncoding::Brotli);

        let mut set = HashSet::new();
        set.insert(ContentEncoding::Identity);
        set.insert(ContentEncoding::Gzip);
        set.insert(ContentEncoding::Deflate);
        set.insert(ContentEncoding::Brotli);
        assert_eq!(set.len(), 4);
        assert!(set.contains(&ContentEncoding::Gzip));
    }

    #[test]
    fn identity_compressor_debug_default() {
        let c = IdentityCompressor::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("IdentityCompressor"), "{dbg}");
    }

    #[test]
    fn identity_decompressor_debug_default() {
        let d = IdentityDecompressor::default();
        let dbg = format!("{d:?}");
        assert!(dbg.contains("IdentityDecompressor"), "{dbg}");
    }
}
