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

            let quality = if let Some(q_part) = pieces.next() {
                let q_part = q_part.trim();
                let q_str = q_part
                    .strip_prefix("q=")
                    .or_else(|| q_part.strip_prefix("Q="))?;
                let q = q_str.trim().parse::<f32>().ok()?;
                if !q.is_finite() || !(0.0..=1.0).contains(&q) {
                    return None;
                }
                q
            } else {
                1.0
            };

            Some(QualityValue { encoding, quality })
        })
        .collect()
}

/// Negotiate the best content encoding from an optional Accept-Encoding header
/// against the server's supported encodings.
///
/// `None` means the request omitted the header entirely. `Some("")` (or
/// whitespace only) means the header was present but empty, which is treated
/// as an explicit no-content-coding request.
///
/// Returns `None` if no acceptable encoding is found.
///
/// # Algorithm
///
/// 1. If the header is absent, prefer `identity` when available, otherwise
///    fall back to server preference order.
/// 2. If the header is present but empty, only `identity` is acceptable.
/// 3. Parse a non-empty Accept-Encoding value into (token, quality) pairs.
/// 4. For each server-supported encoding, find its quality:
///    - Exact match on encoding token.
///    - Wildcard `*` match if no exact match.
///    - `identity` defaults to q=1.0 unless explicitly excluded by
///      `identity;q=0` or `*;q=0` without a more specific `identity` entry.
/// 5. Filter out q=0 (explicitly rejected).
/// 6. Return the encoding with highest quality (ties broken by server
///    preference order).
///
/// # Examples
///
/// ```
/// # use asupersync::http::compress::{ContentEncoding, negotiate_encoding};
/// let supported = &[ContentEncoding::Gzip, ContentEncoding::Deflate, ContentEncoding::Identity];
/// let best = negotiate_encoding(Some("gzip;q=1.0, deflate;q=0.5"), supported);
/// assert_eq!(best, Some(ContentEncoding::Gzip));
/// ```
#[must_use]
pub fn negotiate_encoding(
    accept_encoding: Option<&str>,
    supported: &[ContentEncoding],
) -> Option<ContentEncoding> {
    let Some(accept_encoding) = accept_encoding else {
        // No Accept-Encoding header: keep the existing server-preference
        // behavior and prefer identity when available.
        return if supported.contains(&ContentEncoding::Identity) {
            Some(ContentEncoding::Identity)
        } else {
            supported.first().copied()
        };
    };

    if accept_encoding.trim().is_empty() {
        return supported
            .contains(&ContentEncoding::Identity)
            .then_some(ContentEncoding::Identity);
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

        let explicit_quality = preferences
            .iter()
            .find(|q| q.encoding == token)
            .map(|q| q.quality);

        let quality = match encoding {
            // RFC 9110 §12.5.3: identity is acceptable by default (q=1.0)
            // unless explicitly excluded by `identity;q=0` or `*;q=0`
            // (without a more specific identity entry). A non-zero wildcard
            // like `*;q=0.5` does NOT lower identity from its default.
            ContentEncoding::Identity => explicit_quality.unwrap_or(match wildcard_quality {
                Some(q) if q <= 0.0 => 0.0,
                _ => 1.0,
            }),
            _ => explicit_quality.or(wildcard_quality).unwrap_or(0.0),
        };

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
        update_decompressed_total(&mut self.total, input.len(), self.max_size)?;
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

#[cfg(feature = "compression")]
const BROTLI_BUFFER_SIZE: usize = 4096;

#[cfg(feature = "compression")]
const BROTLI_DEFAULT_QUALITY: u32 = 5;

#[cfg(feature = "compression")]
const BROTLI_DEFAULT_LGWIN: u32 = 22;

// ─── Gzip Compressor ────────────────────────────────────────────────────────

/// Gzip compressor using the flate2 (miniz_oxide) backend.
///
/// Compresses data in RFC 1952 gzip format. Uses compression level 6
/// (default) which provides a good balance of speed and ratio.
#[cfg(feature = "compression")]
pub struct GzipCompressor {
    encoder: flate2::write::GzEncoder<Vec<u8>>,
    finished: bool,
}

#[cfg(feature = "compression")]
impl GzipCompressor {
    /// Create a new gzip compressor with the default compression level.
    #[must_use]
    pub fn new() -> Self {
        Self::with_level(flate2::Compression::default())
    }

    /// Create a new gzip compressor with the specified compression level.
    #[must_use]
    pub fn with_level(level: flate2::Compression) -> Self {
        Self {
            encoder: flate2::write::GzEncoder::new(Vec::new(), level),
            finished: false,
        }
    }
}

#[cfg(feature = "compression")]
impl Default for GzipCompressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "compression")]
impl Compressor for GzipCompressor {
    fn compress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        self.encoder.write_all(input)?;
        let buf = self.encoder.get_mut();
        if !buf.is_empty() {
            output.extend_from_slice(buf);
            buf.clear();
        }
        Ok(())
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        if self.finished {
            return Ok(());
        }
        self.encoder.flush()?;
        // Take the inner buffer, reset encoder with a new empty vec.
        let inner = std::mem::replace(
            &mut self.encoder,
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none()),
        );
        let finished = inner.finish()?;
        output.extend_from_slice(&finished);
        self.finished = true;
        Ok(())
    }

    fn encoding(&self) -> ContentEncoding {
        ContentEncoding::Gzip
    }
}

/// Gzip decompressor using the flate2 (miniz_oxide) backend.
#[cfg(feature = "compression")]
pub struct GzipDecompressor {
    max_size: Option<usize>,
    total: usize,
    decoder: flate2::write::GzDecoder<Vec<u8>>,
}

#[cfg(feature = "compression")]
impl GzipDecompressor {
    /// Create a new gzip decompressor with an optional size limit.
    #[must_use]
    pub fn new(max_size: Option<usize>) -> Self {
        Self {
            max_size,
            total: 0,
            decoder: flate2::write::GzDecoder::new(Vec::new()),
        }
    }
}

#[cfg(feature = "compression")]
impl Decompressor for GzipDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        // Cap the internal buffer before decompressing to prevent transient
        // unbounded allocation from decompression bombs.  The cap is the
        // remaining budget (max_size - total) plus a small margin so flate2
        // can finish a partial block without hitting an artificial limit.
        if let Some(max) = self.max_size {
            let remaining = max.saturating_sub(self.total).saturating_add(4096);
            let buf = self.decoder.get_mut();
            if buf.capacity() > remaining {
                buf.shrink_to(remaining);
            }
        }
        self.decoder.write_all(input)?;
        self.decoder.flush()?;
        let buf = std::mem::take(self.decoder.get_mut());
        update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
        output.extend_from_slice(&buf);
        Ok(())
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        let mut dummy = flate2::write::GzDecoder::new(Vec::new());
        std::mem::swap(&mut self.decoder, &mut dummy);
        let buf = dummy.finish()?;
        update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
        output.extend_from_slice(&buf);
        Ok(())
    }

    fn encoding(&self) -> ContentEncoding {
        ContentEncoding::Gzip
    }
}

// ─── Deflate Compressor ─────────────────────────────────────────────────────

/// Deflate compressor using the flate2 (miniz_oxide) backend.
///
/// Compresses data in RFC 1951 raw deflate format (wrapped in zlib per
/// HTTP deflate convention).
#[cfg(feature = "compression")]
pub struct DeflateCompressor {
    encoder: flate2::write::DeflateEncoder<Vec<u8>>,
    finished: bool,
}

#[cfg(feature = "compression")]
impl DeflateCompressor {
    /// Create a new deflate compressor with the default compression level.
    #[must_use]
    pub fn new() -> Self {
        Self::with_level(flate2::Compression::default())
    }

    /// Create a new deflate compressor with the specified compression level.
    #[must_use]
    pub fn with_level(level: flate2::Compression) -> Self {
        Self {
            encoder: flate2::write::DeflateEncoder::new(Vec::new(), level),
            finished: false,
        }
    }
}

#[cfg(feature = "compression")]
impl Default for DeflateCompressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "compression")]
impl Compressor for DeflateCompressor {
    fn compress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        self.encoder.write_all(input)?;
        let buf = self.encoder.get_mut();
        if !buf.is_empty() {
            output.extend_from_slice(buf);
            buf.clear();
        }
        Ok(())
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        if self.finished {
            return Ok(());
        }
        self.encoder.flush()?;
        let inner = std::mem::replace(
            &mut self.encoder,
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::none()),
        );
        let finished = inner.finish()?;
        output.extend_from_slice(&finished);
        self.finished = true;
        Ok(())
    }

    fn encoding(&self) -> ContentEncoding {
        ContentEncoding::Deflate
    }
}

/// Deflate decompressor using the flate2 (miniz_oxide) backend.
#[cfg(feature = "compression")]
pub struct DeflateDecompressor {
    max_size: Option<usize>,
    total: usize,
    decoder: flate2::write::DeflateDecoder<Vec<u8>>,
}

#[cfg(feature = "compression")]
impl DeflateDecompressor {
    /// Create a new deflate decompressor with an optional size limit.
    #[must_use]
    pub fn new(max_size: Option<usize>) -> Self {
        Self {
            max_size,
            total: 0,
            decoder: flate2::write::DeflateDecoder::new(Vec::new()),
        }
    }
}

#[cfg(feature = "compression")]
impl Decompressor for DeflateDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        // Cap the internal buffer before decompressing to prevent transient
        // unbounded allocation from decompression bombs.
        if let Some(max) = self.max_size {
            let remaining = max.saturating_sub(self.total).saturating_add(4096);
            let buf = self.decoder.get_mut();
            if buf.capacity() > remaining {
                buf.shrink_to(remaining);
            }
        }
        self.decoder.write_all(input)?;
        self.decoder.flush()?;
        let buf = std::mem::take(self.decoder.get_mut());
        update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
        output.extend_from_slice(&buf);
        Ok(())
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        let mut dummy = flate2::write::DeflateDecoder::new(Vec::new());
        std::mem::swap(&mut self.decoder, &mut dummy);
        let buf = dummy.finish()?;
        update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
        output.extend_from_slice(&buf);
        Ok(())
    }

    fn encoding(&self) -> ContentEncoding {
        ContentEncoding::Deflate
    }
}

// ─── Brotli Compressor ──────────────────────────────────────────────────────

/// Brotli compressor using the `brotli` crate's streaming writer.
///
/// Uses a balanced default quality tuned for HTTP response bodies rather than
/// maximum offline compression ratio.
#[cfg(feature = "compression")]
pub struct BrotliCompressor {
    encoder: brotli::CompressorWriter<Vec<u8>>,
    finished: bool,
}

#[cfg(feature = "compression")]
impl BrotliCompressor {
    /// Create a new Brotli compressor with balanced HTTP-oriented defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::with_params(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_LGWIN)
    }

    /// Create a new Brotli compressor with explicit quality and window.
    #[must_use]
    pub fn with_params(quality: u32, lgwin: u32) -> Self {
        Self {
            encoder: brotli::CompressorWriter::new(Vec::new(), BROTLI_BUFFER_SIZE, quality, lgwin),
            finished: false,
        }
    }
}

#[cfg(feature = "compression")]
impl Default for BrotliCompressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "compression")]
impl Compressor for BrotliCompressor {
    fn compress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        self.encoder.write_all(input)?;
        self.encoder.flush()?;
        let buf = self.encoder.get_mut();
        if !buf.is_empty() {
            output.extend_from_slice(buf);
            buf.clear();
        }
        Ok(())
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        if self.finished {
            return Ok(());
        }
        self.encoder.flush()?;
        let finished = std::mem::replace(
            &mut self.encoder,
            brotli::CompressorWriter::new(
                Vec::new(),
                BROTLI_BUFFER_SIZE,
                BROTLI_DEFAULT_QUALITY,
                BROTLI_DEFAULT_LGWIN,
            ),
        )
        .into_inner();
        output.extend_from_slice(&finished);
        self.finished = true;
        Ok(())
    }

    fn encoding(&self) -> ContentEncoding {
        ContentEncoding::Brotli
    }
}

/// Brotli decompressor using the `brotli` crate's streaming writer.
#[cfg(feature = "compression")]
pub struct BrotliDecompressor {
    max_size: Option<usize>,
    total: usize,
    decoder: brotli::DecompressorWriter<Vec<u8>>,
    finished: bool,
}

#[cfg(feature = "compression")]
impl BrotliDecompressor {
    /// Create a new Brotli decompressor with an optional size limit.
    #[must_use]
    pub fn new(max_size: Option<usize>) -> Self {
        Self {
            max_size,
            total: 0,
            decoder: brotli::DecompressorWriter::new(Vec::new(), BROTLI_BUFFER_SIZE),
            finished: false,
        }
    }
}

#[cfg(feature = "compression")]
impl Decompressor for BrotliDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        if let Some(max) = self.max_size {
            let remaining = max
                .saturating_sub(self.total)
                .saturating_add(BROTLI_BUFFER_SIZE);
            let buf = self.decoder.get_mut();
            if buf.capacity() > remaining {
                buf.shrink_to(remaining);
            }
        }
        self.decoder.write_all(input)?;
        self.decoder.flush()?;
        let buf = self.decoder.get_mut();
        update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
        output.extend_from_slice(buf);
        buf.clear();
        Ok(())
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        if self.finished {
            return Ok(());
        }
        self.decoder.flush()?;
        self.decoder.close()?;
        let buf = std::mem::take(self.decoder.get_mut());
        update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
        output.extend_from_slice(&buf);
        self.finished = true;
        Ok(())
    }

    fn encoding(&self) -> ContentEncoding {
        ContentEncoding::Brotli
    }
}

// ─── Compressor factory ─────────────────────────────────────────────────────

/// Create a compressor for the given encoding.
///
/// Returns `None` for encodings that are unavailable in the current build.
#[must_use]
pub fn make_compressor(encoding: ContentEncoding) -> Option<Box<dyn Compressor>> {
    match encoding {
        ContentEncoding::Identity => Some(Box::new(IdentityCompressor)),
        #[cfg(feature = "compression")]
        ContentEncoding::Gzip => Some(Box::new(GzipCompressor::new())),
        #[cfg(feature = "compression")]
        ContentEncoding::Deflate => Some(Box::new(DeflateCompressor::new())),
        #[cfg(feature = "compression")]
        ContentEncoding::Brotli => Some(Box::new(BrotliCompressor::new())),
        #[cfg(not(feature = "compression"))]
        ContentEncoding::Gzip | ContentEncoding::Deflate | ContentEncoding::Brotli => None,
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

fn update_decompressed_total(
    total: &mut usize,
    added: usize,
    max_size: Option<usize>,
) -> io::Result<()> {
    let next_total = total.checked_add(added).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed size exceeds limit",
        )
    })?;
    if let Some(max) = max_size {
        if next_total > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed size exceeds limit",
            ));
        }
    }
    *total = next_total;
    Ok(())
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

    #[test]
    fn parse_accept_encoding_rejects_malformed_q() {
        let parsed =
            parse_accept_encoding("gzip;q=1.5, deflate;q=-0.1, br;q=abc, identity;q=NaN, *;q=1.0");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].encoding, "*");
        assert_quality(parsed[0].quality, 1.0);
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
        let best = negotiate_encoding(Some("gzip;q=0.5, deflate;q=1.0"), supported);
        assert_eq!(best, Some(ContentEncoding::Deflate));
    }

    #[test]
    fn negotiate_server_order_breaks_ties() {
        let supported = &[ContentEncoding::Gzip, ContentEncoding::Deflate];
        let best = negotiate_encoding(Some("gzip, deflate"), supported);
        // Both have q=1.0, server prefers gzip (listed first)
        assert_eq!(best, Some(ContentEncoding::Gzip));
    }

    #[test]
    fn negotiate_wildcard() {
        let supported = &[ContentEncoding::Brotli, ContentEncoding::Identity];
        let best = negotiate_encoding(Some("*"), supported);
        assert_eq!(best, Some(ContentEncoding::Brotli));
    }

    #[test]
    fn negotiate_wildcard_with_explicit_reject() {
        let supported = &[
            ContentEncoding::Gzip,
            ContentEncoding::Deflate,
            ContentEncoding::Identity,
        ];
        let best = negotiate_encoding(Some("gzip;q=0, *;q=0.5"), supported);
        // gzip is explicitly rejected (q=0). deflate inherits wildcard q=0.5.
        // identity keeps its RFC 9110 §12.5.3 default q=1.0 (wildcard only
        // excludes identity when *;q=0).
        assert_eq!(best, Some(ContentEncoding::Identity));
    }

    #[test]
    fn negotiate_all_rejected() {
        let supported = &[ContentEncoding::Gzip];
        let best = negotiate_encoding(Some("gzip;q=0, *;q=0"), supported);
        assert_eq!(best, None);
    }

    #[test]
    fn negotiate_absent_accept_encoding_prefers_identity() {
        let supported = &[ContentEncoding::Gzip, ContentEncoding::Identity];
        let best = negotiate_encoding(None, supported);
        assert_eq!(best, Some(ContentEncoding::Identity));
    }

    #[test]
    fn negotiate_absent_accept_encoding_uses_first_supported_when_identity_missing() {
        let supported = &[ContentEncoding::Gzip];
        let best = negotiate_encoding(None, supported);
        assert_eq!(best, Some(ContentEncoding::Gzip));
    }

    #[test]
    fn negotiate_empty_accept_encoding_only_accepts_identity() {
        let with_identity = &[ContentEncoding::Gzip, ContentEncoding::Identity];
        assert_eq!(
            negotiate_encoding(Some(""), with_identity),
            Some(ContentEncoding::Identity)
        );

        let gzip_only = &[ContentEncoding::Gzip];
        assert_eq!(negotiate_encoding(Some(""), gzip_only), None);
    }

    #[test]
    fn negotiate_whitespace_only_accept_encoding_matches_explicit_empty_header() {
        let with_identity = &[ContentEncoding::Gzip, ContentEncoding::Identity];
        assert_eq!(
            negotiate_encoding(Some("   "), with_identity),
            Some(ContentEncoding::Identity)
        );

        let gzip_only = &[ContentEncoding::Gzip];
        assert_eq!(negotiate_encoding(Some("   "), gzip_only), None);
    }

    #[test]
    fn negotiate_identity_implicit_acceptable() {
        let supported = &[ContentEncoding::Identity, ContentEncoding::Gzip];
        // Only gzip mentioned; identity is implicitly acceptable
        let best = negotiate_encoding(Some("gzip;q=0.5"), supported);
        // Identity gets implicit q=1.0, gzip gets q=0.5
        assert_eq!(best, Some(ContentEncoding::Identity));
    }

    #[test]
    fn negotiate_identity_explicitly_rejected() {
        let supported = &[ContentEncoding::Identity, ContentEncoding::Gzip];
        let best = negotiate_encoding(Some("identity;q=0, gzip;q=1.0"), supported);
        assert_eq!(best, Some(ContentEncoding::Gzip));
    }

    #[test]
    fn negotiate_identity_default_preferred_over_wildcard_quality() {
        let supported = &[ContentEncoding::Brotli, ContentEncoding::Identity];
        let best = negotiate_encoding(Some("*;q=0.5"), supported);
        // Brotli inherits wildcard q=0.5. Identity keeps its RFC 9110 §12.5.3
        // default q=1.0 — the wildcard only excludes identity at *;q=0.
        assert_eq!(best, Some(ContentEncoding::Identity));
    }

    #[test]
    fn negotiate_wildcard_only_identity_keeps_default() {
        // Regression: *;q=0.5 must NOT lower identity from its RFC default 1.0.
        let supported = &[ContentEncoding::Gzip, ContentEncoding::Identity];
        let best = negotiate_encoding(Some("*;q=0.5"), supported);
        // identity q=1.0 (default) > gzip q=0.5 (from wildcard)
        assert_eq!(best, Some(ContentEncoding::Identity));
    }

    #[test]
    fn negotiate_zero_wildcard_rejects_implicit_identity() {
        let supported = &[ContentEncoding::Identity];
        let best = negotiate_encoding(Some("*;q=0"), supported);
        assert_eq!(best, None);
    }

    #[test]
    fn negotiate_identity_default_without_wildcard() {
        // No wildcard at all: identity gets its RFC default q=1.0
        let supported = &[ContentEncoding::Gzip, ContentEncoding::Identity];
        let best = negotiate_encoding(Some("gzip;q=0.8"), supported);
        assert_eq!(best, Some(ContentEncoding::Identity));
    }

    #[test]
    fn negotiate_explicit_identity_overrides_wildcard() {
        // Explicit identity;q=1.0 takes priority over *;q=0.5
        let supported = &[ContentEncoding::Gzip, ContentEncoding::Identity];
        let best = negotiate_encoding(Some("identity;q=1.0, *;q=0.5"), supported);
        assert_eq!(best, Some(ContentEncoding::Identity));
    }

    #[test]
    fn negotiate_wildcard_does_not_lower_identity_default() {
        // RFC 9110 §12.5.3: identity is acceptable by default (q=1.0)
        // unless excluded by *;q=0. *;q=0.3 does NOT lower identity.
        let supported = &[ContentEncoding::Identity];
        let best = negotiate_encoding(Some("*;q=0.3"), supported);
        assert_eq!(best, Some(ContentEncoding::Identity));
        // Identity keeps q=1.0 even when wildcard is lower
        let supported2 = &[ContentEncoding::Gzip, ContentEncoding::Identity];
        let best2 = negotiate_encoding(Some("gzip;q=0.5, *;q=0.3"), supported2);
        // identity q=1.0 (default) > gzip q=0.5
        assert_eq!(best2, Some(ContentEncoding::Identity));
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

    #[test]
    fn identity_decompressor_overflow_is_rejected() {
        let mut dec = IdentityDecompressor {
            max_size: None,
            total: usize::MAX,
        };
        let mut output = Vec::new();
        let result = dec.decompress(b"x", &mut output);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(output.is_empty());
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
        let cloned = gz;
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
        let c = IdentityCompressor;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("IdentityCompressor"), "{dbg}");
    }

    #[test]
    fn identity_decompressor_debug_default() {
        let d = IdentityDecompressor::default();
        let dbg = format!("{d:?}");
        assert!(dbg.contains("IdentityDecompressor"), "{dbg}");
    }

    // ====================================================================
    // make_compressor factory tests
    // ====================================================================

    #[test]
    fn make_compressor_identity() {
        let comp = make_compressor(ContentEncoding::Identity);
        assert!(comp.is_some());
        assert_eq!(comp.unwrap().encoding(), ContentEncoding::Identity);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn make_compressor_brotli() {
        let comp = make_compressor(ContentEncoding::Brotli);
        assert!(comp.is_some());
        assert_eq!(comp.unwrap().encoding(), ContentEncoding::Brotli);
    }

    #[cfg(not(feature = "compression"))]
    #[test]
    fn make_compressor_brotli_unsupported() {
        let comp = make_compressor(ContentEncoding::Brotli);
        assert!(comp.is_none());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn make_compressor_gzip() {
        let comp = make_compressor(ContentEncoding::Gzip);
        assert!(comp.is_some());
        assert_eq!(comp.unwrap().encoding(), ContentEncoding::Gzip);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn make_compressor_deflate() {
        let comp = make_compressor(ContentEncoding::Deflate);
        assert!(comp.is_some());
        assert_eq!(comp.unwrap().encoding(), ContentEncoding::Deflate);
    }

    // ====================================================================
    // Gzip compressor/decompressor tests
    // ====================================================================

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_decompressor_state_across_chunks() {
        let input = b"Hello, World! Here is some data to compress and decompress in chunks.";
        let mut compressor = GzipCompressor::new();
        let mut compressed = Vec::new();
        compressor.compress(input, &mut compressed).unwrap();
        compressor.finish(&mut compressed).unwrap();

        let mut decompressor = GzipDecompressor::new(None);
        let mut decompressed = Vec::new();

        for chunk in compressed.chunks(5) {
            decompressor.decompress(chunk, &mut decompressed).unwrap();
        }
        decompressor.finish(&mut decompressed).unwrap();

        assert_eq!(decompressed, input);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_compress_decompress_roundtrip() {
        let input = b"Hello, World! This is a test of gzip compression.";
        let mut comp = GzipCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(input, &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        // Compressed data should be non-empty and different from input.
        assert!(!compressed.is_empty());

        // Decompress and verify roundtrip.
        let mut dec = GzipDecompressor::new(None);
        let mut decompressed = Vec::new();
        dec.decompress(&compressed, &mut decompressed).unwrap();
        dec.finish(&mut decompressed).unwrap();
        assert_eq!(&decompressed, input);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_empty_input() {
        let mut comp = GzipCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(b"", &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        let mut dec = GzipDecompressor::new(None);
        let mut decompressed = Vec::new();
        dec.decompress(&compressed, &mut decompressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_compressor_default() {
        let comp = GzipCompressor::default();
        assert_eq!(comp.encoding(), ContentEncoding::Gzip);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_decompressor_size_limit() {
        let input = b"Hello, World! This is a test of gzip compression.";
        let mut comp = GzipCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(input, &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        let mut dec = GzipDecompressor::new(Some(10));
        let mut decompressed = Vec::new();
        let result = dec.decompress(&compressed, &mut decompressed);
        assert!(result.is_err());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_decompressor_overflow_is_rejected() {
        let mut comp = GzipCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(b"x", &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        let mut dec = GzipDecompressor {
            max_size: None,
            total: usize::MAX,
            decoder: flate2::write::GzDecoder::new(Vec::new()),
        };
        let mut decompressed = Vec::new();
        let result = dec.decompress(&compressed, &mut decompressed);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(decompressed.is_empty());
    }

    // ====================================================================
    // Deflate compressor/decompressor tests
    // ====================================================================

    #[cfg(feature = "compression")]
    #[test]
    fn deflate_decompressor_state_across_chunks() {
        let input = b"Hello, World! Here is some data to compress and decompress in chunks.";
        let mut compressor = DeflateCompressor::new();
        let mut compressed = Vec::new();
        compressor.compress(input, &mut compressed).unwrap();
        compressor.finish(&mut compressed).unwrap();

        let mut decompressor = DeflateDecompressor::new(None);
        let mut decompressed = Vec::new();

        for chunk in compressed.chunks(5) {
            decompressor.decompress(chunk, &mut decompressed).unwrap();
        }
        decompressor.finish(&mut decompressed).unwrap();

        assert_eq!(decompressed, input);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn deflate_compress_decompress_roundtrip() {
        let input = b"Hello, World! This is a test of deflate compression.";
        let mut comp = DeflateCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(input, &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        assert!(!compressed.is_empty());

        let mut dec = DeflateDecompressor::new(None);
        let mut decompressed = Vec::new();
        dec.decompress(&compressed, &mut decompressed).unwrap();
        dec.finish(&mut decompressed).unwrap();
        assert_eq!(&decompressed, input);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn deflate_empty_input() {
        let mut comp = DeflateCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(b"", &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        let mut dec = DeflateDecompressor::new(None);
        let mut decompressed = Vec::new();
        dec.decompress(&compressed, &mut decompressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn deflate_compressor_default() {
        let comp = DeflateCompressor::default();
        assert_eq!(comp.encoding(), ContentEncoding::Deflate);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn deflate_decompressor_size_limit() {
        let input = b"Hello, World! This is a test of deflate compression.";
        let mut comp = DeflateCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(input, &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        let mut dec = DeflateDecompressor::new(Some(10));
        let mut decompressed = Vec::new();
        let result = dec.decompress(&compressed, &mut decompressed);
        assert!(result.is_err());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn deflate_decompressor_overflow_is_rejected() {
        let mut comp = DeflateCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(b"x", &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        let mut dec = DeflateDecompressor {
            max_size: None,
            total: usize::MAX,
            decoder: flate2::write::DeflateDecoder::new(Vec::new()),
        };
        let mut decompressed = Vec::new();
        let result = dec.decompress(&compressed, &mut decompressed);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(decompressed.is_empty());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_compresses_repetitive_data() {
        // Repetitive data should compress significantly.
        let input: Vec<u8> = "aaaa".repeat(1000).into_bytes();
        let mut comp = GzipCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(&input, &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();
        assert!(
            compressed.len() < input.len() / 2,
            "gzip should compress repetitive data: {} -> {}",
            input.len(),
            compressed.len()
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn deflate_compresses_repetitive_data() {
        let input: Vec<u8> = "bbbb".repeat(1000).into_bytes();
        let mut comp = DeflateCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(&input, &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();
        assert!(
            compressed.len() < input.len() / 2,
            "deflate should compress repetitive data: {} -> {}",
            input.len(),
            compressed.len()
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_compresses_repetitive_data_chunked() {
        let input: Vec<u8> = "aaaa".repeat(1000).into_bytes();
        let mut comp = GzipCompressor::new();
        let mut compressed = Vec::new();
        for chunk in input.chunks(10) {
            comp.compress(chunk, &mut compressed).unwrap();
        }
        comp.finish(&mut compressed).unwrap();
        assert!(
            compressed.len() < input.len() / 2,
            "gzip should compress chunked repetitive data efficiently: {} -> {}",
            input.len(),
            compressed.len()
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_double_finish_is_idempotent() {
        // Regression: calling finish() twice used to append a spurious
        // empty gzip stream, corrupting the output.
        let mut comp = GzipCompressor::new();
        let mut out = Vec::new();
        comp.compress(b"hello", &mut out).unwrap();
        comp.finish(&mut out).unwrap();
        let len_after_first = out.len();
        comp.finish(&mut out).unwrap();
        assert_eq!(
            out.len(),
            len_after_first,
            "second finish must not append extra bytes"
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn deflate_double_finish_is_idempotent() {
        let mut comp = DeflateCompressor::new();
        let mut out = Vec::new();
        comp.compress(b"hello", &mut out).unwrap();
        comp.finish(&mut out).unwrap();
        let len_after_first = out.len();
        comp.finish(&mut out).unwrap();
        assert_eq!(
            out.len(),
            len_after_first,
            "second finish must not append extra bytes"
        );
    }

    // ====================================================================
    // Brotli compressor/decompressor tests
    // ====================================================================

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_decompressor_state_across_chunks() {
        let input = b"Hello, World! Here is some data to compress and decompress in chunks.";
        let mut compressor = BrotliCompressor::new();
        let mut compressed = Vec::new();
        compressor.compress(input, &mut compressed).unwrap();
        compressor.finish(&mut compressed).unwrap();

        let mut decompressor = BrotliDecompressor::new(None);
        let mut decompressed = Vec::new();

        for chunk in compressed.chunks(5) {
            decompressor.decompress(chunk, &mut decompressed).unwrap();
        }
        decompressor.finish(&mut decompressed).unwrap();

        assert_eq!(decompressed, input);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_compress_decompress_roundtrip() {
        let input = b"Hello, World! This is a test of brotli compression.";
        let mut comp = BrotliCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(input, &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        assert!(!compressed.is_empty());

        let mut dec = BrotliDecompressor::new(None);
        let mut decompressed = Vec::new();
        dec.decompress(&compressed, &mut decompressed).unwrap();
        dec.finish(&mut decompressed).unwrap();
        assert_eq!(&decompressed, input);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_empty_input() {
        let mut comp = BrotliCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(b"", &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        let mut dec = BrotliDecompressor::new(None);
        let mut decompressed = Vec::new();
        dec.decompress(&compressed, &mut decompressed).unwrap();
        dec.finish(&mut decompressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_compressor_default() {
        let comp = BrotliCompressor::default();
        assert_eq!(comp.encoding(), ContentEncoding::Brotli);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_decompressor_size_limit() {
        let input = b"Hello, World! This is a test of brotli compression.";
        let mut comp = BrotliCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(input, &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        let mut dec = BrotliDecompressor::new(Some(10));
        let mut decompressed = Vec::new();
        let result = dec.decompress(&compressed, &mut decompressed);
        assert!(result.is_err());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_decompressor_overflow_is_rejected() {
        let mut comp = BrotliCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(b"x", &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();

        let mut dec = BrotliDecompressor {
            max_size: None,
            total: usize::MAX,
            decoder: brotli::DecompressorWriter::new(Vec::new(), BROTLI_BUFFER_SIZE),
            finished: false,
        };
        let mut decompressed = Vec::new();
        let result = dec.decompress(&compressed, &mut decompressed);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(decompressed.is_empty());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_compresses_repetitive_data() {
        let input: Vec<u8> = "cccc".repeat(1000).into_bytes();
        let mut comp = BrotliCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(&input, &mut compressed).unwrap();
        comp.finish(&mut compressed).unwrap();
        assert!(
            compressed.len() < input.len() / 2,
            "brotli should compress repetitive data: {} -> {}",
            input.len(),
            compressed.len()
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_double_finish_is_idempotent() {
        let mut comp = BrotliCompressor::new();
        let mut out = Vec::new();
        comp.compress(b"hello", &mut out).unwrap();
        comp.finish(&mut out).unwrap();
        let len_after_first = out.len();
        comp.finish(&mut out).unwrap();
        assert_eq!(
            out.len(),
            len_after_first,
            "second finish must not append extra bytes"
        );
    }
}
