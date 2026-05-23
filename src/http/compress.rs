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

/// Default maximum compressed response body size produced by HTTP helpers.
///
/// This is intentionally generous for normal web responses while still
/// preventing unbounded growth when compression is applied to hostile or
/// unusually expansion-prone payloads.
pub const DEFAULT_MAX_COMPRESSED_SIZE: usize = 16 * 1024 * 1024;

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
    #[inline]
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
        // br-asupersync-ipsu2a: match Accept-Encoding tokens against the
        // canonical encoding via from_token rather than equality on as_token's
        // canonical name. Otherwise legacy aliases (e.g. RFC 7230 §4.2 lists
        // "x-gzip" as a deprecated-but-valid synonym for "gzip") never bind to
        // their target ContentEncoding and silently fall through to wildcard.
        let explicit_quality = preferences
            .iter()
            .find(|q| ContentEncoding::from_token(&q.encoding) == Some(encoding))
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

/// Identity compressor variant that enforces an output size cap.
#[derive(Debug)]
struct LimitedIdentityCompressor {
    max_size: usize,
    emitted: usize,
}

impl LimitedIdentityCompressor {
    const fn new(max_size: usize) -> Self {
        Self {
            max_size,
            emitted: 0,
        }
    }
}

impl Compressor for LimitedIdentityCompressor {
    fn compress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let next_emitted = self
            .emitted
            .checked_add(input.len())
            .ok_or_else(|| limit_error("compressed size exceeds limit"))?;
        if next_emitted > self.max_size {
            return Err(limit_error("compressed size exceeds limit"));
        }
        output.extend_from_slice(input);
        self.emitted = next_emitted;
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

/// A writer that wraps a `Vec<u8>` and strictly limits its maximum size.
/// This prevents compression/decompression bomb attacks by returning an
/// error before unbounded memory allocation occurs.
#[derive(Debug)]
#[cfg(feature = "compression")]
#[allow(dead_code)]
struct LimitedWriter {
    inner: Vec<u8>,
    max_size: Option<usize>,
    limit_error: &'static str,
}

#[cfg(feature = "compression")]
#[allow(dead_code)]
impl LimitedWriter {
    fn new(max_size: Option<usize>) -> Self {
        Self::with_error(max_size, "decompressed size exceeds limit")
    }

    fn for_compressed_output(max_size: Option<usize>) -> Self {
        Self::with_error(max_size, "compressed size exceeds limit")
    }

    fn with_error(max_size: Option<usize>, limit_error: &'static str) -> Self {
        Self {
            inner: Vec::new(),
            max_size,
            limit_error,
        }
    }
}

#[cfg(feature = "compression")]
impl Default for LimitedWriter {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(feature = "compression")]
impl io::Write for LimitedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(max) = self.max_size {
            let next_len = self
                .inner
                .len()
                .checked_add(buf.len())
                .ok_or_else(|| limit_error(self.limit_error))?;
            if next_len > max {
                return Err(limit_error(self.limit_error));
            }
        }
        self.inner.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "compression")]
const BROTLI_BUFFER_SIZE: usize = 4096;

#[cfg(feature = "compression")]
const BROTLI_DEFAULT_QUALITY: u32 = 5;

#[cfg(feature = "compression")]
const BROTLI_DEFAULT_LGWIN: u32 = 22;

fn limit_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(feature = "compression")]
fn remaining_limit(max_size: Option<usize>, emitted: usize) -> Option<usize> {
    max_size.map(|max| max.saturating_sub(emitted))
}

#[cfg(feature = "compression")]
fn append_limited_output(
    output: &mut Vec<u8>,
    chunk: &mut Vec<u8>,
    emitted: &mut usize,
    max_size: Option<usize>,
) -> io::Result<()> {
    let next_emitted = emitted
        .checked_add(chunk.len())
        .ok_or_else(|| limit_error("compressed size exceeds limit"))?;
    if let Some(max) = max_size {
        if next_emitted > max {
            return Err(limit_error("compressed size exceeds limit"));
        }
    }
    output.append(chunk);
    *emitted = next_emitted;
    Ok(())
}

// ─── Gzip Compressor ────────────────────────────────────────────────────────

/// Gzip compressor using the flate2 (miniz_oxide) backend.
///
/// Compresses data in RFC 1952 gzip format. Uses compression level 6
/// (default) which provides a good balance of speed and ratio.
#[cfg(feature = "compression")]
pub struct GzipCompressor {
    encoder: flate2::write::GzEncoder<LimitedWriter>,
    max_size: Option<usize>,
    emitted: usize,
    finished: bool,
}

#[cfg(feature = "compression")]
impl GzipCompressor {
    /// Create a new gzip compressor with the default compression level.
    #[must_use]
    pub fn new() -> Self {
        Self::with_level(flate2::Compression::default())
    }

    /// Create a new gzip compressor with a compressed output size limit.
    #[must_use]
    pub fn with_output_limit(max_size: Option<usize>) -> Self {
        Self::with_level_and_output_limit(flate2::Compression::default(), max_size)
    }

    /// Create a new gzip compressor with the specified compression level.
    #[must_use]
    pub fn with_level(level: flate2::Compression) -> Self {
        Self::with_level_and_output_limit(level, None)
    }

    /// Create a new gzip compressor with the specified compression level and
    /// compressed output size limit.
    #[must_use]
    pub fn with_level_and_output_limit(
        level: flate2::Compression,
        max_size: Option<usize>,
    ) -> Self {
        Self {
            encoder: flate2::write::GzEncoder::new(
                LimitedWriter::for_compressed_output(max_size),
                level,
            ),
            max_size,
            emitted: 0,
            finished: false,
        }
    }

    fn refresh_remaining_limit(&mut self) {
        self.encoder.get_mut().max_size = remaining_limit(self.max_size, self.emitted);
    }

    fn drain_output_buffer(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        let mut buf = std::mem::take(&mut self.encoder.get_mut().inner);
        append_limited_output(output, &mut buf, &mut self.emitted, self.max_size)
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
        self.refresh_remaining_limit();
        self.encoder.write_all(input)?;
        self.drain_output_buffer(output)
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        if self.finished {
            return Ok(());
        }
        self.refresh_remaining_limit();
        self.encoder.flush()?;
        self.refresh_remaining_limit();
        // Take the inner buffer, reset encoder with a new empty vec.
        let inner = std::mem::replace(
            &mut self.encoder,
            flate2::write::GzEncoder::new(
                LimitedWriter::for_compressed_output(None),
                flate2::Compression::none(),
            ),
        );
        let mut finished = inner.finish()?.inner;
        append_limited_output(output, &mut finished, &mut self.emitted, self.max_size)?;
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
    decoder: flate2::write::GzDecoder<LimitedWriter>,
    /// br-asupersync-8vcp64: once any error path runs, no further calls
    /// to decompress/finish are accepted. Without this flag, a caller
    /// that ignored the first error and called decompress again would
    /// drain stale bytes the decoder produced before the bomb-cap rejection
    /// (via `mem::take` of the LimitedWriter's inner buffer), and update
    /// self.total for them — letting an attacker smuggle bytes past the
    /// cap by triggering a near-cap error then continuing.
    poisoned: bool,
}

#[cfg(feature = "compression")]
impl GzipDecompressor {
    /// Create a new gzip decompressor with an optional size limit.
    #[must_use]
    pub fn new(max_size: Option<usize>) -> Self {
        Self {
            max_size,
            total: 0,
            decoder: flate2::write::GzDecoder::new(LimitedWriter::new(max_size)),
            poisoned: false,
        }
    }
}

#[cfg(feature = "compression")]
impl Decompressor for GzipDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "GzipDecompressor poisoned by prior error (br-asupersync-8vcp64)",
            ));
        }
        use io::Write;

        let remaining = self.max_size.map(|m| m.saturating_sub(self.total));
        self.decoder.get_mut().max_size = remaining;

        // Run the decompression as a fallible inner expression; on any error,
        // mark poisoned and clear stale partial bytes from the inner buffer.
        let result: io::Result<()> = (|| {
            self.decoder.write_all(input)?;
            self.decoder.flush()?;
            let mut buf = std::mem::take(&mut self.decoder.get_mut().inner);
            update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
            output.append(&mut buf);
            Ok(())
        })();
        if let Err(e) = result {
            self.poisoned = true;
            self.decoder.get_mut().inner.clear();
            return Err(e);
        }
        Ok(())
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "GzipDecompressor poisoned by prior error (br-asupersync-8vcp64)",
            ));
        }
        let mut finishing_decoder = flate2::write::GzDecoder::new(LimitedWriter::new(None));
        std::mem::swap(&mut self.decoder, &mut finishing_decoder);
        finishing_decoder.get_mut().max_size = self.max_size.map(|m| m.saturating_sub(self.total));

        let result: io::Result<()> = (|| {
            let mut buf = finishing_decoder.finish()?.inner;
            update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
            output.append(&mut buf);
            Ok(())
        })();
        if let Err(e) = result {
            self.poisoned = true;
            return Err(e);
        }
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
    encoder: flate2::write::DeflateEncoder<LimitedWriter>,
    max_size: Option<usize>,
    emitted: usize,
    finished: bool,
}

#[cfg(feature = "compression")]
impl DeflateCompressor {
    /// Create a new deflate compressor with the default compression level.
    #[must_use]
    pub fn new() -> Self {
        Self::with_level(flate2::Compression::default())
    }

    /// Create a new deflate compressor with a compressed output size limit.
    #[must_use]
    pub fn with_output_limit(max_size: Option<usize>) -> Self {
        Self::with_level_and_output_limit(flate2::Compression::default(), max_size)
    }

    /// Create a new deflate compressor with the specified compression level.
    #[must_use]
    pub fn with_level(level: flate2::Compression) -> Self {
        Self::with_level_and_output_limit(level, None)
    }

    /// Create a new deflate compressor with the specified compression level
    /// and compressed output size limit.
    #[must_use]
    pub fn with_level_and_output_limit(
        level: flate2::Compression,
        max_size: Option<usize>,
    ) -> Self {
        Self {
            encoder: flate2::write::DeflateEncoder::new(
                LimitedWriter::for_compressed_output(max_size),
                level,
            ),
            max_size,
            emitted: 0,
            finished: false,
        }
    }

    fn refresh_remaining_limit(&mut self) {
        self.encoder.get_mut().max_size = remaining_limit(self.max_size, self.emitted);
    }

    fn drain_output_buffer(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        let mut buf = std::mem::take(&mut self.encoder.get_mut().inner);
        append_limited_output(output, &mut buf, &mut self.emitted, self.max_size)
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
        self.refresh_remaining_limit();
        self.encoder.write_all(input)?;
        self.drain_output_buffer(output)
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.refresh_remaining_limit();
        let inner = std::mem::replace(
            &mut self.encoder,
            flate2::write::DeflateEncoder::new(
                LimitedWriter::for_compressed_output(None),
                flate2::Compression::none(),
            ),
        );
        let mut finished = inner.finish()?.inner;
        append_limited_output(output, &mut finished, &mut self.emitted, self.max_size)?;
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
    decoder: flate2::write::DeflateDecoder<LimitedWriter>,
    /// br-asupersync-8vcp64: see [`GzipDecompressor::poisoned`].
    poisoned: bool,
}

#[cfg(feature = "compression")]
impl DeflateDecompressor {
    /// Create a new deflate decompressor with an optional size limit.
    #[must_use]
    pub fn new(max_size: Option<usize>) -> Self {
        Self {
            max_size,
            total: 0,
            decoder: flate2::write::DeflateDecoder::new(LimitedWriter::new(max_size)),
            poisoned: false,
        }
    }
}

#[cfg(feature = "compression")]
impl Decompressor for DeflateDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "DeflateDecompressor poisoned by prior error (br-asupersync-8vcp64)",
            ));
        }
        use io::Write;

        let remaining = self.max_size.map(|m| m.saturating_sub(self.total));
        self.decoder.get_mut().max_size = remaining;

        let result: io::Result<()> = (|| {
            self.decoder.write_all(input)?;
            self.decoder.flush()?;
            let mut buf = std::mem::take(&mut self.decoder.get_mut().inner);
            update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
            output.append(&mut buf);
            Ok(())
        })();
        if let Err(e) = result {
            self.poisoned = true;
            self.decoder.get_mut().inner.clear();
            return Err(e);
        }
        Ok(())
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "DeflateDecompressor poisoned by prior error (br-asupersync-8vcp64)",
            ));
        }
        let mut finishing_decoder = flate2::write::DeflateDecoder::new(LimitedWriter::new(None));
        std::mem::swap(&mut self.decoder, &mut finishing_decoder);
        finishing_decoder.get_mut().max_size = self.max_size.map(|m| m.saturating_sub(self.total));

        let result: io::Result<()> = (|| {
            let mut buf = finishing_decoder.finish()?.inner;
            update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
            output.append(&mut buf);
            Ok(())
        })();
        if let Err(e) = result {
            self.poisoned = true;
            return Err(e);
        }
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
    encoder: brotli::CompressorWriter<LimitedWriter>,
    max_size: Option<usize>,
    emitted: usize,
    finished: bool,
}

#[cfg(feature = "compression")]
impl BrotliCompressor {
    /// Create a new Brotli compressor with balanced HTTP-oriented defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::with_params(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_LGWIN)
    }

    /// Create a new Brotli compressor with a compressed output size limit.
    #[must_use]
    pub fn with_output_limit(max_size: Option<usize>) -> Self {
        Self::with_params_and_output_limit(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_LGWIN, max_size)
    }

    /// Create a new Brotli compressor with explicit quality and window.
    #[must_use]
    pub fn with_params(quality: u32, lgwin: u32) -> Self {
        Self::with_params_and_output_limit(quality, lgwin, None)
    }

    /// Create a new Brotli compressor with explicit quality, window, and
    /// compressed output size limit.
    #[must_use]
    pub fn with_params_and_output_limit(quality: u32, lgwin: u32, max_size: Option<usize>) -> Self {
        Self {
            encoder: brotli::CompressorWriter::new(
                LimitedWriter::for_compressed_output(max_size),
                BROTLI_BUFFER_SIZE,
                quality,
                lgwin,
            ),
            max_size,
            emitted: 0,
            finished: false,
        }
    }

    fn refresh_remaining_limit(&mut self) {
        self.encoder.get_mut().max_size = remaining_limit(self.max_size, self.emitted);
    }

    fn drain_output_buffer(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        let mut buf = std::mem::take(&mut self.encoder.get_mut().inner);
        append_limited_output(output, &mut buf, &mut self.emitted, self.max_size)
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
        self.refresh_remaining_limit();
        self.encoder.write_all(input)?;
        self.refresh_remaining_limit();
        self.encoder.flush()?;
        self.drain_output_buffer(output)
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        use io::Write;
        if self.finished {
            return Ok(());
        }
        self.refresh_remaining_limit();
        self.encoder.flush()?;
        self.refresh_remaining_limit();
        let finished = std::mem::replace(
            &mut self.encoder,
            brotli::CompressorWriter::new(
                LimitedWriter::for_compressed_output(None),
                BROTLI_BUFFER_SIZE,
                BROTLI_DEFAULT_QUALITY,
                BROTLI_DEFAULT_LGWIN,
            ),
        )
        .into_inner();
        let mut finished = finished.inner;
        append_limited_output(output, &mut finished, &mut self.emitted, self.max_size)?;
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
    decoder: brotli::DecompressorWriter<LimitedWriter>,
    finished: bool,
    /// br-asupersync-8vcp64: see [`GzipDecompressor::poisoned`].
    poisoned: bool,
}

#[cfg(feature = "compression")]
impl BrotliDecompressor {
    /// Create a new Brotli decompressor with an optional size limit.
    #[must_use]
    pub fn new(max_size: Option<usize>) -> Self {
        Self {
            max_size,
            total: 0,
            decoder: brotli::DecompressorWriter::new(
                LimitedWriter::new(max_size),
                BROTLI_BUFFER_SIZE,
            ),
            finished: false,
            poisoned: false,
        }
    }
}

#[cfg(feature = "compression")]
impl Decompressor for BrotliDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "BrotliDecompressor poisoned by prior error (br-asupersync-8vcp64)",
            ));
        }
        use io::Write;

        let remaining = self.max_size.map(|m| m.saturating_sub(self.total));
        self.decoder.get_mut().max_size = remaining;

        let result: io::Result<()> = (|| {
            self.decoder.write_all(input)?;
            self.decoder.flush()?;
            let mut buf = std::mem::take(&mut self.decoder.get_mut().inner);
            update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
            output.append(&mut buf);
            Ok(())
        })();
        if let Err(e) = result {
            self.poisoned = true;
            self.decoder.get_mut().inner.clear();
            return Err(e);
        }
        Ok(())
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "BrotliDecompressor poisoned by prior error (br-asupersync-8vcp64)",
            ));
        }
        use io::Write;
        if self.finished {
            return Ok(());
        }

        let remaining = self.max_size.map(|m| m.saturating_sub(self.total));
        self.decoder.get_mut().max_size = remaining;

        let result: io::Result<()> = (|| {
            self.decoder.flush()?;
            self.decoder.close()?;
            let mut buf = std::mem::take(&mut self.decoder.get_mut().inner);
            update_decompressed_total(&mut self.total, buf.len(), self.max_size)?;
            output.append(&mut buf);
            Ok(())
        })();
        if let Err(e) = result {
            self.poisoned = true;
            self.decoder.get_mut().inner.clear();
            return Err(e);
        }
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
    make_compressor_with_output_limit(encoding, None)
}

/// Create a compressor for the given encoding with an optional output limit.
///
/// The limit is enforced by the codec's underlying writer before its internal
/// buffer grows past the configured size.
#[must_use]
pub fn make_compressor_with_output_limit(
    encoding: ContentEncoding,
    max_size: Option<usize>,
) -> Option<Box<dyn Compressor>> {
    match encoding {
        ContentEncoding::Identity => match max_size {
            Some(max_size) => Some(Box::new(LimitedIdentityCompressor::new(max_size))),
            None => Some(Box::new(IdentityCompressor)),
        },
        #[cfg(feature = "compression")]
        ContentEncoding::Gzip => Some(Box::new(GzipCompressor::with_output_limit(max_size))),
        #[cfg(feature = "compression")]
        ContentEncoding::Deflate => Some(Box::new(DeflateCompressor::with_output_limit(max_size))),
        #[cfg(feature = "compression")]
        ContentEncoding::Brotli => Some(Box::new(BrotliCompressor::with_output_limit(max_size))),
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn assert_quality(actual: f32, expected: f32) {
        let delta = (actual - expected).abs();
        assert!(
            delta <= f32::EPSILON,
            "quality mismatch: expected {expected}, got {actual}"
        );
    }

    #[cfg(feature = "compression")]
    #[derive(Debug)]
    struct GzipBoundaryOutcome {
        output: Vec<u8>,
        error_kind: &'static str,
        error_stage: &'static str,
    }

    #[cfg(feature = "compression")]
    fn gzip_member_bytes(input: &[u8]) -> Vec<u8> {
        let mut compressor = GzipCompressor::new();
        let mut compressed = Vec::new();
        compressor.compress(input, &mut compressed).unwrap();
        compressor.finish(&mut compressed).unwrap();
        compressed
    }

    #[cfg(feature = "compression")]
    fn gzip_trailer_fields_for_log(input: &[u8]) -> String {
        if input.len() < 8 {
            return "none".to_string();
        }

        let trailer = &input[input.len() - 8..];
        let crc32 = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        let isize = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
        format!("crc32=0x{crc32:08x},isize={isize}")
    }

    #[cfg(feature = "compression")]
    fn gzip_error_kind_for_log(error: &io::Error) -> &'static str {
        match error.kind() {
            io::ErrorKind::InvalidData => "InvalidData",
            io::ErrorKind::InvalidInput => "InvalidInput",
            io::ErrorKind::UnexpectedEof => "UnexpectedEof",
            io::ErrorKind::WriteZero => "WriteZero",
            io::ErrorKind::Other => "Other",
            _ => "OtherKind",
        }
    }

    #[cfg(feature = "compression")]
    fn run_gzip_boundary_case(input: &[u8], max_size: Option<usize>) -> GzipBoundaryOutcome {
        let mut decompressor = GzipDecompressor::new(max_size);
        let mut output = Vec::new();

        match decompressor.decompress(input, &mut output) {
            Ok(()) => match decompressor.finish(&mut output) {
                Ok(()) => GzipBoundaryOutcome {
                    output,
                    error_kind: "ok",
                    error_stage: "ok",
                },
                Err(error) => GzipBoundaryOutcome {
                    output,
                    error_kind: gzip_error_kind_for_log(&error),
                    error_stage: "finish",
                },
            },
            Err(error) => {
                let _ = decompressor.finish(&mut output);
                GzipBoundaryOutcome {
                    output,
                    error_kind: gzip_error_kind_for_log(&error),
                    error_stage: "decompress",
                }
            }
        }
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

    /// br-asupersync-ipsu2a: negotiate_encoding must bind the legacy
    /// `x-gzip` Accept-Encoding token to ContentEncoding::Gzip. Previously
    /// `q.encoding == as_token()` ("gzip") never matched the
    /// preference's encoding string ("x-gzip") so the server fell through
    /// to identity, dropping a legitimate gzip request.
    ///
    /// RFC 9110 §12.5.3: identity is acceptable by default at q=1.0 unless
    /// excluded by `*;q=0` or `identity;q=0`. So a bare "x-gzip" request
    /// (without disabling identity) ties with identity at q=1.0 and
    /// identity wins by listing order. To verify alias matching, exclude
    /// identity OR ask for x-gzip at higher quality.
    #[test]
    fn ipsu2a_negotiate_x_gzip_with_identity_excluded_picks_gzip() {
        let supported = &[ContentEncoding::Identity, ContentEncoding::Gzip];
        let chosen = negotiate_encoding(Some("x-gzip, identity;q=0"), supported);
        assert_eq!(
            chosen,
            Some(ContentEncoding::Gzip),
            "with identity excluded, x-gzip alias must bind to Gzip per RFC 7230 §4.2"
        );
    }

    #[test]
    fn ipsu2a_negotiate_x_gzip_via_wildcard_zero_picks_gzip() {
        let supported = &[ContentEncoding::Identity, ContentEncoding::Gzip];
        // *;q=0 disables identity per RFC 9110 §12.5.3.
        let chosen = negotiate_encoding(Some("x-gzip;q=1.0, *;q=0"), supported);
        assert_eq!(
            chosen,
            Some(ContentEncoding::Gzip),
            "with wildcard at q=0, x-gzip alias must bind to Gzip"
        );
    }

    #[test]
    fn ipsu2a_negotiate_canonical_gzip_still_works_after_alias_change() {
        // Positive control: the canonical 'gzip' token must still resolve
        // to Gzip after the from_token-based alias matching change.
        let supported = &[ContentEncoding::Identity, ContentEncoding::Gzip];
        let chosen = negotiate_encoding(Some("gzip, identity;q=0"), supported);
        assert_eq!(chosen, Some(ContentEncoding::Gzip));
    }

    #[test]
    fn encoding_roundtrip() {
        for enc in [
            ContentEncoding::Identity,
            ContentEncoding::Gzip,
            ContentEncoding::Deflate,
            ContentEncoding::Brotli,
        ] {
            let token = enc.as_token(); // ubs:ignore - not a hardcoded secret // ubs:ignore - not a secret
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

    #[test]
    fn make_compressor_with_output_limit_caps_identity() {
        let mut comp = make_compressor_with_output_limit(ContentEncoding::Identity, Some(2))
            .expect("identity compressor should always be available");
        let mut output = Vec::new();

        comp.compress(b"ab", &mut output).unwrap();
        let result = comp.compress(b"c", &mut output);

        assert!(result.is_err());
        assert_eq!(output, b"ab");
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

    #[cfg(feature = "compression")]
    #[test]
    fn make_compressor_with_output_limit_rejects_before_output_growth() {
        for encoding in [
            ContentEncoding::Gzip,
            ContentEncoding::Deflate,
            ContentEncoding::Brotli,
        ] {
            let mut comp = make_compressor_with_output_limit(encoding, Some(1))
                .expect("feature-gated compressor should be available");
            let mut output = Vec::new();
            let result = comp
                .compress(b"expansion guard payload", &mut output)
                .and_then(|()| comp.finish(&mut output));

            assert!(
                result.is_err(),
                "{encoding} should reject output beyond configured cap"
            );
            assert!(
                output.len() <= 1,
                "{encoding} wrote {} bytes beyond the cap",
                output.len()
            );
        }
    }

    // ====================================================================
    // Gzip compressor/decompressor tests
    // ====================================================================

    /// br-asupersync-8vcp64: once a decompressor returns Err on any path,
    /// subsequent calls to decompress/finish must return an "already
    /// poisoned" error rather than silently producing stale partial bytes.
    #[cfg(feature = "compression")]
    #[test]
    fn vcp64_gzip_decompressor_poisoned_after_bomb_cap_rejection() {
        // Build a small but valid gzip payload, decompress with a tiny cap
        // that's smaller than the payload to force LimitedWriter::write to
        // reject; then verify a second call returns Err and does not drain
        // any bytes.
        let original = b"Hello, World! Some compressible text payload.";
        let mut compressor = GzipCompressor::new();
        let mut compressed = Vec::new();
        compressor.compress(original, &mut compressed).unwrap();
        compressor.finish(&mut compressed).unwrap();

        // Cap of 4 is well below the decompressed length (~45 bytes).
        let mut decompressor = GzipDecompressor::new(Some(4));
        let mut output = Vec::new();
        // First call must error out (cap exceeded).
        let first = decompressor.decompress(&compressed, &mut output);
        assert!(
            first.is_err(),
            "first call must reject by cap, got {first:?}"
        );

        // Second call MUST be rejected with the poisoned-error message and
        // MUST NOT push any further bytes into output.
        let len_before = output.len();
        let second = decompressor.decompress(&compressed, &mut output);
        match second {
            Err(e) => assert!(
                e.to_string().contains("poisoned"),
                "second call must surface poisoned-error, got: {e}"
            ),
            Ok(()) => panic!("second call must NOT succeed after first error"),
        }
        assert_eq!(
            output.len(),
            len_before,
            "second call must not append stale bytes after poisoning"
        );

        // finish() must also reject after poisoning.
        let after = decompressor.finish(&mut output);
        assert!(
            after.is_err() && after.as_ref().unwrap_err().to_string().contains("poisoned"),
            "finish() after poisoned must surface poisoned-error, got: {after:?}"
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn vcp64_deflate_decompressor_poisoned_after_bomb_cap_rejection() {
        let original = b"Hello, World! Some compressible payload for deflate.";
        let mut compressor = DeflateCompressor::new();
        let mut compressed = Vec::new();
        compressor.compress(original, &mut compressed).unwrap();
        compressor.finish(&mut compressed).unwrap();

        let mut decompressor = DeflateDecompressor::new(Some(4));
        let mut output = Vec::new();
        let first = decompressor.decompress(&compressed, &mut output);
        assert!(first.is_err());

        let len_before = output.len();
        let second = decompressor.decompress(&compressed, &mut output);
        match second {
            Err(e) => assert!(e.to_string().contains("poisoned")),
            Ok(()) => panic!("second call must NOT succeed after first error"),
        }
        assert_eq!(output.len(), len_before);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn vcp64_brotli_decompressor_poisoned_after_bomb_cap_rejection() {
        let original = b"Hello, World! Some compressible payload for brotli.";
        let mut compressor = BrotliCompressor::new();
        let mut compressed = Vec::new();
        compressor.compress(original, &mut compressed).unwrap();
        compressor.finish(&mut compressed).unwrap();

        let mut decompressor = BrotliDecompressor::new(Some(4));
        let mut output = Vec::new();
        let first = decompressor.decompress(&compressed, &mut output);
        assert!(first.is_err());

        let len_before = output.len();
        let second = decompressor.decompress(&compressed, &mut output);
        match second {
            Err(e) => assert!(e.to_string().contains("poisoned")),
            Ok(()) => panic!("second call must NOT succeed after first error"),
        }
        assert_eq!(output.len(), len_before);
    }

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
            decoder: flate2::write::GzDecoder::new(LimitedWriter::new(None)),
            poisoned: false,
        };
        let mut decompressed = Vec::new();
        let result = dec.decompress(&compressed, &mut decompressed);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(decompressed.is_empty());
    }

    /// Proves the HTTP gzip Content-Encoding seam fails closed on malformed
    /// header/trailer/bomb cases while preserving valid single-member output.
    #[cfg(feature = "compression")]
    #[test]
    fn conformance_gzip_content_encoding_boundary_matrix_logs_verdicts() {
        const EXACT_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_7t2qev_http_gzip cargo test -p asupersync --lib conformance_gzip_content_encoding_boundary_matrix_logs_verdicts --features compression -- --nocapture";

        let log_case = |corpus_label: &str,
                        compressed_len: usize,
                        declared_output_len: usize,
                        actual_output_len: usize,
                        ratio: Option<f64>,
                        cap_decision: &str,
                        trailer_fields: &str,
                        error_kind: &str,
                        error_stage: &str| {
            let ratio_field = ratio
                .map(|value| format!("{value:.3}"))
                .unwrap_or_else(|| "none".to_string());
            println!(
                "HTTP_GZIP_BOUNDARY \
                 corpus_label={} \
                 compressed_len={} \
                 declared_output_len={} \
                 actual_output_len={} \
                 ratio={} \
                 cap_decision={} \
                 trailer_fields={} \
                 error_kind={} \
                 error_stage={} \
                 exact_rch_command=\"{}\" \
                 artifact_paths=none \
                 final_bomb_malformed_rejection_verdict=pass",
                corpus_label,
                compressed_len,
                declared_output_len,
                actual_output_len,
                ratio_field,
                cap_decision,
                trailer_fields,
                error_kind,
                error_stage,
                EXACT_RCH_COMMAND,
            );
        };

        let success_plain = b"hello gzip world";
        let success_compressed = gzip_member_bytes(success_plain);
        let success = run_gzip_boundary_case(&success_compressed, None);
        assert_eq!(success.output, success_plain);
        assert_eq!(success.error_kind, "ok");
        log_case(
            "success_single_member",
            success_compressed.len(),
            success_plain.len(),
            success.output.len(),
            Some(success_plain.len() as f64 / success_compressed.len() as f64),
            "within-cap-accept",
            &gzip_trailer_fields_for_log(&success_compressed),
            success.error_kind,
            success.error_stage,
        );

        let empty_compressed = gzip_member_bytes(b"");
        let empty = run_gzip_boundary_case(&empty_compressed, None);
        assert!(empty.output.is_empty());
        assert_eq!(empty.error_kind, "ok");
        log_case(
            "empty_compressed_body",
            empty_compressed.len(),
            0,
            empty.output.len(),
            None,
            "within-cap-accept",
            &gzip_trailer_fields_for_log(&empty_compressed),
            empty.error_kind,
            empty.error_stage,
        );

        let mut malformed_header = success_compressed.clone();
        malformed_header[2] = 0xff;
        let malformed_header_outcome = run_gzip_boundary_case(&malformed_header, None);
        assert_ne!(malformed_header_outcome.error_kind, "ok");
        log_case(
            "malformed_header_invalid_method",
            malformed_header.len(),
            success_plain.len(),
            malformed_header_outcome.output.len(),
            Some(success_plain.len() as f64 / malformed_header.len() as f64),
            "within-cap-invalid-stream",
            &gzip_trailer_fields_for_log(&malformed_header),
            malformed_header_outcome.error_kind,
            malformed_header_outcome.error_stage,
        );

        let mut malformed_trailer = success_compressed.clone();
        let malformed_trailer_len = malformed_trailer.len();
        malformed_trailer[malformed_trailer_len - 8..].fill(0xff);
        let malformed_trailer_outcome = run_gzip_boundary_case(&malformed_trailer, None);
        assert_ne!(malformed_trailer_outcome.error_kind, "ok");
        log_case(
            "malformed_trailer_bytes",
            malformed_trailer.len(),
            success_plain.len(),
            malformed_trailer_outcome.output.len(),
            Some(success_plain.len() as f64 / malformed_trailer.len() as f64),
            "within-cap-invalid-stream",
            &gzip_trailer_fields_for_log(&malformed_trailer),
            malformed_trailer_outcome.error_kind,
            malformed_trailer_outcome.error_stage,
        );

        let mut crc_mismatch = success_compressed.clone();
        let crc_index = crc_mismatch.len() - 8;
        crc_mismatch[crc_index] ^= 0x01;
        let crc_outcome = run_gzip_boundary_case(&crc_mismatch, None);
        assert_ne!(crc_outcome.error_kind, "ok");
        log_case(
            "crc_mismatch",
            crc_mismatch.len(),
            success_plain.len(),
            crc_outcome.output.len(),
            Some(success_plain.len() as f64 / crc_mismatch.len() as f64),
            "within-cap-invalid-stream",
            &gzip_trailer_fields_for_log(&crc_mismatch),
            crc_outcome.error_kind,
            crc_outcome.error_stage,
        );

        let mut isize_mismatch = success_compressed.clone();
        let isize_index = isize_mismatch.len() - 4;
        isize_mismatch[isize_index] ^= 0x01;
        let isize_outcome = run_gzip_boundary_case(&isize_mismatch, None);
        assert_ne!(isize_outcome.error_kind, "ok");
        log_case(
            "isize_mismatch",
            isize_mismatch.len(),
            success_plain.len(),
            isize_outcome.output.len(),
            Some(success_plain.len() as f64 / isize_mismatch.len() as f64),
            "within-cap-invalid-stream",
            &gzip_trailer_fields_for_log(&isize_mismatch),
            isize_outcome.error_kind,
            isize_outcome.error_stage,
        );

        let truncated_stream = success_compressed[..success_compressed.len() - 3].to_vec();
        let truncated_outcome = run_gzip_boundary_case(&truncated_stream, None);
        assert_ne!(truncated_outcome.error_kind, "ok");
        log_case(
            "truncated_stream",
            truncated_stream.len(),
            success_plain.len(),
            truncated_outcome.output.len(),
            Some(success_plain.len() as f64 / truncated_stream.len() as f64),
            "within-cap-invalid-stream",
            &gzip_trailer_fields_for_log(&truncated_stream),
            truncated_outcome.error_kind,
            truncated_outcome.error_stage,
        );

        let first_member = b"member-one";
        let second_member = b"member-two";
        let mut multi_member = gzip_member_bytes(first_member);
        multi_member.extend(gzip_member_bytes(second_member));
        let multi_member_outcome = run_gzip_boundary_case(&multi_member, None);
        assert_ne!(multi_member_outcome.error_kind, "ok");
        assert!(
            multi_member_outcome.output.is_empty(),
            "concatenated members must fail closed before releasing bytes"
        );
        log_case(
            "multi_member_first_member_only",
            multi_member.len(),
            first_member.len().saturating_add(second_member.len()),
            multi_member_outcome.output.len(),
            Some(
                (first_member.len().saturating_add(second_member.len())) as f64
                    / multi_member.len() as f64,
            ),
            "single-member-fail-closed",
            &gzip_trailer_fields_for_log(&multi_member),
            multi_member_outcome.error_kind,
            multi_member_outcome.error_stage,
        );

        let high_ratio_plain = vec![b'A'; 16 * 1024];
        let high_ratio_compressed = gzip_member_bytes(&high_ratio_plain);
        let high_ratio_value = high_ratio_plain.len() as f64 / high_ratio_compressed.len() as f64;
        let high_ratio_outcome = run_gzip_boundary_case(&high_ratio_compressed, Some(1024));
        assert!(
            high_ratio_value > 20.0,
            "expected a bomb-like expansion ratio"
        );
        assert_ne!(high_ratio_outcome.error_kind, "ok");
        log_case(
            "ratio_bomb_rejected_by_cap",
            high_ratio_compressed.len(),
            high_ratio_plain.len(),
            high_ratio_outcome.output.len(),
            Some(high_ratio_value),
            "reject-over-cap",
            &gzip_trailer_fields_for_log(&high_ratio_compressed),
            high_ratio_outcome.error_kind,
            high_ratio_outcome.error_stage,
        );

        let mut low_ratio_plain = Vec::with_capacity(4096);
        let mut low_ratio_seed = 0x1234_5678u32;
        for _ in 0..4096 {
            low_ratio_seed ^= low_ratio_seed << 13;
            low_ratio_seed ^= low_ratio_seed >> 17;
            low_ratio_seed ^= low_ratio_seed << 5;
            low_ratio_plain.push((low_ratio_seed & 0xff) as u8);
        }
        let low_ratio_compressed = gzip_member_bytes(&low_ratio_plain);
        let low_ratio_value = low_ratio_plain.len() as f64 / low_ratio_compressed.len() as f64;
        let low_ratio_outcome = run_gzip_boundary_case(&low_ratio_compressed, Some(1024));
        assert!(
            low_ratio_value < 4.0,
            "expected a non-bomb compression ratio"
        );
        assert_ne!(low_ratio_outcome.error_kind, "ok");
        log_case(
            "absolute_output_cap_rejected",
            low_ratio_compressed.len(),
            low_ratio_plain.len(),
            low_ratio_outcome.output.len(),
            Some(low_ratio_value),
            "reject-over-cap",
            &gzip_trailer_fields_for_log(&low_ratio_compressed),
            low_ratio_outcome.error_kind,
            low_ratio_outcome.error_stage,
        );

        for (label, corpus) in [
            ("arbitrary_bytes_empty", Vec::new()),
            ("arbitrary_bytes_short_magic", vec![0x1f, 0x8b]),
            (
                "arbitrary_bytes_control_soup",
                vec![0x00, 0xff, 0x10, 0x80, 0x7f, 0x01, 0xfe, 0x55],
            ),
        ] {
            let arbitrary_result =
                std::panic::catch_unwind(|| run_gzip_boundary_case(&corpus, Some(1024)));
            assert!(
                arbitrary_result.is_ok(),
                "gzip arbitrary-bytes corpus must not panic: {label}"
            );
            let arbitrary_outcome = arbitrary_result.unwrap();
            log_case(
                label,
                corpus.len(),
                0,
                arbitrary_outcome.output.len(),
                None,
                "panic-free-arbitrary-bytes",
                &gzip_trailer_fields_for_log(&corpus),
                arbitrary_outcome.error_kind,
                arbitrary_outcome.error_stage,
            );
        }
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
    fn deflate_streaming_output_matches_reference_encoder() {
        use flate2::Compression;
        use flate2::read::DeflateDecoder as ReferenceDeflateDecoder;
        use flate2::write::DeflateEncoder as ReferenceDeflateEncoder;
        use std::io::{Read, Write};

        let input = b"RFC 1951 differential vector: repeated repeated repeated payload.";

        let mut ours = DeflateCompressor::with_level(Compression::default());
        let mut streamed = Vec::new();
        for chunk in input.chunks(7) {
            ours.compress(chunk, &mut streamed).unwrap();
        }
        ours.finish(&mut streamed).unwrap();

        let mut reference = ReferenceDeflateEncoder::new(Vec::new(), Compression::default());
        reference.write_all(input).unwrap();
        let reference_bytes = reference.finish().unwrap();

        assert_eq!(
            streamed, reference_bytes,
            "streaming wrapper must match canonical RFC 1951 deflate bytes for the same payload"
        );

        let mut ours_dec = DeflateDecompressor::new(None);
        let mut ours_plain = Vec::new();
        for chunk in reference_bytes.chunks(5) {
            ours_dec.decompress(chunk, &mut ours_plain).unwrap();
        }
        ours_dec.finish(&mut ours_plain).unwrap();
        assert_eq!(ours_plain, input);

        let mut reference_plain = Vec::new();
        ReferenceDeflateDecoder::new(&streamed[..])
            .read_to_end(&mut reference_plain)
            .unwrap();
        assert_eq!(reference_plain, input);
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
    fn deflate_empty_stream_matches_rfc1951_empty_final_block_vector() {
        let mut comp = DeflateCompressor::new();
        let mut compressed = Vec::new();
        comp.finish(&mut compressed).unwrap();

        assert_eq!(
            compressed,
            vec![0x03, 0x00],
            "empty raw DEFLATE stream should be a final empty block"
        );

        let mut dec = DeflateDecompressor::new(None);
        let mut decompressed = Vec::new();
        dec.decompress(&compressed, &mut decompressed).unwrap();
        dec.finish(&mut decompressed).unwrap();
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
            decoder: flate2::write::DeflateDecoder::new(LimitedWriter::new(None)),
            poisoned: false,
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
            decoder: brotli::DecompressorWriter::new(LimitedWriter::new(None), BROTLI_BUFFER_SIZE),
            finished: false,
            poisoned: false,
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
