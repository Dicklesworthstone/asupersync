//! HTTP body compression and content-encoding negotiation.
//!
//! Provides [`ContentEncoding`] for representing transfer encodings,
//! [`negotiate_encoding`] for Accept-Encoding negotiation, and a
//! [`Compressor`] trait for pluggable compression algorithms.
//! [`ContentCoding`] and [`negotiate_coding`] also name `zstd`, which the
//! exhaustive [`ContentEncoding`] cannot.
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

/// Default maximum decompressed body size accepted by HTTP gzip helpers.
///
/// Gzip decompression is always bounded. Callers that need a different cap
/// must provide an explicit [`DecompressionLimit`] when constructing the
/// decoder.
pub const DEFAULT_MAX_DECOMPRESSED_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of decompressed bytes a gzip decoder may emit.
///
/// The dedicated type keeps the resource bound explicit at construction and
/// prevents accidentally selecting an unbounded mode. A zero-byte limit is
/// valid and accepts only streams that produce no output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DecompressionLimit(usize);

impl DecompressionLimit {
    /// Create an explicit decompressed-output limit in bytes.
    #[must_use]
    pub const fn new(max_bytes: usize) -> Self {
        Self(max_bytes)
    }

    /// Return the decompressed-output limit in bytes.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl Default for DecompressionLimit {
    fn default() -> Self {
        Self(DEFAULT_MAX_DECOMPRESSED_SIZE)
    }
}

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

/// A content coding, including ones [`ContentEncoding`] cannot name.
///
/// [`ContentEncoding`] is exhaustive, so it cannot gain a variant without
/// breaking exhaustive matches downstream; new codings are added here
/// instead. Every [`ContentEncoding`] converts into one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ContentCoding {
    /// No encoding (pass-through).
    Identity,
    /// gzip (RFC 1952).
    Gzip,
    /// deflate (RFC 1951 wrapped in zlib).
    Deflate,
    /// Brotli (RFC 7932).
    Brotli,
    /// Zstandard (RFC 8878 §7.2), with windows of at most 8 MiB (RFC 9659).
    Zstd,
}

impl ContentCoding {
    /// Parse from the coding token used in HTTP headers.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        ContentEncoding::from_token(token)
            .map(Self::from)
            .or_else(|| {
                token
                    .trim()
                    .eq_ignore_ascii_case("zstd")
                    .then_some(Self::Zstd)
            })
    }

    /// Returns the HTTP header token for this coding.
    #[must_use]
    pub const fn as_token(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Brotli => "br",
            Self::Zstd => "zstd",
        }
    }

    /// The same coding as a [`ContentEncoding`], when that enum names it.
    #[must_use]
    pub const fn standard(self) -> Option<ContentEncoding> {
        match self {
            Self::Identity => Some(ContentEncoding::Identity),
            Self::Gzip => Some(ContentEncoding::Gzip),
            Self::Deflate => Some(ContentEncoding::Deflate),
            Self::Brotli => Some(ContentEncoding::Brotli),
            Self::Zstd => None,
        }
    }
}

impl From<ContentEncoding> for ContentCoding {
    fn from(encoding: ContentEncoding) -> Self {
        match encoding {
            ContentEncoding::Identity => Self::Identity,
            ContentEncoding::Gzip => Self::Gzip,
            ContentEncoding::Deflate => Self::Deflate,
            ContentEncoding::Brotli => Self::Brotli,
        }
    }
}

impl fmt::Display for ContentCoding {
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
    negotiate(
        accept_encoding,
        supported,
        ContentEncoding::Identity,
        ContentEncoding::from_token,
    )
}

/// [`negotiate_encoding`] over [`ContentCoding`]s, which can name `zstd`.
///
/// The algorithm, including the handling of `identity`, `*` and a missing
/// or empty header, is exactly that of [`negotiate_encoding`].
///
/// # Examples
///
/// ```
/// # use asupersync::http::compress::{ContentCoding, negotiate_coding};
/// let supported = &[ContentCoding::Zstd, ContentCoding::Gzip, ContentCoding::Identity];
/// let best = negotiate_coding(Some("gzip, deflate, br, zstd"), supported);
/// assert_eq!(best, Some(ContentCoding::Zstd));
/// ```
#[must_use]
pub fn negotiate_coding(
    accept_encoding: Option<&str>,
    supported: &[ContentCoding],
) -> Option<ContentCoding> {
    negotiate(
        accept_encoding,
        supported,
        ContentCoding::Identity,
        ContentCoding::from_token,
    )
}

/// The negotiation behind [`negotiate_encoding`] and [`negotiate_coding`],
/// for any coding type with an `identity` value and a token parser.
fn negotiate<T: Copy + PartialEq>(
    accept_encoding: Option<&str>,
    supported: &[T],
    identity: T,
    from_token: fn(&str) -> Option<T>,
) -> Option<T> {
    let Some(accept_encoding) = accept_encoding else {
        // No Accept-Encoding header: keep the existing server-preference
        // behavior and prefer identity when available.
        return if supported.contains(&identity) {
            Some(identity)
        } else {
            supported.first().copied()
        };
    };

    if accept_encoding.trim().is_empty() {
        return supported.contains(&identity).then_some(identity);
    }

    let preferences = parse_accept_encoding(accept_encoding);

    // Find wildcard quality if present
    let wildcard_quality = preferences
        .iter()
        .find(|q| q.encoding == "*")
        .map(|q| q.quality);

    let mut best: Option<(T, f32)> = None;

    for &encoding in supported {
        // br-asupersync-ipsu2a: match Accept-Encoding tokens against the
        // canonical encoding via from_token rather than equality on as_token's
        // canonical name. Otherwise legacy aliases (e.g. RFC 7230 §4.2 lists
        // "x-gzip" as a deprecated-but-valid synonym for "gzip") never bind to
        // their target ContentEncoding and silently fall through to wildcard.
        let explicit_quality = preferences
            .iter()
            .find(|q| from_token(&q.encoding) == Some(encoding))
            .map(|q| q.quality);

        // RFC 9110 §12.5.3: identity is acceptable by default (q=1.0)
        // unless explicitly excluded by `identity;q=0` or `*;q=0`
        // (without a more specific identity entry). A non-zero wildcard
        // like `*;q=0.5` does NOT lower identity from its default.
        let quality = if encoding == identity {
            explicit_quality.unwrap_or(match wildcard_quality {
                Some(q) if q <= 0.0 => 0.0,
                _ => 1.0,
            })
        } else {
            explicit_quality.or(wildcard_quality).unwrap_or(0.0)
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
    limit: DecompressionLimit,
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
    /// Create a new gzip decompressor with a mandatory output limit.
    #[must_use]
    pub fn new(limit: DecompressionLimit) -> Self {
        let max_size = limit.get();
        Self {
            limit,
            total: 0,
            decoder: flate2::write::GzDecoder::new(LimitedWriter::new(Some(max_size))),
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

        let max_size = self.limit.get();
        self.decoder.get_mut().max_size = Some(max_size.saturating_sub(self.total));

        // Run the decompression as a fallible inner expression; on any error,
        // mark poisoned and clear stale partial bytes from the inner buffer.
        let result: io::Result<()> = (|| {
            self.decoder.write_all(input)?;
            self.decoder.flush()?;
            let mut buf = std::mem::take(&mut self.decoder.get_mut().inner);
            update_decompressed_total(&mut self.total, buf.len(), Some(max_size))?;
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
        let max_size = self.limit.get();
        let remaining = max_size.saturating_sub(self.total);
        let mut finishing_decoder =
            flate2::write::GzDecoder::new(LimitedWriter::new(Some(remaining)));
        std::mem::swap(&mut self.decoder, &mut finishing_decoder);
        finishing_decoder.get_mut().max_size = Some(remaining);

        let result: io::Result<()> = (|| {
            let mut buf = finishing_decoder.finish()?.inner;
            update_decompressed_total(&mut self.total, buf.len(), Some(max_size))?;
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

/// HTTP deflate compressor using the flate2 (miniz_oxide) backend.
///
/// Emits the RFC 1950 zlib wrapper around RFC 1951 DEFLATE data, including
/// the Adler-32 trailer, as required by RFC 9110 section 8.4.1.2.
#[cfg(feature = "compression")]
pub struct DeflateCompressor {
    encoder: flate2::write::ZlibEncoder<LimitedWriter>,
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
            encoder: flate2::write::ZlibEncoder::new(
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
            flate2::write::ZlibEncoder::new(
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

/// HTTP deflate decompressor with bounded output and legacy raw-stream support.
///
/// The first two bytes select RFC 1950 zlib framing when they form a valid
/// zlib header; otherwise the stream is treated as legacy raw RFC 1951 data.
/// Selection is independent of input chunk boundaries. Once zlib is selected,
/// checksum or dictionary errors are never retried as raw data.
///
/// Call [`Decompressor::finish`] to validate the end of the stream. Truncated
/// streams and bytes after the single compressed stream are rejected. An error
/// poisons the decoder, and the failing call does not publish partial output.
#[cfg(feature = "compression")]
pub struct DeflateDecompressor {
    max_size: Option<usize>,
    total: usize,
    decoder: flate2::Decompress,
    header: [u8; 2],
    header_len: usize,
    stream_ended: bool,
    finished: bool,
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
            decoder: flate2::Decompress::new(false),
            header: [0; 2],
            header_len: 0,
            stream_ended: false,
            finished: false,
            poisoned: false,
        }
    }

    fn decode_chunk(
        &mut self,
        mut input: &[u8],
        output: &mut LimitedWriter,
        flush: flate2::FlushDecompress,
    ) -> io::Result<()> {
        use io::Write;

        if self.stream_ended {
            return if input.is_empty() {
                Ok(())
            } else {
                Err(limit_error("data after end of deflate stream"))
            };
        }

        // Bound codec scratch space independently of the caller's input size.
        // LimitedWriter enforces the remaining cumulative output budget before
        // allocating, and staged bytes are published only after the call succeeds.
        let mut scratch = [0; 8192];
        loop {
            let before_in = self.decoder.total_in();
            let before_out = self.decoder.total_out();
            let status = self
                .decoder
                .decompress(input, &mut scratch, flush)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let consumed = usize::try_from(self.decoder.total_in() - before_in)
                .map_err(|_| limit_error("deflate input count overflow"))?;
            let produced = usize::try_from(self.decoder.total_out() - before_out)
                .map_err(|_| limit_error("deflate output count overflow"))?;
            input = &input[consumed..];
            output.write_all(&scratch[..produced])?;

            if status == flate2::Status::StreamEnd {
                self.stream_ended = true;
                return if input.is_empty() {
                    Ok(())
                } else {
                    Err(limit_error("data after end of deflate stream"))
                };
            }
            if consumed == 0 && produced == 0 {
                return if input.is_empty() {
                    Ok(())
                } else {
                    Err(limit_error("deflate decoder made no progress"))
                };
            }
        }
    }

    fn decompress_inner(&mut self, mut input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let mut staged = LimitedWriter::new(remaining_limit(self.max_size, self.total));
        if self.header_len < self.header.len() {
            let needed = self.header.len() - self.header_len;
            let copied = needed.min(input.len());
            self.header[self.header_len..self.header_len + copied].copy_from_slice(&input[..copied]);
            self.header_len += copied;
            input = &input[copied..];
            if self.header_len < self.header.len() {
                return Ok(());
            }

            let header = self.header;
            let zlib = header[0] & 0x0f == 8
                && header[0] >> 4 <= 7
                && u16::from_be_bytes(header) % 31 == 0;
            self.decoder.reset(zlib);
            self.decode_chunk(&header, &mut staged, flate2::FlushDecompress::None)?;
        }
        self.decode_chunk(input, &mut staged, flate2::FlushDecompress::None)?;
        update_decompressed_total(&mut self.total, staged.inner.len(), self.max_size)?;
        output.append(&mut staged.inner);
        Ok(())
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
        if self.finished {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DeflateDecompressor already finished",
            ));
        }
        let result = self.decompress_inner(input, output);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn finish(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "DeflateDecompressor poisoned by prior error (br-asupersync-8vcp64)",
            ));
        }
        if self.finished {
            return Ok(());
        }
        let result = (|| {
            if self.header_len < self.header.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated deflate stream",
                ));
            }
            let mut staged = LimitedWriter::new(remaining_limit(self.max_size, self.total));
            self.decode_chunk(&[], &mut staged, flate2::FlushDecompress::Finish)?;
            if !self.stream_ended {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated deflate stream",
                ));
            }
            update_decompressed_total(&mut self.total, staged.inner.len(), self.max_size)?;
            output.append(&mut staged.inner);
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        } else {
            self.finished = true;
        }
        result
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

/// Compresses a whole response body for `coding`, refusing once the result
/// would pass `max_size` bytes. `None` means this build cannot produce
/// `coding`. The standard codings run through
/// [`make_compressor_with_output_limit`].
pub(crate) fn compress_body(
    coding: ContentCoding,
    body: &[u8],
    max_size: usize,
) -> Option<io::Result<Vec<u8>>> {
    if let Some(encoding) = coding.standard() {
        let mut compressor = make_compressor_with_output_limit(encoding, Some(max_size))?;
        let mut compressed = Vec::new();
        let written = compressor
            .compress(body, &mut compressed)
            .and_then(|()| compressor.finish(&mut compressed));
        return Some(written.map(|()| compressed));
    }
    #[cfg(feature = "zstd")]
    {
        Some(zstd_body(body, max_size))
    }
    #[cfg(not(feature = "zstd"))]
    {
        None
    }
}

/// The body as a sequence of zstd frames (RFC 8878 §7.2) of at most 1 MiB
/// each, so every window stays far below the 8 MiB that RFC 9659 allows. The
/// output never grows past `max_size`.
#[cfg(feature = "zstd")]
fn zstd_body(body: &[u8], max_size: usize) -> io::Result<Vec<u8>> {
    const FRAME: usize = 1 << 20;
    let params = asupersync_zstd::EncodeParams::new(asupersync_zstd::Level::Fast);
    let mut compressed = Vec::new();
    let mut frame = Vec::new();
    let mut start = 0;
    // One frame even for an empty body: a zstd coding holds at least one.
    loop {
        let end = body.len().min(start + FRAME);
        frame.clear();
        asupersync_zstd::encode_into(&body[start..end], &params, &mut frame);
        if compressed.len() + frame.len() > max_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed size exceeds limit",
            ));
        }
        compressed.extend_from_slice(&frame);
        start = end;
        if start == body.len() {
            return Ok(compressed);
        }
    }
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
#[path = "compress_inline_tests.rs"]
mod tests;
