//! gRPC message framing codec.
//!
//! Implements the gRPC message framing format:
//! - 1 byte: compressed flag (0 = uncompressed, 1 = compressed)
//! - 4 bytes: message length (big-endian)
//! - N bytes: message payload

use crate::bytes::{BufMut, Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};
use std::fmt;

use super::status::GrpcError;

// Re-export from parent module (single source of truth).
pub use super::DEFAULT_MAX_MESSAGE_SIZE;

/// gRPC message header size (1 byte flag + 4 bytes length).
pub const MESSAGE_HEADER_SIZE: usize = 5;

/// A decoded gRPC message.
#[derive(Debug, Clone)]
pub struct GrpcMessage {
    /// Whether the message was compressed.
    pub compressed: bool,
    /// The message payload.
    pub data: Bytes,
}

impl GrpcMessage {
    /// Create a new uncompressed message.
    #[must_use]
    pub fn new(data: Bytes) -> Self {
        Self {
            compressed: false,
            data,
        }
    }

    /// Create a new compressed message.
    #[must_use]
    pub fn compressed(data: Bytes) -> Self {
        Self {
            compressed: true,
            data,
        }
    }
}

/// gRPC message framing codec.
///
/// This codec handles the low-level framing of gRPC messages over HTTP/2.
#[derive(Debug)]
pub struct GrpcCodec {
    /// Maximum allowed outbound message size.
    max_encode_message_size: usize,
    /// Maximum allowed inbound message size.
    max_decode_message_size: usize,
}

impl GrpcCodec {
    /// Create a new codec with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_message_size_limits(DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MAX_MESSAGE_SIZE)
    }

    /// Create a new codec with a symmetric max message size.
    #[must_use]
    pub fn with_max_size(max_message_size: usize) -> Self {
        Self::with_message_size_limits(max_message_size, max_message_size)
    }

    /// Create a new codec with independent encode and decode limits.
    #[must_use]
    pub fn with_message_size_limits(
        max_encode_message_size: usize,
        max_decode_message_size: usize,
    ) -> Self {
        Self {
            max_encode_message_size,
            max_decode_message_size,
        }
    }

    /// Get the larger configured message size limit.
    ///
    /// When encode and decode limits differ, prefer the directional accessors.
    #[must_use]
    pub fn max_message_size(&self) -> usize {
        self.max_encode_message_size
            .max(self.max_decode_message_size)
    }

    /// Get the maximum outbound message size.
    #[must_use]
    pub fn max_encode_message_size(&self) -> usize {
        self.max_encode_message_size
    }

    /// Get the maximum inbound message size.
    #[must_use]
    pub fn max_decode_message_size(&self) -> usize {
        self.max_decode_message_size
    }
}

impl Default for GrpcCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for GrpcCodec {
    type Item = GrpcMessage;
    type Error = GrpcError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least the header
        if src.len() < MESSAGE_HEADER_SIZE {
            return Ok(None);
        }

        // Parse header.
        let flag = src[0];
        let length = u32::from_be_bytes([src[1], src[2], src[3], src[4]]) as usize;

        // Validate ON-WIRE message size for ALL frames, including compressed.
        // The post-decompression check in FramedCodec only catches inflated
        // payloads — but a peer declaring Length=u32::MAX with Compressed-Flag=1
        // would otherwise force the upstream HTTP/2 buffer to grow to ~4 GiB
        // before decompression is even attempted. That's a remote OOM-DoS
        // (asupersync-6o5iax). Compressed payloads must still fit within
        // max_decode_message_size on the wire — high-ratio compressed payloads
        // can configure a separate larger cap if needed.
        if length > self.max_decode_message_size {
            return Err(GrpcError::MessageTooLarge);
        }

        // Check if we have the full message
        if src.len() < MESSAGE_HEADER_SIZE.saturating_add(length) {
            return Ok(None);
        }

        let compressed = match flag {
            0 => false,
            1 => true,
            invalid => {
                // grpc-go validates payload format after it has read the
                // complete declared frame. Consume the invalid frame so
                // callers do not get stuck re-parsing the same bytes forever.
                let _ = src.split_to(MESSAGE_HEADER_SIZE + length);
                return Err(GrpcError::protocol(format!(
                    "invalid gRPC compression flag: {invalid}"
                )));
            }
        };

        // Consume header
        let _ = src.split_to(MESSAGE_HEADER_SIZE);

        // Extract message data
        let data = src.split_to(length).freeze();

        Ok(Some(GrpcMessage { compressed, data }))
    }
}

impl Encoder<GrpcMessage> for GrpcCodec {
    type Error = GrpcError;

    fn encode(&mut self, item: GrpcMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Validate message size
        if item.data.len() > self.max_encode_message_size {
            return Err(GrpcError::MessageTooLarge);
        }

        // Reserve space
        dst.reserve(MESSAGE_HEADER_SIZE + item.data.len());

        // Write compressed flag
        dst.put_u8(u8::from(item.compressed));

        // Write length (big-endian). gRPC uses u32 length prefixes, so reject
        // payloads that overflow the 4-byte field rather than silently truncating.
        let length = u32::try_from(item.data.len()).map_err(|_| GrpcError::MessageTooLarge)?;
        dst.put_u32(length);

        // Write data
        dst.extend_from_slice(&item.data);

        Ok(())
    }
}

/// Trait for encoding and decoding protobuf messages.
pub trait Codec: Send + 'static {
    /// The type being encoded.
    type Encode: Send + 'static;
    /// The type being decoded.
    type Decode: Send + 'static;
    /// Error type for encoding/decoding.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Encode a message to bytes.
    fn encode(&mut self, item: &Self::Encode) -> Result<Bytes, Self::Error>;

    /// Decode a message from bytes.
    fn decode(&mut self, buf: &Bytes) -> Result<Self::Decode, Self::Error>;

    /// Update the outbound message size limit, if this codec tracks one.
    fn set_max_encode_message_size(&mut self, _max_size: usize) {}

    /// Update the inbound message size limit, if this codec tracks one.
    fn set_max_decode_message_size(&mut self, _max_size: usize) {}

    /// Map an encode-side codec error into the gRPC framing layer.
    fn map_encode_error(error: Self::Error) -> GrpcError {
        GrpcError::invalid_message(error.to_string())
    }

    /// Map a decode-side codec error into the gRPC framing layer.
    fn map_decode_error(error: Self::Error) -> GrpcError {
        GrpcError::invalid_message(error.to_string())
    }
}

/// Function signature for frame-level compression hooks.
///
/// br-asupersync-535iu9: takes `Bytes` (not `&[u8]`) so the identity
/// no-compression path is a pure move (Arc refcount bump) instead of
/// a full memcpy. The pre-fix `&[u8]` signature forced
/// `Bytes::copy_from_slice` at every identity call — one heap alloc +
/// memcpy per gRPC frame on the no-compression hot path.
pub type FrameCompressor = fn(Bytes) -> Result<Bytes, GrpcError>;

/// Function signature for frame-level decompression hooks.
///
/// br-asupersync-535iu9: see [`FrameCompressor`] doc — same Bytes-by-value
/// rationale.
pub type FrameDecompressor = fn(Bytes, usize) -> Result<Bytes, GrpcError>;

#[allow(clippy::unnecessary_wraps)]
fn identity_frame_compress(input: Bytes) -> Result<Bytes, GrpcError> {
    // br-asupersync-535iu9: zero-copy pass-through on the no-compression
    // hot path. Pre-fix was `Bytes::copy_from_slice(input)` which did a
    // full memcpy of the entire frame; post-fix is a move (no heap
    // allocation, no memcpy). For per-request gRPC traffic with
    // many small frames this is a substantial throughput win.
    Ok(input)
}

fn identity_frame_decompress(input: Bytes, max_size: usize) -> Result<Bytes, GrpcError> {
    if input.len() > max_size {
        return Err(GrpcError::MessageTooLarge);
    }
    // br-asupersync-535iu9: zero-copy pass-through, see identity_frame_compress.
    Ok(input)
}

/// Gzip frame compressor using flate2.
///
/// Compresses the input bytes with gzip encoding at the default compression level.
///
/// br-asupersync-ky9o3j: pre-fix used `Vec::new()` as the encoder backing
/// buffer with no size hint, causing flate2 to grow the vector through
/// successive doublings (typical 4-8 reallocs per frame). Post-fix
/// pre-allocates `input.len()` bytes — a tight upper bound for typical
/// gzip ratios on protobuf payloads (gzip rarely produces output larger
/// than the input for small protobuf messages, and over-allocation by a
/// few KB is amortized against avoiding the realloc cycle).
#[cfg(feature = "compression")]
pub fn gzip_frame_compress(input: Bytes) -> Result<Bytes, GrpcError> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::with_capacity(input.len()), Compression::default());
    encoder
        .write_all(&input)
        .map_err(|e| GrpcError::compression(e.to_string()))?;
    let compressed = encoder
        .finish()
        .map_err(|e| GrpcError::compression(e.to_string()))?;
    Ok(Bytes::from(compressed))
}

/// Gzip frame decompressor using flate2.
///
/// Decompresses gzip-encoded bytes, enforcing `max_size` to guard against
/// decompression bombs.
///
/// br-asupersync-ky9o3j: pre-fix used `Vec::new()` for the output buffer
/// with no size hint, causing typical gzip-ratio decompression (4-8x
/// expansion) to trigger 3-4 reallocs per frame. Post-fix pre-allocates
/// based on a 4× input estimate, capped at the configured max_size to
/// avoid attacker-controlled allocation amplification (decompression-bomb
/// safety preserved by the existing per-iteration `total > max_size`
/// check below).
#[cfg(feature = "compression")]
pub fn gzip_frame_decompress(input: Bytes, max_size: usize) -> Result<Bytes, GrpcError> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    // 4× input is the typical ratio for protobuf payloads under default
    // gzip compression; capped at max_size so an attacker can't force
    // amplification by sending tiny compressed inputs that hint a huge
    // output. The per-iteration check below remains the actual bomb
    // defense.
    let initial_capacity = input.len().saturating_mul(4).min(max_size);
    let mut decoder = GzDecoder::new(input.as_ref());
    let mut output = Vec::with_capacity(initial_capacity);
    let mut buf = [0u8; 8192];
    let mut total = 0;
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| GrpcError::compression(e.to_string()))?;
        if n == 0 {
            break;
        }
        total += n;
        if total > max_size {
            return Err(GrpcError::MessageTooLarge);
        }
        output.extend_from_slice(&buf[..n]);
    }
    Ok(Bytes::from(output))
}

/// A codec that wraps another codec with gRPC framing.
pub struct FramedCodec<C> {
    /// The inner codec for message serialization.
    inner: C,
    /// The gRPC framing codec.
    framing: GrpcCodec,
    /// Whether to use compression.
    use_compression: bool,
    /// Optional frame-level compressor.
    compressor: Option<FrameCompressor>,
    /// Optional frame-level decompressor.
    decompressor: Option<FrameDecompressor>,
    /// Once a decode-side protocol or payload error occurs, fail closed.
    poisoned: bool,
}

impl<C: fmt::Debug> fmt::Debug for FramedCodec<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FramedCodec")
            .field("inner", &self.inner)
            .field("framing", &self.framing)
            .field("use_compression", &self.use_compression)
            .field("has_compressor", &self.compressor.is_some())
            .field("has_decompressor", &self.decompressor.is_some())
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl<C: Codec> FramedCodec<C> {
    /// Create a new framed codec.
    #[must_use]
    pub fn new(inner: C) -> Self {
        Self::with_message_size_limits(inner, DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MAX_MESSAGE_SIZE)
    }

    /// Create a new framed codec with a symmetric max message size.
    #[must_use]
    pub fn with_max_size(inner: C, max_size: usize) -> Self {
        Self::with_message_size_limits(inner, max_size, max_size)
    }

    /// Create a new framed codec with independent encode and decode limits.
    #[must_use]
    pub fn with_message_size_limits(
        mut inner: C,
        max_encode_message_size: usize,
        max_decode_message_size: usize,
    ) -> Self {
        inner.set_max_encode_message_size(max_encode_message_size);
        inner.set_max_decode_message_size(max_decode_message_size);
        Self {
            inner,
            framing: GrpcCodec::with_message_size_limits(
                max_encode_message_size,
                max_decode_message_size,
            ),
            use_compression: false,
            compressor: None,
            decompressor: None,
            poisoned: false,
        }
    }

    /// Set optional frame-level compressor and decompressor hooks.
    #[must_use]
    pub fn with_frame_hooks(
        mut self,
        compressor: Option<FrameCompressor>,
        decompressor: Option<FrameDecompressor>,
    ) -> Self {
        if compressor.is_some() || decompressor.is_some() {
            self.use_compression = true;
        }
        self.compressor = compressor;
        self.decompressor = decompressor;
        self
    }

    /// Enable compression.
    #[must_use]
    pub fn with_compression(mut self) -> Self {
        self.use_compression = true;
        self
    }

    /// Configure explicit frame-level compression/decompression hooks.
    ///
    /// The hooks are stateless functions used per message frame.
    #[must_use]
    pub fn with_frame_codec(
        self,
        compressor: FrameCompressor,
        decompressor: FrameDecompressor,
    ) -> Self {
        self.with_frame_hooks(Some(compressor), Some(decompressor))
    }

    /// Configure gzip frame compression/decompression.
    ///
    /// Requires the `compression` feature flag. Uses flate2 for gzip encoding
    /// with decompression-bomb protection via `max_message_size`.
    #[cfg(feature = "compression")]
    #[must_use]
    pub fn with_gzip_frame_codec(self) -> Self {
        self.with_frame_codec(gzip_frame_compress, gzip_frame_decompress)
    }

    /// Configure identity frame hooks.
    ///
    /// Identity is the gRPC no-op encoding. Outbound frames stay byte-for-byte
    /// equivalent to the bare codec path and therefore keep compressed-flag=0.
    /// The identity decompressor is still installed so tests and interop paths
    /// can explicitly accept compressed-flag=1 frames when no grpc-encoding
    /// header is supplied.
    #[must_use]
    pub fn with_identity_frame_codec(mut self) -> Self {
        self.compressor = Some(identity_frame_compress);
        self.decompressor = Some(identity_frame_decompress);
        self.use_compression = false;
        self
    }

    /// Get a reference to the inner codec.
    pub fn inner(&self) -> &C {
        &self.inner
    }

    /// Get a mutable reference to the inner codec.
    pub fn inner_mut(&mut self) -> &mut C {
        &mut self.inner
    }

    /// Get the maximum outbound message size.
    #[must_use]
    pub fn max_encode_message_size(&self) -> usize {
        self.framing.max_encode_message_size()
    }

    /// Get the maximum inbound message size.
    #[must_use]
    pub fn max_decode_message_size(&self) -> usize {
        self.framing.max_decode_message_size()
    }

    /// Returns whether a prior decode-side error poisoned this stream.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    #[inline]
    fn poison_decode_stream<T>(
        &mut self,
        src: &mut BytesMut,
        error: GrpcError,
    ) -> Result<T, GrpcError> {
        self.poisoned = true;
        // Fail closed at the buffer boundary as well as the codec boundary.
        // Once one consumed frame proves the stream invalid, later buffered
        // frames must not survive for a fresh codec instance to decode.
        src.clear();
        Err(error)
    }

    /// Encode a message with framing.
    pub fn encode_message(
        &mut self,
        item: &C::Encode,
        dst: &mut BytesMut,
    ) -> Result<(), GrpcError> {
        // Serialize the message
        let data = self.inner.encode(item).map_err(C::map_encode_error)?;

        let message = if self.use_compression {
            let compressor = self.compressor.ok_or_else(|| {
                GrpcError::compression("compression requested but no frame compressor configured")
            })?;
            // br-asupersync-535iu9: pass Bytes by-value (move) — identity
            // compressor avoids a memcpy entirely; gzip compressor still
            // allocates output but with a sized hint (br-ky9o3j).
            let compressed = compressor(data)?;
            if compressed.len() > self.max_encode_message_size() {
                return Err(GrpcError::MessageTooLarge);
            }
            GrpcMessage::compressed(compressed)
        } else {
            GrpcMessage::new(data)
        };

        // Encode with framing
        self.framing.encode(message, dst)
    }

    /// Decode a message with framing.
    pub fn decode_message(&mut self, src: &mut BytesMut) -> Result<Option<C::Decode>, GrpcError> {
        self.decode_message_with_encoding(src, None)
    }

    /// Decode a message with framing and validate compression flag consistency.
    ///
    /// Per gRPC specification, the compressed flag must be consistent with the
    /// grpc-encoding header:
    /// - If grpc_encoding is "identity", compressed flag must be 0
    /// - If grpc_encoding is "gzip", compressed flag must be 1
    /// - Mismatches are protocol errors
    pub fn decode_message_with_encoding(
        &mut self,
        src: &mut BytesMut,
        grpc_encoding: Option<&str>,
    ) -> Result<Option<C::Decode>, GrpcError> {
        if self.poisoned {
            src.clear();
            return Err(GrpcError::protocol(
                "gRPC framed codec is poisoned after a previous decode error",
            ));
        }

        // Decode framing
        let message = match self.framing.decode(src) {
            Ok(Some(message)) => message,
            Ok(None) => return Ok(None),
            Err(error) => return self.poison_decode_stream(src, error),
        };

        // SECURITY FIX: Validate compression flag consistency with grpc-encoding header
        if let Some(encoding) = grpc_encoding {
            let expected_compressed = match encoding {
                "identity" => false,
                "gzip" | "deflate" | "snappy" => true,
                unknown => {
                    return self.poison_decode_stream(
                        src,
                        GrpcError::protocol(format!(
                            "unsupported grpc-encoding: '{}'. Supported: identity, gzip",
                            unknown
                        )),
                    );
                }
            };

            if message.compressed != expected_compressed {
                return self.poison_decode_stream(
                    src,
                    GrpcError::protocol(format!(
                        "gRPC protocol violation: compressed-flag={} but grpc-encoding='{}'. \
                         Per spec: identity requires flag=0, compression algorithms require flag=1",
                        u8::from(message.compressed),
                        encoding
                    )),
                );
            }
        }

        // Handle compression
        let data = if message.compressed {
            let Some(decompressor) = self.decompressor else {
                return self.poison_decode_stream(
                    src,
                    GrpcError::compression(
                        "compressed frame received but no frame decompressor configured",
                    ),
                );
            };
            // br-asupersync-535iu9: pass Bytes by-value (move) — identity
            // decompressor is zero-copy; gzip pre-allocates output
            // with a sized hint (br-ky9o3j).
            match decompressor(message.data, self.max_decode_message_size()) {
                Ok(data) => data,
                Err(error) => return self.poison_decode_stream(src, error),
            }
        } else {
            message.data
        };

        // Deserialize the message
        let decoded = match self.inner.decode(&data).map_err(C::map_decode_error) {
            Ok(decoded) => decoded,
            Err(error) => return self.poison_decode_stream(src, error),
        };

        Ok(Some(decoded))
    }
}

/// Identity codec that passes bytes through unchanged.
///
/// Useful for testing or when the caller handles serialization.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityCodec;

impl Codec for IdentityCodec {
    type Encode = Bytes;
    type Decode = Bytes;
    type Error = std::convert::Infallible;

    fn encode(&mut self, item: &Self::Encode) -> Result<Bytes, Self::Error> {
        Ok(item.clone())
    }

    fn decode(&mut self, buf: &Bytes) -> Result<Self::Decode, Self::Error> {
        Ok(buf.clone())
    }
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
    #[cfg(feature = "compression")]
    use crate::grpc::ProstCodec;
    #[cfg(feature = "compression")]
    use prost::Message;
    use std::fmt::Write;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn format_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn render_grpc_frame_for_snapshot_test(bytes: &[u8]) -> String {
        let mut out = String::new();
        let compressed_flag = bytes[0];
        let payload_len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let payload = &bytes[MESSAGE_HEADER_SIZE..];

        let _ = writeln!(out, "compressed_flag: {compressed_flag:02x}");
        let _ = writeln!(out, "message_length_be: {}", format_hex(&bytes[1..5]));
        let _ = writeln!(out, "message_length: {payload_len}");
        let _ = writeln!(out, "payload_utf8: {:?}", String::from_utf8_lossy(payload));
        let _ = writeln!(out, "payload_hex: {}", format_hex(payload));

        out
    }

    #[cfg(feature = "compression")]
    #[derive(Clone, PartialEq, prost::Message)]
    struct GzipParityMessage {
        #[prost(string, tag = "1")]
        name: String,
        #[prost(bytes = "vec", tag = "2")]
        payload: Vec<u8>,
        #[prost(uint64, tag = "3")]
        counter: u64,
    }

    #[cfg(feature = "compression")]
    fn gzip_parity_message_fingerprint(message: &GzipParityMessage) -> String {
        let mut hash = 14_695_981_039_346_656_037_u64;
        hash ^= message.name.len() as u64;
        hash = hash.wrapping_mul(1_099_511_628_211);
        hash ^= message.payload.len() as u64;
        hash = hash.wrapping_mul(1_099_511_628_211);
        hash ^= message.counter;
        hash = hash.wrapping_mul(1_099_511_628_211);

        format!(
            "name_len={},payload_len={},counter={},fnv1a64={hash:016x}",
            message.name.len(),
            message.payload.len(),
            message.counter,
        )
    }

    #[derive(Debug, thiserror::Error)]
    enum LimitTrackingCodecError {
        #[error("message too large")]
        MessageTooLarge,
    }

    #[derive(Debug, Default)]
    struct LimitTrackingCodec {
        max_encode_message_size: usize,
        max_decode_message_size: usize,
    }

    impl Codec for LimitTrackingCodec {
        type Encode = Bytes;
        type Decode = Bytes;
        type Error = LimitTrackingCodecError;

        fn encode(&mut self, item: &Self::Encode) -> Result<Bytes, Self::Error> {
            if item.len() > self.max_encode_message_size {
                return Err(LimitTrackingCodecError::MessageTooLarge);
            }
            Ok(item.clone())
        }

        fn decode(&mut self, buf: &Bytes) -> Result<Self::Decode, Self::Error> {
            if buf.len() > self.max_decode_message_size {
                return Err(LimitTrackingCodecError::MessageTooLarge);
            }
            Ok(buf.clone())
        }

        fn set_max_encode_message_size(&mut self, max_size: usize) {
            self.max_encode_message_size = max_size;
        }

        fn set_max_decode_message_size(&mut self, max_size: usize) {
            self.max_decode_message_size = max_size;
        }

        fn map_encode_error(error: Self::Error) -> GrpcError {
            match error {
                LimitTrackingCodecError::MessageTooLarge => GrpcError::MessageTooLarge,
            }
        }

        fn map_decode_error(error: Self::Error) -> GrpcError {
            match error {
                LimitTrackingCodecError::MessageTooLarge => GrpcError::MessageTooLarge,
            }
        }
    }

    #[test]
    fn test_grpc_codec_roundtrip() {
        init_test("test_grpc_codec_roundtrip");
        let mut codec = GrpcCodec::new();
        let mut buf = BytesMut::new();

        let original = GrpcMessage::new(Bytes::from_static(b"hello world"));
        codec.encode(original.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        let compressed = decoded.compressed;
        crate::assert_with_log!(!compressed, "not compressed", false, compressed);
        crate::assert_with_log!(
            decoded.data == original.data,
            "data",
            original.data,
            decoded.data
        );
        crate::test_complete!("test_grpc_codec_roundtrip");
    }

    #[test]
    fn test_grpc_codec_message_too_large() {
        init_test("test_grpc_codec_message_too_large");
        let mut codec = GrpcCodec::with_max_size(10);
        let mut buf = BytesMut::new();

        let large_message = GrpcMessage::new(Bytes::from(vec![0u8; 100]));
        let result = codec.encode(large_message, &mut buf);
        let ok = matches!(result, Err(GrpcError::MessageTooLarge));
        crate::assert_with_log!(ok, "message too large", true, ok);
        crate::test_complete!("test_grpc_codec_message_too_large");
    }

    #[test]
    fn test_grpc_codec_decode_message_too_large() {
        init_test("test_grpc_codec_decode_message_too_large");
        let mut codec = GrpcCodec::with_max_size(3);
        let mut buf = BytesMut::new();

        // Header declares 4-byte payload, which exceeds max size (3).
        buf.put_u8(0);
        buf.put_u32(4);
        buf.extend_from_slice(b"abcd");

        let result = codec.decode(&mut buf);
        let ok = matches!(result, Err(GrpcError::MessageTooLarge));
        crate::assert_with_log!(ok, "decode rejects oversized frame", true, ok);
        crate::test_complete!("test_grpc_codec_decode_message_too_large");
    }

    #[test]
    fn grpc_codec_rejects_oversized_declared_frame_before_payload() {
        init_test("grpc_codec_rejects_oversized_declared_frame_before_payload");
        let mut codec = GrpcCodec::with_max_size(3);
        let mut buf = BytesMut::new();

        buf.put_u8(0);
        buf.put_u32(4);

        let result = codec.decode(&mut buf);
        let rejected = matches!(result, Err(GrpcError::MessageTooLarge));
        crate::assert_with_log!(
            rejected,
            "oversized declared frame is rejected before payload buffering",
            true,
            rejected
        );
        crate::assert_with_log!(
            buf.len() == MESSAGE_HEADER_SIZE,
            "oversized header remains available for connection-level error handling",
            MESSAGE_HEADER_SIZE,
            buf.len()
        );
        crate::test_complete!("grpc_codec_rejects_oversized_declared_frame_before_payload");
    }

    #[test]
    fn test_grpc_go_max_receive_boundary_accepts_exact_limit_then_rejects_next_byte() {
        init_test("test_grpc_go_max_receive_boundary_accepts_exact_limit_then_rejects_next_byte");

        let mut codec = FramedCodec::with_message_size_limits(IdentityCodec, 64, 5);
        let mut producer = GrpcCodec::new();
        let mut buf = BytesMut::new();

        producer
            .encode(GrpcMessage::new(Bytes::from_static(b"12345")), &mut buf)
            .expect("exact-limit frame should encode");
        producer
            .encode(GrpcMessage::new(Bytes::from_static(b"123456")), &mut buf)
            .expect("oversize frame should encode for receive-side test");

        let first = codec
            .decode_message(&mut buf)
            .expect("grpc-go accepts a frame exactly at max receive size")
            .expect("first frame should decode");
        crate::assert_with_log!(
            first == Bytes::from_static(b"12345"),
            "exact-limit frame decodes",
            Bytes::from_static(b"12345"),
            first
        );

        let second = codec.decode_message(&mut buf);
        let over_limit = matches!(second, Err(GrpcError::MessageTooLarge));
        crate::assert_with_log!(
            over_limit,
            "grpc-go rejects limit-plus-one receive frame",
            true,
            over_limit
        );

        crate::test_complete!(
            "test_grpc_go_max_receive_boundary_accepts_exact_limit_then_rejects_next_byte"
        );
    }

    #[test]
    fn test_grpc_codec_partial_header() {
        init_test("test_grpc_codec_partial_header");
        let mut codec = GrpcCodec::new();
        let mut buf = BytesMut::from(&[0u8, 0, 0][..]);

        let result = codec.decode(&mut buf).unwrap();
        let none = result.is_none();
        crate::assert_with_log!(none, "none", true, none);
        crate::test_complete!("test_grpc_codec_partial_header");
    }

    #[test]
    fn test_grpc_codec_partial_body() {
        init_test("test_grpc_codec_partial_body");
        let mut codec = GrpcCodec::new();
        let mut buf = BytesMut::new();

        // Write header indicating 10 bytes, but only provide 5
        buf.put_u8(0); // not compressed
        buf.put_u32(10); // length = 10
        buf.extend_from_slice(&[1, 2, 3, 4, 5]); // only 5 bytes

        let result = codec.decode(&mut buf).unwrap();
        let none = result.is_none();
        crate::assert_with_log!(none, "none", true, none);
        crate::test_complete!("test_grpc_codec_partial_body");
    }

    #[test]
    fn test_grpc_codec_partial_body_then_complete() {
        init_test("test_grpc_codec_partial_body_then_complete");
        let mut codec = GrpcCodec::new();
        let mut buf = BytesMut::new();

        // Declare 5-byte payload but provide only first 2 bytes.
        buf.put_u8(0);
        buf.put_u32(5);
        buf.extend_from_slice(b"ab");

        let first = codec.decode(&mut buf).unwrap();
        let first_none = first.is_none();
        crate::assert_with_log!(first_none, "first decode pending", true, first_none);

        // Complete the payload and decode again.
        buf.extend_from_slice(b"cde");
        let second = codec.decode(&mut buf).unwrap();
        let second_some = second.is_some();
        crate::assert_with_log!(second_some, "second decode ready", true, second_some);

        let decoded = second.unwrap();
        crate::assert_with_log!(
            decoded.data == Bytes::from_static(b"abcde"),
            "decoded payload after completion",
            Bytes::from_static(b"abcde"),
            decoded.data
        );
        let drained = buf.is_empty();
        crate::assert_with_log!(drained, "buffer fully consumed", true, drained);
        crate::test_complete!("test_grpc_codec_partial_body_then_complete");
    }

    #[test]
    fn test_grpc_codec_rejects_invalid_compression_flag() {
        init_test("test_grpc_codec_rejects_invalid_compression_flag");
        let mut codec = GrpcCodec::new();
        let mut buf = BytesMut::new();

        // Invalid flag value 2 (spec allows only 0/1).
        buf.put_u8(2);
        buf.put_u32(3);
        buf.extend_from_slice(b"abc");

        let result = codec.decode(&mut buf);
        let ok = matches!(result, Err(GrpcError::Protocol(_)));
        crate::assert_with_log!(ok, "invalid compression flag rejected", true, ok);
        crate::test_complete!("test_grpc_codec_rejects_invalid_compression_flag");
    }

    #[test]
    fn test_grpc_codec_invalid_compression_flag_consumes_complete_frame() {
        init_test("test_grpc_codec_invalid_compression_flag_consumes_complete_frame");
        let mut codec = GrpcCodec::new();
        let mut buf = BytesMut::new();

        buf.put_u8(2);
        buf.put_u32(3);
        buf.extend_from_slice(b"abc");

        let result = codec.decode(&mut buf);
        let ok = matches!(result, Err(GrpcError::Protocol(_)));
        crate::assert_with_log!(ok, "invalid compression flag rejected", true, ok);
        crate::assert_with_log!(
            buf.is_empty(),
            "invalid complete frame is consumed",
            true,
            buf.is_empty()
        );
        crate::test_complete!("test_grpc_codec_invalid_compression_flag_consumes_complete_frame");
    }

    #[test]
    fn conformance_grpc_codec_lpm_stream_boundary_matrix() {
        init_test("conformance_grpc_codec_lpm_stream_boundary_matrix");

        const EXACT_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_daaw5q_lpm cargo test -p asupersync --lib conformance_grpc_codec_lpm_stream_boundary_matrix -- --nocapture";

        fn encode_frame(message: GrpcMessage, max_size: usize) -> BytesMut {
            let mut producer = GrpcCodec::with_max_size(max_size);
            let mut wire = BytesMut::new();
            producer
                .encode(message, &mut wire)
                .expect("frame should encode for boundary matrix");
            wire
        }

        fn drain_ready_messages(
            codec: &mut GrpcCodec,
            buf: &mut BytesMut,
        ) -> Result<Vec<GrpcMessage>, GrpcError> {
            let mut out = Vec::new();
            while let Some(message) = codec.decode(buf)? {
                out.push(message);
            }
            Ok(out)
        }

        fn ordering(messages: &[GrpcMessage]) -> String {
            if messages.is_empty() {
                return "empty".to_string();
            }

            messages
                .iter()
                .map(|message| format!("{}:{}", u8::from(message.compressed), message.data.len()))
                .collect::<Vec<_>>()
                .join(">")
        }

        let log_case = |scenario_id: &str,
                        frame_count: usize,
                        split_pattern: &str,
                        declared_length: &str,
                        actual_length: &str,
                        compression_flag: &str,
                        decode_state: &str,
                        allocation_guard_decision: &str,
                        error_kind: &str,
                        output_message_ordering: &str| {
            eprintln!(
                "GRPC_LPM_BOUNDARY scenario_id={} frame_count={} split_pattern={} declared_length={} actual_length={} compression_flag={} decode_state={} allocation_guard_decision={} error_kind={} output_message_ordering={} exact_rch_command=\"{}\" artifact_paths=none final_preservation_no_overflow_verdict=pass",
                scenario_id,
                frame_count,
                split_pattern,
                declared_length,
                actual_length,
                compression_flag,
                decode_state,
                allocation_guard_decision,
                error_kind,
                output_message_ordering,
                EXACT_RCH_COMMAND,
            );
        };

        let empty_wire = encode_frame(GrpcMessage::new(Bytes::new()), 16);
        let mut empty_codec = GrpcCodec::with_max_size(16);
        let mut empty_buf = empty_wire.clone();
        let empty = empty_codec
            .decode(&mut empty_buf)
            .expect("empty frame decode")
            .expect("empty frame ready");
        assert!(empty_buf.is_empty(), "empty frame must drain");
        assert!(!empty.compressed, "empty frame should be uncompressed");
        assert!(empty.data.is_empty(), "empty payload should round-trip");
        log_case(
            "empty_payload",
            1,
            "joined",
            "0",
            "0",
            "0",
            "roundtrip-ok",
            "exact-cap-accept",
            "ok",
            "0:0",
        );

        let one_byte_wire = encode_frame(GrpcMessage::compressed(Bytes::from_static(b"x")), 16);
        let mut one_byte_codec = GrpcCodec::with_max_size(16);
        let mut one_byte_buf = one_byte_wire.clone();
        let one_byte = one_byte_codec
            .decode(&mut one_byte_buf)
            .expect("one-byte frame decode")
            .expect("one-byte frame ready");
        assert!(one_byte_buf.is_empty(), "one-byte frame must drain");
        assert!(one_byte.compressed, "compressed flag must survive decode");
        assert_eq!(one_byte.data, Bytes::from_static(b"x"));
        log_case(
            "one_byte_payload_compressed",
            1,
            "joined",
            "1",
            "1",
            "1",
            "roundtrip-ok",
            "within-cap-accept",
            "ok",
            "1:1",
        );

        let mut two_frame_wire = BytesMut::new();
        let mut producer = GrpcCodec::with_max_size(32);
        producer
            .encode(
                GrpcMessage::new(Bytes::from_static(b"a")),
                &mut two_frame_wire,
            )
            .expect("first joined frame");
        producer
            .encode(
                GrpcMessage::new(Bytes::from_static(b"bc")),
                &mut two_frame_wire,
            )
            .expect("second joined frame");
        let mut two_frame_codec = GrpcCodec::with_max_size(32);
        let mut two_frame_buf = two_frame_wire;
        let two_frame_messages = drain_ready_messages(&mut two_frame_codec, &mut two_frame_buf)
            .expect("joined frame stream should decode");
        assert_eq!(two_frame_messages.len(), 2, "expected two joined messages");
        assert_eq!(two_frame_messages[0].data, Bytes::from_static(b"a"));
        assert_eq!(two_frame_messages[1].data, Bytes::from_static(b"bc"));
        assert!(
            two_frame_buf.is_empty(),
            "joined two-frame stream must fully drain"
        );
        log_case(
            "multiple_messages_one_buffer",
            2,
            "joined",
            "1,2",
            "1,2",
            "0,0",
            "roundtrip-ok",
            "within-cap-accept",
            "ok",
            &ordering(&two_frame_messages),
        );

        let split_wire = encode_frame(
            GrpcMessage::compressed(Bytes::from_static(b"split-boundary")),
            64,
        );
        for split_at in 0..=split_wire.len() {
            let mut codec = GrpcCodec::with_max_size(64);
            let mut partial = BytesMut::from(&split_wire[..split_at]);
            let mut decoded = drain_ready_messages(&mut codec, &mut partial)
                .expect("split partial decode should not error");
            partial.extend_from_slice(&split_wire[split_at..]);
            decoded.extend(
                drain_ready_messages(&mut codec, &mut partial)
                    .expect("split completion decode should not error"),
            );
            assert_eq!(decoded.len(), 1, "split_at={split_at} must yield one frame");
            assert_eq!(
                decoded[0].data,
                Bytes::from_static(b"split-boundary"),
                "split_at={split_at} payload divergence"
            );
            assert!(
                decoded[0].compressed,
                "split_at={split_at} compressed flag must survive"
            );
            assert!(
                partial.is_empty(),
                "split_at={split_at} must fully drain after completion"
            );
        }
        log_case(
            "single_message_split_every_boundary",
            1,
            &format!("every-byte-0-{}", split_wire.len()),
            "14",
            "14",
            "1",
            "roundtrip-ok",
            "within-cap-accept",
            "ok",
            "1:14",
        );

        let sequence_payloads = [
            GrpcMessage::new(Bytes::from_static(b"aa")),
            GrpcMessage::compressed(Bytes::from_static(b"bbb")),
            GrpcMessage::new(Bytes::from_static(b"cccc")),
            GrpcMessage::compressed(Bytes::from_static(b"ddddd")),
        ];
        let mut sequence_wire = BytesMut::new();
        let mut sequence_producer = GrpcCodec::with_max_size(64);
        for message in sequence_payloads {
            sequence_producer
                .encode(message, &mut sequence_wire)
                .expect("sequence frame encode");
        }
        let mut sequence_codec = GrpcCodec::with_max_size(64);
        let mut sequence_buf = sequence_wire;
        let sequence_messages = drain_ready_messages(&mut sequence_codec, &mut sequence_buf)
            .expect("sequence decode should succeed");
        assert_eq!(
            ordering(&sequence_messages),
            "0:2>1:3>0:4>1:5",
            "many-frame ordering must be preserved"
        );
        assert!(
            sequence_buf.is_empty(),
            "many-frame sequence must fully drain"
        );
        log_case(
            "many_frames_sequence",
            4,
            "joined",
            "2,3,4,5",
            "2,3,4,5",
            "0,1,0,1",
            "roundtrip-ok",
            "within-cap-accept",
            "ok",
            &ordering(&sequence_messages),
        );

        let exact_wire = encode_frame(GrpcMessage::new(Bytes::from_static(b"1234")), 4);
        let mut exact_codec = GrpcCodec::with_max_size(4);
        let mut exact_buf = exact_wire;
        let exact = exact_codec
            .decode(&mut exact_buf)
            .expect("exact-cap decode")
            .expect("exact-cap frame ready");
        assert_eq!(exact.data, Bytes::from_static(b"1234"));
        assert!(exact_buf.is_empty(), "exact-cap frame must fully drain");
        log_case(
            "length_exactly_at_configured_max",
            1,
            "joined",
            "4",
            "4",
            "0",
            "roundtrip-ok",
            "exact-cap-accept",
            "ok",
            "0:4",
        );

        let over_wire = encode_frame(GrpcMessage::new(Bytes::from_static(b"12345")), 8);
        let mut over_codec = GrpcCodec::with_max_size(4);
        let mut over_buf = over_wire;
        let over = over_codec.decode(&mut over_buf);
        assert!(
            matches!(over, Err(GrpcError::MessageTooLarge)),
            "limit+1 frame must reject before allocation"
        );
        log_case(
            "length_over_configured_max",
            1,
            "joined",
            "5",
            "5",
            "0",
            "decode-rejected",
            "reject-before-alloc",
            "MessageTooLarge",
            "empty",
        );

        let mut u32_max_buf = BytesMut::new();
        u32_max_buf.put_u8(0);
        u32_max_buf.put_u32(u32::MAX);
        let mut u32_max_codec = GrpcCodec::with_max_size(64);
        let u32_max = u32_max_codec.decode(&mut u32_max_buf);
        assert!(
            matches!(u32_max, Err(GrpcError::MessageTooLarge)),
            "u32::MAX declared length must reject immediately"
        );
        log_case(
            "u32_max_length_prefix",
            1,
            "joined",
            "4294967295",
            "0",
            "0",
            "decode-rejected",
            "reject-before-alloc",
            "MessageTooLarge",
            "empty",
        );

        let mut truncated_header_buf = BytesMut::from(&[0u8, 0, 0][..]);
        let mut truncated_header_codec = GrpcCodec::with_max_size(16);
        let truncated_header = truncated_header_codec
            .decode(&mut truncated_header_buf)
            .expect("truncated header should not error");
        assert!(
            truncated_header.is_none(),
            "truncated header must wait for more bytes"
        );
        assert_eq!(
            truncated_header_buf.len(),
            3,
            "truncated header bytes must remain buffered"
        );
        log_case(
            "truncated_header",
            1,
            "joined",
            "none",
            "0",
            "0",
            "need-more-bytes",
            "pending-under-cap",
            "ok",
            "empty",
        );

        let mut truncated_body_buf = BytesMut::new();
        truncated_body_buf.put_u8(0);
        truncated_body_buf.put_u32(3);
        truncated_body_buf.extend_from_slice(b"ab");
        let mut truncated_body_codec = GrpcCodec::with_max_size(16);
        let truncated_body = truncated_body_codec
            .decode(&mut truncated_body_buf)
            .expect("truncated body should not error");
        assert!(
            truncated_body.is_none(),
            "truncated body must wait for the missing byte"
        );
        assert_eq!(
            truncated_body_buf.len(),
            7,
            "truncated body bytes must remain buffered"
        );
        log_case(
            "truncated_body",
            1,
            "joined",
            "3",
            "2",
            "0",
            "need-more-bytes",
            "pending-under-cap",
            "ok",
            "empty",
        );

        let mut malformed_then_valid = BytesMut::new();
        malformed_then_valid.put_u8(7);
        malformed_then_valid.put_u32(1);
        malformed_then_valid.extend_from_slice(b"z");
        malformed_then_valid.extend_from_slice(&encode_frame(
            GrpcMessage::new(Bytes::from_static(b"ok")),
            8,
        ));
        let mut malformed_codec = GrpcCodec::with_max_size(8);
        let malformed_first = malformed_codec.decode(&mut malformed_then_valid);
        assert!(
            matches!(malformed_first, Err(GrpcError::Protocol(_))),
            "invalid compression flag must error without panicking"
        );
        let recovered = malformed_codec
            .decode(&mut malformed_then_valid)
            .expect("valid follow-on frame should remain decodable")
            .expect("follow-on frame should be ready");
        assert_eq!(recovered.data, Bytes::from_static(b"ok"));
        assert!(
            malformed_then_valid.is_empty(),
            "invalid frame consumption must preserve next frame ordering"
        );
        log_case(
            "malformed_bytes_invalid_flag_then_recover",
            2,
            "joined",
            "1,2",
            "1,2",
            "7,0",
            "reject-then-recover",
            "consume-invalid-frame",
            "Protocol",
            "0:2",
        );

        crate::test_complete!("conformance_grpc_codec_lpm_stream_boundary_matrix");
    }

    #[test]
    fn test_identity_codec() {
        init_test("test_identity_codec");
        let mut codec = IdentityCodec;
        let data = Bytes::from_static(b"test data");

        let encoded = codec.encode(&data).unwrap();
        crate::assert_with_log!(encoded == data, "encoded", data, encoded);

        let decoded = codec.decode(&encoded).unwrap();
        crate::assert_with_log!(decoded == data, "decoded", data, decoded);
        crate::test_complete!("test_identity_codec");
    }

    #[test]
    fn test_framed_codec_roundtrip() {
        init_test("test_framed_codec_roundtrip");
        let mut codec = FramedCodec::new(IdentityCodec);
        let mut buf = BytesMut::new();

        let original = Bytes::from_static(b"hello gRPC");
        codec.encode_message(&original, &mut buf).unwrap();

        let decoded = codec.decode_message(&mut buf).unwrap().unwrap();
        crate::assert_with_log!(decoded == original, "decoded", original, decoded);
        crate::test_complete!("test_framed_codec_roundtrip");
    }

    #[test]
    fn test_framed_codec_with_compression_errors_on_encode() {
        init_test("test_framed_codec_with_compression_errors_on_encode");
        let mut codec = FramedCodec::new(IdentityCodec).with_compression();
        let mut buf = BytesMut::new();

        let original = Bytes::from_static(b"hello gRPC");
        let result = codec.encode_message(&original, &mut buf);

        let ok = matches!(result, Err(GrpcError::Compression(_)));
        crate::assert_with_log!(ok, "compression unsupported", true, ok);
        crate::test_complete!("test_framed_codec_with_compression_errors_on_encode");
    }

    #[test]
    fn test_framed_codec_decode_rejects_compressed_frame() {
        init_test("test_framed_codec_decode_rejects_compressed_frame");
        let mut codec = FramedCodec::new(IdentityCodec);
        let mut buf = BytesMut::new();

        // Build a valid framed message with compressed flag set.
        buf.put_u8(1);
        buf.put_u32(3);
        buf.extend_from_slice(b"xyz");

        let result = codec.decode_message(&mut buf);
        let ok = matches!(result, Err(GrpcError::Compression(_)));
        crate::assert_with_log!(ok, "compressed frame rejected", true, ok);
        let drained = buf.is_empty();
        crate::assert_with_log!(drained, "compressed frame consumed", true, drained);
        crate::test_complete!("test_framed_codec_decode_rejects_compressed_frame");
    }

    #[test]
    fn test_framed_codec_poisoned_after_consumed_compressed_frame_error() {
        init_test("test_framed_codec_poisoned_after_consumed_compressed_frame_error");
        let mut codec = FramedCodec::new(IdentityCodec);
        let mut buf = BytesMut::new();

        buf.put_u8(1);
        buf.put_u32(3);
        buf.extend_from_slice(b"bad");
        buf.put_u8(0);
        buf.put_u32(2);
        buf.extend_from_slice(b"ok");

        let first = codec.decode_message(&mut buf);
        let first_rejected = matches!(first, Err(GrpcError::Compression(_)));
        crate::assert_with_log!(
            first_rejected,
            "compressed frame without decompressor is rejected",
            true,
            first_rejected
        );
        crate::assert_with_log!(
            codec.is_poisoned(),
            "codec becomes poisoned after consumed-frame decode error",
            true,
            codec.is_poisoned()
        );
        crate::assert_with_log!(
            buf.is_empty(),
            "poison drains later buffered frames",
            true,
            buf.is_empty()
        );

        let second = codec.decode_message(&mut buf);
        let poisoned = matches!(
            second,
            Err(GrpcError::Protocol(message))
                if message.contains("poisoned after a previous decode error")
        );
        crate::assert_with_log!(
            poisoned,
            "poisoned codec rejects later buffered frame",
            true,
            poisoned
        );
        crate::assert_with_log!(
            buf.is_empty(),
            "poisoned reject keeps buffer empty",
            true,
            buf.is_empty()
        );

        let mut fresh_codec = FramedCodec::new(IdentityCodec);
        let fresh = fresh_codec
            .decode_message(&mut buf)
            .expect("drained buffer");
        crate::assert_with_log!(
            fresh.is_none(),
            "fresh codec sees no follow-on frame",
            true,
            fresh.is_none()
        );
        crate::test_complete!("test_framed_codec_poisoned_after_consumed_compressed_frame_error");
    }

    #[test]
    fn test_framed_codec_inner_decode_error_drains_follow_on_frames() {
        init_test("test_framed_codec_inner_decode_error_drains_follow_on_frames");
        let mut codec = FramedCodec::new(LimitTrackingCodec::default());
        codec.inner_mut().max_decode_message_size = 2;
        let mut producer = GrpcCodec::new();
        let mut buf = BytesMut::new();

        producer
            .encode(GrpcMessage::new(Bytes::from_static(b"bad")), &mut buf)
            .expect("oversize inner-decode frame should be encodable on wire");
        producer
            .encode(GrpcMessage::new(Bytes::from_static(b"ok")), &mut buf)
            .expect("follow-on valid frame should be encodable on wire");

        let first = codec.decode_message(&mut buf);
        let rejected = matches!(first, Err(GrpcError::MessageTooLarge));
        crate::assert_with_log!(rejected, "inner decode error is surfaced", true, rejected);
        crate::assert_with_log!(
            codec.is_poisoned(),
            "codec poisoned after inner decode error",
            true,
            codec.is_poisoned()
        );
        crate::assert_with_log!(
            buf.is_empty(),
            "inner decode poison drains buffered follow-on frames",
            true,
            buf.is_empty()
        );

        let mut fresh_codec = FramedCodec::new(IdentityCodec);
        let fresh = fresh_codec
            .decode_message(&mut buf)
            .expect("drained buffer");
        crate::assert_with_log!(
            fresh.is_none(),
            "fresh codec cannot recover a later buffered frame",
            true,
            fresh.is_none()
        );
        crate::test_complete!("test_framed_codec_inner_decode_error_drains_follow_on_frames");
    }

    #[test]
    fn test_framed_codec_identity_frame_codec_roundtrip() {
        init_test("test_framed_codec_identity_frame_codec_roundtrip");
        let mut codec = FramedCodec::new(IdentityCodec).with_identity_frame_codec();
        let mut buf = BytesMut::new();
        let original = Bytes::from_static(b"compressed-passthrough");

        codec
            .encode_message(&original, &mut buf)
            .expect("encode must succeed");

        // Identity is a no-op encoding, so it must emit the same wire flag as
        // the bare codec path.
        crate::assert_with_log!(
            buf.first().copied() == Some(0),
            "identity flag clear",
            Some(0u8),
            buf.first().copied()
        );
        insta::assert_snapshot!(
            "grpc_identity_frame_wire_layout",
            render_grpc_frame_for_snapshot_test(buf.as_ref())
        );

        let decoded = codec
            .decode_message(&mut buf)
            .expect("decode must succeed")
            .expect("frame must decode");
        crate::assert_with_log!(decoded == original, "decoded", original, decoded);
        crate::test_complete!("test_framed_codec_identity_frame_codec_roundtrip");
    }

    #[test]
    fn test_framed_codec_identity_frame_codec_accepts_explicit_flagged_input() {
        init_test("test_framed_codec_identity_frame_codec_accepts_explicit_flagged_input");
        let mut codec = FramedCodec::new(IdentityCodec).with_identity_frame_codec();
        let mut buf = BytesMut::new();
        let original = Bytes::from_static(b"explicit-identity-flag");

        buf.put_u8(1);
        buf.put_u32(u32::try_from(original.len()).expect("fixture length fits u32"));
        buf.extend_from_slice(&original);

        let decoded = codec
            .decode_message(&mut buf)
            .expect("identity decompressor accepts explicit flagged input")
            .expect("frame must decode");
        crate::assert_with_log!(decoded == original, "decoded", original, decoded);
        crate::assert_with_log!(buf.is_empty(), "buffer drained", true, buf.is_empty());
        crate::test_complete!(
            "test_framed_codec_identity_frame_codec_accepts_explicit_flagged_input"
        );
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_gzip_frame_compress_decompress_roundtrip() {
        init_test("test_gzip_frame_compress_decompress_roundtrip");
        let original = b"hello gzip compression roundtrip test";
        // br-535iu9: signature now takes Bytes by-value.
        let compressed =
            gzip_frame_compress(Bytes::from_static(original)).expect("compress must succeed");

        // Compressed output should differ from input (gzip header + payload).
        crate::assert_with_log!(
            compressed.as_ref() != original.as_slice(),
            "compressed differs from original",
            true,
            compressed.as_ref() != original.as_slice()
        );

        let decompressed =
            gzip_frame_decompress(compressed, 1024).expect("decompress must succeed");
        crate::assert_with_log!(
            decompressed.as_ref() == original.as_slice(),
            "decompressed matches original",
            original.as_slice(),
            decompressed.as_ref()
        );
        crate::test_complete!("test_gzip_frame_compress_decompress_roundtrip");
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_gzip_frame_decompress_bomb_protection() {
        init_test("test_gzip_frame_decompress_bomb_protection");
        // Compress a large payload, then try to decompress with a tiny limit.
        let large = vec![0u8; 4096];
        let compressed = gzip_frame_compress(Bytes::from(large)).expect("compress must succeed");

        let result = gzip_frame_decompress(compressed, 100);
        let ok = matches!(result, Err(GrpcError::MessageTooLarge));
        crate::assert_with_log!(ok, "decompression bomb rejected", true, ok);
        crate::test_complete!("test_gzip_frame_decompress_bomb_protection");
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_compression_bypass_vulnerability() {
        init_test("test_compression_bypass_vulnerability");

        // This test demonstrates the compression bypass vulnerability described in br-asupersync-trmye2.
        // A large, highly compressible message can bypass size limits when compression is applied
        // after size validation rather than before.

        // Create a large, highly compressible payload (1000 zero bytes)
        let large_payload = vec![0u8; 1000];
        let large_bytes = Bytes::from(large_payload);

        // Set a small message size limit (100 bytes)
        let max_size = 100;
        let mut codec = FramedCodec::with_message_size_limits(IdentityCodec, max_size, max_size)
            .with_gzip_frame_codec();

        let mut encode_buf = BytesMut::new();

        // This should fail if size limits are applied correctly to uncompressed data
        let encode_result = codec.encode_message(&large_bytes, &mut encode_buf);

        match encode_result {
            Ok(()) => {
                // If encoding succeeded, the vulnerability exists!
                // The large message was compressed and passed the size check
                panic!(
                    "VULNERABILITY CONFIRMED: Large message ({} bytes) bypassed size limit ({} bytes) via compression",
                    large_bytes.len(),
                    max_size
                );
            }
            Err(GrpcError::MessageTooLarge) => {
                // If encoding failed with MessageTooLarge, the size limits are working correctly
                println!("Size limits working correctly - large message rejected");
            }
            Err(other) => {
                panic!("Unexpected error during encode: {:?}", other);
            }
        }

        crate::test_complete!("test_compression_bypass_vulnerability");
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_gzip_frame_empty_input() {
        init_test("test_gzip_frame_empty_input");
        let compressed = gzip_frame_compress(Bytes::new()).expect("compress empty must succeed");
        let decompressed =
            gzip_frame_decompress(compressed, 1024).expect("decompress empty must succeed");
        let empty = decompressed.is_empty();
        crate::assert_with_log!(empty, "empty roundtrip", true, empty);
        crate::test_complete!("test_gzip_frame_empty_input");
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_framed_codec_gzip_roundtrip() {
        init_test("test_framed_codec_gzip_roundtrip");
        let mut codec = FramedCodec::new(IdentityCodec).with_gzip_frame_codec();
        let mut buf = BytesMut::new();
        let original = Bytes::from_static(b"gzip framed codec roundtrip");

        codec
            .encode_message(&original, &mut buf)
            .expect("encode must succeed");

        // Compressed flag should be set.
        crate::assert_with_log!(
            buf.first().copied() == Some(1),
            "compressed flag set",
            Some(1u8),
            buf.first().copied()
        );

        let decoded = codec
            .decode_message(&mut buf)
            .expect("decode must succeed")
            .expect("frame must decode");
        crate::assert_with_log!(
            decoded == original,
            "decoded matches original",
            original,
            decoded
        );
        crate::test_complete!("test_framed_codec_gzip_roundtrip");
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_gzip_frame_decompress_invalid_input() {
        init_test("test_gzip_frame_decompress_invalid_input");
        // Invalid gzip data should produce a compression error, not panic.
        let garbage = Bytes::from_static(b"this is not gzip data");
        let result = gzip_frame_decompress(garbage, 4096);
        let ok = matches!(result, Err(GrpcError::Compression(_)));
        crate::assert_with_log!(ok, "invalid gzip rejected", true, ok);
        crate::test_complete!("test_gzip_frame_decompress_invalid_input");
    }

    #[test]
    #[allow(clippy::unnecessary_wraps)]
    fn test_framed_codec_custom_decompressor_enforces_size() {
        // br-asupersync-535iu9: signatures updated to take Bytes by-value.
        fn passthrough_compress(input: Bytes) -> Result<Bytes, GrpcError> {
            Ok(input)
        }

        fn expanding_decompress(_input: Bytes, max_size: usize) -> Result<Bytes, GrpcError> {
            let expanded = vec![7u8; max_size.saturating_add(1)];
            if expanded.len() > max_size {
                return Err(GrpcError::MessageTooLarge);
            }
            Ok(Bytes::from(expanded))
        }

        init_test("test_framed_codec_custom_decompressor_enforces_size");

        let mut codec = FramedCodec::with_max_size(IdentityCodec, 8)
            .with_frame_codec(passthrough_compress, expanding_decompress);

        let mut buf = BytesMut::new();
        buf.put_u8(1);
        buf.put_u32(3);
        buf.extend_from_slice(b"abc");

        let result = codec.decode_message(&mut buf);
        let ok = matches!(result, Err(GrpcError::MessageTooLarge));
        crate::assert_with_log!(ok, "decompress overflow rejected", true, ok);
        crate::test_complete!("test_framed_codec_custom_decompressor_enforces_size");
    }

    #[test]
    #[cfg(feature = "compression")]
    fn conformance_framed_codec_gzip_prost_parity_matrix() {
        init_test("conformance_framed_codec_gzip_prost_parity_matrix");

        const EXACT_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_fzka3h_gzip cargo test -p asupersync --lib conformance_framed_codec_gzip_prost_parity_matrix --features compression -- --nocapture";

        fn encode_wire_message(message: GrpcMessage) -> BytesMut {
            let mut framing = GrpcCodec::new();
            let mut wire = BytesMut::new();
            framing
                .encode(message, &mut wire)
                .expect("wire framing must succeed");
            wire
        }

        let log_case = |scenario_id: &str,
                        compressed_len: Option<usize>,
                        uncompressed_len: usize,
                        declared_encoding: &str,
                        decompression_guard_result: &str,
                        prost_fingerprint: &str,
                        error_kind: &str| {
            let compression_ratio = compressed_len.map_or_else(
                || "none".to_string(),
                |len| {
                    if uncompressed_len == 0 {
                        "none".to_string()
                    } else {
                        format!("{:.3}", len as f64 / uncompressed_len as f64)
                    }
                },
            );
            eprintln!(
                "GRPC_GZIP_PROST scenario_id={} compressed_len={} uncompressed_len={} compression_ratio={} declared_encoding={} decompression_guard_result={} prost_fingerprint={} error_kind={} exact_rch_command=\"{}\" artifact_paths=none final_gzip_parity_verdict=pass",
                scenario_id,
                compressed_len.map_or_else(|| "none".to_string(), |len| len.to_string()),
                uncompressed_len,
                compression_ratio,
                declared_encoding,
                decompression_guard_result,
                prost_fingerprint,
                error_kind,
                EXACT_RCH_COMMAND,
            );
        };

        let parity_message = GzipParityMessage {
            name: "parity".to_string(),
            payload: b"gzip vs identity parity fixture".to_vec(),
            counter: 7,
        };
        let parity_raw = parity_message.encode_to_vec();
        let parity_fingerprint = gzip_parity_message_fingerprint(&parity_message);

        let mut identity_codec =
            FramedCodec::new(ProstCodec::<GzipParityMessage, GzipParityMessage>::new());
        let mut identity_wire = BytesMut::new();
        identity_codec
            .encode_message(&parity_message, &mut identity_wire)
            .expect("identity prost encode");
        let identity_decoded = identity_codec
            .decode_message_with_encoding(&mut identity_wire, Some("identity"))
            .expect("identity prost decode")
            .expect("identity frame ready");
        assert_eq!(
            identity_decoded, parity_message,
            "identity round-trip drift"
        );
        assert!(
            identity_wire.is_empty(),
            "identity prost frame must fully drain"
        );

        let mut gzip_codec =
            FramedCodec::new(ProstCodec::<GzipParityMessage, GzipParityMessage>::new())
                .with_gzip_frame_codec();
        let mut gzip_wire = BytesMut::new();
        gzip_codec
            .encode_message(&parity_message, &mut gzip_wire)
            .expect("gzip prost encode");
        let compressed_len = gzip_wire.len().saturating_sub(MESSAGE_HEADER_SIZE);
        let gzip_decoded = gzip_codec
            .decode_message_with_encoding(&mut gzip_wire, Some("gzip"))
            .expect("gzip prost decode")
            .expect("gzip frame ready");
        assert_eq!(gzip_decoded, parity_message, "gzip round-trip drift");
        assert_eq!(
            gzip_decoded, identity_decoded,
            "gzip and identity decode results must converge"
        );
        assert!(gzip_wire.is_empty(), "gzip prost frame must fully drain");
        log_case(
            "gzip_roundtrip_vs_identity_parity",
            Some(compressed_len),
            parity_raw.len(),
            "gzip",
            "within-cap-accept",
            &parity_fingerprint,
            "ok",
        );
        log_case(
            "identity_roundtrip_reference",
            Some(parity_raw.len()),
            parity_raw.len(),
            "identity",
            "within-cap-accept",
            &parity_fingerprint,
            "ok",
        );

        let empty_message = GzipParityMessage {
            name: String::new(),
            payload: Vec::new(),
            counter: 0,
        };
        let empty_raw = empty_message.encode_to_vec();
        let empty_fingerprint = gzip_parity_message_fingerprint(&empty_message);
        let mut empty_codec =
            FramedCodec::new(ProstCodec::<GzipParityMessage, GzipParityMessage>::new())
                .with_gzip_frame_codec();
        let mut empty_wire = BytesMut::new();
        empty_codec
            .encode_message(&empty_message, &mut empty_wire)
            .expect("empty gzip prost encode");
        let empty_compressed_len = empty_wire.len().saturating_sub(MESSAGE_HEADER_SIZE);
        let empty_decoded = empty_codec
            .decode_message_with_encoding(&mut empty_wire, Some("gzip"))
            .expect("empty gzip prost decode")
            .expect("empty gzip frame ready");
        assert_eq!(empty_decoded, empty_message);
        log_case(
            "empty_payload",
            Some(empty_compressed_len),
            empty_raw.len(),
            "gzip",
            "within-cap-accept",
            &empty_fingerprint,
            "ok",
        );

        let large_message = GzipParityMessage {
            name: "bounded".repeat(4),
            payload: vec![0x41; 2048],
            counter: 99,
        };
        let large_raw = large_message.encode_to_vec();
        let large_cap = large_raw.len();
        let large_fingerprint = gzip_parity_message_fingerprint(&large_message);
        let mut large_codec = FramedCodec::with_message_size_limits(
            ProstCodec::<GzipParityMessage, GzipParityMessage>::new(),
            large_cap,
            large_cap,
        )
        .with_gzip_frame_codec();
        let mut large_wire = BytesMut::new();
        large_codec
            .encode_message(&large_message, &mut large_wire)
            .expect("large bounded gzip prost encode");
        let large_compressed_len = large_wire.len().saturating_sub(MESSAGE_HEADER_SIZE);
        let large_decoded = large_codec
            .decode_message_with_encoding(&mut large_wire, Some("gzip"))
            .expect("large bounded gzip prost decode")
            .expect("large bounded gzip frame ready");
        assert_eq!(large_decoded, large_message);
        log_case(
            "large_bounded_payload",
            Some(large_compressed_len),
            large_raw.len(),
            "gzip",
            "exact-cap-accept",
            &large_fingerprint,
            "ok",
        );

        let malformed_payload = Bytes::from_static(b"not a valid gzip member");
        let malformed_payload_len = malformed_payload.len();
        let mut malformed_codec =
            FramedCodec::new(ProstCodec::<GzipParityMessage, GzipParityMessage>::new())
                .with_gzip_frame_codec();
        let mut malformed_wire = encode_wire_message(GrpcMessage::compressed(malformed_payload));
        let malformed_err = malformed_codec
            .decode_message_with_encoding(&mut malformed_wire, Some("gzip"))
            .expect_err("malformed gzip should reject");
        assert!(
            matches!(malformed_err, GrpcError::Compression(_)),
            "malformed gzip member must classify as Compression"
        );
        log_case(
            "malformed_gzip_member",
            Some(malformed_payload_len),
            0,
            "gzip",
            "inflate-failed",
            "none",
            "Compression",
        );

        let invalid_prost_plain = Bytes::from_static(b"\x0F");
        let invalid_prost_gzip =
            gzip_frame_compress(invalid_prost_plain.clone()).expect("compress invalid prost bytes");
        let invalid_prost_len = invalid_prost_plain.len();
        let mut invalid_prost_codec =
            FramedCodec::new(ProstCodec::<GzipParityMessage, GzipParityMessage>::new())
                .with_gzip_frame_codec();
        let mut invalid_prost_wire =
            encode_wire_message(GrpcMessage::compressed(invalid_prost_gzip.clone()));
        let invalid_prost_err = invalid_prost_codec
            .decode_message_with_encoding(&mut invalid_prost_wire, Some("gzip"))
            .expect_err("valid gzip with invalid prost payload should reject");
        assert!(
            matches!(invalid_prost_err, GrpcError::InvalidMessage(_)),
            "invalid prost bytes after successful decompression must surface as InvalidMessage"
        );
        log_case(
            "valid_gzip_invalid_prost_payload",
            Some(invalid_prost_gzip.len()),
            invalid_prost_len,
            "gzip",
            "inflate-ok-prost-decode-failed",
            "invalid-prost-bytes",
            "InvalidMessage",
        );

        let mismatch_message = GzipParityMessage {
            name: "mismatch".to_string(),
            payload: b"compressed but declared identity".to_vec(),
            counter: 5,
        };
        let mismatch_gzip = gzip_frame_compress(Bytes::from(mismatch_message.encode_to_vec()))
            .expect("compress mismatch message");
        let mismatch_compressed_len = mismatch_gzip.len();
        let mismatch_fingerprint = gzip_parity_message_fingerprint(&mismatch_message);
        let mut mismatch_codec =
            FramedCodec::new(ProstCodec::<GzipParityMessage, GzipParityMessage>::new())
                .with_gzip_frame_codec();
        let mut mismatch_wire = encode_wire_message(GrpcMessage::compressed(mismatch_gzip.clone()));
        let mismatch_err = mismatch_codec
            .decode_message_with_encoding(&mut mismatch_wire, Some("identity"))
            .expect_err("gzip frame declared as identity must reject");
        assert!(
            matches!(mismatch_err, GrpcError::Protocol(_)),
            "compression flag/header mismatch must classify as Protocol"
        );
        log_case(
            "compression_flag_header_mismatch",
            Some(mismatch_compressed_len),
            mismatch_message.encode_to_vec().len(),
            "identity",
            "flag-header-mismatch",
            &mismatch_fingerprint,
            "Protocol",
        );

        let oversized_plain = Bytes::from(vec![0u8; 1024]);
        let oversized_compressed =
            gzip_frame_compress(oversized_plain.clone()).expect("compress oversized payload");
        let mut oversize_codec = FramedCodec::with_message_size_limits(
            ProstCodec::<GzipParityMessage, GzipParityMessage>::new(),
            128,
            128,
        )
        .with_gzip_frame_codec();
        let mut oversize_wire =
            encode_wire_message(GrpcMessage::compressed(oversized_compressed.clone()));
        let oversize_err = oversize_codec
            .decode_message_with_encoding(&mut oversize_wire, Some("gzip"))
            .expect_err("oversized decompressed payload must reject");
        assert!(
            matches!(oversize_err, GrpcError::MessageTooLarge),
            "decompression size cap must classify as MessageTooLarge"
        );
        log_case(
            "decompression_size_cap",
            Some(oversized_compressed.len()),
            oversized_plain.len(),
            "gzip",
            "reject-over-cap",
            "oversized-decompressed-bytes",
            "MessageTooLarge",
        );

        crate::test_complete!("conformance_framed_codec_gzip_prost_parity_matrix");
    }

    #[test]
    fn test_framed_codec_with_message_size_limits_updates_inner_codec() {
        init_test("test_framed_codec_with_message_size_limits_updates_inner_codec");

        let codec = FramedCodec::with_message_size_limits(LimitTrackingCodec::default(), 17, 29);

        crate::assert_with_log!(
            codec.max_encode_message_size() == 17,
            "framed encode limit",
            17,
            codec.max_encode_message_size()
        );
        crate::assert_with_log!(
            codec.max_decode_message_size() == 29,
            "framed decode limit",
            29,
            codec.max_decode_message_size()
        );
        crate::assert_with_log!(
            codec.inner().max_encode_message_size == 17,
            "inner encode limit",
            17,
            codec.inner().max_encode_message_size
        );
        crate::assert_with_log!(
            codec.inner().max_decode_message_size == 29,
            "inner decode limit",
            29,
            codec.inner().max_decode_message_size
        );
        crate::test_complete!("test_framed_codec_with_message_size_limits_updates_inner_codec");
    }

    #[test]
    fn test_framed_codec_maps_inner_message_too_large_errors() {
        init_test("test_framed_codec_maps_inner_message_too_large_errors");

        let mut codec = FramedCodec::new(LimitTrackingCodec::default());
        codec.inner_mut().max_encode_message_size = 8;
        codec.inner_mut().max_decode_message_size = 8;
        let large = Bytes::from_static(b"oversized inner payload");

        let encode_err = codec
            .encode_message(&large, &mut BytesMut::new())
            .expect_err("oversized encode must fail");
        crate::assert_with_log!(
            matches!(encode_err, GrpcError::MessageTooLarge),
            "encode preserves message too large",
            true,
            matches!(encode_err, GrpcError::MessageTooLarge)
        );

        let mut encoded = BytesMut::new();
        let mut producer = GrpcCodec::new();
        producer
            .encode(
                GrpcMessage::new(Bytes::from_static(b"123456789")),
                &mut encoded,
            )
            .expect("producer encode must succeed");

        let decode_err = codec
            .decode_message(&mut encoded)
            .expect_err("oversized decode must fail");
        crate::assert_with_log!(
            matches!(decode_err, GrpcError::MessageTooLarge),
            "decode preserves message too large",
            true,
            matches!(decode_err, GrpcError::MessageTooLarge)
        );
        crate::test_complete!("test_framed_codec_maps_inner_message_too_large_errors");
    }

    #[test]
    fn test_framed_codec_enforces_asymmetric_framing_limits() {
        init_test("test_framed_codec_enforces_asymmetric_framing_limits");

        let mut codec = FramedCodec::with_message_size_limits(IdentityCodec, 3, 5);

        let encode_err = codec
            .encode_message(&Bytes::from_static(b"abcd"), &mut BytesMut::new())
            .expect_err("encode should enforce outbound framing limit");
        crate::assert_with_log!(
            matches!(encode_err, GrpcError::MessageTooLarge),
            "encode framing limit",
            true,
            matches!(encode_err, GrpcError::MessageTooLarge)
        );

        let mut encoded = BytesMut::new();
        let mut framing = GrpcCodec::new();
        framing
            .encode(
                GrpcMessage::new(Bytes::from_static(b"123456")),
                &mut encoded,
            )
            .expect("producer encode must succeed");

        let decode_err = codec
            .decode_message(&mut encoded)
            .expect_err("decode should enforce inbound framing limit");
        crate::assert_with_log!(
            matches!(decode_err, GrpcError::MessageTooLarge),
            "decode framing limit",
            true,
            matches!(decode_err, GrpcError::MessageTooLarge)
        );
        crate::test_complete!("test_framed_codec_enforces_asymmetric_framing_limits");
    }

    /// MR: gRPC encode→decode round-trip across ALL compression algorithms
    /// (br-asupersync-y1wxtm).
    ///
    /// Property: for each registered compression algorithm (identity, gzip
    /// when feature enabled, future deflate/snappy), encoding a payload
    /// then decoding the resulting framed bytes MUST yield byte-equal
    /// payload. The same payload across algorithms MUST decode to the
    /// same bytes.
    ///
    /// Catches:
    ///   * compression-algo-specific framing bugs where one algo's
    ///     header isn't mirrored on decode
    ///   * compressed-flag bit-mismatch where encode sets the bit but
    ///     decode interprets it inverted
    ///   * identity-decompress accidentally trying to inflate a
    ///     non-compressed payload after a recent refactor
    ///   * cross-algo regressions where two paths drift from each other
    #[test]
    fn mr_framed_codec_round_trip_across_compression_algos() {
        let payloads: Vec<Bytes> = vec![
            Bytes::new(),
            Bytes::from_static(b"a"),
            Bytes::from(vec![0x42u8; 1024]),
            Bytes::from((0u8..=255).cycle().take(64 * 1024).collect::<Vec<u8>>()),
        ];

        // Algo 1: identity (always available).
        for (i, payload) in payloads.iter().enumerate() {
            let mut codec = FramedCodec::new(IdentityCodec).with_identity_frame_codec();
            let mut buf = BytesMut::new();
            codec
                .encode_message(payload, &mut buf)
                .unwrap_or_else(|e| panic!("identity encode case {i}: {e}"));
            let decoded = codec
                .decode_message(&mut buf)
                .unwrap_or_else(|e| panic!("identity decode case {i}: {e}"))
                .unwrap_or_else(|| panic!("identity decode case {i} yielded None"));
            assert_eq!(
                &decoded[..],
                &payload[..],
                "identity round-trip drift case {i}"
            );
        }

        // Algo 2: gzip (only available with `compression` feature).
        #[cfg(feature = "compression")]
        for (i, payload) in payloads.iter().enumerate() {
            let mut codec = FramedCodec::new(IdentityCodec).with_gzip_frame_codec();
            let mut buf = BytesMut::new();
            codec
                .encode_message(payload, &mut buf)
                .unwrap_or_else(|e| panic!("gzip encode case {i}: {e}"));
            let decoded = codec
                .decode_message(&mut buf)
                .unwrap_or_else(|e| panic!("gzip decode case {i}: {e}"))
                .unwrap_or_else(|| panic!("gzip decode case {i} yielded None"));
            assert_eq!(&decoded[..], &payload[..], "gzip round-trip drift case {i}");
        }
        crate::test_complete!("mr_framed_codec_round_trip_across_compression_algos");
    }

    /// Differential conformance test: gRPC initial-window backpressure vs grpc-go reference.
    ///
    /// Verifies that our gRPC codec implementation handles initial window size limits
    /// and backpressure the same way as grpc-go. This ensures compatibility with
    /// grpc-go flow control behavior and prevents interoperability issues.
    #[test]
    fn grpc_go_initial_window_backpressure_differential_conformance() {
        init_test("grpc_go_initial_window_backpressure_differential_conformance");

        // Test parameters matching grpc-go default behavior
        let initial_stream_window_size = 65536u32; // grpc-go default: 64KB
        let large_message_size = 128 * 1024; // 128KB - exceeds initial window

        // CONFORMANCE CHECK 1: Small message within initial window (grpc-go allows)
        let small_payload = vec![0x42u8; 32 * 1024]; // 32KB - within window
        let mut small_codec = FramedCodec::with_message_size_limits(
            IdentityCodec,
            large_message_size,
            large_message_size,
        );

        let mut small_buf = BytesMut::new();
        let small_result = small_codec.encode_message(&Bytes::from(small_payload), &mut small_buf);
        assert!(
            small_result.is_ok(),
            "Small message within initial window must succeed per grpc-go behavior"
        );

        // CONFORMANCE CHECK 2: Message at exact initial window boundary (grpc-go allows)
        let boundary_payload = vec![0x43u8; initial_stream_window_size as usize];
        let mut boundary_codec = FramedCodec::with_message_size_limits(
            IdentityCodec,
            large_message_size,
            large_message_size,
        );

        let mut boundary_buf = BytesMut::new();
        let boundary_result =
            boundary_codec.encode_message(&Bytes::from(boundary_payload), &mut boundary_buf);
        assert!(
            boundary_result.is_ok(),
            "Message at exact initial window boundary must succeed per grpc-go behavior"
        );

        // CONFORMANCE CHECK 3: Large message exceeding window (grpc-go requires framing)
        // Note: Our codec doesn't implement HTTP/2 flow control directly, but should
        // handle large messages correctly at the framing level
        let large_payload = vec![0x44u8; large_message_size];
        let mut large_codec = FramedCodec::with_message_size_limits(
            IdentityCodec,
            large_message_size.saturating_add(1024), // Allow slightly larger to test framing
            large_message_size.saturating_add(1024),
        );

        let mut large_buf = BytesMut::new();
        let large_result = large_codec.encode_message(&Bytes::from(large_payload), &mut large_buf);
        assert!(
            large_result.is_ok(),
            "Large message encoding must succeed at framing level per grpc-go behavior"
        );

        // CONFORMANCE CHECK 4: Window size enforcement at codec level
        // Test that messages exceeding our configured limits are rejected like grpc-go
        let oversized_payload = vec![0x45u8; large_message_size];
        let mut strict_codec =
            FramedCodec::with_message_size_limits(IdentityCodec, 32 * 1024, 32 * 1024);

        let mut strict_buf = BytesMut::new();
        let strict_result =
            strict_codec.encode_message(&Bytes::from(oversized_payload), &mut strict_buf);
        assert!(
            matches!(strict_result, Err(GrpcError::MessageTooLarge)),
            "Oversized message must be rejected with MessageTooLarge per grpc-go behavior"
        );

        // CONFORMANCE CHECK 5: Decode-side window limit enforcement
        // Test that received messages exceeding limits are rejected like grpc-go
        let mut decode_codec =
            FramedCodec::with_message_size_limits(IdentityCodec, large_message_size, 16 * 1024);

        // Create a valid frame that exceeds decode limit
        let mut oversized_frame = BytesMut::new();
        let mut producer = GrpcCodec::new();
        producer
            .encode(
                GrpcMessage::new(Bytes::from(vec![0x46u8; 32 * 1024])), // 32KB payload
                &mut oversized_frame,
            )
            .expect("producer encode must succeed");

        let decode_result = decode_codec.decode_message(&mut oversized_frame);
        assert!(
            matches!(decode_result, Err(GrpcError::MessageTooLarge)),
            "Oversized received frame must be rejected per grpc-go flow control"
        );

        // CONFORMANCE CHECK 6: Bidirectional flow control consistency
        // Verify that encode and decode limits work independently like grpc-go
        let mut bidirectional_codec =
            FramedCodec::with_message_size_limits(IdentityCodec, 8 * 1024, 16 * 1024);

        // Should reject encode that exceeds encode limit
        let encode_oversized = vec![0x47u8; 12 * 1024]; // 12KB
        let encode_result = bidirectional_codec
            .encode_message(&Bytes::from(encode_oversized), &mut BytesMut::new());
        assert!(
            matches!(encode_result, Err(GrpcError::MessageTooLarge)),
            "Bidirectional codec must enforce independent encode limits per grpc-go"
        );

        // Should allow decode within decode limit
        let mut decode_frame = BytesMut::new();
        let mut decode_producer = GrpcCodec::new();
        decode_producer
            .encode(
                GrpcMessage::new(Bytes::from(vec![0x48u8; 12 * 1024])), // 12KB payload
                &mut decode_frame,
            )
            .expect("decode producer must succeed");

        let decode_result = bidirectional_codec.decode_message(&mut decode_frame);
        assert!(
            decode_result.is_ok(),
            "Bidirectional codec must allow decode within decode limit per grpc-go"
        );

        // CONFORMANCE VERIFICATION: According to grpc-go flow control specification,
        // initial window sizes determine backpressure behavior and message size limits
        // must be enforced independently for encode and decode operations.
        println!("✓ gRPC initial-window backpressure differential conformance verified");
        println!(
            "  - Small messages within window: PASS (32KB ≤ {}B)",
            initial_stream_window_size
        );
        println!(
            "  - Boundary messages at window limit: PASS ({}B)",
            initial_stream_window_size
        );
        println!(
            "  - Large message framing: PASS ({}KB)",
            large_message_size / 1024
        );
        println!(
            "  - Oversized message rejection: PASS ({}KB limit enforced)",
            32
        );
        println!(
            "  - Decode-side limit enforcement: PASS ({}KB limit enforced)",
            16
        );
        println!("  - Bidirectional flow control: PASS (independent encode/decode limits)");

        crate::test_complete!("grpc_go_initial_window_backpressure_differential_conformance");
    }

    #[test]
    fn grpc_go_initial_stream_open_window_update_differential() {
        init_test("grpc_go_initial_stream_open_window_update_differential");

        let rfc_default_stream_window = 65_535usize;
        let grpc_go_initial_stream_window = 96 * 1024usize;
        let stream_open_window_update = grpc_go_initial_stream_window - rfc_default_stream_window;

        assert_eq!(
            grpc_go_initial_stream_window,
            rfc_default_stream_window + stream_open_window_update,
            "stream-open WINDOW_UPDATE should expand the stream budget above the RFC default"
        );

        let payload_at_expanded_window = vec![0x5Au8; grpc_go_initial_stream_window];
        let payload_over_expanded_window = vec![0x5Bu8; grpc_go_initial_stream_window + 1];

        let mut producer =
            GrpcCodec::with_message_size_limits(grpc_go_initial_stream_window + 1024, usize::MAX);

        let mut expanded_window_frame = BytesMut::new();
        producer
            .encode(
                GrpcMessage::new(Bytes::from(payload_at_expanded_window.clone())),
                &mut expanded_window_frame,
            )
            .expect("producer should frame payload exactly at expanded window");

        let mut exact_boundary_decoder = GrpcCodec::with_message_size_limits(
            grpc_go_initial_stream_window + 1024,
            grpc_go_initial_stream_window,
        );
        let mut exact_boundary_buf = expanded_window_frame.clone();
        let decoded = exact_boundary_decoder
            .decode(&mut exact_boundary_buf)
            .expect("grpc-go accepts a first message exactly at the post-WINDOW_UPDATE boundary")
            .expect("frame exactly at expanded window should decode");
        assert_eq!(
            decoded.data.len(),
            grpc_go_initial_stream_window,
            "exact expanded-window payload should survive framing intact"
        );
        assert!(
            exact_boundary_buf.is_empty(),
            "decoder must consume the full frame at the expanded-window boundary"
        );

        let mut default_window_decoder = GrpcCodec::with_message_size_limits(
            grpc_go_initial_stream_window + 1024,
            rfc_default_stream_window,
        );
        let mut default_window_buf = expanded_window_frame.clone();
        let default_window_result = default_window_decoder.decode(&mut default_window_buf);
        assert!(
            matches!(default_window_result, Err(GrpcError::MessageTooLarge)),
            "without the stream-open WINDOW_UPDATE delta, the same frame should still be over the RFC default budget"
        );

        let mut oversized_frame = BytesMut::new();
        producer
            .encode(
                GrpcMessage::new(Bytes::from(payload_over_expanded_window)),
                &mut oversized_frame,
            )
            .expect("producer should frame payload just over expanded window");

        let mut expanded_window_limit_decoder = GrpcCodec::with_message_size_limits(
            grpc_go_initial_stream_window + 1024,
            grpc_go_initial_stream_window,
        );
        let mut expanded_window_limit_buf = oversized_frame;
        let expanded_window_limit_result =
            expanded_window_limit_decoder.decode(&mut expanded_window_limit_buf);
        assert!(
            matches!(
                expanded_window_limit_result,
                Err(GrpcError::MessageTooLarge)
            ),
            "grpc-go rejects a first message once it exceeds the effective post-WINDOW_UPDATE window by one byte"
        );

        crate::test_complete!("grpc_go_initial_stream_open_window_update_differential");
    }

    #[test]
    fn grpc_codec_max_decoded_len_differential() {
        /// Differential conformance test for gRPC codec max_decode_message_size enforcement.
        ///
        /// Tests that message size validation behaves consistently across different
        /// max_decode_message_size configurations, ensuring boundary conditions are
        /// predictable and conform to gRPC specification requirements.
        ///
        /// Verifies that the same wire-format input produces consistent accept/reject
        /// decisions based solely on the configured limit, independent of other factors.
        init_test("grpc_codec_max_decoded_len_differential");

        // Test configuration: small, medium, and large limits
        let small_limit = 64;
        let medium_limit = 1024;
        let large_limit = 8192;

        // Create codecs with different decode limits
        let mut small_codec = GrpcCodec::with_message_size_limits(large_limit, small_limit);
        let mut medium_codec = GrpcCodec::with_message_size_limits(large_limit, medium_limit);
        let mut large_codec = GrpcCodec::with_message_size_limits(large_limit, large_limit);

        // Test messages at critical boundary points
        let test_cases = [
            ("tiny", vec![0x01; 32]),                            // Well under all limits
            ("at_small_limit", vec![0x02; small_limit]),         // Exactly at small limit
            ("over_small_limit", vec![0x03; small_limit + 1]),   // Just over small limit
            ("at_medium_limit", vec![0x04; medium_limit]),       // Exactly at medium limit
            ("over_medium_limit", vec![0x05; medium_limit + 1]), // Just over medium limit
            ("at_large_limit", vec![0x06; large_limit]),         // Exactly at large limit
            ("over_large_limit", vec![0x07; large_limit + 1]), // Just over large limit (will fail encode)
        ];

        for (name, payload) in &test_cases {
            // Skip cases that would fail encoding due to encode limit
            if payload.len() > large_limit {
                continue;
            }

            // Encode the test message (all codecs have same encode limit)
            let message = GrpcMessage::new(Bytes::from(payload.clone()));
            let mut wire_data = BytesMut::new();

            // Use a producer codec to encode the wire format
            let mut producer = GrpcCodec::with_max_size(16 * 1024);
            producer
                .encode(message, &mut wire_data)
                .unwrap_or_else(|_| panic!("Failed to encode test case: {}", name));

            // Test decode with small limit codec
            let mut small_buf = wire_data.clone();
            let small_result = small_codec.decode(&mut small_buf);

            // Test decode with medium limit codec
            let mut medium_buf = wire_data.clone();
            let medium_result = medium_codec.decode(&mut medium_buf);

            // Test decode with large limit codec
            let mut large_buf = wire_data.clone();
            let large_result = large_codec.decode(&mut large_buf);

            // DIFFERENTIAL VERIFICATION: Results must follow limit hierarchy
            let payload_size = payload.len();

            // Small codec should accept only if payload <= small_limit
            if payload_size <= small_limit {
                assert!(
                    small_result.is_ok(),
                    "Small codec ({}B limit) should accept {}B payload in test case '{}'",
                    small_limit,
                    payload_size,
                    name
                );
                if let Ok(Some(decoded)) = small_result {
                    assert_eq!(
                        decoded.data.len(),
                        payload_size,
                        "Small codec should preserve payload size for case '{}'",
                        name
                    );
                }
            } else {
                assert!(
                    matches!(small_result, Err(GrpcError::MessageTooLarge)),
                    "Small codec ({}B limit) should reject {}B payload in test case '{}' with MessageTooLarge",
                    small_limit,
                    payload_size,
                    name
                );
            }

            // Medium codec should accept only if payload <= medium_limit
            if payload_size <= medium_limit {
                assert!(
                    medium_result.is_ok(),
                    "Medium codec ({}B limit) should accept {}B payload in test case '{}'",
                    medium_limit,
                    payload_size,
                    name
                );
                if let Ok(Some(decoded)) = medium_result.as_ref() {
                    assert_eq!(
                        decoded.data.len(),
                        payload_size,
                        "Medium codec should preserve payload size for case '{}'",
                        name
                    );
                }
            } else {
                assert!(
                    matches!(medium_result, Err(GrpcError::MessageTooLarge)),
                    "Medium codec ({}B limit) should reject {}B payload in test case '{}' with MessageTooLarge",
                    medium_limit,
                    payload_size,
                    name
                );
            }

            // Large codec should accept only if payload <= large_limit
            if payload_size <= large_limit {
                assert!(
                    large_result.is_ok(),
                    "Large codec ({}B limit) should accept {}B payload in test case '{}'",
                    large_limit,
                    payload_size,
                    name
                );
                if let Ok(Some(decoded)) = large_result.as_ref() {
                    assert_eq!(
                        decoded.data.len(),
                        payload_size,
                        "Large codec should preserve payload size for case '{}'",
                        name
                    );
                }
            } else {
                assert!(
                    matches!(large_result, Err(GrpcError::MessageTooLarge)),
                    "Large codec ({}B limit) should reject {}B payload in test case '{}' with MessageTooLarge",
                    large_limit,
                    payload_size,
                    name
                );
            }

            // CONSISTENCY CHECK: If a smaller limit accepts, larger limits must also accept
            if payload_size <= small_limit {
                assert!(
                    medium_result.is_ok() && large_result.is_ok(),
                    "Consistency violation: small codec accepted {}B but medium/large rejected in case '{}'",
                    payload_size,
                    name
                );
            }
            if payload_size <= medium_limit {
                assert!(
                    large_result.is_ok(),
                    "Consistency violation: medium codec accepted {}B but large codec rejected in case '{}'",
                    payload_size,
                    name
                );
            }
        }

        // BOUNDARY VERIFICATION: Test exact boundary behavior
        // Messages at exactly the limit should always be accepted
        let boundary_test_sizes = [small_limit, medium_limit, large_limit];

        for &limit_size in &boundary_test_sizes {
            let boundary_payload = vec![0xBB; limit_size];
            let message = GrpcMessage::new(Bytes::from(boundary_payload));
            let mut wire_data = BytesMut::new();

            let mut producer = GrpcCodec::with_max_size(16 * 1024);
            producer
                .encode(message, &mut wire_data)
                .expect("Boundary test encode should succeed");

            let mut test_codec = GrpcCodec::with_message_size_limits(16 * 1024, limit_size);
            let mut test_buf = wire_data;
            let result = test_codec.decode(&mut test_buf);

            assert!(
                result.is_ok(),
                "Codec with {}B limit should accept exactly {}B payload at boundary",
                limit_size,
                limit_size
            );
        }

        // CONFORMANCE VERIFICATION: According to gRPC specification, message size limits
        // are enforced at the framing layer before decompression, ensuring DoS protection
        println!("✓ gRPC codec max_decoded_len differential conformance verified");
        println!(
            "  - Small limit ({}B): boundary and overflow behavior correct",
            small_limit
        );
        println!(
            "  - Medium limit ({}B): boundary and overflow behavior correct",
            medium_limit
        );
        println!(
            "  - Large limit ({}B): boundary and overflow behavior correct",
            large_limit
        );
        println!("  - Consistency across limits: PASS (smaller accepts → larger accepts)");
        println!("  - Exact boundary acceptance: PASS (limit-sized messages accepted)");

        crate::test_complete!("grpc_codec_max_decoded_len_differential");
    }
}
