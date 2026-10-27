//! gRPC message framing codec.
//!
//! Implements the gRPC message framing format:
//! - 1 byte: compressed flag (0 = uncompressed, 1 = compressed)
//! - 4 bytes: message length (big-endian)
//! - N bytes: message payload

use crate::bytes::{BufMut, Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};
use std::fmt;

use super::status::{GrpcError, Status};

// Re-export from parent module (single source of truth).
pub use super::DEFAULT_MAX_MESSAGE_SIZE;

/// gRPC message header size (1 byte flag + 4 bytes length).
pub const MESSAGE_HEADER_SIZE: usize = 5;

#[derive(Clone, Copy)]
enum EncodingValidation {
    Legacy,
    Negotiated,
}

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
                src.advance(MESSAGE_HEADER_SIZE + length);
                return Err(GrpcError::protocol(format!(
                    "invalid gRPC compression flag: {invalid}"
                )));
            }
        };

        // Consume header (advance the front offset; no throwaway alloc+copy)
        src.advance(MESSAGE_HEADER_SIZE);

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

/// Per-call cumulative decoded-body meter for inbound gRPC messages.
///
/// The meter is intentionally attached to the per-call [`FramedCodec`]
/// created by the server. That keeps client-streaming accounting scoped to
/// one RPC and ensures every successfully decoded message is charged exactly
/// once before it can be delivered to a handler.
#[derive(Debug, Clone, Copy)]
pub struct RequestBodyMeter {
    cap: Option<usize>,
    accumulated: usize,
    overflowed: bool,
}

impl RequestBodyMeter {
    /// Construct a new meter with the configured cap.
    ///
    /// `cap = None` disables enforcement while retaining saturating
    /// diagnostic accounting.
    #[must_use]
    pub const fn new(cap: Option<usize>) -> Self {
        Self {
            cap,
            accumulated: 0,
            overflowed: false,
        }
    }

    /// Accumulated decoded payload bytes for this call.
    #[must_use]
    pub const fn bytes_accumulated(&self) -> usize {
        self.accumulated
    }

    /// Configured cap (`None` means unlimited).
    #[must_use]
    pub const fn cap(&self) -> Option<usize> {
        self.cap
    }

    /// Charge one successfully decoded message to this call.
    ///
    /// Arithmetic overflow fails closed when a cap is configured. Without a
    /// cap, accounting saturates at `usize::MAX` and decoding remains enabled.
    pub fn record_message_bytes(&mut self, bytes: usize) -> Result<(), Status> {
        let Some(cap) = self.cap else {
            self.accumulated = self.accumulated.saturating_add(bytes);
            return Ok(());
        };

        if self.overflowed {
            return Err(Status::resource_exhausted(format!(
                "request body exceeds max_request_body_bytes: a prior byte-total overflow \
                 remains > {cap} bytes (aggregate of all decoded messages on this call; \
                 see ServerConfig::max_request_body_bytes)"
            )));
        }

        let previous = self.accumulated;
        let Some(actual) = previous.checked_add(bytes) else {
            self.accumulated = usize::MAX;
            self.overflowed = true;
            return Err(Status::resource_exhausted(format!(
                "request body exceeds max_request_body_bytes: byte total overflow after \
                 {previous} + {bytes}, which is > {cap} bytes \
                 (aggregate of all decoded messages on this call; \
                 see ServerConfig::max_request_body_bytes)"
            )));
        };

        self.accumulated = actual;
        if actual > cap {
            return Err(Status::resource_exhausted(format!(
                "request body exceeds max_request_body_bytes: {actual} bytes > {cap} bytes \
                 (aggregate of all decoded messages on this call; \
                 see ServerConfig::max_request_body_bytes)"
            )));
        }
        Ok(())
    }
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
    /// Per-call aggregate accounting for successfully decoded request bodies.
    request_body_meter: RequestBodyMeter,
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
            .field("request_body_meter", &self.request_body_meter)
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
            request_body_meter: RequestBodyMeter::new(None),
        }
    }

    /// Configure the aggregate decoded-body limit for this call.
    ///
    /// The codec charges the decompressed payload length after the inner
    /// message decoder succeeds. The first message that pushes the cumulative
    /// total above `cap` is not delivered and poisons the request stream.
    #[must_use]
    pub fn with_request_body_limit(mut self, cap: Option<usize>) -> Self {
        self.request_body_meter = RequestBodyMeter::new(cap);
        self
    }

    /// Return this call's aggregate decoded-body meter.
    #[must_use]
    pub const fn request_body_meter(&self) -> &RequestBodyMeter {
        &self.request_body_meter
    }

    /// Set optional frame-level compressor and decompressor hooks.
    ///
    /// Outbound compression turns on only with a compressor. A decompressor
    /// alone accepts compressed input and still encodes uncompressed frames;
    /// enabling compression without a compressor would fail every encode.
    #[must_use]
    pub fn with_frame_hooks(
        mut self,
        compressor: Option<FrameCompressor>,
        decompressor: Option<FrameDecompressor>,
    ) -> Self {
        if compressor.is_some() {
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

    /// Recover the owned message codec, discarding this framing state.
    #[must_use]
    pub fn into_inner(self) -> C {
        self.inner
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

        // The limit bounds the message, not its wire form: check the
        // uncompressed bytes first so a highly compressible payload cannot
        // slip a message larger than the limit past the check
        // (br-asupersync-trmye2, `test_compression_bypass_vulnerability`).
        // The compressed length is still checked below because the framing
        // length prefix and the peer's frame limit apply to the frame.
        if data.len() > self.max_encode_message_size() {
            return Err(GrpcError::MessageTooLarge);
        }

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

    /// Decode a message with the legacy strict compression-flag policy.
    ///
    /// This compatibility entry point requires flag 0 for `identity` and flag 1
    /// for a named compression algorithm. With no header it uses the configured
    /// frame hook, including for compressed frames. These historical rules are
    /// preserved for existing callers.
    ///
    /// Native gRPC transports use [`Self::decode_message_with_negotiated_encoding`]
    /// instead: the wire protocol permits individual uncompressed messages even
    /// when a compression algorithm was negotiated for the call.
    pub fn decode_message_with_encoding(
        &mut self,
        src: &mut BytesMut,
        grpc_encoding: Option<&str>,
    ) -> Result<Option<C::Decode>, GrpcError> {
        self.decode_message_with_validation(src, grpc_encoding, EncodingValidation::Legacy)
    }

    /// Decode a message using the call's negotiated wire encoding.
    ///
    /// Flag 0 always denotes an uncompressed message, including an empty message
    /// or a message in a `gzip` call. Flag 1 requires `grpc-encoding: gzip` and a
    /// configured gzip decompressor. Missing or `identity` encoding cannot
    /// authorize compressed bytes; unsupported algorithm names are rejected.
    /// The caller must first validate that the peer selected an accepted
    /// encoding and install its matching frame hook.
    ///
    /// A framing, encoding, decompression, message, or aggregate-body-limit
    /// error poisons the codec and discards the buffered tail, just as with
    /// [`Self::decode_message_with_encoding`]. An incomplete frame remains
    /// buffered without invoking the decompressor or charging the body meter.
    pub fn decode_message_with_negotiated_encoding(
        &mut self,
        src: &mut BytesMut,
        grpc_encoding: Option<&str>,
    ) -> Result<Option<C::Decode>, GrpcError> {
        self.decode_message_with_validation(src, grpc_encoding, EncodingValidation::Negotiated)
    }

    fn decode_message_with_validation(
        &mut self,
        src: &mut BytesMut,
        grpc_encoding: Option<&str>,
        validation: EncodingValidation,
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

        // Keep the strict public entry point compatible while the native wire
        // path treats compression as a per-message decision (gRPC HTTP/2).
        if matches!(validation, EncodingValidation::Negotiated) {
            match grpc_encoding {
                Some("gzip") => {}
                None | Some("identity") if !message.compressed => {}
                None | Some("identity") => {
                    return self.poison_decode_stream(
                        src,
                        GrpcError::protocol(
                            "compressed gRPC message requires a non-identity grpc-encoding",
                        ),
                    );
                }
                Some(unknown) => {
                    return self.poison_decode_stream(
                        src,
                        GrpcError::protocol(format!(
                            "unsupported grpc-encoding: '{unknown}'. Supported: identity, gzip"
                        )),
                    );
                }
            }
        } else if let Some(encoding) = grpc_encoding {
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
        let decoded_len = data.len();
        let decoded = match self.inner.decode(&data).map_err(C::map_decode_error) {
            Ok(decoded) => decoded,
            Err(error) => return self.poison_decode_stream(src, error),
        };

        if let Err(status) = self.request_body_meter.record_message_bytes(decoded_len) {
            return self.poison_decode_stream(src, GrpcError::Status(status));
        }

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
#[path = "codec_inline_tests.rs"]
mod tests;
