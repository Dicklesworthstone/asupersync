//! gRPC message framing codec.
//!
//! Implements the gRPC message framing format:
//! - 1 byte: compressed flag (0 = uncompressed, 1 = compressed)
//! - 4 bytes: message length (big-endian)
//! - N bytes: message payload

use crate::bytes::{BufMut, Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};

use super::status::GrpcError;

/// Default maximum message size (4 MB).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

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
    /// Maximum allowed message size.
    max_message_size: usize,
}

impl GrpcCodec {
    /// Create a new codec with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        }
    }

    /// Create a new codec with a custom max message size.
    #[must_use]
    pub fn with_max_size(max_message_size: usize) -> Self {
        Self { max_message_size }
    }

    /// Get the maximum message size.
    #[must_use]
    pub fn max_message_size(&self) -> usize {
        self.max_message_size
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
        let compressed = match src[0] {
            0 => false,
            1 => true,
            flag => {
                return Err(GrpcError::protocol(format!(
                    "invalid gRPC compression flag: {flag}"
                )));
            }
        };
        let length = u32::from_be_bytes([src[1], src[2], src[3], src[4]]) as usize;

        // Validate message size
        if length > self.max_message_size {
            return Err(GrpcError::MessageTooLarge);
        }

        // Check if we have the full message
        if src.len() < MESSAGE_HEADER_SIZE + length {
            return Ok(None);
        }

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
        if item.data.len() > self.max_message_size {
            return Err(GrpcError::MessageTooLarge);
        }

        // Reserve space
        dst.reserve(MESSAGE_HEADER_SIZE + item.data.len());

        // Write compressed flag
        dst.put_u8(u8::from(item.compressed));

        // Write length (big-endian)
        dst.put_u32(item.data.len() as u32);

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
}

/// A codec that wraps another codec with gRPC framing.
#[derive(Debug)]
pub struct FramedCodec<C> {
    /// The inner codec for message serialization.
    inner: C,
    /// The gRPC framing codec.
    framing: GrpcCodec,
    /// Whether to use compression.
    use_compression: bool,
}

impl<C: Codec> FramedCodec<C> {
    /// Create a new framed codec.
    #[must_use]
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            framing: GrpcCodec::new(),
            use_compression: false,
        }
    }

    /// Create a new framed codec with custom max message size.
    #[must_use]
    pub fn with_max_size(inner: C, max_size: usize) -> Self {
        Self {
            inner,
            framing: GrpcCodec::with_max_size(max_size),
            use_compression: false,
        }
    }

    /// Enable compression.
    #[must_use]
    pub fn with_compression(mut self) -> Self {
        self.use_compression = true;
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

    /// Encode a message with framing.
    pub fn encode_message(
        &mut self,
        item: &C::Encode,
        dst: &mut BytesMut,
    ) -> Result<(), GrpcError> {
        // Serialize the message
        let data = self
            .inner
            .encode(item)
            .map_err(|e| GrpcError::invalid_message(e.to_string()))?;

        // Compression has not been implemented yet; fail explicitly instead of
        // silently emitting uncompressed frames when compression was requested.
        if self.use_compression {
            return Err(GrpcError::compression("compression not supported"));
        }

        // Create framed message.
        let message = GrpcMessage::new(data);

        // Encode with framing
        self.framing.encode(message, dst)
    }

    /// Decode a message with framing.
    pub fn decode_message(&mut self, src: &mut BytesMut) -> Result<Option<C::Decode>, GrpcError> {
        // Decode framing
        let Some(message) = self.framing.decode(src)? else {
            return Ok(None);
        };

        // Handle compression
        let data = if message.compressed {
            // TODO: Implement decompression
            return Err(GrpcError::compression("compression not supported"));
        } else {
            message.data
        };

        // Deserialize the message
        let decoded = self
            .inner
            .decode(&data)
            .map_err(|e| GrpcError::invalid_message(e.to_string()))?;

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
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
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
}
