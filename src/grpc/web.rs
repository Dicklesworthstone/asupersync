//! gRPC-Web protocol support.
//!
//! Implements the [gRPC-Web protocol](https://github.com/grpc/grpc/blob/main/doc/PROTOCOL-WEB.md)
//! which enables gRPC services to be consumed from browser clients via HTTP/1.1.
//!
//! # Protocol Differences from Standard gRPC
//!
//! - Works over HTTP/1.1 (no HTTP/2 requirement)
//! - Trailers are encoded as a final frame in the response body (flag `0x80`)
//! - Supports two content types:
//!   - `application/grpc-web` (binary, same framing as standard gRPC)
//!   - `application/grpc-web-text` (base64-encoded binary stream)
//!
//! # Trailer Frame Format
//!
//! The trailer frame uses the gRPC framing header with bit 7 set:
//! - Flag byte `0x80` (uncompressed trailers) or `0x81` (compressed trailers)
//! - 4-byte big-endian length
//! - HTTP/1.1 header block (`key: value\r\n` pairs)

use crate::bytes::{BufMut, Bytes, BytesMut};

use super::status::{Code, GrpcError, Status};
use super::streaming::{Metadata, MetadataValue};

/// Trailer frame flag — bit 7 set indicates trailers, not data.
const TRAILER_FLAG: u8 = 0x80;

/// gRPC-Web content type variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// Binary gRPC-Web (`application/grpc-web`).
    GrpcWeb,
    /// Base64-encoded gRPC-Web (`application/grpc-web-text`).
    GrpcWebText,
}

impl ContentType {
    fn matches_media_type(value: &str, prefix: &str) -> bool {
        value.starts_with(prefix)
            && matches!(value.as_bytes().get(prefix.len()), None | Some(b'+' | b';'))
    }

    /// Parse a content type from a header value.
    ///
    /// Matches the media type prefix, ignoring subtype suffixes like `+proto`.
    #[must_use]
    pub fn from_header_value(value: &str) -> Option<Self> {
        let lower = value.trim().to_ascii_lowercase();
        if Self::matches_media_type(&lower, "application/grpc-web-text") {
            Some(Self::GrpcWebText)
        } else if Self::matches_media_type(&lower, "application/grpc-web") {
            Some(Self::GrpcWeb)
        } else {
            None
        }
    }

    /// Return the canonical content-type header value.
    #[must_use]
    pub const fn as_header_value(self) -> &'static str {
        match self {
            Self::GrpcWeb => "application/grpc-web+proto",
            Self::GrpcWebText => "application/grpc-web-text+proto",
        }
    }

    /// Whether this content type uses base64 encoding.
    #[must_use]
    pub const fn is_text_mode(self) -> bool {
        matches!(self, Self::GrpcWebText)
    }
}

/// A parsed gRPC-Web frame which is either a data message or trailers.
#[derive(Debug, Clone)]
pub enum WebFrame {
    /// Data frame (flag bit 7 = 0).
    Data {
        /// Whether message-level compression was applied (flag bit 0).
        compressed: bool,
        /// The message payload.
        data: Bytes,
    },
    /// Trailer frame (flag bit 7 = 1).
    Trailers(TrailerFrame),
}

/// Decoded trailer frame containing status and metadata.
#[derive(Debug, Clone)]
pub struct TrailerFrame {
    /// gRPC status parsed from `grpc-status` header.
    pub status: Status,
    /// Additional trailer metadata beyond grpc-status/grpc-message.
    pub metadata: Metadata,
}

// ── Trailer Encoding ─────────────────────────────────────────────────

/// Encode a [`Status`] and optional trailer metadata into a gRPC-Web
/// trailer frame (flag `0x80` + length-prefixed HTTP/1.1 header block).
pub fn encode_trailers(status: &Status, metadata: &Metadata, dst: &mut BytesMut) {
    // Build the HTTP/1.1 header block.
    let mut block = String::new();
    block.push_str("grpc-status: ");
    block.push_str(&status.code().as_i32().to_string());
    block.push_str("\r\n");

    if !status.message().is_empty() {
        block.push_str("grpc-message: ");
        // Percent-encode CR/LF per gRPC spec to prevent trailer injection.
        let sanitized_msg = status
            .message()
            .replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A");
        block.push_str(&sanitized_msg);
        block.push_str("\r\n");
    }

    for (key, value) in metadata.iter() {
        let key_lower = key.to_ascii_lowercase();
        // Skip status/message — already encoded above.
        if key_lower == "grpc-status" || key_lower == "grpc-message" {
            continue;
        }
        block.push_str(&key_lower);
        block.push_str(": ");
        match value {
            // Sanitize CR/LF in ASCII values to prevent trailer injection.
            MetadataValue::Ascii(s) => {
                let sanitized = s.replace(['\r', '\n'], "");
                block.push_str(&sanitized);
            }
            MetadataValue::Binary(b) => {
                use base64::Engine;
                block.push_str(&base64::engine::general_purpose::STANDARD.encode(b.as_ref()));
            }
        }
        block.push_str("\r\n");
    }

    let block_bytes = block.as_bytes();
    dst.reserve(5 + block_bytes.len());
    dst.put_u8(TRAILER_FLAG);
    dst.put_u32(u32::try_from(block_bytes.len()).unwrap_or(u32::MAX));
    dst.extend_from_slice(block_bytes);
}

/// Decode a trailer frame body (the payload after the 5-byte header) into
/// a [`TrailerFrame`].
pub fn decode_trailers(body: &[u8]) -> Result<TrailerFrame, GrpcError> {
    let text = std::str::from_utf8(body)
        .map_err(|e| GrpcError::protocol(format!("invalid UTF-8 in trailer block: {e}")))?;

    let mut status_code: Option<i32> = None;
    let mut status_message = String::new();
    let mut metadata = Metadata::new();

    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();

        match key.as_str() {
            "grpc-status" => {
                status_code = value.parse::<i32>().ok();
            }
            "grpc-message" => {
                // Reverse the percent-encoding applied by encode_trailers
                // (grpc-message uses percent-encoded ASCII per gRPC spec).
                status_message = value
                    .replace("%0D", "\r")
                    .replace("%0d", "\r")
                    .replace("%0A", "\n")
                    .replace("%0a", "\n")
                    .replace("%25", "%");
            }
            _ => {
                if key.ends_with("-bin") {
                    use base64::Engine;
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) {
                        metadata.insert_bin(&key, Bytes::from(decoded));
                    }
                } else {
                    metadata.insert(&key, value);
                }
            }
        }
    }

    let code = Code::from_i32(status_code.unwrap_or(0));
    let status = if status_message.is_empty() {
        Status::new(code, code.as_str())
    } else {
        Status::new(code, status_message)
    };

    Ok(TrailerFrame { status, metadata })
}

// ── Web Frame Codec ──────────────────────────────────────────────────

/// Maximum gRPC-Web frame size (same as default gRPC max message size).
const DEFAULT_MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Codec for reading/writing gRPC-Web frames (data + trailer).
///
/// Handles the 5-byte framing header and distinguishes data frames from
/// trailer frames via the MSB of the flag byte.
#[derive(Debug)]
pub struct WebFrameCodec {
    max_frame_size: usize,
}

impl WebFrameCodec {
    /// Create a new codec with default max frame size.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }

    /// Create a codec with a custom max frame size.
    #[must_use]
    pub fn with_max_size(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }

    /// Decode the next frame from the buffer, returning `None` if
    /// insufficient data is available.
    pub fn decode(&self, src: &mut BytesMut) -> Result<Option<WebFrame>, GrpcError> {
        if src.len() < 5 {
            return Ok(None);
        }

        let flag = src[0];
        let length = u32::from_be_bytes([src[1], src[2], src[3], src[4]]) as usize;

        if length > self.max_frame_size {
            return Err(GrpcError::MessageTooLarge);
        }

        if src.len() < 5 + length {
            return Ok(None);
        }

        // Consume the header.
        let _ = src.split_to(5);
        let payload = src.split_to(length).freeze();

        let is_trailer = flag & TRAILER_FLAG != 0;
        if is_trailer {
            let trailer = decode_trailers(&payload)?;
            Ok(Some(WebFrame::Trailers(trailer)))
        } else {
            let compressed = flag & 0x01 != 0;
            Ok(Some(WebFrame::Data {
                compressed,
                data: payload,
            }))
        }
    }

    /// Encode a data frame into the buffer.
    pub fn encode_data(
        &self,
        data: &[u8],
        compressed: bool,
        dst: &mut BytesMut,
    ) -> Result<(), GrpcError> {
        if data.len() > self.max_frame_size {
            return Err(GrpcError::MessageTooLarge);
        }
        let len = u32::try_from(data.len()).map_err(|_| GrpcError::MessageTooLarge)?;
        dst.reserve(5 + data.len());
        dst.put_u8(u8::from(compressed));
        dst.put_u32(len);
        dst.extend_from_slice(data);
        Ok(())
    }

    /// Encode trailers into the buffer.
    pub fn encode_trailers(
        &self,
        status: &Status,
        metadata: &Metadata,
        dst: &mut BytesMut,
    ) -> Result<(), GrpcError> {
        encode_trailers(status, metadata, dst);
        Ok(())
    }
}

impl Default for WebFrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

// ── Base64 Text Mode ─────────────────────────────────────────────────

/// Encode raw gRPC-Web binary frames to base64 for text mode.
///
/// This wraps the entire binary stream, not individual frames.
#[must_use]
pub fn base64_encode(binary: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(binary)
}

/// Decode base64 text mode data back to binary frames.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, GrpcError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|e| GrpcError::protocol(format!("invalid base64 in grpc-web-text: {e}")))
}

// ── Request/Response Detection ───────────────────────────────────────

/// Check if an HTTP request is a gRPC-Web request based on the content-type
/// header value.
#[must_use]
pub fn is_grpc_web_request(content_type: &str) -> bool {
    ContentType::from_header_value(content_type).is_some()
}

/// Determine if a gRPC-Web request uses text (base64) mode.
#[must_use]
pub fn is_text_mode(content_type: &str) -> bool {
    ContentType::from_header_value(content_type).is_some_and(ContentType::is_text_mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // ── ContentType Tests ────────────────────────────────────────────

    #[test]
    fn test_content_type_parse_binary() {
        init_test("test_content_type_parse_binary");
        let ct = ContentType::from_header_value("application/grpc-web+proto");
        crate::assert_with_log!(
            ct == Some(ContentType::GrpcWeb),
            "binary content type",
            Some(ContentType::GrpcWeb),
            ct
        );
        crate::test_complete!("test_content_type_parse_binary");
    }

    #[test]
    fn test_content_type_parse_text() {
        init_test("test_content_type_parse_text");
        let ct = ContentType::from_header_value("application/grpc-web-text+proto");
        crate::assert_with_log!(
            ct == Some(ContentType::GrpcWebText),
            "text content type",
            Some(ContentType::GrpcWebText),
            ct
        );
        crate::test_complete!("test_content_type_parse_text");
    }

    #[test]
    fn test_content_type_parse_plain() {
        init_test("test_content_type_parse_plain");
        let ct = ContentType::from_header_value("application/grpc-web");
        crate::assert_with_log!(
            ct == Some(ContentType::GrpcWeb),
            "plain grpc-web",
            Some(ContentType::GrpcWeb),
            ct
        );
        crate::test_complete!("test_content_type_parse_plain");
    }

    #[test]
    fn test_content_type_parse_invalid() {
        init_test("test_content_type_parse_invalid");
        let ct = ContentType::from_header_value("application/json");
        crate::assert_with_log!(ct.is_none(), "invalid content type", true, ct.is_none());
        crate::test_complete!("test_content_type_parse_invalid");
    }

    #[test]
    fn test_content_type_parse_standard_grpc() {
        init_test("test_content_type_parse_standard_grpc");
        // Standard gRPC is NOT grpc-web.
        let ct = ContentType::from_header_value("application/grpc");
        crate::assert_with_log!(
            ct.is_none(),
            "standard grpc is not grpc-web",
            true,
            ct.is_none()
        );
        crate::test_complete!("test_content_type_parse_standard_grpc");
    }

    #[test]
    fn test_content_type_case_insensitive() {
        init_test("test_content_type_case_insensitive");
        let ct = ContentType::from_header_value("Application/gRPC-Web-Text+proto");
        crate::assert_with_log!(
            ct == Some(ContentType::GrpcWebText),
            "case insensitive parse",
            Some(ContentType::GrpcWebText),
            ct
        );
        crate::test_complete!("test_content_type_case_insensitive");
    }

    #[test]
    fn test_content_type_parse_with_parameters() {
        init_test("test_content_type_parse_with_parameters");
        let ct = ContentType::from_header_value("application/grpc-web; charset=utf-8");
        crate::assert_with_log!(
            ct == Some(ContentType::GrpcWeb),
            "parameterized grpc-web content type",
            Some(ContentType::GrpcWeb),
            ct
        );
        crate::test_complete!("test_content_type_parse_with_parameters");
    }

    #[test]
    fn test_content_type_rejects_similar_prefixes() {
        init_test("test_content_type_rejects_similar_prefixes");
        let bogus_binary = ContentType::from_header_value("application/grpc-websocket");
        crate::assert_with_log!(
            bogus_binary.is_none(),
            "grpc-websocket is not grpc-web",
            true,
            bogus_binary.is_none()
        );
        let bogus_text = ContentType::from_header_value("application/grpc-web-textplain");
        crate::assert_with_log!(
            bogus_text.is_none(),
            "grpc-web-textplain is not grpc-web-text",
            true,
            bogus_text.is_none()
        );
        crate::test_complete!("test_content_type_rejects_similar_prefixes");
    }

    // ── Trailer Encoding/Decoding Tests ──────────────────────────────

    #[test]
    fn test_trailer_encode_decode_roundtrip() {
        init_test("test_trailer_encode_decode_roundtrip");
        let status = Status::ok();
        let metadata = Metadata::new();
        let mut buf = BytesMut::new();

        encode_trailers(&status, &metadata, &mut buf);

        // Check trailer flag.
        crate::assert_with_log!(
            buf[0] == TRAILER_FLAG,
            "trailer flag set",
            TRAILER_FLAG,
            buf[0]
        );

        // Decode.
        let frame_codec = WebFrameCodec::new();
        let frame = frame_codec.decode(&mut buf).unwrap().unwrap();
        let WebFrame::Trailers(trailers) = frame else {
            panic!("expected trailer frame")
        };
        crate::assert_with_log!(
            trailers.status.code() == Code::Ok,
            "status code OK",
            Code::Ok,
            trailers.status.code()
        );
        crate::test_complete!("test_trailer_encode_decode_roundtrip");
    }

    #[test]
    fn test_trailer_with_message() {
        init_test("test_trailer_with_message");
        let status = Status::not_found("entity missing");
        let metadata = Metadata::new();
        let mut buf = BytesMut::new();

        encode_trailers(&status, &metadata, &mut buf);

        let frame_codec = WebFrameCodec::new();
        let frame = frame_codec.decode(&mut buf).unwrap().unwrap();
        let WebFrame::Trailers(trailers) = frame else {
            panic!("expected trailer frame")
        };
        crate::assert_with_log!(
            trailers.status.code() == Code::NotFound,
            "status code NotFound",
            Code::NotFound,
            trailers.status.code()
        );
        let msg = trailers.status.message();
        crate::assert_with_log!(
            msg == "entity missing",
            "status message",
            "entity missing",
            msg
        );
        crate::test_complete!("test_trailer_with_message");
    }

    #[test]
    fn test_trailer_message_percent_encoding_roundtrip() {
        init_test("test_trailer_message_percent_encoding_roundtrip");
        let original_msg = "error on line\r\n42: 100% failure";
        let status = Status::new(Code::Internal, original_msg);
        let metadata = Metadata::new();
        let mut buf = BytesMut::new();

        encode_trailers(&status, &metadata, &mut buf);

        let frame_codec = WebFrameCodec::new();
        let frame = frame_codec.decode(&mut buf).unwrap().unwrap();
        let WebFrame::Trailers(trailers) = frame else {
            panic!("expected trailer frame")
        };
        let decoded_msg = trailers.status.message();
        crate::assert_with_log!(
            decoded_msg == original_msg,
            "percent-encoded grpc-message must round-trip",
            original_msg,
            decoded_msg
        );
        crate::test_complete!("test_trailer_message_percent_encoding_roundtrip");
    }

    #[test]
    fn test_trailer_with_custom_metadata() {
        init_test("test_trailer_with_custom_metadata");
        let status = Status::ok();
        let mut metadata = Metadata::new();
        metadata.insert("x-request-id", "abc-123");

        let mut buf = BytesMut::new();
        encode_trailers(&status, &metadata, &mut buf);

        let frame_codec = WebFrameCodec::new();
        let frame = frame_codec.decode(&mut buf).unwrap().unwrap();
        let WebFrame::Trailers(trailers) = frame else {
            panic!("expected trailer frame")
        };

        let request_id = trailers.metadata.get("x-request-id");
        let has_id = request_id.is_some();
        crate::assert_with_log!(has_id, "custom metadata present", true, has_id);
        crate::test_complete!("test_trailer_with_custom_metadata");
    }

    // ── WebFrameCodec Tests ──────────────────────────────────────────

    #[test]
    fn test_data_frame_roundtrip() {
        init_test("test_data_frame_roundtrip");
        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::new();

        codec
            .encode_data(b"hello grpc-web", false, &mut buf)
            .unwrap();

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        let WebFrame::Data { compressed, data } = frame else {
            panic!("expected data frame")
        };
        crate::assert_with_log!(!compressed, "not compressed", false, compressed);
        crate::assert_with_log!(
            data.as_ref() == b"hello grpc-web",
            "data matches",
            "hello grpc-web",
            std::str::from_utf8(data.as_ref()).unwrap_or("<binary>")
        );
        crate::test_complete!("test_data_frame_roundtrip");
    }

    #[test]
    fn test_data_frame_compressed_flag() {
        init_test("test_data_frame_compressed_flag");
        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::new();

        codec.encode_data(b"compressed", true, &mut buf).unwrap();
        crate::assert_with_log!(buf[0] == 1, "compressed flag byte", 1u8, buf[0]);

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        let WebFrame::Data { compressed, .. } = frame else {
            panic!("expected data frame")
        };
        crate::assert_with_log!(compressed, "compressed set", true, compressed);
        crate::test_complete!("test_data_frame_compressed_flag");
    }

    #[test]
    fn test_frame_too_large() {
        init_test("test_frame_too_large");
        let codec = WebFrameCodec::with_max_size(10);
        let mut buf = BytesMut::new();

        let result = codec.encode_data(&[0u8; 100], false, &mut buf);
        let ok = matches!(result, Err(GrpcError::MessageTooLarge));
        crate::assert_with_log!(ok, "encode rejects oversized frame", true, ok);
        crate::test_complete!("test_frame_too_large");
    }

    #[test]
    fn test_decode_partial_header() {
        init_test("test_decode_partial_header");
        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::from(&[0u8, 0, 0][..]);

        let result = codec.decode(&mut buf).unwrap();
        crate::assert_with_log!(
            result.is_none(),
            "partial header returns None",
            true,
            result.is_none()
        );
        crate::test_complete!("test_decode_partial_header");
    }

    #[test]
    fn test_decode_partial_body() {
        init_test("test_decode_partial_body");
        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u32(10);
        buf.extend_from_slice(&[1, 2, 3]); // only 3 of 10 bytes

        let result = codec.decode(&mut buf).unwrap();
        crate::assert_with_log!(
            result.is_none(),
            "partial body returns None",
            true,
            result.is_none()
        );
        crate::test_complete!("test_decode_partial_body");
    }

    #[test]
    fn test_mixed_data_and_trailers() {
        init_test("test_mixed_data_and_trailers");
        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::new();

        // Encode two data frames + trailer.
        codec.encode_data(b"msg1", false, &mut buf).unwrap();
        codec.encode_data(b"msg2", false, &mut buf).unwrap();
        codec
            .encode_trailers(&Status::ok(), &Metadata::new(), &mut buf)
            .unwrap();

        // Decode frame 1.
        let f1 = codec.decode(&mut buf).unwrap().unwrap();
        let is_data1 = matches!(&f1, WebFrame::Data { data, .. } if data.as_ref() == b"msg1");
        crate::assert_with_log!(is_data1, "first data frame", true, is_data1);

        // Decode frame 2.
        let f2 = codec.decode(&mut buf).unwrap().unwrap();
        let is_data2 = matches!(&f2, WebFrame::Data { data, .. } if data.as_ref() == b"msg2");
        crate::assert_with_log!(is_data2, "second data frame", true, is_data2);

        // Decode trailer.
        let f3 = codec.decode(&mut buf).unwrap().unwrap();
        let is_trailer = matches!(f3, WebFrame::Trailers(_));
        crate::assert_with_log!(is_trailer, "trailer frame", true, is_trailer);

        // Buffer should be empty.
        let empty = buf.is_empty();
        crate::assert_with_log!(empty, "buffer consumed", true, empty);
        crate::test_complete!("test_mixed_data_and_trailers");
    }

    // ── Base64 Text Mode Tests ───────────────────────────────────────

    #[test]
    fn test_base64_roundtrip() {
        init_test("test_base64_roundtrip");
        let original = b"hello gRPC-web text mode";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        crate::assert_with_log!(
            decoded == original,
            "base64 roundtrip",
            original.as_slice(),
            decoded.as_slice()
        );
        crate::test_complete!("test_base64_roundtrip");
    }

    #[test]
    fn test_base64_invalid_input() {
        init_test("test_base64_invalid_input");
        let result = base64_decode("not valid base64!!!");
        let ok = matches!(result, Err(GrpcError::Protocol(_)));
        crate::assert_with_log!(ok, "invalid base64 rejected", true, ok);
        crate::test_complete!("test_base64_invalid_input");
    }

    #[test]
    fn test_text_mode_full_stream() {
        init_test("test_text_mode_full_stream");
        let codec = WebFrameCodec::new();
        let mut binary_buf = BytesMut::new();

        // Build a binary stream: data + trailers.
        codec
            .encode_data(b"message-payload", false, &mut binary_buf)
            .unwrap();
        codec
            .encode_trailers(&Status::ok(), &Metadata::new(), &mut binary_buf)
            .unwrap();

        // Base64 encode the whole stream.
        let text = base64_encode(&binary_buf);

        // Decode back to binary.
        let binary = base64_decode(&text).unwrap();
        let mut decode_buf = BytesMut::from(binary.as_slice());

        // Parse frames.
        let f1 = codec.decode(&mut decode_buf).unwrap().unwrap();
        let is_data =
            matches!(&f1, WebFrame::Data { data, .. } if data.as_ref() == b"message-payload");
        crate::assert_with_log!(is_data, "data frame decoded from text mode", true, is_data);

        let f2 = codec.decode(&mut decode_buf).unwrap().unwrap();
        let is_trailer = matches!(f2, WebFrame::Trailers(_));
        crate::assert_with_log!(
            is_trailer,
            "trailer frame decoded from text mode",
            true,
            is_trailer
        );
        crate::test_complete!("test_text_mode_full_stream");
    }

    // ── Detection Helper Tests ───────────────────────────────────────

    #[test]
    fn test_is_grpc_web_request() {
        init_test("test_is_grpc_web_request");
        crate::assert_with_log!(
            is_grpc_web_request("application/grpc-web"),
            "binary",
            true,
            true
        );
        crate::assert_with_log!(
            is_grpc_web_request("application/grpc-web-text+proto"),
            "text",
            true,
            true
        );
        crate::assert_with_log!(
            !is_grpc_web_request("application/grpc"),
            "not grpc-web",
            true,
            true
        );
        crate::test_complete!("test_is_grpc_web_request");
    }

    #[test]
    fn test_is_text_mode() {
        init_test("test_is_text_mode");
        crate::assert_with_log!(
            is_text_mode("application/grpc-web-text"),
            "text mode",
            true,
            true
        );
        crate::assert_with_log!(
            !is_text_mode("application/grpc-web"),
            "binary mode",
            true,
            true
        );
        crate::test_complete!("test_is_text_mode");
    }

    #[test]
    fn test_decode_oversized_trailer_rejected() {
        init_test("test_decode_oversized_trailer_rejected");
        let codec = WebFrameCodec::with_max_size(10);
        let mut buf = BytesMut::new();

        // Fabricate a trailer frame header claiming 100 bytes.
        buf.put_u8(TRAILER_FLAG);
        buf.put_u32(100);
        buf.extend_from_slice(&[b'x'; 100]);

        let result = codec.decode(&mut buf);
        let ok = matches!(result, Err(GrpcError::MessageTooLarge));
        crate::assert_with_log!(ok, "oversized trailer rejected", true, ok);
        crate::test_complete!("test_decode_oversized_trailer_rejected");
    }
}
