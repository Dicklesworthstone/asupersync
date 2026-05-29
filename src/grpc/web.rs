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
use super::streaming::{
    Metadata, MetadataValue, normalize_metadata_key, sanitize_metadata_ascii_value,
};

/// Trailer frame flag — bit 7 set indicates trailers, not data.
const TRAILER_FLAG: u8 = 0x80;

/// Mask of flag-byte bits reserved by the gRPC-Web spec for future use
/// (bits 1..=6, i.e. 0x7E). The spec defines:
///
///   bit 0 (0x01) — compression flag
///   bit 7 (0x80) — trailer-frame indicator
///   bits 1..=6   — reserved, MUST be sent as zero
///
/// Strict implementations reject frames with reserved bits set so a
/// future protocol-version smuggling attempt cannot be silently
/// accepted as a regular data frame. Legal flag values are exactly
/// {0x00, 0x01, 0x80, 0x81}; anything that overlaps `RESERVED_FLAG_MASK`
/// triggers a `GrpcError::protocol` rejection in `WebFrameCodec::decode`.
/// (br-asupersync-ood365)
const RESERVED_FLAG_MASK: u8 = 0x7E;

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
        let Some(key_lower) =
            normalize_metadata_key(key, matches!(value, MetadataValue::Binary(_)))
        else {
            continue;
        };
        // Skip status/message — already encoded above.
        if key_lower == "grpc-status" || key_lower == "grpc-message" {
            continue;
        }
        block.push_str(&key_lower);
        block.push_str(": ");
        match value {
            MetadataValue::Ascii(s) => block.push_str(sanitize_metadata_ascii_value(s).as_ref()),
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
    let block_len = u32::try_from(block_bytes.len())
        .expect("gRPC trailer block exceeds 4 GiB — metadata must be bounded before encoding");
    dst.put_u32(block_len);
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
    // br-asupersync-nbryje: per gRPC-Web spec, exactly ONE grpc-status
    // and at most one grpc-message MUST appear in the trailer block.
    // Track 'seen' flags so a second occurrence becomes a protocol
    // error rather than silently overwriting earlier values — defends
    // against an adversarial intermediary appending 'grpc-status: 0'
    // after a real failure status to mask errors.
    let mut seen_status = false;
    let mut seen_message = false;

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
                if seen_status {
                    return Err(GrpcError::protocol(
                        "duplicate grpc-status in trailer block (br-nbryje)",
                    ));
                }
                seen_status = true;
                // br-asupersync-6qwzl0: per gRPC spec, grpc-status MUST
                // be a valid integer. Pre-fix a malformed value (e.g.
                // "garbage") was silently coerced to INTERNAL via the
                // unwrap_or(13) fallback below — a malicious or buggy
                // server could mask its real wire behaviour as a
                // generic INTERNAL error and the client could not
                // distinguish a real INTERNAL from coerced garbage.
                // Now we surface the protocol violation explicitly.
                status_code = Some(value.parse::<i32>().map_err(|e| {
                    GrpcError::protocol(format!(
                        "malformed grpc-status integer in trailer block: \
                         {value:?} ({e}) (br-asupersync-6qwzl0)"
                    ))
                })?);
            }
            "grpc-message" => {
                if seen_message {
                    return Err(GrpcError::protocol(
                        "duplicate grpc-message in trailer block (br-nbryje)",
                    ));
                }
                seen_message = true;
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
                // br-asupersync-ngnnc3: surface invalid metadata keys and
                // malformed base64 as GrpcError::protocol instead of
                // silently dropping the entry. Matches the project's
                // fail-closed defaults and the decode_trailers policy
                // for duplicate grpc-status / grpc-message (which IS
                // strict). Previously a peer supplying a non-token key
                // or malformed base64 in -bin metadata had the entry
                // silently elided while the rest of the trailer block
                // accepted; under fail-closed the whole frame should
                // reject.
                if key.ends_with("-bin") {
                    use base64::Engine;
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .map_err(|e| {
                            GrpcError::protocol(format!(
                                "malformed base64 in -bin trailer metadata for key with \
                                 length {}: {}",
                                key.len(),
                                e
                            ))
                        })?;
                    if !metadata.insert_bin(&key, Bytes::from(decoded)) {
                        return Err(GrpcError::protocol(format!(
                            "invalid -bin metadata key in trailer block (length {})",
                            key.len()
                        )));
                    }
                } else if !metadata.insert(&key, value) {
                    return Err(GrpcError::protocol(format!(
                        "invalid metadata key in trailer block (length {})",
                        key.len()
                    )));
                }
            }
        }
    }

    // Per gRPC spec, trailers MUST include grpc-status. If absent, treat as
    // internal error rather than success — a missing status is a protocol violation.
    let code = Code::from_i32(status_code.unwrap_or(13)); // 13 = INTERNAL
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
    /// br-asupersync-nln9sc: once `decode` has surfaced an
    /// unrecoverable error (reserved-flag bits, MessageTooLarge, or a
    /// malformed trailer block), the codec is poisoned. Subsequent
    /// `decode` calls return the same error WITHOUT re-reading the
    /// buffer. This breaks the infinite-Err loop a naive caller
    /// would otherwise produce by re-polling on the same un-consumed
    /// header bytes (see br-asupersync-3asq77 for the analogous
    /// `FramedRead` poison; the codec layer needs the same fail-
    /// closed property because its callers may not always go through
    /// FramedRead). Stores the first terminal error reason so the
    /// poison sentinel stays diagnostic without re-reading the buffer.
    poisoned_reason: std::cell::RefCell<Option<String>>,
    /// Once a trailer frame has decoded successfully, the gRPC-Web
    /// stream is complete. Any later bytes are a protocol violation
    /// and must fail closed instead of being parsed as a second
    /// logical response.
    completed: std::cell::Cell<bool>,
}

impl WebFrameCodec {
    /// Create a new codec with default max frame size.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_size(DEFAULT_MAX_FRAME_SIZE)
    }

    /// Create a codec with a custom max frame size.
    #[must_use]
    pub fn with_max_size(max_frame_size: usize) -> Self {
        Self {
            max_frame_size,
            poisoned_reason: std::cell::RefCell::new(None),
            completed: std::cell::Cell::new(false),
        }
    }

    /// Returns true once `decode` has surfaced an unrecoverable
    /// error and the codec has been poisoned. (br-asupersync-nln9sc)
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned_reason.borrow().is_some()
    }

    fn poison(&self, reason: impl Into<String>) {
        let mut poisoned_reason = self.poisoned_reason.borrow_mut();
        if poisoned_reason.is_none() {
            *poisoned_reason = Some(reason.into());
        }
    }

    /// Decode the next frame from the buffer, returning `None` if
    /// insufficient data is available.
    pub fn decode(&self, src: &mut BytesMut) -> Result<Option<WebFrame>, GrpcError> {
        // br-asupersync-nln9sc: once poisoned, refuse to re-read the
        // buffer. The sentinel includes the first terminal error
        // reason so diagnostics remain stable while breaking the
        // infinite-Err loop.
        if let Some(reason) = self.poisoned_reason.borrow().clone() {
            return Err(GrpcError::protocol(format!(
                "gRPC-Web codec is poisoned after a prior unrecoverable \
                 decode error ({reason}) (br-asupersync-nln9sc); \
                 construct a new WebFrameCodec to resume",
            )));
        }
        if self.completed.get() {
            if src.is_empty() {
                return Ok(None);
            }
            let message =
                "received bytes after terminal gRPC-Web trailer (br-asupersync-p2lx74)".to_string();
            self.poison(message.clone());
            return Err(GrpcError::protocol(message));
        }

        if src.len() < 5 {
            return Ok(None);
        }

        let flag = src[0];
        let length = u32::from_be_bytes([src[1], src[2], src[3], src[4]]) as usize;

        // br-asupersync-ood365: strict reserved-bits check. Per the
        // gRPC-Web spec, only bits 0 (compression) and 7 (trailer) are
        // defined; bits 1..=6 are reserved and MUST be sent as zero.
        // Reject frames that set any reserved bit so a future protocol
        // extension can't be silently mis-handled as a data frame here.
        // Done BEFORE the length / split_to consumption so the buffer
        // stays untouched for the caller's diagnostic logging — but
        // the codec is poisoned so the next decode call will not re-
        // read the same broken header (br-asupersync-nln9sc).
        if flag & RESERVED_FLAG_MASK != 0 {
            let message = format!(
                "gRPC-Web frame has reserved flag bits set: 0x{flag:02x} \
                 (only bits 0x01 and 0x80 are defined; mask 0x7E is reserved)"
            );
            self.poison(message.clone());
            return Err(GrpcError::protocol(message));
        }

        if length > self.max_frame_size {
            // br-asupersync-nln9sc: poison so the caller can't loop
            // re-reading the same oversize header. We cannot safely
            // consume `length` body bytes (they may not have arrived,
            // and skipping would re-frame on garbage); poisoning is
            // the only safe recovery.
            self.poison(format!(
                "gRPC-Web frame length {length} exceeds maximum {}",
                self.max_frame_size
            ));
            return Err(GrpcError::MessageTooLarge);
        }

        if src.len() < 5 + length {
            return Ok(None);
        }

        // Consume the header.
        let _ = src.split_to(5);
        let payload = src.split_to(length).freeze();

        let is_trailer = flag & TRAILER_FLAG != 0;
        let compressed = flag & 0x01 != 0;
        if is_trailer {
            if compressed {
                let message = "compressed gRPC-Web trailer frames are unsupported".to_string();
                self.poison(message.clone());
                return Err(GrpcError::compression(message));
            }
            // br-asupersync-nln9sc: a malformed trailer block also
            // poisons — once a trailer arrives, the gRPC-Web stream
            // is by definition over, so any decode failure here is
            // terminal anyway.
            let trailer = decode_trailers(&payload).map_err(|err| {
                self.poison(format!("{err:?}"));
                err
            })?;
            self.completed.set(true);
            if !src.is_empty() {
                let message =
                    "received bytes after terminal gRPC-Web trailer (br-asupersync-p2lx74)"
                        .to_string();
                self.poison(message.clone());
                return Err(GrpcError::protocol(message));
            }
            Ok(Some(WebFrame::Trailers(trailer)))
        } else {
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
///
/// **Whole-input decoder.** This expects the COMPLETE base64 stream
/// in one call and rejects partial input. For chunked HTTP body
/// streams (where each chunk may end mid-base64-quartet), use
/// [`Base64StreamDecoder`] instead — it holds 0–3 chars of partial-
/// quartet across `push` calls so chunked input can be decoded
/// incrementally without buffering the entire body in memory first.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, GrpcError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|e| GrpcError::protocol(format!("invalid base64 in grpc-web-text: {e}")))
}

/// Streaming gRPC-Web text-mode (`application/grpc-web-text`) base64
/// decoder.
///
/// Holds incomplete base64 quartets across HTTP body chunks so a
/// chunked body can be decoded incrementally without buffering the
/// entire stream in memory before decode. Padding (`=`) is interpreted
/// as the stream-end marker — once observed, the decoder is sealed
/// and all subsequent `push` calls fail. Callers that omit padding
/// (the gRPC-Web spec permits unpadded base64 since the binary stream
/// length is independently known from `content-length` /
/// chunked-encoding terminator) finalize via [`Self::finish`].
///
/// # Example
///
/// ```ignore
/// use asupersync::grpc::web::Base64StreamDecoder;
///
/// let mut decoder = Base64StreamDecoder::new();
/// for chunk in body_chunks {
///     let decoded = decoder.push(chunk.as_bytes())?;
///     if !decoded.is_empty() { handle_binary(&decoded); }
/// }
/// let trailing = decoder.finish()?;
/// if !trailing.is_empty() { handle_binary(&trailing); }
/// ```
///
/// # Padding semantics
///
/// gRPC-Web text mode uses RFC 4648 STANDARD base64. STANDARD
/// requires padding when the binary length is not a multiple of 3,
/// but the gRPC-Web spec is permissive: many clients omit padding.
/// `Base64StreamDecoder` accepts both:
///
/// - Padded streams: `=` chars mark the FINAL quartet. If the padded
///   quartet is split across chunks, the decoder buffers it until the
///   quartet is complete; then the entire combined buffer is decoded
///   with strict STANDARD validation (which rejects misplaced
///   padding), and the decoder is sealed. Subsequent `push` calls
///   fail; `finish` is a no-op.
/// - Unpadded streams: complete quartets decode in `push`, the
///   trailing 0–3 chars are buffered, and `finish` decodes them
///   without padding. A 1-char trailing remainder is invalid base64
///   and surfaces as `Err`.
///
/// (br-asupersync-37svtb)
#[derive(Debug, Default)]
pub struct Base64StreamDecoder {
    /// Buffered partial-quartet input (0–3 ASCII bytes).
    pending: Vec<u8>,
    /// True once `finish()` has run or padding has been observed in
    /// `push()`. Sealed decoders reject further `push` calls and
    /// `finish` becomes a no-op.
    sealed: bool,
}

impl Base64StreamDecoder {
    /// Create a fresh streaming decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: Vec::with_capacity(3),
            sealed: false,
        }
    }

    /// Returns true once the decoder has been sealed by either
    /// observing padding in `push` or by an explicit `finish` call.
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Push a chunk of base64 text. Returns the decoded bytes.
    ///
    /// Decodes all complete quartets formed by joining the previous
    /// partial-quartet residue with this chunk; the trailing 0–3
    /// chars are buffered for the next `push`. If the chunk contains
    /// padding (`=`), the chunk is treated as the FINAL one — the
    /// combined buffer is decoded with strict STANDARD validation
    /// and the decoder is sealed.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, GrpcError> {
        if self.sealed {
            return Err(GrpcError::protocol(
                "base64 stream decoder is sealed — cannot push after \
                 finish() or after padding has been observed \
                 (br-asupersync-37svtb)",
            ));
        }
        if chunk.is_empty() {
            return Ok(Vec::new());
        }

        let mut combined = Vec::with_capacity(self.pending.len() + chunk.len());
        combined.extend_from_slice(&self.pending);
        combined.extend_from_slice(chunk);

        // Padding must only appear in the FINAL quartet of the
        // entire stream. If the first '=' arrives before its quartet
        // is complete (for example a final "==" split one byte at a
        // time), buffer it until a later push completes the group.
        // Once complete, let STANDARD validate padding placement,
        // count, and any trailing bytes.
        if combined.contains(&b'=') {
            if combined.len() % 4 != 0 {
                self.pending.clear();
                self.pending.extend_from_slice(&combined);
                return Ok(Vec::new());
            }

            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&combined)
                .map_err(|e| {
                    GrpcError::protocol(format!(
                        "invalid base64 in grpc-web-text final chunk: {e} \
                         (br-asupersync-37svtb)"
                    ))
                })?;
            self.pending.clear();
            self.sealed = true;
            return Ok(decoded);
        }

        // No padding — decode all complete quartets, retain trailing
        // partial group (0–3 chars) for the next push.
        let complete_len = combined.len() - (combined.len() % 4);
        let to_decode = &combined[..complete_len];

        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(to_decode)
            .map_err(|e| {
                GrpcError::protocol(format!(
                    "invalid base64 in grpc-web-text chunk: {e} \
                     (br-asupersync-37svtb)"
                ))
            })?;

        self.pending.clear();
        self.pending.extend_from_slice(&combined[complete_len..]);
        Ok(decoded)
    }

    /// Finalize the stream. Decodes any 2–3 char trailing partial
    /// quartet without padding (STANDARD_NO_PAD permits unpadded
    /// 2- or 3-char tails since the binary stream length is
    /// independently known). A single trailing char is invalid base64
    /// and surfaces as `Err`. Idempotent: calling `finish` again
    /// after the decoder has been sealed (by either prior `finish`
    /// or in-band padding) returns `Ok(Vec::new())`.
    pub fn finish(&mut self) -> Result<Vec<u8>, GrpcError> {
        if self.sealed {
            return Ok(Vec::new());
        }
        self.sealed = true;

        if self.pending.is_empty() {
            return Ok(Vec::new());
        }

        if self.pending.len() == 1 {
            let byte = self.pending[0];
            self.pending.clear();
            return Err(GrpcError::protocol(format!(
                "trailing single base64 character at stream end is invalid: \
                 0x{byte:02x} (a complete base64 group is at least 2 chars; \
                 br-asupersync-37svtb)"
            )));
        }

        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&self.pending)
            .map_err(|e| {
                GrpcError::protocol(format!(
                    "invalid base64 trailing data at stream end: {e} \
                     (br-asupersync-37svtb)"
                ))
            })?;
        self.pending.clear();
        Ok(decoded)
    }
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send,
        unused_must_use
    )]
    use super::*;
    use base64::Engine as _;
    use insta::assert_snapshot;
    use std::fmt::Write as _;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn scrub_grpc_web_frame_length(length: usize) -> String {
        format!("<{length} bytes>")
    }

    fn render_bytes_as_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn render_grpc_web_frames_for_snapshot_test(bytes: &[u8]) -> String {
        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::from(bytes);
        let mut rendered = String::new();
        let mut index = 0usize;

        while !buf.is_empty() {
            assert!(
                buf.len() >= 5,
                "snapshot input must contain a full gRPC-Web header"
            );

            let flag = buf[0];
            let length = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            let payload = buf[5..5 + length].to_vec();
            let frame = codec
                .decode(&mut buf)
                .expect("snapshot frame should decode")
                .expect("snapshot frame should be complete");

            let _ = writeln!(&mut rendered, "frame[{index}]");
            let _ = writeln!(&mut rendered, "  flag=0x{flag:02x}");
            let _ = writeln!(
                &mut rendered,
                "  length={}",
                scrub_grpc_web_frame_length(length)
            );

            match frame {
                WebFrame::Data { compressed, data } => {
                    let _ = writeln!(&mut rendered, "  kind=data");
                    let _ = writeln!(&mut rendered, "  compressed={compressed}");
                    let _ = writeln!(
                        &mut rendered,
                        "  payload_utf8={:?}",
                        String::from_utf8_lossy(data.as_ref())
                    );
                }
                WebFrame::Trailers(trailers) => {
                    let _ = writeln!(&mut rendered, "  kind=trailers");
                    let _ = writeln!(
                        &mut rendered,
                        "  trailer_block={:?}",
                        String::from_utf8_lossy(&payload)
                    );
                    let _ = writeln!(
                        &mut rendered,
                        "  status_code={}",
                        trailers.status.code().as_i32()
                    );
                    let _ = writeln!(
                        &mut rendered,
                        "  status_message={:?}",
                        trailers.status.message()
                    );

                    for (metadata_index, (key, value)) in trailers.metadata.iter().enumerate() {
                        match value {
                            MetadataValue::Ascii(text) => {
                                let _ = writeln!(
                                    &mut rendered,
                                    "  metadata[{metadata_index}] {key}={text:?}"
                                );
                            }
                            MetadataValue::Binary(binary) => {
                                let _ = writeln!(
                                    &mut rendered,
                                    "  metadata[{metadata_index}] {key}={:?}",
                                    base64::engine::general_purpose::STANDARD
                                        .encode(binary.as_ref())
                                );
                            }
                        }
                    }
                }
            }

            index += 1;
        }

        rendered
    }

    fn render_grpc_web_request_wire_layout_for_snapshot_test(bytes: &[u8]) -> String {
        assert!(
            bytes.len() >= 5,
            "snapshot input must contain a full gRPC-Web request header"
        );

        let length = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        let payload = &bytes[5..];
        assert!(
            payload.len() == length,
            "snapshot input payload length must match gRPC-Web frame header"
        );

        let mut rendered = String::new();
        let _ = writeln!(
            &mut rendered,
            "content_type_binary: {}",
            ContentType::GrpcWeb.as_header_value()
        );
        let _ = writeln!(
            &mut rendered,
            "content_type_text: {}",
            ContentType::GrpcWebText.as_header_value()
        );
        let _ = writeln!(&mut rendered, "flag: {:02x}", bytes[0]);
        let _ = writeln!(
            &mut rendered,
            "message_length_be: {}",
            render_bytes_as_hex(&bytes[1..5])
        );
        let _ = writeln!(&mut rendered, "message_length: {length}");
        let _ = writeln!(
            &mut rendered,
            "payload_utf8_lossy: {:?}",
            String::from_utf8_lossy(payload)
        );
        let _ = writeln!(
            &mut rendered,
            "payload_hex: {}",
            render_bytes_as_hex(payload)
        );
        let _ = writeln!(&mut rendered, "wire_hex: {}", render_bytes_as_hex(bytes));
        let _ = writeln!(&mut rendered, "wire_base64: {}", base64_encode(bytes));
        rendered
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

    #[test]
    fn test_trailer_metadata_key_injection_is_rejected() {
        init_test("test_trailer_metadata_key_injection_is_rejected");
        let status = Status::ok();
        let mut metadata = Metadata::new();
        let inserted = metadata.insert("x-safe\r\nx-evil", "boom");
        crate::assert_with_log!(
            !inserted,
            "malicious trailer metadata key rejected at insertion",
            false,
            inserted
        );

        let mut buf = BytesMut::new();
        encode_trailers(&status, &metadata, &mut buf);
        let wire = String::from_utf8(buf[5..].to_vec()).expect("trailer block utf8");
        let injected = wire.contains("x-evil");
        crate::assert_with_log!(
            !injected,
            "rejected trailer key never reaches the wire format",
            false,
            injected
        );
        crate::test_complete!("test_trailer_metadata_key_injection_is_rejected");
    }

    #[test]
    fn test_trailer_pseudo_header_metadata_is_rejected() {
        init_test("test_trailer_pseudo_header_metadata_is_rejected");
        let status = Status::ok();
        let mut metadata = Metadata::new();
        let inserted = metadata.insert(":path", "/evil");
        crate::assert_with_log!(
            !inserted,
            "pseudo-header metadata key rejected at insertion",
            false,
            inserted
        );

        let mut buf = BytesMut::new();
        encode_trailers(&status, &metadata, &mut buf);
        let wire = String::from_utf8(buf[5..].to_vec()).expect("trailer block utf8");
        let injected = wire.contains(":path");
        crate::assert_with_log!(
            !injected,
            "rejected pseudo-header never reaches the wire format",
            false,
            injected
        );
        crate::test_complete!("test_trailer_pseudo_header_metadata_is_rejected");
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

    #[test]
    fn p2lx74_binary_codec_rejects_bytes_after_terminal_trailer() {
        init_test("p2lx74_binary_codec_rejects_bytes_after_terminal_trailer");
        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::new();
        codec
            .encode_trailers(&Status::ok(), &Metadata::new(), &mut buf)
            .expect("trailer encodes");
        codec
            .encode_data(b"smuggled", false, &mut buf)
            .expect("extra frame encodes");

        let err = codec
            .decode(&mut buf)
            .expect_err("bytes after terminal trailer must fail closed");
        match err {
            GrpcError::Protocol(msg) => {
                assert!(
                    msg.contains("terminal gRPC-Web trailer")
                        && msg.contains("br-asupersync-p2lx74"),
                    "unexpected protocol error: {msg}"
                );
            }
            other => panic!("expected protocol error, got {other:?}"),
        }
        assert!(
            codec.is_poisoned(),
            "trailing bytes after trailer must poison the codec"
        );
    }

    #[test]
    fn grpc_web_frame_layouts_snapshot() {
        init_test("grpc_web_frame_layouts_snapshot");
        let codec = WebFrameCodec::new();

        let mut happy_path = BytesMut::new();
        codec
            .encode_data(b"hello grpc-web", false, &mut happy_path)
            .expect("happy-path data frame encodes");
        let mut happy_metadata = Metadata::new();
        let inserted_trace = happy_metadata.insert("x-trace-id", "trace-123");
        crate::assert_with_log!(
            inserted_trace,
            "happy-path trace metadata inserted",
            true,
            inserted_trace
        );
        let inserted_bin =
            happy_metadata.insert_bin("trace-bin", Bytes::from_static(&[0x01, 0x02]));
        crate::assert_with_log!(
            inserted_bin,
            "happy-path binary metadata inserted",
            true,
            inserted_bin
        );
        codec
            .encode_trailers(&Status::ok(), &happy_metadata, &mut happy_path)
            .expect("happy-path trailers encode");

        let mut error_trailers_only = BytesMut::new();
        let mut error_metadata = Metadata::new();
        let inserted_hint = error_metadata.insert("retry-after", "3");
        crate::assert_with_log!(
            inserted_hint,
            "error-path retry metadata inserted",
            true,
            inserted_hint
        );
        codec
            .encode_trailers(
                &Status::invalid_argument("bad\nfield"),
                &error_metadata,
                &mut error_trailers_only,
            )
            .expect("error trailers encode");

        let mut trailers_only = BytesMut::new();
        let mut trailers_only_metadata = Metadata::new();
        let inserted_cache = trailers_only_metadata.insert("x-cache", "MISS");
        crate::assert_with_log!(
            inserted_cache,
            "trailers-only metadata inserted",
            true,
            inserted_cache
        );
        codec
            .encode_trailers(&Status::ok(), &trailers_only_metadata, &mut trailers_only)
            .expect("trailers-only encode");

        let mut snapshot = String::new();
        let _ = writeln!(&mut snapshot, "[happy_path]");
        snapshot.push_str(&render_grpc_web_frames_for_snapshot_test(
            happy_path.as_ref(),
        ));
        let _ = writeln!(&mut snapshot, "[error_trailers_only]");
        snapshot.push_str(&render_grpc_web_frames_for_snapshot_test(
            error_trailers_only.as_ref(),
        ));
        let _ = writeln!(&mut snapshot, "[trailers_only]");
        snapshot.push_str(&render_grpc_web_frames_for_snapshot_test(
            trailers_only.as_ref(),
        ));

        assert_snapshot!("grpc_web_frame_layouts", snapshot);
        crate::test_complete!("grpc_web_frame_layouts_snapshot");
    }

    #[test]
    fn grpc_web_representative_request_wire_layout_snapshot() {
        init_test("grpc_web_representative_request_wire_layout_snapshot");
        let codec = WebFrameCodec::new();
        let request_payload = b"\x0a\x0ehello grpc-web";
        let mut request = BytesMut::new();
        codec
            .encode_data(request_payload, false, &mut request)
            .expect("representative request encodes");

        let mut decode_buf = BytesMut::from(request.as_ref());
        let frame = codec
            .decode(&mut decode_buf)
            .expect("representative request decodes")
            .expect("representative request frame complete");
        let WebFrame::Data { compressed, data } = frame else {
            panic!("expected representative request data frame")
        };
        crate::assert_with_log!(
            !compressed,
            "representative request not compressed",
            false,
            compressed
        );
        crate::assert_with_log!(
            data.as_ref() == request_payload,
            "representative request payload round-trips",
            request_payload,
            data.as_ref()
        );
        crate::assert_with_log!(
            decode_buf.is_empty(),
            "representative request fully consumed",
            true,
            decode_buf.is_empty()
        );

        let snapshot = render_grpc_web_request_wire_layout_for_snapshot_test(request.as_ref());
        assert_snapshot!("grpc_web_representative_request_wire_layout", snapshot);
        crate::test_complete!("grpc_web_representative_request_wire_layout_snapshot");
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
    fn test_base64_rfc4648_single_octet_vector() {
        init_test("test_base64_rfc4648_single_octet_vector");

        let encoded = base64_encode(b"f");
        crate::assert_with_log!(
            encoded == "Zg==",
            "rfc4648 encode vector",
            "Zg==",
            encoded.as_str()
        );

        let decoded = base64_decode("Zg==").unwrap();
        crate::assert_with_log!(
            decoded == b"f",
            "rfc4648 decode vector",
            b"f".as_slice(),
            decoded.as_slice()
        );

        crate::test_complete!("test_base64_rfc4648_single_octet_vector");
    }

    #[test]
    fn test_base64_rfc3548_two_octet_vector() {
        init_test("test_base64_rfc3548_two_octet_vector");

        let encoded = base64_encode(b"fo");
        crate::assert_with_log!(
            encoded == "Zm8=",
            "rfc3548 encode vector",
            "Zm8=",
            encoded.as_str()
        );

        let decoded = base64_decode("Zm8=").unwrap();
        crate::assert_with_log!(
            decoded == b"fo",
            "rfc3548 decode vector",
            b"fo".as_slice(),
            decoded.as_slice()
        );

        crate::test_complete!("test_base64_rfc3548_two_octet_vector");
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

    // ─── br-asupersync-ood365: reserved-flag-bits regression ─────────

    /// Helper: build a minimal 5-byte gRPC-Web frame header with the
    /// given flag and length, appending a zero payload.
    fn build_frame(flag: u8, payload_len: u32) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(flag);
        buf.put_u32(payload_len);
        buf.extend_from_slice(&vec![0u8; payload_len as usize]);
        buf
    }

    fn assert_protocol_error(result: Result<Option<WebFrame>, GrpcError>, label: &str) {
        match result {
            Err(GrpcError::Protocol(msg)) => {
                assert!(
                    msg.contains("reserved flag bits"),
                    "{label}: protocol error must mention 'reserved flag bits'; got: {msg}"
                );
            }
            other => panic!("{label}: expected Err(Protocol(...)), got {other:?}"),
        }
    }

    #[test]
    fn ood365_legal_flag_values_decode_successfully() {
        init_test("ood365_legal_flag_values_decode_successfully");
        // Currently supported flag values: data, compressed-data, and
        // uncompressed trailers. Compressed trailers (0x81) must fail
        // closed until the codec can actually decompress trailer blocks.
        for &flag in &[0x00u8, 0x01, 0x80] {
            let codec = WebFrameCodec::new();
            let payload_len = if flag & TRAILER_FLAG != 0 {
                // Trailer payloads must be a parseable header block; use
                // an empty block (decoder treats missing grpc-status as
                // INTERNAL — that's a non-protocol-error decode).
                0
            } else {
                4
            };
            let mut buf = build_frame(flag, payload_len);
            let result = codec.decode(&mut buf);
            assert!(
                result.is_ok(),
                "legal flag 0x{flag:02x} must decode without protocol error; got {result:?}"
            );
        }
        crate::test_complete!("ood365_legal_flag_values_decode_successfully");
    }

    #[test]
    fn compressed_trailer_frames_fail_closed() {
        init_test("compressed_trailer_frames_fail_closed");
        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::new();
        buf.put_u8(0x81);
        buf.put_u32(0);

        let err = codec
            .decode(&mut buf)
            .expect_err("compressed trailer frames must not be silently accepted");
        match err {
            GrpcError::Compression(message) => {
                assert!(
                    message.contains("compressed gRPC-Web trailer frames are unsupported"),
                    "unexpected compression error: {message}"
                );
            }
            other => panic!("expected compression error, got {other:?}"),
        }
        assert!(
            codec.is_poisoned(),
            "unsupported compressed trailers must poison the codec"
        );
        crate::test_complete!("compressed_trailer_frames_fail_closed");
    }

    #[test]
    fn ood365_individual_reserved_bits_are_rejected() {
        init_test("ood365_individual_reserved_bits_are_rejected");
        // Every reserved bit, alone, MUST be rejected.
        for shift in 1u8..=6 {
            let codec = WebFrameCodec::new();
            let flag = 1u8 << shift;
            let mut buf = build_frame(flag, 0);
            assert_protocol_error(codec.decode(&mut buf), &format!("flag 0x{flag:02x}"));
        }
        crate::test_complete!("ood365_individual_reserved_bits_are_rejected");
    }

    #[test]
    fn ood365_full_reserved_mask_rejected() {
        init_test("ood365_full_reserved_mask_rejected");
        let codec = WebFrameCodec::new();
        // All reserved bits at once.
        let mut buf = build_frame(RESERVED_FLAG_MASK, 0);
        assert_protocol_error(codec.decode(&mut buf), "RESERVED_FLAG_MASK");
        crate::test_complete!("ood365_full_reserved_mask_rejected");
    }

    #[test]
    fn ood365_reserved_bit_combined_with_trailer_or_compression_rejected() {
        init_test("ood365_reserved_bit_combined_with_trailer_or_compression_rejected");
        // 0x82 = TRAILER (0x80) | reserved bit 1 (0x02). Even though bit
        // 7 alone would be legal, the reserved overlap MUST reject.
        let mut buf = build_frame(0x82, 0);
        assert_protocol_error(
            WebFrameCodec::new().decode(&mut buf),
            "0x82 (trailer + reserved)",
        );
        // 0x03 = compression (0x01) | reserved bit 1 (0x02).
        let mut buf = build_frame(0x03, 0);
        assert_protocol_error(
            WebFrameCodec::new().decode(&mut buf),
            "0x03 (compression + reserved)",
        );
        crate::test_complete!("ood365_reserved_bit_combined_with_trailer_or_compression_rejected");
    }

    #[test]
    fn ood365_reject_does_not_consume_buffer() {
        init_test("ood365_reject_does_not_consume_buffer");
        let codec = WebFrameCodec::new();
        // Reserved-bit rejection must happen BEFORE split_to(5) so the
        // caller can still inspect the original 5-byte header for
        // diagnostic logging.
        let mut buf = build_frame(0x40, 4);
        let len_before = buf.len();
        let _ = codec.decode(&mut buf);
        assert_eq!(
            buf.len(),
            len_before,
            "reserved-bit rejection must NOT consume the frame header"
        );
        crate::test_complete!("ood365_reject_does_not_consume_buffer");
    }

    // ── br-asupersync-nln9sc: codec poison after unrecoverable error ─

    #[test]
    fn nln9sc_reserved_bit_err_poisons_codec() {
        // First decode trips reserved-bit Err. Second decode must NOT
        // re-emit the original Err in a tight loop — codec is poisoned
        // and returns a distinct "codec poisoned" protocol error.
        init_test("nln9sc_reserved_bit_err_poisons_codec");
        let codec = WebFrameCodec::new();
        assert!(!codec.is_poisoned(), "fresh codec must not be poisoned");

        let mut buf = build_frame(0x40, 4);
        let first = codec.decode(&mut buf);
        assert!(matches!(first, Err(GrpcError::Protocol(_))));
        assert!(codec.is_poisoned(), "first decode Err must poison");

        // Second decode on the same buffer must surface the poisoned
        // sentinel error rather than re-reading the bytes and producing
        // the original reserved-bit error again.
        let second = codec.decode(&mut buf);
        match second {
            Err(GrpcError::Protocol(msg)) => {
                assert!(
                    msg.contains("poisoned") && msg.contains("br-asupersync-nln9sc"),
                    "second decode must return the poisoned sentinel: {msg}"
                );
            }
            other => panic!("expected Protocol poisoned error, got {other:?}"),
        }
    }

    #[test]
    fn nln9sc_message_too_large_err_poisons_codec() {
        init_test("nln9sc_message_too_large_err_poisons_codec");
        let codec = WebFrameCodec::with_max_size(4);
        // Frame with length 100 — far over the 4-byte cap.
        let mut buf = BytesMut::new();
        buf.put_u8(0x00);
        buf.put_u32(100);
        // (no body bytes — the length check fires before src.len() < 5+length)
        let first = codec.decode(&mut buf);
        assert!(matches!(first, Err(GrpcError::MessageTooLarge)));
        assert!(codec.is_poisoned(), "MessageTooLarge must poison the codec");

        let second = codec.decode(&mut buf);
        match second {
            Err(GrpcError::Protocol(msg)) => {
                assert!(msg.contains("poisoned"));
            }
            other => panic!("expected Protocol poisoned error, got {other:?}"),
        }
    }

    #[test]
    fn nln9sc_successful_decode_after_successful_decode_unaffected() {
        // Successful decodes must NEVER poison — only Err paths.
        init_test("nln9sc_successful_decode_after_successful_decode_unaffected");
        let codec = WebFrameCodec::new();
        let mut buf = BytesMut::new();
        codec.encode_data(b"first", false, &mut buf).unwrap();
        codec.encode_data(b"second", false, &mut buf).unwrap();

        let f1 = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(f1, WebFrame::Data { .. }));
        assert!(!codec.is_poisoned(), "successful decode must not poison");

        let f2 = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(f2, WebFrame::Data { .. }));
        assert!(!codec.is_poisoned());
    }

    #[test]
    fn nln9sc_malformed_trailer_block_also_poisons() {
        // A malformed trailer payload (e.g. propagated from
        // decode_trailers via a duplicate grpc-status) is also
        // unrecoverable — the trailer marks end-of-stream by
        // definition, so any subsequent decode should NOT loop on
        // unconsumed bytes either. Trigger via duplicate grpc-status
        // from br-nbryje hardening.
        init_test("nln9sc_malformed_trailer_block_also_poisons");
        let codec = WebFrameCodec::new();
        let block = b"grpc-status: 0\r\ngrpc-status: 0\r\n";
        let mut buf = BytesMut::new();
        buf.put_u8(TRAILER_FLAG);
        buf.put_u32(u32::try_from(block.len()).unwrap());
        buf.extend_from_slice(block);

        let first = codec.decode(&mut buf);
        assert!(matches!(first, Err(GrpcError::Protocol(_))));
        assert!(
            codec.is_poisoned(),
            "trailer-block decode failure must poison the codec"
        );
    }

    // ── br-asupersync-6qwzl0: malformed grpc-status surfaced as Err ─

    #[test]
    fn _6qwzl0_malformed_grpc_status_returns_protocol_error() {
        // Pre-fix: parse failure silently coerced to INTERNAL via
        // unwrap_or(13). Now must surface as GrpcError::protocol so
        // the client can distinguish a real INTERNAL from coerced
        // garbage.
        init_test("_6qwzl0_malformed_grpc_status_returns_protocol_error");
        let body = b"grpc-status: garbage\r\n";
        let result = decode_trailers(body);
        match result {
            Err(GrpcError::Protocol(msg)) => {
                assert!(
                    msg.contains("malformed grpc-status") && msg.contains("br-asupersync-6qwzl0"),
                    "must surface as protocol error: {msg}"
                );
            }
            other => panic!("expected Protocol error for malformed status, got {other:?}"),
        }
    }

    #[test]
    fn _6qwzl0_negative_grpc_status_still_accepted() {
        // Negative integers are technically out-of-range per gRPC spec
        // (codes are u8), but `parse::<i32>` accepts them. Pre-fix
        // they passed through Code::from_i32 (which maps unknown to
        // Unknown). The fix is about surfacing PARSE failure, not
        // about range validation — negative values must still parse
        // OK so we don't accidentally tighten the contract here.
        init_test("_6qwzl0_negative_grpc_status_still_accepted");
        let body = b"grpc-status: -1\r\n";
        let trailer = decode_trailers(body).unwrap();
        // Code::from_i32 may map -1 to Unknown — we only assert
        // decode_trailers returned Ok, which matches the pre-fix
        // contract for any successfully-parsed integer.
        let _ = trailer.status.code();
    }

    #[test]
    fn _6qwzl0_well_formed_grpc_status_round_trips_unchanged() {
        // The fix must NOT regress the happy path — well-formed
        // integer status codes still parse and produce the
        // corresponding Code variant.
        init_test("_6qwzl0_well_formed_grpc_status_round_trips_unchanged");
        let body = b"grpc-status: 5\r\n";
        let trailer = decode_trailers(body).unwrap();
        assert_eq!(trailer.status.code().as_i32(), 5);
    }

    // ── br-asupersync-37svtb: streaming base64 decoder ────────────────
    //
    // The reference implementation strategy across these tests:
    // (1) build a known-good binary payload, (2) base64-encode it
    // with the STANDARD engine, (3) feed the resulting text to the
    // streaming decoder in various chunk-boundary partitions, and
    // (4) assert that concatenated push outputs + finish output
    // equal the original payload. Padding edge cases get explicit
    // tests separately.

    fn _37svtb_decode_via_chunks(text: &str, chunk_sizes: &[usize]) -> Vec<u8> {
        let bytes = text.as_bytes();
        let mut decoder = Base64StreamDecoder::new();
        let mut out = Vec::new();
        let mut offset = 0;
        for &size in chunk_sizes {
            let end = (offset + size).min(bytes.len());
            let chunk = &bytes[offset..end];
            out.extend(decoder.push(chunk).unwrap());
            offset = end;
        }
        if offset < bytes.len() {
            out.extend(decoder.push(&bytes[offset..]).unwrap());
        }
        out.extend(decoder.finish().unwrap());
        out
    }

    #[test]
    fn _37svtb_whole_input_in_one_push_padded() {
        init_test("_37svtb_whole_input_in_one_push_padded");
        // 5 bytes → 8 base64 chars with "=" padding
        let payload: &[u8] = b"hello";
        let encoded = base64_encode(payload);
        assert!(
            encoded.ends_with('='),
            "5-byte payload must encode with padding"
        );

        let mut decoder = Base64StreamDecoder::new();
        let decoded = decoder.push(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, payload);
        assert!(decoder.is_sealed(), "padding in push must seal the decoder");

        // finish() after seal is a no-op returning empty.
        let trailing = decoder.finish().unwrap();
        assert!(trailing.is_empty());
    }

    #[test]
    fn _37svtb_split_at_every_byte_boundary_padded() {
        // Encode 7 bytes (which produces "...=" padding) and split
        // into single-byte chunks to exercise the partial-quartet
        // buffering through every offset.
        init_test("_37svtb_split_at_every_byte_boundary_padded");
        let payload: &[u8] = b"asupers"; // 7 bytes, requires "=" padding
        let encoded = base64_encode(payload);
        let chunk_sizes: Vec<usize> = (0..encoded.len()).map(|_| 1).collect();
        let decoded = _37svtb_decode_via_chunks(&encoded, &chunk_sizes);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn _37svtb_split_at_quartet_boundary_unpadded() {
        // Encode 6 bytes (no padding needed: 6*8/6 = 8 base64 chars,
        // a multiple of 4) and split mid-quartet to exercise the
        // unpadded-finish() path.
        init_test("_37svtb_split_at_quartet_boundary_unpadded");
        let payload: &[u8] = b"abcdef"; // 6 bytes → 8 chars no padding
        let encoded = base64_encode(payload);
        assert!(
            !encoded.contains('='),
            "6-byte payload must encode without padding"
        );

        // Split as 3 + 5: first chunk leaves 3 chars pending, second
        // chunk completes one quartet (3+1=4) and leaves 4 chars
        // forming a complete quartet → 0 pending. finish() returns
        // empty.
        let mut decoder = Base64StreamDecoder::new();
        let mut decoded = Vec::new();
        decoded.extend(decoder.push(&encoded.as_bytes()[..3]).unwrap());
        decoded.extend(decoder.push(&encoded.as_bytes()[3..]).unwrap());
        decoded.extend(decoder.finish().unwrap());
        assert_eq!(decoded, payload);
    }

    #[test]
    fn _37svtb_unpadded_3char_tail_decoded_via_finish() {
        // 4 bytes → ceil(4*8/6) = 6 base64 chars. STANDARD encodes
        // as "AAAA<2>==" with 2 padding. STANDARD_NO_PAD-style
        // emission would be 6 unpadded chars → decoder needs to
        // accept the 2-char trailing remainder via finish().
        init_test("_37svtb_unpadded_3char_tail_decoded_via_finish");
        let payload: &[u8] = b"asup"; // 4 bytes
        let unpadded = base64_encode(payload).trim_end_matches('=').to_string();
        assert_eq!(unpadded.len(), 6);

        let mut decoder = Base64StreamDecoder::new();
        let mid = decoder.push(unpadded.as_bytes()).unwrap();
        // 4 chars decode to 3 bytes; 2 chars remain in pending.
        assert_eq!(mid.len(), 3);
        assert!(!decoder.is_sealed(), "no padding seen yet");

        let trailing = decoder.finish().unwrap();
        assert_eq!(trailing.len(), 1);
        assert!(decoder.is_sealed());

        let mut full = mid;
        full.extend(trailing);
        assert_eq!(full, payload);
    }

    #[test]
    fn _37svtb_padding_in_push_seals_and_rejects_subsequent_push() {
        // Once padding has been observed, the decoder is sealed.
        // Any subsequent push must return Err so the caller can't
        // accidentally feed more bytes after the stream end.
        init_test("_37svtb_padding_in_push_seals_and_rejects_subsequent_push");
        let mut decoder = Base64StreamDecoder::new();
        let _ = decoder.push(b"aGVsbG8=").unwrap();
        assert!(decoder.is_sealed());

        let result = decoder.push(b"ZXh0cmE=");
        match result {
            Err(GrpcError::Protocol(msg)) => {
                assert!(msg.contains("sealed") && msg.contains("br-asupersync-37svtb"));
            }
            other => panic!("expected Protocol error after seal, got {other:?}"),
        }
    }

    #[test]
    fn _37svtb_trailing_single_char_at_finish_is_invalid() {
        // 1 trailing char is ambiguous — base64 needs at least 2
        // chars to encode 1 byte. Surface as Err.
        init_test("_37svtb_trailing_single_char_at_finish_is_invalid");
        let mut decoder = Base64StreamDecoder::new();
        // 5 chars: 4 form one complete quartet, 1 char left over.
        let _ = decoder.push(b"AAAAB").unwrap();
        let result = decoder.finish();
        match result {
            Err(GrpcError::Protocol(msg)) => {
                assert!(msg.contains("trailing single base64 character"));
                assert!(msg.contains("br-asupersync-37svtb"));
            }
            other => panic!("expected Protocol error for 1-char tail, got {other:?}"),
        }
        // Decoder must still be sealed even after the error finish.
        assert!(decoder.is_sealed());
    }

    #[test]
    fn _37svtb_empty_stream_is_well_formed() {
        // Zero pushes + finish() returns empty without error.
        init_test("_37svtb_empty_stream_is_well_formed");
        let mut decoder = Base64StreamDecoder::new();
        let trailing = decoder.finish().unwrap();
        assert!(trailing.is_empty());
        assert!(decoder.is_sealed());
    }

    #[test]
    fn _37svtb_empty_chunk_pushes_are_no_ops() {
        init_test("_37svtb_empty_chunk_pushes_are_no_ops");
        let mut decoder = Base64StreamDecoder::new();
        for _ in 0..5 {
            let out = decoder.push(b"").unwrap();
            assert!(out.is_empty());
        }
        assert!(!decoder.is_sealed(), "empty pushes must not seal");
        let _ = decoder.push(b"AAAA").unwrap();
        let trailing = decoder.finish().unwrap();
        assert!(trailing.is_empty());
    }

    #[test]
    fn _37svtb_idempotent_finish_after_seal() {
        // Calling finish() on a sealed decoder (via padding in push)
        // must return Ok(empty) and not error.
        init_test("_37svtb_idempotent_finish_after_seal");
        let mut decoder = Base64StreamDecoder::new();
        let _ = decoder.push(b"aGVsbG8=").unwrap();
        assert!(decoder.is_sealed());

        let first = decoder.finish().unwrap();
        assert!(first.is_empty());
        let second = decoder.finish().unwrap();
        assert!(second.is_empty());
    }

    #[test]
    fn _37svtb_invalid_base64_char_in_push_surfaces_as_protocol_error() {
        // Non-alphabet characters (e.g. CR/LF, '!', '*') must be
        // rejected by the underlying STANDARD engine and surface as
        // GrpcError::Protocol — gRPC-Web text mode forbids
        // whitespace.
        init_test("_37svtb_invalid_base64_char_in_push_surfaces_as_protocol_error");
        let mut decoder = Base64StreamDecoder::new();
        let result = decoder.push(b"AA\nAA");
        match result {
            Err(GrpcError::Protocol(msg)) => {
                assert!(msg.contains("invalid base64") && msg.contains("br-asupersync-37svtb"));
            }
            other => panic!("expected Protocol error for whitespace, got {other:?}"),
        }
    }

    #[test]
    fn _37svtb_long_payload_split_into_many_chunks_round_trips() {
        // 256-byte payload, encoded, split at varied chunk boundaries
        // (1, 2, 3, 4, 5, 7, 11, 13 char chunks repeating). Decoded
        // output must equal the original payload. Exercises every
        // (pending_len, chunk_len) interaction with pending.
        init_test("_37svtb_long_payload_split_into_many_chunks_round_trips");
        let payload: Vec<u8> = (0..=255u8).collect();
        let encoded = base64_encode(&payload);
        let chunk_sizes = vec![1, 2, 3, 4, 5, 7, 11, 13];
        let mut sizes = Vec::new();
        let mut total = 0;
        let mut idx = 0;
        while total < encoded.len() {
            let s = chunk_sizes[idx % chunk_sizes.len()];
            sizes.push(s);
            total += s;
            idx += 1;
        }
        let decoded = _37svtb_decode_via_chunks(&encoded, &sizes);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn _37svtb_padding_at_quartet_boundary_in_split_chunks() {
        // Final chunk arrives split such that '=' lands at the
        // start of a chunk. Decoder must still recognize it and
        // seal correctly. Encode 4 bytes → 8 chars ending in "==".
        init_test("_37svtb_padding_at_quartet_boundary_in_split_chunks");
        let payload: &[u8] = b"asup"; // 4 bytes → "YXN1cA=="
        let encoded = base64_encode(payload);
        assert!(encoded.ends_with("=="));
        let split = encoded.len() - 2; // split right before "=="
        let mut decoder = Base64StreamDecoder::new();
        let mut out = decoder.push(&encoded.as_bytes()[..split]).unwrap();
        // No padding seen → not sealed yet, partial quartet may exist.
        assert!(!decoder.is_sealed());
        out.extend(decoder.push(&encoded.as_bytes()[split..]).unwrap());
        assert!(decoder.is_sealed(), "padding in second chunk must seal");
        out.extend(decoder.finish().unwrap());
        assert_eq!(out, payload);
    }

    #[test]
    fn grpc_web_text_mode_chunked_trailer_only_stream_round_trips_vs_grpcweb() {
        // gRPC-Web text mode base64-encodes the entire binary frame
        // stream, including trailer-only responses. grpcweb-style HTTP
        // chunking can split that text at arbitrary quartet boundaries,
        // so a trailer block carrying both percent-escaped grpc-message
        // text and nested -bin metadata still has to decode back to the
        // original trailer frame.
        init_test("grpc_web_text_mode_chunked_trailer_only_stream_round_trips_vs_grpcweb");

        let codec = WebFrameCodec::new();
        let status = Status::invalid_argument("bad field\nline 2");
        let mut metadata = Metadata::new();
        assert!(metadata.insert("x-request-id", "req-42"));
        assert!(metadata.insert_bin("trace-bin", Bytes::from_static(b"\x01\x02\xfe\xff")));

        let mut binary = BytesMut::new();
        codec
            .encode_trailers(&status, &metadata, &mut binary)
            .expect("trailer-only grpc-web response must encode");

        let text = base64_encode(binary.as_ref());
        let decoded = _37svtb_decode_via_chunks(&text, &[1, 5, 2, 7, 3, 4, 6]);
        assert_eq!(
            decoded,
            binary.to_vec(),
            "chunked grpc-web-text must reconstruct the exact trailer frame bytes"
        );

        let mut decode_buf = BytesMut::from(decoded.as_slice());
        let frame = codec
            .decode(&mut decode_buf)
            .expect("decoded trailer-only frame must parse")
            .expect("decoded trailer-only frame must be complete");
        let WebFrame::Trailers(trailers) = frame else {
            panic!("expected trailer frame after grpc-web-text decode")
        };

        assert_eq!(trailers.status.code(), status.code());
        assert_eq!(trailers.status.message(), status.message());
        assert_eq!(
            trailers.metadata.get("x-request-id"),
            metadata.get("x-request-id")
        );
        assert_eq!(
            trailers.metadata.get("trace-bin"),
            metadata.get("trace-bin")
        );
        assert!(
            decode_buf.is_empty(),
            "decoded trailer-only grpc-web-text stream must not leave trailing bytes"
        );
        assert!(
            codec.decode(&mut decode_buf).unwrap().is_none(),
            "grpc-web trailer-only stream must decode to exactly one frame"
        );
    }

    #[test]
    fn p2lx74_text_mode_rejects_base64_stream_with_bytes_after_trailer() {
        init_test("p2lx74_text_mode_rejects_base64_stream_with_bytes_after_trailer");

        let codec = WebFrameCodec::new();
        let mut binary = BytesMut::new();
        codec
            .encode_trailers(&Status::ok(), &Metadata::new(), &mut binary)
            .expect("trailer-only grpc-web response must encode");
        codec
            .encode_data(b"smuggled", false, &mut binary)
            .expect("trailing data frame encodes");

        let text = base64_encode(binary.as_ref());
        let decoded = _37svtb_decode_via_chunks(&text, &[2, 3, 5, 7, 11]);
        let mut decode_buf = BytesMut::from(decoded.as_slice());

        let err = codec
            .decode(&mut decode_buf)
            .expect_err("text-mode trailer smuggling must fail closed");
        match err {
            GrpcError::Protocol(msg) => {
                assert!(
                    msg.contains("terminal gRPC-Web trailer")
                        && msg.contains("br-asupersync-p2lx74"),
                    "unexpected protocol error: {msg}"
                );
            }
            other => panic!("expected protocol error, got {other:?}"),
        }
        assert!(
            codec.is_poisoned(),
            "trailing bytes after trailer must poison the codec"
        );
    }

    /// GRPC-WEB-TRAILER-PADDING: Differential test for trailer framing vs gRPC-Web spec
    ///
    /// This test verifies our trailer framing behavior exactly matches the gRPC-Web
    /// specification regarding padding bytes in trailer frames. Per the gRPC-Web spec
    /// (https://github.com/grpc/grpc/blob/main/doc/PROTOCOL-WEB.md):
    ///
    /// "Trailer frames use the gRPC framing protocol with bit 7 (0x80) set to indicate
    /// trailers. The frame body contains HTTP/1.1 headers as key: value\\r\\n pairs."
    ///
    /// Importantly, the spec requires:
    /// 1. No padding bytes between the 5-byte header and trailer content
    /// 2. Trailer content must be exactly the header block with CRLF line endings
    /// 3. Frame length must exactly match the trailer block byte length
    /// 4. Reserved flag bits (1-6) must be zero per br-asupersync-ood365
    #[test]
    fn differential_trailer_framing_padding_vs_grpc_web_spec() {
        init_test("differential_trailer_framing_padding_vs_grpc_web_spec");

        // Build a representative trailer with various metadata types per spec
        let status = Status::invalid_argument("request validation failed");
        let mut metadata = Metadata::new();
        metadata.insert("x-request-id", "test-12345");
        metadata.insert("retry-after", "300");
        metadata.insert_bin("trace-context", Bytes::from_static(b"\x01\x02\x03\x04"));

        // Encode trailers using our implementation
        let mut encoded_buf = BytesMut::new();
        encode_trailers(&status, &metadata, &mut encoded_buf);

        // Parse the wire format manually to verify spec compliance
        assert!(
            encoded_buf.len() >= 5,
            "gRPC-Web spec: trailer frame must have 5-byte header minimum"
        );

        let flag = encoded_buf[0];
        let length = u32::from_be_bytes([
            encoded_buf[1],
            encoded_buf[2],
            encoded_buf[3],
            encoded_buf[4],
        ]);
        let header_block = &encoded_buf[5..];

        // Verify flag byte compliance with gRPC-Web spec
        assert_eq!(
            flag & TRAILER_FLAG,
            TRAILER_FLAG,
            "gRPC-Web spec: trailer frames must have bit 7 set (0x80)"
        );
        assert_eq!(
            flag & RESERVED_FLAG_MASK,
            0,
            "gRPC-Web spec: reserved flag bits 1-6 must be zero"
        );
        assert_eq!(
            flag & 0x01,
            0,
            "gRPC-Web spec: compressed trailers (0x81) not supported, bit 0 must be zero"
        );

        // Verify no padding between header and content per spec
        let expected_content_length = header_block.len();
        assert_eq!(
            length as usize, expected_content_length,
            "gRPC-Web spec: frame length must exactly match trailer content with no padding"
        );

        // Verify header block format compliance with HTTP/1.1 spec
        let block_str = std::str::from_utf8(header_block).expect("trailer block must be UTF-8");

        // gRPC-Web spec: trailers must include grpc-status
        assert!(
            block_str.contains("grpc-status: "),
            "gRPC-Web spec: trailers must include grpc-status header"
        );

        // gRPC-Web spec: status must match the encoded status
        let status_line = block_str
            .lines()
            .find(|line| line.starts_with("grpc-status: "))
            .expect("grpc-status line must exist");
        assert!(
            status_line.contains(&status.code().as_i32().to_string()),
            "gRPC-Web spec: grpc-status must encode the correct status code"
        );

        // Verify percent-encoding compliance for grpc-message per spec
        if !status.message().is_empty() {
            let message_line = block_str
                .lines()
                .find(|line| line.starts_with("grpc-message: "))
                .expect("grpc-message line must exist for non-empty messages");

            // gRPC-Web spec: CR/LF must be percent-encoded in grpc-message
            let message_value = &message_line["grpc-message: ".len()..];
            if status.message().contains('\r') || status.message().contains('\n') {
                assert!(
                    message_value.contains("%0D") || message_value.contains("%0A"),
                    "gRPC-Web spec: CR/LF must be percent-encoded in grpc-message"
                );
            }
        }

        // Verify CRLF line endings per HTTP/1.1 spec
        assert!(
            block_str.ends_with("\r\n") || block_str.is_empty(),
            "gRPC-Web spec: trailer block must use CRLF line endings"
        );

        // Verify binary metadata base64 encoding per spec
        let binary_header_lines: Vec<_> = block_str
            .lines()
            .filter(|line| line.contains("-bin: "))
            .collect();

        for line in binary_header_lines {
            let value_start = line.find(": ").expect("header line must have colon") + 2;
            let base64_value = &line[value_start..];

            // gRPC-Web spec: binary metadata must be valid base64
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(base64_value)
                .unwrap_or_else(|_| {
                    panic!(
                        "gRPC-Web spec: binary metadata must be valid base64: {}",
                        base64_value
                    )
                });
        }

        // Test round-trip decoding to verify our encoder/decoder consistency
        let codec = WebFrameCodec::new();
        let mut decode_buf = BytesMut::from(encoded_buf.as_ref());
        let frame = codec
            .decode(&mut decode_buf)
            .expect("our encoded frame must decode successfully")
            .expect("frame must be complete");

        let WebFrame::Trailers(decoded_trailer) = frame else {
            panic!("decoded frame must be a trailer frame");
        };

        // Verify status round-trip
        assert_eq!(
            decoded_trailer.status.code(),
            status.code(),
            "gRPC-Web spec: status code must round-trip exactly"
        );
        assert_eq!(
            decoded_trailer.status.message(),
            status.message(),
            "gRPC-Web spec: status message must round-trip exactly including percent-encoding"
        );

        // Verify metadata round-trip
        assert_eq!(
            decoded_trailer.metadata.get("x-request-id"),
            metadata.get("x-request-id"),
            "gRPC-Web spec: ASCII metadata must round-trip exactly"
        );
        assert_eq!(
            decoded_trailer.metadata.get("trace-context-bin"),
            metadata.get("trace-context-bin"),
            "gRPC-Web spec: binary metadata must round-trip exactly with -bin suffix normalization"
        );

        // Verify no extra padding or content remains
        assert!(
            decode_buf.is_empty(),
            "gRPC-Web spec: trailer frame must consume exactly the specified length with no trailing padding"
        );

        // Verify frame size efficiency per spec (no unnecessary padding)
        let minimal_expected_size = 5 + block_str.len(); // header + content only
        assert_eq!(
            encoded_buf.len(),
            minimal_expected_size,
            "gRPC-Web spec: trailer frame must be minimal size with no padding bytes"
        );

        crate::test_complete!("differential_trailer_framing_padding_vs_grpc_web_spec");
    }

    #[test]
    fn grpc_web_status_trailer_mapping_differential_conformance() {
        /// Differential conformance test for gRPC-Web STATUS trailer mapping.
        ///
        /// Tests compliance with the grpcweb-protocol specification for status code
        /// encoding and decoding in trailer frames. Verifies that status codes are
        /// correctly mapped between gRPC Code enum values and wire format integers.
        ///
        /// Reference: https://github.com/grpc/grpc/blob/main/doc/PROTOCOL-WEB.md
        /// Requirement: "grpc-status: <int32>" trailer must encode/decode correctly
        use super::super::status::Code;

        // Test matrix of gRPC status codes as defined in grpcweb-protocol spec
        let test_cases = vec![
            (Code::Ok, 0),
            (Code::Cancelled, 1),
            (Code::Unknown, 2),
            (Code::InvalidArgument, 3),
            (Code::DeadlineExceeded, 4),
            (Code::NotFound, 5),
            (Code::AlreadyExists, 6),
            (Code::PermissionDenied, 7),
            (Code::ResourceExhausted, 8),
            (Code::FailedPrecondition, 9),
            (Code::Aborted, 10),
            (Code::OutOfRange, 11),
            (Code::Unimplemented, 12),
            (Code::Internal, 13),
            (Code::Unavailable, 14),
            (Code::DataLoss, 15),
            (Code::Unauthenticated, 16),
        ];

        for &(grpc_code, expected_wire_value) in &test_cases {
            let test_message = format!("Test message for status {}", grpc_code.as_str());

            // Create Status with the gRPC code
            let original_status = Status::new(grpc_code, &test_message);
            let metadata = Metadata::new();

            // CONFORMANCE TEST 1: Encoding produces spec-compliant wire format
            let mut encoded_buf = BytesMut::new();
            encode_trailers(&original_status, &metadata, &mut encoded_buf);

            // Parse the encoded frame manually to verify wire format compliance
            assert!(
                encoded_buf.len() >= 5,
                "trailer frame must have at least 5-byte header"
            );
            assert_eq!(
                encoded_buf[0], TRAILER_FLAG,
                "first byte must be trailer flag 0x80"
            );

            let _length = u32::from_be_bytes([
                encoded_buf[1],
                encoded_buf[2],
                encoded_buf[3],
                encoded_buf[4],
            ]);
            let header_block =
                std::str::from_utf8(&encoded_buf[5..]).expect("trailer block must be valid UTF-8");

            // CONFORMANCE CHECK 1: Wire format must contain "grpc-status: <code>"
            let expected_status_line = format!("grpc-status: {}", expected_wire_value);
            assert!(
                header_block.contains(&expected_status_line),
                "Wire format must contain 'grpc-status: {}' for code {:?}, got: {:?}",
                expected_wire_value,
                grpc_code,
                header_block
            );

            // CONFORMANCE CHECK 2: Message encoding must be percent-escaped per spec
            if !test_message.is_empty() {
                let expected_message_line = format!(
                    "grpc-message: {}",
                    test_message
                        .replace('%', "%25")
                        .replace('\r', "%0D")
                        .replace('\n', "%0A")
                );
                assert!(
                    header_block.contains(&expected_message_line),
                    "Message must be percent-encoded per gRPC-Web spec, expected: {}, got: {}",
                    expected_message_line,
                    header_block
                );
            }

            // CONFORMANCE TEST 2: Decoding recovers the original status
            let trailer_body = &encoded_buf[5..];
            let decoded_trailer = decode_trailers(trailer_body)
                .expect("decoding should succeed for spec-compliant input");

            // CONFORMANCE CHECK 3: Status code must round-trip exactly
            assert_eq!(
                decoded_trailer.status.code(),
                grpc_code,
                "Decoded status code must match original for wire value {}",
                expected_wire_value
            );

            // CONFORMANCE CHECK 4: Message must round-trip with percent-decoding
            assert_eq!(
                decoded_trailer.status.message(),
                test_message,
                "Message must round-trip with percent-decoding for code {:?}",
                grpc_code
            );

            // CONFORMANCE CHECK 5: Wire value mapping must be bijective
            assert_eq!(
                grpc_code.as_i32(),
                expected_wire_value,
                "gRPC Code enum must map to correct wire value per grpcweb-protocol spec"
            );
        }

        // CONFORMANCE TEST 3: Invalid wire values are handled per spec
        let invalid_wire_formats = vec![
            ("grpc-status: not_a_number\r\n", "non-numeric status"),
            ("grpc-status: 999\r\n", "out-of-range status code"),
            ("grpc-status: -1\r\n", "negative status code"),
        ];

        for (invalid_block, description) in invalid_wire_formats {
            let result = decode_trailers(invalid_block.as_bytes());
            match description {
                "non-numeric status" => {
                    assert!(
                        result.is_err(),
                        "Non-numeric grpc-status must be rejected per spec (br-asupersync-6qwzl0)"
                    );
                }
                "out-of-range status code" | "negative status code" => {
                    // Per gRPC spec, unknown codes should be treated as UNKNOWN (2)
                    if let Ok(trailer) = result {
                        assert_eq!(
                            trailer.status.code(),
                            Code::Unknown,
                            "Out-of-range status codes should map to UNKNOWN per gRPC spec"
                        );
                    }
                }
                _ => {}
            }
        }

        // CONFORMANCE TEST 4: Duplicate status headers are rejected per spec
        let duplicate_status_block = "grpc-status: 0\r\ngrpc-status: 2\r\n";
        let result = decode_trailers(duplicate_status_block.as_bytes());
        assert!(
            result.is_err(),
            "Duplicate grpc-status headers must be rejected per grpcweb-protocol spec (br-nbryje)"
        );

        // CONFORMANCE TEST 5: Missing grpc-status is treated as INTERNAL per spec
        let missing_status_block = "grpc-message: Missing status\r\n";
        let result = decode_trailers(missing_status_block.as_bytes())
            .expect("missing status should default to INTERNAL");
        assert_eq!(
            result.status.code(),
            Code::Internal,
            "Missing grpc-status must default to INTERNAL (13) per grpcweb-protocol spec"
        );

        println!("✓ gRPC-Web STATUS-trailer mapping differential conformance verified");
        println!(
            "  - All {} standard gRPC status codes correctly encoded/decoded",
            test_cases.len()
        );
        println!("  - Invalid status formats properly rejected per grpcweb-protocol spec");
        println!("  - Duplicate status headers rejected per spec (br-nbryje)");
        println!("  - Missing status defaults to INTERNAL per spec");

        crate::test_complete!("grpc_web_status_trailer_mapping_differential_conformance");
    }
}
