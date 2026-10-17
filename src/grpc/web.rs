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

use super::status::{
    Code, GrpcError, Status, percent_decode_grpc_message, percent_encode_grpc_message,
};
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
        block.push_str(&percent_encode_grpc_message(status.message()));
        block.push_str("\r\n");
    }

    let mut encoded_status_details = false;
    if let Some(details) = status.details() {
        if !details.is_empty() {
            use base64::Engine;
            block.push_str("grpc-status-details-bin: ");
            block.push_str(&base64::engine::general_purpose::STANDARD.encode(details));
            block.push_str("\r\n");
            encoded_status_details = true;
        }
    }

    for (key, value) in metadata.iter() {
        let Some(key_lower) =
            normalize_metadata_key(key, matches!(value, MetadataValue::Binary(_)))
        else {
            continue;
        };
        // Skip status/message — already encoded above.
        if key_lower == "grpc-status"
            || key_lower == "grpc-message"
            || (encoded_status_details && key_lower == "grpc-status-details-bin")
        {
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
            return Err(GrpcError::protocol(format!(
                "malformed nonempty trailer line without colon (length {})",
                line.len()
            )));
        };
        // Header names do not permit surrounding whitespace. Preserve the
        // exact key for validation instead of trimming an invalid name into a
        // valid one. Only HTTP optional whitespace (SP / HTAB) is removed from
        // the field-value edges; `str::trim` would also erase other Unicode
        // whitespace and could transmute malformed input.
        let key = key.to_ascii_lowercase();
        let value = value.trim_matches(|ch| matches!(ch, ' ' | '\t'));

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
                status_message = percent_decode_grpc_message(value)?;
            }
            _ => {
                // br-asupersync-ngnnc3: surface invalid metadata keys/values
                // and malformed base64 as GrpcError::protocol instead of
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
                        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
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
                        "invalid ASCII metadata key or value in trailer block \
                         (key length {}, value length {})",
                        key.len(),
                        value.len(),
                    )));
                }
            }
        }
    }

    // Per gRPC spec, trailers MUST include grpc-status. If absent, treat as
    // internal error rather than success — a missing status is a protocol violation.
    let code = Code::from_i32(status_code.unwrap_or(13)); // 13 = INTERNAL
    let message = if status_message.is_empty() {
        code.as_str().to_string()
    } else {
        status_message
    };
    let status = match metadata.get("grpc-status-details-bin") {
        Some(MetadataValue::Binary(details)) => {
            Status::with_details(code, message, details.clone())
        }
        _ => Status::new(code, message),
    };

    Ok(TrailerFrame { status, metadata })
}

// ── Web Frame Codec ──────────────────────────────────────────────────

/// Maximum gRPC-Web frame size (same as default gRPC max message size).
const DEFAULT_MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;
const WEB_FRAME_HEADER_SIZE: usize = 5;

fn checked_web_frame_size(payload_len: usize) -> Option<usize> {
    WEB_FRAME_HEADER_SIZE.checked_add(payload_len)
}

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

        if src.len() < WEB_FRAME_HEADER_SIZE {
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

        let Some(frame_size) = checked_web_frame_size(length) else {
            self.poison(format!(
                "gRPC-Web frame length {length} overflows the target address space"
            ));
            return Err(GrpcError::MessageTooLarge);
        };

        if src.len() < frame_size {
            return Ok(None);
        }

        // Consume the header.
        let _ = src.split_to(WEB_FRAME_HEADER_SIZE);
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
        if let Some(first_padding) = combined.iter().position(|byte| *byte == b'=') {
            if combined[first_padding..].iter().any(|byte| *byte != b'=') {
                return Err(GrpcError::protocol(
                    "invalid base64 in grpc-web-text final chunk: non-padding \
                     bytes after padding (br-asupersync-37svtb)",
                ));
            }

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
#[path = "web_inline_tests.rs"]
mod tests;

