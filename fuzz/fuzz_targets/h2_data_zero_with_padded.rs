#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame header length (9 bytes) per RFC 7540 §4.1
const FRAME_HEADER_LEN: usize = 9;

/// HTTP/2 frame type for DATA per RFC 7540 §6.1
const DATA_FRAME_TYPE: u8 = 0x0;

/// PADDED flag bit for DATA frames per RFC 7540 §6.1
const PADDED_FLAG: u8 = 0x8;

/// END_STREAM flag bit for DATA frames per RFC 7540 §6.1
const END_STREAM_FLAG: u8 = 0x1;

/// HTTP/2 error codes per RFC 7540 §7
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum Http2ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

/// Parse result for HTTP/2 DATA frames
#[derive(Debug, PartialEq)]
enum DataFrameResult {
    /// Successfully parsed DATA frame
    Valid {
        stream_id: u32,
        flags: u8,
        payload: Vec<u8>,
        pad_length: Option<u8>,
    },
    /// Protocol error - specific violation
    ProtocolError(String),
    /// Frame size error
    FrameSizeError,
    /// Incomplete frame data
    IncompleteFrame,
    /// Invalid stream ID (0 for DATA frame)
    InvalidStreamId,
}

/// HTTP/2 frame header per RFC 7540 §4.1
#[derive(Debug, Clone)]
struct FrameHeader {
    length: u32,    // 24-bit length
    frame_type: u8, // 8-bit type
    flags: u8,      // 8-bit flags
    stream_id: u32, // 31-bit stream ID (R bit ignored)
}

impl FrameHeader {
    /// Encode frame header as 9-byte sequence
    fn encode(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];

        // Length (24 bits, big-endian)
        buf[0] = (self.length >> 16) as u8;
        buf[1] = (self.length >> 8) as u8;
        buf[2] = self.length as u8;

        // Type (8 bits)
        buf[3] = self.frame_type;

        // Flags (8 bits)
        buf[4] = self.flags;

        // Stream ID (31 bits + reserved bit, big-endian)
        let stream_id = self.stream_id & 0x7FFF_FFFF; // Clear reserved bit
        buf[5] = (stream_id >> 24) as u8;
        buf[6] = (stream_id >> 16) as u8;
        buf[7] = (stream_id >> 8) as u8;
        buf[8] = stream_id as u8;

        buf
    }

    /// Decode frame header from bytes
    fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 9 {
            return Err("incomplete header");
        }

        // Length (24 bits)
        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);

        let frame_type = buf[3];
        let flags = buf[4];

        // Stream ID (31 bits, ignore reserved bit)
        let stream_id = ((buf[5] as u32 & 0x7F) << 24)
            | ((buf[6] as u32) << 16)
            | ((buf[7] as u32) << 8)
            | (buf[8] as u32);

        Ok(FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }
}

/// Mock HTTP/2 DATA frame parser focused on zero-length + PADDED validation
struct MockH2DataParser {
    max_frame_size: u32,
}

impl MockH2DataParser {
    fn new() -> Self {
        Self {
            max_frame_size: 16384, // Default per RFC 7540
        }
    }

    fn with_max_frame_size(max_frame_size: u32) -> Self {
        Self { max_frame_size }
    }

    /// Parse DATA frame with strict RFC 7540 validation
    ///
    /// Key rule being tested: RFC 7540 §6.1 states that if the PADDED flag is set,
    /// the Pad Length field is present as the first byte of the payload.
    /// For a zero-length payload with PADDED flag, this creates an impossible situation:
    /// - PADDED flag says "first byte is pad length"
    /// - Zero payload means there IS no first byte
    /// This should result in PROTOCOL_ERROR per RFC 7540 §6.1
    fn parse_data_frame(&self, buf: &[u8]) -> DataFrameResult {
        // Parse frame header
        let header = match FrameHeader::decode(buf) {
            Ok(h) => h,
            Err(_) => return DataFrameResult::IncompleteFrame,
        };

        // Must be DATA frame type
        if header.frame_type != DATA_FRAME_TYPE {
            return DataFrameResult::ProtocolError(format!(
                "Expected DATA frame (0x0), got 0x{:x}",
                header.frame_type
            ));
        }

        // DATA frames must have non-zero stream ID per RFC 7540 §6.1
        if header.stream_id == 0 {
            return DataFrameResult::InvalidStreamId;
        }

        // Check frame size against max setting
        if header.length > self.max_frame_size {
            return DataFrameResult::FrameSizeError;
        }

        // Check complete frame is present
        let total_len = FRAME_HEADER_LEN + header.length as usize;
        if buf.len() < total_len {
            return DataFrameResult::IncompleteFrame;
        }

        let payload = &buf[FRAME_HEADER_LEN..total_len];
        let padded_flag_set = (header.flags & PADDED_FLAG) != 0;

        // CRITICAL RFC 7540 §6.1 VALIDATION:
        // "If the PADDED flag is set, the Pad Length field is present as the first byte of the payload"
        // But for zero-length payload, there IS no first byte!
        if padded_flag_set && header.length == 0 {
            return DataFrameResult::ProtocolError(
                "PADDED flag set but payload length is 0 - no room for Pad Length field (RFC 7540 §6.1)".to_string()
            );
        }

        // Extract padding information if PADDED flag is set
        let (pad_length, data_start) = if padded_flag_set {
            if payload.is_empty() {
                // This case should have been caught above, but double-check
                return DataFrameResult::ProtocolError(
                    "PADDED flag set but no payload for Pad Length field".to_string(),
                );
            }

            let pad_len = payload[0];

            // RFC 7540 §6.1: Pad Length must not exceed the remaining payload length
            if pad_len as usize >= payload.len() {
                return DataFrameResult::ProtocolError(format!(
                    "Pad Length {} exceeds remaining payload length {}",
                    pad_len,
                    payload.len() - 1
                ));
            }

            (Some(pad_len), 1)
        } else {
            (None, 0)
        };

        // Extract actual data (payload minus padding)
        let data_end = if let Some(pad_len) = pad_length {
            payload.len().saturating_sub(pad_len as usize)
        } else {
            payload.len()
        };

        let data = if data_start <= data_end {
            payload[data_start..data_end].to_vec()
        } else {
            // This can happen with invalid padding
            return DataFrameResult::ProtocolError(
                "Invalid padding configuration - data start exceeds data end".to_string(),
            );
        };

        DataFrameResult::Valid {
            stream_id: header.stream_id,
            flags: header.flags,
            payload: data,
            pad_length,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Stream ID for DATA frame (will be forced non-zero)
    stream_id: u32,
    /// Whether to set PADDED flag (the key test case)
    set_padded_flag: bool,
    /// Whether to set END_STREAM flag
    set_end_stream_flag: bool,
    /// Actual payload length (key: testing zero length with PADDED)
    payload_length: PayloadLengthVariant,
    /// Max frame size setting for parser
    max_frame_size: u32,
    /// Whether to add extra bytes after frame
    extra_bytes: Vec<u8>,
    /// Whether to truncate the frame
    truncate_at: Option<usize>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum PayloadLengthVariant {
    /// Zero length payload (critical test case with PADDED flag)
    Zero,
    /// One byte payload (minimum for PADDED to be valid)
    One,
    /// Two byte payload (pad length + minimal data)
    Two,
    /// Small payload
    Small(u8),
    /// Random payload up to 1024 bytes
    Random(u16),
}

impl PayloadLengthVariant {
    fn to_length(self) -> usize {
        match self {
            PayloadLengthVariant::Zero => 0,
            PayloadLengthVariant::One => 1,
            PayloadLengthVariant::Two => 2,
            PayloadLengthVariant::Small(n) => n as usize,
            PayloadLengthVariant::Random(n) => (n as usize).min(1024),
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    // Ensure stream ID is non-zero (required for DATA frames)
    let stream_id = if input.stream_id == 0 {
        1
    } else {
        input.stream_id & 0x7FFF_FFFF
    };

    // Create frame flags
    let mut flags = 0u8;
    if input.set_end_stream_flag {
        flags |= END_STREAM_FLAG;
    }
    if input.set_padded_flag {
        flags |= PADDED_FLAG;
    }

    // Determine payload length
    let payload_length = input.payload_length.to_length();

    // Create frame header
    let header = FrameHeader {
        length: payload_length as u32,
        frame_type: DATA_FRAME_TYPE,
        flags,
        stream_id,
    };

    // Build complete frame
    let mut frame_bytes = Vec::new();
    frame_bytes.extend_from_slice(&header.encode());

    // Add payload (if any)
    if payload_length > 0 {
        // For PADDED frames, first byte is pad length
        if input.set_padded_flag {
            let pad_length = if payload_length == 1 {
                0 // No room for actual padding
            } else {
                // Use some padding but leave room for at least some data
                ((payload_length - 1) / 2).min(255) as u8
            };
            frame_bytes.push(pad_length);

            // Add data payload
            for _ in 1..payload_length {
                frame_bytes.push(0x42); // Dummy data
            }
        } else {
            // Non-padded frame - just add data
            for _ in 0..payload_length {
                frame_bytes.push(0x42); // Dummy data
            }
        }
    }

    // Optionally truncate frame to test incomplete frames
    if let Some(truncate_at) = input.truncate_at {
        let truncate_point = truncate_at.min(frame_bytes.len());
        frame_bytes.truncate(truncate_point);
    }

    // Add extra bytes for testing
    frame_bytes.extend_from_slice(&input.extra_bytes);

    // Create parser with specified max frame size
    let max_frame_size = input.max_frame_size.clamp(16384, 16777215); // RFC limits
    let parser = MockH2DataParser::with_max_frame_size(max_frame_size);

    // Parse the frame
    let result = parser.parse_data_frame(&frame_bytes);

    // Validate behavior based on input characteristics
    match result {
        DataFrameResult::Valid {
            stream_id: parsed_stream_id,
            flags: parsed_flags,
            payload: _,
            pad_length,
        } => {
            // Frame parsed successfully - verify this is expected

            // Should only be valid if:
            // 1. Not truncated
            // 2. Payload length fits in max frame size
            // 3. If PADDED flag set, payload length > 0

            assert_eq!(parsed_stream_id, stream_id);
            assert_eq!(parsed_flags, flags);

            if input.set_padded_flag {
                // PADDED flag set - this should only succeed if payload_length > 0
                assert!(
                    payload_length > 0,
                    "PADDED flag with zero payload should not parse successfully"
                );
                assert!(pad_length.is_some(), "PADDED frame should have pad_length");
            }
        }

        DataFrameResult::ProtocolError(msg) => {
            // Expected protocol error cases:
            // 1. Zero payload length with PADDED flag set
            // 2. Invalid padding configuration

            if input.set_padded_flag && payload_length == 0 {
                // This is the EXACT case we're testing - should always be a protocol error
                assert!(
                    msg.contains("PADDED flag set but payload length is 0")
                        || msg.contains("no room for Pad Length field"),
                    "Expected specific protocol error for zero-length PADDED frame, got: {}",
                    msg
                );
            }
        }

        DataFrameResult::FrameSizeError => {
            // Should only occur if payload length exceeds max frame size
            assert!(
                payload_length as u32 > max_frame_size,
                "Frame size error should only occur for oversized frames"
            );
        }

        DataFrameResult::IncompleteFrame => {
            // Expected for truncated frames or frames with insufficient data
            if let Some(truncate_at) = input.truncate_at {
                assert!(
                    truncate_at < FRAME_HEADER_LEN + payload_length,
                    "Incomplete frame should only occur for actually truncated frames"
                );
            }
        }

        DataFrameResult::InvalidStreamId => {
            // Should never happen with our stream ID logic
            panic!("Unexpected InvalidStreamId with stream_id: {}", stream_id);
        }
    }

    // CORE ASSERTION: Zero payload with PADDED flag must be a protocol error
    if input.set_padded_flag && payload_length == 0 && input.truncate_at.is_none() {
        match result {
            DataFrameResult::ProtocolError(ref msg) => {
                // Expected - verify it's the right kind of protocol error
                assert!(
                    msg.contains("PADDED flag set but payload length is 0")
                        || msg.contains("no room for Pad Length field"),
                    "Wrong protocol error message for zero-length PADDED: {}",
                    msg
                );
            }
            DataFrameResult::Valid { .. } => {
                panic!(
                    "CRITICAL RFC VIOLATION: Zero-length payload with PADDED flag parsed as valid! \
                     This violates RFC 7540 §6.1 - PADDED flag requires Pad Length field as first byte, \
                     but zero-length payload has no bytes."
                );
            }
            _ => {
                // Other errors (frame size, incomplete, etc.) are acceptable as long as
                // it doesn't parse as valid
            }
        }
    }

    // Additional boundary testing: One-byte payload with PADDED should work
    // (pad length = 0, no actual padding)
    if input.set_padded_flag && payload_length == 1 && input.truncate_at.is_none() {
        match result {
            DataFrameResult::Valid {
                pad_length: Some(0),
                ..
            } => {
                // Expected: one byte payload allows pad_length=0
            }
            DataFrameResult::Valid {
                pad_length: Some(n),
                ..
            } => {
                panic!(
                    "One-byte PADDED payload should have pad_length=0, got {}",
                    n
                );
            }
            DataFrameResult::Valid {
                pad_length: None, ..
            } => {
                panic!("PADDED frame should have pad_length field");
            }
            // Errors are acceptable (parser may be strict about minimum sizes)
            _ => {}
        }
    }
});
