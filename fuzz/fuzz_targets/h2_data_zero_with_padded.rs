#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{FRAME_HEADER_SIZE, FrameHeader, FrameType, data_flags};
use asupersync::http::h2::{Frame, FrameCodec};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame type for DATA per RFC 7540 §6.1
const DATA_FRAME_TYPE: u8 = FrameType::Data as u8;

/// PADDED flag bit for DATA frames per RFC 7540 §6.1
const PADDED_FLAG: u8 = data_flags::PADDED;

/// END_STREAM flag bit for DATA frames per RFC 7540 §6.1
const END_STREAM_FLAG: u8 = data_flags::END_STREAM;

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

/// Live HTTP/2 DATA frame parser focused on zero-length + PADDED validation.
struct LiveH2DataParser {
    max_frame_size: u32,
}

impl LiveH2DataParser {
    fn with_max_frame_size(max_frame_size: u32) -> Self {
        Self { max_frame_size }
    }

    /// Parse DATA frame with strict RFC 7540 validation through the production H2 codec.
    ///
    /// Key rule being tested: RFC 7540 §6.1 states that if the PADDED flag is set,
    /// the Pad Length field is present as the first byte of the payload.
    /// For a zero-length payload with PADDED flag, this creates an impossible situation:
    /// - PADDED flag says "first byte is pad length"
    /// - Zero payload means there IS no first byte
    ///   This should result in PROTOCOL_ERROR per RFC 7540 §6.1
    fn parse_data_frame(&self, buf: &[u8]) -> DataFrameResult {
        let pad_length = if buf.get(4).is_some_and(|flags| flags & PADDED_FLAG != 0)
            && buf.len() > FRAME_HEADER_SIZE
        {
            Some(buf[FRAME_HEADER_SIZE])
        } else {
            None
        };

        let mut codec = FrameCodec::new();
        codec.set_max_frame_size(self.max_frame_size);
        let mut src = BytesMut::from(buf);

        match codec.decode(&mut src) {
            Ok(Some(Frame::Data(frame))) => DataFrameResult::Valid {
                stream_id: frame.stream_id,
                flags: buf[4],
                payload: frame.data.to_vec(),
                pad_length,
            },
            Ok(Some(other)) => DataFrameResult::ProtocolError(format!(
                "Expected DATA frame (0x0), decoded {other:?}"
            )),
            Ok(None) => DataFrameResult::IncompleteFrame,
            Err(err) => match err.code {
                ErrorCode::FrameSizeError => DataFrameResult::FrameSizeError,
                ErrorCode::ProtocolError if err.message == "DATA frame with stream ID 0" => {
                    DataFrameResult::InvalidStreamId
                }
                ErrorCode::ProtocolError => DataFrameResult::ProtocolError(err.message),
                code => DataFrameResult::ProtocolError(format!("{code}: {}", err.message)),
            },
        }
    }
}

fn is_exact_zero_length_padded_protocol_error(msg: &str) -> bool {
    msg == "PADDED DATA frame with no padding length"
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
    let stream_id = input.stream_id & 0x7FFF_FFFF;
    let stream_id = if stream_id == 0 { 1 } else { stream_id };

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
    let mut frame_bytes = BytesMut::new();
    header.write(&mut frame_bytes);

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
            frame_bytes.extend_from_slice(&[pad_length]);

            // Add data payload
            for _ in 1..payload_length {
                frame_bytes.extend_from_slice(&[0x42]); // Dummy data
            }
        } else {
            // Non-padded frame - just add data
            for _ in 0..payload_length {
                frame_bytes.extend_from_slice(&[0x42]); // Dummy data
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

    let expected_frame_len = FRAME_HEADER_SIZE + payload_length;
    let was_truncated = input
        .truncate_at
        .is_some_and(|truncate_at| truncate_at < expected_frame_len);

    // Create parser with specified max frame size
    let max_frame_size = input.max_frame_size.clamp(16384, 16777215); // RFC limits
    let parser = LiveH2DataParser::with_max_frame_size(max_frame_size);

    // Parse the frame
    let result = parser.parse_data_frame(&frame_bytes);

    // Validate behavior based on input characteristics
    match &result {
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

            assert_eq!(*parsed_stream_id, stream_id);
            assert_eq!(*parsed_flags, flags);

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
                    is_exact_zero_length_padded_protocol_error(msg),
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
            assert!(
                was_truncated,
                "Incomplete frame should only occur for actually truncated frames"
            );
        }

        DataFrameResult::InvalidStreamId => {
            // Should never happen with our stream ID logic
            panic!("Unexpected InvalidStreamId with stream_id: {}", stream_id);
        }
    }

    // CORE ASSERTION: Zero payload with PADDED flag must be a protocol error
    if input.set_padded_flag && payload_length == 0 && input.truncate_at.is_none() {
        match &result {
            DataFrameResult::ProtocolError(msg) => {
                // Expected - verify it's the right kind of protocol error
                assert!(
                    is_exact_zero_length_padded_protocol_error(msg),
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
            other => {
                panic!(
                    "zero-length PADDED DATA must reject with protocol error, got: {:?}",
                    other
                );
            }
        }
    }

    // Additional boundary testing: One-byte payload with PADDED must work
    // (pad length = 0, no actual padding).
    if input.set_padded_flag && payload_length == 1 && input.truncate_at.is_none() {
        match &result {
            DataFrameResult::Valid {
                pad_length: Some(0),
                payload,
                ..
            } => {
                assert!(
                    payload.is_empty(),
                    "one-byte PADDED DATA should expose empty application payload"
                );
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
            other => {
                panic!("one-byte PADDED DATA must parse as empty DATA, got: {other:?}");
            }
        }
    }
});
