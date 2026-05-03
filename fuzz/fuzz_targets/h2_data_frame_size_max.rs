#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// Default SETTINGS_MAX_FRAME_SIZE per RFC 7540 §6.5.2
const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384; // 2^14

/// Maximum allowed SETTINGS_MAX_FRAME_SIZE per RFC 7540 §6.5.2
const MAX_FRAME_SIZE_LIMIT: u32 = 16_777_215; // 2^24 - 1

/// HTTP/2 frame header length (9 bytes)
const FRAME_HEADER_LEN: usize = 9;

/// HTTP/2 frame types per RFC 7540 §6
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

/// HTTP/2 frame flags for DATA frames per RFC 7540 §6.1
#[derive(Debug, Clone, Copy)]
struct DataFlags {
    end_stream: bool,
    padded: bool,
}

impl DataFlags {
    fn to_byte(self) -> u8 {
        let mut flags = 0u8;
        if self.end_stream {
            flags |= 0x1;
        }
        if self.padded {
            flags |= 0x8;
        }
        flags
    }

    fn from_byte(byte: u8) -> Self {
        Self {
            end_stream: (byte & 0x1) != 0,
            padded: (byte & 0x8) != 0,
        }
    }
}

/// HTTP/2 frame header per RFC 7540 §4.1
#[derive(Debug, Clone)]
struct FrameHeader {
    length: u32,
    frame_type: FrameType,
    flags: u8,
    stream_id: u32,
}

impl FrameHeader {
    fn encode(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];

        // Length (24 bits, big-endian)
        buf[0] = (self.length >> 16) as u8;
        buf[1] = (self.length >> 8) as u8;
        buf[2] = self.length as u8;

        // Frame type (8 bits)
        buf[3] = self.frame_type as u8;

        // Flags (8 bits)
        buf[4] = self.flags;

        // Stream ID (31 bits, reserved bit 0, big-endian)
        let stream_id = self.stream_id & 0x7FFF_FFFF; // Clear reserved bit
        buf[5] = (stream_id >> 24) as u8;
        buf[6] = (stream_id >> 16) as u8;
        buf[7] = (stream_id >> 8) as u8;
        buf[8] = stream_id as u8;

        buf
    }

    fn decode(buf: &[u8]) -> Result<Self, FrameError> {
        if buf.len() < 9 {
            return Err(FrameError::IncompleteHeader);
        }

        // Length (24 bits)
        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);

        // Frame type
        let frame_type = match buf[3] {
            0x0 => FrameType::Data,
            0x1 => FrameType::Headers,
            0x2 => FrameType::Priority,
            0x3 => FrameType::RstStream,
            0x4 => FrameType::Settings,
            0x5 => FrameType::PushPromise,
            0x6 => FrameType::Ping,
            0x7 => FrameType::GoAway,
            0x8 => FrameType::WindowUpdate,
            0x9 => FrameType::Continuation,
            unknown => return Err(FrameError::UnknownFrameType(unknown)),
        };

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

/// DATA frame per RFC 7540 §6.1
#[derive(Debug, Clone)]
struct DataFrame {
    header: FrameHeader,
    pad_length: Option<u8>,
    data: Vec<u8>,
}

impl DataFrame {
    fn new(stream_id: u32, data: Vec<u8>, flags: DataFlags) -> Result<Self, FrameError> {
        let mut length = data.len() as u32;
        let pad_length = if flags.padded {
            // Add 1 byte for pad length field
            length += 1;
            Some(0) // No actual padding for simplicity
        } else {
            None
        };

        let header = FrameHeader {
            length,
            frame_type: FrameType::Data,
            flags: flags.to_byte(),
            stream_id,
        };

        Ok(DataFrame {
            header,
            pad_length,
            data,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + self.header.length as usize);

        // Frame header
        buf.extend_from_slice(&self.header.encode());

        // Pad length (if padded flag set)
        if let Some(pad_len) = self.pad_length {
            buf.push(pad_len);
        }

        // Data payload
        buf.extend_from_slice(&self.data);

        buf
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FrameError {
    IncompleteHeader,
    IncompleteFrame,
    UnknownFrameType(u8),
    FrameSizeError,
    InvalidStreamId,
    InvalidPadding,
}

/// Mock HTTP/2 frame parser for testing boundary conditions
struct MockH2FrameParser {
    max_frame_size: u32,
}

impl MockH2FrameParser {
    fn new() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }

    fn with_max_frame_size(max_frame_size: u32) -> Result<Self, FrameError> {
        if max_frame_size > MAX_FRAME_SIZE_LIMIT {
            return Err(FrameError::FrameSizeError);
        }

        Ok(Self { max_frame_size })
    }

    /// Parse HTTP/2 frame with strict size validation
    fn parse_frame(&self, buf: &[u8]) -> Result<DataFrame, FrameError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(FrameError::IncompleteHeader);
        }

        let header = FrameHeader::decode(&buf[..FRAME_HEADER_LEN])?;

        // Critical: Frame size validation (RFC 7540 §4.2)
        if header.length > self.max_frame_size {
            return Err(FrameError::FrameSizeError);
        }

        // Check we have complete frame
        let total_len = FRAME_HEADER_LEN + header.length as usize;
        if buf.len() < total_len {
            return Err(FrameError::IncompleteFrame);
        }

        // Only parse DATA frames for this test
        if header.frame_type != FrameType::Data {
            return Err(FrameError::UnknownFrameType(header.frame_type as u8));
        }

        // DATA frames must be on non-zero stream (RFC 7540 §6.1)
        if header.stream_id == 0 {
            return Err(FrameError::InvalidStreamId);
        }

        let payload = &buf[FRAME_HEADER_LEN..total_len];
        let flags = DataFlags::from_byte(header.flags);

        let (pad_length, data_start) = if flags.padded {
            if payload.is_empty() {
                return Err(FrameError::InvalidPadding);
            }
            let pad_len = payload[0];

            // Pad length must not exceed payload length - 1
            if pad_len as usize >= payload.len() {
                return Err(FrameError::InvalidPadding);
            }

            (Some(pad_len), 1)
        } else {
            (None, 0)
        };

        let data_end = if let Some(pad_len) = pad_length {
            payload.len().saturating_sub(pad_len as usize)
        } else {
            payload.len()
        };

        let data = if data_start <= data_end {
            payload[data_start..data_end].to_vec()
        } else {
            Vec::new()
        };

        Ok(DataFrame {
            header,
            pad_length,
            data,
        })
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// SETTINGS_MAX_FRAME_SIZE to use (will be clamped to valid range)
    max_frame_size_setting: u32,
    /// Target frame size relative to max frame size
    size_variant: SizeVariant,
    /// Stream ID for the DATA frame
    stream_id: u32,
    /// Whether to set PADDED flag
    padded: bool,
    /// Whether to set END_STREAM flag
    end_stream: bool,
    /// Extra data to append after frame (for incomplete frame testing)
    extra_data: Vec<u8>,
    /// Whether to corrupt the frame header length field
    corrupt_length: bool,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum SizeVariant {
    /// Exactly at the limit
    AtLimit,
    /// One byte under the limit (SETTINGS_MAX_FRAME_SIZE - 1)
    OneBelowLimit,
    /// One byte over the limit (should fail)
    OneOverLimit,
    /// Exactly at RFC default (16384)
    AtDefault,
    /// Zero size frame
    Zero,
    /// Random size up to 2^24-1
    Random(u32),
}

fuzz_target!(|input: FuzzInput| {
    // Clamp max_frame_size to valid range per RFC 7540 §6.5.2
    let max_frame_size = input
        .max_frame_size_setting
        .clamp(DEFAULT_MAX_FRAME_SIZE, MAX_FRAME_SIZE_LIMIT);

    let parser = match MockH2FrameParser::with_max_frame_size(max_frame_size) {
        Ok(p) => p,
        Err(_) => return, // Invalid max frame size
    };

    // Calculate target frame size based on variant
    let target_size = match input.size_variant {
        SizeVariant::AtLimit => max_frame_size,
        SizeVariant::OneBelowLimit => max_frame_size.saturating_sub(1),
        SizeVariant::OneOverLimit => max_frame_size.saturating_add(1),
        SizeVariant::AtDefault => DEFAULT_MAX_FRAME_SIZE,
        SizeVariant::Zero => 0,
        SizeVariant::Random(size) => size & 0x00FF_FFFF, // Clamp to 24-bit max
    };

    // Create DATA payload of target size
    let data_payload = vec![0x42u8; target_size as usize];

    // Ensure stream ID is non-zero (required for DATA frames)
    let stream_id = if input.stream_id == 0 {
        1
    } else {
        input.stream_id & 0x7FFF_FFFF
    };

    let flags = DataFlags {
        end_stream: input.end_stream,
        padded: input.padded,
    };

    // Create DATA frame
    let frame = match DataFrame::new(stream_id, data_payload, flags) {
        Ok(f) => f,
        Err(_) => return, // Frame creation failed
    };

    let mut encoded = frame.encode();

    // Optionally corrupt the length field to test parser robustness
    if input.corrupt_length && encoded.len() >= 3 {
        encoded[0] = 0xFF; // Set length to massive value
        encoded[1] = 0xFF;
        encoded[2] = 0xFF;
    }

    // Append extra data for incomplete frame testing
    encoded.extend_from_slice(&input.extra_data);

    // Parse the frame and verify behavior
    let parse_result = parser.parse_frame(&encoded);

    // Assertions about expected behavior
    match parse_result {
        Ok(parsed_frame) => {
            // Frame should only parse successfully if:
            // 1. Size <= max_frame_size
            // 2. Not corrupted
            // 3. Complete frame present

            assert!(
                target_size <= max_frame_size,
                "Oversized frame should not parse successfully"
            );
            assert!(
                !input.corrupt_length,
                "Corrupted length should not parse successfully"
            );

            // Verify parsed frame matches expectations
            assert_eq!(parsed_frame.header.frame_type, FrameType::Data);
            assert_eq!(parsed_frame.header.stream_id, stream_id);

            let parsed_flags = DataFlags::from_byte(parsed_frame.header.flags);
            assert_eq!(parsed_flags.end_stream, flags.end_stream);
            assert_eq!(parsed_flags.padded, flags.padded);

            // Check that length field matches actual payload length
            let expected_length = if flags.padded {
                parsed_frame.data.len() + 1 // +1 for pad_length field
            } else {
                parsed_frame.data.len()
            };
            assert_eq!(parsed_frame.header.length as usize, expected_length);
        }

        Err(FrameError::FrameSizeError) => {
            // Should only get this error for oversized frames
            assert!(
                target_size > max_frame_size || input.corrupt_length,
                "Frame size error should only occur for oversized frames"
            );
        }

        Err(FrameError::IncompleteFrame) => {
            // Expected when frame is truncated or corrupted
        }

        Err(FrameError::IncompleteHeader) => {
            // Expected when not enough bytes for header
        }

        Err(FrameError::InvalidStreamId) => {
            // Should not happen with our stream ID logic
            panic!(
                "Unexpected InvalidStreamId error with stream_id: {}",
                stream_id
            );
        }

        Err(FrameError::InvalidPadding) => {
            // Can occur with invalid padding setup
        }

        Err(FrameError::UnknownFrameType(_)) => {
            // Should not happen since we only create DATA frames
            panic!("Unexpected UnknownFrameType error");
        }
    }

    // Additional boundary testing for off-by-one errors
    if target_size == max_frame_size.saturating_sub(1) {
        // This exact case (max_frame_size - 1) should always parse successfully
        // if the frame is complete and not corrupted
        if !input.corrupt_length && encoded.len() >= FRAME_HEADER_LEN + target_size as usize {
            match parse_result {
                Ok(_) => {
                    // Expected - frame at limit-1 should parse
                }
                Err(e) => {
                    // Only acceptable errors are padding-related or incomplete frame
                    assert!(
                        matches!(e, FrameError::InvalidPadding | FrameError::IncompleteFrame),
                        "Frame at max_frame_size-1 failed unexpectedly: {:?}",
                        e
                    );
                }
            }
        }
    }

    // Test that frames exactly at limit parse (if not corrupted)
    if target_size == max_frame_size && !input.corrupt_length {
        // Should parse successfully unless padding is invalid
        if let Err(e) = parse_result {
            assert!(
                matches!(e, FrameError::InvalidPadding | FrameError::IncompleteFrame),
                "Frame at exact max_frame_size limit failed unexpectedly: {:?}",
                e
            );
        }
    }

    // Test that frames over limit definitely fail (unless incomplete prevents reaching size check)
    if target_size > max_frame_size && !input.corrupt_length {
        // Should get FrameSizeError unless frame is incomplete
        if encoded.len() >= FRAME_HEADER_LEN {
            match parse_result {
                Err(FrameError::FrameSizeError) => {
                    // Expected
                }
                Err(FrameError::IncompleteFrame) => {
                    // Also acceptable - incomplete frame detected first
                }
                Ok(_) => {
                    panic!("Oversized frame should never parse successfully");
                }
                Err(e) => {
                    panic!("Unexpected error for oversized frame: {:?}", e);
                }
            }
        }
    }
});
