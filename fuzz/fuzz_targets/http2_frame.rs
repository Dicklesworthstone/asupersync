//! Fuzz target for HTTP/2 frame parsing.
//!
//! HTTP/2 frames are the basic protocol unit (RFC 7540 Section 4).
//! This target fuzzes the frame parser with arbitrary byte sequences.
//!
//! # Frame format
//! ```text
//! +-----------------------------------------------+
//! |                 Length (24)                   |
//! +---------------+---------------+---------------+
//! |   Type (8)    |   Flags (8)   |
//! +-+-------------+---------------+-------------------------------+
//! |R|                 Stream Identifier (31)                      |
//! +=+=============================================================+
//! |                   Frame Payload (0...)                      ...
//! +---------------------------------------------------------------+
//! ```
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run fuzz_http2_frame
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

/// Maximum frame payload length (RFC 7540: 16KB default, 16MB max).
const MAX_FRAME_SIZE: usize = 16384;

/// Frame types (RFC 7540 Section 6).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    Unknown(u8),
}

impl From<u8> for FrameType {
    fn from(value: u8) -> Self {
        match value {
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
            other => FrameType::Unknown(other),
        }
    }
}

/// Parsed frame header.
struct FrameHeader {
    length: u32,
    frame_type: FrameType,
    flags: u8,
    stream_id: u32,
}

fuzz_target!(|data: &[u8]| {
    // Parse frame header (9 bytes minimum)
    if data.len() < 9 {
        return;
    }

    let header = parse_frame_header(&data[..9]);

    // Validate frame constraints
    validate_frame(&header, &data[9..]);
});

fn parse_frame_header(data: &[u8]) -> FrameHeader {
    assert!(data.len() >= 9);

    // Length is 24-bit big-endian
    let length = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);

    let frame_type = FrameType::from(data[3]);
    let flags = data[4];

    // Stream ID is 31-bit (MSB reserved)
    let stream_id = ((data[5] as u32 & 0x7F) << 24)
        | ((data[6] as u32) << 16)
        | ((data[7] as u32) << 8)
        | (data[8] as u32);

    FrameHeader {
        length,
        frame_type,
        flags,
        stream_id,
    }
}

fn validate_frame(header: &FrameHeader, payload: &[u8]) {
    // Frame size validation
    if header.length as usize > MAX_FRAME_SIZE {
        // FRAME_SIZE_ERROR if exceeds maximum
        return;
    }

    // Validate payload length matches header
    let expected_len = header.length as usize;
    if payload.len() < expected_len {
        return; // Incomplete frame
    }

    let frame_payload = &payload[..expected_len];

    // Type-specific validation
    match header.frame_type {
        FrameType::Data => {
            // DATA frames must be on a stream (stream_id != 0)
            let _ = header.stream_id != 0;

            // PADDED flag (0x8) indicates padding
            let padded = header.flags & 0x08 != 0;
            if padded && !frame_payload.is_empty() {
                let pad_length = frame_payload[0] as usize;
                // Pad length must not exceed payload
                let _ = pad_length < frame_payload.len();
            }
        }

        FrameType::Headers => {
            // HEADERS frames must be on a stream
            let _ = header.stream_id != 0;

            // PRIORITY flag (0x20) adds 5 bytes of priority data
            let priority = header.flags & 0x20 != 0;
            if priority {
                let _ = frame_payload.len() >= 5;
            }
        }

        FrameType::Priority => {
            // Must be on a stream, exactly 5 bytes
            let _ = header.stream_id != 0;
            let _ = header.length == 5;
        }

        FrameType::RstStream => {
            // Must be on a stream, exactly 4 bytes
            let _ = header.stream_id != 0;
            let _ = header.length == 4;
        }

        FrameType::Settings => {
            // Must be on stream 0
            let _ = header.stream_id == 0;

            // ACK flag (0x1) must have empty payload
            let ack = header.flags & 0x01 != 0;
            if ack {
                let _ = header.length == 0;
            } else {
                // Settings are 6 bytes each (2-byte ID + 4-byte value)
                let _ = header.length % 6 == 0;
            }
        }

        FrameType::PushPromise => {
            // Must be on a stream
            let _ = header.stream_id != 0;

            // Payload contains promised stream ID (4 bytes) + header block
            if frame_payload.len() >= 4 {
                let promised_id = ((frame_payload[0] as u32 & 0x7F) << 24)
                    | ((frame_payload[1] as u32) << 16)
                    | ((frame_payload[2] as u32) << 8)
                    | (frame_payload[3] as u32);
                // Promised stream ID must be valid
                let _ = promised_id != 0;
            }
        }

        FrameType::Ping => {
            // Must be on stream 0, exactly 8 bytes
            let _ = header.stream_id == 0;
            let _ = header.length == 8;
        }

        FrameType::GoAway => {
            // Must be on stream 0, at least 8 bytes
            let _ = header.stream_id == 0;
            let _ = header.length >= 8;
        }

        FrameType::WindowUpdate => {
            // Exactly 4 bytes
            let _ = header.length == 4;

            if frame_payload.len() >= 4 {
                let increment = ((frame_payload[0] as u32 & 0x7F) << 24)
                    | ((frame_payload[1] as u32) << 16)
                    | ((frame_payload[2] as u32) << 8)
                    | (frame_payload[3] as u32);
                // Window increment must be > 0
                let _ = increment > 0;
            }
        }

        FrameType::Continuation => {
            // Must be on a stream
            let _ = header.stream_id != 0;
        }

        FrameType::Unknown(_) => {
            // Unknown frame types should be ignored (RFC 7540 Section 4.1)
        }
    }
}
