//! Comprehensive HTTP/2 frame parsing fuzz target (RFC 9113 §6).
//!
//! This target fuzzes the actual HTTP/2 frame parser from src/http/h2/frame.rs
//! with coverage-guided testing of all 10 frame types and edge cases.
//!
//! # Frame Types Covered (RFC 9113 §6)
//! - DATA (0x0)           - Stream data transfer
//! - HEADERS (0x1)        - Header block fragments
//! - PRIORITY (0x2)       - Stream priority dependency
//! - RST_STREAM (0x3)     - Stream termination
//! - SETTINGS (0x4)       - Connection configuration
//! - PUSH_PROMISE (0x5)   - Server push announcement
//! - PING (0x6)           - Connection liveness
//! - GOAWAY (0x7)         - Graceful connection termination
//! - WINDOW_UPDATE (0x8)  - Flow control window management
//! - CONTINUATION (0x9)   - Header block continuation
//!
//! # Frame Header Invariants Tested
//! - 24-bit length field (0 to 16,777,215)
//! - 8-bit type field (0-9 known, 10-255 unknown/extension)
//! - 8-bit flags field (type-specific)
//! - 31-bit stream ID (bit 31 reserved, must be 0)
//!
//! # Edge Cases
//! - Padding validation (PADDED flag)
//! - Priority weight boundaries (1-256)
//! - Settings identifier validation
//! - Frame size limits (16KB default, 16MB max)
//! - Stream ID constraints (0 for connection, >0 for streams)
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run fuzz_http2_frame -- -runs=1000000
//! ```

#![no_main]

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::frame::{FRAME_HEADER_SIZE, FrameHeader, parse_frame};
use libfuzzer_sys::fuzz_target;

/// Frame generation strategies for structured fuzzing
#[derive(Debug, Clone, Copy)]
enum FuzzStrategy {
    /// Raw bytes - completely random frame data
    RawBytes,
    /// Valid header + random payload
    ValidHeaderRandomPayload,
    /// Valid frame with corrupted fields
    ValidFrameCorruption,
    /// Edge case frame sizes and stream IDs
    EdgeCases,
}

impl FuzzStrategy {
    fn from_byte(b: u8) -> Self {
        match b % 4 {
            0 => Self::RawBytes,
            1 => Self::ValidHeaderRandomPayload,
            2 => Self::ValidFrameCorruption,
            _ => Self::EdgeCases,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < FRAME_HEADER_SIZE + 1 {
        return; // Need at least header + strategy byte
    }

    let strategy = FuzzStrategy::from_byte(data[0]);
    let frame_data = &data[1..];

    match strategy {
        FuzzStrategy::RawBytes => fuzz_raw_bytes(frame_data),
        FuzzStrategy::ValidHeaderRandomPayload => fuzz_valid_header_random_payload(frame_data),
        FuzzStrategy::ValidFrameCorruption => fuzz_valid_frame_corruption(frame_data),
        FuzzStrategy::EdgeCases => fuzz_edge_cases(frame_data),
    }
});

/// Fuzz with completely random frame bytes
fn fuzz_raw_bytes(data: &[u8]) {
    if data.len() < FRAME_HEADER_SIZE {
        return;
    }

    // Try to parse frame header from raw bytes
    let mut buf = BytesMut::from(data);
    if let Ok(header) = FrameHeader::parse(&mut buf) {
        let remaining = buf.freeze();

        // Attempt to parse the frame - should handle all error conditions gracefully
        let _ = parse_frame(&header, remaining);
    }
}

/// Fuzz with structurally valid header but random payload
fn fuzz_valid_header_random_payload(data: &[u8]) {
    if data.len() < 6 {
        return; // Need type, flags, stream_id, length_bytes
    }

    let frame_type = data[0];
    let flags = data[1];
    let stream_id = u32::from_be_bytes([0, data[2], data[3], data[4]]) & 0x7FFF_FFFF; // 31-bit
    let payload = &data[5..];

    // Create header with payload length matching actual data
    let header = FrameHeader {
        length: payload.len() as u32,
        frame_type,
        flags,
        stream_id,
    };

    let _ = parse_frame(&header, Bytes::copy_from_slice(payload));
}

/// Fuzz by generating valid frames and then corrupting specific fields
fn fuzz_valid_frame_corruption(data: &[u8]) {
    if data.len() < 5 {
        return;
    }

    let frame_type = data[0] % 10; // Focus on known frame types
    let corruption_type = data[1] % 6;
    let payload_data = &data[2..];

    let (mut header, payload) = generate_valid_frame(frame_type, payload_data);

    // Apply corruption based on type
    match corruption_type {
        0 => header.length = header.length.wrapping_add(1), // Length mismatch
        1 => header.stream_id ^= 0x8000_0000,               // Toggle reserved bit
        2 => header.flags = !header.flags,                  // Flip all flags
        3 => header.length = 0xFFFF_FFFF,                   // Maximum length
        4 => header.stream_id = 0, // Force connection-level for stream frames
        _ => header.frame_type = 255, // Unknown frame type
    }

    let _ = parse_frame(&header, payload);
}

/// Fuzz edge cases like boundary values and special combinations
fn fuzz_edge_cases(data: &[u8]) {
    if data.len() < 3 {
        return;
    }

    let edge_case = data[0] % 12;
    let payload_data = &data[1..];

    let (header, payload) = match edge_case {
        // Frame size edge cases
        0 => edge_case_empty_frame(data[1] % 10),
        1 => edge_case_max_frame_size(payload_data),
        2 => edge_case_oversized_frame(payload_data),

        // Stream ID edge cases
        3 => edge_case_max_stream_id(data[1] % 10, payload_data),
        4 => edge_case_reserved_stream_id(data[1] % 10, payload_data),

        // Frame-specific edge cases
        5 => edge_case_settings_ack_with_data(payload_data),
        6 => edge_case_ping_wrong_size(payload_data),
        7 => edge_case_window_update_zero_increment(payload_data),
        8 => edge_case_data_excessive_padding(payload_data),
        9 => edge_case_headers_priority_corruption(payload_data),
        10 => edge_case_priority_self_dependency(payload_data),
        _ => edge_case_continuation_without_headers(payload_data),
    };

    let _ = parse_frame(&header, payload);
}

/// Generate a structurally valid frame for the given type
fn generate_valid_frame(frame_type: u8, payload_data: &[u8]) -> (FrameHeader, Bytes) {
    let (stream_id, flags, min_payload_size) = match frame_type {
        0 => (1, 0, 0), // DATA: must be on stream, no required payload
        1 => (1, 0, 0), // HEADERS: must be on stream, no required payload
        2 => (1, 0, 5), // PRIORITY: must be on stream, exactly 5 bytes
        3 => (1, 0, 4), // RST_STREAM: must be on stream, exactly 4 bytes
        4 => (0, 0, 0), // SETTINGS: must be connection-level, 6*N bytes
        5 => (1, 0, 4), // PUSH_PROMISE: must be on stream, at least 4 bytes
        6 => (0, 0, 8), // PING: must be connection-level, exactly 8 bytes
        7 => (0, 0, 8), // GOAWAY: must be connection-level, at least 8 bytes
        8 => (1, 0, 4), // WINDOW_UPDATE: can be connection/stream, exactly 4 bytes
        9 => (1, 0, 0), // CONTINUATION: must be on stream, no required payload
        _ => (1, 0, 0), // Unknown: default to stream-level
    };

    // Ensure minimum payload size
    let mut payload = payload_data.to_vec();
    if payload.len() < min_payload_size {
        payload.resize(min_payload_size, 0);
    }

    // Adjust for frame-specific constraints
    match frame_type {
        2 | 3 | 6 | 8 => {
            // PRIORITY, RST_STREAM, PING, WINDOW_UPDATE: exact sizes
            payload.truncate(min_payload_size);
        }
        4 => {
            // SETTINGS: must be multiple of 6 bytes
            let settings_count = (payload.len() / 6).max(0);
            payload.truncate(settings_count * 6);
        }
        _ => {}
    }

    let header = FrameHeader {
        length: payload.len() as u32,
        frame_type,
        flags,
        stream_id,
    };

    (header, Bytes::copy_from_slice(&payload))
}

// Edge case generators

fn edge_case_empty_frame(frame_type: u8) -> (FrameHeader, Bytes) {
    let stream_id = if frame_type == 4 || frame_type == 6 || frame_type == 7 {
        0
    } else {
        1
    };
    (
        FrameHeader {
            length: 0,
            frame_type,
            flags: 0,
            stream_id,
        },
        Bytes::new(),
    )
}

fn edge_case_max_frame_size(data: &[u8]) -> (FrameHeader, Bytes) {
    let max_size = 16_777_215u32; // 24-bit max
    let payload_size = data.len().min(max_size as usize);
    (
        FrameHeader {
            length: payload_size as u32,
            frame_type: 0, // DATA frame
            flags: 0,
            stream_id: 1,
        },
        Bytes::copy_from_slice(&data[..payload_size]),
    )
}

fn edge_case_oversized_frame(data: &[u8]) -> (FrameHeader, Bytes) {
    (
        FrameHeader {
            length: 16_777_216, // Exceeds 24-bit max by 1
            frame_type: 0,
            flags: 0,
            stream_id: 1,
        },
        Bytes::copy_from_slice(data),
    )
}

fn edge_case_max_stream_id(frame_type: u8, data: &[u8]) -> (FrameHeader, Bytes) {
    (
        FrameHeader {
            length: data.len() as u32,
            frame_type,
            flags: 0,
            stream_id: 0x7FFF_FFFF, // 31-bit max
        },
        Bytes::copy_from_slice(data),
    )
}

fn edge_case_reserved_stream_id(frame_type: u8, data: &[u8]) -> (FrameHeader, Bytes) {
    (
        FrameHeader {
            length: data.len() as u32,
            frame_type,
            flags: 0,
            stream_id: 0x8000_0001, // Reserved bit set
        },
        Bytes::copy_from_slice(data),
    )
}

fn edge_case_settings_ack_with_data(data: &[u8]) -> (FrameHeader, Bytes) {
    (
        FrameHeader {
            length: data.len() as u32,
            frame_type: 4, // SETTINGS
            flags: 0x01,   // ACK flag (should have no data)
            stream_id: 0,
        },
        Bytes::copy_from_slice(data),
    )
}

fn edge_case_ping_wrong_size(data: &[u8]) -> (FrameHeader, Bytes) {
    let wrong_size = if data.len() == 8 { 7 } else { data.len() };
    (
        FrameHeader {
            length: wrong_size as u32,
            frame_type: 6, // PING
            flags: 0,
            stream_id: 0,
        },
        Bytes::copy_from_slice(&data[..wrong_size.min(data.len())]),
    )
}

fn edge_case_window_update_zero_increment(_data: &[u8]) -> (FrameHeader, Bytes) {
    (
        FrameHeader {
            length: 4,
            frame_type: 8, // WINDOW_UPDATE
            flags: 0,
            stream_id: 1,
        },
        Bytes::from_static(&[0, 0, 0, 0]),
    ) // Zero increment (invalid)
}

fn edge_case_data_excessive_padding(data: &[u8]) -> (FrameHeader, Bytes) {
    let mut payload = vec![255u8]; // Padding length > payload size
    payload.extend_from_slice(data);
    (
        FrameHeader {
            length: payload.len() as u32,
            frame_type: 0, // DATA
            flags: 0x08,   // PADDED flag
            stream_id: 1,
        },
        Bytes::copy_from_slice(&payload),
    )
}

fn edge_case_headers_priority_corruption(data: &[u8]) -> (FrameHeader, Bytes) {
    let min_data = if data.len() < 5 {
        vec![0; 5]
    } else {
        data.to_vec()
    };

    (
        FrameHeader {
            length: min_data.len() as u32,
            frame_type: 1, // HEADERS
            flags: 0x20,   // PRIORITY flag (requires 5 bytes of priority data)
            stream_id: 1,
        },
        Bytes::copy_from_slice(&min_data),
    )
}

fn edge_case_priority_self_dependency(_data: &[u8]) -> (FrameHeader, Bytes) {
    let stream_id = 1u32;
    // Create priority frame where stream depends on itself (invalid)
    let payload = [
        (stream_id >> 24) as u8,
        (stream_id >> 16) as u8,
        (stream_id >> 8) as u8,
        stream_id as u8,
        255, // Weight 256 (weight is weight + 1)
    ];

    (
        FrameHeader {
            length: 5,
            frame_type: 2, // PRIORITY
            flags: 0,
            stream_id,
        },
        Bytes::copy_from_slice(&payload),
    )
}

fn edge_case_continuation_without_headers(data: &[u8]) -> (FrameHeader, Bytes) {
    (
        FrameHeader {
            length: data.len() as u32,
            frame_type: 9, // CONTINUATION (should only follow HEADERS)
            flags: 0x04,   // END_HEADERS flag
            stream_id: 1,
        },
        Bytes::copy_from_slice(data),
    )
}
