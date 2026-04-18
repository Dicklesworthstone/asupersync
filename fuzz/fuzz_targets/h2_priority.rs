//! HTTP/2 PRIORITY frame fuzzing target (RFC 9113 §6.3)
//!
//! Focuses specifically on PRIORITY frame dependency tree parsing and validation.
//! Tests edge cases like self-dependencies, cycles, weight boundaries, and payload corruption.
//!
//! # PRIORITY Frame Structure (RFC 9113 §6.3)
//! - Exclusive (E): 1 bit
//! - Stream Dependency: 31 bits
//! - Weight: 8 bits (1-256, encoded as 0-255)
//!
//! # Critical Edge Cases
//! - Self-dependencies (stream depends on itself)
//! - Circular dependencies (A->B->A cycles)
//! - Weight boundaries (0, 255, overflow)
//! - Stream ID limits (0, MAX_STREAM_ID)
//! - Malformed payload sizes

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::BytesMut;
use asupersync::http::h2::frame::{FrameHeader, parse_frame};

#[derive(Debug, Clone, Arbitrary)]
struct FuzzPriorityFrame {
    stream_id: u32,
    dependency: u32,
    weight: u8,
    exclusive: bool,
}

impl FuzzPriorityFrame {
    fn create_priority_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(5);

        // PRIORITY payload: [E + Stream Dependency: 32 bits] [Weight: 8 bits]
        let dep_with_exclusive = if self.exclusive {
            self.dependency | 0x8000_0000
        } else {
            self.dependency & 0x7FFF_FFFF
        };
        payload.extend_from_slice(&dep_with_exclusive.to_be_bytes());
        payload.push(self.weight);

        payload
    }

    fn to_frame_bytes(&self) -> Vec<u8> {
        let payload = self.create_priority_payload();
        let mut frame_bytes = Vec::with_capacity(9 + payload.len());

        // Frame header: length(3) + type(1) + flags(1) + stream_id(4)
        let length = payload.len() as u32;
        frame_bytes.extend_from_slice(&length.to_be_bytes()[1..4]); // 24-bit length
        frame_bytes.push(2); // PRIORITY frame type
        frame_bytes.push(0); // No flags for PRIORITY
        frame_bytes.extend_from_slice(&(self.stream_id & 0x7FFF_FFFF).to_be_bytes());
        frame_bytes.extend_from_slice(&payload);

        frame_bytes
    }
}

#[derive(Debug, Clone, Arbitrary)]
enum PriorityFuzzCase {
    /// Test raw bytes that might contain PRIORITY frames
    RawBytes(Vec<u8>),
    /// Test well-formed PRIORITY frame with various edge cases
    StructuredFrame(FuzzPriorityFrame),
    /// Test malformed PRIORITY frame with wrong payload size
    MalformedPayload {
        stream_id: u32,
        payload: Vec<u8>,
    },
    /// Test boundary conditions and edge cases
    EdgeCases {
        case_type: u8,
    },
    /// Test multiple PRIORITY frames in sequence
    FrameSequence(Vec<FuzzPriorityFrame>),
}

fuzz_target!(|data: &[u8]| {
    // Prevent excessive memory usage and timeouts
    if data.len() > 100_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(case) = PriorityFuzzCase::arbitrary(&mut unstructured) else { return };

    match case {
        PriorityFuzzCase::RawBytes(bytes) => {
            fuzz_raw_priority_bytes(&bytes);
        },

        PriorityFuzzCase::StructuredFrame(frame) => {
            fuzz_structured_priority_frame(&frame);
        },

        PriorityFuzzCase::MalformedPayload { stream_id, payload } => {
            fuzz_malformed_priority_payload(stream_id, &payload);
        },

        PriorityFuzzCase::EdgeCases { case_type } => {
            fuzz_priority_edge_cases(case_type);
        },

        PriorityFuzzCase::FrameSequence(frames) => {
            if frames.len() > 50 {
                return; // Limit sequence length
            }
            fuzz_priority_frame_sequence(&frames);
        },
    }
});

fn fuzz_raw_priority_bytes(data: &[u8]) {
    if data.len() < 9 {
        return; // Need at least frame header
    }

    // Try to parse as frame header + potential PRIORITY payload
    let mut buf = BytesMut::from(data);
    if let Ok(header) = FrameHeader::parse(&mut buf) {
        let remaining = buf.freeze();

        // Only parse if it looks like a PRIORITY frame (type 2)
        if header.frame_type == 2 {
            let _ = parse_frame(&header, remaining);
        }
    }
}

fn fuzz_structured_priority_frame(frame: &FuzzPriorityFrame) {
    let frame_bytes = frame.to_frame_bytes();
    let mut buf = BytesMut::from(&frame_bytes[..]);

    if let Ok(header) = FrameHeader::parse(&mut buf) {
        let remaining = buf.freeze();
        let _ = parse_frame(&header, remaining);
    }
}

fn fuzz_malformed_priority_payload(stream_id: u32, payload: &[u8]) {
    if payload.len() > 1_000 {
        return;
    }

    // Create PRIORITY frame with wrong payload size
    let mut frame_bytes = Vec::with_capacity(9 + payload.len());

    // Frame header with actual payload length (might not be 5)
    let length = payload.len() as u32;
    frame_bytes.extend_from_slice(&length.to_be_bytes()[1..4]); // 24-bit length
    frame_bytes.push(2); // PRIORITY frame type
    frame_bytes.push(0); // No flags
    frame_bytes.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());
    frame_bytes.extend_from_slice(payload);

    let mut buf = BytesMut::from(&frame_bytes[..]);
    if let Ok(header) = FrameHeader::parse(&mut buf) {
        let remaining = buf.freeze();
        let _ = parse_frame(&header, remaining);
    }
}

fn fuzz_priority_edge_cases(case_type: u8) {
    match case_type % 8 {
        0 => {
            // Self-dependency: stream depends on itself
            let stream_id = 1u32;
            let frame = FuzzPriorityFrame {
                stream_id,
                dependency: stream_id,
                weight: 128,
                exclusive: false,
            };
            fuzz_structured_priority_frame(&frame);
        },

        1 => {
            // Maximum stream ID
            let frame = FuzzPriorityFrame {
                stream_id: 0x7FFF_FFFF,
                dependency: 1,
                weight: 255,
                exclusive: true,
            };
            fuzz_structured_priority_frame(&frame);
        },

        2 => {
            // Zero weight (should be treated as 1)
            let frame = FuzzPriorityFrame {
                stream_id: 1,
                dependency: 0,
                weight: 0,
                exclusive: false,
            };
            fuzz_structured_priority_frame(&frame);
        },

        3 => {
            // Dependency on stream 0 (connection level, invalid)
            let frame = FuzzPriorityFrame {
                stream_id: 1,
                dependency: 0,
                weight: 16,
                exclusive: true,
            };
            fuzz_structured_priority_frame(&frame);
        },

        4 => {
            // PRIORITY frame on stream 0 (invalid)
            let frame = FuzzPriorityFrame {
                stream_id: 0,
                dependency: 1,
                weight: 64,
                exclusive: false,
            };
            fuzz_structured_priority_frame(&frame);
        },

        5 => {
            // Maximum weight
            let frame = FuzzPriorityFrame {
                stream_id: 3,
                dependency: 1,
                weight: 255,
                exclusive: true,
            };
            fuzz_structured_priority_frame(&frame);
        },

        6 => {
            // Create potential cycle: A depends on B, then test B depends on A
            let frame_a = FuzzPriorityFrame {
                stream_id: 1,
                dependency: 3,
                weight: 100,
                exclusive: false,
            };
            let frame_b = FuzzPriorityFrame {
                stream_id: 3,
                dependency: 1,
                weight: 200,
                exclusive: true,
            };
            fuzz_structured_priority_frame(&frame_a);
            fuzz_structured_priority_frame(&frame_b);
        },

        _ => {
            // Reserved bit set in dependency
            let mut payload = vec![0u8; 5];
            payload[0] = 0xFF; // Set reserved bit + high dependency bits
            payload[1] = 0xFF;
            payload[2] = 0xFF;
            payload[3] = 0x01; // Stream 1 dependency
            payload[4] = 50;   // Weight

            fuzz_malformed_priority_payload(1, &payload);
        },
    }
}

fn fuzz_priority_frame_sequence(frames: &[FuzzPriorityFrame]) {
    for frame in frames {
        fuzz_structured_priority_frame(frame);
    }
}