//! WebSocket fragmentation sequence state machine fuzzer.
//!
//! Tests RFC 6455 §5.4 fragmentation violations and complex frame sequences
//! that can trigger state machine edge cases in WebSocket frame processing.
//!
//! Targets:
//! - src/net/websocket/frame.rs FrameCodec::decode()
//! - Fragmentation state machine across multiple frame sequences
//! - Control frame interleaving violations
//! - Invalid continuation sequences

#![no_main]

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::net::websocket::{FrameCodec, Opcode, Role};
use libfuzzer_sys::fuzz_target;

/// Represents a frame in the fuzz test sequence
#[derive(Debug, Clone)]
struct FuzzFrame {
    /// Final fragment flag
    fin: bool,
    /// Reserved bits (should be 0, but we test violations)
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    /// Frame opcode
    opcode: Opcode,
    /// Whether frame is masked (client frames must be masked)
    masked: bool,
    /// Payload data
    payload: Vec<u8>,
}

impl FuzzFrame {
    /// Encode this frame to bytes for testing
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // First byte: FIN + RSV + Opcode
        let mut first_byte = 0u8;
        if self.fin {
            first_byte |= 0x80;
        }
        if self.rsv1 {
            first_byte |= 0x40;
        }
        if self.rsv2 {
            first_byte |= 0x20;
        }
        if self.rsv3 {
            first_byte |= 0x10;
        }
        first_byte |= self.opcode as u8;
        buf.push(first_byte);

        // Second byte: MASK + payload length (7 bits)
        let payload_len = self.payload.len();
        let mut second_byte = 0u8;
        if self.masked {
            second_byte |= 0x80;
        }

        if payload_len < 126 {
            second_byte |= payload_len as u8;
            buf.push(second_byte);
        } else if payload_len <= u16::MAX as usize {
            second_byte |= 126;
            buf.push(second_byte);
            buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            second_byte |= 127;
            buf.push(second_byte);
            buf.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }

        // Masking key (if masked)
        if self.masked {
            buf.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // Fixed mask key for fuzzing
        }

        // Payload
        if self.masked {
            // Apply masking
            let mask = [0x12, 0x34, 0x56, 0x78];
            for (i, &byte) in self.payload.iter().enumerate() {
                buf.push(byte ^ mask[i % 4]);
            }
        } else {
            buf.extend_from_slice(&self.payload);
        }

        buf
    }
}

/// Generate a frame sequence from fuzz input
fn generate_frame_sequence(data: &[u8]) -> Vec<FuzzFrame> {
    if data.is_empty() {
        return vec![];
    }

    let mut frames = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        if offset + 3 >= data.len() {
            break;
        }

        // Use fuzz data to construct frame parameters
        let control_byte = data[offset];
        let opcode_byte = data[offset + 1];
        let flags_byte = data[offset + 2];
        let payload_len = (data.get(offset + 3).copied().unwrap_or(0) % 32) as usize;

        offset += 4;

        // Extract frame properties from fuzz data
        let fin = (control_byte & 0x01) != 0;
        let rsv1 = (flags_byte & 0x01) != 0;
        let rsv2 = (flags_byte & 0x02) != 0;
        let rsv3 = (flags_byte & 0x04) != 0;
        let masked = (flags_byte & 0x08) != 0;

        // Map opcode byte to valid opcodes (including invalid ones for testing)
        let opcode = match opcode_byte % 11 {
            0 => Opcode::Continuation,
            1 => Opcode::Text,
            2 => Opcode::Binary,
            8 => Opcode::Close,
            9 => Opcode::Ping,
            10 => Opcode::Pong,
            _ => Opcode::Text, // Default fallback
        };

        // Extract payload
        let end_offset = (offset + payload_len).min(data.len());
        let payload = data[offset..end_offset].to_vec();
        offset = end_offset;

        frames.push(FuzzFrame {
            fin,
            rsv1,
            rsv2,
            rsv3,
            opcode,
            masked,
            payload,
        });

        // Limit sequence length to prevent timeouts
        if frames.len() >= 10 {
            break;
        }
    }

    frames
}

/// Test frame sequence violations
fn test_frame_sequence_violations(frames: &[FuzzFrame]) {
    // Test as server (expects masked client frames)
    test_with_role(frames, Role::Server);

    // Test as client (expects unmasked server frames)
    let unmasked_frames: Vec<_> = frames
        .iter()
        .map(|f| {
            let mut frame = f.clone();
            frame.masked = false; // Client expects unmasked server frames
            frame
        })
        .collect();
    test_with_role(&unmasked_frames, Role::Client);
}

fn test_with_role(frames: &[FuzzFrame], role: Role) {
    let mut codec = FrameCodec::new(role);

    // Create single buffer with all frames
    let mut combined_buffer = Vec::new();
    for frame in frames {
        combined_buffer.extend_from_slice(&frame.encode());
    }

    let mut src = BytesMut::from(&combined_buffer[..]);

    // Decode frames one by one
    let mut decoded_count = 0;
    while !src.is_empty() && decoded_count < 20 {
        // Limit iterations
        match codec.decode(&mut src) {
            Ok(Some(_frame)) => {
                decoded_count += 1;
                // Successfully decoded frame
            }
            Ok(None) => {
                // Need more data
                break;
            }
            Err(_) => {
                // Expected for malformed sequences
                break;
            }
        }
    }
}

/// Test specific RFC 6455 §5.4 fragmentation violations
fn test_fragmentation_violations(frames: &[FuzzFrame]) {
    if frames.is_empty() {
        return;
    }

    // Test continuation frame without initial fragment
    let mut violation_frames = vec![FuzzFrame {
        fin: false,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Continuation,
        masked: true,
        payload: b"invalid".to_vec(),
    }];
    test_with_role(&violation_frames, Role::Server);

    // Test control frame with FIN=false (should be rejected)
    violation_frames = vec![FuzzFrame {
        fin: false, // Invalid for control frames
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Ping,
        masked: true,
        payload: b"ping".to_vec(),
    }];
    test_with_role(&violation_frames, Role::Server);

    // Test interleaved control frame in fragmented sequence
    if frames.len() >= 2 {
        let mut interleaved = vec![
            FuzzFrame {
                fin: false,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: Opcode::Text,
                masked: true,
                payload: b"start".to_vec(),
            },
            FuzzFrame {
                fin: true,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: Opcode::Ping, // Control frame in middle
                masked: true,
                payload: b"ping".to_vec(),
            },
            FuzzFrame {
                fin: true,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: Opcode::Continuation,
                masked: true,
                payload: b"end".to_vec(),
            },
        ];
        test_with_role(&interleaved, Role::Server);
    }
}

fuzz_target!(|data: &[u8]| {
    // Generate frame sequence from fuzz input
    let frames = generate_frame_sequence(data);

    if frames.is_empty() {
        return;
    }

    // Test the generated sequence
    test_frame_sequence_violations(&frames);

    // Test specific RFC 6455 violations
    test_fragmentation_violations(&frames);

    // Test reserved bit violations
    let mut reserved_violation = frames.clone();
    if let Some(frame) = reserved_violation.first_mut() {
        frame.rsv1 = true; // Should trigger ReservedBitsSet error
    }
    test_with_role(&reserved_violation, Role::Server);

    // Test oversized control frame
    let oversized_control = vec![FuzzFrame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Ping,
        masked: true,
        payload: vec![0u8; 126], // Too large for control frame
    }];
    test_with_role(&oversized_control, Role::Server);
});
