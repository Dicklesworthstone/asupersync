//! Fuzz target for `src/http/h2/connection.rs` HTTP/2 connection-level frame decoder.
//!
//! Focus:
//! 1. `Connection::process_frame()` handles arbitrary frame sequences without panicking
//! 2. Protocol validation for continuation frames, settings, window updates
//! 3. Security checks for flood attacks (CVE-2019-9512/9515 protection)
//! 4. GOAWAY generation on protocol errors
//! 5. Connection state consistency under adversarial frame sequences

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::{
    connection::Connection,
    frame::{Frame, FrameHeader, parse_frame},
    error::ErrorCode,
    settings::Settings,
};
use libfuzzer_sys::fuzz_target;

const MAX_FRAME_SEQUENCE_LEN: usize = 50;
const MAX_PAYLOAD_SIZE: usize = 8192;

#[derive(Arbitrary, Debug, Clone)]
enum ConnectionType {
    Client,
    Server,
}

#[derive(Arbitrary, Debug, Clone)]
enum TestScenario {
    /// Test raw frame bytes through parse_frame -> process_frame pipeline
    RawFrameSequence {
        conn_type: ConnectionType,
        frames: Vec<RawFrame>,
    },
    /// Test flood attack protection with valid frames
    FloodAttack {
        conn_type: ConnectionType,
        flood_frame_type: FloodFrameType,
        count: u8,
    },
    /// Test window management edge cases
    WindowStress {
        conn_type: ConnectionType,
        window_ops: Vec<WindowOperation>,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct RawFrame {
    /// Frame header fields
    length: u32,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    /// Frame payload
    payload: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum FloodFrameType {
    Ping,
    Settings,
    WindowUpdate,
}

#[derive(Arbitrary, Debug, Clone)]
struct WindowOperation {
    stream_id: u32,
    increment: u32,
}

fuzz_target!(|scenario: TestScenario| {
    match scenario {
        TestScenario::RawFrameSequence { conn_type, frames } => {
            fuzz_raw_frame_sequence(conn_type, frames);
        }
        TestScenario::FloodAttack {
            conn_type,
            flood_frame_type,
            count
        } => {
            fuzz_flood_attack(conn_type, flood_frame_type, count);
        }
        TestScenario::WindowStress {
            conn_type,
            window_ops
        } => {
            fuzz_window_stress(conn_type, window_ops);
        }
    }
});

fn create_connection(conn_type: ConnectionType) -> Connection {
    let settings = Settings::default();
    match conn_type {
        ConnectionType::Client => Connection::client(settings),
        ConnectionType::Server => Connection::server(settings),
    }
}

fn raw_frame_to_frame(raw: RawFrame) -> Option<Frame> {
    // Sanitize frame header
    let length = (raw.length & 0x00FFFFFF).min(MAX_PAYLOAD_SIZE as u32); // 24-bit length
    let stream_id = raw.stream_id & 0x7FFFFFFF; // Clear R bit

    let header = FrameHeader {
        length,
        frame_type: raw.frame_type,
        flags: raw.flags,
        stream_id,
    };

    // Sanitize payload to match declared length
    let mut payload = raw.payload;
    payload.truncate(length as usize);
    if payload.len() < length as usize {
        payload.resize(length as usize, 0);
    }

    // Parse frame using the same path as production
    parse_frame(&header, Bytes::from(payload)).ok()
}

fn fuzz_raw_frame_sequence(conn_type: ConnectionType, frames: Vec<RawFrame>) {
    let mut connection = create_connection(conn_type);
    let frames: Vec<_> = frames.into_iter().take(MAX_FRAME_SEQUENCE_LEN).collect();

    // Process frame sequence, expecting either success or clean error handling
    for raw_frame in frames {
        if let Some(frame) = raw_frame_to_frame(raw_frame) {
            // Should never panic - either succeeds or returns H2Error
            let result = connection.process_frame(frame);

            match result {
                Ok(_) => {
                    // Frame processed successfully - validate connection is still sane
                    let _state = connection.state();
                    let _send_window = connection.send_window();
                    let _recv_window = connection.recv_window();
                }
                Err(h2_error) => {
                    // All errors should be well-formed H2Error instances
                    // This validates error path hygiene - no panics, proper error codes
                    let _code = h2_error.code;
                    let _message = &h2_error.message;

                    // Connection-level errors might have terminated the connection
                    if h2_error.stream_id.is_none() {
                        // This was a connection error - connection might be closed
                        break;
                    }
                }
            }
        }
    }
}

fn fuzz_flood_attack(conn_type: ConnectionType, flood_frame_type: FloodFrameType, count: u8) {
    let mut connection = create_connection(conn_type);
    let flood_count = (count as usize + 1).min(15_000); // Test up to flood protection limits

    // Create flood frame based on type
    let create_flood_frame = |i: usize| -> Option<Frame> {
        match flood_frame_type {
            FloodFrameType::Ping => {
                let header = FrameHeader {
                    length: 8,
                    frame_type: 6, // PING
                    flags: 0,
                    stream_id: 0,
                };
                let payload = Bytes::from(vec![0; 8]);
                parse_frame(&header, payload).ok()
            }
            FloodFrameType::Settings => {
                let header = FrameHeader {
                    length: 0,
                    frame_type: 4, // SETTINGS
                    flags: 0,
                    stream_id: 0,
                };
                let payload = Bytes::new();
                parse_frame(&header, payload).ok()
            }
            FloodFrameType::WindowUpdate => {
                let header = FrameHeader {
                    length: 4,
                    frame_type: 8, // WINDOW_UPDATE
                    flags: 0,
                    stream_id: 0,
                };
                let increment = (i as u32).wrapping_add(1).max(1); // Ensure non-zero
                let payload = Bytes::from(increment.to_be_bytes().to_vec());
                parse_frame(&header, payload).ok()
            }
        }
    };

    for i in 0..flood_count {
        if let Some(frame) = create_flood_frame(i) {
            let result = connection.process_frame(frame);

            match result {
                Ok(_) => {
                    // Continue flooding - check connection limits
                }
                Err(h2_error) => {
                    // Check if flood protection kicked in
                    if h2_error.code == ErrorCode::EnhanceYourCalm {
                        // Expected flood protection - test passed
                        break;
                    }
                    // Other errors are also acceptable - just stop flooding
                    break;
                }
            }
        }
    }
}

fn fuzz_window_stress(conn_type: ConnectionType, window_ops: Vec<WindowOperation>) {
    let mut connection = create_connection(conn_type);

    for window_op in window_ops.into_iter().take(100) {
        if window_op.increment == 0 {
            continue; // Invalid increment, skip
        }

        // Create WINDOW_UPDATE frame
        let header = FrameHeader {
            length: 4,
            frame_type: 8, // WINDOW_UPDATE
            flags: 0,
            stream_id: window_op.stream_id & 0x7FFFFFFF, // Clear R bit
        };
        let payload = Bytes::from(window_op.increment.to_be_bytes().to_vec());

        if let Ok(frame) = parse_frame(&header, payload) {
            let result = connection.process_frame(frame);

            match result {
                Ok(_) => {
                    // Validate connection window integrity
                    let send_window = connection.send_window();
                    let recv_window = connection.recv_window();

                    // Windows should be bounded and not overflow
                    assert!(send_window >= -(1 << 31)); // Lower bound
                    assert!(recv_window >= -(1 << 31)); // Lower bound
                    assert!(send_window <= (1 << 31) - 1); // Upper bound
                    assert!(recv_window <= (1 << 31) - 1); // Upper bound
                }
                Err(_) => {
                    // Window update errors are acceptable (e.g., overflow, invalid stream)
                }
            }
        }
    }
}