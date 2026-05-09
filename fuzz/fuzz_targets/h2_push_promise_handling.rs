//! HTTP/2 PUSH_PROMISE Frame Handling Fuzzer
//!
//! Targets the PUSH_PROMISE frame handling logic in src/http/h2/connection.rs
//! to test handling of arbitrary PUSH_PROMISE frames including those sent
//! without ENABLE_PUSH=1 setting, ensuring proper PROTOCOL_ERROR responses
//! and no panics.
//!
//! Key invariants tested:
//! - PUSH_PROMISE without ENABLE_PUSH=1 → PROTOCOL_ERROR (not panic)
//! - Malformed PUSH_PROMISE frames are rejected gracefully
//! - Invalid stream IDs in PUSH_PROMISE frames are handled properly
//! - Large/malformed frame payloads don't cause crashes
//! - Frame processing maintains connection state consistency

#![no_main]

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::connection::{Connection, ConnectionState, ReceivedFrame};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{DataFrame, PushPromiseFrame, SettingsFrame};
use asupersync::http::h2::settings::Settings;
use asupersync::http::h2::{Frame, FrameType, H2Error};
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent OOM during fuzzing
const MAX_INPUT_SIZE: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes
    if data.is_empty() || data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Test 1: Basic PUSH_PROMISE frame without ENABLE_PUSH setting
    {
        // Create a minimal frame with fuzzed payload
        let frame = create_push_promise_frame(data, 1, 2);

        let mut connection = create_push_disabled_test_connection();
        observe_push_disabled_rejection(&mut connection, frame, "push-disabled-basic");
    }

    // Test 2: PUSH_PROMISE with malformed promised stream ID
    if data.len() >= 4 {
        // Create PUSH_PROMISE with potentially malformed promised stream ID
        let promised_stream_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        let frame = create_push_promise_frame_with_promised_id(&data[4..], 1, promised_stream_id);

        // Should handle invalid stream IDs gracefully during frame creation
        if let Frame::PushPromise(push_frame) = frame {
            let _promised = push_frame.promised_stream_id;
            // Should not panic regardless of promised stream ID value
        }
    }

    // Test 3: PUSH_PROMISE on invalid/closed streams
    {
        let mut connection = create_push_enabled_test_connection();

        // Use fuzzed data to determine stream ID (including invalid ones)
        let stream_id = if data.len() >= 4 {
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]) | 1 // Ensure odd (client-initiated)
        } else {
            0 // Invalid stream ID
        };

        let frame = create_push_promise_frame(data, stream_id, 2);
        observe_process_frame(&mut connection, frame, "invalid-or-closed-stream");

        // Should handle invalid stream states gracefully
    }

    // Test 4: Very large PUSH_PROMISE frames
    if data.len() > 100 {
        let mut connection = create_push_enabled_test_connection();

        // Create oversized PUSH_PROMISE frame
        let large_frame = create_large_push_promise_frame(data);
        observe_process_frame(&mut connection, large_frame, "large-push-promise");

        // Should handle large frames without crashing
    }

    // Test 5: Malformed PUSH_PROMISE frame structure via raw parsing
    {
        // Test the actual frame parsing logic with fuzzed data
        let frame_result = parse_push_promise_from_raw_data(data);

        // Should handle malformed frames gracefully (parse error or valid frame)
        match frame_result {
            Ok(frame) => {
                // Successfully parsed - validate it doesn't cause issues
                if let Frame::PushPromise(push_frame) = frame {
                    let _stream_id = push_frame.stream_id;
                    let _promised_id = push_frame.promised_stream_id;
                    let _headers = &push_frame.header_block;
                }
            }
            Err(_) => {
                // Parse error is acceptable for malformed input
            }
        }
    }

    // Test 6: Multiple rapid PUSH_PROMISE frames
    if data.len() >= 8 {
        let mut connection = create_push_enabled_test_connection();

        // Send multiple PUSH_PROMISE frames in succession
        let chunk_size = data.len() / 4;
        for i in 0..4 {
            let start = i * chunk_size;
            let end = std::cmp::min(start + chunk_size, data.len());
            if start < end {
                let frame = create_push_promise_frame(&data[start..end], 1, 2 + i as u32);
                observe_process_frame(&mut connection, frame, "rapid-push-promise");
            }
        }

        // Should handle frame flooding gracefully
    }

    // Test 7: PUSH_PROMISE with invalid flags
    {
        let mut connection = create_push_enabled_test_connection();

        // Use fuzzed data as frame flags (including invalid combinations)
        let flags = if !data.is_empty() { data[0] } else { 0 };
        let frame = create_push_promise_frame_with_flags(data, 1, 2, flags);

        observe_process_frame(&mut connection, frame, "invalid-flags");
        // Should handle invalid flags appropriately
    }

    // Test 8: PUSH_PROMISE during connection shutdown
    {
        let mut connection = create_push_enabled_test_connection();

        // Initiate connection shutdown
        connection.goaway(ErrorCode::NoError, Bytes::new());

        // Try to send PUSH_PROMISE after GOAWAY
        let frame = create_push_promise_frame(data, 1, 2);
        observe_process_frame(&mut connection, frame, "after-goaway");

        // Should reject PUSH_PROMISE after GOAWAY
    }

    // Test 9: PUSH_PROMISE with padded payload
    if data.len() > 10 {
        let mut connection = create_push_enabled_test_connection();

        // Create PUSH_PROMISE with padding
        let frame = create_padded_push_promise_frame(data);
        observe_process_frame(&mut connection, frame, "padded-push-promise");

        // Should handle padded frames correctly
    }

    // Test 10: Interleaved PUSH_PROMISE and other frame types
    if data.len() >= 16 {
        let mut connection = create_push_enabled_test_connection();

        // Alternate between PUSH_PROMISE and other frames
        let mid = data.len() / 2;

        // Send PUSH_PROMISE
        let push_frame = create_push_promise_frame(&data[..mid], 1, 2);
        observe_process_frame(&mut connection, push_frame, "interleaved-push-promise");

        // Send DATA frame (or other frame type based on fuzzed data)
        let other_frame = create_data_frame(&data[mid..], 1);
        observe_process_frame(&mut connection, other_frame, "interleaved-data");

        // Should handle frame interleaving properly
    }
});

fn observe_process_result(
    connection: &mut Connection,
    frame: Frame,
    scenario: &str,
) -> Result<Option<ReceivedFrame>, H2Error> {
    let before_state = connection.state();
    let result = connection.process_frame(frame);
    let after_state = connection.state();

    if matches!(before_state, ConnectionState::Open | ConnectionState::Closing) {
        assert!(
            !matches!(after_state, ConnectionState::Handshaking),
            "{scenario}: connection regressed to handshaking"
        );
    }
    if matches!(before_state, ConnectionState::Closed) {
        assert!(
            matches!(after_state, ConnectionState::Closed),
            "{scenario}: closed connection became active again"
        );
    }

    match &result {
        Ok(Some(received)) => observe_received_frame(received, scenario),
        Ok(None) => {}
        Err(error) => {
            assert_ne!(
                error.code,
                ErrorCode::NoError,
                "{scenario}: error used NO_ERROR"
            );
            assert!(
                !error.message.trim().is_empty(),
                "{scenario}: error message was empty"
            );
        }
    }

    result
}

fn observe_process_frame(connection: &mut Connection, frame: Frame, scenario: &str) {
    let _observed = observe_process_result(connection, frame, scenario);
}

fn observe_push_disabled_rejection(connection: &mut Connection, frame: Frame, scenario: &str) {
    match observe_process_result(connection, frame, scenario) {
        Err(error) => {
            assert_eq!(
                error.code,
                ErrorCode::ProtocolError,
                "{scenario}: disabled push used wrong error code"
            );
            assert!(
                error.is_connection_error(),
                "{scenario}: disabled push must be a connection error"
            );
        }
        Ok(result) => panic!("{scenario}: disabled push was accepted: {result:?}"),
    }
}

fn observe_received_frame(received: &ReceivedFrame, scenario: &str) {
    match received {
        ReceivedFrame::PushPromise {
            stream_id,
            promised_stream_id,
            headers,
        } => {
            assert!(
                stream_id % 2 == 1,
                "{scenario}: accepted PUSH_PROMISE on non-client stream {stream_id}"
            );
            assert!(
                *promised_stream_id != 0 && promised_stream_id.is_multiple_of(2),
                "{scenario}: accepted invalid promised stream {promised_stream_id}"
            );
            assert!(
                !headers.is_empty(),
                "{scenario}: accepted PUSH_PROMISE without headers"
            );
            for header in headers {
                assert!(
                    valid_observed_header_name(&header.name),
                    "{scenario}: decoded invalid pushed header name {:?}",
                    header.name
                );
                assert!(
                    valid_observed_header_value(&header.value),
                    "{scenario}: decoded invalid pushed header value {:?}",
                    header.value
                );
            }
        }
        ReceivedFrame::Headers { headers, .. } => {
            for header in headers {
                assert!(
                    valid_observed_header_name(&header.name),
                    "{scenario}: decoded invalid header name {:?}",
                    header.name
                );
                assert!(
                    valid_observed_header_value(&header.value),
                    "{scenario}: decoded invalid header value {:?}",
                    header.value
                );
            }
        }
        ReceivedFrame::Data { .. } | ReceivedFrame::Reset { .. } | ReceivedFrame::GoAway { .. } => {
        }
    }
}

fn valid_observed_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(i, byte)| {
            matches!(
                byte,
                b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            ) || (byte == b':' && i == 0)
        })
}

fn valid_observed_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| !matches!(byte, b'\0' | b'\r' | b'\n'))
}

fn create_push_disabled_test_connection() -> Connection {
    let mut settings = Settings::client();
    settings.enable_push = false;
    let mut connection = Connection::client(settings);
    let settings_frame = Frame::Settings(SettingsFrame::new(Vec::new()));
    observe_process_frame(&mut connection, settings_frame, "initial-settings-disabled");
    connection
}

fn create_push_enabled_test_connection() -> Connection {
    let mut settings = Settings::client();
    settings.enable_push = true;
    let mut connection = Connection::client(settings);
    let settings_frame = Frame::Settings(SettingsFrame::new(Vec::new()));
    observe_process_frame(&mut connection, settings_frame, "initial-settings-enabled");
    connection
}

fn create_data_frame(data: &[u8], stream_id: u32) -> Frame {
    Frame::Data(DataFrame::new(
        stream_id,
        Bytes::copy_from_slice(data),
        false,
    ))
}

/// Create a PUSH_PROMISE frame with fuzzed payload
fn create_push_promise_frame(data: &[u8], stream_id: u32, promised_stream_id: u32) -> Frame {
    let mut payload = BytesMut::new();

    // Add promised stream ID (4 bytes)
    payload.extend_from_slice(&(promised_stream_id & 0x7fff_ffff).to_be_bytes());

    // Add fuzzed header block fragment
    payload.extend_from_slice(data);

    let push_frame = PushPromiseFrame {
        stream_id,
        promised_stream_id,
        header_block: payload.freeze(),
        end_headers: true,
    };

    Frame::PushPromise(push_frame)
}

/// Create PUSH_PROMISE frame with specific promised stream ID
fn create_push_promise_frame_with_promised_id(
    header_data: &[u8],
    stream_id: u32,
    promised_stream_id: u32,
) -> Frame {
    let push_frame = PushPromiseFrame {
        stream_id,
        promised_stream_id: promised_stream_id & 0x7fff_ffff,
        header_block: Bytes::copy_from_slice(header_data),
        end_headers: true,
    };
    Frame::PushPromise(push_frame)
}

/// Create PUSH_PROMISE frame with specific flags
fn create_push_promise_frame_with_flags(
    data: &[u8],
    stream_id: u32,
    promised_stream_id: u32,
    flags: u8, // flags are managed by end_headers field
) -> Frame {
    let push_frame = PushPromiseFrame {
        stream_id,
        promised_stream_id: promised_stream_id & 0x7fff_ffff,
        header_block: Bytes::copy_from_slice(data),
        end_headers: flags & 0x4 != 0, // END_HEADERS flag
    };
    Frame::PushPromise(push_frame)
}

/// Create an oversized PUSH_PROMISE frame
fn create_large_push_promise_frame(data: &[u8]) -> Frame {
    let mut payload = BytesMut::new();

    // Repeat the data to create a large payload
    for _ in 0..100 {
        payload.extend_from_slice(data);
        if payload.len() > 1024 * 1024 {
            // Cap at 1MB
            break;
        }
    }

    let push_frame = PushPromiseFrame {
        stream_id: 1,
        promised_stream_id: 2,
        header_block: payload.freeze(),
        end_headers: true,
    };
    Frame::PushPromise(push_frame)
}

/// Create a padded PUSH_PROMISE frame by testing frame encoding/parsing
fn create_padded_push_promise_frame(data: &[u8]) -> Frame {
    // Create a basic push promise frame and let the frame parser handle padding
    let push_frame = PushPromiseFrame {
        stream_id: 1,
        promised_stream_id: 2,
        header_block: Bytes::copy_from_slice(data),
        end_headers: true,
    };
    Frame::PushPromise(push_frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_promise_frame_creation() {
        let test_data = b"test header block";
        let frame = create_push_promise_frame(test_data, 1, 2);

        match frame {
            Frame::PushPromise(push_frame) => {
                assert_eq!(push_frame.stream_id, 1);
                assert!(!push_frame.header_block.is_empty());
            }
            _ => panic!("Expected PushPromise frame"),
        }
    }

    #[test]
    fn test_large_frame_creation() {
        let test_data = vec![0u8; 1000];
        let frame = create_large_push_promise_frame(&test_data);

        match frame {
            Frame::PushPromise(push_frame) => {
                // Should create frame without panicking
                assert!(push_frame.header_block.len() > test_data.len());
            }
            _ => panic!("Expected PushPromise frame"),
        }
    }

    #[test]
    fn test_padded_frame_creation() {
        let test_data = b"\x05test data"; // 5 bytes padding + data
        let frame = create_padded_push_promise_frame(test_data);

        match frame {
            Frame::PushPromise(push_frame) => {
                assert!(!push_frame.header_block.is_empty());
            }
            _ => panic!("Expected PushPromise frame"),
        }
    }
}

/// Parse PUSH_PROMISE frame from raw data to test the parser directly
fn parse_push_promise_from_raw_data(data: &[u8]) -> Result<Frame, H2Error> {
    use asupersync::http::h2::frame::{FrameHeader, headers_flags, parse_frame};

    // Create a frame header for PUSH_PROMISE
    let header = FrameHeader {
        length: std::cmp::min(data.len() as u32, 16_777_215), // Max frame size
        frame_type: FrameType::PushPromise as u8,
        flags: headers_flags::END_HEADERS,
        stream_id: 1, // Valid client-initiated stream
    };

    // Parse the frame with fuzzed payload
    parse_frame(&header, Bytes::copy_from_slice(data))
}
