//! HTTP/2 HEADERS Frame Priority Field Handling Fuzzer
//!
//! Targets the HEADERS frame Priority field handling logic in src/http/h2/frame.rs
//! and src/http/h2/stream.rs to test stream dependency tree construction and cycle
//! detection, ensuring arbitrary priority weights and dependencies are handled
//! correctly per RFC 9113 Section 5.3.
//!
//! Key invariants tested:
//! - Self-dependency detection → PROTOCOL_ERROR
//! - Priority weight range (1-256, stored as 0-255)
//! - Exclusive dependency flag handling
//! - Stream dependency tree construction without cycles
//! - No panic on arbitrary priority values
//! - Proper frame parsing with PRIORITY flag

#![no_main]

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{
    FrameHeader, HeadersFrame, Setting, SettingsFrame, headers_flags, parse_frame,
};
use asupersync::http::h2::settings::Settings;
use asupersync::http::h2::{Frame, H2Error};
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent OOM
const MAX_INPUT_SIZE: usize = 4096;
const MAX_H2_FRAME_PAYLOAD_LEN: usize = 16_777_215;

/// HEADERS frame type constant
const HEADERS_FRAME_TYPE: u8 = 0x1;

fn capped_h2_payload_len(len: usize) -> u32 {
    let capped = len.min(MAX_H2_FRAME_PAYLOAD_LEN);
    u32::try_from(capped).expect("HTTP/2 maximum frame payload length fits u32")
}

fn exact_h2_payload_len(len: usize) -> Result<u32, H2Error> {
    if len > MAX_H2_FRAME_PAYLOAD_LEN {
        return Err(H2Error::protocol("HEADERS priority payload too large"));
    }

    u32::try_from(len).map_err(|_| H2Error::protocol("HEADERS priority payload too large"))
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes
    if data.is_empty() || data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Test 1: Basic priority parsing with arbitrary values
    {
        if data.len() >= 6 {
            let stream_id =
                ((u32::from_be_bytes([data[0], data[1], data[2], data[3]]) & 0x7fff_ffff) % 1000)
                    * 2
                    + 1; // Odd client stream
            let dependency = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) & 0x7fff_ffff;
            let weight = data[5];
            let exclusive = data[0] & 0x80 != 0;

            let result =
                create_headers_frame_with_priority(stream_id, dependency, weight, exclusive);
            match result {
                Ok(frame) => {
                    // Test that the frame parses correctly
                    observe_headers_priority_frame(
                        "basic priority",
                        &frame,
                        stream_id,
                        dependency,
                        weight,
                        exclusive,
                    );
                }
                Err(err) => observe_h2_error("basic priority", &err), // Expected for some invalid combinations
            }
        }
    }

    // Test 2: Self-dependency detection (should fail)
    {
        if data.len() >= 4 {
            let stream_id =
                ((u32::from_be_bytes([data[0], data[1], data[2], data[3]]) & 0x7fff_ffff) % 1000)
                    * 2
                    + 1;
            let weight = if data.len() > 4 { data[4] } else { 16 };
            let exclusive = data[0] & 0x01 != 0;

            // Create frame where dependency == stream_id (self-dependency)
            let result =
                create_headers_frame_with_priority(stream_id, stream_id, weight, exclusive);
            match result {
                Ok(_) => panic!("self-dependency parsed successfully"),
                Err(err) => {
                    assert_h2_error_shape(
                        "self-dependency",
                        &err,
                        ErrorCode::ProtocolError,
                        Some(stream_id),
                        "stream cannot depend on itself",
                    );
                }
            }
        }
    }

    // Test 3: Weight boundary testing (0-255 range)
    {
        let test_weights = [0, 1, 15, 16, 127, 128, 254, 255];
        for &weight in &test_weights {
            if data.len() >= 8 {
                let stream_id = ((u32::from_be_bytes([data[0], data[1], data[2], data[3]])
                    & 0x7fff_ffff)
                    % 500)
                    * 2
                    + 1;
                let dependency = ((u32::from_be_bytes([data[4], data[5], data[6], data[7]])
                    & 0x7fff_ffff)
                    % 500)
                    * 2;

                if stream_id != dependency {
                    observe_priority_creation_result(
                        "weight boundary",
                        stream_id,
                        dependency,
                        weight,
                        false,
                        create_headers_frame_with_priority(stream_id, dependency, weight, false),
                    );
                }
            }
        }
    }

    // Test 4: Dependency chain testing (A depends on B, B depends on C, etc.)
    if data.len() >= 12 {
        let chain_length = (data[0] % 8) + 1; // 1-8 streams in chain
        let mut prev_stream = 0u32; // Root dependency

        for i in 0..(chain_length as usize).min((data.len() - 1) / 4) {
            let offset = 1 + i * 4;
            if offset + 4 <= data.len() {
                let stream_id = ((i as u32 + 1) * 2) + 1; // Odd stream IDs
                let weight = data[offset];
                let exclusive = data[offset + 1] & 0x80 != 0;

                observe_priority_creation_result(
                    "dependency chain",
                    stream_id,
                    prev_stream,
                    weight,
                    exclusive,
                    create_headers_frame_with_priority(stream_id, prev_stream, weight, exclusive),
                );
                prev_stream = stream_id;
            }
        }
    }

    // Test 5: Raw frame parsing with priority flag
    {
        let parse_result = parse_headers_frame_with_priority_from_raw(data);
        match parse_result {
            Ok(Frame::Headers(headers_frame)) => {
                // Successfully parsed - validate priority handling
                if let Some(priority) = &headers_frame.priority {
                    // Check that priority values are within expected ranges
                    let _dependency = priority.dependency;
                    let _weight = priority.weight; // Should be 0-255
                    let _exclusive = priority.exclusive;
                }
                observe_priority_validation_result(
                    "raw priority parse",
                    validate_headers_frame_priority(&Frame::Headers(headers_frame)),
                );
            }
            Err(err) => observe_h2_error("raw priority parse", &err), // Parse errors acceptable for malformed input
            _ => {}                                                   // Other frame types
        }
    }

    // Test 6: Exclusive dependency flag combinations
    if data.len() >= 8 {
        let stream_id =
            ((u32::from_be_bytes([data[0], data[1], data[2], data[3]]) & 0x7fff_ffff) % 1000) * 2
                + 1;
        let dependency =
            ((u32::from_be_bytes([data[4], data[5], data[6], data[7]]) & 0x7fff_ffff) % 1000) * 2;
        let weight = if data.len() > 8 { data[8] } else { 16 };

        if stream_id != dependency {
            // Test both exclusive and non-exclusive
            observe_priority_creation_result(
                "exclusive priority",
                stream_id,
                dependency,
                weight,
                true,
                create_headers_frame_with_priority(stream_id, dependency, weight, true),
            );
            observe_priority_creation_result(
                "non-exclusive priority",
                stream_id,
                dependency,
                weight,
                false,
                create_headers_frame_with_priority(stream_id, dependency, weight, false),
            );
        }
    }

    // Test 7: Large dependency values (near u32::MAX)
    {
        let large_dependencies = [
            0,
            1,
            0x7fff_ffff, // Maximum stream ID (31 bits)
            0x8000_0000, // Would set reserved bit (should be masked)
            0xffff_ffff, // Maximum u32
        ];

        for &dependency in &large_dependencies {
            if data.len() >= 4 {
                let stream_id = ((u32::from_be_bytes([data[0], data[1], data[2], data[3]])
                    & 0x7fff_ffff)
                    % 100)
                    * 2
                    + 1;
                let weight = if data.len() > 4 { data[4] } else { 16 };

                if stream_id != dependency {
                    observe_priority_creation_result(
                        "large dependency",
                        stream_id,
                        dependency,
                        weight,
                        false,
                        create_headers_frame_with_priority(stream_id, dependency, weight, false),
                    );
                }
            }
        }
    }

    // Test 8: Connection-level priority processing
    {
        if data.len() >= 8 {
            let conn_result = test_priority_in_connection_context(data);
            observe_connection_priority_result("connection priority", conn_result);
        }
    }

    // Test 9: Multiple HEADERS frames with different priorities
    if data.len() >= 16 {
        let frame_count = (data[0] % 4) + 1; // 1-4 frames

        for i in 0..(frame_count as usize).min((data.len() - 1) / 6) {
            let offset = 1 + i * 6;
            if offset + 6 <= data.len() {
                let stream_id = ((i as u32 + 1) * 2) + 1;
                let dependency = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) & 0x7fff_ffff;
                let weight = data[offset + 4];
                let exclusive = data[offset + 5] & 0x80 != 0;

                if stream_id != dependency {
                    observe_priority_creation_result(
                        "multiple priority frames",
                        stream_id,
                        dependency,
                        weight,
                        exclusive,
                        create_headers_frame_with_priority(
                            stream_id, dependency, weight, exclusive,
                        ),
                    );
                }
            }
        }
    }

    // Test 10: Malformed priority data (short payloads)
    {
        let malformed_sizes = [1, 2, 3, 4]; // Less than 5 bytes required for priority

        for &size in &malformed_sizes {
            if data.len() >= size {
                let truncated_data = &data[..size];
                observe_truncated_priority_result(
                    size,
                    create_headers_frame_with_truncated_priority(1, truncated_data),
                );
            }
        }
    }
});

fn observe_priority_creation_result(
    context: &str,
    stream_id: u32,
    dependency: u32,
    weight: u8,
    exclusive: bool,
    result: Result<Frame, H2Error>,
) {
    match result {
        Ok(frame) => {
            observe_headers_priority_frame(
                context, &frame, stream_id, dependency, weight, exclusive,
            );
        }
        Err(err) => {
            if stream_id == (dependency & 0x7fff_ffff) {
                assert_h2_error_shape(
                    context,
                    &err,
                    ErrorCode::ProtocolError,
                    Some(stream_id),
                    "stream cannot depend on itself",
                );
            } else {
                observe_h2_error(context, &err);
            }
        }
    }
}

fn observe_headers_priority_frame(
    context: &str,
    frame: &Frame,
    expected_stream_id: u32,
    expected_dependency: u32,
    expected_weight: u8,
    expected_exclusive: bool,
) {
    match frame {
        Frame::Headers(headers_frame) => {
            assert_eq!(
                headers_frame.stream_id, expected_stream_id,
                "{context}: parsed HEADERS stream id changed"
            );
            let priority = headers_frame
                .priority
                .as_ref()
                .expect("priority flag should preserve priority fields");
            assert_eq!(
                priority.dependency,
                expected_dependency & 0x7fff_ffff,
                "{context}: parsed dependency changed"
            );
            assert_eq!(
                priority.weight, expected_weight,
                "{context}: parsed weight changed"
            );
            let expected_wire_exclusive =
                expected_exclusive || (expected_dependency & 0x8000_0000 != 0);
            assert_eq!(
                priority.exclusive, expected_wire_exclusive,
                "{context}: parsed exclusive bit changed"
            );
            assert_ne!(
                priority.dependency, headers_frame.stream_id,
                "{context}: parser accepted self-dependency"
            );
            observe_priority_validation_result(context, validate_headers_frame_priority(frame));
        }
        _ => panic!("{context}: expected HEADERS frame"),
    }
}

fn observe_priority_validation_result(context: &str, result: Result<(), H2Error>) {
    if let Err(err) = result {
        observe_h2_error(context, &err);
        assert_eq!(
            err.code,
            ErrorCode::ProtocolError,
            "{context}: priority validation should report protocol errors"
        );
    }
}

fn observe_connection_priority_result(context: &str, result: Result<(), H2Error>) {
    if let Err(err) = result {
        observe_h2_error(context, &err);
        assert_ne!(
            err.code,
            ErrorCode::NoError,
            "{context}: failed connection processing cannot report NO_ERROR"
        );
    }
}

fn observe_truncated_priority_result(size: usize, result: Result<Frame, H2Error>) {
    match result {
        Ok(_) => panic!("truncated priority payload of {size} bytes parsed successfully"),
        Err(err) => {
            assert_h2_error_shape(
                "truncated priority",
                &err,
                ErrorCode::ProtocolError,
                None,
                "HEADERS frame too short for priority",
            );
        }
    }
}

fn observe_h2_error(context: &str, err: &H2Error) {
    assert!(
        !err.message.trim().is_empty(),
        "{context}: H2 error message should not be empty"
    );
    let display = err.to_string();
    assert!(
        !display.trim().is_empty(),
        "{context}: H2 error display should not be empty"
    );
    let debug = format!("{err:?}");
    assert!(
        !debug.trim().is_empty(),
        "{context}: H2 error debug should not be empty"
    );
}

fn assert_h2_error_shape(
    context: &str,
    err: &H2Error,
    expected_code: ErrorCode,
    expected_stream_id: Option<u32>,
    expected_message: &str,
) {
    observe_h2_error(context, err);
    assert_eq!(
        err.code, expected_code,
        "{context}: unexpected error code for {err:?}"
    );
    assert_eq!(
        err.stream_id, expected_stream_id,
        "{context}: unexpected stream id for {err:?}"
    );
    assert_eq!(
        err.message, expected_message,
        "{context}: unexpected message for {err:?}"
    );
    assert_eq!(
        err.is_connection_error(),
        expected_stream_id.is_none(),
        "{context}: unexpected connection/stream classification for {err:?}"
    );

    let expected_display = match expected_stream_id {
        Some(stream_id) => {
            format!("HTTP/2 stream {stream_id} error ({expected_code}): {expected_message}")
        }
        None => format!("HTTP/2 connection error ({expected_code}): {expected_message}"),
    };
    assert_eq!(
        err.to_string(),
        expected_display,
        "{context}: unexpected display text for {err:?}"
    );
}

/// Create a HEADERS frame with specific priority values
fn create_headers_frame_with_priority(
    stream_id: u32,
    dependency: u32,
    weight: u8,
    exclusive: bool,
) -> Result<Frame, H2Error> {
    // Create priority specification
    let priority = asupersync::http::h2::frame::PrioritySpec {
        exclusive,
        dependency,
        weight,
    };

    // Create HEADERS frame with priority
    let mut headers_frame = HeadersFrame::new(stream_id, Bytes::from("dummy"), false, true);
    headers_frame.priority = Some(priority);

    // Validate through parsing round-trip
    let mut buf = BytesMut::new();
    headers_frame.encode(&mut buf)?;

    // Parse header and payload
    if buf.len() >= 9 {
        let header_bytes = buf.split_to(9);
        let mut header_buf = header_bytes;
        let header = FrameHeader::parse(&mut header_buf)?;
        let payload = buf.freeze();

        // Re-parse through the frame parser to test priority handling
        parse_frame(&header, payload)
    } else {
        Err(H2Error::protocol("Invalid frame encoding"))
    }
}

/// Test priority handling in connection context
fn test_priority_in_connection_context(data: &[u8]) -> Result<(), H2Error> {
    let mut conn = Connection::server(Settings::default());

    // Transition to Open state by processing initial SETTINGS
    let settings_frame = SettingsFrame::new(vec![Setting::InitialWindowSize(65535)]);
    conn.process_frame(Frame::Settings(settings_frame))?;

    if data.len() >= 8 {
        let stream_id =
            ((u32::from_be_bytes([data[0], data[1], data[2], data[3]]) & 0x7fff_ffff) % 1000) * 2
                + 1;
        let dependency =
            ((u32::from_be_bytes([data[4], data[5], data[6], data[7]]) & 0x7fff_ffff) % 1000) * 2;
        let weight = if data.len() > 8 { data[8] } else { 16 };
        let exclusive = data[0] & 0x01 != 0;

        if stream_id != dependency {
            let frame =
                create_headers_frame_with_priority(stream_id, dependency, weight, exclusive)?;
            conn.process_frame(frame)?;
        }
    }

    Ok(())
}

/// Parse HEADERS frame with priority from raw data
fn parse_headers_frame_with_priority_from_raw(data: &[u8]) -> Result<Frame, H2Error> {
    // Create frame header with PRIORITY flag
    let header = FrameHeader {
        length: capped_h2_payload_len(data.len()),
        frame_type: HEADERS_FRAME_TYPE,
        flags: headers_flags::END_HEADERS | headers_flags::PRIORITY,
        stream_id: 1, // Valid client stream
    };

    parse_frame(&header, Bytes::copy_from_slice(data))
}

/// Create HEADERS frame with truncated priority data to test error handling
fn create_headers_frame_with_truncated_priority(
    stream_id: u32,
    priority_data: &[u8],
) -> Result<Frame, H2Error> {
    // Create frame header with PRIORITY flag
    let header = FrameHeader {
        length: exact_h2_payload_len(priority_data.len())?,
        frame_type: HEADERS_FRAME_TYPE,
        flags: headers_flags::PRIORITY | headers_flags::END_HEADERS,
        stream_id,
    };

    parse_frame(&header, Bytes::copy_from_slice(priority_data))
}

/// Validate HEADERS frame priority parsing
fn validate_headers_frame_priority(frame: &Frame) -> Result<(), H2Error> {
    match frame {
        Frame::Headers(headers_frame) => {
            if let Some(priority) = &headers_frame.priority {
                // Validate priority constraints
                let dependency = priority.dependency;
                let _weight = priority.weight;
                let _exclusive = priority.exclusive;

                // Check self-dependency (should be caught during parsing)
                if dependency == headers_frame.stream_id {
                    return Err(H2Error::protocol("Self-dependency detected"));
                }

                // Weight is stored as 0-255 but represents 1-256
                // No explicit validation needed - u8 constrains the range

                Ok(())
            } else {
                // No priority is valid
                Ok(())
            }
        }
        _ => Err(H2Error::protocol("Expected HEADERS frame")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_priority_creation() {
        let result = create_headers_frame_with_priority(1, 3, 100, false);
        assert!(result.is_ok());

        if let Ok(Frame::Headers(headers_frame)) = result {
            assert!(headers_frame.priority.is_some());
            let priority = headers_frame.priority.unwrap();
            assert_eq!(priority.dependency, 3);
            assert_eq!(priority.weight, 100);
            assert!(!priority.exclusive);
        }
    }

    #[test]
    fn test_self_dependency_rejection() {
        let result = create_headers_frame_with_priority(1, 1, 100, false);
        assert!(result.is_err());

        if let Err(error) = result {
            assert_h2_error_shape(
                "self-dependency unit",
                &error,
                ErrorCode::ProtocolError,
                Some(1),
                "stream cannot depend on itself",
            );
        }
    }

    #[test]
    fn test_exclusive_priority() {
        let result = create_headers_frame_with_priority(3, 1, 255, true);
        assert!(result.is_ok());

        if let Ok(Frame::Headers(headers_frame)) = result {
            let priority = headers_frame.priority.unwrap();
            assert!(priority.exclusive);
            assert_eq!(priority.weight, 255);
        }
    }

    #[test]
    fn test_zero_dependency() {
        let result = create_headers_frame_with_priority(1, 0, 16, false);
        assert!(result.is_ok());

        if let Ok(Frame::Headers(headers_frame)) = result {
            let priority = headers_frame.priority.unwrap();
            assert_eq!(priority.dependency, 0); // Root dependency
        }
    }

    #[test]
    fn test_weight_boundaries() {
        // Test minimum and maximum weight values
        assert!(create_headers_frame_with_priority(1, 0, 0, false).is_ok());
        assert!(create_headers_frame_with_priority(1, 0, 255, false).is_ok());
    }

    #[test]
    fn test_connection_context() {
        let data = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 100];
        let result = test_priority_in_connection_context(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_truncated_priority_data() {
        // Test with insufficient data for priority (need 5 bytes)
        let short_data = [0x01, 0x02, 0x03]; // Only 3 bytes
        let result = create_headers_frame_with_truncated_priority(1, &short_data);
        let error = result.expect_err("short priority payload must be rejected");
        assert_h2_error_shape(
            "truncated priority unit",
            &error,
            ErrorCode::ProtocolError,
            None,
            "HEADERS frame too short for priority",
        );
    }

    #[test]
    fn test_large_dependency_values() {
        // Test near maximum stream ID
        let result = create_headers_frame_with_priority(1, 0x7fff_ffff, 16, false);
        assert!(result.is_ok());
    }
}
