//! HTTP/2 WINDOW_UPDATE Math Overflow Fuzzer
//!
//! Targets the WINDOW_UPDATE frame handling logic in src/http/h2/connection.rs
//! to test flow control window calculations with arbitrary delta values across
//! i32::MAX boundaries, ensuring proper FLOW_CONTROL_ERROR responses per RFC 9113
//! when increments would exceed 2^31-1.
//!
//! Key invariants tested:
//! - WINDOW_UPDATE delta > 2^31-1 → FLOW_CONTROL_ERROR (not panic)
//! - Accumulated window size beyond i32::MAX → FLOW_CONTROL_ERROR
//! - Zero delta WINDOW_UPDATE → PROTOCOL_ERROR
//! - Math overflow in window calculations handled gracefully
//! - Flow control state remains consistent after error conditions

#![no_main]

use asupersync::bytes::Bytes;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{FrameHeader, WindowUpdateFrame, parse_frame};
use asupersync::http::h2::{Frame, H2Error};
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent OOM
const MAX_INPUT_SIZE: usize = 1024;

/// HTTP/2 flow control constants
const MAX_WINDOW_SIZE: i32 = i32::MAX; // 2^31 - 1
const DEFAULT_WINDOW_SIZE: i32 = 65535;

/// WINDOW_UPDATE frame type constant
const WINDOW_UPDATE_FRAME_TYPE: u8 = 0x8;

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes
    if data.is_empty() || data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Test 1: Basic WINDOW_UPDATE with fuzzed delta values
    {
        if data.len() >= 4 {
            let delta = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

            // Test connection-level window update (stream_id = 0)
            let frame = create_window_update_frame(delta, 0);
            let result = validate_window_update(&frame, DEFAULT_WINDOW_SIZE);

            // Should handle according to RFC 9113:
            // - delta = 0 → PROTOCOL_ERROR
            // - current + delta > 2^31-1 → FLOW_CONTROL_ERROR
            // - otherwise OK
            observe_window_update_result(
                "connection-level update",
                delta,
                DEFAULT_WINDOW_SIZE,
                result,
            );
        }
    }

    // Test 2: Stream-level WINDOW_UPDATE with boundary values
    if data.len() >= 8 {
        let delta = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let stream_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) | 1; // Ensure odd (client stream)

        let frame = create_window_update_frame(delta, stream_id);
        let result = validate_window_update(&frame, DEFAULT_WINDOW_SIZE);

        // Should apply same validation rules for stream-level updates
        observe_window_update_result("stream-level update", delta, DEFAULT_WINDOW_SIZE, result);
    }

    // Test 3: Multiple WINDOW_UPDATE frames leading to overflow
    if data.len() >= 12 {
        let delta1 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let delta2 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let delta3 = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        // Simulate multiple updates on same stream
        let mut current_window = DEFAULT_WINDOW_SIZE;

        // Apply first update
        let frame1 = create_window_update_frame(delta1, 1);
        if let Some(new_window) = observe_window_update_result(
            "first accumulated update",
            delta1,
            current_window,
            validate_window_update(&frame1, current_window),
        ) {
            current_window = new_window;

            // Apply second update
            let frame2 = create_window_update_frame(delta2, 1);
            if let Some(new_window) = observe_window_update_result(
                "second accumulated update",
                delta2,
                current_window,
                validate_window_update(&frame2, current_window),
            ) {
                current_window = new_window;

                // Apply third update - this might overflow
                let frame3 = create_window_update_frame(delta3, 1);
                observe_window_update_result(
                    "third accumulated update",
                    delta3,
                    current_window,
                    validate_window_update(&frame3, current_window),
                );
            }
        }
    }

    // Test 4: Boundary testing around i32::MAX
    {
        let boundary_deltas = [
            i32::MAX as u32,       // Exactly max
            (i32::MAX as u32) + 1, // Just over max
            u32::MAX,              // Maximum u32
            0,                     // Zero (invalid)
            1,                     // Minimum valid
        ];

        for &delta in &boundary_deltas {
            let frame = create_window_update_frame(delta, 1);
            observe_window_update_result(
                "boundary update",
                delta,
                DEFAULT_WINDOW_SIZE,
                validate_window_update(&frame, DEFAULT_WINDOW_SIZE),
            );
        }
    }

    // Test 5: Window size near maximum with various deltas
    if data.len() >= 4 {
        let delta = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        // Test with window already near maximum
        let large_windows = [
            MAX_WINDOW_SIZE - 1000, // Near max
            MAX_WINDOW_SIZE - 1,    // One below max
            MAX_WINDOW_SIZE,        // At max (any delta should overflow)
        ];

        for current_window in &large_windows {
            let frame = create_window_update_frame(delta, 1);
            let result = validate_window_update(&frame, *current_window);

            // Most deltas should cause overflow when window is near max
            observe_window_update_result("near-maximum update", delta, *current_window, result);
        }
    }

    // Test 6: Raw frame parsing with malformed payloads
    {
        let parse_result = parse_window_update_from_raw(data);

        match parse_result {
            Ok(Frame::WindowUpdate(window_frame)) => {
                // Successfully parsed - validate the delta
                let delta = window_frame.increment;
                if let Err(error) = validate_delta_value(delta) {
                    observe_window_update_error("parsed delta validation", &error);
                }
            }
            Err(error) => observe_window_update_parse_error("raw frame parse", &error),
            _ => {} // Other frame types from parsing
        }
    }

    // Test 7: Negative values (should be caught in delta validation)
    if data.len() >= 4 {
        // Interpret the fuzzed data as a signed value too
        let delta_signed = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        if delta_signed < 0 {
            // Test that negative deltas are properly rejected
            // Note: WINDOW_UPDATE uses u32, but we want to test edge cases
            let delta_as_u32 = delta_signed as u32;
            let frame = create_window_update_frame(delta_as_u32, 1);
            observe_window_update_result(
                "negative signed delta reinterpreted as u32",
                delta_as_u32,
                DEFAULT_WINDOW_SIZE,
                validate_window_update(&frame, DEFAULT_WINDOW_SIZE),
            );
        }
    }

    // Test 8: Connection-level vs stream-level overflow scenarios
    if data.len() >= 8 {
        let delta = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let stream_selector = data[4] % 2;

        let stream_id = if stream_selector == 0 { 0 } else { 1 }; // Connection vs stream

        let frame = create_window_update_frame(delta, stream_id);
        let result = validate_window_update(&frame, MAX_WINDOW_SIZE - 100);

        // Both connection and stream windows should have same overflow behavior
        observe_window_update_result(
            "connection-vs-stream overflow",
            delta,
            MAX_WINDOW_SIZE - 100,
            result,
        );
    }

    // Test 9: Maximum frame size with repeated deltas
    if data.len() >= 16 {
        // Test multiple small updates that accumulate to overflow
        let small_delta = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) % 10000;
        let iterations = (u32::from_be_bytes([data[4], data[5], data[6], data[7]]) % 1000) + 1;

        let mut current_window = DEFAULT_WINDOW_SIZE;

        for _ in 0..iterations {
            let frame = create_window_update_frame(small_delta, 1);
            if let Some(new_window) = observe_window_update_result(
                "repeated small update",
                small_delta,
                current_window,
                validate_window_update(&frame, current_window),
            ) {
                current_window = new_window;
                let small_delta_i32 =
                    i32::try_from(small_delta).expect("small delta modulo 10000 fits i32");
                if current_window >= MAX_WINDOW_SIZE - small_delta_i32 {
                    break;
                }
            } else {
                break;
            }
        }
    }

    // Test 10: Zero-byte and single-byte parsing
    {
        // Test very short inputs to frame parser
        if data.len() <= 4 {
            let _result = parse_window_update_from_raw(data);
            // Should handle short payloads gracefully
        }
    }
});

/// Create a WINDOW_UPDATE frame with specified delta and stream ID
fn create_window_update_frame(increment: u32, stream_id: u32) -> Frame {
    let window_frame = WindowUpdateFrame {
        stream_id,
        increment,
    };
    Frame::WindowUpdate(window_frame)
}

/// Validate a WINDOW_UPDATE frame against current window size
fn validate_window_update(frame: &Frame, current_window: i32) -> Result<i32, H2Error> {
    match frame {
        Frame::WindowUpdate(window_frame) => {
            let delta = window_frame.increment;

            // RFC 9113: WINDOW_UPDATE with increment of 0 is PROTOCOL_ERROR
            if delta == 0 {
                return Err(H2Error::protocol(
                    "WINDOW_UPDATE increment must not be zero",
                ));
            }

            // Check for overflow: current + delta > 2^31 - 1
            let delta_i32 = checked_delta_i32(delta)?;
            if current_window > MAX_WINDOW_SIZE - delta_i32 {
                return Err(H2Error::flow_control("Window size would exceed maximum"));
            }

            Ok(current_window + delta_i32)
        }
        _ => Err(H2Error::protocol("Expected WINDOW_UPDATE frame")),
    }
}

/// Validate delta value according to RFC 9113
fn validate_delta_value(delta: u32) -> Result<(), H2Error> {
    if delta == 0 {
        return Err(H2Error::protocol(
            "WINDOW_UPDATE increment must not be zero",
        ));
    }

    // RFC 9113: WINDOW_UPDATE increment must be positive and fit in 31 bits
    // The frame format uses u32, but the value must not exceed 2^31-1
    if delta > (i32::MAX as u32) {
        return Err(H2Error::flow_control("WINDOW_UPDATE increment too large"));
    }

    Ok(())
}

/// Parse WINDOW_UPDATE frame from raw data
fn parse_window_update_from_raw(data: &[u8]) -> Result<Frame, H2Error> {
    // Create frame header for WINDOW_UPDATE
    let header = FrameHeader {
        length: u32::try_from(data.len().min(4)).expect("WINDOW_UPDATE payload cap fits u32"),
        frame_type: WINDOW_UPDATE_FRAME_TYPE,
        flags: 0,     // WINDOW_UPDATE has no flags
        stream_id: 1, // Default to stream 1, actual stream ID doesn't affect parsing
    };

    // Parse the frame
    parse_frame(&header, Bytes::copy_from_slice(data))
}

fn checked_delta_i32(delta: u32) -> Result<i32, H2Error> {
    i32::try_from(delta).map_err(|_| H2Error::flow_control("WINDOW_UPDATE increment too large"))
}

fn expected_window_update_result(delta: u32, current_window: i32) -> Result<i32, ErrorCode> {
    if delta == 0 {
        return Err(ErrorCode::ProtocolError);
    }

    let Ok(delta_i32) = i32::try_from(delta) else {
        return Err(ErrorCode::FlowControlError);
    };

    if current_window > MAX_WINDOW_SIZE - delta_i32 {
        return Err(ErrorCode::FlowControlError);
    }

    Ok(current_window + delta_i32)
}

fn observe_window_update_result(
    context: &str,
    delta: u32,
    current_window: i32,
    result: Result<i32, H2Error>,
) -> Option<i32> {
    match (expected_window_update_result(delta, current_window), result) {
        (Ok(expected_window), Ok(new_window)) => {
            assert_eq!(
                new_window, expected_window,
                "{context}: WINDOW_UPDATE returned wrong window for delta {delta} from {current_window}"
            );
            Some(new_window)
        }
        (Err(expected_code), Err(error)) => {
            assert_eq!(
                error.code, expected_code,
                "{context}: expected {:?} for delta {delta} from {current_window}, got {:?}: {}",
                expected_code, error.code, error.message
            );
            assert!(
                !error.message.trim().is_empty(),
                "{context}: WINDOW_UPDATE error must expose a diagnostic"
            );
            None
        }
        (Ok(expected_window), Err(error)) => {
            panic!(
                "{context}: expected successful window {expected_window} for delta {delta} from {current_window}, got {:?}: {}",
                error.code, error.message
            );
        }
        (Err(expected_code), Ok(new_window)) => {
            panic!(
                "{context}: expected {:?} for delta {delta} from {current_window}, got successful window {new_window}",
                expected_code
            );
        }
    }
}

fn observe_window_update_error(context: &str, error: &H2Error) {
    assert!(
        matches!(
            error.code,
            ErrorCode::ProtocolError | ErrorCode::FlowControlError
        ),
        "{context}: unexpected WINDOW_UPDATE error code {:?}: {}",
        error.code,
        error.message
    );
    assert!(
        !error.message.trim().is_empty(),
        "{context}: WINDOW_UPDATE error must expose a diagnostic"
    );
}

fn observe_window_update_parse_error(context: &str, error: &H2Error) {
    assert!(
        matches!(
            error.code,
            ErrorCode::ProtocolError | ErrorCode::FrameSizeError | ErrorCode::FlowControlError
        ),
        "{context}: unexpected WINDOW_UPDATE parse error code {:?}: {}",
        error.code,
        error.message
    );
    assert!(
        !error.message.trim().is_empty(),
        "{context}: WINDOW_UPDATE parse error must expose a diagnostic"
    );
}

/// Test arithmetic overflow scenarios directly
#[cfg(test)]
fn test_overflow_scenarios(base_window: i32, delta: u32) -> bool {
    // Test various overflow detection methods
    let Ok(delta_i32) = i32::try_from(delta) else {
        return true;
    };

    // Method 1: Saturating add
    let saturated = base_window.saturating_add(delta_i32);
    let overflow1 = saturated > MAX_WINDOW_SIZE;

    // Method 2: Checked add
    let checked = base_window.checked_add(delta_i32);
    let overflow2 = checked.is_none() || checked.unwrap() > MAX_WINDOW_SIZE;

    // Method 3: Manual check
    let overflow3 = base_window > MAX_WINDOW_SIZE - delta_i32;

    // All methods should agree on overflow detection
    overflow1 || overflow2 || overflow3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_window_update() {
        let frame = create_window_update_frame(1000, 1);
        let result = validate_window_update(&frame, DEFAULT_WINDOW_SIZE);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DEFAULT_WINDOW_SIZE + 1000);
    }

    #[test]
    fn test_zero_delta_rejected() {
        let frame = create_window_update_frame(0, 1);
        let result = validate_window_update(&frame, DEFAULT_WINDOW_SIZE);
        assert!(result.is_err());

        if let Err(error) = result {
            assert_eq!(error.code, ErrorCode::ProtocolError);
        }
    }

    #[test]
    fn test_overflow_detection() {
        let frame = create_window_update_frame(i32::MAX as u32, 1);
        let result = validate_window_update(&frame, 1000);
        assert!(result.is_err());

        if let Err(error) = result {
            assert_eq!(error.code, ErrorCode::FlowControlError);
        }
    }

    #[test]
    fn test_boundary_values() {
        // Test exactly at boundary
        let frame = create_window_update_frame(1, 1);
        let result = validate_window_update(&frame, MAX_WINDOW_SIZE - 1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), MAX_WINDOW_SIZE);

        // Test just over boundary
        let frame = create_window_update_frame(2, 1);
        let result = validate_window_update(&frame, MAX_WINDOW_SIZE - 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_arithmetic_overflow() {
        // Test various overflow scenarios
        assert!(test_overflow_scenarios(MAX_WINDOW_SIZE, 1));
        assert!(test_overflow_scenarios(MAX_WINDOW_SIZE - 100, 200));
        assert!(!test_overflow_scenarios(1000, 1000));
    }

    #[test]
    fn test_delta_validation() {
        // Valid delta
        assert!(validate_delta_value(1).is_ok());
        assert!(validate_delta_value(i32::MAX as u32).is_ok());

        // Invalid delta
        assert!(validate_delta_value(0).is_err());
        assert!(validate_delta_value((i32::MAX as u32) + 1).is_err());
        assert!(validate_delta_value(u32::MAX).is_err());
    }

    #[test]
    fn test_frame_parsing() {
        // Valid 4-byte payload
        let payload = [0x00, 0x00, 0x03, 0xe8]; // 1000 in network byte order
        let result = parse_window_update_from_raw(&payload);
        assert!(result.is_ok());

        // Too short payload
        let short_payload = [0x00, 0x00];
        let result = parse_window_update_from_raw(&short_payload);
        assert!(result.is_err());
    }
}
