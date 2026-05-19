#![no_main]

//! Fuzz target for HTTP/2 WINDOW_UPDATE delta-zero validation.
//!
//! This target tests that WINDOW_UPDATE frames with zero delta result in
//! PROTOCOL_ERROR per RFC 9113 §6.9.1:
//!
//! - Connection-level (stream_id=0): zero increment MUST be connection error
//! - Stream-level (stream_id>0): zero increment MUST be stream error
//! - Both should result in PROTOCOL_ERROR error code
//!
//! Expected behavior:
//! - WINDOW_UPDATE with delta=0: PROTOCOL_ERROR
//! - Connection WINDOW_UPDATE with delta>0: accepted unless the flow-control window overflows
//! - Stream WINDOW_UPDATE with delta>0: accepted only for an existing stream
//! - Delta too large (>i32::MAX): flow_control error
//! - Valid range deltas: accepted with proper window updates or rejected on idle-stream/overflow

use arbitrary::Arbitrary;
use asupersync::http::h2::{
    Connection, ErrorCode, Frame, H2Error, Settings,
    frame::{SettingsFrame, WindowUpdateFrame as LiveWindowUpdateFrame},
};
use libfuzzer_sys::fuzz_target;

const ZERO_INCREMENT_ERROR: &str = "WINDOW_UPDATE with zero increment";
const INCREMENT_TOO_LARGE_ERROR: &str = "window increment too large";
const WINDOW_OVERFLOW_ERROR: &str = "flow control window overflow";
const IDLE_STREAM_ERROR: &str = "WINDOW_UPDATE received on idle stream";

/// HTTP/2 WINDOW_UPDATE frame
#[derive(Debug, Clone, Arbitrary)]
struct WindowUpdateFrame {
    stream_id: u32,
    increment: u32,
}

fn validated_window_i32(window: i64) -> i32 {
    i32::try_from(window).expect("validated H2 flow-control window must fit i32")
}

/// WINDOW_UPDATE test scenario
#[derive(Debug, Clone, Arbitrary)]
struct WindowUpdateScenario {
    frames: Vec<WindowUpdateFrame>,
    /// Test edge cases with specific delta values
    include_edge_cases: bool,
    /// Maximum number of frames to avoid timeout
    max_frames: u8,
}

/// Fuzz-local oracle for the WINDOW_UPDATE invariants this target exercises.
///
/// The target does not synthesize HEADERS frames, so all positive stream-level
/// updates are idle-stream errors under the live `Connection` state machine.
struct WindowUpdateOracle {
    connection_send_window: i32,
}

impl WindowUpdateOracle {
    fn new() -> Self {
        Self {
            connection_send_window: 65535, // Default connection window
        }
    }

    /// Process a WINDOW_UPDATE frame and validate according to RFC 9113
    fn process_window_update(&mut self, frame: &WindowUpdateFrame) -> Result<(), String> {
        // RFC 9113 §6.9: Convert to signed integer for validation
        let increment =
            i32::try_from(frame.increment).map_err(|_| INCREMENT_TOO_LARGE_ERROR.to_string())?;

        // RFC 9113 §6.9.1: increment of 0 MUST be treated as PROTOCOL_ERROR
        if increment == 0 {
            if frame.stream_id == 0 {
                return Err(ZERO_INCREMENT_ERROR.to_string());
            }
            return Err(ZERO_INCREMENT_ERROR.to_string());
        }

        // The fuzz target emits only WINDOW_UPDATE frames. Without an earlier
        // HEADERS frame, any positive stream-level update targets an idle
        // stream and must be a connection-level PROTOCOL_ERROR.
        if frame.stream_id != 0 {
            return Err(IDLE_STREAM_ERROR.to_string());
        }

        let new_window = i64::from(self.connection_send_window) + i64::from(increment);

        // Check for window overflow per RFC 9113 §6.9.1.
        if new_window > i64::from(i32::MAX) {
            return Err(WINDOW_OVERFLOW_ERROR.to_string());
        }

        self.connection_send_window = validated_window_i32(new_window);
        Ok(())
    }
}

/// Generate edge case WINDOW_UPDATE frames for testing
fn generate_edge_case_frames() -> Vec<WindowUpdateFrame> {
    vec![
        // Zero delta cases (should fail)
        WindowUpdateFrame {
            stream_id: 0,
            increment: 0,
        }, // Connection-level zero
        WindowUpdateFrame {
            stream_id: 1,
            increment: 0,
        }, // Stream-level zero
        WindowUpdateFrame {
            stream_id: 3,
            increment: 0,
        }, // Another stream-level zero
        // Valid delta cases (should succeed)
        WindowUpdateFrame {
            stream_id: 0,
            increment: 1,
        }, // Minimum valid increment
        WindowUpdateFrame {
            stream_id: 1,
            increment: 1,
        }, // Positive idle-stream update
        WindowUpdateFrame {
            stream_id: 0,
            increment: 32768,
        }, // Mid-range
        WindowUpdateFrame {
            stream_id: 3,
            increment: 65535,
        }, // Positive idle-stream update
        // Edge cases for overflow testing
        WindowUpdateFrame {
            stream_id: 0,
            increment: i32::MAX as u32,
        }, // Maximum i32
        WindowUpdateFrame {
            stream_id: 1,
            increment: (i32::MAX as u32) + 1,
        }, // Just over i32::MAX
        WindowUpdateFrame {
            stream_id: 3,
            increment: u32::MAX,
        }, // Maximum u32
        // Multiple stream testing
        WindowUpdateFrame {
            stream_id: 5,
            increment: 1024,
        },
        WindowUpdateFrame {
            stream_id: 7,
            increment: 2048,
        },
        WindowUpdateFrame {
            stream_id: 9,
            increment: 4096,
        },
    ]
}

fn assert_oracle_window_update_error(context: &str, actual: &str, expected: &str) {
    assert_eq!(
        actual, expected,
        "{context}: wrong WINDOW_UPDATE diagnostic"
    );
}

fuzz_target!(|scenario: WindowUpdateScenario| {
    // Limit scenario size to avoid timeouts
    if scenario.frames.len() > 50 || scenario.max_frames > 100 {
        return;
    }

    let mut connection = WindowUpdateOracle::new();
    let mut zero_delta_errors = 0;
    let mut expected_zero_failures = 0;

    // Test edge cases if requested
    let test_frames = if scenario.include_edge_cases {
        let mut frames = scenario.frames.clone();
        frames.extend(generate_edge_case_frames());
        frames.truncate(50); // Keep reasonable size
        frames
    } else {
        scenario.frames
    };

    // Process each WINDOW_UPDATE frame
    for frame in &test_frames {
        // Limit stream IDs to reasonable range
        let mut test_frame = frame.clone();
        test_frame.stream_id %= 20; // 0-19 range

        // Track expected failures
        if test_frame.increment == 0 {
            expected_zero_failures += 1;
        }

        let result = connection.process_window_update(&test_frame);

        match result {
            Ok(()) => {
                // Verify zero delta was not accepted (should always fail)
                if test_frame.increment == 0 {
                    panic!(
                        "WINDOW_UPDATE with zero delta incorrectly accepted: stream_id={}",
                        test_frame.stream_id
                    );
                }
            }
            Err(err) => {
                if test_frame.increment == 0 {
                    zero_delta_errors += 1;
                    assert_oracle_window_update_error("zero delta", &err, ZERO_INCREMENT_ERROR);
                } else if test_frame.increment > i32::MAX as u32 {
                    assert_oracle_window_update_error(
                        "invalid increment",
                        &err,
                        INCREMENT_TOO_LARGE_ERROR,
                    );
                } else if test_frame.stream_id != 0 {
                    assert_oracle_window_update_error(
                        "idle stream increment",
                        &err,
                        IDLE_STREAM_ERROR,
                    );
                } else {
                    assert_oracle_window_update_error(
                        "valid increment overflow",
                        &err,
                        WINDOW_OVERFLOW_ERROR,
                    );
                }
            }
        }
    }

    // Validate that all zero deltas were rejected
    if expected_zero_failures > 0 && zero_delta_errors != expected_zero_failures {
        panic!(
            "Expected {} zero-delta failures, got {}. Some zero deltas were incorrectly accepted.",
            expected_zero_failures, zero_delta_errors
        );
    }

    // Test specific RFC violations
    test_specific_rfc_violations(&mut connection);
    assert_live_window_update_delta_zero();
});

/// Test specific RFC 9113 §6.9.1 violations
fn test_specific_rfc_violations(connection: &mut WindowUpdateOracle) {
    // Test 1: Connection-level zero increment (stream_id=0)
    let conn_zero_frame = WindowUpdateFrame {
        stream_id: 0,
        increment: 0,
    };
    let result = connection.process_window_update(&conn_zero_frame);
    assert!(
        result.is_err(),
        "Connection-level WINDOW_UPDATE with zero increment should fail"
    );
    assert_oracle_window_update_error(
        "connection zero increment",
        &result.unwrap_err(),
        ZERO_INCREMENT_ERROR,
    );

    // Test 2: Stream-level zero increment (stream_id>0)
    let stream_zero_frame = WindowUpdateFrame {
        stream_id: 5,
        increment: 0,
    };
    let result = connection.process_window_update(&stream_zero_frame);
    assert!(
        result.is_err(),
        "Stream-level WINDOW_UPDATE with zero increment should fail"
    );
    assert_oracle_window_update_error(
        "stream zero increment",
        &result.unwrap_err(),
        ZERO_INCREMENT_ERROR,
    );

    // Test 3: Positive stream-level increment without an opened stream fails
    // closed just like the live connection state machine.
    let idle_stream_frame = WindowUpdateFrame {
        stream_id: 1,
        increment: 1,
    };
    let result = connection.process_window_update(&idle_stream_frame);
    assert!(
        result.is_err(),
        "idle stream WINDOW_UPDATE with increment=1 should fail"
    );
    assert_oracle_window_update_error(
        "idle stream increment",
        &result.unwrap_err(),
        IDLE_STREAM_ERROR,
    );

    // Test 4: Valid connection-level minimum increment should succeed.
    let valid_frame = WindowUpdateFrame {
        stream_id: 0,
        increment: 1,
    };
    let result = connection.process_window_update(&valid_frame);
    assert!(
        result.is_ok(),
        "WINDOW_UPDATE with increment=1 should succeed: {:?}",
        result
    );

    // Test 5: Large valid connection-level increment should succeed.
    let large_valid_frame = WindowUpdateFrame {
        stream_id: 0,
        increment: 32768,
    };
    let result = connection.process_window_update(&large_valid_frame);
    assert!(
        result.is_ok(),
        "WINDOW_UPDATE with large valid increment should succeed: {:?}",
        result
    );

    // Test 6: Increment too large should fail before stream-state checks.
    let too_large_frame = WindowUpdateFrame {
        stream_id: 0,
        increment: (i32::MAX as u32) + 1,
    };
    let result = connection.process_window_update(&too_large_frame);
    assert!(
        result.is_err(),
        "WINDOW_UPDATE with increment > i32::MAX should fail"
    );
    assert_oracle_window_update_error(
        "oversized increment",
        &result.unwrap_err(),
        INCREMENT_TOO_LARGE_ERROR,
    );

    // Test 7: Maximum in-range increment overflows the current connection window.
    let max_in_range_frame = WindowUpdateFrame {
        stream_id: 0,
        increment: i32::MAX as u32,
    };
    let result = connection.process_window_update(&max_in_range_frame);
    assert!(
        result.is_err(),
        "WINDOW_UPDATE that exceeds i32::MAX window should fail: {:?}",
        result
    );
    assert_oracle_window_update_error(
        "connection window overflow",
        &result.unwrap_err(),
        WINDOW_OVERFLOW_ERROR,
    );
}

fn open_live_connection() -> Connection {
    let mut connection = Connection::server(Settings::default());
    connection
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("initial SETTINGS should open live H2 connection");
    while connection.next_frame().is_some() {}
    connection
}

fn assert_live_h2_error(
    error: &H2Error,
    expected_code: ErrorCode,
    expected_stream_id: Option<u32>,
    expected_message: &str,
) {
    assert_eq!(error.code, expected_code);
    assert_eq!(error.stream_id, expected_stream_id);
    assert_eq!(error.message.as_str(), expected_message);

    assert!(
        error.is_connection_error() == expected_stream_id.is_none(),
        "H2 WINDOW_UPDATE error level changed: {error}"
    );
    let expected_display = if let Some(stream_id) = expected_stream_id {
        format!("HTTP/2 stream {stream_id} error ({expected_code}): {expected_message}")
    } else {
        format!("HTTP/2 connection error ({expected_code}): {expected_message}")
    };
    assert_eq!(
        error.to_string(),
        expected_display,
        "H2 WINDOW_UPDATE error display changed"
    );
}

fn assert_live_window_update_delta_zero() {
    let mut connection = open_live_connection();

    let err = connection
        .process_frame(Frame::WindowUpdate(LiveWindowUpdateFrame::new(0, 0)))
        .expect_err("connection-level zero WINDOW_UPDATE should fail");
    assert_live_h2_error(&err, ErrorCode::ProtocolError, None, ZERO_INCREMENT_ERROR);

    let err = connection
        .process_frame(Frame::WindowUpdate(LiveWindowUpdateFrame::new(1, 0)))
        .expect_err("stream-level zero WINDOW_UPDATE should fail");
    assert_live_h2_error(
        &err,
        ErrorCode::ProtocolError,
        Some(1),
        ZERO_INCREMENT_ERROR,
    );

    let err = connection
        .process_frame(Frame::WindowUpdate(LiveWindowUpdateFrame::new(1, 1)))
        .expect_err("idle-stream WINDOW_UPDATE should fail");
    assert_live_h2_error(&err, ErrorCode::ProtocolError, None, IDLE_STREAM_ERROR);

    connection
        .process_frame(Frame::WindowUpdate(LiveWindowUpdateFrame::new(0, 1)))
        .expect("connection-level WINDOW_UPDATE increment 1 should succeed");

    let err = connection
        .process_frame(Frame::WindowUpdate(LiveWindowUpdateFrame::new(
            0,
            i32::MAX as u32,
        )))
        .expect_err("connection-level WINDOW_UPDATE overflow should fail");
    assert_live_h2_error(
        &err,
        ErrorCode::FlowControlError,
        None,
        "connection window overflow",
    );

    let err = connection
        .process_frame(Frame::WindowUpdate(LiveWindowUpdateFrame::new(
            0,
            (i32::MAX as u32) + 1,
        )))
        .expect_err("oversized WINDOW_UPDATE should fail");
    assert_live_h2_error(
        &err,
        ErrorCode::FlowControlError,
        None,
        INCREMENT_TOO_LARGE_ERROR,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_level_zero_delta() {
        let scenario = WindowUpdateScenario {
            frames: vec![WindowUpdateFrame {
                stream_id: 0,
                increment: 0, // Zero delta - should fail
            }],
            include_edge_cases: false,
            max_frames: 10,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_stream_level_zero_delta() {
        let scenario = WindowUpdateScenario {
            frames: vec![WindowUpdateFrame {
                stream_id: 1,
                increment: 0, // Zero delta - should fail
            }],
            include_edge_cases: false,
            max_frames: 10,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_valid_increments() {
        let scenario = WindowUpdateScenario {
            frames: vec![
                WindowUpdateFrame {
                    stream_id: 0,
                    increment: 1, // Valid connection increment
                },
                WindowUpdateFrame {
                    stream_id: 0,
                    increment: 32768, // Valid connection increment
                },
            ],
            include_edge_cases: false,
            max_frames: 10,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_increment_too_large() {
        let scenario = WindowUpdateScenario {
            frames: vec![
                WindowUpdateFrame {
                    stream_id: 0,
                    increment: (i32::MAX as u32) + 1, // Too large
                },
                WindowUpdateFrame {
                    stream_id: 1,
                    increment: u32::MAX, // Way too large
                },
            ],
            include_edge_cases: false,
            max_frames: 10,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_edge_cases() {
        let scenario = WindowUpdateScenario {
            frames: vec![],
            include_edge_cases: true, // Test all edge cases
            max_frames: 50,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_mixed_valid_invalid() {
        let scenario = WindowUpdateScenario {
            frames: vec![
                WindowUpdateFrame {
                    stream_id: 0,
                    increment: 1024,
                }, // Valid
                WindowUpdateFrame {
                    stream_id: 1,
                    increment: 0,
                }, // Invalid (zero)
                WindowUpdateFrame {
                    stream_id: 2,
                    increment: 2048,
                }, // Invalid (idle stream)
                WindowUpdateFrame {
                    stream_id: 0,
                    increment: 0,
                }, // Invalid (zero)
                WindowUpdateFrame {
                    stream_id: 3,
                    increment: u32::MAX,
                }, // Invalid (too large)
                WindowUpdateFrame {
                    stream_id: 4,
                    increment: 512,
                }, // Invalid (idle stream)
            ],
            include_edge_cases: false,
            max_frames: 10,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }
}
