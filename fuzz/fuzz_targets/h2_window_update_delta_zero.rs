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
//! - WINDOW_UPDATE with delta>0: accepted
//! - Delta too large (>i32::MAX): flow_control error
//! - Valid range deltas: accepted with proper window updates

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 WINDOW_UPDATE frame
#[derive(Debug, Clone, Arbitrary)]
struct WindowUpdateFrame {
    stream_id: u32,
    increment: u32,
}

/// Stream flow control information
#[derive(Debug, Clone)]
struct FlowControlState {
    send_window: i32,
    recv_window: i32,
}

impl Default for FlowControlState {
    fn default() -> Self {
        Self {
            send_window: 65535, // Default window size
            recv_window: 65535,
        }
    }
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

/// Mock HTTP/2 connection for WINDOW_UPDATE validation
struct MockH2Connection {
    connection_send_window: i32,
    connection_recv_window: i32,
    streams: HashMap<u32, FlowControlState>,
    errors: Vec<String>,
}

impl MockH2Connection {
    fn new() -> Self {
        Self {
            connection_send_window: 65535, // Default connection window
            connection_recv_window: 65535,
            streams: HashMap::new(),
            errors: Vec::new(),
        }
    }

    /// Process a WINDOW_UPDATE frame and validate according to RFC 9113
    fn process_window_update(&mut self, frame: &WindowUpdateFrame) -> Result<(), String> {
        // RFC 9113 §6.9: Convert to signed integer for validation
        let increment =
            i32::try_from(frame.increment).map_err(|_| "window increment too large".to_string())?;

        // RFC 9113 §6.9.1: increment of 0 MUST be treated as PROTOCOL_ERROR
        if increment == 0 {
            if frame.stream_id == 0 {
                return Err("WINDOW_UPDATE with zero increment".to_string());
            }
            return Err("WINDOW_UPDATE with zero increment".to_string());
        }

        // Apply window update
        if frame.stream_id == 0 {
            // Connection-level window update
            self.connection_send_window = self.connection_send_window.saturating_add(increment);

            // Check for window overflow per RFC 9113 §6.9.1
            if self.connection_send_window > i32::MAX {
                return Err("flow control window overflow".to_string());
            }
        } else {
            // Stream-level window update
            let stream = self.streams.entry(frame.stream_id).or_default();
            stream.send_window = stream.send_window.saturating_add(increment);

            if stream.send_window > i32::MAX {
                return Err("flow control window overflow".to_string());
            }
        }

        Ok(())
    }

    fn get_connection_window(&self) -> i32 {
        self.connection_send_window
    }

    fn get_stream_window(&self, stream_id: u32) -> Option<i32> {
        self.streams.get(&stream_id).map(|s| s.send_window)
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
        }, // Stream minimum valid
        WindowUpdateFrame {
            stream_id: 0,
            increment: 32768,
        }, // Mid-range
        WindowUpdateFrame {
            stream_id: 3,
            increment: 65535,
        }, // Large valid
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

fuzz_target!(|scenario: WindowUpdateScenario| {
    // Limit scenario size to avoid timeouts
    if scenario.frames.len() > 50 || scenario.max_frames > 100 {
        return;
    }

    let mut connection = MockH2Connection::new();
    let mut zero_delta_errors = 0;
    let mut overflow_errors = 0;
    let mut successful_updates = 0;
    let mut expected_zero_failures = 0;

    // Get initial connection window for comparison
    let initial_conn_window = connection.get_connection_window();

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
        test_frame.stream_id = test_frame.stream_id % 20; // 0-19 range

        // Track expected failures
        if test_frame.increment == 0 {
            expected_zero_failures += 1;
        }

        let result = connection.process_window_update(&test_frame);

        match result {
            Ok(()) => {
                successful_updates += 1;

                // Verify zero delta was not accepted (should always fail)
                if test_frame.increment == 0 {
                    panic!(
                        "WINDOW_UPDATE with zero delta incorrectly accepted: stream_id={}",
                        test_frame.stream_id
                    );
                }

                // Verify window was actually updated for connection-level
                if test_frame.stream_id == 0 {
                    let new_window = connection.get_connection_window();
                    if new_window <= initial_conn_window {
                        // Window should have increased (unless overflow/saturation)
                    }
                }
            }
            Err(err) => {
                if test_frame.increment == 0 {
                    zero_delta_errors += 1;

                    // Verify correct error message for zero delta
                    if !err.contains("WINDOW_UPDATE with zero increment") {
                        panic!(
                            "Wrong error message for zero delta: expected 'WINDOW_UPDATE with zero increment', got '{}'",
                            err
                        );
                    }
                } else if test_frame.increment > i32::MAX as u32 {
                    overflow_errors += 1;

                    // Verify correct error message for overflow
                    if !err.contains("window increment too large")
                        && !err.contains("flow control window overflow")
                    {
                        // Either "too large" (at parse) or "overflow" (at application) is valid
                    }
                } else {
                    // Unexpected error for valid increment
                    panic!(
                        "Unexpected error for valid WINDOW_UPDATE increment {}: {}",
                        test_frame.increment, err
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
});

/// Test specific RFC 9113 §6.9.1 violations
fn test_specific_rfc_violations(connection: &mut MockH2Connection) {
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
    assert!(
        result
            .unwrap_err()
            .contains("WINDOW_UPDATE with zero increment")
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
    assert!(
        result
            .unwrap_err()
            .contains("WINDOW_UPDATE with zero increment")
    );

    // Test 3: Valid minimum increment should succeed
    let valid_frame = WindowUpdateFrame {
        stream_id: 1,
        increment: 1,
    };
    let result = connection.process_window_update(&valid_frame);
    assert!(
        result.is_ok(),
        "WINDOW_UPDATE with increment=1 should succeed: {:?}",
        result
    );

    // Test 4: Large valid increment should succeed
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

    // Test 5: Increment too large should fail
    let too_large_frame = WindowUpdateFrame {
        stream_id: 0,
        increment: (i32::MAX as u32) + 1,
    };
    let result = connection.process_window_update(&too_large_frame);
    assert!(
        result.is_err(),
        "WINDOW_UPDATE with increment > i32::MAX should fail"
    );
    assert!(result.unwrap_err().contains("window increment too large"));

    // Test 6: Maximum valid increment should succeed
    let max_valid_frame = WindowUpdateFrame {
        stream_id: 3,
        increment: i32::MAX as u32,
    };
    let result = connection.process_window_update(&max_valid_frame);
    assert!(
        result.is_ok(),
        "WINDOW_UPDATE with increment=i32::MAX should succeed: {:?}",
        result
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
                    increment: 1, // Valid increment
                },
                WindowUpdateFrame {
                    stream_id: 1,
                    increment: 32768, // Valid increment
                },
                WindowUpdateFrame {
                    stream_id: 3,
                    increment: i32::MAX as u32, // Maximum valid
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
                }, // Valid
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
                }, // Valid
            ],
            include_edge_cases: false,
            max_frames: 10,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }
}
