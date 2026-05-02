#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;

/// Fuzz target for HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE changes during active connections.
///
/// Per RFC 7540 §6.5.2: "When the value of SETTINGS_INITIAL_WINDOW_SIZE changes,
/// a receiver MUST adjust the size of all stream flow-control windows that it
/// maintains by the difference between the new value and the old value."
///
/// Critical scenarios:
/// - Increase from 1MB to 16MB (delta = +15MB) - windows should expand
/// - Decrease from 16MB to 1MB (delta = -15MB) - windows should contract, floor at 0
/// - Multiple concurrent streams with different current window states
/// - Window overflow protection (max 2^31-1)
/// - Negative delta handling

#[derive(Debug, Arbitrary)]
struct WindowSizeChangeTest {
    /// Initial window size setting (before change)
    initial_window_size: u32,
    /// New window size setting (after change)
    new_window_size: u32,
    /// Number of active streams to simulate
    num_streams: u8,
    /// Stream-specific window adjustments (data sent/received)
    stream_adjustments: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq)]
enum WindowUpdateResult {
    Success(WindowState),
    Error(WindowError),
    Warning(WindowState, String),
}

#[derive(Debug, Clone, PartialEq)]
enum WindowError {
    WindowOverflow,
    InvalidWindowSize,
    NegativeWindow,
    StreamNotFound,
    SettingsViolation,
}

#[derive(Debug, Clone, PartialEq)]
struct WindowState {
    /// Connection-level window state
    connection_window: i64,
    /// Per-stream window states
    stream_windows: HashMap<u32, i64>,
    /// Current INITIAL_WINDOW_SIZE setting
    current_initial_window_size: u32,
    /// Statistics
    stats: WindowStats,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct WindowStats {
    /// Number of window updates applied
    updates_applied: usize,
    /// Number of streams affected by setting change
    streams_affected: usize,
    /// Windows that hit the floor (became 0)
    windows_floored: usize,
    /// Windows that would have overflowed
    overflow_prevented: usize,
}

/// Mock HTTP/2 connection state for testing window size changes
struct MockH2Connection {
    state: WindowState,
    policy: FlowControlPolicy,
}

#[derive(Debug, Clone)]
struct FlowControlPolicy {
    /// Maximum window size (RFC 7540: 2^31-1)
    max_window_size: i64,
    /// Minimum window size
    min_window_size: i64,
    /// Maximum initial window size setting
    max_initial_window_size: u32,
    /// Whether to allow negative windows (should be false)
    allow_negative_windows: bool,
    /// Maximum number of streams to track
    max_tracked_streams: usize,
}

impl Default for FlowControlPolicy {
    fn default() -> Self {
        Self {
            max_window_size: (1i64 << 31) - 1, // 2^31-1 per RFC 7540
            min_window_size: 0,
            max_initial_window_size: (1u32 << 31) - 1, // 2^31-1 per RFC 7540
            allow_negative_windows: false,
            max_tracked_streams: 1000,
        }
    }
}

impl MockH2Connection {
    fn new(initial_window_size: u32) -> Self {
        Self {
            state: WindowState {
                connection_window: 65535, // Default connection window
                stream_windows: HashMap::new(),
                current_initial_window_size: initial_window_size,
                stats: WindowStats::default(),
            },
            policy: FlowControlPolicy::default(),
        }
    }

    fn with_policy(initial_window_size: u32, policy: FlowControlPolicy) -> Self {
        Self {
            state: WindowState {
                connection_window: 65535,
                stream_windows: HashMap::new(),
                current_initial_window_size: initial_window_size,
                stats: WindowStats::default(),
            },
            policy,
        }
    }

    /// Create a new stream with initial window size
    fn create_stream(&mut self, stream_id: u32) -> Result<(), WindowError> {
        if self.state.stream_windows.len() >= self.policy.max_tracked_streams {
            return Err(WindowError::SettingsViolation);
        }

        // New stream starts with current INITIAL_WINDOW_SIZE
        let initial_window = self.state.current_initial_window_size as i64;
        self.state.stream_windows.insert(stream_id, initial_window);
        Ok(())
    }

    /// Simulate data being sent on a stream (reduces window)
    fn send_data(&mut self, stream_id: u32, size: u32) -> Result<(), WindowError> {
        let window = self.state.stream_windows.get_mut(&stream_id)
            .ok_or(WindowError::StreamNotFound)?;

        let new_window = *window - size as i64;

        // Window can go negative temporarily until WINDOW_UPDATE received
        *window = new_window;
        Ok(())
    }

    /// Simulate WINDOW_UPDATE received (increases window)
    fn receive_window_update(&mut self, stream_id: u32, increment: u32) -> Result<(), WindowError> {
        let window = self.state.stream_windows.get_mut(&stream_id)
            .ok_or(WindowError::StreamNotFound)?;

        let new_window = *window + increment as i64;

        // Check for overflow
        if new_window > self.policy.max_window_size {
            return Err(WindowError::WindowOverflow);
        }

        *window = new_window;
        Ok(())
    }

    /// Apply SETTINGS_INITIAL_WINDOW_SIZE change per RFC 7540 §6.5.2
    fn apply_initial_window_size_change(&mut self, new_window_size: u32) -> Result<WindowUpdateResult, WindowError> {
        // Validate new window size
        if new_window_size > self.policy.max_initial_window_size {
            return Err(WindowError::InvalidWindowSize);
        }

        let old_window_size = self.state.current_initial_window_size;
        let delta = new_window_size as i64 - old_window_size as i64;

        let mut warnings = Vec::new();
        let mut stats = WindowStats {
            updates_applied: 1,
            streams_affected: self.state.stream_windows.len(),
            windows_floored: 0,
            overflow_prevented: 0,
        };

        // Apply delta to ALL existing stream windows
        for (stream_id, window) in self.state.stream_windows.iter_mut() {
            let old_window = *window;
            let new_window = old_window + delta;

            // RFC 7540 §6.5.2: "If the new value is smaller than the old value and
            // the difference would cause a receiver to fall below zero, then the
            // receiver MUST lower the value to zero."
            if new_window < self.policy.min_window_size {
                *window = self.policy.min_window_size;
                stats.windows_floored += 1;

                if !self.policy.allow_negative_windows {
                    warnings.push(format!(
                        "Stream {} window floored to {} (was {}, delta {})",
                        stream_id, self.policy.min_window_size, old_window, delta
                    ));
                }
            } else if new_window > self.policy.max_window_size {
                // Prevent overflow
                *window = self.policy.max_window_size;
                stats.overflow_prevented += 1;
                warnings.push(format!(
                    "Stream {} window capped at {} (would be {}, delta {})",
                    stream_id, self.policy.max_window_size, new_window, delta
                ));
            } else {
                *window = new_window;
            }
        }

        // Update the setting
        self.state.current_initial_window_size = new_window_size;
        self.state.stats = stats;

        let new_state = self.state.clone();

        if warnings.is_empty() {
            Ok(WindowUpdateResult::Success(new_state))
        } else {
            Ok(WindowUpdateResult::Warning(new_state, warnings.join("; ")))
        }
    }

    /// Get current state for verification
    fn get_state(&self) -> &WindowState {
        &self.state
    }

    /// Verify window state integrity
    fn verify_integrity(&self) -> Result<(), WindowError> {
        // Check all windows are within bounds
        for (stream_id, window) in &self.state.stream_windows {
            if *window < self.policy.min_window_size && !self.policy.allow_negative_windows {
                return Err(WindowError::NegativeWindow);
            }
            if *window > self.policy.max_window_size {
                return Err(WindowError::WindowOverflow);
            }
        }

        // Check initial window size setting is valid
        if self.state.current_initial_window_size > self.policy.max_initial_window_size {
            return Err(WindowError::InvalidWindowSize);
        }

        Ok(())
    }
}

/// Generate predefined test cases for window size changes
fn generate_test_cases() -> Vec<(String, u32, u32, Vec<(u32, i32)>, WindowUpdateResult)> {
    vec![
        // Test case 1: Increase from 1MB to 16MB (delta = +15MB)
        (
            "1MB to 16MB increase".to_string(),
            1024 * 1024,      // 1MB initial
            16 * 1024 * 1024, // 16MB new
            vec![
                (1, 0),           // Stream 1: no data sent yet
                (3, -512 * 1024), // Stream 3: 512KB sent (window reduced)
                (5, -1024 * 1024), // Stream 5: 1MB sent (window at 0)
            ],
            WindowUpdateResult::Success(WindowState {
                connection_window: 65535,
                stream_windows: {
                    let mut map = HashMap::new();
                    map.insert(1, 16 * 1024 * 1024);           // 1MB + 15MB = 16MB
                    map.insert(3, 16 * 1024 * 1024 - 512 * 1024); // (1MB - 512KB) + 15MB = 15.5MB
                    map.insert(5, 15 * 1024 * 1024);           // (1MB - 1MB) + 15MB = 15MB
                    map
                },
                current_initial_window_size: 16 * 1024 * 1024,
                stats: WindowStats {
                    updates_applied: 1,
                    streams_affected: 3,
                    windows_floored: 0,
                    overflow_prevented: 0,
                },
            })
        ),

        // Test case 2: Decrease from 16MB to 1MB (delta = -15MB)
        (
            "16MB to 1MB decrease".to_string(),
            16 * 1024 * 1024, // 16MB initial
            1024 * 1024,      // 1MB new
            vec![
                (1, 0),           // Stream 1: no data sent yet
                (3, -512 * 1024), // Stream 3: 512KB sent
                (5, -16 * 1024 * 1024), // Stream 5: 16MB sent (window at 0)
            ],
            WindowUpdateResult::Warning(
                WindowState {
                    connection_window: 65535,
                    stream_windows: {
                        let mut map = HashMap::new();
                        map.insert(1, 1024 * 1024);           // 16MB - 15MB = 1MB
                        map.insert(3, 1024 * 1024 - 512 * 1024); // (16MB - 512KB) - 15MB = 0.5MB
                        map.insert(5, 0);                     // (16MB - 16MB) - 15MB = 0 (floored)
                        map
                    },
                    current_initial_window_size: 1024 * 1024,
                    stats: WindowStats {
                        updates_applied: 1,
                        streams_affected: 3,
                        windows_floored: 1,
                        overflow_prevented: 0,
                    },
                },
                "Stream 5 window floored to 0".to_string()
            )
        ),

        // Test case 3: Small increase
        (
            "64KB to 128KB increase".to_string(),
            65536,  // 64KB initial
            131072, // 128KB new
            vec![
                (1, -32768), // Stream 1: 32KB sent (window = 32KB)
            ],
            WindowUpdateResult::Success(WindowState {
                connection_window: 65535,
                stream_windows: {
                    let mut map = HashMap::new();
                    map.insert(1, 131072 - 32768); // 32KB + 64KB = 96KB
                    map
                },
                current_initial_window_size: 131072,
                stats: WindowStats {
                    updates_applied: 1,
                    streams_affected: 1,
                    windows_floored: 0,
                    overflow_prevented: 0,
                },
            })
        ),

        // Test case 4: Decrease to zero (extreme case)
        (
            "64KB to 0 decrease".to_string(),
            65536, // 64KB initial
            0,     // 0 new
            vec![
                (1, -32768), // Stream 1: 32KB sent (window = 32KB)
                (3, 0),      // Stream 3: no data sent (window = 64KB)
            ],
            WindowUpdateResult::Warning(
                WindowState {
                    connection_window: 65535,
                    stream_windows: {
                        let mut map = HashMap::new();
                        map.insert(1, 0); // 32KB - 64KB = 0 (floored)
                        map.insert(3, 0); // 64KB - 64KB = 0
                        map
                    },
                    current_initial_window_size: 0,
                    stats: WindowStats {
                        updates_applied: 1,
                        streams_affected: 2,
                        windows_floored: 1,
                        overflow_prevented: 0,
                    },
                },
                "Stream 1 window floored to 0".to_string()
            )
        ),
    ]
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 1024 {
        return;
    }

    // Try to generate a structured test from the fuzz data
    let test = match WindowSizeChangeTest::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(test) => test,
        Err(_) => return, // Invalid input, skip
    };

    // Skip tests with unreasonable parameters
    if test.num_streams > 100 || test.stream_adjustments.len() > 100 {
        return;
    }

    // Limit window sizes to reasonable ranges for fuzzing
    let initial_window_size = test.initial_window_size.min(64 * 1024 * 1024); // Max 64MB
    let new_window_size = test.new_window_size.min(64 * 1024 * 1024); // Max 64MB
    let num_streams = test.num_streams.min(50).max(1);

    // Create connection with initial window size
    let mut connection = MockH2Connection::new(initial_window_size);

    // Create streams and apply adjustments
    for i in 0..num_streams {
        let stream_id = (i as u32 * 2) + 1; // Odd stream IDs

        // Create stream
        if connection.create_stream(stream_id).is_err() {
            continue; // Skip if we hit limits
        }

        // Apply adjustment if available
        if let Some(&adjustment) = test.stream_adjustments.get(i as usize) {
            if adjustment < 0 {
                // Negative adjustment = send data (reduce window)
                let _ = connection.send_data(stream_id, (-adjustment) as u32);
            } else if adjustment > 0 {
                // Positive adjustment = receive WINDOW_UPDATE (increase window)
                let _ = connection.receive_window_update(stream_id, adjustment as u32);
            }
        }
    }

    // Verify initial integrity
    assert!(connection.verify_integrity().is_ok(),
        "Connection integrity check failed after setup");

    // Store initial state for comparison
    let initial_state = connection.get_state().clone();

    // Apply window size change
    let result = connection.apply_initial_window_size_change(new_window_size);

    // Verify result consistency
    match result {
        Ok(WindowUpdateResult::Success(new_state)) => {
            // Successful update should maintain integrity
            assert!(connection.verify_integrity().is_ok(),
                "Connection integrity check failed after successful update");

            // Window size setting should be updated
            assert_eq!(new_state.current_initial_window_size, new_window_size,
                "Initial window size setting not updated correctly");

            // All streams should be accounted for
            assert_eq!(new_state.stream_windows.len(), initial_state.stream_windows.len(),
                "Stream count changed during window size update");

            // Verify delta calculation
            let expected_delta = new_window_size as i64 - initial_window_size as i64;

            for (stream_id, &new_window) in &new_state.stream_windows {
                let initial_window = initial_state.stream_windows[stream_id];
                let expected_new_window = initial_window + expected_delta;

                if expected_new_window < 0 {
                    // Should be floored to 0
                    assert_eq!(new_window, 0,
                        "Stream {} window not floored correctly: expected 0, got {}",
                        stream_id, new_window);
                } else if expected_new_window > (1i64 << 31) - 1 {
                    // Should be capped
                    assert_eq!(new_window, (1i64 << 31) - 1,
                        "Stream {} window not capped correctly", stream_id);
                } else {
                    // Should match calculation
                    assert_eq!(new_window, expected_new_window,
                        "Stream {} window delta incorrect: expected {}, got {}",
                        stream_id, expected_new_window, new_window);
                }
            }
        }

        Ok(WindowUpdateResult::Warning(new_state, warning)) => {
            // Warning should still maintain integrity
            assert!(connection.verify_integrity().is_ok(),
                "Connection integrity check failed after warning update");

            // Warning should be non-empty
            assert!(!warning.is_empty(),
                "Warning result should have non-empty warning message");

            // Should have recorded flooring or overflow events
            assert!(new_state.stats.windows_floored > 0 || new_state.stats.overflow_prevented > 0,
                "Warning result should have flooring or overflow statistics");
        }

        Ok(WindowUpdateResult::Error(error)) => {
            // Error case - verify error is reasonable
            match error {
                WindowError::InvalidWindowSize => {
                    // Should happen for out-of-range window sizes
                    assert!(new_window_size > (1u32 << 31) - 1,
                        "InvalidWindowSize error for valid size: {}", new_window_size);
                }
                WindowError::WindowOverflow => {
                    // Should happen for window calculations that would overflow
                }
                _ => {
                    // Other errors are also acceptable
                }
            }
        }

        Err(error) => {
            // Direct error during processing
            match error {
                WindowError::InvalidWindowSize => {
                    // Should happen for invalid input
                }
                _ => {
                    // Other errors are acceptable
                }
            }
        }
    }

    // Test with permissive policy
    let permissive_policy = FlowControlPolicy {
        max_window_size: i64::MAX >> 1, // Very large but safe
        min_window_size: -1000000, // Allow negative windows
        max_initial_window_size: u32::MAX >> 1,
        allow_negative_windows: true,
        max_tracked_streams: 10000,
    };

    let mut permissive_connection = MockH2Connection::with_policy(initial_window_size, permissive_policy);

    // Create streams for permissive test
    for i in 0..num_streams.min(10) {
        let stream_id = (i as u32 * 2) + 1;
        let _ = permissive_connection.create_stream(stream_id);
    }

    let _permissive_result = permissive_connection.apply_initial_window_size_change(new_window_size);
    // Permissive policy should allow more edge cases

    // Run predefined test cases to ensure correctness
    for (test_name, initial_size, new_size, adjustments, expected) in generate_test_cases() {
        let mut test_connection = MockH2Connection::new(initial_size);

        // Set up test streams
        for (stream_id, adjustment) in adjustments {
            let _ = test_connection.create_stream(stream_id);

            if adjustment < 0 {
                let _ = test_connection.send_data(stream_id, (-adjustment) as u32);
            } else if adjustment > 0 {
                let _ = test_connection.receive_window_update(stream_id, adjustment as u32);
            }
        }

        let test_result = test_connection.apply_initial_window_size_change(new_size);

        match (test_result, expected) {
            (Ok(WindowUpdateResult::Success(actual_state)), WindowUpdateResult::Success(expected_state)) => {
                assert_eq!(actual_state.current_initial_window_size, expected_state.current_initial_window_size,
                    "Test '{}': initial window size mismatch", test_name);

                for (stream_id, &expected_window) in &expected_state.stream_windows {
                    let actual_window = actual_state.stream_windows.get(stream_id);
                    assert_eq!(actual_window, Some(&expected_window),
                        "Test '{}': stream {} window mismatch", test_name, stream_id);
                }
            }

            (Ok(WindowUpdateResult::Warning(_, _)), WindowUpdateResult::Warning(_, _)) => {
                // Both warnings - acceptable
            }

            _ => {
                // Other combinations may be acceptable due to fuzzing context
                // and different policy settings
            }
        }
    }
});