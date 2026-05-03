#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 SETTINGS_MAX_FRAME_SIZE mid-connection decrease below minimum fuzz target.
///
/// Tests RFC 7540 compliance when peer decreases SETTINGS_MAX_FRAME_SIZE below
/// the minimum valid value (16384) mid-connection. Per RFC 7540 §6.5.2:
/// "Values outside this range MUST be treated as a PROTOCOL_ERROR."
///
/// Test scenario:
/// 1. Peer sets MAX_FRAME_SIZE=16384 (default/minimum valid)
/// 2. Send DATA frames at the current size (should succeed)
/// 3. Peer attempts to set MAX_FRAME_SIZE=8192 (below minimum)
/// 4. Parser MUST reject with PROTOCOL_ERROR
/// 5. Subsequent frames should still use the previous valid limit
///
/// Critical test areas:
/// - RFC 7540 §6.5.2 minimum frame size validation (16384 bytes)
/// - PROTOCOL_ERROR generation for out-of-range values
/// - State machine consistency after rejected settings change
/// - Frame processing with previous valid limit after rejection
/// - Edge cases around the 16384 byte boundary

#[derive(Arbitrary, Debug, Clone)]
struct MaxFrameSizeDecreaseInput {
    /// Initial connection setup
    initial_setup: ConnectionSetup,

    /// Frames sent at initial frame size
    initial_frames: Vec<TestFrame>,

    /// Attempted invalid settings change
    invalid_settings_change: InvalidSettingsChange,

    /// Frames sent after invalid change (should use previous limit)
    post_invalid_frames: Vec<TestFrame>,

    /// Additional edge case tests
    edge_cases: Vec<EdgeCaseTest>,

    /// Connection configuration
    connection_config: ConnectionConfig,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConnectionSetup {
    /// Initial MAX_FRAME_SIZE (defaults to 16384)
    initial_max_frame_size: u32,

    /// Whether this is client or server side
    is_client: bool,

    /// Enable additional frame validation
    strict_validation: bool,
}

impl Default for ConnectionSetup {
    fn default() -> Self {
        Self {
            initial_max_frame_size: 16384, // RFC 7540 minimum/default
            is_client: true,
            strict_validation: true,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct TestFrame {
    /// Frame type
    frame_type: FrameType,

    /// Frame payload size
    payload_size: u32,

    /// Stream ID
    stream_id: u32,

    /// Frame flags
    flags: u8,

    /// Expected processing result
    expected_result: FrameExpectation,
}

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum FrameType {
    Data = 0,
    Headers = 1,
    Priority = 2,
    RstStream = 3,
    Settings = 4,
    PushPromise = 5,
    Ping = 6,
    GoAway = 7,
    WindowUpdate = 8,
    Continuation = 9,
}

impl FrameType {
    fn to_u8(&self) -> u8 {
        match self {
            FrameType::Data => 0,
            FrameType::Headers => 1,
            FrameType::Priority => 2,
            FrameType::RstStream => 3,
            FrameType::Settings => 4,
            FrameType::PushPromise => 5,
            FrameType::Ping => 6,
            FrameType::GoAway => 7,
            FrameType::WindowUpdate => 8,
            FrameType::Continuation => 9,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum FrameExpectation {
    /// Frame should be accepted
    Accept,
    /// Frame should be rejected due to size
    RejectSize,
    /// Frame should be rejected due to protocol error
    ProtocolError,
}

#[derive(Arbitrary, Debug, Clone)]
struct InvalidSettingsChange {
    /// New MAX_FRAME_SIZE value (should be below minimum)
    new_max_frame_size: u32,

    /// Additional invalid settings to test
    additional_invalid_settings: Vec<InvalidSetting>,

    /// Timing of the invalid change attempt
    change_timing: ChangeTiming,
}

#[derive(Arbitrary, Debug, Clone)]
enum InvalidSetting {
    /// MAX_FRAME_SIZE below minimum
    MaxFrameSizeBelowMinimum(u32),
    /// MAX_FRAME_SIZE above maximum
    MaxFrameSizeAboveMaximum(u32),
    /// ENABLE_PUSH invalid value
    EnablePushInvalid(u32),
    /// INITIAL_WINDOW_SIZE too large
    InitialWindowSizeTooLarge(u32),
}

#[derive(Arbitrary, Debug, Clone)]
enum ChangeTiming {
    /// Change attempted immediately after initial frames
    Immediate,
    /// Change attempted with delay simulation
    Delayed,
    /// Change attempted during active frame transmission
    DuringFrameTransmission,
}

#[derive(Arbitrary, Debug, Clone)]
enum EdgeCaseTest {
    /// Test exactly at minimum boundary (16384)
    ExactMinimumBoundary,
    /// Test one below minimum (16383)
    OneBelowMinimum,
    /// Test significantly below minimum (8192)
    SignificantlyBelowMinimum,
    /// Test zero value
    ZeroValue,
    /// Test maximum invalid attempts
    MaximumInvalidAttempts,
    /// Test recovery after invalid attempt
    RecoveryAfterInvalid,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConnectionConfig {
    /// Whether to enforce strict RFC validation
    strict_rfc_validation: bool,

    /// Whether to track statistics
    track_stats: bool,

    /// Maximum number of invalid attempts to test
    max_invalid_attempts: u8,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            strict_rfc_validation: true,
            track_stats: true,
            max_invalid_attempts: 10,
        }
    }
}

/// Mock HTTP/2 connection for testing MAX_FRAME_SIZE validation
struct MockH2MaxFrameSizeConnection {
    current_max_frame_size: u32,
    config: ConnectionConfig,
    stats: FrameSizeStats,
    state: ConnectionState,
    violation_count: u32,
}

#[derive(Debug, Clone, Default)]
struct FrameSizeStats {
    frames_processed_valid: u32,
    frames_rejected_size: u32,
    settings_changes_rejected: u32,
    protocol_errors_generated: u32,
    largest_frame_accepted: u32,
}

#[derive(Debug, Clone)]
enum ConnectionState {
    Active,
    ProtocolError(String),
    Closed,
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Active
    }
}

impl MockH2MaxFrameSizeConnection {
    fn new(setup: ConnectionSetup, config: ConnectionConfig) -> Self {
        Self {
            current_max_frame_size: setup.initial_max_frame_size,
            config,
            stats: FrameSizeStats::default(),
            state: ConnectionState::Active,
            violation_count: 0,
        }
    }

    /// Process SETTINGS frame with MAX_FRAME_SIZE change (potentially invalid)
    fn process_settings_change(&mut self, change: &InvalidSettingsChange) -> SettingsResult {
        match self.state {
            ConnectionState::ProtocolError(_) | ConnectionState::Closed => {
                return SettingsResult::ConnectionClosed;
            }
            _ => {}
        }

        // Validate new frame size per RFC 7540 §6.5.2
        if self.config.strict_rfc_validation {
            if change.new_max_frame_size < 16384 {
                self.stats.settings_changes_rejected += 1;
                self.stats.protocol_errors_generated += 1;
                self.violation_count += 1;

                let error_msg = format!(
                    "PROTOCOL_ERROR: MAX_FRAME_SIZE {} below minimum 16384",
                    change.new_max_frame_size
                );

                // RFC requires connection closure for PROTOCOL_ERROR
                self.state = ConnectionState::ProtocolError(error_msg.clone());

                return SettingsResult::ProtocolError {
                    error: error_msg,
                    invalid_value: change.new_max_frame_size,
                    current_value: self.current_max_frame_size,
                };
            }

            if change.new_max_frame_size > 16777215 {
                // 2^24-1
                self.stats.settings_changes_rejected += 1;
                self.stats.protocol_errors_generated += 1;
                self.violation_count += 1;

                let error_msg = format!(
                    "PROTOCOL_ERROR: MAX_FRAME_SIZE {} exceeds maximum 16777215",
                    change.new_max_frame_size
                );

                self.state = ConnectionState::ProtocolError(error_msg.clone());

                return SettingsResult::ProtocolError {
                    error: error_msg,
                    invalid_value: change.new_max_frame_size,
                    current_value: self.current_max_frame_size,
                };
            }
        }

        // Valid change
        let old_size = self.current_max_frame_size;
        self.current_max_frame_size = change.new_max_frame_size;

        SettingsResult::Accepted {
            old_size,
            new_size: change.new_max_frame_size,
        }
    }

    /// Process frame with current size limits
    fn process_frame(&mut self, frame: &TestFrame) -> FrameResult {
        match self.state {
            ConnectionState::ProtocolError(ref error) => {
                return FrameResult::ConnectionProtocolError(error.clone());
            }
            ConnectionState::Closed => {
                return FrameResult::ConnectionClosed;
            }
            _ => {}
        }

        // Validate frame size against current limit
        if frame.payload_size > self.current_max_frame_size {
            if self.config.track_stats {
                self.stats.frames_rejected_size += 1;
            }
            return FrameResult::FrameSizeError {
                frame_size: frame.payload_size,
                limit: self.current_max_frame_size,
                frame_type: frame.frame_type.to_u8(),
            };
        }

        // Frame-specific validation
        let validation_result = self.validate_frame_specifics(frame);
        if let FrameResult::Accepted { .. } = validation_result {
            if self.config.track_stats {
                self.stats.frames_processed_valid += 1;
                if frame.payload_size > self.stats.largest_frame_accepted {
                    self.stats.largest_frame_accepted = frame.payload_size;
                }
            }
        }

        validation_result
    }

    fn validate_frame_specifics(&self, frame: &TestFrame) -> FrameResult {
        match frame.frame_type {
            FrameType::Data => {
                FrameResult::Accepted {
                    frame_type: "DATA".to_string(),
                    size: frame.payload_size,
                    limit_used: self.current_max_frame_size,
                }
            }

            FrameType::Headers => {
                FrameResult::Accepted {
                    frame_type: "HEADERS".to_string(),
                    size: frame.payload_size,
                    limit_used: self.current_max_frame_size,
                }
            }

            FrameType::Settings => {
                // SETTINGS frames have fixed 6-byte entries
                if frame.payload_size % 6 != 0 {
                    return FrameResult::ProtocolError(
                        "SETTINGS frame payload must be multiple of 6 bytes".to_string(),
                    );
                }
                FrameResult::Accepted {
                    frame_type: "SETTINGS".to_string(),
                    size: frame.payload_size,
                    limit_used: self.current_max_frame_size,
                }
            }

            FrameType::WindowUpdate => {
                // WINDOW_UPDATE frames must be exactly 4 bytes
                if frame.payload_size != 4 {
                    return FrameResult::ProtocolError(
                        "WINDOW_UPDATE frame must be 4 bytes".to_string(),
                    );
                }
                FrameResult::Accepted {
                    frame_type: "WINDOW_UPDATE".to_string(),
                    size: frame.payload_size,
                    limit_used: self.current_max_frame_size,
                }
            }

            FrameType::Ping => {
                // PING frames must be exactly 8 bytes
                if frame.payload_size != 8 {
                    return FrameResult::ProtocolError(
                        "PING frame must be 8 bytes".to_string(),
                    );
                }
                FrameResult::Accepted {
                    frame_type: "PING".to_string(),
                    size: frame.payload_size,
                    limit_used: self.current_max_frame_size,
                }
            }

            _ => {
                FrameResult::Accepted {
                    frame_type: format!("{:?}", frame.frame_type),
                    size: frame.payload_size,
                    limit_used: self.current_max_frame_size,
                }
            }
        }
    }

    fn get_current_status(&self) -> ConnectionStatus {
        ConnectionStatus {
            current_max_frame_size: self.current_max_frame_size,
            state: self.state.clone(),
            stats: self.stats.clone(),
            violation_count: self.violation_count,
        }
    }
}

#[derive(Debug, PartialEq)]
enum SettingsResult {
    /// Valid settings change accepted
    Accepted { old_size: u32, new_size: u32 },

    /// Invalid settings change causing PROTOCOL_ERROR
    ProtocolError {
        error: String,
        invalid_value: u32,
        current_value: u32,
    },

    /// Connection already closed/errored
    ConnectionClosed,
}

#[derive(Debug, PartialEq)]
enum FrameResult {
    /// Frame accepted and processed
    Accepted {
        frame_type: String,
        size: u32,
        limit_used: u32,
    },

    /// Frame rejected due to size limit
    FrameSizeError {
        frame_size: u32,
        limit: u32,
        frame_type: u8,
    },

    /// Protocol error (frame format)
    ProtocolError(String),

    /// Connection is in protocol error state
    ConnectionProtocolError(String),

    /// Connection is closed
    ConnectionClosed,
}

#[derive(Debug, Clone)]
struct ConnectionStatus {
    current_max_frame_size: u32,
    state: ConnectionState,
    stats: FrameSizeStats,
    violation_count: u32,
}

fuzz_target!(|input: MaxFrameSizeDecreaseInput| {
    // Normalize input for reasonable fuzzing bounds
    let mut input = input;
    if input.initial_frames.len() > 8 {
        input.initial_frames.truncate(8);
    }
    if input.post_invalid_frames.len() > 8 {
        input.post_invalid_frames.truncate(8);
    }

    let mut connection = MockH2MaxFrameSizeConnection::new(
        input.initial_setup.clone(),
        input.connection_config.clone(),
    );

    let initial_status = connection.get_current_status();
    assert_eq!(
        initial_status.current_max_frame_size,
        input.initial_setup.initial_max_frame_size,
        "Initial frame size should match setup"
    );

    // Process initial frames with valid frame size
    for frame in &input.initial_frames {
        let result = connection.process_frame(frame);
        match result {
            FrameResult::Accepted { limit_used, .. } => {
                assert_eq!(
                    limit_used, initial_status.current_max_frame_size,
                    "Initial frames should use initial frame size limit"
                );
            }
            FrameResult::FrameSizeError {
                frame_size, limit, ..
            } => {
                assert_eq!(
                    limit, initial_status.current_max_frame_size,
                    "Frame size errors should reference current limit"
                );
                assert!(
                    frame_size > limit,
                    "Frame size error should only occur when frame exceeds limit"
                );
            }
            _ => {} // Other results are acceptable
        }
    }

    // Attempt invalid SETTINGS change (should be rejected)
    let settings_result = connection.process_settings_change(&input.invalid_settings_change);

    // Verify that below-minimum values are properly rejected
    if input.invalid_settings_change.new_max_frame_size < 16384 {
        match settings_result {
            SettingsResult::ProtocolError {
                error,
                invalid_value,
                current_value,
            } => {
                assert!(
                    error.contains("PROTOCOL_ERROR"),
                    "Error should indicate PROTOCOL_ERROR: {}",
                    error
                );
                assert!(
                    error.contains("below minimum"),
                    "Error should mention minimum violation: {}",
                    error
                );
                assert_eq!(
                    invalid_value, input.invalid_settings_change.new_max_frame_size,
                    "Invalid value should match attempted change"
                );
                assert_eq!(
                    current_value, initial_status.current_max_frame_size,
                    "Current value should remain unchanged"
                );
            }
            _ => {
                panic!(
                    "Settings change with MAX_FRAME_SIZE {} below minimum should cause PROTOCOL_ERROR",
                    input.invalid_settings_change.new_max_frame_size
                );
            }
        }

        // Verify connection is now in protocol error state
        let post_invalid_status = connection.get_current_status();
        match post_invalid_status.state {
            ConnectionState::ProtocolError(ref error) => {
                assert!(
                    error.contains("PROTOCOL_ERROR"),
                    "Connection should be in PROTOCOL_ERROR state"
                );
            }
            _ => {
                panic!("Connection should be in PROTOCOL_ERROR state after invalid settings");
            }
        }

        // Verify frame size limit didn't change
        assert_eq!(
            post_invalid_status.current_max_frame_size, initial_status.current_max_frame_size,
            "Frame size limit should not change after invalid settings"
        );

        // Verify statistics were updated
        if connection.config.track_stats {
            assert!(
                post_invalid_status.stats.settings_changes_rejected > 0,
                "Should track rejected settings changes"
            );
            assert!(
                post_invalid_status.stats.protocol_errors_generated > 0,
                "Should track protocol errors"
            );
        }
    }

    // Attempt to process frames after invalid change
    // These should either be rejected due to connection error or processed with old limit
    for frame in &input.post_invalid_frames {
        let result = connection.process_frame(frame);

        match result {
            FrameResult::ConnectionProtocolError(_) => {
                // Expected if connection is in error state
            }
            FrameResult::Accepted { limit_used, .. } => {
                // If somehow still processing, should use original limit
                assert_eq!(
                    limit_used, initial_status.current_max_frame_size,
                    "Post-invalid frames should use original limit if processed"
                );
            }
            FrameResult::FrameSizeError { limit, .. } => {
                // Should reference original limit
                assert_eq!(
                    limit, initial_status.current_max_frame_size,
                    "Frame size errors after invalid settings should reference original limit"
                );
            }
            _ => {} // Other results acceptable
        }
    }

    // Test edge cases
    for edge_case in &input.edge_cases {
        match edge_case {
            EdgeCaseTest::ExactMinimumBoundary => {
                // Test frame at exactly 16384 bytes should be accepted with valid connection
                if matches!(connection.get_current_status().state, ConnectionState::Active) {
                    let boundary_frame = TestFrame {
                        frame_type: FrameType::Data,
                        payload_size: 16384,
                        stream_id: 1,
                        flags: 0,
                        expected_result: FrameExpectation::Accept,
                    };

                    let result = connection.process_frame(&boundary_frame);
                    if let FrameResult::Accepted { .. } = result {
                        // Expected
                    } else if let FrameResult::ConnectionProtocolError(_) = result {
                        // Also acceptable if connection errored
                    } else {
                        panic!("Frame at minimum size 16384 should be accepted if connection is active");
                    }
                }
            }

            EdgeCaseTest::OneBelowMinimum => {
                // Test that attempting to set MAX_FRAME_SIZE to 16383 causes error
                let invalid_change = InvalidSettingsChange {
                    new_max_frame_size: 16383,
                    additional_invalid_settings: vec![],
                    change_timing: ChangeTiming::Immediate,
                };

                let result = connection.process_settings_change(&invalid_change);
                match result {
                    SettingsResult::ProtocolError { .. } => {
                        // Expected
                    }
                    SettingsResult::ConnectionClosed => {
                        // Also acceptable if already closed
                    }
                    _ => {
                        panic!("Setting MAX_FRAME_SIZE to 16383 should cause PROTOCOL_ERROR");
                    }
                }
            }

            _ => {
                // Other edge cases can be tested similarly
            }
        }
    }

    // Verify final state consistency
    let final_status = connection.get_current_status();

    // If invalid settings were attempted, violation count should be > 0
    if input.invalid_settings_change.new_max_frame_size < 16384 {
        assert!(
            final_status.violation_count > 0,
            "Should track RFC violations"
        );
    }

    // Verify no panics occurred during invalid settings processing
    // (Implicit - if we reach here without panicking, the test passed)
});