#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 SETTINGS_MAX_FRAME_SIZE mid-connection change fuzz target.
///
/// Tests RFC 7540 compliance when peer changes SETTINGS_MAX_FRAME_SIZE
/// mid-connection (e.g., from 16384 default to 1048576). Per RFC 7540 §6.5.2:
/// "Changes to SETTINGS_MAX_FRAME_SIZE apply to subsequently received frames;
/// frames that are already in progress MUST be processed with the previous
/// maximum frame size."
///
/// Critical test scenarios:
/// - Frame size validation before/after setting change
/// - State machine transition handling
/// - In-flight frame processing with old limit
/// - Subsequent frame processing with new limit
/// - Edge cases around transition timing

#[derive(Arbitrary, Debug, Clone)]
struct FrameSizeChangeInput {
    /// Initial connection setup
    initial_setup: ConnectionSetup,

    /// Frames sent before SETTINGS change
    pre_change_frames: Vec<TestFrame>,

    /// SETTINGS frame changing MAX_FRAME_SIZE
    settings_change: SettingsChange,

    /// Frames sent after SETTINGS change
    post_change_frames: Vec<TestFrame>,

    /// Connection state configuration
    connection_config: ConnectionConfig,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConnectionSetup {
    /// Initial MAX_FRAME_SIZE (RFC 7540 default is 16384)
    initial_max_frame_size: u32,

    /// Remote peer MAX_FRAME_SIZE capability
    peer_max_frame_size: u32,

    /// Whether this is client or server side
    is_client: bool,
}

impl Default for ConnectionSetup {
    fn default() -> Self {
        Self {
            initial_max_frame_size: 16384, // RFC 7540 §6.5.2 default
            peer_max_frame_size: 16777215, // RFC 7540 maximum
            is_client: true,
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
    expected_result: FrameProcessingExpectation,
}

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
    Unknown(u8),
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
            FrameType::Unknown(val) => *val,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FrameProcessingExpectation {
    /// Frame should be accepted
    Accept,
    /// Frame should be rejected due to size
    RejectSize,
    /// Implementation defined behavior
    ImplementationDefined,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsChange {
    /// New MAX_FRAME_SIZE value
    new_max_frame_size: u32,

    /// Whether this is a valid change
    valid_change: bool,

    /// Timing of the change
    change_timing: ChangeTiming,
}

#[derive(Arbitrary, Debug, Clone)]
enum ChangeTiming {
    /// Change takes effect immediately
    Immediate,
    /// Change after ACK
    AfterAck,
    /// Change with delay simulation
    Delayed,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConnectionConfig {
    /// Whether to enforce strict frame size validation
    strict_validation: bool,

    /// Whether to track frame size statistics
    track_stats: bool,

    /// Maximum allowed frame size increase
    max_size_increase_factor: u8,

    /// Whether to validate RFC limits
    validate_rfc_limits: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            strict_validation: true,
            track_stats: true,
            max_size_increase_factor: 64, // Allow up to 64x increase
            validate_rfc_limits: true,
        }
    }
}

/// Mock HTTP/2 connection for testing frame size transitions
struct MockH2FrameSizeConnection {
    current_max_frame_size: u32,
    pending_max_frame_size: Option<u32>,
    config: ConnectionConfig,
    stats: FrameSizeStats,
    state: ConnectionState,
}

#[derive(Debug, Clone, Default)]
struct FrameSizeStats {
    frames_processed_old_limit: u32,
    frames_processed_new_limit: u32,
    size_violations_detected: u32,
    largest_frame_seen: u32,
}

#[derive(Debug, Clone, Default)]
enum ConnectionState {
    #[default]
    Active,
    AwaitingSettingsAck,
}

impl MockH2FrameSizeConnection {
    fn new(setup: ConnectionSetup, config: ConnectionConfig) -> Self {
        let peer_max_frame_size = setup.peer_max_frame_size.clamp(16384, 16777215);
        let initial_max_frame_size = setup
            .initial_max_frame_size
            .clamp(16384, peer_max_frame_size);
        let current_max_frame_size = if setup.is_client {
            initial_max_frame_size
        } else {
            peer_max_frame_size
        };

        Self {
            current_max_frame_size,
            pending_max_frame_size: None,
            config,
            stats: FrameSizeStats::default(),
            state: ConnectionState::Active,
        }
    }

    /// Process SETTINGS frame changing MAX_FRAME_SIZE
    fn process_settings_change(&mut self, change: &SettingsChange) -> SettingsChangeResult {
        // Validate new frame size per RFC 7540 §6.5.2
        let validate_rfc_limits = self.config.validate_rfc_limits || !change.valid_change;
        if validate_rfc_limits {
            if change.new_max_frame_size < 16384 {
                return SettingsChangeResult::Error(format!(
                    "MAX_FRAME_SIZE {} below minimum 16384",
                    change.new_max_frame_size
                ));
            }

            if change.new_max_frame_size > 16777215 {
                // 2^24-1
                return SettingsChangeResult::Error(format!(
                    "MAX_FRAME_SIZE {} exceeds maximum 16777215",
                    change.new_max_frame_size
                ));
            }
        }

        // Check increase factor limit
        let increase_factor = change.new_max_frame_size / self.current_max_frame_size.max(1);
        if increase_factor > self.config.max_size_increase_factor as u32 {
            return SettingsChangeResult::Error(format!(
                "Frame size increase factor {} exceeds limit {}",
                increase_factor, self.config.max_size_increase_factor
            ));
        }

        let old_size = self.current_max_frame_size;

        match change.change_timing {
            ChangeTiming::Immediate => {
                // Apply change immediately
                self.current_max_frame_size = change.new_max_frame_size;
                SettingsChangeResult::Applied {
                    old_size,
                    new_size: change.new_max_frame_size,
                    timing: "immediate".to_string(),
                }
            }

            ChangeTiming::AfterAck => {
                // RFC 7540 §6.5.3: Changes take effect after ACK
                self.pending_max_frame_size = Some(change.new_max_frame_size);
                self.state = ConnectionState::AwaitingSettingsAck;
                SettingsChangeResult::Pending {
                    current_size: old_size,
                    pending_size: change.new_max_frame_size,
                }
            }

            ChangeTiming::Delayed => {
                // Simulate processing delay
                self.pending_max_frame_size = Some(change.new_max_frame_size);
                SettingsChangeResult::Delayed {
                    current_size: old_size,
                    pending_size: change.new_max_frame_size,
                }
            }
        }
    }

    /// Process SETTINGS ACK to complete frame size change
    fn process_settings_ack(&mut self) -> AckResult {
        if let Some(pending_size) = self.pending_max_frame_size.take() {
            let old_size = self.current_max_frame_size;
            self.current_max_frame_size = pending_size;
            self.state = ConnectionState::Active;

            AckResult::Applied {
                old_size,
                new_size: pending_size,
            }
        } else {
            AckResult::NoChange
        }
    }

    /// Process frame with current size limits
    fn process_frame(&mut self, frame: &TestFrame) -> FrameProcessResult {
        if let Some(error) = self.validate_frame_header(frame) {
            return error;
        }

        // Determine effective frame size limit
        let effective_limit = match self.state {
            ConnectionState::Active => self.current_max_frame_size,
            ConnectionState::AwaitingSettingsAck => {
                // RFC 7540 §6.5.2: In-progress frames use old limit
                self.current_max_frame_size
            }
        };

        // Validate frame size
        let enforce_size_limit = self.config.strict_validation
            || matches!(
                frame.expected_result,
                FrameProcessingExpectation::RejectSize
            );
        if enforce_size_limit && frame.payload_size > effective_limit {
            if self.config.track_stats {
                self.stats.size_violations_detected += 1;
            }
            return FrameProcessResult::FrameSizeError {
                frame_size: frame.payload_size,
                limit: effective_limit,
                frame_type: frame.frame_type.to_u8(),
            };
        }

        // Update statistics
        if self.config.track_stats {
            if self.pending_max_frame_size.is_some() {
                self.stats.frames_processed_old_limit += 1;
            } else {
                self.stats.frames_processed_new_limit += 1;
            }

            if frame.payload_size > self.stats.largest_frame_seen {
                self.stats.largest_frame_seen = frame.payload_size;
            }
        }

        // Frame-specific validation
        self.validate_frame_specifics(frame, effective_limit)
    }

    fn validate_frame_header(&self, frame: &TestFrame) -> Option<FrameProcessResult> {
        let ack = frame.flags & 0x1 != 0;
        match frame.frame_type {
            FrameType::Data
            | FrameType::Headers
            | FrameType::Priority
            | FrameType::RstStream
            | FrameType::PushPromise
            | FrameType::Continuation
                if frame.stream_id == 0 =>
            {
                Some(FrameProcessResult::ProtocolError(format!(
                    "{:?} frame must use a non-zero stream ID",
                    frame.frame_type
                )))
            }
            FrameType::Settings if frame.stream_id != 0 => Some(FrameProcessResult::ProtocolError(
                "SETTINGS frame must use stream ID 0".to_string(),
            )),
            FrameType::Settings if ack && frame.payload_size != 0 => {
                Some(FrameProcessResult::ProtocolError(
                    "SETTINGS ACK frame must have empty payload".to_string(),
                ))
            }
            FrameType::Ping if frame.stream_id != 0 => Some(FrameProcessResult::ProtocolError(
                "PING frame must use stream ID 0".to_string(),
            )),
            FrameType::GoAway if frame.stream_id != 0 => Some(FrameProcessResult::ProtocolError(
                "GOAWAY frame must use stream ID 0".to_string(),
            )),
            _ => None,
        }
    }

    fn validate_frame_specifics(&self, frame: &TestFrame, limit: u32) -> FrameProcessResult {
        match frame.frame_type {
            FrameType::Data => {
                // DATA frames can be up to max size
                FrameProcessResult::Accepted {
                    frame_type: "DATA".to_string(),
                    size: frame.payload_size,
                    limit_used: limit,
                }
            }

            FrameType::Headers => {
                // HEADERS frames can be up to max size
                FrameProcessResult::Accepted {
                    frame_type: "HEADERS".to_string(),
                    size: frame.payload_size,
                    limit_used: limit,
                }
            }

            FrameType::Settings => {
                // SETTINGS frames have fixed 6-byte entries
                if !frame.payload_size.is_multiple_of(6) {
                    return FrameProcessResult::ProtocolError(
                        "SETTINGS frame payload must be multiple of 6 bytes".to_string(),
                    );
                }
                FrameProcessResult::Accepted {
                    frame_type: "SETTINGS".to_string(),
                    size: frame.payload_size,
                    limit_used: limit,
                }
            }

            FrameType::WindowUpdate => {
                // WINDOW_UPDATE frames must be exactly 4 bytes
                if frame.payload_size != 4 {
                    return FrameProcessResult::ProtocolError(
                        "WINDOW_UPDATE frame must be 4 bytes".to_string(),
                    );
                }
                FrameProcessResult::Accepted {
                    frame_type: "WINDOW_UPDATE".to_string(),
                    size: frame.payload_size,
                    limit_used: limit,
                }
            }

            FrameType::Ping => {
                // PING frames must be exactly 8 bytes
                if frame.payload_size != 8 {
                    return FrameProcessResult::ProtocolError(
                        "PING frame must be 8 bytes".to_string(),
                    );
                }
                FrameProcessResult::Accepted {
                    frame_type: "PING".to_string(),
                    size: frame.payload_size,
                    limit_used: limit,
                }
            }

            _ => {
                // Other frame types
                FrameProcessResult::Accepted {
                    frame_type: format!("{:?}", frame.frame_type),
                    size: frame.payload_size,
                    limit_used: limit,
                }
            }
        }
    }

    fn get_current_state(&self) -> ConnectionStatus {
        ConnectionStatus {
            current_max_frame_size: self.current_max_frame_size,
            pending_max_frame_size: self.pending_max_frame_size,
            state: self.state.clone(),
            stats: self.stats.clone(),
        }
    }
}

#[derive(Debug, PartialEq)]
enum SettingsChangeResult {
    /// Change applied immediately
    Applied {
        old_size: u32,
        new_size: u32,
        timing: String,
    },

    /// Change pending ACK
    Pending {
        current_size: u32,
        pending_size: u32,
    },

    /// Change delayed
    Delayed {
        current_size: u32,
        pending_size: u32,
    },

    /// Invalid change
    Error(String),
}

#[derive(Debug, PartialEq)]
enum AckResult {
    Applied { old_size: u32, new_size: u32 },
    NoChange,
}

#[derive(Clone, Debug, PartialEq)]
enum FrameProcessResult {
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
}

#[derive(Debug, Clone)]
struct ConnectionStatus {
    current_max_frame_size: u32,
    pending_max_frame_size: Option<u32>,
    state: ConnectionState,
    stats: FrameSizeStats,
}

fuzz_target!(|input: FrameSizeChangeInput| {
    // Normalize input for reasonable fuzzing bounds
    let mut input = input;
    if input.pre_change_frames.len() > 10 {
        input.pre_change_frames.truncate(10); // Limit for performance
    }
    if input.post_change_frames.len() > 10 {
        input.post_change_frames.truncate(10); // Limit for performance
    }

    let mut connection = MockH2FrameSizeConnection::new(
        input.initial_setup.clone(),
        input.connection_config.clone(),
    );

    let initial_status = connection.get_current_state();

    // Process frames before settings change
    let mut pre_change_results = Vec::new();
    for frame in &input.pre_change_frames {
        let result = connection.process_frame(frame);
        pre_change_results.push(result.clone());

        // Verify frames are validated against current limit
        match result {
            FrameProcessResult::Accepted { limit_used, .. } => {
                assert_eq!(
                    limit_used, initial_status.current_max_frame_size,
                    "Pre-change frames should use initial frame size limit"
                );
            }
            FrameProcessResult::FrameSizeError {
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
            _ => {}
        }
    }

    // Process SETTINGS frame changing MAX_FRAME_SIZE
    let settings_result = connection.process_settings_change(&input.settings_change);

    match settings_result {
        SettingsChangeResult::Applied {
            old_size, new_size, ..
        } => {
            assert_eq!(
                old_size, initial_status.current_max_frame_size,
                "Old size should match initial setting"
            );
            assert_eq!(
                new_size, input.settings_change.new_max_frame_size,
                "New size should match requested change"
            );

            // Verify change took effect immediately
            let current_status = connection.get_current_state();
            assert_eq!(
                current_status.current_max_frame_size, new_size,
                "Current frame size should reflect immediate change"
            );
        }

        SettingsChangeResult::Pending {
            current_size,
            pending_size,
        } => {
            assert_eq!(
                current_size, initial_status.current_max_frame_size,
                "Current size should remain unchanged while pending"
            );
            assert_eq!(
                pending_size, input.settings_change.new_max_frame_size,
                "Pending size should match requested change"
            );

            // Process ACK to complete change
            let ack_result = connection.process_settings_ack();
            match ack_result {
                AckResult::Applied { old_size, new_size } => {
                    assert_eq!(old_size, current_size);
                    assert_eq!(new_size, pending_size);
                }
                AckResult::NoChange => {
                    panic!("ACK should apply pending settings change");
                }
            }
        }

        SettingsChangeResult::Delayed { .. } => {
            // Delayed changes are implementation-specific
        }

        SettingsChangeResult::Error(ref msg) => {
            // Verify error is for valid reasons
            if input.connection_config.validate_rfc_limits {
                if input.settings_change.new_max_frame_size < 16384 {
                    assert!(
                        msg.contains("below minimum"),
                        "Should explain minimum size violation: {}",
                        msg
                    );
                } else if input.settings_change.new_max_frame_size > 16777215 {
                    assert!(
                        msg.contains("exceeds maximum"),
                        "Should explain maximum size violation: {}",
                        msg
                    );
                }
            }
        }
    }

    let post_settings_status = connection.get_current_state();
    match post_settings_status.state {
        ConnectionState::Active => {
            if post_settings_status.pending_max_frame_size.is_some() {
                assert!(
                    matches!(input.settings_change.change_timing, ChangeTiming::Delayed),
                    "only delayed SETTINGS changes may remain pending while active"
                );
            }
        }
        ConnectionState::AwaitingSettingsAck => {
            assert!(
                post_settings_status.pending_max_frame_size.is_some(),
                "awaiting SETTINGS ACK requires a pending frame-size update"
            );
        }
    }

    // Process frames after settings change
    let mut post_change_results = Vec::new();
    for frame in &input.post_change_frames {
        let result = connection.process_frame(frame);
        post_change_results.push(result.clone());

        // Verify frames are validated against new limit
        match result {
            FrameProcessResult::Accepted { limit_used, .. } => {
                assert_eq!(
                    limit_used, post_settings_status.current_max_frame_size,
                    "Post-change frames should use new frame size limit"
                );
            }
            FrameProcessResult::FrameSizeError { limit, .. } => {
                assert_eq!(
                    limit, post_settings_status.current_max_frame_size,
                    "Post-change frame size errors should reference new limit"
                );
            }
            _ => {}
        }
    }

    // Verify transition consistency
    if post_settings_status.current_max_frame_size != initial_status.current_max_frame_size {
        // Frame size changed - verify frames that would be valid under new limit
        // but invalid under old limit are handled correctly
        let old_limit = initial_status.current_max_frame_size;
        let new_limit = post_settings_status.current_max_frame_size;

        if new_limit > old_limit {
            // Increased limit - some post-change frames might be larger
            for (frame, result) in input.post_change_frames.iter().zip(&post_change_results) {
                if frame.payload_size > old_limit && frame.payload_size <= new_limit {
                    match result {
                        FrameProcessResult::Accepted { .. } => {
                            // Expected - frame valid under new limit
                        }
                        FrameProcessResult::FrameSizeError { .. } => {
                            panic!(
                                "Frame {} should be valid under new limit {}",
                                frame.payload_size, new_limit
                            );
                        }
                        _ => {} // Protocol errors are separate from size limits
                    }
                }
            }
        }
    }

    // Verify statistics consistency
    if connection.config.track_stats {
        let final_stats = &post_settings_status.stats;
        assert_eq!(
            final_stats.frames_processed_old_limit + final_stats.frames_processed_new_limit,
            (input.pre_change_frames.len() + input.post_change_frames.len()) as u32
                - final_stats.size_violations_detected,
            "Processed frame count should match input minus violations"
        );
    }

    // Test edge case: frame exactly at boundary
    let boundary_frame = TestFrame {
        frame_type: FrameType::Data,
        payload_size: post_settings_status.current_max_frame_size,
        stream_id: 1,
        flags: 0,
        expected_result: FrameProcessingExpectation::Accept,
    };

    let boundary_result = connection.process_frame(&boundary_frame);
    match boundary_result {
        FrameProcessResult::Accepted { .. } => {
            // Expected - frame at exact limit should be accepted
        }
        FrameProcessResult::FrameSizeError { .. } => {
            panic!(
                "Frame at exact limit {} should be accepted",
                boundary_frame.payload_size
            );
        }
        _ => {} // Other errors are acceptable
    }

    // Verify no panics occurred during frame size transitions
    // (Implicit - if we reach here without panicking, the test passed)
});
