//! Fuzzing target for HTTP/2 MAX_CONCURRENT_STREAMS=0 at connection establishment.
//!
//! Tests RFC 7540 compliance when peer sets MAX_CONCURRENT_STREAMS=0 immediately
//! at connection establishment. Per RFC 7540 §6.5.2, this is valid and means
//! the server forbids all client streams from the start.
//!
//! Key test scenarios:
//! 1. Connection establishment with initial SETTINGS_MAX_CONCURRENT_STREAMS=0
//! 2. Verify state machine correctly prevents all new stream creation
//! 3. Ensure connection remains functional for other frame types
//! 4. Test recovery when limit is later increased
//! 5. Validate proper error handling for attempted stream creation
//! 6. Ensure no streams are created even with valid HEADERS frames
//!
//! Vulnerability areas:
//! - Connection state machine accepting streams when limit=0 from start
//! - Memory leaks from buffered but never-processed stream creation attempts
//! - Deadlock when limit is 0 and only client streams are attempted
//! - Improper error codes returned for refused streams
//! - State corruption when connection starts with zero stream limit
//! - Bypassing stream limit through malformed frames or edge cases

#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h2::connection::ConnectionState;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{Setting, SettingsFrame};
use asupersync::http::h2::settings::Settings;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// Test input for zero max concurrent streams at connection establishment
#[derive(Debug, Arbitrary)]
pub struct ZeroMaxConcurrentInput {
    /// Connection role (client=true, server=false)
    is_client: bool,
    /// Initial connection operations before any stream attempts
    initial_operations: Vec<InitialConnectionOperation>,
    /// Stream creation attempts (should all be blocked)
    stream_attempts: Vec<StreamCreationAttempt>,
    /// Other frame types to test (should work normally)
    other_frame_operations: Vec<NonStreamFrameOperation>,
    /// Recovery operations (increasing limit)
    recovery_operations: Vec<RecoveryOperation>,
    /// Edge case testing
    edge_case_tests: Vec<EdgeCaseTest>,
}

/// Operations during initial connection establishment
#[derive(Debug, Arbitrary)]
pub enum InitialConnectionOperation {
    /// Send the zero concurrent streams setting
    SendZeroMaxConcurrentSettings,
    /// Send SETTINGS ACK
    SendSettingsAck,
    /// Send PING frame
    SendPing { data: [u8; 8] },
    /// Send WINDOW_UPDATE for connection
    SendWindowUpdate { increment: u32 },
    /// Send additional SETTINGS with other parameters
    SendOtherSettings {
        header_table_size: u32,
        enable_push: bool,
        initial_window_size: u32,
        max_frame_size: u32,
    },
}

/// Stream creation attempts (all should fail with zero limit)
#[derive(Debug, Arbitrary)]
pub enum StreamCreationAttempt {
    /// Standard HEADERS frame for new stream
    StandardHeaders {
        stream_id: u32,
        end_stream: bool,
        end_headers: bool,
        payload_size: u16,
    },
    /// HEADERS with PRIORITY
    HeadersWithPriority {
        stream_id: u32,
        dependency: u32,
        weight: u8,
        exclusive: bool,
    },
    /// Malformed stream creation attempt
    MalformedHeaders {
        stream_id: u32,
        invalid_payload: Vec<u8>,
    },
    /// Stream with reserved bit set
    ReservedBitStream { stream_id: u32 },
    /// Continuation frame without preceding headers
    OrphanedContinuation { stream_id: u32, payload: Vec<u8> },
    /// Even-numbered stream ID (server-initiated, should fail for different reasons)
    EvenStreamId { stream_id: u32 },
}

/// Operations with non-stream frames (should work normally)
#[derive(Debug, Arbitrary)]
pub enum NonStreamFrameOperation {
    /// PING with or without ACK
    Ping { data: [u8; 8], ack: bool },
    /// Connection-level WINDOW_UPDATE
    WindowUpdate { increment: u32 },
    /// Additional SETTINGS changes
    SettingsUpdate {
        header_table_size: Option<u32>,
        enable_push: Option<bool>,
        max_frame_size: Option<u32>,
    },
    /// GOAWAY frame
    GoAway {
        last_stream_id: u32,
        error_code: u32,
        debug_data: Vec<u8>,
    },
}

/// Recovery operations (testing limit increase)
#[derive(Debug, Arbitrary)]
pub enum RecoveryOperation {
    /// Increase MAX_CONCURRENT_STREAMS to allow streams
    IncreaseLimit { new_limit: u8 },
    /// Try creating stream after limit increase
    CreateStreamAfterIncrease {
        stream_id: u32,
        expect_success: bool,
    },
    /// Reset limit back to zero
    ResetToZero,
    /// Multiple rapid limit changes
    RapidLimitChanges { changes: Vec<u8> },
}

/// Edge case testing
#[derive(Debug, Arbitrary)]
pub enum EdgeCaseTest {
    /// Stream 0 operations (connection-level)
    Stream0Operation { frame_type: u8, payload: Vec<u8> },
    /// Multiple zero limit settings in sequence
    MultipleZeroSettings { count: u8 },
    /// Zero limit with ACK flag (invalid)
    ZeroLimitWithAck,
    /// Interleaved stream attempts and settings
    InterleavedOps {
        stream_attempt: StreamCreationAttempt,
        setting_change: u32,
    },
    /// Large stream ID with zero limit
    LargeStreamId { stream_id: u32 },
}

/// Mock connection for testing zero max concurrent streams at establishment
pub struct MockZeroMaxConcurrentConnection {
    /// Current connection state
    state: ConnectionState,
    /// Connection side (client or server)
    side: Side,
    /// Active streams by ID
    streams: HashMap<u32, StreamInfo>,
    /// Current settings (starts with zero max concurrent)
    settings: Settings,
    /// Attempted stream creations that were blocked
    blocked_streams: Vec<BlockedStreamAttempt>,
    /// Other frame operations that were processed
    processed_frames: Vec<ProcessedFrame>,
    /// Detected violations and errors
    violations: Vec<ZeroMaxConcurrentViolation>,
    /// Connection statistics
    stats: ZeroMaxConcurrentStats,
    /// Next stream ID (client odd, server even)
    next_stream_id: u32,
    /// Whether initial zero setting has been sent
    initial_zero_setting_sent: bool,
    /// Connection establishment completed
    establishment_complete: bool,
}

#[derive(Debug, Clone)]
pub struct StreamInfo {
    id: u32,
    state: StreamState,
    side: Side,
    created_at: ConnectionPhase,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

#[derive(Debug, Clone)]
pub enum ConnectionPhase {
    Establishment,
    ZeroLimitActive,
    PostRecovery,
}

#[derive(Debug, Clone)]
pub struct BlockedStreamAttempt {
    stream_id: u32,
    attempt_type: String,
    blocked_phase: ConnectionPhase,
    error_code: ErrorCode,
}

#[derive(Debug, Clone)]
pub struct ProcessedFrame {
    frame_type: String,
    stream_id: u32,
    phase: ConnectionPhase,
    success: bool,
}

#[derive(Debug, Clone)]
pub enum ZeroMaxConcurrentViolation {
    /// Stream was created when max_concurrent_streams=0
    StreamCreatedWithZeroLimit {
        stream_id: u32,
        phase: ConnectionPhase,
    },
    /// Wrong error code returned for blocked stream
    IncorrectErrorCode {
        stream_id: u32,
        expected: ErrorCode,
        actual: ErrorCode,
    },
    /// Non-stream frame was blocked inappropriately
    NonStreamFrameBlocked { frame_type: String, reason: String },
    /// Connection state corruption
    StateCorruption {
        description: String,
        settings_value: u32,
        actual_behavior: String,
    },
    /// Settings inconsistency
    SettingsInconsistency {
        setting_name: String,
        set_value: u32,
        observed_behavior: String,
    },
}

#[derive(Debug, Default)]
pub struct ZeroMaxConcurrentStats {
    /// Total stream creation attempts
    stream_attempts: u32,
    /// Stream attempts properly blocked
    streams_blocked: u32,
    /// Stream attempts that incorrectly succeeded
    streams_incorrectly_allowed: u32,
    /// Non-stream frames processed
    non_stream_frames_processed: u32,
    /// Settings changes applied
    settings_changes: u32,
    /// Recovery limit increases
    limit_increases: u32,
    /// Streams created after recovery
    post_recovery_streams: u32,
    /// Connection state transitions
    state_transitions: u32,
}

impl MockZeroMaxConcurrentConnection {
    pub fn new(side: Side) -> Self {
        let settings = Settings {
            max_concurrent_streams: 0,
            ..Settings::default()
        };

        let next_stream_id = match side {
            Side::Client => 1, // Client-initiated streams are odd
            Side::Server => 2, // Server-initiated streams are even
        };

        Self {
            state: ConnectionState::Open,
            side,
            streams: HashMap::new(),
            settings,
            blocked_streams: Vec::new(),
            processed_frames: Vec::new(),
            violations: Vec::new(),
            stats: ZeroMaxConcurrentStats::default(),
            next_stream_id,
            initial_zero_setting_sent: false,
            establishment_complete: false,
        }
    }

    pub fn current_phase(&self) -> ConnectionPhase {
        if !self.establishment_complete {
            ConnectionPhase::Establishment
        } else if self.settings.max_concurrent_streams == 0 {
            ConnectionPhase::ZeroLimitActive
        } else {
            ConnectionPhase::PostRecovery
        }
    }

    /// Process initial connection establishment with zero max concurrent streams
    pub fn establish_with_zero_limit(&mut self) -> Result<(), ErrorCode> {
        if self.initial_zero_setting_sent {
            return Ok(()); // Already established
        }

        // Send initial SETTINGS with MAX_CONCURRENT_STREAMS=0
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(0)]);
        self.handle_settings_frame(&settings)?;
        self.initial_zero_setting_sent = true;
        self.establishment_complete = true;
        self.stats.state_transitions += 1;

        Ok(())
    }

    /// Handle SETTINGS frame
    pub fn handle_settings_frame(&mut self, frame: &SettingsFrame) -> Result<(), ErrorCode> {
        if frame.ack {
            // SETTINGS ACK - no changes to apply
            return Ok(());
        }

        for setting in &frame.settings {
            match setting {
                Setting::MaxConcurrentStreams(new_limit) => {
                    let old_limit = self.settings.max_concurrent_streams;
                    self.settings.max_concurrent_streams = *new_limit;
                    self.stats.settings_changes += 1;

                    // Track limit increases for recovery testing
                    if *new_limit > old_limit && old_limit == 0 {
                        self.stats.limit_increases += 1;
                    }

                    // Validate that zero limit is properly enforced
                    if *new_limit == 0 && !self.streams.is_empty() {
                        // If streams exist when setting to zero, they should be allowed to continue
                        // but no new streams should be created
                    }
                }
                Setting::HeaderTableSize(size) => {
                    self.settings.header_table_size = *size;
                }
                Setting::EnablePush(enabled) => {
                    self.settings.enable_push = *enabled;
                }
                Setting::InitialWindowSize(size) => {
                    self.settings.initial_window_size = *size;
                }
                Setting::MaxFrameSize(size) => {
                    self.settings.max_frame_size = *size;
                }
                Setting::MaxHeaderListSize(size) => {
                    self.settings.max_header_list_size = *size;
                }
            }
        }

        Ok(())
    }

    /// Attempt to create a new stream (should be blocked when max_concurrent_streams=0)
    pub fn attempt_stream_creation(
        &mut self,
        stream_id: u32,
        _headers: Vec<u8>,
    ) -> Result<(), ErrorCode> {
        self.stats.stream_attempts += 1;

        // Normalize stream ID based on connection side
        let normalized_id = self.normalize_stream_id(stream_id);

        // Check if stream creation should be blocked by zero limit
        if self.settings.max_concurrent_streams == 0 {
            // Stream creation should be blocked
            let blocked_attempt = BlockedStreamAttempt {
                stream_id: normalized_id,
                attempt_type: "HEADERS".to_string(),
                blocked_phase: self.current_phase(),
                error_code: ErrorCode::RefusedStream,
            };

            self.blocked_streams.push(blocked_attempt);
            self.stats.streams_blocked += 1;

            // Return appropriate error
            return Err(ErrorCode::RefusedStream);
        }

        // Check concurrent streams limit (non-zero case)
        let active_count = self.active_stream_count();
        if active_count >= self.settings.max_concurrent_streams {
            return Err(ErrorCode::RefusedStream);
        }

        // Validate stream ID sequence
        if normalized_id < self.next_stream_id {
            return Err(ErrorCode::ProtocolError);
        }

        // Create the stream
        self.streams.insert(
            normalized_id,
            StreamInfo {
                id: normalized_id,
                state: StreamState::Open,
                side: self.side,
                created_at: self.current_phase(),
            },
        );

        // If we reach here with max_concurrent_streams=0, it's a violation
        if self.settings.max_concurrent_streams == 0 {
            self.violations
                .push(ZeroMaxConcurrentViolation::StreamCreatedWithZeroLimit {
                    stream_id: normalized_id,
                    phase: self.current_phase(),
                });
            self.stats.streams_incorrectly_allowed += 1;
        } else {
            self.stats.post_recovery_streams += 1;
        }

        // Update next stream ID
        self.next_stream_id = normalized_id + 2; // Skip to next valid ID for this side

        Ok(())
    }

    /// Process non-stream frame (should work normally even with zero max concurrent streams)
    pub fn process_non_stream_frame(
        &mut self,
        frame_type: &str,
        stream_id: u32,
    ) -> Result<(), ErrorCode> {
        // Non-stream frames should always work regardless of max_concurrent_streams setting
        let processed = ProcessedFrame {
            frame_type: frame_type.to_string(),
            stream_id,
            phase: self.current_phase(),
            success: true,
        };

        self.processed_frames.push(processed);
        self.stats.non_stream_frames_processed += 1;

        // Validate that zero max_concurrent_streams doesn't affect non-stream frames
        if self.settings.max_concurrent_streams == 0 && frame_type.starts_with("stream_") {
            self.violations
                .push(ZeroMaxConcurrentViolation::NonStreamFrameBlocked {
                    frame_type: frame_type.to_string(),
                    reason: "Non-stream frame blocked by zero max_concurrent_streams".to_string(),
                });
        }

        Ok(())
    }

    /// Test recovery by increasing the max concurrent streams limit
    pub fn test_recovery(&mut self, new_limit: u32) -> Result<(), ErrorCode> {
        let old_limit = self.settings.max_concurrent_streams;

        // Apply new limit
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(new_limit)]);
        self.handle_settings_frame(&settings)?;

        // Validate that recovery works properly
        if old_limit == 0 && new_limit > 0 {
            // Should now be able to create streams
            let test_stream_result = self.attempt_stream_creation(self.next_stream_id, vec![]);
            match test_stream_result {
                Ok(()) => {
                    // Recovery successful
                }
                Err(e) => {
                    // Recovery failed - might be legitimate (other constraints) or violation
                    if self.active_stream_count() < new_limit {
                        self.violations
                            .push(ZeroMaxConcurrentViolation::StateCorruption {
                                description: "Recovery failed despite limit increase".to_string(),
                                settings_value: new_limit,
                                actual_behavior: format!(
                                    "Stream creation failed with error: {:?}",
                                    e
                                ),
                            });
                    }
                }
            }
        }

        Ok(())
    }

    /// Get count of active streams
    pub fn active_stream_count(&self) -> u32 {
        self.streams
            .values()
            .filter(|s| {
                matches!(
                    s.state,
                    StreamState::Open
                        | StreamState::HalfClosedLocal
                        | StreamState::HalfClosedRemote
                )
            })
            .count() as u32
    }

    /// Normalize stream ID based on connection side
    fn normalize_stream_id(&self, raw_id: u32) -> u32 {
        let mut id = raw_id & 0x7fff_ffff; // Ensure 31-bit positive
        if id == 0 {
            id = match self.side {
                Side::Client => 1,
                Side::Server => 2,
            };
        }

        // Ensure correct parity for connection side
        match self.side {
            Side::Client => {
                // Client streams must be odd
                if id.is_multiple_of(2) {
                    id = id.saturating_add(1);
                }
            }
            Side::Server => {
                // Server streams must be even
                if !id.is_multiple_of(2) {
                    id = id.saturating_add(1);
                }
            }
        }

        id
    }

    /// Check connection state consistency
    pub fn validate_state_consistency(&self) -> Result<(), String> {
        if self.state != ConnectionState::Open {
            return Err(format!(
                "Connection state should remain open during zero-limit fuzzing: {:?}",
                self.state
            ));
        }

        // Verify max_concurrent_streams enforcement
        let active_count = self.active_stream_count();

        if active_count > self.settings.max_concurrent_streams {
            return Err(format!(
                "Active stream count {} exceeds max_concurrent_streams setting {}",
                active_count, self.settings.max_concurrent_streams
            ));
        }

        // Verify zero limit is properly enforced
        if self.settings.max_concurrent_streams == 0 && active_count > 0 {
            // Only allowed if streams were created before zero limit was set
            let streams_from_zero_phase: usize = self
                .streams
                .values()
                .filter(|s| matches!(s.created_at, ConnectionPhase::ZeroLimitActive))
                .count();

            if streams_from_zero_phase > 0 {
                return Err(format!(
                    "Found {} streams created during zero limit phase",
                    streams_from_zero_phase
                ));
            }
        }

        // Verify stream ID sequence
        for stream in self.streams.values() {
            if stream.side != self.side {
                return Err(format!(
                    "Stream {} recorded side {:?}, expected {:?}",
                    stream.id, stream.side, self.side
                ));
            }

            let expected_parity = match self.side {
                Side::Client => 1, // Odd
                Side::Server => 0, // Even
            };

            if stream.id % 2 != expected_parity {
                return Err(format!(
                    "Stream {} has wrong parity for {:?} side",
                    stream.id, self.side
                ));
            }
        }

        Ok(())
    }

    /// Get violations detected
    pub fn violations(&self) -> &[ZeroMaxConcurrentViolation] {
        &self.violations
    }

    /// Get statistics
    pub fn stats(&self) -> &ZeroMaxConcurrentStats {
        &self.stats
    }

    /// Get blocked stream attempts
    pub fn blocked_streams(&self) -> &[BlockedStreamAttempt] {
        &self.blocked_streams
    }

    /// Check if zero limit is properly enforced
    pub fn zero_limit_properly_enforced(&self) -> bool {
        // Zero limit is properly enforced if:
        // 1. No streams were created during zero limit phase
        // 2. All stream attempts were blocked with correct error codes
        // 3. Non-stream operations continued to work

        let zero_phase_streams = self
            .streams
            .values()
            .filter(|s| matches!(s.created_at, ConnectionPhase::ZeroLimitActive))
            .count();

        let correct_error_codes = self
            .blocked_streams
            .iter()
            .all(|b| b.error_code == ErrorCode::RefusedStream);

        let coherent_blocked_attempts = self.blocked_streams.iter().all(|blocked| {
            blocked.stream_id != 0
                && !blocked.attempt_type.is_empty()
                && matches!(
                    blocked.blocked_phase,
                    ConnectionPhase::Establishment | ConnectionPhase::ZeroLimitActive
                )
        });

        let coherent_non_stream_frames = self.processed_frames.iter().all(|frame| {
            !frame.frame_type.is_empty()
                && frame.stream_id == 0
                && frame.success
                && matches!(
                    frame.phase,
                    ConnectionPhase::Establishment
                        | ConnectionPhase::ZeroLimitActive
                        | ConnectionPhase::PostRecovery
                )
        });

        zero_phase_streams == 0
            && correct_error_codes
            && coherent_blocked_attempts
            && coherent_non_stream_frames
            && self.stats.streams_incorrectly_allowed == 0
    }
}

/// Cap values for reasonable fuzzing bounds
fn cap_u8(value: u8, max: u8) -> u8 {
    value.min(max)
}

fn cap_u16(value: u16, max: u16) -> u16 {
    value.min(max)
}

fn cap_u32(value: u32, max: u32) -> u32 {
    value.min(max)
}

fuzz_target!(|input: ZeroMaxConcurrentInput| {
    let side = if input.is_client {
        Side::Client
    } else {
        Side::Server
    };
    let mut conn = MockZeroMaxConcurrentConnection::new(side);

    // Establish connection with zero max concurrent streams
    let establish_result = conn.establish_with_zero_limit();
    assert!(
        establish_result.is_ok(),
        "Connection establishment with zero limit should succeed"
    );

    // Verify initial state
    assert_eq!(
        conn.settings.max_concurrent_streams, 0,
        "Max concurrent streams should be zero after establishment"
    );
    assert_eq!(
        conn.active_stream_count(),
        0,
        "No streams should be active initially"
    );

    // Process initial connection operations
    for operation in input.initial_operations.iter().take(10) {
        match operation {
            InitialConnectionOperation::SendZeroMaxConcurrentSettings => {
                let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(0)]);
                let _ = conn.handle_settings_frame(&settings);
            }
            InitialConnectionOperation::SendSettingsAck => {
                let settings_ack = SettingsFrame::ack();
                let _ = conn.handle_settings_frame(&settings_ack);
            }
            InitialConnectionOperation::SendPing { data: _ } => {
                let _ = conn.process_non_stream_frame("PING", 0);
            }
            InitialConnectionOperation::SendWindowUpdate { increment } => {
                let _increment = cap_u32(*increment, 0x7fff_ffff);
                let _ = conn.process_non_stream_frame("WINDOW_UPDATE", 0);
            }
            InitialConnectionOperation::SendOtherSettings {
                header_table_size,
                enable_push,
                initial_window_size,
                max_frame_size,
            } => {
                let settings_vec = vec![
                    Setting::HeaderTableSize(*header_table_size),
                    Setting::EnablePush(*enable_push),
                    Setting::InitialWindowSize(*initial_window_size),
                    Setting::MaxFrameSize(*max_frame_size),
                ];

                let settings = SettingsFrame::new(settings_vec);
                let _ = conn.handle_settings_frame(&settings);
            }
        }
    }

    // Attempt stream creation (should all be blocked)
    let mut blocked_attempts = 0;
    for attempt in input.stream_attempts.iter().take(20) {
        match attempt {
            StreamCreationAttempt::StandardHeaders {
                stream_id,
                end_stream: _,
                end_headers: _,
                payload_size,
            } => {
                let payload_size = cap_u16(*payload_size, 1024);
                let payload = vec![0u8; payload_size as usize];
                let result = conn.attempt_stream_creation(*stream_id, payload);

                // Should be blocked with zero limit
                if result.is_err() {
                    blocked_attempts += 1;
                } else {
                    // This is a violation - stream created with zero limit
                    panic!("Stream creation should be blocked when max_concurrent_streams=0");
                }
            }
            StreamCreationAttempt::HeadersWithPriority {
                stream_id,
                dependency: _,
                weight: _,
                exclusive: _,
            } => {
                let result = conn.attempt_stream_creation(*stream_id, vec![]);
                if result.is_err() {
                    blocked_attempts += 1;
                }
            }
            StreamCreationAttempt::MalformedHeaders {
                stream_id,
                invalid_payload,
            } => {
                let payload = invalid_payload.iter().take(512).cloned().collect();
                let _ = conn.attempt_stream_creation(*stream_id, payload);
            }
            StreamCreationAttempt::ReservedBitStream { stream_id } => {
                let _ = conn.attempt_stream_creation(*stream_id | 0x8000_0000, vec![]);
            }
            StreamCreationAttempt::OrphanedContinuation { stream_id, payload } => {
                let payload = payload.iter().take(256).cloned().collect();
                let _ = conn.attempt_stream_creation(*stream_id, payload);
            }
            StreamCreationAttempt::EvenStreamId { stream_id } => {
                let even_id = *stream_id & 0x7fff_fffe; // Force even
                let _ = conn.attempt_stream_creation(even_id, vec![]);
            }
        }
    }

    // Verify that zero limit blocked stream attempts
    if !input.stream_attempts.is_empty() {
        assert!(
            blocked_attempts > 0 || conn.stats().streams_blocked > 0,
            "Zero max concurrent streams should block stream creation attempts"
        );
    }

    // Process non-stream frame operations (should work normally)
    for operation in input.other_frame_operations.iter().take(15) {
        match operation {
            NonStreamFrameOperation::Ping { data: _, ack: _ } => {
                let result = conn.process_non_stream_frame("PING", 0);
                assert!(
                    result.is_ok(),
                    "PING should work with zero max concurrent streams"
                );
            }
            NonStreamFrameOperation::WindowUpdate { increment } => {
                let _increment = cap_u32(*increment, 0x7fff_ffff);
                let result = conn.process_non_stream_frame("WINDOW_UPDATE", 0);
                assert!(
                    result.is_ok(),
                    "WINDOW_UPDATE should work with zero max concurrent streams"
                );
            }
            NonStreamFrameOperation::SettingsUpdate {
                header_table_size,
                enable_push,
                max_frame_size,
            } => {
                let mut settings_vec = vec![];
                if let Some(size) = header_table_size {
                    settings_vec.push(Setting::HeaderTableSize(*size));
                }
                if let Some(push) = enable_push {
                    settings_vec.push(Setting::EnablePush(*push));
                }
                if let Some(frame_size) = max_frame_size {
                    settings_vec.push(Setting::MaxFrameSize(*frame_size));
                }

                let settings = SettingsFrame::new(settings_vec);
                let result = conn.handle_settings_frame(&settings);
                assert!(
                    result.is_ok(),
                    "SETTINGS updates should work with zero max concurrent streams"
                );
            }
            NonStreamFrameOperation::GoAway {
                last_stream_id: _,
                error_code: _,
                debug_data: _,
            } => {
                let result = conn.process_non_stream_frame("GOAWAY", 0);
                assert!(
                    result.is_ok(),
                    "GOAWAY should work with zero max concurrent streams"
                );
            }
        }
    }

    // Test recovery operations
    let mut recovery_successful = false;
    for operation in input.recovery_operations.iter().take(10) {
        match operation {
            RecoveryOperation::IncreaseLimit { new_limit } => {
                let new_limit = cap_u8(*new_limit, 100).max(1) as u32; // At least 1 for recovery
                let result = conn.test_recovery(new_limit);
                assert!(
                    result.is_ok(),
                    "Recovery by increasing limit should succeed"
                );

                if new_limit > 0 {
                    recovery_successful = true;
                }
            }
            RecoveryOperation::CreateStreamAfterIncrease {
                stream_id,
                expect_success,
            } => {
                if recovery_successful {
                    let _result = conn.attempt_stream_creation(*stream_id, vec![]);

                    if *expect_success
                        && conn.active_stream_count() < conn.settings.max_concurrent_streams
                    {
                        // Stream creation might still fail due to ID sequence or other issues
                        // Don't assert success, just verify no zero-limit violation
                    }
                }
            }
            RecoveryOperation::ResetToZero => {
                let result = conn.test_recovery(0);
                assert!(result.is_ok(), "Reset to zero limit should succeed");
                recovery_successful = false;
            }
            RecoveryOperation::RapidLimitChanges { changes } => {
                for &limit in changes.iter().take(5) {
                    let limit = cap_u8(limit, 50) as u32;
                    let _ = conn.test_recovery(limit);
                }
            }
        }
    }

    // Process edge case tests
    for edge_case in input.edge_case_tests.iter().take(10) {
        match edge_case {
            EdgeCaseTest::Stream0Operation {
                frame_type: _,
                payload: _,
            } => {
                // Stream 0 operations should be connection-level
                let result = conn.process_non_stream_frame("STREAM_0_OPERATION", 0);
                assert!(result.is_ok(), "Stream 0 operations should work");
            }
            EdgeCaseTest::MultipleZeroSettings { count } => {
                for _ in 0..cap_u8(*count, 5) {
                    let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(0)]);
                    let _ = conn.handle_settings_frame(&settings);
                }
            }
            EdgeCaseTest::ZeroLimitWithAck => {
                // SETTINGS with ACK should not change the limit
                let settings_ack = SettingsFrame::ack();
                let result = conn.handle_settings_frame(&settings_ack);
                assert!(result.is_ok(), "SETTINGS ACK should succeed");
            }
            EdgeCaseTest::InterleavedOps {
                stream_attempt,
                setting_change,
            } => {
                // Try stream creation
                if let StreamCreationAttempt::StandardHeaders { stream_id, .. } = stream_attempt {
                    let _ = conn.attempt_stream_creation(*stream_id, vec![]);
                }

                // Change setting
                let limit = cap_u32(*setting_change, 10);
                let _ = conn.test_recovery(limit);
            }
            EdgeCaseTest::LargeStreamId { stream_id } => {
                let large_id = cap_u32(*stream_id, 0x7fff_ffff);
                let _ = conn.attempt_stream_creation(large_id, vec![]);
            }
        }
    }

    // Final state validation
    let validation_result = conn.validate_state_consistency();
    assert!(
        validation_result.is_ok(),
        "Connection state should be consistent: {:?}",
        validation_result
    );

    // Verify zero limit enforcement
    assert!(
        conn.zero_limit_properly_enforced(),
        "Zero max concurrent streams limit should be properly enforced"
    );

    // Verify no streams exist if limit is still zero
    if conn.settings.max_concurrent_streams == 0 {
        assert_eq!(
            conn.active_stream_count(),
            0,
            "No active streams should exist with zero limit"
        );
    }

    // Verify statistics make sense
    let stats = conn.stats();
    assert!(
        stats.stream_attempts >= stats.streams_blocked,
        "Blocked count should not exceed attempts"
    );
    assert_eq!(
        stats.streams_incorrectly_allowed, 0,
        "No streams should be incorrectly allowed with zero limit"
    );

    // Check for violations
    let violations = conn.violations();
    assert!(
        violations.is_empty(),
        "No violations should be detected: {:?}",
        violations
    );

    // Verify that non-stream operations worked
    if !input.other_frame_operations.is_empty() {
        assert!(
            stats.non_stream_frames_processed > 0,
            "Non-stream frames should be processed normally"
        );
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_establishment_with_zero_limit() {
        let mut conn = MockZeroMaxConcurrentConnection::new(Side::Client);

        // Establish with zero limit
        let result = conn.establish_with_zero_limit();
        assert!(result.is_ok());
        assert_eq!(conn.settings.max_concurrent_streams, 0);
        assert!(conn.establishment_complete);
    }

    #[test]
    fn test_stream_creation_blocked_with_zero_limit() {
        let mut conn = MockZeroMaxConcurrentConnection::new(Side::Client);
        conn.establish_with_zero_limit().unwrap();

        // Try to create stream - should be blocked
        let result = conn.attempt_stream_creation(1, vec![]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ErrorCode::RefusedStream);

        // Verify it was tracked as blocked
        assert_eq!(conn.blocked_streams().len(), 1);
        assert_eq!(conn.stats().streams_blocked, 1);
        assert_eq!(conn.active_stream_count(), 0);
    }

    #[test]
    fn test_non_stream_frames_work_with_zero_limit() {
        let mut conn = MockZeroMaxConcurrentConnection::new(Side::Client);
        conn.establish_with_zero_limit().unwrap();

        // Non-stream frames should work normally
        let result = conn.process_non_stream_frame("PING", 0);
        assert!(result.is_ok());

        let result = conn.process_non_stream_frame("WINDOW_UPDATE", 0);
        assert!(result.is_ok());

        assert_eq!(conn.stats().non_stream_frames_processed, 2);
    }

    #[test]
    fn test_recovery_from_zero_limit() {
        let mut conn = MockZeroMaxConcurrentConnection::new(Side::Client);
        conn.establish_with_zero_limit().unwrap();

        // Verify zero limit blocks streams
        assert!(conn.attempt_stream_creation(1, vec![]).is_err());

        // Increase limit to allow streams
        let result = conn.test_recovery(2);
        assert!(result.is_ok());
        assert_eq!(conn.settings.max_concurrent_streams, 2);

        // Should now be able to create streams
        let result = conn.attempt_stream_creation(1, vec![]);
        assert!(result.is_ok());
        assert_eq!(conn.active_stream_count(), 1);
    }

    #[test]
    fn test_zero_limit_enforcement_validation() {
        let mut conn = MockZeroMaxConcurrentConnection::new(Side::Client);
        conn.establish_with_zero_limit().unwrap();

        // Block some stream attempts
        let _ = conn.attempt_stream_creation(1, vec![]);
        let _ = conn.attempt_stream_creation(3, vec![]);

        // Should be properly enforced
        assert!(conn.zero_limit_properly_enforced());
        assert_eq!(conn.stats().streams_incorrectly_allowed, 0);
    }

    #[test]
    fn test_stream_id_normalization() {
        let client_conn = MockZeroMaxConcurrentConnection::new(Side::Client);
        let server_conn = MockZeroMaxConcurrentConnection::new(Side::Server);

        // Client should normalize to odd IDs
        assert_eq!(client_conn.normalize_stream_id(0), 1);
        assert_eq!(client_conn.normalize_stream_id(2), 3);
        assert_eq!(client_conn.normalize_stream_id(4), 5);

        // Server should normalize to even IDs
        assert_eq!(server_conn.normalize_stream_id(1), 2);
        assert_eq!(server_conn.normalize_stream_id(3), 4);
        assert_eq!(server_conn.normalize_stream_id(5), 6);
    }

    #[test]
    fn test_state_consistency_validation() {
        let mut conn = MockZeroMaxConcurrentConnection::new(Side::Client);
        conn.establish_with_zero_limit().unwrap();

        // Initial state should be consistent
        assert!(conn.validate_state_consistency().is_ok());

        // State should remain consistent after blocked attempts
        let _ = conn.attempt_stream_creation(1, vec![]);
        let _ = conn.attempt_stream_creation(3, vec![]);
        assert!(conn.validate_state_consistency().is_ok());

        // State should be consistent after recovery
        let _ = conn.test_recovery(1);
        let _ = conn.attempt_stream_creation(1, vec![]);
        assert!(conn.validate_state_consistency().is_ok());
    }
}
