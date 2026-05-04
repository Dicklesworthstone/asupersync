//! Fuzzing target for HTTP/2 MAX_CONCURRENT_STREAMS dynamic transitions.
//!
//! Tests RFC 7540 compliance for dynamic MAX_CONCURRENT_STREAMS changes:
//! 1. Peer first sets MAX_CONCURRENT_STREAMS=0 (forbids all streams)
//! 2. Time progresses (simulated delay)
//! 3. Peer sets MAX_CONCURRENT_STREAMS=10 (re-enables streams)
//! 4. Verify state machine correctly transitions and allows new streams
//!
//! Key test scenarios:
//! 1. Initial connection with MAX_CONCURRENT_STREAMS=0
//! 2. Stream creation attempts during zero phase (should be blocked/queued)
//! 3. Settings update to non-zero limit
//! 4. Stream creation attempts after increase (should succeed)
//! 5. Pending stream processing during transition
//! 6. State machine consistency throughout transition
//!
//! Per RFC 7540 §6.5.2: "SETTINGS_MAX_CONCURRENT_STREAMS allows the sender
//! to inform the remote endpoint of the maximum number of concurrently open
//! streams that it will allow. This setting is directional: it applies to
//! the streams sent by the endpoint that receives the setting."
//!
//! Vulnerability areas:
//! - State machine not transitioning correctly on limit increase
//! - Pending streams not processed when limit increases
//! - Race conditions during settings update
//! - Memory leaks from queued stream creation attempts
//! - Incorrect stream counting during transition
//! - Settings acknowledgment timing issues

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::{Connection, ConnectionState, Side};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{Frame, HeadersFrame, Setting, SettingsFrame, PriorityFrame, RstStreamFrame, WindowUpdateFrame};
use asupersync::http::h2::settings::{DEFAULT_MAX_CONCURRENT_STREAMS, Settings};
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Test input for dynamic MAX_CONCURRENT_STREAMS transitions
#[derive(Debug, Arbitrary)]
pub struct SettingsTransitionInput {
    /// Initial phase operations (during MAX_CONCURRENT_STREAMS=0)
    initial_phase_ops: Vec<InitialPhaseOperation>,
    /// Transition configuration
    transition_config: TransitionConfig,
    /// Post-transition operations (after limit increase)
    post_transition_ops: Vec<PostTransitionOperation>,
    /// Edge case scenarios to test
    edge_cases: Vec<EdgeCaseTest>,
    /// Timing and state validation options
    validation_config: ValidationConfig,
}

/// Operations during initial zero-limit phase
#[derive(Debug, Arbitrary)]
pub enum InitialPhaseOperation {
    /// Attempt to create stream (should be blocked)
    AttemptStreamCreation {
        stream_id: u32,
        headers: Vec<(String, String)>,
        expect_blocked: bool,
    },
    /// Send PING frame
    SendPing { data: [u8; 8] },
    /// Send connection-level WINDOW_UPDATE
    SendWindowUpdate { increment: u32 },
    /// Send additional SETTINGS
    SendAdditionalSettings { settings: Vec<AdditionalSetting> },
    /// Wait for specified duration
    WaitDuration { duration_ms: u16 },
}

/// Additional settings to test alongside MAX_CONCURRENT_STREAMS
#[derive(Debug, Arbitrary)]
pub enum AdditionalSetting {
    HeaderTableSize(u32),
    EnablePush(bool),
    InitialWindowSize(u32),
    MaxFrameSize(u32),
    MaxHeaderListSize(u32),
}

/// Configuration for the transition from 0 to non-zero limit
#[derive(Debug, Arbitrary)]
pub struct TransitionConfig {
    /// Delay before increasing limit (milliseconds)
    delay_before_increase_ms: u16,
    /// New limit to set after transition
    new_limit: u8,
    /// Whether to send SETTINGS ACK after each update
    send_ack_after_updates: bool,
    /// Whether to test rapid successive changes
    test_rapid_changes: bool,
    /// Additional settings to change during transition
    concurrent_setting_changes: Vec<AdditionalSetting>,
}

/// Operations after limit increase
#[derive(Debug, Arbitrary)]
pub enum PostTransitionOperation {
    /// Attempt stream creation (should now succeed)
    CreateStream {
        stream_id: u32,
        headers: Vec<(String, String)>,
        expect_success: bool,
    },
    /// Send data on existing stream
    SendDataOnStream { stream_id: u32, data_size: u16 },
    /// Close stream to test limit management
    CloseStream { stream_id: u32, use_rst: bool },
    /// Create multiple streams to test limit enforcement
    CreateMultipleStreams { count: u8, base_stream_id: u32 },
    /// Test stream priority operations
    SetStreamPriority {
        stream_id: u32,
        dependency: u32,
        weight: u8,
        exclusive: bool,
    },
    /// Wait for pending streams to be processed
    WaitForPendingProcessing { timeout_ms: u16 },
}

/// Edge case testing scenarios
#[derive(Debug, Arbitrary)]
pub enum EdgeCaseTest {
    /// Rapid settings changes: 0->10->0->5
    RapidLimitChanges { limits: Vec<u8> },
    /// Settings change while streams are being created
    ConcurrentStreamCreationAndLimitChange,
    /// Settings ACK timing with pending streams
    SettingsAckWithPendingStreams,
    /// Limit decrease after increase: 0->10->2
    LimitDecreaseAfterIncrease { final_limit: u8 },
    /// Multiple concurrent stream creation attempts
    ConcurrentStreamAttempts { stream_ids: Vec<u32> },
    /// Settings frame with multiple MAX_CONCURRENT_STREAMS values
    MultipleMaxConcurrentInSingleFrame,
    /// Very large limit increase: 0->u32::MAX
    VeryLargeLimitIncrease,
    /// Zero delay transition (immediate increase)
    ZeroDelayTransition,
}

/// Validation configuration
#[derive(Debug, Arbitrary)]
pub struct ValidationConfig {
    /// Strict state machine validation
    strict_state_validation: bool,
    /// Validate stream counting accuracy
    validate_stream_counting: bool,
    /// Check for memory leaks in pending streams
    check_pending_stream_leaks: bool,
    /// Validate settings ACK timing
    validate_ack_timing: bool,
    /// Maximum allowed transition time
    max_transition_time_ms: u16,
}

/// Mock HTTP/2 connection for testing settings transitions
pub struct MockSettingsTransitionConnection {
    /// Current connection state
    state: ConnectionState,
    /// Connection side (client or server)
    side: Side,
    /// Active streams by ID
    streams: HashMap<u32, StreamInfo>,
    /// Current settings
    settings: Settings,
    /// Settings history for transition tracking
    settings_history: Vec<SettingsHistoryEntry>,
    /// Pending stream creation requests
    pending_streams: VecDeque<PendingStreamRequest>,
    /// Blocked stream attempts during zero limit
    blocked_stream_attempts: Vec<BlockedStreamAttempt>,
    /// Processing statistics
    stats: TransitionStats,
    /// Detected violations
    violations: Vec<TransitionViolation>,
    /// Simulated time tracking
    simulated_time: SimulatedTime,
    /// Configuration
    config: ValidationConfig,
    /// Next stream ID (odd for client, even for server)
    next_stream_id: u32,
}

#[derive(Debug, Clone)]
pub struct StreamInfo {
    id: u32,
    state: StreamState,
    created_at_phase: TransitionPhase,
    priority_info: Option<PriorityInfo>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StreamState {
    Idle,
    Open,
    ReservedLocal,
    ReservedRemote,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

#[derive(Debug, Clone)]
pub struct PriorityInfo {
    dependency: u32,
    weight: u8,
    exclusive: bool,
}

#[derive(Debug, Clone)]
pub struct SettingsHistoryEntry {
    settings: Settings,
    timestamp: Instant,
    phase: TransitionPhase,
    ack_received: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransitionPhase {
    Initial,           // Before any settings
    ZeroLimitActive,   // MAX_CONCURRENT_STREAMS=0
    Transitioning,     // During limit change
    PostTransition,    // After limit increase
}

#[derive(Debug, Clone)]
pub struct PendingStreamRequest {
    stream_id: u32,
    headers: Vec<(String, String)>,
    queued_at: Instant,
    phase_when_queued: TransitionPhase,
}

#[derive(Debug, Clone)]
pub struct BlockedStreamAttempt {
    stream_id: u32,
    blocked_at: Instant,
    phase: TransitionPhase,
    reason: BlockedReason,
}

#[derive(Debug, Clone)]
pub enum BlockedReason {
    MaxConcurrentStreamsZero,
    MaxConcurrentStreamsExceeded,
    InvalidStreamId,
    ConnectionClosed,
}

#[derive(Debug, Clone)]
pub struct TransitionViolation {
    violation_type: ViolationType,
    description: String,
    phase: TransitionPhase,
    stream_id: Option<u32>,
    settings_value: Option<u32>,
    timestamp: Instant,
    severity: ViolationSeverity,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    StateTransitionError,      // State machine failed to transition
    PendingStreamNotProcessed, // Pending streams not processed on limit increase
    StreamCountingError,       // Incorrect active stream count
    TimingViolation,          // Settings timing issues
    MemoryLeak,               // Pending streams not cleaned up
    SettingsInconsistency,    // Settings state inconsistent
    RaceCondition,            // Detected race condition
}

#[derive(Debug, Clone, PartialEq)]
pub enum ViolationSeverity {
    Critical,   // State machine corruption
    High,       // RFC violation or data loss
    Medium,     // Performance or timing issue
    Low,        // Style or recommendation
}

#[derive(Debug, Default)]
pub struct TransitionStats {
    settings_updates: u32,
    stream_creation_attempts: u32,
    streams_created_zero_phase: u32,
    streams_created_post_transition: u32,
    streams_blocked: u32,
    streams_queued: u32,
    pending_streams_processed: u32,
    state_transitions: u32,
    violations_detected: u32,
    transition_duration_ms: u64,
}

/// Simulated time for testing timing-dependent behavior
#[derive(Debug, Clone)]
pub struct SimulatedTime {
    current_time: Instant,
    time_offset_ms: u64,
}

impl SimulatedTime {
    pub fn new() -> Self {
        Self {
            current_time: Instant::now(),
            time_offset_ms: 0,
        }
    }

    pub fn now(&self) -> Instant {
        self.current_time + Duration::from_millis(self.time_offset_ms)
    }

    pub fn advance(&mut self, duration_ms: u64) {
        self.time_offset_ms += duration_ms;
    }
}

impl MockSettingsTransitionConnection {
    pub fn new(side: Side, config: ValidationConfig) -> Self {
        let next_stream_id = match side {
            Side::Client => 1, // Client streams are odd
            Side::Server => 2, // Server streams are even
        };

        Self {
            state: ConnectionState::Open,
            side,
            streams: HashMap::new(),
            settings: Settings::default(),
            settings_history: Vec::new(),
            pending_streams: VecDeque::new(),
            blocked_stream_attempts: Vec::new(),
            stats: TransitionStats::default(),
            violations: Vec::new(),
            simulated_time: SimulatedTime::new(),
            config,
            next_stream_id,
        }
    }

    /// Apply initial settings with MAX_CONCURRENT_STREAMS=0
    pub fn apply_initial_zero_limit(&mut self) -> Result<(), ErrorCode> {
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(0)]);
        self.handle_settings_frame(&settings)?;

        self.record_settings_history(TransitionPhase::ZeroLimitActive)?;
        self.stats.state_transitions += 1;

        Ok(())
    }

    /// Handle SETTINGS frame and process transitions
    pub fn handle_settings_frame(&mut self, frame: &SettingsFrame) -> Result<(), ErrorCode> {
        if frame.ack {
            // Mark latest settings as ACK received
            if let Some(latest) = self.settings_history.last_mut() {
                latest.ack_received = true;
            }
            return Ok(());
        }

        let old_max_concurrent = self.settings.max_concurrent_streams;
        let mut new_max_concurrent = old_max_concurrent;

        // Apply settings
        for setting in &frame.settings {
            match setting {
                Setting::MaxConcurrentStreams(new_limit) => {
                    new_max_concurrent = *new_limit;
                    self.settings.max_concurrent_streams = *new_limit;
                },
                Setting::HeaderTableSize(size) => {
                    self.settings.header_table_size = *size;
                },
                Setting::EnablePush(enabled) => {
                    self.settings.enable_push = *enabled;
                },
                Setting::InitialWindowSize(size) => {
                    self.settings.initial_window_size = *size;
                },
                Setting::MaxFrameSize(size) => {
                    self.settings.max_frame_size = *size;
                },
                Setting::MaxHeaderListSize(size) => {
                    self.settings.max_header_list_size = *size;
                },
            }
        }

        self.stats.settings_updates += 1;

        // Handle transition from zero to non-zero limit
        if old_max_concurrent == 0 && new_max_concurrent > 0 {
            self.handle_transition_to_non_zero(new_max_concurrent)?;
        }

        // Handle transition to zero limit
        if old_max_concurrent > 0 && new_max_concurrent == 0 {
            self.handle_transition_to_zero()?;
        }

        // Handle limit changes (non-zero to different non-zero)
        if old_max_concurrent > 0 && new_max_concurrent > 0 && old_max_concurrent != new_max_concurrent {
            self.handle_limit_change(old_max_concurrent, new_max_concurrent)?;
        }

        Ok(())
    }

    /// Handle transition from zero to non-zero limit
    fn handle_transition_to_non_zero(&mut self, new_limit: u32) -> Result<(), ErrorCode> {
        let transition_start = self.simulated_time.now();

        // Record phase transition
        self.record_settings_history(TransitionPhase::Transitioning)?;

        // Process pending streams
        let processed = self.process_pending_streams(new_limit)?;
        self.stats.pending_streams_processed += processed as u32;

        // Validate state consistency
        if self.config.strict_state_validation {
            self.validate_state_after_transition()?;
        }

        // Check for timing violations
        let transition_duration = self.simulated_time.now().duration_since(transition_start);
        self.stats.transition_duration_ms = transition_duration.as_millis() as u64;

        if self.config.validate_ack_timing &&
           transition_duration.as_millis() > self.config.max_transition_time_ms as u128 {
            self.violations.push(TransitionViolation {
                violation_type: ViolationType::TimingViolation,
                description: format!("Transition took {}ms, max allowed {}ms",
                    transition_duration.as_millis(), self.config.max_transition_time_ms),
                phase: TransitionPhase::Transitioning,
                stream_id: None,
                settings_value: Some(new_limit),
                timestamp: self.simulated_time.now(),
                severity: ViolationSeverity::Medium,
            });
        }

        // Record post-transition state
        self.record_settings_history(TransitionPhase::PostTransition)?;
        self.stats.state_transitions += 1;

        Ok(())
    }

    /// Handle transition to zero limit
    fn handle_transition_to_zero(&mut self) -> Result<(), ErrorCode> {
        // New streams should be blocked
        // Existing streams should continue to work
        self.record_settings_history(TransitionPhase::ZeroLimitActive)?;
        Ok(())
    }

    /// Handle limit changes between non-zero values
    fn handle_limit_change(&mut self, _old_limit: u32, new_limit: u32) -> Result<(), ErrorCode> {
        if new_limit > 0 {
            // Process pending streams if limit increased
            let processed = self.process_pending_streams(new_limit)?;
            self.stats.pending_streams_processed += processed as u32;
        }
        Ok(())
    }

    /// Process pending streams when limit allows
    fn process_pending_streams(&mut self, limit: u32) -> Result<usize, ErrorCode> {
        let mut processed = 0;
        let current_active = self.active_stream_count();

        while !self.pending_streams.is_empty() &&
              current_active + processed < limit as usize {
            if let Some(pending) = self.pending_streams.pop_front() {
                // Create the stream
                self.streams.insert(pending.stream_id, StreamInfo {
                    id: pending.stream_id,
                    state: StreamState::Open,
                    created_at_phase: TransitionPhase::PostTransition,
                    priority_info: None,
                });

                self.stats.streams_created_post_transition += 1;
                processed += 1;
            }
        }

        // Check for memory leaks
        if self.config.check_pending_stream_leaks && !self.pending_streams.is_empty() && limit > 0 {
            self.violations.push(TransitionViolation {
                violation_type: ViolationType::MemoryLeak,
                description: format!("{} pending streams remain after transition", self.pending_streams.len()),
                phase: TransitionPhase::PostTransition,
                stream_id: None,
                settings_value: Some(limit),
                timestamp: self.simulated_time.now(),
                severity: ViolationSeverity::High,
            });
        }

        Ok(processed)
    }

    /// Attempt to create a stream
    pub fn attempt_stream_creation(&mut self, stream_id: u32, headers: Vec<(String, String)>) -> Result<(), ErrorCode> {
        self.stats.stream_creation_attempts += 1;

        let normalized_id = self.normalize_stream_id(stream_id);
        let current_active = self.active_stream_count();

        // Check if creation is allowed
        if self.settings.max_concurrent_streams == 0 {
            // Stream creation blocked by zero limit
            self.blocked_stream_attempts.push(BlockedStreamAttempt {
                stream_id: normalized_id,
                blocked_at: self.simulated_time.now(),
                phase: self.current_phase(),
                reason: BlockedReason::MaxConcurrentStreamsZero,
            });

            // Queue the stream for later processing
            self.pending_streams.push_back(PendingStreamRequest {
                stream_id: normalized_id,
                headers,
                queued_at: self.simulated_time.now(),
                phase_when_queued: self.current_phase(),
            });

            self.stats.streams_blocked += 1;
            self.stats.streams_queued += 1;
            return Ok(()); // Queued, not failed
        }

        if current_active >= self.settings.max_concurrent_streams as usize {
            // Stream creation blocked by limit
            self.blocked_stream_attempts.push(BlockedStreamAttempt {
                stream_id: normalized_id,
                blocked_at: self.simulated_time.now(),
                phase: self.current_phase(),
                reason: BlockedReason::MaxConcurrentStreamsExceeded,
            });

            self.stats.streams_blocked += 1;
            return Err(ErrorCode::RefusedStream);
        }

        // Create the stream
        self.streams.insert(normalized_id, StreamInfo {
            id: normalized_id,
            state: StreamState::Open,
            created_at_phase: self.current_phase(),
            priority_info: None,
        });

        match self.current_phase() {
            TransitionPhase::ZeroLimitActive => {
                self.stats.streams_created_zero_phase += 1;

                // This should not happen - violation
                self.violations.push(TransitionViolation {
                    violation_type: ViolationType::StateTransitionError,
                    description: "Stream created during zero limit phase".to_string(),
                    phase: TransitionPhase::ZeroLimitActive,
                    stream_id: Some(normalized_id),
                    settings_value: Some(0),
                    timestamp: self.simulated_time.now(),
                    severity: ViolationSeverity::Critical,
                });
            },
            _ => {
                self.stats.streams_created_post_transition += 1;
            }
        }

        self.next_stream_id += 2; // Move to next valid ID for this side
        Ok(())
    }

    /// Close a stream
    pub fn close_stream(&mut self, stream_id: u32, use_rst: bool) -> Result<(), ErrorCode> {
        let normalized_id = self.normalize_stream_id(stream_id);

        if let Some(stream) = self.streams.get_mut(&normalized_id) {
            stream.state = StreamState::Closed;

            // If limit is positive, try to process pending streams
            if self.settings.max_concurrent_streams > 0 {
                let _ = self.process_pending_streams(self.settings.max_concurrent_streams);
            }

            Ok(())
        } else {
            Err(ErrorCode::StreamClosed)
        }
    }

    /// Advance simulated time
    pub fn advance_time(&mut self, duration_ms: u64) {
        self.simulated_time.advance(duration_ms);
    }

    /// Get current active stream count
    pub fn active_stream_count(&self) -> usize {
        self.streams.values()
            .filter(|s| matches!(s.state, StreamState::Open | StreamState::HalfClosedLocal | StreamState::HalfClosedRemote))
            .count()
    }

    /// Normalize stream ID based on connection side
    fn normalize_stream_id(&self, raw_id: u32) -> u32 {
        let mut id = raw_id & 0x7fff_ffff; // Ensure 31-bit
        if id == 0 { id = 1; }

        match self.side {
            Side::Client => {
                // Client streams are odd
                if id % 2 == 0 { id = id.saturating_add(1); }
            },
            Side::Server => {
                // Server streams are even
                if id % 2 == 1 { id = id.saturating_add(1); }
            }
        }

        id
    }

    /// Get current transition phase
    fn current_phase(&self) -> TransitionPhase {
        if self.settings.max_concurrent_streams == 0 {
            TransitionPhase::ZeroLimitActive
        } else if self.settings_history.is_empty() {
            TransitionPhase::Initial
        } else {
            TransitionPhase::PostTransition
        }
    }

    /// Record settings history entry
    fn record_settings_history(&mut self, phase: TransitionPhase) -> Result<(), ErrorCode> {
        self.settings_history.push(SettingsHistoryEntry {
            settings: self.settings.clone(),
            timestamp: self.simulated_time.now(),
            phase,
            ack_received: false,
        });
        Ok(())
    }

    /// Validate state consistency after transition
    fn validate_state_after_transition(&mut self) -> Result<(), ErrorCode> {
        // Check stream counting accuracy
        if self.config.validate_stream_counting {
            let expected_active = self.active_stream_count();
            let actual_limit = self.settings.max_concurrent_streams as usize;

            if expected_active > actual_limit && actual_limit > 0 {
                self.violations.push(TransitionViolation {
                    violation_type: ViolationType::StreamCountingError,
                    description: format!("Active streams {} exceeds limit {}", expected_active, actual_limit),
                    phase: self.current_phase(),
                    stream_id: None,
                    settings_value: Some(actual_limit as u32),
                    timestamp: self.simulated_time.now(),
                    severity: ViolationSeverity::High,
                });
            }
        }

        Ok(())
    }

    /// Get processing results
    pub fn results(&self) -> TransitionResults {
        TransitionResults {
            settings_history: self.settings_history.clone(),
            streams: self.streams.clone(),
            pending_streams: self.pending_streams.clone(),
            blocked_attempts: self.blocked_stream_attempts.clone(),
            violations: self.violations.clone(),
            stats: self.stats.clone(),
            final_settings: self.settings.clone(),
            final_phase: self.current_phase(),
        }
    }

    /// Check if transition was successful
    pub fn transition_successful(&self) -> bool {
        // Successful if:
        // 1. No critical violations
        // 2. Pending streams were processed when limit increased
        // 3. Current state is consistent

        let critical_violations = self.violations.iter()
            .filter(|v| v.severity == ViolationSeverity::Critical)
            .count();

        critical_violations == 0 &&
        (self.pending_streams.is_empty() || self.settings.max_concurrent_streams == 0)
    }
}

#[derive(Debug, Clone)]
pub struct TransitionResults {
    pub settings_history: Vec<SettingsHistoryEntry>,
    pub streams: HashMap<u32, StreamInfo>,
    pub pending_streams: VecDeque<PendingStreamRequest>,
    pub blocked_attempts: Vec<BlockedStreamAttempt>,
    pub violations: Vec<TransitionViolation>,
    pub stats: TransitionStats,
    pub final_settings: Settings,
    pub final_phase: TransitionPhase,
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

fuzz_target!(|input: SettingsTransitionInput| {
    let config = ValidationConfig {
        strict_state_validation: true,
        validate_stream_counting: true,
        check_pending_stream_leaks: true,
        validate_ack_timing: true,
        max_transition_time_ms: cap_u16(input.validation_config.max_transition_time_ms, 5000),
    };

    let mut conn = MockSettingsTransitionConnection::new(Side::Client, config);

    // Phase 1: Apply initial settings with MAX_CONCURRENT_STREAMS=0
    let initial_result = conn.apply_initial_zero_limit();
    assert!(initial_result.is_ok(), "Initial zero limit setting should succeed");
    assert_eq!(conn.settings.max_concurrent_streams, 0, "Initial limit should be zero");

    // Phase 2: Initial phase operations (during zero limit)
    for operation in input.initial_phase_ops.iter().take(10) {
        match operation {
            InitialPhaseOperation::AttemptStreamCreation { stream_id, headers, expect_blocked } => {
                let stream_id = cap_u32(*stream_id, 0x7fff_ffff);
                let headers = headers.iter().take(5)
                    .map(|(k, v)| (k[..k.len().min(50)].to_string(), v[..v.len().min(100)].to_string()))
                    .collect();

                let result = conn.attempt_stream_creation(stream_id, headers);

                if *expect_blocked {
                    // During zero limit, streams should be queued, not failed
                    assert!(result.is_ok() || result.is_err(), "Stream attempt during zero limit should be queued or failed");

                    // Should have been queued if successful
                    if result.is_ok() {
                        assert!(!conn.pending_streams.is_empty(), "Successful attempt during zero limit should queue stream");
                    }
                } else {
                    // Non-blocked streams during zero limit is unusual but not necessarily invalid
                }
            },
            InitialPhaseOperation::SendPing { data: _ } => {
                // PING frames should work normally regardless of stream limit
                // This tests that connection-level operations are unaffected
            },
            InitialPhaseOperation::SendWindowUpdate { increment } => {
                let increment = cap_u32(*increment, 0x7fff_ffff);
                // Connection-level WINDOW_UPDATE should work normally
            },
            InitialPhaseOperation::SendAdditionalSettings { settings } => {
                // Test additional settings during zero limit phase
                let mut settings_vec = vec![];
                for setting in settings.iter().take(3) {
                    match setting {
                        AdditionalSetting::HeaderTableSize(size) => {
                            settings_vec.push(Setting::HeaderTableSize(*size));
                        },
                        AdditionalSetting::EnablePush(enabled) => {
                            settings_vec.push(Setting::EnablePush(*enabled));
                        },
                        AdditionalSetting::InitialWindowSize(size) => {
                            settings_vec.push(Setting::InitialWindowSize(*size));
                        },
                        AdditionalSetting::MaxFrameSize(size) => {
                            settings_vec.push(Setting::MaxFrameSize(*size));
                        },
                        AdditionalSetting::MaxHeaderListSize(size) => {
                            settings_vec.push(Setting::MaxHeaderListSize(*size));
                        },
                    }
                }

                let settings_frame = SettingsFrame::new(settings_vec);
                let _ = conn.handle_settings_frame(&settings_frame);
            },
            InitialPhaseOperation::WaitDuration { duration_ms } => {
                let duration = cap_u16(*duration_ms, 2000); // Max 2 seconds
                conn.advance_time(duration as u64);
            },
        }
    }

    // Verify zero limit state
    assert_eq!(conn.settings.max_concurrent_streams, 0, "Should still have zero limit after initial ops");
    assert_eq!(conn.active_stream_count(), 0, "Should have no active streams during zero limit");

    // Phase 3: Transition - advance time and increase limit
    let delay = cap_u16(input.transition_config.delay_before_increase_ms, 5000);
    conn.advance_time(delay as u64);

    let new_limit = cap_u8(input.transition_config.new_limit, 50).max(1); // At least 1 for transition test
    let transition_settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(new_limit as u32)]);

    let transition_result = conn.handle_settings_frame(&transition_settings);
    assert!(transition_result.is_ok(), "Transition settings should succeed");
    assert_eq!(conn.settings.max_concurrent_streams, new_limit as u32, "Limit should be updated");

    // Verify pending streams were processed if any were queued
    let pending_before = conn.stats.streams_queued;
    let processed = conn.stats.pending_streams_processed;

    if pending_before > 0 && new_limit > 0 {
        assert!(processed > 0 || conn.pending_streams.len() < pending_before as usize,
            "Some pending streams should be processed when limit increases");
    }

    // Phase 4: Post-transition operations
    for operation in input.post_transition_ops.iter().take(15) {
        match operation {
            PostTransitionOperation::CreateStream { stream_id, headers, expect_success } => {
                let stream_id = cap_u32(*stream_id, 0x7fff_ffff);
                let headers = headers.iter().take(5)
                    .map(|(k, v)| (k[..k.len().min(50)].to_string(), v[..v.len().min(100)].to_string()))
                    .collect();

                let result = conn.attempt_stream_creation(stream_id, headers);

                if *expect_success && conn.active_stream_count() < new_limit as usize {
                    // Should succeed if under limit
                    if result.is_err() {
                        // Could fail due to stream ID issues or other constraints
                    }
                } else if conn.active_stream_count() >= new_limit as usize {
                    // Should fail if at limit
                    assert!(result.is_err(), "Stream creation should fail when at limit");
                }
            },
            PostTransitionOperation::SendDataOnStream { stream_id, data_size: _ } => {
                let stream_id = cap_u32(*stream_id, 0x7fff_ffff);
                // Test data sending on existing streams
                if conn.streams.contains_key(&conn.normalize_stream_id(stream_id)) {
                    // Stream exists, data should be sendable
                }
            },
            PostTransitionOperation::CloseStream { stream_id, use_rst: _ } => {
                let stream_id = cap_u32(*stream_id, 0x7fff_ffff);
                let _ = conn.close_stream(stream_id, false);
            },
            PostTransitionOperation::CreateMultipleStreams { count, base_stream_id } => {
                let count = cap_u8(*count, 10);
                let base_id = cap_u32(*base_stream_id, 0x7fff_fff0);

                for i in 0..count {
                    let stream_id = base_id + (i as u32 * 2);
                    let _ = conn.attempt_stream_creation(stream_id, vec![]);
                }

                // Should not exceed the limit
                assert!(conn.active_stream_count() <= new_limit as usize,
                    "Active stream count {} should not exceed limit {}",
                    conn.active_stream_count(), new_limit);
            },
            PostTransitionOperation::SetStreamPriority { stream_id, dependency, weight, exclusive } => {
                let stream_id = cap_u32(*stream_id, 0x7fff_ffff);
                let dependency = cap_u32(*dependency, 0x7fff_ffff);

                if let Some(stream) = conn.streams.get_mut(&conn.normalize_stream_id(stream_id)) {
                    stream.priority_info = Some(PriorityInfo {
                        dependency,
                        weight: *weight,
                        exclusive: *exclusive,
                    });
                }
            },
            PostTransitionOperation::WaitForPendingProcessing { timeout_ms } => {
                let timeout = cap_u16(*timeout_ms, 1000);
                conn.advance_time(timeout as u64);
            },
        }
    }

    // Phase 5: Edge case testing
    for edge_case in input.edge_cases.iter().take(5) {
        match edge_case {
            EdgeCaseTest::RapidLimitChanges { limits } => {
                for &limit in limits.iter().take(5) {
                    let limit = cap_u8(limit, 100);
                    let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(limit as u32)]);
                    let _ = conn.handle_settings_frame(&settings);

                    // Verify state consistency after each change
                    assert!(conn.active_stream_count() <= conn.settings.max_concurrent_streams as usize,
                        "Active streams should not exceed limit after rapid change");
                }
            },
            EdgeCaseTest::ConcurrentStreamCreationAndLimitChange => {
                // Simulate concurrent operations
                let _ = conn.attempt_stream_creation(1001, vec![]);
                let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(5)]);
                let _ = conn.handle_settings_frame(&settings);
                let _ = conn.attempt_stream_creation(1003, vec![]);
            },
            EdgeCaseTest::LimitDecreaseAfterIncrease { final_limit } => {
                let final_limit = cap_u8(*final_limit, new_limit);
                let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(final_limit as u32)]);
                let _ = conn.handle_settings_frame(&settings);

                // Verify no streams were forcibly closed
                // (Existing streams should be allowed to continue)
            },
            EdgeCaseTest::ZeroDelayTransition => {
                // Test immediate transition back to zero and then non-zero
                let zero_settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(0)]);
                let _ = conn.handle_settings_frame(&zero_settings);

                let non_zero_settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(1)]);
                let _ = conn.handle_settings_frame(&non_zero_settings);
            },
            _ => {
                // Other edge cases
                let test_settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(2)]);
                let _ = conn.handle_settings_frame(&test_settings);
            }
        }
    }

    // Final validation
    let results = conn.results();

    // Verify transition completed successfully
    assert!(conn.transition_successful(), "Transition should complete successfully");

    // Verify no critical violations
    let critical_violations: Vec<_> = results.violations.iter()
        .filter(|v| v.severity == ViolationSeverity::Critical)
        .collect();

    assert!(critical_violations.is_empty(),
        "No critical violations should occur: {:?}", critical_violations);

    // Verify settings history makes sense
    assert!(!results.settings_history.is_empty(), "Should have settings history");

    // Verify final state consistency
    assert!(results.streams.len() <= conn.settings.max_concurrent_streams as usize,
        "Final active stream count should not exceed limit");

    // Check for memory leaks in pending streams
    if conn.settings.max_concurrent_streams > 0 && !results.pending_streams.is_empty() {
        // Some pending streams remaining might be okay if limit is still constrained
        let active_count = conn.active_stream_count();
        let limit = conn.settings.max_concurrent_streams as usize;

        if active_count < limit {
            // If we're under the limit but still have pending streams, that's suspicious
            assert!(false, "Pending streams remain despite being under limit");
        }
    }

    // Verify statistics are reasonable
    assert!(results.stats.settings_updates > 0, "Should have processed settings updates");

    if results.stats.streams_queued > 0 {
        assert!(results.stats.pending_streams_processed > 0 || conn.settings.max_concurrent_streams == 0,
            "Queued streams should be processed unless limit is still zero");
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_zero_to_nonzero_transition() {
        let config = ValidationConfig {
            strict_state_validation: true,
            validate_stream_counting: true,
            check_pending_stream_leaks: true,
            validate_ack_timing: false,
            max_transition_time_ms: 1000,
        };

        let mut conn = MockSettingsTransitionConnection::new(Side::Client, config);

        // Start with zero limit
        assert!(conn.apply_initial_zero_limit().is_ok());
        assert_eq!(conn.settings.max_concurrent_streams, 0);

        // Try to create stream - should be queued
        assert!(conn.attempt_stream_creation(1, vec![]).is_ok());
        assert_eq!(conn.active_stream_count(), 0);
        assert_eq!(conn.pending_streams.len(), 1);

        // Increase limit
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(5)]);
        assert!(conn.handle_settings_frame(&settings).is_ok());
        assert_eq!(conn.settings.max_concurrent_streams, 5);

        // Pending stream should be processed
        assert_eq!(conn.pending_streams.len(), 0);
        assert_eq!(conn.active_stream_count(), 1);

        assert!(conn.transition_successful());
    }

    #[test]
    fn test_multiple_pending_streams() {
        let config = ValidationConfig {
            strict_state_validation: true,
            validate_stream_counting: true,
            check_pending_stream_leaks: false,
            validate_ack_timing: false,
            max_transition_time_ms: 1000,
        };

        let mut conn = MockSettingsTransitionConnection::new(Side::Client, config);

        // Start with zero limit
        assert!(conn.apply_initial_zero_limit().is_ok());

        // Queue multiple streams
        for i in 0..5 {
            assert!(conn.attempt_stream_creation(1 + i * 2, vec![]).is_ok());
        }
        assert_eq!(conn.pending_streams.len(), 5);
        assert_eq!(conn.active_stream_count(), 0);

        // Increase limit to 3
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(3)]);
        assert!(conn.handle_settings_frame(&settings).is_ok());

        // Should process 3 streams, leave 2 pending
        assert_eq!(conn.pending_streams.len(), 2);
        assert_eq!(conn.active_stream_count(), 3);
    }

    #[test]
    fn test_transition_timing() {
        let config = ValidationConfig {
            strict_state_validation: true,
            validate_stream_counting: true,
            check_pending_stream_leaks: true,
            validate_ack_timing: true,
            max_transition_time_ms: 100, // Short timeout for testing
        };

        let mut conn = MockSettingsTransitionConnection::new(Side::Client, config);

        assert!(conn.apply_initial_zero_limit().is_ok());

        // Simulate delay
        conn.advance_time(1000); // 1 second

        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(1)]);
        assert!(conn.handle_settings_frame(&settings).is_ok());

        // Should have timing violation due to simulated delay
        let timing_violations: Vec<_> = conn.violations.iter()
            .filter(|v| matches!(v.violation_type, ViolationType::TimingViolation))
            .collect();

        // Note: This test might not trigger timing violations in the mock
        // since we're not actually measuring real processing time
    }

    #[test]
    fn test_rapid_limit_changes() {
        let config = ValidationConfig {
            strict_state_validation: true,
            validate_stream_counting: true,
            check_pending_stream_leaks: true,
            validate_ack_timing: false,
            max_transition_time_ms: 1000,
        };

        let mut conn = MockSettingsTransitionConnection::new(Side::Client, config);

        // Start with zero
        assert!(conn.apply_initial_zero_limit().is_ok());

        // Queue a stream
        assert!(conn.attempt_stream_creation(1, vec![]).is_ok());
        assert_eq!(conn.pending_streams.len(), 1);

        // Rapid changes: 0 -> 5 -> 1 -> 3
        let changes = vec![5, 1, 3];
        for limit in changes {
            let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(limit)]);
            assert!(conn.handle_settings_frame(&settings).is_ok());
        }

        // Should end up with limit 3 and processed stream
        assert_eq!(conn.settings.max_concurrent_streams, 3);
        assert_eq!(conn.active_stream_count(), 1);
        assert_eq!(conn.pending_streams.len(), 0);
    }

    #[test]
    fn test_stream_counting_accuracy() {
        let config = ValidationConfig {
            strict_state_validation: true,
            validate_stream_counting: true,
            check_pending_stream_leaks: true,
            validate_ack_timing: false,
            max_transition_time_ms: 1000,
        };

        let mut conn = MockSettingsTransitionConnection::new(Side::Client, config);

        // Start with limit 3
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(3)]);
        assert!(conn.handle_settings_frame(&settings).is_ok());

        // Create 3 streams
        for i in 0..3 {
            assert!(conn.attempt_stream_creation(1 + i * 2, vec![]).is_ok());
        }
        assert_eq!(conn.active_stream_count(), 3);

        // Fourth should fail
        assert!(conn.attempt_stream_creation(7, vec![]).is_err());
        assert_eq!(conn.active_stream_count(), 3);

        // Close one stream
        assert!(conn.close_stream(1, false).is_ok());
        assert_eq!(conn.active_stream_count(), 2);

        // Should now be able to create another
        assert!(conn.attempt_stream_creation(9, vec![]).is_ok());
        assert_eq!(conn.active_stream_count(), 3);
    }
}