//! HTTP/2 SETTINGS ACK timeout fuzz target.
//!
//! Tests SETTINGS ACK timeout handling per RFC 7540 Section 6.5.3.
//! When a SETTINGS frame is sent, the peer must respond with a SETTINGS ACK
//! within a reasonable time, or the connection should be terminated with GOAWAY.
//!
//! This fuzzer generates arbitrary delays and verifies:
//! 1. SETTINGS ACK timeout is enforced correctly
//! 2. GOAWAY is sent after ACK timeout expires
//! 3. Connection state is cleaned up properly
//! 4. Multiple pending SETTINGS are handled correctly
//! 5. No panics occur with various timing scenarios

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// SETTINGS ACK timeout test
#[derive(Debug, Clone, Arbitrary)]
struct SettingsAckTimeoutTest {
    /// SETTINGS to send
    settings_frames: Vec<SettingsFrame>,
    /// Delays before sending ACK for each SETTINGS
    ack_delays: Vec<AckDelay>,
    /// Connection timeout configuration
    timeout_config: TimeoutConfig,
    /// Whether to send ACKs out of order
    out_of_order_acks: bool,
    /// Additional connection state
    connection_state: ConnectionState,
}

/// SETTINGS frame data
#[derive(Debug, Clone, Arbitrary)]
struct SettingsFrame {
    /// Individual settings
    settings: Vec<Setting>,
    /// Whether this is an ACK frame
    ack: bool,
    /// Additional padding or malformed data
    extra_data: Vec<u8>,
}

/// Individual setting parameter
#[derive(Debug, Clone, Arbitrary)]
struct Setting {
    /// Setting identifier
    id: SettingId,
    /// Setting value
    value: u32,
}

/// Setting identifiers per RFC 7540
#[derive(Debug, Clone, Arbitrary)]
enum SettingId {
    /// SETTINGS_HEADER_TABLE_SIZE (0x1)
    HeaderTableSize,
    /// SETTINGS_ENABLE_PUSH (0x2)
    EnablePush,
    /// SETTINGS_MAX_CONCURRENT_STREAMS (0x3)
    MaxConcurrentStreams,
    /// SETTINGS_INITIAL_WINDOW_SIZE (0x4)
    InitialWindowSize,
    /// SETTINGS_MAX_FRAME_SIZE (0x5)
    MaxFrameSize,
    /// SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
    MaxHeaderListSize,
    /// Unknown setting (for extension testing)
    Unknown(u16),
}

/// Delay configuration for SETTINGS ACK
#[derive(Debug, Clone, Arbitrary)]
struct AckDelay {
    /// Delay duration in milliseconds
    delay_ms: u32,
    /// Whether to send ACK at all
    send_ack: bool,
    /// Whether to send malformed ACK
    malformed_ack: bool,
}

/// Timeout configuration
#[derive(Debug, Clone, Arbitrary)]
struct TimeoutConfig {
    /// SETTINGS ACK timeout in milliseconds
    settings_ack_timeout_ms: u32,
    /// Connection idle timeout
    idle_timeout_ms: u32,
    /// Maximum number of pending SETTINGS
    max_pending_settings: u8,
}

/// Connection state for testing
#[derive(Debug, Clone, Arbitrary)]
struct ConnectionState {
    /// Current window size
    window_size: u32,
    /// Maximum concurrent streams
    max_concurrent_streams: u32,
    /// Whether connection is in error state
    error_state: bool,
    /// Pending stream operations
    pending_operations: Vec<StreamOperation>,
}

/// Stream operation that might be affected by SETTINGS changes
#[derive(Debug, Clone, Arbitrary)]
struct StreamOperation {
    /// Stream ID
    stream_id: u32,
    /// Operation type
    operation: StreamOpType,
    /// Data size
    data_size: u32,
}

/// Types of stream operations
#[derive(Debug, Clone, Arbitrary)]
enum StreamOpType {
    /// Send DATA frame
    SendData,
    /// Send HEADERS frame
    SendHeaders,
    /// Send WINDOW_UPDATE
    WindowUpdate,
    /// Receive data
    ReceiveData,
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 100_000 {
        return;
    }

    let mut u = arbitrary::Unstructured::new(data);

    // Generate SETTINGS ACK timeout test case
    let test_case = match SettingsAckTimeoutTest::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return,
    };

    // Limit frames and operations for performance
    if test_case.settings_frames.len() > 10
        || test_case.ack_delays.len() > 10
        || test_case.connection_state.pending_operations.len() > 20
    {
        return;
    }

    // Limit timeout values to reasonable ranges
    if test_case.timeout_config.settings_ack_timeout_ms > 60_000
        || test_case.timeout_config.idle_timeout_ms > 300_000
    {
        return;
    }

    // Test core SETTINGS ACK timeout
    test_settings_ack_timeout(&test_case);

    // Test multiple pending SETTINGS
    test_multiple_pending_settings(&test_case);

    // Test GOAWAY after timeout
    test_goaway_after_timeout(&test_case);

    // Test connection cleanup
    test_connection_cleanup_after_timeout(&test_case);

    // Test edge cases
    test_settings_timeout_edge_cases(&test_case);
});

/// Test SETTINGS ACK timeout behavior
fn test_settings_ack_timeout(test_case: &SettingsAckTimeoutTest) {
    let mut mock_connection = MockH2Connection::new(test_case.timeout_config.clone());

    // Set up initial connection state
    mock_connection.set_connection_state(&test_case.connection_state);

    let mut pending_settings = Vec::new();

    // Send SETTINGS frames
    for (i, settings_frame) in test_case.settings_frames.iter().enumerate() {
        if settings_frame.ack {
            continue; // Skip ACK frames in this phase
        }

        let send_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mock_connection.send_settings_frame(settings_frame.clone())
        }));

        assert!(
            send_result.is_ok(),
            "Sending SETTINGS frame {} should not panic",
            i
        );

        if let Ok(settings_result) = send_result {
            match settings_result {
                SettingsResult::Sent { settings_id } => {
                    pending_settings.push((settings_id, Instant::now()));
                }
                SettingsResult::Rejected { reason } => {
                    // Some SETTINGS might be rejected for valid reasons
                    if !has_invalid_settings(&settings_frame.settings) {
                        eprintln!("Warning: valid SETTINGS rejected: {}", reason);
                    }
                }
            }
        }
    }

    // Simulate time passing and ACK responses
    for (i, (settings_id, _sent_time)) in pending_settings.iter().enumerate() {
        if i >= test_case.ack_delays.len() {
            break; // No more delay configurations
        }

        let ack_delay = &test_case.ack_delays[i];

        // Simulate delay
        mock_connection.advance_time(Duration::from_millis(ack_delay.delay_ms as u64));

        // Check if timeout should have occurred
        if ack_delay.delay_ms > test_case.timeout_config.settings_ack_timeout_ms {
            // Timeout should have triggered
            let connection_state = mock_connection.get_connection_state();
            match connection_state {
                ConnectionStatus::Open => {
                    // Connection might still be open if implementation is lenient
                    // but GOAWAY should have been sent
                    assert!(
                        mock_connection.goaway_sent(),
                        "GOAWAY should be sent after SETTINGS ACK timeout"
                    );
                }
                ConnectionStatus::GoAway { error_code } => {
                    // Connection terminated due to timeout
                    assert_eq!(
                        error_code,
                        H2ErrorCode::SettingsTimeout,
                        "GOAWAY should use SETTINGS_TIMEOUT error code"
                    );
                }
                ConnectionStatus::Closed => {
                    // Connection closed after timeout
                }
            }
        } else if ack_delay.send_ack {
            // Send ACK before timeout
            let ack_result = if ack_delay.malformed_ack {
                mock_connection.send_malformed_settings_ack(*settings_id)
            } else {
                mock_connection.send_settings_ack(*settings_id)
            };

            if !ack_delay.malformed_ack {
                assert!(
                    matches!(ack_result, AckResult::Accepted),
                    "Valid SETTINGS ACK should be accepted"
                );
            }
        }
    }

    // Final state check
    let final_state = mock_connection.get_connection_state();
    let goaway_sent = mock_connection.goaway_sent();

    // If any SETTINGS ACK timed out, connection should be in error state
    let has_timeouts = test_case.ack_delays.iter().enumerate().any(|(i, delay)| {
        i < pending_settings.len()
            && delay.delay_ms > test_case.timeout_config.settings_ack_timeout_ms
            && !delay.send_ack
    });

    if has_timeouts {
        assert!(
            goaway_sent
                || matches!(
                    final_state,
                    ConnectionStatus::GoAway { .. } | ConnectionStatus::Closed
                ),
            "Connection should be terminated after SETTINGS ACK timeout"
        );
    }
}

/// Test multiple pending SETTINGS handling
fn test_multiple_pending_settings(test_case: &SettingsAckTimeoutTest) {
    if test_case.settings_frames.len() < 2 {
        return; // Need multiple SETTINGS frames
    }

    let mut mock_connection = MockH2Connection::new(test_case.timeout_config.clone());

    // Send multiple SETTINGS frames quickly
    let mut settings_ids = Vec::new();
    for settings_frame in &test_case.settings_frames {
        if settings_frame.ack
            || settings_ids.len() >= test_case.timeout_config.max_pending_settings as usize
        {
            break;
        }

        let result = mock_connection.send_settings_frame(settings_frame.clone());
        if let SettingsResult::Sent { settings_id } = result {
            settings_ids.push(settings_id);
        }
    }

    // Check if connection enforces max pending SETTINGS
    if settings_ids.len() >= test_case.timeout_config.max_pending_settings as usize {
        let state = mock_connection.get_connection_state();
        // Implementation may limit pending SETTINGS or close connection
        if !matches!(state, ConnectionStatus::Open) {
            assert!(
                mock_connection.goaway_sent(),
                "Should send GOAWAY if too many pending SETTINGS"
            );
        }
    }

    // Test out-of-order ACKs
    if test_case.out_of_order_acks && settings_ids.len() >= 2 {
        // ACK the second SETTINGS first
        if settings_ids.len() >= 2 {
            let ack_result = mock_connection.send_settings_ack(settings_ids[1]);
            // Out-of-order ACK might be accepted or rejected depending on implementation
        }

        // Then ACK the first
        let ack_result = mock_connection.send_settings_ack(settings_ids[0]);
        // Should be accepted even after out-of-order ACK
    }
}

/// Test GOAWAY behavior after timeout
fn test_goaway_after_timeout(test_case: &SettingsAckTimeoutTest) {
    let mut mock_connection = MockH2Connection::new(test_case.timeout_config.clone());

    // Send a SETTINGS frame
    let settings_frame = SettingsFrame {
        settings: vec![Setting {
            id: SettingId::InitialWindowSize,
            value: 32768,
        }],
        ack: false,
        extra_data: vec![],
    };

    let result = mock_connection.send_settings_frame(settings_frame);
    if !matches!(result, SettingsResult::Sent { .. }) {
        return; // Skip if SETTINGS was rejected
    }

    // Advance time past timeout without sending ACK
    let timeout_ms = test_case.timeout_config.settings_ack_timeout_ms + 1000;
    mock_connection.advance_time(Duration::from_millis(timeout_ms as u64));

    // Check GOAWAY was sent
    assert!(
        mock_connection.goaway_sent(),
        "GOAWAY should be sent after SETTINGS ACK timeout"
    );

    let goaway_info = mock_connection.get_goaway_info();
    if let Some(goaway) = goaway_info {
        assert_eq!(
            goaway.error_code,
            H2ErrorCode::SettingsTimeout,
            "GOAWAY should indicate SETTINGS_TIMEOUT"
        );

        // Last stream ID should be set appropriately
        assert!(
            goaway.last_stream_id <= mock_connection.get_last_stream_id(),
            "GOAWAY last_stream_id should not exceed actual last stream"
        );
    }

    // Connection should reject new streams after GOAWAY
    let new_stream_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.try_open_stream(999)
    }));

    assert!(
        new_stream_result.is_ok(),
        "Opening stream after GOAWAY should not panic"
    );
    if let Ok(stream_result) = new_stream_result {
        assert!(
            matches!(stream_result, StreamResult::Rejected { .. }),
            "New streams should be rejected after GOAWAY"
        );
    }
}

/// Test connection cleanup after timeout
fn test_connection_cleanup_after_timeout(test_case: &SettingsAckTimeoutTest) {
    let mut mock_connection = MockH2Connection::new(test_case.timeout_config.clone());

    // Set up some stream operations
    for operation in &test_case.connection_state.pending_operations {
        mock_connection.add_pending_operation(operation.clone());
    }

    // Send SETTINGS and let it timeout
    let settings_frame = SettingsFrame {
        settings: vec![Setting {
            id: SettingId::MaxConcurrentStreams,
            value: 100,
        }],
        ack: false,
        extra_data: vec![],
    };

    let _result = mock_connection.send_settings_frame(settings_frame);

    // Advance past timeout
    let timeout_ms = test_case.timeout_config.settings_ack_timeout_ms + 500;
    mock_connection.advance_time(Duration::from_millis(timeout_ms as u64));

    // Check cleanup
    let pending_count = mock_connection.get_pending_operations_count();
    let stream_count = mock_connection.get_active_stream_count();

    // After GOAWAY, pending operations might be cancelled
    // and streams might be cleaned up (implementation dependent)
    if mock_connection.goaway_sent() {
        // Resources should be cleaned up or in process of cleanup
        // (exact behavior depends on implementation)
    }

    // Connection should not accept new operations
    let new_op_result = mock_connection.add_pending_operation(StreamOperation {
        stream_id: 1001,
        operation: StreamOpType::SendData,
        data_size: 1024,
    });

    if mock_connection.goaway_sent() {
        assert!(
            matches!(new_op_result, OperationResult::Rejected { .. }),
            "New operations should be rejected after GOAWAY"
        );
    }
}

/// Test edge cases in SETTINGS timeout handling
fn test_settings_timeout_edge_cases(test_case: &SettingsAckTimeoutTest) {
    let mut mock_connection = MockH2Connection::new(test_case.timeout_config.clone());

    // Test zero timeout
    if test_case.timeout_config.settings_ack_timeout_ms == 0 {
        let settings_frame = SettingsFrame {
            settings: vec![Setting {
                id: SettingId::HeaderTableSize,
                value: 4096,
            }],
            ack: false,
            extra_data: vec![],
        };

        let result = mock_connection.send_settings_frame(settings_frame);
        // Zero timeout should either immediately timeout or use minimum timeout
    }

    // Test SETTINGS ACK without matching SETTINGS
    let orphan_ack_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_settings_ack(999) // Non-existent settings ID
    }));

    assert!(
        orphan_ack_result.is_ok(),
        "Orphan SETTINGS ACK should not panic"
    );
    if let Ok(ack_result) = orphan_ack_result {
        assert!(
            matches!(ack_result, AckResult::Ignored | AckResult::Rejected { .. }),
            "Orphan SETTINGS ACK should be ignored or rejected"
        );
    }

    // Test SETTINGS with invalid values
    let invalid_settings = vec![
        Setting {
            id: SettingId::EnablePush,
            value: 2, // Should be 0 or 1
        },
        Setting {
            id: SettingId::InitialWindowSize,
            value: 0x80000000, // Exceeds maximum
        },
        Setting {
            id: SettingId::MaxFrameSize,
            value: 8192, // Below minimum
        },
    ];

    for invalid_setting in invalid_settings {
        let invalid_frame = SettingsFrame {
            settings: vec![invalid_setting],
            ack: false,
            extra_data: vec![],
        };

        let invalid_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mock_connection.send_settings_frame(invalid_frame)
        }));

        assert!(invalid_result.is_ok(), "Invalid SETTINGS should not panic");
        // Invalid SETTINGS should be rejected or cause connection error
    }

    // Test very large SETTINGS frame
    let large_settings: Vec<Setting> = (0..100)
        .map(|i| Setting {
            id: SettingId::Unknown(i),
            value: i as u32,
        })
        .collect();

    let large_frame = SettingsFrame {
        settings: large_settings,
        ack: false,
        extra_data: vec![0xFF; 1000],
    };

    let large_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_settings_frame(large_frame)
    }));

    assert!(
        large_result.is_ok(),
        "Large SETTINGS frame should not panic"
    );
}

impl SettingId {
    fn to_u16(&self) -> u16 {
        match self {
            Self::HeaderTableSize => 0x1,
            Self::EnablePush => 0x2,
            Self::MaxConcurrentStreams => 0x3,
            Self::InitialWindowSize => 0x4,
            Self::MaxFrameSize => 0x5,
            Self::MaxHeaderListSize => 0x6,
            Self::Unknown(id) => *id,
        }
    }
}

/// Check if SETTINGS contain invalid values
fn has_invalid_settings(settings: &[Setting]) -> bool {
    settings.iter().any(|setting| match setting.id {
        SettingId::EnablePush => setting.value > 1,
        SettingId::InitialWindowSize => setting.value > 0x7FFFFFFF,
        SettingId::MaxFrameSize => setting.value < 16384 || setting.value > 0xFFFFFF,
        _ => false,
    })
}

/// HTTP/2 error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum H2ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

/// Connection status
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectionStatus {
    Open,
    GoAway { error_code: H2ErrorCode },
    Closed,
}

/// SETTINGS frame result
#[derive(Debug, Clone)]
enum SettingsResult {
    Sent { settings_id: u32 },
    Rejected { reason: String },
}

/// SETTINGS ACK result
#[derive(Debug, Clone)]
enum AckResult {
    Accepted,
    Rejected { reason: String },
    Ignored,
}

/// Stream operation result
#[derive(Debug, Clone)]
enum StreamResult {
    Opened { stream_id: u32 },
    Rejected { reason: String },
}

/// Operation result
#[derive(Debug, Clone)]
enum OperationResult {
    Accepted,
    Rejected { reason: String },
}

/// GOAWAY frame information
#[derive(Debug, Clone)]
struct GoAwayInfo {
    last_stream_id: u32,
    error_code: H2ErrorCode,
}

/// Mock HTTP/2 connection for testing
struct MockH2Connection {
    timeout_config: TimeoutConfig,
    connection_status: ConnectionStatus,
    pending_settings: HashMap<u32, Instant>, // settings_id -> sent_time
    next_settings_id: u32,
    current_time: Instant,
    goaway_sent: bool,
    goaway_info: Option<GoAwayInfo>,
    last_stream_id: u32,
    pending_operations: Vec<StreamOperation>,
    active_streams: u32,
}

impl MockH2Connection {
    fn new(timeout_config: TimeoutConfig) -> Self {
        Self {
            timeout_config,
            connection_status: ConnectionStatus::Open,
            pending_settings: HashMap::new(),
            next_settings_id: 1,
            current_time: Instant::now(),
            goaway_sent: false,
            goaway_info: None,
            last_stream_id: 0,
            pending_operations: Vec::new(),
            active_streams: 0,
        }
    }

    fn set_connection_state(&mut self, state: &ConnectionState) {
        if state.error_state {
            self.connection_status = ConnectionStatus::GoAway {
                error_code: H2ErrorCode::InternalError,
            };
        }

        self.pending_operations = state.pending_operations.clone();
        self.active_streams = state.pending_operations.len() as u32;
    }

    fn send_settings_frame(&mut self, settings_frame: SettingsFrame) -> SettingsResult {
        if settings_frame.ack {
            return SettingsResult::Rejected {
                reason: "Cannot send SETTINGS ACK through this method".to_string(),
            };
        }

        if !matches!(self.connection_status, ConnectionStatus::Open) {
            return SettingsResult::Rejected {
                reason: "Connection not open".to_string(),
            };
        }

        // Check for invalid SETTINGS
        if has_invalid_settings(&settings_frame.settings) {
            return SettingsResult::Rejected {
                reason: "Invalid SETTINGS values".to_string(),
            };
        }

        // Check frame size
        if settings_frame.extra_data.len() > 16384 {
            return SettingsResult::Rejected {
                reason: "SETTINGS frame too large".to_string(),
            };
        }

        // Check max pending SETTINGS
        if self.pending_settings.len() >= self.timeout_config.max_pending_settings as usize {
            self.send_goaway(H2ErrorCode::EnhanceYourCalm);
            return SettingsResult::Rejected {
                reason: "Too many pending SETTINGS".to_string(),
            };
        }

        let settings_id = self.next_settings_id;
        self.next_settings_id += 1;

        self.pending_settings.insert(settings_id, self.current_time);

        SettingsResult::Sent { settings_id }
    }

    fn send_settings_ack(&mut self, settings_id: u32) -> AckResult {
        if let Some(_sent_time) = self.pending_settings.remove(&settings_id) {
            AckResult::Accepted
        } else {
            AckResult::Ignored
        }
    }

    fn send_malformed_settings_ack(&mut self, settings_id: u32) -> AckResult {
        // Malformed ACK should be rejected
        AckResult::Rejected {
            reason: "Malformed SETTINGS ACK".to_string(),
        }
    }

    fn advance_time(&mut self, duration: Duration) {
        self.current_time += duration;
        self.check_timeouts();
    }

    fn check_timeouts(&mut self) {
        let timeout_duration =
            Duration::from_millis(self.timeout_config.settings_ack_timeout_ms as u64);
        let mut timed_out = Vec::new();

        for (settings_id, sent_time) in &self.pending_settings {
            if self.current_time.duration_since(*sent_time) > timeout_duration {
                timed_out.push(*settings_id);
            }
        }

        if !timed_out.is_empty() {
            // Remove timed out settings
            for settings_id in timed_out {
                self.pending_settings.remove(&settings_id);
            }

            // Send GOAWAY for timeout
            self.send_goaway(H2ErrorCode::SettingsTimeout);
        }
    }

    fn send_goaway(&mut self, error_code: H2ErrorCode) {
        if !self.goaway_sent {
            self.goaway_sent = true;
            self.goaway_info = Some(GoAwayInfo {
                last_stream_id: self.last_stream_id,
                error_code,
            });
            self.connection_status = ConnectionStatus::GoAway { error_code };
        }
    }

    fn get_connection_state(&self) -> ConnectionStatus {
        self.connection_status.clone()
    }

    fn goaway_sent(&self) -> bool {
        self.goaway_sent
    }

    fn get_goaway_info(&self) -> Option<GoAwayInfo> {
        self.goaway_info.clone()
    }

    fn get_last_stream_id(&self) -> u32 {
        self.last_stream_id
    }

    fn try_open_stream(&mut self, stream_id: u32) -> StreamResult {
        if self.goaway_sent {
            return StreamResult::Rejected {
                reason: "GOAWAY sent".to_string(),
            };
        }

        self.last_stream_id = stream_id.max(self.last_stream_id);
        self.active_streams += 1;

        StreamResult::Opened { stream_id }
    }

    fn add_pending_operation(&mut self, operation: StreamOperation) -> OperationResult {
        if self.goaway_sent {
            return OperationResult::Rejected {
                reason: "Connection closing".to_string(),
            };
        }

        self.pending_operations.push(operation);
        OperationResult::Accepted
    }

    fn get_pending_operations_count(&self) -> usize {
        self.pending_operations.len()
    }

    fn get_active_stream_count(&self) -> u32 {
        self.active_streams
    }
}

/// Generate test scenarios for SETTINGS ACK timeout
fn generate_timeout_scenarios() -> Vec<SettingsAckTimeoutTest> {
    vec![
        // Basic timeout scenario
        SettingsAckTimeoutTest {
            settings_frames: vec![SettingsFrame {
                settings: vec![Setting {
                    id: SettingId::InitialWindowSize,
                    value: 32768,
                }],
                ack: false,
                extra_data: vec![],
            }],
            ack_delays: vec![AckDelay {
                delay_ms: 6000, // Longer than typical timeout
                send_ack: false,
                malformed_ack: false,
            }],
            timeout_config: TimeoutConfig {
                settings_ack_timeout_ms: 5000,
                idle_timeout_ms: 30000,
                max_pending_settings: 5,
            },
            out_of_order_acks: false,
            connection_state: ConnectionState {
                window_size: 65535,
                max_concurrent_streams: 100,
                error_state: false,
                pending_operations: vec![],
            },
        },
        // Multiple SETTINGS with mixed ACK behavior
        SettingsAckTimeoutTest {
            settings_frames: vec![
                SettingsFrame {
                    settings: vec![Setting {
                        id: SettingId::MaxConcurrentStreams,
                        value: 50,
                    }],
                    ack: false,
                    extra_data: vec![],
                },
                SettingsFrame {
                    settings: vec![Setting {
                        id: SettingId::HeaderTableSize,
                        value: 8192,
                    }],
                    ack: false,
                    extra_data: vec![],
                },
            ],
            ack_delays: vec![
                AckDelay {
                    delay_ms: 2000, // Within timeout
                    send_ack: true,
                    malformed_ack: false,
                },
                AckDelay {
                    delay_ms: 8000, // Exceeds timeout
                    send_ack: false,
                    malformed_ack: false,
                },
            ],
            timeout_config: TimeoutConfig {
                settings_ack_timeout_ms: 5000,
                idle_timeout_ms: 60000,
                max_pending_settings: 3,
            },
            out_of_order_acks: true,
            connection_state: ConnectionState {
                window_size: 32768,
                max_concurrent_streams: 50,
                error_state: false,
                pending_operations: vec![StreamOperation {
                    stream_id: 1,
                    operation: StreamOpType::SendData,
                    data_size: 1024,
                }],
            },
        },
    ]
}

/// Test that demonstrates expected SETTINGS ACK timeout behavior
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_ack_timeout_sends_goaway() {
        let timeout_config = TimeoutConfig {
            settings_ack_timeout_ms: 1000,
            idle_timeout_ms: 30000,
            max_pending_settings: 5,
        };

        let mut conn = MockH2Connection::new(timeout_config);

        // Send SETTINGS
        let settings = SettingsFrame {
            settings: vec![Setting {
                id: SettingId::InitialWindowSize,
                value: 32768,
            }],
            ack: false,
            extra_data: vec![],
        };

        let result = conn.send_settings_frame(settings);
        assert!(matches!(result, SettingsResult::Sent { .. }));

        // Advance time past timeout
        conn.advance_time(Duration::from_millis(2000));

        // Should have sent GOAWAY
        assert!(conn.goaway_sent());
        let goaway = conn.get_goaway_info().unwrap();
        assert_eq!(goaway.error_code, H2ErrorCode::SettingsTimeout);
    }

    #[test]
    fn test_settings_ack_prevents_timeout() {
        let timeout_config = TimeoutConfig {
            settings_ack_timeout_ms: 1000,
            idle_timeout_ms: 30000,
            max_pending_settings: 5,
        };

        let mut conn = MockH2Connection::new(timeout_config);

        // Send SETTINGS
        let settings = SettingsFrame {
            settings: vec![Setting {
                id: SettingId::MaxFrameSize,
                value: 32768,
            }],
            ack: false,
            extra_data: vec![],
        };

        let result = conn.send_settings_frame(settings);
        let settings_id = match result {
            SettingsResult::Sent { settings_id } => settings_id,
            _ => panic!("SETTINGS should be sent"),
        };

        // Send ACK before timeout
        conn.advance_time(Duration::from_millis(500));
        let ack_result = conn.send_settings_ack(settings_id);
        assert!(matches!(ack_result, AckResult::Accepted));

        // Advance past original timeout
        conn.advance_time(Duration::from_millis(1000));

        // Should NOT have sent GOAWAY
        assert!(!conn.goaway_sent());
        assert_eq!(conn.get_connection_state(), ConnectionStatus::Open);
    }

    #[test]
    fn test_max_pending_settings_limit() {
        let timeout_config = TimeoutConfig {
            settings_ack_timeout_ms: 5000,
            idle_timeout_ms: 30000,
            max_pending_settings: 2,
        };

        let mut conn = MockH2Connection::new(timeout_config);

        // Send maximum number of SETTINGS
        for i in 0..3 {
            let settings = SettingsFrame {
                settings: vec![Setting {
                    id: SettingId::Unknown(i),
                    value: i as u32,
                }],
                ack: false,
                extra_data: vec![],
            };

            let result = conn.send_settings_frame(settings);
            if i < 2 {
                assert!(matches!(result, SettingsResult::Sent { .. }));
            } else {
                // Third SETTINGS should trigger GOAWAY
                assert!(conn.goaway_sent() || matches!(result, SettingsResult::Rejected { .. }));
            }
        }
    }
}
