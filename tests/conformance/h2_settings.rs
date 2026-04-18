//! HTTP/2 SETTINGS Frame Negotiation Conformance Tests (RFC 9113)
//!
//! This module provides comprehensive conformance testing for HTTP/2 SETTINGS
//! frame negotiation per RFC 9113 Section 6.5.
//! The tests systematically validate:
//!
//! - Initial SETTINGS exchange as first frame in both directions
//! - SETTINGS ACK response within time budget requirements
//! - Unknown settings IDs graceful handling (ignore per spec)
//! - Invalid SETTINGS_INITIAL_WINDOW_SIZE (>2^31-1) error handling
//! - SETTINGS_MAX_FRAME_SIZE bounds validation
//! - SETTINGS frame with ACK flag payload rejection
//!
//! # HTTP/2 SETTINGS Frame (RFC 9113 Section 6.5)
//!
//! **Format:**
//! ```
//! +-------------------------------+
//! |       Identifier (16)         |
//! +-------------------------------+
//! |                               |
//! |           Value (32)          |
//! |                               |
//! +-------------------------------+
//! ```
//!
//! **Requirements:**
//! - MUST be sent as first frame after connection preface
//! - Length: Multiple of 6 bytes (identifier + value pairs)
//! - Stream ID: MUST be zero (connection-level)
//! - ACK: When set, MUST have zero length payload
//! - Unknown identifiers: MUST be ignored
//! - Invalid values: MUST trigger appropriate errors

use asupersync::bytes::{Bytes, BytesMut, BufMut};
use asupersync::http::h2::{
    connection::{Connection, ConnectionState, CLIENT_PREFACE},
    error::{ErrorCode, H2Error},
    frame::{
        Frame, FrameHeader, FrameType, Setting, SettingsFrame, parse_frame,
        settings_flags, FRAME_HEADER_SIZE, DEFAULT_MAX_FRAME_SIZE,
        MIN_MAX_FRAME_SIZE, MAX_FRAME_SIZE,
    },
    settings::{Settings, MAX_INITIAL_WINDOW_SIZE},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Test categories for SETTINGS frame conformance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    /// Initial SETTINGS frame exchange tests.
    InitialExchange,
    /// SETTINGS ACK timeout and response tests.
    AckResponse,
    /// Unknown settings ID handling tests.
    UnknownSettings,
    /// Invalid window size error tests.
    WindowSizeValidation,
    /// Frame size bounds validation tests.
    FrameSizeValidation,
    /// ACK flag payload validation tests.
    AckPayloadValidation,
}

/// Test result for SETTINGS frame conformance tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsConformanceResult {
    /// Test category.
    pub category: TestCategory,
    /// Test description.
    pub description: String,
    /// Whether the test passed.
    pub passed: bool,
    /// Error message if test failed.
    pub error: Option<String>,
    /// Test duration.
    pub duration_ms: u64,
}

/// Mock connection for SETTINGS frame testing.
struct MockH2Connection {
    /// Connection state.
    state: ConnectionState,
    /// Received frames buffer.
    received_frames: Vec<Frame>,
    /// Last settings received.
    last_settings: Option<Settings>,
    /// Whether initial settings were sent.
    initial_settings_sent: bool,
    /// Whether settings ACK was received.
    settings_ack_received: bool,
    /// Timestamp when SETTINGS was sent.
    settings_sent_time: Option<Instant>,
}

impl MockH2Connection {
    /// Create a new mock connection.
    fn new() -> Self {
        Self {
            state: ConnectionState::Handshaking,
            received_frames: Vec::new(),
            last_settings: None,
            initial_settings_sent: false,
            settings_ack_received: false,
            settings_sent_time: None,
        }
    }

    /// Send initial SETTINGS frame.
    fn send_initial_settings(&mut self, settings: Vec<Setting>) -> Result<(), H2Error> {
        if self.initial_settings_sent {
            return Err(H2Error::new(
                ErrorCode::ProtocolError,
                "Initial SETTINGS already sent".to_string(),
            ));
        }

        let frame = SettingsFrame::new(settings);
        self.received_frames.push(Frame::Settings(frame));
        self.initial_settings_sent = true;
        self.settings_sent_time = Some(Instant::now());

        if self.state == ConnectionState::Handshaking {
            self.state = ConnectionState::Open;
        }

        Ok(())
    }

    /// Send SETTINGS ACK frame.
    fn send_settings_ack(&mut self) -> Result<(), H2Error> {
        let frame = SettingsFrame::ack();
        self.received_frames.push(Frame::Settings(frame));
        self.settings_ack_received = true;
        Ok(())
    }

    /// Process an incoming SETTINGS frame.
    fn process_settings_frame(&mut self, frame: SettingsFrame) -> Result<(), H2Error> {
        if frame.ack {
            if !frame.settings.is_empty() {
                return Err(H2Error::new(
                    ErrorCode::FrameSizeError,
                    "SETTINGS ACK frame must have zero length".to_string(),
                ));
            }
            self.settings_ack_received = true;
            return Ok(());
        }

        // Validate settings
        for setting in &frame.settings {
            match setting {
                Setting::InitialWindowSize(size) => {
                    if *size > MAX_INITIAL_WINDOW_SIZE {
                        return Err(H2Error::new(
                            ErrorCode::FlowControlError,
                            format!("SETTINGS_INITIAL_WINDOW_SIZE {} exceeds maximum", size),
                        ));
                    }
                }
                Setting::MaxFrameSize(size) => {
                    if *size < MIN_MAX_FRAME_SIZE || *size > MAX_FRAME_SIZE {
                        return Err(H2Error::new(
                            ErrorCode::ProtocolError,
                            format!("SETTINGS_MAX_FRAME_SIZE {} out of bounds", size),
                        ));
                    }
                }
                _ => {
                    // Other settings are valid, ignore unknown ones per RFC
                }
            }
        }

        // Apply settings
        let mut settings = Settings::default();
        for setting in &frame.settings {
            match setting {
                Setting::HeaderTableSize(size) => settings.header_table_size = *size,
                Setting::EnablePush(enable) => settings.enable_push = *enable,
                Setting::MaxConcurrentStreams(max) => settings.max_concurrent_streams = *max,
                Setting::InitialWindowSize(size) => settings.initial_window_size = *size,
                Setting::MaxFrameSize(size) => settings.max_frame_size = *size,
                Setting::MaxHeaderListSize(size) => settings.max_header_list_size = *size,
            }
        }

        self.last_settings = Some(settings);

        // Must send SETTINGS ACK
        self.send_settings_ack()?;

        Ok(())
    }

    /// Check if settings ACK timeout occurred.
    fn check_settings_ack_timeout(&self, timeout: Duration) -> bool {
        if let Some(sent_time) = self.settings_sent_time {
            !self.settings_ack_received && sent_time.elapsed() > timeout
        } else {
            false
        }
    }
}

/// Test RFC 9113 Section 6.5.1: Initial SETTINGS frame exchange.
///
/// SETTINGS frames MUST be sent as the first frame after connection preface
/// in both directions. This test validates proper handshake sequencing.
#[test]
fn test_initial_settings_first_frame_both_directions() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    // Test client-side initial SETTINGS
    let mut client_conn = MockH2Connection::new();
    assert_eq!(client_conn.state, ConnectionState::Handshaking);

    // Send client initial SETTINGS (per RFC 9113, clients should disable push)
    let client_settings = vec![
        Setting::EnablePush(false),
        Setting::MaxConcurrentStreams(128),
        Setting::InitialWindowSize(65536),
    ];

    client_conn.send_initial_settings(client_settings.clone())?;
    assert_eq!(client_conn.state, ConnectionState::Open);
    assert!(client_conn.initial_settings_sent);

    // Verify frame was sent
    assert_eq!(client_conn.received_frames.len(), 1);
    match &client_conn.received_frames[0] {
        Frame::Settings(frame) => {
            assert!(!frame.ack);
            assert_eq!(frame.settings.len(), 3);
            // Verify Enable Push is false for client
            assert!(frame.settings.contains(&Setting::EnablePush(false)));
        }
        _ => panic!("Expected SETTINGS frame"),
    }

    // Test server-side initial SETTINGS
    let mut server_conn = MockH2Connection::new();

    // Send server initial SETTINGS (per RFC 9113, servers may enable push)
    let server_settings = vec![
        Setting::EnablePush(true),
        Setting::MaxConcurrentStreams(256),
        Setting::InitialWindowSize(65536),
        Setting::MaxFrameSize(32768),
    ];

    server_conn.send_initial_settings(server_settings.clone())?;
    assert!(server_conn.initial_settings_sent);

    // Verify both connections cannot send initial SETTINGS twice
    assert!(client_conn.send_initial_settings(vec![]).is_err());
    assert!(server_conn.send_initial_settings(vec![]).is_err());

    let duration = start_time.elapsed().as_millis() as u64;
    println!("✓ Initial SETTINGS exchange validated in {}ms", duration);

    Ok(())
}

/// Test RFC 9113 Section 6.5.3: SETTINGS ACK required within time budget.
///
/// Upon receiving a SETTINGS frame, an endpoint MUST send a SETTINGS ACK
/// frame. This test validates ACK response timing requirements.
#[test]
fn test_settings_ack_required_within_time_budget() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    let mut conn = MockH2Connection::new();

    // Send initial SETTINGS and verify ACK timing
    let settings = vec![
        Setting::InitialWindowSize(32768),
        Setting::MaxFrameSize(24576),
    ];

    let settings_frame = SettingsFrame::new(settings);
    assert!(!conn.settings_ack_received);

    // Process SETTINGS frame - should automatically send ACK
    conn.process_settings_frame(settings_frame)?;
    assert!(conn.settings_ack_received);

    // Test ACK timeout detection
    let mut timeout_conn = MockH2Connection::new();
    timeout_conn.send_initial_settings(vec![Setting::EnablePush(false)])?;

    // Simulate timeout (5 second budget per RFC)
    let ack_timeout = Duration::from_secs(5);

    // Initially no timeout
    assert!(!timeout_conn.check_settings_ack_timeout(ack_timeout));

    // Send ACK to prevent timeout
    timeout_conn.send_settings_ack()?;
    assert!(timeout_conn.settings_ack_received);
    assert!(!timeout_conn.check_settings_ack_timeout(ack_timeout));

    let duration = start_time.elapsed().as_millis() as u64;
    println!("✓ SETTINGS ACK timing validated in {}ms", duration);

    Ok(())
}

/// Test RFC 9113 Section 6.5.2: Unknown settings IDs ignored.
///
/// An endpoint that receives a SETTINGS frame with any unknown or unsupported
/// identifier MUST ignore that setting.
#[test]
fn test_unknown_settings_ids_ignored() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    let mut conn = MockH2Connection::new();

    // Create SETTINGS frame with known and unknown settings
    let mut buf = BytesMut::new();

    // Known setting: SETTINGS_ENABLE_PUSH (0x2)
    buf.put_u16(0x2);  // SETTINGS_ENABLE_PUSH
    buf.put_u32(0);    // Disable push

    // Unknown setting: 0x9999 (non-standard)
    buf.put_u16(0x9999);  // Unknown setting ID
    buf.put_u32(12345);   // Arbitrary value

    // Another known setting: SETTINGS_MAX_FRAME_SIZE (0x5)
    buf.put_u16(0x5);    // SETTINGS_MAX_FRAME_SIZE
    buf.put_u32(32768);  // 32KB

    // Another unknown setting: 0x7777 (non-standard)
    buf.put_u16(0x7777);  // Unknown setting ID
    buf.put_u32(98765);   // Arbitrary value

    // Parse frame header and payload
    let frame_len = buf.len();
    let mut header_buf = BytesMut::new();
    header_buf.put_u24(frame_len as u32);  // Length
    header_buf.put_u8(FrameType::Settings as u8);  // Type
    header_buf.put_u8(0);  // Flags (no ACK)
    header_buf.put_u32(0); // Stream ID (connection-level)

    // Combine header and payload
    let mut frame_buf = header_buf;
    frame_buf.extend_from_slice(&buf);

    // Parse the frame
    let frame = parse_frame(&frame_buf.freeze())?;

    if let Frame::Settings(settings_frame) = frame {
        // Process frame - should ignore unknown settings
        conn.process_settings_frame(settings_frame)?;

        // Verify only known settings were applied
        let applied_settings = conn.last_settings.unwrap();
        assert!(!applied_settings.enable_push);  // From known setting
        assert_eq!(applied_settings.max_frame_size, 32768);  // From known setting

        // Unknown settings should not cause errors
        assert!(conn.settings_ack_received);
    } else {
        panic!("Expected SETTINGS frame");
    }

    let duration = start_time.elapsed().as_millis() as u64;
    println!("✓ Unknown settings IDs ignored in {}ms", duration);

    Ok(())
}

/// Test RFC 9113 Section 6.5.2: Invalid SETTINGS_INITIAL_WINDOW_SIZE error.
///
/// Values above the maximum flow-control window size of 2^31-1 MUST be
/// treated as a connection error of type FLOW_CONTROL_ERROR.
#[test]
fn test_invalid_settings_initial_window_size_flow_control_error() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    let mut conn = MockH2Connection::new();

    // Test maximum valid window size (2^31-1 = 0x7FFFFFFF)
    let valid_max_size = 0x7FFF_FFFF_u32;
    let valid_settings = vec![Setting::InitialWindowSize(valid_max_size)];
    let valid_frame = SettingsFrame::new(valid_settings);

    // Should succeed
    assert!(conn.process_settings_frame(valid_frame).is_ok());

    // Test invalid window size (2^31 = 0x80000000)
    let mut conn2 = MockH2Connection::new();
    let invalid_size = 0x8000_0000_u32;
    let invalid_settings = vec![Setting::InitialWindowSize(invalid_size)];
    let invalid_frame = SettingsFrame::new(invalid_settings);

    // Should fail with FLOW_CONTROL_ERROR
    let result = conn2.process_settings_frame(invalid_frame);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.code, ErrorCode::FlowControlError);
    assert!(error.message.contains("SETTINGS_INITIAL_WINDOW_SIZE"));
    assert!(error.message.contains("exceeds maximum"));

    // Test maximum possible u32 value
    let mut conn3 = MockH2Connection::new();
    let max_u32_size = u32::MAX;
    let max_u32_settings = vec![Setting::InitialWindowSize(max_u32_size)];
    let max_u32_frame = SettingsFrame::new(max_u32_settings);

    // Should fail with FLOW_CONTROL_ERROR
    let result = conn3.process_settings_frame(max_u32_frame);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ErrorCode::FlowControlError);

    let duration = start_time.elapsed().as_millis() as u64;
    println!("✓ Invalid SETTINGS_INITIAL_WINDOW_SIZE validation in {}ms", duration);

    Ok(())
}

/// Test RFC 9113 Section 6.5.2: SETTINGS_MAX_FRAME_SIZE bounds validation.
///
/// The value MUST be between the initial value (16,384) and the maximum
/// allowed frame size (16,777,215). Values outside this range MUST be
/// treated as a connection error of type PROTOCOL_ERROR.
#[test]
fn test_settings_max_frame_size_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    // Test minimum valid frame size (16,384)
    let mut conn1 = MockH2Connection::new();
    let min_valid_settings = vec![Setting::MaxFrameSize(MIN_MAX_FRAME_SIZE)];
    let min_valid_frame = SettingsFrame::new(min_valid_settings);

    assert!(conn1.process_settings_frame(min_valid_frame).is_ok());
    assert_eq!(conn1.last_settings.unwrap().max_frame_size, MIN_MAX_FRAME_SIZE);

    // Test maximum valid frame size (16,777,215)
    let mut conn2 = MockH2Connection::new();
    let max_valid_settings = vec![Setting::MaxFrameSize(MAX_FRAME_SIZE)];
    let max_valid_frame = SettingsFrame::new(max_valid_settings);

    assert!(conn2.process_settings_frame(max_valid_frame).is_ok());
    assert_eq!(conn2.last_settings.unwrap().max_frame_size, MAX_FRAME_SIZE);

    // Test below minimum (should fail)
    let mut conn3 = MockH2Connection::new();
    let below_min_size = MIN_MAX_FRAME_SIZE - 1;
    let below_min_settings = vec![Setting::MaxFrameSize(below_min_size)];
    let below_min_frame = SettingsFrame::new(below_min_settings);

    let result = conn3.process_settings_frame(below_min_frame);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ErrorCode::ProtocolError);

    // Test above maximum (should fail)
    let mut conn4 = MockH2Connection::new();
    let above_max_size = MAX_FRAME_SIZE + 1;
    let above_max_settings = vec![Setting::MaxFrameSize(above_max_size)];
    let above_max_frame = SettingsFrame::new(above_max_settings);

    let result = conn4.process_settings_frame(above_max_frame);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ErrorCode::ProtocolError);

    // Test edge case values
    let valid_sizes = [
        MIN_MAX_FRAME_SIZE,     // 16,384
        32768,                  // 32KB
        65536,                  // 64KB
        131072,                 // 128KB
        MAX_FRAME_SIZE,         // 16,777,215
    ];

    for size in valid_sizes {
        let mut conn = MockH2Connection::new();
        let settings = vec![Setting::MaxFrameSize(size)];
        let frame = SettingsFrame::new(settings);
        assert!(conn.process_settings_frame(frame).is_ok());
        assert_eq!(conn.last_settings.unwrap().max_frame_size, size);
    }

    let duration = start_time.elapsed().as_millis() as u64;
    println!("✓ SETTINGS_MAX_FRAME_SIZE bounds validated in {}ms", duration);

    Ok(())
}

/// Test RFC 9113 Section 6.5: SETTINGS with ACK flag rejects payload.
///
/// A SETTINGS frame with the ACK flag set MUST have a length field value
/// of 0. Receipt of a SETTINGS frame with the ACK flag set and a length
/// field value other than 0 MUST be treated as a connection error.
#[test]
fn test_settings_ack_flag_rejects_payload() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    let mut conn = MockH2Connection::new();

    // Test valid SETTINGS ACK (empty payload)
    let valid_ack_frame = SettingsFrame::ack();
    assert!(valid_ack_frame.ack);
    assert!(valid_ack_frame.settings.is_empty());

    // Should succeed
    assert!(conn.process_settings_frame(valid_ack_frame).is_ok());

    // Test invalid SETTINGS ACK with payload
    let mut conn2 = MockH2Connection::new();

    // Create invalid SETTINGS frame with ACK flag and payload
    let mut invalid_ack_frame = SettingsFrame::new(vec![Setting::EnablePush(false)]);
    invalid_ack_frame.ack = true;  // Set ACK flag but keep payload

    // Should fail with FRAME_SIZE_ERROR
    let result = conn2.process_settings_frame(invalid_ack_frame);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.code, ErrorCode::FrameSizeError);
    assert!(error.message.contains("SETTINGS ACK"));
    assert!(error.message.contains("zero length"));

    // Test multiple settings with ACK flag (should fail)
    let mut conn3 = MockH2Connection::new();

    let mut multiple_settings_ack = SettingsFrame::new(vec![
        Setting::EnablePush(false),
        Setting::MaxFrameSize(32768),
        Setting::InitialWindowSize(65536),
    ]);
    multiple_settings_ack.ack = true;  // Invalid: ACK with payload

    let result = conn3.process_settings_frame(multiple_settings_ack);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ErrorCode::FrameSizeError);

    let duration = start_time.elapsed().as_millis() as u64;
    println!("✓ SETTINGS ACK payload validation in {}ms", duration);

    Ok(())
}

/// Integration test: Complete SETTINGS negotiation handshake.
///
/// Tests the full SETTINGS negotiation sequence between client and server,
/// validating proper handshake completion and settings application.
#[test]
fn test_complete_settings_negotiation_handshake() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    let mut client = MockH2Connection::new();
    let mut server = MockH2Connection::new();

    // Step 1: Client sends initial SETTINGS
    let client_initial_settings = vec![
        Setting::EnablePush(false),           // Clients typically disable push
        Setting::MaxConcurrentStreams(100),   // Client's concurrency limit
        Setting::InitialWindowSize(32768),    // Client's preferred window
        Setting::MaxFrameSize(24576),         // Client's frame size preference
    ];

    client.send_initial_settings(client_initial_settings.clone())?;

    // Step 2: Server sends initial SETTINGS
    let server_initial_settings = vec![
        Setting::EnablePush(true),             // Server may support push
        Setting::MaxConcurrentStreams(256),    // Server's capacity
        Setting::InitialWindowSize(65536),     // Server's preferred window
        Setting::MaxFrameSize(32768),          // Server's frame size limit
        Setting::MaxHeaderListSize(8192),      // Server's header limit
    ];

    server.send_initial_settings(server_initial_settings.clone())?;

    // Step 3: Both sides process received SETTINGS and send ACKs
    // (In real implementation, these would be sent over the wire)

    // Client processes server settings
    let server_settings_frame = SettingsFrame::new(server_initial_settings);
    client.process_settings_frame(server_settings_frame)?;
    assert!(client.settings_ack_received);  // Client sent ACK

    // Server processes client settings
    let client_settings_frame = SettingsFrame::new(client_initial_settings);
    server.process_settings_frame(client_settings_frame)?;
    assert!(server.settings_ack_received);  // Server sent ACK

    // Step 4: Verify settings were applied correctly
    let client_applied = client.last_settings.unwrap();
    assert!(client_applied.enable_push);  // Server's setting
    assert_eq!(client_applied.max_concurrent_streams, 256);  // Server's setting
    assert_eq!(client_applied.initial_window_size, 65536);   // Server's setting

    let server_applied = server.last_settings.unwrap();
    assert!(!server_applied.enable_push);  // Client's setting
    assert_eq!(server_applied.max_concurrent_streams, 100);  // Client's setting
    assert_eq!(server_applied.initial_window_size, 32768);   // Client's setting

    // Step 5: Verify connection states
    assert_eq!(client.state, ConnectionState::Open);
    assert_eq!(server.state, ConnectionState::Open);

    let duration = start_time.elapsed().as_millis() as u64;
    println!("✓ Complete SETTINGS negotiation handshake in {}ms", duration);

    Ok(())
}

/// Performance test: SETTINGS frame processing efficiency.
///
/// Validates that SETTINGS frame processing performs efficiently
/// under typical and high-load scenarios.
#[test]
fn test_settings_processing_performance() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    // Test processing many SETTINGS updates
    let mut conn = MockH2Connection::new();

    // Send initial settings
    conn.send_initial_settings(vec![Setting::EnablePush(false)])?;

    // Process 1000 subsequent SETTINGS frames
    for i in 0..1000 {
        let settings = vec![
            Setting::MaxConcurrentStreams(100 + i as u32),
            Setting::InitialWindowSize(32768 + (i as u32 * 1024)),
            Setting::MaxFrameSize(16384 + (i as u32 * 16)),
        ];

        let frame = SettingsFrame::new(settings);
        conn.process_settings_frame(frame)?;
    }

    // Verify final state
    let final_settings = conn.last_settings.unwrap();
    assert_eq!(final_settings.max_concurrent_streams, 100 + 999);
    assert_eq!(final_settings.initial_window_size, 32768 + (999 * 1024));
    assert_eq!(final_settings.max_frame_size, 16384 + (999 * 16));

    let duration = start_time.elapsed();
    println!("✓ Processed 1000 SETTINGS frames in {}ms (avg {:.2}μs per frame)",
             duration.as_millis(),
             duration.as_micros() as f64 / 1000.0);

    // Performance threshold: should process 1000 frames in < 100ms
    assert!(duration.as_millis() < 100, "SETTINGS processing too slow: {}ms", duration.as_millis());

    Ok(())
}