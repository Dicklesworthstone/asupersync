#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::frame::{Frame, FrameHeader, Setting, SettingsFrame, settings_flags};
use asupersync::http::h2::settings::Settings;
use asupersync::bytes::{Bytes, BytesMut};

/// Comprehensive fuzz input for HTTP/2 SETTINGS frame parsing and handling
#[derive(Arbitrary, Debug, Clone)]
struct H2SettingsFuzz {
    /// Connection role (client vs server)
    pub is_client: bool,
    /// Sequence of SETTINGS operations to test
    pub operations: Vec<SettingsOperation>,
    /// Settings frame configuration scenarios
    pub frame_scenarios: Vec<SettingsFrameScenario>,
    /// Connection state setup
    pub connection_config: ConnectionConfiguration,
}

/// Individual SETTINGS frame operations to fuzz
#[derive(Arbitrary, Debug, Clone)]
enum SettingsOperation {
    /// Send a SETTINGS frame with specific settings
    SendSettings {
        settings: Vec<FuzzSetting>,
        ack: bool,
    },
    /// Send raw SETTINGS frame bytes for parsing edge cases
    SendRawSettingsFrame {
        raw_payload: Vec<u8>,
        ack: bool,
    },
    /// Test unknown settings handling
    SendUnknownSettings {
        unknown_settings: Vec<(u16, u32)>, // (id, value) pairs for unknown settings
    },
    /// Test SETTINGS ACK handling
    SendSettingsAck,
    /// Test boundary value settings
    SendBoundarySettings {
        boundary_type: BoundaryType,
    },
    /// Test SETTINGS flood (CVE-2019-9515)
    SendSettingsFlood {
        frame_count: u32,
    },
}

/// Different boundary conditions to test for settings values
#[derive(Arbitrary, Debug, Clone)]
enum BoundaryType {
    /// Test SETTINGS_HEADER_TABLE_SIZE boundaries
    HeaderTableSizeBoundaries,
    /// Test SETTINGS_MAX_CONCURRENT_STREAMS overflow
    MaxConcurrentStreamsOverflow,
    /// Test SETTINGS_INITIAL_WINDOW_SIZE boundaries
    InitialWindowSizeBoundaries,
    /// Test SETTINGS_MAX_FRAME_SIZE boundaries
    MaxFrameSizeBoundaries,
    /// Test all max values at once
    AllMaxValues,
}

/// SETTINGS frame test scenarios
#[derive(Arbitrary, Debug, Clone)]
enum SettingsFrameScenario {
    /// Valid settings with all types
    AllValidSettings,
    /// Malformed SETTINGS frame
    MalformedFrame {
        invalid_payload_length: bool,
        invalid_setting_size: bool,
    },
    /// SETTINGS flood protection test
    SettingsFlood {
        frame_count: u8,
    },
    /// Mixed valid/invalid settings
    MixedValidInvalid {
        valid_settings: Vec<FuzzSetting>,
        invalid_raw_bytes: Vec<u8>,
    },
}

/// Connection configuration for testing
#[derive(Arbitrary, Debug, Clone)]
struct ConnectionConfiguration {
    /// Initial local settings
    pub initial_settings: FuzzSettings,
    /// Whether to test role-specific behavior (server MUST NOT send ENABLE_PUSH)
    pub test_role_violations: bool,
}

/// Fuzz-friendly representation of Settings
#[derive(Arbitrary, Debug, Clone)]
struct FuzzSettings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

impl From<FuzzSettings> for Settings {
    fn from(fuzz: FuzzSettings) -> Self {
        Settings {
            header_table_size: fuzz.header_table_size,
            enable_push: fuzz.enable_push,
            max_concurrent_streams: fuzz.max_concurrent_streams,
            initial_window_size: fuzz.initial_window_size,
            max_frame_size: fuzz.max_frame_size,
            max_header_list_size: fuzz.max_header_list_size,
            continuation_timeout_ms: 10_000, // Default 10 seconds
        }
    }
}

/// Fuzz-friendly representation of Setting
#[derive(Arbitrary, Debug, Clone)]
enum FuzzSetting {
    HeaderTableSize(u32),
    EnablePush(bool),
    MaxConcurrentStreams(u32),
    InitialWindowSize(u32),
    MaxFrameSize(u32),
    MaxHeaderListSize(u32),
}

impl From<FuzzSetting> for Setting {
    fn from(fuzz: FuzzSetting) -> Self {
        match fuzz {
            FuzzSetting::HeaderTableSize(v) => Setting::HeaderTableSize(v),
            FuzzSetting::EnablePush(v) => Setting::EnablePush(v),
            FuzzSetting::MaxConcurrentStreams(v) => Setting::MaxConcurrentStreams(v),
            FuzzSetting::InitialWindowSize(v) => Setting::InitialWindowSize(v),
            FuzzSetting::MaxFrameSize(v) => Setting::MaxFrameSize(v),
            FuzzSetting::MaxHeaderListSize(v) => Setting::MaxHeaderListSize(v),
        }
    }
}

/// Shadow model to track expected SETTINGS state
#[derive(Debug)]
struct SettingsShadowModel {
    /// Expected local settings
    local_settings: Settings,
    /// Expected remote settings
    remote_settings: Settings,
    /// Whether we've received remote settings
    received_remote_settings: bool,
    /// ACKs expected
    pending_acks: u32,
    /// Role (client = true, server = false)
    is_client: bool,
}

impl SettingsShadowModel {
    fn new(initial_settings: Settings, is_client: bool) -> Self {
        Self {
            local_settings: initial_settings,
            remote_settings: Settings::default(),
            received_remote_settings: false,
            pending_acks: 0,
            is_client,
        }
    }

    fn expect_settings(&mut self, settings: &[Setting]) -> Result<(), String> {
        // Validate settings according to HTTP/2 spec
        for setting in settings {
            match setting {
                Setting::EnablePush(_) if !self.is_client => {
                    return Err("Server MUST NOT send SETTINGS_ENABLE_PUSH".to_string());
                }
                Setting::InitialWindowSize(size) if *size > 0x7fff_ffff => {
                    return Err("SETTINGS_INITIAL_WINDOW_SIZE exceeds maximum".to_string());
                }
                Setting::MaxFrameSize(size) if *size < 16384 || *size > 16_777_215 => {
                    return Err("SETTINGS_MAX_FRAME_SIZE out of bounds".to_string());
                }
                _ => {}
            }

            // Apply setting to remote settings
            self.remote_settings.apply(*setting).map_err(|e| format!("Settings apply failed: {}", e))?;
        }

        self.received_remote_settings = true;
        self.pending_acks += 1;
        Ok(())
    }

    fn ack_settings(&mut self) {
        if self.pending_acks > 0 {
            self.pending_acks -= 1;
        }
    }
}

/// Normalize fuzz input to valid ranges
fn normalize_fuzz_input(input: &mut H2SettingsFuzz) {
    // Limit operations to prevent timeouts
    input.operations.truncate(20);
    input.frame_scenarios.truncate(10);

    // Normalize settings values to reasonable ranges
    normalize_settings(&mut input.connection_config.initial_settings);

    for op in &mut input.operations {
        match op {
            SettingsOperation::SendSettings { settings, .. } => {
                settings.truncate(10);
                for setting in settings {
                    normalize_setting(setting);
                }
            }
            SettingsOperation::SendRawSettingsFrame { raw_payload, .. } => {
                raw_payload.truncate(1024); // Limit raw frame size
            }
            SettingsOperation::SendUnknownSettings { unknown_settings } => {
                unknown_settings.truncate(10);
                for (id, _) in unknown_settings {
                    // Ensure unknown IDs (not 0x1-0x6)
                    if *id <= 0x6 {
                        *id = 0x7; // Force to unknown range
                    }
                    *id = (*id).clamp(0x7, 0xFFFF); // Unknown settings range
                }
            }
            SettingsOperation::SendSettingsFlood { frame_count } => {
                *frame_count = (*frame_count).clamp(1, 50); // Reasonable flood test
            }
            _ => {}
        }
    }
}

fn normalize_settings(settings: &mut FuzzSettings) {
    // Normalize to HTTP/2 valid ranges
    settings.header_table_size = settings.header_table_size.clamp(0, 1024 * 1024); // 0 to 1MB
    // enable_push is bool, always valid
    settings.max_concurrent_streams = settings.max_concurrent_streams.clamp(0, u32::MAX);
    settings.initial_window_size = settings.initial_window_size.clamp(0, 0x7fff_ffff); // 2^31-1
    settings.max_frame_size = settings.max_frame_size.clamp(16384, 16_777_215); // Valid range
    settings.max_header_list_size = settings.max_header_list_size.clamp(0, 16 * 1024 * 1024); // 0 to 16MB
}

fn normalize_setting(setting: &mut FuzzSetting) {
    match setting {
        FuzzSetting::HeaderTableSize(v) => *v = (*v).clamp(0, 1024 * 1024),
        FuzzSetting::EnablePush(_) => {}, // bool is always valid
        FuzzSetting::MaxConcurrentStreams(v) => *v = (*v).clamp(0, u32::MAX),
        FuzzSetting::InitialWindowSize(v) => *v = (*v).clamp(0, 0x7fff_ffff),
        FuzzSetting::MaxFrameSize(v) => *v = (*v).clamp(16384, 16_777_215),
        FuzzSetting::MaxHeaderListSize(v) => *v = (*v).clamp(0, 16 * 1024 * 1024),
    }
}

/// Create a raw SETTINGS frame for boundary/malformed testing
fn create_raw_settings_frame(settings_data: &[u8], ack: bool) -> Vec<u8> {
    let mut frame = Vec::new();

    // Frame header (9 bytes)
    let length = settings_data.len() as u32;
    frame.extend_from_slice(&length.to_be_bytes()[1..4]); // 24-bit length
    frame.push(0x4); // SETTINGS frame type
    frame.push(if ack { settings_flags::ACK } else { 0 }); // Flags
    frame.extend_from_slice(&0u32.to_be_bytes()); // Stream ID (must be 0 for SETTINGS)

    // Payload
    frame.extend_from_slice(settings_data);

    frame
}

/// Test boundary values for specific settings
fn create_boundary_settings(boundary_type: BoundaryType) -> Vec<Setting> {
    match boundary_type {
        BoundaryType::HeaderTableSizeBoundaries => vec![
            Setting::HeaderTableSize(0),           // Minimum
            Setting::HeaderTableSize(4096),        // Default
            Setting::HeaderTableSize(1024 * 1024), // 1MB (common limit)
            Setting::HeaderTableSize(u32::MAX),    // Maximum
        ],
        BoundaryType::MaxConcurrentStreamsOverflow => vec![
            Setting::MaxConcurrentStreams(0),       // Disable new streams
            Setting::MaxConcurrentStreams(1),       // Minimum streams
            Setting::MaxConcurrentStreams(100),     // Typical value
            Setting::MaxConcurrentStreams(u32::MAX), // Maximum (may cause issues)
        ],
        BoundaryType::InitialWindowSizeBoundaries => vec![
            Setting::InitialWindowSize(0),          // Minimum
            Setting::InitialWindowSize(65535),      // Default
            Setting::InitialWindowSize(0x7fff_ffff), // Maximum valid
            Setting::InitialWindowSize(0x8000_0000), // Invalid (should fail)
        ],
        BoundaryType::MaxFrameSizeBoundaries => vec![
            Setting::MaxFrameSize(16384),           // Minimum valid
            Setting::MaxFrameSize(16383),           // Below minimum (invalid)
            Setting::MaxFrameSize(16_777_215),      // Maximum valid
            Setting::MaxFrameSize(16_777_216),      // Above maximum (invalid)
        ],
        BoundaryType::AllMaxValues => vec![
            Setting::HeaderTableSize(u32::MAX),
            Setting::EnablePush(true),
            Setting::MaxConcurrentStreams(u32::MAX),
            Setting::InitialWindowSize(0x7fff_ffff),
            Setting::MaxFrameSize(16_777_215),
            Setting::MaxHeaderListSize(u32::MAX),
        ],
    }
}

/// Execute SETTINGS fuzzing operations
fn execute_settings_operations(
    input: &H2SettingsFuzz,
    shadow: &mut SettingsShadowModel,
) -> Result<(), String> {
    let initial_settings = Settings::from(input.connection_config.initial_settings.clone());
    let mut connection = if input.is_client {
        Connection::client(initial_settings)
    } else {
        Connection::server(initial_settings)
    };

    // Execute operation sequence
    for (op_index, operation) in input.operations.iter().enumerate() {
        match operation {
            SettingsOperation::SendSettings { settings, ack } => {
                if *ack {
                    // Create SETTINGS ACK frame
                    let settings_frame = SettingsFrame::ack();
                    let frame = Frame::Settings(settings_frame);

                    // Process the frame
                    match connection.process_frame(frame) {
                        Ok(_) => {
                            shadow.ack_settings();
                        }
                        Err(e) => {
                            // ACKs should generally succeed
                            return Err(format!("SETTINGS ACK failed at operation {}: {}", op_index, e));
                        }
                    }
                } else {
                    // Create SETTINGS frame with settings
                    let actual_settings: Vec<Setting> = settings.iter().map(|s| s.clone().into()).collect();
                    let settings_frame = SettingsFrame::new(actual_settings.clone());
                    let frame = Frame::Settings(settings_frame);

                    // Validate with shadow model first
                    let expected_result = shadow.expect_settings(&actual_settings);

                    // Process the frame
                    match connection.process_frame(frame) {
                        Ok(_) => {
                            if expected_result.is_err() {
                                return Err(format!(
                                    "SETTINGS frame should have failed at operation {} but succeeded",
                                    op_index
                                ));
                            }
                        }
                        Err(_) => {
                            if expected_result.is_ok() {
                                return Err(format!(
                                    "SETTINGS frame should have succeeded at operation {} but failed",
                                    op_index
                                ));
                            }
                            // Expected failure, continue
                        }
                    }
                }
            }

            SettingsOperation::SendRawSettingsFrame { raw_payload, ack } => {
                // Create raw frame data for edge case testing
                let frame_data = create_raw_settings_frame(raw_payload, *ack);

                // Try to parse the frame (this tests the frame parser robustness)
                if frame_data.len() >= 9 {
                    let mut header_buf = BytesMut::from(&frame_data[0..9]);
                    let payload_bytes = Bytes::copy_from_slice(&frame_data[9..]);

                    // Parse the 9-byte frame header
                    if let Ok(header) = FrameHeader::parse(&mut header_buf) {
                        let _ = asupersync::http::h2::frame::parse_frame(&header, payload_bytes);
                    }
                }
            }

            SettingsOperation::SendUnknownSettings { unknown_settings } => {
                // Test unknown settings are gracefully ignored
                let mut raw_payload = Vec::new();

                for &(id, value) in unknown_settings {
                    raw_payload.extend_from_slice(&id.to_be_bytes());
                    raw_payload.extend_from_slice(&value.to_be_bytes());
                }

                let frame_data = create_raw_settings_frame(&raw_payload, false);

                if frame_data.len() >= 9 {
                    let mut header_buf = BytesMut::from(&frame_data[0..9]);
                    let payload_bytes = Bytes::copy_from_slice(&frame_data[9..]);

                    // Parse and process - unknown settings should be ignored
                    if let Ok(header) = FrameHeader::parse(&mut header_buf) {
                        if let Ok(frame) = asupersync::http::h2::frame::parse_frame(&header, payload_bytes) {
                            let _ = connection.process_frame(frame);
                        }
                    }
                }
            }

            SettingsOperation::SendSettingsAck => {
                let settings_frame = SettingsFrame::ack();
                let frame = Frame::Settings(settings_frame);

                match connection.process_frame(frame) {
                    Ok(_) => {
                        shadow.ack_settings();
                    }
                    Err(e) => {
                        // Most ACKs should succeed
                        if shadow.pending_acks > 0 {
                            return Err(format!("Unexpected SETTINGS ACK failure: {}", e));
                        }
                        // No pending ACKs, failure might be expected
                    }
                }
            }

            SettingsOperation::SendBoundarySettings { boundary_type } => {
                let boundary_settings = create_boundary_settings(boundary_type.clone());
                let settings_frame = SettingsFrame::new(boundary_settings.clone());
                let frame = Frame::Settings(settings_frame);

                // Boundary settings may or may not be valid
                let expected_result = shadow.expect_settings(&boundary_settings);

                match connection.process_frame(frame) {
                    Ok(_) => {
                        // If shadow model expected failure but we succeeded, that's suspicious
                        if expected_result.is_err() {
                            return Err(format!(
                                "Boundary settings should have failed but succeeded at operation {}",
                                op_index
                            ));
                        }
                    }
                    Err(_) => {
                        // Expected for some boundary conditions
                    }
                }
            }
            SettingsOperation::SendSettingsFlood { frame_count } => {
                // Test SETTINGS flood (CVE-2019-9515) - send multiple SETTINGS frames
                for i in 0..*frame_count {
                    let flood_settings = vec![
                        Setting::HeaderTableSize(4096 + i),
                        Setting::MaxConcurrentStreams(100),
                        Setting::InitialWindowSize(65536),
                    ];
                    let settings_frame = SettingsFrame::new(flood_settings);
                    let frame = Frame::Settings(settings_frame);

                    // Process the frame - implementation should handle flooding gracefully
                    match connection.process_frame(frame) {
                        Ok(_) => {
                            // Flood should be rate limited after a certain point
                        }
                        Err(e) => {
                            // Expected after rate limiting kicks in
                            if i < 5 {
                                // First few frames should generally succeed
                                return Err(format!("Early flood frame {} failed: {}", i, e));
                            }
                            // Later frames are expected to fail due to rate limiting
                            break;
                        }
                    }
                }
            }
        }
    }

    // Test frame scenarios
    for scenario in &input.frame_scenarios {
        match scenario {
            SettingsFrameScenario::AllValidSettings => {
                let all_settings = vec![
                    Setting::HeaderTableSize(8192),
                    Setting::EnablePush(input.is_client), // Only valid for clients
                    Setting::MaxConcurrentStreams(100),
                    Setting::InitialWindowSize(32768),
                    Setting::MaxFrameSize(32768),
                    Setting::MaxHeaderListSize(8192),
                ];

                let filtered_settings: Vec<Setting> = if input.is_client {
                    all_settings
                } else {
                    // Server should not send EnablePush
                    all_settings.into_iter().filter(|s| !matches!(s, Setting::EnablePush(_))).collect()
                };

                let settings_frame = SettingsFrame::new(filtered_settings);
                let frame = Frame::Settings(settings_frame);
                let _ = connection.process_frame(frame);
            }

            SettingsFrameScenario::MalformedFrame { invalid_payload_length, invalid_setting_size } => {
                let mut raw_payload = Vec::new();

                if *invalid_setting_size {
                    // Create incomplete setting (less than 6 bytes)
                    raw_payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // Incomplete setting
                }

                if *invalid_payload_length {
                    // Create payload that doesn't align with 6-byte setting boundaries
                    raw_payload.push(0xFF); // Extra byte
                }

                let frame_data = create_raw_settings_frame(&raw_payload, false);

                if frame_data.len() >= 9 {
                    let mut header_buf = BytesMut::from(&frame_data[0..9]);
                    let payload_bytes = Bytes::copy_from_slice(&frame_data[9..]);

                    // Malformed frames should be handled gracefully
                    if let Ok(header) = FrameHeader::parse(&mut header_buf) {
                        let _ = asupersync::http::h2::frame::parse_frame(&header, payload_bytes);
                    }
                }
            }

            SettingsFrameScenario::SettingsFlood { frame_count } => {
                // Test SETTINGS flood protection (CVE-2019-9515)
                for _ in 0..*frame_count {
                    let settings_frame = SettingsFrame::new(vec![Setting::HeaderTableSize(4096)]);
                    let frame = Frame::Settings(settings_frame);

                    match connection.process_frame(frame) {
                        Ok(_) => {},
                        Err(_) => {
                            // Flood protection may kick in - that's good
                            break;
                        }
                    }
                }
            }

            SettingsFrameScenario::MixedValidInvalid { valid_settings, invalid_raw_bytes } => {
                // Mix valid settings with invalid bytes
                let mut raw_payload = Vec::new();

                // Add valid settings
                for setting in valid_settings {
                    let actual_setting: Setting = setting.clone().into();
                    match actual_setting {
                        Setting::HeaderTableSize(v) => {
                            raw_payload.extend_from_slice(&1u16.to_be_bytes());
                            raw_payload.extend_from_slice(&v.to_be_bytes());
                        }
                        Setting::EnablePush(v) => {
                            raw_payload.extend_from_slice(&2u16.to_be_bytes());
                            raw_payload.extend_from_slice(&(if v { 1u32 } else { 0u32 }).to_be_bytes());
                        }
                        Setting::MaxConcurrentStreams(v) => {
                            raw_payload.extend_from_slice(&3u16.to_be_bytes());
                            raw_payload.extend_from_slice(&v.to_be_bytes());
                        }
                        Setting::InitialWindowSize(v) => {
                            raw_payload.extend_from_slice(&4u16.to_be_bytes());
                            raw_payload.extend_from_slice(&v.to_be_bytes());
                        }
                        Setting::MaxFrameSize(v) => {
                            raw_payload.extend_from_slice(&5u16.to_be_bytes());
                            raw_payload.extend_from_slice(&v.to_be_bytes());
                        }
                        Setting::MaxHeaderListSize(v) => {
                            raw_payload.extend_from_slice(&6u16.to_be_bytes());
                            raw_payload.extend_from_slice(&v.to_be_bytes());
                        }
                    }
                }

                // Add invalid raw bytes
                raw_payload.extend_from_slice(invalid_raw_bytes);

                let frame_data = create_raw_settings_frame(&raw_payload, false);

                if frame_data.len() >= 9 {
                    let mut header_buf = BytesMut::from(&frame_data[0..9]);
                    let payload_bytes = Bytes::copy_from_slice(&frame_data[9..]);

                    // Mixed frames should be handled gracefully
                    if let Ok(header) = FrameHeader::parse(&mut header_buf) {
                        let _ = asupersync::http::h2::frame::parse_frame(&header, payload_bytes);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Main fuzzing entry point
fn fuzz_h2_settings(mut input: H2SettingsFuzz) -> Result<(), String> {
    normalize_fuzz_input(&mut input);

    // Skip degenerate cases
    if input.operations.is_empty() && input.frame_scenarios.is_empty() {
        return Ok(());
    }

    let initial_settings = Settings::from(input.connection_config.initial_settings.clone());
    let mut shadow = SettingsShadowModel::new(initial_settings, input.is_client);

    // Test SETTINGS operations
    execute_settings_operations(&input, &mut shadow)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 8_000 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    // Generate fuzz configuration
    let input = if let Ok(input) = H2SettingsFuzz::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };

    // Run HTTP/2 SETTINGS fuzzing
    let _ = fuzz_h2_settings(input);
});