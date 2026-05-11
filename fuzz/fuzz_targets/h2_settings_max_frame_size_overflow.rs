#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{
    Frame, FrameHeader, FrameType, SettingsFrame as H2SettingsFrame, settings_flags,
};
use asupersync::http::h2::settings::{
    DEFAULT_HEADER_TABLE_SIZE, DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_FRAME_SIZE,
    MAX_INITIAL_WINDOW_SIZE, MAX_MAX_FRAME_SIZE, MIN_MAX_FRAME_SIZE, Settings,
};
use libfuzzer_sys::fuzz_target;

/// Tests RFC 7540 §6.5.2 SETTINGS_MAX_FRAME_SIZE validation.
///
/// SETTINGS_MAX_FRAME_SIZE valid range: 16384 (2^14) to 16777215 (2^24-1)
/// Values above 16MB (16777215) MUST be rejected with PROTOCOL_ERROR.
/// Values below 16384 MUST be rejected with PROTOCOL_ERROR.

#[derive(Arbitrary, Debug, Clone)]
struct SettingsMaxFrameSizeInput {
    max_frame_size: u32,
    additional_settings: Vec<(u16, u32)>, // Other SETTINGS parameters
    test_variant: u8,                     // Controls test scenario
}

/// SETTINGS parameter identifiers per RFC 7540 §6.5.2
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
enum SettingsId {
    EnablePush = 0x2,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
}

/// SETTINGS frame parameter
#[derive(Debug, Clone)]
struct SettingsParameter {
    id: u16,
    value: u32,
}

impl SettingsParameter {
    fn new(id: SettingsId, value: u32) -> Self {
        Self {
            id: id as u16,
            value,
        }
    }

    fn new_raw(id: u16, value: u32) -> Self {
        Self { id, value }
    }
}

/// Fuzzer-owned SETTINGS frame shape, serialized before production parsing.
#[derive(Debug, Clone)]
struct SettingsFrame {
    ack: bool,
    parameters: Vec<SettingsParameter>,
}

impl SettingsFrame {
    fn new(ack: bool, parameters: Vec<SettingsParameter>) -> Self {
        Self { ack, parameters }
    }

    fn new_max_frame_size(max_frame_size: u32) -> Self {
        let param = SettingsParameter::new(SettingsId::MaxFrameSize, max_frame_size);
        Self::new(false, vec![param])
    }

    fn is_ack(&self) -> bool {
        self.ack
    }

    fn find_parameter(&self, id: SettingsId) -> Option<u32> {
        self.parameters
            .iter()
            .find(|p| p.id == id as u16)
            .map(|p| p.value)
    }

    /// Serialize SETTINGS frame to bytes (simplified for testing)
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for param in &self.parameters {
            bytes.extend_from_slice(&param.id.to_be_bytes());
            bytes.extend_from_slice(&param.value.to_be_bytes());
        }
        bytes
    }
}

/// SETTINGS validation errors per RFC 7540
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
enum SettingsError {
    MaxFrameSizeTooLarge { value: u32, max_allowed: u32 },
    MaxFrameSizeTooSmall { value: u32, min_required: u32 },
    InvalidWindowSize { value: u32 },
    InvalidEnablePush { value: u32 },
    SettingsAckWithPayload,
    ProductionRejected,
}

/// Thin adapter that preserves the fuzz input schema while routing every
/// parse/apply decision through the production HTTP/2 connection code.
struct ProductionSettingsConnection {
    connection: Connection,

    // Current connection settings (updated by valid SETTINGS frames)
    max_frame_size: u32,
    header_table_size: u32,
    enable_push: bool,
    max_concurrent_streams: Option<u32>,
    initial_window_size: u32,
    max_header_list_size: Option<u32>,

    // Validation state
    processed_frames: usize,
    protocol_errors: Vec<SettingsError>,
    accepted_settings: usize,
}

impl ProductionSettingsConnection {
    fn new() -> Self {
        Self {
            connection: Connection::server(Settings::server()),

            // RFC 7540 default values
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            header_table_size: DEFAULT_HEADER_TABLE_SIZE,
            enable_push: true,
            max_concurrent_streams: None, // Preserves the original harness' external state shape.
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_header_list_size: None,

            processed_frames: 0,
            protocol_errors: Vec::new(),
            accepted_settings: 0,
        }
    }

    fn process_settings_frame(&mut self, frame: &SettingsFrame) -> bool {
        self.processed_frames += 1;

        let result = self.parse_production_settings(frame).and_then(|settings| {
            self.connection
                .process_frame(Frame::Settings(settings))
                .map(|_| ())
        });

        match result {
            Ok(()) => {
                self.sync_from_production();
                if !frame.is_ack() {
                    self.accepted_settings += 1;
                }
                true
            }
            Err(err) => {
                self.record_production_error(frame, &err);
                false
            }
        }
    }

    fn parse_production_settings(&self, frame: &SettingsFrame) -> Result<H2SettingsFrame, H2Error> {
        let payload = Bytes::from(frame.serialize());
        let header = FrameHeader {
            length: u32::try_from(payload.len()).unwrap_or(u32::MAX),
            frame_type: FrameType::Settings as u8,
            flags: if frame.is_ack() {
                settings_flags::ACK
            } else {
                0
            },
            stream_id: 0,
        };
        H2SettingsFrame::parse(&header, &payload)
    }

    fn sync_from_production(&mut self) {
        let remote = self.connection.remote_settings();
        self.max_frame_size = remote.max_frame_size;
        self.header_table_size = remote.header_table_size;
        self.enable_push = remote.enable_push;
        self.max_concurrent_streams = Some(remote.max_concurrent_streams);
        self.initial_window_size = remote.initial_window_size;
        self.max_header_list_size = Some(remote.max_header_list_size);
    }

    fn record_production_error(&mut self, frame: &SettingsFrame, err: &H2Error) {
        if frame.is_ack() && !frame.parameters.is_empty() {
            self.protocol_errors
                .push(SettingsError::SettingsAckWithPayload);
            return;
        }

        if let Some(value) = frame.find_parameter(SettingsId::MaxFrameSize) {
            if value > MAX_MAX_FRAME_SIZE {
                self.protocol_errors
                    .push(SettingsError::MaxFrameSizeTooLarge {
                        value,
                        max_allowed: MAX_MAX_FRAME_SIZE,
                    });
                return;
            }
            if value < MIN_MAX_FRAME_SIZE {
                self.protocol_errors
                    .push(SettingsError::MaxFrameSizeTooSmall {
                        value,
                        min_required: MIN_MAX_FRAME_SIZE,
                    });
                return;
            }
        }

        if err.code == ErrorCode::FlowControlError
            && let Some(value) = frame.find_parameter(SettingsId::InitialWindowSize)
            && value > MAX_INITIAL_WINDOW_SIZE
        {
            self.protocol_errors
                .push(SettingsError::InvalidWindowSize { value });
            return;
        }

        if let Some(value) = frame.find_parameter(SettingsId::EnablePush)
            && value > 1
        {
            self.protocol_errors
                .push(SettingsError::InvalidEnablePush { value });
            return;
        }

        self.protocol_errors.push(SettingsError::ProductionRejected);
    }

    fn has_protocol_errors(&self) -> bool {
        !self.protocol_errors.is_empty()
    }

    fn error_count(&self) -> usize {
        self.protocol_errors.len()
    }

    fn current_max_frame_size(&self) -> u32 {
        self.max_frame_size
    }
}

fuzz_target!(|input: SettingsMaxFrameSizeInput| {
    let mut conn = ProductionSettingsConnection::new();
    let initial_max_frame_size = conn.current_max_frame_size();

    match input.test_variant % 8 {
        0 => {
            // Test case 1: Valid minimum frame size (16384)
            let frame = SettingsFrame::new_max_frame_size(16384);
            let accepted = conn.process_settings_frame(&frame);

            assert!(accepted, "Minimum frame size (16384) should be accepted");
            assert!(
                !conn.has_protocol_errors(),
                "Minimum frame size should not cause errors"
            );
            assert_eq!(conn.current_max_frame_size(), 16384);
        }
        1 => {
            // Test case 2: Valid maximum frame size (16777215 = 2^24-1)
            let frame = SettingsFrame::new_max_frame_size(16777215);
            let accepted = conn.process_settings_frame(&frame);

            assert!(accepted, "Maximum frame size (16777215) should be accepted");
            assert!(
                !conn.has_protocol_errors(),
                "Maximum frame size should not cause errors"
            );
            assert_eq!(conn.current_max_frame_size(), 16777215);
        }
        2 => {
            // Test case 3: INVALID - Frame size too large (16777216 = 2^24)
            let frame = SettingsFrame::new_max_frame_size(16777216);
            let accepted = conn.process_settings_frame(&frame);

            assert!(!accepted, "Frame size 16777216 should be rejected");
            assert!(
                conn.has_protocol_errors(),
                "Should detect PROTOCOL_ERROR for oversized frame"
            );
            assert_eq!(
                conn.current_max_frame_size(),
                initial_max_frame_size,
                "Frame size should not change after error"
            );
        }
        3 => {
            // Test case 4: INVALID - Frame size too small (16383 = 2^14-1)
            let frame = SettingsFrame::new_max_frame_size(16383);
            let accepted = conn.process_settings_frame(&frame);

            assert!(!accepted, "Frame size 16383 should be rejected");
            assert!(
                conn.has_protocol_errors(),
                "Should detect PROTOCOL_ERROR for undersized frame"
            );
            assert_eq!(conn.current_max_frame_size(), initial_max_frame_size);
        }
        4 => {
            // Test case 5: INVALID - Maximum u32 value
            let frame = SettingsFrame::new_max_frame_size(u32::MAX);
            let accepted = conn.process_settings_frame(&frame);

            assert!(!accepted, "Maximum u32 frame size should be rejected");
            assert!(
                conn.has_protocol_errors(),
                "Should detect PROTOCOL_ERROR for maximum u32"
            );
        }
        5 => {
            // Test case 6: Edge case testing around boundary
            let test_values = [
                16384,    // Valid minimum
                65536,    // Valid common value (64KB)
                1048576,  // Valid large value (1MB)
                16777214, // Valid maximum-1
                16777215, // Valid maximum
                16777216, // Invalid first oversized
                33554432, // Invalid (2 * 2^24)
            ];

            for &value in &test_values {
                let mut test_conn = ProductionSettingsConnection::new();
                let frame = SettingsFrame::new_max_frame_size(value);
                let accepted = test_conn.process_settings_frame(&frame);

                if (MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value) {
                    assert!(accepted, "Value {} should be valid", value);
                    assert!(
                        !test_conn.has_protocol_errors(),
                        "Valid value {} should not error",
                        value
                    );
                } else {
                    assert!(!accepted, "Value {} should be invalid", value);
                    assert!(
                        test_conn.has_protocol_errors(),
                        "Invalid value {} should error",
                        value
                    );
                }
            }
        }
        6 => {
            // Test case 7: Multiple SETTINGS parameters with MAX_FRAME_SIZE
            let mut params = vec![
                SettingsParameter::new(SettingsId::MaxFrameSize, input.max_frame_size),
                SettingsParameter::new(SettingsId::InitialWindowSize, 32768),
                SettingsParameter::new(SettingsId::EnablePush, 1),
            ];

            // Add additional settings from fuzzer input
            for (id, value) in input.additional_settings.iter().take(3) {
                if *id != SettingsId::MaxFrameSize as u16 {
                    // Avoid duplicates
                    params.push(SettingsParameter::new_raw(*id, *value));
                }
            }

            let frame = SettingsFrame::new(false, params);
            let accepted = conn.process_settings_frame(&frame);

            // Validation should depend on MAX_FRAME_SIZE value
            let max_frame_size_valid =
                (MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&input.max_frame_size);
            if max_frame_size_valid {
                // Other parameters might still cause errors, but MAX_FRAME_SIZE should be OK
                if !accepted {
                    // Check if error was specifically about MAX_FRAME_SIZE
                    let has_frame_size_error = conn.protocol_errors.iter().any(|e| {
                        matches!(
                            e,
                            SettingsError::MaxFrameSizeTooLarge { .. }
                                | SettingsError::MaxFrameSizeTooSmall { .. }
                        )
                    });
                    assert!(
                        !has_frame_size_error,
                        "Valid MAX_FRAME_SIZE should not cause frame size error"
                    );
                }
            } else {
                assert!(!accepted, "Invalid MAX_FRAME_SIZE should cause rejection");
                assert!(conn.has_protocol_errors(), "Should detect protocol error");
            }
        }
        7 => {
            // Test case 8: SETTINGS ACK frame (should ignore MAX_FRAME_SIZE)
            let ack_frame = SettingsFrame::new(true, vec![]); // ACK with empty payload
            let accepted = conn.process_settings_frame(&ack_frame);

            assert!(accepted, "SETTINGS ACK should be accepted");
            assert!(!conn.has_protocol_errors(), "ACK should not cause errors");

            // ACK with payload should be rejected
            let invalid_ack = SettingsFrame::new(
                true,
                vec![SettingsParameter::new(SettingsId::MaxFrameSize, 32768)],
            );
            let rejected = !conn.process_settings_frame(&invalid_ack);

            assert!(rejected, "SETTINGS ACK with payload should be rejected");
            assert!(
                conn.has_protocol_errors(),
                "ACK with payload should cause error"
            );
        }
        _ => unreachable!(),
    }

    // Verify connection state consistency
    assert!(
        conn.accepted_settings + conn.error_count() <= conn.processed_frames,
        "Connection statistics should be consistent"
    );

    // Verify frame size is within valid range after successful operations
    assert!(
        (MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&conn.current_max_frame_size()),
        "Current max frame size should always be in valid range"
    );
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_frame_sizes() {
        let mut conn = ProductionSettingsConnection::new();

        let valid_sizes = [16384, 32768, 65536, 1048576, 16777215];
        for &size in &valid_sizes {
            let frame = SettingsFrame::new_max_frame_size(size);
            assert!(
                conn.process_settings_frame(&frame),
                "Size {} should be valid",
                size
            );
            assert_eq!(conn.current_max_frame_size(), size);
        }
    }

    #[test]
    fn test_invalid_large_frame_sizes() {
        let mut conn = ProductionSettingsConnection::new();

        let invalid_sizes = [16777216, 33554432, u32::MAX];
        for &size in &invalid_sizes {
            let frame = SettingsFrame::new_max_frame_size(size);
            assert!(
                !conn.process_settings_frame(&frame),
                "Size {} should be invalid",
                size
            );
            assert!(conn.has_protocol_errors());
        }
    }

    #[test]
    fn test_invalid_small_frame_sizes() {
        let mut conn = ProductionSettingsConnection::new();

        let invalid_sizes = [0, 8192, 16383];
        for &size in &invalid_sizes {
            let frame = SettingsFrame::new_max_frame_size(size);
            assert!(
                !conn.process_settings_frame(&frame),
                "Size {} should be invalid",
                size
            );
            assert!(conn.has_protocol_errors());
        }
    }

    #[test]
    fn test_boundary_values() {
        let mut conn = ProductionSettingsConnection::new();

        // Test exact boundary
        let frame_max = SettingsFrame::new_max_frame_size(16777215); // Maximum valid
        assert!(conn.process_settings_frame(&frame_max));

        let frame_over = SettingsFrame::new_max_frame_size(16777216); // First invalid
        assert!(!conn.process_settings_frame(&frame_over));
        assert!(conn.has_protocol_errors());
    }

    #[test]
    fn test_settings_ack_validation() {
        let mut conn = ProductionSettingsConnection::new();

        // Valid ACK (empty payload)
        let ack = SettingsFrame::new(true, vec![]);
        assert!(conn.process_settings_frame(&ack));

        // Invalid ACK (with payload)
        let invalid_ack = SettingsFrame::new(
            true,
            vec![SettingsParameter::new(SettingsId::MaxFrameSize, 32768)],
        );
        assert!(!conn.process_settings_frame(&invalid_ack));
        assert!(conn.has_protocol_errors());
    }

    #[test]
    fn test_multiple_parameters() {
        let mut conn = ProductionSettingsConnection::new();

        let params = vec![
            SettingsParameter::new(SettingsId::MaxFrameSize, 32768),
            SettingsParameter::new(SettingsId::EnablePush, 0),
            SettingsParameter::new(SettingsId::InitialWindowSize, 16384),
        ];

        let frame = SettingsFrame::new(false, params);
        assert!(conn.process_settings_frame(&frame));
        assert_eq!(conn.current_max_frame_size(), 32768);
        assert!(!conn.enable_push);
        assert_eq!(conn.initial_window_size, 16384);
    }
}
