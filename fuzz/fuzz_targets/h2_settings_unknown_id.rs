#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Tests RFC 7540 §6.5 forward compatibility for unknown SETTINGS parameters.
///
/// Unknown setting IDs MUST be ignored (not cause PROTOCOL_ERROR).
/// This enables forward compatibility with future HTTP/2 extensions.
/// Known settings in the same frame MUST still be processed normally.

#[derive(Arbitrary, Debug, Clone)]
struct UnknownSettingsInput {
    unknown_id: u16,                // Unknown setting ID to test
    unknown_value: u32,             // Value for unknown setting
    known_settings: Vec<(u8, u32)>, // Known settings to mix in
    test_variant: u8,               // Controls test scenario
}

/// Known SETTINGS parameter identifiers per RFC 7540 §6.5.2
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
enum KnownSettingsId {
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
}

impl KnownSettingsId {
    fn from_u16(id: u16) -> Option<Self> {
        match id {
            0x1 => Some(Self::HeaderTableSize),
            0x2 => Some(Self::EnablePush),
            0x3 => Some(Self::MaxConcurrentStreams),
            0x4 => Some(Self::InitialWindowSize),
            0x5 => Some(Self::MaxFrameSize),
            0x6 => Some(Self::MaxHeaderListSize),
            _ => None,
        }
    }

    fn is_known(id: u16) -> bool {
        Self::from_u16(id).is_some()
    }
}

/// SETTINGS frame parameter (known or unknown)
#[derive(Debug, Clone)]
struct SettingsParameter {
    id: u16,
    value: u32,
}

impl SettingsParameter {
    fn new_known(id: KnownSettingsId, value: u32) -> Self {
        Self {
            id: id as u16,
            value,
        }
    }

    fn new_unknown(id: u16, value: u32) -> Self {
        // Ensure ID is truly unknown
        debug_assert!(
            !KnownSettingsId::is_known(id),
            "ID {} should be unknown",
            id
        );
        Self { id, value }
    }
}

/// Mock SETTINGS frame for testing
#[derive(Debug, Clone)]
struct SettingsFrame {
    ack: bool,
    parameters: Vec<SettingsParameter>,
}

impl SettingsFrame {
    fn new(ack: bool, parameters: Vec<SettingsParameter>) -> Self {
        Self { ack, parameters }
    }

    fn new_unknown_only(unknown_id: u16, unknown_value: u32) -> Self {
        let param = SettingsParameter::new_unknown(unknown_id, unknown_value);
        Self::new(false, vec![param])
    }

    fn new_mixed(known: Vec<(KnownSettingsId, u32)>, unknown: Vec<(u16, u32)>) -> Self {
        let mut params = Vec::new();

        // Add known settings
        for (id, value) in known {
            params.push(SettingsParameter::new_known(id, value));
        }

        // Add unknown settings
        for (id, value) in unknown {
            params.push(SettingsParameter::new_unknown(id, value));
        }

        Self::new(false, params)
    }

    fn is_ack(&self) -> bool {
        self.ack
    }

    fn find_parameter(&self, id: u16) -> Option<u32> {
        self.parameters.iter().find(|p| p.id == id).map(|p| p.value)
    }

    fn count_known_parameters(&self) -> usize {
        self.parameters
            .iter()
            .filter(|p| KnownSettingsId::is_known(p.id))
            .count()
    }

    fn count_unknown_parameters(&self) -> usize {
        self.parameters
            .iter()
            .filter(|p| !KnownSettingsId::is_known(p.id))
            .count()
    }

    /// Serialize SETTINGS frame to bytes
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for param in &self.parameters {
            bytes.extend_from_slice(&param.id.to_be_bytes());
            bytes.extend_from_slice(&param.value.to_be_bytes());
        }
        bytes
    }
}

/// Mock connection for testing unknown SETTINGS handling
struct MockUnknownSettingsConnection {
    // Current connection settings (updated only by known SETTINGS)
    header_table_size: u32,
    enable_push: bool,
    max_concurrent_streams: Option<u32>,
    initial_window_size: u32,
    max_frame_size: u32,
    max_header_list_size: Option<u32>,

    // Processing state
    processed_frames: usize,
    accepted_frames: usize,
    ignored_unknown_count: usize,
    protocol_errors: Vec<String>,

    // Logging for unknown settings
    unknown_settings_log: Vec<(u16, u32)>, // (id, value) pairs that were ignored
}

impl MockUnknownSettingsConnection {
    fn new() -> Self {
        Self {
            // RFC 7540 default values
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: 65535,
            max_frame_size: 16384,
            max_header_list_size: None,

            processed_frames: 0,
            accepted_frames: 0,
            ignored_unknown_count: 0,
            protocol_errors: Vec::new(),
            unknown_settings_log: Vec::new(),
        }
    }

    fn process_settings_frame(&mut self, frame: &SettingsFrame) -> bool {
        self.processed_frames += 1;

        if frame.is_ack() {
            // ACK frames must have empty payload
            if !frame.parameters.is_empty() {
                self.protocol_errors
                    .push("SETTINGS ACK with non-empty payload".to_string());
                return false;
            }
            self.accepted_frames += 1;
            return true;
        }

        // Process each parameter
        let mut frame_accepted = true;
        for param in &frame.parameters {
            if KnownSettingsId::is_known(param.id) {
                // Process known setting with validation
                if !self.process_known_setting(param.id, param.value) {
                    frame_accepted = false;
                    break;
                }
            } else {
                // RFC 7540 §6.5: Unknown settings MUST be ignored
                self.ignore_unknown_setting(param.id, param.value);
            }
        }

        if frame_accepted {
            self.accepted_frames += 1;
        }

        frame_accepted
    }

    fn process_known_setting(&mut self, id: u16, value: u32) -> bool {
        match KnownSettingsId::from_u16(id) {
            Some(KnownSettingsId::HeaderTableSize) => {
                self.header_table_size = value;
                true
            }
            Some(KnownSettingsId::EnablePush) => {
                if value != 0 && value != 1 {
                    self.protocol_errors
                        .push(format!("Invalid ENABLE_PUSH value: {}", value));
                    false
                } else {
                    self.enable_push = value != 0;
                    true
                }
            }
            Some(KnownSettingsId::MaxConcurrentStreams) => {
                self.max_concurrent_streams = Some(value);
                true
            }
            Some(KnownSettingsId::InitialWindowSize) => {
                if value > 2147483647 {
                    // 2^31-1
                    self.protocol_errors
                        .push(format!("Invalid INITIAL_WINDOW_SIZE: {}", value));
                    false
                } else {
                    self.initial_window_size = value;
                    true
                }
            }
            Some(KnownSettingsId::MaxFrameSize) => {
                if value < 16384 || value > 16777215 {
                    // 2^14 to 2^24-1
                    self.protocol_errors
                        .push(format!("Invalid MAX_FRAME_SIZE: {}", value));
                    false
                } else {
                    self.max_frame_size = value;
                    true
                }
            }
            Some(KnownSettingsId::MaxHeaderListSize) => {
                self.max_header_list_size = Some(value);
                true
            }
            None => {
                // Should not reach here due to is_known check
                unreachable!("Unknown setting ID passed to process_known_setting");
            }
        }
    }

    fn ignore_unknown_setting(&mut self, id: u16, value: u32) {
        // RFC 7540 §6.5: "An endpoint that receives a SETTINGS frame with any unknown
        // or unsupported identifier MUST ignore that setting."
        self.ignored_unknown_count += 1;
        self.unknown_settings_log.push((id, value));

        // This is the correct behavior - ignore silently for forward compatibility
    }

    fn has_protocol_errors(&self) -> bool {
        !self.protocol_errors.is_empty()
    }

    fn error_count(&self) -> usize {
        self.protocol_errors.len()
    }

    fn unknown_ignored_count(&self) -> usize {
        self.ignored_unknown_count
    }

    fn was_unknown_logged(&self, id: u16, value: u32) -> bool {
        self.unknown_settings_log.contains(&(id, value))
    }

    // Getters for current settings (to verify known settings were processed)
    fn current_max_frame_size(&self) -> u32 {
        self.max_frame_size
    }
    fn current_enable_push(&self) -> bool {
        self.enable_push
    }
    fn current_initial_window_size(&self) -> u32 {
        self.initial_window_size
    }
}

fuzz_target!(|input: UnknownSettingsInput| {
    // Ensure we test truly unknown setting IDs
    let unknown_id = if KnownSettingsId::is_known(input.unknown_id) {
        // Force to known-unknown range
        0x8000 | (input.unknown_id & 0x7FFF) // High bit set = definitely unknown
    } else {
        input.unknown_id
    };

    let mut conn = MockUnknownSettingsConnection::new();
    let initial_max_frame_size = conn.current_max_frame_size();

    match input.test_variant % 8 {
        0 => {
            // Test case 1: Single unknown setting - MUST be ignored
            let frame = SettingsFrame::new_unknown_only(unknown_id, input.unknown_value);
            let accepted = conn.process_settings_frame(&frame);

            assert!(
                accepted,
                "Frame with only unknown setting should be accepted"
            );
            assert!(
                !conn.has_protocol_errors(),
                "Unknown setting should not cause PROTOCOL_ERROR"
            );
            assert_eq!(
                conn.unknown_ignored_count(),
                1,
                "Should have ignored exactly 1 unknown setting"
            );
            assert!(
                conn.was_unknown_logged(unknown_id, input.unknown_value),
                "Unknown setting should be logged"
            );

            // Connection state should remain unchanged
            assert_eq!(
                conn.current_max_frame_size(),
                initial_max_frame_size,
                "Unknown setting should not affect connection state"
            );
        }
        1 => {
            // Test case 2: Multiple unknown settings
            let unknown_ids = [
                unknown_id,
                0xFF00 | (input.unknown_value as u16 & 0xFF), // Another unknown ID
                0x7777,                                       // Fixed unknown ID
            ];

            let mut params = Vec::new();
            for (i, &id) in unknown_ids.iter().enumerate() {
                params.push(SettingsParameter::new_unknown(
                    id,
                    input.unknown_value + i as u32,
                ));
            }

            let frame = SettingsFrame::new(false, params);
            let accepted = conn.process_settings_frame(&frame);

            assert!(
                accepted,
                "Frame with multiple unknown settings should be accepted"
            );
            assert!(
                !conn.has_protocol_errors(),
                "Multiple unknown settings should not cause errors"
            );
            assert_eq!(
                conn.unknown_ignored_count(),
                3,
                "Should have ignored 3 unknown settings"
            );
        }
        2 => {
            // Test case 3: Mixed known and unknown settings
            let known_settings = vec![
                (KnownSettingsId::MaxFrameSize, 32768),
                (KnownSettingsId::EnablePush, 0),
            ];
            let unknown_settings = vec![(unknown_id, input.unknown_value), (0xDEAD, 0xBEEF)];

            let frame = SettingsFrame::new_mixed(known_settings, unknown_settings);
            let accepted = conn.process_settings_frame(&frame);

            assert!(accepted, "Mixed known/unknown frame should be accepted");
            assert!(
                !conn.has_protocol_errors(),
                "Mixed frame should not cause errors"
            );
            assert_eq!(
                conn.unknown_ignored_count(),
                2,
                "Should ignore unknown settings"
            );

            // Known settings should be applied
            assert_eq!(
                conn.current_max_frame_size(),
                32768,
                "Known MAX_FRAME_SIZE should be applied"
            );
            assert!(
                !conn.current_enable_push(),
                "Known ENABLE_PUSH should be applied"
            );
        }
        3 => {
            // Test case 4: Unknown setting with reserved/special values
            let special_values = [0x0, 0x1, u32::MAX, 0x80000000, 0x7FFFFFFF];

            for (i, &value) in special_values.iter().enumerate() {
                let mut test_conn = MockUnknownSettingsConnection::new();
                let test_id = unknown_id.wrapping_add(i as u16);
                let frame = SettingsFrame::new_unknown_only(test_id, value);

                let accepted = test_conn.process_settings_frame(&frame);
                assert!(
                    accepted,
                    "Unknown setting with special value {} should be accepted",
                    value
                );
                assert!(
                    !test_conn.has_protocol_errors(),
                    "Special value {} should not cause errors",
                    value
                );
                assert!(
                    test_conn.was_unknown_logged(test_id, value),
                    "Special value should be logged"
                );
            }
        }
        4 => {
            // Test case 5: Unknown setting followed by known setting that might fail
            let frame = SettingsFrame::new_mixed(
                vec![(KnownSettingsId::EnablePush, 42)], // Invalid ENABLE_PUSH value
                vec![(unknown_id, input.unknown_value)],
            );

            let accepted = conn.process_settings_frame(&frame);

            // Frame should be rejected due to invalid ENABLE_PUSH, but unknown setting
            // should still be processed (ignored) before the error
            assert!(
                !accepted,
                "Frame with invalid known setting should be rejected"
            );
            assert!(
                conn.has_protocol_errors(),
                "Invalid ENABLE_PUSH should cause error"
            );

            // However, the unknown setting processing should have happened
            // (Implementation detail: depends on parameter processing order)
        }
        5 => {
            // Test case 6: Unknown settings in SETTINGS ACK (should still be error)
            let params = vec![SettingsParameter::new_unknown(
                unknown_id,
                input.unknown_value,
            )];
            let ack_frame = SettingsFrame::new(true, params); // ACK=true with payload

            let accepted = conn.process_settings_frame(&ack_frame);

            assert!(!accepted, "SETTINGS ACK with payload should be rejected");
            assert!(
                conn.has_protocol_errors(),
                "ACK with payload should cause PROTOCOL_ERROR"
            );
            // Unknown settings don't make ACK valid
        }
        6 => {
            // Test case 7: Very large unknown setting ID (edge case)
            let large_id = u16::MAX;
            let frame = SettingsFrame::new_unknown_only(large_id, input.unknown_value);

            let accepted = conn.process_settings_frame(&frame);

            assert!(accepted, "Unknown setting with large ID should be accepted");
            assert!(
                !conn.has_protocol_errors(),
                "Large unknown ID should not cause errors"
            );
            assert_eq!(
                conn.unknown_ignored_count(),
                1,
                "Large unknown ID should be ignored"
            );
        }
        7 => {
            // Test case 8: Sequence of frames with unknown settings
            let frames = vec![
                SettingsFrame::new_unknown_only(unknown_id, input.unknown_value),
                SettingsFrame::new_mixed(
                    vec![(KnownSettingsId::InitialWindowSize, 32768)],
                    vec![(unknown_id.wrapping_add(1), input.unknown_value + 1)],
                ),
                SettingsFrame::new(true, vec![]), // ACK
            ];

            let mut all_accepted = true;
            for frame in &frames {
                if !conn.process_settings_frame(frame) {
                    all_accepted = false;
                    break;
                }
            }

            assert!(
                all_accepted,
                "Sequence with unknown settings should be accepted"
            );
            assert!(
                !conn.has_protocol_errors(),
                "Sequence should not cause errors"
            );
            assert_eq!(
                conn.unknown_ignored_count(),
                2,
                "Should ignore 2 unknown settings"
            );
            assert_eq!(
                conn.current_initial_window_size(),
                32768,
                "Known setting should be applied"
            );
        }
        _ => unreachable!(),
    }

    // Verify connection state consistency
    assert_eq!(
        conn.accepted_frames + conn.error_count() <= conn.processed_frames,
        true,
        "Connection statistics should be consistent"
    );

    // Verify forward compatibility: unknown settings never cause protocol errors by themselves
    if conn.has_protocol_errors() {
        // If there are errors, they should be due to invalid known settings, not unknown ones
        for error in &conn.protocol_errors {
            assert!(
                !error.contains("unknown") && !error.contains("unsupported"),
                "Protocol errors should not mention unknown settings: {}",
                error
            );
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_unknown_setting_ignored() {
        let mut conn = MockUnknownSettingsConnection::new();
        let frame = SettingsFrame::new_unknown_only(0x8888, 0x12345678);

        assert!(conn.process_settings_frame(&frame));
        assert!(!conn.has_protocol_errors());
        assert_eq!(conn.unknown_ignored_count(), 1);
        assert!(conn.was_unknown_logged(0x8888, 0x12345678));
    }

    #[test]
    fn test_mixed_known_unknown_settings() {
        let mut conn = MockUnknownSettingsConnection::new();
        let frame = SettingsFrame::new_mixed(
            vec![(KnownSettingsId::MaxFrameSize, 32768)],
            vec![(0x9999, 0xABCD)],
        );

        assert!(conn.process_settings_frame(&frame));
        assert!(!conn.has_protocol_errors());
        assert_eq!(conn.unknown_ignored_count(), 1);
        assert_eq!(conn.current_max_frame_size(), 32768);
    }

    #[test]
    fn test_multiple_unknown_settings_ignored() {
        let mut conn = MockUnknownSettingsConnection::new();
        let params = vec![
            SettingsParameter::new_unknown(0xAAAA, 1),
            SettingsParameter::new_unknown(0xBBBB, 2),
            SettingsParameter::new_unknown(0xCCCC, 3),
        ];
        let frame = SettingsFrame::new(false, params);

        assert!(conn.process_settings_frame(&frame));
        assert!(!conn.has_protocol_errors());
        assert_eq!(conn.unknown_ignored_count(), 3);
    }

    #[test]
    fn test_known_settings_still_validated() {
        let mut conn = MockUnknownSettingsConnection::new();
        let frame = SettingsFrame::new_mixed(
            vec![(KnownSettingsId::EnablePush, 42)], // Invalid value
            vec![(0xDDDD, 0x1234)],                  // Unknown setting
        );

        assert!(!conn.process_settings_frame(&frame));
        assert!(conn.has_protocol_errors());
        // Error should be about ENABLE_PUSH, not unknown setting
        assert!(conn.protocol_errors[0].contains("ENABLE_PUSH"));
    }

    #[test]
    fn test_settings_ack_with_unknown_still_error() {
        let mut conn = MockUnknownSettingsConnection::new();
        let params = vec![SettingsParameter::new_unknown(0xEEEE, 0x5678)];
        let frame = SettingsFrame::new(true, params); // ACK with payload

        assert!(!conn.process_settings_frame(&frame));
        assert!(conn.has_protocol_errors());
        // Error should be about ACK with payload
        assert!(conn.protocol_errors[0].contains("ACK"));
    }

    #[test]
    fn test_unknown_id_detection() {
        // Test that our known ID detection is correct
        assert!(KnownSettingsId::is_known(1)); // HEADER_TABLE_SIZE
        assert!(KnownSettingsId::is_known(6)); // MAX_HEADER_LIST_SIZE
        assert!(!KnownSettingsId::is_known(7)); // Unknown
        assert!(!KnownSettingsId::is_known(0x8000)); // Unknown
        assert!(!KnownSettingsId::is_known(u16::MAX)); // Unknown
    }

    #[test]
    fn test_forward_compatibility_principle() {
        // RFC 7540 §6.5 forward compatibility test
        let mut conn = MockUnknownSettingsConnection::new();

        // Simulate future HTTP/2 extension settings
        let future_settings = [
            (0x0007, 1),        // Hypothetical future setting
            (0x0008, 2),        // Another future setting
            (0xFF00, u32::MAX), // Vendor-specific setting
        ];

        for (id, value) in future_settings {
            let frame = SettingsFrame::new_unknown_only(id, value);
            assert!(
                conn.process_settings_frame(&frame),
                "Future setting {} should be forward-compatible",
                id
            );
        }

        assert!(
            !conn.has_protocol_errors(),
            "Forward compatibility should not break existing connections"
        );
        assert_eq!(conn.unknown_ignored_count(), 3);
    }
}
