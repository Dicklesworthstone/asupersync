#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::frame::{
    FrameHeader, FrameType, Setting, SettingsFrame as H2SettingsFrame, settings_flags,
};
use asupersync::http::h2::{ErrorCode, H2Error, Settings};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS unlimited handling testing.
/// Per RFC 7540 §6.5.2, omitted SETTINGS_MAX_CONCURRENT_STREAMS means unlimited.
/// Practical implementations must cap this to prevent resource exhaustion.
/// Tests sensible default cap when unlimited is indicated.
///
/// Tests:
/// - SETTINGS without MAX_CONCURRENT_STREAMS (unlimited → should cap to default)
/// - SETTINGS with very large MAX_CONCURRENT_STREAMS (should cap to reasonable limit)
/// - SETTINGS with MAX_CONCURRENT_STREAMS = 0 (should respect exact value)
/// - SETTINGS with reasonable values (should use as-is)
/// - Resource exhaustion protection
/// - Default cap enforcement

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// SETTINGS frame to test
    settings_frame: SettingsFrame,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsFrame {
    /// Frame flags (should be 0 for non-ACK SETTINGS)
    flags: u8,
    /// Stream ID (must be 0 for SETTINGS)
    stream_id: u32,
    /// Settings entries
    settings: Vec<SettingEntry>,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingEntry {
    /// Setting ID
    id: u16,
    /// Setting value
    value: u32,
}

/// Known HTTP/2 settings
const SETTINGS_HEADER_TABLE_SIZE: u16 = 1;
const SETTINGS_ENABLE_PUSH: u16 = 2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 6;
const KNOWN_SETTING_IDS: [u16; 6] = [
    SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_ENABLE_PUSH,
    SETTINGS_MAX_CONCURRENT_STREAMS,
    SETTINGS_INITIAL_WINDOW_SIZE,
    SETTINGS_MAX_FRAME_SIZE,
    SETTINGS_MAX_HEADER_LIST_SIZE,
];

/// Practical implementation limits
const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 1000; // Sensible default cap
const ABSOLUTE_MAX_CONCURRENT_STREAMS: u32 = 10000; // Hard upper limit
const RESOURCE_EXHAUSTION_THRESHOLD: u32 = 100000; // Clear resource exhaustion attempt

/// Mock HTTP/2 settings parser with practical concurrent streams limiting
struct MockH2SettingsLimiter {
    /// Current settings state
    max_concurrent_streams: Option<u32>, // None = unlimited per RFC
    /// Effective limit used by implementation
    effective_limit: u32,
    /// Warnings for debugging
    warnings: Vec<String>,
}

impl MockH2SettingsLimiter {
    fn new() -> Self {
        Self {
            max_concurrent_streams: None, // Start with RFC default (unlimited)
            effective_limit: DEFAULT_MAX_CONCURRENT_STREAMS, // Practical default
            warnings: Vec::new(),
        }
    }

    /// Process SETTINGS frame and update limits
    fn process_settings_frame(&mut self, frame: &SettingsFrame) -> Result<(), String> {
        // Validate frame structure
        if stream_id_for_wire(frame.stream_id) != 0 {
            return Err("PROTOCOL_ERROR: SETTINGS frame stream ID must be 0".into());
        }

        if (frame.flags & 0x01) != 0 {
            // ACK frame should have empty payload
            if !frame.settings.is_empty() {
                return Err("FRAME_SIZE_ERROR: SETTINGS ACK frame must have empty payload".into());
            }
            return Ok(());
        }

        // Process individual settings
        for setting in &frame.settings {
            match setting.id {
                SETTINGS_MAX_CONCURRENT_STREAMS => {
                    self.process_max_concurrent_streams_setting(setting.value)?;
                }
                SETTINGS_HEADER_TABLE_SIZE => {
                    // Validate but don't process for this test
                    if setting.value > 65536 {
                        self.warnings
                            .push(format!("Large header table size: {}", setting.value));
                    }
                }
                SETTINGS_ENABLE_PUSH => {
                    if setting.value > 1 {
                        return Err("PROTOCOL_ERROR: ENABLE_PUSH must be 0 or 1".into());
                    }
                }
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    if setting.value > 2_147_483_647 {
                        return Err(
                            "FLOW_CONTROL_ERROR: INITIAL_WINDOW_SIZE exceeds maximum".into()
                        );
                    }
                }
                SETTINGS_MAX_FRAME_SIZE => {
                    if !(16_384..=16_777_215).contains(&setting.value) {
                        return Err("PROTOCOL_ERROR: MAX_FRAME_SIZE out of range".into());
                    }
                }
                SETTINGS_MAX_HEADER_LIST_SIZE => {
                    // Any value allowed
                }
                _ => {
                    // Unknown settings are ignored per RFC 7540 §6.5
                    self.warnings
                        .push(format!("Unknown setting ID: {}", setting.id));
                }
            }
        }

        Ok(())
    }

    /// Process MAX_CONCURRENT_STREAMS setting with practical limiting
    fn process_max_concurrent_streams_setting(&mut self, value: u32) -> Result<(), String> {
        // Store the RFC value
        self.max_concurrent_streams = Some(value);

        // Apply practical limits.
        self.effective_limit = if value == 0 {
            // 0 means "disable concurrent streams" - respect this exactly.
            0
        } else if value <= ABSOLUTE_MAX_CONCURRENT_STREAMS {
            // Reasonable value - use as-is.
            value
        } else if value <= RESOURCE_EXHAUSTION_THRESHOLD {
            // Large but not obviously malicious - cap to maximum.
            self.warnings.push(format!(
                "Capping MAX_CONCURRENT_STREAMS from {} to {}",
                value, ABSOLUTE_MAX_CONCURRENT_STREAMS
            ));
            ABSOLUTE_MAX_CONCURRENT_STREAMS
        } else {
            // Clearly excessive - potential resource exhaustion attack.
            self.warnings.push(format!(
                "Suspected resource exhaustion: MAX_CONCURRENT_STREAMS = {} capped to {}",
                value, ABSOLUTE_MAX_CONCURRENT_STREAMS
            ));
            ABSOLUTE_MAX_CONCURRENT_STREAMS
        };

        Ok(())
    }

    /// Get current RFC-specified value (None = unlimited per RFC)
    fn get_rfc_max_concurrent_streams(&self) -> Option<u32> {
        self.max_concurrent_streams
    }

    /// Get effective limit used by implementation
    fn get_effective_limit(&self) -> u32 {
        self.effective_limit
    }

    /// Get warnings generated
    fn get_warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Check if unlimited scenario (RFC allows this but implementation should cap)
    fn is_unlimited_scenario(&self) -> bool {
        self.max_concurrent_streams.is_none()
    }

    /// Simulate concurrent stream allocation to test limits
    fn can_allocate_streams(&self, requested_count: u32) -> bool {
        requested_count <= self.effective_limit
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit settings count to prevent timeouts
    if input.settings_frame.settings.len() > 20 {
        return;
    }

    let mut limiter = MockH2SettingsLimiter::new();
    let result = limiter.process_settings_frame(&input.settings_frame);
    assert_live_settings_behavior(&input.settings_frame);

    // Test 1: Frame validation errors
    if stream_id_for_wire(input.settings_frame.stream_id) != 0 {
        assert!(
            result.is_err(),
            "SETTINGS frame with non-zero stream ID should be rejected"
        );
        return;
    }

    let is_ack = (input.settings_frame.flags & 0x01) != 0;
    if is_ack && !input.settings_frame.settings.is_empty() {
        assert!(
            result.is_err(),
            "SETTINGS ACK frame with payload should be rejected"
        );
        return;
    }

    // Test 2: Setting validation errors
    for setting in &input.settings_frame.settings {
        match setting.id {
            SETTINGS_ENABLE_PUSH => {
                if setting.value > 1 {
                    assert!(
                        result.is_err(),
                        "Invalid ENABLE_PUSH value should be rejected"
                    );
                    return;
                }
            }
            SETTINGS_INITIAL_WINDOW_SIZE => {
                if setting.value > 2_147_483_647 {
                    assert!(
                        result.is_err(),
                        "Invalid INITIAL_WINDOW_SIZE should be rejected"
                    );
                    return;
                }
            }
            SETTINGS_MAX_FRAME_SIZE if !(16_384..=16_777_215).contains(&setting.value) => {
                assert!(result.is_err(), "Invalid MAX_FRAME_SIZE should be rejected");
                return;
            }
            _ => {}
        }
    }

    // For valid frames, test concurrent streams handling
    if result.is_ok() && !is_ack {
        // Test 3: Check if MAX_CONCURRENT_STREAMS was specified
        let has_max_concurrent_streams = input
            .settings_frame
            .settings
            .iter()
            .any(|s| s.id == SETTINGS_MAX_CONCURRENT_STREAMS);

        if !has_max_concurrent_streams {
            // No MAX_CONCURRENT_STREAMS specified - should use default cap
            assert!(
                limiter.is_unlimited_scenario(),
                "Should recognize unlimited scenario when MAX_CONCURRENT_STREAMS not specified"
            );

            assert_eq!(
                limiter.get_effective_limit(),
                DEFAULT_MAX_CONCURRENT_STREAMS,
                "Should apply default cap when unlimited per RFC"
            );
        }

        // Test 4: MAX_CONCURRENT_STREAMS value handling
        for setting in &input.settings_frame.settings {
            if setting.id == SETTINGS_MAX_CONCURRENT_STREAMS {
                let rfc_value = limiter.get_rfc_max_concurrent_streams();
                let effective_limit = limiter.get_effective_limit();

                assert_eq!(
                    rfc_value,
                    Some(setting.value),
                    "RFC value should match setting value"
                );

                match setting.value {
                    0 => {
                        assert_eq!(effective_limit, 0, "Zero value should be respected exactly");
                    }
                    1..=ABSOLUTE_MAX_CONCURRENT_STREAMS => {
                        assert_eq!(
                            effective_limit, setting.value,
                            "Reasonable values should be used as-is"
                        );
                    }
                    _ => {
                        assert_eq!(
                            effective_limit, ABSOLUTE_MAX_CONCURRENT_STREAMS,
                            "Excessive values should be capped"
                        );

                        let warnings = limiter.get_warnings();
                        assert!(
                            warnings
                                .iter()
                                .any(|w| w.contains("Capping") || w.contains("exhaustion")),
                            "Should generate warning for excessive values"
                        );
                    }
                }
            }
        }

        // Test 5: Stream allocation simulation
        assert!(
            limiter.can_allocate_streams(0),
            "Should always allow 0 streams"
        );

        if limiter.get_effective_limit() > 0 {
            assert!(
                limiter.can_allocate_streams(1),
                "Should allow single stream when limit > 0"
            );

            assert!(
                limiter.can_allocate_streams(limiter.get_effective_limit()),
                "Should allow allocation up to effective limit"
            );

            if limiter.get_effective_limit() < u32::MAX {
                assert!(
                    !limiter.can_allocate_streams(limiter.get_effective_limit() + 1),
                    "Should reject allocation beyond effective limit"
                );
            }
        } else {
            assert!(
                !limiter.can_allocate_streams(1),
                "Should reject all streams when limit is 0"
            );
        }

        // Test 6: Resource exhaustion protection
        assert!(
            !limiter.can_allocate_streams(RESOURCE_EXHAUSTION_THRESHOLD),
            "Should protect against clear resource exhaustion attempts"
        );
    }
});

fn assert_live_settings_behavior(frame: &SettingsFrame) {
    let wire = build_settings_frame_wire(frame);
    let mut src = BytesMut::from(wire);
    let header = FrameHeader::parse(&mut src).expect("generated SETTINGS header is complete");
    let payload = src.freeze();
    assert_eq!(header.frame_type, FrameType::Settings as u8);
    assert_eq!(
        header.length as usize,
        payload.len(),
        "generated SETTINGS header length must match payload"
    );

    let result = H2SettingsFrame::parse(&header, &payload);

    if header.stream_id != 0 {
        assert_error_code(result, ErrorCode::ProtocolError);
        return;
    }

    let ack_flag_set = header.has_flag(settings_flags::ACK);
    if ack_flag_set && !payload.is_empty() {
        assert_error_code(result, ErrorCode::FrameSizeError);
        return;
    }

    if let Some(code) = first_live_setting_error(&payload) {
        assert_error_code(result, code);
        return;
    }

    let parsed = result.expect("valid SETTINGS frame should parse");
    assert_eq!(parsed.ack, ack_flag_set);
    if ack_flag_set {
        assert!(
            parsed.settings.is_empty(),
            "SETTINGS ACK must not expose payload settings"
        );
        return;
    }

    assert_eq!(
        parsed.settings,
        expected_known_settings(&payload),
        "live SETTINGS parser must preserve known settings and ignore unknown IDs"
    );
    assert_eq!(
        parsed.settings.len(),
        payload.chunks_exact(6).count() - unknown_setting_count(&payload),
        "live SETTINGS parser must not retain unknown IDs"
    );

    let mut live_settings = Settings::default();
    for setting in parsed.settings {
        live_settings
            .apply(setting)
            .expect("settings accepted by parser must apply");
    }

    let expected_max_concurrent_streams = payload
        .chunks_exact(6)
        .filter_map(|chunk| {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            (id == SETTINGS_MAX_CONCURRENT_STREAMS).then_some(value)
        })
        .next_back()
        .unwrap_or_else(|| Settings::default().max_concurrent_streams);
    assert_eq!(
        live_settings.max_concurrent_streams, expected_max_concurrent_streams,
        "live SETTINGS apply must use the last advertised MAX_CONCURRENT_STREAMS or its default"
    );
}

fn build_settings_frame_wire(frame: &SettingsFrame) -> Vec<u8> {
    let payload = build_settings_payload(&frame.settings);
    let header = FrameHeader {
        length: payload.len() as u32,
        frame_type: FrameType::Settings as u8,
        flags: frame.flags,
        stream_id: stream_id_for_wire(frame.stream_id),
    };

    let mut wire = BytesMut::new();
    header.write(&mut wire);
    wire.extend_from_slice(&payload);
    wire.to_vec()
}

fn build_settings_payload(settings: &[SettingEntry]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(settings.len() * 6);
    for setting in settings {
        payload.extend_from_slice(&setting.id.to_be_bytes());
        payload.extend_from_slice(&setting.value.to_be_bytes());
    }
    payload
}

fn first_live_setting_error(payload: &Bytes) -> Option<ErrorCode> {
    for chunk in payload.chunks_exact(6) {
        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
        let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
        match id {
            SETTINGS_ENABLE_PUSH if value > 1 => return Some(ErrorCode::ProtocolError),
            SETTINGS_INITIAL_WINDOW_SIZE if value > 0x7fff_ffff => {
                return Some(ErrorCode::FlowControlError);
            }
            SETTINGS_MAX_FRAME_SIZE if !(16_384..=16_777_215).contains(&value) => {
                return Some(ErrorCode::ProtocolError);
            }
            _ => {}
        }
    }
    None
}

fn expected_known_settings(payload: &Bytes) -> Vec<Setting> {
    payload
        .chunks_exact(6)
        .filter_map(|chunk| {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            Setting::from_id_value(id, value)
        })
        .collect()
}

fn unknown_setting_count(payload: &Bytes) -> usize {
    payload
        .chunks_exact(6)
        .filter(|chunk| {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            !KNOWN_SETTING_IDS.contains(&id)
        })
        .count()
}

fn assert_error_code(result: Result<H2SettingsFrame, H2Error>, expected: ErrorCode) {
    match result {
        Ok(frame) => panic!("expected {expected:?}, parsed SETTINGS frame: {frame:?}"),
        Err(err) => assert_eq!(err.code, expected, "unexpected SETTINGS parse error: {err}"),
    }
}

fn stream_id_for_wire(stream_id: u32) -> u32 {
    stream_id & 0x7fff_ffff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_max_concurrent_streams_setting() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![
                SettingEntry {
                    id: SETTINGS_HEADER_TABLE_SIZE,
                    value: 4096,
                },
                SettingEntry {
                    id: SETTINGS_ENABLE_PUSH,
                    value: 1,
                },
                // No MAX_CONCURRENT_STREAMS setting
            ],
        };

        let mut limiter = MockH2SettingsLimiter::new();
        let result = limiter.process_settings_frame(&frame);

        assert!(result.is_ok());
        assert!(limiter.is_unlimited_scenario());
        assert_eq!(limiter.get_rfc_max_concurrent_streams(), None);
        assert_eq!(
            limiter.get_effective_limit(),
            DEFAULT_MAX_CONCURRENT_STREAMS
        );
    }

    #[test]
    fn test_reasonable_max_concurrent_streams() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![SettingEntry {
                id: SETTINGS_MAX_CONCURRENT_STREAMS,
                value: 500,
            }],
        };

        let mut limiter = MockH2SettingsLimiter::new();
        let result = limiter.process_settings_frame(&frame);

        assert!(result.is_ok());
        assert!(!limiter.is_unlimited_scenario());
        assert_eq!(limiter.get_rfc_max_concurrent_streams(), Some(500));
        assert_eq!(limiter.get_effective_limit(), 500);
    }

    #[test]
    fn test_zero_max_concurrent_streams() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![SettingEntry {
                id: SETTINGS_MAX_CONCURRENT_STREAMS,
                value: 0,
            }],
        };

        let mut limiter = MockH2SettingsLimiter::new();
        let result = limiter.process_settings_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(limiter.get_rfc_max_concurrent_streams(), Some(0));
        assert_eq!(limiter.get_effective_limit(), 0);
        assert!(!limiter.can_allocate_streams(1));
    }

    #[test]
    fn test_excessive_max_concurrent_streams() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![SettingEntry {
                id: SETTINGS_MAX_CONCURRENT_STREAMS,
                value: 1_000_000,
            }],
        };

        let mut limiter = MockH2SettingsLimiter::new();
        let result = limiter.process_settings_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(limiter.get_rfc_max_concurrent_streams(), Some(1_000_000));
        assert_eq!(
            limiter.get_effective_limit(),
            ABSOLUTE_MAX_CONCURRENT_STREAMS
        );

        let warnings = limiter.get_warnings();
        assert!(warnings.iter().any(|w| w.contains("exhaustion")));
    }

    #[test]
    fn test_at_absolute_limit() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![SettingEntry {
                id: SETTINGS_MAX_CONCURRENT_STREAMS,
                value: ABSOLUTE_MAX_CONCURRENT_STREAMS,
            }],
        };

        let mut limiter = MockH2SettingsLimiter::new();
        let result = limiter.process_settings_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(
            limiter.get_effective_limit(),
            ABSOLUTE_MAX_CONCURRENT_STREAMS
        );
        assert!(limiter.get_warnings().is_empty()); // Should not warn for exactly at limit
    }

    #[test]
    fn test_just_over_absolute_limit() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![SettingEntry {
                id: SETTINGS_MAX_CONCURRENT_STREAMS,
                value: ABSOLUTE_MAX_CONCURRENT_STREAMS + 1,
            }],
        };

        let mut limiter = MockH2SettingsLimiter::new();
        let result = limiter.process_settings_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(
            limiter.get_effective_limit(),
            ABSOLUTE_MAX_CONCURRENT_STREAMS
        );

        let warnings = limiter.get_warnings();
        assert!(warnings.iter().any(|w| w.contains("Capping")));
    }

    #[test]
    fn test_stream_allocation_simulation() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![SettingEntry {
                id: SETTINGS_MAX_CONCURRENT_STREAMS,
                value: 100,
            }],
        };

        let mut limiter = MockH2SettingsLimiter::new();
        assert!(limiter.process_settings_frame(&frame).is_ok());

        // Test various allocation scenarios
        assert!(limiter.can_allocate_streams(0));
        assert!(limiter.can_allocate_streams(1));
        assert!(limiter.can_allocate_streams(50));
        assert!(limiter.can_allocate_streams(100));
        assert!(!limiter.can_allocate_streams(101));
        assert!(!limiter.can_allocate_streams(1000));
    }

    #[test]
    fn test_settings_ack_frame() {
        let frame = SettingsFrame {
            flags: 0x01, // ACK flag
            stream_id: 0,
            settings: vec![], // Empty payload for ACK
        };

        let mut limiter = MockH2SettingsLimiter::new();
        let result = limiter.process_settings_frame(&frame);

        assert!(result.is_ok());
        // ACK frame should not change state
        assert!(limiter.is_unlimited_scenario());
        assert_eq!(
            limiter.get_effective_limit(),
            DEFAULT_MAX_CONCURRENT_STREAMS
        );
    }

    #[test]
    fn test_invalid_enable_push() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![
                SettingEntry {
                    id: SETTINGS_ENABLE_PUSH,
                    value: 2,
                }, // Invalid
            ],
        };

        let mut limiter = MockH2SettingsLimiter::new();
        let result = limiter.process_settings_frame(&frame);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ENABLE_PUSH"));
    }

    #[test]
    fn test_invalid_window_size() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![SettingEntry {
                id: SETTINGS_INITIAL_WINDOW_SIZE,
                value: 2_147_483_648, // > 2^31 - 1
            }],
        };

        let mut limiter = MockH2SettingsLimiter::new();
        let result = limiter.process_settings_frame(&frame);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("FLOW_CONTROL_ERROR"));
    }

    #[test]
    fn test_unknown_setting_ignored() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![
                SettingEntry {
                    id: 99,
                    value: 12345,
                }, // Unknown setting
                SettingEntry {
                    id: SETTINGS_MAX_CONCURRENT_STREAMS,
                    value: 200,
                },
            ],
        };

        let mut limiter = MockH2SettingsLimiter::new();
        let result = limiter.process_settings_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(limiter.get_effective_limit(), 200);

        let warnings = limiter.get_warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("Unknown setting ID: 99"))
        );
    }
}
