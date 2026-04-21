#![allow(clippy::all)]
//! HTTP/3 SETTINGS frame conformance tests for RFC 9114 Section 7.2.4
//!
//! This module implements metamorphic testing for HTTP/3 SETTINGS frame
//! handling with emphasis on RFC 9114 compliance:
//! - QPACK parameter validation and constraint consistency
//! - max_field_section_size enforcement and boundary conditions
//! - Control stream restriction validation (SETTINGS only on control stream)
//! - Duplicate settings rejection and protocol error generation
//! - GREASE value tolerance and unknown setting preservation

use proptest::prelude::*;
use std::collections::HashMap;

use asupersync::http::h3_native::{
    H3_SETTING_ENABLE_CONNECT_PROTOCOL, H3_SETTING_H3_DATAGRAM, H3_SETTING_MAX_FIELD_SECTION_SIZE,
    H3_SETTING_QPACK_BLOCKED_STREAMS, H3_SETTING_QPACK_MAX_TABLE_CAPACITY, H3ConnectionConfig,
    H3ConnectionState, H3ControlState, H3Frame, H3NativeError, H3QpackMode, H3Settings,
    UnknownSetting,
};

/// GREASE setting identifiers for testing unknown setting tolerance.
/// These follow the pattern for HTTP/3 GREASE values.
const GREASE_SETTINGS: &[u64] = &[
    0x15, 0x2A, 0x3F, 0x54, 0x69, 0x7E, 0x93, 0xA8, 0xBD, 0xD2, 0xE7, 0xFC, 0x111, 0x126, 0x13B,
    0x150, 0x165, 0x17A, 0x18F, 0x1A4, 0x1B9, 0x1CE, 0x1E3, 0x1F8, 0x20D, 0x222, 0x237, 0x24C,
    0x261, 0x276, 0x28B, 0x2A0,
];

/// Maximum reasonable field section size for testing (1MB)
const MAX_REASONABLE_FIELD_SECTION_SIZE: u64 = 1024 * 1024;

/// Test input structure for SETTINGS frame metamorphic testing
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SettingsTestCase {
    /// Primary settings configuration
    settings: H3Settings,
    /// Additional unknown/GREASE settings
    unknown_settings: Vec<UnknownSetting>,
    /// Whether to test duplicate settings
    include_duplicates: bool,
    /// QPACK mode constraint
    qpack_mode: H3QpackMode,
    /// Whether to test control stream restriction
    test_control_stream_only: bool,
}

impl Arbitrary for SettingsTestCase {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    #[allow(dead_code)]

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            arbitrary_h3_settings(),
            prop::collection::vec(arbitrary_unknown_setting(), 0..5),
            any::<bool>(),
            arbitrary_qpack_mode(),
            any::<bool>(),
        )
            .prop_map(
                |(
                    settings,
                    unknown_settings,
                    include_duplicates,
                    qpack_mode,
                    test_control_stream_only,
                )| {
                    SettingsTestCase {
                        settings,
                        unknown_settings,
                        include_duplicates,
                        qpack_mode,
                        test_control_stream_only,
                    }
                },
            )
            .boxed()
    }
}

#[allow(dead_code)]

fn arbitrary_h3_settings() -> BoxedStrategy<H3Settings> {
    (
        prop::option::of(0u64..=65536), // qpack_max_table_capacity
        prop::option::of(1u64..=MAX_REASONABLE_FIELD_SECTION_SIZE), // max_field_section_size
        prop::option::of(0u64..=1000),  // qpack_blocked_streams
        prop::option::of(any::<bool>()), // enable_connect_protocol
        prop::option::of(any::<bool>()), // h3_datagram
    )
        .prop_map(
            |(
                qpack_max_table_capacity,
                max_field_section_size,
                qpack_blocked_streams,
                enable_connect_protocol,
                h3_datagram,
            )| {
                H3Settings {
                    qpack_max_table_capacity,
                    max_field_section_size,
                    qpack_blocked_streams,
                    enable_connect_protocol,
                    h3_datagram,
                    unknown: Vec::new(), // Will be filled separately
                }
            },
        )
        .boxed()
}

#[allow(dead_code)]

fn arbitrary_unknown_setting() -> BoxedStrategy<UnknownSetting> {
    prop_oneof![
        // GREASE values
        prop::sample::select(GREASE_SETTINGS.to_vec())
            .prop_map(|id| UnknownSetting { id, value: 0 }),
        // Random unknown settings (avoiding known setting IDs)
        (0x100u64..=0xFFFF, 0u64..=0xFFFF).prop_map(|(id, value)| UnknownSetting { id, value }),
    ]
    .boxed()
}

#[allow(dead_code)]

fn arbitrary_qpack_mode() -> BoxedStrategy<H3QpackMode> {
    prop_oneof![
        Just(H3QpackMode::StaticOnly),
        Just(H3QpackMode::DynamicTableAllowed),
    ]
    .boxed()
}

/// MR1: QPACK Parameter Consistency
///
/// QPACK settings must maintain logical consistency:
/// - If qpack_max_table_capacity is 0, qpack_blocked_streams must be 0 or unset
/// - StaticOnly mode must reject any dynamic table configuration
/// - Settings must survive encode/decode round-trip with values intact
#[allow(dead_code)]
fn mr_qpack_parameter_consistency(test_case: &SettingsTestCase) {
    let mut settings = test_case.settings.clone();
    settings.unknown = test_case.unknown_settings.clone();

    // Test QPACK logical consistency
    let table_capacity = settings.qpack_max_table_capacity.unwrap_or(0);
    let blocked_streams = settings.qpack_blocked_streams.unwrap_or(0);

    if table_capacity == 0 && blocked_streams > 0 {
        // This configuration is logically inconsistent but allowed by spec
        // We test that it's handled gracefully
        let config = H3ConnectionConfig {
            qpack_mode: test_case.qpack_mode,
            ..H3ConnectionConfig::default()
        };
        let mut connection = H3ConnectionState::new();
        connection.set_config(config);

        // Should not panic or cause undefined behavior
        let _ = connection.on_control_frame(&H3Frame::Settings(settings.clone()));
    }

    // Test StaticOnly mode enforcement
    if test_case.qpack_mode == H3QpackMode::StaticOnly {
        let config = H3ConnectionConfig {
            qpack_mode: H3QpackMode::StaticOnly,
            ..H3ConnectionConfig::default()
        };
        let mut connection = H3ConnectionState::new();
        connection.set_config(config);

        if table_capacity > 0 {
            // Should reject dynamic table usage
            let result = connection.on_control_frame(&H3Frame::Settings(settings.clone()));
            assert!(
                result.is_err(),
                "StaticOnly mode should reject non-zero QPACK table capacity"
            );
        }

        if blocked_streams > 0 {
            // Should reject blocked streams
            let mut static_settings = settings.clone();
            static_settings.qpack_max_table_capacity = Some(0);
            static_settings.qpack_blocked_streams = Some(blocked_streams);

            let result = connection.on_control_frame(&H3Frame::Settings(static_settings));
            assert!(
                result.is_err(),
                "StaticOnly mode should reject non-zero blocked streams"
            );
        }
    }

    // Test encode/decode round-trip preservation
    let mut encoded_payload = Vec::new();
    settings
        .encode_payload(&mut encoded_payload)
        .expect("Encoding should succeed");

    let decoded_settings =
        H3Settings::decode_payload(&encoded_payload).expect("Decoding should succeed");

    assert_eq!(
        settings.qpack_max_table_capacity, decoded_settings.qpack_max_table_capacity,
        "QPACK max table capacity not preserved through encode/decode"
    );
    assert_eq!(
        settings.qpack_blocked_streams, decoded_settings.qpack_blocked_streams,
        "QPACK blocked streams not preserved through encode/decode"
    );
}

/// MR2: Max Field Section Size Enforcement
///
/// max_field_section_size must be properly enforced and respected:
/// - Value must be preserved exactly through encode/decode
/// - Must handle edge cases (0, very large values)
/// - Connection must respect the limit when processing headers
#[allow(dead_code)]
fn mr_max_field_section_size_enforcement(test_case: &SettingsTestCase) {
    let mut settings = test_case.settings.clone();
    settings.unknown = test_case.unknown_settings.clone();

    if let Some(max_size) = settings.max_field_section_size {
        // Test encode/decode preservation
        let mut encoded_payload = Vec::new();
        settings
            .encode_payload(&mut encoded_payload)
            .expect("Encoding should succeed");

        let decoded_settings =
            H3Settings::decode_payload(&encoded_payload).expect("Decoding should succeed");

        assert_eq!(
            settings.max_field_section_size, decoded_settings.max_field_section_size,
            "max_field_section_size not preserved through encode/decode"
        );

        // Test boundary conditions
        if max_size == 0 {
            // Zero should be valid (though impractical)
            assert_eq!(decoded_settings.max_field_section_size, Some(0));
        }

        if max_size > MAX_REASONABLE_FIELD_SECTION_SIZE {
            // Very large values should still be preserved
            assert_eq!(decoded_settings.max_field_section_size, Some(max_size));
        }

        // Test connection state respects the setting
        let config = H3ConnectionConfig {
            qpack_mode: test_case.qpack_mode,
            ..H3ConnectionConfig::default()
        };
        let mut connection = H3ConnectionState::new();
        connection.set_config(config);

        let result = connection.on_control_frame(&H3Frame::Settings(settings.clone()));
        assert!(
            result.is_ok(),
            "Valid max_field_section_size should be accepted: {:?}",
            result
        );
    }
}

/// MR3: Control Stream Only Restriction
///
/// SETTINGS frames must only be sent on the control stream:
/// - First frame on control stream must be SETTINGS
/// - Duplicate SETTINGS on control stream must be rejected
/// - SETTINGS frames on non-control streams are protocol violations
#[allow(dead_code)]
fn mr_control_stream_only_restriction(test_case: &SettingsTestCase) {
    if !test_case.test_control_stream_only {
        return;
    }

    let mut settings = test_case.settings.clone();
    settings.unknown = test_case.unknown_settings.clone();
    let settings_frame = H3Frame::Settings(settings);

    // Test first frame must be SETTINGS
    let mut control_state = H3ControlState::new();
    let result = control_state.on_remote_control_frame(&settings_frame);
    assert!(
        result.is_ok(),
        "First SETTINGS frame should be accepted on control stream"
    );

    // Test duplicate SETTINGS rejection
    let duplicate_result = control_state.on_remote_control_frame(&settings_frame);
    assert!(
        duplicate_result.is_err(),
        "Duplicate SETTINGS frame should be rejected"
    );

    match duplicate_result.unwrap_err() {
        H3NativeError::ControlProtocol(msg) if msg.contains("duplicate SETTINGS") => {
            // Expected error
        }
        other_error => panic!("Expected duplicate SETTINGS error, got: {:?}", other_error),
    }

    // Test non-SETTINGS frame as first frame
    let mut fresh_control_state = H3ControlState::new();
    let non_settings_frame = H3Frame::Goaway(0);
    let non_settings_result = fresh_control_state.on_remote_control_frame(&non_settings_frame);
    assert!(
        non_settings_result.is_err(),
        "Non-SETTINGS frame should be rejected as first frame"
    );

    match non_settings_result.unwrap_err() {
        H3NativeError::ControlProtocol(msg)
            if msg.contains("first remote control frame must be SETTINGS") =>
        {
            // Expected error
        }
        other_error => panic!(
            "Expected first frame SETTINGS error, got: {:?}",
            other_error
        ),
    }
}

/// MR4: Duplicate Settings Rejection
///
/// Duplicate setting identifiers in a single SETTINGS frame must be rejected:
/// - Same setting ID appearing twice should cause protocol error
/// - Different setting IDs should be accepted
/// - Unknown settings can be duplicated (for GREASE)
#[allow(dead_code)]
fn mr_duplicate_settings_rejection(test_case: &SettingsTestCase) {
    if !test_case.include_duplicates {
        return;
    }

    // Test duplicate known setting IDs
    let duplicate_cases = vec![
        (H3_SETTING_QPACK_MAX_TABLE_CAPACITY, 4096u64, 8192u64),
        (H3_SETTING_MAX_FIELD_SECTION_SIZE, 16384u64, 32768u64),
        (H3_SETTING_QPACK_BLOCKED_STREAMS, 10u64, 20u64),
        (H3_SETTING_ENABLE_CONNECT_PROTOCOL, 0u64, 1u64),
        (H3_SETTING_H3_DATAGRAM, 0u64, 1u64),
    ];

    for (setting_id, value1, value2) in duplicate_cases {
        // Manually encode a payload with duplicate setting IDs
        let mut payload = Vec::new();

        // Encode first instance
        let mut temp = Vec::new();
        asupersync::net::quic_core::encode_varint(setting_id, &mut temp).unwrap();
        asupersync::net::quic_core::encode_varint(value1, &mut temp).unwrap();
        payload.extend_from_slice(&temp);

        // Encode duplicate instance
        let mut temp = Vec::new();
        asupersync::net::quic_core::encode_varint(setting_id, &mut temp).unwrap();
        asupersync::net::quic_core::encode_varint(value2, &mut temp).unwrap();
        payload.extend_from_slice(&temp);

        // Try to decode - should fail with DuplicateSetting error
        let decode_result = H3Settings::decode_payload(&payload);
        assert!(
            decode_result.is_err(),
            "Duplicate setting ID 0x{:x} should be rejected",
            setting_id
        );

        match decode_result.unwrap_err() {
            H3NativeError::DuplicateSetting(id) if id == setting_id => {
                // Expected error
            }
            other_error => panic!(
                "Expected DuplicateSetting(0x{:x}), got: {:?}",
                setting_id, other_error
            ),
        }
    }

    // Test that non-duplicate settings work correctly
    let mut settings = test_case.settings.clone();
    settings.unknown = test_case.unknown_settings.clone();

    let mut encoded_payload = Vec::new();
    let encode_result = settings.encode_payload(&mut encoded_payload);
    assert!(
        encode_result.is_ok(),
        "Non-duplicate settings should encode successfully"
    );

    let decode_result = H3Settings::decode_payload(&encoded_payload);
    assert!(
        decode_result.is_ok(),
        "Non-duplicate settings should decode successfully"
    );
}

/// MR5: GREASE Value Tolerance
///
/// Unknown and GREASE settings must be preserved and ignored gracefully:
/// - GREASE values should be accepted without error
/// - Unknown settings should be preserved through encode/decode
/// - Connection should continue normally despite unknown settings
#[allow(dead_code)]
fn mr_grease_value_tolerance(test_case: &SettingsTestCase) {
    let mut settings = test_case.settings.clone();

    // Add GREASE settings
    let mut grease_settings = Vec::new();
    for &grease_id in GREASE_SETTINGS.iter().take(3) {
        grease_settings.push(UnknownSetting {
            id: grease_id,
            value: 42, // Arbitrary value
        });
    }

    // Add the unknown settings from test case
    grease_settings.extend(test_case.unknown_settings.clone());
    settings.unknown = grease_settings.clone();

    // Test encode/decode preserves unknown settings
    let mut encoded_payload = Vec::new();
    let encode_result = settings.encode_payload(&mut encoded_payload);
    assert!(
        encode_result.is_ok(),
        "Settings with GREASE values should encode successfully"
    );

    let decode_result = H3Settings::decode_payload(&encoded_payload);
    assert!(
        decode_result.is_ok(),
        "Settings with GREASE values should decode successfully"
    );

    let decoded_settings = decode_result.unwrap();

    // Verify GREASE/unknown settings are preserved
    assert_eq!(
        decoded_settings.unknown.len(),
        grease_settings.len(),
        "Number of unknown settings should be preserved"
    );

    // Create a mapping for comparison since order might differ
    let mut original_map: HashMap<u64, u64> = HashMap::new();
    for unknown in &grease_settings {
        original_map.insert(unknown.id, unknown.value);
    }

    let mut decoded_map: HashMap<u64, u64> = HashMap::new();
    for unknown in &decoded_settings.unknown {
        decoded_map.insert(unknown.id, unknown.value);
    }

    assert_eq!(
        original_map, decoded_map,
        "GREASE/unknown settings values should be preserved exactly"
    );

    // Test connection accepts GREASE values gracefully
    let config = H3ConnectionConfig {
        qpack_mode: test_case.qpack_mode,
        ..H3ConnectionConfig::default()
    };
    let mut connection = H3ConnectionState::new();
    connection.set_config(config);

    let result = connection.on_control_frame(&H3Frame::Settings(decoded_settings));
    assert!(
        result.is_ok(),
        "Connection should accept SETTINGS with GREASE values: {:?}",
        result
    );

    // Test that GREASE values don't interfere with known settings processing
    assert_eq!(
        settings.qpack_max_table_capacity, decoded_settings.qpack_max_table_capacity,
        "GREASE values should not affect known setting processing"
    );
    assert_eq!(
        settings.max_field_section_size, decoded_settings.max_field_section_size,
        "GREASE values should not affect max_field_section_size"
    );
}

// Property-based test runners for each metamorphic relation

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    #[allow(dead_code)]
    fn test_mr_qpack_parameter_consistency(test_case in any::<SettingsTestCase>()) {
        mr_qpack_parameter_consistency(&test_case);
    }

    #[test]
    #[allow(dead_code)]
    fn test_mr_max_field_section_size_enforcement(test_case in any::<SettingsTestCase>()) {
        mr_max_field_section_size_enforcement(&test_case);
    }

    #[test]
    #[allow(dead_code)]
    fn test_mr_control_stream_only_restriction(test_case in any::<SettingsTestCase>()) {
        mr_control_stream_only_restriction(&test_case);
    }

    #[test]
    #[allow(dead_code)]
    fn test_mr_duplicate_settings_rejection(test_case in any::<SettingsTestCase>()) {
        mr_duplicate_settings_rejection(&test_case);
    }

    #[test]
    #[allow(dead_code)]
    fn test_mr_grease_value_tolerance(test_case in any::<SettingsTestCase>()) {
        mr_grease_value_tolerance(&test_case);
    }
}

// Additional focused conformance tests for RFC 9114 Section 7.2.4

#[cfg(test)]
mod rfc_9114_settings_tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn rfc_9114_section_7_2_4_settings_frame_basic_conformance() {
        // Test basic SETTINGS frame structure per RFC 9114 Section 7.2.4
        let settings = H3Settings {
            qpack_max_table_capacity: Some(4096),
            max_field_section_size: Some(16384),
            qpack_blocked_streams: Some(100),
            enable_connect_protocol: Some(true),
            h3_datagram: Some(false),
            unknown: vec![],
        };

        let mut payload = Vec::new();
        settings
            .encode_payload(&mut payload)
            .expect("Encoding should succeed");

        let decoded = H3Settings::decode_payload(&payload).expect("Decoding should succeed");
        assert_eq!(settings, decoded, "Settings should round-trip correctly");
    }

    #[test]
    #[allow(dead_code)]
    fn rfc_9114_settings_boolean_validation() {
        // Boolean settings must be 0 or 1 per RFC 9114
        let mut payload = Vec::new();

        // Encode invalid boolean value (2) for ENABLE_CONNECT_PROTOCOL
        asupersync::net::quic_core::encode_varint(H3_SETTING_ENABLE_CONNECT_PROTOCOL, &mut payload)
            .unwrap();
        asupersync::net::quic_core::encode_varint(2u64, &mut payload).unwrap();

        let result = H3Settings::decode_payload(&payload);
        assert!(result.is_err(), "Invalid boolean values should be rejected");

        match result.unwrap_err() {
            H3NativeError::InvalidSettingValue(id) => {
                assert_eq!(id, H3_SETTING_ENABLE_CONNECT_PROTOCOL);
            }
            other => panic!("Expected InvalidSettingValue error, got: {:?}", other),
        }
    }

    #[test]
    #[allow(dead_code)]
    fn rfc_9114_settings_order_independence() {
        // Settings should be processed regardless of order
        let settings1 = H3Settings {
            max_field_section_size: Some(16384),
            qpack_max_table_capacity: Some(4096),
            unknown: vec![],
            ..Default::default()
        };

        let settings2 = H3Settings {
            qpack_max_table_capacity: Some(4096),
            max_field_section_size: Some(16384),
            unknown: vec![],
            ..Default::default()
        };

        let mut payload1 = Vec::new();
        settings1
            .encode_payload(&mut payload1)
            .expect("Encoding 1 should succeed");

        let mut payload2 = Vec::new();
        settings2
            .encode_payload(&mut payload2)
            .expect("Encoding 2 should succeed");

        let decoded1 = H3Settings::decode_payload(&payload1).expect("Decoding 1 should succeed");
        let decoded2 = H3Settings::decode_payload(&payload2).expect("Decoding 2 should succeed");

        // Both should have same logical content regardless of encoding order
        assert_eq!(
            decoded1.max_field_section_size,
            decoded2.max_field_section_size
        );
        assert_eq!(
            decoded1.qpack_max_table_capacity,
            decoded2.qpack_max_table_capacity
        );
    }

    #[test]
    #[allow(dead_code)]
    fn rfc_9114_settings_unknown_preservation() {
        // Unknown settings must be preserved for future extensibility
        let unknown_setting = UnknownSetting {
            id: 0xDEAD,
            value: 0xBEEF,
        };
        let settings = H3Settings {
            unknown: vec![unknown_setting.clone()],
            ..Default::default()
        };

        let mut payload = Vec::new();
        settings
            .encode_payload(&mut payload)
            .expect("Encoding should succeed");

        let decoded = H3Settings::decode_payload(&payload).expect("Decoding should succeed");

        assert_eq!(decoded.unknown.len(), 1);
        assert_eq!(decoded.unknown[0].id, unknown_setting.id);
        assert_eq!(decoded.unknown[0].value, unknown_setting.value);
    }

    #[test]
    #[allow(dead_code)]
    fn rfc_9114_settings_control_stream_first_frame() {
        // First frame on control stream must be SETTINGS (RFC 9114 Section 6.2.1)
        let mut control = H3ControlState::new();

        // Try to send non-SETTINGS frame first
        let goaway_frame = H3Frame::Goaway(0);
        let result = control.on_remote_control_frame(&goaway_frame);

        assert!(result.is_err());
        if let Err(H3NativeError::ControlProtocol(msg)) = result {
            assert!(msg.contains("first remote control frame must be SETTINGS"));
        } else {
            panic!("Expected ControlProtocol error for non-SETTINGS first frame");
        }
    }
}
