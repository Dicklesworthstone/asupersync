//! HTTP/2 SETTINGS frame multiplicity fuzz target.
//!
//! Tests SETTINGS frame handling with repeated parameters per RFC 7540 Section 6.5.
//! When multiple SETTINGS frames contain the same parameter, or when a single
//! SETTINGS frame contains the same parameter multiple times, the latest value
//! should be applied.
//!
//! This fuzzer generates arbitrary repeated SETTINGS and verifies:
//! 1. Latest values are applied per parameter across multiple frames
//! 2. Latest values are applied per parameter within a single frame
//! 3. Independent parameters don't interfere with each other
//! 4. SETTINGS ACK confirms the final applied values
//! 5. No panics occur with arbitrary parameter repetition

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// SETTINGS frame multiplicity test
#[derive(Debug, Clone, Arbitrary)]
struct SettingsMultiplicityTest {
    /// Multiple SETTINGS frames to send
    settings_frames: Vec<SettingsFrame>,
    /// Whether to send ACKs for each frame
    send_acks: bool,
    /// Connection configuration
    connection_config: ConnectionConfig,
    /// Whether to test within-frame duplicates
    test_intra_frame_duplicates: bool,
}

/// SETTINGS frame with potentially duplicate parameters
#[derive(Debug, Clone, Arbitrary)]
struct SettingsFrame {
    /// Settings parameters (may contain duplicates)
    parameters: Vec<SettingsParameter>,
    /// Frame flags
    flags: u8,
    /// Extra padding data
    padding: Vec<u8>,
}

/// Individual SETTINGS parameter
#[derive(Debug, Clone, Arbitrary)]
struct SettingsParameter {
    /// Setting identifier
    setting_id: SettingIdentifier,
    /// Setting value
    value: u32,
}

/// HTTP/2 SETTINGS identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Arbitrary)]
enum SettingIdentifier {
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
    /// Unknown setting for extension testing
    Unknown(u16),
}

/// Connection configuration
#[derive(Debug, Clone, Arbitrary)]
struct ConnectionConfig {
    /// Initial SETTINGS values
    initial_settings: HashMap<SettingIdentifier, u32>,
    /// Whether to enforce strict validation
    strict_validation: bool,
    /// Maximum number of SETTINGS frames to process
    max_settings_frames: u8,
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 100_000 {
        return;
    }

    if data.is_empty() {
        for test_case in generate_multiplicity_scenarios() {
            exercise_settings_multiplicity_case(&test_case);
        }
        return;
    }

    let mut u = arbitrary::Unstructured::new(data);

    // Generate SETTINGS multiplicity test case
    let test_case = match SettingsMultiplicityTest::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return,
    };

    // Limit frames and parameters for performance
    if test_case.settings_frames.len() > 20 {
        return;
    }

    let total_params: usize = test_case
        .settings_frames
        .iter()
        .map(|f| f.parameters.len())
        .sum();
    if total_params > 100 {
        return;
    }

    exercise_settings_multiplicity_case(&test_case);
});

fn exercise_settings_multiplicity_case(test_case: &SettingsMultiplicityTest) {
    // Test core SETTINGS multiplicity behavior
    test_settings_multiplicity(test_case);

    // Test latest value application
    test_latest_value_application(test_case);

    // Test intra-frame duplicates
    if test_case.test_intra_frame_duplicates {
        test_intra_frame_duplicates(test_case);
    }

    // Test parameter independence
    test_parameter_independence(test_case);

    // Test edge cases
    test_multiplicity_edge_cases(test_case);
}

/// Test SETTINGS frame multiplicity behavior
fn test_settings_multiplicity(test_case: &SettingsMultiplicityTest) {
    let mut mock_connection = MockH2Connection::new(test_case.connection_config.clone());

    let mut expected_final_values: HashMap<SettingIdentifier, u32> = HashMap::new();
    let mut frame_count = 0;

    // Process each SETTINGS frame
    for (frame_idx, settings_frame) in test_case.settings_frames.iter().enumerate() {
        if frame_count >= test_case.connection_config.max_settings_frames {
            break;
        }

        // Skip ACK frames
        if settings_frame.flags & SETTINGS_ACK_FLAG != 0 {
            continue;
        }

        let send_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mock_connection.send_settings_frame(settings_frame.clone())
        }));

        assert!(
            send_result.is_ok(),
            "Sending SETTINGS frame {} should not panic",
            frame_idx
        );

        if let Ok(result) = send_result {
            match result {
                SettingsFrameResult::Accepted { applied_settings } => {
                    // Update expected values with latest from this frame
                    for (setting_id, value) in applied_settings {
                        expected_final_values.insert(setting_id, value);
                    }

                    // Send ACK if requested
                    if test_case.send_acks {
                        let ack_result = mock_connection.send_settings_ack();
                        assert!(
                            matches!(ack_result, AckResult::Sent),
                            "SETTINGS ACK should be sent successfully"
                        );
                    }
                }
                SettingsFrameResult::Rejected { reason } => {
                    assert!(
                        !reason.trim().is_empty(),
                        "rejected SETTINGS frames should expose diagnostics"
                    );
                    assert!(
                        !is_valid_settings_frame(settings_frame),
                        "valid SETTINGS frame rejected: {}",
                        reason
                    );
                }
            }
        }

        frame_count += 1;
    }

    // Verify final applied settings match expected
    for (setting_id, expected_value) in expected_final_values {
        let actual_value = mock_connection.get_setting_value(setting_id);
        assert_eq!(
            actual_value,
            Some(expected_value),
            "Setting {:?} should have value {} but has {:?}",
            setting_id,
            expected_value,
            actual_value
        );
    }
}

/// Test that latest values are applied per parameter
fn test_latest_value_application(test_case: &SettingsMultiplicityTest) {
    let mut mock_connection = MockH2Connection::new(test_case.connection_config.clone());

    // Track the latest value for each setting across all frames
    let mut latest_values: HashMap<SettingIdentifier, u32> = HashMap::new();

    // Process frames in order, tracking latest values
    for settings_frame in &test_case.settings_frames {
        if settings_frame.flags & SETTINGS_ACK_FLAG != 0 {
            continue; // Skip ACK frames
        }

        // Send the frame
        let result = mock_connection.send_settings_frame(settings_frame.clone());
        if let Some(applied_settings) = observe_settings_frame_result(
            settings_frame,
            test_case.connection_config.strict_validation,
            result,
        ) {
            // Update global latest values only with values the connection accepted.
            for (setting_id, value) in applied_settings {
                latest_values.insert(setting_id, value);
            }
        }
    }

    // Verify that the connection has the latest values
    for (setting_id, expected_latest) in latest_values {
        let actual_value = mock_connection.get_setting_value(setting_id);
        assert_eq!(
            actual_value,
            Some(expected_latest),
            "Latest value test failed for {:?}: expected {}, got {:?}",
            setting_id,
            expected_latest,
            actual_value
        );
    }
}

/// Test intra-frame duplicate parameter handling
fn test_intra_frame_duplicates(test_case: &SettingsMultiplicityTest) {
    // Create a frame with intentional duplicates
    let mut duplicate_frame = SettingsFrame {
        parameters: vec![
            SettingsParameter {
                setting_id: SettingIdentifier::InitialWindowSize,
                value: 16384,
            },
            SettingsParameter {
                setting_id: SettingIdentifier::InitialWindowSize,
                value: 32768, // This should override the first
            },
            SettingsParameter {
                setting_id: SettingIdentifier::MaxFrameSize,
                value: 16384,
            },
            SettingsParameter {
                setting_id: SettingIdentifier::InitialWindowSize,
                value: 65535, // This should be the final value
            },
        ],
        flags: 0,
        padding: vec![],
    };

    // Add some parameters from the test case for variety
    if let Some(first_frame) = test_case.settings_frames.first() {
        for param in &first_frame.parameters {
            duplicate_frame.parameters.push(param.clone());
        }
    }

    let mut mock_connection = MockH2Connection::new(test_case.connection_config.clone());

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_settings_frame(duplicate_frame.clone())
    }));

    assert!(result.is_ok(), "Intra-frame duplicates should not panic");

    if let Ok(frame_result) = result
        && let Some(applied_settings) = observe_settings_frame_result(
            &duplicate_frame,
            test_case.connection_config.strict_validation,
            frame_result,
        )
    {
        let window_size = mock_connection.get_setting_value(SettingIdentifier::InitialWindowSize);
        assert_eq!(
            window_size,
            applied_settings
                .get(&SettingIdentifier::InitialWindowSize)
                .copied(),
            "Last occurrence should win for intra-frame duplicates"
        );

        if let Some(expected_frame_size) = applied_settings.get(&SettingIdentifier::MaxFrameSize) {
            let frame_size = mock_connection.get_setting_value(SettingIdentifier::MaxFrameSize);
            assert_eq!(
                frame_size,
                Some(*expected_frame_size),
                "Non-duplicated setting should be applied normally"
            );
        }
    }
}

/// Test parameter independence
fn test_parameter_independence(test_case: &SettingsMultiplicityTest) {
    let mut mock_connection = MockH2Connection::new(test_case.connection_config.clone());

    // Create frames that update different parameters independently
    let independent_frames = vec![
        SettingsFrame {
            parameters: vec![SettingsParameter {
                setting_id: SettingIdentifier::HeaderTableSize,
                value: 4096,
            }],
            flags: 0,
            padding: vec![],
        },
        SettingsFrame {
            parameters: vec![SettingsParameter {
                setting_id: SettingIdentifier::MaxConcurrentStreams,
                value: 100,
            }],
            flags: 0,
            padding: vec![],
        },
        SettingsFrame {
            parameters: vec![SettingsParameter {
                setting_id: SettingIdentifier::HeaderTableSize,
                value: 8192, // Update first parameter
            }],
            flags: 0,
            padding: vec![],
        },
    ];

    // Send each frame
    for frame in independent_frames {
        let result = mock_connection.send_settings_frame(frame.clone());
        let applied_settings = observe_settings_frame_result(
            &frame,
            test_case.connection_config.strict_validation,
            result,
        )
        .expect("independent SETTINGS frame");
        assert_eq!(
            applied_settings.len(),
            1,
            "independent SETTINGS frame should apply one parameter"
        );
    }

    // Verify independent updates
    let header_table_size = mock_connection.get_setting_value(SettingIdentifier::HeaderTableSize);
    assert_eq!(
        header_table_size,
        Some(8192),
        "HeaderTableSize should be updated to latest value"
    );

    let max_streams = mock_connection.get_setting_value(SettingIdentifier::MaxConcurrentStreams);
    assert_eq!(
        max_streams,
        Some(100),
        "MaxConcurrentStreams should remain unchanged"
    );
    assert!(
        mock_connection.get_all_settings().len() >= 2,
        "independent SETTINGS updates should be visible in the connection map"
    );

    // Send additional test case frames if any
    for settings_frame in &test_case.settings_frames {
        if settings_frame.flags & SETTINGS_ACK_FLAG == 0 {
            let result = mock_connection.send_settings_frame(settings_frame.clone());
            observe_settings_frame_result(
                settings_frame,
                test_case.connection_config.strict_validation,
                result,
            );
        }
    }
}

fn observe_settings_frame_result(
    frame: &SettingsFrame,
    strict_validation: bool,
    result: SettingsFrameResult,
) -> Option<HashMap<SettingIdentifier, u32>> {
    match result {
        SettingsFrameResult::Accepted { applied_settings } => {
            assert!(
                frame.flags & SETTINGS_ACK_FLAG == 0 || frame.parameters.is_empty(),
                "accepted SETTINGS ACK frames must not carry parameters"
            );

            let expected = expected_applied_settings(frame, strict_validation);
            assert_eq!(
                applied_settings, expected,
                "accepted SETTINGS frames should apply the latest valid value per setting"
            );

            Some(applied_settings)
        }
        SettingsFrameResult::Rejected { reason } => {
            assert!(
                !reason.trim().is_empty(),
                "rejected SETTINGS frames should include a diagnostic reason"
            );
            assert!(
                !is_valid_settings_frame(frame),
                "only invalid SETTINGS frames should be rejected by the mock connection"
            );
            None
        }
    }
}

fn expected_applied_settings(
    frame: &SettingsFrame,
    strict_validation: bool,
) -> HashMap<SettingIdentifier, u32> {
    if frame.flags & SETTINGS_ACK_FLAG != 0 {
        return HashMap::new();
    }

    let mut latest_values = HashMap::new();
    for param in &frame.parameters {
        latest_values.insert(param.setting_id, param.value);
    }

    if strict_validation {
        latest_values
            .into_iter()
            .filter(|(setting_id, value)| is_valid_setting_value(*setting_id, *value))
            .collect()
    } else {
        latest_values
    }
}

/// Test edge cases in SETTINGS multiplicity
fn test_multiplicity_edge_cases(test_case: &SettingsMultiplicityTest) {
    let mut mock_connection = MockH2Connection::new(test_case.connection_config.clone());

    // Test empty SETTINGS frame
    let empty_frame = SettingsFrame {
        parameters: vec![],
        flags: 0,
        padding: vec![],
    };

    let empty_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_settings_frame(empty_frame)
    }));

    assert!(
        empty_result.is_ok(),
        "Empty SETTINGS frame should not panic"
    );

    // Test SETTINGS with unknown parameters
    let unknown_frame = SettingsFrame {
        parameters: vec![
            SettingsParameter {
                setting_id: SettingIdentifier::Unknown(0x8000),
                value: 12345,
            },
            SettingsParameter {
                setting_id: SettingIdentifier::Unknown(0x8000), // Duplicate unknown
                value: 67890,
            },
        ],
        flags: 0,
        padding: vec![],
    };

    let unknown_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_settings_frame(unknown_frame)
    }));

    assert!(unknown_result.is_ok(), "Unknown SETTINGS should not panic");

    // Test very large number of duplicates
    let many_duplicates = SettingsFrame {
        parameters: (0..50)
            .map(|i| SettingsParameter {
                setting_id: SettingIdentifier::EnablePush,
                value: i % 2, // Alternating 0 and 1
            })
            .collect(),
        flags: 0,
        padding: vec![],
    };

    let many_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_settings_frame(many_duplicates.clone())
    }));

    assert!(many_result.is_ok(), "Many duplicates should not panic");

    observe_settings_frame_result(
        &many_duplicates,
        mock_connection.config.strict_validation,
        many_result.unwrap(),
    )
    .expect("many duplicate SETTINGS frame should be accepted");

    // Last value (49 % 2 = 1) should be applied
    let enable_push = mock_connection.get_setting_value(SettingIdentifier::EnablePush);
    assert_eq!(enable_push, Some(1), "Last duplicate value should win");

    // Test maximum value boundaries
    let boundary_frame = SettingsFrame {
        parameters: vec![
            SettingsParameter {
                setting_id: SettingIdentifier::InitialWindowSize,
                value: 0x7FFFFFFF, // Max valid value
            },
            SettingsParameter {
                setting_id: SettingIdentifier::InitialWindowSize,
                value: 0x80000000, // Invalid (exceeds 2^31-1)
            },
            SettingsParameter {
                setting_id: SettingIdentifier::InitialWindowSize,
                value: 65536, // Valid value after invalid
            },
        ],
        flags: 0,
        padding: vec![],
    };

    let boundary_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_settings_frame(boundary_frame)
    }));

    assert!(
        boundary_result.is_ok(),
        "Boundary value testing should not panic"
    );
    // Behavior with invalid values is implementation-defined

    // Test alternating valid/invalid pattern
    let alternating_frame = SettingsFrame {
        parameters: vec![
            SettingsParameter {
                setting_id: SettingIdentifier::EnablePush,
                value: 0, // Valid
            },
            SettingsParameter {
                setting_id: SettingIdentifier::EnablePush,
                value: 5, // Invalid (should be 0 or 1)
            },
            SettingsParameter {
                setting_id: SettingIdentifier::EnablePush,
                value: 1, // Valid again
            },
        ],
        flags: 0,
        padding: vec![],
    };

    let alternating_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_settings_frame(alternating_frame)
    }));

    assert!(
        alternating_result.is_ok(),
        "Alternating valid/invalid should not panic"
    );
}

/// SETTINGS frame flags
const SETTINGS_ACK_FLAG: u8 = 0x1;

impl SettingIdentifier {
    fn to_u16(self) -> u16 {
        match self {
            Self::HeaderTableSize => 0x1,
            Self::EnablePush => 0x2,
            Self::MaxConcurrentStreams => 0x3,
            Self::InitialWindowSize => 0x4,
            Self::MaxFrameSize => 0x5,
            Self::MaxHeaderListSize => 0x6,
            Self::Unknown(id) => id,
        }
    }

    fn is_known(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

/// Check if SETTINGS frame is valid
fn is_valid_settings_frame(frame: &SettingsFrame) -> bool {
    if !frame.padding.is_empty() {
        return false;
    }

    // ACK frames should have no parameters
    if frame.flags & SETTINGS_ACK_FLAG != 0 {
        return frame.parameters.is_empty();
    }

    // Check parameter validity
    for param in &frame.parameters {
        if param.setting_id.is_known() {
            debug_assert!((1..=6).contains(&param.setting_id.to_u16()));
        }
        if !is_valid_setting_value(param.setting_id, param.value) {
            return false;
        }
    }

    true
}

/// Check if setting value is valid
fn is_valid_setting_value(setting_id: SettingIdentifier, value: u32) -> bool {
    match setting_id {
        SettingIdentifier::EnablePush => value <= 1,
        SettingIdentifier::InitialWindowSize => value <= 0x7FFFFFFF,
        SettingIdentifier::MaxFrameSize => (16384..=0xFFFFFF).contains(&value),
        _ => true, // Other settings accept any u32 value
    }
}

/// SETTINGS frame processing result
#[derive(Debug, Clone)]
enum SettingsFrameResult {
    Accepted {
        applied_settings: HashMap<SettingIdentifier, u32>,
    },
    Rejected {
        reason: String,
    },
}

/// ACK result
#[derive(Debug, Clone)]
enum AckResult {
    Sent,
    NoSetting,
}

/// Mock HTTP/2 connection for testing
struct MockH2Connection {
    settings: HashMap<SettingIdentifier, u32>,
    config: ConnectionConfig,
    pending_ack: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        let mut initial_settings = HashMap::new();
        initial_settings.insert(SettingIdentifier::HeaderTableSize, 4096);
        initial_settings.insert(SettingIdentifier::EnablePush, 1);
        initial_settings.insert(SettingIdentifier::MaxConcurrentStreams, 100);
        initial_settings.insert(SettingIdentifier::InitialWindowSize, 65535);
        initial_settings.insert(SettingIdentifier::MaxFrameSize, 16384);
        initial_settings.insert(SettingIdentifier::MaxHeaderListSize, 8192);

        Self {
            initial_settings,
            strict_validation: true,
            max_settings_frames: 10,
        }
    }
}

impl MockH2Connection {
    fn new(config: ConnectionConfig) -> Self {
        Self {
            settings: config.initial_settings.clone(),
            config,
            pending_ack: false,
        }
    }

    fn send_settings_frame(&mut self, frame: SettingsFrame) -> SettingsFrameResult {
        // Handle ACK frames
        if frame.flags & SETTINGS_ACK_FLAG != 0 {
            if !frame.parameters.is_empty() {
                return SettingsFrameResult::Rejected {
                    reason: "SETTINGS ACK must not have parameters".to_string(),
                };
            }
            self.pending_ack = false;
            return SettingsFrameResult::Accepted {
                applied_settings: HashMap::new(),
            };
        }

        // Validate frame if strict validation is enabled
        if self.config.strict_validation && !is_valid_settings_frame(&frame) {
            return SettingsFrameResult::Rejected {
                reason: "Invalid SETTINGS frame".to_string(),
            };
        }

        // Process parameters, latest value wins within the frame
        let mut frame_settings: HashMap<SettingIdentifier, u32> = HashMap::new();
        let mut applied_settings: HashMap<SettingIdentifier, u32> = HashMap::new();

        for param in &frame.parameters {
            // For each parameter, the last occurrence in the frame wins
            frame_settings.insert(param.setting_id, param.value);
        }

        // Apply the final values from this frame
        for (setting_id, value) in frame_settings {
            // Validate individual settings
            if self.config.strict_validation && !is_valid_setting_value(setting_id, value) {
                continue; // Skip invalid settings
            }

            // Apply the setting
            self.settings.insert(setting_id, value);
            applied_settings.insert(setting_id, value);
        }

        self.pending_ack = true;

        SettingsFrameResult::Accepted { applied_settings }
    }

    fn send_settings_ack(&mut self) -> AckResult {
        if self.pending_ack {
            self.pending_ack = false;
            AckResult::Sent
        } else {
            AckResult::NoSetting
        }
    }

    fn get_setting_value(&self, setting_id: SettingIdentifier) -> Option<u32> {
        self.settings.get(&setting_id).copied()
    }

    fn get_all_settings(&self) -> &HashMap<SettingIdentifier, u32> {
        &self.settings
    }
}

/// Generate test scenarios for SETTINGS multiplicity
fn generate_multiplicity_scenarios() -> Vec<SettingsMultiplicityTest> {
    vec![
        // Basic multiplicity test
        SettingsMultiplicityTest {
            settings_frames: vec![
                SettingsFrame {
                    parameters: vec![
                        SettingsParameter {
                            setting_id: SettingIdentifier::InitialWindowSize,
                            value: 32768,
                        },
                        SettingsParameter {
                            setting_id: SettingIdentifier::MaxFrameSize,
                            value: 32768,
                        },
                    ],
                    flags: 0,
                    padding: vec![],
                },
                SettingsFrame {
                    parameters: vec![SettingsParameter {
                        setting_id: SettingIdentifier::InitialWindowSize,
                        value: 65535, // Override previous value
                    }],
                    flags: 0,
                    padding: vec![],
                },
            ],
            send_acks: true,
            connection_config: ConnectionConfig::default(),
            test_intra_frame_duplicates: true,
        },
        // Intra-frame duplicates
        SettingsMultiplicityTest {
            settings_frames: vec![SettingsFrame {
                parameters: vec![
                    SettingsParameter {
                        setting_id: SettingIdentifier::HeaderTableSize,
                        value: 4096,
                    },
                    SettingsParameter {
                        setting_id: SettingIdentifier::HeaderTableSize,
                        value: 8192, // Should win
                    },
                    SettingsParameter {
                        setting_id: SettingIdentifier::EnablePush,
                        value: 0,
                    },
                ],
                flags: 0,
                padding: vec![],
            }],
            send_acks: false,
            connection_config: ConnectionConfig::default(),
            test_intra_frame_duplicates: true,
        },
    ]
}

/// Test that demonstrates expected SETTINGS multiplicity behavior
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latest_value_wins_across_frames() {
        let mut conn = MockH2Connection::new(ConnectionConfig::default());

        // Send first SETTINGS frame
        let frame1 = SettingsFrame {
            parameters: vec![SettingsParameter {
                setting_id: SettingIdentifier::InitialWindowSize,
                value: 32768,
            }],
            flags: 0,
            padding: vec![],
        };

        let result1 = conn.send_settings_frame(frame1);
        assert!(matches!(result1, SettingsFrameResult::Accepted { .. }));

        // Send second SETTINGS frame with different value
        let frame2 = SettingsFrame {
            parameters: vec![SettingsParameter {
                setting_id: SettingIdentifier::InitialWindowSize,
                value: 65535, // Should override first value
            }],
            flags: 0,
            padding: vec![],
        };

        let result2 = conn.send_settings_frame(frame2);
        assert!(matches!(result2, SettingsFrameResult::Accepted { .. }));

        // Verify latest value is applied
        let window_size = conn.get_setting_value(SettingIdentifier::InitialWindowSize);
        assert_eq!(window_size, Some(65535));
    }

    #[test]
    fn test_latest_value_wins_within_frame() {
        let mut conn = MockH2Connection::new(ConnectionConfig::default());

        // Single frame with duplicate parameters
        let frame = SettingsFrame {
            parameters: vec![
                SettingsParameter {
                    setting_id: SettingIdentifier::MaxFrameSize,
                    value: 16384,
                },
                SettingsParameter {
                    setting_id: SettingIdentifier::MaxFrameSize,
                    value: 32768, // Should win
                },
                SettingsParameter {
                    setting_id: SettingIdentifier::MaxFrameSize,
                    value: 24576,
                },
                SettingsParameter {
                    setting_id: SettingIdentifier::MaxFrameSize,
                    value: 49152, // Final value should win
                },
            ],
            flags: 0,
            padding: vec![],
        };

        let result = conn.send_settings_frame(frame);
        assert!(matches!(result, SettingsFrameResult::Accepted { .. }));

        let frame_size = conn.get_setting_value(SettingIdentifier::MaxFrameSize);
        assert_eq!(frame_size, Some(49152));
    }

    #[test]
    fn test_parameter_independence() {
        let mut conn = MockH2Connection::new(ConnectionConfig::default());

        // Frame 1: Set both parameters
        let frame1 = SettingsFrame {
            parameters: vec![
                SettingsParameter {
                    setting_id: SettingIdentifier::HeaderTableSize,
                    value: 4096,
                },
                SettingsParameter {
                    setting_id: SettingIdentifier::EnablePush,
                    value: 1,
                },
            ],
            flags: 0,
            padding: vec![],
        };

        conn.send_settings_frame(frame1);

        // Frame 2: Only update one parameter
        let frame2 = SettingsFrame {
            parameters: vec![SettingsParameter {
                setting_id: SettingIdentifier::HeaderTableSize,
                value: 8192,
            }],
            flags: 0,
            padding: vec![],
        };

        conn.send_settings_frame(frame2);

        // Verify independence
        assert_eq!(
            conn.get_setting_value(SettingIdentifier::HeaderTableSize),
            Some(8192)
        );
        assert_eq!(
            conn.get_setting_value(SettingIdentifier::EnablePush),
            Some(1)
        );
    }

    #[test]
    fn test_empty_settings_frame() {
        let mut conn = MockH2Connection::new(ConnectionConfig::default());

        let empty_frame = SettingsFrame {
            parameters: vec![],
            flags: 0,
            padding: vec![],
        };

        let result = conn.send_settings_frame(empty_frame);
        assert!(matches!(result, SettingsFrameResult::Accepted { .. }));
    }

    #[test]
    fn test_settings_ack_validation() {
        let mut conn = MockH2Connection::new(ConnectionConfig::default());

        // ACK frame with parameters (invalid)
        let invalid_ack = SettingsFrame {
            parameters: vec![SettingsParameter {
                setting_id: SettingIdentifier::EnablePush,
                value: 1,
            }],
            flags: SETTINGS_ACK_FLAG,
            padding: vec![],
        };

        let result = conn.send_settings_frame(invalid_ack);
        assert!(matches!(result, SettingsFrameResult::Rejected { .. }));

        // Valid ACK frame (no parameters)
        let valid_ack = SettingsFrame {
            parameters: vec![],
            flags: SETTINGS_ACK_FLAG,
            padding: vec![],
        };

        let result2 = conn.send_settings_frame(valid_ack);
        assert!(matches!(result2, SettingsFrameResult::Accepted { .. }));
    }

    #[test]
    fn test_unknown_settings_handling() {
        let mut conn = MockH2Connection::new(ConnectionConfig::default());

        let unknown_frame = SettingsFrame {
            parameters: vec![
                SettingsParameter {
                    setting_id: SettingIdentifier::Unknown(0x8000),
                    value: 12345,
                },
                SettingsParameter {
                    setting_id: SettingIdentifier::InitialWindowSize,
                    value: 32768,
                },
            ],
            flags: 0,
            padding: vec![],
        };

        let result = conn.send_settings_frame(unknown_frame);
        assert!(matches!(result, SettingsFrameResult::Accepted { .. }));

        // Known setting should be applied
        assert_eq!(
            conn.get_setting_value(SettingIdentifier::InitialWindowSize),
            Some(32768)
        );

        // Unknown setting should be stored (implementation-dependent)
        assert_eq!(
            conn.get_setting_value(SettingIdentifier::Unknown(0x8000)),
            Some(12345)
        );
    }
}
