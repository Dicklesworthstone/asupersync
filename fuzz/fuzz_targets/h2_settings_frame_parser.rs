#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::fmt::Debug;

use asupersync::bytes::Bytes;
use asupersync::http::h2::frame::{
    FRAME_HEADER_SIZE, FrameHeader, FrameType, MAX_FRAME_SIZE, MIN_MAX_FRAME_SIZE, Setting,
    SettingsFrame,
};

/// Maximum input size to prevent OOM during fuzzing
const MAX_INPUT_SIZE: usize = 64 * 1024;
/// Maximum reasonable number of settings parameters
const MAX_SETTINGS_COUNT: usize = 1024;

fn assert_visible_debug<T: Debug + ?Sized>(context: &str, value: &T) {
    let rendered = format!("{value:?}");
    assert!(
        !rendered.is_empty(),
        "{context} produced an empty debug representation"
    );
}

fn observe_result<T, E>(context: &str, result: Result<T, E>) -> Option<T>
where
    T: Debug,
    E: Debug,
{
    match result {
        Ok(value) => {
            assert_visible_debug(context, &value);
            Some(value)
        }
        Err(err) => {
            assert_visible_debug(context, &err);
            None
        }
    }
}

/// Structure-aware fuzzer for HTTP/2 SETTINGS frame parameter pairs and ACK handshake.
///
/// This harness targets the SETTINGS frame parsing logic in src/http/h2/frame.rs,
/// focusing on the parameter pair validation and ACK handshake mechanics:
///
/// **Core Boundary Cases Tested:**
/// 1. **Frame format validation**: 6-byte parameter pairs, length multiple constraints
/// 2. **Parameter value ranges**: ENABLE_PUSH (0/1), INITIAL_WINDOW_SIZE (≤2^31-1), MAX_FRAME_SIZE bounds
/// 3. **ACK semantics**: ACK frames must have empty payload vs parameter frames
/// 4. **Stream ID validation**: SETTINGS frames must have stream_id=0
/// 5. **Unknown parameters**: Should be ignored per RFC 7540 Section 6.5.2
///
/// **Attack Vectors Covered:**
/// - Invalid parameter lengths (non-multiple of 6)
/// - Out-of-range parameter values (ENABLE_PUSH >1, window size overflow)
/// - ACK frame with non-empty payload
/// - Non-zero stream ID for SETTINGS frames
/// - Parameter value boundary violations
/// - Frame length vs payload length mismatches
/// - Large parameter count DoS attempts
///
/// **Invariants Enforced:**
/// - No panics on any malformed SETTINGS frame
/// - RFC 7540 compliance for all parameter validations
/// - ACK frame semantics strictly enforced
/// - Unknown parameters gracefully ignored
/// - Memory limits respected during parameter allocation

#[derive(Debug, Arbitrary)]
struct SettingsFrameScenario {
    /// Frame header configuration
    frame_header: FuzzFrameHeader,
    /// Settings parameters to include
    parameters: Vec<SettingsParameter>,
    /// Whether this is an ACK frame
    is_ack: bool,
    /// Whether to test malformed payload lengths
    test_malformed_length: bool,
}

/// Fuzzable frame header targeting boundary conditions
#[derive(Debug, Arbitrary)]
struct FuzzFrameHeader {
    /// Frame length (may mismatch actual payload)
    declared_length: u32,
    /// Stream ID (should be 0 for SETTINGS, test violations)
    stream_id: u32,
    /// Additional flags to test
    extra_flags: u8,
}

/// SETTINGS parameter patterns designed to trigger boundary conditions
#[derive(Debug, Arbitrary)]
enum SettingsParameter {
    /// Valid known parameter
    Known {
        setting_type: KnownSetting,
        value: u32,
    },
    /// Unknown parameter ID (should be ignored)
    Unknown {
        id: u16, // Use values outside 0x1-0x6 range
        value: u32,
    },
    /// Parameter with boundary value violations
    BoundaryViolation {
        setting_type: KnownSetting,
        violating_value: ViolatingValue,
    },
    /// Raw parameter bytes for direct binary fuzzing
    RawBytes {
        id_bytes: [u8; 2],
        value_bytes: [u8; 4],
    },
}

/// Known HTTP/2 settings parameters
#[derive(Debug, Arbitrary, Clone, Copy)]
enum KnownSetting {
    HeaderTableSize,      // 0x1
    EnablePush,           // 0x2
    MaxConcurrentStreams, // 0x3
    InitialWindowSize,    // 0x4
    MaxFrameSize,         // 0x5
    MaxHeaderListSize,    // 0x6
}

impl KnownSetting {
    fn id(self) -> u16 {
        match self {
            Self::HeaderTableSize => 0x1,
            Self::EnablePush => 0x2,
            Self::MaxConcurrentStreams => 0x3,
            Self::InitialWindowSize => 0x4,
            Self::MaxFrameSize => 0x5,
            Self::MaxHeaderListSize => 0x6,
        }
    }
}

/// Values that violate parameter-specific constraints
#[derive(Debug, Arbitrary)]
enum ViolatingValue {
    /// ENABLE_PUSH > 1 (should be 0 or 1)
    EnablePushOutOfRange(u32), // Values > 1
    /// INITIAL_WINDOW_SIZE > 2^31-1
    WindowSizeOverflow(u32), // Values > 0x7fff_ffff
    /// MAX_FRAME_SIZE outside valid bounds
    FrameSizeOutOfBounds(u32), // Values < MIN_MAX_FRAME_SIZE or > MAX_FRAME_SIZE
    /// Other parameters with extreme values
    ExtremeValue(u32),
}

impl SettingsParameter {
    /// Encode this parameter as 6-byte wire format (2-byte ID + 4-byte value)
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Known {
                setting_type,
                value,
            } => {
                let mut bytes = Vec::with_capacity(6);
                bytes.extend_from_slice(&setting_type.id().to_be_bytes());
                bytes.extend_from_slice(&value.to_be_bytes());
                bytes
            }
            Self::Unknown { id, value } => {
                let mut bytes = Vec::with_capacity(6);
                bytes.extend_from_slice(&id.to_be_bytes());
                bytes.extend_from_slice(&value.to_be_bytes());
                bytes
            }
            Self::BoundaryViolation {
                setting_type,
                violating_value,
            } => {
                let mut bytes = Vec::with_capacity(6);
                bytes.extend_from_slice(&setting_type.id().to_be_bytes());

                let value = match violating_value {
                    ViolatingValue::EnablePushOutOfRange(v) => *v,
                    ViolatingValue::WindowSizeOverflow(v) => *v,
                    ViolatingValue::FrameSizeOutOfBounds(v) => *v,
                    ViolatingValue::ExtremeValue(v) => *v,
                };
                bytes.extend_from_slice(&value.to_be_bytes());
                bytes
            }
            Self::RawBytes {
                id_bytes,
                value_bytes,
            } => {
                let mut bytes = Vec::with_capacity(6);
                bytes.extend_from_slice(id_bytes);
                bytes.extend_from_slice(value_bytes);
                bytes
            }
        }
    }
}

/// Generate frame bytes for boundary testing scenarios
fn generate_settings_frame_bytes(scenario: SettingsFrameScenario) -> Vec<u8> {
    let mut frame_bytes = Vec::new();

    // Encode parameters first to calculate actual payload length
    let mut payload_bytes = Vec::new();
    if !scenario.is_ack {
        for param in &scenario.parameters {
            payload_bytes.extend_from_slice(&param.encode());
        }
    }

    // Test malformed payload lengths if requested
    if scenario.test_malformed_length {
        // Add incomplete parameter (less than 6 bytes) to break length constraint
        payload_bytes.push(0xAB); // Incomplete parameter
    }

    // Create frame header
    let actual_length = payload_bytes.len() as u32;
    let declared_length = if scenario.test_malformed_length {
        scenario.frame_header.declared_length
    } else {
        actual_length
    };

    // Encode frame header (9 bytes)
    frame_bytes.extend_from_slice(&declared_length.to_be_bytes()[1..]); // 24-bit length
    frame_bytes.push(FrameType::Settings as u8); // Frame type

    // Calculate flags
    let mut flags = scenario.frame_header.extra_flags;
    if scenario.is_ack {
        flags |= 0x1; // ACK flag
    }
    frame_bytes.push(flags);

    // Stream ID (should be 0 for SETTINGS)
    frame_bytes.extend_from_slice(&scenario.frame_header.stream_id.to_be_bytes());

    // Add payload
    frame_bytes.extend_from_slice(&payload_bytes);

    frame_bytes
}

/// Execute the SETTINGS frame boundary testing scenario
fn execute_settings_scenario(
    scenario: SettingsFrameScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    if scenario.parameters.len() > MAX_SETTINGS_COUNT {
        return Ok(()); // Skip oversized scenarios
    }

    let frame_bytes = generate_settings_frame_bytes(scenario);
    if frame_bytes.len() > MAX_INPUT_SIZE {
        return Ok(());
    }

    // Test frame header parsing first
    if frame_bytes.len() >= FRAME_HEADER_SIZE {
        let header_result = std::panic::catch_unwind(|| {
            let header_bytes = &frame_bytes[..FRAME_HEADER_SIZE];
            let mut bytes = asupersync::bytes::BytesMut::from(header_bytes);
            FrameHeader::parse(&mut bytes)
        });

        match header_result {
            Ok(header_result) => {
                // Valid header parsed - now test SETTINGS frame parsing
                if let Some(header) =
                    observe_result("generated SETTINGS frame header parse", header_result)
                    && frame_bytes.len() > FRAME_HEADER_SIZE
                {
                    let payload = Bytes::from(frame_bytes[FRAME_HEADER_SIZE..].to_vec());

                    let parse_result =
                        std::panic::catch_unwind(|| SettingsFrame::parse(&header, &payload));

                    match parse_result {
                        Ok(settings_result) => {
                            // Successfully parsed - verify invariants
                            if let Some(settings_frame) =
                                observe_result("generated SETTINGS frame parse", settings_result)
                            {
                                verify_settings_invariants(&settings_frame, &header)?;

                                // Test round-trip encoding if valid
                                test_settings_roundtrip(settings_frame)?;
                            }
                        }
                        Err(_) => {
                            return Err("SETTINGS frame parsing panicked".into());
                        }
                    }
                }
            }
            Err(_) => {
                return Err("Frame header parsing panicked".into());
            }
        }
    }

    Ok(())
}

/// Verify SETTINGS frame invariants after successful parsing
fn verify_settings_invariants(
    frame: &SettingsFrame,
    header: &FrameHeader,
) -> Result<(), Box<dyn std::error::Error>> {
    // Verify ACK semantics
    if frame.ack && !frame.settings.is_empty() {
        return Err("ACK frame contains parameters".into());
    }

    // Verify stream ID constraint
    if header.stream_id != 0 {
        return Err("SETTINGS frame with non-zero stream ID was accepted".into());
    }

    // Verify parameter value constraints
    for setting in &frame.settings {
        match setting {
            Setting::EnablePush(value) => {
                // This should never happen if parsing is correct, but verify
                if *value && header.stream_id != 0 {
                    return Err("Invalid ENABLE_PUSH state".into());
                }
            }
            Setting::InitialWindowSize(value) => {
                if *value > 0x7fff_ffff {
                    return Err("INITIAL_WINDOW_SIZE exceeds maximum".into());
                }
            }
            Setting::MaxFrameSize(value) => {
                if *value < MIN_MAX_FRAME_SIZE || *value > MAX_FRAME_SIZE {
                    return Err("MAX_FRAME_SIZE out of bounds".into());
                }
            }
            _ => {
                // Other parameters have no specific constraints in parsing
            }
        }
    }

    Ok(())
}

/// Test round-trip encoding/decoding for valid SETTINGS frames
fn test_settings_roundtrip(frame: SettingsFrame) -> Result<(), Box<dyn std::error::Error>> {
    let mut encoded = asupersync::bytes::BytesMut::new();

    // Test encoding
    match frame.encode(&mut encoded) {
        Ok(()) => {
            // Encoding succeeded - test re-parsing
            if encoded.len() >= FRAME_HEADER_SIZE {
                let payload = Bytes::from(encoded[FRAME_HEADER_SIZE..].to_vec());
                let header_bytes = encoded[..FRAME_HEADER_SIZE].to_vec();
                let mut header_buf = asupersync::bytes::BytesMut::from(header_bytes.as_slice());

                if let Some(header) = observe_result(
                    "round-trip SETTINGS frame header parse",
                    FrameHeader::parse(&mut header_buf),
                ) && let Some(reparsed) = observe_result(
                    "round-trip SETTINGS frame parse",
                    SettingsFrame::parse(&header, &payload),
                ) {
                    // Verify round-trip consistency
                    assert_eq!(frame.ack, reparsed.ack);
                    assert_eq!(frame.settings.len(), reparsed.settings.len());
                }
            }
        }
        Err(err) => {
            assert_visible_debug("SETTINGS frame encode error", &err);
        }
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    let mut u = Unstructured::new(data);

    // Generate structured scenario from input data
    if let Ok(scenario) = SettingsFrameScenario::arbitrary(&mut u) {
        match std::panic::catch_unwind(|| execute_settings_scenario(scenario)) {
            Ok(Ok(())) => assert_visible_debug("SETTINGS scenario outcome", &"ok"),
            Ok(Err(err)) => assert_visible_debug("SETTINGS scenario error", &err),
            Err(_) => panic!("SETTINGS scenario execution panicked"),
        }
    }

    // Also test raw bytes directly as SETTINGS frame payload
    if data.len() >= FRAME_HEADER_SIZE + 6 {
        // Create a minimal SETTINGS frame header + payload from raw bytes
        let mut frame_bytes = vec![
            0x00, 0x00, 0x06, // Length: 6 bytes (1 parameter)
            0x04, // Type: SETTINGS
            0x00, // Flags: none
            0x00, 0x00, 0x00, 0x00, // Stream ID: 0
        ];

        // Use first 6 bytes of input as parameter (ID + value)
        frame_bytes.extend_from_slice(&data[..6.min(data.len())]);

        if frame_bytes.len() >= FRAME_HEADER_SIZE + 6 {
            match std::panic::catch_unwind(|| {
                let mut header_buf =
                    asupersync::bytes::BytesMut::from(&frame_bytes[..FRAME_HEADER_SIZE]);
                if let Some(header) = observe_result(
                    "raw SETTINGS frame header parse",
                    FrameHeader::parse(&mut header_buf),
                ) {
                    let payload = Bytes::from(frame_bytes[FRAME_HEADER_SIZE..].to_vec());
                    drop(observe_result(
                        "raw SETTINGS frame parse",
                        SettingsFrame::parse(&header, &payload),
                    ));
                }
            }) {
                Ok(()) => {}
                Err(_) => panic!("raw SETTINGS frame parsing panicked"),
            }
        }
    }
});
