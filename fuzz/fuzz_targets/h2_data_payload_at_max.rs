#![no_main]

//! Fuzz target: HTTP/2 DATA frame payload at SETTINGS_MAX_FRAME_SIZE boundary
//!
//! Tests DATA frames with payload sizes exactly equal to SETTINGS_MAX_FRAME_SIZE.
//! Per RFC 7540 §6.5.2, frames at the maximum size should be ACCEPTED (boundary
//! condition, not an error). Tests various MAX_FRAME_SIZE values and validates
//! proper boundary handling.
//!
//! Key behaviors tested:
//! - DATA frames with payload = MAX_FRAME_SIZE are accepted
//! - DATA frames with payload > MAX_FRAME_SIZE are rejected
//! - Proper handling of different MAX_FRAME_SIZE settings (16384..16777215)
//! - Boundary testing around the configured limits
//! - Frame parsing with exact size matches

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame type identifiers
const DATA_TYPE: u8 = 0x0;
const SETTINGS_TYPE: u8 = 0x4;

/// HTTP/2 SETTINGS parameter identifiers (RFC 7540 §6.5.2)
const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// HTTP/2 frame flags
const END_STREAM_FLAG: u8 = 0x1;
const PADDED_FLAG: u8 = 0x8;
const SETTINGS_ACK_FLAG: u8 = 0x1;

/// RFC 7540 §6.5.2: SETTINGS_MAX_FRAME_SIZE valid range
const MIN_MAX_FRAME_SIZE: u32 = 16384; // 2^14
const MAX_MAX_FRAME_SIZE: u32 = 16777215; // 2^24 - 1

/// Default SETTINGS_MAX_FRAME_SIZE value
const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;

/// Mock parser for HTTP/2 frame size validation
#[derive(Debug)]
struct MockH2MaxFrameSizeParser {
    max_frame_size: u32,
    connection_established: bool,
}

/// Result types for parsing
#[derive(Debug, PartialEq)]
enum ParseResult {
    /// Settings frame processed successfully
    SettingsProcessed { max_frame_size: u32 },
    /// DATA frame processed successfully
    DataFrameProcessed { stream_id: u32, payload_size: u32 },
    /// Frame size error
    FrameSizeError(String),
    /// Protocol error
    ProtocolError(String),
    /// Frame processed (other frame types)
    FrameProcessed,
}

/// Input for fuzz testing
#[derive(Debug, Arbitrary)]
struct H2DataPayloadMaxInput {
    /// Initial MAX_FRAME_SIZE setting (None = use default)
    initial_max_frame_size: Option<u32>,

    /// Test cases to execute
    test_cases: Vec<FrameSizeTest>,
}

#[derive(Debug, Arbitrary)]
struct FrameSizeTest {
    /// The payload size to test
    payload_size: u32,

    /// Stream ID for the DATA frame (must be > 0)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(1..=u32::MAX))]
    stream_id: u32,

    /// Whether to use the PADDED flag
    padded: bool,

    /// Padding size if padded (0..255)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=255))]
    padding_size: u8,

    /// Whether to set END_STREAM flag
    end_stream: bool,

    /// Update MAX_FRAME_SIZE before this test (None = no update)
    update_max_frame_size: Option<u32>,
}

impl MockH2MaxFrameSizeParser {
    fn new() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            connection_established: false,
        }
    }

    /// Process SETTINGS frame with MAX_FRAME_SIZE
    fn process_settings(&mut self, settings: &[(u16, u32)]) -> Result<ParseResult, String> {
        for &(setting_id, value) in settings {
            match setting_id {
                SETTINGS_MAX_FRAME_SIZE => {
                    // RFC 7540 §6.5.2: Valid range is 2^14 to 2^24-1
                    if value < MIN_MAX_FRAME_SIZE || value > MAX_MAX_FRAME_SIZE {
                        return Err(format!(
                            "PROTOCOL_ERROR: SETTINGS_MAX_FRAME_SIZE {} out of valid range [{}, {}]",
                            value, MIN_MAX_FRAME_SIZE, MAX_MAX_FRAME_SIZE
                        ));
                    }

                    self.max_frame_size = value;
                    return Ok(ParseResult::SettingsProcessed {
                        max_frame_size: value,
                    });
                }
                SETTINGS_HEADER_TABLE_SIZE
                | SETTINGS_ENABLE_PUSH
                | SETTINGS_MAX_CONCURRENT_STREAMS
                | SETTINGS_INITIAL_WINDOW_SIZE
                | SETTINGS_MAX_HEADER_LIST_SIZE => {
                    // Other settings - ignore for this test
                }
                _ => {
                    // Unknown setting - ignore per RFC 7540 §6.5
                }
            }
        }
        Ok(ParseResult::FrameProcessed)
    }

    /// Process DATA frame with size validation
    fn process_data_frame(
        &mut self,
        stream_id: u32,
        payload_size: u32,
        padded: bool,
        padding_size: u8,
        end_stream: bool,
    ) -> ParseResult {
        // Stream ID 0 is invalid for DATA frames
        if stream_id == 0 {
            return ParseResult::ProtocolError("DATA frame with stream_id=0".to_string());
        }

        // Calculate total frame payload size
        let total_payload_size = if padded {
            // Padded DATA frame: 1 byte for pad_length + payload + padding
            1 + payload_size + padding_size as u32
        } else {
            payload_size
        };

        // Validate against current MAX_FRAME_SIZE setting
        if total_payload_size > self.max_frame_size {
            return ParseResult::FrameSizeError(format!(
                "FRAME_SIZE_ERROR: DATA frame payload {} exceeds MAX_FRAME_SIZE {}",
                total_payload_size, self.max_frame_size
            ));
        }

        // If padded, validate padding
        if padded {
            if padding_size as u32 >= payload_size && payload_size > 0 {
                return ParseResult::ProtocolError(
                    "PROTOCOL_ERROR: Padding larger than payload".to_string(),
                );
            }
        }

        ParseResult::DataFrameProcessed {
            stream_id,
            payload_size: total_payload_size,
        }
    }
}

/// Encode DATA frame
fn encode_data_frame(
    stream_id: u32,
    payload: &[u8],
    padded: bool,
    padding_size: u8,
    end_stream: bool,
) -> Vec<u8> {
    let mut frame = Vec::new();
    let mut flags = 0u8;

    if end_stream {
        flags |= END_STREAM_FLAG;
    }
    if padded {
        flags |= PADDED_FLAG;
    }

    let total_payload_len = if padded {
        1 + payload.len() + padding_size as usize // pad_length + payload + padding
    } else {
        payload.len()
    };

    // Frame header (9 bytes)
    frame.extend_from_slice(&(total_payload_len as u32).to_be_bytes()[1..4]); // Length (24 bits)
    frame.push(DATA_TYPE); // Type
    frame.push(flags); // Flags
    frame.extend_from_slice(&stream_id.to_be_bytes()); // Stream ID

    // Payload
    if padded {
        frame.push(padding_size); // Pad length
    }
    frame.extend_from_slice(payload); // Data payload
    if padded {
        frame.extend(vec![0u8; padding_size as usize]); // Padding bytes
    }

    frame
}

/// Encode SETTINGS frame
fn encode_settings_frame(settings: &[(u16, u32)]) -> Vec<u8> {
    let payload_len = settings.len() * 6; // Each setting is 6 bytes
    let mut frame = Vec::new();

    // Frame header (9 bytes)
    frame.extend_from_slice(&(payload_len as u32).to_be_bytes()[1..4]); // Length (24 bits)
    frame.push(SETTINGS_TYPE); // Type
    frame.push(0); // Flags (no ACK)
    frame.extend_from_slice(&0u32.to_be_bytes()); // Stream ID (0 for SETTINGS)

    // Settings payload
    for &(setting_id, value) in settings {
        frame.extend_from_slice(&setting_id.to_be_bytes());
        frame.extend_from_slice(&value.to_be_bytes());
    }

    frame
}

/// Process the input through our mock parser
fn process_input(input: &H2DataPayloadMaxInput) -> Vec<ParseResult> {
    let mut parser = MockH2MaxFrameSizeParser::new();
    let mut results = Vec::new();

    // Set initial MAX_FRAME_SIZE if specified
    if let Some(initial_size) = input.initial_max_frame_size {
        let settings = vec![(SETTINGS_MAX_FRAME_SIZE, initial_size)];
        match parser.process_settings(&settings) {
            Ok(result) => results.push(result),
            Err(e) => results.push(ParseResult::ProtocolError(e)),
        }
    }

    // Process test cases
    for test in &input.test_cases {
        // Update MAX_FRAME_SIZE if requested
        if let Some(new_size) = test.update_max_frame_size {
            let settings = vec![(SETTINGS_MAX_FRAME_SIZE, new_size)];
            match parser.process_settings(&settings) {
                Ok(result) => results.push(result),
                Err(e) => results.push(ParseResult::ProtocolError(e)),
            }
        }

        // Test the DATA frame
        let result = parser.process_data_frame(
            test.stream_id,
            test.payload_size,
            test.padded,
            test.padding_size,
            test.end_stream,
        );
        results.push(result);
    }

    results
}

fuzz_target!(|input: H2DataPayloadMaxInput| {
    // Skip empty inputs
    if input.test_cases.is_empty() {
        return;
    }

    let results = process_input(&input);

    // Test key invariants
    let mut current_max_frame_size = input
        .initial_max_frame_size
        .unwrap_or(DEFAULT_MAX_FRAME_SIZE);

    for (i, test) in input.test_cases.iter().enumerate() {
        // Update current max frame size if changed
        if let Some(new_size) = test.update_max_frame_size {
            if new_size >= MIN_MAX_FRAME_SIZE && new_size <= MAX_MAX_FRAME_SIZE {
                current_max_frame_size = new_size;
            }
        }

        // Find the corresponding result (accounting for possible SETTINGS updates)
        let result_index = if test.update_max_frame_size.is_some() {
            i * 2 + 1 // Skip the SETTINGS result
        } else {
            i
        } + if input.initial_max_frame_size.is_some() {
            1
        } else {
            0
        };

        if let Some(result) = results.get(result_index) {
            // Calculate expected total payload size
            let total_payload_size = if test.padded {
                1 + test.payload_size + test.padding_size as u32
            } else {
                test.payload_size
            };

            match result {
                ParseResult::DataFrameProcessed { payload_size, .. } => {
                    // Frame was accepted - verify it was within limits
                    assert!(
                        total_payload_size <= current_max_frame_size,
                        "Parser accepted frame {} bytes > MAX_FRAME_SIZE {}",
                        total_payload_size,
                        current_max_frame_size
                    );
                    assert_eq!(*payload_size, total_payload_size);
                }
                ParseResult::FrameSizeError(_) => {
                    // Frame was rejected - verify it exceeded limits
                    assert!(
                        total_payload_size > current_max_frame_size,
                        "Parser rejected frame {} bytes <= MAX_FRAME_SIZE {}",
                        total_payload_size,
                        current_max_frame_size
                    );
                }
                ParseResult::ProtocolError(_) => {
                    // Protocol errors are acceptable for malformed frames
                }
                _ => {
                    // Other results are unexpected for DATA frames
                    panic!("Unexpected result for DATA frame: {:?}", result);
                }
            }
        }
    }

    // Test specific boundary conditions
    let boundary_tests = [
        (DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE), // Exactly at default limit
        (DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE - 1), // Just below default limit
        (DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE + 1), // Just above default limit
        (32768, 32768),                                   // Exactly at custom limit
        (32768, 32767),                                   // Just below custom limit
        (32768, 32769),                                   // Just above custom limit
        (MAX_MAX_FRAME_SIZE, MAX_MAX_FRAME_SIZE),         // At maximum possible limit
        (MIN_MAX_FRAME_SIZE, MIN_MAX_FRAME_SIZE),         // At minimum possible limit
    ];

    for (max_frame_size, payload_size) in boundary_tests {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Set MAX_FRAME_SIZE
        let settings = vec![(SETTINGS_MAX_FRAME_SIZE, max_frame_size)];
        if parser.process_settings(&settings).is_err() {
            continue; // Skip invalid MAX_FRAME_SIZE values
        }

        // Test DATA frame
        let result = parser.process_data_frame(1, payload_size, false, 0, false);

        if payload_size <= max_frame_size {
            // Should be accepted
            assert!(
                matches!(result, ParseResult::DataFrameProcessed { .. }),
                "Frame with payload {} should be accepted (limit {}), got: {:?}",
                payload_size,
                max_frame_size,
                result
            );
        } else {
            // Should be rejected
            assert!(
                matches!(result, ParseResult::FrameSizeError(_)),
                "Frame with payload {} should be rejected (limit {}), got: {:?}",
                payload_size,
                max_frame_size,
                result
            );
        }
    }

    // Test padded frame boundary conditions
    let padded_tests = [
        (16384, 16383, 0, true),   // Padded: 1 + 16383 + 0 = 16384 (exactly at limit)
        (16384, 16382, 1, true),   // Padded: 1 + 16382 + 1 = 16384 (exactly at limit)
        (16384, 16384, 0, false),  // Padded: 1 + 16384 + 0 = 16385 (exceeds limit)
        (16384, 16300, 80, true),  // Padded: 1 + 16300 + 80 = 16381 (within limit)
        (16384, 16300, 85, false), // Padded: 1 + 16300 + 85 = 16386 (exceeds limit)
    ];

    for (max_frame_size, payload_size, padding_size, should_pass) in padded_tests {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Set MAX_FRAME_SIZE
        let settings = vec![(SETTINGS_MAX_FRAME_SIZE, max_frame_size)];
        parser.process_settings(&settings).unwrap();

        // Test padded DATA frame
        let result = parser.process_data_frame(1, payload_size, true, padding_size, false);

        if should_pass {
            assert!(
                matches!(result, ParseResult::DataFrameProcessed { .. }),
                "Padded frame (payload={}, padding={}) should be accepted (limit={}), got: {:?}",
                payload_size,
                padding_size,
                max_frame_size,
                result
            );
        } else {
            assert!(
                matches!(result, ParseResult::FrameSizeError(_)),
                "Padded frame (payload={}, padding={}) should be rejected (limit={}), got: {:?}",
                payload_size,
                padding_size,
                max_frame_size,
                result
            );
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_frame_at_default_max() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Test DATA frame with payload exactly at default MAX_FRAME_SIZE
        let result = parser.process_data_frame(1, DEFAULT_MAX_FRAME_SIZE, false, 0, false);

        match result {
            ParseResult::DataFrameProcessed { payload_size, .. } => {
                assert_eq!(payload_size, DEFAULT_MAX_FRAME_SIZE);
            }
            other => panic!("Expected data frame processed, got: {:?}", other),
        }
    }

    #[test]
    fn test_data_frame_above_max() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Test DATA frame with payload above MAX_FRAME_SIZE
        let result = parser.process_data_frame(1, DEFAULT_MAX_FRAME_SIZE + 1, false, 0, false);

        match result {
            ParseResult::FrameSizeError(msg) => {
                assert!(msg.contains("FRAME_SIZE_ERROR"));
                assert!(msg.contains(&(DEFAULT_MAX_FRAME_SIZE + 1).to_string()));
            }
            other => panic!("Expected frame size error, got: {:?}", other),
        }
    }

    #[test]
    fn test_custom_max_frame_size() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Set custom MAX_FRAME_SIZE
        let custom_size = 32768;
        let settings = vec![(SETTINGS_MAX_FRAME_SIZE, custom_size)];
        parser.process_settings(&settings).unwrap();

        // Test frame exactly at custom limit
        let result = parser.process_data_frame(1, custom_size, false, 0, false);
        assert!(matches!(result, ParseResult::DataFrameProcessed { .. }));

        // Test frame above custom limit
        let result = parser.process_data_frame(1, custom_size + 1, false, 0, false);
        assert!(matches!(result, ParseResult::FrameSizeError(_)));
    }

    #[test]
    fn test_padded_data_frame_boundary() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Test padded DATA frame at boundary
        // 1 (pad_length) + 16382 (payload) + 1 (padding) = 16384 (exactly at limit)
        let result = parser.process_data_frame(1, 16382, true, 1, false);

        match result {
            ParseResult::DataFrameProcessed { payload_size, .. } => {
                assert_eq!(payload_size, 16384); // Total frame payload size
            }
            other => panic!("Expected padded frame accepted, got: {:?}", other),
        }

        // Test padded DATA frame over boundary
        // 1 (pad_length) + 16383 (payload) + 1 (padding) = 16385 (exceeds limit)
        let result = parser.process_data_frame(1, 16383, true, 1, false);
        assert!(matches!(result, ParseResult::FrameSizeError(_)));
    }

    #[test]
    fn test_invalid_max_frame_size_settings() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Test below minimum
        let settings = vec![(SETTINGS_MAX_FRAME_SIZE, MIN_MAX_FRAME_SIZE - 1)];
        let result = parser.process_settings(&settings);
        assert!(result.is_err());

        // Test above maximum
        let settings = vec![(SETTINGS_MAX_FRAME_SIZE, MAX_MAX_FRAME_SIZE + 1)];
        let result = parser.process_settings(&settings);
        assert!(result.is_err());

        // Test valid boundaries
        let settings = vec![(SETTINGS_MAX_FRAME_SIZE, MIN_MAX_FRAME_SIZE)];
        assert!(parser.process_settings(&settings).is_ok());

        let settings = vec![(SETTINGS_MAX_FRAME_SIZE, MAX_MAX_FRAME_SIZE)];
        assert!(parser.process_settings(&settings).is_ok());
    }

    #[test]
    fn test_zero_payload_data_frame() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Zero-length DATA frame should be accepted
        let result = parser.process_data_frame(1, 0, false, 0, false);
        match result {
            ParseResult::DataFrameProcessed { payload_size, .. } => {
                assert_eq!(payload_size, 0);
            }
            other => panic!("Expected zero-length frame accepted, got: {:?}", other),
        }
    }

    #[test]
    fn test_data_frame_encoding() {
        let payload = vec![0x42; 1000];
        let frame = encode_data_frame(1, &payload, false, 0, true);

        // Check frame header
        assert_eq!(frame[3], DATA_TYPE);
        assert_eq!(frame[4], END_STREAM_FLAG);
        assert_eq!(
            u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]),
            1
        );

        // Check payload
        assert_eq!(&frame[9..], &payload);
    }

    #[test]
    fn test_padded_data_frame_encoding() {
        let payload = vec![0x42; 100];
        let padding_size = 10;
        let frame = encode_data_frame(1, &payload, true, padding_size, false);

        // Check total frame size
        let expected_total = 1 + payload.len() + padding_size as usize;
        assert_eq!(frame.len() - 9, expected_total); // Subtract header size

        // Check pad length byte
        assert_eq!(frame[9], padding_size);

        // Check payload
        assert_eq!(&frame[10..10 + payload.len()], &payload);

        // Check padding (should be zeros)
        for &byte in &frame[10 + payload.len()..] {
            assert_eq!(byte, 0);
        }
    }

    #[test]
    fn test_maximum_possible_frame_size() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Set to maximum possible MAX_FRAME_SIZE
        let settings = vec![(SETTINGS_MAX_FRAME_SIZE, MAX_MAX_FRAME_SIZE)];
        parser.process_settings(&settings).unwrap();

        // Test frame at maximum limit
        let result = parser.process_data_frame(1, MAX_MAX_FRAME_SIZE, false, 0, false);
        assert!(matches!(result, ParseResult::DataFrameProcessed { .. }));

        // Test frame above maximum limit (should be impossible in practice)
        let result = parser.process_data_frame(1, MAX_MAX_FRAME_SIZE + 1, false, 0, false);
        assert!(matches!(result, ParseResult::FrameSizeError(_)));
    }
}
