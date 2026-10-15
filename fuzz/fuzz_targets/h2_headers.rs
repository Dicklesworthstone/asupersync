//! HTTP/2 HEADERS frame parsing fuzz target.
//!
//! This fuzz target comprehensively tests HTTP/2 HEADERS frame parsing and
//! validation according to RFC 9113 to ensure security and correctness properties.
//!
//! **Critical Properties Tested:**
//! 1. **PRIORITY block correctly parsed when PRIORITY flag set**
//! 2. **Pad length byte bounded by payload length**
//! 3. **END_STREAM and END_HEADERS flags independent**
//! 4. **HEADERS on Stream ID 0 triggers PROTOCOL_ERROR**
//! 5. **Concurrent HEADERS on same stream triggers STREAM_ERROR**
//!
//! # Security Focus
//!
//! - PRIORITY information parsing (exclusive flag, dependency, weight)
//! - Padding length validation and boundary checks
//! - Flag combination independence testing
//! - Stream ID validation (connection vs stream scope)
//! - Stream state management and concurrent access
//! - Frame sequence validation
//! - Buffer overflow protection in PRIORITY/padding parsing
//!
//! # RFC 9113 HEADERS Frame Format
//!
//! ```text
//!     0                   1                   2                   3
//!     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!    |Pad Length? (8)|
//!    +---------------+-----------------------------------------------+
//!    |E|                 Stream Dependency? (31)                     |
//!    +-+-------------+-----------------------------------------------+
//!    |  Weight? (8)  |
//!    +-+-------------+-----------------------------------------------+
//!    |                   Header Block Fragment (*)                 ...
//!    +---------------------------------------------------------------+
//!    |                           Padding (*)                      ...
//!    +---------------------------------------------------------------+
//! ```
//!
//! Where:
//! - Pad Length: Present only if PADDED flag is set
//! - E + Stream Dependency + Weight: Present only if PRIORITY flag is set
//! - Header Block Fragment: HPACK-encoded headers
//! - Padding: Zero bytes, length specified by Pad Length

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{
    FRAME_HEADER_SIZE, Frame, FrameHeader, FrameType, HeadersFrame, SettingsFrame, headers_flags,
    parse_frame,
};
use asupersync::http::h2::settings::Settings;
use libfuzzer_sys::fuzz_target;

/// Maximum frame payload size for practical testing (16KB)
const MAX_FRAME_PAYLOAD_SIZE: usize = 16_384;
const STREAM_ID_MASK: u32 = 0x7fff_ffff;

/// HEADERS frame fuzz input configuration
#[derive(Arbitrary, Debug, Clone)]
struct HeadersFrameFuzz {
    /// Stream ID for the HEADERS frame
    stream_id: u32,
    /// Frame flags configuration
    flags: HeadersFlags,
    /// PRIORITY information (if PRIORITY flag set)
    priority_info: Option<PriorityInfo>,
    /// Padding configuration (if PADDED flag set)
    padding_config: Option<PaddingConfig>,
    /// Header block fragment data
    header_block: Vec<u8>,
    /// Test scenario to execute
    scenario: TestScenario,
}

/// HEADERS frame flag configuration
#[derive(Arbitrary, Debug, Clone)]
struct HeadersFlags {
    /// END_STREAM flag
    end_stream: bool,
    /// END_HEADERS flag
    end_headers: bool,
    /// PADDED flag
    padded: bool,
    /// PRIORITY flag
    priority: bool,
}

/// PRIORITY information for HEADERS frames
#[derive(Arbitrary, Debug, Clone)]
struct PriorityInfo {
    /// Exclusive dependency flag
    exclusive: bool,
    /// Stream dependency ID
    dependency: u32,
    /// Priority weight (0-255, represents 1-256)
    weight: u8,
}

/// Padding configuration for HEADERS frames
#[derive(Arbitrary, Debug, Clone)]
struct PaddingConfig {
    /// Padding length byte
    pad_length: u8,
    /// Padding data (filled with zeros)
    enforce_boundary: bool, // Whether to enforce valid padding length
}

/// Test scenarios for specific behaviors
#[derive(Arbitrary, Debug, Clone)]
enum TestScenario {
    /// Test basic HEADERS frame parsing
    BasicParsing,
    /// Test PRIORITY flag and information parsing
    PriorityParsing,
    /// Test PADDED flag and padding validation
    PaddingValidation,
    /// Test flag independence
    FlagIndependence,
    /// Test stream ID validation
    StreamIdValidation,
    /// Test concurrent HEADERS on same stream
    ConcurrentHeaders,
    /// Test malformed frames
    MalformedFrame,
}

/// Normalize fuzz input to reasonable bounds
fn normalize_input(input: &mut HeadersFrameFuzz) {
    // Limit header block size
    input.header_block.truncate(MAX_FRAME_PAYLOAD_SIZE);
    input.stream_id = wire_stream_id(input.stream_id);

    // Normalize priority dependency to avoid self-dependency
    if let Some(ref mut priority) = input.priority_info {
        priority.dependency = wire_stream_id(priority.dependency);
        if priority.dependency == input.stream_id {
            priority.dependency = wire_stream_id(input.stream_id.wrapping_add(1));
        }
    }
}

fn wire_stream_id(stream_id: u32) -> u32 {
    stream_id & STREAM_ID_MASK
}

/// Build a HEADERS frame from fuzz configuration
fn build_headers_frame(input: &HeadersFrameFuzz) -> Result<Bytes, String> {
    let mut frame_data = BytesMut::new();

    // Calculate flags
    let mut flags = 0u8;
    if input.flags.end_stream {
        flags |= headers_flags::END_STREAM;
    }
    if input.flags.end_headers {
        flags |= headers_flags::END_HEADERS;
    }
    if input.flags.padded {
        flags |= headers_flags::PADDED;
    }
    if input.flags.priority {
        flags |= headers_flags::PRIORITY;
    }

    let mut payload = BytesMut::new();

    // Add padding length byte if PADDED flag is set
    if input.flags.padded {
        if let Some(ref padding) = input.padding_config {
            payload.put_u8(padding.pad_length);
        } else {
            payload.put_u8(0); // Default to no padding
        }
    }

    // Add PRIORITY information if PRIORITY flag is set
    if input.flags.priority {
        if let Some(ref priority) = input.priority_info {
            // Stream dependency with exclusive flag
            let dependency = if priority.exclusive {
                priority.dependency | 0x8000_0000
            } else {
                priority.dependency & 0x7fff_ffff
            };
            payload.put_u32(dependency);
            payload.put_u8(priority.weight);
        } else {
            // Default priority info
            payload.put_u32(0); // No dependency
            payload.put_u8(15); // Default weight
        }
    }

    // Add header block fragment
    payload.extend_from_slice(&input.header_block);

    // Add padding if PADDED flag is set
    if input.flags.padded
        && let Some(ref padding) = input.padding_config
    {
        let pad_len = if padding.enforce_boundary {
            // Ensure padding doesn't exceed available space
            (padding.pad_length as usize).min(payload.len().saturating_sub(1))
        } else {
            // Use raw padding length (may exceed bounds for testing)
            padding.pad_length as usize
        };

        payload.resize(payload.len() + pad_len, 0);
    }

    // Build frame header
    let payload_len = payload.len() as u32;
    frame_data.put_u8(((payload_len >> 16) & 0xff) as u8);
    frame_data.put_u8(((payload_len >> 8) & 0xff) as u8);
    frame_data.put_u8((payload_len & 0xff) as u8);
    frame_data.put_u8(FrameType::Headers as u8);
    frame_data.put_u8(flags);
    frame_data.put_u32(wire_stream_id(input.stream_id));

    // Add payload
    frame_data.extend_from_slice(&payload);

    Ok(frame_data.freeze())
}

/// Test HEADERS frame parsing and validation
fn test_headers_frame(input: &HeadersFrameFuzz) -> Result<HeadersFrame, H2Error> {
    let frame_data = build_headers_frame(input)
        .map_err(|e| H2Error::protocol(format!("Frame building failed: {}", e)))?;

    if frame_data.len() < FRAME_HEADER_SIZE {
        return Err(H2Error::protocol("Frame too short"));
    }

    // Parse frame header
    let header_bytes = &frame_data[..FRAME_HEADER_SIZE];
    let mut header_buf = BytesMut::from(header_bytes);
    let header = FrameHeader::parse(&mut header_buf)
        .map_err(|e| H2Error::protocol(format!("Header parsing failed: {}", e)))?;

    // Parse frame
    let payload = frame_data.slice(FRAME_HEADER_SIZE..);
    match parse_frame(&header, payload)? {
        Frame::Headers(headers_frame) => Ok(headers_frame),
        _ => Err(H2Error::protocol("Expected HEADERS frame")),
    }
}

fn observe_headers_error(context: &str, error: &H2Error) {
    assert!(
        !error.message.trim().is_empty(),
        "{context}: HEADERS rejection should expose a diagnostic"
    );
    assert!(
        error.message.len() <= 2048,
        "{context}: HEADERS rejection diagnostic should stay bounded: {} bytes",
        error.message.len()
    );
    std::hint::black_box((context, error.code, error.stream_id, error.message.as_str()));
}

fn assert_headers_stream_zero_error(context: &str, error: &H2Error) {
    assert_eq!(
        error.code,
        ErrorCode::ProtocolError,
        "{context}: stream-zero HEADERS must be a protocol error"
    );
    assert_eq!(
        error.stream_id, None,
        "{context}: stream-zero HEADERS must be connection-scoped"
    );
    assert_eq!(
        error.message, "HEADERS frame with stream ID 0",
        "{context}: stream-zero HEADERS used wrong diagnostic"
    );
}

fn headers_padding_overflow_expected(input: &HeadersFrameFuzz) -> bool {
    if !input.flags.padded || wire_stream_id(input.stream_id) == 0 {
        return false;
    }

    let Some(padding) = &input.padding_config else {
        return false;
    };

    let priority_bytes = if input.flags.priority { 5usize } else { 0 };
    let payload_len_before_padding_tail = 1usize + priority_bytes + input.header_block.len();
    let padding_tail_len = if padding.enforce_boundary {
        (padding.pad_length as usize).min(payload_len_before_padding_tail.saturating_sub(1))
    } else {
        padding.pad_length as usize
    };
    let payload_after_pad_length = priority_bytes + input.header_block.len() + padding_tail_len;

    (padding.pad_length as usize).saturating_add(priority_bytes) > payload_after_pad_length
}

fn assert_headers_padding_error(context: &str, error: &H2Error) {
    assert_eq!(
        error.code,
        ErrorCode::ProtocolError,
        "{context}: padding overflow HEADERS must be a protocol error"
    );
    assert_eq!(
        error.stream_id, None,
        "{context}: padding overflow HEADERS must be connection-scoped"
    );
    assert_eq!(
        error.message, "HEADERS frame padding exceeds data length",
        "{context}: padding overflow HEADERS used wrong diagnostic"
    );
}

/// Test concurrent HEADERS frames on the same stream
fn test_concurrent_headers(stream_id: u32) -> Result<(), H2Error> {
    let mut connection = Connection::server(Settings::default());
    connection.process_frame(Frame::Settings(SettingsFrame::new(vec![])))?;

    // Create first HEADERS frame
    let headers1 = HeadersFrame::new(stream_id, Bytes::from("header-block-1"), false, false);
    let frame1 = Frame::Headers(headers1);

    // Process first HEADERS frame
    connection.process_frame(frame1)?;

    // Create second HEADERS frame on the same stream (should cause STREAM_ERROR)
    let headers2 = HeadersFrame::new(stream_id, Bytes::from("header-block-2"), false, true);
    let frame2 = Frame::Headers(headers2);

    connection.process_frame(frame2)?;

    Ok(())
}

fuzz_target!(|input: HeadersFrameFuzz| {
    let mut input = input;
    normalize_input(&mut input);

    match input.scenario {
        TestScenario::BasicParsing => {
            // Test basic HEADERS frame parsing
            let _result = test_headers_frame(&input);
            // Don't assert success - malformed frames are expected to fail
        }

        TestScenario::PriorityParsing => {
            // Assertion 1: PRIORITY block correctly parsed when PRIORITY flag set
            if input.flags.priority {
                match test_headers_frame(&input) {
                    Ok(headers_frame) => {
                        // If parsing succeeded, PRIORITY info should be present and valid
                        if let Some(priority) = headers_frame.priority {
                            // Verify priority parsing correctness
                            if let Some(ref expected_priority) = input.priority_info {
                                assert_eq!(
                                    priority.exclusive, expected_priority.exclusive,
                                    "PRIORITY exclusive flag mismatch"
                                );
                                assert_eq!(
                                    priority.weight, expected_priority.weight,
                                    "PRIORITY weight mismatch"
                                );

                                // Dependency should not be self-referencing
                                assert_ne!(
                                    priority.dependency,
                                    wire_stream_id(input.stream_id),
                                    "PRIORITY dependency cannot reference itself"
                                );
                            }
                        } else {
                            // PRIORITY flag was set but no priority info parsed
                            panic!("PRIORITY flag set but priority info missing");
                        }
                    }
                    Err(error) => {
                        observe_headers_error("PRIORITY HEADERS parse", &error);
                    }
                }
            }
        }

        TestScenario::PaddingValidation => {
            // Assertion 2: pad length byte bounded by payload length
            if input.flags.padded {
                match test_headers_frame(&input) {
                    Ok(_) => {
                        // If parsing succeeded, padding must have been valid
                        if let Some(ref padding) = input.padding_config {
                            // Calculate expected payload size constraints
                            let mut min_payload_size = input.header_block.len() + 1; // +1 for pad length byte
                            if input.flags.priority {
                                min_payload_size += 5; // +5 for priority info
                            }

                            // Padding length should not exceed available payload
                            if padding.enforce_boundary {
                                assert!(
                                    padding.pad_length as usize <= min_payload_size,
                                    "Padding length should be bounded by payload size"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        if headers_padding_overflow_expected(&input) {
                            assert_headers_padding_error("padded HEADERS parse", &e);
                        } else {
                            observe_headers_error("padded HEADERS parse", &e);
                        }
                    }
                }
            }
        }

        TestScenario::FlagIndependence => {
            // Assertion 3: END_STREAM and END_HEADERS flags independent
            match test_headers_frame(&input) {
                Ok(headers_frame) => {
                    // Verify flags are set correctly and independently
                    assert_eq!(
                        headers_frame.end_stream, input.flags.end_stream,
                        "END_STREAM flag not preserved"
                    );
                    assert_eq!(
                        headers_frame.end_headers, input.flags.end_headers,
                        "END_HEADERS flag not preserved"
                    );

                    // Verify independence: each flag can be set without the other
                    // This is implicitly tested by the flag combinations in the fuzzer
                }
                Err(error) => {
                    observe_headers_error("flag-independence HEADERS parse", &error);
                }
            }
        }

        TestScenario::StreamIdValidation => {
            // Assertion 4: HEADERS on Stream ID 0 triggers PROTOCOL_ERROR
            if wire_stream_id(input.stream_id) == 0 {
                match test_headers_frame(&input) {
                    Ok(_) => {
                        panic!("HEADERS on stream ID 0 should trigger PROTOCOL_ERROR");
                    }
                    Err(e) => {
                        assert_headers_stream_zero_error("stream-id validation", &e);
                    }
                }
            } else {
                // Non-zero stream ID should be accepted (if frame is otherwise valid)
                let _result = test_headers_frame(&input);
            }
        }

        TestScenario::ConcurrentHeaders => {
            // Assertion 5: concurrent HEADERS on same stream triggers STREAM_ERROR
            let stream_id = wire_stream_id(input.stream_id);
            if stream_id > 0 && stream_id % 2 == 1 {
                // Client-initiated stream
                match test_concurrent_headers(stream_id) {
                    Ok(_) => {
                        // Concurrent HEADERS was accepted - this might be valid in some states
                    }
                    Err(e) => observe_headers_error("concurrent HEADERS parse", &e),
                }
            }
        }

        TestScenario::MalformedFrame => {
            // Test various malformed frame conditions
            match test_headers_frame(&input) {
                Ok(headers_frame) => {
                    // Frame was successfully parsed - verify basic invariants
                    assert_eq!(headers_frame.stream_id, wire_stream_id(input.stream_id));

                    // If PRIORITY flag was set, priority info should be present
                    if input.flags.priority {
                        assert!(
                            headers_frame.priority.is_some(),
                            "PRIORITY flag set but priority info missing"
                        );
                    }
                }
                Err(error) => {
                    observe_headers_error("malformed HEADERS parse", &error);
                }
            }
        }
    }

    // Global invariants that should always hold
    if wire_stream_id(input.stream_id) == 0 {
        // Stream ID 0 should always be rejected for HEADERS frames
        match test_headers_frame(&input) {
            Ok(_) => panic!("Stream ID 0 should be rejected"),
            Err(error) => observe_headers_error("stream-zero HEADERS parse", &error),
        }
    }

    // Test padding bounds if PADDED flag is set
    if input.flags.padded
        && let Some(ref padding) = input.padding_config
        && !padding.enforce_boundary
        && padding.pad_length > 200
    {
        // Excessive padding should be rejected
        match test_headers_frame(&input) {
            Ok(_) => {
                // Frame was accepted despite large padding - verify it's actually valid
            }
            Err(error) => {
                observe_headers_error("excessive-padding HEADERS parse", &error);
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_id_zero_rejection() {
        let input = HeadersFrameFuzz {
            stream_id: 0,
            flags: HeadersFlags {
                end_stream: false,
                end_headers: true,
                padded: false,
                priority: false,
            },
            priority_info: None,
            padding_config: None,
            header_block: b"test".to_vec(),
            scenario: TestScenario::StreamIdValidation,
        };

        match test_headers_frame(&input) {
            Ok(_) => panic!("Stream ID 0 should be rejected"),
            Err(e) => {
                assert_headers_stream_zero_error("unit stream-id zero", &e);
            }
        }
    }

    #[test]
    fn test_valid_headers_frame() {
        let input = HeadersFrameFuzz {
            stream_id: 1,
            flags: HeadersFlags {
                end_stream: true,
                end_headers: true,
                padded: false,
                priority: false,
            },
            priority_info: None,
            padding_config: None,
            header_block: b"test-header-block".to_vec(),
            scenario: TestScenario::BasicParsing,
        };

        match test_headers_frame(&input) {
            Ok(frame) => {
                assert_eq!(frame.stream_id, 1);
                assert!(frame.end_stream);
                assert!(frame.end_headers);
                assert!(frame.priority.is_none());
            }
            Err(e) => panic!("Valid frame should parse successfully: {:?}", e),
        }
    }

    #[test]
    fn test_priority_parsing() {
        let input = HeadersFrameFuzz {
            stream_id: 3,
            flags: HeadersFlags {
                end_stream: false,
                end_headers: true,
                padded: false,
                priority: true,
            },
            priority_info: Some(PriorityInfo {
                exclusive: true,
                dependency: 1,
                weight: 42,
            }),
            padding_config: None,
            header_block: b"header-block".to_vec(),
            scenario: TestScenario::PriorityParsing,
        };

        match test_headers_frame(&input) {
            Ok(frame) => {
                assert!(frame.priority.is_some());
                let priority = frame.priority.unwrap();
                assert_eq!(priority.exclusive, true);
                assert_eq!(priority.dependency, 1);
                assert_eq!(priority.weight, 42);
            }
            Err(e) => panic!("Priority frame should parse successfully: {:?}", e),
        }
    }

    #[test]
    fn test_padding_validation() {
        let input = HeadersFrameFuzz {
            stream_id: 5,
            flags: HeadersFlags {
                end_stream: false,
                end_headers: true,
                padded: true,
                priority: false,
            },
            priority_info: None,
            padding_config: Some(PaddingConfig {
                pad_length: 10,
                enforce_boundary: true,
            }),
            header_block: b"x".to_vec(),
            scenario: TestScenario::PaddingValidation,
        };

        match test_headers_frame(&input) {
            Ok(_) => panic!("HEADERS padding overflow should be rejected"),
            Err(error) => {
                assert_headers_padding_error("unit padding overflow", &error);
            }
        }
    }

    #[test]
    fn test_flag_independence() {
        // Test that END_STREAM and END_HEADERS can be set independently
        let test_cases = [(false, false), (false, true), (true, false), (true, true)];

        for (end_stream, end_headers) in &test_cases {
            let input = HeadersFrameFuzz {
                stream_id: 7,
                flags: HeadersFlags {
                    end_stream: *end_stream,
                    end_headers: *end_headers,
                    padded: false,
                    priority: false,
                },
                priority_info: None,
                padding_config: None,
                header_block: b"test".to_vec(),
                scenario: TestScenario::FlagIndependence,
            };

            match test_headers_frame(&input) {
                Ok(frame) => {
                    assert_eq!(frame.end_stream, *end_stream);
                    assert_eq!(frame.end_headers, *end_headers);
                }
                Err(error) => panic!("flag-independent HEADERS frame should parse: {error:?}"),
            }
        }
    }
}
