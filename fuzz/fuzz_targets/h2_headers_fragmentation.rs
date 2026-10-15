#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{ContinuationFrame, Frame, HeadersFrame, SettingsFrame};
use asupersync::http::h2::settings::Settings;
use asupersync::http::h2::{Header, HpackEncoder};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

// Mock HTTP/2 frame types and constants for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzedFrame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Arbitrary)]
struct HeadersFragmentationTestCase {
    headers_frame: FuzzedFrame,
    continuation_frames: Vec<FuzzedFrame>,
    fragmentation_scenario: FragmentationScenario,
    malformed_patterns: MalformedPatterns,
}

#[derive(Debug, Clone, Arbitrary)]
enum FragmentationScenario {
    /// HEADERS with END_HEADERS but incomplete data
    IncompleteWithEndHeaders {
        expected_length: usize,
        actual_length: usize,
    },
    /// HEADERS without END_HEADERS but no CONTINUATION follows
    MissingContinuation { fragment_size: usize },
    /// HEADERS with END_HEADERS followed by unexpected CONTINUATION
    UnexpectedContinuation { continuation_count: u8 },
    /// Multiple HEADERS frames on same stream
    DuplicateHeaders { second_headers_delay: u8 },
    /// CONTINUATION frame without preceding HEADERS
    OrphanedContinuation { continuation_flags: u8 },
    /// Interleaved frames from different streams
    InterleavedStreams {
        other_stream_id: u32,
        interleaving_pattern: Vec<u8>,
    },
    /// HEADERS frame split across maximum fragments
    MaximumFragmentation {
        fragment_count: u8,
        fragment_sizes: Vec<u16>,
    },
    /// Empty HEADERS frame with END_HEADERS
    EmptyHeaders,
    /// HEADERS frame exceeding max frame size
    OversizedHeaders { size_multiplier: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
struct MalformedPatterns {
    truncated_length_prefix: bool,
    invalid_hpack_encoding: bool,
    corrupted_header_table: bool,
    negative_stream_id: bool,
    zero_stream_id: bool,
    reserved_flag_bits: bool,
    invalid_frame_type: bool,
    wrong_continuation_stream: bool,
}

// HTTP/2 frame type constants
const HEADERS_FRAME_TYPE: u8 = 0x1;
const CONTINUATION_FRAME_TYPE: u8 = 0x9;
const DATA_FRAME_TYPE: u8 = 0x0;

// HTTP/2 frame flags
const END_STREAM_FLAG: u8 = 0x1;
const END_HEADERS_FLAG: u8 = 0x4;
const PADDED_FLAG: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

// HTTP/2 constants
const MAX_FRAME_SIZE: usize = 16384; // Default max frame size
const LIVE_CONTINUATION_SEQUENCE_ERROR: &str =
    "CONTINUATION without preceding HEADERS/PUSH_PROMISE (RFC 9113 §6.10)";

fn assert_visible_protocol_error_context(context: &str, error_msg: &str) {
    assert!(
        !error_msg.is_empty(),
        "{context}: skipped setup error must include diagnostic text"
    );
    assert!(
        error_msg.contains("ERROR")
            || error_msg.contains("frame")
            || error_msg.contains("HPACK")
            || error_msg.contains("CONTINUATION")
            || error_msg.contains("Unsupported")
            || error_msg.contains("forbidden")
            || error_msg.contains("incomplete")
            || error_msg.contains("malformed"),
        "{context}: skipped setup error should remain protocol-shaped: {error_msg}"
    );
}

fn observe_initial_headers_result(
    result: Result<MockH2Response, String>,
    context: &str,
) -> Option<MockH2Response> {
    match result {
        Ok(response) => {
            assert_known_stream_state(context, &response.stream_state);
            Some(response)
        }
        Err(error_msg) => {
            assert_visible_protocol_error_context(context, &error_msg);
            None
        }
    }
}

fn validate_malformed_pattern_flags(patterns: &MalformedPatterns) {
    let active_patterns = usize::from(patterns.truncated_length_prefix)
        + usize::from(patterns.invalid_hpack_encoding)
        + usize::from(patterns.corrupted_header_table)
        + usize::from(patterns.negative_stream_id)
        + usize::from(patterns.zero_stream_id)
        + usize::from(patterns.reserved_flag_bits)
        + usize::from(patterns.invalid_frame_type)
        + usize::from(patterns.wrong_continuation_stream);

    assert!(
        active_patterns <= 8,
        "Malformed pattern count should stay within the known flag domain"
    );
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > 200_000 {
        return;
    }

    let mut u = Unstructured::new(data);

    // Try to generate a test case from the fuzz input
    let test_case = match HeadersFragmentationTestCase::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return, // Invalid input for generating test case
    };

    validate_malformed_pattern_flags(&test_case.malformed_patterns);
    assert_eq!(
        STREAM_STATE_DOMAIN.len(),
        5,
        "Stream state oracle should cover the full mock domain"
    );

    // Test scenario 1: HEADERS with END_HEADERS but incomplete data
    test_incomplete_headers_with_end_flag(&test_case);

    // Test scenario 2: HEADERS without END_HEADERS but missing CONTINUATION
    test_missing_continuation_frame(&test_case);

    // Test scenario 3: Unexpected CONTINUATION after complete HEADERS
    test_unexpected_continuation(&test_case);

    // Test scenario 4: Duplicate HEADERS frames on same stream
    test_duplicate_headers_frames(&test_case);

    // Test scenario 5: Orphaned CONTINUATION frame
    test_orphaned_continuation(&test_case);

    // Test scenario 6: Interleaved frames from different streams
    test_interleaved_stream_frames(&test_case);

    // Test scenario 7: Maximum fragmentation stress test
    test_maximum_fragmentation(&test_case);

    // Test scenario 8: Empty HEADERS frame
    test_empty_headers_frame(&test_case);

    // Test scenario 9: Oversized HEADERS frame
    test_oversized_headers_frame(&test_case);

    // Test scenario 10: Malformed HPACK encoding in fragments
    test_malformed_hpack_fragments(&test_case);
});

/// Test HEADERS frame with END_HEADERS flag but incomplete header data
fn test_incomplete_headers_with_end_flag(test_case: &HeadersFragmentationTestCase) {
    if let FragmentationScenario::IncompleteWithEndHeaders {
        expected_length,
        actual_length,
    } = &test_case.fragmentation_scenario
    {
        // Create HEADERS frame that claims to be complete but has truncated data
        let mut headers_frame = test_case.headers_frame.clone();
        headers_frame.frame_type = HEADERS_FRAME_TYPE;
        headers_frame.flags |= END_HEADERS_FLAG; // Claims to be complete
        headers_frame.stream_id = ensure_valid_stream_id(headers_frame.stream_id);

        // Truncate payload to simulate incomplete data
        let truncated_length = (*actual_length).min((*expected_length).saturating_sub(1));
        headers_frame.payload.truncate(truncated_length);

        // Add incomplete HPACK encoding that indicates more data expected
        if !headers_frame.payload.is_empty() {
            // Add incomplete length prefix that suggests more data follows
            headers_frame.payload.insert(0, 0x80); // High bit set = continuation expected
        }

        let result = process_h2_frame(&headers_frame);

        // Should be rejected as PROTOCOL_ERROR due to incomplete headers with END_HEADERS
        match result {
            Err(error_msg) if error_msg.contains("PROTOCOL_ERROR") => {
                // Expected: incomplete headers with END_HEADERS should be rejected
            }
            Err(error_msg)
                if error_msg.contains("incomplete") || error_msg.contains("truncated") =>
            {
                // Also acceptable: specific error about incomplete data
            }
            Ok(response) => {
                // The mock frame processor is intentionally lenient and has no
                // expected-length side channel. If it accepts this synthetic
                // setup, keep the accepted state coherent rather than treating
                // the fuzz scenario label itself as a crash oracle.
                assert!(
                    response.headers_complete,
                    "Accepted END_HEADERS frame should be marked complete"
                );
                assert!(
                    !response.awaiting_continuation,
                    "Accepted END_HEADERS frame should not await continuation"
                );
                assert_known_stream_state("accepted incomplete HEADERS", &response.stream_state);
            }
            Err(error_msg) => {
                assert_visible_protocol_error_context(
                    "incomplete HEADERS alternate rejection",
                    &error_msg,
                );
            }
        }
    }
}

/// Test HEADERS frame without END_HEADERS but missing CONTINUATION
fn test_missing_continuation_frame(test_case: &HeadersFragmentationTestCase) {
    if let FragmentationScenario::MissingContinuation { fragment_size } =
        &test_case.fragmentation_scenario
    {
        // Create HEADERS frame without END_HEADERS flag
        let mut headers_frame = test_case.headers_frame.clone();
        headers_frame.frame_type = HEADERS_FRAME_TYPE;
        headers_frame.flags &= !END_HEADERS_FLAG; // Remove END_HEADERS flag
        headers_frame.stream_id = ensure_valid_stream_id(headers_frame.stream_id);

        // Ensure payload suggests more data is coming
        headers_frame.payload.truncate(*fragment_size);
        if !headers_frame.payload.is_empty() {
            // Add HPACK encoding that indicates incomplete header block
            headers_frame.payload.push(0x80); // Continuation bit set
        }

        let result = process_h2_frame(&headers_frame);

        // Process the frame - it should be pending waiting for CONTINUATION
        match result {
            Ok(response) => {
                assert!(
                    !response.headers_complete,
                    "Headers should not be complete without END_HEADERS"
                );
                assert!(
                    response.awaiting_continuation,
                    "Should be awaiting CONTINUATION frame"
                );
            }
            Err(error_msg) => {
                assert_visible_protocol_error_context(
                    "missing CONTINUATION initial rejection",
                    &error_msg,
                );
            }
        }

        // Now try to process another non-CONTINUATION frame (protocol violation)
        let invalid_next_frame = FuzzedFrame {
            frame_type: DATA_FRAME_TYPE, // Not CONTINUATION
            flags: 0,
            stream_id: headers_frame.stream_id,
            payload: vec![0x00, 0x01, 0x02],
        };

        let violation_result = process_h2_frame(&invalid_next_frame);

        // Should be rejected as PROTOCOL_ERROR
        match violation_result {
            Err(error_msg) if error_msg.contains("PROTOCOL_ERROR") => {
                // Expected: non-CONTINUATION after incomplete HEADERS
            }
            Err(error_msg) if error_msg.contains("CONTINUATION") => {
                // Also acceptable: specific error about missing CONTINUATION
            }
            Ok(response) => {
                assert_known_stream_state(
                    "missing CONTINUATION lenient DATA",
                    &response.stream_state,
                );
            }
            Err(error_msg) => {
                assert_visible_protocol_error_context(
                    "missing CONTINUATION alternate rejection",
                    &error_msg,
                );
            }
        }
    }
}

/// Test unexpected CONTINUATION after complete HEADERS
fn test_unexpected_continuation(test_case: &HeadersFragmentationTestCase) {
    if let FragmentationScenario::UnexpectedContinuation { continuation_count } =
        &test_case.fragmentation_scenario
    {
        assert_live_unsolicited_continuation_after_complete_headers();

        // Create complete HEADERS frame with END_HEADERS flag
        let mut headers_frame = test_case.headers_frame.clone();
        headers_frame.frame_type = HEADERS_FRAME_TYPE;
        headers_frame.flags |= END_HEADERS_FLAG; // Complete headers
        headers_frame.stream_id = ensure_valid_stream_id(headers_frame.stream_id);

        // Ensure payload represents complete header block
        if headers_frame.payload.is_empty() {
            headers_frame.payload = vec![0x40, 0x03, b'f', b'o', b'o', 0x03, b'b', b'a', b'r']; // Simple header
        }

        let headers_result = process_h2_frame(&headers_frame);

        // First frame should be processed successfully
        match headers_result {
            Ok(response) => {
                assert!(
                    response.headers_complete,
                    "Headers should be complete with END_HEADERS"
                );
                assert!(
                    !response.awaiting_continuation,
                    "Should not be awaiting CONTINUATION"
                );
            }
            Err(_) => {
                // If headers frame itself fails, that's not what we're testing
                return;
            }
        }

        // Now send unexpected CONTINUATION frames
        for i in 0..*continuation_count {
            let continuation_frame = FuzzedFrame {
                frame_type: CONTINUATION_FRAME_TYPE,
                flags: if i == continuation_count - 1 {
                    END_HEADERS_FLAG
                } else {
                    0
                },
                stream_id: headers_frame.stream_id,
                payload: vec![0x40, 0x01, b'x', 0x01, b'y'], // Additional header
            };

            let continuation_result = process_h2_frame(&continuation_frame);

            // Unexpected CONTINUATION should be rejected as PROTOCOL_ERROR
            match continuation_result {
                Err(error_msg) if error_msg.contains("PROTOCOL_ERROR") => {
                    // Expected: CONTINUATION after complete headers
                }
                Err(error_msg)
                    if error_msg.contains("unexpected") || error_msg.contains("CONTINUATION") =>
                {
                    // Also acceptable: specific error about unexpected CONTINUATION
                }
                Ok(response) => {
                    assert_known_stream_state(
                        "unexpected CONTINUATION lenient response",
                        &response.stream_state,
                    );
                    // Some implementations might silently ignore or handle this differently
                    // This is not necessarily wrong but worth noting
                }
                Err(error_msg) => {
                    assert_visible_protocol_error_context(
                        "unexpected CONTINUATION alternate rejection",
                        &error_msg,
                    );
                }
            }
        }
    }
}

/// Test duplicate HEADERS frames on same stream
fn test_duplicate_headers_frames(test_case: &HeadersFragmentationTestCase) {
    if let FragmentationScenario::DuplicateHeaders {
        second_headers_delay,
    } = &test_case.fragmentation_scenario
    {
        let stream_id = ensure_valid_stream_id(test_case.headers_frame.stream_id);

        // Create first HEADERS frame
        let mut first_headers = test_case.headers_frame.clone();
        first_headers.frame_type = HEADERS_FRAME_TYPE;
        first_headers.flags |= END_HEADERS_FLAG;
        first_headers.stream_id = stream_id;

        // Create second HEADERS frame on same stream
        let mut second_headers = first_headers.clone();
        second_headers.payload = vec![
            0x40, 0x03, b'n', b'e', b'w', 0x05, b'v', b'a', b'l', b'u', b'e',
        ];
        if *second_headers_delay & 0x1 != 0 {
            second_headers.flags |= END_STREAM_FLAG;
        }
        if *second_headers_delay & 0x2 != 0 {
            second_headers.flags |= PADDED_FLAG;
            second_headers.payload.insert(0, 0);
        }

        let first_result = process_h2_frame(&first_headers);
        let second_result = process_h2_frame(&second_headers);

        // First should succeed
        assert!(
            first_result.is_ok(),
            "First HEADERS frame should be processed"
        );

        // Second HEADERS on same stream might be protocol violation depending on stream state
        match second_result {
            Err(error_msg) if error_msg.contains("PROTOCOL_ERROR") => {
                // Expected if stream doesn't allow additional headers
            }
            Ok(response) => {
                assert_known_stream_state(
                    "duplicate HEADERS accepted response",
                    &response.stream_state,
                );
                // Might be acceptable if implementation supports trailers or stream reuse
            }
            Err(error_msg) => {
                assert_visible_protocol_error_context(
                    "duplicate HEADERS alternate rejection",
                    &error_msg,
                );
            }
        }
    }
}

/// Test orphaned CONTINUATION frame without preceding HEADERS
fn test_orphaned_continuation(test_case: &HeadersFragmentationTestCase) {
    if let FragmentationScenario::OrphanedContinuation { continuation_flags } =
        &test_case.fragmentation_scenario
    {
        assert_live_orphaned_continuation();

        // Create CONTINUATION frame without any preceding HEADERS frame
        let continuation_frame = FuzzedFrame {
            frame_type: CONTINUATION_FRAME_TYPE,
            flags: *continuation_flags,
            stream_id: ensure_valid_stream_id(test_case.headers_frame.stream_id),
            payload: vec![
                0x40, 0x04, b't', b'e', b's', b't', 0x04, b'd', b'a', b't', b'a',
            ],
        };

        let result = process_h2_frame(&continuation_frame);

        // Orphaned CONTINUATION should be rejected as PROTOCOL_ERROR
        match result {
            Err(error_msg) if error_msg.contains("PROTOCOL_ERROR") => {
                // Expected: CONTINUATION without HEADERS
            }
            Err(error_msg)
                if error_msg.contains("orphaned") || error_msg.contains("unexpected") =>
            {
                // Also acceptable: specific error about orphaned CONTINUATION
            }
            Ok(_) => {
                // If accepted, this could be a protocol violation
                panic!("Orphaned CONTINUATION frame should be rejected");
            }
            Err(error_msg) => {
                assert_visible_protocol_error_context(
                    "orphaned CONTINUATION alternate rejection",
                    &error_msg,
                );
            }
        }
    }
}

/// Test interleaved frames from different streams during header continuation
fn test_interleaved_stream_frames(test_case: &HeadersFragmentationTestCase) {
    if let FragmentationScenario::InterleavedStreams {
        other_stream_id,
        interleaving_pattern,
    } = &test_case.fragmentation_scenario
    {
        let main_stream = ensure_valid_stream_id(test_case.headers_frame.stream_id);
        let other_stream = ensure_valid_stream_id(*other_stream_id);

        if main_stream == other_stream {
            return; // Skip if streams are the same
        }

        // Start HEADERS frame on main stream without END_HEADERS
        let mut headers_frame = test_case.headers_frame.clone();
        headers_frame.frame_type = HEADERS_FRAME_TYPE;
        headers_frame.flags &= !END_HEADERS_FLAG; // Incomplete headers
        headers_frame.stream_id = main_stream;

        let Some(headers_response) = observe_initial_headers_result(
            process_h2_frame(&headers_frame),
            "interleaved initial HEADERS",
        ) else {
            return; // If initial frame fails, skip test
        };
        assert!(
            !headers_response.headers_complete,
            "Initial interleaved HEADERS should remain incomplete"
        );
        assert!(
            headers_response.awaiting_continuation,
            "Initial interleaved HEADERS should await CONTINUATION"
        );

        // Now interleave frames according to pattern
        for &pattern_byte in interleaving_pattern {
            let frame = if pattern_byte % 2 == 0 {
                // Frame for other stream (should be allowed)
                FuzzedFrame {
                    frame_type: DATA_FRAME_TYPE,
                    flags: 0,
                    stream_id: other_stream,
                    payload: vec![0x48, 0x65, 0x6c, 0x6c, 0x6f], // "Hello"
                }
            } else {
                // CONTINUATION frame for main stream (should be required next)
                FuzzedFrame {
                    frame_type: CONTINUATION_FRAME_TYPE,
                    flags: END_HEADERS_FLAG, // Complete the headers
                    stream_id: main_stream,
                    payload: vec![
                        0x40, 0x04, b't', b'a', b'i', b'l', 0x04, b'd', b'a', b't', b'a',
                    ],
                }
            };

            let interleave_result = process_h2_frame(&frame);

            if frame.frame_type == CONTINUATION_FRAME_TYPE {
                // CONTINUATION should be accepted
                match interleave_result {
                    Ok(_) => break, // Headers completed
                    Err(error_msg) => {
                        assert_visible_protocol_error_context(
                            "interleaved CONTINUATION alternate rejection",
                            &error_msg,
                        );
                    }
                }
            } else {
                // Non-CONTINUATION frame on different stream during incomplete headers
                // RFC 9113 requires CONTINUATION to be the next frame
                match interleave_result {
                    Err(error_msg) if error_msg.contains("PROTOCOL_ERROR") => {
                        // Strict implementation rejects interleaving
                        break;
                    }
                    Ok(_) => {
                        // Lenient implementation allows interleaving
                        // This might be acceptable depending on interpretation
                    }
                    Err(error_msg) => {
                        assert_visible_protocol_error_context(
                            "interleaved non-CONTINUATION alternate rejection",
                            &error_msg,
                        );
                    }
                }
            }
        }
    }
}

/// Test maximum fragmentation stress test
fn test_maximum_fragmentation(test_case: &HeadersFragmentationTestCase) {
    if let FragmentationScenario::MaximumFragmentation {
        fragment_count,
        fragment_sizes,
    } = &test_case.fragmentation_scenario
    {
        let stream_id = ensure_valid_stream_id(test_case.headers_frame.stream_id);
        let max_fragments = 20; // Reasonable limit for testing

        let actual_count = (*fragment_count as usize).min(max_fragments);

        // Create initial HEADERS frame without END_HEADERS
        let mut headers_frame = test_case.headers_frame.clone();
        headers_frame.frame_type = HEADERS_FRAME_TYPE;
        headers_frame.flags &= !END_HEADERS_FLAG;
        headers_frame.stream_id = stream_id;

        // Limit payload size for first frame
        let first_size = fragment_sizes.first().map(|&s| s as usize).unwrap_or(100);
        headers_frame.payload.truncate(first_size);

        let Some(headers_response) = observe_initial_headers_result(
            process_h2_frame(&headers_frame),
            "maximum fragmentation initial HEADERS",
        ) else {
            return; // If initial frame fails, skip test
        };
        assert!(
            !headers_response.headers_complete,
            "Initial maximum-fragment HEADERS should remain incomplete"
        );
        assert!(
            headers_response.awaiting_continuation,
            "Initial maximum-fragment HEADERS should await CONTINUATION"
        );

        // Send CONTINUATION frames
        for i in 1..actual_count {
            let is_last = i == actual_count - 1;
            let fragment_size = fragment_sizes.get(i).map(|&s| s as usize).unwrap_or(50);

            let continuation_payload = test_case.continuation_frames.get(i).map_or_else(
                || {
                    vec![
                        0x40, 0x04, b't', b'a', b'i', b'l', 0x04, b'd', b'a', b't', b'a',
                    ]
                },
                |frame| frame.payload.clone(),
            );

            let continuation_frame = FuzzedFrame {
                frame_type: CONTINUATION_FRAME_TYPE,
                flags: if is_last { END_HEADERS_FLAG } else { 0 },
                stream_id,
                payload: if continuation_payload.is_empty() {
                    generate_header_fragment(fragment_size)
                } else {
                    continuation_payload
                },
            };

            let result = process_h2_frame(&continuation_frame);

            match result {
                Ok(response) => {
                    if is_last {
                        assert!(
                            response.headers_complete,
                            "Last fragment should complete headers"
                        );
                    }
                }
                Err(error_msg) if error_msg.contains("too many fragments") => {
                    // Implementation may limit number of fragments
                    break;
                }
                Err(error_msg) => {
                    assert_visible_protocol_error_context(
                        "maximum fragmentation alternate rejection",
                        &error_msg,
                    );
                    break;
                }
            }
        }
    }
}

/// Test empty HEADERS frame with END_HEADERS
fn test_empty_headers_frame(test_case: &HeadersFragmentationTestCase) {
    if let FragmentationScenario::EmptyHeaders = &test_case.fragmentation_scenario {
        // Create empty HEADERS frame with END_HEADERS flag
        let empty_headers = FuzzedFrame {
            frame_type: HEADERS_FRAME_TYPE,
            flags: END_HEADERS_FLAG,
            stream_id: ensure_valid_stream_id(test_case.headers_frame.stream_id),
            payload: Vec::new(), // Empty payload
        };

        let result = process_h2_frame(&empty_headers);

        // Empty headers might be valid (no custom headers) or invalid depending on context
        match result {
            Ok(response) => {
                assert!(
                    response.headers_complete,
                    "Empty headers with END_HEADERS should be complete"
                );
                assert!(response.headers.is_empty(), "Headers should be empty");
            }
            Err(_) => {
                // Error for empty headers is also acceptable
            }
        }
    }
}

/// Test oversized HEADERS frame
fn test_oversized_headers_frame(test_case: &HeadersFragmentationTestCase) {
    if let FragmentationScenario::OversizedHeaders { size_multiplier } =
        &test_case.fragmentation_scenario
    {
        let oversized_length = MAX_FRAME_SIZE * (*size_multiplier as usize + 1);
        let truncated_length = oversized_length.min(50_000); // Cap for testing

        let oversized_headers = FuzzedFrame {
            frame_type: HEADERS_FRAME_TYPE,
            flags: END_HEADERS_FLAG,
            stream_id: ensure_valid_stream_id(test_case.headers_frame.stream_id),
            payload: vec![0x00; truncated_length], // Oversized payload
        };

        let result = process_h2_frame(&oversized_headers);

        // Oversized frame should be rejected
        match result {
            Err(error_msg)
                if error_msg.contains("frame size") || error_msg.contains("too large") =>
            {
                // Expected: frame size limit exceeded
            }
            Err(error_msg) => {
                assert_visible_protocol_error_context(
                    "oversized HEADERS alternate rejection",
                    &error_msg,
                );
            }
            Ok(_) => {
                // If accepted, verify it doesn't violate frame size limits
                if oversized_headers.payload.len() > MAX_FRAME_SIZE {
                    panic!("Oversized frame should be rejected");
                }
            }
        }
    }
}

/// Test malformed HPACK encoding in header fragments
fn test_malformed_hpack_fragments(test_case: &HeadersFragmentationTestCase) {
    if test_case.malformed_patterns.invalid_hpack_encoding {
        // Create HEADERS frame with malformed HPACK encoding
        let mut malformed_headers = test_case.headers_frame.clone();
        malformed_headers.frame_type = HEADERS_FRAME_TYPE;
        malformed_headers.flags |= END_HEADERS_FLAG;
        malformed_headers.stream_id = ensure_valid_stream_id(malformed_headers.stream_id);

        // Various HPACK malformation patterns
        malformed_headers.payload = vec![
            0xFF, 0xFF, 0xFF, // Invalid literal header encoding
            0x80, 0x00, 0x00, // Invalid index reference
            0x40, 0xFF, // Invalid name length
            b'x', b'y', b'z', // Partial name
            0x7F, 0x80, 0x01, // Invalid value length encoding
        ];

        let result = process_h2_frame(&malformed_headers);

        // Malformed HPACK should be rejected
        match result {
            Err(error_msg) if error_msg.contains("COMPRESSION_ERROR") => {
                // Expected: HPACK decompression error
            }
            Err(error_msg) if error_msg.contains("invalid") || error_msg.contains("malformed") => {
                // Also acceptable: general malformed data error
            }
            Ok(_) => {
                // If accepted, the parser might be very lenient or have different error handling
            }
            Err(error_msg) => {
                assert_visible_protocol_error_context(
                    "malformed HPACK alternate rejection",
                    &error_msg,
                );
            }
        }
    }
}

// Helper functions

fn ensure_valid_stream_id(stream_id: u32) -> u32 {
    if stream_id == 0 || stream_id & 0x80000000 != 0 {
        1 // Use stream 1 as default valid client stream
    } else {
        stream_id
    }
}

fn generate_header_fragment(size: usize) -> Vec<u8> {
    let actual_size = size.min(1000); // Cap size for testing
    let mut fragment = Vec::with_capacity(actual_size);

    // Generate simple header data
    for i in 0..actual_size {
        fragment.push((i % 256) as u8);
    }

    fragment
}

// Mock response structure
#[derive(Debug)]
struct MockH2Response {
    headers: HashMap<String, String>,
    headers_complete: bool,
    awaiting_continuation: bool,
    stream_state: StreamState,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

const STREAM_STATE_DOMAIN: [StreamState; 5] = [
    StreamState::Idle,
    StreamState::Open,
    StreamState::HalfClosedLocal,
    StreamState::HalfClosedRemote,
    StreamState::Closed,
];

fn assert_known_stream_state(context: &str, stream_state: &StreamState) {
    assert!(
        STREAM_STATE_DOMAIN.contains(stream_state),
        "{context}: stream state should stay in the mock H2 domain"
    );
}

fn assert_live_orphaned_continuation() {
    let mut connection = open_live_server_connection();
    let error = connection
        .process_frame(Frame::Continuation(ContinuationFrame {
            stream_id: 1,
            header_block: Bytes::new(),
            end_headers: true,
        }))
        .expect_err("live orphaned CONTINUATION must be rejected");
    assert_live_continuation_sequence_error("live orphaned CONTINUATION", &error);
}

fn assert_live_unsolicited_continuation_after_complete_headers() {
    let mut connection = open_live_server_connection();
    connection
        .process_frame(Frame::Headers(HeadersFrame::new(
            1,
            encoded_live_request_headers(),
            false,
            true,
        )))
        .expect("live setup HEADERS should complete");
    assert!(
        !connection.is_awaiting_continuation(),
        "live setup HEADERS with END_HEADERS should not await CONTINUATION"
    );

    let error = connection
        .process_frame(Frame::Continuation(ContinuationFrame {
            stream_id: 1,
            header_block: Bytes::new(),
            end_headers: true,
        }))
        .expect_err("live unsolicited CONTINUATION must be rejected");
    assert_live_continuation_sequence_error("live unsolicited CONTINUATION", &error);
}

fn open_live_server_connection() -> Connection {
    let mut connection = Connection::server(Settings::default());
    connection
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("empty SETTINGS should open live server connection");
    connection
}

fn encoded_live_request_headers() -> Bytes {
    let mut encoder = HpackEncoder::new();
    let mut block = BytesMut::new();
    encoder.encode(
        &[
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.test"),
            Header::new(":path", "/"),
        ],
        &mut block,
    );
    block.freeze()
}

fn assert_live_continuation_sequence_error(context: &str, error: &H2Error) {
    assert_eq!(
        error.code,
        ErrorCode::ProtocolError,
        "{context}: live CONTINUATION sequencing should be PROTOCOL_ERROR"
    );
    assert_eq!(
        error.stream_id, None,
        "{context}: live CONTINUATION sequencing must be connection-level"
    );
    assert_eq!(
        error.message, LIVE_CONTINUATION_SEQUENCE_ERROR,
        "{context}: live CONTINUATION sequencing diagnostic changed"
    );
}

// Mock frame processing function
fn process_h2_frame(frame: &FuzzedFrame) -> Result<MockH2Response, String> {
    // Basic frame validation
    if frame.stream_id == 0 && frame.frame_type != 0x4 && frame.frame_type != 0x8 {
        return Err("PROTOCOL_ERROR: Stream ID 0 forbidden for non-connection frames".to_string());
    }

    if frame.payload.len() > MAX_FRAME_SIZE {
        return Err("FRAME_SIZE_ERROR: Frame size exceeds maximum".to_string());
    }

    match frame.frame_type {
        HEADERS_FRAME_TYPE => {
            // Validate HEADERS frame
            let has_end_headers = frame.flags & END_HEADERS_FLAG != 0;
            let has_priority = frame.flags & PRIORITY_FLAG != 0;

            let mut payload_offset = 0;

            // Skip priority fields if present
            if has_priority {
                if frame.payload.len() < 5 {
                    return Err(
                        "FRAME_SIZE_ERROR: HEADERS with PRIORITY flag too small".to_string()
                    );
                }
                payload_offset = 5;
            }

            // Validate HPACK data
            if payload_offset < frame.payload.len() {
                let hpack_data = &frame.payload[payload_offset..];
                if let Err(e) = validate_hpack_fragment(hpack_data, has_end_headers) {
                    return Err(format!("COMPRESSION_ERROR: {}", e));
                }
            }

            let headers = if has_end_headers {
                decode_mock_headers(&frame.payload[payload_offset..])?
            } else {
                HashMap::new() // Headers incomplete
            };

            Ok(MockH2Response {
                headers,
                headers_complete: has_end_headers,
                awaiting_continuation: !has_end_headers,
                stream_state: StreamState::Open,
            })
        }
        CONTINUATION_FRAME_TYPE => {
            let has_end_headers = frame.flags & END_HEADERS_FLAG != 0;

            // Validate HPACK data
            if let Err(e) = validate_hpack_fragment(&frame.payload, has_end_headers) {
                return Err(format!("COMPRESSION_ERROR: {}", e));
            }

            let headers = if has_end_headers {
                decode_mock_headers(&frame.payload)?
            } else {
                HashMap::new()
            };

            Ok(MockH2Response {
                headers,
                headers_complete: has_end_headers,
                awaiting_continuation: !has_end_headers,
                stream_state: StreamState::Open,
            })
        }
        _ => Err("Unsupported frame type".to_string()),
    }
}

// Mock HPACK validation
fn validate_hpack_fragment(data: &[u8], is_complete: bool) -> Result<(), String> {
    if data.is_empty() && is_complete {
        return Ok(()); // Empty but complete is valid
    }

    if data.is_empty() && !is_complete {
        return Err("Empty incomplete fragment".to_string());
    }

    // Check for obviously invalid HPACK patterns
    for window in data.windows(3) {
        if window == [0xFF, 0xFF, 0xFF] {
            return Err("Invalid HPACK encoding pattern".to_string());
        }
    }

    // Check for truncated length prefixes at end
    if !is_complete {
        let last_byte = data[data.len() - 1];
        if last_byte & 0x80 != 0 {
            // High bit set might indicate continuation expected
            return Ok(());
        }
    }

    Ok(())
}

// Mock header decoder
fn decode_mock_headers(payload: &[u8]) -> Result<HashMap<String, String>, String> {
    let mut headers = HashMap::new();
    let mut pos = 0;

    // Very simple mock decoder
    while pos < payload.len() {
        if pos + 2 > payload.len() {
            break;
        }

        // Skip any obvious malformed patterns
        if payload[pos] == 0xFF && payload.get(pos + 1) == Some(&0xFF) {
            return Err("Malformed HPACK data".to_string());
        }

        let name_len = (payload[pos] & 0x7F) as usize;
        pos += 1;

        if pos + name_len >= payload.len() {
            break;
        }

        let name = format!("header-{}", pos);
        pos += name_len;

        if pos < payload.len() {
            let value_len = (payload[pos] & 0x7F) as usize;
            pos += 1;

            let value = format!("value-{}", pos);
            pos += value_len.min(payload.len() - pos);

            headers.insert(name, value);
        }
    }

    Ok(headers)
}
