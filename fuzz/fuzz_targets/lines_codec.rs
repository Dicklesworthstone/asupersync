//! Fuzz target for LinesCodec parsing.
//!
//! This target fuzzes the LinesCodec with arbitrary byte sequences
//! and configurations, looking for panics, UTF-8 handling issues,
//! state machine corruption, and memory safety issues.
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run fuzz_lines_codec
//! ```
//!
//! # Minimizing crashes
//! ```bash
//! cargo +nightly fuzz tmin fuzz_lines_codec <crash_file>
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, LinesCodec, LinesCodecError};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

#[derive(Arbitrary, Debug)]
struct FuzzConfig {
    max_length: Option<u16>, // None = unlimited, Some(n) = limited
    use_decode_eof: bool,
    split_operations: bool, // Whether to split buffer operations
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    config: FuzzConfig,
    data: Vec<u8>,
    split_points: Vec<u8>, // For splitting operations
}

fn assert_decoded_line_shape(line: &str, max_length: usize) {
    if max_length != usize::MAX {
        assert!(
            line.len() <= max_length,
            "decoded line length {} exceeds max_length {}",
            line.len(),
            max_length
        );
    }
    assert!(
        !line.contains('\n'),
        "decoded line contains newline delimiter"
    );
    assert!(
        !line.ends_with('\r'),
        "decoded line retained trailing carriage return"
    );
}

fn observe_decode(
    codec: &mut LinesCodec,
    buf: &mut BytesMut,
    eof: bool,
) -> Result<Option<String>, LinesCodecError> {
    let before_len = buf.len();
    let max_length = codec.max_length();
    let result = if eof {
        codec.decode_eof(buf)
    } else {
        codec.decode(buf)
    };

    assert!(
        buf.len() <= before_len,
        "LinesCodec decode grew the input buffer"
    );

    match &result {
        Ok(Some(line)) => {
            assert!(
                buf.len() < before_len,
                "successful line decode must consume input"
            );
            assert_decoded_line_shape(line, max_length);
        }
        Ok(None) => {}
        Err(error) => {
            assert!(
                !error.to_string().is_empty(),
                "LinesCodec error must have a non-empty description: {error:?}"
            );
        }
    }

    result
}

fn expect_line(result: Result<Option<String>, LinesCodecError>, expected: &str) {
    match result {
        Ok(Some(line)) => assert_eq!(line, expected),
        other => panic!("expected decoded line {expected:?}, got {other:?}"),
    }
}

fn expect_none(result: Result<Option<String>, LinesCodecError>) {
    match result {
        Ok(None) => {}
        other => panic!("expected no decoded line, got {other:?}"),
    }
}

fn expect_error(
    result: Result<Option<String>, LinesCodecError>,
    matches_expected: impl FnOnce(&LinesCodecError) -> bool,
    label: &str,
) {
    match result {
        Err(error) if matches_expected(&error) => {}
        other => panic!("expected {label} error, got {other:?}"),
    }
}

fn assert_fixed_decode_canaries() {
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from("alpha\nbeta\r\ntail");
    expect_line(observe_decode(&mut codec, &mut buf, false), "alpha");
    expect_line(observe_decode(&mut codec, &mut buf, false), "beta");
    expect_none(observe_decode(&mut codec, &mut buf, false));
    expect_line(observe_decode(&mut codec, &mut buf, true), "tail");
    assert!(buf.is_empty(), "EOF canary should consume trailing line");

    let mut limited = LinesCodec::new_with_max_length(3);
    let mut too_long = BytesMut::from("abcd\nok\n");
    expect_error(
        observe_decode(&mut limited, &mut too_long, false),
        |error| matches!(error, LinesCodecError::MaxLineLengthExceeded),
        "max-line-length",
    );
    expect_line(observe_decode(&mut limited, &mut too_long, false), "ok");
    assert!(
        too_long.is_empty(),
        "discard canary should drain the oversized line and decode the next line"
    );

    let mut invalid_utf8 = LinesCodec::new();
    let mut invalid_buf = BytesMut::from(&b"\xff\n"[..]);
    expect_error(
        observe_decode(&mut invalid_utf8, &mut invalid_buf, false),
        |error| matches!(error, LinesCodecError::InvalidUtf8),
        "invalid-utf8",
    );
    assert!(
        invalid_buf.is_empty(),
        "invalid UTF-8 canary should consume the rejected line"
    );

    let mut empty = LinesCodec::new();
    let mut empty_buf = BytesMut::new();
    expect_none(observe_decode(&mut empty, &mut empty_buf, false));
    expect_none(observe_decode(&mut empty, &mut empty_buf, true));
}

fuzz_target!(|input: FuzzInput| {
    FIXED_CANARIES.get_or_init(assert_fixed_decode_canaries);

    // Guard against excessively large inputs
    if input.data.len() > 100_000 {
        return;
    }

    // Create codec with fuzzed configuration
    let mut codec = if let Some(max_len) = input.config.max_length {
        // Ensure at least 1 to avoid edge cases
        let max_length = std::cmp::max(1, max_len as usize);
        LinesCodec::new_with_max_length(max_length)
    } else {
        LinesCodec::new()
    };

    let max_length = codec.max_length();

    // Test 1: Single decode attempt with all data at once
    {
        let mut buf = BytesMut::from(&input.data[..]);
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 1000;

        loop {
            iterations += 1;
            if iterations > MAX_ITERATIONS {
                break; // Prevent infinite loops
            }

            let decode_at_eof = input.config.use_decode_eof && buf.is_empty();
            let result = observe_decode(&mut codec, &mut buf, decode_at_eof);

            match result {
                Ok(Some(line)) => {
                    // Successfully decoded a line

                    // Basic UTF-8 validation - should never fail if codec returned Ok
                    assert!(
                        line.chars().all(|_| true),
                        "Codec returned invalid UTF-8 string"
                    );

                    // If max_length is set, line should not exceed it
                    if max_length != usize::MAX {
                        assert!(
                            line.len() <= max_length,
                            "Line length {} exceeds max_length {}",
                            line.len(),
                            max_length
                        );
                    }

                    // Ensure line doesn't contain newline characters (they should be stripped)
                    assert!(
                        !line.contains('\n'),
                        "Decoded line contains newline character"
                    );
                    assert!(
                        !line.ends_with('\r'),
                        "Decoded line contains trailing carriage return"
                    );

                    // If buffer is empty, break
                    if buf.is_empty() {
                        break;
                    }
                }
                Ok(None) => {
                    // Need more data or EOF with no trailing data
                    break;
                }
                Err(_) => {
                    // Expected for malformed input (invalid UTF-8, oversized lines)
                    break;
                }
            }
        }
    }

    // Test 2: Split operations if requested
    if input.config.split_operations && !input.data.is_empty() && !input.split_points.is_empty() {
        let mut fresh_codec = if let Some(max_len) = input.config.max_length {
            LinesCodec::new_with_max_length(std::cmp::max(1, max_len as usize))
        } else {
            LinesCodec::new()
        };

        let mut buf = BytesMut::new();
        let mut data_consumed = 0;

        // Add data in chunks based on split points
        for &split_byte in &input.split_points {
            if data_consumed >= input.data.len() {
                break;
            }

            let chunk_size = (split_byte as usize % 32) + 1; // 1-32 bytes per chunk
            let end = std::cmp::min(data_consumed + chunk_size, input.data.len());

            if end > data_consumed {
                buf.extend_from_slice(&input.data[data_consumed..end]);
                data_consumed = end;

                // Try to decode after each chunk
                let _ = observe_decode(&mut fresh_codec, &mut buf, false);
            }
        }

        // Process any remaining data
        if data_consumed < input.data.len() {
            buf.extend_from_slice(&input.data[data_consumed..]);
            let _ = observe_decode(&mut fresh_codec, &mut buf, true);
        }
    }

    // Test 3: Buffer manipulation edge cases
    if !input.data.is_empty() {
        let mut edge_codec = LinesCodec::new_with_max_length(10); // Small limit for testing

        // Test with buffer that gets cleared/replaced between calls
        let mut buf = BytesMut::from(&input.data[..std::cmp::min(input.data.len(), 5)]);
        let _ = observe_decode(&mut edge_codec, &mut buf, false);

        // Replace buffer entirely
        buf.clear();
        if input.data.len() > 5 {
            buf.extend_from_slice(&input.data[5..]);
            let _ = observe_decode(&mut edge_codec, &mut buf, false);
        }
    }

    // Test 4: Clone and state isolation
    {
        let codec_copy = codec.clone();
        assert_eq!(codec_copy.max_length(), codec.max_length());

        // Ensure cloned codec works independently
        if !input.data.is_empty() {
            let mut cloned_codec = codec_copy;
            let mut buf = BytesMut::from(&input.data[..std::cmp::min(input.data.len(), 10)]);
            let _ = observe_decode(&mut cloned_codec, &mut buf, false);
        }
    }

    // Test 5: Edge case with empty and single-byte inputs
    {
        let mut empty_codec = LinesCodec::new();
        let mut empty_buf = BytesMut::new();

        // Empty buffer should return None
        assert_eq!(empty_codec.decode(&mut empty_buf).unwrap(), None);
        assert_eq!(empty_codec.decode_eof(&mut empty_buf).unwrap(), None);

        // Single newline
        let mut newline_buf = BytesMut::from("\n");
        let result = empty_codec.decode(&mut newline_buf).unwrap();
        if let Some(line) = result {
            assert!(line.is_empty()); // Should be empty line
        }
    }

    // Test 6: Various newline combinations
    if input.data.len() >= 2 {
        let mut newline_codec = LinesCodec::new();

        // Test different line ending styles
        let test_cases = [
            b"test\n".as_slice(),
            b"test\r\n".as_slice(),
            b"test\r".as_slice(),
            b"\n".as_slice(),
            b"\r\n".as_slice(),
        ];

        for test_case in &test_cases {
            let mut test_buf = BytesMut::from(*test_case);
            let _ = observe_decode(&mut newline_codec, &mut test_buf, false);
        }
    }

    // Test 7: Encode round-trip testing (missing from original)
    // Property: decode→encode→decode round-trip invariance on valid frames
    {
        use asupersync::codec::Encoder;

        let mut rt_codec = if let Some(max_len) = input.config.max_length {
            LinesCodec::new_with_max_length(std::cmp::max(1, max_len as usize))
        } else {
            LinesCodec::new()
        };

        let mut decode_buf = BytesMut::from(&input.data[..]);
        let mut decoded_lines = Vec::new();

        // Decode all possible lines from input
        let mut decode_iterations = 0;
        const DECODE_MAX_ITERATIONS: usize = 100;

        loop {
            decode_iterations += 1;
            if decode_iterations > DECODE_MAX_ITERATIONS {
                break;
            }

            match rt_codec.decode(&mut decode_buf) {
                Ok(Some(line)) => {
                    decoded_lines.push(line);
                    if decode_buf.is_empty() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        // Handle any remaining data with decode_eof
        if !decode_buf.is_empty()
            && let Ok(Some(final_line)) = rt_codec.decode_eof(&mut decode_buf)
        {
            decoded_lines.push(final_line);
        }

        // Test round-trip: encode each decoded line and decode it back
        for original_line in decoded_lines {
            let mut encode_codec = LinesCodec::new();
            let mut encode_buf = BytesMut::new();

            // Encode the line
            if let Ok(()) = encode_codec.encode(original_line.clone(), &mut encode_buf) {
                // Now decode the encoded data back
                let mut decode_codec = LinesCodec::new();

                if let Ok(Some(roundtrip_line)) = decode_codec.decode(&mut encode_buf) {
                    // Round-trip should preserve content (minus potential newline differences)
                    let original_trimmed = original_line.trim_end_matches(&['\n', '\r'][..]);
                    let roundtrip_trimmed = roundtrip_line.trim_end_matches(&['\n', '\r'][..]);

                    assert_eq!(
                        original_trimmed, roundtrip_trimmed,
                        "Round-trip invariant violated: original={:?}, roundtrip={:?}",
                        original_trimmed, roundtrip_trimmed
                    );
                }
            }
        }
    }

    // Test 8: Mixed newline handling validation (\n, \r\n, \r, bare CR, NUL)
    {
        let mixed_cases: [&[u8]; 5] = [
            b"line1\n".as_slice(),
            b"line2\r\n".as_slice(),
            b"line3\r".as_slice(),
            b"line4\x00with\x00nul\n".as_slice(),
            b"line5".as_slice(), // No newline
        ];
        let mixed_data = mixed_cases.concat();

        let mut mixed_codec = LinesCodec::new();
        let mut mixed_buf = BytesMut::from(&mixed_data[..]);

        // Decode should handle all newline types gracefully
        let mut mixed_lines = Vec::new();
        let mut mixed_iterations = 0;
        const MIXED_MAX_ITERATIONS: usize = 50;

        loop {
            mixed_iterations += 1;
            if mixed_iterations > MIXED_MAX_ITERATIONS {
                break;
            }

            match mixed_codec.decode(&mut mixed_buf) {
                Ok(Some(line)) => {
                    mixed_lines.push(line);
                    if mixed_buf.is_empty() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break, // Invalid UTF-8 or oversized line
            }
        }

        // Handle trailing data
        if !mixed_buf.is_empty() {
            let _ = observe_decode(&mut mixed_codec, &mut mixed_buf, true);
        }
    }
});
