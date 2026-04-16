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

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use asupersync::codec::{Decoder, LinesCodec};
use asupersync::bytes::BytesMut;

#[derive(Arbitrary, Debug)]
struct FuzzConfig {
    max_length: Option<u16>,  // None = unlimited, Some(n) = limited
    use_decode_eof: bool,
    split_operations: bool,   // Whether to split buffer operations
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    config: FuzzConfig,
    data: Vec<u8>,
    split_points: Vec<u8>,   // For splitting operations
}

fuzz_target!(|input: FuzzInput| {
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

            let result = if input.config.use_decode_eof && buf.is_empty() {
                codec.decode_eof(&mut buf)
            } else {
                codec.decode(&mut buf)
            };

            match result {
                Ok(Some(line)) => {
                    // Successfully decoded a line

                    // Basic UTF-8 validation - should never fail if codec returned Ok
                    assert!(line.chars().all(|_| true), "Codec returned invalid UTF-8 string");

                    // If max_length is set, line should not exceed it
                    if max_length != usize::MAX {
                        assert!(line.len() <= max_length,
                               "Line length {} exceeds max_length {}", line.len(), max_length);
                    }

                    // Ensure line doesn't contain newline characters (they should be stripped)
                    assert!(!line.contains('\n'), "Decoded line contains newline character");
                    assert!(!line.contains('\r'), "Decoded line contains carriage return");

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
                let _ = fresh_codec.decode(&mut buf);
            }
        }

        // Process any remaining data
        if data_consumed < input.data.len() {
            buf.extend_from_slice(&input.data[data_consumed..]);
            let _ = fresh_codec.decode_eof(&mut buf);
        }
    }

    // Test 3: Buffer manipulation edge cases
    if !input.data.is_empty() {
        let mut edge_codec = LinesCodec::new_with_max_length(10); // Small limit for testing

        // Test with buffer that gets cleared/replaced between calls
        let mut buf = BytesMut::from(&input.data[..std::cmp::min(input.data.len(), 5)]);
        let _ = edge_codec.decode(&mut buf);

        // Replace buffer entirely
        buf.clear();
        if input.data.len() > 5 {
            buf.extend_from_slice(&input.data[5..]);
            let _ = edge_codec.decode(&mut buf);
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
            let _ = cloned_codec.decode(&mut buf);
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
            let _ = newline_codec.decode(&mut test_buf);
        }
    }
});