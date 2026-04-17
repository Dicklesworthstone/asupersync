//! Fuzz target for LengthDelimitedCodec parsing.
//!
//! This target fuzzes the LengthDelimitedCodec with arbitrary byte sequences
//! and various configurations, looking for panics, infinite loops, integer
//! overflows, and other memory safety issues.
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run fuzz_length_delimited_codec
//! ```
//!
//! # Minimizing crashes
//! ```bash
//! cargo +nightly fuzz tmin fuzz_length_delimited_codec <crash_file>
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzConfig {
    length_field_offset: u8, // 0..=255
    length_field_length: u8, // Will be clamped to 1..=8
    length_adjustment: i16,  // -32768..32767
    num_skip: u8,            // 0..=255
    max_frame_length: u16,   // 1..=65535
    big_endian: bool,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    config: FuzzConfig,
    data: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    // Guard against excessively large inputs
    if input.data.len() > 1_000_000 {
        return;
    }

    // Build codec with fuzzed configuration
    let length_field_length = ((input.config.length_field_length % 8) + 1) as usize; // 1..=8
    let length_field_offset = input.config.length_field_offset as usize;
    let max_frame_length = std::cmp::max(1, input.config.max_frame_length as usize); // At least 1

    let mut codec = LengthDelimitedCodec::builder()
        .length_field_offset(length_field_offset)
        .length_field_length(length_field_length)
        .length_adjustment(input.config.length_adjustment as isize)
        .num_skip(input.config.num_skip as usize)
        .max_frame_length(max_frame_length);

    codec = if input.config.big_endian {
        codec.big_endian()
    } else {
        codec.little_endian()
    };

    let mut codec = codec.new_codec();

    // Create buffer with fuzzed data
    let mut buf = BytesMut::from(&input.data[..]);

    // Track iterations to prevent infinite loops
    let mut iterations = 0;
    const MAX_ITERATIONS: usize = 1000;

    // Try to decode frames from the buffer
    loop {
        iterations += 1;
        if iterations > MAX_ITERATIONS {
            break; // Prevent infinite loops
        }

        match codec.decode(&mut buf) {
            Ok(Some(frame)) => {
                // Successfully decoded a frame

                // Basic sanity checks that should never fail
                assert!(
                    frame.len() <= max_frame_length,
                    "Decoded frame exceeds max_frame_length"
                );

                // Ensure frame is not unreasonably large
                assert!(
                    frame.len() <= 10_000_000,
                    "Decoded frame is suspiciously large"
                );

                // If buffer is empty, we should be done
                if buf.is_empty() {
                    break;
                }
            }
            Ok(None) => {
                // Need more data - this is expected for partial frames
                break;
            }
            Err(_) => {
                // Parsing error - this is expected for malformed input
                break;
            }
        }
    }

    // Additional test: try decoding with fresh codec state
    if !input.data.is_empty() {
        let mut fresh_codec = LengthDelimitedCodec::builder()
            .length_field_offset(length_field_offset)
            .length_field_length(length_field_length)
            .length_adjustment(input.config.length_adjustment as isize)
            .num_skip(input.config.num_skip as usize)
            .max_frame_length(max_frame_length);

        fresh_codec = if input.config.big_endian {
            fresh_codec.big_endian()
        } else {
            fresh_codec.little_endian()
        };

        let mut fresh_codec = fresh_codec.new_codec();
        let mut fresh_buf = BytesMut::from(&input.data[..]);

        // Single decode attempt with fresh state
        let _ = fresh_codec.decode(&mut fresh_buf);
    }

    // Test edge cases with empty buffer
    let mut empty_codec = LengthDelimitedCodec::new();
    let mut empty_buf = BytesMut::new();
    let result = empty_codec.decode(&mut empty_buf);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none()); // Empty buffer should return None

    // Test with single byte
    if !input.data.is_empty() {
        let mut single_codec = LengthDelimitedCodec::new();
        let mut single_buf = BytesMut::from(&input.data[..1]);
        let _ = single_codec.decode(&mut single_buf); // Should not panic
    }
});
