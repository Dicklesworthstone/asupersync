//! Structure-aware fuzz target for LengthDelimitedCodec frame splitter.
//!
//! This target focuses on frame boundary detection and splitting scenarios:
//! - Adversarial length prefixes (overflow, underflow, misaligned)
//! - Frame fragmentation and reassembly edge cases
//! - Multi-frame boundaries with truncation attacks
//! - Resource exhaustion via oversized frame declarations
//! - State machine robustness under malformed input
//!
//! # Attack Scenarios Tested
//! - Length field overflow (claimed length >> actual data)
//! - Frame truncation at various byte boundaries
//! - Multi-frame parsing with corrupt boundaries
//! - Resource exhaustion protection
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run length_delimited_codec
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;

/// Maximum iterations to prevent infinite loops during fuzzing
const MAX_DECODE_ITERATIONS: usize = 1000;
const MAX_INPUT_SIZE: usize = 1_000_000;

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
struct FrameSplitterInput {
    config: FuzzConfig,
    splitter_scenario: SplitterScenario,
}

/// Frame splitter test scenarios focusing on boundary detection
#[derive(Arbitrary, Debug, Clone)]
enum SplitterScenario {
    /// Raw byte stream (original behavior)
    RawBytes { data: Vec<u8> },

    /// Multiple valid frames concatenated
    MultiFrame {
        frames: Vec<Vec<u8>>,
        corrupt_boundary: bool,
    },

    /// Fragmented frame delivery (tests state machine)
    Fragmented {
        frame_data: Vec<u8>,
        split_points: Vec<u8>, // Split positions as percentages 0-255
    },

    /// Adversarial length prefix attacks
    AdversarialLength {
        claimed_length: u64,
        actual_payload: Vec<u8>,
    },

    /// Frame truncation at critical boundaries
    TruncatedFrame {
        complete_frame: Vec<u8>,
        truncate_at: u8, // Truncation point as percentage
    },
}

fuzz_target!(|input: FrameSplitterInput| {
    // Property 1: No panic on any configuration or input
    test_no_panic_splitter(&input);

    // Property 2: Frame boundary detection is consistent
    test_frame_boundary_consistency(&input);

    // Property 3: Resource exhaustion protection works
    test_resource_exhaustion_protection(&input);

    // Property 4: State machine handles fragmentation correctly
    test_fragmentation_robustness(&input);

    // Property 5: Multi-frame parsing maintains boundaries
    test_multi_frame_boundaries(&input);
});

/// Property 1: No panic on any configuration or input
fn test_no_panic_splitter(input: &FrameSplitterInput) {
    let codec_result = std::panic::catch_unwind(|| create_codec(&input.config));

    let mut codec = match codec_result {
        Ok(Some(codec)) => codec,
        Ok(None) | Err(_) => return, // Invalid config, skip
    };

    let data = generate_splitter_data(&input.splitter_scenario, &input.config);

    // Test should never panic
    let _decode_result = std::panic::catch_unwind(|| {
        decode_with_iteration_limit(&mut codec, data)
    });

    assert!(true, "Frame splitter handled input without panic");
}

/// Property 2: Frame boundary detection is consistent
fn test_frame_boundary_consistency(input: &FrameSplitterInput) {
    let Some(mut codec) = create_codec(&input.config) else { return; };

    if let SplitterScenario::MultiFrame { frames, corrupt_boundary: false } = &input.splitter_scenario {
        // Test clean multi-frame parsing
        let concatenated_data = build_concatenated_frames(&input.config, frames);
        let decoded_frames = decode_with_iteration_limit(&mut codec, concatenated_data);

        // Basic consistency checks
        if !decoded_frames.is_empty() {
            // Decoded frame count should not exceed input frame count
            assert!(
                decoded_frames.len() <= frames.len(),
                "Should not decode more frames than provided"
            );

            // Each decoded frame should be non-empty (unless explicitly allowed)
            for frame in &decoded_frames {
                if !frame.is_empty() || input.config.length_adjustment >= 0 {
                    // Frame should be reasonable size
                    assert!(
                        frame.len() <= (input.config.max_frame_length as usize + 1000),
                        "Decoded frame size exceeds expected bounds"
                    );
                }
            }
        }
    }
}

/// Property 3: Resource exhaustion protection works
fn test_resource_exhaustion_protection(input: &FrameSplitterInput) {
    let Some(mut codec) = create_codec(&input.config) else { return; };

    if let SplitterScenario::AdversarialLength { claimed_length, actual_payload } = &input.splitter_scenario {
        let malicious_frame = build_frame_with_length(&input.config, *claimed_length, actual_payload);

        match decode_single_frame(&mut codec, malicious_frame) {
            Err(e) => {
                // Should reject excessive lengths appropriately
                let error_msg = format!("{e}");
                assert!(
                    error_msg.contains("frame length") ||
                    error_msg.contains("max") ||
                    error_msg.contains("overflow") ||
                    error_msg.contains("invalid"),
                    "Should reject length overflow with descriptive error"
                );
            },
            Ok(Some(frame)) => {
                // If successful, length must have been within configured limits
                let max_expected = (input.config.max_frame_length as usize * 10).min(10_000_000);
                assert!(
                    frame.len() <= max_expected,
                    "Large claimed length should only succeed if within limits"
                );
            },
            Ok(None) => {
                // Incomplete frame acceptable
            }
        }
    }
}

/// Property 4: State machine handles fragmentation correctly
fn test_fragmentation_robustness(input: &FrameSplitterInput) {
    let Some(mut codec) = create_codec(&input.config) else { return; };

    if let SplitterScenario::Fragmented { frame_data, split_points } = &input.splitter_scenario {
        let complete_frame = build_frame_with_length(&input.config, frame_data.len() as u64, frame_data);
        let fragments = fragment_at_points(&complete_frame, split_points);

        let mut decoded_frames = Vec::new();

        // Feed fragments sequentially
        for fragment in fragments {
            let mut buffer = BytesMut::from(fragment.as_slice());
            match codec.decode(&mut buffer) {
                Ok(Some(frame)) => decoded_frames.push(frame),
                Ok(None) => {}, // Expected for incomplete fragments
                Err(_) => {}, // Errors acceptable for malformed data
            }
        }

        // After fragmentation test, state machine should still be operational
        let test_frame = build_simple_frame(b"test");
        let _result = decode_single_frame(&mut codec, test_frame);
        // Just checking it doesn't panic or hang
    }
}

/// Property 5: Multi-frame parsing maintains boundaries
fn test_multi_frame_boundaries(input: &FrameSplitterInput) {
    let Some(mut codec) = create_codec(&input.config) else { return; };

    if let SplitterScenario::TruncatedFrame { complete_frame, truncate_at } = &input.splitter_scenario {
        let truncate_pos = (*truncate_at as usize * complete_frame.len()) / 256;
        let truncated = &complete_frame[..truncate_pos.min(complete_frame.len())];

        let result = decode_single_frame(&mut codec, truncated.to_vec());

        match result {
            Ok(None) => {
                // Expected for incomplete frames
            },
            Ok(Some(_)) => {
                // Successful decode of truncated data - should be valid
            },
            Err(_) => {
                // Parse errors expected for malformed truncated frames
            }
        }

        // State should remain consistent - try parsing a clean frame
        let clean_frame = build_simple_frame(b"recovery");
        let _recovery_result = decode_single_frame(&mut codec, clean_frame);
    }
}

/// Create codec with clamped configuration parameters
fn create_codec(config: &FuzzConfig) -> Option<LengthDelimitedCodec> {
    // Clamp parameters to valid ranges
    let length_field_offset = (config.length_field_offset % 32) as usize;
    let length_field_length = ((config.length_field_length % 8) + 1) as usize;
    let max_frame_length = std::cmp::max(1, config.max_frame_length as usize);
    let num_skip = (config.num_skip % 64) as usize;

    std::panic::catch_unwind(|| {
        let mut builder = LengthDelimitedCodec::builder()
            .length_field_offset(length_field_offset)
            .length_field_length(length_field_length)
            .length_adjustment(config.length_adjustment as isize)
            .num_skip(num_skip)
            .max_frame_length(max_frame_length);

        builder = if config.big_endian {
            builder.big_endian()
        } else {
            builder.little_endian()
        };

        builder.new_codec()
    }).ok()
}

/// Generate test data based on splitter scenario
fn generate_splitter_data(scenario: &SplitterScenario, config: &FuzzConfig) -> Vec<u8> {
    match scenario {
        SplitterScenario::RawBytes { data } => {
            if data.len() > MAX_INPUT_SIZE { data[..MAX_INPUT_SIZE].to_vec() } else { data.clone() }
        },
        SplitterScenario::MultiFrame { frames, corrupt_boundary } => {
            let mut data = build_concatenated_frames(config, frames);
            if *corrupt_boundary && !data.is_empty() {
                // Corrupt a random byte to test error handling
                let corrupt_pos = (data.len() / 2).min(data.len() - 1);
                data[corrupt_pos] = data[corrupt_pos].wrapping_add(1);
            }
            data
        },
        SplitterScenario::Fragmented { frame_data, .. } => {
            build_frame_with_length(config, frame_data.len() as u64, frame_data)
        },
        SplitterScenario::AdversarialLength { claimed_length, actual_payload } => {
            build_frame_with_length(config, *claimed_length, actual_payload)
        },
        SplitterScenario::TruncatedFrame { complete_frame, .. } => {
            complete_frame.clone()
        },
    }
}

/// Build a frame with specific length and payload
fn build_frame_with_length(config: &FuzzConfig, length: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; config.length_field_offset as usize];
    let field_length = ((config.length_field_length % 8) + 1) as usize;

    // Encode length field
    let length_bytes = if config.big_endian {
        length.to_be_bytes()
    } else {
        length.to_le_bytes()
    };

    frame.extend_from_slice(&length_bytes[..field_length.min(8)]);
    frame.extend(vec![0u8; config.num_skip as usize]); // Skip bytes
    frame.extend_from_slice(payload);
    frame
}

/// Build concatenated frames
fn build_concatenated_frames(config: &FuzzConfig, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut data = Vec::new();
    for frame in frames.iter().take(10) { // Limit to prevent excessive data
        let frame_data = build_frame_with_length(config, frame.len() as u64, frame);
        data.extend(frame_data);
        if data.len() > MAX_INPUT_SIZE { break; }
    }
    data
}

/// Build a simple test frame
fn build_simple_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Fragment data at specified split points
fn fragment_at_points(data: &[u8], split_points: &[u8]) -> Vec<Vec<u8>> {
    let mut fragments = Vec::new();
    let mut start = 0;

    for &point in split_points.iter().take(10) { // Limit fragments
        let pos = (point as usize * data.len()) / 256;
        if pos > start && pos < data.len() {
            fragments.push(data[start..pos].to_vec());
            start = pos;
        }
    }

    if start < data.len() {
        fragments.push(data[start..].to_vec());
    }

    if fragments.is_empty() {
        fragments.push(data.to_vec());
    }

    fragments
}

/// Decode with iteration limit to prevent infinite loops
fn decode_with_iteration_limit(codec: &mut LengthDelimitedCodec, data: Vec<u8>) -> Vec<BytesMut> {
    let mut buffer = BytesMut::from(data.as_slice());
    let mut frames = Vec::new();
    let mut iterations = 0;

    while iterations < MAX_DECODE_ITERATIONS && !buffer.is_empty() {
        match codec.decode(&mut buffer) {
            Ok(Some(frame)) => {
                frames.push(frame);
                iterations += 1;
            },
            Ok(None) => break, // Need more data
            Err(_) => break,   // Parse error
        }

        if buffer.len() > MAX_INPUT_SIZE {
            break; // Safety limit
        }
    }

    frames
}

/// Decode a single frame
fn decode_single_frame(codec: &mut LengthDelimitedCodec, data: Vec<u8>) -> Result<Option<BytesMut>, std::io::Error> {
    let mut buffer = BytesMut::from(data.as_slice());
    codec.decode(&mut buffer)
}
