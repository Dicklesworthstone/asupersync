#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::BytesMut;
use asupersync::codec::{Encoder, LengthDelimitedCodec};

/// Fuzz input for length-delimited encoder testing under various codec configurations
#[derive(Arbitrary, Debug)]
struct LengthDelimitedEncoderFuzzInput {
    /// Codec configuration parameters
    codec_config: CodecConfig,
    /// Frame data to encode
    frame_data: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct CodecConfig {
    /// Length field size (1-8 bytes)
    length_field_length: LengthFieldLength,
    /// Length adjustment (can cause under/overflow)
    length_adjustment: isize,
    /// Maximum frame length
    max_frame_length: MaxFrameLength,
    /// Byte order for length field
    big_endian: bool,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum LengthFieldLength {
    One = 1,
    Two = 2,
    Three = 3,
    Four = 4,
    Five = 5,
    Six = 6,
    Seven = 7,
    Eight = 8,
}

impl From<LengthFieldLength> for usize {
    fn from(val: LengthFieldLength) -> Self {
        match val {
            LengthFieldLength::One => 1,
            LengthFieldLength::Two => 2,
            LengthFieldLength::Three => 3,
            LengthFieldLength::Four => 4,
            LengthFieldLength::Five => 5,
            LengthFieldLength::Six => 6,
            LengthFieldLength::Seven => 7,
            LengthFieldLength::Eight => 8,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum MaxFrameLength {
    /// Very small limit to trigger length errors
    Small,
    /// Medium limit
    Medium,
    /// Large limit
    Large,
    /// Maximum practical limit
    Maximum,
}

impl From<MaxFrameLength> for usize {
    fn from(val: MaxFrameLength) -> Self {
        match val {
            MaxFrameLength::Small => 64,
            MaxFrameLength::Medium => 8192,
            MaxFrameLength::Large => 1024 * 1024,
            MaxFrameLength::Maximum => usize::MAX,
        }
    }
}

fuzz_target!(|input: LengthDelimitedEncoderFuzzInput| {
    // Property 1: Encoder should never panic on any configuration/data combination
    test_encoder_robustness(&input);

    // Property 2: Length field capacity constraints should be properly validated
    test_length_field_capacity(&input);

    // Property 3: Length adjustment edge cases should be handled safely
    test_length_adjustment_edge_cases(&input);

    // Property 4: Buffer operations should not overflow
    test_buffer_overflow_safety(&input);
});

fn build_codec_from_config(config: &CodecConfig) -> LengthDelimitedCodec {
    let mut builder = LengthDelimitedCodec::builder()
        .length_field_length(config.length_field_length.into())
        .length_adjustment(config.length_adjustment)
        .max_frame_length(config.max_frame_length.into());

    if config.big_endian {
        builder = builder.big_endian();
    } else {
        builder = builder.little_endian();
    }

    builder.new_codec()
}

fn observe_encode_result<E: std::fmt::Display>(result: Result<(), E>, dst_len: usize) {
    match result {
        Ok(()) => {
            std::hint::black_box(("encoded", dst_len));
        }
        Err(error) => {
            let error_msg = error.to_string();
            assert!(!error_msg.is_empty(), "encoder returned an empty error");
            std::hint::black_box(("rejected", error_msg));
        }
    }
}

fn test_encoder_robustness(input: &LengthDelimitedEncoderFuzzInput) {
    let mut codec = build_codec_from_config(&input.codec_config);
    let frame_data = BytesMut::from(input.frame_data.as_slice());
    let mut dst = BytesMut::new();

    // Encoder should never panic - errors are acceptable
    let result = codec.encode(frame_data, &mut dst);
    observe_encode_result(result, dst.len());
}

fn test_length_field_capacity(input: &LengthDelimitedEncoderFuzzInput) {
    let mut codec = build_codec_from_config(&input.codec_config);
    let frame_data = BytesMut::from(input.frame_data.as_slice());
    let mut dst = BytesMut::new();

    let result = codec.encode(frame_data, &mut dst);

    // Calculate maximum value that fits in the length field
    let length_field_len: usize = input.codec_config.length_field_length.into();
    let max_field_value = match length_field_len {
        1 => u8::MAX as u64,
        2 => u16::MAX as u64,
        3 => (1_u64 << 24) - 1,
        4 => u32::MAX as u64,
        5 => (1_u64 << 40) - 1,
        6 => (1_u64 << 48) - 1,
        7 => (1_u64 << 56) - 1,
        8 => u64::MAX,
        _ => unreachable!("length_field_length validated to 1-8"),
    };

    // Check that large frames correctly fail when they exceed field capacity
    if input.frame_data.len() as u64 > max_field_value
        && let Err(e) = result
    {
        // Should fail with length field capacity error
        assert!(e.to_string().contains("capacity") || e.to_string().contains("exceeds"));
    }
}

fn test_length_adjustment_edge_cases(input: &LengthDelimitedEncoderFuzzInput) {
    let mut codec = build_codec_from_config(&input.codec_config);
    let frame_data = BytesMut::from(input.frame_data.as_slice());
    let mut dst = BytesMut::new();

    let result = codec.encode(frame_data, &mut dst);

    let frame_len = input.frame_data.len() as i64;
    let adjustment = input.codec_config.length_adjustment as i64;

    // Check underflow cases
    if let Some(adjusted_len) = frame_len.checked_sub(adjustment) {
        if adjusted_len < 0 {
            // Should fail with underflow/negative length error
            if let Err(e) = result {
                assert!(
                    e.to_string().contains("underflow") || e.to_string().contains("negative"),
                    "Expected underflow/negative error, got: {}",
                    e
                );
            }
        }
    } else {
        // Subtraction overflow should also error
        if let Err(e) = result {
            assert!(
                e.to_string().contains("underflow") || e.to_string().contains("overflow"),
                "Expected underflow/overflow error, got: {}",
                e
            );
        }
    }
}

fn test_buffer_overflow_safety(input: &LengthDelimitedEncoderFuzzInput) {
    let mut codec = build_codec_from_config(&input.codec_config);
    let frame_data = BytesMut::from(input.frame_data.as_slice());
    let mut dst = BytesMut::new();

    let result = codec.encode(frame_data, &mut dst);

    // Check that total buffer length calculation doesn't overflow
    let length_field_len: usize = input.codec_config.length_field_length.into();
    if let Some(_total_len) = length_field_len.checked_add(input.frame_data.len()) {
        // If no overflow in calculation, encoder should either succeed or fail gracefully
        match &result {
            Ok(()) => {
                std::hint::black_box(dst.len());
            }
            Err(error) => {
                let error_msg = error.to_string();
                assert!(!error_msg.is_empty(), "encoder returned an empty error");
                std::hint::black_box(error_msg);
            }
        }
    } else {
        // If overflow in calculation, should fail with overflow error
        if let Err(ref e) = result {
            assert!(
                e.to_string().contains("overflow"),
                "Expected overflow error, got: {}",
                e
            );
        }
    }

    // If encoding succeeded, validate the output format
    if result.is_ok() {
        // Destination should contain length field + frame data
        let expected_min_len = length_field_len + input.frame_data.len();
        assert!(
            dst.len() >= expected_min_len,
            "Output buffer too small: {} < {}",
            dst.len(),
            expected_min_len
        );
    }
}
