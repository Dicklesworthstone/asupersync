#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::BytesMut;
use asupersync::codec::{Encoder, LengthDelimitedCodec};

const ERR_LENGTH_ADJUSTMENT_EXCEEDS_I64: &str = "length adjustment exceeds i64";
const ERR_FRAME_LENGTH_EXCEEDS_I64: &str = "frame length exceeds i64";
const ERR_LENGTH_UNDERFLOW: &str = "length underflow";
const ERR_NEGATIVE_ENCODED_LENGTH: &str = "negative encoded length";
const ERR_ENCODED_LENGTH_EXCEEDS_U64: &str = "encoded length exceeds u64";
const ERR_ENCODED_LENGTH_EXCEEDS_FIELD_CAPACITY: &str =
    "encoded length exceeds length_field_length capacity";
const ERR_FRAME_LENGTH_EXCEEDS_MAX: &str = "frame length exceeds max_frame_length";
const ERR_FRAME_BUFFER_RESERVATION_OVERFLOWS: &str = "frame buffer reservation overflows usize";

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

fn max_length_field_value(length_field_len: usize) -> u64 {
    match length_field_len {
        1 => u64::from(u8::MAX),
        2 => u64::from(u16::MAX),
        3 => (1_u64 << 24) - 1,
        4 => u64::from(u32::MAX),
        5 => (1_u64 << 40) - 1,
        6 => (1_u64 << 48) - 1,
        7 => (1_u64 << 56) - 1,
        8 => u64::MAX,
        _ => unreachable!("length_field_length validated to 1-8"),
    }
}

fn expected_encode_error(config: &CodecConfig, frame_len: usize) -> Option<&'static str> {
    let adjustment = match i64::try_from(config.length_adjustment) {
        Ok(adjustment) => adjustment,
        Err(_) => return Some(ERR_LENGTH_ADJUSTMENT_EXCEEDS_I64),
    };

    let frame_len_i64 = match i64::try_from(frame_len) {
        Ok(frame_len) => frame_len,
        Err(_) => return Some(ERR_FRAME_LENGTH_EXCEEDS_I64),
    };

    let adjusted_len = match frame_len_i64.checked_sub(adjustment) {
        Some(adjusted_len) => adjusted_len,
        None => return Some(ERR_LENGTH_UNDERFLOW),
    };

    if adjusted_len < 0 {
        return Some(ERR_NEGATIVE_ENCODED_LENGTH);
    }

    let length_to_encode = match u64::try_from(adjusted_len) {
        Ok(length_to_encode) => length_to_encode,
        Err(_) => return Some(ERR_ENCODED_LENGTH_EXCEEDS_U64),
    };

    let length_field_len: usize = config.length_field_length.into();
    if length_to_encode > max_length_field_value(length_field_len) {
        return Some(ERR_ENCODED_LENGTH_EXCEEDS_FIELD_CAPACITY);
    }

    if frame_len > config.max_frame_length.into() {
        return Some(ERR_FRAME_LENGTH_EXCEEDS_MAX);
    }

    if length_field_len.checked_add(frame_len).is_none() {
        return Some(ERR_FRAME_BUFFER_RESERVATION_OVERFLOWS);
    }

    None
}

fn observe_encode_result<E: std::fmt::Display>(
    result: &Result<(), E>,
    expected_error: Option<&str>,
    dst_len: usize,
) {
    match (result, expected_error) {
        (Ok(()), None) => {
            std::hint::black_box(("encoded", dst_len));
        }
        (Ok(()), Some(expected_message)) => {
            panic!("encoder succeeded; expected error: {expected_message}");
        }
        (Err(error), Some(expected_message)) => {
            assert_eq!(error.to_string(), expected_message);
            std::hint::black_box(("rejected", expected_message));
        }
        (Err(error), None) => {
            panic!("encoder returned unexpected error: {error}");
        }
    }
}

fn assert_exact_encode_error<E: std::fmt::Display>(result: &Result<(), E>, expected_message: &str) {
    match result {
        Ok(()) => {
            panic!("encoder succeeded; expected error: {expected_message}");
        }
        Err(error) => {
            assert_eq!(error.to_string(), expected_message);
            std::hint::black_box(expected_message);
        }
    }
}

fn test_encoder_robustness(input: &LengthDelimitedEncoderFuzzInput) {
    let mut codec = build_codec_from_config(&input.codec_config);
    let frame_data = BytesMut::from(input.frame_data.as_slice());
    let mut dst = BytesMut::new();

    // Encoder should never panic - errors are acceptable
    let result = codec.encode(frame_data, &mut dst);
    observe_encode_result(
        &result,
        expected_encode_error(&input.codec_config, input.frame_data.len()),
        dst.len(),
    );
}

fn test_length_field_capacity(input: &LengthDelimitedEncoderFuzzInput) {
    let mut codec = build_codec_from_config(&input.codec_config);
    let frame_data = BytesMut::from(input.frame_data.as_slice());
    let mut dst = BytesMut::new();

    let result = codec.encode(frame_data, &mut dst);

    let expected_error = expected_encode_error(&input.codec_config, input.frame_data.len());
    observe_encode_result(&result, expected_error, dst.len());

    if expected_error == Some(ERR_ENCODED_LENGTH_EXCEEDS_FIELD_CAPACITY) {
        assert_exact_encode_error(&result, ERR_ENCODED_LENGTH_EXCEEDS_FIELD_CAPACITY);
    }
}

fn test_length_adjustment_edge_cases(input: &LengthDelimitedEncoderFuzzInput) {
    let mut codec = build_codec_from_config(&input.codec_config);
    let frame_data = BytesMut::from(input.frame_data.as_slice());
    let mut dst = BytesMut::new();

    let result = codec.encode(frame_data, &mut dst);

    let expected_error = expected_encode_error(&input.codec_config, input.frame_data.len());
    observe_encode_result(&result, expected_error, dst.len());

    if expected_error == Some(ERR_NEGATIVE_ENCODED_LENGTH) {
        assert_exact_encode_error(&result, ERR_NEGATIVE_ENCODED_LENGTH);
    } else if expected_error == Some(ERR_LENGTH_UNDERFLOW) {
        assert_exact_encode_error(&result, ERR_LENGTH_UNDERFLOW);
    }
}

fn test_buffer_overflow_safety(input: &LengthDelimitedEncoderFuzzInput) {
    let mut codec = build_codec_from_config(&input.codec_config);
    let frame_data = BytesMut::from(input.frame_data.as_slice());
    let mut dst = BytesMut::new();

    let result = codec.encode(frame_data, &mut dst);
    let expected_error = expected_encode_error(&input.codec_config, input.frame_data.len());
    observe_encode_result(&result, expected_error, dst.len());

    // Check that total buffer length calculation doesn't overflow
    let length_field_len: usize = input.codec_config.length_field_length.into();
    if let Some(_total_len) = length_field_len.checked_add(input.frame_data.len()) {
        // If no overflow in calculation, encoder should either succeed or fail gracefully
        observe_encode_result(&result, expected_error, dst.len());
    } else {
        // If overflow in calculation, should fail with overflow error
        assert_exact_encode_error(&result, ERR_FRAME_BUFFER_RESERVATION_OVERFLOWS);
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
