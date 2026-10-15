//! Structure-aware fuzz target for length-delimited framing arithmetic.
//!
//! Focus:
//! - arbitrary framing config plus arbitrary input bytes
//! - malformed length arithmetic must return an error, never panic
//! - successful first-frame decodes must match the codec's framing model

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;
use std::io;

const MAX_INPUT_LEN: usize = 4 * 1024;
const MAX_OFFSET: usize = 16;
const MAX_SKIP: usize = 48;
const MAX_MAX_FRAME_LENGTH: usize = 2 * 1024;
const MAX_ABS_ADJUSTMENT: i64 = 1024;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum LengthFieldLength {
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
}

impl LengthFieldLength {
    fn bytes(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 4,
            Self::Five => 5,
            Self::Six => 6,
            Self::Seven => 7,
            Self::Eight => 8,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct ConfigInput {
    max_frame_length: u16,
    length_field_offset: u8,
    length_field_length: LengthFieldLength,
    length_adjustment: i16,
    num_skip: u8,
    big_endian: bool,
}

#[derive(Debug, Clone, Copy)]
struct RealizedConfig {
    max_frame_length: usize,
    length_field_offset: usize,
    length_field_length: usize,
    length_adjustment: i64,
    num_skip: usize,
    big_endian: bool,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    config: ConfigInput,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum ExpectedFirstDecode<'a> {
    Frame(&'a [u8]),
    NeedMore,
    Malformed,
}

fuzz_target!(|input: FuzzInput| {
    let config = realize_config(input.config);
    let bytes = input
        .bytes
        .into_iter()
        .take(MAX_INPUT_LEN)
        .collect::<Vec<_>>();

    assert_first_decode_matches_model(config, &bytes);
    drive_decoder(config, &bytes);
});

fn realize_config(input: ConfigInput) -> RealizedConfig {
    RealizedConfig {
        max_frame_length: usize::from(input.max_frame_length % (MAX_MAX_FRAME_LENGTH as u16)),
        length_field_offset: usize::from(input.length_field_offset % (MAX_OFFSET as u8)),
        length_field_length: input.length_field_length.bytes(),
        length_adjustment: i64::from(input.length_adjustment)
            .clamp(-MAX_ABS_ADJUSTMENT, MAX_ABS_ADJUSTMENT),
        num_skip: usize::from(input.num_skip % (MAX_SKIP as u8)),
        big_endian: input.big_endian,
    }
}

fn assert_first_decode_matches_model(config: RealizedConfig, bytes: &[u8]) {
    let expected = predict_first_decode(config, bytes);
    let mut codec = build_codec(config);
    let mut buf = BytesMut::from(bytes);

    match expected {
        ExpectedFirstDecode::Frame(frame) => {
            let decoded = codec
                .decode(&mut buf)
                .expect("model predicted a complete frame, not an error")
                .expect("model predicted a complete frame, not NeedMore");
            assert_eq!(&decoded[..], frame, "decoded frame diverged from model");
            assert_eq!(
                &buf[..],
                &bytes[bytes.len() - buf.len()..],
                "decoder consumed an unexpected number of bytes"
            );
        }
        ExpectedFirstDecode::NeedMore => {
            let result = codec.decode(&mut buf);
            assert!(
                matches!(&result, Ok(None)),
                "incomplete input must report NeedMore rather than {:?}",
                result
            );
            assert_eq!(
                &buf[..],
                bytes,
                "NeedMore must retain the buffered bytes unchanged"
            );
        }
        ExpectedFirstDecode::Malformed => {
            let result = codec.decode(&mut buf);
            assert!(
                result.is_err(),
                "malformed framing arithmetic must return io::Error rather than {:?}",
                result
            );
        }
    }
}

fn predict_first_decode<'a>(config: RealizedConfig, bytes: &'a [u8]) -> ExpectedFirstDecode<'a> {
    let header_len = config.length_field_offset + config.length_field_length;
    if bytes.len() < header_len {
        return ExpectedFirstDecode::NeedMore;
    }

    let raw_len = decode_raw_length(config, bytes);
    let frame_len = match adjusted_frame_len(config, raw_len) {
        Some(len) => len,
        None => return ExpectedFirstDecode::Malformed,
    };

    let total_frame_len = match header_len.checked_add(frame_len) {
        Some(len) => len,
        None => return ExpectedFirstDecode::Malformed,
    };

    let retained_len = match total_frame_len.checked_sub(config.num_skip) {
        Some(len) => len,
        None => return ExpectedFirstDecode::Malformed,
    };

    if bytes.len() < config.num_skip || bytes.len() < total_frame_len {
        return ExpectedFirstDecode::NeedMore;
    }

    let frame_end = config.num_skip + retained_len;
    ExpectedFirstDecode::Frame(&bytes[config.num_skip..frame_end])
}

fn decode_raw_length(config: RealizedConfig, bytes: &[u8]) -> u64 {
    let field_start = config.length_field_offset;
    let field_end = field_start + config.length_field_length;
    let field = &bytes[field_start..field_end];

    let mut value = 0u64;
    if config.big_endian {
        for &byte in field {
            value = (value << 8) | u64::from(byte);
        }
    } else {
        for (shift, &byte) in field.iter().enumerate() {
            value |= u64::from(byte) << (shift * 8);
        }
    }
    value
}

fn adjusted_frame_len(config: RealizedConfig, raw_len: u64) -> Option<usize> {
    let raw_len = i64::try_from(raw_len).ok()?;
    let adjusted = raw_len.checked_add(config.length_adjustment)?;
    if adjusted < 0 {
        return None;
    }

    let adjusted = usize::try_from(adjusted).ok()?;
    if adjusted > config.max_frame_length {
        return None;
    }
    Some(adjusted)
}

fn build_codec(config: RealizedConfig) -> LengthDelimitedCodec {
    let mut builder = LengthDelimitedCodec::builder()
        .max_frame_length(config.max_frame_length)
        .length_field_offset(config.length_field_offset)
        .length_field_length(config.length_field_length)
        .length_adjustment(
            isize::try_from(config.length_adjustment).expect("bounded adjustment fits in isize"),
        )
        .num_skip(config.num_skip);

    builder = if config.big_endian {
        builder.big_endian()
    } else {
        builder.little_endian()
    };

    builder.new_codec()
}

fn observe_decode_eof(
    config: RealizedConfig,
    codec: &mut LengthDelimitedCodec,
    buf: &mut BytesMut,
) {
    let before_len = buf.len();
    let result = codec.decode_eof(buf);

    assert!(
        buf.len() <= before_len,
        "decode_eof must not grow the source buffer"
    );

    match &result {
        Ok(Some(frame)) => {
            assert!(
                buf.len() < before_len,
                "successful EOF decode must consume buffered bytes"
            );

            let header_len = config.length_field_offset + config.length_field_length;
            let retained_header_len = header_len.saturating_sub(config.num_skip);
            let max_visible_len = config.max_frame_length.saturating_add(retained_header_len);
            assert!(
                frame.len() <= max_visible_len,
                "EOF frame length {} exceeds visible bound {}",
                frame.len(),
                max_visible_len
            );
        }
        Ok(None) => {
            assert!(
                buf.is_empty(),
                "Ok(None) at EOF must leave no buffered bytes"
            );
        }
        Err(error) => {
            assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
                ),
                "decode_eof returned unexpected error kind: {error:?}"
            );
            assert!(
                !error.to_string().is_empty(),
                "decode_eof errors must have a non-empty description"
            );
        }
    }
}

fn drive_decoder(config: RealizedConfig, bytes: &[u8]) {
    let mut codec = build_codec(config);
    let mut buf = BytesMut::from(bytes);
    let mut steps = 0usize;
    let max_steps = bytes.len().saturating_add(32);

    loop {
        steps += 1;
        assert!(
            steps <= max_steps,
            "decoder exceeded bounded progress on {} input bytes",
            bytes.len()
        );

        let before = buf.len();
        match codec.decode(&mut buf) {
            Ok(Some(_frame)) => {
                assert!(
                    buf.len() < before,
                    "successful decode must consume bytes from the buffer"
                );
                if buf.is_empty() {
                    break;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }

    observe_decode_eof(config, &mut codec, &mut buf);
}
