//! Structure-aware fuzz target for LengthDelimitedCodec decoder state transitions.
//!
//! Focus:
//! - exact retained-byte expectations across chunked delivery
//! - partial-header state preservation before enough bytes arrive
//! - invalid header paths must fail without consuming buffered bytes

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;
use std::io;

const MAX_FRAMES: usize = 4;
const MAX_PAYLOAD_LEN: usize = 512;
const MAX_CHUNKS: usize = 64;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Width {
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
}

impl Width {
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
    width: Width,
    offset: u8,
    adjustment: i8,
    num_skip: u8,
    max_frame_length: u16,
    big_endian: bool,
}

#[derive(Debug, Clone, Copy)]
struct RealizedConfig {
    width: usize,
    offset: usize,
    adjustment: isize,
    num_skip: usize,
    max_frame_length: usize,
    big_endian: bool,
}

#[derive(Arbitrary, Debug)]
enum Scenario {
    ValidChunkedStream {
        config: ConfigInput,
        frames: Vec<Vec<u8>>,
        chunk_sizes: Vec<u8>,
        trailing: Vec<u8>,
    },
    PartialHeaderThenFrame {
        config: ConfigInput,
        payload: Vec<u8>,
        split_at: u8,
    },
    InvalidHeader {
        case: InvalidHeaderCase,
    },
}

#[derive(Arbitrary, Debug)]
enum InvalidHeaderCase {
    FrameTooLarge {
        width: Width,
        offset: u8,
        big_endian: bool,
        max_frame_length: u16,
        overshoot: u8,
        trailer: Vec<u8>,
    },
    NegativeAdjustedLength {
        width: Width,
        offset: u8,
        big_endian: bool,
        raw_length: u8,
        negative_adjustment: u8,
        trailer: Vec<u8>,
    },
    SkipPastFrame {
        width: Width,
        offset: u8,
        big_endian: bool,
        payload: Vec<u8>,
        overshoot: u8,
    },
}

fuzz_target!(|scenario: Scenario| match scenario {
    Scenario::ValidChunkedStream {
        config,
        frames,
        chunk_sizes,
        trailing,
    } => run_valid_chunked_stream(config, frames, chunk_sizes, trailing),
    Scenario::PartialHeaderThenFrame {
        config,
        payload,
        split_at,
    } => run_partial_header_then_frame(config, payload, split_at),
    Scenario::InvalidHeader { case } => run_invalid_header(case),
});

fn run_valid_chunked_stream(
    config_input: ConfigInput,
    frames: Vec<Vec<u8>>,
    chunk_sizes: Vec<u8>,
    trailing: Vec<u8>,
) {
    if frames.is_empty() {
        return;
    }

    let mut payloads = frames
        .into_iter()
        .take(MAX_FRAMES)
        .map(|frame| frame.into_iter().take(MAX_PAYLOAD_LEN).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    if payloads.is_empty() {
        return;
    }

    let Some((width, offset, adjustment, big_endian)) = realize_base_config(config_input) else {
        return;
    };
    let Some((min_payload, max_payload)) = valid_payload_bounds(width, adjustment) else {
        return;
    };

    for payload in &mut payloads {
        *payload = sanitize_payload(payload.clone(), min_payload, max_payload);
    }

    let header_len = offset + width;
    let min_total_frame_len = payloads
        .iter()
        .map(|payload| header_len + payload.len())
        .min()
        .unwrap_or(header_len);
    let num_skip = (config_input.num_skip as usize) % (min_total_frame_len + 1);
    let max_payload_len = payloads.iter().map(Vec::len).max().unwrap_or(0);
    let max_frame_length = max_payload_len
        .max(1)
        .max(config_input.max_frame_length as usize);

    let config = RealizedConfig {
        width,
        offset,
        adjustment,
        num_skip,
        max_frame_length,
        big_endian,
    };

    let mut wire = BytesMut::new();
    let mut expected_frames = Vec::new();
    for payload in &payloads {
        let frame = manual_encode_frame(config, payload);
        expected_frames.push(BytesMut::from(&frame[config.num_skip..]));
        wire.extend_from_slice(&frame);
    }

    let trailing_limit = header_len.saturating_sub(1);
    let trailing = trailing
        .into_iter()
        .take(trailing_limit.min(MAX_PAYLOAD_LEN))
        .collect::<Vec<_>>();
    wire.extend_from_slice(&trailing);

    let mut decoder = build_codec(config);
    let mut read_buf = BytesMut::new();
    let mut decoded = Vec::new();
    let mut cursor = 0usize;

    for chunk in chunk_sizes.into_iter().take(MAX_CHUNKS) {
        if cursor >= wire.len() {
            break;
        }
        let step = ((chunk as usize) % 17).max(1);
        let end = cursor.saturating_add(step).min(wire.len());
        read_buf.extend_from_slice(&wire[cursor..end]);
        cursor = end;
        drain_decoded_frames(&mut decoder, &mut read_buf, &mut decoded);
    }

    if cursor < wire.len() {
        read_buf.extend_from_slice(&wire[cursor..]);
        drain_decoded_frames(&mut decoder, &mut read_buf, &mut decoded);
    }

    assert_eq!(
        decoded, expected_frames,
        "decoded frames diverged from manual model"
    );
    assert_eq!(
        &read_buf[..],
        &trailing[..],
        "decoder retained unexpected tail bytes"
    );
}

fn run_partial_header_then_frame(config_input: ConfigInput, payload: Vec<u8>, split_at: u8) {
    let Some((width, offset, adjustment, big_endian)) = realize_base_config(config_input) else {
        return;
    };
    let Some((min_payload, max_payload)) = valid_payload_bounds(width, adjustment) else {
        return;
    };

    let payload = sanitize_payload(
        payload.into_iter().take(MAX_PAYLOAD_LEN).collect(),
        min_payload,
        max_payload,
    );
    let header_len = offset + width;
    let num_skip = (config_input.num_skip as usize) % (header_len + payload.len() + 1);
    let config = RealizedConfig {
        width,
        offset,
        adjustment,
        num_skip,
        max_frame_length: payload
            .len()
            .max(1)
            .max(config_input.max_frame_length as usize),
        big_endian,
    };

    let frame = manual_encode_frame(config, &payload);
    let split = (split_at as usize) % header_len;
    let mut first = BytesMut::from(&frame[..split]);
    let snapshot = first.clone();
    let mut decoder = build_codec(config);

    let partial = decoder
        .decode(&mut first)
        .expect("partial header must not error");
    assert!(partial.is_none(), "partial header must not decode a frame");
    assert_eq!(first, snapshot, "partial header must not consume bytes");

    first.extend_from_slice(&frame[split..]);
    let decoded = decoder
        .decode(&mut first)
        .expect("completed frame must decode")
        .expect("completed frame must produce bytes");
    assert_eq!(
        decoded,
        BytesMut::from(&frame[config.num_skip..]),
        "completed frame did not preserve retained-byte semantics"
    );
    assert!(
        first.is_empty(),
        "completed frame left unexpected trailing bytes"
    );
}

fn run_invalid_header(case: InvalidHeaderCase) {
    match case {
        InvalidHeaderCase::FrameTooLarge {
            width,
            offset,
            big_endian,
            max_frame_length,
            overshoot,
            trailer,
        } => {
            let width = width.bytes();
            let offset = (offset as usize) % 4;
            let max_frame_length = (max_frame_length as usize).max(1);
            let raw_length =
                ((max_frame_length + 1 + overshoot as usize) as u64).min(width_max_value(width));
            if raw_length <= max_frame_length as u64 {
                return;
            }

            let config = RealizedConfig {
                width,
                offset,
                adjustment: 0,
                num_skip: offset + width,
                max_frame_length,
                big_endian,
            };

            let mut src = manual_header_bytes(config, raw_length);
            src.extend_from_slice(&trailer.into_iter().take(8).collect::<Vec<_>>());
            assert_head_error(
                config,
                src,
                io::ErrorKind::InvalidData,
                "frame length exceeds max_frame_length",
            );
        }
        InvalidHeaderCase::NegativeAdjustedLength {
            width,
            offset,
            big_endian,
            raw_length,
            negative_adjustment,
            trailer,
        } => {
            let width = width.bytes();
            let offset = (offset as usize) % 4;
            let raw_length = (raw_length as u64).min(width_max_value(width));
            let adjustment = -((raw_length as isize) + 1 + (negative_adjustment as isize % 16));
            let config = RealizedConfig {
                width,
                offset,
                adjustment,
                num_skip: offset + width,
                max_frame_length: MAX_PAYLOAD_LEN,
                big_endian,
            };

            let mut src = manual_header_bytes(config, raw_length);
            src.extend_from_slice(&trailer.into_iter().take(8).collect::<Vec<_>>());
            assert_head_error(
                config,
                src,
                io::ErrorKind::InvalidData,
                "negative frame length",
            );
        }
        InvalidHeaderCase::SkipPastFrame {
            width,
            offset,
            big_endian,
            payload,
            overshoot,
        } => {
            let width = width.bytes();
            let offset = (offset as usize) % 4;
            let payload = payload
                .into_iter()
                .take(MAX_PAYLOAD_LEN.min(64))
                .collect::<Vec<_>>();
            let header_len = offset + width;
            let num_skip = header_len + payload.len() + 1 + overshoot as usize % 8;
            let config = RealizedConfig {
                width,
                offset,
                adjustment: 0,
                num_skip,
                max_frame_length: payload.len().max(1).max(64),
                big_endian,
            };

            let src = manual_encode_frame(config, &payload);
            assert_head_error(
                config,
                src,
                io::ErrorKind::InvalidData,
                "num_skip exceeds total frame length",
            );
        }
    }
}

fn realize_base_config(config: ConfigInput) -> Option<(usize, usize, isize, bool)> {
    let width = config.width.bytes();
    let offset = (config.offset as usize) % 4;
    let adjustment = config.adjustment as isize;
    let max_raw = width_max_value(width);
    if adjustment < 0 && (adjustment.unsigned_abs() as u64) > max_raw {
        return None;
    }
    Some((width, offset, adjustment, config.big_endian))
}

fn valid_payload_bounds(width: usize, adjustment: isize) -> Option<(usize, usize)> {
    let max_raw = width_max_value(width);
    if adjustment >= 0 {
        let min_payload = adjustment as usize;
        let max_payload = usize::try_from(max_raw)
            .ok()?
            .saturating_add(adjustment as usize);
        Some((
            min_payload.min(MAX_PAYLOAD_LEN),
            max_payload.min(MAX_PAYLOAD_LEN),
        ))
    } else {
        let max_payload = max_raw.checked_sub(adjustment.unsigned_abs() as u64)?;
        Some((0, usize::try_from(max_payload).ok()?.min(MAX_PAYLOAD_LEN)))
    }
}

fn sanitize_payload(mut payload: Vec<u8>, min_payload: usize, max_payload: usize) -> Vec<u8> {
    if max_payload < min_payload {
        return Vec::new();
    }
    let target_len = payload.len().clamp(min_payload, max_payload);
    payload.truncate(target_len);
    while payload.len() < target_len {
        payload.push((payload.len() as u8).wrapping_mul(17).wrapping_add(0x5a));
    }
    payload
}

fn build_codec(config: RealizedConfig) -> LengthDelimitedCodec {
    let builder = LengthDelimitedCodec::builder()
        .length_field_offset(config.offset)
        .length_field_length(config.width)
        .length_adjustment(config.adjustment)
        .num_skip(config.num_skip)
        .max_frame_length(config.max_frame_length);

    if config.big_endian {
        builder.big_endian().new_codec()
    } else {
        builder.little_endian().new_codec()
    }
}

fn manual_encode_frame(config: RealizedConfig, payload: &[u8]) -> BytesMut {
    let raw_length = raw_length_for_payload(payload.len(), config.adjustment)
        .expect("valid payloads must map to a header length");
    assert!(
        raw_length <= width_max_value(config.width),
        "manual frame exceeded configured width capacity"
    );

    let mut frame = manual_header_bytes(config, raw_length);
    frame.extend_from_slice(payload);
    frame
}

fn manual_header_bytes(config: RealizedConfig, raw_length: u64) -> BytesMut {
    let mut frame = BytesMut::new();
    for _ in 0..config.offset {
        frame.put_u8(0);
    }
    write_length_field(&mut frame, raw_length, config.width, config.big_endian);
    frame
}

fn write_length_field(dst: &mut BytesMut, raw_length: u64, width: usize, big_endian: bool) {
    if big_endian {
        let bytes = raw_length.to_be_bytes();
        dst.extend_from_slice(&bytes[8 - width..]);
    } else {
        let bytes = raw_length.to_le_bytes();
        dst.extend_from_slice(&bytes[..width]);
    }
}

fn raw_length_for_payload(payload_len: usize, adjustment: isize) -> Option<u64> {
    let payload_len = i64::try_from(payload_len).ok()?;
    let adjustment = i64::try_from(adjustment).ok()?;
    let raw_length = payload_len.checked_sub(adjustment)?;
    if raw_length < 0 {
        return None;
    }
    u64::try_from(raw_length).ok()
}

fn width_max_value(width: usize) -> u64 {
    match width {
        1..=7 => (1u64 << (width * 8)) - 1,
        8 => u64::MAX,
        _ => unreachable!("width is always 1..=8"),
    }
}

fn drain_decoded_frames(
    decoder: &mut LengthDelimitedCodec,
    buf: &mut BytesMut,
    decoded: &mut Vec<BytesMut>,
) {
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        assert!(
            iterations <= MAX_FRAMES + 2,
            "decoder failed to make progress"
        );
        match decoder.decode(buf) {
            Ok(Some(frame)) => decoded.push(frame),
            Ok(None) => break,
            Err(err) => panic!("valid stream unexpectedly errored: {err:?}"),
        }
    }
}

fn assert_head_error(
    config: RealizedConfig,
    src: BytesMut,
    kind: io::ErrorKind,
    expected_message: &str,
) {
    let before = src.clone();
    let mut decoder = build_codec(config);
    let mut first = src.clone();
    let err = decoder
        .decode(&mut first)
        .expect_err("invalid header must error");
    assert_eq!(err.kind(), kind);
    assert!(
        err.to_string().contains(expected_message),
        "unexpected error message: {err:?}"
    );
    assert_eq!(
        first, before,
        "invalid header must not consume buffered bytes"
    );

    let mut second = src;
    let err = decoder
        .decode(&mut second)
        .expect_err("decoder state must remain in head mode after header error");
    assert_eq!(err.kind(), kind);
    assert!(
        err.to_string().contains(expected_message),
        "unexpected second error message: {err:?}"
    );
    assert_eq!(
        second, before,
        "repeated invalid header decode must remain non-consuming"
    );
}
