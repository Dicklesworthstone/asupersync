//! Structure-aware fuzz target for LengthDelimitedCodec frame boundary handling.
//!
//! Focus:
//! - encode/decode round-trip across chunked delivery boundaries
//! - explicit max-frame enforcement on both encode and decode paths
//! - retained-byte semantics while a frame is only partially buffered

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, Encoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;
use std::io;

const MAX_FRAMES: usize = 4;
const MAX_PAYLOAD_LEN: usize = 512;
const MAX_CHUNKS: usize = 64;
const MAX_OFFSET: usize = 4;

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

    fn max_value(self) -> u64 {
        match self {
            Self::One => u8::MAX as u64,
            Self::Two => u16::MAX as u64,
            Self::Three => 0x00FF_FFFF,
            Self::Four => u32::MAX as u64,
            Self::Five => 0x0000_00FF_FFFF_FFFF,
            Self::Six => 0x0000_FFFF_FFFF_FFFF,
            Self::Seven => 0x00FF_FFFF_FFFF_FFFF,
            Self::Eight => u64::MAX,
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
    EncodeDecodeRoundTrip {
        config: ConfigInput,
        frames: Vec<Vec<u8>>,
        chunk_sizes: Vec<u8>,
        trailing: Vec<u8>,
    },
    MaxFrameEnforcement {
        width: Width,
        offset: u8,
        big_endian: bool,
        max_frame_length: u16,
        overshoot: u8,
        payload: Vec<u8>,
    },
    PartialFrameAccumulation {
        config: ConfigInput,
        payload: Vec<u8>,
        split_at: u16,
        completion_chunks: Vec<u8>,
    },
}

fuzz_target!(|scenario: Scenario| match scenario {
    Scenario::EncodeDecodeRoundTrip {
        config,
        frames,
        chunk_sizes,
        trailing,
    } => run_roundtrip(config, frames, chunk_sizes, trailing),
    Scenario::MaxFrameEnforcement {
        width,
        offset,
        big_endian,
        max_frame_length,
        overshoot,
        payload,
    } => run_max_frame_enforcement(
        width,
        offset,
        big_endian,
        max_frame_length,
        overshoot,
        payload,
    ),
    Scenario::PartialFrameAccumulation {
        config,
        payload,
        split_at,
        completion_chunks,
    } => run_partial_accumulation(config, payload, split_at, completion_chunks),
});

fn run_roundtrip(
    config_input: ConfigInput,
    frames: Vec<Vec<u8>>,
    chunk_sizes: Vec<u8>,
    trailing: Vec<u8>,
) {
    if frames.is_empty() {
        return;
    }

    let config = realize_config(config_input);
    let Some((min_payload, max_payload)) = payload_bounds(config, config_input.width) else {
        return;
    };

    let payloads = frames
        .into_iter()
        .take(MAX_FRAMES)
        .map(|payload| sanitize_payload(payload, min_payload, max_payload))
        .collect::<Vec<_>>();
    if payloads.is_empty() {
        return;
    }

    let mut encoder = build_codec(config);
    let mut wire = BytesMut::new();
    let mut expected = Vec::new();

    for payload in &payloads {
        let mut encoded = BytesMut::new();
        encoder
            .encode(BytesMut::from(payload.as_slice()), &mut encoded)
            .expect("sanitized payload must encode");
        expected.push(encoded[config.num_skip..].to_vec());
        wire.extend_from_slice(&encoded);
    }

    let trailing_limit = header_len(config).saturating_sub(1);
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
        drain_valid_frames(&mut decoder, &mut read_buf, &mut decoded);
    }

    if cursor < wire.len() {
        read_buf.extend_from_slice(&wire[cursor..]);
        drain_valid_frames(&mut decoder, &mut read_buf, &mut decoded);
    }

    assert_eq!(
        decoded, expected,
        "chunked decode must preserve frame boundaries"
    );
    assert_eq!(
        &read_buf[..],
        &trailing[..],
        "decoder must retain only the trailing partial frame bytes"
    );
}

fn run_max_frame_enforcement(
    width: Width,
    offset: u8,
    big_endian: bool,
    max_frame_length: u16,
    overshoot: u8,
    payload: Vec<u8>,
) {
    let width_bytes = width.bytes();
    let field_cap = usize::try_from(width.max_value().min(MAX_PAYLOAD_LEN as u64))
        .expect("length-field capacity fits in usize");
    if field_cap < 2 {
        return;
    }

    let max_frame_length = ((max_frame_length as usize) % field_cap).max(1);
    if max_frame_length >= field_cap {
        return;
    }

    let extra_room = field_cap - max_frame_length;
    let oversize_len = max_frame_length + 1 + ((overshoot as usize) % extra_room);
    let mut payload = payload.into_iter().take(oversize_len).collect::<Vec<_>>();
    if payload.len() < oversize_len {
        payload.resize(oversize_len, 0xA5);
    }

    let config = RealizedConfig {
        width: width_bytes,
        offset: (offset as usize) % MAX_OFFSET,
        adjustment: 0,
        num_skip: ((offset as usize) % MAX_OFFSET) + width_bytes,
        max_frame_length,
        big_endian,
    };

    let mut encoder = build_codec(config);
    let mut encoded = BytesMut::new();
    let encode_err = encoder
        .encode(BytesMut::from(payload.as_slice()), &mut encoded)
        .expect_err("oversized payload must fail encode");
    assert_eq!(encode_err.kind(), io::ErrorKind::InvalidData);

    let wire = manual_frame(config, oversize_len as u64, &payload);
    let mut decoder = build_codec(config);
    let mut src = BytesMut::from(&wire[..]);
    let decode_err = decoder
        .decode(&mut src)
        .expect_err("oversized declared length must fail decode");
    assert_eq!(decode_err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        &src[..],
        &wire[..],
        "decode must fail before consuming an oversized frame"
    );
}

fn run_partial_accumulation(
    config_input: ConfigInput,
    payload: Vec<u8>,
    split_at: u16,
    completion_chunks: Vec<u8>,
) {
    let config = realize_config(config_input);
    let Some((min_payload, max_payload)) = payload_bounds(config, config_input.width) else {
        return;
    };
    let payload = sanitize_payload(payload, min_payload, max_payload);

    let mut encoder = build_codec(config);
    let mut wire = BytesMut::new();
    encoder
        .encode(BytesMut::from(payload.as_slice()), &mut wire)
        .expect("sanitized payload must encode");

    if wire.len() < 2 {
        return;
    }

    let prefix_len = 1 + ((split_at as usize) % (wire.len() - 1));
    let mut decoder = build_codec(config);
    let mut buf = BytesMut::from(&wire[..prefix_len]);

    let partial = decoder
        .decode(&mut buf)
        .expect("partial frame must not error");
    assert!(
        partial.is_none(),
        "partial frame must accumulate until the full boundary is available"
    );

    let expected_start = if prefix_len < header_len(config) {
        0
    } else {
        config.num_skip
    };
    assert_eq!(
        &buf[..],
        &wire[expected_start..prefix_len],
        "partial frame accumulation must retain only still-visible bytes"
    );

    let mut decoded = Vec::new();
    let mut cursor = prefix_len;
    for chunk in completion_chunks.into_iter().take(MAX_CHUNKS) {
        if cursor >= wire.len() {
            break;
        }
        let step = ((chunk as usize) % 19).max(1);
        let end = cursor.saturating_add(step).min(wire.len());
        buf.extend_from_slice(&wire[cursor..end]);
        cursor = end;
        drain_valid_frames(&mut decoder, &mut buf, &mut decoded);
    }

    if cursor < wire.len() {
        buf.extend_from_slice(&wire[cursor..]);
        drain_valid_frames(&mut decoder, &mut buf, &mut decoded);
    }

    assert_eq!(
        decoded,
        vec![wire[config.num_skip..].to_vec()],
        "completed partial frame must decode to the same retained bytes"
    );
    assert!(buf.is_empty(), "completed partial frame must drain cleanly");
}

fn realize_config(input: ConfigInput) -> RealizedConfig {
    let width = input.width.bytes();
    let offset = (input.offset as usize) % MAX_OFFSET;
    let max_frame_length = (input.max_frame_length as usize).clamp(1, MAX_PAYLOAD_LEN);
    let num_skip = (input.num_skip as usize) % (offset + width + 1);
    RealizedConfig {
        width,
        offset,
        adjustment: input.adjustment as isize,
        num_skip,
        max_frame_length,
        big_endian: input.big_endian,
    }
}

fn payload_bounds(config: RealizedConfig, width: Width) -> Option<(usize, usize)> {
    let min_payload = config.adjustment.max(0) as usize;
    let upper_by_width =
        i128::from(width.max_value().min(MAX_PAYLOAD_LEN as u64)) + config.adjustment as i128;
    if upper_by_width < 0 {
        return None;
    }
    let max_payload = usize::try_from(upper_by_width)
        .ok()?
        .min(config.max_frame_length)
        .min(MAX_PAYLOAD_LEN);
    (min_payload <= max_payload).then_some((min_payload, max_payload))
}

fn sanitize_payload(mut payload: Vec<u8>, min_payload: usize, max_payload: usize) -> Vec<u8> {
    payload.truncate(max_payload);
    if payload.len() < min_payload {
        payload.resize(min_payload, 0);
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
    let builder = if config.big_endian {
        builder.big_endian()
    } else {
        builder.little_endian()
    };
    builder.new_codec()
}

fn manual_frame(config: RealizedConfig, raw_len: u64, payload: &[u8]) -> BytesMut {
    let mut frame = BytesMut::new();
    for _ in 0..config.offset {
        frame.put_u8(0);
    }
    write_length_field(&mut frame, raw_len, config.width, config.big_endian);
    frame.extend_from_slice(payload);
    frame
}

fn write_length_field(dst: &mut BytesMut, value: u64, width: usize, big_endian: bool) {
    if big_endian {
        for shift in (0..width).rev() {
            dst.put_u8((value >> (shift * 8)) as u8);
        }
    } else {
        for shift in 0..width {
            dst.put_u8((value >> (shift * 8)) as u8);
        }
    }
}

fn drain_valid_frames(
    decoder: &mut LengthDelimitedCodec,
    src: &mut BytesMut,
    decoded: &mut Vec<Vec<u8>>,
) {
    while let Some(frame) = decoder
        .decode(src)
        .expect("valid encoded stream must not error")
    {
        decoded.push(frame.to_vec());
    }
}

const fn header_len(config: RealizedConfig) -> usize {
    config.offset + config.width
}
