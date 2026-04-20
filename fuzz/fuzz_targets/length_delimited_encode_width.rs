//! Structure-aware fuzz target for LengthDelimitedCodec encode-width invariants.
//!
//! Focus:
//! - exact header-byte modeling for configured width/offset/endianness
//! - round-trip decode of concatenated encoded frames under partial delivery
//! - rejection of silent truncation when encoded length exceeds field width

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, BytesMut};
use asupersync::codec::{Decoder, Encoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;
use std::io;

const MAX_FRAMES: usize = 4;
const MAX_PAYLOAD_LEN: usize = 512;
const MAX_TOTAL_LEN: usize = 4096;

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

#[derive(Arbitrary, Debug, Clone)]
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

impl ConfigInput {
    fn realize_for_roundtrip(
        &self,
        min_payload_len: usize,
        max_payload_len: usize,
    ) -> Option<RealizedConfig> {
        let width = self.width.bytes();
        let offset = (self.offset as usize) % 4;
        let header_len = offset + width;
        let adjustment = self.adjustment as isize;

        let min_encodable_frame_len = if adjustment > 0 {
            adjustment as usize
        } else {
            0
        };
        let max_encodable_frame_len = if adjustment >= 0 {
            self.width.max_value().min(MAX_PAYLOAD_LEN as u64) as usize
        } else {
            let extra = adjustment.unsigned_abs() as u64;
            self.width
                .max_value()
                .saturating_sub(extra)
                .min(MAX_PAYLOAD_LEN as u64) as usize
        };

        let lower = min_payload_len.max(min_encodable_frame_len);
        let upper = max_payload_len.min(max_encodable_frame_len);
        if lower > upper {
            return None;
        }

        Some(RealizedConfig {
            width,
            offset,
            adjustment,
            num_skip: (self.num_skip as usize) % (header_len + 1),
            max_frame_length: upper
                .max(1)
                .max((self.max_frame_length as usize).min(MAX_PAYLOAD_LEN)),
            big_endian: self.big_endian,
        })
    }
}

#[derive(Arbitrary, Debug)]
enum Scenario {
    ValidRoundTrip {
        config: ConfigInput,
        frames: Vec<Vec<u8>>,
        chunk_sizes: Vec<u8>,
    },
    WidthOverflow {
        offset: u8,
        big_endian: bool,
        width: OverflowWidth,
        payload: Vec<u8>,
        overflow_by: u8,
    },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum OverflowWidth {
    One,
    Two,
    Three,
}

impl OverflowWidth {
    fn bytes(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
        }
    }

    fn max_value(self) -> u64 {
        match self {
            Self::One => u8::MAX as u64,
            Self::Two => u16::MAX as u64,
            Self::Three => 0x00FF_FFFF,
        }
    }
}

fuzz_target!(|scenario: Scenario| {
    match scenario {
        Scenario::ValidRoundTrip {
            config,
            frames,
            chunk_sizes,
        } => run_roundtrip(config, frames, chunk_sizes),
        Scenario::WidthOverflow {
            offset,
            big_endian,
            width,
            payload,
            overflow_by,
        } => run_width_overflow(offset, big_endian, width, payload, overflow_by),
    }
});

fn run_roundtrip(config_input: ConfigInput, frames: Vec<Vec<u8>>, chunk_sizes: Vec<u8>) {
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

    let min_payload_len = payloads.iter().map(Vec::len).min().unwrap_or(0);
    let max_payload_len = payloads.iter().map(Vec::len).max().unwrap_or(0);
    let Some(config) = config_input.realize_for_roundtrip(min_payload_len, max_payload_len) else {
        return;
    };

    let mut sanitized = Vec::with_capacity(payloads.len());
    for payload in payloads.drain(..) {
        let payload = sanitize_payload(
            payload,
            config.adjustment,
            config.width,
            config.max_frame_length,
        );
        sanitized.push(payload);
    }
    if sanitized
        .iter()
        .any(|payload| payload.len() > config.max_frame_length)
    {
        return;
    }

    let mut encoder = build_codec(config);
    let mut encoded = BytesMut::new();
    let mut expected_frames = Vec::new();

    for payload in &sanitized {
        let payload_buf = BytesMut::from(payload.as_slice());
        let manual = manual_encode_frame(config, payload);
        let before_len = encoded.len();

        encoder
            .encode(payload_buf, &mut encoded)
            .expect("sanitized roundtrip payloads must encode");

        assert_eq!(
            &encoded[before_len..],
            &manual[..],
            "encode output drifted from the manual framing model"
        );
        expected_frames.push(BytesMut::from(&manual[config.num_skip..]));
    }

    assert!(encoded.len() <= MAX_TOTAL_LEN);

    let mut decoder = build_codec(config);
    let mut read_buf = BytesMut::new();
    let mut decoded = Vec::new();
    let mut pos = 0usize;

    for chunk in chunk_sizes.into_iter().take(MAX_TOTAL_LEN.max(1)) {
        if pos >= encoded.len() {
            break;
        }
        let next = pos + ((chunk as usize) % 17).max(1);
        let end = next.min(encoded.len());
        read_buf.extend_from_slice(&encoded[pos..end]);
        pos = end;
        drain_decoded_frames(&mut decoder, &mut read_buf, &mut decoded);
    }

    if pos < encoded.len() {
        read_buf.extend_from_slice(&encoded[pos..]);
        drain_decoded_frames(&mut decoder, &mut read_buf, &mut decoded);
    }

    assert_eq!(
        decoded.len(),
        expected_frames.len(),
        "decode lost framed items"
    );
    for (actual, expected) in decoded.iter().zip(expected_frames.iter()) {
        assert_eq!(
            actual, expected,
            "decoded frame drifted from expected retained bytes"
        );
    }
    assert!(
        read_buf.is_empty(),
        "decoder left trailing bytes after complete input"
    );
}

fn run_width_overflow(
    offset: u8,
    big_endian: bool,
    width: OverflowWidth,
    payload: Vec<u8>,
    overflow_by: u8,
) {
    let payload = payload
        .into_iter()
        .take(MAX_PAYLOAD_LEN)
        .collect::<Vec<_>>();
    if payload.is_empty() {
        return;
    }

    let target_length = width.max_value() + 1 + u64::from(overflow_by % 8);
    let adjustment = i64::try_from(payload.len()).unwrap_or(i64::MAX)
        - i64::try_from(target_length).unwrap_or(i64::MAX);
    if adjustment >= 0 {
        return;
    }

    let mut builder = LengthDelimitedCodec::builder()
        .length_field_offset((offset as usize) % 4)
        .length_field_length(width.bytes())
        .length_adjustment(adjustment as isize)
        .num_skip(width.bytes())
        .max_frame_length(payload.len().max(1));

    builder = if big_endian {
        builder.big_endian()
    } else {
        builder.little_endian()
    };

    let mut codec = builder.new_codec();

    let mut dst = BytesMut::from(&b"sentinel"[..]);
    let original = dst.clone();
    let err = codec
        .encode(BytesMut::from(payload.as_slice()), &mut dst)
        .expect_err("width overflow must be rejected instead of truncating");

    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(dst, original, "failing encode must not mutate dst");
}

fn build_codec(config: RealizedConfig) -> LengthDelimitedCodec {
    let mut builder = LengthDelimitedCodec::builder()
        .length_field_offset(config.offset)
        .length_field_length(config.width)
        .length_adjustment(config.adjustment)
        .num_skip(config.num_skip)
        .max_frame_length(config.max_frame_length);

    builder = if config.big_endian {
        builder.big_endian()
    } else {
        builder.little_endian()
    };

    builder.new_codec()
}

fn sanitize_payload(
    payload: Vec<u8>,
    adjustment: isize,
    width: usize,
    max_frame_length: usize,
) -> Vec<u8> {
    let max_len_by_width = if adjustment >= 0 {
        max_length_for_width(width)
    } else {
        max_length_for_width(width).saturating_sub(adjustment.unsigned_abs())
    };
    let min_len = if adjustment > 0 {
        adjustment as usize
    } else {
        0
    };
    let target_len = payload
        .len()
        .min(max_frame_length)
        .min(max_len_by_width)
        .max(min_len);

    let mut payload = payload.into_iter().take(target_len).collect::<Vec<_>>();
    payload.resize(target_len, 0xA5);
    payload
}

fn drain_decoded_frames(
    decoder: &mut LengthDelimitedCodec,
    read_buf: &mut BytesMut,
    decoded: &mut Vec<BytesMut>,
) {
    loop {
        match decoder.decode(read_buf) {
            Ok(Some(frame)) => decoded.push(frame),
            Ok(None) => return,
            Err(err) => panic!("decode unexpectedly failed for encoded bytes: {err}"),
        }
    }
}

fn manual_encode_frame(config: RealizedConfig, payload: &[u8]) -> BytesMut {
    let mut frame = BytesMut::with_capacity(config.offset + config.width + payload.len());
    for _ in 0..config.offset {
        frame.put_u8(0);
    }

    let adjustment = config.adjustment as i64;
    let payload_len = i64::try_from(payload.len()).unwrap_or(i64::MAX);
    let encoded_len = u64::try_from(payload_len - adjustment).unwrap_or(u64::MAX);

    if config.big_endian {
        match config.width {
            1 => frame.put_u8(encoded_len as u8),
            2 => frame.put_u16(encoded_len as u16),
            3 => {
                frame.put_u8((encoded_len >> 16) as u8);
                frame.put_u16(encoded_len as u16);
            }
            4 => frame.put_u32(encoded_len as u32),
            5 => {
                frame.put_u8((encoded_len >> 32) as u8);
                frame.put_u32(encoded_len as u32);
            }
            6 => {
                frame.put_u16((encoded_len >> 32) as u16);
                frame.put_u32(encoded_len as u32);
            }
            7 => {
                frame.put_u8((encoded_len >> 48) as u8);
                frame.put_u16((encoded_len >> 32) as u16);
                frame.put_u32(encoded_len as u32);
            }
            8 => frame.put_u64(encoded_len),
            _ => unreachable!(),
        }
    } else {
        match config.width {
            1 => frame.put_u8(encoded_len as u8),
            2 => frame.put_u16_le(encoded_len as u16),
            3 => {
                frame.put_u16_le(encoded_len as u16);
                frame.put_u8((encoded_len >> 16) as u8);
            }
            4 => frame.put_u32_le(encoded_len as u32),
            5 => {
                frame.put_u32_le(encoded_len as u32);
                frame.put_u8((encoded_len >> 32) as u8);
            }
            6 => {
                frame.put_u32_le(encoded_len as u32);
                frame.put_u16_le((encoded_len >> 32) as u16);
            }
            7 => {
                frame.put_u32_le(encoded_len as u32);
                frame.put_u16_le((encoded_len >> 32) as u16);
                frame.put_u8((encoded_len >> 48) as u8);
            }
            8 => frame.put_u64_le(encoded_len),
            _ => unreachable!(),
        }
    }

    frame.extend_from_slice(payload);
    frame
}

fn max_length_for_width(width: usize) -> usize {
    match width {
        1..=7 => ((1u64 << (width * 8)) - 1).min(MAX_PAYLOAD_LEN as u64) as usize,
        8 => MAX_PAYLOAD_LEN,
        _ => 0,
    }
}
