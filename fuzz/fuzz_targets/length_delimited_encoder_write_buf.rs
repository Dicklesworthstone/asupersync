//! Structure-aware fuzz target for LengthDelimitedCodec encode write_buf behavior.
//!
//! Focus:
//! - pre-filled destination buffers keep their prefix bytes intact
//! - decode-only builder knobs (`length_field_offset`, `num_skip`) do not leak
//!   into encoded wire bytes
//! - invalid length/width/max-frame configurations fail closed without mutating
//!   the destination buffer

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, Encoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;
use std::io::ErrorKind;

const MAX_PREFIX_LEN: usize = 128;
const MAX_VALID_PAYLOAD_LEN: usize = 1024;
const MAX_ERROR_PAYLOAD_LEN: usize = 512;

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
    num_skip: u8,
    adjustment: i16,
    max_frame_length: u16,
    big_endian: bool,
    dst_extra_capacity: u16,
}

#[derive(Debug, Clone, Copy)]
struct RealizedConfig {
    width: usize,
    offset: usize,
    num_skip: usize,
    adjustment: isize,
    max_frame_length: usize,
    big_endian: bool,
    dst_extra_capacity: usize,
}

impl ConfigInput {
    fn realize(&self) -> RealizedConfig {
        let width = self.width.bytes();
        let header_len = width + ((self.offset as usize) % 8);
        RealizedConfig {
            width,
            offset: (self.offset as usize) % 8,
            num_skip: (self.num_skip as usize) % (header_len + 1),
            adjustment: (self.adjustment as isize).clamp(-256, 256),
            max_frame_length: (self.max_frame_length as usize).min(MAX_VALID_PAYLOAD_LEN),
            big_endian: self.big_endian,
            dst_extra_capacity: (self.dst_extra_capacity as usize) % 256,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum RejectMode {
    NegativeEncodedLength,
    WidthOverflow,
    MaxFrameExceeded,
}

#[derive(Arbitrary, Debug)]
enum Scenario {
    AppendRoundTrip {
        config: ConfigInput,
        prefix: Vec<u8>,
        payload: Vec<u8>,
    },
    RejectInvalid {
        config: ConfigInput,
        prefix: Vec<u8>,
        seed: Vec<u8>,
        mode: RejectMode,
    },
}

fuzz_target!(|scenario: Scenario| {
    match scenario {
        Scenario::AppendRoundTrip {
            config,
            prefix,
            payload,
        } => run_append_roundtrip(config.realize(), prefix, payload),
        Scenario::RejectInvalid {
            config,
            prefix,
            seed,
            mode,
        } => run_reject_invalid(config.realize(), prefix, seed, mode),
    }
});

fn run_append_roundtrip(config: RealizedConfig, prefix: Vec<u8>, payload: Vec<u8>) {
    let Some(payload) = sanitize_valid_payload(payload, config) else {
        return;
    };

    let prefix = truncate(prefix, MAX_PREFIX_LEN);
    let mut dst = BytesMut::with_capacity(prefix.len().saturating_add(config.dst_extra_capacity));
    dst.put_slice(&prefix);
    let before = dst.clone();

    let mut configured_encoder = build_codec(config);
    configured_encoder
        .encode(BytesMut::from(payload.as_slice()), &mut dst)
        .expect("sanitized write_buf roundtrip input must encode");

    let mut canonical_encoded = BytesMut::new();
    build_canonical_codec(config)
        .encode(BytesMut::from(payload.as_slice()), &mut canonical_encoded)
        .expect("canonical encoder must encode sanitized payload");

    assert_eq!(&dst[..prefix.len()], prefix.as_slice());
    assert_eq!(&dst[prefix.len()..], canonical_encoded.as_ref());
    assert!(
        dst.capacity() >= dst.len(),
        "destination capacity must cover the appended bytes"
    );

    // Encode must append to the existing write buffer, not overwrite it.
    assert_eq!(before.len() + canonical_encoded.len(), dst.len());

    let mut decode_buf = BytesMut::from(&dst[prefix.len()..]);
    let mut decoder = build_canonical_codec(config);
    let frame = decoder
        .decode(&mut decode_buf)
        .expect("decode must not error after encode")
        .expect("encoded frame must decode");
    assert_eq!(frame.as_ref(), payload.as_slice());
    assert!(
        decode_buf.is_empty(),
        "canonical decoder must drain the encoded frame"
    );
}

fn run_reject_invalid(config: RealizedConfig, prefix: Vec<u8>, seed: Vec<u8>, mode: RejectMode) {
    let prefix = truncate(prefix, MAX_PREFIX_LEN);
    let mut dst = BytesMut::with_capacity(prefix.len().saturating_add(config.dst_extra_capacity));
    dst.put_slice(&prefix);
    let before = dst.clone();

    let invalid_case = match mode {
        RejectMode::NegativeEncodedLength => build_negative_length_case(config, seed),
        RejectMode::WidthOverflow => build_width_overflow_case(config, seed),
        RejectMode::MaxFrameExceeded => build_max_frame_exceeded_case(config, seed),
    };
    let Some((bad_config, payload)) = invalid_case else {
        return;
    };

    let err = build_codec(bad_config)
        .encode(BytesMut::from(payload.as_slice()), &mut dst)
        .expect_err("invalid write_buf input must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert_eq!(
        dst.as_ref(),
        before.as_ref(),
        "encode must not mutate dst on failure"
    );
}

fn sanitize_valid_payload(payload: Vec<u8>, config: RealizedConfig) -> Option<Vec<u8>> {
    let width_max = usize::try_from(match_width(config.width).max_value()).ok()?;
    let min_len = config.adjustment.max(0) as usize;
    let max_len_by_width = if config.adjustment >= 0 {
        width_max.saturating_add(config.adjustment as usize)
    } else {
        width_max.checked_sub(config.adjustment.unsigned_abs())?
    };
    let max_len = config
        .max_frame_length
        .min(max_len_by_width)
        .min(MAX_VALID_PAYLOAD_LEN);
    if min_len > max_len {
        return None;
    }

    let mut payload = truncate(payload, max_len);
    if payload.len() < min_len {
        payload.resize(min_len, 0);
    }
    Some(payload)
}

fn build_negative_length_case(
    mut config: RealizedConfig,
    seed: Vec<u8>,
) -> Option<(RealizedConfig, Vec<u8>)> {
    let positive_adjustment = config.adjustment.unsigned_abs().max(1).min(64);
    config.adjustment = positive_adjustment as isize;
    let payload_len = positive_adjustment.saturating_sub(1);
    let payload = padded_to(seed, payload_len.min(MAX_ERROR_PAYLOAD_LEN));
    Some((config, payload))
}

fn build_width_overflow_case(
    mut config: RealizedConfig,
    seed: Vec<u8>,
) -> Option<(RealizedConfig, Vec<u8>)> {
    config.adjustment = 0;
    let width_max = usize::try_from(match_width(config.width).max_value()).ok()?;
    let payload_len = width_max.checked_add(1)?;
    if payload_len > MAX_ERROR_PAYLOAD_LEN {
        return None;
    }
    config.max_frame_length = config.max_frame_length.max(payload_len);
    Some((config, padded_to(seed, payload_len)))
}

fn build_max_frame_exceeded_case(
    mut config: RealizedConfig,
    seed: Vec<u8>,
) -> Option<(RealizedConfig, Vec<u8>)> {
    config.adjustment = 0;
    let width_max = usize::try_from(match_width(config.width).max_value()).ok()?;
    let max_frame_length = config
        .max_frame_length
        .min(MAX_ERROR_PAYLOAD_LEN.saturating_sub(1));
    if max_frame_length >= width_max {
        return None;
    }
    let payload_len = max_frame_length.saturating_add(1);
    if payload_len > width_max {
        return None;
    }
    config.max_frame_length = max_frame_length;
    Some((config, padded_to(seed, payload_len)))
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

fn build_canonical_codec(config: RealizedConfig) -> LengthDelimitedCodec {
    let builder = LengthDelimitedCodec::builder()
        .length_field_offset(0)
        .length_field_length(config.width)
        .length_adjustment(config.adjustment)
        .max_frame_length(config.max_frame_length);
    if config.big_endian {
        builder.big_endian().new_codec()
    } else {
        builder.little_endian().new_codec()
    }
}

fn truncate(mut bytes: Vec<u8>, max_len: usize) -> Vec<u8> {
    bytes.truncate(max_len);
    bytes
}

fn padded_to(mut bytes: Vec<u8>, len: usize) -> Vec<u8> {
    bytes.truncate(len);
    if bytes.len() < len {
        bytes.resize(len, 0);
    }
    bytes
}

fn match_width(width: usize) -> Width {
    match width {
        1 => Width::One,
        2 => Width::Two,
        3 => Width::Three,
        4 => Width::Four,
        5 => Width::Five,
        6 => Width::Six,
        7 => Width::Seven,
        _ => Width::Eight,
    }
}
