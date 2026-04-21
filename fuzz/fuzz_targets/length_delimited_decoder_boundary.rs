//! Focused fuzz target for LengthDelimitedCodec decoder boundary handling.
//!
//! This target exercises a narrow set of decoder-only invariants:
//! - incomplete headers are retained without consumption
//! - incomplete payloads are retained until completion
//! - zero-length frames decode successfully
//! - frames at exactly max_frame_length are accepted
//! - oversized declared lengths are rejected without panicking

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;
use std::io;

const HEADER_LEN: usize = 4;
const MAX_BOUNDARY: usize = 512;

#[derive(Arbitrary, Debug)]
enum Scenario {
    TruncatedHeader {
        partial_header: Vec<u8>,
        little_endian: bool,
        max_frame_length: u16,
    },
    TruncatedPayload {
        declared_len: u16,
        available: Vec<u8>,
        completion: Vec<u8>,
        little_endian: bool,
        max_frame_length: u16,
    },
    ZeroLength {
        trailer: Vec<u8>,
        little_endian: bool,
        max_frame_length: u16,
    },
    ExactMaxBoundary {
        payload: Vec<u8>,
        split_at: u16,
        little_endian: bool,
        max_frame_length: u16,
    },
    OversizedLength {
        overshoot: u8,
        little_endian: bool,
        max_frame_length: u16,
    },
}

fuzz_target!(|scenario: Scenario| match scenario {
    Scenario::TruncatedHeader {
        partial_header,
        little_endian,
        max_frame_length,
    } => fuzz_truncated_header(partial_header, little_endian, max_frame_length),
    Scenario::TruncatedPayload {
        declared_len,
        available,
        completion,
        little_endian,
        max_frame_length,
    } => fuzz_truncated_payload(
        declared_len,
        available,
        completion,
        little_endian,
        max_frame_length,
    ),
    Scenario::ZeroLength {
        trailer,
        little_endian,
        max_frame_length,
    } => fuzz_zero_length(trailer, little_endian, max_frame_length),
    Scenario::ExactMaxBoundary {
        payload,
        split_at,
        little_endian,
        max_frame_length,
    } => fuzz_exact_max_boundary(payload, split_at, little_endian, max_frame_length),
    Scenario::OversizedLength {
        overshoot,
        little_endian,
        max_frame_length,
    } => fuzz_oversized_length(overshoot, little_endian, max_frame_length),
});

fn fuzz_truncated_header(partial_header: Vec<u8>, little_endian: bool, max_frame_length: u16) {
    let mut codec = build_codec(little_endian, realized_max(max_frame_length));
    let partial_header = partial_header
        .into_iter()
        .take(HEADER_LEN.saturating_sub(1))
        .collect::<Vec<_>>();
    let mut buf = BytesMut::from(partial_header.as_slice());
    let before = buf.clone();

    let result = codec
        .decode(&mut buf)
        .expect("truncated header should not error");
    assert!(
        result.is_none(),
        "decoder must wait for a full length header"
    );
    assert_eq!(
        &buf[..],
        &before[..],
        "incomplete header bytes must be retained"
    );
}

fn fuzz_truncated_payload(
    declared_len: u16,
    available: Vec<u8>,
    completion: Vec<u8>,
    little_endian: bool,
    max_frame_length: u16,
) {
    let max_frame_length = realized_max(max_frame_length);
    let declared_len = usize::from(declared_len).clamp(1, max_frame_length.max(1));
    let initial_payload = available
        .into_iter()
        .take(declared_len.saturating_sub(1))
        .collect::<Vec<_>>();
    let initial_wire = encode_header(declared_len as u32, little_endian, &initial_payload);
    let mut buf = BytesMut::from(initial_wire.as_slice());
    let before = buf.clone();
    let mut codec = build_codec(little_endian, max_frame_length);

    let first = codec
        .decode(&mut buf)
        .expect("partial payload should not error");
    assert!(
        first.is_none(),
        "decoder must wait for the rest of the payload"
    );
    assert_eq!(
        &buf[..],
        &before[..],
        "incomplete payload bytes must stay buffered until completion"
    );

    let mut expected = initial_payload;
    let remaining = declared_len.saturating_sub(expected.len());
    let mut tail = completion.into_iter().take(remaining).collect::<Vec<_>>();
    if tail.len() < remaining {
        tail.resize(remaining, 0xAB);
    }
    expected.extend_from_slice(&tail);
    buf.extend_from_slice(&tail);

    let second = codec
        .decode(&mut buf)
        .expect("completed payload should decode")
        .expect("completed payload should yield a frame");
    assert_eq!(&second[..], &expected[..]);
    assert!(buf.is_empty(), "completed frame should drain the buffer");
}

fn fuzz_zero_length(trailer: Vec<u8>, little_endian: bool, max_frame_length: u16) {
    let mut codec = build_codec(little_endian, realized_max(max_frame_length));
    let trailer = trailer
        .into_iter()
        .take(HEADER_LEN.saturating_sub(1))
        .collect::<Vec<_>>();
    let wire = encode_header(0, little_endian, &[]);
    let mut buf = BytesMut::from(wire.as_slice());
    buf.extend_from_slice(&trailer);

    let frame = codec
        .decode(&mut buf)
        .expect("zero-length frame should not error")
        .expect("zero-length frame should decode");
    assert!(
        frame.is_empty(),
        "zero-length frame must decode to an empty payload"
    );
    assert_eq!(
        &buf[..],
        &trailer[..],
        "decoder must leave trailing partial bytes untouched after a zero-length frame"
    );
}

fn fuzz_exact_max_boundary(
    payload: Vec<u8>,
    split_at: u16,
    little_endian: bool,
    max_frame_length: u16,
) {
    let max_frame_length = realized_max(max_frame_length);
    let mut expected = payload
        .into_iter()
        .take(max_frame_length)
        .collect::<Vec<_>>();
    if expected.len() < max_frame_length {
        expected.resize(max_frame_length, 0x5A);
    }

    let wire = encode_header(max_frame_length as u32, little_endian, &expected);
    let first_len = (usize::from(split_at) % wire.len().max(1)).min(wire.len().saturating_sub(1));
    let mut buf = BytesMut::from(&wire[..first_len]);
    let mut codec = build_codec(little_endian, max_frame_length);

    let first = codec
        .decode(&mut buf)
        .expect("partial exact-max frame should not error");
    assert!(
        first.is_none(),
        "decoder must buffer an incomplete exact-max frame"
    );

    buf.extend_from_slice(&wire[first_len..]);
    let decoded = codec
        .decode(&mut buf)
        .expect("complete exact-max frame should not error")
        .expect("complete exact-max frame should decode");
    assert_eq!(&decoded[..], &expected[..]);
    assert!(
        buf.is_empty(),
        "exact-max frame should fully drain after decoding"
    );
}

fn fuzz_oversized_length(overshoot: u8, little_endian: bool, max_frame_length: u16) {
    let max_frame_length = realized_max(max_frame_length);
    let declared_len = max_frame_length
        .saturating_add(1)
        .saturating_add((overshoot as usize) % 16);
    let wire = encode_header(declared_len as u32, little_endian, &[]);
    let mut buf = BytesMut::from(wire.as_slice());
    let before = buf.clone();
    let mut codec = build_codec(little_endian, max_frame_length);

    let err = codec
        .decode(&mut buf)
        .expect_err("oversized declared length must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        &buf[..],
        &before[..],
        "oversized frame rejection must not consume buffered bytes"
    );
}

fn build_codec(little_endian: bool, max_frame_length: usize) -> LengthDelimitedCodec {
    let builder = LengthDelimitedCodec::builder()
        .length_field_length(HEADER_LEN)
        .max_frame_length(max_frame_length);
    if little_endian {
        builder.little_endian().new_codec()
    } else {
        builder.new_codec()
    }
}

fn realized_max(raw: u16) -> usize {
    usize::from(raw).clamp(1, MAX_BOUNDARY)
}

fn encode_header(length: u32, little_endian: bool, payload: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(HEADER_LEN + payload.len());
    if little_endian {
        wire.extend_from_slice(&length.to_le_bytes());
    } else {
        wire.extend_from_slice(&length.to_be_bytes());
    }
    wire.extend_from_slice(payload);
    wire
}
