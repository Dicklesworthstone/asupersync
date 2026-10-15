//! Structure-aware fuzzer for RFC 9221 DATAGRAM frame parsing.
//!
//! This target drives the ATP DATAGRAM frame parser with raw and generated
//! malformed frames. It asserts typed rejection for truncated, malformed, and
//! oversize inputs while accepted frames must consume bytes and round-trip
//! through the encoder.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::net::atp::datagram::frame::{DatagramError, DatagramFrame, DatagramFrameType};
use asupersync::types::outcome::Outcome;
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BYTES: usize = 4096;
const MAX_PAYLOAD_BYTES: usize = 2048;
const MAX_TRAILING_BYTES: usize = 256;
const DEFAULT_MAX_FRAME_SIZE: usize = 1200;

#[derive(Debug, Arbitrary)]
struct DatagramFuzzInput {
    mode: DatagramMode,
}

#[derive(Debug, Arbitrary)]
enum DatagramMode {
    Raw {
        bytes: Vec<u8>,
        max_size_hint: u16,
    },
    Structured {
        include_length: bool,
        payload: Vec<u8>,
        trailing: Vec<u8>,
        declared_len_bias: i8,
        truncate_tail: u8,
        max_size_bias: i8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedDecode {
    Accept {
        payload_len: usize,
        remaining: usize,
    },
    InvalidFrame,
    PayloadTooLarge,
}

fuzz_target!(|input: DatagramFuzzInput| {
    let result = catch_unwind(AssertUnwindSafe(|| exercise_datagram_input(input)));
    assert!(
        result.is_ok(),
        "DatagramFrame::decode panicked while parsing fuzz input"
    );
});

fn exercise_datagram_input(input: DatagramFuzzInput) {
    match input.mode {
        DatagramMode::Raw {
            bytes,
            max_size_hint,
        } => {
            if bytes.len() > MAX_RAW_BYTES {
                return;
            }
            let max_size = usize::from(max_size_hint).clamp(1, MAX_RAW_BYTES);
            let mut buf = BytesMut::from(bytes.as_slice());
            let before = buf.len();
            match DatagramFrame::decode(&mut buf, max_size) {
                Outcome::Ok(frame) => assert_accepted_datagram(frame, before, buf.len(), max_size),
                Outcome::Err(error) => assert_typed_datagram_error(&error),
                Outcome::Cancelled(reason) => {
                    panic!("pure DATAGRAM frame parsing should not cancel: {reason}")
                }
                Outcome::Panicked(payload) => {
                    panic!("pure DATAGRAM frame parsing surfaced panic payload: {payload}")
                }
            }
        }
        DatagramMode::Structured {
            include_length,
            payload,
            trailing,
            declared_len_bias,
            truncate_tail,
            max_size_bias,
        } => {
            let payload = limit_vec(&payload, MAX_PAYLOAD_BYTES);
            let trailing = limit_vec(&trailing, MAX_TRAILING_BYTES);
            let declared_len = biased_len(payload.len(), declared_len_bias);
            let emitted_payload_len = payload
                .len()
                .saturating_sub(usize::from(truncate_tail).min(payload.len()));
            let max_size =
                biased_max_size(declared_len, payload.len() + trailing.len(), max_size_bias);
            let mut buf = build_datagram_frame(
                include_length,
                &payload[..emitted_payload_len],
                &trailing,
                declared_len,
            );
            let expected = expected_decode(
                include_length,
                emitted_payload_len,
                trailing.len(),
                declared_len,
                max_size,
            );

            assert_decode_matches_expected(&mut buf, max_size, expected);
        }
    }
}

fn build_datagram_frame(
    include_length: bool,
    payload: &[u8],
    trailing: &[u8],
    declared_len: usize,
) -> BytesMut {
    let mut buf = BytesMut::new();
    let frame_type = if include_length {
        DatagramFrameType::DatagramWithLength
    } else {
        DatagramFrameType::Datagram
    };

    encode_varint(frame_type.to_varint(), &mut buf, "DATAGRAM frame type");
    if include_length {
        encode_varint(
            asupersync::net::atp::protocol::varint::VarInt::from_u64_unchecked(declared_len as u64),
            &mut buf,
            "DATAGRAM payload length",
        );
    }
    buf.extend_from_slice(payload);
    buf.extend_from_slice(trailing);
    buf
}

fn assert_decode_matches_expected(buf: &mut BytesMut, max_size: usize, expected: ExpectedDecode) {
    let before = buf.len();
    match (DatagramFrame::decode(buf, max_size), expected) {
        (
            Outcome::Ok(frame),
            ExpectedDecode::Accept {
                payload_len,
                remaining,
            },
        ) => {
            assert_eq!(frame.payload_len(), payload_len);
            assert_eq!(buf.len(), remaining);
            assert_accepted_datagram(frame, before, buf.len(), max_size);
        }
        (Outcome::Ok(frame), other) => panic!(
            "DATAGRAM parser accepted frame len={} when expected {other:?}",
            frame.payload_len()
        ),
        (Outcome::Err(DatagramError::InvalidFrame(_)), ExpectedDecode::InvalidFrame) => {}
        (Outcome::Err(DatagramError::PayloadTooLarge { .. }), ExpectedDecode::PayloadTooLarge) => {}
        (Outcome::Err(error), _) => panic!("unexpected DATAGRAM parser error: {error:?}"),
        (Outcome::Cancelled(reason), _) => {
            panic!("pure DATAGRAM frame parsing should not cancel: {reason}")
        }
        (Outcome::Panicked(payload), _) => {
            panic!("pure DATAGRAM frame parsing surfaced panic payload: {payload}")
        }
    }
}

fn expected_decode(
    include_length: bool,
    payload_len: usize,
    trailing_len: usize,
    declared_len: usize,
    max_size: usize,
) -> ExpectedDecode {
    if !include_length {
        let total_payload_len = payload_len + trailing_len;
        if total_payload_len > max_size {
            return ExpectedDecode::PayloadTooLarge;
        }
        return ExpectedDecode::Accept {
            payload_len: total_payload_len,
            remaining: 0,
        };
    }

    if declared_len > max_size {
        return ExpectedDecode::PayloadTooLarge;
    }

    let available = payload_len + trailing_len;
    if declared_len > available {
        return ExpectedDecode::InvalidFrame;
    }

    ExpectedDecode::Accept {
        payload_len: declared_len,
        remaining: available - declared_len,
    }
}

fn assert_accepted_datagram(
    frame: DatagramFrame,
    before_len: usize,
    after_len: usize,
    max_size: usize,
) {
    assert!(
        after_len < before_len,
        "DatagramFrame::decode accepted a frame without consuming bytes"
    );
    assert!(
        frame.payload_len() <= max_size,
        "DatagramFrame::decode accepted an oversize payload: {} > {}",
        frame.payload_len(),
        max_size
    );

    let mut encoded = BytesMut::new();
    match frame.encode(&mut encoded) {
        Outcome::Ok(()) => {}
        Outcome::Err(error) => panic!("accepted DATAGRAM frame failed to encode: {error:?}"),
        Outcome::Cancelled(reason) => {
            panic!("pure DATAGRAM frame encoding should not cancel: {reason}")
        }
        Outcome::Panicked(payload) => {
            panic!("pure DATAGRAM frame encoding surfaced panic payload: {payload}")
        }
    }

    let mut reparse = encoded.clone();
    match DatagramFrame::decode(&mut reparse, max_size.max(frame.payload_len())) {
        Outcome::Ok(round_trip) => {
            assert_eq!(round_trip.frame_type, frame.frame_type);
            assert_eq!(round_trip.data, frame.data);
        }
        Outcome::Err(error) => {
            panic!("encoded accepted DATAGRAM frame failed to decode: {error:?}")
        }
        Outcome::Cancelled(reason) => {
            panic!("pure DATAGRAM frame reparsing should not cancel: {reason}")
        }
        Outcome::Panicked(payload) => {
            panic!("pure DATAGRAM frame reparsing surfaced panic payload: {payload}")
        }
    }
}

fn assert_typed_datagram_error(error: &DatagramError) {
    let diagnostic = error.to_string();
    assert!(
        !diagnostic.trim().is_empty(),
        "DATAGRAM parser error diagnostics must be non-empty"
    );

    match error {
        DatagramError::PayloadTooLarge { size, max } => assert!(
            size > max,
            "PayloadTooLarge must report size > max, got {size} <= {max}"
        ),
        DatagramError::InvalidFrame(reason) | DatagramError::EncodingFailed(reason) => assert!(
            !reason.trim().is_empty(),
            "DATAGRAM parser error reason must be non-empty"
        ),
        DatagramError::NotSupported
        | DatagramError::CongestionDrop
        | DatagramError::Expired
        | DatagramError::PathUnavailable => {
            panic!("DATAGRAM parser returned non-parser operational error: {error:?}")
        }
    }
}

fn encode_varint(
    varint: asupersync::net::atp::protocol::varint::VarInt,
    buf: &mut BytesMut,
    context: &str,
) {
    match varint.encode(buf) {
        Outcome::Ok(()) => {}
        Outcome::Err(error) => panic!("{context} varint encode failed: {error:?}"),
        Outcome::Cancelled(reason) => panic!("{context} varint encode cancelled: {reason}"),
        Outcome::Panicked(payload) => panic!("{context} varint encode panicked: {payload}"),
    }
}

fn biased_len(base: usize, bias: i8) -> usize {
    let magnitude = usize::from(bias.unsigned_abs()).min(32);
    if bias.is_negative() {
        base.saturating_sub(magnitude)
    } else {
        base.saturating_add(magnitude)
            .min(MAX_PAYLOAD_BYTES + MAX_TRAILING_BYTES)
    }
}

fn biased_max_size(declared_len: usize, fallback_len: usize, bias: i8) -> usize {
    let base = if declared_len == 0 {
        fallback_len.max(1)
    } else {
        declared_len
    };
    let magnitude = usize::from(bias.unsigned_abs()).min(64);
    if bias.is_negative() {
        base.saturating_sub(magnitude).max(1)
    } else {
        base.saturating_add(magnitude)
            .clamp(1, DEFAULT_MAX_FRAME_SIZE.max(base))
    }
}

fn limit_vec(bytes: &[u8], limit: usize) -> Bytes {
    Bytes::copy_from_slice(&bytes[..bytes.len().min(limit)])
}
