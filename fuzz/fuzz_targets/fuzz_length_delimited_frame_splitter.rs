//! Fuzz target for `src/codec/length_delimited.rs` frame splitting.
//!
//! Focus:
//! 1. Default big-endian frame splitting matches a small reference model
//! 2. Once a complete header arrives, partial payload buffering exposes only visible payload bytes
//! 3. Truncated tails never emit spurious frames
//! 4. Oversized length prefixes fail closed without consuming buffered header bytes

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;
use std::io;

const HEADER_LEN: usize = 4;
const MAX_FRAMES: usize = 8;
const MAX_PAYLOAD_LEN: usize = 512;
const MAX_CHUNKS: usize = 64;
const MAX_MAX_FRAME_LENGTH: usize = 4096;
const MAX_OVERSIZE_SUFFIX: usize = 32;

#[derive(Arbitrary, Debug)]
enum Scenario {
    ValidChunkedStream {
        max_frame_length: u16,
        frames: Vec<Vec<u8>>,
        chunk_sizes: Vec<u8>,
        truncate_tail: u16,
    },
    FragmentedPrefixVisibility {
        max_frame_length: u16,
        payload: Vec<u8>,
        prefix_bytes: u8,
        visible_payload_bytes: u16,
    },
    OversizedPrefix {
        max_frame_length: u16,
        overshoot: u16,
        header_prefix_bytes: u8,
        suffix: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Eq)]
struct SplitterModel {
    frames: Vec<Vec<u8>>,
    visible_tail: Vec<u8>,
}

fuzz_target!(|scenario: Scenario| match scenario {
    Scenario::ValidChunkedStream {
        max_frame_length,
        frames,
        chunk_sizes,
        truncate_tail,
    } => fuzz_valid_chunked_stream(max_frame_length, frames, chunk_sizes, truncate_tail),
    Scenario::FragmentedPrefixVisibility {
        max_frame_length,
        payload,
        prefix_bytes,
        visible_payload_bytes,
    } => fuzz_fragmented_prefix_visibility(
        max_frame_length,
        payload,
        prefix_bytes,
        visible_payload_bytes,
    ),
    Scenario::OversizedPrefix {
        max_frame_length,
        overshoot,
        header_prefix_bytes,
        suffix,
    } => fuzz_oversized_prefix(max_frame_length, overshoot, header_prefix_bytes, suffix),
});

fn fuzz_valid_chunked_stream(
    max_frame_length: u16,
    frames: Vec<Vec<u8>>,
    chunk_sizes: Vec<u8>,
    truncate_tail: u16,
) {
    let max_frame_length = realized_max(max_frame_length);
    let payloads = frames
        .into_iter()
        .take(MAX_FRAMES)
        .map(|payload| sanitize_payload(payload, max_frame_length))
        .collect::<Vec<_>>();
    if payloads.is_empty() {
        return;
    }

    let mut wire = Vec::new();
    for payload in &payloads {
        wire.extend_from_slice(&encode_frame(payload));
    }

    let truncate = usize::from(truncate_tail) % (wire.len() + 1);
    let keep_len = wire.len().saturating_sub(truncate);
    wire.truncate(keep_len);

    let expected = reference_splitter(&wire, max_frame_length)
        .expect("generated valid stream should stay within max frame length");

    let mut decoder = build_codec(max_frame_length);
    let mut read_buf = BytesMut::new();
    let mut actual_frames = Vec::new();
    let mut cursor = 0usize;

    for chunk in chunk_sizes.into_iter().take(MAX_CHUNKS) {
        if cursor >= wire.len() {
            break;
        }
        let step = ((chunk as usize) % 17).max(1);
        let end = cursor.saturating_add(step).min(wire.len());
        read_buf.extend_from_slice(&wire[cursor..end]);
        cursor = end;
        drain_frames(&mut decoder, &mut read_buf, &mut actual_frames);
    }

    if cursor < wire.len() {
        read_buf.extend_from_slice(&wire[cursor..]);
        drain_frames(&mut decoder, &mut read_buf, &mut actual_frames);
    }

    assert_eq!(
        actual_frames, expected.frames,
        "chunked frame splitting must match the reference model"
    );
    assert_eq!(
        &read_buf[..],
        expected.visible_tail.as_slice(),
        "decoder-visible tail must match the reference model after truncation"
    );
}

fn fuzz_fragmented_prefix_visibility(
    max_frame_length: u16,
    payload: Vec<u8>,
    prefix_bytes: u8,
    visible_payload_bytes: u16,
) {
    let max_frame_length = realized_max(max_frame_length);
    let payload = sanitize_non_empty_payload(payload, max_frame_length);
    let mut decoder = build_codec(max_frame_length.max(payload.len()));
    let wire = encode_frame(&payload);

    let prefix_bytes = usize::from(prefix_bytes) % HEADER_LEN;
    let visible_payload_bytes = usize::from(visible_payload_bytes) % payload.len();
    let payload_visible_end = HEADER_LEN + visible_payload_bytes;

    let mut read_buf = BytesMut::new();
    read_buf.extend_from_slice(&wire[..prefix_bytes]);
    let first = decoder
        .decode(&mut read_buf)
        .expect("partial header should not error");
    assert!(first.is_none(), "partial header must not emit a frame");
    assert_eq!(
        &read_buf[..],
        &wire[..prefix_bytes],
        "partial header bytes must stay buffered verbatim"
    );

    read_buf.extend_from_slice(&wire[prefix_bytes..payload_visible_end]);
    let second = decoder
        .decode(&mut read_buf)
        .expect("partial payload should not error");
    assert!(second.is_none(), "partial payload must not emit a frame");
    assert_eq!(
        &read_buf[..],
        &payload[..visible_payload_bytes],
        "after header consumption only visible payload bytes should remain buffered"
    );

    read_buf.extend_from_slice(&wire[payload_visible_end..]);
    let final_frame = decoder
        .decode(&mut read_buf)
        .expect("complete frame should decode")
        .expect("complete frame should be emitted");
    assert_eq!(
        &final_frame[..],
        &payload[..],
        "decoded frame payload changed across fragmented delivery"
    );
    assert!(
        read_buf.is_empty(),
        "complete frame should drain all buffered bytes"
    );
    assert!(
        decoder
            .decode(&mut read_buf)
            .expect("empty buffer should not error")
            .is_none(),
        "post-drain decode should return None"
    );
}

fn fuzz_oversized_prefix(
    max_frame_length: u16,
    overshoot: u16,
    header_prefix_bytes: u8,
    suffix: Vec<u8>,
) {
    let max_frame_length = realized_max(max_frame_length);
    let oversized_len = max_frame_length
        .saturating_add(usize::from(overshoot))
        .saturating_add(1);
    let mut wire = encode_header(oversized_len as u32);
    wire.extend_from_slice(
        &suffix
            .into_iter()
            .take(MAX_OVERSIZE_SUFFIX)
            .collect::<Vec<_>>(),
    );

    let split = usize::from(header_prefix_bytes) % HEADER_LEN;
    let mut decoder = build_codec(max_frame_length);
    let mut read_buf = BytesMut::new();
    read_buf.extend_from_slice(&wire[..split]);
    let first = decoder
        .decode(&mut read_buf)
        .expect("partial oversized header should not error");
    assert!(first.is_none(), "partial oversized header must remain pending");
    assert_eq!(
        &read_buf[..],
        &wire[..split],
        "partial oversized header bytes must stay buffered"
    );

    read_buf.extend_from_slice(&wire[split..]);
    let before = read_buf.clone();
    let err = decoder
        .decode(&mut read_buf)
        .expect_err("oversized prefix must be rejected");
    assert_eq!(
        err.kind(),
        io::ErrorKind::InvalidData,
        "oversized prefix must fail with InvalidData"
    );
    assert_eq!(
        &read_buf[..],
        &before[..],
        "oversized-prefix rejection must not consume buffered bytes"
    );

    let repeat = decoder
        .decode(&mut read_buf)
        .expect_err("oversized prefix must stay rejected on retry");
    assert_eq!(
        repeat.kind(),
        io::ErrorKind::InvalidData,
        "retrying oversized prefix must stay InvalidData"
    );
    assert_eq!(
        &read_buf[..],
        &before[..],
        "retrying oversized prefix must still leave the header untouched"
    );
}

fn reference_splitter(wire: &[u8], max_frame_length: usize) -> io::Result<SplitterModel> {
    let mut cursor = 0usize;
    let mut frames = Vec::new();

    loop {
        let remaining = &wire[cursor..];
        if remaining.len() < HEADER_LEN {
            return Ok(SplitterModel {
                frames,
                visible_tail: remaining.to_vec(),
            });
        }

        let declared_len = u32::from_be_bytes([
            remaining[0],
            remaining[1],
            remaining[2],
            remaining[3],
        ]) as usize;
        if declared_len > max_frame_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame length exceeds max_frame_length",
            ));
        }

        cursor += HEADER_LEN;
        let payload_remaining = &wire[cursor..];
        if payload_remaining.len() < declared_len {
            return Ok(SplitterModel {
                frames,
                visible_tail: payload_remaining.to_vec(),
            });
        }

        frames.push(payload_remaining[..declared_len].to_vec());
        cursor += declared_len;
    }
}

fn drain_frames(
    decoder: &mut LengthDelimitedCodec,
    read_buf: &mut BytesMut,
    actual_frames: &mut Vec<Vec<u8>>,
) {
    while let Some(frame) = decoder
        .decode(read_buf)
        .expect("valid chunked frame stream should decode")
    {
        actual_frames.push(frame.to_vec());
    }
}

fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut wire = encode_header(payload.len() as u32);
    wire.extend_from_slice(payload);
    wire
}

fn encode_header(len: u32) -> Vec<u8> {
    len.to_be_bytes().to_vec()
}

fn build_codec(max_frame_length: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(max_frame_length)
        .new_codec()
}

fn realized_max(max_frame_length: u16) -> usize {
    usize::from(max_frame_length).clamp(1, MAX_MAX_FRAME_LENGTH)
}

fn sanitize_payload(mut payload: Vec<u8>, max_frame_length: usize) -> Vec<u8> {
    payload.truncate(MAX_PAYLOAD_LEN.min(max_frame_length));
    payload
}

fn sanitize_non_empty_payload(mut payload: Vec<u8>, max_frame_length: usize) -> Vec<u8> {
    payload.truncate(MAX_PAYLOAD_LEN.min(max_frame_length));
    if payload.is_empty() {
        payload.push(0);
    }
    payload
}
