#![no_main]

//! Fuzz target for src/codec/framed_read.rs partial-frame buffering.
//!
//! This target asserts that chunk boundaries do not change the decoded output
//! or terminal outcome for a simple length-prefixed wire format. It also checks
//! that truncated final frames fail closed instead of silently dropping bytes.

use arbitrary::Arbitrary;
use asupersync::{
    bytes::BytesMut,
    codec::{Decoder, FramedRead},
    io::{AsyncRead, ReadBuf},
    stream::Stream,
};
use libfuzzer_sys::fuzz_target;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, Waker},
};

const MAX_FRAMES: usize = 32;
const MAX_FRAME_LEN: usize = 64;
const MAX_CHUNK_PLAN: usize = 64;

#[derive(Arbitrary, Debug, Clone)]
struct PartialBufferingInput {
    frames: Vec<Vec<u8>>,
    chunk_sizes: Vec<u8>,
    truncate_tail: u8,
    initial_capacity: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodeOutcome {
    frames: Vec<Vec<u8>>,
    error_kind: Option<io::ErrorKind>,
}

struct LengthPrefixedDecoder;

impl Decoder for LengthPrefixedDecoder {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(&len) = src.first() else {
            return Ok(None);
        };
        let frame_len = len as usize;
        if src.len() < frame_len + 1 {
            return Ok(None);
        }

        let mut frame = src.split_to(frame_len + 1);
        let _ = frame.split_to(1);
        Ok(Some(frame.to_vec()))
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated partial frame",
        ))
    }
}

struct ChunkedReader {
    data: Vec<u8>,
    offset: usize,
    chunk_sizes: Vec<usize>,
    chunk_index: usize,
}

impl ChunkedReader {
    fn new(data: Vec<u8>, chunk_sizes: &[u8]) -> Self {
        let normalized = if chunk_sizes.is_empty() {
            vec![usize::MAX]
        } else {
            chunk_sizes
                .iter()
                .take(MAX_CHUNK_PLAN)
                .map(|size| usize::from((*size).max(1)))
                .collect()
        };
        Self {
            data,
            offset: 0,
            chunk_sizes: normalized,
            chunk_index: 0,
        }
    }
}

impl AsyncRead for ChunkedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset >= self.data.len() {
            return Poll::Ready(Ok(()));
        }

        let remaining = self.data.len() - self.offset;
        let next_chunk = self.chunk_sizes[self.chunk_index % self.chunk_sizes.len()];
        self.chunk_index += 1;
        let to_copy = remaining.min(next_chunk).min(buf.remaining());
        buf.put_slice(&self.data[self.offset..self.offset + to_copy]);
        self.offset += to_copy;
        Poll::Ready(Ok(()))
    }
}

fuzz_target!(|input: PartialBufferingInput| {
    let normalized_frames = normalize_frames(input.frames);
    let full_wire = encode_frames(&normalized_frames);
    let truncated_wire = truncate_wire(&full_wire, input.truncate_tail);
    let capacity = usize::from(input.initial_capacity.max(1));

    let baseline = decode_with_chunks(truncated_wire.clone(), &[u8::MAX], capacity);
    let chunked = decode_with_chunks(truncated_wire.clone(), &input.chunk_sizes, capacity);
    assert_eq!(
        chunked, baseline,
        "chunk boundaries changed FramedRead decoding outcome"
    );

    let expected_prefix = parse_complete_prefix(&truncated_wire);
    assert_eq!(
        chunked.frames, expected_prefix,
        "FramedRead lost or duplicated bytes across partial buffering"
    );

    if truncated_wire.len() == full_wire.len() {
        assert_eq!(
            chunked.frames, normalized_frames,
            "complete wire decode must preserve all frames"
        );
        assert_eq!(
            chunked.error_kind, None,
            "complete wire decode must succeed"
        );
    } else {
        assert_eq!(
            chunked.error_kind,
            Some(io::ErrorKind::UnexpectedEof),
            "truncated final frame must fail closed with UnexpectedEof"
        );
    }
});

fn normalize_frames(frames: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    frames
        .into_iter()
        .take(MAX_FRAMES)
        .map(|mut frame| {
            frame.truncate(MAX_FRAME_LEN);
            frame
        })
        .collect()
}

fn encode_frames(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut wire = Vec::new();
    for frame in frames {
        wire.push(frame.len() as u8);
        wire.extend_from_slice(frame);
    }
    wire
}

fn truncate_wire(wire: &[u8], truncate_tail: u8) -> Vec<u8> {
    let truncate_by = usize::from(truncate_tail).min(wire.len());
    wire[..wire.len() - truncate_by].to_vec()
}

fn parse_complete_prefix(wire: &[u8]) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while offset < wire.len() {
        let frame_len = usize::from(wire[offset]);
        let Some(end) = offset.checked_add(frame_len + 1) else {
            break;
        };
        if end > wire.len() {
            break;
        }
        frames.push(wire[offset + 1..end].to_vec());
        offset = end;
    }
    frames
}

fn decode_with_chunks(data: Vec<u8>, chunk_sizes: &[u8], capacity: usize) -> DecodeOutcome {
    let reader = ChunkedReader::new(data, chunk_sizes);
    let mut framed = FramedRead::with_capacity(reader, LengthPrefixedDecoder, capacity);
    let waker = Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);
    let mut frames = Vec::new();
    let mut error_kind = None;

    for _ in 0..4096 {
        match Pin::new(&mut framed).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => frames.push(frame),
            Poll::Ready(Some(Err(err))) => {
                error_kind = Some(err.kind());
                break;
            }
            Poll::Ready(None) => break,
            Poll::Pending => panic!("ChunkedReader should not yield pending"),
        }
    }

    DecodeOutcome { frames, error_kind }
}
