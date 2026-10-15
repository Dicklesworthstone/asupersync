#![no_main]

//! Structure-aware fuzz target for src/codec/framed_read.rs decoder lifecycle.
//!
//! This harness freezes the narrow seam where `FramedRead` drains a complete
//! length-prefixed prefix via `decode`, then transitions to `decode_eof` once
//! the underlying reader reaches EOF. Chunking must not change:
//! - the frames emitted via `decode`
//! - whether a truncated tail is emitted or rejected by `decode_eof`
//! - the terminal post-error poisoning behavior

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

const MAX_FRAMES: usize = 24;
const MAX_FRAME_LEN: usize = 64;
const MAX_TAIL_PAYLOAD_LEN: usize = 64;
const MAX_CHUNK_PLAN: usize = 64;

#[derive(Arbitrary, Debug, Clone)]
struct LifecycleInput {
    frames: Vec<Vec<u8>>,
    tail_payload: Vec<u8>,
    tail_policy: TailPolicy,
    chunk_sizes: Vec<u8>,
    initial_capacity: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum TailPolicy {
    EmitRemainder,
    RejectRemainder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmitSource {
    Decode,
    DecodeEof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TerminalOutcome {
    Eof,
    Error(io::ErrorKind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LifecycleOutcome {
    frames: Vec<Vec<u8>>,
    sources: Vec<EmitSource>,
    terminal: TerminalOutcome,
    decode_eof_calls: usize,
    post_terminal_is_none: bool,
}

#[derive(Debug)]
struct LifecycleDecoder {
    tail_policy: TailPolicy,
    sources: Vec<EmitSource>,
    decode_eof_calls: usize,
}

impl LifecycleDecoder {
    fn new(tail_policy: TailPolicy) -> Self {
        Self {
            tail_policy,
            sources: Vec::new(),
            decode_eof_calls: 0,
        }
    }
}

impl Decoder for LifecycleDecoder {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(&len) = src.first() else {
            return Ok(None);
        };
        let frame_len = usize::from(len);
        if src.len() < frame_len + 1 {
            return Ok(None);
        }

        let mut frame = src.split_to(frame_len + 1);
        let prefix = frame.split_to(1);
        assert_eq!(
            usize::from(prefix[0]),
            frame_len,
            "length prefix changed while draining complete frame"
        );
        assert_eq!(
            frame.len(),
            frame_len,
            "payload length after prefix drain diverged from announced frame length"
        );
        self.sources.push(EmitSource::Decode);
        Ok(Some(frame.to_vec()))
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decode_eof_calls += 1;

        if src.is_empty() {
            return Ok(None);
        }

        match self.tail_policy {
            TailPolicy::EmitRemainder => {
                self.sources.push(EmitSource::DecodeEof);
                Ok(Some(src.split_to(src.len()).to_vec()))
            }
            TailPolicy::RejectRemainder => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated frame at EOF",
            )),
        }
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

fuzz_target!(|input: LifecycleInput| {
    let frames = normalize_frames(input.frames);
    let tail_wire = encode_truncated_tail(input.tail_payload);
    let wire = encode_frames(&frames, &tail_wire);
    let capacity = usize::from(input.initial_capacity.max(1));

    let baseline = drive_lifecycle(wire.clone(), &[u8::MAX], capacity, input.tail_policy);
    let chunked = drive_lifecycle(wire, &input.chunk_sizes, capacity, input.tail_policy);
    assert_eq!(
        chunked, baseline,
        "chunk boundaries changed the decode/decode_eof lifecycle"
    );

    let expected = expected_outcome(frames, tail_wire, input.tail_policy);
    assert_eq!(
        chunked, expected,
        "FramedRead decode/decode_eof lifecycle diverged from the structured oracle"
    );
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

fn encode_frames(frames: &[Vec<u8>], tail_wire: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    for frame in frames {
        wire.push(frame.len() as u8);
        wire.extend_from_slice(frame);
    }
    wire.extend_from_slice(tail_wire);
    wire
}

fn encode_truncated_tail(mut tail_payload: Vec<u8>) -> Vec<u8> {
    tail_payload.truncate(MAX_TAIL_PAYLOAD_LEN);
    if tail_payload.is_empty() {
        return Vec::new();
    }

    let announced_len = tail_payload.len() + 1;
    let mut tail = Vec::with_capacity(tail_payload.len() + 1);
    tail.push(announced_len as u8);
    tail.extend_from_slice(&tail_payload);
    tail
}

fn expected_outcome(
    mut frames: Vec<Vec<u8>>,
    tail_wire: Vec<u8>,
    tail_policy: TailPolicy,
) -> LifecycleOutcome {
    let mut sources = vec![EmitSource::Decode; frames.len()];

    if tail_wire.is_empty() {
        return LifecycleOutcome {
            frames,
            sources,
            terminal: TerminalOutcome::Eof,
            decode_eof_calls: 1,
            post_terminal_is_none: true,
        };
    }

    match tail_policy {
        TailPolicy::EmitRemainder => {
            frames.push(tail_wire);
            sources.push(EmitSource::DecodeEof);
            LifecycleOutcome {
                frames,
                sources,
                terminal: TerminalOutcome::Eof,
                decode_eof_calls: 2,
                post_terminal_is_none: true,
            }
        }
        TailPolicy::RejectRemainder => LifecycleOutcome {
            frames,
            sources,
            terminal: TerminalOutcome::Error(io::ErrorKind::UnexpectedEof),
            decode_eof_calls: 1,
            post_terminal_is_none: true,
        },
    }
}

fn drive_lifecycle(
    data: Vec<u8>,
    chunk_sizes: &[u8],
    capacity: usize,
    tail_policy: TailPolicy,
) -> LifecycleOutcome {
    let reader = ChunkedReader::new(data, chunk_sizes);
    let decoder = LifecycleDecoder::new(tail_policy);
    let mut framed = FramedRead::with_capacity(reader, decoder, capacity);
    let waker = Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);
    let mut frames = Vec::new();
    let terminal = loop {
        match Pin::new(&mut framed).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => frames.push(frame),
            Poll::Ready(Some(Err(err))) => break TerminalOutcome::Error(err.kind()),
            Poll::Ready(None) => break TerminalOutcome::Eof,
            Poll::Pending => panic!("ChunkedReader should not yield pending"),
        }
    };

    let sources = framed.decoder().sources.clone();
    let decode_eof_calls = framed.decoder().decode_eof_calls;
    let post_terminal_is_none =
        matches!(Pin::new(&mut framed).poll_next(&mut cx), Poll::Ready(None));

    LifecycleOutcome {
        frames,
        sources,
        terminal,
        decode_eof_calls,
        post_terminal_is_none,
    }
}
