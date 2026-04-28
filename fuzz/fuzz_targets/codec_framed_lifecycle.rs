//! Structure-aware fuzz target for `codec/framed.rs` lifecycle semantics.
//!
//! This harness exercises the narrow cancel-safety seam in `Framed<T, U>`:
//! partial decode stays buffered across cancelled `poll_next` calls, and
//! partial writes resume cleanly across cancelled `poll_flush` calls.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::framed::Framed;
use asupersync::codec::{Decoder, Encoder, LinesCodec};
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::stream::Stream;
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const MAX_FRAMES: usize = 24;
const MAX_LINE_LEN: usize = 96;
const MAX_SPLIT_HINTS: usize = 8;
const MAX_EXTRA_PENDING_POLLS: usize = 4;
const MAX_RESUME_POLLS: usize = 64;

#[derive(Arbitrary, Debug)]
struct Scenario {
    frames: Vec<FramePlan>,
    close_after_flush: bool,
}

#[derive(Arbitrary, Debug)]
struct FramePlan {
    line_seed: Vec<u8>,
    split_hints: Vec<u8>,
    extra_pending_polls: u8,
    write_chunk_size: u8,
    pending_write_cycles: u8,
}

#[derive(Debug, Default)]
struct ScriptedDuplex {
    inbound_chunks: VecDeque<Vec<u8>>,
    written: Vec<u8>,
    write_chunk_size: usize,
    pending_write_cycles: usize,
    pending_before_next_write: bool,
    closed: bool,
}

impl ScriptedDuplex {
    fn feed_chunk(&mut self, chunk: Vec<u8>) {
        if !chunk.is_empty() {
            self.inbound_chunks.push_back(chunk);
        }
    }

    fn set_write_plan(&mut self, chunk_size: usize, pending_cycles: usize) {
        self.write_chunk_size = chunk_size.max(1);
        self.pending_write_cycles = pending_cycles;
        self.pending_before_next_write = false;
    }
}

impl AsyncRead for ScriptedDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(mut chunk) = self.inbound_chunks.pop_front() else {
            return Poll::Pending;
        };

        let to_copy = chunk.len().min(buf.remaining());
        buf.put_slice(&chunk[..to_copy]);
        chunk.drain(..to_copy);
        if !chunk.is_empty() {
            self.inbound_chunks.push_front(chunk);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport is closed",
            )));
        }

        if self.pending_before_next_write {
            self.pending_before_next_write = false;
            return Poll::Pending;
        }

        let to_write = buf.len().min(self.write_chunk_size.max(1));
        self.written.extend_from_slice(&buf[..to_write]);

        if self.pending_write_cycles > 0 && to_write < buf.len() {
            self.pending_write_cycles -= 1;
            self.pending_before_next_write = true;
        }

        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport is closed",
            )));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

type LinesFramed = Framed<ScriptedDuplex, LinesCodec>;

fuzz_target!(|scenario: Scenario| {
    if scenario.frames.len() > MAX_FRAMES {
        return;
    }

    let total_seed_bytes = scenario
        .frames
        .iter()
        .map(|frame| frame.line_seed.len() + frame.split_hints.len())
        .sum::<usize>();
    if total_seed_bytes > MAX_FRAMES * (MAX_LINE_LEN + MAX_SPLIT_HINTS) * 4 {
        return;
    }

    exercise_scenario(&scenario);
});

fn exercise_scenario(scenario: &Scenario) {
    let mut framed = Framed::new(ScriptedDuplex::default(), LinesCodec::new());
    let mut echoed_lines = Vec::new();

    for frame in &scenario.frames {
        let line = sanitize_line(&frame.line_seed);
        let wire = encode_line(&line);
        let chunks = split_wire(&wire, &frame.split_hints);
        let decoded = drive_decode_round(&mut framed, &line, &chunks, frame.extra_pending_polls);

        framed
            .send(decoded.clone())
            .expect("encoding sanitized line should succeed");

        let write_chunk_size = choose_write_chunk_size(wire.len(), frame.write_chunk_size);
        let pending_write_cycles =
            choose_pending_write_cycles(wire.len(), write_chunk_size, frame.pending_write_cycles);
        framed
            .get_mut()
            .set_write_plan(write_chunk_size, pending_write_cycles);

        let first_flush = poll_flush_once(&mut framed);
        if pending_write_cycles > 0 {
            assert!(matches!(first_flush, Poll::Pending));
            assert!(
                !framed.write_buffer().is_empty(),
                "cancelled flush must preserve buffered bytes"
            );

            let buffered_len = framed.write_buffer().len();
            assert!(matches!(poll_next_once(&mut framed), Poll::Pending));
            assert_eq!(
                framed.write_buffer().len(),
                buffered_len,
                "read-side polling must not disturb a cancelled flush"
            );
        } else {
            match first_flush {
                Poll::Ready(Ok(())) => {}
                other => panic!("flush without forced cancellation should complete: {other:?}"),
            }
        }

        drive_flush_to_ready(&mut framed);
        assert!(
            framed.write_buffer().is_empty(),
            "resumed flush must drain the buffered wire"
        );

        echoed_lines.push(decoded);
    }

    if scenario.close_after_flush {
        drive_close_to_ready(&mut framed);
    }

    let roundtrip = decode_written_lines(&framed.get_ref().written);
    assert_eq!(
        roundtrip, echoed_lines,
        "decoded outbound wire must match the echoed frames"
    );
}

fn sanitize_line(seed: &[u8]) -> String {
    let mut out = String::with_capacity(seed.len().min(MAX_LINE_LEN));
    for &byte in seed.iter().take(MAX_LINE_LEN) {
        let ch = match byte % 30 {
            26 => ' ',
            27 => '-',
            28 => '_',
            29 => '.',
            value => char::from(b'a' + value),
        };
        out.push(ch);
    }
    out
}

fn encode_line(line: &str) -> Vec<u8> {
    let mut codec = LinesCodec::new();
    let mut wire = BytesMut::new();
    codec
        .encode(line.to_owned(), &mut wire)
        .expect("encoding sanitized line should succeed");
    wire.to_vec()
}

fn split_wire(wire: &[u8], hints: &[u8]) -> Vec<Vec<u8>> {
    if wire.len() <= 1 {
        return vec![wire.to_vec()];
    }

    let mut chunks = Vec::new();
    let mut offset = 0usize;
    let first_len = 1 + usize::from(hints.first().copied().unwrap_or(0)) % (wire.len() - 1);
    chunks.push(wire[..first_len].to_vec());
    offset = first_len;

    for &hint in hints.iter().skip(1).take(MAX_SPLIT_HINTS.saturating_sub(1)) {
        if offset >= wire.len() {
            break;
        }
        let remaining = wire.len() - offset;
        let next_len = 1 + usize::from(hint) % remaining;
        chunks.push(wire[offset..offset + next_len].to_vec());
        offset += next_len;
    }

    if offset < wire.len() {
        chunks.push(wire[offset..].to_vec());
    }

    chunks
}

fn drive_decode_round(
    framed: &mut LinesFramed,
    expected: &str,
    chunks: &[Vec<u8>],
    extra_pending_polls: u8,
) -> String {
    assert!(
        !chunks.is_empty(),
        "encoded line must produce at least one chunk"
    );

    framed.get_mut().feed_chunk(chunks[0].clone());
    let first_poll = poll_next_once(framed);

    if chunks.len() == 1 {
        match first_poll {
            Poll::Ready(Some(Ok(line))) => {
                assert_eq!(line, expected);
                return line;
            }
            other => panic!("single-chunk frame should decode immediately: {other:?}"),
        }
    }

    match first_poll {
        Poll::Pending => {
            let buffered_len = framed.read_buffer().len();
            assert!(
                buffered_len > 0,
                "partial decode must preserve already-read bytes"
            );
            for _ in 0..usize::from(extra_pending_polls).min(MAX_EXTRA_PENDING_POLLS) {
                assert!(matches!(poll_next_once(framed), Poll::Pending));
                assert_eq!(
                    framed.read_buffer().len(),
                    buffered_len,
                    "re-polling a cancelled decode must not drop partial bytes"
                );
            }
        }
        other => panic!("split frame should stay pending until final chunk: {other:?}"),
    }

    for chunk in &chunks[1..chunks.len() - 1] {
        framed.get_mut().feed_chunk(chunk.clone());
        assert!(
            matches!(poll_next_once(framed), Poll::Pending),
            "intermediate chunks must not decode a line early"
        );
    }

    framed
        .get_mut()
        .feed_chunk(chunks.last().expect("final chunk exists").clone());
    match poll_next_once(framed) {
        Poll::Ready(Some(Ok(line))) => {
            assert_eq!(line, expected);
            line
        }
        other => panic!("final chunk should complete the frame: {other:?}"),
    }
}

fn choose_write_chunk_size(total_wire_len: usize, seed: u8) -> usize {
    if total_wire_len <= 1 {
        1
    } else {
        1 + usize::from(seed) % (total_wire_len - 1)
    }
}

fn choose_pending_write_cycles(total_wire_len: usize, write_chunk_size: usize, seed: u8) -> usize {
    if total_wire_len > write_chunk_size {
        1 + usize::from(seed % 2)
    } else {
        0
    }
}

fn poll_next_once(
    framed: &mut LinesFramed,
) -> Poll<Option<Result<String, asupersync::codec::LinesCodecError>>> {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    Pin::new(framed).poll_next(&mut cx)
}

fn poll_flush_once(framed: &mut LinesFramed) -> Poll<io::Result<()>> {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    framed.poll_flush(&mut cx)
}

fn drive_flush_to_ready(framed: &mut LinesFramed) {
    for _ in 0..MAX_RESUME_POLLS {
        match poll_flush_once(framed) {
            Poll::Ready(Ok(())) => return,
            Poll::Pending => {}
            Poll::Ready(Err(err)) => panic!("flush should not fail for scripted duplex: {err}"),
        }
    }
    panic!("flush did not complete within the resume budget");
}

fn drive_close_to_ready(framed: &mut LinesFramed) {
    for _ in 0..MAX_RESUME_POLLS {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        match framed.poll_close(&mut cx) {
            Poll::Ready(Ok(())) => return,
            Poll::Pending => {}
            Poll::Ready(Err(err)) => panic!("close should not fail for scripted duplex: {err}"),
        }
    }
    panic!("close did not complete within the resume budget");
}

fn decode_written_lines(wire: &[u8]) -> Vec<String> {
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from(wire);
    let mut decoded = Vec::new();

    loop {
        match codec
            .decode(&mut buf)
            .expect("scripted outbound wire must stay valid utf-8 lines")
        {
            Some(line) => decoded.push(line),
            None => break,
        }
    }

    assert!(
        buf.is_empty(),
        "fully flushed outbound wire should end on frame boundaries"
    );
    decoded
}
