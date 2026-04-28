#![no_main]

//! Structure-aware fuzz target for `src/codec/framed_write.rs`.
//!
//! This harness models `FramedWrite<_, LinesCodec>` as a small state machine:
//! `send` appends line-encoded bytes into the pending buffer, and `poll_flush`
//! drains that buffer through a scripted `AsyncWrite` surface that can yield
//! `Pending`, partial writes, or `WriteZero`.
//!
//! The oracle pins three lifecycle properties:
//! - written bytes are always the committed prefix of the encoded stream
//! - buffered bytes are always the exact unwritten suffix
//! - cooperative backpressure yields only when the write-pass budget is spent

use arbitrary::Arbitrary;
use asupersync::codec::{FramedWrite, LinesCodec};
use asupersync::io::AsyncWrite;
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

const MAX_WRITE_PASSES_PER_POLL: usize = 32;
const MAX_OPS: usize = 48;
const MAX_LINE_LEN: usize = 64;
const MAX_WRITE_STEPS: usize = 128;
const MAX_FLUSH_STEPS: usize = 64;
const MAX_FINAL_FLUSHES: usize = 128;

#[derive(Arbitrary, Debug)]
struct LifecycleInput {
    initial_capacity: u8,
    operations: Vec<Operation>,
    write_steps: Vec<WriteDirective>,
    flush_steps: Vec<FlushDirective>,
}

#[derive(Arbitrary, Debug)]
enum Operation {
    Send(Vec<u8>),
    Flush,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum WriteDirective {
    Pending,
    Write(u8),
    WriteZero,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FlushDirective {
    Pending,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingReason {
    WriterBackpressure,
    CooperativeBudget,
    InnerFlushBackpressure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlushOutcome {
    Ready,
    Pending(PendingReason),
    Err(io::ErrorKind),
}

#[derive(Debug)]
struct TrackWaker(Arc<AtomicBool>);

impl Wake for TrackWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn tracking_waker(flag: Arc<AtomicBool>) -> Waker {
    Waker::from(Arc::new(TrackWaker(flag)))
}

#[derive(Debug, Clone)]
struct ScriptedWriter {
    sink: Vec<u8>,
    write_steps: VecDeque<WriteDirective>,
    flush_steps: VecDeque<FlushDirective>,
}

impl ScriptedWriter {
    fn new(write_steps: &[WriteDirective], flush_steps: &[FlushDirective]) -> Self {
        Self {
            sink: Vec::new(),
            write_steps: write_steps.iter().copied().collect(),
            flush_steps: flush_steps.iter().copied().collect(),
        }
    }
}

impl AsyncWrite for ScriptedWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let step = self
            .write_steps
            .pop_front()
            .unwrap_or(WriteDirective::Write(u8::MAX));
        match step {
            WriteDirective::Pending => Poll::Pending,
            WriteDirective::WriteZero => Poll::Ready(Ok(0)),
            WriteDirective::Write(limit) => {
                let n = usize::from(limit.max(1)).min(buf.len());
                self.sink.extend_from_slice(&buf[..n]);
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self
            .flush_steps
            .pop_front()
            .unwrap_or(FlushDirective::Ready)
        {
            FlushDirective::Pending => Poll::Pending,
            FlushDirective::Ready => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
struct LifecycleOracle {
    written: Vec<u8>,
    buffered: Vec<u8>,
    write_steps: VecDeque<WriteDirective>,
    flush_steps: VecDeque<FlushDirective>,
}

impl LifecycleOracle {
    fn new(write_steps: &[WriteDirective], flush_steps: &[FlushDirective]) -> Self {
        Self {
            written: Vec::new(),
            buffered: Vec::new(),
            write_steps: write_steps.iter().copied().collect(),
            flush_steps: flush_steps.iter().copied().collect(),
        }
    }

    fn send(&mut self, line: &[u8]) {
        self.buffered.extend_from_slice(line);
        self.buffered.push(b'\n');
    }

    fn poll_flush(&mut self) -> FlushOutcome {
        let mut write_passes = 0usize;
        while !self.buffered.is_empty() {
            if write_passes >= MAX_WRITE_PASSES_PER_POLL {
                return FlushOutcome::Pending(PendingReason::CooperativeBudget);
            }

            let step = self
                .write_steps
                .pop_front()
                .unwrap_or(WriteDirective::Write(u8::MAX));
            match step {
                WriteDirective::Pending => {
                    return FlushOutcome::Pending(PendingReason::WriterBackpressure);
                }
                WriteDirective::WriteZero => {
                    return FlushOutcome::Err(io::ErrorKind::WriteZero);
                }
                WriteDirective::Write(limit) => {
                    let n = usize::from(limit.max(1)).min(self.buffered.len());
                    self.written.extend_from_slice(&self.buffered[..n]);
                    self.buffered.drain(..n);
                    write_passes += 1;
                }
            }
        }

        match self
            .flush_steps
            .pop_front()
            .unwrap_or(FlushDirective::Ready)
        {
            FlushDirective::Pending => FlushOutcome::Pending(PendingReason::InnerFlushBackpressure),
            FlushDirective::Ready => FlushOutcome::Ready,
        }
    }
}

fuzz_target!(|input: LifecycleInput| {
    let operations: Vec<_> = input.operations.into_iter().take(MAX_OPS).collect();
    let write_steps: Vec<_> = input
        .write_steps
        .into_iter()
        .take(MAX_WRITE_STEPS)
        .collect();
    let flush_steps: Vec<_> = input
        .flush_steps
        .into_iter()
        .take(MAX_FLUSH_STEPS)
        .collect();

    let writer = ScriptedWriter::new(&write_steps, &flush_steps);
    let mut framed = FramedWrite::with_capacity(
        writer,
        LinesCodec::new(),
        usize::from(input.initial_capacity.max(1)),
    );
    let mut oracle = LifecycleOracle::new(&write_steps, &flush_steps);

    for (index, operation) in operations.iter().enumerate() {
        match operation {
            Operation::Send(bytes) => {
                let line = normalize_line(bytes);
                let text = String::from_utf8(line.clone()).expect("normalized line is UTF-8");
                framed
                    .send(text)
                    .expect("LinesCodec encodes owned UTF-8 lines");
                oracle.send(&line);
            }
            Operation::Flush => {
                let wake_flag = Arc::new(AtomicBool::new(false));
                let waker = tracking_waker(Arc::clone(&wake_flag));
                let mut cx = Context::from_waker(&waker);

                let actual = framed.poll_flush(&mut cx);
                let expected = oracle.poll_flush();
                assert_flush_matches(actual, expected, wake_flag.load(Ordering::SeqCst));
            }
        }

        assert_state_matches(
            &framed,
            &oracle,
            &format!("after operation {index}: {operation:?}"),
        );
    }

    for attempt in 0..MAX_FINAL_FLUSHES {
        if oracle.buffered.is_empty() {
            break;
        }

        let wake_flag = Arc::new(AtomicBool::new(false));
        let waker = tracking_waker(Arc::clone(&wake_flag));
        let mut cx = Context::from_waker(&waker);

        let actual = framed.poll_flush(&mut cx);
        let expected = oracle.poll_flush();
        assert_flush_matches(actual, expected, wake_flag.load(Ordering::SeqCst));
        assert_state_matches(
            &framed,
            &oracle,
            &format!("during final drain attempt {attempt}"),
        );

        if matches!(expected, FlushOutcome::Err(_)) {
            break;
        }
    }
});

fn normalize_line(bytes: &[u8]) -> Vec<u8> {
    let mut limited = bytes.to_vec();
    limited.truncate(MAX_LINE_LEN);
    String::from_utf8_lossy(&limited).into_owned().into_bytes()
}

fn assert_flush_matches(actual: Poll<io::Result<()>>, expected: FlushOutcome, woke: bool) {
    match expected {
        FlushOutcome::Ready => match actual {
            Poll::Ready(Ok(())) => {
                assert!(!woke, "ready flush should not self-wake");
            }
            other => panic!("expected Ready(Ok(())), got {other:?}"),
        },
        FlushOutcome::Err(kind) => match actual {
            Poll::Ready(Err(err)) => {
                assert_eq!(err.kind(), kind, "flush error kind drifted");
                assert!(!woke, "error flush should not self-wake");
            }
            other => panic!("expected Ready(Err({kind:?})), got {other:?}"),
        },
        FlushOutcome::Pending(reason) => {
            assert!(
                matches!(actual, Poll::Pending),
                "expected Pending for {reason:?}"
            );
            assert_eq!(
                woke,
                reason == PendingReason::CooperativeBudget,
                "wake behavior drifted for {reason:?}"
            );
        }
    }
}

fn assert_state_matches(
    framed: &FramedWrite<ScriptedWriter, LinesCodec>,
    oracle: &LifecycleOracle,
    context: &str,
) {
    assert_eq!(
        &framed.get_ref().sink,
        &oracle.written,
        "{context}: committed prefix drifted"
    );
    assert_eq!(
        &framed.write_buffer()[..],
        oracle.buffered.as_slice(),
        "{context}: buffered suffix drifted"
    );
}
