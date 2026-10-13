//! Resumable, runtime-neutral asynchronous compression transfers.
//!
//! The caller supplies the source, sink, and their nonblocking poll functions.
//! The codec therefore remains std-only and creates no I/O authority or tasks.

use crate::{EncodeParams, StreamEncoder, StreamProgress, StreamStatus};
use std::future::poll_fn;
use std::io;
use std::task::{Context, Poll};

const BUFFER_SIZE: usize = 8192;
const POLL_STEPS: usize = 32;

/// Bytes accepted at the two I/O boundaries, including progress before a wait
/// or error. These are source/sink bytes, not estimates of codec progress.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TransferProgress {
    /// Bytes consumed from the source (plain for encoding, encoded for decoding).
    pub bytes_read: u64,
    /// Bytes accepted by the sink (encoded for encoding, plain for decoding).
    pub bytes_written: u64,
}

trait Transform {
    fn process(&mut self, input: &[u8], output: &mut [u8]) -> io::Result<StreamProgress>;
    fn finish(&mut self, output: &mut [u8]) -> io::Result<StreamProgress>;
}

impl Transform for StreamEncoder {
    fn process(&mut self, input: &[u8], output: &mut [u8]) -> io::Result<StreamProgress> {
        self.encode(input, output)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }

    fn finish(&mut self, output: &mut [u8]) -> io::Result<StreamProgress> {
        Ok(Self::finish(self, output))
    }
}

#[derive(Debug)]
struct Failed {
    kind: io::ErrorKind,
    message: String,
}

impl Failed {
    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

#[derive(Debug)]
struct Transfer<C> {
    codec: C,
    input: Box<[u8; BUFFER_SIZE]>,
    input_position: usize,
    input_length: usize,
    output: Box<[u8; BUFFER_SIZE]>,
    output_position: usize,
    output_length: usize,
    eof: bool,
    codec_finished: bool,
    complete: bool,
    progress: TransferProgress,
    failed: Option<Failed>,
}

impl<C: Transform> Transfer<C> {
    fn new(codec: C) -> Self {
        Self {
            codec,
            input: Box::new([0; BUFFER_SIZE]),
            input_position: 0,
            input_length: 0,
            output: Box::new([0; BUFFER_SIZE]),
            output_position: 0,
            output_length: 0,
            eof: false,
            codec_finished: false,
            complete: false,
            progress: TransferProgress::default(),
            failed: None,
        }
    }

    // I/O Interrupted is resumable (including cooperative cancellation). Do
    // not retry it in a tight loop or poison a retained session. All other
    // errors are terminal: replaying after an ambiguous failure is unsafe.
    fn fail<T>(&mut self, error: io::Error, resumable: bool) -> Poll<io::Result<T>> {
        if !resumable || error.kind() != io::ErrorKind::Interrupted {
            self.failed = Some(Failed {
                kind: error.kind(),
                message: error.to_string(),
            });
        }
        Poll::Ready(Err(error))
    }

    fn poll<S, D, R, W, F>(
        &mut self,
        cx: &mut Context<'_>,
        source: &mut S,
        destination: &mut D,
        read: &mut R,
        write: &mut W,
        flush: &mut F,
    ) -> Poll<io::Result<TransferProgress>>
    where
        S: ?Sized,
        D: ?Sized,
        R: FnMut(&mut S, &mut Context<'_>, &mut [u8]) -> Poll<io::Result<usize>>,
        W: FnMut(&mut D, &mut Context<'_>, &[u8]) -> Poll<io::Result<usize>>,
        F: FnMut(&mut D, &mut Context<'_>) -> Poll<io::Result<()>>,
    {
        if let Some(failed) = &self.failed {
            return Poll::Ready(Err(failed.error()));
        }
        if self.complete {
            return Poll::Ready(Ok(self.progress));
        }
        for _ in 0..POLL_STEPS {
            // Never accept another source read while output is backpressured.
            if self.output_position < self.output_length {
                let pending = &self.output[self.output_position..self.output_length];
                let count = match write(destination, cx, pending) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return self.fail(error, true),
                    Poll::Ready(Ok(0)) => {
                        return self.fail(io::ErrorKind::WriteZero.into(), false);
                    }
                    Poll::Ready(Ok(count)) if count <= pending.len() => count,
                    Poll::Ready(Ok(_)) => {
                        return self.fail(
                            io::Error::new(io::ErrorKind::InvalidData, "sink overreported a write"),
                            false,
                        );
                    }
                };
                self.output_position += count;
                let Some(total) = self.progress.bytes_written.checked_add(count as u64) else {
                    return self.fail(io::Error::other("transfer byte count overflow"), false);
                };
                self.progress.bytes_written = total;
                continue;
            }
            if self.codec_finished {
                return match flush(destination, cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => self.fail(error, true),
                    Poll::Ready(Ok(())) => {
                        self.complete = true;
                        Poll::Ready(Ok(self.progress))
                    }
                };
            }

            let buffered = self.input_length - self.input_position;
            let step = if self.eof && buffered == 0 {
                self.codec.finish(&mut self.output[..])
            } else {
                self.codec.process(
                    &self.input[self.input_position..self.input_length],
                    &mut self.output[..],
                )
            };
            let step = match step {
                Ok(step) => step,
                Err(error) => return self.fail(error, false),
            };
            if step.input_read > buffered || step.output_written > BUFFER_SIZE {
                return self.fail(io::Error::other("invalid codec progress"), false);
            }
            self.input_position += step.input_read;
            self.output_position = 0;
            self.output_length = step.output_written;
            self.codec_finished = step.status == StreamStatus::Finished;
            if step.input_read != 0 || step.output_written != 0 || self.codec_finished {
                continue;
            }
            // Frame boundaries may change codec state without moving bytes.
            // They are not transport EOF; bounded polling handles empty frames.
            if step.status == StreamStatus::FrameFinished {
                continue;
            }
            if self.eof || self.input_position != self.input_length
                || step.status != StreamStatus::NeedInput
            {
                return self.fail(io::Error::other("codec made no progress"), false);
            }
            self.input_position = 0;
            self.input_length = 0;
            match read(source, cx, &mut self.input[..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return self.fail(error, true),
                Poll::Ready(Ok(0)) => self.eof = true,
                Poll::Ready(Ok(count)) if count <= BUFFER_SIZE => {
                    self.input_length = count;
                    let Some(total) = self.progress.bytes_read.checked_add(count as u64) else {
                        return self.fail(io::Error::other("transfer byte count overflow"), false);
                    };
                    self.progress.bytes_read = total;
                }
                Poll::Ready(Ok(_)) => {
                    return self.fail(
                        io::Error::new(io::ErrorKind::InvalidData, "source overreported a read"),
                        false,
                    );
                }
            }
        }
        // A perpetually ready source/sink must not monopolize the executor.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// A caller-owned asynchronous source-to-sink Zstandard encoding session.
///
/// Retain the session AND the same source/sink when dropping a `run` future:
/// read-ahead, pending compressed output, partial writes, EOF and flush state
/// stay in the session, so a new `run` resumes instead of losing or replaying
/// bytes. Cooperative cancellation must come from the supplied callbacks;
/// this session never inspects an ambient runtime context. The guarantee
/// assumes each callback consumes/commits bytes only
/// when returning `Ready(Ok(n))`, never on `Pending` or `Err`. The callbacks
/// must register the supplied waker before returning `Pending`.
///
/// Storage is the encoder's bounded workspace plus two 8 KiB I/O buffers.
/// Every poll performs at most 32 state-machine iterations, then self-wakes.
/// Input is emitted when a frame fills or source EOF seals a partial frame;
/// this transfer is not an interactive per-message flush protocol.
/// Codec work within an iteration is bounded by the configured frame size,
/// not by a wall-clock deadline. No tasks, threads or ambient I/O are created.
///
/// EOF finalizes the codec before flushing the sink. Completion does not
/// shut down or drop the sink: the caller retains connection/file ownership.
/// Dropping this session is not finalization and discards its pending bytes.
/// A returned `Interrupted` I/O error is resumable; other errors are terminal.
/// The bytes already accepted by the sink are not rolled back on failure.
///
/// Poll callbacks receive their I/O object separately, so the write and flush
/// callbacks can use the SAME sink without competing mutable captures. For an
/// Asupersync writer they can call `Pin::new(sink).poll_write(cx, bytes)` and
/// `Pin::new(sink).poll_flush(cx)`. A reader callback wraps its output slice
/// in `asupersync::io::ReadBuf` and returns the filled length on success.
#[derive(Debug)]
pub struct EncodeTransfer {
    inner: Transfer<StreamEncoder>,
}

impl EncodeTransfer {
    /// Creates a session with an explicit plain-frame bound (1 through 8 MiB).
    pub fn new(params: EncodeParams, frame_size: usize) -> Result<Self, crate::StreamEncodeError> {
        Ok(Self {
            inner: Transfer::new(StreamEncoder::new(params, frame_size)?),
        })
    }

    /// Snapshot of I/O progress, also available after cancellation or failure.
    pub fn progress(&self) -> TransferProgress {
        self.inner.progress
    }

    /// Whether final output AND the sink flush have completed successfully.
    pub fn is_finished(&self) -> bool {
        self.inner.complete
    }

    /// Drives the retained session once. `read` returns zero only at EOF.
    /// An empty source is encoded as a valid empty frame. Success is idempotent
    /// and subsequent calls do not touch either endpoint.
    pub fn poll_transfer<S, D, R, W, F>(
        &mut self,
        cx: &mut Context<'_>,
        source: &mut S,
        destination: &mut D,
        read: &mut R,
        write: &mut W,
        flush: &mut F,
    ) -> Poll<io::Result<TransferProgress>>
    where
        S: ?Sized,
        D: ?Sized,
        R: FnMut(&mut S, &mut Context<'_>, &mut [u8]) -> Poll<io::Result<usize>>,
        W: FnMut(&mut D, &mut Context<'_>, &[u8]) -> Poll<io::Result<usize>>,
        F: FnMut(&mut D, &mut Context<'_>) -> Poll<io::Result<()>>,
    {
        self.inner.poll(cx, source, destination, read, write, flush)
    }

    /// Runs until EOF, codec finalization, and sink flush. Dropping this
    /// borrowing future leaves the session ready to resume with the same I/O.
    pub async fn run<S, D, R, W, F>(
        &mut self,
        source: &mut S,
        destination: &mut D,
        mut read: R,
        mut write: W,
        mut flush: F,
    ) -> io::Result<TransferProgress>
    where
        S: ?Sized,
        D: ?Sized,
        R: FnMut(&mut S, &mut Context<'_>, &mut [u8]) -> Poll<io::Result<usize>>,
        W: FnMut(&mut D, &mut Context<'_>, &[u8]) -> Poll<io::Result<usize>>,
        F: FnMut(&mut D, &mut Context<'_>) -> Poll<io::Result<()>>,
    {
        poll_fn(|cx| self.poll_transfer(cx, source, destination, &mut read, &mut write, &mut flush))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{EncodeTransfer, TransferProgress};
    use crate::{DecodeLimits, EncodeParams, Level, decode_all, encode_all};
    use std::future::Future;
    use std::io;
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn complete<F: Future>(future: F) -> F::Output {
        let wake_count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wake_count));
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!(future);
        for _ in 0..500_000 {
            let before = wake_count.0.load(Ordering::Relaxed);
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(result) => return result,
                Poll::Pending => assert!(
                    wake_count.0.load(Ordering::Relaxed) > before,
                    "the scripted callbacks or transfer budget must arrange another poll"
                ),
            }
        }
        panic!("transfer did not terminate within the test poll budget");
    }

    fn alternating_wait(state: &mut Option<bool>, cx: &Context<'_>) -> bool {
        let Some(pending) = state else { return false; };
        let wait = *pending;
        *pending = !wait;
        if wait {
            cx.waker().wake_by_ref();
        }
        wait
    }

    struct Source {
        bytes: Vec<u8>,
        offset: usize,
        chunk: usize,
        calls: usize,
        interrupt_at: Option<usize>,
        alternate_pending: Option<bool>,
    }

    impl Source {
        fn new(bytes: &[u8], chunk: usize) -> Self {
            Self {
                bytes: bytes.to_vec(), offset: 0, chunk, calls: 0,
                interrupt_at: None, alternate_pending: None,
            }
        }
        fn read(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
            assert!(!out.is_empty(), "an empty buffer cannot establish EOF");
            self.calls += 1;
            if self.interrupt_at.is_some_and(|at| self.offset >= at) {
                self.interrupt_at = None;
                return Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
            }
            if alternating_wait(&mut self.alternate_pending, cx) {
                return Poll::Pending;
            }
            let n = out.len().min(self.chunk).min(self.bytes.len() - self.offset);
            out[..n].copy_from_slice(&self.bytes[self.offset..self.offset + n]);
            self.offset += n;
            Poll::Ready(Ok(n))
        }
    }

    #[derive(Default)]
    struct Sink {
        bytes: Vec<u8>,
        chunk: usize,
        calls: usize,
        flushes: usize,
        blocked: bool,
        flush_blocked: bool,
        interrupt_at: Option<usize>,
        alternate_pending: Option<bool>,
    }

    impl Sink {
        fn new(chunk: usize) -> Self {
            Self { chunk, ..Self::default() }
        }
        fn write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            assert_ne!(bytes.len(), 0, "a write is never asked to write nothing");
            self.calls += 1;
            if self.interrupt_at.is_some_and(|at| self.bytes.len() >= at) {
                self.interrupt_at = None;
                return Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
            }
            if self.blocked {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if alternating_wait(&mut self.alternate_pending, cx) {
                return Poll::Pending;
            }
            let n = bytes.len().min(self.chunk);
            self.bytes.extend_from_slice(&bytes[..n]);
            Poll::Ready(Ok(n))
        }
        fn flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            if self.flush_blocked {
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    fn run(session: &mut EncodeTransfer, source: &mut Source, sink: &mut Sink)
        -> io::Result<TransferProgress>
    {
        complete(session.run(source, sink, Source::read, Sink::write, Sink::flush))
    }

    #[test]
    fn encodes_a_known_wire_frame_through_pending_single_byte_io() {
        let params = EncodeParams { level: Level::Store, checksum: false };
        let mut session = EncodeTransfer::new(params, 2).unwrap();
        let mut source = Source::new(b"hi", 1);
        source.alternate_pending = Some(false);
        let mut sink = Sink::new(1);
        sink.alternate_pending = Some(false);
        let result = run(&mut session, &mut source, &mut sink).unwrap();
        assert_eq!(sink.bytes, [0x28, 0xb5, 0x2f, 0xfd, 0x20, 2, 0x11, 0, 0, b'h', b'i']);
        assert_eq!(result.bytes_read, 2);
        assert_eq!(result.bytes_written, 11);
        assert!(session.is_finished());
        assert_eq!(sink.flushes, 1);
    }

    #[test]
    fn fragmented_transfers_preserve_every_frame_and_byte() {
        let input: Vec<u8> = (0..4097).map(|i| u8::try_from(i % 251).unwrap()).collect();
        for level in [Level::Store, Level::Fast] {
            for frame_size in [31, 1024] {
                let params = EncodeParams::new(level);
                let expected: Vec<u8> = input.chunks(frame_size)
                    .flat_map(|chunk| encode_all(chunk, &params)).collect();
                let mut session = EncodeTransfer::new(params, frame_size).unwrap();
                let mut source = Source::new(&input, 257);
                source.alternate_pending = Some(false);
                let mut sink = Sink::new(3);
                sink.alternate_pending = Some(false);
                let result = run(&mut session, &mut source, &mut sink).unwrap();
                assert_eq!(sink.bytes, expected);
                assert_eq!(decode_all(&sink.bytes, &DecodeLimits::new(input.len())).unwrap(), input);
                assert_eq!(result.bytes_read, input.len() as u64);
                assert_eq!(result.bytes_written, sink.bytes.len() as u64);
            }
        }
    }

    #[test]
    fn dropped_future_keeps_read_ahead_and_backpressured_output() {
        let input = b"the source may advance before the sink can write";
        let params = EncodeParams::new(Level::Fast);
        let mut session = EncodeTransfer::new(params, 8).unwrap();
        let mut source = Source::new(input, input.len());
        let mut sink = Sink::new(2);
        sink.blocked = true;
        {
            let future = session.run(&mut source, &mut sink, Source::read, Sink::write, Sink::flush);
            let mut future = pin!(future);
            assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        assert_eq!(source.calls, 1, "backpressure forbids read-ahead beyond one read");
        assert_eq!(source.offset, input.len());
        assert_eq!(session.progress().bytes_read, input.len() as u64);
        assert_eq!(session.progress().bytes_written, 0);
        assert_eq!(sink.bytes, Vec::<u8>::new());
        sink.blocked = false;
        run(&mut session, &mut source, &mut sink).unwrap();
        let expected: Vec<u8> = input.chunks(8).flat_map(|part| encode_all(part, &params)).collect();
        assert_eq!(sink.bytes, expected);
    }

    #[test]
    fn interrupted_partial_write_resumes_without_replaying_accepted_bytes() {
        let params = EncodeParams::new(Level::Store);
        let mut session = EncodeTransfer::new(params, 64).unwrap();
        let mut source = Source::new(b"hello", 2);
        let mut sink = Sink::new(2);
        sink.interrupt_at = Some(2);
        assert_eq!(run(&mut session, &mut source, &mut sink).unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(session.progress().bytes_written, 2);
        assert!(!session.is_finished());
        run(&mut session, &mut source, &mut sink).unwrap();
        assert_eq!(sink.bytes, encode_all(b"hello", &params));
        assert_eq!(session.progress().bytes_written, sink.bytes.len() as u64);
    }

    #[test]
    fn interrupted_read_keeps_a_partially_filled_plain_frame() {
        let params = EncodeParams::new(Level::Store);
        let mut session = EncodeTransfer::new(params, 64).unwrap();
        let mut source = Source::new(b"partial frame", 4);
        source.interrupt_at = Some(4);
        let mut sink = Sink::new(64);
        assert_eq!(run(&mut session, &mut source, &mut sink).unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(session.progress().bytes_read, 4);
        assert_eq!(sink.bytes, Vec::<u8>::new());
        run(&mut session, &mut source, &mut sink).unwrap();
        assert_eq!(sink.bytes, encode_all(b"partial frame", &params));
    }

    #[test]
    fn empty_stream_finalizes_once_and_waits_for_the_sink_flush() {
        let params = EncodeParams::new(Level::Store);
        let mut session = EncodeTransfer::new(params, 64).unwrap();
        let mut source = Source::new(&[], 1);
        let mut sink = Sink::new(64);
        sink.flush_blocked = true;
        {
            let future = session.run(&mut source, &mut sink, Source::read, Sink::write, Sink::flush);
            let mut future = pin!(future);
            assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        assert!(!session.is_finished());
        assert_eq!(sink.bytes, encode_all(&[], &params));
        assert_eq!(sink.flushes, 1);
        assert_eq!(source.calls, 1);
        sink.flush_blocked = false;
        let result = run(&mut session, &mut source, &mut sink).unwrap();
        let counts = (source.calls, sink.calls, sink.flushes);
        assert_eq!(run(&mut session, &mut source, &mut sink).unwrap(), result);
        assert_eq!((source.calls, sink.calls, sink.flushes), counts);
        assert_eq!(sink.bytes, encode_all(&[], &params));
    }

    #[test]
    fn write_zero_is_terminal_and_retry_does_not_touch_io() {
        let mut session = EncodeTransfer::new(EncodeParams::new(Level::Store), 3).unwrap();
        let mut source = Source::new(b"abc", 3);
        let mut sink = Sink::new(0);
        assert_eq!(run(&mut session, &mut source, &mut sink).unwrap_err().kind(), io::ErrorKind::WriteZero);
        let counts = (source.calls, sink.calls, sink.flushes);
        sink.chunk = 64;
        assert_eq!(run(&mut session, &mut source, &mut sink).unwrap_err().kind(), io::ErrorKind::WriteZero);
        assert_eq!((source.calls, sink.calls, sink.flushes), counts);
        assert_eq!(session.progress().bytes_written, 0);
    }

    #[test]
    fn invalid_callback_counts_fail_closed() {
        let mut session = EncodeTransfer::new(EncodeParams::new(Level::Store), 3).unwrap();
        let mut source = Source::new(b"abc", 3);
        let mut sink = Sink::new(64);
        let error = complete(session.run(&mut source, &mut sink,
            |_: &mut Source, _: &mut Context<'_>, out: &mut [u8]| Poll::Ready(Ok(out.len() + 1)),
            Sink::write, Sink::flush)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(session.progress(), TransferProgress::default());
        assert_eq!(sink.calls, 0);

        let mut session = EncodeTransfer::new(EncodeParams::new(Level::Store), 3).unwrap();
        let error = complete(session.run(&mut source, &mut sink, Source::read,
            |_: &mut Sink, _: &mut Context<'_>, bytes: &[u8]| Poll::Ready(Ok(bytes.len() + 1)),
            Sink::flush)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(session.progress().bytes_written, 0);
    }

    #[test]
    fn always_ready_io_yields_instead_of_monopolizing_a_worker() {
        let input: Vec<u8> = (0..200_000).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let params = EncodeParams::new(Level::Store);
        let mut session = EncodeTransfer::new(params, 1024).unwrap();
        let mut source = Source::new(&input, 8192);
        let mut sink = Sink::new(8192);
        let wake_count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wake_count));
        let mut cx = Context::from_waker(&waker);
        {
            let mut future = pin!(session.run(&mut source, &mut sink, Source::read, Sink::write, Sink::flush));
            assert!(future.as_mut().poll(&mut cx).is_pending());
        }
        assert!(wake_count.0.load(Ordering::Relaxed) > 0);
        assert!(session.progress().bytes_read < input.len() as u64);
        run(&mut session, &mut source, &mut sink).unwrap();
        assert_eq!(decode_all(&sink.bytes, &DecodeLimits::new(input.len())).unwrap(), input);
    }
}
