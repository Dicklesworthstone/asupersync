//! Bounded capture and offline replay of duplex asynchronous byte I/O.
//!
//! Wrap an already-authorized socket/TLS stream in [`RecordingIo`], run the
//! ordinary protocol consumer, then take its [`IoTape`]. Replay implements the
//! same byte-I/O traits but owns no socket, provider, reactor, or host capability.
//! Reads retain their exact requested capacity and returned bytes; writes retain
//! request shape and SHA-256, not plaintext. Errors preserve kind and native code,
//! not arbitrary error messages, custom payloads, or downcast identity.
//!
//! Only completed polls are recorded. Replay preserves their total order: an
//! early read waits for a preceding write (and vice versa), with a wake when
//! that operation completes. It does not reproduce readiness timing, pending
//! poll counts, scheduling, cancellation, or external effects. A consumer that
//! never drives a prerequisite operation can stay pending; use the owning
//! task's deadline and [`ReplayIo::verify_complete`] rather than inferring
//! success from idleness. This is an explicit capture window, not proof that
//! the application reached EOF or completed its transaction.
//!
//! Capture limits never change an underlying result: recording is abandoned
//! and tape extraction fails, while production I/O continues. A replay mismatch
//! is sticky across both directions; exhaustion is an error, never invented EOF.
//! All buffers and owned write digests are zeroized on drop. Debug output omits
//! payloads and the inner stream. Captures may contain secrets; nothing is
//! automatically logged or persisted. Install below the consumer to be replayed;
//! recording ciphertext alone cannot reconstruct a TLS session's hidden state.

use super::{AsyncRead, AsyncWrite, ReadBuf};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};
use zeroize::Zeroize;

/// Logical bounds for one capture. Allocator and inner-stream memory are separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoCaptureLimits {
    /// Maximum completed read/write/flush/shutdown calls, including errors and EOF.
    pub max_operations: usize,
    /// Maximum retained bytes appended by reads, including reads returning errors.
    pub max_read_bytes: usize,
    /// Maximum aggregate offered write bytes hashed, including unaccepted tails.
    pub max_write_bytes: usize,
    /// Maximum number of slices in any one vectored write, including empty slices.
    pub max_vectored_slices: usize,
}

impl IoCaptureLimits {
    /// Set all limits explicitly. Zero limits are valid and refuse relevant work.
    #[must_use]
    pub const fn new(operations: usize, read_bytes: usize, write_bytes: usize, slices: usize) -> Self {
        Self { max_operations: operations, max_read_bytes: read_bytes,
            max_write_bytes: write_bytes, max_vectored_slices: slices }
    }
}

/// Why a complete capture window cannot be extracted; never contains I/O data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IoCaptureError {
    /// A logical resource limit was exceeded.
    #[error("I/O capture exceeded its {0} limit")]
    Limit(&'static str),
    /// Bounded storage could not be reserved.
    #[error("I/O capture allocation failed")]
    Allocation,
    /// A source poll unwound. Subsequent I/O still forwards, but capture is invalid.
    #[error("I/O capture contains an interrupted source poll")]
    InterruptedPoll,
    /// A source violated its trait's byte-count/progress contract.
    #[error("I/O capture observed invalid source progress")]
    InvalidProgress,
}

/// A request category, without its payload or digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperation {
    /// A read into one initialized buffer.
    Read,
    /// A scalar write.
    Write,
    /// A write with exact slice boundaries.
    WriteVectored,
    /// Flush the writer.
    Flush,
    /// Shut down the writer.
    Shutdown,
}

impl IoOperation {
    fn is_read(self) -> bool { self == Self::Read }
}

#[derive(Clone, Copy)]
struct IoFailure {
    kind: io::ErrorKind,
    raw: Option<i32>,
}

impl IoFailure {
    fn capture(error: &io::Error) -> Self {
        Self { kind: error.kind(), raw: error.raw_os_error() }
    }

    fn replay(self) -> io::Error {
        self.raw.map_or_else(|| io::Error::from(self.kind), io::Error::from_raw_os_error)
    }
}

enum Event {
    Read { capacity: usize, bytes: Vec<u8>, error: Option<IoFailure> },
    Write { length: usize, slices: Option<Vec<usize>>, digest: [u8; 32],
        accepted: usize, error: Option<IoFailure> },
    Flush(Option<IoFailure>),
    Shutdown(Option<IoFailure>),
}

impl Event {
    fn operation(&self) -> IoOperation {
        match self {
            Self::Read { .. } => IoOperation::Read,
            Self::Write { slices: None, .. } => IoOperation::Write,
            Self::Write { slices: Some(_), .. } => IoOperation::WriteVectored,
            Self::Flush(_) => IoOperation::Flush,
            Self::Shutdown(_) => IoOperation::Shutdown,
        }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        match self {
            Self::Read { bytes, .. } => bytes.zeroize(),
            Self::Write { digest, .. } => digest.zeroize(),
            Self::Flush(_) | Self::Shutdown(_) => {}
        }
    }
}

/// Sensitive completed-poll transcript, detached from its original I/O provider.
///
/// Full consumption verifies this capture window, not the application's success.
/// The tape retains plaintext reads and fingerprints of all attempted write data.
pub struct IoTape {
    events: Vec<Event>,
    read_bytes: usize,
    write_bytes: usize,
    vectored: bool,
}

impl fmt::Debug for IoTape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoTape").field("operations", &self.events.len())
            .field("read_bytes", &self.read_bytes).field("write_bytes", &self.write_bytes)
            .finish_non_exhaustive()
    }
}

impl IoTape {
    /// Number of completed operations captured, including errors and zero lengths.
    #[must_use]
    pub fn operations(&self) -> usize { self.events.len() }

    /// Retained read bytes.
    #[must_use]
    pub const fn read_bytes(&self) -> usize { self.read_bytes }

    /// Aggregate offered write bytes checked during replay, not bytes delivered.
    #[must_use]
    pub const fn write_bytes(&self) -> usize { self.write_bytes }

    /// Consume the tape into an offline, fail-closed byte stream.
    #[must_use]
    pub fn replay(self) -> ReplayIo {
        ReplayIo { tape: self, index: 0, failure: None, read_waiter: None, write_waiter: None }
    }
}

/// Transparent result capture for an explicitly supplied duplex I/O provider.
///
/// The initial efficient-vectored-write capability is retained for replay. This
/// adapter forwards the original scalar/vectored poll method, never flattens a
/// live write, and never invokes arbitrary error formatting. No capture lock is
/// held around provider or waker callbacks. Ready events are recorded in order;
/// a dropped pending operation contributes no fabricated completion event.
pub struct RecordingIo<T> {
    inner: T,
    limits: IoCaptureLimits,
    tape: IoTape,
    failure: Option<IoCaptureError>,
    polling: bool,
}

impl<T> fmt::Debug for RecordingIo<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingIo").field("tape", &self.tape)
            .field("failure", &self.failure).finish_non_exhaustive()
    }
}

impl<T: AsyncWrite> RecordingIo<T> {
    /// Wrap a provider without performing a read or write. Capture is opt-in.
    #[must_use]
    pub fn new(inner: T, limits: IoCaptureLimits) -> Self {
        let vectored = inner.is_write_vectored();
        Self { inner, limits, tape: IoTape { events: Vec::new(), read_bytes: 0,
            write_bytes: 0, vectored }, failure: None, polling: false }
    }
}

impl<T> RecordingIo<T> {
    /// First capture failure, independent of the original provider's I/O result.
    #[must_use]
    pub fn capture_error(&self) -> Option<IoCaptureError> {
        self.failure.or(self.polling.then_some(IoCaptureError::InterruptedPoll))
    }

    /// End capture and return both the original provider and complete tape/error.
    /// An incomplete tape is never returned. This does not close the provider.
    pub fn into_parts(self) -> (T, Result<IoTape, IoCaptureError>) {
        let failure = self.capture_error();
        let result = match failure { Some(error) => Err(error), None => Ok(self.tape) };
        (self.inner, result)
    }

    fn fail(&mut self, error: IoCaptureError) { self.failure.get_or_insert(error); }

    fn begin(&mut self) {
        if self.polling { self.fail(IoCaptureError::InterruptedPoll); }
        self.polling = true;
    }

    fn reserve(&mut self, read: usize, write: usize, slices: usize) -> bool {
        if self.failure.is_some() { return false; }
        let error = if self.tape.events.len() >= self.limits.max_operations {
            Some(IoCaptureError::Limit("operations"))
        } else if read > self.limits.max_read_bytes - self.tape.read_bytes {
            Some(IoCaptureError::Limit("read bytes"))
        } else if write > self.limits.max_write_bytes - self.tape.write_bytes {
            Some(IoCaptureError::Limit("write bytes"))
        } else if slices > self.limits.max_vectored_slices {
            Some(IoCaptureError::Limit("vectored slices"))
        } else if self.tape.events.try_reserve(1).is_err() {
            Some(IoCaptureError::Allocation)
        } else { None };
        if let Some(error) = error { self.fail(error); return false; }
        self.tape.read_bytes += read;
        self.tape.write_bytes += write;
        true
    }

    fn record_write(&mut self, input: WriteInput<'_, '_>, result: &io::Result<usize>) {
        let Some(length) = input.length() else { self.fail(IoCaptureError::InvalidProgress); return; };
        let (accepted, error) = match result {
            Ok(count) if *count <= length => (*count, None),
            Ok(_) => { self.fail(IoCaptureError::InvalidProgress); return; }
            Err(error) => (0, Some(IoFailure::capture(error))),
        };
        if !self.reserve(0, length, input.slice_count()) { return; }
        let slices = match input {
            WriteInput::Scalar(_) => None,
            WriteInput::Vectored(bufs) => {
                let mut lengths = Vec::new();
                if lengths.try_reserve_exact(bufs.len()).is_err() {
                    self.fail(IoCaptureError::Allocation); return;
                }
                lengths.extend(bufs.iter().map(|buf| buf.len()));
                Some(lengths)
            }
        };
        self.tape.events.push(Event::Write { length, slices, digest: input.digest(), accepted, error });
    }
}

#[derive(Clone, Copy)]
enum WriteInput<'a, 'b> { Scalar(&'a [u8]), Vectored(&'a [IoSlice<'b>]) }

impl WriteInput<'_, '_> {
    fn length(self) -> Option<usize> {
        match self {
            Self::Scalar(buf) => Some(buf.len()),
            Self::Vectored(bufs) => bufs.iter().try_fold(0usize, |n, buf| n.checked_add(buf.len())),
        }
    }

    fn slice_count(self) -> usize {
        match self { Self::Scalar(_) => 0, Self::Vectored(bufs) => bufs.len() }
    }

    fn operation(self) -> IoOperation {
        match self { Self::Scalar(_) => IoOperation::Write, Self::Vectored(_) => IoOperation::WriteVectored }
    }

    fn digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"asupersync.io-write.v1");
        match self {
            Self::Scalar(buf) => hash.update(buf),
            Self::Vectored(bufs) => { for buf in bufs { hash.update(buf.as_ref()); } }
        }
        hash.finalize().into()
    }

    fn matches_slices(self, recorded: &Option<Vec<usize>>) -> bool {
        match (self, recorded) {
            (Self::Scalar(_), None) => true,
            (Self::Vectored(bufs), Some(lengths)) => {
                bufs.len() == lengths.len() && bufs.iter().zip(lengths).all(|(buf, len)| buf.len() == *len)
            }
            _ => false,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for RecordingIo<T> {
    fn poll_read(self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let capacity = buf.remaining();
        this.begin();
        let result = Pin::new(&mut this.inner).poll_read(ctx, buf);
        this.polling = false;
        let bytes = &buf.filled()[before..];
        if let Poll::Ready(outcome) = &result {
            if this.reserve(bytes.len(), 0, 0) {
                let mut retained = Vec::new();
                if retained.try_reserve_exact(bytes.len()).is_err() {
                    this.fail(IoCaptureError::Allocation);
                } else {
                    retained.extend_from_slice(bytes);
                    this.tape.events.push(Event::Read { capacity, bytes: retained,
                        error: outcome.as_ref().err().map(IoFailure::capture) });
                }
            }
        } else if !bytes.is_empty() { this.fail(IoCaptureError::InvalidProgress); }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for RecordingIo<T> {
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.begin();
        let result = Pin::new(&mut this.inner).poll_write(ctx, buf);
        this.polling = false;
        if let Poll::Ready(outcome) = &result { this.record_write(WriteInput::Scalar(buf), outcome); }
        result
    }

    fn poll_write_vectored(self: Pin<&mut Self>, ctx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.begin();
        let result = Pin::new(&mut this.inner).poll_write_vectored(ctx, bufs);
        this.polling = false;
        if let Poll::Ready(outcome) = &result { this.record_write(WriteInput::Vectored(bufs), outcome); }
        result
    }

    fn is_write_vectored(&self) -> bool { self.tape.vectored }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.begin();
        let result = Pin::new(&mut this.inner).poll_flush(ctx);
        this.polling = false;
        if let Poll::Ready(outcome) = &result {
            if this.reserve(0, 0, 0) {
                this.tape.events.push(Event::Flush(outcome.as_ref().err().map(IoFailure::capture)));
            }
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>,) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.begin();
        let result = Pin::new(&mut this.inner).poll_shutdown(ctx);
        this.polling = false;
        if let Poll::Ready(outcome) = &result {
            if this.reserve(0, 0, 0) {
                this.tape.events.push(Event::Shutdown(outcome.as_ref().err().map(IoFailure::capture)));
            }
        }
        result
    }
}

/// First replay refusal. Does not contain payloads, fingerprints, or error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("[ASUP-E401] I/O replay divergence at operation {index}: {reason:?} (expected {expected:?}, actual {actual:?})")]
pub struct IoReplayError {
    /// Zero-based completed-operation index.
    pub index: usize,
    /// Recorded operation, absent at tape exhaustion.
    pub expected: Option<IoOperation>,
    /// Operation attempted by the consumer.
    pub actual: IoOperation,
    /// Redacted mismatch classification.
    pub reason: IoReplayMismatch,
}

/// Why replay refused an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoReplayMismatch {
    /// There was no recorded result for another operation.
    Exhausted,
    /// The next operation in the same direction had a different kind.
    Operation,
    /// Buffer size, vectored boundaries, or offered write contents changed.
    Request,
}

/// Completing the consumer is insufficient unless the entire tape was consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IoReplayCompletionError {
    /// A replay refusal occurred, even if its I/O error was ignored by the caller.
    #[error(transparent)]
    Diverged(IoReplayError),
    /// Captured operations are still unused, including any blocked prerequisites.
    #[error("I/O replay has {remaining} unconsumed operations")]
    Remaining {
        /// Number of completed source operations not replayed.
        remaining: usize,
    },
}

/// Offline implementation of the same I/O traits, with no underlying provider.
///
/// At most one waiter per direction is retained, matching exclusive polling of
/// each half of a split stream. Opposite-direction prerequisites wait rather
/// than treating an early poll as divergence. Same-direction request changes
/// fail immediately once their recorded turn arrives. Pending timing itself is
/// not replayed, and callers must still drive both halves and own cancellation.
pub struct ReplayIo {
    tape: IoTape,
    index: usize,
    failure: Option<IoReplayError>,
    read_waiter: Option<Waker>,
    write_waiter: Option<Waker>,
}

impl fmt::Debug for ReplayIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayIo").field("index", &self.index).field("tape", &self.tape)
            .field("failure", &self.failure).finish_non_exhaustive()
    }
}

impl ReplayIo {
    /// Number of exact source completions reproduced.
    #[must_use]
    pub const fn consumed_operations(&self) -> usize { self.index }

    /// Sticky first failure, even after the consumer catches/ignores its I/O error.
    #[must_use]
    pub const fn failure(&self) -> Option<IoReplayError> { self.failure }

    /// Verify both absence of divergence and full capture-window consumption.
    pub fn verify_complete(&self) -> Result<(), IoReplayCompletionError> {
        if let Some(error) = self.failure { return Err(IoReplayCompletionError::Diverged(error)); }
        let remaining = self.tape.events.len() - self.index;
        if remaining != 0 { return Err(IoReplayCompletionError::Remaining { remaining }); }
        Ok(())
    }

    fn refuse(&mut self, actual: IoOperation, reason: IoReplayMismatch) -> io::Error {
        let error = *self.failure.get_or_insert(IoReplayError {
            index: self.index, expected: self.tape.events.get(self.index).map(Event::operation), actual, reason,
        });
        self.wake_waiters();
        io::Error::new(io::ErrorKind::InvalidData, error)
    }

    fn ready(&mut self, ctx: &mut Context<'_>, actual: IoOperation) -> Poll<io::Result<()>> {
        if let Some(error) = self.failure {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
        }
        let Some(event) = self.tape.events.get(self.index) else {
            return Poll::Ready(Err(self.refuse(actual, IoReplayMismatch::Exhausted)));
        };
        let expected = event.operation();
        if expected.is_read() != actual.is_read() {
            let slot = if actual.is_read() { &mut self.read_waiter } else { &mut self.write_waiter };
            if !slot.as_ref().is_some_and(|waker| waker.will_wake(ctx.waker())) {
                *slot = Some(ctx.waker().clone());
            }
            return Poll::Pending;
        }
        if expected != actual {
            return Poll::Ready(Err(self.refuse(actual, IoReplayMismatch::Operation)));
        }
        Poll::Ready(Ok(()))
    }

    fn wake_waiters(&mut self) {
        let read = self.read_waiter.take();
        let write = self.write_waiter.take();
        if let Some(waker) = read { waker.wake(); }
        if let Some(waker) = write { waker.wake(); }
    }

    fn advance(&mut self) {
        self.index += 1;
        self.wake_waiters();
    }

    fn write(&mut self, ctx: &mut Context<'_>, input: WriteInput<'_, '_>) -> Poll<io::Result<usize>> {
        let operation = input.operation();
        ready!(self.ready(ctx, operation))?;
        let Event::Write { length, slices, digest, accepted, error } = &self.tape.events[self.index] else {
            unreachable!("operation checked above")
        };
        if input.length() != Some(*length) || !input.matches_slices(slices) || input.digest() != *digest {
            return Poll::Ready(Err(self.refuse(operation, IoReplayMismatch::Request)));
        }
        let result = error.map_or(Ok(*accepted), |error| Err(error.replay()));
        self.advance();
        Poll::Ready(result)
    }

    fn finish_write(&mut self, ctx: &mut Context<'_>, operation: IoOperation) -> Poll<io::Result<()>> {
        ready!(self.ready(ctx, operation))?;
        let error = match &self.tape.events[self.index] {
            Event::Flush(error) | Event::Shutdown(error) => *error,
            _ => unreachable!("operation checked above"),
        };
        self.advance();
        Poll::Ready(error.map_or(Ok(()), |error| Err(error.replay())))
    }
}

impl AsyncRead for ReplayIo {
    fn poll_read(self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.ready(ctx, IoOperation::Read))?;
        let Event::Read { capacity, bytes, error } = &this.tape.events[this.index] else {
            unreachable!("operation checked above")
        };
        if buf.remaining() != *capacity {
            return Poll::Ready(Err(this.refuse(IoOperation::Read, IoReplayMismatch::Request)));
        }
        buf.put_slice(bytes);
        let result = error.map_or(Ok(()), |error| Err(error.replay()));
        this.advance();
        Poll::Ready(result)
    }
}

impl AsyncWrite for ReplayIo {
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().write(ctx, WriteInput::Scalar(buf))
    }

    fn poll_write_vectored(self: Pin<&mut Self>, ctx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        self.get_mut().write(ctx, WriteInput::Vectored(bufs))
    }

    fn is_write_vectored(&self) -> bool { self.tape.vectored }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().finish_write(ctx, IoOperation::Flush)
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().finish_write(ctx, IoOperation::Shutdown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    #[derive(Default)]
    struct Duplex {
        input: &'static [u8],
        output: Vec<u8>,
        polls: usize,
        pending: bool,
        read_error: bool,
    }

    impl AsyncRead for Duplex {
        fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            self.polls += 1;
            if self.pending { self.pending = false; return Poll::Pending; }
            let n = self.input.len().min(buf.remaining()).min(2);
            buf.put_slice(&self.input[..n]);
            self.input = &self.input[n..];
            Poll::Ready(if self.read_error {
                Err(io::Error::new(io::ErrorKind::ConnectionReset, "private error payload"))
            } else { Ok(()) })
        }
    }

    impl AsyncWrite for Duplex {
        fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.polls += 1;
            let n = buf.len().min(2);
            self.output.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.polls += 1;
            Poll::Ready(Err(io::Error::from_raw_os_error(22)))
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.polls += 1;
            Poll::Ready(Ok(()))
        }
    }

    fn limits() -> IoCaptureLimits { IoCaptureLimits::new(32, 64, 64, 8) }
    fn cx() -> Context<'static> { Context::from_waker(Waker::noop()) }
    fn value<T>(poll: Poll<io::Result<T>>) -> io::Result<T> {
        match poll { Poll::Ready(result) => result, Poll::Pending => panic!("expected completion") }
    }

    #[test]
    fn scalar_capture_replays_partial_progress_eof_and_native_errors() {
        let mut capture = RecordingIo::new(Duplex { input: b"ab", ..Duplex::default() }, limits());
        let mut ctx = cx();
        assert_eq!(value(Pin::new(&mut capture).poll_write(&mut ctx, b"hello")).unwrap(), 2);
        let mut bytes = [0; 5];
        let mut buf = ReadBuf::new(&mut bytes);
        buf.put_slice(b"x");
        value(Pin::new(&mut capture).poll_read(&mut ctx, &mut buf)).unwrap();
        assert_eq!(buf.filled(), b"xab");
        let original_error = value(Pin::new(&mut capture).poll_flush(&mut ctx)).unwrap_err();
        let mut eof = [0; 4];
        value(Pin::new(&mut capture).poll_read(&mut ctx, &mut ReadBuf::new(&mut eof))).unwrap();
        value(Pin::new(&mut capture).poll_shutdown(&mut ctx)).unwrap();
        let (inner, tape) = capture.into_parts();
        let tape = tape.unwrap();
        assert_eq!((inner.polls, inner.output.as_slice()), (5, b"he".as_slice()));
        assert_eq!((tape.operations(), tape.read_bytes(), tape.write_bytes()), (5, 2, 5));
        let mut replay = tape.replay();
        assert_eq!(value(Pin::new(&mut replay).poll_write(&mut ctx, b"hello")).unwrap(), 2);
        let mut bytes = [0; 5];
        let mut buf = ReadBuf::new(&mut bytes);
        buf.put_slice(b"x");
        value(Pin::new(&mut replay).poll_read(&mut ctx, &mut buf)).unwrap();
        assert_eq!(buf.filled(), b"xab");
        let error = value(Pin::new(&mut replay).poll_flush(&mut ctx)).unwrap_err();
        assert_eq!((error.kind(), error.raw_os_error()), (original_error.kind(), original_error.raw_os_error()));
        let mut buf = ReadBuf::new(&mut eof);
        value(Pin::new(&mut replay).poll_read(&mut ctx, &mut buf)).unwrap();
        assert!(buf.filled().is_empty());
        value(Pin::new(&mut replay).poll_shutdown(&mut ctx)).unwrap();
        replay.verify_complete().unwrap();
        let error = value(Pin::new(&mut replay).poll_read(&mut ctx, &mut buf)).unwrap_err();
        assert_eq!(error.get_ref().unwrap().downcast_ref::<IoReplayError>().unwrap().reason, IoReplayMismatch::Exhausted);
        assert!(matches!(replay.verify_complete(), Err(IoReplayCompletionError::Diverged(_))));
    }

    #[test]
    fn capture_limits_never_change_the_underlying_write_result() {
        for limit in [IoCaptureLimits::new(0, 0, 0, 0), IoCaptureLimits::new(8, 0, 1, 0)] {
            let mut capture = RecordingIo::new(Duplex::default(), limit);
            for _ in 0..3 {
                assert_eq!(value(Pin::new(&mut capture).poll_write(&mut cx(), b"abc")).unwrap(), 2);
            }
            let (inner, result) = capture.into_parts();
            assert_eq!(inner.output, b"ababab");
            assert_eq!(inner.polls, 3);
            assert!(matches!(result, Err(IoCaptureError::Limit(_))));
        }
    }

    #[test]
    fn changed_unaccepted_write_tail_poison_is_shared_with_reads() {
        let mut capture = RecordingIo::new(Duplex::default(), limits());
        value(Pin::new(&mut capture).poll_write(&mut cx(), b"abc")).unwrap();
        let mut replay = capture.into_parts().1.unwrap().replay();
        let error = value(Pin::new(&mut replay).poll_write(&mut cx(), b"abX")).unwrap_err();
        let first = *error.get_ref().unwrap().downcast_ref::<IoReplayError>().unwrap();
        assert_eq!(first.reason, IoReplayMismatch::Request);
        let mut bytes = [0xa5; 4];
        assert!(value(Pin::new(&mut replay).poll_read(&mut cx(), &mut ReadBuf::new(&mut bytes))).is_err());
        assert_eq!(bytes, [0xa5; 4]);
        assert_eq!(replay.failure(), Some(first));
        assert_eq!(replay.consumed_operations(), 0);
    }

    #[test]
    fn pending_source_poll_does_not_create_an_eof_or_completion_event() {
        let mut capture = RecordingIo::new(Duplex { input: b"ab", pending: true, ..Duplex::default() }, limits());
        let mut bytes = [0; 2];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(Pin::new(&mut capture).poll_read(&mut cx(), &mut buf).is_pending());
        assert!(buf.filled().is_empty());
        value(Pin::new(&mut capture).poll_read(&mut cx(), &mut buf)).unwrap();
        let (inner, tape) = capture.into_parts();
        assert_eq!(inner.polls, 2);
        assert_eq!(tape.unwrap().operations(), 1);
    }

    #[test]
    fn cross_direction_prerequisite_wakes_without_polling_spin() {
        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        let mut capture = RecordingIo::new(Duplex { input: b"ok", ..Duplex::default() }, limits());
        value(Pin::new(&mut capture).poll_write(&mut cx(), b"go")).unwrap();
        let mut bytes = [0; 2];
        value(Pin::new(&mut capture).poll_read(&mut cx(), &mut ReadBuf::new(&mut bytes))).unwrap();
        let mut replay = capture.into_parts().1.unwrap().replay();
        let probe = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&probe));
        let mut ctx = Context::from_waker(&waker);
        let mut buf = ReadBuf::new(&mut bytes);
        for _ in 0..16 { assert!(Pin::new(&mut replay).poll_read(&mut ctx, &mut buf).is_pending()); }
        assert_eq!(probe.0.load(Ordering::SeqCst), 0);
        assert_eq!(replay.verify_complete(), Err(IoReplayCompletionError::Remaining { remaining: 2 }));
        value(Pin::new(&mut replay).poll_write(&mut cx(), b"go")).unwrap();
        assert_eq!(probe.0.load(Ordering::SeqCst), 1);
        value(Pin::new(&mut replay).poll_read(&mut ctx, &mut buf)).unwrap();
        assert_eq!(buf.filled(), b"ok");
        replay.verify_complete().unwrap();
    }

    #[test]
    fn vectored_write_keeps_boundaries_even_when_concatenated_bytes_match() {
        let mut capture = RecordingIo::new(Duplex::default(), limits());
        let bufs = [IoSlice::new(b"a"), IoSlice::new(b""), IoSlice::new(b"bc")];
        assert_eq!(value(Pin::new(&mut capture).poll_write_vectored(&mut cx(), &bufs)).unwrap(), 1);
        let mut replay = capture.into_parts().1.unwrap().replay();
        let changed = [IoSlice::new(b"ab"), IoSlice::new(b""), IoSlice::new(b"c")];
        assert!(value(Pin::new(&mut replay).poll_write_vectored(&mut cx(), &changed)).is_err());
        assert_eq!(replay.failure().unwrap().reason, IoReplayMismatch::Request);
    }

    #[test]
    fn read_error_preserves_appended_bytes_without_retaining_private_error_text() {
        let mut capture = RecordingIo::new(Duplex { input: b"ok", read_error: true, ..Duplex::default() }, limits());
        let mut bytes = [0; 2];
        let error = value(Pin::new(&mut capture).poll_read(&mut cx(), &mut ReadBuf::new(&mut bytes))).unwrap_err();
        assert_eq!(error.to_string(), "private error payload");
        let tape = capture.into_parts().1.unwrap();
        assert!(!format!("{tape:?}").contains("private"));
        let mut replay = tape.replay();
        let mut output = [0; 2];
        let mut buf = ReadBuf::new(&mut output);
        let error = value(Pin::new(&mut replay).poll_read(&mut cx(), &mut buf)).unwrap_err();
        assert_eq!(buf.filled(), b"ok");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert!(error.get_ref().is_none());
        replay.verify_complete().unwrap();
    }

    #[test]
    fn caught_provider_panic_cannot_publish_a_partial_tape() {
        struct Panics(bool);
        impl AsyncWrite for Panics {
            fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
                if !self.0 { self.0 = true; panic!("source poll panic"); }
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
        }
        let mut capture = RecordingIo::new(Panics(false), limits());
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = Pin::new(&mut capture).poll_write(&mut cx(), b"secret");
        }));
        assert!(failed.is_err());
        assert_eq!(capture.capture_error(), Some(IoCaptureError::InterruptedPoll));
        assert_eq!(value(Pin::new(&mut capture).poll_write(&mut cx(), b"ok")).unwrap(), 2);
        assert!(matches!(capture.into_parts().1, Err(IoCaptureError::InterruptedPoll)));
    }
}

mod codec;
pub use codec::{IoTapeBytes, IoTapeDecodeLimits, IoTapeError};
