//! Bounded capture and offline replay of duplex asynchronous byte I/O.
//!
//! Wrap an already-authorized socket/TLS stream in [`RecordingIo`], run the
//! ordinary protocol consumer, then take its [`IoTape`]. Replay implements the
//! same byte-I/O traits but owns no socket, provider, reactor, or host capability.
//! Reads retain their exact requested capacity and returned bytes; writes retain
//! request shape and SHA-256, not plaintext. Errors preserve kind and native code,
//! not arbitrary error messages, custom payloads, or downcast identity.
//!
//! By default, only completed polls are recorded. Replay preserves their total order: an
//! early read waits for a preceding write (and vice versa), with a wake when
//! that operation completes. It does not reproduce readiness timing, pending
//! poll counts, scheduling, cancellation, or external effects. A consumer that
//! never drives a prerequisite operation can stay pending; use the owning
//! task's deadline and [`ReplayIo::verify_complete`] rather than inferring
//! success from idleness. This is an explicit capture window, not proof that
//! the application reached EOF or completed its transaction.
//!
//! [`RecordingIo::new_with_pending_io`] additionally records each pending poll
//! and its request shape. This mode can end a window with a parked read or
//! write. Each recorded poll is consumed once; an unrecorded retry is still
//! exhaustion. Replay wakes a parked direction only while that direction has
//! recorded observations left. These are progress notifications, not a record
//! of the provider's original wakes, deadlines, or task identities.
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
use zeroize::{Zeroize, Zeroizing};

/// Logical bounds for one capture. Allocator and inner-stream memory are separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoCaptureLimits {
    /// Maximum completed calls, including errors and EOF. Pending-aware capture
    /// counts every poll, including each `Pending` result, against this bound.
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
    pub const fn new(
        operations: usize,
        read_bytes: usize,
        write_bytes: usize,
        slices: usize,
    ) -> Self {
        Self {
            max_operations: operations,
            max_read_bytes: read_bytes,
            max_write_bytes: write_bytes,
            max_vectored_slices: slices,
        }
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
    fn is_read(self) -> bool {
        self == Self::Read
    }
}

#[derive(Clone, Copy)]
struct IoFailure {
    kind: io::ErrorKind,
    raw: Option<i32>,
}

impl IoFailure {
    fn capture(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw: error.raw_os_error(),
        }
    }

    fn replay(self) -> io::Error {
        self.raw
            .map_or_else(|| io::Error::from(self.kind), io::Error::from_raw_os_error)
    }
}

enum Event {
    Read {
        capacity: usize,
        bytes: Vec<u8>,
        error: Option<IoFailure>,
    },
    Write {
        length: usize,
        slices: Option<Vec<usize>>,
        digest: Zeroizing<[u8; 32]>,
        accepted: usize,
        error: Option<IoFailure>,
    },
    Flush(Option<IoFailure>),
    Shutdown(Option<IoFailure>),
    Pending(PendingRequest),
}

enum PendingRequest {
    Read {
        capacity: usize,
    },
    Write {
        length: usize,
        slices: Option<Vec<usize>>,
        digest: Zeroizing<[u8; 32]>,
    },
    Flush,
    Shutdown,
}

impl PendingRequest {
    fn operation(&self) -> IoOperation {
        match self {
            Self::Read { .. } => IoOperation::Read,
            Self::Write { slices: None, .. } => IoOperation::Write,
            Self::Write { slices: Some(_), .. } => IoOperation::WriteVectored,
            Self::Flush => IoOperation::Flush,
            Self::Shutdown => IoOperation::Shutdown,
        }
    }
}

impl Event {
    fn operation(&self) -> IoOperation {
        match self {
            Self::Read { .. } => IoOperation::Read,
            Self::Write { slices: None, .. } => IoOperation::Write,
            Self::Write {
                slices: Some(_), ..
            } => IoOperation::WriteVectored,
            Self::Flush(_) => IoOperation::Flush,
            Self::Shutdown(_) => IoOperation::Shutdown,
            Self::Pending(request) => request.operation(),
        }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        match self {
            Self::Read { bytes, .. } => bytes.zeroize(),
            Self::Write { digest, .. } => digest.zeroize(),
            Self::Pending(PendingRequest::Write { digest, .. }) => digest.zeroize(),
            Self::Flush(_) | Self::Shutdown(_) | Self::Pending(_) => {}
        }
    }
}

/// Sensitive poll transcript, detached from its original I/O provider.
///
/// Full consumption verifies this capture window, not the application's success.
/// The tape retains plaintext reads and fingerprints of all attempted write data.
pub struct IoTape {
    events: Vec<Event>,
    read_bytes: usize,
    write_bytes: usize,
    vectored: bool,
    pending_polls: bool,
}

impl fmt::Debug for IoTape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoTape")
            .field("operations", &self.events.len())
            .field("read_bytes", &self.read_bytes)
            .field("write_bytes", &self.write_bytes)
            .finish_non_exhaustive()
    }
}

impl IoTape {
    /// Number of captured observations, including errors and zero lengths.
    /// Pending-aware tapes also count every captured pending poll.
    #[must_use]
    pub fn operations(&self) -> usize {
        self.events.len()
    }

    /// Retained read bytes.
    #[must_use]
    pub const fn read_bytes(&self) -> usize {
        self.read_bytes
    }

    /// Aggregate offered write bytes checked during replay, not bytes delivered.
    #[must_use]
    pub const fn write_bytes(&self) -> usize {
        self.write_bytes
    }

    /// Whether this window explicitly captured pending request observations.
    #[must_use]
    pub const fn records_pending_polls(&self) -> bool {
        self.pending_polls
    }

    /// Consume the tape into an offline, fail-closed byte stream.
    #[must_use]
    pub fn replay(self) -> ReplayIo {
        let (remaining_reads, remaining_writes) = if self.pending_polls {
            let reads = self.events.iter().filter(|event| event.operation().is_read()).count();
            (reads, self.events.len() - reads)
        } else {
            (0, 0)
        };
        ReplayIo {
            tape: self,
            index: 0,
            failure: None,
            read_waiter: None,
            write_waiter: None,
            remaining_reads,
            remaining_writes,
        }
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
        f.debug_struct("RecordingIo")
            .field("tape", &self.tape)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl<T: AsyncWrite> RecordingIo<T> {
    /// Wrap a provider without performing a read or write. Capture is opt-in.
    #[must_use]
    pub fn new(inner: T, limits: IoCaptureLimits) -> Self {
        let vectored = inner.is_write_vectored();
        Self {
            inner,
            limits,
            tape: IoTape {
                events: Vec::new(),
                read_bytes: 0,
                write_bytes: 0,
                vectored,
                pending_polls: false,
            },
            failure: None,
            polling: false,
        }
    }

    /// Capture every poll, including pending requests, without changing live I/O.
    ///
    /// A window may end after a `Pending` result: replay returns that same
    /// result and full window consumption can then be checked after the owner
    /// drops or otherwise stops the consumer. No EOF or completion is invented.
    /// An additional poll beyond the captured window remains a divergence,
    /// even if its request equals the last pending request.
    ///
    /// Pending reads retain their available capacity; pending writes retain
    /// exact scalar/vector shape and the offered-data fingerprint. Every poll
    /// uses `max_operations`, and every offered write, including retries, uses
    /// `max_write_bytes`. Capture failure never substitutes a live result.
    ///
    /// This observes trait calls, not future or buffer addresses. Dropping a
    /// future and constructing another is visible only through subsequent
    /// polls. Reconstruct the same consumer window and own its cancellation.
    /// Persistence uses the additive V2 tape format; [`Self::new`] keeps V1.
    #[must_use]
    pub fn new_with_pending_io(inner: T, limits: IoCaptureLimits) -> Self {
        let mut recording = Self::new(inner, limits);
        recording.tape.pending_polls = true;
        recording
    }
}

impl<T> RecordingIo<T> {
    /// First capture failure, independent of the original provider's I/O result.
    #[must_use]
    pub fn capture_error(&self) -> Option<IoCaptureError> {
        self.failure
            .or(self.polling.then_some(IoCaptureError::InterruptedPoll))
    }

    /// End capture and return both the original provider and complete tape/error.
    /// An incomplete tape is never returned. This does not close the provider.
    pub fn into_parts(self) -> (T, Result<IoTape, IoCaptureError>) {
        let failure = self.capture_error();
        let result = match failure {
            Some(error) => Err(error),
            None => Ok(self.tape),
        };
        (self.inner, result)
    }

    fn fail(&mut self, error: IoCaptureError) {
        self.failure.get_or_insert(error);
    }

    fn begin(&mut self) {
        if self.polling {
            self.fail(IoCaptureError::InterruptedPoll);
        }
        self.polling = true;
    }

    fn reserve(&mut self, read: usize, write: usize, slices: usize) -> bool {
        if self.failure.is_some() {
            return false;
        }
        let error = if self.tape.events.len() >= self.limits.max_operations {
            Some(IoCaptureError::Limit("operations"))
        } else if read > self.limits.max_read_bytes - self.tape.read_bytes {
            Some(IoCaptureError::Limit("read bytes"))
        } else if write > self.limits.max_write_bytes - self.tape.write_bytes {
            Some(IoCaptureError::Limit("write bytes"))
        } else if slices > self.limits.max_vectored_slices {
            Some(IoCaptureError::Limit("vectored slices"))
        } else {
            None
        };
        if let Some(error) = error {
            self.fail(error);
            return false;
        }
        if self.tape.events.len() == self.tape.events.capacity() {
            let extra = (self.limits.max_operations - self.tape.events.len())
                .min(self.tape.events.len().max(8));
            let mut grown = Vec::new();
            if grown.try_reserve_exact(self.tape.events.len() + extra).is_err() {
                self.fail(IoCaptureError::Allocation);
                return false;
            }
            grown.append(&mut self.tape.events);
            self.tape.events.spare_capacity_mut().zeroize();
            self.tape.events = grown;
        }
        self.tape.read_bytes += read;
        self.tape.write_bytes += write;
        true
    }

    fn record_write(&mut self, input: WriteInput<'_, '_>, result: &io::Result<usize>) {
        let Some(length) = input.length() else {
            self.fail(IoCaptureError::InvalidProgress);
            return;
        };
        let (accepted, error) = match result {
            Ok(count) if *count <= length => (*count, None),
            Ok(_) => {
                self.fail(IoCaptureError::InvalidProgress);
                return;
            }
            Err(error) => (0, Some(IoFailure::capture(error))),
        };
        if !self.reserve(0, length, input.slice_count()) {
            return;
        }
        let slices = match input {
            WriteInput::Scalar(_) => None,
            WriteInput::Vectored(bufs) => {
                let mut lengths = Vec::new();
                if lengths.try_reserve_exact(bufs.len()).is_err() {
                    self.fail(IoCaptureError::Allocation);
                    return;
                }
                lengths.extend(bufs.iter().map(|buf| buf.len()));
                Some(lengths)
            }
        };
        self.tape.events.push(Event::Write {
            length,
            slices,
            digest: input.digest(),
            accepted,
            error,
        });
    }

    fn record_pending_write(&mut self, input: WriteInput<'_, '_>) {
        let Some(length) = input.length() else {
            self.fail(IoCaptureError::InvalidProgress);
            return;
        };
        if !self.reserve(0, length, input.slice_count()) {
            return;
        }
        let slices = match input {
            WriteInput::Scalar(_) => None,
            WriteInput::Vectored(bufs) => {
                let mut lengths = Vec::new();
                if lengths.try_reserve_exact(bufs.len()).is_err() {
                    self.fail(IoCaptureError::Allocation);
                    return;
                }
                lengths.extend(bufs.iter().map(|buf| buf.len()));
                Some(lengths)
            }
        };
        self.tape.events.push(Event::Pending(PendingRequest::Write {
            length,
            slices,
            digest: input.digest(),
        }));
    }
}

#[derive(Clone, Copy)]
enum WriteInput<'a, 'b> {
    Scalar(&'a [u8]),
    Vectored(&'a [IoSlice<'b>]),
}

impl WriteInput<'_, '_> {
    fn length(self) -> Option<usize> {
        match self {
            Self::Scalar(buf) => Some(buf.len()),
            Self::Vectored(bufs) => bufs
                .iter()
                .try_fold(0usize, |n, buf| n.checked_add(buf.len())),
        }
    }

    fn slice_count(self) -> usize {
        match self {
            Self::Scalar(_) => 0,
            Self::Vectored(bufs) => bufs.len(),
        }
    }

    fn operation(self) -> IoOperation {
        match self {
            Self::Scalar(_) => IoOperation::Write,
            Self::Vectored(_) => IoOperation::WriteVectored,
        }
    }

    fn digest(self) -> Zeroizing<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"asupersync.io-write.v1");
        match self {
            Self::Scalar(buf) => hash.update(buf),
            Self::Vectored(bufs) => {
                for buf in bufs {
                    hash.update(&buf[..]);
                }
            }
        }
        Zeroizing::new(hash.finalize().into())
    }

    fn matches_slices(self, recorded: Option<&Vec<usize>>) -> bool {
        match (self, recorded) {
            (Self::Scalar(_), None) => true,
            (Self::Vectored(bufs), Some(lengths)) => {
                bufs.len() == lengths.len()
                    && bufs.iter().zip(lengths).all(|(buf, len)| buf.len() == *len)
            }
            _ => false,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for RecordingIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
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
                    this.tape.events.push(Event::Read {
                        capacity,
                        bytes: retained,
                        error: outcome.as_ref().err().map(IoFailure::capture),
                    });
                }
            }
        } else if !bytes.is_empty() {
            this.fail(IoCaptureError::InvalidProgress);
        } else if this.tape.pending_polls && this.reserve(0, 0, 0) {
            this.tape.events.push(Event::Pending(PendingRequest::Read {
                capacity,
            }));
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for RecordingIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.begin();
        let result = Pin::new(&mut this.inner).poll_write(ctx, buf);
        this.polling = false;
        if let Poll::Ready(outcome) = &result {
            this.record_write(WriteInput::Scalar(buf), outcome);
        } else if this.tape.pending_polls {
            this.record_pending_write(WriteInput::Scalar(buf));
        }
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.begin();
        let result = Pin::new(&mut this.inner).poll_write_vectored(ctx, bufs);
        this.polling = false;
        if let Poll::Ready(outcome) = &result {
            this.record_write(WriteInput::Vectored(bufs), outcome);
        } else if this.tape.pending_polls {
            this.record_pending_write(WriteInput::Vectored(bufs));
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.tape.vectored
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.begin();
        let result = Pin::new(&mut this.inner).poll_flush(ctx);
        this.polling = false;
        if let Poll::Ready(outcome) = &result {
            if this.reserve(0, 0, 0) {
                this.tape
                    .events
                    .push(Event::Flush(outcome.as_ref().err().map(IoFailure::capture)));
            }
        } else if this.tape.pending_polls && this.reserve(0, 0, 0) {
            this.tape.events.push(Event::Pending(PendingRequest::Flush));
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.begin();
        let result = Pin::new(&mut this.inner).poll_shutdown(ctx);
        this.polling = false;
        if let Poll::Ready(outcome) = &result {
            if this.reserve(0, 0, 0) {
                this.tape.events.push(Event::Shutdown(
                    outcome.as_ref().err().map(IoFailure::capture),
                ));
            }
        } else if this.tape.pending_polls && this.reserve(0, 0, 0) {
            this.tape.events.push(Event::Pending(PendingRequest::Shutdown));
        }
        result
    }
}

/// First replay refusal. Does not contain payloads, fingerprints, or error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "[ASUP-E401] I/O replay divergence at operation {index}: {reason:?} (expected {expected:?}, actual {actual:?})"
)]
pub struct IoReplayError {
    /// Zero-based observation index; pending-aware tapes include pending polls.
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
        /// Number of source observations not replayed.
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
/// Pending-aware tapes additionally reproduce each pending request once, and
/// do not wake a trailing parked direction after its last recorded observation.
pub struct ReplayIo {
    tape: IoTape,
    index: usize,
    failure: Option<IoReplayError>,
    read_waiter: Option<Waker>,
    write_waiter: Option<Waker>,
    remaining_reads: usize,
    remaining_writes: usize,
}

impl fmt::Debug for ReplayIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayIo")
            .field("index", &self.index)
            .field("tape", &self.tape)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl ReplayIo {
    /// Number of exact source observations reproduced, including pending polls
    /// when the tape was captured with [`RecordingIo::new_with_pending_io`].
    #[must_use]
    pub const fn consumed_operations(&self) -> usize {
        self.index
    }

    /// Sticky first failure, even after the consumer catches/ignores its I/O error.
    #[must_use]
    pub const fn failure(&self) -> Option<IoReplayError> {
        self.failure
    }

    /// Verify both absence of divergence and full capture-window consumption.
    ///
    /// For a pending-aware tape, consuming the final recorded `Pending` poll
    /// can make this return `Ok(())` while the I/O operation and its owning task
    /// are still pending. This checks the captured window only: it does not
    /// complete I/O, cancel users, or establish task/region quiescence. Polls
    /// caused by cancellation or other events outside that window are not
    /// recorded; an extra I/O poll still exhausts the tape.
    pub fn verify_complete(&self) -> Result<(), IoReplayCompletionError> {
        if let Some(error) = self.failure {
            return Err(IoReplayCompletionError::Diverged(error));
        }
        let remaining = self.tape.events.len() - self.index;
        if remaining != 0 {
            return Err(IoReplayCompletionError::Remaining { remaining });
        }
        Ok(())
    }

    fn refuse(&mut self, actual: IoOperation, reason: IoReplayMismatch) -> io::Error {
        let error = *self.failure.get_or_insert(IoReplayError {
            index: self.index,
            expected: self.tape.events.get(self.index).map(Event::operation),
            actual,
            reason,
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
            let remaining = if actual.is_read() {
                self.remaining_reads
            } else {
                self.remaining_writes
            };
            if self.tape.pending_polls && remaining == 0 {
                return Poll::Ready(Err(self.refuse(actual, IoReplayMismatch::Exhausted)));
            }
            self.remember_waiter(ctx, actual);
            return Poll::Pending;
        }
        if expected != actual {
            return Poll::Ready(Err(self.refuse(actual, IoReplayMismatch::Operation)));
        }
        Poll::Ready(Ok(()))
    }

    fn remember_waiter(&mut self, ctx: &Context<'_>, operation: IoOperation) {
        let slot = if operation.is_read() {
            &mut self.read_waiter
        } else {
            &mut self.write_waiter
        };
        if !slot.as_ref().is_some_and(|waker| waker.will_wake(ctx.waker())) {
            *slot = Some(ctx.waker().clone());
        }
    }

    fn wake_waiters(&mut self) {
        let read = self.read_waiter.take();
        let write = self.write_waiter.take();
        if let Some(waker) = read {
            if self.failure.is_some() || !self.tape.pending_polls || self.remaining_reads != 0 {
                waker.wake();
            }
        }
        if let Some(waker) = write {
            if self.failure.is_some() || !self.tape.pending_polls || self.remaining_writes != 0 {
                waker.wake();
            }
        }
    }

    fn advance(&mut self) {
        if self.tape.pending_polls {
            if self.tape.events[self.index].operation().is_read() {
                self.remaining_reads -= 1;
            } else {
                self.remaining_writes -= 1;
            }
        }
        self.index += 1;
        self.wake_waiters();
    }

    fn pending(&mut self, ctx: &Context<'_>, operation: IoOperation) {
        self.remember_waiter(ctx, operation);
        // A later recorded observation authorizes progress, not an uncaptured
        // retry at the cutoff. A last pending poll leaves no replay wake behind.
        self.advance();
    }

    fn write(
        &mut self,
        ctx: &mut Context<'_>,
        input: WriteInput<'_, '_>,
    ) -> Poll<io::Result<usize>> {
        let operation = input.operation();
        ready!(self.ready(ctx, operation))?;
        let (length, slices, digest, result) = match &self.tape.events[self.index] {
            Event::Write {
                length, slices, digest, accepted, error,
            } => (
                length,
                slices,
                digest,
                Some(error.map_or(Ok(*accepted), |error| Err(error.replay()))),
            ),
            Event::Pending(PendingRequest::Write { length, slices, digest }) => {
                (length, slices, digest, None)
            }
            _ => unreachable!("operation checked above"),
        };
        if input.length() != Some(*length)
            || !input.matches_slices(slices.as_ref())
            || input.digest().as_ref() != digest.as_ref()
        {
            return Poll::Ready(Err(self.refuse(operation, IoReplayMismatch::Request)));
        }
        if let Some(result) = result {
            self.advance();
            Poll::Ready(result)
        } else {
            self.pending(ctx, operation);
            Poll::Pending
        }
    }

    fn finish_write(
        &mut self,
        ctx: &mut Context<'_>,
        operation: IoOperation,
    ) -> Poll<io::Result<()>> {
        ready!(self.ready(ctx, operation))?;
        let error = match &self.tape.events[self.index] {
            Event::Flush(error) | Event::Shutdown(error) => *error,
            Event::Pending(PendingRequest::Flush | PendingRequest::Shutdown) => {
                self.pending(ctx, operation);
                return Poll::Pending;
            }
            _ => unreachable!("operation checked above"),
        };
        self.advance();
        Poll::Ready(error.map_or(Ok(()), |error| Err(error.replay())))
    }
}

impl AsyncRead for ReplayIo {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.ready(ctx, IoOperation::Read))?;
        if let Event::Pending(PendingRequest::Read { capacity }) = &this.tape.events[this.index] {
            if buf.remaining() != *capacity {
                return Poll::Ready(Err(this.refuse(IoOperation::Read, IoReplayMismatch::Request)));
            }
            this.pending(ctx, IoOperation::Read);
            return Poll::Pending;
        }
        let Event::Read {
            capacity,
            bytes,
            error,
        } = &this.tape.events[this.index]
        else {
            unreachable!("operation checked above")
        };
        if buf.remaining() != *capacity {
            return Poll::Ready(Err(
                this.refuse(IoOperation::Read, IoReplayMismatch::Request)
            ));
        }
        buf.put_slice(bytes);
        let result = error.map_or(Ok(()), |error| Err(error.replay()));
        this.advance();
        Poll::Ready(result)
    }
}

impl AsyncWrite for ReplayIo {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().write(ctx, WriteInput::Scalar(buf))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().write(ctx, WriteInput::Vectored(bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.tape.vectored
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().finish_write(ctx, IoOperation::Flush)
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().finish_write(ctx, IoOperation::Shutdown)
    }
}

#[cfg(test)]
#[path = "replay_inline_tests.rs"]
mod tests;

mod codec;
pub use codec::{IoTapeBytes, IoTapeDecodeLimits, IoTapeError};

#[cfg(test)]
#[path = "replay/pending_tests.rs"]
mod pending_tests;
