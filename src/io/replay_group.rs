//! Bounded capture and ordered offline replay across multiple byte streams.
//!
//! Register already-authorized streams with caller-chosen identities. Each
//! stream uses the existing [`RecordingIo`] capture engine; the group records
//! one total order of completed polls across them. Independent live polls may
//! overlap: their order is assigned after the provider returns, before the
//! adapter returns the result. This is an observation order, NOT kernel-event
//! timing, a task schedule, or a claim about the order of remote side effects.
//!
//! Finalize every stream with [`RecordingGroupIo::into_inner`], then finish the
//! group. A dropped stream, source panic, or any exhausted capture bound refuses
//! the entire capture, without changing successful or failed live I/O results.
//! Replay has no provider. An early poll on another stream parks until its turn;
//! changing the next operation on the SAME stream is a sticky error. In
//! particular the unsplit interface rejects reordered read/write operations.
//! [`ReplayGroupIo::into_split`] permits independent polling of owned directions
//! without reordering their completions. Pending live polls are not captured.
//!
//! This records only byte I/O. It does not capture connection establishment,
//! clocks, entropy, cancellation, task lifetimes, or effects outside these
//! adapters. Owners must reconstruct their consumer, drive every prerequisite,
//! and verify complete consumption after draining users. Idleness is not success.
//! Captures may contain plaintext secrets. Debug is redacted, component tapes
//! zeroize their sensitive storage, and nothing is persisted automatically.

use super::replay::{IoCaptureError, IoCaptureLimits, IoOperation, IoReplayError, IoTape, RecordingIo, ReplayIo};
use super::{AsyncRead, AsyncWrite, ReadBuf};
use parking_lot::Mutex;
use std::fmt;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker, ready};

/// Explicit group and per-stream limits; no unbounded default.
///
/// The aggregate component allowance is at most `max_streams` times each
/// per-stream allowance. Order storage is independently bounded by `max_events`.
/// These are logical limits, not allocator, provider, or waiting-task RSS limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoGroupCaptureLimits {
    /// Maximum distinct streams, including empty streams. Identities cannot be reused.
    pub max_streams: usize,
    /// Maximum completed polls across every stream.
    pub max_events: usize,
    /// Independent bounds applied to every registered stream.
    pub per_stream: IoCaptureLimits,
}

/// Redacted capture/registration refusal. No partial tape escapes a failed group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IoGroupCaptureError {
    /// Another stream already registered this caller-chosen identity.
    #[error("I/O group stream identity {0} is already registered")]
    DuplicateStream(u64),
    /// A logical count limit was reached.
    #[error("I/O group capture exceeded its {0} limit")]
    Limit(&'static str),
    /// Bounded metadata storage could not be reserved.
    #[error("I/O group capture allocation failed")]
    Allocation,
    /// A provider poll unwound instead of producing a completed observation.
    #[error("I/O group stream {0} poll unwound")]
    InterruptedPoll(u64),
    /// A stream owner was dropped instead of explicitly finalizing its capture.
    #[error("I/O group stream {0} capture was abandoned")]
    AbandonedStream(u64),
    /// One underlying stream capture refused its window.
    #[error("I/O group stream {stream} capture failed: {error}")]
    Stream {
        /// Caller-selected stream identity.
        stream: u64,
        /// Original component capture refusal.
        error: IoCaptureError,
    },
    /// Finalization may be retried after these stream owners return.
    #[error("I/O group still has {0} live stream captures")]
    LiveStreams(usize),
    /// The complete group tape was already taken.
    #[error("I/O group capture is already finished")]
    Finished,
    /// Internal observation counts did not cover all component operations.
    #[error("I/O group order does not cover its component windows")]
    Coverage,
}

/// Refused registration, retaining the original unwrapped stream.
pub struct IoGroupRegistrationError<T> {
    /// The registration refusal, with no invented admission.
    pub error: IoGroupCaptureError,
    /// The original provider, unchanged by byte-I/O operations.
    pub io: T,
}
impl<T> fmt::Debug for IoGroupRegistrationError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoGroupRegistrationError").field("error", &self.error).finish_non_exhaustive()
    }
}
impl<T> fmt::Display for IoGroupRegistrationError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.error, f) }
}
impl<T> std::error::Error for IoGroupRegistrationError<T> {}

#[derive(Clone, Copy)]
struct Entry { stream: usize, operation: IoOperation }
struct CaptureSlot { id: u64, operations: usize, tape: Option<IoTape> }
struct CaptureState {
    slots: Vec<CaptureSlot>,
    order: Vec<Entry>,
    live: usize,
    finished: bool,
    failure: Option<IoGroupCaptureError>,
}
struct CaptureShared { limits: IoGroupCaptureLimits, state: Mutex<CaptureState> }

impl CaptureShared {
    fn registration_check(&self, state: &CaptureState, id: u64) -> Result<(), IoGroupCaptureError> {
        if state.finished { return Err(IoGroupCaptureError::Finished); }
        if let Some(error) = state.failure { return Err(error); }
        if state.slots.iter().any(|slot| slot.id == id) {
            return Err(IoGroupCaptureError::DuplicateStream(id));
        }
        if state.slots.len() >= self.limits.max_streams {
            return Err(IoGroupCaptureError::Limit("streams"));
        }
        Ok(())
    }

    fn fail(&self, error: IoGroupCaptureError) { self.state.lock().failure.get_or_insert(error); }

    fn record(&self, stream: usize, operation: IoOperation) {
        let mut state = self.state.lock();
        if state.failure.is_some() { return; }
        let error = if state.order.len() >= self.limits.max_events {
            Some(IoGroupCaptureError::Limit("events"))
        } else if state.order.try_reserve(1).is_err() {
            Some(IoGroupCaptureError::Allocation)
        } else { None };
        if let Some(error) = error { state.failure = Some(error); return; }
        state.order.push(Entry { stream, operation });
        state.slots[stream].operations += 1; // bounded by the successfully appended order
    }
}

struct CapturePoll<'a> { shared: &'a CaptureShared, id: u64, armed: bool }
impl Drop for CapturePoll<'_> {
    fn drop(&mut self) {
        if self.armed { self.shared.fail(IoGroupCaptureError::InterruptedPoll(self.id)); }
    }
}

/// Cloneable registration/collection authority, not a runtime or an I/O capability.
#[derive(Clone)]
pub struct IoRecordingGroup { shared: Arc<CaptureShared> }
impl fmt::Debug for IoRecordingGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.state.lock();
        f.debug_struct("IoRecordingGroup").field("streams", &state.slots.len())
            .field("events", &state.order.len()).field("live", &state.live)
            .field("failure", &state.failure).finish_non_exhaustive()
    }
}
impl IoRecordingGroup {
    /// Start an empty bounded window. No provider is invoked.
    #[must_use]
    pub fn new(limits: IoGroupCaptureLimits) -> Self {
        Self { shared: Arc::new(CaptureShared { limits, state: Mutex::new(CaptureState {
            slots: Vec::new(), order: Vec::new(), live: 0, finished: false, failure: None,
        }) }) }
    }

    /// Wrap one supplied stream; heterogeneous stream types may share a group.
    ///
    /// Registration performs no byte I/O. The provider's vectored-write capability
    /// is sampled outside the group lock. If another registration or finish wins
    /// during that query, refusal still returns the original provider.
    pub fn register<T: AsyncWrite>(&self, id: u64, io: T) -> Result<RecordingGroupIo<T>, IoGroupRegistrationError<T>> {
        let checked = self.shared.registration_check(&self.shared.state.lock(), id);
        if let Err(error) = checked { return Err(IoGroupRegistrationError { error, io }); }
        let recording = RecordingIo::new(io, self.shared.limits.per_stream);
        let admitted = {
            let mut state = self.shared.state.lock();
            self.shared.registration_check(&state, id).and_then(|()| {
                state.slots.try_reserve(1).map_err(|_| IoGroupCaptureError::Allocation)?;
                let index = state.slots.len();
                state.slots.push(CaptureSlot { id, operations: 0, tape: None });
                state.live += 1;
                Ok(index)
            })
        };
        match admitted {
            Ok(index) => Ok(RecordingGroupIo { inner: Some(recording), shared: Arc::clone(&self.shared), index, id }),
            Err(error) => {
                let (io, _) = recording.into_parts();
                Err(IoGroupRegistrationError { error, io })
            }
        }
    }

    /// Take all component tapes and their order, once, after every stream returned.
    ///
    /// `LiveStreams` is nonterminal: users can finish and this can be retried.
    /// Registration refusals do not poison otherwise valid captures. A failed
    /// provider window, dropped stream, or group event-limit failure does.
    pub fn finish(&self) -> Result<RecordedIoGroup, IoGroupCaptureError> {
        let mut state = self.shared.state.lock();
        if state.finished { return Err(IoGroupCaptureError::Finished); }
        if let Some(error) = state.failure { return Err(error); }
        if state.live != 0 { return Err(IoGroupCaptureError::LiveStreams(state.live)); }
        if state.slots.iter().any(|slot| slot.tape.as_ref().map(IoTape::operations) != Some(slot.operations)) {
            state.failure = Some(IoGroupCaptureError::Coverage);
            return Err(IoGroupCaptureError::Coverage);
        }
        let mut streams = Vec::new();
        streams.try_reserve_exact(state.slots.len()).map_err(|_| IoGroupCaptureError::Allocation)?;
        for slot in state.slots.drain(..) {
            streams.push(RecordedStream { id: slot.id, tape: slot.tape.expect("completed capture checked") });
        }
        state.finished = true;
        Ok(RecordedIoGroup { streams, order: std::mem::take(&mut state.order) })
    }
}

/// Transparent live stream adapter. Dropping it refuses the complete group tape.
pub struct RecordingGroupIo<T> {
    inner: Option<RecordingIo<T>>, shared: Arc<CaptureShared>, index: usize, id: u64,
}
impl<T> fmt::Debug for RecordingGroupIo<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingGroupIo").field("stream", &self.id).finish_non_exhaustive()
    }
}
impl<T> RecordingGroupIo<T> {
    /// Finalize this stream's window and always return its original provider.
    /// Group-wide success is established separately by `IoRecordingGroup::finish`.
    pub fn into_inner(mut self) -> T {
        let (io, tape) = self.inner.take().expect("live recording stream").into_parts();
        let mut state = self.shared.state.lock();
        state.live -= 1;
        match tape {
            Ok(tape) => state.slots[self.index].tape = Some(tape),
            Err(error) => { state.failure.get_or_insert(IoGroupCaptureError::Stream { stream: self.id, error }); }
        }
        drop(state);
        io
    }

    fn poll_with<O>(&mut self, operation: IoOperation, poll: impl FnOnce(&mut RecordingIo<T>) -> Poll<io::Result<O>>) -> Poll<io::Result<O>> {
        let mut guard = CapturePoll { shared: &self.shared, id: self.id, armed: true };
        let result = poll(self.inner.as_mut().expect("live recording stream"));
        if result.is_ready() { self.shared.record(self.index, operation); }
        guard.armed = false;
        result
    }
}
impl<T> Drop for RecordingGroupIo<T> {
    fn drop(&mut self) {
        if self.inner.is_some() {
            let mut state = self.shared.state.lock();
            state.live -= 1;
            state.failure.get_or_insert(IoGroupCaptureError::AbandonedStream(self.id));
        }
        // The original provider is retired by field Drop after releasing the lock.
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for RecordingGroupIo<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(IoOperation::Read, |io| Pin::new(io).poll_read(cx, buf))
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for RecordingGroupIo<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(IoOperation::Write, |io| Pin::new(io).poll_write(cx, buf))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(IoOperation::WriteVectored, |io| Pin::new(io).poll_write_vectored(cx, bufs))
    }
    fn is_write_vectored(&self) -> bool { self.inner.as_ref().expect("live recording stream").is_write_vectored() }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(IoOperation::Flush, |io| Pin::new(io).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(IoOperation::Shutdown, |io| Pin::new(io).poll_shutdown(cx))
    }
}

struct RecordedStream { id: u64, tape: IoTape }
/// Complete multi-stream observation window; retains no original providers.
pub struct RecordedIoGroup { streams: Vec<RecordedStream>, order: Vec<Entry> }
impl fmt::Debug for RecordedIoGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordedIoGroup").field("streams", &self.streams.len())
            .field("events", &self.order.len()).finish_non_exhaustive()
    }
}
impl RecordedIoGroup {
    /// Number of distinct streams, including zero-operation streams.
    #[must_use]
    pub fn streams(&self) -> usize { self.streams.len() }
    /// Number of captured completed I/O operations across all streams.
    #[must_use]
    pub fn operations(&self) -> usize { self.order.len() }
    /// Caller-selected identities in registration order; not network addresses.
    pub fn stream_ids(&self) -> impl Iterator<Item = u64> + '_ { self.streams.iter().map(|stream| stream.id) }
    /// Create exclusively offline stream providers and shared order verification.
    #[must_use]
    pub fn replay(self) -> IoReplayGroup {
        let slots = self.streams.into_iter().map(|stream| ReplaySlot {
            id: stream.id, operations: stream.tape.operations(), io: Some(stream.tape.replay()), waiter: None,
        }).collect();
        IoReplayGroup { shared: Arc::new(ReplayShared { state: Mutex::new(ReplayState {
            slots, order: self.order, index: 0, failure: None,
        }) }) }
    }
}

/// Opening a replay stream never opens a real connection or invents a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IoGroupOpenError {
    /// No captured provider has this identity.
    #[error("unknown replay stream {0}")]
    UnknownStream(u64),
    /// A stream has exactly one owner; it cannot be reopened or cloned.
    #[error("replay stream {0} was already opened")]
    AlreadyOpened(u64),
}

/// First sticky group replay failure, excluding sensitive request contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IoGroupReplayError {
    /// Per-stream request shape, write fingerprint, or extent changed.
    #[error("replay stream {stream}: {error}")]
    Stream {
        /// Caller-selected stream identity.
        stream: u64,
        /// Original component replay refusal.
        error: IoReplayError,
    },
    /// Wrong operation on the next eligible stream (including opposite direction).
    #[error("replay stream {stream} expected {expected:?}, got {actual:?}")]
    Operation {
        /// Caller-selected stream identity.
        stream: u64,
        /// Next recorded operation.
        expected: IoOperation,
        /// Attempted operation.
        actual: IoOperation,
    },
    /// All captured completions were already consumed.
    #[error("replay stream {0} polled after group exhaustion")]
    Exhausted(u64),
    /// A stream owner was discarded with captured operations still outstanding.
    #[error("replay stream {stream} dropped with {remaining} operations outstanding")]
    AbandonedStream {
        /// Caller-selected stream identity.
        stream: u64,
        /// Unconsumed operations in that stream.
        remaining: usize,
    },
    /// One independently owned direction has no captured operations remaining.
    #[error("replay stream {stream} {direction:?} half polled after exhaustion")]
    ExhaustedHalf {
        /// Caller-selected stream identity.
        stream: u64,
        /// Exhausted direction.
        direction: ReplayDirection,
    },
    /// A direction owner was dropped before consuming its observations.
    #[error("replay stream {stream} {direction:?} half dropped with {remaining} operations outstanding")]
    AbandonedHalf {
        /// Caller-selected stream identity.
        stream: u64,
        /// Abandoned direction.
        direction: ReplayDirection,
        /// Unconsumed observations belonging to this direction.
        remaining: usize,
    },
    /// The eligible replay poll unwound. Unknown local progress is never retried.
    #[error("replay stream {0} poll unwound")]
    InterruptedPoll(u64),
    /// Component and group order disagree; no readiness is fabricated.
    #[error("replay stream {0} has inconsistent component ordering")]
    Coverage(u64),
}

/// The caller's result is not complete replay until this verification succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IoGroupCompletionError {
    /// Even an ignored per-stream error invalidates the whole group.
    #[error(transparent)]
    Diverged(IoGroupReplayError),
    /// Including events for streams which were never opened.
    #[error("I/O group replay has {0} unconsumed operations")]
    Remaining(usize),
}

struct ReplaySlot { id: u64, operations: usize, io: Option<ReplayIo>, waiter: Option<Arc<Waker>> }
struct ReplayState { slots: Vec<ReplaySlot>, order: Vec<Entry>, index: usize, failure: Option<IoGroupReplayError> }
struct ReplayShared { state: Mutex<ReplayState> }

fn wake(waker: Arc<Waker>) {
    // One hostile callback cannot strand the rest of an already-detached fanout.
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake_by_ref())) {
        std::mem::forget(payload);
    }
    // Waker retirement is arbitrary user code too, and may be on an unwind path.
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(waker))) {
        std::mem::forget(payload);
    }
}
impl ReplayState {
    fn turn(&self, index: usize, operation: IoOperation) -> Result<Option<usize>, IoGroupReplayError> {
        if let Some(error) = self.failure { return Err(error); }
        let id = self.slots[index].id;
        let Some(next) = self.order.get(self.index) else { return Err(IoGroupReplayError::Exhausted(id)); };
        if next.stream != index { return Ok(None); }
        if next.operation != operation {
            return Err(IoGroupReplayError::Operation { stream: id, expected: next.operation, actual: operation });
        }
        Ok(Some(self.index))
    }
}
impl ReplayShared {
    fn fail(&self, error: IoGroupReplayError) -> IoGroupReplayError {
        let error = *self.state.lock().failure.get_or_insert(error);
        self.wake_all();
        error
    }
    fn wake_all(&self) {
        // No temporary unbounded callback list. Detach a slot under lock and
        // invoke it only after unlocking; failures stop future registrations.
        let len = self.state.lock().slots.len();
        for index in 0..len {
            let waiter = self.state.lock().slots[index].waiter.take();
            if let Some(waiter) = waiter { wake(waiter); }
        }
    }
    fn enter(&self, index: usize, operation: IoOperation, cx: &Context<'_>) -> Poll<io::Result<usize>> {
        let initial = self.state.lock().turn(index, operation);
        match initial {
            Ok(Some(turn)) => return Poll::Ready(Ok(turn)),
            Err(error) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, self.fail(error)))),
            Ok(None) => {}
        }
        // Clone before locking and recheck afterward to close registration races.
        let mut incoming = Some(Arc::new(cx.waker().clone()));
        let (turn, stale) = {
            let mut state = self.state.lock();
            let turn = state.turn(index, operation);
            let stale = if matches!(turn, Ok(None)) {
                std::mem::replace(&mut state.slots[index].waiter, incoming.take())
            } else { None };
            (turn, stale)
        };
        drop(stale);
        drop(incoming);
        match turn {
            Ok(Some(turn)) => Poll::Ready(Ok(turn)),
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, self.fail(error)))),
        }
    }
    fn advance(&self, turn: usize) {
        let (next, at_end) = {
            let mut state = self.state.lock();
            if state.failure.is_some() { return; }
            assert_eq!(state.index, turn, "only the eligible exclusive stream owns a turn");
            state.index += 1;
            let next = state.order.get(state.index).map(|entry| entry.stream);
            let waiter = next.and_then(|index| state.slots[index].waiter.take());
            (waiter, next.is_none())
        };
        if let Some(next) = next { wake(next); }
        if at_end { self.wake_all(); }
    }
}

struct ReplayPoll<'a> { shared: &'a ReplayShared, id: u64, armed: bool }
impl Drop for ReplayPoll<'_> {
    fn drop(&mut self) {
        if self.armed { self.shared.fail(IoGroupReplayError::InterruptedPoll(self.id)); }
    }
}

/// Cloneable opening/verification handle. Streams themselves have exclusive owners.
#[derive(Clone)]
pub struct IoReplayGroup { shared: Arc<ReplayShared> }
impl fmt::Debug for IoReplayGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.state.lock();
        f.debug_struct("IoReplayGroup").field("streams", &state.slots.len())
            .field("consumed", &state.index).field("events", &state.order.len()).field("failure", &state.failure).finish_non_exhaustive()
    }
}
impl IoReplayGroup {
    /// Open one captured identity exactly once. Unknown identities have no fallback.
    pub fn open(&self, id: u64) -> Result<ReplayGroupIo, IoGroupOpenError> {
        let mut state = self.shared.state.lock();
        let index = state.slots.iter().position(|slot| slot.id == id).ok_or(IoGroupOpenError::UnknownStream(id))?;
        let slot = &mut state.slots[index];
        let inner = slot.io.take().ok_or(IoGroupOpenError::AlreadyOpened(id))?;
        Ok(ReplayGroupIo { shared: Arc::clone(&self.shared), index, id, operations: slot.operations, inner })
    }
    /// Verify the entire window, not just whichever stream the caller inspected.
    /// This is a point-in-time check; the owner must drain its users first. Empty
    /// captured streams need not be opened because they contain no observations.
    pub fn verify_complete(&self) -> Result<(), IoGroupCompletionError> {
        let state = self.shared.state.lock();
        if let Some(error) = state.failure { return Err(IoGroupCompletionError::Diverged(error)); }
        let remaining = state.order.len() - state.index;
        if remaining != 0 { Err(IoGroupCompletionError::Remaining(remaining)) } else { Ok(()) }
    }
}

/// Offline byte provider gated by the group's cross-stream completion order.
/// Dropping it with unread tape operations poisons the group and wakes peers.
pub struct ReplayGroupIo { shared: Arc<ReplayShared>, index: usize, id: u64, operations: usize, inner: ReplayIo }
impl fmt::Debug for ReplayGroupIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayGroupIo").field("stream", &self.id)
            .field("consumed", &self.inner.consumed_operations()).finish_non_exhaustive()
    }
}
impl ReplayGroupIo {
    fn poll_with<O>(&mut self, cx: &mut Context<'_>, operation: IoOperation, poll: impl FnOnce(&mut ReplayIo, &mut Context<'_>) -> Poll<io::Result<O>>) -> Poll<io::Result<O>> {
        // Exhausting one stream is already divergence, even while another
        // stream still has work. Do not park an impossible extra operation.
        if self.inner.consumed_operations() == self.operations {
            let error = self.shared.fail(IoGroupReplayError::Exhausted(self.id));
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
        }
        let turn = ready!(self.shared.enter(self.index, operation, cx))?;
        let mut guard = ReplayPoll { shared: &self.shared, id: self.id, armed: true };
        let result = poll(&mut self.inner, cx);
        let error = self.inner.failure().map(|error| IoGroupReplayError::Stream { stream: self.id, error })
            .or_else(|| result.is_pending().then_some(IoGroupReplayError::Coverage(self.id)));
        if let Some(error) = error {
            let error = self.shared.fail(error);
            guard.armed = false;
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
        }
        self.shared.advance(turn);
        guard.armed = false;
        result
    }
}
impl Drop for ReplayGroupIo {
    fn drop(&mut self) {
        let remaining = self.operations - self.inner.consumed_operations();
        if remaining != 0 { self.shared.fail(IoGroupReplayError::AbandonedStream { stream: self.id, remaining }); }
        let waiter = self.shared.state.lock().slots[self.index].waiter.take();
        if let Some(waiter) = waiter { wake(waiter); }
    }
}
impl AsyncRead for ReplayGroupIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, IoOperation::Read, |io, cx| Pin::new(io).poll_read(cx, buf))
    }
}
impl AsyncWrite for ReplayGroupIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(cx, IoOperation::Write, |io, cx| Pin::new(io).poll_write(cx, buf))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(cx, IoOperation::WriteVectored, |io, cx| Pin::new(io).poll_write_vectored(cx, bufs))
    }
    fn is_write_vectored(&self) -> bool { self.inner.is_write_vectored() }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, IoOperation::Flush, |io, cx| Pin::new(io).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, IoOperation::Shutdown, |io, cx| Pin::new(io).poll_shutdown(cx))
    }
}

#[cfg(test)]
mod tests;

mod codec;
pub use codec::{IoGroupBytes, IoGroupDecodeLimits, IoGroupTapeError};

mod duplex;
pub use duplex::{ReplayDirection, ReplayGroupReadHalf, ReplayGroupWriteHalf};
