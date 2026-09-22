//! Ordered capture/replay of multiple byte streams, one clock, and forked entropy.
//!
//! All providers are supplied explicitly. Unlike independent replay tapes, one
//! timeline binds every completed I/O operation to the surrounding clock and
//! entropy observations. Early I/O waits for its prerequisite; synchronous
//! effects fail rather than block when called out of order. No replay path has
//! a live provider. Original I/O errors are observations, not replay failures.
//!
//! This is a completed-effect window, not an executor or a task/wakeup trace.
//! Concurrent tasks may alternate non-overlapping provider calls, but overlapping
//! or reentrant live calls refuse capture instead of inventing a linearization.
//! Pending polls are not recorded. Within each stream, operation order remains
//! strict. Use the existing standalone group's duplex halves when only byte-I/O
//! order is needed. Unwrapped effects and connection establishment are outside
//! this window; clocks here do not drive a runtime's timers.
//!
//! Drain source users before finishing. Limits invalidate capture without
//! changing live results. Debug omits providers, bytes, timestamps, and entropy;
//! component tapes retain their zeroizing owners. Nothing is saved implicitly.

use super::replay::{IoCaptureLimits, IoOperation, IoTape, RecordingIo, ReplayIo};
use super::{AsyncRead, AsyncWrite, ReadBuf};
use crate::time::TimeSource;
use crate::time::replay::{RecordingTimeSource, ReplayTimeSource, TimeCaptureError, TimeTape};
use crate::types::{TaskId, Time};
use crate::util::entropy::EntropySource;
use crate::util::entropy_replay::{
    EntropyCaptureError, EntropyCaptureLimits, EntropyTape, RecordingEntropy, ReplayEntropy,
};
use parking_lot::Mutex;
use std::fmt;
use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker, ready};

mod gate;
use gate::{CaptureState, CaptureTimeline, ReplaySlot, ReplayState, ReplayTimeline};

/// Explicit logical storage limits; no unbounded default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupSessionCaptureLimits {
    /// Unique byte streams, including empty streams. Identities cannot be reused.
    pub max_streams: usize,
    /// Total completed effects, including entropy forks and empty I/O operations.
    pub max_effects: usize,
    /// Independent limits for each stream. Aggregate allowances multiply by stream count.
    pub per_stream: IoCaptureLimits,
    /// Aggregate entropy calls/bytes/forks.
    pub entropy: EntropyCaptureLimits,
    /// Maximum clock samples, including repeated timestamps.
    pub clock_observations: usize,
}

/// An effect's identity/category, never its captured value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupEffect {
    /// Completed operation on a caller-selected stream identity.
    Io {
        /// Caller-selected byte-stream identity.
        stream: u64,
        /// Exact I/O operation category.
        operation: IoOperation,
    },
    /// Serial clock sample.
    Clock,
    /// Entropy read on a fork-tree ordinal (root is zero).
    Entropy(usize),
    /// Entropy fork on a parent ordinal; exact TaskId is checked by the entropy tape.
    Fork(usize),
}

#[derive(Clone, Copy)]
struct Entry {
    effect: GroupEffect,
    child: usize,
}
struct RecordedStream {
    id: u64,
    tape: IoTape,
}
struct CaptureSlot {
    id: u64,
    tape: Option<IoTape>,
}

/// A refused window or stream admission; contains no captured values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GroupSessionCaptureError {
    /// Duplicate registration does not invalidate previously admitted streams.
    #[error("group session stream {0} is already registered")]
    DuplicateStream(u64),
    /// Stream admission/effect storage exceeded the corresponding logical bound.
    #[error("group session exceeded its {0} limit")]
    Limit(&'static str),
    /// Bounded storage could not be reserved.
    #[error("group session allocation failed")]
    Allocation,
    /// Provider calls overlapped/reentered; no total effect order is asserted.
    #[error("group session provider calls overlapped")]
    Overlap,
    /// A provider panicked while an observation was in flight.
    #[error("group session provider call unwound")]
    Interrupted,
    /// Finish raced a provider call and refuses the whole window.
    #[error("group session finished during a provider call")]
    InFlight,
    /// Finish can be retried after these owners return their providers.
    #[error("group session still has {0} live byte streams")]
    LiveStreams(usize),
    /// The capture has already been taken/refused.
    #[error("group session is already finished")]
    Finished,
    /// An owner dropped instead of explicitly returning its provider.
    #[error("group session stream {0} was abandoned")]
    AbandonedStream(u64),
    /// A component refused its entire capture window.
    #[error("group session stream {stream} capture failed: {error}")]
    Io {
        /// Caller-selected byte-stream identity.
        stream: u64,
        /// Component capture refusal.
        error: super::replay::IoCaptureError,
    },
    /// Entropy capture failed; no partial group escapes.
    #[error("group session entropy capture failed: {0}")]
    Entropy(EntropyCaptureError),
    /// Clock capture failed; no partial group escapes.
    #[error("group session clock capture failed: {0}")]
    Clock(TimeCaptureError),
    /// Counts, source topology, or stream identities do not cover component windows.
    #[error("group session timeline does not cover its component windows")]
    Coverage,
}

/// Failed registration returns the original, unpolled provider.
pub struct GroupSessionRegistrationError<T> {
    /// Admission refusal, without changing any previously admitted window.
    pub error: GroupSessionCaptureError,
    /// Original provider, never polled during registration.
    pub io: T,
}
impl<T> fmt::Debug for GroupSessionRegistrationError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupSessionRegistrationError").field("error", &self.error).finish_non_exhaustive()
    }
}
impl<T> fmt::Display for GroupSessionRegistrationError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.error, f) }
}
impl<T> std::error::Error for GroupSessionRegistrationError<T> {}

/// Live registration/finalization authority and shared clock/entropy adapters.
pub struct RecordingGroupSession<S: ?Sized> {
    timeline: Arc<CaptureTimeline>,
    entropy_recorder: Arc<RecordingEntropy>,
    entropy: Arc<GroupRecordingEntropy>,
    clock: Arc<GroupRecordingClock<S>>,
}
impl<S: ?Sized> fmt::Debug for RecordingGroupSession<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingGroupSession").finish_non_exhaustive()
    }
}
impl<S: TimeSource + ?Sized> RecordingGroupSession<S> {
    /// Wrap authorized source capabilities without sampling either source.
    pub fn new(
        entropy: Arc<dyn EntropySource>,
        clock: Arc<S>,
        limits: GroupSessionCaptureLimits,
    ) -> Result<Self, EntropyCaptureError> {
        let entropy_recorder = Arc::new(RecordingEntropy::new(entropy, limits.entropy)?);
        let timeline = Arc::new(CaptureTimeline {
            limits,
            state: Mutex::new(CaptureState::default()),
        });
        let source: Arc<dyn EntropySource> = entropy_recorder.clone();
        Ok(Self {
            entropy: Arc::new(GroupRecordingEntropy { inner: source, timeline: Arc::clone(&timeline), source: 0 }),
            clock: Arc::new(GroupRecordingClock {
                inner: RecordingTimeSource::new(clock, limits.clock_observations),
                timeline: Arc::clone(&timeline),
            }),
            entropy_recorder,
            timeline,
        })
    }

    /// Share the wrapped entropy capability. All descendants remain in the same timeline.
    #[must_use]
    pub fn entropy(&self) -> Arc<GroupRecordingEntropy> { Arc::clone(&self.entropy) }

    /// Share the wrapped observation clock (not a runtime timer driver).
    #[must_use]
    pub fn clock(&self) -> Arc<GroupRecordingClock<S>> { Arc::clone(&self.clock) }

    /// Register an already-open stream. Different provider types may share a session.
    /// The vectored-write capability is queried outside the timeline lock.
    pub fn register<T: AsyncWrite>(&self, id: u64, io: T) -> Result<GroupRecordingIo<T>, GroupSessionRegistrationError<T>> {
        let checked = self.timeline.check_registration(&self.timeline.state.lock(), id);
        if let Err(error) = checked { return Err(GroupSessionRegistrationError { error, io }); }
        let inner = RecordingIo::new(io, self.timeline.limits.per_stream);
        let admitted = {
            let mut state = self.timeline.state.lock();
            self.timeline.check_registration(&state, id).and_then(|()| {
                state.slots.try_reserve_exact(1).map_err(|_| GroupSessionCaptureError::Allocation)?;
                let index = state.slots.len();
                state.slots.push(CaptureSlot { id, tape: None });
                state.live += 1;
                Ok(index)
            })
        };
        match admitted {
            Ok(index) => Ok(GroupRecordingIo { inner: Some(inner), timeline: Arc::clone(&self.timeline), index, id }),
            Err(error) => {
                let (io, _) = inner.into_parts();
                Err(GroupSessionRegistrationError { error, io })
            }
        }
    }

    /// Finish once, after every stream returned and source users drained.
    ///
    /// `LiveStreams` is retryable and does not finish the clock or entropy tapes.
    /// Every terminal path checks all components. Successful component tapes are
    /// dropped/zeroized on refusal; none is returned as a partial session.
    /// Retained source handles continue forwarding after finish, outside the window.
    pub fn finish(&self) -> Result<RecordedGroupSession, GroupSessionCaptureError> {
        let (slots, entries, failure) = {
            let mut state = self.timeline.state.lock();
            if state.finished { return Err(GroupSessionCaptureError::Finished); }
            if state.live != 0 { return Err(GroupSessionCaptureError::LiveStreams(state.live)); }
            state.finished = true;
            if state.active { state.failure.get_or_insert(GroupSessionCaptureError::InFlight); }
            (std::mem::take(&mut state.slots), std::mem::take(&mut state.entries), state.failure)
        };
        let entropy = self.entropy_recorder.finish();
        let clock = self.clock.inner.finish();
        if let Some(error) = failure { return Err(error); }
        let entropy = entropy.map_err(GroupSessionCaptureError::Entropy)?;
        let clock = clock.map_err(GroupSessionCaptureError::Clock)?;
        let mut streams = Vec::new();
        streams.try_reserve_exact(slots.len()).map_err(|_| GroupSessionCaptureError::Allocation)?;
        for slot in slots {
            streams.push(RecordedStream { id: slot.id, tape: slot.tape.ok_or(GroupSessionCaptureError::Coverage)? });
        }
        let tape = RecordedGroupSession { streams, entropy, clock, entries };
        if !tape.covers()? { return Err(GroupSessionCaptureError::Coverage); }
        Ok(tape)
    }
}

/// A transparent live byte stream in an ordered group session.
/// Return its provider with `into_inner`; dropping it abandons the whole window.
pub struct GroupRecordingIo<T> {
    inner: Option<RecordingIo<T>>,
    timeline: Arc<CaptureTimeline>,
    index: usize,
    id: u64,
}
impl<T> fmt::Debug for GroupRecordingIo<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupRecordingIo").field("stream", &self.id).finish_non_exhaustive()
    }
}
impl<T> GroupRecordingIo<T> {
    /// End this stream's capture without closing or replacing its original provider.
    pub fn into_inner(mut self) -> T {
        let (io, tape) = self.inner.take().expect("live capture owner").into_parts();
        let mut state = self.timeline.state.lock();
        state.live -= 1;
        match tape {
            Ok(tape) => state.slots[self.index].tape = Some(tape),
            Err(error) => { state.failure.get_or_insert(GroupSessionCaptureError::Io { stream: self.id, error }); }
        }
        drop(state);
        io
    }

    fn poll_with<O>(&mut self, operation: IoOperation, poll: impl FnOnce(&mut RecordingIo<T>) -> Poll<io::Result<O>>) -> Poll<io::Result<O>> {
        let guard = self.timeline.begin();
        let result = poll(self.inner.as_mut().expect("live capture owner"));
        if let Some(guard) = guard { guard.finish(GroupEffect::Io { stream: self.id, operation }, result.is_ready()); }
        result
    }
}
impl<T> Drop for GroupRecordingIo<T> {
    fn drop(&mut self) {
        if self.inner.is_some() {
            let mut state = self.timeline.state.lock();
            state.live -= 1;
            state.failure.get_or_insert(GroupSessionCaptureError::AbandonedStream(self.id));
        }
        // Original provider destruction happens after the timeline lock is released.
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for GroupRecordingIo<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(IoOperation::Read, |io| Pin::new(io).poll_read(cx, buf))
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for GroupRecordingIo<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(IoOperation::Write, |io| Pin::new(io).poll_write(cx, buf))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(IoOperation::WriteVectored, |io| Pin::new(io).poll_write_vectored(cx, bufs))
    }
    fn is_write_vectored(&self) -> bool { self.inner.as_ref().expect("live capture owner").is_write_vectored() }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(IoOperation::Flush, |io| Pin::new(io).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(IoOperation::Shutdown, |io| Pin::new(io).poll_shutdown(cx))
    }
}

/// Live entropy capability with ordered, transitive fork capture.
pub struct GroupRecordingEntropy {
    inner: Arc<dyn EntropySource>,
    timeline: Arc<CaptureTimeline>,
    source: usize,
}
impl fmt::Debug for GroupRecordingEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupRecordingEntropy").field("source", &self.source).finish_non_exhaustive()
    }
}
impl EntropySource for GroupRecordingEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) {
        let guard = self.timeline.begin();
        self.inner.fill_bytes(dest);
        if let Some(guard) = guard { guard.finish(GroupEffect::Entropy(self.source), true); }
    }
    fn next_u64(&self) -> u64 {
        let guard = self.timeline.begin();
        let value = self.inner.next_u64();
        if let Some(guard) = guard { guard.finish(GroupEffect::Entropy(self.source), true); }
        value
    }
    fn fork(&self, task: TaskId) -> Arc<dyn EntropySource> {
        let guard = self.timeline.begin();
        let inner = self.inner.fork(task);
        let source = guard.map_or(0, |guard| guard.finish(GroupEffect::Fork(self.source), true));
        Arc::new(Self { inner, timeline: Arc::clone(&self.timeline), source })
    }
    fn source_id(&self) -> &'static str { "group-recording" }
}

/// Live clock capability; original timestamps/results are unchanged.
pub struct GroupRecordingClock<S: ?Sized> {
    inner: RecordingTimeSource<S>,
    timeline: Arc<CaptureTimeline>,
}
impl<S: ?Sized> fmt::Debug for GroupRecordingClock<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("GroupRecordingClock").finish_non_exhaustive() }
}
impl<S: TimeSource + ?Sized> TimeSource for GroupRecordingClock<S> {
    fn now(&self) -> Time {
        let guard = self.timeline.begin();
        let value = self.inner.now();
        if let Some(guard) = guard { guard.finish(GroupEffect::Clock, true); }
        value
    }
}

/// Complete component windows and their one cross-provider timeline.
pub struct RecordedGroupSession {
    streams: Vec<RecordedStream>,
    entropy: EntropyTape,
    clock: TimeTape,
    entries: Vec<Entry>,
}
impl fmt::Debug for RecordedGroupSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordedGroupSession").field("streams", &self.streams.len()).field("effects", &self.entries.len()).finish_non_exhaustive()
    }
}
impl RecordedGroupSession {
    /// Number of distinct byte-stream identities, including empty streams.
    #[must_use]
    pub fn streams(&self) -> usize { self.streams.len() }
    /// Total completed I/O, clock and entropy effects.
    #[must_use]
    pub fn effects(&self) -> usize { self.entries.len() }
    /// Stream identities in admission order; not network addresses or credentials.
    pub fn stream_ids(&self) -> impl Iterator<Item = u64> + '_ { self.streams.iter().map(|stream| stream.id) }

    fn covers(&self) -> Result<bool, GroupSessionCaptureError> {
        let mut counts = Vec::new();
        counts.try_reserve_exact(self.streams.len()).map_err(|_| GroupSessionCaptureError::Allocation)?;
        counts.resize(self.streams.len(), 0usize);
        let (mut entropy, mut clock, mut sources) = (0usize, 0usize, 1usize);
        for (index, stream) in self.streams.iter().enumerate() {
            if self.streams[..index].iter().any(|other| other.id == stream.id) { return Ok(false); }
        }
        for entry in &self.entries {
            if !matches!(entry.effect, GroupEffect::Fork(_)) && entry.child != 0 { return Ok(false); }
            match entry.effect {
                GroupEffect::Io { stream, .. } => {
                    let Some(index) = self.streams.iter().position(|slot| slot.id == stream) else { return Ok(false); };
                    counts[index] += 1;
                }
                GroupEffect::Clock => clock += 1,
                GroupEffect::Entropy(source) if source < sources => entropy += 1,
                GroupEffect::Fork(source) if source < sources && entry.child == sources => {
                    entropy += 1;
                    sources = match sources.checked_add(1) { Some(next) => next, None => return Ok(false) };
                }
                GroupEffect::Entropy(_) | GroupEffect::Fork(_) => return Ok(false),
            }
        }
        Ok(self.streams.iter().zip(counts).all(|(stream, count)| stream.tape.operations() == count)
            && entropy == self.entropy.calls() && clock == self.clock.observations() && sources == self.entropy.streams())
    }

    /// Build offline providers. No original socket, clock, or generator is retained.
    #[must_use]
    pub fn replay(self) -> ReplayGroupSession {
        let slots = self.streams.into_iter().map(|stream| ReplaySlot {
            id: stream.id, remaining: stream.tape.operations(), io: Some(stream.tape.replay()), waiter: None,
        }).collect();
        let timeline = Arc::new(ReplayTimeline { state: Mutex::new(ReplayState {
            slots, entries: self.entries, index: 0, active: false, failure: None,
        }) });
        ReplayGroupSession {
            entropy: GroupReplayEntropy { inner: self.entropy.replay(), source: 0, timeline: Arc::clone(&timeline) },
            clock: GroupReplayClock { inner: self.clock.replay(), timeline: Arc::clone(&timeline) },
            timeline,
        }
    }
}

/// First replay refusal category. No captured values are included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupReplayMismatch {
    /// An extra effect or an exhausted stream was used.
    Exhausted,
    /// A synchronous effect or same-stream operation was out of order.
    Effect,
    /// Effects overlapped or reentered while another effect was admitted.
    Overlap,
    /// An admitted replay effect unwound.
    Interrupted,
    /// A component rejected the request or could not complete its turn.
    Component,
    /// A byte-stream owner was dropped with unconsumed observations.
    AbandonedStream,
}

/// Sticky, session-wide divergence, including errors a consumer ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("group replay diverged at effect {index}: {reason:?}, expected {expected:?}, actual {actual:?}")]
pub struct GroupSessionReplayError {
    /// Zero-based global completed-effect index.
    pub index: usize,
    /// Expected category/identity, absent at timeline exhaustion.
    pub expected: Option<GroupEffect>,
    /// Actual attempted effect; abandonment names the stream's next expected I/O.
    pub actual: GroupEffect,
    /// First failure classification.
    pub reason: GroupReplayMismatch,
}

/// Missing prefix/tail consumption is not successful replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GroupSessionCompletionError {
    /// Even a caught panic or ignored I/O error invalidates the group.
    #[error(transparent)]
    Diverged(GroupSessionReplayError),
    /// Includes effects for streams never opened and forks never used.
    #[error("group replay has {0} unconsumed effects")]
    Remaining(usize),
    /// Component accounting did not agree with the timeline.
    #[error("group replay component windows are incomplete")]
    Components,
}

/// Offline stream opening/verification authority plus ordered shared sources.
pub struct ReplayGroupSession {
    timeline: Arc<ReplayTimeline>,
    entropy: GroupReplayEntropy,
    clock: GroupReplayClock,
}
impl fmt::Debug for ReplayGroupSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("ReplayGroupSession").finish_non_exhaustive() }
}
impl ReplayGroupSession {
    /// Open an identity once. Refused opens do not invent fallback providers.
    pub fn open(&self, id: u64) -> Result<GroupReplayIo, super::replay_group::IoGroupOpenError> {
        use super::replay_group::IoGroupOpenError;
        let mut state = self.timeline.state.lock();
        let index = state.slots.iter().position(|slot| slot.id == id).ok_or(IoGroupOpenError::UnknownStream(id))?;
        let inner = state.slots[index].io.take().ok_or(IoGroupOpenError::AlreadyOpened(id))?;
        Ok(GroupReplayIo { inner, timeline: Arc::clone(&self.timeline), index, id })
    }
    /// Borrow the ordered root entropy provider. Clones/forks share verification.
    #[must_use]
    pub fn entropy(&self) -> &GroupReplayEntropy { &self.entropy }
    /// Borrow the ordered observation clock, without a live fallback.
    #[must_use]
    pub fn clock(&self) -> &GroupReplayClock { &self.clock }
    /// Verify every component after draining users. This is a point-in-time check,
    /// not a runtime join or an irreversible shutdown of source capabilities.
    pub fn verify_complete(&self) -> Result<(), GroupSessionCompletionError> {
        self.timeline.verify_complete()?;
        if self.entropy.inner.verify_complete().is_err() || self.clock.inner.verify_complete().is_err() {
            return Err(GroupSessionCompletionError::Components);
        }
        Ok(())
    }

    /// Run a borrowing consumer and accept output only after complete replay.
    /// Its future is dropped before verification. Application errors are ordinary
    /// output; factory/poll panics propagate. The owner must drain spawned work.
    /// Poll limits do not bound time inside a poll or a permanently parked future;
    /// use an outer deadline/cancellation owner. This driver never busy-polls.
    /// A zero limit refuses before invoking the factory.
    pub async fn run<T, F>(self, max_polls: usize, consumer: F) -> Result<T, GroupSessionRunError>
    where
        F: for<'a> FnOnce(&'a ReplayGroupSession) -> super::replay_session::ReplayConsumerFuture<'a, T>,
    {
        if max_polls == 0 { return Err(GroupSessionRunError::PollLimit { limit: 0 }); }
        let result = {
            let mut future = consumer(&self);
            let mut polls = 0;
            poll_fn(|cx| {
                if polls == max_polls { return Poll::Ready(Err(GroupSessionRunError::PollLimit { limit: max_polls })); }
                polls += 1;
                future.as_mut().poll(cx).map(Ok)
            }).await
        };
        let result = result?;
        self.verify_complete()?;
        Ok(result)
    }
}

/// The consumer's result was not accepted as a complete replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GroupSessionRunError {
    /// Global or component verification refused the output.
    #[error(transparent)]
    Replay(#[from] GroupSessionCompletionError),
    /// Explicit consumer-poll bound reached; no replay success is reported.
    #[error("group replay exceeded its {limit}-poll budget")]
    PollLimit {
        /// Maximum admitted consumer polls.
        limit: usize,
    },
}

/// Offline byte stream whose completions share the clock/entropy timeline.
pub struct GroupReplayIo {
    inner: ReplayIo,
    timeline: Arc<ReplayTimeline>,
    index: usize,
    id: u64,
}
impl fmt::Debug for GroupReplayIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("GroupReplayIo").field("stream", &self.id).finish_non_exhaustive() }
}
impl GroupReplayIo {
    fn poll_with<O>(&mut self, cx: &mut Context<'_>, operation: IoOperation, poll: impl FnOnce(&mut ReplayIo, &mut Context<'_>) -> Poll<io::Result<O>>) -> Poll<io::Result<O>> {
        let effect = GroupEffect::Io { stream: self.id, operation };
        let guard = ready!(self.timeline.enter_io(self.index, effect, cx)).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let result = poll(&mut self.inner, cx);
        guard.finish(result.is_ready() && self.inner.failure().is_none())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        result
    }
}
impl Drop for GroupReplayIo {
    fn drop(&mut self) { self.timeline.close_stream(self.index); }
}
impl AsyncRead for GroupReplayIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, IoOperation::Read, |io, cx| Pin::new(io).poll_read(cx, buf))
    }
}
impl AsyncWrite for GroupReplayIo {
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

/// Offline entropy; exact request shape and task slot/generation are retained.
#[derive(Clone)]
pub struct GroupReplayEntropy {
    inner: ReplayEntropy,
    timeline: Arc<ReplayTimeline>,
    source: usize,
}
impl fmt::Debug for GroupReplayEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("GroupReplayEntropy").field("source", &self.source).finish_non_exhaustive() }
}
impl GroupReplayEntropy {
    /// Pre-admission failure leaves `dest` unchanged; an admitted effect is not rolled back.
    pub fn try_fill_bytes(&self, dest: &mut [u8]) -> Result<(), GroupSessionReplayError> {
        let guard = self.timeline.enter(GroupEffect::Entropy(self.source))?;
        let result = self.inner.try_fill_bytes(dest);
        guard.finish(result.is_ok())
    }
    /// Read only at the exact captured parent-source turn.
    pub fn try_next_u64(&self) -> Result<u64, GroupSessionReplayError> {
        let guard = self.timeline.enter(GroupEffect::Entropy(self.source))?;
        let result = self.inner.try_next_u64();
        guard.finish(result.is_ok())?;
        Ok(result.expect("component accepted"))
    }
    /// Fork only at the recorded turn with the full recorded task identity.
    pub fn try_fork(&self, task: TaskId) -> Result<Self, GroupSessionReplayError> {
        let guard = self.timeline.enter(GroupEffect::Fork(self.source))?;
        let source = guard.child();
        let result = self.inner.try_fork(task);
        guard.finish(result.is_ok())?;
        Ok(Self { inner: result.expect("component accepted"), timeline: Arc::clone(&self.timeline), source })
    }
}
impl EntropySource for GroupReplayEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) { self.try_fill_bytes(dest).unwrap_or_else(|error| std::panic::panic_any(error)); }
    fn next_u64(&self) -> u64 { self.try_next_u64().unwrap_or_else(|error| std::panic::panic_any(error)) }
    fn fork(&self, task: TaskId) -> Arc<dyn EntropySource> { Arc::new(self.try_fork(task).unwrap_or_else(|error| std::panic::panic_any(error))) }
    fn source_id(&self) -> &'static str { "group-replay" }
}

/// Offline clock. An extra or reordered sample never falls back to real time.
pub struct GroupReplayClock {
    inner: ReplayTimeSource,
    timeline: Arc<ReplayTimeline>,
}
impl fmt::Debug for GroupReplayClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("GroupReplayClock").finish_non_exhaustive() }
}
impl GroupReplayClock {
    /// Sample the recorded clock only at its exact cross-provider turn.
    pub fn try_now(&self) -> Result<Time, GroupSessionReplayError> {
        let guard = self.timeline.enter(GroupEffect::Clock)?;
        let result = self.inner.try_now();
        guard.finish(result.is_ok())?;
        Ok(result.expect("component accepted"))
    }
}
impl TimeSource for GroupReplayClock {
    fn now(&self) -> Time { self.try_now().unwrap_or_else(|error| std::panic::panic_any(error)) }
}

#[cfg(test)]
mod tests;

mod codec;
pub use codec::{GroupSessionBytes, GroupSessionDecodeLimits, GroupSessionTapeError};

mod send;
pub use send::GroupSendConsumerFuture;
