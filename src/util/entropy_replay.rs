//! Bounded capture and fail-closed replay of capability entropy.
//!
//! Install a `RecordingEntropy` wherever an `Arc<dyn EntropySource>` is
//! accepted (including `RuntimeState::set_entropy_source` before creating
//! contexts). Forks remain wrapped, so a single capture includes descendants.
//! Calls on each source are ordered at entry; independently forked sources may
//! interleave differently during replay. This records entropy, not a schedule.
//!
//! Capture is opt-in: retained entropy can contain cryptographic keys, nonces,
//! or other secrets. Debug output never prints values and retained values are
//! zeroized on drop. Nothing is automatically logged or written to disk.
//! Capture limits do not substitute random values or fail a production call:
//! the original provider still runs, but `finish` refuses an incomplete tape.
//!
//! Replay never invokes the original provider or falls back to a seeded/OS
//! generator. A request-shape mismatch or exhaustion poisons the whole replay,
//! including children. The infallible `EntropySource` interface panics on that
//! typed failure; the `try_*` methods return it instead. `verify_complete` must
//! also succeed: consuming a prefix is not evidence of complete replay.

use super::entropy::EntropySource;
use crate::types::TaskId;
use parking_lot::Mutex;
use std::fmt;
use std::sync::Arc;
use zeroize::Zeroize;

/// Explicit bounds on a capture, including all child sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyCaptureLimits {
    /// Maximum calls, counting empty reads and forks as well as random values.
    pub max_calls: usize,
    /// Maximum retained bytes; a `next_u64` result costs eight bytes.
    pub max_bytes: usize,
    /// Maximum sources, including the root. Must be at least one.
    pub max_streams: usize,
}

impl EntropyCaptureLimits {
    /// Set all bounds explicitly. Zero calls/bytes permit only an empty capture.
    #[must_use]
    pub const fn new(max_calls: usize, max_bytes: usize, max_streams: usize) -> Self {
        Self { max_calls, max_bytes, max_streams }
    }
}

/// Why a complete entropy capture cannot be published. Contains no entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EntropyCaptureError {
    /// Even the root source was not admitted.
    #[error("entropy capture requires capacity for a root source")]
    NoRootCapacity,
    /// The aggregate call bound was exceeded.
    #[error("entropy capture call limit exceeded")]
    CallLimit,
    /// The aggregate retained-byte bound was exceeded.
    #[error("entropy capture byte limit exceeded")]
    ByteLimit,
    /// The aggregate source/fork bound was exceeded.
    #[error("entropy capture source limit exceeded")]
    StreamLimit,
    /// Bounded recording storage could not be reserved.
    #[error("entropy capture allocation failed")]
    Allocation,
    /// A provider call unwound instead of producing its recorded result.
    #[error("entropy capture contains an interrupted provider call")]
    InterruptedCall,
    /// An admitted call has not returned. Finishing may be retried afterward.
    #[error("entropy capture still has {calls} calls in flight")]
    InFlight {
        /// Number of pending calls across all sources.
        calls: usize,
    },
    /// The tape has already been taken. Providers now run without recording.
    #[error("entropy capture was already finished")]
    Finished,
}

/// The shape of an entropy request, never its returned value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyRequest {
    /// Fill exactly this many bytes, including a possible zero-length request.
    Bytes(usize),
    /// Request a `u64` through the dedicated provider method.
    U64,
    /// Fork with the complete arena slot/generation identity.
    Fork(u64),
}

fn task_key(task: TaskId) -> u64 {
    let index = task.arena_index();
    (u64::from(index.generation()) << 32) | u64::from(index.index())
}

enum Event {
    Bytes(Vec<u8>),
    U64(u64),
    Fork { task: u64, child: usize },
}

impl Event {
    fn request(&self) -> EntropyRequest {
        match self {
            Self::Bytes(bytes) => EntropyRequest::Bytes(bytes.len()),
            Self::U64(_) => EntropyRequest::U64,
            Self::Fork { task, .. } => EntropyRequest::Fork(*task),
        }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        match self {
            Self::Bytes(bytes) => bytes.zeroize(),
            Self::U64(value) => value.zeroize(),
            Self::Fork { .. } => {}
        }
    }
}

/// A complete capture window with a flat, bounded fork tree.
///
/// Construction is restricted to successful capture and validated decoding.
/// No provider is retained. Finishing capture does not assert that its source
/// tasks have terminated; callers own the capture window and runtime drain.
pub struct EntropyTape {
    streams: Vec<Vec<Event>>,
    calls: usize,
    bytes: usize,
}

impl fmt::Debug for EntropyTape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntropyTape")
            .field("streams", &self.streams.len())
            .field("calls", &self.calls)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl EntropyTape {
    /// Total recorded calls, including forks and zero-length reads.
    #[must_use]
    pub const fn calls(&self) -> usize { self.calls }

    /// Total retained random bytes, including eight per `next_u64` result.
    #[must_use]
    pub const fn bytes(&self) -> usize { self.bytes }

    /// Total sources, including the root.
    #[must_use]
    pub fn streams(&self) -> usize { self.streams.len() }

    /// Replay with exact task identities at every recorded fork.
    #[must_use]
    pub fn replay(self) -> ReplayEntropy {
        self.replay_with(EntropyForkMatching::ExactTaskId)
    }

    /// Explicitly select how fork identities are matched during replay.
    #[must_use]
    pub fn replay_with(self, matching: EntropyForkMatching) -> ReplayEntropy {
        let positions = vec![0; self.streams.len()];
        ReplayEntropy {
            shared: Arc::new(ReplayShared {
                tape: self,
                matching,
                state: Mutex::new(ReplayState { positions, consumed: 0, failure: None }),
            }),
            stream: 0,
        }
    }
}

struct CaptureState {
    streams: Vec<Vec<Option<Event>>>,
    calls: usize,
    bytes: usize,
    in_flight: usize,
    finished: bool,
    failure: Option<EntropyCaptureError>,
}

struct CaptureShared {
    limits: EntropyCaptureLimits,
    state: Mutex<CaptureState>,
}

/// Wraps a real entropy provider and captures its actual outputs and forks.
///
/// The underlying provider is never called while the capture mutex is held.
/// Concurrent callers on one source are ordered at capture admission, not by
/// return order. Use task-local forks when independent consumers should replay
/// without depending on cross-thread ordering of a shared source.
pub struct RecordingEntropy {
    source: Arc<dyn EntropySource>,
    shared: Arc<CaptureShared>,
    stream: usize,
}

impl fmt::Debug for RecordingEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.state.lock();
        f.debug_struct("RecordingEntropy")
            .field("stream", &self.stream)
            .field("calls", &state.calls)
            .field("bytes", &state.bytes)
            .field("in_flight", &state.in_flight)
            .field("finished", &state.finished)
            .field("failure", &state.failure)
            .finish_non_exhaustive()
    }
}

impl RecordingEntropy {
    /// Start a bounded capture. The source is not called during construction.
    pub fn new(
        source: Arc<dyn EntropySource>, limits: EntropyCaptureLimits,
    ) -> Result<Self, EntropyCaptureError> {
        if limits.max_streams == 0 { return Err(EntropyCaptureError::NoRootCapacity); }
        Ok(Self {
            source,
            shared: Arc::new(CaptureShared {
                limits,
                state: Mutex::new(CaptureState {
                    streams: vec![Vec::new()], calls: 0, bytes: 0, in_flight: 0,
                    finished: false, failure: None,
                }),
            }),
            stream: 0,
        })
    }

    /// First permanent capture failure, if any. No returned random data leaks.
    #[must_use]
    pub fn failure(&self) -> Option<EntropyCaptureError> {
        self.shared.state.lock().failure
    }

    /// Atomically close admission and take the complete capture window.
    ///
    /// Refuses overflow, allocation failure, provider unwind and in-flight
    /// calls. An in-flight refusal does not close capture and can be retried.
    /// After success, existing wrapped providers continue to work transparently
    /// without recording; the returned tape is an immutable, explicit window.
    pub fn finish(&self) -> Result<EntropyTape, EntropyCaptureError> {
        let (streams, calls, bytes) = {
            let mut state = self.shared.state.lock();
            if state.finished { return Err(EntropyCaptureError::Finished); }
            if let Some(error) = state.failure { return Err(error); }
            if state.in_flight != 0 {
                return Err(EntropyCaptureError::InFlight { calls: state.in_flight });
            }
            state.finished = true;
            (std::mem::take(&mut state.streams), state.calls, state.bytes)
        };
        let streams = streams.into_iter().map(|events| {
            events.into_iter().map(|event| event.expect("completed capture entry")).collect()
        }).collect();
        Ok(EntropyTape { streams, calls, bytes })
    }

    fn reserve(&self, request: EntropyRequest) -> Option<PendingCapture> {
        let mut state = self.shared.state.lock();
        if state.finished || state.failure.is_some() { return None; }
        let bytes = match request { EntropyRequest::Bytes(n) => n, EntropyRequest::U64 => 8, EntropyRequest::Fork(_) => 0 };
        let refusal = if state.calls >= self.shared.limits.max_calls {
            Some(EntropyCaptureError::CallLimit)
        } else if bytes > self.shared.limits.max_bytes - state.bytes {
            Some(EntropyCaptureError::ByteLimit)
        } else if matches!(request, EntropyRequest::Fork(_)) && state.streams.len() >= self.shared.limits.max_streams {
            Some(EntropyCaptureError::StreamLimit)
        } else { None };
        if let Some(error) = refusal {
            state.failure = Some(error);
            return None;
        }
        if state.streams[self.stream].try_reserve(1).is_err()
            || (matches!(request, EntropyRequest::Fork(_)) && state.streams.try_reserve(1).is_err())
        {
            state.failure = Some(EntropyCaptureError::Allocation);
            return None;
        }
        let child = if matches!(request, EntropyRequest::Fork(_)) {
            let child = state.streams.len();
            state.streams.push(Vec::new());
            Some(child)
        } else { None };
        let index = state.streams[self.stream].len();
        state.streams[self.stream].push(None);
        state.calls += 1;
        state.bytes += bytes;
        state.in_flight += 1;
        Some(PendingCapture {
            shared: Arc::clone(&self.shared), stream: self.stream, index, child, completed: false,
        })
    }
}

struct PendingCapture {
    shared: Arc<CaptureShared>,
    stream: usize,
    index: usize,
    child: Option<usize>,
    completed: bool,
}

impl PendingCapture {
    fn complete(mut self, event: Event) {
        let mut state = self.shared.state.lock();
        state.streams[self.stream][self.index] = Some(event);
        state.in_flight -= 1;
        self.completed = true;
    }

    fn allocation_failed(&self) {
        let mut state = self.shared.state.lock();
        state.failure.get_or_insert(EntropyCaptureError::Allocation);
    }
}

impl Drop for PendingCapture {
    fn drop(&mut self) {
        if !self.completed {
            let mut state = self.shared.state.lock();
            state.failure.get_or_insert(EntropyCaptureError::InterruptedCall);
            state.in_flight -= 1;
        }
    }
}

impl EntropySource for RecordingEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) {
        let pending = self.reserve(EntropyRequest::Bytes(dest.len()));
        self.source.fill_bytes(dest);
        if let Some(pending) = pending {
            let mut bytes = Vec::new();
            if bytes.try_reserve_exact(dest.len()).is_err() {
                pending.allocation_failed();
                return;
            }
            bytes.extend_from_slice(dest);
            pending.complete(Event::Bytes(bytes));
        }
    }

    fn next_u64(&self) -> u64 {
        let pending = self.reserve(EntropyRequest::U64);
        let value = self.source.next_u64();
        if let Some(pending) = pending { pending.complete(Event::U64(value)); }
        value
    }

    fn fork(&self, task_id: TaskId) -> Arc<dyn EntropySource> {
        let task = task_key(task_id);
        let pending = self.reserve(EntropyRequest::Fork(task));
        let source = self.source.fork(task_id);
        let Some(pending) = pending else { return source; };
        let child = pending.child.expect("reserved child source");
        pending.complete(Event::Fork { task, child });
        Arc::new(Self { source, shared: Arc::clone(&self.shared), stream: child })
    }

    fn source_id(&self) -> &'static str { "recording" }
}

/// Task identity policy for replaying a recorded fork tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyForkMatching {
    /// Require exactly the recorded arena slot and generation at each fork.
    ExactTaskId,
    /// Match parent-source fork order, allowing fresh runtime arena identities.
    /// The caller must reproduce the same logical spawn topology. This mode
    /// does not prove task identity, scheduling, or semantic correspondence.
    ForkOrder,
}

/// A sticky replay divergence, with request shapes only, never random values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("[ASUP-E401] entropy replay divergence at source {stream} call {call}: expected {expected:?}, got {actual:?}")]
pub struct EntropyReplayError {
    /// Source ordinal in the captured fork tree.
    pub stream: usize,
    /// Zero-based call ordinal within that source.
    pub call: usize,
    /// Expected request, or `None` at source exhaustion.
    pub expected: Option<EntropyRequest>,
    /// Rejected request.
    pub actual: EntropyRequest,
}

/// Why a replay has not established complete consumption of its capture.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntropyReplayCompletionError {
    /// Some call diverged, even if user code caught the trait-method panic.
    #[error(transparent)]
    Diverged(#[from] EntropyReplayError),
    /// Includes unused child-source events as well as the root's tail.
    #[error("entropy replay has {calls} unconsumed calls")]
    Remaining {
        /// Total outstanding recorded calls across the whole fork tree.
        calls: usize,
    },
}

struct ReplayState {
    positions: Vec<usize>,
    consumed: usize,
    failure: Option<EntropyReplayError>,
}

struct ReplayShared {
    tape: EntropyTape,
    matching: EntropyForkMatching,
    state: Mutex<ReplayState>,
}

/// Strict entropy provider backed only by recorded values.
///
/// Clones share the same source cursor, not independent copies. Forks have
/// independent cursors but share a sticky failure and completion accounting.
#[derive(Clone)]
pub struct ReplayEntropy {
    shared: Arc<ReplayShared>,
    stream: usize,
}

impl fmt::Debug for ReplayEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.state.lock();
        f.debug_struct("ReplayEntropy")
            .field("stream", &self.stream)
            .field("consumed_calls", &state.consumed)
            .field("total_calls", &self.shared.tape.calls)
            .field("failure", &state.failure)
            .finish_non_exhaustive()
    }
}

impl ReplayEntropy {
    /// First divergence in any source. Catching a panic does not erase it.
    #[must_use]
    pub fn failure(&self) -> Option<EntropyReplayError> {
        self.shared.state.lock().failure.clone()
    }

    /// Verify that every recorded call in every source was consumed, with no
    /// divergence. Observation is non-consuming; a remaining-tail error may
    /// be checked again after further valid calls. Divergence is permanent.
    pub fn verify_complete(&self) -> Result<(), EntropyReplayCompletionError> {
        let state = self.shared.state.lock();
        if let Some(error) = &state.failure { return Err(error.clone().into()); }
        let calls = self.shared.tape.calls - state.consumed;
        if calls != 0 { return Err(EntropyReplayCompletionError::Remaining { calls }); }
        Ok(())
    }

    fn consume<T>(
        &self, actual: EntropyRequest, read: impl FnOnce(&Event) -> T,
    ) -> Result<T, EntropyReplayError> {
        let mut state = self.shared.state.lock();
        if let Some(error) = &state.failure { return Err(error.clone()); }
        let call = state.positions[self.stream];
        let event = self.shared.tape.streams[self.stream].get(call);
        let expected = event.map(Event::request);
        let matches = expected == Some(actual)
            || (self.shared.matching == EntropyForkMatching::ForkOrder
                && matches!((expected, actual), (Some(EntropyRequest::Fork(_)), EntropyRequest::Fork(_))));
        if !matches {
            let error = EntropyReplayError { stream: self.stream, call, expected, actual };
            state.failure = Some(error.clone());
            return Err(error);
        }
        // Only internal, non-callback operations run under this mutex. A
        // rejected request never changes a destination, cursor, or child tree.
        let result = read(event.expect("matched recorded event"));
        state.positions[self.stream] += 1;
        state.consumed += 1;
        Ok(result)
    }

    /// Fill exactly the next recorded byte request. Leaves `dest` unchanged on
    /// mismatch, exhaustion, or a prior divergence in any source.
    pub fn try_fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyReplayError> {
        self.consume(EntropyRequest::Bytes(dest.len()), |event| match event {
            Event::Bytes(bytes) => dest.copy_from_slice(bytes),
            _ => unreachable!("matched byte request"),
        })
    }

    /// Return exactly the next recorded `next_u64` value.
    pub fn try_next_u64(&self) -> Result<u64, EntropyReplayError> {
        self.consume(EntropyRequest::U64, |event| match event {
            Event::U64(value) => *value,
            _ => unreachable!("matched u64 request"),
        })
    }

    /// Open exactly the next recorded child source under the selected identity
    /// policy. No original provider is invoked, and no seed is synthesized.
    pub fn try_fork(&self, task: TaskId) -> Result<Self, EntropyReplayError> {
        let stream = self.consume(EntropyRequest::Fork(task_key(task)), |event| match event {
            Event::Fork { child, .. } => *child,
            _ => unreachable!("matched fork request"),
        })?;
        Ok(Self { shared: Arc::clone(&self.shared), stream })
    }
}

impl EntropySource for ReplayEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap_or_else(|error| panic!("{error}"));
    }

    fn next_u64(&self) -> u64 {
        self.try_next_u64().unwrap_or_else(|error| panic!("{error}"))
    }

    fn fork(&self, task_id: TaskId) -> Arc<dyn EntropySource> {
        Arc::new(self.try_fork(task_id).unwrap_or_else(|error| panic!("{error}")))
    }

    fn source_id(&self) -> &'static str { "replay" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{ArenaIndex, DetEntropy};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn task(index: u32, generation: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(index, generation))
    }

    fn recorder(limits: EntropyCaptureLimits) -> RecordingEntropy {
        RecordingEntropy::new(Arc::new(DetEntropy::new(42)), limits).unwrap()
    }

    #[test]
    fn records_real_values_and_nested_forks_without_global_interleaving_dependency() {
        let capture = recorder(EntropyCaptureLimits::new(20, 128, 4));
        let first = capture.fork(task(1, 3));
        let second = capture.fork(task(2, 4));
        let nested = first.fork(task(3, 5));
        let root_value = capture.next_u64();
        let first_value = first.next_u64();
        let mut bytes = [0; 13];
        second.fill_bytes(&mut bytes);
        let nested_value = nested.next_u64();
        let tape = capture.finish().unwrap();
        assert_eq!((tape.calls(), tape.bytes(), tape.streams()), (7, 37, 4));
        let replay = tape.replay();
        let first = replay.try_fork(task(1, 3)).unwrap();
        let second = replay.try_fork(task(2, 4)).unwrap();
        let mut actual = [0; 13];
        second.try_fill_bytes(&mut actual).unwrap();
        assert_eq!(actual, bytes);
        let nested = first.try_fork(task(3, 5)).unwrap();
        assert_eq!(nested.try_next_u64().unwrap(), nested_value);
        assert_eq!(first.try_next_u64().unwrap(), first_value);
        assert_eq!(replay.try_next_u64().unwrap(), root_value);
        replay.verify_complete().unwrap();
    }

    #[test]
    fn request_kind_and_length_are_not_interchangeable_and_failure_is_sticky() {
        let capture = recorder(EntropyCaptureLimits::new(3, 16, 2));
        let child = capture.fork(task(1, 0));
        capture.next_u64();
        child.next_u64();
        let replay = capture.finish().unwrap().replay();
        let child = replay.try_fork(task(1, 0)).unwrap();
        let mut unchanged = [0xa5; 8];
        let error = replay.try_fill_bytes(&mut unchanged).unwrap_err();
        assert_eq!(error.expected, Some(EntropyRequest::U64));
        assert_eq!(unchanged, [0xa5; 8]);
        assert_eq!(child.try_next_u64().unwrap_err(), error);
        assert_eq!(replay.try_next_u64().unwrap_err(), error);
        assert!(matches!(replay.verify_complete(), Err(EntropyReplayCompletionError::Diverged(_))));
    }

    #[test]
    fn exhaustion_panics_through_trait_and_cannot_be_hidden_by_catching_it() {
        let replay = recorder(EntropyCaptureLimits::new(1, 8, 1)).finish().unwrap().replay();
        replay.verify_complete().unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| replay.next_u64())).is_err());
        let error = replay.failure().unwrap();
        assert_eq!((error.stream, error.call, error.expected), (0, 0, None));
        assert!(replay.verify_complete().is_err());
    }

    #[test]
    fn unread_child_calls_prevent_a_complete_replay_receipt() {
        let capture = recorder(EntropyCaptureLimits::new(2, 8, 2));
        capture.fork(task(1, 0)).next_u64();
        let replay = capture.finish().unwrap().replay();
        let child = replay.try_fork(task(1, 0)).unwrap();
        assert_eq!(replay.verify_complete(), Err(EntropyReplayCompletionError::Remaining { calls: 1 }));
        child.try_next_u64().unwrap();
        replay.verify_complete().unwrap();
    }

    #[test]
    fn overflow_preserves_provider_behavior_but_never_publishes_a_partial_tape() {
        for limits in [EntropyCaptureLimits::new(0, 8, 1), EntropyCaptureLimits::new(1, 7, 1)] {
            let capture = recorder(limits);
            let reference = DetEntropy::new(42);
            assert_eq!(capture.next_u64(), reference.next_u64());
            assert_eq!(capture.next_u64(), reference.next_u64());
            assert!(capture.failure().is_some());
            assert!(capture.finish().is_err());
        }
        let capture = recorder(EntropyCaptureLimits::new(10, 80, 1));
        let child = capture.fork(task(2, 0));
        child.next_u64();
        assert_eq!(capture.failure(), Some(EntropyCaptureError::StreamLimit));
        assert!(capture.finish().is_err());
    }

    #[test]
    fn fork_remapping_requires_explicit_opt_in_and_preserves_child_values() {
        for matching in [EntropyForkMatching::ExactTaskId, EntropyForkMatching::ForkOrder] {
            let capture = recorder(EntropyCaptureLimits::new(2, 8, 2));
            let expected = capture.fork(task(1, 9)).next_u64();
            let replay = capture.finish().unwrap().replay_with(matching);
            let child = replay.try_fork(task(8, 1));
            if matching == EntropyForkMatching::ExactTaskId {
                assert!(child.is_err());
            } else {
                assert_eq!(child.unwrap().try_next_u64().unwrap(), expected);
                replay.verify_complete().unwrap();
            }
        }
    }

    #[test]
    fn completed_capture_seals_the_window_without_disabling_the_provider() {
        let capture = recorder(EntropyCaptureLimits::new(1, 8, 1));
        let reference = DetEntropy::new(42);
        let expected = capture.next_u64();
        assert_eq!(expected, reference.next_u64());
        let tape = capture.finish().unwrap();
        assert_eq!(capture.next_u64(), reference.next_u64());
        assert!(matches!(capture.finish(), Err(EntropyCaptureError::Finished)));
        let replay = tape.replay();
        assert_eq!(replay.next_u64(), expected);
        replay.verify_complete().unwrap();
    }
}

mod codec;
pub use codec::{EntropyTapeBytes, EntropyTapeDecodeLimits, EntropyTapeError};
