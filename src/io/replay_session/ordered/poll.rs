//! Reproduce a single consumer's poll boundaries and pending I/O outcomes.
//!
//! Completed-effect order alone cannot reproduce a consumer that samples time
//! on every poll: a production read may return Pending before the next sample,
//! while an offline read already has all bytes. This opt-in layer retains each
//! I/O poll's request fingerprint, effect position and Pending/Ready result,
//! plus checkpoints at future construction, each consumer poll, and destruction.
//!
//! Replay supplies recorded Pending results without consulting a live provider.
//! After a matching Pending consumer poll, the driver wakes itself for the NEXT
//! recorded poll. This is bounded playback, not captured OS readiness timing or
//! the production scheduler. Uncaptured external effects, multi-task scheduling,
//! concurrent source users, and cancellation are outside this single-consumer
//! contract. The owner must still bound production execution with a deadline.
//! Capture limits invalidate recording, never change a live result or terminate
//! the consumer. Panics propagate; a caught I/O panic invalidates the transcript.
//! Start from [`OrderedRecordingSession::new`], not `new_with_pending_io`: the
//! latter owns a different pending transcript and is refused on capture/import
//! rather than publishing incompatible checkpoints. Live output stays unchanged.

use super::{
    OrderedCaptureError, OrderedRecordedSession, OrderedRecordingClock,
    OrderedRecordingEntropy, OrderedRecordingIo, OrderedRecordingSession,
    OrderedReplayClock, OrderedReplayEntropy, OrderedReplayError, OrderedReplayIo,
    OrderedReplaySession,
};
use super::gate::{RecordOrder, ReplayOrder};
use crate::io::AsyncWrite;
use crate::time::TimeSource;
use crate::util::entropy_replay::RecordingEntropy;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

mod trace;
use trace::{PollTape, RecordTrace, ReplayTrace};
mod io;
pub use io::PolledIo;

/// Additional, independent resource limits for poll-level capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollCaptureLimits {
    /// Maximum consumer polls retained (not a production execution budget).
    pub max_polls: usize,
    /// Maximum I/O polls, including Pending and empty operations.
    pub max_io_polls: usize,
    /// Maximum aggregate offered write bytes fingerprinted, including Pending.
    pub max_write_bytes: usize,
    /// Maximum slice count of a single vectored call, including empty slices.
    pub max_vectored_slices: usize,
}

/// Why the entire poll capture must be refused; contains no source values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PollCaptureError {
    /// A caller-selected resource ceiling was exceeded.
    #[error("poll capture exceeds its {0} limit")]
    Limit(&'static str),
    /// Bounded storage could not be reserved.
    #[error("poll capture allocation failed")]
    Allocation,
    /// A size or count cannot be represented on the target.
    #[error("poll capture size overflow")]
    Overflow,
    /// A source poll unwound without returning an outcome.
    #[error("poll capture contains an interrupted I/O poll")]
    Interrupted,
    /// Source use overlapped with a captured poll or terminal extraction.
    #[error("poll capture contains overlapping source use")]
    Overlap,
    /// The transcript does not cover its ordered component window.
    #[error("poll capture has inconsistent checkpoints")]
    Inconsistent,
}

/// Capture refusals from both the poll transcript and ordered component tapes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("polled capture refused (polls: {polls:?}, ordered: {ordered:?})")]
pub struct PolledCaptureError {
    /// Poll-level refusal.
    pub polls: Option<PollCaptureError>,
    /// Ordered I/O/entropy/clock refusal.
    pub ordered: Option<OrderedCaptureError>,
}

/// A redacted poll replay mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollMismatch {
    /// An I/O operation, buffer shape or offered write contents changed.
    Request,
    /// An I/O poll occurred at a different completed-effect position.
    Position,
    /// Another I/O call or consumer poll was not in the transcript.
    Exhausted,
    /// An expected Ready I/O call could not complete from the underlying tape.
    Outcome,
    /// A consumer poll changed its result or observation counts.
    Boundary,
    /// Future construction changed its observation counts.
    Construction,
    /// Future destruction or terminal consumption did not match.
    Completion,
}

/// Sticky transcript failure. Indices and categories only, never fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("poll replay diverged at consumer poll {poll}, I/O poll {io_poll}: {reason:?}")]
pub struct PollReplayError {
    /// Zero-based consumer poll, or the terminal poll count during destruction.
    pub poll: usize,
    /// Zero-based I/O poll (including Pending calls).
    pub io_poll: usize,
    /// Refusal classification.
    pub reason: PollMismatch,
}

/// Why a consumer result was not accepted as complete polled replay.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolledRunError {
    /// Poll-level mismatch, including an ignored I/O error.
    #[error(transparent)]
    Poll(#[from] PollReplayError),
    /// Ordered component replay did not verify.
    #[error(transparent)]
    Ordered(#[from] OrderedReplayError),
    /// The recorded consumer poll count exceeds the caller's execution ceiling.
    #[error("polled replay requires {required} polls, exceeding limit {limit}")]
    Budget {
        /// Recorded consumer polls.
        required: usize,
        /// Maximum admitted consumer polls.
        limit: usize,
    },
}

/// Live providers borrowed by the single consumer being recorded.
pub struct PollRecordingInputs<'a, T, S: ?Sized> {
    /// I/O adapter retaining Pending and Ready outcomes.
    pub io: &'a mut PolledIo<OrderedRecordingIo<T>>,
    /// Ordered entropy; forks remain in the same component/order window.
    pub entropy: &'a OrderedRecordingEntropy,
    /// Ordered clock observations.
    pub clock: &'a OrderedRecordingClock<S>,
}
impl<T, S: ?Sized> fmt::Debug for PollRecordingInputs<'_, T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PollRecordingInputs").finish_non_exhaustive()
    }
}

/// Offline providers borrowed by the consumer being reproduced.
#[derive(Debug)]
pub struct PollReplayInputs<'a> {
    /// I/O with exact recorded Pending/Ready outcomes.
    pub io: &'a mut PolledIo<OrderedReplayIo>,
    /// Ordered entropy with exact fork identities.
    pub entropy: &'a OrderedReplayEntropy,
    /// Ordered clock with no live fallback.
    pub clock: &'a OrderedReplayClock,
}

/// A borrowing consumer future for a local or lab driver.
pub type PollConsumerFuture<'a, R> = Pin<Box<dyn Future<Output = R> + 'a>>;
/// A borrowing consumer future that preserves Send for an owned native task.
pub type SendPollConsumerFuture<'a, R> = Pin<Box<dyn Future<Output = R> + Send + 'a>>;

/// Complete ordered observations and a single consumer's poll transcript.
///
/// No original provider is retained. Request digests are sensitive fingerprints
/// and are zeroized on drop. Debug omits all captured values. This is not proof
/// of task quiescence, transaction success, or captured external wake timing.
pub struct PolledRecordedSession {
    ordered: OrderedRecordedSession,
    polls: PollTape,
}
impl fmt::Debug for PolledRecordedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolledRecordedSession")
            .field("consumer_polls", &self.polls.frames.len())
            .field("io_polls", &self.polls.io.len())
            .finish_non_exhaustive()
    }
}
impl PolledRecordedSession {
    /// Recorded consumer polls, including the final Ready poll.
    #[must_use]
    pub fn consumer_polls(&self) -> usize { self.polls.frames.len() }
    /// Recorded I/O polls, including Pending and destructor calls.
    #[must_use]
    pub fn io_polls(&self) -> usize { self.polls.io.len() }

    /// Reproduce the supplied single consumer and verify all observations.
    ///
    /// Only recorded Pending boundaries cause synthetic wakeups. No live I/O,
    /// clock, or entropy is substituted. The limit is checked before invoking
    /// the factory. The consumer future is destroyed before final validation.
    pub async fn run<R, F>(self, max_polls: usize, consumer: F) -> Result<R, PolledRunError>
    where
        F: for<'a> FnOnce(PollReplayInputs<'a>) -> PollConsumerFuture<'a, R>,
    {
        let mut driver = Replayer::new(self, max_polls)?;
        let trace = Arc::clone(&driver.trace);
        let order = Arc::clone(&driver.order);
        let output = drive_replay(consumer(driver.inputs()), &trace, &order).await?;
        driver.finish()?;
        Ok(output)
    }

    /// As [`run`](Self::run), preserving Send for the factory and its future.
    /// No task is spawned here: the caller supplies the task/region owner.
    pub async fn run_send<R: Send, F>(self, max_polls: usize, consumer: F) -> Result<R, PolledRunError>
    where
        F: Send + for<'a> FnOnce(PollReplayInputs<'a>) -> SendPollConsumerFuture<'a, R>,
    {
        let mut driver = Replayer::new(self, max_polls)?;
        let trace = Arc::clone(&driver.trace);
        let order = Arc::clone(&driver.order);
        let output = drive_replay(consumer(driver.inputs()), &trace, &order).await?;
        driver.finish()?;
        Ok(output)
    }
}

impl<T: AsyncWrite, S: TimeSource + ?Sized> OrderedRecordingSession<T, S> {
    /// Run one local consumer while capturing poll-level behavior.
    ///
    /// Returns its original output, original I/O owner, and complete capture or
    /// refusal. Bounds constrain recording only: the live consumer still runs
    /// through its original wakeups. A production deadline/cancellation remains
    /// the owner's responsibility. Factory and destructor observations are
    /// captured; source users must not escape or execute concurrently.
    pub async fn record_polls<R, F>(
        self, limits: PollCaptureLimits, consumer: F,
    ) -> (R, T, Result<PolledRecordedSession, PolledCaptureError>)
    where
        F: for<'a> FnOnce(PollRecordingInputs<'a, T, S>) -> PollConsumerFuture<'a, R>,
    {
        let mut driver = Recorder::new(self, limits);
        let trace = Arc::clone(&driver.trace);
        let order = Arc::clone(&driver.order);
        let output = drive_record(consumer(driver.inputs()), &trace, &order).await;
        let (io, tape) = driver.finish();
        (output, io, tape)
    }

    /// As [`record_polls`](Self::record_polls), preserving a Send consumer future.
    pub async fn record_polls_send<R: Send, F>(
        self, limits: PollCaptureLimits, consumer: F,
    ) -> (R, T, Result<PolledRecordedSession, PolledCaptureError>)
    where
        T: Send,
        F: Send + for<'a> FnOnce(PollRecordingInputs<'a, T, S>) -> SendPollConsumerFuture<'a, R>,
    {
        let mut driver = Recorder::new(self, limits);
        let trace = Arc::clone(&driver.trace);
        let order = Arc::clone(&driver.order);
        let output = drive_record(consumer(driver.inputs()), &trace, &order).await;
        let (io, tape) = driver.finish();
        (output, io, tape)
    }
}

struct Recorder<T, S: ?Sized> {
    io: PolledIo<OrderedRecordingIo<T>>,
    entropy: Arc<OrderedRecordingEntropy>,
    clock: Arc<OrderedRecordingClock<S>>,
    recorder: Arc<RecordingEntropy>,
    order: Arc<RecordOrder>,
    trace: Arc<RecordTrace>,
}
impl<T, S: TimeSource + ?Sized> Recorder<T, S> {
    fn new(session: OrderedRecordingSession<T, S>, limits: PollCaptureLimits) -> Self {
        let OrderedRecordingSession { io, entropy, clock, recorder, order } = session;
        let trace = Arc::new(RecordTrace::new(limits));
        if order.effect_position() != 0 { trace.invalidate(PollCaptureError::Inconsistent); }
        let io = PolledIo::record(io, Arc::clone(&trace), Arc::clone(&order));
        Self { io, entropy, clock, recorder, order, trace }
    }
    fn inputs(&mut self) -> PollRecordingInputs<'_, T, S> {
        PollRecordingInputs { io: &mut self.io, entropy: &self.entropy, clock: &self.clock }
    }
    fn finish(self) -> (T, Result<PolledRecordedSession, PolledCaptureError>) {
        let polls = self.trace.finish(self.order.effect_position());
        let (io, ordered) = OrderedRecordingSession {
            io: self.io.into_inner(), entropy: self.entropy, clock: self.clock,
            recorder: self.recorder, order: self.order,
        }.into_parts();
        let error = PolledCaptureError {
            polls: polls.as_ref().err().copied(),
            ordered: ordered.as_ref().err().copied(),
        };
        let result = match (polls, ordered) {
            (Ok(polls), Ok(ordered)) if polls.covers(&ordered) => Ok(PolledRecordedSession { ordered, polls }),
            (Ok(_), Ok(_)) => Err(PolledCaptureError { polls: Some(PollCaptureError::Inconsistent), ordered: None }),
            _ => Err(error),
        };
        (io, result)
    }
}

struct Replayer {
    io: PolledIo<OrderedReplayIo>,
    entropy: OrderedReplayEntropy,
    clock: OrderedReplayClock,
    order: Arc<ReplayOrder>,
    trace: Arc<ReplayTrace>,
}
impl Replayer {
    fn new(session: PolledRecordedSession, max: usize) -> Result<Self, PolledRunError> {
        let required = session.consumer_polls();
        if required > max { return Err(PolledRunError::Budget { required, limit: max }); }
        let OrderedReplaySession { io, entropy, clock, order } = session.ordered.replay();
        let trace = Arc::new(ReplayTrace::new(session.polls));
        let io = PolledIo::replay(io, Arc::clone(&trace), Arc::clone(&order));
        Ok(Self { io, entropy, clock, order, trace })
    }
    fn inputs(&mut self) -> PollReplayInputs<'_> {
        PollReplayInputs { io: &mut self.io, entropy: &self.entropy, clock: &self.clock }
    }
    fn finish(self) -> Result<(), PolledRunError> {
        self.trace.finish(self.order.effect_position())?;
        OrderedReplaySession {
            io: self.io.into_inner(), entropy: self.entropy, clock: self.clock, order: self.order,
        }.verify_complete()?;
        Ok(())
    }
}

async fn drive_record<F: Future>(future: F, trace: &RecordTrace, order: &RecordOrder) -> F::Output {
    trace.construction(order.effect_position());
    let mut future = std::pin::pin!(future);
    poll_fn(|cx| {
        let result = future.as_mut().poll(cx);
        trace.boundary(order.effect_position(), result.is_ready());
        result
    }).await
    // The pinned future is destroyed before control returns to Recorder::finish.
}

async fn drive_replay<F: Future>(
    future: F, trace: &ReplayTrace, order: &ReplayOrder,
) -> Result<F::Output, PolledRunError> {
    trace.construction(order.effect_position())?;
    let mut future = std::pin::pin!(future);
    poll_fn(|cx| {
        if let Err(error) = trace.before_poll() { return Poll::Ready(Err(error.into())); }
        let result = future.as_mut().poll(cx);
        if let Err(error) = trace.boundary(order.effect_position(), result.is_ready()) {
            return Poll::Ready(Err(error.into()));
        }
        match result {
            Poll::Ready(output) => Poll::Ready(Ok(output)),
            Poll::Pending => {
                // One wake for one validated captured boundary, never an open-ended
                // readiness fallback. before_poll refuses exhaustion before polling.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }).await
}

#[cfg(test)]
mod tests;

mod codec;
pub use codec::{PolledDecodeLimits, PolledSessionBytes, PolledTapeError};
