//! Capture and execute one consumer's I/O, entropy, and clock replay together.
//!
//! [`RecordingSession`] groups explicitly supplied, already-authorized providers.
//! After the owner has drained their users, finish the window with `into_parts`.
//! No partial [`RecordedSession`] escapes if any component refuses capture.
//! [`ReplaySession::run`] executes the caller's real async consumer against only
//! recorded providers and accepts its output only after all three tapes verify.
//! An application error is a valid output: replay success means the captured
//! observations were reproduced, not that the original transaction succeeded.
//!
//! Each component retains its existing semantics: exact completed I/O requests,
//! per-fork entropy call order, and serial clock observations. This does NOT
//! capture a total order between components, a task schedule, pending readiness,
//! cancellation, or unwrapped effects. The caller must reconstruct the consumer
//! and drain any work it starts. Use the lab's exact scheduler replay separately
//! when schedule decisions matter. There is no ambient provider or RNG fallback.
//!
//! Data can include plaintext, keys, and activity patterns. Debug is redacted;
//! component tapes zeroize their owned sensitive storage. Nothing is persisted
//! automatically. Capture limits never replace a live provider's result.

use super::replay::{
    IoCaptureError, IoCaptureLimits, IoReplayCompletionError, IoTape, RecordingIo, ReplayIo,
};
use super::AsyncWrite;
use crate::time::replay::{
    RecordingTimeSource, ReplayTimeSource, TimeCaptureError, TimeReplayError, TimeTape,
};
use crate::time::TimeSource;
use crate::util::entropy::EntropySource;
use crate::util::entropy_replay::{
    EntropyCaptureError, EntropyCaptureLimits, EntropyReplayCompletionError, EntropyTape,
    RecordingEntropy, ReplayEntropy,
};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

/// Independent bounds for all providers in a session. No unbounded default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionCaptureLimits {
    /// Completed I/O operations, read bytes, offered write bytes, and vector sizes.
    pub io: IoCaptureLimits,
    /// Aggregate entropy calls, bytes, and sources, including fork descendants.
    pub entropy: EntropyCaptureLimits,
    /// Maximum serial clock observations, including repeated timestamps.
    pub clock_observations: usize,
}

/// All component refusals at the end of a capture, without sensitive values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("session capture refused (I/O: {io:?}, entropy: {entropy:?}, clock: {clock:?})")]
pub struct SessionCaptureError {
    /// I/O capture refusal, if present.
    pub io: Option<IoCaptureError>,
    /// Entropy capture refusal, if present.
    pub entropy: Option<EntropyCaptureError>,
    /// Clock capture refusal, if present.
    pub clock: Option<TimeCaptureError>,
}

/// Live capture adapters for a single explicitly owned consumer window.
///
/// Source handles may be installed where their existing capability traits are
/// accepted. The owner must quiesce all clones/forks before `into_parts`: this
/// adapter neither cancels users nor claims that separately finished sources
/// have one atomic cross-provider cutoff. Outstanding calls refuse capture.
pub struct RecordingSession<T, S: ?Sized> {
    io: RecordingIo<T>,
    entropy: Arc<RecordingEntropy>,
    clock: Arc<RecordingTimeSource<S>>,
}

impl<T, S: ?Sized> fmt::Debug for RecordingSession<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingSession")
            .field("io", &self.io)
            .field("entropy", &self.entropy)
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}

impl<T: AsyncWrite, S: TimeSource + ?Sized> RecordingSession<T, S> {
    /// Wrap supplied providers. Does not read, write, sample time, or draw entropy.
    /// The I/O provider's vectored-write capability is queried once.
    pub fn new(
        io: T,
        entropy: Arc<dyn EntropySource>,
        clock: Arc<S>,
        limits: SessionCaptureLimits,
    ) -> Result<Self, EntropyCaptureError> {
        let entropy = Arc::new(RecordingEntropy::new(entropy, limits.entropy)?);
        Ok(Self {
            io: RecordingIo::new(io, limits.io),
            entropy,
            clock: Arc::new(RecordingTimeSource::new(clock, limits.clock_observations)),
        })
    }
}

impl<T, S: TimeSource + ?Sized> RecordingSession<T, S> {
    /// Borrow the transparent I/O adapter for the live consumer.
    pub fn io(&mut self) -> &mut RecordingIo<T> {
        &mut self.io
    }

    /// Share the wrapped entropy provider, including capture of its forks.
    #[must_use]
    pub fn entropy(&self) -> Arc<RecordingEntropy> {
        Arc::clone(&self.entropy)
    }

    /// Share the serial-observation clock adapter.
    #[must_use]
    pub fn clock(&self) -> Arc<RecordingTimeSource<S>> {
        Arc::clone(&self.clock)
    }

    /// End the explicit window and return the original I/O owner on every path.
    ///
    /// Every component is checked even if another fails. Successful component
    /// tapes are dropped/zeroized on refusal, never returned as a partial session.
    /// This does not close the stream or terminate outstanding source users.
    /// In particular, entropy's in-flight refusal retains its existing bounded
    /// recorder until those provider handles are released by their owner.
    pub fn into_parts(self) -> (T, Result<RecordedSession, SessionCaptureError>) {
        let (inner, io) = self.io.into_parts();
        let entropy = self.entropy.finish();
        let clock = self.clock.finish();
        let errors = SessionCaptureError {
            io: io.as_ref().err().copied(),
            entropy: entropy.as_ref().err().copied(),
            clock: clock.as_ref().err().copied(),
        };
        let session = match (io, entropy, clock) {
            (Ok(io), Ok(entropy), Ok(clock)) => Ok(RecordedSession { io, entropy, clock }),
            _ => Err(errors),
        };
        (inner, session)
    }
}

/// Three complete observation windows captured by one session owner.
///
/// No original provider is retained. Construction does not assert cross-domain
/// causality, task quiescence, or transaction success. Debug omits captured data.
#[derive(Debug)]
pub struct RecordedSession {
    io: IoTape,
    entropy: EntropyTape,
    clock: TimeTape,
}

impl RecordedSession {
    /// Completed I/O operations in the window.
    #[must_use]
    pub fn io_operations(&self) -> usize {
        self.io.operations()
    }

    /// Entropy calls across the root and every fork.
    #[must_use]
    pub fn entropy_calls(&self) -> usize {
        self.entropy.calls()
    }

    /// Serial clock observations in the window.
    #[must_use]
    pub fn clock_observations(&self) -> usize {
        self.clock.observations()
    }

    /// Consume the capture into exclusively offline providers.
    /// Entropy forks require exact task slot AND generation identities.
    #[must_use]
    pub fn replay(self) -> ReplaySession {
        ReplaySession {
            io: self.io.replay(),
            entropy: self.entropy.replay(),
            clock: self.clock.replay(),
        }
    }
}

/// All incompleteness/divergence diagnostics, including ignored component errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("session replay refused (I/O: {io:?}, entropy: {entropy:?}, clock: {clock:?})")]
pub struct SessionReplayError {
    /// I/O divergence or unused operations.
    pub io: Option<IoReplayCompletionError>,
    /// Entropy divergence or unused calls in any fork.
    pub entropy: Option<EntropyReplayCompletionError>,
    /// Clock exhaustion or unused observations.
    pub clock: Option<TimeReplayError>,
}

/// Refusal to accept a consumer's result as complete replay.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionRunError {
    /// One or more observation windows did not verify after the consumer drained.
    #[error(transparent)]
    Replay(#[from] SessionReplayError),
    /// The consumer did not complete within the supplied number of polls.
    #[error("session replay exceeded its {limit}-poll budget")]
    PollLimit {
        /// The explicit poll budget, which may be zero.
        limit: usize,
    },
}

/// Borrowed offline providers for the async consumer being reproduced.
#[derive(Debug)]
pub struct ReplayInputs<'a> {
    /// Duplex I/O replay; use the normal AsyncRead/AsyncWrite consumers.
    pub io: &'a mut ReplayIo,
    /// Root entropy replay; forks share failure/completion accounting.
    pub entropy: &'a ReplayEntropy,
    /// Exact serial clock observations, with no live-clock fallback.
    pub clock: &'a ReplayTimeSource,
}

/// A boxed borrowing consumer future. It need not be `Send` or `'static`.
pub type ReplayConsumerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Offline execution and joint completion validation for a recorded consumer.
#[derive(Debug)]
pub struct ReplaySession {
    io: ReplayIo,
    entropy: ReplayEntropy,
    clock: ReplayTimeSource,
}

impl ReplaySession {
    /// Borrow all providers for manual driving with an existing lab/region owner.
    pub fn inputs(&mut self) -> ReplayInputs<'_> {
        ReplayInputs {
            io: &mut self.io,
            entropy: &self.entropy,
            clock: &self.clock,
        }
    }

    /// Check every component without drawing values or consuming operations.
    /// A remaining-tail check is nonterminal; component divergence stays sticky.
    pub fn verify_complete(&self) -> Result<(), SessionReplayError> {
        let errors = SessionReplayError {
            io: self.io.verify_complete().err(),
            entropy: self.entropy.verify_complete().err(),
            clock: self.clock.verify_complete().err(),
        };
        if errors.io.is_none() && errors.entropy.is_none() && errors.clock.is_none() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Drive the supplied consumer, then verify all windows before returning output.
    ///
    /// The future is dropped BEFORE verification so destructor-side observations
    /// and ignored errors cannot evade the final check. Application errors are
    /// preserved as ordinary output. Consumer panics (including infallible replay
    /// trait refusals) propagate; they are never converted into replay success.
    /// Dropping this driver returns no output and drops the owned consumer future.
    ///
    /// The poll budget bounds calls into `Future::poll`, not time inside a poll.
    /// A parked consumer still requires an owner-controlled deadline/cancellation;
    /// this driver neither busy-polls nor invents readiness/time to make progress.
    /// Zero rejects BEFORE invoking the consumer factory. The factory and any
    /// spawned work must be caller-owned; this is not an executor or a region.
    pub async fn run<T, F>(mut self, max_polls: usize, consumer: F) -> Result<T, SessionRunError>
    where
        F: for<'a> FnOnce(ReplayInputs<'a>) -> ReplayConsumerFuture<'a, T>,
    {
        if max_polls == 0 {
            return Err(SessionRunError::PollLimit { limit: 0 });
        }
        let result = {
            let mut future = consumer(self.inputs());
            let mut polls = 0;
            poll_fn(|cx| {
                if polls == max_polls {
                    return Poll::Ready(Err(SessionRunError::PollLimit { limit: max_polls }));
                }
                polls += 1;
                future.as_mut().poll(cx).map(Ok)
            })
            .await
        };
        let output = result?;
        self.verify_complete()?;
        Ok(output)
    }
}

mod codec;
pub use codec::{SessionBytes, SessionDecodeLimits, SessionTapeError};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod http_tests;
