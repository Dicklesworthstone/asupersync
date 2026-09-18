//! Bounded capture and offline replay of monotonic clock observations.
//!
//! [`RecordingTimeSource`] wraps an explicitly supplied [`TimeSource`]. It never
//! changes a source result, samples an ambient clock, or holds its capture lock
//! across a source callback. Capture failure invalidates the entire window while
//! live clock reads continue. Overlapping/reentrant reads are refused for capture:
//! this interface has no task identity with which to replay their attribution.
//!
//! [`ReplayTimeSource`] returns exactly the recorded observations, including
//! repeated timestamps. It never advances time on its own or substitutes a live
//! clock when the tape ends. Use its fallible API for diagnostics; the infallible
//! [`TimeSource::now`] interface panics with a typed [`TimeReplayError`] after
//! releasing its lock. Exhaustion remains sticky even if the panic is caught.
//!
//! This is an explicit, serial observation window, not a scheduler transcript.
//! Call order must be reproduced by the consumer. Timer registration, readiness,
//! cancellation, UTC, unwrapped clock reads, and cross-task ordering are not
//! captured. Consuming a tape proves only that window, not application success.
//! Neither recording nor replay is installed globally or enabled by default.

use super::TimeSource;
use crate::types::Time;
use parking_lot::Mutex;
use std::fmt;
use std::sync::Arc;
use zeroize::Zeroize;

mod codec;
pub use codec::{TimeTapeBytes, TimeTapeDecodeLimits, TimeTapeError};

/// Why a complete clock-observation window cannot be extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TimeCaptureError {
    /// The caller-selected observation count was exceeded.
    #[error("clock capture exceeded its observation limit")]
    ObservationLimit,
    /// Bounded storage could not be reserved.
    #[error("clock capture allocation failed")]
    Allocation,
    /// Reads overlapped; the source interface supplies no caller attribution.
    #[error("clock capture observed overlapping source calls")]
    ConcurrentObservation,
    /// A source call unwound instead of returning an observation.
    #[error("clock capture contains an interrupted source call")]
    InterruptedObservation,
    /// A completed serial source observation moved backwards.
    #[error("clock capture observed non-monotonic time")]
    NonMonotonic,
    /// Capture was finished while a source call was still in flight.
    #[error("clock capture was finished during a source call")]
    ObservationInFlight,
    /// This capture window has already been extracted or refused.
    #[error("clock capture is already finished")]
    Finished,
}

struct CaptureState {
    samples: Vec<u64>,
    limit: usize,
    in_flight: bool,
    finished: bool,
    failure: Option<TimeCaptureError>,
}

impl Drop for CaptureState {
    fn drop(&mut self) {
        self.samples.zeroize();
    }
}

/// Transparent, opt-in capture of serial reads from an authorized clock.
///
/// The observation limit bounds retained sample count, not allocator overhead or
/// the supplied source. A failed capture never changes the source's result or
/// panic. An outstanding observation makes [`finish`](Self::finish) refuse the
/// window instead of returning a deceptively complete prefix. Further reads
/// after finishing still forward to the source, but are outside the window.
/// Debug output excludes timestamps and the source, which need not be `Debug`.
pub struct RecordingTimeSource<S: ?Sized> {
    source: Arc<S>,
    state: Mutex<CaptureState>,
}

impl<S: ?Sized> fmt::Debug for RecordingTimeSource<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (observations, finished, failure) = {
            let state = self.state.lock();
            (state.samples.len(), state.finished, state.failure)
        };
        f.debug_struct("RecordingTimeSource")
            .field("observations", &observations)
            .field("finished", &finished)
            .field("failure", &failure)
            .finish_non_exhaustive()
    }
}

impl<S: TimeSource + ?Sized> RecordingTimeSource<S> {
    /// Wrap a supplied clock without sampling it. Zero is a valid capture limit.
    #[must_use]
    pub fn new(source: Arc<S>, max_observations: usize) -> Self {
        Self {
            source,
            state: Mutex::new(CaptureState {
                samples: Vec::new(),
                limit: max_observations,
                in_flight: false,
                finished: false,
                failure: None,
            }),
        }
    }

    /// Return the first capture failure without sampling the source.
    #[must_use]
    pub fn capture_error(&self) -> Option<TimeCaptureError> {
        self.state.lock().failure
    }

    /// Whether the window has been finished, successfully or otherwise.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.lock().finished
    }

    /// Finish exactly one window without closing or sampling the source.
    ///
    /// Failure discards and zeroizes captured samples. No partial tape escapes.
    /// This operation does not wait for an outstanding source call; such a call
    /// invalidates the window and continues forwarding its original result.
    pub fn finish(&self) -> Result<TimeTape, TimeCaptureError> {
        let (tape, failure) = {
            let mut state = self.state.lock();
            if state.finished {
                return Err(TimeCaptureError::Finished);
            }
            state.finished = true;
            if state.in_flight {
                state
                    .failure
                    .get_or_insert(TimeCaptureError::ObservationInFlight);
            }
            let tape = TimeTape {
                samples: std::mem::take(&mut state.samples),
            };
            (tape, state.failure)
        };
        match failure {
            Some(error) => Err(error),
            None => Ok(tape),
        }
    }

    fn begin(&self) -> Option<ObservationGuard<'_>> {
        let mut state = self.state.lock();
        if state.finished || state.failure.is_some() {
            return None;
        }
        let failure = if state.in_flight {
            Some(TimeCaptureError::ConcurrentObservation)
        } else if state.samples.len() == state.limit {
            Some(TimeCaptureError::ObservationLimit)
        } else if state.samples.len() == state.samples.capacity() {
            // Amortize growth without requesting capacity beyond the logical
            // ceiling. No source callback runs until storage has been reserved.
            let additional = (state.limit - state.samples.len()).min(state.samples.len().max(8));
            state
                .samples
                .try_reserve_exact(additional)
                .err()
                .map(|_| TimeCaptureError::Allocation)
        } else {
            None
        };
        if let Some(error) = failure {
            state.failure = Some(error);
            return None;
        }
        state.in_flight = true;
        Some(ObservationGuard {
            state: &self.state,
            completed: false,
        })
    }
}

impl<S: TimeSource + ?Sized> TimeSource for RecordingTimeSource<S> {
    fn now(&self) -> Time {
        let guard = self.begin();
        let now = self.source.now();
        if let Some(guard) = guard {
            guard.complete(now);
        }
        now
    }
}

struct ObservationGuard<'a> {
    state: &'a Mutex<CaptureState>,
    completed: bool,
}

impl ObservationGuard<'_> {
    fn complete(mut self, now: Time) {
        let mut state = self.state.lock();
        if !state.finished && state.failure.is_none() {
            let sample = now.as_nanos();
            if state.samples.last().is_some_and(|last| *last > sample) {
                state.failure = Some(TimeCaptureError::NonMonotonic);
            } else {
                // begin reserved this slot and disallowed overlapping capture.
                state.samples.push(sample);
            }
        }
        state.in_flight = false;
        self.completed = true;
    }
}

impl Drop for ObservationGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let mut state = self.state.lock();
            state.in_flight = false;
            state
                .failure
                .get_or_insert(TimeCaptureError::InterruptedObservation);
        }
    }
}

/// An owned, complete, nondecreasing sequence of clock observations.
///
/// Debug output omits timestamps. Owned samples are zeroized on drop, not copies
/// retained by the caller or by the original source. Timestamps can reveal
/// activity patterns; treat an exported capture as sensitive application data.
pub struct TimeTape {
    samples: Vec<u64>,
}

impl fmt::Debug for TimeTape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeTape")
            .field("observations", &self.samples.len())
            .finish_non_exhaustive()
    }
}

impl Drop for TimeTape {
    fn drop(&mut self) {
        self.samples.zeroize();
    }
}

impl TimeTape {
    /// Number of completed observations, including repeated timestamps.
    #[must_use]
    pub fn observations(&self) -> usize {
        self.samples.len()
    }

    /// Consume the capture into a clock with no host-clock capability.
    #[must_use]
    pub fn replay(self) -> ReplayTimeSource {
        ReplayTimeSource {
            state: Mutex::new(ReplayState {
                tape: self,
                index: 0,
                failure: None,
            }),
        }
    }
}

/// A redacted clock replay diagnostic; never includes a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TimeReplayError {
    /// The consumer requested an observation absent from the capture.
    #[error("clock replay exhausted at observation {index}")]
    Exhausted {
        /// Zero-based position of the refused observation.
        index: usize,
    },
    /// The consumer has not yet consumed the entire capture window.
    #[error("clock replay consumed {consumed} of {total} observations")]
    Unconsumed {
        /// Number of observations already returned.
        consumed: usize,
        /// Number of observations in the captured window.
        total: usize,
    },
}

struct ReplayState {
    tape: TimeTape,
    index: usize,
    failure: Option<TimeReplayError>,
}

/// Offline, fail-closed clock implementing the existing timer-driver interface.
///
/// Calls are serialized, but no scheduler or caller identity is reproduced.
/// Use only with a consumer that reproduces the captured serial call order.
/// `TimeSource::now` panics on exhaustion because its signature cannot return an
/// error. [`try_now`](Self::try_now) exposes the same sticky failure without a
/// panic. Diagnostic methods do not consume observations or access a live clock.
pub struct ReplayTimeSource {
    state: Mutex<ReplayState>,
}

impl fmt::Debug for ReplayTimeSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (consumed, total, failure) = {
            let state = self.state.lock();
            (state.index, state.tape.samples.len(), state.failure)
        };
        f.debug_struct("ReplayTimeSource")
            .field("consumed", &consumed)
            .field("total", &total)
            .field("failure", &failure)
            .finish_non_exhaustive()
    }
}

impl ReplayTimeSource {
    /// Return the next exact observation, or permanently refuse exhaustion.
    pub fn try_now(&self) -> Result<Time, TimeReplayError> {
        let mut state = self.state.lock();
        if let Some(error) = state.failure {
            return Err(error);
        }
        let Some(sample) = state.tape.samples.get(state.index).copied() else {
            let error = TimeReplayError::Exhausted { index: state.index };
            state.failure = Some(error);
            return Err(error);
        };
        state.index += 1;
        Ok(Time::from_nanos(sample))
    }

    /// Check complete consumption without advancing time.
    ///
    /// An incomplete check is nonterminal: consumption may continue. An actual
    /// read past the end remains an error even after every sample was consumed.
    pub fn verify_complete(&self) -> Result<(), TimeReplayError> {
        let state = self.state.lock();
        if let Some(error) = state.failure {
            Err(error)
        } else if state.index != state.tape.samples.len() {
            Err(TimeReplayError::Unconsumed {
                consumed: state.index,
                total: state.tape.samples.len(),
            })
        } else {
            Ok(())
        }
    }

    /// Number of observations successfully returned so far.
    #[must_use]
    pub fn observations_consumed(&self) -> usize {
        self.state.lock().index
    }

    /// First terminal replay failure, independent of nonterminal completeness checks.
    #[must_use]
    pub fn replay_error(&self) -> Option<TimeReplayError> {
        self.state.lock().failure
    }
}

impl TimeSource for ReplayTimeSource {
    fn now(&self) -> Time {
        match self.try_now() {
            Ok(time) => time,
            // try_now has released its mutex before invoking the panic hook.
            Err(error) => std::panic::panic_any(error),
        }
    }
}

#[cfg(test)]
mod tests;
