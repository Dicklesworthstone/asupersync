//! Demand-driven timeouts for individual stream items.

use super::Stream;
use crate::cx::{CancelWakerToken, Cx, cap};
use crate::time::{Elapsed, Sleep, TimerDriverHandle};
use crate::types::{CancelReason, Time};
use pin_project::pin_project;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// Why a per-item stream wait ended before the source produced an item.
///
/// Errors produced by the source itself remain values inside the adapter's
/// `Ok`; this type only describes the adapter's time and cancellation boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamTimeoutError {
    /// The current item's allowance elapsed while the source remained pending.
    Elapsed(Elapsed),
    /// The supplied context acknowledged cancellation, with its exact reason.
    Cancelled(CancelReason),
    /// The supplied context could not provide an authorized timer driver.
    TimerUnavailable,
}

impl StreamTimeoutError {
    fn cancelled<Caps>(cx: &Cx<Caps>) -> Self {
        Self::Cancelled(
            cx.cancel_reason()
                .unwrap_or_else(|| CancelReason::user("stream wait cancelled")),
        )
    }
}

impl fmt::Display for StreamTimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elapsed(error) => write!(f, "stream item {error}"),
            Self::Cancelled(reason) => write!(f, "stream wait cancelled: {reason:?}"),
            Self::TimerUnavailable => {
                f.write_str("stream timeout requires time capability and a timer driver")
            }
        }
    }
}

impl std::error::Error for StreamTimeoutError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Elapsed(error) => Some(error),
            Self::Cancelled(_) | Self::TimerUnavailable => None,
        }
    }
}

/// A stream with a separate timeout for each item the consumer requests.
///
/// Created by [`StreamExt::timeout`](super::StreamExt::timeout). Its item is
/// `Result<S::Item, StreamTimeoutError>`; an underlying `Result<T, E>` becomes
/// `Result<Result<T, E>, StreamTimeoutError>` without losing either error type.
///
/// An allowance starts on the first poll for an item and survives later pending
/// polls, including dropping a borrowed `next()` future. After returning an
/// item, no timer or cancellation observer remains until the next poll. Thus
/// backpressure from a slow consumer does not time out a future item.
/// Deadlines saturate at [`Time::MAX`] and use only the supplied context's clock.
///
/// # Poll boundaries and cancellation
///
/// Cancellation observed before polling the source prevents that poll and
/// returns the complete [`CancelReason`]. Checkpoints honor cancellation masks.
/// An item returned by the source wins a simultaneous expiry or cancellation,
/// including a zero timeout: the adapter never discards an obtained item. This
/// is a cooperative poll boundary, not a preemption of synchronous source work.
/// Cancellation during a source poll that returns `None` is reported as
/// cancellation rather than clean end-of-stream.
///
/// An adapter error is yielded once, followed by `None` on every later poll.
/// A clean source `None` is also terminal. All terminal paths remove the timer
/// and cancellation registration before returning. The source remains owned
/// and can be recovered through [`into_inner`](Self::into_inner); it is not
/// polled again after termination.
///
/// Dropping the adapter removes its registrations and drops the source. It
/// cannot roll back effects of prior source polls, unregister a waker retained
/// by that source, or cancel and drain tasks independently owned by the source.
/// No source or item `Send`, `Sync`, `Unpin`, `Clone`, or `'static` bound is added.
#[pin_project]
#[must_use = "streams do nothing unless polled"]
pub struct Timeout<'cx, S, Caps = cap::All> {
    #[pin]
    stream: S,
    cx: &'cx Cx<Caps>,
    duration: Duration,
    waiting: Option<Waiting<'cx, Caps>>,
    done: bool,
}

impl<S: fmt::Debug, Caps> fmt::Debug for Timeout<'_, S, Caps> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Timeout")
            .field("stream", &self.stream)
            .field("duration", &self.duration)
            .field("deadline", &self.waiting.as_ref().map(|wait| wait.deadline))
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<'cx, S, Caps> Timeout<'cx, S, Caps> {
    pub(crate) fn new(stream: S, cx: &'cx Cx<Caps>, duration: Duration) -> Self {
        Self {
            stream,
            cx,
            duration,
            waiting: None,
            done: false,
        }
    }

    /// Returns a reference to the underlying source.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying source.
    ///
    /// Direct source polling does not reset an already-started item allowance.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Recovers the source and removes this adapter's timer and observer.
    ///
    /// No extra source item is consumed, including after a timeout. Effects
    /// of earlier pending source polls remain governed by the source itself.
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Returns the allowance configured for each requested item.
    #[must_use]
    pub const fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns whether clean EOF or the adapter's single error was emitted.
    #[must_use]
    pub const fn is_terminated(&self) -> bool {
        self.done
    }
}

// Every registration lives in this per-demand owner. Taking it after an item,
// error, EOF, or source recovery retires both independent wake sources.
struct Waiting<'cx, Caps> {
    cx: &'cx Cx<Caps>,
    deadline: Time,
    driver: TimerDriverHandle,
    cancel_waker: Option<CancelWakerToken>,
    timer: Option<Sleep>,
}

impl<'cx, Caps: cap::HasTime> Waiting<'cx, Caps> {
    fn new(cx: &'cx Cx<Caps>, duration: Duration) -> Result<Self, StreamTimeoutError> {
        let driver = cx
            .timer_driver()
            .ok_or(StreamTimeoutError::TimerUnavailable)?;
        let deadline = driver.now() + duration;
        // Taking the clock snapshot may cross the owner's own deadline.
        cx.checkpoint()
            .map_err(|_| StreamTimeoutError::cancelled(cx))?;
        Ok(Self {
            cx,
            deadline,
            driver,
            cancel_waker: None,
            timer: None,
        })
    }

    fn poll(&mut self, task: &mut Context<'_>) -> Poll<StreamTimeoutError> {
        let cx = self.cx;
        // One owner-deadline wake can require rearming while cancellation is
        // masked. Bound even an adversarial clock's ready/rearm work per poll.
        for _ in 0..2 {
            let now = self.driver.now();
            if cx.checkpoint().is_err() {
                return Poll::Ready(StreamTimeoutError::cancelled(cx));
            }
            if now >= self.deadline {
                return Poll::Ready(StreamTimeoutError::Elapsed(Elapsed::new(self.deadline)));
            }
            // Keep the subscription even when a request is currently masked.
            // The mask's exit must still wake this owner when cancellation
            // becomes observable; a completed `Cx::cancelled()` cannot do so.
            self.cancel_waker = Some(cx.refresh_cancel_waker(self.cancel_waker, task.waker()));

            // Owner deadlines also need a real wake even outside a native
            // task. Once a masked deadline has elapsed, use the item's future
            // deadline instead of repeatedly arming an already-ready timer.
            let wake_at = cx
                .budget()
                .deadline
                .filter(|deadline| *deadline > now)
                .map_or(self.deadline, |deadline| self.deadline.min(deadline));
            if self.timer.as_ref().map(Sleep::deadline) != Some(wake_at) {
                self.timer = Some(Sleep::with_timer_driver(wake_at, self.driver.clone()));
            }
            let timer = self.timer.as_mut().expect("item wait has its wake timer");
            if Pin::new(timer).poll_deadline(task).is_pending() {
                // Timer/waker registration and retirement can run callbacks.
                // Close the cancellation check/register race before parking.
                if cx.checkpoint().is_err() {
                    return Poll::Ready(StreamTimeoutError::cancelled(cx));
                }
                return Poll::Pending;
            }
            self.timer = None;
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<Caps> Drop for Waiting<'_, Caps> {
    fn drop(&mut self) {
        if let Some(token) = self.cancel_waker.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

impl<S: Stream, Caps: cap::HasTime> Stream for Timeout<'_, S, Caps> {
    type Item = Result<S::Item, StreamTimeoutError>;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let cx = *this.cx;
        if *this.done {
            return Poll::Ready(None);
        }
        if cx.checkpoint().is_err() {
            *this.done = true;
            *this.waiting = None;
            return Poll::Ready(Some(Err(StreamTimeoutError::cancelled(cx))));
        }
        if this.waiting.is_none() {
            match Waiting::new(cx, *this.duration) {
                Ok(waiting) => *this.waiting = Some(waiting),
                Err(error) => {
                    *this.done = true;
                    return Poll::Ready(Some(Err(error)));
                }
            }
        }

        match this.stream.poll_next(task) {
            Poll::Ready(Some(item)) => {
                *this.waiting = None;
                Poll::Ready(Some(Ok(item)))
            }
            Poll::Ready(None) => {
                *this.done = true;
                *this.waiting = None;
                if cx.checkpoint().is_err() {
                    Poll::Ready(Some(Err(StreamTimeoutError::cancelled(cx))))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Pending => {
                let waiting = this
                    .waiting
                    .as_mut()
                    .expect("item wait starts before polling");
                match waiting.poll(task) {
                    Poll::Ready(error) => {
                        *this.done = true;
                        *this.waiting = None;
                        Poll::Ready(Some(Err(error)))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "timeout_inline_tests.rs"]
mod tests;
