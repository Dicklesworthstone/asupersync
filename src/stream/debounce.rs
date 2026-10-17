//! Debounce combinator for streams.
//!
//! The `Debounce` combinator suppresses rapid bursts of items, yielding
//! only the most recent item after a quiet period has elapsed.

use super::Stream;
use crate::time::Sleep;
use crate::types::Time;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// Cooperative budget for immediately-ready items drained in a single poll.
///
/// Without this cap, an always-ready upstream stream can monopolize the
/// executor forever while debounce keeps replacing the buffered item and
/// resetting the quiet-period timer.
const DEBOUNCE_READY_DRAIN_BUDGET: usize = 1024;

/// A stream that debounces items, emitting only after a quiet period.
///
/// Created by [`StreamExt::debounce`](super::StreamExt::debounce).
///
/// When the underlying stream produces an item, it is buffered. If no
/// new item arrives for `period`, the buffered item is yielded. Each
/// new item replaces the buffered value and resets the timer.
///
/// When the underlying stream ends, any buffered item is flushed
/// immediately.
///
/// # Note
///
/// By default this combinator uses the runtime wall clock via
/// [`crate::time::wall_now`], but tests and adapters can override that with
/// [`Debounce::with_time_getter`]. The combinator still arms an internal
/// [`Sleep`] so the executor gets a real wakeup when the quiet period expires,
/// while readiness decisions continue to use the configured time getter.
#[pin_project]
#[must_use = "streams do nothing unless polled"]
pub struct Debounce<S: Stream> {
    #[pin]
    stream: S,
    period: Duration,
    /// The most recently received item and when it was received.
    pending: Option<(S::Item, Time)>,
    /// Whether the underlying stream has ended.
    done: bool,
    /// Wake-capable timer source for delayed wakeup (avoids spin-loop).
    ///
    /// Expiry decisions still use `time_getter`; this sleep exists so the
    /// executor has a real wake source instead of hanging until an unrelated
    /// poll arrives.
    timer: Option<Pin<Box<Sleep>>>,
    time_getter: fn() -> Time,
}

impl<S: Stream + std::fmt::Debug> std::fmt::Debug for Debounce<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Debounce")
            .field("stream", &self.stream)
            .field("period", &self.period)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<S: Stream> Debounce<S> {
    /// Creates a new `Debounce` stream.
    #[inline]
    pub(crate) fn new(stream: S, period: Duration) -> Self {
        Self::with_time_getter(stream, period, wall_clock_now)
    }

    /// Creates a new `Debounce` stream with a custom time source.
    #[inline]
    pub fn with_time_getter(stream: S, period: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            stream,
            period,
            pending: None,
            done: false,
            timer: None,
            time_getter,
        }
    }

    /// Returns a reference to the underlying stream.
    #[inline]
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    #[inline]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    #[inline]
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Returns the configured time source.
    #[inline]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }
}

impl<S: Stream> Stream for Debounce<S> {
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let mut this = self.project();

        // Drain all immediately available items from the underlying stream.
        let had_pending_before = this.pending.is_some();
        let mut drained_this_poll = 0usize;
        if !*this.done {
            loop {
                match this.stream.as_mut().poll_next(cx) {
                    Poll::Ready(Some(item)) => {
                        *this.pending = Some((item, (this.time_getter)()));
                        // New item arrived, reset the timer.
                        *this.timer = None;
                        drained_this_poll += 1;
                        if drained_this_poll >= DEBOUNCE_READY_DRAIN_BUDGET {
                            // Yield cooperatively so an always-ready source
                            // cannot monopolize the executor. The buffered item
                            // remains pending and a self-wake drives the next
                            // burst-drain step.
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                    Poll::Ready(None) => {
                        *this.done = true;
                        break;
                    }
                    Poll::Pending => break,
                }
            }
        }

        // Check if the buffered item's quiet period has elapsed.
        let received_at_opt = this.pending.as_ref().map(|(_, t)| *t);
        if let Some(received_at) = received_at_opt {
            let now = (this.time_getter)();
            let elapsed = Duration::from_nanos(now.duration_since(received_at));
            if *this.done || elapsed >= *this.period {
                *this.timer = None;
                if let Some((item, _)) = this.pending.take() {
                    return Poll::Ready(Some(item));
                }
            }
            // Set up a timer for the remaining quiet period.
            let remaining = this.period.saturating_sub(elapsed);
            if this.timer.is_none() || !had_pending_before {
                let remaining_nanos = remaining.as_nanos().min(u128::from(u64::MAX)) as u64;
                // The wake source must use wall time so `Sleep` can register
                // a real waker even when `time_getter` points at a custom clock.
                let wake_deadline = wall_clock_now().saturating_add_nanos(remaining_nanos);
                *this.timer = Some(Box::pin(Sleep::new(wake_deadline)));
            }
            // Poll the timer to register the waker for delayed wakeup. The
            // timer is only a wake source, not a cancellation point: a
            // cancel-aware poll completes at once while the task is cancelled,
            // and re-arming it would spin until the period really elapsed
            // (br-asupersync-jqhteu).
            if let Some(ref mut timer) = *this.timer {
                if timer.as_mut().poll_deadline(cx).is_ready() {
                    *this.timer = None;
                    let now = (this.time_getter)();
                    let elapsed = Duration::from_nanos(now.duration_since(received_at));
                    if *this.done || elapsed >= *this.period {
                        if let Some((item, _)) = this.pending.take() {
                            return Poll::Ready(Some(item));
                        }
                    }
                    // A wall-clock wake must not override a custom logical
                    // clock. Re-arm the timer for the remaining period so
                    // there is always a wake source for the buffered item.
                    let remaining = this.period.saturating_sub(elapsed);
                    let remaining_nanos = remaining.as_nanos().min(u128::from(u64::MAX)) as u64;
                    let wake_deadline = wall_clock_now().saturating_add_nanos(remaining_nanos);
                    let mut new_timer = Box::pin(Sleep::new(wake_deadline));
                    // Registration can complete immediately if the deadline
                    // elapsed. Reset before retaining the timer: Sleep cannot
                    // be polled after Ready. A wake still cannot override the
                    // configured quiet clock.
                    if new_timer.as_mut().poll_deadline(cx).is_ready() {
                        new_timer.as_mut().get_mut().reset(wake_deadline);
                        cx.waker().wake_by_ref();
                    }
                    *this.timer = Some(new_timer);
                    return Poll::Pending;
                }
            }
            return Poll::Pending;
        }

        if *this.done {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
#[path = "debounce_inline_tests.rs"]
mod tests;
