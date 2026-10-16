//! Throttle combinator for streams.
//!
//! The `Throttle` combinator rate-limits a stream, yielding at most one
//! item per time period. Items that arrive during the suppression window
//! are dropped.

use super::Stream;
use crate::types::Time;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// Cooperative budget for suppressed items drained in a single poll.
///
/// Without this cap, an always-ready inner stream can monopolize the executor
/// forever while the throttle window is still closed.
const MAX_SUPPRESSED_DRAIN_PER_POLL: usize = 64;

/// A stream that yields at most one item per time period.
///
/// Created by [`StreamExt::throttle`](super::StreamExt::throttle).
///
/// The first item from the underlying stream passes through immediately.
/// Subsequent items are suppressed until `period` has elapsed since
/// the last yielded item.
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Throttle<S> {
    #[pin]
    stream: S,
    period: Duration,
    last_yield: Option<Time>,
    done: bool,
    time_getter: fn() -> Time,
}

impl<S> Throttle<S> {
    /// Creates a new `Throttle` stream.
    #[inline]
    pub(crate) fn new(stream: S, period: Duration) -> Self {
        Self::with_time_getter(stream, period, wall_clock_now)
    }

    /// Creates a new `Throttle` stream with a custom time source.
    #[inline]
    pub fn with_time_getter(stream: S, period: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            stream,
            period,
            last_yield: None,
            done: false,
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

impl<S: Stream> Stream for Throttle<S> {
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let mut this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }
        let mut suppressed = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    let now = (this.time_getter)();
                    let should_yield = match this.last_yield {
                        None => true,
                        Some(last) => {
                            Duration::from_nanos(now.duration_since(*last)) >= *this.period
                        }
                    };
                    if should_yield {
                        *this.last_yield = Some(now);
                        return Poll::Ready(Some(item));
                    }
                    // Drop suppressed items in bounded batches so an always-ready
                    // producer cannot monopolize the executor while the window is closed.
                    suppressed += 1;
                    if suppressed >= MAX_SUPPRESSED_DRAIN_PER_POLL {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.done = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
#[path = "throttle_inline_tests.rs"]
mod tests;
