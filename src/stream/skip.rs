//! Skip combinator.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for skipped items drained in a single poll.
///
/// Without this bound, always-ready upstream streams can monopolize an
/// executor turn when skipping large prefixes (or an unbounded skip_while
/// predicate), preventing fair progress for sibling tasks.
const SKIP_COOPERATIVE_BUDGET: usize = 1024;

/// Stream for the [`skip`](super::StreamExt::skip) method.
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Skip<S> {
    #[pin]
    stream: S,
    remaining: usize,
    exhausted: bool,
}

impl<S> Skip<S> {
    #[inline]
    pub(crate) fn new(stream: S, remaining: usize) -> Self {
        Self {
            stream,
            remaining,
            exhausted: false,
        }
    }
}

impl<S: Stream> Stream for Skip<S> {
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }

        let mut skipped_this_poll = 0usize;
        while *this.remaining > 0 {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(_)) => {
                    *this.remaining -= 1;
                    skipped_this_poll += 1;
                    if *this.remaining > 0 && skipped_this_poll >= SKIP_COOPERATIVE_BUDGET {
                        // Yield cooperatively for fairness, then continue skipping
                        // on the next poll.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.exhausted = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        match this.stream.poll_next(cx) {
            Poll::Ready(None) => {
                *this.exhausted = true;
                Poll::Ready(None)
            }
            other => other,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            return (0, Some(0));
        }
        let (lower, upper) = self.stream.size_hint();
        let lower = lower.saturating_sub(self.remaining);
        let upper = upper.map(|x| x.saturating_sub(self.remaining));
        (lower, upper)
    }
}

/// Stream for the [`skip_while`](super::StreamExt::skip_while) method.
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct SkipWhile<S, F> {
    #[pin]
    stream: S,
    predicate: F,
    done: bool,
    exhausted: bool,
}

impl<S, F> SkipWhile<S, F> {
    #[inline]
    pub(crate) fn new(stream: S, predicate: F) -> Self {
        Self {
            stream,
            predicate,
            done: false,
            exhausted: false,
        }
    }
}

impl<S, F> Stream for SkipWhile<S, F>
where
    S: Stream,
    F: FnMut(&S::Item) -> bool,
{
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }

        if *this.done {
            return match this.stream.poll_next(cx) {
                Poll::Ready(None) => {
                    *this.exhausted = true;
                    Poll::Ready(None)
                }
                other => other,
            };
        }

        let mut skipped_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if !(this.predicate)(&item) {
                        *this.done = true;
                        return Poll::Ready(Some(item));
                    }
                    skipped_this_poll += 1;
                    if skipped_this_poll >= SKIP_COOPERATIVE_BUDGET {
                        // Prevent one poll from consuming an unbounded run of
                        // skip-matching items.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.exhausted = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            return (0, Some(0));
        }
        let (lower, upper) = self.stream.size_hint();
        if self.done {
            (lower, upper)
        } else {
            (0, upper)
        }
    }
}

#[cfg(test)]
#[path = "skip_inline_tests.rs"]
mod tests;
