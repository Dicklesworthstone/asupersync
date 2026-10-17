//! Any and All combinators for streams.
//!
//! The `Any` future checks if any item matches a predicate.
//! The `All` future checks if all items match a predicate.

use super::Stream;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items scanned in a single poll.
///
/// Without this cap, always-ready upstream streams can monopolize an executor
/// turn when `Any`/`All` do not hit an early-exit condition.
const ANY_ALL_COOPERATIVE_BUDGET: usize = 1024;

/// A future that checks if any item in a stream matches a predicate.
///
/// Created by [`StreamExt::any`](super::StreamExt::any).
#[pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Any<S, P> {
    #[pin]
    stream: S,
    predicate: P,
    result: Option<bool>,
}

impl<S, P> Any<S, P> {
    /// Creates a new `Any` future.
    #[inline]
    pub(crate) fn new(stream: S, predicate: P) -> Self {
        Self {
            stream,
            predicate,
            result: None,
        }
    }
}

impl<S, P> Future for Any<S, P>
where
    S: Stream,
    P: FnMut(&S::Item) -> bool,
{
    type Output = bool;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<bool> {
        let mut this = self.project();
        assert!(this.result.is_none(), "Any polled after completion");
        let mut scanned_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if (this.predicate)(&item) {
                        *this.result = Some(true);
                        return Poll::Ready(true);
                    }

                    scanned_this_poll += 1;
                    if scanned_this_poll >= ANY_ALL_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.result = Some(false);
                    return Poll::Ready(false);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A future that checks if all items in a stream match a predicate.
///
/// Created by [`StreamExt::all`](super::StreamExt::all).
#[pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct All<S, P> {
    #[pin]
    stream: S,
    predicate: P,
    result: Option<bool>,
}

impl<S, P> All<S, P> {
    /// Creates a new `All` future.
    #[inline]
    pub(crate) fn new(stream: S, predicate: P) -> Self {
        Self {
            stream,
            predicate,
            result: None,
        }
    }
}

impl<S, P> Future for All<S, P>
where
    S: Stream,
    P: FnMut(&S::Item) -> bool,
{
    type Output = bool;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<bool> {
        let mut this = self.project();
        assert!(this.result.is_none(), "All polled after completion");
        let mut scanned_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if !(this.predicate)(&item) {
                        *this.result = Some(false);
                        return Poll::Ready(false);
                    }

                    scanned_this_poll += 1;
                    if scanned_this_poll >= ANY_ALL_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.result = Some(true);
                    return Poll::Ready(true);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
#[path = "any_all_inline_tests.rs"]
mod tests;
