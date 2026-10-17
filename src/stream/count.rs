//! Count combinator for streams.
//!
//! The `Count` future consumes a stream and counts the number of items.

use super::Stream;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items drained in a single poll.
///
/// Without this bound, an always-ready upstream stream can monopolize one
/// executor turn while `Count` drains the entire stream.
const COUNT_COOPERATIVE_BUDGET: usize = 1024;

/// A future that counts the items in a stream.
///
/// Created by [`StreamExt::count`](super::StreamExt::count).
#[pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Count<S> {
    #[pin]
    stream: S,
    total: usize,
    completed: bool,
}

impl<S> Count<S> {
    /// Creates a new `Count` future.
    #[inline]
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            total: 0,
            completed: false,
        }
    }
}

impl<S> Future for Count<S>
where
    S: Stream,
{
    type Output = usize;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
        let mut this = self.project();
        assert!(!*this.completed, "Count polled after completion");
        let mut counted_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(_)) => {
                    *this.total += 1;
                    counted_this_poll += 1;
                    if counted_this_poll >= COUNT_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.completed = true;
                    return Poll::Ready(*this.total);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
#[path = "count_inline_tests.rs"]
mod tests;
