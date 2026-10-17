//! Collect combinator for streams.
//!
//! The `Collect` future consumes a stream and collects all items into a collection.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items drained in a single poll.
///
/// Without this cap, `Collect` can monopolize an executor turn when the
/// upstream stream stays always-ready for long runs.
const COLLECT_COOPERATIVE_BUDGET: usize = 1024;

/// A future that collects all items from a stream into a collection.
///
/// Created by [`StreamExt::collect`](super::StreamExt::collect).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Collect<S, C> {
    stream: S,
    collection: C,
    completed: bool,
}

impl<S, C> Collect<S, C> {
    /// Creates a new `Collect` future.
    #[inline]
    pub(crate) fn new(stream: S, collection: C) -> Self {
        Self {
            stream,
            collection,
            completed: false,
        }
    }
}

impl<S: Unpin, C> Unpin for Collect<S, C> {}

impl<S, C> Future for Collect<S, C>
where
    S: Stream + Unpin,
    C: Default + Extend<S::Item>,
{
    type Output = C;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<C> {
        assert!(
            !self.completed,
            "Collect polled after completion; terminal output cannot be replayed soundly"
        );
        let mut collected_this_poll = 0usize;
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.collection.extend(std::iter::once(item));
                    collected_this_poll += 1;
                    if collected_this_poll >= COLLECT_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    self.completed = true;
                    return Poll::Ready(std::mem::take(&mut self.collection));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
#[path = "collect_inline_tests.rs"]
mod tests;
