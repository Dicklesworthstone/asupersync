//! ForEach combinator for streams.
//!
//! The `ForEach` future consumes a stream and executes a closure for each item.

use super::Stream;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items processed in a single poll.
///
/// Without this bound, always-ready streams can monopolize one executor turn.
const FOR_EACH_COOPERATIVE_BUDGET: usize = 1024;

/// A future that executes a closure for each item in a stream.
///
/// Created by [`StreamExt::for_each`](super::StreamExt::for_each).
#[pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ForEach<S, F> {
    #[pin]
    stream: S,
    f: F,
    completed: bool,
}

impl<S, F> ForEach<S, F> {
    /// Creates a new `ForEach` future.
    #[inline]
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            completed: false,
        }
    }
}

impl<S, F> Future for ForEach<S, F>
where
    S: Stream,
    F: FnMut(S::Item),
{
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut this = self.project();
        if *this.completed {
            return Poll::Ready(());
        }
        let mut processed_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    (this.f)(item);
                    processed_this_poll += 1;
                    if processed_this_poll >= FOR_EACH_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.completed = true;
                    return Poll::Ready(());
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A future that executes an async closure for each item in a stream.
///
/// Created by [`StreamExt::for_each_async`](super::StreamExt::for_each_async).
#[pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ForEachAsync<S, F, Fut> {
    #[pin]
    stream: S,
    f: F,
    #[pin]
    pending: Option<Fut>,
    completed: bool,
}

impl<S, F, Fut> ForEachAsync<S, F, Fut> {
    #[inline]
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            pending: None,
            completed: false,
        }
    }
}

impl<S, F, Fut> Future for ForEachAsync<S, F, Fut>
where
    S: Stream,
    F: FnMut(S::Item) -> Fut,
    Fut: Future<Output = ()>,
{
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut this = self.project();
        if *this.completed {
            return Poll::Ready(());
        }
        let mut processed_this_poll = 0usize;
        loop {
            // Complete pending future first
            if let Some(fut) = this.pending.as_mut().as_pin_mut() {
                match fut.poll(cx) {
                    Poll::Ready(()) => {
                        this.pending.set(None);
                        processed_this_poll += 1;
                        if processed_this_poll >= FOR_EACH_COOPERATIVE_BUDGET {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Get next item
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    this.pending.set(Some((this.f)(item)));
                }
                Poll::Ready(None) => {
                    *this.completed = true;
                    return Poll::Ready(());
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
#[path = "for_each_inline_tests.rs"]
mod tests;
