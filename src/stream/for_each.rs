//! ForEach combinator for streams.
//!
//! The `ForEach` future consumes a stream and executes a closure for each item.

use super::Stream;
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
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ForEach<S, F> {
    stream: S,
    f: F,
    completed: bool,
}

struct ForEachProj<'a, S, F> {
    stream: Pin<&'a mut S>,
    f: &'a mut F,
    completed: &'a mut bool,
}

impl<S, F> ForEach<S, F> {
    #[allow(unsafe_code)]
    fn project(self: Pin<&mut Self>) -> ForEachProj<'_, S, F> {
        // SAFETY: `stream` is structurally pinned; `f` and `completed` are not pinned.
        let this = unsafe { self.get_unchecked_mut() };
        ForEachProj {
            stream: unsafe { Pin::new_unchecked(&mut this.stream) },
            f: &mut this.f,
            completed: &mut this.completed,
        }
    }

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
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ForEachAsync<S, F, Fut> {
    stream: S,
    f: F,
    pending: Option<Fut>,
    completed: bool,
}

struct ForEachAsyncProj<'a, S, F, Fut> {
    stream: Pin<&'a mut S>,
    f: &'a mut F,
    pending: Pin<&'a mut Option<Fut>>,
    completed: &'a mut bool,
}

impl<S, F, Fut> ForEachAsync<S, F, Fut> {
    #[allow(unsafe_code)]
    fn project(self: Pin<&mut Self>) -> ForEachAsyncProj<'_, S, F, Fut> {
        // SAFETY: `stream` and `pending` are structurally pinned; `f` and `completed` are not pinned.
        let this = unsafe { self.get_unchecked_mut() };
        ForEachAsyncProj {
            stream: unsafe { Pin::new_unchecked(&mut this.stream) },
            f: &mut this.f,
            pending: unsafe { Pin::new_unchecked(&mut this.pending) },
            completed: &mut this.completed,
        }
    }

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
