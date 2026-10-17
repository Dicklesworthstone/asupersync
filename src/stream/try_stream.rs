//! Try combinators for streams of Results.
//!
//! These combinators short-circuit on the first error.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Error returned by try-stream terminal combinators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TryStreamError<E> {
    /// The wrapped stream or closure returned an error.
    Inner(E),
    /// The same future was polled again after it already returned `Ready`.
    PolledAfterCompletion,
}

impl<E: std::fmt::Display> std::fmt::Display for TryStreamError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(err) => err.fmt(f),
            Self::PolledAfterCompletion => {
                write!(f, "try_stream future polled after completion")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for TryStreamError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(err) => Some(err),
            Self::PolledAfterCompletion => None,
        }
    }
}

impl<E> From<E> for TryStreamError<E> {
    #[inline]
    fn from(value: E) -> Self {
        Self::Inner(value)
    }
}

/// Cooperative budget for success-path items drained in a single poll.
///
/// Without this bound, an always-ready success-heavy stream can monopolize one
/// executor turn while these terminal futures drain the entire input.
const TRY_STREAM_COOPERATIVE_BUDGET: usize = 1024;

/// A future that collects items from a stream of Results.
///
/// Short-circuits on the first error.
///
/// Created by [`StreamExt::try_collect`](super::StreamExt::try_collect).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct TryCollect<S, C> {
    stream: S,
    collection: C,
    completed: bool,
}

impl<S, C> TryCollect<S, C> {
    /// Creates a new `TryCollect` future.
    #[inline]
    pub(crate) fn new(stream: S, collection: C) -> Self {
        Self {
            stream,
            collection,
            completed: false,
        }
    }
}

impl<S: Unpin, C> Unpin for TryCollect<S, C> {}

impl<S, T, E, C> Future for TryCollect<S, C>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    C: Default + Extend<T>,
{
    type Output = Result<C, TryStreamError<E>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(TryStreamError::PolledAfterCompletion));
        }
        let mut processed_this_poll = 0usize;
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(item))) => {
                    self.collection.extend(std::iter::once(item));
                    processed_this_poll += 1;
                    if processed_this_poll >= TRY_STREAM_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    self.completed = true;
                    return Poll::Ready(Err(TryStreamError::Inner(e)));
                }
                Poll::Ready(None) => {
                    self.completed = true;
                    return Poll::Ready(Ok(std::mem::take(&mut self.collection)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A future that folds items from a stream of Results.
///
/// Short-circuits on the first error.
///
/// Created by [`StreamExt::try_fold`](super::StreamExt::try_fold).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct TryFold<S, F, Acc> {
    stream: S,
    f: F,
    acc: Option<Acc>,
    completed: bool,
}

impl<S, F, Acc> TryFold<S, F, Acc> {
    /// Creates a new `TryFold` future.
    #[inline]
    pub(crate) fn new(stream: S, init: Acc, f: F) -> Self {
        Self {
            stream,
            f,
            acc: Some(init),
            completed: false,
        }
    }
}

impl<S: Unpin, F, Acc> Unpin for TryFold<S, F, Acc> {}

impl<S, F, Acc, T, E> Future for TryFold<S, F, Acc>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    F: FnMut(Acc, T) -> Result<Acc, E>,
{
    type Output = Result<Acc, TryStreamError<E>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(TryStreamError::PolledAfterCompletion));
        }
        let mut processed_this_poll = 0usize;
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(item))) => {
                    let acc = self
                        .acc
                        .take()
                        .expect("TryFold accumulator missing before completion");
                    match (self.f)(acc, item) {
                        Ok(new_acc) => self.acc = Some(new_acc),
                        Err(e) => {
                            self.completed = true;
                            return Poll::Ready(Err(TryStreamError::Inner(e)));
                        }
                    }
                    processed_this_poll += 1;
                    if processed_this_poll >= TRY_STREAM_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    self.completed = true;
                    return Poll::Ready(Err(TryStreamError::Inner(e)));
                }
                Poll::Ready(None) => {
                    self.completed = true;
                    return Poll::Ready(Ok(self
                        .acc
                        .take()
                        .expect("TryFold accumulator missing on completion")));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A future that executes a fallible closure for each item.
///
/// Short-circuits on the first error.
///
/// Created by [`StreamExt::try_for_each`](super::StreamExt::try_for_each).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct TryForEach<S, F> {
    stream: S,
    f: F,
    completed: bool,
}

impl<S, F> TryForEach<S, F> {
    /// Creates a new `TryForEach` future.
    #[inline]
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            completed: false,
        }
    }
}

impl<S: Unpin, F> Unpin for TryForEach<S, F> {}

impl<S, F, E> Future for TryForEach<S, F>
where
    S: Stream + Unpin,
    F: FnMut(S::Item) -> Result<(), E>,
{
    type Output = Result<(), TryStreamError<E>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(TryStreamError::PolledAfterCompletion));
        }
        let mut processed_this_poll = 0usize;
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if let Err(e) = (self.f)(item) {
                        self.completed = true;
                        return Poll::Ready(Err(TryStreamError::Inner(e)));
                    }
                    processed_this_poll += 1;
                    if processed_this_poll >= TRY_STREAM_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    self.completed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
#[path = "try_stream_inline_tests.rs"]
mod tests;
