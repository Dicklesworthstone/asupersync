//! Filter combinator for streams.
//!
//! The `Filter` combinator yields only items that match a predicate.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for rejected items drained in a single poll.
///
/// Without this cap, an always-ready upstream stream can monopolize the
/// executor forever if the predicate or mapper keeps rejecting items.
const FILTER_REJECTION_BUDGET: usize = 1024;

/// A stream that yields only items matching a predicate.
///
/// Created by [`StreamExt::filter`](super::StreamExt::filter).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Filter<S, P> {
    #[pin]
    stream: S,
    predicate: P,
    exhausted: bool,
}

impl<S, P> Filter<S, P> {
    /// Creates a new `Filter` stream.
    #[inline]
    pub(crate) fn new(stream: S, predicate: P) -> Self {
        Self {
            stream,
            predicate,
            exhausted: false,
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
}

impl<S, P> Stream for Filter<S, P>
where
    S: Stream,
    P: FnMut(&S::Item) -> bool,
{
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let mut this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }
        let mut rejected_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if (this.predicate)(&item) {
                        return Poll::Ready(Some(item));
                    }
                    rejected_this_poll += 1;
                    if rejected_this_poll >= FILTER_REJECTION_BUDGET {
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
        let (_, upper) = self.stream.size_hint();
        // Lower bound is 0 since all items might be filtered
        (0, upper)
    }
}

/// A stream that yields only items matching an async predicate.
///
/// Created by [`StreamExt::filter_map`](super::StreamExt::filter_map).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct FilterMap<S, F> {
    #[pin]
    stream: S,
    f: F,
    exhausted: bool,
}

impl<S, F> FilterMap<S, F> {
    /// Creates a new `FilterMap` stream.
    #[inline]
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            exhausted: false,
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
}

impl<S, F, T> Stream for FilterMap<S, F>
where
    S: Stream,
    F: FnMut(S::Item) -> Option<T>,
{
    type Item = T;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }
        let mut rejected_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if let Some(result) = (this.f)(item) {
                        return Poll::Ready(Some(result));
                    }
                    rejected_this_poll += 1;
                    if rejected_this_poll >= FILTER_REJECTION_BUDGET {
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
        let (_, upper) = self.stream.size_hint();
        // Lower bound is 0 since all items might be filtered
        (0, upper)
    }
}

#[cfg(test)]
#[path = "filter_inline_tests.rs"]
mod tests;
