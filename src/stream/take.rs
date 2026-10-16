//! Take combinator.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`take`](super::StreamExt::take) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Take<S> {
    #[pin]
    stream: S,
    remaining: usize,
    done: bool,
}

impl<S> Take<S> {
    #[inline]
    pub(crate) fn new(stream: S, remaining: usize) -> Self {
        Self {
            stream,
            remaining,
            done: false,
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

impl<S: Stream> Stream for Take<S> {
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }
        if *this.remaining == 0 {
            *this.done = true;
            return Poll::Ready(None);
        }

        let next = this.stream.poll_next(cx);
        match next {
            Poll::Ready(Some(item)) => {
                *this.remaining -= 1;
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => {
                *this.remaining = 0;
                *this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done || self.remaining == 0 {
            return (0, Some(0));
        }

        let (lower, upper) = self.stream.size_hint();
        let lower = lower.min(self.remaining);
        let upper = upper.map_or(Some(self.remaining), |x| Some(x.min(self.remaining)));

        (lower, upper)
    }
}

/// Stream for the [`take_while`](super::StreamExt::take_while) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct TakeWhile<S, F> {
    #[pin]
    stream: S,
    predicate: F,
    done: bool,
}

impl<S, F> TakeWhile<S, F> {
    #[inline]
    pub(crate) fn new(stream: S, predicate: F) -> Self {
        Self {
            stream,
            predicate,
            done: false,
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

impl<S, F> Stream for TakeWhile<S, F>
where
    S: Stream,
    F: FnMut(&S::Item) -> bool,
{
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }

        let next = this.stream.poll_next(cx);
        match next {
            Poll::Ready(Some(item)) => {
                if (this.predicate)(&item) {
                    Poll::Ready(Some(item))
                } else {
                    *this.done = true;
                    Poll::Ready(None)
                }
            }
            Poll::Ready(None) => {
                *this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
            return (0, Some(0));
        }
        let (_, upper) = self.stream.size_hint();
        (0, upper)
    }
}

#[cfg(test)]
#[path = "take_inline_tests.rs"]
mod tests;
