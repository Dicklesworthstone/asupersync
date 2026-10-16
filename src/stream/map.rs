//! Map combinator for streams.
//!
//! The `Map` combinator transforms each item in a stream using a provided function.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that transforms each item using a function.
///
/// Created by [`StreamExt::map`](super::StreamExt::map).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Map<S, F> {
    #[pin]
    stream: S,
    f: F,
    exhausted: bool,
}

impl<S, F> Map<S, F> {
    /// Creates a new `Map` stream.
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

impl<S, F, T> Stream for Map<S, F>
where
    S: Stream,
    F: FnMut(S::Item) -> T,
{
    type Item = T;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }

        match this.stream.poll_next(cx) {
            Poll::Ready(Some(item)) => Poll::Ready(Some((this.f)(item))),
            Poll::Ready(None) => {
                *this.exhausted = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            (0, Some(0))
        } else {
            self.stream.size_hint()
        }
    }
}

#[cfg(test)]
#[path = "map_inline_tests.rs"]
mod tests;
