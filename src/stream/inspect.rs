//! Inspect combinator.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`inspect`](super::StreamExt::inspect) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Inspect<S, F> {
    stream: S,
    f: F,
    exhausted: bool,
}

impl<S, F> Inspect<S, F> {
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

impl<S, F> Stream for Inspect<S, F>
where
    S: Stream + Unpin,
    F: FnMut(&S::Item) + Unpin,
{
    type Item = S::Item;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.exhausted {
            return Poll::Ready(None);
        }

        let next = Pin::new(&mut self.stream).poll_next(cx);
        if let Poll::Ready(Some(ref item)) = next {
            (self.f)(item);
        } else if matches!(next, Poll::Ready(None)) {
            self.exhausted = true;
        }
        next
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
#[path = "inspect_inline_tests.rs"]
mod tests;
