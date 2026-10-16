//! Chain combinator for streams.
//!
//! The `Chain` combinator yields all items from the first stream, then all
//! items from the second stream.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that yields items from the first stream then the second.
///
/// Created by [`StreamExt::chain`](super::StreamExt::chain).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Chain<S1, S2> {
    first: Option<S1>,
    second: S2,
    done: bool,
}

impl<S1, S2> Chain<S1, S2> {
    /// Creates a new `Chain` stream.
    #[inline]
    pub(crate) fn new(first: S1, second: S2) -> Self {
        Self {
            first: Some(first),
            second,
            done: false,
        }
    }

    /// Returns a reference to the first stream, if still active.
    #[inline]
    pub fn first_ref(&self) -> Option<&S1> {
        self.first.as_ref()
    }

    /// Returns a mutable reference to the first stream, if still active.
    #[inline]
    pub fn first_mut(&mut self) -> Option<&mut S1> {
        self.first.as_mut()
    }

    /// Returns a reference to the second stream.
    #[inline]
    pub fn second_ref(&self) -> &S2 {
        &self.second
    }

    /// Returns a mutable reference to the second stream.
    #[inline]
    pub fn second_mut(&mut self) -> &mut S2 {
        &mut self.second
    }

    /// Consumes the combinator, returning the two underlying streams.
    #[inline]
    pub fn into_inner(self) -> (Option<S1>, S2) {
        (self.first, self.second)
    }
}

impl<S1: Unpin, S2: Unpin> Unpin for Chain<S1, S2> {}

impl<S1, S2> Stream for Chain<S1, S2>
where
    S1: Stream + Unpin,
    S2: Stream<Item = S1::Item> + Unpin,
{
    type Item = S1::Item;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }

        if let Some(first) = self.first.as_mut() {
            match Pin::new(first).poll_next(cx) {
                Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
                Poll::Ready(None) => {
                    self.first = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        match Pin::new(&mut self.second).poll_next(cx) {
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            other => other,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
            return (0, Some(0));
        }

        let second_hint = self.second.size_hint();
        let Some(first) = self.first.as_ref() else {
            return second_hint;
        };

        let (first_lower, first_upper) = first.size_hint();
        let (second_lower, second_upper) = second_hint;

        let lower = first_lower.saturating_add(second_lower);
        let upper = match (first_upper, second_upper) {
            (Some(a), Some(b)) => a.checked_add(b),
            _ => None,
        };

        (lower, upper)
    }
}

#[cfg(test)]
#[path = "chain_inline_tests.rs"]
mod tests;
