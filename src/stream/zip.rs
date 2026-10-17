//! Zip combinator for streams.
//!
//! The `Zip` combinator yields pairs from two streams until either stream ends.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that zips two streams into pairs.
///
/// Created by [`StreamExt::zip`](super::StreamExt::zip).
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Zip<S1: Stream, S2: Stream> {
    #[pin]
    stream1: S1,
    #[pin]
    stream2: S2,
    queued1: Option<S1::Item>,
    queued2: Option<S2::Item>,
    exhausted: bool,
}

impl<S1: Stream, S2: Stream> Zip<S1, S2> {
    /// Creates a new `Zip` stream.
    pub(crate) fn new(stream1: S1, stream2: S2) -> Self {
        Self {
            stream1,
            stream2,
            queued1: None,
            queued2: None,
            exhausted: false,
        }
    }

    /// Returns a reference to the first stream.
    pub fn first_ref(&self) -> &S1 {
        &self.stream1
    }

    /// Returns a reference to the second stream.
    pub fn second_ref(&self) -> &S2 {
        &self.stream2
    }

    /// Returns mutable references to the underlying streams.
    pub fn get_mut(&mut self) -> (&mut S1, &mut S2) {
        (&mut self.stream1, &mut self.stream2)
    }

    /// Consumes the combinator, returning the underlying streams and any
    /// already-buffered items that were not yet yielded as a pair.
    pub fn into_inner(self) -> (S1, S2, Option<S1::Item>, Option<S2::Item>) {
        (self.stream1, self.stream2, self.queued1, self.queued2)
    }
}

impl<S1, S2> Stream for Zip<S1, S2>
where
    S1: Stream,
    S2: Stream,
{
    type Item = (S1::Item, S2::Item);

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }
        if this.queued1.is_none() {
            match this.stream1.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => *this.queued1 = Some(item),
                Poll::Ready(None) => {
                    *this.queued1 = None;
                    *this.queued2 = None;
                    *this.exhausted = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => {}
            }
        }

        if this.queued2.is_none() {
            match this.stream2.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => *this.queued2 = Some(item),
                Poll::Ready(None) => {
                    *this.queued1 = None;
                    *this.queued2 = None;
                    *this.exhausted = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => {}
            }
        }

        if this.queued1.is_some() && this.queued2.is_some() {
            let item1 = this.queued1.take().expect("queued1 should have item");
            let item2 = this.queued2.take().expect("queued2 should have item");
            Poll::Ready(Some((item1, item2)))
        } else {
            Poll::Pending
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            return (0, Some(0));
        }

        let (lower1, upper1) = self.stream1.size_hint();
        let (lower2, upper2) = self.stream2.size_hint();
        let queued1 = usize::from(self.queued1.is_some());
        let queued2 = usize::from(self.queued2.is_some());

        let lower = lower1
            .saturating_add(queued1)
            .min(lower2.saturating_add(queued2));
        let upper = match (
            upper1.map(|upper| upper.saturating_add(queued1)),
            upper2.map(|upper| upper.saturating_add(queued2)),
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (bound @ Some(_), None) | (None, bound @ Some(_)) => bound,
            (None, None) => None,
        };

        (lower, upper)
    }
}

#[cfg(test)]
#[path = "zip_inline_tests.rs"]
mod tests;
