//! Take combinator.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`take`](super::StreamExt::take) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Take<S> {
    stream: S,
    remaining: usize,
}

impl<S> Take<S> {
    pub(crate) fn new(stream: S, remaining: usize) -> Self {
        Self { stream, remaining }
    }
}

impl<S: Stream + Unpin> Stream for Take<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }

        let next = Pin::new(&mut self.stream).poll_next(cx);
        match next {
            Poll::Ready(Some(item)) => {
                self.remaining -= 1;
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => {
                self.remaining = 0;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.remaining == 0 {
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
pub struct TakeWhile<S, F> {
    stream: S,
    predicate: F,
    done: bool,
}

impl<S, F> TakeWhile<S, F> {
    pub(crate) fn new(stream: S, predicate: F) -> Self {
        Self {
            stream,
            predicate,
            done: false,
        }
    }
}

impl<S, F> Stream for TakeWhile<S, F>
where
    S: Stream + Unpin,
    F: FnMut(&S::Item) -> bool + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }

        let next = Pin::new(&mut self.stream).poll_next(cx);
        match next {
            Poll::Ready(Some(item)) => {
                if (self.predicate)(&item) {
                    Poll::Ready(Some(item))
                } else {
                    self.done = true;
                    Poll::Ready(None)
                }
            }
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
            return (0, Some(0));
        }
        let (_, upper) = self.stream.size_hint();
        (0, upper)
    }
}
