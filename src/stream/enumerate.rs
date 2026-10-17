//! Enumerate combinator.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`enumerate`](super::StreamExt::enumerate) method.
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Enumerate<S> {
    #[pin]
    stream: S,
    count: usize,
    done: bool,
}

impl<S> Enumerate<S> {
    #[inline]
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            count: 0,
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

impl<S: Stream> Stream for Enumerate<S> {
    type Item = (usize, S::Item);

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }

        match this.stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(item)) => {
                let index = *this.count;
                *this.count += 1;
                Poll::Ready(Some((index, item)))
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
            (0, Some(0))
        } else {
            self.stream.size_hint()
        }
    }
}

#[cfg(test)]
#[path = "enumerate_inline_tests.rs"]
mod tests;
