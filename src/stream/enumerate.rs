//! Enumerate combinator.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`enumerate`](super::StreamExt::enumerate) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Enumerate<S> {
    stream: S,
    count: usize,
    done: bool,
}

struct EnumerateProj<'a, S> {
    stream: Pin<&'a mut S>,
    count: &'a mut usize,
    done: &'a mut bool,
}

impl<S> Enumerate<S> {
    #[allow(unsafe_code)]
    fn project(self: Pin<&mut Self>) -> EnumerateProj<'_, S> {
        // SAFETY: `stream` is structurally pinned; `count` and `done` are `Unpin`.
        let this = unsafe { self.get_unchecked_mut() };
        EnumerateProj {
            stream: unsafe { Pin::new_unchecked(&mut this.stream) },
            count: &mut this.count,
            done: &mut this.done,
        }
    }

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
