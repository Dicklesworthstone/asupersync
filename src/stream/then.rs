//! Then (async map) combinator.

use super::Stream;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`then`](super::StreamExt::then) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Then<S, Fut, F> {
    #[pin]
    stream: S,
    f: F,
    #[pin]
    pending: Option<Fut>,
    done: bool,
}

impl<S, Fut, F> Then<S, Fut, F> {
    #[inline]
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            pending: None,
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

impl<S, Fut, F> Stream for Then<S, Fut, F>
where
    S: Stream,
    F: FnMut(S::Item) -> Fut,
    Fut: Future,
{
    type Item = Fut::Output;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }

        loop {
            if let Some(fut) = this.pending.as_mut().as_pin_mut() {
                match fut.poll(cx) {
                    Poll::Ready(item) => {
                        this.pending.set(None);
                        return Poll::Ready(Some(item));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    let fut = (this.f)(item);
                    this.pending.set(Some(fut));
                }
                Poll::Ready(None) => {
                    *this.done = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
            return (0, Some(0));
        }
        let (lower, upper) = self.stream.size_hint();
        let pending_len = usize::from(self.pending.is_some());
        (
            lower.saturating_add(pending_len),
            upper.and_then(|u| u.checked_add(pending_len)),
        )
    }
}

#[cfg(test)]
#[path = "then_inline_tests.rs"]
mod tests;
