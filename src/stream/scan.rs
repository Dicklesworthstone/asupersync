//! Scan combinator for streams.
//!
//! The `Scan` combinator is like [`Fold`](super::Fold), but yields each
//! intermediate accumulator value instead of only the final result.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that yields intermediate accumulator values.
///
/// Created by [`StreamExt::scan`](super::StreamExt::scan).
///
/// For each item in the underlying stream, calls `f(state, item)`.
/// If `f` returns `Some(value)`, that value is yielded and the state
/// is updated. If `f` returns `None`, the stream terminates.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Scan<S, St, F> {
    #[pin]
    stream: S,
    state: Option<St>,
    f: F,
}

impl<S, St, F> Scan<S, St, F> {
    /// Creates a new `Scan` stream.
    #[inline]
    pub(crate) fn new(stream: S, initial_state: St, f: F) -> Self {
        Self {
            stream,
            state: Some(initial_state),
            f,
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

impl<S, St, B, F> Stream for Scan<S, St, F>
where
    S: Stream,
    F: FnMut(&mut St, S::Item) -> Option<B>,
{
    type Item = B;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<B>> {
        let this = self.project();
        let Some(state) = this.state else {
            return Poll::Ready(None);
        };

        match this.stream.poll_next(cx) {
            Poll::Ready(Some(item)) => {
                if let Some(value) = (this.f)(state, item) {
                    Poll::Ready(Some(value))
                } else {
                    *this.state = None;
                    Poll::Ready(None)
                }
            }
            Poll::Ready(None) => {
                *this.state = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
#[path = "scan_inline_tests.rs"]
mod tests;
