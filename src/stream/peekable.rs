//! Peekable combinator for streams.
//!
//! The `Peekable` combinator allows looking at the next item without
//! consuming it, similar to [`std::iter::Peekable`].

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that supports peeking at the next element without consuming it.
///
/// Created by [`StreamExt::peekable`](super::StreamExt::peekable).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Peekable<S: Stream> {
    #[pin]
    stream: S,
    peeked: PeekSlot<S::Item>,
}

#[derive(Debug)]
enum PeekSlot<T> {
    Empty,
    Item(T),
    Exhausted,
}

impl<S: Stream> Peekable<S> {
    /// Creates a new `Peekable` stream.
    #[inline]
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            peeked: PeekSlot::Empty,
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
    ///
    /// Note: any peeked item is lost.
    #[inline]
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Peeks at the next item without consuming it.
    ///
    /// Returns `Poll::Ready(Some(&item))` if the next item is available,
    /// `Poll::Ready(None)` if the stream is exhausted, or `Poll::Pending`
    /// if the next item is not yet ready.
    #[inline]
    pub fn poll_peek(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<&S::Item>> {
        let mut this = self.project();
        if matches!(this.peeked, PeekSlot::Empty) {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => *this.peeked = PeekSlot::Item(item),
                Poll::Ready(None) => *this.peeked = PeekSlot::Exhausted,
                Poll::Pending => return Poll::Pending,
            }
        }
        match &*this.peeked {
            PeekSlot::Item(item) => Poll::Ready(Some(item)),
            PeekSlot::Exhausted => Poll::Ready(None),
            PeekSlot::Empty => Poll::Pending,
        }
    }

    /// Returns a reference to the peeked item, if one has been peeked.
    ///
    /// Unlike `poll_peek`, this does not poll the underlying stream.
    #[inline]
    #[must_use]
    pub fn peek_cached(&self) -> Option<&S::Item> {
        match &self.peeked {
            PeekSlot::Item(item) => Some(item),
            PeekSlot::Empty | PeekSlot::Exhausted => None,
        }
    }
}

impl<S: Stream> Stream for Peekable<S> {
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let mut this = self.project();
        match this.peeked {
            PeekSlot::Item(_) => {
                let PeekSlot::Item(item) = std::mem::replace(this.peeked, PeekSlot::Empty) else {
                    unreachable!()
                };
                Poll::Ready(Some(item))
            }
            PeekSlot::Exhausted => Poll::Ready(None),
            PeekSlot::Empty => {
                let poll = this.stream.as_mut().poll_next(cx);
                if matches!(poll, Poll::Ready(None)) {
                    *this.peeked = PeekSlot::Exhausted;
                }
                poll
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.peeked {
            PeekSlot::Exhausted => (0, Some(0)),
            PeekSlot::Empty => self.stream.size_hint(),
            PeekSlot::Item(_) => {
                let (lo, hi) = self.stream.size_hint();
                (lo.saturating_add(1), hi.map(|h| h.saturating_add(1)))
            }
        }
    }
}

#[cfg(test)]
#[path = "peekable_inline_tests.rs"]
mod tests;
