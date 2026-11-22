#![allow(clippy::cast_possible_wrap)]
//! Chunking combinators for streams.
//!
//! `Chunks` yields fixed-size batches, while `ReadyChunks` yields whatever is
//! immediately available without waiting for a full batch.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items drained in a single poll.
///
/// Without this bound, large chunk capacities combined with always-ready
/// upstream streams can monopolize an executor turn.
const CHUNKS_COOPERATIVE_BUDGET: usize = 1024;

/// Reserve room for the next chunk before its first item, but never more
/// than one poll's budget of items: a chunk size such as `usize::MAX` (a
/// chunk per stream) must not allocate, or overflow, up front.
fn reserve_chunk<T>(items: &mut Vec<T>, cap: usize) {
    if items.capacity() == 0 {
        items.reserve(cap.min(CHUNKS_COOPERATIVE_BUDGET));
    }
}

/// A stream that yields items in fixed-size chunks.
///
/// Created by [`StreamExt::chunks`](super::StreamExt::chunks).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Chunks<S: Stream> {
    stream: S,
    items: Vec<S::Item>,
    cap: usize,
    done: bool,
}

struct ChunksProj<'a, S: Stream> {
    stream: Pin<&'a mut S>,
    items: &'a mut Vec<S::Item>,
    cap: &'a mut usize,
    done: &'a mut bool,
}

impl<S: Stream> Chunks<S> {
    #[allow(unsafe_code)]
    fn project(self: Pin<&mut Self>) -> ChunksProj<'_, S> {
        // SAFETY: `stream` is structurally pinned; remaining fields are never moved out as pinned.
        let this = unsafe { self.get_unchecked_mut() };
        ChunksProj {
            stream: unsafe { Pin::new_unchecked(&mut this.stream) },
            items: &mut this.items,
            cap: &mut this.cap,
            done: &mut this.done,
        }
    }

    /// Creates a new `Chunks` stream.
    #[inline]
    pub(crate) fn new(stream: S, cap: usize) -> Self {
        assert!(cap > 0, "chunk size must be non-zero");
        Self {
            stream,
            items: Vec::new(),
            cap,
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

impl<S> Stream for Chunks<S>
where
    S: Stream,
{
    type Item = Vec<S::Item>;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        // Terminal guard: once the upstream has signalled end-of-stream and the
        // final partial chunk has been yielded, never poll the (possibly
        // non-fused) upstream again — a restarting or panicking upstream must
        // not produce a phantom extra chunk. Consistent with map/filter/take.
        if *this.done {
            return Poll::Ready(None);
        }
        let mut drained_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    reserve_chunk(this.items, *this.cap);
                    this.items.push(item);
                    if this.items.len() >= *this.cap {
                        return Poll::Ready(Some(std::mem::take(this.items)));
                    }
                    drained_this_poll += 1;
                    if drained_this_poll >= CHUNKS_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.done = true;
                    if this.items.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(std::mem::take(this.items)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let buffered = self.items.len();
        let (lower, upper) = self.stream.size_hint();
        let total_lower = lower.saturating_add(buffered);
        let lower = total_lower.div_ceil(self.cap);
        let upper = upper.map(|u| u.saturating_add(buffered).div_ceil(self.cap));
        (lower, upper)
    }
}

/// A stream that yields chunks of immediately available items.
///
/// Created by [`StreamExt::ready_chunks`](super::StreamExt::ready_chunks).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct ReadyChunks<S: Stream> {
    stream: S,
    cap: usize,
    items: Vec<S::Item>,
    done: bool,
}

struct ReadyChunksProj<'a, S: Stream> {
    stream: Pin<&'a mut S>,
    cap: &'a mut usize,
    items: &'a mut Vec<S::Item>,
    done: &'a mut bool,
}

impl<S: Stream> ReadyChunks<S> {
    #[allow(unsafe_code)]
    fn project(self: Pin<&mut Self>) -> ReadyChunksProj<'_, S> {
        // SAFETY: `stream` is structurally pinned; remaining fields are never moved out as pinned.
        let this = unsafe { self.get_unchecked_mut() };
        ReadyChunksProj {
            stream: unsafe { Pin::new_unchecked(&mut this.stream) },
            cap: &mut this.cap,
            items: &mut this.items,
            done: &mut this.done,
        }
    }

    /// Creates a new `ReadyChunks` stream.
    #[inline]
    pub(crate) fn new(stream: S, cap: usize) -> Self {
        assert!(cap > 0, "chunk size must be non-zero");
        Self {
            stream,
            cap,
            items: Vec::new(),
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

impl<S> Stream for ReadyChunks<S>
where
    S: Stream,
{
    type Item = Vec<S::Item>;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        // Terminal guard: never re-poll a (possibly non-fused) upstream after
        // it has signalled end-of-stream. Consistent with map/filter/take.
        if *this.done {
            return Poll::Ready(None);
        }
        let cap = *this.cap;
        let mut drained_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    reserve_chunk(this.items, cap);
                    this.items.push(item);
                    if this.items.len() >= cap {
                        return Poll::Ready(Some(std::mem::take(this.items)));
                    }
                    drained_this_poll += 1;
                    if drained_this_poll >= CHUNKS_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.done = true;
                    if this.items.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(std::mem::take(this.items)));
                }
                Poll::Pending => {
                    if this.items.is_empty() {
                        return Poll::Pending;
                    }
                    return Poll::Ready(Some(std::mem::take(this.items)));
                }
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let buffered = self.items.len();
        let (lower_items, upper_items) = self.stream.size_hint();
        let total_lower_items = lower_items.saturating_add(buffered);
        let lower = if total_lower_items == 0 {
            0
        } else {
            total_lower_items.div_ceil(self.cap)
        };
        let upper =
            upper_items.map(|upper_items| upper_items.saturating_add(usize::from(buffered > 0)));
        (lower, upper)
    }
}

#[cfg(test)]
#[path = "chunks_inline_tests.rs"]
mod tests;
