//! Buffered combinators for streams of futures.
//!
//! `Buffered` preserves output order, while `BufferUnordered` yields results
//! as soon as futures complete.

use super::Stream;
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

struct BufferedEntry<Fut: Future> {
    fut: Fut,
    output: Option<Fut::Output>,
}

impl<Fut: Future> BufferedEntry<Fut> {
    fn new(fut: Fut) -> Self {
        Self { fut, output: None }
    }
}

/// A stream that buffers and polls futures, preserving order.
///
/// Created by [`StreamExt::buffered`](super::StreamExt::buffered).
#[must_use = "streams do nothing unless polled"]
pub struct Buffered<S>
where
    S: Stream,
    S::Item: Future,
{
    stream: S,
    in_flight: VecDeque<BufferedEntry<S::Item>>,
    limit: usize,
    done: bool,
}

impl<S> Buffered<S>
where
    S: Stream,
    S::Item: Future,
{
    /// Creates a new `Buffered` stream with the given limit.
    pub(crate) fn new(stream: S, limit: usize) -> Self {
        assert!(limit > 0, "buffered limit must be non-zero");
        Self {
            stream,
            in_flight: VecDeque::new(),
            limit,
            done: false,
        }
    }

    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> Unpin for Buffered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
}

impl<S> Stream for Buffered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
    type Item = <S::Item as Future>::Output;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        while !self.done && self.in_flight.len() < self.limit {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(fut)) => self.in_flight.push_back(BufferedEntry::new(fut)),
                Poll::Ready(None) => {
                    self.done = true;
                    break;
                }
                Poll::Pending => break,
            }
        }

        for entry in &mut self.in_flight {
            if entry.output.is_some() {
                continue;
            }

            match Pin::new(&mut entry.fut).poll(cx) {
                Poll::Ready(output) => entry.output = Some(output),
                Poll::Pending => {}
            }
        }

        if let Some(front) = self.in_flight.front_mut() {
            if front.output.is_some() {
                let mut entry = self.in_flight.pop_front().expect("front exists");
                return Poll::Ready(entry.output.take());
            }
        }

        if self.done && self.in_flight.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lower, upper) = self.stream.size_hint();
        let in_flight = self.in_flight.len();

        let lower = lower.saturating_add(in_flight);
        let upper = upper.and_then(|u| u.checked_add(in_flight));

        (lower, upper)
    }
}

/// A stream that buffers and polls futures, yielding results as they complete.
///
/// Created by [`StreamExt::buffer_unordered`](super::StreamExt::buffer_unordered).
#[must_use = "streams do nothing unless polled"]
pub struct BufferUnordered<S>
where
    S: Stream,
    S::Item: Future,
{
    stream: S,
    in_flight: VecDeque<S::Item>,
    limit: usize,
    done: bool,
}

impl<S> fmt::Debug for Buffered<S>
where
    S: Stream,
    S::Item: Future,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffered")
            .field("in_flight", &self.in_flight.len())
            .field("limit", &self.limit)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<S> fmt::Debug for BufferUnordered<S>
where
    S: Stream,
    S::Item: Future,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferUnordered")
            .field("in_flight", &self.in_flight.len())
            .field("limit", &self.limit)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<S> BufferUnordered<S>
where
    S: Stream,
    S::Item: Future,
{
    /// Creates a new `BufferUnordered` stream with the given limit.
    pub(crate) fn new(stream: S, limit: usize) -> Self {
        assert!(limit > 0, "buffer_unordered limit must be non-zero");
        Self {
            stream,
            in_flight: VecDeque::new(),
            limit,
            done: false,
        }
    }

    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> Unpin for BufferUnordered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
}

impl<S> Stream for BufferUnordered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
    type Item = <S::Item as Future>::Output;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        while !self.done && self.in_flight.len() < self.limit {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(fut)) => self.in_flight.push_back(fut),
                Poll::Ready(None) => {
                    self.done = true;
                    break;
                }
                Poll::Pending => break,
            }
        }

        let len = self.in_flight.len();
        for _ in 0..len {
            let mut fut = self.in_flight.pop_front().expect("length checked");
            match Pin::new(&mut fut).poll(cx) {
                Poll::Ready(output) => return Poll::Ready(Some(output)),
                Poll::Pending => self.in_flight.push_back(fut),
            }
        }

        if self.done && self.in_flight.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lower, upper) = self.stream.size_hint();
        let in_flight = self.in_flight.len();

        let lower = lower.saturating_add(in_flight);
        let upper = upper.and_then(|u| u.checked_add(in_flight));

        (lower, upper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::iter;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    #[test]
    fn buffered_preserves_order() {
        let stream = iter(vec![
            std::future::ready(1),
            std::future::ready(2),
            std::future::ready(3),
        ]);
        let mut stream = Buffered::new(stream, 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(1))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(2))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(3))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn buffer_unordered_yields_all() {
        let stream = iter(vec![
            std::future::ready(1),
            std::future::ready(2),
            std::future::ready(3),
        ]);
        let mut stream = BufferUnordered::new(stream, 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut items = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => items.push(item),
                Poll::Ready(None) => break,
                Poll::Pending => {}
            }
        }

        items.sort_unstable();
        assert_eq!(items, vec![1, 2, 3]);
    }
}
