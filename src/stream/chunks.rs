//! Chunking combinators for streams.
//!
//! `Chunks` yields fixed-size batches, while `ReadyChunks` yields whatever is
//! immediately available without waiting for a full batch.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that yields items in fixed-size chunks.
///
/// Created by [`StreamExt::chunks`](super::StreamExt::chunks).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Chunks<S: Stream> {
    stream: S,
    items: Vec<S::Item>,
    cap: usize,
}

impl<S: Stream> Chunks<S> {
    /// Creates a new `Chunks` stream.
    pub(crate) fn new(stream: S, cap: usize) -> Self {
        assert!(cap > 0, "chunk size must be non-zero");
        Self {
            stream,
            items: Vec::with_capacity(cap),
            cap,
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

impl<S: Stream + Unpin> Unpin for Chunks<S> {}

impl<S> Stream for Chunks<S>
where
    S: Stream + Unpin,
{
    type Item = Vec<S::Item>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.items.push(item);
                    if self.items.len() >= self.cap {
                        return Poll::Ready(Some(std::mem::take(&mut self.items)));
                    }
                }
                Poll::Ready(None) => {
                    if self.items.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(std::mem::take(&mut self.items)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let buffered = self.items.len();
        let (lower, upper) = self.stream.size_hint();
        let total_lower = lower.saturating_add(buffered);
        let lower = total_lower / self.cap;
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
}

impl<S: Stream> ReadyChunks<S> {
    /// Creates a new `ReadyChunks` stream.
    pub(crate) fn new(stream: S, cap: usize) -> Self {
        assert!(cap > 0, "chunk size must be non-zero");
        Self { stream, cap }
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

impl<S: Stream + Unpin> Unpin for ReadyChunks<S> {}

impl<S> Stream for ReadyChunks<S>
where
    S: Stream + Unpin,
{
    type Item = Vec<S::Item>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut items = Vec::with_capacity(self.cap);

        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    items.push(item);
                    if items.len() >= self.cap {
                        return Poll::Ready(Some(items));
                    }
                }
                Poll::Ready(None) => {
                    if items.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(items));
                }
                Poll::Pending => {
                    if items.is_empty() {
                        return Poll::Pending;
                    }
                    return Poll::Ready(Some(items));
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (_, upper) = self.stream.size_hint();
        let upper = upper.map(|u| u.div_ceil(self.cap));
        (0, upper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::iter;
    use crate::stream::StreamExt;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn chunks_groups_items() {
        init_test("chunks_groups_items");
        let mut stream = Chunks::new(iter(vec![1, 2, 3, 4, 5, 6, 7]), 3);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref chunk)) if chunk == &vec![1, 2, 3]);
        crate::assert_with_log!(ok, "chunk 1", "Poll::Ready(Some([1,2,3]))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref chunk)) if chunk == &vec![4, 5, 6]);
        crate::assert_with_log!(ok, "chunk 2", "Poll::Ready(Some([4,5,6]))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref chunk)) if chunk == &vec![7]);
        crate::assert_with_log!(ok, "chunk 3", "Poll::Ready(Some([7]))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("chunks_groups_items");
    }

    struct PendingOnce {
        yielded: bool,
        pending: bool,
    }

    impl Stream for PendingOnce {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if !self.pending {
                self.pending = true;
                return Poll::Pending;
            }
            if !self.yielded {
                self.yielded = true;
                return Poll::Ready(Some(1));
            }
            Poll::Ready(None)
        }
    }

    #[test]
    fn ready_chunks_returns_immediate_items() {
        init_test("ready_chunks_returns_immediate_items");
        let stream = iter(vec![1, 2]).chain(PendingOnce {
            yielded: false,
            pending: false,
        });
        let mut stream = ReadyChunks::new(stream, 10);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref chunk)) if chunk == &vec![1, 2]);
        crate::assert_with_log!(ok, "ready chunk", "Poll::Ready(Some([1,2]))", poll);
        crate::test_complete!("ready_chunks_returns_immediate_items");
    }
}
