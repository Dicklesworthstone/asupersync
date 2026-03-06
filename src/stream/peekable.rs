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
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            peeked: PeekSlot::Empty,
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
    ///
    /// Note: any peeked item is lost.
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Peeks at the next item without consuming it.
    ///
    /// Returns `Poll::Ready(Some(&item))` if the next item is available,
    /// `Poll::Ready(None)` if the stream is exhausted, or `Poll::Pending`
    /// if the next item is not yet ready.
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

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let mut this = self.project();
        match std::mem::replace(this.peeked, PeekSlot::Empty) {
            PeekSlot::Item(item) => Poll::Ready(Some(item)),
            PeekSlot::Exhausted => Poll::Ready(None),
            PeekSlot::Empty => this.stream.as_mut().poll_next(cx),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lo, hi) = self.stream.size_hint();
        let peek_len = usize::from(matches!(self.peeked, PeekSlot::Item(_)));
        (
            lo.saturating_add(peek_len),
            hi.map(|h| h.saturating_add(peek_len)),
        )
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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn peek_then_consume() {
        init_test("peek_then_consume");
        let mut stream = Peekable::new(iter(vec![1, 2, 3]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Peek at the first item.
        let peeked = Pin::new(&mut stream).poll_peek(&mut cx);
        assert_eq!(peeked, Poll::Ready(Some(&1)));

        // Peek again — still the same item.
        let peeked = Pin::new(&mut stream).poll_peek(&mut cx);
        assert_eq!(peeked, Poll::Ready(Some(&1)));

        // Consume: returns the peeked item.
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(1)));

        // Next item.
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(2)));

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(3)));

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("peek_then_consume");
    }

    #[test]
    fn peek_at_end() {
        init_test("peek_at_end");
        let mut stream = Peekable::new(iter(Vec::<i32>::new()));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let peeked = Pin::new(&mut stream).poll_peek(&mut cx);
        assert_eq!(peeked, Poll::Ready(None));

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("peek_at_end");
    }

    #[test]
    fn consume_without_peeking() {
        init_test("consume_without_peeking");
        let mut stream = Peekable::new(iter(vec![10, 20]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(10)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(20)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("consume_without_peeking");
    }

    #[test]
    fn peek_cached_before_and_after() {
        init_test("peek_cached_before_and_after");
        let mut stream = Peekable::new(iter(vec![42]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Nothing cached yet.
        assert!(stream.peek_cached().is_none());

        // Peek populates the cache.
        let _ = Pin::new(&mut stream).poll_peek(&mut cx);
        assert_eq!(stream.peek_cached(), Some(&42));

        // Consuming clears the cache.
        let _ = Pin::new(&mut stream).poll_next(&mut cx);
        assert!(stream.peek_cached().is_none());
        crate::test_complete!("peek_cached_before_and_after");
    }

    #[test]
    fn size_hint_accounts_for_peeked() {
        init_test("size_hint_accounts_for_peeked");
        let mut stream = Peekable::new(iter(vec![1, 2, 3]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(stream.size_hint(), (3, Some(3)));

        // Peek consumes from underlying but caches.
        let _ = Pin::new(&mut stream).poll_peek(&mut cx);
        // Underlying now has (2, Some(2)) but we have 1 peeked → (3, Some(3))
        assert_eq!(stream.size_hint(), (3, Some(3)));

        // Consume the peeked item.
        let _ = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(stream.size_hint(), (2, Some(2)));
        crate::test_complete!("size_hint_accounts_for_peeked");
    }

    #[test]
    fn interleaved_peek_and_next() {
        init_test("interleaved_peek_and_next");
        let mut stream = Peekable::new(iter(vec![1, 2, 3, 4]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Peek 1.
        assert_eq!(
            Pin::new(&mut stream).poll_peek(&mut cx),
            Poll::Ready(Some(&1))
        );
        // Consume 1.
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );
        // Consume 2 directly.
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(2))
        );
        // Peek 3.
        assert_eq!(
            Pin::new(&mut stream).poll_peek(&mut cx),
            Poll::Ready(Some(&3))
        );
        // Peek 3 again.
        assert_eq!(
            Pin::new(&mut stream).poll_peek(&mut cx),
            Poll::Ready(Some(&3))
        );
        // Consume 3.
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(3))
        );
        // Consume 4.
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(4))
        );
        // Done.
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("interleaved_peek_and_next");
    }

    #[test]
    fn peekable_accessors() {
        init_test("peekable_accessors");
        let mut stream = Peekable::new(iter(vec![1, 2]));
        let _ref = stream.get_ref();
        let _mut_ref = stream.get_mut();
        let inner = stream.into_inner();
        let mut inner = inner;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(
            Pin::new(&mut inner).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );
        crate::test_complete!("peekable_accessors");
    }

    #[test]
    fn peekable_debug() {
        let stream = Peekable::new(iter(vec![1, 2, 3]));
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("Peekable"));
    }
}
