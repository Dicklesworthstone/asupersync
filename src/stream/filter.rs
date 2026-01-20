//! Filter combinator for streams.
//!
//! The `Filter` combinator yields only items that match a predicate.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that yields only items matching a predicate.
///
/// Created by [`StreamExt::filter`](super::StreamExt::filter).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Filter<S, P> {
    stream: S,
    predicate: P,
}

impl<S, P> Filter<S, P> {
    /// Creates a new `Filter` stream.
    pub(crate) fn new(stream: S, predicate: P) -> Self {
        Self { stream, predicate }
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

impl<S: Unpin, P> Unpin for Filter<S, P> {}

impl<S, P> Stream for Filter<S, P>
where
    S: Stream + Unpin,
    P: FnMut(&S::Item) -> bool,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if (self.predicate)(&item) {
                        return Poll::Ready(Some(item));
                    }
                    // Item filtered out, continue to next
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (_, upper) = self.stream.size_hint();
        // Lower bound is 0 since all items might be filtered
        (0, upper)
    }
}

/// A stream that yields only items matching an async predicate.
///
/// Created by [`StreamExt::filter_map`](super::StreamExt::filter_map).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct FilterMap<S, F> {
    stream: S,
    f: F,
}

impl<S, F> FilterMap<S, F> {
    /// Creates a new `FilterMap` stream.
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self { stream, f }
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

impl<S: Unpin, F> Unpin for FilterMap<S, F> {}

impl<S, F, T> Stream for FilterMap<S, F>
where
    S: Stream + Unpin,
    F: FnMut(S::Item) -> Option<T>,
{
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if let Some(result) = (self.f)(item) {
                        return Poll::Ready(Some(result));
                    }
                    // Item filtered out, continue to next
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (_, upper) = self.stream.size_hint();
        // Lower bound is 0 since all items might be filtered
        (0, upper)
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
    fn filter_keeps_matching() {
        init_test("filter_keeps_matching");
        let mut stream = Filter::new(iter(vec![1, 2, 3, 4, 5, 6]), |&x: &i32| x % 2 == 0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(4)));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some(4))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(6)));
        crate::assert_with_log!(ok, "poll 3", "Poll::Ready(Some(6))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("filter_keeps_matching");
    }

    #[test]
    fn filter_all_rejected() {
        init_test("filter_all_rejected");
        let mut stream = Filter::new(iter(vec![1, 3, 5]), |&x: &i32| x % 2 == 0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("filter_all_rejected");
    }

    #[test]
    fn filter_map_transforms_and_filters() {
        init_test("filter_map_transforms_and_filters");
        let mut stream = FilterMap::new(iter(vec!["1", "two", "3", "four"]), |s: &str| {
            s.parse::<i32>().ok()
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(1))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(3)));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some(3))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("filter_map_transforms_and_filters");
    }

    #[test]
    fn filter_size_hint() {
        init_test("filter_size_hint");
        let stream = Filter::new(iter(vec![1, 2, 3]), |_: &i32| true);
        // Lower bound is 0, upper is preserved
        let hint = stream.size_hint();
        let ok = hint == (0, Some(3));
        crate::assert_with_log!(ok, "size hint", (0, Some(3)), hint);
        crate::test_complete!("filter_size_hint");
    }
}
