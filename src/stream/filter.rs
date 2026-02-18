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
    use crate::stream::{StreamExt, iter};
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

    #[test]
    fn filter_empty_stream() {
        init_test("filter_empty_stream");
        let mut stream = Filter::new(iter(Vec::<i32>::new()), |_: &i32| true);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "empty done", "Poll::Ready(None)", poll);
        crate::test_complete!("filter_empty_stream");
    }

    #[test]
    fn filter_all_accepted() {
        init_test("filter_all_accepted");
        let mut stream = Filter::new(iter(vec![2, 4, 6]), |&x: &i32| x % 2 == 0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut collected = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(v)) => collected.push(v),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("unexpected Pending"),
            }
        }
        assert_eq!(collected, vec![2, 4, 6]);
        crate::test_complete!("filter_all_accepted");
    }

    #[test]
    fn filter_stateful_predicate() {
        init_test("filter_stateful_predicate");
        let mut count = 0usize;
        let mut stream = Filter::new(iter(vec![10, 20, 30, 40, 50]), move |_: &i32| {
            count += 1;
            count <= 3
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut collected = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(v)) => collected.push(v),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("unexpected Pending"),
            }
        }
        // Predicate accepts first 3 calls, rejects the rest
        assert_eq!(collected, vec![10, 20, 30]);
        crate::test_complete!("filter_stateful_predicate");
    }

    #[test]
    fn filter_accessors() {
        init_test("filter_accessors");
        let stream = Filter::new(iter(vec![1, 2, 3]), |_: &i32| true);
        assert_eq!(stream.get_ref().size_hint(), (3, Some(3)));

        let inner = stream.into_inner();
        assert_eq!(inner.size_hint(), (3, Some(3)));
        crate::test_complete!("filter_accessors");
    }

    #[test]
    fn filter_map_empty_stream() {
        init_test("filter_map_empty_stream");
        let mut stream = FilterMap::new(iter(Vec::<i32>::new()), |x: i32| Some(x));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "empty done", "Poll::Ready(None)", poll);
        crate::test_complete!("filter_map_empty_stream");
    }

    #[test]
    fn filter_map_all_none() {
        init_test("filter_map_all_none");
        let mut stream = FilterMap::new(iter(vec![1, 2, 3]), |_: i32| -> Option<i32> { None });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "all filtered", "Poll::Ready(None)", poll);
        crate::test_complete!("filter_map_all_none");
    }

    #[test]
    fn filter_map_alternating() {
        init_test("filter_map_alternating");
        let mut stream = FilterMap::new(
            iter(1..=6),
            |x: i32| {
                if x % 2 == 0 { Some(x * 10) } else { None }
            },
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut collected = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(v)) => collected.push(v),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("unexpected Pending"),
            }
        }
        assert_eq!(collected, vec![20, 40, 60]);
        crate::test_complete!("filter_map_alternating");
    }

    #[test]
    fn filter_map_type_change() {
        init_test("filter_map_type_change");
        let mut stream = FilterMap::new(iter(vec![1, 2, 3]), |x: i32| Some(format!("v{x}")));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some("v1".to_string())));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some("v2".to_string())));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some("v3".to_string())));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("filter_map_type_change");
    }

    #[test]
    fn filter_map_size_hint() {
        init_test("filter_map_size_hint");
        let stream = FilterMap::new(iter(vec![1, 2, 3, 4, 5]), |x: i32| Some(x));
        let hint = stream.size_hint();
        // Lower bound 0 (all could be filtered), upper preserved
        let ok = hint == (0, Some(5));
        crate::assert_with_log!(ok, "size hint", (0, Some(5)), hint);
        crate::test_complete!("filter_map_size_hint");
    }

    #[test]
    fn filter_map_stateful_closure() {
        init_test("filter_map_stateful_closure");
        let mut sum = 0i32;
        let mut stream = FilterMap::new(iter(vec![1, 2, 3, 4, 5]), move |x: i32| {
            sum += x;
            if sum > 6 { Some(sum) } else { None }
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut collected = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(v)) => collected.push(v),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("unexpected Pending"),
            }
        }
        // sum: 1, 3, 6, 10, 15 — yields when sum > 6: [10, 15]
        assert_eq!(collected, vec![10, 15]);
        crate::test_complete!("filter_map_stateful_closure");
    }

    #[test]
    fn filter_map_identity() {
        init_test("filter_map_identity");
        let mut stream = FilterMap::new(iter(vec![1, 2, 3, 4]), |x: i32| Some(x));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut collected = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(v)) => collected.push(v),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("unexpected Pending"),
            }
        }
        assert_eq!(collected, vec![1, 2, 3, 4]);
        crate::test_complete!("filter_map_identity");
    }

    #[test]
    fn filter_map_composition() {
        init_test("filter_map_composition");
        let mut stream = iter(vec!["1", "2", "x", "3", "4"])
            .filter_map(|s| s.parse::<i32>().ok())
            .filter_map(|n| if n % 2 == 1 { Some(n * 10) } else { None });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut collected = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(v)) => collected.push(v),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("unexpected Pending"),
            }
        }
        assert_eq!(collected, vec![10, 30]);
        crate::test_complete!("filter_map_composition");
    }

    #[test]
    fn filter_map_large_stream() {
        init_test("filter_map_large_stream");
        let data: Vec<i32> = (0..1000).collect();
        let mut stream = FilterMap::new(
            iter(data),
            |x: i32| {
                if x % 10 == 0 { Some(x) } else { None }
            },
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut collected = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(v)) => collected.push(v),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("unexpected Pending"),
            }
        }
        let expected: Vec<i32> = (0..1000).filter(|x| x % 10 == 0).collect();
        assert_eq!(collected, expected);
        crate::test_complete!("filter_map_large_stream");
    }

    #[test]
    fn filter_map_result_error_handling() {
        init_test("filter_map_result_error_handling");
        let mut stream = FilterMap::new(
            iter(vec![Ok(1), Err("boom"), Ok(2), Err("nope")]),
            |v: Result<i32, &str>| v.ok(),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut collected = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(v)) => collected.push(v),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("unexpected Pending"),
            }
        }
        assert_eq!(collected, vec![1, 2]);
        crate::test_complete!("filter_map_result_error_handling");
    }

    #[test]
    fn filter_map_accessors() {
        init_test("filter_map_accessors");
        let stream = FilterMap::new(iter(vec![1, 2]), |x: i32| Some(x));
        assert_eq!(stream.get_ref().size_hint(), (2, Some(2)));

        let inner = stream.into_inner();
        assert_eq!(inner.size_hint(), (2, Some(2)));
        crate::test_complete!("filter_map_accessors");
    }
}
