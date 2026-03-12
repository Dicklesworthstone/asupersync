//! Filter combinator for streams.
//!
//! The `Filter` combinator yields only items that match a predicate.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for rejected items drained in a single poll.
///
/// Without this cap, an always-ready upstream stream can monopolize the
/// executor forever if the predicate or mapper keeps rejecting items.
const FILTER_REJECTION_BUDGET: usize = 1024;

/// A stream that yields only items matching a predicate.
///
/// Created by [`StreamExt::filter`](super::StreamExt::filter).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Filter<S, P> {
    #[pin]
    stream: S,
    predicate: P,
    exhausted: bool,
}

impl<S, P> Filter<S, P> {
    /// Creates a new `Filter` stream.
    pub(crate) fn new(stream: S, predicate: P) -> Self {
        Self {
            stream,
            predicate,
            exhausted: false,
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

impl<S, P> Stream for Filter<S, P>
where
    S: Stream,
    P: FnMut(&S::Item) -> bool,
{
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let mut this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }
        let mut rejected_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if (this.predicate)(&item) {
                        return Poll::Ready(Some(item));
                    }
                    rejected_this_poll += 1;
                    if rejected_this_poll >= FILTER_REJECTION_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.exhausted = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            return (0, Some(0));
        }
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
#[pin_project]
pub struct FilterMap<S, F> {
    #[pin]
    stream: S,
    f: F,
    exhausted: bool,
}

impl<S, F> FilterMap<S, F> {
    /// Creates a new `FilterMap` stream.
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            exhausted: false,
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

impl<S, F, T> Stream for FilterMap<S, F>
where
    S: Stream,
    F: FnMut(S::Item) -> Option<T>,
{
    type Item = T;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }
        let mut rejected_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if let Some(result) = (this.f)(item) {
                        return Poll::Ready(Some(result));
                    }
                    rejected_this_poll += 1;
                    if rejected_this_poll >= FILTER_REJECTION_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.exhausted = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            return (0, Some(0));
        }
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    struct TrackWaker(Arc<AtomicBool>);

    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[derive(Debug, Default)]
    struct AlwaysReadyCounter {
        next: usize,
    }

    impl Stream for AlwaysReadyCounter {
        type Item = usize;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let item = self.next;
            self.next = self.next.saturating_add(1);
            Poll::Ready(Some(item))
        }
    }

    #[derive(Debug)]
    struct OneThenNoneThenPanics {
        item: Option<i32>,
        completed: bool,
        polls: Arc<AtomicUsize>,
    }

    impl OneThenNoneThenPanics {
        fn new(item: i32, polls: Arc<AtomicUsize>) -> Self {
            Self {
                item: Some(item),
                completed: false,
                polls,
            }
        }
    }

    impl Stream for OneThenNoneThenPanics {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            assert!(!self.completed, "inner stream repolled after completion");
            self.polls.fetch_add(1, Ordering::SeqCst);
            if let Some(item) = self.item.take() {
                Poll::Ready(Some(item))
            } else {
                self.completed = true;
                Poll::Ready(None)
            }
        }
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

    #[test]
    fn filter_debug() {
        #[allow(clippy::trivially_copy_pass_by_ref)]
        fn pred(x: &i32) -> bool {
            *x > 1
        }
        let stream = Filter::new(iter(vec![1, 2, 3]), pred as fn(&i32) -> bool);
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("Filter"));
    }

    #[test]
    fn filter_map_debug() {
        #[allow(clippy::unnecessary_wraps)]
        fn mapper(x: i32) -> Option<i32> {
            Some(x)
        }
        let stream = FilterMap::new(iter(vec![1, 2]), mapper as fn(i32) -> Option<i32>);
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("FilterMap"));
    }

    #[test]
    fn filter_yields_after_rejection_budget_on_always_ready_stream() {
        init_test("filter_yields_after_rejection_budget_on_always_ready_stream");
        let wake_flag = Arc::new(AtomicBool::new(false));
        let waker: Waker = Arc::new(TrackWaker(Arc::clone(&wake_flag))).into();
        let mut cx = Context::from_waker(&waker);
        let accept_after = FILTER_REJECTION_BUDGET + 1;
        let mut stream = Filter::new(AlwaysReadyCounter::default(), move |item: &usize| {
            *item == accept_after
        });

        let first = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(first, Poll::Pending);
        assert!(wake_flag.load(Ordering::SeqCst));

        let second = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(second, Poll::Ready(Some(accept_after)));
        crate::test_complete!("filter_yields_after_rejection_budget_on_always_ready_stream");
    }

    #[test]
    fn filter_map_yields_after_rejection_budget_on_always_ready_stream() {
        init_test("filter_map_yields_after_rejection_budget_on_always_ready_stream");
        let wake_flag = Arc::new(AtomicBool::new(false));
        let waker: Waker = Arc::new(TrackWaker(Arc::clone(&wake_flag))).into();
        let mut cx = Context::from_waker(&waker);
        let accept_after = FILTER_REJECTION_BUDGET + 1;
        let mut stream = FilterMap::new(AlwaysReadyCounter::default(), move |item: usize| {
            (item == accept_after).then_some(item)
        });

        let first = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(first, Poll::Pending);
        assert!(wake_flag.load(Ordering::SeqCst));

        let second = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(second, Poll::Ready(Some(accept_after)));
        crate::test_complete!("filter_map_yields_after_rejection_budget_on_always_ready_stream");
    }

    #[test]
    fn filter_does_not_repoll_exhausted_upstream_after_rejected_terminal_pass() {
        init_test("filter_does_not_repoll_exhausted_upstream_after_rejected_terminal_pass");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut stream = Filter::new(
            OneThenNoneThenPanics::new(7, Arc::clone(&polls)),
            |_: &i32| false,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.size_hint(), (0, Some(0)));
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        crate::test_complete!(
            "filter_does_not_repoll_exhausted_upstream_after_rejected_terminal_pass"
        );
    }

    #[test]
    fn filter_map_does_not_repoll_exhausted_upstream_after_rejected_terminal_pass() {
        init_test("filter_map_does_not_repoll_exhausted_upstream_after_rejected_terminal_pass");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut stream = FilterMap::new(OneThenNoneThenPanics::new(7, Arc::clone(&polls)), |_| {
            None::<i32>
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.size_hint(), (0, Some(0)));
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        crate::test_complete!(
            "filter_map_does_not_repoll_exhausted_upstream_after_rejected_terminal_pass"
        );
    }
}
