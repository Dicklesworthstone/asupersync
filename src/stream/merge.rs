//! Merge combinator for streams.
//!
//! The `Merge` combinator interleaves items from multiple streams, polling
//! them in round-robin order.

use super::Stream;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that merges multiple streams.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Merge<S> {
    streams: VecDeque<S>,
}

impl<S> Merge<S> {
    /// Creates a new `Merge` from the given streams.
    pub(crate) fn new(streams: impl IntoIterator<Item = S>) -> Self {
        Self {
            streams: streams.into_iter().collect(),
        }
    }

    /// Returns the number of active streams.
    #[must_use]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Returns true if there are no active streams.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Consumes the combinator, returning the remaining streams.
    #[must_use]
    pub fn into_inner(self) -> VecDeque<S> {
        self.streams
    }
}

impl<S: Unpin> Unpin for Merge<S> {}

impl<S> Stream for Merge<S>
where
    S: Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let len = self.streams.len();
        if len == 0 {
            return Poll::Ready(None);
        }

        for _ in 0..len {
            let mut stream = self.streams.pop_front().expect("length checked");

            match Pin::new(&mut stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.streams.push_back(stream);
                    return Poll::Ready(Some(item));
                }
                Poll::Ready(None) => {
                    // Stream exhausted; drop it.
                }
                Poll::Pending => {
                    self.streams.push_back(stream);
                }
            }
        }

        if self.streams.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut lower = 0usize;
        let mut upper = Some(0usize);

        for stream in &self.streams {
            let (l, u) = stream.size_hint();
            lower = lower.saturating_add(l);
            upper = match (upper, u) {
                (Some(total), Some(v)) => total.checked_add(v),
                _ => None,
            };
        }

        (lower, upper)
    }
}

/// Merge multiple streams into a single stream.
pub fn merge<S>(streams: impl IntoIterator<Item = S>) -> Merge<S>
where
    S: Stream,
{
    Merge::new(streams)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::{iter, StreamExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
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

    #[derive(Debug)]
    struct PendingEveryOther {
        items: Vec<i32>,
        index: usize,
        pending_next: bool,
    }

    impl PendingEveryOther {
        fn new(items: Vec<i32>) -> Self {
            Self {
                items,
                index: 0,
                pending_next: true,
            }
        }
    }

    impl Stream for PendingEveryOther {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<i32>> {
            if self.pending_next {
                self.pending_next = false;
                return Poll::Pending;
            }

            if self.index >= self.items.len() {
                return Poll::Ready(None);
            }

            let item = self.items[self.index];
            self.index += 1;
            self.pending_next = true;
            Poll::Ready(Some(item))
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.items.len().saturating_sub(self.index);
            (remaining, Some(remaining))
        }
    }

    #[derive(Debug)]
    struct UnknownUpper {
        remaining: usize,
    }

    impl UnknownUpper {
        fn new(remaining: usize) -> Self {
            Self { remaining }
        }
    }

    impl Stream for UnknownUpper {
        type Item = usize;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<usize>> {
            if self.remaining == 0 {
                return Poll::Ready(None);
            }
            self.remaining -= 1;
            Poll::Ready(Some(self.remaining))
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (0, None)
        }
    }

    #[derive(Debug)]
    struct LaggyStream {
        source: usize,
        items: Vec<i32>,
        index: usize,
        pending_budget: usize,
        pending_left: usize,
    }

    impl LaggyStream {
        fn new(source: usize, items: Vec<i32>, pending_budget: usize) -> Self {
            Self {
                source,
                items,
                index: 0,
                pending_budget,
                pending_left: pending_budget,
            }
        }
    }

    impl Stream for LaggyStream {
        type Item = (usize, i32);

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.index >= self.items.len() {
                return Poll::Ready(None);
            }

            if self.pending_left > 0 {
                self.pending_left -= 1;
                return Poll::Pending;
            }

            let item = self.items[self.index];
            self.index += 1;
            self.pending_left = self.pending_budget;
            Poll::Ready(Some((self.source, item)))
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.items.len().saturating_sub(self.index);
            (remaining, Some(remaining))
        }
    }

    #[derive(Debug)]
    struct DropStream {
        source: usize,
        dropped: Arc<AtomicUsize>,
    }

    impl DropStream {
        fn new(source: usize, dropped: Arc<AtomicUsize>) -> Self {
            Self { source, dropped }
        }
    }

    impl Drop for DropStream {
        fn drop(&mut self) {
            let count = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::info!(
                source = self.source,
                dropped = count,
                "merge stream dropped"
            );
        }
    }

    impl Stream for DropStream {
        type Item = (usize, i32);

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (0, None)
        }
    }

    type BoxedStream<T> = Box<dyn Stream<Item = T> + Unpin>;

    fn boxed_stream<T, S>(stream: S) -> BoxedStream<T>
    where
        S: Stream<Item = T> + Unpin + 'static,
    {
        Box::new(stream)
    }

    #[test]
    fn merge_yields_all_items() {
        init_test("merge_yields_all_items");
        let mut stream = merge([iter(vec![1, 3, 5]), iter(vec![2, 4, 6])]);
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
        let ok = items == vec![1, 2, 3, 4, 5, 6];
        crate::assert_with_log!(ok, "merged items", vec![1, 2, 3, 4, 5, 6], items);
        crate::test_complete!("merge_yields_all_items");
    }

    #[test]
    fn merge_round_robin_order() {
        init_test("merge_round_robin_order");
        let mut stream = merge([iter(vec![1, 3, 5]), iter(vec![2, 4, 6])]);
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

        let ok = items == vec![1, 2, 3, 4, 5, 6];
        crate::assert_with_log!(ok, "round robin order", vec![1, 2, 3, 4, 5, 6], items);
        crate::test_complete!("merge_round_robin_order");
    }

    #[test]
    fn merge_drops_exhausted_streams() {
        init_test("merge_drops_exhausted_streams");
        let mut stream = merge([iter(vec![10]), iter(vec![1, 2])]);
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

        let ok = items == vec![10, 1, 2];
        crate::assert_with_log!(ok, "exhausted drop", vec![10, 1, 2], items);
        crate::test_complete!("merge_drops_exhausted_streams");
    }

    #[test]
    fn merge_pending_streams_make_progress() {
        init_test("merge_pending_streams_make_progress");
        let streams: Vec<Box<dyn Stream<Item = i32> + Unpin>> = vec![
            Box::new(PendingEveryOther::new(vec![1, 3, 5])),
            Box::new(iter(vec![2, 4, 6])),
        ];
        let mut stream = merge(streams);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut items = Vec::new();
        let mut pending_count = 0usize;
        let mut polls = 0usize;
        loop {
            polls += 1;
            if polls > 64 {
                break;
            }
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => items.push(item),
                Poll::Ready(None) => break,
                Poll::Pending => pending_count += 1,
            }
        }

        items.sort_unstable();
        let ok = items == vec![1, 2, 3, 4, 5, 6];
        crate::assert_with_log!(ok, "merged items", vec![1, 2, 3, 4, 5, 6], items);
        crate::assert_with_log!(pending_count > 0, "pending seen", true, pending_count > 0);
        crate::test_complete!("merge_pending_streams_make_progress");
    }

    #[test]
    fn merge_size_hint_unknown_upper() {
        init_test("merge_size_hint_unknown_upper");
        let streams: Vec<Box<dyn Stream<Item = usize> + Unpin>> = vec![
            Box::new(UnknownUpper::new(3)),
            Box::new(iter(vec![1usize, 2])),
        ];
        let stream = merge(streams);
        let hint = stream.size_hint();
        let ok = hint == (2, None);
        crate::assert_with_log!(ok, "size hint", (2, None::<usize>), hint);
        crate::test_complete!("merge_size_hint_unknown_upper");
    }

    #[test]
    fn merge_empty() {
        init_test("merge_empty");
        let mut stream: Merge<crate::stream::Iter<std::vec::IntoIter<i32>>> = merge([]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll empty", "Poll::Ready(None)", poll);
        crate::test_complete!("merge_empty");
    }

    #[test]
    fn merge_three_streams_all_items_once() {
        init_test("merge_three_streams_all_items_once");
        let streams: Vec<BoxedStream<(usize, i32)>> = vec![
            boxed_stream(iter(vec![1, 2]).map(|v| (0usize, v))),
            boxed_stream(iter(vec![10, 20]).map(|v| (1usize, v))),
            boxed_stream(iter(vec![100, 200]).map(|v| (2usize, v))),
        ];
        let mut stream = merge(streams);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut items = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => {
                    tracing::info!(source = item.0, value = item.1, "merge item");
                    items.push(item);
                }
                Poll::Ready(None) => break,
                Poll::Pending => {}
            }
        }

        items.sort_unstable();
        let expected = vec![(0, 1), (0, 2), (1, 10), (1, 20), (2, 100), (2, 200)];
        let ok = items == expected;
        tracing::info!(total = items.len(), "merge total");
        crate::assert_with_log!(ok, "all items once", expected, items);
        crate::test_complete!("merge_three_streams_all_items_once");
    }

    #[test]
    fn merge_empty_stream_passes_through_other() {
        init_test("merge_empty_stream_passes_through_other");
        let streams: Vec<BoxedStream<(usize, i32)>> = vec![
            boxed_stream(iter(Vec::<i32>::new()).map(|v| (0usize, v))),
            boxed_stream(iter(vec![1, 2, 3]).map(|v| (1usize, v))),
        ];
        let mut stream = merge(streams);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut items = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => {
                    tracing::info!(source = item.0, value = item.1, "merge item");
                    items.push(item);
                }
                Poll::Ready(None) => break,
                Poll::Pending => {}
            }
        }

        let expected = vec![(1, 1), (1, 2), (1, 3)];
        let ok = items == expected;
        tracing::info!(total = items.len(), "merge total");
        crate::assert_with_log!(ok, "pass through", expected, items);
        crate::test_complete!("merge_empty_stream_passes_through_other");
    }

    #[test]
    fn merge_both_streams_empty() {
        init_test("merge_both_streams_empty");
        let streams: Vec<BoxedStream<(usize, i32)>> = vec![
            boxed_stream(iter(Vec::<i32>::new()).map(|v| (0usize, v))),
            boxed_stream(iter(Vec::<i32>::new()).map(|v| (1usize, v))),
        ];
        let mut stream = merge(streams);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "both empty", "Poll::Ready(None)", poll);
        crate::test_complete!("merge_both_streams_empty");
    }

    #[test]
    fn merge_error_item_propagates() {
        init_test("merge_error_item_propagates");
        let streams: Vec<BoxedStream<(usize, Result<i32, &'static str>)>> = vec![
            boxed_stream(iter(vec![Ok(1), Err("boom"), Ok(2)]).map(|v| (0usize, v))),
            boxed_stream(iter(vec![Ok(10)]).map(|v| (1usize, v))),
        ];
        let mut stream = merge(streams);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut items = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => {
                    tracing::info!(source = item.0, value = ?item.1, "merge item");
                    items.push(item);
                }
                Poll::Ready(None) => break,
                Poll::Pending => {}
            }
        }

        let has_error = items.iter().any(|(_, v)| v.is_err());
        let ok_count = items.iter().filter(|(_, v)| v.is_ok()).count();
        tracing::info!(total = items.len(), ok_count, has_error, "merge totals");
        crate::assert_with_log!(has_error, "error observed", true, has_error);
        crate::assert_with_log!(ok_count == 3, "ok count", 3usize, ok_count);
        crate::test_complete!("merge_error_item_propagates");
    }

    #[test]
    fn merge_size_hint_sum() {
        init_test("merge_size_hint_sum");
        let stream = merge([iter(vec![1, 2, 3]), iter(vec![4, 5])]);
        let hint = stream.size_hint();
        let ok = hint == (5, Some(5));
        crate::assert_with_log!(ok, "size hint sum", (5, Some(5)), hint);
        crate::test_complete!("merge_size_hint_sum");
    }

    #[test]
    fn merge_drop_cancels_streams() {
        init_test("merge_drop_cancels_streams");
        let dropped = Arc::new(AtomicUsize::new(0));
        let streams = vec![
            DropStream::new(0, dropped.clone()),
            DropStream::new(1, dropped.clone()),
        ];
        let stream = merge(streams);
        drop(stream);
        let count = dropped.load(Ordering::Relaxed);
        crate::assert_with_log!(count == 2, "drop count", 2usize, count);
        crate::test_complete!("merge_drop_cancels_streams");
    }

    #[test]
    fn merge_fairness_fast_slow() {
        init_test("merge_fairness_fast_slow");
        let streams: Vec<BoxedStream<(usize, i32)>> = vec![
            boxed_stream(iter(vec![1, 2, 3, 4, 5]).map(|v| (0usize, v))),
            boxed_stream(LaggyStream::new(1, vec![10, 20], 3)),
        ];
        let mut stream = merge(streams);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut items = Vec::new();
        let mut polls = 0usize;
        while polls < 128 {
            polls += 1;
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => {
                    tracing::info!(source = item.0, value = item.1, "merge item");
                    items.push(item);
                }
                Poll::Ready(None) => break,
                Poll::Pending => {}
            }
        }

        let fast_count = items.iter().filter(|(s, _)| *s == 0).count();
        let slow_count = items.iter().filter(|(s, _)| *s == 1).count();
        let first_slow = items.iter().position(|(s, _)| *s == 1);
        tracing::info!(fast_count, slow_count, "merge totals");
        crate::assert_with_log!(fast_count == 5, "fast count", 5usize, fast_count);
        crate::assert_with_log!(slow_count == 2, "slow count", 2usize, slow_count);
        let ok = first_slow.is_some() && first_slow.unwrap_or(0) < items.len().saturating_sub(1);
        crate::assert_with_log!(ok, "slow not starved", true, ok);
        crate::test_complete!("merge_fairness_fast_slow");
    }

    #[test]
    fn merge_interleaving_pending_alternates() {
        init_test("merge_interleaving_pending_alternates");
        let streams: Vec<BoxedStream<(usize, i32)>> = vec![
            boxed_stream(PendingEveryOther::new(vec![1, 3, 5]).map(|v| (0usize, v))),
            boxed_stream(PendingEveryOther::new(vec![2, 4, 6]).map(|v| (1usize, v))),
        ];
        let mut stream = merge(streams);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut items = Vec::new();
        let mut polls = 0usize;
        while polls < 128 {
            polls += 1;
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => {
                    tracing::info!(source = item.0, value = item.1, "merge item");
                    items.push(item);
                }
                Poll::Ready(None) => break,
                Poll::Pending => {}
            }
        }

        let transitions = items.windows(2).filter(|w| w[0].0 != w[1].0).count();
        let total = items.len();
        tracing::info!(total, transitions, "merge totals");
        crate::assert_with_log!(total == 6, "total items", 6usize, total);
        crate::assert_with_log!(transitions > 0, "has interleaving", true, transitions > 0);
        crate::test_complete!("merge_interleaving_pending_alternates");
    }

    #[test]
    fn merge_backpressure_resume_no_loss() {
        init_test("merge_backpressure_resume_no_loss");
        let streams: Vec<BoxedStream<(usize, i32)>> = vec![
            boxed_stream(iter(vec![1, 3, 5]).map(|v| (0usize, v))),
            boxed_stream(iter(vec![2, 4, 6]).map(|v| (1usize, v))),
        ];
        let mut stream = merge(streams);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut items = Vec::new();
        for _ in 0..2 {
            if let Poll::Ready(Some(item)) = Pin::new(&mut stream).poll_next(&mut cx) {
                tracing::info!(source = item.0, value = item.1, "merge item");
                items.push(item);
            }
        }

        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => {
                    tracing::info!(source = item.0, value = item.1, "merge item");
                    items.push(item);
                }
                Poll::Ready(None) => break,
                Poll::Pending => {}
            }
        }

        items.sort_unstable();
        let expected = vec![(0, 1), (0, 3), (0, 5), (1, 2), (1, 4), (1, 6)];
        tracing::info!(total = items.len(), "merge total");
        crate::assert_with_log!(items == expected, "no loss", expected, items);
        crate::test_complete!("merge_backpressure_resume_no_loss");
    }
}
