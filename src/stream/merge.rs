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
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<i32>> {
            if self.remaining == 0 {
                return Poll::Ready(None);
            }
            self.remaining -= 1;
            Poll::Ready(Some(self.remaining as i32))
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (0, None)
        }
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
        let streams: Vec<Box<dyn Stream<Item = i32> + Unpin>> =
            vec![Box::new(UnknownUpper::new(3)), Box::new(iter(vec![1, 2]))];
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
}
