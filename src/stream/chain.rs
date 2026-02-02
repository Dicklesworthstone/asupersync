//! Chain combinator for streams.
//!
//! The `Chain` combinator yields all items from the first stream, then all
//! items from the second stream.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that yields items from the first stream then the second.
///
/// Created by [`StreamExt::chain`](super::StreamExt::chain).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Chain<S1, S2> {
    first: Option<S1>,
    second: S2,
}

impl<S1, S2> Chain<S1, S2> {
    /// Creates a new `Chain` stream.
    pub(crate) fn new(first: S1, second: S2) -> Self {
        Self {
            first: Some(first),
            second,
        }
    }

    /// Returns a reference to the first stream, if still active.
    pub fn first_ref(&self) -> Option<&S1> {
        self.first.as_ref()
    }

    /// Returns a mutable reference to the first stream, if still active.
    pub fn first_mut(&mut self) -> Option<&mut S1> {
        self.first.as_mut()
    }

    /// Returns a reference to the second stream.
    pub fn second_ref(&self) -> &S2 {
        &self.second
    }

    /// Returns a mutable reference to the second stream.
    pub fn second_mut(&mut self) -> &mut S2 {
        &mut self.second
    }

    /// Consumes the combinator, returning the two underlying streams.
    pub fn into_inner(self) -> (Option<S1>, S2) {
        (self.first, self.second)
    }
}

impl<S1: Unpin, S2: Unpin> Unpin for Chain<S1, S2> {}

impl<S1, S2> Stream for Chain<S1, S2>
where
    S1: Stream + Unpin,
    S2: Stream<Item = S1::Item> + Unpin,
{
    type Item = S1::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(first) = self.first.as_mut() {
            match Pin::new(first).poll_next(cx) {
                Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
                Poll::Ready(None) => {
                    self.first = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.second).poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let second_hint = self.second.size_hint();
        let Some(first) = self.first.as_ref() else {
            return second_hint;
        };

        let (first_lower, first_upper) = first.size_hint();
        let (second_lower, second_upper) = second_hint;

        let lower = first_lower.saturating_add(second_lower);
        let upper = match (first_upper, second_upper) {
            (Some(a), Some(b)) => a.checked_add(b),
            _ => None,
        };

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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn chain_yields_both_streams() {
        init_test("chain_yields_both_streams");
        let mut stream = Chain::new(iter(vec![1, 2]), iter(vec![3, 4]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(1))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(3)));
        crate::assert_with_log!(ok, "poll 3", "Poll::Ready(Some(3))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(4)));
        crate::assert_with_log!(ok, "poll 4", "Poll::Ready(Some(4))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("chain_yields_both_streams");
    }

    #[test]
    fn chain_size_hint_combines() {
        init_test("chain_size_hint_combines");
        let stream = Chain::new(iter(vec![1, 2, 3]), iter(vec![4]));
        let hint = stream.size_hint();
        let ok = hint == (4, Some(4));
        crate::assert_with_log!(ok, "size hint", (4, Some(4)), hint);
        crate::test_complete!("chain_size_hint_combines");
    }

    #[test]
    fn chain_empty_first() {
        init_test("chain_empty_first");
        let mut stream = Chain::new(iter(Vec::<i32>::new()), iter(vec![1, 2]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "skips empty first", "Poll::Ready(Some(1))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "second item", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "done", "Poll::Ready(None)", poll);
        crate::test_complete!("chain_empty_first");
    }

    #[test]
    fn chain_empty_second() {
        init_test("chain_empty_second");
        let mut stream = Chain::new(iter(vec![1, 2]), iter(Vec::<i32>::new()));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "first item", "Poll::Ready(Some(1))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "second item", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "done", "Poll::Ready(None)", poll);
        crate::test_complete!("chain_empty_second");
    }

    #[test]
    fn chain_both_empty() {
        init_test("chain_both_empty");
        let mut stream = Chain::new(iter(Vec::<i32>::new()), iter(Vec::<i32>::new()));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "immediately done", "Poll::Ready(None)", poll);
        crate::test_complete!("chain_both_empty");
    }

    #[test]
    fn chain_accessors() {
        init_test("chain_accessors");
        let stream = Chain::new(iter(vec![1, 2]), iter(vec![3]));

        assert!(stream.first_ref().is_some());
        assert_eq!(stream.second_ref().size_hint(), (1, Some(1)));
        crate::test_complete!("chain_accessors");
    }

    #[test]
    fn chain_first_consumed_after_exhaustion() {
        init_test("chain_first_consumed_after_exhaustion");
        let mut stream = Chain::new(iter(Vec::<i32>::new()), iter(vec![1]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First stream is empty, so after one poll it should be dropped
        let _ = Pin::new(&mut stream).poll_next(&mut cx);
        assert!(
            stream.first_ref().is_none(),
            "first should be None after exhaustion"
        );
        crate::test_complete!("chain_first_consumed_after_exhaustion");
    }

    #[test]
    fn chain_into_inner() {
        init_test("chain_into_inner");
        let stream = Chain::new(iter(vec![1]), iter(vec![2]));
        let (first, _second) = stream.into_inner();
        assert!(first.is_some(), "first should be Some before polling");
        crate::test_complete!("chain_into_inner");
    }

    #[test]
    fn chain_size_hint_after_first_exhausted() {
        init_test("chain_size_hint_after_first_exhausted");
        let mut stream = Chain::new(iter(vec![1]), iter(vec![2, 3]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Consume first stream entirely
        let _ = Pin::new(&mut stream).poll_next(&mut cx); // yields 1
        let _ = Pin::new(&mut stream).poll_next(&mut cx); // first exhausted, yields 2

        // Size hint should now reflect only second stream's remaining items (one left: 3)
        let hint = stream.size_hint();
        let ok = hint == (1, Some(1));
        crate::assert_with_log!(ok, "hint after exhaust", (1, Some(1)), hint);
        crate::test_complete!("chain_size_hint_after_first_exhausted");
    }

    #[test]
    fn chain_large_streams() {
        init_test("chain_large_streams");
        let first: Vec<i32> = (0..100).collect();
        let second: Vec<i32> = (100..200).collect();
        let mut stream = Chain::new(iter(first), iter(second));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut collected = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(v)) => collected.push(v),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("unexpected Pending from iter stream"),
            }
        }
        let expected: Vec<i32> = (0..200).collect();
        assert_eq!(collected, expected);
        crate::test_complete!("chain_large_streams");
    }

    #[test]
    fn chain_multiple_chains() {
        init_test("chain_multiple_chains");
        let inner = Chain::new(iter(vec![1, 2]), iter(vec![3, 4]));
        let mut stream = Chain::new(inner, iter(vec![5, 6]));
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
        assert_eq!(collected, vec![1, 2, 3, 4, 5, 6]);
        crate::test_complete!("chain_multiple_chains");
    }
}
