//! Zip combinator for streams.
//!
//! The `Zip` combinator yields pairs from two streams until either stream ends.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that zips two streams into pairs.
///
/// Created by [`StreamExt::zip`](super::StreamExt::zip).
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Zip<S1: Stream, S2: Stream> {
    #[pin]
    stream1: S1,
    #[pin]
    stream2: S2,
    queued1: Option<S1::Item>,
    queued2: Option<S2::Item>,
    exhausted: bool,
}

impl<S1: Stream, S2: Stream> Zip<S1, S2> {
    /// Creates a new `Zip` stream.
    pub(crate) fn new(stream1: S1, stream2: S2) -> Self {
        Self {
            stream1,
            stream2,
            queued1: None,
            queued2: None,
            exhausted: false,
        }
    }

    /// Returns a reference to the first stream.
    pub fn first_ref(&self) -> &S1 {
        &self.stream1
    }

    /// Returns a reference to the second stream.
    pub fn second_ref(&self) -> &S2 {
        &self.stream2
    }

    /// Returns mutable references to the underlying streams.
    pub fn get_mut(&mut self) -> (&mut S1, &mut S2) {
        (&mut self.stream1, &mut self.stream2)
    }

    /// Consumes the combinator, returning the underlying streams.
    pub fn into_inner(self) -> (S1, S2) {
        (self.stream1, self.stream2)
    }
}

impl<S1, S2> Stream for Zip<S1, S2>
where
    S1: Stream,
    S2: Stream,
{
    type Item = (S1::Item, S2::Item);

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }
        if this.queued1.is_none() {
            match this.stream1.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => *this.queued1 = Some(item),
                Poll::Ready(None) => {
                    *this.queued1 = None;
                    *this.queued2 = None;
                    *this.exhausted = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => {}
            }
        }

        if this.queued2.is_none() {
            match this.stream2.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => *this.queued2 = Some(item),
                Poll::Ready(None) => {
                    *this.queued1 = None;
                    *this.queued2 = None;
                    *this.exhausted = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => {}
            }
        }

        if this.queued1.is_some() && this.queued2.is_some() {
            let item1 = this.queued1.take().expect("queued1 should have item");
            let item2 = this.queued2.take().expect("queued2 should have item");
            Poll::Ready(Some((item1, item2)))
        } else {
            Poll::Pending
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            return (0, Some(0));
        }

        let (lower1, upper1) = self.stream1.size_hint();
        let (lower2, upper2) = self.stream2.size_hint();
        let queued1 = usize::from(self.queued1.is_some());
        let queued2 = usize::from(self.queued2.is_some());

        let lower = lower1
            .saturating_add(queued1)
            .min(lower2.saturating_add(queued2));
        let upper = match (
            upper1.map(|upper| upper.saturating_add(queued1)),
            upper2.map(|upper| upper.saturating_add(queued2)),
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        (lower, upper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::iter;
    use std::collections::VecDeque;
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
    fn zip_pairs_items() {
        init_test("zip_pairs_items");
        let mut stream = Zip::new(iter(vec![1, 2, 3]), iter(vec!["a", "b", "c"]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some((1, "a"))));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some((1, \"a\")))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some((2, "b"))));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some((2, \"b\")))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some((3, "c"))));
        crate::assert_with_log!(ok, "poll 3", "Poll::Ready(Some((3, \"c\")))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("zip_pairs_items");
    }

    #[test]
    fn zip_ends_when_shorter_finishes() {
        init_test("zip_ends_when_shorter_finishes");
        let mut stream = Zip::new(iter(vec![1, 2, 3]), iter(vec!["a"]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some((1, "a"))));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some((1, \"a\")))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("zip_ends_when_shorter_finishes");
    }

    #[test]
    fn zip_size_hint_min() {
        init_test("zip_size_hint_min");
        let stream = Zip::new(iter(vec![1, 2, 3]), iter(vec!["a", "b"]));
        let hint = stream.size_hint();
        let ok = hint == (2, Some(2));
        crate::assert_with_log!(ok, "size hint", (2, Some(2)), hint);
        crate::test_complete!("zip_size_hint_min");
    }

    #[derive(Debug)]
    struct PendingOnceThenIter<T> {
        items: VecDeque<T>,
        first_poll_pending: bool,
    }

    impl<T> PendingOnceThenIter<T> {
        fn new(items: Vec<T>) -> Self {
            Self {
                items: VecDeque::from(items),
                first_poll_pending: true,
            }
        }
    }

    impl<T: Unpin> Stream for PendingOnceThenIter<T> {
        type Item = T;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.first_poll_pending {
                self.first_poll_pending = false;
                Poll::Pending
            } else {
                Poll::Ready(self.items.pop_front())
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let len = self.items.len();
            (len, Some(len))
        }
    }

    #[derive(Debug)]
    struct PollCountingPendingThenEmpty {
        polls: usize,
        completed: bool,
    }

    impl PollCountingPendingThenEmpty {
        fn new() -> Self {
            Self {
                polls: 0,
                completed: false,
            }
        }
    }

    impl Stream for PollCountingPendingThenEmpty {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            assert!(
                !self.completed,
                "pending-then-empty stream polled after completion"
            );
            self.polls += 1;
            if self.polls == 1 {
                Poll::Pending
            } else {
                self.completed = true;
                Poll::Ready(None)
            }
        }
    }

    #[derive(Debug)]
    struct PollCountingSingleThenEmpty<T> {
        polls: usize,
        next: Option<T>,
        completed: bool,
    }

    impl<T> PollCountingSingleThenEmpty<T> {
        fn new(item: T) -> Self {
            Self {
                polls: 0,
                next: Some(item),
                completed: false,
            }
        }
    }

    impl<T: Unpin> Stream for PollCountingSingleThenEmpty<T> {
        type Item = T;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            assert!(
                !self.completed,
                "single-then-empty stream polled after completion"
            );
            self.polls += 1;
            if let Some(item) = self.next.take() {
                Poll::Ready(Some(item))
            } else {
                self.completed = true;
                Poll::Ready(None)
            }
        }
    }

    #[test]
    fn zip_size_hint_counts_buffered_items() {
        init_test("zip_size_hint_counts_buffered_items");
        let mut stream = Zip::new(
            iter(vec![1, 2, 3]),
            PendingOnceThenIter::new(vec![10, 20, 30]),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(stream.size_hint(), (3, Some(3)));

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert!(
            poll.is_pending(),
            "second stream should delay the first pair"
        );

        // One item is buffered from stream1, so the remaining pair count is still exact.
        assert_eq!(stream.size_hint(), (3, Some(3)));

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some((1, 10))));
        crate::assert_with_log!(ok, "buffered pair yielded", true, ok);

        crate::test_complete!("zip_size_hint_counts_buffered_items");
    }

    #[test]
    fn zip_clears_left_buffer_when_right_exhausts() {
        init_test("zip_clears_left_buffer_when_right_exhausts");
        let mut stream = Zip::new(iter(vec![1, 2]), PollCountingSingleThenEmpty::new(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some((1, 10)))
        );
        assert_eq!(stream.size_hint(), (0, Some(1)));

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.size_hint(), (0, Some(0)));

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.size_hint(), (0, Some(0)));

        crate::test_complete!("zip_clears_left_buffer_when_right_exhausts");
    }

    #[test]
    fn zip_clears_right_buffer_when_left_exhausts() {
        init_test("zip_clears_right_buffer_when_left_exhausts");
        let mut stream = Zip::new(PollCountingPendingThenEmpty::new(), iter(vec![10]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Pin::new(&mut stream).poll_next(&mut cx).is_pending());
        assert_eq!(stream.size_hint(), (0, Some(1)));

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.size_hint(), (0, Some(0)));

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.size_hint(), (0, Some(0)));

        crate::test_complete!("zip_clears_right_buffer_when_left_exhausts");
    }

    /// Invariant: zipping two empty streams immediately yields None.
    #[test]
    fn zip_both_empty_returns_none() {
        init_test("zip_both_empty_returns_none");
        let mut stream = Zip::new(iter(Vec::<i32>::new()), iter(Vec::<i32>::new()));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let is_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(is_none, "both empty yields None", true, is_none);
        crate::test_complete!("zip_both_empty_returns_none");
    }

    /// Invariant: accessors (first_ref, second_ref, get_mut, into_inner) work correctly.
    #[test]
    fn zip_accessors() {
        init_test("zip_accessors");
        let mut stream = Zip::new(iter(vec![1, 2]), iter(vec![3, 4]));

        // first_ref and second_ref return references.
        let _first = stream.first_ref();
        let _second = stream.second_ref();

        // get_mut returns mutable references to both streams.
        let (_s1, _s2) = stream.get_mut();

        // into_inner consumes and returns both streams.
        let (s1, s2) = stream.into_inner();
        // Verify we can still poll the recovered streams.
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut s1 = s1;
        let poll = Pin::new(&mut s1).poll_next(&mut cx);
        let got_1 = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(got_1, "s1 still has items", true, got_1);
        let mut s2 = s2;
        let poll = Pin::new(&mut s2).poll_next(&mut cx);
        let got_3 = matches!(poll, Poll::Ready(Some(3)));
        crate::assert_with_log!(got_3, "s2 still has items", true, got_3);

        crate::test_complete!("zip_accessors");
    }
}
