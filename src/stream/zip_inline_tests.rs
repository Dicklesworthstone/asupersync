    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::stream::iter;
    use std::collections::VecDeque;

    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
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

        // into_inner consumes and returns both streams plus any buffered items.
        let (s1, s2, queued1, queued2) = stream.into_inner();
        assert!(queued1.is_none());
        assert!(queued2.is_none());
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

    #[test]
    fn zip_into_inner_preserves_buffered_items() {
        init_test("zip_into_inner_preserves_buffered_items");
        let mut stream = Zip::new(iter(vec![1, 2]), PendingOnceThenIter::new(vec![10, 20]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first_poll = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "first poll buffers left item while right is pending",
            true,
            first_poll.is_pending()
        );

        let (mut left, mut right, queued_left, queued_right) = stream.into_inner();
        crate::assert_with_log!(
            queued_left == Some(1),
            "buffered left item preserved",
            Some(1),
            queued_left
        );
        crate::assert_with_log!(
            queued_right.is_none(),
            "right side has no buffered item",
            true,
            queued_right.is_none()
        );

        let left_next = Pin::new(&mut left).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(left_next, Poll::Ready(Some(2))),
            "left stream advances past preserved buffered item",
            "Poll::Ready(Some(2))",
            format!("{left_next:?}")
        );

        let right_next = Pin::new(&mut right).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(right_next, Poll::Ready(Some(10))),
            "right stream still yields its first item",
            "Poll::Ready(Some(10))",
            format!("{right_next:?}")
        );

        crate::test_complete!("zip_into_inner_preserves_buffered_items");
    }

    fn drain_ready_i32_zip<S1, S2>(mut stream: Zip<S1, S2>) -> Vec<(i32, i32)>
    where
        S1: Stream<Item = i32> + Unpin,
        S2: Stream<Item = i32> + Unpin,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut out = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(pair)) => out.push(pair),
                Poll::Ready(None) => return out,
                Poll::Pending => panic!("unexpected Pending from ready zip stream"),
            }
        }
    }

    #[test]
    fn mr_zip_length_and_projections_follow_shorter_input() {
        init_test("mr_zip_length_and_projections_follow_shorter_input");
        for left_len in 0..=8usize {
            for right_len in 0..=8usize {
                let left: Vec<i32> = (0..left_len).map(|n| 100 + n as i32).collect();
                let right: Vec<i32> = (0..right_len).map(|n| -10 - n as i32).collect();
                let pairs = drain_ready_i32_zip(Zip::new(iter(left.clone()), iter(right.clone())));
                let expected_len = left_len.min(right_len);

                assert_eq!(
                    pairs.len(),
                    expected_len,
                    "zip length must be min(left_len, right_len)"
                );
                assert_eq!(
                    pairs.iter().map(|(left, _)| *left).collect::<Vec<_>>(),
                    left[..expected_len],
                    "left projection must equal the left prefix"
                );
                assert_eq!(
                    pairs.iter().map(|(_, right)| *right).collect::<Vec<_>>(),
                    right[..expected_len],
                    "right projection must equal the right prefix"
                );
            }
        }
        crate::test_complete!("mr_zip_length_and_projections_follow_shorter_input");
    }

    #[test]
    fn mr_zip_swapping_inputs_swaps_output_components() {
        init_test("mr_zip_swapping_inputs_swaps_output_components");
        for left_len in 0..=8usize {
            for right_len in 0..=8usize {
                let left: Vec<i32> = (0..left_len).map(|n| 2 * n as i32 + 1).collect();
                let right: Vec<i32> = (0..right_len).map(|n| 1000 - n as i32).collect();

                let forward =
                    drain_ready_i32_zip(Zip::new(iter(left.clone()), iter(right.clone())));
                let swapped = drain_ready_i32_zip(Zip::new(iter(right), iter(left)))
                    .into_iter()
                    .map(|(right, left)| (left, right))
                    .collect::<Vec<_>>();

                assert_eq!(
                    forward, swapped,
                    "zip(a, b) must match zip(b, a) with each output pair swapped"
                );
            }
        }
        crate::test_complete!("mr_zip_swapping_inputs_swaps_output_components");
    }

    #[test]
    fn mr_zip_pending_left_preserves_queued_right_item() {
        init_test("mr_zip_pending_left_preserves_queued_right_item");
        let mut stream = Zip::new(PendingOnceThenIter::new(vec![1, 2]), iter(vec![10, 20]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Pin::new(&mut stream).poll_next(&mut cx).is_pending());
        assert_eq!(
            stream.size_hint(),
            (2, Some(2)),
            "right item queued during a left-side pending poll must still count toward pairs"
        );

        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some((1, 10)))
        );
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some((2, 20)))
        );
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("mr_zip_pending_left_preserves_queued_right_item");
    }
