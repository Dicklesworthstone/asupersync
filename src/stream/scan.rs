//! Scan combinator for streams.
//!
//! The `Scan` combinator is like [`Fold`](super::Fold), but yields each
//! intermediate accumulator value instead of only the final result.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that yields intermediate accumulator values.
///
/// Created by [`StreamExt::scan`](super::StreamExt::scan).
///
/// For each item in the underlying stream, calls `f(state, item)`.
/// If `f` returns `Some(value)`, that value is yielded and the state
/// is updated. If `f` returns `None`, the stream terminates.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Scan<S, St, F> {
    #[pin]
    stream: S,
    state: Option<St>,
    f: F,
}

impl<S, St, F> Scan<S, St, F> {
    /// Creates a new `Scan` stream.
    #[inline]
    pub(crate) fn new(stream: S, initial_state: St, f: F) -> Self {
        Self {
            stream,
            state: Some(initial_state),
            f,
        }
    }

    /// Returns a reference to the underlying stream.
    #[inline]
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    #[inline]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    #[inline]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S, St, B, F> Stream for Scan<S, St, F>
where
    S: Stream,
    F: FnMut(&mut St, S::Item) -> Option<B>,
{
    type Item = B;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<B>> {
        let this = self.project();
        let Some(state) = this.state else {
            return Poll::Ready(None);
        };

        match this.stream.poll_next(cx) {
            Poll::Ready(Some(item)) => {
                if let Some(value) = (this.f)(state, item) {
                    Poll::Ready(Some(value))
                } else {
                    *this.state = None;
                    Poll::Ready(None)
                }
            }
            Poll::Ready(None) => {
                *this.state = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::stream::{StreamExt, iter};
    use std::marker::PhantomPinned;

    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn collect_scan_to_completion<S, St, F, B>(stream: Scan<S, St, F>) -> (Vec<B>, usize)
    where
        S: Stream,
        F: FnMut(&mut St, S::Item) -> Option<B>,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        let mut pending_polls = 0usize;
        let mut stream = Box::pin(stream);

        loop {
            match stream.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(item)) => items.push(item),
                Poll::Ready(None) => return (items, pending_polls),
                Poll::Pending => {
                    pending_polls += 1;
                    assert!(
                        pending_polls <= 16,
                        "scan stream did not complete after {pending_polls} pending polls",
                    );
                }
            }
        }
    }

    #[derive(Debug)]
    struct EmptyThenPanics {
        completed: bool,
    }

    impl EmptyThenPanics {
        fn new() -> Self {
            Self { completed: false }
        }
    }

    impl Stream for EmptyThenPanics {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            assert!(
                !self.completed,
                "scan inner stream repolled after completion"
            );
            self.completed = true;
            Poll::Ready(None)
        }
    }

    #[derive(Debug)]
    struct PendingBeforeEach {
        items: Vec<i32>,
        next: usize,
        pending_next: bool,
    }

    impl PendingBeforeEach {
        fn new(items: Vec<i32>) -> Self {
            Self {
                items,
                next: 0,
                pending_next: true,
            }
        }
    }

    impl Stream for PendingBeforeEach {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.next >= self.items.len() {
                return Poll::Ready(None);
            }

            if self.pending_next {
                self.pending_next = false;
                return Poll::Pending;
            }

            let item = self.items[self.next];
            self.next += 1;
            self.pending_next = true;
            Poll::Ready(Some(item))
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.items.len().saturating_sub(self.next);
            (remaining, Some(remaining))
        }
    }

    #[pin_project::pin_project]
    struct PinnedOnce {
        item: Option<i32>,
        _pin: PhantomPinned,
    }

    impl PinnedOnce {
        fn new(item: i32) -> Self {
            Self {
                item: Some(item),
                _pin: PhantomPinned,
            }
        }
    }

    impl Stream for PinnedOnce {
        type Item = i32;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.project();
            Poll::Ready(this.item.take())
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = usize::from(self.item.is_some());
            (remaining, Some(remaining))
        }
    }

    #[test]
    fn scan_running_sum() {
        init_test("scan_running_sum");
        let mut stream = Scan::new(iter(vec![1, 2, 3, 4, 5]), 0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            Some(*acc)
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(1)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(3)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(6)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(10)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(15)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("scan_running_sum");
    }

    #[test]
    fn scan_early_termination() {
        init_test("scan_early_termination");
        // Terminate when accumulator exceeds 5.
        let mut stream = Scan::new(iter(vec![1, 2, 3, 4, 5]), 0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            if *acc > 5 { None } else { Some(*acc) }
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(3))
        );
        // 3 + 3 = 6 > 5 → None
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        // After termination, stays None.
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("scan_early_termination");
    }

    #[test]
    fn scan_empty_stream() {
        init_test("scan_empty_stream");
        let mut stream = Scan::new(iter(Vec::<i32>::new()), 0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            Some(*acc)
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("scan_empty_stream");
    }

    #[test]
    fn mr_scan_identity_preserves_sequence() {
        init_test("mr_scan_identity_preserves_sequence");
        let input = vec![5i32, -2, 0, 11, -7];

        let (items, pending_polls) =
            collect_scan_to_completion(Scan::new(iter(input.clone()), (), |_: &mut (), item| {
                Some(item)
            }));

        assert_eq!(items, input);
        assert_eq!(pending_polls, 0);
        crate::test_complete!("mr_scan_identity_preserves_sequence");
    }

    #[test]
    fn mr_scan_running_sum_partition_matches_seeded_suffix() {
        init_test("mr_scan_running_sum_partition_matches_seeded_suffix");
        let prefix = vec![4i32, -7, 12, 3];
        let suffix = vec![9i32, -2, 5];
        let mut combined = prefix.clone();
        combined.extend(suffix.iter().copied());

        let scan_sum = |acc: &mut i32, item: i32| {
            *acc += item;
            Some(*acc)
        };
        let (combined_items, combined_pending) =
            collect_scan_to_completion(Scan::new(iter(combined), 17i32, scan_sum));
        let (mut partitioned_items, prefix_pending) =
            collect_scan_to_completion(Scan::new(iter(prefix), 17i32, scan_sum));
        let suffix_seed = *partitioned_items.last().expect("prefix has running sums");
        let (suffix_items, suffix_pending) =
            collect_scan_to_completion(Scan::new(iter(suffix), suffix_seed, scan_sum));
        partitioned_items.extend(suffix_items);

        assert_eq!(combined_items, partitioned_items);
        assert_eq!(combined_pending + prefix_pending + suffix_pending, 0);
        crate::test_complete!("mr_scan_running_sum_partition_matches_seeded_suffix");
    }

    #[test]
    fn mr_scan_running_sum_scaled_inputs_scale_deltas() {
        init_test("mr_scan_running_sum_scaled_inputs_scale_deltas");
        let input = vec![6i32, -4, 10, 3, -1];
        let scaled: Vec<_> = input.iter().map(|item| item * 3).collect();
        let scan_sum = |acc: &mut i32, item: i32| {
            *acc += item;
            Some(*acc)
        };

        let (base_items, _) = collect_scan_to_completion(Scan::new(iter(input), 0i32, scan_sum));
        let (scaled_items, _) = collect_scan_to_completion(Scan::new(iter(scaled), 0i32, scan_sum));
        let expected_scaled: Vec<_> = base_items.iter().map(|item| item * 3).collect();

        assert_eq!(scaled_items, expected_scaled);
        crate::test_complete!("mr_scan_running_sum_scaled_inputs_scale_deltas");
    }

    #[test]
    fn mr_scan_termination_ignores_tail_after_cutoff() {
        init_test("mr_scan_termination_ignores_tail_after_cutoff");
        let prefix = vec![1i32, 2, 3];
        let mut with_tail = prefix.clone();
        with_tail.extend([100, 200, 300]);
        let until_over_five = |acc: &mut i32, item: i32| {
            *acc += item;
            (*acc <= 5).then_some(*acc)
        };

        let (prefix_items, _) =
            collect_scan_to_completion(Scan::new(iter(prefix), 0i32, until_over_five));
        let (tail_items, _) =
            collect_scan_to_completion(Scan::new(iter(with_tail), 0i32, until_over_five));

        assert_eq!(tail_items, prefix_items);
        crate::test_complete!("mr_scan_termination_ignores_tail_after_cutoff");
    }

    #[test]
    fn mr_scan_pending_before_items_preserves_stateful_outputs() {
        init_test("mr_scan_pending_before_items_preserves_stateful_outputs");
        let input = vec![2i32, 4, -1, 6];
        let scan_sum = |acc: &mut i32, item: i32| {
            *acc += item;
            Some(*acc)
        };

        let (always_ready_items, always_ready_pending) =
            collect_scan_to_completion(Scan::new(iter(input.clone()), 0i32, scan_sum));
        let (pending_items, pending_polls) =
            collect_scan_to_completion(Scan::new(PendingBeforeEach::new(input), 0i32, scan_sum));

        assert_eq!(pending_items, always_ready_items);
        assert_eq!(always_ready_pending, 0);
        assert_eq!(pending_polls, pending_items.len());
        crate::test_complete!("mr_scan_pending_before_items_preserves_stateful_outputs");
    }

    #[test]
    fn scan_does_not_repoll_exhausted_upstream() {
        init_test("scan_does_not_repoll_exhausted_upstream");
        let mut stream = Scan::new(EmptyThenPanics::new(), 0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            Some(*acc)
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));

        crate::test_complete!("scan_does_not_repoll_exhausted_upstream");
    }

    #[test]
    fn scan_type_change() {
        init_test("scan_type_change");
        let mut stream = Scan::new(
            iter(vec!["hello", "world"]),
            String::new(),
            |acc: &mut String, item| {
                if !acc.is_empty() {
                    acc.push(' ');
                }
                acc.push_str(item);
                Some(acc.clone())
            },
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some("hello".to_string())));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some("hello world".to_string())));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("scan_type_change");
    }

    #[test]
    fn scan_accessors() {
        init_test("scan_accessors");
        let mut stream = Scan::new(iter(vec![1, 2, 3]), 0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            Some(*acc)
        });
        let _ref = stream.get_ref();
        let _mut = stream.get_mut();
        let inner = stream.into_inner();

        let mut inner = inner;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(
            Pin::new(&mut inner).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );
        crate::test_complete!("scan_accessors");
    }

    #[test]
    fn scan_debug() {
        #[allow(clippy::unnecessary_wraps)]
        fn sum(acc: &mut i32, x: i32) -> Option<i32> {
            *acc += x;
            Some(*acc)
        }
        let stream = Scan::new(
            iter(vec![1, 2]),
            0i32,
            sum as fn(&mut i32, i32) -> Option<i32>,
        );
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("Scan"));
    }

    #[test]
    fn scan_accepts_pinned_non_unpin_streams() {
        init_test("scan_accepts_pinned_non_unpin_streams");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let stream = PinnedOnce::new(7).scan(10i32, |acc: &mut i32, item| {
            *acc += item;
            Some(*acc)
        });
        let mut stream = std::pin::pin!(stream);

        assert_eq!(stream.as_mut().poll_next(&mut cx), Poll::Ready(Some(17)));
        assert_eq!(stream.as_mut().poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("scan_accepts_pinned_non_unpin_streams");
    }
}
