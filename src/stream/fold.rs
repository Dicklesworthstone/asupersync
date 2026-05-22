//! Fold combinator for streams.
//!
//! The `Fold` future consumes a stream and folds all items into a single value.

use super::Stream;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items folded in a single poll.
///
/// Without this cap, a synchronously ready stream can keep `Fold` inside one
/// `poll` call until exhaustion and starve sibling tasks.
const FOLD_COOPERATIVE_BUDGET: usize = 1024;

/// A future that folds all items from a stream into a single value.
///
/// Created by [`StreamExt::fold`](super::StreamExt::fold).
#[pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Fold<S, F, Acc> {
    #[pin]
    stream: S,
    f: F,
    acc: Option<Acc>,
    completed: bool,
}

impl<S, F, Acc> Fold<S, F, Acc> {
    /// Creates a new `Fold` future.
    #[inline]
    pub(crate) fn new(stream: S, init: Acc, f: F) -> Self {
        Self {
            stream,
            f,
            acc: Some(init),
            completed: false,
        }
    }
}

impl<S, F, Acc> Future for Fold<S, F, Acc>
where
    S: Stream,
    F: FnMut(Acc, S::Item) -> Acc,
{
    type Output = Acc;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Acc> {
        let mut this = self.project();
        assert!(!*this.completed, "Fold polled after completion");
        let mut folded_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    let acc = this.acc.take().expect("Fold polled after completion");
                    *this.acc = Some((this.f)(acc, item));
                    folded_this_poll += 1;
                    if folded_this_poll >= FOLD_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.completed = true;
                    return Poll::Ready(this.acc.take().expect("Fold polled after completion"));
                }
                Poll::Pending => return Poll::Pending,
            }
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
    use crate::stream::iter;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct TrackWaker(Arc<AtomicBool>);

    use std::task::Wake;
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
        end: usize,
    }

    impl AlwaysReadyCounter {
        fn new(end: usize) -> Self {
            Self { next: 0, end }
        }
    }

    impl Stream for AlwaysReadyCounter {
        type Item = usize;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.next >= self.end {
                return Poll::Ready(None);
            }

            let item = self.next;
            self.next += 1;
            Poll::Ready(Some(item))
        }
    }

    #[derive(Debug)]
    struct PollCountingEmptyStream {
        polls: Arc<AtomicUsize>,
    }

    impl PollCountingEmptyStream {
        fn new(polls: Arc<AtomicUsize>) -> Self {
            Self { polls }
        }
    }

    impl Stream for PollCountingEmptyStream {
        type Item = usize;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(None)
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn poll_fold_to_completion<S, F, Acc>(future: &mut Fold<S, F, Acc>) -> (Acc, usize)
    where
        Fold<S, F, Acc>: std::future::Future<Output = Acc> + Unpin,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pending_polls = 0usize;

        loop {
            match Pin::new(&mut *future).poll(&mut cx) {
                Poll::Ready(value) => return (value, pending_polls),
                Poll::Pending => {
                    pending_polls += 1;
                    assert!(
                        pending_polls <= 8,
                        "fold future did not complete after {pending_polls} pending polls",
                    );
                }
            }
        }
    }

    #[test]
    fn fold_sum() {
        init_test("fold_sum");
        let mut future = Fold::new(iter(vec![1i32, 2, 3, 4, 5]), 0i32, |acc, x| acc + x);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(sum) => {
                let ok = sum == 15;
                crate::assert_with_log!(ok, "sum", 15, sum);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("fold_sum");
    }

    #[test]
    fn fold_product() {
        init_test("fold_product");
        let mut future = Fold::new(iter(vec![1i32, 2, 3, 4, 5]), 1i32, |acc, x| acc * x);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(product) => {
                let ok = product == 120;
                crate::assert_with_log!(ok, "product", 120, product);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("fold_product");
    }

    #[test]
    fn fold_string_concat() {
        init_test("fold_string_concat");
        let mut future = Fold::new(
            iter(vec!["a", "b", "c"]),
            String::new(),
            |mut acc: String, s: &str| {
                acc.push_str(s);
                acc
            },
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(s) => {
                let ok = s == "abc";
                crate::assert_with_log!(ok, "concat", "abc", s);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("fold_string_concat");
    }

    #[test]
    fn fold_empty() {
        init_test("fold_empty");
        let mut future = Fold::new(iter(Vec::<i32>::new()), 42i32, |acc, x| acc + x);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(result) => {
                let ok = result == 42;
                crate::assert_with_log!(ok, "empty result", 42, result);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("fold_empty");
    }

    #[test]
    fn mr_fold_sum_partition_matches_seeded_suffix() {
        init_test("mr_fold_sum_partition_matches_seeded_suffix");
        let prefix = vec![4i32, -7, 12, 3];
        let suffix = vec![9i32, -2, 5];
        let mut combined = prefix.clone();
        combined.extend(suffix.iter().copied());

        let (full, full_pending) =
            poll_fold_to_completion(&mut Fold::new(iter(combined), 17i32, |acc, item| {
                acc + item
            }));
        let (prefix_result, prefix_pending) =
            poll_fold_to_completion(&mut Fold::new(iter(prefix), 17i32, |acc, item| acc + item));
        let (partitioned, suffix_pending) =
            poll_fold_to_completion(&mut Fold::new(iter(suffix), prefix_result, |acc, item| {
                acc + item
            }));

        assert_eq!(full, partitioned);
        assert_eq!(full_pending, 0);
        assert_eq!(prefix_pending, 0);
        assert_eq!(suffix_pending, 0);
        crate::test_complete!("mr_fold_sum_partition_matches_seeded_suffix");
    }

    #[test]
    fn mr_fold_sum_ignores_additive_identity_injection() {
        init_test("mr_fold_sum_ignores_additive_identity_injection");
        let base = vec![8i32, -3, 5, 11, -6];
        let injected = vec![0i32, 8, 0, -3, 5, 0, 11, -6, 0];

        let (base_sum, _) =
            poll_fold_to_completion(&mut Fold::new(iter(base), 13i32, |acc, item| acc + item));
        let (injected_sum, _) =
            poll_fold_to_completion(&mut Fold::new(iter(injected), 13i32, |acc, item| {
                acc + item
            }));

        assert_eq!(base_sum, injected_sum);
        crate::test_complete!("mr_fold_sum_ignores_additive_identity_injection");
    }

    #[test]
    fn mr_fold_sum_scaled_inputs_scale_delta_from_seed() {
        init_test("mr_fold_sum_scaled_inputs_scale_delta_from_seed");
        let base = vec![6i32, -4, 10, 3, -1];
        let scaled: Vec<_> = base.iter().map(|item| item * 3).collect();
        let seed = 23i32;

        let (base_sum, _) =
            poll_fold_to_completion(&mut Fold::new(iter(base), seed, |acc, item| acc + item));
        let (scaled_sum, _) =
            poll_fold_to_completion(&mut Fold::new(iter(scaled), seed, |acc, item| acc + item));

        assert_eq!(scaled_sum - seed, (base_sum - seed) * 3);
        crate::test_complete!("mr_fold_sum_scaled_inputs_scale_delta_from_seed");
    }

    #[test]
    fn mr_fold_string_partition_matches_seeded_suffix() {
        init_test("mr_fold_string_partition_matches_seeded_suffix");
        let prefix = vec!["asu", "per"];
        let suffix = vec!["sync", "-", "runtime"];
        let mut combined = prefix.clone();
        combined.extend(suffix.iter().copied());

        let concat = |mut acc: String, item: &str| {
            acc.push_str(item);
            acc
        };
        let (full, _) = poll_fold_to_completion(&mut Fold::new(
            iter(combined),
            String::from("spec:"),
            concat,
        ));
        let (prefix_result, _) =
            poll_fold_to_completion(&mut Fold::new(iter(prefix), String::from("spec:"), concat));
        let (partitioned, _) =
            poll_fold_to_completion(&mut Fold::new(iter(suffix), prefix_result, concat));

        assert_eq!(full, partitioned);
        crate::test_complete!("mr_fold_string_partition_matches_seeded_suffix");
    }

    #[test]
    fn mr_fold_cooperative_yields_preserve_large_stream_sum() {
        init_test("mr_fold_cooperative_yields_preserve_large_stream_sum");
        let end = (FOLD_COOPERATIVE_BUDGET * 2) + 17;
        let mut future = Fold::new(AlwaysReadyCounter::new(end), 0usize, |acc, item| acc + item);

        let (sum, pending_polls) = poll_fold_to_completion(&mut future);

        assert_eq!(sum, (0..end).sum::<usize>());
        assert_eq!(pending_polls, 2);
        crate::test_complete!("mr_fold_cooperative_yields_preserve_large_stream_sum");
    }

    #[test]
    fn fold_yields_after_budget_on_always_ready_stream() {
        init_test("fold_yields_after_budget_on_always_ready_stream");
        let mut future = Fold::new(
            AlwaysReadyCounter::new(FOLD_COOPERATIVE_BUDGET + 5),
            0usize,
            |acc, x| acc + x,
        );
        let woke = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(woke.clone())));
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first poll yields cooperatively",
            "Poll::Pending",
            first
        );
        let expected_partial = (0..FOLD_COOPERATIVE_BUDGET).sum::<usize>();
        crate::assert_with_log!(
            future.acc == Some(expected_partial),
            "partial accumulator retained across yield",
            Some(expected_partial),
            future.acc
        );
        crate::assert_with_log!(
            future.stream.next == FOLD_COOPERATIVE_BUDGET,
            "upstream advanced only to budget",
            FOLD_COOPERATIVE_BUDGET,
            future.stream.next
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "self-wake requested",
            true,
            woke.load(Ordering::SeqCst)
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        let expected_total = (0..FOLD_COOPERATIVE_BUDGET + 5).sum::<usize>();
        crate::assert_with_log!(
            second == Poll::Ready(expected_total),
            "second poll completes fold",
            Poll::Ready(expected_total),
            second
        );
        crate::test_complete!("fold_yields_after_budget_on_always_ready_stream");
    }

    #[test]
    #[should_panic(expected = "Fold polled after completion")]
    fn fold_repoll_after_completion_panics() {
        init_test("fold_repoll_after_completion_panics");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut future = Fold::new(
            PollCountingEmptyStream::new(Arc::clone(&polls)),
            7usize,
            |acc, item| acc + item,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert_eq!(first, Poll::Ready(7));

        // Repoll after completion must panic (fail-closed), not return
        // Pending without a waker which would cause a silent hang.
        let _repoll = Pin::new(&mut future).poll(&mut cx);
    }
}
