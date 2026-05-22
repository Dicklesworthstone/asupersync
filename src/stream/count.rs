//! Count combinator for streams.
//!
//! The `Count` future consumes a stream and counts the number of items.

use super::Stream;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items drained in a single poll.
///
/// Without this bound, an always-ready upstream stream can monopolize one
/// executor turn while `Count` drains the entire stream.
const COUNT_COOPERATIVE_BUDGET: usize = 1024;

/// A future that counts the items in a stream.
///
/// Created by [`StreamExt::count`](super::StreamExt::count).
#[pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Count<S> {
    #[pin]
    stream: S,
    total: usize,
    completed: bool,
}

impl<S> Count<S> {
    /// Creates a new `Count` future.
    #[inline]
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            total: 0,
            completed: false,
        }
    }
}

impl<S> Future for Count<S>
where
    S: Stream,
{
    type Output = usize;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
        let mut this = self.project();
        assert!(!*this.completed, "Count polled after completion");
        let mut counted_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(_)) => {
                    *this.total += 1;
                    counted_this_poll += 1;
                    if counted_this_poll >= COUNT_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.completed = true;
                    return Poll::Ready(*this.total);
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
    use crate::stream::{Chain, iter};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
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

    #[derive(Debug, Default)]
    struct OneThenDoneThenPanicStream {
        emitted: bool,
        completed: bool,
    }

    impl Stream for OneThenDoneThenPanicStream {
        type Item = usize;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            assert!(!self.completed, "inner stream repolled after completion");

            if self.emitted {
                self.completed = true;
                Poll::Ready(None)
            } else {
                self.emitted = true;
                Poll::Ready(Some(1))
            }
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn poll_count<S>(future: &mut Count<S>) -> usize
    where
        Count<S>: Unpin,
        S: Stream,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        match Pin::new(future).poll(&mut cx) {
            Poll::Ready(count) => count,
            Poll::Pending => panic!("expected Ready"), // ubs:ignore - test logic
        }
    }

    fn poll_count_to_completion<S>(future: &mut Count<S>) -> (usize, usize)
    where
        Count<S>: Unpin,
        S: Stream,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pending_polls = 0usize;

        loop {
            match Pin::new(&mut *future).poll(&mut cx) {
                Poll::Ready(count) => return (count, pending_polls),
                Poll::Pending => {
                    pending_polls += 1;
                    assert!(
                        pending_polls <= 8,
                        "count future did not complete after {pending_polls} pending polls",
                    );
                }
            }
        }
    }

    #[test]
    fn count_items() {
        init_test("count_items");
        let mut future = Count::new(iter(vec![1i32, 2, 3, 4, 5]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(count) => {
                let ok = count == 5;
                crate::assert_with_log!(ok, "count", 5, count);
            }
            Poll::Pending => panic!("expected Ready"), // ubs:ignore - test logic
        }
        crate::test_complete!("count_items");
    }

    #[test]
    fn count_empty() {
        init_test("count_empty");
        let mut future = Count::new(iter(Vec::<i32>::new()));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(count) => {
                let ok = count == 0;
                crate::assert_with_log!(ok, "count", 0, count);
            }
            Poll::Pending => panic!("expected Ready"), // ubs:ignore - test logic
        }
        crate::test_complete!("count_empty");
    }

    #[test]
    fn count_single() {
        init_test("count_single");
        let mut future = Count::new(iter(vec![42i32]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(count) => {
                let ok = count == 1;
                crate::assert_with_log!(ok, "count", 1, count);
            }
            Poll::Pending => panic!("expected Ready"), // ubs:ignore - test logic
        }
        crate::test_complete!("count_single");
    }

    #[test]
    fn mr_count_depends_only_on_cardinality() {
        for len in 0..=64usize {
            let ascending: Vec<i32> = (0..len).map(|item| item as i32).collect();
            let transformed: Vec<i32> = (0..len).map(|item| item as i32 * -7 + 31).collect();
            let mut first = Count::new(iter(ascending));
            let mut second = Count::new(iter(transformed));

            assert_eq!(
                poll_count(&mut first),
                len,
                "count must match input cardinality for len {len}",
            );
            assert_eq!(
                poll_count(&mut second),
                len,
                "count must ignore item values for len {len}",
            );
        }
    }

    #[test]
    fn mr_count_chain_is_additive_across_lengths() {
        for left_len in 0..=16usize {
            for right_len in 0..=16usize {
                let left_items: Vec<i32> = (0..left_len).map(|item| item as i32 - 13).collect();
                let right_items: Vec<i32> =
                    (0..right_len).map(|item| item as i32 * 3 + 5).collect();
                let mut chained = Count::new(Chain::new(
                    iter(left_items.clone()),
                    iter(right_items.clone()),
                ));
                let mut left = Count::new(iter(left_items));
                let mut right = Count::new(iter(right_items));

                assert_eq!(
                    poll_count(&mut chained),
                    poll_count(&mut left) + poll_count(&mut right),
                    "count(chain(left, right)) must equal count(left) + count(right) for lengths {left_len}, {right_len}",
                );
            }
        }
    }

    #[test]
    fn mr_count_chain_associativity_preserves_total() {
        for left_len in 0..=6usize {
            for middle_len in 0..=6usize {
                for right_len in 0..=6usize {
                    let left_items: Vec<i32> = (0..left_len).map(|item| item as i32 - 3).collect();
                    let middle_items: Vec<i32> =
                        (0..middle_len).map(|item| item as i32 + 17).collect();
                    let right_items: Vec<i32> =
                        (0..right_len).map(|item| item as i32 * 2).collect();
                    let mut left_assoc = Count::new(Chain::new(
                        Chain::new(iter(left_items.clone()), iter(middle_items.clone())),
                        iter(right_items.clone()),
                    ));
                    let mut right_assoc = Count::new(Chain::new(
                        iter(left_items),
                        Chain::new(iter(middle_items), iter(right_items)),
                    ));

                    assert_eq!(
                        poll_count(&mut left_assoc),
                        poll_count(&mut right_assoc),
                        "count must be stable under chain reassociation for lengths {left_len}, {middle_len}, {right_len}",
                    );
                }
            }
        }
    }

    #[test]
    fn mr_count_cooperative_yields_match_full_budget_blocks() {
        for len in [
            0usize,
            1,
            COUNT_COOPERATIVE_BUDGET - 1,
            COUNT_COOPERATIVE_BUDGET,
            COUNT_COOPERATIVE_BUDGET + 1,
            COUNT_COOPERATIVE_BUDGET * 2,
            COUNT_COOPERATIVE_BUDGET * 2 + 3,
        ] {
            let mut future = Count::new(AlwaysReadyCounter::new(len));
            let (count, pending_polls) = poll_count_to_completion(&mut future);

            assert_eq!(count, len, "count must complete with full length {len}");
            assert_eq!(
                pending_polls,
                len / COUNT_COOPERATIVE_BUDGET,
                "count should yield once per full cooperative budget block for len {len}",
            );
        }
    }

    #[test]
    fn count_chain_matches_sum_of_parts() {
        init_test("count_chain_matches_sum_of_parts");
        let left_items = vec![1usize, 2, 3];
        let right_items = vec![4usize, 5];

        let mut chained = Count::new(Chain::new(
            iter(left_items.clone()),
            iter(right_items.clone()),
        ));
        let mut left = Count::new(iter(left_items));
        let mut right = Count::new(iter(right_items));

        let chained_count = poll_count(&mut chained);
        let summed_count = poll_count(&mut left) + poll_count(&mut right);
        crate::assert_with_log!(
            chained_count == summed_count,
            "count(chain(a, b)) equals count(a) + count(b)",
            summed_count,
            chained_count
        );
        crate::test_complete!("count_chain_matches_sum_of_parts");
    }

    #[test]
    fn count_yields_after_budget_on_always_ready_stream() {
        init_test("count_yields_after_budget_on_always_ready_stream");
        let mut future = Count::new(AlwaysReadyCounter::new(COUNT_COOPERATIVE_BUDGET + 5));
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
        crate::assert_with_log!(
            future.total == COUNT_COOPERATIVE_BUDGET,
            "count preserved across yield",
            COUNT_COOPERATIVE_BUDGET,
            future.total
        );
        crate::assert_with_log!(
            future.stream.next == COUNT_COOPERATIVE_BUDGET,
            "upstream advanced only to budget",
            COUNT_COOPERATIVE_BUDGET,
            future.stream.next
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "self-wake requested",
            true,
            woke.load(Ordering::SeqCst)
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            second == Poll::Ready(COUNT_COOPERATIVE_BUDGET + 5),
            "second poll completes count",
            Poll::Ready(COUNT_COOPERATIVE_BUDGET + 5),
            second
        );
        crate::test_complete!("count_yields_after_budget_on_always_ready_stream");
    }

    #[test]
    fn count_repoll_panics_after_completion() {
        init_test("count_repoll_panics_after_completion");
        let mut future = Count::new(OneThenDoneThenPanicStream::default());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            first == Poll::Ready(1),
            "first poll counts item",
            Poll::Ready(1),
            first
        );

        let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Pin::new(&mut future).poll(&mut cx)
        }));
        let payload = second.expect_err("repoll after completion must panic");
        let message = payload
            .downcast_ref::<&str>()
            .map(ToString::to_string)
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        crate::assert_with_log!(
            message.contains("Count polled after completion"),
            "second poll fails closed",
            true,
            message.contains("Count polled after completion")
        );
        crate::test_complete!("count_repoll_panics_after_completion");
    }

    #[test]
    fn count_empty_repoll_panics_after_completion() {
        init_test("count_empty_repoll_panics_after_completion");
        let mut future = Count::new(iter(Vec::<usize>::new()));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            first == Poll::Ready(0),
            "first poll returns empty count",
            Poll::Ready(0),
            first
        );

        let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Pin::new(&mut future).poll(&mut cx)
        }));
        let payload = second.expect_err("repoll after completion must panic");
        let message = payload
            .downcast_ref::<&str>()
            .map(ToString::to_string)
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        crate::assert_with_log!(
            message.contains("Count polled after completion"),
            "second poll fails closed",
            true,
            message.contains("Count polled after completion")
        );
        crate::test_complete!("count_empty_repoll_panics_after_completion");
    }
}
