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
        if *this.completed {
            return Poll::Pending;
        }
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
    use super::*;
    use crate::stream::iter;
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
    fn fold_repoll_after_completion_returns_pending_without_repolling_upstream() {
        init_test("fold_repoll_after_completion_returns_pending_without_repolling_upstream");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut future = Fold::new(
            PollCountingEmptyStream::new(Arc::clone(&polls)),
            7usize,
            |acc, item| acc + item,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            first == Poll::Ready(7),
            "first poll completes empty fold",
            Poll::Ready(7),
            first
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "first completion polls upstream once",
            1,
            polls.load(Ordering::SeqCst)
        );

        let repoll = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            repoll == Poll::<usize>::Pending,
            "repoll returns pending",
            Poll::<usize>::Pending,
            repoll
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "repoll does not touch upstream again",
            1,
            polls.load(Ordering::SeqCst)
        );

        crate::test_complete!(
            "fold_repoll_after_completion_returns_pending_without_repolling_upstream"
        );
    }
}
