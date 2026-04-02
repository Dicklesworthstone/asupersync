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
    use super::*;
    use crate::stream::iter;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
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
            Poll::Pending => panic!("expected Ready"),
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
            Poll::Pending => panic!("expected Ready"),
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
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("count_single");
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
