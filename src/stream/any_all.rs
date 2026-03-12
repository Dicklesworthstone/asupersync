//! Any and All combinators for streams.
//!
//! The `Any` future checks if any item matches a predicate.
//! The `All` future checks if all items match a predicate.

use super::Stream;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items scanned in a single poll.
///
/// Without this cap, always-ready upstream streams can monopolize an executor
/// turn when `Any`/`All` do not hit an early-exit condition.
const ANY_ALL_COOPERATIVE_BUDGET: usize = 1024;

/// A future that checks if any item in a stream matches a predicate.
///
/// Created by [`StreamExt::any`](super::StreamExt::any).
#[pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Any<S, P> {
    #[pin]
    stream: S,
    predicate: P,
    result: Option<bool>,
}

impl<S, P> Any<S, P> {
    /// Creates a new `Any` future.
    pub(crate) fn new(stream: S, predicate: P) -> Self {
        Self {
            stream,
            predicate,
            result: None,
        }
    }
}

impl<S, P> Future for Any<S, P>
where
    S: Stream,
    P: FnMut(&S::Item) -> bool,
{
    type Output = bool;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<bool> {
        let mut this = self.project();
        assert!(this.result.is_none(), "Any polled after completion");
        let mut scanned_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if (this.predicate)(&item) {
                        *this.result = Some(true);
                        return Poll::Ready(true);
                    }

                    scanned_this_poll += 1;
                    if scanned_this_poll >= ANY_ALL_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.result = Some(false);
                    return Poll::Ready(false);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A future that checks if all items in a stream match a predicate.
///
/// Created by [`StreamExt::all`](super::StreamExt::all).
#[pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct All<S, P> {
    #[pin]
    stream: S,
    predicate: P,
    result: Option<bool>,
}

impl<S, P> All<S, P> {
    /// Creates a new `All` future.
    pub(crate) fn new(stream: S, predicate: P) -> Self {
        Self {
            stream,
            predicate,
            result: None,
        }
    }
}

impl<S, P> Future for All<S, P>
where
    S: Stream,
    P: FnMut(&S::Item) -> bool,
{
    type Output = bool;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<bool> {
        let mut this = self.project();
        assert!(this.result.is_none(), "All polled after completion");
        let mut scanned_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if !(this.predicate)(&item) {
                        *this.result = Some(false);
                        return Poll::Ready(false);
                    }

                    scanned_this_poll += 1;
                    if scanned_this_poll >= ANY_ALL_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.result = Some(true);
                    return Poll::Ready(true);
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
    use std::task::{Poll, Wake, Waker};

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
    struct MatchThenPanicStream {
        emitted: bool,
    }

    impl Stream for MatchThenPanicStream {
        type Item = usize;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            assert!(
                !self.emitted,
                "inner stream repolled after early completion"
            );

            self.emitted = true;
            Poll::Ready(Some(1))
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
                Poll::Ready(Some(2))
            }
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn any_found() {
        init_test("any_found");
        let mut future = Any::new(iter(vec![1i32, 2, 3, 4, 5]), |&x: &i32| x > 3);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(found) => {
                crate::assert_with_log!(found, "any found", true, found);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("any_found");
    }

    #[test]
    fn any_not_found() {
        init_test("any_not_found");
        let mut future = Any::new(iter(vec![1i32, 2, 3]), |&x: &i32| x > 5);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(found) => {
                crate::assert_with_log!(!found, "any not found", false, found);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("any_not_found");
    }

    #[test]
    fn any_empty() {
        init_test("any_empty");
        let mut future = Any::new(iter(Vec::<i32>::new()), |_: &i32| true);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(found) => {
                crate::assert_with_log!(!found, "empty false", false, found);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("any_empty");
    }

    #[test]
    fn all_pass() {
        init_test("all_pass");
        let mut future = All::new(iter(vec![2i32, 4, 6, 8]), |&x: &i32| x % 2 == 0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(all_pass) => {
                crate::assert_with_log!(all_pass, "all pass", true, all_pass);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("all_pass");
    }

    #[test]
    fn all_fail() {
        init_test("all_fail");
        let mut future = All::new(iter(vec![2i32, 4, 5, 8]), |&x: &i32| x % 2 == 0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(all_pass) => {
                crate::assert_with_log!(!all_pass, "all fail", false, all_pass);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("all_fail");
    }

    #[test]
    fn all_empty() {
        init_test("all_empty");
        let mut future = All::new(iter(Vec::<i32>::new()), |_: &i32| false);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(all_pass) => {
                crate::assert_with_log!(all_pass, "empty true", true, all_pass);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("all_empty");
    }

    #[test]
    fn any_yields_after_budget_when_predicate_never_matches() {
        init_test("any_yields_after_budget_when_predicate_never_matches");
        let mut future = Any::new(
            AlwaysReadyCounter::new(ANY_ALL_COOPERATIVE_BUDGET + 5),
            |_: &usize| false,
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
        crate::assert_with_log!(
            future.stream.next == ANY_ALL_COOPERATIVE_BUDGET,
            "upstream advanced only to budget",
            ANY_ALL_COOPERATIVE_BUDGET,
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
            second == Poll::Ready(false),
            "second poll completes with no match",
            Poll::Ready(false),
            second
        );
        crate::test_complete!("any_yields_after_budget_when_predicate_never_matches");
    }

    #[test]
    fn all_yields_after_budget_when_predicate_stays_true() {
        init_test("all_yields_after_budget_when_predicate_stays_true");
        let mut future = All::new(
            AlwaysReadyCounter::new(ANY_ALL_COOPERATIVE_BUDGET + 5),
            |_: &usize| true,
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
        crate::assert_with_log!(
            future.stream.next == ANY_ALL_COOPERATIVE_BUDGET,
            "upstream advanced only to budget",
            ANY_ALL_COOPERATIVE_BUDGET,
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
            second == Poll::Ready(true),
            "second poll completes with all true",
            Poll::Ready(true),
            second
        );
        crate::test_complete!("all_yields_after_budget_when_predicate_stays_true");
    }

    #[test]
    fn any_repoll_panics_after_completion() {
        init_test("any_repoll_panics_after_completion");
        let mut future = Any::new(MatchThenPanicStream::default(), |_: &usize| true);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            first == Poll::Ready(true),
            "first poll finds match",
            Poll::Ready(true),
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
            message.contains("Any polled after completion"),
            "second poll fails closed",
            true,
            message.contains("Any polled after completion")
        );
        crate::test_complete!("any_repoll_panics_after_completion");
    }

    #[test]
    fn all_repoll_panics_after_completion() {
        init_test("all_repoll_panics_after_completion");
        let mut future = All::new(OneThenDoneThenPanicStream::default(), |_: &usize| true);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            first == Poll::Ready(true),
            "first poll exhausts stream",
            Poll::Ready(true),
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
            message.contains("All polled after completion"),
            "second poll fails closed",
            true,
            message.contains("All polled after completion")
        );
        crate::test_complete!("all_repoll_panics_after_completion");
    }
}
