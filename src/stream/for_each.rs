//! ForEach combinator for streams.
//!
//! The `ForEach` future consumes a stream and executes a closure for each item.

use super::Stream;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items processed in a single poll.
///
/// Without this bound, always-ready streams can monopolize one executor turn.
const FOR_EACH_COOPERATIVE_BUDGET: usize = 1024;

/// A future that executes a closure for each item in a stream.
///
/// Created by [`StreamExt::for_each`](super::StreamExt::for_each).
#[pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ForEach<S, F> {
    #[pin]
    stream: S,
    f: F,
    completed: bool,
}

impl<S, F> ForEach<S, F> {
    /// Creates a new `ForEach` future.
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            completed: false,
        }
    }
}

impl<S, F> Future for ForEach<S, F>
where
    S: Stream,
    F: FnMut(S::Item),
{
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut this = self.project();
        if *this.completed {
            return Poll::Ready(());
        }
        let mut processed_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    (this.f)(item);
                    processed_this_poll += 1;
                    if processed_this_poll >= FOR_EACH_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.completed = true;
                    return Poll::Ready(());
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A future that executes an async closure for each item in a stream.
///
/// Created by [`StreamExt::for_each_async`](super::StreamExt::for_each_async).
#[pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ForEachAsync<S, F, Fut> {
    #[pin]
    stream: S,
    f: F,
    #[pin]
    pending: Option<Fut>,
    completed: bool,
}

impl<S, F, Fut> ForEachAsync<S, F, Fut> {
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            pending: None,
            completed: false,
        }
    }
}

impl<S, F, Fut> Future for ForEachAsync<S, F, Fut>
where
    S: Stream,
    F: FnMut(S::Item) -> Fut,
    Fut: Future<Output = ()>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut this = self.project();
        if *this.completed {
            return Poll::Ready(());
        }
        let mut processed_this_poll = 0usize;
        loop {
            // Complete pending future first
            if let Some(fut) = this.pending.as_mut().as_pin_mut() {
                match fut.poll(cx) {
                    Poll::Ready(()) => {
                        this.pending.set(None);
                        processed_this_poll += 1;
                        if processed_this_poll >= FOR_EACH_COOPERATIVE_BUDGET {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Get next item
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    this.pending.set(Some((this.f)(item)));
                }
                Poll::Ready(None) => {
                    *this.completed = true;
                    return Poll::Ready(());
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
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
                Poll::Ready(Some(7))
            }
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
    fn for_each_collects_side_effects() {
        init_test("for_each_collects_side_effects");
        let results = RefCell::new(Vec::new());
        let mut future = ForEach::new(iter(vec![1i32, 2, 3]), |x| {
            results.borrow_mut().push(x);
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(()) => {
                let collected = results.borrow().clone();
                let ok = collected == vec![1, 2, 3];
                crate::assert_with_log!(ok, "collected", vec![1, 2, 3], collected);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("for_each_collects_side_effects");
    }

    #[test]
    fn for_each_empty() {
        init_test("for_each_empty");
        let mut called = false;
        let mut future = ForEach::new(iter(Vec::<i32>::new()), |_| {
            called = true;
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(()) => {
                crate::assert_with_log!(!called, "not called", false, called);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("for_each_empty");
    }

    #[test]
    fn for_each_async() {
        init_test("for_each_async");
        let results = RefCell::new(Vec::new());
        let mut future = ForEachAsync::new(iter(vec![1i32, 2, 3]), |x| {
            let res = &results;
            Box::pin(async move {
                res.borrow_mut().push(x);
            })
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // This test requires re-polling because async block yields?
        // No, Box::pin(async { ... }) is ready immediately if no await.
        // But ForEachAsync needs to poll the future.

        // We simulate polling loop
        loop {
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(()) => break,
                Poll::Pending => {} // Should not happen for immediate futures but safe
            }
        }

        let collected = results.borrow().clone();
        let ok = collected == vec![1, 2, 3];
        crate::assert_with_log!(ok, "collected", vec![1, 2, 3], collected);
        crate::test_complete!("for_each_async");
    }

    /// Invariant: ForEachAsync with empty stream completes without calling the closure.
    #[test]
    fn for_each_async_empty() {
        init_test("for_each_async_empty");
        let mut called = false;
        let mut future = ForEachAsync::new(iter(Vec::<i32>::new()), |_x| {
            called = true;
            Box::pin(async {})
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut future).poll(&mut cx);
        let completed = matches!(poll, Poll::Ready(()));
        crate::assert_with_log!(completed, "async empty completes", true, completed);
        crate::assert_with_log!(!called, "closure not called", false, called);

        crate::test_complete!("for_each_async_empty");
    }

    #[test]
    fn for_each_yields_after_budget_on_always_ready_stream() {
        init_test("for_each_yields_after_budget_on_always_ready_stream");
        let seen = RefCell::new(Vec::new());
        let mut future = ForEach::new(
            AlwaysReadyCounter::new(FOR_EACH_COOPERATIVE_BUDGET + 5),
            |x| seen.borrow_mut().push(x),
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
            future.stream.next == FOR_EACH_COOPERATIVE_BUDGET,
            "upstream advanced only to budget",
            FOR_EACH_COOPERATIVE_BUDGET,
            future.stream.next
        );
        crate::assert_with_log!(
            seen.borrow().len() == FOR_EACH_COOPERATIVE_BUDGET,
            "side effects applied to budget items",
            FOR_EACH_COOPERATIVE_BUDGET,
            seen.borrow().len()
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "self-wake requested",
            true,
            woke.load(Ordering::SeqCst)
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(())),
            "second poll completes",
            "Poll::Ready(())",
            second
        );
        crate::assert_with_log!(
            seen.borrow().len() == FOR_EACH_COOPERATIVE_BUDGET + 5,
            "all side effects complete",
            FOR_EACH_COOPERATIVE_BUDGET + 5,
            seen.borrow().len()
        );
        crate::test_complete!("for_each_yields_after_budget_on_always_ready_stream");
    }

    #[test]
    fn for_each_async_yields_after_budget_on_immediate_futures() {
        init_test("for_each_async_yields_after_budget_on_immediate_futures");
        let seen = RefCell::new(Vec::new());
        let mut future = ForEachAsync::new(
            AlwaysReadyCounter::new(FOR_EACH_COOPERATIVE_BUDGET + 5),
            |x| {
                let seen = &seen;
                Box::pin(async move {
                    seen.borrow_mut().push(x);
                })
            },
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
            future.stream.next == FOR_EACH_COOPERATIVE_BUDGET,
            "upstream advanced only to budget",
            FOR_EACH_COOPERATIVE_BUDGET,
            future.stream.next
        );
        crate::assert_with_log!(
            future.pending.is_none(),
            "no pending future left at cooperative boundary",
            true,
            future.pending.is_none()
        );
        crate::assert_with_log!(
            seen.borrow().len() == FOR_EACH_COOPERATIVE_BUDGET,
            "side effects applied to budget items",
            FOR_EACH_COOPERATIVE_BUDGET,
            seen.borrow().len()
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "self-wake requested",
            true,
            woke.load(Ordering::SeqCst)
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(())),
            "second poll completes",
            "Poll::Ready(())",
            second
        );
        crate::assert_with_log!(
            seen.borrow().len() == FOR_EACH_COOPERATIVE_BUDGET + 5,
            "all side effects complete",
            FOR_EACH_COOPERATIVE_BUDGET + 5,
            seen.borrow().len()
        );
        crate::test_complete!("for_each_async_yields_after_budget_on_immediate_futures");
    }

    #[test]
    fn for_each_repoll_after_completion_fails_closed_without_repolling_upstream() {
        init_test("for_each_repoll_after_completion_fails_closed_without_repolling_upstream");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut future = ForEach::new(PollCountingEmptyStream::new(Arc::clone(&polls)), |_| {});
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(())),
            "first poll completes",
            "Poll::Ready(())",
            first
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "first completion polls upstream once",
            1,
            polls.load(Ordering::SeqCst)
        );

        // Fail-closed: repoll returns Ready(()) instead of panicking
        let repoll = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(repoll, Poll::Ready(())),
            "repoll returns Ready(())",
            "Poll::Ready(())",
            repoll
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "repoll does not touch upstream again",
            1,
            polls.load(Ordering::SeqCst)
        );
        crate::test_complete!(
            "for_each_repoll_after_completion_fails_closed_without_repolling_upstream"
        );
    }

    #[test]
    fn for_each_async_repoll_after_completion_fails_closed_without_repolling_upstream() {
        init_test("for_each_async_repoll_after_completion_fails_closed_without_repolling_upstream");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut future =
            ForEachAsync::new(PollCountingEmptyStream::new(Arc::clone(&polls)), |_| {
                Box::pin(async {})
            });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(())),
            "first poll completes",
            "Poll::Ready(())",
            first
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "first completion polls upstream once",
            1,
            polls.load(Ordering::SeqCst)
        );

        // Fail-closed: repoll returns Ready(()) instead of panicking
        let repoll = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(repoll, Poll::Ready(())),
            "repoll returns Ready(())",
            "Poll::Ready(())",
            repoll
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "repoll does not touch upstream again",
            1,
            polls.load(Ordering::SeqCst)
        );
        crate::test_complete!(
            "for_each_async_repoll_after_completion_fails_closed_without_repolling_upstream"
        );
    }
}
