//! Collect combinator for streams.
//!
//! The `Collect` future consumes a stream and collects all items into a collection.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items drained in a single poll.
///
/// Without this cap, `Collect` can monopolize an executor turn when the
/// upstream stream stays always-ready for long runs.
const COLLECT_COOPERATIVE_BUDGET: usize = 1024;

/// A future that collects all items from a stream into a collection.
///
/// Created by [`StreamExt::collect`](super::StreamExt::collect).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Collect<S, C> {
    stream: S,
    collection: C,
    completed: bool,
}

impl<S, C> Collect<S, C> {
    /// Creates a new `Collect` future.
    pub(crate) fn new(stream: S, collection: C) -> Self {
        Self {
            stream,
            collection,
            completed: false,
        }
    }
}

impl<S: Unpin, C> Unpin for Collect<S, C> {}

impl<S, C> Future for Collect<S, C>
where
    S: Stream + Unpin,
    C: Default + Extend<S::Item>,
{
    type Output = C;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<C> {
        assert!(
            !self.completed,
            "Collect polled after completion; terminal output cannot be replayed soundly"
        );
        let mut collected_this_poll = 0usize;
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.collection.extend(std::iter::once(item));
                    collected_this_poll += 1;
                    if collected_this_poll >= COLLECT_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    self.completed = true;
                    return Poll::Ready(std::mem::take(&mut self.collection));
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
    use std::collections::HashSet;
    use std::panic::{AssertUnwindSafe, catch_unwind};
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
    struct PanicOnRepollStream {
        items: Vec<usize>,
        next: usize,
        completed: bool,
        polls: Arc<AtomicUsize>,
    }

    impl PanicOnRepollStream {
        fn new(items: Vec<usize>, polls: Arc<AtomicUsize>) -> Self {
            Self {
                items,
                next: 0,
                completed: false,
                polls,
            }
        }
    }

    impl Stream for PanicOnRepollStream {
        type Item = usize;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            assert!(!self.completed, "inner stream repolled after completion");

            if self.next >= self.items.len() {
                self.completed = true;
                return Poll::Ready(None);
            }

            let item = self.items[self.next];
            self.next += 1;
            Poll::Ready(Some(item))
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn collect_to_vec() {
        init_test("collect_to_vec");
        let mut future = Collect::new(iter(vec![1i32, 2, 3]), Vec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(collected) => {
                let ok = collected == vec![1, 2, 3];
                crate::assert_with_log!(ok, "collected vec", vec![1, 2, 3], collected);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("collect_to_vec");
    }

    #[test]
    fn collect_to_hashset() {
        init_test("collect_to_hashset");
        let mut future = Collect::new(iter(vec![1i32, 2, 2, 3, 3, 3]), HashSet::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(collected) => {
                let len = collected.len();
                let ok = len == 3;
                crate::assert_with_log!(ok, "set len", 3, len);
                let has_one = collected.contains(&1);
                crate::assert_with_log!(has_one, "contains 1", true, has_one);
                let has_two = collected.contains(&2);
                crate::assert_with_log!(has_two, "contains 2", true, has_two);
                let has_three = collected.contains(&3);
                crate::assert_with_log!(has_three, "contains 3", true, has_three);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("collect_to_hashset");
    }

    #[test]
    fn collect_empty() {
        init_test("collect_empty");
        let mut future = Collect::new(iter(Vec::<i32>::new()), Vec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(collected) => {
                let empty = collected.is_empty();
                crate::assert_with_log!(empty, "collected empty", true, empty);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("collect_empty");
    }

    /// Invariant: collect works with String (via Extend<char>).
    #[test]
    fn collect_to_string() {
        init_test("collect_to_string");
        let mut future = Collect::new(iter(vec!['h', 'i', '!']), String::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(collected) => {
                let ok = collected == "hi!";
                crate::assert_with_log!(ok, "collected string", "hi!", collected);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("collect_to_string");
    }

    #[test]
    fn collect_yields_after_budget_on_always_ready_stream() {
        init_test("collect_yields_after_budget_on_always_ready_stream");
        let mut future = Collect::new(
            AlwaysReadyCounter::new(COLLECT_COOPERATIVE_BUDGET + 5),
            Vec::new(),
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
            future.collection.len() == COLLECT_COOPERATIVE_BUDGET,
            "partial collection retained across yield",
            COLLECT_COOPERATIVE_BUDGET,
            future.collection.len()
        );
        crate::assert_with_log!(
            future.stream.next == COLLECT_COOPERATIVE_BUDGET,
            "upstream advanced only to budget",
            COLLECT_COOPERATIVE_BUDGET,
            future.stream.next
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "self-wake requested",
            true,
            woke.load(Ordering::SeqCst)
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        let expected: Vec<usize> = (0..COLLECT_COOPERATIVE_BUDGET + 5).collect();
        crate::assert_with_log!(
            matches!(&second, Poll::Ready(collected) if collected == &expected),
            "second poll completes collection",
            &expected,
            second
        );
        crate::test_complete!("collect_yields_after_budget_on_always_ready_stream");
    }

    #[test]
    fn collect_repoll_after_completion_panics_without_repolling_upstream() {
        init_test("collect_repoll_after_completion_panics_without_repolling_upstream");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut future = Collect::new(
            PanicOnRepollStream::new(vec![1, 2, 3], Arc::clone(&polls)),
            Vec::new(),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(&first, Poll::Ready(collected) if collected == &vec![1, 2, 3]),
            "first poll collects terminal output",
            &vec![1, 2, 3],
            first
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 4,
            "upstream polled through terminal completion exactly once",
            4,
            polls.load(Ordering::SeqCst)
        );

        let repoll = catch_unwind(AssertUnwindSafe(|| Pin::new(&mut future).poll(&mut cx)));
        crate::assert_with_log!(
            repoll.is_err(),
            "re-poll after completion must fail closed",
            true,
            repoll.is_err()
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 4,
            "completed collect must not re-poll upstream",
            4,
            polls.load(Ordering::SeqCst)
        );
        crate::test_complete!("collect_repoll_after_completion_panics_without_repolling_upstream");
    }
}
