//! Try combinators for streams of Results.
//!
//! These combinators short-circuit on the first error.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Error returned by try-stream terminal combinators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TryStreamError<E> {
    /// The wrapped stream or closure returned an error.
    Inner(E),
    /// The same future was polled again after it already returned `Ready`.
    PolledAfterCompletion,
}

impl<E: std::fmt::Display> std::fmt::Display for TryStreamError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(err) => err.fmt(f),
            Self::PolledAfterCompletion => {
                write!(f, "try_stream future polled after completion")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for TryStreamError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(err) => Some(err),
            Self::PolledAfterCompletion => None,
        }
    }
}

impl<E> From<E> for TryStreamError<E> {
    #[inline]
    fn from(value: E) -> Self {
        Self::Inner(value)
    }
}

/// Cooperative budget for success-path items drained in a single poll.
///
/// Without this bound, an always-ready success-heavy stream can monopolize one
/// executor turn while these terminal futures drain the entire input.
const TRY_STREAM_COOPERATIVE_BUDGET: usize = 1024;

/// A future that collects items from a stream of Results.
///
/// Short-circuits on the first error.
///
/// Created by [`StreamExt::try_collect`](super::StreamExt::try_collect).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct TryCollect<S, C> {
    stream: S,
    collection: C,
    completed: bool,
}

impl<S, C> TryCollect<S, C> {
    /// Creates a new `TryCollect` future.
    #[inline]
    pub(crate) fn new(stream: S, collection: C) -> Self {
        Self {
            stream,
            collection,
            completed: false,
        }
    }
}

impl<S: Unpin, C> Unpin for TryCollect<S, C> {}

impl<S, T, E, C> Future for TryCollect<S, C>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    C: Default + Extend<T>,
{
    type Output = Result<C, TryStreamError<E>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(TryStreamError::PolledAfterCompletion));
        }
        let mut processed_this_poll = 0usize;
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(item))) => {
                    self.collection.extend(std::iter::once(item));
                    processed_this_poll += 1;
                    if processed_this_poll >= TRY_STREAM_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    self.completed = true;
                    return Poll::Ready(Err(TryStreamError::Inner(e)));
                }
                Poll::Ready(None) => {
                    self.completed = true;
                    return Poll::Ready(Ok(std::mem::take(&mut self.collection)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A future that folds items from a stream of Results.
///
/// Short-circuits on the first error.
///
/// Created by [`StreamExt::try_fold`](super::StreamExt::try_fold).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct TryFold<S, F, Acc> {
    stream: S,
    f: F,
    acc: Option<Acc>,
    completed: bool,
}

impl<S, F, Acc> TryFold<S, F, Acc> {
    /// Creates a new `TryFold` future.
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

impl<S: Unpin, F, Acc> Unpin for TryFold<S, F, Acc> {}

impl<S, F, Acc, T, E> Future for TryFold<S, F, Acc>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    F: FnMut(Acc, T) -> Result<Acc, E>,
{
    type Output = Result<Acc, TryStreamError<E>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(TryStreamError::PolledAfterCompletion));
        }
        let mut processed_this_poll = 0usize;
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(item))) => {
                    let acc = self
                        .acc
                        .take()
                        .expect("TryFold accumulator missing before completion");
                    match (self.f)(acc, item) {
                        Ok(new_acc) => self.acc = Some(new_acc),
                        Err(e) => {
                            self.completed = true;
                            return Poll::Ready(Err(TryStreamError::Inner(e)));
                        }
                    }
                    processed_this_poll += 1;
                    if processed_this_poll >= TRY_STREAM_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    self.completed = true;
                    return Poll::Ready(Err(TryStreamError::Inner(e)));
                }
                Poll::Ready(None) => {
                    self.completed = true;
                    return Poll::Ready(Ok(self
                        .acc
                        .take()
                        .expect("TryFold accumulator missing on completion")));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A future that executes a fallible closure for each item.
///
/// Short-circuits on the first error.
///
/// Created by [`StreamExt::try_for_each`](super::StreamExt::try_for_each).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct TryForEach<S, F> {
    stream: S,
    f: F,
    completed: bool,
}

impl<S, F> TryForEach<S, F> {
    /// Creates a new `TryForEach` future.
    #[inline]
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            completed: false,
        }
    }
}

impl<S: Unpin, F> Unpin for TryForEach<S, F> {}

impl<S, F, E> Future for TryForEach<S, F>
where
    S: Stream + Unpin,
    F: FnMut(S::Item) -> Result<(), E>,
{
    type Output = Result<(), TryStreamError<E>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(TryStreamError::PolledAfterCompletion));
        }
        let mut processed_this_poll = 0usize;
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if let Err(e) = (self.f)(item) {
                        self.completed = true;
                        return Poll::Ready(Err(TryStreamError::Inner(e)));
                    }
                    processed_this_poll += 1;
                    if processed_this_poll >= TRY_STREAM_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    self.completed = true;
                    return Poll::Ready(Ok(()));
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
    struct AlwaysReadyOkStream {
        next: usize,
        end: usize,
    }

    impl AlwaysReadyOkStream {
        fn new(end: usize) -> Self {
            Self { next: 0, end }
        }
    }

    impl Stream for AlwaysReadyOkStream {
        type Item = Result<usize, &'static str>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.next >= self.end {
                return Poll::Ready(None);
            }

            let item = self.next;
            self.next += 1;
            Poll::Ready(Some(Ok(item)))
        }
    }

    #[derive(Debug, Default)]
    struct AlwaysReadyValueStream {
        next: usize,
        end: usize,
    }

    impl AlwaysReadyValueStream {
        fn new(end: usize) -> Self {
            Self { next: 0, end }
        }
    }

    impl Stream for AlwaysReadyValueStream {
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
    struct PollCountingEmptyTryStream {
        polls: Arc<AtomicUsize>,
    }

    impl PollCountingEmptyTryStream {
        fn new(polls: Arc<AtomicUsize>) -> Self {
            Self { polls }
        }
    }

    impl Stream for PollCountingEmptyTryStream {
        type Item = Result<i32, &'static str>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(None)
        }
    }

    #[derive(Debug)]
    struct PollCountingEmptyValueStream {
        polls: Arc<AtomicUsize>,
    }

    impl PollCountingEmptyValueStream {
        fn new(polls: Arc<AtomicUsize>) -> Self {
            Self { polls }
        }
    }

    impl Stream for PollCountingEmptyValueStream {
        type Item = i32;

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
    fn try_collect_success() {
        init_test("try_collect_success");
        let items: Vec<Result<i32, &str>> = vec![Ok(1), Ok(2), Ok(3)];
        let mut future = TryCollect::new(iter(items), Vec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Ok(collected)) => {
                let ok = collected == vec![1, 2, 3];
                crate::assert_with_log!(ok, "collected", vec![1, 2, 3], collected);
            }
            Poll::Ready(Err(_)) => panic!("expected Ok"),
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("try_collect_success");
    }

    #[test]
    fn try_collect_error() {
        init_test("try_collect_error");
        let items: Vec<Result<i32, &str>> = vec![Ok(1), Err("error"), Ok(3)];
        let mut future = TryCollect::new(iter(items), Vec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Err(TryStreamError::Inner(e))) => {
                let ok = e == "error";
                crate::assert_with_log!(ok, "error", "error", e);
            }
            Poll::Ready(Err(TryStreamError::PolledAfterCompletion)) => {
                panic!("unexpected PolledAfterCompletion")
            }
            Poll::Ready(Ok(_)) => panic!("expected Err"),
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("try_collect_error");
    }

    #[test]
    fn try_collect_empty() {
        init_test("try_collect_empty");
        let items: Vec<Result<i32, &str>> = vec![];
        let mut future = TryCollect::new(iter(items), Vec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Ok(collected)) => {
                let empty = collected.is_empty();
                crate::assert_with_log!(empty, "collected empty", true, empty);
            }
            Poll::Ready(Err(_)) => panic!("expected Ok"),
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("try_collect_empty");
    }

    #[test]
    fn try_fold_success() {
        init_test("try_fold_success");
        let items: Vec<Result<i32, &str>> = vec![Ok(1), Ok(2), Ok(3)];
        let mut future = TryFold::new(iter(items), 0i32, |acc, x| Ok(acc + x));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Ok(sum)) => {
                let ok = sum == 6;
                crate::assert_with_log!(ok, "sum", 6, sum);
            }
            Poll::Ready(Err(_)) => panic!("expected Ok"),
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("try_fold_success");
    }

    #[test]
    fn try_fold_stream_error() {
        init_test("try_fold_stream_error");
        let items: Vec<Result<i32, &str>> = vec![Ok(1), Err("stream error"), Ok(3)];
        let mut future = TryFold::new(iter(items), 0i32, |acc, x| Ok(acc + x));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Err(TryStreamError::Inner(e))) => {
                let ok = e == "stream error";
                crate::assert_with_log!(ok, "stream error", "stream error", e);
            }
            Poll::Ready(Err(TryStreamError::PolledAfterCompletion)) => {
                panic!("unexpected PolledAfterCompletion")
            }
            Poll::Ready(Ok(_)) => panic!("expected Err"),
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("try_fold_stream_error");
    }

    #[test]
    fn try_fold_closure_error() {
        init_test("try_fold_closure_error");
        let items: Vec<Result<i32, &str>> = vec![Ok(1), Ok(2), Ok(3)];
        let mut future = TryFold::new(iter(items), 0i32, |acc, x| {
            if x == 2 {
                Err("closure error")
            } else {
                Ok(acc + x)
            }
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Err(TryStreamError::Inner(e))) => {
                let ok = e == "closure error";
                crate::assert_with_log!(ok, "closure error", "closure error", e);
            }
            Poll::Ready(Err(TryStreamError::PolledAfterCompletion)) => {
                panic!("unexpected PolledAfterCompletion")
            }
            Poll::Ready(Ok(_)) => panic!("expected Err"),
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("try_fold_closure_error");
    }

    #[test]
    fn try_fold_repoll_after_completion_does_not_repoll_stream() {
        init_test("try_fold_repoll_after_completion_does_not_repoll_stream");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut future = TryFold::new(
            PollCountingEmptyTryStream::new(polls.clone()),
            7i32,
            |acc, x| Ok::<i32, &'static str>(acc + x),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            first == Poll::Ready(Ok(7)),
            "first poll returns final accumulator",
            Poll::Ready(Ok::<i32, TryStreamError<&'static str>>(7)),
            first
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "first poll touches upstream once",
            1,
            polls.load(Ordering::SeqCst)
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(
                second,
                Poll::Ready(Err(TryStreamError::<&'static str>::PolledAfterCompletion))
            ),
            "second poll fails closed",
            "Poll::Ready(Err(TryStreamError::PolledAfterCompletion))",
            second
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "second poll does not touch upstream",
            1,
            polls.load(Ordering::SeqCst)
        );
        crate::test_complete!("try_fold_repoll_after_completion_does_not_repoll_stream");
    }

    #[test]
    fn try_collect_repoll_after_completion_does_not_repoll_stream() {
        init_test("try_collect_repoll_after_completion_does_not_repoll_stream");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut future = TryCollect::new(
            PollCountingEmptyTryStream::new(polls.clone()),
            Vec::<i32>::new(),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            first == Poll::Ready(Ok::<Vec<i32>, TryStreamError<&'static str>>(Vec::new())),
            "first poll completes empty collect",
            Poll::Ready(Ok::<Vec<i32>, TryStreamError<&'static str>>(Vec::new())),
            first
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "first poll touches upstream once",
            1,
            polls.load(Ordering::SeqCst)
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(
                second,
                Poll::Ready(Err(TryStreamError::<&'static str>::PolledAfterCompletion))
            ),
            "second poll fails closed",
            "Poll::Ready(Err(TryStreamError::PolledAfterCompletion))",
            second
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "second poll does not touch upstream",
            1,
            polls.load(Ordering::SeqCst)
        );
        crate::test_complete!("try_collect_repoll_after_completion_does_not_repoll_stream");
    }

    #[test]
    fn try_for_each_success() {
        init_test("try_for_each_success");
        let mut results = Vec::new();
        let mut future = TryForEach::new(iter(vec![1i32, 2, 3]), |x| {
            results.push(x);
            Ok::<(), &str>(())
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Ok(())) => {
                let ok = results == vec![1, 2, 3];
                crate::assert_with_log!(ok, "results", vec![1, 2, 3], results);
            }
            Poll::Ready(Err(_)) => panic!("expected Ok"),
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("try_for_each_success");
    }

    #[test]
    fn try_for_each_error() {
        init_test("try_for_each_error");
        let mut results = Vec::new();
        let mut future = TryForEach::new(iter(vec![1i32, 2, 3]), |x| {
            if x == 2 {
                Err("error at 2")
            } else {
                results.push(x);
                Ok(())
            }
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Err(TryStreamError::Inner(e))) => {
                let err_ok = e == "error at 2";
                crate::assert_with_log!(err_ok, "error", "error at 2", e);
                let ok = results == vec![1];
                crate::assert_with_log!(ok, "results", vec![1], results);
            }
            Poll::Ready(Err(TryStreamError::PolledAfterCompletion)) => {
                panic!("unexpected PolledAfterCompletion")
            }
            Poll::Ready(Ok(())) => panic!("expected Err"),
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("try_for_each_error");
    }

    #[test]
    fn try_for_each_repoll_after_completion_does_not_repoll_stream() {
        init_test("try_for_each_repoll_after_completion_does_not_repoll_stream");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut future = TryForEach::new(PollCountingEmptyValueStream::new(polls.clone()), |_| {
            Ok::<(), &'static str>(())
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            first == Poll::Ready(Ok::<(), TryStreamError<&'static str>>(())),
            "first poll completes empty for_each",
            Poll::Ready(Ok::<(), TryStreamError<&'static str>>(())),
            first
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "first poll touches upstream once",
            1,
            polls.load(Ordering::SeqCst)
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(
                second,
                Poll::Ready(Err(TryStreamError::<&'static str>::PolledAfterCompletion))
            ),
            "second poll fails closed",
            "Poll::Ready(Err(TryStreamError::PolledAfterCompletion))",
            second
        );
        crate::assert_with_log!(
            polls.load(Ordering::SeqCst) == 1,
            "second poll does not touch upstream",
            1,
            polls.load(Ordering::SeqCst)
        );
        crate::test_complete!("try_for_each_repoll_after_completion_does_not_repoll_stream");
    }

    #[test]
    fn try_collect_yields_after_budget_on_always_ready_success_stream() {
        init_test("try_collect_yields_after_budget_on_always_ready_success_stream");
        let mut future = TryCollect::new(
            AlwaysReadyOkStream::new(TRY_STREAM_COOPERATIVE_BUDGET + 5),
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
            future.collection.len() == TRY_STREAM_COOPERATIVE_BUDGET,
            "collection preserved across yield",
            TRY_STREAM_COOPERATIVE_BUDGET,
            future.collection.len()
        );
        crate::assert_with_log!(
            future.stream.next == TRY_STREAM_COOPERATIVE_BUDGET,
            "upstream advanced only to budget",
            TRY_STREAM_COOPERATIVE_BUDGET,
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
            second
                == Poll::Ready(Ok::<Vec<usize>, TryStreamError<&'static str>>(
                    (0..TRY_STREAM_COOPERATIVE_BUDGET + 5).collect(),
                )),
            "second poll completes collection",
            Poll::Ready(Ok::<Vec<usize>, TryStreamError<&'static str>>(
                (0..TRY_STREAM_COOPERATIVE_BUDGET + 5).collect::<Vec<_>>()
            )),
            second
        );
        crate::test_complete!("try_collect_yields_after_budget_on_always_ready_success_stream");
    }

    #[test]
    fn try_fold_yields_after_budget_on_always_ready_success_stream() {
        init_test("try_fold_yields_after_budget_on_always_ready_success_stream");
        let mut future = TryFold::new(
            AlwaysReadyOkStream::new(TRY_STREAM_COOPERATIVE_BUDGET + 5),
            0usize,
            |acc, x| Ok::<usize, &'static str>(acc + x),
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
            future.acc == Some((0..TRY_STREAM_COOPERATIVE_BUDGET).sum()),
            "accumulator preserved across yield",
            Some((0..TRY_STREAM_COOPERATIVE_BUDGET).sum::<usize>()),
            future.acc
        );
        crate::assert_with_log!(
            future.stream.next == TRY_STREAM_COOPERATIVE_BUDGET,
            "upstream advanced only to budget",
            TRY_STREAM_COOPERATIVE_BUDGET,
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
            second
                == Poll::Ready(Ok::<usize, TryStreamError<&'static str>>(
                    (0..TRY_STREAM_COOPERATIVE_BUDGET + 5).sum(),
                )),
            "second poll completes fold",
            Poll::Ready(Ok::<usize, TryStreamError<&'static str>>(
                (0..TRY_STREAM_COOPERATIVE_BUDGET + 5).sum::<usize>()
            )),
            second
        );
        crate::test_complete!("try_fold_yields_after_budget_on_always_ready_success_stream");
    }

    #[test]
    fn try_for_each_yields_after_budget_on_always_ready_success_stream() {
        use std::cell::RefCell;
        use std::rc::Rc;
        init_test("try_for_each_yields_after_budget_on_always_ready_success_stream");
        let results = Rc::new(RefCell::new(Vec::new()));
        let results_clone = results.clone();
        let mut future = TryForEach::new(
            AlwaysReadyValueStream::new(TRY_STREAM_COOPERATIVE_BUDGET + 5),
            move |x| {
                results_clone.borrow_mut().push(x);
                Ok::<(), &'static str>(())
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
            results.borrow().len() == TRY_STREAM_COOPERATIVE_BUDGET,
            "side effects preserved across yield",
            TRY_STREAM_COOPERATIVE_BUDGET,
            results.borrow().len()
        );
        crate::assert_with_log!(
            future.stream.next == TRY_STREAM_COOPERATIVE_BUDGET,
            "upstream advanced only to budget",
            TRY_STREAM_COOPERATIVE_BUDGET,
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
            second == Poll::Ready(Ok::<(), TryStreamError<&'static str>>(())),
            "second poll completes for_each",
            Poll::Ready(Ok::<(), TryStreamError<&'static str>>(())),
            second
        );
        crate::assert_with_log!(
            *results.borrow() == (0..TRY_STREAM_COOPERATIVE_BUDGET + 5).collect::<Vec<_>>(),
            "all side effects observed after completion",
            (0..TRY_STREAM_COOPERATIVE_BUDGET + 5).collect::<Vec<_>>(),
            *results.borrow()
        );
        crate::test_complete!("try_for_each_yields_after_budget_on_always_ready_success_stream");
    }
}
