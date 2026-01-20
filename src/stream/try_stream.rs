//! Try combinators for streams of Results.
//!
//! These combinators short-circuit on the first error.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

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
}

impl<S, C> TryCollect<S, C> {
    /// Creates a new `TryCollect` future.
    pub(crate) fn new(stream: S, collection: C) -> Self {
        Self { stream, collection }
    }
}

impl<S: Unpin, C> Unpin for TryCollect<S, C> {}

impl<S, T, E, C> Future for TryCollect<S, C>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    C: Default + Extend<T>,
{
    type Output = Result<C, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<C, E>> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(item))) => {
                    self.collection.extend(std::iter::once(item));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(None) => {
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
}

impl<S, F, Acc> TryFold<S, F, Acc> {
    /// Creates a new `TryFold` future.
    pub(crate) fn new(stream: S, init: Acc, f: F) -> Self {
        Self {
            stream,
            f,
            acc: Some(init),
        }
    }
}

impl<S: Unpin, F, Acc> Unpin for TryFold<S, F, Acc> {}

impl<S, F, Acc, T, E> Future for TryFold<S, F, Acc>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    F: FnMut(Acc, T) -> Result<Acc, E>,
{
    type Output = Result<Acc, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<Acc, E>> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(item))) => {
                    let acc = self.acc.take().expect("TryFold polled after completion");
                    match (self.f)(acc, item) {
                        Ok(new_acc) => self.acc = Some(new_acc),
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => {
                    return Poll::Ready(Ok(self
                        .acc
                        .take()
                        .expect("TryFold polled after completion")));
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
}

impl<S, F> TryForEach<S, F> {
    /// Creates a new `TryForEach` future.
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self { stream, f }
    }
}

impl<S: Unpin, F> Unpin for TryForEach<S, F> {}

impl<S, F, E> Future for TryForEach<S, F>
where
    S: Stream + Unpin,
    F: FnMut(S::Item) -> Result<(), E>,
{
    type Output = Result<(), E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), E>> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if let Err(e) = (self.f)(item) {
                        return Poll::Ready(Err(e));
                    }
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
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
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
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
            Poll::Ready(Err(e)) => {
                let ok = e == "error";
                crate::assert_with_log!(ok, "error", "error", e);
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
            Poll::Ready(Err(e)) => {
                let ok = e == "stream error";
                crate::assert_with_log!(ok, "stream error", "stream error", e);
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
            Poll::Ready(Err(e)) => {
                let ok = e == "closure error";
                crate::assert_with_log!(ok, "closure error", "closure error", e);
            }
            Poll::Ready(Ok(_)) => panic!("expected Err"),
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("try_fold_closure_error");
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
            Poll::Ready(Err(e)) => {
                let err_ok = e == "error at 2";
                crate::assert_with_log!(err_ok, "error", "error at 2", e);
                let ok = results == vec![1];
                crate::assert_with_log!(ok, "results", vec![1], results);
            }
            Poll::Ready(Ok(())) => panic!("expected Err"),
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("try_for_each_error");
    }
}
