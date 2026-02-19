//! ForEach combinator for streams.
//!
//! The `ForEach` future consumes a stream and executes a closure for each item.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A future that executes a closure for each item in a stream.
///
/// Created by [`StreamExt::for_each`](super::StreamExt::for_each).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ForEach<S, F> {
    stream: S,
    f: F,
}

impl<S, F> ForEach<S, F> {
    /// Creates a new `ForEach` future.
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self { stream, f }
    }
}

impl<S: Unpin, F> Unpin for ForEach<S, F> {}

impl<S, F> Future for ForEach<S, F>
where
    S: Stream + Unpin,
    F: FnMut(S::Item),
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    (self.f)(item);
                }
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A future that executes an async closure for each item in a stream.
///
/// Created by [`StreamExt::for_each_async`](super::StreamExt::for_each_async).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ForEachAsync<S, F, Fut> {
    stream: S,
    f: F,
    pending: Option<Fut>,
}

impl<S, F, Fut> ForEachAsync<S, F, Fut> {
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            pending: None,
        }
    }
}

impl<S: Unpin, F, Fut: Unpin> Unpin for ForEachAsync<S, F, Fut> {}

impl<S, F, Fut> Future for ForEachAsync<S, F, Fut>
where
    S: Stream + Unpin,
    F: FnMut(S::Item) -> Fut,
    Fut: Future<Output = ()> + Unpin,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            // Complete pending future first
            if let Some(fut) = &mut self.pending {
                match Pin::new(fut).poll(cx) {
                    Poll::Ready(()) => {
                        self.pending = None;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Get next item
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.pending = Some((self.f)(item));
                }
                Poll::Ready(None) => return Poll::Ready(()),
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
}
