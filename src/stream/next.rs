//! Next combinator for streams.
//!
//! The `Next` future returns the next item from a stream.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A future that returns the next item from a stream.
///
/// Created by [`StreamExt::next`](super::StreamExt::next).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Next<'a, S: ?Sized> {
    stream: &'a mut S,
    done: bool,
}

impl<'a, S: ?Sized> Next<'a, S> {
    /// Creates a new `Next` future.
    pub(crate) fn new(stream: &'a mut S) -> Self {
        Self {
            stream,
            done: false,
        }
    }
}

impl<S: ?Sized + Unpin> Unpin for Next<'_, S> {}

impl<S> Future for Next<'_, S>
where
    S: Stream + Unpin + ?Sized,
{
    type Output = Option<S::Item>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        let poll = Pin::new(&mut *self.stream).poll_next(cx);
        if poll.is_ready() {
            self.done = true;
        }
        poll
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

    #[test]
    fn next_returns_items() {
        let mut stream = iter(vec![1i32, 2, 3]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        {
            let mut future = Next::new(&mut stream);
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(Some(1)) => {}
                _ => panic!("expected Ready(Some(1))"),
            }
        }

        {
            let mut future = Next::new(&mut stream);
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(Some(2)) => {}
                _ => panic!("expected Ready(Some(2))"),
            }
        }

        {
            let mut future = Next::new(&mut stream);
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(Some(3)) => {}
                _ => panic!("expected Ready(Some(3))"),
            }
        }

        {
            let mut future = Next::new(&mut stream);
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(None) => {}
                _ => panic!("expected Ready(None)"),
            }
        }
    }

    #[test]
    fn next_empty_stream() {
        let mut stream = iter(Vec::<i32>::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = Next::new(&mut stream);
        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(None) => {}
            _ => panic!("expected Ready(None)"),
        }
    }

    #[test]
    fn next_repoll_after_ready_some_returns_none() {
        let mut stream = iter(vec![1i32]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = Next::new(&mut stream);
        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Some(1)) => {}
            _ => panic!("expected Ready(Some(1))"),
        }

        let repoll = Pin::new(&mut future).poll(&mut cx);
        assert!(
            matches!(repoll, Poll::Ready(None)),
            "repoll after completion must return None"
        );
    }

    #[test]
    fn next_repoll_after_ready_none_returns_none() {
        let mut stream = iter(Vec::<i32>::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = Next::new(&mut stream);
        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(None) => {}
            _ => panic!("expected Ready(None)"),
        }

        let repoll = Pin::new(&mut future).poll(&mut cx);
        assert!(
            matches!(repoll, Poll::Ready(None)),
            "repoll after completion must return None"
        );
    }
}
