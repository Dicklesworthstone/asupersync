//! Count combinator for streams.
//!
//! The `Count` future consumes a stream and counts the number of items.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A future that counts the items in a stream.
///
/// Created by [`StreamExt::count`](super::StreamExt::count).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Count<S> {
    stream: S,
    count: usize,
}

impl<S> Count<S> {
    /// Creates a new `Count` future.
    pub(crate) fn new(stream: S) -> Self {
        Self { stream, count: 0 }
    }
}

impl<S: Unpin> Unpin for Count<S> {}

impl<S> Future for Count<S>
where
    S: Stream + Unpin,
{
    type Output = usize;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(_)) => {
                    self.count += 1;
                }
                Poll::Ready(None) => return Poll::Ready(self.count),
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
}
