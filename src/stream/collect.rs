//! Collect combinator for streams.
//!
//! The `Collect` future consumes a stream and collects all items into a collection.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A future that collects all items from a stream into a collection.
///
/// Created by [`StreamExt::collect`](super::StreamExt::collect).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Collect<S, C> {
    stream: S,
    collection: C,
}

impl<S, C> Collect<S, C> {
    /// Creates a new `Collect` future.
    pub(crate) fn new(stream: S, collection: C) -> Self {
        Self { stream, collection }
    }
}

impl<S: Unpin, C> Unpin for Collect<S, C> {}

impl<S, C> Future for Collect<S, C>
where
    S: Stream + Unpin,
    C: Default + Extend<S::Item>,
{
    type Output = C;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<C> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.collection.extend(std::iter::once(item));
                }
                Poll::Ready(None) => {
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
}
