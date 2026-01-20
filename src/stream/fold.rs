//! Fold combinator for streams.
//!
//! The `Fold` future consumes a stream and folds all items into a single value.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A future that folds all items from a stream into a single value.
///
/// Created by [`StreamExt::fold`](super::StreamExt::fold).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Fold<S, F, Acc> {
    stream: S,
    f: F,
    acc: Option<Acc>,
}

impl<S, F, Acc> Fold<S, F, Acc> {
    /// Creates a new `Fold` future.
    pub(crate) fn new(stream: S, init: Acc, f: F) -> Self {
        Self {
            stream,
            f,
            acc: Some(init),
        }
    }
}

impl<S: Unpin, F, Acc> Unpin for Fold<S, F, Acc> {}

impl<S, F, Acc> Future for Fold<S, F, Acc>
where
    S: Stream + Unpin,
    F: FnMut(Acc, S::Item) -> Acc,
{
    type Output = Acc;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Acc> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    let acc = self.acc.take().expect("Fold polled after completion");
                    self.acc = Some((self.f)(acc, item));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(self.acc.take().expect("Fold polled after completion"));
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
    fn fold_sum() {
        init_test("fold_sum");
        let mut future = Fold::new(iter(vec![1i32, 2, 3, 4, 5]), 0i32, |acc, x| acc + x);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(sum) => {
                let ok = sum == 15;
                crate::assert_with_log!(ok, "sum", 15, sum);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("fold_sum");
    }

    #[test]
    fn fold_product() {
        init_test("fold_product");
        let mut future = Fold::new(iter(vec![1i32, 2, 3, 4, 5]), 1i32, |acc, x| acc * x);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(product) => {
                let ok = product == 120;
                crate::assert_with_log!(ok, "product", 120, product);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("fold_product");
    }

    #[test]
    fn fold_string_concat() {
        init_test("fold_string_concat");
        let mut future = Fold::new(
            iter(vec!["a", "b", "c"]),
            String::new(),
            |mut acc: String, s: &str| {
                acc.push_str(s);
                acc
            },
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(s) => {
                let ok = s == "abc";
                crate::assert_with_log!(ok, "concat", "abc", s);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("fold_string_concat");
    }

    #[test]
    fn fold_empty() {
        init_test("fold_empty");
        let mut future = Fold::new(iter(Vec::<i32>::new()), 42i32, |acc, x| acc + x);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(result) => {
                let ok = result == 42;
                crate::assert_with_log!(ok, "empty result", 42, result);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("fold_empty");
    }
}
