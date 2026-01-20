//! Any and All combinators for streams.
//!
//! The `Any` future checks if any item matches a predicate.
//! The `All` future checks if all items match a predicate.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A future that checks if any item in a stream matches a predicate.
///
/// Created by [`StreamExt::any`](super::StreamExt::any).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Any<S, P> {
    stream: S,
    predicate: P,
}

impl<S, P> Any<S, P> {
    /// Creates a new `Any` future.
    pub(crate) fn new(stream: S, predicate: P) -> Self {
        Self { stream, predicate }
    }
}

impl<S: Unpin, P> Unpin for Any<S, P> {}

impl<S, P> Future for Any<S, P>
where
    S: Stream + Unpin,
    P: FnMut(&S::Item) -> bool,
{
    type Output = bool;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<bool> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if (self.predicate)(&item) {
                        return Poll::Ready(true);
                    }
                }
                Poll::Ready(None) => return Poll::Ready(false),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A future that checks if all items in a stream match a predicate.
///
/// Created by [`StreamExt::all`](super::StreamExt::all).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct All<S, P> {
    stream: S,
    predicate: P,
}

impl<S, P> All<S, P> {
    /// Creates a new `All` future.
    pub(crate) fn new(stream: S, predicate: P) -> Self {
        Self { stream, predicate }
    }
}

impl<S: Unpin, P> Unpin for All<S, P> {}

impl<S, P> Future for All<S, P>
where
    S: Stream + Unpin,
    P: FnMut(&S::Item) -> bool,
{
    type Output = bool;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<bool> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if !(self.predicate)(&item) {
                        return Poll::Ready(false);
                    }
                }
                Poll::Ready(None) => return Poll::Ready(true),
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
}
