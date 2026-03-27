//! Scan combinator for streams.
//!
//! The `Scan` combinator is like [`Fold`](super::Fold), but yields each
//! intermediate accumulator value instead of only the final result.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that yields intermediate accumulator values.
///
/// Created by [`StreamExt::scan`](super::StreamExt::scan).
///
/// For each item in the underlying stream, calls `f(state, item)`.
/// If `f` returns `Some(value)`, that value is yielded and the state
/// is updated. If `f` returns `None`, the stream terminates.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Scan<S, St, F> {
    #[pin]
    stream: S,
    state: Option<St>,
    f: F,
}

impl<S, St, F> Scan<S, St, F> {
    /// Creates a new `Scan` stream.
    pub(crate) fn new(stream: S, initial_state: St, f: F) -> Self {
        Self {
            stream,
            state: Some(initial_state),
            f,
        }
    }

    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S, St, B, F> Stream for Scan<S, St, F>
where
    S: Stream,
    F: FnMut(&mut St, S::Item) -> Option<B>,
{
    type Item = B;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<B>> {
        let this = self.project();
        let Some(state) = this.state else {
            return Poll::Ready(None);
        };

        match this.stream.poll_next(cx) {
            Poll::Ready(Some(item)) => {
                if let Some(value) = (this.f)(state, item) {
                    Poll::Ready(Some(value))
                } else {
                    *this.state = None;
                    Poll::Ready(None)
                }
            }
            Poll::Ready(None) => {
                *this.state = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::{StreamExt, iter};
    use std::marker::PhantomPinned;
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

    #[derive(Debug)]
    struct EmptyThenPanics {
        completed: bool,
    }

    impl EmptyThenPanics {
        fn new() -> Self {
            Self { completed: false }
        }
    }

    impl Stream for EmptyThenPanics {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            assert!(
                !self.completed,
                "scan inner stream repolled after completion"
            );
            self.completed = true;
            Poll::Ready(None)
        }
    }

    #[pin_project::pin_project]
    struct PinnedOnce {
        item: Option<i32>,
        _pin: PhantomPinned,
    }

    impl PinnedOnce {
        fn new(item: i32) -> Self {
            Self {
                item: Some(item),
                _pin: PhantomPinned,
            }
        }
    }

    impl Stream for PinnedOnce {
        type Item = i32;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.project();
            Poll::Ready(this.item.take())
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = usize::from(self.item.is_some());
            (remaining, Some(remaining))
        }
    }

    #[test]
    fn scan_running_sum() {
        init_test("scan_running_sum");
        let mut stream = Scan::new(iter(vec![1, 2, 3, 4, 5]), 0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            Some(*acc)
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(1)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(3)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(6)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(10)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(15)));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("scan_running_sum");
    }

    #[test]
    fn scan_early_termination() {
        init_test("scan_early_termination");
        // Terminate when accumulator exceeds 5.
        let mut stream = Scan::new(iter(vec![1, 2, 3, 4, 5]), 0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            if *acc > 5 { None } else { Some(*acc) }
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(3))
        );
        // 3 + 3 = 6 > 5 → None
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        // After termination, stays None.
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("scan_early_termination");
    }

    #[test]
    fn scan_empty_stream() {
        init_test("scan_empty_stream");
        let mut stream = Scan::new(iter(Vec::<i32>::new()), 0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            Some(*acc)
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("scan_empty_stream");
    }

    #[test]
    fn scan_does_not_repoll_exhausted_upstream() {
        init_test("scan_does_not_repoll_exhausted_upstream");
        let mut stream = Scan::new(EmptyThenPanics::new(), 0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            Some(*acc)
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));

        crate::test_complete!("scan_does_not_repoll_exhausted_upstream");
    }

    #[test]
    fn scan_type_change() {
        init_test("scan_type_change");
        let mut stream = Scan::new(
            iter(vec!["hello", "world"]),
            String::new(),
            |acc: &mut String, item| {
                if !acc.is_empty() {
                    acc.push(' ');
                }
                acc.push_str(item);
                Some(acc.clone())
            },
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some("hello".to_string())));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some("hello world".to_string())));
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("scan_type_change");
    }

    #[test]
    fn scan_accessors() {
        init_test("scan_accessors");
        let mut stream = Scan::new(iter(vec![1, 2, 3]), 0i32, |acc: &mut i32, x: i32| {
            *acc += x;
            Some(*acc)
        });
        let _ref = stream.get_ref();
        let _mut = stream.get_mut();
        let inner = stream.into_inner();

        let mut inner = inner;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(
            Pin::new(&mut inner).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );
        crate::test_complete!("scan_accessors");
    }

    #[test]
    fn scan_debug() {
        #[allow(clippy::unnecessary_wraps)]
        fn sum(acc: &mut i32, x: i32) -> Option<i32> {
            *acc += x;
            Some(*acc)
        }
        let stream = Scan::new(
            iter(vec![1, 2]),
            0i32,
            sum as fn(&mut i32, i32) -> Option<i32>,
        );
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("Scan"));
    }

    #[test]
    fn scan_accepts_pinned_non_unpin_streams() {
        init_test("scan_accepts_pinned_non_unpin_streams");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let stream = PinnedOnce::new(7).scan(10i32, |acc: &mut i32, item| {
            *acc += item;
            Some(*acc)
        });
        let mut stream = std::pin::pin!(stream);

        assert_eq!(stream.as_mut().poll_next(&mut cx), Poll::Ready(Some(17)));
        assert_eq!(stream.as_mut().poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("scan_accepts_pinned_non_unpin_streams");
    }
}
