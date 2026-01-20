//! Convert iterators into streams.
//!
//! This module provides the [`iter`] function to convert any `IntoIterator`
//! into a `Stream`.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that yields items from an iterator.
///
/// Created by the [`iter`] function.
#[derive(Debug)]
pub struct Iter<I> {
    iter: I,
}

impl<I> Iter<I> {
    /// Creates a new `Iter` stream from an iterator.
    pub(crate) fn new(iter: I) -> Self {
        Self { iter }
    }
}

impl<I> Unpin for Iter<I> {}

impl<I: Iterator> Stream for Iter<I> {
    type Item = I::Item;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.iter.next())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

/// Convert an iterator into a stream.
///
/// The resulting stream will yield items synchronously (always returning
/// `Poll::Ready`), making it useful for testing and for converting
/// synchronous data sources.
///
/// # Examples
///
/// ```ignore
/// use asupersync::stream::{iter, StreamExt};
///
/// let stream = iter(vec![1, 2, 3]);
/// // stream.next().await returns Some(1), Some(2), Some(3), None
/// ```
pub fn iter<I>(i: I) -> Iter<I::IntoIter>
where
    I: IntoIterator,
{
    Iter::new(i.into_iter())
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn iter_from_vec() {
        init_test("iter_from_vec");
        let mut stream = iter(vec![1, 2, 3]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(1))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(3)));
        crate::assert_with_log!(ok, "poll 3", "Poll::Ready(Some(3))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("iter_from_vec");
    }

    #[test]
    fn iter_from_range() {
        init_test("iter_from_range");
        let mut stream = iter(1..=3);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(1))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(3)));
        crate::assert_with_log!(ok, "poll 3", "Poll::Ready(Some(3))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("iter_from_range");
    }

    #[test]
    fn iter_empty() {
        init_test("iter_empty");
        let mut stream = iter(std::iter::empty::<i32>());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll empty", "Poll::Ready(None)", poll);
        crate::test_complete!("iter_empty");
    }

    #[test]
    fn iter_size_hint() {
        init_test("iter_size_hint");
        let stream = iter(vec![1, 2, 3]);
        let hint = stream.size_hint();
        let ok = hint == (3, Some(3));
        crate::assert_with_log!(ok, "size hint", (3, Some(3)), hint);
        crate::test_complete!("iter_size_hint");
    }
}
