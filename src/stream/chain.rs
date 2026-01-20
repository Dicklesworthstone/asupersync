//! Chain combinator for streams.
//!
//! The `Chain` combinator yields all items from the first stream, then all
//! items from the second stream.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that yields items from the first stream then the second.
///
/// Created by [`StreamExt::chain`](super::StreamExt::chain).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Chain<S1, S2> {
    first: Option<S1>,
    second: S2,
}

impl<S1, S2> Chain<S1, S2> {
    /// Creates a new `Chain` stream.
    pub(crate) fn new(first: S1, second: S2) -> Self {
        Self {
            first: Some(first),
            second,
        }
    }

    /// Returns a reference to the first stream, if still active.
    pub fn first_ref(&self) -> Option<&S1> {
        self.first.as_ref()
    }

    /// Returns a mutable reference to the first stream, if still active.
    pub fn first_mut(&mut self) -> Option<&mut S1> {
        self.first.as_mut()
    }

    /// Returns a reference to the second stream.
    pub fn second_ref(&self) -> &S2 {
        &self.second
    }

    /// Returns a mutable reference to the second stream.
    pub fn second_mut(&mut self) -> &mut S2 {
        &mut self.second
    }

    /// Consumes the combinator, returning the two underlying streams.
    pub fn into_inner(self) -> (Option<S1>, S2) {
        (self.first, self.second)
    }
}

impl<S1: Unpin, S2: Unpin> Unpin for Chain<S1, S2> {}

impl<S1, S2> Stream for Chain<S1, S2>
where
    S1: Stream + Unpin,
    S2: Stream<Item = S1::Item> + Unpin,
{
    type Item = S1::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(first) = self.first.as_mut() {
            match Pin::new(first).poll_next(cx) {
                Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
                Poll::Ready(None) => {
                    self.first = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.second).poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let second_hint = self.second.size_hint();
        let Some(first) = self.first.as_ref() else {
            return second_hint;
        };

        let (first_lower, first_upper) = first.size_hint();
        let (second_lower, second_upper) = second_hint;

        let lower = first_lower.saturating_add(second_lower);
        let upper = match (first_upper, second_upper) {
            (Some(a), Some(b)) => a.checked_add(b),
            _ => None,
        };

        (lower, upper)
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
    fn chain_yields_both_streams() {
        init_test("chain_yields_both_streams");
        let mut stream = Chain::new(iter(vec![1, 2]), iter(vec![3, 4]));
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
        let ok = matches!(poll, Poll::Ready(Some(4)));
        crate::assert_with_log!(ok, "poll 4", "Poll::Ready(Some(4))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("chain_yields_both_streams");
    }

    #[test]
    fn chain_size_hint_combines() {
        init_test("chain_size_hint_combines");
        let stream = Chain::new(iter(vec![1, 2, 3]), iter(vec![4]));
        let hint = stream.size_hint();
        let ok = hint == (4, Some(4));
        crate::assert_with_log!(ok, "size hint", (4, Some(4)), hint);
        crate::test_complete!("chain_size_hint_combines");
    }
}
