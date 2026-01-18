//! Zip combinator for streams.
//!
//! The `Zip` combinator yields pairs from two streams until either stream ends.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that zips two streams into pairs.
///
/// Created by [`StreamExt::zip`](super::StreamExt::zip).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Zip<S1: Stream, S2: Stream> {
    stream1: S1,
    stream2: S2,
    queued1: Option<S1::Item>,
    queued2: Option<S2::Item>,
}

impl<S1: Stream, S2: Stream> Zip<S1, S2> {
    /// Creates a new `Zip` stream.
    pub(crate) fn new(stream1: S1, stream2: S2) -> Self {
        Self {
            stream1,
            stream2,
            queued1: None,
            queued2: None,
        }
    }

    /// Returns a reference to the first stream.
    pub fn first_ref(&self) -> &S1 {
        &self.stream1
    }

    /// Returns a reference to the second stream.
    pub fn second_ref(&self) -> &S2 {
        &self.stream2
    }

    /// Returns mutable references to the underlying streams.
    pub fn get_mut(&mut self) -> (&mut S1, &mut S2) {
        (&mut self.stream1, &mut self.stream2)
    }

    /// Consumes the combinator, returning the underlying streams.
    pub fn into_inner(self) -> (S1, S2) {
        (self.stream1, self.stream2)
    }
}

impl<S1: Stream + Unpin, S2: Stream + Unpin> Unpin for Zip<S1, S2> {}

impl<S1, S2> Stream for Zip<S1, S2>
where
    S1: Stream + Unpin,
    S2: Stream + Unpin,
{
    type Item = (S1::Item, S2::Item);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.queued1.is_none() {
            match Pin::new(&mut self.stream1).poll_next(cx) {
                Poll::Ready(Some(item)) => self.queued1 = Some(item),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => {}
            }
        }

        if self.queued2.is_none() {
            match Pin::new(&mut self.stream2).poll_next(cx) {
                Poll::Ready(Some(item)) => self.queued2 = Some(item),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => {}
            }
        }

        if self.queued1.is_some() && self.queued2.is_some() {
            let item1 = self.queued1.take().expect("queued1 must be set");
            let item2 = self.queued2.take().expect("queued2 must be set");
            Poll::Ready(Some((item1, item2)))
        } else {
            Poll::Pending
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lower1, upper1) = self.stream1.size_hint();
        let (lower2, upper2) = self.stream2.size_hint();

        let lower = lower1.min(lower2);
        let upper = match (upper1, upper2) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
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

    #[test]
    fn zip_pairs_items() {
        let mut stream = Zip::new(iter(vec![1, 2, 3]), iter(vec!["a", "b", "c"]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some((1, "a")))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some((2, "b")))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some((3, "c")))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn zip_ends_when_shorter_finishes() {
        let mut stream = Zip::new(iter(vec![1, 2, 3]), iter(vec!["a"]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some((1, "a")))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn zip_size_hint_min() {
        let stream = Zip::new(iter(vec![1, 2, 3]), iter(vec!["a", "b"]));
        assert_eq!(stream.size_hint(), (2, Some(2)));
    }
}
