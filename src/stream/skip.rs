//! Skip combinator.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`skip`](super::StreamExt::skip) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Skip<S> {
    stream: S,
    remaining: usize,
}

impl<S> Skip<S> {
    pub(crate) fn new(stream: S, remaining: usize) -> Self {
        Self { stream, remaining }
    }
}

impl<S: Stream + Unpin> Stream for Skip<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        while self.remaining > 0 {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(_)) => self.remaining -= 1,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.stream).poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lower, upper) = self.stream.size_hint();
        let lower = lower.saturating_sub(self.remaining);
        let upper = upper.map(|x| x.saturating_sub(self.remaining));
        (lower, upper)
    }
}

/// Stream for the [`skip_while`](super::StreamExt::skip_while) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct SkipWhile<S, F> {
    stream: S,
    predicate: F,
    done: bool,
}

impl<S, F> SkipWhile<S, F> {
    pub(crate) fn new(stream: S, predicate: F) -> Self {
        Self {
            stream,
            predicate,
            done: false,
        }
    }
}

impl<S, F> Stream for SkipWhile<S, F>
where
    S: Stream + Unpin,
    F: FnMut(&S::Item) -> bool + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Pin::new(&mut self.stream).poll_next(cx);
        }

        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if !(self.predicate)(&item) {
                        self.done = true;
                        return Poll::Ready(Some(item));
                    }
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lower, upper) = self.stream.size_hint();
        if self.done {
            (lower, upper)
        } else {
            (0, upper)
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

    fn collect<S: Stream + Unpin>(stream: &mut S) -> Vec<S::Item> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        while let Poll::Ready(Some(item)) = Pin::new(&mut *stream).poll_next(&mut cx) {
            items.push(item);
        }
        items
    }

    #[test]
    fn test_skip_zero() {
        let mut s = Skip::new(iter(vec![1, 2, 3]), 0);
        assert_eq!(collect(&mut s), vec![1, 2, 3]);
    }

    #[test]
    fn test_skip_some() {
        let mut s = Skip::new(iter(vec![1, 2, 3, 4, 5]), 2);
        assert_eq!(collect(&mut s), vec![3, 4, 5]);
    }

    #[test]
    fn test_skip_all() {
        let mut s = Skip::new(iter(vec![1, 2, 3]), 3);
        assert_eq!(collect(&mut s), Vec::<i32>::new());
    }

    #[test]
    fn test_skip_more_than_len() {
        let mut s = Skip::new(iter(vec![1, 2]), 100);
        assert_eq!(collect(&mut s), Vec::<i32>::new());
    }

    #[test]
    fn test_skip_empty_stream() {
        let mut s = Skip::new(iter(Vec::<i32>::new()), 5);
        assert_eq!(collect(&mut s), Vec::<i32>::new());
    }

    #[test]
    fn test_skip_size_hint() {
        let s = Skip::new(iter(vec![1, 2, 3, 4, 5]), 2);
        let (lower, upper) = s.size_hint();
        assert_eq!(lower, 3);
        assert_eq!(upper, Some(3));
    }

    #[test]
    fn test_skip_while_basic() {
        let mut s = SkipWhile::new(iter(vec![1, 2, 3, 4, 5]), |x: &i32| *x < 3);
        assert_eq!(collect(&mut s), vec![3, 4, 5]);
    }

    #[test]
    fn test_skip_while_none_skipped() {
        let mut s = SkipWhile::new(iter(vec![5, 4, 3]), |x: &i32| *x < 3);
        assert_eq!(collect(&mut s), vec![5, 4, 3]);
    }

    #[test]
    fn test_skip_while_all_skipped() {
        let mut s = SkipWhile::new(iter(vec![1, 2]), |x: &i32| *x < 10);
        assert_eq!(collect(&mut s), Vec::<i32>::new());
    }

    #[test]
    fn test_skip_while_empty() {
        let mut s = SkipWhile::new(iter(Vec::<i32>::new()), |_: &i32| true);
        assert_eq!(collect(&mut s), Vec::<i32>::new());
    }

    #[test]
    fn test_skip_while_size_hint_before_done() {
        let s = SkipWhile::new(iter(vec![1, 2, 3]), |x: &i32| *x < 2);
        let (lower, upper) = s.size_hint();
        assert_eq!(lower, 0); // unknown how many will be skipped
        assert_eq!(upper, Some(3));
    }
}
