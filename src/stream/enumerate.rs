//! Enumerate combinator.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`enumerate`](super::StreamExt::enumerate) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Enumerate<S> {
    stream: S,
    count: usize,
}

impl<S> Enumerate<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self { stream, count: 0 }
    }
}

impl<S: Stream + Unpin> Stream for Enumerate<S> {
    type Item = (usize, S::Item);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.stream).poll_next(cx) {
            Poll::Ready(Some(item)) => {
                let index = self.count;
                self.count += 1;
                Poll::Ready(Some((index, item)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
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

    fn collect_enum<S: Stream + Unpin>(stream: &mut Enumerate<S>) -> Vec<(usize, S::Item)> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        while let Poll::Ready(Some(item)) = Pin::new(&mut *stream).poll_next(&mut cx) {
            items.push(item);
        }
        items
    }

    #[test]
    fn test_enumerate_indices() {
        let mut e = Enumerate::new(iter(vec!["a", "b", "c"]));
        let items = collect_enum(&mut e);
        assert_eq!(items, vec![(0, "a"), (1, "b"), (2, "c")]);
    }

    #[test]
    fn test_enumerate_empty() {
        let mut e = Enumerate::new(iter(Vec::<i32>::new()));
        let items = collect_enum(&mut e);
        assert!(items.is_empty());
    }

    #[test]
    fn test_enumerate_single() {
        let mut e = Enumerate::new(iter(vec![42]));
        let items = collect_enum(&mut e);
        assert_eq!(items, vec![(0, 42)]);
    }

    #[test]
    fn test_enumerate_size_hint() {
        let e = Enumerate::new(iter(vec![1, 2, 3]));
        assert_eq!(e.size_hint(), (3, Some(3)));
    }

    #[test]
    fn test_enumerate_many_items() {
        let v: Vec<i32> = (0..100).collect();
        let mut e = Enumerate::new(iter(v));
        let items = collect_enum(&mut e);
        assert_eq!(items.len(), 100);
        assert_eq!(items[0], (0, 0));
        assert_eq!(items[99], (99, 99));
    }
}
