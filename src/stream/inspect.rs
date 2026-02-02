//! Inspect combinator.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`inspect`](super::StreamExt::inspect) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Inspect<S, F> {
    stream: S,
    f: F,
}

impl<S, F> Inspect<S, F> {
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self { stream, f }
    }
}

impl<S, F> Stream for Inspect<S, F>
where
    S: Stream + Unpin,
    F: FnMut(&S::Item) + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let next = Pin::new(&mut self.stream).poll_next(cx);
        if let Poll::Ready(Some(ref item)) = next {
            (self.f)(item);
        }
        next
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

    fn collect_inspect<S: Stream<Item = I> + Unpin, F: FnMut(&I) + Unpin, I>(
        stream: &mut Inspect<S, F>,
    ) -> Vec<I> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        while let Poll::Ready(Some(item)) = Pin::new(&mut *stream).poll_next(&mut cx) {
            items.push(item);
        }
        items
    }

    #[test]
    fn test_inspect_calls_closure() {
        let mut seen = Vec::new();
        let mut stream = Inspect::new(iter(vec![1, 2, 3]), |item: &i32| seen.push(*item));
        let items = collect_inspect(&mut stream);
        assert_eq!(items, vec![1, 2, 3]);
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn test_inspect_empty_stream() {
        let mut count = 0;
        let mut stream = Inspect::new(iter(Vec::<i32>::new()), |_: &i32| count += 1);
        let items = collect_inspect(&mut stream);
        assert!(items.is_empty());
        assert_eq!(count, 0);
    }

    #[test]
    fn test_inspect_does_not_modify_items() {
        let mut stream = Inspect::new(iter(vec![10, 20]), |_: &i32| {});
        let items = collect_inspect(&mut stream);
        assert_eq!(items, vec![10, 20]);
    }

    #[test]
    fn test_inspect_size_hint() {
        let stream = Inspect::new(iter(vec![1, 2, 3]), |_: &i32| {});
        assert_eq!(stream.size_hint(), (3, Some(3)));
    }

    #[test]
    fn test_inspect_ordering() {
        let mut order = Vec::new();
        let mut stream = Inspect::new(iter(vec!['a', 'b', 'c']), |c: &char| order.push(*c));
        let _ = collect_inspect(&mut stream);
        assert_eq!(order, vec!['a', 'b', 'c']);
    }
}
