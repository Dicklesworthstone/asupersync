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
    exhausted: bool,
}

impl<S, F> Inspect<S, F> {
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            exhausted: false,
        }
    }
}

impl<S, F> Stream for Inspect<S, F>
where
    S: Stream + Unpin,
    F: FnMut(&S::Item) + Unpin,
{
    type Item = S::Item;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.exhausted {
            return Poll::Ready(None);
        }

        let next = Pin::new(&mut self.stream).poll_next(cx);
        if let Poll::Ready(Some(ref item)) = next {
            (self.f)(item);
        } else if matches!(next, Poll::Ready(None)) {
            self.exhausted = true;
        }
        next
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            (0, Some(0))
        } else {
            self.stream.size_hint()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::iter;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;
    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }
    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    #[derive(Debug)]
    struct EmptyThenPanics {
        polls: Arc<AtomicUsize>,
    }

    impl EmptyThenPanics {
        fn new(polls: Arc<AtomicUsize>) -> Self {
            Self { polls }
        }
    }

    impl Stream for EmptyThenPanics {
        type Item = i32;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let polls = self.polls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(polls, 0, "inspect inner stream repolled after completion");
            Poll::Ready(None)
        }
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

    #[test]
    fn test_inspect_does_not_repoll_exhausted_upstream() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut stream = Inspect::new(EmptyThenPanics::new(Arc::clone(&polls)), |_: &i32| {});
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_inspect_size_hint_after_exhaustion_is_zero() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut stream = Inspect::new(EmptyThenPanics::new(Arc::clone(&polls)), |_: &i32| {});
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.size_hint(), (0, Some(0)));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }
}
