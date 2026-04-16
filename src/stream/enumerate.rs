//! Enumerate combinator.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`enumerate`](super::StreamExt::enumerate) method.
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Enumerate<S> {
    #[pin]
    stream: S,
    count: usize,
    done: bool,
}

impl<S> Enumerate<S> {
    #[inline]
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            count: 0,
            done: false,
        }
    }

    /// Returns a reference to the underlying stream.
    #[inline]
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    #[inline]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    #[inline]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Stream> Stream for Enumerate<S> {
    type Item = (usize, S::Item);

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }

        match this.stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(item)) => {
                let index = *this.count;
                *this.count += 1;
                Poll::Ready(Some((index, item)))
            }
            Poll::Ready(None) => {
                *this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
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
            assert_eq!(polls, 0, "enumerate inner stream repolled after completion");
            Poll::Ready(None)
        }
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

    #[test]
    fn test_enumerate_does_not_repoll_exhausted_upstream() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut enumerate = Enumerate::new(EmptyThenPanics::new(Arc::clone(&polls)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            Pin::new(&mut enumerate).poll_next(&mut cx),
            Poll::Ready(None)
        );
        assert_eq!(
            Pin::new(&mut enumerate).poll_next(&mut cx),
            Poll::Ready(None)
        );
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_enumerate_size_hint_after_exhaustion() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut enumerate = Enumerate::new(EmptyThenPanics::new(Arc::clone(&polls)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            Pin::new(&mut enumerate).poll_next(&mut cx),
            Poll::Ready(None)
        );
        assert_eq!(enumerate.size_hint(), (0, Some(0)));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }
}
