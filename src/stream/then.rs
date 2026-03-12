//! Then (async map) combinator.

use super::Stream;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`then`](super::StreamExt::then) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Then<S, Fut, F> {
    #[pin]
    stream: S,
    f: F,
    #[pin]
    pending: Option<Fut>,
    done: bool,
}

impl<S, Fut, F> Then<S, Fut, F> {
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            pending: None,
            done: false,
        }
    }
}

impl<S, Fut, F> Stream for Then<S, Fut, F>
where
    S: Stream,
    F: FnMut(S::Item) -> Fut,
    Fut: Future,
{
    type Item = Fut::Output;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }

        loop {
            if let Some(fut) = this.pending.as_mut().as_pin_mut() {
                match fut.poll(cx) {
                    Poll::Ready(item) => {
                        this.pending.set(None);
                        return Poll::Ready(Some(item));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    let fut = (this.f)(item);
                    this.pending.set(Some(fut));
                }
                Poll::Ready(None) => {
                    *this.done = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
            return (0, Some(0));
        }
        let (lower, upper) = self.stream.size_hint();
        let pending_len = usize::from(self.pending.is_some());
        (
            lower.saturating_add(pending_len),
            upper.and_then(|u| u.checked_add(pending_len)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::iter;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;
    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }
    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    #[derive(Debug, Default)]
    struct EmptyThenPanics {
        completed: bool,
    }

    impl Stream for EmptyThenPanics {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            assert!(
                !self.completed,
                "then inner stream repolled after completion"
            );
            self.completed = true;
            Poll::Ready(None)
        }
    }

    fn collect_then<S, Fut, F>(stream: Then<S, Fut, F>) -> Vec<Fut::Output>
    where
        S: Stream,
        F: FnMut(S::Item) -> Fut,
        Fut: Future,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        let mut stream = Box::pin(stream);
        while let Poll::Ready(Some(item)) = stream.as_mut().poll_next(&mut cx) {
            items.push(item);
        }
        items
    }

    #[test]
    fn test_then_async_transform() {
        let s = Then::new(iter(vec![1, 2, 3]), |x: i32| async move { x * 2 });
        let items = collect_then(s);
        assert_eq!(items, vec![2, 4, 6]);
    }

    #[test]
    fn test_then_empty_stream() {
        let s = Then::new(iter(Vec::<i32>::new()), |x: i32| async move { x });
        let items = collect_then(s);
        assert!(items.is_empty());
    }

    #[test]
    fn test_then_type_change() {
        let s = Then::new(iter(vec![1, 2]), |x: i32| async move { format!("{x}") });
        let items = collect_then(s);
        assert_eq!(items, vec!["1".to_string(), "2".to_string()]);
    }

    #[test]
    fn test_then_size_hint() {
        let s = Then::new(iter(vec![1, 2, 3]), |x: i32| async move { x });
        assert_eq!(s.size_hint(), (3, Some(3)));
    }

    #[test]
    fn test_then_single_item() {
        let s = Then::new(iter(vec![42]), |x: i32| async move { x + 1 });
        let items = collect_then(s);
        assert_eq!(items, vec![43]);
    }

    #[test]
    fn test_then_does_not_repoll_exhausted_upstream() {
        let stream = Then::new(EmptyThenPanics::default(), |x: i32| async move { x });
        let mut stream = std::pin::pin!(stream);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(stream.as_mut().poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.as_mut().poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.size_hint(), (0, Some(0)));
    }
}
