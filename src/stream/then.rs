//! Then (async map) combinator.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`then`](super::StreamExt::then) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Then<S, Fut, F> {
    stream: S,
    f: F,
    pending: Option<Pin<Box<Fut>>>,
}

impl<S, Fut, F> Then<S, Fut, F> {
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            pending: None,
        }
    }
}

impl<S, Fut, F> Stream for Then<S, Fut, F>
where
    S: Stream + Unpin,
    F: FnMut(S::Item) -> Fut + Unpin,
    Fut: Future,
{
    type Item = Fut::Output;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(fut) = self.pending.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(item) => {
                        self.pending = None;
                        return Poll::Ready(Some(item));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    let fut = (self.f)(item);
                    self.pending = Some(Box::pin(fut));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
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
    use std::task::{Wake, Waker};

    struct NoopWaker;
    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }
    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn collect_then<S, Fut, F>(stream: &mut Then<S, Fut, F>) -> Vec<Fut::Output>
    where
        S: Stream + Unpin,
        F: FnMut(S::Item) -> Fut + Unpin,
        Fut: Future,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        loop {
            match Pin::new(&mut *stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => items.push(item),
                Poll::Ready(None) => break,
                Poll::Pending => break,
            }
        }
        items
    }

    #[test]
    fn test_then_async_transform() {
        let mut s = Then::new(iter(vec![1, 2, 3]), |x: i32| async move { x * 2 });
        let items = collect_then(&mut s);
        assert_eq!(items, vec![2, 4, 6]);
    }

    #[test]
    fn test_then_empty_stream() {
        let mut s = Then::new(iter(Vec::<i32>::new()), |x: i32| async move { x });
        let items = collect_then(&mut s);
        assert!(items.is_empty());
    }

    #[test]
    fn test_then_type_change() {
        let mut s = Then::new(iter(vec![1, 2]), |x: i32| async move { format!("{x}") });
        let items = collect_then(&mut s);
        assert_eq!(items, vec!["1".to_string(), "2".to_string()]);
    }

    #[test]
    fn test_then_size_hint() {
        let s = Then::new(iter(vec![1, 2, 3]), |x: i32| async move { x });
        assert_eq!(s.size_hint(), (3, Some(3)));
    }

    #[test]
    fn test_then_single_item() {
        let mut s = Then::new(iter(vec![42]), |x: i32| async move { x + 1 });
        let items = collect_then(&mut s);
        assert_eq!(items, vec![43]);
    }
}
