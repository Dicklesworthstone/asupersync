//! Fuse combinator.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`fuse`](super::StreamExt::fuse) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Fuse<S> {
    stream: Option<S>,
}

impl<S> Fuse<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream: Some(stream),
        }
    }
}

impl<S: Stream + Unpin> Stream for Fuse<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Some(stream) = self.stream.as_mut() else {
            return Poll::Ready(None);
        };

        match Pin::new(stream).poll_next(cx) {
            Poll::Ready(None) => {
                self.stream = None;
                Poll::Ready(None)
            }
            other => other,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.as_ref().map_or((0, Some(0)), Stream::size_hint)
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

    fn collect_fused<S: Stream + Unpin>(stream: &mut Fuse<S>) -> Vec<S::Item> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        while let Poll::Ready(Some(item)) = Pin::new(&mut *stream).poll_next(&mut cx) {
            items.push(item);
        }
        items
    }

    #[test]
    fn test_fuse_yields_all_items() {
        let mut fused = Fuse::new(iter(vec![1, 2, 3]));
        let items = collect_fused(&mut fused);
        assert_eq!(items, vec![1, 2, 3]);
    }

    #[test]
    fn test_fuse_returns_none_after_exhaustion() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fused = Fuse::new(iter(vec![1]));

        assert!(matches!(
            Pin::new(&mut fused).poll_next(&mut cx),
            Poll::Ready(Some(1))
        ));
        assert!(matches!(
            Pin::new(&mut fused).poll_next(&mut cx),
            Poll::Ready(None)
        ));
        // After fusing, always None
        assert!(matches!(
            Pin::new(&mut fused).poll_next(&mut cx),
            Poll::Ready(None)
        ));
        assert!(matches!(
            Pin::new(&mut fused).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn test_fuse_empty_stream() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fused = Fuse::new(iter(Vec::<i32>::new()));
        assert!(matches!(
            Pin::new(&mut fused).poll_next(&mut cx),
            Poll::Ready(None)
        ));
        assert!(matches!(
            Pin::new(&mut fused).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn test_fuse_size_hint_before_exhaustion() {
        let fused = Fuse::new(iter(vec![1, 2, 3]));
        let (lower, upper) = fused.size_hint();
        assert_eq!(lower, 3);
        assert_eq!(upper, Some(3));
    }

    #[test]
    fn test_fuse_size_hint_after_exhaustion() {
        let mut fused = Fuse::new(iter(Vec::<i32>::new()));
        let _ = collect_fused(&mut fused);
        let (lower, upper) = fused.size_hint();
        assert_eq!(lower, 0);
        assert_eq!(upper, Some(0));
    }
}
