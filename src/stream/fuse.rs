//! Fuse combinator.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`fuse`](super::StreamExt::fuse) method.
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Fuse<S> {
    #[pin]
    stream: Option<S>,
}

impl<S> Fuse<S> {
    #[inline]
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream: Some(stream),
        }
    }

    /// Returns a reference to the underlying stream, if it hasn't been fused.
    #[inline]
    pub fn get_ref(&self) -> Option<&S> {
        self.stream.as_ref()
    }

    /// Returns a mutable reference to the underlying stream, if it hasn't been fused.
    #[inline]
    pub fn get_mut(&mut self) -> Option<&mut S> {
        self.stream.as_mut()
    }

    /// Consumes the combinator, returning the underlying stream if it hasn't been fused.
    #[inline]
    pub fn into_inner(self) -> Option<S> {
        self.stream
    }
}

impl<S: Stream> Stream for Fuse<S> {
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let Some(stream) = this.stream.as_mut().as_pin_mut() else {
            return Poll::Ready(None);
        };

        match stream.poll_next(cx) {
            Poll::Ready(None) => {
                this.stream.set(None);
                Poll::Ready(None)
            }
            other => other,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.as_ref().map_or((0, Some(0)), Stream::size_hint)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use crate::stream::iter;

    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
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
