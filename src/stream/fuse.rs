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
        let stream = match self.stream.as_mut() {
            Some(s) => s,
            None => return Poll::Ready(None),
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
        match self.stream {
            Some(ref s) => s.size_hint(),
            None => (0, Some(0)),
        }
    }
}
