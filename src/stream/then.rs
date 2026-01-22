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
