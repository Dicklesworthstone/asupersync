//! Merge combinator for streams.
//!
//! The `Merge` combinator interleaves items from multiple streams, polling
//! them in round-robin order.

use super::Stream;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that merges multiple streams.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Merge<S> {
    streams: VecDeque<S>,
}

impl<S> Merge<S> {
    /// Creates a new `Merge` from the given streams.
    pub(crate) fn new(streams: impl IntoIterator<Item = S>) -> Self {
        Self {
            streams: streams.into_iter().collect(),
        }
    }

    /// Returns the number of active streams.
    #[must_use]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Returns true if there are no active streams.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Consumes the combinator, returning the remaining streams.
    #[must_use]
    pub fn into_inner(self) -> VecDeque<S> {
        self.streams
    }
}

impl<S: Unpin> Unpin for Merge<S> {}

impl<S> Stream for Merge<S>
where
    S: Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let len = self.streams.len();
        if len == 0 {
            return Poll::Ready(None);
        }

        for _ in 0..len {
            let mut stream = self.streams.pop_front().expect("length checked");

            match Pin::new(&mut stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.streams.push_back(stream);
                    return Poll::Ready(Some(item));
                }
                Poll::Ready(None) => {
                    // Stream exhausted; drop it.
                }
                Poll::Pending => {
                    self.streams.push_back(stream);
                }
            }
        }

        if self.streams.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut lower = 0usize;
        let mut upper = Some(0usize);

        for stream in &self.streams {
            let (l, u) = stream.size_hint();
            lower = lower.saturating_add(l);
            upper = match (upper, u) {
                (Some(total), Some(v)) => total.checked_add(v),
                _ => None,
            };
        }

        (lower, upper)
    }
}

/// Merge multiple streams into a single stream.
pub fn merge<S>(streams: impl IntoIterator<Item = S>) -> Merge<S>
where
    S: Stream,
{
    Merge::new(streams)
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

    #[test]
    fn merge_yields_all_items() {
        let mut stream = merge([iter(vec![1, 3, 5]), iter(vec![2, 4, 6])]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut items = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => items.push(item),
                Poll::Ready(None) => break,
                Poll::Pending => {}
            }
        }

        items.sort_unstable();
        assert_eq!(items, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn merge_empty() {
        let mut stream: Merge<crate::stream::Iter<std::vec::IntoIter<i32>>> = merge([]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }
}
