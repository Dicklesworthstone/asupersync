//! Take combinator.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`take`](super::StreamExt::take) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Take<S> {
    stream: S,
    remaining: usize,
}

impl<S> Take<S> {
    pub(crate) fn new(stream: S, remaining: usize) -> Self {
        Self { stream, remaining }
    }
}

impl<S: Stream + Unpin> Stream for Take<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }

        let next = Pin::new(&mut self.stream).poll_next(cx);
        match next {
            Poll::Ready(Some(item)) => {
                self.remaining -= 1;
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => {
                self.remaining = 0;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.remaining == 0 {
            return (0, Some(0));
        }

        let (lower, upper) = self.stream.size_hint();
        let lower = lower.min(self.remaining);
        let upper = upper.map_or(Some(self.remaining), |x| Some(x.min(self.remaining)));

        (lower, upper)
    }
}

/// Stream for the [`take_while`](super::StreamExt::take_while) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct TakeWhile<S, F> {
    stream: S,
    predicate: F,
    done: bool,
}

impl<S, F> TakeWhile<S, F> {
    pub(crate) fn new(stream: S, predicate: F) -> Self {
        Self {
            stream,
            predicate,
            done: false,
        }
    }
}

impl<S, F> Stream for TakeWhile<S, F>
where
    S: Stream + Unpin,
    F: FnMut(&S::Item) -> bool + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }

        let next = Pin::new(&mut self.stream).poll_next(cx);
        match next {
            Poll::Ready(Some(item)) => {
                if (self.predicate)(&item) {
                    Poll::Ready(Some(item))
                } else {
                    self.done = true;
                    Poll::Ready(None)
                }
            }
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
            return (0, Some(0));
        }
        let (_, upper) = self.stream.size_hint();
        (0, upper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::{iter, StreamExt};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_take_basic() {
        init_test("test_take_basic");
        futures_lite::future::block_on(async {
            let values = iter(vec![1, 2, 3]).take(2).collect::<Vec<_>>().await;
            crate::assert_with_log!(values == vec![1, 2], "take values", vec![1, 2], values);
        });
        crate::test_complete!("test_take_basic");
    }

    #[test]
    fn test_take_zero() {
        init_test("test_take_zero");
        futures_lite::future::block_on(async {
            let values = iter(vec![1, 2]).take(0).collect::<Vec<_>>().await;
            crate::assert_with_log!(values.is_empty(), "take zero", true, values.is_empty());
        });
        let take = Take::new(iter(vec![1, 2]), 0);
        let hint = take.size_hint();
        crate::assert_with_log!(hint == (0, Some(0)), "size_hint", (0, Some(0)), hint);
        crate::test_complete!("test_take_zero");
    }

    #[test]
    fn test_take_size_hint_after_poll() {
        init_test("test_take_size_hint_after_poll");
        let mut take = Take::new(iter(vec![1, 2, 3, 4]), 3);
        let initial = take.size_hint();
        crate::assert_with_log!(
            initial == (3, Some(3)),
            "initial size_hint",
            (3, Some(3)),
            initial
        );
        futures_lite::future::block_on(async {
            let _ = take.next().await;
        });
        let after = take.size_hint();
        crate::assert_with_log!(
            after == (2, Some(2)),
            "after size_hint",
            (2, Some(2)),
            after
        );
        crate::test_complete!("test_take_size_hint_after_poll");
    }

    #[test]
    fn test_take_while_basic() {
        init_test("test_take_while_basic");
        futures_lite::future::block_on(async {
            let values = iter(vec![1, 2, 3, 2])
                .take_while(|v| *v < 3)
                .collect::<Vec<_>>()
                .await;
            crate::assert_with_log!(
                values == vec![1, 2],
                "take_while values",
                vec![1, 2],
                values
            );
        });
        crate::test_complete!("test_take_while_basic");
    }

    #[test]
    fn test_take_while_done_behavior() {
        init_test("test_take_while_done_behavior");
        futures_lite::future::block_on(async {
            let mut stream = iter(vec![1, 2, 3]).take_while(|v| *v < 3);
            let first = stream.next().await;
            crate::assert_with_log!(first == Some(1), "first", Some(1), first);
            let second = stream.next().await;
            crate::assert_with_log!(second == Some(2), "second", Some(2), second);
            let third = stream.next().await;
            crate::assert_with_log!(third.is_none(), "third none", true, third.is_none());
            let fourth = stream.next().await;
            crate::assert_with_log!(fourth.is_none(), "fourth none", true, fourth.is_none());
            let hint = stream.size_hint();
            crate::assert_with_log!(hint == (0, Some(0)), "size_hint done", (0, Some(0)), hint);
        });
        crate::test_complete!("test_take_while_done_behavior");
    }

    #[test]
    fn test_take_while_size_hint() {
        init_test("test_take_while_size_hint");
        let stream = TakeWhile::new(iter(vec![1, 2, 3, 4]), |v: &i32| *v < 10);
        let hint = stream.size_hint();
        crate::assert_with_log!(hint == (0, Some(4)), "size_hint", (0, Some(4)), hint);
        crate::test_complete!("test_take_while_size_hint");
    }
}
