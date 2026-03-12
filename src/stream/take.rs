//! Take combinator.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`take`](super::StreamExt::take) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Take<S> {
    #[pin]
    stream: S,
    remaining: usize,
    done: bool,
}

impl<S> Take<S> {
    pub(crate) fn new(stream: S, remaining: usize) -> Self {
        Self {
            stream,
            remaining,
            done: false,
        }
    }
}

impl<S: Stream> Stream for Take<S> {
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }
        if *this.remaining == 0 {
            *this.done = true;
            return Poll::Ready(None);
        }

        let next = this.stream.poll_next(cx);
        match next {
            Poll::Ready(Some(item)) => {
                *this.remaining -= 1;
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => {
                *this.remaining = 0;
                *this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done || self.remaining == 0 {
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
#[pin_project]
pub struct TakeWhile<S, F> {
    #[pin]
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
    S: Stream,
    F: FnMut(&S::Item) -> bool,
{
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }

        let next = this.stream.poll_next(cx);
        match next {
            Poll::Ready(Some(item)) => {
                if (this.predicate)(&item) {
                    Poll::Ready(Some(item))
                } else {
                    *this.done = true;
                    Poll::Ready(None)
                }
            }
            Poll::Ready(None) => {
                *this.done = true;
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
    use crate::stream::{StreamExt, iter};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
    }

    #[derive(Debug)]
    struct PollCountingEmptyStream {
        polls: Arc<AtomicUsize>,
    }

    impl PollCountingEmptyStream {
        fn new(polls: Arc<AtomicUsize>) -> Self {
            Self { polls }
        }
    }

    impl Stream for PollCountingEmptyStream {
        type Item = i32;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(None)
        }
    }

    #[derive(Debug)]
    struct PollCountingSingleStream {
        polls: Arc<AtomicUsize>,
        next: Option<i32>,
        completed: bool,
    }

    impl PollCountingSingleStream {
        fn new(item: i32, polls: Arc<AtomicUsize>) -> Self {
            Self {
                polls,
                next: Some(item),
                completed: false,
            }
        }
    }

    impl Stream for PollCountingSingleStream {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            assert!(!self.completed, "inner stream repolled after completion");
            self.polls.fetch_add(1, Ordering::SeqCst);
            if let Some(item) = self.next.take() {
                Poll::Ready(Some(item))
            } else {
                self.completed = true;
                Poll::Ready(None)
            }
        }
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
        let stream = iter(vec![1, 2, 3]).take_while(|v| *v < 3);
        let mut stream = std::pin::pin!(stream);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = stream.as_mut().poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Some(1))),
            "first",
            "Poll::Ready(Some(1))",
            &first
        );
        let second = stream.as_mut().poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Some(2))),
            "second",
            "Poll::Ready(Some(2))",
            &second
        );
        let third = stream.as_mut().poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(third, Poll::Ready(None)),
            "third none",
            "Poll::Ready(None)",
            &third
        );
        let hint = stream.as_ref().get_ref().size_hint();
        crate::assert_with_log!(hint == (0, Some(0)), "size_hint done", (0, Some(0)), hint);

        let fourth = stream.as_mut().poll_next(&mut cx);
        crate::assert_with_log!(
            fourth == Poll::Ready(None),
            "fourth returns None",
            Poll::Ready(None::<i32>),
            fourth
        );
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

    #[test]
    fn take_debug() {
        let stream = Take::new(iter(vec![1, 2, 3]), 2);
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("Take"));
    }

    #[test]
    fn take_while_debug() {
        #[allow(clippy::trivially_copy_pass_by_ref)]
        fn pred(v: &i32) -> bool {
            *v < 5
        }
        let stream = TakeWhile::new(iter(vec![1, 2]), pred as fn(&i32) -> bool);
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("TakeWhile"));
    }

    #[test]
    fn test_take_repoll_after_zero_limit_returns_none_without_polling_inner() {
        init_test("test_take_repoll_after_zero_limit_returns_none_without_polling_inner");
        let polls = Arc::new(AtomicUsize::new(0));
        let stream = Take::new(PollCountingEmptyStream::new(Arc::clone(&polls)), 0);
        let mut stream = std::pin::pin!(stream);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            stream.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));
        let second = stream.as_mut().poll_next(&mut cx);

        assert!(
            matches!(second, Poll::Ready(None)),
            "second poll should return None"
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "zero-limit take must not touch the inner stream"
        );
        crate::test_complete!(
            "test_take_repoll_after_zero_limit_returns_none_without_polling_inner"
        );
    }

    #[test]
    fn test_take_repoll_after_inner_completion_returns_none_without_repolling_inner() {
        init_test("test_take_repoll_after_inner_completion_returns_none_without_repolling_inner");
        let polls = Arc::new(AtomicUsize::new(0));
        let stream = Take::new(PollCountingEmptyStream::new(Arc::clone(&polls)), 1);
        let mut stream = std::pin::pin!(stream);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            stream.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "inner stream should be polled once to discover exhaustion"
        );

        let second = stream.as_mut().poll_next(&mut cx);

        assert!(
            matches!(second, Poll::Ready(None)),
            "second poll should return None"
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "completed take must not repoll the exhausted inner stream"
        );
        crate::test_complete!(
            "test_take_repoll_after_inner_completion_returns_none_without_repolling_inner"
        );
    }

    #[test]
    fn test_take_while_repoll_after_completion_returns_none_without_repolling_inner() {
        init_test("test_take_while_repoll_after_completion_returns_none_without_repolling_inner");
        let polls = Arc::new(AtomicUsize::new(0));
        let stream = TakeWhile::new(
            PollCountingSingleStream::new(3, Arc::clone(&polls)),
            |v: &i32| *v < 3,
        );
        let mut stream = std::pin::pin!(stream);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            stream.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "predicate-failing item should be observed exactly once"
        );

        let second = stream.as_mut().poll_next(&mut cx);

        assert!(
            matches!(second, Poll::Ready(None)),
            "second poll should return None"
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "completed take_while must not repoll the inner stream"
        );
        crate::test_complete!(
            "test_take_while_repoll_after_completion_returns_none_without_repolling_inner"
        );
    }
}
