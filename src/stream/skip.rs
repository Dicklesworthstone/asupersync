//! Skip combinator.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for skipped items drained in a single poll.
///
/// Without this bound, always-ready upstream streams can monopolize an
/// executor turn when skipping large prefixes (or an unbounded skip_while
/// predicate), preventing fair progress for sibling tasks.
const SKIP_COOPERATIVE_BUDGET: usize = 1024;

/// Stream for the [`skip`](super::StreamExt::skip) method.
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Skip<S> {
    #[pin]
    stream: S,
    remaining: usize,
    exhausted: bool,
}

impl<S> Skip<S> {
    #[inline]
    pub(crate) fn new(stream: S, remaining: usize) -> Self {
        Self {
            stream,
            remaining,
            exhausted: false,
        }
    }
}

impl<S: Stream> Stream for Skip<S> {
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }

        let mut skipped_this_poll = 0usize;
        while *this.remaining > 0 {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(_)) => {
                    *this.remaining -= 1;
                    skipped_this_poll += 1;
                    if *this.remaining > 0 && skipped_this_poll >= SKIP_COOPERATIVE_BUDGET {
                        // Yield cooperatively for fairness, then continue skipping
                        // on the next poll.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.exhausted = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        match this.stream.poll_next(cx) {
            Poll::Ready(None) => {
                *this.exhausted = true;
                Poll::Ready(None)
            }
            other => other,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            return (0, Some(0));
        }
        let (lower, upper) = self.stream.size_hint();
        let lower = lower.saturating_sub(self.remaining);
        let upper = upper.map(|x| x.saturating_sub(self.remaining));
        (lower, upper)
    }
}

/// Stream for the [`skip_while`](super::StreamExt::skip_while) method.
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct SkipWhile<S, F> {
    #[pin]
    stream: S,
    predicate: F,
    done: bool,
    exhausted: bool,
}

impl<S, F> SkipWhile<S, F> {
    #[inline]
    pub(crate) fn new(stream: S, predicate: F) -> Self {
        Self {
            stream,
            predicate,
            done: false,
            exhausted: false,
        }
    }
}

impl<S, F> Stream for SkipWhile<S, F>
where
    S: Stream,
    F: FnMut(&S::Item) -> bool,
{
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }

        if *this.done {
            return match this.stream.poll_next(cx) {
                Poll::Ready(None) => {
                    *this.exhausted = true;
                    Poll::Ready(None)
                }
                other => other,
            };
        }

        let mut skipped_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    if !(this.predicate)(&item) {
                        *this.done = true;
                        return Poll::Ready(Some(item));
                    }
                    skipped_this_poll += 1;
                    if skipped_this_poll >= SKIP_COOPERATIVE_BUDGET {
                        // Prevent one poll from consuming an unbounded run of
                        // skip-matching items.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.exhausted = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            return (0, Some(0));
        }
        let (lower, upper) = self.stream.size_hint();
        if self.done {
            (lower, upper)
        } else {
            (0, upper)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::iter;

    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn collect<S: Stream + Unpin>(stream: &mut S) -> Vec<S::Item> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        while let Poll::Ready(Some(item)) = Pin::new(&mut *stream).poll_next(&mut cx) {
            items.push(item);
        }
        items
    }

    #[derive(Debug, Default)]
    struct AlwaysReadyCounter {
        next: usize,
    }

    impl Stream for AlwaysReadyCounter {
        type Item = usize;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            let item = this.next;
            this.next = this.next.saturating_add(1);
            Poll::Ready(Some(item))
        }
    }

    #[derive(Debug)]
    struct ItemThenNoneThenPanics<T> {
        item: Option<T>,
        completed: bool,
    }

    impl<T> ItemThenNoneThenPanics<T> {
        fn new(item: T) -> Self {
            Self {
                item: Some(item),
                completed: false,
            }
        }
    }

    impl<T: Unpin> Stream for ItemThenNoneThenPanics<T> {
        type Item = T;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            if let Some(item) = this.item.take() {
                return Poll::Ready(Some(item));
            }

            assert!(!this.completed, "inner stream repolled after completion");
            this.completed = true;
            Poll::Ready(None)
        }
    }

    #[test]
    fn test_skip_zero() {
        let mut s = Skip::new(iter(vec![1, 2, 3]), 0);
        assert_eq!(collect(&mut s), vec![1, 2, 3]);
    }

    #[test]
    fn test_skip_some() {
        let mut s = Skip::new(iter(vec![1, 2, 3, 4, 5]), 2);
        assert_eq!(collect(&mut s), vec![3, 4, 5]);
    }

    #[test]
    fn test_skip_all() {
        let mut s = Skip::new(iter(vec![1, 2, 3]), 3);
        assert_eq!(collect(&mut s), Vec::<i32>::new());
    }

    #[test]
    fn test_skip_more_than_len() {
        let mut s = Skip::new(iter(vec![1, 2]), 100);
        assert_eq!(collect(&mut s), Vec::<i32>::new());
    }

    #[test]
    fn test_skip_empty_stream() {
        let mut s = Skip::new(iter(Vec::<i32>::new()), 5);
        assert_eq!(collect(&mut s), Vec::<i32>::new());
    }

    #[test]
    fn test_skip_size_hint() {
        let s = Skip::new(iter(vec![1, 2, 3, 4, 5]), 2);
        let (lower, upper) = s.size_hint();
        assert_eq!(lower, 3);
        assert_eq!(upper, Some(3));
    }

    #[test]
    fn test_skip_while_basic() {
        let mut s = SkipWhile::new(iter(vec![1, 2, 3, 4, 5]), |x: &i32| *x < 3);
        assert_eq!(collect(&mut s), vec![3, 4, 5]);
    }

    #[test]
    fn test_skip_while_none_skipped() {
        let mut s = SkipWhile::new(iter(vec![5, 4, 3]), |x: &i32| *x < 3);
        assert_eq!(collect(&mut s), vec![5, 4, 3]);
    }

    #[test]
    fn test_skip_while_all_skipped() {
        let mut s = SkipWhile::new(iter(vec![1, 2]), |x: &i32| *x < 10);
        assert_eq!(collect(&mut s), Vec::<i32>::new());
    }

    #[test]
    fn test_skip_while_empty() {
        let mut s = SkipWhile::new(iter(Vec::<i32>::new()), |_: &i32| true);
        assert_eq!(collect(&mut s), Vec::<i32>::new());
    }

    #[test]
    fn test_skip_while_size_hint_before_done() {
        let s = SkipWhile::new(iter(vec![1, 2, 3]), |x: &i32| *x < 2);
        let (lower, upper) = s.size_hint();
        assert_eq!(lower, 0); // unknown how many will be skipped
        assert_eq!(upper, Some(3));
    }

    #[test]
    fn test_skip_yields_after_budget_on_always_ready_stream() {
        let mut s = Skip::new(AlwaysReadyCounter::default(), SKIP_COOPERATIVE_BUDGET + 5);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut s).poll_next(&mut cx);
        assert!(matches!(first, Poll::Pending));
        assert_eq!(s.remaining, 5);
        assert_eq!(s.stream.next, SKIP_COOPERATIVE_BUDGET);

        let second = Pin::new(&mut s).poll_next(&mut cx);
        assert_eq!(second, Poll::Ready(Some(SKIP_COOPERATIVE_BUDGET + 5)));
    }

    #[test]
    fn test_skip_does_not_repoll_exhausted_upstream() {
        let mut s = Skip::new(ItemThenNoneThenPanics::new(0usize), 1);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut s).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(Pin::new(&mut s).poll_next(&mut cx), Poll::Ready(None));
    }

    #[test]
    fn test_skip_while_yields_after_budget_when_predicate_stays_true() {
        let mut s = SkipWhile::new(AlwaysReadyCounter::default(), |_: &usize| true);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut s).poll_next(&mut cx);
        assert!(matches!(first, Poll::Pending));
        assert_eq!(s.stream.next, SKIP_COOPERATIVE_BUDGET);
        assert!(!s.done);
    }

    #[test]
    fn test_skip_while_does_not_repoll_exhausted_upstream_while_skipping() {
        let mut s = SkipWhile::new(ItemThenNoneThenPanics::new(0usize), |_: &usize| true);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut s).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(Pin::new(&mut s).poll_next(&mut cx), Poll::Ready(None));
    }

    #[test]
    fn test_skip_while_does_not_repoll_exhausted_upstream_after_done() {
        let mut s = SkipWhile::new(ItemThenNoneThenPanics::new(5usize), |x: &usize| *x < 5);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut s).poll_next(&mut cx), Poll::Ready(Some(5)));
        assert_eq!(Pin::new(&mut s).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(Pin::new(&mut s).poll_next(&mut cx), Poll::Ready(None));
    }
}
