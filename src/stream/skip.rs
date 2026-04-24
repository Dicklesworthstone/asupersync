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
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
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

    // =========================================================================
    // Conformance: take/skip adapter algebra laws.
    //
    // Per-case tests cover individual Take/Skip behavior. These laws cover
    // *composition*: nested adapters and cross-adapter identities that a
    // StreamExt user relies on (slicing, chunking, cursor-style iteration).
    // A refactor that preserves each adapter in isolation but breaks
    // composition semantics would not be caught by per-case tests.
    // =========================================================================

    mod take_skip_laws {
        use super::*;
        use crate::stream::StreamExt;

        fn drain<S: Stream + Unpin>(mut s: S) -> Vec<S::Item> {
            collect(&mut s)
        }

        /// LAW-TT: take(m).take(n) ≡ take(min(m, n)).
        /// Nested bounded takes collapse to the tighter bound.
        #[test]
        fn law_take_take_is_min() {
            let xs: Vec<i32> = (0..10).collect();
            for m in 0..=12usize {
                for n in 0..=12usize {
                    let nested = drain(iter(xs.clone()).take(m).take(n));
                    let collapsed = drain(iter(xs.clone()).take(m.min(n)));
                    assert_eq!(
                        nested, collapsed,
                        "take({m}).take({n}) != take(min) for xs=0..10",
                    );
                }
            }
        }

        /// LAW-SS: skip(m).skip(n) ≡ skip(m + n).
        /// Nested skips sum. saturating_add guards against usize overflow
        /// for caller-supplied counts near usize::MAX.
        #[test]
        fn law_skip_skip_is_sum() {
            let xs: Vec<i32> = (0..10).collect();
            for m in 0..=6usize {
                for n in 0..=6usize {
                    let nested = drain(iter(xs.clone()).skip(m).skip(n));
                    let collapsed = drain(iter(xs.clone()).skip(m.saturating_add(n)));
                    assert_eq!(
                        nested, collapsed,
                        "skip({m}).skip({n}) != skip(m+n) for xs=0..10",
                    );
                }
            }
        }

        /// LAW-SLICE: skip(n).take(m) ≡ xs[n..n+m] clamped to len.
        /// This is the core slicing invariant users rely on.
        #[test]
        fn law_skip_then_take_is_slice() {
            let xs: Vec<i32> = (0..8).collect();
            for n in 0..=10usize {
                for m in 0..=10usize {
                    let got = drain(iter(xs.clone()).skip(n).take(m));
                    let lo = n.min(xs.len());
                    let hi = lo.saturating_add(m).min(xs.len());
                    let expected: Vec<i32> = xs[lo..hi].to_vec();
                    assert_eq!(
                        got, expected,
                        "skip({n}).take({m}) != xs[{lo}..{hi}]",
                    );
                }
            }
        }

        /// LAW-PARTITION: for any n, the concatenation of take(n)(xs) and
        /// skip(n)(xs) equals xs exactly (order-preserving).
        /// This is the fundamental "prefix/suffix partition" identity.
        #[test]
        fn law_take_skip_partition_preserves_stream() {
            let xs: Vec<i32> = (0..10).collect();
            for n in 0..=12usize {
                let prefix = drain(iter(xs.clone()).take(n));
                let suffix = drain(iter(xs.clone()).skip(n));
                let mut joined = prefix;
                joined.extend(suffix);
                assert_eq!(
                    joined, xs,
                    "take({n}) ++ skip({n}) did not reconstruct xs",
                );
            }
        }

        /// LAW-TAKE-ZERO: take(0) of any stream yields the empty stream.
        #[test]
        fn law_take_zero_is_empty() {
            let samples: Vec<Vec<i32>> = vec![vec![], vec![1], vec![1, 2, 3, 4, 5]];
            for xs in samples {
                let got = drain(iter(xs.clone()).take(0));
                assert!(
                    got.is_empty(),
                    "take(0) on {xs:?} should be empty, got {got:?}",
                );
            }
        }

        /// LAW-SKIP-ZERO: skip(0) is identity on order and content.
        #[test]
        fn law_skip_zero_is_identity() {
            let samples: Vec<Vec<i32>> = vec![vec![], vec![1], vec![1, 2, 3, 4, 5]];
            for xs in samples {
                let got = drain(iter(xs.clone()).skip(0));
                assert_eq!(got, xs, "skip(0) is not identity for {xs:?}");
            }
        }

        /// LAW-SKIP-OVERFLOW: skip(len + k) on an xs of length len yields
        /// the empty stream for any k ≥ 0.
        #[test]
        fn law_skip_beyond_length_is_empty() {
            let xs: Vec<i32> = (0..5).collect();
            for k in 0..=3usize {
                let n = xs.len().saturating_add(k);
                let got = drain(iter(xs.clone()).skip(n));
                assert!(
                    got.is_empty(),
                    "skip(len+{k})={n} on 5-elt stream should be empty, got {got:?}",
                );
            }
        }

        /// LAW-TAKE-SATURATE: take(n) where n >= xs.len() yields all items.
        /// Beyond-length takes saturate at the stream length rather than
        /// extending with None spuriously.
        #[test]
        fn law_take_beyond_length_is_identity() {
            let xs: Vec<i32> = (0..5).collect();
            for k in 0..=3usize {
                let n = xs.len().saturating_add(k);
                let got = drain(iter(xs.clone()).take(n));
                assert_eq!(
                    got, xs,
                    "take(len+{k})={n} on 5-elt stream should be identity",
                );
            }
        }

        /// LAW-TS: take(m).skip(n) ≡ xs[n..m.min(len)] (reversed-order
        /// composition). Differs from skip().take() in that the window
        /// is bounded by m first, then we discard the first n of that.
        #[test]
        fn law_take_then_skip_bounded_by_take() {
            let xs: Vec<i32> = (0..8).collect();
            for m in 0..=10usize {
                for n in 0..=10usize {
                    let got = drain(iter(xs.clone()).take(m).skip(n));
                    let upper = m.min(xs.len());
                    let lo = n.min(upper);
                    let expected: Vec<i32> = xs[lo..upper].to_vec();
                    assert_eq!(
                        got, expected,
                        "take({m}).skip({n}) != xs[{lo}..{upper}]",
                    );
                }
            }
        }
    }
}
