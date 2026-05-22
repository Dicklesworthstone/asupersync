//! Inspect combinator.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`inspect`](super::StreamExt::inspect) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Inspect<S, F> {
    stream: S,
    f: F,
    exhausted: bool,
}

impl<S, F> Inspect<S, F> {
    #[inline]
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            exhausted: false,
        }
    }

    /// Returns a reference to the underlying stream.
    #[inline]
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    #[inline]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    #[inline]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S, F> Stream for Inspect<S, F>
where
    S: Stream + Unpin,
    F: FnMut(&S::Item) + Unpin,
{
    type Item = S::Item;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.exhausted {
            return Poll::Ready(None);
        }

        let next = Pin::new(&mut self.stream).poll_next(cx);
        if let Poll::Ready(Some(ref item)) = next {
            (self.f)(item);
        } else if matches!(next, Poll::Ready(None)) {
            self.exhausted = true;
        }
        next
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            (0, Some(0))
        } else {
            self.stream.size_hint()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::stream::iter;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[derive(Debug)]
    struct EmptyThenPanics {
        polls: Arc<AtomicUsize>,
    }

    impl EmptyThenPanics {
        fn new(polls: Arc<AtomicUsize>) -> Self {
            Self { polls }
        }
    }

    impl Stream for EmptyThenPanics {
        type Item = i32;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let polls = self.polls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(polls, 0, "inspect inner stream repolled after completion");
            Poll::Ready(None)
        }
    }

    fn collect_inspect<S: Stream<Item = I> + Unpin, F: FnMut(&I) + Unpin, I>(
        stream: &mut Inspect<S, F>,
    ) -> Vec<I> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        while let Poll::Ready(Some(item)) = Pin::new(&mut *stream).poll_next(&mut cx) {
            items.push(item);
        }
        items
    }

    #[test]
    fn test_inspect_calls_closure() {
        let mut seen = Vec::new();
        let mut stream = Inspect::new(iter(vec![1, 2, 3]), |item: &i32| seen.push(*item));
        let items = collect_inspect(&mut stream);
        assert_eq!(items, vec![1, 2, 3]);
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn test_inspect_empty_stream() {
        let mut count = 0;
        let mut stream = Inspect::new(iter(Vec::<i32>::new()), |_: &i32| count += 1);
        let items = collect_inspect(&mut stream);
        assert!(items.is_empty());
        assert_eq!(count, 0);
    }

    #[test]
    fn test_inspect_does_not_modify_items() {
        let mut stream = Inspect::new(iter(vec![10, 20]), |_: &i32| {});
        let items = collect_inspect(&mut stream);
        assert_eq!(items, vec![10, 20]);
    }

    #[test]
    fn test_inspect_size_hint() {
        let stream = Inspect::new(iter(vec![1, 2, 3]), |_: &i32| {});
        assert_eq!(stream.size_hint(), (3, Some(3)));
    }

    #[test]
    fn test_inspect_ordering() {
        let mut order = Vec::new();
        let mut stream = Inspect::new(iter(vec!['a', 'b', 'c']), |c: &char| order.push(*c));
        let _ = collect_inspect(&mut stream);
        assert_eq!(order, vec!['a', 'b', 'c']);
    }

    #[test]
    fn mr_inspect_is_identity_for_items() {
        for len in 0..=32usize {
            let values: Vec<i32> = (0..len).map(|item| item as i32 * 3 - 11).collect();
            let mut stream = Inspect::new(iter(values.clone()), |_: &i32| {});

            assert_eq!(
                collect_inspect(&mut stream),
                values,
                "inspect must yield the original item sequence for len {len}",
            );
        }
    }

    #[test]
    fn mr_inspect_observes_each_item_once_in_order() {
        for len in 0..=32usize {
            let values: Vec<i32> = (0..len).map(|item| item as i32 * 5 - 17).collect();
            let seen = Rc::new(RefCell::new(Vec::new()));
            let seen_by_closure = Rc::clone(&seen);
            let mut stream = Inspect::new(iter(values.clone()), move |item: &i32| {
                seen_by_closure.borrow_mut().push(*item);
            });

            assert_eq!(
                collect_inspect(&mut stream),
                values,
                "inspect output must stay unchanged for len {len}",
            );
            assert_eq!(
                seen.borrow().as_slice(),
                values.as_slice(),
                "inspect side effects must observe each item once in order for len {len}",
            );
        }
    }

    #[test]
    fn mr_composed_inspect_observers_see_same_sequence() {
        for len in 0..=32usize {
            let values: Vec<i32> = (0..len).map(|item| item as i32 - 13).collect();
            let first_seen = Rc::new(RefCell::new(Vec::new()));
            let second_seen = Rc::new(RefCell::new(Vec::new()));
            let first_by_closure = Rc::clone(&first_seen);
            let second_by_closure = Rc::clone(&second_seen);
            let mut stream = Inspect::new(
                Inspect::new(iter(values.clone()), move |item: &i32| {
                    first_by_closure.borrow_mut().push(*item);
                }),
                move |item: &i32| {
                    second_by_closure.borrow_mut().push(*item);
                },
            );

            assert_eq!(
                collect_inspect(&mut stream),
                values,
                "composed inspect output must stay unchanged for len {len}",
            );
            assert_eq!(
                first_seen.borrow().as_slice(),
                values.as_slice(),
                "first inspect observer must see each item for len {len}",
            );
            assert_eq!(
                second_seen.borrow().as_slice(),
                values.as_slice(),
                "second inspect observer must see each item for len {len}",
            );
        }
    }

    #[test]
    fn mr_inspect_preserves_size_hint_until_exhaustion() {
        for len in 0..=32usize {
            let values: Vec<i32> = (0..len).map(|item| item as i32 + 7).collect();
            let mut stream = Inspect::new(iter(values), |_: &i32| {});
            assert_eq!(
                stream.size_hint(),
                (len, Some(len)),
                "inspect must preserve upstream size hint before polling for len {len}",
            );

            let collected = collect_inspect(&mut stream);
            assert_eq!(collected.len(), len);
            assert_eq!(
                stream.size_hint(),
                (0, Some(0)),
                "inspect size hint must be exhausted after collection for len {len}",
            );
        }
    }

    #[test]
    fn test_inspect_does_not_repoll_exhausted_upstream() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut stream = Inspect::new(EmptyThenPanics::new(Arc::clone(&polls)), |_: &i32| {});
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_inspect_size_hint_after_exhaustion_is_zero() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut stream = Inspect::new(EmptyThenPanics::new(Arc::clone(&polls)), |_: &i32| {});
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.size_hint(), (0, Some(0)));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }
}
