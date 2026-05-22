//! Enumerate combinator.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`enumerate`](super::StreamExt::enumerate) method.
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Enumerate<S> {
    #[pin]
    stream: S,
    count: usize,
    done: bool,
}

impl<S> Enumerate<S> {
    #[inline]
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            count: 0,
            done: false,
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

impl<S: Stream> Stream for Enumerate<S> {
    type Item = (usize, S::Item);

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }

        match this.stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(item)) => {
                let index = *this.count;
                *this.count += 1;
                Poll::Ready(Some((index, item)))
            }
            Poll::Ready(None) => {
                *this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
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
    use crate::stream::{Chain, Map, iter};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn collect_enum<S: Stream + Unpin>(stream: &mut Enumerate<S>) -> Vec<(usize, S::Item)> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        while let Poll::Ready(Some(item)) = Pin::new(&mut *stream).poll_next(&mut cx) {
            items.push(item);
        }
        items
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
            assert_eq!(polls, 0, "enumerate inner stream repolled after completion");
            Poll::Ready(None)
        }
    }

    #[test]
    fn test_enumerate_indices() {
        let mut e = Enumerate::new(iter(vec!["a", "b", "c"]));
        let items = collect_enum(&mut e);
        assert_eq!(items, vec![(0, "a"), (1, "b"), (2, "c")]);
    }

    #[test]
    fn test_enumerate_empty() {
        let mut e = Enumerate::new(iter(Vec::<i32>::new()));
        let items = collect_enum(&mut e);
        assert!(items.is_empty());
    }

    #[test]
    fn test_enumerate_single() {
        let mut e = Enumerate::new(iter(vec![42]));
        let items = collect_enum(&mut e);
        assert_eq!(items, vec![(0, 42)]);
    }

    #[test]
    fn test_enumerate_size_hint() {
        let e = Enumerate::new(iter(vec![1, 2, 3]));
        assert_eq!(e.size_hint(), (3, Some(3)));
    }

    #[test]
    fn test_enumerate_many_items() {
        let v: Vec<i32> = (0..100).collect();
        let mut e = Enumerate::new(iter(v));
        let items = collect_enum(&mut e);
        assert_eq!(items.len(), 100);
        assert_eq!(items[0], (0, 0));
        assert_eq!(items[99], (99, 99));
    }

    #[test]
    fn test_enumerate_chain_matches_offset_parts() {
        let left_items = vec!["a", "b", "c"];
        let right_items = vec!["d", "e"];

        let mut chained = Enumerate::new(Chain::new(
            iter(left_items.clone()),
            iter(right_items.clone()),
        ));
        let chained_items = collect_enum(&mut chained);

        let mut expected = Enumerate::new(iter(left_items.clone()));
        let mut expected_items = collect_enum(&mut expected);
        expected_items.extend(
            right_items
                .into_iter()
                .enumerate()
                .map(|(index, item)| (index + left_items.len(), item)),
        );

        assert_eq!(chained_items, expected_items);
    }

    #[test]
    fn mr_enumerate_indices_match_input_length() {
        for len in 0..=32usize {
            let values: Vec<i32> = (0..len).map(|item| item as i32 * 3 - 11).collect();
            let mut enumerated = Enumerate::new(iter(values));
            let items = collect_enum(&mut enumerated);

            let indices: Vec<usize> = items.iter().map(|(index, _)| *index).collect();
            assert_eq!(
                indices,
                (0..len).collect::<Vec<_>>(),
                "enumerate indices must be exactly 0..len for len {len}",
            );
        }
    }

    #[test]
    fn mr_enumerate_projection_preserves_input_order() {
        for len in 0..=32usize {
            let values: Vec<i32> = (0..len).map(|item| item as i32 * 5 - 17).collect();
            let mut enumerated = Enumerate::new(iter(values.clone()));
            let items = collect_enum(&mut enumerated);
            let projected: Vec<i32> = items.into_iter().map(|(_, item)| item).collect();

            assert_eq!(
                projected, values,
                "dropping enumerate indices must recover the original stream order for len {len}",
            );
        }
    }

    #[test]
    fn mr_enumerate_map_preserves_indices_and_maps_values() {
        for len in 0..=32usize {
            let values: Vec<i32> = (0..len).map(|item| item as i32 - 13).collect();
            let mut mapped = Enumerate::new(Map::new(iter(values.clone()), |item: i32| {
                item.wrapping_mul(7).wrapping_add(3)
            }));
            let expected: Vec<(usize, i32)> = values
                .into_iter()
                .enumerate()
                .map(|(index, item)| (index, item.wrapping_mul(7).wrapping_add(3)))
                .collect();

            assert_eq!(
                collect_enum(&mut mapped),
                expected,
                "enumerating a mapped stream must preserve indices and map values for len {len}",
            );
        }
    }

    #[test]
    fn mr_enumerate_chain_offsets_right_indices() {
        for left_len in 0..=12usize {
            for right_len in 0..=12usize {
                let left: Vec<i32> = (0..left_len).map(|item| item as i32 - 20).collect();
                let right: Vec<i32> = (0..right_len).map(|item| item as i32 + 50).collect();
                let mut chained =
                    Enumerate::new(Chain::new(iter(left.clone()), iter(right.clone())));
                let mut expected: Vec<(usize, i32)> = left.into_iter().enumerate().collect();
                expected.extend(
                    right
                        .into_iter()
                        .enumerate()
                        .map(|(index, item)| (index + left_len, item)),
                );

                assert_eq!(
                    collect_enum(&mut chained),
                    expected,
                    "right-hand chain indices must be offset by left length {left_len} for right length {right_len}",
                );
            }
        }
    }

    #[test]
    fn test_enumerate_does_not_repoll_exhausted_upstream() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut enumerate = Enumerate::new(EmptyThenPanics::new(Arc::clone(&polls)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            Pin::new(&mut enumerate).poll_next(&mut cx),
            Poll::Ready(None)
        );
        assert_eq!(
            Pin::new(&mut enumerate).poll_next(&mut cx),
            Poll::Ready(None)
        );
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_enumerate_size_hint_after_exhaustion() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut enumerate = Enumerate::new(EmptyThenPanics::new(Arc::clone(&polls)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            Pin::new(&mut enumerate).poll_next(&mut cx),
            Poll::Ready(None)
        );
        assert_eq!(enumerate.size_hint(), (0, Some(0)));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }
}
