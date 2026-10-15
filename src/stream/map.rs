//! Map combinator for streams.
//!
//! The `Map` combinator transforms each item in a stream using a provided function.

use super::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that transforms each item using a function.
///
/// Created by [`StreamExt::map`](super::StreamExt::map).
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Map<S, F> {
    #[pin]
    stream: S,
    f: F,
    exhausted: bool,
}

impl<S, F> Map<S, F> {
    /// Creates a new `Map` stream.
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

impl<S, F, T> Stream for Map<S, F>
where
    S: Stream,
    F: FnMut(S::Item) -> T,
{
    type Item = T;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let this = self.project();
        if *this.exhausted {
            return Poll::Ready(None);
        }

        match this.stream.poll_next(cx) {
            Poll::Ready(Some(item)) => Poll::Ready(Some((this.f)(item))),
            Poll::Ready(None) => {
                *this.exhausted = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn collect_ready<S: Stream + Unpin>(stream: &mut S) -> Vec<S::Item> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        while let Poll::Ready(Some(item)) = Pin::new(&mut *stream).poll_next(&mut cx) {
            items.push(item);
        }
        items
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
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
            assert_eq!(polls, 0, "map inner stream repolled after completion");
            Poll::Ready(None)
        }
    }

    #[test]
    fn map_transforms_items() {
        init_test("map_transforms_items");
        let mut stream = Map::new(iter(vec![1i32, 2, 3]), |x: i32| x * 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(4)));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some(4))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(6)));
        crate::assert_with_log!(ok, "poll 3", "Poll::Ready(Some(6))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("map_transforms_items");
    }

    #[test]
    fn map_preserves_size_hint() {
        init_test("map_preserves_size_hint");
        let stream = Map::new(iter(vec![1i32, 2, 3]), |x: i32| x * 2);
        let hint = stream.size_hint();
        let ok = hint == (3, Some(3));
        crate::assert_with_log!(ok, "size hint", (3, Some(3)), hint);
        crate::test_complete!("map_preserves_size_hint");
    }

    #[test]
    fn map_type_change() {
        init_test("map_type_change");
        let mut stream = Map::new(iter(vec![1i32, 2, 3]), |x: i32| x.to_string());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(ref s)) if s == "1");
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(\"1\"))", poll);
        crate::test_complete!("map_type_change");
    }

    /// Invariant: map of empty stream produces None immediately.
    #[test]
    fn map_empty_stream() {
        init_test("map_empty_stream");
        let mut stream = Map::new(iter(Vec::<i32>::new()), |x: i32| x * 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let is_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(is_none, "empty map yields None", true, is_none);
        crate::test_complete!("map_empty_stream");
    }

    /// Invariant: Map accessors (get_ref, get_mut, into_inner) work correctly.
    #[test]
    fn map_accessors() {
        init_test("map_accessors");
        let mut stream = Map::new(iter(vec![1, 2, 3]), |x: i32| x + 10);

        let _inner_ref = stream.get_ref();
        let _inner_mut = stream.get_mut();

        let recovered = stream.into_inner();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut recovered = recovered;
        let poll = Pin::new(&mut recovered).poll_next(&mut cx);
        let got_1 = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(got_1, "into_inner preserves items", true, got_1);

        crate::test_complete!("map_accessors");
    }

    #[test]
    fn map_composition_matches_single_pass_map() {
        init_test("map_composition_matches_single_pass_map");
        let values = vec![-3i32, -1, 0, 2, 5, 8];

        let mut two_stage = Map::new(Map::new(iter(values.clone()), |x: i32| x * 2 + 1), |x| {
            x - 4
        });
        let mut one_stage = Map::new(iter(values), |x: i32| (x * 2 + 1) - 4);

        assert_eq!(collect_ready(&mut two_stage), collect_ready(&mut one_stage));
        crate::test_complete!("map_composition_matches_single_pass_map");
    }

    #[test]
    fn mr_map_identity_preserves_items_across_lengths() {
        init_test("mr_map_identity_preserves_items_across_lengths");
        for len in 0..=16usize {
            let values: Vec<i32> = (0..len).map(|item| item as i32 - 8).collect();
            let mut stream = Map::new(iter(values.clone()), |x: i32| x);

            assert_eq!(
                collect_ready(&mut stream),
                values,
                "mapping identity must preserve order and contents for len {len}",
            );
        }
        crate::test_complete!("mr_map_identity_preserves_items_across_lengths");
    }

    #[test]
    fn mr_map_composition_matches_single_pass_for_affine_transforms() {
        init_test("mr_map_composition_matches_single_pass_for_affine_transforms");
        for len in 0..=12usize {
            let values: Vec<i32> = (0..len).map(|item| item as i32 * 2 - 11).collect();
            for scale in [-3, -1, 0, 2, 5] {
                for offset in [-7, 0, 4] {
                    let mut two_stage = Map::new(
                        Map::new(iter(values.clone()), move |x: i32| x * scale),
                        move |x| x + offset,
                    );
                    let mut one_stage =
                        Map::new(iter(values.clone()), move |x: i32| (x * scale) + offset);

                    assert_eq!(
                        collect_ready(&mut two_stage),
                        collect_ready(&mut one_stage),
                        "map composition must match fused transform for len {len}, scale {scale}, offset {offset}",
                    );
                }
            }
        }
        crate::test_complete!("mr_map_composition_matches_single_pass_for_affine_transforms");
    }

    #[test]
    fn mr_map_preserves_cardinality_and_size_hint() {
        init_test("mr_map_preserves_cardinality_and_size_hint");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        for len in 0..=10usize {
            let values: Vec<i32> = (0..len).map(|item| item as i32 - 3).collect();
            let mut stream = Map::new(iter(values), |x: i32| (x * 3) - 1);

            assert_eq!(stream.size_hint(), (len, Some(len)));
            for consumed in 0..len {
                assert!(matches!(
                    Pin::new(&mut stream).poll_next(&mut cx),
                    Poll::Ready(Some(_))
                ));
                let remaining = len - consumed - 1;
                assert_eq!(stream.size_hint(), (remaining, Some(remaining)));
            }

            assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
            assert_eq!(stream.size_hint(), (0, Some(0)));
        }
        crate::test_complete!("mr_map_preserves_cardinality_and_size_hint");
    }

    #[test]
    fn map_debug() {
        fn double(x: i32) -> i32 {
            x * 2
        }
        let stream = Map::new(iter(vec![1, 2, 3]), double as fn(i32) -> i32);
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("Map"));
    }

    #[test]
    fn map_does_not_repoll_exhausted_upstream() {
        init_test("map_does_not_repoll_exhausted_upstream");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut stream = Map::new(EmptyThenPanics::new(Arc::clone(&polls)), |x: i32| x * 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        crate::test_complete!("map_does_not_repoll_exhausted_upstream");
    }

    #[test]
    fn map_size_hint_after_exhaustion_is_zero() {
        init_test("map_size_hint_after_exhaustion_is_zero");
        let polls = Arc::new(AtomicUsize::new(0));
        let mut stream = Map::new(EmptyThenPanics::new(Arc::clone(&polls)), |x: i32| x * 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.size_hint(), (0, Some(0)));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        crate::test_complete!("map_size_hint_after_exhaustion_is_zero");
    }
}
