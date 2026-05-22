//! Convert iterators into streams.
//!
//! This module provides the [`iter`] function to convert any `IntoIterator`
//! into a `Stream`.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that yields items from an iterator.
///
/// Created by the [`iter`] function.
#[derive(Debug)]
pub struct Iter<I> {
    iter: I,
}

impl<I> Iter<I> {
    /// Creates a new `Iter` stream from an iterator.
    #[inline]
    pub(crate) fn new(iter: I) -> Self {
        Self { iter }
    }
}

impl<I> Unpin for Iter<I> {}

impl<I: Iterator> Stream for Iter<I> {
    type Item = I::Item;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.iter.next())
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

/// Convert an iterator into a stream.
///
/// The resulting stream will yield items synchronously (always returning
/// `Poll::Ready`), making it useful for testing and for converting
/// synchronous data sources.
///
/// # Examples
///
/// ```ignore
/// use asupersync::stream::{iter, StreamExt};
///
/// let stream = iter(vec![1, 2, 3]);
/// // stream.next().await returns Some(1), Some(2), Some(3), None
/// ```
#[inline]
pub fn iter<I>(i: I) -> Iter<I::IntoIter>
where
    I: IntoIterator,
{
    Iter::new(i.into_iter())
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

    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn collect_stream<T>(stream: &mut Iter<std::vec::IntoIter<T>>) -> Vec<T> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();

        while let Poll::Ready(Some(item)) = Pin::new(&mut *stream).poll_next(&mut cx) {
            items.push(item);
        }

        items
    }

    #[test]
    fn iter_from_vec() {
        init_test("iter_from_vec");
        let mut stream = iter(vec![1, 2, 3]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(1))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(3)));
        crate::assert_with_log!(ok, "poll 3", "Poll::Ready(Some(3))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("iter_from_vec");
    }

    #[test]
    fn iter_from_range() {
        init_test("iter_from_range");
        let mut stream = iter(1..=3);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(1))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(3)));
        crate::assert_with_log!(ok, "poll 3", "Poll::Ready(Some(3))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("iter_from_range");
    }

    #[test]
    fn iter_empty() {
        init_test("iter_empty");
        let mut stream = iter(std::iter::empty::<i32>());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll empty", "Poll::Ready(None)", poll);
        crate::test_complete!("iter_empty");
    }

    #[test]
    fn iter_size_hint() {
        init_test("iter_size_hint");
        let stream = iter(vec![1, 2, 3]);
        let hint = stream.size_hint();
        let ok = hint == (3, Some(3));
        crate::assert_with_log!(ok, "size hint", (3, Some(3)), hint);
        crate::test_complete!("iter_size_hint");
    }

    #[test]
    fn mr_iter_collection_is_identity_across_boundary_lengths() {
        init_test("mr_iter_collection_is_identity_across_boundary_lengths");
        for len in [0usize, 1, 2, 7, 32, 65] {
            let values: Vec<i32> = (0..len).map(|index| index as i32 * 3 - 11).collect();
            let mut stream = iter(values.clone());

            assert_eq!(
                collect_stream(&mut stream),
                values,
                "iter stream collection must equal original input for len {len}",
            );
            assert_eq!(stream.size_hint(), (0, Some(0)));
        }
        crate::test_complete!("mr_iter_collection_is_identity_across_boundary_lengths");
    }

    #[test]
    fn mr_iter_concatenation_matches_combined_input() {
        init_test("mr_iter_concatenation_matches_combined_input");
        let left = vec![-9, -3, 0, 2];
        let right = vec![5, 8, 13];
        let mut combined = left.clone();
        combined.extend(right.iter().copied());

        let mut left_stream = iter(left);
        let mut right_stream = iter(right);
        let mut combined_stream = iter(combined.clone());
        let mut segmented = collect_stream(&mut left_stream);
        segmented.extend(collect_stream(&mut right_stream));

        assert_eq!(segmented, collect_stream(&mut combined_stream));
        assert_eq!(segmented, combined);
        crate::test_complete!("mr_iter_concatenation_matches_combined_input");
    }

    #[test]
    fn mr_iter_translation_maps_outputs_by_same_offset() {
        init_test("mr_iter_translation_maps_outputs_by_same_offset");
        let values: Vec<i32> = (-8..=8).collect();
        let offset = 23;
        let shifted: Vec<_> = values.iter().map(|value| value + offset).collect();

        let mut baseline_stream = iter(values);
        let mut shifted_stream = iter(shifted);
        let shifted_from_baseline: Vec<_> = collect_stream(&mut baseline_stream)
            .into_iter()
            .map(|value| value + offset)
            .collect();

        assert_eq!(shifted_from_baseline, collect_stream(&mut shifted_stream));
        crate::test_complete!("mr_iter_translation_maps_outputs_by_same_offset");
    }

    #[test]
    fn mr_iter_size_hint_decreases_by_one_per_item() {
        init_test("mr_iter_size_hint_decreases_by_one_per_item");
        let values: Vec<_> = (0..17).collect();
        let mut stream = iter(values.clone());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        for (index, expected) in values.iter().enumerate() {
            let remaining = values.len() - index;
            assert_eq!(
                stream.size_hint(),
                (remaining, Some(remaining)),
                "size hint before poll {index}",
            );
            assert!(matches!(
                Pin::new(&mut stream).poll_next(&mut cx),
                Poll::Ready(Some(item)) if item == *expected
            ));
        }

        assert_eq!(stream.size_hint(), (0, Some(0)));
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(None)
        ));
        assert_eq!(stream.size_hint(), (0, Some(0)));
        crate::test_complete!("mr_iter_size_hint_decreases_by_one_per_item");
    }
}
