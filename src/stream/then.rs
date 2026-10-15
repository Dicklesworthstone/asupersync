//! Then (async map) combinator.

use super::Stream;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`then`](super::StreamExt::then) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
#[pin_project]
pub struct Then<S, Fut, F> {
    #[pin]
    stream: S,
    f: F,
    #[pin]
    pending: Option<Fut>,
    done: bool,
}

impl<S, Fut, F> Then<S, Fut, F> {
    #[inline]
    pub(crate) fn new(stream: S, f: F) -> Self {
        Self {
            stream,
            f,
            pending: None,
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

impl<S, Fut, F> Stream for Then<S, Fut, F>
where
    S: Stream,
    F: FnMut(S::Item) -> Fut,
    Fut: Future,
{
    type Item = Fut::Output;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }

        loop {
            if let Some(fut) = this.pending.as_mut().as_pin_mut() {
                match fut.poll(cx) {
                    Poll::Ready(item) => {
                        this.pending.set(None);
                        return Poll::Ready(Some(item));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    let fut = (this.f)(item);
                    this.pending.set(Some(fut));
                }
                Poll::Ready(None) => {
                    *this.done = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
            return (0, Some(0));
        }
        let (lower, upper) = self.stream.size_hint();
        let pending_len = usize::from(self.pending.is_some());
        (
            lower.saturating_add(pending_len),
            upper.and_then(|u| u.checked_add(pending_len)),
        )
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

    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[derive(Debug, Default)]
    struct EmptyThenPanics {
        completed: bool,
    }

    impl Stream for EmptyThenPanics {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            assert!(
                !self.completed,
                "then inner stream repolled after completion"
            );
            self.completed = true;
            Poll::Ready(None)
        }
    }

    #[derive(Debug)]
    struct PendingOnce<T> {
        item: Option<T>,
        yielded_pending: bool,
    }

    impl<T> PendingOnce<T> {
        fn new(item: T) -> Self {
            Self {
                item: Some(item),
                yielded_pending: false,
            }
        }
    }

    impl<T: Unpin> Future for PendingOnce<T> {
        type Output = T;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if !self.yielded_pending {
                self.yielded_pending = true;
                return Poll::Pending;
            }

            Poll::Ready(
                self.item
                    .take()
                    .expect("pending-once future polled after completion"),
            )
        }
    }

    fn collect_then<S, Fut, F>(stream: Then<S, Fut, F>) -> Vec<Fut::Output>
    where
        S: Stream,
        F: FnMut(S::Item) -> Fut,
        Fut: Future,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        let mut stream = Box::pin(stream);
        while let Poll::Ready(Some(item)) = stream.as_mut().poll_next(&mut cx) {
            items.push(item);
        }
        items
    }

    fn collect_then_to_completion<S, Fut, F>(stream: Then<S, Fut, F>) -> (Vec<Fut::Output>, usize)
    where
        S: Stream,
        F: FnMut(S::Item) -> Fut,
        Fut: Future,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut items = Vec::new();
        let mut pending_polls = 0usize;
        let mut stream = Box::pin(stream);

        loop {
            match stream.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(item)) => items.push(item),
                Poll::Ready(None) => return (items, pending_polls),
                Poll::Pending => {
                    pending_polls += 1;
                    assert!(
                        pending_polls <= 16,
                        "then stream did not complete after {pending_polls} pending polls",
                    );
                }
            }
        }
    }

    #[test]
    fn test_then_async_transform() {
        let s = Then::new(iter(vec![1, 2, 3]), |x: i32| async move { x * 2 });
        let items = collect_then(s);
        assert_eq!(items, vec![2, 4, 6]);
    }

    #[test]
    fn test_then_empty_stream() {
        let s = Then::new(iter(Vec::<i32>::new()), |x: i32| async move { x });
        let items = collect_then(s);
        assert!(items.is_empty());
    }

    #[test]
    fn test_then_type_change() {
        let s = Then::new(iter(vec![1, 2]), |x: i32| async move { format!("{x}") });
        let items = collect_then(s);
        assert_eq!(items, vec!["1".to_string(), "2".to_string()]);
    }

    #[test]
    fn test_then_size_hint() {
        let s = Then::new(iter(vec![1, 2, 3]), |x: i32| async move { x });
        assert_eq!(s.size_hint(), (3, Some(3)));
    }

    #[test]
    fn test_then_single_item() {
        let s = Then::new(iter(vec![42]), |x: i32| async move { x + 1 });
        let items = collect_then(s);
        assert_eq!(items, vec![43]);
    }

    #[test]
    fn test_then_does_not_repoll_exhausted_upstream() {
        let stream = Then::new(EmptyThenPanics::default(), |x: i32| async move { x });
        let mut stream = std::pin::pin!(stream);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(stream.as_mut().poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.as_mut().poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(stream.size_hint(), (0, Some(0)));
    }

    #[test]
    fn mr_then_identity_preserves_sequence() {
        let input = vec![5i32, -2, 0, 11, -7];
        let stream = Then::new(iter(input.clone()), |x: i32| async move { x });

        let (items, pending_polls) = collect_then_to_completion(stream);

        assert_eq!(items, input);
        assert_eq!(pending_polls, 0);
    }

    #[test]
    fn mr_then_partition_matches_concatenated_input() {
        let prefix = vec![3i32, -1, 8];
        let suffix = vec![0i32, 5, -4];
        let mut combined = prefix.clone();
        combined.extend(suffix.iter().copied());
        let transform = |x: i32| async move { (x * x) - 2 };

        let (combined_items, combined_pending) =
            collect_then_to_completion(Then::new(iter(combined), transform));
        let (mut partitioned_items, prefix_pending) =
            collect_then_to_completion(Then::new(iter(prefix), transform));
        let (suffix_items, suffix_pending) =
            collect_then_to_completion(Then::new(iter(suffix), transform));
        partitioned_items.extend(suffix_items);

        assert_eq!(combined_items, partitioned_items);
        assert_eq!(combined_pending + prefix_pending + suffix_pending, 0);
    }

    #[test]
    fn mr_then_affine_transform_scales_translated_inputs() {
        let input = vec![-3i32, 0, 4, 9];
        let translated: Vec<_> = input.iter().map(|x| x + 10).collect();
        let transform = |x: i32| async move { (x * 3) - 7 };

        let (base_items, _) = collect_then_to_completion(Then::new(iter(input), transform));
        let (translated_items, _) =
            collect_then_to_completion(Then::new(iter(translated), transform));
        let expected_translated: Vec<_> = base_items.iter().map(|x| x + 30).collect();

        assert_eq!(translated_items, expected_translated);
    }

    #[test]
    fn mr_then_pending_futures_preserve_order() {
        let stream = Then::new(iter(vec![1i32, 2, 3, 4]), |x: i32| PendingOnce::new(x * 10));

        let (items, pending_polls) = collect_then_to_completion(stream);

        assert_eq!(items, vec![10, 20, 30, 40]);
        assert_eq!(pending_polls, 4);
    }

    #[test]
    fn mr_then_size_hint_retains_pending_item() {
        let stream = Then::new(iter(vec![7i32, 8]), |x: i32| PendingOnce::new(x * 10));
        let mut stream = std::pin::pin!(stream);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(stream.size_hint(), (2, Some(2)));
        assert_eq!(stream.as_mut().poll_next(&mut cx), Poll::Pending);
        assert_eq!(stream.size_hint(), (2, Some(2)));
        assert_eq!(stream.as_mut().poll_next(&mut cx), Poll::Ready(Some(70)));
        assert_eq!(stream.size_hint(), (1, Some(1)));
    }
}
