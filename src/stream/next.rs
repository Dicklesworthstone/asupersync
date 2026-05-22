//! Next combinator for streams.
//!
//! The `Next` future returns the next item from a stream.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A future that returns the next item from a stream.
///
/// Created by [`StreamExt::next`](super::StreamExt::next).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Next<'a, S: ?Sized> {
    stream: &'a mut S,
    done: bool,
}

impl<'a, S: ?Sized> Next<'a, S> {
    /// Creates a new `Next` future.
    #[inline]
    pub(crate) fn new(stream: &'a mut S) -> Self {
        Self {
            stream,
            done: false,
        }
    }
}

impl<S: ?Sized + Unpin> Unpin for Next<'_, S> {}

impl<S> Future for Next<'_, S>
where
    S: Stream + Unpin + ?Sized,
{
    type Output = Option<S::Item>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        let poll = Pin::new(&mut *self.stream).poll_next(cx);
        if poll.is_ready() {
            self.done = true;
        }
        poll
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

    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn collect_with_next<S>(stream: &mut S) -> Vec<S::Item>
    where
        S: Stream + Unpin,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut collected = Vec::new();

        loop {
            let mut future = Next::new(stream);
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(Some(item)) => collected.push(item),
                Poll::Ready(None) => return collected,
                Poll::Pending => panic!("ready test stream should not return Pending"),
            }
        }
    }

    fn poll_next_once<S>(stream: &mut S) -> Poll<Option<S::Item>>
    where
        S: Stream + Unpin,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = Next::new(stream);
        Pin::new(&mut future).poll(&mut cx)
    }

    #[derive(Debug)]
    struct PendingOnceThenIter<T> {
        pending: bool,
        items: std::vec::IntoIter<T>,
    }

    impl<T> PendingOnceThenIter<T> {
        fn new(items: Vec<T>) -> Self {
            Self {
                pending: true,
                items: items.into_iter(),
            }
        }
    }

    impl<T: Unpin> Stream for PendingOnceThenIter<T> {
        type Item = T;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.pending {
                self.pending = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            Poll::Ready(self.items.next())
        }
    }

    #[test]
    fn next_returns_items() {
        let mut stream = iter(vec![1i32, 2, 3]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        {
            let mut future = Next::new(&mut stream);
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(Some(1)) => {}
                _ => panic!("expected Ready(Some(1))"),
            }
        }

        {
            let mut future = Next::new(&mut stream);
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(Some(2)) => {}
                _ => panic!("expected Ready(Some(2))"),
            }
        }

        {
            let mut future = Next::new(&mut stream);
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(Some(3)) => {}
                _ => panic!("expected Ready(Some(3))"),
            }
        }

        {
            let mut future = Next::new(&mut stream);
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(None) => {}
                _ => panic!("expected Ready(None)"),
            }
        }
    }

    #[test]
    fn next_empty_stream() {
        let mut stream = iter(Vec::<i32>::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = Next::new(&mut stream);
        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(None) => {}
            _ => panic!("expected Ready(None)"),
        }
    }

    #[test]
    fn next_repoll_after_ready_some_returns_none() {
        let mut stream = iter(vec![1i32]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = Next::new(&mut stream);
        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(Some(1)) => {}
            _ => panic!("expected Ready(Some(1))"),
        }

        let repoll = Pin::new(&mut future).poll(&mut cx);
        assert!(
            matches!(repoll, Poll::Ready(None)),
            "repoll after completion must return None"
        );
    }

    #[test]
    fn next_repoll_after_ready_none_returns_none() {
        let mut stream = iter(Vec::<i32>::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = Next::new(&mut stream);
        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(None) => {}
            _ => panic!("expected Ready(None)"),
        }

        let repoll = Pin::new(&mut future).poll(&mut cx);
        assert!(
            matches!(repoll, Poll::Ready(None)),
            "repoll after completion must return None"
        );
    }

    #[test]
    fn mr_next_repeated_calls_collect_original_sequence() {
        let cases = vec![
            Vec::new(),
            vec![7],
            vec![-3, 0, 8, 13],
            (0..25).map(|index| index * 2 - 17).collect(),
        ];

        for values in cases {
            let mut stream = iter(values.clone());
            assert_eq!(
                collect_with_next(&mut stream),
                values,
                "repeated Next futures must observe the original stream order"
            );
        }
    }

    #[test]
    fn mr_next_prefix_consumption_matches_split_sequence() {
        let values: Vec<i32> = (0..16).map(|index| index * 3 - 9).collect();

        for split in 0..=values.len() {
            let mut stream = iter(values.clone());
            let mut prefix = Vec::new();

            for _ in 0..split {
                match poll_next_once(&mut stream) {
                    Poll::Ready(Some(item)) => prefix.push(item),
                    other => panic!("expected prefix item, got {other:?}"),
                }
            }

            let suffix = collect_with_next(&mut stream);
            assert_eq!(prefix, values[..split].to_vec());
            assert_eq!(suffix, values[split..].to_vec());

            let mut recombined = prefix;
            recombined.extend(suffix);
            assert_eq!(
                recombined, values,
                "prefix + suffix Next consumption must equal unsplit input"
            );
        }
    }

    #[test]
    fn mr_next_pending_cancellation_preserves_first_item() {
        let mut stream = PendingOnceThenIter::new(vec![10, 20]);

        assert!(
            matches!(poll_next_once(&mut stream), Poll::Pending),
            "first Next future should observe the upstream pending state"
        );

        assert_eq!(
            poll_next_once(&mut stream),
            Poll::Ready(Some(10)),
            "dropping a pending Next future must not consume the first item"
        );
        assert_eq!(poll_next_once(&mut stream), Poll::Ready(Some(20)));
        assert_eq!(poll_next_once(&mut stream), Poll::Ready(None));
    }

    #[test]
    fn mr_next_pending_cancellation_preserves_empty_completion() {
        let mut stream = PendingOnceThenIter::<i32>::new(Vec::new());

        assert!(
            matches!(poll_next_once(&mut stream), Poll::Pending),
            "first Next future should observe pending before empty completion"
        );
        assert_eq!(
            poll_next_once(&mut stream),
            Poll::Ready(None),
            "dropping a pending Next future must preserve empty completion"
        );
    }
}
