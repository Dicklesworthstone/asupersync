//! Throttle combinator for streams.
//!
//! The `Throttle` combinator rate-limits a stream, yielding at most one
//! item per time period. Items that arrive during the suppression window
//! are dropped.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// A stream that yields at most one item per time period.
///
/// Created by [`StreamExt::throttle`](super::StreamExt::throttle).
///
/// The first item from the underlying stream passes through immediately.
/// Subsequent items are suppressed until `period` has elapsed since
/// the last yielded item.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Throttle<S> {
    stream: S,
    period: Duration,
    last_yield: Option<Instant>,
}

impl<S> Throttle<S> {
    /// Creates a new `Throttle` stream.
    pub(crate) fn new(stream: S, period: Duration) -> Self {
        Self {
            stream,
            period,
            last_yield: None,
        }
    }

    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Stream + Unpin> Stream for Throttle<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    let now = Instant::now();
                    let should_yield = match self.last_yield {
                        None => true,
                        Some(last) => now.duration_since(last) >= self.period,
                    };
                    if should_yield {
                        self.last_yield = Some(now);
                        return Poll::Ready(Some(item));
                    }
                    // Drop the item and poll the next one.
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::iter;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn throttle_zero_duration_passes_all() {
        init_test("throttle_zero_duration_passes_all");
        let mut stream = Throttle::new(iter(vec![1, 2, 3]), Duration::ZERO);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(2))
        );
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(3))
        );
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("throttle_zero_duration_passes_all");
    }

    #[test]
    fn throttle_first_item_passes_immediately() {
        init_test("throttle_first_item_passes_immediately");
        let mut stream = Throttle::new(iter(vec![42]), Duration::from_secs(999));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First item always passes regardless of period.
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(42))
        );
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("throttle_first_item_passes_immediately");
    }

    #[test]
    fn throttle_suppresses_rapid_items() {
        init_test("throttle_suppresses_rapid_items");
        // With a large period, all items after the first should be dropped
        // since iter produces them synchronously (zero time between items).
        let mut stream = Throttle::new(iter(vec![1, 2, 3, 4, 5]), Duration::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First item passes.
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(1)));

        // Remaining items are all within 10s window → dropped; stream ends.
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("throttle_suppresses_rapid_items");
    }

    #[test]
    fn throttle_empty_stream() {
        init_test("throttle_empty_stream");
        let mut stream = Throttle::new(iter(Vec::<i32>::new()), Duration::from_millis(100));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("throttle_empty_stream");
    }

    #[test]
    fn throttle_with_delay() {
        init_test("throttle_with_delay");
        // Use a very short period to verify items pass after the window.
        let mut stream = Throttle::new(iter(vec![1, 2, 3]), Duration::from_millis(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First item passes immediately.
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );

        // Sleep to let the window expire.
        std::thread::sleep(Duration::from_millis(5));

        // Now the next available item should pass (2 or 3 depending on timing).
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(_))));
        crate::test_complete!("throttle_with_delay");
    }

    #[test]
    fn throttle_accessors() {
        init_test("throttle_accessors");
        let mut stream = Throttle::new(iter(vec![1, 2]), Duration::from_millis(100));
        let _ref = stream.get_ref();
        let _mut = stream.get_mut();
        let inner = stream.into_inner();
        let mut inner = inner;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(
            Pin::new(&mut inner).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );
        crate::test_complete!("throttle_accessors");
    }

    #[test]
    fn throttle_debug() {
        let stream = Throttle::new(iter(vec![1, 2, 3]), Duration::from_millis(100));
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("Throttle"));
    }
}
