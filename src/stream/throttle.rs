//! Throttle combinator for streams.
//!
//! The `Throttle` combinator rate-limits a stream, yielding at most one
//! item per time period. Items that arrive during the suppression window
//! are dropped.

use super::Stream;
use crate::types::Time;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// Cooperative budget for suppressed items drained in a single poll.
///
/// Without this cap, an always-ready inner stream can monopolize the executor
/// forever while the throttle window is still closed.
const MAX_SUPPRESSED_DRAIN_PER_POLL: usize = 64;

/// A stream that yields at most one item per time period.
///
/// Created by [`StreamExt::throttle`](super::StreamExt::throttle).
///
/// The first item from the underlying stream passes through immediately.
/// Subsequent items are suppressed until `period` has elapsed since
/// the last yielded item.
#[pin_project]
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Throttle<S> {
    #[pin]
    stream: S,
    period: Duration,
    last_yield: Option<Time>,
    done: bool,
    time_getter: fn() -> Time,
}

impl<S> Throttle<S> {
    /// Creates a new `Throttle` stream.
    pub(crate) fn new(stream: S, period: Duration) -> Self {
        Self::with_time_getter(stream, period, wall_clock_now)
    }

    /// Creates a new `Throttle` stream with a custom time source.
    pub fn with_time_getter(stream: S, period: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            stream,
            period,
            last_yield: None,
            done: false,
            time_getter,
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

    /// Returns the configured time source.
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }
}

impl<S: Stream> Stream for Throttle<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let mut this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }
        let mut suppressed = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    let now = (this.time_getter)();
                    let should_yield = match this.last_yield {
                        None => true,
                        Some(last) => {
                            Duration::from_nanos(now.duration_since(*last)) >= *this.period
                        }
                    };
                    if should_yield {
                        *this.last_yield = Some(now);
                        return Poll::Ready(Some(item));
                    }
                    // Drop suppressed items in bounded batches so an always-ready
                    // producer cannot monopolize the executor while the window is closed.
                    suppressed += 1;
                    if suppressed >= MAX_SUPPRESSED_DRAIN_PER_POLL {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.done = true;
                    return Poll::Ready(None);
                }
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    static TEST_NOW_NANOS: AtomicU64 = AtomicU64::new(0);

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    struct TrackWaker(Arc<std::sync::atomic::AtomicBool>);

    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn set_test_time(nanos: u64) {
        TEST_NOW_NANOS.store(nanos, Ordering::SeqCst);
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW_NANOS.load(Ordering::SeqCst))
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
        set_test_time(0);
        let mut stream =
            Throttle::with_time_getter(iter(vec![1, 2, 3]), Duration::from_millis(1), test_time);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First item passes immediately.
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );

        set_test_time(
            Duration::from_millis(5)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );

        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(2))
        );
        set_test_time(
            Duration::from_millis(10)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(3))
        );
        crate::test_complete!("throttle_with_delay");
    }

    #[test]
    fn throttle_accessors() {
        init_test("throttle_accessors");
        set_test_time(17);
        let mut stream =
            Throttle::with_time_getter(iter(vec![1, 2]), Duration::from_millis(100), test_time);
        let _ref = stream.get_ref();
        let _mut = stream.get_mut();
        assert_eq!((stream.time_getter())().as_nanos(), 17);
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

    struct AlwaysReadyStream {
        polls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Stream for AlwaysReadyStream {
        type Item = usize;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let call = self.polls.fetch_add(1, Ordering::SeqCst) + 1;
            assert!(
                call <= MAX_SUPPRESSED_DRAIN_PER_POLL + 1,
                "throttle kept draining suppressed items without yielding"
            );
            Poll::Ready(Some(call))
        }
    }

    #[test]
    fn throttle_yields_after_suppression_budget_on_always_ready_stream() {
        init_test("throttle_yields_after_suppression_budget_on_always_ready_stream");
        set_test_time(0);
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wake_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker: Waker = Arc::new(TrackWaker(Arc::clone(&wake_flag))).into();
        let mut cx = Context::from_waker(&waker);
        let inner = AlwaysReadyStream {
            polls: Arc::clone(&polls),
        };
        let mut stream = Throttle::with_time_getter(inner, Duration::from_secs(1), test_time);

        let first = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(first, Poll::Ready(Some(1)));
        assert_eq!(polls.load(Ordering::SeqCst), 1);

        let second = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(second, Poll::Pending);
        assert!(wake_flag.load(Ordering::SeqCst));
        assert_eq!(
            polls.load(Ordering::SeqCst),
            MAX_SUPPRESSED_DRAIN_PER_POLL + 1
        );
        crate::test_complete!("throttle_yields_after_suppression_budget_on_always_ready_stream");
    }

    #[derive(Debug, Default)]
    struct OneThenDoneThenPanicStream {
        yielded_once: bool,
        completed: bool,
    }

    impl Stream for OneThenDoneThenPanicStream {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if !self.yielded_once {
                self.yielded_once = true;
                return Poll::Ready(Some(7));
            }

            assert!(
                !self.completed,
                "throttle inner stream repolled after completion"
            );
            self.completed = true;
            Poll::Ready(None)
        }
    }

    #[test]
    fn throttle_does_not_repoll_exhausted_upstream() {
        init_test("throttle_does_not_repoll_exhausted_upstream");
        set_test_time(0);
        let mut stream = Throttle::with_time_getter(
            OneThenDoneThenPanicStream::default(),
            Duration::from_secs(1),
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(7))
        );
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("throttle_does_not_repoll_exhausted_upstream");
    }
}
