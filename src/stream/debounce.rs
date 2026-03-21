//! Debounce combinator for streams.
//!
//! The `Debounce` combinator suppresses rapid bursts of items, yielding
//! only the most recent item after a quiet period has elapsed.

use super::Stream;
use crate::time::Sleep;
use crate::types::Time;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// Cooperative budget for immediately-ready items drained in a single poll.
///
/// Without this cap, an always-ready upstream stream can monopolize the
/// executor forever while debounce keeps replacing the buffered item and
/// resetting the quiet-period timer.
const DEBOUNCE_READY_DRAIN_BUDGET: usize = 1024;

/// A stream that debounces items, emitting only after a quiet period.
///
/// Created by [`StreamExt::debounce`](super::StreamExt::debounce).
///
/// When the underlying stream produces an item, it is buffered. If no
/// new item arrives for `period`, the buffered item is yielded. Each
/// new item replaces the buffered value and resets the timer.
///
/// When the underlying stream ends, any buffered item is flushed
/// immediately.
///
/// # Note
///
/// By default this combinator uses the runtime wall clock via
/// [`crate::time::wall_now`], but tests and adapters can override that with
/// [`Debounce::with_time_getter`]. The combinator still arms an internal
/// [`Sleep`] so the executor gets a real wakeup when the quiet period expires,
/// while readiness decisions continue to use the configured time getter.
#[pin_project]
#[must_use = "streams do nothing unless polled"]
pub struct Debounce<S: Stream> {
    #[pin]
    stream: S,
    period: Duration,
    /// The most recently received item and when it was received.
    pending: Option<(S::Item, Time)>,
    /// Whether the underlying stream has ended.
    done: bool,
    /// Wake-capable timer source for delayed wakeup (avoids spin-loop).
    ///
    /// Expiry decisions still use `time_getter`; this sleep exists so the
    /// executor has a real wake source instead of hanging until an unrelated
    /// poll arrives.
    timer: Option<Pin<Box<Sleep>>>,
    time_getter: fn() -> Time,
}

impl<S: Stream + std::fmt::Debug> std::fmt::Debug for Debounce<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Debounce")
            .field("stream", &self.stream)
            .field("period", &self.period)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<S: Stream> Debounce<S> {
    /// Creates a new `Debounce` stream.
    pub(crate) fn new(stream: S, period: Duration) -> Self {
        Self::with_time_getter(stream, period, wall_clock_now)
    }

    /// Creates a new `Debounce` stream with a custom time source.
    pub fn with_time_getter(stream: S, period: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            stream,
            period,
            pending: None,
            done: false,
            timer: None,
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

impl<S: Stream> Stream for Debounce<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let mut this = self.project();

        // Drain all immediately available items from the underlying stream.
        let had_pending_before = this.pending.is_some();
        let mut drained_this_poll = 0usize;
        if !*this.done {
            loop {
                match this.stream.as_mut().poll_next(cx) {
                    Poll::Ready(Some(item)) => {
                        *this.pending = Some((item, (this.time_getter)()));
                        // New item arrived, reset the timer.
                        *this.timer = None;
                        drained_this_poll += 1;
                        if drained_this_poll >= DEBOUNCE_READY_DRAIN_BUDGET {
                            // Yield cooperatively so an always-ready source
                            // cannot monopolize the executor. The buffered item
                            // remains pending and a self-wake drives the next
                            // burst-drain step.
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                    Poll::Ready(None) => {
                        *this.done = true;
                        break;
                    }
                    Poll::Pending => break,
                }
            }
        }

        // Check if the buffered item's quiet period has elapsed.
        let received_at_opt = this.pending.as_ref().map(|(_, t)| *t);
        if let Some(received_at) = received_at_opt {
            let now = (this.time_getter)();
            let elapsed = Duration::from_nanos(now.duration_since(received_at));
            if *this.done || elapsed >= *this.period {
                *this.timer = None;
                if let Some((item, _)) = this.pending.take() {
                    return Poll::Ready(Some(item));
                }
            }
            // Set up a timer for the remaining quiet period.
            let remaining = this.period.saturating_sub(elapsed);
            if this.timer.is_none() || !had_pending_before {
                let remaining_nanos = remaining.as_nanos().min(u128::from(u64::MAX)) as u64;
                // The wake source must use wall time so `Sleep` can register
                // a real waker even when `time_getter` points at a custom clock.
                let wake_deadline = wall_clock_now().saturating_add_nanos(remaining_nanos);
                *this.timer = Some(Box::pin(Sleep::new(wake_deadline)));
            }
            // Poll the timer to register the waker for delayed wakeup.
            if let Some(ref mut timer) = *this.timer {
                if Pin::new(timer).poll(cx).is_ready() {
                    *this.timer = None;
                    let now = (this.time_getter)();
                    let elapsed = Duration::from_nanos(now.duration_since(received_at));
                    if *this.done || elapsed >= *this.period {
                        if let Some((item, _)) = this.pending.take() {
                            return Poll::Ready(Some(item));
                        }
                    }
                    // A wall-clock wake must not override a custom logical
                    // clock. Re-arm the timer for the remaining period so
                    // there is always a wake source for the buffered item.
                    let remaining = this.period.saturating_sub(elapsed);
                    let remaining_nanos = remaining.as_nanos().min(u128::from(u64::MAX)) as u64;
                    let wake_deadline = wall_clock_now().saturating_add_nanos(remaining_nanos);
                    let mut new_timer = Box::pin(Sleep::new(wake_deadline));
                    // Register the waker with the new timer.
                    let _ = Pin::new(&mut new_timer).poll(cx);
                    *this.timer = Some(new_timer);
                    return Poll::Pending;
                }
            }
            return Poll::Pending;
        }

        if *this.done {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::iter;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::task::{Poll, Wake, Waker};

    thread_local! {
        static TEST_NOW_NANOS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

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
        TEST_NOW_NANOS.with(|t| t.set(nanos));
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW_NANOS.with(std::cell::Cell::get))
    }

    #[test]
    fn debounce_flushes_on_stream_end() {
        init_test("debounce_flushes_on_stream_end");
        // When the stream ends, the buffered item should be flushed immediately.
        let mut stream = Debounce::new(iter(vec![1, 2, 3]), Duration::from_secs(999));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // All items arrive synchronously and stream ends.
        // The last item (3) should be flushed.
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(3)));

        // Stream is done.
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("debounce_flushes_on_stream_end");
    }

    #[test]
    fn debounce_zero_duration_passes_last() {
        init_test("debounce_zero_duration_passes_last");
        // With zero period, debounce should emit the last synchronously-available item.
        let mut stream = Debounce::new(iter(vec![10, 20, 30]), Duration::ZERO);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(30)));

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("debounce_zero_duration_passes_last");
    }

    #[test]
    fn debounce_empty_stream() {
        init_test("debounce_empty_stream");
        let mut stream = Debounce::new(iter(Vec::<i32>::new()), Duration::from_millis(100));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("debounce_empty_stream");
    }

    #[test]
    fn debounce_single_item_flushes() {
        init_test("debounce_single_item_flushes");
        let mut stream = Debounce::new(iter(vec![42]), Duration::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Single item + stream end → immediate flush.
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(42))
        );
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("debounce_single_item_flushes");
    }

    #[test]
    fn debounce_with_elapsed_quiet_period() {
        init_test("debounce_with_elapsed_quiet_period");
        // Use a very short debounce period.
        let mut stream = Debounce::new(iter(vec![1, 2, 3]), Duration::from_millis(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // All items arrive synchronously. Since the stream ends, the last
        // item is flushed regardless of debounce period.
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(3)));
        crate::test_complete!("debounce_with_elapsed_quiet_period");
    }

    #[test]
    fn debounce_accessors() {
        init_test("debounce_accessors");
        set_test_time(17);
        let mut stream =
            Debounce::with_time_getter(iter(vec![1, 2]), Duration::from_millis(100), test_time);
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
        crate::test_complete!("debounce_accessors");
    }

    #[test]
    fn debounce_debug() {
        let stream = Debounce::new(iter(vec![1, 2, 3]), Duration::from_millis(100));
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("Debounce"));
    }

    #[derive(Debug)]
    struct PendingStream;

    impl Stream for PendingStream {
        type Item = i32;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    #[derive(Debug, Default)]
    struct AlwaysReadyCounter {
        next: usize,
    }

    impl Stream for AlwaysReadyCounter {
        type Item = usize;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let item = self.next;
            self.next = self.next.saturating_add(1);
            Poll::Ready(Some(item))
        }
    }

    #[test]
    fn debounce_emits_immediately_when_timer_future_is_ready() {
        init_test("debounce_does_not_emit_early_when_timer_future_is_ready");
        set_test_time(0);
        let mut stream =
            Debounce::with_time_getter(PendingStream, Duration::from_mins(1), test_time);
        stream.pending = Some((7, Time::from_nanos(0)));
        stream.timer = Some(Box::pin(Sleep::new(Time::from_nanos(0))));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Pending);
        assert_eq!(
            stream.pending.as_ref().map(|(item, _)| *item),
            Some(7),
            "pending item must remain buffered until the custom clock reaches the quiet period"
        );
        assert!(
            stream.timer.is_some(),
            "timer should be re-armed for the remaining period so there is a wake source"
        );

        set_test_time(Duration::from_mins(1).as_nanos().min(u128::from(u64::MAX)) as u64);
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(7))
        );
        assert!(stream.pending.is_none(), "pending item should be drained");
        crate::test_complete!("debounce_does_not_emit_early_when_timer_future_is_ready");
    }

    #[test]
    fn debounce_respects_custom_time_getter_without_sleeping() {
        init_test("debounce_respects_custom_time_getter_without_sleeping");
        set_test_time(0);
        let mut stream =
            Debounce::with_time_getter(PendingStream, Duration::from_secs(5), test_time);
        stream.pending = Some((11, Time::from_nanos(0)));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Pending);
        assert!(stream.pending.is_some(), "item should still be buffered");
        assert!(stream.timer.is_some(), "timer should be armed");

        set_test_time(Duration::from_secs(5).as_nanos().min(u128::from(u64::MAX)) as u64);

        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(11))
        );
        assert!(stream.pending.is_none(), "pending item should be emitted");
        assert!(stream.timer.is_none(), "timer should be cleared after emit");
        crate::test_complete!("debounce_respects_custom_time_getter_without_sleeping");
    }

    #[test]
    fn debounce_custom_time_getter_arms_wake_capable_sleep() {
        init_test("debounce_custom_time_getter_arms_wake_capable_sleep");
        set_test_time(0);
        let mut stream =
            Debounce::with_time_getter(PendingStream, Duration::from_secs(5), test_time);
        stream.pending = Some((13, Time::from_nanos(0)));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Pending);
        let timer = stream.timer.as_ref().expect("timer should be armed");
        let sleep = timer.as_ref().get_ref();
        assert!(
            sleep.time_getter.is_none(),
            "debounce timer must use Sleep::new for wake registration"
        );
        crate::test_complete!("debounce_custom_time_getter_arms_wake_capable_sleep");
    }

    #[test]
    fn debounce_yields_cooperatively_on_always_ready_burst() {
        init_test("debounce_yields_cooperatively_on_always_ready_burst");
        set_test_time(0);
        let woke = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(Arc::clone(&woke))));
        let mut cx = Context::from_waker(&waker);
        let mut stream = Debounce::with_time_getter(
            AlwaysReadyCounter::default(),
            Duration::from_secs(5),
            test_time,
        );

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Pending);
        assert!(
            woke.swap(false, Ordering::SeqCst),
            "debounce should self-wake after hitting the cooperative burst budget"
        );
        assert_eq!(
            stream.pending.as_ref().map(|(item, _)| *item),
            Some(DEBOUNCE_READY_DRAIN_BUDGET - 1)
        );
        assert!(
            stream.timer.is_none(),
            "timer should stay cleared while the upstream keeps producing immediately"
        );

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Pending);
        assert!(
            woke.load(Ordering::SeqCst),
            "debounce should continue self-waking while draining later burst slices"
        );
        assert_eq!(
            stream.pending.as_ref().map(|(item, _)| *item),
            Some((DEBOUNCE_READY_DRAIN_BUDGET * 2) - 1)
        );
        crate::test_complete!("debounce_yields_cooperatively_on_always_ready_burst");
    }
}
