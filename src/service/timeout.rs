//! Timeout middleware layer.
//!
//! The [`TimeoutLayer`] wraps a service to impose a maximum execution time
//! on each request. If the inner service doesn't complete within the timeout,
//! an [`Elapsed`] error is returned.

use super::{Layer, Service};
use crate::time::{Elapsed, Sleep};
use crate::types::Time;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// A layer that applies a timeout to requests.
///
/// # Example
///
/// ```ignore
/// use asupersync::service::{ServiceBuilder, ServiceExt};
/// use asupersync::service::timeout::TimeoutLayer;
/// use std::time::Duration;
///
/// let svc = ServiceBuilder::new()
///     .layer(TimeoutLayer::new(Duration::from_secs(30)))
///     .service(my_service);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TimeoutLayer {
    duration: Duration,
    time_getter: fn() -> Time,
}

impl TimeoutLayer {
    /// Creates a new timeout layer with the given duration.
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self {
            duration: timeout,
            time_getter: wall_clock_now,
        }
    }

    /// Creates a new timeout layer with a custom time source.
    #[must_use]
    pub const fn with_time_getter(timeout: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            duration: timeout,
            time_getter,
        }
    }

    /// Returns the timeout duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.duration
    }

    /// Returns the time source used by this layer.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = Timeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Timeout::with_time_getter(inner, self.duration, self.time_getter)
    }
}

/// A service that imposes a timeout on requests.
///
/// If the inner service doesn't complete within the timeout, the request
/// fails with a [`TimeoutError`]. Each successful `poll_ready` authorizes
/// exactly one subsequent `call`; skipping readiness fails closed with
/// [`TimeoutError::NotReady`].
#[derive(Debug)]
pub struct Timeout<S> {
    inner: S,
    duration: Duration,
    time_getter: fn() -> Time,
    ready_observed: bool,
}

impl<S: Clone> Clone for Timeout<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            duration: self.duration,
            time_getter: self.time_getter,
            // Readiness authorization is handle-local and must not be cloned.
            ready_observed: false,
        }
    }
}

impl<S> Timeout<S> {
    /// Creates a new timeout service.
    #[must_use]
    pub const fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            duration: timeout,
            time_getter: wall_clock_now,
            ready_observed: false,
        }
    }

    /// Creates a new timeout service with a custom time source.
    #[must_use]
    pub const fn with_time_getter(inner: S, timeout: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            inner,
            duration: timeout,
            time_getter,
            ready_observed: false,
        }
    }

    /// Returns the timeout duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.duration
    }

    /// Returns the time source used by this service.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }

    /// Returns a reference to the inner service.
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns a mutable reference to the inner service.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consumes the timeout, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Error returned when a request times out.
#[derive(Debug)]
pub enum TimeoutError<E> {
    /// The caller attempted `call()` without a preceding successful `poll_ready()`.
    NotReady,
    /// The timeout future was polled after it had already completed.
    PolledAfterCompletion,
    /// The request timed out.
    Elapsed(Elapsed),
    /// The inner service returned an error.
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for TimeoutError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady => write!(f, "poll_ready required before call"),
            Self::PolledAfterCompletion => write!(f, "timeout future polled after completion"),
            Self::Elapsed(e) => write!(f, "request timed out: {e}"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for TimeoutError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotReady | Self::PolledAfterCompletion => None,
            Self::Elapsed(e) => Some(e),
            Self::Inner(e) => Some(e),
        }
    }
}

impl<S, Request> Service<Request> for Timeout<S>
where
    S: Service<Request>,
    S::Future: Unpin,
{
    type Response = S::Response;
    type Error = TimeoutError<S::Error>;
    type Future = TimeoutFuture<S::Future>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                self.ready_observed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                self.ready_observed = false;
                Poll::Ready(Err(TimeoutError::Inner(err)))
            }
            Poll::Pending => {
                self.ready_observed = false;
                Poll::Pending
            }
        }
    }

    #[inline]
    fn call(&mut self, req: Request) -> Self::Future {
        if !std::mem::replace(&mut self.ready_observed, false) {
            return TimeoutFuture::not_ready();
        }
        let now = (self.time_getter)();
        let deadline = now.saturating_add_nanos(duration_to_nanos(self.duration));
        TimeoutFuture::with_time_getter(self.inner.call(req), deadline, self.time_getter)
    }
}

/// Future returned by [`Timeout`] service.
#[derive(Debug)]
pub struct TimeoutFuture<F> {
    state: TimeoutFutureState<F>,
}

#[derive(Debug)]
enum TimeoutFutureState<F> {
    /// Caller skipped `poll_ready` or reused a consumed readiness window.
    NotReady,
    /// Active timeout-wrapped inner future.
    Running {
        inner: F,
        sleep: Sleep,
        time_getter: Option<fn() -> Time>,
    },
    /// Future has completed.
    Done,
}

impl<F> TimeoutFuture<F> {
    /// Creates a future that immediately returns a readiness misuse error.
    #[must_use]
    pub const fn not_ready() -> Self {
        Self {
            state: TimeoutFutureState::NotReady,
        }
    }

    /// Creates a new timeout future.
    #[must_use]
    pub fn new(inner: F, deadline: Time) -> Self {
        Self {
            state: TimeoutFutureState::Running {
                inner,
                sleep: Sleep::new(deadline),
                time_getter: None,
            },
        }
    }

    /// Creates a new timeout future with a custom time source.
    ///
    /// The `time_getter` is used by both timeout decisions and the underlying
    /// sleep so they agree on the current time.
    #[must_use]
    pub fn with_time_getter(inner: F, deadline: Time, time_getter: fn() -> Time) -> Self {
        Self {
            state: TimeoutFutureState::Running {
                inner,
                sleep: Sleep::with_time_getter(deadline, time_getter),
                time_getter: Some(time_getter),
            },
        }
    }

    /// Returns the deadline for this timeout.
    #[must_use]
    pub fn deadline(&self) -> Time {
        match &self.state {
            TimeoutFutureState::Running { sleep, .. } => sleep.deadline(),
            TimeoutFutureState::NotReady | TimeoutFutureState::Done => Time::ZERO,
        }
    }

    /// Polls with an explicit time value.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time
    /// * `cx` - The task context
    pub fn poll_with_time<T, E>(
        &mut self,
        now: Time,
        cx: &mut Context<'_>,
    ) -> Poll<Result<T, TimeoutError<E>>>
    where
        F: Future<Output = Result<T, E>> + Unpin,
    {
        let state = std::mem::replace(&mut self.state, TimeoutFutureState::Done);
        match state {
            TimeoutFutureState::NotReady => Poll::Ready(Err(TimeoutError::NotReady)),
            TimeoutFutureState::Done => Poll::Ready(Err(TimeoutError::PolledAfterCompletion)),
            TimeoutFutureState::Running {
                mut inner,
                mut sleep,
                time_getter,
            } => {
                // Prefer completed work at the timeout boundary.
                match Pin::new(&mut inner).poll(cx) {
                    Poll::Ready(Ok(response)) => Poll::Ready(Ok(response)),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(TimeoutError::Inner(e))),
                    Poll::Pending => {
                        if sleep.poll_with_time(now).is_ready() {
                            Poll::Ready(Err(TimeoutError::Elapsed(Elapsed::new(sleep.deadline()))))
                        } else {
                            // Preserve wake registration only when the sleep
                            // uses the same time source as the explicit `now`
                            // or an ambient timer driver is available. Falling
                            // back to wall clock here can spuriously expire a
                            // manual-time poll.
                            let has_ambient_timer = crate::cx::Cx::current()
                                .and_then(|current| current.timer_driver())
                                .is_some();
                            if time_getter.is_some() || has_ambient_timer {
                                let _ = Pin::new(&mut sleep).poll(cx);
                            }
                            self.state = TimeoutFutureState::Running {
                                inner,
                                sleep,
                                time_getter,
                            };
                            Poll::Pending
                        }
                    }
                }
            }
        }
    }
}

impl<F, T, E> Future for TimeoutFuture<F>
where
    F: Future<Output = Result<T, E>> + Unpin,
{
    type Output = Result<T, TimeoutError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let state = std::mem::replace(&mut this.state, TimeoutFutureState::Done);
        match state {
            TimeoutFutureState::NotReady => Poll::Ready(Err(TimeoutError::NotReady)),
            TimeoutFutureState::Done => Poll::Ready(Err(TimeoutError::PolledAfterCompletion)),
            TimeoutFutureState::Running {
                mut inner,
                mut sleep,
                time_getter,
            } => {
                match Pin::new(&mut inner).poll(cx) {
                    Poll::Ready(Ok(response)) => return Poll::Ready(Ok(response)),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(TimeoutError::Inner(e))),
                    Poll::Pending => {}
                }

                if let Some(time_getter) = time_getter {
                    if sleep.poll_with_time(time_getter()).is_ready() {
                        return Poll::Ready(Err(TimeoutError::Elapsed(Elapsed::new(
                            sleep.deadline(),
                        ))));
                    }

                    // Preserve wake registration even when timeout decisions use a
                    // manual or virtual clock.
                    let _ = Pin::new(&mut sleep).poll(cx);
                    this.state = TimeoutFutureState::Running {
                        inner,
                        sleep,
                        time_getter: Some(time_getter),
                    };
                    return Poll::Pending;
                }

                match Pin::new(&mut sleep).poll(cx) {
                    Poll::Ready(()) => {
                        Poll::Ready(Err(TimeoutError::Elapsed(Elapsed::new(sleep.deadline()))))
                    }
                    Poll::Pending => {
                        this.state = TimeoutFutureState::Running {
                            inner,
                            sleep,
                            time_getter: None,
                        };
                        Poll::Pending
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cx;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::future::{pending, ready};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    /// A no-op waker for testing.
    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
    }

    struct CountingWaker(AtomicUsize);

    impl CountingWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self(AtomicUsize::new(0)))
        }

        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    // A simple test service that returns the request
    struct EchoService;

    impl Service<i32> for EchoService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            ready(Ok(req))
        }
    }

    // A service that never completes
    struct NeverService;

    impl Service<()> for NeverService {
        type Response = ();
        type Error = std::convert::Infallible;
        type Future = std::future::Pending<Result<(), std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            pending()
        }
    }

    #[derive(Clone)]
    struct CountingReadyService {
        calls: Arc<AtomicUsize>,
    }

    impl CountingReadyService {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self { calls }
        }
    }

    impl Service<i32> for CountingReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ready(Ok(req))
        }
    }

    #[test]
    fn timeout_layer_creates_service() {
        let layer = TimeoutLayer::new(Duration::from_secs(5));
        let _svc: Timeout<EchoService> = layer.layer(EchoService);
    }

    #[test]
    fn timeout_accessors() {
        let timeout = Timeout::new(EchoService, Duration::from_secs(10));
        assert_eq!(timeout.timeout(), Duration::from_secs(10));
        let _ = timeout.inner();
    }

    static TEST_NOW: AtomicU64 = AtomicU64::new(0);

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
    }

    #[test]
    fn timeout_uses_time_getter_for_deadline() {
        TEST_NOW.store(1_000, Ordering::SeqCst);
        let mut svc = Timeout::with_time_getter(EchoService, Duration::from_nanos(500), test_time);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let future = svc.call(1);
        assert_eq!(future.deadline(), Time::from_nanos(1_500));
    }

    #[test]
    fn timeout_future_poll_honors_custom_time_getter() {
        TEST_NOW.store(1_000, Ordering::SeqCst);
        let mut svc = Timeout::with_time_getter(NeverService, Duration::from_nanos(500), test_time);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let mut future = svc.call(());

        let first: Poll<Result<(), TimeoutError<std::convert::Infallible>>> =
            Future::poll(Pin::new(&mut future), &mut cx);
        assert!(first.is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        let second: Poll<Result<(), TimeoutError<std::convert::Infallible>>> =
            Future::poll(Pin::new(&mut future), &mut cx);
        assert!(matches!(second, Poll::Ready(Err(TimeoutError::Elapsed(_)))));
    }

    #[test]
    fn timeout_future_completes_before_deadline() {
        let mut future = TimeoutFuture::new(ready(Ok::<_, ()>(42)), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is well before deadline
        let result = future.poll_with_time(Time::from_secs(1), &mut cx);
        assert!(matches!(result, Poll::Ready(Ok(42))));
    }

    #[test]
    fn timeout_future_times_out() {
        let mut future = TimeoutFuture::new(pending::<Result<(), ()>>(), Time::from_secs(5));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is past deadline
        let result: Poll<Result<(), TimeoutError<()>>> =
            future.poll_with_time(Time::from_secs(10), &mut cx);
        assert!(matches!(result, Poll::Ready(Err(TimeoutError::Elapsed(_)))));
    }

    #[test]
    fn timeout_future_pending_before_deadline() {
        let mut future = TimeoutFuture::new(pending::<Result<(), ()>>(), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is before deadline
        let result: Poll<Result<(), TimeoutError<()>>> =
            future.poll_with_time(Time::from_secs(5), &mut cx);
        assert!(result.is_pending());
    }

    #[test]
    fn timeout_future_poll_with_time_registers_timeout_waker() {
        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let runtime_cx = Cx::new_with_drivers(
            RegionId::new_for_test(1, 0),
            TaskId::new_for_test(1, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(runtime_cx));

        let waker = CountingWaker::new();
        let waker_handle = waker.clone();
        let task_waker: Waker = waker.into();
        let mut cx = Context::from_waker(&task_waker);

        let mut future = TimeoutFuture::new(pending::<Result<(), ()>>(), Time::from_millis(5));
        let first = future.poll_with_time(Time::ZERO, &mut cx);
        assert!(first.is_pending());
        assert_eq!(timer.pending_count(), 1);

        clock.advance(Time::from_millis(5).as_nanos());
        let fired = timer.process_timers();
        assert_eq!(fired, 1);
        assert!(waker_handle.count() > 0);

        let second = future.poll_with_time(Time::from_millis(5), &mut cx);
        assert!(matches!(second, Poll::Ready(Err(TimeoutError::Elapsed(_)))));
    }

    #[test]
    fn timeout_future_boundary_prefers_ready_inner_result() {
        let mut future = TimeoutFuture::new(ready(Ok::<_, ()>(7)), Time::from_secs(5));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = future.poll_with_time(Time::from_secs(5), &mut cx);
        assert!(matches!(result, Poll::Ready(Ok(7))));
    }

    #[test]
    fn timeout_future_poll_enforces_timeout_without_custom_time_source() {
        let mut future = TimeoutFuture::new(pending::<Result<(), ()>>(), Time::ZERO);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut future);

        let result: Poll<Result<(), TimeoutError<()>>> = Future::poll(pinned.as_mut(), &mut cx);
        assert!(matches!(result, Poll::Ready(Err(TimeoutError::Elapsed(_)))));
    }

    #[test]
    fn timeout_service_poll_ready() {
        let mut svc = Timeout::new(EchoService, Duration::from_secs(5));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = svc.poll_ready(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(()))));
    }

    #[test]
    fn timeout_call_without_poll_ready_returns_not_ready() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut svc = Timeout::new(
            CountingReadyService::new(Arc::clone(&calls)),
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = svc.call(7);
        let result = Future::poll(Pin::new(&mut future), &mut cx);
        assert!(matches!(result, Poll::Ready(Err(TimeoutError::NotReady))));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn timeout_readiness_authorizes_only_one_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut svc = Timeout::new(
            CountingReadyService::new(Arc::clone(&calls)),
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let mut first = svc.call(11);
        let first_result = Future::poll(Pin::new(&mut first), &mut cx);
        assert!(matches!(first_result, Poll::Ready(Ok(11))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let mut second = svc.call(12);
        let second_result = Future::poll(Pin::new(&mut second), &mut cx);
        assert!(matches!(
            second_result,
            Poll::Ready(Err(TimeoutError::NotReady))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn timeout_error_display() {
        let err: TimeoutError<&str> = TimeoutError::NotReady;
        let display = format!("{err}");
        assert!(display.contains("poll_ready"));

        let err: TimeoutError<&str> = TimeoutError::PolledAfterCompletion;
        let display = format!("{err}");
        assert!(display.contains("polled after completion"));

        let err: TimeoutError<&str> = TimeoutError::Elapsed(Elapsed::new(Time::from_secs(5)));
        let display = format!("{err}");
        assert!(display.contains("timed out"));

        let err: TimeoutError<&str> = TimeoutError::Inner("inner error");
        let display = format!("{err}");
        assert!(display.contains("inner service error"));
    }

    // =========================================================================
    // Wave 49 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn timeout_layer_debug_clone_copy() {
        let layer = TimeoutLayer::new(Duration::from_secs(10));
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("TimeoutLayer"), "{dbg}");
        let copied = layer;
        let cloned = layer;
        assert_eq!(copied.timeout(), cloned.timeout());
    }

    #[test]
    fn timeout_service_accessors() {
        let svc = Timeout::new(EchoService, Duration::from_secs(5));
        assert_eq!(svc.timeout(), Duration::from_secs(5));
    }

    #[test]
    fn timeout_error_debug() {
        let err0: TimeoutError<&str> = TimeoutError::NotReady;
        let dbg0 = format!("{err0:?}");
        assert!(dbg0.contains("NotReady"), "{dbg0}");

        let err1: TimeoutError<&str> = TimeoutError::PolledAfterCompletion;
        let dbg1 = format!("{err1:?}");
        assert!(dbg1.contains("PolledAfterCompletion"), "{dbg1}");

        let err: TimeoutError<&str> = TimeoutError::Elapsed(Elapsed::new(Time::from_secs(5)));
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Elapsed"), "{dbg}");
        let err2: TimeoutError<&str> = TimeoutError::Inner("fail");
        let dbg2 = format!("{err2:?}");
        assert!(dbg2.contains("Inner"), "{dbg2}");
    }
}
