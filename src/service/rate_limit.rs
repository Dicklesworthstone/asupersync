//! Rate limiting middleware layer.
//!
//! The [`RateLimitLayer`] wraps a service to limit the rate of requests using
//! a token bucket algorithm. Requests are only allowed when tokens are available.

use super::{Layer, Service};
use crate::types::Time;
use parking_lot::Mutex;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// A layer that rate-limits requests using a token bucket.
///
/// The rate limiter allows `rate` requests per `period`. Requests beyond the
/// limit will cause `poll_ready` to return `Poll::Pending` until more tokens
/// become available.
///
/// # Example
///
/// ```ignore
/// use asupersync::service::{ServiceBuilder, ServiceExt};
/// use asupersync::service::rate_limit::RateLimitLayer;
/// use std::time::Duration;
///
/// let svc = ServiceBuilder::new()
///     .layer(RateLimitLayer::new(100, Duration::from_secs(1)))  // 100 req/sec
///     .service(my_service);
/// ```
#[derive(Debug, Clone)]
pub struct RateLimitLayer {
    /// Tokens added per period.
    rate: u64,
    /// Duration of each period.
    period: Duration,
    time_getter: fn() -> Time,
}

impl RateLimitLayer {
    /// Creates a new rate limit layer.
    ///
    /// # Arguments
    ///
    /// * `rate` - Maximum requests allowed per period
    /// * `period` - The time period for the rate limit
    #[must_use]
    pub const fn new(rate: u64, period: Duration) -> Self {
        Self {
            rate,
            period,
            time_getter: wall_clock_now,
        }
    }

    /// Creates a new rate limit layer with a custom time source.
    #[must_use]
    pub const fn with_time_getter(rate: u64, period: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            rate,
            period,
            time_getter,
        }
    }

    /// Returns the rate (tokens per period).
    #[must_use]
    pub const fn rate(&self) -> u64 {
        self.rate
    }

    /// Returns the period duration.
    #[must_use]
    pub const fn period(&self) -> Duration {
        self.period
    }

    /// Returns the time source used by this layer.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimit::with_time_getter(inner, self.rate, self.period, self.time_getter)
    }
}

/// A service that rate-limits requests using a token bucket.
///
/// The token bucket refills at a rate of `rate` tokens per `period`.
/// Each request consumes one token. When no tokens are available,
/// `poll_ready` returns `Poll::Pending`.
#[derive(Debug)]
pub struct RateLimit<S> {
    inner: S,
    /// Shared token-bucket state. Cloned services must coordinate available
    /// capacity through the same bucket so cloning cannot multiply throughput.
    state: Arc<Mutex<SharedRateLimitState>>,
    /// Number of tokens reserved by successful `poll_ready` calls that have not
    /// yet been consumed by `call()`. Reservations are handle-local because a
    /// fresh clone must not be able to spend another handle's readiness grant.
    ///
    /// Because clones share the bucket, abandoning a granted reservation must
    /// return the token to the shared bucket on drop instead of leaking shared
    /// capacity until the next refill window.
    reservations: LocalReservationState,
    /// Maximum tokens (bucket capacity).
    rate: u64,
    /// Period for refilling tokens.
    period: Duration,
    time_getter: fn() -> Time,
    /// Timer for sleeping when tokens are exhausted.
    sleep: Option<crate::time::Sleep>,
}

#[derive(Debug)]
struct SharedRateLimitState {
    /// Current number of available tokens in the shared bucket.
    tokens: u64,
    /// Last time the bucket state was refilled.
    last_refill: Option<Time>,
}

impl<S: Clone> Clone for RateLimit<S> {
    fn clone(&self) -> Self {
        let state = Arc::clone(&self.state);
        Self {
            inner: self.inner.clone(),
            state: Arc::clone(&state),
            // Readiness reservations are handle-local and must not be inherited
            // by a fresh clone, or a clone can spend another handle's poll_ready
            // reservation without performing its own readiness check.
            reservations: LocalReservationState::new(state, self.rate),
            rate: self.rate,
            period: self.period,
            time_getter: self.time_getter,
            sleep: None, // Sleep state is not cloned
        }
    }
}

impl<S> RateLimit<S> {
    /// Creates a new rate-limited service.
    ///
    /// # Arguments
    ///
    /// * `inner` - The inner service to wrap
    /// * `rate` - Maximum requests per period
    /// * `period` - The time period
    #[must_use]
    pub fn new(inner: S, rate: u64, period: Duration) -> Self {
        let state = Arc::new(Mutex::new(SharedRateLimitState {
            tokens: rate, // Start with full bucket
            last_refill: None,
        }));
        Self {
            inner,
            state: Arc::clone(&state),
            reservations: LocalReservationState::new(state, rate),
            rate,
            period,
            time_getter: wall_clock_now,
            sleep: None,
        }
    }

    /// Creates a new rate-limited service with a custom time source.
    #[must_use]
    pub fn with_time_getter(
        inner: S,
        rate: u64,
        period: Duration,
        time_getter: fn() -> Time,
    ) -> Self {
        let state = Arc::new(Mutex::new(SharedRateLimitState {
            tokens: rate,
            last_refill: None,
        }));
        Self {
            inner,
            state: Arc::clone(&state),
            reservations: LocalReservationState::new(state, rate),
            rate,
            period,
            time_getter,
            sleep: None,
        }
    }

    /// Returns the rate (tokens per period).
    #[must_use]
    pub const fn rate(&self) -> u64 {
        self.rate
    }

    /// Returns the period duration.
    #[must_use]
    pub const fn period(&self) -> Duration {
        self.period
    }

    /// Returns the time source used by this rate limiter.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }

    /// Returns the current number of available tokens.
    #[inline]
    #[must_use]
    pub fn available_tokens(&self) -> u64 {
        self.state.lock().tokens
    }

    #[cfg(test)]
    #[inline]
    #[must_use]
    fn reserved_tokens(&self) -> u64 {
        self.reservations.reserved_tokens
    }

    /// Returns a reference to the inner service.
    #[inline]
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns a mutable reference to the inner service.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consumes the rate limiter, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Refills tokens based on elapsed time.
    #[inline]
    fn refill_state_locked(
        state: &mut SharedRateLimitState,
        rate: u64,
        period: Duration,
        now: Time,
    ) {
        let last_refill = state.last_refill.unwrap_or(now);
        let elapsed_nanos = now.as_nanos().saturating_sub(last_refill.as_nanos());
        let period_nanos = period.as_nanos().min(u128::from(u64::MAX)) as u64;

        if period_nanos == 0 {
            // Zero period means "no throttling": always make at least one token
            // available so poll_ready never stalls even when rate == 0.
            state.tokens = rate.max(1);
            state.last_refill = Some(now);
            return;
        }

        if period_nanos > 0 && elapsed_nanos > 0 {
            // Calculate how many periods have passed
            let periods = elapsed_nanos / period_nanos;
            if periods > 0 {
                // Add tokens for complete periods
                let new_tokens = periods.saturating_mul(rate);
                state.tokens = state.tokens.saturating_add(new_tokens).min(rate);
                // Update last_refill to the last complete period boundary
                let refill_time = last_refill.saturating_add_nanos(periods * period_nanos);
                state.last_refill = Some(refill_time);
            }
        } else if state.last_refill.is_none() {
            state.last_refill = Some(now);
        }
    }

    /// Refills tokens based on elapsed time.
    #[cfg(test)]
    fn refill(&self, now: Time) {
        let mut state = self.state.lock();
        Self::refill_state_locked(&mut state, self.rate, self.period, now);
    }

    /// Polls readiness with an explicit time value.
    ///
    /// This mirrors [`Service::poll_ready`] while taking the current logical
    /// time as an explicit parameter for deterministic tests.
    pub fn poll_ready_with_time<Request>(
        &mut self,
        now: Time,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), RateLimitError<S::Error>>>
    where
        S: Service<Request>,
    {
        if self.reservations.reserved_tokens > 0 {
            let mut reservation_restore_guard = ExistingReservationGuard::new(
                Arc::clone(&self.state),
                &mut self.reservations.reserved_tokens,
                self.rate,
                self.period.is_zero(),
                true,
            );

            return match self.inner.poll_ready(cx).map_err(RateLimitError::Inner) {
                Poll::Ready(Ok(())) => {
                    reservation_restore_guard.defuse();
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => {
                    reservation_restore_guard.defuse();
                    Poll::Pending
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            };
        }

        let next_deadline = {
            let mut state = self.state.lock();
            Self::refill_state_locked(&mut state, self.rate, self.period, now);
            if state.tokens == 0 {
                let next_deadline = state.last_refill.map(|last_refill| {
                    let period_nanos = self.period.as_nanos().min(u128::from(u64::MAX)) as u64;
                    last_refill.saturating_add_nanos(period_nanos)
                });
                drop(state);
                next_deadline
            } else {
                state.tokens -= 1;
                drop(state);
                None
            }
        };

        if next_deadline.is_some() {
            // Wake up caller to retry later
            if let Some(next_deadline) = next_deadline {
                let need_new_sleep = self
                    .sleep
                    .as_ref()
                    .is_none_or(|s| s.deadline() != next_deadline);
                if need_new_sleep {
                    self.sleep = Some(crate::time::Sleep::new(next_deadline));
                }

                if let Some(sleep) = &mut self.sleep {
                    let _ = std::pin::Pin::new(sleep).poll(cx);
                }
            } else {
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }

        self.sleep = None;
        let inner = &mut self.inner;
        let reserved_tokens = &mut self.reservations.reserved_tokens;
        let mut token_restore_guard = ReservedTokenGuard::new(
            Arc::clone(&self.state),
            self.rate,
            self.period.is_zero(),
            true,
        );

        match inner.poll_ready(cx).map_err(RateLimitError::Inner) {
            Poll::Ready(Ok(())) => {
                *reserved_tokens += 1;
                token_restore_guard.defuse();
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// Error returned by rate-limited services.
#[derive(Debug)]
pub enum RateLimitError<E> {
    /// The caller attempted `call()` without a preceding successful `poll_ready()`.
    NotReady,
    /// Rate limit exceeded (should not normally be seen - poll_ready handles this).
    RateLimitExceeded,
    /// The future was polled after it had already completed.
    PolledAfterCompletion,
    /// The inner service returned an error.
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for RateLimitError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady => write!(f, "poll_ready required before call"),
            Self::RateLimitExceeded => write!(f, "rate limit exceeded"),
            Self::PolledAfterCompletion => write!(f, "future polled after completion"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RateLimitError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotReady | Self::RateLimitExceeded | Self::PolledAfterCompletion => None,
            Self::Inner(e) => Some(e),
        }
    }
}

impl<S, Request> Service<Request> for RateLimit<S>
where
    S: Service<Request>,
{
    type Response = S::Response;
    type Error = RateLimitError<S::Error>;
    type Future = RateLimitFuture<S::Future, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let now = (self.time_getter)();
        self.poll_ready_with_time::<Request>(now, cx)
    }

    #[inline]
    fn call(&mut self, req: Request) -> Self::Future {
        if self.reservations.reserved_tokens == 0 {
            return RateLimitFuture::immediate_error(RateLimitError::NotReady);
        }

        self.reservations.reserved_tokens -= 1;
        let mut token_restore_guard = ReservedTokenGuard::new(
            Arc::clone(&self.state),
            self.rate,
            self.period.is_zero(),
            true,
        );
        let future = self.inner.call(req);
        token_restore_guard.defuse();
        RateLimitFuture::new(future)
    }
}

#[derive(Debug)]
struct LocalReservationState {
    state: Arc<Mutex<SharedRateLimitState>>,
    reserved_tokens: u64,
    rate: u64,
}

impl LocalReservationState {
    fn new(state: Arc<Mutex<SharedRateLimitState>>, rate: u64) -> Self {
        Self {
            state,
            reserved_tokens: 0,
            rate,
        }
    }
}

impl Drop for LocalReservationState {
    fn drop(&mut self) {
        if self.reserved_tokens == 0 {
            return;
        }

        let mut state = self.state.lock();
        let max_tokens = self.rate.max(1);
        state.tokens = state
            .tokens
            .saturating_add(self.reserved_tokens)
            .min(max_tokens);
    }
}

struct ReservedTokenGuard {
    state: Arc<Mutex<SharedRateLimitState>>,
    rate: u64,
    zero_period: bool,
    armed: bool,
}

impl ReservedTokenGuard {
    fn new(
        state: Arc<Mutex<SharedRateLimitState>>,
        rate: u64,
        zero_period: bool,
        armed: bool,
    ) -> Self {
        Self {
            state,
            rate,
            zero_period,
            armed,
        }
    }

    fn defuse(&mut self) {
        self.armed = false;
    }
}

impl Drop for ReservedTokenGuard {
    fn drop(&mut self) {
        if self.armed {
            let mut state = self.state.lock();
            let max_tokens = if self.zero_period {
                self.rate.max(1)
            } else {
                self.rate
            };
            state.tokens = state.tokens.saturating_add(1).min(max_tokens);
        }
    }
}

struct ExistingReservationGuard<'a> {
    state: Arc<Mutex<SharedRateLimitState>>,
    reserved_tokens: &'a mut u64,
    rate: u64,
    zero_period: bool,
    armed: bool,
}

impl<'a> ExistingReservationGuard<'a> {
    fn new(
        state: Arc<Mutex<SharedRateLimitState>>,
        reserved_tokens: &'a mut u64,
        rate: u64,
        zero_period: bool,
        armed: bool,
    ) -> Self {
        Self {
            state,
            reserved_tokens,
            rate,
            zero_period,
            armed,
        }
    }

    fn defuse(&mut self) {
        self.armed = false;
    }
}

impl Drop for ExistingReservationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            *self.reserved_tokens = self.reserved_tokens.saturating_sub(1);
            let mut state = self.state.lock();
            let max_tokens = if self.zero_period {
                self.rate.max(1)
            } else {
                self.rate
            };
            state.tokens = state.tokens.saturating_add(1).min(max_tokens);
        }
    }
}

/// Future returned by [`RateLimit`] service.
#[pin_project(project = RateLimitFutureProj)]
pub struct RateLimitFuture<F, E> {
    #[pin]
    state: RateLimitFutureState<F, E>,
}

#[pin_project(project = RateLimitFutureStateProj)]
enum RateLimitFutureState<F, E> {
    Inner {
        #[pin]
        inner: F,
    },
    Error {
        error: Option<RateLimitError<E>>,
    },
    Done,
}

impl<F, E> RateLimitFuture<F, E> {
    /// Creates a new rate-limited future.
    #[must_use]
    pub fn new(inner: F) -> Self {
        Self {
            state: RateLimitFutureState::Inner { inner },
        }
    }

    /// Creates a future that resolves to an immediate rate-limit error.
    #[must_use]
    pub fn immediate_error(error: RateLimitError<E>) -> Self {
        Self {
            state: RateLimitFutureState::Error { error: Some(error) },
        }
    }
}

impl<F, T, E> Future for RateLimitFuture<F, E>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<T, RateLimitError<E>>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        match this.state.as_mut().project() {
            RateLimitFutureStateProj::Inner { inner } => match inner.poll(cx) {
                Poll::Ready(Ok(response)) => {
                    this.state.set(RateLimitFutureState::Done);
                    Poll::Ready(Ok(response))
                }
                Poll::Ready(Err(error)) => {
                    this.state.set(RateLimitFutureState::Done);
                    Poll::Ready(Err(RateLimitError::Inner(error)))
                }
                Poll::Pending => Poll::Pending,
            },
            RateLimitFutureStateProj::Error { error } => {
                let error = error
                    .take()
                    .unwrap_or(RateLimitError::PolledAfterCompletion);
                this.state.set(RateLimitFutureState::Done);
                Poll::Ready(Err(error))
            }
            RateLimitFutureStateProj::Done => {
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            }
        }
    }
}

impl<F: std::fmt::Debug, E> std::fmt::Debug for RateLimitFuture<F, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.state {
            RateLimitFutureState::Inner { inner } => f
                .debug_struct("RateLimitFuture")
                .field("state", &"Inner")
                .field("inner", inner)
                .finish(),
            RateLimitFutureState::Error { .. } => f
                .debug_struct("RateLimitFuture")
                .field("state", &"ImmediateError")
                .finish(),
            RateLimitFutureState::Done => f
                .debug_struct("RateLimitFuture")
                .field("state", &"Done")
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::ready;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
    }

    #[derive(Clone, Copy)]
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

    struct ToggleReadyService {
        ready: Arc<AtomicBool>,
        error: bool,
    }

    impl ToggleReadyService {
        fn new(ready: Arc<AtomicBool>, error: bool) -> Self {
            Self { ready, error }
        }
    }

    impl Service<()> for ToggleReadyService {
        type Response = ();
        type Error = &'static str;
        type Future = std::future::Ready<Result<(), &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.error {
                Poll::Ready(Err("inner error"))
            } else if self.ready.load(Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            ready(Ok(()))
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct PanicOnCallService;

    impl Service<()> for PanicOnCallService {
        type Response = ();
        type Error = &'static str;
        type Future = std::future::Ready<Result<(), &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            panic!("panic while constructing rate-limited future");
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct PanicOnPollReadyService;

    impl Service<()> for PanicOnPollReadyService {
        type Response = ();
        type Error = &'static str;
        type Future = std::future::Ready<Result<(), &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            panic!("panic while probing inner readiness");
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            ready(Ok(()))
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct ReadyThenErrorService {
        returned_ready_once: bool,
    }

    impl Service<()> for ReadyThenErrorService {
        type Response = ();
        type Error = &'static str;
        type Future = std::future::Ready<Result<(), &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.returned_ready_once {
                Poll::Ready(Err("inner error"))
            } else {
                self.returned_ready_once = true;
                Poll::Ready(Ok(()))
            }
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            ready(Ok(()))
        }
    }

    std::thread_local! {
        static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.with(std::cell::Cell::get))
    }

    fn set_test_time(t: u64) {
        TEST_NOW.with(|now| now.set(t));
    }

    fn set_bucket_state<S>(svc: &RateLimit<S>, tokens: u64, last_refill: Option<Time>) {
        let mut state = svc.state.lock();
        state.tokens = tokens;
        state.last_refill = last_refill;
    }

    #[test]
    fn layer_creates_service() {
        init_test("layer_creates_service");
        let layer = RateLimitLayer::new(10, Duration::from_secs(1));
        let rate = layer.rate();
        crate::assert_with_log!(rate == 10, "rate", 10, rate);
        let period = layer.period();
        crate::assert_with_log!(
            period == Duration::from_secs(1),
            "period",
            Duration::from_secs(1),
            period
        );
        let _svc: RateLimit<EchoService> = layer.layer(EchoService);
        crate::test_complete!("layer_creates_service");
    }

    #[test]
    fn service_starts_with_full_bucket() {
        init_test("service_starts_with_full_bucket");
        let svc = RateLimit::new(EchoService, 5, Duration::from_secs(1));
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 5, "available", 5, available);
        crate::test_complete!("service_starts_with_full_bucket");
    }

    #[test]
    fn tokens_consumed_on_ready() {
        init_test("tokens_consumed_on_ready");
        let mut svc = RateLimit::new(EchoService, 5, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Each poll_ready → call cycle should consume a token from the shared bucket.
        for expected in (1..=5).rev() {
            let result = svc.poll_ready(&mut cx);
            let ok = matches!(result, Poll::Ready(Ok(())));
            crate::assert_with_log!(ok, "ready ok", true, ok);
            let available = svc.available_tokens();
            crate::assert_with_log!(
                available == expected - 1,
                "available",
                expected - 1,
                available
            );
            // Consume the reservation so the next poll_ready can acquire a fresh token.
            let mut future = svc.call(42);
            let _ = Pin::new(&mut future).poll(&mut cx);
        }
        crate::test_complete!("tokens_consumed_on_ready");
    }

    #[test]
    fn pending_when_no_tokens() {
        init_test("pending_when_no_tokens");
        let mut svc = RateLimit::new(EchoService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First poll_ready + call cycle consumes the sole token.
        let result = svc.poll_ready(&mut cx);
        let ok = matches!(result, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "first ready", true, ok);
        let mut future = svc.call(42);
        let _ = Pin::new(&mut future).poll(&mut cx);

        // Second poll_ready should be pending (no tokens left in shared bucket).
        let result = svc.poll_ready(&mut cx);
        let pending = result.is_pending();
        crate::assert_with_log!(pending, "pending", true, pending);
        crate::test_complete!("pending_when_no_tokens");
    }

    #[test]
    fn inner_pending_does_not_consume_token() {
        init_test("inner_pending_does_not_consume_token");
        let ready = Arc::new(AtomicBool::new(false));
        let mut svc = RateLimit::new(
            ToggleReadyService::new(ready.clone(), false),
            1,
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready(&mut cx);
        crate::assert_with_log!(first.is_pending(), "pending", true, first.is_pending());
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 1, "available", 1, available);

        ready.store(true, Ordering::SeqCst);
        let second = svc.poll_ready(&mut cx);
        let ok = matches!(second, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 0, "available", 0, available);
        crate::test_complete!("inner_pending_does_not_consume_token");
    }

    #[test]
    fn inner_error_does_not_consume_token() {
        init_test("inner_error_does_not_consume_token");
        let ready = Arc::new(AtomicBool::new(true));
        let mut svc = RateLimit::new(
            ToggleReadyService::new(ready, true),
            1,
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = svc.poll_ready(&mut cx);
        let err = matches!(result, Poll::Ready(Err(RateLimitError::Inner(_))));
        crate::assert_with_log!(err, "inner err", true, err);
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 1, "available", 1, available);
        crate::test_complete!("inner_error_does_not_consume_token");
    }

    #[test]
    fn synchronous_inner_call_panic_restores_reserved_token() {
        init_test("synchronous_inner_call_panic_restores_reserved_token");
        let mut svc = RateLimit::new(PanicOnCallService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);

        let available = svc.available_tokens();
        crate::assert_with_log!(available == 0, "available after reserve", 0, available);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _f = svc.call(());
        }));
        let panicked = panic.is_err();
        crate::assert_with_log!(panicked, "inner call panicked", true, panicked);

        let available = svc.available_tokens();
        crate::assert_with_log!(available == 1, "available after panic", 1, available);
        crate::test_complete!("synchronous_inner_call_panic_restores_reserved_token");
    }

    #[test]
    fn refill_adds_tokens() {
        init_test("refill_adds_tokens");
        let svc = RateLimit::new(EchoService, 10, Duration::from_secs(1));

        // Drain all tokens
        set_bucket_state(&svc, 0, Some(Time::from_secs(0)));

        // Refill after 1 second
        svc.refill(Time::from_secs(1));

        // Should have refilled to max
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 10, "available", 10, available);
        crate::test_complete!("refill_adds_tokens");
    }

    #[test]
    fn refill_caps_at_rate() {
        init_test("refill_caps_at_rate");
        let svc = RateLimit::new(EchoService, 5, Duration::from_secs(1));

        // Start with some tokens
        set_bucket_state(&svc, 3, Some(Time::from_secs(0)));

        // Refill after 2 seconds
        svc.refill(Time::from_secs(2));

        // Should cap at rate (5), not 3 + 10
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 5, "available", 5, available);
        crate::test_complete!("refill_caps_at_rate");
    }

    #[test]
    fn poll_ready_uses_time_getter() {
        init_test("poll_ready_uses_time_getter");
        let mut svc =
            RateLimit::with_time_getter(EchoService, 5, Duration::from_secs(1), test_time);
        set_bucket_state(&svc, 0, Some(Time::from_secs(0)));
        set_test_time(1_000_000_000);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = svc.poll_ready(&mut cx);
        let ok = matches!(result, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);

        let available = svc.available_tokens();
        crate::assert_with_log!(available == 4, "available", 4, available);
        crate::test_complete!("poll_ready_uses_time_getter");
    }

    #[test]
    fn poll_ready_with_time_respects_inner_pending_and_reserves_token_on_ready() {
        init_test("poll_ready_with_time_respects_inner_pending_and_reserves_token_on_ready");
        let ready = Arc::new(AtomicBool::new(false));
        let mut svc = RateLimit::new(
            ToggleReadyService::new(ready.clone(), false),
            1,
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready_with_time::<()>(Time::from_secs(0), &mut cx);
        crate::assert_with_log!(first.is_pending(), "pending", true, first.is_pending());
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available",
            1,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 0,
            "reserved",
            0,
            svc.reserved_tokens()
        );

        ready.store(true, Ordering::SeqCst);
        let second = svc.poll_ready_with_time::<()>(Time::from_secs(0), &mut cx);
        let ok = matches!(second, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        crate::assert_with_log!(
            svc.available_tokens() == 0,
            "available",
            0,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 1,
            "reserved",
            1,
            svc.reserved_tokens()
        );
        crate::test_complete!(
            "poll_ready_with_time_respects_inner_pending_and_reserves_token_on_ready"
        );
    }

    #[test]
    fn poll_ready_with_time_propagates_inner_error() {
        init_test("poll_ready_with_time_propagates_inner_error");
        let ready = Arc::new(AtomicBool::new(true));
        let mut svc = RateLimit::new(
            ToggleReadyService::new(ready, true),
            1,
            Duration::from_secs(1),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = svc.poll_ready_with_time::<()>(Time::from_secs(0), &mut cx);
        let err = matches!(
            result,
            Poll::Ready(Err(RateLimitError::Inner("inner error")))
        );
        crate::assert_with_log!(err, "inner err", true, err);
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available",
            1,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 0,
            "reserved",
            0,
            svc.reserved_tokens()
        );
        crate::test_complete!("poll_ready_with_time_propagates_inner_error");
    }

    #[test]
    fn reserved_poll_ready_error_restores_token_and_clears_reservation() {
        init_test("reserved_poll_ready_error_restores_token_and_clears_reservation");
        let mut svc = RateLimit::new(ReadyThenErrorService::default(), 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready_with_time::<()>(Time::ZERO, &mut cx);
        let first_ok = matches!(first, Poll::Ready(Ok(())));
        crate::assert_with_log!(first_ok, "first ready", true, first_ok);
        crate::assert_with_log!(
            svc.available_tokens() == 0,
            "available after reservation",
            0,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 1,
            "reserved after first ready",
            1,
            svc.reserved_tokens()
        );

        let second = svc.poll_ready_with_time::<()>(Time::ZERO, &mut cx);
        let second_err = matches!(
            second,
            Poll::Ready(Err(RateLimitError::Inner("inner error")))
        );
        crate::assert_with_log!(second_err, "second ready error", true, second_err);
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available after reserved-path error",
            1,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 0,
            "reserved cleared after reserved-path error",
            0,
            svc.reserved_tokens()
        );

        let mut future = svc.call(());
        let result = Pin::new(&mut future).poll(&mut cx);
        let not_ready = matches!(result, Poll::Ready(Err(RateLimitError::NotReady)));
        crate::assert_with_log!(
            not_ready,
            "call requires a fresh successful poll_ready after error",
            true,
            not_ready
        );
        crate::test_complete!("reserved_poll_ready_error_restores_token_and_clears_reservation");
    }

    #[test]
    fn poll_ready_with_time_reserved_token_restores_on_call_panic() {
        init_test("poll_ready_with_time_reserved_token_restores_on_call_panic");
        let mut svc = RateLimit::new(PanicOnCallService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready_with_time::<()>(Time::from_secs(0), &mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        crate::assert_with_log!(
            svc.available_tokens() == 0,
            "available after reserve",
            0,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 1,
            "reserved",
            1,
            svc.reserved_tokens()
        );

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _future = svc.call(());
        }));
        let panicked = panic.is_err();
        crate::assert_with_log!(panicked, "inner call panicked", true, panicked);
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available after panic",
            1,
            svc.available_tokens()
        );
        crate::test_complete!("poll_ready_with_time_reserved_token_restores_on_call_panic");
    }

    #[test]
    fn poll_ready_with_time_restores_token_on_inner_panic() {
        init_test("poll_ready_with_time_restores_token_on_inner_panic");
        let mut svc = RateLimit::new(PanicOnPollReadyService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = svc.poll_ready_with_time::<()>(Time::from_secs(0), &mut cx);
        }));
        let panicked = panic.is_err();
        crate::assert_with_log!(panicked, "inner poll_ready panicked", true, panicked);
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available after panic",
            1,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 0,
            "reserved",
            0,
            svc.reserved_tokens()
        );
        crate::test_complete!("poll_ready_with_time_restores_token_on_inner_panic");
    }

    #[test]
    fn call_without_poll_ready_returns_not_ready() {
        init_test("call_without_poll_ready_returns_not_ready");
        let mut svc = RateLimit::new(PanicOnCallService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut future = svc.call(());
            Pin::new(&mut future).poll(&mut cx)
        }))
        .expect("call without poll_ready must not invoke inner service");

        let not_ready = matches!(result, Poll::Ready(Err(RateLimitError::NotReady)));
        crate::assert_with_log!(not_ready, "not ready", true, not_ready);
        crate::assert_with_log!(
            svc.available_tokens() == 1,
            "available tokens unchanged",
            1,
            svc.available_tokens()
        );
        crate::assert_with_log!(
            svc.reserved_tokens() == 0,
            "reserved",
            0,
            svc.reserved_tokens()
        );
        crate::test_complete!("call_without_poll_ready_returns_not_ready");
    }

    #[test]
    fn zero_period_keeps_bucket_full() {
        init_test("zero_period_keeps_bucket_full");
        let mut svc = RateLimit::with_time_getter(EchoService, 2, Duration::ZERO, test_time);
        set_bucket_state(&svc, 0, Some(Time::from_secs(0)));

        set_test_time(1);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready(&mut cx);
        crate::assert_with_log!(first.is_ready(), "first ready", true, first.is_ready());

        let second = svc.poll_ready(&mut cx);
        crate::assert_with_log!(second.is_ready(), "second ready", true, second.is_ready());
        crate::test_complete!("zero_period_keeps_bucket_full");
    }

    #[test]
    fn zero_period_zero_rate_still_ready() {
        init_test("zero_period_zero_rate_still_ready");
        let mut svc = RateLimit::with_time_getter(EchoService, 0, Duration::ZERO, test_time);
        set_test_time(1);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready(&mut cx);
        crate::assert_with_log!(first.is_ready(), "first ready", true, first.is_ready());

        let second = svc.poll_ready(&mut cx);
        crate::assert_with_log!(second.is_ready(), "second ready", true, second.is_ready());
        crate::test_complete!("zero_period_zero_rate_still_ready");
    }

    // =========================================================================
    // Wave 31: Data-type trait coverage
    // =========================================================================

    #[test]
    fn rate_limit_layer_debug_clone() {
        let layer = RateLimitLayer::new(10, Duration::from_secs(1));
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("RateLimitLayer"));
        let cloned = layer;
        assert_eq!(cloned.rate(), 10);
        assert_eq!(cloned.period(), Duration::from_secs(1));
    }

    #[test]
    fn rate_limit_layer_with_time_getter() {
        let layer = RateLimitLayer::with_time_getter(5, Duration::from_millis(500), test_time);
        assert_eq!(layer.rate(), 5);
        assert_eq!(layer.period(), Duration::from_millis(500));
    }

    #[test]
    fn rate_limit_service_debug() {
        let svc = RateLimit::new(42_i32, 10, Duration::from_secs(1));
        let dbg = format!("{svc:?}");
        assert!(dbg.contains("RateLimit"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn rate_limit_service_clone() {
        let svc = RateLimit::new(42_i32, 10, Duration::from_secs(1));
        let cloned = svc.clone();
        assert_eq!(*cloned.inner(), 42);
        assert_eq!(cloned.rate(), 10);
        assert_eq!(cloned.available_tokens(), 10);
        assert_eq!(svc.rate(), cloned.rate()); // use svc to avoid redundant_clone warning
    }

    #[test]
    fn rate_limit_clone_does_not_inherit_reserved_tokens() {
        init_test("rate_limit_clone_does_not_inherit_reserved_tokens");
        let mut svc = RateLimit::new(EchoService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        crate::assert_with_log!(
            svc.reserved_tokens() == 1,
            "reserved",
            1,
            svc.reserved_tokens()
        );

        let mut cloned = svc.clone();
        crate::assert_with_log!(
            cloned.available_tokens() == 0,
            "clone sees shared token depletion",
            0,
            cloned.available_tokens()
        );
        crate::assert_with_log!(
            cloned.reserved_tokens() == 0,
            "clone reserved tokens reset",
            0,
            cloned.reserved_tokens()
        );

        let mut clone_future = cloned.call(7);
        let clone_result = Pin::new(&mut clone_future).poll(&mut cx);
        let clone_limited = matches!(clone_result, Poll::Ready(Err(RateLimitError::NotReady)));
        crate::assert_with_log!(
            clone_limited,
            "clone cannot spend original reservation",
            true,
            clone_limited
        );

        let mut original_future = svc.call(7);
        let original_result = Pin::new(&mut original_future).poll(&mut cx);
        let original_ok = matches!(original_result, Poll::Ready(Ok(7)));
        crate::assert_with_log!(
            original_ok,
            "original reservation still works",
            true,
            original_ok
        );
        crate::test_complete!("rate_limit_clone_does_not_inherit_reserved_tokens");
    }

    #[test]
    fn rate_limit_clone_shares_bucket_state() {
        init_test("rate_limit_clone_shares_bucket_state");
        let mut svc = RateLimit::new(EchoService, 1, Duration::from_secs(1));
        let mut cloned = svc.clone();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready_with_time::<i32>(Time::ZERO, &mut cx);
        let first_ready = matches!(first, Poll::Ready(Ok(())));
        crate::assert_with_log!(first_ready, "first ready", true, first_ready);
        crate::assert_with_log!(
            cloned.available_tokens() == 0,
            "clone sees depleted bucket",
            0,
            cloned.available_tokens()
        );

        let second = cloned.poll_ready_with_time::<i32>(Time::from_millis(500), &mut cx);
        crate::assert_with_log!(
            second.is_pending(),
            "second pending",
            true,
            second.is_pending()
        );

        let mut fut = svc.call(7);
        let result = Pin::new(&mut fut).poll(&mut cx);
        let first_ok = matches!(result, Poll::Ready(Ok(7)));
        crate::assert_with_log!(first_ok, "first call result", true, first_ok);

        let third = cloned.poll_ready_with_time::<i32>(Time::from_secs(1), &mut cx);
        let third_ready = matches!(third, Poll::Ready(Ok(())));
        crate::assert_with_log!(third_ready, "third ready after refill", true, third_ready);
        crate::test_complete!("rate_limit_clone_shares_bucket_state");
    }

    #[test]
    fn dropping_clone_restores_shared_reserved_token() {
        init_test("dropping_clone_restores_shared_reserved_token");
        let mut svc = RateLimit::new(EchoService, 1, Duration::from_secs(1));
        let mut cloned = svc.clone();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready_with_time::<i32>(Time::ZERO, &mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "original ready", true, ready_ok);
        crate::assert_with_log!(
            cloned.available_tokens() == 0,
            "clone sees depleted bucket before drop",
            0,
            cloned.available_tokens()
        );

        drop(svc);

        crate::assert_with_log!(
            cloned.available_tokens() == 1,
            "drop restores shared token",
            1,
            cloned.available_tokens()
        );

        let clone_ready = cloned.poll_ready_with_time::<i32>(Time::ZERO, &mut cx);
        let clone_ready_ok = matches!(clone_ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(
            clone_ready_ok,
            "clone ready after drop",
            true,
            clone_ready_ok
        );
        crate::test_complete!("dropping_clone_restores_shared_reserved_token");
    }

    #[test]
    fn reserved_token_guard_caps_restored_bucket_at_rate() {
        init_test("reserved_token_guard_caps_restored_bucket_at_rate");
        let state = Arc::new(Mutex::new(SharedRateLimitState {
            tokens: 1,
            last_refill: Some(Time::ZERO),
        }));

        {
            let _guard = ReservedTokenGuard::new(Arc::clone(&state), 1, false, true);
        }

        let tokens = state.lock().tokens;
        crate::assert_with_log!(tokens == 1, "restored tokens capped", 1, tokens);
        crate::test_complete!("reserved_token_guard_caps_restored_bucket_at_rate");
    }

    #[test]
    fn rate_limit_service_accessors() {
        let mut svc = RateLimit::new(42_i32, 10, Duration::from_secs(1));
        assert_eq!(*svc.inner(), 42);
        assert_eq!(svc.rate(), 10);
        assert_eq!(svc.period(), Duration::from_secs(1));
        *svc.inner_mut() = 99;
        assert_eq!(svc.into_inner(), 99);
    }

    #[test]
    fn rate_limit_error_debug() {
        let err: RateLimitError<&str> = RateLimitError::NotReady;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotReady"));

        let err: RateLimitError<&str> = RateLimitError::RateLimitExceeded;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimitExceeded"));

        let err: RateLimitError<&str> = RateLimitError::PolledAfterCompletion;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PolledAfterCompletion"));

        let err: RateLimitError<&str> = RateLimitError::Inner("fail");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Inner"));
    }

    #[test]
    fn rate_limit_error_source() {
        use std::error::Error;
        let err: RateLimitError<std::io::Error> = RateLimitError::NotReady;
        assert!(err.source().is_none());

        let err: RateLimitError<std::io::Error> = RateLimitError::RateLimitExceeded;
        assert!(err.source().is_none());

        let err: RateLimitError<std::io::Error> = RateLimitError::PolledAfterCompletion;
        assert!(err.source().is_none());

        let inner = std::io::Error::other("test");
        let err = RateLimitError::Inner(inner);
        assert!(err.source().is_some());
    }

    #[test]
    fn rate_limit_future_debug() {
        let future: RateLimitFuture<_, &str> =
            RateLimitFuture::new(std::future::ready(Ok::<i32, &str>(42)));
        let dbg = format!("{future:?}");
        assert!(dbg.contains("RateLimitFuture"));
    }

    #[test]
    fn immediate_error_repolls_fail_closed_after_completion() {
        init_test("immediate_error_repolls_fail_closed_after_completion");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future: RateLimitFuture<
            std::future::Ready<Result<i32, &'static str>>,
            &'static str,
        > = RateLimitFuture::immediate_error(RateLimitError::NotReady);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Err(RateLimitError::NotReady))),
            "first poll returns stored error",
            true,
            matches!(first, Poll::Ready(Err(RateLimitError::NotReady)))
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            ),
            "second poll fails closed",
            true,
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            )
        );
        crate::test_complete!("immediate_error_repolls_fail_closed_after_completion");
    }

    #[test]
    fn completed_inner_future_repolls_fail_closed() {
        init_test("completed_inner_future_repolls_fail_closed");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future: RateLimitFuture<_, &'static str> =
            RateLimitFuture::new(std::future::ready(Ok::<i32, &'static str>(42)));

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(42))),
            "first poll returns success",
            true,
            matches!(first, Poll::Ready(Ok(42)))
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            ),
            "second poll fails closed",
            true,
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            )
        );
        crate::test_complete!("completed_inner_future_repolls_fail_closed");
    }

    #[test]
    fn completed_inner_error_repolls_fail_closed() {
        init_test("completed_inner_error_repolls_fail_closed");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = RateLimitFuture::new(std::future::ready(Err::<i32, &'static str>("boom")));

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Err(RateLimitError::Inner("boom")))),
            "first poll returns inner error",
            true,
            matches!(first, Poll::Ready(Err(RateLimitError::Inner("boom"))))
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            ),
            "second poll fails closed",
            true,
            matches!(
                second,
                Poll::Ready(Err(RateLimitError::PolledAfterCompletion))
            )
        );
        crate::test_complete!("completed_inner_error_repolls_fail_closed");
    }

    struct TrackWaker(Arc<AtomicBool>);
    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Regression test: Sleep must register a waker when tokens are exhausted.
    ///
    /// Previously, `Sleep::with_time_getter()` was used, which returns Pending
    /// without registering any waker — causing tasks to hang forever. The fix
    /// uses `Sleep::new()` which properly registers with the timer driver or
    /// spawns a fallback thread.
    #[test]
    fn exhausted_tokens_register_waker_not_hang() {
        init_test("exhausted_tokens_register_waker_not_hang");
        let woken = Arc::new(AtomicBool::new(false));

        let waker: Waker = Arc::new(TrackWaker(woken)).into();
        let mut cx = Context::from_waker(&waker);

        // Create a rate limiter with 1 token, custom time getter.
        let mut svc =
            RateLimit::with_time_getter(EchoService, 1, Duration::from_secs(1), test_time);

        // Set time to 0, consume the single token via poll_ready + call.
        set_test_time(0);
        let first = svc.poll_ready(&mut cx);
        let ok = matches!(first, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "first ready", true, ok);
        let mut future = svc.call(42);
        let _ = Pin::new(&mut future).poll(&mut cx);

        // Now tokens are exhausted. poll_ready should return Pending.
        let second = svc.poll_ready(&mut cx);
        crate::assert_with_log!(second.is_pending(), "pending", true, second.is_pending());

        // The Sleep should NOT use time_getter (which would skip waker registration).
        // Verify the sleep field exists and was created with Sleep::new (no time_getter).
        let sleep = svc.sleep.as_ref().expect("sleep must be created");
        let has_time_getter = sleep.time_getter.is_some();
        crate::assert_with_log!(
            !has_time_getter,
            "sleep must NOT have time_getter",
            false,
            has_time_getter
        );

        crate::test_complete!("exhausted_tokens_register_waker_not_hang");
    }

    #[test]
    fn error_display() {
        init_test("error_display");
        let err: RateLimitError<&str> = RateLimitError::NotReady;
        let display = format!("{err}");
        let has_not_ready = display.contains("poll_ready required before call");
        crate::assert_with_log!(has_not_ready, "not ready", true, has_not_ready);

        let err: RateLimitError<&str> = RateLimitError::RateLimitExceeded;
        let display = format!("{err}");
        let has_rate = display.contains("rate limit exceeded");
        crate::assert_with_log!(has_rate, "rate limit", true, has_rate);

        let err: RateLimitError<&str> = RateLimitError::PolledAfterCompletion;
        let display = format!("{err}");
        let has_polled_after_completion = display.contains("future polled after completion");
        crate::assert_with_log!(
            has_polled_after_completion,
            "polled after completion",
            true,
            has_polled_after_completion
        );

        let err: RateLimitError<&str> = RateLimitError::Inner("inner error");
        let display = format!("{err}");
        let has_inner = display.contains("inner service error");
        crate::assert_with_log!(has_inner, "inner error", true, has_inner);
        crate::test_complete!("error_display");
    }
}
