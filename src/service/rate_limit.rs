//! Rate limiting middleware layer.
//!
//! The [`RateLimitLayer`] wraps a service to limit the rate of requests using
//! a token bucket algorithm. Requests are only allowed when tokens are available.

use super::{Layer, Service};
use crate::time::{TimeSource, WallClock};
use crate::types::Time;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;

fn wall_clock_now() -> Time {
    static CLOCK: OnceLock<WallClock> = OnceLock::new();
    CLOCK.get_or_init(WallClock::new).now()
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
    /// Current number of available tokens (plain field — `&mut self` is exclusive).
    tokens: u64,
    /// Last time tokens were refilled.
    last_refill: Option<Time>,
    /// Maximum tokens (bucket capacity).
    rate: u64,
    /// Period for refilling tokens.
    period: Duration,
    time_getter: fn() -> Time,
}

impl<S: Clone> Clone for RateLimit<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            tokens: self.tokens,
            last_refill: self.last_refill,
            rate: self.rate,
            period: self.period,
            time_getter: self.time_getter,
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
        Self {
            inner,
            tokens: rate, // Start with full bucket
            last_refill: None,
            rate,
            period,
            time_getter: wall_clock_now,
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
        Self {
            inner,
            tokens: rate,
            last_refill: None,
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

    /// Returns the time source used by this rate limiter.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }

    /// Returns the current number of available tokens.
    #[must_use]
    pub fn available_tokens(&self) -> u64 {
        self.tokens
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
    fn refill_state(&mut self, now: Time) {
        let last_refill = self.last_refill.unwrap_or(now);
        let elapsed_nanos = now.as_nanos().saturating_sub(last_refill.as_nanos());
        let period_nanos = self.period.as_nanos().min(u128::from(u64::MAX)) as u64;

        if period_nanos == 0 {
            // Zero period means "no throttling": keep the bucket full.
            self.tokens = self.rate;
            self.last_refill = Some(now);
            return;
        }

        if period_nanos > 0 && elapsed_nanos > 0 {
            // Calculate how many periods have passed
            let periods = elapsed_nanos / period_nanos;
            if periods > 0 {
                // Add tokens for complete periods
                let new_tokens = periods.saturating_mul(self.rate);
                self.tokens = self.tokens.saturating_add(new_tokens).min(self.rate);
                // Update last_refill to the last complete period boundary
                let refill_time = last_refill.saturating_add_nanos(periods * period_nanos);
                self.last_refill = Some(refill_time);
            }
        } else if self.last_refill.is_none() {
            self.last_refill = Some(now);
        }
    }

    /// Refills tokens based on elapsed time.
    fn refill(&mut self, now: Time) {
        self.refill_state(now);
    }

    /// Tries to acquire a token.
    fn try_acquire(&mut self) -> bool {
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Polls readiness with an explicit time value.
    ///
    /// Single lock acquisition: refill + acquire in one critical section.
    pub fn poll_ready_with_time(
        &mut self,
        now: Time,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), RateLimitError<std::convert::Infallible>>>
    where
        S: Service<()>,
    {
        self.refill_state(now);
        if self.tokens > 0 {
            self.tokens -= 1;
            Poll::Ready(Ok(()))
        } else {
            // Wake up caller to retry later
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Error returned by rate-limited services.
#[derive(Debug)]
pub enum RateLimitError<E> {
    /// Rate limit exceeded (should not normally be seen - poll_ready handles this).
    RateLimitExceeded,
    /// The inner service returned an error.
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for RateLimitError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimitExceeded => write!(f, "rate limit exceeded"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RateLimitError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RateLimitExceeded => None,
            Self::Inner(e) => Some(e),
        }
    }
}

impl<S, Request> Service<Request> for RateLimit<S>
where
    S: Service<Request>,
    S::Future: Unpin,
{
    type Response = S::Response;
    type Error = RateLimitError<S::Error>;
    type Future = RateLimitFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let now = (self.time_getter)();

        // Refill + eagerly acquire token (no lock — `&mut self` is exclusive).
        self.refill_state(now);
        if self.tokens == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.tokens -= 1;

        // Token reserved. Check inner readiness.
        match self.inner.poll_ready(cx).map_err(RateLimitError::Inner) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            other => {
                // Inner not ready or errored — return the reserved token.
                self.tokens += 1;
                other
            }
        }
    }

    #[inline]
    fn call(&mut self, req: Request) -> Self::Future {
        RateLimitFuture::new(self.inner.call(req))
    }
}

/// Future returned by [`RateLimit`] service.
pub struct RateLimitFuture<F> {
    inner: F,
}

impl<F> RateLimitFuture<F> {
    /// Creates a new rate-limited future.
    #[must_use]
    pub fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F, T, E> Future for RateLimitFuture<F>
where
    F: Future<Output = Result<T, E>> + Unpin,
{
    type Output = Result<T, RateLimitError<E>>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll(cx) {
            Poll::Ready(Ok(response)) => Poll::Ready(Ok(response)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(RateLimitError::Inner(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F: std::fmt::Debug> std::fmt::Debug for RateLimitFuture<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitFuture")
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::ready;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

    static TEST_NOW: AtomicU64 = AtomicU64::new(0);

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
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

        // Each poll_ready should consume a token
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
        }
        crate::test_complete!("tokens_consumed_on_ready");
    }

    #[test]
    fn pending_when_no_tokens() {
        init_test("pending_when_no_tokens");
        let mut svc = RateLimit::new(EchoService, 1, Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First call succeeds
        let result = svc.poll_ready(&mut cx);
        let ok = matches!(result, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "first ready", true, ok);

        // Second call should be pending (no tokens)
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
    fn refill_adds_tokens() {
        init_test("refill_adds_tokens");
        let mut svc = RateLimit::new(EchoService, 10, Duration::from_secs(1));

        // Drain all tokens
        {
            svc.tokens = 0;
            svc.last_refill = Some(Time::from_secs(0));
        }

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
        let mut svc = RateLimit::new(EchoService, 5, Duration::from_secs(1));

        // Start with some tokens
        {
            svc.tokens = 3;
            svc.last_refill = Some(Time::from_secs(0));
        }

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
        {
            svc.tokens = 0;
            svc.last_refill = Some(Time::from_secs(0));
        }
        TEST_NOW.store(1_000_000_000, Ordering::SeqCst);
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
    fn zero_period_keeps_bucket_full() {
        init_test("zero_period_keeps_bucket_full");
        let mut svc = RateLimit::with_time_getter(EchoService, 2, Duration::ZERO, test_time);
        {
            svc.tokens = 0;
            svc.last_refill = Some(Time::from_secs(0));
        }

        TEST_NOW.store(1, Ordering::SeqCst);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready(&mut cx);
        crate::assert_with_log!(first.is_ready(), "first ready", true, first.is_ready());

        let second = svc.poll_ready(&mut cx);
        crate::assert_with_log!(second.is_ready(), "second ready", true, second.is_ready());
        crate::test_complete!("zero_period_keeps_bucket_full");
    }

    #[test]
    fn error_display() {
        init_test("error_display");
        let err: RateLimitError<&str> = RateLimitError::RateLimitExceeded;
        let display = format!("{err}");
        let has_rate = display.contains("rate limit exceeded");
        crate::assert_with_log!(has_rate, "rate limit", true, has_rate);

        let err: RateLimitError<&str> = RateLimitError::Inner("inner error");
        let display = format!("{err}");
        let has_inner = display.contains("inner service error");
        crate::assert_with_log!(has_inner, "inner error", true, has_inner);
        crate::test_complete!("error_display");
    }
}
