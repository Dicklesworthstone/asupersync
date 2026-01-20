//! Rate limiting middleware layer.
//!
//! The [`RateLimitLayer`] wraps a service to limit the rate of requests using
//! a token bucket algorithm. Requests are only allowed when tokens are available.

use super::{Layer, Service};
use crate::types::Time;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;

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
        Self { rate, period }
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
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimit::new(inner, self.rate, self.period)
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
    state: Mutex<RateLimitState>,
    /// Maximum tokens (bucket capacity).
    rate: u64,
    /// Period for refilling tokens.
    period: Duration,
}

#[derive(Debug)]
struct RateLimitState {
    /// Current number of available tokens.
    tokens: u64,
    /// Last time tokens were refilled.
    last_refill: Option<Time>,
}

impl<S: Clone> Clone for RateLimit<S> {
    fn clone(&self) -> Self {
        let state = self.state.lock().expect("rate limit lock poisoned");
        Self {
            inner: self.inner.clone(),
            state: Mutex::new(RateLimitState {
                tokens: state.tokens,
                last_refill: state.last_refill,
            }),
            rate: self.rate,
            period: self.period,
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
            state: Mutex::new(RateLimitState {
                tokens: rate, // Start with full bucket
                last_refill: None,
            }),
            rate,
            period,
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

    /// Returns the current number of available tokens.
    #[must_use]
    pub fn available_tokens(&self) -> u64 {
        self.state.lock().expect("rate limit lock poisoned").tokens
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

    /// Consumes the rate limiter, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Refills tokens based on elapsed time.
    fn refill(&self, now: Time) {
        let mut state = self.state.lock().expect("rate limit lock poisoned");

        let last_refill = state.last_refill.unwrap_or(now);
        let elapsed_nanos = now.as_nanos().saturating_sub(last_refill.as_nanos());
        let period_nanos = self.period.as_nanos() as u64;

        if period_nanos > 0 && elapsed_nanos > 0 {
            // Calculate how many periods have passed
            let periods = elapsed_nanos / period_nanos;
            if periods > 0 {
                // Add tokens for complete periods
                let new_tokens = periods.saturating_mul(self.rate);
                state.tokens = state.tokens.saturating_add(new_tokens).min(self.rate);
                // Update last_refill to the last complete period boundary
                let refill_time = last_refill.saturating_add_nanos(periods * period_nanos);
                state.last_refill = Some(refill_time);
            }
        } else if state.last_refill.is_none() {
            state.last_refill = Some(now);
        }
    }

    /// Tries to acquire a token.
    fn try_acquire(&self) -> bool {
        let mut state = self.state.lock().expect("rate limit lock poisoned");
        if state.tokens > 0 {
            state.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Polls readiness with an explicit time value.
    pub fn poll_ready_with_time(
        &mut self,
        now: Time,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), RateLimitError<std::convert::Infallible>>>
    where
        S: Service<()>,
    {
        self.refill(now);

        if self.try_acquire() {
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
        // Use wall clock time for refill calculation
        // Note: In production, this should integrate with the runtime's time source
        let now = Time::from_nanos(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos() as u64,
        );
        self.refill(now);

        if self.try_acquire() {
            // Also check inner service readiness
            self.inner.poll_ready(cx).map_err(RateLimitError::Inner)
        } else {
            // No tokens available
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

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
            crate::assert_with_log!(available == expected - 1, "available", expected - 1, available);
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
    fn refill_adds_tokens() {
        init_test("refill_adds_tokens");
        let svc = RateLimit::new(EchoService, 10, Duration::from_secs(1));

        // Drain all tokens
        {
            let mut state = svc.state.lock().unwrap();
            state.tokens = 0;
            state.last_refill = Some(Time::from_secs(0));
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
        let svc = RateLimit::new(EchoService, 5, Duration::from_secs(1));

        // Start with some tokens
        {
            let mut state = svc.state.lock().unwrap();
            state.tokens = 3;
            state.last_refill = Some(Time::from_secs(0));
        }

        // Refill after 2 seconds
        svc.refill(Time::from_secs(2));

        // Should cap at rate (5), not 3 + 10
        let available = svc.available_tokens();
        crate::assert_with_log!(available == 5, "available", 5, available);
        crate::test_complete!("refill_caps_at_rate");
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
