//! Retry middleware layer.
//!
//! The [`RetryLayer`] wraps a service to automatically retry failed requests
//! according to a configurable [`Policy`].

use super::{Layer, Service};
use crate::cx::Cx;
use crate::time::{Sleep, wall_now};
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// Cooperative budget for immediately completed retry attempts in a single
/// outer poll.
///
/// Without this bound, an always-ready inner service combined with an
/// immediate retry policy can monopolize one executor turn while it burns
/// through a long retry chain.
const RETRY_COOPERATIVE_BUDGET: usize = 1024;

/// A policy that determines whether and how to retry a request.
///
/// The policy is consulted after each request completes to determine if
/// a retry should be attempted.
pub trait Policy<Req, Res, E>: Clone {
    /// Future returned by [`Policy::retry`] when a retry is warranted.
    type Future: Future<Output = Self>;

    /// Determines whether to retry the request.
    ///
    /// Returns `Some(future)` if the request should be retried, where the
    /// future resolves to the policy to use for the retry. The future can
    /// implement delays (backoff) before retrying.
    ///
    /// Returns `None` if the request should not be retried.
    fn retry(&self, req: &Req, result: Result<&Res, &E>) -> Option<Self::Future>;

    /// Clones the request for retry.
    ///
    /// Returns `None` if the request cannot be cloned (e.g., it was consumed).
    /// In this case, the retry will not be attempted even if [`Policy::retry`]
    /// returns `Some`.
    fn clone_request(&self, req: &Req) -> Option<Req>;
}

/// A layer that retries requests according to a policy.
///
/// # Example
///
/// ```ignore
/// use asupersync::service::{ServiceBuilder, ServiceExt};
/// use asupersync::service::retry::{RetryLayer, Policy};
/// use std::time::Duration;
///
/// let policy = MyRetryPolicy::new(3, Duration::from_millis(100));
/// let svc = ServiceBuilder::new()
///     .layer(RetryLayer::new(policy))
///     .service(my_service);
/// ```
#[derive(Debug, Clone)]
pub struct RetryLayer<P> {
    policy: P,
}

impl<P> RetryLayer<P> {
    /// Creates a new retry layer with the given policy.
    #[must_use]
    pub const fn new(policy: P) -> Self {
        Self { policy }
    }

    /// Returns a reference to the policy.
    #[must_use]
    pub const fn policy(&self) -> &P {
        &self.policy
    }
}

impl<S, P: Clone> Layer<S> for RetryLayer<P> {
    type Service = Retry<P, S>;

    fn layer(&self, inner: S) -> Self::Service {
        Retry::new(inner, self.policy.clone())
    }
}

/// Error returned by the retry middleware.
#[derive(Debug)]
pub enum RetryError<E> {
    /// The retry future was polled after it had already completed.
    PolledAfterCompletion,
    /// The inner service returned an error.
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for RetryError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolledAfterCompletion => write!(f, "retry future polled after completion"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RetryError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PolledAfterCompletion => None,
            Self::Inner(e) => Some(e),
        }
    }
}

/// A service that retries requests according to a policy.
#[derive(Debug, Clone)]
pub struct Retry<P, S> {
    policy: P,
    inner: S,
}

impl<P, S> Retry<P, S> {
    /// Creates a new retry service.
    #[must_use]
    pub const fn new(inner: S, policy: P) -> Self {
        Self { policy, inner }
    }

    /// Returns a reference to the policy.
    #[must_use]
    pub const fn policy(&self) -> &P {
        &self.policy
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

    /// Consumes the retry service, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<P, S, Request> Service<Request> for Retry<P, S>
where
    P: Policy<Request, S::Response, S::Error> + Unpin,
    P::Future: Unpin,
    S: Service<Request> + Clone + Unpin,
    S::Future: Unpin,
    S::Response: Unpin,
    S::Error: Unpin,
    Request: Unpin,
{
    type Response = S::Response;
    type Error = RetryError<S::Error>;
    type Future = RetryFuture<P, S, Request>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Requests execute against a cloned service inside RetryFuture. Polling
        // readiness on `self.inner` here can strand stateful reservations
        // (permits/tokens/slots) on the source service while the actual request
        // waits on its clone.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        RetryFuture::new(self.inner.clone(), self.policy.clone(), req)
    }
}

/// Future returned by [`Retry`] service.
pub struct RetryFuture<P, S, Request>
where
    S: Service<Request>,
    P: Policy<Request, S::Response, S::Error>,
{
    state: RetryState<P, S, Request>,
}

enum RetryState<P, S, Request>
where
    S: Service<Request>,
    P: Policy<Request, S::Response, S::Error>,
{
    /// Polling the inner service for readiness.
    PollReady {
        service: S,
        policy: P,
        request: Option<Request>,
    },
    /// Calling the inner service.
    Calling {
        service: S,
        policy: P,
        request: Option<Request>,
        future: S::Future,
    },
    /// Waiting for retry policy decision.
    Checking {
        service: S,
        request: Option<Request>,
        result: Option<Result<S::Response, S::Error>>,
        retry_future: P::Future,
        request_consumed: bool,
    },
    /// Completed.
    Done,
}

impl<P, S, Request> RetryFuture<P, S, Request>
where
    S: Service<Request>,
    P: Policy<Request, S::Response, S::Error>,
{
    /// Creates a new retry future.
    #[must_use]
    pub fn new(service: S, policy: P, request: Request) -> Self {
        Self {
            state: RetryState::PollReady {
                service,
                policy,
                request: Some(request),
            },
        }
    }
}

impl<P, S, Request> Future for RetryFuture<P, S, Request>
where
    P: Policy<Request, S::Response, S::Error> + Unpin,
    P::Future: Unpin,
    S: Service<Request> + Clone + Unpin,
    S::Future: Unpin,
    S::Response: Unpin,
    S::Error: Unpin,
    Request: Unpin,
{
    type Output = Result<S::Response, RetryError<S::Error>>;

    #[allow(clippy::too_many_lines)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut completed_attempts_this_poll = 0usize;

        loop {
            let state = std::mem::replace(&mut this.state, RetryState::Done);

            match state {
                RetryState::PollReady {
                    mut service,
                    policy,
                    request,
                } => {
                    match service.poll_ready(cx) {
                        Poll::Pending => {
                            this.state = RetryState::PollReady {
                                service,
                                policy,
                                request,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            let retry_decision = request.as_ref().and_then(|req_ref| {
                                policy.retry(req_ref, Err::<&S::Response, &S::Error>(&e))
                            });

                            match retry_decision {
                                None => {
                                    this.state = RetryState::Done;
                                    return Poll::Ready(Err(RetryError::Inner(e)));
                                }
                                Some(retry_future) => {
                                    completed_attempts_this_poll += 1;
                                    this.state = RetryState::Checking {
                                        service,
                                        request,
                                        result: Some(Err(e)),
                                        retry_future,
                                        request_consumed: false,
                                    };

                                    if completed_attempts_this_poll >= RETRY_COOPERATIVE_BUDGET {
                                        cx.waker().wake_by_ref();
                                        return Poll::Pending;
                                    }
                                }
                            }
                        }
                        Poll::Ready(Ok(())) => {
                            let req = request.expect("request already taken");

                            // Try to clone the request for potential retry
                            let backup = policy.clone_request(&req);
                            // println!("PollReady: req={:?}, backup={:?}", std::any::type_name::<Request>(), backup.is_some());

                            let future = service.call(req);

                            this.state = RetryState::Calling {
                                service,
                                policy,
                                request: backup,
                                future,
                            };
                        }
                    }
                }
                RetryState::Calling {
                    service,
                    policy,
                    request,
                    mut future,
                } => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        this.state = RetryState::Calling {
                            service,
                            policy,
                            request,
                            future,
                        };
                        return Poll::Pending;
                    }
                    Poll::Ready(result) => {
                        // Check if we should retry
                        let retry_decision = request.as_ref().map_or_else(
                            || None,
                            |req_ref| match &result {
                                Ok(res) => policy.retry(req_ref, Ok(res)),
                                Err(e) => policy.retry(req_ref, Err(e)),
                            },
                        );

                        match retry_decision {
                            None => {
                                // No retry - return the result
                                this.state = RetryState::Done;
                                return Poll::Ready(result.map_err(RetryError::Inner));
                            }
                            Some(retry_future) => {
                                completed_attempts_this_poll += 1;
                                this.state = RetryState::Checking {
                                    service,
                                    request,
                                    result: Some(result),
                                    retry_future,
                                    request_consumed: true,
                                };

                                if completed_attempts_this_poll >= RETRY_COOPERATIVE_BUDGET {
                                    cx.waker().wake_by_ref();
                                    return Poll::Pending;
                                }
                            }
                        }
                    }
                },
                RetryState::Checking {
                    service,
                    request,
                    mut result,
                    mut retry_future,
                    request_consumed,
                } => {
                    match Pin::new(&mut retry_future).poll(cx) {
                        Poll::Pending => {
                            this.state = RetryState::Checking {
                                service,
                                request,
                                result,
                                retry_future,
                                request_consumed,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(new_policy) => {
                            let next_request = if request_consumed {
                                // After `call()` the original request has been consumed, so
                                // retries must use a policy-approved backup clone.
                                request.as_ref().and_then(|r| new_policy.clone_request(r))
                            } else {
                                // A `poll_ready()` failure happens before the request is sent.
                                // Reuse the original request directly instead of requiring an
                                // artificial clone for a side-effect-free retry.
                                request
                            };

                            if let Some(new_request) = next_request {
                                this.state = RetryState::PollReady {
                                    service,
                                    policy: new_policy,
                                    request: Some(new_request),
                                };
                            } else {
                                // Cannot clone request - return original result
                                let result = result.take().expect("result should exist");
                                this.state = RetryState::Done;
                                return Poll::Ready(result.map_err(RetryError::Inner));
                            }
                        }
                    }
                }
                RetryState::Done => {
                    return Poll::Ready(Err(RetryError::PolledAfterCompletion));
                }
            }
        }
    }
}

impl<P, S, Request> std::fmt::Debug for RetryFuture<P, S, Request>
where
    S: Service<Request>,
    P: Policy<Request, S::Response, S::Error>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetryFuture").finish_non_exhaustive()
    }
}

/// A simple retry policy that retries a fixed number of times.
///
/// This policy retries on any error up to `max_retries` times.
/// It does not implement backoff - all retries are immediate.
#[derive(Debug, Clone, Copy)]
pub struct LimitedRetry<Request> {
    max_retries: usize,
    current_attempt: usize,
    _marker: PhantomData<fn(Request) -> Request>,
}

impl<Request> LimitedRetry<Request> {
    /// Creates a new limited retry policy.
    #[must_use]
    pub const fn new(max_retries: usize) -> Self {
        Self {
            max_retries,
            current_attempt: 0,
            _marker: PhantomData,
        }
    }

    /// Returns the maximum number of retries.
    #[must_use]
    pub const fn max_retries(&self) -> usize {
        self.max_retries
    }

    /// Returns the current attempt number (0-indexed).
    #[must_use]
    pub const fn current_attempt(&self) -> usize {
        self.current_attempt
    }
}

impl<Request: Clone, Res, E> Policy<Request, Res, E> for LimitedRetry<Request> {
    type Future = std::future::Ready<Self>;

    fn retry(&self, _req: &Request, result: Result<&Res, &E>) -> Option<Self::Future> {
        // Only retry on error
        if result.is_ok() {
            return None;
        }

        // Check if we have retries remaining
        if self.current_attempt >= self.max_retries {
            return None;
        }

        // Return new policy with incremented attempt counter
        let new_policy = Self {
            max_retries: self.max_retries,
            current_attempt: self.current_attempt + 1,
            _marker: PhantomData,
        };

        Some(std::future::ready(new_policy))
    }

    fn clone_request(&self, req: &Request) -> Option<Request> {
        Some(req.clone())
    }
}

/// A policy that never retries.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRetry;

impl NoRetry {
    /// Creates a new no-retry policy.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<Request, Res, E> Policy<Request, Res, E> for NoRetry {
    type Future = std::future::Pending<Self>;

    fn retry(&self, _req: &Request, _result: Result<&Res, &E>) -> Option<Self::Future> {
        None
    }

    fn clone_request(&self, _req: &Request) -> Option<Request> {
        None
    }
}

/// Jitter strategy for exponential backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterStrategy {
    /// No jitter: delay = base_delay * 2^attempt
    None,
    /// Full jitter: delay = random(0, base_delay * 2^attempt)
    Full,
    /// Equal jitter: delay = (base_delay * 2^attempt) / 2 + random(0, (base_delay * 2^attempt) / 2)
    Equal,
    /// Decorrelated jitter: delay = random(base_delay, delay * 3)
    Decorrelated,
}

/// Exponential backoff retry policy with configurable jitter.
///
/// This policy retries on error with exponential backoff and jitter to avoid thundering herd.
/// The backoff delay follows the formula based on the chosen jitter strategy.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff<Request> {
    max_retries: usize,
    current_attempt: usize,
    base_delay_ms: u64,
    max_delay_ms: u64,
    jitter: JitterStrategy,
    last_delay_ms: u64,
    _marker: PhantomData<fn(Request) -> Request>,
}

impl<Request> ExponentialBackoff<Request> {
    /// Creates a new exponential backoff policy.
    #[must_use]
    pub fn new(max_retries: usize, base_delay_ms: u64, jitter: JitterStrategy) -> Self {
        Self {
            max_retries,
            current_attempt: 0,
            base_delay_ms,
            max_delay_ms: 30_000, // 30 seconds default max
            jitter,
            last_delay_ms: base_delay_ms,
            _marker: PhantomData,
        }
    }

    /// Sets the maximum delay in milliseconds.
    #[must_use]
    pub fn with_max_delay(mut self, max_delay_ms: u64) -> Self {
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// Returns the maximum number of retries.
    #[must_use]
    pub const fn max_retries(&self) -> usize {
        self.max_retries
    }

    /// Returns the current attempt number (0-indexed).
    #[must_use]
    pub const fn current_attempt(&self) -> usize {
        self.current_attempt
    }

    /// Returns the base delay in milliseconds.
    #[must_use]
    pub const fn base_delay_ms(&self) -> u64 {
        self.base_delay_ms
    }

    /// Returns the jitter strategy.
    #[must_use]
    pub const fn jitter(&self) -> JitterStrategy {
        self.jitter
    }

    /// Calculates the next delay based on the jitter strategy.
    fn calculate_delay(&self) -> u64 {
        use crate::util::DetEntropy;

        let entropy = DetEntropy::new(42); // Deterministic seed

        match self.jitter {
            JitterStrategy::None => self
                .base_delay_ms
                .saturating_mul(
                    1_u64
                        .checked_shl(self.current_attempt as u32)
                        .unwrap_or(u64::MAX),
                )
                .min(self.max_delay_ms),
            JitterStrategy::Full => {
                // Full jitter: random(0, base_delay * 2^attempt)
                let max_delay = self
                    .base_delay_ms
                    .saturating_mul(
                        1_u64
                            .checked_shl(self.current_attempt as u32)
                            .unwrap_or(u64::MAX),
                    )
                    .min(self.max_delay_ms);
                if max_delay == 0 {
                    0
                } else {
                    crate::util::entropy::EntropySource::next_u64(&entropy) % (max_delay + 1)
                }
            }
            JitterStrategy::Equal => {
                // Equal jitter: base/2 + random(0, base/2) where base = base_delay * 2^attempt
                let base_delay = self
                    .base_delay_ms
                    .saturating_mul(
                        1_u64
                            .checked_shl(self.current_attempt as u32)
                            .unwrap_or(u64::MAX),
                    )
                    .min(self.max_delay_ms);
                let half_delay = base_delay / 2;
                let jitter = if half_delay == 0 {
                    0
                } else {
                    crate::util::entropy::EntropySource::next_u64(&entropy) % (half_delay + 1)
                };
                half_delay + jitter
            }
            JitterStrategy::Decorrelated => {
                // Decorrelated jitter: random(base_delay, last_delay * 3)
                let min_delay = self.base_delay_ms;
                let max_delay = self.last_delay_ms.saturating_mul(3).min(self.max_delay_ms);
                if max_delay <= min_delay {
                    min_delay
                } else {
                    let range = max_delay - min_delay;
                    min_delay
                        + (crate::util::entropy::EntropySource::next_u64(&entropy) % (range + 1))
                }
            }
        }
    }
}

#[derive(Debug)]
struct RetryDelay<P> {
    delay: Duration,
    sleep: Option<Sleep>,
    next_policy: Option<P>,
}

impl<P> RetryDelay<P> {
    fn new(delay: Duration, next_policy: P) -> Self {
        Self {
            delay,
            sleep: None,
            next_policy: Some(next_policy),
        }
    }

    fn initialize_sleep(&mut self) {
        if self.sleep.is_some() {
            return;
        }

        let sleep = Cx::current().and_then(|cx| cx.timer_driver()).map_or_else(
            || Sleep::after(wall_now(), self.delay),
            |timer| {
                let deadline = timer
                    .now()
                    .saturating_add_nanos(self.delay.as_nanos().min(u128::from(u64::MAX)) as u64);
                Sleep::with_timer_driver(deadline, timer)
            },
        );

        self.sleep = Some(sleep);
    }
}

impl<P: Unpin> Future for RetryDelay<P> {
    type Output = P;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.initialize_sleep();
        let sleep = self
            .sleep
            .as_mut()
            .expect("retry delay sleep should be initialized before polling");

        match Pin::new(sleep).poll(cx) {
            Poll::Ready(()) => Poll::Ready(
                self.next_policy
                    .take()
                    .expect("retry delay policy should be present until completion"),
            ),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<Request: Clone + 'static, Res, E> Policy<Request, Res, E> for ExponentialBackoff<Request> {
    type Future = Pin<Box<dyn Future<Output = Self> + Send + 'static>>;

    fn retry(&self, _req: &Request, result: Result<&Res, &E>) -> Option<Self::Future> {
        // Only retry on error
        if result.is_ok() {
            return None;
        }

        // Check if we have retries remaining
        if self.current_attempt >= self.max_retries {
            return None;
        }

        // Calculate delay for this retry
        let delay_ms = self.calculate_delay();

        let new_policy = Self {
            max_retries: self.max_retries,
            current_attempt: self.current_attempt + 1,
            base_delay_ms: self.base_delay_ms,
            max_delay_ms: self.max_delay_ms,
            jitter: self.jitter,
            last_delay_ms: delay_ms.max(1), // Ensure non-zero for decorrelated
            _marker: PhantomData,
        };

        if delay_ms == 0 {
            // No delay - return immediately
            Some(Box::pin(std::future::ready(new_policy)))
        } else {
            Some(Box::pin(RetryDelay::new(
                Duration::from_millis(delay_ms),
                new_policy,
            )))
        }
    }

    fn clone_request(&self, req: &Request) -> Option<Request> {
        Some(req.clone())
    }
}

/// Request classification for idempotency handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestClassification {
    /// Safe to retry on any error (GET, HEAD, OPTIONS, etc.)
    Idempotent,
    /// Only retry on network errors, not application errors (POST, PUT, etc.)
    NonIdempotent,
}

/// Smart retry policy that considers request idempotency.
///
/// Idempotent requests (GET, HEAD) can be retried on any error.
/// Non-idempotent requests (POST, PUT) are only retried on network/infrastructure errors.
#[derive(Debug, Clone)]
pub struct SmartRetry<Request> {
    backoff: ExponentialBackoff<Request>,
    classification: RequestClassification,
}

impl<Request> SmartRetry<Request> {
    /// Creates a new smart retry policy.
    #[must_use]
    pub fn new(
        max_retries: usize,
        base_delay_ms: u64,
        jitter: JitterStrategy,
        classification: RequestClassification,
    ) -> Self {
        Self {
            backoff: ExponentialBackoff::new(max_retries, base_delay_ms, jitter),
            classification,
        }
    }

    /// Returns the request classification.
    #[must_use]
    pub const fn classification(&self) -> RequestClassification {
        self.classification
    }

    /// Returns a reference to the backoff policy.
    #[must_use]
    pub const fn backoff(&self) -> &ExponentialBackoff<Request> {
        &self.backoff
    }

    /// Determines if the error is retryable based on request classification.
    fn is_retryable_error<E>(&self, _error: &E) -> bool {
        match self.classification {
            RequestClassification::Idempotent => {
                // Idempotent requests can retry on any error
                true
            }
            RequestClassification::NonIdempotent => {
                // Fail closed until the caller can distinguish transport failures
                // from application-level errors, which avoids replaying side effects.
                false
            }
        }
    }
}

impl<Request: Clone + 'static, Res, E> Policy<Request, Res, E> for SmartRetry<Request> {
    type Future = Pin<Box<dyn Future<Output = Self> + Send + 'static>>;

    fn retry(&self, req: &Request, result: Result<&Res, &E>) -> Option<Self::Future> {
        // Only retry on error
        if let Err(error) = result {
            if !self.is_retryable_error(error) {
                return None;
            }
        } else {
            return None;
        }

        // Delegate to the backoff policy
        if let Some(backoff_future) = self.backoff.retry(req, result) {
            let classification = self.classification;
            Some(Box::pin(async move {
                let new_backoff = backoff_future.await;
                SmartRetry {
                    backoff: new_backoff,
                    classification,
                }
            })
                as Pin<Box<dyn Future<Output = Self> + Send + 'static>>)
        } else {
            None
        }
    }

    fn clone_request(&self, req: &Request) -> Option<Request> {
        Some(req.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::service::concurrency_limit::ConcurrencyLimitLayer;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }
    use std::task::{Waker};

    struct TrackWaker(Arc<AtomicBool>);

    use std::task::Wake;
    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    // A service that fails N times then succeeds
    struct FailingService {
        fail_count: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    }

    impl Clone for FailingService {
        fn clone(&self) -> Self {
            Self {
                fail_count: self.fail_count.clone(),
                calls: self.calls.clone(),
            }
        }
    }

    impl FailingService {
        fn new(fail_count: usize) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    fail_count: Arc::new(AtomicUsize::new(fail_count)),
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl Service<i32> for FailingService {
        type Response = i32;
        type Error = &'static str;
        type Future = std::future::Ready<Result<i32, &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let remaining = self.fail_count.load(Ordering::SeqCst);
            if remaining > 0 {
                self.fail_count.fetch_sub(1, Ordering::SeqCst);
                std::future::ready(Err("service error"))
            } else {
                std::future::ready(Ok(req * 2))
            }
        }
    }

    struct OneShotRequest(i32);

    #[derive(Clone)]
    struct ReadyFailThenSucceedService {
        ready_failures_remaining: Arc<AtomicUsize>,
        ready_polls: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    }

    impl ReadyFailThenSucceedService {
        fn new(ready_failures: usize) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
            let ready_polls = Arc::new(AtomicUsize::new(0));
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    ready_failures_remaining: Arc::new(AtomicUsize::new(ready_failures)),
                    ready_polls: Arc::clone(&ready_polls),
                    calls: Arc::clone(&calls),
                },
                ready_polls,
                calls,
            )
        }
    }

    impl Service<OneShotRequest> for ReadyFailThenSucceedService {
        type Response = i32;
        type Error = &'static str;
        type Future = std::future::Ready<Result<i32, &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.ready_polls.fetch_add(1, Ordering::SeqCst);
            let remaining = self.ready_failures_remaining.load(Ordering::SeqCst);
            if remaining > 0 {
                self.ready_failures_remaining.fetch_sub(1, Ordering::SeqCst);
                Poll::Ready(Err("transient readiness failure"))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn call(&mut self, req: OneShotRequest) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(req.0 * 3))
        }
    }

    #[derive(Clone, Copy)]
    struct RetryReadyOnceWithoutClone {
        attempted: bool,
    }

    impl RetryReadyOnceWithoutClone {
        const fn new() -> Self {
            Self { attempted: false }
        }
    }

    impl Policy<OneShotRequest, i32, &'static str> for RetryReadyOnceWithoutClone {
        type Future = std::future::Ready<Self>;

        fn retry(
            &self,
            _req: &OneShotRequest,
            result: Result<&i32, &&'static str>,
        ) -> Option<Self::Future> {
            if self.attempted || result.is_ok() {
                None
            } else {
                Some(std::future::ready(Self { attempted: true }))
            }
        }

        fn clone_request(&self, _req: &OneShotRequest) -> Option<OneShotRequest> {
            None
        }
    }

    #[test]
    fn layer_creates_service() {
        init_test("layer_creates_service");
        let policy = LimitedRetry::<i32>::new(3);
        let layer = RetryLayer::new(policy);
        let (svc, _) = FailingService::new(0);
        let _retry_svc: Retry<_, FailingService> = layer.layer(svc);
        crate::test_complete!("layer_creates_service");
    }

    #[test]
    fn limited_retry_policy_basics() {
        init_test("limited_retry_policy_basics");
        let policy = LimitedRetry::<i32>::new(3);
        let max = policy.max_retries();
        crate::assert_with_log!(max == 3, "max_retries", 3, max);
        let attempt = policy.current_attempt();
        crate::assert_with_log!(attempt == 0, "current_attempt", 0, attempt);
        crate::test_complete!("limited_retry_policy_basics");
    }

    #[test]
    fn limited_retry_clones_request() {
        init_test("limited_retry_clones_request");
        let policy = LimitedRetry::<i32>::new(3);
        // Specify generic types for Policy trait: Request=i32, Res=(), E=()
        let cloned = Policy::<i32, (), ()>::clone_request(&policy, &42);
        crate::assert_with_log!(cloned == Some(42), "cloned", Some(42), cloned);
        crate::test_complete!("limited_retry_clones_request");
    }

    #[test]
    fn limited_retry_returns_none_on_success() {
        init_test("limited_retry_returns_none_on_success");
        let policy = LimitedRetry::<i32>::new(3);
        let result: Option<_> = policy.retry(&42, Ok::<&i32, &String>(&100));
        crate::assert_with_log!(result.is_none(), "none on success", true, result.is_none());
        crate::test_complete!("limited_retry_returns_none_on_success");
    }

    #[test]
    fn limited_retry_returns_some_on_error() {
        init_test("limited_retry_returns_some_on_error");
        let policy = LimitedRetry::<i32>::new(3);
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        crate::assert_with_log!(result.is_some(), "some on error", true, result.is_some());
        crate::test_complete!("limited_retry_returns_some_on_error");
    }

    #[test]
    fn limited_retry_exhausts_retries() {
        init_test("limited_retry_exhausts_retries");
        let mut policy = LimitedRetry::<i32>::new(2);

        // First retry
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        crate::assert_with_log!(result.is_some(), "first retry", true, result.is_some());
        policy.current_attempt = 1;

        // Second retry
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        crate::assert_with_log!(result.is_some(), "second retry", true, result.is_some());
        policy.current_attempt = 2;

        // Third attempt - should fail (max_retries reached)
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        crate::assert_with_log!(result.is_none(), "third retry none", true, result.is_none());
        crate::test_complete!("limited_retry_exhausts_retries");
    }

    #[test]
    fn no_retry_policy() {
        init_test("no_retry_policy");
        let policy = NoRetry::new();
        let result: Option<std::future::Pending<NoRetry>> =
            Policy::<i32, (), &str>::retry(&policy, &42, Err(&"error"));
        crate::assert_with_log!(result.is_none(), "retry none", true, result.is_none());

        let cloned: Option<i32> = Policy::<i32, (), ()>::clone_request(&policy, &42);
        crate::assert_with_log!(cloned.is_none(), "clone none", true, cloned.is_none());
        crate::test_complete!("no_retry_policy");
    }

    #[test]
    fn retry_succeeds_after_failures() {
        init_test("retry_succeeds_after_failures");
        let policy = LimitedRetry::<i32>::new(3);
        let (svc, calls) = FailingService::new(2); // Fail twice, then succeed
        let mut retry_svc = Retry::new(svc, policy);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // poll_ready
        let _ = retry_svc.poll_ready(&mut cx);

        // Start the retry future
        let mut future = retry_svc.call(21);

        // Poll until completion
        loop {
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(result) => {
                    let ok = matches!(result, Ok(42));
                    crate::assert_with_log!(ok, "result ok", true, ok);
                    break;
                }
                Poll::Pending => {}
            }
        }

        // Should have called the service 3 times (2 failures + 1 success)
        let count = calls.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 3, "call count", 3, count);
        crate::test_complete!("retry_succeeds_after_failures");
    }

    #[test]
    fn retry_reuses_original_request_after_poll_ready_error() {
        init_test("retry_reuses_original_request_after_poll_ready_error");
        let policy = RetryReadyOnceWithoutClone::new();
        let (svc, ready_polls, calls) = ReadyFailThenSucceedService::new(1);
        let mut retry_svc = Retry::new(svc, policy);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = retry_svc.call(OneShotRequest(7));
        let result = Pin::new(&mut future).poll(&mut cx);

        crate::assert_with_log!(
            matches!(result, Poll::Ready(Ok(21))),
            "poll_ready failure retries with original one-shot request",
            "Poll::Ready(Ok(21))",
            result
        );

        let ready_poll_count = ready_polls.load(Ordering::SeqCst);
        crate::assert_with_log!(
            ready_poll_count == 2,
            "service polled ready twice",
            2usize,
            ready_poll_count
        );

        let call_count = calls.load(Ordering::SeqCst);
        crate::assert_with_log!(
            call_count == 1,
            "request was not duplicated across readiness retry",
            1usize,
            call_count
        );

        crate::test_complete!("retry_reuses_original_request_after_poll_ready_error");
    }

    // =========================================================================
    // Wave 30: Data-type trait coverage
    // =========================================================================

    #[test]
    fn retry_layer_debug() {
        let layer = RetryLayer::new(LimitedRetry::<i32>::new(3));
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("RetryLayer"));
    }

    #[test]
    fn retry_layer_clone() {
        let layer = RetryLayer::new(LimitedRetry::<i32>::new(3));
        let cloned = layer;
        assert_eq!(cloned.policy().max_retries(), 3);
    }

    #[test]
    fn retry_layer_policy_accessor() {
        let layer = RetryLayer::new(LimitedRetry::<i32>::new(5));
        assert_eq!(layer.policy().max_retries(), 5);
        assert_eq!(layer.policy().current_attempt(), 0);
    }

    #[test]
    fn retry_service_debug_clone() {
        let svc = Retry::new(42_i32, LimitedRetry::<i32>::new(3));
        let dbg = format!("{svc:?}");
        assert!(dbg.contains("Retry"));
        let cloned = svc;
        assert_eq!(*cloned.inner(), 42);
    }

    #[test]
    fn retry_service_accessors() {
        let mut svc = Retry::new(42_i32, LimitedRetry::<i32>::new(3));
        assert_eq!(*svc.inner(), 42);
        assert_eq!(svc.policy().max_retries(), 3);
        *svc.inner_mut() = 99;
        assert_eq!(*svc.inner(), 99);
        let inner = svc.into_inner();
        assert_eq!(inner, 99);
    }

    #[test]
    fn limited_retry_debug_clone_copy() {
        let policy = LimitedRetry::<i32>::new(5);
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("LimitedRetry"));
        assert!(dbg.contains('5'));
        let cloned = policy;
        let copied = policy; // Copy
        assert_eq!(cloned.max_retries(), copied.max_retries());
    }

    #[test]
    fn no_retry_debug_clone_copy_default() {
        let policy = NoRetry::new();
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("NoRetry"));
        let cloned = policy; // Copy
        assert_eq!(format!("{cloned:?}"), format!("{policy:?}"));
        let default = NoRetry;
        let _ = format!("{default:?}");
    }

    #[test]
    fn retry_future_debug() {
        let (svc, _) = FailingService::new(0);
        let policy = LimitedRetry::<i32>::new(1);
        let future = RetryFuture::new(svc, policy, 42);
        let dbg = format!("{future:?}");
        assert!(dbg.contains("RetryFuture"));
    }

    #[test]
    fn retry_error_display_and_source() {
        let inner = RetryError::Inner(std::io::Error::other("boom"));
        assert!(format!("{inner}").contains("boom"));
        assert!(std::error::Error::source(&inner).is_some());

        let done: RetryError<std::io::Error> = RetryError::PolledAfterCompletion;
        assert_eq!(format!("{done}"), "retry future polled after completion");
        assert!(std::error::Error::source(&done).is_none());
        assert!(format!("{done:?}").contains("PolledAfterCompletion"));
    }

    #[test]
    fn retry_future_second_poll_fails_closed() {
        init_test("retry_future_second_poll_fails_closed");
        let policy = NoRetry::new();
        let (svc, _) = FailingService::new(0);
        let mut retry_svc = Retry::new(svc, policy);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = retry_svc.poll_ready(&mut cx);
        let mut future = retry_svc.call(21);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(42))),
            "first poll returns success",
            "Poll::Ready(Ok(42))",
            first
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(RetryError::PolledAfterCompletion))),
            "second poll fails closed",
            "Poll::Ready(Err(RetryError::PolledAfterCompletion))",
            second
        );
        crate::test_complete!("retry_future_second_poll_fails_closed");
    }

    #[test]
    fn retry_exhausts_and_returns_error() {
        init_test("retry_exhausts_and_returns_error");
        let policy = LimitedRetry::<i32>::new(2);
        let (svc, calls) = FailingService::new(10); // Always fail
        let mut retry_svc = Retry::new(svc, policy);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = retry_svc.poll_ready(&mut cx);
        let mut future = retry_svc.call(21);

        loop {
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(result) => {
                    let err = matches!(result, Err(RetryError::Inner("service error")));
                    crate::assert_with_log!(err, "result err", true, err);
                    break;
                }
                Poll::Pending => {}
            }
        }

        // Should have called 3 times (initial + 2 retries)
        let count = calls.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 3, "call count", 3, count);
        crate::test_complete!("retry_exhausts_and_returns_error");
    }

    #[test]
    fn retry_yields_after_budget_on_immediate_retry_loop() {
        init_test("retry_yields_after_budget_on_immediate_retry_loop");
        let policy = LimitedRetry::<i32>::new(RETRY_COOPERATIVE_BUDGET);
        let (svc, calls) = FailingService::new(RETRY_COOPERATIVE_BUDGET + 1);
        let mut retry_svc = Retry::new(svc, policy);
        let woke = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(woke.clone())));
        let mut cx = Context::from_waker(&waker);

        let _ = retry_svc.poll_ready(&mut cx);
        let mut future = retry_svc.call(21);

        let first = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first poll yields after cooperative budget",
            "Poll::Pending",
            first
        );
        let first_calls = calls.load(Ordering::SeqCst);
        crate::assert_with_log!(
            first_calls == RETRY_COOPERATIVE_BUDGET,
            "retry attempts capped at cooperative budget",
            RETRY_COOPERATIVE_BUDGET,
            first_calls
        );
        let was_woken = woke.load(Ordering::SeqCst);
        crate::assert_with_log!(
            was_woken,
            "self-wake requested after budget exhaustion",
            true,
            was_woken
        );

        let second = Pin::new(&mut future).poll(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(RetryError::Inner("service error")))),
            "second poll resumes and returns the terminal error",
            "Poll::Ready(Err(RetryError::Inner(\"service error\")))",
            second
        );
        let total_calls = calls.load(Ordering::SeqCst);
        crate::assert_with_log!(
            total_calls == RETRY_COOPERATIVE_BUDGET + 1,
            "remaining retry completes on second poll",
            RETRY_COOPERATIVE_BUDGET + 1,
            total_calls
        );
        crate::test_complete!("retry_yields_after_budget_on_immediate_retry_loop");
    }

    #[test]
    fn metamorphic_retry_first_poll_work_is_monotone_under_longer_failure_chains() {
        init_test("metamorphic_retry_first_poll_work_is_monotone_under_longer_failure_chains");

        fn first_poll_snapshot(failures_before_success: usize) -> (bool, usize, bool) {
            let policy = LimitedRetry::<i32>::new(failures_before_success);
            let (svc, calls) = FailingService::new(failures_before_success);
            let mut retry_svc = Retry::new(svc, policy);
            let woke = Arc::new(AtomicBool::new(false));
            let waker = Waker::from(Arc::new(TrackWaker(Arc::clone(&woke))));
            let mut cx = Context::from_waker(&waker);

            let _ = retry_svc.poll_ready(&mut cx);
            let mut future = retry_svc.call(21);
            let first = Pin::new(&mut future).poll(&mut cx);

            (
                matches!(first, Poll::Pending),
                calls.load(Ordering::SeqCst),
                woke.load(Ordering::SeqCst),
            )
        }

        let budget_plus_one = first_poll_snapshot(RETRY_COOPERATIVE_BUDGET + 1);
        let much_longer = first_poll_snapshot(RETRY_COOPERATIVE_BUDGET * 2 + 17);

        crate::assert_with_log!(
            budget_plus_one.0 && much_longer.0,
            "both over-budget chains must yield on first poll",
            true,
            budget_plus_one.0 && much_longer.0
        );
        crate::assert_with_log!(
            budget_plus_one.1 == RETRY_COOPERATIVE_BUDGET
                && much_longer.1 == RETRY_COOPERATIVE_BUDGET,
            "first poll work stays capped at cooperative budget for longer chains",
            RETRY_COOPERATIVE_BUDGET,
            (budget_plus_one.1, much_longer.1)
        );
        crate::assert_with_log!(
            budget_plus_one.2 && much_longer.2,
            "both over-budget chains request a self-wake after budget exhaustion",
            true,
            budget_plus_one.2 && much_longer.2
        );

        crate::test_complete!(
            "metamorphic_retry_first_poll_work_is_monotone_under_longer_failure_chains"
        );
    }

    #[test]
    fn poll_ready_does_not_strand_concurrency_limit_reservations() {
        init_test("poll_ready_does_not_strand_concurrency_limit_reservations");
        let inner = ConcurrencyLimitLayer::new(1).layer(FailingService::new(0).0);
        let mut retry_svc = Retry::new(inner, NoRetry::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = retry_svc.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "retry poll_ready ok", true, ready_ok);

        let available_after_ready = retry_svc.inner().available();
        crate::assert_with_log!(
            available_after_ready == 1,
            "available permits after outer poll_ready",
            1,
            available_after_ready
        );

        let mut future = retry_svc.call(21);
        let result = Pin::new(&mut future).poll(&mut cx);
        let call_ok = matches!(result, Poll::Ready(Ok(42)));
        crate::assert_with_log!(
            call_ok,
            "retry-wrapped concurrency-limited call completes",
            true,
            call_ok
        );

        let available_after_call = retry_svc.inner().available();
        crate::assert_with_log!(
            available_after_call == 1,
            "available permits after call completion",
            1,
            available_after_call
        );
        crate::test_complete!("poll_ready_does_not_strand_concurrency_limit_reservations");
    }

    // =========================================================================
    // Conformance: Jitter Algorithm Golden Tests
    // =========================================================================

    /// Golden test for full jitter distribution
    #[test]
    fn golden_full_jitter_distribution() {
        init_test("golden_full_jitter_distribution");

        // Use deterministic entropy to ensure reproducible results
        let mut delays = Vec::new();

        // Generate delays for first 5 attempts
        for attempt in 0..5 {
            let policy = ExponentialBackoff::<i32> {
                max_retries: 10,
                current_attempt: attempt,
                base_delay_ms: 100,
                max_delay_ms: 30_000,
                jitter: JitterStrategy::Full,
                last_delay_ms: 100,
                _marker: PhantomData,
            };

            let delay = policy.calculate_delay();
            delays.push((attempt, delay));
        }

        // Golden values (deterministic due to DetEntropy)
        let expected = vec![
            (0, 93),  // random(0, 100)
            (1, 124), // random(0, 200)
            (2, 344), // random(0, 400)
            (3, 372), // random(0, 800)
            (4, 822), // random(0, 1600)
        ];

        for ((attempt, delay), (exp_attempt, exp_delay)) in delays.iter().zip(expected.iter()) {
            crate::assert_with_log!(
                attempt == exp_attempt && delay == exp_delay,
                format!("full jitter attempt {}", attempt),
                *exp_delay,
                *delay
            );
        }

        crate::test_complete!("golden_full_jitter_distribution");
    }

    /// Golden test for equal jitter distribution
    #[test]
    fn golden_equal_jitter_distribution() {
        init_test("golden_equal_jitter_distribution");

        let mut delays = Vec::new();

        for attempt in 0..5 {
            let policy = ExponentialBackoff::<i32> {
                max_retries: 10,
                current_attempt: attempt,
                base_delay_ms: 100,
                max_delay_ms: 30_000,
                jitter: JitterStrategy::Equal,
                last_delay_ms: 100,
                _marker: PhantomData,
            };

            let delay = policy.calculate_delay();
            delays.push((attempt, delay));
        }

        // Golden values: base/2 + random(0, base/2) where base = 100 * 2^attempt
        let expected = vec![
            (0, 96),   // 50 + random(0, 50) = 50 + 46 = 96
            (1, 162),  // 100 + random(0, 100) = 100 + 62 = 162
            (2, 372),  // 200 + random(0, 200) = 200 + 172 = 372
            (3, 586),  // 400 + random(0, 400) = 400 + 186 = 586
            (4, 1211), // 800 + random(0, 800) = 800 + 411 = 1211
        ];

        for ((attempt, delay), (exp_attempt, exp_delay)) in delays.iter().zip(expected.iter()) {
            crate::assert_with_log!(
                attempt == exp_attempt && delay == exp_delay,
                format!("equal jitter attempt {}", attempt),
                *exp_delay,
                *delay
            );
        }

        crate::test_complete!("golden_equal_jitter_distribution");
    }

    /// Golden test for decorrelated jitter distribution
    #[test]
    fn golden_decorrelated_jitter_distribution() {
        init_test("golden_decorrelated_jitter_distribution");

        let mut delays = Vec::new();
        let mut policy = ExponentialBackoff::<i32> {
            max_retries: 10,
            current_attempt: 0,
            base_delay_ms: 100,
            max_delay_ms: 30_000,
            jitter: JitterStrategy::Decorrelated,
            last_delay_ms: 100,
            _marker: PhantomData,
        };

        // Generate sequence where each delay affects the next
        for attempt in 0..5 {
            policy.current_attempt = attempt;
            let delay = policy.calculate_delay();
            delays.push((attempt, delay));
            policy.last_delay_ms = delay.max(1); // Update for next iteration
        }

        // Golden values: random(base_delay, last_delay * 3)
        let expected = vec![
            (0, 186),  // random(100, 300) = 186
            (1, 390),  // random(100, 558) = 390
            (2, 571),  // random(100, 1170) = 571
            (3, 857),  // random(100, 1713) = 857
            (4, 1186), // random(100, 2571) = 1186
        ];

        for ((attempt, delay), (exp_attempt, exp_delay)) in delays.iter().zip(expected.iter()) {
            crate::assert_with_log!(
                attempt == exp_attempt && delay == exp_delay,
                format!("decorrelated jitter attempt {}", attempt),
                *exp_delay,
                *delay
            );
        }

        crate::test_complete!("golden_decorrelated_jitter_distribution");
    }

    /// Golden test verifying max_retries is enforced exactly
    #[test]
    fn golden_max_retries_enforcement() {
        init_test("golden_max_retries_enforcement");

        let mut policy = ExponentialBackoff::<i32>::new(3, 100, JitterStrategy::Full);
        let mut retry_results = Vec::new();

        // Simulate retry attempts
        for attempt in 0..6 {
            let request = 42;
            let error_result: Result<&i32, &&str> = Err(&"error");
            let retry_future = policy.retry(&request, error_result);

            let should_retry = retry_future.is_some();
            retry_results.push((attempt, should_retry));

            if should_retry {
                policy.current_attempt += 1;
            }
        }

        // Golden values: should retry for attempts 0, 1, 2 (max_retries=3), then stop
        let expected = vec![
            (0, true),  // First retry (attempt 0 → 1)
            (1, true),  // Second retry (attempt 1 → 2)
            (2, true),  // Third retry (attempt 2 → 3)
            (3, false), // Fourth attempt - should not retry (3 >= max_retries)
            (4, false), // Fifth attempt - should not retry
            (5, false), // Sixth attempt - should not retry
        ];

        for ((attempt, should_retry), (exp_attempt, exp_should_retry)) in
            retry_results.iter().zip(expected.iter())
        {
            crate::assert_with_log!(
                attempt == exp_attempt && should_retry == exp_should_retry,
                format!("max retries attempt {}", attempt),
                *exp_should_retry,
                *should_retry
            );
        }

        crate::test_complete!("golden_max_retries_enforcement");
    }

    /// Golden test for idempotent vs non-idempotent request classification
    #[test]
    fn golden_request_classification() {
        init_test("golden_request_classification");

        let idempotent_policy = SmartRetry::<i32>::new(
            3,
            100,
            JitterStrategy::Full,
            RequestClassification::Idempotent,
        );
        let non_idempotent_policy = SmartRetry::<i32>::new(
            3,
            100,
            JitterStrategy::Full,
            RequestClassification::NonIdempotent,
        );

        // Test classification properties
        let mut results = Vec::new();

        // Non-idempotent retries fail closed unless the caller can prove the
        // error is transport-only.
        let error_result: Result<&i32, &&str> = Err(&"error");
        let success_result: Result<&i32, &&str> = Ok(&42);

        results.push((
            "idempotent_error",
            idempotent_policy.retry(&42, error_result).is_some(),
        ));
        results.push((
            "idempotent_success",
            idempotent_policy.retry(&42, success_result).is_some(),
        ));
        results.push((
            "non_idempotent_error",
            non_idempotent_policy.retry(&42, error_result).is_some(),
        ));
        results.push((
            "non_idempotent_success",
            non_idempotent_policy.retry(&42, success_result).is_some(),
        ));

        // Golden values
        let expected = vec![
            ("idempotent_error", true),        // Should retry on error
            ("idempotent_success", false),     // Should not retry on success
            ("non_idempotent_error", false),   // Should fail closed on error
            ("non_idempotent_success", false), // Should not retry on success
        ];

        for ((name, result), (exp_name, exp_result)) in results.iter().zip(expected.iter()) {
            crate::assert_with_log!(
                name == exp_name && result == exp_result,
                format!("classification {}", name),
                *exp_result,
                *result
            );
        }

        crate::test_complete!("golden_request_classification");
    }

    /// Golden test for jitter strategy behavior differences
    #[test]
    fn golden_jitter_strategy_comparison() {
        init_test("golden_jitter_strategy_comparison");

        // Compare delay distributions for same attempt across strategies
        let attempt = 3;
        let base_delay = 100;

        let full_policy = ExponentialBackoff::<i32> {
            max_retries: 10,
            current_attempt: attempt,
            base_delay_ms: base_delay,
            max_delay_ms: 30_000,
            jitter: JitterStrategy::Full,
            last_delay_ms: 800, // Previous delay for decorrelated
            _marker: PhantomData,
        };

        let equal_policy = ExponentialBackoff::<i32> {
            max_retries: 10,
            current_attempt: attempt,
            base_delay_ms: base_delay,
            max_delay_ms: 30_000,
            jitter: JitterStrategy::Equal,
            last_delay_ms: 800,
            _marker: PhantomData,
        };

        let decorrelated_policy = ExponentialBackoff::<i32> {
            max_retries: 10,
            current_attempt: attempt,
            base_delay_ms: base_delay,
            max_delay_ms: 30_000,
            jitter: JitterStrategy::Decorrelated,
            last_delay_ms: 800,
            _marker: PhantomData,
        };

        let full_delay = full_policy.calculate_delay();
        let equal_delay = equal_policy.calculate_delay();
        let decorrelated_delay = decorrelated_policy.calculate_delay();

        // Golden values for attempt 3 with base_delay 100
        let expected_full = 372; // random(0, 800)
        let expected_equal = 586; // 400 + random(0, 400)
        let expected_decorrelated = 1356; // random(100, 2400)

        crate::assert_with_log!(
            full_delay == expected_full,
            "full jitter delay",
            expected_full,
            full_delay
        );

        crate::assert_with_log!(
            equal_delay == expected_equal,
            "equal jitter delay",
            expected_equal,
            equal_delay
        );

        crate::assert_with_log!(
            decorrelated_delay == expected_decorrelated,
            "decorrelated jitter delay",
            expected_decorrelated,
            decorrelated_delay
        );

        crate::test_complete!("golden_jitter_strategy_comparison");
    }

    #[test]
    fn smart_retry_non_idempotent_errors_fail_closed() {
        init_test("smart_retry_non_idempotent_errors_fail_closed");

        let policy = SmartRetry::<i32>::new(
            3,
            10,
            JitterStrategy::None,
            RequestClassification::NonIdempotent,
        );

        let error_result: Result<&i32, &&str> = Err(&"transient");
        crate::assert_with_log!(
            policy.retry(&42, error_result).is_none(),
            "non-idempotent errors are not retried",
            true,
            false
        );

        crate::test_complete!("smart_retry_non_idempotent_errors_fail_closed");
    }

    #[test]
    fn exponential_backoff_future_waits_before_retrying() {
        init_test("exponential_backoff_future_waits_before_retrying");

        let policy = ExponentialBackoff::<i32>::new(3, 10, JitterStrategy::None);
        let error_result: Result<&i32, &&str> = Err(&"transient");
        let mut future = policy
            .retry(&7, error_result)
            .expect("retry should be scheduled");

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        crate::assert_with_log!(
            matches!(future.as_mut().poll(&mut cx), Poll::Pending),
            "backoff delay yields pending before timer fires",
            true,
            false
        );

        std::thread::sleep(Duration::from_millis(25));

        let next_policy = match future.as_mut().poll(&mut cx) {
            Poll::Ready(policy) => policy,
            Poll::Pending => panic!("retry backoff should complete after the delay"),
        };

        crate::assert_with_log!(
            next_policy.current_attempt() == 1,
            "retry advances after delay",
            1usize,
            next_policy.current_attempt()
        );

        crate::test_complete!("exponential_backoff_future_waits_before_retrying");
    }

    #[test]
    fn exponential_backoff_uses_ambient_timer_driver() {
        init_test("exponential_backoff_uses_ambient_timer_driver");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let policy = ExponentialBackoff::<i32>::new(3, 10, JitterStrategy::None);
        let error_result: Result<&i32, &&str> = Err(&"transient");
        let mut future = policy
            .retry(&7, error_result)
            .expect("retry should be scheduled");

        let waker = std::task::Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        crate::assert_with_log!(
            matches!(future.as_mut().poll(&mut poll_cx), Poll::Pending),
            "virtual timer starts pending",
            true,
            false
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "retry delay registered with ambient timer",
            1usize,
            timer.pending_count()
        );

        clock.advance(Duration::from_millis(10).as_nanos() as u64);

        let next_policy = match future.as_mut().poll(&mut poll_cx) {
            Poll::Ready(policy) => policy,
            Poll::Pending => panic!("retry delay should complete after virtual time advance"),
        };

        crate::assert_with_log!(
            next_policy.current_attempt() == 1,
            "retry completes after virtual advance",
            1usize,
            next_policy.current_attempt()
        );
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "retry delay clears timer registration",
            0usize,
            timer.pending_count()
        );

        crate::test_complete!("exponential_backoff_uses_ambient_timer_driver");
    }
}
