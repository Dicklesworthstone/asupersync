//! Retry middleware layer.
//!
//! The [`RetryLayer`] wraps a service to automatically retry failed requests
//! according to a configurable [`Policy`].

use super::{Layer, Service};
use crate::cx::Cx;
use crate::time::{Sleep, wall_now};
use crate::util::{DetEntropy, DetRng};
use std::cell::Cell;
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

const DEFAULT_RETRY_ROOT_ID: u64 = u64::from_le_bytes(*b"retry.v1");
const RETRY_LAYER_CLONE_DOMAIN: u64 = u64::from_le_bytes(*b"retry.lc");
const RETRY_LAYER_SERVICE_DOMAIN: u64 = u64::from_le_bytes(*b"retry.ls");
const RETRY_SERVICE_CLONE_DOMAIN: u64 = u64::from_le_bytes(*b"retry.sc");
const RETRY_REQUEST_DOMAIN: u64 = u64::from_le_bytes(*b"retry.rq");
const RETRY_JITTER_DOMAIN: u64 = u64::from_le_bytes(*b"retry.jt");
const RETRY_LINEAGE_STEP: u64 = 0x9e37_79b9_7f4a_7c15;

/// Samples uniformly from the inclusive range without modulo bias.
///
/// Degenerate ranges deliberately consume no entropy, matching the historical
/// retry-policy behavior. The full `u64` domain needs its own branch because
/// its cardinality (`2^64`) is not representable as a `u64`.
fn sample_inclusive(rng: &mut DetRng, lower: u64, upper: u64) -> u64 {
    debug_assert!(lower <= upper);

    if lower == upper {
        return lower;
    }
    if lower == 0 && upper == u64::MAX {
        return rng.next_u64();
    }

    let span = upper - lower + 1;
    let reject_below = span.wrapping_neg() % span;
    loop {
        let word = rng.next_u64();
        if word >= reject_below {
            return lower + word % span;
        }
    }
}

fn derive_retry_lineage(parent: u64, domain: u64, ordinal: u64) -> u64 {
    let ordinal = DetEntropy::mix_seed(ordinal.wrapping_add(RETRY_LINEAGE_STEP));
    DetEntropy::mix_seed(DetEntropy::mix_seed(parent ^ domain) ^ ordinal)
}

fn allocate_retry_lineage(parent: u64, domain: u64, next_ordinal: &Cell<u64>) -> u64 {
    let ordinal = next_ordinal.get();
    let following_ordinal = ordinal
        .checked_add(1)
        .expect("retry lineage ordinal overflow");
    next_ordinal.set(following_ordinal);
    derive_retry_lineage(parent, domain, ordinal)
}

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

    /// Forks this policy for one logical request stream.
    ///
    /// The default preserves existing policy behavior. Policies with
    /// deterministic entropy should override this hook so sibling requests do
    /// not replay the same pseudo-random sequence.
    fn fork_for_request(&self, _stream_id: u64) -> Self {
        self.clone()
    }
}

/// A layer that retries requests according to a policy.
///
/// Cloning forks a new deterministic lineage and advances the source layer's
/// clone counter. The interior counter makes a layer `Send` when its policy is
/// `Send`, but deliberately not `Sync`; share separately constructed layers or
/// clones instead of cloning one layer concurrently.
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
#[derive(Debug)]
pub struct RetryLayer<P> {
    policy: P,
    root_id: u64,
    next_clone_ordinal: Cell<u64>,
    next_service_ordinal: Cell<u64>,
}

impl<P> RetryLayer<P> {
    /// Creates a new retry layer with the given policy.
    #[must_use]
    pub const fn new(policy: P) -> Self {
        Self {
            policy,
            root_id: DEFAULT_RETRY_ROOT_ID,
            next_clone_ordinal: Cell::new(0),
            next_service_ordinal: Cell::new(0),
        }
    }

    /// Returns a reference to the policy.
    #[must_use]
    pub const fn policy(&self) -> &P {
        &self.policy
    }

    /// Sets the deterministic lineage root for this layer.
    ///
    /// Independently constructed retry trees should use distinct roots. Reuse
    /// the same root only when deterministic replay of the same construction
    /// and call topology is desired.
    #[must_use]
    pub fn with_root_id(mut self, root_id: u64) -> Self {
        self.root_id = root_id;
        self.next_clone_ordinal.set(0);
        self.next_service_ordinal.set(0);
        self
    }
}

impl<P: Clone> Clone for RetryLayer<P> {
    fn clone(&self) -> Self {
        let root_id = allocate_retry_lineage(
            self.root_id,
            RETRY_LAYER_CLONE_DOMAIN,
            &self.next_clone_ordinal,
        );
        Self {
            policy: self.policy.clone(),
            root_id,
            next_clone_ordinal: Cell::new(0),
            next_service_ordinal: Cell::new(0),
        }
    }
}

impl<S, P: Clone> Layer<S> for RetryLayer<P> {
    type Service = Retry<P, S>;

    fn layer(&self, inner: S) -> Self::Service {
        let root_id = allocate_retry_lineage(
            self.root_id,
            RETRY_LAYER_SERVICE_DOMAIN,
            &self.next_service_ordinal,
        );
        Retry::new(inner, self.policy.clone()).with_root_id(root_id)
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
///
/// Cloning forks a new deterministic lineage and advances the source service's
/// clone counter. The interior counter makes a retry service `Send` when its
/// fields are `Send`, but deliberately not `Sync`; each clone owns independent
/// request and descendant-clone counters.
#[derive(Debug)]
pub struct Retry<P, S> {
    policy: P,
    inner: S,
    root_id: u64,
    next_clone_ordinal: Cell<u64>,
    next_request_ordinal: Cell<u64>,
}

impl<P, S> Retry<P, S> {
    /// Creates a new retry service.
    #[must_use]
    pub const fn new(inner: S, policy: P) -> Self {
        Self {
            policy,
            inner,
            root_id: DEFAULT_RETRY_ROOT_ID,
            next_clone_ordinal: Cell::new(0),
            next_request_ordinal: Cell::new(0),
        }
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

    /// Sets the deterministic lineage root for this retry service.
    ///
    /// Independently constructed retry services should use distinct roots.
    /// Reusing a root reproduces streams only when clone and call topology is
    /// also reproduced.
    #[must_use]
    pub fn with_root_id(mut self, root_id: u64) -> Self {
        self.root_id = root_id;
        self.next_clone_ordinal.set(0);
        self.next_request_ordinal.set(0);
        self
    }

    /// Consumes the retry service, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<P: Clone, S: Clone> Clone for Retry<P, S> {
    fn clone(&self) -> Self {
        let root_id = allocate_retry_lineage(
            self.root_id,
            RETRY_SERVICE_CLONE_DOMAIN,
            &self.next_clone_ordinal,
        );
        Self {
            policy: self.policy.clone(),
            inner: self.inner.clone(),
            root_id,
            next_clone_ordinal: Cell::new(0),
            next_request_ordinal: Cell::new(0),
        }
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
        let stream_id = allocate_retry_lineage(
            self.root_id,
            RETRY_REQUEST_DOMAIN,
            &self.next_request_ordinal,
        );
        RetryFuture::new(
            self.inner.clone(),
            self.policy.fork_for_request(stream_id),
            req,
        )
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
        service: super::service::ReadinessService<S, Request>,
        policy: P,
        request: Option<Request>,
    },
    /// Calling the inner service.
    Calling {
        service: super::service::ReadinessService<S, Request>,
        policy: P,
        request: Option<Request>,
        future: S::Future,
    },
    /// Waiting for retry policy decision.
    Checking {
        service: super::service::ReadinessService<S, Request>,
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
                service: super::service::ReadinessService::new(service),
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
                            // A cancelled task starts no further attempt, as
                            // Hedge starts no backup: a backoff Sleep completes
                            // at once once the task is cancelled, so retrying
                            // would turn the cancellation into a burst of
                            // calls. The last attempt's result is returned.
                            if crate::cx::Cx::current()
                                .is_some_and(|current| current.is_cancel_requested())
                            {
                                let result = result.take().expect("result should exist");
                                this.state = RetryState::Done;
                                return Poll::Ready(result.map_err(RetryError::Inner));
                            }
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
pub struct ExponentialBackoff<Request> {
    max_retries: usize,
    current_attempt: usize,
    base_delay_ms: u64,
    max_delay_ms: u64,
    jitter: JitterStrategy,
    last_delay_ms: u64,
    jitter_seed: u64,
    jitter_rng: DetRng,
    _marker: PhantomData<fn(Request) -> Request>,
}

impl<Request> Clone for ExponentialBackoff<Request> {
    fn clone(&self) -> Self {
        Self {
            max_retries: self.max_retries,
            current_attempt: self.current_attempt,
            base_delay_ms: self.base_delay_ms,
            max_delay_ms: self.max_delay_ms,
            jitter: self.jitter,
            last_delay_ms: self.last_delay_ms,
            jitter_seed: self.jitter_seed,
            jitter_rng: self.jitter_rng.clone(),
            _marker: PhantomData,
        }
    }
}

impl<Request> fmt::Debug for ExponentialBackoff<Request> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExponentialBackoff")
            .field("max_retries", &self.max_retries)
            .field("current_attempt", &self.current_attempt)
            .field("base_delay_ms", &self.base_delay_ms)
            .field("max_delay_ms", &self.max_delay_ms)
            .field("jitter", &self.jitter)
            .field("last_delay_ms", &self.last_delay_ms)
            .field("jitter_seed", &"<redacted>")
            .field("jitter_rng", &"<redacted>")
            .finish()
    }
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
            jitter_seed: 42,
            jitter_rng: DetRng::new(42),
            _marker: PhantomData,
        }
    }

    /// Sets the maximum delay in milliseconds.
    #[must_use]
    pub fn with_max_delay(mut self, max_delay_ms: u64) -> Self {
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// Sets the deterministic seed used to derive per-request jitter streams.
    #[must_use]
    pub fn with_jitter_seed(mut self, jitter_seed: u64) -> Self {
        self.jitter_seed = jitter_seed;
        self.jitter_rng = DetRng::new(jitter_seed);
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
    fn calculate_delay(&mut self) -> u64 {
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
                sample_inclusive(&mut self.jitter_rng, 0, max_delay)
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
                let jitter = sample_inclusive(&mut self.jitter_rng, 0, half_delay);
                half_delay + jitter
            }
            JitterStrategy::Decorrelated => {
                // Decorrelated jitter: random(base_delay, last_delay * 3)
                let min_delay = self.base_delay_ms.min(self.max_delay_ms);
                let max_delay = self
                    .last_delay_ms
                    .saturating_mul(3)
                    .min(self.max_delay_ms)
                    .max(min_delay);
                sample_inclusive(&mut self.jitter_rng, min_delay, max_delay)
            }
        }
    }

    fn advance_for_retry(&self) -> (u64, Self) {
        // Advance entropy only in the returned policy. Calling retry() remains
        // observationally pure; dropped retry futures cannot perturb the
        // source policy's request-local stream.
        let mut next_policy = self.clone();
        let delay_ms = next_policy.calculate_delay();
        next_policy.current_attempt += 1;
        next_policy.last_delay_ms = delay_ms.max(1); // Ensure non-zero for decorrelated
        (delay_ms, next_policy)
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

        let (delay_ms, new_policy) = self.advance_for_retry();

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

    fn fork_for_request(&self, stream_id: u64) -> Self {
        let jitter_seed = derive_retry_lineage(self.jitter_seed, RETRY_JITTER_DOMAIN, stream_id);
        let mut policy = self.clone();
        policy.jitter_seed = jitter_seed;
        policy.jitter_rng = DetRng::new(jitter_seed);
        policy
    }
}

/// Request classification for idempotency handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestClassification {
    /// Safe to retry on any error (GET, HEAD, OPTIONS, etc.)
    Idempotent,
    /// Never retried (POST, PUT, etc.): the policy cannot tell a network
    /// error from an application error, so it fails closed rather than
    /// replay a side effect.
    NonIdempotent,
}

/// Smart retry policy that considers request idempotency.
///
/// Idempotent requests (GET, HEAD) can be retried on any error.
/// Non-idempotent requests (POST, PUT) are not retried.
pub struct SmartRetry<Request> {
    backoff: ExponentialBackoff<Request>,
    classification: RequestClassification,
}

impl<Request> fmt::Debug for SmartRetry<Request> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmartRetry")
            .field("backoff", &self.backoff)
            .field("classification", &self.classification)
            .finish()
    }
}

impl<Request> Clone for SmartRetry<Request> {
    fn clone(&self) -> Self {
        Self {
            backoff: self.backoff.clone(),
            classification: self.classification,
        }
    }
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

    /// Sets the deterministic seed used for per-request jitter streams.
    #[must_use]
    pub fn with_jitter_seed(mut self, jitter_seed: u64) -> Self {
        self.backoff = self.backoff.with_jitter_seed(jitter_seed);
        self
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

    fn fork_for_request(&self, stream_id: u64) -> Self {
        Self {
            backoff: <ExponentialBackoff<Request> as Policy<Request, Res, E>>::fork_for_request(
                &self.backoff,
                stream_id,
            ),
            classification: self.classification,
        }
    }
}

#[cfg(test)]
#[path = "retry_inline_tests.rs"]
mod tests;
