//! Circuit breaker middleware layer.
//!
//! The [`CircuitBreakerLayer`] wraps a service with the runtime's shared
//! circuit-breaker state machine. Rejected calls fail immediately, while
//! admitted calls record success or failure when the inner future resolves.

use super::{Layer, Service};
use crate::combinator::circuit_breaker::{
    CircuitBreaker as InnerCircuitBreaker, CircuitBreakerError as InnerCircuitBreakerError,
    CircuitBreakerMetrics, CircuitBreakerPolicy, Permit, State,
};
use crate::types::Time;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// How a completed inner call should be recorded against the breaker.
///
/// Returned by a [`ResultClassifier`]. Configurable failure classification
/// (bead eeexl1.7 AC4) hinges on this: a transport-successful response can still
/// be a breaker *failure* (e.g. an HTTP 5xx returned as `Ok(Response)`), and
/// some completed calls should be *ignored* entirely (e.g. a caller-driven
/// `Cancelled`, or an HTTP 4xx client error that does not mean the upstream is
/// unhealthy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Count as a success (advances a half-open circuit toward closing).
    Success,
    /// Count as a failure (advances the circuit toward opening).
    Failure,
    /// Neither — release the permit without affecting open/close transitions.
    Ignore,
}

/// Classifies a completed inner-service result into a breaker [`Disposition`].
///
/// The default ([`DefaultClassifier`]) preserves the simplest behaviour: `Ok`
/// is a success and `Err` is a failure (errors are then further filtered by the
/// breaker policy's `FailurePredicate`). Supply a custom classifier — e.g. via
/// [`FnClassifier`] — to count successful-looking responses as failures or to
/// ignore specific outcomes.
pub trait ResultClassifier<Res, Err> {
    /// Classify a completed inner result.
    fn classify(&self, result: &Result<Res, Err>) -> Disposition;
}

/// The default classifier.
///
/// `Ok` => [`Disposition::Success`], `Err` => [`Disposition::Failure`].
/// Reproduces the breaker's original behaviour, where error filtering is
/// delegated to the policy's `FailurePredicate`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultClassifier;

impl<Res, Err> ResultClassifier<Res, Err> for DefaultClassifier {
    fn classify(&self, result: &Result<Res, Err>) -> Disposition {
        match result {
            Ok(_) => Disposition::Success,
            Err(_) => Disposition::Failure,
        }
    }
}

/// A [`ResultClassifier`] backed by a function or closure.
///
/// The function is the determinism-friendly extension point (mirroring the
/// breaker policy's function-pointer `FailurePredicate`): pass a plain `fn`
/// pointer for fully deterministic, replayable classification — for example,
/// the canonical HTTP policy "5xx counts, 4xx does not, cancellation ignored":
///
/// ```ignore
/// FnClassifier(|r: &Result<Resp, Err>| match r {
///     Ok(resp) if resp.status() >= 500 => Disposition::Failure, // 5xx counts
///     Ok(resp) if resp.status() >= 400 => Disposition::Ignore,  // 4xx neither
///     Ok(_) => Disposition::Success,                            // 2xx success
///     Err(e) if e.is_cancelled() => Disposition::Ignore,        // cancel ignored
///     Err(_) => Disposition::Failure,
/// })
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FnClassifier<F>(pub F);

impl<Res, Err, F> ResultClassifier<Res, Err> for FnClassifier<F>
where
    F: Fn(&Result<Res, Err>) -> Disposition,
{
    fn classify(&self, result: &Result<Res, Err>) -> Disposition {
        (self.0)(result)
    }
}

/// A layer that applies circuit-breaker protection to requests.
///
/// Each service this layer builds gets its own breaker, which clones of that
/// service share. To track one endpoint's health across separately built
/// services, build them around one breaker with
/// [`CircuitBreaker::from_shared`] or
/// [`CircuitBreaker::from_shared_with_classifier`].
#[derive(Debug, Clone)]
pub struct CircuitBreakerLayer<C = DefaultClassifier> {
    policy: CircuitBreakerPolicy,
    time_getter: fn() -> Time,
    classifier: C,
}

impl CircuitBreakerLayer {
    /// Creates a new circuit-breaker layer with the given policy and the
    /// [`DefaultClassifier`] (`Ok` => success, `Err` => failure).
    #[must_use]
    pub fn new(policy: CircuitBreakerPolicy) -> Self {
        Self {
            policy,
            time_getter: wall_clock_now,
            classifier: DefaultClassifier,
        }
    }

    /// Creates a new circuit-breaker layer with a custom time source and the
    /// [`DefaultClassifier`].
    #[must_use]
    pub fn with_time_getter(policy: CircuitBreakerPolicy, time_getter: fn() -> Time) -> Self {
        Self {
            policy,
            time_getter,
            classifier: DefaultClassifier,
        }
    }
}

impl<C> CircuitBreakerLayer<C> {
    /// Creates a layer with a custom failure classifier (bead eeexl1.7 AC4).
    #[must_use]
    pub fn with_classifier(policy: CircuitBreakerPolicy, classifier: C) -> Self {
        Self {
            policy,
            time_getter: wall_clock_now,
            classifier,
        }
    }

    /// Creates a layer with a custom failure classifier and time source.
    #[must_use]
    pub fn with_classifier_and_time(
        policy: CircuitBreakerPolicy,
        classifier: C,
        time_getter: fn() -> Time,
    ) -> Self {
        Self {
            policy,
            time_getter,
            classifier,
        }
    }

    /// Returns the policy used by this layer.
    #[must_use]
    pub const fn policy(&self) -> &CircuitBreakerPolicy {
        &self.policy
    }

    /// Returns the time source used by this layer.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }
}

impl<S, C: Clone> Layer<S> for CircuitBreakerLayer<C> {
    type Service = CircuitBreaker<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        CircuitBreaker::from_parts(
            inner,
            self.policy.clone(),
            self.time_getter,
            self.classifier.clone(),
        )
    }
}

/// Service wrapper that rejects calls while its circuit is open.
#[derive(Debug)]
pub struct CircuitBreaker<S, C = DefaultClassifier> {
    inner: S,
    breaker: Arc<InnerCircuitBreaker>,
    time_getter: fn() -> Time,
    ready_observed: bool,
    classifier: C,
}

impl<S: Clone, C: Clone> Clone for CircuitBreaker<S, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            breaker: self.breaker.clone(),
            time_getter: self.time_getter,
            ready_observed: false,
            classifier: self.classifier.clone(),
        }
    }
}

impl<S> CircuitBreaker<S> {
    /// Creates a new circuit-breaker service with the [`DefaultClassifier`].
    #[must_use]
    pub fn new(inner: S, policy: CircuitBreakerPolicy) -> Self {
        Self::with_time_getter(inner, policy, wall_clock_now)
    }

    /// Creates a new circuit-breaker service with a custom time source and the
    /// [`DefaultClassifier`].
    #[must_use]
    pub fn with_time_getter(
        inner: S,
        policy: CircuitBreakerPolicy,
        time_getter: fn() -> Time,
    ) -> Self {
        Self::from_shared(
            inner,
            Arc::new(InnerCircuitBreaker::new(policy)),
            time_getter,
        )
    }

    /// Creates a new service wrapper sharing an existing breaker, with the
    /// [`DefaultClassifier`].
    #[must_use]
    pub fn from_shared(
        inner: S,
        breaker: Arc<InnerCircuitBreaker>,
        time_getter: fn() -> Time,
    ) -> Self {
        Self::from_shared_with_classifier(inner, breaker, time_getter, DefaultClassifier)
    }
}

impl<S, C> CircuitBreaker<S, C> {
    /// Creates a circuit-breaker service with a custom failure classifier
    /// (bead eeexl1.7 AC4).
    #[must_use]
    pub fn with_classifier(inner: S, policy: CircuitBreakerPolicy, classifier: C) -> Self {
        Self::from_parts(inner, policy, wall_clock_now, classifier)
    }

    /// Creates a circuit-breaker service with a custom classifier and time
    /// source.
    #[must_use]
    pub fn with_classifier_and_time(
        inner: S,
        policy: CircuitBreakerPolicy,
        time_getter: fn() -> Time,
        classifier: C,
    ) -> Self {
        Self::from_parts(inner, policy, time_getter, classifier)
    }

    /// Builds a service from a policy, time source, and classifier.
    #[must_use]
    pub fn from_parts(
        inner: S,
        policy: CircuitBreakerPolicy,
        time_getter: fn() -> Time,
        classifier: C,
    ) -> Self {
        Self::from_shared_with_classifier(
            inner,
            Arc::new(InnerCircuitBreaker::new(policy)),
            time_getter,
            classifier,
        )
    }

    /// Builds a service sharing an existing breaker, with a custom classifier.
    #[must_use]
    pub fn from_shared_with_classifier(
        inner: S,
        breaker: Arc<InnerCircuitBreaker>,
        time_getter: fn() -> Time,
        classifier: C,
    ) -> Self {
        Self {
            inner,
            breaker,
            time_getter,
            ready_observed: false,
            classifier,
        }
    }

    /// Returns the shared breaker.
    #[must_use]
    pub fn breaker(&self) -> &InnerCircuitBreaker {
        &self.breaker
    }

    /// Clones the shared breaker handle.
    #[must_use]
    pub fn shared_breaker(&self) -> Arc<InnerCircuitBreaker> {
        self.breaker.clone()
    }

    /// Returns the current breaker state.
    #[must_use]
    pub fn state(&self) -> State {
        self.breaker.state()
    }

    /// Returns current breaker metrics.
    #[must_use]
    pub fn metrics(&self) -> CircuitBreakerMetrics {
        self.breaker.metrics()
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

    /// Consumes the wrapper, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Error returned by the circuit-breaker middleware.
#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    /// The caller attempted `call()` without a preceding successful `poll_ready()`.
    NotReady,
    /// The future was polled after it had already completed.
    PolledAfterCompletion,
    /// The circuit is open and rejecting calls.
    Open {
        /// Time remaining until a half-open probe may be attempted.
        remaining: std::time::Duration,
    },
    /// The circuit is half-open and already has its maximum active probes.
    HalfOpenFull,
    /// The inner service returned an error.
    Inner(E),
}

impl<E> CircuitBreakerError<E> {
    /// Returns true when the breaker rejected a call before it reached the
    /// inner service.
    #[must_use]
    pub const fn is_rejected(&self) -> bool {
        matches!(self, Self::Open { .. } | Self::HalfOpenFull)
    }

    /// Returns true when the circuit is open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        matches!(self, Self::Open { .. })
    }

    /// Returns true when the circuit is half-open and has no probe slots left.
    #[must_use]
    pub const fn is_half_open_full(&self) -> bool {
        matches!(self, Self::HalfOpenFull)
    }

    /// Returns true when the inner service returned the error.
    #[must_use]
    pub const fn is_inner(&self) -> bool {
        matches!(self, Self::Inner(_))
    }
}

impl<E: fmt::Display> fmt::Display for CircuitBreakerError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady => write!(f, "poll_ready required before call"),
            Self::PolledAfterCompletion => {
                write!(f, "circuit breaker future polled after completion")
            }
            Self::Open { remaining } => write!(f, "circuit open, retry after {remaining:?}"),
            Self::HalfOpenFull => write!(f, "circuit half-open, max probes active"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CircuitBreakerError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(e) => Some(e),
            Self::NotReady
            | Self::PolledAfterCompletion
            | Self::Open { .. }
            | Self::HalfOpenFull => None,
        }
    }
}

impl<S, C, Request> Service<Request> for CircuitBreaker<S, C>
where
    S: Service<Request>,
    S::Error: fmt::Display,
    S::Future: Unpin,
    C: ResultClassifier<S::Response, S::Error> + Clone + Unpin,
{
    type Response = S::Response;
    type Error = CircuitBreakerError<S::Error>;
    type Future = CircuitBreakerFuture<S::Future, C>;

    fn release_readiness(&mut self) -> super::ReadinessRelease {
        self.ready_observed = false;
        self.inner.release_readiness()
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                self.ready_observed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                self.ready_observed = false;
                Poll::Ready(Err(CircuitBreakerError::Inner(err)))
            }
            Poll::Pending => {
                self.ready_observed = false;
                Poll::Pending
            }
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if !std::mem::replace(&mut self.ready_observed, false) {
            return CircuitBreakerFuture::not_ready();
        }

        let permit = match self.breaker.should_allow((self.time_getter)()) {
            Ok(permit) => permit,
            Err(InnerCircuitBreakerError::Open { remaining }) => {
                drop(self.inner.release_readiness());
                return CircuitBreakerFuture::open(remaining);
            }
            Err(InnerCircuitBreakerError::HalfOpenFull) => {
                drop(self.inner.release_readiness());
                return CircuitBreakerFuture::half_open_full();
            }
            Err(InnerCircuitBreakerError::Inner(())) => unreachable!(),
        };

        let guard = PermitGuard::new(
            self.breaker.clone(),
            permit,
            self.time_getter,
            "service future dropped before completion",
        );
        let future = self.inner.call(req);
        CircuitBreakerFuture::running(future, guard, self.classifier.clone())
    }
}

/// Future returned by [`CircuitBreaker`] service.
#[derive(Debug)]
pub struct CircuitBreakerFuture<F, C = DefaultClassifier> {
    state: CircuitBreakerFutureState<F, C>,
}

#[derive(Debug)]
enum CircuitBreakerFutureState<F, C> {
    NotReady,
    Open {
        remaining: std::time::Duration,
    },
    HalfOpenFull,
    Running {
        inner: F,
        guard: PermitGuard,
        classifier: C,
    },
    Done,
}

impl<F, C> CircuitBreakerFuture<F, C> {
    /// Creates a future that immediately returns a readiness misuse error.
    #[must_use]
    pub const fn not_ready() -> Self {
        Self {
            state: CircuitBreakerFutureState::NotReady,
        }
    }

    /// Creates a future that immediately returns an open-circuit error.
    #[must_use]
    pub const fn open(remaining: std::time::Duration) -> Self {
        Self {
            state: CircuitBreakerFutureState::Open { remaining },
        }
    }

    /// Creates a future that immediately returns a half-open saturation error.
    #[must_use]
    pub const fn half_open_full() -> Self {
        Self {
            state: CircuitBreakerFutureState::HalfOpenFull,
        }
    }

    fn running(inner: F, guard: PermitGuard, classifier: C) -> Self {
        Self {
            state: CircuitBreakerFutureState::Running {
                inner,
                guard,
                classifier,
            },
        }
    }
}

impl<F, C, Response, Error> Future for CircuitBreakerFuture<F, C>
where
    F: Future<Output = Result<Response, Error>> + Unpin,
    Error: fmt::Display,
    C: ResultClassifier<Response, Error> + Unpin,
{
    type Output = Result<Response, CircuitBreakerError<Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let state = std::mem::replace(&mut this.state, CircuitBreakerFutureState::Done);

        match state {
            CircuitBreakerFutureState::NotReady => Poll::Ready(Err(CircuitBreakerError::NotReady)),
            CircuitBreakerFutureState::Open { remaining } => {
                Poll::Ready(Err(CircuitBreakerError::Open { remaining }))
            }
            CircuitBreakerFutureState::HalfOpenFull => {
                Poll::Ready(Err(CircuitBreakerError::HalfOpenFull))
            }
            CircuitBreakerFutureState::Running {
                mut inner,
                guard,
                classifier,
            } => match Pin::new(&mut inner).poll(cx) {
                Poll::Pending => {
                    this.state = CircuitBreakerFutureState::Running {
                        inner,
                        guard,
                        classifier,
                    };
                    Poll::Pending
                }
                Poll::Ready(output) => {
                    // The classifier — not just Ok/Err — decides how a completed
                    // call is recorded (bead eeexl1.7 AC4): a successful-looking
                    // response can be a failure (5xx), and some outcomes are
                    // neither (4xx, cancellation).
                    match classifier.classify(&output) {
                        Disposition::Success => guard.record_success(),
                        Disposition::Ignore => guard.record_ignored(),
                        Disposition::Failure => match &output {
                            Ok(_) => {
                                guard.record_failure_with(
                                    "circuit breaker classified response as failure",
                                );
                            }
                            Err(error) => guard.record_failure_with(&error.to_string()),
                        },
                    }
                    match output {
                        Ok(response) => Poll::Ready(Ok(response)),
                        Err(error) => Poll::Ready(Err(CircuitBreakerError::Inner(error))),
                    }
                }
            },
            CircuitBreakerFutureState::Done => {
                Poll::Ready(Err(CircuitBreakerError::PolledAfterCompletion))
            }
        }
    }
}

#[derive(Debug)]
struct PermitGuard {
    breaker: Arc<InnerCircuitBreaker>,
    permit: Option<Permit>,
    time_getter: fn() -> Time,
    drop_error: &'static str,
}

impl PermitGuard {
    fn new(
        breaker: Arc<InnerCircuitBreaker>,
        permit: Permit,
        time_getter: fn() -> Time,
        drop_error: &'static str,
    ) -> Self {
        Self {
            breaker,
            permit: Some(permit),
            time_getter,
            drop_error,
        }
    }

    fn record_success(mut self) {
        if let Some(permit) = self.permit.take() {
            self.breaker.record_success(permit, (self.time_getter)());
        }
    }

    fn record_failure_with(mut self, error: &str) {
        if let Some(permit) = self.permit.take() {
            self.breaker
                .record_failure(permit, error, (self.time_getter)());
        }
    }

    fn record_ignored(mut self) {
        if let Some(permit) = self.permit.take() {
            self.breaker.record_ignored(permit);
        }
    }
}

impl Drop for PermitGuard {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            self.breaker
                .record_failure(permit, self.drop_error, (self.time_getter)());
        }
    }
}

#[cfg(test)]
#[path = "circuit_breaker_inline_tests.rs"]
mod tests;
