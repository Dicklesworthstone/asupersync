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

/// A layer that applies circuit-breaker protection to requests.
///
/// Cloned services share one breaker instance so endpoint health is tracked
/// across all handles produced from this layer.
#[derive(Debug, Clone)]
pub struct CircuitBreakerLayer {
    policy: CircuitBreakerPolicy,
    time_getter: fn() -> Time,
}

impl CircuitBreakerLayer {
    /// Creates a new circuit-breaker layer with the given policy.
    #[must_use]
    pub fn new(policy: CircuitBreakerPolicy) -> Self {
        Self {
            policy,
            time_getter: wall_clock_now,
        }
    }

    /// Creates a new circuit-breaker layer with a custom time source.
    #[must_use]
    pub fn with_time_getter(policy: CircuitBreakerPolicy, time_getter: fn() -> Time) -> Self {
        Self {
            policy,
            time_getter,
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

impl<S> Layer<S> for CircuitBreakerLayer {
    type Service = CircuitBreaker<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CircuitBreaker::with_time_getter(inner, self.policy.clone(), self.time_getter)
    }
}

/// Service wrapper that rejects calls while its circuit is open.
#[derive(Debug)]
pub struct CircuitBreaker<S> {
    inner: S,
    breaker: Arc<InnerCircuitBreaker>,
    time_getter: fn() -> Time,
    ready_observed: bool,
}

impl<S: Clone> Clone for CircuitBreaker<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            breaker: self.breaker.clone(),
            time_getter: self.time_getter,
            ready_observed: false,
        }
    }
}

impl<S> CircuitBreaker<S> {
    /// Creates a new circuit-breaker service.
    #[must_use]
    pub fn new(inner: S, policy: CircuitBreakerPolicy) -> Self {
        Self::with_time_getter(inner, policy, wall_clock_now)
    }

    /// Creates a new circuit-breaker service with a custom time source.
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

    /// Creates a new service wrapper sharing an existing breaker.
    #[must_use]
    pub fn from_shared(
        inner: S,
        breaker: Arc<InnerCircuitBreaker>,
        time_getter: fn() -> Time,
    ) -> Self {
        Self {
            inner,
            breaker,
            time_getter,
            ready_observed: false,
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

impl<S, Request> Service<Request> for CircuitBreaker<S>
where
    S: Service<Request>,
    S::Error: fmt::Display,
    S::Future: Unpin,
{
    type Response = S::Response;
    type Error = CircuitBreakerError<S::Error>;
    type Future = CircuitBreakerFuture<S::Future>;

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
                return CircuitBreakerFuture::open(remaining);
            }
            Err(InnerCircuitBreakerError::HalfOpenFull) => {
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
        CircuitBreakerFuture::running(future, guard)
    }
}

/// Future returned by [`CircuitBreaker`] service.
#[derive(Debug)]
pub struct CircuitBreakerFuture<F> {
    state: CircuitBreakerFutureState<F>,
}

#[derive(Debug)]
enum CircuitBreakerFutureState<F> {
    NotReady,
    Open { remaining: std::time::Duration },
    HalfOpenFull,
    Running { inner: F, guard: PermitGuard },
    Done,
}

impl<F> CircuitBreakerFuture<F> {
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

    fn running(inner: F, guard: PermitGuard) -> Self {
        Self {
            state: CircuitBreakerFutureState::Running { inner, guard },
        }
    }
}

impl<F, Response, Error> Future for CircuitBreakerFuture<F>
where
    F: Future<Output = Result<Response, Error>> + Unpin,
    Error: fmt::Display,
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
            CircuitBreakerFutureState::Running { mut inner, guard } => {
                match Pin::new(&mut inner).poll(cx) {
                    Poll::Pending => {
                        this.state = CircuitBreakerFutureState::Running { inner, guard };
                        Poll::Pending
                    }
                    Poll::Ready(Ok(response)) => {
                        guard.record_success();
                        Poll::Ready(Ok(response))
                    }
                    Poll::Ready(Err(error)) => {
                        guard.record_failure(&error);
                        Poll::Ready(Err(CircuitBreakerError::Inner(error)))
                    }
                }
            }
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

    fn record_failure<E: fmt::Display>(mut self, error: &E) {
        if let Some(permit) = self.permit.take() {
            self.breaker
                .record_failure(permit, &error.to_string(), (self.time_getter)());
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]

    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::task::Waker;
    use std::time::Duration;

    std::thread_local! {
        static TEST_NOW_MS: Cell<u64> = const { Cell::new(0) };
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
        set_test_time_ms(0);
    }

    fn test_time() -> Time {
        Time::from_millis(TEST_NOW_MS.with(Cell::get))
    }

    fn set_test_time_ms(ms: u64) {
        TEST_NOW_MS.with(|now| now.set(ms));
    }

    fn noop_waker() -> Waker {
        Waker::noop().clone()
    }

    fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(future).poll(&mut cx)
    }

    fn test_policy() -> CircuitBreakerPolicy {
        CircuitBreakerPolicy {
            name: "test-endpoint".to_string(),
            failure_threshold: 2,
            success_threshold: 1,
            open_duration: Duration::from_millis(10),
            half_open_max_probes: 1,
            ..CircuitBreakerPolicy::default()
        }
    }

    #[derive(Clone, Debug)]
    enum Step {
        Ok(&'static str),
        Err(&'static str),
        Pending,
    }

    #[derive(Debug)]
    struct ScriptedService {
        steps: VecDeque<Step>,
        calls: usize,
    }

    impl ScriptedService {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                calls: 0,
            }
        }

        const fn calls(&self) -> usize {
            self.calls
        }
    }

    impl Service<()> for ScriptedService {
        type Response = &'static str;
        type Error = &'static str;
        type Future = ScriptedFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            self.calls = self.calls.saturating_add(1);
            match self.steps.pop_front().expect("scripted service exhausted") {
                Step::Ok(value) => ScriptedFuture::ready(Ok(value)),
                Step::Err(error) => ScriptedFuture::ready(Err(error)),
                Step::Pending => ScriptedFuture::pending(),
            }
        }
    }

    #[derive(Debug)]
    struct ScriptedFuture {
        result: Option<Result<&'static str, &'static str>>,
        pending: bool,
    }

    impl ScriptedFuture {
        const fn ready(result: Result<&'static str, &'static str>) -> Self {
            Self {
                result: Some(result),
                pending: false,
            }
        }

        const fn pending() -> Self {
            Self {
                result: None,
                pending: true,
            }
        }
    }

    impl Future for ScriptedFuture {
        type Output = Result<&'static str, &'static str>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.pending {
                Poll::Pending
            } else {
                Poll::Ready(self.result.take().expect("future polled after completion"))
            }
        }
    }

    #[test]
    fn failure_burst_opens_rejects_half_open_and_recovers() {
        init_test("failure_burst_opens_rejects_half_open_and_recovers");
        let mut service = CircuitBreaker::with_time_getter(
            ScriptedService::new([Step::Err("e1"), Step::Err("e2"), Step::Ok("recovered")]),
            test_policy(),
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first_ready = service.poll_ready(&mut cx);
        let first_ready_ok = matches!(first_ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(first_ready_ok, "first ready", true, first_ready_ok);
        let mut first = service.call(());
        let first_result = poll_once(&mut first);
        let first_error = matches!(
            first_result,
            Poll::Ready(Err(CircuitBreakerError::Inner("e1")))
        );
        crate::assert_with_log!(first_error, "first error", true, first_error);
        crate::assert_with_log!(
            service.state() == (State::Closed { failures: 1 }),
            "one failure recorded",
            State::Closed { failures: 1 },
            service.state()
        );

        let second_ready = service.poll_ready(&mut cx);
        let second_ready_ok = matches!(second_ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(second_ready_ok, "second ready", true, second_ready_ok);
        let mut second = service.call(());
        let second_result = poll_once(&mut second);
        let second_error = matches!(
            second_result,
            Poll::Ready(Err(CircuitBreakerError::Inner("e2")))
        );
        crate::assert_with_log!(second_error, "second error", true, second_error);
        let breaker_open = matches!(service.state(), State::Open { .. });
        crate::assert_with_log!(breaker_open, "breaker open", true, breaker_open);

        let calls_after_open = service.inner().calls();
        let open_ready = service.poll_ready(&mut cx);
        let open_ready_ok = matches!(open_ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(open_ready_ok, "open ready delegates", true, open_ready_ok);
        let mut rejected = service.call(());
        let rejected_result = poll_once(&mut rejected);
        let rejected_open = matches!(
            rejected_result,
            Poll::Ready(Err(CircuitBreakerError::Open { .. }))
        );
        crate::assert_with_log!(rejected_open, "open rejection", true, rejected_open);
        crate::assert_with_log!(
            service.inner().calls() == calls_after_open,
            "open rejection did not call inner",
            calls_after_open,
            service.inner().calls()
        );

        set_test_time_ms(11);
        let probe_ready = service.poll_ready(&mut cx);
        let probe_ready_ok = matches!(probe_ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(probe_ready_ok, "probe ready", true, probe_ready_ok);
        let mut probe = service.call(());
        let probe_result = poll_once(&mut probe);
        let probe_recovered = matches!(probe_result, Poll::Ready(Ok("recovered")));
        crate::assert_with_log!(probe_recovered, "probe recovered", true, probe_recovered);
        crate::assert_with_log!(
            service.state() == (State::Closed { failures: 0 }),
            "breaker closed",
            State::Closed { failures: 0 },
            service.state()
        );
        let metrics = service.metrics();
        crate::assert_with_log!(
            metrics.times_opened == 1,
            "opened once",
            1,
            metrics.times_opened
        );
        crate::assert_with_log!(
            metrics.times_closed == 1,
            "closed once",
            1,
            metrics.times_closed
        );
        crate::test_complete!("failure_burst_opens_rejects_half_open_and_recovers");
    }

    #[test]
    fn call_without_poll_ready_fails_closed() {
        init_test("call_without_poll_ready_fails_closed");
        let mut service = CircuitBreaker::with_time_getter(
            ScriptedService::new([Step::Ok("unused")]),
            test_policy(),
            test_time,
        );

        let mut future = service.call(());
        let result = poll_once(&mut future);
        let not_ready = matches!(result, Poll::Ready(Err(CircuitBreakerError::NotReady)));
        crate::assert_with_log!(not_ready, "not ready", true, not_ready);
        crate::assert_with_log!(
            service.inner().calls() == 0,
            "inner not called",
            0,
            service.inner().calls()
        );
        crate::test_complete!("call_without_poll_ready_fails_closed");
    }

    #[test]
    fn dropped_half_open_probe_reopens_without_stranding_probe() {
        init_test("dropped_half_open_probe_reopens_without_stranding_probe");
        let policy = CircuitBreakerPolicy {
            failure_threshold: 1,
            success_threshold: 1,
            open_duration: Duration::from_millis(10),
            half_open_max_probes: 1,
            ..test_policy()
        };
        let mut service = CircuitBreaker::with_time_getter(
            ScriptedService::new([Step::Err("open"), Step::Pending, Step::Ok("later")]),
            policy,
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = service.poll_ready(&mut cx);
        let mut opener = service.call(());
        let _ = poll_once(&mut opener);
        let opened = matches!(service.state(), State::Open { .. });
        crate::assert_with_log!(opened, "opened", true, opened);

        set_test_time_ms(11);
        let _ = service.poll_ready(&mut cx);
        let mut pending_probe = service.call(());
        let probe_poll = poll_once(&mut pending_probe);
        let probe_pending = probe_poll.is_pending();
        crate::assert_with_log!(probe_pending, "probe pending", true, probe_pending);
        let probe_active = matches!(
            service.state(),
            State::HalfOpen {
                probes_active: 1,
                ..
            }
        );
        crate::assert_with_log!(probe_active, "probe active", true, probe_active);

        drop(pending_probe);
        let reopened = matches!(service.state(), State::Open { .. });
        crate::assert_with_log!(reopened, "drop reopens", true, reopened);

        let _ = service.poll_ready(&mut cx);
        let mut rejected = service.call(());
        let rejected_result = poll_once(&mut rejected);
        let rejected_open = matches!(
            rejected_result,
            Poll::Ready(Err(CircuitBreakerError::Open { .. }))
        );
        crate::assert_with_log!(
            rejected_open,
            "rejected after dropped probe",
            true,
            rejected_open
        );
        crate::test_complete!("dropped_half_open_probe_reopens_without_stranding_probe");
    }
}
