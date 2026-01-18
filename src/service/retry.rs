//! Retry middleware layer.
//!
//! The [`RetryLayer`] wraps a service to automatically retry failed requests
//! according to a configurable [`Policy`].

use super::{Layer, Service};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

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
    type Error = S::Error;
    type Future = RetryFuture<P, S, Request>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
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
    type Output = Result<S::Response, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            let state = std::mem::replace(&mut this.state, RetryState::Done);

            match state {
                RetryState::PollReady {
                    mut service,
                    policy,
                    mut request,
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
                            this.state = RetryState::Done;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            let req = request.take().expect("request already taken");
                            
                            // Try to clone the request for potential retry
                            let backup = policy.clone_request(&req);
                            
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
                        let retry_decision = if let Some(req_ref) = request.as_ref() {
                            match &result {
                                Ok(res) => policy.retry(req_ref, Ok(res)),
                                Err(e) => policy.retry(req_ref, Err(e)),
                            }
                        } else {
                            None
                        };

                        match retry_decision {
                            None => {
                                // No retry - return the result
                                this.state = RetryState::Done;
                                return Poll::Ready(result);
                            }
                            Some(retry_future) => {
                                this.state = RetryState::Checking {
                                    service,
                                    request,
                                    result: Some(result),
                                    retry_future,
                                };
                            }
                        }
                    }
                },
                RetryState::Checking {
                    service,
                    request,
                    mut result,
                    mut retry_future,
                } => {
                    match Pin::new(&mut retry_future).poll(cx) {
                        Poll::Pending => {
                            this.state = RetryState::Checking {
                                service,
                                request,
                                result,
                                retry_future,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(new_policy) => {
                            // Try to clone the request for retry
                            let req_ref = request.as_ref().expect("request should exist");
                            match new_policy.clone_request(req_ref) {
                                Some(new_request) => {
                                    this.state = RetryState::PollReady {
                                        service,
                                        policy: new_policy,
                                        request: Some(new_request),
                                    };
                                }
                                None => {
                                    // Cannot clone request - return original result
                                    let result = result.take().expect("result should exist");
                                    this.state = RetryState::Done;
                                    return Poll::Ready(result);
                                }
                            }
                        }
                    }
                }
                RetryState::Done => {
                    panic!("RetryFuture polled after completion");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
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

    #[test]
    fn layer_creates_service() {
        let policy = LimitedRetry::<i32>::new(3);
        let layer = RetryLayer::new(policy);
        let (svc, _) = FailingService::new(0);
        let _retry_svc: Retry<_, FailingService> = layer.layer(svc);
    }

    #[test]
    fn limited_retry_policy_basics() {
        let policy = LimitedRetry::<i32>::new(3);
        assert_eq!(policy.max_retries(), 3);
        assert_eq!(policy.current_attempt(), 0);
    }

    #[test]
    fn limited_retry_clones_request() {
        let policy = LimitedRetry::<i32>::new(3);
        // Specify generic types for Policy trait: Request=i32, Res=(), E=()
        let cloned = Policy::<i32, (), ()>::clone_request(&policy, &42);
        assert_eq!(cloned, Some(42));
    }

    #[test]
    fn limited_retry_returns_none_on_success() {
        let policy = LimitedRetry::<i32>::new(3);
        let result: Option<_> = policy.retry(&42, Ok::<&i32, &String>(&100));
        assert!(result.is_none());
    }

    #[test]
    fn limited_retry_returns_some_on_error() {
        let policy = LimitedRetry::<i32>::new(3);
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        assert!(result.is_some());
    }

    #[test]
    fn limited_retry_exhausts_retries() {
        let mut policy = LimitedRetry::<i32>::new(2);

        // First retry
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        assert!(result.is_some());
        policy.current_attempt = 1;

        // Second retry
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        assert!(result.is_some());
        policy.current_attempt = 2;

        // Third attempt - should fail (max_retries reached)
        let result: Option<_> = policy.retry(&42, Err::<&i32, &&str>(&"error"));
        assert!(result.is_none());
    }

    #[test]
    fn no_retry_policy() {
        let policy = NoRetry::new();
        let result: Option<std::future::Pending<NoRetry>> =
            Policy::<i32, (), &str>::retry(&policy, &42, Err(&"error"));
        assert!(result.is_none());

        let cloned: Option<i32> = Policy::<i32, (), ()>::clone_request(&policy, &42);
        assert!(cloned.is_none());
    }

    #[test]
    fn retry_succeeds_after_failures() {
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
                    assert!(matches!(result, Ok(42)));
                    break;
                }
                Poll::Pending => continue,
            }
        }

        // Should have called the service 3 times (2 failures + 1 success)
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn retry_exhausts_and_returns_error() {
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
                    assert!(matches!(result, Err("service error")));
                    break;
                }
                Poll::Pending => continue,
            }
        }

        // Should have called 3 times (initial + 2 retries)
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
