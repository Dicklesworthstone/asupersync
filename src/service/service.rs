//! Service trait and utility combinators.

use crate::cx::Cx;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A composable async service.
///
/// Services are request/response handlers that can be composed with middleware
/// layers. The `poll_ready` method lets a service apply backpressure before
/// accepting work.
pub trait Service<Request> {
    /// Response type produced by this service.
    type Response;
    /// Error type produced by this service.
    type Error;
    /// Future returned by [`Service::call`].
    type Future: Future<Output = Result<Self::Response, Self::Error>>;

    /// Polls readiness to accept a request.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;

    /// Dispatches a request to the service.
    fn call(&mut self, req: Request) -> Self::Future;
}

/// Extension trait providing convenience adapters for services.
pub trait ServiceExt<Request>: Service<Request> {
    /// Waits until the service is ready to accept a request.
    fn ready(&mut self) -> Ready<'_, Self, Request>
    where
        Self: Sized,
    {
        Ready::new(self)
    }

    /// Executes a single request on this service.
    ///
    /// # Note
    ///
    /// This adapter requires `Self` and `Request` to be `Unpin` so we can safely
    /// move the service and request through the internal state machine without
    /// unsafe code.
    fn oneshot(self, req: Request) -> Oneshot<Self, Request>
    where
        Self: Sized + Unpin,
        Request: Unpin,
        Self::Future: Unpin,
    {
        Oneshot::new(self, req)
    }
}

impl<T, Request> ServiceExt<Request> for T where T: Service<Request> + ?Sized {}

/// A service that executes within an Asupersync [`Cx`].
///
/// Unlike [`Service`], this trait is async-native and does not expose readiness
/// polling. Callers supply a `Cx` so cancellation, budgets, and capabilities
/// are explicitly threaded through the call.
#[allow(async_fn_in_trait)]
pub trait AsupersyncService<Request>: Send + Sync {
    /// Response type returned by the service.
    type Response;
    /// Error type returned by the service.
    type Error;

    /// Dispatches a request within the given context.
    async fn call(&self, cx: &Cx, request: Request) -> Result<Self::Response, Self::Error>;
}

/// Extension helpers for [`AsupersyncService`].
pub trait AsupersyncServiceExt<Request>: AsupersyncService<Request> {
    /// Map the response type.
    fn map_response<F, NewResponse>(self, f: F) -> MapResponse<Self, F>
    where
        Self: Sized,
        F: Fn(Self::Response) -> NewResponse + Send + Sync,
    {
        MapResponse::new(self, f)
    }

    /// Map the error type.
    fn map_err<F, NewError>(self, f: F) -> MapErr<Self, F>
    where
        Self: Sized,
        F: Fn(Self::Error) -> NewError + Send + Sync,
    {
        MapErr::new(self, f)
    }

    /// Convert this service into a Tower-compatible adapter.
    #[cfg(feature = "tower")]
    fn into_tower(self) -> TowerAdapter<Self>
    where
        Self: Sized,
    {
        TowerAdapter::new(self)
    }
}

impl<T, Request> AsupersyncServiceExt<Request> for T where T: AsupersyncService<Request> + ?Sized {}

/// Adapter that maps the response type of an [`AsupersyncService`].
pub struct MapResponse<S, F> {
    service: S,
    map: F,
}

impl<S, F> MapResponse<S, F> {
    fn new(service: S, map: F) -> Self {
        Self { service, map }
    }
}

impl<S, F, Request, NewResponse> AsupersyncService<Request> for MapResponse<S, F>
where
    S: AsupersyncService<Request>,
    F: Fn(S::Response) -> NewResponse + Send + Sync,
{
    type Response = NewResponse;
    type Error = S::Error;

    async fn call(&self, cx: &Cx, request: Request) -> Result<Self::Response, Self::Error> {
        let response = self.service.call(cx, request).await?;
        Ok((self.map)(response))
    }
}

/// Adapter that maps the error type of an [`AsupersyncService`].
pub struct MapErr<S, F> {
    service: S,
    map: F,
}

impl<S, F> MapErr<S, F> {
    fn new(service: S, map: F) -> Self {
        Self { service, map }
    }
}

impl<S, F, Request, NewError> AsupersyncService<Request> for MapErr<S, F>
where
    S: AsupersyncService<Request>,
    F: Fn(S::Error) -> NewError + Send + Sync,
{
    type Response = S::Response;
    type Error = NewError;

    async fn call(&self, cx: &Cx, request: Request) -> Result<Self::Response, Self::Error> {
        self.service.call(cx, request).await.map_err(&self.map)
    }
}

/// Blanket implementation for async functions and closures.
impl<F, Fut, Request, Response, Error> AsupersyncService<Request> for F
where
    F: Fn(&Cx, Request) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Response, Error>> + Send,
{
    type Response = Response;
    type Error = Error;

    async fn call(&self, cx: &Cx, request: Request) -> Result<Self::Response, Self::Error> {
        (self)(cx, request).await
    }
}

// =============================================================================
// Tower Adapter Types
// =============================================================================

/// How to handle Tower services that don't support cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CancellationMode {
    /// Best effort: set cancelled flag, but operation may complete.
    #[default]
    BestEffort,

    /// Strict: fail if service doesn't respect cancellation.
    Strict,

    /// Timeout: cancel via timeout if Cx cancelled.
    TimeoutFallback,
}

/// Configuration for Tower service adaptation.
#[derive(Debug, Clone)]
pub struct AdapterConfig {
    /// How to handle Tower services that ignore cancellation.
    pub cancellation_mode: CancellationMode,

    /// Timeout for non-cancellable operations.
    pub fallback_timeout: Option<std::time::Duration>,

    /// Minimum budget required to wait for service readiness.
    /// If budget is below this, fail fast with overload error.
    pub min_budget_for_wait: u64,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            cancellation_mode: CancellationMode::BestEffort,
            fallback_timeout: None,
            min_budget_for_wait: 10,
        }
    }
}

impl AdapterConfig {
    /// Create a new adapter config with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the cancellation mode.
    #[must_use]
    pub fn cancellation_mode(mut self, mode: CancellationMode) -> Self {
        self.cancellation_mode = mode;
        self
    }

    /// Set the fallback timeout.
    #[must_use]
    pub fn fallback_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.fallback_timeout = Some(timeout);
        self
    }

    /// Set the minimum budget required to wait for service readiness.
    #[must_use]
    pub fn min_budget_for_wait(mut self, budget: u64) -> Self {
        self.min_budget_for_wait = budget;
        self
    }
}

/// Trait for mapping between Tower and Asupersync error types.
pub trait ErrorAdapter: Send + Sync {
    /// The Tower error type.
    type TowerError;
    /// The Asupersync error type.
    type AsupersyncError;

    /// Convert a Tower error to an Asupersync error.
    fn to_asupersync(&self, err: Self::TowerError) -> Self::AsupersyncError;

    /// Convert an Asupersync error to a Tower error.
    fn to_tower(&self, err: Self::AsupersyncError) -> Self::TowerError;
}

/// Default error adapter that converts errors using Into.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultErrorAdapter<E> {
    _marker: PhantomData<E>,
}

impl<E> DefaultErrorAdapter<E> {
    /// Create a new default error adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<E> ErrorAdapter for DefaultErrorAdapter<E>
where
    E: Clone + Send + Sync,
{
    type TowerError = E;
    type AsupersyncError = E;

    fn to_asupersync(&self, err: Self::TowerError) -> Self::AsupersyncError {
        err
    }

    fn to_tower(&self, err: Self::AsupersyncError) -> Self::TowerError {
        err
    }
}

/// Error type for Tower adapter failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TowerAdapterError<E> {
    /// The inner service returned an error.
    Service(E),
    /// The operation was cancelled.
    Cancelled,
    /// The operation timed out.
    Timeout,
    /// The service is overloaded and budget is too low.
    Overloaded,
    /// Strict mode: service didn't respect cancellation.
    CancellationIgnored,
}

impl<E: std::fmt::Display> std::fmt::Display for TowerAdapterError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Service(e) => write!(f, "service error: {e}"),
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::Timeout => write!(f, "operation timed out"),
            Self::Overloaded => write!(f, "service overloaded, insufficient budget"),
            Self::CancellationIgnored => {
                write!(f, "service ignored cancellation request (strict mode)")
            }
        }
    }
}

impl<E: std::fmt::Display + std::fmt::Debug> std::error::Error for TowerAdapterError<E> {}

#[cfg(feature = "tower")]
pub struct TowerAdapter<S> {
    service: std::sync::Arc<S>,
}

#[cfg(feature = "tower")]
impl<S> TowerAdapter<S> {
    fn new(service: S) -> Self {
        Self {
            service: std::sync::Arc::new(service),
        }
    }
}

#[cfg(feature = "tower")]
impl<S, Request> tower::Service<(Cx, Request)> for TowerAdapter<S>
where
    S: AsupersyncService<Request> + Send + Sync + 'static,
    Request: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, (cx, request): (Cx, Request)) -> Self::Future {
        let service = std::sync::Arc::clone(&self.service);
        Box::pin(async move { service.call(&cx, request).await })
    }
}

/// Adapter that wraps a Tower service for use with Asupersync.
///
/// This adapter bridges Tower-style services to the Asupersync service model,
/// providing graceful degradation when Tower services don't support asupersync
/// features like cancellation.
///
/// # Example
///
/// ```ignore
/// use asupersync::service::{AsupersyncAdapter, AdapterConfig, CancellationMode};
///
/// let tower_service = MyTowerService::new();
/// let adapter = AsupersyncAdapter::new(tower_service)
///     .with_config(AdapterConfig::new()
///         .cancellation_mode(CancellationMode::TimeoutFallback)
///         .fallback_timeout(Duration::from_secs(30)));
/// ```
#[cfg(feature = "tower")]
pub struct AsupersyncAdapter<S> {
    inner: std::sync::Mutex<S>,
    config: AdapterConfig,
}

#[cfg(feature = "tower")]
impl<S> AsupersyncAdapter<S> {
    /// Create a new adapter with default configuration.
    pub fn new(service: S) -> Self {
        Self {
            inner: std::sync::Mutex::new(service),
            config: AdapterConfig::default(),
        }
    }

    /// Create a new adapter with the specified configuration.
    pub fn with_config(service: S, config: AdapterConfig) -> Self {
        Self {
            inner: std::sync::Mutex::new(service),
            config,
        }
    }

    /// Returns a reference to the adapter configuration.
    pub fn config(&self) -> &AdapterConfig {
        &self.config
    }
}

#[cfg(feature = "tower")]
impl<S, Request> AsupersyncService<Request> for AsupersyncAdapter<S>
where
    S: tower::Service<Request> + Send + 'static,
    Request: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + std::fmt::Debug + std::fmt::Display + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = TowerAdapterError<S::Error>;

    async fn call(&self, cx: &Cx, request: Request) -> Result<Self::Response, Self::Error> {
        use std::future::poll_fn;

        // Check if already cancelled
        if cx.is_cancel_requested() {
            return Err(TowerAdapterError::Cancelled);
        }

        // Check budget for waiting on readiness
        let budget = cx.remaining_budget();
        if budget.units() < self.config.min_budget_for_wait {
            return Err(TowerAdapterError::Overloaded);
        }

        // Get the inner service
        let mut service = self.inner.lock().expect("lock poisoned");

        // Poll for readiness
        let ready_result = poll_fn(|poll_cx| service.poll_ready(poll_cx)).await;
        if let Err(e) = ready_result {
            return Err(TowerAdapterError::Service(e));
        }

        // Check cancellation again before calling
        if cx.is_cancel_requested() {
            return Err(TowerAdapterError::Cancelled);
        }

        // Dispatch the request
        let future = service.call(request);

        // Drop the lock before awaiting
        drop(service);

        // Handle the call based on cancellation mode
        match self.config.cancellation_mode {
            CancellationMode::BestEffort => {
                // Just await the future, no special handling
                future.await.map_err(TowerAdapterError::Service)
            }
            CancellationMode::Strict => {
                // Use tokio's select to race cancellation
                // For now, fallback to best effort since we don't have tokio dependency
                // In strict mode, we'd fail if cancellation is requested during execution
                let result = future.await.map_err(TowerAdapterError::Service);

                // After completion, check if we were cancelled
                if cx.is_cancel_requested() {
                    // In strict mode, we report this as an error
                    return Err(TowerAdapterError::CancellationIgnored);
                }

                result
            }
            CancellationMode::TimeoutFallback => {
                // If we have a fallback timeout, use it
                if let Some(_timeout) = self.config.fallback_timeout {
                    // Note: Full timeout implementation would require async runtime support
                    // For now, just await the future directly
                    future.await.map_err(TowerAdapterError::Service)
                } else {
                    future.await.map_err(TowerAdapterError::Service)
                }
            }
        }
    }
}

/// Future returned by [`ServiceExt::ready`].
#[derive(Debug)]
pub struct Ready<'a, S: ?Sized, Request> {
    service: &'a mut S,
    _marker: PhantomData<fn(Request)>,
}

impl<'a, S: ?Sized, Request> Ready<'a, S, Request> {
    fn new(service: &'a mut S) -> Self {
        Self {
            service,
            _marker: PhantomData,
        }
    }
}

impl<S, Request> Future for Ready<'_, S, Request>
where
    S: Service<Request> + ?Sized,
{
    type Output = Result<(), S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.service.poll_ready(cx)
    }
}

/// Future returned by [`ServiceExt::oneshot`].
pub struct Oneshot<S, Request>
where
    S: Service<Request>,
{
    state: OneshotState<S, Request>,
}

enum OneshotState<S, Request>
where
    S: Service<Request>,
{
    Ready {
        service: S,
        request: Option<Request>,
    },
    Calling {
        future: S::Future,
    },
    Done,
}

impl<S, Request> Oneshot<S, Request>
where
    S: Service<Request>,
{
    /// Creates a new oneshot future.
    pub fn new(service: S, request: Request) -> Self {
        Self {
            state: OneshotState::Ready {
                service,
                request: Some(request),
            },
        }
    }
}

impl<S, Request> Future for Oneshot<S, Request>
where
    S: Service<Request> + Unpin,
    Request: Unpin,
    S::Future: Unpin,
{
    type Output = Result<S::Response, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            match &mut this.state {
                OneshotState::Ready { service, request } => match service.poll_ready(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => {
                        this.state = OneshotState::Done;
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Ok(())) => {
                        let req = request.take().expect("Oneshot polled after request taken");
                        let fut = service.call(req);
                        this.state = OneshotState::Calling { future: fut };
                    }
                },
                OneshotState::Calling { future } => {
                    let result = Pin::new(future).poll(cx);
                    if result.is_ready() {
                        this.state = OneshotState::Done;
                    }
                    return result;
                }
                OneshotState::Done => {
                    panic!("Oneshot polled after completion");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AsupersyncService, AsupersyncServiceExt};
    use crate::test_utils::run_test_with_cx;

    #[test]
    fn function_service_call_works() {
        run_test_with_cx(|cx| async move {
            let svc = |_: &crate::cx::Cx, req: i32| async move { Ok::<_, ()>(req + 1) };
            let result = AsupersyncService::call(&svc, &cx, 41).await.unwrap();
            assert_eq!(result, 42);
        });
    }

    #[test]
    fn map_response_and_map_err() {
        run_test_with_cx(|cx| async move {
            let svc = |_: &crate::cx::Cx, req: i32| async move { Ok::<_, &str>(req) };
            let svc = svc.map_response(|v| v + 1).map_err(|e| format!("err:{e}"));
            let result = AsupersyncService::call(&svc, &cx, 41).await.unwrap();
            assert_eq!(result, 42);

            let fail = |_: &crate::cx::Cx, _: i32| async move { Err::<i32, &str>("nope") };
            let fail = fail.map_err(|e| format!("err:{e}"));
            let err = AsupersyncService::call(&fail, &cx, 0).await.unwrap_err();
            assert_eq!(err, "err:nope");
        });
    }

    // ========================================================================
    // Tower Adapter Configuration Tests
    // ========================================================================

    use super::{AdapterConfig, CancellationMode, DefaultErrorAdapter, ErrorAdapter, TowerAdapterError};

    #[test]
    fn cancellation_mode_default_is_best_effort() {
        let mode = CancellationMode::default();
        assert_eq!(mode, CancellationMode::BestEffort);
    }

    #[test]
    fn adapter_config_builder_pattern() {
        let config = AdapterConfig::new()
            .cancellation_mode(CancellationMode::Strict)
            .fallback_timeout(std::time::Duration::from_secs(30))
            .min_budget_for_wait(100);

        assert_eq!(config.cancellation_mode, CancellationMode::Strict);
        assert_eq!(config.fallback_timeout, Some(std::time::Duration::from_secs(30)));
        assert_eq!(config.min_budget_for_wait, 100);
    }

    #[test]
    fn adapter_config_default_values() {
        let config = AdapterConfig::default();

        assert_eq!(config.cancellation_mode, CancellationMode::BestEffort);
        assert!(config.fallback_timeout.is_none());
        assert_eq!(config.min_budget_for_wait, 10);
    }

    #[test]
    fn default_error_adapter_round_trip() {
        let adapter = DefaultErrorAdapter::<String>::new();

        let original = "test error".to_string();
        let converted = adapter.to_asupersync(original.clone());
        assert_eq!(converted, original);

        let back = adapter.to_tower(converted);
        assert_eq!(back, original);
    }

    #[test]
    fn tower_adapter_error_display() {
        let service_err: TowerAdapterError<&str> = TowerAdapterError::Service("inner error");
        assert_eq!(format!("{service_err}"), "service error: inner error");

        let cancelled: TowerAdapterError<&str> = TowerAdapterError::Cancelled;
        assert_eq!(format!("{cancelled}"), "operation cancelled");

        let timeout: TowerAdapterError<&str> = TowerAdapterError::Timeout;
        assert_eq!(format!("{timeout}"), "operation timed out");

        let overloaded: TowerAdapterError<&str> = TowerAdapterError::Overloaded;
        assert_eq!(format!("{overloaded}"), "service overloaded, insufficient budget");

        let ignored: TowerAdapterError<&str> = TowerAdapterError::CancellationIgnored;
        assert_eq!(
            format!("{ignored}"),
            "service ignored cancellation request (strict mode)"
        );
    }

    #[test]
    fn tower_adapter_error_equality() {
        let err1: TowerAdapterError<i32> = TowerAdapterError::Service(42);
        let err2: TowerAdapterError<i32> = TowerAdapterError::Service(42);
        let err3: TowerAdapterError<i32> = TowerAdapterError::Service(43);

        assert_eq!(err1, err2);
        assert_ne!(err1, err3);

        assert_eq!(
            TowerAdapterError::<i32>::Cancelled,
            TowerAdapterError::Cancelled
        );
        assert_ne!(
            TowerAdapterError::<i32>::Cancelled,
            TowerAdapterError::Timeout
        );
    }

    #[test]
    fn cancellation_mode_all_variants() {
        // Ensure all variants are distinct
        let best_effort = CancellationMode::BestEffort;
        let strict = CancellationMode::Strict;
        let timeout = CancellationMode::TimeoutFallback;

        assert_ne!(best_effort, strict);
        assert_ne!(best_effort, timeout);
        assert_ne!(strict, timeout);
    }
}
