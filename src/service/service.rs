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

    /// Convert this service into a Tower-compatible adapter requiring `(Cx, Request)`.
    ///
    /// The returned adapter implements `tower::Service<(Cx, Request)>`. Use this
    /// when you want explicit control over Cx passing.
    ///
    /// For a version that obtains Cx automatically via a provider, use
    /// [`into_tower_with_provider`](Self::into_tower_with_provider).
    #[cfg(feature = "tower")]
    fn into_tower(self) -> TowerAdapter<Self>
    where
        Self: Sized,
    {
        TowerAdapter::new(self)
    }

    /// Convert this service into a Tower-compatible adapter with automatic Cx resolution.
    ///
    /// The returned adapter implements `tower::Service<Request>` by obtaining Cx
    /// from thread-local storage (set by the runtime during task polling).
    ///
    /// # Errors
    ///
    /// Calls will fail with [`ProviderAdapterError::NoCx`] if no Cx is available.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use asupersync::service::AsupersyncServiceExt;
    /// use tower::ServiceBuilder;
    /// use std::time::Duration;
    ///
    /// let service = my_service.into_tower_with_provider();
    ///
    /// let service = ServiceBuilder::new()
    ///     .rate_limit(100, Duration::from_secs(1))
    ///     .service(service);
    /// ```
    #[cfg(feature = "tower")]
    fn into_tower_with_provider(self) -> TowerAdapterWithProvider<Self, ThreadLocalCxProvider>
    where
        Self: Sized,
    {
        TowerAdapterWithProvider::new(self)
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
// Cx Provider Types
// =============================================================================

/// A mechanism for providing a [`Cx`] to Tower services.
///
/// Since Tower services don't receive a Cx in their call signature, adapters
/// need a way to obtain one. This trait abstracts over different strategies
/// for Cx acquisition.
///
/// # Built-in Implementations
///
/// - [`ThreadLocalCxProvider`]: Uses the thread-local Cx set by the runtime
/// - [`FixedCxProvider`]: Uses a fixed Cx (useful for testing)
///
/// # Example
///
/// ```rust,ignore
/// use asupersync::service::{CxProvider, TowerAdapterWithProvider};
///
/// // Custom provider that creates Cx on demand
/// struct OnDemandProvider;
///
/// impl CxProvider for OnDemandProvider {
///     fn current_cx(&self) -> Option<Cx> {
///         Some(Cx::for_testing())
///     }
/// }
/// ```
pub trait CxProvider: Send + Sync {
    /// Returns the current Cx, if one is available.
    ///
    /// Returns `None` if no Cx is available (e.g., not running within
    /// the asupersync runtime).
    fn current_cx(&self) -> Option<Cx>;
}

/// Provides Cx from thread-local storage.
///
/// This provider uses [`Cx::current()`] to retrieve the Cx that was set
/// by the runtime when polling the current task. This is the standard
/// provider for production use.
///
/// # Panics
///
/// The adapter using this provider will return an error (not panic) if
/// no Cx is available in thread-local storage.
///
/// # Example
///
/// ```rust,ignore
/// use asupersync::service::{TowerAdapterWithProvider, ThreadLocalCxProvider};
///
/// let adapter = TowerAdapterWithProvider::new(my_service);
/// // Uses ThreadLocalCxProvider by default
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadLocalCxProvider;

impl CxProvider for ThreadLocalCxProvider {
    fn current_cx(&self) -> Option<Cx> {
        Cx::current()
    }
}

/// Provides a fixed Cx for testing.
///
/// This provider always returns a clone of the Cx provided at construction.
/// Useful for testing Tower middleware stacks outside of the asupersync runtime.
///
/// # Example
///
/// ```rust,ignore
/// use asupersync::service::{TowerAdapterWithProvider, FixedCxProvider};
/// use asupersync::Cx;
///
/// let cx = Cx::for_testing();
/// let provider = FixedCxProvider::new(cx);
/// let adapter = TowerAdapterWithProvider::with_provider(my_service, provider);
///
/// // Can now use the adapter in tests without a runtime
/// ```
#[derive(Clone, Debug)]
pub struct FixedCxProvider {
    cx: Cx,
}

impl FixedCxProvider {
    /// Creates a new fixed Cx provider.
    #[must_use]
    pub fn new(cx: Cx) -> Self {
        Self { cx }
    }

    /// Creates a provider with a test Cx.
    #[must_use]
    pub fn for_testing() -> Self {
        Self {
            cx: Cx::for_testing(),
        }
    }
}

impl CxProvider for FixedCxProvider {
    fn current_cx(&self) -> Option<Cx> {
        Some(self.cx.clone())
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

/// Adapter that wraps an [`AsupersyncService`] for use with Tower.
///
/// This adapter allows Asupersync services to be used in Tower middleware stacks.
/// The service is wrapped in an `Arc` for shared ownership.
///
/// # Request Type
///
/// The Tower service accepts `(Cx, Request)` tuples, where `Cx` is the capability
/// context that provides cancellation, budget, and other contextual information.
///
/// # Limitations
///
/// The returned future is not `Send` because `AsupersyncService::call` uses
/// `async fn in trait` which doesn't guarantee Send futures. For multi-threaded
/// Tower usage, services should implement `tower::Service` directly.
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
    // Note: This future is not Send because AsupersyncService::call uses async fn in trait
    // which doesn't guarantee Send futures. For multi-threaded Tower usage, services should
    // implement tower::Service directly or use a Send-compatible wrapper.
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, (cx, request): (Cx, Request)) -> Self::Future {
        let service = std::sync::Arc::clone(&self.service);
        Box::pin(async move { service.call(&cx, request).await })
    }
}

/// Error returned when no Cx is available from the provider.
#[cfg(feature = "tower")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoCxAvailable;

#[cfg(feature = "tower")]
impl std::fmt::Display for NoCxAvailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no Cx available from provider (not running within asupersync runtime?)"
        )
    }
}

#[cfg(feature = "tower")]
impl std::error::Error for NoCxAvailable {}

/// Error type for [`TowerAdapterWithProvider`].
#[cfg(feature = "tower")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderAdapterError<E> {
    /// No Cx was available from the provider.
    NoCx(NoCxAvailable),
    /// The inner service returned an error.
    Service(E),
}

#[cfg(feature = "tower")]
impl<E: std::fmt::Display> std::fmt::Display for ProviderAdapterError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCx(e) => write!(f, "{e}"),
            Self::Service(e) => write!(f, "service error: {e}"),
        }
    }
}

#[cfg(feature = "tower")]
impl<E: std::fmt::Display + std::fmt::Debug> std::error::Error for ProviderAdapterError<E> {}

/// Adapter that wraps an [`AsupersyncService`] for use with Tower middleware.
///
/// Unlike [`TowerAdapter`], which requires `(Cx, Request)` tuples, this adapter
/// uses a [`CxProvider`] to obtain the Cx automatically. This allows seamless
/// integration with Tower middleware that expects `Service<Request>`.
///
/// # Cx Resolution
///
/// The adapter obtains a Cx by calling [`CxProvider::current_cx()`] on each
/// request. The default provider ([`ThreadLocalCxProvider`]) retrieves the Cx
/// from thread-local storage, which is set by the runtime while polling tasks.
///
/// # Example
///
/// ```rust,ignore
/// use asupersync::service::{TowerAdapterWithProvider, AsupersyncService};
/// use tower::ServiceBuilder;
/// use std::time::Duration;
///
/// struct MyService;
///
/// impl AsupersyncService<Request> for MyService {
///     type Response = Response;
///     type Error = Error;
///
///     async fn call(&self, cx: &Cx, req: Request) -> Result<Response, Error> {
///         // Implementation
///     }
/// }
///
/// // Wrap for use with Tower middleware
/// let service = TowerAdapterWithProvider::new(MyService);
///
/// // Use with Tower ServiceBuilder
/// let service = ServiceBuilder::new()
///     .rate_limit(100, Duration::from_secs(1))
///     .service(service);
/// ```
///
/// # Testing
///
/// For testing outside the runtime, use [`FixedCxProvider`]:
///
/// ```rust,ignore
/// use asupersync::service::{TowerAdapterWithProvider, FixedCxProvider};
/// use asupersync::Cx;
///
/// let provider = FixedCxProvider::for_testing();
/// let adapter = TowerAdapterWithProvider::with_provider(MyService, provider);
/// ```
///
/// # Limitations
///
/// The returned future is not `Send` because `AsupersyncService::call` uses
/// `async fn in trait`. For multi-threaded Tower usage, consider implementing
/// `tower::Service` directly on your type.
#[cfg(feature = "tower")]
pub struct TowerAdapterWithProvider<S, P = ThreadLocalCxProvider> {
    service: std::sync::Arc<S>,
    provider: P,
}

#[cfg(feature = "tower")]
impl<S> TowerAdapterWithProvider<S, ThreadLocalCxProvider> {
    /// Creates a new adapter using the default thread-local Cx provider.
    ///
    /// The provider uses [`Cx::current()`] to retrieve the Cx from thread-local
    /// storage that was set by the runtime.
    ///
    /// # Errors
    ///
    /// Calls will fail with [`ProviderAdapterError::NoCx`] if no Cx is
    /// available in thread-local storage (e.g., called outside the runtime).
    #[must_use]
    pub fn new(service: S) -> Self {
        Self {
            service: std::sync::Arc::new(service),
            provider: ThreadLocalCxProvider,
        }
    }
}

#[cfg(feature = "tower")]
impl<S, P> TowerAdapterWithProvider<S, P> {
    /// Creates a new adapter with a custom Cx provider.
    ///
    /// Use this constructor when you need custom Cx resolution, such as:
    /// - Testing with [`FixedCxProvider`]
    /// - Custom runtime integration
    /// - Cx pooling or caching strategies
    #[must_use]
    pub fn with_provider(service: S, provider: P) -> Self {
        Self {
            service: std::sync::Arc::new(service),
            provider,
        }
    }

    /// Returns a reference to the Cx provider.
    #[must_use]
    pub fn provider(&self) -> &P {
        &self.provider
    }
}

#[cfg(feature = "tower")]
impl<S, P> Clone for TowerAdapterWithProvider<S, P>
where
    P: Clone,
{
    fn clone(&self) -> Self {
        Self {
            service: std::sync::Arc::clone(&self.service),
            provider: self.provider.clone(),
        }
    }
}

#[cfg(feature = "tower")]
impl<S, P, Request> tower::Service<Request> for TowerAdapterWithProvider<S, P>
where
    S: AsupersyncService<Request> + Send + Sync + 'static,
    P: CxProvider,
    Request: Send + 'static,
    S::Response: 'static,
    S::Error: 'static,
{
    type Response = S::Response;
    type Error = ProviderAdapterError<S::Error>;
    // Note: This future is not Send because AsupersyncService::call uses async fn in trait
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Asupersync services are always ready (backpressure via budgets)
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        // Get Cx from provider
        let Some(cx) = self.provider.current_cx() else {
            return Box::pin(std::future::ready(Err(ProviderAdapterError::NoCx(
                NoCxAvailable,
            ))));
        };

        let service = std::sync::Arc::clone(&self.service);
        Box::pin(async move {
            service
                .call(&cx, request)
                .await
                .map_err(ProviderAdapterError::Service)
        })
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

    #[allow(clippy::await_holding_lock)]
    #[allow(clippy::future_not_send)]
    async fn call(&self, cx: &Cx, request: Request) -> Result<Self::Response, Self::Error> {
        use std::future::poll_fn;

        // Check if already cancelled
        if cx.is_cancel_requested() {
            return Err(TowerAdapterError::Cancelled);
        }

        // Check budget for waiting on readiness
        // Note: min_budget_for_wait is compared against poll_quota
        let budget = cx.budget();
        if u64::from(budget.poll_quota) < self.config.min_budget_for_wait {
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
                if let Some(timeout_duration) = self.config.fallback_timeout {
                    if let Some(timer) = cx.timer_driver() {
                        let now = timer.now();
                        match crate::time::timeout(now, timeout_duration, future).await {
                            Ok(output) => Ok(output),
                            Err(_) => Err(TowerAdapterError::Timeout),
                        }
                    } else {
                        // No timer driver available; fall back to best-effort.
                        future.await.map_err(TowerAdapterError::Service)
                    }
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

    use super::{
        AdapterConfig, CancellationMode, DefaultErrorAdapter, ErrorAdapter, TowerAdapterError,
    };

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
        assert_eq!(
            config.fallback_timeout,
            Some(std::time::Duration::from_secs(30))
        );
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
        assert_eq!(
            format!("{overloaded}"),
            "service overloaded, insufficient budget"
        );

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

    // ========================================================================
    // Cx Provider Tests
    // ========================================================================

    use super::{CxProvider, FixedCxProvider, ThreadLocalCxProvider};
    use crate::Cx;

    #[test]
    fn thread_local_provider_returns_none_when_not_set() {
        let provider = ThreadLocalCxProvider;
        // Outside of runtime context, should return None
        assert!(provider.current_cx().is_none());
    }

    #[test]
    fn fixed_provider_returns_cx() {
        let cx: Cx = Cx::for_testing();
        let provider = FixedCxProvider::new(cx.clone());

        let retrieved = provider.current_cx();
        assert!(retrieved.is_some());
        // Same task ID indicates it's the same (or equivalent) Cx
        assert_eq!(retrieved.unwrap().task_id(), cx.task_id());
    }

    #[test]
    fn fixed_provider_for_testing_convenience() {
        let provider = FixedCxProvider::for_testing();
        assert!(provider.current_cx().is_some());
    }

    #[test]
    fn thread_local_provider_default() {
        let provider = ThreadLocalCxProvider;
        // Just verify it doesn't panic
        let _ = provider.current_cx();
    }

    #[test]
    fn fixed_provider_is_cloneable() {
        let provider = FixedCxProvider::for_testing();
        let cloned = provider.clone();
        assert!(provider.current_cx().is_some());
        assert!(cloned.current_cx().is_some());
    }

    // ========================================================================
    // Tower Adapter with Provider Tests (cfg(feature = "tower"))
    // ========================================================================

    #[cfg(feature = "tower")]
    mod tower_provider_tests {
        use super::super::{
            AsupersyncService, CxProvider, FixedCxProvider, NoCxAvailable, ProviderAdapterError,
            TowerAdapterWithProvider,
        };
        use crate::Cx;

        // A simple test service
        struct AddOneService;

        impl AsupersyncService<i32> for AddOneService {
            type Response = i32;
            type Error = std::convert::Infallible;

            async fn call(&self, _cx: &Cx, req: i32) -> Result<Self::Response, Self::Error> {
                Ok(req + 1)
            }
        }

        #[test]
        fn adapter_with_fixed_provider_works() {
            let provider = FixedCxProvider::for_testing();
            let adapter = TowerAdapterWithProvider::with_provider(AddOneService, provider);

            // Verify provider is accessible
            assert!(adapter.provider().current_cx().is_some());
        }

        #[test]
        fn adapter_new_uses_thread_local_provider() {
            let adapter = TowerAdapterWithProvider::new(AddOneService);
            // Thread-local provider returns None when not in runtime
            assert!(adapter.provider().current_cx().is_none());
        }

        #[test]
        fn adapter_is_cloneable_with_clone_provider() {
            let provider = FixedCxProvider::for_testing();
            let adapter = TowerAdapterWithProvider::with_provider(AddOneService, provider);
            let _cloned = adapter.clone();
        }

        #[test]
        fn no_cx_available_error_display() {
            let err = NoCxAvailable;
            let msg = format!("{err}");
            assert!(msg.contains("no Cx available"));
        }

        #[test]
        fn provider_adapter_error_display() {
            let no_cx: ProviderAdapterError<&str> = ProviderAdapterError::NoCx(NoCxAvailable);
            assert!(format!("{no_cx}").contains("no Cx available"));

            let service_err: ProviderAdapterError<&str> =
                ProviderAdapterError::Service("test error");
            assert_eq!(format!("{service_err}"), "service error: test error");
        }

        #[test]
        fn provider_adapter_error_equality() {
            let err1: ProviderAdapterError<i32> = ProviderAdapterError::Service(42);
            let err2: ProviderAdapterError<i32> = ProviderAdapterError::Service(42);
            let err3: ProviderAdapterError<i32> = ProviderAdapterError::Service(43);

            assert_eq!(err1, err2);
            assert_ne!(err1, err3);

            let no_cx1: ProviderAdapterError<i32> = ProviderAdapterError::NoCx(NoCxAvailable);
            let no_cx2: ProviderAdapterError<i32> = ProviderAdapterError::NoCx(NoCxAvailable);
            assert_eq!(no_cx1, no_cx2);
        }
    }

    #[cfg(feature = "tower")]
    mod tower_adapter_timeout_tests {
        use super::super::{
            AdapterConfig, AsupersyncAdapter, AsupersyncService, CancellationMode,
            TowerAdapterError,
        };
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Budget, RegionId, TaskId, Time};
        use crate::Cx;
        use std::future::pending;
        use std::pin::Pin;
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};
        use std::time::Duration;

        struct NoopWaker;

        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
            fn wake_by_ref(self: &Arc<Self>) {}
        }

        fn noop_waker() -> Waker {
            Arc::new(NoopWaker).into()
        }

        #[derive(Clone)]
        struct PendingService;

        impl tower::Service<()> for PendingService {
            type Response = ();
            type Error = ();
            type Future = std::future::Pending<Result<(), ()>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _req: ()) -> Self::Future {
                pending()
            }
        }

        #[test]
        fn timeout_fallback_triggers_timeout_error() {
            crate::test_utils::init_test_logging();
            crate::test_phase!("timeout_fallback_triggers_timeout_error");

            let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
            let timer = TimerDriverHandle::with_virtual_clock(clock.clone());

            let cx = Cx::new_with_drivers(
                RegionId::new_for_test(1, 0),
                TaskId::new_for_test(1, 0),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            );
            let _guard = Cx::set_current(Some(cx.clone()));

            let config = AdapterConfig::new()
                .cancellation_mode(CancellationMode::TimeoutFallback)
                .fallback_timeout(Duration::from_millis(5));
            let adapter = AsupersyncAdapter::with_config(PendingService, config);

            let mut fut = adapter.call(&cx, ());
            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);

            let first = Pin::new(&mut fut).poll(&mut context);
            assert!(first.is_pending());

            clock.advance(Time::from_millis(6).as_nanos());
            timer.process_timers();

            let result = Pin::new(&mut fut).poll(&mut context);
            let timed_out = matches!(result, Poll::Ready(Err(TowerAdapterError::Timeout)));
            crate::assert_with_log!(timed_out, "timeout error", true, timed_out);
            crate::test_complete!("timeout_fallback_triggers_timeout_error");
        }
    }
}
