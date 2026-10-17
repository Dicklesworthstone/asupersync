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

    /// Relinquishes this handle's unused readiness reservation or queued wait.
    ///
    /// Call this when a request is shed, rejected, or stops waiting before
    /// `call`. A fresh `poll_ready` is required before another dispatch. Work
    /// already transferred into a call future is unaffected.
    ///
    /// Implementations detach their readiness state here and return its cleanup
    /// in the owned action. They must not invoke wakers or other user callbacks
    /// while detaching: shared adapters call this method under their service
    /// mutex, then drop the action after unlocking. Wrappers forward the action.
    /// The default preserves existing implementations that reserve no capacity.
    fn release_readiness(&mut self) -> ReadinessRelease {
        ReadinessRelease::default()
    }
}

/// Detached readiness cleanup, run when this value is dropped.
///
/// Construct this after removing a reservation from its service. Keep it alive
/// until any service/coordinator locks have been released. Cleanup is synchronous
/// and must return; it may release permits, unregister waiters, or wake peers.
/// Combining actions by capturing them in a new action runs no cleanup early.
/// Shared adapters also defer actions dropped by nested middleware until their
/// outermost synchronous service call has unlocked.
#[derive(Default)]
pub struct ReadinessRelease {
    cleanup: Option<Box<dyn FnOnce() + 'static>>,
}

impl ReadinessRelease {
    /// Own a detached reservation and its cleanup without running it yet.
    #[must_use]
    pub fn new(cleanup: impl FnOnce() + 'static) -> Self {
        Self {
            cleanup: Some(Box::new(cleanup)),
        }
    }
}

impl std::fmt::Debug for ReadinessRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadinessRelease")
            .field("pending", &self.cleanup.is_some())
            .finish()
    }
}

#[derive(Default)]
struct DeferredReadinessReleases {
    depth: usize,
    pending: Vec<ReadinessRelease>,
}

thread_local! {
    static DEFERRED_READINESS_RELEASES: std::cell::RefCell<DeferredReadinessReleases> =
        const { std::cell::RefCell::new(DeferredReadinessReleases {
            depth: 0,
            pending: Vec::new(),
        }) };
}

/// Defers transitive readiness cleanup while a shared service is locked.
///
/// Declare this before acquiring the service mutex and never retain it across
/// an await. A nested middleware may release readiness from poll_ready or call;
/// its action then runs only after the outermost scope unlocks, including on
/// unwind. The marker prevents moving an active scope to another thread.
pub(super) struct ReadinessReleaseScope {
    marker: PhantomData<std::rc::Rc<()>>,
}

impl ReadinessReleaseScope {
    pub(super) fn new() -> Self {
        DEFERRED_READINESS_RELEASES.with(|releases| {
            releases.borrow_mut().depth += 1;
        });
        Self {
            marker: PhantomData,
        }
    }
}

impl Drop for ReadinessReleaseScope {
    fn drop(&mut self) {
        let pending = DEFERRED_READINESS_RELEASES.with(|releases| {
            let mut releases = releases.borrow_mut();
            releases.depth -= 1;
            if releases.depth == 0 {
                std::mem::take(&mut releases.pending)
            } else {
                Vec::new()
            }
        });
        // Drop outside the RefCell borrow so cleanup may reenter shared
        // services. Keeping queued actions as RAII values also runs the rest
        // if an earlier callback panics while this vector is being dropped.
        drop(pending);
    }
}

impl Drop for ReadinessRelease {
    fn drop(&mut self) {
        let mut cleanup = self.cleanup.take();
        if cleanup.is_none() {
            return;
        }
        // try_with also permits detached actions to finish during thread-local
        // teardown, when no shared-service scope can remain active.
        let _ = DEFERRED_READINESS_RELEASES.try_with(|releases| {
            let mut releases = releases.borrow_mut();
            if releases.depth != 0 {
                releases.pending.push(Self {
                    cleanup: cleanup.take(),
                });
            }
        });
        if let Some(cleanup) = cleanup {
            if std::thread::panicking() {
                if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup))
                {
                    std::mem::forget(payload);
                }
            } else {
                cleanup();
            }
        }
    }
}

/// Owns the readiness attempt of a service retained by an adapter future.
pub(super) struct ReadinessService<S, Request>
where
    S: Service<Request>,
{
    inner: S,
    armed: bool,
    marker: PhantomData<fn(Request)>,
}

impl<S, Request> ReadinessService<S, Request>
where
    S: Service<Request>,
{
    pub(super) fn new(inner: S) -> Self {
        Self {
            inner,
            armed: false,
            marker: PhantomData,
        }
    }

    pub(super) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.armed = true;
        let result = self.inner.poll_ready(cx);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.armed = false;
            drop(self.inner.release_readiness());
        }
        result
    }

    pub(super) fn call(&mut self, request: Request) -> S::Future {
        let future = self.inner.call(request);
        self.armed = false;
        future
    }
}

impl<S, Request> Drop for ReadinessService<S, Request>
where
    S: Service<Request>,
{
    fn drop(&mut self) {
        if self.armed {
            drop(self.inner.release_readiness());
        }
    }
}

/// Extension trait providing convenience adapters for services.
pub trait ServiceExt<Request>: Service<Request> {
    /// Waits until the service is ready to accept a request.
    /// Dropping this future after a pending poll releases its readiness wait.
    /// A successful wait retains readiness for the subsequent `call`.
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
    /// Calls will fail with `ProviderAdapterError::NoCx` if no Cx is available.
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
/// This API is only available when the `tower` feature is enabled.
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
#[cfg(feature = "tower")]
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
#[cfg(feature = "tower")]
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadLocalCxProvider;

#[cfg(feature = "tower")]
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
#[cfg(feature = "tower")]
#[derive(Clone, Debug)]
pub struct FixedCxProvider {
    cx: Cx,
}

#[cfg(feature = "tower")]
impl FixedCxProvider {
    /// Creates a new fixed Cx provider.
    #[must_use]
    pub fn new(cx: Cx) -> Self {
        Self { cx }
    }

    /// Creates a provider with a test Cx.
    ///
    /// This convenience constructor is available only to crate tests and
    /// consumers that explicitly enable `test-internals`. Production callers
    /// can provide an explicit context with [`Self::new`].
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn for_testing() -> Self {
        Self {
            cx: Cx::for_testing(),
        }
    }
}

#[cfg(feature = "tower")]
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

    /// Timeout deadline shared across non-cancellable readiness waits and
    /// request futures.
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
/// uses a `CxProvider` to obtain the Cx automatically. This allows seamless
/// integration with Tower middleware that expects `Service<Request>`.
///
/// # Cx Resolution
///
/// The adapter obtains a Cx by calling `CxProvider::current_cx()` on each
/// request. The default provider (`ThreadLocalCxProvider`) retrieves the Cx
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
    /// Calls will fail with `ProviderAdapterError::NoCx` if no Cx is
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
    inner: crate::sync::Mutex<S>,
    config: AdapterConfig,
}

#[cfg(feature = "tower")]
impl<S> AsupersyncAdapter<S> {
    /// Create a new adapter with default configuration.
    pub fn new(service: S) -> Self {
        Self {
            inner: crate::sync::Mutex::with_name("service_adapter", service),
            config: AdapterConfig::default(),
        }
    }

    /// Create a new adapter with the specified configuration.
    pub fn with_config(service: S, config: AdapterConfig) -> Self {
        Self {
            inner: crate::sync::Mutex::with_name("service_adapter", service),
            config,
        }
    }

    /// Returns a reference to the adapter configuration.
    pub fn config(&self) -> &AdapterConfig {
        &self.config
    }

    fn lock_error<E>(err: crate::sync::LockError) -> TowerAdapterError<E> {
        match err {
            crate::sync::LockError::Cancelled => TowerAdapterError::Cancelled,
            crate::sync::LockError::TimedOut(_) => TowerAdapterError::Timeout,
            crate::sync::LockError::Poisoned | crate::sync::LockError::PolledAfterCompletion => {
                TowerAdapterError::Overloaded
            }
        }
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

    #[allow(clippy::future_not_send)]
    async fn call(&self, cx: &Cx, request: Request) -> Result<Self::Response, Self::Error> {
        use std::future::poll_fn;

        // Check if already cancelled
        if cx.checkpoint().is_err() {
            return Err(TowerAdapterError::Cancelled);
        }

        // Check budget for waiting on readiness
        // Note: min_budget_for_wait is compared against poll_quota
        let budget = cx.budget();
        if u64::from(budget.poll_quota) < self.config.min_budget_for_wait {
            return Err(TowerAdapterError::Overloaded);
        }

        let timeout_deadline = match self.config.cancellation_mode {
            CancellationMode::TimeoutFallback => self
                .config
                .fallback_timeout
                .and_then(|timeout| cx.timer_driver().map(|timer| timer.now() + timeout)),
            _ => None,
        };

        // Get the inner service without blocking a worker thread. Tower services
        // require `&mut self` for readiness and calls, so this adapter serializes
        // access while letting competing callers yield/cancel/timeout.
        let mut service = if let Some(deadline) = timeout_deadline {
            self.inner
                .lock_until(cx, deadline)
                .await
                .map_err(Self::lock_error)?
        } else {
            self.inner.lock(cx).await.map_err(Self::lock_error)?
        };

        // Poll for readiness
        let ready_result = if let Some(deadline) = timeout_deadline {
            crate::time::timeout_at(deadline, poll_fn(|poll_cx| service.poll_ready(poll_cx)))
                .await
                .map_err(|_| TowerAdapterError::Timeout)?
        } else {
            poll_fn(|poll_cx| service.poll_ready(poll_cx)).await
        };
        if let Err(e) = ready_result {
            return Err(TowerAdapterError::Service(e));
        }

        // Check cancellation again before calling
        if cx.checkpoint().is_err() {
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
                // Use a select-style race with cancellation once we wire the runtime primitive.
                // For now, fall back to best effort and report if cancellation was ignored.
                let result = future.await.map_err(TowerAdapterError::Service);

                // After completion, check if we were cancelled
                if cx.checkpoint().is_err() {
                    // In strict mode, we report this as an error
                    return Err(TowerAdapterError::CancellationIgnored);
                }

                result
            }
            CancellationMode::TimeoutFallback => {
                if let Some(deadline) = timeout_deadline {
                    crate::time::timeout_at(deadline, Box::pin(future))
                        .await
                        .map_or_else(
                            |_| Err(TowerAdapterError::Timeout),
                            |output| output.map_err(TowerAdapterError::Service),
                        )
                } else {
                    // No timer driver or fallback timeout available; fall back to best-effort.
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
    release: fn(&mut S) -> ReadinessRelease,
    armed: bool,
    _marker: PhantomData<fn(Request)>,
}

impl<'a, S: Service<Request> + ?Sized, Request> Ready<'a, S, Request> {
    fn new(service: &'a mut S) -> Self {
        Self {
            service,
            release: <S as Service<Request>>::release_readiness,
            armed: false,
            _marker: PhantomData,
        }
    }
}

impl<S, Request> Future for Ready<'_, S, Request>
where
    S: Service<Request> + ?Sized,
{
    type Output = Result<(), S::Error>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.armed = true;
        let result = this.service.poll_ready(cx);
        match &result {
            Poll::Ready(Ok(())) => this.armed = false,
            Poll::Ready(Err(_)) => {
                this.armed = false;
                drop((this.release)(this.service));
            }
            Poll::Pending => {}
        }
        result
    }
}

impl<S: ?Sized, Request> Drop for Ready<'_, S, Request> {
    fn drop(&mut self) {
        if self.armed {
            drop((self.release)(self.service));
        }
    }
}

/// Error returned by [`ServiceExt::oneshot`].
#[derive(Debug)]
pub enum OneshotError<E> {
    /// The inner service returned an error.
    Inner(E),
    /// The future was polled after it had already completed.
    PolledAfterCompletion,
}

impl<E: std::fmt::Display> std::fmt::Display for OneshotError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(err) => write!(f, "inner service error: {err}"),
            Self::PolledAfterCompletion => write!(f, "oneshot future polled after completion"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for OneshotError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(err) => Some(err),
            Self::PolledAfterCompletion => None,
        }
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
        service: ReadinessService<S, Request>,
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
                service: ReadinessService::new(service),
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
    type Output = Result<S::Response, OneshotError<S::Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            let state = std::mem::replace(&mut this.state, OneshotState::Done);
            match state {
                OneshotState::Ready {
                    mut service,
                    mut request,
                } => match service.poll_ready(cx) {
                    Poll::Pending => {
                        this.state = OneshotState::Ready { service, request };
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(err)) => {
                        return Poll::Ready(Err(OneshotError::Inner(err)));
                    }
                    Poll::Ready(Ok(())) => {
                        let Some(req) = request.take() else {
                            return Poll::Ready(Err(OneshotError::PolledAfterCompletion));
                        };
                        let fut = service.call(req);
                        this.state = OneshotState::Calling { future: fut };
                    }
                },
                OneshotState::Calling { mut future } => {
                    let result = Pin::new(&mut future).poll(cx);
                    if result.is_pending() {
                        this.state = OneshotState::Calling { future };
                    }
                    return result.map_err(OneshotError::Inner);
                }
                OneshotState::Done => {
                    return Poll::Ready(Err(OneshotError::PolledAfterCompletion));
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "service_inline_tests.rs"]
mod tests;
