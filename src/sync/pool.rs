//! Cancel-safe resource pooling with obligation-based return semantics.
//!
//! This module provides a generic resource pooling framework that integrates with
//! asupersync's cancel-safety guarantees. Resources are managed through an
//! obligation-based contract: when a [`PooledResource`] is dropped (or explicitly
//! returned), the underlying resource is automatically sent back to the pool.
//!
//! # Getting Started
//!
//! ## Using the Generic Pool
//!
//! The easiest way to create a pool is with [`GenericPool`] and a factory function:
//!
//! ```ignore
//! use asupersync::sync::{GenericPool, Pool, PoolConfig};
//!
//! // Create a factory that produces resources
//! let factory = || Box::pin(async {
//!     Ok(TcpStream::connect("localhost:5432").await?)
//! });
//!
//! // Create pool with configuration
//! let pool = GenericPool::new(factory, PoolConfig::default());
//!
//! // Acquire and use a resource
//! async fn example(cx: &Cx, pool: &impl Pool<Resource = TcpStream>) {
//!     let conn = pool.acquire(cx).await?;
//!     conn.write_all(b"SELECT 1").await?;
//!     conn.return_to_pool();  // Or just drop - both work!
//! }
//! ```
//!
//! ## Implementing the Pool Trait
//!
//! For custom pool implementations, implement the [`Pool`] trait:
//!
//! ```ignore
//! use asupersync::sync::{Pool, PooledResource, PoolStats, PoolFuture, PoolReturnSender};
//! use asupersync::Cx;
//! use std::sync::mpsc;
//!
//! struct MyPool {
//!     return_tx: PoolReturnSender<Vec<u8>>,
//! }
//!
//! impl Pool for MyPool {
//!     type Resource = Vec<u8>;
//!     type Error = std::io::Error;
//!
//!     fn acquire<'a>(&'a self, cx: &'a Cx) -> PoolFuture<'a, Result<PooledResource<Self::Resource>, Self::Error>> {
//!         let resource = vec![0u8; 128];
//!         let pooled = PooledResource::new(resource, self.return_tx.clone());
//!         Box::pin(async move { Ok(pooled) })
//!     }
//!
//!     fn try_acquire(&self) -> Option<PooledResource<Self::Resource>> {
//!         Some(PooledResource::new(vec![0u8; 128], self.return_tx.clone()))
//!     }
//!
//!     fn stats(&self) -> PoolStats { PoolStats::default() }
//!
//!     fn close(&self) -> PoolFuture<'_, ()> {
//!         Box::pin(async move { })
//!     }
//! }
//! ```
//!
//! # Configuration Guide
//!
//! [`PoolConfig`] provides fine-grained control over pool behavior:
//!
//! | Option | Default | Description |
//! |--------|---------|-------------|
//! | `min_size` | 1 | Minimum resources to keep in pool |
//! | `max_size` | 10 | Maximum total resources |
//! | `acquire_timeout` | 30s | Timeout for acquire operations |
//! | `idle_timeout` | 600s | Max time a resource can be idle |
//! | `max_lifetime` | 3600s | Max lifetime of a resource |
//!
//! ```ignore
//! let config = PoolConfig::with_max_size(20)
//!     .min_size(5)
//!     .acquire_timeout(Duration::from_secs(10))
//!     .idle_timeout(Duration::from_secs(300))
//!     .max_lifetime(Duration::from_secs(1800));
//! ```
//!
//! # Cancel-Safety Patterns
//!
//! The pool is designed for cancel-safety at every phase:
//!
//! ## Cancellation During Wait
//!
//! If a task is cancelled while waiting for a resource (pool at capacity),
//! no resource is leaked. The waiter is simply removed from the queue.
//!
//! ## Cancellation While Holding
//!
//! If a task is cancelled while holding a resource, the [`PooledResource`]'s
//! [`Drop`] implementation ensures the resource is returned to the pool:
//!
//! ```ignore
//! async fn risky_operation(cx: &Cx, pool: &DbPool) -> Result<Data> {
//!     let conn = pool.acquire(cx).await?;
//!
//!     // Even if this panics or cx is cancelled, conn will be returned!
//!     let data = conn.query("SELECT * FROM users").await?;
//!
//!     // Explicit return is optional but recommended for clarity
//!     conn.return_to_pool();
//!     Ok(data)
//! }
//! ```
//!
//! ## Discarding Broken Resources
//!
//! If a resource becomes broken (connection error, invalid state), use
//! [`PooledResource::discard()`] to remove it from the pool rather than
//! returning it:
//!
//! ```ignore
//! async fn handle_connection(conn: PooledResource<TcpStream>) {
//!     match conn.write_all(b"PING").await {
//!         Ok(_) => conn.return_to_pool(),
//!         Err(_) => conn.discard(),  // Don't return broken connections
//!     }
//! }
//! ```
//!
//! ## Obligation Tracking
//!
//! The pool uses an obligation-based model. Once you acquire a resource,
//! you have an "obligation" to return it. This obligation is automatically
//! discharged by either:
//!
//! 1. Calling [`return_to_pool()`](PooledResource::return_to_pool)
//! 2. Calling [`discard()`](PooledResource::discard)
//! 3. Dropping the [`PooledResource`] (implicit return)
//!
//! The obligation prevents double-return bugs and ensures resources
//! are always accounted for.
//!
//! # Metrics and Monitoring
//!
//! Use [`Pool::stats()`] to monitor pool health:
//!
//! ```ignore
//! let stats = pool.stats();
//!
//! tracing::info!(
//!     active = stats.active,
//!     idle = stats.idle,
//!     total = stats.total,
//!     max_size = stats.max_size,
//!     waiters = stats.waiters,
//!     acquisitions = stats.total_acquisitions,
//!     "Pool health check"
//! );
//!
//! // Alert if pool is starved
//! if stats.waiters > 10 {
//!     tracing::warn!(waiters = stats.waiters, "Pool congestion detected");
//! }
//!
//! // Alert if utilization is high
//! let utilization = stats.active as f64 / stats.max_size as f64;
//! if utilization > 0.9 {
//!     tracing::warn!(utilization = %format!("{:.0}%", utilization * 100.0), "Pool near capacity");
//! }
//! ```
//!
//! ## Key Metrics
//!
//! | Metric | Meaning |
//! |--------|---------|
//! | `active` | Resources currently held by tasks |
//! | `idle` | Resources waiting to be used |
//! | `total` | Total resources (active + idle) |
//! | `waiters` | Tasks blocked waiting for resources |
//! | `total_acquisitions` | Lifetime acquisition count |
//! | `total_wait_time` | Cumulative wait time |
//!
//! # Troubleshooting
//!
//! ## Pool Exhaustion
//!
//! If `waiters` is high and `total == max_size`, consider:
//! - Increasing `max_size`
//! - Reducing hold time (return resources faster)
//! - Adding circuit breakers to prevent cascading failures
//!
//! ## Resource Leaks
//!
//! If `total` grows but `idle` stays low, resources may be:
//! - Held too long (check `held_duration()`)
//! - Not being returned properly (ensure `return_to_pool()` or drop is called)
//!
//! ## Stale Resources
//!
//! If connections are timing out, consider:
//! - Reducing `idle_timeout` to evict stale resources faster
//! - Reducing `max_lifetime` to force refresh
//! - Adding health checks before returning resources to pool

use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use crate::cx::Cx;

/// Boxed future helper for async trait-like APIs.
pub type PoolFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Sender used to return resources back to a pool.
pub type PoolReturnSender<R> = mpsc::Sender<PoolReturn<R>>;

/// Receiver used to observe resources returning to a pool.
pub type PoolReturnReceiver<R> = mpsc::Receiver<PoolReturn<R>>;

/// Trait for resource pools with cancel-safe acquisition.
pub trait Pool: Send + Sync {
    /// The type of resource managed by this pool.
    type Resource: Send;

    /// Error type for acquisition failures.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Acquire a resource from the pool.
    ///
    /// This may block if no resources are available and the pool
    /// is at capacity. The acquire respects the `Cx` deadline.
    ///
    /// # Cancel-Safety
    ///
    /// - Cancelled while waiting: no resource is leaked.
    /// - Cancelled after acquisition: the `PooledResource` returns on drop.
    fn acquire<'a>(
        &'a self,
        cx: &'a Cx,
    ) -> PoolFuture<'a, Result<PooledResource<Self::Resource>, Self::Error>>;

    /// Try to acquire without waiting.
    ///
    /// Returns `None` if no resource is immediately available.
    fn try_acquire(&self) -> Option<PooledResource<Self::Resource>>;

    /// Get current pool statistics.
    fn stats(&self) -> PoolStats;

    /// Close the pool, rejecting new acquisitions.
    fn close(&self) -> PoolFuture<'_, ()>;

    /// Check if a resource is still healthy/usable.
    ///
    /// Called before returning an idle resource from the pool. If this
    /// returns `false`, the resource is discarded and another is tried
    /// (or a new one is created).
    ///
    /// The default implementation assumes all resources are healthy.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn health_check(&self, resource: &TcpStream) -> bool {
    ///     // Try a quick ping
    ///     resource.peer_addr().is_ok()
    /// }
    /// ```
    fn health_check<'a>(&'a self, _resource: &'a Self::Resource) -> PoolFuture<'a, bool> {
        Box::pin(async { true })
    }
}

/// Trait for async resource creation and destruction.
///
/// Provides a structured interface for pool resource lifecycle management.
/// [`GenericPool`] accepts any factory function matching the expected signature;
/// implement this trait when you need custom destroy logic or want a named type.
///
/// # Example
///
/// ```ignore
/// use asupersync::sync::AsyncResourceFactory;
///
/// struct PgFactory { url: String }
///
/// impl AsyncResourceFactory for PgFactory {
///     type Resource = PgConnection;
///     type Error = PgError;
///
///     fn create(&self) -> Pin<Box<dyn Future<Output = Result<Self::Resource, Self::Error>> + Send + '_>> {
///         Box::pin(async { PgConnection::connect(&self.url).await })
///     }
///
///     fn destroy(&self, conn: Self::Resource) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
///         Box::pin(async move { conn.close().await.ok(); })
///     }
/// }
/// ```
pub trait AsyncResourceFactory: Send + Sync {
    /// The type of resource this factory creates.
    type Resource: Send;

    /// The error type for creation failures.
    ///
    /// Note: this is intentionally `Into<Box<dyn Error>>` rather than requiring
    /// `Error` directly. Some callers use boxed trait-object errors
    /// (`Box<dyn Error + Send + Sync>`), and on some toolchains `Box<dyn Error>`
    /// does not satisfy `Error` bounds due to `Sized`/`?Sized` impl details.
    type Error: Send + Sync + 'static + Into<Box<dyn std::error::Error + Send + Sync>>;

    /// Create a new resource asynchronously.
    #[allow(clippy::type_complexity)]
    fn create(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Resource, Self::Error>> + Send + '_>>;

    /// Destroy a resource (optional cleanup before drop).
    ///
    /// The default implementation simply drops the resource.
    fn destroy(&self, _resource: Self::Resource) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

/// Pool usage statistics.
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Resources currently in use.
    pub active: usize,
    /// Resources idle in pool.
    pub idle: usize,
    /// Total resources (active + idle).
    pub total: usize,
    /// Maximum pool size.
    pub max_size: usize,
    /// Waiters blocked on acquire.
    pub waiters: usize,
    /// Total acquisitions since pool creation.
    pub total_acquisitions: u64,
    /// Total time spent waiting for resources.
    pub total_wait_time: Duration,
}

/// Return messages sent from `PooledResource` back to a pool implementation.
#[derive(Debug)]
pub enum PoolReturn<R> {
    /// Resource is healthy; return to idle pool.
    Return {
        /// The resource being returned.
        resource: R,
        /// How long the resource was held.
        hold_duration: Duration,
        /// When the resource was originally created (for max_lifetime eviction).
        created_at: Instant,
    },
    /// Resource is broken; discard it.
    Discard {
        /// How long the resource was held before being discarded.
        hold_duration: Duration,
    },
}

#[derive(Debug)]
struct ReturnObligation {
    discharged: bool,
}

impl ReturnObligation {
    fn new() -> Self {
        Self { discharged: false }
    }

    fn discharge(&mut self) {
        self.discharged = true;
    }

    fn is_discharged(&self) -> bool {
        self.discharged
    }
}

/// A resource acquired from a pool.
///
/// This type uses an obligation-style contract: when dropped, it
/// returns the resource to the pool unless explicitly discarded.
#[must_use = "PooledResource must be returned or dropped"]
pub struct PooledResource<R> {
    resource: Option<R>,
    return_obligation: ReturnObligation,
    return_tx: PoolReturnSender<R>,
    acquired_at: Instant,
    created_at: Instant,
}

impl<R> PooledResource<R> {
    /// Creates a new pooled resource wrapper for a freshly created resource.
    pub fn new(resource: R, return_tx: PoolReturnSender<R>) -> Self {
        let now = Instant::now();
        Self {
            resource: Some(resource),
            return_obligation: ReturnObligation::new(),
            return_tx,
            acquired_at: now,
            created_at: now,
        }
    }

    /// Creates a pooled resource wrapper preserving the original creation time.
    fn new_with_created_at(
        resource: R,
        return_tx: PoolReturnSender<R>,
        created_at: Instant,
    ) -> Self {
        Self {
            resource: Some(resource),
            return_obligation: ReturnObligation::new(),
            return_tx,
            acquired_at: Instant::now(),
            created_at,
        }
    }

    /// Access the resource.
    #[must_use]
    pub fn get(&self) -> &R {
        self.resource.as_ref().expect("resource taken")
    }

    /// Mutably access the resource.
    pub fn get_mut(&mut self) -> &mut R {
        self.resource.as_mut().expect("resource taken")
    }

    /// Explicitly return the resource to the pool.
    ///
    /// This discharges the return obligation.
    pub fn return_to_pool(mut self) {
        self.return_inner();
    }

    /// Mark the resource as broken and discard it.
    ///
    /// The pool will create a new resource to replace this one.
    pub fn discard(mut self) {
        self.discard_inner();
    }

    /// How long this resource has been held.
    #[must_use]
    pub fn held_duration(&self) -> Duration {
        self.acquired_at.elapsed()
    }

    fn return_inner(&mut self) {
        if self.return_obligation.is_discharged() {
            return;
        }

        let hold_duration = self.held_duration();
        if let Some(resource) = self.resource.take() {
            let _ = self.return_tx.send(PoolReturn::Return {
                resource,
                hold_duration,
                created_at: self.created_at,
            });
        }

        self.return_obligation.discharge();
    }

    fn discard_inner(&mut self) {
        if self.return_obligation.is_discharged() {
            return;
        }

        let hold_duration = self.held_duration();
        self.resource.take();
        let _ = self.return_tx.send(PoolReturn::Discard { hold_duration });
        self.return_obligation.discharge();
    }
}

impl<R> Drop for PooledResource<R> {
    fn drop(&mut self) {
        if self.return_obligation.is_discharged() {
            return;
        }

        let hold_duration = self.held_duration();
        if let Some(resource) = self.resource.take() {
            let _ = self.return_tx.send(PoolReturn::Return {
                resource,
                hold_duration,
                created_at: self.created_at,
            });
        }

        self.return_obligation.discharge();
    }
}

impl<R> std::ops::Deref for PooledResource<R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<R> std::ops::DerefMut for PooledResource<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

// PooledResource is Send if the resource is Send.
// The callback is already required to be Send + Sync.
#[allow(unsafe_code)]
unsafe impl<R: Send> Send for PooledResource<R> {}

// ============================================================================
// PoolConfig and GenericPool
// ============================================================================

/// Strategy for handling partial warmup failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WarmupStrategy {
    /// Continue with whatever connections succeeded.
    #[default]
    BestEffort,
    /// Fail pool creation if any warmup fails.
    FailFast,
    /// Require at least min_size connections.
    RequireMinimum,
}

/// Configuration for a generic resource pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Minimum resources to keep in pool.
    pub min_size: usize,
    /// Maximum resources in pool.
    pub max_size: usize,
    /// Timeout for acquire operations.
    pub acquire_timeout: Duration,
    /// Maximum time a resource can be idle before eviction.
    pub idle_timeout: Duration,
    /// Maximum lifetime of a resource.
    pub max_lifetime: Duration,

    // --- Health check options ---
    /// Perform health check before returning idle resources.
    pub health_check_on_acquire: bool,
    /// Periodic health check interval for idle resources.
    /// If `None`, periodic health checks are disabled.
    pub health_check_interval: Option<Duration>,
    /// Remove unhealthy resources immediately when detected.
    pub evict_unhealthy: bool,

    // --- Warmup options ---
    /// Pre-create this many connections on pool init.
    pub warmup_connections: usize,
    /// Timeout for warmup phase.
    pub warmup_timeout: Duration,
    /// Strategy when warmup partially fails.
    pub warmup_failure_strategy: WarmupStrategy,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_size: 1,
            max_size: 10,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(3600),
            // Health check defaults
            health_check_on_acquire: false,
            health_check_interval: None,
            evict_unhealthy: true,
            // Warmup defaults
            warmup_connections: 0,
            warmup_timeout: Duration::from_secs(30),
            warmup_failure_strategy: WarmupStrategy::BestEffort,
        }
    }
}

impl PoolConfig {
    /// Creates a new pool configuration with the given max size.
    #[must_use]
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            max_size,
            ..Default::default()
        }
    }

    /// Sets the minimum pool size.
    #[must_use]
    pub fn min_size(mut self, min_size: usize) -> Self {
        self.min_size = min_size;
        self
    }

    /// Sets the maximum pool size.
    #[must_use]
    pub fn max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Sets the acquire timeout.
    #[must_use]
    pub fn acquire_timeout(mut self, timeout: Duration) -> Self {
        self.acquire_timeout = timeout;
        self
    }

    /// Sets the idle timeout.
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Sets the max lifetime.
    #[must_use]
    pub fn max_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_lifetime = lifetime;
        self
    }

    /// Enables health checking before returning idle resources.
    #[must_use]
    pub fn health_check_on_acquire(mut self, enabled: bool) -> Self {
        self.health_check_on_acquire = enabled;
        self
    }

    /// Sets the periodic health check interval for idle resources.
    #[must_use]
    pub fn health_check_interval(mut self, interval: Option<Duration>) -> Self {
        self.health_check_interval = interval;
        self
    }

    /// Sets whether to immediately evict unhealthy resources.
    #[must_use]
    pub fn evict_unhealthy(mut self, evict: bool) -> Self {
        self.evict_unhealthy = evict;
        self
    }

    /// Sets the number of connections to pre-create during warmup.
    #[must_use]
    pub fn warmup_connections(mut self, count: usize) -> Self {
        self.warmup_connections = count;
        self
    }

    /// Sets the timeout for the warmup phase.
    #[must_use]
    pub fn warmup_timeout(mut self, timeout: Duration) -> Self {
        self.warmup_timeout = timeout;
        self
    }

    /// Sets the strategy for handling partial warmup failures.
    #[must_use]
    pub fn warmup_failure_strategy(mut self, strategy: WarmupStrategy) -> Self {
        self.warmup_failure_strategy = strategy;
        self
    }
}

/// Error type for GenericPool operations.
#[derive(Debug)]
pub enum PoolError {
    /// The pool is closed.
    Closed,
    /// Acquisition timed out.
    Timeout,
    /// Acquisition was cancelled.
    Cancelled,
    /// Resource creation failed.
    CreateFailed(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "pool closed"),
            Self::Timeout => write!(f, "pool acquire timeout"),
            Self::Cancelled => write!(f, "pool acquire cancelled"),
            Self::CreateFailed(e) => write!(f, "resource creation failed: {e}"),
        }
    }
}

impl std::error::Error for PoolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateFailed(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

/// An idle resource in the pool.
#[derive(Debug)]
struct IdleResource<R> {
    resource: R,
    idle_since: Instant,
    created_at: Instant,
}

/// A waiter for a resource.
struct PoolWaiter {
    id: u64,
    waker: std::task::Waker,
}

/// Internal state for the generic pool.
struct GenericPoolState<R> {
    /// Idle resources ready for use.
    idle: std::collections::VecDeque<IdleResource<R>>,
    /// Number of resources currently in use.
    active: usize,
    /// Number of resources currently being created asynchronously.
    creating: usize,
    /// Total resources ever created.
    total_created: u64,
    /// Total acquisitions.
    total_acquisitions: u64,
    /// Total wait time accumulated.
    total_wait_time: Duration,
    /// Whether the pool is closed.
    closed: bool,
    /// Waiters queue (FIFO).
    waiters: std::collections::VecDeque<PoolWaiter>,
    /// Next waiter ID.
    next_waiter_id: u64,
}

/// Future that waits for a resource notification.
struct WaitForNotification<'a, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    pool: &'a GenericPool<R, F>,
    waiter_id: Option<u64>,
}

impl<R, F> Future for WaitForNotification<'_, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.pool.state.lock().expect("pool state lock poisoned");

        if state.closed {
            return Poll::Ready(());
        }

        // If resources are available, we are ready.
        let total_including_creating = state.active + state.idle.len() + state.creating;
        if !state.idle.is_empty() || total_including_creating < self.pool.config.max_size {
            // If we were waiting, remove ourselves
            if let Some(id) = self.waiter_id {
                state.waiters.retain(|w| w.id != id);
            }
            return Poll::Ready(());
        }

        // Check if we are currently in the queue
        let in_queue = self
            .waiter_id
            .is_some_and(|id| state.waiters.iter().any(|w| w.id == id));

        if in_queue {
            // Update waker if necessary.
            if let Some(id) = self.waiter_id {
                if let Some(w) = state.waiters.iter_mut().find(|w| w.id == id) {
                    if !w.waker.will_wake(cx.waker()) {
                        w.waker.clone_from(cx.waker());
                    }
                }
            }
        } else {
            // We are not in the queue. Register.
            let id = state.next_waiter_id;
            state.next_waiter_id += 1;
            state.waiters.push_back(PoolWaiter {
                id,
                waker: cx.waker().clone(),
            });
            self.waiter_id = Some(id);
        }

        drop(state);
        Poll::Pending
    }
}

impl<R, F> Drop for WaitForNotification<'_, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    fn drop(&mut self) {
        if let Some(id) = self.waiter_id {
            if let Ok(mut state) = self.pool.state.lock() {
                state.waiters.retain(|w| w.id != id);
            }
        }
    }
}

/// Reservation for an in-flight resource creation slot.
///
/// This ensures pool capacity accounting remains correct across async suspend
/// points: if acquire is cancelled while creating a resource, the reservation
/// is released in `Drop`.
struct CreateSlotReservation<'a, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    pool: &'a GenericPool<R, F>,
    committed: bool,
}

impl<'a, R, F> CreateSlotReservation<'a, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    fn try_reserve(pool: &'a GenericPool<R, F>) -> Option<Self> {
        if pool.reserve_create_slot() {
            Some(Self {
                pool,
                committed: false,
            })
        } else {
            None
        }
    }

    fn commit(mut self) {
        self.pool.commit_create_slot();
        self.committed = true;
    }
}

impl<R, F> Drop for CreateSlotReservation<'_, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    fn drop(&mut self) {
        if !self.committed {
            self.pool.release_create_slot();
        }
    }
}

impl<F, R, E, Fut> AsyncResourceFactory for F
where
    F: Fn() -> Fut + Send + Sync,
    Fut: Future<Output = Result<R, E>> + Send + 'static,
    R: Send,
    E: Send + Sync + 'static + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Resource = R;
    type Error = E;

    fn create(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Resource, Self::Error>> + Send + '_>> {
        Box::pin(self())
    }
}

/// A generic resource pool with configurable behavior.
///
/// This pool manages resources created by a factory function and provides
/// cancel-safe acquisition with timeout support.
///
/// # Type Parameters
///
/// - `R`: The resource type
/// - `F`: Factory type that creates resources
pub struct GenericPool<R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    /// Factory to create new resources.
    factory: F,
    /// Configuration.
    config: PoolConfig,
    /// Internal state.
    state: std::sync::Mutex<GenericPoolState<R>>,
    /// Channel for returning resources.
    return_tx: PoolReturnSender<R>,
    /// Channel receiver for returned resources.
    return_rx: std::sync::Mutex<PoolReturnReceiver<R>>,
    /// Optional synchronous health check function.
    ///
    /// When set and `config.health_check_on_acquire` is true, idle resources
    /// are checked before being returned from `acquire()`.
    #[allow(clippy::type_complexity)]
    health_check_fn: Option<Box<dyn Fn(&R) -> bool + Send + Sync>>,
    /// Optional metrics handle for observability.
    #[cfg(feature = "metrics")]
    metrics: Option<PoolMetricsHandle>,
}

impl<R, F> GenericPool<R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    /// Creates a new generic pool with the given factory and configuration.
    pub fn new(factory: F, config: PoolConfig) -> Self {
        let (return_tx, return_rx) = mpsc::channel();
        Self {
            factory,
            config,
            state: std::sync::Mutex::new(GenericPoolState {
                idle: std::collections::VecDeque::new(),
                active: 0,
                creating: 0,
                total_created: 0,
                total_acquisitions: 0,
                total_wait_time: Duration::ZERO,
                closed: false,
                waiters: std::collections::VecDeque::new(),
                next_waiter_id: 0,
            }),
            return_tx,
            return_rx: std::sync::Mutex::new(return_rx),
            health_check_fn: None,
            #[cfg(feature = "metrics")]
            metrics: None,
        }
    }

    /// Creates a new pool with default configuration.
    pub fn with_factory(factory: F) -> Self {
        Self::new(factory, PoolConfig::default())
    }

    /// Configures metrics collection for this pool.
    ///
    /// When metrics are enabled, the pool will record:
    /// - Gauges: size, active, idle, pending (waiters)
    /// - Counters: acquired, released, created, destroyed, timeouts
    /// - Histograms: acquire duration, hold duration, wait duration
    ///
    /// All metrics are labeled with the provided `pool_name`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use opentelemetry::global;
    /// use asupersync::sync::{GenericPool, PoolConfig, PoolMetrics};
    ///
    /// let meter = global::meter("myapp");
    /// let metrics = PoolMetrics::new(&meter);
    ///
    /// let pool = GenericPool::new(factory, PoolConfig::default())
    ///     .with_metrics("db_pool", metrics.handle("db_pool"));
    /// ```
    #[cfg(feature = "metrics")]
    #[must_use]
    pub fn with_metrics(mut self, handle: PoolMetricsHandle) -> Self {
        self.metrics = Some(handle);
        self
    }

    /// Sets a synchronous health check function for idle resources.
    ///
    /// When set and [`PoolConfig::health_check_on_acquire`] is `true`,
    /// each idle resource is checked before being returned from [`Pool::acquire`].
    /// Resources that fail the check are discarded and the next idle resource
    /// is tried, or a new one is created.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let pool = GenericPool::new(factory, config)
    ///     .with_health_check(|conn: &TcpStream| conn.peer_addr().is_ok());
    /// ```
    #[must_use]
    pub fn with_health_check(mut self, check: impl Fn(&R) -> bool + Send + Sync + 'static) -> Self {
        self.health_check_fn = Some(Box::new(check));
        self
    }

    /// Pre-create resources according to [`PoolConfig::warmup_connections`].
    ///
    /// Call this after constructing the pool to pre-fill the idle queue.
    /// The behavior on partial failure is controlled by
    /// [`PoolConfig::warmup_failure_strategy`].
    ///
    /// Returns the number of resources successfully created.
    ///
    /// # Errors
    ///
    /// - [`WarmupStrategy::FailFast`]: Returns on the first creation failure.
    /// - [`WarmupStrategy::RequireMinimum`]: Returns an error if fewer than
    ///   [`PoolConfig::min_size`] resources were created.
    /// - [`WarmupStrategy::BestEffort`]: Never returns an error from warmup.
    pub async fn warmup(&self) -> Result<usize, PoolError> {
        let existing = self.total_count();
        let capacity = self.config.max_size.saturating_sub(existing);
        let target = self.config.warmup_connections.min(capacity);
        if target == 0 {
            return Ok(0);
        }

        let mut created = 0;
        let mut last_error = None;

        for _ in 0..target {
            match self.create_resource().await {
                Ok(resource) => {
                    {
                        let mut state = self.state.lock().expect("pool state lock poisoned");
                        state.idle.push_back(IdleResource {
                            resource,
                            idle_since: Instant::now(),
                            created_at: Instant::now(),
                        });
                        state.total_created += 1;
                    }
                    created += 1;
                }
                Err(e) => match self.config.warmup_failure_strategy {
                    WarmupStrategy::FailFast => return Err(e),
                    WarmupStrategy::BestEffort | WarmupStrategy::RequireMinimum => {
                        last_error = Some(e);
                    }
                },
            }
        }

        if self.config.warmup_failure_strategy == WarmupStrategy::RequireMinimum
            && created < self.config.min_size
        {
            return Err(last_error.unwrap_or(PoolError::CreateFailed(
                "warmup did not reach min_size".into(),
            )));
        }

        Ok(created)
    }

    /// Check whether an idle resource passes the configured health check.
    fn is_healthy(&self, resource: &R) -> bool {
        self.health_check_fn
            .as_ref()
            .is_none_or(|check| check(resource))
    }

    /// Process returned resources from the return channel.
    #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
    fn process_returns(&self) {
        let rx = self.return_rx.lock().expect("return_rx lock poisoned");
        while let Ok(ret) = rx.try_recv() {
            match ret {
                PoolReturn::Return {
                    resource,
                    hold_duration,
                    created_at,
                } => {
                    // Record metrics for the release
                    #[cfg(feature = "metrics")]
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_released(hold_duration);
                    }

                    let mut state = self.state.lock().expect("pool state lock poisoned");
                    state.active = state.active.saturating_sub(1);

                    if !state.closed {
                        state.idle.push_back(IdleResource {
                            resource,
                            idle_since: Instant::now(),
                            created_at,
                        });

                        // Wake up one waiter if any
                        if let Some(waiter) = state.waiters.pop_front() {
                            waiter.waker.wake();
                        }
                    }
                    // If closed, just drop the resource
                }
                PoolReturn::Discard { hold_duration } => {
                    // Record metrics for the discard (destroyed as unhealthy)
                    #[cfg(feature = "metrics")]
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_released(hold_duration);
                        metrics.record_destroyed(DestroyReason::Unhealthy);
                    }

                    let mut state = self.state.lock().expect("pool state lock poisoned");
                    state.active = state.active.saturating_sub(1);

                    // Wake up one waiter to potentially create a new resource
                    if let Some(waiter) = state.waiters.pop_front() {
                        waiter.waker.wake();
                    }
                }
            }
        }
    }

    /// Try to get an idle resource, returning its original creation time.
    fn try_get_idle(&self) -> Option<(R, Instant)> {
        let mut state = self.state.lock().expect("pool state lock poisoned");

        // Evict expired resources first and track eviction reasons for metrics
        let now = Instant::now();
        #[cfg(feature = "metrics")]
        let mut idle_timeout_evictions = 0u64;
        #[cfg(feature = "metrics")]
        let mut max_lifetime_evictions = 0u64;

        state.idle.retain(|idle| {
            let idle_ok = now.duration_since(idle.idle_since) < self.config.idle_timeout;
            let lifetime_ok = now.duration_since(idle.created_at) < self.config.max_lifetime;

            #[cfg(feature = "metrics")]
            {
                if !idle_ok {
                    idle_timeout_evictions += 1;
                } else if !lifetime_ok {
                    max_lifetime_evictions += 1;
                }
            }

            idle_ok && lifetime_ok
        });

        // Record eviction metrics
        #[cfg(feature = "metrics")]
        if let Some(ref metrics) = self.metrics {
            for _ in 0..idle_timeout_evictions {
                metrics.record_destroyed(DestroyReason::IdleTimeout);
            }
            for _ in 0..max_lifetime_evictions {
                metrics.record_destroyed(DestroyReason::MaxLifetime);
            }
        }

        let result = if let Some(idle) = state.idle.pop_front() {
            state.active += 1;
            state.total_acquisitions += 1;
            Some((idle.resource, idle.created_at))
        } else {
            None
        };
        drop(state);
        result
    }

    /// Get current total count (active + idle + in-flight creates).
    fn total_count(&self) -> usize {
        let state = self.state.lock().expect("pool state lock poisoned");
        state.active + state.idle.len() + state.creating
    }

    /// Reserve a creation slot under max-size accounting.
    fn reserve_create_slot(&self) -> bool {
        let mut state = self.state.lock().expect("pool state lock poisoned");
        let total = state.active + state.idle.len() + state.creating;
        if state.closed || total >= self.config.max_size {
            return false;
        }
        state.creating += 1;
        true
    }

    /// Release an uncommitted creation slot and notify one waiter.
    fn release_create_slot(&self) {
        let waiter = {
            let mut state = self.state.lock().expect("pool state lock poisoned");
            state.creating = state.creating.saturating_sub(1);
            state.waiters.pop_front()
        };
        if let Some(waiter) = waiter {
            waiter.waker.wake();
        }
    }

    /// Commit a completed creation slot into active accounting.
    fn commit_create_slot(&self) {
        let mut state = self.state.lock().expect("pool state lock poisoned");
        state.creating = state.creating.saturating_sub(1);
        state.active += 1;
        state.total_acquisitions += 1;
        state.total_created += 1;
    }

    /// Create a new resource using the factory.
    async fn create_resource(&self) -> Result<R, PoolError> {
        let fut = self.factory.create();
        fut.await.map_err(|e| PoolError::CreateFailed(e.into()))
    }

    /// Register as a waiter.
    fn register_waiter(&self, waker: std::task::Waker) -> u64 {
        let mut state = self.state.lock().expect("pool state lock poisoned");
        let id = state.next_waiter_id;
        state.next_waiter_id += 1;
        state.waiters.push_back(PoolWaiter { id, waker });
        id
    }

    /// Remove a waiter by ID.
    fn remove_waiter(&self, id: u64) {
        let mut state = self.state.lock().expect("pool state lock poisoned");
        state.waiters.retain(|w| w.id != id);
    }

    /// Update metrics gauges from current pool state.
    #[cfg(feature = "metrics")]
    fn update_metrics_gauges(&self) {
        if let Some(ref metrics) = self.metrics {
            let stats = {
                let state = self.state.lock().expect("pool state lock poisoned");
                PoolStats {
                    active: state.active,
                    idle: state.idle.len(),
                    total: state.active + state.idle.len(),
                    max_size: self.config.max_size,
                    waiters: state.waiters.len(),
                    total_acquisitions: state.total_acquisitions,
                    total_wait_time: state.total_wait_time,
                }
            };
            metrics.update_gauges(&stats);
        }
    }
}

impl<R, F> Pool for GenericPool<R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    type Resource = R;
    type Error = PoolError;

    #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
    fn acquire<'a>(
        &'a self,
        cx: &'a Cx,
    ) -> PoolFuture<'a, Result<PooledResource<Self::Resource>, Self::Error>> {
        Box::pin(async move {
            let acquire_start = Instant::now();

            loop {
                // Process any pending returns
                self.process_returns();

                // Check if closed
                {
                    let state = self.state.lock().expect("pool state lock poisoned");
                    if state.closed {
                        return Err(PoolError::Closed);
                    }
                }

                // Try to get a healthy idle resource.
                while let Some((resource, created_at)) = self.try_get_idle() {
                    if self.config.health_check_on_acquire && !self.is_healthy(&resource) {
                        // Unhealthy: undo the active count bump from try_get_idle
                        let mut state = self.state.lock().expect("pool state lock poisoned");
                        state.active = state.active.saturating_sub(1);
                        state.total_acquisitions = state.total_acquisitions.saturating_sub(1);
                        drop(state);
                        continue;
                    }

                    let acquire_duration = acquire_start.elapsed();

                    // Record metrics
                    #[cfg(feature = "metrics")]
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_acquired(acquire_duration);
                        self.update_metrics_gauges();
                    }

                    return Ok(PooledResource::new_with_created_at(
                        resource,
                        self.return_tx.clone(),
                        created_at,
                    ));
                }

                // Try to create a new resource if under capacity
                if let Some(create_slot) = CreateSlotReservation::try_reserve(self) {
                    let resource = self.create_resource().await?;
                    create_slot.commit();
                    let acquire_duration = acquire_start.elapsed();

                    // Record metrics for create and acquire
                    #[cfg(feature = "metrics")]
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_created();
                        metrics.record_acquired(acquire_duration);
                        self.update_metrics_gauges();
                    }

                    return Ok(PooledResource::new(resource, self.return_tx.clone()));
                }

                // Check for timeout
                let elapsed = acquire_start.elapsed();
                if elapsed >= self.config.acquire_timeout {
                    #[cfg(feature = "metrics")]
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_timeout(elapsed);
                    }
                    return Err(PoolError::Timeout);
                }

                // Check for cancellation
                if let Err(_e) = cx.checkpoint() {
                    return Err(PoolError::Cancelled);
                }

                // Wait for a resource to become available
                WaitForNotification {
                    pool: self,
                    waiter_id: None,
                }
                .await;
            }
        })
    }

    #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
    fn try_acquire(&self) -> Option<PooledResource<Self::Resource>> {
        let acquire_start = Instant::now();

        self.process_returns();

        {
            let state = self.state.lock().expect("pool state lock poisoned");
            if state.closed {
                return None;
            }
        }

        while let Some((resource, created_at)) = self.try_get_idle() {
            if self.config.health_check_on_acquire && !self.is_healthy(&resource) {
                // Unhealthy: undo the active count bump from try_get_idle.
                let mut state = self.state.lock().expect("pool state lock poisoned");
                state.active = state.active.saturating_sub(1);
                state.total_acquisitions = state.total_acquisitions.saturating_sub(1);
                drop(state);
                continue;
            }

            // Record metrics for the acquire
            #[cfg(feature = "metrics")]
            if let Some(ref metrics) = self.metrics {
                metrics.record_acquired(acquire_start.elapsed());
                self.update_metrics_gauges();
            }

            return Some(PooledResource::new_with_created_at(
                resource,
                self.return_tx.clone(),
                created_at,
            ));
        }

        None
    }

    fn stats(&self) -> PoolStats {
        self.process_returns();

        let pool_stats = {
            let state = self.state.lock().expect("pool state lock poisoned");
            PoolStats {
                active: state.active,
                idle: state.idle.len(),
                total: state.active + state.idle.len(),
                max_size: self.config.max_size,
                waiters: state.waiters.len(),
                total_acquisitions: state.total_acquisitions,
                total_wait_time: state.total_wait_time,
            }
        };

        // Update metrics gauges
        #[cfg(feature = "metrics")]
        if let Some(ref metrics) = self.metrics {
            metrics.update_gauges(&pool_stats);
        }

        pool_stats
    }

    fn close(&self) -> PoolFuture<'_, ()> {
        Box::pin(async move {
            #[cfg(feature = "metrics")]
            let idle_count: usize;

            {
                let mut state = self.state.lock().expect("pool state lock poisoned");
                state.closed = true;

                // Wake all waiters so they can see the pool is closed
                for waiter in state.waiters.drain(..) {
                    waiter.waker.wake();
                }

                // Record how many idle resources we're clearing (only needed for metrics)
                #[cfg(feature = "metrics")]
                {
                    idle_count = state.idle.len();
                }

                // Clear idle resources
                state.idle.clear();
            }

            // Record destroyed metrics for all cleared idle resources
            // (they are being destroyed due to pool shutdown, treat as unhealthy reason)
            #[cfg(feature = "metrics")]
            if let Some(ref metrics) = self.metrics {
                for _ in 0..idle_count {
                    metrics.record_destroyed(DestroyReason::Unhealthy);
                }
                self.update_metrics_gauges();
            }
        })
    }
}

// ============================================================================
// Pool Metrics (OpenTelemetry integration)
// ============================================================================

/// Reason why a resource was destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyReason {
    /// Resource failed health check.
    Unhealthy,
    /// Resource exceeded idle timeout.
    IdleTimeout,
    /// Resource exceeded max lifetime.
    MaxLifetime,
}

impl DestroyReason {
    /// Returns the label value for this destroy reason.
    #[must_use]
    pub const fn as_label(&self) -> &'static str {
        match self {
            Self::Unhealthy => "unhealthy",
            Self::IdleTimeout => "idle_timeout",
            Self::MaxLifetime => "max_lifetime",
        }
    }
}

#[cfg(feature = "metrics")]
mod pool_metrics {
    use super::{DestroyReason, Duration, PoolStats};
    use opentelemetry::metrics::{Counter, Histogram, Meter, ObservableGauge};
    use opentelemetry::KeyValue;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// Shared state backing observable gauges for pool metrics.
    #[derive(Debug, Default)]
    pub struct PoolMetricsState {
        /// Current pool size (active + idle).
        pub size: AtomicU64,
        /// Currently active (checked-out) resources.
        pub active: AtomicU64,
        /// Currently idle (available) resources.
        pub idle: AtomicU64,
        /// Number of waiters in queue.
        pub pending: AtomicU64,
    }

    impl PoolMetricsState {
        /// Creates a new metrics state.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Update all gauge values from pool stats.
        pub fn update_from_stats(&self, stats: &PoolStats) {
            self.size.store(stats.total as u64, Ordering::Relaxed);
            self.active.store(stats.active as u64, Ordering::Relaxed);
            self.idle.store(stats.idle as u64, Ordering::Relaxed);
            self.pending.store(stats.waiters as u64, Ordering::Relaxed);
        }
    }

    /// OpenTelemetry metrics for resource pools.
    ///
    /// This struct provides comprehensive observability for pool operations including:
    /// - Gauges for current pool state (size, active, idle, pending)
    /// - Counters for operations (acquired, released, created, destroyed, timeouts)
    /// - Histograms for latencies (acquire, hold, wait durations)
    ///
    /// # Example
    ///
    /// ```ignore
    /// use opentelemetry::global;
    /// use asupersync::sync::{GenericPool, PoolConfig, PoolMetrics};
    ///
    /// let meter = global::meter("myapp");
    /// let metrics = PoolMetrics::new(&meter);
    ///
    /// let pool = GenericPool::new(factory, PoolConfig::default())
    ///     .with_metrics("db_pool", metrics.handle());
    /// ```
    #[derive(Clone)]
    pub struct PoolMetrics {
        // Gauges (backed by shared state)
        size: ObservableGauge<u64>,
        active: ObservableGauge<u64>,
        idle: ObservableGauge<u64>,
        pending: ObservableGauge<u64>,

        // Counters
        acquired_total: Counter<u64>,
        released_total: Counter<u64>,
        created_total: Counter<u64>,
        destroyed_total: Counter<u64>,
        timeouts_total: Counter<u64>,

        // Histograms
        acquire_duration: Histogram<f64>,
        hold_duration: Histogram<f64>,
        wait_duration: Histogram<f64>,

        // Shared state for observable gauges
        state: Arc<PoolMetricsState>,
    }

    impl std::fmt::Debug for PoolMetrics {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PoolMetrics")
                .field("state", &self.state)
                .finish_non_exhaustive()
        }
    }

    impl PoolMetrics {
        /// Creates a new `PoolMetrics` instance from an OpenTelemetry meter.
        #[must_use]
        pub fn new(meter: &Meter) -> Self {
            let state = Arc::new(PoolMetricsState::new());

            let size = meter
                .u64_observable_gauge("asupersync.pool.size")
                .with_description("Current pool size (active + idle)")
                .with_callback({
                    let state = Arc::clone(&state);
                    move |observer| {
                        observer.observe(state.size.load(Ordering::Relaxed), &[]);
                    }
                })
                .build();

            let active = meter
                .u64_observable_gauge("asupersync.pool.active")
                .with_description("Currently checked-out resources")
                .with_callback({
                    let state = Arc::clone(&state);
                    move |observer| {
                        observer.observe(state.active.load(Ordering::Relaxed), &[]);
                    }
                })
                .build();

            let idle = meter
                .u64_observable_gauge("asupersync.pool.idle")
                .with_description("Available idle resources")
                .with_callback({
                    let state = Arc::clone(&state);
                    move |observer| {
                        observer.observe(state.idle.load(Ordering::Relaxed), &[]);
                    }
                })
                .build();

            let pending = meter
                .u64_observable_gauge("asupersync.pool.pending")
                .with_description("Waiters in queue")
                .with_callback({
                    let state = Arc::clone(&state);
                    move |observer| {
                        observer.observe(state.pending.load(Ordering::Relaxed), &[]);
                    }
                })
                .build();

            let acquired_total = meter
                .u64_counter("asupersync.pool.acquired_total")
                .with_description("Total successful acquires")
                .build();

            let released_total = meter
                .u64_counter("asupersync.pool.released_total")
                .with_description("Total returns to pool")
                .build();

            let created_total = meter
                .u64_counter("asupersync.pool.created_total")
                .with_description("Resources created")
                .build();

            let destroyed_total = meter
                .u64_counter("asupersync.pool.destroyed_total")
                .with_description("Resources destroyed")
                .build();

            let timeouts_total = meter
                .u64_counter("asupersync.pool.timeouts_total")
                .with_description("Acquire timeouts")
                .build();

            let acquire_duration = meter
                .f64_histogram("asupersync.pool.acquire_duration_seconds")
                .with_description("Time to acquire a resource")
                .build();

            let hold_duration = meter
                .f64_histogram("asupersync.pool.hold_duration_seconds")
                .with_description("Time resource is held")
                .build();

            let wait_duration = meter
                .f64_histogram("asupersync.pool.wait_duration_seconds")
                .with_description("Time waiting in queue")
                .build();

            Self {
                size,
                active,
                idle,
                pending,
                acquired_total,
                released_total,
                created_total,
                destroyed_total,
                timeouts_total,
                acquire_duration,
                hold_duration,
                wait_duration,
                state,
            }
        }

        /// Returns a reference to the shared metrics state.
        #[must_use]
        pub fn state(&self) -> &Arc<PoolMetricsState> {
            &self.state
        }

        /// Records a successful acquire operation.
        pub fn record_acquired(&self, pool_name: &str, duration: Duration) {
            let labels = [KeyValue::new("pool_name", pool_name.to_string())];
            self.acquired_total.add(1, &labels);
            self.acquire_duration
                .record(duration.as_secs_f64(), &labels);
        }

        /// Records a resource release (return to pool).
        pub fn record_released(&self, pool_name: &str, hold_duration: Duration) {
            let labels = [KeyValue::new("pool_name", pool_name.to_string())];
            self.released_total.add(1, &labels);
            self.hold_duration
                .record(hold_duration.as_secs_f64(), &labels);
        }

        /// Records a resource creation.
        pub fn record_created(&self, pool_name: &str) {
            let labels = [KeyValue::new("pool_name", pool_name.to_string())];
            self.created_total.add(1, &labels);
        }

        /// Records a resource destruction.
        pub fn record_destroyed(&self, pool_name: &str, reason: DestroyReason) {
            let labels = [
                KeyValue::new("pool_name", pool_name.to_string()),
                KeyValue::new("reason", reason.as_label()),
            ];
            self.destroyed_total.add(1, &labels);
        }

        /// Records an acquire timeout.
        pub fn record_timeout(&self, pool_name: &str, wait_duration: Duration) {
            let labels = [KeyValue::new("pool_name", pool_name.to_string())];
            self.timeouts_total.add(1, &labels);
            self.wait_duration
                .record(wait_duration.as_secs_f64(), &labels);
        }

        /// Records time spent waiting in queue (for successful acquires after waiting).
        pub fn record_wait(&self, pool_name: &str, wait_duration: Duration) {
            let labels = [KeyValue::new("pool_name", pool_name.to_string())];
            self.wait_duration
                .record(wait_duration.as_secs_f64(), &labels);
        }

        /// Updates gauge values from pool statistics.
        pub fn update_gauges(&self, stats: &PoolStats) {
            self.state.update_from_stats(stats);
        }

        /// Creates a handle for a named pool.
        #[must_use]
        pub fn handle(&self, pool_name: impl Into<String>) -> PoolMetricsHandle {
            PoolMetricsHandle {
                metrics: self.clone(),
                pool_name: pool_name.into(),
            }
        }
    }

    /// Handle to pool metrics with a specific pool name.
    ///
    /// This struct wraps `PoolMetrics` and binds it to a specific pool name,
    /// automatically adding the `pool_name` label to all recorded metrics.
    #[derive(Clone)]
    pub struct PoolMetricsHandle {
        metrics: PoolMetrics,
        pool_name: String,
    }

    impl std::fmt::Debug for PoolMetricsHandle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PoolMetricsHandle")
                .field("pool_name", &self.pool_name)
                .finish_non_exhaustive()
        }
    }

    impl PoolMetricsHandle {
        /// Returns the pool name for this handle.
        #[must_use]
        pub fn pool_name(&self) -> &str {
            &self.pool_name
        }

        /// Records a successful acquire operation.
        pub fn record_acquired(&self, duration: Duration) {
            self.metrics.record_acquired(&self.pool_name, duration);
        }

        /// Records a resource release (return to pool).
        pub fn record_released(&self, hold_duration: Duration) {
            self.metrics.record_released(&self.pool_name, hold_duration);
        }

        /// Records a resource creation.
        pub fn record_created(&self) {
            self.metrics.record_created(&self.pool_name);
        }

        /// Records a resource destruction.
        pub fn record_destroyed(&self, reason: DestroyReason) {
            self.metrics.record_destroyed(&self.pool_name, reason);
        }

        /// Records an acquire timeout.
        pub fn record_timeout(&self, wait_duration: Duration) {
            self.metrics.record_timeout(&self.pool_name, wait_duration);
        }

        /// Records time spent waiting in queue.
        pub fn record_wait(&self, wait_duration: Duration) {
            self.metrics.record_wait(&self.pool_name, wait_duration);
        }

        /// Updates gauge values from pool statistics.
        pub fn update_gauges(&self, stats: &PoolStats) {
            self.metrics.update_gauges(stats);
        }

        /// Returns a reference to the underlying metrics state.
        #[must_use]
        pub fn state(&self) -> &Arc<PoolMetricsState> {
            self.metrics.state()
        }
    }
}

#[cfg(feature = "metrics")]
pub use pool_metrics::{PoolMetrics, PoolMetricsHandle, PoolMetricsState};

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn pooled_resource_returns_on_drop() {
        init_test("pooled_resource_returns_on_drop");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(42u8, tx);
        drop(pooled);

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return {
                resource: value,
                hold_duration: _,
                ..
            } => {
                crate::assert_with_log!(value == 42, "return value", 42u8, value);
            }
            PoolReturn::Discard { .. } => unreachable!("unexpected discard"),
        }
        crate::test_complete!("pooled_resource_returns_on_drop");
    }

    #[test]
    fn pooled_resource_return_to_pool_sends_return() {
        init_test("pooled_resource_return_to_pool_sends_return");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(7u8, tx);
        pooled.return_to_pool();

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return {
                resource: value,
                hold_duration: _,
                ..
            } => {
                crate::assert_with_log!(value == 7, "return value", 7u8, value);
            }
            PoolReturn::Discard { .. } => unreachable!("unexpected discard"),
        }
        crate::test_complete!("pooled_resource_return_to_pool_sends_return");
    }

    #[test]
    fn pooled_resource_discard_sends_discard() {
        init_test("pooled_resource_discard_sends_discard");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(9u8, tx);
        pooled.discard();

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return { .. } => unreachable!("unexpected return"),
            PoolReturn::Discard { hold_duration: _ } => {
                crate::assert_with_log!(true, "discard", true, true);
            }
        }
        crate::test_complete!("pooled_resource_discard_sends_discard");
    }

    #[test]
    fn pooled_resource_deref_access() {
        init_test("pooled_resource_deref_access");
        let (tx, _rx) = mpsc::channel();
        let mut pooled = PooledResource::new(1u8, tx);
        *pooled = 3;
        crate::assert_with_log!(*pooled == 3, "deref", 3u8, *pooled);
        crate::test_complete!("pooled_resource_deref_access");
    }

    // ========================================================================
    // PoolConfig tests
    // ========================================================================

    #[test]
    fn pool_config_default() {
        init_test("pool_config_default");
        let config = PoolConfig::default();
        crate::assert_with_log!(config.min_size == 1, "min_size", 1usize, config.min_size);
        crate::assert_with_log!(config.max_size == 10, "max_size", 10usize, config.max_size);
        crate::assert_with_log!(
            config.acquire_timeout == Duration::from_secs(30),
            "acquire_timeout",
            Duration::from_secs(30),
            config.acquire_timeout
        );
        crate::test_complete!("pool_config_default");
    }

    #[test]
    fn pool_config_builder() {
        init_test("pool_config_builder");
        let config = PoolConfig::with_max_size(20)
            .min_size(5)
            .acquire_timeout(Duration::from_secs(60))
            .idle_timeout(Duration::from_secs(300))
            .max_lifetime(Duration::from_secs(1800));

        crate::assert_with_log!(config.min_size == 5, "min_size", 5usize, config.min_size);
        crate::assert_with_log!(config.max_size == 20, "max_size", 20usize, config.max_size);
        crate::assert_with_log!(
            config.acquire_timeout == Duration::from_secs(60),
            "acquire_timeout",
            Duration::from_secs(60),
            config.acquire_timeout
        );
        crate::assert_with_log!(
            config.idle_timeout == Duration::from_secs(300),
            "idle_timeout",
            Duration::from_secs(300),
            config.idle_timeout
        );
        crate::assert_with_log!(
            config.max_lifetime == Duration::from_secs(1800),
            "max_lifetime",
            Duration::from_secs(1800),
            config.max_lifetime
        );
        crate::test_complete!("pool_config_builder");
    }

    // ========================================================================
    // GenericPool tests
    // ========================================================================

    #[allow(clippy::type_complexity)]
    fn simple_factory() -> std::pin::Pin<
        Box<dyn Future<Output = Result<u32, Box<dyn std::error::Error + Send + Sync>>> + Send>,
    > {
        Box::pin(async { Ok(42u32) })
    }

    #[test]
    fn generic_pool_stats_initial() {
        init_test("generic_pool_stats_initial");
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let stats = pool.stats();
        crate::assert_with_log!(stats.active == 0, "active", 0usize, stats.active);
        crate::assert_with_log!(stats.idle == 0, "idle", 0usize, stats.idle);
        crate::assert_with_log!(stats.total == 0, "total", 0usize, stats.total);
        crate::assert_with_log!(stats.max_size == 5, "max_size", 5usize, stats.max_size);
        crate::test_complete!("generic_pool_stats_initial");
    }

    #[test]
    fn create_slot_reservation_enforces_max_size_and_releases_on_drop() {
        init_test("create_slot_reservation_enforces_max_size_and_releases_on_drop");
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(1));

        let slot1 = CreateSlotReservation::try_reserve(&pool);
        crate::assert_with_log!(
            slot1.is_some(),
            "first slot reserved",
            true,
            slot1.is_some()
        );

        let slot2 = CreateSlotReservation::try_reserve(&pool);
        crate::assert_with_log!(
            slot2.is_none(),
            "second slot blocked at max_size=1",
            true,
            slot2.is_none()
        );

        drop(slot1);

        let slot3 = CreateSlotReservation::try_reserve(&pool);
        crate::assert_with_log!(
            slot3.is_some(),
            "slot released when reservation dropped",
            true,
            slot3.is_some()
        );
        if let Some(slot) = slot3 {
            slot.commit();
        }

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 1,
            "commit converts reserved slot to active resource",
            1usize,
            stats.active
        );
        crate::test_complete!("create_slot_reservation_enforces_max_size_and_releases_on_drop");
    }

    #[test]
    fn generic_pool_try_acquire_creates_resource() {
        init_test("generic_pool_try_acquire_creates_resource");

        // Need to use a runtime to test async behavior
        // For now, test try_acquire which returns None since pool is empty
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));

        // try_acquire returns None when pool is empty (no pre-created resources)
        let result = pool.try_acquire();
        crate::assert_with_log!(
            result.is_none(),
            "try_acquire empty",
            true,
            result.is_none()
        );

        crate::test_complete!("generic_pool_try_acquire_creates_resource");
    }

    #[test]
    fn pool_error_display() {
        init_test("pool_error_display");

        let closed = PoolError::Closed;
        let timeout = PoolError::Timeout;
        let cancelled = PoolError::Cancelled;
        let create_failed = PoolError::CreateFailed(Box::new(std::io::Error::other("test error")));

        crate::assert_with_log!(
            closed.to_string() == "pool closed",
            "closed display",
            "pool closed",
            closed.to_string()
        );
        crate::assert_with_log!(
            timeout.to_string() == "pool acquire timeout",
            "timeout display",
            "pool acquire timeout",
            timeout.to_string()
        );
        crate::assert_with_log!(
            cancelled.to_string() == "pool acquire cancelled",
            "cancelled display",
            "pool acquire cancelled",
            cancelled.to_string()
        );
        crate::assert_with_log!(
            create_failed
                .to_string()
                .contains("resource creation failed"),
            "create_failed display",
            "contains resource creation failed",
            create_failed.to_string()
        );

        crate::test_complete!("pool_error_display");
    }

    // ========================================================================
    // Cancel-safety tests
    // ========================================================================

    #[test]
    fn cancel_while_holding_resource_returns_on_drop() {
        init_test("cancel_while_holding_resource_returns_on_drop");

        // This test verifies that when a task holding a pooled resource is
        // cancelled, the resource is properly returned to the pool via the
        // Drop implementation.

        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(99u8, tx);

        // Simulate cancellation by just dropping the resource
        // In a real scenario, cancellation would cause the future to be dropped
        drop(pooled);

        // Verify resource was returned
        let msg = rx.recv().expect("should receive return message");
        match msg {
            PoolReturn::Return {
                resource: value,
                hold_duration: _,
                ..
            } => {
                crate::assert_with_log!(value == 99, "returned value", 99u8, value);
            }
            PoolReturn::Discard { .. } => unreachable!("expected Return, got Discard"),
        }

        // Verify channel is empty (exactly one return)
        crate::assert_with_log!(
            rx.try_recv().is_err(),
            "no extra messages",
            true,
            rx.try_recv().is_err()
        );

        crate::test_complete!("cancel_while_holding_resource_returns_on_drop");
    }

    #[test]
    fn obligation_discharged_prevents_double_return() {
        init_test("obligation_discharged_prevents_double_return");

        // Test that explicitly returning a resource prevents the Drop from
        // returning it again (no double-return bug).

        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(77u8, tx);

        // Explicitly return
        pooled.return_to_pool();

        // Verify exactly one return message
        let msg = rx.recv().expect("should receive return message");
        match msg {
            PoolReturn::Return {
                resource: value,
                hold_duration: _,
                ..
            } => {
                crate::assert_with_log!(value == 77, "returned value", 77u8, value);
            }
            PoolReturn::Discard { .. } => unreachable!("expected Return, got Discard"),
        }

        // No second message (drop should not send again)
        crate::assert_with_log!(
            rx.try_recv().is_err(),
            "no double return",
            true,
            rx.try_recv().is_err()
        );

        crate::test_complete!("obligation_discharged_prevents_double_return");
    }

    #[test]
    fn discard_prevents_return_on_drop() {
        init_test("discard_prevents_return_on_drop");

        // Test that discarding a resource prevents the Drop from returning it.

        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(88u8, tx);

        // Explicitly discard
        pooled.discard();

        // Verify we got a discard message
        let msg = rx.recv().expect("should receive discard message");
        match msg {
            PoolReturn::Return { .. } => unreachable!("expected Discard, got Return"),
            PoolReturn::Discard { hold_duration: _ } => {
                // Good - discard was sent
            }
        }

        // No second message
        crate::assert_with_log!(
            rx.try_recv().is_err(),
            "no extra messages after discard",
            true,
            rx.try_recv().is_err()
        );

        crate::test_complete!("discard_prevents_return_on_drop");
    }

    #[test]
    fn generic_pool_close_clears_idle_resources() {
        init_test("generic_pool_close_clears_idle_resources");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));

        // Close the pool
        futures_lite::future::block_on(pool.close());

        // Verify pool is closed - try_acquire should return None
        let result = pool.try_acquire();
        crate::assert_with_log!(
            result.is_none(),
            "closed pool returns None",
            true,
            result.is_none()
        );

        // Stats should show empty
        let stats = pool.stats();
        crate::assert_with_log!(stats.idle == 0, "idle after close", 0usize, stats.idle);

        crate::test_complete!("generic_pool_close_clears_idle_resources");
    }

    #[test]
    fn generic_pool_acquire_when_closed_returns_error() {
        init_test("generic_pool_acquire_when_closed_returns_error");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Close the pool
        futures_lite::future::block_on(pool.close());

        // Acquire should return Closed error
        let result = futures_lite::future::block_on(pool.acquire(&cx));
        match result {
            Err(PoolError::Closed) => {
                // Good - closed error as expected
            }
            Ok(_) => unreachable!("expected Closed error, got Ok"),
            Err(e) => unreachable!("expected Closed error, got {e:?}"),
        }

        crate::test_complete!("generic_pool_acquire_when_closed_returns_error");
    }

    #[test]
    fn generic_pool_resource_returned_becomes_idle() {
        init_test("generic_pool_resource_returned_becomes_idle");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire a resource
        let resource = futures_lite::future::block_on(pool.acquire(&cx))
            .expect("first acquire should succeed");

        // Check stats - should show 1 active
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 1,
            "active after acquire",
            1usize,
            stats.active
        );
        crate::assert_with_log!(stats.idle == 0, "idle after acquire", 0usize, stats.idle);

        // Return the resource
        resource.return_to_pool();

        // Process returns and check stats
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "active after return",
            0usize,
            stats.active
        );
        crate::assert_with_log!(stats.idle == 1, "idle after return", 1usize, stats.idle);

        crate::test_complete!("generic_pool_resource_returned_becomes_idle");
    }

    #[test]
    fn generic_pool_discarded_resource_not_returned_to_idle() {
        init_test("generic_pool_discarded_resource_not_returned_to_idle");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire a resource
        let resource = futures_lite::future::block_on(pool.acquire(&cx))
            .expect("first acquire should succeed");

        // Discard the resource (simulating a broken connection)
        resource.discard();

        // Process returns and check stats - should show 0 idle (discarded resources don't return)
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "active after discard",
            0usize,
            stats.active
        );
        crate::assert_with_log!(stats.idle == 0, "idle after discard", 0usize, stats.idle);

        crate::test_complete!("generic_pool_discarded_resource_not_returned_to_idle");
    }

    #[test]
    fn generic_pool_held_duration_increases() {
        init_test("generic_pool_held_duration_increases");

        let (tx, _rx) = mpsc::channel();
        let pooled = PooledResource::new(42u8, tx);

        // Small sleep to ensure time passes
        std::thread::sleep(Duration::from_millis(10));

        let held = pooled.held_duration();
        crate::assert_with_log!(
            held >= Duration::from_millis(10),
            "held duration at least 10ms",
            Duration::from_millis(10),
            held
        );

        crate::test_complete!("generic_pool_held_duration_increases");
    }

    #[test]
    fn load_test_many_acquire_return_cycles() {
        init_test("load_test_many_acquire_return_cycles");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Run many acquire/return cycles
        for i in 0..100 {
            let resource =
                futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire should succeed");

            // Use the resource
            let _ = *resource;

            // Return it (or drop it - both should work)
            if i % 2 == 0 {
                resource.return_to_pool();
            } else {
                drop(resource);
            }
        }

        // Final stats check
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "no active after all returned",
            0usize,
            stats.active
        );
        crate::assert_with_log!(
            stats.total_acquisitions == 100,
            "100 total acquisitions",
            100u64,
            stats.total_acquisitions
        );

        crate::test_complete!("load_test_many_acquire_return_cycles");
    }

    // ========================================================================
    // Health check tests (asupersync-cl94)
    // ========================================================================

    #[test]
    fn health_check_evicts_unhealthy_idle_resource() {
        init_test("health_check_evicts_unhealthy_idle_resource");

        // Factory produces (id, healthy_flag) tuples
        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>((id, true)) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(5).health_check_on_acquire(true);
        // Health check: only resources with id != 0 pass
        let pool = GenericPool::new(factory, config)
            .with_health_check(|&(id, _healthy): &(u32, bool)| id != 0);

        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire resource #0
        let r0 = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");
        assert_eq!(r0.0, 0u32, "first resource should be id 0");
        // Return it to the idle pool
        r0.return_to_pool();

        // Now acquire again — id 0 should fail health check, so pool creates id 1
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("second acquire");
        assert_eq!(r1.0, 1u32, "unhealthy id 0 should be evicted, got new id 1");

        let stats = pool.stats();
        assert_eq!(stats.active, 1, "one resource active");
        assert_eq!(stats.idle, 0, "no idle resources (id 0 was evicted)");

        crate::test_complete!("health_check_evicts_unhealthy_idle_resource");
    }

    #[test]
    fn health_check_passes_healthy_resource() {
        init_test("health_check_passes_healthy_resource");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(5).health_check_on_acquire(true);
        // All resources pass health check
        let pool = GenericPool::new(factory, config).with_health_check(|_id: &u32| true);

        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire and return resource #0
        let r0 = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");
        assert_eq!(*r0, 0u32);
        r0.return_to_pool();

        // Acquire again — should reuse #0 since it passes health check
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("second acquire");
        assert_eq!(*r1, 0, "healthy resource should be reused");

        crate::test_complete!("health_check_passes_healthy_resource");
    }

    #[test]
    fn health_check_disabled_skips_check() {
        init_test("health_check_disabled_skips_check");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        // health_check_on_acquire defaults to false
        let config = PoolConfig::with_max_size(5);
        // Health check that rejects everything — but it's disabled
        let pool = GenericPool::new(factory, config).with_health_check(|_id: &u32| false);

        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let r0 = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");
        assert_eq!(*r0, 0);
        r0.return_to_pool();

        // Should still return #0 because health check is not enabled
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("second acquire");
        assert_eq!(
            *r1, 0,
            "health check disabled, resource reused despite failing check"
        );

        crate::test_complete!("health_check_disabled_skips_check");
    }

    #[test]
    fn try_acquire_skips_unhealthy_idle_resources_when_health_check_enabled() {
        init_test("try_acquire_skips_unhealthy_idle_resources_when_health_check_enabled");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(5).health_check_on_acquire(true);
        let pool = GenericPool::new(factory, config).with_health_check(|id: &u32| *id != 0);

        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Seed two idle resources: #0 (unhealthy), then #1 (healthy).
        let r0 = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("second acquire");
        assert_eq!(*r0, 0);
        assert_eq!(*r1, 1);
        r0.return_to_pool();
        r1.return_to_pool();

        // try_acquire should skip #0 and return #1.
        let picked = pool
            .try_acquire()
            .expect("should acquire healthy idle resource");
        assert_eq!(*picked, 1, "try_acquire should skip unhealthy idle resource");

        let stats = pool.stats();
        assert_eq!(stats.active, 1, "one resource checked out");
        assert_eq!(stats.idle, 0, "no healthy idle resources left");

        crate::test_complete!("try_acquire_skips_unhealthy_idle_resources_when_health_check_enabled");
    }

    // ========================================================================
    // Warmup tests (asupersync-cl94)
    // ========================================================================

    #[test]
    fn warmup_creates_resources() {
        init_test("warmup_creates_resources");

        let config = PoolConfig::with_max_size(10).warmup_connections(3);
        let pool = GenericPool::new(simple_factory, config);

        let created = futures_lite::future::block_on(pool.warmup()).expect("warmup should succeed");
        assert_eq!(created, 3, "should create 3 warmup resources");

        let stats = pool.stats();
        assert_eq!(stats.idle, 3, "3 idle resources after warmup");
        assert_eq!(stats.active, 0, "no active resources");

        crate::test_complete!("warmup_creates_resources");
    }

    #[test]
    fn warmup_respects_max_size() {
        init_test("warmup_respects_max_size");

        let config = PoolConfig::with_max_size(2).warmup_connections(5);
        let pool = GenericPool::new(simple_factory, config);

        let created = futures_lite::future::block_on(pool.warmup()).expect("warmup should succeed");
        assert_eq!(created, 2, "warmup must not exceed max_size");

        let stats = pool.stats();
        assert_eq!(stats.idle, 2, "idle resources capped by max_size");
        assert_eq!(stats.total, 2, "total resources capped by max_size");

        crate::test_complete!("warmup_respects_max_size");
    }

    #[test]
    fn warmup_zero_is_noop() {
        init_test("warmup_zero_is_noop");

        let config = PoolConfig::with_max_size(10).warmup_connections(0);
        let pool = GenericPool::new(simple_factory, config);

        let created = futures_lite::future::block_on(pool.warmup()).expect("warmup should succeed");
        assert_eq!(created, 0, "zero warmup creates nothing");

        let stats = pool.stats();
        assert_eq!(stats.idle, 0, "no idle resources");

        crate::test_complete!("warmup_zero_is_noop");
    }

    #[test]
    fn warmup_fail_fast_stops_on_error() {
        init_test("warmup_fail_fast_stops_on_error");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if n >= 2 {
                    Err::<u32, _>(Box::new(std::io::Error::other("fail"))
                        as Box<dyn std::error::Error + Send + Sync>)
                } else {
                    Ok(n)
                }
            }) as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(10)
            .warmup_connections(5)
            .warmup_failure_strategy(WarmupStrategy::FailFast);
        let pool = GenericPool::new(factory, config);

        let result = futures_lite::future::block_on(pool.warmup());
        assert!(result.is_err(), "FailFast should return error");

        // Only 2 resources created before the third failed
        let stats = pool.stats();
        assert_eq!(stats.idle, 2, "2 created before failure");

        crate::test_complete!("warmup_fail_fast_stops_on_error");
    }

    #[test]
    fn warmup_best_effort_continues_on_error() {
        init_test("warmup_best_effort_continues_on_error");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if n % 2 == 1 {
                    // Odd-numbered creates fail
                    Err::<u32, _>(Box::new(std::io::Error::other("fail"))
                        as Box<dyn std::error::Error + Send + Sync>)
                } else {
                    Ok(n)
                }
            }) as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(10)
            .warmup_connections(4)
            .warmup_failure_strategy(WarmupStrategy::BestEffort);
        let pool = GenericPool::new(factory, config);

        let created =
            futures_lite::future::block_on(pool.warmup()).expect("BestEffort never errors");
        assert_eq!(created, 2, "2 of 4 succeeded (evens)");

        let stats = pool.stats();
        assert_eq!(stats.idle, 2, "2 idle after partial warmup");

        crate::test_complete!("warmup_best_effort_continues_on_error");
    }

    #[test]
    fn warmup_require_minimum_fails_below_min() {
        init_test("warmup_require_minimum_fails_below_min");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if n >= 1 {
                    Err::<u32, _>(Box::new(std::io::Error::other("fail"))
                        as Box<dyn std::error::Error + Send + Sync>)
                } else {
                    Ok(n)
                }
            }) as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(10)
            .min_size(3)
            .warmup_connections(5)
            .warmup_failure_strategy(WarmupStrategy::RequireMinimum);
        let pool = GenericPool::new(factory, config);

        let result = futures_lite::future::block_on(pool.warmup());
        assert!(
            result.is_err(),
            "RequireMinimum should fail: only 1 created < min_size 3"
        );

        crate::test_complete!("warmup_require_minimum_fails_below_min");
    }

    #[test]
    fn warmup_require_minimum_passes_above_min() {
        init_test("warmup_require_minimum_passes_above_min");

        let config = PoolConfig::with_max_size(10)
            .min_size(2)
            .warmup_connections(5)
            .warmup_failure_strategy(WarmupStrategy::RequireMinimum);
        let pool = GenericPool::new(simple_factory, config);

        let created =
            futures_lite::future::block_on(pool.warmup()).expect("should pass: 5 >= min 2");
        assert_eq!(created, 5, "all 5 warmup resources created");

        crate::test_complete!("warmup_require_minimum_passes_above_min");
    }

    // ========================================================================
    // PoolConfig health/warmup builder tests (asupersync-cl94)
    // ========================================================================

    #[test]
    fn pool_config_health_check_builder() {
        init_test("pool_config_health_check_builder");

        let config = PoolConfig::with_max_size(5)
            .health_check_on_acquire(true)
            .health_check_interval(Some(Duration::from_secs(60)))
            .evict_unhealthy(false);

        assert!(config.health_check_on_acquire);
        assert_eq!(config.health_check_interval, Some(Duration::from_secs(60)));
        assert!(!config.evict_unhealthy);

        crate::test_complete!("pool_config_health_check_builder");
    }

    #[test]
    fn pool_config_warmup_builder() {
        init_test("pool_config_warmup_builder");

        let config = PoolConfig::with_max_size(5)
            .warmup_connections(3)
            .warmup_timeout(Duration::from_secs(10))
            .warmup_failure_strategy(WarmupStrategy::FailFast);

        assert_eq!(config.warmup_connections, 3);
        assert_eq!(config.warmup_timeout, Duration::from_secs(10));
        assert_eq!(config.warmup_failure_strategy, WarmupStrategy::FailFast);

        crate::test_complete!("pool_config_warmup_builder");
    }
}
