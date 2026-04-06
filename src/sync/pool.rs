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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use parking_lot::Mutex as PoolMutex;
use smallvec::SmallVec;

use crate::cx::Cx;

fn wall_clock_now() -> Instant {
    Instant::now()
}

/// Boxed future helper for async trait-like APIs.
pub type PoolFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Sender used to return resources back to a pool.
pub type PoolReturnSender<R> = mpsc::Sender<PoolReturn<R>>;

/// Receiver used to observe resources returning to a pool.
pub type PoolReturnReceiver<R> = mpsc::Receiver<PoolReturn<R>>;

type ReturnWakerEntry = (u64, Waker);
type ReturnWakerList = SmallVec<[ReturnWakerEntry; 4]>;
type ReturnWakers = Arc<PoolMutex<ReturnWakerList>>;

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
    time_getter: fn() -> Instant,
    /// Shared waker list for notifying pool waiters when a resource is
    /// returned.  [`GenericPool`] populates this; custom [`Pool`]
    /// implementations that use only the public `new()` constructor get
    /// `None`, which is harmless — it just means notification relies on
    /// the next `process_returns` call instead of being immediate.
    return_wakers: Option<ReturnWakers>,
}

impl<R> PooledResource<R> {
    /// Creates a new pooled resource wrapper for a freshly created resource.
    ///
    /// This uses the wall clock for hold-duration bookkeeping.
    pub fn new(resource: R, return_tx: PoolReturnSender<R>) -> Self {
        Self::new_with_time_getter(resource, return_tx, wall_clock_now)
    }

    /// Creates a new pooled resource wrapper with a custom time source.
    pub fn new_with_time_getter(
        resource: R,
        return_tx: PoolReturnSender<R>,
        time_getter: fn() -> Instant,
    ) -> Self {
        let now = time_getter();
        Self {
            resource: Some(resource),
            return_obligation: ReturnObligation::new(),
            return_tx,
            acquired_at: now,
            created_at: now,
            time_getter,
            return_wakers: None,
        }
    }

    /// Creates a pooled resource wrapper preserving the original creation time.
    fn new_with_created_at(
        resource: R,
        return_tx: PoolReturnSender<R>,
        created_at: Instant,
        time_getter: fn() -> Instant,
    ) -> Self {
        Self {
            resource: Some(resource),
            return_obligation: ReturnObligation::new(),
            return_tx,
            acquired_at: time_getter(),
            created_at,
            time_getter,
            return_wakers: None,
        }
    }

    /// Attach the shared return-notification wakers from a
    /// [`GenericPool`].  Called internally after construction so that
    /// returning/discarding the resource immediately wakes waiting
    /// acquirers.
    fn with_return_notify(mut self, wakers: ReturnWakers) -> Self {
        self.return_wakers = Some(wakers);
        self
    }

    /// Access the resource.
    #[inline]
    #[must_use]
    pub fn get(&self) -> &R {
        self.resource.as_ref().expect("resource taken")
    }

    /// Mutably access the resource.
    #[inline]
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
        (self.time_getter)().saturating_duration_since(self.acquired_at)
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
        // Wake pool waiters so they re-poll and call process_returns
        // to move the returned resource from the mpsc channel into idle.
        self.notify_return_wakers();
    }

    fn discard_inner(&mut self) {
        if self.return_obligation.is_discharged() {
            return;
        }

        let hold_duration = self.held_duration();
        self.resource.take();
        let _ = self.return_tx.send(PoolReturn::Discard { hold_duration });
        self.return_obligation.discharge();
        // Wake pool waiters — a discard frees a creation slot.
        self.notify_return_wakers();
    }

    /// Wake the first registered pool waiter to act as a dispatcher.
    /// When it polls, it will call `process_returns()` which drains the return
    /// channel and wakes the exact number of subsequent waiters needed based on capacity.
    fn notify_return_wakers(&self) {
        if let Some(ref wakers) = self.return_wakers {
            let waker = {
                let lock = wakers.lock();
                lock.first().map(|(_, waker)| waker.clone())
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
}

impl<R> Drop for PooledResource<R> {
    fn drop(&mut self) {
        self.return_inner();
    }
}

impl<R> std::ops::Deref for PooledResource<R> {
    type Target = R;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<R> std::ops::DerefMut for PooledResource<R> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

// PooledResource is auto-derived as Send when R: Send because all fields
// (Option<R>, ReturnObligation, mpsc::Sender<PoolReturn<R>>, Instant) are Send.
// No manual unsafe impl needed.

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
            idle_timeout: Duration::from_mins(10),
            max_lifetime: Duration::from_hours(1),
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
struct WaitForNotification<'a, 'b, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    pool: &'a GenericPool<R, F>,
    waiter_id: &'b mut Option<u64>,
    cx: &'a Cx,
}

impl<R, F> Future for WaitForNotification<'_, '_, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cx.checkpoint().is_err() {
            return Poll::Ready(());
        }

        self.pool.process_returns();

        let mut state = self.pool.state.lock();

        if state.closed {
            return Poll::Ready(());
        }

        let total_including_creating = state.active + state.idle.len() + state.creating;
        let available = state.idle.len()
            + self
                .pool
                .config
                .max_size
                .saturating_sub(total_including_creating);

        // Single-pass: check if already queued, update waker/register, and get position.
        let pos = if let Some(id) = *self.waiter_id {
            if let Some(idx) = state.waiters.iter().position(|w| w.id == id) {
                let w = &mut state.waiters[idx];
                if !w.waker.will_wake(cx.waker()) {
                    w.waker.clone_from(cx.waker());
                }
                idx
            } else {
                // Was removed by try_get_idle but health check failed.
                // Re-register at the FRONT to preserve FIFO fairness.
                state.waiters.push_front(PoolWaiter {
                    id,
                    waker: cx.waker().clone(),
                });
                0
            }
        } else {
            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
            let idx = state.waiters.len();
            state.waiters.push_back(PoolWaiter {
                id,
                waker: cx.waker().clone(),
            });
            *self.waiter_id = Some(id);
            idx
        };

        let id = self.waiter_id.expect("waiter_id assigned above");
        drop(state);

        if pos < available {
            return Poll::Ready(());
        }

        // Also register in the return_wakers list
        {
            let mut wakers = self.pool.return_wakers.lock();
            if let Some((_, existing)) = wakers.iter_mut().find(|(wid, _)| *wid == id) {
                if !existing.will_wake(cx.waker()) {
                    existing.clone_from(cx.waker());
                }
            } else {
                wakers.push((id, cx.waker().clone()));
            }
        }

        // Process returns again to close the race condition:
        // A resource might have been returned between `drop(state)` and locking `return_wakers`.
        self.pool.process_returns();

        Poll::Pending
    }
}

struct HealthCheckGuard<'a, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    pool: &'a GenericPool<R, F>,
    completed: bool,
}

impl<R, F> Drop for HealthCheckGuard<'_, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    fn drop(&mut self) {
        if !self.completed {
            self.pool.reject_unhealthy_idle_resource();
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
    fn try_reserve(pool: &'a GenericPool<R, F>, waiter_id: Option<u64>) -> Option<Self> {
        if pool.reserve_create_slot(waiter_id) {
            Some(Self {
                pool,
                committed: false,
            })
        } else {
            None
        }
    }

    fn commit(mut self) -> bool {
        let handed_out = self.pool.commit_create_slot();
        self.committed = true;
        handed_out
    }

    /// Mark the reservation as committed without calling
    /// `commit_create_slot`.  The caller is responsible for adjusting
    /// pool accounting (e.g., via `commit_create_slot_as_idle`).
    fn committed_manually(mut self) {
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
    state: PoolMutex<GenericPoolState<R>>,
    /// Channel for returning resources.
    return_tx: PoolReturnSender<R>,
    /// Channel receiver for returned resources.
    return_rx: PoolMutex<PoolReturnReceiver<R>>,
    /// Time source for lifecycle bookkeeping that should remain deterministic
    /// in tests and virtual-time harnesses.
    time_getter: fn() -> Instant,
    /// Optional synchronous health check function.
    ///
    /// When set and `config.health_check_on_acquire` is true, idle resources
    /// are checked before being returned from `acquire()`.
    #[allow(clippy::type_complexity)]
    health_check_fn: Option<Box<dyn Fn(&R) -> bool + Send + Sync>>,
    /// Shared waker list: [`PooledResource`] drains and wakes these on
    /// return/discard so that [`WaitForNotification`] futures are
    /// re-polled immediately instead of waiting for the next
    /// `process_returns` call.
    return_wakers: ReturnWakers,
    /// Lock-free snapshot of `GenericPoolState::closed` (monotone false→true).
    closed: AtomicBool,
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
        Self::with_time_getter(factory, config, wall_clock_now)
    }

    /// Creates a new generic pool with a custom time source for lifecycle
    /// bookkeeping such as idle eviction, hold durations, and warmup-created
    /// timestamps.
    pub fn with_time_getter(factory: F, config: PoolConfig, time_getter: fn() -> Instant) -> Self {
        let (return_tx, return_rx) = mpsc::channel();
        Self {
            factory,
            config,
            state: PoolMutex::new(GenericPoolState {
                idle: std::collections::VecDeque::with_capacity(8),
                active: 0,
                creating: 0,
                total_created: 0,
                total_acquisitions: 0,
                total_wait_time: Duration::ZERO,
                closed: false,
                waiters: std::collections::VecDeque::with_capacity(4),
                next_waiter_id: 0,
            }),
            return_tx,
            return_rx: PoolMutex::new(return_rx),
            time_getter,
            health_check_fn: None,
            return_wakers: Arc::new(PoolMutex::new(SmallVec::new())),
            closed: AtomicBool::new(false),
            #[cfg(feature = "metrics")]
            metrics: None,
        }
    }

    /// Creates a new pool with default configuration.
    pub fn with_factory(factory: F) -> Self {
        Self::new(factory, PoolConfig::default())
    }

    /// Returns the time source used for lifecycle bookkeeping.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Instant {
        self.time_getter
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
    /// - [`PoolConfig::warmup_timeout`]: Applies to the entire warmup phase,
    ///   not each individual create attempt.
    pub async fn warmup(&self) -> Result<usize, PoolError> {
        let mut created = 0;
        let mut last_error = None;
        let warmup_deadline = crate::time::wall_now() + self.config.warmup_timeout;

        let target = self.config.warmup_connections;
        for _ in 0..target {
            // Reserve a creation slot so concurrent acquire() calls see
            // an accurate capacity picture.  Without this, concurrent
            // acquires could exceed max_size during warmup.
            let Some(slot) = CreateSlotReservation::try_reserve(self, None) else {
                break; // max_size reached (possibly by concurrent activity)
            };

            let now = crate::time::wall_now();
            let remaining = Duration::from_nanos(warmup_deadline.duration_since(now));
            let create_result = if remaining.is_zero() {
                Err(PoolError::Timeout)
            } else {
                match crate::time::timeout(now, remaining, self.create_resource()).await {
                    Ok(result) => result,
                    Err(_elapsed) => Err(PoolError::Timeout),
                }
            };

            match create_result {
                Ok(resource) => {
                    // Commit the slot as idle — not active.
                    // CreateSlotReservation::drop is disarmed because we
                    // set committed before drop.
                    slot.committed_manually();
                    self.commit_create_slot_as_idle(resource);
                    created += 1;
                }
                Err(PoolError::Timeout) => match self.config.warmup_failure_strategy {
                    WarmupStrategy::FailFast => return Err(PoolError::Timeout),
                    WarmupStrategy::BestEffort | WarmupStrategy::RequireMinimum => {
                        last_error = Some(PoolError::Timeout);
                        break;
                    }
                },
                Err(e) => {
                    // slot is dropped here → releases the creating count
                    match self.config.warmup_failure_strategy {
                        WarmupStrategy::FailFast => return Err(e),
                        WarmupStrategy::BestEffort | WarmupStrategy::RequireMinimum => {
                            last_error = Some(e);
                        }
                    }
                }
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

    /// Handle an unhealthy idle resource that was popped by `try_get_idle`.
    ///
    /// `try_get_idle` increments `active` and `total_acquisitions` when it
    /// pops an idle entry. If health-check rejects that entry we must undo
    /// those counters, and (when metrics are enabled) record a destroy event.
    fn reject_unhealthy_idle_resource(&self) {
        let waker = {
            let mut state = self.state.lock();
            state.active = state.active.saturating_sub(1);
            state.total_acquisitions = state.total_acquisitions.saturating_sub(1);

            let total = state.active + state.idle.len() + state.creating;
            let available = state.idle.len() + self.config.max_size.saturating_sub(total);
            if available > 0 && available - 1 < state.waiters.len() {
                Some(state.waiters[available - 1].waker.clone())
            } else {
                None
            }
        };

        if let Some(waker) = waker {
            waker.wake();
        }

        #[cfg(feature = "metrics")]
        if let Some(ref metrics) = self.metrics {
            metrics.record_destroyed(DestroyReason::Unhealthy);
            self.update_metrics_gauges();
        }
    }

    /// Process returned resources from the return channel.
    #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
    fn process_returns(&self) {
        let rx = self.return_rx.lock();
        let mut waiters_to_wake: SmallVec<[Waker; 4]> = SmallVec::new();
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

                    let mut state = self.state.lock();
                    state.active = state.active.saturating_sub(1);

                    if !state.closed {
                        state.idle.push_back(IdleResource {
                            resource,
                            idle_since: (self.time_getter)(),
                            created_at,
                        });

                        let total = state.active + state.idle.len() + state.creating;
                        let available =
                            state.idle.len() + self.config.max_size.saturating_sub(total);
                        if available > 0 && available - 1 < state.waiters.len() {
                            waiters_to_wake.push(state.waiters[available - 1].waker.clone());
                        }
                    }
                    drop(state);
                }
                PoolReturn::Discard { hold_duration } => {
                    // Record metrics for the discard (destroyed as unhealthy)
                    #[cfg(feature = "metrics")]
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_released(hold_duration);
                        metrics.record_destroyed(DestroyReason::Unhealthy);
                    }

                    let mut state = self.state.lock();
                    state.active = state.active.saturating_sub(1);

                    let total = state.active + state.idle.len() + state.creating;
                    let available = state.idle.len() + self.config.max_size.saturating_sub(total);
                    if available > 0 && available - 1 < state.waiters.len() {
                        waiters_to_wake.push(state.waiters[available - 1].waker.clone());
                    }
                    drop(state);
                }
            }
        }
        drop(rx);

        for waker in waiters_to_wake {
            waker.wake();
        }
    }

    /// Try to get an idle resource, returning its original creation time.
    fn try_get_idle(&self, waiter_id: Option<u64>) -> Option<(R, Instant)> {
        let mut state = self.state.lock();

        // Evict expired resources first and track eviction reasons for metrics
        let now = (self.time_getter)();
        #[cfg(feature = "metrics")]
        let mut idle_timeout_evictions = 0u64;
        #[cfg(feature = "metrics")]
        let mut max_lifetime_evictions = 0u64;

        state.idle.retain(|idle| {
            let idle_ok = now.saturating_duration_since(idle.idle_since) < self.config.idle_timeout;
            let lifetime_ok =
                now.saturating_duration_since(idle.created_at) < self.config.max_lifetime;

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

        // Evictions don't increase `available` window, so we don't need to wake anyone.
        // The slot is just converted from idle to can_create, so the currently
        // authorized task will just create instead of reusing.

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

        let total = state.active + state.idle.len() + state.creating;
        let available = state.idle.len() + self.config.max_size.saturating_sub(total);

        let pos = waiter_id.map_or_else(
            || state.waiters.len(),
            |id| {
                state
                    .waiters
                    .iter()
                    .position(|w| w.id == id)
                    .unwrap_or(state.waiters.len())
            },
        );

        let can_acquire = pos < available;

        let result = if can_acquire {
            if let Some(idle) = state.idle.pop_front() {
                state.active += 1;
                state.total_acquisitions += 1;
                // Waiter is NOT removed here. It is removed in `acquire` upon success,
                // or remains in queue if health check fails to preserve FIFO.
                Some((idle.resource, idle.created_at))
            } else {
                None
            }
        } else {
            None
        };
        drop(state);

        result
    }

    /// Reserve a creation slot under max-size accounting.
    fn reserve_create_slot(&self, waiter_id: Option<u64>) -> bool {
        let mut state = self.state.lock();
        let total = state.active + state.idle.len() + state.creating;
        if state.closed || total >= self.config.max_size {
            return false;
        }

        let available = state.idle.len() + self.config.max_size.saturating_sub(total);
        let pos = waiter_id.map_or_else(
            || state.waiters.len(),
            |id| {
                state
                    .waiters
                    .iter()
                    .position(|w| w.id == id)
                    .unwrap_or(state.waiters.len())
            },
        );

        if pos >= available {
            return false;
        }

        state.creating += 1;
        if waiter_id.is_some() && pos < state.waiters.len() {
            state.waiters.remove(pos);
        }
        true
    }

    /// Release an uncommitted creation slot and notify one waiter.
    fn release_create_slot(&self) {
        let waker = {
            let mut state = self.state.lock();
            state.creating = state.creating.saturating_sub(1);
            let total = state.active + state.idle.len() + state.creating;
            let available = state.idle.len() + self.config.max_size.saturating_sub(total);
            if available > 0 && available - 1 < state.waiters.len() {
                Some(state.waiters[available - 1].waker.clone())
            } else {
                None
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Commit a completed creation slot into active accounting.
    ///
    /// Returns `true` when the created resource may still be handed out.
    /// If the pool was closed while creation was in flight, this returns
    /// `false` and the caller must drop the freshly created resource.
    fn commit_create_slot(&self) -> bool {
        let mut state = self.state.lock();
        state.creating = state.creating.saturating_sub(1);
        state.total_created += 1;

        if state.closed {
            return false;
        }

        state.active += 1;
        state.total_acquisitions += 1;
        true
    }

    /// Commit a completed creation slot as an idle resource (for warmup).
    /// Unlike `commit_create_slot`, this does NOT increment `active` or
    /// `total_acquisitions` — the resource goes straight to the idle queue.
    fn commit_create_slot_as_idle(&self, resource: R) {
        let waker = {
            let mut state = self.state.lock();
            state.creating = state.creating.saturating_sub(1);
            state.total_created += 1;

            if state.closed {
                // Drop the resource instead of leaking it in the idle queue of a closed pool
                drop(state);
                return;
            }

            let now = (self.time_getter)();
            state.idle.push_back(IdleResource {
                resource,
                idle_since: now,
                created_at: now,
            });

            let total = state.active + state.idle.len() + state.creating;
            let available = state.idle.len() + self.config.max_size.saturating_sub(total);
            if available > 0 && available - 1 < state.waiters.len() {
                Some(state.waiters[available - 1].waker.clone())
            } else {
                None
            }
        };

        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Create a new resource using the factory.
    async fn create_resource(&self) -> Result<R, PoolError> {
        let fut = self.factory.create();
        fut.await.map_err(|e| PoolError::CreateFailed(e.into()))
    }

    /// Remove a waiter by ID.
    fn remove_waiter(&self, id: u64) {
        let mut state = self.state.lock();
        state.waiters.retain(|w| w.id != id);
    }

    /// Record elapsed wait time for blocked acquires.
    #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
    fn record_wait_time(&self, wait_duration: Duration) {
        if wait_duration.is_zero() {
            return;
        }

        let mut state = self.state.lock();
        state.total_wait_time = state
            .total_wait_time
            .checked_add(wait_duration)
            .unwrap_or(Duration::MAX);
        drop(state);

        #[cfg(feature = "metrics")]
        if let Some(ref metrics) = self.metrics {
            metrics.record_wait(wait_duration);
        }
    }

    /// Update metrics gauges from current pool state.
    #[cfg(feature = "metrics")]
    fn update_metrics_gauges(&self) {
        if let Some(ref metrics) = self.metrics {
            let stats = {
                let state = self.state.lock();
                PoolStats {
                    active: state.active,
                    idle: state.idle.len(),
                    total: state.active + state.idle.len() + state.creating,
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
    #[allow(clippy::too_many_lines)]
    fn acquire<'a>(
        &'a self,
        cx: &'a Cx,
    ) -> PoolFuture<'a, Result<PooledResource<Self::Resource>, Self::Error>> {
        Box::pin(async move {
            struct WaiterCleanup<'a, R, F>
            where
                R: Send + 'static,
                F: AsyncResourceFactory<Resource = R>,
            {
                pool: &'a GenericPool<R, F>,
                waiter_id: Option<u64>,
            }

            impl<R, F> Drop for WaiterCleanup<'_, R, F>
            where
                R: Send + 'static,
                F: AsyncResourceFactory<Resource = R>,
            {
                fn drop(&mut self) {
                    if let Some(id) = self.waiter_id {
                        let mut state = self.pool.state.lock();
                        let pos = state.waiters.iter().position(|w| w.id == id);
                        if let Some(p) = pos {
                            state.waiters.remove(p);
                        }

                        let waker: Option<std::task::Waker> = if state.closed {
                            None
                        } else {
                            let total_including_creating =
                                state.active + state.idle.len() + state.creating;
                            let available = state.idle.len()
                                + self
                                    .pool
                                    .config
                                    .max_size
                                    .saturating_sub(total_including_creating);

                            pos.and_then(|p| {
                                if p < available
                                    && available > 0
                                    && available - 1 < state.waiters.len()
                                {
                                    Some(state.waiters[available - 1].waker.clone())
                                } else {
                                    None
                                }
                            })
                        };
                        drop(state);

                        if let Some(w) = waker {
                            w.wake();
                        }
                        self.pool.return_wakers.lock().retain(|(wid, _)| *wid != id);
                    }
                    self.pool.process_returns();
                }
            }

            let get_now = || {
                cx.timer_driver()
                    .map_or_else(crate::time::wall_now, |d| d.now())
            };
            let acquire_start = get_now();
            let mut cleanup = WaiterCleanup {
                pool: self,
                waiter_id: None,
            };

            loop {
                // Process any pending returns
                self.process_returns();

                // Check if closed (lock-free fast path).
                if self.closed.load(Ordering::Acquire) {
                    return Err(PoolError::Closed);
                }

                // Try to get a healthy idle resource.
                while let Some((resource, created_at)) = self.try_get_idle(cleanup.waiter_id) {
                    let is_healthy = if self.config.health_check_on_acquire {
                        let mut guard = HealthCheckGuard {
                            pool: self,
                            completed: false,
                        };
                        let healthy = self.is_healthy(&resource);
                        guard.completed = true;
                        healthy
                    } else {
                        true
                    };

                    if !is_healthy {
                        self.reject_unhealthy_idle_resource();
                        continue;
                    }

                    let id = cleanup.waiter_id.take();
                    if let Some(id) = id {
                        self.return_wakers.lock().retain(|(wid, _)| *wid != id);
                        self.remove_waiter(id);
                    }

                    let acquire_duration =
                        Duration::from_nanos(get_now().duration_since(acquire_start));

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
                        self.time_getter,
                    )
                    .with_return_notify(Arc::clone(&self.return_wakers)));
                }

                // Try to create a new resource if under capacity
                if let Some(create_slot) =
                    CreateSlotReservation::try_reserve(self, cleanup.waiter_id)
                {
                    let id = cleanup.waiter_id.take();
                    if let Some(id) = id {
                        self.return_wakers.lock().retain(|(wid, _)| *wid != id);
                        self.remove_waiter(id);
                    }

                    let now = get_now();
                    let elapsed = Duration::from_nanos(now.duration_since(acquire_start));
                    let remaining = self.config.acquire_timeout.saturating_sub(elapsed);

                    if remaining.is_zero() {
                        #[cfg(feature = "metrics")]
                        if let Some(ref metrics) = self.metrics {
                            metrics.record_timeout(elapsed);
                        }
                        return Err(PoolError::Timeout);
                    }

                    let create_result =
                        crate::time::timeout(now, remaining, self.create_resource()).await;
                    let resource = match create_result {
                        Ok(Ok(res)) => res,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => {
                            #[cfg(feature = "metrics")]
                            if let Some(ref metrics) = self.metrics {
                                metrics.record_timeout(self.config.acquire_timeout);
                            }
                            return Err(PoolError::Timeout);
                        }
                    };

                    let committed = create_slot.commit();
                    let acquire_duration =
                        Duration::from_nanos(get_now().duration_since(acquire_start));

                    // Record metrics for create and acquire
                    #[cfg(feature = "metrics")]
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_created();
                        if committed {
                            metrics.record_acquired(acquire_duration);
                        }
                        self.update_metrics_gauges();
                    }

                    if !committed {
                        return Err(PoolError::Closed);
                    }

                    return Ok(PooledResource::new_with_time_getter(
                        resource,
                        self.return_tx.clone(),
                        self.time_getter,
                    )
                    .with_return_notify(Arc::clone(&self.return_wakers)));
                }

                // Check for timeout
                let now = get_now();
                let elapsed = Duration::from_nanos(now.duration_since(acquire_start));
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
                let wait_started = now;
                let wait_fut = WaitForNotification {
                    pool: self,
                    waiter_id: &mut cleanup.waiter_id,
                    cx,
                };
                if crate::time::timeout(
                    now,
                    self.config.acquire_timeout.saturating_sub(elapsed),
                    wait_fut,
                )
                .await
                .is_err()
                {
                    let wait_duration =
                        Duration::from_nanos(get_now().duration_since(wait_started));
                    #[cfg(feature = "metrics")]
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_timeout(wait_duration);
                    }
                    self.record_wait_time(wait_duration);
                    return Err(PoolError::Timeout);
                }
                self.record_wait_time(Duration::from_nanos(get_now().duration_since(wait_started)));
            }
        })
    }

    #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
    fn try_acquire(&self) -> Option<PooledResource<Self::Resource>> {
        let acquire_start = (self.time_getter)();

        self.process_returns();

        if self.closed.load(Ordering::Acquire) {
            return None;
        }

        while let Some((resource, created_at)) = self.try_get_idle(None) {
            let is_healthy = if self.config.health_check_on_acquire {
                let mut guard = HealthCheckGuard {
                    pool: self,
                    completed: false,
                };
                let healthy = self.is_healthy(&resource);
                guard.completed = true;
                let _ = guard.completed;
                healthy
            } else {
                true
            };

            if !is_healthy {
                self.reject_unhealthy_idle_resource();
                continue;
            }

            // Record metrics for the acquire
            #[cfg(feature = "metrics")]
            if let Some(ref metrics) = self.metrics {
                metrics
                    .record_acquired((self.time_getter)().saturating_duration_since(acquire_start));
                self.update_metrics_gauges();
            }

            return Some(
                PooledResource::new_with_created_at(
                    resource,
                    self.return_tx.clone(),
                    created_at,
                    self.time_getter,
                )
                .with_return_notify(Arc::clone(&self.return_wakers)),
            );
        }

        None
    }

    fn stats(&self) -> PoolStats {
        self.process_returns();

        let pool_stats = {
            let state = self.state.lock();
            PoolStats {
                active: state.active,
                idle: state.idle.len(),
                total: state.active + state.idle.len() + state.creating,
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

            let waiters = {
                let mut state = self.state.lock();
                state.closed = true;
                self.closed.store(true, Ordering::Release);

                // Drain waiters, then wake after releasing the state lock.
                let waiters: SmallVec<[Waker; 4]> =
                    state.waiters.drain(..).map(|waiter| waiter.waker).collect();

                // Record how many idle resources we're clearing (only needed for metrics)
                #[cfg(feature = "metrics")]
                {
                    idle_count = state.idle.len();
                }

                // Clear idle resources
                state.idle.clear();
                waiters
            };

            for waker in waiters {
                waker.wake();
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
    use opentelemetry::KeyValue;
    use opentelemetry::metrics::{Counter, Histogram, Meter, ObservableGauge};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

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
        #[allow(dead_code)]
        size: ObservableGauge<u64>,
        #[allow(dead_code)]
        active: ObservableGauge<u64>,
        #[allow(dead_code)]
        idle: ObservableGauge<u64>,
        #[allow(dead_code)]
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
            let pool_name = pool_name.into();
            let labels = [KeyValue::new("pool_name", pool_name.clone())];
            PoolMetricsHandle {
                metrics: self.clone(),
                pool_name,
                labels,
            }
        }
    }

    /// Handle to pool metrics with a specific pool name.
    ///
    /// This struct wraps `PoolMetrics` and binds it to a specific pool name,
    /// automatically adding the `pool_name` label to all recorded metrics.
    /// The label is pre-computed once at construction to avoid per-call
    /// String allocation.
    #[derive(Clone)]
    pub struct PoolMetricsHandle {
        metrics: PoolMetrics,
        pool_name: String,
        labels: [KeyValue; 1],
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
            self.metrics.acquired_total.add(1, &self.labels);
            self.metrics
                .acquire_duration
                .record(duration.as_secs_f64(), &self.labels);
        }

        /// Records a resource release (return to pool).
        pub fn record_released(&self, hold_duration: Duration) {
            self.metrics.released_total.add(1, &self.labels);
            self.metrics
                .hold_duration
                .record(hold_duration.as_secs_f64(), &self.labels);
        }

        /// Records a resource creation.
        pub fn record_created(&self) {
            self.metrics.created_total.add(1, &self.labels);
        }

        /// Records a resource destruction.
        pub fn record_destroyed(&self, reason: DestroyReason) {
            let labels = [
                self.labels[0].clone(),
                KeyValue::new("reason", reason.as_label()),
            ];
            self.metrics.destroyed_total.add(1, &labels);
        }

        /// Records an acquire timeout.
        pub fn record_timeout(&self, wait_duration: Duration) {
            self.metrics.timeouts_total.add(1, &self.labels);
            self.metrics
                .wait_duration
                .record(wait_duration.as_secs_f64(), &self.labels);
        }

        /// Records time spent waiting in queue.
        pub fn record_wait(&self, wait_duration: Duration) {
            self.metrics
                .wait_duration
                .record(wait_duration.as_secs_f64(), &self.labels);
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
    use std::cell::{Cell, RefCell};
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    use crate::Time;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};

    std::thread_local! {
        static TEST_POOL_TIME_BASE: RefCell<Option<Instant>> = const { RefCell::new(None) };
        static TEST_POOL_TIME_OFFSET_NANOS: Cell<u64> = const { Cell::new(0) };
    }

    fn test_pool_time_now() -> Instant {
        let offset = TEST_POOL_TIME_OFFSET_NANOS.with(Cell::get);
        TEST_POOL_TIME_BASE.with(|base| {
            let mut base = base.borrow_mut();
            let base_instant = *base.get_or_insert_with(Instant::now);
            base_instant
                .checked_add(Duration::from_nanos(offset))
                .unwrap_or(base_instant)
        })
    }

    fn reset_test_pool_time() {
        TEST_POOL_TIME_BASE.with(|base| {
            *base.borrow_mut() = None;
        });
        TEST_POOL_TIME_OFFSET_NANOS.with(|offset| offset.set(0));
    }

    fn set_test_pool_time_offset(offset: Duration) {
        let nanos = offset.as_nanos().min(u128::from(u64::MAX)) as u64;
        TEST_POOL_TIME_OFFSET_NANOS.with(|value| value.set(nanos));
    }

    fn advance_test_pool_time(delta: Duration) {
        let nanos = delta.as_nanos().min(u128::from(u64::MAX)) as u64;
        TEST_POOL_TIME_OFFSET_NANOS.with(|offset| {
            offset.set(offset.get().saturating_add(nanos));
        });
    }

    fn init_test(name: &str) {
        reset_test_pool_time();
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx_with_timer(timer: TimerDriverHandle) -> Cx {
        Cx::new_with_drivers(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer),
            None,
        )
    }

    struct ReentrantReturnWaker {
        return_wakers: ReturnWakers,
        tx: mpsc::Sender<bool>,
    }

    impl Wake for ReentrantReturnWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let lock_was_free = self.return_wakers.try_lock().is_some();
            let _ = self.tx.send(lock_was_free);
        }
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
    fn pooled_resource_return_hold_duration_uses_time_getter() {
        init_test("pooled_resource_return_hold_duration_uses_time_getter");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new_with_time_getter(7u8, tx, test_pool_time_now);

        advance_test_pool_time(Duration::from_millis(15));
        pooled.return_to_pool();

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return {
                resource: value,
                hold_duration,
                ..
            } => {
                crate::assert_with_log!(value == 7, "return value", 7u8, value);
                crate::assert_with_log!(
                    hold_duration == Duration::from_millis(15),
                    "hold duration uses injected time getter",
                    Duration::from_millis(15),
                    hold_duration
                );
            }
            PoolReturn::Discard { .. } => unreachable!("unexpected discard"),
        }

        crate::test_complete!("pooled_resource_return_hold_duration_uses_time_getter");
    }

    #[test]
    fn pooled_resource_notifies_wakers_outside_return_waker_lock() {
        init_test("pooled_resource_notifies_wakers_outside_return_waker_lock");
        let (return_tx, _return_rx) = mpsc::channel();
        let return_wakers = Arc::new(PoolMutex::new(ReturnWakerList::new()));
        let (probe_tx, probe_rx) = mpsc::channel();

        {
            let probe = Arc::new(ReentrantReturnWaker {
                return_wakers: Arc::clone(&return_wakers),
                tx: probe_tx,
            });
            let mut wakers = return_wakers.lock();
            wakers.push((1, Waker::from(probe)));
        }

        let pooled =
            PooledResource::new(7u8, return_tx).with_return_notify(Arc::clone(&return_wakers));
        pooled.return_to_pool();

        let lock_was_free = probe_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("probe wake result");
        crate::assert_with_log!(
            lock_was_free,
            "waker should run after return_wakers lock is released",
            true,
            lock_was_free
        );
        crate::test_complete!("pooled_resource_notifies_wakers_outside_return_waker_lock");
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
    fn pooled_resource_discard_hold_duration_uses_time_getter() {
        init_test("pooled_resource_discard_hold_duration_uses_time_getter");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new_with_time_getter(9u8, tx, test_pool_time_now);

        advance_test_pool_time(Duration::from_millis(12));
        pooled.discard();

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return { .. } => unreachable!("unexpected return"),
            PoolReturn::Discard { hold_duration } => {
                crate::assert_with_log!(
                    hold_duration == Duration::from_millis(12),
                    "discard hold duration uses injected time getter",
                    Duration::from_millis(12),
                    hold_duration
                );
            }
        }

        crate::test_complete!("pooled_resource_discard_hold_duration_uses_time_getter");
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
        crate::assert_with_log!(
            config.idle_timeout == Duration::from_mins(10),
            "idle_timeout",
            Duration::from_mins(10),
            config.idle_timeout
        );
        crate::assert_with_log!(
            config.max_lifetime == Duration::from_hours(1),
            "max_lifetime",
            Duration::from_hours(1),
            config.max_lifetime
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

    struct TimeoutAfterNSuccessesFactory {
        successes: u32,
        next_attempt: std::sync::atomic::AtomicU32,
    }

    impl AsyncResourceFactory for TimeoutAfterNSuccessesFactory {
        type Resource = u32;
        type Error = Box<dyn std::error::Error + Send + Sync>;

        fn create(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<Self::Resource, Self::Error>> + Send + '_>>
        {
            let attempt = self
                .next_attempt
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let successes = self.successes;
            Box::pin(async move {
                if attempt < successes {
                    Ok(attempt)
                } else {
                    std::future::pending::<Result<u32, Box<dyn std::error::Error + Send + Sync>>>()
                        .await
                }
            })
        }
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

        let slot1 = CreateSlotReservation::try_reserve(&pool, None);
        crate::assert_with_log!(
            slot1.is_some(),
            "first slot reserved",
            true,
            slot1.is_some()
        );

        let slot2 = CreateSlotReservation::try_reserve(&pool, None);
        crate::assert_with_log!(
            slot2.is_none(),
            "second slot blocked at max_size=1",
            true,
            slot2.is_none()
        );

        drop(slot1);

        let slot3 = CreateSlotReservation::try_reserve(&pool, None);
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
    fn pool_stats_total_includes_creating_slots() {
        init_test("pool_stats_total_includes_creating_slots");

        // Verify that PoolStats::total includes in-flight creates (the `creating`
        // counter), not just active + idle. This ensures monitoring accurately
        // reflects actual capacity usage.
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(3));

        // Reserve a create slot (simulates async resource creation in progress)
        let slot = CreateSlotReservation::try_reserve(&pool, None);
        assert!(slot.is_some(), "should reserve a create slot");

        let stats = pool.stats();
        // total should be 1 (0 active + 0 idle + 1 creating)
        crate::assert_with_log!(
            stats.total == 1,
            "total includes creating slot",
            1usize,
            stats.total
        );

        // Drop the reservation without committing (simulates cancelled create)
        drop(slot);

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.total == 0,
            "total after released creating slot",
            0usize,
            stats.total
        );

        crate::test_complete!("pool_stats_total_includes_creating_slots");
    }

    #[test]
    fn drop_delegates_to_return_inner_no_double_send() {
        init_test("drop_delegates_to_return_inner_no_double_send");

        // Verify that Drop delegates to return_inner and does not
        // produce double sends on the return channel.
        let (tx, rx) = mpsc::channel();
        {
            let _pooled = PooledResource::new(55u8, tx);
            // _pooled dropped here
        }

        let msg = rx
            .recv()
            .expect("should receive exactly one return message");
        match msg {
            PoolReturn::Return {
                resource: value, ..
            } => {
                crate::assert_with_log!(value == 55, "returned value", 55u8, value);
            }
            PoolReturn::Discard { .. } => unreachable!("expected Return, got Discard"),
        }

        // Verify no second message (no double-send from duplicated drop logic)
        crate::assert_with_log!(
            rx.try_recv().is_err(),
            "no double send from Drop",
            true,
            rx.try_recv().is_err()
        );

        crate::test_complete!("drop_delegates_to_return_inner_no_double_send");
    }

    #[test]
    fn pooled_resource_is_send_when_resource_is_send() {
        fn assert_send<T: Send>() {}

        init_test("pooled_resource_is_send_when_resource_is_send");

        // Verify that PooledResource<R> auto-derives Send when R: Send
        // (no manual unsafe impl needed).
        assert_send::<PooledResource<u8>>();
        assert_send::<PooledResource<String>>();
        assert_send::<PooledResource<Vec<u8>>>();

        crate::test_complete!("pooled_resource_is_send_when_resource_is_send");
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
        let pooled = PooledResource::new_with_time_getter(42u8, tx, test_pool_time_now);
        advance_test_pool_time(Duration::from_millis(10));

        let held = pooled.held_duration();
        crate::assert_with_log!(
            held == Duration::from_millis(10),
            "held duration follows injected clock exactly",
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

    #[test]
    fn record_wait_time_accumulates_in_pool_stats() {
        init_test("record_wait_time_accumulates_in_pool_stats");

        let pool = GenericPool::new(
            simple_factory,
            PoolConfig::with_max_size(1).acquire_timeout(Duration::from_secs(1)),
        );
        let before = pool.stats().total_wait_time;

        pool.record_wait_time(Duration::from_millis(15));
        pool.record_wait_time(Duration::ZERO);

        let stats = pool.stats();
        assert!(
            stats.total_wait_time >= before + Duration::from_millis(15),
            "recorded wait time should be reflected in pool stats, got {:?}",
            stats.total_wait_time
        );

        crate::test_complete!("record_wait_time_accumulates_in_pool_stats");
    }

    #[test]
    fn acquire_timeout_reports_timeout_and_cleans_waiter_state() {
        init_test("acquire_timeout_reports_timeout_and_cleans_waiter_state");

        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = test_cx_with_timer(timer.clone());
        let _guard = Cx::set_current(Some(cx.clone()));
        let pool = GenericPool::with_time_getter(
            simple_factory,
            PoolConfig::with_max_size(1).acquire_timeout(Duration::from_millis(25)),
            test_pool_time_now,
        );

        // Hold the only slot so the next acquire must wait and hit timeout.
        let held = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");

        let waker = noop_pool_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut acquire_fut = std::pin::pin!(pool.acquire(&cx));

        let first_poll = acquire_fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "second acquire should block while pool is exhausted",
            true,
            first_poll.is_pending()
        );
        crate::assert_with_log!(
            pool.stats().waiters == 1,
            "blocked acquire should register exactly one waiter",
            1usize,
            pool.stats().waiters
        );

        advance_test_pool_time(Duration::from_millis(25));
        clock.advance(Time::from_millis(25).as_nanos());
        let _ = timer.process_timers();

        let result = acquire_fut.as_mut().poll(&mut task_cx);

        assert!(
            matches!(result, Poll::Ready(Err(PoolError::Timeout))),
            "second acquire should timeout when pool remains exhausted"
        );

        // Waiter cleanup and wait-time accounting must run even on timeout.
        let stats = pool.stats();
        assert_eq!(stats.waiters, 0, "timeout should not leak waiters");
        assert!(
            stats.total_wait_time == Duration::from_millis(25),
            "timeout wait should be accounted in pool stats; got {got:?}",
            got = stats.total_wait_time
        );

        held.return_to_pool();
        crate::test_complete!("acquire_timeout_reports_timeout_and_cleans_waiter_state");
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
        assert_eq!(
            *picked, 1,
            "try_acquire should skip unhealthy idle resource"
        );

        let stats = pool.stats();
        assert_eq!(stats.active, 1, "one resource checked out");
        assert_eq!(stats.idle, 0, "no healthy idle resources left");

        crate::test_complete!(
            "try_acquire_skips_unhealthy_idle_resources_when_health_check_enabled"
        );
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
    fn warmup_timeout_fail_fast_returns_timeout() {
        init_test("warmup_timeout_fail_fast_returns_timeout");

        let factory = TimeoutAfterNSuccessesFactory {
            successes: 0,
            next_attempt: std::sync::atomic::AtomicU32::new(0),
        };
        let config = PoolConfig::with_max_size(2)
            .warmup_connections(1)
            .warmup_timeout(Duration::from_millis(25))
            .warmup_failure_strategy(WarmupStrategy::FailFast);
        let pool = GenericPool::new(factory, config);

        let result = futures_lite::future::block_on(pool.warmup());
        assert!(
            matches!(result, Err(PoolError::Timeout)),
            "stalled warmup should return PoolError::Timeout under FailFast"
        );

        let stats = pool.stats();
        assert_eq!(stats.total, 0, "timed out warmup must release create slot");
        assert_eq!(
            stats.idle, 0,
            "timed out warmup must not leak idle resources"
        );

        crate::test_complete!("warmup_timeout_fail_fast_returns_timeout");
    }

    #[test]
    fn warmup_timeout_best_effort_returns_partial_progress() {
        init_test("warmup_timeout_best_effort_returns_partial_progress");

        let factory = TimeoutAfterNSuccessesFactory {
            successes: 1,
            next_attempt: std::sync::atomic::AtomicU32::new(0),
        };
        let config = PoolConfig::with_max_size(3)
            .warmup_connections(2)
            .warmup_timeout(Duration::from_millis(25))
            .warmup_failure_strategy(WarmupStrategy::BestEffort);
        let pool = GenericPool::new(factory, config);

        let created =
            futures_lite::future::block_on(pool.warmup()).expect("BestEffort should keep progress");
        assert_eq!(
            created, 1,
            "warmup should report resources created before timeout"
        );

        let stats = pool.stats();
        assert_eq!(
            stats.idle, 1,
            "successful warmup resource should remain idle"
        );
        assert_eq!(
            stats.total, 1,
            "timeout must not retain the stalled create slot"
        );

        crate::test_complete!("warmup_timeout_best_effort_returns_partial_progress");
    }

    #[test]
    fn warmup_timeout_require_minimum_errors_when_min_not_reached() {
        init_test("warmup_timeout_require_minimum_errors_when_min_not_reached");

        let factory = TimeoutAfterNSuccessesFactory {
            successes: 1,
            next_attempt: std::sync::atomic::AtomicU32::new(0),
        };
        let config = PoolConfig::with_max_size(3)
            .min_size(2)
            .warmup_connections(3)
            .warmup_timeout(Duration::from_millis(25))
            .warmup_failure_strategy(WarmupStrategy::RequireMinimum);
        let pool = GenericPool::new(factory, config);

        let result = futures_lite::future::block_on(pool.warmup());
        assert!(
            matches!(result, Err(PoolError::Timeout)),
            "RequireMinimum should surface timeout when min_size is not reached"
        );

        let stats = pool.stats();
        assert_eq!(
            stats.idle, 1,
            "successful creates before timeout should remain usable"
        );
        assert_eq!(stats.total, 1, "timed out create slot must be released");

        crate::test_complete!("warmup_timeout_require_minimum_errors_when_min_not_reached");
    }

    #[test]
    fn warmup_timeout_require_minimum_keeps_progress_once_min_reached() {
        init_test("warmup_timeout_require_minimum_keeps_progress_once_min_reached");

        let factory = TimeoutAfterNSuccessesFactory {
            successes: 1,
            next_attempt: std::sync::atomic::AtomicU32::new(0),
        };
        let config = PoolConfig::with_max_size(3)
            .min_size(1)
            .warmup_connections(3)
            .warmup_timeout(Duration::from_millis(25))
            .warmup_failure_strategy(WarmupStrategy::RequireMinimum);
        let pool = GenericPool::new(factory, config);

        let created = futures_lite::future::block_on(pool.warmup())
            .expect("RequireMinimum should keep partial progress once min_size is met");
        assert_eq!(
            created, 1,
            "warmup should retain successful creates before timeout"
        );

        let stats = pool.stats();
        assert_eq!(
            stats.idle, 1,
            "resource created before timeout should remain idle"
        );
        assert_eq!(stats.total, 1, "timed out create slot must be released");

        crate::test_complete!("warmup_timeout_require_minimum_keeps_progress_once_min_reached");
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

    #[test]
    fn warmup_created_timestamps_follow_time_getter() {
        init_test("warmup_created_timestamps_follow_time_getter");

        set_test_pool_time_offset(Duration::from_secs(86_400));

        let config = PoolConfig::with_max_size(4)
            .warmup_connections(1)
            .max_lifetime(Duration::from_secs(1));
        let pool = GenericPool::with_time_getter(simple_factory, config, test_pool_time_now);

        let created = futures_lite::future::block_on(pool.warmup()).expect("warmup should succeed");
        assert_eq!(created, 1, "warmup should create one idle resource");

        let resource = pool
            .try_acquire()
            .expect("warmup resource should not look immediately expired");
        assert_eq!(*resource, 42u32, "warmup resource should stay reusable");

        resource.return_to_pool();
        crate::test_complete!("warmup_created_timestamps_follow_time_getter");
    }

    // ========================================================================
    // Audit regression tests (asupersync-10x0x.44)
    // ========================================================================

    #[test]
    fn return_to_closed_pool_drops_resource() {
        init_test("return_to_closed_pool_drops_resource");

        // Verify that returning a resource to a closed pool silently drops
        // the resource instead of adding it to the idle queue.
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire a resource
        let resource =
            futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire should succeed");

        // Close the pool while the resource is held
        futures_lite::future::block_on(pool.close());

        // Return the resource — it should be silently dropped, not added to idle
        resource.return_to_pool();

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.idle == 0,
            "no idle after return to closed pool",
            0usize,
            stats.idle
        );
        crate::assert_with_log!(
            stats.active == 0,
            "active decremented despite closed pool",
            0usize,
            stats.active
        );

        crate::test_complete!("return_to_closed_pool_drops_resource");
    }

    #[test]
    fn discard_to_closed_pool_decrements_active() {
        init_test("discard_to_closed_pool_decrements_active");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let resource =
            futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire should succeed");

        futures_lite::future::block_on(pool.close());

        // Discard the resource after pool is closed
        resource.discard();

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "active decremented after discard to closed pool",
            0usize,
            stats.active
        );

        crate::test_complete!("discard_to_closed_pool_decrements_active");
    }

    #[test]
    fn create_slot_reservation_cancel_safety() {
        init_test("create_slot_reservation_cancel_safety");

        // Verify that dropping a CreateSlotReservation without committing
        // correctly releases the slot and wakes a waiter.
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(1));

        // Reserve a slot (simulates start of resource creation)
        let slot = CreateSlotReservation::try_reserve(&pool, None);
        assert!(slot.is_some(), "should reserve slot");

        // Verify pool is at capacity
        let slot2 = CreateSlotReservation::try_reserve(&pool, None);
        assert!(slot2.is_none(), "pool at capacity with one creating slot");

        // Drop without committing (simulates cancel during create)
        drop(slot);

        // Creating count should be back to 0
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.total == 0,
            "total back to 0 after cancelled reservation",
            0usize,
            stats.total
        );

        // Should be able to reserve again
        let slot3 = CreateSlotReservation::try_reserve(&pool, None);
        assert!(slot3.is_some(), "slot available after cancel");
        if let Some(s) = slot3 {
            s.commit();
        }

        crate::test_complete!("create_slot_reservation_cancel_safety");
    }

    #[test]
    fn idle_eviction_respects_idle_timeout() {
        init_test("idle_eviction_respects_idle_timeout");

        let config = PoolConfig::with_max_size(5).idle_timeout(Duration::from_millis(10));
        let pool = GenericPool::with_time_getter(simple_factory, config, test_pool_time_now);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let r = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire");
        r.return_to_pool();

        let stats = pool.stats();
        assert_eq!(stats.idle, 1, "resource should be idle");

        advance_test_pool_time(Duration::from_millis(20));

        let result = pool.try_acquire();
        assert!(
            result.is_none(),
            "expired idle resource should be evicted, try_acquire returns None"
        );

        let stats = pool.stats();
        assert_eq!(
            stats.idle, 0,
            "expired idle resource should have been evicted"
        );

        crate::test_complete!("idle_eviction_respects_idle_timeout");
    }

    #[test]
    fn idle_eviction_respects_max_lifetime() {
        init_test("idle_eviction_respects_max_lifetime");

        let config = PoolConfig::with_max_size(5).max_lifetime(Duration::from_millis(10));
        let pool = GenericPool::with_time_getter(simple_factory, config, test_pool_time_now);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let r = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire");
        r.return_to_pool();

        advance_test_pool_time(Duration::from_millis(20));

        let result = pool.try_acquire();
        assert!(
            result.is_none(),
            "resource past max_lifetime should be evicted"
        );

        let stats = pool.stats();
        assert_eq!(
            stats.idle, 0,
            "expired resource should be evicted from idle"
        );

        crate::test_complete!("idle_eviction_respects_max_lifetime");
    }

    #[test]
    fn multiple_acquire_return_cycles_keep_accounting_consistent() {
        init_test("multiple_acquire_return_cycles_keep_accounting_consistent");

        // Verify that mixed return_to_pool, discard, and implicit drop
        // all keep the accounting correct over many cycles.
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(3));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        for i in 0..50 {
            let r = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire");
            match i % 3 {
                0 => r.return_to_pool(),
                1 => r.discard(),
                _ => drop(r), // implicit return via Drop
            }
        }

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "no active after all returned/discarded",
            0usize,
            stats.active
        );
        crate::assert_with_log!(
            stats.total_acquisitions == 50,
            "50 total acquisitions",
            50u64,
            stats.total_acquisitions
        );

        crate::test_complete!("multiple_acquire_return_cycles_keep_accounting_consistent");
    }

    #[test]
    fn warmup_resources_reused_by_acquire() {
        init_test("warmup_resources_reused_by_acquire");

        // Verify that warmup resources are available for acquire.
        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(10).warmup_connections(2);
        let pool = GenericPool::new(factory, config);

        let created = futures_lite::future::block_on(pool.warmup()).expect("warmup should succeed");
        assert_eq!(created, 2);

        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire should reuse warmup resources (ids 0 and 1), not create new ones
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire 1");
        let r2 = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire 2");

        // Both should be from warmup (ids 0 or 1)
        assert!(
            *r1 <= 1u32 && *r2 <= 1u32,
            "warmup resources should be reused: got {} and {}",
            *r1,
            *r2
        );
        assert_ne!(*r1, *r2, "should be different resources");

        crate::test_complete!("warmup_resources_reused_by_acquire");
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

    // ========================================================================
    // Invariant tests: cancel-safety, exhaustion, factory errors
    // ========================================================================

    /// Invariant: dropping an acquire future that is suspended inside
    /// `WaitForNotification` removes the waiter from the queue.
    #[test]
    #[allow(unsafe_code)]
    fn pool_cancel_during_wait_does_not_leak_waiter() {
        init_test("pool_cancel_during_wait_does_not_leak_waiter");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(1));
        let cx_handle: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire the one resource so pool is at capacity.
        let held = futures_lite::future::block_on(pool.acquire(&cx_handle)).expect("first acquire");

        // Create a second acquire future. It will enter WaitForNotification
        // because the pool is exhausted (max_size=1, active=1).
        let waker = noop_pool_waker();
        let mut task_cx = std::task::Context::from_waker(&waker);
        {
            let mut acquire_fut = pool.acquire(&cx_handle);
            // SAFETY: acquire_fut lives on the stack and we do not move it.
            let pinned = std::pin::Pin::new(&mut acquire_fut);
            let poll_result = pinned.poll(&mut task_cx);
            // Should be Pending — pool is full.
            let is_pending = poll_result.is_pending();
            crate::assert_with_log!(is_pending, "acquire is Pending", true, is_pending);

            // Verify a waiter was registered.
            let waiters_before = pool.stats().waiters;
            crate::assert_with_log!(
                waiters_before >= 1,
                "waiter registered",
                true,
                waiters_before >= 1
            );
            // acquire_fut dropped here — WaitForNotification::drop fires.
        }

        // After drop, waiters must be 0.
        let waiters_after = pool.stats().waiters;
        crate::assert_with_log!(
            waiters_after == 0,
            "waiter cleaned on drop",
            0usize,
            waiters_after
        );

        // Return the held resource and verify normal operation.
        held.return_to_pool();
        let reacquired = futures_lite::future::block_on(pool.acquire(&cx_handle));
        let ok = reacquired.is_ok();
        crate::assert_with_log!(ok, "reacquire succeeds", true, ok);

        crate::test_complete!("pool_cancel_during_wait_does_not_leak_waiter");
    }

    /// Invariant: when the pool is at capacity, acquire blocks; when a
    /// resource is returned, the blocked acquirer is woken and succeeds.
    #[test]
    fn pool_exhaustion_blocks_then_unblocks_on_return() {
        init_test("pool_exhaustion_blocks_then_unblocks_on_return");

        let pool = Arc::new(GenericPool::new(
            simple_factory,
            PoolConfig::with_max_size(1),
        ));
        let cx_handle: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire the single resource.
        let held = futures_lite::future::block_on(pool.acquire(&cx_handle)).expect("first acquire");
        let held_val = *held;

        // Spawn a thread that will block on acquire.
        let pool2 = Arc::clone(&pool);
        let blocker = std::thread::spawn(move || {
            let cx2: crate::cx::Cx = crate::cx::Cx::for_testing();
            let waker = noop_pool_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut acquire_fut = std::pin::pin!(pool2.acquire(&cx2));

            match acquire_fut.as_mut().poll(&mut task_cx) {
                Poll::Pending => {}
                Poll::Ready(result) => return result,
            }

            loop {
                match acquire_fut.as_mut().poll(&mut task_cx) {
                    Poll::Ready(result) => return result,
                    Poll::Pending => std::thread::yield_now(),
                }
            }
        });

        let mut waiter_registered = false;
        for _ in 0..4_096 {
            if pool.stats().waiters == 1 {
                waiter_registered = true;
                break;
            }
            std::thread::yield_now();
        }
        crate::assert_with_log!(
            waiter_registered,
            "blocker should register as a waiter without sleep-based synchronization",
            true,
            waiter_registered
        );

        // Return the resource — this should wake the blocked acquirer.
        held.return_to_pool();

        let result = blocker.join().expect("blocker thread panicked");
        let acquired = result.expect("blocked acquire should succeed");
        let val = *acquired;
        crate::assert_with_log!(
            val == held_val,
            "blocked acquirer got returned resource",
            held_val,
            val
        );

        crate::test_complete!("pool_exhaustion_blocks_then_unblocks_on_return");
    }

    /// Invariant: returning one resource from an exhausted pool only wakes one
    /// waiter; remaining waiters stay queued until another resource return.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn pool_return_wakes_waiters_one_at_a_time() {
        init_test("pool_return_wakes_waiters_one_at_a_time");

        let pool = Arc::new(GenericPool::new(
            simple_factory,
            PoolConfig::with_max_size(1),
        ));
        let cx_handle: crate::cx::Cx = crate::cx::Cx::for_testing();
        let held = futures_lite::future::block_on(pool.acquire(&cx_handle)).expect("first acquire");

        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();
        let (release_second_tx, release_second_rx) = std::sync::mpsc::channel();

        let first_waiter_pool = Arc::clone(&pool);
        let first_waiter_tx = acquired_tx.clone();
        let first_waiter = std::thread::spawn(move || {
            let cx = crate::cx::Cx::for_testing();
            let acquired =
                futures_lite::future::block_on(first_waiter_pool.acquire(&cx)).expect("waiter A");
            first_waiter_tx
                .send(1usize)
                .expect("send waiter A acquisition");
            release_first_rx.recv().expect("waiter A release signal");
            acquired.return_to_pool();
        });

        let second_waiter_pool = Arc::clone(&pool);
        let second_waiter_tx = acquired_tx;
        let second_waiter = std::thread::spawn(move || {
            let cx = crate::cx::Cx::for_testing();
            let acquired =
                futures_lite::future::block_on(second_waiter_pool.acquire(&cx)).expect("waiter B");
            second_waiter_tx
                .send(2usize)
                .expect("send waiter B acquisition");
            release_second_rx.recv().expect("waiter B release signal");
            acquired.return_to_pool();
        });

        let mut both_waiters_registered = false;
        for _ in 0..4_096 {
            if pool.stats().waiters == 2 {
                both_waiters_registered = true;
                break;
            }
            std::thread::yield_now();
        }
        crate::assert_with_log!(
            both_waiters_registered,
            "both blocked acquirers should register as waiters",
            true,
            both_waiters_registered
        );

        held.return_to_pool();

        let first = acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first waiter should wake");

        let mut one_waiter_still_blocked = false;
        for _ in 0..4_096 {
            let stats = pool.stats();
            if stats.waiters == 1 && stats.active == 1 {
                one_waiter_still_blocked = true;
                break;
            }
            std::thread::yield_now();
        }
        crate::assert_with_log!(
            one_waiter_still_blocked,
            "one waiter should remain queued while the woken waiter holds the resource",
            true,
            one_waiter_still_blocked
        );

        match first {
            1 => release_first_tx.send(()).expect("release waiter A"),
            2 => release_second_tx.send(()).expect("release waiter B"),
            other => panic!("unexpected waiter id: {other}"),
        }

        let second = acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second waiter should wake after the next return");
        crate::assert_with_log!(
            first != second,
            "resource returns should wake distinct waiters sequentially",
            true,
            first != second
        );

        let mut no_waiters_left = false;
        for _ in 0..4_096 {
            let stats = pool.stats();
            if stats.waiters == 0 && stats.active == 1 {
                no_waiters_left = true;
                break;
            }
            std::thread::yield_now();
        }
        crate::assert_with_log!(
            no_waiters_left,
            "second wake should drain the waiter queue while the final borrower holds the resource",
            true,
            no_waiters_left
        );

        match second {
            1 => release_first_tx
                .send(())
                .expect("release waiter A after second wake"),
            2 => release_second_tx
                .send(())
                .expect("release waiter B after second wake"),
            other => panic!("unexpected waiter id: {other}"),
        }

        first_waiter.join().expect("waiter A should not panic");
        second_waiter.join().expect("waiter B should not panic");

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.waiters == 0,
            "all waiters should be drained after both resources are returned",
            0usize,
            stats.waiters
        );
        crate::assert_with_log!(
            stats.active == 0,
            "no active resources should remain after both waiters release",
            0usize,
            stats.active
        );
        crate::assert_with_log!(
            stats.idle == 1,
            "the single pooled resource should be returned to idle storage",
            1usize,
            stats.idle
        );
        crate::assert_with_log!(
            stats.total == 1,
            "capacity accounting should settle back to a single retained resource",
            1usize,
            stats.total
        );

        crate::test_complete!("pool_return_wakes_waiters_one_at_a_time");
    }

    /// Invariant: if the factory returns an error during acquire, the
    /// creating slot is released and does not permanently reduce capacity.
    #[test]
    fn pool_factory_error_releases_create_slot() {
        init_test("pool_factory_error_releases_create_slot");

        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = Arc::clone(&call_count);

        // Factory that fails on the first call, succeeds on subsequent ones.
        let factory = move || {
            let count = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if count == 0 {
                    Err::<u32, Box<dyn std::error::Error + Send + Sync>>(
                        "deliberate factory error".into(),
                    )
                } else {
                    Ok(count)
                }
            })
                as std::pin::Pin<
                    Box<
                        dyn Future<Output = Result<u32, Box<dyn std::error::Error + Send + Sync>>>
                            + Send,
                    >,
                >
        };

        let pool = GenericPool::new(factory, PoolConfig::with_max_size(2));
        let cx_handle: crate::cx::Cx = crate::cx::Cx::for_testing();

        // First acquire should fail (factory error).
        let first = futures_lite::future::block_on(pool.acquire(&cx_handle));
        let is_err = first.is_err();
        crate::assert_with_log!(is_err, "first acquire fails", true, is_err);

        // After the error, creating count must be 0 (slot released by RAII).
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.total == 0,
            "no phantom slot leaked",
            0usize,
            stats.total
        );

        // Second acquire should succeed (factory returns Ok now).
        let second = futures_lite::future::block_on(pool.acquire(&cx_handle));
        let ok = second.is_ok();
        crate::assert_with_log!(ok, "second acquire succeeds", true, ok);

        crate::test_complete!("pool_factory_error_releases_create_slot");
    }

    struct DropTrackedResource {
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for DropTrackedResource {
        fn drop(&mut self) {
            self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn pool_close_while_create_in_flight_returns_closed() {
        init_test("pool_close_while_create_in_flight_returns_closed");

        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (unblock_tx, unblock_rx) = std::sync::mpsc::channel();
        let unblock_rx = Arc::new(std::sync::Mutex::new(unblock_rx));
        let drop_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let factory = {
            let unblock_rx = Arc::clone(&unblock_rx);
            let drop_count = Arc::clone(&drop_count);
            move || {
                let unblock_rx = Arc::clone(&unblock_rx);
                let entered_tx = entered_tx.clone();
                let drop_count = Arc::clone(&drop_count);
                Box::pin(async move {
                    entered_tx.send(()).expect("factory entered");
                    unblock_rx
                        .lock()
                        .expect("factory unblock receiver lock")
                        .recv()
                        .expect("factory unblock signal");
                    Ok::<DropTrackedResource, Box<dyn std::error::Error + Send + Sync>>(
                        DropTrackedResource { drops: drop_count },
                    )
                })
                    as std::pin::Pin<
                        Box<
                            dyn Future<
                                    Output = Result<
                                        DropTrackedResource,
                                        Box<dyn std::error::Error + Send + Sync>,
                                    >,
                                > + Send,
                        >,
                    >
            }
        };

        let pool = Arc::new(GenericPool::new(factory, PoolConfig::with_max_size(1)));
        let acquire_pool = Arc::clone(&pool);
        let (result_tx, result_rx) = std::sync::mpsc::channel();

        let worker = std::thread::spawn(move || {
            let cx_handle: crate::cx::Cx = crate::cx::Cx::for_testing();
            let result =
                futures_lite::future::block_on(acquire_pool.acquire(&cx_handle)).map(|_| ());
            result_tx.send(result).expect("send acquire result");
        });

        entered_rx.recv().expect("wait for factory entry");
        futures_lite::future::block_on(pool.close());
        unblock_tx.send(()).expect("unblock factory");

        let result = result_rx.recv().expect("receive acquire result");
        crate::assert_with_log!(
            matches!(result, Err(PoolError::Closed)),
            "acquire returns closed once close wins the create race",
            true,
            matches!(result, Err(PoolError::Closed))
        );

        worker.join().expect("worker thread panicked");

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "no active resources leaked",
            0usize,
            stats.active
        );
        crate::assert_with_log!(
            stats.total == 0,
            "no total capacity leaked",
            0usize,
            stats.total
        );

        let reacquire = pool.try_acquire();
        crate::assert_with_log!(
            reacquire.is_none(),
            "closed pool does not expose created resource",
            true,
            reacquire.is_none()
        );
        crate::assert_with_log!(
            drop_count.load(std::sync::atomic::Ordering::SeqCst) == 1,
            "freshly created resource is dropped when close wins create race",
            1usize,
            drop_count.load(std::sync::atomic::Ordering::SeqCst)
        );

        crate::test_complete!("pool_close_while_create_in_flight_returns_closed");
    }

    // =========================================================================
    // Pure data-type tests (wave 42 – CyanBarn)
    // =========================================================================

    #[test]
    fn warmup_strategy_debug_clone_copy_eq_default() {
        let def = WarmupStrategy::default();
        assert_eq!(def, WarmupStrategy::BestEffort);
        for s in [
            WarmupStrategy::BestEffort,
            WarmupStrategy::FailFast,
            WarmupStrategy::RequireMinimum,
        ] {
            let copied = s;
            let cloned = s;
            assert_eq!(copied, cloned);
            let dbg = format!("{s:?}");
            assert!(!dbg.is_empty());
        }
        assert_ne!(WarmupStrategy::BestEffort, WarmupStrategy::FailFast);
        assert_ne!(WarmupStrategy::FailFast, WarmupStrategy::RequireMinimum);
    }

    #[test]
    fn destroy_reason_debug_clone_copy_eq() {
        for r in [
            DestroyReason::Unhealthy,
            DestroyReason::IdleTimeout,
            DestroyReason::MaxLifetime,
        ] {
            let copied = r;
            let cloned = r;
            assert_eq!(copied, cloned);
            let dbg = format!("{r:?}");
            assert!(!dbg.is_empty());
        }
        assert_ne!(DestroyReason::Unhealthy, DestroyReason::IdleTimeout);
        assert_eq!(DestroyReason::Unhealthy.as_label(), "unhealthy");
        assert_eq!(DestroyReason::IdleTimeout.as_label(), "idle_timeout");
        assert_eq!(DestroyReason::MaxLifetime.as_label(), "max_lifetime");
    }

    #[test]
    fn pool_stats_debug_clone_default() {
        let def = PoolStats::default();
        assert_eq!(def.active, 0);
        assert_eq!(def.idle, 0);
        assert_eq!(def.total, 0);
        assert_eq!(def.total_acquisitions, 0);
        let cloned = def.clone();
        assert_eq!(cloned.active, 0);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("PoolStats"));
    }

    fn noop_pool_waker() -> Waker {
        struct NoopPoolWaker;

        impl Wake for NoopPoolWaker {
            fn wake(self: Arc<Self>) {}
            fn wake_by_ref(self: &Arc<Self>) {}
        }

        Waker::from(Arc::new(NoopPoolWaker))
    }
}
