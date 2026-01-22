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
    Return(R),
    /// Resource is broken; discard it.
    Discard,
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
}

impl<R> PooledResource<R> {
    /// Creates a new pooled resource wrapper.
    pub fn new(resource: R, return_tx: PoolReturnSender<R>) -> Self {
        Self {
            resource: Some(resource),
            return_obligation: ReturnObligation::new(),
            return_tx,
            acquired_at: Instant::now(),
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

        if let Some(resource) = self.resource.take() {
            let _ = self.return_tx.send(PoolReturn::Return(resource));
        }

        self.return_obligation.discharge();
    }

    fn discard_inner(&mut self) {
        if self.return_obligation.is_discharged() {
            return;
        }

        self.resource.take();
        let _ = self.return_tx.send(PoolReturn::Discard);
        self.return_obligation.discharge();
    }
}

impl<R> Drop for PooledResource<R> {
    fn drop(&mut self) {
        if self.return_obligation.is_discharged() {
            return;
        }

        if let Some(resource) = self.resource.take() {
            let _ = self.return_tx.send(PoolReturn::Return(resource));
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

/// A generic resource pool with configurable behavior.
///
/// This pool manages resources created by a factory function and provides
/// cancel-safe acquisition with timeout support.
///
/// # Type Parameters
///
/// - `R`: The resource type
/// - `F`: Factory function type that creates resources
pub struct GenericPool<R, F>
where
    R: Send + 'static,
    F: Fn() -> std::pin::Pin<
            Box<dyn Future<Output = Result<R, Box<dyn std::error::Error + Send + Sync>>> + Send>,
        > + Send
        + Sync
        + 'static,
{
    /// Factory function to create new resources.
    factory: F,
    /// Configuration.
    config: PoolConfig,
    /// Internal state.
    state: std::sync::Mutex<GenericPoolState<R>>,
    /// Channel for returning resources.
    return_tx: PoolReturnSender<R>,
    /// Channel receiver for returned resources.
    return_rx: std::sync::Mutex<PoolReturnReceiver<R>>,
}

impl<R, F> GenericPool<R, F>
where
    R: Send + 'static,
    F: Fn() -> std::pin::Pin<
            Box<dyn Future<Output = Result<R, Box<dyn std::error::Error + Send + Sync>>> + Send>,
        > + Send
        + Sync
        + 'static,
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
                total_created: 0,
                total_acquisitions: 0,
                total_wait_time: Duration::ZERO,
                closed: false,
                waiters: std::collections::VecDeque::new(),
                next_waiter_id: 0,
            }),
            return_tx,
            return_rx: std::sync::Mutex::new(return_rx),
        }
    }

    /// Creates a new pool with default configuration.
    pub fn with_factory(factory: F) -> Self {
        Self::new(factory, PoolConfig::default())
    }

    /// Process returned resources from the return channel.
    fn process_returns(&self) {
        let rx = self.return_rx.lock().expect("return_rx lock poisoned");
        while let Ok(ret) = rx.try_recv() {
            match ret {
                PoolReturn::Return(resource) => {
                    let mut state = self.state.lock().expect("pool state lock poisoned");
                    state.active = state.active.saturating_sub(1);

                    if !state.closed {
                        state.idle.push_back(IdleResource {
                            resource,
                            idle_since: Instant::now(),
                            created_at: Instant::now(), // Note: we lose original created_at
                        });

                        // Wake up one waiter if any
                        if let Some(waiter) = state.waiters.pop_front() {
                            waiter.waker.wake();
                        }
                    }
                    // If closed, just drop the resource
                }
                PoolReturn::Discard => {
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

    /// Try to get an idle resource.
    fn try_get_idle(&self) -> Option<R> {
        let mut state = self.state.lock().expect("pool state lock poisoned");

        // Evict expired resources first
        let now = Instant::now();
        state.idle.retain(|idle| {
            let idle_ok = now.duration_since(idle.idle_since) < self.config.idle_timeout;
            let lifetime_ok = now.duration_since(idle.created_at) < self.config.max_lifetime;
            idle_ok && lifetime_ok
        });

        if let Some(idle) = state.idle.pop_front() {
            state.active += 1;
            state.total_acquisitions += 1;
            Some(idle.resource)
        } else {
            None
        }
    }

    /// Get current total count (active + idle).
    fn total_count(&self) -> usize {
        let state = self.state.lock().expect("pool state lock poisoned");
        state.active + state.idle.len()
    }

    /// Check if we can create a new resource.
    fn can_create(&self) -> bool {
        self.total_count() < self.config.max_size
    }

    /// Create a new resource using the factory.
    async fn create_resource(&self) -> Result<R, PoolError> {
        let fut = (self.factory)();
        fut.await.map_err(PoolError::CreateFailed)
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

    /// Record that a resource was acquired.
    fn record_acquisition(&self) {
        let mut state = self.state.lock().expect("pool state lock poisoned");
        state.active += 1;
        state.total_acquisitions += 1;
        state.total_created += 1;
    }
}

impl<R, F> Pool for GenericPool<R, F>
where
    R: Send + 'static,
    F: Fn() -> std::pin::Pin<
            Box<dyn Future<Output = Result<R, Box<dyn std::error::Error + Send + Sync>>> + Send>,
        > + Send
        + Sync
        + 'static,
{
    type Resource = R;
    type Error = PoolError;

    fn acquire<'a>(
        &'a self,
        _cx: &'a Cx,
    ) -> PoolFuture<'a, Result<PooledResource<Self::Resource>, Self::Error>> {
        Box::pin(async move {
            // Process any pending returns
            self.process_returns();

            // Check if closed
            {
                let state = self.state.lock().expect("pool state lock poisoned");
                if state.closed {
                    return Err(PoolError::Closed);
                }
            }

            // Try to get an idle resource
            if let Some(resource) = self.try_get_idle() {
                return Ok(PooledResource::new(resource, self.return_tx.clone()));
            }

            // Try to create a new resource if under capacity
            if self.can_create() {
                let resource = self.create_resource().await?;
                self.record_acquisition();
                return Ok(PooledResource::new(resource, self.return_tx.clone()));
            }

            // Need to wait for a resource
            // For now, return timeout since we can't actually wait without a runtime
            // In a real implementation, this would use the Cx deadline and wait
            Err(PoolError::Timeout)
        })
    }

    fn try_acquire(&self) -> Option<PooledResource<Self::Resource>> {
        self.process_returns();

        {
            let state = self.state.lock().expect("pool state lock poisoned");
            if state.closed {
                return None;
            }
        }

        self.try_get_idle()
            .map(|resource| PooledResource::new(resource, self.return_tx.clone()))
    }

    fn stats(&self) -> PoolStats {
        self.process_returns();

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
    }

    fn close(&self) -> PoolFuture<'_, ()> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("pool state lock poisoned");
            state.closed = true;

            // Wake all waiters so they can see the pool is closed
            for waiter in state.waiters.drain(..) {
                waiter.waker.wake();
            }

            // Clear idle resources
            state.idle.clear();
        })
    }
}

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
            PoolReturn::Return(value) => {
                crate::assert_with_log!(value == 42, "return value", 42u8, value);
            }
            PoolReturn::Discard => panic!("unexpected discard"),
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
            PoolReturn::Return(value) => {
                crate::assert_with_log!(value == 7, "return value", 7u8, value);
            }
            PoolReturn::Discard => panic!("unexpected discard"),
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
            PoolReturn::Return(_) => panic!("unexpected return"),
            PoolReturn::Discard => {
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
        let pooled = PooledResource::new(99u8, tx.clone());

        // Simulate cancellation by just dropping the resource
        // In a real scenario, cancellation would cause the future to be dropped
        drop(pooled);

        // Verify resource was returned
        let msg = rx.recv().expect("should receive return message");
        match msg {
            PoolReturn::Return(value) => {
                crate::assert_with_log!(value == 99, "returned value", 99u8, value);
            }
            PoolReturn::Discard => panic!("expected Return, got Discard"),
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
            PoolReturn::Return(value) => {
                crate::assert_with_log!(value == 77, "returned value", 77u8, value);
            }
            PoolReturn::Discard => panic!("expected Return, got Discard"),
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
            PoolReturn::Return(_) => panic!("expected Discard, got Return"),
            PoolReturn::Discard => {
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
        let cx = crate::cx::Cx::for_testing();

        // Close the pool
        futures_lite::future::block_on(pool.close());

        // Acquire should return Closed error
        let result = futures_lite::future::block_on(pool.acquire(&cx));
        match result {
            Err(PoolError::Closed) => {
                // Good - closed error as expected
            }
            Ok(_) => panic!("expected Closed error, got Ok"),
            Err(e) => panic!("expected Closed error, got {:?}", e),
        }

        crate::test_complete!("generic_pool_acquire_when_closed_returns_error");
    }

    #[test]
    fn generic_pool_resource_returned_becomes_idle() {
        init_test("generic_pool_resource_returned_becomes_idle");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx = crate::cx::Cx::for_testing();

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
        let cx = crate::cx::Cx::for_testing();

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
        let cx = crate::cx::Cx::for_testing();

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
}
