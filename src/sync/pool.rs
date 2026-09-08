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

use super::waiter::DeferredWaker;

fn wall_clock_now() -> Instant {
    Instant::now()
}

/// Boxed future helper for async trait-like APIs.
pub type PoolFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Sender used to return resources back to a pool.
pub type PoolReturnSender<R> = mpsc::Sender<PoolReturn<R>>;

/// Receiver used to observe resources returning to a pool.
pub type PoolReturnReceiver<R> = mpsc::Receiver<PoolReturn<R>>;

type ReturnWakerEntry = (u64, DeferredWaker);
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
    #[inline]
    fn new() -> Self {
        Self { discharged: false }
    }

    #[inline]
    fn discharge(&mut self) {
        self.discharged = true;
    }

    #[inline]
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
    /// Caller-flagged "this resource is broken, do not re-pool" bit.
    /// Set via [`mark_broken`](Self::mark_broken). When `true`, the
    /// `Drop` impl routes through `discard_inner` instead of
    /// `return_inner`, ensuring known-bad resources can never poison
    /// the idle pool — even when the holder hits an error path that
    /// drops the wrapper via `?`-propagation rather than calling
    /// [`discard`](Self::discard) explicitly. (br-asupersync-ob62ki)
    #[allow(dead_code)]
    is_broken: bool,
}

impl<R> PooledResource<R> {
    /// Creates a new pooled resource wrapper for a freshly created resource.
    ///
    /// This uses the wall clock for hold-duration bookkeeping.
    #[inline]
    pub fn new(resource: R, return_tx: PoolReturnSender<R>) -> Self {
        Self::new_with_time_getter(resource, return_tx, wall_clock_now)
    }

    /// Creates a new pooled resource wrapper with a custom time source.
    #[inline]
    pub fn new_with_time_getter(
        resource: R,
        return_tx: PoolReturnSender<R>,
        time_getter: fn() -> Instant,
    ) -> Self {
        let now = time_getter();
        Self::new_with_timestamps(resource, return_tx, now, now, time_getter)
    }

    /// Creates a pooled resource wrapper from already-snapshotted timestamps.
    ///
    /// This constructor performs no callbacks, so pool checkout accounting can
    /// remain guarded until the wrapper is complete.
    fn new_with_timestamps(
        resource: R,
        return_tx: PoolReturnSender<R>,
        acquired_at: Instant,
        created_at: Instant,
        time_getter: fn() -> Instant,
    ) -> Self {
        Self {
            resource: Some(resource),
            return_obligation: ReturnObligation::new(),
            return_tx,
            acquired_at,
            created_at,
            time_getter,
            return_wakers: None,
            is_broken: false,
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
        self.resource.as_ref().expect(
            "PooledResource accessed after drop or return - resource has been taken. \
            This indicates a use-after-drop bug or concurrent access violation.",
        )
    }

    /// Mutably access the resource.
    #[inline]
    pub fn get_mut(&mut self) -> &mut R {
        self.resource.as_mut().expect(
            "PooledResource accessed after drop or return - resource has been taken. \
            This indicates a use-after-drop bug or concurrent access violation.",
        )
    }

    /// Try to access the resource, returning None if already taken.
    ///
    /// This is a safer alternative to get() that doesn't panic when called
    /// after the resource has been returned or dropped.
    #[inline]
    #[must_use]
    pub fn try_get(&self) -> Option<&R> {
        self.resource.as_ref()
    }

    /// Try to mutably access the resource, returning None if already taken.
    ///
    /// This is a safer alternative to get_mut() that doesn't panic when called
    /// after the resource has been returned or dropped.
    #[inline]
    pub fn try_get_mut(&mut self) -> Option<&mut R> {
        self.resource.as_mut()
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

    /// Flag this resource as broken WITHOUT consuming it.
    ///
    /// Use when the holder discovers mid-use that the resource is in a
    /// bad state (network blip mid-query, server-side connection close,
    /// stored-procedure left an open transaction, etc.) but still needs
    /// to use the wrapper through the rest of an error-handling scope.
    /// The subsequent `Drop` (e.g. via `?`-propagation) routes through
    /// `discard_inner` instead of `return_inner`, so the broken
    /// resource never re-enters the idle pool.
    ///
    /// Idempotent — calling twice is a no-op. (br-asupersync-ob62ki)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut conn = pool.acquire(&cx).await?;
    /// match conn.execute_query(sql).await {
    ///     Ok(rows) => return Ok(rows),
    ///     Err(e) if e.is_connection_broken() => {
    ///         conn.mark_broken();           // ← key call
    ///         return Err(e);                 // Drop now routes to discard
    ///     }
    ///     Err(e) => return Err(e),          // Drop returns to pool (healthy)
    /// }
    /// ```
    #[inline]
    pub fn mark_broken(&mut self) {
        self.is_broken = true;
    }

    /// Returns whether the resource has been flagged as broken.
    /// (br-asupersync-ob62ki)
    #[inline]
    #[must_use]
    pub fn is_broken(&self) -> bool {
        self.is_broken
    }

    /// How long this resource has been held.
    #[inline]
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
        // Commit the logical discard before destroying arbitrary resource
        // state. `R::drop` may unwind; the pool must already know that its
        // active slot is reusable, and blocked acquirers must already have
        // been notified, before that destructor runs.
        let discarded = self.resource.take();
        let _ = self.return_tx.send(PoolReturn::Discard { hold_duration });
        self.return_obligation.discharge();
        // Wake pool waiters — a discard frees a creation slot.
        self.notify_return_wakers();
        drop(discarded);
    }

    /// Wake the first registered pool waiter to act as a dispatcher.
    /// When it polls, it will call `process_returns()` which drains the return
    /// channel and wakes the exact number of subsequent waiters needed based on capacity.
    fn notify_return_wakers(&self) {
        if let Some(ref wakers) = self.return_wakers {
            let waker = {
                let lock = wakers.lock();
                lock.first().map(|(_, waker)| waker.clone_waker())
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
}

impl<R> Drop for PooledResource<R> {
    /// Routes the resource based on its broken flag:
    ///
    /// * If [`mark_broken`](PooledResource::mark_broken) was called at any
    ///   point during this resource's lifetime, route through
    ///   `discard_inner` so the pool destroys the resource and creates a
    ///   fresh one in its place. This prevents broken connections from
    ///   poisoning the idle pool when the holder hits an error path that
    ///   drops the wrapper via `?`-propagation rather than calling
    ///   [`discard`](PooledResource::discard) explicitly.
    /// * Otherwise (default, healthy path), route through `return_inner`
    ///   so the resource re-enters the idle pool for reuse.
    ///
    /// (br-asupersync-ob62ki)
    fn drop(&mut self) {
        if self.is_broken {
            self.discard_inner();
        } else {
            self.return_inner();
        }
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

/// A pool checkout whose return liability was admitted before acquisition
/// succeeded.
///
/// [`GenericPool::acquire_checked`] and [`GenericPool::try_acquire_checked`]
/// account this as a runtime [`crate::record::ObligationKind::Lease`]. Explicit
/// healthy return commits the lease; dropping, discarding, or returning a
/// resource marked broken aborts it. Healthy resources are physically returned
/// even on abort. Moving this wrapper does not transfer its original holder's
/// liability. An explicitly stateless context has no runtime token.
///
/// This separate wrapper leaves the legacy [`PooledResource`] representation
/// and auto traits unchanged. A resource need only be `Send`, not `Sync`, to
/// move the checked checkout between threads.
#[must_use = "a checked pool resource must be returned or dropped"]
pub struct CheckedPooledResource<R> {
    pooled: Option<PooledResource<R>>,
    obligation: Option<crate::runtime::obligation_mailbox::ObligationToken>,
}

impl<R> CheckedPooledResource<R> {
    fn admit(pooled: PooledResource<R>, cx: &Cx) -> Result<Self, CheckedPoolError> {
        // Own physical rollback before admission publishes or calls notify.
        let mut checked = Self {
            pooled: Some(pooled),
            obligation: None,
        };
        checked.obligation =
            cx.try_register_obligation_checked(crate::record::ObligationKind::Lease, cx.task_id())?;
        Ok(checked)
    }

    /// Borrow the checked-out resource.
    #[must_use]
    pub fn get(&self) -> &R {
        self.pooled.as_ref().expect("active checked checkout").get()
    }

    /// Mutably borrow the checked-out resource.
    pub fn get_mut(&mut self) -> &mut R {
        self.pooled
            .as_mut()
            .expect("active checked checkout")
            .get_mut()
    }

    /// Mark the resource for destruction instead of reuse on any return path.
    pub fn mark_broken(&mut self) {
        self.pooled
            .as_mut()
            .expect("active checked checkout")
            .mark_broken();
    }

    /// Whether the resource has been marked for destruction.
    #[must_use]
    pub fn is_broken(&self) -> bool {
        self.pooled
            .as_ref()
            .expect("active checked checkout")
            .is_broken()
    }

    /// Elapsed hold time from the pool's configured clock.
    #[must_use]
    pub fn held_duration(&self) -> Duration {
        self.pooled
            .as_ref()
            .expect("active checked checkout")
            .held_duration()
    }

    /// Return a healthy resource and commit its admitted lease.
    /// A resource marked broken is discarded and its lease aborted.
    pub fn return_to_pool(mut self) {
        self.finish(true, false);
    }

    /// Destroy the resource and abort its admitted lease.
    pub fn discard(mut self) {
        self.finish(false, true);
    }

    fn finish(&mut self, explicit_return: bool, discard: bool) {
        let Some(mut pooled) = self.pooled.take() else {
            return;
        };
        // Retire the legacy destructor before any callback can unwind. Each
        // detached resource, notifier and waker below has one cleanup owner.
        pooled.return_obligation.discharge();
        let mut resource = pooled.resource.take();
        let discard = discard || pooled.is_broken;
        let mut panics = CheckedPoolCleanupPanics::new();
        let mut hold_duration = Duration::ZERO;
        panics.run(|| hold_duration = pooled.held_duration());
        // ZERO is used only if the injected clock panicked; that same panic
        // is propagated after cleanup. It is not a successful duration sample.
        let message = if discard {
            PoolReturn::Discard { hold_duration }
        } else {
            PoolReturn::Return {
                resource: resource.take().expect("active checked resource"),
                hold_duration,
                created_at: pooled.created_at,
            }
        };
        let returned = match pooled.return_tx.send(message) {
            Ok(()) => true,
            Err(mpsc::SendError(PoolReturn::Return { resource: lost, .. })) => {
                resource = Some(lost);
                false
            }
            Err(mpsc::SendError(PoolReturn::Discard { .. })) => false,
        };
        // Physical cleanup is queued before quota is synchronously released.
        // No notifier, waker or resource destructor runs during settlement.
        let notification = self.obligation.take().and_then(|token| {
            let (_, notification) = if explicit_return && !discard && returned {
                token.commit_deferred()
            } else {
                token.abort_deferred(crate::record::ObligationAbortReason::Explicit)
            };
            notification
        });
        let waker = pooled
            .return_wakers
            .as_ref()
            .and_then(|wakers| wakers.lock().first().map(|(_, waker)| waker.clone_waker()));
        if let Some(gateway) = notification {
            panics.run(|| gateway.notify());
            panics.run(|| drop(gateway));
        }
        if let Some(waker) = waker {
            // Keep the owner outside the callback catch: consuming wake can
            // combine a wake panic and final-payload Drop panic into an abort.
            panics.run(|| waker.wake_by_ref());
            panics.run(|| drop(waker));
        }
        panics.run(|| drop(resource));
        panics.run(|| drop(pooled));
    }
}

impl<R> Drop for CheckedPooledResource<R> {
    fn drop(&mut self) {
        self.finish(false, false);
    }
}

impl<R> std::ops::Deref for CheckedPooledResource<R> {
    type Target = R;

    fn deref(&self) -> &R {
        self.get()
    }
}

impl<R> std::ops::DerefMut for CheckedPooledResource<R> {
    fn deref_mut(&mut self) -> &mut R {
        self.get_mut()
    }
}

impl<R: std::fmt::Debug> std::fmt::Debug for CheckedPooledResource<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedPooledResource")
            .field(
                "resource",
                &self.pooled.as_ref().and_then(PooledResource::try_get),
            )
            .field("tracked", &self.obligation.is_some())
            .finish_non_exhaustive()
    }
}

/// Complete every independent callback, preserving the original failure even
/// when another callback or its panic payload also has a panicking destructor.
struct CheckedPoolCleanupPanics {
    already_unwinding: bool,
    first: Option<Box<dyn std::any::Any + Send>>,
}

impl CheckedPoolCleanupPanics {
    fn new() -> Self {
        Self {
            already_unwinding: std::thread::panicking(),
            first: None,
        }
    }

    fn run(&mut self, callback: impl FnOnce()) {
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(callback)) {
            if self.already_unwinding || self.first.is_some() {
                std::mem::forget(payload);
            } else {
                self.first = Some(payload);
            }
        }
    }
}

impl Drop for CheckedPoolCleanupPanics {
    fn drop(&mut self) {
        if let Some(payload) = self.first.take() {
            if std::thread::panicking() {
                std::mem::forget(payload);
            } else {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

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

/// Failure of an explicitly checked pool acquisition.
///
/// Admission refusal returns the physical checkout to the pool and never
/// changes the existing [`PoolError`] variants or legacy acquisition behavior.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckedPoolError {
    /// The underlying pool acquisition failed.
    #[error(transparent)]
    Pool(#[from] PoolError),
    /// The runtime refused the return liability before acquisition succeeded.
    #[error(transparent)]
    Admission(#[from] crate::runtime::obligation_mailbox::ObligationAdmissionError),
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
    waker: DeferredWaker,
}

/// Queue-owned wake state detached from pool locks and ready for retirement.
struct DetachedPoolWakers {
    state_waker: Option<DeferredWaker>,
    return_waker: Option<DeferredWaker>,
    next_dispatcher: Option<Waker>,
}

impl DetachedPoolWakers {
    /// Preserve the return-dispatch baton before retiring task-owned state.
    /// If waking panics, the detached relay owners unwind outside pool locks.
    fn retire(self) {
        let Self {
            state_waker,
            return_waker,
            next_dispatcher,
        } = self;
        if let Some(next) = next_dispatcher {
            next.wake();
        }
        drop(state_waker);
        drop(return_waker);
    }
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
    completed: bool,
}

impl<R, F> Future for WaitForNotification<'_, '_, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cx.checkpoint().is_err() {
            self.completed = true;
            return Poll::Ready(());
        }

        self.pool.process_returns();

        // Construct both queue candidates before either queue lock is held.
        // A task-provided RawWaker may run user code from clone/drop callbacks.
        let mut state_candidate = Some(DeferredWaker::new(cx.waker().clone()));
        let mut return_candidate = Some(DeferredWaker::new(cx.waker().clone()));
        let mut retired_state_waker = None;
        let mut state = self.pool.state.lock();

        if state.closed {
            self.completed = true;
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
                // An eligible waiter completes this internal future now and
                // the outer acquire loop either detaches it on success or
                // polls a fresh WaitForNotification before returning Pending.
                // Keep its queued waker intact so successful dequeue performs
                // the retirement, rather than refreshing it on this ready poll.
                if idx >= available {
                    let w = &mut state.waiters[idx];
                    let candidate = state_candidate
                        .take()
                        .expect("state waker candidate is available");
                    if w.waker.will_wake(cx.waker()) {
                        retired_state_waker = Some(candidate);
                    } else {
                        retired_state_waker = Some(std::mem::replace(&mut w.waker, candidate));
                    }
                }
                idx
            } else {
                // Was removed by try_get_idle but health check failed.
                // Re-register at the FRONT to preserve FIFO fairness.
                state.waiters.reserve(1);
                state.waiters.push_front(PoolWaiter {
                    id,
                    waker: state_candidate
                        .take()
                        .expect("state waker candidate is available"),
                });
                0
            }
        } else {
            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
            let idx = state.waiters.len();
            state.waiters.reserve(1);
            state.waiters.push_back(PoolWaiter {
                id,
                waker: state_candidate
                    .take()
                    .expect("state waker candidate is available"),
            });
            *self.waiter_id = Some(id);
            idx
        };

        let id = self.waiter_id.expect("waiter_id assigned above");
        drop(state);

        if pos < available {
            self.completed = true;
            drop(retired_state_waker);
            drop(state_candidate);
            drop(return_candidate);
            return Poll::Ready(());
        }

        // Also register in the return_wakers list
        let mut retired_return_waker = None;
        {
            let mut wakers = self.pool.return_wakers.lock();
            if let Some((_, existing)) = wakers.iter_mut().find(|(wid, _)| *wid == id) {
                let candidate = return_candidate
                    .take()
                    .expect("return waker candidate is available");
                if existing.will_wake(cx.waker()) {
                    retired_return_waker = Some(candidate);
                } else {
                    retired_return_waker = Some(std::mem::replace(existing, candidate));
                }
            } else {
                wakers.reserve(1);
                wakers.push((
                    id,
                    return_candidate
                        .take()
                        .expect("return waker candidate is available"),
                ));
            }
        }

        // `close` drains the state queue. If it raced the gap between the
        // state registration and the return-dispatch registration, no later
        // state wake remains for us. Observe the monotone close flag here;
        // any close after this check still finds the state registration.
        let closed_after_registration = self.pool.closed.load(Ordering::Acquire);
        drop(retired_state_waker);
        drop(retired_return_waker);
        drop(state_candidate);
        drop(return_candidate);

        if closed_after_registration {
            self.completed = true;
            return Poll::Ready(());
        }

        // Process returns again to close the race condition:
        // A resource might have been returned between `drop(state)` and locking `return_wakers`.
        self.pool.process_returns();

        Poll::Pending
    }
}

impl<R, F> Drop for WaitForNotification<'_, '_, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    fn drop(&mut self) {
        if !self.completed
            && let Some(id) = *self.waiter_id
        {
            // Remove from the main waiters queue AND, if this cancelled waiter
            // was eligible, wake the waiter that shifts into its eligible slot.
            // This future (`wait_fut`) drops before the sibling `WaiterCleanup`,
            // so we remove the waiter first — WaiterCleanup::drop then finds
            // `pos == None` and its own marginal wake is dead. Without doing the
            // marginal wake here, a cancellation shifts a later waiter into
            // eligibility without waking it, stranding it (with an idle resource
            // free) until `acquire_timeout`. Mirrors WaiterCleanup::drop. (br)
            let mut retired_state_waker = None;
            let marginal_waker: Option<Waker> = {
                let mut state = self.pool.state.lock();
                if let Some(p) = state.waiters.iter().position(|w| w.id == id) {
                    retired_state_waker = state.waiters.remove(p).map(|waiter| waiter.waker);
                    if state.closed {
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
                        if p < available && available > 0 && available - 1 < state.waiters.len() {
                            Some(state.waiters[available - 1].waker.clone_waker())
                        } else {
                            None
                        }
                    }
                } else {
                    None
                }
            };
            // Remove from return_wakers list. If we were the dispatcher (the
            // first entry, which `notify_return_wakers` wakes to drain the
            // return channel via `process_returns`), hand the dispatcher role
            // to the next waiter. Otherwise a resource returned just before
            // this cancellation — which already woke us — would sit undrained
            // in the channel and the remaining waiters would never wake
            // (lost wakeup). (br-asupersync-dq5g7a)
            let (retired_return_waker, next_dispatcher) = self.pool.detach_return_waker(id);

            if let Some(waker) = marginal_waker {
                waker.wake();
            }
            DetachedPoolWakers {
                state_waker: retired_state_waker,
                return_waker: retired_return_waker,
                next_dispatcher,
            }
            .retire();
        }
    }
}

/// Roll back an active checkout until a complete [`PooledResource`] owns its
/// return obligation.
///
/// This guard is armed immediately after pool state moves a slot into
/// `active`. It stays armed across health checks, waiter retirement, clocks,
/// and wrapper construction so a panic in any of those steps cannot strand
/// capacity. Once the complete wrapper owns the return obligation, that
/// wrapper becomes responsible for unwind cleanup.
struct ActiveCheckoutGuard<'a, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    pool: &'a GenericPool<R, F>,
    completed: bool,
    health_check_in_progress: bool,
}

impl<'a, R, F> ActiveCheckoutGuard<'a, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    fn new(pool: &'a GenericPool<R, F>) -> Self {
        Self {
            pool,
            completed: false,
            health_check_in_progress: false,
        }
    }

    fn begin_health_check(&mut self) {
        self.health_check_in_progress = true;
    }

    fn finish_health_check(&mut self) {
        self.health_check_in_progress = false;
    }

    fn reject_unhealthy(mut self) {
        self.completed = true;
        self.pool.reject_unhealthy_idle_resource();
    }

    fn commit(mut self) {
        self.completed = true;
    }
}

impl<R, F> Drop for ActiveCheckoutGuard<'_, R, F>
where
    R: Send + 'static,
    F: AsyncResourceFactory<Resource = R>,
{
    fn drop(&mut self) {
        if !self.completed {
            if self.health_check_in_progress {
                self.pool.reject_unhealthy_idle_resource();
            } else {
                self.pool.rollback_active_checkout();
            }
        }
    }
}

/// The synchronous state mutation that precedes arming a slot reservation.
struct CreateSlotClaim {
    retired_waker: Option<DeferredWaker>,
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
        let CreateSlotClaim { retired_waker } = pool.reserve_create_slot(waiter_id)?;
        let reservation = Self {
            pool,
            committed: false,
        };
        // Arm the accounting guard before retiring user-provided wake state.
        // If that destructor panics, unwinding releases the reserved slot.
        drop(retired_waker);
        Some(reservation)
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

    /// Acquire a resource and admit its return liability before returning it.
    ///
    /// Waiting, creation, cancellation and timeout retain [`Pool::acquire`]
    /// semantics. Admission happens after physical checkout, outside pool
    /// locks; a refused or unwinding admission returns that resource. A
    /// runtime-associated context without a live holder is refused, while an
    /// explicitly stateless context returns a wrapper without a runtime token.
    pub fn acquire_checked<'a>(
        &'a self,
        cx: &'a Cx,
    ) -> PoolFuture<'a, Result<CheckedPooledResource<R>, CheckedPoolError>> {
        Box::pin(async move {
            let pooled = self.acquire(cx).await?;
            CheckedPooledResource::admit(pooled, cx)
        })
    }

    /// Try to check out an idle resource with checked return liability.
    ///
    /// `Ok(None)` means an idle resource is unavailable or an earlier FIFO
    /// waiter has priority; this method does not create a resource. Closed,
    /// cancelled and admission-refused operations return distinct typed errors.
    pub fn try_acquire_checked(
        &self,
        cx: &Cx,
    ) -> Result<Option<CheckedPooledResource<R>>, CheckedPoolError> {
        cx.checkpoint().map_err(|_| PoolError::Cancelled)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(PoolError::Closed.into());
        }
        match self.try_acquire() {
            Some(pooled) => CheckedPooledResource::admit(pooled, cx).map(Some),
            None if self.closed.load(Ordering::Acquire) => Err(PoolError::Closed.into()),
            None => Ok(None),
        }
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

    /// Undo accounting for a checkout that never reached the caller.
    ///
    /// Both idle checkout and committed creation increment `active` and
    /// `total_acquisitions` before panic-capable handoff work. Roll those
    /// counters back and notify the newly marginal waiter.
    fn rollback_active_checkout(&self) {
        let waker = {
            let mut state = self.state.lock();
            state.active = state.active.saturating_sub(1);
            state.total_acquisitions = state.total_acquisitions.saturating_sub(1);

            let total = state.active + state.idle.len() + state.creating;
            let available = state.idle.len() + self.config.max_size.saturating_sub(total);
            if available > 0 && available - 1 < state.waiters.len() {
                Some(state.waiters[available - 1].waker.clone_waker())
            } else {
                None
            }
        };

        #[cfg(feature = "metrics")]
        self.update_metrics_gauges();

        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Reject an unhealthy idle resource after undoing its checkout.
    fn reject_unhealthy_idle_resource(&self) {
        self.rollback_active_checkout();

        #[cfg(feature = "metrics")]
        if let Some(ref metrics) = self.metrics {
            metrics.record_destroyed(DestroyReason::Unhealthy);
        }
    }

    /// Detach one return message from the receiver lock.
    fn try_recv_return(&self) -> Result<PoolReturn<R>, mpsc::TryRecvError> {
        let rx = self.return_rx.lock();
        rx.try_recv()
    }

    /// Process returned resources from the return channel.
    #[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
    fn process_returns(&self) {
        let mut waiters_to_wake: SmallVec<[Waker; 4]> = SmallVec::new();
        // Detach exactly one message from the receiver before inspecting its
        // payload. A closed-pool Return may destroy arbitrary R state, and that
        // destructor must never run while return_rx is locked.
        while let Ok(ret) = self.try_recv_return() {
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

                    // Declare the pending owner before the state guard. If the
                    // injected clock or capacity reservation unwinds, the guard
                    // unlocks before either this owner or `resource` is dropped.
                    #[allow(clippy::needless_late_init)]
                    let mut pending_idle: Option<IdleResource<R>>;
                    let mut state = self.state.lock();
                    state.active = state.active.saturating_sub(1);

                    if state.closed {
                        drop(state);
                        drop(resource);
                        continue;
                    }

                    let idle_since = (self.time_getter)();
                    pending_idle = Some(IdleResource {
                        resource,
                        idle_since,
                        created_at,
                    });
                    state.idle.reserve(1);
                    state.idle.push_back(
                        pending_idle
                            .take()
                            .expect("return payload prepared before idle insertion"),
                    );

                    let total = state.active + state.idle.len() + state.creating;
                    let available = state.idle.len() + self.config.max_size.saturating_sub(total);
                    if available > 0 && available - 1 < state.waiters.len() {
                        waiters_to_wake.push(state.waiters[available - 1].waker.clone_waker());
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
                        waiters_to_wake.push(state.waiters[available - 1].waker.clone_waker());
                    }
                    drop(state);
                }
            }
        }

        for waker in waiters_to_wake {
            waker.wake();
        }
    }

    /// Try to get an idle resource, returning its original creation time.
    fn try_get_idle(&self, waiter_id: Option<u64>) -> Option<(R, Instant)> {
        // Snapshot time before locking so an injected clock can neither reenter
        // state nor strand a detached resource during unwind.
        let now = (self.time_getter)();
        loop {
            // This owner predates the state guard so unwind always unlocks
            // before destroying any resource detached by the partition.
            let mut retired_idle = Vec::new();
            let mut state = self.state.lock();
            #[cfg(feature = "metrics")]
            let mut idle_timeout_evictions = 0u64;
            #[cfg(feature = "metrics")]
            let mut max_lifetime_evictions = 0u64;

            let idle_len = state.idle.len();
            let mut expired_count = 0usize;
            for idle in &state.idle {
                let idle_ok =
                    now.saturating_duration_since(idle.idle_since) < self.config.idle_timeout;
                let lifetime_ok =
                    now.saturating_duration_since(idle.created_at) < self.config.max_lifetime;

                if !idle_ok || !lifetime_ok {
                    expired_count += 1;

                    #[cfg(feature = "metrics")]
                    if !idle_ok {
                        idle_timeout_evictions += 1;
                    } else {
                        max_lifetime_evictions += 1;
                    }
                }
            }

            // Reserve before moving any R out of state. The fixed-length
            // pop/requeue pass preserves survivor order and cannot grow either
            // destination after this point.
            retired_idle.reserve(expired_count);
            if expired_count > 0 {
                for _ in 0..idle_len {
                    let idle = state
                        .idle
                        .pop_front()
                        .expect("idle partition length captured under state lock");
                    let idle_ok =
                        now.saturating_duration_since(idle.idle_since) < self.config.idle_timeout;
                    let lifetime_ok =
                        now.saturating_duration_since(idle.created_at) < self.config.max_lifetime;

                    if idle_ok && lifetime_ok {
                        state.idle.push_back(idle);
                    } else {
                        retired_idle.push(idle);
                    }
                }
                drop(state);
                drop(retired_idle);

                // Match the previous retain-before-accounting order, but do
                // the resource destruction and metrics work without state.
                #[cfg(feature = "metrics")]
                if let Some(ref metrics) = self.metrics {
                    for _ in 0..idle_timeout_evictions {
                        metrics.record_destroyed(DestroyReason::IdleTimeout);
                    }
                    for _ in 0..max_lifetime_evictions {
                        metrics.record_destroyed(DestroyReason::MaxLifetime);
                    }
                }

                // A destructor may have reentered the pool, so revalidate the
                // queue and FIFO window before committing any checkout.
                continue;
            }

            // Evictions don't increase `available`: they convert an idle slot
            // into creation capacity for the currently authorized task.
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

            let result = if pos < available && !state.idle.is_empty() {
                // Compute overflow-capable counters before detaching R.
                let active = state.active + 1;
                let total_acquisitions = state.total_acquisitions + 1;
                let idle = state
                    .idle
                    .pop_front()
                    .expect("non-empty idle queue checked under state lock");
                state.active = active;
                state.total_acquisitions = total_acquisitions;
                // Waiter remains queued until acquire succeeds, or stays when
                // a health check fails so FIFO position is preserved.
                Some((idle.resource, idle.created_at))
            } else {
                None
            };
            drop(state);
            return result;
        }
    }

    /// Reserve a creation slot under max-size accounting.
    fn reserve_create_slot(&self, waiter_id: Option<u64>) -> Option<CreateSlotClaim> {
        let mut state = self.state.lock();
        let total = state.active + state.idle.len() + state.creating;
        if state.closed || total >= self.config.max_size {
            return None;
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
            return None;
        }

        state.creating += 1;
        let retired_waker = (waiter_id.is_some() && pos < state.waiters.len()).then(|| {
            state
                .waiters
                .remove(pos)
                .expect("waiter position was validated")
                .waker
        });
        drop(state);
        Some(CreateSlotClaim { retired_waker })
    }

    /// Release an uncommitted creation slot and notify one waiter.
    fn release_create_slot(&self) {
        let waker = {
            let mut state = self.state.lock();
            state.creating = state.creating.saturating_sub(1);
            let total = state.active + state.idle.len() + state.creating;
            let available = state.idle.len() + self.config.max_size.saturating_sub(total);
            if available > 0 && available - 1 < state.waiters.len() {
                Some(state.waiters[available - 1].waker.clone_waker())
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
        let creating = state.creating.saturating_sub(1);
        let total_created = state.total_created + 1;

        if state.closed {
            state.creating = creating;
            state.total_created = total_created;
            return false;
        }

        // Precompute every overflow-capable counter before mutating state. The
        // active checkout guard cannot be armed until this transition returns,
        // so a debug-overflow panic must leave the reservation intact for its
        // own Drop rollback.
        let active = state.active + 1;
        let total_acquisitions = state.total_acquisitions + 1;
        state.creating = creating;
        state.total_created = total_created;
        state.active = active;
        state.total_acquisitions = total_acquisitions;
        true
    }

    /// Commit a completed creation slot as an idle resource (for warmup).
    /// Unlike `commit_create_slot`, this does NOT increment `active` or
    /// `total_acquisitions` — the resource goes straight to the idle queue.
    fn commit_create_slot_as_idle(&self, resource: R) {
        // Keep the pending owner outside the state guard's drop scope.
        #[allow(clippy::needless_late_init)]
        let mut pending_idle: Option<IdleResource<R>>;
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
            pending_idle = Some(IdleResource {
                resource,
                idle_since: now,
                created_at: now,
            });
            state.idle.reserve(1);
            state.idle.push_back(
                pending_idle
                    .take()
                    .expect("warmup payload prepared before idle insertion"),
            );

            let total = state.active + state.idle.len() + state.creating;
            let available = state.idle.len() + self.config.max_size.saturating_sub(total);
            if available > 0 && available - 1 < state.waiters.len() {
                Some(state.waiters[available - 1].waker.clone_waker())
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

    /// Compute the remaining time for an acquire attempt after applying both
    /// the pool timeout and any tighter deadline carried by the caller's `Cx`.
    fn remaining_acquire_timeout(
        &self,
        cx: &Cx,
        acquire_start: crate::types::Time,
        now: crate::types::Time,
    ) -> Result<Duration, PoolError> {
        let elapsed = Duration::from_nanos(now.duration_since(acquire_start));
        if elapsed >= self.config.acquire_timeout {
            return Err(PoolError::Timeout);
        }

        let remaining = self.config.acquire_timeout.saturating_sub(elapsed);
        if let Some(budget_remaining) = cx.budget().remaining_time(now) {
            if budget_remaining.is_zero() {
                return Err(PoolError::Cancelled);
            }
            Ok(remaining.min(budget_remaining))
        } else {
            Ok(remaining)
        }
    }

    /// Detach a waiter by ID without retiring its task waker under the lock.
    fn detach_waiter(&self, id: u64) -> Option<DeferredWaker> {
        let mut state = self.state.lock();
        state
            .waiters
            .iter()
            .position(|waiter| waiter.id == id)
            .and_then(|position| state.waiters.remove(position))
            .map(|waiter| waiter.waker)
    }

    /// Detach a return-dispatch waiter and preserve the dispatcher baton.
    fn detach_return_waker(&self, id: u64) -> (Option<DeferredWaker>, Option<Waker>) {
        let mut retired_waker = None;
        let next_dispatcher = {
            let mut wakers = self.return_wakers.lock();
            if let Some(position) = wakers.iter().position(|(waiter_id, _)| *waiter_id == id) {
                let was_dispatcher = position == 0;
                retired_waker = Some(wakers.remove(position).1);
                if was_dispatcher {
                    wakers.first().map(|(_, next)| next.clone_waker())
                } else {
                    None
                }
            } else {
                None
            }
        };
        (retired_waker, next_dispatcher)
    }

    /// Detach both registrations for one acquire before running user code.
    fn detach_waiter_registrations(&self, id: u64) -> DetachedPoolWakers {
        let state_waker = self.detach_waiter(id);
        let (return_waker, next_dispatcher) = self.detach_return_waker(id);
        DetachedPoolWakers {
            state_waker,
            return_waker,
            next_dispatcher,
        }
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
                        let mut retired_state_waker = None;
                        let marginal_waker = {
                            let mut state = self.pool.state.lock();
                            let pos = state.waiters.iter().position(|w| w.id == id);
                            if let Some(p) = pos {
                                retired_state_waker =
                                    state.waiters.remove(p).map(|waiter| waiter.waker);
                            }

                            if state.closed {
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
                                        Some(state.waiters[available - 1].waker.clone_waker())
                                    } else {
                                        None
                                    }
                                })
                            }
                        };

                        let (retired_return_waker, next_dispatcher) =
                            self.pool.detach_return_waker(id);

                        if let Some(w) = marginal_waker {
                            w.wake();
                        }
                        DetachedPoolWakers {
                            state_waker: retired_state_waker,
                            return_waker: retired_return_waker,
                            next_dispatcher,
                        }
                        .retire();
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

                // A waiter can resume because of cancellation/deadline as well
                // as because a resource became available. Re-check before taking
                // any fast path so cancelled acquirers do not steal capacity.
                if cx.checkpoint().is_err() {
                    return Err(PoolError::Cancelled);
                }

                // Check if closed (lock-free fast path).
                if self.closed.load(Ordering::Acquire) {
                    return Err(PoolError::Closed);
                }

                // Try to get a healthy idle resource.
                while let Some((resource, created_at)) = self.try_get_idle(cleanup.waiter_id) {
                    let mut checkout = ActiveCheckoutGuard::new(self);
                    let is_healthy = if self.config.health_check_on_acquire {
                        checkout.begin_health_check();
                        let healthy = self.is_healthy(&resource);
                        checkout.finish_health_check();
                        healthy
                    } else {
                        true
                    };

                    if !is_healthy {
                        checkout.reject_unhealthy();
                        continue;
                    }

                    if let Some(id) = cleanup.waiter_id {
                        let detached = self.detach_waiter_registrations(id);
                        cleanup.waiter_id = None;
                        detached.retire();
                    }

                    let acquire_duration =
                        Duration::from_nanos(get_now().duration_since(acquire_start));

                    let acquired_at = (self.time_getter)();
                    let pooled = PooledResource::new_with_timestamps(
                        resource,
                        self.return_tx.clone(),
                        acquired_at,
                        created_at,
                        self.time_getter,
                    )
                    .with_return_notify(Arc::clone(&self.return_wakers));
                    checkout.commit();

                    // Count the acquisition only after responsibility has
                    // transferred to the complete wrapper.
                    #[cfg(feature = "metrics")]
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_acquired(acquire_duration);
                        self.update_metrics_gauges();
                    }

                    return Ok(pooled);
                }

                // Try to create a new resource if under capacity
                if let Some(create_slot) =
                    CreateSlotReservation::try_reserve(self, cleanup.waiter_id)
                {
                    if let Some(id) = cleanup.waiter_id {
                        let detached = self.detach_waiter_registrations(id);
                        cleanup.waiter_id = None;
                        detached.retire();
                    }

                    let now = get_now();
                    let remaining = match self.remaining_acquire_timeout(cx, acquire_start, now) {
                        Ok(remaining) => remaining,
                        Err(PoolError::Timeout) => {
                            #[cfg(feature = "metrics")]
                            if let Some(ref metrics) = self.metrics {
                                metrics.record_timeout(Duration::from_nanos(
                                    now.duration_since(acquire_start),
                                ));
                            }
                            return Err(PoolError::Timeout);
                        }
                        Err(PoolError::Cancelled) => return Err(PoolError::Cancelled),
                        Err(other) => return Err(other),
                    };

                    if remaining.is_zero() {
                        #[cfg(feature = "metrics")]
                        if let Some(ref metrics) = self.metrics {
                            metrics.record_timeout(Duration::from_nanos(
                                now.duration_since(acquire_start),
                            ));
                        }
                        return if cx.checkpoint().is_err() {
                            Err(PoolError::Cancelled)
                        } else {
                            Err(PoolError::Timeout)
                        };
                    }

                    let create_result =
                        crate::time::timeout(now, remaining, self.create_resource()).await;
                    let resource = match create_result {
                        Ok(Ok(res)) => res,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => {
                            if cx.checkpoint().is_err() {
                                return Err(PoolError::Cancelled);
                            }

                            #[cfg(feature = "metrics")]
                            if let Some(ref metrics) = self.metrics {
                                metrics.record_timeout(Duration::from_nanos(
                                    get_now().duration_since(acquire_start),
                                ));
                            }
                            return Err(PoolError::Timeout);
                        }
                    };

                    let committed = create_slot.commit();
                    let checkout = committed.then(|| ActiveCheckoutGuard::new(self));
                    let acquire_duration =
                        Duration::from_nanos(get_now().duration_since(acquire_start));

                    // The factory succeeded even if handoff is interrupted.
                    #[cfg(feature = "metrics")]
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_created();
                    }

                    if !committed {
                        #[cfg(feature = "metrics")]
                        self.update_metrics_gauges();
                        return Err(PoolError::Closed);
                    }

                    let acquired_at = (self.time_getter)();
                    let pooled = PooledResource::new_with_timestamps(
                        resource,
                        self.return_tx.clone(),
                        acquired_at,
                        acquired_at,
                        self.time_getter,
                    )
                    .with_return_notify(Arc::clone(&self.return_wakers));
                    checkout
                        .expect("committed creation slot arms active checkout guard")
                        .commit();

                    // Count the acquisition only after responsibility has
                    // transferred to the complete wrapper.
                    #[cfg(feature = "metrics")]
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_acquired(acquire_duration);
                        self.update_metrics_gauges();
                    }

                    return Ok(pooled);
                }

                // Check for timeout
                let now = get_now();
                let remaining = match self.remaining_acquire_timeout(cx, acquire_start, now) {
                    Ok(remaining) => remaining,
                    Err(PoolError::Timeout) => {
                        let elapsed = Duration::from_nanos(now.duration_since(acquire_start));
                        #[cfg(feature = "metrics")]
                        if let Some(ref metrics) = self.metrics {
                            metrics.record_timeout(elapsed);
                        }
                        return Err(PoolError::Timeout);
                    }
                    Err(PoolError::Cancelled) => return Err(PoolError::Cancelled),
                    Err(other) => return Err(other),
                };

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
                    completed: false,
                };
                if crate::time::timeout(now, remaining, wait_fut)
                    .await
                    .is_err()
                {
                    let wait_duration =
                        Duration::from_nanos(get_now().duration_since(wait_started));
                    if cx.checkpoint().is_err() {
                        self.record_wait_time(wait_duration);
                        return Err(PoolError::Cancelled);
                    }

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
            let mut checkout = ActiveCheckoutGuard::new(self);
            let is_healthy = if self.config.health_check_on_acquire {
                checkout.begin_health_check();
                let healthy = self.is_healthy(&resource);
                checkout.finish_health_check();
                healthy
            } else {
                true
            };

            if !is_healthy {
                checkout.reject_unhealthy();
                continue;
            }

            #[cfg(feature = "metrics")]
            let acquire_duration = self
                .metrics
                .as_ref()
                .map(|_| (self.time_getter)().saturating_duration_since(acquire_start));

            let acquired_at = (self.time_getter)();
            let pooled = PooledResource::new_with_timestamps(
                resource,
                self.return_tx.clone(),
                acquired_at,
                created_at,
                self.time_getter,
            )
            .with_return_notify(Arc::clone(&self.return_wakers));
            checkout.commit();

            // Count the acquisition only after responsibility has transferred
            // to the complete wrapper.
            #[cfg(feature = "metrics")]
            if let (Some(metrics), Some(acquire_duration)) = (&self.metrics, acquire_duration) {
                metrics.record_acquired(acquire_duration);
                self.update_metrics_gauges();
            }

            return Some(pooled);
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
            let (waiters, idle_resources) = {
                let mut state = self.state.lock();
                state.closed = true;
                self.closed.store(true, Ordering::Release);

                // Detach both destructor-capable queues, then notify/destroy
                // only after releasing the state lock.
                let waiters = std::mem::take(&mut state.waiters);
                let idle_resources = std::mem::take(&mut state.idle);
                (waiters, idle_resources)
            };

            #[cfg(feature = "metrics")]
            let idle_count = idle_resources.len();

            for waiter in waiters {
                waiter.waker.clone_waker().wake();
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

            drop(idle_resources);
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
include!("pool_tests.rs");
