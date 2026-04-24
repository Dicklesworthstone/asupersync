//! Generic database connection pool with health checks.
//!
//! Provides a database-specific abstraction over [`sync::Pool`](crate::sync::Pool)
//! with connection validation, lifecycle management, and typed connection managers.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::database::pool::{DbPool, ConnectionManager, DbPoolConfig};
//!
//! struct PgManager { url: String }
//!
//! impl ConnectionManager for PgManager {
//!     type Connection = PgConnection;
//!     type Error = PgError;
//!
//!     fn connect(&self) -> Result<Self::Connection, Self::Error> {
//!         PgConnection::connect(&self.url)
//!     }
//!
//!     fn is_valid(&self, conn: &Self::Connection) -> bool {
//!         conn.ping().is_ok()
//!     }
//! }
//!
//! let pool = DbPool::new(PgManager { url: db_url }, DbPoolConfig::default());
//! let conn = pool.get()?;
//! ```

use crate::combinator::{RetryPolicy, calculate_delay};

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ─── ConnectionManager trait ────────────────────────────────────────────────

/// Manages the lifecycle of database connections.
///
/// Implement this trait for each database backend to provide connection
/// creation, validation, and optional cleanup.
pub trait ConnectionManager: Send + Sync + 'static {
    /// The connection type managed by this manager.
    type Connection: Send + 'static;

    /// Error type for connection operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Create a new connection.
    fn connect(&self) -> Result<Self::Connection, Self::Error>;

    /// Validate that a connection is still usable.
    ///
    /// Called before returning idle connections to callers when
    /// `validate_on_checkout` is enabled.
    fn is_valid(&self, conn: &Self::Connection) -> bool;

    /// Called when a connection is permanently removed from the pool.
    ///
    /// Default implementation does nothing. Override for cleanup
    /// (e.g., sending disconnect protocol messages).
    fn disconnect(&self, _conn: Self::Connection) {}
}

// ─── DbPoolConfig ───────────────────────────────────────────────────────────

/// Configuration for the database connection pool.
#[derive(Debug, Clone)]
pub struct DbPoolConfig {
    /// Minimum number of idle connections to maintain.
    pub min_idle: usize,
    /// Maximum number of connections in the pool.
    pub max_size: usize,
    /// Validate connections before handing them out.
    pub validate_on_checkout: bool,
    /// Maximum time a connection can be idle before eviction.
    pub idle_timeout: Duration,
    /// Maximum lifetime of a connection.
    pub max_lifetime: Duration,
    /// Maximum time to wait when acquiring a connection.
    pub connection_timeout: Duration,
}

impl Default for DbPoolConfig {
    fn default() -> Self {
        Self {
            min_idle: 1,
            max_size: 10,
            validate_on_checkout: true,
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(3600),
            connection_timeout: Duration::from_secs(30),
        }
    }
}

impl DbPoolConfig {
    /// Create a config with the given max size.
    #[inline]
    #[must_use]
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            max_size,
            ..Default::default()
        }
    }

    /// Set the minimum idle connections.
    #[inline]
    #[must_use]
    pub fn min_idle(mut self, min_idle: usize) -> Self {
        self.min_idle = min_idle;
        self
    }

    /// Set the maximum pool size.
    #[inline]
    #[must_use]
    pub fn max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Enable or disable checkout validation.
    #[inline]
    #[must_use]
    pub fn validate_on_checkout(mut self, enabled: bool) -> Self {
        self.validate_on_checkout = enabled;
        self
    }

    /// Set the idle timeout.
    #[inline]
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the maximum connection lifetime.
    #[inline]
    #[must_use]
    pub fn max_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_lifetime = lifetime;
        self
    }

    /// Set the connection acquisition timeout.
    #[inline]
    #[must_use]
    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }
}

// ─── Pool internals ─────────────────────────────────────────────────────────

/// An idle connection with metadata.
struct IdleConnection<C> {
    conn: C,
    created_at: Instant,
    last_used: Instant,
}

impl<C> IdleConnection<C> {
    fn is_expired(&self, config: &DbPoolConfig) -> bool {
        self.created_at.elapsed() > config.max_lifetime
    }

    fn is_idle_too_long(&self, config: &DbPoolConfig) -> bool {
        self.last_used.elapsed() > config.idle_timeout
    }
}

struct PoolInner<C> {
    idle: VecDeque<IdleConnection<C>>,
    /// Total connections (idle + checked out).
    total: usize,
    closed: bool,
}

// ─── DbPool ─────────────────────────────────────────────────────────────────

/// A generic database connection pool with health checks.
///
/// The pool maintains a set of reusable connections, validating them
/// on checkout and evicting stale connections. Connections are created
/// on demand up to `max_size`.
pub struct DbPool<M: ConnectionManager> {
    manager: Arc<M>,
    config: DbPoolConfig,
    inner: Mutex<PoolInner<M::Connection>>,
    stats: PoolStatCounters,
}

#[allow(clippy::struct_field_names)]
struct PoolStatCounters {
    total_acquisitions: AtomicU64,
    total_creates: AtomicU64,
    total_discards: AtomicU64,
    total_timeouts: AtomicU64,
    total_validation_failures: AtomicU64,
}

impl Default for PoolStatCounters {
    fn default() -> Self {
        Self {
            total_acquisitions: AtomicU64::new(0),
            total_creates: AtomicU64::new(0),
            total_discards: AtomicU64::new(0),
            total_timeouts: AtomicU64::new(0),
            total_validation_failures: AtomicU64::new(0),
        }
    }
}

impl fmt::Debug for PoolStatCounters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolStatCounters")
            .field(
                "total_acquisitions",
                &self.total_acquisitions.load(Ordering::Relaxed),
            )
            .field("total_creates", &self.total_creates.load(Ordering::Relaxed))
            .field(
                "total_discards",
                &self.total_discards.load(Ordering::Relaxed),
            )
            .field(
                "total_timeouts",
                &self.total_timeouts.load(Ordering::Relaxed),
            )
            .field(
                "total_validation_failures",
                &self.total_validation_failures.load(Ordering::Relaxed),
            )
            .finish()
    }
}

/// Statistics for a database connection pool.
#[derive(Debug, Clone, Default)]
pub struct DbPoolStats {
    /// Number of idle connections.
    pub idle: usize,
    /// Number of active (checked out) connections.
    pub active: usize,
    /// Total connections (idle + active).
    pub total: usize,
    /// Maximum pool size.
    pub max_size: usize,
    /// Total successful acquisitions.
    pub total_acquisitions: u64,
    /// Total connections created.
    pub total_creates: u64,
    /// Total connections discarded.
    pub total_discards: u64,
    /// Total timeout errors.
    pub total_timeouts: u64,
    /// Total validation failures.
    pub total_validation_failures: u64,
}

/// Error returned by pool operations.
#[derive(Debug)]
pub enum DbPoolError<E: std::error::Error> {
    /// Pool is closed.
    Closed,
    /// Pool is at capacity.
    Full,
    /// Connection timed out.
    Timeout,
    /// Connection creation failed.
    Connect(E),
    /// Connection validation failed.
    ValidationFailed,
}

impl<E: std::error::Error> fmt::Display for DbPoolError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "pool closed"),
            Self::Full => write!(f, "pool at capacity"),
            Self::Timeout => write!(f, "connection acquisition timed out"),
            Self::Connect(e) => write!(f, "connection failed: {e}"),
            Self::ValidationFailed => write!(f, "connection validation failed"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for DbPoolError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) => Some(e),
            _ => None,
        }
    }
}

struct ValidationGuard<'a, M: ConnectionManager> {
    pool: &'a DbPool<M>,
    conn: Option<M::Connection>,
}

impl<M: ConnectionManager> Drop for ValidationGuard<'_, M> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let mut inner = self.pool.inner.lock();
            inner.total = inner.total.saturating_sub(1);
            drop(inner);
            self.pool
                .stats
                .total_discards
                .fetch_add(1, Ordering::Relaxed);
            self.pool.manager.disconnect(conn);
        }
    }
}

struct CreationGuard<'a, M: ConnectionManager> {
    pool: &'a DbPool<M>,
    disarmed: bool,
}

impl<M: ConnectionManager> Drop for CreationGuard<'_, M> {
    fn drop(&mut self) {
        if !self.disarmed {
            let mut inner = self.pool.inner.lock();
            inner.total = inner.total.saturating_sub(1);
        }
    }
}

impl<M: ConnectionManager> DbPool<M> {
    /// Create a new connection pool with the given manager and configuration.
    pub fn new(manager: M, config: DbPoolConfig) -> Self {
        Self {
            manager: Arc::new(manager),
            config,
            inner: Mutex::new(PoolInner {
                idle: VecDeque::new(),
                total: 0,
                closed: false,
            }),
            stats: PoolStatCounters::default(),
        }
    }

    /// Create a pool with default configuration.
    pub fn with_manager(manager: M) -> Self {
        Self::new(manager, DbPoolConfig::default())
    }

    /// Get the pool configuration.
    #[must_use]
    pub fn config(&self) -> &DbPoolConfig {
        &self.config
    }

    /// Get current pool statistics.
    #[must_use]
    pub fn stats(&self) -> DbPoolStats {
        let inner = self.inner.lock();
        DbPoolStats {
            idle: inner.idle.len(),
            active: inner.total.saturating_sub(inner.idle.len()),
            total: inner.total,
            max_size: self.config.max_size,
            total_acquisitions: self.stats.total_acquisitions.load(Ordering::Relaxed),
            total_creates: self.stats.total_creates.load(Ordering::Relaxed),
            total_discards: self.stats.total_discards.load(Ordering::Relaxed),
            total_timeouts: self.stats.total_timeouts.load(Ordering::Relaxed),
            total_validation_failures: self.stats.total_validation_failures.load(Ordering::Relaxed),
        }
    }

    /// Acquire a connection from the pool.
    ///
    /// Returns a `PooledConnection` that automatically returns the connection
    /// to the pool when dropped.
    pub fn get(&self) -> Result<PooledConnection<'_, M>, DbPoolError<M::Error>> {
        loop {
            let conn_to_validate = {
                let mut inner = self.inner.lock();

                if inner.closed {
                    return Err(DbPoolError::Closed);
                }

                let mut popped = None;
                if let Some(idle) = inner.idle.pop_front() {
                    if idle.is_expired(&self.config) || idle.is_idle_too_long(&self.config) {
                        inner.total = inner.total.saturating_sub(1);
                        self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                        popped = Some((idle.conn, false, idle.created_at));
                    } else {
                        popped = Some((idle.conn, true, idle.created_at));
                    }
                }

                if popped.is_none() {
                    // No valid idle connection; create new if under capacity.
                    if inner.total < self.config.max_size {
                        inner.total += 1;
                        // Release lock during creation.
                    } else {
                        return Err(DbPoolError::Full);
                    }
                }
                drop(inner);
                popped
            };

            if let Some((conn, needs_validation, created_at)) = conn_to_validate {
                if !needs_validation {
                    self.manager.disconnect(conn);
                    continue;
                }

                // Validate if configured.
                if self.config.validate_on_checkout {
                    let mut guard = ValidationGuard {
                        pool: self,
                        conn: Some(conn),
                    };

                    let valid = self.manager.is_valid(guard.conn.as_ref().unwrap());

                    if !valid {
                        self.stats
                            .total_validation_failures
                            .fetch_add(1, Ordering::Relaxed);
                        // Guard will drop here and safely decrement total & disconnect
                        continue;
                    }

                    let valid_conn = guard.conn.take().unwrap();
                    self.stats
                        .total_acquisitions
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(PooledConnection {
                        conn: Some(valid_conn),
                        pool: self,
                        created_at,
                    });
                }

                self.stats
                    .total_acquisitions
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(PooledConnection {
                    conn: Some(conn),
                    pool: self,
                    created_at,
                });
            }

            let mut creation_guard = CreationGuard {
                pool: self,
                disarmed: false,
            };

            match self.manager.connect() {
                Ok(conn) => {
                    creation_guard.disarmed = true;
                    self.stats.total_creates.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .total_acquisitions
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(PooledConnection {
                        conn: Some(conn),
                        pool: self,
                        created_at: Instant::now(),
                    });
                }
                Err(e) => {
                    // Drop guard rolls back total count on failure (or panic).
                    return Err(DbPoolError::Connect(e));
                }
            }
        }
    }

    /// Acquire a connection with retry and exponential backoff.
    ///
    /// On transient failures (`Connect` error or `Full` pool), retries
    /// with exponential backoff per the given policy. Total time is
    /// bounded by `connection_timeout` from the pool config.
    ///
    /// # Contract: C-RTY-03
    ///
    /// 1. First attempt: immediate.
    /// 2. On connection failure: retry with `initial_delay`.
    /// 3. Total attempts bounded by `max_attempts`.
    /// 4. Total time bounded by `connection_timeout`.
    /// 5. No resource leak on any failure path.
    pub fn get_with_retry(
        &self,
        policy: &RetryPolicy,
    ) -> Result<PooledConnection<'_, M>, DbPoolError<M::Error>> {
        let deadline = Instant::now() + self.config.connection_timeout;
        let mut attempt = 0u32;

        loop {
            attempt += 1;

            match self.get() {
                Ok(conn) => return Ok(conn),
                Err(DbPoolError::Closed) => return Err(DbPoolError::Closed),
                Err(e) => {
                    // Connect and Full are retryable; others are not.
                    if !matches!(e, DbPoolError::Connect(_) | DbPoolError::Full) {
                        return Err(e);
                    }

                    if attempt >= policy.max_attempts {
                        return Err(e);
                    }

                    // Check if deadline already passed.
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout);
                    }

                    // Calculate backoff delay (no jitter in synchronous context).
                    let delay = calculate_delay(policy, attempt, None);
                    std::thread::sleep(delay.min(remaining));

                    // Re-check deadline after sleep.
                    if Instant::now() >= deadline {
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout);
                    }
                }
            }
        }
    }

    /// Try to acquire without blocking. Returns `None` if no connection available.
    #[must_use]
    pub fn try_get(&self) -> Option<PooledConnection<'_, M>> {
        self.get().ok()
    }

    /// Return a connection to the pool, preserving its original creation time.
    fn return_connection(&self, conn: M::Connection, created_at: Instant) {
        let conn_to_disconnect = {
            let mut inner = self.inner.lock();
            if inner.closed {
                inner.total = inner.total.saturating_sub(1);
                Some(conn)
            } else {
                inner.idle.push_back(IdleConnection {
                    conn,
                    created_at,
                    last_used: Instant::now(),
                });
                None
            }
        };

        if let Some(c) = conn_to_disconnect {
            self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
            self.manager.disconnect(c);
        }
    }

    /// Discard a connection (don't return to pool).
    fn discard_connection(&self, conn: M::Connection) {
        {
            let mut inner = self.inner.lock();
            inner.total = inner.total.saturating_sub(1);
        }
        self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
        self.manager.disconnect(conn);
    }

    /// Close the pool, preventing new acquisitions.
    ///
    /// Existing checked-out connections will be discarded when returned.
    pub fn close(&self) {
        let mut inner = self.inner.lock();
        inner.closed = true;
        // Drain idle connections.
        let idle: Vec<_> = inner.idle.drain(..).collect();
        let drained = idle.len();
        inner.total = inner.total.saturating_sub(drained);
        if drained > 0 {
            self.stats
                .total_discards
                .fetch_add(drained as u64, Ordering::Relaxed);
        }
        drop(inner);
        for entry in idle {
            self.manager.disconnect(entry.conn);
        }
    }

    /// Returns `true` if the pool is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().closed
    }

    /// Evict all idle connections that are expired or stale.
    ///
    /// Returns the number of connections evicted.
    pub fn evict_stale(&self) -> usize {
        let mut inner = self.inner.lock();

        // Drain all idle, keep only the valid ones.
        let mut keep = VecDeque::new();
        let mut to_disconnect = Vec::new();

        while let Some(entry) = inner.idle.pop_front() {
            if entry.is_expired(&self.config) || entry.is_idle_too_long(&self.config) {
                to_disconnect.push(entry.conn);
            } else {
                keep.push_back(entry);
            }
        }

        let evicted = to_disconnect.len();
        inner.idle = keep;
        inner.total = inner.total.saturating_sub(evicted);
        drop(inner);

        for conn in to_disconnect {
            self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
            self.manager.disconnect(conn);
        }
        evicted
    }

    /// Pre-warm the pool by creating connections up to min_idle.
    ///
    /// Returns the number of connections successfully created.
    pub fn warm_up(&self) -> usize {
        let mut created = 0;
        for _ in 0..self.config.min_idle {
            let mut inner = self.inner.lock();
            if inner.total >= self.config.max_size || inner.closed {
                break;
            }
            inner.total += 1;
            drop(inner);

            if let Ok(conn) = self.manager.connect() {
                self.stats.total_creates.fetch_add(1, Ordering::Relaxed);
                self.return_connection(conn, Instant::now());
                created += 1;
            } else {
                let mut inner = self.inner.lock();
                inner.total = inner.total.saturating_sub(1);
            }
        }
        created
    }
}

impl<M: ConnectionManager> Drop for DbPool<M> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<M: ConnectionManager> fmt::Debug for DbPool<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("DbPool")
            .field("idle", &inner.idle.len())
            .field("total", &inner.total)
            .field("max_size", &self.config.max_size)
            .field("closed", &inner.closed)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

// ─── PooledConnection ───────────────────────────────────────────────────────

/// A connection borrowed from the pool.
///
/// Automatically returns the connection to the pool on drop.
/// Use [`discard`](PooledConnection::discard) to permanently remove
/// a broken connection.
pub struct PooledConnection<'a, M: ConnectionManager> {
    conn: Option<M::Connection>,
    pool: &'a DbPool<M>,
    created_at: Instant,
}

impl<M: ConnectionManager> PooledConnection<'_, M> {
    /// Access the underlying connection.
    #[must_use]
    pub fn get(&self) -> &M::Connection {
        self.conn.as_ref().expect("connection already taken")
    }

    /// Access the underlying connection mutably.
    pub fn get_mut(&mut self) -> &mut M::Connection {
        self.conn.as_mut().expect("connection already taken")
    }

    /// Explicitly return the connection to the pool.
    pub fn return_to_pool(mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.return_connection(conn, self.created_at);
        }
    }

    /// Discard this connection instead of returning it.
    ///
    /// Use when the connection is broken or in an invalid state.
    pub fn discard(mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.discard_connection(conn);
        }
    }
}

impl<M: ConnectionManager> std::ops::Deref for PooledConnection<'_, M> {
    type Target = M::Connection;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<M: ConnectionManager> std::ops::DerefMut for PooledConnection<'_, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

impl<M: ConnectionManager> Drop for PooledConnection<'_, M> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.return_connection(conn, self.created_at);
        }
    }
}

impl<M: ConnectionManager> fmt::Debug for PooledConnection<'_, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PooledConnection")
            .field("active", &self.conn.is_some())
            .finish()
    }
}

// ─── AsyncConnectionManager ─────────────────────────────────────────────────

use crate::cx::Cx;
use crate::types::Outcome;

/// Async connection manager for database backends whose `connect` and
/// `is_valid` operations are asynchronous and require a [`Cx`].
///
/// This is the async counterpart of [`ConnectionManager`], designed for
/// clients like PostgreSQL whose connect methods are async and return
/// [`Outcome`].
pub trait AsyncConnectionManager: Send + Sync + 'static {
    /// The connection type managed by this manager.
    type Connection: Send + 'static;

    /// Error type for connection operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Create a new connection asynchronously.
    fn connect(
        &self,
        cx: &Cx,
    ) -> impl std::future::Future<Output = Outcome<Self::Connection, Self::Error>> + Send;

    /// Validate that a connection is still usable.
    ///
    /// Takes `&mut` because validation typically requires sending a query
    /// that mutates protocol state.
    fn is_valid(
        &self,
        cx: &Cx,
        conn: &mut Self::Connection,
    ) -> impl std::future::Future<Output = bool> + Send;

    /// Called when a connection is permanently removed from the pool.
    fn disconnect(&self, _conn: Self::Connection) {}
}

// ─── AsyncDbPool ─────────────────────────────────────────────────────────────

/// An async database connection pool with health checks.
///
/// The async counterpart of [`DbPool`], designed for backends whose connect
/// and validate operations are asynchronous. All acquisition methods take a
/// [`Cx`] for cancellation integration.
pub struct AsyncDbPool<M: AsyncConnectionManager> {
    manager: Arc<M>,
    config: DbPoolConfig,
    inner: Mutex<PoolInner<M::Connection>>,
    stats: PoolStatCounters,
}

struct AsyncValidationGuard<'a, M: AsyncConnectionManager> {
    pool: &'a AsyncDbPool<M>,
    conn: Option<M::Connection>,
}

impl<M: AsyncConnectionManager> Drop for AsyncValidationGuard<'_, M> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let mut inner = self.pool.inner.lock();
            inner.total = inner.total.saturating_sub(1);
            drop(inner);
            self.pool
                .stats
                .total_discards
                .fetch_add(1, Ordering::Relaxed);
            self.pool.manager.disconnect(conn);
        }
    }
}

struct AsyncCreationGuard<'a, M: AsyncConnectionManager> {
    pool: &'a AsyncDbPool<M>,
    disarmed: bool,
}

impl<M: AsyncConnectionManager> Drop for AsyncCreationGuard<'_, M> {
    fn drop(&mut self) {
        if !self.disarmed {
            let mut inner = self.pool.inner.lock();
            inner.total = inner.total.saturating_sub(1);
        }
    }
}

impl<M: AsyncConnectionManager> AsyncDbPool<M> {
    /// Create a new async connection pool.
    pub fn new(manager: M, config: DbPoolConfig) -> Self {
        Self {
            manager: Arc::new(manager),
            config,
            inner: Mutex::new(PoolInner {
                idle: VecDeque::new(),
                total: 0,
                closed: false,
            }),
            stats: PoolStatCounters::default(),
        }
    }

    /// Create a pool with default configuration.
    pub fn with_manager(manager: M) -> Self {
        Self::new(manager, DbPoolConfig::default())
    }

    /// Get the pool configuration.
    #[must_use]
    pub fn config(&self) -> &DbPoolConfig {
        &self.config
    }

    /// Get current pool statistics.
    #[must_use]
    pub fn stats(&self) -> DbPoolStats {
        let inner = self.inner.lock();
        DbPoolStats {
            idle: inner.idle.len(),
            active: inner.total.saturating_sub(inner.idle.len()),
            total: inner.total,
            max_size: self.config.max_size,
            total_acquisitions: self.stats.total_acquisitions.load(Ordering::Relaxed),
            total_creates: self.stats.total_creates.load(Ordering::Relaxed),
            total_discards: self.stats.total_discards.load(Ordering::Relaxed),
            total_timeouts: self.stats.total_timeouts.load(Ordering::Relaxed),
            total_validation_failures: self.stats.total_validation_failures.load(Ordering::Relaxed),
        }
    }

    async fn sleep_retry_backoff(cx: &Cx, mut duration: Duration) -> bool {
        const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(10);

        while !duration.is_zero() {
            if cx.checkpoint().is_err() {
                return false;
            }

            let chunk = duration.min(CANCEL_POLL_INTERVAL);
            crate::time::sleep(cx.now(), chunk).await;
            duration = duration.saturating_sub(chunk);
        }

        cx.checkpoint().is_ok()
    }

    /// Acquire a connection from the pool.
    pub async fn get(
        &self,
        cx: &Cx,
    ) -> Result<AsyncPooledConnection<'_, M>, DbPoolError<M::Error>> {
        loop {
            if cx.checkpoint().is_err() {
                return Err(DbPoolError::Timeout);
            }

            let candidate = {
                let mut inner = self.inner.lock();
                if inner.closed {
                    return Err(DbPoolError::Closed);
                }
                inner.idle.pop_front()
            };

            if let Some(idle) = candidate {
                let is_expired = idle.is_expired(&self.config);
                let is_stale = idle.is_idle_too_long(&self.config);

                if is_expired || is_stale {
                    {
                        let mut inner = self.inner.lock();
                        inner.total = inner.total.saturating_sub(1);
                    }
                    self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                    self.manager.disconnect(idle.conn);
                    continue;
                }

                if self.config.validate_on_checkout {
                    let mut guard = AsyncValidationGuard {
                        pool: self,
                        conn: Some(idle.conn),
                    };

                    let valid = self
                        .manager
                        .is_valid(cx, guard.conn.as_mut().unwrap())
                        .await;

                    if cx.checkpoint().is_err() {
                        return Err(DbPoolError::Timeout);
                    }

                    if !valid {
                        self.stats
                            .total_validation_failures
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    let conn = guard.conn.take().unwrap();
                    return self.finish_async_checkout(conn, idle.created_at);
                }

                return self.finish_async_checkout(idle.conn, idle.created_at);
            }

            {
                let mut inner = self.inner.lock();
                if inner.total >= self.config.max_size {
                    return Err(DbPoolError::Full);
                }
                inner.total += 1;
            }

            let mut creation_guard = AsyncCreationGuard {
                pool: self,
                disarmed: false,
            };

            match self.manager.connect(cx).await {
                Outcome::Ok(conn) => {
                    if cx.checkpoint().is_err() {
                        self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                        self.manager.disconnect(conn);
                        return Err(DbPoolError::Timeout);
                    }
                    creation_guard.disarmed = true;
                    self.stats.total_creates.fetch_add(1, Ordering::Relaxed);
                    return self.finish_async_checkout(conn, Instant::now());
                }
                Outcome::Err(e) => return Err(DbPoolError::Connect(e)),
                Outcome::Cancelled(_) | Outcome::Panicked(_) => {
                    return Err(DbPoolError::Timeout);
                }
            }
        }
    }

    /// Acquire a connection with retry and exponential backoff.
    pub async fn get_with_retry(
        &self,
        cx: &Cx,
        policy: &RetryPolicy,
    ) -> Result<AsyncPooledConnection<'_, M>, DbPoolError<M::Error>> {
        let deadline = crate::time::wall_now() + self.config.connection_timeout;
        let mut attempt = 0u32;

        loop {
            attempt += 1;

            match self.get(cx).await {
                Ok(conn) => return Ok(conn),
                Err(DbPoolError::Closed) => return Err(DbPoolError::Closed),
                Err(e) => {
                    if !matches!(e, DbPoolError::Connect(_) | DbPoolError::Full) {
                        return Err(e);
                    }

                    if attempt >= policy.max_attempts {
                        return Err(e);
                    }

                    let remaining = std::time::Duration::from_nanos(
                        deadline.duration_since(crate::time::wall_now()),
                    );
                    if remaining.is_zero() || cx.checkpoint().is_err() {
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout);
                    }

                    let delay = calculate_delay(policy, attempt, None);
                    if !Self::sleep_retry_backoff(cx, delay.min(remaining)).await {
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout);
                    }

                    if crate::time::wall_now() >= deadline || cx.checkpoint().is_err() {
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout);
                    }
                }
            }
        }
    }

    fn finish_async_checkout(
        &self,
        conn: M::Connection,
        created_at: Instant,
    ) -> Result<AsyncPooledConnection<'_, M>, DbPoolError<M::Error>> {
        {
            let mut inner = self.inner.lock();
            if inner.closed {
                inner.total = inner.total.saturating_sub(1);
                drop(inner);
                self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                self.manager.disconnect(conn);
                return Err(DbPoolError::Closed);
            }
        }

        self.stats
            .total_acquisitions
            .fetch_add(1, Ordering::Relaxed);
        Ok(AsyncPooledConnection {
            conn: Some(conn),
            pool: self,
            created_at,
        })
    }

    /// Return a connection to the pool.
    fn return_connection(&self, conn: M::Connection, created_at: Instant) {
        let conn_to_disconnect = {
            let mut inner = self.inner.lock();
            if inner.closed {
                inner.total = inner.total.saturating_sub(1);
                Some(conn)
            } else {
                inner.idle.push_back(IdleConnection {
                    conn,
                    created_at,
                    last_used: Instant::now(),
                });
                None
            }
        };

        if let Some(conn) = conn_to_disconnect {
            self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
            self.manager.disconnect(conn);
        }
    }

    /// Discard a connection instead of returning it to the pool.
    fn discard_connection(&self, conn: M::Connection) {
        {
            let mut inner = self.inner.lock();
            inner.total = inner.total.saturating_sub(1);
        }
        self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
        self.manager.disconnect(conn);
    }

    /// Close the pool, preventing new acquisitions.
    pub fn close(&self) {
        let mut inner = self.inner.lock();
        inner.closed = true;
        let idle: Vec<_> = inner.idle.drain(..).collect();
        let drained = idle.len();
        inner.total = inner.total.saturating_sub(drained);
        if drained > 0 {
            self.stats
                .total_discards
                .fetch_add(drained as u64, Ordering::Relaxed);
        }
        drop(inner);
        for entry in idle {
            self.manager.disconnect(entry.conn);
        }
    }

    /// Returns `true` if the pool is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().closed
    }
}

impl<M: AsyncConnectionManager> Drop for AsyncDbPool<M> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<M: AsyncConnectionManager> fmt::Debug for AsyncDbPool<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("AsyncDbPool")
            .field("idle", &inner.idle.len())
            .field("total", &inner.total)
            .field("max_size", &self.config.max_size)
            .field("closed", &inner.closed)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

// ─── AsyncPooledConnection ───────────────────────────────────────────────────

/// A connection borrowed from an [`AsyncDbPool`].
///
/// Automatically returns the connection to the pool on drop.
pub struct AsyncPooledConnection<'a, M: AsyncConnectionManager> {
    conn: Option<M::Connection>,
    pool: &'a AsyncDbPool<M>,
    created_at: Instant,
}

impl<M: AsyncConnectionManager> AsyncPooledConnection<'_, M> {
    /// Access the underlying connection.
    #[must_use]
    pub fn get(&self) -> &M::Connection {
        self.conn.as_ref().expect("connection already taken")
    }

    /// Access the underlying connection mutably.
    pub fn get_mut(&mut self) -> &mut M::Connection {
        self.conn.as_mut().expect("connection already taken")
    }

    /// Explicitly return the connection to the pool.
    pub fn return_to_pool(mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.return_connection(conn, self.created_at);
        }
    }

    /// Discard this connection instead of returning it.
    pub fn discard(mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.discard_connection(conn);
        }
    }
}

impl<M: AsyncConnectionManager> std::ops::Deref for AsyncPooledConnection<'_, M> {
    type Target = M::Connection;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<M: AsyncConnectionManager> std::ops::DerefMut for AsyncPooledConnection<'_, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

impl<M: AsyncConnectionManager> Drop for AsyncPooledConnection<'_, M> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.return_connection(conn, self.created_at);
        }
    }
}

impl<M: AsyncConnectionManager> fmt::Debug for AsyncPooledConnection<'_, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncPooledConnection")
            .field("active", &self.conn.is_some())
            .finish()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

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
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::runtime::yield_now;
    use crate::types::Budget;
    use futures_lite::future::block_on;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn db_pool_stats_snapshot(stats: &DbPoolStats) -> serde_json::Value {
        json!({
            "idle": stats.idle,
            "active": stats.active,
            "total": stats.total,
            "max_size": stats.max_size,
            "total_acquisitions": stats.total_acquisitions,
            "total_creates": stats.total_creates,
            "total_discards": stats.total_discards,
            "total_timeouts": stats.total_timeouts,
            "total_validation_failures": stats.total_validation_failures,
        })
    }

    fn db_pool_inventory_snapshot(stats: &DbPoolStats) -> serde_json::Value {
        json!({
            "idle": stats.idle,
            "active": stats.active,
            "total": stats.total,
            "max_size": stats.max_size,
        })
    }

    // ================================================================
    // Test connection manager
    // ================================================================

    /// A simple in-memory connection for testing.
    #[derive(Debug)]
    struct TestConnection {
        id: usize,
        valid: Arc<AtomicBool>,
    }

    #[derive(Clone)]
    struct TestManager {
        next_id: Arc<AtomicUsize>,
        valid: Arc<AtomicBool>,
        creates: Arc<AtomicUsize>,
        disconnects: Arc<AtomicUsize>,
        fail_connect: Arc<AtomicBool>,
    }

    impl TestManager {
        fn new() -> Self {
            Self {
                next_id: Arc::new(AtomicUsize::new(1)),
                valid: Arc::new(AtomicBool::new(true)),
                creates: Arc::new(AtomicUsize::new(0)),
                disconnects: Arc::new(AtomicUsize::new(0)),
                fail_connect: Arc::new(AtomicBool::new(false)),
            }
        }

        fn disconnects(&self) -> usize {
            self.disconnects.load(Ordering::SeqCst)
        }

        fn set_fail_connect(&self, fail: bool) {
            self.fail_connect.store(fail, Ordering::SeqCst);
        }

        fn set_valid(&self, valid: bool) {
            self.valid.store(valid, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct TestError(String);

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for TestError {}

    impl ConnectionManager for TestManager {
        type Connection = TestConnection;
        type Error = TestError;

        fn connect(&self) -> Result<Self::Connection, Self::Error> {
            if self.fail_connect.load(Ordering::SeqCst) {
                return Err(TestError("connection refused".to_string()));
            }
            self.creates.fetch_add(1, Ordering::SeqCst);
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            Ok(TestConnection {
                id,
                valid: self.valid.clone(),
            })
        }

        fn is_valid(&self, conn: &Self::Connection) -> bool {
            conn.valid.load(Ordering::SeqCst)
        }

        fn disconnect(&self, _conn: Self::Connection) {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct AsyncTestManager {
        next_id: AtomicUsize,
        valid: Arc<AtomicBool>,
        creates: AtomicUsize,
        disconnects: AtomicUsize,
        fail_connect: AtomicBool,
    }

    impl AsyncTestManager {
        fn new() -> Self {
            Self {
                next_id: AtomicUsize::new(1),
                valid: Arc::new(AtomicBool::new(true)),
                creates: AtomicUsize::new(0),
                disconnects: AtomicUsize::new(0),
                fail_connect: AtomicBool::new(false),
            }
        }

        fn always_failing() -> Self {
            let manager = Self::new();
            manager.fail_connect.store(true, Ordering::SeqCst);
            manager
        }
    }

    impl AsyncConnectionManager for AsyncTestManager {
        type Connection = TestConnection;
        type Error = TestError;

        async fn connect(&self, _cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
            if self.fail_connect.load(Ordering::SeqCst) {
                return Outcome::Err(TestError("connection refused".to_string()));
            }

            self.creates.fetch_add(1, Ordering::SeqCst);
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            Outcome::Ok(TestConnection {
                id,
                valid: self.valid.clone(),
            })
        }

        async fn is_valid(&self, _cx: &Cx, conn: &mut Self::Connection) -> bool {
            conn.valid.load(Ordering::SeqCst)
        }

        fn disconnect(&self, _conn: Self::Connection) {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct SlowAsyncTestManager {
        next_id: AtomicUsize,
        valid: Arc<AtomicBool>,
        disconnects: AtomicUsize,
        connect_delay: Duration,
        validate_delay: Duration,
    }

    impl SlowAsyncTestManager {
        fn with_delays(connect_delay: Duration, validate_delay: Duration) -> Self {
            Self {
                next_id: AtomicUsize::new(1),
                valid: Arc::new(AtomicBool::new(true)),
                disconnects: AtomicUsize::new(0),
                connect_delay,
                validate_delay,
            }
        }

        fn disconnects(&self) -> usize {
            self.disconnects.load(Ordering::SeqCst)
        }
    }

    impl AsyncConnectionManager for SlowAsyncTestManager {
        type Connection = TestConnection;
        type Error = TestError;

        async fn connect(&self, _cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
            crate::time::sleep(crate::time::wall_now(), self.connect_delay).await;
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            Outcome::Ok(TestConnection {
                id,
                valid: self.valid.clone(),
            })
        }

        async fn is_valid(&self, _cx: &Cx, conn: &mut Self::Connection) -> bool {
            crate::time::sleep(crate::time::wall_now(), self.validate_delay).await;
            conn.valid.load(Ordering::SeqCst)
        }

        fn disconnect(&self, _conn: Self::Connection) {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
        }
    }

    // ================================================================
    // DbPoolConfig
    // ================================================================

    #[test]
    fn config_defaults() {
        init_test("config_defaults");
        let config = DbPoolConfig::default();
        assert_eq!(config.min_idle, 1);
        assert_eq!(config.max_size, 10);
        assert!(config.validate_on_checkout);
        assert_eq!(config.idle_timeout, Duration::from_secs(600));
        assert_eq!(config.max_lifetime, Duration::from_secs(3600));
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
        crate::test_complete!("config_defaults");
    }

    #[test]
    fn config_builder() {
        init_test("config_builder");
        let config = DbPoolConfig::with_max_size(20)
            .min_idle(5)
            .validate_on_checkout(false)
            .idle_timeout(Duration::from_secs(120))
            .max_lifetime(Duration::from_secs(600))
            .connection_timeout(Duration::from_secs(10));

        assert_eq!(config.max_size, 20);
        assert_eq!(config.min_idle, 5);
        assert!(!config.validate_on_checkout);
        assert_eq!(config.idle_timeout, Duration::from_secs(120));
        assert_eq!(config.max_lifetime, Duration::from_secs(600));
        assert_eq!(config.connection_timeout, Duration::from_secs(10));
        crate::test_complete!("config_builder");
    }

    #[test]
    fn config_debug_clone() {
        let config = DbPoolConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("DbPoolConfig"));
        let cloned = config;
        assert_eq!(cloned.max_size, 10);
    }

    // ================================================================
    // DbPool basics
    // ================================================================

    #[test]
    fn pool_new() {
        init_test("pool_new");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let stats = pool.stats();
        assert_eq!(stats.idle, 0);
        assert_eq!(stats.active, 0);
        assert_eq!(stats.total, 0);
        assert_eq!(stats.max_size, 10);
        assert!(!pool.is_closed());
        crate::test_complete!("pool_new");
    }

    #[test]
    fn async_get_with_retry_observes_cancellation_during_backoff() {
        init_test("async_get_with_retry_observes_cancellation_during_backoff");
        let pool = AsyncDbPool::new(
            AsyncTestManager::always_failing(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(1)),
        );
        let policy = RetryPolicy::fixed_delay(Duration::from_millis(250), 3);
        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            cancel_cx.set_cancel_requested(true);
        });

        let started = Instant::now();
        let result = block_on(pool.get_with_retry(&cx, &policy));
        let elapsed = started.elapsed();

        canceller
            .join()
            .expect("cancel thread should finish cleanly");

        assert!(matches!(result, Err(DbPoolError::Timeout)));
        assert!(
            elapsed < Duration::from_millis(200),
            "cancellation during backoff should stop promptly, observed {elapsed:?}"
        );
        let stats = pool.stats();
        assert_eq!(
            stats.total, 0,
            "cancelled retries must not leak connections"
        );
        assert_eq!(
            stats.active, 0,
            "cancelled retries must not hold active leases"
        );
        crate::test_complete!("async_get_with_retry_observes_cancellation_during_backoff");
    }

    #[test]
    fn async_get_cancellation_after_connect_does_not_hand_out_connection() {
        init_test("async_get_cancellation_after_connect_does_not_hand_out_connection");
        let pool = AsyncDbPool::new(
            SlowAsyncTestManager::with_delays(Duration::from_millis(40), Duration::ZERO),
            DbPoolConfig::with_max_size(1).validate_on_checkout(false),
        );
        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            cancel_cx.set_cancel_requested(true);
        });

        let result = block_on(pool.get(&cx));

        canceller
            .join()
            .expect("cancel thread should finish cleanly");

        assert!(matches!(result, Err(DbPoolError::Timeout)));
        let stats = pool.stats();
        assert_eq!(stats.total, 0, "cancelled connect must not retain capacity");
        assert_eq!(
            stats.active, 0,
            "cancelled connect must not hand out a lease"
        );
        assert_eq!(
            stats.total_discards, 1,
            "late connect success should be disconnected"
        );
        assert_eq!(pool.manager.disconnects(), 1);
        crate::test_complete!("async_get_cancellation_after_connect_does_not_hand_out_connection");
    }

    #[test]
    fn async_get_cancellation_during_validation_discards_connection() {
        init_test("async_get_cancellation_during_validation_discards_connection");
        let pool = AsyncDbPool::new(
            SlowAsyncTestManager::with_delays(Duration::ZERO, Duration::from_millis(40)),
            DbPoolConfig::with_max_size(1),
        );

        let warm_cx = Cx::for_testing();
        let conn = block_on(pool.get(&warm_cx)).expect("warmup acquire should succeed");
        conn.return_to_pool();
        assert_eq!(
            pool.stats().idle,
            1,
            "warmup should leave one idle connection"
        );

        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            cancel_cx.set_cancel_requested(true);
        });

        let result = block_on(pool.get(&cx));

        canceller
            .join()
            .expect("cancel thread should finish cleanly");

        assert!(matches!(result, Err(DbPoolError::Timeout)));
        let stats = pool.stats();
        assert_eq!(
            stats.total, 0,
            "cancelled validation must discard the in-flight connection"
        );
        assert_eq!(
            stats.active, 0,
            "cancelled validation must not leak a checked-out lease"
        );
        assert_eq!(
            stats.idle, 0,
            "cancelled validation must not return the stale connection"
        );
        assert_eq!(
            stats.total_discards, 1,
            "validated connection cancelled mid-flight should be disconnected"
        );
        assert_eq!(pool.manager.disconnects(), 1);
        crate::test_complete!("async_get_cancellation_during_validation_discards_connection");
    }

    #[test]
    fn mr_cancelled_async_acquire_releases_slot_across_cancellation_points() {
        init_test("mr_cancelled_async_acquire_releases_slot_across_cancellation_points");
        let mut recovered_inventory = Vec::new();

        for (name, connect_delay, validate_delay, needs_warm_idle) in [
            (
                "after_connect",
                Duration::from_millis(40),
                Duration::ZERO,
                false,
            ),
            (
                "during_validation",
                Duration::ZERO,
                Duration::from_millis(40),
                true,
            ),
        ] {
            let pool = AsyncDbPool::new(
                SlowAsyncTestManager::with_delays(connect_delay, validate_delay),
                DbPoolConfig::with_max_size(1).validate_on_checkout(!validate_delay.is_zero()),
            );

            if needs_warm_idle {
                let warm_cx = Cx::for_testing();
                let lease = block_on(pool.get(&warm_cx)).expect("warmup acquire should succeed");
                lease.return_to_pool();
                assert_eq!(
                    pool.stats().idle,
                    1,
                    "{name} should start from an idle lease"
                );
            }

            let cx = Cx::for_testing();
            let cancel_cx = cx.clone();
            let canceller = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                cancel_cx.set_cancel_requested(true);
            });

            let result = block_on(pool.get(&cx));

            canceller
                .join()
                .expect("cancel thread should finish cleanly");

            assert!(
                matches!(result, Err(DbPoolError::Timeout)),
                "{name} cancellation point should time out the acquire"
            );

            let post_cancel = pool.stats();
            assert_eq!(post_cancel.total, 0, "{name} must release total capacity");
            assert_eq!(post_cancel.active, 0, "{name} must release active capacity");
            assert_eq!(post_cancel.idle, 0, "{name} must leave no stale idle lease");

            let recovery_cx = Cx::for_testing();
            let recovery = block_on(pool.get(&recovery_cx))
                .expect("fresh acquire should succeed after cancelled attempt");
            recovery.return_to_pool();
            let final_stats = pool.stats();
            assert_eq!(
                final_stats.idle, 1,
                "{name} should recover one reusable idle lease"
            );
            assert_eq!(
                final_stats.active, 0,
                "{name} should not retain active leases"
            );
            assert_eq!(
                final_stats.total, 1,
                "{name} should recover exactly one slot"
            );
            recovered_inventory.push(db_pool_inventory_snapshot(&final_stats));
        }

        assert!(
            recovered_inventory
                .windows(2)
                .all(|pair| pair[0] == pair[1]),
            "cancellation point should not change recovered pool inventory"
        );
        crate::test_complete!(
            "mr_cancelled_async_acquire_releases_slot_across_cancellation_points"
        );
    }

    #[test]
    fn async_pool_contention_retries_under_lab_runtime() {
        init_test("async_pool_contention_retries_under_lab_runtime");
        let config = TestConfig::new()
            .with_seed(0xD8A5_E001)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let pool = Arc::new(AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_millis(200)),
        ));
        let retry_policy = RetryPolicy::fixed_delay(Duration::from_millis(5), 32);
        let checkpoints = Arc::new(Mutex::new(Vec::new()));
        let result_checkpoints = Arc::clone(&checkpoints);

        let (holder_id, waiter_id, final_stats) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = Cx::current().expect("lab runtime should install a current Cx");
                let holder_spawn_cx = cx.clone();
                let waiter_spawn_cx = cx.clone();

                let holder_pool = Arc::clone(&pool);
                let holder_checkpoints = Arc::clone(&checkpoints);
                let holder_task_cx = holder_spawn_cx.clone();
                let holder =
                    LabRuntimeTarget::spawn(&holder_spawn_cx, Budget::INFINITE, async move {
                        let lease = holder_pool
                            .get(&holder_task_cx)
                            .await
                            .expect("holder acquires pool lease");
                        let holder_id = lease.id;
                        let acquired = serde_json::json!({
                            "phase": "holder_acquired",
                            "connection_id": holder_id,
                        });
                        tracing::info!(event = %acquired, "pool_contention_lab_checkpoint");
                        holder_checkpoints.lock().push(acquired);

                        crate::time::sleep(holder_task_cx.now(), Duration::from_millis(25)).await;
                        yield_now().await;
                        lease.return_to_pool();

                        let returned = serde_json::json!({
                            "phase": "holder_returned",
                            "connection_id": holder_id,
                        });
                        tracing::info!(event = %returned, "pool_contention_lab_checkpoint");
                        holder_checkpoints.lock().push(returned);
                        holder_id
                    });

                let waiter_pool = Arc::clone(&pool);
                let waiter_checkpoints = Arc::clone(&checkpoints);
                let waiter_task_cx = waiter_spawn_cx.clone();
                let waiter =
                    LabRuntimeTarget::spawn(&waiter_spawn_cx, Budget::INFINITE, async move {
                        let started = serde_json::json!({
                            "phase": "waiter_started",
                            "max_attempts": retry_policy.max_attempts,
                        });
                        tracing::info!(event = %started, "pool_contention_lab_checkpoint");
                        waiter_checkpoints.lock().push(started);

                        let lease = waiter_pool
                            .get_with_retry(&waiter_task_cx, &retry_policy)
                            .await
                            .expect("waiter retries until the pool returns capacity");
                        let waiter_id = lease.id;
                        let acquired = serde_json::json!({
                            "phase": "waiter_acquired",
                            "connection_id": waiter_id,
                        });
                        tracing::info!(event = %acquired, "pool_contention_lab_checkpoint");
                        waiter_checkpoints.lock().push(acquired);
                        lease.return_to_pool();
                        waiter_id
                    });

                yield_now().await;

                let holder_outcome = holder.await;
                crate::assert_with_log!(
                    matches!(holder_outcome, crate::types::Outcome::Ok(_)),
                    "holder task completes successfully",
                    true,
                    matches!(holder_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(holder_id) = holder_outcome else {
                    unreachable!("validated successful holder outcome");
                };

                let waiter_outcome = waiter.await;
                crate::assert_with_log!(
                    matches!(waiter_outcome, crate::types::Outcome::Ok(_)),
                    "waiter task completes successfully",
                    true,
                    matches!(waiter_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(waiter_id) = waiter_outcome else {
                    unreachable!("validated successful waiter outcome");
                };

                (holder_id, waiter_id, pool.stats())
            });

        crate::assert_with_log!(
            holder_id == waiter_id,
            "waiter reuses returned connection",
            holder_id,
            waiter_id
        );
        crate::assert_with_log!(
            final_stats.total_creates == 1,
            "contention path creates only one connection",
            1,
            final_stats.total_creates
        );
        crate::assert_with_log!(
            final_stats.idle == 1,
            "connection returns to idle pool after both tasks",
            1,
            final_stats.idle
        );
        crate::assert_with_log!(
            final_stats.active == 0,
            "contention path leaves no active leases",
            0,
            final_stats.active
        );
        crate::assert_with_log!(
            result_checkpoints.lock().len() == 4,
            "lab runtime emits contention checkpoints",
            4,
            result_checkpoints.lock().len()
        );
        crate::assert_with_log!(
            runtime.is_quiescent(),
            "lab runtime reaches quiescence after pool contention",
            true,
            runtime.is_quiescent()
        );

        crate::test_complete!("async_pool_contention_retries_under_lab_runtime");
    }

    #[test]
    fn pool_with_manager() {
        init_test("pool_with_manager");
        let pool = DbPool::with_manager(TestManager::new());
        assert_eq!(pool.config().max_size, 10);
        crate::test_complete!("pool_with_manager");
    }

    #[test]
    fn pool_debug() {
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let dbg = format!("{pool:?}");
        assert!(dbg.contains("DbPool"));
        assert!(dbg.contains("max_size"));
        assert!(dbg.contains("stats"));
        assert!(dbg.contains("total_acquisitions: 0"));
    }

    #[test]
    fn async_pool_debug() {
        let pool = AsyncDbPool::new(AsyncTestManager::new(), DbPoolConfig::default());
        let dbg = format!("{pool:?}");
        assert!(dbg.contains("AsyncDbPool"));
        assert!(dbg.contains("stats"));
        assert!(dbg.contains("total_acquisitions: 0"));
    }

    #[test]
    fn async_pool_debug_reports_live_counter_values() {
        init_test("async_pool_debug_reports_live_counter_values");
        let pool = AsyncDbPool::new(AsyncTestManager::new(), DbPoolConfig::default());
        let cx = Cx::for_testing();
        let _conn = block_on(pool.get(&cx)).expect("async pool get should succeed");

        let dbg = format!("{pool:?}");
        assert!(dbg.contains("total_acquisitions: 1"));
        assert!(dbg.contains("total_creates: 1"));
        assert!(dbg.contains("total_discards: 0"));
        crate::test_complete!("async_pool_debug_reports_live_counter_values");
    }

    // ================================================================
    // Get / return
    // ================================================================

    #[test]
    fn get_creates_connection() {
        init_test("get_creates_connection");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let conn = pool.get().unwrap();
        assert_eq!(conn.id, 1);

        let stats = pool.stats();
        assert_eq!(stats.active, 1);
        assert_eq!(stats.total, 1);
        assert_eq!(stats.total_creates, 1);
        crate::test_complete!("get_creates_connection");
    }

    #[test]
    fn return_on_drop() {
        init_test("return_on_drop");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        {
            let _conn = pool.get().unwrap();
            assert_eq!(pool.stats().active, 1);
        }
        // Connection returned on drop.
        assert_eq!(pool.stats().idle, 1);
        assert_eq!(pool.stats().active, 0);
        crate::test_complete!("return_on_drop");
    }

    #[test]
    fn explicit_return() {
        init_test("explicit_return");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        let conn = pool.get().unwrap();
        conn.return_to_pool();
        assert_eq!(pool.stats().idle, 1);
        assert_eq!(pool.stats().active, 0);
        crate::test_complete!("explicit_return");
    }

    #[test]
    fn reuse_idle_connection() {
        init_test("reuse_idle_connection");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        // First checkout creates.
        let conn1 = pool.get().unwrap();
        let id1 = conn1.id;
        conn1.return_to_pool();

        // Second checkout reuses.
        let conn2 = pool.get().unwrap();
        assert_eq!(conn2.id, id1);
        assert_eq!(pool.stats().total_creates, 1);
        crate::test_complete!("reuse_idle_connection");
    }

    #[test]
    fn mr_idle_return_order_preserves_capacity_bounds() {
        init_test("mr_idle_return_order_preserves_capacity_bounds");
        const MAX_SIZE: usize = 3;
        let config = DbPoolConfig::with_max_size(MAX_SIZE).validate_on_checkout(false);
        let return_orders = [
            [0usize, 1usize, 2usize],
            [2usize, 1usize, 0usize],
            [1usize, 2usize, 0usize],
        ];
        let mut final_snapshots = Vec::new();

        for order in return_orders {
            let pool = DbPool::new(TestManager::new(), config.clone());
            let mut leases = (0..MAX_SIZE)
                .map(|_| Some(pool.get().expect("acquire within pool capacity")))
                .collect::<Vec<_>>();

            for (step, index) in order.into_iter().enumerate() {
                leases[index]
                    .take()
                    .expect("lease should still be checked out")
                    .return_to_pool();

                let stats = pool.stats();
                assert_eq!(stats.idle, step + 1);
                assert_eq!(stats.total, MAX_SIZE);
                assert_eq!(stats.active + stats.idle, stats.total);
                assert!(
                    stats.idle <= stats.max_size,
                    "idle connections must remain bounded by capacity"
                );
            }

            final_snapshots.push(db_pool_inventory_snapshot(&pool.stats()));
        }

        assert!(
            final_snapshots.windows(2).all(|pair| pair[0] == pair[1]),
            "return order should not change the final idle inventory snapshot"
        );
        crate::test_complete!("mr_idle_return_order_preserves_capacity_bounds");
    }

    // ================================================================
    // Capacity limits
    // ================================================================

    #[test]
    fn max_size_enforced() {
        init_test("max_size_enforced");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(2));

        let _c1 = pool.get().unwrap();
        let _c2 = pool.get().unwrap();

        let result = pool.get();
        assert!(matches!(result, Err(DbPoolError::Full)));
        crate::test_complete!("max_size_enforced");
    }

    #[test]
    fn capacity_frees_on_return() {
        init_test("capacity_frees_on_return");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(1));

        let conn = pool.get().unwrap();
        conn.return_to_pool();

        // Can get another one now.
        let _conn2 = pool.get().unwrap();
        crate::test_complete!("capacity_frees_on_return");
    }

    // ================================================================
    // Discard
    // ================================================================

    #[test]
    fn discard_removes_from_pool() {
        init_test("discard_removes_from_pool");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(2));

        let conn = pool.get().unwrap();
        conn.discard();

        // Total should decrease.
        assert_eq!(pool.stats().total, 0);
        assert_eq!(pool.stats().total_discards, 1);
        assert_eq!(pool.manager.disconnects(), 1);
        crate::test_complete!("discard_removes_from_pool");
    }

    // ================================================================
    // Health check / validation
    // ================================================================

    #[test]
    fn validation_on_checkout_rejects_invalid() {
        init_test("validation_on_checkout_rejects_invalid");
        let manager = TestManager::new();
        let pool = DbPool::new(manager, DbPoolConfig::default());

        // Get and return a connection.
        let conn = pool.get().unwrap();
        conn.return_to_pool();
        assert_eq!(pool.stats().idle, 1);

        // Invalidate all connections.
        pool.manager.set_valid(false);

        // Next get should discard the invalid one and create a new one.
        // But creation also creates an invalid conn — is_valid is checked on checkout,
        // new connections are not checked.
        pool.manager.set_valid(true); // New connections are valid again.
        pool.manager.set_valid(false); // But the idle one is still invalid.

        // Actually: set_valid affects all conns since they share the Arc<AtomicBool>.
        // Let's test differently: make the idle conn invalid, then make new ones valid.
        // Since they all share the same Arc, we need a different approach.
        // Instead: just verify the validation failure counter increases.
        pool.manager.set_valid(false);
        let _result = pool.get();
        // The idle one gets rejected (validation failure), then a new one is created.
        assert_eq!(pool.stats().total_validation_failures, 1);
        crate::test_complete!("validation_on_checkout_rejects_invalid");
    }

    #[test]
    fn no_validation_when_disabled() {
        init_test("no_validation_when_disabled");
        let manager = TestManager::new();
        let config = DbPoolConfig::default().validate_on_checkout(false);
        let pool = DbPool::new(manager, config);

        let conn = pool.get().unwrap();
        conn.return_to_pool();

        pool.manager.set_valid(false);

        // Should still succeed (no validation).
        let conn2 = pool.get().unwrap();
        assert_eq!(pool.stats().total_validation_failures, 0);
        drop(conn2);
        crate::test_complete!("no_validation_when_disabled");
    }

    // ================================================================
    // Connection failure
    // ================================================================

    #[test]
    fn connect_failure_returns_error() {
        init_test("connect_failure_returns_error");
        let manager = TestManager::new();
        manager.set_fail_connect(true);
        let pool = DbPool::new(manager, DbPoolConfig::default());

        let result = pool.get();
        assert!(matches!(result, Err(DbPoolError::Connect(_))));
        assert_eq!(pool.stats().total, 0);
        crate::test_complete!("connect_failure_returns_error");
    }

    #[test]
    fn connect_failure_doesnt_leak_capacity() {
        init_test("connect_failure_doesnt_leak_capacity");
        let manager = TestManager::new();
        let pool = DbPool::new(manager, DbPoolConfig::with_max_size(2));

        pool.manager.set_fail_connect(true);
        let _ = pool.get(); // Fails
        let _ = pool.get(); // Fails

        pool.manager.set_fail_connect(false);
        // Should still be able to get — capacity wasn't leaked.
        let _c1 = pool.get().unwrap();
        let _c2 = pool.get().unwrap();
        crate::test_complete!("connect_failure_doesnt_leak_capacity");
    }

    // ================================================================
    // Close
    // ================================================================

    #[test]
    fn close_rejects_new_gets() {
        init_test("close_rejects_new_gets");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        pool.close();
        assert!(pool.is_closed());

        let result = pool.get();
        assert!(matches!(result, Err(DbPoolError::Closed)));
        crate::test_complete!("close_rejects_new_gets");
    }

    #[test]
    fn close_drains_idle() {
        init_test("close_drains_idle");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        let conn = pool.get().unwrap();
        conn.return_to_pool();
        assert_eq!(pool.stats().idle, 1);

        pool.close();
        assert_eq!(pool.stats().idle, 0);
        assert_eq!(pool.manager.disconnects(), 1);
        assert_eq!(pool.stats().total_discards, 1);
        crate::test_complete!("close_drains_idle");
    }

    #[test]
    fn mr_drop_matches_close_for_idle_cleanup() {
        init_test("mr_drop_matches_close_for_idle_cleanup");
        let config = DbPoolConfig::with_max_size(2).validate_on_checkout(false);

        let close_manager = TestManager::new();
        let close_observer = close_manager.clone();
        let close_snapshot = {
            let pool = DbPool::new(close_manager, config.clone());
            let first = pool.get().expect("first checkout should succeed");
            let second = pool.get().expect("second checkout should succeed");
            first.return_to_pool();
            second.return_to_pool();
            assert_eq!(pool.stats().idle, 2, "two returned connections go idle");
            pool.close();
            db_pool_inventory_snapshot(&pool.stats())
        };

        let drop_manager = TestManager::new();
        let drop_observer = drop_manager.clone();
        {
            let pool = DbPool::new(drop_manager, config.clone());
            let first = pool.get().expect("first checkout should succeed");
            let second = pool.get().expect("second checkout should succeed");
            first.return_to_pool();
            second.return_to_pool();
            assert_eq!(pool.stats().idle, 2, "two returned connections go idle");
        }

        assert_eq!(
            close_snapshot,
            json!({
                "idle": 0,
                "active": 0,
                "total": 0,
                "max_size": 2,
            }),
            "close must synchronously drain idle inventory"
        );
        assert_eq!(close_observer.disconnects(), 2);
        assert_eq!(
            drop_observer.disconnects(),
            close_observer.disconnects(),
            "dropping a pool with only idle connections should match explicit close cleanup"
        );
        crate::test_complete!("mr_drop_matches_close_for_idle_cleanup");
    }

    #[test]
    fn close_discards_returned_connections() {
        init_test("close_discards_returned_connections");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        let conn = pool.get().unwrap();
        pool.close();

        // Return after close → disconnected.
        conn.return_to_pool();
        assert_eq!(pool.stats().total, 0);
        assert_eq!(pool.manager.disconnects(), 1);
        assert_eq!(pool.stats().total_discards, 1);
        crate::test_complete!("close_discards_returned_connections");
    }

    // ================================================================
    // try_get
    // ================================================================

    #[test]
    fn try_get_success() {
        init_test("try_get_success");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let conn = pool.try_get();
        assert!(conn.is_some());
        crate::test_complete!("try_get_success");
    }

    #[test]
    fn try_get_when_full() {
        init_test("try_get_when_full");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(1));
        let _held = pool.get().unwrap();
        assert!(pool.try_get().is_none());
        crate::test_complete!("try_get_when_full");
    }

    // ================================================================
    // Warm-up
    // ================================================================

    #[test]
    fn warm_up_creates_connections() {
        init_test("warm_up_creates_connections");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default().min_idle(3));
        let created = pool.warm_up();
        assert_eq!(created, 3);
        assert_eq!(pool.stats().idle, 3);
        assert_eq!(pool.stats().total, 3);
        crate::test_complete!("warm_up_creates_connections");
    }

    #[test]
    fn warm_up_respects_max_size() {
        init_test("warm_up_respects_max_size");
        let pool = DbPool::new(
            TestManager::new(),
            DbPoolConfig::with_max_size(2).min_idle(5),
        );
        let created = pool.warm_up();
        assert_eq!(created, 2);
        assert_eq!(pool.stats().total, 2);
        crate::test_complete!("warm_up_respects_max_size");
    }

    // ================================================================
    // PooledConnection
    // ================================================================

    #[test]
    fn pooled_connection_deref() {
        init_test("pooled_connection_deref");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let conn = pool.get().unwrap();
        // Deref to TestConnection.
        assert_eq!(conn.id, 1);
        crate::test_complete!("pooled_connection_deref");
    }

    #[test]
    fn pooled_connection_debug() {
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let conn = pool.get().unwrap();
        let dbg = format!("{conn:?}");
        assert!(dbg.contains("PooledConnection"));
        assert!(dbg.contains("active"));
    }

    // ================================================================
    // DbPoolError
    // ================================================================

    #[test]
    fn pool_error_display() {
        init_test("pool_error_display");
        let closed: DbPoolError<TestError> = DbPoolError::Closed;
        assert!(format!("{closed}").contains("closed"));

        let full: DbPoolError<TestError> = DbPoolError::Full;
        assert!(format!("{full}").contains("capacity"));

        let timeout: DbPoolError<TestError> = DbPoolError::Timeout;
        assert!(format!("{timeout}").contains("timed out"));

        let connect: DbPoolError<TestError> =
            DbPoolError::Connect(TestError("refused".to_string()));
        assert!(format!("{connect}").contains("refused"));

        let validation: DbPoolError<TestError> = DbPoolError::ValidationFailed;
        assert!(format!("{validation}").contains("validation"));
        crate::test_complete!("pool_error_display");
    }

    #[test]
    fn pool_error_debug() {
        let err: DbPoolError<TestError> = DbPoolError::Full;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Full"));
    }

    #[test]
    fn pool_error_source() {
        use std::error::Error;
        let closed: DbPoolError<TestError> = DbPoolError::Closed;
        assert!(closed.source().is_none());

        let connect = DbPoolError::Connect(TestError("fail".to_string()));
        assert!(connect.source().is_some());
    }

    // ================================================================
    // Stats
    // ================================================================

    #[test]
    fn stats_track_lifecycle() {
        init_test("stats_track_lifecycle");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(2));

        let c1 = pool.get().unwrap();
        let c2 = pool.get().unwrap();
        assert_eq!(pool.stats().total_creates, 2);
        assert_eq!(pool.stats().total_acquisitions, 2);
        assert_eq!(pool.stats().active, 2);

        c1.return_to_pool();
        assert_eq!(pool.stats().idle, 1);
        assert_eq!(pool.stats().active, 1);

        c2.discard();
        assert_eq!(pool.stats().total_discards, 1);
        assert_eq!(pool.stats().total, 1);
        crate::test_complete!("stats_track_lifecycle");
    }

    #[test]
    fn stats_default() {
        let stats = DbPoolStats::default();
        assert_eq!(stats.idle, 0);
        assert_eq!(stats.active, 0);
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn stats_debug_clone() {
        let stats = DbPoolStats::default();
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("DbPoolStats"));
        let cloned = stats.clone();
        assert_eq!(stats.total, 0);
        assert_eq!(cloned.total, 0);
    }

    #[test]
    fn pool_debug_reports_live_counter_values() {
        init_test("pool_debug_reports_live_counter_values");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let _conn = pool.get().unwrap();

        let dbg = format!("{pool:?}");
        assert!(dbg.contains("total_acquisitions: 1"));
        assert!(dbg.contains("total_creates: 1"));
        assert!(dbg.contains("total_discards: 0"));
        crate::test_complete!("pool_debug_reports_live_counter_values");
    }

    #[test]
    fn pool_telemetry_snapshot() {
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(2));

        let initial = pool.stats();

        let conn = pool.get().expect("first checkout should succeed");
        let checked_out = pool.stats();

        conn.return_to_pool();
        let returned = pool.stats();

        let recycled = pool.get().expect("recycled checkout should succeed");
        recycled.discard();
        let discarded = pool.stats();

        insta::assert_json_snapshot!(
            "pool_telemetry_snapshot",
            json!({
                "initial": db_pool_stats_snapshot(&initial),
                "checked_out": db_pool_stats_snapshot(&checked_out),
                "returned": db_pool_stats_snapshot(&returned),
                "discarded": db_pool_stats_snapshot(&discarded),
            })
        );
    }
}
