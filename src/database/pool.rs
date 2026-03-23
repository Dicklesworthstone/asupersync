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

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::Mutex;
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
    #[must_use]
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            max_size,
            ..Default::default()
        }
    }

    /// Set the minimum idle connections.
    #[must_use]
    pub fn min_idle(mut self, min_idle: usize) -> Self {
        self.min_idle = min_idle;
        self
    }

    /// Set the maximum pool size.
    #[must_use]
    pub fn max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Enable or disable checkout validation.
    #[must_use]
    pub fn validate_on_checkout(mut self, enabled: bool) -> Self {
        self.validate_on_checkout = enabled;
        self
    }

    /// Set the idle timeout.
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the maximum connection lifetime.
    #[must_use]
    pub fn max_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_lifetime = lifetime;
        self
    }

    /// Set the connection acquisition timeout.
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
    fn new(conn: C) -> Self {
        let now = Instant::now();
        Self {
            conn,
            created_at: now,
            last_used: now,
        }
    }

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
        let inner = self.inner.lock().unwrap();
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
        let mut inner = self.inner.lock().unwrap();

        if inner.closed {
            return Err(DbPoolError::Closed);
        }

        // Try to get a valid idle connection.
        while let Some(idle) = inner.idle.pop_front() {
            // Evict expired or stale connections.
            if idle.is_expired(&self.config) || idle.is_idle_too_long(&self.config) {
                inner.total = inner.total.saturating_sub(1);
                self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                self.manager.disconnect(idle.conn);
                continue;
            }

            // Validate if configured.
            if self.config.validate_on_checkout && !self.manager.is_valid(&idle.conn) {
                inner.total = inner.total.saturating_sub(1);
                self.stats
                    .total_validation_failures
                    .fetch_add(1, Ordering::Relaxed);
                self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                self.manager.disconnect(idle.conn);
                continue;
            }

            self.stats
                .total_acquisitions
                .fetch_add(1, Ordering::Relaxed);
            return Ok(PooledConnection {
                conn: Some(idle.conn),
                pool: self,
                created_at: idle.created_at,
            });
        }

        // No valid idle connection; create new if under capacity.
        if inner.total < self.config.max_size {
            inner.total += 1;
            drop(inner); // Release lock during creation.

            match self.manager.connect() {
                Ok(conn) => {
                    self.stats.total_creates.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .total_acquisitions
                        .fetch_add(1, Ordering::Relaxed);
                    Ok(PooledConnection {
                        conn: Some(conn),
                        pool: self,
                        created_at: Instant::now(),
                    })
                }
                Err(e) => {
                    // Roll back total count on failure.
                    let mut inner = self.inner.lock().unwrap();
                    inner.total = inner.total.saturating_sub(1);
                    Err(DbPoolError::Connect(e))
                }
            }
        } else {
            Err(DbPoolError::Full)
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
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            inner.total = inner.total.saturating_sub(1);
            self.manager.disconnect(conn);
            return;
        }
        inner.idle.push_back(IdleConnection {
            conn,
            created_at,
            last_used: Instant::now(),
        });
    }

    /// Discard a connection (don't return to pool).
    fn discard_connection(&self, conn: M::Connection) {
        let mut inner = self.inner.lock().unwrap();
        inner.total = inner.total.saturating_sub(1);
        self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
        self.manager.disconnect(conn);
    }

    /// Close the pool, preventing new acquisitions.
    ///
    /// Existing checked-out connections will be discarded when returned.
    pub fn close(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.closed = true;
        // Drain idle connections.
        let idle: Vec<_> = inner.idle.drain(..).collect();
        let drained = idle.len();
        inner.total = inner.total.saturating_sub(drained);
        drop(inner);
        for entry in idle {
            self.manager.disconnect(entry.conn);
        }
    }

    /// Returns `true` if the pool is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().unwrap().closed
    }

    /// Evict all idle connections that are expired or stale.
    ///
    /// Returns the number of connections evicted.
    pub fn evict_stale(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();

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
            let mut inner = self.inner.lock().unwrap();
            if inner.total >= self.config.max_size || inner.closed {
                break;
            }
            inner.total += 1;
            drop(inner);

            match self.manager.connect() {
                Ok(conn) => {
                    self.stats.total_creates.fetch_add(1, Ordering::Relaxed);
                    self.return_connection(conn, Instant::now());
                    created += 1;
                }
                Err(_) => {
                    let mut inner = self.inner.lock().unwrap();
                    inner.total = inner.total.saturating_sub(1);
                }
            }
        }
        created
    }
}

impl<M: ConnectionManager> fmt::Debug for DbPool<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        f.debug_struct("DbPool")
            .field("idle", &inner.idle.len())
            .field("total", &inner.total)
            .field("max_size", &self.config.max_size)
            .field("closed", &inner.closed)
            .finish()
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

impl<'a, M: ConnectionManager> PooledConnection<'a, M> {
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

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
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

    struct TestManager {
        next_id: AtomicUsize,
        valid: Arc<AtomicBool>,
        creates: AtomicUsize,
        disconnects: AtomicUsize,
        fail_connect: AtomicBool,
    }

    impl TestManager {
        fn new() -> Self {
            Self {
                next_id: AtomicUsize::new(1),
                valid: Arc::new(AtomicBool::new(true)),
                creates: AtomicUsize::new(0),
                disconnects: AtomicUsize::new(0),
                fail_connect: AtomicBool::new(false),
            }
        }

        fn creates(&self) -> usize {
            self.creates.load(Ordering::SeqCst)
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
        let cloned = config.clone();
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
        crate::test_complete!("close_drains_idle");
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
        assert_eq!(cloned.total, 0);
    }
}
