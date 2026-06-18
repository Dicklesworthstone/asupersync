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
use crate::runtime::pool_sizing::{
    PoolSizingAction, PoolSizingBounds, PoolSizingControllerState, PoolSizingDecision,
    PoolSizingPolicy, PoolSizingTarget, PoolWorkloadEstimate, decide_pool_sizing,
};

use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crate::types::Time;

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

    /// Synchronous release-time health check (br-asupersync-5bv5sr).
    ///
    /// Called by [`PooledConnection`]'s `Drop` impl BEFORE returning the
    /// connection to the idle pool. Return `true` to route through the
    /// normal return-to-pool path; return `false` to route to
    /// [`Self::disconnect`] instead. The default impl returns `true` —
    /// preserving the legacy behaviour for backends that do not
    /// implement release-time validation.
    ///
    /// **Why this exists:** without it, `PooledConnection`'s `Drop`
    /// unconditionally returned the connection to the pool — even when
    /// the previous caller errored mid-transaction or left protocol
    /// state poisoned. The next caller acquired the connection with
    /// uncommitted-transaction state, holding the prior caller's locks
    /// until the next operation triggered `ensure_no_orphaned_transaction`
    /// (which itself only catches a narrow set of recoverable cases).
    /// Backends that can detect such state synchronously (e.g.,
    /// PostgreSQL's `transaction_status` byte read in `in_transaction()`,
    /// MySQL's status flags) should override this to return `false` for
    /// any connection that should not be handed to a fresh caller.
    ///
    /// Async cleanup (e.g., issuing a `ROLLBACK` round-trip) is NOT
    /// possible from this hook because `Drop` cannot await. The honest
    /// safe choice is to discard suspect connections; the cost is one
    /// fresh connection on the next acquire vs. cross-caller state leak.
    fn release_check(&self, _conn: &mut Self::Connection) -> bool {
        true
    }

    /// Called when a connection is permanently removed from the pool.
    ///
    /// Default implementation does nothing. Override for cleanup
    /// (e.g., sending disconnect protocol messages).
    fn disconnect(&self, _conn: Self::Connection) {}

    /// Check if a connection has authentication state for a specific client.
    ///
    /// br-asupersync-gb3rck: Returns Some(client_id) if the connection is
    /// authenticated for a specific client, None if it's in a clean/unauthenticated state.
    /// Implementations should check connection-specific authentication state
    /// (e.g., active sessions, user context, database roles).
    fn authentication_state(&self, _conn: &Self::Connection) -> Option<String> {
        // Default: no authentication state tracking
        None
    }

    /// Clear authentication state from a connection.
    ///
    /// br-asupersync-gb3rck: Called to reset a connection to clean/unauthenticated state
    /// before returning to pool for potential reuse by different clients.
    /// Return true if successfully cleared, false if connection should be discarded.
    fn clear_authentication_state(&self, _conn: &mut Self::Connection) -> bool {
        // Default: assume no authentication state to clear
        true
    }
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
    /// Maximum connections per client (None = unlimited per client).
    /// br-asupersync-qydi3j: DoS protection against connection exhaustion.
    pub max_connections_per_client: Option<usize>,
    /// Enable per-client connection tracking and enforcement.
    /// br-asupersync-qydi3j: When true, tracks connection usage by client ID.
    pub enforce_client_quotas: bool,
    /// Validate authentication state to prevent cross-user connection reuse.
    /// br-asupersync-gb3rck: When true, ensures connections authenticated for one user
    /// are not handed to another user, preventing privilege escalation.
    pub validate_authentication_state: bool,
    /// Maximum retry attempts per client for connection acquisition.
    /// br-asupersync-mlojr9: Prevents retry storm amplification DoS attacks.
    pub max_retry_attempts_per_client: u32,
    /// Minimum delay between retry attempts per client in milliseconds.
    /// br-asupersync-mlojr9: Enforces per-client retry rate limiting.
    pub min_retry_delay_per_client_ms: u64,
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
            // br-asupersync-qydi3j: Conservative defaults for DoS protection
            max_connections_per_client: Some(3), // Allow up to 3 connections per client by default
            enforce_client_quotas: true,         // Enable protection by default
            // br-asupersync-gb3rck: Security defaults for authentication state validation
            validate_authentication_state: true, // Enable authentication state validation by default
            // br-asupersync-mlojr9: Retry storm amplification DoS protection defaults
            max_retry_attempts_per_client: 5, // Max 5 retry attempts per client
            min_retry_delay_per_client_ms: 100, // Min 100ms between retries per client
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

    /// Set the maximum connections per client (None = unlimited).
    /// br-asupersync-qydi3j: DoS protection against connection exhaustion.
    #[inline]
    #[must_use]
    pub fn max_connections_per_client(mut self, max: Option<usize>) -> Self {
        self.max_connections_per_client = max;
        self
    }

    /// Enable or disable client quota enforcement.
    /// br-asupersync-qydi3j: Controls per-client connection tracking.
    #[inline]
    #[must_use]
    pub fn enforce_client_quotas(mut self, enforce: bool) -> Self {
        self.enforce_client_quotas = enforce;
        self
    }

    /// Enable or disable authentication state validation.
    /// br-asupersync-gb3rck: Controls whether connections with authentication state
    /// are prevented from being reused by different clients.
    #[inline]
    #[must_use]
    pub fn validate_authentication_state(mut self, validate: bool) -> Self {
        self.validate_authentication_state = validate;
        self
    }

    /// Set the maximum retry attempts per client.
    /// br-asupersync-mlojr9: Prevents retry storm amplification DoS attacks.
    #[inline]
    #[must_use]
    pub fn max_retry_attempts_per_client(mut self, max_attempts: u32) -> Self {
        self.max_retry_attempts_per_client = max_attempts;
        self
    }

    /// Set the minimum delay between retry attempts per client.
    /// br-asupersync-mlojr9: Enforces per-client retry rate limiting.
    #[inline]
    #[must_use]
    pub fn min_retry_delay_per_client_ms(mut self, delay_ms: u64) -> Self {
        self.min_retry_delay_per_client_ms = delay_ms;
        self
    }

    /// Returns the hard floor and ceiling used by advisory pool-sizing.
    #[inline]
    #[must_use]
    pub const fn pool_sizing_bounds(&self) -> PoolSizingBounds {
        PoolSizingBounds::new(self.min_idle, self.max_size)
    }
}

// ─── Pool internals ─────────────────────────────────────────────────────────

/// An idle connection with metadata.
///
/// br-asupersync-w3g9kb: time fields use the runtime
/// [`crate::types::Time`] abstraction (returned by `cx.now()` in
/// async paths and `crate::time::wall_now()` in Drop / sync paths)
/// rather than `std::time::Instant::now()` directly. This routes
/// every wall-clock read through a single typed boundary that
/// future Cx-aware test injection can intercept.
struct IdleConnection<C> {
    conn: C,
    created_at: Time,
    last_used: Time,
    /// br-asupersync-gb3rck: Track authentication state to prevent cross-user reuse.
    /// None means unauthenticated/clean state; Some(client_id) means authenticated for that client.
    authenticated_for: Option<String>,
}

impl<C> IdleConnection<C> {
    fn is_expired(&self, config: &DbPoolConfig, now: Time) -> bool {
        Duration::from_nanos(now.duration_since(self.created_at)) > config.max_lifetime
    }

    fn is_idle_too_long(&self, config: &DbPoolConfig, now: Time) -> bool {
        Duration::from_nanos(now.duration_since(self.last_used)) > config.idle_timeout
    }
}

struct PoolInner<C> {
    idle: VecDeque<IdleConnection<C>>,
    /// Total connections (idle + checked out).
    total: usize,
    closed: bool,
    /// Async acquisition waiters ordered by arrival. The synchronous pool
    /// leaves this empty because it has no `Cx` budget/cancellation surface.
    waiters: VecDeque<Arc<AsyncPoolWaiter>>,
    /// br-asupersync-qydi3j: Per-client connection count tracking.
    /// Maps client_id -> count of active connections for that client.
    client_connections: HashMap<String, usize>,
    /// br-asupersync-mlojr9: Per-client retry attempt tracking.
    /// Maps client_id -> (current_attempts, last_retry_time).
    client_retry_state: HashMap<String, (u32, Time)>,
}

struct AsyncPoolWaiter {
    notify: crate::sync::Notify,
    ready: AtomicBool,
    cancelled: AtomicBool,
}

impl AsyncPoolWaiter {
    fn new() -> Self {
        Self {
            notify: crate::sync::Notify::new(),
            ready: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        }
    }
}

enum AsyncAcquireStep<C> {
    Wait,
    Idle(IdleConnection<C>),
    Create,
    Discard(C),
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
    /// Live maximum pool size enforced by capacity checks (yj2nxx.7).
    ///
    /// Starts at `config.max_size`; managed pool sizing may lower it toward
    /// `config.min_idle` and raise it back, but never above `config.max_size`
    /// (the configured hard ceiling). A shrink never force-closes live
    /// connections — it only blocks new creates until the pool drains.
    live_max_size: AtomicUsize,
}

#[derive(Default)]
#[allow(clippy::struct_field_names)]
struct PoolStatCounters {
    total_acquisitions: AtomicU64,
    total_creates: AtomicU64,
    total_discards: AtomicU64,
    total_timeouts: AtomicU64,
    total_validation_failures: AtomicU64,
    total_retry_limits_exceeded: AtomicU64,
    total_disconnect_failures: AtomicU64,
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
            .field(
                "total_retry_limits_exceeded",
                &self.total_retry_limits_exceeded.load(Ordering::Relaxed),
            )
            .field(
                "total_disconnect_failures",
                &self.total_disconnect_failures.load(Ordering::Relaxed),
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
    /// Total retry limits exceeded.
    /// br-asupersync-mlojr9: Tracks retry storm protection activations.
    pub total_retry_limits_exceeded: u64,
    /// Total disconnect failures.
    /// br-asupersync-sxhome: Tracks connection disconnect failure events.
    pub total_disconnect_failures: u64,
    /// Acquirers currently parked in the async FIFO waiter queue.
    ///
    /// br-asupersync-eeexl1.5 AC3: callers blocked inside an async `acquire`
    /// awaiting a released or freshly created connection, ordered by arrival.
    /// Always `0` for the synchronous pool, which never parks waiters. A
    /// sustained nonzero value signals the pool is saturated and acquisitions
    /// are queueing FIFO (rather than failing fast with `DbPoolError::Full`).
    pub pending_waiters: usize,
}

impl DbPoolStats {
    /// Returns the live controller state used by advisory pool-sizing.
    #[must_use]
    pub const fn pool_sizing_controller_state(&self) -> PoolSizingControllerState {
        PoolSizingControllerState {
            current_size: self.total,
            last_resize_epoch: 0,
        }
    }
}

fn db_pool_advisory_pool_sizing_decision(
    bounds: PoolSizingBounds,
    state: PoolSizingControllerState,
    estimate: PoolWorkloadEstimate,
    target: PoolSizingTarget,
) -> PoolSizingDecision {
    let mut policy = PoolSizingPolicy::advisory(bounds);
    policy.target = target;
    let decision = decide_pool_sizing(policy, state, estimate, 0);
    debug_assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
    decision
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
    /// The async FIFO acquire budget was exhausted while waiting for an
    /// available connection.
    ///
    /// Distinct from [`DbPoolError::Timeout`] (which also covers cancellation
    /// and connection-creation timeouts): the caller waited in the pool's FIFO
    /// waiter queue for the full [`DbPoolConfig::connection_timeout`] budget
    /// without a connection being released. Emits the stable `[ASUP-E601]`
    /// token so callers can treat acquire backpressure as a distinct, typed
    /// failure rather than retrying immediately.
    AcquireTimeout,
    /// Connection creation failed.
    Connect(E),
    /// Connection validation failed.
    ValidationFailed,
    /// Client quota exceeded.
    /// br-asupersync-qydi3j: DoS protection against connection exhaustion.
    ClientQuotaExceeded(String),
    /// Authentication state mismatch.
    /// br-asupersync-gb3rck: Prevents connections authenticated for one user being reused by another.
    AuthenticationMismatch { expected: String, found: String },
    /// Client retry limit exceeded.
    /// br-asupersync-mlojr9: Prevents retry storm amplification DoS attacks.
    RetryLimitExceeded {
        client_id: String,
        attempts: u32,
        max_attempts: u32,
    },
}

impl<E: std::error::Error> fmt::Display for DbPoolError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "pool closed"),
            Self::Full => write!(f, "pool at capacity"),
            Self::Timeout => write!(f, "connection acquisition timed out"),
            Self::AcquireTimeout => write!(
                f,
                "[ASUP-E601] pool connection acquisition timed out after exhausting the acquire budget while waiting in the FIFO waiter queue"
            ),
            Self::Connect(e) => write!(f, "connection failed: {e}"),
            Self::ValidationFailed => write!(f, "connection validation failed"),
            Self::ClientQuotaExceeded(client) => write!(f, "client quota exceeded for '{client}'"),
            Self::AuthenticationMismatch { expected, found } => write!(
                f,
                "authentication state mismatch: expected '{expected}', found '{found}'"
            ),
            Self::RetryLimitExceeded {
                client_id,
                attempts,
                max_attempts,
            } => write!(
                f,
                "retry limit exceeded for client '{client_id}': {attempts}/{max_attempts} attempts"
            ),
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
            // br-asupersync-sxhome: Use safe disconnect to prevent resource leaks
            if self.pool.safe_disconnect(conn) {
                // Only update counts if disconnect succeeded
                let mut inner = self.pool.inner.lock();
                inner.total = inner.total.saturating_sub(1);
                drop(inner);
                self.pool
                    .stats
                    .total_discards
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                crate::tracing_compat::warn!(
                    event = "database_pool_disconnect_failure",
                    guard = "validation",
                    action = "preserve_pool_state",
                    "validation guard disconnect failed"
                );
            }
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
        let live_max_size = AtomicUsize::new(config.max_size);
        Self {
            manager: Arc::new(manager),
            config,
            inner: Mutex::new(PoolInner {
                idle: VecDeque::new(),
                total: 0,
                closed: false,
                waiters: VecDeque::new(),
                client_connections: HashMap::new(), // br-asupersync-qydi3j
                client_retry_state: HashMap::new(), // br-asupersync-mlojr9
            }),
            stats: PoolStatCounters::default(),
            live_max_size,
        }
    }

    /// Create a pool with default configuration.
    pub fn with_manager(manager: M) -> Self {
        Self::new(manager, DbPoolConfig::default())
    }

    /// The live maximum pool size currently enforced by capacity checks.
    ///
    /// This is the managed-mode operational cap (yj2nxx.7). It starts at
    /// `config.max_size` and is adjusted by [`set_max_size`](Self::set_max_size)
    /// within `[config.min_idle, config.max_size]`. `DbPoolStats::max_size`
    /// continues to report the configured ceiling.
    #[must_use]
    pub fn current_max_size(&self) -> usize {
        self.effective_max_size()
    }

    fn effective_max_size(&self) -> usize {
        self.live_max_size.load(Ordering::Relaxed)
    }

    /// Set the live maximum pool size, clamped into `[min_idle, config.max_size]`.
    ///
    /// The configured `max_size` is the hard ceiling: managed sizing may shrink
    /// the pool below it and grow it back, but never beyond it. A shrink only
    /// prevents new creates; live connections drain naturally. Returns the
    /// clamped value actually applied.
    pub fn set_max_size(&self, requested: usize) -> usize {
        let applied = requested
            .max(self.config.min_idle)
            .min(self.config.max_size);
        self.live_max_size.store(applied, Ordering::Relaxed);
        applied
    }

    /// Apply a managed pool-sizing decision to the live maximum size.
    ///
    /// Only [`PoolSizingAction::Resize`] mutates the cap (clamped into the
    /// configured bounds); advisory mode and hysteresis/cadence holds are
    /// no-ops. Returns the applied size when a resize was taken.
    pub fn apply_pool_sizing_decision(&self, decision: &PoolSizingDecision) -> Option<usize> {
        match decision.action {
            PoolSizingAction::Resize { to_size, .. } => Some(self.set_max_size(to_size)),
            _ => None,
        }
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
            total_retry_limits_exceeded: self
                .stats
                .total_retry_limits_exceeded
                .load(Ordering::Relaxed),
            total_disconnect_failures: self.stats.total_disconnect_failures.load(Ordering::Relaxed),
            pending_waiters: inner.waiters.len(),
        }
    }

    /// Returns the hard floor and ceiling used by advisory pool-sizing.
    #[must_use]
    pub fn pool_sizing_bounds(&self) -> PoolSizingBounds {
        self.config.pool_sizing_bounds()
    }

    /// Returns the live controller state used by advisory pool-sizing.
    #[must_use]
    pub fn pool_sizing_controller_state(&self) -> PoolSizingControllerState {
        self.stats().pool_sizing_controller_state()
    }

    /// Computes an advisory pool-sizing decision without opening or closing connections.
    #[must_use]
    pub fn advisory_pool_sizing_decision(
        &self,
        estimate: PoolWorkloadEstimate,
        target: PoolSizingTarget,
    ) -> PoolSizingDecision {
        db_pool_advisory_pool_sizing_decision(
            self.pool_sizing_bounds(),
            self.pool_sizing_controller_state(),
            estimate,
            target,
        )
    }

    fn sleep_retry_backoff(&self, mut duration: Duration) -> bool {
        const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(10);

        while !duration.is_zero() {
            if self.is_closed() {
                return false;
            }

            let chunk = duration.min(SHUTDOWN_POLL_INTERVAL);
            std::thread::sleep(chunk);
            duration = duration.saturating_sub(chunk);
        }

        !self.is_closed()
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
                    // br-asupersync-w3g9kb: sync get path has no Cx;
                    // sample wall_now() once for both eviction checks.
                    let now = crate::time::wall_now();
                    if idle.is_expired(&self.config, now)
                        || idle.is_idle_too_long(&self.config, now)
                    {
                        inner.total = inner.total.saturating_sub(1);
                        self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                        popped = Some((idle.conn, false, idle.created_at, idle.authenticated_for));
                    } else {
                        // br-asupersync-gb3rck: For get() without client_id, only reuse clean connections
                        // If authentication validation is enabled and connection has auth state, discard it
                        if self.config.validate_authentication_state
                            && idle.authenticated_for.is_some()
                        {
                            inner.total = inner.total.saturating_sub(1);
                            self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                            popped =
                                Some((idle.conn, false, idle.created_at, idle.authenticated_for));
                        } else {
                            popped =
                                Some((idle.conn, true, idle.created_at, idle.authenticated_for));
                        }
                    }
                }

                if popped.is_none() {
                    // No valid idle connection; create new if under capacity.
                    if inner.total < self.effective_max_size() {
                        inner.total += 1;
                        // Release lock during creation.
                    } else {
                        return Err(DbPoolError::Full);
                    }
                }
                drop(inner);
                popped
            };

            if let Some((conn, needs_validation, created_at, _authenticated_for)) = conn_to_validate
            {
                if !needs_validation {
                    // br-asupersync-sxhome: Use safe disconnect for expired connections
                    self.safe_disconnect(conn);
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
                        client_id: None, // br-asupersync-qydi3j: legacy get() has no client tracking
                    });
                }

                self.stats
                    .total_acquisitions
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(PooledConnection {
                    conn: Some(conn),
                    pool: self,
                    created_at,
                    client_id: None, // br-asupersync-qydi3j: legacy get() has no client tracking
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
                        // br-asupersync-w3g9kb: sync path → wall_now().
                        created_at: crate::time::wall_now(),
                        client_id: None, // br-asupersync-qydi3j: legacy get() has no client tracking
                    });
                }
                Err(e) => {
                    // Drop guard rolls back total count on failure (or panic).
                    return Err(DbPoolError::Connect(e));
                }
            }
        }
    }

    /// Acquire a connection from the pool for a specific client.
    ///
    /// br-asupersync-qydi3j: DoS protection against connection exhaustion.
    /// Enforces per-client connection quotas when `enforce_client_quotas` is enabled.
    pub fn get_for_client(
        &self,
        client_id: &str,
    ) -> Result<PooledConnection<'_, M>, DbPoolError<M::Error>> {
        // If client quotas are disabled, delegate to regular get()
        if !self.config.enforce_client_quotas {
            return self.get().map(|mut conn| {
                conn.client_id = Some(client_id.to_string());
                conn
            });
        }

        // Check client quota before attempting acquisition
        let client_id_owned = client_id.to_string();
        loop {
            let conn_to_validate = {
                let mut inner = self.inner.lock();

                if inner.closed {
                    return Err(DbPoolError::Closed);
                }

                // br-asupersync-qydi3j: Enforce per-client connection quota
                if let Some(max_per_client) = self.config.max_connections_per_client {
                    let current_count = inner
                        .client_connections
                        .get(&client_id_owned)
                        .copied()
                        .unwrap_or(0);
                    if current_count >= max_per_client {
                        return Err(DbPoolError::ClientQuotaExceeded(client_id_owned));
                    }
                }

                // br-asupersync-gb3rck: Authentication state validation for client-specific connection acquisition
                let mut popped = None;
                if let Some(idle) = inner.idle.pop_front() {
                    let now = crate::time::wall_now();
                    if idle.is_expired(&self.config, now)
                        || idle.is_idle_too_long(&self.config, now)
                    {
                        inner.total = inner.total.saturating_sub(1);
                        self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                        popped = Some((idle.conn, false, idle.created_at, idle.authenticated_for));
                    } else if self.config.validate_authentication_state {
                        // Authentication state validation: check for cross-user reuse
                        match &idle.authenticated_for {
                            None => {
                                // Clean connection - safe to reuse for any client
                                popped = Some((
                                    idle.conn,
                                    true,
                                    idle.created_at,
                                    idle.authenticated_for,
                                ));
                            }
                            Some(auth_client) if auth_client == &client_id_owned => {
                                // Connection authenticated for same client - safe to reuse
                                popped = Some((
                                    idle.conn,
                                    true,
                                    idle.created_at,
                                    idle.authenticated_for,
                                ));
                            }
                            Some(other_client) => {
                                // SECURITY: Connection authenticated for different client - must not reuse
                                // This prevents privilege escalation and cross-user data access
                                inner.total = inner.total.saturating_sub(1);
                                self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                                popped = Some((
                                    idle.conn,
                                    false,
                                    idle.created_at,
                                    Some(other_client.clone()),
                                ));
                            }
                        }
                    } else {
                        // Authentication validation disabled - reuse any connection
                        popped = Some((idle.conn, true, idle.created_at, idle.authenticated_for));
                    }
                }

                if popped.is_none() {
                    if inner.total < self.effective_max_size() {
                        inner.total += 1;
                    } else {
                        return Err(DbPoolError::Full);
                    }
                }

                // br-asupersync-qydi3j: Increment client connection count
                *inner
                    .client_connections
                    .entry(client_id_owned.clone())
                    .or_insert(0) += 1;

                drop(inner);
                popped
            };

            if let Some((conn, needs_validation, created_at, authenticated_for)) = conn_to_validate
            {
                if !needs_validation {
                    // Decrement client count since we're discarding this connection
                    let mut inner = self.inner.lock();
                    if let Some(count) = inner.client_connections.get_mut(&client_id_owned) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            inner.client_connections.remove(&client_id_owned);
                        }
                    }
                    drop(inner);

                    // br-asupersync-gb3rck: Log security event when discarding connection with mismatched auth state
                    if let Some(auth_client) = authenticated_for {
                        if auth_client != client_id_owned {
                            // This is a security-relevant event - connection was authenticated for different client
                            crate::tracing_compat::warn!(
                                event = "database_pool_authentication_mismatch_discard",
                                authenticated_for = %auth_client,
                                requested_by = %client_id_owned,
                                "discarding connection authenticated for a different client"
                            );
                        }
                    }

                    // br-asupersync-sxhome: Use safe disconnect for mismatched auth connections
                    self.safe_disconnect(conn);
                    continue;
                }

                // Validate if configured
                if self.config.validate_on_checkout {
                    let mut guard = ValidationGuard {
                        pool: self,
                        conn: Some(conn),
                    };

                    let valid = self.manager.is_valid(guard.conn.as_ref().unwrap());

                    if !valid {
                        // Decrement client count since validation failed
                        let mut inner = self.inner.lock();
                        if let Some(count) = inner.client_connections.get_mut(&client_id_owned) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                inner.client_connections.remove(&client_id_owned);
                            }
                        }
                        drop(inner);

                        self.stats
                            .total_validation_failures
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    let mut valid_conn = guard.conn.take().unwrap();

                    // br-asupersync-gb3rck: Additional authentication state validation after basic validation
                    if self.config.validate_authentication_state {
                        let current_auth_state = self.manager.authentication_state(&valid_conn);
                        match (&current_auth_state, &authenticated_for) {
                            (Some(current_client), Some(expected_client))
                                if current_client != expected_client =>
                            {
                                // Authentication state mismatch - connection shows different auth than expected
                                // Decrement client count and return error
                                let mut inner = self.inner.lock();
                                if let Some(count) =
                                    inner.client_connections.get_mut(&client_id_owned)
                                {
                                    *count = count.saturating_sub(1);
                                    if *count == 0 {
                                        inner.client_connections.remove(&client_id_owned);
                                    }
                                }
                                // br-asupersync-c5d0q: this connection was popped via the
                                // needs_validation=true path (total NOT decremented at pop) and
                                // taken out of the ValidationGuard above, so the guard's Drop
                                // rollback no longer applies. Disconnecting it without
                                // decrementing `total` permanently leaks a capacity slot
                                // (eventually -> DbPoolError::Full forever). The async twin
                                // decrements here; mirror it for the sync path.
                                inner.total = inner.total.saturating_sub(1);
                                drop(inner);

                                self.stats
                                    .total_validation_failures
                                    .fetch_add(1, Ordering::Relaxed);
                                self.manager.disconnect(valid_conn);
                                return Err(DbPoolError::AuthenticationMismatch {
                                    expected: expected_client.clone(),
                                    found: current_client.clone(),
                                });
                            }
                            // Not collapsed into the arm guard:
                            // clear_authentication_state mutates the
                            // connection, and side effects in match guards
                            // obscure when the reset actually runs.
                            #[allow(clippy::collapsible_match)]
                            (Some(current_client), None) if current_client != &client_id_owned => {
                                // Connection has unexpected authentication state - try to clear it
                                if !self.manager.clear_authentication_state(&mut valid_conn) {
                                    // Failed to clear auth state - discard connection
                                    let mut inner = self.inner.lock();
                                    if let Some(count) =
                                        inner.client_connections.get_mut(&client_id_owned)
                                    {
                                        *count = count.saturating_sub(1);
                                        if *count == 0 {
                                            inner.client_connections.remove(&client_id_owned);
                                        }
                                    }
                                    // br-asupersync-c5d0q: same leak as the mismatch arm above
                                    // -- the connection was taken out of the ValidationGuard, so
                                    // disconnecting it here without decrementing `total` leaks a
                                    // capacity slot. Mirror the async twin's decrement.
                                    inner.total = inner.total.saturating_sub(1);
                                    drop(inner);

                                    self.stats
                                        .total_validation_failures
                                        .fetch_add(1, Ordering::Relaxed);
                                    self.manager.disconnect(valid_conn);
                                    continue;
                                }
                            }
                            _ => {
                                // Authentication state is acceptable (clean, same client, or validation disabled)
                            }
                        }
                    }

                    self.stats
                        .total_acquisitions
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(PooledConnection {
                        conn: Some(valid_conn),
                        pool: self,
                        created_at,
                        client_id: Some(client_id_owned),
                    });
                }

                self.stats
                    .total_acquisitions
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(PooledConnection {
                    conn: Some(conn),
                    pool: self,
                    created_at,
                    client_id: Some(client_id_owned.clone()),
                });
            }

            // Create new connection
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
                        created_at: crate::time::wall_now(),
                        client_id: Some(client_id_owned),
                    });
                }
                Err(e) => {
                    // Decrement client count since creation failed
                    let mut inner = self.inner.lock();
                    if let Some(count) = inner.client_connections.get_mut(&client_id_owned) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            inner.client_connections.remove(&client_id_owned);
                        }
                    }
                    drop(inner);

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
        // br-asupersync-w3g9kb: deadline + remaining computed in
        // Time space; Time supports `+ Duration` and saturating
        // `duration_since` returning u64 nanoseconds, which we
        // convert back to `Duration` for `std::thread::sleep`.
        let deadline: Time = crate::time::wall_now() + self.config.connection_timeout;
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

                    // Check if deadline already passed (Time-space).
                    let remaining_nanos = deadline.duration_since(crate::time::wall_now());
                    if remaining_nanos == 0 {
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout);
                    }
                    let remaining = Duration::from_nanos(remaining_nanos);

                    // Calculate backoff delay (no jitter in synchronous context).
                    let delay = calculate_delay(policy, attempt, None);
                    if !self.sleep_retry_backoff(delay.min(remaining)) {
                        return Err(DbPoolError::Closed);
                    }

                    // Re-check deadline after sleep.
                    if self.is_closed() {
                        return Err(DbPoolError::Closed);
                    }
                    if crate::time::wall_now() >= deadline {
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout);
                    }
                }
            }
        }
    }

    /// Acquire a connection with client-aware retry and amplification protection.
    ///
    /// br-asupersync-mlojr9: This method provides retry storm amplification DoS protection
    /// by enforcing per-client retry limits and rate limiting.
    ///
    /// On transient failures (`Connect` error or `Full` pool), retries with exponential
    /// backoff per the given policy, but additionally enforces:
    /// 1. Maximum retry attempts per client (prevents amplification)
    /// 2. Minimum delay between retries per client (prevents rapid retries)
    /// 3. Per-client retry state tracking (isolation)
    pub fn get_with_retry_for_client(
        &self,
        client_id: &str,
        policy: &RetryPolicy,
    ) -> Result<PooledConnection<'_, M>, DbPoolError<M::Error>> {
        let client_id_owned = client_id.to_string();
        let deadline: Time = crate::time::wall_now() + self.config.connection_timeout;
        let now = crate::time::wall_now();

        // br-asupersync-mlojr9: Check and update per-client retry state
        let (current_attempts, should_delay) = {
            let mut inner = self.inner.lock();
            let (attempts, last_retry) = inner
                .client_retry_state
                .get(&client_id_owned)
                .copied()
                .unwrap_or((0, now));

            // Check if client has exceeded maximum retry attempts
            if attempts >= self.config.max_retry_attempts_per_client {
                self.stats
                    .total_retry_limits_exceeded
                    .fetch_add(1, Ordering::Relaxed);
                return Err(DbPoolError::RetryLimitExceeded {
                    client_id: client_id_owned,
                    attempts,
                    max_attempts: self.config.max_retry_attempts_per_client,
                });
            }

            // Check if minimum delay has elapsed since last retry
            let min_delay_ms = self.config.min_retry_delay_per_client_ms;
            let time_since_last_retry = now.duration_since(last_retry);
            let should_delay =
                if min_delay_ms > 0 && time_since_last_retry < min_delay_ms * 1_000_000 {
                    Some(
                        Duration::from_millis(min_delay_ms)
                            .saturating_sub(Duration::from_nanos(time_since_last_retry)),
                    )
                } else {
                    None
                };

            // Increment attempt counter and update last retry time
            let new_attempts = attempts + 1;
            inner
                .client_retry_state
                .insert(client_id_owned.clone(), (new_attempts, now));

            (new_attempts, should_delay)
        };

        // Enforce minimum delay between retries if needed
        if let Some(delay) = should_delay {
            if !self.sleep_retry_backoff(delay) {
                return Err(DbPoolError::Closed);
            }
        }

        let mut attempt = 0u32;
        loop {
            attempt += 1;

            match self.get_for_client(client_id) {
                Ok(conn) => {
                    // Success - reset client retry state
                    let mut inner = self.inner.lock();
                    inner.client_retry_state.remove(&client_id_owned);
                    return Ok(conn);
                }
                Err(DbPoolError::Closed) => return Err(DbPoolError::Closed),
                Err(DbPoolError::RetryLimitExceeded { .. }) => {
                    // Don't retry if we've hit retry limits
                    self.stats
                        .total_retry_limits_exceeded
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(DbPoolError::RetryLimitExceeded {
                        client_id: client_id_owned,
                        attempts: current_attempts,
                        max_attempts: self.config.max_retry_attempts_per_client,
                    });
                }
                Err(e) => {
                    // Only retry on Connect, Full, and ClientQuotaExceeded errors
                    if !matches!(
                        e,
                        DbPoolError::Connect(_)
                            | DbPoolError::Full
                            | DbPoolError::ClientQuotaExceeded(_)
                    ) {
                        // Reset retry state on non-retryable error
                        let mut inner = self.inner.lock();
                        inner.client_retry_state.remove(&client_id_owned);
                        return Err(e);
                    }

                    if attempt >= policy.max_attempts {
                        // Reset retry state on final failure
                        let mut inner = self.inner.lock();
                        inner.client_retry_state.remove(&client_id_owned);
                        return Err(e);
                    }

                    // Check if deadline already passed
                    let remaining_nanos = deadline.duration_since(crate::time::wall_now());
                    if remaining_nanos == 0 {
                        let mut inner = self.inner.lock();
                        inner.client_retry_state.remove(&client_id_owned);
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout);
                    }
                    let remaining = Duration::from_nanos(remaining_nanos);

                    // Calculate backoff delay (no jitter in synchronous context)
                    let backoff_delay = calculate_delay(policy, attempt, None);

                    // Also enforce minimum per-client delay
                    let client_delay =
                        Duration::from_millis(self.config.min_retry_delay_per_client_ms);
                    let total_delay = backoff_delay.max(client_delay);

                    if !self.sleep_retry_backoff(total_delay.min(remaining)) {
                        let mut inner = self.inner.lock();
                        inner.client_retry_state.remove(&client_id_owned);
                        return Err(DbPoolError::Closed);
                    }

                    // Re-check deadline after sleep
                    if self.is_closed() {
                        let mut inner = self.inner.lock();
                        inner.client_retry_state.remove(&client_id_owned);
                        return Err(DbPoolError::Closed);
                    }
                    if crate::time::wall_now() >= deadline {
                        let mut inner = self.inner.lock();
                        inner.client_retry_state.remove(&client_id_owned);
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
    fn return_connection(&self, conn: M::Connection, created_at: Time, client_id: Option<String>) {
        // br-asupersync-gb3rck: Determine authentication state for this connection
        let authenticated_for = if self.config.validate_authentication_state {
            // If authentication validation is enabled, check current auth state
            self.manager.authentication_state(&conn)
        } else {
            // If validation disabled, preserve the client_id that was using this connection
            client_id
        };

        let conn_to_disconnect = {
            let mut inner = self.inner.lock();
            if inner.closed {
                inner.total = inner.total.saturating_sub(1);
                Some(conn)
            } else {
                inner.idle.push_back(IdleConnection {
                    conn,
                    created_at,
                    // br-asupersync-w3g9kb: Drop / sync return path
                    // has no Cx; wall_now() is the runtime-time
                    // abstraction.
                    last_used: crate::time::wall_now(),
                    authenticated_for, // br-asupersync-gb3rck: Track authentication state
                });
                None
            }
        };

        if let Some(c) = conn_to_disconnect {
            // br-asupersync-sxhome: Use safe disconnect to prevent resource leaks
            if !self.safe_disconnect(c) {
                // If disconnect failed, we still decremented total count above,
                // so we need to increment it back to maintain consistency
                let mut inner = self.inner.lock();
                inner.total += 1;
                crate::tracing_compat::warn!(
                    event = "database_pool_disconnect_failure",
                    operation = "return_connection",
                    action = "restore_pool_count",
                    "disconnect failed while returning connection"
                );
            } else {
                self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
            }
        }
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
        // br-asupersync-sxhome: Use safe disconnect to prevent resource leaks during close
        let mut failed_disconnects = 0;
        for entry in idle {
            if !self.safe_disconnect(entry.conn) {
                failed_disconnects += 1;
            }
        }

        // If any disconnects failed during close, log the security event
        if failed_disconnects > 0 {
            crate::tracing_compat::warn!(
                event = "database_pool_disconnect_failure",
                operation = "close",
                failed_disconnects,
                "disconnect failures during pool close"
            );
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
        self.cleanup_stale_retry_state();
        let mut inner = self.inner.lock();

        // Drain all idle, keep only the valid ones.
        let mut keep = VecDeque::new();
        let mut to_disconnect = Vec::new();
        // br-asupersync-w3g9kb: sample wall_now() once for the entire
        // eviction sweep so all entries see the same "now".
        let now = crate::time::wall_now();

        while let Some(entry) = inner.idle.pop_front() {
            if entry.is_expired(&self.config, now) || entry.is_idle_too_long(&self.config, now) {
                to_disconnect.push(entry.conn);
            } else {
                keep.push_back(entry);
            }
        }

        let evicted = to_disconnect.len();
        inner.idle = keep;
        inner.total = inner.total.saturating_sub(evicted);
        drop(inner);

        // br-asupersync-sxhome: Use safe disconnect to prevent resource leaks during eviction
        let mut failed_disconnects = 0;
        for conn in to_disconnect {
            if self.safe_disconnect(conn) {
                self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
            } else {
                failed_disconnects += 1;
            }
        }

        // If any disconnects failed, restore the pool total count to maintain consistency
        if failed_disconnects > 0 {
            let mut inner = self.inner.lock();
            inner.total += failed_disconnects;
            crate::tracing_compat::warn!(
                event = "database_pool_disconnect_failure",
                operation = "evict_idle",
                failed_disconnects,
                action = "adjust_pool_count",
                "disconnect failures during idle eviction"
            );
        }
        evicted
    }

    /// Clean up stale retry state entries.
    ///
    /// br-asupersync-mlojr9: Removes retry state entries that are older than 10 minutes
    /// to prevent memory leaks from clients that never retry again.
    fn cleanup_stale_retry_state(&self) {
        let mut inner = self.inner.lock();
        let now = crate::time::wall_now();
        let stale_threshold = Duration::from_secs(600); // 10 minutes

        inner
            .client_retry_state
            .retain(|_client_id, (_, last_retry)| {
                let age = Duration::from_nanos(now.duration_since(*last_retry));
                age < stale_threshold
            });
    }

    /// Safely disconnect a connection with proper error handling and resource cleanup.
    ///
    /// br-asupersync-sxhome: This method provides resource leak protection by ensuring
    /// that connection disconnect failures don't leave the pool in an inconsistent state.
    /// Returns true if disconnect succeeded, false if it failed.
    fn safe_disconnect(&self, conn: M::Connection) -> bool {
        // Use std::panic::catch_unwind to handle disconnect panics
        let disconnect_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.manager.disconnect(conn);
        }));

        match disconnect_result {
            Ok(()) => {
                // Disconnect succeeded
                true
            }
            Err(_panic_info) => {
                // Disconnect panicked - this is a resource leak
                self.stats
                    .total_disconnect_failures
                    .fetch_add(1, Ordering::Relaxed);
                crate::tracing_compat::warn!(
                    event = "database_pool_disconnect_panic",
                    "connection disconnect panicked"
                );
                false
            }
        }
    }

    /// Safely discard a connection with proper resource cleanup on disconnect failure.
    ///
    /// br-asupersync-sxhome: Enhanced version of discard_connection that handles
    /// disconnect failures gracefully and ensures pool state consistency.
    fn safe_discard_connection(&self, conn: M::Connection, client_id: Option<String>) -> bool {
        let disconnect_succeeded = self.safe_disconnect(conn);

        if disconnect_succeeded {
            // Only update stats and counts if disconnect actually succeeded
            {
                let mut inner = self.inner.lock();
                inner.total = inner.total.saturating_sub(1);

                // br-asupersync-qydi3j: Update client connection count only on successful disconnect
                if let Some(ref client) = client_id {
                    if self.config.enforce_client_quotas {
                        if let Some(count) = inner.client_connections.get_mut(client) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                inner.client_connections.remove(client);
                            }
                        }
                    }
                }
            }
            self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
        } else {
            // Disconnect failed - log security event but don't update pool counts
            // to prevent resource count inconsistencies
            crate::tracing_compat::warn!(
                event = "database_pool_disconnect_failure",
                client_id = client_id.as_deref().unwrap_or("unknown"),
                action = "preserve_pool_count",
                "failed to discard connection"
            );
        }

        disconnect_succeeded
    }

    /// Pre-warm the pool by creating connections up to min_idle.
    ///
    /// Returns the number of connections successfully created.
    pub fn warm_up(&self) -> usize {
        let mut created = 0;
        for _ in 0..self.config.min_idle {
            let mut inner = self.inner.lock();
            if inner.total >= self.effective_max_size() || inner.closed {
                break;
            }
            inner.total += 1;
            drop(inner);

            if let Ok(conn) = self.manager.connect() {
                self.stats.total_creates.fetch_add(1, Ordering::Relaxed);
                self.return_connection(conn, crate::time::wall_now(), None); // br-asupersync-gb3rck: clean connection
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
    // br-asupersync-w3g9kb: Time replaces Instant; same values
    // produced by wall_now() in sync paths and cx.now() in async.
    created_at: Time,
    // br-asupersync-qydi3j: Track client for quota enforcement
    client_id: Option<String>,
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
    pub fn return_to_pool(self) {
        // Returning is exactly what `Drop` does: decrement the per-client quota
        // (br-asupersync-qydi3j) AND run the manager's release-time health gate
        // (br-asupersync-5bv5sr), returning the connection only if healthy and
        // discarding it otherwise. Let the guard drop to run that single path —
        // taking `conn` and calling `return_connection` directly here bypassed
        // both, leaking the client quota slot and re-pooling poisoned
        // connections.
        drop(self);
    }

    /// Discard this connection instead of returning it.
    ///
    /// Use when the connection is broken or in an invalid state.
    pub fn discard(mut self) {
        if let Some(conn) = self.conn.take() {
            // Pass the client id and use the safe discard helper so the
            // per-client quota slot is released (it decrements
            // `client_connections`). The prior `discard_connection(conn)`
            // hardcoded `client_id = None` and leaked the quota slot.
            let _ = self
                .pool
                .safe_discard_connection(conn, self.client_id.clone());
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
        if let Some(mut conn) = self.conn.take() {
            // br-asupersync-5bv5sr: gate the return-to-pool path on the
            // manager's release-time health check. Backends that detect a
            // poisoned protocol state, an open transaction, or any other
            // condition that would corrupt the next caller's view should
            // override `release_check` to return `false`; we then route
            // the connection through `safe_discard_connection` so it's closed
            // rather than handed back to a fresh caller.
            //
            // br-asupersync-db-pool-drop-unhealthy-double-decrement-b18gr5: the
            // per-client quota is decremented by EXACTLY ONE owner per branch.
            // `return_connection` does NOT touch `client_connections`, so the
            // healthy path decrements inline here; `safe_discard_connection`
            // decrements internally on a successful disconnect (and preserves the
            // count on failure, since the connection is still alive), so the
            // unhealthy path must NOT decrement inline. The previous code
            // decremented inline UNCONDITIONALLY and then let
            // `safe_discard_connection` decrement again, double-counting the
            // release whenever a client held >1 connection and the unhealthy
            // disconnect succeeded; the failure path then needed a +1 restore.
            if self.pool.manager.release_check(&mut conn) {
                // br-asupersync-qydi3j: healthy return decrements the client quota.
                if let Some(client_id) = &self.client_id {
                    if self.pool.config.enforce_client_quotas {
                        let mut inner = self.pool.inner.lock();
                        if let Some(count) = inner.client_connections.get_mut(client_id) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                inner.client_connections.remove(client_id);
                            }
                        }
                        drop(inner);
                    }
                }
                self.pool
                    .return_connection(conn, self.created_at, self.client_id.clone());
            } else {
                // br-asupersync-sxhome: safe discard owns the per-client quota for
                // this path (decrement-on-success / preserve-on-failure), so there
                // is no inline decrement and no restore compensation to do.
                self.pool
                    .safe_discard_connection(conn, self.client_id.clone());
            }
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

fn trace_async_pool_event(
    cx: &Cx,
    operation: &'static str,
    outcome: &'static str,
    client_scope: &'static str,
) {
    cx.trace_with_fields(
        "database.pool.lifecycle",
        &[
            ("component", "database"),
            ("resource", "pool"),
            ("pool_kind", "async"),
            ("operation", operation),
            ("outcome", outcome),
            ("client_scope", client_scope),
        ],
    );
}

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

    /// Synchronous release-time health check (br-asupersync-5bv5sr).
    ///
    /// See [`ConnectionManager::release_check`] — same contract, applied
    /// from `AsyncPooledConnection`'s `Drop` impl. Async cleanup is NOT
    /// possible from `Drop`, so this hook can only signal reuse-vs-discard.
    fn release_check(&self, _conn: &mut Self::Connection) -> bool {
        true
    }

    /// Called when a connection is permanently removed from the pool.
    fn disconnect(&self, _conn: Self::Connection) {}

    /// Check if a connection has authentication state for a specific client.
    ///
    /// br-asupersync-80525g: Validation bypass fix - adds authentication state checking to async pool.
    /// Returns Some(client_id) if the connection is authenticated for a specific client,
    /// None if it's in a clean/unauthenticated state. Implementations should check
    /// connection-specific authentication state (e.g., active sessions, user context, database roles).
    fn authentication_state(&self, _conn: &Self::Connection) -> Option<String> {
        // Default: no authentication state tracking
        None
    }

    /// Clear authentication state from a connection.
    ///
    /// br-asupersync-80525g: Validation bypass fix - adds authentication state clearing to async pool.
    /// Called to reset a connection to clean/unauthenticated state before returning to pool
    /// for potential reuse by different clients. Return true if successfully cleared,
    /// false if connection should be discarded.
    fn clear_authentication_state(&self, _conn: &mut Self::Connection) -> bool {
        // Default: assume no authentication state to clear
        true
    }
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
    /// Live maximum pool size enforced by capacity checks (yj2nxx.7).
    ///
    /// Async twin of [`DbPool::live_max_size`]: starts at `config.max_size`,
    /// adjustable within `[config.min_idle, config.max_size]` by managed pool
    /// sizing. A shrink only blocks new creates / waiter admission; live
    /// connections drain naturally.
    live_max_size: AtomicUsize,
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
            self.pool.wake_next_async_pool_waiter_locked(&mut inner);
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
            self.pool.wake_next_async_pool_waiter_locked(&mut inner);
        }
    }
}

impl<M: AsyncConnectionManager> AsyncDbPool<M> {
    /// Create a new async connection pool.
    pub fn new(manager: M, config: DbPoolConfig) -> Self {
        let live_max_size = AtomicUsize::new(config.max_size);
        Self {
            manager: Arc::new(manager),
            config,
            inner: Mutex::new(PoolInner {
                idle: VecDeque::new(),
                total: 0,
                closed: false,
                waiters: VecDeque::new(),
                // br-asupersync-80525g: Validation bypass fix - add client tracking to async pool
                client_connections: HashMap::new(),
                client_retry_state: HashMap::new(),
            }),
            stats: PoolStatCounters::default(),
            live_max_size,
        }
    }

    /// Create a pool with default configuration.
    pub fn with_manager(manager: M) -> Self {
        Self::new(manager, DbPoolConfig::default())
    }

    /// The live maximum pool size currently enforced by capacity checks.
    ///
    /// Async twin of [`DbPool::current_max_size`] (yj2nxx.7). Adjusted by
    /// [`set_max_size`](Self::set_max_size) within
    /// `[config.min_idle, config.max_size]`; `DbPoolStats::max_size` keeps
    /// reporting the configured ceiling.
    #[must_use]
    pub fn current_max_size(&self) -> usize {
        self.effective_max_size()
    }

    fn effective_max_size(&self) -> usize {
        self.live_max_size.load(Ordering::Relaxed)
    }

    /// Set the live maximum pool size, clamped into `[min_idle, config.max_size]`.
    ///
    /// The configured `max_size` is the hard ceiling. A shrink only blocks new
    /// creates and waiter admission; live connections drain naturally. Returns
    /// the clamped value actually applied.
    pub fn set_max_size(&self, requested: usize) -> usize {
        let applied = requested
            .max(self.config.min_idle)
            .min(self.config.max_size);
        self.live_max_size.store(applied, Ordering::Relaxed);
        applied
    }

    /// Apply a managed pool-sizing decision to the live maximum size.
    ///
    /// Only [`PoolSizingAction::Resize`] mutates the cap (clamped into the
    /// configured bounds); advisory mode and hysteresis/cadence holds are
    /// no-ops. Returns the applied size when a resize was taken.
    pub fn apply_pool_sizing_decision(&self, decision: &PoolSizingDecision) -> Option<usize> {
        match decision.action {
            PoolSizingAction::Resize { to_size, .. } => Some(self.set_max_size(to_size)),
            _ => None,
        }
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
            total_retry_limits_exceeded: self
                .stats
                .total_retry_limits_exceeded
                .load(Ordering::Relaxed),
            total_disconnect_failures: self.stats.total_disconnect_failures.load(Ordering::Relaxed),
            pending_waiters: inner.waiters.len(),
        }
    }

    /// Returns the hard floor and ceiling used by advisory pool-sizing.
    #[must_use]
    pub fn pool_sizing_bounds(&self) -> PoolSizingBounds {
        self.config.pool_sizing_bounds()
    }

    /// Returns the live controller state used by advisory pool-sizing.
    #[must_use]
    pub fn pool_sizing_controller_state(&self) -> PoolSizingControllerState {
        self.stats().pool_sizing_controller_state()
    }

    /// Computes an advisory pool-sizing decision without opening or closing connections.
    #[must_use]
    pub fn advisory_pool_sizing_decision(
        &self,
        estimate: PoolWorkloadEstimate,
        target: PoolSizingTarget,
    ) -> PoolSizingDecision {
        db_pool_advisory_pool_sizing_decision(
            self.pool_sizing_bounds(),
            self.pool_sizing_controller_state(),
            estimate,
            target,
        )
    }

    fn async_pool_capacity_available_locked(&self, inner: &PoolInner<M::Connection>) -> bool {
        !inner.idle.is_empty() || inner.total < self.effective_max_size()
    }

    fn prune_cancelled_async_pool_waiters_locked(&self, inner: &mut PoolInner<M::Connection>) {
        while inner
            .waiters
            .front()
            .is_some_and(|waiter| waiter.cancelled.load(Ordering::Acquire))
        {
            inner.waiters.pop_front();
        }
    }

    fn async_pool_caller_has_turn_locked(
        &self,
        inner: &mut PoolInner<M::Connection>,
        waiter: Option<&Arc<AsyncPoolWaiter>>,
    ) -> bool {
        self.prune_cancelled_async_pool_waiters_locked(inner);

        match waiter {
            Some(waiter) => inner.waiters.front().is_some_and(|front| {
                Arc::ptr_eq(front, waiter) && waiter.ready.load(Ordering::Acquire)
            }),
            None => inner.waiters.is_empty(),
        }
    }

    fn remove_async_pool_waiter_locked(
        &self,
        inner: &mut PoolInner<M::Connection>,
        waiter: &Arc<AsyncPoolWaiter>,
    ) {
        if let Some(position) = inner
            .waiters
            .iter()
            .position(|queued| Arc::ptr_eq(queued, waiter))
        {
            inner.waiters.remove(position);
        }
    }

    fn complete_async_pool_turn_locked(
        &self,
        inner: &mut PoolInner<M::Connection>,
        waiter: Option<&Arc<AsyncPoolWaiter>>,
    ) {
        if let Some(waiter) = waiter {
            self.remove_async_pool_waiter_locked(inner, waiter);
        }
        self.wake_next_async_pool_waiter_locked(inner);
    }

    fn wake_next_async_pool_waiter_locked(&self, inner: &mut PoolInner<M::Connection>) {
        self.prune_cancelled_async_pool_waiters_locked(inner);

        if inner.closed {
            self.wake_all_async_pool_waiters_locked(inner);
            return;
        }

        if !self.async_pool_capacity_available_locked(inner) {
            return;
        }

        if let Some(waiter) = inner.waiters.front() {
            let already_ready = waiter.ready.swap(true, Ordering::AcqRel);
            if !already_ready {
                waiter.notify.notify_one();
            }
        }
    }

    fn wake_all_async_pool_waiters_locked(&self, inner: &mut PoolInner<M::Connection>) {
        for waiter in inner.waiters.drain(..) {
            waiter.ready.store(true, Ordering::Release);
            waiter.notify.notify_one();
        }
    }

    fn cancel_async_pool_waiter(&self, waiter: &Arc<AsyncPoolWaiter>) {
        waiter.cancelled.store(true, Ordering::Release);
        let mut inner = self.inner.lock();
        self.remove_async_pool_waiter_locked(&mut inner, waiter);
        self.wake_next_async_pool_waiter_locked(&mut inner);
    }

    async fn wait_for_async_pool_turn(
        &self,
        cx: &Cx,
        waiter_slot: &mut Option<Arc<AsyncPoolWaiter>>,
        client_scope: &'static str,
    ) -> Result<(), DbPoolError<M::Error>> {
        const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(10);

        if self.effective_max_size() == 0 {
            // Symmetric cleanup with the cancel/closed/timeout exits below: if we
            // are re-entering with an already-registered waiter (the acquire loop
            // returns here via the `Wait` arm without clearing the slot), it must
            // be removed from `inner.waiters` and the next waiter woken. Otherwise
            // the orphaned waiter is never marked cancelled, never reaped by
            // `prune_cancelled_async_pool_waiters_locked`, and wedges the pool's
            // FIFO turn handoff for every other acquirer once capacity returns.
            if let Some(waiter) = waiter_slot.as_ref() {
                let waiter = Arc::clone(waiter);
                self.cancel_async_pool_waiter(&waiter);
                waiter_slot.take();
            }
            trace_async_pool_event(cx, "wait", "full", client_scope);
            return Err(DbPoolError::Full);
        }
        let deadline = cx.now() + self.config.connection_timeout;

        let waiter = if let Some(waiter) = waiter_slot.as_ref() {
            Arc::clone(waiter)
        } else {
            let waiter = Arc::new(AsyncPoolWaiter::new());
            let mut inner = self.inner.lock();
            if inner.closed {
                return Err(DbPoolError::Closed);
            }
            inner.waiters.push_back(Arc::clone(&waiter));
            self.wake_next_async_pool_waiter_locked(&mut inner);
            *waiter_slot = Some(Arc::clone(&waiter));
            trace_async_pool_event(cx, "wait", "queued", client_scope);
            waiter
        };

        loop {
            if cx.checkpoint().is_err() {
                self.cancel_async_pool_waiter(&waiter);
                waiter_slot.take();
                trace_async_pool_event(cx, "wait", "cancelled", client_scope);
                return Err(DbPoolError::Timeout);
            }
            if self.is_closed() {
                self.cancel_async_pool_waiter(&waiter);
                waiter_slot.take();
                trace_async_pool_event(cx, "wait", "closed", client_scope);
                return Err(DbPoolError::Closed);
            }
            if waiter.ready.load(Ordering::Acquire) {
                trace_async_pool_event(cx, "wait", "ready", client_scope);
                return Ok(());
            }

            let remaining = Duration::from_nanos(deadline.duration_since(cx.now()));
            if remaining.is_zero() {
                self.cancel_async_pool_waiter(&waiter);
                waiter_slot.take();
                self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                trace_async_pool_event(cx, "wait", "timeout", client_scope);
                return Err(DbPoolError::AcquireTimeout);
            }
            let chunk = remaining.min(CANCEL_POLL_INTERVAL);
            let _ = crate::time::timeout(cx.now(), chunk, waiter.notify.notified()).await;
        }
    }

    async fn sleep_retry_backoff(&self, cx: &Cx, mut duration: Duration) -> bool {
        const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(10);

        while !duration.is_zero() {
            if self.is_closed() {
                return false;
            }
            if cx.checkpoint().is_err() {
                return false;
            }

            let chunk = duration.min(CANCEL_POLL_INTERVAL);
            crate::time::sleep(cx.now(), chunk).await;
            duration = duration.saturating_sub(chunk);
        }

        !self.is_closed() && cx.checkpoint().is_ok()
    }

    /// Acquire a connection from the pool.
    pub async fn get(
        &self,
        cx: &Cx,
    ) -> Result<AsyncPooledConnection<'_, M>, DbPoolError<M::Error>> {
        trace_async_pool_event(cx, "acquire", "start", "anonymous");
        let mut waiter = None;

        loop {
            if cx.checkpoint().is_err() {
                trace_async_pool_event(cx, "acquire", "cancelled", "anonymous");
                return Err(DbPoolError::Timeout);
            }

            let step = {
                let mut inner = self.inner.lock();
                if inner.closed {
                    trace_async_pool_event(cx, "acquire", "closed", "anonymous");
                    return Err(DbPoolError::Closed);
                }

                if !self.async_pool_caller_has_turn_locked(&mut inner, waiter.as_ref()) {
                    AsyncAcquireStep::Wait
                } else if let Some(idle) = inner.idle.pop_front() {
                    let granted_waiter = waiter.take();
                    self.complete_async_pool_turn_locked(&mut inner, granted_waiter.as_ref());
                    AsyncAcquireStep::Idle(idle)
                } else if inner.total >= self.effective_max_size() {
                    AsyncAcquireStep::Wait
                } else {
                    inner.total += 1;
                    let granted_waiter = waiter.take();
                    self.complete_async_pool_turn_locked(&mut inner, granted_waiter.as_ref());
                    AsyncAcquireStep::Create
                }
            };

            let idle = match step {
                AsyncAcquireStep::Wait => {
                    self.wait_for_async_pool_turn(cx, &mut waiter, "anonymous")
                        .await?;
                    continue;
                }
                AsyncAcquireStep::Idle(idle) => idle,
                AsyncAcquireStep::Create => {
                    trace_async_pool_event(cx, "create", "start", "anonymous");
                    let mut creation_guard = AsyncCreationGuard {
                        pool: self,
                        disarmed: false,
                    };

                    match self.manager.connect(cx).await {
                        Outcome::Ok(conn) => {
                            if cx.checkpoint().is_err() {
                                self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                                self.manager.disconnect(conn);
                                trace_async_pool_event(
                                    cx,
                                    "create",
                                    "cancelled_after_connect",
                                    "anonymous",
                                );
                                return Err(DbPoolError::Timeout);
                            }
                            creation_guard.disarmed = true;
                            self.stats.total_creates.fetch_add(1, Ordering::Relaxed);
                            trace_async_pool_event(cx, "acquire", "ok_created", "anonymous");
                            return self.finish_async_checkout(conn, cx.now());
                        }
                        Outcome::Err(e) => {
                            trace_async_pool_event(cx, "create", "err", "anonymous");
                            return Err(DbPoolError::Connect(e));
                        }
                        Outcome::Cancelled(_) | Outcome::Panicked(_) => {
                            trace_async_pool_event(cx, "create", "cancelled", "anonymous");
                            return Err(DbPoolError::Timeout);
                        }
                    }
                }
                AsyncAcquireStep::Discard(_) => {
                    unreachable!("anonymous async get never pre-discards")
                }
            };

            {
                // br-asupersync-w3g9kb: async path uses cx.now() so
                // eviction decisions follow the runtime's logical
                // clock (deterministic in the lab runtime).
                let now = cx.now();
                let is_expired = idle.is_expired(&self.config, now);
                let is_stale = idle.is_idle_too_long(&self.config, now);

                if is_expired || is_stale {
                    {
                        let mut inner = self.inner.lock();
                        inner.total = inner.total.saturating_sub(1);
                        self.wake_next_async_pool_waiter_locked(&mut inner);
                    }
                    self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                    trace_async_pool_event(
                        cx,
                        "idle_discard",
                        if is_expired { "expired" } else { "stale" },
                        "anonymous",
                    );
                    self.manager.disconnect(idle.conn);
                    continue;
                }

                // br-asupersync-80525g: Validation bypass fix - check authentication state for async pool
                // For async get() without client_id, only reuse clean connections
                if self.config.validate_authentication_state && idle.authenticated_for.is_some() {
                    {
                        let mut inner = self.inner.lock();
                        inner.total = inner.total.saturating_sub(1);
                        self.wake_next_async_pool_waiter_locked(&mut inner);
                    }
                    self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                    trace_async_pool_event(cx, "idle_discard", "authentication_state", "anonymous");
                    crate::tracing_compat::warn!(
                        event = "async_database_pool_authentication_state_discard",
                        requested_by = "anonymous",
                        "discarding authenticated connection for anonymous checkout"
                    );
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
                        trace_async_pool_event(cx, "validation", "cancelled", "anonymous");
                        return Err(DbPoolError::Timeout);
                    }

                    if !valid {
                        self.stats
                            .total_validation_failures
                            .fetch_add(1, Ordering::Relaxed);
                        trace_async_pool_event(cx, "validation", "failed", "anonymous");
                        continue;
                    }

                    let conn = guard.conn.take().unwrap();
                    trace_async_pool_event(cx, "acquire", "ok_idle", "anonymous");
                    return self.finish_async_checkout(conn, idle.created_at);
                }

                trace_async_pool_event(cx, "acquire", "ok_idle", "anonymous");
                return self.finish_async_checkout(idle.conn, idle.created_at);
            }
        }
    }

    /// Acquire a connection from the pool for a specific client.
    ///
    /// br-asupersync-80525g: Validation bypass fix - adds client-specific connection acquisition to async pool.
    /// Enforces per-client connection quotas when `enforce_client_quotas` is enabled and validates
    /// authentication state to prevent cross-user connection reuse.
    pub async fn get_for_client(
        &self,
        cx: &Cx,
        client_id: &str,
    ) -> Result<AsyncPooledConnection<'_, M>, DbPoolError<M::Error>> {
        trace_async_pool_event(cx, "acquire", "start", "client");
        // If client quotas are disabled, delegate to regular get()
        if !self.config.enforce_client_quotas {
            return self.get(cx).await.map(|mut conn| {
                conn.client_id = Some(client_id.to_string());
                conn
            });
        }

        let client_id_owned = client_id.to_string();
        let mut waiter = None;

        loop {
            if cx.checkpoint().is_err() {
                trace_async_pool_event(cx, "acquire", "cancelled", "client");
                return Err(DbPoolError::Timeout);
            }

            let step = {
                let mut inner = self.inner.lock();
                if inner.closed {
                    trace_async_pool_event(cx, "acquire", "closed", "client");
                    return Err(DbPoolError::Closed);
                }

                // br-asupersync-80525g: Enforce per-client connection quota for async pool
                if let Some(max_per_client) = self.config.max_connections_per_client {
                    let current_count = inner
                        .client_connections
                        .get(&client_id_owned)
                        .copied()
                        .unwrap_or(0);
                    if current_count >= max_per_client {
                        trace_async_pool_event(cx, "acquire", "client_quota_exceeded", "client");
                        return Err(DbPoolError::ClientQuotaExceeded(client_id_owned));
                    }
                }

                if !self.async_pool_caller_has_turn_locked(&mut inner, waiter.as_ref()) {
                    AsyncAcquireStep::Wait
                } else {
                    // Try to get an idle connection with authentication state validation.
                    let mut discard = None;
                    let mut candidate = inner.idle.pop_front();
                    if let Some(idle) = candidate.take() {
                        if self.config.validate_authentication_state {
                            // Authentication state validation: check for cross-user reuse.
                            match &idle.authenticated_for {
                                Some(auth_client) if auth_client != &client_id_owned => {
                                    // SECURITY: Connection authenticated for different client - must not reuse.
                                    crate::tracing_compat::warn!(
                                        event = "async_database_pool_authentication_mismatch_discard",
                                        authenticated_for = %auth_client,
                                        requested_by = %client_id_owned,
                                        "discarding connection authenticated for a different client"
                                    );
                                    inner.total = inner.total.saturating_sub(1);
                                    self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                                    discard = Some(idle.conn);
                                }
                                _ => {
                                    // Clean connection or same client - safe to reuse.
                                    candidate = Some(idle);
                                }
                            }
                        } else {
                            // Authentication validation disabled - reuse any connection.
                            candidate = Some(idle);
                        }
                    }

                    if let Some(conn) = discard {
                        AsyncAcquireStep::Discard(conn)
                    } else if let Some(idle) = candidate {
                        let granted_waiter = waiter.take();
                        self.complete_async_pool_turn_locked(&mut inner, granted_waiter.as_ref());
                        *inner
                            .client_connections
                            .entry(client_id_owned.clone())
                            .or_insert(0) += 1;
                        AsyncAcquireStep::Idle(idle)
                    } else if inner.total >= self.effective_max_size() {
                        AsyncAcquireStep::Wait
                    } else {
                        inner.total += 1;
                        let granted_waiter = waiter.take();
                        self.complete_async_pool_turn_locked(&mut inner, granted_waiter.as_ref());
                        *inner
                            .client_connections
                            .entry(client_id_owned.clone())
                            .or_insert(0) += 1;
                        AsyncAcquireStep::Create
                    }
                }
            };

            let idle = match step {
                AsyncAcquireStep::Wait => {
                    self.wait_for_async_pool_turn(cx, &mut waiter, "client")
                        .await?;
                    continue;
                }
                AsyncAcquireStep::Idle(idle) => idle,
                AsyncAcquireStep::Create => {
                    trace_async_pool_event(cx, "create", "start", "client");
                    let mut creation_guard = AsyncCreationGuard {
                        pool: self,
                        disarmed: false,
                    };

                    match self.manager.connect(cx).await {
                        Outcome::Ok(conn) => {
                            if cx.checkpoint().is_err() {
                                // Decrement client count since we're cancelling
                                let mut inner = self.inner.lock();
                                if let Some(count) =
                                    inner.client_connections.get_mut(&client_id_owned)
                                {
                                    *count = count.saturating_sub(1);
                                    if *count == 0 {
                                        inner.client_connections.remove(&client_id_owned);
                                    }
                                }
                                drop(inner);
                                self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                                self.manager.disconnect(conn);
                                trace_async_pool_event(
                                    cx,
                                    "create",
                                    "cancelled_after_connect",
                                    "client",
                                );
                                return Err(DbPoolError::Timeout);
                            }
                            creation_guard.disarmed = true;
                            self.stats.total_creates.fetch_add(1, Ordering::Relaxed);
                            self.stats
                                .total_acquisitions
                                .fetch_add(1, Ordering::Relaxed);
                            trace_async_pool_event(cx, "acquire", "ok_created", "client");
                            return Ok(AsyncPooledConnection {
                                conn: Some(conn),
                                pool: self,
                                created_at: cx.now(),
                                client_id: Some(client_id_owned),
                            });
                        }
                        Outcome::Err(e) => {
                            // Decrement client count since creation failed.
                            let mut inner = self.inner.lock();
                            if let Some(count) = inner.client_connections.get_mut(&client_id_owned)
                            {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    inner.client_connections.remove(&client_id_owned);
                                }
                            }
                            trace_async_pool_event(cx, "create", "err", "client");
                            return Err(DbPoolError::Connect(e));
                        }
                        Outcome::Cancelled(_) | Outcome::Panicked(_) => {
                            // Decrement client count on cancellation/panic.
                            let mut inner = self.inner.lock();
                            if let Some(count) = inner.client_connections.get_mut(&client_id_owned)
                            {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    inner.client_connections.remove(&client_id_owned);
                                }
                            }
                            trace_async_pool_event(cx, "create", "cancelled", "client");
                            return Err(DbPoolError::Timeout);
                        }
                    }
                }
                AsyncAcquireStep::Discard(conn) => {
                    trace_async_pool_event(cx, "idle_discard", "authentication_state", "client");
                    self.manager.disconnect(conn);
                    continue;
                }
            };

            {
                let now = cx.now();
                let is_expired = idle.is_expired(&self.config, now);
                let is_stale = idle.is_idle_too_long(&self.config, now);

                if is_expired || is_stale {
                    // Decrement client count since we're discarding this connection
                    {
                        let mut inner = self.inner.lock();
                        if let Some(count) = inner.client_connections.get_mut(&client_id_owned) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                inner.client_connections.remove(&client_id_owned);
                            }
                        }
                        inner.total = inner.total.saturating_sub(1);
                        self.wake_next_async_pool_waiter_locked(&mut inner);
                    }
                    self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                    trace_async_pool_event(
                        cx,
                        "idle_discard",
                        if is_expired { "expired" } else { "stale" },
                        "client",
                    );
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
                        // Decrement client count on cancellation
                        let mut inner = self.inner.lock();
                        if let Some(count) = inner.client_connections.get_mut(&client_id_owned) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                inner.client_connections.remove(&client_id_owned);
                            }
                        }
                        trace_async_pool_event(cx, "validation", "cancelled", "client");
                        return Err(DbPoolError::Timeout);
                    }

                    if !valid {
                        // Decrement client count since validation failed
                        {
                            let mut inner = self.inner.lock();
                            if let Some(count) = inner.client_connections.get_mut(&client_id_owned)
                            {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    inner.client_connections.remove(&client_id_owned);
                                }
                            }
                        }
                        self.stats
                            .total_validation_failures
                            .fetch_add(1, Ordering::Relaxed);
                        trace_async_pool_event(cx, "validation", "failed", "client");
                        continue;
                    }

                    let mut valid_conn = guard.conn.take().unwrap();

                    // br-asupersync-80525g: Additional authentication state validation after basic validation
                    if self.config.validate_authentication_state {
                        let current_auth_state = self.manager.authentication_state(&valid_conn);
                        match (&current_auth_state, &idle.authenticated_for) {
                            (Some(current_client), Some(expected_client))
                                if current_client != expected_client =>
                            {
                                // Authentication state mismatch - connection shows different auth than expected
                                let mut inner = self.inner.lock();
                                if let Some(count) =
                                    inner.client_connections.get_mut(&client_id_owned)
                                {
                                    *count = count.saturating_sub(1);
                                    if *count == 0 {
                                        inner.client_connections.remove(&client_id_owned);
                                    }
                                }
                                inner.total = inner.total.saturating_sub(1);
                                self.wake_next_async_pool_waiter_locked(&mut inner);
                                drop(inner);
                                self.stats
                                    .total_validation_failures
                                    .fetch_add(1, Ordering::Relaxed);
                                self.manager.disconnect(valid_conn);
                                trace_async_pool_event(
                                    cx,
                                    "validation",
                                    "authentication_mismatch",
                                    "client",
                                );
                                return Err(DbPoolError::AuthenticationMismatch {
                                    expected: expected_client.clone(),
                                    found: current_client.clone(),
                                });
                            }
                            // Not collapsed into the arm guard:
                            // clear_authentication_state mutates the
                            // connection, and side effects in match guards
                            // obscure when the reset actually runs.
                            #[allow(clippy::collapsible_match)]
                            (Some(current_client), None) if current_client != &client_id_owned => {
                                // Connection has unexpected authentication state - try to clear it
                                if !self.manager.clear_authentication_state(&mut valid_conn) {
                                    // Failed to clear auth state - discard connection
                                    let mut inner = self.inner.lock();
                                    if let Some(count) =
                                        inner.client_connections.get_mut(&client_id_owned)
                                    {
                                        *count = count.saturating_sub(1);
                                        if *count == 0 {
                                            inner.client_connections.remove(&client_id_owned);
                                        }
                                    }
                                    inner.total = inner.total.saturating_sub(1);
                                    self.wake_next_async_pool_waiter_locked(&mut inner);
                                    drop(inner);
                                    self.stats
                                        .total_validation_failures
                                        .fetch_add(1, Ordering::Relaxed);
                                    self.manager.disconnect(valid_conn);
                                    trace_async_pool_event(
                                        cx,
                                        "validation",
                                        "authentication_clear_failed",
                                        "client",
                                    );
                                    continue;
                                }
                            }
                            _ => {
                                // Authentication state is acceptable
                            }
                        }
                    }

                    self.stats
                        .total_acquisitions
                        .fetch_add(1, Ordering::Relaxed);
                    trace_async_pool_event(cx, "acquire", "ok_idle", "client");
                    return Ok(AsyncPooledConnection {
                        conn: Some(valid_conn),
                        pool: self,
                        created_at: idle.created_at,
                        client_id: Some(client_id_owned),
                    });
                }

                self.stats
                    .total_acquisitions
                    .fetch_add(1, Ordering::Relaxed);
                trace_async_pool_event(cx, "acquire", "ok_idle", "client");
                return Ok(AsyncPooledConnection {
                    conn: Some(idle.conn),
                    pool: self,
                    created_at: idle.created_at,
                    client_id: Some(client_id_owned.clone()),
                });
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
                    if !self.sleep_retry_backoff(cx, delay.min(remaining)).await {
                        if self.is_closed() {
                            return Err(DbPoolError::Closed);
                        }
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout);
                    }

                    if self.is_closed() {
                        return Err(DbPoolError::Closed);
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
        created_at: Time,
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
            client_id: None, // br-asupersync-80525g: legacy get() has no client tracking
        })
    }

    /// Return a connection to the pool.
    fn return_connection(&self, conn: M::Connection, created_at: Time, client_id: Option<String>) {
        // br-asupersync-80525g: Validation bypass fix - determine authentication state for async pool
        let authenticated_for = if self.config.validate_authentication_state {
            // If authentication validation is enabled, check current auth state
            self.manager.authentication_state(&conn)
        } else {
            // If validation disabled, preserve the client_id that was using this connection
            client_id
        };

        let conn_to_disconnect = {
            let mut inner = self.inner.lock();
            if inner.closed {
                inner.total = inner.total.saturating_sub(1);
                Some(conn)
            } else {
                inner.idle.push_back(IdleConnection {
                    conn,
                    created_at,
                    // br-asupersync-w3g9kb: Drop / async return
                    // path has no Cx; wall_now() is the runtime-time
                    // abstraction.
                    last_used: crate::time::wall_now(),
                    // br-asupersync-80525g: Validation bypass fix - track authentication state
                    authenticated_for,
                });
                self.wake_next_async_pool_waiter_locked(&mut inner);
                None
            }
        };

        if let Some(conn) = conn_to_disconnect {
            self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
            self.manager.disconnect(conn);
        }
    }

    /// br-asupersync-80525g: Internal method to discard connection with client tracking.
    fn discard_connection_with_client(&self, conn: M::Connection, client_id: Option<String>) {
        {
            let mut inner = self.inner.lock();
            inner.total = inner.total.saturating_sub(1);
            self.wake_next_async_pool_waiter_locked(&mut inner);

            // br-asupersync-80525g: Update client connection count on discard
            if let Some(ref client) = client_id {
                if self.config.enforce_client_quotas {
                    if let Some(count) = inner.client_connections.get_mut(client) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            inner.client_connections.remove(client);
                        }
                    }
                }
            }
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
        self.wake_all_async_pool_waiters_locked(&mut inner);
        if drained > 0 {
            self.stats
                .total_discards
                .fetch_add(drained as u64, Ordering::Relaxed);
        }
        drop(inner);
        // br-asupersync-80525g: Use safe disconnect to prevent resource leaks during async pool close
        let mut failed_disconnects = 0;
        for entry in idle {
            if !self.safe_disconnect(entry.conn) {
                failed_disconnects += 1;
            }
        }

        // If any disconnects failed during close, log the security event
        if failed_disconnects > 0 {
            crate::tracing_compat::warn!(
                event = "async_database_pool_disconnect_failure",
                operation = "close",
                failed_disconnects,
                "disconnect failures during async pool close"
            );
        }
    }

    /// Returns `true` if the pool is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().closed
    }

    /// Safely disconnect a connection with proper error handling and resource cleanup.
    ///
    /// br-asupersync-80525g: Validation bypass fix - adds safe disconnect to async pool
    /// to ensure connection disconnect failures don't leave the pool in an inconsistent state.
    /// Returns true if disconnect succeeded, false if it failed.
    fn safe_disconnect(&self, conn: M::Connection) -> bool {
        // Use std::panic::catch_unwind to handle disconnect panics
        let disconnect_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.manager.disconnect(conn);
        }));

        match disconnect_result {
            Ok(()) => {
                // Disconnect succeeded
                true
            }
            Err(_panic_info) => {
                // Disconnect panicked - this is a resource leak
                self.stats
                    .total_disconnect_failures
                    .fetch_add(1, Ordering::Relaxed);
                crate::tracing_compat::warn!(
                    event = "async_database_pool_disconnect_panic",
                    "async pool connection disconnect panicked"
                );
                false
            }
        }
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
    // br-asupersync-w3g9kb: Time replaces Instant; populated by
    // cx.now() at finish_async_checkout.
    created_at: Time,
    // br-asupersync-80525g: Validation bypass fix - track client for quota enforcement
    client_id: Option<String>,
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
    pub fn return_to_pool(self) {
        // Returning is exactly what `Drop` does: decrement the per-client quota
        // (br-asupersync-80525g) AND run the manager's release-time health gate
        // (br-asupersync-5bv5sr). Let the guard drop to run that single path —
        // taking `conn` and calling `return_connection` directly here bypassed
        // both, leaking the client quota slot and re-pooling poisoned
        // connections.
        drop(self);
    }

    /// Discard this connection instead of returning it.
    pub fn discard(mut self) {
        if let Some(conn) = self.conn.take() {
            // `discard_connection_with_client` releases the per-client quota
            // slot (decrements `client_connections`); the client id must be
            // passed so the slot is actually freed.
            self.pool
                .discard_connection_with_client(conn, self.client_id.clone());
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
        if let Some(mut conn) = self.conn.take() {
            // br-asupersync-80525g: Decrement client connection count when dropping
            if let Some(client_id) = &self.client_id {
                if self.pool.config.enforce_client_quotas {
                    let mut inner = self.pool.inner.lock();
                    if let Some(count) = inner.client_connections.get_mut(client_id) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            inner.client_connections.remove(client_id);
                        }
                    }
                    drop(inner);
                }
            }

            // br-asupersync-5bv5sr: gate on the manager's release-time
            // health check; discard rather than return-to-pool when the
            // backend reports the connection is in a state that would
            // poison the next caller (open transaction, half-drained
            // result set, protocol desync).
            if self.pool.manager.release_check(&mut conn) {
                self.pool
                    .return_connection(conn, self.created_at, self.client_id.clone());
            } else {
                // br-asupersync-80525g: Use safe disconnect for unhealthy connections
                if !self.pool.safe_disconnect(conn) {
                    // If disconnect fails, client count was already decremented above,
                    // so we need to restore it
                    if let Some(ref client_id) = self.client_id {
                        if self.pool.config.enforce_client_quotas {
                            let mut inner = self.pool.inner.lock();
                            let count = inner
                                .client_connections
                                .entry(client_id.clone())
                                .or_insert(0);
                            *count += 1;
                            crate::tracing_compat::warn!(
                                event = "async_database_pool_disconnect_failure",
                                operation = "async_pooled_connection_drop",
                                client_id = %client_id,
                                action = "restore_client_count",
                                "disconnect failed while dropping async pooled connection"
                            );
                        }
                    }
                } else {
                    let mut inner = self.pool.inner.lock();
                    inner.total = inner.total.saturating_sub(1);
                    self.pool.wake_next_async_pool_waiter_locked(&mut inner);
                }
            }
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
    use crate::observability::{LogCollector, LogEntry, LogLevel};
    use crate::runtime::yield_now;
    use crate::types::Budget;
    use futures_lite::future::block_on;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;

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

    // br-asupersync-c5d0q: a connection manager whose reported authentication
    // state can be driven to drift between return-time and the next checkout,
    // with a toggle for clear_authentication_state success. This exercises the
    // two auth-validation failure arms of the sync `get_for_client` that
    // previously leaked a pool capacity slot (the connection is taken out of the
    // ValidationGuard, so the guard's Drop rollback no longer applies).
    struct AuthDriftManager {
        next_id: Arc<AtomicUsize>,
        auth_state: Arc<Mutex<Option<String>>>,
        clear_ok: Arc<AtomicBool>,
        disconnects: Arc<AtomicUsize>,
    }

    impl AuthDriftManager {
        fn new() -> Self {
            Self {
                next_id: Arc::new(AtomicUsize::new(1)),
                auth_state: Arc::new(Mutex::new(None)),
                clear_ok: Arc::new(AtomicBool::new(true)),
                disconnects: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn set_auth_state(&self, state: Option<&str>) {
            *self.auth_state.lock() = state.map(str::to_string);
        }

        fn set_clear_ok(&self, ok: bool) {
            self.clear_ok.store(ok, Ordering::SeqCst);
        }
    }

    impl ConnectionManager for AuthDriftManager {
        type Connection = TestConnection;
        type Error = TestError;

        fn connect(&self) -> Result<Self::Connection, Self::Error> {
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            Ok(TestConnection {
                id,
                valid: Arc::new(AtomicBool::new(true)),
            })
        }

        fn is_valid(&self, _conn: &Self::Connection) -> bool {
            true
        }

        fn disconnect(&self, _conn: Self::Connection) {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
        }

        fn authentication_state(&self, _conn: &Self::Connection) -> Option<String> {
            self.auth_state.lock().clone()
        }

        fn clear_authentication_state(&self, _conn: &mut Self::Connection) -> bool {
            self.clear_ok.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn db_pool_stats_reports_pending_async_waiter_depth() {
        // br-asupersync-eeexl1.5 AC3: DbPoolStats surfaces the async FIFO
        // waiter-queue depth so saturation / no-thundering-herd is observable.
        init_test("db_pool_stats_reports_pending_async_waiter_depth");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        // Fresh pool: nothing parked in the FIFO waiter queue.
        assert_eq!(pool.stats().pending_waiters, 0);
        let baseline = pool.stats();

        // Park three acquirers (white-box mirror of the saturated acquire path,
        // which pushes one Arc<AsyncPoolWaiter> per blocked caller).
        {
            let mut inner = pool.inner.lock();
            for _ in 0..3 {
                inner.waiters.push_back(Arc::new(AsyncPoolWaiter::new()));
            }
        }
        let saturated = pool.stats();
        assert_eq!(
            saturated.pending_waiters, 3,
            "stats().pending_waiters must reflect the live waiter-queue length"
        );
        // Waiter accounting is independent of connection inventory.
        assert_eq!(saturated.idle, baseline.idle, "idle unaffected by waiters");
        assert_eq!(
            saturated.active, baseline.active,
            "active unaffected by waiters"
        );
        assert_eq!(
            saturated.total, baseline.total,
            "total unaffected by waiters"
        );

        // Waking the FIFO head (pop_front) decrements the reported depth — the
        // field tracks the live queue, not a monotonic counter.
        {
            let mut inner = pool.inner.lock();
            inner.waiters.pop_front();
        }
        assert_eq!(pool.stats().pending_waiters, 2);
    }

    #[test]
    fn get_for_client_auth_mismatch_does_not_leak_capacity_slot() {
        init_test("get_for_client_auth_mismatch_does_not_leak_capacity_slot");
        let pool = DbPool::new(
            AuthDriftManager::new(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(true)
                .validate_authentication_state(true),
        );

        // Seed the idle list with a connection authenticated for "c1" (return
        // records manager.authentication_state()).
        pool.manager.set_auth_state(Some("c1"));
        {
            let _conn = pool
                .get_for_client("c1")
                .expect("first acquire creates a connection");
        }
        assert_eq!(pool.stats().idle, 1, "connection should return to idle");
        assert_eq!(pool.stats().total, 1);

        // Auth state drifts to a different client between return and checkout.
        pool.manager.set_auth_state(Some("c2"));
        let err = pool
            .get_for_client("c1")
            .expect_err("auth-state mismatch must be rejected");
        assert!(
            matches!(err, DbPoolError::AuthenticationMismatch { .. }),
            "expected AuthenticationMismatch, got {err:?}"
        );

        // Regression: the rejected connection must free its capacity slot. With
        // the leak, total stays pinned at max_size with zero live connections,
        // so every later acquire fails with Full forever.
        assert_eq!(
            pool.stats().total,
            0,
            "auth-mismatch rejection must not leak a pool capacity slot"
        );
        pool.manager.set_auth_state(Some("c1"));
        assert!(
            pool.get_for_client("c1").is_ok(),
            "pool must be usable again after an auth-mismatch rejection"
        );
        crate::test_complete!("get_for_client_auth_mismatch_does_not_leak_capacity_slot");
    }

    #[test]
    fn get_for_client_clear_auth_failure_does_not_leak_capacity_slot() {
        init_test("get_for_client_clear_auth_failure_does_not_leak_capacity_slot");
        let pool = DbPool::new(
            AuthDriftManager::new(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(true)
                .validate_authentication_state(true),
        );

        // Seed the idle list with a connection that has no recorded auth client
        // (authenticated_for = None).
        pool.manager.set_auth_state(None);
        {
            let _conn = pool
                .get_for_client("c1")
                .expect("first acquire creates a connection");
        }
        assert_eq!(pool.stats().total, 1);

        // On checkout the connection now reports an unexpected client and the
        // manager cannot scrub it, driving the clear-auth-failure discard arm.
        // (The auth state is read at validation time; the idle conn's recorded
        // authenticated_for is None, so the (Some, None) clear arm fires.)
        pool.manager.set_auth_state(Some("intruder"));
        pool.manager.set_clear_ok(false);

        // With the slot leaked, the retry inside get_for_client observes a full
        // pool (total == max_size) and returns Full forever. With the slot
        // freed, the retry takes the create path (which does not re-validate
        // auth) and succeeds.
        let result = pool.get_for_client("c1");
        assert!(
            result.is_ok(),
            "clear-auth-failure discard must free the slot so the pool stays usable, got {:?}",
            result.err()
        );
        crate::test_complete!("get_for_client_clear_auth_failure_does_not_leak_capacity_slot");
    }

    #[test]
    fn explicit_return_to_pool_and_discard_release_client_quota_slot() {
        init_test("explicit_return_to_pool_and_discard_release_client_quota_slot");
        let pool = DbPool::new(
            TestManager::new(),
            DbPoolConfig::with_max_size(4)
                .max_connections_per_client(Some(1))
                .enforce_client_quotas(true),
        );

        // Acquire under client "c1" and explicitly return it. The per-client
        // quota slot must be released. The prior code took the connection out
        // of the guard and called `return_connection` directly, so the guard's
        // Drop (which owns the quota decrement) saw `None` and the slot leaked —
        // the second acquire then failed with ClientQuotaExceeded forever.
        {
            let conn = pool.get_for_client("c1").expect("first acquire");
            conn.return_to_pool();
        }
        pool.get_for_client("c1")
            .expect("return_to_pool must free the client quota slot")
            .return_to_pool();

        // Same for discard(): the sync path previously called
        // `discard_connection` with no client id, so the per-client slot leaked.
        {
            let conn = pool.get_for_client("c1").expect("acquire before discard");
            conn.discard();
        }
        pool.get_for_client("c1")
            .expect("discard must free the client quota slot")
            .return_to_pool();

        crate::test_complete!("explicit_return_to_pool_and_discard_release_client_quota_slot");
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

    fn has_pool_lifecycle_entry(
        entries: &[LogEntry],
        operation: &str,
        outcome: &str,
        client_scope: &str,
    ) -> bool {
        entries.iter().any(|entry| {
            entry.message() == "database.pool.lifecycle"
                && entry.get_field("component") == Some("database")
                && entry.get_field("resource") == Some("pool")
                && entry.get_field("pool_kind") == Some("async")
                && entry.get_field("operation") == Some(operation)
                && entry.get_field("outcome") == Some(outcome)
                && entry.get_field("client_scope") == Some(client_scope)
        })
    }

    #[test]
    fn async_pool_advisory_sizing_stays_observe_only() {
        init_test("async_pool_advisory_sizing_stays_observe_only");
        let pool = AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(6).min_idle(2),
        );
        let estimate = PoolWorkloadEstimate::new(6_000_000, 1_000_000, 0);
        let target = PoolSizingTarget::MaxWaitProbabilityPpm(50_000);

        let decision = pool.advisory_pool_sizing_decision(estimate, target);
        assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
        assert_eq!(decision.recommendation.bounds, PoolSizingBounds::new(2, 6));
        assert_eq!(decision.recommendation.target, target);
        assert_eq!(
            pool.pool_sizing_controller_state(),
            PoolSizingControllerState {
                current_size: 0,
                last_resize_epoch: 0,
            }
        );
        assert_eq!(pool.manager.creates.load(Ordering::SeqCst), 0);
        crate::test_complete!("async_pool_advisory_sizing_stays_observe_only");
    }

    #[test]
    fn async_get_records_structured_pool_lifecycle_traces() {
        init_test("async_get_records_structured_pool_lifecycle_traces");
        let cx = Cx::for_testing();
        let collector = LogCollector::new(32).with_min_level(LogLevel::Trace);
        cx.set_log_collector(collector.clone());
        let pool = AsyncDbPool::new(AsyncTestManager::new(), DbPoolConfig::with_max_size(1));

        {
            let first = block_on(pool.get(&cx)).expect("first checkout creates");
            assert_eq!(first.id, 1);
        }
        {
            let second = block_on(pool.get(&cx)).expect("second checkout reuses idle");
            assert_eq!(second.id, 1);
        }

        let entries = collector.peek();
        assert!(
            has_pool_lifecycle_entry(&entries, "acquire", "start", "anonymous"),
            "acquire start trace missing from {entries:?}"
        );
        assert!(
            has_pool_lifecycle_entry(&entries, "create", "start", "anonymous"),
            "create start trace missing from {entries:?}"
        );
        assert!(
            has_pool_lifecycle_entry(&entries, "acquire", "ok_created", "anonymous"),
            "created checkout trace missing from {entries:?}"
        );
        assert!(
            has_pool_lifecycle_entry(&entries, "acquire", "ok_idle", "anonymous"),
            "idle checkout trace missing from {entries:?}"
        );
        crate::test_complete!("async_get_records_structured_pool_lifecycle_traces");
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
    fn config_pool_sizing_bounds_follow_min_idle_and_max_size() {
        init_test("config_pool_sizing_bounds_follow_min_idle_and_max_size");
        let config = DbPoolConfig::with_max_size(8).min_idle(3);

        assert_eq!(config.pool_sizing_bounds(), PoolSizingBounds::new(3, 8));
        crate::test_complete!("config_pool_sizing_bounds_follow_min_idle_and_max_size");
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
    fn pool_advisory_sizing_uses_live_total_without_mutating_capacity() {
        init_test("pool_advisory_sizing_uses_live_total_without_mutating_capacity");
        let manager = TestManager::new();
        let pool = DbPool::new(
            manager.clone(),
            DbPoolConfig::with_max_size(4)
                .min_idle(1)
                .validate_on_checkout(false),
        );
        let _first = pool.get().expect("first checkout creates a connection");
        let _second = pool.get().expect("second checkout creates a connection");
        let estimate = PoolWorkloadEstimate::new(5_000_000, 1_000_000, 0);
        let target = PoolSizingTarget::MaxWaitProbabilityPpm(100_000);

        assert_eq!(pool.pool_sizing_bounds(), PoolSizingBounds::new(1, 4));
        assert_eq!(
            pool.pool_sizing_controller_state(),
            PoolSizingControllerState {
                current_size: 2,
                last_resize_epoch: 0,
            }
        );

        let decision = pool.advisory_pool_sizing_decision(estimate, target);
        assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
        assert_eq!(decision.recommendation.bounds, PoolSizingBounds::new(1, 4));
        assert_eq!(decision.recommendation.target, target);
        assert_eq!(manager.creates.load(Ordering::SeqCst), 2);
        assert_eq!(pool.stats().total, 2);
        crate::test_complete!("pool_advisory_sizing_uses_live_total_without_mutating_capacity");
    }

    #[test]
    fn get_with_retry_observes_close_during_backoff() {
        init_test("get_with_retry_observes_close_during_backoff");
        let pool = Arc::new(DbPool::new(
            TestManager::new(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(1)),
        ));
        let held = pool.get().expect("holder acquires the only slot");
        let policy = RetryPolicy::fixed_delay(Duration::from_millis(250), 3);
        let close_pool = Arc::clone(&pool);
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            close_pool.close();
        });

        let started = Instant::now();
        let result = pool.get_with_retry(&policy);
        let elapsed = started.elapsed();

        closer.join().expect("close thread should finish cleanly");

        assert!(matches!(result, Err(DbPoolError::Closed)));
        assert!(
            elapsed < Duration::from_millis(200),
            "close during retry backoff should stop promptly, observed {elapsed:?}"
        );

        drop(held);

        let stats = pool.stats();
        assert_eq!(stats.total, 0, "closed pool should not retain capacity");
        assert_eq!(
            stats.active, 0,
            "closed pool should not retain active leases"
        );
        assert_eq!(
            stats.total_discards, 1,
            "return after close should discard the held connection"
        );
        assert_eq!(pool.manager.disconnects(), 1);
        crate::test_complete!("get_with_retry_observes_close_during_backoff");
    }

    #[test]
    fn async_get_with_retry_observes_close_during_backoff() {
        init_test("async_get_with_retry_observes_close_during_backoff");
        let pool = Arc::new(AsyncDbPool::new(
            AsyncTestManager::always_failing(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(1)),
        ));
        let policy = RetryPolicy::fixed_delay(Duration::from_millis(250), 3);
        let cx = Cx::for_testing();
        let close_pool = Arc::clone(&pool);
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            close_pool.close();
        });

        let started = Instant::now();
        let result = block_on(pool.get_with_retry(&cx, &policy));
        let elapsed = started.elapsed();

        closer.join().expect("close thread should finish cleanly");

        assert!(matches!(result, Err(DbPoolError::Closed)));
        assert!(
            elapsed < Duration::from_millis(200),
            "close during retry backoff should stop promptly, observed {elapsed:?}"
        );
        let stats = pool.stats();
        assert_eq!(
            stats.total, 0,
            "closed async pool should not retain capacity"
        );
        assert_eq!(
            stats.active, 0,
            "closed async pool should not retain active leases"
        );
        crate::test_complete!("async_get_with_retry_observes_close_during_backoff");
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
    fn async_get_waits_for_returned_capacity_without_retry() {
        init_test("async_get_waits_for_returned_capacity_without_retry");
        let pool = Arc::new(AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(1).validate_on_checkout(false),
        ));
        let cx = Cx::for_testing();
        let holder = block_on(pool.get(&cx)).expect("holder acquires the only slot");
        let holder_id = holder.id;
        let waiter_started = Arc::new(AtomicBool::new(false));
        let waiter_finished = Arc::new(AtomicBool::new(false));

        let waiter_pool = Arc::clone(&pool);
        let waiter_started_thread = Arc::clone(&waiter_started);
        let waiter_finished_thread = Arc::clone(&waiter_finished);
        let waiter = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            waiter_started_thread.store(true, Ordering::SeqCst);
            let lease = block_on(waiter_pool.get(&cx))
                .expect("direct async get should wait for returned capacity");
            let waiter_id = lease.id;
            lease.return_to_pool();
            waiter_finished_thread.store(true, Ordering::SeqCst);
            waiter_id
        });

        while !waiter_started.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(25));
        assert!(
            !waiter_finished.load(Ordering::SeqCst),
            "direct async get should not fail fast or acquire while the only slot is held"
        );

        holder.return_to_pool();
        let waiter_id = waiter.join().expect("waiter thread should not panic");
        assert_eq!(
            holder_id, waiter_id,
            "direct waiter should reuse the returned connection"
        );

        let stats = pool.stats();
        assert_eq!(stats.total_creates, 1);
        assert_eq!(stats.idle, 1);
        assert_eq!(stats.active, 0);
        crate::test_complete!("async_get_waits_for_returned_capacity_without_retry");
    }

    #[test]
    fn async_get_waiter_queue_admits_direct_waiters_fifo() {
        init_test("async_get_waiter_queue_admits_direct_waiters_fifo");

        #[derive(Debug, PartialEq, Eq)]
        enum Event {
            Started(u8),
            Acquired(u8),
        }

        let pool = Arc::new(AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(1).validate_on_checkout(false),
        ));
        let holder_cx = Cx::for_testing();
        let holder = block_on(pool.get(&holder_cx)).expect("holder acquires the only slot");
        let (events_tx, events_rx) = std::sync::mpsc::channel();
        let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();

        let first_pool = Arc::clone(&pool);
        let first_events = events_tx.clone();
        let first = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            first_events.send(Event::Started(1)).expect("send start");
            let lease = block_on(first_pool.get(&cx)).expect("first waiter acquires");
            first_events
                .send(Event::Acquired(1))
                .expect("send acquisition");
            release_first_rx.recv().expect("first release signal");
            lease.return_to_pool();
        });

        assert_eq!(
            events_rx
                .recv_timeout(Duration::from_millis(500))
                .expect("first waiter starts"),
            Event::Started(1)
        );
        std::thread::sleep(Duration::from_millis(20));

        let second_pool = Arc::clone(&pool);
        let second_events = events_tx.clone();
        let second = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            second_events.send(Event::Started(2)).expect("send start");
            let lease = block_on(second_pool.get(&cx)).expect("second waiter acquires");
            second_events
                .send(Event::Acquired(2))
                .expect("send acquisition");
            lease.return_to_pool();
        });

        assert_eq!(
            events_rx
                .recv_timeout(Duration::from_millis(500))
                .expect("second waiter starts"),
            Event::Started(2)
        );

        holder.return_to_pool();
        assert_eq!(
            events_rx
                .recv_timeout(Duration::from_millis(500))
                .expect("first waiter acquires after holder returns"),
            Event::Acquired(1)
        );
        assert!(
            events_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "second waiter must not acquire while the first waiter still holds the slot"
        );

        release_first_tx.send(()).expect("release first waiter");
        assert_eq!(
            events_rx
                .recv_timeout(Duration::from_millis(500))
                .expect("second waiter acquires after first returns"),
            Event::Acquired(2)
        );

        first.join().expect("first waiter thread should finish");
        second.join().expect("second waiter thread should finish");
        let stats = pool.stats();
        assert_eq!(stats.total_creates, 1);
        assert_eq!(stats.idle, 1);
        assert_eq!(stats.active, 0);
        crate::test_complete!("async_get_waiter_queue_admits_direct_waiters_fifo");
    }

    #[test]
    fn async_get_waiter_budget_exhaustion_returns_acquire_timeout() {
        init_test("async_get_waiter_budget_exhaustion_returns_acquire_timeout");
        let pool = AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_millis(120)),
        );
        let holder_cx = Cx::for_testing();
        let holder = block_on(pool.get(&holder_cx)).expect("holder acquires the only slot");

        let waiter_cx = Cx::for_testing();
        let started = Instant::now();
        let outcome = block_on(pool.get(&waiter_cx));
        let elapsed = started.elapsed();

        let err = match outcome {
            Err(err) => err,
            Ok(_) => panic!("waiter must not acquire while the only slot is held"),
        };
        assert!(
            matches!(err, DbPoolError::AcquireTimeout),
            "exhausting the FIFO acquire budget must yield AcquireTimeout"
        );
        assert!(
            err.to_string().starts_with("[ASUP-E601]"),
            "AcquireTimeout Display must lead with the ASUP-E601 token, got: {err}"
        );
        assert!(
            elapsed >= Duration::from_millis(90),
            "acquire should wait close to the full budget before timing out, observed {elapsed:?}"
        );
        assert_eq!(
            pool.stats().total_timeouts,
            1,
            "budget exhaustion records exactly one acquire timeout"
        );

        holder.return_to_pool();
        crate::test_complete!("async_get_waiter_budget_exhaustion_returns_acquire_timeout");
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

    /// br-asupersync-5bv5sr: PooledConnection::Drop must consult
    /// `ConnectionManager::release_check` and route the connection to
    /// `disconnect()` (NOT the idle pool) when release_check returns
    /// false. This is the cross-user transaction-state-leak defense:
    /// a backend that detects an open transaction or poisoned protocol
    /// state at release time signals "discard" so the next acquire
    /// gets a fresh connection rather than inheriting the prior
    /// caller's half-state.
    #[test]
    fn drop_routes_unhealthy_to_discard_via_release_check() {
        init_test("drop_routes_unhealthy_to_discard_via_release_check");

        struct UnhealthyOnReleaseManager {
            inner: TestManager,
            // Set to true to make every release_check return false.
            unhealthy: Arc<AtomicBool>,
        }

        impl ConnectionManager for UnhealthyOnReleaseManager {
            type Connection = TestConnection;
            type Error = TestError;

            fn connect(&self) -> Result<Self::Connection, Self::Error> {
                self.inner.connect()
            }

            fn is_valid(&self, conn: &Self::Connection) -> bool {
                self.inner.is_valid(conn)
            }

            fn release_check(&self, _conn: &mut Self::Connection) -> bool {
                // Inverted: false means "don't reuse — discard".
                !self.unhealthy.load(Ordering::SeqCst)
            }

            fn disconnect(&self, conn: Self::Connection) {
                self.inner.disconnect(conn);
            }
        }

        let unhealthy = Arc::new(AtomicBool::new(false));
        let manager = UnhealthyOnReleaseManager {
            inner: TestManager::new(),
            unhealthy: unhealthy.clone(),
        };
        let pool = DbPool::new(manager, DbPoolConfig::with_max_size(2));

        // Healthy path: release_check returns true, conn returns to pool.
        {
            let _conn = pool.get().unwrap();
        }
        assert_eq!(
            pool.stats().idle,
            1,
            "healthy connection must return to idle pool"
        );
        assert_eq!(
            pool.stats().total_discards,
            0,
            "healthy drop must NOT discard"
        );

        // Mark all subsequent releases as unhealthy. Acquire the idle
        // connection and drop it — it should be discarded, not returned.
        unhealthy.store(true, Ordering::SeqCst);
        {
            let _conn = pool.get().unwrap();
        }
        assert_eq!(
            pool.stats().idle,
            0,
            "unhealthy drop must remove from idle pool"
        );
        assert_eq!(
            pool.stats().total_discards,
            1,
            "unhealthy drop must increment discards"
        );
        assert_eq!(
            pool.stats().total,
            0,
            "unhealthy drop must decrement total connection count"
        );

        crate::test_complete!("drop_routes_unhealthy_to_discard_via_release_check");
    }

    /// br-asupersync-db-pool-drop-unhealthy-double-decrement-b18gr5: dropping an
    /// unhealthy connection (release_check=false → safe_discard) must decrement
    /// the per-client quota EXACTLY ONCE. The buggy code decremented inline AND
    /// again inside safe_discard_connection, so a client holding 2 connections
    /// dropped to 0 after releasing one (over-count → premature entry removal /
    /// quota corruption).
    #[test]
    fn drop_unhealthy_decrements_client_quota_exactly_once() {
        init_test("drop_unhealthy_decrements_client_quota_exactly_once");

        struct UnhealthyOnReleaseManager {
            inner: TestManager,
            unhealthy: Arc<AtomicBool>,
        }

        impl ConnectionManager for UnhealthyOnReleaseManager {
            type Connection = TestConnection;
            type Error = TestError;

            fn connect(&self) -> Result<Self::Connection, Self::Error> {
                self.inner.connect()
            }

            fn is_valid(&self, conn: &Self::Connection) -> bool {
                self.inner.is_valid(conn)
            }

            fn release_check(&self, _conn: &mut Self::Connection) -> bool {
                !self.unhealthy.load(Ordering::SeqCst)
            }

            fn disconnect(&self, conn: Self::Connection) {
                self.inner.disconnect(conn);
            }
        }

        let unhealthy = Arc::new(AtomicBool::new(false));
        let manager = UnhealthyOnReleaseManager {
            inner: TestManager::new(),
            unhealthy: unhealthy.clone(),
        };
        // Default max_connections_per_client = 3, so one client may hold 2.
        let pool = DbPool::new(manager, DbPoolConfig::with_max_size(4));
        let client = "client-a";
        let client_count =
            || pool.inner.lock().client_connections.get(client).copied().unwrap_or(0);

        // Hold TWO connections for the same client at once.
        let c1 = pool.get_for_client(client).expect("acquire 1");
        let c2 = pool.get_for_client(client).expect("acquire 2");
        assert_eq!(client_count(), 2, "client should hold 2 connections");

        // Unhealthy release routes the drop through safe_discard_connection
        // (disconnect succeeds). Releasing ONE must drop the quota 2 -> 1.
        unhealthy.store(true, Ordering::SeqCst);
        drop(c2);
        assert_eq!(
            client_count(),
            1,
            "unhealthy drop must decrement the client quota exactly once \
             (regression: the double-decrement bug dropped it to 0)"
        );

        // Releasing the survivor drops 1 -> 0 and removes the entry.
        drop(c1);
        assert_eq!(client_count(), 0, "last connection released");

        crate::test_complete!("drop_unhealthy_decrements_client_quota_exactly_once");
    }

    /// br-asupersync-5bv5sr: default release_check returns true, so
    /// existing ConnectionManager implementations that DO NOT override
    /// release_check observe the legacy return-to-pool behavior. This
    /// is the non-breaking-change guarantee.
    #[test]
    fn drop_default_release_check_preserves_legacy_return_to_pool() {
        init_test("drop_default_release_check_preserves_legacy_return_to_pool");
        // Plain TestManager — does NOT override release_check.
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(2));
        {
            let _conn = pool.get().unwrap();
        }
        assert_eq!(
            pool.stats().idle,
            1,
            "default release_check=true must return-to-pool as before"
        );
        assert_eq!(pool.stats().total_discards, 0);
        crate::test_complete!("drop_default_release_check_preserves_legacy_return_to_pool");
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

        // sort_maps keeps the snapshot stable whether or not some feature
        // combination unifies serde_json's preserve_order feature into the
        // test build (br-asupersync-uvqpga).
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!(
                "pool_telemetry_snapshot",
                json!({
                    "initial": db_pool_stats_snapshot(&initial),
                    "checked_out": db_pool_stats_snapshot(&checked_out),
                    "returned": db_pool_stats_snapshot(&returned),
                    "discarded": db_pool_stats_snapshot(&discarded),
                })
            );
        });
    }
}
