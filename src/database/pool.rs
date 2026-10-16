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
    /// Minimum number of idle connections to maintain. Only `warm_up` opens
    /// them and `set_max_size` keeps the cap at or above it; the pool does
    /// not open new ones when idle connections close or expire.
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
            let previous = inner.client_retry_state.get(&client_id_owned).copied();
            let (attempts, last_retry) = previous.unwrap_or((0, now));

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

            // Check if minimum delay has elapsed since last retry. A client
            // with no recorded call has nothing to space from: defaulting its
            // last retry to `now` made every first call sleep the whole delay.
            let min_delay_ms = self.config.min_retry_delay_per_client_ms;
            let time_since_last_retry = now.duration_since(last_retry);
            let should_delay = if previous.is_some()
                && min_delay_ms > 0
                && time_since_last_retry < min_delay_ms * 1_000_000
            {
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
use crate::types::{CancelReason, Outcome, PanicPayload};

/// Internal acquisition result shared by the legacy and four-valued APIs.
enum AsyncAcquireFailure<E: std::error::Error> {
    Pool(DbPoolError<E>),
    Cancelled(CancelReason),
    Panicked(PanicPayload),
}

impl<E: std::error::Error> From<DbPoolError<E>> for AsyncAcquireFailure<E> {
    fn from(error: DbPoolError<E>) -> Self {
        Self::Pool(error)
    }
}

impl<E: std::error::Error> AsyncAcquireFailure<E> {
    fn cancelled(cx: &Cx) -> Self {
        Self::Cancelled(
            cx.cancel_reason()
                .unwrap_or_else(|| CancelReason::user("database pool acquisition cancelled")),
        )
    }

    fn into_outcome<T>(self) -> Outcome<T, DbPoolError<E>> {
        match self {
            Self::Pool(error) => Outcome::Err(error),
            Self::Cancelled(reason) => Outcome::Cancelled(reason),
            Self::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    fn into_legacy_error(self) -> DbPoolError<E> {
        match self {
            Self::Pool(error) => error,
            Self::Cancelled(_) | Self::Panicked(_) => DbPoolError::Timeout,
        }
    }
}

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

    /// Asynchronous cleanup of a returned connection, awaited by
    /// [`AsyncPooledConnection::reset_and_return`] after
    /// [`Self::release_check`] accepted the connection and before it
    /// re-enters the idle queue. Return `false` to discard the connection
    /// instead. Dropping the guard does not run this hook.
    ///
    /// The default does nothing and keeps the connection.
    fn reset_on_return(
        &self,
        _cx: &Cx,
        _conn: &mut Self::Connection,
    ) -> impl std::future::Future<Output = bool> + Send {
        std::future::ready(true)
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
    client_id: Option<String>,
}

impl<M: AsyncConnectionManager> AsyncValidationGuard<'_, M> {
    /// Discards a connection that failed validation as the guard's drop does,
    /// but the caller keeps its FIFO turn
    /// (`requeue_async_pool_waiter_at_front_locked`, before the wake).
    fn discard_keeping_turn(mut self, waiter_slot: &mut Option<Arc<AsyncPoolWaiter>>) {
        if let Some(conn) = self.conn.take() {
            let mut inner = self.pool.inner.lock();
            inner.total = inner.total.saturating_sub(1);
            AsyncDbPool::<M>::release_client_quota_locked(&mut inner, self.client_id.as_deref());
            self.pool
                .requeue_async_pool_waiter_at_front_locked(&mut inner, waiter_slot);
            self.pool.wake_next_async_pool_waiter_locked(&mut inner);
            drop(inner);
            self.pool
                .stats
                .total_discards
                .fetch_add(1, Ordering::Relaxed);
            self.pool.safe_disconnect(conn);
        }
    }
}

impl<M: AsyncConnectionManager> Drop for AsyncValidationGuard<'_, M> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let mut inner = self.pool.inner.lock();
            inner.total = inner.total.saturating_sub(1);
            AsyncDbPool::<M>::release_client_quota_locked(&mut inner, self.client_id.as_deref());
            self.pool.wake_next_async_pool_waiter_locked(&mut inner);
            drop(inner);
            self.pool
                .stats
                .total_discards
                .fetch_add(1, Ordering::Relaxed);
            self.pool.safe_disconnect(conn);
        }
    }
}

struct AsyncCreationGuard<'a, M: AsyncConnectionManager> {
    pool: &'a AsyncDbPool<M>,
    disarmed: bool,
    client_id: Option<String>,
}

/// Owns the client quota from admission until checkout publication. In
/// particular, dropping a pending connect/validation future releases its quota.
struct AsyncClientQuotaGuard<'a, M: AsyncConnectionManager> {
    pool: &'a AsyncDbPool<M>,
    client_id: Option<String>,
}

impl<M: AsyncConnectionManager> Drop for AsyncClientQuotaGuard<'_, M> {
    fn drop(&mut self) {
        if let Some(client_id) = self.client_id.take() {
            let mut inner = self.pool.inner.lock();
            AsyncDbPool::<M>::release_client_quota_locked(&mut inner, Some(&client_id));
        }
    }
}

impl<M: AsyncConnectionManager> Drop for AsyncCreationGuard<'_, M> {
    fn drop(&mut self) {
        if !self.disarmed {
            let mut inner = self.pool.inner.lock();
            inner.total = inner.total.saturating_sub(1);
            AsyncDbPool::<M>::release_client_quota_locked(&mut inner, self.client_id.as_deref());
            self.pool.wake_next_async_pool_waiter_locked(&mut inner);
        }
    }
}

/// RAII guard for a caller's FIFO-turn waiter in the async acquire loop.
///
/// The waiter `Arc` is registered in `inner.waiters` while the caller parks for
/// its turn. Every *cooperative* exit — a granted turn, or the checkpoint /
/// closed / timeout arms — clears `slot` before returning, so this guard is a
/// no-op on those paths. Its job is the one path that runs no in-loop cleanup: a
/// hard **drop** of the `get()`/`get_for_client()` future while still parked
/// (wrapped in `time::timeout`, a losing `select!`/`race!` branch, or any
/// caller that drops the future instead of polling it to a checkpoint). Without
/// it the orphaned waiter stays in `inner.waiters` uncancelled,
/// `wake_next_async_pool_waiter_locked` pins it `ready` at the FIFO front
/// forever, and `prune_cancelled_async_pool_waiters_locked` never reaps it
/// (`cancelled == false`) — wedging async acquisition pool-wide.
struct AsyncWaiterGuard<'a, M: AsyncConnectionManager> {
    pool: &'a AsyncDbPool<M>,
    slot: Option<Arc<AsyncPoolWaiter>>,
}

impl<M: AsyncConnectionManager> Drop for AsyncWaiterGuard<'_, M> {
    fn drop(&mut self) {
        if let Some(waiter) = self.slot.take() {
            self.pool.cancel_async_pool_waiter(&waiter);
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
        // A raised cap is capacity a parked waiter can use now.
        let mut inner = self.inner.lock();
        self.wake_next_async_pool_waiter_locked(&mut inner);
        applied
    }

    /// The caller holds the turn but no capacity is left: the pool shrank
    /// after its waiter was woken. Clearing `ready` makes the wait park until
    /// capacity returns; with it set, the wait returned at once and the
    /// acquire loop spun without yielding or timing out.
    fn give_back_async_pool_turn(waiter: Option<&Arc<AsyncPoolWaiter>>) {
        if let Some(waiter) = waiter {
            waiter.ready.store(false, Ordering::Release);
        }
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

    /// The caller was granted an idle connection it could not use (expired,
    /// stale, invalid, or authenticated for someone else) and has dropped it
    /// from the pool's count. It keeps its turn: a waiter is queued for it at
    /// the front, ahead of the callers that queued while it held the turn,
    /// and the wake that follows (the discard freed capacity) readies it. It
    /// used to re-queue at the back, so each unusable connection it drew cost
    /// it its place. Called before that wake; a no-op on a closed pool.
    fn requeue_async_pool_waiter_at_front_locked(
        &self,
        inner: &mut PoolInner<M::Connection>,
        waiter_slot: &mut Option<Arc<AsyncPoolWaiter>>,
    ) {
        if inner.closed {
            return;
        }
        let waiter = match waiter_slot.take() {
            Some(waiter) => {
                self.remove_async_pool_waiter_locked(inner, &waiter);
                waiter
            }
            None => Arc::new(AsyncPoolWaiter::new()),
        };
        // Only the front waiter may be ready. The one this pushes back may
        // have been readied (by the grant's wake, when more idle connections
        // were left); still ready behind this one, its wait would return at
        // once and its acquire loop would retry without ever parking.
        if let Some(front) = inner.waiters.front() {
            front.ready.store(false, Ordering::Release);
        }
        inner.waiters.push_front(Arc::clone(&waiter));
        *waiter_slot = Some(waiter);
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

    fn release_client_quota_locked(
        inner: &mut PoolInner<M::Connection>,
        client_id: Option<&str>,
    ) {
        if let Some(client_id) = client_id
            && let Some(count) = inner.client_connections.get_mut(client_id)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.client_connections.remove(client_id);
            }
        }
    }

    /// Parks until the caller's waiter holds the FIFO turn. `deadline` is the
    /// whole acquire's: an acquire that waits more than once (its turn given
    /// back, or a granted idle connection discarded) does not restart its
    /// `connection_timeout` budget.
    async fn wait_for_async_pool_turn(
        &self,
        cx: &Cx,
        waiter_slot: &mut Option<Arc<AsyncPoolWaiter>>,
        client_scope: &'static str,
        deadline: Time,
    ) -> Result<(), AsyncAcquireFailure<M::Error>> {
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
            return Err(DbPoolError::Full.into());
        }

        let waiter = if let Some(waiter) = waiter_slot.as_ref() {
            Arc::clone(waiter)
        } else {
            let waiter = Arc::new(AsyncPoolWaiter::new());
            let mut inner = self.inner.lock();
            if inner.closed {
                return Err(DbPoolError::Closed.into());
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
                return Err(AsyncAcquireFailure::cancelled(cx));
            }
            if self.is_closed() {
                self.cancel_async_pool_waiter(&waiter);
                waiter_slot.take();
                trace_async_pool_event(cx, "wait", "closed", client_scope);
                return Err(DbPoolError::Closed.into());
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
                return Err(DbPoolError::AcquireTimeout.into());
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
    ///
    /// This compatibility API maps cancellation and a manager's panic outcome
    /// to [`DbPoolError::Timeout`]. Use [`Self::get_outcome`] to retain them.
    pub async fn get(
        &self,
        cx: &Cx,
    ) -> Result<AsyncPooledConnection<'_, M>, DbPoolError<M::Error>> {
        self.acquire(cx)
            .await
            .map_err(AsyncAcquireFailure::into_legacy_error)
    }

    /// Acquire a connection while preserving all four [`Outcome`] variants.
    ///
    /// Manager cancellation reasons and panic payloads are returned unchanged.
    /// Cancellation while queued, connecting, or validating is distinct from
    /// [`DbPoolError::AcquireTimeout`]. As with [`Self::get`], dropping a pending
    /// acquisition releases its waiter and reserved pool capacity. Rust panics
    /// from connect or validation still unwind; explicit manager panic outcomes
    /// are returned as [`Outcome::Panicked`].
    pub async fn get_outcome(
        &self,
        cx: &Cx,
    ) -> Outcome<AsyncPooledConnection<'_, M>, DbPoolError<M::Error>> {
        match self.acquire(cx).await {
            Ok(connection) => Outcome::Ok(connection),
            Err(failure) => failure.into_outcome(),
        }
    }

    async fn acquire(
        &self,
        cx: &Cx,
    ) -> Result<AsyncPooledConnection<'_, M>, AsyncAcquireFailure<M::Error>> {
        trace_async_pool_event(cx, "acquire", "start", "anonymous");
        let wait_deadline = cx.now() + self.config.connection_timeout;
        let mut waiter_guard = AsyncWaiterGuard {
            pool: self,
            slot: None,
        };

        loop {
            if cx.checkpoint().is_err() {
                trace_async_pool_event(cx, "acquire", "cancelled", "anonymous");
                return Err(AsyncAcquireFailure::cancelled(cx));
            }

            let step = {
                let mut inner = self.inner.lock();
                if inner.closed {
                    trace_async_pool_event(cx, "acquire", "closed", "anonymous");
                    return Err(DbPoolError::Closed.into());
                }

                if !self.async_pool_caller_has_turn_locked(&mut inner, waiter_guard.slot.as_ref()) {
                    AsyncAcquireStep::Wait
                } else if let Some(idle) = inner.idle.pop_front() {
                    let granted_waiter = waiter_guard.slot.take();
                    self.complete_async_pool_turn_locked(&mut inner, granted_waiter.as_ref());
                    AsyncAcquireStep::Idle(idle)
                } else if inner.total >= self.effective_max_size() {
                    Self::give_back_async_pool_turn(waiter_guard.slot.as_ref());
                    AsyncAcquireStep::Wait
                } else {
                    inner.total += 1;
                    let granted_waiter = waiter_guard.slot.take();
                    self.complete_async_pool_turn_locked(&mut inner, granted_waiter.as_ref());
                    AsyncAcquireStep::Create
                }
            };

            let idle = match step {
                AsyncAcquireStep::Wait => {
                    self.wait_for_async_pool_turn(
                        cx,
                        &mut waiter_guard.slot,
                        "anonymous",
                        wait_deadline,
                    )
                    .await?;
                    continue;
                }
                AsyncAcquireStep::Idle(idle) => idle,
                AsyncAcquireStep::Create => {
                    trace_async_pool_event(cx, "create", "start", "anonymous");
                    let mut creation_guard = AsyncCreationGuard {
                        pool: self,
                        disarmed: false,
                        client_id: None,
                    };

                    match self.manager.connect(cx).await {
                        Outcome::Ok(conn) => {
                            if cx.checkpoint().is_err() {
                                self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                                self.safe_disconnect(conn);
                                trace_async_pool_event(
                                    cx,
                                    "create",
                                    "cancelled_after_connect",
                                    "anonymous",
                                );
                                return Err(AsyncAcquireFailure::cancelled(cx));
                            }
                            creation_guard.disarmed = true;
                            self.stats.total_creates.fetch_add(1, Ordering::Relaxed);
                            trace_async_pool_event(cx, "acquire", "ok_created", "anonymous");
                            return self.finish_async_checkout(conn, cx.now(), None);
                        }
                        Outcome::Err(e) => {
                            trace_async_pool_event(cx, "create", "err", "anonymous");
                            return Err(DbPoolError::Connect(e).into());
                        }
                        Outcome::Cancelled(reason) => {
                            trace_async_pool_event(cx, "create", "cancelled", "anonymous");
                            return Err(AsyncAcquireFailure::Cancelled(reason));
                        }
                        Outcome::Panicked(payload) => {
                            trace_async_pool_event(cx, "create", "panicked", "anonymous");
                            return Err(AsyncAcquireFailure::Panicked(payload));
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
                        self.requeue_async_pool_waiter_at_front_locked(
                            &mut inner,
                            &mut waiter_guard.slot,
                        );
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
                        self.requeue_async_pool_waiter_at_front_locked(
                            &mut inner,
                            &mut waiter_guard.slot,
                        );
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
                        client_id: None,
                    };

                    let valid = self
                        .manager
                        .is_valid(cx, guard.conn.as_mut().unwrap())
                        .await;

                    if cx.checkpoint().is_err() {
                        trace_async_pool_event(cx, "validation", "cancelled", "anonymous");
                        return Err(AsyncAcquireFailure::cancelled(cx));
                    }

                    if !valid {
                        self.stats
                            .total_validation_failures
                            .fetch_add(1, Ordering::Relaxed);
                        trace_async_pool_event(cx, "validation", "failed", "anonymous");
                        guard.discard_keeping_turn(&mut waiter_guard.slot);
                        continue;
                    }

                    let conn = guard.conn.take().unwrap();
                    trace_async_pool_event(cx, "acquire", "ok_idle", "anonymous");
                    return self.finish_async_checkout(conn, idle.created_at, None);
                }

                trace_async_pool_event(cx, "acquire", "ok_idle", "anonymous");
                return self.finish_async_checkout(idle.conn, idle.created_at, None);
            }
        }
    }

    /// Acquire a connection from the pool for a specific client.
    ///
    /// br-asupersync-80525g: Validation bypass fix - adds client-specific connection acquisition to async pool.
    /// Enforces per-client connection quotas when `enforce_client_quotas` is enabled and validates
    /// authentication state to prevent cross-user connection reuse.
    /// Cancellation and manager panic outcomes retain the legacy `Timeout`
    /// mapping; [`Self::get_for_client_outcome`] preserves those outcomes.
    pub async fn get_for_client(
        &self,
        cx: &Cx,
        client_id: &str,
    ) -> Result<AsyncPooledConnection<'_, M>, DbPoolError<M::Error>> {
        self.acquire_for_client(cx, client_id)
            .await
            .map_err(AsyncAcquireFailure::into_legacy_error)
    }

    /// Acquire for a client with the same quota and authentication checks as
    /// [`Self::get_for_client`], preserving cancellation and manager panic
    /// outcomes. A pending acquisition owns its quota until checkout succeeds
    /// or the acquisition terminates, including when its future is dropped.
    pub async fn get_for_client_outcome(
        &self,
        cx: &Cx,
        client_id: &str,
    ) -> Outcome<AsyncPooledConnection<'_, M>, DbPoolError<M::Error>> {
        match self.acquire_for_client(cx, client_id).await {
            Ok(connection) => Outcome::Ok(connection),
            Err(failure) => failure.into_outcome(),
        }
    }

    async fn acquire_for_client(
        &self,
        cx: &Cx,
        client_id: &str,
    ) -> Result<AsyncPooledConnection<'_, M>, AsyncAcquireFailure<M::Error>> {
        trace_async_pool_event(cx, "acquire", "start", "client");
        // If client quotas are disabled, delegate to regular get()
        if !self.config.enforce_client_quotas {
            return self.acquire(cx).await.map(|mut conn| {
                conn.client_id = Some(client_id.to_string());
                conn
            });
        }

        let client_id_owned = client_id.to_string();
        let wait_deadline = cx.now() + self.config.connection_timeout;
        let mut waiter_guard = AsyncWaiterGuard {
            pool: self,
            slot: None,
        };

        loop {
            if cx.checkpoint().is_err() {
                trace_async_pool_event(cx, "acquire", "cancelled", "client");
                return Err(AsyncAcquireFailure::cancelled(cx));
            }

            let step = {
                let mut inner = self.inner.lock();
                if inner.closed {
                    trace_async_pool_event(cx, "acquire", "closed", "client");
                    return Err(DbPoolError::Closed.into());
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
                        return Err(DbPoolError::ClientQuotaExceeded(client_id_owned).into());
                    }
                }

                if !self.async_pool_caller_has_turn_locked(&mut inner, waiter_guard.slot.as_ref()) {
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
                        self.requeue_async_pool_waiter_at_front_locked(
                            &mut inner,
                            &mut waiter_guard.slot,
                        );
                        self.wake_next_async_pool_waiter_locked(&mut inner);
                        AsyncAcquireStep::Discard(conn)
                    } else if let Some(idle) = candidate {
                        let granted_waiter = waiter_guard.slot.take();
                        self.complete_async_pool_turn_locked(&mut inner, granted_waiter.as_ref());
                        *inner
                            .client_connections
                            .entry(client_id_owned.clone())
                            .or_insert(0) += 1;
                        AsyncAcquireStep::Idle(idle)
                    } else if inner.total >= self.effective_max_size() {
                        Self::give_back_async_pool_turn(waiter_guard.slot.as_ref());
                        AsyncAcquireStep::Wait
                    } else {
                        inner.total += 1;
                        let granted_waiter = waiter_guard.slot.take();
                        self.complete_async_pool_turn_locked(&mut inner, granted_waiter.as_ref());
                        *inner
                            .client_connections
                            .entry(client_id_owned.clone())
                            .or_insert(0) += 1;
                        AsyncAcquireStep::Create
                    }
                }
            };

            let mut quota_guard = AsyncClientQuotaGuard {
                pool: self,
                client_id: match &step {
                    AsyncAcquireStep::Idle(_) | AsyncAcquireStep::Create => {
                        Some(client_id_owned.clone())
                    }
                    AsyncAcquireStep::Wait | AsyncAcquireStep::Discard(_) => None,
                },
            };
            let idle = match step {
                AsyncAcquireStep::Wait => {
                    self.wait_for_async_pool_turn(
                        cx,
                        &mut waiter_guard.slot,
                        "client",
                        wait_deadline,
                    )
                    .await?;
                    continue;
                }
                AsyncAcquireStep::Idle(idle) => idle,
                AsyncAcquireStep::Create => {
                    trace_async_pool_event(cx, "create", "start", "client");
                    let mut creation_guard = AsyncCreationGuard {
                        pool: self,
                        disarmed: false,
                        client_id: quota_guard.client_id.take(),
                    };

                    match self.manager.connect(cx).await {
                        Outcome::Ok(conn) => {
                            if cx.checkpoint().is_err() {
                                self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                                self.safe_disconnect(conn);
                                trace_async_pool_event(
                                    cx,
                                    "create",
                                    "cancelled_after_connect",
                                    "client",
                                );
                                return Err(AsyncAcquireFailure::cancelled(cx));
                            }
                            creation_guard.disarmed = true;
                            self.stats.total_creates.fetch_add(1, Ordering::Relaxed);
                            trace_async_pool_event(cx, "acquire", "ok_created", "client");
                            return self.finish_async_checkout(
                                conn,
                                cx.now(),
                                creation_guard.client_id.take(),
                            );
                        }
                        Outcome::Err(e) => {
                            trace_async_pool_event(cx, "create", "err", "client");
                            return Err(DbPoolError::Connect(e).into());
                        }
                        Outcome::Cancelled(reason) => {
                            trace_async_pool_event(cx, "create", "cancelled", "client");
                            return Err(AsyncAcquireFailure::Cancelled(reason));
                        }
                        Outcome::Panicked(payload) => {
                            trace_async_pool_event(cx, "create", "panicked", "client");
                            return Err(AsyncAcquireFailure::Panicked(payload));
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
                    {
                        let mut inner = self.inner.lock();
                        Self::release_client_quota_locked(
                            &mut inner,
                            quota_guard.client_id.take().as_deref(),
                        );
                        inner.total = inner.total.saturating_sub(1);
                        self.requeue_async_pool_waiter_at_front_locked(
                            &mut inner,
                            &mut waiter_guard.slot,
                        );
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
                        client_id: quota_guard.client_id.take(),
                    };

                    let valid = self
                        .manager
                        .is_valid(cx, guard.conn.as_mut().unwrap())
                        .await;

                    if cx.checkpoint().is_err() {
                        trace_async_pool_event(cx, "validation", "cancelled", "client");
                        return Err(AsyncAcquireFailure::cancelled(cx));
                    }

                    if !valid {
                        self.stats
                            .total_validation_failures
                            .fetch_add(1, Ordering::Relaxed);
                        trace_async_pool_event(cx, "validation", "failed", "client");
                        guard.discard_keeping_turn(&mut waiter_guard.slot);
                        continue;
                    }

                    // br-asupersync-80525g: Additional authentication state validation after basic validation
                    if self.config.validate_authentication_state {
                        let current_auth_state =
                            self.manager.authentication_state(guard.conn.as_ref().unwrap());
                        match (&current_auth_state, &idle.authenticated_for) {
                            (Some(current_client), Some(expected_client))
                                if current_client != expected_client =>
                            {
                                // Authentication state mismatch - connection shows different auth than expected
                                self.stats
                                    .total_validation_failures
                                    .fetch_add(1, Ordering::Relaxed);
                                trace_async_pool_event(
                                    cx,
                                    "validation",
                                    "authentication_mismatch",
                                    "client",
                                );
                                return Err(DbPoolError::AuthenticationMismatch {
                                    expected: expected_client.clone(),
                                    found: current_client.clone(),
                                }
                                .into());
                            }
                            // Not collapsed into the arm guard:
                            // clear_authentication_state mutates the
                            // connection, and side effects in match guards
                            // obscure when the reset actually runs.
                            #[allow(clippy::collapsible_match)]
                            (Some(current_client), None) if current_client != &client_id_owned => {
                                // Connection has unexpected authentication state - try to clear it
                                if !self
                                    .manager
                                    .clear_authentication_state(guard.conn.as_mut().unwrap())
                                {
                                    // Failed to clear auth state - discard connection
                                    self.stats
                                        .total_validation_failures
                                        .fetch_add(1, Ordering::Relaxed);
                                    trace_async_pool_event(
                                        cx,
                                        "validation",
                                        "authentication_clear_failed",
                                        "client",
                                    );
                                    guard.discard_keeping_turn(&mut waiter_guard.slot);
                                    continue;
                                }
                            }
                            _ => {
                                // Authentication state is acceptable
                            }
                        }
                    }

                    trace_async_pool_event(cx, "acquire", "ok_idle", "client");
                    return self.finish_async_checkout(
                        guard.conn.take().unwrap(),
                        idle.created_at,
                        guard.client_id.take(),
                    );
                }

                trace_async_pool_event(cx, "acquire", "ok_idle", "client");
                return self.finish_async_checkout(
                    idle.conn,
                    idle.created_at,
                    quota_guard.client_id.take(),
                );
            }
        }
    }

    /// Acquire a connection with retry and exponential backoff.
    ///
    /// Use [`Self::get_with_retry_outcome`] to retain cancellation reasons and
    /// manager panic payloads instead of the legacy `Timeout` mapping.
    pub async fn get_with_retry(
        &self,
        cx: &Cx,
        policy: &RetryPolicy,
    ) -> Result<AsyncPooledConnection<'_, M>, DbPoolError<M::Error>> {
        self.acquire_with_retry(cx, policy)
            .await
            .map_err(AsyncAcquireFailure::into_legacy_error)
    }

    /// Acquire with retry while preserving all four outcome variants.
    ///
    /// Only connection errors and capacity errors are retried. Cancellation,
    /// manager panic outcomes, and other pool errors terminate immediately.
    /// Cancellation during backoff retains the caller's cancellation reason.
    pub async fn get_with_retry_outcome(
        &self,
        cx: &Cx,
        policy: &RetryPolicy,
    ) -> Outcome<AsyncPooledConnection<'_, M>, DbPoolError<M::Error>> {
        match self.acquire_with_retry(cx, policy).await {
            Ok(connection) => Outcome::Ok(connection),
            Err(failure) => failure.into_outcome(),
        }
    }

    async fn acquire_with_retry(
        &self,
        cx: &Cx,
        policy: &RetryPolicy,
    ) -> Result<AsyncPooledConnection<'_, M>, AsyncAcquireFailure<M::Error>> {
        let deadline = crate::time::wall_now() + self.config.connection_timeout;
        let mut attempt = 0u32;

        loop {
            attempt += 1;

            match self.acquire(cx).await {
                Ok(conn) => return Ok(conn),
                Err(AsyncAcquireFailure::Pool(DbPoolError::Closed)) => {
                    return Err(DbPoolError::Closed.into());
                }
                Err(
                    failure
                    @ (AsyncAcquireFailure::Cancelled(_) | AsyncAcquireFailure::Panicked(_)),
                ) => {
                    return Err(failure);
                }
                Err(AsyncAcquireFailure::Pool(e)) => {
                    if !matches!(e, DbPoolError::Connect(_) | DbPoolError::Full) {
                        return Err(e.into());
                    }

                    if attempt >= policy.max_attempts {
                        return Err(e.into());
                    }

                    let remaining = std::time::Duration::from_nanos(
                        deadline.duration_since(crate::time::wall_now()),
                    );
                    if cx.checkpoint().is_err() {
                        return Err(AsyncAcquireFailure::cancelled(cx));
                    }
                    if remaining.is_zero() {
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout.into());
                    }

                    let delay = calculate_delay(policy, attempt, None);
                    if !self.sleep_retry_backoff(cx, delay.min(remaining)).await {
                        if self.is_closed() {
                            return Err(DbPoolError::Closed.into());
                        }
                        if cx.checkpoint().is_err() {
                            return Err(AsyncAcquireFailure::cancelled(cx));
                        }
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout.into());
                    }

                    if self.is_closed() {
                        return Err(DbPoolError::Closed.into());
                    }
                    if cx.checkpoint().is_err() {
                        return Err(AsyncAcquireFailure::cancelled(cx));
                    }
                    if crate::time::wall_now() >= deadline {
                        self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(DbPoolError::Timeout.into());
                    }
                }
            }
        }
    }

    fn finish_async_checkout(
        &self,
        conn: M::Connection,
        created_at: Time,
        client_id: Option<String>,
    ) -> Result<AsyncPooledConnection<'_, M>, AsyncAcquireFailure<M::Error>> {
        let mut quota_guard = AsyncClientQuotaGuard {
            pool: self,
            client_id,
        };
        {
            let mut inner = self.inner.lock();
            if inner.closed {
                inner.total = inner.total.saturating_sub(1);
                drop(inner);
                self.stats.total_discards.fetch_add(1, Ordering::Relaxed);
                self.safe_disconnect(conn);
                return Err(DbPoolError::Closed.into());
            }
        }

        self.stats
            .total_acquisitions
            .fetch_add(1, Ordering::Relaxed);
        Ok(AsyncPooledConnection {
            conn: Some(conn),
            pool: self,
            created_at,
            client_id: quota_guard.client_id.take(),
            release_verdict: None,
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
    // Set by reset_and_return: whether Drop keeps the connection, in place of
    // calling release_check again. Some(false) while the reset is in flight,
    // so a cancelled reset discards the connection.
    release_verdict: Option<bool>,
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

    /// Returns the connection to the pool after awaiting the manager's
    /// [`AsyncConnectionManager::reset_on_return`], so that cleanup finishes
    /// before the connection goes idle. For PostgreSQL with
    /// `reset_session_on_return`, `DISCARD ALL` then releases the session's
    /// advisory locks and `LISTEN` registrations now. Dropping the guard, or
    /// [`Self::return_to_pool`], defers that reset to the connection's next
    /// use.
    ///
    /// The manager's `release_check` runs first, as on drop. A connection it
    /// refuses, one whose reset fails, and one whose reset is cancelled (this
    /// future dropped before it completes) are discarded instead.
    pub async fn reset_and_return(mut self, cx: &Cx) {
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        // Discard unless the check passes and the reset completes.
        self.release_verdict = Some(false);
        if !self.pool.manager.release_check(conn) {
            return;
        }
        let reset = self.pool.manager.reset_on_return(cx, conn).await;
        self.release_verdict = Some(reset);
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
            // result set, protocol desync). reset_and_return already ran it.
            let keep = match self.release_verdict {
                Some(keep) => keep,
                None => self.pool.manager.release_check(&mut conn),
            };
            if keep {
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
                    drop(inner);
                    // Counted like every other discard, as the sync pool's
                    // safe_discard_connection does.
                    self.pool
                        .stats
                        .total_discards
                        .fetch_add(1, Ordering::Relaxed);
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
#[path = "pool_inline_tests.rs"]
mod tests;
