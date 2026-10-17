//! Connection tracking and lifecycle management.
//!
//! Provides [`ConnectionManager`] for tracking active connections with capacity limits,
//! and [`ConnectionGuard`] for RAII-based connection deregistration.

use crate::server::shutdown::{ShutdownPhase, ShutdownSignal};
use crate::sync::Notify;
use crate::types::Time;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

/// br-asupersync-368gxk: default idle-connection timeout (60 seconds).
/// Connections that have not seen any application-level activity for
/// this duration are eligible for `drop_idle_connections()`.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// br-asupersync-368gxk: minimum grace period for legitimate slow clients.
///
/// This period is guaranteed before a client can be flagged idle, even when
/// `idle_timeout` is configured below this value. Protects against
/// misconfiguration that would close TCP handshakes mid-flight.
pub const MIN_IDLE_GRACE: Duration = Duration::from_secs(5);

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

const DRAIN_COUNT_UNSET: usize = usize::MAX;

/// Unique identifier for a tracked connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Returns the raw numeric identifier.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "conn-{}", self.0)
    }
}

/// Metadata for a tracked connection.
///
/// br-asupersync-368gxk: `last_activity_nanos` is shared with the
/// returned [`ConnectionGuard`] via `Arc<AtomicU64>` so the guard's
/// `touch()` call updates the manager-visible activity timestamp
/// without re-acquiring the registry lock on every byte of I/O.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Remote peer address.
    pub addr: SocketAddr,
    /// When the connection was accepted.
    pub connected_at: Time,
    /// Last application-activity timestamp in nanoseconds since the
    /// epoch the manager's `time_getter` reports.
    pub last_activity_nanos: Arc<AtomicU64>,
}

/// Tracks active connections and enforces capacity limits.
///
/// The connection manager provides:
/// - Connection registration with capacity enforcement
/// - RAII-based deregistration via [`ConnectionGuard`]
/// - Active connection counting for drain coordination
/// - Notification when all connections close (for shutdown)
///
/// # One Manager per Signal
///
/// Each [`ShutdownSignal`] should be associated with at most one [`ConnectionManager`].
/// When [`ConnectionManager::drain_with_stats`] finishes draining an empty manager, it calls
/// [`ShutdownSignal::mark_stopped`], transitioning the signal to [`ShutdownPhase::Stopped`]
/// and immediately force-closing any remaining connections on any other manager sharing the signal.
///
/// # Example
///
/// ```
/// use asupersync::server::{ConnectionManager, ShutdownSignal};
/// use std::net::SocketAddr;
///
/// let signal = ShutdownSignal::new();
/// let manager = ConnectionManager::new(Some(1000), signal);
///
/// let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
/// if let Some(guard) = manager.register(addr) {
///     // Connection tracked; dropped when guard is dropped
///     assert_eq!(manager.active_count(), 1);
/// }
/// // guard dropped here — active_count returns to 0
/// ```
#[derive(Clone)]
pub struct ConnectionManager {
    state: Arc<Mutex<HashMap<ConnectionId, ConnectionInfo>>>,
    next_id: Arc<AtomicU64>,
    accepting: Arc<AtomicBool>,
    max_connections: Option<usize>,
    /// br-asupersync-f46twu: per-IP connection cap. `None` means
    /// unbounded per-IP (legacy behaviour). When `Some(n)`, a single
    /// remote IP may not occupy more than `n` of the global pool.
    per_ip_max: Option<u32>,
    /// br-asupersync-f46twu: live count of registered connections per
    /// IP. Stored under its own `Mutex` so the per-IP check inside
    /// `register()` can run while holding the main registry lock —
    /// lock order is always `state` → `per_ip_counts`. Drop releases
    /// in reverse order to match.
    per_ip_counts: Arc<Mutex<HashMap<IpAddr, u32>>>,
    /// br-asupersync-368gxk: idle-connection timeout. `None` disables
    /// idle eviction (legacy behaviour); `Some(d)` makes
    /// `drop_idle_connections()` flag every connection whose
    /// `last_activity` is at least `max(d, MIN_IDLE_GRACE)` old.
    idle_timeout: Option<Duration>,
    time_getter: fn() -> Time,
    shutdown_signal: ShutdownSignal,
    all_closed: Arc<Notify>,
    drain_initial_count: Arc<AtomicUsize>,
    force_close_initial_count: Arc<AtomicUsize>,
}

impl ConnectionManager {
    /// Creates a new connection manager.
    ///
    /// # Arguments
    ///
    /// * `max_connections` — Optional capacity limit. `None` means unlimited.
    /// * `shutdown_signal` — Shared shutdown signal for drain coordination. Each signal
    ///   should be paired with at most one `ConnectionManager`.
    #[must_use]
    pub fn new(max_connections: Option<usize>, shutdown_signal: ShutdownSignal) -> Self {
        Self::with_time_getter(max_connections, shutdown_signal, wall_clock_now)
    }

    /// Creates a new connection manager with a custom time source.
    #[must_use]
    pub fn with_time_getter(
        max_connections: Option<usize>,
        shutdown_signal: ShutdownSignal,
        time_getter: fn() -> Time,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::with_capacity(
                max_connections.unwrap_or(64),
            ))),
            next_id: Arc::new(AtomicU64::new(1)),
            accepting: Arc::new(AtomicBool::new(true)),
            max_connections,
            per_ip_max: None,
            per_ip_counts: Arc::new(Mutex::new(HashMap::new())),
            idle_timeout: None,
            time_getter,
            shutdown_signal,
            all_closed: Arc::new(Notify::new()),
            drain_initial_count: Arc::new(AtomicUsize::new(DRAIN_COUNT_UNSET)),
            force_close_initial_count: Arc::new(AtomicUsize::new(DRAIN_COUNT_UNSET)),
        }
    }

    /// br-asupersync-f46twu: configure the per-IP connection cap.
    ///
    /// `None` (default) leaves the per-IP dimension unbounded — the
    /// legacy behaviour where a single hostile IP can occupy the
    /// entire global pool. `Some(n)` rejects any registration that
    /// would push the IP's live count above `n`. The cap is enforced
    /// inside `register()` while the registry lock is held, so it
    /// cannot be raced past.
    ///
    /// Suggested production value: 64–256, balancing legitimate
    /// browser connection-coalescing (HTTP/1.1 typically opens 6–8
    /// per origin; HTTP/2 multiplexes a single one but proxies and
    /// CDNs may fan out many) against the slowloris-class DoS shape
    /// the cap defends against.
    #[must_use]
    pub fn with_per_ip_max(mut self, per_ip_max: Option<u32>) -> Self {
        self.per_ip_max = per_ip_max;
        self
    }

    /// br-asupersync-368gxk: configure the idle-connection timeout.
    ///
    /// `None` (default) disables idle eviction. `Some(d)` enables
    /// `drop_idle_connections()` to flag connections whose last
    /// `touch()` was more than `d` ago. A grace window of
    /// [`MIN_IDLE_GRACE`] is applied as the floor so legitimate slow
    /// clients (TLS handshakes, mobile networks, CDN cold paths)
    /// always get at least 5 seconds before they can be classified
    /// idle — that floor preserves correctness when the configured
    /// timeout is shorter than handshake reality.
    ///
    /// Suggested production value: 60s (the default constant
    /// [`DEFAULT_IDLE_TIMEOUT`]) for HTTP request/response servers;
    /// shorter for chatty WebSocket bridges that send heartbeats; do
    /// NOT enable for long-poll endpoints where the protocol legally
    /// holds the connection idle.
    #[must_use]
    pub fn with_idle_timeout(mut self, idle_timeout: Option<Duration>) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    /// Returns the configured per-IP connection cap (br-asupersync-f46twu).
    #[must_use]
    pub const fn per_ip_max(&self) -> Option<u32> {
        self.per_ip_max
    }

    /// Returns the configured idle-connection timeout (br-asupersync-368gxk).
    #[must_use]
    pub const fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    /// Registers a new connection.
    ///
    /// Returns a [`ConnectionGuard`] that automatically deregisters the connection
    /// when dropped. Returns `None` if the server is at capacity, the per-IP cap
    /// is exhausted, or shutdown is in progress.
    ///
    /// br-asupersync-f46twu: per-IP capacity is checked while the
    /// registry lock is held, so concurrent registrations from the
    /// same hostile IP cannot race past the cap.
    /// br-asupersync-368gxk: the new connection's `last_activity` is
    /// stamped at the current time so `drop_idle_connections()` does
    /// not flag a freshly-accepted connection that has not yet had a
    /// chance to send any bytes.
    #[must_use]
    pub fn register(&self, addr: SocketAddr) -> Option<ConnectionGuard> {
        // Reject new connections during shutdown or after the drain gate closes.
        if !self.accepting.load(Ordering::Acquire) || self.shutdown_signal.is_shutting_down() {
            return None;
        }

        let mut connections = self.state.lock();

        // Re-check after acquiring the state lock so begin_drain() can close
        // acceptance before any waiter finishes registration.
        if !self.accepting.load(Ordering::Acquire) || self.shutdown_signal.is_shutting_down() {
            return None;
        }

        // Global capacity.
        if let Some(max) = self.max_connections {
            if connections.len() >= max {
                return None;
            }
        }

        // br-asupersync-f46twu: per-IP capacity. Lock order: state → per_ip_counts.
        // Both Drop and drop_idle_connections take state first, then per_ip_counts,
        // matching this order to keep the deadlock graph acyclic.
        let ip = addr.ip();
        if let Some(per_ip_max) = self.per_ip_max {
            let mut per_ip = self.per_ip_counts.lock();
            let current = per_ip.get(&ip).copied().unwrap_or(0);
            if current >= per_ip_max {
                return None;
            }
            per_ip
                .entry(ip)
                .and_modify(|c| *c = c.saturating_add(1))
                .or_insert(1);
        }

        let id = ConnectionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let now = (self.time_getter)();
        let last_activity = Arc::new(AtomicU64::new(time_to_nanos(now)));
        let info = ConnectionInfo {
            addr,
            connected_at: now,
            last_activity_nanos: Arc::clone(&last_activity),
        };
        connections.insert(id, info);
        drop(connections);

        Some(ConnectionGuard {
            id,
            addr,
            state: Arc::clone(&self.state),
            per_ip_counts: Arc::clone(&self.per_ip_counts),
            track_per_ip: self.per_ip_max.is_some(),
            last_activity_nanos: last_activity,
            time_getter: self.time_getter,
            all_closed: Arc::clone(&self.all_closed),
        })
    }

    /// br-asupersync-368gxk: scan the registry and return the
    /// `ConnectionId` of every connection whose `last_activity` is
    /// at least `max(idle_timeout, MIN_IDLE_GRACE)` old. Returns an
    /// empty vec when `idle_timeout` is `None` or every connection is
    /// active.
    ///
    /// This method does NOT remove the connections from the registry
    /// — that is the [`ConnectionGuard::drop`] path's responsibility,
    /// which keeps the per-IP counters and the `all_closed`
    /// notification consistent. The caller (typically the per-server
    /// I/O dispatch loop) is expected to:
    ///   1. Call `drop_idle_connections()` periodically (e.g., once
    ///      per `idle_timeout / 4`).
    ///   2. For each returned id, force-close the underlying socket
    ///      so the worker future returns and drops its guard.
    ///
    /// Connections that legitimately need to remain idle (long-poll
    /// endpoints, server-sent events, websocket idle frames) should
    /// either set `idle_timeout = None` for that listener or call
    /// `ConnectionGuard::touch()` on every keepalive.
    #[must_use]
    pub fn drop_idle_connections(&self) -> Vec<ConnectionId> {
        let Some(timeout) = self.idle_timeout else {
            return Vec::new();
        };
        let effective = timeout.max(MIN_IDLE_GRACE);
        let now_nanos = time_to_nanos((self.time_getter)());
        // A timeout past u64 nanoseconds (~584 years) means "never idle"; a
        // truncating cast made it a fraction of a second.
        let threshold_nanos = u64::try_from(effective.as_nanos()).unwrap_or(u64::MAX);

        let connections = self.state.lock();
        let mut idle = Vec::new();
        for (id, info) in connections.iter() {
            let last = info.last_activity_nanos.load(Ordering::Relaxed);
            // Saturating_sub: guarantees zero (i.e. not-idle) when the
            // clock has gone backwards (NTP step) instead of producing
            // a wraparound that would flag the world.
            if now_nanos.saturating_sub(last) >= threshold_nanos {
                idle.push(*id);
            }
        }
        idle.sort();
        idle
    }

    /// br-asupersync-368gxk: per-IP active-count snapshot, suitable
    /// for diagnostics and metrics.
    #[must_use]
    pub fn per_ip_snapshot(&self) -> Vec<(IpAddr, u32)> {
        let per_ip = self.per_ip_counts.lock();
        let mut entries: Vec<_> = per_ip.iter().map(|(ip, c)| (*ip, *c)).collect();
        entries.sort();
        entries
    }

    /// Begins graceful drain in a way that races correctly with registration.
    ///
    /// This closes the registration gate while holding the connection-state lock,
    /// then transitions the shared shutdown signal into draining.
    #[must_use]
    pub fn begin_drain(&self, timeout: Duration) -> bool {
        let active_count = {
            let connections = self.state.lock();
            self.accepting.store(false, Ordering::Release);
            connections.len()
        };

        if self.shutdown_signal.begin_drain(timeout) {
            self.drain_initial_count
                .store(active_count, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Stops admission and captures the exact number of connections present at
    /// the force-close boundary before waking their shutdown waiters.
    ///
    /// The snapshot is the operator force-close boundary. It is recorded while
    /// holding the connection registry lock, but the lock is released before
    /// notifying shutdown waiters so a reentrant waker cannot deadlock on the
    /// registry.
    pub fn force_close(&self) {
        {
            let connections = self.state.lock();
            self.accepting.store(false, Ordering::Release);
            if self.force_close_initial_count.load(Ordering::Acquire) == DRAIN_COUNT_UNSET {
                self.force_close_initial_count
                    .store(connections.len(), Ordering::Release);
            }
        }
        self.shutdown_signal.trigger_immediate();
    }

    /// Transitions the shared shutdown signal from `Draining` to `ForceClosing`,
    /// snapshotting the active connection count if not already recorded.
    ///
    /// The transition and the snapshot happen together under the connection
    /// registry lock, so a connection that closes concurrently is counted on one
    /// side of the boundary only; shutdown waiters are notified after unlocking.
    /// In any other phase this changes nothing: admission and the drain counts
    /// stay as they were.
    ///
    /// Returns `true` if this call transitioned the shutdown signal to `ForceClosing`.
    pub fn begin_force_close(&self) -> bool {
        let entered = {
            let connections = self.state.lock();
            let entered = self.shutdown_signal.enter_force_closing();
            if entered {
                self.accepting.store(false, Ordering::Release);
                if self.force_close_initial_count.load(Ordering::Acquire) == DRAIN_COUNT_UNSET {
                    self.force_close_initial_count
                        .store(connections.len(), Ordering::Release);
                }
            }
            entered
        };
        if entered {
            self.shutdown_signal.notify_force_closing();
        }
        entered
    }

    /// Returns the number of active connections.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.state.lock().len()
    }

    /// Returns `true` if there are no active connections.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active_count() == 0
    }

    /// Returns the current shutdown phase.
    #[must_use]
    pub fn shutdown_phase(&self) -> ShutdownPhase {
        self.shutdown_signal.phase()
    }

    /// Returns a clone of the shutdown signal.
    #[must_use]
    pub fn shutdown_signal(&self) -> &ShutdownSignal {
        &self.shutdown_signal
    }

    /// Returns info for all active connections.
    #[must_use]
    pub fn active_connections(&self) -> Vec<(ConnectionId, ConnectionInfo)> {
        let mut connections: Vec<_> = self
            .state
            .lock()
            .iter()
            .map(|(id, info)| (*id, info.clone()))
            .collect();
        connections.sort_by_key(|(id, _)| *id);
        connections
    }

    /// Waits until all connections have been closed.
    ///
    /// Returns immediately if there are no active connections.
    pub async fn wait_all_closed(&self) {
        loop {
            if self.is_empty() {
                return;
            }

            let mut notified = std::pin::pin!(self.all_closed.notified());
            poll_fn(|cx| {
                if std::future::Future::poll(notified.as_mut(), cx).is_ready() || self.is_empty() {
                    return std::task::Poll::Ready(());
                }
                std::task::Poll::Pending
            })
            .await;
        }
    }

    /// Returns the configured maximum connections.
    #[must_use]
    pub const fn max_connections(&self) -> Option<usize> {
        self.max_connections
    }

    fn drain_started_count(&self) -> usize {
        let recorded = self.drain_initial_count.load(Ordering::Acquire);
        if recorded == DRAIN_COUNT_UNSET {
            let force_closed = self.force_close_initial_count.load(Ordering::Acquire);
            if force_closed == DRAIN_COUNT_UNSET {
                self.active_count()
            } else {
                force_closed
            }
        } else {
            recorded
        }
    }

    fn drain_counts(&self, started_count: usize) -> (usize, usize) {
        let force_closed = self.force_close_initial_count.load(Ordering::Acquire);
        if force_closed != DRAIN_COUNT_UNSET {
            let force_closed = force_closed.min(started_count);
            return (started_count.saturating_sub(force_closed), force_closed);
        }
        let remaining = self.active_count();
        (started_count.saturating_sub(remaining), remaining)
    }

    /// Orchestrates a graceful drain with timeout, returning shutdown statistics.
    ///
    /// This method:
    /// 1. Records the active connection count at drain start
    /// 2. Waits for connections to close or the drain deadline to expire
    /// 3. If deadline expires, transitions to force-close phase
    /// 4. Returns `ShutdownStats` with drained vs force-closed counts
    ///
    /// The caller should call [`ConnectionManager::begin_drain`] (or let this method
    /// sample the active count on start) before awaiting drain completion.
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.begin_drain(Duration::from_secs(30));
    /// let stats = manager.drain_with_stats().await;
    /// println!("Drained: {}, Force-closed: {}", stats.drained, stats.force_closed);
    /// ```
    pub async fn drain_with_stats(&self) -> super::shutdown::ShutdownStats {
        let initial_count = self.drain_started_count();

        if initial_count == 0 {
            self.shutdown_signal.mark_stopped();
            return self.shutdown_signal.collect_stats(0, 0);
        }

        loop {
            if self.shutdown_signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8 {
                let (drained, remaining) = self.drain_counts(initial_count);
                return self.shutdown_signal.collect_stats(drained, remaining);
            }

            if self.is_empty() {
                // All connections drained gracefully.
                let drained = initial_count;
                self.shutdown_signal.mark_stopped();
                return self.shutdown_signal.collect_stats(drained, 0);
            }

            // Check if drain deadline has passed
            if let Some(deadline) = self.shutdown_signal.drain_deadline() {
                if self.shutdown_signal.current_time() >= deadline {
                    // Timeout expired — transition to force close. Count after
                    // the transition: its snapshot, taken under the registry
                    // lock, is the boundary drain_counts reports.
                    let _ = self.begin_force_close();
                    let (drained, remaining) = self.drain_counts(initial_count);
                    return self.shutdown_signal.collect_stats(drained, remaining);
                }
            }

            // Register for the next connection close or deadline notification.
            let notified = self.all_closed.notified();
            let phase_notified = self.shutdown_signal.phase_notified();
            let force_close = self
                .shutdown_signal
                .wait_for_phase(ShutdownPhase::ForceClosing);
            let mut notified = std::pin::pin!(notified);
            let mut phase_notified = std::pin::pin!(phase_notified);
            // Register now: the re-checks below must not miss a close that
            // lands before the first poll of `notified` (br-asupersync-m8xsjx).
            let _ = notified.as_mut().enable();
            let _ = phase_notified.as_mut().enable();
            let mut force_close = std::pin::pin!(force_close);

            // Re-check state after registration to avoid missing close/timeout
            if self.shutdown_signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8 {
                let (drained, remaining) = self.drain_counts(initial_count);
                return self.shutdown_signal.collect_stats(drained, remaining);
            }

            if self.is_empty() {
                let drained = initial_count;
                self.shutdown_signal.mark_stopped();
                return self.shutdown_signal.collect_stats(drained, 0);
            }

            if let Some(deadline) = self.shutdown_signal.drain_deadline() {
                if self.shutdown_signal.current_time() >= deadline {
                    let _ = self.begin_force_close();
                    let (drained, remaining) = self.drain_counts(initial_count);
                    return self.shutdown_signal.collect_stats(drained, remaining);
                }
            }

            if let Some(deadline) = self.shutdown_signal.drain_deadline() {
                let sleep = self.shutdown_signal.wait_until(deadline);
                let mut sleep = std::pin::pin!(sleep);
                poll_fn(|cx| {
                    if notified.as_mut().poll(cx).is_ready()
                        || force_close.as_mut().poll(cx).is_ready()
                        || sleep.as_mut().poll(cx).is_ready()
                    {
                        return std::task::Poll::Ready(());
                    }
                    std::task::Poll::Pending
                })
                .await;
            } else {
                poll_fn(|cx| {
                    if notified.as_mut().poll(cx).is_ready()
                        || force_close.as_mut().poll(cx).is_ready()
                        || phase_notified.as_mut().poll(cx).is_ready()
                    {
                        return std::task::Poll::Ready(());
                    }
                    std::task::Poll::Pending
                })
                .await;
            }
        }
    }
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManager")
            .field("active", &self.active_count())
            .field("max", &self.max_connections)
            .field("phase", &self.shutdown_signal.phase())
            .finish_non_exhaustive()
    }
}

/// RAII guard that deregisters a connection when dropped.
///
/// Obtained from [`ConnectionManager::register`]. The associated connection
/// is automatically removed from the registry when this guard is dropped,
/// which enables drain-phase tracking — the server knows when all in-flight
/// connections have completed.
///
/// br-asupersync-f46twu: the guard remembers the peer's `IpAddr` so
/// `Drop` can decrement the manager's per-IP counter.
/// br-asupersync-368gxk: the guard exposes [`ConnectionGuard::touch`]
/// to bump the manager's view of the connection's last activity, used
/// by [`ConnectionManager::drop_idle_connections`] to identify
/// slowloris-class connections that hold a slot without making
/// progress.
pub struct ConnectionGuard {
    id: ConnectionId,
    addr: SocketAddr,
    state: Arc<Mutex<HashMap<ConnectionId, ConnectionInfo>>>,
    per_ip_counts: Arc<Mutex<HashMap<IpAddr, u32>>>,
    /// Whether the manager has a per-IP cap configured; the guard's
    /// Drop only decrements the per-IP counter when this is true so
    /// the unbounded-per-IP legacy mode incurs no map activity at all.
    track_per_ip: bool,
    last_activity_nanos: Arc<AtomicU64>,
    time_getter: fn() -> Time,
    all_closed: Arc<Notify>,
}

impl ConnectionGuard {
    /// Returns the connection ID.
    #[must_use]
    pub const fn id(&self) -> ConnectionId {
        self.id
    }

    /// br-asupersync-368gxk: bump the connection's last-activity
    /// timestamp to "now" as reported by the manager's time source.
    /// Callers should invoke this on every meaningful application
    /// event (request line read, response head written, websocket
    /// frame received, etc.) — a connection that never calls touch()
    /// becomes eligible for `drop_idle_connections()` after the
    /// configured timeout.
    pub fn touch(&self) {
        let now = (self.time_getter)();
        self.last_activity_nanos
            .store(time_to_nanos(now), Ordering::Relaxed);
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        // Lock order: state → per_ip_counts (matches register()).
        let mut connections = self.state.lock();
        connections.remove(&self.id);
        if self.track_per_ip {
            let mut per_ip = self.per_ip_counts.lock();
            let ip = self.addr.ip();
            if let Some(count) = per_ip.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    per_ip.remove(&ip);
                }
            }
            drop(per_ip);
        }
        // Notify on every removal so drain_with_stats can re-check deadlines.
        // wait_all_closed loops on is_empty(), so extra wakeups are harmless.
        drop(connections);
        self.all_closed.notify_waiters();
    }
}

/// br-asupersync-368gxk: convert a `Time` into a u64 nanosecond
/// representation suitable for atomic compare-and-swap. The runtime's
/// `Time` type is monotonic-domain agnostic; we squash to nanos for
/// the `AtomicU64` storage and compare via saturating subtraction so
/// non-monotonic clock steps (NTP) cannot flag the world idle.
#[inline]
fn time_to_nanos(t: Time) -> u64 {
    t.as_nanos()
}

impl std::fmt::Debug for ConnectionGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionGuard")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "connection_inline_tests.rs"]
mod tests;
