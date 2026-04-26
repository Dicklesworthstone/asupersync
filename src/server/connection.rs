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

/// br-asupersync-368gxk: minimum grace period that legitimate slow
/// clients are guaranteed before they can be flagged idle, even when
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
/// # Example
///
/// ```ignore
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
    /// `last_activity` is older than `d` minus the grace window.
    idle_timeout: Option<Duration>,
    time_getter: fn() -> Time,
    shutdown_signal: ShutdownSignal,
    all_closed: Arc<Notify>,
    drain_initial_count: Arc<AtomicUsize>,
}

impl ConnectionManager {
    /// Creates a new connection manager.
    ///
    /// # Arguments
    ///
    /// * `max_connections` — Optional capacity limit. `None` means unlimited.
    /// * `shutdown_signal` — Shared shutdown signal for drain coordination.
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
    /// older than `idle_timeout - MIN_IDLE_GRACE`. Returns an empty
    /// vec when `idle_timeout` is `None` or every connection is
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
        let threshold_nanos = effective.as_nanos() as u64;

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
            let notified = self.all_closed.notified();
            if self.is_empty() {
                return;
            }
            notified.await;
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
            self.active_count()
        } else {
            recorded
        }
    }

    fn drain_counts(&self, started_count: usize) -> (usize, usize) {
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
    /// The caller must have already called [`ShutdownSignal::begin_drain`] before
    /// calling this method. The caller is responsible for force-closing connections
    /// after this method transitions to `ForceClosing` phase.
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.begin_drain(Duration::from_secs(30));
    /// let stats = manager.drain_with_stats().await;
    /// signal.mark_stopped();
    /// println!("Drained: {}, Force-closed: {}", stats.drained, stats.force_closed);
    /// ```
    pub async fn drain_with_stats(&self) -> super::shutdown::ShutdownStats {
        let initial_count = self.drain_started_count();

        if initial_count == 0 {
            self.shutdown_signal.mark_stopped();
            return self.shutdown_signal.collect_stats(0, 0);
        }

        loop {
            if self.is_empty() {
                // All connections drained gracefully
                let drained = initial_count;
                self.shutdown_signal.mark_stopped();
                return self.shutdown_signal.collect_stats(drained, 0);
            }

            if self.shutdown_signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8 {
                let (drained, remaining) = self.drain_counts(initial_count);
                return self.shutdown_signal.collect_stats(drained, remaining);
            }

            // Check if drain deadline has passed
            if let Some(deadline) = self.shutdown_signal.drain_deadline() {
                if self.shutdown_signal.current_time() >= deadline {
                    // Timeout expired — transition to force close
                    let (drained, remaining) = self.drain_counts(initial_count);
                    let _ = self.shutdown_signal.begin_force_close();
                    return self.shutdown_signal.collect_stats(drained, remaining);
                }
            }

            // Register for the next connection close or deadline notification.
            let notified = self.all_closed.notified();
            let force_close = self
                .shutdown_signal
                .wait_for_phase(ShutdownPhase::ForceClosing);
            let mut notified = std::pin::pin!(notified);
            let mut force_close = std::pin::pin!(force_close);

            // Re-check state after registration to avoid missing close/timeout
            if self.is_empty() {
                let drained = initial_count;
                self.shutdown_signal.mark_stopped();
                return self.shutdown_signal.collect_stats(drained, 0);
            }

            if self.shutdown_signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8 {
                let (drained, remaining) = self.drain_counts(initial_count);
                return self.shutdown_signal.collect_stats(drained, remaining);
            }

            if let Some(deadline) = self.shutdown_signal.drain_deadline() {
                if self.shutdown_signal.current_time() >= deadline {
                    let (drained, remaining) = self.drain_counts(initial_count);
                    let _ = self.shutdown_signal.begin_force_close();
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
    use crate::test_utils::init_test_logging;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    static TEST_NOW: AtomicU64 = AtomicU64::new(0);

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn set_test_time(nanos: u64) {
        TEST_NOW.store(nanos, Ordering::Relaxed);
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.load(Ordering::Relaxed))
    }

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[test]
    fn register_and_deregister() {
        init_test("register_and_deregister");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal);

        let count_before = manager.active_count();
        crate::assert_with_log!(count_before == 0, "empty initially", 0, count_before);

        let guard = manager.register(test_addr(8080));
        let has_guard = guard.is_some();
        crate::assert_with_log!(has_guard, "registered", true, has_guard);

        let count_during = manager.active_count();
        crate::assert_with_log!(count_during == 1, "one active", 1, count_during);

        drop(guard);

        let count_after = manager.active_count();
        crate::assert_with_log!(count_after == 0, "empty after drop", 0, count_after);
        crate::test_complete!("register_and_deregister");
    }

    #[test]
    fn capacity_limit_enforced() {
        init_test("capacity_limit_enforced");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(Some(2), signal);

        let g1 = manager.register(test_addr(1));
        let g2 = manager.register(test_addr(2));
        let g3 = manager.register(test_addr(3));

        let has_g1 = g1.is_some();
        let has_g2 = g2.is_some();
        let has_g3 = g3.is_some();
        crate::assert_with_log!(has_g1, "first accepted", true, has_g1);
        crate::assert_with_log!(has_g2, "second accepted", true, has_g2);
        crate::assert_with_log!(!has_g3, "third rejected", false, has_g3);

        let count = manager.active_count();
        crate::assert_with_log!(count == 2, "at capacity", 2, count);

        // Free one slot
        drop(g1);
        let g4 = manager.register(test_addr(4));
        let has_g4 = g4.is_some();
        crate::assert_with_log!(has_g4, "fourth accepted after free", true, has_g4);
        crate::test_complete!("capacity_limit_enforced");
    }

    #[test]
    fn rejects_during_shutdown() {
        init_test("rejects_during_shutdown");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal);

        let g1 = manager.register(test_addr(1));
        let has_g1 = g1.is_some();
        crate::assert_with_log!(has_g1, "accepted before shutdown", true, has_g1);

        let began = manager.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "begin drain", true, began);

        let g2 = manager.register(test_addr(2));
        let has_g2 = g2.is_some();
        crate::assert_with_log!(!has_g2, "rejected during shutdown", false, has_g2);

        // Existing connection still tracked
        let count = manager.active_count();
        crate::assert_with_log!(count == 1, "existing still active", 1, count);
        crate::test_complete!("rejects_during_shutdown");
    }

    #[test]
    fn multiple_connections() {
        init_test("multiple_connections");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal);

        let guards: Vec<_> = (0..5)
            .filter_map(|i| manager.register(test_addr(8080 + i)))
            .collect();

        let count = manager.active_count();
        crate::assert_with_log!(count == 5, "five active", 5, count);

        drop(guards);

        let count = manager.active_count();
        crate::assert_with_log!(count == 0, "all dropped", 0, count);
        crate::test_complete!("multiple_connections");
    }

    #[test]
    fn connection_ids_are_unique() {
        init_test("connection_ids_are_unique");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal);

        let g1 = manager.register(test_addr(1)).expect("register");
        let g2 = manager.register(test_addr(2)).expect("register");

        let ids_differ = g1.id() != g2.id();
        crate::assert_with_log!(ids_differ, "unique ids", true, ids_differ);
        crate::test_complete!("connection_ids_are_unique");
    }

    #[test]
    fn active_connections_returns_info() {
        init_test("active_connections_returns_info");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal);

        let _g1 = manager.register(test_addr(8080)).expect("register");
        let _g2 = manager.register(test_addr(8081)).expect("register");

        let active = manager.active_connections();
        let len = active.len();
        crate::assert_with_log!(len == 2, "two connections", 2, len);

        let addresses: Vec<_> = active.iter().map(|(_, info)| info.addr).collect();
        crate::assert_with_log!(
            addresses == vec![test_addr(8080), test_addr(8081)],
            "active connections keep deterministic registration order",
            format!("{:?}", vec![test_addr(8080), test_addr(8081)]),
            format!("{addresses:?}")
        );
        crate::test_complete!("active_connections_returns_info");
    }

    #[test]
    fn active_connections_are_sorted_by_connection_id() {
        init_test("active_connections_are_sorted_by_connection_id");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal);

        let g1 = manager.register(test_addr(9001)).expect("register 1");
        let g2 = manager.register(test_addr(9002)).expect("register 2");
        let g3 = manager.register(test_addr(9003)).expect("register 3");

        let g1_id = g1.id().raw();
        let g2_id = g2.id().raw();
        let g3_id = g3.id().raw();
        crate::assert_with_log!(g1_id == 1, "g1 is 1", 1, g1_id);
        crate::assert_with_log!(g2_id == 2, "g2 is 2", 2, g2_id);
        crate::assert_with_log!(g3_id == 3, "g3 is 3", 3, g3_id);

        // Drop the middle guard so the remaining snapshot must still sort by
        // logical connection ID rather than by HashMap bucket order.
        let middle_id = g2.id();
        drop(g2);
        let g4 = manager.register(test_addr(9004)).expect("register 4");
        let g4_id = g4.id().raw();
        crate::assert_with_log!(g4_id == 4, "g4 is 4", 4, g4_id);

        let active = manager.active_connections();
        let ids: Vec<_> = active.iter().map(|(id, _)| id.raw()).collect();
        crate::assert_with_log!(
            ids.windows(2).all(|pair| pair[0] < pair[1]),
            "active connection ids are strictly ascending",
            "strictly ascending ids",
            format!("{ids:?}")
        );
        crate::assert_with_log!(
            !ids.contains(&middle_id.raw()),
            "dropped connections stay absent from the deterministic snapshot",
            false,
            ids.contains(&middle_id.raw())
        );
        crate::assert_with_log!(
            ids == vec![g1_id, g3_id, g4_id],
            "remaining snapshot keeps deterministic connection-id ordering",
            format!("{:?}", vec![g1_id, g3_id, g4_id]),
            format!("{ids:?}")
        );
        crate::test_complete!("active_connections_are_sorted_by_connection_id");
    }

    #[test]
    fn unlimited_capacity() {
        init_test("unlimited_capacity");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal);

        let max = manager.max_connections();
        let is_none = max.is_none();
        crate::assert_with_log!(is_none, "unlimited", true, is_none);

        // Register many connections
        let guards: Vec<_> = (0..100)
            .filter_map(|i| manager.register(test_addr(i)))
            .collect();

        let count = manager.active_count();
        crate::assert_with_log!(count == 100, "hundred active", 100, count);
        drop(guards);
        crate::test_complete!("unlimited_capacity");
    }

    #[test]
    fn guard_debug_format() {
        init_test("guard_debug_format");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal);
        let guard = manager.register(test_addr(1)).expect("register");

        let debug = format!("{guard:?}");
        let has_conn = debug.contains("ConnectionGuard");
        crate::assert_with_log!(has_conn, "debug format", true, has_conn);
        crate::test_complete!("guard_debug_format");
    }

    #[test]
    fn connection_id_display() {
        init_test("connection_id_display");
        let id = ConnectionId(42);
        let formatted = format!("{id}");
        crate::assert_with_log!(formatted == "conn-42", "formatted id", "conn-42", formatted);
        crate::test_complete!("connection_id_display");
    }

    #[test]
    fn is_empty_check() {
        init_test("is_empty_check");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal);

        let empty_before = manager.is_empty();
        crate::assert_with_log!(empty_before, "empty before", true, empty_before);

        let _guard = manager.register(test_addr(1));
        let not_empty = !manager.is_empty();
        crate::assert_with_log!(not_empty, "not empty", true, not_empty);
        crate::test_complete!("is_empty_check");
    }

    // ====================================================================
    // Async integration tests
    // ====================================================================

    #[test]
    fn wait_all_closed_resolves_when_empty() {
        init_test("wait_all_closed_resolves_when_empty");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let manager = ConnectionManager::new(None, signal);

            // No connections — should resolve immediately
            manager.wait_all_closed().await;

            let empty = manager.is_empty();
            crate::assert_with_log!(empty, "is empty", true, empty);
        });
        crate::test_complete!("wait_all_closed_resolves_when_empty");
    }

    #[test]
    fn wait_all_closed_resolves_after_drop() {
        init_test("wait_all_closed_resolves_after_drop");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let manager = ConnectionManager::new(None, signal);

            // Register some connections
            let g1 = manager.register(test_addr(1)).expect("register");
            let g2 = manager.register(test_addr(2)).expect("register");

            let count = manager.active_count();
            crate::assert_with_log!(count == 2, "two active", 2, count);

            // Drop connections from a thread after a delay
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                drop(g1);
                drop(g2);
            });

            // Wait for all to close — should resolve after thread drops guards
            manager.wait_all_closed().await;

            let empty = manager.is_empty();
            crate::assert_with_log!(empty, "all closed", true, empty);

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("wait_all_closed_resolves_after_drop");
    }

    #[test]
    fn wait_all_closed_with_staggered_drops() {
        init_test("wait_all_closed_with_staggered_drops");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let manager = ConnectionManager::new(None, signal);

            let g1 = manager.register(test_addr(1)).expect("register");
            let g2 = manager.register(test_addr(2)).expect("register");
            let g3 = manager.register(test_addr(3)).expect("register");

            let count = manager.active_count();
            crate::assert_with_log!(count == 3, "three active", 3, count);

            // Drop connections one at a time from a thread
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                drop(g1);
                std::thread::sleep(Duration::from_millis(10));
                drop(g2);
                std::thread::sleep(Duration::from_millis(10));
                drop(g3);
            });

            manager.wait_all_closed().await;

            let empty = manager.is_empty();
            crate::assert_with_log!(empty, "all closed after stagger", true, empty);

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("wait_all_closed_with_staggered_drops");
    }

    #[test]
    fn drain_rejects_then_wait_for_inflight() {
        init_test("drain_rejects_then_wait_for_inflight");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let manager = ConnectionManager::new(None, signal);

            // Register a connection before shutdown
            let g1 = manager.register(test_addr(1)).expect("register");
            let count = manager.active_count();
            crate::assert_with_log!(count == 1, "one active", 1, count);

            // Begin drain
            let began = manager.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "drain started", true, began);

            // New connections should be rejected
            let g2 = manager.register(test_addr(2));
            let rejected = g2.is_none();
            crate::assert_with_log!(rejected, "rejected during drain", true, rejected);

            // Existing connection still tracked
            let count = manager.active_count();
            crate::assert_with_log!(count == 1, "in-flight still active", 1, count);

            // Drop the in-flight connection from a thread
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                drop(g1);
            });

            // Wait for all to close
            manager.wait_all_closed().await;

            let empty = manager.is_empty();
            crate::assert_with_log!(empty, "drained", true, empty);

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("drain_rejects_then_wait_for_inflight");
    }

    #[test]
    fn full_server_lifecycle() {
        init_test("full_server_lifecycle");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let manager = ConnectionManager::new(Some(100), signal.clone());

            // Phase 1: Accept connections
            let guards: Vec<_> = (0..5)
                .filter_map(|i| manager.register(test_addr(8080 + i)))
                .collect();
            let count = manager.active_count();
            crate::assert_with_log!(count == 5, "five connected", 5, count);

            // Phase 2: Begin drain
            let initiated = manager.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(initiated, "drain started", true, initiated);

            // New connections rejected
            let rejected = manager.register(test_addr(9000)).is_none();
            crate::assert_with_log!(rejected, "new conn rejected", true, rejected);

            // Phase 3: In-flight connections complete (simulate from thread)
            let handle = std::thread::spawn(move || {
                // Simulate gradual connection completion
                for guard in guards {
                    std::thread::sleep(Duration::from_millis(5));
                    drop(guard);
                }
            });

            // Wait for all to close
            manager.wait_all_closed().await;

            let empty = manager.is_empty();
            crate::assert_with_log!(empty, "all drained", true, empty);

            // Phase 4: Mark stopped
            let forced = signal.begin_force_close();
            crate::assert_with_log!(forced, "force close", true, forced);
            signal.mark_stopped();

            let stopped = signal.is_stopped();
            crate::assert_with_log!(stopped, "stopped", true, stopped);

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("full_server_lifecycle");
    }

    #[test]
    fn drain_with_stats_empty() {
        init_test("drain_with_stats_empty");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let manager = ConnectionManager::new(None, signal.clone());

            // Begin drain with no active connections
            let began = manager.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "drain started", true, began);

            let stats = manager.drain_with_stats().await;

            let drained = stats.drained;
            crate::assert_with_log!(drained == 0, "zero drained", 0, drained);

            let fc = stats.force_closed;
            crate::assert_with_log!(fc == 0, "zero force-closed", 0, fc);

            // Should have transitioned to Stopped
            let stopped = signal.is_stopped();
            crate::assert_with_log!(stopped, "stopped", true, stopped);
        });
        crate::test_complete!("drain_with_stats_empty");
    }

    #[test]
    fn drain_with_stats_all_drained() {
        init_test("drain_with_stats_all_drained");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let manager = ConnectionManager::new(None, signal.clone());

            // Register 3 connections
            let g1 = manager.register(test_addr(1)).expect("register 1");
            let g2 = manager.register(test_addr(2)).expect("register 2");
            let g3 = manager.register(test_addr(3)).expect("register 3");

            // Begin drain with generous timeout
            let began = manager.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "drain started", true, began);

            // Drop all connections from a thread (simulating graceful close)
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                drop(g1);
                std::thread::sleep(Duration::from_millis(10));
                drop(g2);
                std::thread::sleep(Duration::from_millis(10));
                drop(g3);
            });

            let stats = manager.drain_with_stats().await;

            let drained = stats.drained;
            crate::assert_with_log!(drained == 3, "three drained", 3, drained);

            let fc = stats.force_closed;
            crate::assert_with_log!(fc == 0, "zero force-closed", 0, fc);

            let stopped = signal.is_stopped();
            crate::assert_with_log!(stopped, "stopped", true, stopped);

            let phase = signal.phase();
            let is_stopped = phase == ShutdownPhase::Stopped;
            crate::assert_with_log!(is_stopped, "phase stopped", "Stopped", phase);

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("drain_with_stats_all_drained");
    }

    #[test]
    fn drain_with_stats_timeout_force_close() {
        init_test("drain_with_stats_timeout_force_close");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let manager = ConnectionManager::new(None, signal.clone());

            // Register 3 connections — only 1 will close before timeout
            let g1 = manager.register(test_addr(1)).expect("register 1");
            let _g2 = manager.register(test_addr(2)).expect("register 2");
            let _g3 = manager.register(test_addr(3)).expect("register 3");

            // Very short drain timeout so it expires quickly
            let began = manager.begin_drain(Duration::from_millis(50));
            crate::assert_with_log!(began, "drain started", true, began);

            // Drop one connection quickly, leave two lingering
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                drop(g1);
            });

            let stats = manager.drain_with_stats().await;

            // 1 drained gracefully, 2 force-closed
            let drained = stats.drained;
            crate::assert_with_log!(drained == 1, "one drained", 1, drained);

            let fc = stats.force_closed;
            crate::assert_with_log!(fc == 2, "two force-closed", 2, fc);

            // Should have transitioned to ForceClosing
            let phase = signal.phase();
            let is_force = phase == ShutdownPhase::ForceClosing;
            crate::assert_with_log!(is_force, "phase force-closing", "ForceClosing", phase);

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("drain_with_stats_timeout_force_close");
    }

    #[test]
    fn drain_with_stats_timeout_uses_injected_shutdown_clock() {
        init_test("drain_with_stats_timeout_uses_injected_shutdown_clock");
        set_test_time(0);

        let signal = ShutdownSignal::with_time_getter(test_time);
        let manager = ConnectionManager::with_time_getter(None, signal.clone(), test_time);
        let _guard = manager.register(test_addr(1)).expect("register");

        let began = manager.begin_drain(Duration::from_millis(50));
        crate::assert_with_log!(began, "drain started", true, began);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut drain = Box::pin(manager.drain_with_stats());

        crate::assert_with_log!(
            matches!(drain.as_mut().poll(&mut cx), Poll::Pending),
            "drain future initially pending",
            true,
            true
        );

        set_test_time(
            Duration::from_millis(60)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );

        let poll = drain.as_mut().poll(&mut cx);
        let completed = matches!(poll, Poll::Ready(_));
        crate::assert_with_log!(
            completed,
            "drain completes once injected clock passes deadline",
            true,
            completed
        );
        let Poll::Ready(stats) = poll else {
            return;
        };

        crate::assert_with_log!(stats.drained == 0, "zero drained", 0, stats.drained);
        crate::assert_with_log!(
            stats.force_closed == 1,
            "one force-closed",
            1,
            stats.force_closed
        );
        crate::assert_with_log!(
            stats.duration == Duration::from_millis(60),
            "duration uses injected shutdown clock",
            Duration::from_millis(60),
            stats.duration
        );
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::ForceClosing,
            "phase force-closing",
            ShutdownPhase::ForceClosing,
            signal.phase()
        );
        crate::test_complete!("drain_with_stats_timeout_uses_injected_shutdown_clock");
    }

    #[test]
    fn drain_with_stats_counts_connections_closed_before_future_started() {
        init_test("drain_with_stats_counts_connections_closed_before_future_started");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let manager = ConnectionManager::new(None, signal.clone());

            let g1 = manager.register(test_addr(1)).expect("register 1");
            let g2 = manager.register(test_addr(2)).expect("register 2");
            let g3 = manager.register(test_addr(3)).expect("register 3");

            let began = manager.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "drain started", true, began);

            drop(g1);
            drop(g2);

            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                drop(g3);
            });

            let stats = manager.drain_with_stats().await;
            crate::assert_with_log!(stats.drained == 3, "three drained", 3, stats.drained);
            crate::assert_with_log!(
                stats.force_closed == 0,
                "zero force-closed",
                0,
                stats.force_closed
            );
            crate::assert_with_log!(
                signal.phase() == ShutdownPhase::Stopped,
                "phase stopped",
                ShutdownPhase::Stopped,
                signal.phase()
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("drain_with_stats_counts_connections_closed_before_future_started");
    }

    #[test]
    fn drain_with_stats_treats_immediate_trigger_as_force_close() {
        init_test("drain_with_stats_treats_immediate_trigger_as_force_close");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal.clone());

        let _g1 = manager.register(test_addr(1)).expect("register 1");
        let _g2 = manager.register(test_addr(2)).expect("register 2");

        signal.trigger_immediate();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut drain = Box::pin(manager.drain_with_stats());
        let poll = drain.as_mut().poll(&mut cx);
        let ready = matches!(poll, Poll::Ready(_));
        crate::assert_with_log!(
            ready,
            "immediate trigger returns without grace wait",
            true,
            ready
        );
        let Poll::Ready(stats) = poll else {
            return;
        };

        crate::assert_with_log!(stats.drained == 0, "zero drained", 0, stats.drained);
        crate::assert_with_log!(
            stats.force_closed == 2,
            "two force-closed",
            2,
            stats.force_closed
        );
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::ForceClosing,
            "phase force-closing",
            ShutdownPhase::ForceClosing,
            signal.phase()
        );
    }

    #[test]
    fn concurrent_register_respects_capacity() {
        init_test("concurrent_register_respects_capacity");
        let signal = ShutdownSignal::new();
        let manager = Arc::new(ConnectionManager::new(Some(5), signal));

        let barrier = Arc::new(std::sync::Barrier::new(11));
        let successes = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();
        for i in 0..10 {
            let m = Arc::clone(&manager);
            let b = Arc::clone(&barrier);
            let s = Arc::clone(&successes);
            handles.push(std::thread::spawn(move || {
                b.wait();
                if let Some(_guard) = m.register(test_addr(9000 + i)) {
                    s.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // Hold the guard alive until thread exits
                    std::thread::sleep(Duration::from_millis(100));
                }
            }));
        }

        barrier.wait();
        for h in handles {
            h.join().expect("thread panicked");
        }

        let total = successes.load(std::sync::atomic::Ordering::Relaxed);
        crate::assert_with_log!(total <= 5, "capacity not exceeded", "<=5", total);
        crate::test_complete!("concurrent_register_respects_capacity");
    }

    #[test]
    fn begin_drain_closes_acceptance_gate() {
        init_test("begin_drain_closes_acceptance_gate");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal.clone());

        let began = manager.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "drain started", true, began);

        let rejected = manager.register(test_addr(1)).is_none();
        crate::assert_with_log!(
            rejected,
            "register rejected after begin_drain",
            true,
            rejected
        );

        let draining = signal.is_draining();
        crate::assert_with_log!(draining, "signal entered draining", true, draining);
        crate::test_complete!("begin_drain_closes_acceptance_gate");
    }

    #[test]
    fn guard_drop_notifies_all_closed() {
        init_test("guard_drop_notifies_all_closed");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal);

        let guard = manager.register(test_addr(1)).expect("register");
        let count_before = manager.active_count();
        crate::assert_with_log!(count_before == 1, "one active", 1, count_before);

        // Drop guard - this should remove from HashMap and notify
        drop(guard);

        let count_after = manager.active_count();
        crate::assert_with_log!(count_after == 0, "none after drop", 0, count_after);
        let empty = manager.is_empty();
        crate::assert_with_log!(empty, "is empty", true, empty);
        crate::test_complete!("guard_drop_notifies_all_closed");
    }

    // --- wave 78 trait coverage ---

    #[test]
    fn connection_id_debug_clone_copy_eq_ord_hash() {
        use std::collections::HashSet;
        let id = ConnectionId(42);
        let id2 = id; // Copy
        let id3 = id;
        assert_eq!(id, id2);
        assert_eq!(id, id3);
        assert_ne!(id, ConnectionId(99));
        assert!(id < ConnectionId(100));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("42"));
        let mut set = HashSet::new();
        set.insert(id);
        assert!(set.contains(&id2));
    }

    #[test]
    fn connection_info_debug_clone() {
        let info = ConnectionInfo {
            addr: test_addr(9090),
            connected_at: Time::from_nanos(42),
            last_activity_nanos: Arc::new(AtomicU64::new(42)),
        };
        let info2 = info.clone();
        assert_eq!(info.addr, info2.addr);
        assert_eq!(info.connected_at, info2.connected_at);
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ConnectionInfo"));
    }

    #[test]
    fn connection_manager_time_getter_controls_connected_at() {
        init_test("connection_manager_time_getter_controls_connected_at");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::with_time_getter(None, signal, test_time);

        set_test_time(7);
        let _g1 = manager.register(test_addr(1)).expect("first register");
        let active = manager.active_connections();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].1.connected_at, Time::from_nanos(7));

        set_test_time(42);
        let _g2 = manager.register(test_addr(2)).expect("second register");
        let active = manager.active_connections();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].1.connected_at, Time::from_nanos(7));
        assert_eq!(active[1].1.connected_at, Time::from_nanos(42));
        crate::test_complete!("connection_manager_time_getter_controls_connected_at");
    }

    // ====================================================================
    // br-asupersync-f46twu + br-asupersync-368gxk: per-IP cap + idle
    // timeout regression tests. Both verify the rejection-of-attacker
    // surface plus the legitimate-slow-client preservation surface.
    // ====================================================================

    fn ipv4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([a, b, c, d], port))
    }

    #[test]
    fn f46twu_per_ip_cap_rejects_third_connection_from_same_ip() {
        init_test("f46twu_per_ip_cap_rejects_third_connection_from_same_ip");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(Some(100), signal).with_per_ip_max(Some(2));

        let attacker = ipv4(10, 0, 0, 1, 0);
        let _g1 = manager
            .register(ipv4(10, 0, 0, 1, 12345))
            .expect("first ok");
        let _g2 = manager
            .register(ipv4(10, 0, 0, 1, 12346))
            .expect("second ok");
        // Third from the same IP rejected by per-IP cap, even though
        // the global pool has 98 slots free.
        assert!(manager.register(attacker).is_none());
        assert_eq!(manager.active_count(), 2);
    }

    #[test]
    fn f46twu_per_ip_cap_does_not_punish_distinct_ips() {
        init_test("f46twu_per_ip_cap_does_not_punish_distinct_ips");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(Some(100), signal).with_per_ip_max(Some(2));

        // Cap is per-IP, so each of these distinct IPs should get
        // their own quota independently.
        let _g1 = manager.register(ipv4(10, 0, 0, 1, 1)).expect("ip1 a");
        let _g2 = manager.register(ipv4(10, 0, 0, 1, 2)).expect("ip1 b");
        let _g3 = manager.register(ipv4(10, 0, 0, 2, 1)).expect("ip2 a");
        let _g4 = manager.register(ipv4(10, 0, 0, 2, 2)).expect("ip2 b");
        let _g5 = manager.register(ipv4(10, 0, 0, 3, 1)).expect("ip3 a");
        assert_eq!(manager.active_count(), 5);
    }

    #[test]
    fn f46twu_per_ip_cap_decrements_on_drop() {
        init_test("f46twu_per_ip_cap_decrements_on_drop");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal).with_per_ip_max(Some(2));

        let g1 = manager.register(ipv4(10, 0, 0, 1, 1)).expect("first");
        let g2 = manager.register(ipv4(10, 0, 0, 1, 2)).expect("second");
        assert!(manager.register(ipv4(10, 0, 0, 1, 3)).is_none());
        drop(g1);
        // After one drops, a new registration succeeds — the per-IP
        // counter decremented and the slot is reusable.
        let _g4 = manager.register(ipv4(10, 0, 0, 1, 4)).expect("post-drop");
        drop(g2);
        // After both drop, the per_ip map removes the entry entirely
        // (zero-value cleanup).
        let snap = manager.per_ip_snapshot();
        assert_eq!(snap.len(), 1, "only one IP remaining: {snap:?}");
    }

    #[test]
    fn f46twu_unbounded_per_ip_default_preserves_legacy_behaviour() {
        init_test("f46twu_unbounded_per_ip_default_preserves_legacy_behaviour");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(Some(100), signal); // no with_per_ip_max

        // Without a per-IP cap, a single IP can take the whole pool.
        let mut guards = Vec::new();
        for port in 1..=50 {
            guards.push(manager.register(ipv4(10, 0, 0, 1, port)).expect("ok"));
        }
        assert_eq!(manager.active_count(), 50);
    }

    #[test]
    fn _368gxk_drop_idle_lists_connections_past_timeout() {
        init_test("368gxk_drop_idle_lists_connections_past_timeout");
        let signal = ShutdownSignal::new();
        set_test_time(0);
        let manager = ConnectionManager::with_time_getter(None, signal, test_time)
            .with_idle_timeout(Some(Duration::from_secs(60)));

        let g1 = manager.register(test_addr(1)).expect("g1");
        let _g2 = manager.register(test_addr(2)).expect("g2");
        let _g3 = manager.register(test_addr(3)).expect("g3");

        // Advance virtual time past the timeout for all three. None
        // of them have called touch(), so all should be flagged.
        set_test_time(120 * 1_000_000_000); // 120s in nanos
        let idle = manager.drop_idle_connections();
        assert_eq!(idle.len(), 3, "all three idle past 60s: {idle:?}");

        // touch() the first guard at t=120s and re-scan — it should
        // no longer be idle.
        g1.touch();
        let idle = manager.drop_idle_connections();
        assert_eq!(idle.len(), 2, "after touch g1 is fresh: {idle:?}");
        assert!(!idle.contains(&g1.id()));
    }

    #[test]
    fn _368gxk_drop_idle_returns_empty_when_disabled() {
        init_test("368gxk_drop_idle_returns_empty_when_disabled");
        let signal = ShutdownSignal::new();
        set_test_time(0);
        let manager = ConnectionManager::with_time_getter(None, signal, test_time);
        // No idle_timeout configured → drop_idle is a no-op even
        // after a long elapsed virtual time.
        let _g1 = manager.register(test_addr(1)).expect("g1");
        set_test_time(3600 * 1_000_000_000);
        assert!(manager.drop_idle_connections().is_empty());
    }

    #[test]
    fn _368gxk_min_grace_floors_aggressive_timeout() {
        init_test("368gxk_min_grace_floors_aggressive_timeout");
        let signal = ShutdownSignal::new();
        set_test_time(0);
        // Misconfigured: 1ms idle timeout would close every TCP
        // handshake mid-flight in the real world. The MIN_IDLE_GRACE
        // floor protects against that — connections get at least 5s
        // before the manager can flag them idle.
        let manager = ConnectionManager::with_time_getter(None, signal, test_time)
            .with_idle_timeout(Some(Duration::from_millis(1)));
        let _g1 = manager.register(test_addr(1)).expect("g1");

        // 1 second elapsed: NOT yet idle because grace floor is 5s.
        set_test_time(1_000_000_000);
        assert!(manager.drop_idle_connections().is_empty(), "1s < 5s floor");

        // 6 seconds elapsed: now past the floor.
        set_test_time(6_000_000_000);
        let idle = manager.drop_idle_connections();
        assert_eq!(idle.len(), 1, "past 5s floor: {idle:?}");
    }

    #[test]
    fn _368gxk_clock_step_backwards_does_not_flag_world_idle() {
        init_test("368gxk_clock_step_backwards_does_not_flag_world_idle");
        let signal = ShutdownSignal::new();
        set_test_time(1_000_000_000_000); // 1000s
        let manager = ConnectionManager::with_time_getter(None, signal, test_time)
            .with_idle_timeout(Some(Duration::from_secs(60)));
        let _g1 = manager.register(test_addr(1)).expect("g1");
        // Clock steps backwards (NTP). Saturating subtraction means
        // the elapsed time is 0, so nothing is flagged idle.
        set_test_time(500_000_000_000);
        assert!(manager.drop_idle_connections().is_empty());
    }

    #[test]
    fn batch_per_ip_and_idle_compose_cleanly() {
        init_test("batch_per_ip_and_idle_compose_cleanly");
        let signal = ShutdownSignal::new();
        set_test_time(0);
        let manager = ConnectionManager::with_time_getter(Some(64), signal, test_time)
            .with_per_ip_max(Some(2))
            .with_idle_timeout(Some(Duration::from_secs(30)));

        let attacker_ip = ipv4(10, 0, 0, 1, 1);
        let _g1 = manager.register(attacker_ip).expect("g1");
        let _g2 = manager.register(ipv4(10, 0, 0, 1, 2)).expect("g2");
        // Per-IP cap kicks in.
        assert!(manager.register(ipv4(10, 0, 0, 1, 3)).is_none());

        // Distinct IP still admitted.
        let _g4 = manager.register(ipv4(10, 0, 0, 2, 1)).expect("g4");

        // Time advances past idle threshold for all.
        set_test_time(31 * 1_000_000_000);
        let idle = manager.drop_idle_connections();
        assert_eq!(idle.len(), 3);
    }
}
