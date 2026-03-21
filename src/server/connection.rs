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
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

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
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Remote peer address.
    pub addr: SocketAddr,
    /// When the connection was accepted.
    pub connected_at: Time,
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
            time_getter,
            shutdown_signal,
            all_closed: Arc::new(Notify::new()),
            drain_initial_count: Arc::new(AtomicUsize::new(DRAIN_COUNT_UNSET)),
        }
    }

    /// Registers a new connection.
    ///
    /// Returns a [`ConnectionGuard`] that automatically deregisters the connection
    /// when dropped. Returns `None` if the server is at capacity or shutting down.
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

        // Check capacity
        if let Some(max) = self.max_connections {
            if connections.len() >= max {
                return None;
            }
        }

        let id = ConnectionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let info = ConnectionInfo {
            addr,
            connected_at: (self.time_getter)(),
        };
        connections.insert(id, info);
        drop(connections);

        Some(ConnectionGuard {
            id,
            state: Arc::clone(&self.state),
            all_closed: Arc::clone(&self.all_closed),
        })
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
pub struct ConnectionGuard {
    id: ConnectionId,
    state: Arc<Mutex<HashMap<ConnectionId, ConnectionInfo>>>,
    all_closed: Arc<Notify>,
}

impl ConnectionGuard {
    /// Returns the connection ID.
    #[must_use]
    pub const fn id(&self) -> ConnectionId {
        self.id
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut connections = self.state.lock();
        connections.remove(&self.id);
        // Notify on every removal so drain_with_stats can re-check deadlines.
        // wait_all_closed loops on is_empty(), so extra wakeups are harmless.
        drop(connections);
        self.all_closed.notify_waiters();
    }
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
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    static TEST_NOW: AtomicU64 = AtomicU64::new(0);

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

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
        Waker::from(Arc::new(NoopWake))
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
}
