//! Connection tracking and lifecycle management.
//!
//! Provides [`ConnectionManager`] for tracking active connections with capacity limits,
//! and [`ConnectionGuard`] for RAII-based connection deregistration.

use crate::server::shutdown::{ShutdownPhase, ShutdownSignal};
use crate::sync::Notify;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Unique identifier for a tracked connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub connected_at: Instant,
}

/// Internal state for the connection registry.
struct RegistryState {
    connections: HashMap<ConnectionId, ConnectionInfo>,
    next_id: AtomicU64,
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
pub struct ConnectionManager {
    state: Arc<Mutex<HashMap<ConnectionId, ConnectionInfo>>>,
    next_id: Arc<AtomicU64>,
    max_connections: Option<usize>,
    shutdown_signal: ShutdownSignal,
    all_closed: Arc<Notify>,
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
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            max_connections,
            shutdown_signal,
            all_closed: Arc::new(Notify::new()),
        }
    }

    /// Registers a new connection.
    ///
    /// Returns a [`ConnectionGuard`] that automatically deregisters the connection
    /// when dropped. Returns `None` if the server is at capacity or shutting down.
    #[must_use]
    pub fn register(&self, addr: SocketAddr) -> Option<ConnectionGuard> {
        // Reject new connections during shutdown
        if self.shutdown_signal.is_shutting_down() {
            return None;
        }

        let mut connections = self
            .state
            .lock()
            .expect("connection registry lock poisoned");

        // Check capacity
        if let Some(max) = self.max_connections {
            if connections.len() >= max {
                return None;
            }
        }

        let id = ConnectionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let info = ConnectionInfo {
            addr,
            connected_at: Instant::now(),
        };
        connections.insert(id, info);
        drop(connections);

        Some(ConnectionGuard {
            id,
            state: Arc::clone(&self.state),
            all_closed: Arc::clone(&self.all_closed),
        })
    }

    /// Returns the number of active connections.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.state
            .lock()
            .expect("connection registry lock poisoned")
            .len()
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
        self.state
            .lock()
            .expect("connection registry lock poisoned")
            .iter()
            .map(|(id, info)| (*id, info.clone()))
            .collect()
    }

    /// Waits until all connections have been closed.
    ///
    /// Returns immediately if there are no active connections.
    pub async fn wait_all_closed(&self) {
        loop {
            if self.is_empty() {
                return;
            }
            self.all_closed.notified().await;
        }
    }

    /// Returns the configured maximum connections.
    #[must_use]
    pub const fn max_connections(&self) -> Option<usize> {
        self.max_connections
    }

    /// Orchestrates a graceful drain with timeout, returning shutdown statistics.
    ///
    /// This method:
    /// 1. Records the active connection count at drain start
    /// 2. Waits for connections to close or the drain deadline to expire
    /// 3. If deadline expires, transitions to force-close phase
    /// 4. Returns [`ShutdownStats`] with drained vs force-closed counts
    ///
    /// The caller must have already called [`ShutdownSignal::begin_drain`] before
    /// calling this method. The caller is responsible for force-closing connections
    /// after this method transitions to `ForceClosing` phase.
    ///
    /// # Example
    ///
    /// ```ignore
    /// signal.begin_drain(Duration::from_secs(30));
    /// let stats = manager.drain_with_stats().await;
    /// signal.mark_stopped();
    /// println!("Drained: {}, Force-closed: {}", stats.drained, stats.force_closed);
    /// ```
    pub async fn drain_with_stats(&self) -> super::shutdown::ShutdownStats {
        let initial_count = self.active_count();

        if initial_count == 0 {
            self.shutdown_signal.mark_stopped();
            return self.shutdown_signal.collect_stats(0, 0);
        }

        // Wait for connections to close, checking the drain deadline periodically.
        // Since we don't have a timer in this module, we poll in a loop checking
        // both the connection count and the deadline.
        loop {
            if self.is_empty() {
                // All connections drained gracefully
                let drained = initial_count;
                self.shutdown_signal.mark_stopped();
                return self.shutdown_signal.collect_stats(drained, 0);
            }

            // Check if drain deadline has passed
            if let Some(deadline) = self.shutdown_signal.drain_deadline() {
                if std::time::Instant::now() >= deadline {
                    // Timeout expired — transition to force close
                    let remaining = self.active_count();
                    let drained = initial_count.saturating_sub(remaining);
                    let _ = self.shutdown_signal.begin_force_close();
                    return self.shutdown_signal.collect_stats(drained, remaining);
                }
            }

            // Wait for the next connection close notification
            self.all_closed.notified().await;
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
        let mut connections = self
            .state
            .lock()
            .expect("connection registry lock poisoned");
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
    use std::time::Duration;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
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
        let manager = ConnectionManager::new(None, signal.clone());

        let g1 = manager.register(test_addr(1));
        let has_g1 = g1.is_some();
        crate::assert_with_log!(has_g1, "accepted before shutdown", true, has_g1);

        let began = signal.begin_drain(Duration::from_secs(30));
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
        crate::test_complete!("active_connections_returns_info");
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
            let manager = ConnectionManager::new(None, signal.clone());

            // Register a connection before shutdown
            let g1 = manager.register(test_addr(1)).expect("register");
            let count = manager.active_count();
            crate::assert_with_log!(count == 1, "one active", 1, count);

            // Begin drain
            let began = signal.begin_drain(Duration::from_secs(30));
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
            let initiated = signal.begin_drain(Duration::from_secs(30));
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
            let began = signal.begin_drain(Duration::from_secs(30));
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
            let began = signal.begin_drain(Duration::from_secs(30));
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
            let began = signal.begin_drain(Duration::from_millis(50));
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
}
