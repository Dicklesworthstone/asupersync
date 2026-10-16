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
    static TEST_TIME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn set_test_time(nanos: u64) {
        TEST_NOW.store(nanos, Ordering::Relaxed);
    }

    fn lock_test_time() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_TIME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set_test_time(0);
        guard
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
        let _time_guard = lock_test_time();
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
    fn drain_with_stats_retains_force_close_snapshot_after_guards_drop() {
        init_test("drain_with_stats_retains_force_close_snapshot_after_guards_drop");
        crate::test_utils::run_test(|| async {
            struct ReentrantConnectionWaker {
                manager: ConnectionManager,
                woke: std::sync::atomic::AtomicBool,
            }

            impl std::task::Wake for ReentrantConnectionWaker {
                fn wake(self: Arc<Self>) {
                    self.wake_by_ref();
                }

                fn wake_by_ref(self: &Arc<Self>) {
                    let _ = self.manager.active_count();
                    self.woke.store(true, Ordering::Release);
                }
            }

            let signal = ShutdownSignal::new();
            let manager = ConnectionManager::new(None, signal.clone());

            let g1 = manager.register(test_addr(1)).expect("register 1");
            let g2 = manager.register(test_addr(2)).expect("register 2");
            let began = manager.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "drain started", true, began);

            let reentrant = Arc::new(ReentrantConnectionWaker {
                manager: manager.clone(),
                woke: std::sync::atomic::AtomicBool::new(false),
            });
            let waker = Waker::from(Arc::clone(&reentrant));
            let mut context = Context::from_waker(&waker);
            let mut force_close = Box::pin(signal.wait_for_phase(ShutdownPhase::ForceClosing));
            let pending = force_close.as_mut().poll(&mut context).is_pending();
            crate::assert_with_log!(pending, "force-close waiter registered", true, pending);

            manager.force_close();
            crate::assert_with_log!(
                reentrant.woke.load(Ordering::Acquire),
                "force-close wake can reenter connection manager",
                true,
                reentrant.woke.load(Ordering::Acquire)
            );
            let ready = force_close.as_mut().poll(&mut context).is_ready();
            crate::assert_with_log!(ready, "force-close waiter observes transition", true, ready);
            drop(g1);
            drop(g2);

            let stats = manager.drain_with_stats().await;
            crate::assert_with_log!(stats.drained == 0, "zero drained", 0, stats.drained);
            crate::assert_with_log!(
                stats.force_closed == 2,
                "force-close snapshot retained after deregistration",
                2,
                stats.force_closed
            );
            crate::assert_with_log!(
                signal.phase() == ShutdownPhase::ForceClosing,
                "phase force-closing",
                ShutdownPhase::ForceClosing,
                signal.phase()
            );
        });
        crate::test_complete!("drain_with_stats_retains_force_close_snapshot_after_guards_drop");
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
        let _time_guard = lock_test_time();
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
        let _time_guard = lock_test_time();
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
        let _time_guard = lock_test_time();
        let signal = ShutdownSignal::new();
        set_test_time(0);
        let manager = ConnectionManager::with_time_getter(None, signal, test_time);
        // No idle_timeout configured → drop_idle is a no-op even
        // after a long elapsed virtual time.
        let _g1 = manager.register(test_addr(1)).expect("g1");
        set_test_time(3600 * 1_000_000_000);
        assert!(manager.drop_idle_connections().is_empty());
    }

    /// A timeout past u64 nanoseconds (~584 years) never flags a
    /// connection. The truncating cast made 18_446_744_074 s a threshold
    /// of about 0.29 s.
    #[test]
    fn idle_timeout_past_u64_nanos_never_flags_a_connection() {
        init_test("idle_timeout_past_u64_nanos_never_flags_a_connection");
        let _time_guard = lock_test_time();
        let signal = ShutdownSignal::new();
        set_test_time(0);
        let manager = ConnectionManager::with_time_getter(None, signal, test_time)
            .with_idle_timeout(Some(Duration::from_secs(18_446_744_074)));
        let _g1 = manager.register(test_addr(1)).expect("g1");
        set_test_time(10 * 1_000_000_000);
        assert!(manager.drop_idle_connections().is_empty());
    }

    #[test]
    fn _368gxk_min_grace_floors_aggressive_timeout() {
        init_test("368gxk_min_grace_floors_aggressive_timeout");
        let _time_guard = lock_test_time();
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
        let _time_guard = lock_test_time();
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
        let _time_guard = lock_test_time();
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

    /// Review r28-e8 of f42354543 (C4-M1): `begin_force_close` on a server
    /// that is not draining refuses without side effects. It used to close
    /// admission and record a force-close count before the signal refused, so a
    /// running server dropped every new connection while reporting `Running`,
    /// and a later drain that timed out counted graceful closes as force-closed.
    #[test]
    fn begin_force_close_on_a_running_server_changes_nothing() {
        init_test("begin_force_close_on_a_running_server_changes_nothing");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal.clone());
        let early = manager.register(test_addr(1)).expect("register 1");

        let forced = manager.begin_force_close();
        crate::assert_with_log!(!forced, "refused while running", false, forced);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Running,
            "still running",
            ShutdownPhase::Running,
            signal.phase()
        );
        let admitted = manager.register(test_addr(2));
        crate::assert_with_log!(
            admitted.is_some(),
            "still accepting",
            true,
            admitted.is_some()
        );
        let unset = manager.force_close_initial_count.load(Ordering::Acquire) == DRAIN_COUNT_UNSET;
        crate::assert_with_log!(unset, "no force-close count recorded", true, unset);
        drop(admitted);
        drop(early);
        crate::test_complete!("begin_force_close_on_a_running_server_changes_nothing");
    }

    #[test]
    fn drain_with_stats_retains_force_close_snapshot_via_begin_force_close() {
        init_test("drain_with_stats_retains_force_close_snapshot_via_begin_force_close");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let manager = ConnectionManager::new(None, signal.clone());

            let g1 = manager.register(test_addr(1)).expect("register 1");
            let g2 = manager.register(test_addr(2)).expect("register 2");
            let began = manager.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "drain started", true, began);

            // Escalation via manager.begin_force_close() snapshots under registry lock
            let forced = manager.begin_force_close();
            crate::assert_with_log!(forced, "force-close transitioned", true, forced);

            // Now connection guards drop after force-close transition
            drop(g1);
            drop(g2);

            let stats = manager.drain_with_stats().await;
            crate::assert_with_log!(stats.drained == 0, "zero drained", 0, stats.drained);
            crate::assert_with_log!(
                stats.force_closed == 2,
                "force-close snapshot retained after deregistration via begin_force_close",
                2,
                stats.force_closed
            );
            crate::assert_with_log!(
                signal.phase() == ShutdownPhase::ForceClosing,
                "phase force-closing",
                ShutdownPhase::ForceClosing,
                signal.phase()
            );
        });
        crate::test_complete!("drain_with_stats_retains_force_close_snapshot_via_begin_force_close");
    }

    #[test]
    fn drain_wakes_on_phase_notify_when_deadline_stored_after_phase_switch() {
        init_test("drain_wakes_on_phase_notify_when_deadline_stored_after_phase_switch");
        let signal = ShutdownSignal::new();
        let manager = ConnectionManager::new(None, signal.clone());
        let _g1 = manager.register(test_addr(1)).expect("g1");

        // Simulate the race where phase is switched to Draining but deadline is not yet stored
        let switched = signal.state.phase.compare_exchange(
            ShutdownPhase::Running as u8,
            ShutdownPhase::Draining as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        crate::assert_with_log!(switched.is_ok(), "phase switched", true, switched.is_ok());

        // Spawn drain_with_stats in background
        let drain_mgr = manager.clone();
        let stats_slot = std::sync::Arc::new(std::sync::Mutex::new(None));
        let stats_ret = std::sync::Arc::clone(&stats_slot);
        let drain_handle = std::thread::spawn(move || {
            crate::test_utils::run_test(|| async move {
                let stats = drain_mgr.drain_with_stats().await;
                *stats_ret.lock().unwrap() = Some(stats);
            })
        });

        // Brief pause to allow drain_with_stats to enter wait_for_drain and register phase_notified
        std::thread::sleep(Duration::from_millis(15));

        // Now store the deadline and notify phase_notify
        let now = signal.current_time();
        let deadline = now.saturating_add_nanos(50_000_000); // 50ms
        signal.state.drain_deadline.store(deadline.as_nanos(), Ordering::Release);
        signal.state.has_drain_deadline.store(true, Ordering::Release);
        signal.state.phase_notify.notify_waiters();

        // The background drain should observe the deadline and complete force-closing
        drain_handle.join().expect("drain thread panicked");
        let stats = stats_slot.lock().unwrap().take().expect("stats recorded");
        crate::assert_with_log!(
            stats.force_closed == 1,
            "force closed after deadline",
            1,
            stats.force_closed
        );
        crate::test_complete!("drain_wakes_on_phase_notify_when_deadline_stored_after_phase_switch");
    }
