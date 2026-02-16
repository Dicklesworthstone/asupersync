//! E2E: Signal handling under load — graceful shutdown, drain in-flight,
//! ShutdownController coordination, multiple receivers, double shutdown.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use asupersync::signal::{ShutdownController, SignalKind};

// =========================================================================
// Phase 1: Graceful shutdown with in-flight work
// =========================================================================

#[test]
fn e2e_graceful_shutdown_drain_inflight() {
    common::init_test_logging();
    test_phase!("Graceful Shutdown with In-Flight Work");

    let controller = ShutdownController::new();
    let completed = Arc::new(AtomicUsize::new(0));

    // Simulate 5 "in-flight" workers
    test_section!("Start workers");
    let mut handles = Vec::new();
    for i in 0..5 {
        let rx = controller.subscribe();
        let completed = Arc::clone(&completed);
        handles.push(thread::spawn(move || {
            // Simulate work
            thread::sleep(Duration::from_millis(10 + i * 5));
            // Check if shutdown was requested
            if rx.is_shutting_down() {
                tracing::debug!(worker = i, "worker saw shutdown, finishing up");
            }
            completed.fetch_add(1, Ordering::SeqCst);
        }));
    }

    test_section!("Initiate shutdown");
    thread::sleep(Duration::from_millis(20)); // Let some workers start
    controller.shutdown();
    assert!(controller.is_shutting_down());

    test_section!("Wait for drain");
    for h in handles {
        h.join().expect("worker panicked");
    }

    let total = completed.load(Ordering::SeqCst);
    tracing::info!(completed = total, "all workers drained");
    assert_eq!(total, 5);

    test_complete!("e2e_graceful_shutdown", workers_completed = total);
}

// =========================================================================
// Phase 2: Double shutdown is idempotent
// =========================================================================

#[test]
fn e2e_double_shutdown_idempotent() {
    common::init_test_logging();
    test_phase!("Double Shutdown");

    let controller = ShutdownController::new();
    let rx = controller.subscribe();

    assert!(!controller.is_shutting_down());

    test_section!("First shutdown");
    controller.shutdown();
    assert!(controller.is_shutting_down());
    assert!(rx.is_shutting_down());

    test_section!("Second shutdown (no-op)");
    controller.shutdown();
    assert!(controller.is_shutting_down());
    assert!(rx.is_shutting_down());

    test_section!("Third shutdown (still no-op)");
    controller.shutdown();
    assert!(controller.is_shutting_down());

    test_complete!("e2e_double_shutdown");
}

// =========================================================================
// Phase 3: Multiple receivers all notified
// =========================================================================

#[test]
fn e2e_multi_receiver_notification() {
    common::init_test_logging();
    test_phase!("Multi-Receiver Notification");

    let controller = ShutdownController::new();
    let notified = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    test_section!("Subscribe 10 receivers");
    for i in 0..10 {
        let rx = controller.subscribe();
        let notified = Arc::clone(&notified);
        handles.push(thread::spawn(move || {
            // Busy-wait for shutdown (since we can't async poll in threads easily)
            while !rx.is_shutting_down() {
                thread::sleep(Duration::from_millis(1));
            }
            notified.fetch_add(1, Ordering::SeqCst);
            tracing::debug!(receiver = i, "notified");
        }));
    }

    test_section!("Trigger shutdown");
    thread::sleep(Duration::from_millis(10)); // Let receivers start polling
    controller.shutdown();

    test_section!("Verify all notified");
    for h in handles {
        h.join().expect("receiver panicked");
    }
    let total = notified.load(Ordering::SeqCst);
    assert_eq!(total, 10);
    tracing::info!(receivers_notified = total, "all receivers saw shutdown");

    test_complete!("e2e_multi_receiver", receivers = total);
}

// =========================================================================
// Phase 4: Shutdown from cloned controller
// =========================================================================

#[test]
fn e2e_shutdown_from_clone() {
    common::init_test_logging();
    test_phase!("Shutdown From Clone");

    let controller = ShutdownController::new();
    let clone = controller.clone();
    let rx = controller.subscribe();

    test_section!("Shutdown via clone");
    clone.shutdown();

    assert!(controller.is_shutting_down());
    assert!(clone.is_shutting_down());
    assert!(rx.is_shutting_down());

    test_complete!("e2e_shutdown_from_clone");
}

// =========================================================================
// Phase 5: Receiver subscribed after shutdown
// =========================================================================

#[test]
fn e2e_late_subscriber_sees_shutdown() {
    common::init_test_logging();
    test_phase!("Late Subscriber");

    let controller = ShutdownController::new();
    controller.shutdown();

    test_section!("Subscribe after shutdown");
    let rx = controller.subscribe();
    assert!(rx.is_shutting_down());

    test_complete!("e2e_late_subscriber");
}

// =========================================================================
// Phase 6: Concurrent shutdown from multiple threads
// =========================================================================

#[test]
fn e2e_concurrent_shutdown_calls() {
    common::init_test_logging();
    test_phase!("Concurrent Shutdown Calls");

    let controller = Arc::new(ShutdownController::new());
    let rx = controller.subscribe();

    test_section!("Race 10 shutdown calls");
    let mut handles = Vec::new();
    for _ in 0..10 {
        let c = Arc::clone(&controller);
        handles.push(thread::spawn(move || {
            c.shutdown();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert!(controller.is_shutting_down());
    assert!(rx.is_shutting_down());

    test_complete!("e2e_concurrent_shutdown");
}

// =========================================================================
// Phase 7: Signal kind enumeration (API surface)
// =========================================================================

#[test]
fn e2e_signal_kind_variants() {
    common::init_test_logging();
    test_phase!("Signal Kind Variants");

    let kinds = [
        SignalKind::interrupt(),
        SignalKind::terminate(),
        SignalKind::hangup(),
        SignalKind::quit(),
        SignalKind::user_defined1(),
        SignalKind::user_defined2(),
        SignalKind::child(),
        SignalKind::window_change(),
        SignalKind::pipe(),
        SignalKind::alarm(),
    ];

    for kind in &kinds {
        tracing::debug!(kind = ?kind, "signal kind available");
    }
    assert_eq!(kinds.len(), 10);

    test_complete!("e2e_signal_kinds", count = kinds.len());
}
