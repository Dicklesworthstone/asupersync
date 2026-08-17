//! Regression coverage for two runtime-teardown/entry contracts:
//!
//! 1. Bounded shutdown (#60): ordinary `Runtime` drop joins worker threads
//!    without a bound, so a future that blocks inside `poll` wedges runtime
//!    destruction forever. `Runtime::shutdown_timeout` / `shutdown_background`
//!    are the bounded alternatives and must return within their bound even
//!    when a worker never comes back.
//!
//! 2. Nested/re-entrant current-thread `block_on` (#56): timers registered by
//!    a future polled under a nested `rt_b.block_on(...)` (entered from inside
//!    another runtime's `block_on`, then re-entered on the same runtime) must
//!    still fire; the park loop must pump the innermost registration set
//!    instead of parking forever.
//!
//! The blocked-worker tests intentionally leak a detached worker thread (it
//! is parked on a channel that never receives); that is the exact scenario
//! the bounded API exists for, and the leaked thread holds only its own
//! runtime's retained state.

use asupersync::runtime::RuntimeBuilder;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Run `f` on a helper thread and wait at most `limit` for its result.
///
/// `None` means `f` itself failed to finish inside `limit` — i.e. the API
/// under test blocked, which is exactly what these regressions guard against.
fn bounded<T: Send + 'static>(
    limit: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).ok()
}

/// Build a runtime with one spawned task that is blocked inside `poll` on a
/// channel that never receives, and prove the task has entered that state.
fn runtime_with_blocked_worker() -> asupersync::runtime::Runtime {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build runtime");
    let (started_tx, started_rx) = mpsc::channel();
    let (never_tx, never_rx) = mpsc::channel::<()>();
    // Keep the sender alive forever so the blocking recv never disconnects.
    std::mem::forget(never_tx);
    runtime.handle().spawn(async move {
        started_tx.send(()).expect("signal task start");
        // Deliberate contract violation: blocking recv inside poll.
        let _ = never_rx.recv();
    });
    started_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("task entered its blocking poll");
    runtime
}

#[test]
fn shutdown_timeout_returns_false_within_bound_for_blocked_worker() {
    let outcome = bounded(Duration::from_secs(10), || {
        let runtime = runtime_with_blocked_worker();
        let start = Instant::now();
        let clean = runtime.shutdown_timeout(Duration::from_millis(100));
        (clean, start.elapsed())
    });
    let (clean, elapsed) = outcome.expect("shutdown_timeout must not block past its bound");
    assert!(
        !clean,
        "a permanently blocked worker cannot produce a clean shutdown"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "shutdown_timeout(100ms) took {elapsed:?}"
    );
}

#[test]
fn shutdown_background_returns_immediately_for_blocked_worker() {
    let outcome = bounded(Duration::from_secs(10), || {
        let runtime = runtime_with_blocked_worker();
        let start = Instant::now();
        runtime.shutdown_background();
        start.elapsed()
    });
    let elapsed = outcome.expect("shutdown_background must not block");
    assert!(
        elapsed < Duration::from_secs(5),
        "shutdown_background took {elapsed:?}"
    );
}

#[test]
fn shutdown_timeout_reports_clean_teardown_for_cooperative_runtime() {
    let outcome = bounded(Duration::from_secs(30), || {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        let value = runtime.block_on(runtime.handle().spawn(async { 41_u32 + 1 }));
        assert_eq!(value, 42);
        runtime.shutdown_timeout(Duration::from_secs(20))
    });
    assert_eq!(
        outcome,
        Some(true),
        "a cooperative runtime must tear down cleanly inside a generous bound"
    );
}

#[test]
fn reentrant_current_thread_block_on_fires_inner_timer() {
    // #56 topology: thread T runs rt_a.block_on(f); f enters rt_b.block_on(g);
    // g re-enters rt_b.block_on(h); h awaits a short timeout. The inner timer
    // must fire instead of the innermost park loop sleeping forever.
    let outcome = bounded(Duration::from_secs(30), || {
        let rt_a = RuntimeBuilder::current_thread().build().expect("rt_a");
        let rt_b = RuntimeBuilder::current_thread().build().expect("rt_b");
        let start = Instant::now();
        rt_a.block_on(async {
            rt_b.block_on(async {
                rt_b.block_on(async {
                    let _ = asupersync::time::timeout(
                        asupersync::time::wall_now(),
                        Duration::from_millis(25),
                        std::future::pending::<()>(),
                    )
                    .await;
                });
            });
        });
        start.elapsed()
    });
    let elapsed =
        outcome.expect("nested block_on parked forever instead of firing the inner timer");
    assert!(
        elapsed >= Duration::from_millis(20),
        "inner timeout fired implausibly early: {elapsed:?}"
    );
}
