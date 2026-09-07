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
use std::future::Future;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A teardown regression must not strand the test harness if destruction
/// deadlocks. This guard owns only the subprocess created by this test.
struct TeardownChild(Option<std::process::Child>);

impl Drop for TeardownChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut()
            && child.try_wait().ok().flatten().is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn last_runtime_owner_dropped_on_worker_finishes_without_self_join() {
    const NAME: &str = "last_runtime_owner_dropped_on_worker_finishes_without_self_join";
    const CHILD: &str = "ASUPERSYNC_LAST_OWNER_TEARDOWN_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let (stopped_tx, stopped_rx) = mpsc::channel();
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .blocking_threads(0, 0)
            .on_thread_stop(move || {
                stopped_tx
                    .send(std::thread::current().id())
                    .expect("teardown observer remains alive");
            })
            .build()
            .expect("build two-worker runtime");
        let owner = runtime.clone();
        let cx = runtime.request_cx_with_budget(asupersync::types::Budget::INFINITE);
        let (release_tx, mut release_rx) = asupersync::channel::oneshot::channel();
        let (parked_tx, parked_rx) = mpsc::channel();
        let (dropped_tx, dropped_rx) = mpsc::channel();
        let join = runtime.handle().spawn(async move {
            let mut parked_tx = Some(parked_tx);
            let mut release = std::pin::pin!(release_rx.recv(&cx));
            std::future::poll_fn(|context| {
                let result = release.as_mut().poll(context);
                if result.is_pending()
                    && let Some(sender) = parked_tx.take()
                {
                    sender
                        .send(std::thread::current().id())
                        .expect("parent observes the actual Pending boundary");
                }
                result
            })
            .await
            .expect("parent releases the parked owner");
            // The parent has already dropped its Runtime. This is the last
            // strong owner, and destruction happens inside an actual poll.
            drop(owner);
            dropped_tx.send(()).expect("report completed owner drop");
            42_u32
        });
        let worker = parked_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("task reached Pending before ownership transfer");
        assert_ne!(worker, std::thread::current().id());
        println!("last-owner: held Pending on {worker:?}");
        drop(runtime);
        release_tx.send_blocking(()).expect("release owned task");
        dropped_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("last owner drop must return without a self-join panic");
        let first = stopped_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("first worker exits its run loop");
        let second = stopped_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("second worker exits its run loop");
        assert_ne!(first, second, "both distinct workers must stop");
        assert!(
            join.is_finished(),
            "the owned task reaches a terminal result"
        );
        let mut join = std::pin::pin!(join);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert_eq!(join.as_mut().poll(&mut context), std::task::Poll::Ready(42));
        println!("last-owner: drop returned; task result=42; stopped workers=2");
        return;
    }

    let mut child = TeardownChild(Some(
        std::process::Command::new(std::env::current_exe().expect("current test executable"))
            .args(["--exact", NAME, "--nocapture"])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn owned teardown regression child"),
    ));
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            break;
        }
        assert!(Instant::now() < deadline, "owned teardown child timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("{stdout}");
    eprintln!("{stderr}");
    assert!(
        output.status.success(),
        "teardown child failed: {}",
        output.status
    );
    assert!(stdout.contains("1 passed; 0 failed; 0 ignored;"));
    assert!(stdout.contains("last-owner: held Pending on "));
    assert!(stdout.contains("last-owner: drop returned; task result=42; stopped workers=2"));
}

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
