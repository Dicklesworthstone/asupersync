//! Regression tests for GH#56: nested/re-entrant current-thread
//! `Runtime::block_on` must still fire timers registered by the inner
//! future instead of parking forever.
//!
//! Topology from the issue (found via mcp_agent_mail_rust#203):
//! thread T runs `rt_a.block_on(f)`; while polling `f`, code enters
//! `rt_b.block_on(g)` on the same thread, and inside `g`'s poll the same
//! `rt_b.block_on(h)` is re-entered once more. `h` awaits
//! `asupersync::time::timeout(wall_now(), 25ms, <pending>)`.
//!
//! Each scenario runs on a scratch thread with a watchdog so a regression
//! shows up as a test failure with a clear message instead of a hung test
//! binary.
//!
//! The `block_on_back_into_the_outer_runtime_*` tests cover re-entry into an
//! outer runtime (A -> B -> A, br-asupersync-kopidb H2): the innermost call
//! must drive rt_a's worker, which the outer drive parked on this thread.

#![allow(missing_docs)]

use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{timeout, wall_now};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const INNER_TIMEOUT: Duration = Duration::from_millis(25);
/// Generous watchdog: the inner timeout is 25ms, so several seconds means
/// the timer never fired (permanent park), not a slow CI machine.
const WATCHDOG: Duration = Duration::from_secs(20);

/// Await a 25ms timeout around a never-ready future and return how long the
/// await actually took. If timers are being pumped this returns quickly; if
/// the block_on loop lost the registration it never returns.
async fn await_inner_timeout() -> Duration {
    let start = Instant::now();
    let res = timeout(wall_now(), INNER_TIMEOUT, std::future::pending::<()>()).await;
    assert!(
        res.is_err(),
        "pending future cannot complete: must be Elapsed"
    );
    start.elapsed()
}

/// Run `scenario` on a scratch thread; fail (not hang) if it doesn't finish
/// within the watchdog window.
fn run_with_watchdog(name: &str, scenario: impl FnOnce() -> Duration + Send + 'static) {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name(format!("repro-{name}"))
        .spawn(move || {
            // If the scenario panics, drop(tx) makes recv_timeout return
            // Disconnected instead of Timeout.
            let elapsed = scenario();
            let _ = tx.send(elapsed);
        })
        .expect("spawn scenario thread");

    match rx.recv_timeout(WATCHDOG) {
        Ok(elapsed) => {
            // The timeout must have actually elapsed (not fired early).
            assert!(
                elapsed >= INNER_TIMEOUT,
                "{name}: timeout fired after {elapsed:?}, before the {INNER_TIMEOUT:?} deadline"
            );
        }
        Err(mpsc::RecvTimeoutError::Timeout) => panic!(
            "{name}: inner {INNER_TIMEOUT:?} timeout never fired within {WATCHDOG:?} — \
             nested block_on parked permanently (GH#56 regression)"
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{name}: scenario thread panicked before reporting")
        }
    }
}

/// Baseline: a single (non-nested) current-thread block_on fires the timer.
#[test]
fn single_block_on_fires_timeout() {
    run_with_watchdog("single", || {
        let rt = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        rt.block_on(await_inner_timeout())
    });
}

/// Two levels, two distinct runtimes: rt_a.block_on(f) where f's poll enters
/// rt_b.block_on(h) and h awaits the timeout.
#[test]
fn nested_block_on_two_runtimes_fires_timeout() {
    run_with_watchdog("two-level", || {
        let rt_a = RuntimeBuilder::current_thread()
            .build()
            .expect("build rt_a");
        let rt_b = RuntimeBuilder::current_thread()
            .build()
            .expect("build rt_b");
        rt_a.block_on(async { rt_b.block_on(await_inner_timeout()) })
    });
}

/// Full GH#56 topology: rt_a.block_on(f) -> rt_b.block_on(g) -> the SAME
/// rt_b.block_on(h) re-entered from inside g's poll; h awaits the timeout.
#[test]
fn reentrant_block_on_same_runtime_fires_timeout() {
    run_with_watchdog("three-level-reentrant", || {
        let rt_a = RuntimeBuilder::current_thread()
            .build()
            .expect("build rt_a");
        let rt_b = RuntimeBuilder::current_thread()
            .build()
            .expect("build rt_b");
        rt_a.block_on(async { rt_b.block_on(async { rt_b.block_on(await_inner_timeout()) }) })
    });
}

/// Re-entrant block_on on a single runtime with no outer foreign runtime:
/// rt.block_on(f) where f's poll re-enters rt.block_on(h).
#[test]
fn reentrant_block_on_single_runtime_fires_timeout() {
    run_with_watchdog("two-level-same-rt", || {
        let rt = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        rt.block_on(async { rt.block_on(await_inner_timeout()) })
    });
}

/// Exact fastmcp construction: the inner runtime is a current-thread runtime
/// with a platform I/O reactor attached (fastmcp-core/src/runtime.rs), and it
/// is re-entered once from inside its own block_on, all nested under a host
/// runtime's block_on (`run_transport_returning*` consumers).
#[test]
fn reentrant_block_on_with_reactor_fires_timeout() {
    run_with_watchdog("three-level-reactor", || {
        let rt_a = RuntimeBuilder::current_thread()
            .build()
            .expect("build rt_a");
        let reactor =
            asupersync::runtime::reactor::create_reactor().expect("create platform reactor");
        let rt_b = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("build rt_b");
        rt_a.block_on(async { rt_b.block_on(async { rt_b.block_on(await_inner_timeout()) }) })
    });
}

/// Run `scenario` on a scratch thread and return its value; fail (not hang)
/// if it does not finish within the watchdog window.
fn value_within_watchdog<T: Send + 'static>(
    name: &str,
    scenario: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name(format!("repro-{name}"))
        .spawn(move || {
            let _ = tx.send(scenario());
        })
        .expect("spawn scenario thread");
    match rx.recv_timeout(WATCHDOG) {
        Ok(value) => value,
        Err(mpsc::RecvTimeoutError::Timeout) => panic!(
            "{name}: nested block_on did not finish within {WATCHDOG:?}; the inner call \
             could not drive the outer runtime's worker parked on this thread"
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{name}: scenario thread panicked before reporting")
        }
    }
}

/// A -> B -> A: a root of rt_a enters rt_b.block_on, whose root enters
/// rt_a.block_on again. rt_a's worker is parked on this thread by the outer
/// drive, so the inner call must drive it (nothing else can) to run the task
/// it joins.
#[test]
fn block_on_back_into_the_outer_runtime_joins_its_task() {
    let value = value_within_watchdog("a-b-a-join", || {
        let rt_a = RuntimeBuilder::current_thread()
            .build()
            .expect("build rt_a");
        let rt_b = RuntimeBuilder::current_thread()
            .build()
            .expect("build rt_b");
        rt_a.block_on(async {
            rt_b.block_on(async { rt_a.block_on(rt_a.handle().spawn(async { 7_u32 })) })
        })
    });
    assert_eq!(value, 7);
}

/// A -> B -> A with a `!Send` task the outer rt_a root queued before entering
/// rt_b: the inner rt_a call admits and polls it on this thread.
#[test]
fn block_on_back_into_the_outer_runtime_joins_a_local_task_of_its_root() {
    let value = value_within_watchdog("a-b-a-local", || {
        let rt_a = RuntimeBuilder::current_thread()
            .build()
            .expect("build rt_a");
        let rt_b = RuntimeBuilder::current_thread()
            .build()
            .expect("build rt_b");
        rt_a.block_on(async {
            let local = rt_a.spawn_local(async { *std::rc::Rc::new(11_u32) });
            rt_b.block_on(async { rt_a.block_on(local) })
                .expect("the local task completes")
        })
    });
    assert_eq!(value, 11);
}

/// A -> B -> A with a timer awaited by the innermost root.
#[test]
fn block_on_back_into_the_outer_runtime_fires_timeout() {
    run_with_watchdog("a-b-a-timeout", || {
        let rt_a = RuntimeBuilder::current_thread()
            .build()
            .expect("build rt_a");
        let rt_b = RuntimeBuilder::current_thread()
            .build()
            .expect("build rt_b");
        rt_a.block_on(async { rt_b.block_on(async { rt_a.block_on(await_inner_timeout()) }) })
    });
}
