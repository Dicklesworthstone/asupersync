//! Runtime concurrency proof for `join!` / `join_all!` (u1z5hn.6 AC1 + AC3 join-arity).
//!
//! The original `join!` expansion awaited its branches **sequentially**, silently
//! serializing every caller. The fix (committed earlier under this bead) rewrote the
//! expansion to a single concurrent `poll_fn` that pins each branch once and re-polls
//! only the not-yet-ready branches per wake. The token-shape unit tests in
//! `src/join.rs` pin the *structure*; this file pins the *observable behavior*: under
//! the lab's virtual clock, N concurrent `sleep`s of duration D complete in D, not
//! N*D.
//!
//! The proof is discriminating by construction — the same three 10ms sleeps awaited
//! sequentially are shown to take 30ms in the identical harness, so a regression back
//! to serialized awaits would flip the concurrent assertions from 10ms to 30ms.
//!
//! Determinism is virtual-time: `cx.now()` reads the lab `VirtualClock`, `sleep` uses
//! the ambient lab timer driver, and `LabConfig::with_auto_advance` jumps the clock to
//! the next pending timer deadline whenever every task is parked. No wall-clock, no
//! flake.

#![allow(missing_docs)]

use asupersync::cx::Cx;
use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::time::sleep;
use asupersync::types::Budget;
use asupersync_macros::{join, join_all};
use std::future::Future;
use std::time::Duration;

/// Nanoseconds per millisecond — the lab clock counts nanos.
const MS: u64 = 1_000_000;

/// Drives `fut` to completion inside a fresh auto-advancing lab runtime and returns
/// its output. Virtual time advances across timer parks, so any `sleep` inside `fut`
/// resolves deterministically against the lab clock.
fn run_scenario<T, Fut>(seed: u64, fut: Fut) -> T
where
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let mut lab = LabRuntime::new(LabConfig::new(seed).with_auto_advance());
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut handle) = lab
        .state
        .create_task(root, Budget::INFINITE, fut)
        .expect("create lab task");
    lab.scheduler.lock().schedule(task, 0);
    let _report = lab.run_with_auto_advance();

    let violations = lab.check_invariants();
    assert!(
        violations.is_empty(),
        "lab invariants violated during join! scenario: {violations:?}"
    );

    match handle.try_join() {
        Ok(Some(value)) => value,
        Ok(None) => panic!("join! scenario remained pending after auto-advance"),
        Err(err) => panic!("join! scenario join failed: {err:?}"),
    }
}

/// Returns the virtual nanoseconds elapsed while awaiting three uniform sleeps via
/// `join!`. Concurrent => one sleep duration; serialized => three.
async fn join_three_uniform(d: Duration) -> u64 {
    let cx = Cx::current().expect("lab task context");
    let start = cx.now();
    join!(cx; sleep(cx.now(), d), sleep(cx.now(), d), sleep(cx.now(), d));
    cx.now().duration_since(start)
}

/// The serialized baseline: the exact same three sleeps awaited one-by-one. Proves the
/// harness measures serialization, so the concurrent assertions are meaningful.
async fn sequential_three_uniform(d: Duration) -> u64 {
    let cx = Cx::current().expect("lab task context");
    let start = cx.now();
    sleep(cx.now(), d).await;
    sleep(cx.now(), d).await;
    sleep(cx.now(), d).await;
    cx.now().duration_since(start)
}

/// Three sleeps with distinct deadlines joined concurrently. Concurrent `join!`
/// completes at the **max** deadline, not the **sum**.
async fn join_three_staggered(a: Duration, b: Duration, c: Duration) -> u64 {
    let cx = Cx::current().expect("lab task context");
    let start = cx.now();
    join!(cx; sleep(cx.now(), a), sleep(cx.now(), b), sleep(cx.now(), c));
    cx.now().duration_since(start)
}

async fn join_two_uniform(d: Duration) -> u64 {
    let cx = Cx::current().expect("lab task context");
    let start = cx.now();
    join!(cx; sleep(cx.now(), d), sleep(cx.now(), d));
    cx.now().duration_since(start)
}

async fn join_five_uniform(d: Duration) -> u64 {
    let cx = Cx::current().expect("lab task context");
    let start = cx.now();
    join!(
        cx;
        sleep(cx.now(), d),
        sleep(cx.now(), d),
        sleep(cx.now(), d),
        sleep(cx.now(), d),
        sleep(cx.now(), d)
    );
    cx.now().duration_since(start)
}

async fn join_eight_uniform(d: Duration) -> u64 {
    let cx = Cx::current().expect("lab task context");
    let start = cx.now();
    join!(
        cx;
        sleep(cx.now(), d),
        sleep(cx.now(), d),
        sleep(cx.now(), d),
        sleep(cx.now(), d),
        sleep(cx.now(), d),
        sleep(cx.now(), d),
        sleep(cx.now(), d),
        sleep(cx.now(), d)
    );
    cx.now().duration_since(start)
}

/// The `join_all!` array form must be concurrent for the same reason as `join!`.
async fn join_all_three_uniform(d: Duration) -> u64 {
    let cx = Cx::current().expect("lab task context");
    let start = cx.now();
    let _outcomes: [(); 3] =
        join_all!(cx; sleep(cx.now(), d), sleep(cx.now(), d), sleep(cx.now(), d));
    cx.now().duration_since(start)
}

#[test]
fn join_three_uniform_sleeps_complete_concurrently() {
    let elapsed = run_scenario(0, join_three_uniform(Duration::from_millis(10)));
    assert_eq!(
        elapsed,
        10 * MS,
        "three concurrent 10ms sleeps must finish in 10ms virtual time, \
         not 30ms — this is the sequential-join regression guard"
    );
}

#[test]
fn sequential_three_sleeps_take_the_sum_proving_harness_discriminates() {
    let elapsed = run_scenario(0, sequential_three_uniform(Duration::from_millis(10)));
    assert_eq!(
        elapsed,
        30 * MS,
        "serialized awaits of the same three 10ms sleeps must sum to 30ms — \
         confirms the harness would catch a join! that fell back to sequential awaits"
    );
}

#[test]
fn join_completes_at_max_deadline_not_the_sum() {
    let elapsed = run_scenario(
        0,
        join_three_staggered(
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(30),
        ),
    );
    assert_eq!(
        elapsed,
        30 * MS,
        "join! over 10/20/30ms branches must resolve at the longest deadline (30ms)"
    );
    assert!(
        elapsed < 60 * MS,
        "a serialized join! would have summed to 60ms; got {elapsed}ns"
    );
}

#[test]
fn join_is_concurrent_across_arities_2_3_5_8() {
    let d = Duration::from_millis(10);
    assert_eq!(run_scenario(0, join_two_uniform(d)), 10 * MS, "arity 2");
    assert_eq!(run_scenario(0, join_three_uniform(d)), 10 * MS, "arity 3");
    assert_eq!(run_scenario(0, join_five_uniform(d)), 10 * MS, "arity 5");
    assert_eq!(run_scenario(0, join_eight_uniform(d)), 10 * MS, "arity 8");
}

#[test]
fn join_all_array_form_is_concurrent() {
    let elapsed = run_scenario(0, join_all_three_uniform(Duration::from_millis(10)));
    assert_eq!(
        elapsed,
        10 * MS,
        "join_all! array form must be concurrent like join!"
    );
}

#[test]
fn join_concurrency_is_seed_independent() {
    let d = Duration::from_millis(10);
    for seed in 0..6 {
        assert_eq!(
            run_scenario(seed, join_three_uniform(d)),
            10 * MS,
            "join! virtual-time concurrency must be identical for seed {seed}"
        );
    }
}
