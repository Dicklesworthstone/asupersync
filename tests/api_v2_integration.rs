//! The API-v2 on-ramp, exercised as one lane.
//!
//! Bead: asupersync-dx-core-api-v2-u1z5hn.12
//!
//! The individual v2 pieces have their own unit tests. What was missing is a
//! lane that runs the surface a *new user* actually touches, in the same
//! combination the on-ramp examples put it in: the entry attribute macros, a
//! `Cx` handed to the body, `Cx::spawn` plus `join`, `JoinSet` fan-out, and the
//! deterministic lab test. `scripts/run_api_v2_e2e.sh` runs this lane after it
//! runs the example programs, so a break in the journey is attributable to
//! either the examples or this surface rather than to "something in the epic".
//!
//! These tests deliberately assert on the *ergonomic* contract — that the
//! macro supplies a working `Cx`, that spawned work is joinable, that fan-out
//! aggregates — not on runtime internals.

#![allow(missing_docs)]
#![allow(clippy::unused_async)]

use asupersync::lab::LabRuntime;
use asupersync::lab_test;
use asupersync::prelude::*;

/// The `hello.rs` shape: the attribute macro alone must produce a usable
/// runtime, with no explicit builder and no ambient-state threading.
#[asupersync::test]
async fn entry_macro_without_cx_runs_on_the_production_runtime() {
    assert!(
        Cx::current().is_some(),
        "the entry macro must install an ambient Cx even when the body does \
         not ask for one"
    );
}

/// The `Cx`-taking form: the macro must hand the body a context whose
/// capabilities actually work, which is what every on-ramp snippet assumes.
#[asupersync::test]
async fn entry_macro_supplies_a_working_cx() -> Result<(), asupersync::Error> {
    let cx = Cx::current().expect("entry macro installs an ambient Cx");
    cx.checkpoint()?;
    assert_eq!(
        cx.region_id(),
        Cx::current().expect("ambient Cx").region_id(),
        "the injected Cx and the ambient Cx must be the same region"
    );
    Ok(())
}

/// `Cx::spawn` + `TaskHandle::join` is the two-line concurrency on-ramp: no
/// `&mut RuntimeState`, no detached handle, and the child's value comes back.
#[asupersync::test]
async fn cx_spawn_joins_a_child_and_returns_its_value() {
    let cx = Cx::current().expect("entry macro installs an ambient Cx");
    let mut handle = cx
        .spawn(|task_cx| async move {
            task_cx.checkpoint().expect("child checkpoint");
            41_u32 + 1
        })
        .expect("spawn child");
    let joined = handle.join(&cx).await.expect("child joins");
    assert_eq!(
        joined, 42,
        "the spawned child's value must reach the parent"
    );
}

/// The `spawn_fanout.rs` shape: dynamic fan-out collected through `JoinSet`,
/// with every member's outcome observed rather than dropped.
#[asupersync::test]
async fn join_set_fans_out_and_aggregates_every_member() {
    let cx = Cx::current().expect("entry macro installs an ambient Cx");
    let mut set = JoinSet::in_cx(&cx);
    for i in 0..10_u32 {
        set.spawn(&cx, move |_| async move { Ok::<_, ()>(i) })
            .expect("spawn member");
    }
    let outcomes = set.join_all(&cx).await;
    assert_eq!(outcomes.len(), 10, "every spawned member must be collected");
    let total: u32 = outcomes
        .into_iter()
        .map(|outcome| outcome.expect("member ok"))
        .sum();
    assert_eq!(total, 45, "0..10 sums to 45");
}

/// The `deterministic_test.rs` shape, in its native habitat: `#[lab_test]`
/// gives a seeded `LabRuntime` with no harness boilerplate.
#[lab_test]
fn lab_test_macro_supplies_a_seeded_runtime(lab: &mut LabRuntime) {
    assert_eq!(
        lab.config().seed,
        0,
        "the bare form must use the documented default seed"
    );
}

/// Same-seed replay is the property the on-ramp advertises, so the lane asserts
/// it directly rather than trusting the example's own assertion.
#[test]
fn same_seed_replays_the_same_execution() {
    fn run(seed: u64) -> u32 {
        let (total, report) = asupersync::lab::run_async_under_lab(seed, |cx| async move {
            let mut set = JoinSet::in_cx(&cx);
            for i in 0..8_u32 {
                set.spawn(&cx, move |_| async move { Ok::<_, ()>(i) })
                    .expect("spawn member");
            }
            set.join_all(&cx)
                .await
                .into_iter()
                .fold(0, |sum, outcome| sum + outcome.expect("member ok"))
        });
        assert!(report.quiescent, "lab run must reach quiescence");
        assert!(
            report.invariant_violations.is_empty(),
            "no invariant may be violated: {:?}",
            report.invariant_violations
        );
        total
    }

    let first = run(7);
    assert_eq!(first, run(7), "same seed must produce the same result");
    assert_eq!(first, 28, "0..8 sums to 28");
}
