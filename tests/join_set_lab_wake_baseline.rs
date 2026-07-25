//! Baseline: child tasks and `JoinSet::join_all` are wake-correct under the
//! deterministic lab scheduler.
//!
//! Bead: asupersync-dx-core-api-v2-u1z5hn.5
//!
//! These two cases bound the `join_next` liveness bug (`asupersync-tncxj9`).
//! They establish that the lab harness itself drives child tasks correctly and
//! that `drain_all` keeps its wakers registered, so the `join_next` hang cannot
//! be dismissed as a harness limitation.
//!
//! Keep these green. If one of them ever starts hanging, the conclusion in
//! `asupersync-tncxj9` no longer holds and the bug needs re-diagnosing rather
//! than re-confirming.

#![allow(missing_docs)]

use asupersync::combinator::JoinSet;
use asupersync::lab::run_async_under_lab;

#[test]
fn a_single_spawned_child_completes_under_the_lab_harness() {
    let (joined, report) = run_async_under_lab(1, |cx| async move {
        let mut handle = cx
            .spawn_in(&cx.scope(), |_cx| async move { Ok::<u32, ()>(7) })
            .expect("spawn child");
        format!("{:?}", handle.join(&cx).await)
    });

    assert!(
        joined.contains("Ok(7)"),
        "child task must complete under the lab: {joined}"
    );
    assert!(report.quiescent, "lab must reach quiescence");
    assert!(report.invariant_violations.is_empty());
}

#[test]
fn join_all_is_wake_correct_under_the_lab_scheduler() {
    let (collected, report) = run_async_under_lab(4, |cx| async move {
        let mut set: JoinSet<'static, u32, (), _> = JoinSet::in_cx(&cx);
        for member in 0..3u32 {
            set.spawn(&cx, move |_cx| async move { Ok(member) })
                .expect("spawn member");
        }
        set.join_all(&cx).await.len()
    });

    assert_eq!(collected, 3, "join_all must collect every member");
    assert!(
        report.quiescent,
        "join_all holds its join futures, so wakers stay registered"
    );
    assert!(report.invariant_violations.is_empty());
}
