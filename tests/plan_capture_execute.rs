//! Differential proof for tjrmwz.1: a captured plan executes *identically* to
//! the equivalent direct combinator nesting, for each law-sheet node kind.
//!
//! These run reactor-free under `futures_lite::future::block_on`: every leaf is
//! immediately ready, so the first poll resolves the whole tree (no parking).
//! Run with `--features test-internals` (for `Cx::for_testing`).

#![cfg(feature = "test-internals")]

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use asupersync::Cx;
use asupersync::plan::execute::{
    NodeId, PlanCapture, PlanExecError, PlanValue, capture, capture_optimized,
};
use asupersync::plan::{PlanNode, RewriteRule};
use futures_lite::future::block_on;

// ---------------------------------------------------------------------------
// Per-kind capture == direct combinator (Acceptance Criteria 1)
// ---------------------------------------------------------------------------

#[test]
fn leaf_executes_to_scalar() {
    let cx = Cx::for_testing();
    let plan = capture(|p| p.leaf(async { 42u32 })).expect("valid");
    let got = block_on(plan.execute_scalar(&cx)).expect("ok");
    assert_eq!(got, 42);
}

#[test]
fn race_matches_direct_cx_race() {
    let cx = Cx::for_testing();

    let captured = block_on(
        capture(|p| {
            let a = p.leaf(async { 1u32 });
            let b = p.leaf(async { 2u32 });
            p.race([a, b])
        })
        .expect("valid")
        .execute_scalar(&cx),
    )
    .expect("ok");

    // Direct: the exact engine `Cx::race` drives (SelectAll), index 0 wins.
    let futs: Vec<Pin<Box<dyn Future<Output = u32> + Send>>> =
        vec![Box::pin(async { 1u32 }), Box::pin(async { 2u32 })];
    let direct: u32 = block_on(cx.race(futs)).expect("race ok");

    assert_eq!(captured, direct);
    assert_eq!(captured, 1);
}

#[test]
fn join_matches_direct_join_macro() {
    let cx = Cx::for_testing();

    let captured = block_on(
        capture(|p| {
            let a = p.leaf(async { 10u32 });
            let b = p.leaf(async { 20u32 });
            let c = p.leaf(async { 30u32 });
            p.join([a, b, c])
        })
        .expect("valid")
        .execute_all(&cx),
    )
    .expect("ok");

    // Direct: the `join!` macro — concurrent, input-order tuple.
    let (x, y, z) =
        block_on(async { asupersync::join!(async { 10u32 }, async { 20u32 }, async { 30u32 }) });

    assert_eq!(captured, vec![x, y, z]);
    assert_eq!(captured, vec![10, 20, 30]);
}

#[test]
fn timeout_success_matches_direct_time_timeout() {
    let cx = Cx::for_testing();
    let dur = Duration::from_secs(60);

    let captured = block_on(
        capture(|p| {
            let c = p.leaf(async { 7u32 });
            p.timeout(c, dur)
        })
        .expect("valid")
        .execute_scalar(&cx),
    )
    .expect("ok");

    // Direct: the same `crate::time::timeout` the interpreter reuses.
    let now = cx.now();
    let direct =
        block_on(asupersync::time::timeout(now, dur, async { 7u32 })).expect("not elapsed");

    assert_eq!(captured, direct);
    assert_eq!(captured, 7);
}

#[test]
fn first_ok_returns_first_success_in_order() {
    let cx = Cx::for_testing();

    let captured = block_on(
        capture(|p| {
            let a = p.leaf(async { 0u32 }); // fails predicate
            let b = p.leaf(async { 5u32 }); // first success
            let c = p.leaf(async { 9u32 });
            p.first_ok([a, b, c], |v: &u32| *v > 0)
        })
        .expect("valid")
        .execute_scalar(&cx),
    )
    .expect("ok");

    assert_eq!(captured, 5);
}

#[test]
fn first_ok_exhausted_when_no_success() {
    let cx = Cx::for_testing();
    let plan = capture(|p| {
        let a = p.leaf(async { 0u32 });
        let b = p.leaf(async { 0u32 });
        p.first_ok([a, b], |v: &u32| *v > 0)
    })
    .expect("valid");
    let err = block_on(plan.execute(&cx)).expect_err("should fail");
    assert!(matches!(err, PlanExecError::FirstOkExhausted { .. }));
}

#[test]
fn quorum_collects_successes_when_threshold_met() {
    let cx = Cx::for_testing();

    let captured = block_on(
        capture(|p| {
            let positive_one = p.leaf(async { 1u32 });
            let zero_one = p.leaf(async { 0u32 });
            let positive_three = p.leaf(async { 3u32 });
            let zero_two = p.leaf(async { 0u32 });
            let positive_five = p.leaf(async { 5u32 });
            p.quorum(
                [
                    positive_one,
                    zero_one,
                    positive_three,
                    zero_two,
                    positive_five,
                ],
                2,
                |v: &u32| *v > 0,
            )
        })
        .expect("valid")
        .execute_all(&cx),
    )
    .expect("ok");

    assert_eq!(captured, vec![1, 3, 5]);
}

#[test]
fn quorum_not_met_reports_shortfall() {
    let cx = Cx::for_testing();
    let plan = capture(|p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 0u32 });
        let c = p.leaf(async { 0u32 });
        p.quorum([a, b, c], 2, |v: &u32| *v > 0)
    })
    .expect("valid");
    let err = block_on(plan.execute(&cx)).expect_err("should fail");
    assert!(matches!(
        err,
        PlanExecError::QuorumNotMet {
            achieved: 1,
            required: 2,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// Nested worked example: race(join(a, b), timeout(d, c))  (the bead's example)
// ---------------------------------------------------------------------------

#[test]
fn nested_race_of_join_and_timeout() {
    let cx = Cx::for_testing();
    let plan = capture(|p| {
        let left = p.leaf(async { 1u32 });
        let right = p.leaf(async { 2u32 });
        let joined = p.join([left, right]);
        let timed_leaf = p.leaf(async { 3u32 });
        let timed = p.timeout(timed_leaf, Duration::from_secs(60));
        p.race([joined, timed])
    })
    .expect("valid");

    // Both subtrees are ready; SelectAll polls index 0 (the join) first.
    let got = block_on(plan.execute(&cx)).expect("ok");
    assert_eq!(got, PlanValue::Vector(vec![1, 2]));
}

// ---------------------------------------------------------------------------
// Loser drain / cancellation: race drops losers without running them (AC2)
// ---------------------------------------------------------------------------

#[test]
fn race_drops_losers_without_completing_them() {
    let cx = Cx::for_testing();
    let loser_ran = Rc::new(Cell::new(false));
    let flag = loser_ran.clone();

    let plan = capture(move |p| {
        let winner = p.leaf(async { 0u32 });
        let loser = p.leaf(async move {
            // Only observed if the interpreter runs the loser to completion.
            flag.set(true);
            99u32
        });
        p.race([winner, loser])
    })
    .expect("valid");

    let got = block_on(plan.execute_scalar(&cx)).expect("ok");
    assert_eq!(got, 0);
    assert!(
        !loser_ran.get(),
        "loser future must be dropped (cancelled), not run to completion"
    );
}

// ---------------------------------------------------------------------------
// Structural re-emission for the rewrite engine (try_structure)
// ---------------------------------------------------------------------------

#[test]
fn try_structure_emits_plandag_for_core_kinds() {
    let plan = capture(|p| {
        let left = p.leaf(async { 1u32 });
        let right = p.leaf(async { 2u32 });
        let joined = p.join([left, right]);
        let timed_leaf = p.leaf(async { 3u32 });
        let timed = p.timeout(timed_leaf, Duration::from_secs(1));
        p.race([joined, timed])
    })
    .expect("valid");

    let dag = plan.try_structure().expect("core kinds are representable");
    assert_eq!(dag.node_count(), 6);
    assert!(matches!(
        dag.root().and_then(|id| dag.node(id)),
        Some(PlanNode::Race { .. })
    ));
    dag.validate().expect("emitted dag validates");
}

#[test]
fn try_structure_rejects_first_ok_and_quorum() {
    let first_ok_plan = capture(|p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        p.first_ok([a, b], |v: &u32| *v > 0)
    })
    .expect("valid");
    assert!(matches!(
        first_ok_plan.try_structure(),
        Err(PlanExecError::NotRepresentable { .. })
    ));

    let quorum_plan = capture(|p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        p.quorum([a, b], 1, |v: &u32| *v > 0)
    })
    .expect("valid");
    assert!(matches!(
        quorum_plan.try_structure(),
        Err(PlanExecError::NotRepresentable { .. })
    ));
}

// ---------------------------------------------------------------------------
// Capture-time validation (structural errors fail before execution)
// ---------------------------------------------------------------------------

#[test]
fn finish_requires_a_root() {
    let mut b: PlanCapture<u32> = PlanCapture::new();
    let _ = b.leaf(async { 1u32 });
    assert!(matches!(b.finish(), Err(PlanExecError::MissingRoot)));
}

#[test]
fn shared_child_is_rejected() {
    // `ExecPlan` cannot be `Debug` (it holds futures), so match instead of
    // `expect_err`.
    let result = capture(|p| {
        let a = p.leaf(async { 1u32 });
        p.join([a, a]) // one-shot leaf cannot be shared
    });
    assert!(matches!(result, Err(PlanExecError::SharedNode { .. })));
}

#[test]
fn empty_join_is_rejected() {
    let result = capture::<u32, _>(|p| p.join(Vec::<NodeId>::new()));
    assert!(matches!(result, Err(PlanExecError::EmptyChildren { .. })));
}

#[test]
fn invalid_quorum_threshold_is_rejected() {
    let result = capture(|p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        p.quorum([a, b], 3, |_: &u32| true) // 3 > 2 children
    });
    assert!(matches!(result, Err(PlanExecError::InvalidQuorum { .. })));
}

// ---------------------------------------------------------------------------
// Certified rewrite application (tjrmwz.2): capture_optimized fail-closed ladder
// ---------------------------------------------------------------------------

#[test]
fn capture_optimized_flattens_nested_join_with_certificate() {
    let cx = Cx::for_testing();
    // join(join(a, b), c) flattens to join(a, b, c) under conservative policy.
    let exec = block_on(capture_optimized(&cx, |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        let inner = p.join([a, b]);
        let c = p.leaf(async { 3u32 });
        p.join([inner, c])
    }))
    .expect("ok");

    assert!(exec.rewritten, "nested join must flatten");
    assert!(exec.fired_rules.contains(&RewriteRule::JoinAssoc));
    let cert = exec.certificate.expect("representable plan -> certificate");
    assert!(!cert.is_identity(), "a rule fired, so not identity");
    assert!(exec.fallback_reason.is_none());
    // Outcome is identical to the unrewritten plan (the equivalence guarantee).
    assert_eq!(exec.value, PlanValue::Vector(vec![1, 2, 3]));
}

#[test]
fn capture_optimized_identity_runs_original_with_reason() {
    let cx = Cx::for_testing();
    // A flat join has nothing to rewrite: identity certificate, original runs.
    let exec = block_on(capture_optimized(&cx, |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        p.join([a, b])
    }))
    .expect("ok");

    assert!(!exec.rewritten);
    assert!(exec.fired_rules.is_empty());
    assert!(exec.certificate.expect("representable").is_identity());
    assert!(exec.fallback_reason.is_some());
    assert_eq!(exec.value, PlanValue::Vector(vec![1, 2]));
}

#[test]
fn capture_optimized_first_ok_runs_directly_no_ir() {
    let cx = Cx::for_testing();
    let exec = block_on(capture_optimized(&cx, |p| {
        let a = p.leaf(async { 0u32 });
        let b = p.leaf(async { 7u32 });
        p.first_ok([a, b], |v: &u32| *v > 0)
    }))
    .expect("ok");

    assert!(!exec.rewritten);
    assert!(exec.certificate.is_none(), "first_ok has no structural IR");
    assert_eq!(exec.value, PlanValue::Scalar(7));
    assert!(exec.fallback_reason.unwrap().contains("first_ok"));
}

#[test]
fn capture_optimized_outcome_matches_unoptimized() {
    let cx = Cx::for_testing();
    // race(race(a, b), c) flattens to race(a, b, c); index-0 winner is identical.
    let optimized = block_on(capture_optimized(&cx, |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        let inner = p.race([a, b]);
        let c = p.leaf(async { 3u32 });
        p.race([inner, c])
    }))
    .expect("ok");

    let direct = block_on(
        capture(|p| {
            let a = p.leaf(async { 1u32 });
            let b = p.leaf(async { 2u32 });
            let inner = p.race([a, b]);
            let c = p.leaf(async { 3u32 });
            p.race([inner, c])
        })
        .expect("valid")
        .execute(&cx),
    )
    .expect("ok");

    assert_eq!(optimized.value, direct);
    assert_eq!(optimized.value, PlanValue::Scalar(1));
}
