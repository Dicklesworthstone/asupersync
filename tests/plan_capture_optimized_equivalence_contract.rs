//! Conformance contract for tjrmwz.2 (certified rewrite application): the
//! `plan::capture_optimized` entry point preserves outcomes (the
//! certified-*equivalence* guarantee — the whole point of the rewrite engine)
//! and its [`OptimizedExecution`] report obeys the fail-closed ladder's
//! postcondition invariants, across every rule reachable through capture under
//! the conservative policy (JoinAssoc, RaceAssoc, TimeoutMin).
//!
//! This complements `plan_capture_execute.rs` (which proves capture==direct per
//! kind, plus the success/identity/no-IR cases) by:
//!   * exercising the previously-untested **TimeoutMin** rewrite path;
//!   * driving **deeper, multi-fire** associativity flattening;
//!   * proving the conservative policy **never** fires a commutativity rule
//!     end-to-end through `capture_optimized`;
//!   * checking rewrite/original **equivalence** as an oracle-free property over
//!     a family of nested shapes (the differentiator), every one of which also
//!     satisfies the structural `OptimizedExecution` invariants.
//!
//! Oracle-free: each rewritten outcome is checked against the *same* plan run
//! unoptimized (the equivalence oracle), never a hand-computed expectation — the
//! handful of literal-value asserts only anchor shapes already pinned by
//! `plan_capture_execute.rs`. Reactor-free under `block_on`: every leaf is
//! immediately ready, so one poll resolves the tree (no parking, no timer fires;
//! the 30s/60s timeouts never elapse). Run with `--features test-internals`.

#![cfg(feature = "test-internals")]

use std::time::Duration;

use asupersync::Cx;
use asupersync::plan::RewriteRule;
use asupersync::plan::execute::{OptimizedExecution, PlanValue, capture, capture_optimized};
use futures_lite::future::block_on;

// ---------------------------------------------------------------------------
// Universal postconditions of `capture_optimized`, read straight off the
// fail-closed ladder in `src/plan/execute.rs`. These must hold for *any* plan,
// so every test funnels its result through here.
// ---------------------------------------------------------------------------

fn assert_optimized_invariants<T: std::fmt::Debug>(exec: &OptimizedExecution<T>) {
    // The conservative policy disables commutativity, so a reordering rule can
    // never fire through `capture_optimized` — proven end-to-end, not by
    // inspecting the policy struct.
    for rule in &exec.fired_rules {
        assert!(
            !matches!(rule, RewriteRule::JoinCommute | RewriteRule::RaceCommute),
            "conservative policy must never fire a commutativity rule, saw {rule:?}"
        );
    }

    if exec.rewritten {
        // Executed the rewritten DAG ⟹ a rule fired, a non-identity certificate
        // is surfaced, and there is no fallback reason.
        assert!(
            !exec.fired_rules.is_empty(),
            "rewritten ⟹ at least one rule fired"
        );
        let cert = exec
            .certificate
            .as_ref()
            .expect("rewritten ⟹ a certificate is surfaced");
        assert!(
            !cert.is_identity(),
            "rewritten ⟹ the certificate is non-identity"
        );
        assert!(
            exec.fallback_reason.is_none(),
            "rewritten ⟹ no fail-closed reason"
        );
    } else {
        // Fell closed to the original plan ⟹ a logged reason explains why.
        assert!(
            exec.fallback_reason.is_some(),
            "fell-closed ⟹ a fallback reason is always logged (the safety contract)"
        );
    }

    // No structural IR (first_ok/quorum) ⟹ certificate absent ⟹ the original ran.
    if exec.certificate.is_none() {
        assert!(
            !exec.rewritten,
            "absent certificate ⟹ no rewrite was executed"
        );
    }
}

/// Runs `build` twice — once through the certified-rewrite path and once as a
/// plain capture+execute — and asserts the outcomes are identical (the
/// equivalence guarantee), after checking the optimized result's invariants.
/// Returns the `OptimizedExecution` so callers can make rule-specific asserts.
///
/// `build` is expanded as a fresh closure on each side, so each `capture` infers
/// its own lifetimes and constructs its own (one-shot) leaf futures.
macro_rules! assert_equivalent {
    ($name:literal, |$p:ident| $body:block) => {{
        let cx = Cx::for_testing();
        let exec = block_on(capture_optimized(&cx, |$p| $body)).expect("optimized execution ok");
        assert_optimized_invariants(&exec);

        let baseline_cx = Cx::for_testing();
        let baseline = block_on(
            capture(|$p| $body)
                .expect("valid plan")
                .execute(&baseline_cx),
        )
        .expect("baseline execution ok");

        assert_eq!(
            exec.value, baseline,
            "{}: certified rewrite changed the outcome (equivalence violated)",
            $name
        );
        exec
    }};
}

// ---------------------------------------------------------------------------
// TimeoutMin — the rewrite path `plan_capture_execute.rs` never exercised.
// Timeout(d1, Timeout(d2, f)) -> Timeout(min(d1,d2), f).
// ---------------------------------------------------------------------------

#[test]
fn timeout_min_collapses_nested_timeouts_and_preserves_outcome() {
    // outer=60s wrapping inner=30s; neither elapses (leaf is ready), so the
    // value is the leaf scalar both before and after the collapse.
    let exec = assert_equivalent!("timeout_min", |p| {
        let leaf = p.leaf(async { 7u32 });
        let inner = p.timeout(leaf, Duration::from_secs(30));
        p.timeout(inner, Duration::from_secs(60))
    });

    assert!(
        exec.rewritten,
        "nested timeouts must collapse under conservative"
    );
    assert!(
        exec.fired_rules.contains(&RewriteRule::TimeoutMin),
        "TimeoutMin must be among the fired rules, got {:?}",
        exec.fired_rules
    );
    assert_eq!(exec.value, PlanValue::Scalar(7));
}

#[test]
fn timeout_min_is_symmetric_in_duration_order() {
    // Same shape with the *inner* timeout the larger one: min() still collapses,
    // the rule still fires, and the outcome is unchanged.
    let exec = assert_equivalent!("timeout_min_swapped", |p| {
        let leaf = p.leaf(async { 11u32 });
        let inner = p.timeout(leaf, Duration::from_secs(90));
        p.timeout(inner, Duration::from_secs(45))
    });

    assert!(exec.rewritten);
    assert!(exec.fired_rules.contains(&RewriteRule::TimeoutMin));
    assert_eq!(exec.value, PlanValue::Scalar(11));
}

// ---------------------------------------------------------------------------
// Deep associativity: multi-fire flattening, outcome + conservative gating.
// ---------------------------------------------------------------------------

#[test]
fn deep_nested_join_flattens_to_a_single_ordered_vector() {
    // join(join(join(a,b),c),d): `eval` flattens via into_flat both before and
    // after, so the value is the in-order [1,2,3,4] either way.
    let exec = assert_equivalent!("deep_join", |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        let j1 = p.join([a, b]);
        let c = p.leaf(async { 3u32 });
        let j2 = p.join([j1, c]);
        let d = p.leaf(async { 4u32 });
        p.join([j2, d])
    });

    assert!(exec.rewritten, "a 3-deep nested join must flatten");
    assert!(exec.fired_rules.contains(&RewriteRule::JoinAssoc));
    // Conservative gating, proven end-to-end: only associativity fires for joins.
    assert!(
        exec.fired_rules
            .iter()
            .all(|r| matches!(r, RewriteRule::JoinAssoc)),
        "only JoinAssoc may fire for a pure-join tree, got {:?}",
        exec.fired_rules
    );
    assert_eq!(exec.value, PlanValue::Vector(vec![1, 2, 3, 4]));
}

#[test]
fn deep_nested_race_flattens_to_the_first_winner() {
    // race(race(race(a,b),c),d): index-0 winner is `a` before and after the
    // flatten (SelectAll resolves the first ready branch).
    let exec = assert_equivalent!("deep_race", |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        let r1 = p.race([a, b]);
        let c = p.leaf(async { 3u32 });
        let r2 = p.race([r1, c]);
        let d = p.leaf(async { 4u32 });
        p.race([r2, d])
    });

    assert!(exec.rewritten, "a 3-deep nested race must flatten");
    assert!(exec.fired_rules.contains(&RewriteRule::RaceAssoc));
    assert!(
        exec.fired_rules
            .iter()
            .all(|r| matches!(r, RewriteRule::RaceAssoc)),
        "only RaceAssoc may fire for a pure-race tree, got {:?}",
        exec.fired_rules
    );
    assert_eq!(exec.value, PlanValue::Scalar(1));
}

// ---------------------------------------------------------------------------
// Fail-closed paths: a logged reason is the safety proof (AC2).
// ---------------------------------------------------------------------------

#[test]
fn identity_plan_falls_closed_with_a_no_rewrite_reason() {
    // A flat join has nothing to rewrite: identity certificate, original runs.
    let exec = assert_equivalent!("identity_join", |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        p.join([a, b])
    });

    assert!(!exec.rewritten);
    assert!(exec.fired_rules.is_empty());
    let cert = exec
        .certificate
        .as_ref()
        .expect("representable -> certificate");
    assert!(cert.is_identity(), "no rule fired -> identity certificate");
    let reason = exec.fallback_reason.as_deref().expect("reason logged");
    assert!(
        reason.contains("no conservative rewrite"),
        "identity reason should name the no-rewrite cause, got {reason:?}"
    );
    assert_eq!(exec.value, PlanValue::Vector(vec![1, 2]));
}

#[test]
fn no_structural_ir_plan_falls_closed_with_a_first_ok_reason() {
    // first_ok has no rewrite IR: certificate is absent, original runs, and the
    // reason names the cause.
    let exec = assert_equivalent!("first_ok_no_ir", |p| {
        let a = p.leaf(async { 0u32 }); // fails the predicate
        let b = p.leaf(async { 8u32 }); // first success
        p.first_ok([a, b], |v: &u32| *v > 0)
    });

    assert!(!exec.rewritten);
    assert!(exec.certificate.is_none(), "first_ok has no structural IR");
    assert!(exec.fired_rules.is_empty());
    let reason = exec.fallback_reason.as_deref().expect("reason logged");
    assert!(
        reason.contains("first_ok") || reason.contains("quorum"),
        "no-IR reason should name first_ok/quorum, got {reason:?}"
    );
    assert_eq!(exec.value, PlanValue::Scalar(8));
}

// ---------------------------------------------------------------------------
// Headline: certified rewrite preserves the outcome across a shape family, and
// every result obeys the structural invariants (handled inside the macro).
// ---------------------------------------------------------------------------

#[test]
fn certified_rewrite_preserves_outcome_across_shapes() {
    // Each shape mixes the reachable rules (or none). The macro asserts
    // optimized == unoptimized AND the OptimizedExecution invariants for all.

    // No rule: race over heterogeneous children (winner = the index-0 join).
    let _ = assert_equivalent!("race_join_timeout", |p| {
        let first_leaf = p.leaf(async { 1u32 });
        let second_leaf = p.leaf(async { 2u32 });
        let joined = p.join([first_leaf, second_leaf]);
        let third_leaf = p.leaf(async { 3u32 });
        let timed = p.timeout(third_leaf, Duration::from_secs(60));
        p.race([joined, timed])
    });

    // TimeoutMin fires inside a join arm; the join is otherwise flat.
    let _ = assert_equivalent!("join_of_collapsing_timeout", |p| {
        let a = p.leaf(async { 5u32 });
        let inner = p.timeout(a, Duration::from_secs(20));
        let collapsed = p.timeout(inner, Duration::from_secs(60));
        let b = p.leaf(async { 6u32 });
        p.join([collapsed, b])
    });

    // RaceAssoc fires across two race subtrees.
    let _ = assert_equivalent!("race_of_races", |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        let left = p.race([a, b]);
        let c = p.leaf(async { 3u32 });
        let d = p.leaf(async { 4u32 });
        let right = p.race([c, d]);
        p.race([left, right])
    });

    // JoinAssoc nested under a top-level race arm (mixed operators, deeper).
    let _ = assert_equivalent!("race_over_nested_join", |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        let inner = p.join([a, b]);
        let c = p.leaf(async { 3u32 });
        let flat = p.join([inner, c]);
        let d = p.leaf(async { 4u32 });
        let solo = p.timeout(d, Duration::from_secs(60));
        p.race([flat, solo])
    });

    // Single leaf wrapped in a timeout: representable, nothing to rewrite.
    let _ = assert_equivalent!("lone_timeout", |p| {
        let a = p.leaf(async { 42u32 });
        p.timeout(a, Duration::from_secs(60))
    });
}
