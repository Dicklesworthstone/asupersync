//! Conformance contract for tjrmwz.2 AC5 (the aggressive policy): the honest
//! characterization of `RewritePolicy::assume_all` through the typed [`capture`]
//! front door, and the reproducing fixtures that show **why it must stay gated**.
//!
//! The headline finding (empirically discovered by this very contract): the
//! aggressive policy is **not** outcome-preserving, even through `capture`. It
//! agrees with `conservative()` only while no rewrite perturbs a node's child
//! order. Capture's structuring DFS hands every node strictly ascending child
//! `PlanId`s, so on the *captured shape itself* the commutativity rules (which
//! fire only on a non-canonical child order) have nothing to do, and
//! `DedupRaceJoin` needs a shared subtree a captured tree never contains.
//!
//! But any node-replacing rewrite — `TimeoutMin` collapsing nested timeouts,
//! `JoinAssoc`/`RaceAssoc` flattening a subtree — installs a *fresh, higher-id*
//! node in place of a child. If that child sits under a `Join`/`Race`, the
//! parent's children are suddenly out of order, and under `assume_all()` the
//! commutativity rule then canonicalizes them:
//!   * re-ordering a `Join`'s children **permutes** its aggregated value;
//!   * re-ordering a `Race`'s children **changes the index-0 winner** outright.
//!
//! So this crate pins three things:
//!   1. the conservative path (front door + explicit policy) **never** fires a
//!      reordering/dedup rule — it forbids commutativity, so it is order-stable;
//!   2. the aggressive policy **agrees** with conservative on order-stable shapes
//!      (no rewrite, or a rewrite that leaves sibling order canonical);
//!   3. the aggressive policy **diverges** on two ordinary captured plans — a
//!      `Join` whose outcome is permuted, and a `Race` whose winner flips — which
//!      is the concrete justification for keeping it behind the I3 differential
//!      equivalence gate (tjrmwz.3) and never defaulting it on.
//!
//! Oracle-free and reactor-free under `block_on`: every leaf is immediately
//! ready, so one poll resolves each tree (no parking, no timer fires; the 60s
//! timeouts never elapse). Run with `--features test-internals`.

#![cfg(feature = "test-internals")]

use std::time::Duration;

use asupersync::Cx;
use asupersync::plan::execute::{
    OptimizedExecution, PlanValue, capture_optimized, capture_optimized_with_policy,
};
use asupersync::plan::{RewritePolicy, RewriteRule};
use futures_lite::future::block_on;

// ---------------------------------------------------------------------------
// The conservative policy forbids commutativity and (effectively) shared-child
// dedup, so it can never fire a reordering/dedup rule. This is the order-stable
// invariant the aggressive policy gives up.
// ---------------------------------------------------------------------------

fn assert_conservative_never_reorders<T>(exec: &OptimizedExecution<T>, label: &str) {
    for rule in &exec.fired_rules {
        assert!(
            !matches!(
                rule,
                RewriteRule::JoinCommute | RewriteRule::RaceCommute | RewriteRule::DedupRaceJoin
            ),
            "{label}: conservative fired a reordering/dedup rule: {rule:?}"
        );
    }
}

// Run a build through `capture_optimized_with_policy` under an explicit policy.
macro_rules! run_with {
    ($policy:expr, |$p:ident| $body:block) => {{
        let cx = Cx::for_testing();
        block_on(capture_optimized_with_policy(&cx, |$p| $body, $policy))
            .expect("optimized execution ok")
    }};
}

// Run a build through the conservative front door `capture_optimized`.
macro_rules! run_front_door {
    (|$p:ident| $body:block) => {{
        let cx = Cx::for_testing();
        block_on(capture_optimized(&cx, |$p| $body)).expect("optimized execution ok")
    }};
}

/// Asserts AGREEMENT for an order-stable shape: the conservative front door, the
/// explicit conservative policy, and the aggressive (`assume_all`) policy all
/// produce the identical certified outcome — same fired rules, same rewritten
/// flag, same certificate identity, same value — and the conservative path never
/// reorders. Returns the conservative execution for shape-specific asserts.
macro_rules! assert_aggressive_agrees {
    ($name:literal, |$p:ident| $body:block) => {{
        let front = run_front_door!(|$p| $body);
        let cons = run_with!(RewritePolicy::conservative(), |$p| $body);
        let aggr = run_with!(RewritePolicy::assume_all(), |$p| $body);

        assert_conservative_never_reorders(&front, concat!($name, "/front-door"));
        assert_conservative_never_reorders(&cons, concat!($name, "/conservative"));

        // The conservative front door is exactly the explicit conservative
        // policy (the delegation introduced by the refactor is faithful).
        assert_eq!(
            front.value, cons.value,
            concat!($name, ": front door != explicit conservative (value)")
        );
        assert_eq!(
            front.rewritten, cons.rewritten,
            concat!($name, ": front door != explicit conservative (rewritten)")
        );
        assert_eq!(
            front.fired_rules, cons.fired_rules,
            concat!($name, ": front door != explicit conservative (rules)")
        );

        // Agreement: aggressive == conservative on this order-stable shape.
        assert_eq!(
            cons.value, aggr.value,
            concat!($name, ": aggressive changed the executed value")
        );
        assert_eq!(
            cons.rewritten, aggr.rewritten,
            concat!($name, ": aggressive changed the rewritten flag")
        );
        assert_eq!(
            cons.fired_rules, aggr.fired_rules,
            concat!($name, ": aggressive changed the fired rules")
        );
        assert_eq!(
            cons.certificate.is_some(),
            aggr.certificate.is_some(),
            concat!($name, ": aggressive changed certificate presence")
        );
        if let (Some(c), Some(a)) = (&cons.certificate, &aggr.certificate) {
            assert_eq!(
                c.is_identity(),
                a.is_identity(),
                concat!($name, ": aggressive changed certificate identity")
            );
        }
        cons
    }};
}

// ---------------------------------------------------------------------------
// AGREEMENT: order-stable shapes where the aggressive policy is a no-op.
// ---------------------------------------------------------------------------

#[test]
fn root_timeout_collapse_agrees() {
    // TimeoutMin fires, but the collapsed timeout is the root — no Join/Race
    // parent whose child order could be perturbed. Aggressive has nothing extra.
    let cons = assert_aggressive_agrees!("timeout_root", |p| {
        let leaf = p.leaf(async { 7u32 });
        let inner = p.timeout(leaf, Duration::from_secs(30));
        p.timeout(inner, Duration::from_secs(60))
    });
    assert!(cons.rewritten);
    assert_eq!(cons.fired_rules, vec![RewriteRule::TimeoutMin]);
    assert_eq!(cons.value, PlanValue::Scalar(7));
}

#[test]
fn pure_deep_join_assoc_agrees() {
    // Assoc flattens to a single root join whose children stay ascending —
    // canonical — so commutativity finds nothing even under assume_all.
    let cons = assert_aggressive_agrees!("deep_join", |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        let j1 = p.join([a, b]);
        let c = p.leaf(async { 3u32 });
        let j2 = p.join([j1, c]);
        let d = p.leaf(async { 4u32 });
        p.join([j2, d])
    });
    assert!(cons.rewritten);
    assert!(cons.fired_rules.contains(&RewriteRule::JoinAssoc));
    assert_eq!(cons.value, PlanValue::Vector(vec![1, 2, 3, 4]));
}

#[test]
fn pure_deep_race_assoc_agrees() {
    let cons = assert_aggressive_agrees!("deep_race", |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        let r1 = p.race([a, b]);
        let c = p.leaf(async { 3u32 });
        let r2 = p.race([r1, c]);
        let d = p.leaf(async { 4u32 });
        p.race([r2, d])
    });
    assert!(cons.rewritten);
    assert!(cons.fired_rules.contains(&RewriteRule::RaceAssoc));
    assert_eq!(cons.value, PlanValue::Scalar(1));
}

#[test]
fn identity_plan_agrees_and_reasons_name_the_policy() {
    // No rule fires under either policy. The fail-closed reason names the policy
    // that declined — proof the aggressive policy really ran, it just had nothing
    // to do (the equality is not a vacuous "same code path" artifact).
    let cons = run_with!(RewritePolicy::conservative(), |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        p.join([a, b])
    });
    let aggr = run_with!(RewritePolicy::assume_all(), |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        p.join([a, b])
    });

    assert!(
        !cons.rewritten && !aggr.rewritten,
        "a flat join is identity"
    );
    assert!(cons.fired_rules.is_empty() && aggr.fired_rules.is_empty());
    assert_eq!(cons.value, aggr.value);
    assert_eq!(cons.value, PlanValue::Vector(vec![1, 2]));
    for exec in [&cons, &aggr] {
        let cert = exec
            .certificate
            .as_ref()
            .expect("representable -> certificate");
        assert!(cert.is_identity(), "no rule fired -> identity certificate");
    }
    let cons_reason = cons.fallback_reason.as_deref().expect("reason logged");
    let aggr_reason = aggr.fallback_reason.as_deref().expect("reason logged");
    assert!(
        cons_reason.contains("conservative"),
        "conservative reason should name the policy, got {cons_reason:?}"
    );
    assert!(
        aggr_reason.contains("aggressive"),
        "aggressive reason should name the policy, got {aggr_reason:?}"
    );
}

#[test]
fn no_rewrite_mixed_shape_agrees() {
    // A race over a flat join and a single timeout: nothing rewrites under either
    // policy (no nested timeout, no nested join, race children canonical), so the
    // outcome is the index-0 winner — the join — identically.
    let cons = assert_aggressive_agrees!("race_join_timeout", |p| {
        let first_leaf = p.leaf(async { 1u32 });
        let second_leaf = p.leaf(async { 2u32 });
        let joined = p.join([first_leaf, second_leaf]);
        let third_leaf = p.leaf(async { 3u32 });
        let timed = p.timeout(third_leaf, Duration::from_secs(60));
        p.race([joined, timed])
    });
    assert!(!cons.rewritten);
    assert_eq!(cons.value, PlanValue::Vector(vec![1, 2]));
}

// ---------------------------------------------------------------------------
// DIVERGENCE: the gated risk. A node-replacing rewrite perturbs sibling order,
// then the aggressive commutativity rule changes the observable outcome.
// ---------------------------------------------------------------------------

#[test]
fn aggressive_permutes_a_join_outcome_after_timeout_collapse() {
    // join([ Timeout(60, Timeout(20, leaf=5)), leaf=6 ]).
    //
    // TimeoutMin collapses the nested timeout into a FRESH higher-id node, so the
    // join's children become [collapsed(high), b(low)] — non-canonical. The
    // conservative policy leaves them: value [5, 6]. The aggressive policy then
    // fires JoinCommute, sorting to [b(low), collapsed(high)]: value [6, 5].
    let cons = run_with!(RewritePolicy::conservative(), |p| {
        let a = p.leaf(async { 5u32 });
        let inner = p.timeout(a, Duration::from_secs(20));
        let collapsed = p.timeout(inner, Duration::from_secs(60));
        let b = p.leaf(async { 6u32 });
        p.join([collapsed, b])
    });
    let aggr = run_with!(RewritePolicy::assume_all(), |p| {
        let a = p.leaf(async { 5u32 });
        let inner = p.timeout(a, Duration::from_secs(20));
        let collapsed = p.timeout(inner, Duration::from_secs(60));
        let b = p.leaf(async { 6u32 });
        p.join([collapsed, b])
    });

    assert_conservative_never_reorders(&cons, "join_permute/conservative");
    assert!(cons.rewritten && aggr.rewritten);

    // Conservative: only the timeout collapses; the join order is preserved.
    assert_eq!(cons.fired_rules, vec![RewriteRule::TimeoutMin]);
    assert_eq!(cons.value, PlanValue::Vector(vec![5, 6]));

    // Aggressive: the collapse perturbs the join, then JoinCommute reorders it.
    assert!(
        aggr.fired_rules.contains(&RewriteRule::TimeoutMin),
        "aggressive still collapses the timeout, got {:?}",
        aggr.fired_rules
    );
    assert!(
        aggr.fired_rules.contains(&RewriteRule::JoinCommute),
        "aggressive must fire JoinCommute on the perturbed join, got {:?}",
        aggr.fired_rules
    );
    assert_eq!(aggr.value, PlanValue::Vector(vec![6, 5]));

    // The divergence is a pure permutation (same multiset, different order): the
    // aggregate is reordered, no leaf gained or lost. This is the outcome change
    // the I3 gate must clear before the aggressive policy could ever default on.
    assert_ne!(
        cons.value, aggr.value,
        "the aggressive policy must change the observed order here"
    );
    let (mut cv, mut av) = (vec_of(&cons.value), vec_of(&aggr.value));
    cv.sort_unstable();
    av.sort_unstable();
    assert_eq!(
        cv, av,
        "the divergence must be a permutation, not a different set"
    );
}

#[test]
fn aggressive_changes_a_race_winner_after_join_flatten() {
    // race([ join(join(a=1, b=2), c=3), Timeout(60, d=4) ]).
    //
    // JoinAssoc flattens the inner join into a FRESH higher-id node, so the
    // race's children become [flat(high), timeout(low)] — non-canonical. The
    // conservative winner is index-0 = the join, value [1, 2, 3]. The aggressive
    // policy fires RaceCommute, sorting to [timeout(low), flat(high)]: the winner
    // flips to the timeout, value 4 — a different *variant*, not just an order.
    let cons = run_with!(RewritePolicy::conservative(), |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        let inner = p.join([a, b]);
        let c = p.leaf(async { 3u32 });
        let flat = p.join([inner, c]);
        let d = p.leaf(async { 4u32 });
        let solo = p.timeout(d, Duration::from_secs(60));
        p.race([flat, solo])
    });
    let aggr = run_with!(RewritePolicy::assume_all(), |p| {
        let a = p.leaf(async { 1u32 });
        let b = p.leaf(async { 2u32 });
        let inner = p.join([a, b]);
        let c = p.leaf(async { 3u32 });
        let flat = p.join([inner, c]);
        let d = p.leaf(async { 4u32 });
        let solo = p.timeout(d, Duration::from_secs(60));
        p.race([flat, solo])
    });

    assert_conservative_never_reorders(&cons, "race_winner/conservative");
    assert!(cons.rewritten && aggr.rewritten);

    // Conservative: only the join flattens; the race order (winner) is preserved.
    assert_eq!(cons.fired_rules, vec![RewriteRule::JoinAssoc]);
    assert_eq!(cons.value, PlanValue::Vector(vec![1, 2, 3]));

    // Aggressive: the flatten perturbs the race, then RaceCommute flips the winner.
    assert!(
        aggr.fired_rules.contains(&RewriteRule::JoinAssoc),
        "aggressive still flattens the join, got {:?}",
        aggr.fired_rules
    );
    assert!(
        aggr.fired_rules.contains(&RewriteRule::RaceCommute),
        "aggressive must fire RaceCommute on the perturbed race, got {:?}",
        aggr.fired_rules
    );
    assert_eq!(aggr.value, PlanValue::Scalar(4));
    assert_ne!(
        cons.value, aggr.value,
        "the aggressive policy must change the race winner here"
    );
}

// ---------------------------------------------------------------------------
// Sanity: the aggressive policy is genuinely functional one layer down. On a
// hand-built non-canonical PlanDag (a structure `capture` never emits) it fires
// JoinCommute where conservative does not — so the agreement above is a property
// of *capture's* canonical ordering, not a dead policy.
// ---------------------------------------------------------------------------

// children [PlanId(1), PlanId(0)] — descending, hence non-canonical. A free `fn`
// (not a closure) is `Copy`, so it can seed both DAGs.
fn build_non_canonical_join(b: &mut asupersync::plan::PlanBuilder) -> asupersync::plan::PlanId {
    let a = b.leaf("a");
    let c = b.leaf("b");
    b.join([c, a])
}

#[test]
fn aggressive_policy_is_functional_on_a_hand_built_non_canonical_dag() {
    use asupersync::plan::capture as capture_dag;

    let menu = [RewriteRule::JoinCommute];

    let mut cons_dag = capture_dag(build_non_canonical_join).expect("valid dag");
    let cons_report = cons_dag.apply_rewrites(RewritePolicy::conservative(), &menu);
    assert!(
        cons_report.is_empty(),
        "conservative must not commute a non-canonical join, got {:?}",
        cons_report
            .steps()
            .iter()
            .map(|s| s.rule)
            .collect::<Vec<_>>()
    );

    let mut aggr_dag = capture_dag(build_non_canonical_join).expect("valid dag");
    let aggr_report = aggr_dag.apply_rewrites(RewritePolicy::assume_all(), &menu);
    assert!(
        aggr_report
            .steps()
            .iter()
            .any(|s| matches!(s.rule, RewriteRule::JoinCommute)),
        "aggressive must canonicalize the non-canonical join via JoinCommute, got {:?}",
        aggr_report
            .steps()
            .iter()
            .map(|s| s.rule)
            .collect::<Vec<_>>()
    );
}

// Extracts the scalar leaves of a `PlanValue` aggregate for multiset comparison.
fn vec_of(value: &PlanValue<u32>) -> Vec<u32> {
    match value {
        PlanValue::Scalar(v) => vec![*v],
        PlanValue::Vector(vs) => vs.clone(),
    }
}
