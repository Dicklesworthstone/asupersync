#![cfg(feature = "test-internals")]
//! AC3 evidence for tjrmwz.2 (certified rewrite application): do the rewrites
//! reachable through `capture_optimized` deliver a **real, measurable win**, and
//! where they do not, say so per the honesty discipline.
//!
//! The bead's AC3 asks for ">=2 rewrite rules show measurable improvement on
//! representative fixtures (numbers committed) OR documented negative result".
//! This crate commits *both halves*:
//!
//! ## The measurable win (numbers committed, deterministic)
//!
//! The interpreter's cost is defined exactly in `src/plan/execute.rs`: it pays
//! "one heap allocation per leaf plus one per **interior node**" and "one extra
//! `poll_fn`/`Future` indirection layer per interior node". So the win a
//! structure-flattening rewrite delivers is precisely the reduction in the count
//! of *reachable interior nodes* of the executed tree — fewer `Box::pin`'d `eval`
//! futures and fewer poll-indirection layers, per execution. These tests measure
//! that reduction structurally (no wall-clock noise) on representative fixtures
//! and commit the exact before/after counts:
//!
//!   * `JoinAssoc`  : `join(join(a,b),c)`            interior 2 -> 1, leaves 3 -> 3
//!   * `RaceAssoc`  : `race(race(a,b),c)`            interior 2 -> 1, leaves 3 -> 3
//!   * `TimeoutMin` : `timeout(60, timeout(20, f))`  interior 2 -> 1, leaf   1 -> 1
//!     (and the surviving deadline is `min` = 20s, the min-plus hoist)
//!
//! That is three reachable rules, each with a committed interior-node reduction
//! while **conserving the leaf set** (the rewrite removes interpreter overhead,
//! never executed work). The win is also shown on the *actually executed* path:
//! `capture_optimized` runs the flattened DAG and returns the same value as the
//! unoptimized run (equivalence), so the structural saving is realized, not just
//! an IR-layer artifact.
//!
//! ## The documented limit (the honest half)
//!
//! The one rewrite that would reduce executed *work* rather than interpreter
//! overhead — `DedupRaceJoin` (race/join distributivity: execute a shared
//! subtree once instead of once per branch) — is **structurally unreachable**
//! through one-shot capture. It needs a shared subtree, and a captured plan is a
//! tree of one-shot futures: `PlanCapture::finish` rejects any plan that
//! references a node twice (`SharedNode`). So through `capture_optimized` the
//! rewrites can only shrink interpreter overhead, never redundant leaf
//! execution. That bound is proven here, not asserted in prose.
//!
//! Run with `--features test-internals` (for `Cx::for_testing`).

use std::time::Duration;

use asupersync::Cx;
use asupersync::plan::execute::{
    PlanCapture, PlanExecError, PlanValue, capture as capture_exec, capture_optimized,
};
use asupersync::plan::{
    PlanBuilder, PlanDag, PlanId, PlanNode, RewritePolicy, RewriteRule, capture as capture_dag,
};
use futures_lite::future::block_on;

/// The full rule menu the certified ladder offers the engine (mirrors
/// `REWRITE_RULE_MENU` in `src/plan/execute.rs`). The policy gates which fire.
const MENU: [RewriteRule; 6] = [
    RewriteRule::JoinAssoc,
    RewriteRule::RaceAssoc,
    RewriteRule::JoinCommute,
    RewriteRule::RaceCommute,
    RewriteRule::TimeoutMin,
    RewriteRule::DedupRaceJoin,
];

/// Reachable structural cost of the tree rooted at `dag`'s root, counting leaf
/// *executions* with multiplicity (a shared subtree is executed once per
/// reference, so it is counted once per reference — the work metric) and
/// interior nodes with multiplicity (the per-node interpreter tax).
fn reachable_cost(dag: &PlanDag) -> (usize, usize) {
    fn walk(dag: &PlanDag, id: PlanId, interior: &mut usize, leaves: &mut usize) {
        match dag.node(id).expect("reachable id has a node") {
            PlanNode::Leaf { .. } => *leaves += 1,
            PlanNode::Join { children } | PlanNode::Race { children } => {
                *interior += 1;
                for &c in children {
                    walk(dag, c, interior, leaves);
                }
            }
            PlanNode::Timeout { child, .. } => {
                *interior += 1;
                walk(dag, *child, interior, leaves);
            }
        }
    }
    let root = dag.root().expect("dag has a root");
    let (mut interior, mut leaves) = (0usize, 0usize);
    walk(dag, root, &mut interior, &mut leaves);
    (interior, leaves)
}

/// True iff `rule` appears in the certified report's fired-rule list.
fn fired(report: &asupersync::plan::RewriteReport, rule: RewriteRule) -> bool {
    report.steps().iter().any(|s| s.rule == rule)
}

// ---------------------------------------------------------------------------
// The measurable win: each reachable rule shrinks interior-node count while
// conserving the leaf set. Committed exact numbers.
// ---------------------------------------------------------------------------

#[test]
fn join_assoc_drops_one_interior_node_conserving_leaves() {
    let mut dag = capture_dag(|b: &mut PlanBuilder| {
        let l0 = b.leaf("l0");
        let l1 = b.leaf("l1");
        let l2 = b.leaf("l2");
        let inner = b.join([l0, l1]);
        b.join([inner, l2])
    })
    .expect("valid dag");

    let (interior_before, leaves_before) = reachable_cost(&dag);
    assert_eq!(
        (interior_before, leaves_before),
        (2, 3),
        "nested join(join(a,b),c): two interior joins over three leaves"
    );

    let (report, cert) = dag.apply_rewrites_certified(RewritePolicy::conservative(), &MENU);
    assert!(
        fired(&report, RewriteRule::JoinAssoc),
        "JoinAssoc must fire"
    );
    assert!(
        !cert.is_identity(),
        "a rule fired => non-identity certificate"
    );

    let (interior_after, leaves_after) = reachable_cost(&dag);
    assert_eq!(
        (interior_after, leaves_after),
        (1, 3),
        "flattened to one n-ary join: ONE fewer Box::pin'd eval future + poll layer, leaves conserved"
    );
    assert!(
        interior_after < interior_before,
        "the win: interior nodes {interior_before} -> {interior_after}"
    );
    assert_eq!(
        leaves_before, leaves_after,
        "leaf set conserved (no work removed)"
    );
}

#[test]
fn race_assoc_drops_one_interior_node_conserving_leaves() {
    let mut dag = capture_dag(|b: &mut PlanBuilder| {
        let l0 = b.leaf("l0");
        let l1 = b.leaf("l1");
        let l2 = b.leaf("l2");
        let inner = b.race([l0, l1]);
        b.race([inner, l2])
    })
    .expect("valid dag");

    let (interior_before, leaves_before) = reachable_cost(&dag);
    assert_eq!((interior_before, leaves_before), (2, 3));

    let (report, _cert) = dag.apply_rewrites_certified(RewritePolicy::conservative(), &MENU);
    assert!(
        fired(&report, RewriteRule::RaceAssoc),
        "RaceAssoc must fire"
    );

    let (interior_after, leaves_after) = reachable_cost(&dag);
    assert_eq!(
        (interior_after, leaves_after),
        (1, 3),
        "flattened to one n-ary race; leaves conserved"
    );
    assert!(interior_after < interior_before);
}

#[test]
fn timeout_min_collapses_nested_timeout_to_the_min_deadline() {
    let outer = Duration::from_secs(60);
    let inner = Duration::from_secs(20);

    let mut dag = capture_dag(|b: &mut PlanBuilder| {
        let leaf = b.leaf("f");
        let timed = b.timeout(leaf, inner);
        b.timeout(timed, outer)
    })
    .expect("valid dag");

    let (interior_before, leaves_before) = reachable_cost(&dag);
    assert_eq!(
        (interior_before, leaves_before),
        (2, 1),
        "two nested timeout nodes over one leaf"
    );

    let (report, _cert) = dag.apply_rewrites_certified(RewritePolicy::conservative(), &MENU);
    assert!(
        fired(&report, RewriteRule::TimeoutMin),
        "TimeoutMin must fire"
    );

    let (interior_after, leaves_after) = reachable_cost(&dag);
    assert_eq!(
        (interior_after, leaves_after),
        (1, 1),
        "collapsed to a single timeout: one fewer interior node"
    );

    // The min-plus hoist: the surviving deadline is min(outer, inner) = inner.
    let root = dag.root().expect("root");
    match dag.node(root).expect("root node") {
        PlanNode::Timeout { duration, .. } => assert_eq!(
            *duration, inner,
            "surviving deadline is the tighter (min) bound"
        ),
        other => panic!("expected a collapsed Timeout, got {other:?}"),
    }
}

#[test]
fn deeper_join_chain_strictly_reduces_interior_nodes() {
    // Four-leaf left-nested join: the win scales with nesting depth. We do not
    // hard-code the single-pass residual (apply_rewrites is one pass over the
    // original node ids, not a fixpoint); we commit the invariant that matters:
    // a strict interior-node reduction with the leaf set conserved.
    let mut dag = capture_dag(|b: &mut PlanBuilder| {
        let l0 = b.leaf("l0");
        let l1 = b.leaf("l1");
        let l2 = b.leaf("l2");
        let l3 = b.leaf("l3");
        let a = b.join([l0, l1]);
        let c = b.join([a, l2]);
        b.join([c, l3])
    })
    .expect("valid dag");

    let (interior_before, leaves_before) = reachable_cost(&dag);
    assert_eq!((interior_before, leaves_before), (3, 4));

    let (report, _cert) = dag.apply_rewrites_certified(RewritePolicy::conservative(), &MENU);
    assert!(fired(&report, RewriteRule::JoinAssoc));

    let (interior_after, leaves_after) = reachable_cost(&dag);
    assert!(
        interior_after < interior_before,
        "interior nodes must strictly drop: {interior_before} -> {interior_after}"
    );
    assert_eq!(
        leaves_after, leaves_before,
        "leaf set conserved across flattening: {leaves_before} -> {leaves_after}"
    );
}

// ---------------------------------------------------------------------------
// The win is realized on the executed path, not just the IR: capture_optimized
// runs the flattened DAG and returns the SAME value as the unoptimized run.
// ---------------------------------------------------------------------------

#[test]
fn capture_optimized_executes_the_flattened_plan_with_identical_outcome() {
    let cx = Cx::for_testing();
    let optimized = block_on(capture_optimized::<u32, _, _>(
        &cx,
        |p: &mut PlanCapture<u32>| {
            let l0 = p.leaf(async { 1u32 });
            let l1 = p.leaf(async { 2u32 });
            let l2 = p.leaf(async { 3u32 });
            let inner = p.join([l0, l1]);
            p.join([inner, l2])
        },
    ))
    .expect("optimized execution ok");

    assert!(optimized.rewritten, "the flattened DAG was executed");
    assert!(
        optimized.fired_rules.contains(&RewriteRule::JoinAssoc),
        "JoinAssoc fired on the executed path"
    );
    assert!(optimized.fallback_reason.is_none());

    let baseline_cx = Cx::for_testing();
    let baseline = block_on(
        capture_exec::<u32, _>(|p: &mut PlanCapture<u32>| {
            let l0 = p.leaf(async { 1u32 });
            let l1 = p.leaf(async { 2u32 });
            let l2 = p.leaf(async { 3u32 });
            let inner = p.join([l0, l1]);
            p.join([inner, l2])
        })
        .expect("captured plan")
        .execute(&baseline_cx),
    )
    .expect("baseline execution ok");

    // Equivalence: the structural saving did not change the observable outcome.
    assert_eq!(
        optimized.value, baseline,
        "rewritten flattened plan == unoptimized plan (the saving is free)"
    );
    // join flattens nested aggregates in input order.
    assert_eq!(optimized.value, PlanValue::Vector(vec![1, 2, 3]));
}

// ---------------------------------------------------------------------------
// The documented limit (the honest half of AC3): the only work-reducing rewrite
// needs a shared subtree, which one-shot capture structurally forbids.
// ---------------------------------------------------------------------------

#[test]
fn dedup_race_join_work_win_is_unreachable_through_one_shot_capture() {
    // DedupRaceJoin (distributivity) is the only rewrite that removes executed
    // *work* — it hoists a subtree shared across a race of joins so it runs once
    // instead of once per branch. It requires a shared subtree. A captured plan
    // is a tree of one-shot futures: a leaf future may be awaited exactly once,
    // so finish() must reject any plan that references a node from two parents.
    let mut b: PlanCapture<u32> = PlanCapture::new();
    let shared = b.leaf(async { 0u32 });
    let a = b.leaf(async { 1u32 });
    let other = b.leaf(async { 2u32 });
    let ja = b.join([shared, a]);
    let jb = b.join([shared, other]); // re-references `shared` — the shape DedupRaceJoin needs
    let root = b.race([ja, jb]);
    b.set_root(root);

    // `ExecPlan` is not `Debug`, so match the result rather than `expect_err`.
    let err = match b.finish() {
        Ok(_) => panic!("sharing a one-shot leaf must be rejected at capture time"),
        Err(e) => e,
    };
    assert!(
        matches!(err, PlanExecError::SharedNode { .. }),
        "the shared-subtree shape DedupRaceJoin needs is structurally rejected, got {err:?}"
    );
}

#[test]
fn dedup_race_join_does_not_fire_on_a_captured_tree() {
    // Corollary: on a *captured* (tree) race-of-joins with no sharing,
    // DedupRaceJoin has nothing to dedupe, so it never fires. Only the
    // overhead-reducing associativity rules can apply through capture.
    let mut dag = capture_dag(|b: &mut PlanBuilder| {
        let s0 = b.leaf("s0");
        let a = b.leaf("a");
        let s1 = b.leaf("s1");
        let other = b.leaf("b");
        let ja = b.join([s0, a]);
        let jb = b.join([s1, other]);
        b.race([ja, jb])
    })
    .expect("valid dag");

    let (report, _cert) = dag.apply_rewrites_certified(RewritePolicy::conservative(), &MENU);
    assert!(
        !fired(&report, RewriteRule::DedupRaceJoin),
        "no shared subtree => DedupRaceJoin cannot fire on a captured tree"
    );
}
