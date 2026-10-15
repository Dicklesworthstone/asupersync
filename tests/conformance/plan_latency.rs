use asupersync::plan::latency_algebra::{ArrivalCurve, LatencyAnalyzer, NodeCurves, ServiceCurve};
use asupersync::plan::{PlanDag, PlanId};
use std::time::Duration;

const EPS: f64 = 1e-6;

fn approx_eq(left: f64, right: f64) -> bool {
    (left - right).abs() <= EPS
}

fn curve(index: usize) -> NodeCurves {
    match index {
        0 => NodeCurves::new(
            ArrivalCurve::token_bucket(100.0, 10.0),
            ServiceCurve::rate_latency(200.0, 0.0),
        ),
        1 => NodeCurves::new(
            ArrivalCurve::token_bucket(100.0, 50.0),
            ServiceCurve::rate_latency(200.0, 0.01),
        ),
        2 => NodeCurves::new(
            ArrivalCurve::token_bucket(60.0, 10.0),
            ServiceCurve::rate_latency(120.0, 0.002),
        ),
        _ => panic!("unknown fixture index {index}"),
    }
}

fn analyze_delay(dag: &PlanDag, annotations: &[(PlanId, usize)]) -> f64 {
    let mut analyzer = LatencyAnalyzer::new();
    for (id, fixture) in annotations {
        analyzer.annotate(*id, curve(*fixture));
    }
    analyzer
        .analyze(dag)
        .end_to_end_delay()
        .expect("root bound should exist")
}

#[test]
fn join_latency_is_commutative_and_associative() {
    let mut left_assoc = PlanDag::new();
    let a0 = left_assoc.leaf("a");
    let b0 = left_assoc.leaf("b");
    let c0 = left_assoc.leaf("c");
    let ab0 = left_assoc.join(vec![a0, b0]);
    let root0 = left_assoc.join(vec![ab0, c0]);
    left_assoc.set_root(root0);

    let mut right_assoc = PlanDag::new();
    let a1 = right_assoc.leaf("a");
    let b1 = right_assoc.leaf("b");
    let c1 = right_assoc.leaf("c");
    let bc1 = right_assoc.join(vec![b1, c1]);
    let root1 = right_assoc.join(vec![a1, bc1]);
    right_assoc.set_root(root1);

    let mut reordered = PlanDag::new();
    let a2 = reordered.leaf("a");
    let b2 = reordered.leaf("b");
    let c2 = reordered.leaf("c");
    let root2 = reordered.join(vec![c2, a2, b2]);
    reordered.set_root(root2);

    let left_delay = analyze_delay(&left_assoc, &[(a0, 0), (b0, 1), (c0, 2)]);
    let right_delay = analyze_delay(&right_assoc, &[(a1, 0), (b1, 1), (c1, 2)]);
    let reordered_delay = analyze_delay(&reordered, &[(a2, 0), (b2, 1), (c2, 2)]);

    assert!(approx_eq(left_delay, right_delay));
    assert!(approx_eq(left_delay, reordered_delay));
}

#[test]
fn race_latency_is_commutative_and_associative() {
    let mut left_assoc = PlanDag::new();
    let a0 = left_assoc.leaf("a");
    let b0 = left_assoc.leaf("b");
    let c0 = left_assoc.leaf("c");
    let ab0 = left_assoc.race(vec![a0, b0]);
    let root0 = left_assoc.race(vec![ab0, c0]);
    left_assoc.set_root(root0);

    let mut right_assoc = PlanDag::new();
    let a1 = right_assoc.leaf("a");
    let b1 = right_assoc.leaf("b");
    let c1 = right_assoc.leaf("c");
    let bc1 = right_assoc.race(vec![b1, c1]);
    let root1 = right_assoc.race(vec![a1, bc1]);
    right_assoc.set_root(root1);

    let mut reordered = PlanDag::new();
    let a2 = reordered.leaf("a");
    let b2 = reordered.leaf("b");
    let c2 = reordered.leaf("c");
    let root2 = reordered.race(vec![c2, a2, b2]);
    reordered.set_root(root2);

    let left_delay = analyze_delay(&left_assoc, &[(a0, 0), (b0, 1), (c0, 2)]);
    let right_delay = analyze_delay(&right_assoc, &[(a1, 0), (b1, 1), (c1, 2)]);
    let reordered_delay = analyze_delay(&reordered, &[(a2, 0), (b2, 1), (c2, 2)]);

    assert!(approx_eq(left_delay, right_delay));
    assert!(approx_eq(left_delay, reordered_delay));
}

#[test]
fn join_and_race_singleton_identity_hold() {
    let mut leaf_only = PlanDag::new();
    let leaf = leaf_only.leaf("task");
    leaf_only.set_root(leaf);

    let mut joined = PlanDag::new();
    let joined_leaf = joined.leaf("task");
    let joined_root = joined.join(vec![joined_leaf]);
    joined.set_root(joined_root);

    let mut raced = PlanDag::new();
    let raced_leaf = raced.leaf("task");
    let raced_root = raced.race(vec![raced_leaf]);
    raced.set_root(raced_root);

    let leaf_delay = analyze_delay(&leaf_only, &[(leaf, 1)]);
    let join_delay = analyze_delay(&joined, &[(joined_leaf, 1)]);
    let race_delay = analyze_delay(&raced, &[(raced_leaf, 1)]);

    assert!(approx_eq(leaf_delay, join_delay));
    assert!(approx_eq(leaf_delay, race_delay));
}

#[test]
fn timeout_passthrough_and_nested_min_laws_hold() {
    let mut passthrough = PlanDag::new();
    let fast = passthrough.leaf("fast");
    let fast_timeout = passthrough.timeout(fast, Duration::from_secs(10));
    passthrough.set_root(fast_timeout);

    let mut fast_leaf = PlanDag::new();
    let fast_only = fast_leaf.leaf("fast");
    fast_leaf.set_root(fast_only);

    let passthrough_delay = analyze_delay(&passthrough, &[(fast, 0)]);
    let direct_fast_delay = analyze_delay(&fast_leaf, &[(fast_only, 0)]);
    assert!(approx_eq(passthrough_delay, direct_fast_delay));

    let mut nested = PlanDag::new();
    let slow = nested.leaf("slow");
    let inner = nested.timeout(slow, Duration::from_millis(500));
    let outer = nested.timeout(inner, Duration::from_millis(200));
    nested.set_root(outer);

    let mut collapsed = PlanDag::new();
    let slow2 = collapsed.leaf("slow");
    let root = collapsed.timeout(slow2, Duration::from_millis(200));
    collapsed.set_root(root);

    let nested_delay = analyze_delay(&nested, &[(slow, 1)]);
    let collapsed_delay = analyze_delay(&collapsed, &[(slow2, 1)]);
    assert!(approx_eq(nested_delay, collapsed_delay));
}

#[test]
fn race_over_joins_stays_below_join_over_race() {
    let mut lhs = PlanDag::new();
    let a0 = lhs.leaf("a");
    let b0 = lhs.leaf("b");
    let a1 = lhs.leaf("a_copy");
    let c0 = lhs.leaf("c");
    let join_ab = lhs.join(vec![a0, b0]);
    let join_ac = lhs.join(vec![a1, c0]);
    let lhs_root = lhs.race(vec![join_ab, join_ac]);
    lhs.set_root(lhs_root);

    let mut rhs = PlanDag::new();
    let a2 = rhs.leaf("a");
    let b1 = rhs.leaf("b");
    let c1 = rhs.leaf("c");
    let race_bc = rhs.race(vec![b1, c1]);
    let rhs_root = rhs.join(vec![a2, race_bc]);
    rhs.set_root(rhs_root);

    let lhs_delay = analyze_delay(&lhs, &[(a0, 0), (b0, 1), (a1, 0), (c0, 2)]);
    let rhs_delay = analyze_delay(&rhs, &[(a2, 0), (b1, 1), (c1, 2)]);

    assert!(
        lhs_delay <= rhs_delay + EPS,
        "expected race(join(a,b), join(a,c)) <= join(a, race(b,c)), got lhs={lhs_delay}, rhs={rhs_delay}"
    );
}
