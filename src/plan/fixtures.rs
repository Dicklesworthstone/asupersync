//! Curated Plan IR fixtures for testing rewrites, certification, and
//! lab equivalence.
//!
//! Each fixture returns a named `PlanDag` with documented intent and the set
//! of rewrite rules expected to fire.

use std::time::Duration;

use super::rewrite::RewriteRule;
use super::PlanDag;

/// A named plan fixture with metadata.
#[derive(Debug)]
pub struct PlanFixture {
    /// Short identifier (e.g., "simple_join_race_dedup").
    pub name: &'static str,
    /// What this fixture exercises.
    pub intent: &'static str,
    /// The plan DAG.
    pub dag: PlanDag,
    /// Rules expected to fire (empty = no rewrites expected).
    pub expected_rules: Vec<RewriteRule>,
    /// Number of rewrite steps expected.
    pub expected_step_count: usize,
}

/// Build the full fixture suite (≥ 10 fixtures).
#[must_use]
pub fn all_fixtures() -> Vec<PlanFixture> {
    vec![
        simple_join_race_dedup(),
        three_way_race_of_joins(),
        nested_timeout_join_race(),
        no_shared_child(),
        single_branch_race(),
        deep_chain_no_rewrite(),
        shared_non_leaf_conservative(),
        shared_non_leaf_associative(),
        diamond_join_race(),
        timeout_wrapping_dedup(),
        independent_subtrees(),
        race_of_leaves(),
    ]
}

/// F1: Two binary joins sharing a leaf child, wrapped in a race.
/// DedupRaceJoin should fire once.
fn simple_join_race_dedup() -> PlanFixture {
    let mut dag = PlanDag::new();
    let shared = dag.leaf("shared");
    let left = dag.leaf("left");
    let right = dag.leaf("right");
    let join_a = dag.join(vec![shared, left]);
    let join_b = dag.join(vec![shared, right]);
    let race = dag.race(vec![join_a, join_b]);
    dag.set_root(race);
    PlanFixture {
        name: "simple_join_race_dedup",
        intent: "Basic DedupRaceJoin: Race[Join[s,a], Join[s,b]] -> Join[s, Race[a,b]]",
        dag,
        expected_rules: vec![RewriteRule::DedupRaceJoin],
        expected_step_count: 1,
    }
}

/// F2: Three-way race of joins sharing one leaf.
/// Conservative policy requires binary joins, so no rewrite expected.
fn three_way_race_of_joins() -> PlanFixture {
    let mut dag = PlanDag::new();
    let shared = dag.leaf("shared");
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let j1 = dag.join(vec![shared, a]);
    let j2 = dag.join(vec![shared, b]);
    let j3 = dag.join(vec![shared, c]);
    let race = dag.race(vec![j1, j2, j3]);
    dag.set_root(race);
    PlanFixture {
        name: "three_way_race_of_joins",
        intent: "3-way race: conservative rejects non-binary race",
        dag,
        expected_rules: vec![],
        expected_step_count: 0,
    }
}

/// F3: Timeout wrapping a race-of-joins that should dedup.
fn nested_timeout_join_race() -> PlanFixture {
    let mut dag = PlanDag::new();
    let shared = dag.leaf("shared");
    let left = dag.leaf("left");
    let right = dag.leaf("right");
    let join_a = dag.join(vec![shared, left]);
    let join_b = dag.join(vec![shared, right]);
    let race = dag.race(vec![join_a, join_b]);
    let timed = dag.timeout(race, Duration::from_secs(5));
    dag.set_root(timed);
    PlanFixture {
        name: "nested_timeout_join_race",
        intent: "Timeout[Race[Join[s,a], Join[s,b]]] -> Timeout[Join[s, Race[a,b]]]",
        dag,
        expected_rules: vec![RewriteRule::DedupRaceJoin],
        expected_step_count: 1,
    }
}

/// F4: Race of joins with NO shared child. No rewrite expected.
fn no_shared_child() -> PlanFixture {
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let d = dag.leaf("d");
    let j1 = dag.join(vec![a, b]);
    let j2 = dag.join(vec![c, d]);
    let race = dag.race(vec![j1, j2]);
    dag.set_root(race);
    PlanFixture {
        name: "no_shared_child",
        intent: "No shared child across joins; no rewrite fires",
        dag,
        expected_rules: vec![],
        expected_step_count: 0,
    }
}

/// F5: Race with a single branch. No rewrite expected.
fn single_branch_race() -> PlanFixture {
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let join = dag.join(vec![a, b]);
    let race = dag.race(vec![join]);
    dag.set_root(race);
    PlanFixture {
        name: "single_branch_race",
        intent: "Single-branch race: DedupRaceJoin requires >= 2 children",
        dag,
        expected_rules: vec![],
        expected_step_count: 0,
    }
}

/// F6: Deep chain of joins with no race. No rewrite expected.
fn deep_chain_no_rewrite() -> PlanFixture {
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let d = dag.leaf("d");
    let j1 = dag.join(vec![a, b]);
    let j2 = dag.join(vec![j1, c]);
    let j3 = dag.join(vec![j2, d]);
    dag.set_root(j3);
    PlanFixture {
        name: "deep_chain_no_rewrite",
        intent: "Linear join chain with no race; no rewrite applicable",
        dag,
        expected_rules: vec![],
        expected_step_count: 0,
    }
}

/// F7: Shared non-leaf child under Conservative policy. No rewrite.
fn shared_non_leaf_conservative() -> PlanFixture {
    let mut dag = PlanDag::new();
    let x = dag.leaf("x");
    let y = dag.leaf("y");
    let shared_join = dag.join(vec![x, y]);
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let j1 = dag.join(vec![shared_join, a]);
    let j2 = dag.join(vec![shared_join, b]);
    let race = dag.race(vec![j1, j2]);
    dag.set_root(race);
    PlanFixture {
        name: "shared_non_leaf_conservative",
        intent: "Shared child is a Join (non-leaf); conservative policy rejects",
        dag,
        expected_rules: vec![],
        expected_step_count: 0,
    }
}

/// F8: Same as F7 but under `AssumeAssociativeComm` policy.
/// This fixture documents the intent; callers must apply with the right policy.
fn shared_non_leaf_associative() -> PlanFixture {
    let mut dag = PlanDag::new();
    let x = dag.leaf("x");
    let y = dag.leaf("y");
    let shared_join = dag.join(vec![x, y]);
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let j1 = dag.join(vec![shared_join, a]);
    let j2 = dag.join(vec![shared_join, b]);
    let race = dag.race(vec![j1, j2]);
    dag.set_root(race);
    PlanFixture {
        name: "shared_non_leaf_associative",
        intent: "Shared non-leaf under AssumeAssociativeComm: rewrite fires",
        dag,
        expected_rules: vec![RewriteRule::DedupRaceJoin],
        expected_step_count: 1,
    }
}

/// F9: Diamond shape — join at top, race at bottom, two paths.
/// No DedupRaceJoin pattern present.
fn diamond_join_race() -> PlanFixture {
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let race = dag.race(vec![b, c]);
    let join = dag.join(vec![a, race]);
    dag.set_root(join);
    PlanFixture {
        name: "diamond_join_race",
        intent: "Join[a, Race[b,c]]: already in deduped form; no rewrite",
        dag,
        expected_rules: vec![],
        expected_step_count: 0,
    }
}

/// F10: Timeout wrapping a dedup-eligible race, nested inside another join.
fn timeout_wrapping_dedup() -> PlanFixture {
    let mut dag = PlanDag::new();
    let shared = dag.leaf("shared");
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let j1 = dag.join(vec![shared, a]);
    let j2 = dag.join(vec![shared, b]);
    let race = dag.race(vec![j1, j2]);
    let timed = dag.timeout(race, Duration::from_millis(500));
    let outer = dag.leaf("outer");
    let top = dag.join(vec![outer, timed]);
    dag.set_root(top);
    PlanFixture {
        name: "timeout_wrapping_dedup",
        intent: "Join[outer, Timeout[Race[Join[s,a], Join[s,b]]]]: inner race rewrites",
        dag,
        expected_rules: vec![RewriteRule::DedupRaceJoin],
        expected_step_count: 1,
    }
}

/// F11: Two independent subtrees in a join. No rewrite applicable.
fn independent_subtrees() -> PlanFixture {
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let d = dag.leaf("d");
    let left = dag.join(vec![a, b]);
    let right = dag.join(vec![c, d]);
    let top = dag.join(vec![left, right]);
    dag.set_root(top);
    PlanFixture {
        name: "independent_subtrees",
        intent: "Two independent join subtrees; no race pattern",
        dag,
        expected_rules: vec![],
        expected_step_count: 0,
    }
}

/// F12: Race of raw leaves (not joins). No DedupRaceJoin applies.
fn race_of_leaves() -> PlanFixture {
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let race = dag.race(vec![a, b, c]);
    dag.set_root(race);
    PlanFixture {
        name: "race_of_leaves",
        intent: "Race[a,b,c]: children aren't joins, no DedupRaceJoin",
        dag,
        expected_rules: vec![],
        expected_step_count: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::certificate::{verify, verify_steps};
    use crate::plan::rewrite::{RewritePolicy, RewriteRule};
    use crate::test_utils::init_test_logging;

    fn init_test() {
        init_test_logging();
    }

    #[test]
    fn all_fixtures_validate() {
        init_test();
        for fixture in all_fixtures() {
            assert!(
                fixture.dag.validate().is_ok(),
                "fixture {} failed validation",
                fixture.name
            );
        }
    }

    #[test]
    fn fixture_count_at_least_10() {
        init_test();
        let fixtures = all_fixtures();
        assert!(
            fixtures.len() >= 10,
            "need >= 10 fixtures, got {}",
            fixtures.len()
        );
    }

    #[test]
    fn conservative_rewrites_match_expected_counts() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        for mut fixture in all_fixtures() {
            // Skip fixtures designed for non-conservative policy.
            if fixture.name == "shared_non_leaf_associative" {
                continue;
            }
            let (report, cert) = fixture
                .dag
                .apply_rewrites_certified(RewritePolicy::Conservative, &rules);
            assert_eq!(
                report.steps().len(),
                fixture.expected_step_count,
                "fixture {}: expected {} steps, got {}",
                fixture.name,
                fixture.expected_step_count,
                report.steps().len()
            );
            assert!(
                verify(&cert, &fixture.dag).is_ok(),
                "fixture {}: certificate verification failed",
                fixture.name
            );
            assert!(
                verify_steps(&cert, &fixture.dag).is_ok(),
                "fixture {}: step verification failed",
                fixture.name
            );
        }
    }

    #[test]
    fn associative_policy_fires_on_non_leaf_shared() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let fixtures = all_fixtures();
        let fixture = fixtures
            .iter()
            .find(|f| f.name == "shared_non_leaf_associative")
            .expect("fixture exists");
        let mut dag = PlanDag::new();
        // Rebuild the fixture DAG (can't move out of Vec reference).
        let x = dag.leaf("x");
        let y = dag.leaf("y");
        let shared_join = dag.join(vec![x, y]);
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let j1 = dag.join(vec![shared_join, a]);
        let j2 = dag.join(vec![shared_join, b]);
        let race = dag.race(vec![j1, j2]);
        dag.set_root(race);

        let (report, cert) =
            dag.apply_rewrites_certified(RewritePolicy::AssumeAssociativeComm, &rules);
        assert_eq!(report.steps().len(), fixture.expected_step_count);
        assert!(verify(&cert, &dag).is_ok());
    }
}
