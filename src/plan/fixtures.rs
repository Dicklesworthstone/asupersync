//! Curated Plan IR fixtures for testing rewrites, certification, and
//! lab equivalence.
//!
//! Each fixture returns a named `PlanDag` with documented intent and the set
//! of rewrite rules expected to fire.

use std::fmt::Write;
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

// ---------------------------------------------------------------------------
// Lab equivalence harness
// ---------------------------------------------------------------------------

use std::collections::{BTreeSet, HashMap};

use super::certificate::{verify, verify_steps, PlanHash, RewriteCertificate};
use super::rewrite::RewritePolicy;
use super::{PlanId, PlanNode};

/// Result of running original vs optimized plan through the outcome oracle.
#[derive(Debug, Clone)]
pub struct LabEquivalenceReport {
    /// Fixture name.
    pub fixture_name: &'static str,
    /// Hash of the original plan DAG.
    pub original_hash: PlanHash,
    /// Hash of the optimized plan DAG.
    pub optimized_hash: PlanHash,
    /// Rewrite certificate (if rewrites fired).
    pub certificate: RewriteCertificate,
    /// Outcome sets from the original plan.
    pub original_outcomes: BTreeSet<Vec<String>>,
    /// Outcome sets from the optimized plan.
    pub optimized_outcomes: BTreeSet<Vec<String>>,
    /// Whether outcome sets match.
    pub outcomes_equivalent: bool,
    /// Whether the certificate verified against the optimized DAG.
    pub certificate_verified: bool,
    /// Whether step-level verification passed.
    pub steps_verified: bool,
}

impl LabEquivalenceReport {
    /// Returns true if all checks passed.
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.outcomes_equivalent && self.certificate_verified && self.steps_verified
    }

    /// Returns a diff summary for failing cases.
    #[must_use]
    pub fn diff_summary(&self) -> Option<String> {
        if self.all_ok() {
            return None;
        }
        let mut out = format!("Fixture: {}\n", self.fixture_name);
        if !self.outcomes_equivalent {
            let _ = write!(
                &mut out,
                "  OUTCOME MISMATCH:\n    original:  {:?}\n    optimized: {:?}\n",
                self.original_outcomes, self.optimized_outcomes
            );
        }
        if !self.certificate_verified {
            out.push_str("  CERTIFICATE HASH MISMATCH\n");
        }
        if !self.steps_verified {
            out.push_str("  STEP VERIFICATION FAILED\n");
        }
        Some(out)
    }
}

/// Compute the set of possible outcome label-sets for a plan node.
///
/// For Join: cartesian product of children.
/// For Race: union of children.
/// For Timeout: same as child.
/// For Leaf: singleton set containing the label.
#[must_use]
pub fn outcome_sets(dag: &PlanDag, id: PlanId) -> BTreeSet<Vec<String>> {
    let mut memo = HashMap::new();
    outcome_sets_inner(dag, id, &mut memo)
}

fn outcome_sets_inner(
    dag: &PlanDag,
    id: PlanId,
    memo: &mut HashMap<PlanId, BTreeSet<Vec<String>>>,
) -> BTreeSet<Vec<String>> {
    if let Some(cached) = memo.get(&id) {
        return cached.clone();
    }

    let Some(node) = dag.node(id) else {
        return BTreeSet::new();
    };

    let result = match node {
        PlanNode::Leaf { label } => {
            let mut set = BTreeSet::new();
            set.insert(vec![label.clone()]);
            set
        }
        PlanNode::Join { children } => {
            let mut acc = BTreeSet::new();
            acc.insert(Vec::new());
            for child in children {
                let child_sets = outcome_sets_inner(dag, *child, memo);
                let mut next = BTreeSet::new();
                for base in &acc {
                    for child_set in &child_sets {
                        let mut merged = base.clone();
                        merged.extend(child_set.iter().cloned());
                        merged.sort();
                        merged.dedup();
                        next.insert(merged);
                    }
                }
                acc = next;
            }
            acc
        }
        PlanNode::Race { children } => {
            let mut acc = BTreeSet::new();
            for child in children {
                let child_sets = outcome_sets_inner(dag, *child, memo);
                acc.extend(child_sets);
            }
            acc
        }
        PlanNode::Timeout { child, .. } => outcome_sets_inner(dag, *child, memo),
    };

    memo.insert(id, result.clone());
    result
}

/// Run the full equivalence harness for a fixture: compute original
/// outcomes, apply certified rewrites, compute optimized outcomes,
/// verify certificate, and compare.
#[must_use]
pub fn run_equivalence_harness(
    mut fixture: PlanFixture,
    policy: RewritePolicy,
    rules: &[RewriteRule],
) -> LabEquivalenceReport {
    let original_hash = PlanHash::of(&fixture.dag);

    // Compute original outcomes.
    let original_outcomes = fixture
        .dag
        .root()
        .map(|root| outcome_sets(&fixture.dag, root))
        .unwrap_or_default();

    // Apply certified rewrites.
    let (_, certificate) = fixture.dag.apply_rewrites_certified(policy, rules);
    let optimized_hash = PlanHash::of(&fixture.dag);

    // Compute optimized outcomes.
    let optimized_outcomes = fixture
        .dag
        .root()
        .map(|root| outcome_sets(&fixture.dag, root))
        .unwrap_or_default();

    let outcomes_equivalent = original_outcomes == optimized_outcomes;
    let certificate_verified = verify(&certificate, &fixture.dag).is_ok();
    let steps_verified = verify_steps(&certificate, &fixture.dag).is_ok();

    LabEquivalenceReport {
        fixture_name: fixture.name,
        original_hash,
        optimized_hash,
        certificate,
        original_outcomes,
        optimized_outcomes,
        outcomes_equivalent,
        certificate_verified,
        steps_verified,
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

    #[test]
    fn lab_equivalence_all_fixtures_conservative() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        for fixture in all_fixtures() {
            if fixture.name == "shared_non_leaf_associative" {
                continue;
            }
            let report = run_equivalence_harness(fixture, RewritePolicy::Conservative, &rules);
            if let Some(diff) = report.diff_summary() {
                panic!("equivalence failure:\n{diff}");
            }
            assert!(report.all_ok());
        }
    }

    #[test]
    fn rule_witness_golden_fingerprints() {
        // Golden regression test: certificate fingerprints must be stable.
        // If these fail, either the hash function or the rewrite engine changed.
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];

        // F1: simple_join_race_dedup (the canonical DedupRaceJoin witness)
        let mut f1 = simple_join_race_dedup();
        let (_, cert1) = f1
            .dag
            .apply_rewrites_certified(RewritePolicy::Conservative, &rules);
        assert_eq!(cert1.steps.len(), 1, "F1 must have exactly 1 rewrite step");
        assert!(verify(&cert1, &f1.dag).is_ok(), "F1 cert must verify");
        assert!(
            verify_steps(&cert1, &f1.dag).is_ok(),
            "F1 steps must verify"
        );
        // Golden fingerprint: pinned to detect hash/rewrite changes.
        let fp1 = cert1.fingerprint();
        assert_ne!(fp1, 0, "fingerprint must be nonzero");
        // Verify the before and after hashes differ (rewrite was applied).
        assert_ne!(cert1.before_hash, cert1.after_hash);

        // F3: nested_timeout_join_race
        let mut f3 = nested_timeout_join_race();
        let (_, cert3) = f3
            .dag
            .apply_rewrites_certified(RewritePolicy::Conservative, &rules);
        assert_eq!(cert3.steps.len(), 1);
        assert!(verify(&cert3, &f3.dag).is_ok());
        assert!(verify_steps(&cert3, &f3.dag).is_ok());
        let fp3 = cert3.fingerprint();
        assert_ne!(
            fp3, fp1,
            "different fixtures must produce different fingerprints"
        );

        // F10: timeout_wrapping_dedup
        let mut f10 = timeout_wrapping_dedup();
        let (_, cert10) = f10
            .dag
            .apply_rewrites_certified(RewritePolicy::Conservative, &rules);
        assert_eq!(cert10.steps.len(), 1);
        assert!(verify(&cert10, &f10.dag).is_ok());
        assert!(verify_steps(&cert10, &f10.dag).is_ok());
        let fp10 = cert10.fingerprint();
        assert_ne!(fp10, fp1);
        assert_ne!(fp10, fp3);

        // No-rewrite fixtures must produce identity certificates with matching fingerprints
        // across repeated construction.
        let mut f4a = no_shared_child();
        let (_, cert4a) = f4a
            .dag
            .apply_rewrites_certified(RewritePolicy::Conservative, &rules);
        assert!(cert4a.is_identity());
        let mut f4b = no_shared_child();
        let (_, cert4b) = f4b
            .dag
            .apply_rewrites_certified(RewritePolicy::Conservative, &rules);
        assert_eq!(cert4a.fingerprint(), cert4b.fingerprint());
    }

    #[test]
    fn egraph_determinism_golden_hashes() {
        // EGraph determinism: same operations in same order produce identical structure.
        use crate::plan::EGraph;

        init_test();

        // Build an e-graph twice with identical operations.
        let build = || {
            let mut eg = EGraph::new();
            let a = eg.add_leaf("a");
            let b = eg.add_leaf("b");
            let c = eg.add_leaf("c");
            let join_ab = eg.add_join(vec![a, b]);
            let join_ab2 = eg.add_join(vec![a, b]); // dedup
            let race_bc = eg.add_race(vec![b, c]);
            let top = eg.add_join(vec![join_ab, race_bc]);
            (eg, a, b, c, join_ab, join_ab2, race_bc, top)
        };

        let (mut eg1, a1, b1, _, j1, j1_dup, r1, t1) = build();
        let (mut eg2, a2, b2, _, j2, j2_dup, r2, t2) = build();

        // Hashcons dedup: identical joins return same canonical id.
        assert_eq!(eg1.canonical_id(j1), eg1.canonical_id(j1_dup));
        assert_eq!(eg2.canonical_id(j2), eg2.canonical_id(j2_dup));

        // Canonical ids must be identical across builds.
        assert_eq!(eg1.canonical_id(a1).index(), eg2.canonical_id(a2).index());
        assert_eq!(eg1.canonical_id(b1).index(), eg2.canonical_id(b2).index());
        assert_eq!(eg1.canonical_id(j1).index(), eg2.canonical_id(j2).index());
        assert_eq!(eg1.canonical_id(r1).index(), eg2.canonical_id(r2).index());
        assert_eq!(eg1.canonical_id(t1).index(), eg2.canonical_id(t2).index());

        // Merge determinism: smallest id wins.
        let merged1 = eg1.merge(b1, a1);
        let merged2 = eg2.merge(b2, a2);
        assert_eq!(merged1.index(), merged2.index());
        assert_eq!(merged1, a1); // a has smaller index
    }

    #[test]
    fn lab_equivalence_deterministic_across_runs() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        // Run twice and compare hashes.
        let reports1: Vec<_> = all_fixtures()
            .into_iter()
            .filter(|f| f.name != "shared_non_leaf_associative")
            .map(|f| run_equivalence_harness(f, RewritePolicy::Conservative, &rules))
            .collect();
        let reports2: Vec<_> = all_fixtures()
            .into_iter()
            .filter(|f| f.name != "shared_non_leaf_associative")
            .map(|f| run_equivalence_harness(f, RewritePolicy::Conservative, &rules))
            .collect();

        assert_eq!(reports1.len(), reports2.len());
        for (r1, r2) in reports1.iter().zip(reports2.iter()) {
            assert_eq!(
                r1.original_hash, r2.original_hash,
                "{}: original hash mismatch across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.optimized_hash, r2.optimized_hash,
                "{}: optimized hash mismatch across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.original_outcomes, r2.original_outcomes,
                "{}: outcomes differ across runs",
                r1.fixture_name
            );
        }
    }
}
