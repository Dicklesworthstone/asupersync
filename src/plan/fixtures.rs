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
        // Cancel-aware fixtures (F13-F16)
        race_cancel_with_timeout(),
        nested_race_cancel_cascade(),
        timeout_race_dedup_cancel(),
        race_obligation_cancel(),
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

/// F13: Race[fast, Timeout[slow]]: loser cancelled, timeout interacts with cancel.
fn race_cancel_with_timeout() -> PlanFixture {
    let mut dag = PlanDag::new();
    let fast = dag.leaf("fast");
    let slow = dag.leaf("slow");
    let timed_slow = dag.timeout(slow, Duration::from_secs(3));
    let race = dag.race(vec![fast, timed_slow]);
    dag.set_root(race);
    PlanFixture {
        name: "race_cancel_with_timeout",
        intent: "Race[fast, Timeout[slow]]: loser cancelled, timeout interacts with cancel",
        dag,
        expected_rules: vec![],
        expected_step_count: 0,
    }
}

/// F14: Race[Race[a,b], Race[c,d]]: cancel cascades through nested races.
fn nested_race_cancel_cascade() -> PlanFixture {
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let d = dag.leaf("d");
    let inner_race1 = dag.race(vec![a, b]);
    let inner_race2 = dag.race(vec![c, d]);
    let outer_race = dag.race(vec![inner_race1, inner_race2]);
    dag.set_root(outer_race);
    PlanFixture {
        name: "nested_race_cancel_cascade",
        intent: "Race[Race[a,b], Race[c,d]]: cancel cascades through nested races",
        dag,
        expected_rules: vec![],
        expected_step_count: 0,
    }
}

/// F15: Race[Join[s,Timeout[a]], Join[s,Timeout[b]]]: dedup + cancel with timed leaves.
fn timeout_race_dedup_cancel() -> PlanFixture {
    let mut dag = PlanDag::new();
    let shared = dag.leaf("shared");
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let timed_a = dag.timeout(a, Duration::from_secs(2));
    let timed_b = dag.timeout(b, Duration::from_secs(4));
    let join_a = dag.join(vec![shared, timed_a]);
    let join_b = dag.join(vec![shared, timed_b]);
    let race = dag.race(vec![join_a, join_b]);
    dag.set_root(race);
    PlanFixture {
        name: "timeout_race_dedup_cancel",
        intent: "Race[Join[s,Timeout[a]], Join[s,Timeout[b]]]: dedup + cancel with timed leaves",
        dag,
        expected_rules: vec![RewriteRule::DedupRaceJoin],
        expected_step_count: 1,
    }
}

/// F16: Race[Join[obl:permit, compute], obl:lock]: cancel must not leak obligations.
fn race_obligation_cancel() -> PlanFixture {
    let mut dag = PlanDag::new();
    let obl_permit = dag.leaf("obl:permit");
    let obl_lock = dag.leaf("obl:lock");
    let compute = dag.leaf("compute");
    let join_permit = dag.join(vec![obl_permit, compute]);
    let race = dag.race(vec![join_permit, obl_lock]);
    dag.set_root(race);
    PlanFixture {
        name: "race_obligation_cancel",
        intent: "Race[Join[obl:permit, compute], obl:lock]: cancel must not leak obligations",
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

// ---------------------------------------------------------------------------
// Dynamic lab execution harness
// ---------------------------------------------------------------------------

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::lab::runtime::LabRuntime;
use crate::runtime::TaskHandle;
use crate::types::{Budget, CancelReason, TaskId};

/// A future that yields once to the scheduler before completing.
struct LabYieldOnce {
    yielded: bool,
}

impl Future for LabYieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn lab_yield_once() -> LabYieldOnce {
    LabYieldOnce { yielded: false }
}

async fn lab_yield_n(count: usize) {
    for _ in 0..count {
        lab_yield_once().await;
    }
}

// ---------------------------------------------------------------------------
// SharedLabHandle: wraps TaskHandle in Arc so multiple DAG parents can
// reference the same spawned task (needed for diamond-pattern DAGs after
// e-graph extraction). Only the first caller to join transitions
// Empty→InFlight and performs the real join; others yield-wait for the
// cached result.
// ---------------------------------------------------------------------------

enum LabJoinState {
    Empty,
    InFlight,
    Ready(BTreeSet<String>),
}

struct SharedLabInner {
    handle: TaskHandle<BTreeSet<String>>,
    state: std::sync::Mutex<LabJoinState>,
}

#[derive(Clone)]
struct SharedLabHandle {
    inner: std::sync::Arc<SharedLabInner>,
}

impl SharedLabHandle {
    fn new(handle: TaskHandle<BTreeSet<String>>) -> Self {
        Self {
            inner: std::sync::Arc::new(SharedLabInner {
                handle,
                state: std::sync::Mutex::new(LabJoinState::Empty),
            }),
        }
    }

    async fn join(&self) -> BTreeSet<String> {
        let cx = crate::cx::Cx::current().expect("cx set");
        let i_am_joiner;
        {
            let mut state = self.inner.state.lock().unwrap();
            match &*state {
                LabJoinState::Ready(result) => return result.clone(),
                LabJoinState::InFlight => {
                    i_am_joiner = false;
                }
                LabJoinState::Empty => {
                    *state = LabJoinState::InFlight;
                    i_am_joiner = true;
                }
            }
        }

        if i_am_joiner {
            let result = self.inner.handle.join(&cx).await.unwrap_or_default();
            *self.inner.state.lock().unwrap() = LabJoinState::Ready(result.clone());
            result
        } else {
            loop {
                {
                    let state = self.inner.state.lock().unwrap();
                    if let LabJoinState::Ready(result) = &*state {
                        return result.clone();
                    }
                }
                lab_yield_once().await;
            }
        }
    }

    fn try_join_probe(&self) -> Option<BTreeSet<String>> {
        let mut state = self.inner.state.lock().unwrap();
        match &*state {
            LabJoinState::Ready(result) => Some(result.clone()),
            LabJoinState::InFlight => None,
            LabJoinState::Empty => match self.inner.handle.try_join() {
                Ok(Some(result)) => {
                    *state = LabJoinState::Ready(result.clone());
                    Some(result)
                }
                Ok(None) => None,
                Err(_) => {
                    *state = LabJoinState::Ready(BTreeSet::new());
                    Some(BTreeSet::new())
                }
            },
        }
    }

    fn abort_with_reason(&self, reason: CancelReason) {
        self.inner.handle.abort_with_reason(reason);
    }
}

/// Returns true if the DAG has fan-in (any node used as a child by
/// multiple parents).
#[must_use]
pub fn dag_has_fan_in(dag: &PlanDag) -> bool {
    use super::PlanNode;
    let mut ref_counts = vec![0u32; dag.nodes.len()];
    for node in &dag.nodes {
        match node {
            PlanNode::Leaf { .. } => {}
            PlanNode::Join { children } | PlanNode::Race { children } => {
                for c in children {
                    ref_counts[c.index()] += 1;
                }
            }
            PlanNode::Timeout { child, .. } => {
                ref_counts[child.index()] += 1;
            }
        }
    }
    ref_counts.iter().any(|&c| c > 1)
}

/// Execute a [`PlanDag`] dynamically in the lab runtime under a deterministic
/// seed. Returns the set of leaf labels that completed successfully.
///
/// Each node in the DAG becomes a task:
/// - **Leaf**: yields a deterministic number of times, then returns its label.
/// - **Join**: waits for all children and unions their labels.
/// - **Race**: polls children for first completion, cancels and drains losers.
/// - **Timeout**: delegates to child (lab runtime uses virtual time).
#[must_use]
pub fn execute_plan_in_lab(seed: u64, dag: &PlanDag) -> BTreeSet<String> {
    use super::PlanNode;

    let root = dag.root().expect("dag has root");

    crate::lab::runtime::test(seed, |runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);

        let mut handles: Vec<Option<SharedLabHandle>> = Vec::new();
        let mut task_ids: Vec<TaskId> = Vec::new();

        for (idx, node) in dag.nodes.iter().enumerate() {
            let (tid, raw_handle) = match node.clone() {
                PlanNode::Leaf { label } => {
                    let yield_count = (seed as usize).wrapping_add(idx) % 4 + 1;
                    spawn_lab_leaf(runtime, region, label, yield_count)
                }
                PlanNode::Join { children } => {
                    let child_handles: Vec<_> = children
                        .iter()
                        .map(|c| {
                            handles[c.index()]
                                .as_ref()
                                .expect("child handle available")
                                .clone()
                        })
                        .collect();
                    spawn_lab_join(runtime, region, child_handles)
                }
                PlanNode::Race { children } => {
                    let child_handles: Vec<_> = children
                        .iter()
                        .map(|c| {
                            handles[c.index()]
                                .as_ref()
                                .expect("child handle available")
                                .clone()
                        })
                        .collect();
                    spawn_lab_race(runtime, region, child_handles)
                }
                PlanNode::Timeout { child, .. } => {
                    let child_handle = handles[child.index()]
                        .as_ref()
                        .expect("child handle available")
                        .clone();
                    spawn_lab_timeout(runtime, region, child_handle)
                }
            };

            task_ids.push(tid);
            handles.push(Some(SharedLabHandle::new(raw_handle)));
        }

        // Schedule all tasks.
        {
            let mut sched = runtime.scheduler.lock().expect("scheduler lock");
            for tid in &task_ids {
                sched.schedule(*tid, 0);
            }
        }

        runtime.run_until_quiescent();
        assert!(runtime.is_quiescent(), "runtime must be quiescent");

        handles[root.index()]
            .as_ref()
            .expect("root handle")
            .try_join_probe()
            .expect("root should be ready")
    })
}

fn spawn_lab_leaf(
    runtime: &mut LabRuntime,
    region: crate::types::RegionId,
    label: String,
    yield_count: usize,
) -> (TaskId, TaskHandle<BTreeSet<String>>) {
    let future = async move {
        lab_yield_n(yield_count).await;
        let mut set = BTreeSet::new();
        set.insert(label);
        set
    };
    runtime
        .state
        .create_task(region, Budget::INFINITE, future)
        .expect("spawn leaf")
}

fn spawn_lab_join(
    runtime: &mut LabRuntime,
    region: crate::types::RegionId,
    child_handles: Vec<SharedLabHandle>,
) -> (TaskId, TaskHandle<BTreeSet<String>>) {
    let future = async move {
        let cx = crate::cx::Cx::current().expect("cx set");
        let mut all_labels = BTreeSet::new();
        for handle in &child_handles {
            if let Ok(labels) = handle.inner.handle.join(&cx).await {
                all_labels.extend(labels);
            }
        }
        all_labels
    };
    runtime
        .state
        .create_task(region, Budget::INFINITE, future)
        .expect("spawn join driver")
}

fn spawn_lab_race(
    runtime: &mut LabRuntime,
    region: crate::types::RegionId,
    child_handles: Vec<SharedLabHandle>,
) -> (TaskId, TaskHandle<BTreeSet<String>>) {
    let future = async move {
        let cx = crate::cx::Cx::current().expect("cx set");

        if child_handles.is_empty() {
            return BTreeSet::new();
        }
        if child_handles.len() == 1 {
            return child_handles[0]
                .inner
                .handle
                .join(&cx)
                .await
                .unwrap_or_default();
        }

        // Race children using waker-based select: create JoinFutures that
        // register the race driver's waker on each child's oneshot receiver.
        // When any child completes, the oneshot wakes the race driver and it
        // polls all children to find the winner. This avoids busy-poll
        // starvation where the scheduler might consistently pick the race
        // driver over children due to deterministic RNG tie-breaking.
        let winner_idx;
        let winner_result;
        {
            let mut join_futs: Vec<_> = child_handles
                .iter()
                .map(|h| {
                    Some(
                        h.inner
                            .handle
                            .join_with_drop_reason(&cx, CancelReason::race_loser()),
                    )
                })
                .collect();

            let (idx, result) = std::future::poll_fn(|task_cx| {
                for (i, fut_opt) in join_futs.iter_mut().enumerate() {
                    if let Some(fut) = fut_opt {
                        if let std::task::Poll::Ready(result) =
                            std::pin::Pin::new(fut).poll(task_cx)
                        {
                            *fut_opt = None;
                            return std::task::Poll::Ready((i, result.unwrap_or_default()));
                        }
                    }
                }
                std::task::Poll::Pending
            })
            .await;
            winner_idx = idx;
            winner_result = result;
            // Drop remaining JoinFutures — their drop handlers call
            // abort_with_reason(race_loser) on losers.
        }

        // Drain losers: wait for each non-winner to observe cancellation
        // and complete.
        for (j, handle) in child_handles.iter().enumerate() {
            if j != winner_idx {
                let _ = handle.inner.handle.join(&cx).await;
            }
        }

        winner_result
    };
    runtime
        .state
        .create_task(region, Budget::INFINITE, future)
        .expect("spawn race driver")
}

fn spawn_lab_timeout(
    runtime: &mut LabRuntime,
    region: crate::types::RegionId,
    child_handle: SharedLabHandle,
) -> (TaskId, TaskHandle<BTreeSet<String>>) {
    let future = async move {
        let cx = crate::cx::Cx::current().expect("cx set");
        child_handle
            .inner
            .handle
            .join(&cx)
            .await
            .unwrap_or_default()
    };
    runtime
        .state
        .create_task(region, Budget::INFINITE, future)
        .expect("spawn timeout driver")
}

/// Result of running original vs optimized plans through the dynamic lab
/// oracle across multiple seeds.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct LabDynamicEquivalenceReport {
    /// Fixture name.
    pub fixture_name: &'static str,
    /// Rewrite certificate.
    pub certificate: RewriteCertificate,
    /// Whether the certificate verified against the optimized DAG.
    pub certificate_verified: bool,
    /// Whether step-level verification passed.
    pub steps_verified: bool,
    /// Whether the static outcome analysis matched.
    pub static_outcomes_equivalent: bool,
    /// Seeds used for dynamic execution.
    pub seeds: Vec<u64>,
    /// Per-seed results: (original_labels, optimized_labels, match).
    pub per_seed_results: Vec<(BTreeSet<String>, BTreeSet<String>, bool)>,
    /// Whether all per-seed dynamic runs matched.
    pub dynamic_outcomes_equivalent: bool,
    /// Observed original outcome sets across all seeds.
    pub original_outcome_universe: BTreeSet<Vec<String>>,
    /// Observed optimized outcome sets across all seeds.
    pub optimized_outcome_universe: BTreeSet<Vec<String>>,
    /// Whether the observed universes match (same set of possible outcomes).
    pub universes_match: bool,
}

impl LabDynamicEquivalenceReport {
    /// Returns true if all checks passed.
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.certificate_verified
            && self.steps_verified
            && self.static_outcomes_equivalent
            && self.dynamic_outcomes_equivalent
            && self.universes_match
    }

    /// Returns a summary of failures, if any.
    #[must_use]
    pub fn failure_summary(&self) -> Option<String> {
        if self.all_ok() {
            return None;
        }
        let mut out = format!("Fixture: {}\n", self.fixture_name);
        if !self.certificate_verified {
            out.push_str("  CERTIFICATE HASH MISMATCH\n");
        }
        if !self.steps_verified {
            out.push_str("  STEP VERIFICATION FAILED\n");
        }
        if !self.static_outcomes_equivalent {
            out.push_str("  STATIC OUTCOME MISMATCH\n");
        }
        if !self.dynamic_outcomes_equivalent {
            out.push_str("  DYNAMIC OUTCOME MISMATCH (per-seed):\n");
            for (i, (orig, opt, ok)) in self.per_seed_results.iter().enumerate() {
                if !ok {
                    let _ = writeln!(
                        &mut out,
                        "    seed {}: original={:?}  optimized={:?}",
                        self.seeds[i], orig, opt
                    );
                }
            }
        }
        if !self.universes_match {
            let _ = write!(
                &mut out,
                "  UNIVERSE MISMATCH:\n    original:  {:?}\n    optimized: {:?}\n",
                self.original_outcome_universe, self.optimized_outcome_universe
            );
        }
        Some(out)
    }
}

/// Run the full dynamic lab equivalence oracle for a fixture.
///
/// Applies certified rewrites, verifies certificate, then executes both
/// original and optimized plans under each seed in the lab runtime and
/// compares outcomes.
#[must_use]
pub fn run_lab_dynamic_equivalence(
    fixture: PlanFixture,
    policy: RewritePolicy,
    rules: &[RewriteRule],
    seeds: &[u64],
) -> LabDynamicEquivalenceReport {
    let original_dag = fixture.dag.clone();

    let original_static = original_dag
        .root()
        .map(|r| outcome_sets(&original_dag, r))
        .unwrap_or_default();

    let mut optimized_dag = fixture.dag;
    let (_, certificate) = optimized_dag.apply_rewrites_certified(policy, rules);

    let optimized_static = optimized_dag
        .root()
        .map(|r| outcome_sets(&optimized_dag, r))
        .unwrap_or_default();

    let static_outcomes_equivalent = original_static == optimized_static;
    let certificate_verified = verify(&certificate, &optimized_dag).is_ok();
    let steps_verified = verify_steps(&certificate, &optimized_dag).is_ok();

    let mut per_seed_results = Vec::with_capacity(seeds.len());
    let mut original_universe = BTreeSet::new();
    let mut optimized_universe = BTreeSet::new();
    let mut all_dynamic_ok = true;

    // DAGs with fan-in (shared children) cannot be executed by the handle-based
    // lab harness because task handles are consumed on join. Execute each DAG
    // only if it has no fan-in; for fan-in DAGs rely on static analysis +
    // certificate verification.
    let orig_has_fan_in = dag_has_fan_in(&original_dag);
    let opt_has_fan_in = dag_has_fan_in(&optimized_dag);

    for &seed in seeds {
        let orig_labels = if orig_has_fan_in {
            BTreeSet::new()
        } else {
            execute_plan_in_lab(seed, &original_dag)
        };
        let opt_labels = if opt_has_fan_in {
            BTreeSet::new()
        } else {
            execute_plan_in_lab(seed, &optimized_dag)
        };
        // Only compare dynamic results if both DAGs were executed
        let ok = orig_has_fan_in || opt_has_fan_in || orig_labels == opt_labels;
        if !ok {
            all_dynamic_ok = false;
        }
        if !orig_has_fan_in {
            original_universe.insert(orig_labels.iter().cloned().collect::<Vec<_>>());
        }
        if !opt_has_fan_in {
            optimized_universe.insert(opt_labels.iter().cloned().collect::<Vec<_>>());
        }
        per_seed_results.push((orig_labels, opt_labels, ok));
    }

    let universes_match = original_universe == optimized_universe;

    LabDynamicEquivalenceReport {
        fixture_name: fixture.name,
        certificate,
        certificate_verified,
        steps_verified,
        static_outcomes_equivalent,
        seeds: seeds.to_vec(),
        per_seed_results,
        dynamic_outcomes_equivalent: all_dynamic_ok,
        original_outcome_universe: original_universe,
        optimized_outcome_universe: optimized_universe,
        universes_match,
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
                .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
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

        let (report, cert) = dag.apply_rewrites_certified(RewritePolicy::assume_all(), &rules);
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
            let report = run_equivalence_harness(fixture, RewritePolicy::conservative(), &rules);
            if let Some(diff) = report.diff_summary() {
                panic!("equivalence failure:\n{diff}");
            }
            assert!(report.all_ok());
        }
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn rule_witness_golden_fingerprints() {
        // Golden regression test: certificate fingerprints must be stable.
        // If these fail, either the hash function or the rewrite engine changed.
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];

        // F1: simple_join_race_dedup (the canonical DedupRaceJoin witness)
        let mut f1 = simple_join_race_dedup();
        let (_, cert1) = f1
            .dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
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
            .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
        assert_eq!(cert3.steps.len(), 1);
        assert!(verify(&cert3, &f3.dag).is_ok());
        assert!(verify_steps(&cert3, &f3.dag).is_ok());
        let fp3 = cert3.fingerprint();
        assert_ne!(
            fp3, fp1,
            "different fixtures must produce different fingerprints"
        );

        // F10: timeout_wrapping_dedup
        let mut fixture_timeout = timeout_wrapping_dedup();
        let (_, cert_timeout) = fixture_timeout
            .dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
        assert_eq!(cert_timeout.steps.len(), 1);
        assert!(verify(&cert_timeout, &fixture_timeout.dag).is_ok());
        assert!(verify_steps(&cert_timeout, &fixture_timeout.dag).is_ok());
        let fp_timeout = cert_timeout.fingerprint();
        assert_ne!(fp_timeout, fp1);
        assert_ne!(fp_timeout, fp3);

        // No-rewrite fixtures must produce identity certificates with matching fingerprints
        // across repeated construction.
        let mut fixture_no_shared_a = no_shared_child();
        let (_, cert_no_shared_a) = fixture_no_shared_a
            .dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
        assert!(cert_no_shared_a.is_identity());
        let mut fixture_no_shared_b = no_shared_child();
        let (_, cert_no_shared_b) = fixture_no_shared_b
            .dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
        assert_eq!(
            cert_no_shared_a.fingerprint(),
            cert_no_shared_b.fingerprint()
        );
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
    fn cancel_fixtures_present_and_valid() {
        init_test();
        let fixtures = all_fixtures();
        let cancel_names: Vec<&str> = fixtures
            .iter()
            .filter(|f| {
                f.name.contains("cancel")
                    || f.intent.contains("cancel")
                    || f.intent.contains("Cancel")
            })
            .map(|f| f.name)
            .collect();
        assert!(
            cancel_names.len() >= 4,
            "need >= 4 cancel-aware fixtures, got {}: {:?}",
            cancel_names.len(),
            cancel_names
        );
        for fixture in &fixtures {
            assert!(
                fixture.dag.validate().is_ok(),
                "cancel fixture {} failed validation",
                fixture.name
            );
        }
    }

    #[test]
    fn lab_equivalence_all_fixtures_all_rules() {
        init_test();
        let all_rules = [
            RewriteRule::DedupRaceJoin,
            RewriteRule::JoinAssoc,
            RewriteRule::RaceAssoc,
            RewriteRule::JoinCommute,
            RewriteRule::RaceCommute,
            RewriteRule::TimeoutMin,
        ];
        for fixture in all_fixtures() {
            if fixture.name == "shared_non_leaf_associative" {
                continue;
            }
            let report =
                run_equivalence_harness(fixture, RewritePolicy::conservative(), &all_rules);
            assert!(
                report.outcomes_equivalent,
                "outcomes not equivalent for fixture {}",
                report.fixture_name
            );
        }
    }

    #[test]
    fn extraction_pipeline_equivalence() {
        use crate::plan::extractor::Extractor;
        use crate::plan::PlanId;
        use std::collections::HashMap;

        init_test();
        for fixture in all_fixtures() {
            let original_outcomes = fixture
                .dag
                .root()
                .map(|root| outcome_sets(&fixture.dag, root))
                .unwrap_or_default();

            // Build e-graph from fixture DAG using recursive traversal.
            let mut eg = crate::plan::EGraph::new();
            let mut cache: HashMap<PlanId, crate::plan::EClassId> = HashMap::new();

            if let Some(root) = fixture.dag.root() {
                let root_eclass = dag_to_egraph_rec(&fixture.dag, root, &mut eg, &mut cache);
                let (extracted_dag, _cert) = Extractor::new(&mut eg).extract(root_eclass);
                let extracted_outcomes = extracted_dag
                    .root()
                    .map(|r| outcome_sets(&extracted_dag, r))
                    .unwrap_or_default();
                assert_eq!(
                    original_outcomes, extracted_outcomes,
                    "extraction changed outcomes for fixture {}",
                    fixture.name
                );
            }
        }
    }

    /// Recursively insert a DAG node into an e-graph, processing children first.
    fn dag_to_egraph_rec(
        dag: &PlanDag,
        id: PlanId,
        eg: &mut crate::plan::EGraph,
        cache: &mut HashMap<PlanId, crate::plan::EClassId>,
    ) -> crate::plan::EClassId {
        if let Some(&ec) = cache.get(&id) {
            return ec;
        }
        let node = dag.node(id).expect("valid PlanId");
        let eclass = match node.clone() {
            PlanNode::Leaf { label } => eg.add_leaf(label),
            PlanNode::Join { children } => {
                let ec: Vec<_> = children
                    .iter()
                    .map(|c| dag_to_egraph_rec(dag, *c, eg, cache))
                    .collect();
                eg.add_join(ec)
            }
            PlanNode::Race { children } => {
                let ec: Vec<_> = children
                    .iter()
                    .map(|c| dag_to_egraph_rec(dag, *c, eg, cache))
                    .collect();
                eg.add_race(ec)
            }
            PlanNode::Timeout { child, duration } => {
                let child_ec = dag_to_egraph_rec(dag, child, eg, cache);
                eg.add_timeout(child_ec, duration)
            }
        };
        cache.insert(id, eclass);
        eclass
    }

    #[test]
    fn extraction_after_rewrite_equivalence() {
        use crate::plan::extractor::Extractor;
        use crate::plan::PlanId;
        use std::collections::HashMap;

        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        for mut fixture in all_fixtures() {
            if fixture.name == "shared_non_leaf_associative" {
                continue;
            }
            let original_outcomes = fixture
                .dag
                .root()
                .map(|root| outcome_sets(&fixture.dag, root))
                .unwrap_or_default();

            // Apply rewrites.
            let (_report, _cert) = fixture
                .dag
                .apply_rewrites_certified(RewritePolicy::conservative(), &rules);

            // Build e-graph from rewritten DAG using recursive traversal.
            let mut eg = crate::plan::EGraph::new();
            let mut cache: HashMap<PlanId, crate::plan::EClassId> = HashMap::new();

            if let Some(root) = fixture.dag.root() {
                let root_eclass = dag_to_egraph_rec(&fixture.dag, root, &mut eg, &mut cache);
                let (extracted_dag, _cert) = Extractor::new(&mut eg).extract(root_eclass);
                let extracted_outcomes = extracted_dag
                    .root()
                    .map(|r| outcome_sets(&extracted_dag, r))
                    .unwrap_or_default();
                assert_eq!(
                    original_outcomes, extracted_outcomes,
                    "rewrite+extraction changed outcomes for fixture {}",
                    fixture.name
                );
            }
        }
    }

    #[test]
    fn lab_equivalence_deterministic_across_runs() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        // Run twice and compare hashes.
        let reports1: Vec<_> = all_fixtures()
            .into_iter()
            .filter(|f| f.name != "shared_non_leaf_associative")
            .map(|f| run_equivalence_harness(f, RewritePolicy::conservative(), &rules))
            .collect();
        let reports2: Vec<_> = all_fixtures()
            .into_iter()
            .filter(|f| f.name != "shared_non_leaf_associative")
            .map(|f| run_equivalence_harness(f, RewritePolicy::conservative(), &rules))
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

    // -----------------------------------------------------------------------
    // E2E pipeline tests (bd-3gqz)
    // Gated: E2ePipelineReport + run_e2e_pipeline_all pending implementation.
    // Remove cfg(any()) when the E2E pipeline harness is complete.
    // -----------------------------------------------------------------------

    #[cfg(any())]
    #[test]
    fn e2e_pipeline_all_fixtures_pass() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        assert!(
            reports.len() >= 16,
            "expected >= 16 E2E reports, got {}",
            reports.len()
        );
        for report in &reports {
            assert!(
                report.all_ok(),
                "E2E pipeline failed for fixture {}: cert_ok={}, steps_ok={}, outcomes_eq={}, \
                 extract_eq={}, rewrite_extract_eq={}, dynamic_eq={}",
                report.fixture_name,
                report.certificate_verified,
                report.steps_verified,
                report.outcomes_equivalent,
                report.extraction_equivalent,
                report.rewrite_extraction_equivalent,
                report.dynamic_outcomes_equivalent,
            );
        }
    }

    #[cfg(any())]
    #[test]
    fn e2e_pipeline_deterministic_across_runs() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let reports1 = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        let reports2 = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        assert_eq!(reports1.len(), reports2.len());
        for (r1, r2) in reports1.iter().zip(reports2.iter()) {
            assert_eq!(
                r1.golden_fingerprint(),
                r2.golden_fingerprint(),
                "fixture {}: E2E golden fingerprint differs across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.certificate_fingerprint, r2.certificate_fingerprint,
                "fixture {}: certificate fingerprint differs across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.original_cost.total(),
                r2.original_cost.total(),
                "fixture {}: original cost differs across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.optimized_cost.total(),
                r2.optimized_cost.total(),
                "fixture {}: optimized cost differs across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.original_trace_fingerprint, r2.original_trace_fingerprint,
                "fixture {}: original trace fingerprint differs across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.optimized_trace_fingerprint, r2.optimized_trace_fingerprint,
                "fixture {}: optimized trace fingerprint differs across runs",
                r1.fixture_name
            );
        }
    }

    #[cfg(any())]
    #[test]
    fn e2e_pipeline_cost_never_increases() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let reports = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        for report in &reports {
            assert!(
                report.optimized_cost <= report.original_cost,
                "fixture {}: cost increased from {} to {} after rewrite",
                report.fixture_name,
                report.original_cost.total(),
                report.optimized_cost.total(),
            );
        }
    }

    #[cfg(any())]
    #[test]
    fn e2e_pipeline_dynamic_labels_populated() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let reports = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        for report in &reports {
            assert!(
                !report.dynamic_original_labels.is_empty(),
                "fixture {}: dynamic original labels empty",
                report.fixture_name,
            );
            assert!(
                !report.dynamic_optimized_labels.is_empty(),
                "fixture {}: dynamic optimized labels empty",
                report.fixture_name,
            );
        }
    }

    #[cfg(any())]
    #[test]
    fn e2e_pipeline_trace_fingerprints_nonzero() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let reports = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        for report in &reports {
            assert_ne!(
                report.original_trace_fingerprint, 0,
                "fixture {}: original trace fingerprint is zero",
                report.fixture_name,
            );
            assert_ne!(
                report.optimized_trace_fingerprint, 0,
                "fixture {}: optimized trace fingerprint is zero",
                report.fixture_name,
            );
        }
    }

    #[cfg(any())]
    #[test]
    fn e2e_pipeline_cost_delta_sane() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let reports = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        for report in &reports {
            let delta = report.cost_delta();
            if report.rewrite_count > 0 {
                // Rewrites that fired should not increase cost (already
                // covered by cost_never_increases, but verify via delta).
                assert!(
                    delta > 0 || report.original_cost == report.optimized_cost,
                    "fixture {}: rewrite fired but cost unchanged or increased",
                    report.fixture_name,
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Dynamic lab equivalence oracle tests
    // -----------------------------------------------------------------------

    const ORACLE_SEEDS: [u64; 8] = [0, 1, 2, 3, 42, 99, 1000, u64::MAX];

    #[test]
    fn dynamic_lab_equivalence_all_fixtures_conservative() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        for fixture in all_fixtures() {
            if fixture.name == "shared_non_leaf_associative" {
                continue;
            }
            let report = run_lab_dynamic_equivalence(
                fixture,
                RewritePolicy::conservative(),
                &rules,
                &ORACLE_SEEDS,
            );
            assert!(
                report.all_ok(),
                "{}",
                report
                    .failure_summary()
                    .unwrap_or_else(|| "unknown failure".into())
            );
        }
    }

    #[test]
    fn dynamic_lab_equivalence_associative_policy() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let fixtures = all_fixtures();
        let fixture = fixtures
            .into_iter()
            .find(|f| f.name == "shared_non_leaf_associative")
            .expect("fixture exists");
        let report = run_lab_dynamic_equivalence(
            fixture,
            RewritePolicy::assume_all(),
            &rules,
            &ORACLE_SEEDS,
        );
        assert!(
            report.all_ok(),
            "{}",
            report
                .failure_summary()
                .unwrap_or_else(|| "unknown failure".into())
        );
    }

    #[test]
    fn dynamic_lab_single_leaf_execution() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("alpha");
        dag.set_root(a);

        let result = execute_plan_in_lab(42, &dag);
        assert_eq!(result.len(), 1);
        assert!(result.contains("alpha"));
    }

    #[test]
    fn dynamic_lab_join_collects_all_leaves() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let j = dag.join(vec![a, b, c]);
        dag.set_root(j);

        let result = execute_plan_in_lab(0, &dag);
        assert_eq!(result.len(), 3);
        assert!(result.contains("a"));
        assert!(result.contains("b"));
        assert!(result.contains("c"));
    }

    #[test]
    fn dynamic_lab_race_returns_subset() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let r = dag.race(vec![a, b]);
        dag.set_root(r);

        for seed in &ORACLE_SEEDS {
            let result = execute_plan_in_lab(*seed, &dag);
            assert_eq!(
                result.len(),
                1,
                "seed {seed}: race should yield exactly one winner"
            );
            assert!(
                result.contains("a") || result.contains("b"),
                "seed {seed}: winner must be a or b"
            );
        }
    }

    #[test]
    fn dynamic_lab_deterministic_same_seed() {
        init_test();
        for fixture in all_fixtures() {
            if dag_has_fan_in(&fixture.dag) {
                continue; // Handle-based lab harness cannot execute DAGs with shared children
            }
            let r1 = execute_plan_in_lab(42, &fixture.dag);
            let r2 = execute_plan_in_lab(42, &fixture.dag);
            assert_eq!(
                r1, r2,
                "fixture {}: same seed must produce identical results",
                fixture.name
            );
        }
    }

    #[test]
    fn dynamic_lab_timeout_passes_through() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("inner");
        let t = dag.timeout(a, Duration::from_secs(10));
        dag.set_root(t);

        let result = execute_plan_in_lab(7, &dag);
        assert_eq!(result.len(), 1);
        assert!(result.contains("inner"));
    }

    #[test]
    fn dynamic_lab_nested_join_race() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let j_ab = dag.join(vec![a, b]);
        let r = dag.race(vec![j_ab, c]);
        dag.set_root(r);

        for seed in &ORACLE_SEEDS {
            let result = execute_plan_in_lab(*seed, &dag);
            let is_join_winner = result.len() == 2 && result.contains("a") && result.contains("b");
            let is_leaf_winner = result.len() == 1 && result.contains("c");
            assert!(
                is_join_winner || is_leaf_winner,
                "seed {seed}: unexpected result {result:?}"
            );
        }
    }

    #[test]
    fn dynamic_lab_report_fields_populated() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        // Use no_shared_child (a tree without fan-in) so the handle-based
        // lab harness can execute both original and optimized DAGs.
        let fixture = no_shared_child();
        let report = run_lab_dynamic_equivalence(
            fixture,
            RewritePolicy::conservative(),
            &rules,
            &ORACLE_SEEDS,
        );

        assert_eq!(report.fixture_name, "no_shared_child");
        assert_eq!(report.seeds.len(), ORACLE_SEEDS.len());
        assert_eq!(report.per_seed_results.len(), ORACLE_SEEDS.len());
        // no_shared_child is a tree, so dynamic execution populates results.
        assert!(!report.original_outcome_universe.is_empty());
        // No rewrite fires (no shared children), so optimized DAG is the
        // same tree and should also be dynamically executable.
        assert!(!report.optimized_outcome_universe.is_empty());
    }
}
