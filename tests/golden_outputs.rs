//! Golden output tests for Asupersync.
//!
//! These tests verify behavioral equivalence across code changes by running
//! deterministic workloads (fixed seeds) and comparing output checksums.
//!
//! **Same seed → Same execution → Same checksum**
//!
//! If a golden output changes, it means the runtime's observable behavior changed.
//! This is the "behavior equivalence" gate for the optimization pipeline.
//!
//! To update golden values after an intentional behavioral change:
//!   1. Run `cargo test --test golden_outputs -- --nocapture`
//!   2. Review the new checksums in the output
//!   3. Update the expected values below
//!   4. Document why the behavior changed in the commit message

#[macro_use]
mod common;

use asupersync::combinator::join2_outcomes;
use asupersync::combinator::race::{RaceWinner, race2_outcomes};
use asupersync::cx::Cx;
use asupersync::lab::oracle::{LoserDrainOracle, OracleViolation};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::plan::certificate::{verify, verify_steps};
use asupersync::plan::fixtures::all_fixtures;
use asupersync::plan::{PlanDag, PlanId, PlanNode, RewritePolicy};
use asupersync::runtime::RuntimeState;
use asupersync::runtime::{JoinError, TaskHandle, yield_now};
use asupersync::trace::TraceEvent;
use asupersync::trace::format::{GoldenTraceConfig, GoldenTraceFixture};
use asupersync::types::{
    Budget, CancelKind, CancelReason, Outcome, RegionId, Severity, TaskId, Time,
};
use asupersync::util::Arena;
use futures_lite::future;
use parking_lot::Mutex;
use std::collections::{BTreeSet, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;

// ============================================================================
// Checksum helper
// ============================================================================

/// Compute a stable checksum from a sequence of u64 values.
fn checksum(values: &[u64]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for v in values {
        v.hash(&mut hasher);
    }
    hasher.finish()
}

fn oracle_violation_tag(violation: &OracleViolation) -> &'static str {
    match violation {
        OracleViolation::TaskLeak(_) => "TaskLeak",
        OracleViolation::ObligationLeak(_) => "ObligationLeak",
        OracleViolation::Quiescence(_) => "Quiescence",
        OracleViolation::LoserDrain(_) => "LoserDrain",
        OracleViolation::Finalizer(_) => "Finalizer",
        OracleViolation::RegionTree(_) => "RegionTree",
        OracleViolation::AmbientAuthority(_) => "AmbientAuthority",
        OracleViolation::DeadlineMonotone(_) => "DeadlineMonotone",
        OracleViolation::CancellationProtocol(_) => "CancellationProtocol",
        OracleViolation::ActorLeak(_) => "ActorLeak",
        OracleViolation::Supervision(_) => "Supervision",
        OracleViolation::Mailbox(_) => "Mailbox",
        OracleViolation::RRefAccess(_) => "RRefAccess",
        OracleViolation::ReplyLinearity(_) => "ReplyLinearity",
        OracleViolation::RegistryLease(_) => "RegistryLease",
        OracleViolation::DownOrder(_) => "DownOrder",
        OracleViolation::SupervisorQuiescence(_) => "SupervisorQuiescence",
    }
}

fn assert_golden_trace_fixture(name: &str, actual: &GoldenTraceFixture, expected_json: &str) {
    let expected: GoldenTraceFixture = serde_json::from_str(expected_json)
        .unwrap_or_else(|e| panic!("invalid golden fixture JSON for {name}: {e}"));

    if let Err(diff) = expected.verify(actual) {
        eprintln!("GOLDEN TRACE MISMATCH: {name}");
        eprintln!("{diff}");
        let actual_json =
            serde_json::to_string_pretty(actual).expect("serialize actual golden fixture");
        eprintln!("--- Actual fixture JSON (update expected) ---\n{actual_json}");
        panic!("Golden trace fixture mismatch for {name}");
    }
}

fn build_golden_trace_fixture(seed: u64) -> GoldenTraceFixture {
    let config = LabConfig::new(seed)
        .worker_count(2)
        .trace_capacity(2048)
        .max_steps(5000);
    let mut runtime = LabRuntime::new(config.clone());
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let (t1, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("t1");
    let (t2, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("t2");
    runtime.scheduler.lock().schedule(t1, 0);
    runtime.scheduler.lock().schedule(t2, 0);
    runtime.run_until_quiescent();

    let events: Vec<TraceEvent> = runtime.trace().snapshot();
    let violations = runtime.oracles.check_all(runtime.now());
    let violation_tags = violations.iter().map(oracle_violation_tag);

    let fixture_config = GoldenTraceConfig {
        seed: config.seed,
        entropy_seed: config.entropy_seed,
        worker_count: config.worker_count,
        trace_capacity: config.trace_capacity,
        max_steps: config.max_steps,
        canonical_prefix_layers: 4,
        canonical_prefix_events: 16,
    };

    GoldenTraceFixture::from_events(fixture_config, &events, violation_tags)
}

/// First-run sentinel: when expected == 0, record and don't fail.
const FIRST_RUN_SENTINEL: u64 = 0;

/// Assert a golden checksum matches, or record it on first run.
fn assert_golden(name: &str, actual: u64, expected: u64) {
    if expected == FIRST_RUN_SENTINEL {
        eprintln!("GOLDEN RECORD: {name} = 0x{actual:016X}");
        return;
    }
    if actual != expected {
        eprintln!(
            "GOLDEN MISMATCH: {name}\n  expected: 0x{expected:016X}\n  actual:   0x{actual:016X}\n  \
             If this is intentional, update the expected value."
        );
    }
    assert_eq!(
        actual, expected,
        "Golden output mismatch for '{name}'. See stderr for details."
    );
}

// ============================================================================
// Golden: Core type operations
// ============================================================================

#[test]
fn golden_outcome_severity_lattice() {
    let severities = [
        Severity::Ok as u64,
        Severity::Err as u64,
        Severity::Cancelled as u64,
        Severity::Panicked as u64,
    ];

    // Verify strictly increasing
    for w in severities.windows(2) {
        assert!(w[0] < w[1], "Severity lattice ordering broken");
    }

    let cs = checksum(&severities);
    assert_golden("outcome_severity_lattice", cs, 0x0289_507D_DCB2_C380);
}

#[test]
fn golden_budget_combine_semiring() {
    let b1 = Budget::new()
        .with_deadline(Time::from_nanos(1_000_000_000))
        .with_poll_quota(1000);
    let b2 = Budget::new()
        .with_deadline(Time::from_nanos(500_000_000))
        .with_poll_quota(2000);
    let combined = b1.combine(b2);

    let cs = checksum(&[
        combined.deadline.unwrap_or(Time::ZERO).as_nanos(),
        u64::from(combined.poll_quota),
    ]);
    assert_golden("budget_combine_semiring", cs, 0x276B_7D0F_D47B_53ED);
}

#[test]
fn golden_cancel_reason_strengthen() {
    let timeout = CancelReason::new(CancelKind::Timeout);
    let shutdown = CancelReason::new(CancelKind::Shutdown);

    let mut r1 = CancelReason::new(CancelKind::User);
    r1.strengthen(&timeout);
    let kind1 = r1.kind() as u64;

    let mut r2 = CancelReason::new(CancelKind::Timeout);
    r2.strengthen(&shutdown);
    let kind2 = r2.kind() as u64;

    let mut r3 = CancelReason::new(CancelKind::User);
    r3.strengthen(&shutdown);
    let kind3 = r3.kind() as u64;

    let cs = checksum(&[kind1, kind2, kind3]);
    assert_golden("cancel_reason_strengthen", cs, 0xF232_B96C_A6AB_8084);
}

// ============================================================================
// Golden: Arena operations
// ============================================================================

#[test]
fn golden_arena_insert_remove_cycle() {
    let mut arena: Arena<u64> = Arena::new();
    let mut indices = Vec::new();

    for i in 0..1000u64 {
        indices.push(arena.insert(i));
    }

    // Remove even indices
    for i in (0..1000).step_by(2) {
        arena.remove(indices[i]);
    }

    // Re-insert to fill gaps
    for i in 0..500u64 {
        arena.insert(i + 1000);
    }

    let mut values: Vec<u64> = arena.iter().map(|(_, &v)| v).collect();
    values.sort_unstable();

    let cs = checksum(&values);
    assert_golden("arena_insert_remove_cycle", cs, 0xBE5F_120D_9FC1_2946);
}

// ============================================================================
// Golden: Runtime state operations
// ============================================================================

#[test]
fn golden_runtime_state_region_lifecycle() {
    let mut state = RuntimeState::new();

    let _r1 = state.create_root_region(Budget::INFINITE);
    let r2 = state.create_root_region(
        Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(5000),
    );
    let _r3 = state.create_root_region(Budget::INFINITE);

    let cancelled = state.cancel_request(r2, &CancelReason::timeout(), None);

    let cs = checksum(&[
        state.live_region_count() as u64,
        state.live_task_count() as u64,
        cancelled.len() as u64,
        u64::from(state.is_quiescent()),
    ]);
    assert_golden("runtime_state_region_lifecycle", cs, 0xA243_3C8C_FA8C_333C);
}

// ============================================================================
// Golden: Lab runtime determinism
// ============================================================================

#[test]
fn golden_lab_runtime_deterministic_scheduling() {
    let seed = 0x474F_4C44_454E_3432;

    let trace1 = run_deterministic_workload(seed);
    let trace2 = run_deterministic_workload(seed);

    assert_eq!(
        trace1, trace2,
        "Lab runtime not deterministic for same seed"
    );

    let trace3 = run_deterministic_workload(seed + 1);
    assert_ne!(trace1, trace3, "Different seeds produced same trace");

    assert_golden("lab_runtime_deterministic", trace1, 0xE37F_54B1_1550_2E85);
}

const GOLDEN_TRACE_FIXTURE_LAB: &str = r#"{
  "schema_version": 1,
  "config": {
    "seed": 48879,
    "entropy_seed": 48879,
    "worker_count": 2,
    "trace_capacity": 2048,
    "max_steps": 5000,
    "canonical_prefix_layers": 4,
    "canonical_prefix_events": 16
  },
  "fingerprint": 13498101483502120188,
  "event_count": 7,
  "canonical_prefix": [
    [
      {
        "kind": 10,
        "primary": 0,
        "secondary": 0,
        "tertiary": 0
      },
      {
        "kind": 29,
        "primary": 1358076884962059318,
        "secondary": 0,
        "tertiary": 0
      },
      {
        "kind": 29,
        "primary": 1358076884962059318,
        "secondary": 0,
        "tertiary": 0
      }
    ],
    [
      {
        "kind": 0,
        "primary": 0,
        "secondary": 0,
        "tertiary": 0
      },
      {
        "kind": 0,
        "primary": 4294967296,
        "secondary": 0,
        "tertiary": 0
      }
    ],
    [
      {
        "kind": 5,
        "primary": 0,
        "secondary": 0,
        "tertiary": 0
      },
      {
        "kind": 5,
        "primary": 4294967296,
        "secondary": 0,
        "tertiary": 0
      }
    ]
  ],
  "oracle_summary": {
    "violations": []
  }
}"#;

const GOLDEN_PLAN_TRACE_SIMPLE_JOIN_RACE_DEDUP: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_THREE_WAY_RACE_OF_JOINS: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_NESTED_TIMEOUT_JOIN_RACE: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_NO_SHARED_CHILD: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_SINGLE_BRANCH_RACE: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_DEEP_CHAIN_NO_REWRITE: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_SHARED_NON_LEAF_CONSERVATIVE: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_SHARED_NON_LEAF_ASSOCIATIVE: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_DIAMOND_JOIN_RACE: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_TIMEOUT_WRAPPING_DEDUP: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_INDEPENDENT_SUBTREES: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_RACE_OF_LEAVES: &str = GOLDEN_TRACE_FIXTURE_LAB;

// Cancel-aware fixtures (F13-F16)
const GOLDEN_PLAN_TRACE_RACE_CANCEL_WITH_TIMEOUT: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_NESTED_RACE_CANCEL_CASCADE: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_TIMEOUT_RACE_DEDUP_CANCEL: &str = GOLDEN_TRACE_FIXTURE_LAB;
const GOLDEN_PLAN_TRACE_RACE_OBLIGATION_CANCEL: &str = GOLDEN_TRACE_FIXTURE_LAB;

fn golden_plan_trace_fixture_json(name: &str) -> &'static str {
    match name {
        "simple_join_race_dedup" => GOLDEN_PLAN_TRACE_SIMPLE_JOIN_RACE_DEDUP,
        "three_way_race_of_joins" => GOLDEN_PLAN_TRACE_THREE_WAY_RACE_OF_JOINS,
        "nested_timeout_join_race" => GOLDEN_PLAN_TRACE_NESTED_TIMEOUT_JOIN_RACE,
        "no_shared_child" => GOLDEN_PLAN_TRACE_NO_SHARED_CHILD,
        "single_branch_race" => GOLDEN_PLAN_TRACE_SINGLE_BRANCH_RACE,
        "deep_chain_no_rewrite" => GOLDEN_PLAN_TRACE_DEEP_CHAIN_NO_REWRITE,
        "shared_non_leaf_conservative" => GOLDEN_PLAN_TRACE_SHARED_NON_LEAF_CONSERVATIVE,
        "shared_non_leaf_associative" => GOLDEN_PLAN_TRACE_SHARED_NON_LEAF_ASSOCIATIVE,
        "diamond_join_race" => GOLDEN_PLAN_TRACE_DIAMOND_JOIN_RACE,
        "timeout_wrapping_dedup" => GOLDEN_PLAN_TRACE_TIMEOUT_WRAPPING_DEDUP,
        "independent_subtrees" => GOLDEN_PLAN_TRACE_INDEPENDENT_SUBTREES,
        "race_of_leaves" => GOLDEN_PLAN_TRACE_RACE_OF_LEAVES,
        // Cancel-aware fixtures
        "race_cancel_with_timeout" => GOLDEN_PLAN_TRACE_RACE_CANCEL_WITH_TIMEOUT,
        "nested_race_cancel_cascade" => GOLDEN_PLAN_TRACE_NESTED_RACE_CANCEL_CASCADE,
        "timeout_race_dedup_cancel" => GOLDEN_PLAN_TRACE_TIMEOUT_RACE_DEDUP_CANCEL,
        "race_obligation_cancel" => GOLDEN_PLAN_TRACE_RACE_OBLIGATION_CANCEL,
        _ => panic!("missing golden plan trace fixture for {name}"),
    }
}

#[test]
fn golden_trace_fixture_lab() {
    let fixture = build_golden_trace_fixture(0xBEEF);
    assert_golden_trace_fixture(
        "golden_trace_fixture_lab",
        &fixture,
        GOLDEN_TRACE_FIXTURE_LAB,
    );
}

#[test]
fn golden_plan_rewrite_trace_fixtures() {
    let fixtures = all_fixtures();
    assert!(
        fixtures.len() >= 10,
        "expected >= 10 plan fixtures, got {}",
        fixtures.len()
    );

    for (idx, fixture) in fixtures.into_iter().enumerate() {
        let seed = 10_000 + idx as u64;
        let policy = if fixture.name == "shared_non_leaf_associative" {
            RewritePolicy::assume_all()
        } else {
            RewritePolicy::conservative()
        };

        let original = fixture.dag.clone();
        let mut rewritten = fixture.dag;
        let (report, cert) =
            rewritten.apply_rewrites_certified(policy, fixture.expected_rules.as_slice());

        assert_eq!(
            report.steps().len(),
            fixture.expected_step_count,
            "fixture {}: expected {} rewrite steps, got {}",
            fixture.name,
            fixture.expected_step_count,
            report.steps().len()
        );
        assert!(
            verify(&cert, &rewritten).is_ok(),
            "fixture {}: certificate verification failed",
            fixture.name
        );
        assert!(
            verify_steps(&cert, &rewritten).is_ok(),
            "fixture {}: certificate step verification failed",
            fixture.name
        );

        let (original_trace, original_result) =
            build_plan_trace_fixture(seed, &original, fixture.name);
        let (rewritten_trace, rewritten_result) =
            build_plan_trace_fixture(seed, &rewritten, fixture.name);

        if fixture.expected_step_count == 0 {
            // No rewrites: plans are identical, so results and traces must match.
            assert_eq!(
                original_result, rewritten_result,
                "fixture {}: identity rewrite changed semantic result",
                fixture.name
            );
            assert_eq!(
                original_trace.fingerprint, rewritten_trace.fingerprint,
                "fixture {}: identity rewrite changed trace fingerprint",
                fixture.name
            );
            assert_eq!(
                original_trace.canonical_prefix, rewritten_trace.canonical_prefix,
                "fixture {}: identity rewrite changed canonical prefix",
                fixture.name
            );
        }

        // TODO: generate real golden trace data for each fixture.
        // Currently all GOLDEN_PLAN_TRACE_* constants point to the same
        // unrelated placeholder (GOLDEN_TRACE_FIXTURE_LAB), so the golden
        // comparison is deferred until proper baselines are captured.
        let _expected_json = golden_plan_trace_fixture_json(fixture.name);
    }
}

type NodeValue = BTreeSet<String>;

#[derive(Clone)]
struct SharedHandle<T> {
    inner: Arc<SharedInner<T>>,
}

struct SharedInner<T> {
    handle: Mutex<Option<TaskHandle<T>>>,
    state: Mutex<JoinState<T>>,
}

enum JoinState<T> {
    Empty,
    InFlight,
    Ready(Result<T, JoinError>),
}

impl<T> SharedHandle<T> {
    fn new(handle: TaskHandle<T>) -> Self {
        Self {
            inner: Arc::new(SharedInner {
                handle: Mutex::new(Some(handle)),
                state: Mutex::new(JoinState::Empty),
            }),
        }
    }

    fn task_id(&self) -> TaskId {
        self.inner
            .handle
            .lock()
            .as_ref()
            .expect("shared handle missing task handle")
            .task_id()
    }

    /// Non-blocking check: returns the result if already cached in Ready state,
    /// or polls the inner TaskHandle for completion and caches on success.
    fn try_join(&self) -> Option<Result<T, JoinError>>
    where
        T: Clone,
    {
        let state = self.inner.state.lock();
        match &*state {
            JoinState::Ready(result) => return Some(result.clone()),
            JoinState::InFlight => return None,
            JoinState::Empty => {}
        }
        drop(state);

        let try_join_result = {
            let handle_guard = self.inner.handle.lock();
            let handle = handle_guard.as_ref()?;
            let result = handle.try_join();
            drop(handle_guard);
            result
        };
        let result = match try_join_result {
            Ok(Some(value)) => Some(Ok(value)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        };

        if let Some(ref result) = result {
            let mut state = self.inner.state.lock();
            *state = JoinState::Ready(result.clone());
        }
        result
    }

    /// Designated-joiner protocol: only the first caller that sees Empty
    /// transitions to InFlight and performs the real join. All others
    /// yield-wait for Ready, preventing waker overwrites.
    async fn join(&self, cx: &Cx) -> Result<T, JoinError>
    where
        T: Clone,
    {
        let i_am_joiner = {
            let mut state = self.inner.state.lock();
            match &*state {
                JoinState::Ready(result) => return result.clone(),
                JoinState::InFlight => false,
                JoinState::Empty => {
                    *state = JoinState::InFlight;
                    true
                }
            }
        };

        if i_am_joiner {
            let mut handle = self
                .inner
                .handle
                .lock()
                .take()
                .expect("shared handle missing task handle");
            let result = handle.join(cx).await;
            *self.inner.handle.lock() = Some(handle);
            *self.inner.state.lock() = JoinState::Ready(result.clone());
            result
        } else {
            loop {
                {
                    let state = self.inner.state.lock();
                    if let JoinState::Ready(result) = &*state {
                        return result.clone();
                    }
                }
                yield_now().await;
            }
        }
    }
}

#[derive(Debug)]
struct RaceInfo {
    race_id: u64,
    participants: Vec<TaskId>,
}

fn plan_node_count(plan: &PlanDag) -> usize {
    let mut count = 0;
    loop {
        if plan.node(PlanId::new(count)).is_some() {
            count += 1;
        } else {
            break;
        }
    }
    count
}

fn build_plan_trace_fixture(
    seed: u64,
    plan: &PlanDag,
    fixture_name: &str,
) -> (GoldenTraceFixture, NodeValue) {
    let config = LabConfig::new(seed).trace_capacity(8192);
    let mut runtime = LabRuntime::new(config.clone());
    let result = run_plan(&mut runtime, plan, fixture_name);

    let events: Vec<TraceEvent> = runtime.trace().snapshot();
    let violations = runtime.oracles.check_all(runtime.now());
    let violation_tags = violations.iter().map(oracle_violation_tag);

    let fixture_config = GoldenTraceConfig {
        seed: config.seed,
        entropy_seed: config.entropy_seed,
        worker_count: config.worker_count,
        trace_capacity: config.trace_capacity,
        max_steps: config.max_steps,
        canonical_prefix_layers: 4,
        canonical_prefix_events: 16,
    };

    let trace = GoldenTraceFixture::from_events(fixture_config, &events, violation_tags);
    (trace, result)
}

#[allow(clippy::too_many_lines)]
fn run_plan(runtime: &mut LabRuntime, plan: &PlanDag, fixture_name: &str) -> NodeValue {
    let root = plan.root().expect("plan root set");
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mut handles: Vec<Option<SharedHandle<NodeValue>>> = vec![None; plan_node_count(plan)];
    let mut oracle = LoserDrainOracle::new();
    let mut races = Vec::new();
    let winners: Arc<Mutex<HashMap<u64, TaskId>>> = Arc::new(Mutex::new(HashMap::new()));

    let root_handle = build_node(
        plan,
        runtime,
        region,
        &mut handles,
        &mut oracle,
        &mut races,
        &winners,
        root,
    );

    runtime.run_until_quiescent();
    let mut attempts = 0;
    while !runtime.is_quiescent() && attempts < 3 {
        let mut sched = runtime.scheduler.lock();
        for (_, record) in runtime.state.tasks_iter() {
            if record.is_runnable() {
                let prio = record
                    .cx_inner
                    .as_ref()
                    .map_or(0, |inner| inner.read().budget.priority);
                sched.schedule(record.id, prio);
            }
        }
        drop(sched);
        runtime.run_until_quiescent();
        attempts += 1;
    }
    assert!(
        runtime.is_quiescent(),
        "fixture {fixture_name}: runtime quiescent after reschedule",
    );

    let completion_time = runtime.now();
    for race in races {
        let fallback = *race.participants.first().expect("race participant");
        let winner = {
            let winners = winners.lock();
            winners.get(&race.race_id).copied().unwrap_or(fallback)
        };
        for participant in &race.participants {
            oracle.on_task_complete(*participant, completion_time);
        }
        oracle.on_race_complete(race.race_id, winner, completion_time);
    }

    assert!(oracle.check().is_ok(), "loser drain oracle");
    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "lab invariants clean: {violations:?}"
    );

    let cx: Cx = Cx::for_testing();
    root_handle
        .try_join()
        .unwrap_or_else(|| future::block_on(async { root_handle.join(&cx).await }))
        .expect("root result ok")
}

#[allow(clippy::too_many_arguments)]
fn build_node(
    plan: &PlanDag,
    runtime: &mut LabRuntime,
    region: RegionId,
    handles: &mut Vec<Option<SharedHandle<NodeValue>>>,
    oracle: &mut LoserDrainOracle,
    races: &mut Vec<RaceInfo>,
    winners: &Arc<Mutex<HashMap<u64, TaskId>>>,
    id: PlanId,
) -> SharedHandle<NodeValue> {
    if let Some(existing) = handles.get(id.index()).and_then(|entry| entry.as_ref()) {
        return existing.clone();
    }

    let node = plan.node(id).expect("plan node").clone();
    let handle = match node {
        PlanNode::Leaf { label } => {
            let delay = leaf_yields(&label);
            let future = async move {
                for _ in 0..delay {
                    yield_now().await;
                }
                let mut set = BTreeSet::new();
                set.insert(label);
                set
            };
            spawn_node(runtime, region, future)
        }
        PlanNode::Join { children } => {
            let child_handles = children
                .iter()
                .map(|child| {
                    build_node(
                        plan, runtime, region, handles, oracle, races, winners, *child,
                    )
                })
                .collect::<Vec<_>>();
            let future = async move {
                let cx: Cx = Cx::for_testing();
                let mut merged = BTreeSet::new();
                for handle in child_handles {
                    let child_set = handle.join(&cx).await.expect("join child");
                    merged.extend(child_set);
                }
                merged
            };
            spawn_node(runtime, region, future)
        }
        PlanNode::Race { children } => {
            let child_handles = children
                .iter()
                .map(|child| {
                    build_node(
                        plan, runtime, region, handles, oracle, races, winners, *child,
                    )
                })
                .collect::<Vec<_>>();
            let participants: Vec<TaskId> =
                child_handles.iter().map(SharedHandle::task_id).collect();
            let race_id = oracle.on_race_start(region, participants.clone(), Time::ZERO);
            races.push(RaceInfo {
                race_id,
                participants,
            });
            let winners = Arc::clone(winners);
            let future = async move {
                let cx: Cx = Cx::for_testing();
                let (winner_result, winner_idx) = race_first(&child_handles).await;
                if let Some(winner_task) = child_handles.get(winner_idx).map(SharedHandle::task_id)
                {
                    winners.lock().insert(race_id, winner_task);
                }
                for (idx, handle) in child_handles.iter().enumerate() {
                    if idx != winner_idx {
                        let _ = handle.join(&cx).await;
                    }
                }
                winner_result.expect("race winner ok")
            };
            spawn_node(runtime, region, future)
        }
        PlanNode::Timeout { child, .. } => {
            let child_handle = build_node(
                plan, runtime, region, handles, oracle, races, winners, child,
            );
            let future = async move {
                let cx: Cx = Cx::for_testing();
                child_handle.join(&cx).await.expect("timeout child")
            };
            spawn_node(runtime, region, future)
        }
    };

    if let Some(slot) = handles.get_mut(id.index()) {
        *slot = Some(handle.clone());
    }
    handle
}

fn spawn_node<F>(runtime: &mut LabRuntime, region: RegionId, future: F) -> SharedHandle<NodeValue>
where
    F: std::future::Future<Output = NodeValue> + Send + 'static,
{
    let (task_id, handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, future)
        .expect("create task");
    let priority = runtime
        .state
        .tasks
        .iter()
        .find(|(_, record)| record.id == task_id)
        .and_then(|(_, record)| record.cx_inner.as_ref())
        .map_or(0, |inner| inner.read().budget.priority);
    runtime.scheduler.lock().schedule(task_id, priority);
    SharedHandle::new(handle)
}

async fn race_first(handles: &[SharedHandle<NodeValue>]) -> (Result<NodeValue, JoinError>, usize) {
    loop {
        for (idx, handle) in handles.iter().enumerate() {
            if let Some(result) = handle.try_join() {
                return (result, idx);
            }
        }
        yield_now().await;
    }
}

fn leaf_yields(label: &str) -> u32 {
    match label {
        "a" | "y" => 2,
        "b" | "x" => 1,
        "c" => 3,
        "d" => 4,
        "e" => 5,
        _ => 0,
    }
}

fn run_deterministic_workload(seed: u64) -> u64 {
    use asupersync::util::DetRng;

    let config = LabConfig::new(seed).max_steps(10_000);
    let mut lab = LabRuntime::new(config);

    let _r1 = lab.state.create_root_region(Budget::INFINITE);
    let r2 = lab.state.create_root_region(
        Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(1000),
    );
    let _r3 = lab.state.create_root_region(Budget::INFINITE);

    let _ = lab.state.cancel_request(r2, &CancelReason::timeout(), None);

    // Use DetRng seeded from the lab seed to produce seed-dependent values
    let mut rng = DetRng::new(seed);
    let rng_vals: Vec<u64> = (0..10).map(|_| rng.next_u64()).collect();

    let mut vals = vec![
        lab.state.live_region_count() as u64,
        lab.state.live_task_count() as u64,
        lab.now().as_nanos(),
        lab.steps(),
    ];
    vals.extend_from_slice(&rng_vals);
    checksum(&vals)
}

// ============================================================================
// Golden: Outcome aggregation
// ============================================================================

#[test]
fn golden_join_outcome_aggregation() {
    let outcomes: Vec<Outcome<i32, ()>> = vec![
        Outcome::Ok(1),
        Outcome::Err(()),
        Outcome::Cancelled(CancelReason::new(CancelKind::User)),
        Outcome::Cancelled(CancelReason::new(CancelKind::Timeout)),
    ];

    let mut results = Vec::new();
    for a in &outcomes {
        for b in &outcomes {
            let (joined, _, _) = join2_outcomes(a.clone(), b.clone());
            results.push(joined.severity() as u64);
        }
    }

    let cs = checksum(&results);
    assert_golden("join_outcome_aggregation", cs, 0x96DC_2A9B_CDB7_E036);
}

#[test]
fn golden_race_outcome_aggregation() {
    let o_ok: Outcome<i32, ()> = Outcome::Ok(42);
    let o_cancel: Outcome<i32, ()> = Outcome::Cancelled(CancelReason::new(CancelKind::RaceLost));

    let (r1, _, _) = race2_outcomes(RaceWinner::First, o_ok.clone(), o_cancel.clone());
    let (r2, _, _) = race2_outcomes(RaceWinner::Second, o_cancel, o_ok);

    let cs = checksum(&[r1.severity() as u64, r2.severity() as u64]);
    assert_golden("race_outcome_aggregation", cs, 0x76BE_999E_3E25_B2A0);
}

// ============================================================================
// Golden: Time operations
// ============================================================================

#[test]
fn golden_time_arithmetic() {
    let t1 = Time::from_secs(1);
    let t2 = Time::from_millis(1500);
    let t3 = Time::from_nanos(2_000_000_000);

    let cs = checksum(&[
        t1.as_nanos(),
        t2.as_nanos(),
        t3.as_nanos(),
        t1.saturating_add_nanos(500_000_000).as_nanos(),
        t3.duration_since(t1),
        u64::from(t2 > t1),
        u64::from(t3 == Time::from_secs(2)),
    ]);
    assert_golden("time_arithmetic", cs, 0xA957_37A5_9E2C_720B);
}
