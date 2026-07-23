#![allow(warnings)]
#![allow(clippy::all)]
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
//!   1. Run `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_golden_outputs cargo test --test golden_outputs -- --nocapture`
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
use asupersync::plan::fixtures::{all_fixtures, outcome_sets};
use asupersync::plan::{PlanDag, PlanId, PlanNode, RewritePolicy};
use asupersync::runtime::RuntimeState;
use asupersync::runtime::{JoinError, TaskHandle, yield_now};
use asupersync::trace::TraceEvent;
use asupersync::trace::event::{TraceData, TraceEventKind as RuntimeTraceEventKind};
use asupersync::trace::format::{GoldenTraceConfig, GoldenTraceFixture};
use asupersync::types::{
    Budget, CancelKind, CancelReason, Outcome, RegionId, Severity, TaskId, Time,
};
use asupersync::util::Arena;
use conformance::logging::{TestEvent, TestEventKind};
use conformance::report::render_console_summary;
use conformance::runner::{SuiteResult, SuiteTestResult};
use conformance::{Checkpoint, TestCategory, TestResult};
use futures_lite::future;
use insta::{assert_debug_snapshot, assert_snapshot};
use parking_lot::Mutex;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

// ============================================================================
// Checksum helper
// ============================================================================

/// Compute a cross-toolchain-stable checksum from a sequence of `u64` values.
///
/// The domain marker and explicit little-endian framing are part of the golden
/// contract. The first 64 bits keep the historical compact display format;
/// SHA-256 makes the bytes independent of `std`'s intentionally unspecified
/// `DefaultHasher` implementation.
fn checksum(values: &[u64]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.golden-u64.v1");
    hasher.update(
        u64::try_from(values.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for value in values {
        hasher.update(value.to_le_bytes());
    }
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 prefix is 8 bytes"))
}

fn stable_json_digest(value: &impl serde::Serialize) -> String {
    let encoded = serde_json::to_vec(value).expect("serialize stable golden receipt");
    let digest = Sha256::digest(encoded);
    hex::encode(digest)
}

fn stable_plan_trace_digest(trace: &GoldenTraceFixture) -> String {
    // `GoldenTraceFixture::fingerprint` is a compact runtime lookup key. Pin
    // the actual serialized trace contract here with SHA-256 instead: config,
    // event count, canonical event prefix, and oracle verdicts.
    stable_json_digest(&json!({
        "schema_version": trace.schema_version,
        "config": &trace.config,
        "event_count": trace.event_count,
        "canonical_prefix": &trace.canonical_prefix,
        "oracle_summary": &trace.oracle_summary,
    }))
}

fn oracle_violation_tag(violation: &OracleViolation) -> &'static str {
    match violation {
        OracleViolation::TaskLeak(_) => "TaskLeak",
        OracleViolation::ObligationLeak(_) => "ObligationLeak",
        OracleViolation::Quiescence(_) => "Quiescence",
        OracleViolation::LoserDrain(_) => "LoserDrain",
        OracleViolation::Finalizer(_) => "Finalizer",
        OracleViolation::RegionTree(_) => "RegionTree",
        OracleViolation::RegionLeak(_) => "RegionLeak",
        OracleViolation::AmbientAuthority(_) => "AmbientAuthority",
        OracleViolation::DeadlineMonotone(_) => "DeadlineMonotone",
        OracleViolation::CancellationProtocol(_) => "CancellationProtocol",
        OracleViolation::CancelCorrectness(_) => "CancelCorrectness",
        OracleViolation::CancelDebt(_) => "CancelDebt",
        OracleViolation::CancelOrdering(_) => "CancelOrdering",
        OracleViolation::RuntimeEpoch(_) => "RuntimeEpoch",
        OracleViolation::ChannelAtomicity(_) => "ChannelAtomicity",
        OracleViolation::WakerDedup(_) => "WakerDedup",
        OracleViolation::ActorLeak(_) => "ActorLeak",
        OracleViolation::Supervision(_) => "Supervision",
        OracleViolation::Mailbox(_) => "Mailbox",
        OracleViolation::RRefAccess(_) => "RRefAccess",
        OracleViolation::ReplyLinearity(_) => "ReplyLinearity",
        OracleViolation::RegistryLease(_) => "RegistryLease",
        OracleViolation::DownOrder(_) => "DownOrder",
        OracleViolation::SupervisorQuiescence(_) => "SupervisorQuiescence",
        OracleViolation::PriorityInversion(_) => "PriorityInversion",
        #[cfg(feature = "messaging-fabric")]
        OracleViolation::FabricPublish(_) => "FabricPublish",
        #[cfg(feature = "messaging-fabric")]
        OracleViolation::FabricReply(_) => "FabricReply",
        #[cfg(feature = "messaging-fabric")]
        OracleViolation::FabricQuiescence(_) => "FabricQuiescence",
        #[cfg(feature = "messaging-fabric")]
        OracleViolation::FabricRedelivery(_) => "FabricRedelivery",
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
    assert_golden("outcome_severity_lattice", cs, 0xE180_EB72_306A_2BAC);
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
    assert_golden("budget_combine_semiring", cs, 0xDF9D_D68F_C9EC_3694);
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
    assert_golden("cancel_reason_strengthen", cs, 0x5043_3370_4DE8_7FDC);
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
    assert_golden("arena_insert_remove_cycle", cs, 0xC865_5E8C_82A2_704D);
}

// ============================================================================
// Golden: Runtime state operations
// ============================================================================

#[test]
fn golden_runtime_state_region_lifecycle() {
    let mut state = RuntimeState::new();

    let r1 = state.create_root_region(Budget::INFINITE);
    let r2 = state
        .create_child_region(
            r1,
            Budget::new()
                .with_deadline(Time::from_secs(10))
                .with_poll_quota(5000),
        )
        .unwrap();
    let _r3 = state.create_child_region(r1, Budget::INFINITE).unwrap();

    let cancel_effects = state.cancel_request(r2, &CancelReason::timeout(), None);
    // This owned-state fixture has no scheduler or installed Wakers.
    let (cancelled, wake_effects) = cancel_effects.into_parts();
    wake_effects.dispatch();

    let cs = checksum(&[
        state.live_region_count() as u64,
        state.live_task_count() as u64,
        cancelled.len() as u64,
        u64::from(state.is_quiescent()),
    ]);
    assert_golden("runtime_state_region_lifecycle", cs, 0xAF3C_9BE4_8F6F_72CE);
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

    assert_golden("lab_runtime_deterministic", trace1, 0xDEEA_BFC7_6E0C_37E0);
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
  "fingerprint": 5286518520354602670,
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
        "primary": 17841621336708427690,
        "secondary": 0,
        "tertiary": 0
      },
      {
        "kind": 29,
        "primary": 17841621336708427690,
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

struct PlanRewriteGolden {
    name: &'static str,
    seed: u64,
    steps: &'static str,
    before_hash: &'static str,
    after_hash: &'static str,
    certificate_fingerprint: &'static str,
}

const PLAN_REWRITE_GOLDENS: &[PlanRewriteGolden] = &[
    PlanRewriteGolden {
        name: "simple_join_race_dedup",
        seed: 10_000,
        steps: "DedupRaceJoin:5->7",
        before_hash: "9ab853b5bb73b95ab9b307e02357fb8e898496b7d3413557f419c0e7069e8e95",
        after_hash: "0cffa48607f55c8b136238a76fec2d8707a9fa8956a76be5c74b163cefb665d1",
        certificate_fingerprint: "76d3485657bf9a913513dcb613198117dcaa1a3997bb6dc2afb92ecc61bbd34e",
    },
    PlanRewriteGolden {
        name: "nested_timeout_join_race",
        seed: 10_002,
        steps: "DedupRaceJoin:5->8",
        before_hash: "439f8048051846cdce752e3ffe259b0431f8d44ced1fd180f0dd986a65996dc0",
        after_hash: "26fd6ec1de81e172840dc39a0b9ab57f0e367a4d1c9bc076168cd66a8dd64f59",
        certificate_fingerprint: "4636b36fb4b81e1908aeb87b11228bcc7b0b36232fa27e7cbb3f21306c7a59b6",
    },
    PlanRewriteGolden {
        name: "shared_non_leaf_associative",
        seed: 10_007,
        steps: "DedupRaceJoin:7->9",
        before_hash: "e491f8bcc017c9fbd2b4566804bc0ab4ef84ce71b017b25c9eaa9267fd5c203f",
        after_hash: "00982263e2b81be4953f0f44314f5719e53b16938c8d85a273f2d5d5c53d33fe",
        certificate_fingerprint: "aa18580c8a1922640ba0d12801e6082d47576471baf189b0ec7efe1815743999",
    },
    PlanRewriteGolden {
        name: "timeout_wrapping_dedup",
        seed: 10_009,
        steps: "DedupRaceJoin:5->10",
        before_hash: "3f58fb0f84f8fdfca9dcc7e163bcd7a98297b8ec21ff457b1631f975534d84b6",
        after_hash: "896aca7fd80cd912ed06ba80ce1b700340294ee11984edf3acc987748039def0",
        certificate_fingerprint: "843b0b37ef6d14371e0bdea54e7822a7ae5e838e0c28d771580d3a8aafd45a5a",
    },
    PlanRewriteGolden {
        name: "timeout_race_dedup_cancel",
        seed: 10_014,
        steps: "DedupRaceJoin:7->9",
        before_hash: "3cc3fbe70d9e32b9bfb820ee379944c7d87125dce6a71449de1cabf1c4093794",
        after_hash: "70830f3ef46567d026a951e51569ccae42223c952372def529f6d70331f79525",
        certificate_fingerprint: "e4eeb5a5a07c05c568f776e22251f130e50f610e910f7a532dc5a6b083c6cb78",
    },
];

fn plan_rewrite_golden(name: &str) -> &'static PlanRewriteGolden {
    PLAN_REWRITE_GOLDENS
        .iter()
        .find(|golden| golden.name == name)
        .unwrap_or_else(|| panic!("missing real plan-rewrite golden receipt for {name}"))
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
    let mut covered_rewrite_fixtures = BTreeSet::new();
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
        assert_eq!(
            cert.before_hash,
            asupersync::plan::certificate::PlanHash::of(&original),
            "fixture {}: certificate must hash the actual input plan",
            fixture.name
        );
        assert_eq!(
            cert.after_hash,
            asupersync::plan::certificate::PlanHash::of(&rewritten),
            "fixture {}: certificate must hash the actual rewritten plan",
            fixture.name
        );

        let (original_trace, original_result) =
            build_plan_trace_fixture(seed, &original, fixture.name);
        let (rewritten_trace, rewritten_result) =
            build_plan_trace_fixture(seed, &rewritten, fixture.name);

        assert!(
            original_trace.oracle_summary.violations.is_empty(),
            "fixture {}: original plan trace has oracle violations",
            fixture.name
        );
        assert!(
            rewritten_trace.oracle_summary.violations.is_empty(),
            "fixture {}: rewritten plan trace has oracle violations",
            fixture.name
        );

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
        } else {
            let expected = plan_rewrite_golden(fixture.name);
            assert_eq!(seed, expected.seed, "fixture {}: seed drift", fixture.name);
            assert_ne!(
                cert.before_hash, cert.after_hash,
                "fixture {}: claimed rewrite must change the plan hash",
                fixture.name
            );
            let steps = report
                .steps()
                .iter()
                .map(|step| {
                    format!(
                        "{:?}:{}->{}",
                        step.rule,
                        step.before.index(),
                        step.after.index()
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            assert_eq!(
                steps, expected.steps,
                "fixture {}: rewrite-step drift",
                fixture.name
            );
            assert_eq!(
                cert.before_hash.to_hex(),
                expected.before_hash,
                "fixture {}: input plan checksum drift",
                fixture.name
            );
            assert_eq!(
                cert.after_hash.to_hex(),
                expected.after_hash,
                "fixture {}: rewritten plan checksum drift",
                fixture.name
            );
            assert_eq!(
                cert.fingerprint().to_hex(),
                expected.certificate_fingerprint,
                "fixture {}: certificate checksum drift",
                fixture.name
            );

            let original_static = outcome_sets(&original, original.root().expect("original root"));
            let rewritten_static =
                outcome_sets(&rewritten, rewritten.root().expect("rewritten root"));
            assert_eq!(
                original_static, rewritten_static,
                "fixture {}: rewrite changed the static result set",
                fixture.name
            );
            let original_labels = original_result.iter().cloned().collect::<Vec<_>>();
            let rewritten_labels = rewritten_result.iter().cloned().collect::<Vec<_>>();
            assert!(
                original_static.contains(&original_labels),
                "fixture {}: original runtime result escaped the static contract",
                fixture.name
            );
            assert!(
                rewritten_static.contains(&rewritten_labels),
                "fixture {}: rewritten runtime result escaped the static contract",
                fixture.name
            );
            assert_ne!(
                stable_plan_trace_digest(&original_trace),
                stable_plan_trace_digest(&rewritten_trace),
                "fixture {}: real rewrite must produce a distinct trace receipt",
                fixture.name
            );
            assert!(
                covered_rewrite_fixtures.insert(fixture.name),
                "fixture {}: duplicate rewrite coverage",
                fixture.name
            );
        }
    }

    assert_eq!(
        covered_rewrite_fixtures.len(),
        PLAN_REWRITE_GOLDENS.len(),
        "every reviewed rewrite golden must execute exactly once"
    );
    for expected in PLAN_REWRITE_GOLDENS {
        assert!(
            covered_rewrite_fixtures.contains(expected.name),
            "golden receipt {} did not execute",
            expected.name
        );
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
            let mut handle_guard = self.inner.handle.lock();
            let handle = handle_guard.as_mut()?;
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

#[test]
fn snapshot_trace_fixture_seed_7_pretty_json() {
    let fixture = build_golden_trace_fixture(7);
    let json = serde_json::to_string_pretty(&fixture).expect("serialize trace fixture");

    assert_snapshot!("trace_fixture_seed_7_pretty_json", json);
}

#[test]
fn snapshot_trace_tla_region_obligation_behavior() {
    let events = [
        TraceEvent::region_created(1, Time::ZERO, RegionId::new_for_test(1, 0), None),
        TraceEvent::spawn(
            2,
            Time::from_nanos(5),
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::obligation_reserve(
            3,
            Time::from_nanos(8),
            asupersync::types::ObligationId::new_for_test(1, 0),
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
            asupersync::record::ObligationKind::SendPermit,
        ),
        TraceEvent::obligation_commit(
            4,
            Time::from_nanos(13),
            asupersync::types::ObligationId::new_for_test(1, 0),
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
            asupersync::record::ObligationKind::SendPermit,
            64,
        ),
        TraceEvent::complete(
            5,
            Time::from_nanos(21),
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::new(
            6,
            Time::from_nanos(34),
            RuntimeTraceEventKind::RegionCloseComplete,
            TraceData::Region {
                region: RegionId::new_for_test(1, 0),
                parent: None,
            },
        ),
    ];
    let module = asupersync::trace::tla_export::TlaExporter::from_trace(&events)
        .export_behavior("GoldenTraceBehavior");

    assert_snapshot!("trace_tla_region_obligation_behavior", module.source);
}

#[test]
fn snapshot_plan_compact_certificate_dedup_race_join() {
    let mut dag = PlanDag::new();
    let shared = dag.leaf("shared");
    let left = dag.leaf("left");
    let right = dag.leaf("right");
    let join_a = dag.join(vec![shared, left]);
    let join_b = dag.join(vec![shared, right]);
    let race = dag.race(vec![join_a, join_b]);
    dag.set_root(race);

    let (_rewritten, cert) = dag.apply_rewrites_certified(
        RewritePolicy::conservative(),
        &[asupersync::plan::rewrite::RewriteRule::DedupRaceJoin],
    );
    let compact = cert
        .minimize()
        .compact()
        .expect("compact certificate fits snapshot wire format");

    assert_debug_snapshot!("plan_compact_certificate_dedup_race_join", compact);
}

#[test]
fn snapshot_conformance_console_summary_scrubbed_durations() {
    let summary = SuiteResult {
        runtime_name: "golden-runtime".to_string(),
        total: 2,
        passed: 1,
        failed: 1,
        skipped: 0,
        duration_ms: 37,
        results: vec![
            SuiteTestResult {
                test_id: "spawn.basic".to_string(),
                test_name: "spawns a task".to_string(),
                category: TestCategory::Spawn,
                expected: "spawn completes successfully".to_string(),
                result: TestResult::passed()
                    .with_checkpoint(Checkpoint::new("after_spawn", json!({"task": 1})))
                    .with_duration(11),
                events: vec![TestEvent::new(
                    TestEventKind::Phase,
                    "spawned",
                    3,
                    json!({"region": 1}),
                )],
            },
            SuiteTestResult {
                test_id: "cancel.propagation".to_string(),
                test_name: "propagates cancellation".to_string(),
                category: TestCategory::Cancel,
                expected: "child sees cancellation reason".to_string(),
                result: TestResult::failed("child task never observed cancellation")
                    .with_duration(26),
                events: vec![TestEvent::new(
                    TestEventKind::Assertion,
                    "cancel_reason_missing",
                    19,
                    json!({"task": 7}),
                )],
            },
        ],
    };
    let rendered = render_console_summary(&summary);
    assert_snapshot!("conformance_console_summary_scrubbed_durations", rendered);
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

    let r1 = lab.state.create_root_region(Budget::INFINITE);
    let r2 = lab
        .state
        .create_child_region(
            r1,
            Budget::new()
                .with_deadline(Time::from_secs(5))
                .with_poll_quota(1000),
        )
        .unwrap();
    let _r3 = lab.state.create_child_region(r1, Budget::INFINITE).unwrap();

    let cancel_effects = lab.state.cancel_request(r2, &CancelReason::timeout(), None);
    // This region-only fixture has no scheduled tasks or installed Wakers.
    let (_cancelled, wake_effects) = cancel_effects.into_parts();
    wake_effects.dispatch();

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
    assert_golden("join_outcome_aggregation", cs, 0x280E_8891_E969_8970);
}

#[test]
fn golden_race_outcome_aggregation() {
    let o_ok: Outcome<i32, ()> = Outcome::Ok(42);
    let o_cancel: Outcome<i32, ()> = Outcome::Cancelled(CancelReason::new(CancelKind::RaceLost));

    let (r1, _, _) = race2_outcomes(RaceWinner::First, o_ok.clone(), o_cancel.clone());
    let (r2, _, _) = race2_outcomes(RaceWinner::Second, o_cancel, o_ok);

    let cs = checksum(&[r1.severity() as u64, r2.severity() as u64]);
    assert_golden("race_outcome_aggregation", cs, 0xE737_01C1_F1CD_AB7F);
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
    assert_golden("time_arithmetic", cs, 0xA1C4_630F_B3E2_E63F);
}
