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
use asupersync::combinator::race::{race2_outcomes, RaceWinner};
use asupersync::lab::oracle::OracleViolation;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::RuntimeState;
use asupersync::trace::format::{GoldenTraceConfig, GoldenTraceFixture};
use asupersync::trace::TraceEvent;
use asupersync::types::{Budget, CancelKind, CancelReason, Outcome, Severity, Time};
use asupersync::util::Arena;
use std::hash::{DefaultHasher, Hash, Hasher};

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
    runtime.scheduler.lock().unwrap().schedule(t1, 0);
    runtime.scheduler.lock().unwrap().schedule(t2, 0);
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

#[test]
fn golden_trace_fixture_lab() {
    let fixture = build_golden_trace_fixture(0xBEEF);
    assert_golden_trace_fixture(
        "golden_trace_fixture_lab",
        &fixture,
        GOLDEN_TRACE_FIXTURE_LAB,
    );
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
