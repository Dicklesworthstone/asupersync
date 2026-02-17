//! End-to-end geodesic normalization harness (bd-1i1w).
//!
//! Proves geodesic normalization works in practice by exercising:
//!   trace capture → poset build → normalization (exact/heuristic) → deterministic report
//!
//! Acceptance criteria:
//! - Running twice yields byte-identical JSON reports (given same seed/config).
//! - For at least one scenario, switch cost strictly decreases vs baseline.
//! - Golden checksums catch regressions automatically.

#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::lab::oracle::OracleViolation;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::ObligationKind;
use asupersync::trace::canonicalize::canonicalize;
use asupersync::trace::event_structure::{OwnerKey, TracePoset};
use asupersync::trace::{geodesic_normalize, GeodesicAlgorithm, GeodesicConfig, TraceEvent};
use asupersync::types::{Budget, CancelReason, Time};
use serde::{Deserialize, Serialize};
use std::hash::{DefaultHasher, Hash, Hasher};

// ============================================================================
// Report structure
// ============================================================================

/// Deterministic report for a single normalization scenario.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ScenarioReport {
    name: String,
    seed: u64,
    event_count: usize,
    original_switches: usize,
    normalized_switches: usize,
    switch_reduction: usize,
    algorithm: String,
    is_valid_linear_extension: bool,
    foata_switches: usize,
    oracle_violations: Vec<String>,
}

/// Aggregate report across all scenarios.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NormalizationE2eReport {
    scenarios: Vec<ScenarioReport>,
    total_scenarios: usize,
    scenarios_with_improvement: usize,
    golden_checksum: u64,
}

// ============================================================================
// Helpers
// ============================================================================

fn algorithm_name(algo: &GeodesicAlgorithm) -> String {
    match algo {
        GeodesicAlgorithm::ExactAStar => "ExactAStar".into(),
        GeodesicAlgorithm::Greedy => "Greedy".into(),
        GeodesicAlgorithm::BeamSearch { width } => format!("BeamSearch(w={width})"),
        GeodesicAlgorithm::TopoSort => "TopoSort".into(),
    }
}

fn foata_switch_cost(events: &[TraceEvent]) -> usize {
    let foata = canonicalize(events);
    let flat = foata.flatten();
    if flat.len() < 2 {
        return 0;
    }
    flat.windows(2)
        .filter(|w| OwnerKey::for_event(&w[0]) != OwnerKey::for_event(&w[1]))
        .count()
}

fn oracle_violation_tag(v: &OracleViolation) -> String {
    match v {
        OracleViolation::TaskLeak(_) => "TaskLeak".into(),
        OracleViolation::ObligationLeak(_) => "ObligationLeak".into(),
        OracleViolation::Quiescence(_) => "Quiescence".into(),
        OracleViolation::LoserDrain(_) => "LoserDrain".into(),
        OracleViolation::Finalizer(_) => "Finalizer".into(),
        OracleViolation::RegionTree(_) => "RegionTree".into(),
        OracleViolation::AmbientAuthority(_) => "AmbientAuthority".into(),
        OracleViolation::DeadlineMonotone(_) => "DeadlineMonotone".into(),
        OracleViolation::CancellationProtocol(_) => "CancellationProtocol".into(),
        OracleViolation::ActorLeak(_) => "ActorLeak".into(),
        OracleViolation::Supervision(_) => "Supervision".into(),
        OracleViolation::Mailbox(_) => "Mailbox".into(),
        OracleViolation::RRefAccess(_) => "RRefAccess".into(),
        OracleViolation::ReplyLinearity(_) => "ReplyLinearity".into(),
        OracleViolation::RegistryLease(_) => "RegistryLease".into(),
        OracleViolation::DownOrder(_) => "DownOrder".into(),
        OracleViolation::SupervisorQuiescence(_) => "SupervisorQuiescence".into(),
    }
}

/// Compute a stable checksum from scenario report fields.
fn report_checksum(scenarios: &[ScenarioReport]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for s in scenarios {
        s.name.hash(&mut hasher);
        s.seed.hash(&mut hasher);
        s.event_count.hash(&mut hasher);
        s.original_switches.hash(&mut hasher);
        s.normalized_switches.hash(&mut hasher);
        s.algorithm.hash(&mut hasher);
        s.foata_switches.hash(&mut hasher);
    }
    hasher.finish()
}

// ============================================================================
// Scenario runner
// ============================================================================

fn run_scenario(name: &str, seed: u64, task_count: usize) -> ScenarioReport {
    let config = LabConfig::new(seed)
        .worker_count(2)
        .trace_capacity(4096)
        .max_steps(10_000);
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Create tasks and schedule them
    for _ in 0..task_count {
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let events: Vec<TraceEvent> = runtime.trace().snapshot();
    let violations = runtime.oracles.check_all(runtime.now());

    // Build poset and normalize
    let poset = TracePoset::from_trace(&events);
    let geo_config = GeodesicConfig::default();
    let result = geodesic_normalize(&poset, &geo_config);

    // Compute original switch cost
    let original_switches = if events.len() < 2 {
        0
    } else {
        events
            .windows(2)
            .filter(|w| OwnerKey::for_event(&w[0]) != OwnerKey::for_event(&w[1]))
            .count()
    };

    let foata_switches = foata_switch_cost(&events);
    let valid = asupersync::trace::is_valid_linear_extension(&poset, &result.schedule);

    ScenarioReport {
        name: name.to_string(),
        seed,
        event_count: events.len(),
        original_switches,
        normalized_switches: result.switch_count,
        switch_reduction: original_switches.saturating_sub(result.switch_count),
        algorithm: algorithm_name(&result.algorithm),
        is_valid_linear_extension: valid,
        foata_switches,
        oracle_violations: violations.iter().map(oracle_violation_tag).collect(),
    }
}

// ============================================================================
// Scenarios
// ============================================================================

fn scenario_two_lane_simple() -> ScenarioReport {
    run_scenario("two_lane_simple", 42, 2)
}

fn scenario_three_tasks_interleaved() -> ScenarioReport {
    run_scenario("three_tasks_interleaved", 99, 3)
}

fn scenario_many_tasks_convergence() -> ScenarioReport {
    run_scenario("many_tasks_convergence", 7777, 6)
}

fn scenario_single_task_baseline() -> ScenarioReport {
    run_scenario("single_task_baseline", 1234, 1)
}

fn scenario_four_tasks_high_contention() -> ScenarioReport {
    run_scenario("four_tasks_high_contention", 31337, 4)
}

/// Cancellation-heavy scenario: create tasks, cancel some mid-flight, then drain.
/// Produces traces with cancel/abort events that interleave with normal execution,
/// exercising geodesic normalization over mixed cancel/commit owner transitions.
fn scenario_cancel_drain() -> ScenarioReport {
    let config = LabConfig::new(0xCAFE)
        .worker_count(2)
        .trace_capacity(4096)
        .max_steps(10_000);
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Create 4 tasks, schedule them all
    let mut task_ids = Vec::new();
    for _ in 0..4 {
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
        task_ids.push(task_id);
    }

    // Let them start executing briefly
    for _ in 0..5 {
        runtime.step_for_test();
    }

    // Cancel the first two tasks mid-flight
    for &tid in &task_ids[..2] {
        if let Some(record) = runtime.state.task_mut(tid) {
            if !record.state.is_terminal() {
                record.request_cancel_with_budget(
                    CancelReason::user("e2e-cancel-drain"),
                    Budget::ZERO,
                );
            }
        }
    }

    // Run to quiescence so remaining tasks complete and cancelled tasks drain
    runtime.run_until_quiescent();

    let events: Vec<TraceEvent> = runtime.trace().snapshot();
    let violations = runtime.oracles.check_all(runtime.now());

    let poset = TracePoset::from_trace(&events);
    let geo_config = GeodesicConfig::default();
    let result = geodesic_normalize(&poset, &geo_config);

    let original_switches = if events.len() < 2 {
        0
    } else {
        events
            .windows(2)
            .filter(|w| OwnerKey::for_event(&w[0]) != OwnerKey::for_event(&w[1]))
            .count()
    };

    let foata_switches = foata_switch_cost(&events);
    let valid = asupersync::trace::is_valid_linear_extension(&poset, &result.schedule);

    ScenarioReport {
        name: "cancel_drain".to_string(),
        seed: 0xCAFE,
        event_count: events.len(),
        original_switches,
        normalized_switches: result.switch_count,
        switch_reduction: original_switches.saturating_sub(result.switch_count),
        algorithm: algorithm_name(&result.algorithm),
        is_valid_linear_extension: valid,
        foata_switches,
        oracle_violations: violations.iter().map(oracle_violation_tag).collect(),
    }
}

/// Obligation-interleave scenario: tasks create and commit/abort obligations
/// at staggered times, producing a trace with many owner switches from
/// obligation lifecycle events interspersed with task execution.
fn scenario_obligation_interleave() -> ScenarioReport {
    let config = LabConfig::new(0x0B11)
        .worker_count(2)
        .trace_capacity(4096)
        .max_steps(10_000);
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Create 3 tasks and schedule them
    let mut task_ids = Vec::new();
    for _ in 0..3 {
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
        task_ids.push(task_id);
    }

    // Advance time, then create obligations on the first two tasks
    runtime.advance_time_to(Time::from_nanos(100));
    let mut obligations = Vec::new();
    for (i, &tid) in task_ids[..2].iter().enumerate() {
        let kind = if i == 0 {
            ObligationKind::SendPermit
        } else {
            ObligationKind::Ack
        };
        if let Ok(obl) =
            runtime
                .state
                .create_obligation(kind, tid, region, Some(format!("e2e-obl-{i}")))
        {
            obligations.push((obl, i));
        }
    }

    // Advance and commit the first, abort the second
    runtime.advance_time_to(Time::from_nanos(500));
    if let Some(&(obl, _)) = obligations.first() {
        let _ = runtime.state.commit_obligation(obl);
    }
    if let Some(&(obl, _)) = obligations.get(1) {
        let _ = runtime
            .state
            .abort_obligation(obl, asupersync::record::ObligationAbortReason::Cancel);
    }

    runtime.run_until_quiescent();

    let events: Vec<TraceEvent> = runtime.trace().snapshot();
    let violations = runtime.oracles.check_all(runtime.now());

    let poset = TracePoset::from_trace(&events);
    let geo_config = GeodesicConfig::default();
    let result = geodesic_normalize(&poset, &geo_config);

    let original_switches = if events.len() < 2 {
        0
    } else {
        events
            .windows(2)
            .filter(|w| OwnerKey::for_event(&w[0]) != OwnerKey::for_event(&w[1]))
            .count()
    };

    let foata_switches = foata_switch_cost(&events);
    let valid = asupersync::trace::is_valid_linear_extension(&poset, &result.schedule);

    ScenarioReport {
        name: "obligation_interleave".to_string(),
        seed: 0x0B11,
        event_count: events.len(),
        original_switches,
        normalized_switches: result.switch_count,
        switch_reduction: original_switches.saturating_sub(result.switch_count),
        algorithm: algorithm_name(&result.algorithm),
        is_valid_linear_extension: valid,
        foata_switches,
        oracle_violations: violations.iter().map(oracle_violation_tag).collect(),
    }
}

fn run_all_scenarios() -> NormalizationE2eReport {
    let scenarios = vec![
        scenario_two_lane_simple(),
        scenario_three_tasks_interleaved(),
        scenario_many_tasks_convergence(),
        scenario_single_task_baseline(),
        scenario_four_tasks_high_contention(),
        scenario_cancel_drain(),
        scenario_obligation_interleave(),
    ];

    let total = scenarios.len();
    let improved = scenarios.iter().filter(|s| s.switch_reduction > 0).count();
    let checksum = report_checksum(&scenarios);

    NormalizationE2eReport {
        scenarios,
        total_scenarios: total,
        scenarios_with_improvement: improved,
        golden_checksum: checksum,
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Core acceptance: running the harness twice produces byte-identical reports.
#[test]
fn e2e_normalization_deterministic_report() {
    let report1 = run_all_scenarios();
    let report2 = run_all_scenarios();

    let json1 = serde_json::to_string_pretty(&report1).expect("serialize report1");
    let json2 = serde_json::to_string_pretty(&report2).expect("serialize report2");

    assert_eq!(json1, json2, "Reports must be byte-identical across runs");
    assert_eq!(
        report1.golden_checksum, report2.golden_checksum,
        "Golden checksums must match"
    );
}

/// Acceptance: at least one scenario shows switch cost improvement.
#[test]
fn e2e_normalization_switch_cost_improvement() {
    let report = run_all_scenarios();

    assert!(
        report.scenarios_with_improvement > 0,
        "At least one scenario must show switch cost improvement. \
         Got {} improvements across {} scenarios. Details:\n{}",
        report.scenarios_with_improvement,
        report.total_scenarios,
        report
            .scenarios
            .iter()
            .map(|s| format!(
                "  {}: orig={} norm={} foata={} reduction={}",
                s.name,
                s.original_switches,
                s.normalized_switches,
                s.foata_switches,
                s.switch_reduction,
            ))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// Acceptance: all schedules are valid linear extensions.
#[test]
fn e2e_normalization_all_valid_linear_extensions() {
    let report = run_all_scenarios();

    for scenario in &report.scenarios {
        assert!(
            scenario.is_valid_linear_extension,
            "Scenario '{}' produced an invalid linear extension",
            scenario.name,
        );
    }
}

/// Acceptance: geodesic cost never exceeds Foata-flatten cost.
#[test]
fn e2e_normalization_geodesic_leq_foata() {
    let report = run_all_scenarios();

    for scenario in &report.scenarios {
        assert!(
            scenario.normalized_switches <= scenario.foata_switches,
            "Scenario '{}': geodesic ({}) > foata ({}) — regression!",
            scenario.name,
            scenario.normalized_switches,
            scenario.foata_switches,
        );
    }
}

/// Golden checksum regression gate.
/// If this fails, the normalization pipeline's observable behavior changed.
/// To update: run with --nocapture, copy the new checksum.
#[test]
fn e2e_normalization_golden_checksum() {
    let report = run_all_scenarios();

    // Print report for debugging
    eprintln!(
        "=== Normalization E2E Report ===\n\
         Total scenarios: {}\n\
         With improvement: {}\n\
         Golden checksum: {:#018x}",
        report.total_scenarios, report.scenarios_with_improvement, report.golden_checksum,
    );
    for s in &report.scenarios {
        eprintln!(
            "  [{:>20}] seed={:<6} events={:<4} orig_sw={:<3} norm_sw={:<3} \
             foata_sw={:<3} reduction={:<3} algo={} violations={:?}",
            s.name,
            s.seed,
            s.event_count,
            s.original_switches,
            s.normalized_switches,
            s.foata_switches,
            s.switch_reduction,
            s.algorithm,
            s.oracle_violations,
        );
    }

    // Golden checksum: pinned to detect behavioral changes.
    // Update this value only after reviewing what changed.
    let golden = report.golden_checksum;
    assert_eq!(
        golden, 0xd51b_54d3_df64_e516,
        "golden checksum changed — normalization behavior diverged. \
         Review the report above and update if intentional."
    );
}

/// No oracle violations in any scenario.
#[test]
fn e2e_normalization_no_oracle_violations() {
    let report = run_all_scenarios();

    for scenario in &report.scenarios {
        assert!(
            scenario.oracle_violations.is_empty(),
            "Scenario '{}' has oracle violations: {:?}",
            scenario.name,
            scenario.oracle_violations,
        );
    }
}
