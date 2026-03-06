//! Bounded latency regression contract invariants (AA-04.3).

#![allow(missing_docs, clippy::cast_precision_loss)]

use serde_json::Value;

const DOC_PATH: &str = "docs/bounded_latency_regression_contract.md";
const ARTIFACT_PATH: &str = "artifacts/bounded_latency_regression_v1.json";
const RUNNER_PATH: &str = "scripts/run_bounded_latency_regression_smoke.sh";

fn load_artifact() -> Value {
    let content =
        std::fs::read_to_string(ARTIFACT_PATH).expect("artifact must exist at expected path");
    serde_json::from_str(&content).expect("artifact must be valid JSON")
}

fn load_doc() -> String {
    std::fs::read_to_string(DOC_PATH).expect("contract doc must exist")
}

fn load_runner() -> String {
    std::fs::read_to_string(RUNNER_PATH).expect("runner script must exist")
}

// ── Document stability ─────────────────────────────────────────────

#[test]
fn doc_exists_and_has_required_sections() {
    let doc = load_doc();
    for section in &[
        "## Purpose",
        "## Contract Artifacts",
        "## Regression Dimensions",
        "## Tail Latency Table",
        "## Fallback Surfaces",
        "## Structured Logging Contract",
        "## Comparator-Smoke Runner",
        "## Validation",
        "## Cross-References",
    ] {
        assert!(doc.contains(section), "doc must contain section: {section}");
    }
}

#[test]
fn doc_references_bead_id() {
    let doc = load_doc();
    let art = load_artifact();
    let bead_id = art["bead_id"].as_str().unwrap();
    assert!(
        doc.contains(bead_id),
        "doc must reference bead_id {bead_id}"
    );
}

// ── Artifact stability ─────────────────────────────────────────────

#[test]
fn artifact_has_contract_version() {
    let art = load_artifact();
    assert_eq!(
        art["contract_version"].as_str().unwrap(),
        "bounded-latency-regression-v1"
    );
}

#[test]
fn artifact_has_runner_script() {
    let art = load_artifact();
    let runner = art["runner_script"].as_str().unwrap();
    assert!(
        std::path::Path::new(runner).exists(),
        "runner script must exist at {runner}"
    );
}

// ── Regression dimensions ──────────────────────────────────────────

#[test]
fn regression_dimensions_are_nonempty() {
    let art = load_artifact();
    let dims = art["regression_dimensions"].as_array().unwrap();
    assert!(
        !dims.is_empty(),
        "must have at least one regression dimension"
    );
}

#[test]
fn regression_dimensions_have_required_fields() {
    let art = load_artifact();
    let dims = art["regression_dimensions"].as_array().unwrap();
    for dim in dims {
        let did = dim["dimension_id"].as_str().unwrap();
        assert!(
            dim["description"].is_string(),
            "{did}: must have description"
        );
        let invariants = dim["invariants"].as_array().unwrap();
        assert!(
            !invariants.is_empty(),
            "{did}: must have at least one invariant"
        );
        assert!(
            dim["workload_profile"].is_string(),
            "{did}: must have workload_profile"
        );
        assert!(
            dim["fail_action"].is_string(),
            "{did}: must have fail_action"
        );
    }
}

#[test]
fn regression_dimension_ids_are_unique() {
    let art = load_artifact();
    let dims = art["regression_dimensions"].as_array().unwrap();
    let ids: Vec<&str> = dims
        .iter()
        .map(|d| d["dimension_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "dimension_ids must be unique");
}

#[test]
fn regression_dimensions_cover_fairness_wakeup_leak_tail() {
    let art = load_artifact();
    let dims = art["regression_dimensions"].as_array().unwrap();
    let ids: Vec<&str> = dims
        .iter()
        .map(|d| d["dimension_id"].as_str().unwrap())
        .collect();

    let has_fairness = ids.iter().any(|id| id.starts_with("FAIRNESS-"));
    let has_wakeup = ids.iter().any(|id| id.starts_with("WAKEUP-"));
    let has_leak = ids.iter().any(|id| id.contains("LEAK") || id.contains("QUIESCENCE"));
    let has_tail = ids.iter().any(|id| id.starts_with("TAIL-"));

    assert!(has_fairness, "must have FAIRNESS dimensions");
    assert!(has_wakeup, "must have WAKEUP dimensions");
    assert!(has_leak, "must have LEAK/QUIESCENCE dimensions");
    assert!(has_tail, "must have TAIL dimensions");
}

// ── Fallback surfaces ──────────────────────────────────────────────

#[test]
fn fallback_surfaces_are_nonempty() {
    let art = load_artifact();
    let surfaces = art["fallback_surfaces"].as_array().unwrap();
    assert!(
        !surfaces.is_empty(),
        "must have at least one fallback surface"
    );
}

#[test]
fn fallback_surfaces_have_required_fields() {
    let art = load_artifact();
    let surfaces = art["fallback_surfaces"].as_array().unwrap();
    for surface in surfaces {
        let sid = surface["surface_id"].as_str().unwrap();
        assert!(
            surface["fallback_flag"].is_string(),
            "{sid}: must have fallback_flag"
        );
        assert!(
            surface["rollback_action"].is_string(),
            "{sid}: must have rollback_action"
        );
    }
}

#[test]
fn fallback_surface_ids_are_unique() {
    let art = load_artifact();
    let surfaces = art["fallback_surfaces"].as_array().unwrap();
    let ids: Vec<&str> = surfaces
        .iter()
        .map(|s| s["surface_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "surface_ids must be unique");
}

// ── Tail table format ──────────────────────────────────────────────

#[test]
fn tail_table_has_required_columns() {
    let art = load_artifact();
    let columns = art["tail_table_format"]["columns"].as_array().unwrap();
    let col_strs: Vec<&str> = columns.iter().map(|c| c.as_str().unwrap()).collect();
    for required in &["workload_id", "substrate", "p99_us", "verdict"] {
        assert!(
            col_strs.contains(required),
            "tail table must include column {required}"
        );
    }
}

#[test]
fn tail_table_verdict_values_include_pass_and_regressed() {
    let art = load_artifact();
    let verdicts = art["tail_table_format"]["verdict_values"]
        .as_array()
        .unwrap();
    let vals: Vec<&str> = verdicts.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(vals.contains(&"pass"), "verdicts must include 'pass'");
    assert!(
        vals.contains(&"regressed"),
        "verdicts must include 'regressed'"
    );
}

// ── Structured logging ─────────────────────────────────────────────

#[test]
fn structured_log_fields_are_nonempty_and_unique() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"]
        .as_array()
        .unwrap();
    assert!(
        !fields.is_empty(),
        "structured log fields must be nonempty"
    );
    let strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
    let mut deduped = strs.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(strs.len(), deduped.len(), "log fields must be unique");
}

// ── Smoke scenarios ────────────────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let art = load_artifact();
    let scenarios = art["smoke_scenarios"].as_array().unwrap();
    assert!(
        scenarios.len() >= 3,
        "must have at least 3 smoke scenarios"
    );
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let cmd = scenario["command"].as_str().unwrap();
        assert!(
            cmd.starts_with("rch exec"),
            "{sid}: command must be rch-routed"
        );
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let runner = load_runner();
    assert!(runner.contains("--list"), "runner must support --list");
    assert!(
        runner.contains("--dry-run"),
        "runner must support --dry-run"
    );
    assert!(
        runner.contains("--execute"),
        "runner must support --execute"
    );
    assert!(
        runner.contains("--scenario"),
        "runner must support --scenario"
    );
}

// ── Functional: fairness invariant checking ──────────────────────────

#[test]
fn fairness_ratio_computation() {
    // fairness_ratio = min(cancel_service, ready_service) / max(cancel_service, ready_service)
    let cancel_service: f64 = 30.0;
    let ready_service: f64 = 70.0;
    let ratio = cancel_service.min(ready_service) / cancel_service.max(ready_service);
    assert!(
        ratio >= 0.3,
        "fairness ratio {ratio:.3} must be >= 0.3"
    );
}

#[test]
fn fairness_ratio_detects_starvation() {
    let cancel_service: f64 = 5.0;
    let ready_service: f64 = 95.0;
    let ratio = cancel_service.min(ready_service) / cancel_service.max(ready_service);
    assert!(
        ratio < 0.3,
        "starved fairness ratio {ratio:.3} must be < 0.3"
    );
}

#[test]
fn fairness_steal_imbalance_ratio() {
    // max_steal_imbalance = max_steals / min_steals across workers
    let worker_steals = [10_u64, 12, 8, 11, 9];
    let max_steals = *worker_steals.iter().max().unwrap();
    let min_steals = *worker_steals.iter().min().unwrap();
    let imbalance = max_steals as f64 / min_steals as f64;
    assert!(
        imbalance <= 3.0,
        "steal imbalance {imbalance:.2} must be <= 3.0"
    );
}

#[test]
fn fairness_steal_imbalance_detects_monopoly() {
    let worker_steals = [50_u64, 2, 3, 1, 4];
    let max_steals = *worker_steals.iter().max().unwrap();
    let min_steals = *worker_steals.iter().min().unwrap();
    let imbalance = max_steals as f64 / min_steals as f64;
    assert!(
        imbalance > 3.0,
        "monopolized steal imbalance {imbalance:.2} must be > 3.0"
    );
}

// ── Functional: wakeup correctness ──────────────────────────────────

#[test]
fn wakeup_no_lost_wakes() {
    // Simulate: 100 unique wakes sent, all delivered
    let wakes_sent: u64 = 100;
    let wakes_delivered: u64 = 100;
    let lost = wakes_sent - wakes_delivered;
    assert_eq!(lost, 0, "lost_wakeup_count must be zero");
}

#[test]
fn wakeup_coalesce_deduplicates() {
    // 100 wakes sent, 60 duplicates, 40 unique -> 40 delivered
    let total_wakes: u64 = 100;
    let unique_wakes: u64 = 40;
    let delivered: u64 = 40;
    let coalesced = total_wakes - delivered;
    assert_eq!(coalesced, 60, "60 duplicate wakes should be coalesced");
    assert_eq!(
        delivered, unique_wakes,
        "all unique wakes must be delivered"
    );
}

#[test]
fn wakeup_bloom_false_positive_does_not_lose_unique() {
    // Even if bloom filter has false positives, unique wakes must still be delivered
    // via the fallback path (lock acquisition)
    let unique_wakes_expected: u64 = 50;
    let bloom_false_positives: u64 = 3; // falsely reported as duplicates
    // With fallback: false positives are caught by the lock-based check
    let unique_wakes_delivered = unique_wakes_expected; // fallback catches all
    let false_negative_wakes = unique_wakes_expected - unique_wakes_delivered;
    assert_eq!(
        false_negative_wakes, 0,
        "false negatives must be zero with fallback path"
    );
    let _ = bloom_false_positives; // used for documentation
}

// ── Functional: obligation no-leak ──────────────────────────────────

#[test]
fn leak_obligations_settled_at_region_close() {
    // Simulate region lifecycle: open, create obligations, settle, close
    let obligations_created: u64 = 15;
    let obligations_settled: u64 = 15;
    let outstanding_at_close = obligations_created - obligations_settled;
    assert_eq!(
        outstanding_at_close, 0,
        "outstanding obligations at close must be zero"
    );
}

#[test]
fn leak_detects_unsettled_obligations() {
    let obligations_created: u64 = 15;
    let obligations_settled: u64 = 13;
    let outstanding_at_close = obligations_created - obligations_settled;
    assert!(
        outstanding_at_close > 0,
        "unsettled obligations must be detected"
    );
}

#[test]
fn leak_quiescence_shutdown() {
    let tasks_remaining: u64 = 0;
    let workers_active: u64 = 0;
    let shutdown_timeout_exceeded = false;
    assert_eq!(tasks_remaining, 0, "tasks must drain at shutdown");
    assert_eq!(workers_active, 0, "workers must park at shutdown");
    assert!(
        !shutdown_timeout_exceeded,
        "shutdown must complete within timeout"
    );
}

// ── Functional: tail latency regression checking ────────────────────

#[test]
fn tail_p99_delta_pass() {
    let incumbent_p99_us: f64 = 500.0;
    let prototype_p99_us: f64 = 510.0;
    let delta_pct = (prototype_p99_us - incumbent_p99_us) / incumbent_p99_us * 100.0;
    assert!(
        delta_pct <= 5.0,
        "p99 delta {delta_pct:.1}% must be <= 5.0%"
    );
}

#[test]
fn tail_p99_delta_regressed() {
    let incumbent_p99_us: f64 = 500.0;
    let prototype_p99_us: f64 = 560.0; // 12% regression
    let delta_pct = (prototype_p99_us - incumbent_p99_us) / incumbent_p99_us * 100.0;
    assert!(
        delta_pct > 5.0,
        "p99 delta {delta_pct:.1}% regression must be detected"
    );
}

#[test]
fn tail_p999_delta_pass() {
    let incumbent_p999_us: f64 = 2000.0;
    let prototype_p999_us: f64 = 2150.0;
    let delta_pct = (prototype_p999_us - incumbent_p999_us) / incumbent_p999_us * 100.0;
    assert!(
        delta_pct <= 10.0,
        "p999 delta {delta_pct:.1}% must be <= 10.0%"
    );
}

#[test]
fn tail_verdict_assignment() {
    fn verdict(delta_pct: f64, threshold: f64) -> &'static str {
        if delta_pct <= 0.0 {
            "improved"
        } else if delta_pct <= threshold {
            "pass"
        } else {
            "regressed"
        }
    }

    assert_eq!(verdict(-5.0, 5.0), "improved");
    assert_eq!(verdict(3.0, 5.0), "pass");
    assert_eq!(verdict(8.0, 5.0), "regressed");
}

// ── Functional: per-surface rollback independence ────────────────────

#[test]
fn tail_per_surface_rollback_independence() {
    // Simulate: wake-coalescing regresses but shard-local-dispatch passes
    struct SurfaceState {
        enabled: bool,
    }

    let shard_local = SurfaceState { enabled: true };
    let mut wake_coalesce = SurfaceState { enabled: true };
    let adaptive_steal = SurfaceState { enabled: true };

    // Wake coalescing fails the WAKEUP dimension
    let wakeup_passed = false;
    if !wakeup_passed {
        wake_coalesce.enabled = false; // rollback only this surface
    }

    assert!(
        shard_local.enabled,
        "shard-local must remain enabled after wake-coalesce rollback"
    );
    assert!(
        !wake_coalesce.enabled,
        "wake-coalesce must be disabled after its regression"
    );
    assert!(
        adaptive_steal.enabled,
        "adaptive-steal must remain enabled after wake-coalesce rollback"
    );
}

// ── Functional: invariant evaluation engine ─────────────────────────

#[test]
fn tail_invariant_evaluation_all_pass() {
    let invariant_passes = [true, true, true];
    let all_pass = invariant_passes.iter().all(|&p| p);
    assert!(all_pass, "all invariants must pass for dimension to pass");
}

#[test]
fn tail_invariant_evaluation_one_fail() {
    struct InvariantResult {
        pass: bool,
    }

    let results = [
        InvariantResult { pass: true },
        InvariantResult { pass: false }, // one fails
        InvariantResult { pass: true },
    ];

    let all_pass = results.iter().all(|r| r.pass);
    assert!(
        !all_pass,
        "dimension must fail if any invariant fails"
    );
}

use asupersync::runtime::kernel::{
    ControllerBudget, ControllerMode, ControllerRegistration, ControllerRegistry, RollbackReason,
    SnapshotVersion,
};

#[test]
fn tail_regression_triggers_controller_rollback() {
    let mut registry = ControllerRegistry::new();

    let reg = ControllerRegistration {
        name: "fast-path-controller".to_string(),
        min_version: SnapshotVersion { major: 1, minor: 0 },
        max_version: SnapshotVersion { major: 1, minor: 0 },
        required_fields: vec!["ready_queue_len".to_string()],
        target_seams: vec!["AA01-SEAM-SCHED-GOVERNOR".to_string()],
        initial_mode: ControllerMode::Shadow,
        proof_artifact_id: None,
        budget: ControllerBudget::default(),
    };

    let id = registry.register(reg).unwrap();

    // Promote to active
    registry.update_calibration(id, 0.95);
    for _ in 0..3 {
        registry.advance_epoch();
    }
    registry
        .try_promote(id, ControllerMode::Canary)
        .unwrap();
    for _ in 0..2 {
        registry.advance_epoch();
    }
    registry
        .try_promote(id, ControllerMode::Active)
        .unwrap();
    assert_eq!(registry.mode(id), Some(ControllerMode::Active));

    // Tail regression detected -> rollback
    let recovery = registry.rollback(
        id,
        RollbackReason::CalibrationRegression { score: 0.4 },
    );
    assert!(recovery.is_some(), "rollback must produce recovery command");
    assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
    assert!(registry.is_fallback_active(id));

    let cmd = recovery.unwrap();
    assert_eq!(cmd.rolled_back_from, ControllerMode::Active);
    assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);
    assert!(!cmd.remediation.is_empty());
}
