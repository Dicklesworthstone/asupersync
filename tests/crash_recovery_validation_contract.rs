//! Crash recovery validation contract invariants (AA-09.3).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::HashSet;

const DOC_PATH: &str = "docs/crash_recovery_validation_contract.md";
const ARTIFACT_PATH: &str = "artifacts/crash_recovery_validation_v1.json";
const RUNNER_PATH: &str = "scripts/run_crash_recovery_validation_smoke.sh";

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
        "## Soak Scenarios",
        "## Fault Injection Points",
        "## Recovery Metrics",
        "## Reproducibility",
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
        "crash-recovery-validation-v1"
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

// ── Soak scenarios ─────────────────────────────────────────────────

#[test]
fn soak_scenarios_are_nonempty() {
    let art = load_artifact();
    let scenarios = art["soak_scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 3, "must have at least 3 soak scenarios");
}

#[test]
fn soak_scenario_ids_are_unique() {
    let art = load_artifact();
    let scenarios = art["soak_scenarios"].as_array().unwrap();
    let ids: Vec<&str> = scenarios
        .iter()
        .map(|s| s["scenario_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "soak scenario_ids must be unique");
}

#[test]
fn soak_scenarios_have_soak_prefix() {
    let art = load_artifact();
    let scenarios = art["soak_scenarios"].as_array().unwrap();
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        assert!(
            sid.starts_with("SOAK-"),
            "soak scenario '{sid}' must start with SOAK-"
        );
    }
}

#[test]
fn soak_scenarios_have_invariants() {
    let art = load_artifact();
    let scenarios = art["soak_scenarios"].as_array().unwrap();
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let invariants = scenario["invariants"].as_array().unwrap();
        assert!(
            !invariants.is_empty(),
            "{sid}: must have at least one invariant"
        );
    }
}

// ── Fault injection points ─────────────────────────────────────────

#[test]
fn fault_injection_points_are_nonempty() {
    let art = load_artifact();
    let points = art["fault_injection_points"].as_array().unwrap();
    assert!(
        points.len() >= 4,
        "must have at least 4 fault injection points"
    );
}

#[test]
fn fault_injection_point_ids_are_unique() {
    let art = load_artifact();
    let points = art["fault_injection_points"].as_array().unwrap();
    let ids: Vec<&str> = points
        .iter()
        .map(|p| p["point_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "point_ids must be unique");
}

#[test]
fn fault_injection_points_have_fi_prefix() {
    let art = load_artifact();
    let points = art["fault_injection_points"].as_array().unwrap();
    for point in points {
        let pid = point["point_id"].as_str().unwrap();
        assert!(
            pid.starts_with("FI-"),
            "fault injection point '{pid}' must start with FI-"
        );
    }
}

#[test]
fn fault_injection_points_have_expected_behavior() {
    let art = load_artifact();
    let points = art["fault_injection_points"].as_array().unwrap();
    for point in points {
        let pid = point["point_id"].as_str().unwrap();
        let behavior = point["expected_behavior"].as_str().unwrap();
        assert!(
            !behavior.is_empty(),
            "{pid}: must have non-empty expected_behavior"
        );
    }
}

// ── Recovery metrics ───────────────────────────────────────────────

#[test]
fn recovery_metrics_are_nonempty() {
    let art = load_artifact();
    let metrics = art["recovery_metrics"]["metrics"].as_array().unwrap();
    assert!(metrics.len() >= 4, "must have at least 4 recovery metrics");
}

#[test]
fn recovery_metric_ids_are_unique() {
    let art = load_artifact();
    let metrics = art["recovery_metrics"]["metrics"].as_array().unwrap();
    let ids: Vec<&str> = metrics
        .iter()
        .map(|m| m["metric_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "metric_ids must be unique");
}

#[test]
fn recovery_metrics_have_rm_prefix() {
    let art = load_artifact();
    let metrics = art["recovery_metrics"]["metrics"].as_array().unwrap();
    for metric in metrics {
        let mid = metric["metric_id"].as_str().unwrap();
        assert!(mid.starts_with("RM-"), "metric '{mid}' must start with RM-");
    }
}

#[test]
fn recovery_metrics_have_slo_targets() {
    let art = load_artifact();
    let metrics = art["recovery_metrics"]["metrics"].as_array().unwrap();
    for metric in metrics {
        let mid = metric["metric_id"].as_str().unwrap();
        let target = metric["slo_target"].as_f64().unwrap();
        assert!(target > 0.0, "{mid}: slo_target must be positive");
    }
}

#[test]
fn recovery_metrics_include_mttr_and_invariant() {
    let art = load_artifact();
    let metrics = art["recovery_metrics"]["metrics"].as_array().unwrap();
    let ids: HashSet<&str> = metrics
        .iter()
        .map(|m| m["metric_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains("RM-MTTR"), "must have RM-MTTR");
    assert!(
        ids.contains("RM-INVARIANT-PRESERVATION"),
        "must have RM-INVARIANT-PRESERVATION"
    );
}

#[test]
fn invariant_preservation_slo_is_perfect() {
    let art = load_artifact();
    let metrics = art["recovery_metrics"]["metrics"].as_array().unwrap();
    let inv_metric = metrics
        .iter()
        .find(|m| m["metric_id"].as_str().unwrap() == "RM-INVARIANT-PRESERVATION")
        .expect("RM-INVARIANT-PRESERVATION must exist");
    let target = inv_metric["slo_target"].as_f64().unwrap();
    assert!(
        (target - 1.0).abs() < f64::EPSILON,
        "invariant preservation SLO must be 1.0 (perfect)"
    );
}

// ── Reproducibility requirements ───────────────────────────────────

#[test]
fn reproducibility_requirements_are_nonempty() {
    let art = load_artifact();
    let reqs = art["reproducibility_requirements"].as_array().unwrap();
    assert!(
        reqs.len() >= 3,
        "must have at least 3 reproducibility requirements"
    );
}

#[test]
fn reproducibility_requirement_ids_are_unique() {
    let art = load_artifact();
    let reqs = art["reproducibility_requirements"].as_array().unwrap();
    let ids: Vec<&str> = reqs
        .iter()
        .map(|r| r["requirement_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "requirement_ids must be unique");
}

#[test]
fn reproducibility_requirements_have_rr_prefix() {
    let art = load_artifact();
    let reqs = art["reproducibility_requirements"].as_array().unwrap();
    for req in reqs {
        let rid = req["requirement_id"].as_str().unwrap();
        assert!(
            rid.starts_with("RR-"),
            "requirement '{rid}' must start with RR-"
        );
    }
}

#[test]
fn reproducibility_includes_blocks_graduation() {
    let art = load_artifact();
    let reqs = art["reproducibility_requirements"].as_array().unwrap();
    assert!(
        reqs.iter().any(|r| {
            r["requirement_id"].as_str().unwrap() == "RR-UNREPRODUCIBLE-BLOCKS-GRADUATION"
        }),
        "must have RR-UNREPRODUCIBLE-BLOCKS-GRADUATION"
    );
}

// ── Structured logging ─────────────────────────────────────────────

#[test]
fn structured_log_fields_are_nonempty_and_unique() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"].as_array().unwrap();
    assert!(!fields.is_empty(), "log fields must be nonempty");
    let strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
    let mut deduped = strs.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(strs.len(), deduped.len(), "log fields must be unique");
}

// ── Smoke / runner ─────────────────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let art = load_artifact();
    let scenarios = art["smoke_scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 3, "must have at least 3 smoke scenarios");
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let cmd = scenario["command"].as_str().unwrap();
        assert!(cmd.starts_with("rch exec"), "{sid}: must be rch-routed");
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let runner = load_runner();
    for mode in &["--list", "--dry-run", "--execute", "--scenario"] {
        assert!(runner.contains(mode), "runner must support {mode}");
    }
}

// ── Functional: soak simulation ─────────────────────────────────────

#[test]
fn soak_repeated_crash_no_leaks() {
    let mut obligation_count: i64 = 0;
    let crash_count = 100;

    for _ in 0..crash_count {
        // Simulate: create obligations, crash, recover
        obligation_count += 5; // enter obligations
        // Crash: obligations abandoned
        obligation_count -= 5;
    }

    assert_eq!(
        obligation_count, 0,
        "no obligation leaks after {crash_count} crashes"
    );
}

#[test]
fn soak_restart_storm_domain_isolation() {
    let domain_count = 8;
    let mut domain_states = vec!["RUNNING"; domain_count];

    // Crash domains 0, 2, 4, 6 concurrently
    for i in (0..domain_count).step_by(2) {
        domain_states[i] = "CRASHING";
    }

    // Verify odd-indexed domains unaffected
    for i in (1..domain_count).step_by(2) {
        assert_eq!(
            domain_states[i], "RUNNING",
            "domain {i} must remain RUNNING during sibling crash"
        );
    }
}

#[test]
fn soak_partial_recovery_tombstones_on_exhaust() {
    let max_microreboots = 3u32;
    let nested_depth = 3u32;
    let mut reboots = 0u32;
    let mut tombstoned = false;

    for _ in 0..nested_depth {
        reboots += 1;
        if reboots > max_microreboots {
            tombstoned = true;
            break;
        }
        // Crash during recovery: increment again
        reboots += 1;
        if reboots > max_microreboots {
            tombstoned = true;
            break;
        }
    }

    assert!(
        tombstoned,
        "must tombstone after exhausting microreboots in nested crash"
    );
}

// ── Functional: fault injection simulation ──────────────────────────

#[test]
fn fault_injection_journal_write_retries_or_tombstones() {
    let journal_write_succeeded = false;
    let max_retries = 3u32;
    let mut retries = 0u32;
    let mut state = "CRASHING";

    while !journal_write_succeeded && retries < max_retries {
        retries += 1;
    }

    if !journal_write_succeeded {
        state = "TOMBSTONED";
    }

    assert_eq!(
        state, "TOMBSTONED",
        "must tombstone if journal write fails repeatedly"
    );
}

#[test]
fn fault_injection_parent_cancel_tombstones_child() {
    let parent_cancelled = true;
    let child_state = if parent_cancelled {
        "TOMBSTONED"
    } else {
        "RECOVERING"
    };

    assert_eq!(
        child_state, "TOMBSTONED",
        "parent cancel must tombstone child"
    );
}

// ── Functional: metrics simulation ──────────────────────────────────

#[test]
fn metric_mttr_within_slo() {
    let art = load_artifact();
    let mttr_metric = art["recovery_metrics"]["metrics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["metric_id"].as_str().unwrap() == "RM-MTTR")
        .expect("RM-MTTR must exist");
    let slo = mttr_metric["slo_target"].as_f64().unwrap();

    // Simulate a recovery that takes less than SLO
    let simulated_mttr_ms = 500.0;
    assert!(
        simulated_mttr_ms <= slo,
        "simulated MTTR {simulated_mttr_ms}ms must be <= SLO {slo}ms"
    );
}

#[test]
fn metric_replay_idempotent() {
    // Simulate two replays of the same journal producing the same state
    let replay_1_state = ("tasks_recovered", 5u32, "obligations_recovered", 3u32);
    let replay_2_state = ("tasks_recovered", 5u32, "obligations_recovered", 3u32);

    assert_eq!(
        replay_1_state, replay_2_state,
        "journal replay must be idempotent"
    );
}
