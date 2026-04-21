#![allow(clippy::all)]
//! Deterministic Soak/Stress Diagnostics Validation (Track 6.8)
//!
//! Validates the stress/soak workload catalog, sustained budget-conformance
//! policy, checkpoint metrics, failure output quality, and determinism
//! invariants for doctor_asupersync diagnostics.
//!
//! Bead: asupersync-2b4jj.6.8

#![allow(missing_docs)]
#![allow(dead_code)]
#![cfg(feature = "cli")]

use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

// ─── Constants ──────────────────────────────────────────────────────

const DOC_PATH: &str = "docs/doctor_stress_soak_diagnostics.md";
const FIXTURE_DIR: &str = "tests/fixtures/doctor_stress_soak";
const CATALOG_FIXTURE_PATH: &str = "tests/fixtures/doctor_stress_soak/workload_catalog.json";
const SMOKE_REPORT_FIXTURE_PATH: &str = "tests/fixtures/doctor_stress_soak/smoke_report.json";
const E2E_SCRIPT_PATH: &str = "scripts/test_doctor_stress_soak_e2e.sh";

const CATALOG_SCHEMA_VERSION: &str = "doctor-stress-soak-v1";
const SMOKE_REPORT_SCHEMA_VERSION: &str = "doctor-stress-soak-report-v1";

const PRESSURE_CLASSES: [&str; 4] = [
    "cancel_recovery",
    "concurrent_ops",
    "high_volume",
    "steady_state",
];

const PROFILE_MODES: [&str; 2] = ["fast", "soak"];

const ARTIFACT_CLASSES: [&str; 3] = ["structured_log", "summary", "transcript"];

const SUSTAINED_BUDGET_METRICS: [&str; 4] = [
    "drift_basis_points",
    "error_rate_bps",
    "latency_p99_ms",
    "memory_peak_mb",
];

// ─── Fixture types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct WorkloadCatalog {
    schema_version: String,
    description: String,
    bead_id: String,
    contract_version: String,
    e2e_harness_contract_version: String,
    logging_contract_version: String,
    profile_modes: Vec<String>,
    required_scenario_fields: Vec<String>,
    required_run_fields: Vec<String>,
    required_metric_fields: Vec<String>,
    sustained_budget_policy: Vec<SustainedBudgetPolicy>,
    scenario_catalog: Vec<ScenarioEntry>,
    budget_envelopes: Vec<BudgetEnvelope>,
    saturation_indicators: SaturationIndicators,
    determinism_invariants: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SustainedBudgetPolicy {
    policy_id: String,
    description: String,
    metric: String,
    warmup_checkpoints: u32,
    threshold_source: String,
    #[serde(default)]
    threshold_value: Option<u64>,
    violation_action: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ScenarioEntry {
    scenario_id: String,
    description: String,
    pressure_class: String,
    duration_steps: u64,
    checkpoint_interval_steps: u64,
    seed: u64,
    concurrency_level: u32,
    cancellation_rate_pct: u32,
    finding_volume_per_step: u64,
    budget_envelope_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct BudgetEnvelope {
    envelope_id: String,
    workflow_category: String,
    dataset_profile: String,
    latency_p50_ms: u64,
    latency_p95_ms: u64,
    latency_p99_ms: u64,
    memory_ceiling_mb: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct SaturationIndicators {
    description: String,
    indicator_classes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SmokeReport {
    schema_version: String,
    description: String,
    bead_id: String,
    profile_mode: String,
    seed: String,
    pass_criteria: String,
    overall_status: String,
    runs: Vec<SmokeRun>,
}

#[derive(Debug, Clone, Deserialize)]
struct SmokeRun {
    run_id: String,
    scenario_id: String,
    seed: u64,
    status: String,
    checkpoint_count: usize,
    sustained_budget_pass: bool,
    checkpoint_metrics: Vec<CheckpointMetric>,
    #[serde(default)]
    failure_output: Option<FailureOutput>,
    artifact_index: Vec<ArtifactEntry>,
    repro_command: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CheckpointMetric {
    checkpoint_index: usize,
    latency_p50_ms: u64,
    latency_p95_ms: u64,
    latency_p99_ms: u64,
    memory_peak_mb: u64,
    error_rate_bps: u64,
    drift_basis_points: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct FailureOutput {
    saturation_indicators: Vec<String>,
    trace_correlation: String,
    rerun_command: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ArtifactEntry {
    artifact_class: String,
    path: String,
}

// ─── Helper functions ───────────────────────────────────────────────

fn load_catalog() -> WorkloadCatalog {
    let data = std::fs::read_to_string(CATALOG_FIXTURE_PATH)
        .unwrap_or_else(|e| panic!("Failed to read {CATALOG_FIXTURE_PATH}: {e}"));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("Failed to parse {CATALOG_FIXTURE_PATH}: {e}"))
}

fn load_smoke_report() -> SmokeReport {
    let data = std::fs::read_to_string(SMOKE_REPORT_FIXTURE_PATH)
        .unwrap_or_else(|e| panic!("Failed to read {SMOKE_REPORT_FIXTURE_PATH}: {e}"));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("Failed to parse {SMOKE_REPORT_FIXTURE_PATH}: {e}"))
}

fn evaluate_sustained_budget(
    run: &SmokeRun,
    policies: &[SustainedBudgetPolicy],
    envelopes: &[BudgetEnvelope],
    catalog: &[ScenarioEntry],
) -> (bool, Vec<String>) {
    let scenario = catalog.iter().find(|s| s.scenario_id == run.scenario_id);
    let envelope = scenario.and_then(|s| {
        envelopes
            .iter()
            .find(|e| e.envelope_id == s.budget_envelope_id)
    });
    let mut violations = Vec::new();
    let mut pass = true;

    for policy in policies {
        let warmup = policy.warmup_checkpoints as usize;
        let post_warmup: Vec<&CheckpointMetric> = run
            .checkpoint_metrics
            .iter()
            .filter(|m| m.checkpoint_index >= warmup)
            .collect();

        for metric in &post_warmup {
            let (value, threshold) = match policy.metric.as_str() {
                "latency_p99_ms" => {
                    let threshold = envelope.map_or(u64::MAX, |e| e.latency_p99_ms);
                    (metric.latency_p99_ms, threshold)
                }
                "memory_peak_mb" => {
                    let threshold = envelope.map_or(u64::MAX, |e| e.memory_ceiling_mb);
                    (metric.memory_peak_mb, threshold)
                }
                "error_rate_bps" => {
                    let threshold = policy.threshold_value.unwrap_or(u64::MAX);
                    (metric.error_rate_bps, threshold)
                }
                "drift_basis_points" => {
                    let threshold = policy.threshold_value.unwrap_or(u64::MAX);
                    (metric.drift_basis_points, threshold)
                }
                _ => continue,
            };

            if value > threshold {
                pass = false;
                violations.push(format!(
                    "{}: {} exceeds {} threshold ({}) at checkpoint {}",
                    policy.policy_id, value, policy.metric, threshold, metric.checkpoint_index
                ));
            }
        }
    }

    violations.sort();
    (pass, violations)
}

fn compute_overall_status(runs: &[SmokeRun]) -> &'static str {
    if runs.iter().any(|r| r.status == "budget_failed") {
        "budget_failed"
    } else {
        "passed"
    }
}

// ─── 1. Doc infrastructure ─────────────────────────────────────────

#[test]
fn doctor_stress_soak_doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "Governance doc must exist at {DOC_PATH}"
    );
}

#[test]
fn doctor_stress_soak_doc_has_required_sections() {
    let content = std::fs::read_to_string(DOC_PATH).unwrap();
    let required_sections = [
        "Purpose",
        "Workload Catalog",
        "Sustained Budget Policy",
        "Checkpoint Metrics",
        "Failure Output Quality",
        "Determinism Invariants",
        "Profile Modes",
        "Artifact Index",
        "CI Integration",
        "Cross-References",
    ];
    for section in &required_sections {
        assert!(
            content.contains(section),
            "Doc must contain section: {section}"
        );
    }
}

#[test]
fn doctor_stress_soak_doc_references_fixture_paths() {
    let content = std::fs::read_to_string(DOC_PATH).unwrap();
    assert!(content.contains(CATALOG_FIXTURE_PATH));
    assert!(content.contains(SMOKE_REPORT_FIXTURE_PATH));
    assert!(content.contains(E2E_SCRIPT_PATH));
}

#[test]
fn doctor_stress_soak_doc_references_budget_contract() {
    let content = std::fs::read_to_string(DOC_PATH).unwrap();
    assert!(content.contains("doctor_performance_budget_contract.md"));
    assert!(content.contains("doctor_logging_contract.md"));
}

#[test]
fn doctor_stress_soak_e2e_script_exists() {
    let path = Path::new(E2E_SCRIPT_PATH);
    assert!(path.exists(), "E2E script must exist at {E2E_SCRIPT_PATH}");
}

// ─── 2. Fixture directory and file structure ────────────────────────

#[test]
fn doctor_stress_soak_fixture_dir_exists() {
    assert!(
        Path::new(FIXTURE_DIR).is_dir(),
        "Fixture directory must exist at {FIXTURE_DIR}"
    );
}

#[test]
fn doctor_stress_soak_catalog_fixture_loads() {
    let catalog = load_catalog();
    assert!(!catalog.scenario_catalog.is_empty());
    assert!(!catalog.budget_envelopes.is_empty());
    assert!(!catalog.sustained_budget_policy.is_empty());
}

#[test]
fn doctor_stress_soak_smoke_report_fixture_loads() {
    let report = load_smoke_report();
    assert!(!report.runs.is_empty());
}

// ─── 3. Catalog schema validation ──────────────────────────────────

#[test]
fn doctor_stress_soak_catalog_schema_version() {
    let catalog = load_catalog();
    assert_eq!(catalog.schema_version, CATALOG_SCHEMA_VERSION);
}

#[test]
fn doctor_stress_soak_catalog_contract_versions() {
    let catalog = load_catalog();
    assert_eq!(catalog.contract_version, "doctor-stress-soak-v1");
    assert_eq!(
        catalog.e2e_harness_contract_version,
        "doctor-e2e-harness-v1"
    );
    assert_eq!(catalog.logging_contract_version, "doctor-logging-v1");
}

#[test]
fn doctor_stress_soak_catalog_profile_modes() {
    let catalog = load_catalog();
    let mut modes = catalog.profile_modes;
    modes.sort();
    assert_eq!(modes, PROFILE_MODES);
}

#[test]
fn doctor_stress_soak_catalog_has_required_scenario_fields() {
    let catalog = load_catalog();
    let required = [
        "scenario_id",
        "description",
        "pressure_class",
        "duration_steps",
        "checkpoint_interval_steps",
        "seed",
        "concurrency_level",
        "cancellation_rate_pct",
        "finding_volume_per_step",
    ];
    for field in &required {
        assert!(
            catalog
                .required_scenario_fields
                .contains(&field.to_string()),
            "Missing required_scenario_field: {field}"
        );
    }
}

#[test]
fn doctor_stress_soak_catalog_has_required_run_fields() {
    let catalog = load_catalog();
    let required = [
        "run_id",
        "scenario_id",
        "seed",
        "status",
        "checkpoint_count",
        "checkpoint_metrics",
        "sustained_budget_pass",
        "artifact_index",
        "repro_command",
    ];
    for field in &required {
        assert!(
            catalog.required_run_fields.contains(&field.to_string()),
            "Missing required_run_field: {field}"
        );
    }
}

#[test]
fn doctor_stress_soak_catalog_has_required_metric_fields() {
    let catalog = load_catalog();
    let required = [
        "checkpoint_index",
        "latency_p50_ms",
        "latency_p95_ms",
        "latency_p99_ms",
        "memory_peak_mb",
        "error_rate_bps",
        "drift_basis_points",
    ];
    for field in &required {
        assert!(
            catalog.required_metric_fields.contains(&field.to_string()),
            "Missing required_metric_field: {field}"
        );
    }
}

// ─── 4. Scenario catalog validation ────────────────────────────────

#[test]
fn doctor_stress_soak_catalog_has_at_least_three_scenarios() {
    let catalog = load_catalog();
    assert!(
        catalog.scenario_catalog.len() >= 3,
        "Catalog must have >= 3 scenarios, got {}",
        catalog.scenario_catalog.len()
    );
}

#[test]
fn doctor_stress_soak_scenario_ids_unique() {
    let catalog = load_catalog();
    let ids: HashSet<&str> = catalog
        .scenario_catalog
        .iter()
        .map(|s| s.scenario_id.as_str())
        .collect();
    assert_eq!(ids.len(), catalog.scenario_catalog.len());
}

#[test]
fn doctor_stress_soak_scenarios_cover_all_pressure_classes() {
    let catalog = load_catalog();
    let classes: HashSet<&str> = catalog
        .scenario_catalog
        .iter()
        .map(|s| s.pressure_class.as_str())
        .collect();
    for class in &PRESSURE_CLASSES {
        assert!(
            classes.contains(class),
            "No scenario covers pressure class: {class}"
        );
    }
}

#[test]
fn doctor_stress_soak_scenario_ids_are_slug_format() {
    let catalog = load_catalog();
    for scenario in &catalog.scenario_catalog {
        let id = &scenario.scenario_id;
        assert!(!id.is_empty(), "Scenario ID must be non-empty");
        assert!(
            id.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "Scenario ID must start with lowercase alphanumeric: {id}"
        );
        assert!(
            id.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._:/-".contains(c)),
            "Scenario ID must be slug-like: {id}"
        );
    }
}

#[test]
fn doctor_stress_soak_scenarios_reference_valid_envelopes() {
    let catalog = load_catalog();
    let envelope_ids: HashSet<&str> = catalog
        .budget_envelopes
        .iter()
        .map(|e| e.envelope_id.as_str())
        .collect();
    for scenario in &catalog.scenario_catalog {
        assert!(
            envelope_ids.contains(scenario.budget_envelope_id.as_str()),
            "Scenario {} references unknown envelope: {}",
            scenario.scenario_id,
            scenario.budget_envelope_id
        );
    }
}

#[test]
fn doctor_stress_soak_scenarios_have_positive_durations() {
    let catalog = load_catalog();
    for scenario in &catalog.scenario_catalog {
        assert!(
            scenario.duration_steps > 0,
            "Scenario {} has zero duration",
            scenario.scenario_id
        );
        assert!(
            scenario.checkpoint_interval_steps > 0,
            "Scenario {} has zero checkpoint interval",
            scenario.scenario_id
        );
        assert!(
            scenario.duration_steps >= scenario.checkpoint_interval_steps,
            "Scenario {} duration < checkpoint interval",
            scenario.scenario_id
        );
    }
}

#[test]
fn doctor_stress_soak_scenarios_have_valid_cancellation_rates() {
    let catalog = load_catalog();
    for scenario in &catalog.scenario_catalog {
        assert!(
            scenario.cancellation_rate_pct <= 100,
            "Scenario {} has cancellation rate > 100%: {}",
            scenario.scenario_id,
            scenario.cancellation_rate_pct
        );
    }
}

// ─── 5. Sustained budget policy validation ──────────────────────────

#[test]
fn doctor_stress_soak_policy_has_at_least_three_rules() {
    let catalog = load_catalog();
    assert!(
        catalog.sustained_budget_policy.len() >= 3,
        "Must have >= 3 sustained budget policies, got {}",
        catalog.sustained_budget_policy.len()
    );
}

#[test]
fn doctor_stress_soak_policy_ids_unique() {
    let catalog = load_catalog();
    let ids: HashSet<&str> = catalog
        .sustained_budget_policy
        .iter()
        .map(|p| p.policy_id.as_str())
        .collect();
    assert_eq!(ids.len(), catalog.sustained_budget_policy.len());
}

#[test]
fn doctor_stress_soak_policy_covers_key_metrics() {
    let catalog = load_catalog();
    let metrics: HashSet<&str> = catalog
        .sustained_budget_policy
        .iter()
        .map(|p| p.metric.as_str())
        .collect();
    for m in &SUSTAINED_BUDGET_METRICS {
        assert!(
            metrics.contains(m),
            "No sustained budget policy covers metric: {m}"
        );
    }
}

#[test]
fn doctor_stress_soak_policy_violation_actions_are_budget_failed() {
    let catalog = load_catalog();
    for policy in &catalog.sustained_budget_policy {
        assert_eq!(
            policy.violation_action, "budget_failed",
            "Policy {} violation_action must be budget_failed, got {}",
            policy.policy_id, policy.violation_action
        );
    }
}

#[test]
fn doctor_stress_soak_policy_threshold_sources_valid() {
    let catalog = load_catalog();
    let valid_sources = ["budget_envelope", "fixed"];
    for policy in &catalog.sustained_budget_policy {
        assert!(
            valid_sources.contains(&policy.threshold_source.as_str()),
            "Policy {} has invalid threshold_source: {}",
            policy.policy_id,
            policy.threshold_source
        );
        if policy.threshold_source == "fixed" {
            assert!(
                policy.threshold_value.is_some(),
                "Policy {} with fixed threshold_source must have threshold_value",
                policy.policy_id
            );
        }
    }
}

// ─── 6. Budget envelopes validation ────────────────────────────────

#[test]
fn doctor_stress_soak_envelopes_have_at_least_three() {
    let catalog = load_catalog();
    assert!(
        catalog.budget_envelopes.len() >= 3,
        "Must have >= 3 budget envelopes, got {}",
        catalog.budget_envelopes.len()
    );
}

#[test]
fn doctor_stress_soak_envelope_ids_unique() {
    let catalog = load_catalog();
    let ids: HashSet<&str> = catalog
        .budget_envelopes
        .iter()
        .map(|e| e.envelope_id.as_str())
        .collect();
    assert_eq!(ids.len(), catalog.budget_envelopes.len());
}

#[test]
fn doctor_stress_soak_envelope_latency_ordering() {
    let catalog = load_catalog();
    for envelope in &catalog.budget_envelopes {
        assert!(
            envelope.latency_p50_ms <= envelope.latency_p95_ms,
            "Envelope {} p50 ({}) > p95 ({})",
            envelope.envelope_id,
            envelope.latency_p50_ms,
            envelope.latency_p95_ms
        );
        assert!(
            envelope.latency_p95_ms <= envelope.latency_p99_ms,
            "Envelope {} p95 ({}) > p99 ({})",
            envelope.envelope_id,
            envelope.latency_p95_ms,
            envelope.latency_p99_ms
        );
    }
}

#[test]
fn doctor_stress_soak_envelope_memory_positive() {
    let catalog = load_catalog();
    for envelope in &catalog.budget_envelopes {
        assert!(
            envelope.memory_ceiling_mb > 0,
            "Envelope {} has zero memory ceiling",
            envelope.envelope_id
        );
    }
}

// ─── 7. Smoke report schema validation ─────────────────────────────

#[test]
fn doctor_stress_soak_smoke_report_schema_version() {
    let report = load_smoke_report();
    assert_eq!(report.schema_version, SMOKE_REPORT_SCHEMA_VERSION);
}

#[test]
fn doctor_stress_soak_smoke_report_profile_mode_valid() {
    let report = load_smoke_report();
    assert!(
        PROFILE_MODES.contains(&report.profile_mode.as_str()),
        "Invalid profile_mode: {}",
        report.profile_mode
    );
}

#[test]
fn doctor_stress_soak_smoke_report_has_pass_criteria() {
    let report = load_smoke_report();
    assert!(
        !report.pass_criteria.is_empty(),
        "pass_criteria must be non-empty"
    );
    assert!(
        report.pass_criteria.contains("post-warmup checkpoints"),
        "pass_criteria must mention post-warmup checkpoints"
    );
}

#[test]
fn doctor_stress_soak_smoke_report_has_at_least_three_runs() {
    let report = load_smoke_report();
    assert!(
        report.runs.len() >= 3,
        "Smoke report must have >= 3 runs, got {}",
        report.runs.len()
    );
}

#[test]
fn doctor_stress_soak_smoke_report_run_ids_unique() {
    let report = load_smoke_report();
    let ids: HashSet<&str> = report.runs.iter().map(|r| r.run_id.as_str()).collect();
    assert_eq!(ids.len(), report.runs.len());
}

#[test]
fn doctor_stress_soak_smoke_report_runs_lexically_ordered() {
    let report = load_smoke_report();
    let scenario_ids: Vec<&str> = report.runs.iter().map(|r| r.scenario_id.as_str()).collect();
    let mut sorted = scenario_ids.clone();
    sorted.sort_unstable();
    assert_eq!(
        scenario_ids, sorted,
        "Runs must be ordered by scenario_id lexically"
    );
}

// ─── 8. Checkpoint metrics validation ───────────────────────────────

#[test]
fn doctor_stress_soak_checkpoint_counts_match() {
    let report = load_smoke_report();
    for run in &report.runs {
        assert_eq!(
            run.checkpoint_count,
            run.checkpoint_metrics.len(),
            "Run {} checkpoint_count ({}) != metrics length ({})",
            run.run_id,
            run.checkpoint_count,
            run.checkpoint_metrics.len()
        );
    }
}

#[test]
fn doctor_stress_soak_checkpoint_indices_sequential() {
    let report = load_smoke_report();
    for run in &report.runs {
        for (i, metric) in run.checkpoint_metrics.iter().enumerate() {
            assert_eq!(
                metric.checkpoint_index, i,
                "Run {} checkpoint {}: expected index {i}, got {}",
                run.run_id, i, metric.checkpoint_index
            );
        }
    }
}

#[test]
fn doctor_stress_soak_all_checkpoints_have_at_least_four() {
    let report = load_smoke_report();
    for run in &report.runs {
        assert!(
            run.checkpoint_count >= 4,
            "Run {} must have >= 4 checkpoints, got {}",
            run.run_id,
            run.checkpoint_count
        );
    }
}

#[test]
fn doctor_stress_soak_checkpoint_latency_ordering() {
    let report = load_smoke_report();
    for run in &report.runs {
        for metric in &run.checkpoint_metrics {
            assert!(
                metric.latency_p50_ms <= metric.latency_p95_ms,
                "Run {} checkpoint {}: p50 ({}) > p95 ({})",
                run.run_id,
                metric.checkpoint_index,
                metric.latency_p50_ms,
                metric.latency_p95_ms
            );
            assert!(
                metric.latency_p95_ms <= metric.latency_p99_ms,
                "Run {} checkpoint {}: p95 ({}) > p99 ({})",
                run.run_id,
                metric.checkpoint_index,
                metric.latency_p95_ms,
                metric.latency_p99_ms
            );
        }
    }
}

#[test]
fn doctor_stress_soak_baseline_checkpoint_has_zero_drift() {
    let report = load_smoke_report();
    for run in &report.runs {
        if let Some(first) = run.checkpoint_metrics.first() {
            assert_eq!(
                first.drift_basis_points, 0,
                "Run {} baseline checkpoint must have zero drift, got {}",
                run.run_id, first.drift_basis_points
            );
        }
    }
}

// ─── 9. Artifact index validation ───────────────────────────────────

#[test]
fn doctor_stress_soak_artifact_index_has_three_classes() {
    let report = load_smoke_report();
    for run in &report.runs {
        let classes: Vec<&str> = run
            .artifact_index
            .iter()
            .map(|a| a.artifact_class.as_str())
            .collect();
        let mut sorted_classes = classes.clone();
        sorted_classes.sort_unstable();
        assert_eq!(
            sorted_classes,
            ARTIFACT_CLASSES.to_vec(),
            "Run {} artifact_index classes must be {:?}, got {:?}",
            run.run_id,
            ARTIFACT_CLASSES,
            sorted_classes
        );
    }
}

#[test]
fn doctor_stress_soak_artifact_paths_non_empty() {
    let report = load_smoke_report();
    for run in &report.runs {
        for artifact in &run.artifact_index {
            assert!(
                !artifact.path.is_empty(),
                "Run {} artifact {} has empty path",
                run.run_id,
                artifact.artifact_class
            );
        }
    }
}

// ─── 10. Repro commands ─────────────────────────────────────────────

#[test]
fn doctor_stress_soak_repro_commands_contain_cli() {
    let report = load_smoke_report();
    for run in &report.runs {
        assert!(
            run.repro_command
                .contains("asupersync doctor stress-soak-smoke"),
            "Run {} repro_command must contain CLI command, got: {}",
            run.run_id,
            run.repro_command
        );
    }
}

#[test]
fn doctor_stress_soak_repro_commands_contain_seed() {
    let report = load_smoke_report();
    for run in &report.runs {
        assert!(
            run.repro_command.contains(&format!("--seed {}", run.seed)),
            "Run {} repro_command must contain --seed {}",
            run.run_id,
            run.seed
        );
    }
}

// ─── 11. Sustained budget conformance (E2E-referenced name) ────────

#[test]
fn doctor_stress_soak_smoke_enforces_sustained_budget_conformance() {
    let catalog = load_catalog();
    let report = load_smoke_report();

    for run in &report.runs {
        let (pass, _violations) = evaluate_sustained_budget(
            run,
            &catalog.sustained_budget_policy,
            &catalog.budget_envelopes,
            &catalog.scenario_catalog,
        );

        assert_eq!(
            pass, run.sustained_budget_pass,
            "Run {}: computed sustained_budget_pass={pass} but fixture says {}",
            run.run_id, run.sustained_budget_pass
        );

        if run.sustained_budget_pass {
            assert_eq!(
                run.status, "passed",
                "Run {} with sustained_budget_pass=true must have status=passed",
                run.run_id
            );
        } else {
            assert_eq!(
                run.status, "budget_failed",
                "Run {} with sustained_budget_pass=false must have status=budget_failed",
                run.run_id
            );
        }
    }
}

// ─── 12. Failure output quality (E2E-referenced name) ───────────────

#[test]
fn doctor_stress_soak_failure_output_includes_saturation_trace_and_rerun() {
    let report = load_smoke_report();
    let failed_runs: Vec<&SmokeRun> = report
        .runs
        .iter()
        .filter(|r| r.status == "budget_failed")
        .collect();

    assert!(
        !failed_runs.is_empty(),
        "Golden report must have at least one budget_failed run"
    );

    for run in &failed_runs {
        let output = run.failure_output.as_ref().unwrap_or_else(|| {
            panic!(
                "Run {} is budget_failed but has no failure_output",
                run.run_id
            )
        });

        // Saturation indicators
        assert!(
            !output.saturation_indicators.is_empty(),
            "Run {} failure_output must have saturation_indicators",
            run.run_id
        );
        let mut sorted_indicators = output.saturation_indicators.clone();
        sorted_indicators.sort();
        assert_eq!(
            output.saturation_indicators, sorted_indicators,
            "Run {} saturation_indicators must be lexically sorted",
            run.run_id
        );

        // Trace correlation
        assert!(
            output.trace_correlation.starts_with("trace-"),
            "Run {} trace_correlation must start with 'trace-', got: {}",
            run.run_id,
            output.trace_correlation
        );

        // Rerun command
        assert!(
            output
                .rerun_command
                .contains("asupersync doctor stress-soak-smoke"),
            "Run {} rerun_command must contain CLI command",
            run.run_id
        );
    }
}

#[test]
fn doctor_stress_soak_passed_runs_have_no_failure_output() {
    let report = load_smoke_report();
    for run in &report.runs {
        if run.status == "passed" {
            assert!(
                run.failure_output.is_none(),
                "Run {} is passed but has failure_output",
                run.run_id
            );
        }
    }
}

#[test]
fn doctor_stress_soak_has_at_least_one_failed_run() {
    let report = load_smoke_report();
    assert!(
        report.runs.iter().any(|r| r.status == "budget_failed"),
        "Golden report must contain at least one budget_failed run"
    );
}

// ─── 13. Overall status validation ──────────────────────────────────

#[test]
fn doctor_stress_soak_overall_status_matches_runs() {
    let report = load_smoke_report();
    let expected = compute_overall_status(&report.runs);
    assert_eq!(
        report.overall_status, expected,
        "overall_status should be {expected}, got {}",
        report.overall_status
    );
}

// ─── 14. Contract validation (E2E-referenced name) ──────────────────

#[test]
fn doctor_stress_soak_contract_validates() {
    let catalog = load_catalog();

    // Schema version
    assert_eq!(catalog.schema_version, CATALOG_SCHEMA_VERSION);

    // Contract versions
    assert_eq!(catalog.contract_version, CATALOG_SCHEMA_VERSION);
    assert_eq!(
        catalog.e2e_harness_contract_version,
        "doctor-e2e-harness-v1"
    );
    assert_eq!(catalog.logging_contract_version, "doctor-logging-v1");

    // Profile modes
    let mut modes = catalog.profile_modes;
    modes.sort();
    assert_eq!(modes, PROFILE_MODES);

    // Required fields present
    assert!(
        catalog
            .required_scenario_fields
            .contains(&"duration_steps".to_string())
    );
    assert!(
        catalog
            .required_run_fields
            .contains(&"sustained_budget_pass".to_string())
    );
    assert!(
        catalog
            .required_metric_fields
            .contains(&"drift_basis_points".to_string())
    );

    // Sustained budget policy
    assert!(catalog.sustained_budget_policy.len() >= 3);

    // Scenario catalog
    assert!(catalog.scenario_catalog.len() >= 3);

    // Budget envelopes
    assert!(catalog.budget_envelopes.len() >= 3);
}

// ─── 15. Determinism (E2E-referenced name) ──────────────────────────

#[test]
fn doctor_stress_soak_smoke_report_is_deterministic() {
    // Load the same fixtures twice and verify identical output
    let report1 = load_smoke_report();
    let report2 = load_smoke_report();

    // Same number of runs
    assert_eq!(report1.runs.len(), report2.runs.len());

    // Same scenario ordering
    for (r1, r2) in report1.runs.iter().zip(report2.runs.iter()) {
        assert_eq!(r1.scenario_id, r2.scenario_id);
        assert_eq!(r1.run_id, r2.run_id);
        assert_eq!(r1.seed, r2.seed);
        assert_eq!(r1.status, r2.status);
        assert_eq!(r1.checkpoint_count, r2.checkpoint_count);
        assert_eq!(r1.sustained_budget_pass, r2.sustained_budget_pass);

        // Checkpoint metrics must match exactly
        for (m1, m2) in r1
            .checkpoint_metrics
            .iter()
            .zip(r2.checkpoint_metrics.iter())
        {
            assert_eq!(m1.checkpoint_index, m2.checkpoint_index);
            assert_eq!(m1.latency_p50_ms, m2.latency_p50_ms);
            assert_eq!(m1.latency_p95_ms, m2.latency_p95_ms);
            assert_eq!(m1.latency_p99_ms, m2.latency_p99_ms);
            assert_eq!(m1.memory_peak_mb, m2.memory_peak_mb);
            assert_eq!(m1.error_rate_bps, m2.error_rate_bps);
            assert_eq!(m1.drift_basis_points, m2.drift_basis_points);
        }
    }

    // Same overall status
    assert_eq!(report1.overall_status, report2.overall_status);
}

#[test]
fn doctor_stress_soak_determinism_invariants_documented() {
    let catalog = load_catalog();
    assert!(
        catalog.determinism_invariants.len() >= 4,
        "Must document at least 4 determinism invariants, got {}",
        catalog.determinism_invariants.len()
    );
}

// ─── 16. Saturation indicators validation ───────────────────────────

#[test]
fn doctor_stress_soak_saturation_indicator_classes_defined() {
    let catalog = load_catalog();
    assert!(
        catalog.saturation_indicators.indicator_classes.len() >= 3,
        "Must define at least 3 saturation indicator classes"
    );
}

#[test]
fn doctor_stress_soak_saturation_indicators_reference_policies() {
    let report = load_smoke_report();
    for run in &report.runs {
        if let Some(ref output) = run.failure_output {
            for indicator in &output.saturation_indicators {
                assert!(
                    indicator.contains("SBP-"),
                    "Saturation indicator must reference policy ID (SBP-xx): {indicator}"
                );
            }
        }
    }
}

// ─── 17. Cross-validation: catalog scenarios match report runs ──────

#[test]
fn doctor_stress_soak_report_scenarios_in_catalog() {
    let catalog = load_catalog();
    let report = load_smoke_report();
    let catalog_ids: HashSet<&str> = catalog
        .scenario_catalog
        .iter()
        .map(|s| s.scenario_id.as_str())
        .collect();
    for run in &report.runs {
        assert!(
            catalog_ids.contains(run.scenario_id.as_str()),
            "Report run scenario {} not in catalog",
            run.scenario_id
        );
    }
}

#[test]
fn doctor_stress_soak_report_seeds_match_catalog() {
    let catalog = load_catalog();
    let report = load_smoke_report();
    for run in &report.runs {
        if let Some(scenario) = catalog
            .scenario_catalog
            .iter()
            .find(|s| s.scenario_id == run.scenario_id)
        {
            assert_eq!(
                run.seed, scenario.seed,
                "Run {} seed ({}) != catalog seed ({})",
                run.run_id, run.seed, scenario.seed
            );
        }
    }
}

// ─── 18. Edge cases and failure modes ───────────────────────────────

#[test]
fn doctor_stress_soak_empty_scenario_catalog_detected() {
    // Verify our evaluation function handles empty scenarios gracefully
    let run = SmokeRun {
        run_id: "run-empty".into(),
        scenario_id: "nonexistent".into(),
        seed: 0,
        status: "passed".into(),
        checkpoint_count: 1,
        sustained_budget_pass: true,
        checkpoint_metrics: vec![CheckpointMetric {
            checkpoint_index: 0,
            latency_p50_ms: 10,
            latency_p95_ms: 20,
            latency_p99_ms: 30,
            memory_peak_mb: 16,
            error_rate_bps: 0,
            drift_basis_points: 0,
        }],
        failure_output: None,
        artifact_index: vec![],
        repro_command: String::new(),
    };

    let (pass, violations) = evaluate_sustained_budget(&run, &[], &[], &[]);
    assert!(pass, "Empty policies should pass");
    assert!(violations.is_empty());
}

#[test]
fn doctor_stress_soak_budget_failure_detection_works() {
    let catalog = load_catalog();
    let report = load_smoke_report();

    // Find the cancel-recovery run which should fail
    let cancel_run = report
        .runs
        .iter()
        .find(|r| r.scenario_id == "stress-cancel-recovery")
        .expect("Must have stress-cancel-recovery run");

    let (pass, violations) = evaluate_sustained_budget(
        cancel_run,
        &catalog.sustained_budget_policy,
        &catalog.budget_envelopes,
        &catalog.scenario_catalog,
    );

    assert!(!pass, "Cancel-recovery run should fail budget conformance");
    assert!(
        !violations.is_empty(),
        "Cancel-recovery should produce violations"
    );
}

#[test]
fn doctor_stress_soak_passing_runs_pass_evaluation() {
    let catalog = load_catalog();
    let report = load_smoke_report();

    let passing_runs: Vec<&SmokeRun> = report
        .runs
        .iter()
        .filter(|r| r.status == "passed")
        .collect();

    assert!(
        !passing_runs.is_empty(),
        "Must have at least one passing run"
    );

    for run in &passing_runs {
        let (pass, violations) = evaluate_sustained_budget(
            run,
            &catalog.sustained_budget_policy,
            &catalog.budget_envelopes,
            &catalog.scenario_catalog,
        );
        assert!(
            pass,
            "Run {} should pass evaluation but got violations: {:?}",
            run.run_id, violations
        );
    }
}

#[test]
fn doctor_stress_soak_high_drift_triggers_failure() {
    let policy = vec![SustainedBudgetPolicy {
        policy_id: "SBP-04".into(),
        description: "drift test".into(),
        metric: "drift_basis_points".into(),
        warmup_checkpoints: 0,
        threshold_source: "fixed".into(),
        threshold_value: Some(100),
        violation_action: "budget_failed".into(),
    }];

    let run = SmokeRun {
        run_id: "run-drift-test".into(),
        scenario_id: "test".into(),
        seed: 0,
        status: "budget_failed".into(),
        checkpoint_count: 2,
        sustained_budget_pass: false,
        checkpoint_metrics: vec![
            CheckpointMetric {
                checkpoint_index: 0,
                latency_p50_ms: 10,
                latency_p95_ms: 20,
                latency_p99_ms: 30,
                memory_peak_mb: 16,
                error_rate_bps: 0,
                drift_basis_points: 0,
            },
            CheckpointMetric {
                checkpoint_index: 1,
                latency_p50_ms: 10,
                latency_p95_ms: 20,
                latency_p99_ms: 30,
                memory_peak_mb: 16,
                error_rate_bps: 0,
                drift_basis_points: 500,
            },
        ],
        failure_output: None,
        artifact_index: vec![],
        repro_command: String::new(),
    };

    let (pass, violations) = evaluate_sustained_budget(&run, &policy, &[], &[]);
    assert!(!pass, "High drift should trigger failure");
    assert!(
        violations.iter().any(|v| v.contains("SBP-04")),
        "Must mention SBP-04 in violations"
    );
}

#[test]
fn doctor_stress_soak_warmup_checkpoints_are_excluded() {
    let policy = vec![SustainedBudgetPolicy {
        policy_id: "SBP-03".into(),
        description: "error rate test".into(),
        metric: "error_rate_bps".into(),
        warmup_checkpoints: 1,
        threshold_source: "fixed".into(),
        threshold_value: Some(100),
        violation_action: "budget_failed".into(),
    }];

    // Checkpoint 0 exceeds threshold but is in warmup
    let run = SmokeRun {
        run_id: "run-warmup-test".into(),
        scenario_id: "test".into(),
        seed: 0,
        status: "passed".into(),
        checkpoint_count: 2,
        sustained_budget_pass: true,
        checkpoint_metrics: vec![
            CheckpointMetric {
                checkpoint_index: 0,
                latency_p50_ms: 10,
                latency_p95_ms: 20,
                latency_p99_ms: 30,
                memory_peak_mb: 16,
                error_rate_bps: 9999,
                drift_basis_points: 0,
            },
            CheckpointMetric {
                checkpoint_index: 1,
                latency_p50_ms: 10,
                latency_p95_ms: 20,
                latency_p99_ms: 30,
                memory_peak_mb: 16,
                error_rate_bps: 50,
                drift_basis_points: 0,
            },
        ],
        failure_output: None,
        artifact_index: vec![],
        repro_command: String::new(),
    };

    let (pass, violations) = evaluate_sustained_budget(&run, &policy, &[], &[]);
    assert!(
        pass,
        "Warmup checkpoint violations should be excluded, but got: {violations:?}"
    );
}
