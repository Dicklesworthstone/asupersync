#![allow(warnings)]
#![allow(clippy::all)]
//! Performance Budget and Instrumentation Gate Validation (Track 6.2)
//!
//! Validates the performance budget matrix, gate evaluation logic,
//! golden fixture schema, structured log integration, and document
//! coverage for doctor_asupersync performance instrumentation.
//!
//! Bead: asupersync-2b4jj.6.2

#![allow(missing_docs)]
#![allow(dead_code)]
#![cfg(feature = "cli")]

use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ─── Constants ──────────────────────────────────────────────────────

const DOC_PATH: &str = "docs/doctor_performance_budget_contract.md";
const FIXTURE_DIR: &str = "tests/fixtures/doctor_performance_budget";
const BUDGET_FIXTURE_PATH: &str = "tests/fixtures/doctor_performance_budget/budgets.json";
const GATE_REPORT_FIXTURE_PATH: &str = "tests/fixtures/doctor_performance_budget/gate_report.json";
const BUDGET_FIXTURE_SCHEMA_VERSION: &str = "doctor-performance-budget-fixture-pack-v1";
const GATE_REPORT_SCHEMA_VERSION: &str = "doctor-performance-gate-report-v1";

const WORKFLOW_CATEGORIES: [&str; 5] = ["scan", "analyze", "ingest", "remediate", "render"];
const DATASET_PROFILES: [&str; 3] = ["small", "medium", "large"];
const METRIC_CLASSES: [&str; 4] = ["latency", "memory", "render_cost", "update_cost"];
const GATE_OUTCOMES: [&str; 3] = ["pass", "warn", "fail"];

// ─── Fixture types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct BudgetFixturePack {
    schema_version: String,
    description: String,
    budgets: Vec<BudgetFixture>,
}

#[derive(Debug, Clone, Deserialize)]
struct BudgetFixture {
    budget_id: String,
    workflow_category: String,
    dataset_profile: String,
    latency_p50_ms: u64,
    latency_p95_ms: u64,
    latency_p99_ms: u64,
    memory_ceiling_mb: u32,
    render_cost_max: u32,
    update_cost_max: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct GateReportFixture {
    schema_version: String,
    run_id: String,
    scenario_id: String,
    budgets: Vec<BudgetFixture>,
    metrics: Vec<MetricFixture>,
    evaluations: Vec<EvaluationFixture>,
    overall_outcome: String,
    reproduction_command: String,
    correlation_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct MetricFixture {
    metric_id: String,
    metric_class: String,
    workflow_category: String,
    dataset_profile: String,
    value: u64,
    unit: String,
    percentile: String,
    correlation_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct EvaluationFixture {
    gate_id: String,
    budget_id: String,
    metric_id: String,
    threshold: u64,
    measured: u64,
    outcome: String,
    headroom_pct: i32,
    confidence: u8,
    correlation_id: String,
}

// ─── Helpers ────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load performance budget doc")
}

fn load_budget_pack() -> BudgetFixturePack {
    let raw = std::fs::read_to_string(repo_root().join(BUDGET_FIXTURE_PATH))
        .expect("failed to load budget fixture pack");
    serde_json::from_str(&raw).expect("failed to parse budget fixture pack")
}

fn load_gate_report() -> GateReportFixture {
    let raw = std::fs::read_to_string(repo_root().join(GATE_REPORT_FIXTURE_PATH))
        .expect("failed to load gate report fixture");
    serde_json::from_str(&raw).expect("failed to parse gate report fixture")
}

fn evaluate_gate(threshold: u64, measured: u64) -> &'static str {
    let warn_threshold = (threshold * 80) / 100;
    if measured > threshold {
        "fail"
    } else if measured > warn_threshold {
        "warn"
    } else {
        "pass"
    }
}

#[allow(clippy::cast_possible_wrap)]
fn compute_headroom(threshold: u64, measured: u64) -> i32 {
    if threshold == 0 {
        return 0;
    }
    (((threshold as i64 - measured as i64) * 100) / threshold as i64) as i32
}

fn outcome_severity(outcome: &str) -> u8 {
    match outcome {
        "pass" => 0,
        "warn" => 1,
        "fail" => 2,
        _ => 3,
    }
}

// ─── Document infrastructure ────────────────────────────────────────

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "Performance budget doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2b4jj.6.2"),
        "Doc must reference its own bead ID"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Budget Data Model",
        "Budget Matrix",
        "Gate Evaluation Logic",
        "Structured Log Integration",
        "CI Integration",
        "Determinism Invariants",
        "CI Validation",
        "Cross-References",
    ];
    let mut missing = Vec::new();
    for section in &sections {
        if !doc.contains(section) {
            missing.push(*section);
        }
    }
    assert!(
        missing.is_empty(),
        "Doc missing sections:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_cross_documents() {
    let doc = load_doc();
    let refs = [
        "doctor_visual_regression_harness.md",
        "doctor_e2e_harness_contract.md",
        "doctor_logging_contract.md",
        "doctor_analyzer_fixture_harness.md",
    ];
    let mut missing = Vec::new();
    for r in &refs {
        if !doc.contains(r) {
            missing.push(*r);
        }
    }
    assert!(
        missing.is_empty(),
        "Doc missing cross-references:\n{}",
        missing
            .iter()
            .map(|r| format!("  - {r}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_test_file() {
    let doc = load_doc();
    assert!(
        doc.contains("doctor_performance_budget_gates.rs"),
        "Doc must reference its own test file"
    );
}

#[test]
fn doc_documents_all_workflow_categories() {
    let doc = load_doc();
    for cat in &WORKFLOW_CATEGORIES {
        assert!(
            doc.contains(&format!("`{cat}`")),
            "Doc must document workflow category: {cat}"
        );
    }
}

#[test]
fn doc_documents_all_dataset_profiles() {
    let doc = load_doc();
    for profile in &DATASET_PROFILES {
        assert!(
            doc.contains(&format!("`{profile}`")),
            "Doc must document dataset profile: {profile}"
        );
    }
}

#[test]
fn doc_documents_gate_outcomes() {
    let doc = load_doc();
    for outcome in &GATE_OUTCOMES {
        assert!(
            doc.contains(&format!("`{outcome}`")),
            "Doc must document gate outcome: {outcome}"
        );
    }
}

#[test]
fn doc_documents_warning_threshold() {
    let doc = load_doc();
    assert!(
        doc.contains("80%") || doc.contains("0.80"),
        "Doc must document the 80% warning threshold"
    );
}

#[test]
fn doc_documents_determinism_invariant_count() {
    let doc = load_doc();
    let count = doc
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            (1..=8).any(|i| trimmed.starts_with(&format!("{i}. **")))
        })
        .count();
    assert!(
        count >= 8,
        "Doc must have at least 8 determinism invariants, found {count}"
    );
}

#[test]
fn doc_documents_event_kinds() {
    let doc = load_doc();
    let kinds = [
        "perf_metric_collected",
        "perf_gate_evaluated",
        "perf_gate_report_emitted",
        "perf_regression_detected",
    ];
    let mut missing = Vec::new();
    for kind in &kinds {
        if !doc.contains(kind) {
            missing.push(*kind);
        }
    }
    assert!(
        missing.is_empty(),
        "Doc missing event kinds:\n{}",
        missing
            .iter()
            .map(|k| format!("  - {k}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Budget fixture pack validation ─────────────────────────────────

#[test]
fn fixture_directory_exists() {
    assert!(
        Path::new(FIXTURE_DIR).exists(),
        "Performance budget fixture directory must exist"
    );
}

#[test]
fn budget_pack_loads() {
    let pack = load_budget_pack();
    assert_eq!(pack.schema_version, BUDGET_FIXTURE_SCHEMA_VERSION);
    assert!(!pack.description.is_empty());
}

#[test]
fn budget_pack_covers_all_workflow_categories() {
    let pack = load_budget_pack();
    let categories: HashSet<&str> = pack
        .budgets
        .iter()
        .map(|b| b.workflow_category.as_str())
        .collect();
    for cat in &WORKFLOW_CATEGORIES {
        assert!(
            categories.contains(cat),
            "Budget pack must cover workflow category: {cat}"
        );
    }
}

#[test]
fn budget_pack_covers_all_dataset_profiles() {
    let pack = load_budget_pack();
    let profiles: HashSet<&str> = pack
        .budgets
        .iter()
        .map(|b| b.dataset_profile.as_str())
        .collect();
    for profile in &DATASET_PROFILES {
        assert!(
            profiles.contains(profile),
            "Budget pack must cover dataset profile: {profile}"
        );
    }
}

#[test]
fn budget_pack_has_expected_count() {
    let pack = load_budget_pack();
    let expected = WORKFLOW_CATEGORIES.len() * DATASET_PROFILES.len();
    assert_eq!(
        pack.budgets.len(),
        expected,
        "Budget pack should have {expected} entries (5 categories x 3 profiles)"
    );
}

#[test]
fn budget_pack_ids_are_unique() {
    let pack = load_budget_pack();
    let mut ids = HashSet::new();
    for budget in &pack.budgets {
        assert!(
            ids.insert(&budget.budget_id),
            "Duplicate budget ID: {}",
            budget.budget_id
        );
    }
}

#[test]
fn budget_pack_latency_ordering() {
    let pack = load_budget_pack();
    for budget in &pack.budgets {
        assert!(
            budget.latency_p50_ms <= budget.latency_p95_ms,
            "Budget {} p50 ({}) must be <= p95 ({})",
            budget.budget_id,
            budget.latency_p50_ms,
            budget.latency_p95_ms
        );
        assert!(
            budget.latency_p95_ms <= budget.latency_p99_ms,
            "Budget {} p95 ({}) must be <= p99 ({})",
            budget.budget_id,
            budget.latency_p95_ms,
            budget.latency_p99_ms
        );
    }
}

#[test]
fn budget_pack_latency_increases_with_dataset_size() {
    let pack = load_budget_pack();
    for cat in &WORKFLOW_CATEGORIES {
        let budgets: Vec<&BudgetFixture> = pack
            .budgets
            .iter()
            .filter(|b| b.workflow_category == *cat)
            .collect();
        let small = budgets.iter().find(|b| b.dataset_profile == "small");
        let medium = budgets.iter().find(|b| b.dataset_profile == "medium");
        let large = budgets.iter().find(|b| b.dataset_profile == "large");

        if let (Some(s), Some(m)) = (small, medium) {
            assert!(
                s.latency_p50_ms <= m.latency_p50_ms,
                "{cat}: small p50 should be <= medium p50"
            );
        }
        if let (Some(m), Some(l)) = (medium, large) {
            assert!(
                m.latency_p50_ms <= l.latency_p50_ms,
                "{cat}: medium p50 should be <= large p50"
            );
        }
    }
}

#[test]
fn budget_pack_memory_increases_with_dataset_size() {
    let pack = load_budget_pack();
    for cat in &WORKFLOW_CATEGORIES {
        let budgets: Vec<&BudgetFixture> = pack
            .budgets
            .iter()
            .filter(|b| b.workflow_category == *cat)
            .collect();
        let small = budgets.iter().find(|b| b.dataset_profile == "small");
        let medium = budgets.iter().find(|b| b.dataset_profile == "medium");
        let large = budgets.iter().find(|b| b.dataset_profile == "large");

        if let (Some(s), Some(m)) = (small, medium) {
            assert!(
                s.memory_ceiling_mb <= m.memory_ceiling_mb,
                "{cat}: small memory should be <= medium memory"
            );
        }
        if let (Some(m), Some(l)) = (medium, large) {
            assert!(
                m.memory_ceiling_mb <= l.memory_ceiling_mb,
                "{cat}: medium memory should be <= large memory"
            );
        }
    }
}

#[test]
fn budget_pack_render_workflows_have_costs() {
    let pack = load_budget_pack();
    for budget in &pack.budgets {
        if budget.workflow_category == "remediate" || budget.workflow_category == "render" {
            assert!(
                budget.render_cost_max > 0,
                "Budget {} must have render_cost_max > 0",
                budget.budget_id
            );
            assert!(
                budget.update_cost_max > 0,
                "Budget {} must have update_cost_max > 0",
                budget.budget_id
            );
        }
    }
}

#[test]
fn budget_pack_non_render_workflows_zero_costs() {
    let pack = load_budget_pack();
    for budget in &pack.budgets {
        if budget.workflow_category != "remediate" && budget.workflow_category != "render" {
            assert_eq!(
                budget.render_cost_max, 0,
                "Budget {} should have render_cost_max = 0",
                budget.budget_id
            );
            assert_eq!(
                budget.update_cost_max, 0,
                "Budget {} should have update_cost_max = 0",
                budget.budget_id
            );
        }
    }
}

// ─── Gate report fixture validation ─────────────────────────────────

#[test]
fn gate_report_loads() {
    let report = load_gate_report();
    assert_eq!(report.schema_version, GATE_REPORT_SCHEMA_VERSION);
    assert!(!report.run_id.is_empty());
    assert!(!report.scenario_id.is_empty());
}

#[test]
fn gate_report_correlation_consistent() {
    let report = load_gate_report();
    for metric in &report.metrics {
        assert_eq!(
            metric.correlation_id, report.correlation_id,
            "Metric {} correlation_id must match report",
            metric.metric_id
        );
    }
    for eval in &report.evaluations {
        assert_eq!(
            eval.correlation_id, report.correlation_id,
            "Evaluation {} correlation_id must match report",
            eval.gate_id
        );
    }
}

#[test]
fn gate_report_evaluations_sorted() {
    let report = load_gate_report();
    let ids: Vec<&str> = report
        .evaluations
        .iter()
        .map(|e| e.gate_id.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "Gate evaluations must be sorted by gate_id");
}

#[test]
fn gate_report_metrics_sorted() {
    let report = load_gate_report();
    let ids: Vec<&str> = report
        .metrics
        .iter()
        .map(|m| m.metric_id.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "Metrics must be sorted by metric_id");
}

#[test]
fn gate_report_outcomes_valid() {
    let report = load_gate_report();
    let valid: HashSet<&str> = GATE_OUTCOMES.iter().copied().collect();
    for eval in &report.evaluations {
        assert!(
            valid.contains(eval.outcome.as_str()),
            "Invalid outcome '{}' in evaluation {}",
            eval.outcome,
            eval.gate_id
        );
    }
    assert!(
        valid.contains(report.overall_outcome.as_str()),
        "Invalid overall_outcome: {}",
        report.overall_outcome
    );
}

#[test]
fn gate_report_overall_is_worst_case() {
    let report = load_gate_report();
    let worst = report
        .evaluations
        .iter()
        .map(|e| outcome_severity(&e.outcome))
        .max()
        .unwrap_or(0);
    let expected = match worst {
        0 => "pass",
        1 => "warn",
        _ => "fail",
    };
    assert_eq!(
        report.overall_outcome, expected,
        "overall_outcome must be worst-case of all evaluations"
    );
}

#[test]
fn gate_report_metric_classes_valid() {
    let report = load_gate_report();
    let valid: HashSet<&str> = METRIC_CLASSES.iter().copied().collect();
    for metric in &report.metrics {
        assert!(
            valid.contains(metric.metric_class.as_str()),
            "Invalid metric class '{}' in metric {}",
            metric.metric_class,
            metric.metric_id
        );
    }
}

#[test]
fn gate_report_metric_units_valid() {
    let report = load_gate_report();
    let valid_units = ["ms", "mb", "cost_units"];
    for metric in &report.metrics {
        assert!(
            valid_units.contains(&metric.unit.as_str()),
            "Invalid unit '{}' in metric {}",
            metric.unit,
            metric.metric_id
        );
    }
}

#[test]
fn gate_report_confidence_range() {
    let report = load_gate_report();
    for eval in &report.evaluations {
        assert!(
            eval.confidence <= 100,
            "Confidence must be 0..=100, got {} in evaluation {}",
            eval.confidence,
            eval.gate_id
        );
    }
}

#[test]
fn gate_report_has_reproduction_command() {
    let report = load_gate_report();
    assert!(
        !report.reproduction_command.is_empty(),
        "Gate report must include reproduction command"
    );
}

// ─── Gate evaluation logic ──────────────────────────────────────────

#[test]
fn gate_eval_pass_below_80_pct() {
    assert_eq!(evaluate_gate(100, 50), "pass");
    assert_eq!(evaluate_gate(100, 79), "pass");
    assert_eq!(evaluate_gate(100, 80), "pass");
}

#[test]
fn gate_eval_warn_between_80_and_100_pct() {
    assert_eq!(evaluate_gate(100, 81), "warn");
    assert_eq!(evaluate_gate(100, 90), "warn");
    assert_eq!(evaluate_gate(100, 100), "warn");
}

#[test]
fn gate_eval_fail_above_100_pct() {
    assert_eq!(evaluate_gate(100, 101), "fail");
    assert_eq!(evaluate_gate(100, 200), "fail");
    assert_eq!(evaluate_gate(50, 51), "fail");
}

#[test]
fn gate_eval_headroom_computation() {
    assert_eq!(compute_headroom(100, 70), 30);
    assert_eq!(compute_headroom(100, 100), 0);
    assert_eq!(compute_headroom(100, 120), -20);
    assert_eq!(compute_headroom(200, 150), 25);
}

#[test]
fn gate_eval_golden_report_headrooms_consistent() {
    let report = load_gate_report();
    for eval in &report.evaluations {
        let expected_headroom = compute_headroom(eval.threshold, eval.measured);
        assert_eq!(
            eval.headroom_pct, expected_headroom,
            "Headroom mismatch for {}: expected {expected_headroom}, got {}",
            eval.gate_id, eval.headroom_pct
        );
    }
}

#[test]
fn gate_eval_golden_report_outcomes_consistent() {
    let report = load_gate_report();
    for eval in &report.evaluations {
        let expected_outcome = evaluate_gate(eval.threshold, eval.measured);
        assert_eq!(
            eval.outcome, expected_outcome,
            "Outcome mismatch for {}: expected {expected_outcome}, got {}",
            eval.gate_id, eval.outcome
        );
    }
}

#[test]
fn outcome_severity_ordering() {
    assert!(outcome_severity("pass") < outcome_severity("warn"));
    assert!(outcome_severity("warn") < outcome_severity("fail"));
}

// ─── Budget determinism ─────────────────────────────────────────────

#[test]
fn budget_determinism_same_inputs_same_output() {
    let pack = load_budget_pack();
    let scan_small: Vec<&BudgetFixture> = pack
        .budgets
        .iter()
        .filter(|b| b.workflow_category == "scan" && b.dataset_profile == "small")
        .collect();
    assert_eq!(
        scan_small.len(),
        1,
        "Should have exactly one scan-small budget"
    );
    let b = scan_small[0];
    assert_eq!(b.latency_p50_ms, 50);
    assert_eq!(b.latency_p95_ms, 100);
    assert_eq!(b.latency_p99_ms, 200);
    assert_eq!(b.memory_ceiling_mb, 32);
}

#[test]
fn gate_determinism_same_inputs_same_outcome() {
    let outcome_a = evaluate_gate(100, 85);
    let outcome_b = evaluate_gate(100, 85);
    assert_eq!(
        outcome_a, outcome_b,
        "Same inputs must produce same outcome"
    );

    let headroom_a = compute_headroom(100, 85);
    let headroom_b = compute_headroom(100, 85);
    assert_eq!(
        headroom_a, headroom_b,
        "Same inputs must produce same headroom"
    );
}

// ─── Cross-validation ───────────────────────────────────────────────

#[test]
fn gate_report_budgets_match_fixture_pack() {
    let pack = load_budget_pack();
    let report = load_gate_report();
    for report_budget in &report.budgets {
        let found = pack
            .budgets
            .iter()
            .find(|b| b.budget_id == report_budget.budget_id);
        assert!(
            found.is_some(),
            "Report budget {} must exist in fixture pack",
            report_budget.budget_id
        );
        let fixture = found.unwrap();
        assert_eq!(
            report_budget.latency_p50_ms, fixture.latency_p50_ms,
            "Budget {} p50 mismatch",
            report_budget.budget_id
        );
        assert_eq!(
            report_budget.latency_p95_ms, fixture.latency_p95_ms,
            "Budget {} p95 mismatch",
            report_budget.budget_id
        );
        assert_eq!(
            report_budget.latency_p99_ms, fixture.latency_p99_ms,
            "Budget {} p99 mismatch",
            report_budget.budget_id
        );
    }
}

#[test]
fn gate_report_evaluation_refs_valid() {
    let report = load_gate_report();
    let budget_ids: HashSet<&str> = report
        .budgets
        .iter()
        .map(|b| b.budget_id.as_str())
        .collect();
    let metric_ids: HashSet<&str> = report
        .metrics
        .iter()
        .map(|m| m.metric_id.as_str())
        .collect();
    for eval in &report.evaluations {
        assert!(
            budget_ids.contains(eval.budget_id.as_str()),
            "Evaluation {} references unknown budget: {}",
            eval.gate_id,
            eval.budget_id
        );
        assert!(
            metric_ids.contains(eval.metric_id.as_str()),
            "Evaluation {} references unknown metric: {}",
            eval.gate_id,
            eval.metric_id
        );
    }
}
