#![allow(warnings)]
#![allow(clippy::all)]
//! Logging-Quality Validators and Observability Assertions (Track 6.7)
//!
//! Validates log completeness, schema compliance, trace-correlation integrity,
//! severity classification, suppression policy, and troubleshooting usefulness
//! across doctor_asupersync unit/e2e flows.
//!
//! Bead: asupersync-2b4jj.6.7

#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::manual_string_new)]
#![allow(clippy::useless_vec)]
#![cfg(feature = "cli")]

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

// ─── Constants ──────────────────────────────────────────────────────

const DOC_PATH: &str = "docs/doctor_logging_quality_governance.md";
const LOGGING_CONTRACT_DOC: &str = "docs/doctor_logging_contract.md";
const OBSERVABILITY_DOC: &str = "docs/doctor_observability_taxonomy.md";
const RULES_FIXTURE_PATH: &str = "tests/fixtures/doctor_logging_quality/log_quality_rules.json";
const STREAM_FIXTURE_PATH: &str = "tests/fixtures/doctor_logging_quality/sample_event_stream.json";
const RULES_SCHEMA_VERSION: &str = "doctor-log-quality-rules-v1";
const STREAM_SCHEMA_VERSION: &str = "doctor-log-quality-event-stream-v1";

const ALLOWED_FLOW_IDS: [&str; 4] = ["execution", "integration", "remediation", "replay"];
const ALLOWED_OUTCOMES: [&str; 3] = ["cancelled", "failed", "success"];
const SEVERITY_LEVELS: [&str; 4] = ["info", "warning", "error", "critical"];
const CONSTRAINT_TYPES: [&str; 4] = ["exact_match", "non_empty", "one_of", "regex"];

// ─── Fixture types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct RulesFixture {
    schema_version: String,
    #[allow(dead_code)]
    description: String,
    bead_id: String,
    baseline_contract_version: String,
    observability_contract_version: String,
    envelope_rules: Vec<EnvelopeRule>,
    correlation_rules: Vec<CorrelationRule>,
    taxonomy_rules: Vec<TaxonomyRule>,
    severity_classification: SeverityClassification,
    suppression_policy: SuppressionPolicy,
    quality_scoring: QualityScoring,
}

#[derive(Debug, Clone, Deserialize)]
struct EnvelopeRule {
    rule_id: String,
    field: String,
    constraint: String,
    #[serde(default)]
    expected: serde_json::Value,
    severity: String,
    #[allow(dead_code)]
    description: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CorrelationRule {
    rule_id: String,
    #[allow(dead_code)]
    description: String,
    scope: String,
    severity: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TaxonomyRule {
    rule_id: String,
    #[allow(dead_code)]
    description: String,
    severity: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SeverityClassification {
    levels: Vec<String>,
    escalation_order: Vec<String>,
    outcome_defaults: BTreeMap<String, String>,
    conflict_escalation: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SuppressionPolicy {
    #[allow(dead_code)]
    description: String,
    suppression_entries: Vec<SuppressionEntry>,
    governance: SuppressionGovernance,
}

#[derive(Debug, Clone, Deserialize)]
struct SuppressionEntry {
    suppression_id: String,
    rule_id: String,
    #[allow(dead_code)]
    reason: String,
    scope: String,
    expires: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SuppressionGovernance {
    max_suppressions: usize,
    review_cadence_days: u32,
    expiry_required: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct QualityScoring {
    max_score: u32,
    deductions: BTreeMap<String, u32>,
    pass_threshold: u32,
    warn_threshold: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct EventStreamFixture {
    schema_version: String,
    #[allow(dead_code)]
    description: String,
    bead_id: String,
    run_id: String,
    events: Vec<LogEvent>,
    expected_violations: Vec<ExpectedViolation>,
    expected_quality_score: u32,
    expected_quality_gate: String,
}

#[derive(Debug, Clone, Deserialize)]
struct LogEvent {
    contract_version: String,
    flow_id: String,
    event_kind: String,
    outcome_class: String,
    run_id: String,
    scenario_id: String,
    trace_id: String,
    artifact_pointer: String,
    command_provenance: String,
    #[allow(dead_code)]
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExpectedViolation {
    event_index: usize,
    rule_id: String,
    #[allow(dead_code)]
    field: String,
    severity: String,
    suppressed_by: Option<String>,
}

// ─── Violation tracking ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Violation {
    event_index: usize,
    rule_id: String,
    field: String,
    severity: String,
    suppressed: bool,
}

// ─── Helpers ────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|e| panic!("failed to load {path}: {e}"))
}

fn load_rules() -> RulesFixture {
    let raw = std::fs::read_to_string(repo_root().join(RULES_FIXTURE_PATH))
        .expect("failed to load rules fixture");
    serde_json::from_str(&raw).expect("failed to parse rules fixture")
}

fn load_event_stream() -> EventStreamFixture {
    let raw = std::fs::read_to_string(repo_root().join(STREAM_FIXTURE_PATH))
        .expect("failed to load event stream fixture");
    serde_json::from_str(&raw).expect("failed to parse event stream fixture")
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "info" => 0,
        "warning" => 1,
        "error" => 2,
        "critical" => 3,
        _ => 255,
    }
}

fn matches_regex_simple(pattern: &str, value: &str) -> bool {
    // Simple regex subset: ^prefix[charset]+$
    // Sufficient for run_id, scenario_id, trace_id patterns.
    if let Some(inner) = pattern.strip_prefix('^').and_then(|p| p.strip_suffix('$')) {
        // Split into literal prefix and charset
        if let Some(bracket_start) = inner.find('[') {
            let prefix = &inner[..bracket_start];
            if !value.starts_with(prefix) {
                return false;
            }
            let rest = &value[prefix.len()..];
            if rest.is_empty() {
                return false; // '+' requires at least one char
            }
            // Extract allowed chars from [charset]
            let bracket_end = inner.find(']').unwrap_or(inner.len());
            let charset = &inner[bracket_start + 1..bracket_end];
            // Check the '+' quantifier
            rest.chars().all(|c| {
                charset.contains(c)
                    || (charset.contains("a-z") && c.is_ascii_lowercase())
                    || (charset.contains("0-9") && c.is_ascii_digit())
            })
        } else {
            value == inner
        }
    } else {
        value.contains(pattern)
    }
}

fn is_suppressed(
    rule_id: &str,
    event: &LogEvent,
    suppressions: &[SuppressionEntry],
) -> Option<String> {
    for sup in suppressions {
        if sup.rule_id != rule_id {
            continue;
        }
        // Parse scope: "flow_id=replay"
        if let Some((key, val)) = sup.scope.split_once('=') {
            let matches = match key {
                "flow_id" => event.flow_id == val,
                "scenario_id" => event.scenario_id == val,
                _ => false,
            };
            if matches {
                return Some(sup.suppression_id.clone());
            }
        }
    }
    None
}

fn validate_envelope(event_index: usize, event: &LogEvent, rules: &RulesFixture) -> Vec<Violation> {
    let mut violations = Vec::new();
    for rule in &rules.envelope_rules {
        let value = match rule.field.as_str() {
            "contract_version" => &event.contract_version,
            "flow_id" => &event.flow_id,
            "outcome_class" => &event.outcome_class,
            "run_id" => &event.run_id,
            "scenario_id" => &event.scenario_id,
            "trace_id" => &event.trace_id,
            "artifact_pointer" => &event.artifact_pointer,
            "command_provenance" => &event.command_provenance,
            _ => continue,
        };

        let violated = match rule.constraint.as_str() {
            "exact_match" => {
                if let Some(expected) = rule.expected.as_str() {
                    value != expected
                } else {
                    false
                }
            }
            "one_of" => {
                if let Some(arr) = rule.expected.as_array() {
                    !arr.iter().any(|v| v.as_str().is_some_and(|s| s == value))
                } else {
                    false
                }
            }
            "regex" => {
                if let Some(pattern) = rule.expected.as_str() {
                    !matches_regex_simple(pattern, value)
                } else {
                    false
                }
            }
            "non_empty" => value.is_empty(),
            _ => false,
        };

        if violated {
            let suppressed = is_suppressed(
                &rule.rule_id,
                event,
                &rules.suppression_policy.suppression_entries,
            );
            violations.push(Violation {
                event_index,
                rule_id: rule.rule_id.clone(),
                field: rule.field.clone(),
                severity: rule.severity.clone(),
                suppressed: suppressed.is_some(),
            });
        }
    }
    violations
}

fn validate_correlation(events: &[LogEvent], rules: &RulesFixture) -> Vec<Violation> {
    let mut violations = Vec::new();

    for rule in &rules.correlation_rules {
        match rule.rule_id.as_str() {
            "LQ-COR-01" => {
                // All events must share the same run_id
                let run_ids: HashSet<&str> = events.iter().map(|e| e.run_id.as_str()).collect();
                if run_ids.len() > 1 {
                    violations.push(Violation {
                        event_index: 0,
                        rule_id: rule.rule_id.clone(),
                        field: "run_id".into(),
                        severity: rule.severity.clone(),
                        suppressed: false,
                    });
                }
            }
            "LQ-COR-02" => {
                // trace_id must be unique per event
                let mut seen = HashSet::new();
                for (i, event) in events.iter().enumerate() {
                    if !seen.insert(&event.trace_id) {
                        violations.push(Violation {
                            event_index: i,
                            rule_id: rule.rule_id.clone(),
                            field: "trace_id".into(),
                            severity: rule.severity.clone(),
                            suppressed: false,
                        });
                    }
                }
            }
            "LQ-COR-03" => {
                // Events must be ordered by (flow_id, event_kind, trace_id)
                let keys: Vec<(&str, &str, &str)> = events
                    .iter()
                    .map(|e| {
                        (
                            e.flow_id.as_str(),
                            e.event_kind.as_str(),
                            e.trace_id.as_str(),
                        )
                    })
                    .collect();
                for i in 1..keys.len() {
                    if keys[i] < keys[i - 1] {
                        violations.push(Violation {
                            event_index: i,
                            rule_id: rule.rule_id.clone(),
                            field: "ordering".into(),
                            severity: rule.severity.clone(),
                            suppressed: false,
                        });
                        break; // Report first violation only
                    }
                }
            }
            _ => {}
        }
    }
    violations
}

fn compute_quality_score(violations: &[Violation], scoring: &QualityScoring) -> u32 {
    let mut deduction: u32 = 0;
    for v in violations {
        if v.suppressed {
            continue;
        }
        let key = format!("{}_violation", v.severity);
        if let Some(&d) = scoring.deductions.get(&key) {
            deduction = deduction.saturating_add(d);
        }
    }
    scoring.max_score.saturating_sub(deduction)
}

fn quality_gate(score: u32, scoring: &QualityScoring) -> &'static str {
    if score >= scoring.pass_threshold {
        "pass"
    } else if score >= scoring.warn_threshold {
        "warn"
    } else {
        "fail"
    }
}

// ═══════════════════════════════════════════════════════════════════
// Document infrastructure tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn doc_exists() {
    assert!(
        repo_root().join(DOC_PATH).exists(),
        "Logging quality governance doc must exist at {DOC_PATH}"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc(DOC_PATH);
    assert!(
        doc.contains("asupersync-2b4jj.6.7"),
        "Doc must reference its own bead ID"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc(DOC_PATH);
    let sections = [
        "Purpose",
        "Rule Lifecycle",
        "Introduction",
        "Modification",
        "Retirement",
        "Suppression Policy",
        "Quality Scoring",
        "Severity Classification",
        "Determinism Invariants",
        "CI Integration",
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
    let doc = load_doc(DOC_PATH);
    let refs = [
        "doctor_logging_contract.md",
        "doctor_observability_taxonomy.md",
        "doctor_performance_budget_contract.md",
        "log_quality_rules.json",
        "sample_event_stream.json",
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
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_test_file() {
    let doc = load_doc(DOC_PATH);
    assert!(
        doc.contains("doctor_logging_quality_validators"),
        "Doc must reference the test file name"
    );
}

#[test]
fn baseline_contract_doc_exists() {
    assert!(
        repo_root().join(LOGGING_CONTRACT_DOC).exists(),
        "Baseline logging contract doc must exist"
    );
}

#[test]
fn observability_doc_exists() {
    assert!(
        repo_root().join(OBSERVABILITY_DOC).exists(),
        "Observability taxonomy doc must exist"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Rules fixture schema validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn rules_fixture_loads() {
    let _ = load_rules();
}

#[test]
fn rules_fixture_schema_version() {
    let rules = load_rules();
    assert_eq!(rules.schema_version, RULES_SCHEMA_VERSION);
}

#[test]
fn rules_fixture_bead_id() {
    let rules = load_rules();
    assert_eq!(rules.bead_id, "asupersync-2b4jj.6.7");
}

#[test]
fn rules_fixture_contract_versions() {
    let rules = load_rules();
    assert_eq!(rules.baseline_contract_version, "doctor-logging-v1");
    assert_eq!(
        rules.observability_contract_version,
        "doctor-observability-v1"
    );
}

#[test]
fn envelope_rules_have_unique_ids() {
    let rules = load_rules();
    let ids: Vec<&str> = rules
        .envelope_rules
        .iter()
        .map(|r| r.rule_id.as_str())
        .collect();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len(), "Envelope rule IDs must be unique");
}

#[test]
fn envelope_rules_have_valid_severities() {
    let rules = load_rules();
    for rule in &rules.envelope_rules {
        assert!(
            SEVERITY_LEVELS.contains(&rule.severity.as_str()),
            "Rule {} has invalid severity: {}",
            rule.rule_id,
            rule.severity
        );
    }
}

#[test]
fn envelope_rules_have_valid_constraints() {
    let rules = load_rules();
    for rule in &rules.envelope_rules {
        assert!(
            CONSTRAINT_TYPES.contains(&rule.constraint.as_str()),
            "Rule {} has invalid constraint: {}",
            rule.rule_id,
            rule.constraint
        );
    }
}

#[test]
fn envelope_rules_cover_all_required_fields() {
    let rules = load_rules();
    let required_fields: BTreeSet<&str> = [
        "artifact_pointer",
        "command_provenance",
        "contract_version",
        "flow_id",
        "outcome_class",
        "run_id",
        "scenario_id",
        "trace_id",
    ]
    .into_iter()
    .collect();

    let covered: BTreeSet<&str> = rules
        .envelope_rules
        .iter()
        .map(|r| r.field.as_str())
        .collect();

    let missing: Vec<&&str> = required_fields.difference(&covered).collect();
    assert!(
        missing.is_empty(),
        "Envelope rules missing coverage for: {missing:?}"
    );
}

#[test]
fn correlation_rules_have_unique_ids() {
    let rules = load_rules();
    let ids: Vec<&str> = rules
        .correlation_rules
        .iter()
        .map(|r| r.rule_id.as_str())
        .collect();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len());
}

#[test]
fn correlation_rules_all_stream_scope() {
    let rules = load_rules();
    for rule in &rules.correlation_rules {
        assert_eq!(
            rule.scope, "stream",
            "Correlation rule {} must have stream scope",
            rule.rule_id
        );
    }
}

#[test]
fn taxonomy_rules_have_unique_ids() {
    let rules = load_rules();
    let ids: Vec<&str> = rules
        .taxonomy_rules
        .iter()
        .map(|r| r.rule_id.as_str())
        .collect();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len());
}

// ═══════════════════════════════════════════════════════════════════
// Severity classification tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn severity_levels_match_contract() {
    let rules = load_rules();
    let expected: Vec<String> = SEVERITY_LEVELS.iter().map(|s| s.to_string()).collect();
    assert_eq!(rules.severity_classification.levels, expected);
}

#[test]
fn severity_escalation_order_is_ascending() {
    let rules = load_rules();
    let ranks: Vec<u8> = rules
        .severity_classification
        .escalation_order
        .iter()
        .map(|s| severity_rank(s))
        .collect();
    for i in 1..ranks.len() {
        assert!(
            ranks[i] >= ranks[i - 1],
            "Escalation order must be ascending: {:?}",
            rules.severity_classification.escalation_order
        );
    }
}

#[test]
fn outcome_defaults_cover_all_outcomes() {
    let rules = load_rules();
    for outcome in &ALLOWED_OUTCOMES {
        assert!(
            rules
                .severity_classification
                .outcome_defaults
                .contains_key(*outcome),
            "Missing outcome default for: {outcome}"
        );
    }
}

#[test]
fn outcome_defaults_map_to_valid_severities() {
    let rules = load_rules();
    for (outcome, severity) in &rules.severity_classification.outcome_defaults {
        assert!(
            SEVERITY_LEVELS.contains(&severity.as_str()),
            "Outcome {outcome} maps to invalid severity: {severity}"
        );
    }
}

#[test]
fn conflict_escalation_is_critical() {
    let rules = load_rules();
    assert_eq!(
        rules.severity_classification.conflict_escalation,
        "critical"
    );
}

#[test]
fn outcome_success_maps_to_info() {
    let rules = load_rules();
    assert_eq!(
        rules
            .severity_classification
            .outcome_defaults
            .get("success"),
        Some(&"info".to_string())
    );
}

#[test]
fn outcome_cancelled_maps_to_warning() {
    let rules = load_rules();
    assert_eq!(
        rules
            .severity_classification
            .outcome_defaults
            .get("cancelled"),
        Some(&"warning".to_string())
    );
}

#[test]
fn outcome_failed_maps_to_error() {
    let rules = load_rules();
    assert_eq!(
        rules.severity_classification.outcome_defaults.get("failed"),
        Some(&"error".to_string())
    );
}

// ═══════════════════════════════════════════════════════════════════
// Suppression policy tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn suppression_count_within_limit() {
    let rules = load_rules();
    assert!(
        rules.suppression_policy.suppression_entries.len()
            <= rules.suppression_policy.governance.max_suppressions,
        "Too many suppressions: {} > {}",
        rules.suppression_policy.suppression_entries.len(),
        rules.suppression_policy.governance.max_suppressions,
    );
}

#[test]
fn suppression_ids_are_unique() {
    let rules = load_rules();
    let ids: Vec<&str> = rules
        .suppression_policy
        .suppression_entries
        .iter()
        .map(|s| s.suppression_id.as_str())
        .collect();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len());
}

#[test]
fn suppression_rule_ids_exist_in_envelope_rules() {
    let rules = load_rules();
    let envelope_ids: BTreeSet<&str> = rules
        .envelope_rules
        .iter()
        .map(|r| r.rule_id.as_str())
        .collect();
    for sup in &rules.suppression_policy.suppression_entries {
        assert!(
            envelope_ids.contains(sup.rule_id.as_str()),
            "Suppression {} references unknown rule: {}",
            sup.suppression_id,
            sup.rule_id
        );
    }
}

#[test]
fn suppression_entries_have_expiry() {
    let rules = load_rules();
    assert!(rules.suppression_policy.governance.expiry_required);
    for sup in &rules.suppression_policy.suppression_entries {
        assert!(
            !sup.expires.is_empty(),
            "Suppression {} must have an expiry date",
            sup.suppression_id
        );
        // Validate date format: YYYY-MM-DD
        assert!(
            sup.expires.len() == 10 && sup.expires.chars().nth(4) == Some('-'),
            "Suppression {} has invalid expiry format: {}",
            sup.suppression_id,
            sup.expires
        );
    }
}

#[test]
fn suppression_scopes_are_well_formed() {
    let rules = load_rules();
    for sup in &rules.suppression_policy.suppression_entries {
        assert!(
            sup.scope.contains('='),
            "Suppression {} scope must contain key=value: {}",
            sup.suppression_id,
            sup.scope
        );
    }
}

#[test]
fn review_cadence_is_positive() {
    let rules = load_rules();
    assert!(
        rules.suppression_policy.governance.review_cadence_days > 0,
        "Review cadence must be positive"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Quality scoring tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn scoring_thresholds_are_ordered() {
    let rules = load_rules();
    assert!(rules.quality_scoring.warn_threshold < rules.quality_scoring.pass_threshold);
    assert!(rules.quality_scoring.pass_threshold <= rules.quality_scoring.max_score);
}

#[test]
fn scoring_deductions_have_required_keys() {
    let rules = load_rules();
    assert!(
        rules
            .quality_scoring
            .deductions
            .contains_key("error_violation")
    );
    assert!(
        rules
            .quality_scoring
            .deductions
            .contains_key("warning_violation")
    );
    assert!(
        rules
            .quality_scoring
            .deductions
            .contains_key("suppressed_violation")
    );
}

#[test]
fn suppressed_violation_zero_deduction() {
    let rules = load_rules();
    assert_eq!(
        rules.quality_scoring.deductions.get("suppressed_violation"),
        Some(&0),
        "Suppressed violations must have zero deduction"
    );
}

#[test]
fn error_deduction_exceeds_warning_deduction() {
    let rules = load_rules();
    let error_d = rules.quality_scoring.deductions["error_violation"];
    let warning_d = rules.quality_scoring.deductions["warning_violation"];
    assert!(
        error_d > warning_d,
        "Error deduction ({error_d}) must exceed warning deduction ({warning_d})"
    );
}

#[test]
fn perfect_score_with_no_violations() {
    let rules = load_rules();
    let score = compute_quality_score(&[], &rules.quality_scoring);
    assert_eq!(score, rules.quality_scoring.max_score);
}

#[test]
fn single_error_reduces_score() {
    let rules = load_rules();
    let violations = vec![Violation {
        event_index: 0,
        rule_id: "LQ-ENV-01".into(),
        field: "contract_version".into(),
        severity: "error".into(),
        suppressed: false,
    }];
    let score = compute_quality_score(&violations, &rules.quality_scoring);
    let expected =
        rules.quality_scoring.max_score - rules.quality_scoring.deductions["error_violation"];
    assert_eq!(score, expected);
}

#[test]
fn single_warning_reduces_score() {
    let rules = load_rules();
    let violations = vec![Violation {
        event_index: 0,
        rule_id: "LQ-ENV-07".into(),
        field: "artifact_pointer".into(),
        severity: "warning".into(),
        suppressed: false,
    }];
    let score = compute_quality_score(&violations, &rules.quality_scoring);
    let expected =
        rules.quality_scoring.max_score - rules.quality_scoring.deductions["warning_violation"];
    assert_eq!(score, expected);
}

#[test]
fn suppressed_violation_does_not_reduce_score() {
    let rules = load_rules();
    let violations = vec![Violation {
        event_index: 0,
        rule_id: "LQ-ENV-07".into(),
        field: "artifact_pointer".into(),
        severity: "warning".into(),
        suppressed: true,
    }];
    let score = compute_quality_score(&violations, &rules.quality_scoring);
    assert_eq!(score, rules.quality_scoring.max_score);
}

#[test]
fn quality_gate_pass() {
    let rules = load_rules();
    assert_eq!(quality_gate(100, &rules.quality_scoring), "pass");
    assert_eq!(
        quality_gate(rules.quality_scoring.pass_threshold, &rules.quality_scoring),
        "pass"
    );
}

#[test]
fn quality_gate_warn() {
    let rules = load_rules();
    let score = rules.quality_scoring.pass_threshold - 1;
    if score >= rules.quality_scoring.warn_threshold {
        assert_eq!(quality_gate(score, &rules.quality_scoring), "warn");
    }
}

#[test]
fn quality_gate_fail() {
    let rules = load_rules();
    let score = rules.quality_scoring.warn_threshold.saturating_sub(1);
    assert_eq!(quality_gate(score, &rules.quality_scoring), "fail");
}

// ═══════════════════════════════════════════════════════════════════
// Event stream fixture validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn event_stream_fixture_loads() {
    let _ = load_event_stream();
}

#[test]
fn event_stream_schema_version() {
    let stream = load_event_stream();
    assert_eq!(stream.schema_version, STREAM_SCHEMA_VERSION);
}

#[test]
fn event_stream_bead_id() {
    let stream = load_event_stream();
    assert_eq!(stream.bead_id, "asupersync-2b4jj.6.7");
}

#[test]
fn event_stream_all_events_share_run_id() {
    let stream = load_event_stream();
    for (i, event) in stream.events.iter().enumerate() {
        assert_eq!(
            event.run_id, stream.run_id,
            "Event {i} run_id mismatch: {} vs {}",
            event.run_id, stream.run_id
        );
    }
}

#[test]
fn event_stream_trace_ids_unique() {
    let stream = load_event_stream();
    let trace_ids: Vec<&str> = stream.events.iter().map(|e| e.trace_id.as_str()).collect();
    let unique: BTreeSet<&str> = trace_ids.iter().copied().collect();
    assert_eq!(
        trace_ids.len(),
        unique.len(),
        "Trace IDs must be unique within the stream"
    );
}

#[test]
fn event_stream_is_lexically_ordered() {
    let stream = load_event_stream();
    let keys: Vec<(&str, &str, &str)> = stream
        .events
        .iter()
        .map(|e| {
            (
                e.flow_id.as_str(),
                e.event_kind.as_str(),
                e.trace_id.as_str(),
            )
        })
        .collect();
    for i in 1..keys.len() {
        assert!(
            keys[i] >= keys[i - 1],
            "Events not lexically ordered at index {i}: {:?} < {:?}",
            keys[i],
            keys[i - 1]
        );
    }
}

#[test]
fn event_stream_all_flow_ids_valid() {
    let stream = load_event_stream();
    for (i, event) in stream.events.iter().enumerate() {
        assert!(
            ALLOWED_FLOW_IDS.contains(&event.flow_id.as_str()),
            "Event {i} has invalid flow_id: {}",
            event.flow_id
        );
    }
}

#[test]
fn event_stream_all_outcomes_valid() {
    let stream = load_event_stream();
    for (i, event) in stream.events.iter().enumerate() {
        assert!(
            ALLOWED_OUTCOMES.contains(&event.outcome_class.as_str()),
            "Event {i} has invalid outcome_class: {}",
            event.outcome_class
        );
    }
}

#[test]
fn event_stream_contract_versions_consistent() {
    let stream = load_event_stream();
    for (i, event) in stream.events.iter().enumerate() {
        assert_eq!(
            event.contract_version, "doctor-logging-v1",
            "Event {i} has wrong contract_version"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Validator execution tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn envelope_validation_golden_stream_produces_expected_violations() {
    let rules = load_rules();
    let stream = load_event_stream();

    let mut all_violations: Vec<Violation> = Vec::new();
    for (i, event) in stream.events.iter().enumerate() {
        let vs = validate_envelope(i, event, &rules);
        all_violations.extend(vs);
    }

    // Check against expected violations
    for expected in &stream.expected_violations {
        let found = all_violations
            .iter()
            .any(|v| v.event_index == expected.event_index && v.rule_id == expected.rule_id);
        assert!(
            found,
            "Expected violation not found: event_index={}, rule_id={}",
            expected.event_index, expected.rule_id
        );
    }
}

#[test]
fn correlation_validation_golden_stream_clean() {
    let rules = load_rules();
    let stream = load_event_stream();

    let violations = validate_correlation(&stream.events, &rules);
    assert!(
        violations.is_empty(),
        "Golden stream should have no correlation violations: {violations:?}"
    );
}

#[test]
fn golden_stream_quality_score_matches_expected() {
    let rules = load_rules();
    let stream = load_event_stream();

    let mut all_violations = Vec::new();
    for (i, event) in stream.events.iter().enumerate() {
        all_violations.extend(validate_envelope(i, event, &rules));
    }
    all_violations.extend(validate_correlation(&stream.events, &rules));

    let score = compute_quality_score(&all_violations, &rules.quality_scoring);
    assert_eq!(
        score, stream.expected_quality_score,
        "Quality score mismatch: got {score}, expected {}",
        stream.expected_quality_score
    );
}

#[test]
fn golden_stream_quality_gate_matches_expected() {
    let rules = load_rules();
    let stream = load_event_stream();

    let mut all_violations = Vec::new();
    for (i, event) in stream.events.iter().enumerate() {
        all_violations.extend(validate_envelope(i, event, &rules));
    }
    all_violations.extend(validate_correlation(&stream.events, &rules));

    let score = compute_quality_score(&all_violations, &rules.quality_scoring);
    let gate = quality_gate(score, &rules.quality_scoring);
    assert_eq!(
        gate, stream.expected_quality_gate,
        "Quality gate mismatch: got {gate}, expected {}",
        stream.expected_quality_gate
    );
}

// ═══════════════════════════════════════════════════════════════════
// Determinism tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn validator_output_is_deterministic() {
    let rules = load_rules();
    let stream = load_event_stream();

    let run = || -> Vec<Violation> {
        let mut violations = Vec::new();
        for (i, event) in stream.events.iter().enumerate() {
            violations.extend(validate_envelope(i, event, &rules));
        }
        violations.extend(validate_correlation(&stream.events, &rules));
        violations.sort();
        violations
    };

    let run1 = run();
    let run2 = run();
    assert_eq!(
        run1, run2,
        "Validator output must be deterministic across runs"
    );
}

#[test]
fn violation_sort_order_is_by_event_index_then_rule_id() {
    let mut violations = vec![
        Violation {
            event_index: 2,
            rule_id: "LQ-ENV-01".into(),
            field: "f".into(),
            severity: "error".into(),
            suppressed: false,
        },
        Violation {
            event_index: 0,
            rule_id: "LQ-ENV-03".into(),
            field: "f".into(),
            severity: "error".into(),
            suppressed: false,
        },
        Violation {
            event_index: 0,
            rule_id: "LQ-ENV-01".into(),
            field: "f".into(),
            severity: "error".into(),
            suppressed: false,
        },
    ];
    violations.sort();
    assert_eq!(violations[0].event_index, 0);
    assert_eq!(violations[0].rule_id, "LQ-ENV-01");
    assert_eq!(violations[1].event_index, 0);
    assert_eq!(violations[1].rule_id, "LQ-ENV-03");
    assert_eq!(violations[2].event_index, 2);
}

// ═══════════════════════════════════════════════════════════════════
// Edge case and failure-mode tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn invalid_contract_version_detected() {
    let rules = load_rules();
    let event = LogEvent {
        contract_version: "doctor-logging-v0".into(),
        flow_id: "execution".into(),
        event_kind: "gate_start".into(),
        outcome_class: "success".into(),
        run_id: "run-test-001".into(),
        scenario_id: "test-scenario".into(),
        trace_id: "trace-test-001".into(),
        artifact_pointer: "test".into(),
        command_provenance: "cargo test".into(),
        fields: BTreeMap::new(),
    };
    let violations = validate_envelope(0, &event, &rules);
    assert!(
        violations.iter().any(|v| v.rule_id == "LQ-ENV-01"),
        "Must detect invalid contract version"
    );
}

#[test]
fn invalid_flow_id_detected() {
    let rules = load_rules();
    let event = LogEvent {
        contract_version: "doctor-logging-v1".into(),
        flow_id: "unknown_flow".into(),
        event_kind: "gate_start".into(),
        outcome_class: "success".into(),
        run_id: "run-test-001".into(),
        scenario_id: "test-scenario".into(),
        trace_id: "trace-test-001".into(),
        artifact_pointer: "test".into(),
        command_provenance: "cargo test".into(),
        fields: BTreeMap::new(),
    };
    let violations = validate_envelope(0, &event, &rules);
    assert!(
        violations.iter().any(|v| v.rule_id == "LQ-ENV-02"),
        "Must detect invalid flow_id"
    );
}

#[test]
fn malformed_run_id_detected() {
    let rules = load_rules();
    let event = LogEvent {
        contract_version: "doctor-logging-v1".into(),
        flow_id: "execution".into(),
        event_kind: "gate_start".into(),
        outcome_class: "success".into(),
        run_id: "INVALID-RUN-ID".into(),
        scenario_id: "test-scenario".into(),
        trace_id: "trace-test-001".into(),
        artifact_pointer: "test".into(),
        command_provenance: "cargo test".into(),
        fields: BTreeMap::new(),
    };
    let violations = validate_envelope(0, &event, &rules);
    assert!(
        violations.iter().any(|v| v.rule_id == "LQ-ENV-04"),
        "Must detect malformed run_id"
    );
}

#[test]
fn malformed_trace_id_detected() {
    let rules = load_rules();
    let event = LogEvent {
        contract_version: "doctor-logging-v1".into(),
        flow_id: "execution".into(),
        event_kind: "gate_start".into(),
        outcome_class: "success".into(),
        run_id: "run-test-001".into(),
        scenario_id: "test-scenario".into(),
        trace_id: "BAD_TRACE".into(),
        artifact_pointer: "test".into(),
        command_provenance: "cargo test".into(),
        fields: BTreeMap::new(),
    };
    let violations = validate_envelope(0, &event, &rules);
    assert!(
        violations.iter().any(|v| v.rule_id == "LQ-ENV-06"),
        "Must detect malformed trace_id"
    );
}

#[test]
fn empty_artifact_pointer_is_warning() {
    let rules = load_rules();
    let event = LogEvent {
        contract_version: "doctor-logging-v1".into(),
        flow_id: "execution".into(),
        event_kind: "gate_start".into(),
        outcome_class: "success".into(),
        run_id: "run-test-001".into(),
        scenario_id: "test-scenario".into(),
        trace_id: "trace-test-001".into(),
        artifact_pointer: "".into(),
        command_provenance: "cargo test".into(),
        fields: BTreeMap::new(),
    };
    let violations = validate_envelope(0, &event, &rules);
    let v = violations.iter().find(|v| v.rule_id == "LQ-ENV-07");
    assert!(v.is_some(), "Must detect empty artifact_pointer");
    assert_eq!(v.unwrap().severity, "warning");
}

#[test]
fn duplicate_trace_id_detected() {
    let rules = load_rules();
    let events = vec![
        LogEvent {
            contract_version: "doctor-logging-v1".into(),
            flow_id: "execution".into(),
            event_kind: "gate_start".into(),
            outcome_class: "success".into(),
            run_id: "run-test-001".into(),
            scenario_id: "test-scenario".into(),
            trace_id: "trace-dup-001".into(),
            artifact_pointer: "test".into(),
            command_provenance: "cargo test".into(),
            fields: BTreeMap::new(),
        },
        LogEvent {
            contract_version: "doctor-logging-v1".into(),
            flow_id: "execution".into(),
            event_kind: "gate_complete".into(),
            outcome_class: "success".into(),
            run_id: "run-test-001".into(),
            scenario_id: "test-scenario".into(),
            trace_id: "trace-dup-001".into(), // duplicate!
            artifact_pointer: "test".into(),
            command_provenance: "cargo test".into(),
            fields: BTreeMap::new(),
        },
    ];
    let violations = validate_correlation(&events, &rules);
    assert!(
        violations.iter().any(|v| v.rule_id == "LQ-COR-02"),
        "Must detect duplicate trace_id"
    );
}

#[test]
fn out_of_order_events_detected() {
    let rules = load_rules();
    let events = vec![
        LogEvent {
            contract_version: "doctor-logging-v1".into(),
            flow_id: "replay".into(),
            event_kind: "replay_start".into(),
            outcome_class: "success".into(),
            run_id: "run-test-001".into(),
            scenario_id: "test-scenario".into(),
            trace_id: "trace-002".into(),
            artifact_pointer: "test".into(),
            command_provenance: "cargo test".into(),
            fields: BTreeMap::new(),
        },
        LogEvent {
            contract_version: "doctor-logging-v1".into(),
            flow_id: "execution".into(), // out of order (execution < replay)
            event_kind: "gate_start".into(),
            outcome_class: "success".into(),
            run_id: "run-test-001".into(),
            scenario_id: "test-scenario".into(),
            trace_id: "trace-001".into(),
            artifact_pointer: "test".into(),
            command_provenance: "cargo test".into(),
            fields: BTreeMap::new(),
        },
    ];
    let violations = validate_correlation(&events, &rules);
    assert!(
        violations.iter().any(|v| v.rule_id == "LQ-COR-03"),
        "Must detect out-of-order events"
    );
}

#[test]
fn mismatched_run_ids_detected() {
    let rules = load_rules();
    let events = vec![
        LogEvent {
            contract_version: "doctor-logging-v1".into(),
            flow_id: "execution".into(),
            event_kind: "gate_start".into(),
            outcome_class: "success".into(),
            run_id: "run-aaa".into(),
            scenario_id: "test-scenario".into(),
            trace_id: "trace-001".into(),
            artifact_pointer: "test".into(),
            command_provenance: "cargo test".into(),
            fields: BTreeMap::new(),
        },
        LogEvent {
            contract_version: "doctor-logging-v1".into(),
            flow_id: "execution".into(),
            event_kind: "gate_complete".into(),
            outcome_class: "success".into(),
            run_id: "run-bbb".into(), // different run_id!
            scenario_id: "test-scenario".into(),
            trace_id: "trace-002".into(),
            artifact_pointer: "test".into(),
            command_provenance: "cargo test".into(),
            fields: BTreeMap::new(),
        },
    ];
    let violations = validate_correlation(&events, &rules);
    assert!(
        violations.iter().any(|v| v.rule_id == "LQ-COR-01"),
        "Must detect mismatched run_ids"
    );
}

#[test]
fn multiple_errors_deduct_cumulatively() {
    let rules = load_rules();
    let violations = vec![
        Violation {
            event_index: 0,
            rule_id: "LQ-ENV-01".into(),
            field: "contract_version".into(),
            severity: "error".into(),
            suppressed: false,
        },
        Violation {
            event_index: 0,
            rule_id: "LQ-ENV-02".into(),
            field: "flow_id".into(),
            severity: "error".into(),
            suppressed: false,
        },
        Violation {
            event_index: 1,
            rule_id: "LQ-ENV-03".into(),
            field: "outcome_class".into(),
            severity: "error".into(),
            suppressed: false,
        },
    ];
    let score = compute_quality_score(&violations, &rules.quality_scoring);
    let expected =
        rules.quality_scoring.max_score - 3 * rules.quality_scoring.deductions["error_violation"];
    assert_eq!(score, expected);
}

#[test]
fn score_does_not_underflow() {
    let rules = load_rules();
    // 11 error violations at 10 points each = 110 > 100 max
    let violations: Vec<Violation> = (0..11)
        .map(|i| Violation {
            event_index: i,
            rule_id: format!("LQ-TEST-{i:02}"),
            field: "test".into(),
            severity: "error".into(),
            suppressed: false,
        })
        .collect();
    let score = compute_quality_score(&violations, &rules.quality_scoring);
    assert_eq!(score, 0, "Score must not underflow past 0");
}
