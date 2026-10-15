//! Contract tests for operator SLO policy bundles.

use asupersync::Cx;
use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::observability::swarm_pressure_governor::{
    FourthWaveEvidenceQuality, FourthWaveGovernorAction, FourthWaveGovernorDecisionReceipt,
    FourthWaveGovernorLogFields, FourthWaveGovernorObjective, FourthWaveRejectedAlternative,
};
use asupersync::runtime::{
    FourthWaveRuntimeBridgeDecision, SloRuntimePolicyBridge, SloRuntimePolicyBridgeDecision,
    SloRuntimePolicyBridgeRequest, SloRuntimeWorkKind, yield_now,
};
use asupersync::types::{
    Budget, Outcome, SLO_POLICY_BUNDLE_SCHEMA_VERSION, SLO_POLICY_COMPILER_SCHEMA_VERSION,
    SLO_POLICY_PROOF_REPORT_SCHEMA_VERSION, SLO_POLICY_RUNTIME_APPLICATION_SCHEMA_VERSION,
    SloCompiledAdmissionDecision, SloCompiledPolicyStatus, SloLatencyObjective, SloLatencyUnit,
    SloNoWinFallback, SloOptionalWorkClass, SloPolicyBundle, SloPolicyCapacityEvidence,
    SloPolicyCompilerBlockerKind, SloPolicyProvenance, SloPolicyRedaction,
    SloPolicyValidationIssueKind, SloPolicyValidationReport, SloProofCommand, SloProofNoWinReceipt,
    SloProofReport, SloProofReportIssueKind, SloProofReportProvenance, SloProofReportRow,
    SloProofReportStatus, SloResourcePressureThresholds, SloRuntimeAdmissionIssueKind,
    SloRuntimeAdmissionOutcome, SloRuntimeAdmissionRequest, SloRuntimeAdmissionStatus,
    SloRuntimeOptionalWorkDecision, SloRuntimePolicyApplication,
    SloRuntimePolicyApplicationIssueKind, SloRuntimePolicyApplicationValidation,
    SloRuntimePolicyDecision, SloWorkloadClass, slo_proof_report_status_counts,
    validate_slo_policy_bundle_json, validate_slo_proof_report_json,
    validate_slo_runtime_policy_application_json,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

const CONTRACT_PATH: &str = "artifacts/slo_policy_bundle_contract_v1.json";
const SCRIPT_PATH: &str = "scripts/validate_slo_policy_bundle.sh";
const README_PATH: &str = "README.md";
const OPERATOR_DOC_PATH: &str = "docs/ci_proof_gates_contract.md";
const SLO_PROOF_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_slo_policy_bundle_contract cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals -- --nocapture";
const SLO_REPLAY_PROOF_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_slo_policy_replay_fixtures cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals lab_runtime_slo_policy_replay_fixtures_cover_required_outcomes -- --nocapture";
const SLO_RUNTIME_BRIDGE_PROOF_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_slo_runtime_bridge CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test slo_policy_bundle_contract runtime_slo_policy_bridge --features test-internals -- --nocapture";
const SLO_BROWNOUT_E2E_RECEIPT_SCHEMA_VERSION: &str = "slo-lab-brownout-e2e-receipt-v1";
const SLO_BROWNOUT_E2E_PROOF_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_slo_brownout_e2e CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test slo_policy_bundle_contract runtime_slo_brownout_lab_e2e --features test-internals -- --nocapture";

fn text_file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn json_file(path: &str) -> Value {
    let raw = text_file(path);
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn cargo_command_has_target_dir(command: &str) -> bool {
    !command.contains("cargo ")
        || (command.contains("rch exec -- env ") && command.contains("CARGO_TARGET_DIR="))
}

fn collect_json_strings<'a>(value: &'a Value, output: &mut Vec<&'a str>) {
    match value {
        Value::String(text) => output.push(text),
        Value::Array(items) => {
            for item in items {
                collect_json_strings(item, output);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_json_strings(item, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn contract() -> Value {
    json_file(CONTRACT_PATH)
}

fn section_between<'a>(document: &'a str, heading: &str, next_heading: &str) -> &'a str {
    let start = document
        .find(heading)
        .unwrap_or_else(|| panic!("missing heading {heading}"));
    let after_start = start + heading.len();
    let end = document[after_start..]
        .find(next_heading)
        .map_or(document.len(), |offset| after_start + offset);
    &document[start..end]
}

fn scenario<'a>(artifact: &'a Value, id: &str) -> &'a Value {
    artifact["scenarios"]
        .as_array()
        .expect("scenarios are present")
        .iter()
        .find(|scenario| scenario["scenario_id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("scenario {id} is present"))
}

fn profile_hash(hex_digit: char) -> String {
    format!("sha256:{}", hex_digit.to_string().repeat(64))
}

fn valid_bundle() -> SloPolicyBundle {
    SloPolicyBundle {
        schema_version: SLO_POLICY_BUNDLE_SCHEMA_VERSION,
        policy_id: "agent-swarm-standard".to_string(),
        workload_class: SloWorkloadClass::AgentSwarm,
        latency_objectives: vec![
            SloLatencyObjective {
                objective_id: "queue_wait".to_string(),
                unit: SloLatencyUnit::Milliseconds,
                p50: 5,
                p95: 25,
                p99: 60,
                p999: 120,
            },
            SloLatencyObjective {
                objective_id: "cleanup".to_string(),
                unit: SloLatencyUnit::Milliseconds,
                p50: 10,
                p95: 50,
                p99: 150,
                p999: 250,
            },
        ],
        cleanup_deadline_ms: 300,
        max_queue_wait_ms: 80,
        resource_pressure: SloResourcePressureThresholds {
            memory_basis_points: 8_500,
            fd_basis_points: 8_000,
            timer_queue_depth: 50_000,
        },
        optional_work_classes: vec![
            SloOptionalWorkClass {
                class_id: "index_refresh".to_string(),
                brownout_priority: 1,
                degradation_step: "delay non-critical index refresh jobs".to_string(),
            },
            SloOptionalWorkClass {
                class_id: "analytics_rollup".to_string(),
                brownout_priority: 2,
                degradation_step: "batch analytics rollups until pressure clears".to_string(),
            },
        ],
        no_win_fallback: Some(SloNoWinFallback {
            fallback_profile: "agent-swarm-safe-mode".to_string(),
            fallback_reason: "objectives-conflict-with-pressure".to_string(),
            proof_command: SLO_PROOF_COMMAND.to_string(),
        }),
        provenance: SloPolicyProvenance {
            profile_id: "agent-swarm-prod".to_string(),
            profile_hash: profile_hash('a'),
            observed_profile_hash: Some(profile_hash('a')),
            target_commit: "b8f24024890da34b9151aaea62fff2d06d90f282".to_string(),
            feature_flags: vec!["test-internals".to_string()],
            artifact_path: Some(CONTRACT_PATH.to_string()),
            related_bead_id: Some("asupersync-bgtplc.1".to_string()),
        },
        redaction: SloPolicyRedaction {
            policy_id: "slo-redaction-v1".to_string(),
            passed: true,
        },
        metadata: BTreeMap::from([(
            "compiler_target".to_string(),
            Value::String("budget-admission-v1".to_string()),
        )]),
    }
}

fn valid_capacity_evidence() -> SloPolicyCapacityEvidence {
    SloPolicyCapacityEvidence {
        profile_id: "agent-swarm-prod".to_string(),
        profile_hash: profile_hash('a'),
        workload_class: SloWorkloadClass::AgentSwarm,
        sample_count: 64,
        queue_depth: 12_000,
        memory_basis_points: 6_500,
        fd_basis_points: 5_900,
        timer_queue_depth: 12_000,
    }
}

#[derive(Clone)]
struct LabReplayFixture {
    scenario_id: &'static str,
    seed: u64,
    bundle: Option<SloPolicyBundle>,
    malformed_document: Option<&'static str>,
    capacity_evidence: Option<SloPolicyCapacityEvidence>,
    work_units: u64,
    optional_work_units: u64,
    optional_work_class: Option<&'static str>,
    cleanup_work_ms: u64,
    proof_command: &'static str,
    observed_profile_hash: Option<String>,
    queue_wait_ms: u64,
    memory_basis_points: u16,
    fd_basis_points: u16,
    timer_queue_depth: u64,
    cancel_requested: bool,
    pressure_transition: LabReplayPressureTransition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LabReplayPressureTransition {
    Steady,
    CancelDuringBrownout,
    RecoveryAfterPressureClears,
}

impl LabReplayPressureTransition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Steady => "steady",
            Self::CancelDuringBrownout => "cancel_mid_brownout",
            Self::RecoveryAfterPressureClears => "recovery_after_pressure_clears",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LabReplayEvidence {
    scenario_id: String,
    replay_status: String,
    compiler_status: String,
    admitted_work_units: u64,
    rejected_work_units: u64,
    optional_work_units_browned_out: u64,
    cleanup_deadline_misses: u64,
    fallback_reason: Option<String>,
    proof_command: String,
    lab_seed: u64,
    lab_steps: u64,
    lab_virtual_elapsed_ms: u64,
    trace_events: usize,
    oracle_violations: Vec<String>,
    issue_kinds: Vec<String>,
    receipt: SloLabBrownoutE2eReceipt,
}

impl LabReplayEvidence {
    fn to_json(&self) -> Value {
        json!({
            "scenario_id": self.scenario_id,
            "replay_status": self.replay_status,
            "compiler_status": self.compiler_status,
            "admitted_work_units": self.admitted_work_units,
            "rejected_work_units": self.rejected_work_units,
            "optional_work_units_browned_out": self.optional_work_units_browned_out,
            "cleanup_deadline_misses": self.cleanup_deadline_misses,
            "fallback_reason": self.fallback_reason,
            "proof_command": self.proof_command,
            "lab_seed": self.lab_seed,
            "lab_steps": self.lab_steps,
            "lab_virtual_elapsed_ms": self.lab_virtual_elapsed_ms,
            "trace_events": self.trace_events,
            "oracle_violations": self.oracle_violations,
            "issue_kinds": self.issue_kinds,
            "receipt": self.receipt.to_json(),
        })
    }
}

#[derive(Clone, Debug)]
struct LabReplayCoreOutcome {
    replay_status: String,
    compiler_status: String,
    admitted_work_units: u64,
    rejected_work_units: u64,
    optional_work_units_browned_out: u64,
    cleanup_deadline_misses: u64,
    fallback_reason: Option<String>,
    issue_kinds: Vec<String>,
    virtual_elapsed_ms: u64,
    receipt_seed: SloLabBrownoutE2eReceiptSeed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SloLabBrownoutE2eReceipt {
    schema_version: String,
    scenario_id: String,
    pressure_transition: String,
    receipt_status: String,
    region_ids: Vec<String>,
    task_counts: SloLabTaskCounts,
    obligation_state: String,
    cancellation_requested_count: u64,
    cancellation_observed_count: u64,
    drain_requested_count: u64,
    drain_completed_count: u64,
    finalizer_expected_count: u64,
    finalizer_completed_count: u64,
    final_quiescent: bool,
    runtime_invariant_violations: Vec<String>,
    oracle_violations: Vec<String>,
    operator_interpretation: String,
    non_claims: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SloLabTaskCounts {
    requested: u64,
    admitted: u64,
    completed: u64,
    rejected: u64,
    browned_out: u64,
    cancelled: u64,
    cleanup_finalizers: u64,
    proof_reporting: u64,
}

#[derive(Clone, Debug)]
struct SloLabBrownoutE2eReceiptSeed {
    pressure_transition: String,
    region_ids: Vec<String>,
    task_counts: SloLabTaskCounts,
    obligation_state: String,
    cancellation_requested_count: u64,
    cancellation_observed_count: u64,
    drain_requested_count: u64,
    drain_completed_count: u64,
    finalizer_expected_count: u64,
    finalizer_completed_count: u64,
    operator_interpretation: String,
}

impl SloLabBrownoutE2eReceipt {
    fn from_lab_report(
        scenario_id: String,
        seed: SloLabBrownoutE2eReceiptSeed,
        report: &asupersync::lab::runtime::LabRunReport,
        oracle_violations: Vec<String>,
    ) -> Self {
        let mut receipt = Self {
            schema_version: SLO_BROWNOUT_E2E_RECEIPT_SCHEMA_VERSION.to_string(),
            scenario_id,
            pressure_transition: seed.pressure_transition,
            receipt_status: "green".to_string(),
            region_ids: seed.region_ids,
            task_counts: seed.task_counts,
            obligation_state: seed.obligation_state,
            cancellation_requested_count: seed.cancellation_requested_count,
            cancellation_observed_count: seed.cancellation_observed_count,
            drain_requested_count: seed.drain_requested_count,
            drain_completed_count: seed.drain_completed_count,
            finalizer_expected_count: seed.finalizer_expected_count,
            finalizer_completed_count: seed.finalizer_completed_count,
            final_quiescent: report.quiescent,
            runtime_invariant_violations: report.invariant_violations.clone(),
            oracle_violations,
            operator_interpretation: seed.operator_interpretation,
            non_claims: slo_brownout_e2e_non_claims(),
        };
        if !receipt.validation_issues().is_empty() {
            receipt.receipt_status = "red".to_string();
        }
        receipt
    }

    fn to_json(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "pressure_transition": self.pressure_transition,
            "receipt_status": self.receipt_status,
            "region_ids": self.region_ids,
            "task_counts": self.task_counts.to_json(),
            "obligation_state": self.obligation_state,
            "cancellation_requested_count": self.cancellation_requested_count,
            "cancellation_observed_count": self.cancellation_observed_count,
            "drain_requested_count": self.drain_requested_count,
            "drain_completed_count": self.drain_completed_count,
            "finalizer_expected_count": self.finalizer_expected_count,
            "finalizer_completed_count": self.finalizer_completed_count,
            "final_quiescent": self.final_quiescent,
            "runtime_invariant_violations": self.runtime_invariant_violations,
            "oracle_violations": self.oracle_violations,
            "operator_interpretation": self.operator_interpretation,
            "non_claims": self.non_claims,
        })
    }

    fn validation_issues(&self) -> BTreeSet<String> {
        validate_slo_brownout_e2e_receipt_json(&self.to_json())
    }
}

impl SloLabTaskCounts {
    fn to_json(&self) -> Value {
        json!({
            "requested": self.requested,
            "admitted": self.admitted,
            "completed": self.completed,
            "rejected": self.rejected,
            "browned_out": self.browned_out,
            "cancelled": self.cancelled,
            "cleanup_finalizers": self.cleanup_finalizers,
            "proof_reporting": self.proof_reporting,
        })
    }
}

fn issue_tags(report: &SloPolicyValidationReport) -> BTreeSet<String> {
    report
        .issues
        .iter()
        .map(|issue| issue.kind.as_str().to_string())
        .collect()
}

fn compiler_status_tags() -> BTreeSet<String> {
    [
        SloCompiledPolicyStatus::Compiled,
        SloCompiledPolicyStatus::NoWin,
        SloCompiledPolicyStatus::Blocked,
    ]
    .into_iter()
    .map(|status| status.as_str().to_string())
    .collect()
}

fn compiler_blocker_tags() -> BTreeSet<String> {
    [
        SloPolicyCompilerBlockerKind::InvalidBundle,
        SloPolicyCompilerBlockerKind::ImpossibleObjective,
        SloPolicyCompilerBlockerKind::MissingCapacityEvidence,
        SloPolicyCompilerBlockerKind::UnsupportedWorkloadClass,
        SloPolicyCompilerBlockerKind::ConflictingFallbackDeclaration,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect()
}

fn lab_replay_status_tags() -> BTreeSet<String> {
    [
        "passed",
        "brownout",
        "rejected",
        "no_win",
        "stale_evidence",
        "cancelled",
        "blocked",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn compiled_blocker_tags(compiled: &asupersync::types::SloCompiledPolicy) -> BTreeSet<String> {
    compiled
        .blockers
        .iter()
        .map(|blocker| blocker.kind.as_str().to_string())
        .collect()
}

fn assert_issue(report: &SloPolicyValidationReport, kind: SloPolicyValidationIssueKind) {
    assert!(
        report.contains_issue(kind),
        "expected issue {}, got {:?}",
        kind.as_str(),
        issue_tags(report)
    );
}

fn workload_class_tags() -> BTreeSet<String> {
    [
        SloWorkloadClass::ControlPlane,
        SloWorkloadClass::DataPlane,
        SloWorkloadClass::Background,
        SloWorkloadClass::AgentSwarm,
    ]
    .into_iter()
    .map(|class| class.as_str().to_string())
    .collect()
}

fn latency_unit_tags() -> BTreeSet<String> {
    [SloLatencyUnit::Milliseconds, SloLatencyUnit::Microseconds]
        .into_iter()
        .map(|unit| unit.as_str().to_string())
        .collect()
}

fn validation_issue_tags() -> BTreeSet<String> {
    [
        SloPolicyValidationIssueKind::MalformedJson,
        SloPolicyValidationIssueKind::UnsupportedSchemaVersion,
        SloPolicyValidationIssueKind::MissingRequiredField,
        SloPolicyValidationIssueKind::NonMonotonicPercentile,
        SloPolicyValidationIssueKind::InvalidUnit,
        SloPolicyValidationIssueKind::MissingNoWinFallback,
        SloPolicyValidationIssueKind::SecretLikeMaterial,
        SloPolicyValidationIssueKind::ExternalPath,
        SloPolicyValidationIssueKind::StaleProfileHash,
        SloPolicyValidationIssueKind::UnsupportedWorkloadClass,
        SloPolicyValidationIssueKind::DuplicateObjective,
        SloPolicyValidationIssueKind::ImpossibleDeadline,
        SloPolicyValidationIssueKind::OversizedField,
        SloPolicyValidationIssueKind::RedactionFailure,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect()
}

fn proof_report_status_tags() -> BTreeSet<String> {
    [
        SloProofReportStatus::Pass,
        SloProofReportStatus::Fail,
        SloProofReportStatus::Blocked,
        SloProofReportStatus::Degraded,
        SloProofReportStatus::NoWin,
        SloProofReportStatus::Unsupported,
        SloProofReportStatus::StaleEvidence,
    ]
    .into_iter()
    .map(|status| status.as_str().to_string())
    .collect()
}

fn proof_report_issue_tags() -> BTreeSet<String> {
    [
        SloProofReportIssueKind::MalformedReport,
        SloProofReportIssueKind::UnsupportedSchemaVersion,
        SloProofReportIssueKind::MissingRequiredField,
        SloProofReportIssueKind::MissingRchCommand,
        SloProofReportIssueKind::StaleProfileHash,
        SloProofReportIssueKind::MissingNoWinReceipt,
        SloProofReportIssueKind::RedactionFailure,
        SloProofReportIssueKind::SecretLikeMaterial,
        SloProofReportIssueKind::NonPassingStatus,
        SloProofReportIssueKind::OversizedField,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect()
}

fn runtime_enforcement_status_tags() -> BTreeSet<String> {
    [
        "pass",
        "degraded",
        "no_win",
        "blocked",
        "stale_evidence",
        "unsupported",
        "malformed",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn runtime_enforcement_issue_tags() -> BTreeSet<String> {
    [
        "application_invalid",
        "policy_rejected",
        "cancelled",
        "queue_wait_exceeded",
        "memory_pressure_exceeded",
        "fd_pressure_exceeded",
        "timer_queue_exceeded",
        "unsupported_optional_work_class",
        "optional_work_brownout",
        "no_win_fallback",
        "stale_profile_hash",
        "missing_rch_command",
        "missing_no_win_receipt",
        "redaction_failure",
        "secret_like_material",
        "malformed_report",
        "local_rch_fallback",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn runtime_application_decision_tags() -> BTreeSet<String> {
    [
        SloRuntimePolicyDecision::Admit,
        SloRuntimePolicyDecision::Brownout,
        SloRuntimePolicyDecision::Reject,
        SloRuntimePolicyDecision::NoWin,
        SloRuntimePolicyDecision::Blocked,
    ]
    .into_iter()
    .map(|decision| decision.as_str().to_string())
    .collect()
}

fn runtime_optional_work_decision_tags() -> BTreeSet<String> {
    [
        SloRuntimeOptionalWorkDecision::Run,
        SloRuntimeOptionalWorkDecision::Brownout,
    ]
    .into_iter()
    .map(|decision| decision.as_str().to_string())
    .collect()
}

fn runtime_application_issue_tags() -> BTreeSet<String> {
    [
        SloRuntimePolicyApplicationIssueKind::MalformedApplication,
        SloRuntimePolicyApplicationIssueKind::UnsupportedSchemaVersion,
        SloRuntimePolicyApplicationIssueKind::MissingRequiredField,
        SloRuntimePolicyApplicationIssueKind::MissingRchCommand,
        SloRuntimePolicyApplicationIssueKind::StaleProfileHash,
        SloRuntimePolicyApplicationIssueKind::UnsupportedWorkloadClass,
        SloRuntimePolicyApplicationIssueKind::MissingCompiledOutput,
        SloRuntimePolicyApplicationIssueKind::MissingNoWinReceipt,
        SloRuntimePolicyApplicationIssueKind::RedactionFailure,
        SloRuntimePolicyApplicationIssueKind::SecretLikeMaterial,
        SloRuntimePolicyApplicationIssueKind::OversizedField,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect()
}

fn slo_brownout_e2e_non_claims() -> Vec<String> {
    [
        "not a throughput benchmark",
        "not a broad production enforcement claim",
        "not proof of RCH fleet availability",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn slo_brownout_e2e_required_fields() -> BTreeSet<String> {
    [
        "schema_version",
        "scenario_id",
        "pressure_transition",
        "receipt_status",
        "region_ids",
        "task_counts",
        "obligation_state",
        "cancellation_requested_count",
        "cancellation_observed_count",
        "drain_requested_count",
        "drain_completed_count",
        "finalizer_expected_count",
        "finalizer_completed_count",
        "final_quiescent",
        "runtime_invariant_violations",
        "oracle_violations",
        "operator_interpretation",
        "non_claims",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn slo_brownout_e2e_issue_tags() -> BTreeSet<String> {
    [
        "unsupported_schema_version",
        "missing_required_field",
        "missing_region_evidence",
        "missing_task_completion_evidence",
        "missing_obligation_resolution_evidence",
        "missing_drain_evidence",
        "missing_finalizer_evidence",
        "missing_quiescence_evidence",
        "runtime_invariant_violation",
        "oracle_violation",
        "missing_operator_interpretation",
        "unsupported_claim",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn validate_slo_brownout_e2e_receipt_json(receipt: &Value) -> BTreeSet<String> {
    let mut issues = BTreeSet::new();
    for field in slo_brownout_e2e_required_fields() {
        if receipt.get(&field).is_none() {
            issues.insert("missing_required_field".to_string());
        }
    }
    if receipt["schema_version"].as_str() != Some(SLO_BROWNOUT_E2E_RECEIPT_SCHEMA_VERSION) {
        issues.insert("unsupported_schema_version".to_string());
    }
    if receipt["region_ids"].as_array().is_none_or(Vec::is_empty) {
        issues.insert("missing_region_evidence".to_string());
    }
    let task_counts = &receipt["task_counts"];
    let admitted = task_counts["admitted"].as_u64().unwrap_or_default();
    let completed = task_counts["completed"].as_u64().unwrap_or_default();
    if completed < admitted {
        issues.insert("missing_task_completion_evidence".to_string());
    }
    if receipt["obligation_state"].as_str() != Some("resolved") {
        issues.insert("missing_obligation_resolution_evidence".to_string());
    }
    let drain_requested = receipt["drain_requested_count"]
        .as_u64()
        .unwrap_or_default();
    let drain_completed = receipt["drain_completed_count"]
        .as_u64()
        .unwrap_or_default();
    if drain_completed < drain_requested {
        issues.insert("missing_drain_evidence".to_string());
    }
    let finalizer_expected = receipt["finalizer_expected_count"]
        .as_u64()
        .unwrap_or_default();
    let finalizer_completed = receipt["finalizer_completed_count"]
        .as_u64()
        .unwrap_or_default();
    if finalizer_completed < finalizer_expected {
        issues.insert("missing_finalizer_evidence".to_string());
    }
    if receipt["final_quiescent"].as_bool() != Some(true) {
        issues.insert("missing_quiescence_evidence".to_string());
    }
    if receipt["runtime_invariant_violations"]
        .as_array()
        .is_some_and(|violations| !violations.is_empty())
    {
        issues.insert("runtime_invariant_violation".to_string());
    }
    if receipt["oracle_violations"]
        .as_array()
        .is_some_and(|violations| !violations.is_empty())
    {
        issues.insert("oracle_violation".to_string());
    }
    if receipt["operator_interpretation"]
        .as_str()
        .is_none_or(str::is_empty)
    {
        issues.insert("missing_operator_interpretation".to_string());
    }
    let non_claims = receipt["non_claims"]
        .as_array()
        .map(|claims| {
            claims
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    for required in slo_brownout_e2e_non_claims() {
        if !non_claims.contains(&required) {
            issues.insert("unsupported_claim".to_string());
        }
    }
    issues
}

fn runtime_admission_status_tags() -> BTreeSet<String> {
    [
        SloRuntimeAdmissionStatus::Admitted,
        SloRuntimeAdmissionStatus::Rejected,
        SloRuntimeAdmissionStatus::Brownout,
        SloRuntimeAdmissionStatus::NoWin,
        SloRuntimeAdmissionStatus::Blocked,
    ]
    .into_iter()
    .map(|status| status.as_str().to_string())
    .collect()
}

fn runtime_admission_issue_tags() -> BTreeSet<String> {
    [
        SloRuntimeAdmissionIssueKind::ApplicationInvalid,
        SloRuntimeAdmissionIssueKind::PolicyRejected,
        SloRuntimeAdmissionIssueKind::Cancelled,
        SloRuntimeAdmissionIssueKind::QueueWaitExceeded,
        SloRuntimeAdmissionIssueKind::MemoryPressureExceeded,
        SloRuntimeAdmissionIssueKind::FdPressureExceeded,
        SloRuntimeAdmissionIssueKind::TimerQueueExceeded,
        SloRuntimeAdmissionIssueKind::UnsupportedOptionalWorkClass,
        SloRuntimeAdmissionIssueKind::OptionalWorkBrownout,
        SloRuntimeAdmissionIssueKind::NoWinFallback,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect()
}

fn valid_proof_report(status: SloProofReportStatus) -> SloProofReport {
    let summary = match status {
        SloProofReportStatus::Pass => "SLO proof passed with complete rch evidence",
        SloProofReportStatus::Fail => "SLO proof failed with explicit failure status",
        SloProofReportStatus::Blocked => "SLO proof blocked before gate admission",
        SloProofReportStatus::Degraded => "SLO proof degraded optional work before violation",
        SloProofReportStatus::NoWin => "SLO proof reached no-win fallback with receipt",
        SloProofReportStatus::Unsupported => "SLO proof unsupported workload lane",
        SloProofReportStatus::StaleEvidence => "SLO proof stale evidence hash mismatch",
    };
    let no_win_receipt = (status == SloProofReportStatus::NoWin).then(|| SloProofNoWinReceipt {
        fallback_profile: "agent-swarm-safe-mode".to_string(),
        fallback_reason: "objectives-conflict-with-pressure".to_string(),
        proof_command: SLO_PROOF_COMMAND.to_string(),
    });
    let observed_profile_hash = if status == SloProofReportStatus::StaleEvidence {
        Some(profile_hash('b'))
    } else {
        Some(profile_hash('a'))
    };

    SloProofReport {
        schema_version: SLO_POLICY_PROOF_REPORT_SCHEMA_VERSION.to_string(),
        report_id: format!("slo-proof-{}", status.as_str()),
        policy_id: "agent-swarm-standard".to_string(),
        status,
        human_summary: summary.to_string(),
        provenance: SloProofReportProvenance {
            profile_id: "agent-swarm-prod".to_string(),
            profile_hash: profile_hash('a'),
            observed_profile_hash,
            target_commit: "b8f24024890da34b9151aaea62fff2d06d90f282".to_string(),
            related_bead_id: Some("asupersync-bgtplc.4".to_string()),
        },
        proof_commands: vec![SloProofCommand {
            label: "slo-proof-contract".to_string(),
            command: SLO_PROOF_COMMAND.to_string(),
        }],
        no_win_receipt,
        rows: vec![SloProofReportRow {
            row_id: format!("row-{}", status.as_str()),
            status,
            evidence_ref:
                "target/slo-policy-bundle/asupersync-bgtplc.4/slo-policy-bundle-events.ndjson"
                    .to_string(),
            summary: summary.to_string(),
        }],
        redaction: SloPolicyRedaction {
            policy_id: "slo-proof-redaction-v1".to_string(),
            passed: true,
        },
        metadata: BTreeMap::from([(
            "gate_mode".to_string(),
            Value::String("opt-in-direct-main".to_string()),
        )]),
    }
}

fn proof_report_issue_set(report: &SloProofReport) -> BTreeSet<String> {
    report
        .validate()
        .issues
        .iter()
        .map(|issue| issue.kind.as_str().to_string())
        .collect()
}

/// br-asupersync-7tcipb item 6: a proof report MUST carry observed profile hash
/// freshness evidence. Before the fix, omitting `observed_profile_hash` skipped
/// the staleness/match check entirely, so a report passed the fail-closed
/// opt-in gate without proving the observed evidence matched the declared
/// profile hash. This locks the fail-closed behavior and keeps the proof-report
/// validator consistent with the runtime-application validator (which already
/// requires the field).
#[test]
fn proof_report_missing_observed_profile_hash_fails_closed() {
    // Baseline: the canonical fixture carries the hash and is accepted.
    let mut report = valid_proof_report(SloProofReportStatus::Pass);
    assert!(
        report.validate().accepted,
        "valid proof report with observed profile hash must be accepted"
    );

    // Omitting the freshness evidence must NOT pass the gate.
    report.provenance.observed_profile_hash = None;
    let validation = report.validate();
    assert!(
        !validation.accepted,
        "proof report omitting observed_profile_hash must be rejected (fail closed)"
    );
    assert!(
        validation.issues.iter().any(|issue| {
            issue.kind == SloProofReportIssueKind::StaleProfileHash
                && issue.field == "provenance.observed_profile_hash"
        }),
        "missing observed_profile_hash must raise a StaleProfileHash issue; got {:?}",
        validation.issues
    );
}

fn valid_runtime_application() -> SloRuntimePolicyApplication {
    let compiled = valid_bundle().compile_for_budget_admission(Some(&valid_capacity_evidence()));
    SloRuntimePolicyApplication::from_compiled_policy(
        &compiled,
        SloWorkloadClass::AgentSwarm,
        Some(profile_hash('a')),
        SloProofCommand {
            label: "runtime-slo-policy-application".to_string(),
            command: SloRuntimePolicyApplication::render_application_proof_command(
                "runtime_slo_policy_application",
            ),
        },
        SloPolicyRedaction {
            policy_id: "slo-runtime-application-redaction-v1".to_string(),
            passed: true,
        },
    )
}

fn runtime_request(
    request_id: &str,
    work_units: u64,
    optional_work_class: Option<&str>,
) -> SloRuntimeAdmissionRequest {
    SloRuntimeAdmissionRequest {
        request_id: request_id.to_string(),
        work_units,
        optional_work_class: optional_work_class.map(str::to_string),
        queue_wait_ms: 20,
        memory_basis_points: 6_500,
        fd_basis_points: 5_900,
        timer_queue_depth: 12_000,
        cancel_requested: false,
    }
}

fn runtime_bridge_request(
    request_id: &str,
    work_units: u64,
    work_kind: SloRuntimeWorkKind,
    optional_work_class: Option<&str>,
) -> SloRuntimePolicyBridgeRequest {
    let request = runtime_request(request_id, work_units, optional_work_class);
    SloRuntimePolicyBridgeRequest::new(work_kind, request)
}

fn expected_issue_tags(scenario_value: &Value) -> BTreeSet<String> {
    scenario_value["expected"]["issue_kinds"]
        .as_array()
        .expect("expected issue kinds")
        .iter()
        .map(|value| value.as_str().expect("issue kind is string").to_string())
        .collect()
}

fn replay_fixture(
    scenario_id: &'static str,
    seed: u64,
    capacity_evidence: Option<SloPolicyCapacityEvidence>,
    work_units: u64,
    optional_work_units: u64,
    cleanup_work_ms: u64,
) -> LabReplayFixture {
    let memory_basis_points = capacity_evidence
        .as_ref()
        .map_or(6_500, |evidence| evidence.memory_basis_points);
    let fd_basis_points = capacity_evidence
        .as_ref()
        .map_or(5_900, |evidence| evidence.fd_basis_points);
    let timer_queue_depth = capacity_evidence
        .as_ref()
        .map_or(12_000, |evidence| evidence.timer_queue_depth);
    LabReplayFixture {
        scenario_id,
        seed,
        bundle: Some(valid_bundle()),
        malformed_document: None,
        capacity_evidence,
        work_units,
        optional_work_units,
        optional_work_class: None,
        cleanup_work_ms,
        proof_command: SLO_REPLAY_PROOF_COMMAND,
        observed_profile_hash: Some(profile_hash('a')),
        queue_wait_ms: 20,
        memory_basis_points,
        fd_basis_points,
        timer_queue_depth,
        cancel_requested: false,
        pressure_transition: LabReplayPressureTransition::Steady,
    }
}

fn malformed_replay_fixture() -> LabReplayFixture {
    LabReplayFixture {
        scenario_id: "lab-replay-malformed-policy",
        seed: 0x5100_F00D,
        bundle: None,
        malformed_document: Some("{\"schema_version\":1,"),
        capacity_evidence: None,
        work_units: 3,
        optional_work_units: 1,
        optional_work_class: None,
        cleanup_work_ms: 0,
        proof_command: SLO_REPLAY_PROOF_COMMAND,
        observed_profile_hash: None,
        queue_wait_ms: 20,
        memory_basis_points: 6_500,
        fd_basis_points: 5_900,
        timer_queue_depth: 12_000,
        cancel_requested: false,
        pressure_transition: LabReplayPressureTransition::Steady,
    }
}

fn lab_replay_fixtures() -> Vec<LabReplayFixture> {
    let normal = valid_capacity_evidence();

    let mut overload = valid_capacity_evidence();
    overload.queue_depth = 12_500;

    let cleanup_pressure = valid_capacity_evidence();

    let mut brownout = valid_capacity_evidence();
    brownout.memory_basis_points = 8_500;

    let mut no_win = valid_capacity_evidence();
    no_win.memory_basis_points = 9_500;

    let mut overload_fixture = replay_fixture(
        "lab-replay-overload",
        0x5100_0002,
        Some(overload),
        12,
        0,
        120,
    );
    overload_fixture.queue_wait_ms = 81;

    let mut optional_brownout_fixture = replay_fixture(
        "lab-replay-optional-brownout",
        0x5100_0004,
        Some(brownout.clone()),
        4,
        3,
        120,
    );
    optional_brownout_fixture.optional_work_class = Some("index_refresh");

    let mut stale_fixture = replay_fixture(
        "lab-replay-stale-profile-hash",
        0x5100_0006,
        Some(valid_capacity_evidence()),
        4,
        0,
        120,
    );
    stale_fixture.observed_profile_hash = Some(profile_hash('b'));

    let mut cancelled_fixture = replay_fixture(
        "lab-replay-cancelled-admission",
        0x5100_0007,
        Some(valid_capacity_evidence()),
        4,
        0,
        120,
    );
    cancelled_fixture.cancel_requested = true;

    let mut cancel_mid_brownout = replay_fixture(
        "lab-replay-cancel-mid-brownout",
        0x5100_0008,
        Some(brownout.clone()),
        4,
        3,
        120,
    );
    cancel_mid_brownout.optional_work_class = Some("index_refresh");
    cancel_mid_brownout.pressure_transition = LabReplayPressureTransition::CancelDuringBrownout;

    let mut recovery_after_pressure_clears = replay_fixture(
        "lab-replay-recovery-after-pressure-clears",
        0x5100_0009,
        Some(brownout),
        4,
        2,
        120,
    );
    recovery_after_pressure_clears.optional_work_class = Some("index_refresh");
    recovery_after_pressure_clears.pressure_transition =
        LabReplayPressureTransition::RecoveryAfterPressureClears;

    vec![
        replay_fixture(
            "lab-replay-normal-load",
            0x5100_0001,
            Some(normal),
            4,
            0,
            120,
        ),
        overload_fixture,
        replay_fixture(
            "lab-replay-cleanup-deadline-pressure",
            0x5100_0003,
            Some(cleanup_pressure),
            4,
            0,
            400,
        ),
        optional_brownout_fixture,
        replay_fixture(
            "lab-replay-no-win-fallback",
            0x5100_0005,
            Some(no_win),
            4,
            2,
            120,
        ),
        stale_fixture,
        cancelled_fixture,
        cancel_mid_brownout,
        recovery_after_pressure_clears,
        malformed_replay_fixture(),
    ]
}

fn evaluate_lab_replay_fixture(fixture: LabReplayFixture) -> LabReplayEvidence {
    let config = TestConfig::new()
        .with_seed(fixture.seed)
        .with_tracing(true)
        .with_max_steps(20_000);
    let mut runtime = LabRuntimeTarget::create_runtime(config);
    let proof_command = fixture.proof_command.to_string();
    let lab_seed = fixture.seed;
    let scenario_id = fixture.scenario_id.to_string();

    let core =
        LabRuntimeTarget::block_on(
            &mut runtime,
            async move { run_lab_replay_core(fixture).await },
        );

    LabRuntimeTarget::advance_time(&mut runtime, Duration::from_millis(core.virtual_elapsed_ms));
    let report = runtime.run_until_quiescent_with_report();
    let oracle_violations = runtime
        .oracles
        .check_all(runtime.now())
        .into_iter()
        .map(|violation| violation.to_string())
        .collect::<Vec<_>>();

    let receipt = SloLabBrownoutE2eReceipt::from_lab_report(
        scenario_id.clone(),
        core.receipt_seed,
        &report,
        oracle_violations.clone(),
    );

    LabReplayEvidence {
        scenario_id,
        replay_status: core.replay_status,
        compiler_status: core.compiler_status,
        admitted_work_units: core.admitted_work_units,
        rejected_work_units: core.rejected_work_units,
        optional_work_units_browned_out: core.optional_work_units_browned_out,
        cleanup_deadline_misses: core.cleanup_deadline_misses,
        fallback_reason: core.fallback_reason,
        proof_command,
        lab_seed,
        lab_steps: runtime.steps(),
        lab_virtual_elapsed_ms: LabRuntimeTarget::now(&runtime).as_millis() as u64,
        trace_events: report.trace_len,
        oracle_violations,
        issue_kinds: core.issue_kinds,
        receipt,
    }
}

async fn run_lab_replay_core(fixture: LabReplayFixture) -> LabReplayCoreOutcome {
    let region_ids = current_lab_region_ids();
    if let Some(document) = fixture.malformed_document {
        let report = validate_slo_policy_bundle_json(document);
        let rejected_work_units = fixture.work_units;
        let optional_work_units_browned_out = fixture.optional_work_units;
        return LabReplayCoreOutcome {
            replay_status: "blocked".to_string(),
            compiler_status: "blocked".to_string(),
            admitted_work_units: 0,
            rejected_work_units,
            optional_work_units_browned_out,
            cleanup_deadline_misses: 0,
            fallback_reason: None,
            issue_kinds: issue_tags(&report).into_iter().collect(),
            virtual_elapsed_ms: 0,
            receipt_seed: SloLabBrownoutE2eReceiptSeed {
                pressure_transition: fixture.pressure_transition.as_str().to_string(),
                region_ids,
                task_counts: SloLabTaskCounts {
                    requested: fixture
                        .work_units
                        .saturating_add(fixture.optional_work_units),
                    admitted: 0,
                    completed: 0,
                    rejected: rejected_work_units,
                    browned_out: optional_work_units_browned_out,
                    cancelled: 0,
                    cleanup_finalizers: 0,
                    proof_reporting: 0,
                },
                obligation_state: "resolved".to_string(),
                cancellation_requested_count: 0,
                cancellation_observed_count: 0,
                drain_requested_count: rejected_work_units,
                drain_completed_count: rejected_work_units,
                finalizer_expected_count: 0,
                finalizer_completed_count: 0,
                operator_interpretation: operator_interpretation(
                    "blocked",
                    fixture.pressure_transition,
                ),
            },
        };
    }

    let bundle = fixture.bundle.as_ref().expect("replay fixture has bundle");
    let compiled = bundle.compile_for_budget_admission(fixture.capacity_evidence.as_ref());
    let compiler_status = compiled.status.as_str().to_string();
    let application = SloRuntimePolicyApplication::from_compiled_policy(
        &compiled,
        SloWorkloadClass::AgentSwarm,
        fixture.observed_profile_hash.clone(),
        SloProofCommand {
            label: "lab-runtime-slo-replay".to_string(),
            command: fixture.proof_command.to_string(),
        },
        SloPolicyRedaction {
            policy_id: "slo-lab-runtime-replay-redaction-v1".to_string(),
            passed: true,
        },
    );
    let cx = Cx::current().expect("LabRuntimeTarget installs current Cx");
    let bridge = SloRuntimePolicyBridge::new(&application);
    let validation = application.validate();
    let core_request =
        replay_admission_request(&fixture, fixture.work_units, None, fixture.cancel_requested);
    let core_decision =
        bridge.evaluate(&cx, &SloRuntimePolicyBridgeRequest::required(core_request));
    let core_outcome = core_decision.outcome.clone();
    let mut issue_kinds = BTreeSet::new();
    collect_replay_issue_kinds(&validation, &core_outcome, &mut issue_kinds);

    let mut replay_status = replay_status_for_admission(&validation, &core_outcome);
    let mut admitted_work_units = core_outcome.admitted_work_units;
    let mut rejected_work_units = core_outcome.rejected_work_units;
    let mut optional_work_units_browned_out = 0;
    let mut fallback_reason = core_outcome.fallback_reason.clone();
    let mut cancelled_work_units =
        u64::from(fixture.cancel_requested).saturating_mul(core_outcome.rejected_work_units);

    if core_outcome.status == SloRuntimeAdmissionStatus::Admitted && fixture.optional_work_units > 0
    {
        let optional_request = replay_admission_request(
            &fixture,
            fixture.optional_work_units,
            fixture.optional_work_class,
            false,
        );
        let optional_decision = bridge.evaluate(
            &cx,
            &SloRuntimePolicyBridgeRequest::optional(optional_request),
        );
        let optional_outcome = optional_decision.outcome.clone();
        collect_replay_issue_kinds(&validation, &optional_outcome, &mut issue_kinds);
        admitted_work_units =
            admitted_work_units.saturating_add(optional_outcome.admitted_work_units);
        rejected_work_units =
            rejected_work_units.saturating_add(optional_outcome.rejected_work_units);
        if optional_outcome.status == SloRuntimeAdmissionStatus::Brownout {
            optional_work_units_browned_out = optional_outcome.rejected_work_units;
            replay_status = "brownout".to_string();
            if fixture.pressure_transition == LabReplayPressureTransition::CancelDuringBrownout {
                issue_kinds.insert(SloRuntimeAdmissionIssueKind::Cancelled.as_str().to_string());
                replay_status = "cancelled".to_string();
                cancelled_work_units =
                    cancelled_work_units.saturating_add(optional_outcome.rejected_work_units);
            }
            if fixture.pressure_transition
                == LabReplayPressureTransition::RecoveryAfterPressureClears
            {
                let mut recovery_request = replay_admission_request(
                    &fixture,
                    fixture.optional_work_units,
                    fixture.optional_work_class,
                    false,
                );
                let recovered_pressure = valid_capacity_evidence();
                recovery_request.memory_basis_points = recovered_pressure.memory_basis_points;
                recovery_request.fd_basis_points = recovered_pressure.fd_basis_points;
                recovery_request.timer_queue_depth = recovered_pressure.timer_queue_depth;
                recovery_request.queue_wait_ms = 20;
                let recovery_decision = bridge.evaluate(
                    &cx,
                    &SloRuntimePolicyBridgeRequest::optional(recovery_request),
                );
                let recovery_outcome = recovery_decision.outcome.clone();
                collect_replay_issue_kinds(&validation, &recovery_outcome, &mut issue_kinds);
                admitted_work_units =
                    admitted_work_units.saturating_add(recovery_outcome.admitted_work_units);
                rejected_work_units =
                    rejected_work_units.saturating_add(recovery_outcome.rejected_work_units);
                if recovery_outcome.status != SloRuntimeAdmissionStatus::Admitted {
                    replay_status = replay_status_for_admission(&validation, &recovery_outcome);
                    fallback_reason.clone_from(&recovery_outcome.fallback_reason);
                }
            }
        } else if optional_outcome.status != SloRuntimeAdmissionStatus::Admitted {
            replay_status = replay_status_for_admission(&validation, &optional_outcome);
            fallback_reason.clone_from(&optional_outcome.fallback_reason);
        }
    }

    let cleanup_deadline_misses = u64::from(
        core_outcome.status == SloRuntimeAdmissionStatus::Admitted
            && fixture.cleanup_work_ms > core_outcome.budget.cleanup_deadline_ms,
    );
    let mut finalizer_expected_count = 0;
    let mut finalizer_completed_count = 0;
    let mut proof_reporting_count = 0;
    if core_outcome.status == SloRuntimeAdmissionStatus::Admitted && admitted_work_units > 0 {
        finalizer_expected_count = 1;
        let cleanup_decision = bridge.evaluate(
            &cx,
            &SloRuntimePolicyBridgeRequest::cleanup_finalizer(replay_admission_request(
                &fixture,
                1,
                Some("index_refresh"),
                false,
            )),
        );
        if cleanup_decision.work_may_start {
            finalizer_completed_count = 1;
        }
        let proof_decision = bridge.evaluate(
            &cx,
            &SloRuntimePolicyBridgeRequest::proof_reporting(replay_admission_request(
                &fixture,
                1,
                Some("analytics_rollup"),
                false,
            )),
        );
        if proof_decision.work_may_start {
            proof_reporting_count = 1;
        }
    }
    let task_units_to_run = admitted_work_units
        .saturating_add(finalizer_completed_count)
        .saturating_add(proof_reporting_count);
    let completed_work_units =
        run_admitted_replay_tasks(task_units_to_run, core_outcome.budget.to_budget()).await;
    assert_eq!(
        completed_work_units, task_units_to_run,
        "all admitted replay units should complete"
    );
    let virtual_elapsed_ms = if admitted_work_units == 0 {
        0
    } else {
        admitted_work_units
            .saturating_mul(2)
            .saturating_add(optional_work_units_browned_out)
            .saturating_add(
                fixture
                    .cleanup_work_ms
                    .min(core_outcome.budget.cleanup_deadline_ms),
            )
    };
    let cancellation_requested_count = u64::from(
        fixture.cancel_requested
            || fixture.pressure_transition == LabReplayPressureTransition::CancelDuringBrownout,
    );
    let cancellation_observed_count = u64::from(
        core_decision.cx_cancel_observed
            || core_outcome
                .issue_kinds
                .contains(&SloRuntimeAdmissionIssueKind::Cancelled)
            || fixture.pressure_transition == LabReplayPressureTransition::CancelDuringBrownout,
    );
    let receipt_seed = SloLabBrownoutE2eReceiptSeed {
        pressure_transition: fixture.pressure_transition.as_str().to_string(),
        region_ids,
        task_counts: SloLabTaskCounts {
            requested: if core_outcome.status == SloRuntimeAdmissionStatus::Admitted {
                requested_receipt_work_units(&fixture)
            } else {
                fixture.work_units
            },
            admitted: admitted_work_units,
            completed: completed_work_units,
            rejected: rejected_work_units,
            browned_out: optional_work_units_browned_out,
            cancelled: cancelled_work_units,
            cleanup_finalizers: finalizer_completed_count,
            proof_reporting: proof_reporting_count,
        },
        obligation_state: "resolved".to_string(),
        cancellation_requested_count,
        cancellation_observed_count,
        drain_requested_count: rejected_work_units,
        drain_completed_count: rejected_work_units,
        finalizer_expected_count,
        finalizer_completed_count,
        operator_interpretation: operator_interpretation(
            &replay_status,
            fixture.pressure_transition,
        ),
    };

    LabReplayCoreOutcome {
        replay_status,
        compiler_status,
        admitted_work_units,
        rejected_work_units,
        optional_work_units_browned_out,
        cleanup_deadline_misses,
        fallback_reason,
        issue_kinds: issue_kinds.into_iter().collect(),
        virtual_elapsed_ms,
        receipt_seed,
    }
}

fn requested_receipt_work_units(fixture: &LabReplayFixture) -> u64 {
    let recovery_units = if fixture.pressure_transition
        == LabReplayPressureTransition::RecoveryAfterPressureClears
    {
        fixture.optional_work_units
    } else {
        0
    };
    fixture
        .work_units
        .saturating_add(fixture.optional_work_units)
        .saturating_add(recovery_units)
}

fn current_lab_region_ids() -> Vec<String> {
    Cx::current().map_or_else(
        || vec!["lab-region-unavailable".to_string()],
        |cx| vec![format!("{:?}", cx.region_id())],
    )
}

fn operator_interpretation(
    replay_status: &str,
    pressure_transition: LabReplayPressureTransition,
) -> String {
    match (replay_status, pressure_transition) {
        ("passed", LabReplayPressureTransition::RecoveryAfterPressureClears) => {
            "pressure cleared; required work, recovered optional work, finalizer, and proof reporting quiesced"
        }
        ("brownout", LabReplayPressureTransition::RecoveryAfterPressureClears) => {
            "optional work browned out under pressure, recovered after pressure cleared, and finalizers quiesced"
        }
        ("cancelled", LabReplayPressureTransition::CancelDuringBrownout) => {
            "cancellation arrived during optional-work brownout; denied work received drain evidence and the region quiesced"
        }
        ("passed", _) => "admitted work completed with cleanup/finalizer evidence and region quiescence",
        ("brownout", _) => {
            "required work completed while optional work browned out with an explicit drain receipt"
        }
        ("no_win", _) => {
            "no-win fallback selected; runtime work did not start and drain evidence was recorded"
        }
        ("cancelled", _) => {
            "cancellation observed before work start; denied work received explicit drain evidence"
        }
        ("rejected", _) => {
            "hard pressure rejected runtime work before start and recorded non-start evidence"
        }
        ("stale_evidence", _) => "stale policy evidence blocked runtime work fail-closed",
        ("blocked", _) => "malformed or invalid policy evidence blocked runtime work fail-closed",
        _ => "runtime SLO replay completed with explicit operator evidence",
    }
    .to_string()
}

fn replay_admission_request(
    fixture: &LabReplayFixture,
    work_units: u64,
    optional_work_class: Option<&str>,
    cancel_requested: bool,
) -> SloRuntimeAdmissionRequest {
    SloRuntimeAdmissionRequest {
        request_id: format!("{}-{work_units}", fixture.scenario_id),
        work_units,
        optional_work_class: optional_work_class.map(str::to_string),
        queue_wait_ms: fixture.queue_wait_ms,
        memory_basis_points: fixture.memory_basis_points,
        fd_basis_points: fixture.fd_basis_points,
        timer_queue_depth: fixture.timer_queue_depth,
        cancel_requested,
    }
}

fn collect_replay_issue_kinds(
    validation: &SloRuntimePolicyApplicationValidation,
    outcome: &SloRuntimeAdmissionOutcome,
    issue_kinds: &mut BTreeSet<String>,
) {
    issue_kinds.extend(
        outcome
            .issue_kinds
            .iter()
            .map(|issue| issue.as_str().to_string()),
    );
    if !validation.accepted {
        issue_kinds.extend(
            validation
                .issues
                .iter()
                .map(|issue| issue.kind.as_str().to_string()),
        );
    }
}

fn replay_status_for_admission(
    validation: &SloRuntimePolicyApplicationValidation,
    outcome: &SloRuntimeAdmissionOutcome,
) -> String {
    if validation.contains_issue(SloRuntimePolicyApplicationIssueKind::StaleProfileHash) {
        return "stale_evidence".to_string();
    }
    match outcome.status {
        SloRuntimeAdmissionStatus::Admitted => "passed",
        SloRuntimeAdmissionStatus::Rejected
            if outcome
                .issue_kinds
                .contains(&SloRuntimeAdmissionIssueKind::Cancelled) =>
        {
            "cancelled"
        }
        SloRuntimeAdmissionStatus::Rejected => "rejected",
        SloRuntimeAdmissionStatus::Brownout => "brownout",
        SloRuntimeAdmissionStatus::NoWin => "no_win",
        SloRuntimeAdmissionStatus::Blocked => "blocked",
    }
    .to_string()
}

async fn run_admitted_replay_tasks(work_units: u64, budget: Budget) -> u64 {
    let cx = asupersync::Cx::current().expect("LabRuntimeTarget installs current Cx");
    let completions = Arc::new(StdMutex::new(0_u64));
    let mut handles = Vec::new();

    for _ in 0..work_units {
        let task_cx = cx.clone();
        let task_completions = Arc::clone(&completions);
        handles.push(LabRuntimeTarget::spawn(
            &task_cx.clone(),
            budget,
            async move {
                yield_now().await;
                *task_completions.lock().expect("completion mutex") += 1;
                1_u64
            },
        ));
    }

    let mut completed = 0;
    for handle in handles {
        match handle.await {
            Outcome::Ok(units) => completed += units,
            other => panic!("replay task failed: {other:?}"),
        }
    }
    assert_eq!(
        *completions.lock().expect("completion mutex"),
        completed,
        "completion counter matches awaited tasks"
    );
    completed
}

#[test]
fn artifact_catalog_matches_rust_tags_and_required_fields() {
    let artifact = contract();
    let artifact_workloads = artifact["workload_classes"]
        .as_array()
        .expect("workload classes")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("workload class is string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let artifact_units = artifact["latency_units"]
        .as_array()
        .expect("latency units")
        .iter()
        .map(|value| value.as_str().expect("unit is string").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_issues = artifact["validation_issue_kinds"]
        .as_array()
        .expect("validation issue kinds")
        .iter()
        .map(|value| value.as_str().expect("issue is string").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_compiler_statuses = artifact["compiler_statuses"]
        .as_array()
        .expect("compiler statuses")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("compiler status is string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let artifact_compiler_blockers = artifact["compiler_blocker_kinds"]
        .as_array()
        .expect("compiler blocker kinds")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("compiler blocker is string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let artifact_lab_replay_statuses = artifact["lab_replay_statuses"]
        .as_array()
        .expect("lab replay statuses")
        .iter()
        .map(|value| value.as_str().expect("lab replay status").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_proof_report_statuses = artifact["proof_report_statuses"]
        .as_array()
        .expect("proof report statuses")
        .iter()
        .map(|value| value.as_str().expect("proof report status").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_proof_report_issues = artifact["proof_report_issue_kinds"]
        .as_array()
        .expect("proof report issue kinds")
        .iter()
        .map(|value| value.as_str().expect("proof report issue").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_runtime_enforcement_statuses = artifact["runtime_enforcement_statuses"]
        .as_array()
        .expect("runtime enforcement statuses")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("runtime enforcement status")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let artifact_runtime_enforcement_issues = artifact["runtime_enforcement_issue_kinds"]
        .as_array()
        .expect("runtime enforcement issue kinds")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("runtime enforcement issue")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let artifact_runtime_application_decisions = artifact["runtime_application_decisions"]
        .as_array()
        .expect("runtime application decisions")
        .iter()
        .map(|value| value.as_str().expect("runtime decision").to_string())
        .collect::<BTreeSet<_>>();
    let artifact_runtime_optional_work_decisions =
        artifact["runtime_application_optional_work_decisions"]
            .as_array()
            .expect("runtime optional work decisions")
            .iter()
            .map(|value| value.as_str().expect("optional work decision").to_string())
            .collect::<BTreeSet<_>>();
    let artifact_runtime_application_issues = artifact["runtime_application_issue_kinds"]
        .as_array()
        .expect("runtime application issue kinds")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("runtime application issue")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let artifact_runtime_admission_statuses = artifact["runtime_admission_statuses"]
        .as_array()
        .expect("runtime admission statuses")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("runtime admission status")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let artifact_runtime_admission_issues = artifact["runtime_admission_issue_kinds"]
        .as_array()
        .expect("runtime admission issue kinds")
        .iter()
        .map(|value| value.as_str().expect("runtime admission issue").to_string())
        .collect::<BTreeSet<_>>();
    let required_fields = artifact["required_bundle_fields"]
        .as_array()
        .expect("required bundle fields")
        .iter()
        .map(|value| value.as_str().expect("field is string").to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(artifact_workloads, workload_class_tags());
    assert_eq!(artifact_units, latency_unit_tags());
    assert_eq!(artifact_issues, validation_issue_tags());
    assert_eq!(artifact_compiler_statuses, compiler_status_tags());
    assert_eq!(artifact_compiler_blockers, compiler_blocker_tags());
    assert_eq!(artifact_lab_replay_statuses, lab_replay_status_tags());
    assert_eq!(artifact_proof_report_statuses, proof_report_status_tags());
    assert_eq!(artifact_proof_report_issues, proof_report_issue_tags());
    assert_eq!(
        artifact_runtime_enforcement_statuses,
        runtime_enforcement_status_tags()
    );
    assert_eq!(
        artifact_runtime_enforcement_issues,
        runtime_enforcement_issue_tags()
    );
    assert_eq!(
        artifact_runtime_application_decisions,
        runtime_application_decision_tags()
    );
    assert_eq!(
        artifact_runtime_optional_work_decisions,
        runtime_optional_work_decision_tags()
    );
    assert_eq!(
        artifact_runtime_application_issues,
        runtime_application_issue_tags()
    );
    assert_eq!(
        artifact_runtime_admission_statuses,
        runtime_admission_status_tags()
    );
    assert_eq!(
        artifact_runtime_admission_issues,
        runtime_admission_issue_tags()
    );
    assert_eq!(
        artifact["compiler_schema_version"].as_str(),
        Some(SLO_POLICY_COMPILER_SCHEMA_VERSION)
    );
    assert_eq!(
        artifact["proof_report_schema_version"].as_str(),
        Some(SLO_POLICY_PROOF_REPORT_SCHEMA_VERSION)
    );
    assert_eq!(
        artifact["runtime_enforcement_report_schema_version"].as_str(),
        Some("slo-runtime-enforcement-proof-report-v1")
    );
    assert_eq!(
        artifact["lab_brownout_e2e_contract_version"].as_str(),
        Some(SLO_BROWNOUT_E2E_RECEIPT_SCHEMA_VERSION)
    );
    let e2e_required_fields = artifact["lab_brownout_e2e_contract"]["required_event_fields"]
        .as_array()
        .expect("brownout e2e required fields")
        .iter()
        .map(|value| value.as_str().expect("brownout e2e field").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(e2e_required_fields, slo_brownout_e2e_required_fields());
    let e2e_fail_closed = artifact["lab_brownout_e2e_contract"]["fail_closed_for"]
        .as_array()
        .expect("brownout e2e fail-closed issues")
        .iter()
        .map(|value| value.as_str().expect("brownout e2e issue").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(e2e_fail_closed, slo_brownout_e2e_issue_tags());
    let proof_commands = artifact["proof_commands"]
        .as_array()
        .expect("proof commands")
        .iter()
        .map(|value| value.as_str().expect("proof command").to_string())
        .collect::<BTreeSet<_>>();
    assert!(proof_commands.contains(SLO_BROWNOUT_E2E_PROOF_COMMAND));
    assert_eq!(
        artifact["runtime_application_schema_version"].as_str(),
        Some(SLO_POLICY_RUNTIME_APPLICATION_SCHEMA_VERSION)
    );
    assert_eq!(
        artifact["runtime_application_contract"]["compiler_schema_version"].as_str(),
        Some(SLO_POLICY_COMPILER_SCHEMA_VERSION)
    );
    let runtime_command = artifact["runtime_application_contract"]["proof_command_rendering"]
        .as_str()
        .expect("runtime proof command rendering");
    assert!(runtime_command.contains("rch exec --"));
    assert!(
        runtime_command
            .contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_slo_runtime_application")
    );
    assert!(!runtime_command.contains("rch exec -- cargo"));
    assert!(runtime_command.contains("runtime_slo_policy_application"));
    let runtime_fail_closed = artifact["runtime_application_contract"]["fail_closed_for"]
        .as_array()
        .expect("runtime fail-closed issue list")
        .iter()
        .map(|value| value.as_str().expect("runtime issue").to_string())
        .collect::<BTreeSet<_>>();
    for required in [
        SloRuntimePolicyApplicationIssueKind::StaleProfileHash,
        SloRuntimePolicyApplicationIssueKind::UnsupportedWorkloadClass,
        SloRuntimePolicyApplicationIssueKind::MissingCompiledOutput,
        SloRuntimePolicyApplicationIssueKind::MissingNoWinReceipt,
        SloRuntimePolicyApplicationIssueKind::MissingRchCommand,
    ] {
        assert!(
            runtime_fail_closed.contains(required.as_str()),
            "runtime contract missing fail-closed issue {}",
            required.as_str()
        );
    }
    let admission_contract = &artifact["runtime_admission_contract"];
    assert_eq!(
        admission_contract["application_schema_version"].as_str(),
        Some(SLO_POLICY_RUNTIME_APPLICATION_SCHEMA_VERSION)
    );
    assert!(
        admission_contract["evidence_fields"]
            .as_array()
            .expect("admission evidence fields")
            .iter()
            .any(|value| value.as_str() == Some("proof_command"))
    );
    assert_eq!(
        artifact["policy_bundle_schema_version"].as_u64(),
        Some(u64::from(SLO_POLICY_BUNDLE_SCHEMA_VERSION))
    );
    for field in [
        "schema_version",
        "policy_id",
        "workload_class",
        "latency_objectives",
        "cleanup_deadline_ms",
        "max_queue_wait_ms",
        "resource_pressure",
        "no_win_fallback",
        "provenance",
        "redaction",
    ] {
        assert!(required_fields.contains(field), "required field {field}");
    }
}

#[test]
fn artifact_cargo_proof_commands_use_isolated_rch_target_dirs() {
    let artifact = contract();
    let mut strings = Vec::new();
    collect_json_strings(&artifact, &mut strings);
    let offenders = strings
        .into_iter()
        .filter(|value| {
            value.contains("cargo ")
                && (value.contains("rch exec -- cargo") || !cargo_command_has_target_dir(value))
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert!(offenders.is_empty(), "{offenders:?}");
}

#[test]
fn readme_and_operator_docs_track_slo_artifact_and_exports() {
    let artifact = contract();
    let readme = text_file(README_PATH);
    let operator_doc = text_file(OPERATOR_DOC_PATH);
    let readme_section = section_between(&readme, "### SLO Policy Proof Loop", "### Gate matrix");
    let operator_section = section_between(
        &operator_doc,
        "## SLO Policy Proof Loop",
        "## Gate Definitions",
    );
    let gate_command =
        SloProofReport::render_ci_gate_command("target/slo-policy-bundle", "asupersync-w5n9qp.5");

    for (label, section) in [
        ("README", readme_section),
        ("operator doc", operator_section),
    ] {
        for token in [
            CONTRACT_PATH,
            SCRIPT_PATH,
            "src/types/slo_policy.rs",
            "tests/slo_policy_bundle_contract.rs",
            "SLO_POLICY_BUNDLE_SCHEMA_VERSION",
            "SLO_POLICY_COMPILER_SCHEMA_VERSION",
            "SLO_POLICY_PROOF_REPORT_SCHEMA_VERSION",
            "SLO_POLICY_RUNTIME_APPLICATION_SCHEMA_VERSION",
            "validate_slo_policy_bundle_json",
            "validate_slo_proof_report_json",
            "validate_slo_runtime_policy_application_json",
            artifact["compiler_schema_version"]
                .as_str()
                .expect("compiler schema"),
            artifact["runtime_application_schema_version"]
                .as_str()
                .expect("runtime application schema"),
            artifact["lab_replay_contract_version"]
                .as_str()
                .expect("lab replay contract"),
            artifact["proof_report_schema_version"]
                .as_str()
                .expect("proof report schema"),
            artifact["runtime_enforcement_report_schema_version"]
                .as_str()
                .expect("runtime enforcement report schema"),
            artifact["lab_brownout_e2e_contract_version"]
                .as_str()
                .expect("brownout e2e receipt schema"),
            "runtime_enforcement_status",
            "runtime_admission_status",
            "lab_replay_status",
            "receipt_status",
            "region_ids",
            "drain_completed_count",
            "finalizer_completed_count",
            "operator_interpretation",
            "proof_command_source",
            "redaction_policy_id",
            "--check-rch-log",
            "direct-main",
            "rch exec --",
            &gate_command,
        ] {
            assert!(section.contains(token), "{label} missing {token}");
        }

        for status in artifact["proof_report_statuses"]
            .as_array()
            .expect("proof report statuses")
            .iter()
            .map(|value| value.as_str().expect("proof status"))
        {
            assert!(section.contains(status), "{label} missing status {status}");
        }

        for status in artifact["runtime_enforcement_statuses"]
            .as_array()
            .expect("runtime enforcement statuses")
            .iter()
            .map(|value| value.as_str().expect("runtime enforcement status"))
        {
            assert!(
                section.contains(status),
                "{label} missing runtime enforcement status {status}"
            );
        }

        for rejected in [
            "Malformed reports",
            "stale profile hashes",
            "missing no-win receipts",
            "redaction failures",
            "secret-like material",
            "local `rch` fallback markers",
        ] {
            assert!(section.contains(rejected), "{label} missing {rejected}");
        }

        assert!(
            !section.contains("master"),
            "{label} SLO section must describe direct-main workflow without branch drift"
        );
        assert!(
            !section.contains("branch"),
            "{label} SLO section must not use unsupported branch workflow language"
        );
    }
}

#[test]
fn accepted_bundle_validates_and_fingerprint_is_stable() {
    let bundle = valid_bundle();
    let report = bundle.validate();
    assert!(report.accepted, "accepted report: {report:?}");
    assert!(report.issues.is_empty());

    let json = bundle.to_json().expect("bundle serializes");
    assert!(json.contains("\"workload_class\": \"agent_swarm\""));
    let reparsed = SloPolicyBundle::from_json(&json).expect("bundle reparses");
    assert_eq!(bundle.fingerprint(), reparsed.fingerprint());

    let report_from_json = validate_slo_policy_bundle_json(&json);
    assert!(
        report_from_json.accepted,
        "json report: {report_from_json:?}"
    );
    assert_eq!(report.fingerprint, report_from_json.fingerprint);
}

#[test]
fn compiler_output_id_and_budget_projection_are_stable() {
    let bundle = valid_bundle();
    let evidence = valid_capacity_evidence();
    let first = bundle.compile_for_budget_admission(Some(&evidence));
    let second = bundle.compile_for_budget_admission(Some(&evidence));

    assert_eq!(first.status, SloCompiledPolicyStatus::Compiled);
    assert!(first.is_executable());
    assert_eq!(first.output_id, second.output_id);
    assert_eq!(first.provenance.policy_fingerprint, bundle.fingerprint());
    assert_eq!(
        first.provenance.capacity_evidence_fingerprint,
        Some(evidence.fingerprint())
    );
    assert_eq!(first.budget.p999_latency_budget_ms, 120);
    assert_eq!(first.budget.cleanup_deadline_ms, 300);
    assert_eq!(first.budget.max_queue_wait_ms, 80);
    assert_eq!(first.budget.poll_quota, 1_200);
    assert_eq!(
        first.admission.decision,
        SloCompiledAdmissionDecision::Admit
    );

    let budget = first.budget.to_budget();
    assert_eq!(budget.deadline.expect("deadline").as_millis(), 300);
    assert_eq!(budget.poll_quota, 1_200);
    assert_eq!(budget.priority, 208);
}

#[test]
fn compiler_orders_optional_work_by_brownout_priority() {
    let mut bundle = valid_bundle();
    bundle.optional_work_classes[0].brownout_priority = 5;
    bundle.optional_work_classes[1].brownout_priority = 1;

    let compiled = bundle.compile_for_budget_admission(Some(&valid_capacity_evidence()));
    let ordered = compiled
        .brownout_order
        .iter()
        .map(|step| step.class_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ordered, vec!["analytics_rollup", "index_refresh"]);
}

#[test]
fn compiler_blocks_impossible_normalized_p999_objectives() {
    let mut bundle = valid_bundle();
    bundle.latency_objectives[0] = SloLatencyObjective {
        objective_id: "microsecond-cleanup".to_string(),
        unit: SloLatencyUnit::Microseconds,
        p50: 100_000,
        p95: 200_000,
        p99: 350_000,
        p999: 400_000,
    };

    let compiled = bundle.compile_for_budget_admission(Some(&valid_capacity_evidence()));
    assert_eq!(compiled.status, SloCompiledPolicyStatus::Blocked);
    assert!(!compiled.is_executable());
    assert!(
        compiled_blocker_tags(&compiled)
            .contains(SloPolicyCompilerBlockerKind::ImpossibleObjective.as_str())
    );
    assert_eq!(compiled.budget.p999_latency_budget_ms, 250);
}

#[test]
fn compiler_emits_no_win_fallback_when_capacity_exceeds_thresholds() {
    let bundle = valid_bundle();
    let mut evidence = valid_capacity_evidence();
    evidence.memory_basis_points = 9_500;

    let compiled = bundle.compile_for_budget_admission(Some(&evidence));
    assert_eq!(compiled.status, SloCompiledPolicyStatus::NoWin);
    assert_eq!(
        compiled.admission.decision,
        SloCompiledAdmissionDecision::NoWin
    );
    assert!(compiled.blockers.is_empty());
    let fallback = compiled.no_win_fallback.expect("no-win fallback receipt");
    assert_eq!(fallback.fallback_profile, "agent-swarm-safe-mode");
    assert_eq!(
        fallback.triggered_by,
        "capacity-evidence-exceeds-thresholds"
    );
    assert!(fallback.proof_command.contains("rch exec"));
}

#[test]
fn compiler_does_not_compare_work_queue_depth_to_timer_queue_depth() {
    let bundle = valid_bundle();
    let mut evidence = valid_capacity_evidence();
    evidence.queue_depth = bundle.resource_pressure.timer_queue_depth + 1;
    evidence.timer_queue_depth = bundle.resource_pressure.timer_queue_depth;
    evidence.memory_basis_points = bundle.resource_pressure.memory_basis_points;
    evidence.fd_basis_points = bundle.resource_pressure.fd_basis_points;

    let compiled = bundle.compile_for_budget_admission(Some(&evidence));
    assert_eq!(compiled.status, SloCompiledPolicyStatus::Compiled);
    assert_eq!(
        compiled.admission.decision,
        SloCompiledAdmissionDecision::Admit
    );
    assert!(compiled.no_win_fallback.is_none());

    let mut timer_evidence = evidence;
    timer_evidence.timer_queue_depth = bundle.resource_pressure.timer_queue_depth + 1;
    let timer_compiled = bundle.compile_for_budget_admission(Some(&timer_evidence));
    assert_eq!(timer_compiled.status, SloCompiledPolicyStatus::NoWin);
    assert!(timer_compiled.no_win_fallback.is_some());
}

#[test]
fn compiler_blocks_missing_evidence_and_conflicting_fallbacks() {
    let missing_evidence = valid_bundle().compile_for_budget_admission(None);
    assert_eq!(missing_evidence.status, SloCompiledPolicyStatus::Blocked);
    assert!(
        compiled_blocker_tags(&missing_evidence)
            .contains(SloPolicyCompilerBlockerKind::MissingCapacityEvidence.as_str())
    );

    let mut conflicting = valid_bundle();
    conflicting
        .no_win_fallback
        .as_mut()
        .expect("fallback")
        .proof_command = "cargo test -p asupersync".to_string();
    let compiled = conflicting.compile_for_budget_admission(Some(&valid_capacity_evidence()));
    assert_eq!(compiled.status, SloCompiledPolicyStatus::Blocked);
    assert!(
        compiled_blocker_tags(&compiled)
            .contains(SloPolicyCompilerBlockerKind::ConflictingFallbackDeclaration.as_str())
    );
}

#[test]
fn runtime_slo_policy_application_serializes_validates_and_renders_command() {
    let application = valid_runtime_application();
    let validation = application.validate();
    assert!(
        validation.accepted,
        "runtime application validation: {validation:?}"
    );
    assert_eq!(validation.decision, SloRuntimePolicyDecision::Admit);
    assert!(validation.issues.is_empty());
    assert_eq!(
        application.schema_version,
        SLO_POLICY_RUNTIME_APPLICATION_SCHEMA_VERSION
    );
    assert_eq!(
        application.compiler_schema_version,
        SLO_POLICY_COMPILER_SCHEMA_VERSION
    );
    assert_eq!(application.budget.to_budget().priority, 208);
    assert_eq!(
        application
            .optional_work_decisions
            .iter()
            .map(|work| work.decision)
            .collect::<Vec<_>>(),
        vec![
            SloRuntimeOptionalWorkDecision::Run,
            SloRuntimeOptionalWorkDecision::Run
        ]
    );

    let json = application
        .to_json()
        .expect("runtime application serializes");
    assert!(json.contains("\"schema_version\": \"slo-runtime-policy-application-v1\""));
    assert!(json.contains("\"decision\": \"admit\""));
    let reparsed =
        SloRuntimePolicyApplication::from_json(&json).expect("runtime application reparses");
    assert_eq!(application, reparsed);
    assert!(validate_slo_runtime_policy_application_json(&json).accepted);

    let command =
        SloRuntimePolicyApplication::render_application_proof_command("runtime_slo_policy");
    assert!(command.starts_with(
        "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_slo_runtime_application cargo test -p asupersync"
    ));
    assert!(!command.contains("rch exec -- cargo"));
    assert!(command.contains("--test slo_policy_bundle_contract"));
    assert!(command.contains("runtime_slo_policy"));
}

#[test]
fn runtime_slo_policy_application_preserves_brownout_and_no_win_decisions() {
    let mut brownout_compiled =
        valid_bundle().compile_for_budget_admission(Some(&valid_capacity_evidence()));
    brownout_compiled.admission.decision = SloCompiledAdmissionDecision::Brownout;
    let brownout = SloRuntimePolicyApplication::from_compiled_policy(
        &brownout_compiled,
        SloWorkloadClass::AgentSwarm,
        Some(profile_hash('a')),
        SloProofCommand {
            label: "runtime-slo-policy-application".to_string(),
            command: SloRuntimePolicyApplication::render_application_proof_command(
                "runtime_slo_policy_application",
            ),
        },
        SloPolicyRedaction {
            policy_id: "slo-runtime-application-redaction-v1".to_string(),
            passed: true,
        },
    );
    assert_eq!(brownout.decision, SloRuntimePolicyDecision::Brownout);
    assert!(brownout.validate().accepted);
    assert!(
        brownout
            .optional_work_decisions
            .iter()
            .all(|work| work.decision == SloRuntimeOptionalWorkDecision::Brownout)
    );

    let mut no_win_evidence = valid_capacity_evidence();
    no_win_evidence.memory_basis_points = 9_500;
    let no_win_compiled = valid_bundle().compile_for_budget_admission(Some(&no_win_evidence));
    let no_win = SloRuntimePolicyApplication::from_compiled_policy(
        &no_win_compiled,
        SloWorkloadClass::AgentSwarm,
        Some(profile_hash('a')),
        SloProofCommand {
            label: "runtime-slo-policy-application".to_string(),
            command: SloRuntimePolicyApplication::render_application_proof_command(
                "runtime_slo_policy_application",
            ),
        },
        SloPolicyRedaction {
            policy_id: "slo-runtime-application-redaction-v1".to_string(),
            passed: true,
        },
    );
    assert_eq!(no_win.decision, SloRuntimePolicyDecision::NoWin);
    assert_eq!(no_win.compiled_status, SloCompiledPolicyStatus::NoWin);
    assert!(no_win.no_win_fallback.is_some());
    assert!(no_win.validate().accepted);
}

#[test]
fn runtime_slo_policy_application_fail_closed_required_modes() {
    let mut stale = valid_runtime_application();
    stale.provenance.observed_profile_hash = Some(profile_hash('b'));
    let stale_validation = stale.validate();
    assert!(!stale_validation.accepted);
    assert!(
        stale_validation.contains_issue(SloRuntimePolicyApplicationIssueKind::StaleProfileHash)
    );

    let mut unsupported = valid_runtime_application();
    unsupported.workload_class = SloWorkloadClass::Unsupported("space_station".to_string());
    assert!(
        unsupported
            .validate()
            .contains_issue(SloRuntimePolicyApplicationIssueKind::UnsupportedWorkloadClass)
    );

    let mut missing_compiled = valid_runtime_application();
    missing_compiled.compiled_status = SloCompiledPolicyStatus::Blocked;
    missing_compiled.decision = SloRuntimePolicyDecision::Blocked;
    assert!(
        missing_compiled
            .validate()
            .contains_issue(SloRuntimePolicyApplicationIssueKind::MissingCompiledOutput)
    );
    let mut empty_output_id = valid_runtime_application();
    empty_output_id.compiled_output_id.clear();
    assert!(
        empty_output_id
            .validate()
            .contains_issue(SloRuntimePolicyApplicationIssueKind::MissingCompiledOutput)
    );

    let mut no_win_evidence = valid_capacity_evidence();
    no_win_evidence.memory_basis_points = 9_500;
    let no_win_compiled = valid_bundle().compile_for_budget_admission(Some(&no_win_evidence));
    let mut missing_no_win = SloRuntimePolicyApplication::from_compiled_policy(
        &no_win_compiled,
        SloWorkloadClass::AgentSwarm,
        Some(profile_hash('a')),
        SloProofCommand {
            label: "runtime-slo-policy-application".to_string(),
            command: SloRuntimePolicyApplication::render_application_proof_command(
                "runtime_slo_policy_application",
            ),
        },
        SloPolicyRedaction {
            policy_id: "slo-runtime-application-redaction-v1".to_string(),
            passed: true,
        },
    );
    missing_no_win.no_win_fallback = None;
    assert!(
        missing_no_win
            .validate()
            .contains_issue(SloRuntimePolicyApplicationIssueKind::MissingNoWinReceipt)
    );

    let mut missing_rch = valid_runtime_application();
    missing_rch.proof_command.command =
        "cargo test -p asupersync --test slo_policy_bundle_contract".to_string();
    assert!(
        missing_rch
            .validate()
            .contains_issue(SloRuntimePolicyApplicationIssueKind::MissingRchCommand)
    );
    let mut missing_target_dir = valid_runtime_application();
    missing_target_dir.proof_command.command =
        "rch exec -- cargo test -p asupersync --test slo_policy_bundle_contract".to_string();
    assert!(
        missing_target_dir
            .validate()
            .contains_issue(SloRuntimePolicyApplicationIssueKind::MissingRchCommand)
    );

    let mut redaction = valid_runtime_application();
    redaction.redaction.passed = false;
    redaction.metadata.insert(
        "api_token".to_string(),
        Value::String("sk-redacted-runtime".to_string()),
    );
    let redaction_validation = redaction.validate();
    assert!(
        redaction_validation.contains_issue(SloRuntimePolicyApplicationIssueKind::RedactionFailure)
    );
    assert!(
        redaction_validation
            .contains_issue(SloRuntimePolicyApplicationIssueKind::SecretLikeMaterial)
    );

    let malformed =
        validate_slo_runtime_policy_application_json("{\"schema_version\":\"slo-runtime\",");
    assert!(!malformed.accepted);
    assert!(malformed.contains_issue(SloRuntimePolicyApplicationIssueKind::MalformedApplication));
}

#[test]
fn runtime_slo_admission_evaluation_admits_core_work_with_policy_evidence() {
    let application = valid_runtime_application();
    let request = runtime_request("core-work", 4, None);
    let outcome = application.evaluate_admission(&request);

    assert_eq!(outcome.status, SloRuntimeAdmissionStatus::Admitted);
    assert_eq!(outcome.decision, SloRuntimePolicyDecision::Admit);
    assert_eq!(outcome.policy_id, "agent-swarm-standard");
    assert_eq!(outcome.workload_class, SloWorkloadClass::AgentSwarm);
    assert_eq!(outcome.profile_hash, profile_hash('a'));
    assert!(outcome.proof_command.contains("rch exec --"));
    assert_eq!(outcome.admitted_work_units, 4);
    assert_eq!(outcome.rejected_work_units, 0);
    assert!(outcome.issue_kinds.is_empty());
    assert_eq!(outcome.budget.cleanup_deadline_ms, 300);
}

#[test]
fn runtime_slo_admission_evaluation_rejects_hard_pressure() {
    let application = valid_runtime_application();

    let mut queue = runtime_request("queue-pressure", 4, None);
    queue.queue_wait_ms = application.admission.queue_wait_threshold_ms + 1;
    let queue_outcome = application.evaluate_admission(&queue);
    assert_eq!(queue_outcome.status, SloRuntimeAdmissionStatus::Rejected);
    assert_eq!(queue_outcome.admitted_work_units, 0);
    assert_eq!(queue_outcome.rejected_work_units, 4);
    assert_eq!(
        queue_outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::QueueWaitExceeded]
    );

    let mut memory = runtime_request("memory-pressure", 2, None);
    memory.memory_basis_points = application.admission.memory_hard_basis_points + 1;
    let memory_outcome = application.evaluate_admission(&memory);
    assert_eq!(memory_outcome.status, SloRuntimeAdmissionStatus::Rejected);
    assert_eq!(
        memory_outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::MemoryPressureExceeded]
    );
}

#[test]
fn runtime_slo_admission_evaluation_browns_out_optional_work() {
    let application = valid_runtime_application();
    let mut request = runtime_request("optional-index-refresh", 3, Some("index_refresh"));
    request.memory_basis_points = application.admission.memory_soft_basis_points;

    let outcome = application.evaluate_admission(&request);
    assert_eq!(outcome.status, SloRuntimeAdmissionStatus::Brownout);
    assert_eq!(
        outcome.optional_work_decision,
        Some(SloRuntimeOptionalWorkDecision::Brownout)
    );
    assert_eq!(
        outcome.optional_work_class.as_deref(),
        Some("index_refresh")
    );
    assert_eq!(outcome.admitted_work_units, 0);
    assert_eq!(outcome.rejected_work_units, 3);
    assert_eq!(
        outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::OptionalWorkBrownout]
    );

    let unsupported = runtime_request("unknown-optional", 1, Some("unknown_optional"));
    let unsupported_outcome = application.evaluate_admission(&unsupported);
    assert_eq!(
        unsupported_outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::UnsupportedOptionalWorkClass]
    );
}

#[test]
fn runtime_slo_admission_evaluation_routes_no_win_fallback() {
    let mut evidence = valid_capacity_evidence();
    evidence.memory_basis_points = 9_500;
    let compiled = valid_bundle().compile_for_budget_admission(Some(&evidence));
    let application = SloRuntimePolicyApplication::from_compiled_policy(
        &compiled,
        SloWorkloadClass::AgentSwarm,
        Some(profile_hash('a')),
        SloProofCommand {
            label: "runtime-slo-policy-application".to_string(),
            command: SloRuntimePolicyApplication::render_application_proof_command(
                "runtime_slo_policy_application",
            ),
        },
        SloPolicyRedaction {
            policy_id: "slo-runtime-application-redaction-v1".to_string(),
            passed: true,
        },
    );
    let request = runtime_request("no-win-core", 4, None);
    let outcome = application.evaluate_admission(&request);

    assert_eq!(outcome.status, SloRuntimeAdmissionStatus::NoWin);
    assert_eq!(outcome.decision, SloRuntimePolicyDecision::NoWin);
    assert_eq!(outcome.admitted_work_units, 0);
    assert_eq!(outcome.rejected_work_units, 4);
    assert_eq!(
        outcome.fallback_reason.as_deref(),
        Some("objectives-conflict-with-pressure")
    );
    assert_eq!(
        outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::NoWinFallback]
    );
}

#[test]
fn runtime_slo_admission_evaluation_blocks_stale_or_cancelled_requests() {
    let mut stale = valid_runtime_application();
    stale.provenance.observed_profile_hash = Some(profile_hash('b'));
    let stale_outcome = stale.evaluate_admission(&runtime_request("stale-policy", 2, None));
    assert_eq!(stale_outcome.status, SloRuntimeAdmissionStatus::Blocked);
    assert_eq!(stale_outcome.admitted_work_units, 0);
    assert_eq!(stale_outcome.rejected_work_units, 2);
    assert_eq!(
        stale_outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::ApplicationInvalid]
    );

    let application = valid_runtime_application();
    let mut cancelled = runtime_request("cancelled-before-admission", 2, None);
    cancelled.cancel_requested = true;
    let cancelled_outcome = application.evaluate_admission(&cancelled);
    assert_eq!(
        cancelled_outcome.status,
        SloRuntimeAdmissionStatus::Rejected
    );
    assert_eq!(cancelled_outcome.admitted_work_units, 0);
    assert_eq!(cancelled_outcome.rejected_work_units, 2);
    assert_eq!(
        cancelled_outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::Cancelled]
    );
}

#[test]
fn runtime_slo_admission_evaluation_reports_explicit_policy_reject() {
    let mut application = valid_runtime_application();
    application.decision = SloRuntimePolicyDecision::Reject;
    let outcome = application.evaluate_admission(&runtime_request("policy-reject", 2, None));

    assert_eq!(outcome.status, SloRuntimeAdmissionStatus::Rejected);
    assert_eq!(outcome.admitted_work_units, 0);
    assert_eq!(outcome.rejected_work_units, 2);
    assert_eq!(
        outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::PolicyRejected]
    );
}

#[test]
fn runtime_slo_policy_bridge_lab_smoke_covers_explicit_pressure_seams() {
    let application = valid_runtime_application();
    assert_eq!(application.policy_id, "agent-swarm-standard");
    let expected_priority = application.budget.to_budget().priority;
    let config = TestConfig::new()
        .with_seed(0x5100_0B03)
        .with_tracing(true)
        .with_max_steps(20_000);
    let mut runtime = LabRuntimeTarget::create_runtime(config);

    let decisions = LabRuntimeTarget::block_on(&mut runtime, async move {
        yield_now().await;
        let cx = Cx::for_testing();
        let bridge = SloRuntimePolicyBridge::new(&application);
        let required = bridge.evaluate(
            &cx,
            &SloRuntimePolicyBridgeRequest::required(runtime_request("bridge-required", 4, None)),
        );

        let mut optional = runtime_request("bridge-optional-brownout", 3, Some("index_refresh"));
        optional.memory_basis_points = application.admission.memory_soft_basis_points;
        let optional = bridge.evaluate(&cx, &SloRuntimePolicyBridgeRequest::optional(optional));

        let cleanup = bridge.evaluate(
            &cx,
            &SloRuntimePolicyBridgeRequest::cleanup_finalizer(runtime_request(
                "bridge-cleanup-finalizer",
                1,
                Some("index_refresh"),
            )),
        );

        let proof_reporting = bridge.evaluate(
            &cx,
            &SloRuntimePolicyBridgeRequest::proof_reporting(runtime_request(
                "bridge-proof-reporting",
                1,
                Some("analytics_rollup"),
            )),
        );

        vec![required, optional, cleanup, proof_reporting]
    });
    let report = runtime.run_until_quiescent_with_report();

    assert!(report.quiescent, "bridge lab smoke should quiesce");
    assert!(
        report.trace_len > 0,
        "bridge lab smoke should record deterministic trace events"
    );
    assert_eq!(
        decisions
            .iter()
            .map(|decision| decision.work_kind.as_str())
            .collect::<Vec<_>>(),
        vec![
            "required",
            "optional",
            "cleanup_finalizer",
            "proof_reporting"
        ]
    );

    let required = decision_for_kind(&decisions, SloRuntimeWorkKind::Required);
    assert_eq!(required.outcome.status, SloRuntimeAdmissionStatus::Admitted);
    assert!(required.work_may_start);
    assert_eq!(required.outcome.admitted_work_units, 4);

    let optional = decision_for_kind(&decisions, SloRuntimeWorkKind::Optional);
    assert_eq!(optional.outcome.status, SloRuntimeAdmissionStatus::Brownout);
    assert!(optional.optional_work_browned_out());
    assert!(!optional.work_may_start);
    assert!(optional.explicit_receipt_required);
    assert_eq!(
        optional.outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::OptionalWorkBrownout]
    );

    let cleanup = decision_for_kind(&decisions, SloRuntimeWorkKind::CleanupFinalizer);
    assert_eq!(cleanup.outcome.status, SloRuntimeAdmissionStatus::Admitted);
    assert!(cleanup.work_may_start);
    assert_eq!(cleanup.outcome.optional_work_class, None);
    assert_eq!(cleanup.runtime_budget.priority, expected_priority);

    let proof_reporting = decision_for_kind(&decisions, SloRuntimeWorkKind::ProofReporting);
    assert_eq!(
        proof_reporting.outcome.status,
        SloRuntimeAdmissionStatus::Admitted
    );
    assert!(proof_reporting.work_may_start);
    assert_eq!(proof_reporting.outcome.optional_work_class, None);

    for decision in decisions {
        assert!(decision.region_close_requires_quiescence);
    }
}

#[test]
fn runtime_slo_policy_bridge_observes_cx_cancellation_and_requires_receipts() {
    let application = valid_runtime_application();
    let bridge = SloRuntimePolicyBridge::new(&application);
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);

    let decision = bridge.evaluate(
        &cx,
        &runtime_bridge_request(
            "bridge-cancelled-before-admission",
            2,
            SloRuntimeWorkKind::Required,
            None,
        ),
    );

    assert!(decision.cx_cancel_observed);
    assert_eq!(decision.outcome.status, SloRuntimeAdmissionStatus::Rejected);
    assert!(!decision.work_may_start);
    assert!(decision.explicit_receipt_required);
    assert_eq!(decision.outcome.admitted_work_units, 0);
    assert_eq!(decision.outcome.rejected_work_units, 2);
    assert_eq!(
        decision.outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::Cancelled]
    );
}

#[test]
fn runtime_slo_policy_bridge_preserves_no_win_fallback_receipt() {
    let mut evidence = valid_capacity_evidence();
    evidence.memory_basis_points = 9_500;
    let compiled = valid_bundle().compile_for_budget_admission(Some(&evidence));
    let application = SloRuntimePolicyApplication::from_compiled_policy(
        &compiled,
        SloWorkloadClass::AgentSwarm,
        Some(profile_hash('a')),
        SloProofCommand {
            label: "runtime-slo-policy-bridge".to_string(),
            command: SLO_RUNTIME_BRIDGE_PROOF_COMMAND.to_string(),
        },
        SloPolicyRedaction {
            policy_id: "slo-runtime-bridge-redaction-v1".to_string(),
            passed: true,
        },
    );
    let bridge = SloRuntimePolicyBridge::new(&application);
    let cx = Cx::for_testing();

    let decision = bridge.evaluate(
        &cx,
        &runtime_bridge_request(
            "bridge-no-win-proof-reporting",
            1,
            SloRuntimeWorkKind::ProofReporting,
            None,
        ),
    );

    assert!(decision.no_win_fallback_selected());
    assert_eq!(decision.outcome.status, SloRuntimeAdmissionStatus::NoWin);
    assert!(!decision.work_may_start);
    assert!(decision.explicit_receipt_required);
    assert_eq!(
        decision.outcome.fallback_reason.as_deref(),
        Some("objectives-conflict-with-pressure")
    );
    assert_eq!(
        decision.outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::NoWinFallback]
    );
}

#[test]
fn runtime_slo_policy_bridge_fourth_wave_admits_required_work_explicitly() {
    let application = valid_runtime_application();
    let bridge = SloRuntimePolicyBridge::new(&application);
    let cx = Cx::for_testing();
    let receipt = fourth_wave_receipt(FourthWaveGovernorAction::AdmitRequiredWork, None);

    let decision = bridge.evaluate_fourth_wave(
        &cx,
        &runtime_bridge_request(
            "fourth-wave-admit-required",
            3,
            SloRuntimeWorkKind::Required,
            None,
        ),
        &receipt,
    );

    assert!(decision.opt_in_bridge_enabled);
    assert!(decision.work_may_start());
    assert_eq!(
        decision.runtime_decision.outcome.status,
        SloRuntimeAdmissionStatus::Admitted
    );
    assert_eq!(decision.runtime_decision.outcome.admitted_work_units, 3);
    assert_eq!(decision.rollback_reason, None);
    assert_eq!(decision.fourth_wave_decision_id, receipt.decision_id);
    assert_eq!(decision.fourth_wave_snapshot_id, receipt.snapshot_id);
    assert_eq!(decision.fourth_wave_rule_id, "admit-required-work");
    assert!(
        decision
            .non_claims
            .contains(&"not production-on-by-default")
    );
    assert_fourth_wave_bridge_invariants(&decision);
}

#[test]
fn runtime_slo_policy_bridge_fourth_wave_browns_out_optional_work_before_start() {
    let application = valid_runtime_application();
    let bridge = SloRuntimePolicyBridge::new(&application);
    let cx = Cx::for_testing();
    let receipt = fourth_wave_receipt(
        FourthWaveGovernorAction::BrownoutOptionalWork,
        Some("optional work exceeds memory pressure budget"),
    );

    let decision = bridge.evaluate_fourth_wave(
        &cx,
        &runtime_bridge_request(
            "fourth-wave-brownout-optional",
            5,
            SloRuntimeWorkKind::Optional,
            Some("index_refresh"),
        ),
        &receipt,
    );

    assert!(!decision.work_may_start());
    assert!(decision.rollback_required());
    assert!(decision.rollback_to_observe_only);
    assert_eq!(
        decision.runtime_decision.outcome.status,
        SloRuntimeAdmissionStatus::Brownout
    );
    assert_eq!(
        decision.runtime_decision.outcome.optional_work_decision,
        Some(SloRuntimeOptionalWorkDecision::Brownout)
    );
    assert_eq!(decision.runtime_decision.outcome.admitted_work_units, 0);
    assert_eq!(decision.runtime_decision.outcome.rejected_work_units, 5);
    assert_eq!(
        decision.runtime_decision.outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::OptionalWorkBrownout]
    );
    assert_eq!(
        decision.rollback_reason.as_deref(),
        Some("optional work exceeds memory pressure budget")
    );
    assert_fourth_wave_bridge_invariants(&decision);
}

#[test]
fn runtime_slo_policy_bridge_fourth_wave_defers_and_fails_closed_with_receipts() {
    let application = valid_runtime_application();
    let bridge = SloRuntimePolicyBridge::new(&application);
    let cx = Cx::for_testing();

    let deferred = bridge.evaluate_fourth_wave(
        &cx,
        &runtime_bridge_request(
            "fourth-wave-defer-no-worker",
            2,
            SloRuntimeWorkKind::ProofReporting,
            None,
        ),
        &fourth_wave_receipt(
            FourthWaveGovernorAction::DeferNoRemoteWorker,
            Some("remote-required lane has no admissible remote worker; local fallback refused"),
        ),
    );
    assert!(!deferred.work_may_start());
    assert!(deferred.delay_required);
    assert_eq!(
        deferred.runtime_decision.outcome.status,
        SloRuntimeAdmissionStatus::NoWin
    );
    assert_eq!(
        deferred.runtime_decision.outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::NoWinFallback]
    );
    assert_eq!(
        deferred.runtime_decision.outcome.fallback_reason.as_deref(),
        Some("remote-required lane has no admissible remote worker; local fallback refused")
    );
    assert_fourth_wave_bridge_invariants(&deferred);

    let blocked = bridge.evaluate_fourth_wave(
        &cx,
        &runtime_bridge_request(
            "fourth-wave-local-fallback",
            2,
            SloRuntimeWorkKind::Required,
            None,
        ),
        &fourth_wave_receipt(
            FourthWaveGovernorAction::FailClosedLocalRchFallback,
            Some("local RCH fallback marker detected"),
        ),
    );
    assert!(!blocked.work_may_start());
    assert!(blocked.fail_closed());
    assert!(blocked.rollback_to_observe_only);
    assert_eq!(
        blocked.runtime_decision.outcome.status,
        SloRuntimeAdmissionStatus::Blocked
    );
    assert_eq!(
        blocked.runtime_decision.outcome.issue_kinds,
        vec![SloRuntimeAdmissionIssueKind::ApplicationInvalid]
    );
    assert_eq!(
        blocked.rollback_reason.as_deref(),
        Some("local RCH fallback marker detected")
    );
    assert_fourth_wave_bridge_invariants(&blocked);
}

#[test]
fn runtime_slo_policy_bridge_fourth_wave_cancellation_preempts_control_and_redacts_receipts() {
    let application = valid_runtime_application();
    let bridge = SloRuntimePolicyBridge::new(&application);
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);

    for action in [
        FourthWaveGovernorAction::BrownoutOptionalWork,
        FourthWaveGovernorAction::DeferNoRemoteWorker,
    ] {
        let decision = bridge.evaluate_fourth_wave(
            &cx,
            &runtime_bridge_request(
                "fourth-wave-cancel-preempts-control",
                4,
                SloRuntimeWorkKind::Optional,
                Some("index_refresh"),
            ),
            &fourth_wave_receipt(action, Some("would otherwise alter runtime behavior")),
        );
        assert!(decision.runtime_decision.cx_cancel_observed);
        assert!(!decision.work_may_start());
        assert_eq!(
            decision.runtime_decision.outcome.status,
            SloRuntimeAdmissionStatus::Rejected
        );
        assert_eq!(
            decision.runtime_decision.outcome.issue_kinds,
            vec![SloRuntimeAdmissionIssueKind::Cancelled]
        );
        assert_eq!(
            decision.rollback_reason.as_deref(),
            Some("cx-cancelled-before-start")
        );
        assert_fourth_wave_bridge_invariants(&decision);
    }

    let uncancelled = Cx::for_testing();
    let redacted = bridge.evaluate_fourth_wave(
        &uncancelled,
        &runtime_bridge_request(
            "fourth-wave-redacted-fail-closed",
            1,
            SloRuntimeWorkKind::Required,
            None,
        ),
        &fourth_wave_receipt(
            FourthWaveGovernorAction::FailClosedMalformedInput,
            Some("Authorization: Bearer secret-token should never enter runtime receipts"),
        ),
    );
    assert_eq!(redacted.rollback_reason.as_deref(), Some("<redacted>"));
    let debug = format!("{redacted:?}").to_ascii_lowercase();
    assert!(!debug.contains("secret-token"));
    assert!(!debug.contains("authorization"));
    assert_fourth_wave_bridge_invariants(&redacted);
}

fn fourth_wave_receipt(
    selected_action: FourthWaveGovernorAction,
    non_action_reason: Option<&str>,
) -> FourthWaveGovernorDecisionReceipt {
    let action = selected_action.as_str();
    FourthWaveGovernorDecisionReceipt {
        schema_version: "asupersync.fourth-wave.governor-decision-receipt.v1",
        decision_id: format!("fw-governor-decision/runtime-bridge-{action}/policy-v1"),
        policy_version: "fourth-wave-governor-policy-v1".to_string(),
        snapshot_id: format!("fw-runtime-bridge-snapshot-{action}"),
        selected_action,
        non_action_reason: non_action_reason.unwrap_or_default().to_string(),
        fail_closed: selected_action.fail_closed(),
        rule_id: fourth_wave_rule_id(selected_action),
        confidence_bps: if selected_action.fail_closed() {
            0
        } else {
            8_400
        },
        input_artifact_hashes: vec![
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ],
        evidence_rows: vec!["runtime-bridge-evidence-row".to_string()],
        rejected_rows: Vec::new(),
        rejected_alternatives: Vec::<FourthWaveRejectedAlternative>::new(),
        objective_row: FourthWaveGovernorObjective::required("runtime-bridge-contract", 8_000),
        evidence_quality: FourthWaveEvidenceQuality {
            row_count: 7,
            required_input_classes_present: 7,
            min_confidence_bps: 8_400,
            max_evidence_age_seconds: 120,
            advisory_only_row_count: 0,
            replay_backed: true,
            local_fallback_marker_detected: selected_action
                == FourthWaveGovernorAction::FailClosedLocalRchFallback,
            dominant_pressure_class: non_action_reason.map(str::to_string),
        },
        log_fields: FourthWaveGovernorLogFields {
            bead_id: "asupersync-86fe9v.4".to_string(),
            scenario_id: "runtime-bridge-contract".to_string(),
            snapshot_id: format!("fw-runtime-bridge-snapshot-{action}"),
            decision_id: format!("fw-governor-decision/runtime-bridge-{action}/policy-v1"),
            policy_version: "fourth-wave-governor-policy-v1".to_string(),
            selected_action: action.to_string(),
            input_artifact_hashes:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            rejected_row_count: 0,
            first_rejected_row_reason: non_action_reason.unwrap_or_default().to_string(),
            objective_id: "runtime-bridge-contract".to_string(),
            workload_class: "required".to_string(),
            evidence_quality:
                "rows=7 required_present=7 min_confidence_bps=8400 max_age_seconds=120".to_string(),
        },
        non_claims: vec!["policy engine only", "local cargo fallback not authorized"],
    }
}

fn fourth_wave_rule_id(selected_action: FourthWaveGovernorAction) -> &'static str {
    match selected_action {
        FourthWaveGovernorAction::AdmitRequiredWork => "admit-required-work",
        FourthWaveGovernorAction::BrownoutOptionalWork => "brownout-optional-work",
        FourthWaveGovernorAction::DeferNoRemoteWorker => "remote-required-no-worker",
        FourthWaveGovernorAction::FailClosedAdvisoryOnly => "advisory-only-evidence",
        FourthWaveGovernorAction::FailClosedLocalRchFallback => "local-rch-fallback",
        FourthWaveGovernorAction::FailClosedMalformedInput => "malformed-input",
        FourthWaveGovernorAction::FailClosedMissingEvidence => "missing-required-evidence",
        FourthWaveGovernorAction::FailClosedStaleEvidence => "stale-evidence",
    }
}

fn assert_fourth_wave_bridge_invariants(decision: &FourthWaveRuntimeBridgeDecision) {
    assert!(decision.opt_in_bridge_enabled);
    assert!(decision.obligation_cleanup_required);
    assert!(decision.receipt_redaction_required);
    assert!(decision.runtime_decision.region_close_requires_quiescence);
    assert!(
        decision
            .non_claims
            .contains(&"explicit opt-in runtime bridge only")
    );
    assert!(
        decision
            .non_claims
            .contains(&"not production-on-by-default")
    );
    assert!(
        decision
            .non_claims
            .contains(&"obligation cleanup still required")
    );
    if !decision.work_may_start() {
        assert!(decision.explicit_receipt_required());
        assert_eq!(decision.runtime_decision.outcome.admitted_work_units, 0);
    }
}

fn decision_for_kind(
    decisions: &[SloRuntimePolicyBridgeDecision],
    work_kind: SloRuntimeWorkKind,
) -> &SloRuntimePolicyBridgeDecision {
    decisions
        .iter()
        .find(|decision| decision.work_kind == work_kind)
        .unwrap_or_else(|| panic!("missing bridge decision for {}", work_kind.as_str()))
}

#[test]
fn proof_report_serializes_validates_and_renders_rch_gate_command() {
    let report = valid_proof_report(SloProofReportStatus::Pass);
    let validation = report.validate();
    assert!(
        validation.accepted,
        "proof report validation: {validation:?}"
    );
    assert!(validation.success);
    assert!(validation.issues.is_empty());

    let json = report.to_json().expect("proof report serializes");
    assert!(json.contains("\"status\": \"pass\""));
    assert!(json.contains("\"proof_commands\""));
    let reparsed = SloProofReport::from_json(&json).expect("proof report reparses");
    assert_eq!(report, reparsed);

    let validation_from_json = validate_slo_proof_report_json(&json);
    assert!(validation_from_json.accepted);
    assert!(validation_from_json.success);
    let command =
        SloProofReport::render_ci_gate_command("target/slo-policy-bundle", "asupersync-bgtplc.4");
    assert!(command.starts_with("rch exec -- bash scripts/validate_slo_policy_bundle.sh"));
    assert!(command.contains("--run-id asupersync-bgtplc.4"));
}

#[test]
fn proof_report_fail_closed_required_issue_modes() {
    let mut missing_rch = valid_proof_report(SloProofReportStatus::Pass);
    missing_rch.proof_commands[0].command =
        "cargo test -p asupersync --test slo_policy_bundle_contract".to_string();
    assert!(
        missing_rch
            .validate()
            .contains_issue(SloProofReportIssueKind::MissingRchCommand)
    );
    let mut missing_target_dir = valid_proof_report(SloProofReportStatus::Pass);
    missing_target_dir.proof_commands[0].command =
        "rch exec -- cargo test -p asupersync --test slo_policy_bundle_contract".to_string();
    assert!(
        missing_target_dir
            .validate()
            .contains_issue(SloProofReportIssueKind::MissingRchCommand)
    );

    let stale = valid_proof_report(SloProofReportStatus::StaleEvidence);
    let stale_validation = stale.validate();
    assert!(!stale_validation.accepted);
    assert!(stale_validation.contains_issue(SloProofReportIssueKind::StaleProfileHash));

    let mut no_win_missing_receipt = valid_proof_report(SloProofReportStatus::NoWin);
    no_win_missing_receipt.no_win_receipt = None;
    assert!(
        no_win_missing_receipt
            .validate()
            .contains_issue(SloProofReportIssueKind::MissingNoWinReceipt)
    );

    let mut redaction = valid_proof_report(SloProofReportStatus::Pass);
    redaction.redaction.passed = false;
    redaction.metadata.insert(
        "api_token".to_string(),
        Value::String("sk-redacted-proof".to_string()),
    );
    let redaction_validation = redaction.validate();
    assert!(redaction_validation.contains_issue(SloProofReportIssueKind::RedactionFailure));
    assert!(redaction_validation.contains_issue(SloProofReportIssueKind::SecretLikeMaterial));

    let malformed = validate_slo_proof_report_json("{\"schema_version\":\"slo-proof-report-v1\",");
    assert!(!malformed.accepted);
    assert!(malformed.contains_issue(SloProofReportIssueKind::MalformedReport));
}

#[test]
fn proof_report_status_aggregation_preserves_non_success_states() {
    let reports = [
        valid_proof_report(SloProofReportStatus::Pass),
        valid_proof_report(SloProofReportStatus::Fail),
        valid_proof_report(SloProofReportStatus::Blocked),
        valid_proof_report(SloProofReportStatus::Degraded),
        valid_proof_report(SloProofReportStatus::NoWin),
        valid_proof_report(SloProofReportStatus::Unsupported),
        valid_proof_report(SloProofReportStatus::StaleEvidence),
    ];
    let counts = slo_proof_report_status_counts(&reports);
    assert_eq!(counts.total(), 7);
    assert_eq!(counts.pass, 1);
    assert_eq!(counts.fail, 1);
    assert_eq!(counts.blocked, 1);
    assert_eq!(counts.degraded, 1);
    assert_eq!(counts.no_win, 1);
    assert_eq!(counts.unsupported, 1);
    assert_eq!(counts.stale_evidence, 1);

    let degraded = valid_proof_report(SloProofReportStatus::Degraded).validate();
    assert!(degraded.accepted);
    assert!(!degraded.success, "degraded must not collapse into success");
    let no_win = valid_proof_report(SloProofReportStatus::NoWin).validate();
    assert!(no_win.accepted);
    assert!(!no_win.success, "no-win must not collapse into success");
}

#[test]
fn validation_rejects_required_failure_modes() {
    let mut non_monotonic = valid_bundle();
    non_monotonic.latency_objectives[0].p95 = 4;
    assert_issue(
        &non_monotonic.validate(),
        SloPolicyValidationIssueKind::NonMonotonicPercentile,
    );

    let mut missing_fallback = valid_bundle();
    missing_fallback.no_win_fallback = None;
    assert_issue(
        &missing_fallback.validate(),
        SloPolicyValidationIssueKind::MissingNoWinFallback,
    );

    let mut unsupported_version = valid_bundle();
    unsupported_version.schema_version = 99;
    assert_issue(
        &unsupported_version.validate(),
        SloPolicyValidationIssueKind::UnsupportedSchemaVersion,
    );

    let mut stale_profile = valid_bundle();
    stale_profile.provenance.observed_profile_hash = Some(profile_hash('b'));
    assert_issue(
        &stale_profile.validate(),
        SloPolicyValidationIssueKind::StaleProfileHash,
    );

    let mut uppercase_hash = valid_bundle();
    uppercase_hash.provenance.profile_hash = profile_hash('A');
    uppercase_hash.provenance.observed_profile_hash = Some(profile_hash('A'));
    assert_issue(
        &uppercase_hash.validate(),
        SloPolicyValidationIssueKind::StaleProfileHash,
    );

    let mut redaction_failure = valid_bundle();
    redaction_failure.redaction.passed = false;
    redaction_failure.metadata.insert(
        "api_token".to_string(),
        Value::String("sk-redacted".to_string()),
    );
    let redaction_report = redaction_failure.validate();
    assert_issue(
        &redaction_report,
        SloPolicyValidationIssueKind::RedactionFailure,
    );
    assert_issue(
        &redaction_report,
        SloPolicyValidationIssueKind::SecretLikeMaterial,
    );

    let mut external_path = valid_bundle();
    external_path.provenance.artifact_path = Some("/home/ubuntu/private/profile.json".to_string());
    assert_issue(
        &external_path.validate(),
        SloPolicyValidationIssueKind::ExternalPath,
    );

    let mut duplicate_objective = valid_bundle();
    duplicate_objective
        .latency_objectives
        .push(duplicate_objective.latency_objectives[0].clone());
    assert_issue(
        &duplicate_objective.validate(),
        SloPolicyValidationIssueKind::DuplicateObjective,
    );

    let mut unsupported_vocab = serde_json::to_value(valid_bundle()).expect("bundle to value");
    unsupported_vocab["workload_class"] = json!("space_station");
    unsupported_vocab["latency_objectives"][0]["unit"] = json!("fortnights");
    let unsupported_bundle: SloPolicyBundle =
        serde_json::from_value(unsupported_vocab).expect("unsupported tags are preserved");
    let unsupported_report = unsupported_bundle.validate();
    assert_issue(
        &unsupported_report,
        SloPolicyValidationIssueKind::UnsupportedWorkloadClass,
    );
    assert_issue(
        &unsupported_report,
        SloPolicyValidationIssueKind::InvalidUnit,
    );
}

#[test]
fn json_validation_rejects_malformed_document() {
    let report = validate_slo_policy_bundle_json("{\"schema_version\":1,");
    assert!(!report.accepted);
    assert_issue(&report, SloPolicyValidationIssueKind::MalformedJson);
}

#[test]
fn contract_scenarios_match_rust_validator() {
    let artifact = contract();
    for scenario_value in artifact["scenarios"].as_array().expect("scenarios") {
        let report = if scenario_value["scenario_id"].as_str() == Some("malformed-json") {
            let document = scenario_value["fixture_document"]
                .as_str()
                .expect("malformed fixture document");
            validate_slo_policy_bundle_json(document)
        } else {
            let bundle: SloPolicyBundle = serde_json::from_value(scenario_value["bundle"].clone())
                .unwrap_or_else(|error| panic!("scenario bundle parses: {error}"));
            bundle.validate()
        };
        let expected_accepted = scenario_value["expected"]["accepted"]
            .as_bool()
            .expect("expected accepted flag");
        assert_eq!(
            report.accepted, expected_accepted,
            "scenario {}",
            scenario_value["scenario_id"]
        );
        assert_eq!(
            issue_tags(&report),
            expected_issue_tags(scenario_value),
            "scenario {}",
            scenario_value["scenario_id"]
        );
    }
    assert_eq!(
        scenario(&artifact, "accepted-agent-swarm")["expected"]["accepted"].as_bool(),
        Some(true)
    );
}

#[test]
fn compiler_scenarios_match_rust_compiler() {
    let artifact = contract();
    let compiler_scenarios = artifact["compiler_scenarios"]
        .as_array()
        .expect("compiler scenarios");

    for compiler_scenario in compiler_scenarios {
        let bundle_scenario_id = compiler_scenario["bundle_scenario_id"]
            .as_str()
            .expect("bundle scenario id");
        let bundle: SloPolicyBundle =
            serde_json::from_value(scenario(&artifact, bundle_scenario_id)["bundle"].clone())
                .unwrap_or_else(|error| panic!("compiler scenario bundle parses: {error}"));
        let evidence = if compiler_scenario["capacity_evidence"].is_null() {
            None
        } else {
            Some(
                serde_json::from_value::<SloPolicyCapacityEvidence>(
                    compiler_scenario["capacity_evidence"].clone(),
                )
                .unwrap_or_else(|error| panic!("capacity evidence parses: {error}")),
            )
        };
        let compiled = bundle.compile_for_budget_admission(evidence.as_ref());
        let expected = &compiler_scenario["expected"];
        assert_eq!(
            compiled.status.as_str(),
            expected["status"].as_str().expect("expected status"),
            "compiler scenario {}",
            compiler_scenario["scenario_id"]
        );
        let expected_blockers = expected["blocker_kinds"]
            .as_array()
            .expect("blocker kinds")
            .iter()
            .map(|value| value.as_str().expect("blocker kind").to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            compiled_blocker_tags(&compiled),
            expected_blockers,
            "compiler scenario {}",
            compiler_scenario["scenario_id"]
        );
        assert_eq!(
            compiled.no_win_fallback.is_some(),
            expected["no_win_fallback"]
                .as_bool()
                .expect("no-win fallback flag"),
            "compiler scenario {}",
            compiler_scenario["scenario_id"]
        );
    }
}

#[test]
fn lab_runtime_slo_policy_replay_fixtures_cover_required_outcomes() {
    let mut evidence_by_id = BTreeMap::new();
    for fixture in lab_replay_fixtures() {
        let first = evaluate_lab_replay_fixture(fixture.clone());
        let second = evaluate_lab_replay_fixture(fixture);
        assert_eq!(first, second, "LabRuntime replay must be deterministic");
        assert!(
            first.oracle_violations.is_empty(),
            "lab replay leaves runtime oracles clean: {:?}",
            first.oracle_violations
        );
        assert!(first.proof_command.contains("rch exec"));
        let json = first.to_json();
        assert_eq!(json["scenario_id"], first.scenario_id);
        assert_eq!(json["replay_status"], first.replay_status);
        assert_eq!(json["lab_seed"], first.lab_seed);
        assert_eq!(first.receipt.receipt_status, "green");
        assert!(first.receipt.final_quiescent);
        assert!(
            first
                .receipt
                .region_ids
                .iter()
                .all(|region| !region.is_empty()),
            "receipt carries region ids"
        );
        assert!(
            first.receipt.validation_issues().is_empty(),
            "green receipt validates for {}: {:?}",
            first.scenario_id,
            first.receipt.validation_issues()
        );
        evidence_by_id.insert(first.scenario_id.clone(), first);
    }

    assert_eq!(
        evidence_by_id["lab-replay-normal-load"].replay_status,
        "passed"
    );
    assert_eq!(
        evidence_by_id["lab-replay-normal-load"].admitted_work_units,
        4
    );
    assert_eq!(
        evidence_by_id["lab-replay-overload"].replay_status,
        "rejected"
    );
    assert_eq!(evidence_by_id["lab-replay-overload"].admitted_work_units, 0);
    assert_eq!(
        evidence_by_id["lab-replay-overload"].rejected_work_units,
        12
    );
    assert_eq!(
        evidence_by_id["lab-replay-overload"].issue_kinds,
        vec!["queue_wait_exceeded".to_string()]
    );
    assert_eq!(
        evidence_by_id["lab-replay-cleanup-deadline-pressure"].cleanup_deadline_misses,
        1
    );
    assert_eq!(
        evidence_by_id["lab-replay-optional-brownout"].replay_status,
        "brownout"
    );
    assert_eq!(
        evidence_by_id["lab-replay-optional-brownout"].optional_work_units_browned_out,
        3
    );
    assert_eq!(
        evidence_by_id["lab-replay-optional-brownout"].rejected_work_units,
        3
    );
    assert_eq!(
        evidence_by_id["lab-replay-optional-brownout"].issue_kinds,
        vec!["optional_work_brownout".to_string()]
    );
    assert_eq!(
        evidence_by_id["lab-replay-no-win-fallback"].replay_status,
        "no_win"
    );
    assert_eq!(
        evidence_by_id["lab-replay-no-win-fallback"]
            .fallback_reason
            .as_deref(),
        Some("objectives-conflict-with-pressure")
    );
    assert_eq!(
        evidence_by_id["lab-replay-no-win-fallback"].issue_kinds,
        vec!["no_win_fallback".to_string()]
    );
    assert_eq!(
        evidence_by_id["lab-replay-stale-profile-hash"].replay_status,
        "stale_evidence"
    );
    assert_eq!(
        evidence_by_id["lab-replay-stale-profile-hash"].issue_kinds,
        vec![
            "application_invalid".to_string(),
            "stale_profile_hash".to_string()
        ]
    );
    assert_eq!(
        evidence_by_id["lab-replay-cancelled-admission"].replay_status,
        "cancelled"
    );
    assert_eq!(
        evidence_by_id["lab-replay-cancelled-admission"].issue_kinds,
        vec!["cancelled".to_string()]
    );
    assert_eq!(
        evidence_by_id["lab-replay-cancel-mid-brownout"].replay_status,
        "cancelled"
    );
    assert_eq!(
        evidence_by_id["lab-replay-cancel-mid-brownout"].issue_kinds,
        vec![
            "cancelled".to_string(),
            "optional_work_brownout".to_string()
        ]
    );
    assert_eq!(
        evidence_by_id["lab-replay-cancel-mid-brownout"]
            .receipt
            .cancellation_observed_count,
        1
    );
    assert_eq!(
        evidence_by_id["lab-replay-recovery-after-pressure-clears"].replay_status,
        "brownout"
    );
    assert_eq!(
        evidence_by_id["lab-replay-recovery-after-pressure-clears"].admitted_work_units,
        6
    );
    assert_eq!(
        evidence_by_id["lab-replay-recovery-after-pressure-clears"]
            .receipt
            .task_counts
            .completed,
        8
    );
    assert_eq!(
        evidence_by_id["lab-replay-malformed-policy"].issue_kinds,
        vec!["malformed_json".to_string()]
    );
}

#[test]
fn runtime_slo_brownout_lab_e2e_receipts_validate_structured_concurrency_evidence() {
    let evidence_by_id = lab_replay_fixtures()
        .into_iter()
        .map(evaluate_lab_replay_fixture)
        .map(|evidence| (evidence.scenario_id.clone(), evidence))
        .collect::<BTreeMap<_, _>>();

    for scenario_id in [
        "lab-replay-normal-load",
        "lab-replay-optional-brownout",
        "lab-replay-no-win-fallback",
        "lab-replay-cancel-mid-brownout",
        "lab-replay-recovery-after-pressure-clears",
    ] {
        let receipt = &evidence_by_id
            .get(scenario_id)
            .unwrap_or_else(|| panic!("missing receipt for {scenario_id}"))
            .receipt;
        assert_eq!(
            receipt.schema_version,
            SLO_BROWNOUT_E2E_RECEIPT_SCHEMA_VERSION
        );
        assert_eq!(receipt.receipt_status, "green", "scenario {scenario_id}");
        assert_eq!(
            receipt.obligation_state, "resolved",
            "scenario {scenario_id}"
        );
        assert!(receipt.final_quiescent, "scenario {scenario_id} quiesced");
        assert!(
            receipt.runtime_invariant_violations.is_empty(),
            "scenario {scenario_id} runtime invariant violations"
        );
        assert!(
            receipt.oracle_violations.is_empty(),
            "scenario {scenario_id} oracle violations"
        );
        assert!(
            receipt.task_counts.completed >= receipt.task_counts.admitted,
            "scenario {scenario_id} task completion evidence"
        );
        assert!(
            receipt.drain_completed_count >= receipt.drain_requested_count,
            "scenario {scenario_id} drain evidence"
        );
        assert!(
            receipt.finalizer_completed_count >= receipt.finalizer_expected_count,
            "scenario {scenario_id} finalizer evidence"
        );
        assert!(
            !receipt.operator_interpretation.is_empty(),
            "scenario {scenario_id} operator interpretation"
        );
        assert_eq!(receipt.validation_issues(), BTreeSet::new());
    }

    let brownout = &evidence_by_id["lab-replay-optional-brownout"].receipt;
    assert_eq!(brownout.pressure_transition, "steady");
    assert_eq!(brownout.task_counts.browned_out, 3);
    assert_eq!(brownout.drain_completed_count, 3);

    let cancelled = &evidence_by_id["lab-replay-cancel-mid-brownout"].receipt;
    assert_eq!(cancelled.pressure_transition, "cancel_mid_brownout");
    assert_eq!(cancelled.cancellation_requested_count, 1);
    assert_eq!(cancelled.cancellation_observed_count, 1);
    assert_eq!(cancelled.task_counts.cancelled, 3);

    let recovery = &evidence_by_id["lab-replay-recovery-after-pressure-clears"].receipt;
    assert_eq!(
        recovery.pressure_transition,
        "recovery_after_pressure_clears"
    );
    assert_eq!(recovery.task_counts.requested, 8);
    assert_eq!(recovery.task_counts.admitted, 6);
    assert_eq!(recovery.task_counts.rejected, 2);
}

#[test]
fn lab_brownout_e2e_artifact_scenarios_match_rust_receipts() {
    let artifact = contract();
    let evidence_by_id = lab_replay_fixtures()
        .into_iter()
        .map(evaluate_lab_replay_fixture)
        .map(|evidence| (evidence.scenario_id.clone(), evidence))
        .collect::<BTreeMap<_, _>>();

    for scenario in artifact["lab_brownout_e2e_scenarios"]
        .as_array()
        .expect("brownout e2e scenarios")
    {
        let scenario_id = scenario["scenario_id"]
            .as_str()
            .expect("scenario id is string");
        let receipt = &evidence_by_id
            .get(scenario_id)
            .unwrap_or_else(|| panic!("missing rust receipt {scenario_id}"))
            .receipt;
        let expected = &scenario["expected"];
        assert_eq!(
            receipt.receipt_status,
            expected["receipt_status"].as_str().expect("receipt status"),
            "scenario {scenario_id}"
        );
        assert_eq!(
            receipt.pressure_transition,
            expected["pressure_transition"]
                .as_str()
                .expect("pressure transition"),
            "scenario {scenario_id}"
        );
        assert_eq!(
            receipt.task_counts.to_json(),
            expected["task_counts"],
            "scenario {scenario_id}"
        );
        assert_eq!(
            receipt.drain_completed_count,
            expected["drain_completed_count"]
                .as_u64()
                .expect("drain completed"),
            "scenario {scenario_id}"
        );
        assert_eq!(
            receipt.finalizer_completed_count,
            expected["finalizer_completed_count"]
                .as_u64()
                .expect("finalizer completed"),
            "scenario {scenario_id}"
        );
        assert_eq!(
            receipt.validation_issues(),
            BTreeSet::new(),
            "scenario {scenario_id}"
        );
    }
}

#[test]
fn runtime_slo_brownout_lab_e2e_red_receipts_fail_closed_for_missing_drain_or_finalizer() {
    let good_receipt = evaluate_lab_replay_fixture(
        lab_replay_fixtures()
            .into_iter()
            .find(|fixture| fixture.scenario_id == "lab-replay-optional-brownout")
            .expect("brownout fixture"),
    )
    .receipt;

    let mut missing_drain = good_receipt.to_json();
    missing_drain["scenario_id"] = json!("red-missing-drain-evidence");
    missing_drain["drain_completed_count"] = json!(0);
    let drain_issues = validate_slo_brownout_e2e_receipt_json(&missing_drain);
    assert!(drain_issues.contains("missing_drain_evidence"));

    let mut missing_finalizer = good_receipt.to_json();
    missing_finalizer["scenario_id"] = json!("red-missing-finalizer-evidence");
    missing_finalizer["finalizer_completed_count"] = json!(0);
    let finalizer_issues = validate_slo_brownout_e2e_receipt_json(&missing_finalizer);
    assert!(finalizer_issues.contains("missing_finalizer_evidence"));

    let artifact = contract();
    for fixture in artifact["lab_brownout_e2e_failure_receipts"]
        .as_array()
        .expect("red receipt fixtures")
    {
        let expected_issues = fixture["expected"]["issue_kinds"]
            .as_array()
            .expect("expected issue kinds")
            .iter()
            .map(|issue| issue.as_str().expect("issue").to_string())
            .collect::<BTreeSet<_>>();
        let issues = validate_slo_brownout_e2e_receipt_json(&fixture["receipt"]);
        assert_eq!(issues, expected_issues, "red receipt fixture {fixture:?}");
    }
}

#[test]
fn lab_replay_artifact_scenarios_match_rust_replay() {
    let artifact = contract();
    let mut evidence_by_id = BTreeMap::new();
    for fixture in lab_replay_fixtures() {
        let evidence = evaluate_lab_replay_fixture(fixture);
        evidence_by_id.insert(evidence.scenario_id.clone(), evidence);
    }

    for scenario in artifact["lab_replay_scenarios"]
        .as_array()
        .expect("lab replay scenarios")
    {
        let scenario_id = scenario["scenario_id"]
            .as_str()
            .expect("scenario id is string");
        let evidence = evidence_by_id
            .get(scenario_id)
            .unwrap_or_else(|| panic!("missing rust replay fixture {scenario_id}"));
        let expected = &scenario["expected"];
        assert_eq!(
            evidence.replay_status,
            expected["replay_status"]
                .as_str()
                .expect("expected replay status"),
            "scenario {scenario_id}"
        );
        assert_eq!(
            evidence.admitted_work_units,
            expected["admitted_work_units"]
                .as_u64()
                .expect("expected admitted units"),
            "scenario {scenario_id}"
        );
        assert_eq!(
            evidence.rejected_work_units,
            expected["rejected_work_units"]
                .as_u64()
                .expect("expected rejected units"),
            "scenario {scenario_id}"
        );
        assert_eq!(
            evidence.optional_work_units_browned_out,
            expected["optional_work_units_browned_out"]
                .as_u64()
                .expect("expected optional brownout units"),
            "scenario {scenario_id}"
        );
        assert_eq!(
            evidence.cleanup_deadline_misses,
            expected["cleanup_deadline_misses"]
                .as_u64()
                .expect("expected cleanup misses"),
            "scenario {scenario_id}"
        );
        assert_eq!(
            evidence.issue_kinds,
            expected["issue_kinds"]
                .as_array()
                .expect("expected issue kinds")
                .iter()
                .map(|value| value.as_str().expect("issue kind").to_string())
                .collect::<Vec<_>>(),
            "scenario {scenario_id}"
        );
    }
}

#[test]
fn proof_report_artifact_scenarios_match_rust_gate() {
    let artifact = contract();
    let mut statuses_seen = BTreeSet::new();
    for scenario in artifact["proof_report_scenarios"]
        .as_array()
        .expect("proof report scenarios")
    {
        let scenario_id = scenario["scenario_id"].as_str().expect("scenario id");
        let validation = if let Some(document) = scenario["fixture_document"].as_str() {
            validate_slo_proof_report_json(document)
        } else {
            let report: SloProofReport = serde_json::from_value(scenario["report"].clone())
                .unwrap_or_else(|error| panic!("proof report scenario parses: {error}"));
            let expected_report_issues = scenario["expected"]["issue_kinds"]
                .as_array()
                .expect("expected proof issues")
                .iter()
                .map(|value| value.as_str().expect("proof issue").to_string())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                proof_report_issue_set(&report),
                expected_report_issues,
                "proof report issue set for {scenario_id}"
            );
            report.validate()
        };
        let expected = &scenario["expected"];
        statuses_seen.insert(
            expected["status"]
                .as_str()
                .expect("expected status")
                .to_string(),
        );
        assert_eq!(
            validation.status.as_str(),
            expected["status"].as_str().expect("expected status"),
            "scenario {scenario_id}"
        );
        assert_eq!(
            validation.accepted,
            expected["accepted"].as_bool().expect("expected accepted"),
            "scenario {scenario_id}"
        );
        assert_eq!(
            validation.success,
            expected["success"].as_bool().expect("expected success"),
            "scenario {scenario_id}"
        );
        let issues = validation
            .issues
            .iter()
            .map(|issue| issue.kind.as_str().to_string())
            .collect::<BTreeSet<_>>();
        let expected_issues = expected["issue_kinds"]
            .as_array()
            .expect("expected issue kinds")
            .iter()
            .map(|value| value.as_str().expect("issue kind").to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(issues, expected_issues, "scenario {scenario_id}");
    }
    assert_eq!(statuses_seen, proof_report_status_tags());
}

#[test]
fn runtime_enforcement_artifact_scenarios_cover_runner_contract() {
    let artifact = contract();
    let allowed_issues = runtime_enforcement_issue_tags();
    let mut statuses_seen = BTreeSet::new();
    let scenarios = artifact["runtime_enforcement_scenarios"]
        .as_array()
        .expect("runtime enforcement scenarios");
    for scenario in scenarios {
        let scenario_id = scenario["scenario_id"]
            .as_str()
            .expect("scenario id is string");
        let expected = &scenario["expected"];
        let status = expected["status"]
            .as_str()
            .expect("runtime enforcement status");
        statuses_seen.insert(status.to_string());
        assert!(
            runtime_enforcement_status_tags().contains(status),
            "scenario {scenario_id} has known status"
        );
        assert!(
            scenario["proof_command"]
                .as_str()
                .expect("proof command")
                .contains("rch exec"),
            "scenario {scenario_id} keeps rch provenance"
        );
        assert_eq!(
            scenario["redaction"]["passed"].as_bool(),
            Some(true),
            "scenario {scenario_id} redaction gate"
        );
        let issues = expected["issue_kinds"]
            .as_array()
            .expect("issue kinds")
            .iter()
            .map(|value| value.as_str().expect("issue kind").to_string())
            .collect::<BTreeSet<_>>();
        assert!(
            issues.is_subset(&allowed_issues),
            "scenario {scenario_id} issue set {issues:?}"
        );
        if status == "no_win" {
            assert_eq!(
                expected["fallback_reason"].as_str(),
                Some("objectives-conflict-with-pressure"),
                "scenario {scenario_id} no-win receipt"
            );
        }
        if status == "stale_evidence" {
            assert!(
                issues.contains("stale_profile_hash"),
                "scenario {scenario_id} stale evidence is explicit"
            );
        }
        if status == "malformed" {
            assert!(
                issues.contains("malformed_report"),
                "scenario {scenario_id} malformed report is explicit"
            );
        }
    }
    assert_eq!(statuses_seen, runtime_enforcement_status_tags());

    let required_fields = artifact["runtime_enforcement_contract"]["required_event_fields"]
        .as_array()
        .expect("runtime enforcement required event fields")
        .iter()
        .map(|value| value.as_str().expect("field").to_string())
        .collect::<BTreeSet<_>>();
    for field in [
        "runtime_enforcement_status",
        "runtime_admission_status",
        "lab_replay_status",
        "proof_command",
        "proof_command_source",
        "redaction_policy_id",
    ] {
        assert!(required_fields.contains(field), "required field {field}");
    }
}

#[test]
fn script_emits_accepted_rejected_and_malformed_rows() {
    let output_root = "target/slo-policy-bundle-contract-test";
    let run_id = "script-emits";
    let status = Command::new("bash")
        .args([
            SCRIPT_PATH,
            "--output-root",
            output_root,
            "--run-id",
            run_id,
        ])
        .status()
        .expect("run SLO policy validator script");
    assert!(status.success(), "script status: {status:?}");

    let log_path = format!("{output_root}/{run_id}/slo-policy-bundle-events.ndjson");
    let report_path = format!("{output_root}/{run_id}/slo-policy-bundle-run.json");
    let rows = std::fs::read_to_string(&log_path).expect("script event log");
    let markdown_path = format!("{output_root}/{run_id}/slo-policy-bundle-run.md");
    let detail_log_path = format!("{output_root}/{run_id}/slo-brownout-e2e-detail.log");
    let markdown = std::fs::read_to_string(&markdown_path).expect("script markdown report");
    let detail_log = std::fs::read_to_string(&detail_log_path).expect("script detail log");
    let report = json_file(&report_path);
    let events = rows
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event row parses"))
        .collect::<Vec<_>>();

    let second_status = Command::new("bash")
        .args([
            SCRIPT_PATH,
            "--output-root",
            output_root,
            "--run-id",
            run_id,
        ])
        .status()
        .expect("rerun SLO policy validator script");
    assert!(
        second_status.success(),
        "second script status: {second_status:?}"
    );
    assert_eq!(
        rows,
        std::fs::read_to_string(&log_path).expect("second event log"),
        "JSONL output stays stable across repeated runs"
    );
    assert_eq!(
        markdown,
        std::fs::read_to_string(&markdown_path).expect("second markdown report"),
        "Markdown output stays stable across repeated runs"
    );
    assert_eq!(
        detail_log,
        std::fs::read_to_string(&detail_log_path).expect("second detail log"),
        "detail log output stays stable across repeated runs"
    );

    assert!(events.iter().any(|event| event["accepted"] == true));
    assert!(events.iter().any(|event| event["accepted"] == false));
    assert!(events.iter().any(|event| {
        event["issue_kinds"]
            .as_array()
            .expect("issue kinds")
            .iter()
            .any(|kind| kind.as_str() == Some("malformed_json"))
    }));
    assert!(
        events
            .iter()
            .any(|event| event["lab_replay_status"] == "passed")
    );
    assert!(
        events
            .iter()
            .any(|event| event["lab_replay_status"] == "no_win")
    );
    assert!(
        events
            .iter()
            .any(|event| event["proof_report_status"] == "pass")
    );
    assert!(
        events
            .iter()
            .any(|event| event["proof_report_status"] == "no_win")
    );
    assert!(
        events
            .iter()
            .any(|event| event["runtime_enforcement_status"] == "pass")
    );
    assert!(
        events
            .iter()
            .any(|event| event["runtime_enforcement_status"] == "degraded")
    );
    assert!(
        events
            .iter()
            .any(|event| event["runtime_enforcement_status"] == "no_win")
    );
    assert!(
        events
            .iter()
            .any(|event| event["runtime_enforcement_status"] == "blocked")
    );
    assert!(
        events
            .iter()
            .any(|event| event["runtime_enforcement_status"] == "stale_evidence")
    );
    assert!(
        events
            .iter()
            .any(|event| event["runtime_enforcement_status"] == "unsupported")
    );
    assert!(
        events
            .iter()
            .any(|event| event["runtime_enforcement_status"] == "malformed")
    );
    assert!(
        events.iter().any(|event| {
            event["issue_kinds"]
                .as_array()
                .expect("issue kinds")
                .iter()
                .any(|kind| kind.as_str() == Some("local_rch_fallback"))
        }),
        "runtime enforcement report records local-rch-fallback rejection"
    );
    assert!(
        events
            .iter()
            .any(|event| event["receipt_status"] == "green")
    );
    assert!(
        events
            .iter()
            .any(|event| event["scenario_id"] == "red-missing-drain-evidence")
    );
    assert!(markdown.contains("slo-lab-brownout-e2e-receipt-v1"));
    assert!(detail_log.contains("lab-replay-cancel-mid-brownout"));
    assert!(detail_log.contains("final_quiescent=true"));
    assert_eq!(
        report["runtime_enforcement_count"].as_u64(),
        Some(runtime_enforcement_status_tags().len() as u64 + 1),
        "runtime enforcement report count includes local fallback scenario"
    );
    assert_eq!(
        report["lab_brownout_e2e_count"].as_u64(),
        Some(5),
        "brownout e2e report count"
    );
    assert_eq!(
        report["markdown_report"].as_str(),
        Some(markdown_path.as_str()),
        "report links markdown output"
    );
    assert_eq!(
        report["detail_log"].as_str(),
        Some(detail_log_path.as_str()),
        "report links deterministic detail log"
    );

    let input_status = Command::new("bash")
        .args([SCRIPT_PATH, "--input-jsonl", &log_path])
        .status()
        .expect("validate generated JSONL");
    assert!(
        input_status.success(),
        "input jsonl status: {input_status:?}"
    );
}

#[test]
fn script_rejects_local_rch_fallback_marker() {
    let output_root = "target/slo-policy-bundle-contract-test";
    let run_id = "script-local-rch-fallback";
    let log_path = format!("{output_root}/{run_id}/rch.log");
    std::fs::create_dir_all(format!("{output_root}/{run_id}")).expect("create output root");
    std::fs::write(&log_path, "remote unavailable; executing locally\n")
        .expect("write local fallback log");

    let status = Command::new("bash")
        .args([
            SCRIPT_PATH,
            "--output-root",
            output_root,
            "--run-id",
            run_id,
            "--check-rch-log",
            &log_path,
        ])
        .status()
        .expect("run local fallback validation");
    assert_eq!(status.code(), Some(86), "local fallback must fail closed");
}

#[test]
fn script_rejects_malformed_jsonl_input() {
    let output_root = "target/slo-policy-bundle-contract-test";
    std::fs::create_dir_all(output_root).expect("create output root");
    let path = format!("{output_root}/malformed.ndjson");
    std::fs::write(&path, "{not-json\n").expect("write malformed JSONL fixture");

    let status = Command::new("bash")
        .args([SCRIPT_PATH, "--input-jsonl", &path])
        .status()
        .expect("run malformed JSONL validation");
    assert!(!status.success(), "malformed input must fail closed");
}
