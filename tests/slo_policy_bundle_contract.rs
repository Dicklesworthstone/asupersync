//! Contract tests for operator SLO policy bundles.

use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::runtime::yield_now;
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

fn text_file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn json_file(path: &str) -> Value {
    let raw = text_file(path);
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"))
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
            proof_command: "rch exec -- cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals -- --nocapture".to_string(),
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
        proof_command: "rch exec -- cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals -- --nocapture".to_string(),
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
            command: "rch exec -- cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals -- --nocapture".to_string(),
        }],
        no_win_receipt,
        rows: vec![SloProofReportRow {
            row_id: format!("row-{}", status.as_str()),
            status,
            evidence_ref: "target/slo-policy-bundle/asupersync-bgtplc.4/slo-policy-bundle-events.ndjson".to_string(),
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
        proof_command: "rch exec -- cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals -- --nocapture",
        observed_profile_hash: Some(profile_hash('a')),
        queue_wait_ms: 20,
        memory_basis_points,
        fd_basis_points,
        timer_queue_depth,
        cancel_requested: false,
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
        proof_command: "rch exec -- cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals -- --nocapture",
        observed_profile_hash: None,
        queue_wait_ms: 20,
        memory_basis_points: 6_500,
        fd_basis_points: 5_900,
        timer_queue_depth: 12_000,
        cancel_requested: false,
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
        Some(brownout),
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
    }
}

async fn run_lab_replay_core(fixture: LabReplayFixture) -> LabReplayCoreOutcome {
    if let Some(document) = fixture.malformed_document {
        let report = validate_slo_policy_bundle_json(document);
        return LabReplayCoreOutcome {
            replay_status: "blocked".to_string(),
            compiler_status: "blocked".to_string(),
            admitted_work_units: 0,
            rejected_work_units: fixture.work_units,
            optional_work_units_browned_out: fixture.optional_work_units,
            cleanup_deadline_misses: 0,
            fallback_reason: None,
            issue_kinds: issue_tags(&report).into_iter().collect(),
            virtual_elapsed_ms: 0,
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
    let validation = application.validate();
    let core_request =
        replay_admission_request(&fixture, fixture.work_units, None, fixture.cancel_requested);
    let core_outcome = application.evaluate_admission(&core_request);
    let mut issue_kinds = BTreeSet::new();
    collect_replay_issue_kinds(&validation, &core_outcome, &mut issue_kinds);

    let mut replay_status = replay_status_for_admission(&validation, &core_outcome);
    let mut admitted_work_units = core_outcome.admitted_work_units;
    let mut rejected_work_units = core_outcome.rejected_work_units;
    let mut optional_work_units_browned_out = 0;
    let mut fallback_reason = core_outcome.fallback_reason.clone();

    if core_outcome.status == SloRuntimeAdmissionStatus::Admitted && fixture.optional_work_units > 0
    {
        let optional_request = replay_admission_request(
            &fixture,
            fixture.optional_work_units,
            fixture.optional_work_class,
            false,
        );
        let optional_outcome = application.evaluate_admission(&optional_request);
        collect_replay_issue_kinds(&validation, &optional_outcome, &mut issue_kinds);
        admitted_work_units =
            admitted_work_units.saturating_add(optional_outcome.admitted_work_units);
        rejected_work_units =
            rejected_work_units.saturating_add(optional_outcome.rejected_work_units);
        if optional_outcome.status == SloRuntimeAdmissionStatus::Brownout {
            optional_work_units_browned_out = optional_outcome.rejected_work_units;
            replay_status = "brownout".to_string();
        } else if optional_outcome.status != SloRuntimeAdmissionStatus::Admitted {
            replay_status = replay_status_for_admission(&validation, &optional_outcome);
            fallback_reason.clone_from(&optional_outcome.fallback_reason);
        }
    }

    let cleanup_deadline_misses = u64::from(
        core_outcome.status == SloRuntimeAdmissionStatus::Admitted
            && fixture.cleanup_work_ms > core_outcome.budget.cleanup_deadline_ms,
    );
    let completed_work_units =
        run_admitted_replay_tasks(admitted_work_units, core_outcome.budget.to_budget()).await;
    assert_eq!(
        completed_work_units, admitted_work_units,
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
    }
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
        SloProofReport::render_ci_gate_command("target/slo-policy-bundle", "asupersync-bgtplc.5");

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
            "validate_slo_policy_bundle_json",
            "validate_slo_proof_report_json",
            artifact["compiler_schema_version"]
                .as_str()
                .expect("compiler schema"),
            artifact["lab_replay_contract_version"]
                .as_str()
                .expect("lab replay contract"),
            artifact["proof_report_schema_version"]
                .as_str()
                .expect("proof report schema"),
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

        for rejected in [
            "Malformed reports",
            "stale profile hashes",
            "missing no-win receipts",
            "redaction failures",
            "secret-like material",
        ] {
            assert!(section.contains(rejected), "{label} missing {rejected}");
        }

        assert!(
            !section.contains("master"),
            "{label} SLO section must describe direct-main workflow without branch drift"
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
    assert_eq!(first.budget.p999_latency_budget_ms, 250);
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
    assert_eq!(compiled.budget.p999_latency_budget_ms, 400);
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
    assert!(command.starts_with("rch exec -- cargo test -p asupersync"));
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
        evidence_by_id["lab-replay-malformed-policy"].issue_kinds,
        vec!["malformed_json".to_string()]
    );
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
    let report = json_file(&report_path);
    let events = rows
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event row parses"))
        .collect::<Vec<_>>();

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
    assert_eq!(
        report["runtime_enforcement_count"].as_u64(),
        Some(runtime_enforcement_status_tags().len() as u64 + 1),
        "runtime enforcement report count includes local fallback scenario"
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
