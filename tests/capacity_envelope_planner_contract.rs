//! Contract-backed proofs for the massive-swarm capacity envelope planner.

use asupersync::runtime::config::{
    ArenaTemperaturePolicy, BlockingPoolAffinityProfile, CapacityEnvelopeBrownoutStage,
    CapacityEnvelopeBudget, CapacityEnvelopeBudgetOverrides, CapacityEnvelopeCalibrationStatus,
    CapacityEnvelopeCertificate, CapacityEnvelopeEvidenceSnapshot, CapacityEnvelopeHostFingerprint,
    CapacityEnvelopePlannerRequest, CoordinationWorkloadExpansionEvidence,
    CoordinationWorkloadRedactionStatus, CoordinationWorkloadTrustStatus,
    HostProfileEvidenceArtifact, HostProfileEvidenceCalibrationStatus, HostProfileEvidenceSet,
    HostProfileHostResources, HostProfileId, HostProfileManualOverrides,
    HostProfilePlannerObjective, RuntimeCapacityHints, RuntimeConfig, TraceStorageProfile,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;

const DEFAULT_SCENARIO_ID: &str = "AA-CAPACITY-ENVELOPE-LOCALITY-CERT-64C-256G";

#[derive(Debug, Clone, Deserialize)]
struct CapacityEnvelopeContract {
    contract_version: String,
    smoke_scenarios: Vec<CapacityEnvelopeScenario>,
}

#[derive(Debug, Clone, Deserialize)]
struct CapacityEnvelopeScenario {
    scenario_id: String,
    description: String,
    objective: String,
    requested_profile: Option<String>,
    host_resources: HostProfileResourcesFixture,
    host_fingerprint: HostFingerprintFixture,
    controller_evidence: HostProfileEvidenceSetFixture,
    #[serde(default)]
    manual_overrides: HostProfileManualOverridesFixture,
    evidence_snapshot: EvidenceSnapshotFixture,
    budget: BudgetFixture,
    #[serde(default)]
    budget_overrides: BudgetOverridesFixture,
    worker_count_sweep: Vec<usize>,
    agent_count_sweep: Vec<usize>,
    environment_note: Option<String>,
    validation_command: Option<String>,
    expected_report_projection: Option<Value>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct HostProfileResourcesFixture {
    cpu_cores: usize,
    memory_gib: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct HostFingerprintFixture {
    hostname: String,
    arch: String,
    cpu_cores: usize,
    memory_gib: usize,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct HostProfileEvidenceSetFixture {
    brownout: Option<HostProfileEvidenceArtifactFixture>,
    otlp_brownout: Option<HostProfileEvidenceArtifactFixture>,
    admission_steering: Option<HostProfileEvidenceArtifactFixture>,
    adaptive_batch_sizing: Option<HostProfileEvidenceArtifactFixture>,
    blocking_pool_affinity: Option<HostProfileEvidenceArtifactFixture>,
    trace_storage_profile: Option<HostProfileEvidenceArtifactFixture>,
}

#[derive(Debug, Clone, Deserialize)]
struct HostProfileEvidenceArtifactFixture {
    artifact_id: String,
    contract_version: String,
    validation_passed: bool,
    #[serde(default = "default_host_profile_confidence_percent")]
    confidence_percent: u8,
    #[serde(default = "default_host_profile_calibration_status")]
    calibration_status: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct HostProfileManualOverridesFixture {
    worker_threads: Option<usize>,
    worker_cohort_map: Option<Vec<usize>>,
    global_queue_limit: Option<usize>,
    steal_batch_size: Option<usize>,
    blocking_affinity_profile: Option<BlockingAffinityFixture>,
    capacity_hints: Option<CapacityHintsFixture>,
    trace_storage_profile: Option<String>,
    arena_temperature_policy: Option<String>,
    enable_governor: Option<bool>,
    enable_read_biased_region_snapshot: Option<bool>,
    enable_adaptive_cancel_streak: Option<bool>,
    browser_ready_handoff_limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "profile", rename_all = "snake_case")]
enum BlockingAffinityFixture {
    Disabled,
    CohortBiased {
        local_queue_soft_limit: usize,
        spill_check_interval: usize,
    },
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct CapacityHintsFixture {
    task_capacity: usize,
    region_capacity: usize,
    obligation_capacity: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct EvidenceSnapshotFixture {
    scenario_artifact_id: String,
    scenario_artifact_hash: String,
    scenario_contract_version: String,
    sample_count: usize,
    calibration_status: String,
    host_fingerprint: HostFingerprintFixture,
    artifact_age_hours: u64,
    measured_worker_count: usize,
    measured_agent_count: usize,
    measured_queue_depth: usize,
    throughput_ops_per_sec: u64,
    wake_to_run_p50_ns: u64,
    wake_to_run_p95_ns: u64,
    wake_to_run_p99_ns: u64,
    cancellation_debt_units: u64,
    memory_pressure_basis_points: u16,
    brownout_stage: String,
    brownout_risk_basis_points: u16,
    retention_budget_gib: usize,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct BudgetFixture {
    target_p99_ns: u64,
    target_cancel_debt_units: u64,
    max_memory_pressure_basis_points: u16,
    max_brownout_risk_basis_points: u16,
    max_queue_depth: usize,
    max_artifact_age_hours: u64,
    min_sample_count: usize,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
struct BudgetOverridesFixture {
    target_p99_ns: Option<u64>,
    target_cancel_debt_units: Option<u64>,
    max_memory_pressure_basis_points: Option<u16>,
    max_brownout_risk_basis_points: Option<u16>,
    max_queue_depth: Option<usize>,
    max_artifact_age_hours: Option<u64>,
    min_sample_count: Option<usize>,
}

impl From<HostProfileEvidenceArtifactFixture> for HostProfileEvidenceArtifact {
    fn from(value: HostProfileEvidenceArtifactFixture) -> Self {
        Self {
            artifact_id: value.artifact_id,
            contract_version: value.contract_version,
            validation_passed: value.validation_passed,
            confidence_percent: value.confidence_percent,
            calibration_status: parse_host_profile_calibration_status(&value.calibration_status),
        }
    }
}

impl From<HostProfileEvidenceSetFixture> for HostProfileEvidenceSet {
    fn from(value: HostProfileEvidenceSetFixture) -> Self {
        Self {
            brownout: value.brownout.map(Into::into),
            otlp_brownout: value.otlp_brownout.map(Into::into),
            admission_steering: value.admission_steering.map(Into::into),
            adaptive_batch_sizing: value.adaptive_batch_sizing.map(Into::into),
            blocking_pool_affinity: value.blocking_pool_affinity.map(Into::into),
            trace_storage_profile: value.trace_storage_profile.map(Into::into),
            coordination_workload_expansion: None,
        }
    }
}

impl From<BlockingAffinityFixture> for BlockingPoolAffinityProfile {
    fn from(value: BlockingAffinityFixture) -> Self {
        match value {
            BlockingAffinityFixture::Disabled => Self::Disabled,
            BlockingAffinityFixture::CohortBiased {
                local_queue_soft_limit,
                spill_check_interval,
            } => Self::CohortBiased {
                local_queue_soft_limit,
                spill_check_interval,
            },
        }
    }
}

impl From<HostProfileManualOverridesFixture> for HostProfileManualOverrides {
    fn from(value: HostProfileManualOverridesFixture) -> Self {
        Self {
            worker_threads: value.worker_threads,
            worker_cohort_map: value
                .worker_cohort_map
                .map(asupersync::runtime::config::WorkerCohortMapping::new),
            global_queue_limit: value.global_queue_limit,
            steal_batch_size: value.steal_batch_size,
            blocking_affinity_profile: value.blocking_affinity_profile.map(Into::into),
            capacity_hints: value.capacity_hints.map(|hints| {
                RuntimeCapacityHints::new(
                    hints.task_capacity,
                    hints.region_capacity,
                    hints.obligation_capacity,
                )
            }),
            trace_storage_profile: value
                .trace_storage_profile
                .as_deref()
                .map(parse_trace_storage_profile),
            arena_temperature_policy: value
                .arena_temperature_policy
                .as_deref()
                .map(parse_arena_temperature_policy),
            enable_governor: value.enable_governor,
            enable_read_biased_region_snapshot: value.enable_read_biased_region_snapshot,
            enable_adaptive_cancel_streak: value.enable_adaptive_cancel_streak,
            browser_ready_handoff_limit: value.browser_ready_handoff_limit,
        }
    }
}

impl From<HostFingerprintFixture> for CapacityEnvelopeHostFingerprint {
    fn from(value: HostFingerprintFixture) -> Self {
        Self {
            hostname: value.hostname,
            arch: value.arch,
            cpu_cores: value.cpu_cores,
            memory_gib: value.memory_gib,
        }
    }
}

impl From<BudgetFixture> for CapacityEnvelopeBudget {
    fn from(value: BudgetFixture) -> Self {
        Self {
            target_p99_ns: value.target_p99_ns,
            target_cancel_debt_units: value.target_cancel_debt_units,
            max_memory_pressure_basis_points: value.max_memory_pressure_basis_points,
            max_brownout_risk_basis_points: value.max_brownout_risk_basis_points,
            max_queue_depth: value.max_queue_depth,
            max_artifact_age_hours: value.max_artifact_age_hours,
            min_sample_count: value.min_sample_count,
        }
    }
}

impl From<BudgetOverridesFixture> for CapacityEnvelopeBudgetOverrides {
    fn from(value: BudgetOverridesFixture) -> Self {
        Self {
            target_p99_ns: value.target_p99_ns,
            target_cancel_debt_units: value.target_cancel_debt_units,
            max_memory_pressure_basis_points: value.max_memory_pressure_basis_points,
            max_brownout_risk_basis_points: value.max_brownout_risk_basis_points,
            max_queue_depth: value.max_queue_depth,
            max_artifact_age_hours: value.max_artifact_age_hours,
            min_sample_count: value.min_sample_count,
        }
    }
}

fn parse_trace_storage_profile(value: &str) -> TraceStorageProfile {
    value.parse().unwrap_or_else(|_| {
        panic!("unsupported trace storage profile override {value}");
    })
}

fn default_host_profile_confidence_percent() -> u8 {
    100
}

fn default_host_profile_calibration_status() -> String {
    "current".to_string()
}

fn parse_host_profile_calibration_status(value: &str) -> HostProfileEvidenceCalibrationStatus {
    match value {
        "current" => HostProfileEvidenceCalibrationStatus::Current,
        "stale" => HostProfileEvidenceCalibrationStatus::Stale,
        other => panic!("unsupported host profile evidence calibration status {other}"),
    }
}

fn parse_arena_temperature_policy(value: &str) -> ArenaTemperaturePolicy {
    value
        .parse()
        .unwrap_or_else(|_| panic!("unknown arena temperature policy fixture: {value}"))
}

fn parse_objective(value: &str) -> HostProfilePlannerObjective {
    match value {
        "locality_first" => HostProfilePlannerObjective::LocalityFirst,
        "tail_protection_first" => HostProfilePlannerObjective::TailProtectionFirst,
        "evidence_retention_first" => HostProfilePlannerObjective::EvidenceRetentionFirst,
        other => panic!("unsupported host profile objective {other}"),
    }
}

fn parse_profile_id(value: &str) -> HostProfileId {
    match value {
        "conservative_baseline" => HostProfileId::ConservativeBaseline,
        "locality_first_64c_256g" => HostProfileId::LocalityFirst64C256G,
        "tail_protection_first_64c_256g" => HostProfileId::TailProtectionFirst64C256G,
        "large_memory_evidence_retention_256g" => HostProfileId::LargeMemoryEvidenceRetention256G,
        other => panic!("unsupported host profile id {other}"),
    }
}

fn parse_brownout_stage(value: &str) -> CapacityEnvelopeBrownoutStage {
    match value {
        "full_surfaces" => CapacityEnvelopeBrownoutStage::FullSurfaces,
        "optional_first" => CapacityEnvelopeBrownoutStage::OptionalFirst,
        "priority_gate" => CapacityEnvelopeBrownoutStage::PriorityGate,
        "standalone_fallback" => CapacityEnvelopeBrownoutStage::StandaloneFallback,
        other => panic!("unsupported brownout stage {other}"),
    }
}

fn parse_calibration_status(value: &str) -> CapacityEnvelopeCalibrationStatus {
    match value {
        "calibrated" => CapacityEnvelopeCalibrationStatus::Calibrated,
        "drifted" => CapacityEnvelopeCalibrationStatus::Drifted,
        other => panic!("unsupported calibration status {other}"),
    }
}

fn default_contract() -> CapacityEnvelopeContract {
    serde_json::from_str(include_str!(
        "../artifacts/capacity_envelope_planner_smoke_contract_v1.json"
    ))
    .expect("embedded capacity envelope contract must parse")
}

fn load_contract() -> CapacityEnvelopeContract {
    if let Ok(path) = std::env::var("ASUPERSYNC_CAPACITY_ENVELOPE_CONTRACT_PATH") {
        let contents = fs::read_to_string(&path).expect("capacity envelope contract must load");
        serde_json::from_str(&contents).expect("capacity envelope contract must parse")
    } else {
        default_contract()
    }
}

fn selected_scenario<'a>(contract: &'a CapacityEnvelopeContract) -> &'a CapacityEnvelopeScenario {
    let selected = std::env::var("ASUPERSYNC_CAPACITY_ENVELOPE_SCENARIO")
        .unwrap_or_else(|_| DEFAULT_SCENARIO_ID.to_string());
    contract
        .smoke_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == selected)
        .unwrap_or_else(|| panic!("capacity envelope scenario {selected} not found"))
}

fn build_request(scenario: &CapacityEnvelopeScenario) -> CapacityEnvelopePlannerRequest {
    CapacityEnvelopePlannerRequest {
        objective: parse_objective(&scenario.objective),
        requested_profile: scenario.requested_profile.as_deref().map(parse_profile_id),
        host_resources: HostProfileHostResources {
            cpu_cores: scenario.host_resources.cpu_cores,
            memory_gib: scenario.host_resources.memory_gib,
        },
        controller_evidence: scenario.controller_evidence.clone().into(),
        manual_overrides: scenario.manual_overrides.clone().into(),
        host_fingerprint: scenario.host_fingerprint.clone().into(),
        evidence_snapshot: CapacityEnvelopeEvidenceSnapshot {
            scenario_artifact_id: scenario.evidence_snapshot.scenario_artifact_id.clone(),
            scenario_artifact_hash: scenario.evidence_snapshot.scenario_artifact_hash.clone(),
            scenario_contract_version: scenario.evidence_snapshot.scenario_contract_version.clone(),
            sample_count: scenario.evidence_snapshot.sample_count,
            calibration_status: parse_calibration_status(
                &scenario.evidence_snapshot.calibration_status,
            ),
            host_fingerprint: scenario.evidence_snapshot.host_fingerprint.clone().into(),
            artifact_age_hours: scenario.evidence_snapshot.artifact_age_hours,
            measured_worker_count: scenario.evidence_snapshot.measured_worker_count,
            measured_agent_count: scenario.evidence_snapshot.measured_agent_count,
            measured_queue_depth: scenario.evidence_snapshot.measured_queue_depth,
            throughput_ops_per_sec: scenario.evidence_snapshot.throughput_ops_per_sec,
            wake_to_run_p50_ns: scenario.evidence_snapshot.wake_to_run_p50_ns,
            wake_to_run_p95_ns: scenario.evidence_snapshot.wake_to_run_p95_ns,
            wake_to_run_p99_ns: scenario.evidence_snapshot.wake_to_run_p99_ns,
            cancellation_debt_units: scenario.evidence_snapshot.cancellation_debt_units,
            memory_pressure_basis_points: scenario.evidence_snapshot.memory_pressure_basis_points,
            brownout_stage: parse_brownout_stage(&scenario.evidence_snapshot.brownout_stage),
            brownout_risk_basis_points: scenario.evidence_snapshot.brownout_risk_basis_points,
            retention_budget_gib: scenario.evidence_snapshot.retention_budget_gib,
        },
        candidate_worker_counts: scenario.worker_count_sweep.clone(),
        candidate_agent_counts: scenario.agent_count_sweep.clone(),
        budget: scenario.budget.into(),
        budget_overrides: scenario.budget_overrides.into(),
        environment_note: scenario.environment_note.clone(),
        validation_command: scenario.validation_command.clone(),
    }
}

fn coordination_workload_evidence(
    pressure_basis_points: u32,
) -> CoordinationWorkloadExpansionEvidence {
    CoordinationWorkloadExpansionEvidence {
        artifact_id: "artifacts/runtime_workload_corpus_v1.json".to_string(),
        contract_version: "runtime-workload-coordination-synthesis-v1".to_string(),
        pack_hash: "sha256:coordination-planner-handoff-accepted".to_string(),
        source_bundle_hash: "sha256:coordination-runtime-fixture-accepted-all-families".to_string(),
        validation_passed: true,
        redaction_status: CoordinationWorkloadRedactionStatus::Passed,
        trust_status: CoordinationWorkloadTrustStatus::Trusted,
        sample_count: 96,
        artifact_age_hours: 6,
        host_fingerprint: CapacityEnvelopeHostFingerprint {
            hostname: "lab-64c-256g-a".to_string(),
            arch: "x86_64".to_string(),
            cpu_cores: 64,
            memory_gib: 256,
        },
        pressure_basis_points,
    }
}

fn summarize_config(config: &RuntimeConfig) -> Value {
    json!({
        "worker_threads": config.worker_threads,
        "worker_cohort_map": config.worker_cohort_map.as_ref().map(|mapping| mapping.worker_to_cohort.clone()),
        "global_queue_limit": config.global_queue_limit,
        "steal_batch_size": config.steal_batch_size,
        "capacity_hints": match config.capacity_hints {
            Some(hints) => json!({
                "task_capacity": hints.task_capacity,
                "region_capacity": hints.region_capacity,
                "obligation_capacity": hints.obligation_capacity,
            }),
            None => Value::Null,
        },
        "trace_storage_profile": config.trace_storage_profile.to_string(),
        "enable_governor": config.enable_governor,
        "enable_read_biased_region_snapshot": config.enable_read_biased_region_snapshot,
        "enable_adaptive_cancel_streak": config.enable_adaptive_cancel_streak,
    })
}

fn point_json(point: &asupersync::runtime::config::CapacityEnvelopePointEvaluation) -> Value {
    json!({
        "worker_count": point.worker_count,
        "agent_count": point.agent_count,
        "predicted_p50_ns": point.predicted_p50_ns,
        "predicted_p95_ns": point.predicted_p95_ns,
        "predicted_p99_ns": point.predicted_p99_ns,
        "predicted_cancellation_debt_units": point.predicted_cancellation_debt_units,
        "predicted_queue_depth": point.predicted_queue_depth,
        "predicted_memory_gib": point.predicted_memory_gib,
        "predicted_memory_pressure_basis_points": point.predicted_memory_pressure_basis_points,
        "predicted_brownout_risk_basis_points": point.predicted_brownout_risk_basis_points,
        "status": match point.status {
            asupersync::runtime::config::CapacityEnvelopePointStatus::Safe => "safe",
            asupersync::runtime::config::CapacityEnvelopePointStatus::Refused => "refused",
        },
        "refusal_reasons": point.refusal_reasons,
    })
}

fn range_json(range: Option<asupersync::runtime::config::CapacityEnvelopeRange>) -> Value {
    match range {
        Some(range) => json!({
            "worker_min": range.worker_min,
            "worker_max": range.worker_max,
            "agent_min": range.agent_min,
            "agent_max": range.agent_max,
            "max_queue_depth": range.max_queue_depth,
            "max_memory_gib": range.max_memory_gib,
        }),
        None => Value::Null,
    }
}

fn projection_hash(projection: &Value) -> u64 {
    let bytes = serde_json::to_vec(projection).expect("projection must serialize");
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn report_projection(report: &Value) -> Value {
    let safe_agent_max = report["safe_envelope"]["agent_max"].as_u64().unwrap_or(0);
    let safe_worker_max = report["safe_envelope"]["worker_max"].as_u64().unwrap_or(0);
    let refused_agent_min = report["refused_envelope"]["agent_min"]
        .as_u64()
        .unwrap_or(0);
    let refused_worker_min = report["refused_envelope"]["worker_min"]
        .as_u64()
        .unwrap_or(0);
    let mut object = json!({
        "selected_profile": report["selected_profile"],
        "fallback_profile": report["fallback_profile"],
        "used_safe_fallback": report["used_safe_fallback"],
        "safe_worker_max": safe_worker_max,
        "safe_agent_max": safe_agent_max,
        "refused_worker_min": refused_worker_min,
        "refused_agent_min": refused_agent_min,
        "proof_artifact_count": report["input_evidence_artifact_ids"].as_array().expect("evidence ids").len(),
        "refusal_count": report["refusal_reasons"].as_array().expect("refusal reasons").len(),
        "target_p99_ns": report["effective_budget"]["target_p99_ns"],
        "target_cancel_debt_units": report["effective_budget"]["target_cancel_debt_units"],
        "min_sample_count": report["effective_budget"]["min_sample_count"],
        "sample_count": report["evidence_snapshot"]["sample_count"],
        "calibration_status": report["evidence_snapshot"]["calibration_status"],
        "host_cpu_cores": report["host_fingerprint"]["cpu_cores"],
        "host_memory_gib": report["host_fingerprint"]["memory_gib"],
        "brownout_stage": report["evidence_snapshot"]["brownout_stage"],
    });
    let hash = projection_hash(&object);
    object
        .as_object_mut()
        .expect("projection object")
        .insert("projection_hash".to_string(), json!(hash));
    object
}

fn certificate_report_json(
    contract_version: &str,
    scenario: &CapacityEnvelopeScenario,
    certificate: &CapacityEnvelopeCertificate,
) -> Value {
    let safe_envelope = range_json(certificate.safe_envelope);
    let refused_envelope = range_json(Some(certificate.refused_envelope));
    let mut report = json!({
        "schema_version": "asupersync.capacity-envelope-certificate.v1",
        "contract_version": contract_version,
        "scenario_id": scenario.scenario_id,
        "description": scenario.description,
        "objective": certificate.objective.as_str(),
        "requested_profile": certificate.requested_profile.map(|profile| profile.as_str()),
        "selected_profile": certificate.selected_profile.as_str(),
        "fallback_profile": certificate.fallback_profile.as_str(),
        "used_safe_fallback": certificate.used_safe_fallback(),
        "profile_bundle": summarize_config(&certificate.profile_bundle),
        "final_bundle": summarize_config(&certificate.final_bundle),
        "assumptions_ledger": certificate.assumptions_ledger,
        "refusal_reasons": certificate.refusal_reasons,
        "input_evidence_artifact_ids": certificate.evidence_artifact_ids,
        "host_fingerprint": {
            "hostname": certificate.host_fingerprint.hostname,
            "arch": certificate.host_fingerprint.arch,
            "cpu_cores": certificate.host_fingerprint.cpu_cores,
            "memory_gib": certificate.host_fingerprint.memory_gib,
        },
        "evidence_snapshot": {
            "scenario_artifact_id": certificate.evidence_snapshot.scenario_artifact_id,
            "scenario_artifact_hash": certificate.evidence_snapshot.scenario_artifact_hash,
            "scenario_contract_version": certificate.evidence_snapshot.scenario_contract_version,
            "sample_count": certificate.evidence_snapshot.sample_count,
            "calibration_status": certificate.evidence_snapshot.calibration_status.as_str(),
            "artifact_age_hours": certificate.evidence_snapshot.artifact_age_hours,
            "measured_worker_count": certificate.evidence_snapshot.measured_worker_count,
            "measured_agent_count": certificate.evidence_snapshot.measured_agent_count,
            "measured_queue_depth": certificate.evidence_snapshot.measured_queue_depth,
            "throughput_ops_per_sec": certificate.evidence_snapshot.throughput_ops_per_sec,
            "wake_to_run_p50_ns": certificate.evidence_snapshot.wake_to_run_p50_ns,
            "wake_to_run_p95_ns": certificate.evidence_snapshot.wake_to_run_p95_ns,
            "wake_to_run_p99_ns": certificate.evidence_snapshot.wake_to_run_p99_ns,
            "cancellation_debt_units": certificate.evidence_snapshot.cancellation_debt_units,
            "memory_pressure_basis_points": certificate.evidence_snapshot.memory_pressure_basis_points,
            "brownout_stage": certificate.evidence_snapshot.brownout_stage.as_str(),
            "brownout_risk_basis_points": certificate.evidence_snapshot.brownout_risk_basis_points,
            "retention_budget_gib": certificate.evidence_snapshot.retention_budget_gib,
        },
        "effective_budget": {
            "target_p99_ns": certificate.effective_budget.target_p99_ns,
            "target_cancel_debt_units": certificate.effective_budget.target_cancel_debt_units,
            "max_memory_pressure_basis_points": certificate.effective_budget.max_memory_pressure_basis_points,
            "max_brownout_risk_basis_points": certificate.effective_budget.max_brownout_risk_basis_points,
            "max_queue_depth": certificate.effective_budget.max_queue_depth,
            "max_artifact_age_hours": certificate.effective_budget.max_artifact_age_hours,
            "min_sample_count": certificate.effective_budget.min_sample_count,
        },
        "worker_count_sweep": certificate.candidate_worker_counts,
        "agent_count_sweep": certificate.candidate_agent_counts,
        "safe_envelope": safe_envelope,
        "refused_envelope": refused_envelope,
        "evaluations": certificate.evaluations.iter().map(point_json).collect::<Vec<_>>(),
        "coordination_workload_status": {
            "verdict": certificate.coordination_workload_status.verdict.as_str(),
            "artifact_id": certificate.coordination_workload_status.artifact_id.clone(),
            "pack_hash": certificate.coordination_workload_status.pack_hash.clone(),
            "source_bundle_hash": certificate.coordination_workload_status.source_bundle_hash.clone(),
            "pressure_basis_points": certificate.coordination_workload_status.pressure_basis_points,
            "agent_ceiling": certificate.coordination_workload_status.agent_ceiling,
            "refusal_reasons": certificate.coordination_workload_status.refusal_reasons.clone(),
        },
        "sanitized_environment_note": certificate.sanitized_environment_note,
        "sanitized_validation_command": certificate.sanitized_validation_command,
        "validation_verdict": {
            "status": "passed",
            "checks": [
                "host fingerprint and scenario evidence must match the requested host",
                "capacity certificates refuse stale or invalid artifacts before certifying a profile",
                "capacity certificates refuse under-sampled or drifted evidence before extrapolation",
                "safe envelopes stay dry-run only and never mutate runtime state",
                "manual SLO overrides take precedence over the default certificate budget",
                "operator notes and validation commands are secret-scrubbed before reporting"
            ],
            "no_win": certificate.safe_envelope.is_none(),
            "safe_fallback_profile": certificate.fallback_profile.as_str(),
        },
    });
    let projection = report_projection(&report);
    report
        .as_object_mut()
        .expect("capacity report object")
        .insert("report_projection".to_string(), projection);
    report
}

fn write_report_if_requested(report: &Value) {
    if let Ok(path) = std::env::var("ASUPERSYNC_CAPACITY_ENVELOPE_REPORT_PATH") {
        let path = Path::new(&path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("report parent directory should exist");
        }
        let rendered = serde_json::to_string_pretty(report).expect("capacity report must render");
        fs::write(path, rendered).expect("capacity report should write");
    }
}

#[test]
fn capacity_envelope_stale_artifact_is_rejected() {
    let contract = default_contract();
    let mut request = build_request(&contract.smoke_scenarios[0]);
    request.evidence_snapshot.artifact_age_hours = 72;
    let certificate = request.plan();
    assert!(certificate.used_safe_fallback());
    assert!(
        certificate
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("artifact_age_hours")),
        "{:?}",
        certificate.refusal_reasons
    );
}

#[test]
fn capacity_envelope_host_fingerprint_mismatch_is_rejected() {
    let contract = default_contract();
    let mut request = build_request(&contract.smoke_scenarios[0]);
    request.host_fingerprint.hostname = "mismatch-host".to_string();
    let certificate = request.plan();
    assert!(certificate.used_safe_fallback());
    assert!(
        certificate
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("did not match the requested host fingerprint")),
        "{:?}",
        certificate.refusal_reasons
    );
}

#[test]
fn capacity_envelope_under_sampled_evidence_is_rejected() {
    let contract = default_contract();
    let mut request = build_request(&contract.smoke_scenarios[0]);
    request.evidence_snapshot.sample_count = request.budget.min_sample_count.saturating_sub(1);
    let certificate = request.plan();
    assert!(certificate.used_safe_fallback());
    assert!(
        certificate
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("sample_count")),
        "{:?}",
        certificate.refusal_reasons
    );
}

#[test]
fn capacity_envelope_calibration_drift_is_rejected() {
    let contract = default_contract();
    let mut request = build_request(&contract.smoke_scenarios[0]);
    request.evidence_snapshot.calibration_status = CapacityEnvelopeCalibrationStatus::Drifted;
    let certificate = request.plan();
    assert!(certificate.used_safe_fallback());
    assert!(
        certificate
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("calibration_status")),
        "{:?}",
        certificate.refusal_reasons
    );
}

#[test]
fn capacity_envelope_missing_child_proof_falls_back_conservatively() {
    let contract = default_contract();
    let mut request = build_request(&contract.smoke_scenarios[0]);
    request.controller_evidence.otlp_brownout = None;
    let certificate = request.plan();
    assert!(certificate.used_safe_fallback());
    assert!(
        certificate
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("otlp_brownout proof is missing")),
        "{:?}",
        certificate.refusal_reasons
    );
}

#[test]
fn capacity_envelope_recommendation_order_is_deterministic() {
    let contract = default_contract();
    let request = build_request(&contract.smoke_scenarios[0]);
    let report_a = certificate_report_json(
        &contract.contract_version,
        &contract.smoke_scenarios[0],
        &request.plan(),
    );
    let report_b = certificate_report_json(
        &contract.contract_version,
        &contract.smoke_scenarios[0],
        &request.plan(),
    );
    assert_eq!(report_a["report_projection"], report_b["report_projection"]);
}

#[test]
fn capacity_envelope_manual_budget_overrides_take_precedence() {
    let contract = default_contract();
    let mut request = build_request(&contract.smoke_scenarios[0]);
    let strict = request.plan();
    request.budget_overrides = CapacityEnvelopeBudgetOverrides {
        target_p99_ns: Some(1_450_000),
        target_cancel_debt_units: Some(150),
        max_queue_depth: Some(50_000),
        max_memory_pressure_basis_points: Some(9_000),
        max_brownout_risk_basis_points: Some(2_000),
        ..CapacityEnvelopeBudgetOverrides::default()
    };
    let relaxed = request.plan();
    assert_eq!(
        strict.safe_envelope.expect("strict envelope").agent_max,
        512,
        "strict budget should cap the certificate at 512 agents"
    );
    assert_eq!(
        relaxed.safe_envelope.expect("relaxed envelope").agent_max,
        640,
        "manual SLO overrides should widen the safe agent range when they relax the budgets"
    );
}

#[test]
fn capacity_envelope_no_win_certificate_renders_refusal_reason() {
    let contract = default_contract();
    let request = build_request(&contract.smoke_scenarios[1]);
    let certificate = request.plan();
    assert!(certificate.used_safe_fallback());
    assert!(certificate.safe_envelope.is_none());
    assert!(
        certificate
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("artifact_age_hours")),
        "{:?}",
        certificate.refusal_reasons
    );
}

#[test]
fn capacity_envelope_stricter_slo_shrinks_safe_envelope_monotonically() {
    let contract = default_contract();
    let mut request = build_request(&contract.smoke_scenarios[0]);
    let relaxed = request.plan();
    request.budget_overrides = CapacityEnvelopeBudgetOverrides {
        target_p99_ns: Some(1_050_000),
        ..CapacityEnvelopeBudgetOverrides::default()
    };
    let strict = request.plan();
    assert_eq!(
        relaxed.safe_envelope.expect("relaxed envelope").agent_max,
        512
    );
    assert_eq!(
        strict.safe_envelope.expect("strict envelope").agent_max,
        384
    );
}

#[test]
fn capacity_envelope_coordination_pack_narrows_capacity_monotonically() {
    let contract = default_contract();
    let mut baseline = build_request(&contract.smoke_scenarios[0]);
    baseline.candidate_agent_counts = vec![128, 192, 256, 384, 512];
    let baseline_certificate = baseline.plan();

    let mut moderate = baseline.clone();
    moderate.controller_evidence.coordination_workload_expansion =
        Some(coordination_workload_evidence(12_000));
    let moderate_certificate = moderate.plan();

    let mut severe = baseline;
    severe.controller_evidence.coordination_workload_expansion =
        Some(coordination_workload_evidence(20_000));
    let severe_certificate = severe.plan();

    assert_eq!(
        moderate_certificate
            .coordination_workload_status
            .verdict
            .as_str(),
        "used"
    );
    assert_eq!(
        severe_certificate
            .coordination_workload_status
            .verdict
            .as_str(),
        "used"
    );
    assert!(
        moderate_certificate
            .assumptions_ledger
            .iter()
            .any(|line| line.contains("coordination workload expansion pack"))
    );
    let baseline_agent_max = baseline_certificate
        .safe_envelope
        .expect("baseline safe envelope")
        .agent_max;
    let moderate_agent_max = moderate_certificate
        .safe_envelope
        .expect("moderate safe envelope")
        .agent_max;
    let severe_agent_max = severe_certificate
        .safe_envelope
        .expect("severe safe envelope")
        .agent_max;
    assert!(
        baseline_agent_max > moderate_agent_max,
        "coordination pressure must only narrow, not widen, the safe envelope"
    );
    assert!(
        moderate_agent_max >= severe_agent_max,
        "worse coordination pressure must not increase the safe envelope"
    );
}

#[test]
fn capacity_envelope_coordination_rejects_stale_redaction_failed_and_under_sampled_packs() {
    let contract = default_contract();
    let mut request = build_request(&contract.smoke_scenarios[0]);

    let mut stale = request.clone();
    let mut stale_pack = coordination_workload_evidence(12_000);
    stale_pack.artifact_age_hours = 72;
    stale.controller_evidence.coordination_workload_expansion = Some(stale_pack);
    let stale_certificate = stale.plan();
    assert!(stale_certificate.used_safe_fallback());
    assert!(stale_certificate.refusal_reasons.iter().any(|reason| {
        reason.contains("coordination workload expansion rejected")
            && reason.contains("artifact_age_hours")
    }));

    let mut redaction_failed = request.clone();
    let mut redaction_failed_pack = coordination_workload_evidence(12_000);
    redaction_failed_pack.redaction_status = CoordinationWorkloadRedactionStatus::Failed;
    redaction_failed
        .controller_evidence
        .coordination_workload_expansion = Some(redaction_failed_pack);
    let redaction_failed_certificate = redaction_failed.plan();
    assert!(redaction_failed_certificate.used_safe_fallback());
    assert!(
        redaction_failed_certificate
            .refusal_reasons
            .iter()
            .any(|reason| {
                reason.contains("coordination workload expansion rejected")
                    && reason.contains("redaction_status")
            })
    );

    let mut under_sampled_pack = coordination_workload_evidence(12_000);
    under_sampled_pack.sample_count = 8;
    request.controller_evidence.coordination_workload_expansion = Some(under_sampled_pack);
    let under_sampled_certificate = request.plan();
    assert!(under_sampled_certificate.used_safe_fallback());
    assert!(
        under_sampled_certificate
            .refusal_reasons
            .iter()
            .any(|reason| {
                reason.contains("coordination workload expansion rejected")
                    && reason.contains("sample_count")
            })
    );
}

#[test]
fn capacity_envelope_coordination_host_mismatch_is_rejected() {
    let contract = default_contract();
    let mut request = build_request(&contract.smoke_scenarios[0]);
    let mut pack = coordination_workload_evidence(12_000);
    pack.host_fingerprint.hostname = "different-host".to_string();
    request.controller_evidence.coordination_workload_expansion = Some(pack);

    let certificate = request.plan();
    assert!(certificate.used_safe_fallback());
    assert_eq!(
        certificate.coordination_workload_status.verdict.as_str(),
        "refused"
    );
    assert!(certificate.refusal_reasons.iter().any(|reason| {
        reason.contains("coordination workload expansion rejected")
            && reason.contains("host fingerprint")
    }));
}

#[test]
fn capacity_envelope_redacts_sensitive_command_and_env_notes() {
    let contract = default_contract();
    let request = build_request(&contract.smoke_scenarios[0]);
    let certificate = request.plan();
    assert_eq!(
        certificate
            .sanitized_environment_note
            .as_deref()
            .expect("environment note"),
        "ticket=OPS-CAP api_token=[REDACTED]"
    );
    assert_eq!(
        certificate
            .sanitized_validation_command
            .as_deref()
            .expect("validation command"),
        "run_id=CAP-64 token=[REDACTED]"
    );
}

#[test]
fn capacity_envelope_disabled_mode_matches_conservative_baseline() {
    let contract = default_contract();
    let mut request = build_request(&contract.smoke_scenarios[0]);
    request.requested_profile = Some(HostProfileId::ConservativeBaseline);
    request.objective = HostProfilePlannerObjective::LocalityFirst;
    let certificate = request.plan();
    let mut expected = RuntimeConfig::default();
    request.manual_overrides.apply_to_config(&mut expected);
    expected.normalize();
    assert_eq!(
        certificate.selected_profile,
        HostProfileId::ConservativeBaseline
    );
    assert_eq!(
        summarize_config(&certificate.final_bundle),
        summarize_config(&expected)
    );
}

#[test]
fn capacity_envelope_certificate_emits_expected_locality_bundle() {
    let contract = default_contract();
    let request = build_request(&contract.smoke_scenarios[0]);
    let certificate = request.plan();
    assert_eq!(
        certificate.selected_profile,
        HostProfileId::LocalityFirst64C256G
    );
    let envelope = certificate.safe_envelope.expect("safe envelope");
    assert_eq!(envelope.worker_max, 64);
    assert_eq!(envelope.agent_max, 512);
    assert_eq!(certificate.refused_envelope.agent_min, 512);
}

#[test]
fn capacity_envelope_smoke_contract_emits_report() {
    let contract = load_contract();
    let scenario = selected_scenario(&contract);
    let request = build_request(scenario);
    let certificate = request.plan();
    let report = certificate_report_json(&contract.contract_version, scenario, &certificate);
    if let Some(expected_projection) = scenario
        .expected_report_projection
        .as_ref()
        .filter(|projection| !projection.is_null())
    {
        assert_eq!(&report["report_projection"], expected_projection);
    }
    write_report_if_requested(&report);
    println!("CAPACITY_ENVELOPE_CERTIFICATE_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("capacity report must render"),
    );
    println!("CAPACITY_ENVELOPE_CERTIFICATE_JSON_END");
}
