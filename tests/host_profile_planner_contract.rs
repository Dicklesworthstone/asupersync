#![recursion_limit = "256"]

//! Contract-backed proofs for the explainable host-profile planner.

use asupersync::runtime::config::{
    ArenaTemperaturePolicy, BlockingPoolAffinityProfile, HostProfileConfigDiffSource,
    HostProfileEvidenceArtifact, HostProfileEvidenceCalibrationStatus, HostProfileEvidenceSet,
    HostProfileHostResources, HostProfileId, HostProfileManualOverrides,
    HostProfilePlannerObjective, HostProfilePlannerRequest, RuntimeCapacityHints, RuntimeConfig,
    TraceStorageProfile,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

const DEFAULT_SCENARIO_ID: &str = "AA-HOST-PROFILE-PLANNER-LOCALITY-FIRST-64C-256G";

#[derive(Debug, Clone, Deserialize)]
struct HostProfilePlannerContract {
    contract_version: String,
    smoke_scenarios: Vec<HostProfilePlannerScenario>,
}

#[derive(Debug, Clone, Deserialize)]
struct HostProfilePlannerScenario {
    scenario_id: String,
    description: String,
    objective: String,
    requested_profile: Option<String>,
    host_resources: HostProfileResourcesFixture,
    #[serde(default)]
    controller_evidence: HostProfileEvidenceSetFixture,
    #[serde(default)]
    manual_overrides: HostProfileManualOverridesFixture,
    operator_note: Option<String>,
    expected_report_projection: Option<Value>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct HostProfileResourcesFixture {
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
    #[serde(default = "default_confidence_percent")]
    confidence_percent: u8,
    #[serde(default = "default_calibration_status")]
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

impl From<HostProfileEvidenceArtifactFixture> for HostProfileEvidenceArtifact {
    fn from(value: HostProfileEvidenceArtifactFixture) -> Self {
        Self {
            artifact_id: value.artifact_id,
            contract_version: value.contract_version,
            validation_passed: value.validation_passed,
            confidence_percent: value.confidence_percent,
            calibration_status: parse_evidence_calibration_status(&value.calibration_status),
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

fn default_contract() -> HostProfilePlannerContract {
    serde_json::from_str(include_str!(
        "../artifacts/host_profile_planner_smoke_contract_v1.json"
    ))
    .expect("embedded host profile planner contract must parse")
}

fn load_contract() -> HostProfilePlannerContract {
    if let Ok(path) = std::env::var("ASUPERSYNC_HOST_PROFILE_PLANNER_CONTRACT_PATH") {
        let contents = fs::read_to_string(&path).expect("host profile planner contract must load");
        serde_json::from_str(&contents).expect("host profile planner contract must parse")
    } else {
        default_contract()
    }
}

fn selected_scenario<'a>(
    contract: &'a HostProfilePlannerContract,
) -> &'a HostProfilePlannerScenario {
    let selected = std::env::var("ASUPERSYNC_HOST_PROFILE_PLANNER_SCENARIO")
        .unwrap_or_else(|_| DEFAULT_SCENARIO_ID.to_string());
    contract
        .smoke_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == selected)
        .unwrap_or_else(|| panic!("host profile planner scenario {selected} not found"))
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

fn default_confidence_percent() -> u8 {
    100
}

fn default_calibration_status() -> String {
    "current".to_string()
}

fn parse_evidence_calibration_status(value: &str) -> HostProfileEvidenceCalibrationStatus {
    match value {
        "current" => HostProfileEvidenceCalibrationStatus::Current,
        "stale" => HostProfileEvidenceCalibrationStatus::Stale,
        other => panic!("unsupported host profile evidence calibration status {other}"),
    }
}

fn parse_trace_storage_profile(value: &str) -> TraceStorageProfile {
    value.parse().unwrap_or_else(|_| {
        panic!("unsupported trace storage profile override {value}");
    })
}

fn parse_arena_temperature_policy(value: &str) -> ArenaTemperaturePolicy {
    value
        .parse()
        .unwrap_or_else(|_| panic!("unknown arena temperature policy fixture: {value}"))
}

fn build_request(scenario: &HostProfilePlannerScenario) -> HostProfilePlannerRequest {
    HostProfilePlannerRequest {
        objective: parse_objective(&scenario.objective),
        requested_profile: scenario.requested_profile.as_deref().map(parse_profile_id),
        host_resources: HostProfileHostResources {
            cpu_cores: scenario.host_resources.cpu_cores,
            memory_gib: scenario.host_resources.memory_gib,
        },
        controller_evidence: scenario.controller_evidence.clone().into(),
        manual_overrides: scenario.manual_overrides.clone().into(),
        operator_note: scenario.operator_note.clone(),
    }
}

fn format_capacity_hints(config: &RuntimeConfig) -> Value {
    match config.capacity_hints {
        Some(hints) => json!({
            "task_capacity": hints.task_capacity,
            "region_capacity": hints.region_capacity,
            "obligation_capacity": hints.obligation_capacity,
        }),
        None => Value::Null,
    }
}

fn format_worker_cohort_map(config: &RuntimeConfig) -> Value {
    match config.worker_cohort_map.as_ref() {
        Some(mapping) => json!(mapping.worker_to_cohort),
        None => Value::Null,
    }
}

fn format_blocking_affinity(profile: BlockingPoolAffinityProfile) -> Value {
    match profile {
        BlockingPoolAffinityProfile::Disabled => json!({
            "profile": "disabled"
        }),
        BlockingPoolAffinityProfile::CohortBiased {
            local_queue_soft_limit,
            spill_check_interval,
        } => json!({
            "profile": "cohort_biased",
            "local_queue_soft_limit": local_queue_soft_limit,
            "spill_check_interval": spill_check_interval,
        }),
    }
}

fn summarize_config(config: &RuntimeConfig) -> Value {
    json!({
        "worker_threads": config.worker_threads,
        "worker_cohort_map": format_worker_cohort_map(config),
        "global_queue_limit": config.global_queue_limit,
        "steal_batch_size": config.steal_batch_size,
        "blocking_affinity_profile": format_blocking_affinity(config.blocking.affinity_profile),
        "capacity_hints": format_capacity_hints(config),
        "trace_storage_profile": config.trace_storage_profile.to_string(),
        "arena_temperature_policy": config.arena_temperature_policy.to_string(),
        "browser_ready_handoff_limit": config.browser_ready_handoff_limit,
        "enable_governor": config.enable_governor,
        "enable_read_biased_region_snapshot": config.enable_read_biased_region_snapshot,
        "enable_adaptive_cancel_streak": config.enable_adaptive_cancel_streak,
    })
}

fn controller_stance(report: &Value, controller: &str) -> String {
    report["controller_ledger_state"]
        .as_array()
        .expect("controller ledger state array")
        .iter()
        .find(|entry| entry["controller"].as_str() == Some(controller))
        .unwrap_or_else(|| panic!("controller {controller} missing from report"))["stance"]
        .as_str()
        .expect("stance string")
        .to_string()
}

fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn projection_hash(projection: &Value) -> u64 {
    let encoded = serde_json::to_vec(projection).expect("projection should encode");
    stable_hash64(&encoded)
}

fn report_projection(report: &Value) -> Value {
    let projection = json!({
        "selected_profile": report["selected_profile"],
        "fallback_profile": report["fallback_profile"],
        "used_safe_fallback": report["used_safe_fallback"],
        "evidence_sufficiency_score_percent": report["evidence_sufficiency_score_percent"],
        "evidence_confidence_status": report["evidence_confidence_status"],
        "unresolved_child_proof_count": report["unresolved_child_proof_ids"].as_array().expect("unresolved child proof ids").len(),
        "conflict_row_count": report["profile_conflict_matrix"].as_array().expect("conflict matrix rows").len(),
        "dominant_risk_count": report["dominant_risk_contributors"].as_array().expect("dominant risk contributors").len(),
        "estimated_impact_metric_count": report["expected_impact_estimates"].as_array().expect("expected impact estimates").len(),
        "proof_artifact_count": report["input_evidence_artifact_ids"].as_array().expect("artifact ids array").len(),
        "manual_override_count": report["manual_overrides_applied"].as_array().expect("manual overrides array").len(),
        "refusal_count": report["refusal_reasons"].as_array().expect("refusal reasons array").len(),
        "brownout_stage": report["brownout_stage_included"],
        "otlp_shedding_stance": report["otlp_shedding_stance"],
        "admission_steering_stance": report["admission_steering_stance"],
        "adaptive_batch_sizing_stance": report["adaptive_batch_sizing_stance"],
        "blocking_pool_affinity_stance": report["blocking_pool_affinity_stance"],
        "large_memory_trace_profile_stance": report["large_memory_trace_profile_stance"],
        "final_worker_threads": report["final_bundle"]["worker_threads"],
        "final_global_queue_limit": report["final_bundle"]["global_queue_limit"],
        "final_trace_storage_profile": report["final_bundle"]["trace_storage_profile"],
        "final_arena_temperature_policy": report["final_bundle"]["arena_temperature_policy"],
        "sanitized_operator_note": report["sanitized_operator_note"],
        "dry_run_line_count": report["dry_run_config_diff"].as_array().expect("dry run lines array").len(),
    });
    let hash = projection_hash(&projection);
    let mut object = projection
        .as_object()
        .expect("projection should be object")
        .clone();
    object.insert("projection_hash".to_string(), json!(hash));
    Value::Object(object)
}

fn format_conflict_matrix(plan: &asupersync::runtime::config::HostProfilePlan) -> Vec<Value> {
    plan.conflict_matrix
        .iter()
        .map(|row| {
            json!({
                "profile": row.profile.to_string(),
                "verdict": row.verdict,
                "reason": row.reason,
            })
        })
        .collect()
}

fn format_expected_impact_estimates(
    plan: &asupersync::runtime::config::HostProfilePlan,
) -> Vec<Value> {
    plan.expected_impact_estimates
        .iter()
        .map(|estimate| {
            json!({
                "metric": estimate.metric,
                "label": estimate.label,
                "estimate": estimate.estimate,
            })
        })
        .collect()
}

fn build_report(
    contract_version: &str,
    scenario: &HostProfilePlannerScenario,
    request: &HostProfilePlannerRequest,
) -> Value {
    let plan = request.plan();
    let config_diff = plan
        .config_diff
        .iter()
        .map(|entry| {
            json!({
                "field_path": entry.field_path,
                "baseline_value": entry.baseline_value,
                "profile_value": entry.profile_value,
                "final_value": entry.final_value,
                "source": entry.source.to_string(),
                "rendered": entry.render(),
            })
        })
        .collect::<Vec<_>>();
    let controller_ledger_state = plan
        .controller_ledger_state
        .iter()
        .map(|entry| {
            json!({
                "controller": entry.controller,
                "stance": entry.stance,
                "proof_artifact_id": entry.proof_artifact_id,
                "validation_passed": entry.validation_passed,
            })
        })
        .collect::<Vec<_>>();
    let mut report = json!({
        "schema_version": "asupersync.host-profile-planner-report.v1",
        "contract_version": contract_version,
        "scenario_id": scenario.scenario_id,
        "description": scenario.description,
        "objective": plan.objective.to_string(),
        "requested_profile": plan.requested_profile.map(|profile| profile.to_string()),
        "selected_profile": plan.selected_profile.to_string(),
        "fallback_profile": plan.fallback_profile.to_string(),
        "used_safe_fallback": plan.used_safe_fallback(),
        "input_evidence_artifact_ids": plan.input_evidence_artifact_ids,
        "controller_ledger_state": controller_ledger_state,
        "profile_bundle": summarize_config(&plan.profile_bundle),
        "final_bundle": summarize_config(&plan.final_bundle),
        "manual_overrides_applied": plan.manual_overrides_applied,
        "config_diff": config_diff,
        "dry_run_config_diff": plan.config_diff.iter().map(|entry| entry.render()).collect::<Vec<_>>(),
        "evidence_sufficiency_score_percent": plan.evidence_sufficiency_score_percent,
        "evidence_confidence_status": plan.evidence_confidence_status,
        "unresolved_child_proof_ids": plan.unresolved_child_proof_ids,
        "dominant_risk_contributors": plan.dominant_risk_contributors,
        "profile_conflict_matrix": format_conflict_matrix(&plan),
        "expected_impact_estimates": format_expected_impact_estimates(&plan),
        "planner_scope": "reviewable_profile_candidates_and_dry_run_diffs_only",
        "capacity_certificate_boundary": "capacity certification remains asupersync-tdgqjy; p95/p99/p999 fields here are estimates, not certificates",
        "rationale": plan.rationale,
        "refusal_reasons": plan.refusal_reasons,
        "when_not_to_use": plan.when_not_to_use,
        "sanitized_operator_note": plan.sanitized_operator_note,
        "brownout_stage_included": controller_stance(&json!({ "controller_ledger_state": controller_ledger_state.clone() }), "brownout"),
        "otlp_shedding_stance": controller_stance(&json!({ "controller_ledger_state": controller_ledger_state.clone() }), "otlp_brownout"),
        "admission_steering_stance": controller_stance(&json!({ "controller_ledger_state": controller_ledger_state.clone() }), "admission_steering"),
        "adaptive_batch_sizing_stance": controller_stance(&json!({ "controller_ledger_state": controller_ledger_state.clone() }), "adaptive_batch_sizing"),
        "blocking_pool_affinity_stance": controller_stance(&json!({ "controller_ledger_state": controller_ledger_state.clone() }), "blocking_pool_affinity"),
        "large_memory_trace_profile_stance": controller_stance(&json!({ "controller_ledger_state": controller_ledger_state.clone() }), "trace_storage_profile"),
        "validation_verdict": {
            "status": "passed",
            "safe_fallback_profile": plan.fallback_profile.to_string(),
            "no_win_trigger": plan.used_safe_fallback(),
            "checks": [
                "named profile bundles remain explicit and reviewable",
                "manual overrides win over the profile bundle without mutating hidden runtime state",
                "missing or invalid child proofs force a conservative fallback",
                "low-confidence or stale child proofs force a conservative fallback",
                "expected p95/p99/p999 impact fields are labelled as estimates, not capacity certificates",
                "dry-run config diffs stay deterministic and operator-readable",
                "operator notes are secret-scrubbed before they reach the report surface",
            ]
        }
    });
    let projection = report_projection(&report);
    report
        .as_object_mut()
        .expect("report should be object")
        .insert("report_projection".to_string(), projection);
    report
}

fn maybe_write_report(report: &Value) {
    if let Ok(path) = std::env::var("ASUPERSYNC_HOST_PROFILE_PLANNER_REPORT_PATH") {
        let report_path = Path::new(&path);
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).expect("report parent directory should exist");
        }
        fs::write(
            report_path,
            serde_json::to_vec_pretty(report).expect("report should serialize"),
        )
        .expect("report should write");
    }
}

fn full_proof_fixture() -> HostProfileEvidenceSet {
    HostProfileEvidenceSetFixture {
        brownout: Some(HostProfileEvidenceArtifactFixture {
            artifact_id: "artifacts/overload_brownout_smoke_contract_v1.json".to_string(),
            contract_version: "overload-brownout-smoke-contract-v1".to_string(),
            validation_passed: true,
            confidence_percent: 100,
            calibration_status: "current".to_string(),
        }),
        otlp_brownout: Some(HostProfileEvidenceArtifactFixture {
            artifact_id: "artifacts/otlp_brownout_shedding_smoke_contract_v1.json".to_string(),
            contract_version: "otlp-brownout-shedding-smoke-contract-v1".to_string(),
            validation_passed: true,
            confidence_percent: 100,
            calibration_status: "current".to_string(),
        }),
        admission_steering: Some(HostProfileEvidenceArtifactFixture {
            artifact_id: "artifacts/cohort_admission_steering_smoke_contract_v1.json".to_string(),
            contract_version: "cohort-admission-steering-smoke-contract-v1".to_string(),
            validation_passed: true,
            confidence_percent: 100,
            calibration_status: "current".to_string(),
        }),
        adaptive_batch_sizing: Some(HostProfileEvidenceArtifactFixture {
            artifact_id: "artifacts/adaptive_batch_sizing_smoke_contract_v1.json".to_string(),
            contract_version: "adaptive-batch-sizing-smoke-contract-v1".to_string(),
            validation_passed: true,
            confidence_percent: 100,
            calibration_status: "current".to_string(),
        }),
        blocking_pool_affinity: Some(HostProfileEvidenceArtifactFixture {
            artifact_id: "artifacts/blocking_pool_affinity_smoke_contract_v1.json".to_string(),
            contract_version: "blocking-pool-affinity-smoke-contract-v1".to_string(),
            validation_passed: true,
            confidence_percent: 100,
            calibration_status: "current".to_string(),
        }),
        trace_storage_profile: Some(HostProfileEvidenceArtifactFixture {
            artifact_id: "artifacts/trace_storage_profile_smoke_contract_v1.json".to_string(),
            contract_version: "trace-storage-profile-smoke-contract-v1".to_string(),
            validation_passed: true,
            confidence_percent: 100,
            calibration_status: "current".to_string(),
        }),
    }
    .into()
}

fn sample_request(
    objective: HostProfilePlannerObjective,
    requested_profile: Option<HostProfileId>,
) -> HostProfilePlannerRequest {
    HostProfilePlannerRequest {
        objective,
        requested_profile,
        host_resources: HostProfileHostResources {
            cpu_cores: 64,
            memory_gib: 256,
        },
        controller_evidence: full_proof_fixture(),
        manual_overrides: HostProfileManualOverrides::default(),
        operator_note: None,
    }
}

#[test]
fn host_profile_named_bundle_composes_expected_large_host_knobs() {
    let request = sample_request(
        HostProfilePlannerObjective::LocalityFirst,
        Some(HostProfileId::LocalityFirst64C256G),
    );
    let plan = request.plan();
    assert_eq!(plan.selected_profile, HostProfileId::LocalityFirst64C256G);
    assert_eq!(plan.profile_bundle.worker_threads, 64);
    assert_eq!(plan.profile_bundle.global_queue_limit, 65_536);
    assert_eq!(plan.profile_bundle.steal_batch_size, 8);
    assert_eq!(
        plan.profile_bundle.trace_storage_profile,
        TraceStorageProfile::LargeMemory256G
    );
    assert_eq!(
        plan.profile_bundle.arena_temperature_policy,
        ArenaTemperaturePolicy::Unified
    );
    assert_eq!(
        plan.profile_bundle.blocking.affinity_profile,
        BlockingPoolAffinityProfile::CohortBiased {
            local_queue_soft_limit: 32,
            spill_check_interval: 4,
        }
    );
    assert_eq!(
        plan.profile_bundle
            .worker_cohort_map
            .as_ref()
            .expect("worker cohort map")
            .worker_to_cohort
            .len(),
        64
    );
}

#[test]
fn host_profile_manual_overrides_take_precedence() {
    let mut request = sample_request(
        HostProfilePlannerObjective::LocalityFirst,
        Some(HostProfileId::LocalityFirst64C256G),
    );
    request.manual_overrides.global_queue_limit = Some(49_152);
    request.manual_overrides.trace_storage_profile = Some(TraceStorageProfile::Default);
    let plan = request.plan();
    assert_eq!(plan.final_bundle.global_queue_limit, 49_152);
    assert_eq!(
        plan.final_bundle.trace_storage_profile,
        TraceStorageProfile::Default
    );
    let override_sources = plan
        .config_diff
        .iter()
        .filter(|entry| entry.source == HostProfileConfigDiffSource::ManualOverride)
        .map(|entry| entry.field_path.clone())
        .collect::<Vec<_>>();
    assert!(override_sources.contains(&"global_queue_limit".to_string()));
    assert!(override_sources.contains(&"trace_storage_profile".to_string()));
}

#[test]
fn host_profile_large_memory_retention_bundle_enables_tiered_arena_temperature() {
    let request = sample_request(
        HostProfilePlannerObjective::EvidenceRetentionFirst,
        Some(HostProfileId::LargeMemoryEvidenceRetention256G),
    );
    let plan = request.plan();
    assert_eq!(
        plan.selected_profile,
        HostProfileId::LargeMemoryEvidenceRetention256G
    );
    assert_eq!(
        plan.profile_bundle.arena_temperature_policy,
        ArenaTemperaturePolicy::TieredColdEvidence
    );
    assert_eq!(
        plan.final_bundle.arena_temperature_policy,
        ArenaTemperaturePolicy::TieredColdEvidence
    );
}

#[test]
fn host_profile_arena_temperature_override_takes_precedence() {
    let mut request = sample_request(
        HostProfilePlannerObjective::EvidenceRetentionFirst,
        Some(HostProfileId::LargeMemoryEvidenceRetention256G),
    );
    request.manual_overrides.arena_temperature_policy = Some(ArenaTemperaturePolicy::Unified);
    let plan = request.plan();
    assert_eq!(
        plan.profile_bundle.arena_temperature_policy,
        ArenaTemperaturePolicy::TieredColdEvidence
    );
    assert_eq!(
        plan.final_bundle.arena_temperature_policy,
        ArenaTemperaturePolicy::Unified
    );
    let override_sources = plan
        .config_diff
        .iter()
        .filter(|entry| entry.source == HostProfileConfigDiffSource::ManualOverride)
        .map(|entry| entry.field_path.clone())
        .collect::<Vec<_>>();
    assert!(override_sources.contains(&"arena_temperature_policy".to_string()));
}

#[test]
fn host_profile_missing_child_proof_falls_back_conservatively() {
    let mut request = sample_request(
        HostProfilePlannerObjective::TailProtectionFirst,
        Some(HostProfileId::TailProtectionFirst64C256G),
    );
    request.controller_evidence.adaptive_batch_sizing = None;
    let plan = request.plan();
    assert_eq!(plan.selected_profile, HostProfileId::ConservativeBaseline);
    assert!(plan.used_safe_fallback());
    assert!(
        plan.refusal_reasons
            .iter()
            .any(|reason| reason.contains("adaptive_batch_sizing proof is missing"))
    );
}

#[test]
fn host_profile_invalid_evidence_is_rejected() {
    let mut request = sample_request(
        HostProfilePlannerObjective::TailProtectionFirst,
        Some(HostProfileId::TailProtectionFirst64C256G),
    );
    request
        .controller_evidence
        .otlp_brownout
        .as_mut()
        .expect("otlp proof")
        .artifact_id = "../../secrets/token.json".to_string();
    let plan = request.plan();
    assert_eq!(plan.selected_profile, HostProfileId::ConservativeBaseline);
    assert!(
        plan.refusal_reasons
            .iter()
            .any(|reason| reason.contains("otlp_brownout proof rejected"))
    );
}

#[test]
fn host_profile_low_confidence_evidence_falls_back_with_score() {
    let mut request = sample_request(
        HostProfilePlannerObjective::LocalityFirst,
        Some(HostProfileId::LocalityFirst64C256G),
    );
    request
        .controller_evidence
        .admission_steering
        .as_mut()
        .expect("admission steering proof")
        .confidence_percent = 79;
    let plan = request.plan();
    assert_eq!(plan.selected_profile, HostProfileId::ConservativeBaseline);
    assert_eq!(plan.evidence_sufficiency_score_percent, 83);
    assert_eq!(plan.evidence_confidence_status, "low-confidence");
    assert!(
        plan.unresolved_child_proof_ids
            .iter()
            .any(|proof| proof.starts_with("admission_steering:"))
    );
    assert!(
        plan.dominant_risk_contributors
            .iter()
            .any(|risk| risk.contains("confidence_percent 79"))
    );
}

#[test]
fn host_profile_stale_evidence_is_reported_separately_from_missing_proofs() {
    let mut request = sample_request(
        HostProfilePlannerObjective::EvidenceRetentionFirst,
        Some(HostProfileId::LargeMemoryEvidenceRetention256G),
    );
    request
        .controller_evidence
        .trace_storage_profile
        .as_mut()
        .expect("trace storage proof")
        .calibration_status = HostProfileEvidenceCalibrationStatus::Stale;
    let plan = request.plan();
    assert_eq!(plan.selected_profile, HostProfileId::ConservativeBaseline);
    assert_eq!(plan.evidence_confidence_status, "stale-evidence");
    assert!(
        plan.refusal_reasons
            .iter()
            .any(|reason| reason.contains("calibration_status stale"))
    );
}

#[test]
fn host_profile_conflict_rows_and_estimates_are_labelled() {
    let request = sample_request(HostProfilePlannerObjective::LocalityFirst, None);
    let plan = request.plan();
    assert_eq!(plan.conflict_matrix.len(), 4);
    assert!(plan.conflict_matrix.iter().any(|row| row.profile
        == HostProfileId::LargeMemoryEvidenceRetention256G
        && row.verdict == "conflicting_goal"));
    assert_eq!(plan.expected_impact_estimates.len(), 3);
    for estimate in &plan.expected_impact_estimates {
        assert_eq!(estimate.label, "estimate_not_capacity_certificate");
        assert!(estimate.metric.starts_with("p9"));
    }
}

#[test]
fn host_profile_dry_run_diff_renders_stable_override_lines() {
    let mut request = sample_request(
        HostProfilePlannerObjective::LocalityFirst,
        Some(HostProfileId::LocalityFirst64C256G),
    );
    request.manual_overrides.global_queue_limit = Some(49_152);
    let plan = request.plan();
    let rendered = plan
        .config_diff
        .iter()
        .find(|entry| entry.field_path == "global_queue_limit")
        .expect("global queue diff")
        .render();
    assert_eq!(
        rendered,
        "global_queue_limit: 0 -> 65536 -> 49152 (manual_override)"
    );
}

#[test]
fn host_profile_redacts_sensitive_operator_note() {
    let mut request = sample_request(
        HostProfilePlannerObjective::LocalityFirst,
        Some(HostProfileId::LocalityFirst64C256G),
    );
    request.operator_note = Some("ticket=OPS-7 api_token=super-secret".to_string());
    let plan = request.plan();
    assert_eq!(
        plan.sanitized_operator_note.as_deref(),
        Some("ticket=OPS-7 api_token=[REDACTED]")
    );
}

#[test]
fn host_profile_recommendation_order_is_deterministic() {
    assert_eq!(
        HostProfilePlannerObjective::EvidenceRetentionFirst
            .candidate_order()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec![
            "large_memory_evidence_retention_256g".to_string(),
            "locality_first_64c_256g".to_string(),
            "tail_protection_first_64c_256g".to_string(),
            "conservative_baseline".to_string(),
        ]
    );
    let request = sample_request(HostProfilePlannerObjective::EvidenceRetentionFirst, None);
    let plan = request.plan();
    assert_eq!(
        plan.selected_profile,
        HostProfileId::LargeMemoryEvidenceRetention256G
    );
}

#[test]
fn host_profile_disabled_mode_matches_default_runtime_config() {
    let request = HostProfilePlannerRequest {
        objective: HostProfilePlannerObjective::LocalityFirst,
        requested_profile: Some(HostProfileId::ConservativeBaseline),
        host_resources: HostProfileHostResources {
            cpu_cores: 8,
            memory_gib: 32,
        },
        controller_evidence: HostProfileEvidenceSet::default(),
        manual_overrides: HostProfileManualOverrides::default(),
        operator_note: None,
    };
    let plan = request.plan();
    let defaults = RuntimeConfig::default();
    assert_eq!(plan.selected_profile, HostProfileId::ConservativeBaseline);
    assert_eq!(plan.final_bundle.worker_threads, defaults.worker_threads);
    assert_eq!(
        plan.final_bundle.global_queue_limit,
        defaults.global_queue_limit
    );
    assert_eq!(
        plan.final_bundle.trace_storage_profile,
        defaults.trace_storage_profile
    );
    assert_eq!(
        plan.final_bundle.arena_temperature_policy,
        defaults.arena_temperature_policy
    );
    assert!(plan.config_diff.is_empty());
}

#[test]
fn host_profile_when_not_to_use_explanations_are_rendered() {
    let request = sample_request(
        HostProfilePlannerObjective::TailProtectionFirst,
        Some(HostProfileId::TailProtectionFirst64C256G),
    );
    let plan = request.plan();
    assert!(plan.when_not_to_use.len() >= 2);
    assert!(
        plan.when_not_to_use
            .iter()
            .any(|line| line.contains("64-core / 256 GiB") || line.contains("64 cores"))
    );
}

#[test]
fn host_profile_planner_smoke_contract_emits_report() {
    let contract = load_contract();
    let scenario = selected_scenario(&contract);
    let request = build_request(scenario);
    let report = build_report(&contract.contract_version, scenario, &request);
    if let Some(expected_projection) = &scenario.expected_report_projection {
        assert_eq!(&report["report_projection"], expected_projection);
    }
    maybe_write_report(&report);
    println!("HOST_PROFILE_PLANNER_REPORT_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report should serialize")
    );
    println!("HOST_PROFILE_PLANNER_REPORT_JSON_END");
}
