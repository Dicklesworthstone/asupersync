//! Contract tests for the opt-in memory-residency policy engine.

#![allow(missing_docs)]

use asupersync::runtime::config::{
    ArenaLocalityAccessModel, ArenaLocalityPolicy, ArenaTemperaturePolicy, RuntimeCapacityHints,
    RuntimeConfig, TraceStorageProfile, WorkerCohortMapping,
};
use asupersync::runtime::resource_monitor::{
    MonitorConfig, ResourceMeasurement, ResourceMonitor, ResourceType, RuntimePressureSnapshot,
    RuntimePressureVerdict,
};
use asupersync::runtime::{
    ArtifactMemoryPressureSnapshot, MEMORY_RESIDENCY_DECISION_SCHEMA_VERSION,
    MemoryResidencyLiveTaskAction, MemoryResidencyPolicy, MemoryResidencyPolicyInput,
    MemoryResidencyProfile, MemoryResidencyReasonCode, MemoryResidencyTier,
    ProofPackWarmthTelemetry,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

const CONTRACT_PATH: &str = "artifacts/memory_residency_policy_contract_v1.json";
const DOCS_PATH: &str = "docs/proof/memory_residency_policy.md";
const POLICY_SOURCE_PATH: &str = "src/runtime/memory_residency.rs";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    let path = repo_root().join(path);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn load_contract() -> Value {
    serde_json::from_str(&read_repo_file(CONTRACT_PATH)).expect("parse policy contract")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
        .as_slice()
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string array entry").to_string())
        .collect()
}

fn large_host_worker_cohort_map() -> WorkerCohortMapping {
    WorkerCohortMapping::new(vec![
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3,
        3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7,
        7, 7, 7, 7,
    ])
}

fn skewed_access_model() -> ArenaLocalityAccessModel {
    ArenaLocalityAccessModel {
        task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
        obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
        task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
    }
}

fn balanced_access_model() -> ArenaLocalityAccessModel {
    ArenaLocalityAccessModel {
        task_arena_touches_by_cohort: vec![1024; 8],
        region_arena_touches_by_cohort: vec![256; 8],
        obligation_arena_touches_by_cohort: vec![512; 8],
        task_record_pool_touches_by_cohort: vec![1024; 8],
    }
}

fn locality_report(
    access_model: &ArenaLocalityAccessModel,
    budget_bps: u16,
) -> asupersync::runtime::config::ArenaLocalityReport {
    RuntimeConfig {
        worker_threads: 64,
        worker_cohort_map: Some(large_host_worker_cohort_map()),
        capacity_hints: Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096)),
        ..RuntimeConfig::default()
    }
    .arena_locality_report(
        ArenaLocalityPolicy::CohortPinned {
            min_topology_confidence_percent: 80,
            remote_touch_budget_bps: budget_bps,
            accounting_epoch: 11,
        },
        Some(95),
        access_model,
    )
}

fn roomy_cache_snapshot() -> ArtifactMemoryPressureSnapshot {
    ArtifactMemoryPressureSnapshot {
        resident_bytes: 128 * 1024 * 1024,
        max_resident_bytes: 8 * 1024 * 1024 * 1024,
        hot_resident_bytes: 96 * 1024 * 1024,
        cold_resident_bytes: 32 * 1024 * 1024,
        spill_eligible_bytes: 2 * 1024 * 1024 * 1024,
        remote_numa_bytes: 0,
        pressure_bps: 1_500,
        high_pressure: false,
        duplicate_bytes_avoided: 0,
        artifact_count: 12,
    }
}

fn exhausted_cache_snapshot() -> ArtifactMemoryPressureSnapshot {
    ArtifactMemoryPressureSnapshot {
        resident_bytes: 490 * 1024 * 1024,
        max_resident_bytes: 512 * 1024 * 1024,
        hot_resident_bytes: 420 * 1024 * 1024,
        cold_resident_bytes: 70 * 1024 * 1024,
        spill_eligible_bytes: 32 * 1024 * 1024,
        remote_numa_bytes: 0,
        pressure_bps: 9_100,
        high_pressure: true,
        duplicate_bytes_avoided: 0,
        artifact_count: 48,
    }
}

fn critical_pressure_snapshot() -> RuntimePressureSnapshot {
    let monitor = ResourceMonitor::new(MonitorConfig::default());
    monitor.pressure().update_measurement(
        ResourceType::Memory,
        ResourceMeasurement::new(98, 80, 95, 100),
    );
    monitor.runtime_pressure_snapshot(None, None)
}

fn base_input<'a>(
    locality: &'a asupersync::runtime::config::ArenaLocalityReport,
    cache: &'a ArtifactMemoryPressureSnapshot,
) -> MemoryResidencyPolicyInput<'a> {
    MemoryResidencyPolicyInput::new(
        RuntimeCapacityHints::from_expected_concurrent_tasks(4096),
        TraceStorageProfile::LargeMemory256G,
        ArenaTemperaturePolicy::TieredColdEvidence,
    )
    .with_locality_report(locality, 30)
    .with_artifact_cache_pressure(cache)
    .with_proof_pack_warmth(ProofPackWarmthTelemetry::new(true, true, 30, 900))
}

fn assert_reason(
    decision: &asupersync::runtime::MemoryResidencyDecision,
    reason: MemoryResidencyReasonCode,
) {
    assert!(
        decision.reason_codes.contains(&reason),
        "decision missing reason {reason:?}: {:?}",
        decision.reason_codes
    );
}

#[test]
fn contract_artifact_and_docs_pin_consumers_non_consumers_and_proof() {
    let contract = load_contract();
    assert_eq!(
        string_field(&contract, "schema_version"),
        "memory-residency-policy-contract-v1"
    );
    assert_eq!(
        string_field(&contract, "bead_id"),
        "asupersync-memory-residency-control-ho2itz.2"
    );
    assert_eq!(string_field(&contract, "status"), "contract_guarded");

    for path in [
        string_field(&contract["source_of_truth"], "policy_source"),
        string_field(&contract["source_of_truth"], "runtime_export"),
        string_field(&contract["source_of_truth"], "contract_test"),
        string_field(&contract["source_of_truth"], "docs"),
        string_field(&contract["source_of_truth"], "inventory"),
    ] {
        assert!(repo_root().join(path).exists(), "{path} must exist");
    }

    let command = string_field(&contract["proof_lane"], "command");
    assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "));
    assert!(command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_"));
    assert!(command.contains("cargo test -p asupersync --test memory_residency_policy_contract"));

    let scenarios: BTreeSet<_> = array(&contract, "decision_scenarios")
        .iter()
        .map(|row| string_field(row, "scenario_id").to_string())
        .collect();
    for scenario in [
        "disabled_default_no_effect",
        "fresh_topology_warm_evidence",
        "artifact_cache_pressure_spill_available",
        "stale_topology_fallback",
        "no_win_locality",
        "cold_evidence_budget_exhausted",
        "proof_pack_warmth_mismatch",
        "critical_memory_pressure",
        "unsupported_large_pages",
    ] {
        assert!(scenarios.contains(scenario), "missing scenario {scenario}");
    }

    let consumers = string_set(&contract, "consumers");
    assert!(consumers.iter().any(|row| row.contains("ho2itz.3")));
    assert!(consumers.iter().any(|row| row.contains("ho2itz.4")));
    assert!(consumers.iter().any(|row| row.contains("ho2itz.5")));

    let non_consumers = string_set(&contract, "non_consumers");
    assert!(non_consumers.contains("RuntimeBuilder default configuration"));
    assert!(non_consumers.contains("task cancellation or migration paths"));

    let docs = read_repo_file(DOCS_PATH);
    assert!(docs.contains(CONTRACT_PATH));
    assert!(docs.contains(POLICY_SOURCE_PATH));
    assert!(docs.contains("Non-consumers"));
    assert!(docs.contains("release readiness"));
}

#[test]
fn default_policy_is_disabled_and_recommendation_only() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = roomy_cache_snapshot();
    let decision = MemoryResidencyPolicy::default().decide(&base_input(&locality, &cache));

    assert_eq!(
        MemoryResidencyPolicy::default().profile,
        MemoryResidencyProfile::Disabled
    );
    assert!(!decision.policy_enabled);
    assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
    assert_eq!(
        decision.live_task_action,
        MemoryResidencyLiveTaskAction::RecommendOnly
    );
    assert_reason(&decision, MemoryResidencyReasonCode::PolicyDisabled);
}

#[test]
fn fresh_topology_selects_warm_evidence_recommendation() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = roomy_cache_snapshot();
    let decision =
        MemoryResidencyPolicy::experimental_opt_in().decide(&base_input(&locality, &cache));

    assert_eq!(
        decision.schema_version,
        MEMORY_RESIDENCY_DECISION_SCHEMA_VERSION
    );
    assert!(decision.policy_enabled);
    assert_eq!(decision.selected_tier, MemoryResidencyTier::Warm);
    assert!(decision.recommended_warm_evidence_bytes > 0);
    assert_eq!(decision.recommended_cold_evidence_bytes, 0);
    assert_eq!(decision.fallback_evidence_bytes, 0);
    assert_reason(&decision, MemoryResidencyReasonCode::FreshTopology);
}

#[test]
fn artifact_cache_pressure_with_spill_budget_selects_cold() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = ArtifactMemoryPressureSnapshot {
        pressure_bps: 8_700,
        high_pressure: true,
        spill_eligible_bytes: u64::MAX,
        ..roomy_cache_snapshot()
    };
    let decision =
        MemoryResidencyPolicy::experimental_opt_in().decide(&base_input(&locality, &cache));

    assert_eq!(decision.selected_tier, MemoryResidencyTier::Cold);
    assert!(decision.recommended_cold_evidence_bytes > 0);
    assert_reason(&decision, MemoryResidencyReasonCode::ArtifactCachePressure);
}

#[test]
fn stale_topology_fails_closed_to_fallback() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = roomy_cache_snapshot();
    let input = base_input(&locality, &cache).with_locality_report(&locality, 901);
    let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

    assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
    assert!(decision.fallback_evidence_bytes > 0);
    assert_reason(&decision, MemoryResidencyReasonCode::StaleTopology);
}

#[test]
fn no_win_locality_returns_no_win_without_live_task_action() {
    let locality = locality_report(&balanced_access_model(), 9000);
    let cache = roomy_cache_snapshot();
    let decision =
        MemoryResidencyPolicy::experimental_opt_in().decide(&base_input(&locality, &cache));

    assert!(locality.no_win_trigger);
    assert_eq!(decision.selected_tier, MemoryResidencyTier::NoWin);
    assert_eq!(
        decision.live_task_action,
        MemoryResidencyLiveTaskAction::RecommendOnly
    );
    assert!(decision.no_win_evidence_bytes > 0);
    assert_reason(&decision, MemoryResidencyReasonCode::NoWinLocality);
}

#[test]
fn exhausted_cold_evidence_budget_fails_closed() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = exhausted_cache_snapshot();
    let decision =
        MemoryResidencyPolicy::experimental_opt_in().decide(&base_input(&locality, &cache));

    assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
    assert_eq!(decision.artifact_cache_pressure_bps, Some(9_100));
    assert_reason(&decision, MemoryResidencyReasonCode::ArtifactCachePressure);
    assert_reason(
        &decision,
        MemoryResidencyReasonCode::ColdEvidenceBudgetExhausted,
    );
}

#[test]
fn proof_pack_warmth_mismatch_fails_closed_not_correctness() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = roomy_cache_snapshot();
    let input = base_input(&locality, &cache)
        .with_proof_pack_warmth(ProofPackWarmthTelemetry::new(false, true, 30, 900));
    let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

    assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
    assert!(decision.fallback_evidence_bytes > 0);
    assert_reason(
        &decision,
        MemoryResidencyReasonCode::ProofPackWarmthMismatch,
    );
}

#[test]
fn critical_memory_pressure_refuses_with_no_win() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = roomy_cache_snapshot();
    let pressure = critical_pressure_snapshot();
    assert_eq!(pressure.overall_verdict, RuntimePressureVerdict::Critical);

    let input = base_input(&locality, &cache).with_runtime_pressure(&pressure);
    let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

    assert_eq!(decision.selected_tier, MemoryResidencyTier::NoWin);
    assert_eq!(
        decision.runtime_pressure_verdict.as_deref(),
        Some("critical")
    );
    assert_reason(&decision, MemoryResidencyReasonCode::CriticalMemoryPressure);
}

#[test]
fn unsupported_large_pages_fall_back() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = roomy_cache_snapshot();
    let input = MemoryResidencyPolicyInput::new(
        RuntimeCapacityHints::from_expected_concurrent_tasks(4096),
        TraceStorageProfile::LargeMemory256G,
        ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
    )
    .with_locality_report(&locality, 30)
    .with_large_page_cold_slabs_supported(false)
    .with_artifact_cache_pressure(&cache)
    .with_proof_pack_warmth(ProofPackWarmthTelemetry::new(true, true, 30, 900));

    let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

    assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
    assert_reason(&decision, MemoryResidencyReasonCode::UnsupportedLargePages);
}

#[test]
fn decisions_are_byte_stable_for_repeated_fixed_inputs() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = roomy_cache_snapshot();
    let input = base_input(&locality, &cache);
    let policy = MemoryResidencyPolicy::experimental_opt_in();
    let first = policy.decide(&input);
    let second = policy.decide(&input);

    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).expect("serialize first"),
        serde_json::to_vec(&second).expect("serialize second")
    );
    assert_eq!(
        first.reason_codes,
        vec![
            MemoryResidencyReasonCode::PolicyEnabled,
            MemoryResidencyReasonCode::FreshTopology,
        ]
    );
}
