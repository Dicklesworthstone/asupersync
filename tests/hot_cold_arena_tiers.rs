//! Contract-backed proofs for hot/cold arena temperature planning.

use asupersync::runtime::TraceStorageProfile;
use asupersync::runtime::config::{ArenaTemperaturePolicy, RuntimeCapacityHints, RuntimeConfig};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;

const DEFAULT_SCENARIO_ID: &str = "AA-HOT-COLD-ARENA-TIERED-RETENTION-64C-256G";

#[derive(Debug, Clone, Deserialize)]
struct HotColdArenaContract {
    smoke_scenarios: Vec<HotColdArenaScenario>,
}

#[derive(Debug, Clone, Deserialize)]
struct HotColdArenaScenario {
    scenario_id: String,
    description: String,
    requested_policy: String,
    trace_storage_profile: String,
    host_requirements: HostRequirementsFixture,
    workload_model: HotColdArenaWorkloadFixture,
    operator_notes: Value,
    expected_report_projection: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct HostRequirementsFixture {
    min_worker_threads: usize,
    min_memory_gib: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct HotColdArenaWorkloadFixture {
    capacity_hints: CapacityHintsFixture,
    locality_profile_input: String,
    large_page_cold_slabs_supported: bool,
    default_safe_fallback_profile: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct CapacityHintsFixture {
    task_capacity: usize,
    region_capacity: usize,
    obligation_capacity: usize,
}

impl CapacityHintsFixture {
    fn into_runtime_hints(self) -> RuntimeCapacityHints {
        RuntimeCapacityHints::new(
            self.task_capacity,
            self.region_capacity,
            self.obligation_capacity,
        )
    }
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn parse_policy(value: &str) -> ArenaTemperaturePolicy {
    value
        .parse()
        .unwrap_or_else(|_| panic!("unknown arena temperature policy fixture: {value}"))
}

fn parse_trace_storage_profile(value: &str) -> TraceStorageProfile {
    value
        .parse()
        .unwrap_or_else(|_| panic!("unknown trace storage profile fixture: {value}"))
}

fn default_scenario() -> HotColdArenaScenario {
    HotColdArenaScenario {
        scenario_id: DEFAULT_SCENARIO_ID.to_string(),
        description: "Deterministic large-host arena tiering comparison.".to_string(),
        requested_policy: "tiered_cold_evidence".to_string(),
        trace_storage_profile: "large_memory_256g".to_string(),
        host_requirements: HostRequirementsFixture {
            min_worker_threads: 64,
            min_memory_gib: 256,
        },
        workload_model: HotColdArenaWorkloadFixture {
            capacity_hints: CapacityHintsFixture {
                task_capacity: 32_768,
                region_capacity: 8_192,
                obligation_capacity: 16_384,
            },
            locality_profile_input: "pending_numa_locality_profile".to_string(),
            large_page_cold_slabs_supported: false,
            default_safe_fallback_profile: "unified".to_string(),
        },
        operator_notes: json!({
            "recommended_for": [
                "64+ core / 256GiB hosts that want retained evidence off the hot allocator path",
                "Operator dry-runs that need explicit fallback accounting before NUMA placement lands"
            ],
            "avoid_when": [
                "Hosts where default unified allocation is still the only approved policy"
            ],
            "fallback_policy": "unified"
        }),
        expected_report_projection: None,
    }
}

fn load_contract_scenario() -> HotColdArenaScenario {
    let Ok(contract_path) = std::env::var("ASUPERSYNC_HOT_COLD_ARENA_CONTRACT_PATH") else {
        return default_scenario();
    };
    let scenario_id = std::env::var("ASUPERSYNC_HOT_COLD_ARENA_SCENARIO")
        .unwrap_or_else(|_| DEFAULT_SCENARIO_ID.to_string());
    let contract: HotColdArenaContract = serde_json::from_str(
        &fs::read_to_string(&contract_path).expect("read hot/cold arena contract"),
    )
    .expect("parse hot/cold arena contract");
    contract
        .smoke_scenarios
        .into_iter()
        .find(|scenario| scenario.scenario_id == scenario_id)
        .unwrap_or_else(|| panic!("scenario {scenario_id} missing from {contract_path}"))
}

fn report_fields_json(config: &RuntimeConfig, large_page_cold_slabs_supported: bool) -> Value {
    let report = config.arena_temperature_report(large_page_cold_slabs_supported);
    let mut fields = serde_json::Map::new();
    for (key, value) in report.render_report_fields() {
        fields.insert(key.to_string(), Value::String(value));
    }
    fields.insert(
        "requested_policy_name".to_string(),
        Value::String(report.requested_policy.as_str().to_string()),
    );
    fields.insert(
        "effective_policy_name".to_string(),
        Value::String(report.effective_policy.as_str().to_string()),
    );
    fields.insert(
        "cold_allocation_source_name".to_string(),
        Value::String(report.cold_allocation_source.as_str().to_string()),
    );
    fields.insert(
        "fallback_reason_name".to_string(),
        report.fallback_reason.map_or(Value::Null, |reason| {
            Value::String(reason.as_str().to_string())
        }),
    );
    Value::Object(fields)
}

fn projection_hash(mut projection: Value) -> Value {
    let mut hasher = DefaultHasher::new();
    serde_json::to_string(&projection)
        .expect("serialize projection")
        .hash(&mut hasher);
    projection
        .as_object_mut()
        .expect("projection object")
        .insert("projection_hash".to_string(), json!(hasher.finish()));
    projection
}

fn build_report(scenario: &HotColdArenaScenario) -> Value {
    let capacity_hints = scenario.workload_model.capacity_hints.into_runtime_hints();
    let trace_storage_profile = parse_trace_storage_profile(&scenario.trace_storage_profile);
    let requested_policy = parse_policy(&scenario.requested_policy);

    let mut default_config = RuntimeConfig::default();
    default_config.worker_threads = scenario.host_requirements.min_worker_threads;
    default_config.capacity_hints = Some(capacity_hints);
    default_config.trace_storage_profile = trace_storage_profile;
    default_config.arena_temperature_policy = ArenaTemperaturePolicy::Unified;

    let mut candidate_config = default_config.clone();
    candidate_config.arena_temperature_policy = requested_policy;

    let default_report = default_config
        .arena_temperature_report(scenario.workload_model.large_page_cold_slabs_supported);
    let candidate_report = candidate_config
        .arena_temperature_report(scenario.workload_model.large_page_cold_slabs_supported);

    let hot_bytes_preserved =
        default_report.estimated_hot_bytes() == candidate_report.estimated_hot_bytes();
    let retained_evidence_preserved =
        default_report.retained_evidence_bytes == candidate_report.retained_evidence_bytes;
    let cold_ratio = if candidate_report.retained_evidence_bytes == 0 {
        0.0
    } else {
        round4(
            candidate_report.cold_evidence_bytes as f64
                / candidate_report.retained_evidence_bytes as f64,
        )
    };
    let hot_share_of_total = if candidate_report.estimated_total_bytes() == 0 {
        0.0
    } else {
        round4(
            candidate_report.estimated_hot_bytes() as f64
                / candidate_report.estimated_total_bytes() as f64,
        )
    };
    let operator_verdict = if candidate_report.fallback_reason.is_some() {
        "fallback_without_large_pages"
    } else if candidate_report.cold_evidence_bytes == 0 {
        "stay_unified"
    } else {
        "tiered_retention_active"
    };
    let no_win_trigger = if !hot_bytes_preserved {
        "hot_bytes_drifted"
    } else if !retained_evidence_preserved {
        "retained_evidence_drifted"
    } else if candidate_report.fallback_reason.is_some() {
        "large_pages_unsupported"
    } else {
        "none"
    };

    let projection = projection_hash(json!({
        "schema_version": "hot-cold-arena-tiers-smoke-projection-v1",
        "scenario_id": scenario.scenario_id.as_str(),
        "requested_policy": requested_policy.as_str(),
        "effective_policy": candidate_report.effective_policy.as_str(),
        "fallback_reason": candidate_report.fallback_reason.map(|reason| reason.as_str()),
        "cold_allocation_source": candidate_report.cold_allocation_source.as_str(),
        "large_page_cold_slabs_active": candidate_report.large_page_cold_slabs_active,
        "hot_bytes_preserved": hot_bytes_preserved,
        "retained_evidence_preserved": retained_evidence_preserved,
        "default_estimated_hot_bytes": default_report.estimated_hot_bytes(),
        "candidate_estimated_hot_bytes": candidate_report.estimated_hot_bytes(),
        "retained_evidence_bytes": candidate_report.retained_evidence_bytes,
        "candidate_cold_evidence_bytes": candidate_report.cold_evidence_bytes,
        "cold_tier_retention_ratio": cold_ratio,
        "hot_share_of_total_bytes": hot_share_of_total,
        "locality_profile_input": scenario.workload_model.locality_profile_input.as_str(),
        "safe_fallback_profile": scenario.workload_model.default_safe_fallback_profile.as_str(),
        "operator_verdict": operator_verdict,
        "no_win_trigger": no_win_trigger,
    }));

    json!({
        "schema_version": "asupersync.hot-cold-arena-tier-comparison.v1",
        "scenario_id": scenario.scenario_id.as_str(),
        "description": scenario.description.as_str(),
        "requested_policy": requested_policy.as_str(),
        "trace_storage_profile": trace_storage_profile.as_str(),
        "host_requirements": {
            "worker_threads": scenario.host_requirements.min_worker_threads,
            "memory_gib": scenario.host_requirements.min_memory_gib,
        },
        "capacity_hints": {
            "task_capacity": capacity_hints.task_capacity,
            "region_capacity": capacity_hints.region_capacity,
            "obligation_capacity": capacity_hints.obligation_capacity,
        },
        "locality_profile_input": scenario.workload_model.locality_profile_input.as_str(),
        "large_page_cold_slabs_supported": scenario.workload_model.large_page_cold_slabs_supported,
        "default_safe_fallback_profile": scenario.workload_model.default_safe_fallback_profile.as_str(),
        "default_policy_report": report_fields_json(
            &default_config,
            scenario.workload_model.large_page_cold_slabs_supported,
        ),
        "candidate_policy_report": report_fields_json(
            &candidate_config,
            scenario.workload_model.large_page_cold_slabs_supported,
        ),
        "comparison": {
            "allocator_interference_proxy_basis": "hot allocator bytes stay constant while retained evidence moves to the cold tier",
            "hot_bytes_preserved": hot_bytes_preserved,
            "retained_evidence_preserved": retained_evidence_preserved,
            "cold_tier_retention_ratio": cold_ratio,
            "hot_share_of_total_bytes": hot_share_of_total,
            "operator_verdict": operator_verdict,
            "no_win_trigger": no_win_trigger,
        },
        "operator_notes": scenario.operator_notes.clone(),
        "validation_verdict": {
            "status": "passed",
            "checks": [
                "candidate policy preserves the hot-byte budget relative to unified mode",
                "candidate policy preserves retained evidence bytes while exposing cold-tier accounting",
                "large-page fallback remains explicit when the host support probe is false"
            ]
        },
        "report_projection": projection,
    })
}

fn maybe_write_report(path: &str, report: &Value) {
    let report_path = Path::new(path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).expect("create hot/cold arena report directory");
    }
    fs::write(
        report_path,
        serde_json::to_string_pretty(report).expect("serialize hot/cold arena report"),
    )
    .expect("write hot/cold arena report");
}

#[test]
fn tiered_cold_evidence_moves_retained_evidence_without_changing_hot_bytes() {
    let mut config = RuntimeConfig::default();
    config.capacity_hints = Some(RuntimeCapacityHints::new(32_768, 8_192, 16_384));
    config.trace_storage_profile = TraceStorageProfile::LargeMemory256G;
    config.arena_temperature_policy = ArenaTemperaturePolicy::TieredColdEvidence;

    let default_report = RuntimeConfig {
        arena_temperature_policy: ArenaTemperaturePolicy::Unified,
        ..config.clone()
    }
    .arena_temperature_report(false);
    let tiered_report = config.arena_temperature_report(false);

    assert_eq!(
        tiered_report.estimated_hot_bytes(),
        default_report.estimated_hot_bytes(),
        "tiered retention should not move hot runtime metadata out of the hot-byte budget"
    );
    assert_eq!(
        tiered_report.retained_evidence_bytes, default_report.retained_evidence_bytes,
        "tiered retention should preserve retained evidence volume"
    );
    assert_eq!(
        tiered_report.cold_evidence_bytes, tiered_report.retained_evidence_bytes,
        "tiered retention should route all retained evidence bytes to the cold tier"
    );
}

#[test]
fn large_page_policy_falls_back_cleanly_when_support_is_absent() {
    let mut config = RuntimeConfig::default();
    config.capacity_hints = Some(RuntimeCapacityHints::new(32_768, 8_192, 16_384));
    config.trace_storage_profile = TraceStorageProfile::LargeMemory256G;
    config.arena_temperature_policy = ArenaTemperaturePolicy::TieredColdEvidenceLargePages;

    let report = config.arena_temperature_report(false);

    assert_eq!(
        report.effective_policy,
        ArenaTemperaturePolicy::TieredColdEvidence,
        "unsupported large pages must conservatively fall back to the non-large-page cold tier"
    );
    assert_eq!(
        report.fallback_reason.map(|reason| reason.as_str()),
        Some("large_pages_unsupported"),
        "fallback reason should remain stable for operator reports"
    );
    assert!(!report.large_page_cold_slabs_active);
}

#[test]
fn hot_cold_arena_tiers_smoke_contract_emits_operator_report() {
    let scenario = load_contract_scenario();
    let report = build_report(&scenario);
    if let Some(expected_projection) = scenario.expected_report_projection {
        assert_eq!(
            report["report_projection"], expected_projection,
            "hot/cold arena smoke projection should remain stable"
        );
    } else {
        assert!(
            report["report_projection"].is_object(),
            "hot/cold arena smoke report should always emit a projection"
        );
    }

    assert_eq!(
        report["comparison"]["hot_bytes_preserved"].as_bool(),
        Some(true),
        "candidate policy should preserve the hot-byte budget"
    );
    assert_eq!(
        report["comparison"]["retained_evidence_preserved"].as_bool(),
        Some(true),
        "candidate policy should preserve retained evidence bytes"
    );

    if let Ok(report_path) = std::env::var("ASUPERSYNC_HOT_COLD_ARENA_REPORT_PATH") {
        maybe_write_report(&report_path, &report);
        println!("hot_cold_arena_report_path={report_path}");
        println!("HOT_COLD_ARENA_REPORT_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string(&report).expect("serialize compact hot/cold arena report")
        );
        println!("HOT_COLD_ARENA_REPORT_JSON_END");
    }
}
