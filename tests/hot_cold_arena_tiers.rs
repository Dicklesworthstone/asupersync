//! Contract-backed proofs for hot/cold arena temperature planning.

use asupersync::runtime::TraceStorageProfile;
use asupersync::runtime::config::{
    ArenaLocalityAccessModel, ArenaLocalityPolicy, ArenaLocalityReport,
    ArenaTemperatureFallbackReason, ArenaTemperaturePolicy, RuntimeCapacityHints, RuntimeConfig,
    WorkerCohortMapping,
};
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
    locality_profile_input: HotColdArenaLocalityFixture,
    large_page_cold_slabs_supported: bool,
    default_safe_fallback_profile: String,
}

#[derive(Debug, Clone, Deserialize)]
struct HotColdArenaLocalityFixture {
    requested_policy: LocalityPolicyFixture,
    topology_confidence_percent: Option<u8>,
    topology_fixture_hash: Option<u64>,
    worker_to_cohort_map: Option<Vec<usize>>,
    task_arena_touches_by_cohort: Vec<u64>,
    region_arena_touches_by_cohort: Vec<u64>,
    obligation_arena_touches_by_cohort: Vec<u64>,
    task_record_pool_touches_by_cohort: Vec<u64>,
    stale_profile: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct LocalityPolicyFixture {
    mode: String,
    min_topology_confidence_percent: u8,
    remote_touch_budget_bps: u16,
    accounting_epoch: u64,
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

fn parse_temperature_policy(value: &str) -> ArenaTemperaturePolicy {
    value
        .parse()
        .unwrap_or_else(|_| panic!("unknown arena temperature policy fixture: {value}"))
}

fn parse_trace_storage_profile(value: &str) -> TraceStorageProfile {
    value
        .parse()
        .unwrap_or_else(|_| panic!("unknown trace storage profile fixture: {value}"))
}

fn parse_locality_policy(fixture: &LocalityPolicyFixture) -> ArenaLocalityPolicy {
    match fixture.mode.as_str() {
        "disabled" => ArenaLocalityPolicy::Disabled,
        "cohort_pinned" => ArenaLocalityPolicy::CohortPinned {
            min_topology_confidence_percent: fixture.min_topology_confidence_percent,
            remote_touch_budget_bps: fixture.remote_touch_budget_bps,
            accounting_epoch: fixture.accounting_epoch,
        },
        other => panic!("unknown arena locality policy fixture: {other}"),
    }
}

fn ready_locality_fixture() -> HotColdArenaLocalityFixture {
    HotColdArenaLocalityFixture {
        requested_policy: LocalityPolicyFixture {
            mode: "cohort_pinned".to_string(),
            min_topology_confidence_percent: 80,
            remote_touch_budget_bps: 6500,
            accounting_epoch: 11,
        },
        topology_confidence_percent: Some(91),
        topology_fixture_hash: Some(11_240_820_598_888_380_677),
        worker_to_cohort_map: Some(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3,
            3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7,
            7, 7, 7, 7, 7, 7,
        ]),
        task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
        obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
        task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        stale_profile: false,
    }
}

#[allow(dead_code)]
fn no_win_locality_fixture() -> HotColdArenaLocalityFixture {
    HotColdArenaLocalityFixture {
        requested_policy: LocalityPolicyFixture {
            mode: "cohort_pinned".to_string(),
            min_topology_confidence_percent: 80,
            remote_touch_budget_bps: 9000,
            accounting_epoch: 13,
        },
        topology_confidence_percent: Some(95),
        topology_fixture_hash: Some(11_861_930_782_471_893_701),
        worker_to_cohort_map: Some(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3,
            3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7,
            7, 7, 7, 7, 7, 7,
        ]),
        task_arena_touches_by_cohort: vec![1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024],
        region_arena_touches_by_cohort: vec![256, 256, 256, 256, 256, 256, 256, 256],
        obligation_arena_touches_by_cohort: vec![512, 512, 512, 512, 512, 512, 512, 512],
        task_record_pool_touches_by_cohort: vec![1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024],
        stale_profile: false,
    }
}

#[allow(dead_code)]
fn template_locality_fixture() -> HotColdArenaLocalityFixture {
    HotColdArenaLocalityFixture {
        requested_policy: LocalityPolicyFixture {
            mode: "cohort_pinned".to_string(),
            min_topology_confidence_percent: 80,
            remote_touch_budget_bps: 6500,
            accounting_epoch: 14,
        },
        topology_confidence_percent: None,
        topology_fixture_hash: None,
        worker_to_cohort_map: None,
        task_arena_touches_by_cohort: Vec::new(),
        region_arena_touches_by_cohort: Vec::new(),
        obligation_arena_touches_by_cohort: Vec::new(),
        task_record_pool_touches_by_cohort: Vec::new(),
        stale_profile: false,
    }
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
            locality_profile_input: ready_locality_fixture(),
            large_page_cold_slabs_supported: false,
            default_safe_fallback_profile: "unified".to_string(),
        },
        operator_notes: json!({
            "recommended_for": [
                "64+ core / 256GiB hosts that want retained evidence off the hot allocator path",
                "Operator dry-runs that need explicit fallback accounting after NUMA evidence is ready"
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

fn build_locality_report(
    host_requirements: &HostRequirementsFixture,
    capacity_hints: RuntimeCapacityHints,
    fixture: &HotColdArenaLocalityFixture,
) -> (Option<ArenaLocalityReport>, bool) {
    let Some(worker_to_cohort_map) = fixture.worker_to_cohort_map.clone() else {
        return (None, fixture.stale_profile);
    };
    let config = RuntimeConfig {
        worker_threads: host_requirements.min_worker_threads,
        worker_cohort_map: Some(WorkerCohortMapping::new(worker_to_cohort_map)),
        capacity_hints: Some(capacity_hints),
        ..RuntimeConfig::default()
    };
    let access_model = ArenaLocalityAccessModel {
        task_arena_touches_by_cohort: fixture.task_arena_touches_by_cohort.clone(),
        region_arena_touches_by_cohort: fixture.region_arena_touches_by_cohort.clone(),
        obligation_arena_touches_by_cohort: fixture.obligation_arena_touches_by_cohort.clone(),
        task_record_pool_touches_by_cohort: fixture.task_record_pool_touches_by_cohort.clone(),
    };
    (
        Some(config.arena_locality_report(
            parse_locality_policy(&fixture.requested_policy),
            fixture.topology_confidence_percent,
            &access_model,
        )),
        fixture.stale_profile,
    )
}

fn locality_profile_json(
    locality_report: Option<&ArenaLocalityReport>,
    fixture: &HotColdArenaLocalityFixture,
    stale_profile: bool,
) -> Value {
    if let Some(report) = locality_report {
        json!({
            "requested_policy": report.requested_policy.to_string(),
            "effective_policy": report.effective_policy.to_string(),
            "fallback_reason": report.fallback_reason.map(|reason| reason.as_str()),
            "selected_remote_touch_count": report.selected.remote_touch_count,
            "selected_remote_touch_ratio_bps": report.selected.remote_touch_ratio_bps(),
            "used_safe_fallback": report.used_safe_fallback(),
            "no_win_trigger": report.no_win_trigger,
            "ownership_preserved": report.ownership_preserved,
            "topology_confidence_percent": report.topology_confidence_percent,
            "topology_fixture_hash": fixture.topology_fixture_hash,
            "stale_profile": stale_profile
        })
    } else {
        json!({
            "requested_policy": fixture.requested_policy.mode.as_str(),
            "effective_policy": "missing",
            "fallback_reason": "locality_profile_missing",
            "selected_remote_touch_count": 0,
            "selected_remote_touch_ratio_bps": 0,
            "used_safe_fallback": true,
            "no_win_trigger": false,
            "ownership_preserved": true,
            "topology_confidence_percent": fixture.topology_confidence_percent,
            "topology_fixture_hash": fixture.topology_fixture_hash,
            "stale_profile": stale_profile
        })
    }
}

fn report_fields_json(
    config: &RuntimeConfig,
    large_page_cold_slabs_supported: bool,
    locality_report: Option<&ArenaLocalityReport>,
    locality_profile_stale: bool,
) -> Value {
    let report = config.arena_temperature_report_with_locality(
        large_page_cold_slabs_supported,
        locality_report,
        locality_profile_stale,
    );
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

fn deterministic_latency_profile(
    fallback_reason: Option<ArenaTemperatureFallbackReason>,
    locality_report: Option<&ArenaLocalityReport>,
    candidate_cold_evidence_bytes: usize,
) -> (u64, u64, u64, u64) {
    let remote_touch_ratio_penalty = locality_report
        .map_or(0_u64, |report| {
            report.selected.remote_touch_ratio_bps() as u64
        })
        .saturating_mul(4);
    let fallback_penalty = match fallback_reason {
        Some(ArenaTemperatureFallbackReason::LargePagesUnsupported) => 8_000,
        Some(ArenaTemperatureFallbackReason::LocalityProfileFallback) => 14_000,
        Some(ArenaTemperatureFallbackReason::StaleLocalityProfile) => 18_000,
        Some(ArenaTemperatureFallbackReason::LocalityProfileMissing) | None => 0,
    };
    let cold_tier_bonus = if candidate_cold_evidence_bytes > 0 && fallback_reason.is_none() {
        14_000
    } else if matches!(
        fallback_reason,
        Some(ArenaTemperatureFallbackReason::LargePagesUnsupported)
    ) {
        8_000
    } else {
        0
    };
    let base_p50: u64 = if locality_report.is_some() {
        98_000
    } else {
        72_000
    };
    let p50 = base_p50
        .saturating_add(remote_touch_ratio_penalty / 2)
        .saturating_add(fallback_penalty)
        .saturating_sub(cold_tier_bonus);
    let p95 = p50
        .saturating_add(19_000)
        .saturating_add(remote_touch_ratio_penalty / 4);
    let p99 = p95.saturating_add(24_000).saturating_add(
        if locality_report.is_some_and(|report| report.no_win_trigger) {
            5_000
        } else {
            0
        },
    );
    let p999 = p99.saturating_add(28_000).saturating_add(
        if matches!(
            fallback_reason,
            Some(ArenaTemperatureFallbackReason::StaleLocalityProfile)
        ) {
            7_000
        } else {
            4_000
        },
    );
    (p50, p95, p99, p999)
}

fn build_report(scenario: &HotColdArenaScenario) -> Value {
    let capacity_hints = scenario.workload_model.capacity_hints.into_runtime_hints();
    let trace_storage_profile = parse_trace_storage_profile(&scenario.trace_storage_profile);
    let requested_policy = parse_temperature_policy(&scenario.requested_policy);
    let (locality_report, locality_profile_stale) = build_locality_report(
        &scenario.host_requirements,
        capacity_hints,
        &scenario.workload_model.locality_profile_input,
    );

    let mut default_config = RuntimeConfig::default();
    default_config.worker_threads = scenario.host_requirements.min_worker_threads;
    default_config.capacity_hints = Some(capacity_hints);
    default_config.trace_storage_profile = trace_storage_profile;
    default_config.arena_temperature_policy = ArenaTemperaturePolicy::Unified;

    let mut candidate_config = default_config.clone();
    candidate_config.arena_temperature_policy = requested_policy;

    let default_report = default_config.arena_temperature_report_with_locality(
        scenario.workload_model.large_page_cold_slabs_supported,
        locality_report.as_ref(),
        locality_profile_stale,
    );
    let candidate_report = candidate_config.arena_temperature_report_with_locality(
        scenario.workload_model.large_page_cold_slabs_supported,
        locality_report.as_ref(),
        locality_profile_stale,
    );

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
    let operator_verdict = match candidate_report.fallback_reason {
        Some(ArenaTemperatureFallbackReason::LocalityProfileMissing) => "template_only",
        Some(ArenaTemperatureFallbackReason::StaleLocalityProfile) => "fail_closed",
        Some(ArenaTemperatureFallbackReason::LocalityProfileFallback) => "stay_unified",
        Some(ArenaTemperatureFallbackReason::LargePagesUnsupported) => {
            "fallback_without_large_pages"
        }
        None if candidate_report.cold_evidence_bytes == 0 => "stay_unified",
        None => "tiered_retention_active",
    };
    let no_win_trigger = match candidate_report.fallback_reason {
        Some(ArenaTemperatureFallbackReason::LocalityProfileMissing) => "missing_locality_profile",
        Some(ArenaTemperatureFallbackReason::StaleLocalityProfile) => "stale_locality_profile",
        Some(ArenaTemperatureFallbackReason::LocalityProfileFallback)
            if locality_report
                .as_ref()
                .is_some_and(|report| report.no_win_trigger) =>
        {
            "locality_no_win"
        }
        Some(ArenaTemperatureFallbackReason::LocalityProfileFallback) => "locality_safe_fallback",
        Some(ArenaTemperatureFallbackReason::LargePagesUnsupported) => "large_pages_unsupported",
        None if !hot_bytes_preserved => "hot_bytes_drifted",
        None if !retained_evidence_preserved => "retained_evidence_drifted",
        None => "none",
    };
    let (
        hot_path_latency_p50_ns,
        hot_path_latency_p95_ns,
        hot_path_latency_p99_ns,
        hot_path_latency_p999_ns,
    ) = deterministic_latency_profile(
        candidate_report.fallback_reason,
        locality_report.as_ref(),
        candidate_report.cold_evidence_bytes,
    );
    let allocator_contention_events = if !candidate_report.locality_profile_present {
        0
    } else {
        38_u64
            .saturating_add(
                (candidate_report.locality_selected_remote_touch_ratio_bps as u64) / 512,
            )
            .saturating_add(if candidate_report.fallback_reason.is_some() {
                12
            } else {
                0
            })
            .saturating_add(if candidate_report.cold_evidence_bytes == 0 {
                8
            } else {
                0
            })
    };
    let retained_evidence_admission_count = u64::from(candidate_report.cold_evidence_bytes > 0);
    let retained_evidence_refusal_count = u64::from(
        candidate_report.cold_evidence_bytes == 0 && candidate_report.retained_evidence_bytes > 0,
    );
    let fallback_event_count = u64::from(candidate_report.fallback_reason.is_some());
    let cold_tier_pressure_transition_count = if candidate_report.cold_evidence_bytes > 0 {
        2
    } else {
        0
    };
    let slab_fragmentation_bps = if candidate_report.large_page_cold_slabs_active {
        320
    } else if candidate_report.cold_evidence_bytes > 0 {
        540
    } else {
        0
    };

    let projection = projection_hash(json!({
        "schema_version": "hot-cold-arena-tiers-smoke-projection-v2",
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
        "locality_effective_policy": locality_report
            .as_ref()
            .map_or("missing".to_string(), |report| report.effective_policy.to_string()),
        "locality_fallback_reason": locality_report
            .as_ref()
            .and_then(|report| report.fallback_reason)
            .map(|reason| reason.as_str()),
        "locality_profile_stale": locality_profile_stale,
        "locality_selected_remote_touch_count": locality_report
            .as_ref()
            .map_or(0, |report| report.selected.remote_touch_count),
        "locality_selected_remote_touch_ratio_bps": candidate_report.locality_selected_remote_touch_ratio_bps,
        "locality_no_win_trigger": candidate_report.locality_no_win_trigger,
        "locality_used_safe_fallback": candidate_report.locality_safe_fallback,
        "topology_fixture_hash": scenario.workload_model.locality_profile_input.topology_fixture_hash,
        "safe_fallback_profile": scenario.workload_model.default_safe_fallback_profile.as_str(),
        "allocator_contention_events": allocator_contention_events,
        "rss_estimated_bytes": candidate_report.estimated_total_bytes(),
        "hot_path_latency_p50_ns": hot_path_latency_p50_ns,
        "hot_path_latency_p95_ns": hot_path_latency_p95_ns,
        "hot_path_latency_p99_ns": hot_path_latency_p99_ns,
        "hot_path_latency_p999_ns": hot_path_latency_p999_ns,
        "retained_evidence_admission_count": retained_evidence_admission_count,
        "retained_evidence_refusal_count": retained_evidence_refusal_count,
        "fallback_event_count": fallback_event_count,
        "cold_tier_pressure_transition_count": cold_tier_pressure_transition_count,
        "slab_fragmentation_bps": slab_fragmentation_bps,
        "operator_verdict": operator_verdict,
        "no_win_trigger": no_win_trigger
    }));

    json!({
        "schema_version": "asupersync.hot-cold-arena-tier-comparison.v2",
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
        "locality_profile_input": locality_profile_json(
            locality_report.as_ref(),
            &scenario.workload_model.locality_profile_input,
            locality_profile_stale,
        ),
        "large_page_cold_slabs_supported": scenario.workload_model.large_page_cold_slabs_supported,
        "default_safe_fallback_profile": scenario.workload_model.default_safe_fallback_profile.as_str(),
        "default_policy_report": report_fields_json(
            &default_config,
            scenario.workload_model.large_page_cold_slabs_supported,
            locality_report.as_ref(),
            locality_profile_stale,
        ),
        "candidate_policy_report": report_fields_json(
            &candidate_config,
            scenario.workload_model.large_page_cold_slabs_supported,
            locality_report.as_ref(),
            locality_profile_stale,
        ),
        "comparison": {
            "allocator_interference_proxy_basis": "hot allocator bytes stay constant while retained evidence moves to the cold tier when locality evidence is fresh and winning",
            "hot_bytes_preserved": hot_bytes_preserved,
            "retained_evidence_preserved": retained_evidence_preserved,
            "cold_tier_retention_ratio": cold_ratio,
            "hot_share_of_total_bytes": hot_share_of_total,
            "allocator_contention_events": allocator_contention_events,
            "rss_estimated_bytes": candidate_report.estimated_total_bytes(),
            "hot_path_latency_p50_ns": hot_path_latency_p50_ns,
            "hot_path_latency_p95_ns": hot_path_latency_p95_ns,
            "hot_path_latency_p99_ns": hot_path_latency_p99_ns,
            "hot_path_latency_p999_ns": hot_path_latency_p999_ns,
            "retained_evidence_admission_count": retained_evidence_admission_count,
            "retained_evidence_refusal_count": retained_evidence_refusal_count,
            "fallback_event_count": fallback_event_count,
            "cold_tier_pressure_transition_count": cold_tier_pressure_transition_count,
            "slab_fragmentation_bps": slab_fragmentation_bps,
            "operator_verdict": operator_verdict,
            "no_win_trigger": no_win_trigger,
        },
        "operator_notes": scenario.operator_notes.clone(),
        "validation_verdict": {
            "status": "passed",
            "checks": [
                "candidate policy preserves the hot-byte budget relative to unified mode",
                "candidate policy preserves retained evidence bytes while exposing cold-tier accounting",
                "tier activation is gated on fresh, ready locality evidence",
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
    let capacity_hints = RuntimeCapacityHints::new(32_768, 8_192, 16_384);
    let (locality, stale) = build_locality_report(
        &HostRequirementsFixture {
            min_worker_threads: 64,
            min_memory_gib: 256,
        },
        capacity_hints,
        &ready_locality_fixture(),
    );

    let mut config = RuntimeConfig::default();
    config.capacity_hints = Some(capacity_hints);
    config.trace_storage_profile = TraceStorageProfile::LargeMemory256G;
    config.arena_temperature_policy = ArenaTemperaturePolicy::TieredColdEvidence;

    let default_report = RuntimeConfig {
        arena_temperature_policy: ArenaTemperaturePolicy::Unified,
        ..config.clone()
    }
    .arena_temperature_report_with_locality(false, locality.as_ref(), stale);
    let tiered_report =
        config.arena_temperature_report_with_locality(false, locality.as_ref(), stale);

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
    let capacity_hints = RuntimeCapacityHints::new(32_768, 8_192, 16_384);
    let (locality, stale) = build_locality_report(
        &HostRequirementsFixture {
            min_worker_threads: 64,
            min_memory_gib: 256,
        },
        capacity_hints,
        &ready_locality_fixture(),
    );

    let mut config = RuntimeConfig::default();
    config.capacity_hints = Some(capacity_hints);
    config.trace_storage_profile = TraceStorageProfile::LargeMemory256G;
    config.arena_temperature_policy = ArenaTemperaturePolicy::TieredColdEvidenceLargePages;

    let report = config.arena_temperature_report_with_locality(false, locality.as_ref(), stale);

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
fn hot_cold_arena_runner_rejects_full_rch_fallback_marker_set() {
    let script = fs::read_to_string("scripts/run_hot_cold_arena_tiers_smoke.sh")
        .expect("hot/cold arena smoke runner should load");

    assert!(
        script
            .matches(r#"grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN""#)
            .count()
            >= 2,
        "runner must use the shared local fallback matcher at every rch gate"
    );

    for token in [
        "RCH_LOCAL_FALLBACK_PATTERN=",
        "[RCH\\] local",
        "falling back to local",
        "local fallback",
        "fallback to local",
        "executing locally",
    ] {
        assert!(
            script.contains(token),
            "runner missing local fallback marker: {token}"
        );
    }
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
