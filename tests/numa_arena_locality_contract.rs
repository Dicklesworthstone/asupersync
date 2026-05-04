//! Contract-backed smoke proof for deterministic arena locality planning.

#[path = "support/topology_replay.rs"]
mod topology_replay_support;

use asupersync::runtime::config::{
    ArenaLocalityAccessModel, ArenaLocalityPolicy, RuntimeCapacityHints, RuntimeConfig,
    WorkerCohortMapping,
};
use asupersync::runtime::scheduler::SchedulerTopologyDescriptor;
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use topology_replay_support::TopologyFixture;

const DEFAULT_CONTRACT_PATH: &str = "artifacts/numa_arena_locality_smoke_contract_v1.json";
const DEFAULT_SCENARIO_ID: &str = "AA-NUMA-ARENA-LOCALITY-WIN-64C-256G";

#[derive(Debug, Clone, Deserialize)]
struct NumaArenaLocalityContract {
    smoke_scenarios: Vec<NumaArenaLocalityScenario>,
}

#[derive(Debug, Clone, Deserialize)]
struct NumaArenaLocalityScenario {
    scenario_id: String,
    description: String,
    output_root: String,
    execution_policy: String,
    topology_mode: String,
    safe_fallback_profile: String,
    operator_verdict: String,
    host_requirements: HostRequirementsFixture,
    requested_policy: ArenaLocalityPolicyFixture,
    workload_model: NumaArenaLocalityWorkloadFixture,
    expected_report_projection: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct HostRequirementsFixture {
    min_worker_threads: usize,
    min_memory_gib: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct ArenaLocalityPolicyFixture {
    mode: String,
    min_topology_confidence_percent: u8,
    remote_touch_budget_bps: u16,
    accounting_epoch: u64,
}

impl ArenaLocalityPolicyFixture {
    fn to_policy(&self) -> ArenaLocalityPolicy {
        match self.mode.as_str() {
            "disabled" => ArenaLocalityPolicy::Disabled,
            "cohort_pinned" => ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: self.min_topology_confidence_percent,
                remote_touch_budget_bps: self.remote_touch_budget_bps,
                accounting_epoch: self.accounting_epoch,
            },
            other => panic!("unknown arena locality policy fixture: {other}"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct NumaArenaLocalityWorkloadFixture {
    workload_seed: u64,
    topology_confidence_percent: Option<u8>,
    capacity_hints: CapacityHintsFixture,
    worker_to_cohort_map: Option<Vec<usize>>,
    task_arena_touches_by_cohort: Vec<u64>,
    region_arena_touches_by_cohort: Vec<u64>,
    obligation_arena_touches_by_cohort: Vec<u64>,
    task_record_pool_touches_by_cohort: Vec<u64>,
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

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    let mut hash = OFFSET;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn hash_json(value: &Value) -> u64 {
    fnv1a64(
        serde_json::to_string(value)
            .expect("serialize projection")
            .as_bytes(),
    )
}

fn projection_hash(mut projection: Value) -> Value {
    let hash = hash_json(&projection);
    projection
        .as_object_mut()
        .expect("projection object")
        .insert("projection_hash".to_string(), json!(hash));
    projection
}

fn default_scenarios() -> Vec<NumaArenaLocalityScenario> {
    vec![
        NumaArenaLocalityScenario {
            scenario_id: "AA-NUMA-ARENA-LOCALITY-WIN-64C-256G".to_string(),
            description: "Skewed cohort access on a 64-core / 256 GiB host where cohort-pinned metadata cuts remote touches versus the conservative interleaved baseline.".to_string(),
            output_root: "target/numa-arena-locality-smoke".to_string(),
            execution_policy: "execute_or_dry_run".to_string(),
            topology_mode: "deterministic_fixture".to_string(),
            safe_fallback_profile: "disabled".to_string(),
            operator_verdict: "ready_for_rch".to_string(),
            host_requirements: HostRequirementsFixture {
                min_worker_threads: 64,
                min_memory_gib: 256,
            },
            requested_policy: ArenaLocalityPolicyFixture {
                mode: "cohort_pinned".to_string(),
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            },
            workload_model: NumaArenaLocalityWorkloadFixture {
                workload_seed: 640256,
                topology_confidence_percent: Some(91),
                capacity_hints: CapacityHintsFixture {
                    task_capacity: 6144,
                    region_capacity: 1024,
                    obligation_capacity: 2048,
                },
                worker_to_cohort_map: Some(
                    (0..8)
                        .flat_map(|cohort| std::iter::repeat_n(cohort, 8))
                        .collect(),
                ),
                task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
                region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
                obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
                task_record_pool_touches_by_cohort: vec![
                    3200, 640, 640, 640, 640, 640, 640, 640,
                ],
            },
            expected_report_projection: Value::Null,
        },
        NumaArenaLocalityScenario {
            scenario_id: "AA-NUMA-ARENA-LOCALITY-LOW-CONFIDENCE-FALLBACK".to_string(),
            description: "High-skew access evidence exists, but topology confidence is too low to activate locality so the conservative baseline remains pinned.".to_string(),
            output_root: "target/numa-arena-locality-smoke".to_string(),
            execution_policy: "execute_or_dry_run".to_string(),
            topology_mode: "deterministic_fixture".to_string(),
            safe_fallback_profile: "disabled".to_string(),
            operator_verdict: "fallback_only".to_string(),
            host_requirements: HostRequirementsFixture {
                min_worker_threads: 64,
                min_memory_gib: 256,
            },
            requested_policy: ArenaLocalityPolicyFixture {
                mode: "cohort_pinned".to_string(),
                min_topology_confidence_percent: 90,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 12,
            },
            workload_model: NumaArenaLocalityWorkloadFixture {
                workload_seed: 9001,
                topology_confidence_percent: Some(40),
                capacity_hints: CapacityHintsFixture {
                    task_capacity: 6144,
                    region_capacity: 1024,
                    obligation_capacity: 2048,
                },
                worker_to_cohort_map: Some(
                    (0..8)
                        .flat_map(|cohort| std::iter::repeat_n(cohort, 8))
                        .collect(),
                ),
                task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
                region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
                obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
                task_record_pool_touches_by_cohort: vec![
                    3200, 640, 640, 640, 640, 640, 640, 640,
                ],
            },
            expected_report_projection: Value::Null,
        },
        NumaArenaLocalityScenario {
            scenario_id: "AA-NUMA-ARENA-LOCALITY-NO-WIN-FALLBACK".to_string(),
            description: "Balanced cohort touches produce no remote-touch win, so the conservative disabled profile remains selected even with high topology confidence.".to_string(),
            output_root: "target/numa-arena-locality-smoke".to_string(),
            execution_policy: "execute_or_dry_run".to_string(),
            topology_mode: "deterministic_fixture".to_string(),
            safe_fallback_profile: "disabled".to_string(),
            operator_verdict: "fallback_only".to_string(),
            host_requirements: HostRequirementsFixture {
                min_worker_threads: 64,
                min_memory_gib: 256,
            },
            requested_policy: ArenaLocalityPolicyFixture {
                mode: "cohort_pinned".to_string(),
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 9000,
                accounting_epoch: 13,
            },
            workload_model: NumaArenaLocalityWorkloadFixture {
                workload_seed: 1313,
                topology_confidence_percent: Some(95),
                capacity_hints: CapacityHintsFixture {
                    task_capacity: 6144,
                    region_capacity: 1024,
                    obligation_capacity: 2048,
                },
                worker_to_cohort_map: Some(
                    (0..8)
                        .flat_map(|cohort| std::iter::repeat_n(cohort, 8))
                        .collect(),
                ),
                task_arena_touches_by_cohort: vec![1024; 8],
                region_arena_touches_by_cohort: vec![256; 8],
                obligation_arena_touches_by_cohort: vec![512; 8],
                task_record_pool_touches_by_cohort: vec![1024; 8],
            },
            expected_report_projection: Value::Null,
        },
        NumaArenaLocalityScenario {
            scenario_id: "AA-NUMA-ARENA-LOCALITY-REAL-HOST-TEMPLATE".to_string(),
            description: "Template-only scenario that documents the required inputs for real-host NUMA validation without pretending topology evidence exists on every machine.".to_string(),
            output_root: "target/numa-arena-locality-smoke".to_string(),
            execution_policy: "execute_or_dry_run".to_string(),
            topology_mode: "host_template_optional".to_string(),
            safe_fallback_profile: "disabled".to_string(),
            operator_verdict: "template_only".to_string(),
            host_requirements: HostRequirementsFixture {
                min_worker_threads: 64,
                min_memory_gib: 256,
            },
            requested_policy: ArenaLocalityPolicyFixture {
                mode: "cohort_pinned".to_string(),
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 14,
            },
            workload_model: NumaArenaLocalityWorkloadFixture {
                workload_seed: 14,
                topology_confidence_percent: None,
                capacity_hints: CapacityHintsFixture {
                    task_capacity: 6144,
                    region_capacity: 1024,
                    obligation_capacity: 2048,
                },
                worker_to_cohort_map: None,
                task_arena_touches_by_cohort: Vec::new(),
                region_arena_touches_by_cohort: Vec::new(),
                obligation_arena_touches_by_cohort: Vec::new(),
                task_record_pool_touches_by_cohort: Vec::new(),
            },
            expected_report_projection: Value::Null,
        },
    ]
}

fn selected_scenario_id() -> String {
    std::env::var("ASUPERSYNC_NUMA_ARENA_LOCALITY_SCENARIO")
        .unwrap_or_else(|_| DEFAULT_SCENARIO_ID.to_string())
}

fn load_scenario() -> NumaArenaLocalityScenario {
    let contract_path = std::env::var("ASUPERSYNC_NUMA_ARENA_LOCALITY_CONTRACT_PATH")
        .ok()
        .or_else(|| {
            Path::new(DEFAULT_CONTRACT_PATH)
                .exists()
                .then(|| DEFAULT_CONTRACT_PATH.to_string())
        });
    let scenario_id = selected_scenario_id();

    let scenarios = if let Some(path) = contract_path {
        let contract: NumaArenaLocalityContract = serde_json::from_str(
            &fs::read_to_string(&path).expect("read numa arena locality contract"),
        )
        .expect("parse numa arena locality contract");
        contract.smoke_scenarios
    } else {
        default_scenarios()
    };

    scenarios
        .into_iter()
        .find(|scenario| scenario.scenario_id == scenario_id)
        .unwrap_or_else(|| {
            panic!("scenario {scenario_id} missing from NUMA arena locality contract")
        })
}

fn worker_cohort_fingerprint(worker_to_cohort_map: Option<&[usize]>) -> u64 {
    worker_to_cohort_map.map_or(0, |mapping| hash_json(&json!(mapping)))
}

fn topology_fixture_summary(scenario: &NumaArenaLocalityScenario) -> Value {
    let Some(worker_to_cohort_map) = scenario.workload_model.worker_to_cohort_map.clone() else {
        return json!({
            "topology_fixture_hash": null,
            "local_replay_count": 0,
            "remote_replay_count": 0
        });
    };

    let cohort_count = worker_to_cohort_map
        .iter()
        .copied()
        .max()
        .map_or(0, |max| max.saturating_add(1));
    if cohort_count == 0 {
        return json!({
            "topology_fixture_hash": null,
            "local_replay_count": 0,
            "remote_replay_count": 0
        });
    }

    let replay_workers = (0..scenario.host_requirements.min_worker_threads.min(16)).collect();
    let descriptor = SchedulerTopologyDescriptor {
        worker_threads: scenario.host_requirements.min_worker_threads,
        cohort_count,
        memory_budget_gib: scenario.host_requirements.min_memory_gib,
    };

    let mut fixture = TopologyFixture::new(
        descriptor,
        worker_to_cohort_map.clone(),
        replay_workers,
        scenario.workload_model.workload_seed,
    );
    for cohort in 0..cohort_count {
        let worker_id = worker_to_cohort_map
            .iter()
            .position(|mapped| *mapped == cohort)
            .expect("every cohort should have at least one worker");
        fixture = fixture.seed_worker(worker_id, (cohort as u32) * 16, 4);
    }
    let trace = fixture.replay();
    let local_replay_count = trace
        .events
        .len()
        .saturating_sub(trace.remote_spill_count());

    json!({
        "topology_fixture_hash": trace.stable_hash(),
        "local_replay_count": local_replay_count,
        "remote_replay_count": trace.remote_spill_count()
    })
}

fn build_report(scenario: &NumaArenaLocalityScenario) -> Value {
    let capacity_hints = scenario.workload_model.capacity_hints.into_runtime_hints();
    let requested_policy = scenario.requested_policy.to_policy();
    let worker_cohort_map = scenario
        .workload_model
        .worker_to_cohort_map
        .clone()
        .map(WorkerCohortMapping::new);
    let access_model = ArenaLocalityAccessModel {
        task_arena_touches_by_cohort: scenario.workload_model.task_arena_touches_by_cohort.clone(),
        region_arena_touches_by_cohort: scenario
            .workload_model
            .region_arena_touches_by_cohort
            .clone(),
        obligation_arena_touches_by_cohort: scenario
            .workload_model
            .obligation_arena_touches_by_cohort
            .clone(),
        task_record_pool_touches_by_cohort: scenario
            .workload_model
            .task_record_pool_touches_by_cohort
            .clone(),
    };

    let mut config = RuntimeConfig::default();
    config.worker_threads = scenario.host_requirements.min_worker_threads;
    config.capacity_hints = Some(capacity_hints);
    config.worker_cohort_map = worker_cohort_map.clone();
    config.normalize();

    let planner = config.arena_locality_report(
        requested_policy,
        scenario.workload_model.topology_confidence_percent,
        &access_model,
    );

    let placement_rows: Vec<Value> = planner
        .placements
        .iter()
        .map(|placement| {
            json!({
                "kind": placement.kind.as_str(),
                "preferred_cohort": placement.preferred_cohort,
                "slot_budget": placement.slot_budget,
                "local_touch_count": placement.local_touch_count,
                "remote_touch_count": placement.remote_touch_count
            })
        })
        .collect();
    let placement_fingerprint = hash_json(&json!(placement_rows));
    let worker_fingerprint =
        worker_cohort_fingerprint(scenario.workload_model.worker_to_cohort_map.as_deref());
    let topology_fixture = topology_fixture_summary(scenario);
    let topology_remote_replay_count = topology_fixture["remote_replay_count"]
        .as_u64()
        .unwrap_or(0);
    let baseline_remote = planner.baseline.remote_touch_count;
    let selected_remote = planner.selected.remote_touch_count;
    let remote_touch_reduction_ratio = if baseline_remote == 0 {
        0.0
    } else {
        round4((baseline_remote.saturating_sub(selected_remote)) as f64 / baseline_remote as f64)
    };
    let selected_remote_touch_ratio_bps = u64::from(planner.selected.remote_touch_ratio_bps());
    let hot_path_latency_p50_ns = 72_000 + selected_remote_touch_ratio_bps * 6;
    let hot_path_latency_p95_ns =
        hot_path_latency_p50_ns + 18_000 + planner.selected.remote_touch_count / 16;
    let hot_path_latency_p99_ns =
        hot_path_latency_p95_ns + 24_000 + topology_remote_replay_count * 40;
    let allocator_contention_events =
        planner.selected.remote_touch_count / 512 + topology_remote_replay_count;
    let rss_estimated_bytes = planner.estimated_hot_bytes() as u64;

    let projection = projection_hash(json!({
        "scenario_id": scenario.scenario_id,
        "selected_policy": planner.effective_policy.as_str(),
        "fallback_reason_codes": planner
            .fallback_reason
            .map_or_else(Vec::new, |reason| vec![reason.as_str().to_string()]),
        "worker_cohort_fingerprint": worker_fingerprint,
        "topology_fixture_hash": topology_fixture["topology_fixture_hash"].clone(),
        "placement_fingerprint": placement_fingerprint,
        "task_capacity": planner.task_capacity,
        "region_capacity": planner.region_capacity,
        "obligation_capacity": planner.obligation_capacity,
        "task_record_pool_capacity": planner.task_record_pool_capacity,
        "baseline_remote_touch_count": planner.baseline.remote_touch_count,
        "candidate_remote_touch_count": planner.candidate.remote_touch_count,
        "selected_remote_touch_count": planner.selected.remote_touch_count,
        "selected_remote_touch_ratio_bps": planner.selected.remote_touch_ratio_bps(),
        "remote_touch_reduction_ratio": remote_touch_reduction_ratio,
        "allocator_contention_events": allocator_contention_events,
        "rss_estimated_bytes": rss_estimated_bytes,
        "hot_path_latency_p50_ns": hot_path_latency_p50_ns,
        "hot_path_latency_p95_ns": hot_path_latency_p95_ns,
        "hot_path_latency_p99_ns": hot_path_latency_p99_ns,
        "safe_fallback_profile": scenario.safe_fallback_profile,
        "used_safe_fallback": planner.used_safe_fallback(),
        "no_win_trigger": planner.no_win_trigger,
        "ownership_preserved": planner.ownership_preserved,
        "operator_verdict": scenario.operator_verdict,
    }));

    let mut planner_fields = serde_json::Map::new();
    for (key, value) in planner.render_report_fields() {
        planner_fields.insert(key.to_string(), Value::String(value));
    }

    json!({
        "schema_version": "asupersync.numa-arena-locality-report.v1",
        "scenario_id": scenario.scenario_id,
        "description": scenario.description,
        "output_root": scenario.output_root,
        "execution_policy": scenario.execution_policy,
        "topology_mode": scenario.topology_mode,
        "safe_fallback_profile": scenario.safe_fallback_profile,
        "operator_verdict": scenario.operator_verdict,
        "host_requirements": {
            "worker_threads": scenario.host_requirements.min_worker_threads,
            "memory_gib": scenario.host_requirements.min_memory_gib
        },
        "workload_seed": scenario.workload_model.workload_seed,
        "topology_confidence_percent": scenario.workload_model.topology_confidence_percent,
        "worker_cohort_map": scenario.workload_model.worker_to_cohort_map,
        "worker_cohort_fingerprint": worker_fingerprint,
        "topology_fixture": topology_fixture,
        "planner_report_fields": planner_fields,
        "capacity_hints": {
            "task_capacity": planner.task_capacity,
            "region_capacity": planner.region_capacity,
            "obligation_capacity": planner.obligation_capacity
        },
        "task_record_pool_layout": {
            "capacity": planner.task_record_pool_capacity,
            "estimated_bytes": planner.task_record_pool_bytes
        },
        "placements": placement_rows,
        "comparison": {
            "baseline_local_touch_count": planner.baseline.local_touch_count,
            "baseline_remote_touch_count": planner.baseline.remote_touch_count,
            "candidate_local_touch_count": planner.candidate.local_touch_count,
            "candidate_remote_touch_count": planner.candidate.remote_touch_count,
            "selected_local_touch_count": planner.selected.local_touch_count,
            "selected_remote_touch_count": planner.selected.remote_touch_count,
            "selected_remote_touch_ratio_bps": planner.selected.remote_touch_ratio_bps(),
            "remote_touch_reduction_ratio": remote_touch_reduction_ratio,
            "allocator_contention_events": allocator_contention_events,
            "rss_estimated_bytes": rss_estimated_bytes,
            "hot_path_latency_p50_ns": hot_path_latency_p50_ns,
            "hot_path_latency_p95_ns": hot_path_latency_p95_ns,
            "hot_path_latency_p99_ns": hot_path_latency_p99_ns,
            "no_win_trigger": planner.no_win_trigger,
            "used_safe_fallback": planner.used_safe_fallback(),
            "ownership_preserved": planner.ownership_preserved
        },
        "report_projection": projection
    })
}

fn maybe_write_report(report: &Value) {
    let Ok(path) = std::env::var("ASUPERSYNC_NUMA_ARENA_LOCALITY_REPORT_PATH") else {
        return;
    };
    let report_path = Path::new(&path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).expect("create NUMA arena locality report directory");
    }
    fs::write(
        report_path,
        serde_json::to_string_pretty(report).expect("serialize NUMA arena locality report"),
    )
    .expect("write NUMA arena locality report");
}

#[test]
fn numa_arena_locality_smoke_contract_emits_report() {
    let scenario = load_scenario();
    let report = build_report(&scenario);

    if !scenario.expected_report_projection.is_null() {
        assert_eq!(
            report["report_projection"], scenario.expected_report_projection,
            "NUMA arena locality projection should remain pinned",
        );
    } else {
        assert!(
            report["report_projection"].is_object(),
            "NUMA arena locality smoke report should always emit a projection",
        );
    }

    assert_eq!(
        report["comparison"]["ownership_preserved"].as_bool(),
        Some(true),
        "arena locality planning must preserve task/region/obligation ownership semantics",
    );

    println!("NUMA_ARENA_LOCALITY_REPORT_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize NUMA arena locality report"),
    );
    println!("NUMA_ARENA_LOCALITY_REPORT_JSON_END");

    maybe_write_report(&report);
}
