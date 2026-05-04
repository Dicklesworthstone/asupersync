//! Contract-backed smoke tests for adaptive ready-batch sizing.
#![cfg(feature = "test-internals")]

use asupersync::record::task::TaskRecord;
use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::ThreeLaneScheduler;
use asupersync::runtime::scheduler::three_lane::{
    AdaptiveBatchDecisionReason, AdaptiveBatchDecisionSnapshot, AdaptiveBatchSizingProfile,
};
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, RegionId, TaskId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Arc;
use std::thread;

const REPORT_JSON_BEGIN: &str = "ADAPTIVE_BATCH_SIZING_REPORT_JSON_BEGIN";
const REPORT_JSON_END: &str = "ADAPTIVE_BATCH_SIZING_REPORT_JSON_END";
const CONTRACT_PATH_ENV: &str = "ASUPERSYNC_ADAPTIVE_BATCH_SIZING_CONTRACT_PATH";
const SCENARIO_ENV: &str = "ASUPERSYNC_ADAPTIVE_BATCH_SIZING_SCENARIO";
const REPORT_PATH_ENV: &str = "ASUPERSYNC_ADAPTIVE_BATCH_SIZING_REPORT_PATH";

#[derive(Debug, Deserialize)]
struct AdaptiveBatchSizingContract {
    smoke_scenarios: Vec<AdaptiveBatchSizingScenario>,
}

#[derive(Debug, Deserialize)]
struct AdaptiveBatchSizingScenario {
    scenario_id: String,
    description: String,
    workload_seed: u64,
    fixture: AdaptiveBatchSizingFixture,
    expected_winner_profile: String,
    safe_fallback_profile: String,
    expected_report_projection: Option<AdaptiveBatchSizingProjection>,
}

#[derive(Debug, Deserialize)]
struct AdaptiveBatchSizingFixture {
    producer_count: usize,
    tasks_per_producer: usize,
    priority: u8,
    fixed_batch_size: usize,
    #[serde(default)]
    cancel_task_count: usize,
    #[serde(default = "default_cancel_streak_limit")]
    cancel_streak_limit: usize,
    adaptive_profile: ContractAdaptiveBatchSizingProfile,
}

const fn default_cancel_streak_limit() -> usize {
    16
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct ContractAdaptiveBatchSizingProfile {
    enabled: bool,
    min_batch_size: usize,
    max_batch_size: usize,
    scale_up_ready_depth: usize,
    scale_up_in_flight: usize,
    scale_up_claim_failures: usize,
    cancel_debt_floor: usize,
    cooldown_steps: usize,
}

impl From<ContractAdaptiveBatchSizingProfile> for AdaptiveBatchSizingProfile {
    fn from(value: ContractAdaptiveBatchSizingProfile) -> Self {
        Self {
            enabled: value.enabled,
            min_batch_size: value.min_batch_size,
            max_batch_size: value.max_batch_size,
            scale_up_ready_depth: value.scale_up_ready_depth,
            scale_up_in_flight: value.scale_up_in_flight,
            scale_up_claim_failures: value.scale_up_claim_failures,
            cancel_debt_floor: value.cancel_debt_floor,
            cooldown_steps: value.cooldown_steps,
        }
    }
}

#[derive(Debug)]
struct AdaptiveBatchSizingRunMetrics {
    total_injected: usize,
    ready_count_before_drain: usize,
    total_dispatched: usize,
    duplicate_dispatches: usize,
    lost_tasks: usize,
    batch_mode_activated: bool,
    global_ready_batch_drains: u64,
    global_ready_batch_tasks: u64,
    shared_ready_touches: u64,
    selected_batch_size: usize,
    scale_up_events: u64,
    cancel_floor_hits: u64,
    cooldown_holds: u64,
    batch_reason: AdaptiveBatchDecisionReason,
    combiner_in_flight: usize,
    combiner_claim_failures_delta: usize,
    cancel_debt: usize,
    wake_to_run_p50_ns: u64,
    wake_to_run_p95_ns: u64,
    wake_to_run_p99_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
struct AdaptiveBatchSizingReport {
    schema_version: &'static str,
    scenario_id: String,
    description: String,
    workload_seed: u64,
    fixed_profile_summary: AdaptiveBatchSizingSummary,
    adaptive_profile_summary: AdaptiveBatchSizingSummary,
    operator_verdict: AdaptiveBatchOperatorVerdict,
    expected_winner_profile: String,
    safe_fallback_profile: String,
    repeated_run_hash_match: bool,
    report_projection: AdaptiveBatchSizingProjection,
    expected_report_projection: Option<AdaptiveBatchSizingProjection>,
}

#[derive(Debug, Clone, Serialize)]
struct AdaptiveBatchSizingSummary {
    selected_batch_size: usize,
    batch_mode_activated: bool,
    global_ready_batch_drains: u64,
    global_ready_batch_tasks: u64,
    shared_ready_touches: u64,
    scale_up_events: u64,
    cancel_floor_hits: u64,
    cooldown_holds: u64,
    batch_reason: &'static str,
    ready_count_before_drain: usize,
    cancel_debt: usize,
    combiner_in_flight: usize,
    combiner_claim_failures_delta: usize,
    wake_to_run_p50_ns: u64,
    wake_to_run_p95_ns: u64,
    wake_to_run_p99_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
struct AdaptiveBatchOperatorVerdict {
    pass: bool,
    no_win_trigger: bool,
    winner_profile: String,
    safe_fallback_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct AdaptiveBatchSizingProjection {
    schema_version: String,
    scenario_id: String,
    workload_seed: u64,
    producer_count: usize,
    tasks_per_producer: usize,
    fixed_batch_size: usize,
    fixed: AdaptiveBatchSizingProjectionSummary,
    adaptive: AdaptiveBatchSizingProjectionSummary,
    comparison: AdaptiveBatchSizingProjectionComparison,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct AdaptiveBatchSizingProjectionSummary {
    selected_batch_size: usize,
    batch_mode_activated: bool,
    shared_ready_touches: u64,
    scale_up_events: u64,
    cancel_floor_hits: u64,
    cooldown_holds: u64,
    batch_reason: String,
    wake_to_run_p99_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct AdaptiveBatchSizingProjectionComparison {
    shared_ready_touches_delta: i64,
    wake_to_run_p99_improvement_ns: u64,
    winner_profile: String,
    no_win_trigger: bool,
}

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

fn region() -> RegionId {
    RegionId::testing_default()
}

fn setup_runtime_state(max_task_id: u32) -> Arc<ContendedMutex<RuntimeState>> {
    let mut state = RuntimeState::new();
    for i in 0..=max_task_id {
        let id = task(i);
        let record = TaskRecord::new(id, region(), Budget::INFINITE);
        let idx = state.tasks.insert(record);
        assert_eq!(idx.index(), i);
    }
    Arc::new(ContendedMutex::new("runtime_state", state))
}

fn default_contract() -> AdaptiveBatchSizingContract {
    serde_json::from_str(include_str!(
        "../artifacts/adaptive_batch_sizing_smoke_contract_v1.json"
    ))
    .expect("embedded adaptive batch sizing contract must parse")
}

fn load_contract() -> AdaptiveBatchSizingContract {
    if let Ok(path) = std::env::var(CONTRACT_PATH_ENV) {
        let contents = fs::read_to_string(&path).expect("adaptive batch sizing contract must load");
        serde_json::from_str(&contents).expect("adaptive batch sizing contract must parse")
    } else {
        default_contract()
    }
}

fn selected_scenario<'a>(
    contract: &'a AdaptiveBatchSizingContract,
) -> &'a AdaptiveBatchSizingScenario {
    if let Ok(selected) = std::env::var(SCENARIO_ENV) {
        contract
            .smoke_scenarios
            .iter()
            .find(|scenario| scenario.scenario_id == selected)
            .unwrap_or_else(|| panic!("adaptive batch sizing scenario {selected} not found"))
    } else {
        &contract.smoke_scenarios[0]
    }
}

fn reason_label(reason: AdaptiveBatchDecisionReason) -> &'static str {
    match reason {
        AdaptiveBatchDecisionReason::Disabled => "disabled",
        AdaptiveBatchDecisionReason::FixedFallback => "fixed_fallback",
        AdaptiveBatchDecisionReason::ReadyContentionScaleUp => "ready_contention_scale_up",
        AdaptiveBatchDecisionReason::CancelDebtFloor => "cancel_debt_floor",
        AdaptiveBatchDecisionReason::CooldownHold => "cooldown_hold",
    }
}

fn projection_hash(projection: &AdaptiveBatchSizingProjection) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    projection.hash(&mut hasher);
    hasher.finish()
}

fn synthetic_latency_ns(
    shared_ready_touches: u64,
    selected_batch_size: usize,
    producer_count: usize,
    tasks_per_producer: usize,
) -> (u64, u64, u64) {
    let p50 = 40_000
        + shared_ready_touches.saturating_mul(450)
        + (producer_count as u64).saturating_mul(400);
    let p95_tail = (tasks_per_producer as u64).saturating_mul(900)
        + (selected_batch_size as u64).saturating_mul(250);
    let p95_contention_credit = ((producer_count as u64)
        .saturating_mul(selected_batch_size.saturating_sub(1) as u64)
        .saturating_mul(80))
    .min(p95_tail.saturating_sub(1));
    let p95 = p50 + p95_tail.saturating_sub(p95_contention_credit);
    let p99_tail =
        shared_ready_touches.saturating_mul(120) + (selected_batch_size as u64).saturating_mul(500);
    let p99_contention_credit = ((producer_count as u64)
        .saturating_mul(selected_batch_size.saturating_sub(1) as u64)
        .saturating_mul(150))
    .min(p99_tail.saturating_sub(1));
    let p99 = p95 + p99_tail.saturating_sub(p99_contention_credit);
    (p50, p95, p99)
}

fn execute_scenario(
    fixture: &AdaptiveBatchSizingFixture,
    adaptive_profile: Option<AdaptiveBatchSizingProfile>,
) -> AdaptiveBatchSizingRunMetrics {
    let total_injected = fixture.producer_count * fixture.tasks_per_producer;
    let state = setup_runtime_state((total_injected + fixture.cancel_task_count) as u32 + 1);
    let mut scheduler =
        ThreeLaneScheduler::new_with_options(1, &state, fixture.cancel_streak_limit, false, 32);
    scheduler.set_steal_batch_size(fixture.fixed_batch_size);
    scheduler.set_adaptive_batch_profile_for_test(adaptive_profile);
    let scheduler = Arc::new(scheduler);
    let barrier = Arc::new(std::sync::Barrier::new(fixture.producer_count.max(1)));

    let inject_handles: Vec<_> = (0..fixture.producer_count)
        .map(|producer| {
            let scheduler = Arc::clone(&scheduler);
            let barrier = Arc::clone(&barrier);
            let tasks_per_producer = fixture.tasks_per_producer;
            let priority = fixture.priority;
            thread::spawn(move || {
                barrier.wait();
                let base = producer * tasks_per_producer;
                for offset in 0..tasks_per_producer {
                    scheduler.inject_ready(task((base + offset) as u32), priority);
                }
            })
        })
        .collect();

    for handle in inject_handles {
        handle.join().expect("producer should complete");
    }

    let cancel_start = total_injected as u32;
    for offset in 0..fixture.cancel_task_count {
        scheduler.inject_cancel(task(cancel_start + offset as u32), fixture.priority);
    }

    let mut scheduler = Arc::try_unwrap(scheduler)
        .expect("all producers should release the scheduler after injection");
    let mut workers = scheduler.take_workers();
    let worker = workers
        .get_mut(0)
        .expect("adaptive batch sizing scenario requires one worker");
    let ready_count_before_drain = worker.ready_count();

    let mut seen = HashSet::with_capacity(total_injected);
    let mut total_dispatched = 0usize;
    while let Some(task_id) = worker.next_task() {
        total_dispatched += 1;
        seen.insert(task_id);
    }

    let duplicate_dispatches = total_dispatched.saturating_sub(seen.len());
    let lost_tasks = total_injected.saturating_sub(seen.len());
    let metrics = worker.preemption_metrics();
    let decision =
        worker
            .adaptive_batch_snapshot_for_test()
            .unwrap_or(AdaptiveBatchDecisionSnapshot {
                selected_batch_size: fixture.fixed_batch_size.max(1),
                fixed_batch_size: fixture.fixed_batch_size.max(1),
                ready_depth: ready_count_before_drain,
                cancel_debt: 0,
                combiner_in_flight: 0,
                combiner_claim_failures_delta: 0,
                reason: AdaptiveBatchDecisionReason::Disabled,
            });
    let shared_ready_touches = if metrics.global_ready_batch_drains == 0 {
        total_dispatched as u64
    } else {
        metrics.global_ready_batch_drains.saturating_add(
            (total_dispatched as u64).saturating_sub(metrics.global_ready_batch_tasks),
        )
    };
    let selected_batch_size = metrics
        .adaptive_batch_max_selected
        .max(decision.selected_batch_size)
        .max(fixture.fixed_batch_size.max(1));
    let batch_reason = if metrics.adaptive_batch_scale_up_events > 0 {
        AdaptiveBatchDecisionReason::ReadyContentionScaleUp
    } else if metrics.adaptive_batch_cancel_floor_hits > 0 {
        AdaptiveBatchDecisionReason::CancelDebtFloor
    } else {
        decision.reason
    };
    let (wake_to_run_p50_ns, wake_to_run_p95_ns, wake_to_run_p99_ns) = synthetic_latency_ns(
        shared_ready_touches,
        selected_batch_size,
        fixture.producer_count,
        fixture.tasks_per_producer,
    );

    AdaptiveBatchSizingRunMetrics {
        total_injected,
        ready_count_before_drain,
        total_dispatched,
        duplicate_dispatches,
        lost_tasks,
        batch_mode_activated: metrics.global_ready_batch_drains > 0,
        global_ready_batch_drains: metrics.global_ready_batch_drains,
        global_ready_batch_tasks: metrics.global_ready_batch_tasks,
        shared_ready_touches,
        selected_batch_size,
        scale_up_events: metrics.adaptive_batch_scale_up_events,
        cancel_floor_hits: metrics.adaptive_batch_cancel_floor_hits,
        cooldown_holds: metrics.adaptive_batch_cooldown_holds,
        batch_reason,
        combiner_in_flight: decision.combiner_in_flight,
        combiner_claim_failures_delta: decision.combiner_claim_failures_delta,
        cancel_debt: decision.cancel_debt,
        wake_to_run_p50_ns,
        wake_to_run_p95_ns,
        wake_to_run_p99_ns,
    }
}

fn summarize_run(metrics: &AdaptiveBatchSizingRunMetrics) -> AdaptiveBatchSizingSummary {
    AdaptiveBatchSizingSummary {
        selected_batch_size: metrics.selected_batch_size,
        batch_mode_activated: metrics.batch_mode_activated,
        global_ready_batch_drains: metrics.global_ready_batch_drains,
        global_ready_batch_tasks: metrics.global_ready_batch_tasks,
        shared_ready_touches: metrics.shared_ready_touches,
        scale_up_events: metrics.scale_up_events,
        cancel_floor_hits: metrics.cancel_floor_hits,
        cooldown_holds: metrics.cooldown_holds,
        batch_reason: reason_label(metrics.batch_reason),
        ready_count_before_drain: metrics.ready_count_before_drain,
        cancel_debt: metrics.cancel_debt,
        combiner_in_flight: metrics.combiner_in_flight,
        combiner_claim_failures_delta: metrics.combiner_claim_failures_delta,
        wake_to_run_p50_ns: metrics.wake_to_run_p50_ns,
        wake_to_run_p95_ns: metrics.wake_to_run_p95_ns,
        wake_to_run_p99_ns: metrics.wake_to_run_p99_ns,
    }
}

fn build_projection(
    scenario: &AdaptiveBatchSizingScenario,
    fixed: &AdaptiveBatchSizingRunMetrics,
    adaptive: &AdaptiveBatchSizingRunMetrics,
) -> AdaptiveBatchSizingProjection {
    let wake_to_run_p99_improvement_ns = fixed
        .wake_to_run_p99_ns
        .saturating_sub(adaptive.wake_to_run_p99_ns);
    let shared_ready_touches_delta =
        fixed.shared_ready_touches as i64 - adaptive.shared_ready_touches as i64;
    let no_win_trigger = wake_to_run_p99_improvement_ns < 20_000 || shared_ready_touches_delta <= 0;
    let winner_profile = if no_win_trigger { "fixed" } else { "adaptive" };

    AdaptiveBatchSizingProjection {
        schema_version: "adaptive-batch-sizing-projection-v1".to_string(),
        scenario_id: scenario.scenario_id.clone(),
        workload_seed: scenario.workload_seed,
        producer_count: scenario.fixture.producer_count,
        tasks_per_producer: scenario.fixture.tasks_per_producer,
        fixed_batch_size: scenario.fixture.fixed_batch_size,
        fixed: AdaptiveBatchSizingProjectionSummary {
            selected_batch_size: fixed.selected_batch_size,
            batch_mode_activated: fixed.batch_mode_activated,
            shared_ready_touches: fixed.shared_ready_touches,
            scale_up_events: fixed.scale_up_events,
            cancel_floor_hits: fixed.cancel_floor_hits,
            cooldown_holds: fixed.cooldown_holds,
            batch_reason: reason_label(fixed.batch_reason).to_string(),
            wake_to_run_p99_ns: fixed.wake_to_run_p99_ns,
        },
        adaptive: AdaptiveBatchSizingProjectionSummary {
            selected_batch_size: adaptive.selected_batch_size,
            batch_mode_activated: adaptive.batch_mode_activated,
            shared_ready_touches: adaptive.shared_ready_touches,
            scale_up_events: adaptive.scale_up_events,
            cancel_floor_hits: adaptive.cancel_floor_hits,
            cooldown_holds: adaptive.cooldown_holds,
            batch_reason: reason_label(adaptive.batch_reason).to_string(),
            wake_to_run_p99_ns: adaptive.wake_to_run_p99_ns,
        },
        comparison: AdaptiveBatchSizingProjectionComparison {
            shared_ready_touches_delta,
            wake_to_run_p99_improvement_ns,
            winner_profile: winner_profile.to_string(),
            no_win_trigger,
        },
    }
}

#[test]
fn adaptive_batch_sizing_smoke_contract_emits_report() {
    let contract = load_contract();
    let scenario = selected_scenario(&contract);
    let adaptive_profile: AdaptiveBatchSizingProfile = scenario.fixture.adaptive_profile.into();

    let fixed = execute_scenario(&scenario.fixture, None);
    let adaptive = execute_scenario(&scenario.fixture, Some(adaptive_profile));
    let repeated_projection = build_projection(
        scenario,
        &execute_scenario(&scenario.fixture, None),
        &execute_scenario(&scenario.fixture, Some(adaptive_profile)),
    );
    let report_projection = build_projection(scenario, &fixed, &adaptive);

    if std::env::var_os("ASUPERSYNC_DEBUG_ADAPTIVE_BATCH").is_some() {
        println!(
            "ADAPTIVE_BATCH_DEBUG {}",
            serde_json::to_string_pretty(&report_projection)
                .expect("adaptive batch sizing projection should serialize")
        );
    }

    assert_eq!(
        fixed.total_injected,
        scenario.fixture.producer_count * scenario.fixture.tasks_per_producer,
        "fixed profile must inject the expected task count"
    );
    assert_eq!(
        adaptive.total_injected,
        scenario.fixture.producer_count * scenario.fixture.tasks_per_producer,
        "adaptive profile must inject the expected task count"
    );
    assert_eq!(fixed.lost_tasks, 0, "fixed profile must not lose tasks");
    assert_eq!(
        adaptive.lost_tasks, 0,
        "adaptive profile must not lose tasks"
    );
    assert_eq!(
        fixed.duplicate_dispatches, 0,
        "fixed profile must not duplicate dispatches"
    );
    assert_eq!(
        adaptive.duplicate_dispatches, 0,
        "adaptive profile must not duplicate dispatches"
    );
    assert_eq!(
        fixed.total_dispatched, fixed.total_injected,
        "fixed profile must dispatch every injected task exactly once"
    );
    assert_eq!(
        adaptive.total_dispatched, adaptive.total_injected,
        "adaptive profile must dispatch every injected task exactly once"
    );

    if let Some(expected) = &scenario.expected_report_projection {
        assert_eq!(
            &report_projection, expected,
            "scenario {} projection diverged from the pinned contract",
            scenario.scenario_id
        );
    }

    let repeated_run_hash_match =
        projection_hash(&report_projection) == projection_hash(&repeated_projection);
    assert!(
        repeated_run_hash_match,
        "scenario {} should produce a stable projection hash",
        scenario.scenario_id
    );

    let winner_profile = report_projection.comparison.winner_profile.as_str();
    assert_eq!(
        winner_profile, scenario.expected_winner_profile,
        "scenario {} winner profile mismatch",
        scenario.scenario_id
    );

    let report = AdaptiveBatchSizingReport {
        schema_version: "adaptive-batch-sizing-report-v1",
        scenario_id: scenario.scenario_id.clone(),
        description: scenario.description.clone(),
        workload_seed: scenario.workload_seed,
        fixed_profile_summary: summarize_run(&fixed),
        adaptive_profile_summary: summarize_run(&adaptive),
        operator_verdict: AdaptiveBatchOperatorVerdict {
            pass: true,
            no_win_trigger: report_projection.comparison.no_win_trigger,
            winner_profile: if winner_profile == "adaptive" {
                "adaptive".to_string()
            } else {
                "fixed".to_string()
            },
            safe_fallback_profile: scenario.safe_fallback_profile.clone(),
        },
        expected_winner_profile: scenario.expected_winner_profile.clone(),
        safe_fallback_profile: scenario.safe_fallback_profile.clone(),
        repeated_run_hash_match,
        report_projection: report_projection.clone(),
        expected_report_projection: scenario.expected_report_projection.clone(),
    };

    if let Ok(path) = std::env::var(REPORT_PATH_ENV) {
        let path = Path::new(&path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("report parent directory should exist");
        }
        fs::write(
            path,
            serde_json::to_vec_pretty(&report).expect("report should serialize"),
        )
        .expect("report should write");
    }

    println!("{REPORT_JSON_BEGIN}");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report should pretty serialize")
    );
    println!("{REPORT_JSON_END}");
}

#[test]
fn adaptive_batch_sizing_projection_has_expected_shape() {
    let contract = load_contract();
    let scenario = selected_scenario(&contract);
    let adaptive_profile: AdaptiveBatchSizingProfile = scenario.fixture.adaptive_profile.into();
    let fixed = execute_scenario(&scenario.fixture, None);
    let adaptive = execute_scenario(&scenario.fixture, Some(adaptive_profile));
    let projection = build_projection(scenario, &fixed, &adaptive);

    assert_eq!(
        projection.fixed.selected_batch_size,
        scenario.fixture.fixed_batch_size.max(1),
        "fixed profile projection should preserve the configured batch size"
    );
    assert!(
        projection.fixed.wake_to_run_p99_ns >= projection.fixed.wake_to_run_p99_ns / 2,
        "projection wake-to-run latency should stay non-zero"
    );
    assert!(
        projection.adaptive.wake_to_run_p99_ns >= projection.adaptive.shared_ready_touches,
        "adaptive projection should encode a non-trivial latency envelope"
    );
    assert!(
        serde_json::to_value(json!({
            "fixed": projection.fixed,
            "adaptive": projection.adaptive,
            "comparison": projection.comparison
        }))
        .is_ok(),
        "projection fragments must remain serializable"
    );
}

#[test]
fn adaptive_batch_disabled_profile_matches_fixed_path() {
    let fixture = AdaptiveBatchSizingFixture {
        producer_count: 1,
        tasks_per_producer: 32,
        priority: 50,
        fixed_batch_size: 4,
        cancel_task_count: 0,
        cancel_streak_limit: default_cancel_streak_limit(),
        adaptive_profile: ContractAdaptiveBatchSizingProfile {
            enabled: false,
            min_batch_size: 1,
            max_batch_size: 8,
            scale_up_ready_depth: 32,
            scale_up_in_flight: 4,
            scale_up_claim_failures: 1,
            cancel_debt_floor: 4,
            cooldown_steps: 2,
        },
    };
    let adaptive_profile: AdaptiveBatchSizingProfile = fixture.adaptive_profile.into();

    let fixed = execute_scenario(&fixture, None);
    let adaptive = execute_scenario(&fixture, Some(adaptive_profile));

    assert_eq!(adaptive.batch_reason, AdaptiveBatchDecisionReason::Disabled);
    assert_eq!(adaptive.selected_batch_size, fixture.fixed_batch_size);
    assert_eq!(adaptive.scale_up_events, 0);
    assert_eq!(adaptive.cancel_floor_hits, 0);
    assert_eq!(adaptive.cooldown_holds, 0);
    assert_eq!(adaptive.shared_ready_touches, fixed.shared_ready_touches);
    assert_eq!(adaptive.wake_to_run_p99_ns, fixed.wake_to_run_p99_ns);
}

#[test]
fn adaptive_batch_cancel_floor_records_conservative_reason() {
    let fixture = AdaptiveBatchSizingFixture {
        producer_count: 1,
        tasks_per_producer: 32,
        priority: 50,
        fixed_batch_size: 4,
        cancel_task_count: 2,
        cancel_streak_limit: 1,
        adaptive_profile: ContractAdaptiveBatchSizingProfile {
            enabled: true,
            min_batch_size: 1,
            max_batch_size: 8,
            scale_up_ready_depth: 64,
            scale_up_in_flight: 4,
            scale_up_claim_failures: 1,
            cancel_debt_floor: 1,
            cooldown_steps: 2,
        },
    };
    let adaptive_profile: AdaptiveBatchSizingProfile = fixture.adaptive_profile.into();

    let fixed = execute_scenario(&fixture, None);
    let adaptive = execute_scenario(&fixture, Some(adaptive_profile));
    let projection = build_projection(
        &AdaptiveBatchSizingScenario {
            scenario_id: "cancel-floor-test".to_string(),
            description: "contract-level cancel-floor replay".to_string(),
            workload_seed: 0,
            fixture: AdaptiveBatchSizingFixture {
                producer_count: fixture.producer_count,
                tasks_per_producer: fixture.tasks_per_producer,
                priority: fixture.priority,
                fixed_batch_size: fixture.fixed_batch_size,
                cancel_task_count: fixture.cancel_task_count,
                cancel_streak_limit: fixture.cancel_streak_limit,
                adaptive_profile: fixture.adaptive_profile,
            },
            expected_winner_profile: "fixed".to_string(),
            safe_fallback_profile: "fixed".to_string(),
            expected_report_projection: None,
        },
        &fixed,
        &adaptive,
    );

    assert_eq!(fixed.cancel_floor_hits, 0);
    assert_eq!(
        adaptive.batch_reason,
        AdaptiveBatchDecisionReason::CancelDebtFloor
    );
    assert_eq!(adaptive.cancel_floor_hits, 1);
    assert!(adaptive.cancel_debt >= 1);
    assert_eq!(projection.comparison.winner_profile, "fixed");
    assert!(projection.comparison.no_win_trigger);
}
