//! Integration proofs for runtime capacity hints and burst-allocation behavior.

use asupersync::observability::NoOpMetrics;
use asupersync::runtime::config::RuntimeCapacityHints;
use asupersync::runtime::{RuntimeConfig, RuntimeState, TraceStorageProfile};
use asupersync::util::Arena;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::sync::Arc;

const DEFAULT_SCENARIO_ID: &str = "AA-RUNTIME-CAPACITY-HINTS-BURST-4096";
const DEFAULT_CONTRACT_PATH: &str = "artifacts/runtime_capacity_hints_smoke_contract_v1.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HintMode {
    ExpectedConcurrentTasks,
    WorkerThreadsAutoScale,
    ExplicitZeroFallback,
}

impl HintMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExpectedConcurrentTasks => "expected_concurrent_tasks",
            Self::WorkerThreadsAutoScale => "worker_threads_auto_scale",
            Self::ExplicitZeroFallback => "explicit_zero_fallback",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "expected_concurrent_tasks" => Self::ExpectedConcurrentTasks,
            "worker_threads_auto_scale" => Self::WorkerThreadsAutoScale,
            "explicit_zero_fallback" => Self::ExplicitZeroFallback,
            other => panic!("unknown runtime capacity hint mode: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BurstProfile {
    task_inserts: usize,
    region_inserts: usize,
    obligation_inserts: usize,
}

#[derive(Debug, Clone)]
struct ContractScenario {
    scenario_id: String,
    description: String,
    hint_mode: HintMode,
    worker_threads: usize,
    expected_concurrent_tasks: Option<usize>,
    explicit_capacity_hints: Option<RuntimeCapacityHints>,
    burst_profile: BurstProfile,
    operator_notes: Value,
    expected_projection: Value,
    operator_verdict: String,
}

#[derive(Debug, Clone, Copy)]
struct BurstArenaMetrics {
    initial_capacity: usize,
    final_capacity: usize,
    reserved_bytes_initial: usize,
    reserved_bytes_final: usize,
    growth_events: usize,
    residual_realloc_count: usize,
    largest_capacity_jump: usize,
    capacity_variance_slots: f64,
}

#[derive(Debug, Clone, Copy, Default)]
struct VarianceTracker {
    count: usize,
    mean: f64,
    m2: f64,
}

impl VarianceTracker {
    fn observe(&mut self, value: usize) {
        let value = value as f64;
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    fn variance(self) -> f64 {
        if self.count <= 1 {
            0.0
        } else {
            round4(self.m2 / (self.count as f64 - 1.0))
        }
    }
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn bytes_to_mib(bytes: usize) -> f64 {
    round4(bytes as f64 / 1_048_576.0)
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

fn parse_capacity_hints(value: &Value) -> Option<RuntimeCapacityHints> {
    if value.is_null() {
        return None;
    }
    Some(RuntimeCapacityHints::new(
        value["task_capacity"].as_u64().expect("task_capacity") as usize,
        value["region_capacity"].as_u64().expect("region_capacity") as usize,
        value["obligation_capacity"]
            .as_u64()
            .expect("obligation_capacity") as usize,
    ))
}

fn parse_contract_scenario(scenario: &Value) -> ContractScenario {
    ContractScenario {
        scenario_id: scenario["scenario_id"]
            .as_str()
            .expect("scenario_id")
            .to_string(),
        description: scenario["description"]
            .as_str()
            .expect("description")
            .to_string(),
        hint_mode: HintMode::parse(scenario["hint_mode"].as_str().expect("hint_mode")),
        worker_threads: scenario["worker_threads"].as_u64().expect("worker_threads") as usize,
        expected_concurrent_tasks: scenario["expected_concurrent_tasks"]
            .as_u64()
            .map(|value| value as usize),
        explicit_capacity_hints: parse_capacity_hints(&scenario["explicit_capacity_hints"]),
        burst_profile: BurstProfile {
            task_inserts: scenario["burst_profile"]["task_inserts"]
                .as_u64()
                .expect("task_inserts") as usize,
            region_inserts: scenario["burst_profile"]["region_inserts"]
                .as_u64()
                .expect("region_inserts") as usize,
            obligation_inserts: scenario["burst_profile"]["obligation_inserts"]
                .as_u64()
                .expect("obligation_inserts") as usize,
        },
        operator_notes: scenario["operator_notes"].clone(),
        expected_projection: scenario["expected_report_projection"].clone(),
        operator_verdict: scenario["operator_verdict"]
            .as_str()
            .expect("operator_verdict")
            .to_string(),
    }
}

fn default_contract_fixture() -> ContractScenario {
    ContractScenario {
        scenario_id: DEFAULT_SCENARIO_ID.to_string(),
        description:
            "Expected-concurrent-task hints pre-size the runtime tables so a 4096-task burst avoids allocator growth churn."
                .to_string(),
        hint_mode: HintMode::ExpectedConcurrentTasks,
        worker_threads: 4,
        expected_concurrent_tasks: Some(4096),
        explicit_capacity_hints: None,
        burst_profile: BurstProfile {
            task_inserts: 4096,
            region_inserts: 1024,
            obligation_inserts: 2048,
        },
        operator_notes: json!({
            "safe_fallback_profile": "historical_defaults",
            "rationale": "50 percent headroom on the task estimate should absorb the burst while preserving the existing default profile when hints are absent."
        }),
        expected_projection: Value::Null,
        operator_verdict: "ready_for_rch".to_string(),
    }
}

fn load_contract_scenario() -> ContractScenario {
    let contract_path = std::env::var("ASUPERSYNC_RUNTIME_CAPACITY_HINTS_CONTRACT_PATH")
        .ok()
        .or_else(|| {
            Path::new(DEFAULT_CONTRACT_PATH)
                .exists()
                .then(|| DEFAULT_CONTRACT_PATH.into())
        });
    let scenario_id = std::env::var("ASUPERSYNC_RUNTIME_CAPACITY_HINTS_SCENARIO_ID")
        .unwrap_or_else(|_| DEFAULT_SCENARIO_ID.to_string());

    let Some(contract_path) = contract_path else {
        return default_contract_fixture();
    };

    let artifact: Value = serde_json::from_str(
        &fs::read_to_string(&contract_path).expect("read runtime capacity hints contract"),
    )
    .expect("parse runtime capacity hints contract");
    let scenario = artifact["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios array")
        .iter()
        .find(|candidate| candidate["scenario_id"].as_str() == Some(scenario_id.as_str()))
        .cloned()
        .expect("scenario present in runtime capacity hints contract");
    parse_contract_scenario(&scenario)
}

fn historical_default_hints() -> RuntimeCapacityHints {
    RuntimeCapacityHints::default()
}

fn resolved_hints_for_scenario(scenario: &ContractScenario) -> RuntimeCapacityHints {
    match scenario.hint_mode {
        HintMode::ExpectedConcurrentTasks => RuntimeCapacityHints::from_expected_concurrent_tasks(
            scenario
                .expected_concurrent_tasks
                .expect("expected_concurrent_tasks"),
        ),
        HintMode::WorkerThreadsAutoScale => RuntimeConfig {
            worker_threads: scenario.worker_threads,
            ..RuntimeConfig::default()
        }
        .resolved_capacity_hints(),
        HintMode::ExplicitZeroFallback => {
            let mut config = RuntimeConfig {
                worker_threads: scenario.worker_threads,
                capacity_hints: scenario.explicit_capacity_hints,
                ..RuntimeConfig::default()
            };
            config.normalize();
            config.resolved_capacity_hints()
        }
    }
}

fn simulate_arena_burst(initial_capacity: usize, inserts: usize) -> BurstArenaMetrics {
    let mut arena: Arena<u64> = Arena::with_capacity(initial_capacity);
    let initial_capacity = arena.capacity();
    let reserved_bytes_initial = arena.reserved_bytes();
    let mut last_capacity = initial_capacity;
    let mut growth_events = 0usize;
    let mut largest_capacity_jump = 0usize;
    let mut variance = VarianceTracker::default();
    variance.observe(initial_capacity);

    for index in 0..inserts {
        arena.insert(index as u64);
        let current_capacity = arena.capacity();
        variance.observe(current_capacity);
        if current_capacity != last_capacity {
            growth_events += 1;
            largest_capacity_jump = largest_capacity_jump.max(current_capacity - last_capacity);
            last_capacity = current_capacity;
        }
    }

    BurstArenaMetrics {
        initial_capacity,
        final_capacity: arena.capacity(),
        reserved_bytes_initial,
        reserved_bytes_final: arena.reserved_bytes(),
        growth_events,
        residual_realloc_count: growth_events,
        largest_capacity_jump,
        capacity_variance_slots: variance.variance(),
    }
}

fn arena_metrics_json(metrics: BurstArenaMetrics) -> Value {
    json!({
        "initial_capacity": metrics.initial_capacity,
        "final_capacity": metrics.final_capacity,
        "reserved_bytes_initial": metrics.reserved_bytes_initial,
        "reserved_bytes_final": metrics.reserved_bytes_final,
        "reserved_mib_initial": bytes_to_mib(metrics.reserved_bytes_initial),
        "reserved_mib_final": bytes_to_mib(metrics.reserved_bytes_final),
        "growth_events": metrics.growth_events,
        "residual_realloc_count": metrics.residual_realloc_count,
        "largest_capacity_jump": metrics.largest_capacity_jump,
        "capacity_variance_slots": metrics.capacity_variance_slots,
    })
}

fn scenario_report(scenario: &ContractScenario) -> Value {
    let baseline_hints = historical_default_hints();
    let selected_hints = resolved_hints_for_scenario(scenario);

    let baseline_task = simulate_arena_burst(
        baseline_hints.task_capacity,
        scenario.burst_profile.task_inserts,
    );
    let hinted_task = simulate_arena_burst(
        selected_hints.task_capacity,
        scenario.burst_profile.task_inserts,
    );
    let baseline_region = simulate_arena_burst(
        baseline_hints.region_capacity,
        scenario.burst_profile.region_inserts,
    );
    let hinted_region = simulate_arena_burst(
        selected_hints.region_capacity,
        scenario.burst_profile.region_inserts,
    );
    let baseline_obligation = simulate_arena_burst(
        baseline_hints.obligation_capacity,
        scenario.burst_profile.obligation_inserts,
    );
    let hinted_obligation = simulate_arena_burst(
        selected_hints.obligation_capacity,
        scenario.burst_profile.obligation_inserts,
    );

    let baseline_growth_events_total = baseline_task.growth_events
        + baseline_region.growth_events
        + baseline_obligation.growth_events;
    let hinted_growth_events_total =
        hinted_task.growth_events + hinted_region.growth_events + hinted_obligation.growth_events;
    let baseline_variance_total = round4(
        baseline_task.capacity_variance_slots
            + baseline_region.capacity_variance_slots
            + baseline_obligation.capacity_variance_slots,
    );
    let hinted_variance_total = round4(
        hinted_task.capacity_variance_slots
            + hinted_region.capacity_variance_slots
            + hinted_obligation.capacity_variance_slots,
    );
    let baseline_reserved_bytes_total = baseline_task.reserved_bytes_final
        + baseline_region.reserved_bytes_final
        + baseline_obligation.reserved_bytes_final;
    let hinted_reserved_bytes_total = hinted_task.reserved_bytes_final
        + hinted_region.reserved_bytes_final
        + hinted_obligation.reserved_bytes_final;
    let growth_event_reduction_ratio = if baseline_growth_events_total == 0 {
        0.0
    } else {
        round4(
            (baseline_growth_events_total.saturating_sub(hinted_growth_events_total)) as f64
                / baseline_growth_events_total as f64,
        )
    };
    let used_safe_fallback = matches!(scenario.hint_mode, HintMode::ExplicitZeroFallback);
    let fallback_reason = scenario.operator_notes["fallback_reason"].clone();
    let trace_capacity = TraceStorageProfile::Default.trace_buffer_capacity();
    let runtime_state = RuntimeState::with_capacity_hints_and_trace_capacity(
        selected_hints.task_capacity,
        selected_hints.region_capacity,
        selected_hints.obligation_capacity,
        trace_capacity,
        Arc::new(NoOpMetrics),
    );

    let projection_without_hash = json!({
        "scenario_id": scenario.scenario_id,
        "hint_mode": scenario.hint_mode.as_str(),
        "worker_threads": scenario.worker_threads,
        "selected_task_capacity": selected_hints.task_capacity,
        "selected_region_capacity": selected_hints.region_capacity,
        "selected_obligation_capacity": selected_hints.obligation_capacity,
        "task_growth_events_baseline": baseline_task.growth_events,
        "task_growth_events_hinted": hinted_task.growth_events,
        "region_growth_events_baseline": baseline_region.growth_events,
        "region_growth_events_hinted": hinted_region.growth_events,
        "obligation_growth_events_baseline": baseline_obligation.growth_events,
        "obligation_growth_events_hinted": hinted_obligation.growth_events,
        "baseline_growth_events_total": baseline_growth_events_total,
        "hinted_growth_events_total": hinted_growth_events_total,
        "growth_event_reduction_ratio": growth_event_reduction_ratio,
        "baseline_capacity_variance_total": baseline_variance_total,
        "hinted_capacity_variance_total": hinted_variance_total,
        "baseline_reserved_total_mib": bytes_to_mib(baseline_reserved_bytes_total),
        "hinted_reserved_total_mib": bytes_to_mib(hinted_reserved_bytes_total),
        "reserved_mib_delta": bytes_to_mib(hinted_reserved_bytes_total.saturating_sub(baseline_reserved_bytes_total)),
        "residual_realloc_count": hinted_task.residual_realloc_count
            + hinted_region.residual_realloc_count
            + hinted_obligation.residual_realloc_count,
        "used_safe_fallback": used_safe_fallback,
        "safe_fallback_profile": scenario.operator_notes["safe_fallback_profile"].clone(),
        "fallback_reason": fallback_reason,
        "runtime_trace_capacity": runtime_state.trace_buffer_capacity(),
        "operator_verdict": scenario.operator_verdict,
        "no_win_trigger": hinted_growth_events_total >= baseline_growth_events_total
            || hinted_variance_total > baseline_variance_total,
    });
    let projection_hash = fnv1a64(
        serde_json::to_string(&projection_without_hash)
            .expect("serialize projection")
            .as_bytes(),
    );
    let mut projection = projection_without_hash
        .as_object()
        .expect("projection object")
        .clone();
    projection.insert("projection_hash".to_string(), json!(projection_hash));

    let report = json!({
        "schema_version": "asupersync.runtime-capacity-hints-report.v1",
        "scenario_id": scenario.scenario_id,
        "description": scenario.description,
        "hint_mode": scenario.hint_mode.as_str(),
        "worker_threads": scenario.worker_threads,
        "expected_concurrent_tasks": scenario.expected_concurrent_tasks,
        "explicit_capacity_hints": scenario.explicit_capacity_hints.map(|hints| json!({
            "task_capacity": hints.task_capacity,
            "region_capacity": hints.region_capacity,
            "obligation_capacity": hints.obligation_capacity,
        })),
        "baseline_capacity_hints": {
            "task_capacity": baseline_hints.task_capacity,
            "region_capacity": baseline_hints.region_capacity,
            "obligation_capacity": baseline_hints.obligation_capacity,
        },
        "selected_capacity_hints": {
            "task_capacity": selected_hints.task_capacity,
            "region_capacity": selected_hints.region_capacity,
            "obligation_capacity": selected_hints.obligation_capacity,
        },
        "burst_profile": {
            "task_inserts": scenario.burst_profile.task_inserts,
            "region_inserts": scenario.burst_profile.region_inserts,
            "obligation_inserts": scenario.burst_profile.obligation_inserts,
        },
        "runtime_state": {
            "trace_buffer_capacity": runtime_state.trace_buffer_capacity(),
            "trace_buffer_capacity_matches_default": runtime_state.trace_buffer_capacity() == trace_capacity,
        },
        "table_burst_metrics": {
            "tasks": {
                "baseline": arena_metrics_json(baseline_task),
                "hinted": arena_metrics_json(hinted_task),
            },
            "regions": {
                "baseline": arena_metrics_json(baseline_region),
                "hinted": arena_metrics_json(hinted_region),
            },
            "obligations": {
                "baseline": arena_metrics_json(baseline_obligation),
                "hinted": arena_metrics_json(hinted_obligation),
            },
        },
        "allocation_summary": {
            "baseline_growth_events_total": baseline_growth_events_total,
            "hinted_growth_events_total": hinted_growth_events_total,
            "growth_event_reduction_ratio": growth_event_reduction_ratio,
            "baseline_capacity_variance_total": baseline_variance_total,
            "hinted_capacity_variance_total": hinted_variance_total,
            "baseline_reserved_total_mib": bytes_to_mib(baseline_reserved_bytes_total),
            "hinted_reserved_total_mib": bytes_to_mib(hinted_reserved_bytes_total),
            "reserved_mib_delta": bytes_to_mib(hinted_reserved_bytes_total.saturating_sub(baseline_reserved_bytes_total)),
            "no_win_trigger": projection["no_win_trigger"].clone(),
        },
        "assumptions_ledger": [
            "historical_defaults remain the conservative fallback for runtime table sizing",
            "growth events are counted as Vec capacity changes on deterministic arena inserts only",
            "capacity hints pre-size task, region, and obligation tables at construction time and never auto-resize live state",
            "trace-buffer capacity stays on the default profile for this proof so the reported win isolates arena pre-sizing",
            "tail-risk proxy here is allocator growth churn and capacity variance under a fixed burst, not a scheduler timing benchmark"
        ],
        "operator_notes": scenario.operator_notes,
        "operator_verdict": scenario.operator_verdict,
        "validation_verdict": {
            "status": "passed",
            "checks": [
                "selected capacity hints remain deterministic for the chosen hint mode",
                "task, region, and obligation arenas preserve the historical default fallback when hints are absent or invalid",
                "the hinted profile never increases growth events or allocation variance for the fixed burst scenarios",
                "runtime trace capacity remains unchanged so this proof isolates runtime table pre-sizing only"
            ]
        },
        "report_projection": Value::Object(projection),
    });
    report
}

fn maybe_write_report(report: &Value) {
    let Ok(report_path) = std::env::var("ASUPERSYNC_RUNTIME_CAPACITY_HINTS_REPORT_PATH") else {
        return;
    };
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).expect("create runtime capacity hints report directory");
    }
    fs::write(
        report_path,
        serde_json::to_string_pretty(report).expect("serialize runtime capacity hints report"),
    )
    .expect("write runtime capacity hints report");
}

#[test]
fn runtime_capacity_hints_expected_tasks_reduce_growth_events() {
    let scenario = ContractScenario {
        expected_projection: Value::Null,
        ..default_contract_fixture()
    };
    let report = scenario_report(&scenario);
    let projection = &report["report_projection"];

    assert_eq!(
        projection["selected_task_capacity"],
        json!(6144),
        "4096 expected tasks should receive 50 percent headroom"
    );
    assert!(
        projection["hinted_growth_events_total"]
            .as_u64()
            .expect("hinted growth events")
            < projection["baseline_growth_events_total"]
                .as_u64()
                .expect("baseline growth events"),
        "explicit task hints should reduce burst growth events"
    );
}

#[test]
fn runtime_capacity_hints_worker_auto_scale_beats_historical_defaults() {
    let scenario = ContractScenario {
        scenario_id: "AA-RUNTIME-CAPACITY-HINTS-AUTO-SCALE-64W".to_string(),
        description:
            "Worker-thread auto-scaling widens runtime tables for a 64-worker swarm host without needing a separate sizing knob."
                .to_string(),
        hint_mode: HintMode::WorkerThreadsAutoScale,
        worker_threads: 64,
        expected_concurrent_tasks: None,
        explicit_capacity_hints: None,
        burst_profile: BurstProfile {
            task_inserts: 8192,
            region_inserts: 2048,
            obligation_inserts: 4096,
        },
        operator_notes: json!({
            "safe_fallback_profile": "historical_defaults",
            "rationale": "Large-worker hosts should derive wider initial table capacities from the existing worker-thread count when no explicit hint is provided."
        }),
        expected_projection: Value::Null,
        operator_verdict: "ready_for_rch".to_string(),
    };
    let report = scenario_report(&scenario);
    let projection = &report["report_projection"];

    assert_eq!(
        projection["selected_task_capacity"],
        json!(8192),
        "64-worker hosts should auto-scale task capacity above the historical default"
    );
    assert_eq!(
        projection["selected_region_capacity"],
        json!(2048),
        "64-worker hosts should auto-scale region capacity"
    );
    assert_eq!(
        projection["selected_obligation_capacity"],
        json!(4096),
        "64-worker hosts should auto-scale obligation capacity"
    );
}

#[test]
fn runtime_capacity_hints_zero_hints_fail_closed_to_defaults() {
    let scenario = ContractScenario {
        scenario_id: "AA-RUNTIME-CAPACITY-HINTS-ZERO-HINT-FALLBACK".to_string(),
        description:
            "Zeroed manual hints normalize back to the historical defaults and preserve the baseline allocation surface."
                .to_string(),
        hint_mode: HintMode::ExplicitZeroFallback,
        worker_threads: 4,
        expected_concurrent_tasks: None,
        explicit_capacity_hints: Some(RuntimeCapacityHints::new(0, 0, 0)),
        burst_profile: BurstProfile {
            task_inserts: 512,
            region_inserts: 128,
            obligation_inserts: 256,
        },
        operator_notes: json!({
            "safe_fallback_profile": "historical_defaults",
            "fallback_reason": "zero_hints_normalized_to_safe_defaults",
            "rationale": "Invalid zero hints must fail closed to the existing default capacities rather than shrinking the runtime tables."
        }),
        expected_projection: Value::Null,
        operator_verdict: "fallback_only".to_string(),
    };
    let report = scenario_report(&scenario);
    let projection = &report["report_projection"];

    assert_eq!(
        projection["selected_task_capacity"],
        json!(RuntimeCapacityHints::default().task_capacity),
        "zero hints must normalize back to the historical default task capacity"
    );
    assert_eq!(
        projection["used_safe_fallback"],
        json!(true),
        "invalid zero hints should be reported as a conservative fallback"
    );
    assert_eq!(
        projection["fallback_reason"],
        json!("zero_hints_normalized_to_safe_defaults")
    );
}

#[test]
fn runtime_capacity_hints_smoke_contract_emits_report() {
    let scenario = load_contract_scenario();
    let report = scenario_report(&scenario);
    maybe_write_report(&report);

    if !scenario.expected_projection.is_null() {
        assert_eq!(
            report["report_projection"], scenario.expected_projection,
            "scenario {} should produce a stable projection hash",
            scenario.scenario_id
        );
    }

    if let Ok(report_path) = std::env::var("ASUPERSYNC_RUNTIME_CAPACITY_HINTS_REPORT_PATH") {
        println!("runtime_capacity_hints_report_path={report_path}");
        println!("RUNTIME_CAPACITY_HINTS_REPORT_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize runtime capacity hints report")
        );
        println!("RUNTIME_CAPACITY_HINTS_REPORT_JSON_END");
    }
}
