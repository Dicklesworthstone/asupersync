//! Contract-backed topology replay smoke scenarios.

#[path = "support/topology_replay.rs"]
mod topology_replay_support;

use asupersync::runtime::scheduler::SchedulerTopologyDescriptor;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::Path;
use topology_replay_support::{ReplayLocality, TopologyFixture, TopologyReplayTrace};

const CONTRACT_JSON: &str =
    include_str!("../artifacts/scheduler_topology_replay_smoke_contract_v1.json");
const OUTPUT_DIR_ENV: &str = "ASUPERSYNC_TOPOLOGY_REPLAY_OUTPUT_DIR";
const SCENARIO_ENV: &str = "ASUPERSYNC_TOPOLOGY_REPLAY_SCENARIO";

#[derive(Debug, Deserialize)]
struct ReplayContract {
    runner_script: String,
    required_execute_output_files: Vec<String>,
    smoke_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    fixture: ReplayFixture,
    expected_trace: ExpectedTrace,
}

#[derive(Debug, Deserialize)]
struct ReplayFixture {
    topology: SchedulerTopologyDescriptor,
    worker_to_cohort: Vec<usize>,
    replay_workers: Vec<usize>,
    seed: u64,
    seeded_workers: Vec<SeededWorker>,
}

#[derive(Debug, Deserialize)]
struct SeededWorker {
    worker_id: usize,
    task_id_start: u32,
    task_count: usize,
}

#[derive(Debug, Deserialize)]
struct ExpectedTrace {
    first_hash: u64,
    second_hash: u64,
    event_count: usize,
    #[serde(default)]
    local_steal_count: Option<usize>,
    remote_spill_count: usize,
    locality_sequence: Vec<String>,
    #[serde(default)]
    cohort_event_counts: Vec<usize>,
    #[serde(default)]
    wake_to_run_latency_by_cohort: Vec<CohortLatencyByCohort>,
    #[serde(default)]
    fairness_checks: Option<FairnessChecks>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CohortLatencyByCohort {
    cohort_id: usize,
    slots: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct FairnessChecks {
    active_replay_cohorts: Vec<usize>,
    cohorts_with_events: Vec<usize>,
    starvation_free: bool,
    drained_all_seeded_tasks: bool,
}

struct ActualTrace {
    first_hash: u64,
    second_hash: u64,
    event_count: usize,
    local_steal_count: usize,
    remote_spill_count: usize,
    locality_sequence: Vec<String>,
    cohort_event_counts: Vec<usize>,
    wake_to_run_latency_by_cohort: Vec<CohortLatencyByCohort>,
    fairness_checks: FairnessChecks,
    first_trace: TopologyReplayTrace,
    second_trace: TopologyReplayTrace,
}

#[test]
fn scheduler_topology_replay_contract_scenarios_match_expected_trace() {
    let contract: ReplayContract =
        serde_json::from_str(CONTRACT_JSON).expect("topology replay contract must parse");
    assert_eq!(
        contract.runner_script,
        "scripts/run_scheduler_topology_replay_smoke.sh"
    );
    assert_eq!(
        contract.required_execute_output_files,
        [
            "bundle_manifest.json",
            "run_report.json",
            "topology_manifest.json",
            "topology_trace.json",
            "run.log",
        ]
    );

    let selected_scenario = env::var(SCENARIO_ENV).ok();
    let output_dir = env::var(OUTPUT_DIR_ENV).ok();
    let mut emitted_selected = false;

    for scenario in &contract.smoke_scenarios {
        let actual = execute_scenario(&scenario.fixture);

        if selected_scenario.as_deref() == Some(scenario.scenario_id.as_str()) {
            let output_dir = output_dir
                .as_deref()
                .expect("output directory must be set when selecting a scenario");
            emit_artifacts(Path::new(output_dir), scenario, &actual)
                .expect("selected scenario should emit topology artifacts");
            eprintln!(
                "selected scenario summary: id={} first_hash={} second_hash={} events={} local_steals={} remote_spills={} locality_sequence={:?} cohort_event_counts={:?} wake_to_run_latency_by_cohort={:?} fairness_checks={:?}",
                scenario.scenario_id,
                actual.first_hash,
                actual.second_hash,
                actual.event_count,
                actual.local_steal_count,
                actual.remote_spill_count,
                actual.locality_sequence,
                actual.cohort_event_counts,
                actual.wake_to_run_latency_by_cohort,
                actual.fairness_checks
            );
            emitted_selected = true;
        }

        assert_eq!(
            actual.first_trace.events, actual.second_trace.events,
            "scenario {} must keep identical steal-path decisions across reruns",
            scenario.scenario_id
        );
        assert_eq!(
            actual.first_hash, actual.second_hash,
            "scenario {} must keep identical stable hashes across reruns",
            scenario.scenario_id
        );
        assert_eq!(
            actual.event_count, scenario.expected_trace.event_count,
            "scenario {} emitted an unexpected event count",
            scenario.scenario_id
        );
        if let Some(expected_local_steal_count) = scenario.expected_trace.local_steal_count {
            assert_eq!(
                actual.local_steal_count, expected_local_steal_count,
                "scenario {} emitted an unexpected local steal count",
                scenario.scenario_id
            );
        }
        assert_eq!(
            actual.remote_spill_count, scenario.expected_trace.remote_spill_count,
            "scenario {} emitted an unexpected remote spill count: actual locality sequence = {:?}",
            scenario.scenario_id, actual.locality_sequence
        );
        if !scenario.expected_trace.locality_sequence.is_empty() {
            assert_eq!(
                actual.locality_sequence, scenario.expected_trace.locality_sequence,
                "scenario {} emitted an unexpected locality sequence: actual remote spills = {}",
                scenario.scenario_id, actual.remote_spill_count
            );
        }
        if !scenario.expected_trace.cohort_event_counts.is_empty() {
            assert_eq!(
                actual.cohort_event_counts, scenario.expected_trace.cohort_event_counts,
                "scenario {} emitted unexpected cohort event counts",
                scenario.scenario_id
            );
        }
        if !scenario
            .expected_trace
            .wake_to_run_latency_by_cohort
            .is_empty()
        {
            assert_eq!(
                actual.wake_to_run_latency_by_cohort,
                scenario.expected_trace.wake_to_run_latency_by_cohort,
                "scenario {} emitted unexpected wake-to-run latency slots by cohort",
                scenario.scenario_id
            );
        }
        if let Some(expected_fairness_checks) = &scenario.expected_trace.fairness_checks {
            assert_eq!(
                &actual.fairness_checks, expected_fairness_checks,
                "scenario {} emitted unexpected fairness checks",
                scenario.scenario_id
            );
        }
        if scenario.expected_trace.first_hash != 0 {
            assert_eq!(
                actual.first_hash, scenario.expected_trace.first_hash,
                "scenario {} emitted an unexpected first stable hash",
                scenario.scenario_id
            );
        }
        if scenario.expected_trace.second_hash != 0 {
            assert_eq!(
                actual.second_hash, scenario.expected_trace.second_hash,
                "scenario {} emitted an unexpected second stable hash",
                scenario.scenario_id
            );
        }
    }

    if let Some(selected_scenario) = selected_scenario {
        assert!(
            emitted_selected,
            "selected scenario {selected_scenario} was not found in the contract"
        );
    }
}

fn execute_scenario(fixture: &ReplayFixture) -> ActualTrace {
    let first_fixture = build_fixture(fixture);
    let second_fixture = build_fixture(fixture);
    let first_trace = first_fixture.replay();
    let second_trace = second_fixture.replay();
    let total_seeded_tasks = fixture
        .seeded_workers
        .iter()
        .map(|seeded_worker| seeded_worker.task_count)
        .sum();
    let locality_sequence = first_trace
        .events
        .iter()
        .map(|event| locality_label(event.locality))
        .collect();

    ActualTrace {
        first_hash: first_trace.stable_hash(),
        second_hash: second_trace.stable_hash(),
        event_count: first_trace.events.len(),
        local_steal_count: first_trace
            .events
            .iter()
            .filter(|event| event.locality == ReplayLocality::Local)
            .count(),
        remote_spill_count: first_trace.remote_spill_count(),
        locality_sequence,
        cohort_event_counts: cohort_event_counts(&first_trace),
        wake_to_run_latency_by_cohort: wake_to_run_latency_by_cohort(&first_trace),
        fairness_checks: fairness_checks(&first_trace, total_seeded_tasks),
        first_trace,
        second_trace,
    }
}

fn build_fixture(fixture: &ReplayFixture) -> TopologyFixture {
    let mut replay_fixture = TopologyFixture::new(
        fixture.topology.clone(),
        fixture.worker_to_cohort.clone(),
        fixture.replay_workers.clone(),
        fixture.seed,
    );
    for seeded_worker in &fixture.seeded_workers {
        replay_fixture = replay_fixture.seed_worker(
            seeded_worker.worker_id,
            seeded_worker.task_id_start,
            seeded_worker.task_count,
        );
    }
    replay_fixture
}

fn emit_artifacts(
    output_dir: &Path,
    scenario: &ReplayScenario,
    actual: &ActualTrace,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let topology_manifest_path = output_dir.join("topology_manifest.json");
    let topology_trace_path = output_dir.join("topology_trace.json");

    let topology_manifest = json!({
        "scenario_id": scenario.scenario_id,
        "topology": scenario.fixture.topology,
        "worker_to_cohort": scenario.fixture.worker_to_cohort,
        "replay_workers": scenario.fixture.replay_workers,
        "seed": scenario.fixture.seed,
        "seeded_workers": scenario.fixture.seeded_workers.iter().map(|seeded_worker| json!({
            "worker_id": seeded_worker.worker_id,
            "task_id_start": seeded_worker.task_id_start,
            "task_count": seeded_worker.task_count,
        })).collect::<Vec<_>>(),
    });

    let topology_trace = json!({
        "scenario_id": scenario.scenario_id,
        "first_trace_hash": actual.first_hash,
        "second_trace_hash": actual.second_hash,
        "hashes_match": actual.first_hash == actual.second_hash,
        "event_count": actual.event_count,
        "local_steal_count": actual.local_steal_count,
        "remote_spill_count": actual.remote_spill_count,
        "locality_sequence": actual.locality_sequence,
        "cohort_event_counts": actual.cohort_event_counts,
        "wake_to_run_latency_by_cohort": actual.wake_to_run_latency_by_cohort.iter().map(|summary| json!({
            "cohort_id": summary.cohort_id,
            "slots": summary.slots,
        })).collect::<Vec<_>>(),
        "fairness_checks": {
            "active_replay_cohorts": actual.fairness_checks.active_replay_cohorts,
            "cohorts_with_events": actual.fairness_checks.cohorts_with_events,
            "starvation_free": actual.fairness_checks.starvation_free,
            "drained_all_seeded_tasks": actual.fairness_checks.drained_all_seeded_tasks,
        },
        "events": actual.first_trace.events.iter().map(|event| json!({
            "thief_worker": event.thief_worker,
            "source_worker": event.source_worker,
            "thief_cohort": event.thief_cohort,
            "source_cohort": event.source_cohort,
            "task_id_u64": event.task_id.as_u64(),
            "task_id_debug": format!("{:?}", event.task_id),
            "locality": locality_label(event.locality),
        })).collect::<Vec<_>>(),
    });

    fs::write(
        topology_manifest_path,
        serde_json::to_vec_pretty(&topology_manifest)?,
    )?;
    fs::write(
        topology_trace_path,
        serde_json::to_vec_pretty(&topology_trace)?,
    )?;
    Ok(())
}

fn locality_label(locality: ReplayLocality) -> String {
    match locality {
        ReplayLocality::Local => "local".to_string(),
        ReplayLocality::Remote => "remote".to_string(),
    }
}

fn cohort_event_counts(trace: &TopologyReplayTrace) -> Vec<usize> {
    let mut counts = vec![0; trace.topology.cohort_count];
    for event in &trace.events {
        counts[event.thief_cohort] += 1;
    }
    counts
}

fn wake_to_run_latency_by_cohort(trace: &TopologyReplayTrace) -> Vec<CohortLatencyByCohort> {
    let mut slots_by_cohort = vec![Vec::new(); trace.topology.cohort_count];
    for (slot_index, event) in trace.events.iter().enumerate() {
        slots_by_cohort[event.thief_cohort].push(slot_index + 1);
    }
    slots_by_cohort
        .into_iter()
        .enumerate()
        .filter_map(|(cohort_id, slots)| {
            (!slots.is_empty()).then_some(CohortLatencyByCohort { cohort_id, slots })
        })
        .collect()
}

fn fairness_checks(trace: &TopologyReplayTrace, total_seeded_tasks: usize) -> FairnessChecks {
    let active_replay_cohorts = trace
        .replay_workers
        .iter()
        .map(|worker_id| trace.worker_to_cohort[*worker_id])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let cohorts_with_events = trace
        .events
        .iter()
        .map(|event| event.thief_cohort)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    FairnessChecks {
        starvation_free: active_replay_cohorts == cohorts_with_events,
        drained_all_seeded_tasks: trace.events.len() == total_seeded_tasks,
        active_replay_cohorts,
        cohorts_with_events,
    }
}
