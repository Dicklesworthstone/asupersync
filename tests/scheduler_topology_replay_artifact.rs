//! Contract-backed topology replay smoke scenarios.

#[path = "support/topology_replay.rs"]
mod topology_replay_support;

use asupersync::runtime::scheduler::SchedulerTopologyDescriptor;
use serde::Deserialize;
use serde_json::json;
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
    remote_spill_count: usize,
    locality_sequence: Vec<String>,
}

struct ActualTrace {
    first_hash: u64,
    second_hash: u64,
    event_count: usize,
    remote_spill_count: usize,
    locality_sequence: Vec<String>,
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
                "selected scenario summary: id={} first_hash={} second_hash={} events={} remote_spills={} locality_sequence={:?}",
                scenario.scenario_id,
                actual.first_hash,
                actual.second_hash,
                actual.event_count,
                actual.remote_spill_count,
                actual.locality_sequence
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
    let locality_sequence = first_trace
        .events
        .iter()
        .map(|event| locality_label(event.locality))
        .collect();

    ActualTrace {
        first_hash: first_trace.stable_hash(),
        second_hash: second_trace.stable_hash(),
        event_count: first_trace.events.len(),
        remote_spill_count: first_trace.remote_spill_count(),
        locality_sequence,
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
        "remote_spill_count": actual.remote_spill_count,
        "locality_sequence": actual.locality_sequence,
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
