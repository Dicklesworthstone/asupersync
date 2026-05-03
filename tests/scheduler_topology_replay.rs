//! Deterministic topology replay tests for steal-heavy scheduler traces.

#[path = "support/topology_replay.rs"]
mod topology_replay_support;

use asupersync::runtime::scheduler::SchedulerTopologyDescriptor;
use serde_json::json;
use std::panic::AssertUnwindSafe;
use topology_replay_support::{ReplayLocality, TopologyFixture};

#[test]
fn scheduler_topology_replay_hash_stable_across_reruns() {
    let fixture = TopologyFixture::new(
        SchedulerTopologyDescriptor {
            worker_threads: 4,
            cohort_count: 2,
            memory_budget_gib: 256,
        },
        vec![0, 0, 1, 1],
        vec![1, 3],
        17,
    )
    .seed_worker(0, 10_000, 3)
    .seed_worker(2, 20_000, 2);

    let first = fixture.replay();
    let second = fixture.replay();

    assert_eq!(
        first.events, second.events,
        "identical topology replay fixtures must produce identical steal traces"
    );
    assert_eq!(
        first.stable_hash(),
        second.stable_hash(),
        "identical topology replay fixtures must produce identical stable hashes"
    );

    let local_steals = first
        .events
        .iter()
        .filter(|event| event.locality == ReplayLocality::Local)
        .count();
    let remote_steals = first.remote_spill_count();
    let replay_summary = json!({
        "topology": {
            "worker_threads": first.topology.worker_threads,
            "cohort_count": first.topology.cohort_count,
            "memory_budget_gib": first.topology.memory_budget_gib,
        },
        "worker_to_cohort": first.worker_to_cohort,
        "replay_workers": first.replay_workers,
        "replay_hash": first.stable_hash(),
        "locality_labels": first.events.iter().map(|event| match event.locality {
            ReplayLocality::Local => "local",
            ReplayLocality::Remote => "remote",
        }).collect::<Vec<_>>(),
        "local_steals": local_steals,
        "remote_steals": remote_steals,
        "spill_count": remote_steals,
        "deterministic_rerun_equal": first.events == second.events,
    });
    println!("SCHEDULER_TOPOLOGY_REPLAY_SUMMARY_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&replay_summary).expect("serialize replay summary")
    );
    println!("SCHEDULER_TOPOLOGY_REPLAY_SUMMARY_JSON_END");
}

#[test]
fn scheduler_topology_fixture_preserves_worker_to_cohort_mapping() {
    let worker_to_cohort = vec![0, 0, 2, 2];
    let fixture = TopologyFixture::new(
        SchedulerTopologyDescriptor {
            worker_threads: 4,
            cohort_count: 3,
            memory_budget_gib: 256,
        },
        worker_to_cohort.clone(),
        vec![1, 3],
        99,
    )
    .seed_worker(0, 50_000, 2)
    .seed_worker(2, 60_000, 2);

    let trace = fixture.replay();
    assert_eq!(trace.worker_to_cohort, worker_to_cohort);
    assert_eq!(trace.topology.worker_threads, 4);
    assert_eq!(trace.topology.cohort_count, 3);
    assert!(
        trace
            .events
            .iter()
            .all(|event| trace.worker_to_cohort[event.thief_worker] == event.thief_cohort),
        "thief cohort labels must match the declared worker mapping"
    );
    assert!(
        trace
            .events
            .iter()
            .all(|event| trace.worker_to_cohort[event.source_worker] == event.source_cohort),
        "source cohort labels must match the declared worker mapping"
    );
}

#[test]
fn scheduler_topology_replay_allows_empty_cohort_slots() {
    let fixture = TopologyFixture::new(
        SchedulerTopologyDescriptor {
            worker_threads: 4,
            cohort_count: 3,
            memory_budget_gib: 256,
        },
        vec![0, 0, 2, 2],
        vec![1, 3],
        123,
    )
    .seed_worker(0, 70_000, 1)
    .seed_worker(2, 80_000, 1);

    let trace = fixture.replay();
    assert_eq!(trace.events.len(), 2);
    assert_eq!(trace.remote_spill_count(), 0);
    assert!(
        trace
            .events
            .iter()
            .all(|event| event.source_cohort != 1 && event.thief_cohort != 1),
        "unused cohort slots should remain absent from the trace instead of corrupting replay state"
    );
    assert!(
        trace
            .events
            .iter()
            .all(|event| event.locality == ReplayLocality::Local),
        "empty cohort slots should not force same-cohort steals to be classified as remote"
    );
}

#[test]
fn scheduler_topology_replay_supports_single_worker_cohorts() {
    let fixture = TopologyFixture::new(
        SchedulerTopologyDescriptor {
            worker_threads: 4,
            cohort_count: 4,
            memory_budget_gib: 256,
        },
        vec![0, 1, 2, 3],
        vec![1, 3],
        321,
    )
    .seed_worker(0, 90_000, 2)
    .seed_worker(2, 91_000, 1);

    let trace = fixture.replay();
    assert_eq!(trace.events.len(), 3);
    assert_eq!(trace.remote_spill_count(), 3);
    assert!(
        trace
            .events
            .iter()
            .all(|event| event.locality == ReplayLocality::Remote),
        "single-worker cohorts should classify every cross-worker steal as remote"
    );
}

#[test]
fn scheduler_topology_replay_rejects_duplicate_seeded_task_ids() {
    let fixture = TopologyFixture::new(
        SchedulerTopologyDescriptor {
            worker_threads: 2,
            cohort_count: 2,
            memory_budget_gib: 256,
        },
        vec![0, 1],
        vec![1],
        77,
    )
    .seed_worker(0, 1_000, 2)
    .seed_worker(0, 1_000, 1);

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| fixture.replay()));
    assert!(
        result.is_err(),
        "repeated task seeds should fail explicitly instead of silently aliasing task ownership"
    );
}

#[test]
fn scheduler_topology_replay_labels_locality_and_remote_spill() {
    let local_fixture = TopologyFixture::new(
        SchedulerTopologyDescriptor {
            worker_threads: 2,
            cohort_count: 1,
            memory_budget_gib: 256,
        },
        vec![0, 0],
        vec![1],
        7,
    )
    .seed_worker(0, 30_000, 1);
    let local_trace = local_fixture.replay();
    assert_eq!(local_trace.events.len(), 1);
    assert_eq!(local_trace.events[0].locality, ReplayLocality::Local);
    assert_eq!(local_trace.remote_spill_count(), 0);

    let remote_fixture = TopologyFixture::new(
        SchedulerTopologyDescriptor {
            worker_threads: 2,
            cohort_count: 2,
            memory_budget_gib: 256,
        },
        vec![0, 1],
        vec![1],
        7,
    )
    .seed_worker(0, 40_000, 1);
    let remote_trace = remote_fixture.replay();
    assert_eq!(remote_trace.events.len(), 1);
    assert_eq!(remote_trace.events[0].locality, ReplayLocality::Remote);
    assert_eq!(remote_trace.remote_spill_count(), 1);
}
