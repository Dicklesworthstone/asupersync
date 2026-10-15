//! Additional consumers for the deterministic topology replay helper.

#[path = "support/topology_replay.rs"]
mod topology_replay_support;

use asupersync::runtime::scheduler::SchedulerTopologyDescriptor;
use topology_replay_support::{ReplayLocality, TopologyFixture};

#[test]
fn scheduler_topology_replay_hash_changes_with_cohort_mapping() {
    let local_fixture = TopologyFixture::new(
        SchedulerTopologyDescriptor {
            worker_threads: 2,
            cohort_count: 1,
            memory_budget_gib: 256,
        },
        vec![0, 0],
        vec![1],
        99,
    )
    .seed_worker(0, 50_000, 1);
    let local_trace = local_fixture.replay();

    let remote_fixture = TopologyFixture::new(
        SchedulerTopologyDescriptor {
            worker_threads: 2,
            cohort_count: 2,
            memory_budget_gib: 256,
        },
        vec![0, 1],
        vec![1],
        99,
    )
    .seed_worker(0, 50_000, 1);
    let remote_trace = remote_fixture.replay();

    assert_eq!(local_trace.events.len(), 1);
    assert_eq!(remote_trace.events.len(), 1);
    assert_eq!(local_trace.events[0].locality, ReplayLocality::Local);
    assert_eq!(remote_trace.events[0].locality, ReplayLocality::Remote);
    assert_eq!(local_trace.remote_spill_count(), 0);
    assert_eq!(remote_trace.remote_spill_count(), 1);
    assert_ne!(
        local_trace.stable_hash(),
        remote_trace.stable_hash(),
        "cohort mapping must contribute to the replay hash"
    );
}

#[test]
fn scheduler_topology_replay_multidonor_fixture_drains_without_loss() {
    let fixture = TopologyFixture::new(
        SchedulerTopologyDescriptor {
            worker_threads: 4,
            cohort_count: 2,
            memory_budget_gib: 256,
        },
        vec![0, 0, 1, 1],
        vec![1, 3],
        23,
    )
    .seed_worker(0, 60_000, 2)
    .seed_worker(2, 70_000, 3);

    let trace = fixture.replay();

    assert_eq!(
        trace.events.len(),
        5,
        "all seeded tasks should appear exactly once in the replay trace"
    );
    assert!(
        trace.stable_hash() != 0,
        "stable hash should remain non-zero for non-empty replay traces"
    );
}
