//! Deterministic topology replay tests for steal-heavy scheduler traces.

#[path = "support/topology_replay.rs"]
mod topology_replay_support;

use asupersync::runtime::scheduler::SchedulerTopologyDescriptor;
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
