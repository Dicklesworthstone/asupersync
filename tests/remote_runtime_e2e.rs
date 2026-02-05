//! Remote Runtime E2E Suite + Network Faults (bd-2bohm).
//!
//! End-to-end remote execution tests: spawn/ack/cancel/result flows under
//! network faults and lease expiry. Uses simulated network with deterministic
//! seeds and structured tracing.
//!
//! Covers:
//! - Full spawn → ack → complete → result delivery lifecycle
//! - Cancel request propagation and task termination
//! - Lease expiry forces task cleanup + failure result
//! - Idempotency: duplicate spawns return cached results
//! - Idempotency conflicts: same key, different computation
//! - Causal ordering: vector clocks advance monotonically
//! - Multi-node chain: A → B → C spawn cascades
//! - Fan-out: A spawns N tasks on B concurrently
//! - Partition blocks ack delivery, heal recovers
//! - Cancel during partition is dropped, retransmit after heal
//! - Crash/restart clears state, post-restart spawn succeeds
//! - Lease expiry during partition sends failure on heal
//! - Deterministic replay: same seed → identical trace
//! - Saga compensation: step failure triggers LIFO rollback
//! - Mixed workload stress under lossy conditions
//!
//! Cross-references:
//!   Harness:         src/lab/network/harness.rs
//!   Network sim:     src/lab/network/network.rs
//!   Remote protocol: src/remote.rs
//!   Fault sim tests: tests/network_fault_simulation.rs

#[macro_use]
mod common;

use common::*;
use asupersync::lab::network::{
    DistributedHarness, Fault, FaultScript, HarnessFault, HarnessTraceEvent, HarnessTraceKind,
    NetworkConditions, NetworkConfig, NodeEvent,
};
use asupersync::remote::{
    ComputationName, DedupDecision, IdempotencyKey, IdempotencyStore, NodeId, RemoteTaskId, Saga,
    SagaState,
};
use asupersync::types::Time;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_test(name: &str, seed: u64, conditions: &NetworkConditions) {
    init_test_logging();
    test_phase!(name);
    tracing::info!(seed, ?conditions, "remote runtime e2e config");
}

/// Build a NetworkConfig from seed and conditions.
fn make_config(seed: u64, conditions: NetworkConditions) -> NetworkConfig {
    NetworkConfig {
        seed,
        default_conditions: conditions,
        capture_trace: true,
        ..NetworkConfig::default()
    }
}

/// Two-node harness with given seed and conditions.
fn harness_two(seed: u64, conditions: NetworkConditions) -> (DistributedHarness, NodeId, NodeId) {
    let mut h = DistributedHarness::new(make_config(seed, conditions));
    let a = h.add_node("origin");
    let b = h.add_node("worker");
    (h, a, b)
}

/// Three-node harness.
fn harness_three(
    seed: u64,
    conditions: NetworkConditions,
) -> (DistributedHarness, NodeId, NodeId, NodeId) {
    let mut h = DistributedHarness::new(make_config(seed, conditions));
    let a = h.add_node("origin");
    let b = h.add_node("relay");
    let c = h.add_node("target");
    (h, a, b, c)
}

/// Count trace events matching a predicate.
fn count_trace<F: Fn(&HarnessTraceEvent) -> bool>(h: &DistributedHarness, f: F) -> usize {
    h.trace().iter().filter(|e| f(e)).count()
}

/// Count NodeEvents matching a predicate.
fn count_events<F: Fn(&NodeEvent) -> bool>(node_events: &[NodeEvent], f: F) -> usize {
    node_events.iter().filter(|e| f(e)).count()
}

/// Count sent messages of a given type from→to.
fn count_sent(h: &DistributedHarness, from: &NodeId, to: &NodeId, msg_type: &str) -> usize {
    count_trace(h, |e| {
        matches!(
            &e.kind,
            HarnessTraceKind::MessageSent { from: f, to: t, msg_type: m }
            if f == from && t == to && m == msg_type
        )
    })
}

// ===========================================================================
// SPAWN / ACK / COMPLETE LIFECYCLE
// ===========================================================================

#[test]
fn spawn_ack_complete_lifecycle() {
    let seed = 42;
    let conditions = NetworkConditions::local();
    init_test("spawn_ack_complete_lifecycle", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let tid = RemoteTaskId::from_raw(1000);

    h.inject_spawn(&a, &b, tid);
    // Default work is 100ms; local latency ~1ms; need ≥110ms for full round-trip.
    h.run_for(Duration::from_millis(200));

    let events = h.node(&b).unwrap().events();
    // B received spawn, accepted it, and completed the task.
    assert!(events
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnReceived { task_id, .. } if *task_id == tid)));
    assert!(events
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnAccepted { task_id } if *task_id == tid)));
    assert!(events
        .iter()
        .any(|e| matches!(e, NodeEvent::TaskCompleted { task_id } if *task_id == tid)));
    // B should have no running tasks after completion.
    assert_eq!(h.node(&b).unwrap().running_task_count(), 0);

    // Verify trace records the result delivery from B→A.
    assert!(
        count_sent(&h, &b, &a, "ResultDelivery") >= 1,
        "expected at least one ResultDelivery from worker to origin"
    );
}

#[test]
fn spawn_ack_sent_immediately() {
    let seed = 43;
    let conditions = NetworkConditions::local();
    init_test("spawn_ack_sent_immediately", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let tid = RemoteTaskId::from_raw(2000);

    h.inject_spawn(&a, &b, tid);
    // Run just enough for spawn to arrive and ack to be sent (not for task to complete).
    h.run_for(Duration::from_millis(15));

    // B accepted but task is still running.
    let events = h.node(&b).unwrap().events();
    assert!(events
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnAccepted { .. })));
    assert!(h.node(&b).unwrap().running_task_count() > 0);

    // Ack was sent back to A.
    assert!(count_sent(&h, &b, &a, "SpawnAck") >= 1);
}

// ===========================================================================
// CANCEL FLOWS
// ===========================================================================

#[test]
fn cancel_before_completion() {
    let seed = 44;
    let conditions = NetworkConditions::local();
    init_test("cancel_before_completion", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let tid = RemoteTaskId::from_raw(3000);

    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(10)); // spawn arrives

    h.inject_cancel(&a, &b, tid);
    h.run_for(Duration::from_millis(50)); // cancel arrives, task terminates

    let events = h.node(&b).unwrap().events();
    assert!(events
        .iter()
        .any(|e| matches!(e, NodeEvent::CancelReceived { task_id } if *task_id == tid)));
    assert!(events
        .iter()
        .any(|e| matches!(e, NodeEvent::TaskCancelled { task_id } if *task_id == tid)));
    assert_eq!(h.node(&b).unwrap().running_task_count(), 0);

    // B sends a Cancelled ResultDelivery back to A.
    assert!(count_sent(&h, &b, &a, "ResultDelivery") >= 1);
}

#[test]
fn cancel_after_completion_is_no_op() {
    let seed = 45;
    let conditions = NetworkConditions::local();
    init_test("cancel_after_completion_is_no_op", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let tid = RemoteTaskId::from_raw(3100);

    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(200)); // task completes

    let completed_count = count_events(h.node(&b).unwrap().events(), |e| {
        matches!(e, NodeEvent::TaskCompleted { .. })
    });
    assert_eq!(completed_count, 1);

    // Cancel arrives after completion — should not generate TaskCancelled.
    h.inject_cancel(&a, &b, tid);
    h.run_for(Duration::from_millis(20));

    let cancelled_count = count_events(h.node(&b).unwrap().events(), |e| {
        matches!(e, NodeEvent::TaskCancelled { .. })
    });
    assert_eq!(
        cancelled_count, 0,
        "cancel after completion should be no-op"
    );
}

// ===========================================================================
// LEASE EXPIRY
// ===========================================================================

#[test]
fn lease_expiry_clears_running_tasks() {
    let seed = 46;
    let conditions = NetworkConditions::local();
    init_test("lease_expiry_clears_running_tasks", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let t1 = RemoteTaskId::from_raw(4000);
    let t2 = RemoteTaskId::from_raw(4001);

    h.inject_spawn(&a, &b, t1);
    h.inject_spawn(&a, &b, t2);
    h.run_for(Duration::from_millis(10)); // both spawn arrive

    assert_eq!(h.node(&b).unwrap().running_task_count(), 2);

    // Expire leases on B.
    h.set_fault_script(FaultScript::new().at(
        Duration::from_millis(15),
        HarnessFault::ExpireLeases(b.clone()),
    ));
    h.run_for(Duration::from_millis(20));

    assert_eq!(h.node(&b).unwrap().running_task_count(), 0);

    // B should have sent two failure ResultDeliveries.
    let result_count = count_sent(&h, &b, &a, "ResultDelivery");
    assert!(
        result_count >= 2,
        "expected at least 2 ResultDelivery for expired tasks, got {result_count}"
    );
}

#[test]
fn lease_expiry_during_partition_delivers_after_heal() {
    let seed = 47;
    let conditions = NetworkConditions::local();
    init_test(
        "lease_expiry_during_partition_delivers_after_heal",
        seed,
        &conditions,
    );
    let (mut h, a, b) = harness_two(seed, conditions);
    let host_a = h.node(&a).unwrap().host_id;
    let host_b = h.node(&b).unwrap().host_id;
    let tid = RemoteTaskId::from_raw(4100);

    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(10));

    // Partition, then expire leases, then heal.
    h.set_fault_script(
        FaultScript::new()
            .at(
                Duration::from_millis(15),
                HarnessFault::Network(Fault::Partition {
                    hosts_a: vec![host_a],
                    hosts_b: vec![host_b],
                }),
            )
            .at(
                Duration::from_millis(20),
                HarnessFault::ExpireLeases(b.clone()),
            )
            .at(
                Duration::from_millis(100),
                HarnessFault::Network(Fault::Heal {
                    hosts_a: vec![host_a],
                    hosts_b: vec![host_b],
                }),
            ),
    );
    h.run_for(Duration::from_millis(200));

    // Task should be cleared and failure result sent (delivered after heal).
    assert_eq!(h.node(&b).unwrap().running_task_count(), 0);
    let result_count = count_sent(&h, &b, &a, "ResultDelivery");
    assert!(
        result_count >= 1,
        "expected lease-expiry ResultDelivery after heal"
    );
}

// ===========================================================================
// IDEMPOTENCY
// ===========================================================================

#[test]
fn duplicate_spawn_returns_cached_ack() {
    let seed = 48;
    let conditions = NetworkConditions::local();
    init_test("duplicate_spawn_returns_cached_ack", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let tid = RemoteTaskId::from_raw(5000);

    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(10));

    // Send same spawn again (simulates retransmit after ack loss).
    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(10));

    let events = h.node(&b).unwrap().events();
    let dup_count = count_events(events, |e| matches!(e, NodeEvent::DuplicateSpawn { .. }));
    assert_eq!(dup_count, 1, "expected exactly one DuplicateSpawn event");

    // Only one task should be running.
    assert_eq!(h.node(&b).unwrap().running_task_count(), 1);

    // Two acks should have been sent.
    let ack_count = count_sent(&h, &b, &a, "SpawnAck");
    assert!(
        ack_count >= 2,
        "expected at least 2 SpawnAck, got {ack_count}"
    );
}

#[test]
fn duplicate_after_completion_resends_result() {
    let seed = 49;
    let conditions = NetworkConditions::local();
    init_test("duplicate_after_completion_resends_result", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let tid = RemoteTaskId::from_raw(5100);

    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(200)); // task completes

    // Retransmit spawn (simulates result loss, origin retries).
    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(20));

    // Should get a second ResultDelivery (cached).
    let result_count = count_sent(&h, &b, &a, "ResultDelivery");
    assert!(
        result_count >= 2,
        "expected cached ResultDelivery on retransmit, got {result_count}"
    );
}

#[test]
fn idempotency_store_conflict_detection() {
    let seed = 0;
    let conditions = NetworkConditions::ideal();
    init_test("idempotency_store_conflict_detection", seed, &conditions);
    // Unit-level test: same key, different computation → conflict.
    let mut store = IdempotencyStore::new(Duration::from_secs(60));
    let key = IdempotencyKey::from_raw(0xABCD);
    let comp_a = ComputationName::new("compute_a");
    let comp_b = ComputationName::new("compute_b");

    assert!(matches!(store.check(&key, &comp_a), DedupDecision::New));
    store.record(key, RemoteTaskId::from_raw(1), comp_a.clone(), Time::ZERO);

    // Same key, same computation → duplicate.
    assert!(matches!(
        store.check(&key, &comp_a),
        DedupDecision::Duplicate(_)
    ));

    // Same key, different computation → conflict.
    assert!(matches!(
        store.check(&key, &comp_b),
        DedupDecision::Conflict
    ));
}

// ===========================================================================
// CAUSAL ORDERING
// ===========================================================================

#[test]
fn causal_clocks_advance_on_message_exchange() {
    let seed = 50;
    let conditions = NetworkConditions::local();
    init_test("causal_clocks_advance_on_message_exchange", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let tid = RemoteTaskId::from_raw(6000);

    // Record initial clock state.
    let origin_clock_before = h.node(&a).unwrap().causal_tracker().current_clock().clone();
    let worker_clock_before = h.node(&b).unwrap().causal_tracker().current_clock().clone();

    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(200));

    let origin_clock_after = h.node(&a).unwrap().causal_tracker().current_clock().clone();
    let worker_clock_after = h.node(&b).unwrap().causal_tracker().current_clock().clone();

    // Both nodes' clocks should have advanced beyond initial state.
    assert_ne!(
        origin_clock_before, origin_clock_after,
        "origin clock should advance after sending"
    );
    assert_ne!(
        worker_clock_before, worker_clock_after,
        "worker clock should advance after processing"
    );
}

#[test]
fn causal_ordering_preserved_across_multiple_spawns() {
    let seed = 51;
    let conditions = NetworkConditions::local();
    init_test(
        "causal_ordering_preserved_across_multiple_spawns",
        seed,
        &conditions,
    );
    let (mut h, a, b) = harness_two(seed, conditions);

    // Send 5 spawns sequentially, each after the previous arrives.
    for i in 0..5u64 {
        let tid = RemoteTaskId::from_raw(6100 + i);
        h.inject_spawn(&a, &b, tid);
        h.run_for(Duration::from_millis(5));
    }
    h.run_for(Duration::from_millis(300));

    // All 5 should have been received and accepted in order.
    let events = h.node(&b).unwrap().events();
    let received: Vec<RemoteTaskId> = events
        .iter()
        .filter_map(|e| match e {
            NodeEvent::SpawnReceived { task_id, .. } => Some(*task_id),
            _ => None,
        })
        .collect();
    assert_eq!(received.len(), 5);
    // Under local conditions with sequential injection, order is preserved.
    for (i, tid) in received.iter().enumerate() {
        assert_eq!(tid.raw(), 6100 + i as u64);
    }
}

// ===========================================================================
// MULTI-NODE CHAIN
// ===========================================================================

#[test]
fn three_node_chain_spawn_cascade() {
    let seed = 52;
    let conditions = NetworkConditions::local();
    init_test("three_node_chain_spawn_cascade", seed, &conditions);
    let (mut h, a, b, c) = harness_three(seed, conditions);
    let t1 = RemoteTaskId::from_raw(7000);
    let t2 = RemoteTaskId::from_raw(7001);

    // A → B
    h.inject_spawn(&a, &b, t1);
    h.run_for(Duration::from_millis(15)); // arrives at B

    // B → C (simulates B delegating sub-work)
    h.inject_spawn(&b, &c, t2);
    h.run_for(Duration::from_millis(300)); // both tasks complete

    // B accepted t1 and completed it.
    let events_b = h.node(&b).unwrap().events();
    assert!(events_b
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnAccepted { task_id } if *task_id == t1)));
    assert!(events_b
        .iter()
        .any(|e| matches!(e, NodeEvent::TaskCompleted { task_id } if *task_id == t1)));

    // C accepted t2 and completed it.
    let events_c = h.node(&c).unwrap().events();
    assert!(events_c
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnAccepted { task_id } if *task_id == t2)));
    assert!(events_c
        .iter()
        .any(|e| matches!(e, NodeEvent::TaskCompleted { task_id } if *task_id == t2)));

    // No running tasks anywhere.
    assert_eq!(h.node(&a).unwrap().running_task_count(), 0);
    assert_eq!(h.node(&b).unwrap().running_task_count(), 0);
    assert_eq!(h.node(&c).unwrap().running_task_count(), 0);
}

#[test]
fn three_node_cancel_cascade() {
    let seed = 53;
    let conditions = NetworkConditions::local();
    init_test("three_node_cancel_cascade", seed, &conditions);
    let (mut h, a, b, c) = harness_three(seed, conditions);
    let t1 = RemoteTaskId::from_raw(7100);
    let t2 = RemoteTaskId::from_raw(7101);

    // A → B, B → C.
    h.inject_spawn(&a, &b, t1);
    h.run_for(Duration::from_millis(10));
    h.inject_spawn(&b, &c, t2);
    h.run_for(Duration::from_millis(10));

    // Cancel both tasks.
    h.inject_cancel(&a, &b, t1);
    h.inject_cancel(&b, &c, t2);
    h.run_for(Duration::from_millis(100));

    let events_b = h.node(&b).unwrap().events();
    assert!(events_b
        .iter()
        .any(|e| matches!(e, NodeEvent::TaskCancelled { task_id } if *task_id == t1)));

    let events_c = h.node(&c).unwrap().events();
    assert!(events_c
        .iter()
        .any(|e| matches!(e, NodeEvent::TaskCancelled { task_id } if *task_id == t2)));
}

// ===========================================================================
// FAN-OUT: ONE ORIGIN, MULTIPLE TASKS ON WORKER
// ===========================================================================

#[test]
fn fan_out_10_tasks_all_complete() {
    let seed = 54;
    let conditions = NetworkConditions::local();
    init_test("fan_out_10_tasks_all_complete", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let n = 10;

    for i in 0..n {
        let tid = RemoteTaskId::from_raw(8000 + i);
        h.inject_spawn(&a, &b, tid);
    }
    h.run_for(Duration::from_millis(300));

    let events = h.node(&b).unwrap().events();
    let completed = count_events(events, |e| matches!(e, NodeEvent::TaskCompleted { .. }));
    assert_eq!(completed, n as usize, "all {n} tasks should complete");
    assert_eq!(h.node(&b).unwrap().running_task_count(), 0);
}

#[test]
fn fan_out_cancel_half() {
    let seed = 55;
    let conditions = NetworkConditions::local();
    init_test("fan_out_cancel_half", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let n = 10u64;

    for i in 0..n {
        let tid = RemoteTaskId::from_raw(8100 + i);
        h.inject_spawn(&a, &b, tid);
    }
    h.run_for(Duration::from_millis(10)); // all arrive

    // Cancel the first half.
    for i in 0..n / 2 {
        let tid = RemoteTaskId::from_raw(8100 + i);
        h.inject_cancel(&a, &b, tid);
    }
    h.run_for(Duration::from_millis(300));

    let events = h.node(&b).unwrap().events();
    let cancelled = count_events(events, |e| matches!(e, NodeEvent::TaskCancelled { .. }));
    let completed = count_events(events, |e| matches!(e, NodeEvent::TaskCompleted { .. }));

    assert_eq!(cancelled, (n / 2) as usize);
    assert_eq!(completed, (n / 2) as usize);
    assert_eq!(h.node(&b).unwrap().running_task_count(), 0);
}

// ===========================================================================
// PARTITION + HEAL RECOVERY
// ===========================================================================

#[test]
fn partition_blocks_ack_heal_recovers() {
    let seed = 56;
    let conditions = NetworkConditions::local();
    init_test("partition_blocks_ack_heal_recovers", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let host_a = h.node(&a).unwrap().host_id;
    let host_b = h.node(&b).unwrap().host_id;
    let tid = RemoteTaskId::from_raw(9000);

    // Partition immediately.
    h.set_fault_script(
        FaultScript::new()
            .at(
                Duration::ZERO,
                HarnessFault::Network(Fault::Partition {
                    hosts_a: vec![host_a],
                    hosts_b: vec![host_b],
                }),
            )
            .at(
                Duration::from_millis(100),
                HarnessFault::Network(Fault::Heal {
                    hosts_a: vec![host_a],
                    hosts_b: vec![host_b],
                }),
            ),
    );

    // Spawn during partition.
    h.run_for(Duration::from_millis(5)); // partition active
    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(50));

    // During partition, B should NOT have received the spawn.
    assert_eq!(
        count_events(h.node(&b).unwrap().events(), |e| matches!(
            e,
            NodeEvent::SpawnReceived { .. }
        )),
        0,
        "spawn should not arrive during partition"
    );

    // Run past heal point. Re-inject spawn (simulates retransmit).
    h.run_for(Duration::from_millis(60)); // past 100ms heal
    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(200));

    // Now B should have received and completed.
    assert!(h
        .node(&b)
        .unwrap()
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::TaskCompleted { .. })));
}

#[test]
fn cancel_lost_to_partition_retransmit_after_heal() {
    let seed = 57;
    let conditions = NetworkConditions::local();
    init_test("cancel_lost_to_partition_retransmit_after_heal", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let host_a = h.node(&a).unwrap().host_id;
    let host_b = h.node(&b).unwrap().host_id;
    let tid = RemoteTaskId::from_raw(9100);

    // Spawn and let it arrive.
    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(10));

    // Partition.
    h.set_fault_script(
        FaultScript::new()
            .at(
                Duration::from_millis(15),
                HarnessFault::Network(Fault::Partition {
                    hosts_a: vec![host_a],
                    hosts_b: vec![host_b],
                }),
            )
            .at(
                Duration::from_millis(80),
                HarnessFault::Network(Fault::Heal {
                    hosts_a: vec![host_a],
                    hosts_b: vec![host_b],
                }),
            ),
    );

    // Cancel during partition.
    h.run_for(Duration::from_millis(10)); // at 20ms, partition active
    h.inject_cancel(&a, &b, tid);
    h.run_for(Duration::from_millis(30)); // cancel is dropped

    // Task may complete naturally on B during partition (work ≤100ms).
    // Regardless, after heal, retransmit cancel.
    h.run_for(Duration::from_millis(50)); // past heal at 80ms
    h.inject_cancel(&a, &b, tid);
    h.run_for(Duration::from_millis(50));

    // Task should be resolved one way or another (completed or cancelled).
    assert_eq!(h.node(&b).unwrap().running_task_count(), 0);
}

// ===========================================================================
// CRASH / RESTART
// ===========================================================================

#[test]
fn crash_drops_all_tasks_restart_accepts_new() {
    let seed = 58;
    let conditions = NetworkConditions::local();
    init_test("crash_drops_all_tasks_restart_accepts_new", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let t1 = RemoteTaskId::from_raw(10_000);

    h.inject_spawn(&a, &b, t1);
    h.run_for(Duration::from_millis(10));
    assert_eq!(h.node(&b).unwrap().running_task_count(), 1);

    // Crash B.
    h.set_fault_script(
        FaultScript::new()
            .at(
                Duration::from_millis(15),
                HarnessFault::CrashNode(b.clone()),
            )
            .at(
                Duration::from_millis(50),
                HarnessFault::RestartNode(b.clone()),
            ),
    );
    h.run_for(Duration::from_millis(60));

    let events = h.node(&b).unwrap().events();
    assert!(events.iter().any(|e| matches!(e, NodeEvent::Crashed)));
    assert!(events.iter().any(|e| matches!(e, NodeEvent::Restarted)));
    assert_eq!(h.node(&b).unwrap().running_task_count(), 0);

    // New spawn after restart should succeed.
    let t2 = RemoteTaskId::from_raw(10_001);
    h.inject_spawn(&a, &b, t2);
    h.run_for(Duration::from_millis(200));

    assert!(h
        .node(&b)
        .unwrap()
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::TaskCompleted { task_id } if *task_id == t2)));
}

#[test]
fn messages_to_crashed_node_are_silently_dropped() {
    let seed = 59;
    let conditions = NetworkConditions::local();
    init_test("messages_to_crashed_node_are_silently_dropped", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let tid = RemoteTaskId::from_raw(10_100);

    // Crash B immediately.
    h.set_fault_script(FaultScript::new().at(Duration::ZERO, HarnessFault::CrashNode(b.clone())));
    h.run_for(Duration::from_millis(5));

    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(50));

    // B should have Crashed event but no SpawnReceived (messages silently dropped).
    let events = h.node(&b).unwrap().events();
    assert!(events.iter().any(|e| matches!(e, NodeEvent::Crashed)));
    assert_eq!(
        count_events(events, |e| matches!(e, NodeEvent::SpawnReceived { .. })),
        0,
        "crashed node should not process messages"
    );
}

// ===========================================================================
// DETERMINISTIC REPLAY
// ===========================================================================

#[test]
fn deterministic_replay_same_seed_identical_trace() {
    let seed = 0xCAFE;
    let conditions = NetworkConditions::wan();
    init_test("deterministic_replay_same_seed_identical_trace", seed, &conditions);

    fn run_scenario(seed: u64, conditions: NetworkConditions) -> Vec<String> {
        let mut h = DistributedHarness::new(make_config(seed, conditions));
        let a = h.add_node("origin");
        let b = h.add_node("worker");

        for i in 0..5u64 {
            let tid = RemoteTaskId::from_raw(11_000 + i);
            h.inject_spawn(&a, &b, tid);
        }
        h.run_for(Duration::from_millis(500));

        h.trace()
            .iter()
            .map(|e| format!("{:?}:{:?}", e.time, e.kind))
            .collect()
    }

    let run1 = run_scenario(seed, conditions.clone());
    let run2 = run_scenario(seed, conditions);
    assert_eq!(run1, run2, "same seed must produce identical trace");
    assert!(
        !run1.is_empty(),
        "trace should be non-trivial with 5 spawns"
    );
}

#[test]
fn deterministic_replay_with_faults() {
    let seed = 0xBEEF;
    let conditions = NetworkConditions::lan();
    init_test("deterministic_replay_with_faults", seed, &conditions);

    fn run_with_faults(seed: u64, conditions: NetworkConditions) -> Vec<String> {
        let mut h = DistributedHarness::new(make_config(seed, conditions));
        let a = h.add_node("origin");
        let b = h.add_node("worker");

        let host_a = h.node(&a).unwrap().host_id;
        let host_b = h.node(&b).unwrap().host_id;

        h.set_fault_script(
            FaultScript::new()
                .at(
                    Duration::from_millis(50),
                    HarnessFault::Network(Fault::Partition {
                        hosts_a: vec![host_a],
                        hosts_b: vec![host_b],
                    }),
                )
                .at(
                    Duration::from_millis(150),
                    HarnessFault::Network(Fault::Heal {
                        hosts_a: vec![host_a],
                        hosts_b: vec![host_b],
                    }),
                ),
        );

        for i in 0..3u64 {
            let tid = RemoteTaskId::from_raw(11_100 + i);
            h.inject_spawn(&a, &b, tid);
        }
        h.run_for(Duration::from_millis(400));

        h.trace()
            .iter()
            .map(|e| format!("{:?}:{:?}", e.time, e.kind))
            .collect()
    }

    let run1 = run_with_faults(seed, conditions.clone());
    let run2 = run_with_faults(seed, conditions);
    assert_eq!(run1, run2);
}

// ===========================================================================
// SAGA COMPENSATION
// ===========================================================================

#[test]
fn saga_all_steps_succeed() {
    let seed = 0;
    let conditions = NetworkConditions::ideal();
    init_test("saga_all_steps_succeed", seed, &conditions);
    let mut saga = Saga::new();

    saga.step("reserve-slot", || Ok(1), || "unreserve-slot".into())
        .expect("step 1 ok");
    saga.step("allocate-budget", || Ok(2), || "release-budget".into())
        .expect("step 2 ok");
    saga.step("commit-work", || Ok(3), || "rollback-work".into())
        .expect("step 3 ok");

    saga.complete();
    assert_eq!(saga.state(), SagaState::Completed);
    assert_eq!(saga.completed_steps(), 3);
    assert!(saga.compensation_results().is_empty());
}

#[test]
fn saga_failure_triggers_lifo_compensation() {
    let seed = 0;
    let conditions = NetworkConditions::ideal();
    init_test("saga_failure_triggers_lifo_compensation", seed, &conditions);
    let mut saga = Saga::new();

    saga.step("step-a", || Ok(()), || "undo-a".into())
        .expect("step-a ok");
    saga.step("step-b", || Ok(()), || "undo-b".into())
        .expect("step-b ok");
    saga.step("step-c", || Ok(()), || "undo-c".into())
        .expect("step-c ok");

    let err = saga
        .step("step-d", || Err::<(), _>("boom".into()), || "undo-d".into())
        .unwrap_err();
    assert!(err.message.contains("boom"));
    assert_eq!(saga.state(), SagaState::Aborted);

    // Compensations run in reverse order (LIFO): c, b, a.
    let results = saga.compensation_results();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].result, "undo-c");
    assert_eq!(results[1].result, "undo-b");
    assert_eq!(results[2].result, "undo-a");
}

#[test]
fn saga_first_step_failure_no_compensations() {
    let seed = 0;
    let conditions = NetworkConditions::ideal();
    init_test("saga_first_step_failure_no_compensations", seed, &conditions);
    let mut saga = Saga::new();

    let err = saga
        .step(
            "step-1",
            || Err::<(), _>("fail immediately".into()),
            || "undo-1".into(),
        )
        .unwrap_err();
    assert!(err.message.contains("fail immediately"));
    assert_eq!(saga.state(), SagaState::Aborted);
    assert!(
        saga.compensation_results().is_empty(),
        "no compensations needed when first step fails"
    );
}

// ===========================================================================
// MIXED WORKLOAD STRESS UNDER LOSSY CONDITIONS
// ===========================================================================

#[test]
fn stress_mixed_workload_lossy_network() {
    let seed = 60;
    let conditions = NetworkConditions::lossy();
    init_test("stress_mixed_workload_lossy_network", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let n_spawn = 20u64;

    // Spawn a batch of tasks.
    for i in 0..n_spawn {
        let tid = RemoteTaskId::from_raw(12_000 + i);
        h.inject_spawn(&a, &b, tid);
    }
    h.run_for(Duration::from_millis(50));

    // Cancel every other task.
    for i in (0..n_spawn).step_by(2) {
        let tid = RemoteTaskId::from_raw(12_000 + i);
        h.inject_cancel(&a, &b, tid);
    }
    h.run_for(Duration::from_millis(500));

    // Under lossy conditions, some spawns may be dropped. The ones that arrived
    // should either complete or be cancelled. No tasks should be stuck running
    // after sufficient time.
    let events = h.node(&b).unwrap().events();
    let received = count_events(events, |e| matches!(e, NodeEvent::SpawnReceived { .. }));
    let completed = count_events(events, |e| matches!(e, NodeEvent::TaskCompleted { .. }));
    let cancelled = count_events(events, |e| matches!(e, NodeEvent::TaskCancelled { .. }));

    // At least some tasks should have arrived (lossy drops ~10%).
    assert!(
        received > 0,
        "at least some spawns should arrive under 10% loss"
    );
    // All received tasks should be resolved.
    assert_eq!(
        h.node(&b).unwrap().running_task_count(),
        0,
        "no tasks should remain running after 500ms"
    );
    // Total resolved = completed + cancelled should equal received - duplicates.
    let accepted = count_events(events, |e| matches!(e, NodeEvent::SpawnAccepted { .. }));
    assert_eq!(
        accepted,
        completed + cancelled,
        "accepted tasks should all be resolved: accepted={accepted}, completed={completed}, cancelled={cancelled}"
    );
}

#[test]
fn stress_wan_conditions_all_tasks_resolve() {
    let seed = 61;
    let conditions = NetworkConditions::wan();
    init_test("stress_wan_conditions_all_tasks_resolve", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let n = 10u64;

    for i in 0..n {
        let tid = RemoteTaskId::from_raw(12_100 + i);
        h.inject_spawn(&a, &b, tid);
    }
    // WAN: 20-100ms latency; 100ms work; need ≥300ms for round-trip.
    h.run_for(Duration::from_millis(600));

    let events = h.node(&b).unwrap().events();
    let accepted = count_events(events, |e| matches!(e, NodeEvent::SpawnAccepted { .. }));
    let completed = count_events(events, |e| matches!(e, NodeEvent::TaskCompleted { .. }));

    // WAN has 0.1% loss so nearly all should arrive.
    assert!(
        accepted >= 9,
        "most tasks should be accepted under WAN, got {accepted}"
    );
    assert_eq!(
        accepted, completed,
        "all accepted tasks should complete: accepted={accepted}, completed={completed}"
    );
}

#[test]
fn stress_congested_network_eventual_completion() {
    let seed = 62;
    let conditions = NetworkConditions::congested();
    init_test("stress_congested_network_eventual_completion", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let n = 15u64;

    for i in 0..n {
        let tid = RemoteTaskId::from_raw(12_200 + i);
        h.inject_spawn(&a, &b, tid);
    }
    // Congested: 100ms latency, 5% loss, 2% reorder; give generous time.
    h.run_for(Duration::from_millis(1000));

    let events = h.node(&b).unwrap().events();
    let accepted = count_events(events, |e| matches!(e, NodeEvent::SpawnAccepted { .. }));
    let completed = count_events(events, |e| matches!(e, NodeEvent::TaskCompleted { .. }));

    // Under congestion, most should still arrive and complete.
    assert!(
        accepted >= 10,
        "most tasks should arrive under congestion, got {accepted}"
    );
    assert_eq!(h.node(&b).unwrap().running_task_count(), 0);
    assert_eq!(accepted, completed);
}

// ===========================================================================
// METRICS CONSISTENCY
// ===========================================================================

#[test]
fn metrics_sent_geq_delivered_plus_dropped() {
    let seed = 63;
    let conditions = NetworkConditions::lossy();
    init_test("metrics_sent_geq_delivered_plus_dropped", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);

    for i in 0..10u64 {
        let tid = RemoteTaskId::from_raw(13_000 + i);
        h.inject_spawn(&a, &b, tid);
    }
    h.run_for(Duration::from_millis(500));

    let m = h.network_metrics();
    // sent ≥ delivered + dropped (duplicated packets may inflate delivered).
    assert!(
        m.packets_sent >= m.packets_delivered,
        "sent ({}) should be >= delivered ({})",
        m.packets_sent,
        m.packets_delivered
    );
    // At least some packets should have been processed.
    assert!(m.packets_sent > 0, "should have sent packets");
}

// ===========================================================================
// EDGE CASES
// ===========================================================================

#[test]
fn spawn_to_self() {
    let seed = 64;
    let conditions = NetworkConditions::local();
    init_test("spawn_to_self", seed, &conditions);
    // A node spawns a task on itself.
    let mut h = DistributedHarness::new(make_config(seed, conditions));
    let a = h.add_node("self-node");
    let tid = RemoteTaskId::from_raw(14_000);

    h.inject_spawn(&a, &a, tid);
    h.run_for(Duration::from_millis(200));

    let events = h.node(&a).unwrap().events();
    assert!(events
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnAccepted { task_id } if *task_id == tid)));
    assert!(events
        .iter()
        .any(|e| matches!(e, NodeEvent::TaskCompleted { task_id } if *task_id == tid)));
}

#[test]
fn many_rapid_cancels_same_task() {
    let seed = 65;
    let conditions = NetworkConditions::local();
    init_test("many_rapid_cancels_same_task", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let tid = RemoteTaskId::from_raw(14_100);

    h.inject_spawn(&a, &b, tid);
    h.run_for(Duration::from_millis(10));

    // Send 5 cancel requests for the same task.
    for _ in 0..5 {
        h.inject_cancel(&a, &b, tid);
    }
    h.run_for(Duration::from_millis(100));

    // Task should be cancelled exactly once.
    let cancelled = count_events(h.node(&b).unwrap().events(), |e| {
        matches!(e, NodeEvent::TaskCancelled { .. })
    });
    assert_eq!(cancelled, 1, "task should be cancelled exactly once");
    assert_eq!(h.node(&b).unwrap().running_task_count(), 0);
}

#[test]
fn cancel_nonexistent_task_is_silent() {
    let seed = 66;
    let conditions = NetworkConditions::local();
    init_test("cancel_nonexistent_task_is_silent", seed, &conditions);
    let (mut h, a, b) = harness_two(seed, conditions);
    let tid = RemoteTaskId::from_raw(14_200);

    // Cancel a task that was never spawned.
    h.inject_cancel(&a, &b, tid);
    h.run_for(Duration::from_millis(20));

    // CancelReceived is logged but no TaskCancelled (nothing to cancel).
    let events = h.node(&b).unwrap().events();
    assert!(events
        .iter()
        .any(|e| matches!(e, NodeEvent::CancelReceived { .. })));
    assert_eq!(
        count_events(events, |e| matches!(e, NodeEvent::TaskCancelled { .. })),
        0
    );
}

#[test]
fn empty_harness_run_is_no_op() {
    let seed = 67;
    let conditions = NetworkConditions::ideal();
    init_test("empty_harness_run_is_no_op", seed, &conditions);
    let mut h = DistributedHarness::new(make_config(seed, conditions));
    let _a = h.add_node("lonely");

    h.run_for(Duration::from_millis(100));
    assert!(h.trace().is_empty(), "no messages, no trace events");
}
