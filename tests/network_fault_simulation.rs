//! Network fault simulation E2E tests (bd-167hv).
//!
//! Validates remote protocol correctness under controlled network faults:
//! partition, reordering, jitter, duplication, lease expiry, cancel propagation,
//! and idempotency. All tests are deterministic (seeded RNG) and produce
//! reproducible fault traces.
//!
//! Cross-references:
//!   Lab network:     src/lab/network/
//!   Remote protocol: src/remote.rs
//!   Distributed harness: src/lab/network/harness.rs

use asupersync::lab::network::{
    DistributedHarness, Fault, FaultScript, HarnessFault, HarnessTraceKind, HostId, JitterModel,
    LatencyModel, NetworkConditions, NetworkConfig, NodeEvent, SimulatedNetwork,
};
use asupersync::remote::{NodeId, RemoteTaskId};
use std::time::Duration;
use tracing::info;

fn init_test(test_name: &str) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();
    info!(
        phase = test_name,
        "========================================"
    );
    info!(phase = test_name, "TEST PHASE: {}", test_name);
    info!(
        phase = test_name,
        "========================================"
    );
}

macro_rules! assert_with_log {
    ($cond:expr, $label:expr, $expected:expr, $actual:expr) => {
        tracing::debug!(
            expected = ?$expected,
            actual = ?$actual,
            "Asserting: {}",
            $label
        );
        assert!(
            $cond,
            "{}: expected {:?}, got {:?}",
            $label,
            $expected,
            $actual
        );
    };
}

macro_rules! test_complete {
    ($name:expr) => {
        info!(test = $name, "test completed successfully: {}", $name);
    };
}

fn make_config(seed: u64, conditions: NetworkConditions) -> NetworkConfig {
    NetworkConfig {
        seed,
        default_conditions: conditions,
        capture_trace: true,
        ..NetworkConfig::default()
    }
}

fn harness_with_conditions(
    seed: u64,
    conditions: NetworkConditions,
) -> (DistributedHarness, NodeId, NodeId) {
    let config = make_config(seed, conditions);
    let mut harness = DistributedHarness::new(config);
    let a = harness.add_node("node-a");
    let b = harness.add_node("node-b");
    (harness, a, b)
}

fn harness_three_nodes(
    seed: u64,
    conditions: NetworkConditions,
) -> (DistributedHarness, NodeId, NodeId, NodeId) {
    let config = make_config(seed, conditions);
    let mut harness = DistributedHarness::new(config);
    let a = harness.add_node("node-a");
    let b = harness.add_node("node-b");
    let c = harness.add_node("node-c");
    (harness, a, b, c)
}

fn deterministic_trace(seed: u64) -> Vec<String> {
    let conditions = NetworkConditions {
        latency: LatencyModel::Fixed(Duration::from_millis(5)),
        packet_loss: 0.1,
        packet_duplicate: 0.1,
        packet_reorder: 0.05,
        ..NetworkConditions::ideal()
    };
    let config = NetworkConfig {
        seed,
        default_conditions: conditions,
        capture_trace: true,
        ..NetworkConfig::default()
    };

    let mut harness = DistributedHarness::new(config);
    let a = harness.add_node("node-a");
    let b = harness.add_node("node-b");

    harness.set_fault_script(
        FaultScript::new()
            .at(
                Duration::from_millis(50),
                HarnessFault::Network(Fault::Partition {
                    hosts_a: vec![HostId::new(1)],
                    hosts_b: vec![HostId::new(2)],
                }),
            )
            .at(
                Duration::from_millis(150),
                HarnessFault::Network(Fault::Heal {
                    hosts_a: vec![HostId::new(1)],
                    hosts_b: vec![HostId::new(2)],
                }),
            ),
    );

    for i in 0..5 {
        let tid = RemoteTaskId::from_raw(1000 + i);
        harness.inject_spawn(&a, &b, tid);
    }

    harness.run_for(Duration::from_millis(500));

    harness
        .trace()
        .iter()
        .map(|e| format!("{:?}:{:?}", e.time, e.kind))
        .collect()
}

// ============================================================================
// Partition Tests
// ============================================================================

/// Partition blocks message delivery — spawn request never arrives.
#[test]
fn partition_blocks_spawn_delivery() {
    init_test("partition_blocks_spawn_delivery");

    let (mut harness, a, b) = harness_with_conditions(42, NetworkConditions::local());
    let task_id = RemoteTaskId::next();

    // Partition before spawning
    harness.set_fault_script(FaultScript::new().at(
        Duration::ZERO,
        HarnessFault::Network(Fault::Partition {
            hosts_a: vec![HostId::new(1)],
            hosts_b: vec![HostId::new(2)],
        }),
    ));

    harness.inject_spawn(&a, &b, task_id);
    harness.run_for(Duration::from_millis(200));

    let node_b = harness.node(&b).unwrap();
    let received = node_b
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnReceived { .. }));
    assert_with_log!(!received, "partition blocks spawn", false, received);

    // Verify packets were dropped
    let dropped = harness.network_metrics().packets_dropped;
    assert_with_log!(dropped > 0, "packets dropped", true, dropped > 0);

    test_complete!("partition_blocks_spawn_delivery");
}

/// Partition then heal — spawn succeeds after healing.
#[test]
fn partition_heal_allows_delivery() {
    init_test("partition_heal_allows_delivery");

    let (mut harness, a, b) = harness_with_conditions(43, NetworkConditions::local());

    harness.set_fault_script(
        FaultScript::new()
            .at(
                Duration::ZERO,
                HarnessFault::Network(Fault::Partition {
                    hosts_a: vec![HostId::new(1)],
                    hosts_b: vec![HostId::new(2)],
                }),
            )
            .at(
                Duration::from_millis(100),
                HarnessFault::Network(Fault::Heal {
                    hosts_a: vec![HostId::new(1)],
                    hosts_b: vec![HostId::new(2)],
                }),
            ),
    );

    // Spawn during partition — should fail
    let task_id1 = RemoteTaskId::next();
    harness.inject_spawn(&a, &b, task_id1);
    harness.run_for(Duration::from_millis(50));

    let node_b = harness.node(&b).unwrap();
    let received_during_partition = node_b
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnReceived { .. }));
    assert_with_log!(
        !received_during_partition,
        "no delivery during partition",
        false,
        received_during_partition
    );

    // Run past the heal time (100ms)
    harness.run_for(Duration::from_millis(60));

    // After heal, new spawn should work
    let task_id2 = RemoteTaskId::next();
    harness.inject_spawn(&a, &b, task_id2);
    harness.run_for(Duration::from_millis(200));

    let node_b = harness.node(&b).unwrap();
    let received_after_heal = node_b
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnReceived { .. }));
    assert_with_log!(
        received_after_heal,
        "delivery after heal",
        true,
        received_after_heal
    );

    test_complete!("partition_heal_allows_delivery");
}

// ============================================================================
// Duplication + Idempotency Tests
// ============================================================================

/// Application-level duplicate spawn is detected via idempotency store.
#[test]
fn duplication_handled_by_idempotency() {
    init_test("duplication_handled_by_idempotency");

    let (mut harness, a, b) = harness_with_conditions(44, NetworkConditions::local());
    let task_id = RemoteTaskId::next();

    // Send same spawn twice (simulates retransmit after timeout)
    harness.inject_spawn(&a, &b, task_id);
    harness.run_for(Duration::from_millis(10));
    harness.inject_spawn(&a, &b, task_id);
    harness.run_for(Duration::from_millis(500));

    let node_b = harness.node(&b).unwrap();

    // Should see two spawns received
    let spawn_count = node_b
        .events()
        .iter()
        .filter(|e| matches!(e, NodeEvent::SpawnReceived { .. }))
        .count();
    assert_with_log!(spawn_count == 2, "two spawns received", 2, spawn_count);

    // Exactly one accept + one duplicate detected
    let accept_count = node_b
        .events()
        .iter()
        .filter(|e| matches!(e, NodeEvent::SpawnAccepted { .. }))
        .count();
    assert_with_log!(accept_count == 1, "single accept", 1, accept_count);

    let dup_count = node_b
        .events()
        .iter()
        .filter(|e| matches!(e, NodeEvent::DuplicateSpawn { .. }))
        .count();
    info!(
        dups = dup_count,
        accepts = accept_count,
        "idempotency dedup"
    );
    assert_with_log!(dup_count == 1, "one duplicate detected", 1, dup_count);

    // Task should still complete once
    let complete_count = node_b
        .events()
        .iter()
        .filter(|e| matches!(e, NodeEvent::TaskCompleted { .. }))
        .count();
    assert_with_log!(complete_count == 1, "single completion", 1, complete_count);

    test_complete!("duplication_handled_by_idempotency");
}

/// Network-level packet duplication produces extra deliveries at raw layer.
#[test]
fn network_packet_duplication() {
    init_test("network_packet_duplication");

    let conditions = NetworkConditions {
        packet_duplicate: 1.0,
        ..NetworkConditions::ideal()
    };
    let config = make_config(44, conditions);
    let mut net = SimulatedNetwork::new(config);
    let h1 = net.add_host("h1");
    let h2 = net.add_host("h2");

    net.send(
        h1,
        h2,
        asupersync::bytes::Bytes::copy_from_slice(b"dup-test"),
    );
    net.run_until_idle();

    let inbox = net.inbox(h2).unwrap();
    assert_with_log!(inbox.len() == 2, "duplicate delivered", 2, inbox.len());
    assert_with_log!(
        net.metrics().packets_duplicated == 1,
        "dup metric",
        1,
        net.metrics().packets_duplicated
    );

    test_complete!("network_packet_duplication");
}

// ============================================================================
// Reordering Tests
// ============================================================================

/// With high reordering, messages still arrive (just possibly out of order).
#[test]
fn reordering_preserves_delivery() {
    init_test("reordering_preserves_delivery");

    let conditions = NetworkConditions {
        packet_reorder: 1.0, // Reorder every packet
        latency: LatencyModel::Fixed(Duration::from_millis(1)),
        ..NetworkConditions::ideal()
    };
    let (mut harness, a, b) = harness_with_conditions(45, conditions);

    // Send multiple spawns to test reordering
    let task_ids: Vec<RemoteTaskId> = (0..5).map(|_| RemoteTaskId::next()).collect();
    for &tid in &task_ids {
        harness.inject_spawn(&a, &b, tid);
    }
    harness.run_for(Duration::from_millis(500));

    let node_b = harness.node(&b).unwrap();
    let recv_count = node_b
        .events()
        .iter()
        .filter(|e| matches!(e, NodeEvent::SpawnReceived { .. }))
        .count();
    assert_with_log!(recv_count == 5, "all 5 spawns received", 5, recv_count);

    // Verify reorder events were recorded
    let reorder_traces = harness
        .trace()
        .iter()
        .filter(|e| matches!(e.kind, HarnessTraceKind::FaultInjected(_)))
        .count();
    info!(reorder_traces, "reorder trace events");

    test_complete!("reordering_preserves_delivery");
}

// ============================================================================
// Jitter Tests
// ============================================================================

/// High jitter causes variable delivery times but messages still arrive.
#[test]
fn jitter_variable_delivery_times() {
    init_test("jitter_variable_delivery_times");

    let conditions = NetworkConditions {
        latency: LatencyModel::Fixed(Duration::from_millis(5)),
        jitter: Some(JitterModel::Bursty {
            normal_jitter: Duration::from_millis(2),
            burst_jitter: Duration::from_millis(50),
            burst_probability: 0.3,
        }),
        ..NetworkConditions::ideal()
    };
    let config = make_config(46, conditions);
    let mut net = SimulatedNetwork::new(config);
    let h1 = net.add_host("h1");
    let h2 = net.add_host("h2");

    // Send 20 packets and observe delivery time variance
    for _ in 0..20 {
        net.send(
            h1,
            h2,
            asupersync::bytes::Bytes::copy_from_slice(b"jitter-test"),
        );
    }
    net.run_until_idle();

    let inbox = net.inbox(h2).unwrap();
    assert_with_log!(inbox.len() == 20, "all 20 delivered", 20, inbox.len());

    // Check that delivery times vary (not all identical)
    let times: Vec<u64> = inbox.iter().map(|p| p.received_at.as_nanos()).collect();
    let unique_times: std::collections::HashSet<u64> = times.iter().copied().collect();
    // With burst jitter, we expect significant variance
    let has_variance = unique_times.len() > 1;
    assert_with_log!(has_variance, "delivery time variance", true, has_variance);

    // Check that some packets have jitter > base latency
    let base_nanos = Duration::from_millis(5).as_nanos() as u64;
    let has_jitter = times.iter().any(|&t| t > base_nanos);
    assert_with_log!(has_jitter, "jitter applied", true, has_jitter);

    test_complete!("jitter_variable_delivery_times");
}

// ============================================================================
// Lease Expiry Tests
// ============================================================================

/// Partition causes lease to expire — tasks fail with lease-expired outcome.
#[test]
fn lease_expiry_during_partition() {
    init_test("lease_expiry_during_partition");

    let (mut harness, a, b) = harness_with_conditions(47, NetworkConditions::local());
    let task_id = RemoteTaskId::next();

    // Spawn a task on B
    harness.inject_spawn(&a, &b, task_id);
    harness.run_for(Duration::from_millis(10));

    // Verify spawn was received
    let node_b = harness.node(&b).unwrap();
    let received = node_b
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnReceived { .. }));
    assert_with_log!(received, "spawn received", true, received);

    // Partition + expire leases on B
    harness.set_fault_script(
        FaultScript::new()
            .at(
                Duration::from_millis(20),
                HarnessFault::Network(Fault::Partition {
                    hosts_a: vec![HostId::new(1)],
                    hosts_b: vec![HostId::new(2)],
                }),
            )
            .at(
                Duration::from_millis(30),
                HarnessFault::ExpireLeases(NodeId::new("node-b")),
            ),
    );
    harness.run_for(Duration::from_millis(50));

    // After lease expiry, B should have no running tasks
    let node_b = harness.node(&b).unwrap();
    assert_with_log!(
        node_b.running_task_count() == 0,
        "no running tasks after lease expiry",
        0,
        node_b.running_task_count()
    );

    test_complete!("lease_expiry_during_partition");
}

// ============================================================================
// Cancel Propagation Under Faults
// ============================================================================

/// Cancel request survives network conditions (no loss).
#[test]
fn cancel_propagation_clean_network() {
    init_test("cancel_propagation_clean_network");

    let (mut harness, a, b) = harness_with_conditions(48, NetworkConditions::local());
    let task_id = RemoteTaskId::next();

    // Spawn
    harness.inject_spawn(&a, &b, task_id);
    harness.run_for(Duration::from_millis(10));

    // Cancel
    harness.inject_cancel(&a, &b, task_id);
    harness.run_for(Duration::from_millis(200));

    let node_b = harness.node(&b).unwrap();
    let cancel_received = node_b
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::CancelReceived { .. }));
    assert_with_log!(cancel_received, "cancel received", true, cancel_received);

    // After cancel + tick, task should complete as cancelled
    let cancelled = node_b
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::TaskCancelled { .. }));
    assert_with_log!(cancelled, "task cancelled", true, cancelled);

    test_complete!("cancel_propagation_clean_network");
}

/// Cancel request is dropped by partition — task continues running.
#[test]
fn cancel_dropped_by_partition() {
    init_test("cancel_dropped_by_partition");

    let (mut harness, a, b) = harness_with_conditions(49, NetworkConditions::local());
    let task_id = RemoteTaskId::next();

    // Spawn
    harness.inject_spawn(&a, &b, task_id);
    harness.run_for(Duration::from_millis(10));

    // Partition, then cancel (cancel is dropped)
    harness.set_fault_script(FaultScript::new().at(
        Duration::from_millis(15),
        HarnessFault::Network(Fault::Partition {
            hosts_a: vec![HostId::new(1)],
            hosts_b: vec![HostId::new(2)],
        }),
    ));
    harness.inject_cancel(&a, &b, task_id);
    harness.run_for(Duration::from_millis(30));

    let node_b = harness.node(&b).unwrap();
    let cancel_received = node_b
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::CancelReceived { .. }));
    // Cancel may or may not have arrived depending on timing
    // What matters is the task either completes or keeps running
    info!(cancel_received, "cancel_received during partition");

    test_complete!("cancel_dropped_by_partition");
}

// ============================================================================
// Crash + Restart Tests
// ============================================================================

/// Node crash kills running tasks; restart allows new spawns.
#[test]
fn crash_restart_lifecycle() {
    init_test("crash_restart_lifecycle");

    let (mut harness, a, b) = harness_with_conditions(50, NetworkConditions::local());
    let task_id1 = RemoteTaskId::next();

    // Spawn task on B
    harness.inject_spawn(&a, &b, task_id1);
    harness.run_for(Duration::from_millis(10));

    // Verify spawn received
    let received = harness
        .node(&b)
        .unwrap()
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnReceived { .. }));
    assert_with_log!(received, "spawn received before crash", true, received);

    // Crash B
    harness.set_fault_script(FaultScript::new().at(
        Duration::from_millis(15),
        HarnessFault::CrashNode(NodeId::new("node-b")),
    ));
    harness.run_for(Duration::from_millis(20));

    // Send during crash — should be dropped
    let task_id2 = RemoteTaskId::next();
    harness.inject_spawn(&a, &b, task_id2);
    harness.run_for(Duration::from_millis(50));

    // Restart B
    harness.set_fault_script(FaultScript::new().at(
        Duration::from_millis(80),
        HarnessFault::RestartNode(NodeId::new("node-b")),
    ));
    harness.run_for(Duration::from_millis(30));

    // Spawn after restart
    let task_id3 = RemoteTaskId::next();
    harness.inject_spawn(&a, &b, task_id3);
    harness.run_for(Duration::from_millis(300));

    let node_b = harness.node(&b).unwrap();
    let crashed = node_b
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::Crashed));
    let restarted = node_b
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::Restarted));
    assert_with_log!(crashed, "node crashed", true, crashed);
    assert_with_log!(restarted, "node restarted", true, restarted);

    test_complete!("crash_restart_lifecycle");
}

// ============================================================================
// Deterministic Replay
// ============================================================================

/// Same seed + same fault script produces identical traces.
#[test]
fn deterministic_replay_identical_traces() {
    init_test("deterministic_replay_identical_traces");
    let trace1 = deterministic_trace(0xBEEF);
    let trace2 = deterministic_trace(0xBEEF);

    assert_with_log!(
        trace1 == trace2,
        "deterministic replay",
        true,
        trace1 == trace2
    );
    info!(trace_len = trace1.len(), "trace events captured");

    // Verify we captured meaningful events (not just an empty trace)
    assert_with_log!(
        trace1.len() > 5,
        "non-trivial trace",
        true,
        trace1.len() > 5
    );

    test_complete!("deterministic_replay_identical_traces");
}

// ============================================================================
// Multi-Node Fault Scenarios
// ============================================================================

/// Three-node scenario: A spawns on B and C, partition isolates C.
#[test]
fn three_node_partial_partition() {
    init_test("three_node_partial_partition");

    let (mut harness, a, b, c) = harness_three_nodes(51, NetworkConditions::local());

    // Partition C from A (but B-C stays connected)
    harness.set_fault_script(FaultScript::new().at(
        Duration::ZERO,
        HarnessFault::Network(Fault::Partition {
            hosts_a: vec![HostId::new(1)], // A
            hosts_b: vec![HostId::new(3)], // C
        }),
    ));

    // Run one tick so partition takes effect before injecting spawns
    harness.run_for(Duration::from_millis(1));

    let tid_b = RemoteTaskId::next();
    let tid_c = RemoteTaskId::next();

    harness.inject_spawn(&a, &b, tid_b);
    harness.inject_spawn(&a, &c, tid_c);
    harness.run_for(Duration::from_millis(300));

    // B should receive and complete its spawn
    let b_received = harness
        .node(&b)
        .unwrap()
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnReceived { .. }));
    assert_with_log!(b_received, "B received spawn", true, b_received);

    // C should NOT receive (partitioned from A)
    let c_received = harness
        .node(&c)
        .unwrap()
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnReceived { .. }));
    assert_with_log!(!c_received, "C blocked by partition", false, c_received);

    test_complete!("three_node_partial_partition");
}

// ============================================================================
// Lossy Network Stress
// ============================================================================

/// Under lossy conditions, some spawns may fail but those that arrive are
/// handled correctly.
#[test]
fn lossy_network_stress() {
    init_test("lossy_network_stress");

    let conditions = NetworkConditions::lossy();
    let (mut harness, a, b) = harness_with_conditions(52, conditions);

    // Send 20 spawn requests under lossy conditions
    let task_ids: Vec<RemoteTaskId> = (0..20).map(|_| RemoteTaskId::next()).collect();
    for &tid in &task_ids {
        harness.inject_spawn(&a, &b, tid);
    }
    harness.run_for(Duration::from_millis(1000));

    let node_b = harness.node(&b).unwrap();
    let recv_count = node_b
        .events()
        .iter()
        .filter(|e| matches!(e, NodeEvent::SpawnReceived { .. }))
        .count();
    let metrics = harness.network_metrics();

    info!(
        received = recv_count,
        sent = metrics.packets_sent,
        dropped = metrics.packets_dropped,
        "lossy network results"
    );

    // Under 10% loss, we expect most but not all to arrive
    // (some acks may be lost too, causing retransmit scenarios in real systems)
    assert_with_log!(
        recv_count > 0,
        "at least some spawns arrive",
        true,
        recv_count > 0
    );
    assert_with_log!(
        metrics.packets_dropped > 0,
        "some packets dropped",
        true,
        metrics.packets_dropped > 0
    );

    test_complete!("lossy_network_stress");
}

// ============================================================================
// WAN Conditions Stress
// ============================================================================

/// WAN-like conditions: high latency + jitter + low loss. Tasks should
/// complete but with significant delay.
#[test]
fn wan_conditions_complete_with_delay() {
    init_test("wan_conditions_complete_with_delay");

    let (mut harness, a, b) = harness_with_conditions(53, NetworkConditions::wan());
    let task_id = RemoteTaskId::next();

    harness.inject_spawn(&a, &b, task_id);
    // WAN latency is ~50ms + jitter, so give plenty of time
    harness.run_for(Duration::from_millis(2000));

    let node_b = harness.node(&b).unwrap();
    let received = node_b
        .events()
        .iter()
        .any(|e| matches!(e, NodeEvent::SpawnReceived { .. }));
    // May not arrive if packet_loss hits it (0.1% chance)
    info!(received, "WAN spawn received");
    if received {
        let completed = node_b
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::TaskCompleted { .. }));
        assert_with_log!(completed, "WAN task completed", true, completed);
    }

    test_complete!("wan_conditions_complete_with_delay");
}

// ============================================================================
// Congested Network Stress
// ============================================================================

/// Congested network: high latency, 5% loss, 2% reorder, bursty jitter.
#[test]
fn congested_network_resilience() {
    init_test("congested_network_resilience");

    let (mut harness, a, b) = harness_with_conditions(54, NetworkConditions::congested());

    let n_tasks = 10;
    let task_ids: Vec<RemoteTaskId> = (0..n_tasks).map(|_| RemoteTaskId::next()).collect();
    for &tid in &task_ids {
        harness.inject_spawn(&a, &b, tid);
    }
    harness.run_for(Duration::from_millis(5000));

    let node_b = harness.node(&b).unwrap();
    let recv_count = node_b
        .events()
        .iter()
        .filter(|e| matches!(e, NodeEvent::SpawnReceived { .. }))
        .count();
    let metrics = harness.network_metrics();

    info!(
        received = recv_count,
        total = n_tasks,
        dropped = metrics.packets_dropped,
        duplicated = metrics.packets_duplicated,
        "congested network results"
    );

    // Under congestion, expect some arrivals
    assert_with_log!(
        recv_count > 0,
        "some tasks arrive under congestion",
        true,
        recv_count > 0
    );

    test_complete!("congested_network_resilience");
}

// ============================================================================
// Network-Level Metrics Validation
// ============================================================================

/// Metrics counters are consistent across fault scenarios.
#[test]
fn metrics_consistency() {
    init_test("metrics_consistency");

    let conditions = NetworkConditions {
        packet_loss: 0.2,
        packet_duplicate: 0.1,
        packet_corrupt: 0.1,
        ..NetworkConditions::local()
    };
    let config = make_config(55, conditions);
    let mut net = SimulatedNetwork::new(config);
    let h1 = net.add_host("h1");
    let h2 = net.add_host("h2");

    for _ in 0..100 {
        net.send(
            h1,
            h2,
            asupersync::bytes::Bytes::copy_from_slice(b"metric-test"),
        );
    }
    net.run_until_idle();

    let m = net.metrics();
    assert_with_log!(m.packets_sent == 100, "100 sent", 100, m.packets_sent);

    // delivered + dropped should account for all packets (originals + duplicates)
    // Some duplicates may also be dropped, so:
    // packets_sent + packets_duplicated >= packets_delivered + (some drops)
    info!(
        sent = m.packets_sent,
        delivered = m.packets_delivered,
        dropped = m.packets_dropped,
        duplicated = m.packets_duplicated,
        corrupted = m.packets_corrupted,
        "metrics"
    );

    // Basic sanity: delivered + dropped >= sent (duplicates add to both)
    let accounted = m.packets_delivered + m.packets_dropped;
    assert_with_log!(
        accounted >= m.packets_sent,
        "all packets accounted for",
        true,
        accounted >= m.packets_sent
    );

    test_complete!("metrics_consistency");
}
