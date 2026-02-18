//! Channel partition fault injection integration tests (bd-2ktrc.2).
//!
//! Validates the `PartitionController` and `PartitionSender` wrapper under
//! partition scenarios. Pass criteria:
//!
//! 1. **Partition blocks delivery**: Messages sent across a partition are
//!    either dropped or return errors, depending on `PartitionBehavior`.
//! 2. **Recovery after heal**: After healing, messages flow normally.
//! 3. **No split-brain**: Partitioned actors cannot make conflicting progress
//!    through the same channel.
//! 4. **Asymmetric partitions**: One-way partitions work correctly.
//! 5. **Cascading partitions**: Multiple overlapping partitions compose.
//! 6. **Budget/deadline expiry during partition**: Cancelled contexts return
//!    appropriate errors even when partitioned.
//! 7. **Evidence logging**: All partition events are logged.

use asupersync::channel::mpsc;
use asupersync::channel::partition::{
    ActorId, PartitionBehavior, PartitionController, partition_channel,
};
use asupersync::evidence_sink::{CollectorSink, EvidenceSink};
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use asupersync::{RegionId, TaskId};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

fn test_cx() -> asupersync::cx::Cx {
    asupersync::cx::Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

fn block_on<F: Future>(f: F) -> F::Output {
    struct NoopWaker;
    impl std::task::Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut pinned = Box::pin(f);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn make_controller(behavior: PartitionBehavior) -> (Arc<PartitionController>, Arc<CollectorSink>) {
    let collector = Arc::new(CollectorSink::new());
    let sink: Arc<dyn EvidenceSink> = collector.clone();
    let ctrl = Arc::new(PartitionController::new(behavior, sink));
    (ctrl, collector)
}

// ---------------------------------------------------------------------------
// Criterion 1: Partition blocks delivery
// ---------------------------------------------------------------------------

#[test]
fn partition_blocks_all_messages_drop_mode() {
    let (ctrl, _) = make_controller(PartitionBehavior::Drop);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx, rx) = partition_channel::<u32>(64, ctrl.clone(), a, b);
    let cx = test_cx();

    ctrl.partition(a, b);

    // Send 100 messages; all should be silently dropped.
    for i in 0..100 {
        block_on(ptx.send(&cx, i)).expect("send should succeed in drop mode");
    }

    // Nothing delivered.
    assert!(rx.is_empty(), "no messages should arrive during partition");
    assert_eq!(ctrl.stats().messages_dropped, 100);
}

#[test]
fn partition_blocks_all_messages_error_mode() {
    let (ctrl, _) = make_controller(PartitionBehavior::Error);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx, _rx) = partition_channel::<u32>(64, ctrl.clone(), a, b);
    let cx = test_cx();

    ctrl.partition(a, b);

    for i in 0..10 {
        let result = block_on(ptx.send(&cx, i));
        assert!(
            matches!(result, Err(mpsc::SendError::Disconnected(v)) if v == i),
            "expected Disconnected({i}), got: {result:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Criterion 2: Recovery after heal
// ---------------------------------------------------------------------------

#[test]
fn recovery_after_heal_drop_mode() {
    let (ctrl, _) = make_controller(PartitionBehavior::Drop);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx, rx) = partition_channel::<u32>(64, ctrl.clone(), a, b);
    let cx = test_cx();

    // Phase 1: partition active, messages dropped.
    ctrl.partition(a, b);
    for i in 0..5 {
        block_on(ptx.send(&cx, i)).unwrap();
    }
    assert!(rx.is_empty());

    // Phase 2: heal, messages flow.
    ctrl.heal(a, b);
    for i in 10..15 {
        block_on(ptx.send(&cx, i)).unwrap();
    }
    let mut received = Vec::new();
    while let Ok(v) = rx.try_recv() {
        received.push(v);
    }
    assert_eq!(received, vec![10, 11, 12, 13, 14]);
}

#[test]
fn recovery_after_heal_error_mode() {
    let (ctrl, _) = make_controller(PartitionBehavior::Error);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx, rx) = partition_channel::<u32>(64, ctrl.clone(), a, b);
    let cx = test_cx();

    ctrl.partition(a, b);
    assert!(block_on(ptx.send(&cx, 1)).is_err());

    ctrl.heal(a, b);
    block_on(ptx.send(&cx, 2)).expect("send should succeed after heal");
    assert_eq!(rx.try_recv().unwrap(), 2);
}

#[test]
fn multiple_partition_heal_cycles() {
    let (ctrl, _) = make_controller(PartitionBehavior::Drop);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx, rx) = partition_channel::<u32>(64, ctrl.clone(), a, b);
    let cx = test_cx();

    for cycle in 0..5 {
        // Partition.
        ctrl.partition(a, b);
        block_on(ptx.send(&cx, cycle * 100)).unwrap(); // Dropped.

        // Heal.
        ctrl.heal(a, b);
        block_on(ptx.send(&cx, cycle * 100 + 1)).unwrap(); // Delivered.
    }

    let mut received = Vec::new();
    while let Ok(v) = rx.try_recv() {
        received.push(v);
    }
    // Only the post-heal messages should arrive.
    assert_eq!(received, vec![1, 101, 201, 301, 401]);
}

// ---------------------------------------------------------------------------
// Criterion 3: No split-brain
// ---------------------------------------------------------------------------

#[test]
fn no_split_brain_under_symmetric_partition() {
    let (ctrl, _) = make_controller(PartitionBehavior::Drop);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx_ab, rx_b) = partition_channel::<String>(16, ctrl.clone(), a, b);
    let (ptx_ba, rx_a) = partition_channel::<String>(16, ctrl.clone(), b, a);
    let cx = test_cx();

    ctrl.partition_symmetric(a, b);

    // Neither side can reach the other — no conflicting state possible.
    block_on(ptx_ab.send(&cx, "from_a".to_string())).unwrap();
    block_on(ptx_ba.send(&cx, "from_b".to_string())).unwrap();

    assert!(rx_b.is_empty(), "B should not receive from A");
    assert!(rx_a.is_empty(), "A should not receive from B");

    // After heal, both sides can communicate.
    ctrl.heal_symmetric(a, b);

    block_on(ptx_ab.send(&cx, "post_heal_a".to_string())).unwrap();
    block_on(ptx_ba.send(&cx, "post_heal_b".to_string())).unwrap();

    assert_eq!(rx_b.try_recv().unwrap(), "post_heal_a");
    assert_eq!(rx_a.try_recv().unwrap(), "post_heal_b");
}

// ---------------------------------------------------------------------------
// Criterion 4: Asymmetric partitions
// ---------------------------------------------------------------------------

#[test]
fn asymmetric_partition_one_way_block() {
    let (ctrl, _) = make_controller(PartitionBehavior::Drop);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx_ab, rx_b) = partition_channel::<u32>(16, ctrl.clone(), a, b);
    let (ptx_ba, rx_a) = partition_channel::<u32>(16, ctrl.clone(), b, a);
    let cx = test_cx();

    // Only A→B partitioned.
    ctrl.partition(a, b);

    block_on(ptx_ab.send(&cx, 1)).unwrap(); // Dropped.
    block_on(ptx_ba.send(&cx, 2)).unwrap(); // Delivered.

    assert!(rx_b.is_empty());
    assert_eq!(rx_a.try_recv().unwrap(), 2);
}

#[test]
fn asymmetric_reverse_direction_not_affected() {
    let (ctrl, _) = make_controller(PartitionBehavior::Error);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx_ab, _rx_b) = partition_channel::<u32>(16, ctrl.clone(), a, b);
    let (ptx_ba, rx_a) = partition_channel::<u32>(16, ctrl.clone(), b, a);
    let cx = test_cx();

    ctrl.partition(a, b);

    // A→B errors.
    assert!(block_on(ptx_ab.send(&cx, 1)).is_err());
    // B→A succeeds.
    block_on(ptx_ba.send(&cx, 2)).expect("reverse direction should work");
    assert_eq!(rx_a.try_recv().unwrap(), 2);
}

// ---------------------------------------------------------------------------
// Criterion 5: Cascading partitions
// ---------------------------------------------------------------------------

#[test]
fn three_way_cascading_partition() {
    let (ctrl, _) = make_controller(PartitionBehavior::Drop);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let c = ActorId::new(3);

    let (tx_a2b, rx_b) = partition_channel::<u32>(16, ctrl.clone(), a, b);
    let (tx_b2c, rx_c_from_b) = partition_channel::<u32>(16, ctrl.clone(), b, c);
    let (tx_a2c, rx_c_from_a) = partition_channel::<u32>(16, ctrl.clone(), a, c);
    let cx = test_cx();

    // Partition A from {B, C}.
    ctrl.partition(a, b);
    ctrl.partition(a, c);

    block_on(tx_a2b.send(&cx, 1)).unwrap(); // Dropped.
    block_on(tx_a2c.send(&cx, 2)).unwrap(); // Dropped.
    block_on(tx_b2c.send(&cx, 3)).unwrap(); // B→C not partitioned, delivered.

    assert!(rx_b.is_empty());
    assert!(rx_c_from_a.is_empty());
    assert_eq!(rx_c_from_b.try_recv().unwrap(), 3);

    // Heal A→B only.
    ctrl.heal(a, b);
    block_on(tx_a2b.send(&cx, 4)).unwrap(); // Delivered.
    block_on(tx_a2c.send(&cx, 5)).unwrap(); // Still dropped.

    assert_eq!(rx_b.try_recv().unwrap(), 4);
    assert!(rx_c_from_a.is_empty());
}

#[test]
fn cascading_heal_all() {
    let (ctrl, _) = make_controller(PartitionBehavior::Drop);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let c = ActorId::new(3);

    ctrl.partition_symmetric(a, b);
    ctrl.partition_symmetric(b, c);
    ctrl.partition_symmetric(a, c);
    assert_eq!(ctrl.active_partition_count(), 6);

    ctrl.heal_all();
    assert_eq!(ctrl.active_partition_count(), 0);
    assert!(!ctrl.is_partitioned(a, b));
    assert!(!ctrl.is_partitioned(b, c));
    assert!(!ctrl.is_partitioned(a, c));
}

// ---------------------------------------------------------------------------
// Criterion 6: Cancellation during partition
// ---------------------------------------------------------------------------

#[test]
fn cancelled_context_during_partition_error_mode() {
    let (ctrl, _) = make_controller(PartitionBehavior::Error);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx, _rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
    let cx = test_cx();

    // Cancel the context.
    cx.set_cancel_requested(true);

    // Cancellation checkpoint runs before partition behavior, so Cancelled
    // takes precedence even when the link is partitioned.
    ctrl.partition(a, b);
    let result = block_on(ptx.send(&cx, 42));
    assert!(
        matches!(result, Err(mpsc::SendError::Cancelled(42))),
        "cancel checkpoint should take precedence over partition behavior: {result:?}"
    );
}

#[test]
fn cancelled_context_without_partition_returns_cancelled() {
    let (ctrl, _) = make_controller(PartitionBehavior::Error);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx, _rx) = partition_channel::<u32>(16, ctrl, a, b);
    let cx = test_cx();

    cx.set_cancel_requested(true);
    let result = block_on(ptx.send(&cx, 42));
    // Without partition, the inner send detects cancellation.
    assert!(
        matches!(result, Err(mpsc::SendError::Cancelled(42))),
        "expected Cancelled, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Criterion 7: Evidence logging
// ---------------------------------------------------------------------------

#[test]
fn evidence_logged_for_all_events() {
    let (ctrl, collector) = make_controller(PartitionBehavior::Drop);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx, _rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
    let cx = test_cx();

    ctrl.partition(a, b);
    block_on(ptx.send(&cx, 1)).unwrap(); // Dropped.
    ctrl.heal(a, b);

    let entries = collector.entries();

    // Should have: partition_create, message_dropped, partition_heal.
    let create = entries
        .iter()
        .filter(|e| e.action.contains("partition_create"))
        .count();
    let drop = entries
        .iter()
        .filter(|e| e.action.contains("message_dropped"))
        .count();
    let heal = entries
        .iter()
        .filter(|e| e.action.contains("partition_heal"))
        .count();

    assert_eq!(create, 1, "should log 1 partition_create");
    assert_eq!(drop, 1, "should log 1 message_dropped");
    assert_eq!(heal, 1, "should log 1 partition_heal");

    for entry in &entries {
        assert_eq!(entry.component, "channel_partition");
        assert!(entry.is_valid(), "evidence entry must be valid: {entry:?}");
    }
}

#[test]
fn evidence_includes_actor_ids_in_features() {
    let (ctrl, collector) = make_controller(PartitionBehavior::Drop);
    let a = ActorId::new(10);
    let b = ActorId::new(20);

    ctrl.partition(a, b);

    let entries = collector.entries();
    assert!(!entries.is_empty());

    let entry = &entries[0];
    let src_feature = entry
        .top_features
        .iter()
        .find(|(k, _)| k == "src_actor")
        .map(|(_, v)| *v);
    let dst_feature = entry
        .top_features
        .iter()
        .find(|(k, _)| k == "dst_actor")
        .map(|(_, v)| *v);

    assert!(
        (src_feature.unwrap_or(0.0) - 10.0).abs() < f64::EPSILON,
        "src_actor should be 10"
    );
    assert!(
        (dst_feature.unwrap_or(0.0) - 20.0).abs() < f64::EPSILON,
        "dst_actor should be 20"
    );
}

// ---------------------------------------------------------------------------
// Additional: Stats correctness
// ---------------------------------------------------------------------------

#[test]
fn stats_track_all_operations() {
    let (ctrl, _) = make_controller(PartitionBehavior::Drop);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let (ptx, _rx) = partition_channel::<u32>(16, ctrl.clone(), a, b);
    let cx = test_cx();

    ctrl.partition(a, b);
    for _ in 0..10 {
        block_on(ptx.send(&cx, 0)).unwrap();
    }
    ctrl.heal(a, b);

    let stats = ctrl.stats();
    assert_eq!(stats.partitions_created, 1);
    assert_eq!(stats.partitions_healed, 1);
    assert_eq!(stats.messages_dropped, 10);
}

#[test]
fn heal_all_stats() {
    let (ctrl, _) = make_controller(PartitionBehavior::Drop);
    let a = ActorId::new(1);
    let b = ActorId::new(2);
    let c = ActorId::new(3);

    ctrl.partition_symmetric(a, b);
    ctrl.partition(a, c);
    // 3 directed partitions.

    ctrl.heal_all();

    let stats = ctrl.stats();
    assert_eq!(stats.partitions_created, 3);
    assert_eq!(stats.partitions_healed, 3);
}
