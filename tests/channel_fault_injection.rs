//! Channel fault injection integration tests (bd-2ktrc.1).
//!
//! Validates the `FaultSender` wrapper under reorder and duplication
//! scenarios. Pass criteria:
//!
//! 1. **No obligation leak**: Reserved slots are always committed or aborted,
//!    even when messages are reordered or duplicated.
//! 2. **Idempotency**: Duplicated messages do not cause double-processing
//!    when consumers de-duplicate.
//! 3. **Eventual delivery**: All messages sent through a reorder buffer are
//!    eventually delivered after `flush()`.
//! 4. **Evidence logging**: All injected faults are logged to the evidence sink.
//! 5. **Determinism**: Same seed produces identical fault sequences.

use asupersync::channel::fault::{FaultChannelConfig, fault_channel};
use asupersync::evidence_sink::{CollectorSink, EvidenceSink};
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use asupersync::{RegionId, TaskId};
use std::collections::HashSet;
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

fn drain_receiver<T>(rx: &asupersync::channel::Receiver<T>) -> Vec<T> {
    let mut received = Vec::new();
    while let Ok(val) = rx.try_recv() {
        received.push(val);
    }
    received
}

// ---------------------------------------------------------------------------
// Pass criterion 1: No obligation leak
// ---------------------------------------------------------------------------

#[test]
fn no_obligation_leak_under_reorder() {
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(42).with_reorder(0.5, 4);
    let (fault_tx, rx) = fault_channel::<u32>(64, config, sink);
    let cx = test_cx();

    for i in 0..20 {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }
    block_on(fault_tx.flush(&cx)).expect("flush");

    let received = drain_receiver(&rx);

    // After flush, the underlying channel should have zero reserved slots.
    // The receiver reports is_empty only if all messages are drained.
    assert!(rx.is_empty(), "channel should be empty after draining");

    // All 20 values should be present (eventual delivery).
    let unique: HashSet<u32> = received.iter().copied().collect();
    for i in 0..20 {
        assert!(unique.contains(&i), "missing message {i}");
    }
}

#[test]
fn no_obligation_leak_under_duplication() {
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(42).with_duplication(0.5);
    let (fault_tx, rx) = fault_channel::<u32>(128, config, sink);
    let cx = test_cx();

    for i in 0..20 {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }

    let received = drain_receiver(&rx);

    // Must have at least the 20 originals.
    assert!(
        received.len() >= 20,
        "expected >= 20 messages, got {}",
        received.len()
    );

    // No reserved slots should remain.
    assert!(rx.is_empty());
}

#[test]
fn no_obligation_leak_mixed_faults() {
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(42)
        .with_reorder(0.3, 5)
        .with_duplication(0.2);
    let (fault_tx, rx) = fault_channel::<u32>(256, config, sink);
    let cx = test_cx();

    for i in 0..50 {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }
    block_on(fault_tx.flush(&cx)).expect("flush");

    let received = drain_receiver(&rx);
    let unique: HashSet<u32> = received.iter().copied().collect();

    // All originals must be present.
    for i in 0..50 {
        assert!(unique.contains(&i), "missing message {i}");
    }

    // Channel should be drained clean.
    assert!(rx.is_empty());
}

// ---------------------------------------------------------------------------
// Pass criterion 2: Idempotency (duplicated messages)
// ---------------------------------------------------------------------------

#[test]
fn idempotent_dedup_under_duplication() {
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(42).with_duplication(1.0);
    let (fault_tx, rx) = fault_channel::<u32>(64, config, sink);
    let cx = test_cx();

    for i in 0..10 {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }

    let received = drain_receiver(&rx);

    // All messages are duplicated → 20 received.
    assert_eq!(
        received.len(),
        20,
        "expected 20 messages (10 originals + 10 dups)"
    );

    // Consumer de-duplication: build a set.
    let unique: HashSet<u32> = received.iter().copied().collect();
    assert_eq!(
        unique.len(),
        10,
        "de-duplicated set should have 10 unique values"
    );

    // Each value appears exactly twice.
    for i in 0..10 {
        let count = received.iter().filter(|&&v| v == i).count();
        assert_eq!(count, 2, "message {i} should appear twice, got {count}");
    }
}

#[test]
fn idempotent_processing_with_sequence_numbers() {
    // Simulate an idempotent processor that tracks seen sequence numbers.
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(99).with_duplication(0.5);
    let (fault_tx, rx) = fault_channel::<u32>(128, config, sink);
    let cx = test_cx();

    for i in 0..30 {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }

    // Simulate idempotent consumer.
    let mut seen = HashSet::new();
    let mut processed = Vec::new();
    let received = drain_receiver(&rx);

    for val in received {
        if seen.insert(val) {
            // First time seeing this value; process it.
            processed.push(val);
        }
        // Duplicate: skip.
    }

    // All 30 originals should be processed exactly once.
    assert_eq!(processed.len(), 30);
    processed.sort_unstable();
    let expected: Vec<u32> = (0..30).collect();
    assert_eq!(processed, expected);
}

// ---------------------------------------------------------------------------
// Pass criterion 3: Eventual delivery (reordered messages)
// ---------------------------------------------------------------------------

#[test]
fn eventual_delivery_reorder_only() {
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(42).with_reorder(1.0, 5);
    let (fault_tx, rx) = fault_channel::<u32>(128, config, sink);
    let cx = test_cx();

    let count = 25;
    for i in 0..count {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }
    // Flush ensures all buffered messages are delivered.
    block_on(fault_tx.flush(&cx)).expect("flush");

    let mut received = drain_receiver(&rx);
    assert_eq!(
        received.len(),
        count as usize,
        "all messages must be delivered"
    );

    // Verify all values are present.
    received.sort_unstable();
    let expected: Vec<u32> = (0..count).collect();
    assert_eq!(received, expected);
}

#[test]
fn eventual_delivery_large_message_count() {
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(42).with_reorder(0.7, 8);
    let (fault_tx, rx) = fault_channel::<u32>(512, config, sink);
    let cx = test_cx();

    let count = 200;
    for i in 0..count {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }
    block_on(fault_tx.flush(&cx)).expect("flush");

    let mut received = drain_receiver(&rx);
    received.sort_unstable();
    received.dedup();
    assert_eq!(
        received.len(),
        count as usize,
        "all unique messages must arrive"
    );
}

#[test]
fn reorder_actually_reorders() {
    // Verify that reordering actually changes the order (with high probability).
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(42).with_reorder(1.0, 10);
    let (fault_tx, rx) = fault_channel::<u32>(128, config, sink);
    let cx = test_cx();

    let count: u32 = 20;
    for i in 0..count {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }
    block_on(fault_tx.flush(&cx)).expect("flush");

    let received = drain_receiver(&rx);
    let in_order: Vec<u32> = (0..count).collect();

    // With 20 messages and buffer=10, reordering should change something.
    // (Probability of maintaining order through shuffle is astronomically low.)
    assert_ne!(
        received, in_order,
        "reordering should change message order (seed=42, count=20, buf=10)"
    );

    // But all values should still be present.
    let mut sorted = received;
    sorted.sort_unstable();
    assert_eq!(sorted, in_order);
}

// ---------------------------------------------------------------------------
// Pass criterion 4: Evidence logging
// ---------------------------------------------------------------------------

#[test]
fn evidence_logged_for_reorder() {
    let collector = Arc::new(CollectorSink::new());
    let sink: Arc<dyn EvidenceSink> = collector.clone();
    let config = FaultChannelConfig::new(42).with_reorder(1.0, 3);
    let (fault_tx, _rx) = fault_channel::<u32>(64, config, sink);
    let cx = test_cx();

    for i in 0..6 {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }

    let entries = collector.entries();
    assert!(
        !entries.is_empty(),
        "evidence must be logged for reorder faults"
    );

    // Check that entries have correct component and action.
    for entry in &entries {
        assert_eq!(entry.component, "channel_fault");
        assert!(
            entry.action.starts_with("inject_"),
            "action should start with 'inject_', got: {}",
            entry.action
        );
        assert!(entry.is_valid(), "evidence entry must be valid");
    }

    // Should have reorder_buffer entries and reorder_flush entries.
    let buffer_entries = entries
        .iter()
        .filter(|e| e.action.contains("reorder_buffer"))
        .count();
    let flush_entries = entries
        .iter()
        .filter(|e| e.action.contains("reorder_flush"))
        .count();
    assert!(
        buffer_entries > 0,
        "should have reorder_buffer evidence entries"
    );
    assert!(
        flush_entries > 0,
        "should have reorder_flush evidence entries"
    );
}

#[test]
fn evidence_logged_for_duplication() {
    let collector = Arc::new(CollectorSink::new());
    let sink: Arc<dyn EvidenceSink> = collector.clone();
    let config = FaultChannelConfig::new(42).with_duplication(1.0);
    let (fault_tx, _rx) = fault_channel::<u32>(64, config, sink);
    let cx = test_cx();

    for i in 0..5 {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }

    let entries = collector.entries();
    let dup_entries = entries
        .iter()
        .filter(|e| e.action.contains("duplication"))
        .count();
    assert_eq!(
        dup_entries, 5,
        "each send should log a duplication evidence entry"
    );
}

#[test]
fn no_evidence_when_disabled() {
    let collector = Arc::new(CollectorSink::new());
    let sink: Arc<dyn EvidenceSink> = collector.clone();
    let config = FaultChannelConfig::new(42); // No faults enabled.
    let (fault_tx, _rx) = fault_channel::<u32>(64, config, sink);
    let cx = test_cx();

    for i in 0..10 {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }

    assert!(
        collector.is_empty(),
        "no evidence should be logged when faults are disabled"
    );
}

// ---------------------------------------------------------------------------
// Pass criterion 5: Determinism
// ---------------------------------------------------------------------------

#[test]
fn deterministic_reorder_sequence() {
    let run = |seed: u64| -> Vec<u32> {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(seed).with_reorder(0.5, 4);
        let (fault_tx, rx) = fault_channel::<u32>(128, config, sink);
        let cx = test_cx();

        for i in 0..20 {
            block_on(fault_tx.send(&cx, i)).expect("send");
        }
        block_on(fault_tx.flush(&cx)).expect("flush");
        drain_receiver(&rx)
    };

    let run1 = run(42);
    let run2 = run(42);
    let run3 = run(99); // Different seed.

    assert_eq!(run1, run2, "same seed must produce identical output");
    // Different seeds should (with overwhelming probability) differ.
    assert_ne!(
        run1, run3,
        "different seeds should produce different output"
    );
}

#[test]
fn deterministic_duplication_sequence() {
    let run = |seed: u64| -> Vec<u32> {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(seed).with_duplication(0.5);
        let (fault_tx, rx) = fault_channel::<u32>(128, config, sink);
        let cx = test_cx();

        for i in 0..20 {
            block_on(fault_tx.send(&cx, i)).expect("send");
        }
        drain_receiver(&rx)
    };

    let run1 = run(42);
    let run2 = run(42);
    assert_eq!(run1, run2, "same seed must produce identical output");
}

#[test]
fn deterministic_mixed_faults() {
    let run = |seed: u64| -> (Vec<u32>, u64, u64) {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(seed)
            .with_reorder(0.3, 5)
            .with_duplication(0.2);
        let (fault_tx, rx) = fault_channel::<u32>(256, config, sink);
        let cx = test_cx();

        for i in 0..30 {
            block_on(fault_tx.send(&cx, i)).expect("send");
        }
        block_on(fault_tx.flush(&cx)).expect("flush");
        let received = drain_receiver(&rx);
        let stats = fault_tx.stats();
        (
            received,
            stats.messages_reordered,
            stats.messages_duplicated,
        )
    };

    let (recv1, reorder1, dup1) = run(42);
    let (recv2, reorder2, dup2) = run(42);

    assert_eq!(recv1, recv2);
    assert_eq!(reorder1, reorder2);
    assert_eq!(dup1, dup2);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn flush_without_sends_is_noop() {
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(42).with_reorder(1.0, 4);
    let (fault_tx, _rx) = fault_channel::<u32>(16, config, sink);
    let cx = test_cx();

    block_on(fault_tx.flush(&cx)).expect("empty flush");
    assert_eq!(fault_tx.stats().reorder_flushes, 0);
}

#[test]
fn stats_track_all_operations() {
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(42)
        .with_reorder(1.0, 3)
        .with_duplication(0.0);
    let (fault_tx, _rx) = fault_channel::<u32>(64, config, sink);
    let cx = test_cx();

    for i in 0..9 {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }
    // 9 messages with 100% reorder and buffer=3 → 3 auto-flushes.
    let stats = fault_tx.stats();
    assert_eq!(stats.messages_reordered, 9);
    assert_eq!(stats.reorder_flushes, 3);
    assert_eq!(stats.messages_sent, 9); // 9 messages sent through the underlying channel.
    assert_eq!(stats.messages_duplicated, 0);
}

#[test]
fn partial_buffer_flush_on_manual_call() {
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(42).with_reorder(1.0, 10);
    let (fault_tx, rx) = fault_channel::<u32>(64, config, sink);
    let cx = test_cx();

    // Send 3 messages (buffer size is 10, so no auto-flush).
    for i in 0..3 {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }
    assert_eq!(fault_tx.buffered_count(), 3);

    // Manual flush delivers partial buffer.
    block_on(fault_tx.flush(&cx)).expect("flush");
    assert_eq!(fault_tx.buffered_count(), 0);

    let mut received = drain_receiver(&rx);
    received.sort_unstable();
    assert_eq!(received, vec![0, 1, 2]);
}

#[test]
fn high_volume_stress_test() {
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = FaultChannelConfig::new(12345)
        .with_reorder(0.4, 8)
        .with_duplication(0.1);
    let (fault_tx, rx) = fault_channel::<u32>(2048, config, sink);
    let cx = test_cx();

    let count: u32 = 500;
    for i in 0..count {
        block_on(fault_tx.send(&cx, i)).expect("send");
    }
    block_on(fault_tx.flush(&cx)).expect("flush");

    let received = drain_receiver(&rx);

    // All originals must be present (eventual delivery + no loss).
    let unique: HashSet<u32> = received.iter().copied().collect();
    for i in 0..count {
        assert!(
            unique.contains(&i),
            "missing message {i} in high-volume test"
        );
    }

    // Duplicates mean total >= count.
    let stats = fault_tx.stats();
    assert!(
        received.len() as u64 >= u64::from(count),
        "total messages ({}) should be >= count ({count}), stats: {stats}",
        received.len()
    );
}
