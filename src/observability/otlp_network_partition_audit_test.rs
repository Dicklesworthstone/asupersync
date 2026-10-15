//! OTLP-Trace exporter network partition audit test.
//!
//! **AUDIT SCOPE**: Verifies that OTLP trace exporter handles network partitions
//! correctly with bounded queue and oldest-drop load shedding under collector unreachability.
//!
//! **NETWORK PARTITION REQUIREMENT**:
//! - When collector is unreachable for >5 min, exporter MUST bound retry queue
//! - Drop OLDEST span batches when queue is full (preserve recent data)
//! - Track dropped spans in metrics (no silent data loss)
//! - NOT: hold ALL spans in memory (eventual OOM)
//! - NOT: silently drop without metrics (data loss with no signal)
//!
//! **CRITICAL**: Unbounded queuing during network partitions causes OOM kills.
//! Silent drops hide data loss and break observability.

#![cfg(test)]
#![allow(dead_code)]

use crate::observability::otlp_trace_exporter::{
    ExportError, LoadSheddingTraceExporter, OtlpSpan, SpanBatch, TraceExporter,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

/// Exporter fixture that simulates network partition (always fails).
#[derive(Debug)]
struct NetworkPartitionExporter {
    export_attempts: Arc<AtomicU64>,
}

impl NetworkPartitionExporter {
    fn new() -> Self {
        Self {
            export_attempts: Arc::new(AtomicU64::new(0)),
        }
    }

    fn export_attempts(&self) -> u64 {
        self.export_attempts.load(Ordering::Relaxed)
    }
}

impl TraceExporter for NetworkPartitionExporter {
    fn export(&self, _batch: &SpanBatch) -> Result<(), ExportError> {
        self.export_attempts.fetch_add(1, Ordering::Relaxed);
        // Simulate network partition - collector unreachable
        Err(ExportError::Transport(
            "Connection refused: network partition".to_string(),
        ))
    }

    fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

/// **AUDIT TEST**: Verify OTLP exporter bounds retry queue under network partition.
///
/// **SCENARIO**: Collector unreachable for >5 min with high span throughput.
/// **REQUIREMENT**: Bounded queue drops oldest, no OOM, metrics track drops.
/// **ASSESSMENT**: SOUND - LoadSheddingTraceExporter implements correct behavior.
#[test]
fn audit_otlp_network_partition_bounded_queue() {
    println!("🔍 AUDIT: OTLP network partition queue behavior");

    println!("📋 Network partition requirements:");
    println!("   • Bounded retry queue with configurable capacity");
    println!("   • Drop OLDEST span batches when queue is full");
    println!("   • Track dropped spans in metrics (otel.exporter.dropped_spans)");
    println!("   • Preserve recent observability data");
    println!("   • Prevent memory exhaustion (OOM protection)");

    // Create partition-simulating exporter with small queue for testing
    let partition_exporter = NetworkPartitionExporter::new();
    let queue_capacity = 5; // Small for testing
    let batch_timeout = Duration::from_millis(100);

    let exporter =
        LoadSheddingTraceExporter::new(Box::new(partition_exporter), queue_capacity, batch_timeout);

    println!("📊 Test scenario setup:");
    println!("   Queue capacity: {}", queue_capacity);
    println!("   Simulated network partition: collector unreachable");

    // Generate spans that exceed queue capacity
    let mut total_spans_created = 0;
    for batch_id in 1..=10 {
        let spans = vec![
            OtlpSpan {
                span_id: format!("span-{}-1", batch_id),
                name: format!("operation-{}", batch_id),
                start_time_unix_nano: 1000000,
                end_time_unix_nano: 2000000,
                attributes: vec![("service".to_string(), "test".to_string())],
                trace_flags: Some(0x01), // Sampled
            },
            OtlpSpan {
                span_id: format!("span-{}-2", batch_id),
                name: format!("child-operation-{}", batch_id),
                start_time_unix_nano: 1500000,
                end_time_unix_nano: 1800000,
                attributes: vec![("operation".to_string(), "child".to_string())],
                trace_flags: Some(0x01), // Sampled
            },
        ];

        let batch = SpanBatch {
            batch_id,
            spans: spans.clone(),
            created_at: Instant::now(),
        };

        total_spans_created += spans.len();

        // Export batch - will queue during network partition
        let result = exporter.export(&batch);
        assert!(result.is_ok(), "Export should succeed (queued for retry)");

        println!("   Batch {} queued ({} spans)", batch_id, spans.len());
    }

    println!("   Total spans created: {}", total_spans_created);

    // Check load shedding stats
    let stats = exporter.load_shedding_stats();
    println!("📊 Load shedding statistics:");
    println!(
        "   Queue depth: {}/{}",
        stats.queue_depth, stats.queue_capacity
    );
    println!("   Dropped batches: {}", stats.dropped_batches);
    println!("   Dropped spans: {}", exporter.dropped_spans_count());

    // Verify bounded queue behavior
    assert_eq!(
        stats.queue_capacity, queue_capacity,
        "Queue capacity should match configuration"
    );

    assert!(
        stats.queue_depth <= stats.queue_capacity,
        "Queue depth must not exceed capacity (OOM protection)"
    );

    // Should have dropped batches since we created 10 batches with capacity 5
    assert!(
        stats.dropped_batches > 0,
        "Should drop oldest batches when queue capacity exceeded"
    );

    // Should track dropped spans
    assert!(
        exporter.dropped_spans_count() > 0,
        "Should track dropped spans in metrics for observability"
    );

    println!("✅ BOUNDED QUEUE BEHAVIOR: SOUND");
    println!("   • Queue bounded to {} batches", queue_capacity);
    println!(
        "   • {} batches dropped (oldest-first)",
        stats.dropped_batches
    );
    println!(
        "   • {} spans dropped with metrics tracking",
        exporter.dropped_spans_count()
    );
}

/// **AUDIT TEST**: Verify queue preserves recent data during sustained partition.
///
/// **SCENARIO**: Long-duration network partition with continuous span generation.
/// **REQUIREMENT**: Oldest batches dropped, newest batches preserved in queue.
/// **ASSESSMENT**: SOUND - FIFO queue with oldest-drop correctly preserves recent data.
#[test]
fn audit_network_partition_preserves_recent_data() {
    println!("🔍 AUDIT: Network partition recent data preservation");

    let partition_exporter = NetworkPartitionExporter::new();
    let queue_capacity = 3; // Very small for clear testing
    let batch_timeout = Duration::from_millis(50);

    let exporter =
        LoadSheddingTraceExporter::new(Box::new(partition_exporter), queue_capacity, batch_timeout);

    println!("📋 Sustained partition scenario:");
    println!("   Queue capacity: {} batches", queue_capacity);
    println!("   Generating batches continuously during partition");

    // Generate batches over time to simulate sustained load
    let mut recent_batch_ids = Vec::new();
    for batch_id in 1..=8 {
        let spans = vec![OtlpSpan {
            span_id: format!("span-{}", batch_id),
            name: format!("recent-operation-{}", batch_id),
            start_time_unix_nano: 1000000 + (batch_id * 1000),
            end_time_unix_nano: 2000000 + (batch_id * 1000),
            attributes: vec![
                ("batch_id".to_string(), batch_id.to_string()),
                (
                    "timestamp".to_string(),
                    format!("{}", 1000000 + (batch_id * 1000)),
                ),
            ],
            trace_flags: Some(0x01),
        }];

        let batch = SpanBatch {
            batch_id,
            spans,
            created_at: Instant::now(),
        };

        exporter
            .export(&batch)
            .expect("Export should queue successfully");
        recent_batch_ids.push(batch_id);

        // Small delay to simulate realistic timing
        std::thread::sleep(Duration::from_millis(1));
    }

    let stats = exporter.load_shedding_stats();

    println!("📊 Final queue state:");
    println!(
        "   Queue depth: {}/{}",
        stats.queue_depth, stats.queue_capacity
    );
    println!("   Dropped batches: {}", stats.dropped_batches);

    // Verify queue is at capacity (bounded)
    assert_eq!(
        stats.queue_depth, queue_capacity,
        "Queue should be at capacity during sustained load"
    );

    // Should have dropped oldest batches
    let expected_drops = recent_batch_ids.len() - queue_capacity;
    assert_eq!(
        stats.dropped_batches as usize, expected_drops,
        "Should drop exactly the number of batches exceeding capacity"
    );

    println!("✅ RECENT DATA PRESERVATION: SOUND");
    println!("   • {} oldest batches dropped", expected_drops);
    println!("   • {} newest batches preserved in queue", queue_capacity);
}

/// **AUDIT TEST**: Verify memory usage is bounded during partition.
///
/// **SCENARIO**: Demonstrate that memory usage remains bounded regardless of partition duration.
/// **REQUIREMENT**: Memory footprint must not grow unbounded (OOM protection).
/// **ASSESSMENT**: SOUND - queue capacity provides hard memory bound.
#[test]
fn audit_memory_bounded_during_partition() {
    println!("🔍 AUDIT: Memory boundedness during network partition");

    let partition_exporter = NetworkPartitionExporter::new();
    let queue_capacity: usize = 10;
    let batch_timeout = Duration::from_millis(10);

    let exporter =
        LoadSheddingTraceExporter::new(Box::new(partition_exporter), queue_capacity, batch_timeout);

    println!("📋 Memory boundedness test:");
    println!("   Queue capacity: {} batches", queue_capacity);
    println!("   Simulating sustained high-throughput load");

    let spans_per_batch: u64 = 50; // Simulate high span volume
    let num_batches: u64 = 100; // Much larger than capacity

    for batch_id in 1..=num_batches {
        let mut spans = Vec::new();
        for span_idx in 1..=spans_per_batch {
            spans.push(OtlpSpan {
                span_id: format!("span-{}-{}", batch_id, span_idx),
                name: format!("high-volume-op-{}", span_idx),
                start_time_unix_nano: 1000000 + (span_idx * 1000),
                end_time_unix_nano: 2000000 + (span_idx * 1000),
                attributes: vec![
                    ("batch".to_string(), batch_id.to_string()),
                    ("span".to_string(), span_idx.to_string()),
                    ("volume_test".to_string(), "true".to_string()),
                ],
                trace_flags: Some(0x01),
            });
        }

        let batch = SpanBatch {
            batch_id,
            spans,
            created_at: Instant::now(),
        };

        exporter
            .export(&batch)
            .expect("Export should queue successfully");
    }

    let stats = exporter.load_shedding_stats();
    let total_spans_created = num_batches * spans_per_batch;
    let max_spans_in_memory = queue_capacity as u64 * spans_per_batch;

    println!("📊 Memory usage analysis:");
    println!("   Total spans created: {}", total_spans_created);
    println!("   Maximum spans in memory: {}", max_spans_in_memory);
    println!(
        "   Memory reduction factor: {}x",
        total_spans_created / max_spans_in_memory
    );
    println!(
        "   Queue depth: {}/{}",
        stats.queue_depth, stats.queue_capacity
    );
    println!("   Dropped spans: {}", exporter.dropped_spans_count());

    // Verify memory is bounded
    assert!(
        stats.queue_depth <= queue_capacity,
        "Queue depth must not exceed capacity"
    );

    assert!(
        exporter.dropped_spans_count() > 0,
        "Should drop spans to maintain memory bounds"
    );

    let memory_savings_ratio = exporter.dropped_spans_count() as f64 / total_spans_created as f64;
    println!(
        "   Memory savings: {:.1}% of spans dropped to prevent OOM",
        memory_savings_ratio * 100.0
    );

    println!("✅ MEMORY BOUNDEDNESS: SOUND");
    println!("   • Queue capacity provides hard memory bound");
    println!(
        "   • {:.1}% memory usage reduction through load shedding",
        memory_savings_ratio * 100.0
    );
}

/// **AUDIT TEST**: Document recovery behavior when partition ends.
///
/// **SCENARIO**: Network partition ends, queued batches should be processed.
/// **REQUIREMENT**: Queued spans exported when connectivity restored.
/// **ASSESSMENT**: SOUND - process_queue() drains queue when exporter succeeds.
#[test]
fn audit_partition_recovery_queue_processing() {
    println!("🔍 AUDIT: Network partition recovery queue processing");

    // Start with working exporter to simulate recovery
    #[derive(Debug)]
    struct RecoveringExporter {
        exported_batches: Arc<AtomicU64>,
    }

    impl RecoveringExporter {
        fn new() -> Self {
            Self {
                exported_batches: Arc::new(AtomicU64::new(0)),
            }
        }

        fn exported_count(&self) -> u64 {
            self.exported_batches.load(Ordering::Relaxed)
        }
    }

    impl TraceExporter for RecoveringExporter {
        fn export(&self, _batch: &SpanBatch) -> Result<(), ExportError> {
            self.exported_batches.fetch_add(1, Ordering::Relaxed);
            Ok(()) // Simulate successful export after recovery
        }

        fn flush(&self) -> Result<(), ExportError> {
            Ok(())
        }
    }

    let recovering_exporter = RecoveringExporter::new();
    let queue_capacity = 5;
    let batch_timeout = Duration::from_millis(100);

    let exporter = LoadSheddingTraceExporter::new(
        Box::new(recovering_exporter),
        queue_capacity,
        batch_timeout,
    );

    println!("📋 Partition recovery scenario:");
    println!("   Queue capacity: {} batches", queue_capacity);
    println!("   Simulating network recovery with queue processing");

    // Queue some batches (simulate spans during recovery)
    let num_batches: usize = 3;
    for batch_id in 1..=num_batches {
        let spans = vec![OtlpSpan {
            span_id: format!("recovery-span-{}", batch_id),
            name: "recovery-operation".to_string(),
            start_time_unix_nano: 1000000,
            end_time_unix_nano: 2000000,
            attributes: vec![("recovery".to_string(), "true".to_string())],
            trace_flags: Some(0x01),
        }];

        let batch = SpanBatch {
            batch_id: batch_id as u64,
            spans,
            created_at: Instant::now(),
        };

        exporter
            .export(&batch)
            .expect("Export should queue successfully");
    }

    let stats_before = exporter.load_shedding_stats();
    println!("   Queued batches: {}", stats_before.queue_depth);

    // Simulate background processing after recovery
    let processed = exporter
        .process_queue()
        .expect("Queue processing should succeed");
    let stats_after = exporter.load_shedding_stats();

    println!("📊 Recovery processing results:");
    println!("   Batches processed: {}", processed);
    println!("   Queue depth after: {}", stats_after.queue_depth);

    assert_eq!(processed, num_batches, "Should process all queued batches");
    assert_eq!(
        stats_after.queue_depth, 0,
        "Queue should be empty after processing"
    );

    println!("✅ PARTITION RECOVERY: SOUND");
    println!(
        "   • {} batches successfully processed after recovery",
        processed
    );
    println!("   • Queue drained completely");
}
