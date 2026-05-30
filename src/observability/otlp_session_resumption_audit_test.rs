//! OTLP-Trace exporter session resumption audit test.
//!
//! **AUDIT SCOPE**: Verifies that OTLP trace exporter preserves accumulated spans
//! during network partitions and flushes them when connectivity resumes.
//!
//! **SESSION RESUMPTION REQUIREMENT**:
//! - When network reconnects after partition, accumulated spans MUST be flushed to collector
//! - Spans queued during outage MUST be preserved (no data loss)
//! - Resumption behavior consistent with OTLP exporter specification
//! - NOT: drop accumulated spans (data loss)
//! - NOT: require manual intervention to flush (poor UX)
//!
//! **CRITICAL**: Data preservation during network partitions is essential for
//! complete observability. Lost spans create gaps in distributed traces.

#![cfg(test)]

use crate::observability::otlp_trace_exporter::{
    ExportError, LoadSheddingTraceExporter, OtlpSpan, SpanBatch, TraceExporter,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

/// Exporter fixture that can simulate network partitions and recovery.
#[derive(Debug, Clone)]
struct PartitionSimulatorExporter {
    is_partitioned: Arc<AtomicBool>,
    export_attempts: Arc<AtomicU64>,
    successful_exports: Arc<AtomicU64>,
    exported_batches: Arc<parking_lot::Mutex<Vec<SpanBatch>>>,
}

impl PartitionSimulatorExporter {
    fn new() -> Self {
        Self {
            is_partitioned: Arc::new(AtomicBool::new(false)),
            export_attempts: Arc::new(AtomicU64::new(0)),
            successful_exports: Arc::new(AtomicU64::new(0)),
            exported_batches: Arc::new(parking_lot::Mutex::new(Vec::new())),
        }
    }

    fn simulate_partition(&self) {
        self.is_partitioned.store(true, Ordering::Relaxed);
    }

    fn simulate_recovery(&self) {
        self.is_partitioned.store(false, Ordering::Relaxed);
    }

    fn export_attempts(&self) -> u64 {
        self.export_attempts.load(Ordering::Relaxed)
    }

    fn successful_exports(&self) -> u64 {
        self.successful_exports.load(Ordering::Relaxed)
    }

    fn exported_batches(&self) -> Vec<SpanBatch> {
        self.exported_batches.lock().clone()
    }
}

impl TraceExporter for PartitionSimulatorExporter {
    fn export(&self, batch: &SpanBatch) -> Result<(), ExportError> {
        self.export_attempts.fetch_add(1, Ordering::Relaxed);

        if self.is_partitioned.load(Ordering::Relaxed) {
            // Simulate network partition - collector unreachable
            Err(ExportError::Transport(
                "Connection refused: network partition".to_string(),
            ))
        } else {
            // Simulate successful export
            self.successful_exports.fetch_add(1, Ordering::Relaxed);
            self.exported_batches.lock().push(batch.clone());
            Ok(())
        }
    }

    fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

/// **AUDIT TEST**: Verify spans are preserved during partition and flushed on recovery.
///
/// **SCENARIO**: Network partition occurs, spans accumulate, network recovers.
/// **REQUIREMENT**: All accumulated spans flushed when connectivity restored.
/// **ASSESSMENT**: SOUND - LoadSheddingTraceExporter preserves spans and flushes on recovery.
#[test]
fn audit_session_resumption_preserves_accumulated_spans() {
    println!("🔍 AUDIT: OTLP session resumption span preservation");

    println!("📋 Session resumption requirements:");
    println!("   • Spans accumulated during partition are preserved");
    println!("   • process_queue() flushes all accumulated spans after recovery");
    println!("   • No data loss due to network outages");
    println!("   • Flush() automatically triggers resumption");

    let partition_exporter = PartitionSimulatorExporter::new();
    let queue_capacity = 10; // Allow multiple batches to accumulate
    let batch_timeout = Duration::from_millis(100);

    let exporter = LoadSheddingTraceExporter::new(
        Box::new(partition_exporter.clone()),
        queue_capacity,
        batch_timeout,
    );

    println!("📊 Test scenario setup:");
    println!("   Queue capacity: {}", queue_capacity);

    // Phase 1: Normal operation (network working)
    println!("📊 Phase 1: Normal operation");
    partition_exporter.simulate_recovery(); // Ensure network is working

    let normal_batch = SpanBatch {
        batch_id: 1,
        spans: vec![OtlpSpan {
            span_id: "span-normal".to_string(),
            name: "normal-operation".to_string(),
            start_time_unix_nano: 1000000,
            end_time_unix_nano: 2000000,
            attributes: vec![("phase".to_string(), "normal".to_string())],
            trace_flags: Some(0x01),
        }],
        created_at: Instant::now(),
    };

    exporter
        .export(&normal_batch)
        .expect("Normal export should succeed");

    // Process queue to export normal batch
    exporter
        .process_queue()
        .expect("Normal processing should succeed");

    println!(
        "   Normal exports: {}",
        partition_exporter.successful_exports()
    );

    // Phase 2: Simulate network partition
    println!("📊 Phase 2: Network partition simulation");
    partition_exporter.simulate_partition();

    // Generate spans during partition (they should queue, not be lost)
    let mut partition_batches = Vec::new();
    for batch_id in 2..=6 {
        let spans = vec![
            OtlpSpan {
                span_id: format!("span-partition-{}-1", batch_id),
                name: format!("partition-operation-{}", batch_id),
                start_time_unix_nano: 1000000 + (batch_id * 1000),
                end_time_unix_nano: 2000000 + (batch_id * 1000),
                attributes: vec![
                    ("phase".to_string(), "partition".to_string()),
                    ("batch_id".to_string(), batch_id.to_string()),
                ],
                trace_flags: Some(0x01),
            },
            OtlpSpan {
                span_id: format!("span-partition-{}-2", batch_id),
                name: format!("child-operation-{}", batch_id),
                start_time_unix_nano: 1500000 + (batch_id * 1000),
                end_time_unix_nano: 1800000 + (batch_id * 1000),
                attributes: vec![
                    ("phase".to_string(), "partition".to_string()),
                    ("operation".to_string(), "child".to_string()),
                ],
                trace_flags: Some(0x01),
            },
        ];

        let batch = SpanBatch {
            batch_id,
            spans: spans.clone(),
            created_at: Instant::now(),
        };

        partition_batches.push(batch.clone());

        // Export during partition - should queue for later processing
        let result = exporter.export(&batch);
        assert!(result.is_ok(), "Export should succeed (queued for retry)");

        println!("   Batch {} queued during partition", batch_id);
    }

    let stats_during_partition = exporter.load_shedding_stats();
    println!("📊 State during partition:");
    println!(
        "   Queue depth: {}/{}",
        stats_during_partition.queue_depth, stats_during_partition.queue_capacity
    );
    println!(
        "   Export attempts during partition: {}",
        partition_exporter.export_attempts()
    );

    // Verify spans are queued, not exported during partition
    assert_eq!(
        stats_during_partition.queue_depth, 5,
        "Should have 5 batches queued during partition"
    );
    assert_eq!(
        partition_exporter.successful_exports(),
        1,
        "Only normal batch should be exported (before partition)"
    );

    // Phase 3: Network recovery and session resumption
    println!("📊 Phase 3: Network recovery and session resumption");
    partition_exporter.simulate_recovery();

    // Simulate session resumption via process_queue()
    let processed = exporter
        .process_queue()
        .expect("Session resumption should succeed");

    let stats_after_recovery = exporter.load_shedding_stats();
    let final_exported = partition_exporter.exported_batches();

    println!("📊 Session resumption results:");
    println!("   Batches processed during resumption: {}", processed);
    println!(
        "   Queue depth after resumption: {}",
        stats_after_recovery.queue_depth
    );
    println!(
        "   Total successful exports: {}",
        partition_exporter.successful_exports()
    );
    println!("   Final exported batches: {}", final_exported.len());

    // Verify session resumption worked correctly
    assert_eq!(
        processed, 5,
        "Should process all 5 queued batches during resumption"
    );
    assert_eq!(
        stats_after_recovery.queue_depth, 0,
        "Queue should be empty after successful resumption"
    );
    assert_eq!(
        partition_exporter.successful_exports(),
        6,
        "Should have 1 normal + 5 resumed = 6 total successful exports"
    );
    assert_eq!(
        final_exported.len(),
        6,
        "Should have exported all 6 batches (1 normal + 5 resumed)"
    );

    // Verify all partition batches were preserved and exported
    let exported_batch_ids: Vec<u64> = final_exported.iter().map(|b| b.batch_id).collect();
    let expected_batch_ids: Vec<u64> = vec![1, 2, 3, 4, 5, 6]; // Normal + partition batches
    assert_eq!(
        exported_batch_ids, expected_batch_ids,
        "All batches should be preserved and exported in order"
    );

    println!("✅ SESSION RESUMPTION: SOUND");
    println!("   • {} batches preserved during partition", processed);
    println!("   • Queue completely drained after recovery");
    println!("   • No span data loss during network outage");
    println!("   • OTLP exporter behavior specification compliance");
}

/// **AUDIT TEST**: Verify automatic session resumption via flush().
///
/// **SCENARIO**: Network recovery followed by flush() call.
/// **REQUIREMENT**: flush() should automatically trigger process_queue().
/// **ASSESSMENT**: SOUND - flush() calls process_queue() internally.
#[test]
fn audit_automatic_resumption_via_flush() {
    println!("🔍 AUDIT: OTLP automatic session resumption via flush()");

    let partition_exporter = PartitionSimulatorExporter::new();
    let queue_capacity = 5;
    let batch_timeout = Duration::from_millis(50);

    let exporter = LoadSheddingTraceExporter::new(
        Box::new(partition_exporter.clone()),
        queue_capacity,
        batch_timeout,
    );

    println!("📋 Automatic resumption scenario:");
    println!("   Simulate partition → queue spans → recover → flush()");

    // Start with partition
    partition_exporter.simulate_partition();

    // Queue spans during partition
    for batch_id in 1..=3 {
        let batch = SpanBatch {
            batch_id,
            spans: vec![OtlpSpan {
                span_id: format!("auto-span-{}", batch_id),
                name: "auto-resumption-test".to_string(),
                start_time_unix_nano: 1000000,
                end_time_unix_nano: 2000000,
                attributes: vec![("auto".to_string(), "true".to_string())],
                trace_flags: Some(0x01),
            }],
            created_at: Instant::now(),
        };

        exporter
            .export(&batch)
            .expect("Export should queue during partition");
    }

    let before_recovery = exporter.load_shedding_stats();
    println!("   Queued batches: {}", before_recovery.queue_depth);

    // Recover network
    partition_exporter.simulate_recovery();

    // Call flush() - should automatically trigger session resumption
    exporter.flush().expect("Flush should succeed");

    let after_flush = exporter.load_shedding_stats();
    println!("📊 Automatic resumption via flush():");
    println!("   Queue depth after flush: {}", after_flush.queue_depth);
    println!(
        "   Successful exports: {}",
        partition_exporter.successful_exports()
    );

    // Verify flush() automatically resumed the session
    assert_eq!(
        after_flush.queue_depth, 0,
        "flush() should automatically drain queue"
    );
    assert_eq!(
        partition_exporter.successful_exports(),
        3,
        "flush() should export all queued batches"
    );

    println!("✅ AUTOMATIC RESUMPTION: SOUND");
    println!("   • flush() automatically calls process_queue()");
    println!("   • No manual intervention required for session resumption");
}

/// **AUDIT TEST**: Verify resumption preserves span ordering and data integrity.
///
/// **SCENARIO**: Complex spans with attributes during partition recovery.
/// **REQUIREMENT**: All span data preserved with correct ordering.
/// **ASSESSMENT**: SOUND - FIFO order maintained, attributes preserved.
#[test]
fn audit_resumption_data_integrity_and_ordering() {
    println!("🔍 AUDIT: Session resumption data integrity and ordering");

    let partition_exporter = PartitionSimulatorExporter::new();
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(partition_exporter.clone()),
        10,
        Duration::from_millis(100),
    );

    // Start partition
    partition_exporter.simulate_partition();

    // Create batches with rich span data
    let expected_data = vec![
        (
            "service_auth",
            "user_login",
            vec![("user_id", "12345"), ("method", "oauth2")],
        ),
        (
            "service_db",
            "user_query",
            vec![("table", "users"), ("query_time_ms", "42")],
        ),
        (
            "service_cache",
            "cache_miss",
            vec![("key", "user:12345"), ("ttl", "300")],
        ),
    ];

    for (i, (_service, operation, attrs)) in expected_data.iter().enumerate() {
        let spans = vec![OtlpSpan {
            span_id: format!("integrity-span-{}", i),
            name: operation.to_string(),
            start_time_unix_nano: 1000000 + (i as u64 * 1000),
            end_time_unix_nano: 2000000 + (i as u64 * 1000),
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            trace_flags: Some(0x01),
        }];

        let batch = SpanBatch {
            batch_id: i as u64 + 1,
            spans,
            created_at: Instant::now(),
        };

        exporter
            .export(&batch)
            .expect("Export should queue during partition");
    }

    // Recover and process
    partition_exporter.simulate_recovery();
    exporter.process_queue().expect("Resumption should succeed");

    let exported = partition_exporter.exported_batches();
    println!("📊 Data integrity verification:");
    println!("   Exported batches: {}", exported.len());

    // Verify ordering preserved
    for (i, batch) in exported.iter().enumerate() {
        assert_eq!(
            batch.batch_id,
            (i + 1) as u64,
            "FIFO order should be preserved"
        );

        let span = &batch.spans[0];
        let (_expected_service, expected_operation, expected_attrs) = &expected_data[i];

        assert_eq!(span.name, *expected_operation, "Span name preserved");
        assert_eq!(
            span.attributes.len(),
            expected_attrs.len(),
            "All attributes preserved"
        );

        for (expected_key, expected_value) in expected_attrs {
            let found = span
                .attributes
                .iter()
                .find(|(k, _)| k == expected_key)
                .map(|(_, v)| v.as_str());
            assert_eq!(
                found,
                Some(*expected_value),
                "Attribute {}={} should be preserved",
                expected_key,
                expected_value
            );
        }

        println!("   Batch {}: {} - ✓", batch.batch_id, span.name);
    }

    println!("✅ DATA INTEGRITY: SOUND");
    println!("   • FIFO ordering preserved during resumption");
    println!("   • All span attributes correctly preserved");
    println!("   • No data corruption during queue storage");
}
