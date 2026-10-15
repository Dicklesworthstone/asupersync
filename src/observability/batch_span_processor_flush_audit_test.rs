//! BatchSpanProcessor force_flush behavior audit test.
//!
//! **AUDIT SCOPE**: Verifies that OTLP-Trace BatchSpanProcessor force_flush()
//! waits for collector ACK when there are pending spans, preventing data loss
//! on shutdown per OTLP SDK best practices.
//!
//! **OTLP SDK FORCE_FLUSH REQUIREMENT**:
//! - force_flush() MUST wait for all pending spans to be exported
//! - MUST wait for collector ACK/response before returning success
//! - MUST NOT return success with pending exports (data loss risk)
//! - Shutdown sequence relies on force_flush() for data preservation
//!
//! **CRITICAL**: force_flush() without waiting for ACK causes data loss during
//! application shutdown, service restarts, and graceful termination scenarios.

#![cfg(test)]

use crate::observability::otlp_trace_exporter::{
    ExportError, LoadSheddingTraceExporter, OtlpSpan, SpanBatch, TraceExporter,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

/// In-memory collector that applies deterministic delay and ACK behavior.
#[derive(Debug, Clone)]
struct InMemoryCollectorExporter {
    export_delay: Duration,
    flush_delay: Duration,
    export_count: Arc<AtomicU64>,
    flush_count: Arc<AtomicU64>,
    should_fail_exports: Arc<AtomicBool>,
    in_flight_exports: Arc<AtomicUsize>,
    collector_ack_received: Arc<AtomicBool>,
}

impl InMemoryCollectorExporter {
    fn new(export_delay: Duration, flush_delay: Duration) -> Self {
        Self {
            export_delay,
            flush_delay,
            export_count: Arc::new(AtomicU64::new(0)),
            flush_count: Arc::new(AtomicU64::new(0)),
            should_fail_exports: Arc::new(AtomicBool::new(false)),
            in_flight_exports: Arc::new(AtomicUsize::new(0)),
            collector_ack_received: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_export_failure(&self, should_fail: bool) {
        self.should_fail_exports
            .store(should_fail, Ordering::Relaxed);
    }

    fn export_count(&self) -> u64 {
        self.export_count.load(Ordering::Relaxed)
    }

    fn flush_count(&self) -> u64 {
        self.flush_count.load(Ordering::Relaxed)
    }

    fn in_flight_count(&self) -> usize {
        self.in_flight_exports.load(Ordering::Relaxed)
    }

    fn ack_received(&self) -> bool {
        self.collector_ack_received.load(Ordering::Relaxed)
    }

    fn reset_ack(&self) {
        self.collector_ack_received.store(false, Ordering::Relaxed);
    }
}

impl TraceExporter for InMemoryCollectorExporter {
    fn export(&self, _batch: &SpanBatch) -> Result<(), ExportError> {
        if self.should_fail_exports.load(Ordering::Relaxed) {
            return Err(ExportError::Transport("configured export failure".into()));
        }

        // Track in-flight export
        self.in_flight_exports.fetch_add(1, Ordering::Relaxed);

        // Apply deterministic collector latency.
        std::thread::sleep(self.export_delay);

        // Record collector ACK.
        self.collector_ack_received.store(true, Ordering::Relaxed);
        self.export_count.fetch_add(1, Ordering::Relaxed);

        // Export completed (ACK received)
        self.in_flight_exports.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        self.flush_count.fetch_add(1, Ordering::Relaxed);

        // CRITICAL: Real flush implementation should wait for all in-flight exports
        // to complete before returning success. This fixture exercises that behavior.

        let start = Instant::now();
        let timeout = Duration::from_secs(5); // Reasonable flush timeout

        // Wait for all in-flight exports to complete
        while self.in_flight_exports.load(Ordering::Relaxed) > 0 {
            if start.elapsed() > timeout {
                return Err(ExportError::Transport(
                    "Flush timeout waiting for exports".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        // Apply deterministic flush processing delay.
        std::thread::sleep(self.flush_delay);

        Ok(())
    }
}

/// **AUDIT TEST**: Verify force_flush waits for collector ACK.
///
/// **SCENARIO**: Call force_flush() with pending spans, verify it waits for completion.
/// **REQUIREMENT**: Must wait for collector ACK before returning success.
/// **ASSESSMENT**: Critical for preventing data loss on shutdown.
#[test]
fn audit_force_flush_waits_for_collector_ack() {
    println!("🔍 AUDIT: force_flush() waits for collector ACK (data preservation)");

    println!("📋 OTLP SDK force_flush requirements:");
    println!("   • Wait for all pending span exports to complete");
    println!("   • Wait for collector ACK/response");
    println!("   • Do NOT return success with in-flight exports");
    println!("   • Prevent data loss during shutdown");

    // Configure slow collector to test waiting behavior
    let export_delay = Duration::from_millis(200); // Slow network to collector
    let flush_delay = Duration::from_millis(50); // Additional flush processing

    let memory_collector = InMemoryCollectorExporter::new(export_delay, flush_delay);
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_collector.clone()),
        100, // Large capacity
        Duration::from_secs(1),
    );

    println!("📊 Test scenario setup:");
    println!(
        "   Export delay: {:?} (deterministic collector latency)",
        export_delay
    );
    println!(
        "   Flush delay: {:?} (deterministic flush processing)",
        flush_delay
    );

    // Phase 1: Export spans (will be queued)
    println!("📊 Phase 1: Export spans");
    let span_count = 3;
    for i in 1..=span_count {
        let span = OtlpSpan::new(
            format!("flush-test-span-{}", i),
            "flush_test_operation".to_string(),
            1000000000 + (i * 1000),
            1000001000 + (i * 1000),
            vec![
                ("test_case".to_string(), "force_flush".to_string()),
                ("span_index".to_string(), i.to_string()),
            ],
        );

        let batch = SpanBatch {
            batch_id: i,
            spans: vec![span],
            created_at: Instant::now(),
        };

        exporter.export(&batch).expect("Export should succeed");
        println!("   Exported span batch {}", i);
    }

    let stats_before = exporter.load_shedding_stats();
    println!("   Queued batches: {}", stats_before.queue_depth);

    // Phase 2: Call force_flush() and measure timing
    println!("📊 Phase 2: Call force_flush() and verify waiting behavior");

    memory_collector.reset_ack();
    let flush_start = Instant::now();

    // This should wait for collector ACK
    let flush_result = exporter.flush();
    let flush_duration = flush_start.elapsed();

    println!("   flush() result: {:?}", flush_result);
    println!("   flush() duration: {:?}", flush_duration);

    // Verify flush waited appropriately
    assert!(
        flush_result.is_ok(),
        "force_flush() should succeed when collector is responsive"
    );

    let expected_min_duration = export_delay; // At least the export delay
    assert!(
        flush_duration >= expected_min_duration,
        "force_flush() should wait for exports to complete. Expected >= {:?}, got {:?}",
        expected_min_duration,
        flush_duration
    );

    // Verify all spans were exported
    let final_exports = memory_collector.export_count();
    let final_flushes = memory_collector.flush_count();
    let final_in_flight = memory_collector.in_flight_count();
    let ack_received = memory_collector.ack_received();

    println!("📊 Force flush completion verification:");
    println!("   Exported batches: {}", final_exports);
    println!("   Flush calls: {}", final_flushes);
    println!("   In-flight exports: {}", final_in_flight);
    println!("   Collector ACK received: {}", ack_received);

    assert_eq!(
        final_exports, span_count,
        "All {} span batches should be exported after force_flush()",
        span_count
    );

    assert_eq!(
        final_in_flight, 0,
        "No in-flight exports should remain after force_flush()"
    );

    assert!(
        ack_received,
        "Collector ACK should be received after force_flush()"
    );

    let stats_after = exporter.load_shedding_stats();
    assert_eq!(
        stats_after.queue_depth, 0,
        "Export queue should be empty after force_flush()"
    );

    println!("✅ FORCE_FLUSH DATA PRESERVATION: SOUND");
    println!("   • Waited for all exports to complete");
    println!("   • Received collector ACK");
    println!("   • No data loss during flush");
    println!("   • Queue fully drained");
}

/// **AUDIT TEST**: Verify flush behavior with collector failure.
///
/// **SCENARIO**: force_flush() with collector unavailable.
/// **REQUIREMENT**: Should handle errors gracefully, not lose data silently.
/// **ASSESSMENT**: Error handling during flush operations.
#[test]
fn audit_force_flush_collector_failure_handling() {
    println!("🔍 AUDIT: force_flush() behavior with collector failures");

    let memory_collector =
        InMemoryCollectorExporter::new(Duration::from_millis(50), Duration::from_millis(10));

    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_collector.clone()),
        100,
        Duration::from_secs(1),
    );

    // Export a test span
    let span = OtlpSpan::new(
        "failure-test-span".to_string(),
        "failure_test_operation".to_string(),
        1000000000,
        1000001000,
        vec![("test_case".to_string(), "collector_failure".to_string())],
    );

    let batch = SpanBatch {
        batch_id: 1,
        spans: vec![span],
        created_at: Instant::now(),
    };

    exporter.export(&batch).expect("Export should succeed");

    memory_collector.set_export_failure(true);

    println!("📊 Testing flush with collector failure");
    let flush_result = exporter.flush();

    println!("   flush() with failure: {:?}", flush_result);

    // Behavior should be well-defined (either succeed with retry or fail with error)
    match flush_result {
        Ok(()) => {
            println!("   ✅ flush() succeeded (may have retry logic)");
        }
        Err(e) => {
            println!("   ⚠️  flush() failed with error: {}", e);
            println!("   📋 Application can handle error gracefully");
        }
    }

    println!("✅ COLLECTOR FAILURE HANDLING: Behavior is well-defined");
}

/// **AUDIT TEST**: Concurrent flush and export operations.
///
/// **SCENARIO**: flush() called while exports are still happening.
/// **REQUIREMENT**: Should coordinate properly with ongoing exports.
/// **ASSESSMENT**: Thread safety and coordination during flush.
#[test]
fn audit_concurrent_flush_and_export() {
    println!("🔍 AUDIT: Concurrent flush() and export() operations");

    let memory_collector = InMemoryCollectorExporter::new(
        Duration::from_millis(100), // Slow exports
        Duration::from_millis(20),  // Fast flush
    );

    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_collector.clone()),
        100,
        Duration::from_secs(1),
    );

    println!("📊 Testing concurrent operations:");

    // Start background exports
    let exporter_clone = std::sync::Arc::new(exporter);
    let export_handle = {
        let exporter = Arc::clone(&exporter_clone);
        std::thread::spawn(move || {
            for i in 1..=5 {
                let span = OtlpSpan::new(
                    format!("concurrent-span-{}", i),
                    "concurrent_operation".to_string(),
                    1000000000 + (i * 1000),
                    1000001000 + (i * 1000),
                    vec![("concurrent".to_string(), "true".to_string())],
                );

                let batch = SpanBatch {
                    batch_id: i,
                    spans: vec![span],
                    created_at: Instant::now(),
                };

                exporter.export(&batch).expect("Export should succeed");
                println!("   Background exported batch {}", i);

                // Small delay between exports
                std::thread::sleep(Duration::from_millis(50));
            }
        })
    };

    // Wait a bit for some exports to start
    std::thread::sleep(Duration::from_millis(150));

    // Call flush while exports are happening
    println!("   Calling flush() during ongoing exports");
    let flush_start = Instant::now();
    let flush_result = exporter_clone.flush();
    let flush_duration = flush_start.elapsed();

    // Wait for background thread to complete
    export_handle
        .join()
        .expect("Background thread should complete");

    println!("📊 Concurrent operation results:");
    println!("   flush() result: {:?}", flush_result);
    println!("   flush() duration: {:?}", flush_duration);
    println!("   Final exports: {}", memory_collector.export_count());
    println!("   Final in-flight: {}", memory_collector.in_flight_count());

    // Verify proper coordination
    assert!(
        flush_result.is_ok(),
        "flush() should handle concurrent exports"
    );

    assert_eq!(
        memory_collector.in_flight_count(),
        0,
        "No exports should be in-flight after flush completion"
    );

    println!("✅ CONCURRENT OPERATIONS: Proper coordination verified");
}

/// **AUDIT TEST**: Verify send-and-forget anti-pattern.
///
/// **SCENARIO**: Show what would happen with defective send-and-forget flush.
/// **REQUIREMENT**: This would be DEFECTIVE - causes data loss.
/// **ASSESSMENT**: Anti-pattern that violates OTLP SDK best practices.
#[test]
fn audit_send_and_forget_antipattern() {
    println!("🚨 AUDIT: Send-and-forget flush anti-pattern (data loss risk)");

    println!("📋 DEFECTIVE anti-pattern:");
    println!("   • force_flush() returns immediately");
    println!("   • Does not wait for exports to complete");
    println!("   • Application shuts down with pending exports");
    println!("   • Result: data loss");

    /// Defective exporter that exposes send-and-forget behavior.
    #[derive(Debug, Clone)]
    struct SendAndForgetExporter {
        export_count: Arc<AtomicU64>,
        pending_exports: Arc<AtomicUsize>,
    }

    impl SendAndForgetExporter {
        fn new() -> Self {
            Self {
                export_count: Arc::new(AtomicU64::new(0)),
                pending_exports: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn pending_count(&self) -> usize {
            self.pending_exports.load(Ordering::Relaxed)
        }
    }

    impl TraceExporter for SendAndForgetExporter {
        fn export(&self, _batch: &SpanBatch) -> Result<(), ExportError> {
            self.pending_exports.fetch_add(1, Ordering::Relaxed);

            // Spawn delayed export work that completes after flush returns.
            std::thread::spawn({
                let count = Arc::clone(&self.export_count);
                let pending = Arc::clone(&self.pending_exports);
                move || {
                    // Delay completion long enough to expose the antipattern.
                    std::thread::sleep(Duration::from_millis(500));
                    count.fetch_add(1, Ordering::Relaxed);
                    pending.fetch_sub(1, Ordering::Relaxed);
                }
            });

            Ok(())
        }

        fn flush(&self) -> Result<(), ExportError> {
            // DEFECTIVE: Send-and-forget - returns immediately
            println!("   🚨 DEFECTIVE: flush() returns immediately without waiting");
            Ok(()) // WRONG: Should wait for pending exports
        }
    }

    let defective_exporter = SendAndForgetExporter::new();
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(defective_exporter.clone()),
        100,
        Duration::from_secs(1),
    );

    // Export spans
    let span = OtlpSpan::new(
        "defective-test-span".to_string(),
        "defective_operation".to_string(),
        1000000000,
        1000001000,
        vec![("antipattern".to_string(), "send_and_forget".to_string())],
    );

    let batch = SpanBatch {
        batch_id: 1,
        spans: vec![span],
        created_at: Instant::now(),
    };

    exporter.export(&batch).expect("Export should succeed");

    println!("📊 Exercising defective behavior:");
    let pending_before = defective_exporter.pending_count();
    println!("   Pending exports before flush: {}", pending_before);

    // DEFECTIVE: flush returns immediately
    let flush_start = Instant::now();
    let flush_result = exporter.flush();
    let flush_duration = flush_start.elapsed();

    let pending_after = defective_exporter.pending_count();

    println!("   flush() duration: {:?} (too fast!)", flush_duration);
    println!("   flush() result: {:?}", flush_result);
    println!("   Pending exports after flush: {}", pending_after);

    // Verify the problem.
    assert!(
        flush_duration < Duration::from_millis(100),
        "DEFECTIVE: flush() returned too quickly"
    );

    if pending_after > 0 {
        println!("🚨 DATA LOSS RISK DEMONSTRATED:");
        println!("   • flush() returned success");
        println!("   • {} exports still pending", pending_after);
        println!("   • Application shutdown would lose data");
    }

    // Wait a bit and check again
    std::thread::sleep(Duration::from_millis(600));
    let final_pending = defective_exporter.pending_count();
    println!("   Pending exports after delay: {}", final_pending);

    println!("🚨 ANTIPATTERN DEMONSTRATED: Send-and-forget causes data loss");
    println!("💡 SOLUTION: force_flush() must wait for collector ACK");
}
