//! OTLP-Trace exporter high-volume export latency audit.
//!
//! **Audit Question**: Under high-volume export (100K spans/sec), what are the
//! export latency percentiles (p50/p99)? Does p99 stay under acceptable thresholds?
//!
//! **Performance Requirements**:
//! - Target Load: 100,000 spans/sec sustained export rate
//! - Latency SLA: p99 export latency < 50ms (excellent) or < 100ms (acceptable)
//! - Throughput SLA: No significant drops in sustained export rate under load
//!
//! **Expected Behavior**: Export latency should remain bounded under high volume,
//! with load shedding preventing unbounded queuing that would degrade latency.

#[cfg(test)]
mod tests {
    use crate::observability::otlp_trace_exporter::{
        InMemoryOtlpHttpExporter, LoadSheddingTraceExporter, OtlpSpan, SpanBatch, TraceExporter,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};
    use std::collections::BTreeMap;

    /// High-volume span export latency profiler.
    struct ExportLatencyProfiler {
        thread_count: usize,
        target_spans_per_sec: usize,
        test_duration_secs: u64,
        batch_size: usize,
        start_barrier: Arc<Barrier>,
        latency_measurements: Arc<parking_lot::Mutex<Vec<Duration>>>,
    }

    impl ExportLatencyProfiler {
        fn new(
            thread_count: usize,
            target_spans_per_sec: usize,
            test_duration_secs: u64,
            batch_size: usize,
        ) -> Self {
            Self {
                thread_count,
                target_spans_per_sec,
                test_duration_secs,
                batch_size,
                start_barrier: Arc::new(Barrier::new(thread_count)),
                latency_measurements: Arc::new(parking_lot::Mutex::new(Vec::new())),
            }
        }

        /// Execute high-volume export test and measure end-to-end latencies.
        fn run_export_latency_benchmark(
            &self,
            exporter: Arc<LoadSheddingTraceExporter>,
        ) -> LatencyBenchmarkResult {
            let spans_per_thread_per_sec = self.target_spans_per_sec / self.thread_count;
            let target_batches_per_sec = spans_per_thread_per_sec / self.batch_size;
            let inter_batch_delay = Duration::from_nanos(1_000_000_000 / target_batches_per_sec as u64);

            eprintln!("📊 Benchmark configuration:");
            eprintln!("  Target rate: {} spans/sec", self.target_spans_per_sec);
            eprintln!("  Test duration: {}s", self.test_duration_secs);
            eprintln!("  Threads: {}", self.thread_count);
            eprintln!("  Spans per thread/sec: {}", spans_per_thread_per_sec);
            eprintln!("  Batch size: {}", self.batch_size);
            eprintln!("  Inter-batch delay: {:?}", inter_batch_delay);

            let total_spans = Arc::new(AtomicU64::new(0));
            let total_exports = Arc::new(AtomicU64::new(0));

            let handles: Vec<_> = (0..self.thread_count)
                .map(|thread_id| {
                    let barrier = Arc::clone(&self.start_barrier);
                    let measurements = Arc::clone(&self.latency_measurements);
                    let exporter = Arc::clone(&exporter);
                    let total_spans = Arc::clone(&total_spans);
                    let total_exports = Arc::clone(&total_exports);
                    let test_duration = Duration::from_secs(self.test_duration_secs);
                    let batch_size = self.batch_size;

                    thread::spawn(move || {
                        // Wait for all threads to start simultaneously
                        barrier.wait();
                        let start_time = Instant::now();

                        let mut batch_id = 0u64;

                        while start_time.elapsed() < test_duration {
                            let batch_start = Instant::now();

                            // Create span batch
                            let spans: Vec<OtlpSpan> = (0..batch_size)
                                .map(|i| OtlpSpan {
                                    span_id: format!("span-{}-{}-{}", thread_id, batch_id, i),
                                    name: "high_volume_operation".to_string(),
                                    start_time_unix_nano: start_time.elapsed().as_nanos() as u64,
                                    end_time_unix_nano: (start_time.elapsed().as_nanos() + 1_000_000) as u64,
                                    attributes: vec![
                                        ("thread_id".to_string(), thread_id.to_string()),
                                        ("batch_id".to_string(), batch_id.to_string()),
                                        ("operation_type".to_string(), "latency_test".to_string()),
                                    ],
                                    trace_flags: Some(0x01), // Sampled
                                })
                                .collect();

                            let batch = SpanBatch {
                                batch_id,
                                spans,
                                created_at: batch_start,
                            };

                            // **CRITICAL MEASUREMENT**: Export latency from creation to completion
                            match exporter.export(&batch) {
                                Ok(()) => {
                                    let export_latency = batch_start.elapsed();
                                    measurements.lock().push(export_latency);
                                    total_spans.fetch_add(batch_size as u64, Ordering::Relaxed);
                                    total_exports.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    eprintln!("Export failed for thread {}: {}", thread_id, e);
                                }
                            }

                            batch_id += 1;

                            // Rate limiting: maintain target spans/sec
                            thread::sleep(inter_batch_delay);
                        }

                        (thread_id, batch_id)
                    })
                })
                .collect();

            let benchmark_start = Instant::now();
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            let benchmark_duration = benchmark_start.elapsed();

            let final_spans = total_spans.load(Ordering::Relaxed);
            let final_exports = total_exports.load(Ordering::Relaxed);

            eprintln!("📊 Raw benchmark results:");
            for (thread_id, batches) in results {
                eprintln!("  Thread {}: {} batches", thread_id, batches);
            }
            eprintln!("  Total spans: {}", final_spans);
            eprintln!("  Total exports: {}", final_exports);
            eprintln!("  Duration: {:?}", benchmark_duration);

            // Process latency measurements
            let latencies = self.latency_measurements.lock();
            let mut sorted_latencies = latencies.clone();
            sorted_latencies.sort();

            if sorted_latencies.is_empty() {
                panic!("No latency measurements collected");
            }

            let actual_throughput = final_spans as f64 / benchmark_duration.as_secs_f64();
            let percentiles = calculate_percentiles(&sorted_latencies);

            LatencyBenchmarkResult {
                total_spans: final_spans,
                total_exports: final_exports,
                benchmark_duration,
                actual_throughput,
                percentiles,
                latency_measurements: sorted_latencies,
            }
        }
    }

    /// Latency benchmark results with percentile analysis.
    #[derive(Debug)]
    struct LatencyBenchmarkResult {
        total_spans: u64,
        total_exports: u64,
        benchmark_duration: Duration,
        actual_throughput: f64,
        percentiles: LatencyPercentiles,
        latency_measurements: Vec<Duration>,
    }

    /// Export latency percentiles for SLA assessment.
    #[derive(Debug)]
    struct LatencyPercentiles {
        min: Duration,
        p50: Duration,
        p90: Duration,
        p95: Duration,
        p99: Duration,
        p99_9: Duration,
        max: Duration,
    }

    /// Calculate latency percentiles from sorted measurements.
    fn calculate_percentiles(sorted_latencies: &[Duration]) -> LatencyPercentiles {
        let len = sorted_latencies.len();
        if len == 0 {
            panic!("Cannot calculate percentiles from empty measurements");
        }

        let percentile_idx = |p: f64| -> usize {
            ((len as f64 - 1.0) * p / 100.0).round() as usize
        };

        LatencyPercentiles {
            min: sorted_latencies[0],
            p50: sorted_latencies[percentile_idx(50.0)],
            p90: sorted_latencies[percentile_idx(90.0)],
            p95: sorted_latencies[percentile_idx(95.0)],
            p99: sorted_latencies[percentile_idx(99.0)],
            p99_9: sorted_latencies[percentile_idx(99.9)],
            max: sorted_latencies[len - 1],
        }
    }

    /// Format duration in human-readable milliseconds.
    fn format_latency_ms(duration: Duration) -> String {
        format!("{:.2}ms", duration.as_secs_f64() * 1000.0)
    }

    #[test]
    fn otlp_high_volume_export_latency_audit() {
        eprintln!("\n🔍 OTLP HIGH-VOLUME EXPORT LATENCY AUDIT");
        eprintln!("========================================");

        eprintln!("\n📋 Performance SLA Requirements:");
        eprintln!("  • Target Load: 100,000 spans/sec sustained export");
        eprintln!("  • Excellent Latency SLA: p99 < 50ms");
        eprintln!("  • Acceptable Latency SLA: p99 < 100ms");
        eprintln!("  • Critical Threshold: p99 > 100ms (performance issue)");
        eprintln!("  • Load Shedding: Should prevent unbounded latency growth");

        // Test configuration for 100K spans/sec
        let thread_count = 8;
        let target_spans_per_sec = 100_000;
        let test_duration_secs = 10; // 10 second test for sustained load
        let batch_size = 100; // Typical OTLP batch size

        let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_micros(50));
        let queue_capacity = 500; // Reasonable queue for high throughput
        let batch_timeout = Duration::from_millis(100);

        let exporter = Arc::new(LoadSheddingTraceExporter::new(
            Box::new(memory_exporter.clone()),
            queue_capacity,
            batch_timeout,
        ));

        eprintln!("\n🎯 HIGH-VOLUME EXPORT LATENCY TEST");
        eprintln!("==================================");

        // Execute high-volume benchmark
        let profiler = ExportLatencyProfiler::new(
            thread_count,
            target_spans_per_sec,
            test_duration_secs,
            batch_size,
        );

        let result = profiler.run_export_latency_benchmark(Arc::clone(&exporter));

        // Report throughput results
        eprintln!("\n📊 THROUGHPUT ANALYSIS:");
        eprintln!("  Target: {} spans/sec", target_spans_per_sec);
        eprintln!("  Actual: {:.0} spans/sec", result.actual_throughput);
        eprintln!("  Total spans: {}", result.total_spans);
        eprintln!("  Total exports: {}", result.total_exports);
        eprintln!("  Test duration: {:?}", result.benchmark_duration);

        let throughput_ratio = result.actual_throughput / target_spans_per_sec as f64;
        eprintln!("  Throughput ratio: {:.1}%", throughput_ratio * 100.0);

        if throughput_ratio < 0.9 {
            eprintln!("  ⚠️  THROUGHPUT BELOW TARGET: {:.1}% of 100K spans/sec", throughput_ratio * 100.0);
        } else {
            eprintln!("  ✅ THROUGHPUT TARGET MET: {:.1}% of 100K spans/sec", throughput_ratio * 100.0);
        }

        // Report latency percentiles
        eprintln!("\n📊 EXPORT LATENCY PERCENTILES:");
        eprintln!("  Min:  {}", format_latency_ms(result.percentiles.min));
        eprintln!("  p50:  {}", format_latency_ms(result.percentiles.p50));
        eprintln!("  p90:  {}", format_latency_ms(result.percentiles.p90));
        eprintln!("  p95:  {}", format_latency_ms(result.percentiles.p95));
        eprintln!("  p99:  {}", format_latency_ms(result.percentiles.p99));
        eprintln!("  p99.9: {}", format_latency_ms(result.percentiles.p99_9));
        eprintln!("  Max:  {}", format_latency_ms(result.percentiles.max));
        eprintln!("  Measurements: {} samples", result.latency_measurements.len());

        // **CRITICAL SLA ASSESSMENT**
        eprintln!("\n🎯 LATENCY SLA ASSESSMENT:");

        let p50_ms = result.percentiles.p50.as_secs_f64() * 1000.0;
        let p99_ms = result.percentiles.p99.as_secs_f64() * 1000.0;

        eprintln!("  p50 latency: {:.2}ms", p50_ms);
        eprintln!("  p99 latency: {:.2}ms", p99_ms);

        // SLA evaluation logic
        if p99_ms <= 50.0 {
            eprintln!("  ✅ EXCELLENT: p99 ≤ 50ms - performance is excellent");
            eprintln!("  📌 ACTION: Pin behavior with audit test to prevent regression");
        } else if p99_ms <= 100.0 {
            eprintln!("  ✅ ACCEPTABLE: p99 ≤ 100ms - performance meets SLA");
            eprintln!("  📌 ACTION: Pin behavior with audit test and monitor for improvement");
        } else {
            eprintln!("  ❌ CRITICAL: p99 > 100ms - performance issue detected");
            eprintln!("  📌 ACTION: File performance bead for optimization work");
        }

        if p50_ms > 25.0 {
            eprintln!("  ⚠️  p50 > 25ms - median latency elevated");
        } else {
            eprintln!("  ✅ p50 ≤ 25ms - median latency good");
        }

        // Load shedding analysis
        let stats = exporter.load_shedding_stats();
        eprintln!("\n📊 LOAD SHEDDING ANALYSIS:");
        eprintln!("  Queue capacity: {}", stats.queue_capacity);
        eprintln!("  Queue depth: {}", stats.queue_depth);
        eprintln!("  Dropped batches: {}", stats.dropped_batches);
        eprintln!("  Dropped spans: {}", exporter.dropped_spans_count());

        if stats.dropped_batches > 0 {
            let drop_rate = stats.dropped_batches as f64 / result.total_exports as f64;
            eprintln!("  Drop rate: {:.2}% of batches", drop_rate * 100.0);

            if drop_rate > 0.1 {
                eprintln!("  ⚠️  HIGH DROP RATE: > 10% - queue capacity may be insufficient");
            } else {
                eprintln!("  ✅ ACCEPTABLE DROP RATE: < 10% - load shedding working correctly");
            }
        } else {
            eprintln!("  ✅ NO DROPS: Queue capacity sufficient for test load");
        }

        // **PERFORMANCE VERDICT**
        eprintln!("\n🏁 HIGH-VOLUME EXPORT AUDIT CONCLUSION:");
        eprintln!("======================================");

        if p99_ms <= 50.0 && throughput_ratio >= 0.9 {
            eprintln!("✅ EXCELLENT PERFORMANCE:");
            eprintln!("  • p99 latency: {:.2}ms ≤ 50ms", p99_ms);
            eprintln!("  • Throughput: {:.0} spans/sec ≥ 90K", result.actual_throughput);
            eprintln!("  • Status: Performance excellent, pin behavior");
        } else if p99_ms <= 100.0 && throughput_ratio >= 0.8 {
            eprintln!("✅ ACCEPTABLE PERFORMANCE:");
            eprintln!("  • p99 latency: {:.2}ms ≤ 100ms", p99_ms);
            eprintln!("  • Throughput: {:.0} spans/sec ≥ 80K", result.actual_throughput);
            eprintln!("  • Status: Meets SLA, monitor for improvement");
        } else {
            eprintln!("❌ PERFORMANCE ISSUE DETECTED:");
            eprintln!("  • p99 latency: {:.2}ms", p99_ms);
            eprintln!("  • Throughput: {:.0} spans/sec", result.actual_throughput);
            eprintln!("  • Status: Performance bead required");
        }

        eprintln!("📊 Export mechanism: LoadSheddingTraceExporter");
        eprintln!("📊 Queue implementation: BoundedExportQueue (ArrayQueue)");
        eprintln!("📊 Load shedding: Oldest-drop policy");

        // **SLA ASSERTION** - this determines test outcome
        if p99_ms > 100.0 {
            // User requested: if p99 > 100ms, file perf bead (handled by test failure)
            panic!("PERFORMANCE BEAD REQUIRED: p99 latency {:.2}ms exceeds 100ms SLA threshold", p99_ms);
        }

        if p99_ms <= 50.0 {
            eprintln!("\n🎯 BEHAVIOR PINNED: p99 ≤ 50ms - excellent performance confirmed");
        } else {
            eprintln!("\n🎯 BEHAVIOR PINNED: p99 ≤ 100ms - acceptable performance confirmed");
        }

        // Assertions for test validation
        assert!(result.total_spans > 0, "Should have exported spans");
        assert!(result.total_exports > 0, "Should have completed exports");
        assert!(result.actual_throughput > 50_000.0, "Should achieve at least 50K spans/sec");
        assert!(p99_ms <= 100.0, "p99 latency must not exceed 100ms SLA");
        assert!(p50_ms <= 50.0, "p50 latency should be reasonable");

        eprintln!("✅ HIGH-VOLUME EXPORT LATENCY AUDIT COMPLETE");
    }

    /// Verify latency distribution characteristics under sustained load.
    #[test]
    fn audit_sustained_load_latency_distribution() {
        eprintln!("\n🔍 SUSTAINED LOAD LATENCY DISTRIBUTION AUDIT");
        eprintln!("===========================================");

        eprintln!("📋 Latency distribution characteristics test:");
        eprintln!("  • Verify latency stability over time");
        eprintln!("  • Check for latency spikes under sustained 100K spans/sec");
        eprintln!("  • Analyze tail latency behavior");
        eprintln!("  • Validate load shedding prevents latency explosion");

        let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_micros(100));
        let exporter = Arc::new(LoadSheddingTraceExporter::new(
            Box::new(memory_exporter.clone()),
            200, // Smaller queue to trigger load shedding
            Duration::from_millis(50),
        ));

        // Extended test for sustained load
        let profiler = ExportLatencyProfiler::new(
            4,      // threads
            80_000, // spans/sec (high but sustainable)
            15,     // 15 second sustained test
            50,     // batch size
        );

        let result = profiler.run_export_latency_benchmark(Arc::clone(&exporter));

        eprintln!("\n📊 SUSTAINED LOAD RESULTS:");
        eprintln!("  Duration: {:?}", result.benchmark_duration);
        eprintln!("  Spans exported: {}", result.total_spans);
        eprintln!("  Throughput: {:.0} spans/sec", result.actual_throughput);

        // Analyze latency distribution
        eprintln!("\n📊 LATENCY DISTRIBUTION ANALYSIS:");
        let p_values = [50.0, 90.0, 95.0, 99.0, 99.9];
        let percentiles = [
            result.percentiles.p50,
            result.percentiles.p90,
            result.percentiles.p95,
            result.percentiles.p99,
            result.percentiles.p99_9,
        ];

        for (p, latency) in p_values.iter().zip(percentiles.iter()) {
            eprintln!("  p{}: {}", p, format_latency_ms(*latency));
        }

        // Check for latency stability (tail shouldn't be too far from median)
        let tail_ratio = result.percentiles.p99.as_secs_f64() / result.percentiles.p50.as_secs_f64();
        eprintln!("\n📊 LATENCY STABILITY:");
        eprintln!("  p99/p50 ratio: {:.1}x", tail_ratio);

        if tail_ratio > 10.0 {
            eprintln!("  ⚠️  HIGH TAIL LATENCY: p99 is {}x p50 (may indicate queueing issues)", tail_ratio);
        } else if tail_ratio > 5.0 {
            eprintln!("  ⚠️  MODERATE TAIL: p99 is {}x p50 (acceptable but monitor)", tail_ratio);
        } else {
            eprintln!("  ✅ STABLE LATENCY: p99/p50 ratio good ({}x)", tail_ratio);
        }

        // Check load shedding effectiveness
        let stats = exporter.load_shedding_stats();
        eprintln!("\n📊 LOAD SHEDDING EFFECTIVENESS:");
        eprintln!("  Queue utilization: {}/{} ({:.1}%)",
            stats.queue_depth,
            stats.queue_capacity,
            (stats.queue_depth as f64 / stats.queue_capacity as f64) * 100.0
        );

        if stats.dropped_batches > 0 {
            eprintln!("  Dropped batches: {}", stats.dropped_batches);
            eprintln!("  ✅ LOAD SHEDDING ACTIVE: Preventing queue overflow");

            // With load shedding, p99 should still be bounded
            let p99_ms = result.percentiles.p99.as_secs_f64() * 1000.0;
            assert!(p99_ms < 200.0, "Even with load shedding, p99 should be bounded: {:.2}ms", p99_ms);
        } else {
            eprintln!("  ✅ NO DROPS NEEDED: Queue capacity sufficient");
        }

        // Validate sustained performance
        assert!(result.actual_throughput > 60_000.0, "Should sustain at least 60K spans/sec");
        assert!(result.percentiles.p99.as_millis() < 150, "p99 should be under 150ms even under sustained load");

        eprintln!("✅ SUSTAINED LOAD LATENCY DISTRIBUTION AUDIT COMPLETE");
    }

    /// Profile export latency vs queue depth relationship.
    #[test]
    fn audit_queue_depth_latency_relationship() {
        eprintln!("\n🔍 QUEUE DEPTH vs LATENCY RELATIONSHIP AUDIT");
        eprintln!("===========================================");

        eprintln!("📋 Queue depth impact on export latency:");
        eprintln!("  • Test various queue capacities");
        eprintln!("  • Measure latency vs queue utilization");
        eprintln!("  • Identify optimal queue sizing");

        let queue_capacities = vec![50, 100, 200, 500];
        let mut results = Vec::new();

        for capacity in queue_capacities {
            eprintln!("\n📊 Testing queue capacity: {}", capacity);

            let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_micros(75));
            let exporter = Arc::new(LoadSheddingTraceExporter::new(
                Box::new(memory_exporter.clone()),
                capacity,
                Duration::from_millis(100),
            ));

            // Short high-intensity test
            let profiler = ExportLatencyProfiler::new(
                6,      // threads
                60_000, // spans/sec
                5,      // 5 second test
                40,     // batch size
            );

            let result = profiler.run_export_latency_benchmark(Arc::clone(&exporter));
            let stats = exporter.load_shedding_stats();

            let p50_ms = result.percentiles.p50.as_secs_f64() * 1000.0;
            let p99_ms = result.percentiles.p99.as_secs_f64() * 1000.0;
            let drop_rate = stats.dropped_batches as f64 / result.total_exports as f64;

            eprintln!("  Results:");
            eprintln!("    p50: {:.1}ms, p99: {:.1}ms", p50_ms, p99_ms);
            eprintln!("    Drop rate: {:.1}%", drop_rate * 100.0);
            eprintln!("    Queue utilization: {:.1}%",
                (stats.queue_depth as f64 / capacity as f64) * 100.0);

            results.push((capacity, p50_ms, p99_ms, drop_rate));
        }

        eprintln!("\n📊 QUEUE CAPACITY ANALYSIS SUMMARY:");
        eprintln!("  Capacity | p50 (ms) | p99 (ms) | Drop Rate");
        eprintln!("  ---------|----------|----------|----------");

        for (capacity, p50, p99, drop_rate) in &results {
            eprintln!("  {:8} | {:8.1} | {:8.1} | {:8.1}%",
                capacity, p50, p99, drop_rate * 100.0);
        }

        // Find optimal configuration
        eprintln!("\n📊 OPTIMAL CONFIGURATION ANALYSIS:");
        let optimal = results.iter()
            .filter(|(_, _, p99, drop_rate)| *p99 <= 100.0 && *drop_rate <= 0.05)
            .min_by(|(_, _, a_p99, _), (_, _, b_p99, _)| a_p99.partial_cmp(b_p99).unwrap());

        if let Some((capacity, p50, p99, drop_rate)) = optimal {
            eprintln!("  ✅ OPTIMAL: Capacity {} (p50: {:.1}ms, p99: {:.1}ms, drops: {:.1}%)",
                capacity, p50, p99, drop_rate * 100.0);
        } else {
            eprintln!("  ⚠️  NO OPTIMAL FOUND: All configurations exceed latency or drop rate targets");
        }

        eprintln!("✅ QUEUE DEPTH vs LATENCY AUDIT COMPLETE");
    }
}
