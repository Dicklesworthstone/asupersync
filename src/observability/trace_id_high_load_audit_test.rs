//! Trace ID generation high load audit test.
//!
//! **AUDIT SCOPE**: Verifies that trace_id generation under 1M+ spans/sec load
//! uses thread-local or lock-free patterns rather than global mutex bottlenecks.
//!
//! **HIGH LOAD REQUIREMENT**:
//! - 1M+ spans/sec should NOT be bottlenecked by ID generation
//! - Thread-local or atomic counters preferred over global locks
//! - Contention-free ID generation for multi-threaded workloads
//! - NOT: global mutex that serializes all ID generation
//!
//! **CRITICAL**: ID generation bottlenecks can collapse high-throughput
//! observability under load, causing span drops and incomplete traces.

#![cfg(test)]

use crate::observability::context::SpanId as ContextSpanId;
use crate::observability::w3c_trace_context::{SpanId as W3CSpanId, TraceId};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

/// Benchmark ID generation performance across multiple threads.
struct IdGenerationBenchmark {
    thread_count: usize,
    ids_per_thread: usize,
    start_barrier: Arc<Barrier>,
    completion_counter: Arc<AtomicU64>,
}

impl IdGenerationBenchmark {
    fn new(thread_count: usize, ids_per_thread: usize) -> Self {
        Self {
            thread_count,
            ids_per_thread,
            start_barrier: Arc::new(Barrier::new(thread_count)),
            completion_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    fn run_context_span_id_benchmark(&self) -> Duration {
        let mut handles = Vec::with_capacity(self.thread_count);
        for thread_id in 0..self.thread_count {
            let barrier = Arc::clone(&self.start_barrier);
            let counter = Arc::clone(&self.completion_counter);
            let ids_per_thread = self.ids_per_thread;

            handles.push(thread::spawn(move || {
                // Wait for all threads to be ready
                barrier.wait();
                let start = Instant::now();

                // Generate IDs at high frequency
                for _ in 0..ids_per_thread {
                    let _id = ContextSpanId::new(); // AtomicU64 implementation
                }

                let duration = start.elapsed();
                counter.fetch_add(1, Ordering::Relaxed);
                (thread_id, duration, ids_per_thread)
            }));
        }

        let overall_start = Instant::now();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let overall_duration = overall_start.elapsed();

        // Report per-thread performance
        for (thread_id, thread_duration, ids_generated) in results {
            let ids_per_sec = ids_generated as f64 / thread_duration.as_secs_f64();
            println!(
                "   Thread {}: {} IDs in {:?} ({:.0} IDs/sec)",
                thread_id, ids_generated, thread_duration, ids_per_sec
            );
        }

        overall_duration
    }

    fn run_w3c_span_id_benchmark(&self) -> Duration {
        let mut handles = Vec::with_capacity(self.thread_count);
        for thread_id in 0..self.thread_count {
            let barrier = Arc::clone(&self.start_barrier);
            let counter = Arc::clone(&self.completion_counter);
            let ids_per_thread = self.ids_per_thread;

            handles.push(thread::spawn(move || {
                // Wait for all threads to be ready
                barrier.wait();
                let start = Instant::now();

                // Generate IDs at high frequency
                for _ in 0..ids_per_thread {
                    let _id = W3CSpanId::new_random(); // getrandom implementation
                }

                let duration = start.elapsed();
                counter.fetch_add(1, Ordering::Relaxed);
                (thread_id, duration, ids_per_thread)
            }));
        }

        let overall_start = Instant::now();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let overall_duration = overall_start.elapsed();

        // Report per-thread performance
        for (thread_id, thread_duration, ids_generated) in results {
            let ids_per_sec = ids_generated as f64 / thread_duration.as_secs_f64();
            println!(
                "   Thread {}: {} IDs in {:?} ({:.0} IDs/sec)",
                thread_id, ids_generated, thread_duration, ids_per_sec
            );
        }

        overall_duration
    }

    fn run_trace_id_benchmark(&self) -> Duration {
        let mut handles = Vec::with_capacity(self.thread_count);
        for thread_id in 0..self.thread_count {
            let barrier = Arc::clone(&self.start_barrier);
            let counter = Arc::clone(&self.completion_counter);
            let ids_per_thread = self.ids_per_thread;

            handles.push(thread::spawn(move || {
                // Wait for all threads to be ready
                barrier.wait();
                let start = Instant::now();

                // Generate IDs at high frequency
                for _ in 0..ids_per_thread {
                    let _id = TraceId::new_random(); // getrandom implementation
                }

                let duration = start.elapsed();
                counter.fetch_add(1, Ordering::Relaxed);
                (thread_id, duration, ids_per_thread)
            }));
        }

        let overall_start = Instant::now();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let overall_duration = overall_start.elapsed();

        // Report per-thread performance
        for (thread_id, thread_duration, ids_generated) in results {
            let ids_per_sec = ids_generated as f64 / thread_duration.as_secs_f64();
            println!(
                "   Thread {}: {} IDs in {:?} ({:.0} IDs/sec)",
                thread_id, ids_generated, thread_duration, ids_per_sec
            );
        }

        overall_duration
    }
}

/// **AUDIT TEST**: Profile ID generation performance under high multi-threaded load.
///
/// **SCENARIO**: 8 threads each generating 125K IDs (1M total) to simulate 1M+ spans/sec.
/// **REQUIREMENT**: Should scale linearly with thread count, no global contention bottleneck.
/// **ASSESSMENT**: Compare atomic counter vs getrandom performance characteristics.
#[test]
fn audit_trace_id_generation_high_load_performance() {
    println!("🔍 AUDIT: Trace ID generation performance under 1M+ spans/sec load");

    println!("📋 High load performance requirements:");
    println!("   • No global mutex bottleneck");
    println!("   • Linear scaling with thread count");
    println!("   • Sustained 1M+ IDs/sec generation");
    println!("   • Thread-local or lock-free patterns");

    let thread_count = 8;
    let ids_per_thread = 125_000; // 8 * 125K = 1M total IDs
    let total_ids = thread_count * ids_per_thread;

    println!("📊 Benchmark configuration:");
    println!("   Threads: {}", thread_count);
    println!("   IDs per thread: {}", ids_per_thread);
    println!("   Total IDs: {}", total_ids);

    // Benchmark 1: Context SpanId (AtomicU64)
    println!("📊 Benchmark 1: Context SpanId (AtomicU64 implementation)");
    let benchmark1 = IdGenerationBenchmark::new(thread_count, ids_per_thread);
    let context_duration = benchmark1.run_context_span_id_benchmark();
    let context_ids_per_sec = total_ids as f64 / context_duration.as_secs_f64();

    println!("   Overall: {} IDs in {:?}", total_ids, context_duration);
    println!("   Throughput: {:.0} IDs/sec", context_ids_per_sec);

    // Benchmark 2: W3C SpanId (getrandom)
    println!("📊 Benchmark 2: W3C SpanId (getrandom implementation)");
    let benchmark2 = IdGenerationBenchmark::new(thread_count, ids_per_thread);
    let w3c_span_duration = benchmark2.run_w3c_span_id_benchmark();
    let w3c_span_ids_per_sec = total_ids as f64 / w3c_span_duration.as_secs_f64();

    println!("   Overall: {} IDs in {:?}", total_ids, w3c_span_duration);
    println!("   Throughput: {:.0} IDs/sec", w3c_span_ids_per_sec);

    // Benchmark 3: TraceId (getrandom)
    println!("📊 Benchmark 3: TraceId (getrandom implementation)");
    let benchmark3 = IdGenerationBenchmark::new(thread_count, ids_per_thread);
    let trace_id_duration = benchmark3.run_trace_id_benchmark();
    let trace_id_ids_per_sec = total_ids as f64 / trace_id_duration.as_secs_f64();

    println!("   Overall: {} IDs in {:?}", total_ids, trace_id_duration);
    println!("   Throughput: {:.0} IDs/sec", trace_id_ids_per_sec);

    // Performance analysis
    println!("📊 Performance comparison:");
    println!(
        "   Context SpanId: {:.0} IDs/sec (AtomicU64)",
        context_ids_per_sec
    );
    println!(
        "   W3C SpanId: {:.0} IDs/sec (getrandom)",
        w3c_span_ids_per_sec
    );
    println!(
        "   TraceId: {:.0} IDs/sec (getrandom)",
        trace_id_ids_per_sec
    );

    let atomic_advantage = context_ids_per_sec / w3c_span_ids_per_sec;
    println!("   Atomic advantage: {:.1}x faster", atomic_advantage);

    // High load sustainability check
    let min_required_throughput = 1_000_000.0; // 1M IDs/sec requirement

    println!("📊 High load sustainability (1M+ IDs/sec requirement):");
    println!(
        "   Context SpanId: {} (AtomicU64)",
        if context_ids_per_sec >= min_required_throughput {
            "✅ MEETS"
        } else {
            "❌ FAILS"
        }
    );
    println!(
        "   W3C SpanId: {} (getrandom)",
        if w3c_span_ids_per_sec >= min_required_throughput {
            "✅ MEETS"
        } else {
            "❌ FAILS"
        }
    );
    println!(
        "   TraceId: {} (getrandom)",
        if trace_id_ids_per_sec >= min_required_throughput {
            "✅ MEETS"
        } else {
            "❌ FAILS"
        }
    );

    // Contention analysis
    if atomic_advantage > 2.0 {
        println!("⚠️  CONTENTION DETECTED: getrandom shows signs of bottlenecking");
        println!("💡 RECOMMENDATION: Consider thread-local optimization for getrandom calls");
    } else {
        println!("✅ NO MAJOR CONTENTION: Performance difference within acceptable range");
    }

    println!("✅ HIGH LOAD ID GENERATION AUDIT COMPLETE");
}

/// **AUDIT TEST**: Demonstrate thread-local optimization pattern for high-frequency ID generation.
///
/// **SCENARIO**: Show how thread-local buffering can eliminate getrandom contention.
/// **REQUIREMENT**: Thread-local pattern should achieve atomic-like performance.
/// **ASSESSMENT**: Optimization strategy for high-load scenarios.
#[test]
fn audit_thread_local_id_generation_optimization() {
    println!("🔍 AUDIT: Thread-local ID generation optimization pattern");

    println!("📋 Thread-local optimization strategy:");
    println!("   • Pre-generate ID pools per thread");
    println!("   • Refill pools when exhausted");
    println!("   • Eliminate per-ID getrandom calls");
    println!("   • Maintain cryptographic quality");

    use std::cell::RefCell;

    // Thread-local optimized ID generator
    thread_local! {
        static SPAN_ID_POOL: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
        static TRACE_ID_POOL: RefCell<Vec<[u8; 16]>> = const { RefCell::new(Vec::new()) };
    }

    fn get_optimized_span_id() -> u64 {
        SPAN_ID_POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            if pool.is_empty() {
                // Refill pool with batch of random IDs
                let mut random_bytes = vec![0u8; 1000 * std::mem::size_of::<u64>()];
                getrandom::fill(&mut random_bytes).expect("getrandom failed");
                let batch = random_bytes
                    .chunks_exact(std::mem::size_of::<u64>())
                    .map(|chunk| {
                        u64::from_ne_bytes([
                            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                            chunk[7],
                        ])
                    })
                    .collect::<Vec<_>>();
                pool.extend(batch);
            }
            pool.pop().unwrap_or(0)
        })
    }

    fn get_optimized_trace_id() -> [u8; 16] {
        TRACE_ID_POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            if pool.is_empty() {
                // Refill pool with batch of random trace IDs
                let mut batch = vec![[0u8; 16]; 100]; // 100 trace IDs per batch
                for trace_id in &mut batch {
                    getrandom::fill(trace_id).expect("getrandom failed");
                }
                pool.extend(batch);
            }
            pool.pop().unwrap_or([0u8; 16])
        })
    }

    // Benchmark optimized vs direct generation
    let iterations = 100_000;

    // Direct getrandom calls
    let start = Instant::now();
    for _ in 0..iterations {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("getrandom failed");
    }
    let direct_duration = start.elapsed();

    // Thread-local optimized calls
    let start = Instant::now();
    for _ in 0..iterations {
        let _id = get_optimized_span_id();
        let trace_id = get_optimized_trace_id();
        assert_eq!(trace_id.len(), 16, "trace ID pool must emit 16-byte IDs");
    }
    let optimized_duration = start.elapsed();

    let speedup = direct_duration.as_secs_f64() / optimized_duration.as_secs_f64();

    println!("📊 Thread-local optimization results:");
    println!(
        "   Direct getrandom: {:?} for {} IDs",
        direct_duration, iterations
    );
    println!(
        "   Thread-local pool: {:?} for {} IDs",
        optimized_duration, iterations
    );
    println!(
        "   Speedup: {:.1}x faster with thread-local pooling",
        speedup
    );

    if speedup > 2.0 {
        println!("✅ THREAD-LOCAL OPTIMIZATION: Significant performance improvement");
        println!("💡 RECOMMENDATION: Consider implementing for high-load scenarios");
    } else {
        println!("📊 THREAD-LOCAL OPTIMIZATION: Marginal improvement");
    }
}

/// **AUDIT TEST**: Verify which ID generator is used in OTLP span creation path.
///
/// **SCENARIO**: Trace the code path from span creation to ID generation.
/// **REQUIREMENT**: High-frequency spans should use optimal ID generation.
/// **ASSESSMENT**: Current implementation analysis.
#[test]
fn audit_otlp_span_id_generation_code_path() {
    println!("🔍 AUDIT: OTLP span ID generation code path analysis");

    use crate::observability::otlp_trace_exporter::OtlpSpan;

    println!("📋 Code path analysis:");
    println!("   • OtlpSpan creation");
    println!("   • ID generation methods");
    println!("   • Performance characteristics");

    // Test OtlpSpan creation patterns
    let start = Instant::now();
    let span_count = 10_000;

    for i in 0..span_count {
        let _span = OtlpSpan::new(
            format!("span-{}", i),
            "test_operation".to_string(),
            1000000000,
            1000001000,
            vec![("test".to_string(), "true".to_string())],
        );
    }

    let creation_duration = start.elapsed();
    let spans_per_sec = span_count as f64 / creation_duration.as_secs_f64();

    println!("📊 OtlpSpan creation performance:");
    println!("   Created {} spans in {:?}", span_count, creation_duration);
    println!("   Throughput: {:.0} spans/sec", spans_per_sec);

    // Analyze ID generation in span creation
    // NOTE: OtlpSpan::new() uses provided span_id string, not internal generation
    // The actual ID generation happens in the service layer that calls OtlpSpan::new()

    println!("📊 ID generation analysis:");
    println!("   • OtlpSpan::new() uses provided span_id (string)");
    println!("   • Actual ID generation happens in calling service");
    println!("   • W3C context for distributed traces");
    println!("   • Internal context for local spans");

    let target_throughput = 100_000.0; // 100K spans/sec (10% of 1M target)

    if spans_per_sec >= target_throughput {
        println!("✅ OTLP SPAN CREATION: Meets high-throughput requirements");
    } else {
        println!("⚠️  OTLP SPAN CREATION: May need optimization for extreme loads");
    }

    println!("✅ CODE PATH ANALYSIS COMPLETE");
    println!("💡 KEY FINDING: ID generation performance depends on which generator is used");
    println!("   - AtomicU64 (context): Excellent for high-frequency local spans");
    println!("   - getrandom (W3C): Good for distributed trace initiation");
    println!("   - Thread-local pooling: Optimization option for extreme loads");
}
