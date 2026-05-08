//! IO capability budget accounting profiling harness.
//!
//! Profiles the atomic counter hot path in IoCap budget accounting.
//! Expected bottleneck: AtomicU64 operations under high contention.
//!
//! Usage:
//! cargo build --profile release-perf --bin io_cap_budget_profile --features test-internals
//! samply record --save-only -o io_cap_cpu.json -- ./target/release-perf/io_cap_budget_profile

use asupersync::io::cap::LabIoCap;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

fn main() {
    println!("IO Capability Budget Accounting Profiling");

    // High-contention scenario: many threads hitting budget accounting simultaneously
    let threads = 8;
    let ops_per_thread = 1_000_000;
    let total_ops = threads * ops_per_thread;

    println!(
        "Scenario: {} threads × {} ops = {} total operations",
        threads, ops_per_thread, total_ops
    );

    // Shared IoCap for contention
    let io_cap = Arc::new(LabIoCap::new_for_tests());

    println!("=== PROFILING TARGET: ATOMIC BUDGET ACCOUNTING ===");
    let start = Instant::now();

    // Spawn threads to simulate high I/O operation contention
    let handles: Vec<_> = (0..threads)
        .map(|thread_id| {
            let cap = Arc::clone(&io_cap);
            thread::spawn(move || {
                // Simulate typical I/O operation pattern: submit → complete
                for i in 0..ops_per_thread {
                    // Hot path 1: record_submit() -> AtomicU64::fetch_add
                    cap.record_submit();

                    // Hot path 2: record_complete() -> AtomicU64::fetch_add
                    cap.record_complete();

                    // Hot path 3: stats() reading for budget checks (every 100 ops)
                    if i % 100 == 0 {
                        let _stats = cap.stats(); // AtomicU64::load operations
                    }
                }

                println!(
                    "Thread {} completed {} I/O operations",
                    thread_id, ops_per_thread
                );
            })
        })
        .collect();

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = start.elapsed();
    let total_atomic_ops = total_ops * 2 + (total_ops / 100) * 2; // submit + complete + stats reads

    println!(
        "*** BUDGET ACCOUNTING COMPLETED: {:.1}s ***",
        elapsed.as_secs_f64()
    );
    println!("Total atomic operations: {}", total_atomic_ops);
    println!(
        "Throughput: {:.1} atomic ops/sec",
        total_atomic_ops as f64 / elapsed.as_secs_f64()
    );
    println!(
        "Latency: {:.1} ns/op",
        elapsed.as_nanos() as f64 / total_atomic_ops as f64
    );

    // Verify correctness
    let final_stats = io_cap.stats();
    println!(
        "Final stats: submitted={}, completed={}",
        final_stats.submitted, final_stats.completed
    );

    if final_stats.submitted != total_ops as u64 || final_stats.completed != total_ops as u64 {
        panic!(
            "Incorrect accounting! Expected {}, got submit={} complete={}",
            total_ops, final_stats.submitted, final_stats.completed
        );
    }

    println!("✓ Budget accounting correctness verified");
}
