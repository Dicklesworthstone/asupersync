#!/usr/bin/env rust-script
//! Targeted profiling benchmark for scheduler, cx, and channel hotspots
//!
//! This benchmark specifically targets the functions identified in:
//! - src/runtime/scheduler/ (scheduling primitives, wake path)
//! - src/cx/ (capability context building)
//! - src/channel/ (two-phase operations)

use std::time::Instant;
use std::hint::black_box;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::thread;
use std::collections::VecDeque;

fn main() {
    println!("=== Targeted Scheduler/Cx/Channel Profiling Benchmark ===");
    println!("Focus areas: scheduler wake path, cx building, channel ops");

    let iterations = 500_000; // Smaller for detailed profiling

    println!("\n1. Scheduler Wake Path Simulation (post-yvmiat optimization)");
    let start = Instant::now();
    for i in 0..iterations {
        black_box(simulate_optimized_wake_path(black_box(i)));
    }
    let wake_time = start.elapsed();
    println!("   Optimized wake path: {:.2} µs/op", wake_time.as_micros() as f64 / iterations as f64);

    println!("\n2. Context Building Simulation (build_child_task_cx pattern)");
    let start = Instant::now();
    for i in 0..iterations {
        black_box(simulate_cx_building(black_box(i)));
    }
    let cx_time = start.elapsed();
    println!("   Cx building: {:.2} µs/op", cx_time.as_micros() as f64 / iterations as f64);

    println!("\n3. Channel Two-Phase Operations");
    let start = Instant::now();
    for i in 0..iterations {
        black_box(simulate_two_phase_channel(black_box(i)));
    }
    let channel_time = start.elapsed();
    println!("   Two-phase ops: {:.2} µs/op", channel_time.as_micros() as f64 / iterations as f64);

    println!("\n4. Multi-threaded Scheduler Contention");
    let start = Instant::now();
    simulate_scheduler_contention();
    let contention_time = start.elapsed();
    println!("   Scheduler contention: {:?} total", contention_time);

    // Generate relative hotspot percentages
    let total_time = wake_time + cx_time + channel_time + contention_time;
    println!("\n=== HOTSPOT ANALYSIS ===");
    println!("Wake path: {:.1}%", (wake_time.as_nanos() as f64 / total_time.as_nanos() as f64) * 100.0);
    println!("Cx building: {:.1}%", (cx_time.as_nanos() as f64 / total_time.as_nanos() as f64) * 100.0);
    println!("Channel ops: {:.1}%", (channel_time.as_nanos() as f64 / total_time.as_nanos() as f64) * 100.0);
    println!("Contention: {:.1}%", (contention_time.as_nanos() as f64 / total_time.as_nanos() as f64) * 100.0);
}

/// Simulate the post-yvmiat optimized wake path (single lock vs double lock)
fn simulate_optimized_wake_path(task_id: usize) -> bool {
    use std::collections::HashSet;

    // Simulates the optimized schedule_local_push without arena validation
    let mut presence = HashSet::new();
    let mut queue = VecDeque::new();

    if presence.insert(task_id) {
        queue.push_back(task_id);
        true
    } else {
        false
    }
}

/// Simulate build_child_task_cx Arc cloning pattern
fn simulate_cx_building(seed: usize) -> Vec<Arc<usize>> {
    // Simulates 8-12 Arc clones for capability context building
    let io_driver = Arc::new(seed);
    let timer_driver = Arc::new(seed + 1);
    let logical_clock = Arc::new(seed + 2);
    let observability = Arc::new(seed + 3);

    vec![
        io_driver.clone(),
        timer_driver.clone(),
        logical_clock.clone(),
        observability.clone(),
        io_driver.clone(), // Additional clones seen in build_child_task_cx
        timer_driver.clone(),
        logical_clock.clone(),
        observability.clone(),
    ]
}

/// Simulate two-phase channel reserve/send pattern
fn simulate_two_phase_channel(value: usize) -> Option<usize> {
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();

    // Simulate reserve phase (would be async in real code)
    if value % 7 != 0 {  // Simulate occasional backpressure
        // Simulate send phase
        tx.send(value).ok()?;
        rx.recv().ok()
    } else {
        None
    }
}

/// Multi-threaded scheduler contention simulation
fn simulate_scheduler_contention() {
    let shared_queue = Arc::new(std::sync::Mutex::new(VecDeque::<usize>::new()));
    let counter = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..4).map(|worker_id| {
        let queue = shared_queue.clone();
        let counter = counter.clone();

        thread::spawn(move || {
            for i in 0..10_000 {
                // Simulate scheduler operations
                let work_id = worker_id * 10_000 + i;

                // Push work
                {
                    let mut q = queue.lock().unwrap();
                    q.push_back(work_id);
                }

                // Pop work
                {
                    let mut q = queue.lock().unwrap();
                    if let Some(_work) = q.pop_front() {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                }

                if i % 1000 == 0 {
                    thread::yield_now(); // Simulate scheduler yields
                }
            }
        })
    }).collect();

    for handle in handles {
        handle.join().unwrap();
    }

    println!("   Processed {} work items", counter.load(Ordering::Relaxed));
}