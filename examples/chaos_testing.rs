//! Chaos Testing Example for Asupersync
//!
//! This example demonstrates how to use chaos injection to stress-test async code
//! for resilience to failures, delays, and adverse conditions.
//!
//! # What is Chaos Testing?
//!
//! Chaos testing involves deliberately injecting faults into a system to verify
//! that it handles failures correctly. The key insight is that bugs often hide
//! in error handling paths that rarely execute in production.
//!
//! Asupersync's chaos mode injects:
//! - Random cancellations at poll points
//! - Artificial delays to simulate slow operations
//! - Budget exhaustion to test resource limit handling
//! - Spurious wakeups to test waker correctness
//!
//! # Determinism
//!
//! A critical feature: given the same seed, chaos injection produces identical
//! results. This means when a test fails, you can reproduce it exactly:
//!
//! ```text
//! Test failed with seed 12345. Re-run with same seed to reproduce.
//! ```
//!
//! # Running This Example
//!
//! ```bash
//! cargo run --example chaos_testing
//! ```

use asupersync::lab::chaos::ChaosConfig;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// A future that yields N times before completing.
/// Useful for giving chaos more opportunities to inject faults.
struct YieldN {
    remaining: u32,
}

impl Future for YieldN {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.remaining == 0 {
            Poll::Ready(())
        } else {
            self.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

async fn yield_times(n: u32) {
    YieldN { remaining: n }.await
}

fn main() {
    println!("=== Asupersync Chaos Testing Example ===\n");

    // Example 1: Light chaos for CI (fast, low-probability faults)
    example_light_chaos();

    // Example 2: Heavy chaos for thorough testing
    example_heavy_chaos();

    // Example 3: Deterministic reproduction
    example_deterministic_chaos();

    // Example 4: Custom chaos configuration
    example_custom_chaos();

    // Example 5: Verifying chaos stats
    example_chaos_stats();

    println!("\n=== All examples completed successfully! ===");
}

/// Light chaos is suitable for CI pipelines.
/// Low probabilities catch obvious issues without excessive flakiness.
fn example_light_chaos() {
    println!("--- Example 1: Light Chaos (CI-friendly) ---");

    let config = LabConfig::new(42).with_light_chaos();
    let mut runtime = LabRuntime::new(config);

    assert!(runtime.has_chaos(), "Chaos should be enabled");

    let region = runtime.state.create_root_region(Budget::INFINITE);
    let completed = Arc::new(AtomicU32::new(0));
    let completed_clone = completed.clone();

    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            // Simulate some work with multiple yield points
            yield_times(50).await;
            completed_clone.fetch_add(1, Ordering::SeqCst);
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let stats = runtime.chaos_stats();
    println!("  Decision points: {}", stats.decision_points);
    println!("  Delays injected: {}", stats.delays);
    println!("  Total delay: {:?}", stats.total_delay);
    println!(
        "  Task completed: {}\n",
        completed.load(Ordering::SeqCst) > 0
    );
}

/// Heavy chaos for thorough testing.
/// Higher probabilities stress-test error handling paths.
fn example_heavy_chaos() {
    println!("--- Example 2: Heavy Chaos (Thorough Testing) ---");

    let config = LabConfig::new(999).with_heavy_chaos();
    let mut runtime = LabRuntime::new(config);

    let region = runtime.state.create_root_region(Budget::INFINITE);

    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {
            yield_times(20).await;
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let stats = runtime.chaos_stats();
    println!("  Decision points: {}", stats.decision_points);
    println!("  Cancellations: {}", stats.cancellations);
    println!("  Delays: {}", stats.delays);
    println!("  Budget exhaustions: {}", stats.budget_exhaustions);
    println!(
        "  Wakeup storms: {} ({} wakeups)\n",
        stats.wakeup_storms, stats.spurious_wakeups
    );
}

/// Demonstrates deterministic chaos reproduction.
/// Same seed = same chaos sequence = reproducible failures.
fn example_deterministic_chaos() {
    println!("--- Example 3: Deterministic Reproduction ---");

    let chaos = ChaosConfig::new(12345)
        .with_delay_probability(0.3)
        .with_delay_range(Duration::ZERO..Duration::from_micros(100));

    // Run 1
    let config1 = LabConfig::new(12345).with_chaos(chaos.clone());
    let mut runtime1 = LabRuntime::new(config1);
    let region1 = runtime1.state.create_root_region(Budget::INFINITE);
    let (task_id1, _) = runtime1
        .state
        .create_task(region1, Budget::INFINITE, async { yield_times(30).await })
        .expect("create task");
    runtime1.scheduler.lock().unwrap().schedule(task_id1, 0);
    let steps1 = runtime1.run_until_quiescent();
    let stats1 = runtime1.chaos_stats();

    // Run 2 with same seed
    let config2 = LabConfig::new(12345).with_chaos(chaos);
    let mut runtime2 = LabRuntime::new(config2);
    let region2 = runtime2.state.create_root_region(Budget::INFINITE);
    let (task_id2, _) = runtime2
        .state
        .create_task(region2, Budget::INFINITE, async { yield_times(30).await })
        .expect("create task");
    runtime2.scheduler.lock().unwrap().schedule(task_id2, 0);
    let steps2 = runtime2.run_until_quiescent();
    let stats2 = runtime2.chaos_stats();

    println!(
        "  Run 1: {} steps, {} delays, {:?} total delay",
        steps1, stats1.delays, stats1.total_delay
    );
    println!(
        "  Run 2: {} steps, {} delays, {:?} total delay",
        steps2, stats2.delays, stats2.total_delay
    );
    println!(
        "  Identical: {}\n",
        steps1 == steps2 && stats1.delays == stats2.delays
    );
}

/// Custom chaos configuration for specific scenarios.
fn example_custom_chaos() {
    println!("--- Example 4: Custom Chaos Configuration ---");

    // Delay-focused testing (no cancellations)
    let delay_only = ChaosConfig::new(42)
        .with_cancel_probability(0.0) // No cancellations
        .with_delay_probability(0.5) // 50% delay
        .with_delay_range(Duration::from_micros(1)..Duration::from_micros(100))
        .with_budget_exhaust_probability(0.0)
        .with_wakeup_storm_probability(0.0);

    let config = LabConfig::new(42).with_chaos(delay_only);
    let mut runtime = LabRuntime::new(config);

    let region = runtime.state.create_root_region(Budget::INFINITE);
    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async { yield_times(100).await })
        .expect("create task");
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let stats = runtime.chaos_stats();
    println!("  Delay-only config:");
    println!("    Cancellations: {} (should be 0)", stats.cancellations);
    println!("    Delays: {} (should be ~50)", stats.delays);
    println!(
        "    Budget exhaustions: {} (should be 0)\n",
        stats.budget_exhaustions
    );
}

/// Verifying chaos injection via statistics.
fn example_chaos_stats() {
    println!("--- Example 5: Chaos Statistics ---");

    let chaos = ChaosConfig::light();
    let config = LabConfig::new(42).with_chaos(chaos);
    let mut runtime = LabRuntime::new(config);

    let region = runtime.state.create_root_region(Budget::INFINITE);
    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async { yield_times(1000).await })
        .expect("create task");
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let stats = runtime.chaos_stats();

    println!("  Chaos Statistics Summary:");
    println!("    Total decision points: {}", stats.decision_points);
    println!("    Injection rate: {:.2}%", stats.injection_rate() * 100.0);
    println!("    Breakdown:");
    println!("      - Cancellations: {}", stats.cancellations);
    println!("      - Delays: {} ({:?})", stats.delays, stats.total_delay);
    println!("      - Budget exhaustions: {}", stats.budget_exhaustions);
    println!(
        "      - Wakeup storms: {} ({} wakeups)",
        stats.wakeup_storms, stats.spurious_wakeups
    );
}
