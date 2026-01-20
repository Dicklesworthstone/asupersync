#[macro_use]
mod common;

use asupersync::lab::LabConfig;
use asupersync::lab::LabRuntime;
use asupersync::types::Budget;
use common::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

async fn yield_now() {
    YieldNow { yielded: false }.await
}

#[test]
fn test_lab_executor_runs_task() {
    init_test("test_lab_executor_runs_task");
    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());

    // 1. Create root region
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // 2. Create task
    let executed = Arc::new(AtomicBool::new(false));
    let executed_clone = executed.clone();

    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            executed_clone.store(true, Ordering::SeqCst);
        })
        .expect("create task");

    test_section!("schedule");
    // 3. Schedule the task (RuntimeState.create_task doesn't schedule)
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);

    // 4. Run until quiescent
    let steps = runtime.run_until_quiescent();

    test_section!("verify");
    assert_with_log!(
        steps > 0,
        "should have executed at least one step",
        "> 0",
        steps
    );
    let executed_value = executed.load(Ordering::SeqCst);
    assert_with_log!(
        executed_value,
        "task should have executed",
        true,
        executed_value
    );

    // Verify task is done using public API
    let live_tasks = runtime.state.live_task_count();
    assert_with_log!(
        live_tasks == 0,
        "no live tasks should remain",
        0,
        live_tasks
    );
    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "runtime should be quiescent", true, quiescent);
    test_complete!("test_lab_executor_runs_task");
}

#[test]
fn test_lab_executor_wakes_task_yielding() {
    init_test("test_lab_executor_wakes_task_yielding");
    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let counter = Arc::new(AtomicBool::new(false));
    let counter_clone = counter.clone();

    // Create a task that yields once then sets flag
    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            // yield once
            yield_now().await;
            counter_clone.store(true, Ordering::SeqCst);
        })
        .expect("create task");

    test_section!("schedule");
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let completed = counter.load(Ordering::SeqCst);
    assert_with_log!(
        completed,
        "task should have completed after yield",
        true,
        completed
    );
    test_complete!("test_lab_executor_wakes_task_yielding");
}

// ─────────────────────────────────────────────────────────────────────────────
// Chaos Injection Tests
// ─────────────────────────────────────────────────────────────────────────────

use asupersync::lab::chaos::ChaosConfig;
use std::sync::atomic::AtomicU32;
use std::time::Duration;

/// Helper that yields multiple times to give chaos more chances to inject.
async fn yield_many(count: u32) {
    for _ in 0..count {
        yield_now().await;
    }
}

#[test]
fn test_chaos_config_integration() {
    init_test("test_chaos_config_integration");
    test_section!("setup");
    // Verify that chaos can be enabled on LabConfig
    let config = LabConfig::new(42).with_light_chaos();
    let has_chaos = config.has_chaos();
    assert_with_log!(
        has_chaos,
        "config should have chaos enabled",
        true,
        has_chaos
    );

    let runtime = LabRuntime::new(config);
    let runtime_has_chaos = runtime.has_chaos();
    assert_with_log!(
        runtime_has_chaos,
        "runtime should have chaos enabled",
        true,
        runtime_has_chaos
    );
    test_complete!("test_chaos_config_integration");
}

#[test]
fn test_chaos_stats_tracking() {
    init_test("test_chaos_stats_tracking");
    test_section!("setup");
    // Use high chaos probabilities to ensure some injections occur
    let chaos_config = ChaosConfig::new(12345)
        .with_delay_probability(0.5)
        .with_delay_range(Duration::ZERO..Duration::from_micros(1));

    let config = LabConfig::new(12345).with_chaos(chaos_config);
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Create a task that yields many times to give chaos chances to inject
    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {
            yield_many(100).await;
        })
        .expect("create task");

    test_section!("schedule");
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);

    test_section!("run");
    runtime.run_until_quiescent();

    // Check that stats were tracked
    test_section!("verify");
    let stats = runtime.chaos_stats();
    assert_with_log!(
        stats.decision_points > 0,
        "should have made chaos decisions",
        "> 0",
        stats.decision_points
    );
    // With 50% delay probability and 100 yields, we should see some delays
    assert_with_log!(
        stats.delays > 0,
        "should have injected some delays",
        "> 0",
        stats.delays
    );
    test_complete!("test_chaos_stats_tracking");
}

#[test]
fn test_chaos_determinism() {
    init_test("test_chaos_determinism");
    test_section!("setup");
    // Same seed should produce identical chaos sequences
    let chaos_config = ChaosConfig::new(42)
        .with_delay_probability(0.3)
        .with_delay_range(Duration::ZERO..Duration::from_micros(10));

    // First run
    let config1 = LabConfig::new(42).with_chaos(chaos_config.clone());
    let mut runtime1 = LabRuntime::new(config1);
    let region1 = runtime1.state.create_root_region(Budget::INFINITE);

    let poll_count1 = Arc::new(AtomicU32::new(0));
    let poll_count1_clone = poll_count1.clone();

    let (task_id1, _) = runtime1
        .state
        .create_task(region1, Budget::INFINITE, async move {
            for _ in 0..50 {
                poll_count1_clone.fetch_add(1, Ordering::SeqCst);
                yield_now().await;
            }
        })
        .expect("create task");

    runtime1.scheduler.lock().unwrap().schedule(task_id1, 0);
    let steps1 = runtime1.run_until_quiescent();
    let stats1 = runtime1.chaos_stats().clone();

    // Second run with same config
    let config2 = LabConfig::new(42).with_chaos(chaos_config);
    let mut runtime2 = LabRuntime::new(config2);
    let region2 = runtime2.state.create_root_region(Budget::INFINITE);

    let poll_count2 = Arc::new(AtomicU32::new(0));
    let poll_count2_clone = poll_count2.clone();

    let (task_id2, _) = runtime2
        .state
        .create_task(region2, Budget::INFINITE, async move {
            for _ in 0..50 {
                poll_count2_clone.fetch_add(1, Ordering::SeqCst);
                yield_now().await;
            }
        })
        .expect("create task");

    runtime2.scheduler.lock().unwrap().schedule(task_id2, 0);
    let steps2 = runtime2.run_until_quiescent();
    let stats2 = runtime2.chaos_stats().clone();

    // Verify determinism
    test_section!("verify");
    assert_with_log!(
        steps1 == steps2,
        "same seed should produce same number of steps",
        steps1,
        steps2
    );
    assert_with_log!(
        stats1.delays == stats2.delays,
        "same seed should produce same number of delays",
        stats1.delays,
        stats2.delays
    );
    assert_with_log!(
        stats1.total_delay == stats2.total_delay,
        "same seed should produce same total delay",
        stats1.total_delay,
        stats2.total_delay
    );
    let poll_count1_value = poll_count1.load(Ordering::SeqCst);
    let poll_count2_value = poll_count2.load(Ordering::SeqCst);
    assert_with_log!(
        poll_count1_value == poll_count2_value,
        "same seed should produce same poll counts",
        poll_count1_value,
        poll_count2_value
    );
    test_complete!("test_chaos_determinism");
}

#[test]
fn test_chaos_with_heavy_preset() {
    init_test("test_chaos_with_heavy_preset");
    test_section!("setup");
    // Test that heavy chaos preset works without panicking
    let config = LabConfig::new(999).with_heavy_chaos();
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            // Yield a few times
            yield_many(10).await;
            completed_clone.store(true, Ordering::SeqCst);
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);

    // Should complete despite chaos (or be cancelled by chaos)
    test_section!("run");
    runtime.run_until_quiescent();

    // Either completed or cancelled is fine - we just verify no panic
    let stats = runtime.chaos_stats();
    test_section!("verify");
    assert_with_log!(
        stats.decision_points > 0,
        "should have made some decisions",
        "> 0",
        stats.decision_points
    );
    test_complete!("test_chaos_with_heavy_preset");
}

#[test]
fn test_chaos_disabled_by_default() {
    init_test("test_chaos_disabled_by_default");
    test_section!("setup");
    let config = LabConfig::default();
    let config_has_chaos = config.has_chaos();
    assert_with_log!(
        !config_has_chaos,
        "default config should not have chaos",
        false,
        config_has_chaos
    );

    let runtime = LabRuntime::new(config);
    let runtime_has_chaos = runtime.has_chaos();
    assert_with_log!(
        !runtime_has_chaos,
        "default runtime should not have chaos",
        false,
        runtime_has_chaos
    );
    test_complete!("test_chaos_disabled_by_default");
}

#[test]
fn test_chaos_off_produces_no_injections() {
    init_test("test_chaos_off_produces_no_injections");
    test_section!("setup");
    // Explicitly disable chaos
    let chaos_config = ChaosConfig::off();
    let config = LabConfig::new(42).with_chaos(chaos_config);
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {
            yield_many(50).await;
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    test_section!("run");
    runtime.run_until_quiescent();

    let stats = runtime.chaos_stats();
    test_section!("verify");
    assert_with_log!(
        stats.cancellations == 0,
        "ChaosConfig::off should inject no cancellations",
        0,
        stats.cancellations
    );
    assert_with_log!(
        stats.delays == 0,
        "ChaosConfig::off should inject no delays",
        0,
        stats.delays
    );
    assert_with_log!(
        stats.budget_exhaustions == 0,
        "ChaosConfig::off should inject no budget exhaustions",
        0,
        stats.budget_exhaustions
    );
    assert_with_log!(
        stats.wakeup_storms == 0,
        "ChaosConfig::off should inject no wakeup storms",
        0,
        stats.wakeup_storms
    );
    test_complete!("test_chaos_off_produces_no_injections");
}
