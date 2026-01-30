#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::lab::assert_deterministic;
use asupersync::lab::LabConfig;
use asupersync::lab::LabRuntime;
use asupersync::runtime::{AdaptiveDeadlineConfig, DeadlineWarning, MonitorConfig, WarningReason};
use asupersync::types::{Budget, Time};
use common::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
    YieldNow { yielded: false }.await;
}

fn schedule_yielding_tasks(
    runtime: &mut LabRuntime,
    task_count: usize,
    yields_per_task: usize,
) -> Arc<Vec<AtomicUsize>> {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let completions: Arc<Vec<AtomicUsize>> = Arc::new(
        (0..task_count)
            .map(|_| AtomicUsize::new(0))
            .collect::<Vec<_>>(),
    );

    for idx in 0..task_count {
        let completions = Arc::clone(&completions);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                for _ in 0..yields_per_task {
                    yield_now().await;
                }
                completions[idx].fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    completions
}

fn run_and_collect_counts(
    runtime: &mut LabRuntime,
    task_count: usize,
    yields_per_task: usize,
) -> Vec<usize> {
    let completions = schedule_yielding_tasks(runtime, task_count, yields_per_task);
    runtime.run_until_quiescent();
    completions
        .iter()
        .map(|count| count.load(Ordering::SeqCst))
        .collect()
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
fn test_parallel_lab_completes_without_loss() {
    init_test("test_parallel_lab_completes_without_loss");
    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(1337).worker_count(4));
    let completions = schedule_yielding_tasks(&mut runtime, 31, 4);

    test_section!("run");
    let steps = runtime.run_until_quiescent();

    test_section!("verify");
    assert_with_log!(
        steps > 0,
        "should execute steps in parallel lab run",
        "> 0",
        steps
    );
    for count in completions.iter() {
        let value = count.load(Ordering::SeqCst);
        assert_with_log!(value == 1, "task completed exactly once", 1usize, value);
    }
    test_complete!("test_parallel_lab_completes_without_loss");
}

#[test]
fn test_parallel_lab_determinism_multiworker_yields() {
    init_test("test_parallel_lab_determinism_multiworker_yields");
    test_section!("setup");
    let config = LabConfig::new(2025).worker_count(4);

    test_section!("verify");
    assert_deterministic(config, |runtime| {
        let _ = schedule_yielding_tasks(runtime, 29, 3);
        runtime.run_until_quiescent();
    });

    test_complete!("test_parallel_lab_determinism_multiworker_yields");
}

#[test]
fn test_parallel_lab_equivalent_to_single_worker_outcomes() {
    init_test("test_parallel_lab_equivalent_to_single_worker_outcomes");
    test_section!("setup");
    let seed = 9001;
    let task_count = 37;
    let yields_per_task = 3;

    test_section!("single_worker");
    let mut single = LabRuntime::new(LabConfig::new(seed).worker_count(1));
    let single_counts = run_and_collect_counts(&mut single, task_count, yields_per_task);

    test_section!("multi_worker");
    let mut multi = LabRuntime::new(LabConfig::new(seed).worker_count(4));
    let multi_counts = run_and_collect_counts(&mut multi, task_count, yields_per_task);

    test_section!("verify");
    let single_ok = single_counts.iter().all(|count| *count == 1);
    let multi_ok = multi_counts.iter().all(|count| *count == 1);
    assert_with_log!(
        single_ok,
        "single-worker run should complete each task exactly once",
        true,
        single_ok
    );
    assert_with_log!(
        multi_ok,
        "multi-worker run should complete each task exactly once",
        true,
        multi_ok
    );
    assert_with_log!(
        single_counts == multi_counts,
        "single-worker and multi-worker runs should be outcome-equivalent",
        single_counts.len(),
        multi_counts.len()
    );
    test_complete!("test_parallel_lab_equivalent_to_single_worker_outcomes");
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

// ─────────────────────────────────────────────────────────────────────────────
// Deadline Monitoring Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_deadline_monitor_warns_on_approaching_deadline() {
    init_test("test_deadline_monitor_warns_on_approaching_deadline");
    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(42));

    let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
    let warnings_ref = warnings.clone();
    let config = MonitorConfig {
        check_interval: Duration::ZERO,
        warning_threshold_fraction: 0.2,
        checkpoint_timeout: Duration::from_secs(3600),
        adaptive: AdaptiveDeadlineConfig::default(),
        enabled: true,
    };
    runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
        warnings_ref.lock().unwrap().push(warning);
    });

    let region = runtime.state.create_root_region(Budget::INFINITE);
    let budget = Budget::new().with_deadline(Time::from_secs(100));
    let (task_id, _handle) = runtime
        .state
        .create_task(region, budget, async {
            let cx = Cx::current().expect("cx set");
            cx.checkpoint_with("progress").expect("checkpoint");
            yield_now().await;
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.advance_time_to(Time::from_secs(90));

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let recorded = warnings.lock().unwrap();
    assert_with_log!(
        recorded.len() == 1,
        "one warning emitted",
        1usize,
        recorded.len()
    );
    assert_with_log!(
        recorded[0].reason == WarningReason::ApproachingDeadline,
        "approaching deadline warning",
        WarningReason::ApproachingDeadline,
        recorded[0].reason
    );
    drop(recorded);
    test_complete!("test_deadline_monitor_warns_on_approaching_deadline");
}

#[test]
fn test_deadline_monitor_warns_at_threshold_boundary() {
    init_test("test_deadline_monitor_warns_at_threshold_boundary");
    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(123));

    let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
    let warnings_ref = warnings.clone();
    let config = MonitorConfig {
        check_interval: Duration::ZERO,
        warning_threshold_fraction: 0.2,
        checkpoint_timeout: Duration::from_secs(3600),
        adaptive: AdaptiveDeadlineConfig::default(),
        enabled: true,
    };
    runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
        warnings_ref.lock().unwrap().push(warning);
    });

    let region = runtime.state.create_root_region(Budget::INFINITE);
    let budget = Budget::new().with_deadline(Time::from_secs(100));
    let (task_id, _handle) = runtime
        .state
        .create_task(region, budget, async {
            yield_now().await;
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.advance_time_to(Time::from_secs(80));

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let recorded = warnings.lock().unwrap();
    assert_with_log!(
        recorded.len() == 1,
        "one warning emitted at threshold boundary",
        1usize,
        recorded.len()
    );
    assert_with_log!(
        recorded[0].reason == WarningReason::ApproachingDeadline,
        "approaching deadline warning",
        WarningReason::ApproachingDeadline,
        recorded[0].reason
    );
    drop(recorded);
    test_complete!("test_deadline_monitor_warns_at_threshold_boundary");
}

#[test]
fn test_deadline_monitor_warns_on_no_progress() {
    init_test("test_deadline_monitor_warns_on_no_progress");
    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(7));

    let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
    let warnings_ref = warnings.clone();
    let config = MonitorConfig {
        check_interval: Duration::ZERO,
        warning_threshold_fraction: 0.1,
        checkpoint_timeout: Duration::ZERO,
        adaptive: AdaptiveDeadlineConfig::default(),
        enabled: true,
    };
    runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
        warnings_ref.lock().unwrap().push(warning);
    });

    let region = runtime.state.create_root_region(Budget::INFINITE);
    let budget = Budget::new().with_deadline(Time::from_secs(1000));
    let (task_id, _handle) = runtime
        .state
        .create_task(region, budget, async {
            yield_now().await;
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.advance_time_to(Time::from_secs(100));

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let recorded = warnings.lock().unwrap();
    assert_with_log!(
        recorded.len() == 1,
        "one warning emitted",
        1usize,
        recorded.len()
    );
    assert_with_log!(
        recorded[0].reason == WarningReason::NoProgress,
        "no progress warning",
        WarningReason::NoProgress,
        recorded[0].reason
    );
    drop(recorded);
    test_complete!("test_deadline_monitor_warns_on_no_progress");
}

#[test]
fn test_deadline_monitor_warns_on_approaching_deadline_no_progress() {
    init_test("test_deadline_monitor_warns_on_approaching_deadline_no_progress");
    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(8));

    let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
    let warnings_ref = warnings.clone();
    let config = MonitorConfig {
        check_interval: Duration::ZERO,
        warning_threshold_fraction: 0.2,
        checkpoint_timeout: Duration::ZERO,
        adaptive: AdaptiveDeadlineConfig::default(),
        enabled: true,
    };
    runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
        warnings_ref.lock().unwrap().push(warning);
    });

    let region = runtime.state.create_root_region(Budget::INFINITE);
    let budget = Budget::new().with_deadline(Time::from_secs(100));
    let (task_id, _handle) = runtime
        .state
        .create_task(region, budget, async {
            yield_now().await;
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.advance_time_to(Time::from_secs(90));

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let recorded = warnings.lock().unwrap();
    assert_with_log!(
        recorded.len() == 1,
        "one warning emitted",
        1usize,
        recorded.len()
    );
    assert_with_log!(
        recorded[0].reason == WarningReason::ApproachingDeadlineNoProgress,
        "approaching deadline + no progress warning",
        WarningReason::ApproachingDeadlineNoProgress,
        recorded[0].reason
    );
    drop(recorded);
    test_complete!("test_deadline_monitor_warns_on_approaching_deadline_no_progress");
}

#[test]
fn test_deadline_monitor_includes_checkpoint_message() {
    init_test("test_deadline_monitor_includes_checkpoint_message");
    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(99));

    let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
    let warnings_ref = warnings.clone();
    let config = MonitorConfig {
        check_interval: Duration::ZERO,
        warning_threshold_fraction: 0.2,
        checkpoint_timeout: Duration::from_secs(3600),
        adaptive: AdaptiveDeadlineConfig::default(),
        enabled: true,
    };
    runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
        warnings_ref.lock().unwrap().push(warning);
    });

    let region = runtime.state.create_root_region(Budget::INFINITE);
    let budget = Budget::new().with_deadline(Time::from_secs(100));
    let (task_id, _handle) = runtime
        .state
        .create_task(region, budget, async {
            let cx = Cx::current().expect("cx set");
            cx.checkpoint_with("checkpoint message")
                .expect("checkpoint");
            yield_now().await;
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.advance_time_to(Time::from_secs(90));

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let recorded = warnings.lock().unwrap();
    assert_with_log!(
        recorded.len() == 1,
        "one warning emitted",
        1usize,
        recorded.len()
    );
    assert_with_log!(
        recorded[0].last_checkpoint_message.as_deref() == Some("checkpoint message"),
        "warning includes last checkpoint message",
        Some("checkpoint message"),
        recorded[0].last_checkpoint_message.as_deref()
    );
    drop(recorded);
    test_complete!("test_deadline_monitor_includes_checkpoint_message");
}

#[test]
fn test_deadline_monitor_e2e_stuck_task_detection() {
    init_test("test_deadline_monitor_e2e_stuck_task_detection");
    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(2024));

    let detected = Arc::new(AtomicBool::new(false));
    let detected_ref = detected.clone();
    let config = MonitorConfig {
        check_interval: Duration::ZERO,
        warning_threshold_fraction: 0.2,
        checkpoint_timeout: Duration::ZERO,
        adaptive: AdaptiveDeadlineConfig::default(),
        enabled: true,
    };
    runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
        if matches!(
            warning.reason,
            WarningReason::NoProgress | WarningReason::ApproachingDeadlineNoProgress
        ) {
            detected_ref.store(true, Ordering::SeqCst);
        }
    });

    let region = runtime.state.create_root_region(Budget::INFINITE);
    let budget = Budget::new().with_deadline(Time::from_secs(100));
    let (task_id, _handle) = runtime
        .state
        .create_task(region, budget, async {
            let cx = Cx::current().expect("cx set");
            cx.checkpoint_with("starting batch").expect("checkpoint");
            yield_now().await;
            // Simulate a stall: no further checkpoints.
            yield_now().await;
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.advance_time_to(Time::from_secs(90));

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let stuck = detected.load(Ordering::SeqCst);
    assert_with_log!(stuck, "stuck task detected", true, stuck);
    test_complete!("test_deadline_monitor_e2e_stuck_task_detection");
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
    let completed_clone = completed;

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
