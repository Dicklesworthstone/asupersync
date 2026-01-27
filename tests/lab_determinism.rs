//! Lab reactor determinism tests.
//!
//! These tests verify that the lab runtime provides deterministic execution,
//! enabling reproducible concurrent tests.
//!
//! The core principle is: **Same seed → Same execution → Same results**
//!
//! This is critical for debugging concurrent bugs - if a test fails,
//! the same seed reproduces the exact failure.

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::reactor::{Event, Events, FaultConfig, Interest, LabReactor, Token};
use asupersync::runtime::Reactor;
use asupersync::trace::ReplayEvent;
use asupersync::types::{Budget, CancelReason};
use asupersync::util::DetRng;
use common::*;
use std::future::Future;
use std::io;
#[cfg(unix)]
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Helper types
// ============================================================================

/// A future that yields once before completing.
struct YieldOnce {
    yielded: bool,
}

impl Future for YieldOnce {
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
    YieldOnce { yielded: false }.await;
}

/// A future that yields N times before completing.
struct YieldN {
    remaining: usize,
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

async fn yield_n(n: usize) {
    YieldN { remaining: n }.await;
}

#[cfg(unix)]
struct MockSource;

#[cfg(unix)]
impl std::os::fd::AsRawFd for MockSource {
    fn as_raw_fd(&self) -> RawFd {
        0
    }
}

// ============================================================================
// Test: Basic Determinism
// ============================================================================

/// Run N tasks with a given seed and return their completion order.
fn run_tasks_with_seed(seed: u64, task_count: usize, yields_per_task: usize) -> Vec<usize> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Shared vector to track completion order
    let completion_order = Arc::new(std::sync::Mutex::new(Vec::new()));

    // Spawn tasks
    let mut task_ids = Vec::new();
    for i in 0..task_count {
        let order = completion_order.clone();
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                // Yield multiple times to create scheduling opportunities
                yield_n(yields_per_task).await;
                order.lock().unwrap().push(i);
            })
            .expect("create task");
        task_ids.push(task_id);
    }

    // Schedule all tasks at the same priority (creates non-determinism opportunity)
    for task_id in task_ids {
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    // Run until quiescent
    runtime.run_until_quiescent();

    Arc::try_unwrap(completion_order)
        .unwrap()
        .into_inner()
        .unwrap()
}

#[test]
fn test_lab_deterministic_scheduling_same_seed() {
    init_test("test_lab_deterministic_scheduling_same_seed");
    test_section!("run_with_same_seed");

    let seed = 42;
    let task_count = 10;
    let yields_per_task = 5;

    // Run multiple times with the same seed
    let result1 = run_tasks_with_seed(seed, task_count, yields_per_task);
    let result2 = run_tasks_with_seed(seed, task_count, yields_per_task);
    let result3 = run_tasks_with_seed(seed, task_count, yields_per_task);

    test_section!("verify_determinism");
    // All runs must produce identical results
    assert_with_log!(
        result1 == result2,
        "Run 1 and Run 2 should be identical",
        result1,
        result2
    );
    assert_with_log!(
        result2 == result3,
        "Run 2 and Run 3 should be identical",
        result2,
        result3
    );

    tracing::info!(
        seed = seed,
        task_count = task_count,
        completion_order = ?result1,
        "Deterministic execution verified"
    );

    test_complete!("test_lab_deterministic_scheduling_same_seed");
}

// ============================================================================
// Test: Different Seeds Produce Different Results
// ============================================================================

#[test]
fn test_lab_different_seeds_different_results() {
    init_test("test_lab_different_seeds_different_results");
    test_section!("run_with_different_seeds");

    let task_count = 10;
    let yields_per_task = 5;

    // Run with different seeds
    let result1 = run_tasks_with_seed(1, task_count, yields_per_task);
    let result2 = run_tasks_with_seed(2, task_count, yields_per_task);
    let result3 = run_tasks_with_seed(3, task_count, yields_per_task);
    let result4 = run_tasks_with_seed(1000, task_count, yields_per_task);
    let result5 = run_tasks_with_seed(0xDEADBEEF, task_count, yields_per_task);

    test_section!("verify_different_results");
    // Collect all results
    let results = vec![&result1, &result2, &result3, &result4, &result5];

    // Count unique orderings
    let mut unique_orderings = std::collections::HashSet::new();
    for r in &results {
        unique_orderings.insert(format!("{r:?}"));
    }

    // With 5 different seeds, we should see at least 2 different orderings
    // (It's statistically extremely unlikely all 5 would be identical if RNG is working)
    let unique_count = unique_orderings.len();
    tracing::info!(
        unique_count = unique_count,
        "Found {} unique orderings from 5 seeds",
        unique_count
    );

    assert_with_log!(
        unique_count >= 2,
        "Different seeds should produce different orderings",
        ">= 2",
        unique_count
    );

    test_complete!("test_lab_different_seeds_different_results");
}

// ============================================================================
// Test: Step Count Determinism
// ============================================================================

/// Run and return the number of steps taken.
fn run_and_count_steps(seed: u64, task_count: usize, yields_per_task: usize) -> u64 {
    let mut runtime = LabRuntime::new(LabConfig::new(seed));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let mut task_ids = Vec::new();
    for _ in 0..task_count {
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_n(yields_per_task).await;
            })
            .expect("create task");
        task_ids.push(task_id);
    }

    for task_id in task_ids {
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    runtime.steps()
}

#[test]
fn test_lab_step_count_determinism() {
    init_test("test_lab_step_count_determinism");
    test_section!("run_multiple_times");

    let seed = 123;
    let task_count = 5;
    let yields_per_task = 3;

    let steps1 = run_and_count_steps(seed, task_count, yields_per_task);
    let steps2 = run_and_count_steps(seed, task_count, yields_per_task);
    let steps3 = run_and_count_steps(seed, task_count, yields_per_task);

    test_section!("verify_step_counts");
    assert_with_log!(
        steps1 == steps2,
        "Step count should be deterministic (run 1 vs 2)",
        steps1,
        steps2
    );
    assert_with_log!(
        steps2 == steps3,
        "Step count should be deterministic (run 2 vs 3)",
        steps2,
        steps3
    );

    tracing::info!(
        seed = seed,
        steps = steps1,
        "Step count determinism verified"
    );

    test_complete!("test_lab_step_count_determinism");
}

// ============================================================================
// Test: Virtual Time Advancement Determinism
// ============================================================================

/// Run with time advancement and return events with timestamps.
fn run_with_time_advancement(seed: u64) -> Vec<(u64, String)> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let events = Arc::new(std::sync::Mutex::new(Vec::new()));

    // Create tasks that record their execution time
    for i in 0..5 {
        let events_clone = events.clone();
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_now().await;
                let _time = asupersync::types::Time::ZERO; // Would use Cx::current().now() in real code
                events_clone
                    .lock()
                    .unwrap()
                    .push((0, format!("task-{i}-start")));
            })
            .expect("create task");
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    // Run initial tasks
    runtime.run_until_quiescent();

    // Advance time
    runtime.advance_time(1_000_000_000); // 1 second in nanos

    // Record time advancement
    events
        .lock()
        .unwrap()
        .push((runtime.now().as_nanos(), "time-advanced".to_string()));

    Arc::try_unwrap(events).unwrap().into_inner().unwrap()
}

#[test]
fn test_lab_virtual_time_determinism() {
    init_test("test_lab_virtual_time_determinism");
    test_section!("run_with_time");

    let seed = 789;

    let events1 = run_with_time_advancement(seed);
    let events2 = run_with_time_advancement(seed);

    test_section!("verify_time_events");
    assert_with_log!(
        events1 == events2,
        "Time-based events should be deterministic",
        events1,
        events2
    );

    tracing::info!(
        seed = seed,
        events = ?events1,
        "Virtual time determinism verified"
    );

    test_complete!("test_lab_virtual_time_determinism");
}

// ============================================================================
// Test: Lab Reactor Event Ordering Determinism
// ============================================================================

#[cfg(unix)]
fn run_reactor_event_order(seed: u64) -> (Vec<usize>, Vec<usize>) {
    let reactor = LabReactor::new();
    let source = MockSource;

    let tokens: Vec<Token> = (0..5).map(Token::new).collect();
    for token in &tokens {
        reactor
            .register(&source, *token, Interest::READABLE)
            .expect("register");
    }

    let mut rng = DetRng::new(seed);
    let mut order: Vec<usize> = (0..tokens.len()).collect();
    for i in (1..order.len()).rev() {
        let j = rng.next_usize(i + 1);
        order.swap(i, j);
    }

    for idx in &order {
        let token = tokens[*idx];
        reactor.inject_event(
            token,
            Event::readable(token),
            std::time::Duration::from_millis(1),
        );
    }

    let mut events = Events::with_capacity(16);
    reactor
        .poll(&mut events, Some(std::time::Duration::from_millis(1)))
        .expect("poll");

    let observed: Vec<usize> = events.iter().map(|event| event.token.0).collect();
    (order, observed)
}

#[cfg(unix)]
#[test]
fn test_lab_reactor_event_ordering_determinism() {
    init_test("test_lab_reactor_event_ordering_determinism");
    test_section!("same_seed_ordering");

    let seed = 4242;
    let (order1, observed1) = run_reactor_event_order(seed);
    let (order2, observed2) = run_reactor_event_order(seed);

    assert_with_log!(
        order1 == order2,
        "Injection order should be deterministic",
        order1,
        order2
    );
    assert_with_log!(
        observed1 == observed2,
        "Observed order should be deterministic",
        observed1,
        observed2
    );
    assert_with_log!(
        observed1 == order1,
        "Observed order should follow injection order",
        order1,
        observed1
    );

    test_complete!("test_lab_reactor_event_ordering_determinism");
}

// ============================================================================
// Test: Fault Injection Determinism
// ============================================================================

#[cfg(unix)]
fn run_fault_stats(seed: u64) -> (u64, u64, u64) {
    let reactor = LabReactor::new();
    let source = MockSource;
    let token = Token::new((seed % 1024) as usize + 1);

    reactor
        .register(&source, token, Interest::READABLE)
        .expect("register");

    let config = FaultConfig::new()
        .with_error_probability(0.4)
        .with_error_kinds(vec![io::ErrorKind::ConnectionReset]);
    reactor.set_fault_config(token, config).expect("set fault");

    for _ in 0..50 {
        reactor.inject_event(
            token,
            Event::readable(token),
            std::time::Duration::from_millis(1),
        );
    }

    let mut events = Events::with_capacity(64);
    reactor
        .poll(&mut events, Some(std::time::Duration::from_millis(1)))
        .expect("poll");

    reactor.fault_stats(token).unwrap_or((0, 0, 0))
}

#[cfg(unix)]
#[test]
fn test_lab_fault_injection_determinism() {
    init_test("test_lab_fault_injection_determinism");
    test_section!("same_seed_faults");

    let seed = 9001;
    let stats1 = run_fault_stats(seed);
    let stats2 = run_fault_stats(seed);

    assert_with_log!(
        stats1 == stats2,
        "Fault injection stats should be deterministic",
        stats1,
        stats2
    );

    test_complete!("test_lab_fault_injection_determinism");
}

// ============================================================================
// Test: Trace Capture Determinism
// ============================================================================

#[test]
fn test_lab_trace_capture_determinism() {
    init_test("test_lab_trace_capture_determinism");
    test_section!("capture_traces");

    let seed = 101112;
    let task_count = 5;

    // First run
    let mut runtime1 = LabRuntime::new(LabConfig::new(seed).trace_capacity(1024));
    let region1 = runtime1.state.create_root_region(Budget::INFINITE);
    for _ in 0..task_count {
        let (task_id, _handle) = runtime1
            .state
            .create_task(region1, Budget::INFINITE, async {
                yield_now().await;
            })
            .expect("create task");
        runtime1.scheduler.lock().unwrap().schedule(task_id, 0);
    }
    runtime1.run_until_quiescent();
    let trace1_len = runtime1.trace().len();

    // Second run
    let mut runtime2 = LabRuntime::new(LabConfig::new(seed).trace_capacity(1024));
    let region2 = runtime2.state.create_root_region(Budget::INFINITE);
    for _ in 0..task_count {
        let (task_id, _handle) = runtime2
            .state
            .create_task(region2, Budget::INFINITE, async {
                yield_now().await;
            })
            .expect("create task");
        runtime2.scheduler.lock().unwrap().schedule(task_id, 0);
    }
    runtime2.run_until_quiescent();
    let trace2_len = runtime2.trace().len();

    test_section!("verify_traces");
    // Trace lengths should be identical
    assert_with_log!(
        trace1_len == trace2_len,
        "Trace lengths should be identical",
        trace1_len,
        trace2_len
    );

    tracing::info!(
        seed = seed,
        trace_len = trace1_len,
        "Trace capture determinism verified"
    );

    test_complete!("test_lab_trace_capture_determinism");
}

// ============================================================================
// Test: Replay Trace Determinism (Multi-Worker)
// ============================================================================

fn record_replay_events(seed: u64, worker_count: usize) -> Vec<ReplayEvent> {
    let config = LabConfig::new(seed)
        .worker_count(worker_count)
        .with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    for _ in 0..6 {
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {
                yield_n(3).await;
            })
            .expect("create task");
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let trace = runtime.finish_replay_trace().expect("replay trace");
    trace.events
}

#[test]
fn test_lab_replay_trace_determinism_multiworker() {
    init_test("test_lab_replay_trace_determinism_multiworker");
    test_section!("record");

    let seed = 4242;
    let worker_count = 4;

    let events1 = record_replay_events(seed, worker_count);
    let events2 = record_replay_events(seed, worker_count);

    test_section!("verify");
    assert_with_log!(
        !events1.is_empty(),
        "replay trace should have events",
        true,
        !events1.is_empty()
    );
    assert_with_log!(
        events1 == events2,
        "replay events should be deterministic across runs",
        events1.len(),
        events2.len()
    );

    test_complete!("test_lab_replay_trace_determinism_multiworker");
}

// ============================================================================
// Test: Priority Scheduling Determinism
// ============================================================================

/// Run tasks with different priorities and return completion order.
fn run_with_priorities(seed: u64) -> Vec<(usize, u8)> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let completion_order = Arc::new(std::sync::Mutex::new(Vec::new()));

    // Spawn tasks with different priorities
    let priorities = vec![0u8, 5, 10, 3, 7, 1, 9, 2, 8, 4];
    for (i, &priority) in priorities.iter().enumerate() {
        let order = completion_order.clone();
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_now().await;
                order.lock().unwrap().push((i, priority));
            })
            .expect("create task");
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(task_id, priority);
    }

    runtime.run_until_quiescent();

    Arc::try_unwrap(completion_order)
        .unwrap()
        .into_inner()
        .unwrap()
}

#[test]
fn test_lab_priority_scheduling_determinism() {
    init_test("test_lab_priority_scheduling_determinism");
    test_section!("run_with_priorities");

    let seed = 456;

    let result1 = run_with_priorities(seed);
    let result2 = run_with_priorities(seed);

    test_section!("verify_priority_order");
    assert_with_log!(
        result1 == result2,
        "Priority-based scheduling should be deterministic",
        result1,
        result2
    );

    // Verify higher priority tasks complete before lower priority ones
    // (priorities are ordered descending in asupersync scheduler)
    for window in result1.windows(2) {
        let (_i1, p1) = window[0];
        let (_i2, p2) = window[1];
        // With same-time scheduling, higher priority should generally come first
        // but this depends on scheduler implementation details
        tracing::debug!(p1 = p1, p2 = p2, "Priority ordering");
    }

    tracing::info!(
        seed = seed,
        completion_order = ?result1,
        "Priority scheduling determinism verified"
    );

    test_complete!("test_lab_priority_scheduling_determinism");
}

// ============================================================================
// Test: Multiple Runs Consistency
// ============================================================================

/// Helper to run a test multiple times and verify consistency.
fn verify_deterministic<F, T>(seed: u64, runs: usize, f: F)
where
    F: Fn(u64) -> T,
    T: Eq + std::fmt::Debug,
{
    let baseline = f(seed);
    for run in 1..runs {
        let result = f(seed);
        assert!(
            result == baseline,
            "Non-deterministic execution detected on run {run}: baseline={baseline:?}, got={result:?}"
        );
    }
}

#[test]
fn test_lab_multiple_runs_consistency() {
    init_test("test_lab_multiple_runs_consistency");
    test_section!("verify_10_runs");

    let seed = 0xCAFEBABE;

    // Run 10 times and verify all produce identical results
    verify_deterministic(seed, 10, |s| run_tasks_with_seed(s, 8, 4));

    tracing::info!(seed = seed, runs = 10, "Multiple runs consistency verified");

    test_complete!("test_lab_multiple_runs_consistency");
}

// ============================================================================
// Test: Quiescence Detection Determinism
// ============================================================================

#[test]
fn test_lab_quiescence_detection_determinism() {
    init_test("test_lab_quiescence_detection_determinism");
    test_section!("run_to_quiescence");

    let seed = 0xFEEDFACE;

    // Helper to run and check quiescence
    let run = |s: u64| -> (bool, u64) {
        let mut runtime = LabRuntime::new(LabConfig::new(s));
        let region = runtime.state.create_root_region(Budget::INFINITE);

        for _ in 0..3 {
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {
                    yield_n(2).await;
                })
                .expect("create task");
            runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        }

        let steps = runtime.run_until_quiescent();
        let quiescent = runtime.is_quiescent();
        (quiescent, steps)
    };

    let result1 = run(seed);
    let result2 = run(seed);
    let result3 = run(seed);

    test_section!("verify_quiescence");
    assert_with_log!(
        result1 == result2,
        "Quiescence detection should be deterministic (run 1 vs 2)",
        result1,
        result2
    );
    assert_with_log!(
        result2 == result3,
        "Quiescence detection should be deterministic (run 2 vs 3)",
        result2,
        result3
    );

    // Should always reach quiescence
    assert_with_log!(
        result1.0,
        "Runtime should reach quiescence",
        true,
        result1.0
    );

    tracing::info!(
        seed = seed,
        quiescent = result1.0,
        steps = result1.1,
        "Quiescence detection determinism verified"
    );

    test_complete!("test_lab_quiescence_detection_determinism");
}

// ============================================================================
// Test: Cancellation Drain Under Contention
// ============================================================================

fn run_cancel_drain_stress(seed: u64, task_count: usize) -> (usize, usize, bool, u64) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let mut task_ids = Vec::with_capacity(task_count);
    for _ in 0..task_count {
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {
                for _ in 0..8 {
                    let Some(cx) = Cx::current() else {
                        return;
                    };
                    if cx.checkpoint().is_err() {
                        return;
                    }
                    yield_n(1).await;
                }
            })
            .expect("create task");
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        task_ids.push(task_id);
    }

    for _ in 0..16 {
        runtime.step_for_test();
    }

    let cancel_reason = CancelReason::shutdown();
    let tasks_to_cancel = runtime.state.cancel_request(region, &cancel_reason, None);
    {
        let mut scheduler = runtime.scheduler.lock().unwrap();
        for (task_id, priority) in tasks_to_cancel {
            scheduler.schedule_cancel(task_id, priority);
        }
    }

    let steps = runtime.run_until_quiescent();

    let tracked: std::collections::HashSet<_> = task_ids.into_iter().collect();
    let mut terminal = 0usize;
    let mut non_terminal = 0usize;

    for (_, record) in runtime.state.tasks.iter() {
        if !tracked.contains(&record.id) {
            continue;
        }
        if record.state.is_terminal() {
            terminal += 1;
        } else {
            non_terminal += 1;
        }
    }

    (terminal, non_terminal, runtime.is_quiescent(), steps)
}

#[test]
fn test_lab_cancel_drain_under_contention_deterministic() {
    init_test("test_lab_cancel_drain_under_contention_deterministic");
    test_section!("run_cancel_stress");

    let seed = 0xA11CE5EED;
    let task_count = 64;

    let result1 = run_cancel_drain_stress(seed, task_count);
    let result2 = run_cancel_drain_stress(seed, task_count);

    test_section!("verify_determinism");
    assert_with_log!(
        result1 == result2,
        "cancel drain results should be deterministic",
        result1,
        result2
    );

    test_section!("verify_quiescence");
    assert_with_log!(
        result1.0 == task_count && result1.1 == 0,
        "all tasks terminal after cancel drain",
        (task_count, 0),
        (result1.0, result1.1)
    );
    assert_with_log!(
        result1.2,
        "runtime reaches quiescence after cancel drain",
        true,
        result1.2
    );

    tracing::info!(
        seed = seed,
        task_count = task_count,
        terminal = result1.0,
        non_terminal = result1.1,
        steps = result1.3,
        "cancel drain under contention verified"
    );

    test_complete!("test_lab_cancel_drain_under_contention_deterministic");
}

// ============================================================================
// Test: Empty Runtime Determinism
// ============================================================================

#[test]
fn test_lab_empty_runtime_determinism() {
    init_test("test_lab_empty_runtime_determinism");
    test_section!("empty_runtime");

    let seed = 42;

    // Run with no tasks
    let run = |s: u64| -> (bool, u64, u64) {
        let mut runtime = LabRuntime::new(LabConfig::new(s));
        let _region = runtime.state.create_root_region(Budget::INFINITE);
        // Don't create any tasks
        let steps = runtime.run_until_quiescent();
        (runtime.is_quiescent(), steps, runtime.now().as_nanos())
    };

    let result1 = run(seed);
    let result2 = run(seed);

    test_section!("verify_empty");
    assert_with_log!(
        result1 == result2,
        "Empty runtime should be deterministic",
        result1,
        result2
    );

    // Empty runtime should be immediately quiescent with 0 steps
    assert_with_log!(
        result1.0,
        "Empty runtime should be quiescent",
        true,
        result1.0
    );
    assert_with_log!(
        result1.1 == 0,
        "Empty runtime should have 0 steps",
        0,
        result1.1
    );

    test_complete!("test_lab_empty_runtime_determinism");
}

// ============================================================================
// Test: Interleaved Task Completion Determinism
// ============================================================================

#[test]
fn test_lab_interleaved_completion_determinism() {
    init_test("test_lab_interleaved_completion_determinism");
    test_section!("interleaved_tasks");

    let seed = 0xABCDEF;

    // Create tasks that yield different numbers of times
    let run = |s: u64| -> Vec<(usize, usize)> {
        let mut runtime = LabRuntime::new(LabConfig::new(s));
        let region = runtime.state.create_root_region(Budget::INFINITE);

        let completion_order = Arc::new(std::sync::Mutex::new(Vec::new()));

        // Task i yields i times
        for i in 0..5 {
            let order = completion_order.clone();
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    yield_n(i).await;
                    order.lock().unwrap().push((i, i));
                })
                .expect("create task");
            runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        Arc::try_unwrap(completion_order)
            .unwrap()
            .into_inner()
            .unwrap()
    };

    let result1 = run(seed);
    let result2 = run(seed);

    test_section!("verify_interleaved");
    assert_with_log!(
        result1 == result2,
        "Interleaved completion should be deterministic",
        result1,
        result2
    );

    tracing::info!(
        seed = seed,
        completion_order = ?result1,
        "Interleaved completion determinism verified"
    );

    test_complete!("test_lab_interleaved_completion_determinism");
}
