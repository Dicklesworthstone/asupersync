#![allow(missing_docs)]
//! Lane fairness tests for the three-lane scheduler.
//!
//! These tests verify that the scheduler's fairness properties work correctly
//! by checking observable outcomes (task completion) rather than internal state.

use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::three_lane::ThreeLaneScheduler;
use asupersync::sync::ContendedMutex;
use asupersync::test_utils::init_test_logging;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{Budget, TaskId, Time};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const MAX_CONSECUTIVE_CANCEL: usize = 16;

fn init_test(name: &str) {
    init_test_logging();
    asupersync::test_phase!(name);
}

#[test]
fn test_cancel_preempts_timed_and_ready_deterministic() {
    init_test("cancel_preempts_timed_ready_deterministic");

    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1_000)));
    let mut runtime_state = RuntimeState::new();
    runtime_state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
    let state = Arc::new(ContendedMutex::new("runtime_state", runtime_state));

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    let cancel_task = TaskId::new_for_test(1, 1);
    let timed_task = TaskId::new_for_test(1, 2);
    let ready_task = TaskId::new_for_test(1, 3);

    asupersync::test_section!("inject tasks");
    scheduler.inject_ready(ready_task, 10);
    scheduler.inject_timed(timed_task, Time::from_nanos(500));
    scheduler.inject_cancel(cancel_task, 10);

    let mut workers = scheduler.take_workers().into_iter();
    let mut worker = workers.next().expect("worker");

    asupersync::test_section!("pop in lane order");
    let first = worker.next_task();
    let second = worker.next_task();
    let third = worker.next_task();

    asupersync::assert_with_log!(
        first == Some(cancel_task),
        "cancel lane should preempt timed/ready",
        Some(cancel_task),
        first
    );
    asupersync::assert_with_log!(
        second == Some(timed_task),
        "timed lane should preempt ready when due",
        Some(timed_task),
        second
    );
    asupersync::assert_with_log!(
        third == Some(ready_task),
        "ready lane should come last",
        Some(ready_task),
        third
    );

    asupersync::test_complete!("cancel_preempts_timed_ready_deterministic");
}

#[test]
fn test_timed_lane_edf_ordering_deterministic() {
    init_test("timed_lane_edf_ordering_deterministic");

    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1_000)));
    let mut runtime_state = RuntimeState::new();
    runtime_state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
    let state = Arc::new(ContendedMutex::new("runtime_state", runtime_state));

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    let t1 = TaskId::new_for_test(1, 10);
    let t2 = TaskId::new_for_test(1, 11);
    let t3 = TaskId::new_for_test(1, 12);

    asupersync::test_section!("inject timed tasks (all due)");
    scheduler.inject_timed(t2, Time::from_nanos(750));
    scheduler.inject_timed(t3, Time::from_nanos(900));
    scheduler.inject_timed(t1, Time::from_nanos(500));

    let mut workers = scheduler.take_workers().into_iter();
    let mut worker = workers.next().expect("worker");

    let first = worker.next_task();
    let second = worker.next_task();
    let third = worker.next_task();

    asupersync::assert_with_log!(
        first == Some(t1),
        "earliest deadline should dispatch first",
        Some(t1),
        first
    );
    asupersync::assert_with_log!(
        second == Some(t2),
        "second earliest deadline should dispatch next",
        Some(t2),
        second
    );
    asupersync::assert_with_log!(
        third == Some(t3),
        "latest deadline should dispatch last",
        Some(t3),
        third
    );

    asupersync::test_complete!("timed_lane_edf_ordering_deterministic");
}

#[test]
fn test_timed_not_due_yields_ready_then_due() {
    init_test("timed_not_due_yields_ready_then_due");

    let clock = Arc::new(VirtualClock::new());
    let mut runtime_state = RuntimeState::new();
    runtime_state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));
    let state = Arc::new(ContendedMutex::new("runtime_state", runtime_state));

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    let timed_task = TaskId::new_for_test(1, 20);
    let ready_task = TaskId::new_for_test(1, 21);

    asupersync::test_section!("inject ready and future timed");
    scheduler.inject_ready(ready_task, 10);
    scheduler.inject_timed(timed_task, Time::from_nanos(1_000));

    let mut workers = scheduler.take_workers().into_iter();
    let mut worker = workers.next().expect("worker");

    let first = worker.next_task();
    asupersync::assert_with_log!(
        first == Some(ready_task),
        "ready task should dispatch before not-due timed task",
        Some(ready_task),
        first
    );

    asupersync::test_section!("advance time and dispatch timed");
    clock.advance(2_000);
    let second = worker.next_task();
    asupersync::assert_with_log!(
        second == Some(timed_task),
        "timed task should dispatch after deadline",
        Some(timed_task),
        second
    );

    asupersync::test_complete!("timed_not_due_yields_ready_then_due");
}

#[test]
fn test_cancel_fairness_bound_deterministic() {
    init_test("cancel_fairness_bound_deterministic");

    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 2);

    let cancel_a = TaskId::new_for_test(1, 30);
    let cancel_b = TaskId::new_for_test(1, 31);
    let cancel_c = TaskId::new_for_test(1, 32);
    let ready_task = TaskId::new_for_test(1, 33);

    asupersync::test_section!("inject cancel flood and one ready");
    scheduler.inject_cancel(cancel_a, 10);
    scheduler.inject_cancel(cancel_b, 10);
    scheduler.inject_cancel(cancel_c, 10);
    scheduler.inject_ready(ready_task, 10);

    let mut workers = scheduler.take_workers().into_iter();
    let mut worker = workers.next().expect("worker");

    let first = worker.next_task().expect("first");
    let second = worker.next_task().expect("second");
    let third = worker.next_task().expect("third");

    asupersync::assert_with_log!(
        first != ready_task && second != ready_task,
        "ready task should not preempt before fairness limit",
        ready_task,
        (first, second)
    );
    asupersync::assert_with_log!(
        third == ready_task,
        "ready task should dispatch within fairness bound",
        ready_task,
        third
    );

    asupersync::test_complete!("cancel_fairness_bound_deterministic");
}

#[test]
fn test_steal_only_from_ready_lane_deterministic() {
    init_test("steal_only_from_ready_lane_deterministic");

    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = ThreeLaneScheduler::new(2, &state);

    let cancel_task = TaskId::new_for_test(1, 40);
    let ready_task1 = TaskId::new_for_test(1, 41);
    let ready_task2 = TaskId::new_for_test(1, 42);

    let mut worker_iter = scheduler.take_workers().into_iter();
    let worker0 = worker_iter.next().expect("worker0");
    let mut thief = worker_iter.next().expect("worker1");

    asupersync::test_section!("seed worker0 local queues");
    {
        let mut local0 = worker0.local.lock().expect("local0 lock");
        local0.schedule_cancel(cancel_task, 10);
        local0.schedule(ready_task1, 10);
        local0.schedule(ready_task2, 10);
    }

    asupersync::test_section!("thief steals from ready lane");
    let stolen = thief.next_task();
    asupersync::assert_with_log!(
        stolen == Some(ready_task1) || stolen == Some(ready_task2),
        "steal should only return ready-lane tasks",
        (ready_task1, ready_task2),
        stolen
    );

    asupersync::test_complete!("steal_only_from_ready_lane_deterministic");
}

/// Test that ready work completes despite a flood of cancel work.
/// This verifies the fairness limit prevents cancel starvation.
#[test]
fn test_ready_not_starved_by_cancel_flood() {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    // Create a ready task that we want to see complete
    let ready_id = {
        let mut guard = state.lock().unwrap();
        let (id, _) = guard
            .create_task(region, Budget::INFINITE, async {})
            .unwrap();
        id
    };

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    // Create many cancel tasks (well over the limit)
    let num_cancel = MAX_CONSECUTIVE_CANCEL * 3;

    // Create cancel tasks and inject them
    for _ in 0..num_cancel {
        let cancel_id = {
            let mut guard = state.lock().unwrap();
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .unwrap();
            id
        };
        scheduler.inject_cancel(cancel_id, 100);
    }

    // Inject ready task
    scheduler.inject_ready(ready_id, 100);

    // Run worker
    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();

    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    // Give it time to process
    std::thread::sleep(Duration::from_millis(200));

    scheduler.shutdown();
    handle.join().unwrap();

    // Ready task should have completed (removed from tasks map)
    let ready_completed = state.lock().unwrap().task(ready_id).is_none();
    assert!(ready_completed, "Ready task was starved by cancel flood");
}

/// Test that ready work runs within the fairness window when cancel tasks flood.
#[test]
fn test_ready_runs_within_fairness_window() {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let seq = Arc::new(AtomicUsize::new(0));
    let ready_position = Arc::new(AtomicUsize::new(usize::MAX));

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    // Flood cancel lane well beyond the fairness limit.
    let num_cancel = MAX_CONSECUTIVE_CANCEL * 2;
    for _ in 0..num_cancel {
        let seq = Arc::clone(&seq);
        let cancel_id = {
            let mut guard = state.lock().unwrap();
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async move {
                    seq.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
            id
        };
        scheduler.inject_cancel(cancel_id, 100);
    }

    // One ready task that records when it ran.
    let seq_ready = Arc::clone(&seq);
    let ready_position_ref = Arc::clone(&ready_position);
    let ready_id = {
        let mut guard = state.lock().unwrap();
        let (id, _) = guard
            .create_task(region, Budget::INFINITE, async move {
                let pos = seq_ready.fetch_add(1, Ordering::SeqCst) + 1;
                ready_position_ref.store(pos, Ordering::SeqCst);
            })
            .unwrap();
        id
    };
    scheduler.inject_ready(ready_id, 100);

    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();

    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    std::thread::sleep(Duration::from_millis(200));
    scheduler.shutdown();
    handle.join().unwrap();

    let pos = ready_position.load(Ordering::SeqCst);
    assert!(pos != usize::MAX, "Ready task never executed");
    assert!(
        pos <= MAX_CONSECUTIVE_CANCEL + 1,
        "Ready task executed too late: {pos} (limit {})",
        MAX_CONSECUTIVE_CANCEL + 1
    );
}

/// Test that timed work completes despite a flood of cancel work.
#[test]
fn test_timed_not_starved_by_cancel_flood() {
    let mut runtime_state = RuntimeState::new();
    runtime_state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::new(
        VirtualClock::new(),
    )));
    let state = Arc::new(ContendedMutex::new("runtime_state", runtime_state));

    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    // Create a timed task
    let timed_id = {
        let mut guard = state.lock().unwrap();
        let (id, _) = guard
            .create_task(region, Budget::INFINITE, async {})
            .unwrap();
        id
    };

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    // Inject cancel flood
    let num_cancel = MAX_CONSECUTIVE_CANCEL * 2;
    for _ in 0..num_cancel {
        let cancel_id = {
            let mut guard = state.lock().unwrap();
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .unwrap();
            id
        };
        scheduler.inject_cancel(cancel_id, 100);
    }

    // Inject timed task with deadline in the past (immediately due)
    scheduler.inject_timed(timed_id, Time::ZERO);

    // Run worker
    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();

    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    std::thread::sleep(Duration::from_millis(200));
    scheduler.shutdown();
    handle.join().unwrap();

    // Timed task should have completed
    let timed_completed = state.lock().unwrap().task(timed_id).is_none();
    assert!(timed_completed, "Timed task was starved by cancel flood");
}

/// Test that all lanes make progress in a mixed workload.
#[test]
fn test_all_lanes_make_progress() {
    let mut runtime_state = RuntimeState::new();
    runtime_state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::new(
        VirtualClock::new(),
    )));
    let state = Arc::new(ContendedMutex::new("runtime_state", runtime_state));

    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    // Create and inject tasks for each lane
    let num_per_lane = 10;
    let mut cancel_ids = Vec::new();
    let mut timed_ids = Vec::new();
    let mut ready_ids = Vec::new();

    for _ in 0..num_per_lane {
        let c = {
            let mut guard = state.lock().unwrap();
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .unwrap();
            id
        };
        let t = {
            let mut guard = state.lock().unwrap();
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .unwrap();
            id
        };
        let r = {
            let mut guard = state.lock().unwrap();
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .unwrap();
            id
        };
        scheduler.inject_cancel(c, 100);
        scheduler.inject_timed(t, Time::ZERO);
        scheduler.inject_ready(r, 100);
        cancel_ids.push(c);
        timed_ids.push(t);
        ready_ids.push(r);
    }

    // Run worker
    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();

    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    std::thread::sleep(Duration::from_millis(300));
    scheduler.shutdown();
    handle.join().unwrap();

    // Count completed tasks using public API
    let guard = state.lock().unwrap();
    let cancel_completed = cancel_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let timed_completed = timed_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let ready_completed = ready_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();

    assert!(
        cancel_completed > 0,
        "Cancel lane made no progress: {cancel_completed}/{num_per_lane}"
    );
    assert!(
        timed_completed > 0,
        "Timed lane made no progress: {timed_completed}/{num_per_lane}"
    );
    assert!(
        ready_completed > 0,
        "Ready lane made no progress: {ready_completed}/{num_per_lane}"
    );
}

/// Stress test: cascading cancellation doesn't starve ready work.
#[test]
fn stress_cascading_cancellation() {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    // Create ready task
    let ready_id = {
        let mut guard = state.lock().unwrap();
        let (id, _) = guard
            .create_task(region, Budget::INFINITE, async {})
            .unwrap();
        id
    };
    scheduler.inject_ready(ready_id, 100);

    // Create many cancel tasks simulating a cascade
    let num_cancel = 500;
    for _ in 0..num_cancel {
        let cancel_id = {
            let mut guard = state.lock().unwrap();
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .unwrap();
            id
        };
        scheduler.inject_cancel(cancel_id, 100);
    }

    // Run worker
    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();

    let ready_completed = Arc::new(AtomicBool::new(false));

    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    // Wait with timeout for ready task
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(5);

    while start.elapsed() < timeout {
        if state.lock().unwrap().task(ready_id).is_none() {
            ready_completed.store(true, Ordering::Release);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    scheduler.shutdown();
    handle.join().unwrap();

    assert!(
        ready_completed.load(Ordering::Acquire),
        "Ready work starved by cancel cascade (waited {:?})",
        start.elapsed()
    );
}

/// Stress test with multiple workers.
#[test]
fn stress_multi_worker_lane_fairness() {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(4, &state);

    let num_per_lane = 100;
    let mut cancel_ids = Vec::new();
    let mut ready_ids = Vec::new();

    for _ in 0..num_per_lane {
        let c = {
            let mut guard = state.lock().unwrap();
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .unwrap();
            id
        };
        let r = {
            let mut guard = state.lock().unwrap();
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .unwrap();
            id
        };
        scheduler.inject_cancel(c, 100);
        scheduler.inject_ready(r, 100);
        cancel_ids.push(c);
        ready_ids.push(r);
    }

    // Run workers
    let workers = scheduler.take_workers();
    let handles: Vec<_> = workers
        .into_iter()
        .map(|mut worker| {
            std::thread::spawn(move || {
                worker.run_loop();
            })
        })
        .collect();

    std::thread::sleep(Duration::from_secs(1));
    scheduler.shutdown();

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify completion
    let guard = state.lock().unwrap();
    let cancel_done = cancel_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let ready_done = ready_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();

    assert_eq!(
        cancel_done, num_per_lane,
        "Cancel: {cancel_done}/{num_per_lane}"
    );
    assert_eq!(
        ready_done, num_per_lane,
        "Ready: {ready_done}/{num_per_lane}"
    );
}
