#![allow(clippy::all)]
#![allow(missing_docs)]
//! B3 Scheduler Wakeup & Cancellation Correctness Tests (br-legjy.2.3).
//!
//! Proves that the B2 scheduler changes (follower backoff, select_backoff_deadline)
//! preserve cancellation/wakeup correctness:
//!
//! 1. Every enqueued task is eventually dispatched (no lost wakeups)
//! 2. Workers do not park indefinitely when work is available
//! 3. Cancellation tasks still execute under follower backoff policy
//! 4. Mixed cancel/timed/ready workloads are all dispatched
//! 5. Multi-worker coordination delivers all tasks exactly once

mod common;

use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::three_lane::ThreeLaneScheduler;
use asupersync::sync::ContendedMutex;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{Budget, TaskId, Time};
use common::init_test_logging;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup_state() -> Arc<ContendedMutex<RuntimeState>> {
    Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()))
}

fn setup_state_with_clock() -> (Arc<ContendedMutex<RuntimeState>>, Arc<VirtualClock>) {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1_000)));
    let mut rs = RuntimeState::new();
    rs.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));
    (Arc::new(ContendedMutex::new("runtime_state", rs)), clock)
}

fn create_task(
    state: &Arc<ContendedMutex<RuntimeState>>,
    region: asupersync::types::RegionId,
) -> TaskId {
    let mut guard = state.lock().unwrap();
    let (id, _) = guard
        .create_task(region, Budget::INFINITE, async {})
        .unwrap();
    id
}

fn create_counting_task(
    state: &Arc<ContendedMutex<RuntimeState>>,
    region: asupersync::types::RegionId,
    counter: Arc<AtomicUsize>,
) -> TaskId {
    let mut guard = state.lock().unwrap();
    let (id, _) = guard
        .create_task(region, Budget::INFINITE, async move {
            counter.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    id
}

// ===========================================================================
// WAKEUP CORRECTNESS: NO LOST TASKS
// ===========================================================================

/// Verify that all injected ready tasks are dispatched by a single worker.
/// Tests the core invariant: inject → unpark → dispatch for every task.
#[test]
fn all_ready_tasks_dispatched_single_worker() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let counter = Arc::new(AtomicUsize::new(0));

    let n = 50;
    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    for _ in 0..n {
        let id = create_counting_task(&state, region, Arc::clone(&counter));
        scheduler.inject_ready(id, 100);
    }

    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();
    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    std::thread::sleep(Duration::from_millis(500));
    scheduler.shutdown();
    handle.join().unwrap();

    let dispatched = counter.load(Ordering::SeqCst);
    assert_eq!(
        dispatched, n,
        "all {n} ready tasks must be dispatched, got {dispatched}"
    );
}

/// Verify that all cancel tasks are dispatched despite follower backoff.
#[test]
fn all_cancel_tasks_dispatched_single_worker() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let counter = Arc::new(AtomicUsize::new(0));

    let n = 40;
    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    for _ in 0..n {
        let id = create_counting_task(&state, region, Arc::clone(&counter));
        scheduler.inject_cancel(id, 100);
    }

    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();
    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    std::thread::sleep(Duration::from_millis(500));
    scheduler.shutdown();
    handle.join().unwrap();

    let dispatched = counter.load(Ordering::SeqCst);
    assert_eq!(
        dispatched, n,
        "all {n} cancel tasks must be dispatched, got {dispatched}"
    );
}

/// Mixed workload: cancel + ready + timed tasks all dispatched completely.
#[test]
fn mixed_cancel_ready_timed_all_dispatched() {
    init_test_logging();
    let (state, clock) = setup_state_with_clock();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let cancel_counter = Arc::new(AtomicUsize::new(0));
    let ready_counter = Arc::new(AtomicUsize::new(0));
    let timed_counter = Arc::new(AtomicUsize::new(0));

    let n_cancel = 20;
    let n_ready = 20;
    let n_timed = 10;

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    for _ in 0..n_cancel {
        let id = create_counting_task(&state, region, Arc::clone(&cancel_counter));
        scheduler.inject_cancel(id, 100);
    }
    for _ in 0..n_ready {
        let id = create_counting_task(&state, region, Arc::clone(&ready_counter));
        scheduler.inject_ready(id, 100);
    }
    // Timed tasks due immediately
    for _ in 0..n_timed {
        let id = create_counting_task(&state, region, Arc::clone(&timed_counter));
        scheduler.inject_timed(id, Time::from_nanos(500));
    }

    // Advance clock past timed deadlines
    clock.advance(1_000_000); // 1ms in nanos

    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();
    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    std::thread::sleep(Duration::from_millis(500));
    scheduler.shutdown();
    handle.join().unwrap();

    let c = cancel_counter.load(Ordering::SeqCst);
    let r = ready_counter.load(Ordering::SeqCst);
    let t = timed_counter.load(Ordering::SeqCst);

    assert_eq!(c, n_cancel, "cancel: expected {n_cancel}, got {c}");
    assert_eq!(r, n_ready, "ready: expected {n_ready}, got {r}");
    assert_eq!(t, n_timed, "timed: expected {n_timed}, got {t}");
}

// ===========================================================================
// MULTI-WORKER CORRECTNESS
// ===========================================================================

/// Verify all tasks dispatched exactly once across multiple workers.
#[test]
fn multi_worker_all_tasks_dispatched_exactly_once() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let counter = Arc::new(AtomicUsize::new(0));

    let n = 100;
    let num_workers = 4;
    let mut scheduler = ThreeLaneScheduler::new(num_workers, &state);

    for _ in 0..n {
        let id = create_counting_task(&state, region, Arc::clone(&counter));
        scheduler.inject_ready(id, 100);
    }

    let workers = scheduler.take_workers();
    let handles: Vec<_> = workers
        .into_iter()
        .map(|mut worker| {
            std::thread::spawn(move || {
                worker.run_loop();
            })
        })
        .collect();

    std::thread::sleep(Duration::from_millis(500));
    scheduler.shutdown();
    for h in handles {
        h.join().unwrap();
    }

    let dispatched = counter.load(Ordering::SeqCst);
    assert_eq!(
        dispatched, n,
        "all {n} tasks dispatched exactly once across {num_workers} workers, got {dispatched}"
    );
}

/// Multi-worker mixed workload: interleaved cancel and ready tasks.
#[test]
fn multi_worker_mixed_cancel_ready() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let cancel_counter = Arc::new(AtomicUsize::new(0));
    let ready_counter = Arc::new(AtomicUsize::new(0));

    let n_cancel = 40;
    let n_ready = 40;
    let num_workers = 3;
    let mut scheduler = ThreeLaneScheduler::new(num_workers, &state);

    // Interleave cancel and ready
    for i in 0..(n_cancel + n_ready) {
        if i % 2 == 0 && (i / 2) < n_cancel {
            let id = create_counting_task(&state, region, Arc::clone(&cancel_counter));
            scheduler.inject_cancel(id, 100);
        } else {
            let id = create_counting_task(&state, region, Arc::clone(&ready_counter));
            scheduler.inject_ready(id, 100);
        }
    }

    let workers = scheduler.take_workers();
    let handles: Vec<_> = workers
        .into_iter()
        .map(|mut worker| {
            std::thread::spawn(move || {
                worker.run_loop();
            })
        })
        .collect();

    std::thread::sleep(Duration::from_millis(500));
    scheduler.shutdown();
    for h in handles {
        h.join().unwrap();
    }

    let c = cancel_counter.load(Ordering::SeqCst);
    let r = ready_counter.load(Ordering::SeqCst);
    assert_eq!(c, n_cancel, "cancel: expected {n_cancel}, got {c}");
    assert_eq!(r, n_ready, "ready: expected {n_ready}, got {r}");
}

// ===========================================================================
// LATE INJECTION: TASKS INJECTED AFTER WORKERS START
// ===========================================================================

/// Tasks injected after workers start running should still be dispatched
/// (verifies wakeup signal reaches parked workers).
#[test]
fn late_injection_wakes_parked_worker() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let counter = Arc::new(AtomicUsize::new(0));

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    // Start workers first with no work → they should park
    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();
    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    // Let worker park
    std::thread::sleep(Duration::from_millis(50));

    // Inject tasks after worker is parked
    let n = 20;
    for _ in 0..n {
        let id = create_counting_task(&state, region, Arc::clone(&counter));
        scheduler.inject_ready(id, 100);
    }

    // Wait for dispatch
    std::thread::sleep(Duration::from_millis(500));
    scheduler.shutdown();
    handle.join().unwrap();

    let dispatched = counter.load(Ordering::SeqCst);
    assert_eq!(
        dispatched, n,
        "late-injected tasks must wake parked worker: expected {n}, got {dispatched}"
    );
}

/// Late cancel injection wakes parked workers.
#[test]
fn late_cancel_injection_wakes_parked_worker() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let counter = Arc::new(AtomicUsize::new(0));

    let mut scheduler = ThreeLaneScheduler::new(2, &state);

    let workers = scheduler.take_workers();
    let handles: Vec<_> = workers
        .into_iter()
        .map(|mut w| std::thread::spawn(move || w.run_loop()))
        .collect();

    // Let workers park
    std::thread::sleep(Duration::from_millis(50));

    let n = 30;
    for _ in 0..n {
        let id = create_counting_task(&state, region, Arc::clone(&counter));
        scheduler.inject_cancel(id, 100);
    }

    std::thread::sleep(Duration::from_millis(500));
    scheduler.shutdown();
    for h in handles {
        h.join().unwrap();
    }

    let dispatched = counter.load(Ordering::SeqCst);
    assert_eq!(
        dispatched, n,
        "late cancel tasks must wake workers: expected {n}, got {dispatched}"
    );
}

// ===========================================================================
// STAGGERED INJECTION STRESS
// ===========================================================================

/// Inject tasks in waves with gaps, verifying workers wake and sleep correctly.
#[test]
fn staggered_injection_waves() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let counter = Arc::new(AtomicUsize::new(0));

    let mut scheduler = ThreeLaneScheduler::new(2, &state);

    let workers = scheduler.take_workers();
    let handles: Vec<_> = workers
        .into_iter()
        .map(|mut w| std::thread::spawn(move || w.run_loop()))
        .collect();

    let total = 60;
    let waves = 3;
    let per_wave = total / waves;

    for _wave in 0..waves {
        // Inject batch
        for _ in 0..per_wave {
            let id = create_counting_task(&state, region, Arc::clone(&counter));
            scheduler.inject_ready(id, 100);
        }
        // Wait for dispatch + allow re-park
        std::thread::sleep(Duration::from_millis(100));
    }

    std::thread::sleep(Duration::from_millis(200));
    scheduler.shutdown();
    for h in handles {
        h.join().unwrap();
    }

    let dispatched = counter.load(Ordering::SeqCst);
    assert_eq!(
        dispatched, total,
        "staggered waves: expected {total}, got {dispatched}"
    );
}

// ===========================================================================
// CONCURRENT ENQUEUE + PARK RACE
// ===========================================================================

/// Rapidly enqueue single tasks while workers are cycling between active/park.
/// Tests the race window between empty-queue check and park entry.
#[test]
fn rapid_single_task_enqueue_no_lost_wakeup() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let counter = Arc::new(AtomicUsize::new(0));

    let mut scheduler = ThreeLaneScheduler::new(2, &state);

    let workers = scheduler.take_workers();
    let handles: Vec<_> = workers
        .into_iter()
        .map(|mut w| std::thread::spawn(move || w.run_loop()))
        .collect();

    let n = 200;
    for _ in 0..n {
        let id = create_counting_task(&state, region, Arc::clone(&counter));
        scheduler.inject_ready(id, 100);
        // Small gaps to maximize park/unpark cycling
        std::thread::yield_now();
    }

    std::thread::sleep(Duration::from_millis(500));
    scheduler.shutdown();
    for h in handles {
        h.join().unwrap();
    }

    let dispatched = counter.load(Ordering::SeqCst);
    assert_eq!(
        dispatched, n,
        "rapid enqueue: no lost wakeups — expected {n}, got {dispatched}"
    );
}

// ===========================================================================
// CANCEL STREAK RESETS AFTER BACKOFF
// ===========================================================================

/// After backoff/park, cancel_streak resets to 0, allowing subsequent cancel
/// tasks to execute without fairness-yield overhead.
#[test]
fn cancel_streak_resets_after_park_cycle() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let counter = Arc::new(AtomicUsize::new(0));

    let cancel_limit = 4;
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_limit);

    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();
    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    // Wait for worker to park (no work yet)
    std::thread::sleep(Duration::from_millis(50));

    // First wave: cancel_limit cancel tasks (should all execute from streak=0)
    for _ in 0..cancel_limit {
        let id = create_counting_task(&state, region, Arc::clone(&counter));
        scheduler.inject_cancel(id, 100);
    }
    std::thread::sleep(Duration::from_millis(100));

    // Wait for park again
    std::thread::sleep(Duration::from_millis(50));

    // Second wave: after park, streak should be 0 again
    for _ in 0..cancel_limit {
        let id = create_counting_task(&state, region, Arc::clone(&counter));
        scheduler.inject_cancel(id, 100);
    }
    std::thread::sleep(Duration::from_millis(100));

    scheduler.shutdown();
    handle.join().unwrap();

    let dispatched = counter.load(Ordering::SeqCst);
    assert_eq!(
        dispatched,
        cancel_limit * 2,
        "cancel streak must reset after park: expected {}, got {dispatched}",
        cancel_limit * 2
    );
}

// ===========================================================================
// SHUTDOWN SAFETY
// ===========================================================================

/// Workers must drain all pending work before exiting on shutdown.
#[test]
fn shutdown_drains_pending_work() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let counter = Arc::new(AtomicUsize::new(0));

    let n = 30;
    let mut scheduler = ThreeLaneScheduler::new(2, &state);

    for _ in 0..n {
        let id = create_counting_task(&state, region, Arc::clone(&counter));
        scheduler.inject_ready(id, 100);
    }

    let workers = scheduler.take_workers();
    let handles: Vec<_> = workers
        .into_iter()
        .map(|mut w| std::thread::spawn(move || w.run_loop()))
        .collect();

    // Brief execution time, then immediate shutdown
    std::thread::sleep(Duration::from_millis(50));
    scheduler.shutdown();

    for h in handles {
        h.join().unwrap();
    }

    let dispatched = counter.load(Ordering::SeqCst);
    assert_eq!(
        dispatched, n,
        "shutdown must drain pending work: expected {n}, got {dispatched}"
    );
}

// ===========================================================================
// METRICS CORRECTNESS AFTER B2 CHANGES
// ===========================================================================

/// Preemption fairness certificate invariant holds under mixed workload.
#[test]
fn fairness_certificate_invariant_holds() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let cancel_limit = 4;
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_limit);

    // Mixed workload
    for _ in 0..20 {
        let id = create_task(&state, region);
        scheduler.inject_cancel(id, 100);
    }
    for _ in 0..10 {
        let id = create_task(&state, region);
        scheduler.inject_ready(id, 100);
    }

    let mut workers = scheduler.take_workers();
    let mut worker = workers.pop().unwrap();

    let mut dispatched = 0;
    while worker.next_task().is_some() {
        dispatched += 1;
        if dispatched > 50 {
            break;
        }
    }

    let cert = worker.preemption_fairness_certificate();
    assert!(
        cert.invariant_holds(),
        "fairness certificate invariant must hold after mixed dispatch"
    );
    assert!(
        cert.ready_stall_bound_steps() <= cancel_limit + 1,
        "ready stall bound {} exceeds expected {}",
        cert.ready_stall_bound_steps(),
        cancel_limit + 1
    );
}

/// Backoff metrics are consistent: total parks = timeout + indefinite.
#[test]
fn backoff_metrics_consistency() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let counter = Arc::new(AtomicUsize::new(0));

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    // Start worker, wait for it to park, inject work, let it run, shutdown
    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();

    let metrics_holder: Arc<
        std::sync::Mutex<Option<asupersync::runtime::scheduler::three_lane::PreemptionMetrics>>,
    > = Arc::new(std::sync::Mutex::new(None));
    let mh = metrics_holder.clone();

    let handle = std::thread::spawn(move || {
        worker.run_loop();
        *mh.lock().unwrap() = Some(worker.preemption_metrics().clone());
    });

    // Let worker park
    std::thread::sleep(Duration::from_millis(30));

    // Inject then shutdown
    for _ in 0..5 {
        let id = create_counting_task(&state, region, Arc::clone(&counter));
        scheduler.inject_ready(id, 100);
    }
    std::thread::sleep(Duration::from_millis(100));
    scheduler.shutdown();
    handle.join().unwrap();

    if let Some(metrics) = metrics_holder.lock().unwrap().as_ref() {
        assert_eq!(
            metrics.backoff_parks_total,
            metrics.backoff_timeout_parks_total + metrics.backoff_indefinite_parks,
            "total parks must equal timeout + indefinite"
        );
        assert!(
            metrics.follower_timeout_parks <= metrics.backoff_timeout_parks_total,
            "follower timeout parks cannot exceed total timeout parks"
        );
        assert!(
            metrics.follower_indefinite_parks <= metrics.backoff_indefinite_parks,
            "follower indefinite parks cannot exceed total indefinite parks"
        );
    }
}

// ===========================================================================
// TAIL LATENCY BOUND
// ===========================================================================

/// Verify that task dispatch latency stays within acceptable bounds.
/// A task injected into an idle scheduler should dispatch within 100ms.
#[test]
fn dispatch_latency_under_100ms() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let dispatch_time = Arc::new(std::sync::Mutex::new(None));
    let dt = dispatch_time.clone();

    let mut guard = state.lock().unwrap();
    let (id, _) = guard
        .create_task(region, Budget::INFINITE, async move {
            *dt.lock().unwrap() = Some(Instant::now());
        })
        .unwrap();
    drop(guard);

    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    let workers = scheduler.take_workers();
    let mut worker = workers.into_iter().next().unwrap();
    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    // Let worker park
    std::thread::sleep(Duration::from_millis(50));

    let inject_time = Instant::now();
    scheduler.inject_ready(id, 100);

    // Wait for dispatch
    std::thread::sleep(Duration::from_millis(200));
    scheduler.shutdown();
    handle.join().unwrap();

    let dispatched_at = {
        let guard = dispatch_time.lock().unwrap();
        *guard
    };
    if let Some(dispatched_at) = dispatched_at {
        let latency = dispatched_at.duration_since(inject_time);
        assert!(
            latency < Duration::from_millis(100),
            "dispatch latency {latency:?} exceeds 100ms SLO"
        );
    } else {
        panic!("task was never dispatched");
    }
}
