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

/// An earlier timer published after the reactor selected a long timeout must
/// interrupt that wait and retire the actual task without another timer pump.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "windows",
))]
#[test]
fn earlier_timer_publication_interrupts_selected_native_reactor_timeout() {
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::runtime::reactor::{
        Events, Interest, IoReactorCapabilitySnapshot, Reactor, Source, Token, create_reactor,
    };
    use std::future::Future;
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Mutex, mpsc};
    use std::task::{Context, Poll, Wake, Waker};

    const WAIT: Duration = Duration::from_secs(2);
    const FAR: Duration = Duration::from_secs(60);
    const NEAR: Duration = Duration::from_millis(10);

    struct ControlledReactor {
        inner: Arc<dyn Reactor>,
        arm: AtomicBool,
        selected: mpsc::Sender<Duration>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl Reactor for ControlledReactor {
        fn capability_snapshot(&self) -> IoReactorCapabilitySnapshot {
            self.inner.capability_snapshot()
        }

        fn register(
            &self,
            source: &dyn Source,
            token: Token,
            interest: Interest,
        ) -> io::Result<()> {
            self.inner.register(source, token, interest)
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            self.inner.modify(token, interest)
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            self.inner.deregister(token)
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            if let Some(selected) = timeout.filter(|duration| *duration > FAR / 2)
                && self.arm.swap(false, Ordering::AcqRel)
            {
                // Remove startup/spawn wake permits before exposing the frozen
                // timeout. No sources are registered in this test. A timer
                // publication during the gate must create a NEW native permit.
                if self.inner.poll(events, Some(Duration::ZERO))? != 0 {
                    return Err(io::Error::other("unexpected I/O in timer-only probe"));
                }
                self.selected
                    .send(selected)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                self.release
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv_timeout(WAIT)
                    .map_err(|error| io::Error::other(error.to_string()))?;
            }
            // Preserve the timeout the scheduler already selected. The real
            // kernel backend, including its wake permit, decides when to return.
            self.inner.poll(events, timeout)
        }

        fn wake(&self) -> io::Result<()> {
            self.inner.wake()
        }

        fn registration_count(&self) -> usize {
            self.inner.registration_count()
        }
    }

    struct ReadyWake {
        ready: Arc<AtomicBool>,
        task: Option<Waker>,
    }

    impl Wake for ReadyWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.ready.store(true, Ordering::Release);
            if let Some(task) = &self.task {
                task.wake_by_ref();
            }
        }
    }

    struct Probe {
        ready: Arc<AtomicBool>,
        first_poll: Option<mpsc::Sender<Waker>>,
        dropped: Arc<AtomicUsize>,
        retired: mpsc::Sender<()>,
    }

    impl Future for Probe {
        type Output = usize;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
            if self.ready.load(Ordering::Acquire) {
                Poll::Ready(42)
            } else {
                if let Some(first_poll) = self.first_poll.take() {
                    let _ = first_poll.send(cx.waker().clone());
                }
                Poll::Pending
            }
        }
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::AcqRel);
            let _ = self.retired.send(());
        }
    }

    init_test_logging();
    let (selected_tx, selected_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let reactor = Arc::new(ControlledReactor {
        inner: create_reactor().expect("create native platform reactor"),
        arm: AtomicBool::new(false),
        selected: selected_tx,
        release: Mutex::new(release_rx),
    });
    let timer = TimerDriverHandle::with_wall_clock();
    let far_fired = Arc::new(AtomicBool::new(false));
    let far = timer.register(
        timer.now() + FAR,
        Waker::from(Arc::new(ReadyWake {
            ready: Arc::clone(&far_fired),
            task: None,
        })),
    );
    // A single worker excludes an incidental second-worker timer pump while
    // its reactor timeout is frozen. The caller never uses Runtime::block_on.
    let runtime = RuntimeBuilder::new()
        .worker_threads(1)
        .with_reactor(reactor.clone())
        .with_timer_driver(timer.clone())
        .build()
        .expect("build native timer probe runtime");
    let (first_tx, first_rx) = mpsc::channel();
    let (retired_tx, retired_rx) = mpsc::channel();
    let ready = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut task = runtime
        .handle()
        .try_spawn(Probe {
            ready: Arc::clone(&ready),
            first_poll: Some(first_tx),
            dropped: Arc::clone(&dropped),
            retired: retired_tx,
        })
        .expect("spawn native timer probe");
    let mut near = None;
    let observed = (|| -> Result<(Duration, usize, bool), String> {
        let task_waker = first_rx
            .recv_timeout(WAIT)
            .map_err(|error| format!("probe first Pending poll: {error}"))?;
        reactor.arm.store(true, Ordering::Release);
        // This setup wake precedes the controlled handoff and is explicitly
        // drained by the wrapper; it cannot deliver the later timer's wake.
        reactor.wake().map_err(|error| error.to_string())?;
        let selected = selected_rx
            .recv_timeout(WAIT)
            .map_err(|error| format!("selected long reactor timeout: {error}"))?;
        near = Some(timer.register(
            timer.now() + NEAR,
            Waker::from(Arc::new(ReadyWake {
                ready: Arc::clone(&ready),
                task: Some(task_waker),
            })),
        ));
        release_tx.send(()).map_err(|error| error.to_string())?;
        retired_rx.recv_timeout(WAIT).map_err(|error| {
            format!(
                "earlier timer did not retire task while native reactor held {selected:?}: {error}"
            )
        })?;
        Ok((
            selected,
            dropped.load(Ordering::Acquire),
            far_fired.load(Ordering::Acquire),
        ))
    })();

    // Release both the handshake and native poll before asserting, including
    // the expected old-code failure. Shutdown then joins the worker normally.
    let _ = release_tx.send(());
    if let Some(near) = near {
        let _ = timer.cancel(&near);
    }
    let _ = timer.cancel(&far);
    let _ = reactor.wake();
    drop(runtime);

    let (selected, dropped_before_cleanup, far_fired_before_cleanup) =
        observed.expect("earlier timer publication must interrupt the selected native wait");
    assert!(
        selected > FAR / 2,
        "the old long timeout was actually selected"
    );
    assert_eq!(
        dropped_before_cleanup, 1,
        "actual future retired before cleanup"
    );
    assert!(
        !far_fired_before_cleanup,
        "near timer must beat the far timer"
    );
    assert_eq!(
        dropped.load(Ordering::Acquire),
        1,
        "future drops exactly once"
    );
    assert!(
        ready.load(Ordering::Acquire),
        "the timer delivered readiness"
    );
    assert_eq!(
        Pin::new(&mut task).poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(42),
        "actual task result survives terminal publication and shutdown",
    );
}
