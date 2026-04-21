#![allow(missing_docs)]

//! Integration target for sync fairness metamorphic relations.

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::yield_now;
use asupersync::sync::{Mutex, RwLock, TryLockError};
use asupersync::types::Budget;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

const MUTEX_WAITERS: usize = 3;
const RWLOCK_SPIN_LIMIT: usize = 32;

fn mutex_handoff_order(seed: u64, try_lock_noise: usize) -> Vec<usize> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(4_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mutex = Arc::new(Mutex::new(0usize));
    let acquisition_order = Arc::new(StdMutex::new(Vec::new()));
    let completed = Arc::new(AtomicUsize::new(0));
    let initial_guard = mutex.try_lock().expect("seed initial mutex guard");

    for waiter_id in 0..MUTEX_WAITERS {
        let mutex = Arc::clone(&mutex);
        let acquisition_order = Arc::clone(&acquisition_order);
        let completed = Arc::clone(&completed);
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::for_testing();
                let mut guard = mutex.lock(&cx).await.expect("mutex waiter acquires");
                acquisition_order.lock().expect("order lock").push(waiter_id);
                *guard += 1;
                yield_now().await;
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create mutex waiter");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    let mut steps = 0usize;
    while mutex.waiters() < MUTEX_WAITERS && steps < RWLOCK_SPIN_LIMIT {
        runtime.step_for_test();
        steps += 1;
    }
    assert_eq!(
        mutex.waiters(),
        MUTEX_WAITERS,
        "all mutex waiters should be queued before release"
    );

    for _ in 0..try_lock_noise {
        assert!(
            matches!(mutex.try_lock(), Err(TryLockError::Locked)),
            "observation noise must not steal the held mutex"
        );
        runtime.step_for_test();
    }

    drop(initial_guard);
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "mutex fairness run violated invariants: {violations:?}"
    );
    assert_eq!(
        completed.load(Ordering::SeqCst),
        MUTEX_WAITERS,
        "all mutex waiters should complete"
    );

    let final_value = {
        let guard = mutex.try_lock().expect("final mutex lock");
        *guard
    };
    assert_eq!(
        final_value, MUTEX_WAITERS,
        "each waiter should have incremented the shared state once"
    );

    acquisition_order.lock().expect("final order lock").clone()
}

fn rwlock_writer_preference_trace(seed: u64, late_readers: usize) -> Vec<String> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(8_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let rwlock = Arc::new(RwLock::new(0u32));
    let events = Arc::new(StdMutex::new(Vec::new()));
    let completed = Arc::new(AtomicUsize::new(0));
    let initial_reader = rwlock.try_read().expect("seed initial reader");

    {
        let rwlock = Arc::clone(&rwlock);
        let events = Arc::clone(&events);
        let completed = Arc::clone(&completed);
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::for_testing();
                events
                    .lock()
                    .expect("events lock")
                    .push("writer_waiting".to_string());
                let mut guard = rwlock.write(&cx).await.expect("writer acquires");
                events
                    .lock()
                    .expect("events lock")
                    .push("writer_acquired".to_string());
                *guard += 1;
                yield_now().await;
                events
                    .lock()
                    .expect("events lock")
                    .push("writer_released".to_string());
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create writer waiter");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    let mut spins = 0usize;
    while spins < RWLOCK_SPIN_LIMIT {
        runtime.step_for_test();
        if events
            .lock()
            .expect("events lock")
            .iter()
            .any(|event| event == "writer_waiting")
        {
            break;
        }
        spins += 1;
    }
    assert!(
        events
            .lock()
            .expect("events lock")
            .iter()
            .any(|event| event == "writer_waiting"),
        "writer should be queued before late readers are introduced"
    );

    for reader_id in 0..late_readers {
        let rwlock = Arc::clone(&rwlock);
        let events = Arc::clone(&events);
        let completed = Arc::clone(&completed);
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::for_testing();
                events
                    .lock()
                    .expect("events lock")
                    .push(format!("reader_{reader_id}_waiting"));
                let guard = rwlock.read(&cx).await.expect("late reader acquires");
                let value = *guard;
                events
                    .lock()
                    .expect("events lock")
                    .push(format!("reader_{reader_id}_acquired_after_{value}"));
                yield_now().await;
                events
                    .lock()
                    .expect("events lock")
                    .push(format!("reader_{reader_id}_released"));
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create late reader");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    let mut spins = 0usize;
    while completed.load(Ordering::SeqCst) == 0 && spins < RWLOCK_SPIN_LIMIT {
        runtime.step_for_test();
        let waiting_entries = events.lock().expect("events lock").len();
        if waiting_entries > late_readers {
            break;
        }
        spins += 1;
    }

    drop(initial_reader);
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "rwlock fairness run violated invariants: {violations:?}"
    );
    assert_eq!(
        completed.load(Ordering::SeqCst),
        late_readers + 1,
        "writer and all late readers should complete"
    );

    events.lock().expect("final events lock").clone()
}

#[test]
fn mr_mutex_fifo_handoff_survives_pre_release_try_lock_noise() {
    for seed in [0x5eed_u64, 0x5eed_u64 + 7] {
        let baseline = mutex_handoff_order(seed, 0);
        let noisy = mutex_handoff_order(seed, 8);

        assert_eq!(
            baseline.len(),
            MUTEX_WAITERS,
            "baseline should hand off to every queued mutex waiter"
        );
        assert_eq!(
            noisy, baseline,
            "extra pre-release try_lock noise must not perturb mutex FIFO handoff"
        );
    }
}

#[test]
fn mr_rwlock_waiting_writer_beats_late_reader_amplification() {
    for &(seed, late_readers) in &[(0x7001_u64, 1usize), (0x7001_u64, 3usize)] {
        let trace = rwlock_writer_preference_trace(seed, late_readers);
        let writer_acquired = trace
            .iter()
            .position(|event| event == "writer_acquired")
            .expect("writer acquisition recorded");
        let first_reader_acquired = trace
            .iter()
            .position(|event| event.contains("_acquired_after_"))
            .expect("reader acquisition recorded");
        let reader_acquires = trace
            .iter()
            .filter(|event| event.contains("_acquired_after_"))
            .count();

        assert!(
            writer_acquired < first_reader_acquired,
            "queued writer must acquire before any late reader: {trace:?}"
        );
        assert_eq!(
            reader_acquires, late_readers,
            "all amplified late readers should still make progress"
        );
        assert!(
            trace
                .iter()
                .filter(|event| event.as_str() == "writer_acquired")
                .count()
                == 1,
            "writer should acquire exactly once: {trace:?}"
        );
    }
}
