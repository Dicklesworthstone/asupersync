#![allow(warnings)]
#![allow(clippy::all)]
//! Integration target for sync mutex poisoning metamorphic relations.

use asupersync::lab::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::sync::{LockError, Mutex, TryLockError};
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use asupersync::{Cx, RegionId, TaskId};
use std::sync::Arc;

fn create_test_context(region_id: u32, task_id: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(region_id, 0)),
        TaskId::from_arena(ArenaIndex::new(task_id, 0)),
        Budget::INFINITE,
    )
}

fn poison_mutex(mutex: &Arc<Mutex<u32>>) {
    let poison_target = Arc::clone(mutex);
    let handle = std::thread::spawn(move || {
        let cx = create_test_context(1, 1);
        let _lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on::<()>(async move {
            let mut guard = poison_target
                .lock(&cx)
                .await
                .expect("poison lock should succeed");
            *guard += 1;
            panic!("deliberate panic to poison mutex");
        });
    });

    let _ = handle.join();
}

#[test]
fn mr_poison_observation_is_idempotent_for_repeated_probes() {
    let mutex = Arc::new(Mutex::new(41u32));
    poison_mutex(&mutex);

    assert!(mutex.is_poisoned(), "mutex should be poisoned after panic");
    assert_eq!(mutex.waiters(), 0, "poisoning should not strand waiters");

    for probe in 0..4 {
        let cx = create_test_context((probe + 2) as u32, (probe + 2) as u32);
        let cloned = Arc::clone(&mutex);
        let lock_result = futures_lite::future::block_on(async move {
            match cloned.lock(&cx).await {
                Ok(_guard) => Ok(()),
                Err(err) => Err(err),
            }
        });
        assert!(
            matches!(lock_result, Err(LockError::Poisoned)),
            "async poison probe {probe} should stay Poisoned, got {:?}",
            lock_result
        );

        let try_result = mutex.try_lock();
        assert!(
            matches!(try_result, Err(TryLockError::Poisoned)),
            "try_lock poison probe {probe} should stay Poisoned, got {:?}",
            try_result
        );

        assert!(mutex.is_poisoned(), "probe {probe} should not clear poison");
        assert_eq!(
            mutex.waiters(),
            0,
            "probe {probe} should not leave queued waiters"
        );
    }
}

#[test]
fn mr_late_waiter_after_poison_matches_direct_probe() {
    let mutex = Arc::new(Mutex::new(7u32));
    poison_mutex(&mutex);

    let direct = mutex.try_lock();
    assert!(
        matches!(direct, Err(TryLockError::Poisoned)),
        "direct probe should report poison, got {:?}",
        direct
    );

    let late_waiter = Arc::clone(&mutex);
    let handle = std::thread::spawn(move || {
        let cx = create_test_context(8, 8);
        let _lab = LabRuntime::new(LabConfig::default());
        futures_lite::future::block_on(async move {
            match late_waiter.lock(&cx).await {
                Ok(_guard) => Ok(()),
                Err(err) => Err(err),
            }
        })
    });

    let late_result = handle.join().expect("late waiter thread should not panic");
    assert!(
        matches!(late_result, Err(LockError::Poisoned)),
        "late waiter should match direct poison probe, got {:?}",
        late_result
    );
    assert_eq!(
        mutex.waiters(),
        0,
        "late poisoned waiters should not accumulate"
    );
}
