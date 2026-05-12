//! Fuzz same-owner mutex acquisition attempts against the live mutex API.
//!
//! The target keeps the oracle nonblocking: while a guard is held, immediate
//! `try_lock` paths must report `Locked`, and a single poll of `lock(&Cx)` must
//! park as a waiter. Dropping that pending future must remove the waiter before
//! the held guard is released.

#![no_main]

use std::future::Future;
use std::pin::pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Waker};

use arbitrary::Arbitrary;
use asupersync::cx::Cx;
use asupersync::sync::{Mutex, TryLockError};
use libfuzzer_sys::fuzz_target;

const MAX_SCENARIOS: usize = 24;
const MAX_RAPID_ATTEMPTS: u8 = 16;
const MAX_MIXED_ROUNDS: u8 = 8;

#[derive(Debug, Arbitrary)]
struct ReentrantConfig {
    initial_value: u32,
    scenarios: Vec<ReentrantScenario>,
}

#[derive(Debug, Clone, Arbitrary)]
enum ReentrantScenario {
    TryLockWhileHeld,
    OwnedTryLockWhileBorrowedHeld,
    PollLockWhileHeld,
    DropOrderReleases,
    RapidTryLock { attempts: u8 },
    Mixed { rounds: u8 },
}

#[derive(Debug, Default)]
struct ReentrantTracker {
    locked_observations: AtomicUsize,
    pending_observations: AtomicUsize,
    release_observations: AtomicUsize,
}

impl ReentrantTracker {
    fn observe_locked(&self) {
        self.locked_observations.fetch_add(1, Ordering::SeqCst);
    }

    fn observe_pending(&self) {
        self.pending_observations.fetch_add(1, Ordering::SeqCst);
    }

    fn observe_release(&self) {
        self.release_observations.fetch_add(1, Ordering::SeqCst);
    }

    fn observations(&self) -> usize {
        self.locked_observations.load(Ordering::SeqCst)
            + self.pending_observations.load(Ordering::SeqCst)
            + self.release_observations.load(Ordering::SeqCst)
    }
}

fuzz_target!(|case: ReentrantConfig| {
    let mutex = Arc::new(Mutex::new(case.initial_value));
    let tracker = ReentrantTracker::default();

    if case.scenarios.is_empty() {
        drive_scenario(&ReentrantScenario::TryLockWhileHeld, &mutex, &tracker);
    } else {
        for scenario in case.scenarios.iter().take(MAX_SCENARIOS) {
            drive_scenario(scenario, &mutex, &tracker);
        }
    }

    assert!(
        tracker.observations() > 0,
        "mutex reentrant target must execute at least one oracle"
    );
    assert_available(&mutex, &tracker);
});

fn drive_scenario(
    scenario: &ReentrantScenario,
    mutex: &Arc<Mutex<u32>>,
    tracker: &ReentrantTracker,
) {
    match scenario {
        ReentrantScenario::TryLockWhileHeld => assert_try_lock_blocks_while_held(mutex, tracker),
        ReentrantScenario::OwnedTryLockWhileBorrowedHeld => {
            assert_owned_try_lock_blocks_while_held(mutex, tracker);
        }
        ReentrantScenario::PollLockWhileHeld => assert_lock_future_parks_while_held(mutex, tracker),
        ReentrantScenario::DropOrderReleases => assert_drop_order_releases(mutex, tracker),
        ReentrantScenario::RapidTryLock { attempts } => {
            assert_rapid_try_lock_blocks_while_held(*attempts, mutex, tracker);
        }
        ReentrantScenario::Mixed { rounds } => {
            for round in 0..(*rounds).clamp(1, MAX_MIXED_ROUNDS) {
                match round % 4 {
                    0 => assert_try_lock_blocks_while_held(mutex, tracker),
                    1 => assert_owned_try_lock_blocks_while_held(mutex, tracker),
                    2 => assert_lock_future_parks_while_held(mutex, tracker),
                    _ => assert_drop_order_releases(mutex, tracker),
                }
            }
        }
    }
}

fn assert_try_lock_blocks_while_held(mutex: &Mutex<u32>, tracker: &ReentrantTracker) {
    let mut guard = mutex
        .try_lock()
        .expect("fresh mutex should allow first try_lock");
    *guard = (*guard).wrapping_add(1);

    match mutex.try_lock() {
        Err(TryLockError::Locked) => tracker.observe_locked(),
        Err(TryLockError::Poisoned) => panic!("fresh mutex should not be poisoned"),
        Ok(_) => panic!("same-owner try_lock unexpectedly reentered the mutex"),
    }

    drop(guard);
    assert_available(mutex, tracker);
}

fn assert_owned_try_lock_blocks_while_held(mutex: &Arc<Mutex<u32>>, tracker: &ReentrantTracker) {
    let mut guard = mutex
        .try_lock()
        .expect("fresh mutex should allow first borrowed guard");
    *guard = (*guard).wrapping_add(1);

    match mutex.try_lock_owned() {
        Err(TryLockError::Locked) => tracker.observe_locked(),
        Err(TryLockError::Poisoned) => panic!("fresh mutex should not be poisoned"),
        Ok(_) => panic!("owned try_lock unexpectedly reentered while borrowed guard was held"),
    }

    drop(guard);
    assert_available(mutex, tracker);
}

fn assert_lock_future_parks_while_held(mutex: &Mutex<u32>, tracker: &ReentrantTracker) {
    let mut guard = mutex
        .try_lock()
        .expect("fresh mutex should allow first try_lock");
    *guard = (*guard).wrapping_add(1);

    {
        let lock_cx = Cx::for_testing();
        let waker = Waker::noop().clone();
        let mut context = Context::from_waker(&waker);
        let mut future = pin!(mutex.lock(&lock_cx));

        match Future::poll(future.as_mut(), &mut context) {
            Poll::Pending => tracker.observe_pending(),
            Poll::Ready(Ok(_)) => panic!("lock future reentered a held mutex"),
            Poll::Ready(Err(err)) => panic!("fresh lock future failed unexpectedly: {err:?}"),
        }

        assert_eq!(
            mutex.waiters(),
            1,
            "pending lock future should register exactly one waiter"
        );
    }

    assert_eq!(
        mutex.waiters(),
        0,
        "dropping pending lock future should remove its waiter"
    );

    drop(guard);
    assert_available(mutex, tracker);
}

fn assert_drop_order_releases(mutex: &Mutex<u32>, tracker: &ReentrantTracker) {
    {
        let mut guard = mutex
            .try_lock()
            .expect("fresh mutex should allow first try_lock");
        *guard = (*guard).wrapping_add(1);
        assert!(mutex.is_locked(), "held guard should mark mutex locked");
    }

    assert_available(mutex, tracker);
}

fn assert_rapid_try_lock_blocks_while_held(
    attempts: u8,
    mutex: &Mutex<u32>,
    tracker: &ReentrantTracker,
) {
    let guard = mutex
        .try_lock()
        .expect("fresh mutex should allow first try_lock");
    let attempts = attempts.clamp(1, MAX_RAPID_ATTEMPTS);

    for _ in 0..attempts {
        match mutex.try_lock() {
            Err(TryLockError::Locked) => tracker.observe_locked(),
            Err(TryLockError::Poisoned) => panic!("fresh mutex should not be poisoned"),
            Ok(_) => panic!("rapid try_lock unexpectedly reentered the mutex"),
        }
    }

    drop(guard);
    assert_available(mutex, tracker);
}

fn assert_available(mutex: &Mutex<u32>, tracker: &ReentrantTracker) {
    assert_eq!(
        mutex.waiters(),
        0,
        "mutex should not retain waiters after local futures are dropped"
    );

    let _guard = mutex
        .try_lock()
        .expect("mutex should be immediately available after prior guard drops");
    tracker.observe_release();
}
