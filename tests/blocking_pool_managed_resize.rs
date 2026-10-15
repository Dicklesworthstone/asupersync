//! Integration proof for runtime-mutable blocking-pool spawn cap + managed
//! resize (br-asupersync-adaptive-control-plane-yj2nxx.7, slice 3).
//!
//! The blocking pool gates worker spawns on a live `current_max_threads()` cap
//! (within `[min_threads, max_threads]`), so a managed pool-sizing decision can
//! throttle the pool's concurrency. The configured `max_threads` stays the hard
//! ceiling; a shrink only blocks new spawns — threads above the cap retire
//! naturally, preserving the pool's atomic claim/retire invariants.
//!
//! Standalone integration test (one small crate linking the lib) so it is immune
//! to peer `#[cfg(test)]` breakage in the shared tree.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use asupersync::runtime::BlockingPool;
use asupersync::runtime::pool_sizing::{
    PoolSizingAction, PoolSizingBounds, PoolSizingControllerState, PoolSizingPolicy,
    PoolSizingTarget, PoolWorkloadEstimate, decide_pool_sizing,
};

#[test]
fn set_max_threads_clamps_into_configured_bounds() {
    // Floor = min_threads = 1, ceiling = max_threads = 8.
    let pool = BlockingPool::new(1, 8);
    assert_eq!(
        pool.current_max_threads(),
        8,
        "live cap starts at the ceiling"
    );
    assert_eq!(pool.set_max_threads(100), 8, "above ceiling clamps down");
    assert_eq!(
        pool.set_max_threads(0),
        1,
        "below floor clamps up to min_threads"
    );
    assert_eq!(pool.set_max_threads(4), 4, "in-range applied verbatim");
    assert_eq!(pool.current_max_threads(), 4);
    // pool_sizing_bounds keeps reporting the configured floor/ceiling.
    assert_eq!(pool.pool_sizing_bounds(), PoolSizingBounds::new(1, 8));
}

#[test]
fn apply_pool_sizing_decision_drives_the_spawn_cap() {
    let pool = BlockingPool::new(1, 8);
    assert_eq!(pool.current_max_threads(), 8);

    let bounds = PoolSizingBounds::new(1, 8);
    let policy =
        PoolSizingPolicy::managed(bounds, PoolSizingTarget::conservative_wait_probability());
    let state = PoolSizingControllerState {
        current_size: pool.current_max_threads(),
        last_resize_epoch: 0,
    };
    // No observed load => recommendation collapses to the floor; managed mode
    // resizes 8 -> 1.
    let idle_estimate = PoolWorkloadEstimate::new(0, 0, 0);
    let decision = decide_pool_sizing(policy, state, idle_estimate, 5);
    assert!(matches!(decision.action, PoolSizingAction::Resize { .. }));
    assert_eq!(pool.apply_pool_sizing_decision(&decision), Some(1));
    assert_eq!(pool.current_max_threads(), 1);

    // Advisory decisions never mutate the cap.
    let advisory = decide_pool_sizing(
        PoolSizingPolicy::advisory(bounds),
        PoolSizingControllerState {
            current_size: 1,
            last_resize_epoch: 0,
        },
        idle_estimate,
        6,
    );
    assert_eq!(pool.apply_pool_sizing_decision(&advisory), None);
    assert_eq!(pool.current_max_threads(), 1);
}

#[test]
fn shrunk_cap_limits_worker_concurrency() {
    // Ceiling of 8, but shrink the live cap to 2 before submitting work.
    let pool = BlockingPool::new(0, 8);
    assert_eq!(pool.set_max_threads(2), 2);

    let concurrent = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));

    const TASKS: usize = 16;
    for _ in 0..TASKS {
        let concurrent = Arc::clone(&concurrent);
        let peak = Arc::clone(&peak);
        let done = Arc::clone(&done);
        pool.spawn(move || {
            let now = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            concurrent.fetch_sub(1, Ordering::SeqCst);
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    // Wait (bounded) for every task to complete.
    let deadline = Instant::now() + Duration::from_secs(10);
    while done.load(Ordering::SeqCst) < TASKS && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        done.load(Ordering::SeqCst),
        TASKS,
        "all tasks must complete"
    );

    // The key property: the shrunk cap is an upper bound on observed concurrency
    // and on live worker threads (this holds for any scheduling timing).
    assert!(
        peak.load(Ordering::SeqCst) <= 2,
        "observed concurrency {} exceeded the shrunk cap of 2",
        peak.load(Ordering::SeqCst)
    );
    assert!(
        pool.active_threads() <= 2,
        "active threads {} exceeded the shrunk cap of 2",
        pool.active_threads()
    );
}

#[test]
fn grow_cap_restores_higher_concurrency() {
    // Start capped at 1, then grow back to 4 and confirm the pool can now run
    // more than one worker concurrently.
    let pool = BlockingPool::new(0, 4);
    assert_eq!(pool.set_max_threads(1), 1);
    assert_eq!(pool.set_max_threads(4), 4, "grow back up to the ceiling");

    let concurrent = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));

    const TASKS: usize = 16;
    for _ in 0..TASKS {
        let concurrent = Arc::clone(&concurrent);
        let peak = Arc::clone(&peak);
        let done = Arc::clone(&done);
        pool.spawn(move || {
            let now = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(30));
            concurrent.fetch_sub(1, Ordering::SeqCst);
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    while done.load(Ordering::SeqCst) < TASKS && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        done.load(Ordering::SeqCst),
        TASKS,
        "all tasks must complete"
    );
    // Concurrency must still respect the grown ceiling of 4.
    assert!(
        peak.load(Ordering::SeqCst) <= 4,
        "observed concurrency {} exceeded the grown cap of 4",
        peak.load(Ordering::SeqCst)
    );
}
