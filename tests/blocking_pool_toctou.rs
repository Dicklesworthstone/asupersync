#![allow(warnings)]
#![allow(clippy::all)]
//! Regression test for a `BlockingPool` spawn/shutdown TOCTOU race.

use asupersync::runtime::BlockingPool;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn run_spawn_shutdown_race(iterations: usize, use_handle_api: bool) {
    for _ in 0..iterations {
        let pool = Arc::new(BlockingPool::new(1, 1));
        let counter = Arc::new(AtomicUsize::new(0));

        let c = Arc::clone(&counter);
        let pool_clone1 = Arc::clone(&pool);
        let pool_clone2 = Arc::clone(&pool);

        let t1 = std::thread::spawn(move || {
            if use_handle_api {
                let handle_api = pool_clone1.handle();
                handle_api.spawn(move || {
                    c.fetch_add(1, Ordering::SeqCst);
                })
            } else {
                pool_clone1.spawn(move || {
                    c.fetch_add(1, Ordering::SeqCst);
                })
            }
        });

        let t2 = std::thread::spawn(move || {
            pool_clone2.shutdown();
        });

        let handle = t1.join().unwrap();
        t2.join().unwrap();

        pool.shutdown_and_wait(Duration::from_secs(1));

        let success = handle.wait_timeout(Duration::from_millis(50));
        assert!(success, "Deadlock detected! Task was lost.");
    }
}

#[test]
fn test_blocking_pool_toctou() {
    run_spawn_shutdown_race(10_000, false);
}

#[test]
fn test_blocking_pool_handle_toctou() {
    run_spawn_shutdown_race(10_000, true);
}
