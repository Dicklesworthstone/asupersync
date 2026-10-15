#![allow(missing_docs)]
//! Scheduler backoff tests.

use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::WorkStealingScheduler;
use asupersync::sync::ContendedMutex;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[test]
fn scheduler_shutdown_with_backoff_exits_idle_worker() {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = WorkStealingScheduler::new(1, &state);

    let workers = scheduler.take_workers();
    assert_eq!(workers.len(), 1);
    let mut worker = workers
        .into_iter()
        .next()
        .expect("single-worker scheduler should produce one worker");

    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let started = Instant::now();
        worker.run_loop();
        tx.send(started.elapsed())
            .expect("worker shutdown timing send should succeed");
    });

    std::thread::sleep(Duration::from_millis(50));
    scheduler.shutdown();

    let elapsed = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("idle worker should observe scheduler shutdown");
    handle.join().expect("worker thread join");

    assert!(
        elapsed < Duration::from_secs(1),
        "idle worker should exit promptly after shutdown, elapsed={elapsed:?}"
    );
}
