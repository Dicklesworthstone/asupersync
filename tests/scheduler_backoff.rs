#![allow(missing_docs)]
//! Scheduler backoff tests.

use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::WorkStealingScheduler;
use asupersync::sync::ContendedMutex;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_scheduler_shutdown_with_backoff() {
    // This test verifies that the worker loop with backoff eventually parks and
    // can be properly shut down.

    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = WorkStealingScheduler::new(1, &state);

    // Take workers to run in a thread
    let workers = scheduler.take_workers();
    assert_eq!(workers.len(), 1);
    let mut worker = workers.into_iter().next().unwrap();

    // Spawn worker thread
    let handle = std::thread::spawn(move || {
        worker.run_loop();
    });

    // Sleep to allow worker to enter backoff and park
    std::thread::sleep(Duration::from_millis(50));

    // Signal shutdown
    scheduler.shutdown();

    // Join thread - if backoff/park logic is broken, this might hang
    handle.join().expect("worker thread join");
}
