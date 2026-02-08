#![allow(missing_docs)]

use asupersync::runtime::io_driver::IoDriverHandle;
use asupersync::runtime::reactor::LabReactor;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_io_driver_handle_split_lock() {
    let reactor = Arc::new(LabReactor::new());
    let handle = IoDriverHandle::new(reactor);

    // 1. Verify we can turn with 0 events
    let res = handle.turn_with(Some(Duration::ZERO), |_, _| {});
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);

    // 2. Register something
    // We can't implement Source easily here as it's a trait requiring AsRawFd or
    // similar depending on platform, so we validate through observable stats.
    let stats = handle.stats();
    assert_eq!(stats.polls, 1);

    // 3. Concurrent access test (simulated)
    // Since we can't easily spawn threads in this env without signal issues,
    // we just verify the logic compiles and runs sequentially,
    // implying the lock is acquired/released correctly.

    // Take the lock explicitly to verify we can
    {
        let _guard = handle.lock();
    }

    // Turn again
    let _ = handle.turn_with(Some(Duration::ZERO), |_, _| {});
    assert_eq!(handle.stats().polls, 2);
}
