#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::time::timeout;
use asupersync::types::Time;
use common::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Waker};
use std::time::Duration;

#[test]
fn timeout_wakes_up_pending_future() {
    init_test_logging();
    test_phase!("timeout_wakes_up_pending_future");
    test_section!("setup");
    // This test verifies that timeout() actually wakes up the task when the deadline passes,
    // even if the inner future is completely unresponsive (Pending forever).

    // Use logical time 0 start (will use wall clock internally via Sleep fix)
    let duration = Duration::from_millis(200);
    let mut t = timeout(Time::ZERO, duration, std::future::pending::<()>());

    struct NotifyWaker(Arc<std::sync::atomic::AtomicBool>);
    impl std::task::Wake for NotifyWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waker = Waker::from(Arc::new(NotifyWaker(flag.clone())));
    let mut cx = Context::from_waker(&waker);

    test_section!("first_poll");
    // First poll: inner is pending. Timeout should register wakeup.
    let first_poll_pending = Pin::new(&mut t).poll(&mut cx).is_pending();
    assert_with_log!(
        first_poll_pending,
        "first poll should be pending",
        true,
        first_poll_pending
    );

    // If the timeout works, it should spawn a thread (via Sleep) that wakes us up.
    test_section!("wait_for_wake");
    let wait_start = std::time::Instant::now();
    loop {
        if flag.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        std::thread::yield_now();
        assert!(
            wait_start.elapsed().as_secs() <= 5,
            "Timeout future failed to wake up within 5 seconds (expected ~200ms)"
        )
    }

    // Poll again: should be Ready(Err(Elapsed))
    let result = Pin::new(&mut t).poll(&mut cx);
    test_section!("verify");
    let is_ready = result.is_ready();
    assert_with_log!(is_ready, "second poll should be ready", true, is_ready);
    // Verify it is an error (timeout) not Ok (completion)
    match result {
        std::task::Poll::Ready(Err(_)) => {}
        _ => panic!("Expected Ready(Err(Elapsed)), got {result:?}"),
    }
    test_complete!("timeout_wakes_up_pending_future");
}
