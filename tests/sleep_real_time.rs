#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::time::Sleep;
use asupersync::types::Time;
use common::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::time::Duration;

#[test]
fn sleep_spawns_thread_and_wakes() {
    init_test_logging();
    test_phase!("sleep_spawns_thread_and_wakes");
    test_section!("setup");
    // We use Sleep::after(Time::ZERO, ...) which sets deadline relative to logical epoch (0).
    // The internal START_TIME will be initialized on first poll, defining logical 0.
    // So current_time() will be ~0.
    // Deadline will be 200ms.
    let duration = Duration::from_millis(200);
    // Use Sleep::after(Time::ZERO, duration) effectively creates a sleep starting "now".
    let mut s = Sleep::after(Time::ZERO, duration);

    struct NotifyWaker(Arc<std::sync::atomic::AtomicBool>);
    impl std::task::Wake for NotifyWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waker = std::task::Waker::from(Arc::new(NotifyWaker(flag.clone())));
    let mut cx = Context::from_waker(&waker);

    test_section!("first_poll");
    // First poll: should be pending (elapsed < 200ms)
    let first_pending = Pin::new(&mut s).poll(&mut cx).is_pending();
    assert_with_log!(
        first_pending,
        "first poll should be pending",
        true,
        first_pending
    );

    // The poll should have spawned a background thread to wake us up.
    // Wait for the flag to be set.
    test_section!("wait_for_wake");
    let wait_start = std::time::Instant::now();
    while !flag.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::yield_now();
        assert!(
            wait_start.elapsed().as_secs() <= 5,
            "Timed out waiting for waker"
        )
    }

    // Verify delay
    let elapsed = wait_start.elapsed();
    // We expect roughly 200ms. Allow some slop.
    test_section!("verify");
    let elapsed_ms = elapsed.as_millis();
    assert_with_log!(elapsed_ms > 50, "woke up too early", "> 50ms", elapsed_ms);
    test_complete!("sleep_spawns_thread_and_wakes");
}
