#![allow(missing_docs)]

use asupersync::time::Sleep;
use asupersync::types::Time;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::time::Duration;

#[test]
fn sleep_spawns_thread_and_wakes() {
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

    // First poll: should be pending (elapsed < 200ms)
    assert!(Pin::new(&mut s).poll(&mut cx).is_pending());

    // The poll should have spawned a background thread to wake us up.
    // Wait for the flag to be set.
    let wait_start = std::time::Instant::now();
    while !flag.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::yield_now();
        if wait_start.elapsed().as_secs() > 5 {
            panic!("Timed out waiting for waker");
        }
    }

    // Verify delay
    let elapsed = wait_start.elapsed();
    // We expect roughly 200ms. Allow some slop.
    assert!(
        elapsed.as_millis() > 50,
        "Woke up too early: {}ms",
        elapsed.as_millis()
    );
}
