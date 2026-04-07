#![allow(missing_docs)]
#![cfg(feature = "test-internals")]
//! Regression coverage for create-time acquire timeouts in `GenericPool`.

use asupersync::cx::Cx;
use asupersync::sync::{GenericPool, Pool, PoolConfig, PoolError};
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{Budget, RegionId, TaskId};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

#[test]
fn pool_creation_respects_acquire_timeout() {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
    let cx = Cx::new_with_drivers(
        RegionId::new_for_test(0, 0),
        TaskId::new_for_test(0, 0),
        Budget::INFINITE,
        None,
        None,
        None,
        Some(timer.clone()),
        None,
    );
    let _guard = Cx::set_current(Some(cx.clone()));

    let factory = || async move {
        // Sleep long enough that the acquire timeout must fire first.
        let now = Cx::current()
            .and_then(|current| current.timer_driver())
            .map_or_else(asupersync::time::wall_now, |driver| driver.now());
        asupersync::time::sleep(now, Duration::from_secs(100)).await;
        Ok::<(), std::io::Error>(())
    };

    let config = PoolConfig::with_max_size(2).acquire_timeout(Duration::from_millis(50));

    // Acquire timeout follows the task Cx timer driver, not the pool's wall-clock
    // resource age getter.
    let pool = GenericPool::new(factory, config);

    let mut fut = Box::pin(pool.acquire(&cx));

    let waker = Waker::from(Arc::new(TestWaker));
    let mut ctx = Context::from_waker(&waker);

    let poll1 = fut.as_mut().poll(&mut ctx);
    assert!(poll1.is_pending());

    clock.advance(
        Duration::from_millis(60)
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64,
    );
    let _ = timer.process_timers();

    let poll2 = fut.as_mut().poll(&mut ctx);
    assert!(
        matches!(poll2, Poll::Ready(Err(PoolError::Timeout))),
        "Should timeout during creation"
    );
}

struct TestWaker;
impl Wake for TestWaker {
    fn wake(self: Arc<Self>) {}
}
