#![allow(missing_docs)]

use asupersync::cx::Cx;
use asupersync::sync::{AsyncResourceFactory, GenericPool, Pool, PoolConfig};
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

struct ManualWakerFactory {
    waker: Arc<Mutex<Option<Waker>>>,
    created_val: u32,
}

impl AsyncResourceFactory for ManualWakerFactory {
    type Resource = u32;
    type Error = std::io::Error;

    fn create(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Resource, Self::Error>> + Send + '_>> {
        let waker = self.waker.clone();
        let val = self.created_val;
        Box::pin(async move {
            // Wait until we are signaled to proceed
            WaitOnce::new(waker).await;
            Ok(val)
        })
    }
}

struct WaitOnce {
    waker: Arc<Mutex<Option<Waker>>>,
    polled: bool,
}

impl WaitOnce {
    fn new(waker: Arc<Mutex<Option<Waker>>>) -> Self {
        Self {
            waker,
            polled: false,
        }
    }
}

impl Future for WaitOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.polled {
            Poll::Ready(())
        } else {
            *self.waker.lock() = Some(cx.waker().clone());
            self.polled = true;
            Poll::Pending
        }
    }
}

#[test]
fn test_warmup_wakes_waiters() {
    // This test uses a manual future implementation to verify wakeup behavior
    // It's a bit complex because we need to control the execution order precisely.

    let factory_waker = Arc::new(Mutex::new(None));
    let factory = ManualWakerFactory {
        waker: factory_waker.clone(),
        created_val: 42,
    };

    // Max size 1. Warmup will take this 1 slot.
    let config = PoolConfig::with_max_size(1)
        .warmup_connections(1)
        .warmup_failure_strategy(asupersync::sync::WarmupStrategy::BestEffort); // Don't fail if test messes up

    let pool = Arc::new(GenericPool::new(factory, config));
    let cx = Cx::for_testing(); // Assuming this is available or similar

    // Spawn warmup in background
    let pool_clone = pool.clone();
    let warmup_handle =
        std::thread::spawn(move || futures_lite::future::block_on(pool_clone.warmup()));

    // Wait for factory to be called (meaning warmup has reserved the slot)
    // We poll the factory_waker until it's set
    let mut factory_task_waker = None;
    for _ in 0..50 {
        {
            let mut lock = factory_waker.lock();
            if lock.is_some() {
                factory_task_waker = lock.take();
                drop(lock);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        factory_task_waker.is_some(),
        "Warmup should have started creating resource"
    );

    // Now acquire. The pool is "full" (1 creating, max 1).
    // This acquire should block waiting for a slot.
    // We run acquire in another thread to detect if it hangs
    let acquire_handle = std::thread::spawn(move || {
        let result = futures_lite::future::block_on(pool.acquire(&cx));
        result.expect("Acquire should succeed")
    });

    // Give acquire a moment to block
    std::thread::sleep(Duration::from_millis(50));

    // Now finish the warmup creation
    if let Some(waker) = factory_task_waker {
        waker.wake();
    }

    // Wait for warmup to complete
    warmup_handle
        .join()
        .unwrap()
        .expect("Warmup should succeed");

    // Now acquire should complete immediately because warmup finished and put resource in idle.
    // If there is a bug, acquire will hang (or timeout if configured, but we didn't set short timeout)
    // We'll join with a timeout to detect the hang.

    // Since std::thread::join doesn't timeout, we can't easily timeout here without extra crates.
    // But if we just wait, the test will hang if bug is present.
    // Let's assume the test runner has a timeout.

    let resource = acquire_handle.join().unwrap();
    assert_eq!(*resource, 42);
}
