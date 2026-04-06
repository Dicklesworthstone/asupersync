//! Regression test: two waiters on a Mutex both complete after the holder drops.

#[cfg(test)]
mod tests {
    use crate::cx::Cx;
    use crate::sync::mutex::Mutex;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::task::{Context, Poll, Waker};

    fn poll_pinned_until_ready<T>(mut future: std::pin::Pin<&mut impl Future<Output = T>>) -> T {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn mutex_two_waiters_both_acquire_after_release() {
        let lock = Arc::new(Mutex::new(0u32));
        let acquired_count = Arc::new(AtomicU32::new(0));

        // Acquire the lock on the main thread.
        let cx = Cx::for_testing();
        let guard = poll_pinned_until_ready(pin!(lock.lock(&cx))).expect("initial lock failed");

        // Spawn two std threads that each try to acquire the mutex.
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let lock = lock.clone();
                let count = acquired_count.clone();
                std::thread::spawn(move || {
                    let cx = Cx::for_testing();
                    let _g =
                        poll_pinned_until_ready(pin!(lock.lock(&cx))).expect("waiter lock failed");
                    count.fetch_add(1, Ordering::Relaxed);
                })
            })
            .collect();

        // Wait until both waiters are actually queued before releasing.
        for _ in 0..10_000 {
            if lock.waiters() == 2 {
                break;
            }
            std::thread::yield_now();
        }
        assert_eq!(
            lock.waiters(),
            2,
            "both waiters should be queued before release"
        );

        // Release the lock so both waiters can proceed.
        drop(guard);

        // Both threads should complete within a reasonable time.
        for h in handles {
            h.join().expect("waiter thread panicked");
        }

        assert_eq!(
            acquired_count.load(Ordering::Relaxed),
            2,
            "both waiters should have acquired the mutex"
        );
    }
}
