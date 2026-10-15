//! Regression test: two waiters on a Mutex both complete after the holder drops.

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use crate::cx::Cx;
    use crate::sync::mutex::Mutex;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

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

        let (queued_tx, queued_rx) = mpsc::channel();

        // Spawn two std threads that each try to acquire the mutex.
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let lock = lock.clone();
                let count = acquired_count.clone();
                let queued_tx = queued_tx.clone();
                std::thread::spawn(move || {
                    let cx = Cx::for_testing();
                    let mut lock_future = pin!(lock.lock(&cx));
                    let waker = Waker::noop();
                    let mut task_cx = Context::from_waker(waker);
                    match lock_future.as_mut().poll(&mut task_cx) {
                        Poll::Pending => queued_tx.send(()).expect("signal queued waiter"),
                        Poll::Ready(result) => {
                            drop(result.expect("waiter lock should not fail before queueing"));
                            panic!("waiter acquired the mutex before the holder released it");
                        }
                    }
                    let _g = poll_pinned_until_ready(lock_future).expect("waiter lock failed");
                    count.fetch_add(1, Ordering::Relaxed);
                })
            })
            .collect();
        drop(queued_tx);

        // Wait until both waiters have polled once and queued themselves before releasing.
        for _ in 0..2 {
            queued_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("waiter should queue before release");
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
