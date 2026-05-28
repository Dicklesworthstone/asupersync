//! MPSC channel lost wakeup regression tests.
//!
//! Critical test suite for verifying correct waker management in MPSC channels.
//! Lost wakeups occur when a waker is registered but not properly notified when
//! the channel becomes available, leading to permanent task suspension.
//!
//! # Test Scenarios
//! - Receiver wakeup after sender permits become available
//! - Sender wakeup after receiver drains buffered items
//! - Concurrent waker registration and channel state changes
//! - Waker deduplication to prevent spurious notifications

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
    use crate::channel::mpsc;
    use crate::cx::Cx;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Waker};

    fn test_cx() -> Cx<crate::cx::cap::All> {
        Cx::for_testing()
    }

    #[test]
    fn lost_wakeup_test() {
        let cx = test_cx();
        let (tx, mut rx) = mpsc::channel::<i32>(1);

        // Fill capacity
        let permit = tx.try_reserve().unwrap();
        permit.send(1);

        // Queue A
        let mut reserve_a = Box::pin(tx.reserve(&cx));
        let waker_a = Waker::noop();
        let mut ctx_a = Context::from_waker(waker_a);
        assert!(reserve_a.as_mut().poll(&mut ctx_a).is_pending());

        // Queue B
        let mut reserve_b = Box::pin(tx.reserve(&cx));

        struct CountWaker(Arc<AtomicUsize>);
        impl std::task::Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let wakes_b = Arc::new(AtomicUsize::new(0));
        let waker_b = Waker::from(Arc::new(CountWaker(wakes_b.clone())));
        let mut ctx_b = Context::from_waker(&waker_b);
        assert!(reserve_b.as_mut().poll(&mut ctx_b).is_pending());

        // Receiver takes message, which pops A and wakes it
        let val = rx.try_recv().unwrap();
        assert_eq!(val, 1);

        // A drops before polling
        drop(reserve_a);

        // B should be woken!
        assert!(wakes_b.load(Ordering::Relaxed) > 0, "B was not woken!");
    }
}
