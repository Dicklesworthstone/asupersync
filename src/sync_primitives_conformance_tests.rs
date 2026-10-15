//! Sync primitive conformance checks over production implementations.
//!
//! This module is wired into the crate test surface, so it must exercise the
//! real `Mutex`, `Semaphore`, `Barrier`, and `Cx` behavior. It must not carry
//! local replacement implementations that can report conformance without
//! touching the production synchronization primitives.

#[cfg(test)]
mod tests {
    use crate::cx::{Cx, cap};
    use crate::sync::{
        AcquireError, Barrier, BarrierWaitError, LockError, Mutex, Semaphore, TryAcquireError,
        TryLockError,
    };
    use futures_lite::future::block_on;
    use proptest::prelude::*;
    use std::future::Future;
    use std::pin::{Pin, pin};
    use std::task::{Context, Poll, Waker};

    fn poll_once<F>(future: Pin<&mut F>) -> Poll<F::Output>
    where
        F: Future,
    {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        future.poll(&mut context)
    }

    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    fn cancelled_cx() -> Cx<cap::All> {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        cx
    }

    #[test]
    fn mutex_try_lock_enforces_mutual_exclusion_and_releases_on_drop() {
        let mutex = Mutex::new(Vec::<u8>::new());

        {
            let mut guard = mutex.try_lock().expect("first try_lock should acquire");
            assert!(mutex.is_locked());
            assert_eq!(
                mutex.try_lock().unwrap_err(),
                TryLockError::Locked,
                "a held production mutex must reject a second try_lock"
            );
            guard.extend_from_slice(&[1, 2, 3]);
        }

        assert!(
            !mutex.is_locked(),
            "dropping the guard must release the mutex"
        );
        let guard = mutex
            .try_lock()
            .expect("mutex should be reusable after drop");
        assert_eq!(guard.as_slice(), [1, 2, 3]);
    }

    #[test]
    fn mutex_cancelled_context_fails_before_queueing_or_stealing_lock() {
        let mutex = Mutex::new(7_u64);
        let holding_guard = mutex.try_lock().expect("setup lock should acquire");
        let cx = cancelled_cx();

        let result = block_on(mutex.lock(&cx));
        assert_eq!(
            result.unwrap_err(),
            LockError::Cancelled,
            "cancelled lock acquisition must fail through the production Cx checkpoint"
        );
        assert_eq!(
            mutex.waiters(),
            0,
            "pre-cancelled lock must not enqueue a waiter"
        );
        assert!(
            mutex.is_locked(),
            "cancelled waiter must not steal the held mutex"
        );

        drop(holding_guard);
        assert_eq!(*mutex.try_lock().expect("lock should recover"), 7);
    }

    #[test]
    fn mutex_dropped_waiter_is_removed_from_production_wait_queue() {
        let mutex = Mutex::new(0_u8);
        let cx = test_cx();
        let guard = mutex.try_lock().expect("setup lock should acquire");

        {
            let mut waiting = pin!(mutex.lock(&cx));
            assert!(
                poll_once(waiting.as_mut()).is_pending(),
                "lock future should wait while the mutex is held"
            );
            assert_eq!(
                mutex.waiters(),
                1,
                "pending lock future must register one waiter"
            );
        }

        assert_eq!(
            mutex.waiters(),
            0,
            "dropping a pending lock future must unlink its waiter"
        );
        drop(guard);
        assert!(
            mutex.try_lock().is_ok(),
            "waiter cleanup must leave mutex usable"
        );
    }

    #[test]
    fn semaphore_try_acquire_conserves_permits_across_guard_drop() {
        let semaphore = Semaphore::new(5);
        assert_eq!(semaphore.max_permits(), 5);
        assert_eq!(semaphore.available_permits(), 5);

        let two = semaphore
            .try_acquire(2)
            .expect("two permits should acquire");
        assert_eq!(two.count(), 2);
        assert_eq!(semaphore.available_permits(), 3);

        let three = semaphore
            .try_acquire(3)
            .expect("remaining permits should acquire");
        assert_eq!(three.count(), 3);
        assert_eq!(semaphore.available_permits(), 0);
        assert_eq!(
            semaphore.try_acquire(1).unwrap_err(),
            TryAcquireError,
            "no extra production permits may be fabricated"
        );

        drop(two);
        assert_eq!(semaphore.available_permits(), 2);
        drop(three);
        assert_eq!(
            semaphore.available_permits(),
            semaphore.max_permits(),
            "all held permits must return to the production semaphore"
        );
    }

    #[test]
    fn semaphore_cancelled_acquire_does_not_consume_or_enqueue_permits() {
        let semaphore = Semaphore::new(2);
        let held = semaphore
            .try_acquire(2)
            .expect("setup should consume permits");
        let cx = cancelled_cx();

        let result = block_on(semaphore.acquire(&cx, 1));
        assert_eq!(
            result.unwrap_err(),
            AcquireError::Cancelled,
            "cancelled acquire must fail through the production Cx checkpoint"
        );
        assert_eq!(
            semaphore.available_permits(),
            0,
            "cancelled acquire must not manufacture or release permits"
        );

        drop(held);
        assert_eq!(semaphore.available_permits(), 2);
        assert_eq!(
            semaphore
                .try_acquire(2)
                .expect("permits should be reusable")
                .count(),
            2
        );
    }

    #[test]
    fn semaphore_dropped_waiter_does_not_block_later_acquire() {
        let semaphore = Semaphore::new(1);
        let held = semaphore
            .try_acquire(1)
            .expect("setup should consume permit");
        let cx = test_cx();

        {
            let mut waiting = pin!(semaphore.acquire(&cx, 1));
            assert!(
                poll_once(waiting.as_mut()).is_pending(),
                "acquire should wait when all permits are held"
            );
        }

        drop(held);
        let permit = block_on(semaphore.acquire(&cx, 1))
            .expect("dropping a queued waiter must not strand the permit");
        assert_eq!(permit.count(), 1);
    }

    #[test]
    fn semaphore_close_fails_pending_waiters_fail_closed() {
        let semaphore = Semaphore::new(1);
        let held = semaphore
            .try_acquire(1)
            .expect("setup should consume permit");
        let cx = test_cx();
        let mut waiting = pin!(semaphore.acquire(&cx, 1));

        assert!(poll_once(waiting.as_mut()).is_pending());
        semaphore.close();
        assert_eq!(semaphore.available_permits(), 0);
        assert!(semaphore.is_closed());

        let Poll::Ready(result) = poll_once(waiting.as_mut()) else {
            panic!("closed semaphore should wake pending waiter to a terminal result");
        };
        assert_eq!(result.unwrap_err(), AcquireError::Closed);

        drop(held);
        assert_eq!(
            semaphore.available_permits(),
            0,
            "dropping a permit after close must not reopen capacity"
        );
    }

    #[test]
    fn barrier_trips_once_per_generation_with_single_leader() {
        let barrier = Barrier::new(3);
        let cx1 = test_cx();
        let cx2 = test_cx();
        let cx3 = test_cx();
        let mut first = pin!(barrier.wait(&cx1));
        let mut second = pin!(barrier.wait(&cx2));

        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_pending());

        let leader = block_on(barrier.wait(&cx3)).expect("third party should trip barrier");
        assert!(
            leader.is_leader(),
            "last arriving party must lead the generation"
        );

        let Poll::Ready(first_result) = poll_once(first.as_mut()) else {
            panic!("tripped barrier should release first waiter");
        };
        let Poll::Ready(second_result) = poll_once(second.as_mut()) else {
            panic!("tripped barrier should release second waiter");
        };
        assert!(!first_result.expect("first waiter released").is_leader());
        assert!(!second_result.expect("second waiter released").is_leader());
    }

    #[test]
    fn barrier_cancelled_waiter_is_removed_from_generation() {
        let barrier = Barrier::new(2);
        let cancelled_after_queue = test_cx();
        let mut cancelled_waiter = pin!(barrier.wait(&cancelled_after_queue));

        assert!(poll_once(cancelled_waiter.as_mut()).is_pending());
        cancelled_after_queue.set_cancel_requested(true);
        let Poll::Ready(cancel_result) = poll_once(cancelled_waiter.as_mut()) else {
            panic!("cancelled waiter should complete immediately on next poll");
        };
        assert_eq!(cancel_result.unwrap_err(), BarrierWaitError::Cancelled);

        let replacement_cx = test_cx();
        let leader_cx = test_cx();
        let mut replacement = pin!(barrier.wait(&replacement_cx));
        assert!(poll_once(replacement.as_mut()).is_pending());

        let leader = block_on(barrier.wait(&leader_cx)).expect("replacement pair should trip");
        assert!(leader.is_leader());
        let Poll::Ready(replacement_result) = poll_once(replacement.as_mut()) else {
            panic!("replacement waiter should be released by leader");
        };
        assert!(
            !replacement_result
                .expect("replacement released")
                .is_leader()
        );
    }

    proptest! {
        #[test]
        fn semaphore_conserves_permits_for_sequential_acquire_drop_counts(
            initial in 1usize..16,
            first in 0usize..16,
            second in 0usize..16,
        ) {
            let first = first % (initial + 1);
            let second = second % (initial + 1);
            let semaphore = Semaphore::new(initial);
            let mut held = Vec::new();
            let mut held_count = 0usize;

            if first <= semaphore.available_permits() {
                let permit = semaphore.try_acquire(first).expect("bounded first acquire should succeed");
                held_count += permit.count();
                held.push(permit);
            }
            if second <= semaphore.available_permits() {
                let permit = semaphore.try_acquire(second).expect("bounded second acquire should succeed");
                held_count += permit.count();
                held.push(permit);
            }

            prop_assert_eq!(
                semaphore.available_permits() + held_count,
                semaphore.max_permits(),
                "production semaphore must conserve permits while guards are held"
            );

            held.clear();
            prop_assert_eq!(
                semaphore.available_permits(),
                semaphore.max_permits(),
                "dropping all production permits must restore full capacity"
            );
        }
    }
}
