//! Barrier for N-way rendezvous with cancel-aware waiting.
//!
//! The barrier trips when `parties` callers have arrived. Exactly one
//! caller observes `is_leader = true` per generation.

use std::sync::{Condvar, Mutex as StdMutex};
use std::time::Duration;

use crate::cx::Cx;

/// Error returned when waiting on a barrier fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierWaitError {
    /// Cancelled while waiting.
    Cancelled,
}

impl std::fmt::Display for BarrierWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "barrier wait cancelled"),
        }
    }
}

impl std::error::Error for BarrierWaitError {}

#[derive(Debug)]
struct BarrierState {
    arrived: usize,
    generation: u64,
}

/// Barrier for N-way rendezvous.
#[derive(Debug)]
pub struct Barrier {
    parties: usize,
    state: StdMutex<BarrierState>,
    cvar: Condvar,
}

impl Barrier {
    /// Creates a new barrier that trips when `parties` have arrived.
    ///
    /// # Panics
    /// Panics if `parties == 0`.
    #[must_use]
    pub fn new(parties: usize) -> Self {
        assert!(parties > 0, "barrier requires at least 1 party");
        Self {
            parties,
            state: StdMutex::new(BarrierState {
                arrived: 0,
                generation: 0,
            }),
            cvar: Condvar::new(),
        }
    }

    /// Returns the number of parties required to trip the barrier.
    #[must_use]
    pub fn parties(&self) -> usize {
        self.parties
    }

    /// Waits for the barrier to trip.
    ///
    /// If cancelled while waiting, returns `BarrierWaitError::Cancelled` and
    /// removes the caller from the current generation.
    pub fn wait(&self, cx: &Cx) -> Result<BarrierWaitResult, BarrierWaitError> {
        cx.trace("barrier::wait starting");

        let mut state = self.state.lock().expect("barrier lock poisoned");
        let local_gen = state.generation;
        state.arrived += 1;

        if state.arrived == self.parties {
            // Trip the barrier and advance the generation.
            state.arrived = 0;
            state.generation = state.generation.wrapping_add(1);
            self.cvar.notify_all();
            cx.trace("barrier::wait leader");
            return Ok(BarrierWaitResult { is_leader: true });
        }

        loop {
            if state.generation != local_gen {
                cx.trace("barrier::wait released");
                return Ok(BarrierWaitResult { is_leader: false });
            }

            if cx.checkpoint().is_err() {
                // Re-check generation in case we were woken by a trip just as we cancelled
                if state.generation != local_gen {
                    cx.trace("barrier::wait cancelled after trip");
                    return Ok(BarrierWaitResult { is_leader: false });
                }

                if state.arrived > 0 {
                    state.arrived -= 1;
                }
                // Notify others in case they are waiting for this arrival (which is now gone)
                // Actually, decreasing arrived means we are further from target.
                // We typically don't need to notify because nobody is waiting for *less* people.
                // However, if we were the last one and we leave, we aren't the last one anymore.

                cx.trace("barrier::wait cancelled");
                return Err(BarrierWaitError::Cancelled);
            }

            let (guard, _) = self
                .cvar
                .wait_timeout(state, Duration::from_millis(10))
                .expect("barrier lock poisoned");
            state = guard;
        }
    }
}

/// Result of a barrier wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarrierWaitResult {
    is_leader: bool,
}

impl BarrierWaitResult {
    /// Returns true for exactly one party (the leader) each generation.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.is_leader
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn barrier_trips_and_leader_elected() {
        init_test("barrier_trips_and_leader_elected");
        let barrier = Arc::new(Barrier::new(3));
        let leaders = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let leaders = Arc::clone(&leaders);
            handles.push(std::thread::spawn(move || {
                let cx: Cx = Cx::for_testing();
                let result = barrier.wait(&cx).expect("wait failed");
                if result.is_leader() {
                    leaders.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        let cx: Cx = Cx::for_testing();
        let result = barrier.wait(&cx).expect("wait failed");
        if result.is_leader() {
            leaders.fetch_add(1, Ordering::SeqCst);
        }

        for handle in handles {
            handle.join().expect("thread failed");
        }

        let leader_count = leaders.load(Ordering::SeqCst);
        crate::assert_with_log!(leader_count == 1, "leader count", 1usize, leader_count);
        crate::test_complete!("barrier_trips_and_leader_elected");
    }

    #[test]
    fn barrier_cancel_removes_arrival() {
        init_test("barrier_cancel_removes_arrival");
        let barrier = Barrier::new(2);
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let err = barrier.wait(&cx).expect_err("expected cancellation");
        crate::assert_with_log!(
            err == BarrierWaitError::Cancelled,
            "cancelled error",
            BarrierWaitError::Cancelled,
            err
        );

        // Ensure barrier can still trip after a cancelled waiter.
        let barrier = Arc::new(barrier);
        let leaders = Arc::new(AtomicUsize::new(0));

        let barrier_clone = Arc::clone(&barrier);
        let leaders_clone = Arc::clone(&leaders);
        let handle = std::thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            let result = barrier_clone.wait(&cx).expect("wait failed");
            if result.is_leader() {
                leaders_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        let cx: Cx = Cx::for_testing();
        let result = barrier.wait(&cx).expect("wait failed");
        if result.is_leader() {
            leaders.fetch_add(1, Ordering::SeqCst);
        }

        handle.join().expect("thread failed");

        let leader_count = leaders.load(Ordering::SeqCst);
        crate::assert_with_log!(leader_count == 1, "leader count", 1usize, leader_count);
        crate::test_complete!("barrier_cancel_removes_arrival");
    }

    #[test]
    fn barrier_single_party_trips_immediately() {
        init_test("barrier_single_party_trips_immediately");
        let barrier = Barrier::new(1);
        let cx: Cx = Cx::for_testing();

        let result = barrier.wait(&cx).expect("wait failed");
        crate::assert_with_log!(
            result.is_leader(),
            "single party is leader",
            true,
            result.is_leader()
        );
        crate::test_complete!("barrier_single_party_trips_immediately");
    }

    #[test]
    fn barrier_parties_accessor() {
        init_test("barrier_parties_accessor");
        let barrier = Barrier::new(7);
        let parties = barrier.parties();
        crate::assert_with_log!(parties == 7, "parties", 7usize, parties);
        crate::test_complete!("barrier_parties_accessor");
    }

    #[test]
    fn barrier_multiple_generations() {
        init_test("barrier_multiple_generations");
        let barrier = Arc::new(Barrier::new(2));
        let leader_count = Arc::new(AtomicUsize::new(0));

        // Run two generations of the barrier.
        for gen in 0..2u32 {
            let b = Arc::clone(&barrier);
            let lc = Arc::clone(&leader_count);
            let handle = std::thread::spawn(move || {
                let cx: Cx = Cx::for_testing();
                let result = b.wait(&cx).expect("wait failed");
                if result.is_leader() {
                    lc.fetch_add(1, Ordering::SeqCst);
                }
            });

            let cx: Cx = Cx::for_testing();
            let result = barrier.wait(&cx).expect("wait failed");
            if result.is_leader() {
                leader_count.fetch_add(1, Ordering::SeqCst);
            }

            handle.join().expect("thread failed");
            let leaders_so_far = leader_count.load(Ordering::SeqCst);
            let expected = (gen + 1) as usize;
            crate::assert_with_log!(
                leaders_so_far == expected,
                "leader per generation",
                expected,
                leaders_so_far
            );
        }

        crate::test_complete!("barrier_multiple_generations");
    }

    #[test]
    fn barrier_cancel_does_not_trip() {
        init_test("barrier_cancel_does_not_trip");
        // With 3 parties, if one cancels, only 2 arrive — barrier should not trip.
        let barrier = Arc::new(Barrier::new(3));

        // Cancelled party.
        let cx_cancel: Cx = Cx::for_testing();
        cx_cancel.set_cancel_requested(true);
        let err = barrier.wait(&cx_cancel).expect_err("expected cancel");
        crate::assert_with_log!(
            err == BarrierWaitError::Cancelled,
            "cancelled",
            BarrierWaitError::Cancelled,
            err
        );

        // Now send 3 real parties to verify the barrier still works.
        let barrier2 = Arc::clone(&barrier);
        let mut handles = Vec::new();
        for _ in 0..2 {
            let b = Arc::clone(&barrier2);
            handles.push(std::thread::spawn(move || {
                let cx: Cx = Cx::for_testing();
                b.wait(&cx).expect("wait failed")
            }));
        }

        let cx: Cx = Cx::for_testing();
        let result = barrier2.wait(&cx).expect("wait failed");
        let mut leader_count = usize::from(result.is_leader());

        for h in handles {
            let r = h.join().expect("thread failed");
            if r.is_leader() {
                leader_count += 1;
            }
        }

        crate::assert_with_log!(
            leader_count == 1,
            "exactly one leader",
            1usize,
            leader_count
        );
        crate::test_complete!("barrier_cancel_does_not_trip");
    }

    #[test]
    #[should_panic(expected = "barrier requires at least 1 party")]
    fn barrier_zero_parties_panics() {
        let _ = Barrier::new(0);
    }
}
