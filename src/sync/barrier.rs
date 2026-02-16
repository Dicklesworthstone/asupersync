//! Barrier for N-way rendezvous with cancel-aware waiting.
//!
//! The barrier trips when `parties` callers have arrived. Exactly one
//! caller observes `is_leader = true` per generation.
//!
//! # Cancel Safety
//!
//! - **Wait**: If a task is cancelled while waiting, it is removed from the
//!   arrival count. The barrier will not trip until a replacement task arrives.
//! - **Trip**: Once the barrier trips, all waiting tasks are woken and will
//!   observe completion, even if cancelled concurrently.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

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
    waiters: Vec<Waker>,
}

/// Barrier for N-way rendezvous.
#[derive(Debug)]
pub struct Barrier {
    parties: usize,
    state: Mutex<BarrierState>,
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
            state: Mutex::new(BarrierState {
                arrived: 0,
                generation: 0,
                waiters: Vec::new(),
            }),
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
    /// decrements the arrival count so the barrier remains consistent for
    /// other waiters.
    pub fn wait<'a>(&'a self, cx: &'a Cx) -> BarrierWaitFuture<'a> {
        BarrierWaitFuture {
            barrier: self,
            cx,
            state: WaitState::Init,
        }
    }
}

/// Internal state of the wait future.
#[derive(Debug)]
enum WaitState {
    Init,
    /// Waiting for the barrier to trip.
    ///
    /// `slot` is the index into `BarrierState::waiters` where our waker was
    /// pushed.  On re-poll we try an O(1) indexed lookup first; if the slot
    /// has been invalidated by another waiter's cancellation (which uses
    /// `swap_remove`), we fall back to a linear scan.
    Waiting {
        generation: u64,
        slot: usize,
    },
}

/// Future returned by `Barrier::wait`.
#[derive(Debug)]
pub struct BarrierWaitFuture<'a> {
    barrier: &'a Barrier,
    cx: &'a Cx,
    state: WaitState,
}

impl Future for BarrierWaitFuture<'_> {
    type Output = Result<BarrierWaitResult, BarrierWaitError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // 1. Check cancellation first.
        if let Err(_e) = self.cx.checkpoint() {
            // If we were waiting, we need to unregister.
            if let WaitState::Waiting { generation, slot } = self.state {
                let mut state = self
                    .barrier
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);

                // Only decrement if the generation hasn't changed (barrier hasn't tripped).
                if state.generation == generation {
                    if state.arrived > 0 {
                        state.arrived -= 1;
                    }
                    // Remove our waker via O(1) swap_remove when possible,
                    // falling back to O(N) retain for robustness.
                    let waker = cx.waker();
                    if slot < state.waiters.len() && state.waiters[slot].will_wake(waker) {
                        state.waiters.swap_remove(slot);
                    } else {
                        state.waiters.retain(|w| !w.will_wake(waker));
                    }
                    drop(state);

                    // Mark state as done so Drop doesn't decrement again.
                    self.state = WaitState::Init;
                    return Poll::Ready(Err(BarrierWaitError::Cancelled));
                }
                // Generation changed means barrier tripped just before cancel.
                // We treat this as success.
                drop(state);
                self.state = WaitState::Init;
                return Poll::Ready(Ok(BarrierWaitResult { is_leader: false }));
            }
            // Cancelled before even registering.
            return Poll::Ready(Err(BarrierWaitError::Cancelled));
        }

        let mut state = self
            .barrier
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        match self.state {
            WaitState::Init => {
                if state.arrived + 1 >= self.barrier.parties {
                    // We are the leader (or the last one to arrive).
                    // Trip the barrier.
                    state.arrived = 0;
                    state.generation = state.generation.wrapping_add(1);

                    // Wake all waiters.
                    for waker in state.waiters.drain(..) {
                        waker.wake();
                    }
                    drop(state);

                    Poll::Ready(Ok(BarrierWaitResult { is_leader: true }))
                } else {
                    // Not full yet. Arrive and wait.
                    state.arrived += 1;
                    let gen = state.generation;
                    let slot = state.waiters.len();
                    state.waiters.push(cx.waker().clone());
                    drop(state);
                    self.state = WaitState::Waiting {
                        generation: gen,
                        slot,
                    };
                    Poll::Pending
                }
            }
            WaitState::Waiting { generation, slot } => {
                if state.generation == generation {
                    // Still waiting. Update waker if changed.
                    // O(1) fast path: use the remembered slot index.
                    let waker = cx.waker();
                    if slot < state.waiters.len() && state.waiters[slot].will_wake(waker) {
                        // Slot still valid — update in place (no-op if same waker).
                        state.waiters[slot].clone_from(waker);
                    } else {
                        // Slot invalidated by a concurrent cancellation's
                        // swap_remove.  Fall back to linear scan + push.
                        let mut found = false;
                        for (i, w) in state.waiters.iter_mut().enumerate() {
                            if w.will_wake(waker) {
                                w.clone_from(waker);
                                // Update slot for next re-poll.
                                self.state = WaitState::Waiting {
                                    generation,
                                    slot: i,
                                };
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            let new_slot = state.waiters.len();
                            state.waiters.push(waker.clone());
                            self.state = WaitState::Waiting {
                                generation,
                                slot: new_slot,
                            };
                        }
                    }
                    drop(state);

                    Poll::Pending
                } else {
                    // Generation advanced! We are done.
                    drop(state);
                    self.state = WaitState::Init;
                    Poll::Ready(Ok(BarrierWaitResult { is_leader: false }))
                }
            }
        }
    }
}

impl Drop for BarrierWaitFuture<'_> {
    fn drop(&mut self) {
        if let WaitState::Waiting { generation, .. } = self.state {
            // We must use a separate block or variable to handle the lock result
            // because poisoning might happen.
            let mut state = match self.barrier.state.lock() {
                Ok(guard) => guard,
                Err(poison) => poison.into_inner(),
            };

            // Only decrement if the generation hasn't changed (barrier hasn't tripped).
            if state.generation == generation && state.arrived > 0 {
                state.arrived -= 1;
            }
            // Note: We leave the waker in the list. It will be woken (harmlessly)
            // when the barrier trips, and the list will be cleared then.
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
    use std::time::Duration;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    // Helper to block on futures for testing (since we don't have the full runtime here)
    fn block_on<F: Future>(f: F) -> F::Output {
        let mut f = Box::pin(f);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match f.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
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
                let result = block_on(barrier.wait(&cx)).expect("wait failed");
                if result.is_leader() {
                    leaders.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        let cx: Cx = Cx::for_testing();
        let result = block_on(barrier.wait(&cx)).expect("wait failed");
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

        // This should return cancelled immediately
        let err = block_on(barrier.wait(&cx)).expect_err("expected cancellation");
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
            let result = block_on(barrier_clone.wait(&cx)).expect("wait failed");
            if result.is_leader() {
                leaders_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        // Give thread time to arrive
        std::thread::sleep(Duration::from_millis(50));

        let cx: Cx = Cx::for_testing();
        let result = block_on(barrier.wait(&cx)).expect("wait failed");
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

        let result = block_on(barrier.wait(&cx)).expect("wait failed");
        crate::assert_with_log!(
            result.is_leader(),
            "single party is leader",
            true,
            result.is_leader()
        );
        crate::test_complete!("barrier_single_party_trips_immediately");
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
                let result = block_on(b.wait(&cx)).expect("wait failed");
                if result.is_leader() {
                    lc.fetch_add(1, Ordering::SeqCst);
                }
            });

            let cx: Cx = Cx::for_testing();
            let result = block_on(barrier.wait(&cx)).expect("wait failed");
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
    #[should_panic(expected = "barrier requires at least 1 party")]
    fn barrier_zero_parties_panics() {
        let _ = Barrier::new(0);
    }
}
