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

use parking_lot::Mutex;
use smallvec::SmallVec;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;

/// Error returned when waiting on a barrier fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierWaitError {
    /// Cancelled while waiting.
    Cancelled,
    /// The wait future was polled after it had already completed.
    PolledAfterCompletion,
}

impl std::fmt::Display for BarrierWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "barrier wait cancelled"),
            Self::PolledAfterCompletion => write!(f, "barrier future polled after completion"),
        }
    }
}

impl std::error::Error for BarrierWaitError {}

#[derive(Debug)]
struct BarrierState {
    arrived: usize,
    generation: u64,
    next_waiter_id: u64,
    waiters: SmallVec<[(u64, Waker); 7]>,
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
    #[inline]
    #[must_use]
    pub fn new(parties: usize) -> Self {
        assert!(parties > 0, "barrier requires at least 1 party");
        Self {
            parties,
            state: Mutex::new(BarrierState {
                arrived: 0,
                generation: 0,
                next_waiter_id: 0,
                waiters: SmallVec::new(),
            }),
        }
    }

    /// Returns the number of parties required to trip the barrier.
    #[inline]
    #[must_use]
    pub fn parties(&self) -> usize {
        self.parties
    }

    /// Waits for the barrier to trip.
    ///
    /// If cancelled while waiting, returns `BarrierWaitError::Cancelled` and
    /// decrements the arrival count so the barrier remains consistent for
    /// other waiters.
    #[inline]
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
    Waiting {
        generation: u64,
        id: u64,
        slot: usize,
    },
    Done,
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

    #[allow(clippy::too_many_lines)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if matches!(self.state, WaitState::Done) {
            return Poll::Ready(Err(BarrierWaitError::PolledAfterCompletion));
        }

        // 1. Check cancellation first.
        if let Err(_e) = self.cx.checkpoint() {
            // If we were waiting, we need to unregister.
            if let WaitState::Waiting {
                generation,
                id,
                slot,
            } = self.state
            {
                let mut state = self.barrier.state.lock();

                // Only decrement if the generation hasn't changed (barrier hasn't tripped).
                if state.generation == generation {
                    if state.arrived > 0 {
                        state.arrived -= 1;
                    }
                    // Remove our waker via O(1) swap_remove when possible,
                    // falling back to O(N) scan + swap_remove for robustness.
                    if slot < state.waiters.len() && state.waiters[slot].0 == id {
                        state.waiters.swap_remove(slot);
                    } else if let Some(idx) = state.waiters.iter().position(|w| w.0 == id) {
                        state.waiters.swap_remove(idx);
                    }
                    drop(state);

                    // Mark state as done so Drop doesn't decrement again.
                    self.state = WaitState::Done;
                    return Poll::Ready(Err(BarrierWaitError::Cancelled));
                }
                // Generation changed means barrier tripped just before cancel.
                // We treat this as success.
                drop(state);
                self.state = WaitState::Done;
                return Poll::Ready(Ok(BarrierWaitResult { is_leader: false }));
            }
            // Cancelled before even registering.
            self.state = WaitState::Done;
            return Poll::Ready(Err(BarrierWaitError::Cancelled));
        }

        let mut state = self.barrier.state.lock();

        match self.state {
            WaitState::Init => {
                if state.arrived + 1 >= self.barrier.parties {
                    // We are the leader (or the last one to arrive).
                    // Trip the barrier.
                    state.arrived = 0;
                    state.generation = state.generation.wrapping_add(1);

                    // Drain wakers and release lock before waking to
                    // avoid wake-under-lock contention.
                    let wakers: SmallVec<[(u64, Waker); 7]> = state.waiters.drain(..).collect();
                    drop(state);
                    for (_, waker) in wakers {
                        waker.wake();
                    }

                    self.state = WaitState::Done;
                    Poll::Ready(Ok(BarrierWaitResult { is_leader: true }))
                } else {
                    // Not full yet. Arrive and wait.
                    let waker = cx.waker().clone();
                    let generation = state.generation;
                    let id = state.next_waiter_id;
                    let slot = state.waiters.len();

                    // Do fallible operations first to ensure exception safety
                    state.waiters.push((id, waker));

                    // Now commit infallible state changes
                    state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
                    state.arrived += 1;

                    drop(state);
                    self.state = WaitState::Waiting {
                        generation,
                        id,
                        slot,
                    };
                    Poll::Pending
                }
            }
            WaitState::Waiting {
                generation,
                id,
                slot,
            } => {
                if state.generation == generation {
                    // Still waiting. Update waker if changed.
                    // O(1) fast path: use the remembered slot index.
                    let waker = cx.waker();
                    if slot < state.waiters.len() && state.waiters[slot].0 == id {
                        if !state.waiters[slot].1.will_wake(waker) {
                            state.waiters[slot].1.clone_from(waker);
                        }
                    } else {
                        // Slot invalidated by a concurrent cancellation's
                        // swap_remove.  Fall back to linear scan + push.
                        let mut found = false;
                        for (i, w) in state.waiters.iter_mut().enumerate() {
                            if w.0 == id {
                                if !w.1.will_wake(waker) {
                                    w.1.clone_from(waker);
                                }
                                // Update slot for next re-poll.
                                self.state = WaitState::Waiting {
                                    generation,
                                    id,
                                    slot: i,
                                };
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            unreachable!("waiter must be present if generation is unchanged");
                        }
                    }
                    drop(state);

                    Poll::Pending
                } else {
                    // Generation advanced! We are done.
                    drop(state);
                    self.state = WaitState::Done;
                    Poll::Ready(Ok(BarrierWaitResult { is_leader: false }))
                }
            }
            WaitState::Done => Poll::Ready(Err(BarrierWaitError::PolledAfterCompletion)),
        }
    }
}

impl Drop for BarrierWaitFuture<'_> {
    fn drop(&mut self) {
        if let WaitState::Waiting {
            generation,
            id,
            slot,
        } = self.state
        {
            let mut state = self.barrier.state.lock();

            // Only clean up if the generation hasn't changed (barrier hasn't tripped).
            if state.generation == generation {
                if state.arrived > 0 {
                    state.arrived -= 1;
                }
                // Remove the dead waker to avoid spurious wake overhead on trip.
                // O(1) fast path if slot is still valid
                if slot < state.waiters.len() && state.waiters[slot].0 == id {
                    state.waiters.swap_remove(slot);
                } else if let Some(idx) = state.waiters.iter().position(|w| w.0 == id) {
                    state.waiters.swap_remove(idx);
                }
            }
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
    #[inline]
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.is_leader
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::runtime::yield_now;
    use crate::test_utils::init_test_logging;
    use crate::types::Budget;
    use serde_json::Value;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    // Helper to block on futures for testing (since we don't have the full runtime here)
    fn block_on<F: Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
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
        for generation in 0..2u32 {
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
            let expected = (generation + 1) as usize;
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
    fn barrier_n_party_sync_under_lab_runtime() {
        init_test("barrier_n_party_sync_under_lab_runtime");

        let config = TestConfig::new()
            .with_seed(0xBA22_1E42)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let barrier = Arc::new(Barrier::new(3));
        let checkpoints = Arc::new(StdMutex::new(Vec::<Value>::new()));

        let (leaders, checkpoints, generation, arrived, waiter_count) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = Cx::current().expect("lab runtime should install a current Cx");
                let mut tasks = Vec::new();

                for party in 0..3usize {
                    let spawn_cx = cx.clone();
                    let task_cx = spawn_cx.clone();
                    let barrier = Arc::clone(&barrier);
                    let checkpoints = Arc::clone(&checkpoints);
                    tasks.push(LabRuntimeTarget::spawn(
                        &spawn_cx,
                        Budget::INFINITE,
                        async move {
                            for _ in 0..party {
                                yield_now().await;
                            }

                            let arrived_event = serde_json::json!({
                                "phase": "arrived",
                                "party": party,
                            });
                            tracing::info!(event = %arrived_event, "barrier_lab_checkpoint");
                            checkpoints.lock().unwrap().push(arrived_event);

                            let wait_result = barrier
                                .wait(&task_cx)
                                .await
                                .expect("barrier wait should succeed");
                            let released_event = serde_json::json!({
                                "phase": "released",
                                "party": party,
                                "leader": wait_result.is_leader(),
                                "time_ns": task_cx.now().as_nanos(),
                            });
                            tracing::info!(event = %released_event, "barrier_lab_checkpoint");
                            checkpoints.lock().unwrap().push(released_event);
                            wait_result.is_leader()
                        },
                    ));
                }

                let mut leaders = 0usize;
                for task in tasks {
                    let outcome = task.await;
                    crate::assert_with_log!(
                        matches!(outcome, crate::types::Outcome::Ok(_)),
                        "barrier task completes successfully",
                        true,
                        matches!(outcome, crate::types::Outcome::Ok(_))
                    );
                    let crate::types::Outcome::Ok(is_leader) = outcome else {
                        panic!("barrier task should finish successfully");
                    };
                    leaders += usize::from(is_leader);
                }

                let state = barrier.state.lock();
                (
                    leaders,
                    checkpoints.lock().unwrap().clone(),
                    state.generation,
                    state.arrived,
                    state.waiters.len(),
                )
            });

        assert_eq!(leaders, 1, "exactly one barrier party should be the leader");
        assert_eq!(
            generation, 1,
            "barrier should advance exactly one generation"
        );
        assert_eq!(
            arrived, 0,
            "barrier should clear arrived count after release"
        );
        assert_eq!(waiter_count, 0, "barrier should drain waiter registrations");

        let first_release_index = checkpoints
            .iter()
            .position(|event| event["phase"] == "released")
            .expect("released checkpoint should be recorded");
        let arrived_before_release = checkpoints[..first_release_index]
            .iter()
            .filter(|event| event["phase"] == "arrived")
            .count();
        assert_eq!(
            arrived_before_release, 3,
            "all parties should arrive before the barrier releases any waiter"
        );
        assert_eq!(
            checkpoints
                .iter()
                .filter(|event| event["phase"] == "released")
                .count(),
            3,
            "all parties should record a release checkpoint"
        );

        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "barrier lab-runtime rendezvous should leave runtime invariants clean: {violations:?}"
        );
    }

    #[test]
    #[should_panic(expected = "barrier requires at least 1 party")]
    fn barrier_zero_parties_panics() {
        let _ = Barrier::new(0);
    }

    // ── Invariant: drop-without-poll cancel path ───────────────────────

    /// Invariant: dropping a `BarrierWaitFuture` after it has registered
    /// (polled once → Pending) but without re-polling must decrement
    /// `arrived`, leaving the barrier in a consistent state for future
    /// generations.  This is the most common real-world cancel pattern
    /// (e.g. `select!` drops the losing branch without a final poll).
    #[test]
    #[allow(unsafe_code)]
    fn barrier_drop_mid_wait_decrements_arrived() {
        init_test("barrier_drop_mid_wait_decrements_arrived");
        let barrier = Arc::new(Barrier::new(3));

        // Arrive as party 1 via a background thread (will block until trip).
        let b1 = Arc::clone(&barrier);
        let handle = std::thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            block_on(b1.wait(&cx)).expect("wait failed")
        });

        // Arrive as party 2 and poll once to register, then drop.
        {
            let cx: Cx = Cx::for_testing();
            let waker = Waker::noop();
            let mut poll_cx = Context::from_waker(waker);
            let mut fut = barrier.wait(&cx);
            let pinned = Pin::new(&mut fut);
            let status = pinned.poll(&mut poll_cx);
            let pending = status.is_pending();
            crate::assert_with_log!(pending, "party 2 pending", true, pending);
            // Drop fut here — BarrierWaitFuture::drop must decrement arrived.
        }

        // After the drop, arrived should be back to 1 (just party 1's thread).
        // We verify by: a new party 2 + party 3 should trip the barrier.
        let b3 = Arc::clone(&barrier);
        let handle2 = std::thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            block_on(b3.wait(&cx)).expect("wait failed")
        });

        let cx: Cx = Cx::for_testing();
        let result = block_on(barrier.wait(&cx)).expect("final wait failed");
        // Exactly one leader per generation.
        let first_party = handle.join().expect("party 1 thread failed");
        let third_party = handle2.join().expect("party 3 thread failed");

        let total_leaders = [
            result.is_leader(),
            first_party.is_leader(),
            third_party.is_leader(),
        ]
        .iter()
        .filter(|&&b| b)
        .count();
        crate::assert_with_log!(
            total_leaders == 1,
            "exactly 1 leader",
            1usize,
            total_leaders
        );
        crate::test_complete!("barrier_drop_mid_wait_decrements_arrived");
    }

    /// Invariant: cancelling a waiter that has arrived via poll (not just
    /// Init-cancelled) must decrement `arrived` and remove its waker,
    /// leaving the barrier functional for replacement parties.
    #[test]
    #[allow(unsafe_code)]
    fn barrier_cancel_after_poll_arrival_cleans_state() {
        init_test("barrier_cancel_after_poll_arrival_cleans_state");
        let barrier = Barrier::new(2);

        let cx: Cx = Cx::for_testing();
        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);

        // Poll once to arrive and register as a waiter.
        let mut fut = barrier.wait(&cx);
        let pinned = Pin::new(&mut fut);
        let status = pinned.poll(&mut poll_cx);
        let pending = status.is_pending();
        crate::assert_with_log!(pending, "arrived and waiting", true, pending);

        // Now cancel.
        cx.set_cancel_requested(true);
        let pinned = Pin::new(&mut fut);
        let status = pinned.poll(&mut poll_cx);
        let cancelled = matches!(status, Poll::Ready(Err(BarrierWaitError::Cancelled)));
        crate::assert_with_log!(cancelled, "cancelled after arrival", true, cancelled);
        drop(fut);

        // Barrier should be usable: 2 new parties should trip it.
        let barrier = Arc::new(barrier);
        let b2 = Arc::clone(&barrier);
        let handle = std::thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            block_on(b2.wait(&cx)).expect("replacement wait 1 failed")
        });

        let cx2: Cx = Cx::for_testing();
        let result = block_on(barrier.wait(&cx2)).expect("replacement wait 2 failed");
        let handle_result = handle.join().expect("thread failed");

        let total_leaders =
            usize::from(result.is_leader()) + usize::from(handle_result.is_leader());
        crate::assert_with_log!(
            total_leaders == 1,
            "exactly 1 leader",
            1usize,
            total_leaders
        );
        crate::test_complete!("barrier_cancel_after_poll_arrival_cleans_state");
    }

    /// Invariant: when one of multiple registered waiters is dropped,
    /// the remaining waiters can still trip the barrier with a replacement.
    #[test]
    #[allow(unsafe_code)]
    fn barrier_drop_one_of_multiple_waiters_allows_trip() {
        init_test("barrier_drop_one_of_multiple_waiters_allows_trip");
        let barrier = Arc::new(Barrier::new(3));

        // Party 1: thread that blocks in wait.
        let b1 = Arc::clone(&barrier);
        let handle = std::thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            block_on(b1.wait(&cx)).expect("party 1 wait failed")
        });
        // Give party 1 time to arrive.
        std::thread::sleep(Duration::from_millis(30));

        // Party 2: arrives via poll, then is dropped (simulating select! cancel).
        {
            let cx: Cx = Cx::for_testing();
            let waker = Waker::noop();
            let mut poll_cx = Context::from_waker(waker);
            let mut fut = barrier.wait(&cx);
            let pinned = Pin::new(&mut fut);
            let _ = pinned.poll(&mut poll_cx); // arrives -> Pending
            // drop here
        }

        // Party 2 replacement + party 3: should trip the barrier.
        let b2 = Arc::clone(&barrier);
        let handle2 = std::thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            block_on(b2.wait(&cx)).expect("party 2 replacement failed")
        });

        let cx: Cx = Cx::for_testing();
        let result = block_on(barrier.wait(&cx)).expect("party 3 failed");

        let r1 = handle.join().expect("party 1 thread");
        let r2 = handle2.join().expect("party 2 replacement thread");

        let total_leaders = [result.is_leader(), r1.is_leader(), r2.is_leader()]
            .iter()
            .filter(|&&b| b)
            .count();
        crate::assert_with_log!(
            total_leaders == 1,
            "exactly 1 leader",
            1usize,
            total_leaders
        );
        crate::test_complete!("barrier_drop_one_of_multiple_waiters_allows_trip");
    }

    #[test]
    fn barrier_wait_second_poll_fails_closed() {
        init_test("barrier_wait_second_poll_fails_closed");
        let barrier = Barrier::new(1);
        let cx: Cx = Cx::for_testing();
        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);

        let mut fut = barrier.wait(&cx);
        let first = Pin::new(&mut fut).poll(&mut poll_cx);
        let first_is_leader = matches!(first, Poll::Ready(Ok(result)) if result.is_leader());
        crate::assert_with_log!(
            first_is_leader,
            "first poll completes as leader",
            true,
            first_is_leader
        );

        let second = Pin::new(&mut fut).poll(&mut poll_cx);
        let second_is_polled_after_completion = matches!(
            second,
            Poll::Ready(Err(BarrierWaitError::PolledAfterCompletion))
        );
        crate::assert_with_log!(
            second_is_polled_after_completion,
            "second poll fails closed",
            true,
            second_is_polled_after_completion
        );
        crate::test_complete!("barrier_wait_second_poll_fails_closed");
    }

    #[test]
    fn barrier_cancelled_wait_second_poll_fails_closed() {
        init_test("barrier_cancelled_wait_second_poll_fails_closed");
        let barrier = Barrier::new(2);
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);

        let mut fut = barrier.wait(&cx);
        let first = Pin::new(&mut fut).poll(&mut poll_cx);
        let first_is_cancelled = matches!(first, Poll::Ready(Err(BarrierWaitError::Cancelled)));
        crate::assert_with_log!(
            first_is_cancelled,
            "first poll is cancelled",
            true,
            first_is_cancelled
        );

        let second = Pin::new(&mut fut).poll(&mut poll_cx);
        let second_is_polled_after_completion = matches!(
            second,
            Poll::Ready(Err(BarrierWaitError::PolledAfterCompletion))
        );
        crate::assert_with_log!(
            second_is_polled_after_completion,
            "second poll fails closed",
            true,
            second_is_polled_after_completion
        );
        crate::test_complete!("barrier_cancelled_wait_second_poll_fails_closed");
    }

    #[test]
    fn barrier_wait_error_debug() {
        init_test("barrier_wait_error_debug");
        let err = BarrierWaitError::Cancelled;
        let dbg = format!("{err:?}");
        assert_eq!(dbg, "Cancelled");
        crate::test_complete!("barrier_wait_error_debug");
    }

    #[test]
    fn barrier_wait_error_clone_copy_eq() {
        init_test("barrier_wait_error_clone_copy_eq");
        let err = BarrierWaitError::Cancelled;
        let err2 = err;
        let err3 = err;
        assert_eq!(err2, err3);
        let done = BarrierWaitError::PolledAfterCompletion;
        let done2 = done;
        assert_eq!(done2, BarrierWaitError::PolledAfterCompletion);
        crate::test_complete!("barrier_wait_error_clone_copy_eq");
    }

    #[test]
    fn barrier_wait_error_display() {
        init_test("barrier_wait_error_display");
        let err = BarrierWaitError::Cancelled;
        let display = format!("{err}");
        assert_eq!(display, "barrier wait cancelled");
        let done = BarrierWaitError::PolledAfterCompletion;
        let done_display = format!("{done}");
        assert_eq!(done_display, "barrier future polled after completion");
        crate::test_complete!("barrier_wait_error_display");
    }

    #[test]
    fn barrier_wait_error_is_std_error() {
        init_test("barrier_wait_error_is_std_error");
        let err = BarrierWaitError::Cancelled;
        let e: &dyn std::error::Error = &err;
        let display = format!("{e}");
        assert!(display.contains("cancelled"));
        crate::test_complete!("barrier_wait_error_is_std_error");
    }

    #[test]
    fn barrier_debug() {
        init_test("barrier_debug");
        let barrier = Barrier::new(3);
        let dbg = format!("{barrier:?}");
        assert!(dbg.contains("Barrier"));
        crate::test_complete!("barrier_debug");
    }

    #[test]
    fn barrier_parties() {
        init_test("barrier_parties");
        let barrier = Barrier::new(5);
        assert_eq!(barrier.parties(), 5);
        crate::test_complete!("barrier_parties");
    }

    #[test]
    fn barrier_wait_result_is_leader() {
        init_test("barrier_wait_result_is_leader");
        let result = BarrierWaitResult { is_leader: true };
        assert!(result.is_leader());
        let result2 = BarrierWaitResult { is_leader: false };
        assert!(!result2.is_leader());
        crate::test_complete!("barrier_wait_result_is_leader");
    }
}
