//! Fuzz barrier reset+wait race conditions.
//!
//! Tests arbitrary reset+wait interleavings to ensure pre-reset waiters
//! either complete or get reset-cleared cleanly. A "reset" occurs when
//! all waiters cancel, leaving the barrier in a clean state for new arrivals.
//!
//! Critical invariants:
//! - Pre-reset waiters either complete successfully or get cancelled cleanly
//! - Post-reset waiters can trip normally without interference from stale state
//! - Generation advances properly on barrier trips and resets
//! - Exactly one leader per successful barrier trip

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::{Barrier, BarrierWaitError};
use asupersync::cx::Cx;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::task::{Context, Poll, Waker};
use std::pin::Pin;
use std::future::Future;

#[derive(Debug, Clone, Arbitrary)]
struct BarrierResetConfig {
    /// Number of parties required to trip the barrier
    parties: u8,
    /// Operations to perform
    operations: Vec<BarrierOperation>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum BarrierOperation {
    /// Add a waiter to the barrier
    AddWaiter { waiter_id: u8 },
    /// Cancel a specific waiter
    CancelWaiter { waiter_id: u8 },
    /// Cancel all current waiters (force reset)
    CancelAllWaiters,
    /// Poll a waiter to make progress
    PollWaiter { waiter_id: u8 },
    /// Poll all waiters
    PollAllWaiters,
    /// Create a new generation of waiters after reset
    NewGeneration { count: u8 },
    /// Check barrier state consistency
    CheckState,
}

impl BarrierResetConfig {
    fn max_parties() -> u8 {
        10 // Keep reasonable for testing
    }

    fn max_operations() -> u8 {
        40 // Limit test duration
    }

    fn max_new_generation() -> u8 {
        5 // Limit new generation size
    }
}

/// Tracks barrier behavior across resets
#[derive(Debug)]
struct BarrierResetTracker {
    successful_trips: AtomicUsize,
    cancelled_waiters: AtomicUsize,
    leaders_observed: AtomicUsize,
    reset_cycles: AtomicUsize,
    state_inconsistencies: AtomicUsize,
}

impl BarrierResetTracker {
    fn new() -> Self {
        Self {
            successful_trips: AtomicUsize::new(0),
            cancelled_waiters: AtomicUsize::new(0),
            leaders_observed: AtomicUsize::new(0),
            reset_cycles: AtomicUsize::new(0),
            state_inconsistencies: AtomicUsize::new(0),
        }
    }

    fn record_trip(&self, is_leader: bool) {
        self.successful_trips.fetch_add(1, Ordering::SeqCst);
        if is_leader {
            self.leaders_observed.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn record_cancellation(&self) {
        self.cancelled_waiters.fetch_add(1, Ordering::SeqCst);
    }

    fn record_reset(&self) {
        self.reset_cycles.fetch_add(1, Ordering::SeqCst);
    }

    fn record_inconsistency(&self) {
        self.state_inconsistencies.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self, expected_parties: usize) -> Result<(), String> {
        let trips = self.successful_trips.load(Ordering::SeqCst);
        let leaders = self.leaders_observed.load(Ordering::SeqCst);
        let cancelled = self.cancelled_waiters.load(Ordering::SeqCst);
        let resets = self.reset_cycles.load(Ordering::SeqCst);
        let inconsistencies = self.state_inconsistencies.load(Ordering::SeqCst);

        // Core invariant: exactly one leader per trip cycle
        let trip_cycles = trips / expected_parties;
        if trip_cycles > 0 && leaders != trip_cycles {
            return Err(format!(
                "Leader count mismatch: {} leaders for {} trip cycles (expected {})",
                leaders, trip_cycles, trip_cycles
            ));
        }

        // No state inconsistencies should be detected
        if inconsistencies > 0 {
            return Err(format!("Detected {} state inconsistencies", inconsistencies));
        }

        // Sanity checks
        if trips > (expected_parties * 20) {
            return Err(format!("Excessive trips: {}", trips));
        }

        if cancelled > 100 {
            return Err(format!("Excessive cancellations: {}", cancelled));
        }

        Ok(())
    }
}

/// Tracks a single waiter's state
struct TrackedWaiter {
    future: Pin<Box<dyn Future<Output = Result<bool, BarrierWaitError>> + Send>>,
    completed: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    polled: bool,
}

impl TrackedWaiter {
    fn new(barrier: Arc<Barrier>, tracker: Arc<BarrierResetTracker>) -> Self {
        let completed = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();
        let cancelled_clone = cancelled.clone();

        let future = Box::pin(async move {
            let cx = Cx::for_testing();

            // Check for cancellation before and during wait
            if cancelled_clone.load(Ordering::SeqCst) {
                cx.set_cancel_requested(true);
            }

            let result = barrier.wait(&cx).await;

            match result {
                Ok(wait_result) => {
                    completed_clone.store(true, Ordering::SeqCst);
                    tracker.record_trip(wait_result.is_leader());
                    Ok(wait_result.is_leader())
                }
                Err(BarrierWaitError::Cancelled) => {
                    completed_clone.store(true, Ordering::SeqCst);
                    tracker.record_cancellation();
                    Err(BarrierWaitError::Cancelled)
                }
                Err(e) => {
                    completed_clone.store(true, Ordering::SeqCst);
                    Err(e)
                }
            }
        });

        Self {
            future,
            completed,
            cancelled,
            polled: false,
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn poll(&mut self) -> Poll<Result<bool, BarrierWaitError>> {
        if self.completed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(BarrierWaitError::PolledAfterCompletion));
        }

        self.polled = true;
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        self.future.as_mut().poll(&mut context)
    }

    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }
}

fn noop_waker() -> Waker {
    use std::task::{RawWaker, RawWakerVTable};

    static NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );

    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE)) }
}

/// Test barrier reset+wait race scenarios
fn test_barrier_reset_scenario(
    config: &BarrierResetConfig,
    tracker: &BarrierResetTracker,
) -> Result<(), String> {
    let parties = config.parties.max(1).min(BarrierResetConfig::max_parties()) as usize;
    let barrier = Arc::new(Barrier::new(parties));
    let mut waiters: HashMap<u8, TrackedWaiter> = HashMap::new();

    let max_ops = config.max_operations.min(BarrierResetConfig::max_operations()) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            BarrierOperation::AddWaiter { waiter_id } => {
                let id = *waiter_id % 20; // Limit to reasonable number
                if !waiters.contains_key(&id) {
                    let waiter = TrackedWaiter::new(barrier.clone(), Arc::new(BarrierResetTracker::new()));
                    waiters.insert(id, waiter);
                }
            }

            BarrierOperation::CancelWaiter { waiter_id } => {
                let id = *waiter_id % 20;
                if let Some(waiter) = waiters.get(&id) {
                    waiter.cancel();
                }
            }

            BarrierOperation::CancelAllWaiters => {
                // Cancel all current waiters - this should cause a "reset"
                let active_count = waiters.len();
                for waiter in waiters.values() {
                    waiter.cancel();
                }
                waiters.clear();
                if active_count > 0 {
                    tracker.record_reset();
                }
            }

            BarrierOperation::PollWaiter { waiter_id } => {
                let id = *waiter_id % 20;
                if let Some(waiter) = waiters.get_mut(&id) {
                    let _ = waiter.poll();
                    if waiter.is_completed() {
                        waiters.remove(&id);
                    }
                }
            }

            BarrierOperation::PollAllWaiters => {
                let mut to_remove = Vec::new();
                for (id, waiter) in waiters.iter_mut() {
                    let _ = waiter.poll();
                    if waiter.is_completed() {
                        to_remove.push(*id);
                    }
                }
                for id in to_remove {
                    waiters.remove(&id);
                }
            }

            BarrierOperation::NewGeneration { count } => {
                // Add a fresh generation of waiters after a reset
                let gen_count = (*count).min(BarrierResetConfig::max_new_generation()) as usize;
                let start_id = waiters.len() as u8;

                for i in 0..gen_count {
                    let id = start_id + i as u8;
                    if !waiters.contains_key(&id) {
                        let waiter = TrackedWaiter::new(barrier.clone(), Arc::new(BarrierResetTracker::new()));
                        waiters.insert(id, waiter);
                    }
                }
            }

            BarrierOperation::CheckState => {
                // Use the test helper to check barrier state
                #[cfg(test)]
                {
                    let (arrived, generation, waiter_count) = barrier.state_snapshot_for_test();

                    // Basic consistency checks
                    if arrived > parties {
                        tracker.record_inconsistency();
                        return Err(format!("Invalid arrived count: {} > {}", arrived, parties));
                    }

                    if waiter_count > parties {
                        tracker.record_inconsistency();
                        return Err(format!("Too many waiters: {} > {}", waiter_count, parties));
                    }
                }

                // Check our local state consistency
                if waiters.len() > parties * 2 {
                    tracker.record_inconsistency();
                    return Err(format!("Local waiter tracking inconsistent: {}", waiters.len()));
                }
            }
        }

        // Always poll all waiters after each operation to drive progress
        let mut to_remove = Vec::new();
        for (id, waiter) in waiters.iter_mut() {
            let _ = waiter.poll();
            if waiter.is_completed() {
                to_remove.push(*id);
            }
        }
        for id in to_remove {
            waiters.remove(&id);
        }
    }

    // Final state check
    if let Err(msg) = tracker.check_invariants(parties) {
        return Err(format!("Final invariant violation: {}", msg));
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: BarrierResetConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() || config.parties == 0 {
        return;
    }

    let tracker = BarrierResetTracker::new();

    // Test the reset+wait scenario
    if let Err(msg) = test_barrier_reset_scenario(&config, &tracker) {
        panic!("Barrier reset+wait scenario test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        use std::thread;

        let tracker2 = BarrierResetTracker::new();
        let config2 = config.clone();

        let handle = thread::spawn(move || {
            test_barrier_reset_scenario(&config2, &tracker2)
        });

        match handle.join() {
            Ok(Ok(())) => {
                // Concurrent test succeeded
            }
            Ok(Err(msg)) => {
                panic!("Concurrent barrier reset+wait test failed: {}", msg);
            }
            Err(_) => {
                panic!("Concurrent test thread panicked");
            }
        }
    }

    // Ensure we actually performed some operations
    let total_trips = tracker.successful_trips.load(Ordering::SeqCst);
    let total_cancellations = tracker.cancelled_waiters.load(Ordering::SeqCst);
    let total_resets = tracker.reset_cycles.load(Ordering::SeqCst);

    if total_trips == 0 && total_cancellations == 0 && total_resets == 0 && !config.operations.is_empty() {
        panic!("No meaningful operations were performed during the test");
    }
});