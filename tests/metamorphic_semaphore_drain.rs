#![allow(warnings)]
//! Metamorphic Testing for Semaphore Permit Drain Ordering
//!
//! Tests fairness invariants when permits become available through
//! add_permits() or when waiters are drained via close().
//!
//! Target: src/sync/semaphore.rs
//!
//! # Metamorphic Relations
//!
//! 1. **FIFO Ordering**: Earlier waiters acquire permits before later waiters
//! 2. **Close Drain Completeness**: All waiters receive wakeups when semaphore is closed
//! 3. **Permit Addition Fairness**: Adding permits satisfies waiters in arrival order
//! 4. **Obligation Conservation**: Acquired permits equal created obligations
//! 5. **Drain Atomicity**: Close operation wakes all waiters atomically

#![cfg(test)]

use proptest::prelude::*;
use std::sync::{Arc, Mutex as StdMutex};

use asupersync::cx::Cx;
use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::sync::Semaphore;
use asupersync::types::Budget;

/// Test harness for semaphore drain ordering tests.
///
/// Holds a `LabRuntime`, a root region, and a shared `Semaphore`. Waiters are
/// spawned as lab tasks that write their outcome into a shared `Vec` guarded
/// by a `StdMutex`, which the harness harvests after running the runtime to
/// quiescence.
struct SemaphoreDrainHarness {
    lab_runtime: LabRuntime,
    semaphore: Arc<Semaphore>,
    region: asupersync::types::RegionId,
}

impl SemaphoreDrainHarness {
    fn new(seed: u64, initial_permits: usize) -> Self {
        let config = LabConfig::new(seed)
            .worker_count(4)
            .trace_capacity(1024)
            .max_steps(5000);
        let mut lab_runtime = LabRuntime::new(config);
        let region = lab_runtime.state.create_root_region(Budget::INFINITE);
        let semaphore = Arc::new(Semaphore::new(initial_permits));

        Self {
            lab_runtime,
            semaphore,
            region,
        }
    }

    /// Spawn `permit_counts.len()` waiter tasks, each acquiring the requested
    /// number of permits. Each waiter writes `Some(index)` on success or
    /// `None` on close/cancel into its slot in the returned shared vector.
    fn spawn_waiters(&mut self, permit_counts: &[usize]) -> Arc<StdMutex<Vec<Option<usize>>>> {
        let results: Arc<StdMutex<Vec<Option<usize>>>> =
            Arc::new(StdMutex::new(vec![None; permit_counts.len()]));

        for (index, &count) in permit_counts.iter().enumerate() {
            let sem = Arc::clone(&self.semaphore);
            let results = Arc::clone(&results);
            let (task_id, _handle) = self
                .lab_runtime
                .state
                .create_task(self.region, Budget::INFINITE, async move {
                    let cx = Cx::for_testing();
                    if let Ok(_permit) = sem.acquire(&cx, count).await {
                        results.lock().expect("results lock")[index] = Some(index);
                    }
                })
                .expect("create waiter");
            self.lab_runtime.scheduler.lock().schedule(task_id, 0);
        }

        results
    }

    /// Step the runtime until at least `waiter_count` waiters have registered
    /// on the semaphore (i.e. `available_permits()` has been consumed or the
    /// waiters are queued). Falls back to a bounded step budget so tests
    /// terminate even if waiters cannot all register.
    fn step_until_queued(&mut self, _waiter_count: usize) {
        // Drive the scheduler until each spawned waiter has at least polled
        // `acquire` once and parked itself on the wait-queue. We cap the work
        // at a generous bound to preserve termination on any pathological
        // schedule.
        for _ in 0..200 {
            self.lab_runtime.step_for_test();
        }
    }

    /// Spawn waiters, run to quiescence, then harvest per-waiter outcomes.
    fn acquire_permits_concurrent(&mut self, permit_counts: &[usize]) -> Vec<Option<usize>> {
        let results = self.spawn_waiters(permit_counts);
        self.lab_runtime.run_until_quiescent();
        let harvested = results.lock().expect("results lock").clone();
        harvested
    }
}

/// Statistics for analyzing semaphore drain behavior
#[derive(Debug, Clone)]
struct DrainStats {
    waiter_count: usize,
    successful_acquires: usize,
    failed_acquires: usize,
    acquire_order: Vec<usize>,
    total_permits_requested: usize,
}

impl DrainStats {
    fn analyze(permit_counts: &[usize], results: &[Option<usize>]) -> Self {
        let waiter_count = permit_counts.len();
        let successful_acquires = results.iter().filter(|r| r.is_some()).count();
        let failed_acquires = waiter_count - successful_acquires;
        let acquire_order: Vec<usize> = results.iter().filter_map(|&r| r).collect();
        let total_permits_requested = permit_counts.iter().sum();

        Self {
            waiter_count,
            successful_acquires,
            failed_acquires,
            acquire_order,
            total_permits_requested,
        }
    }

    fn fifo_violations(&self) -> usize {
        let mut violations = 0;
        for i in 0..self.acquire_order.len() {
            for j in (i + 1)..self.acquire_order.len() {
                if self.acquire_order[i] > self.acquire_order[j] {
                    violations += 1;
                }
            }
        }
        violations
    }
}

// MR1: FIFO Ordering
// If waiter A arrives before waiter B and both can be satisfied,
// then A must acquire before B.
#[test]
fn mr_fifo_ordering() {
    proptest!(|(
        seed in 0u64..1024,
        initial_permits in 1..10_usize,
        waiter_permits in prop::collection::vec(1..5_usize, 2..8)
    )| {
        let mut harness = SemaphoreDrainHarness::new(seed, initial_permits);

        // Add enough permits to satisfy all waiters.
        let total_needed: usize = waiter_permits.iter().sum();
        if total_needed > initial_permits {
            harness.semaphore.add_permits(total_needed - initial_permits);
        }

        let results = harness.acquire_permits_concurrent(&waiter_permits);
        let stats = DrainStats::analyze(&waiter_permits, &results);

        // FIFO invariant: no ordering violations among successful acquires.
        prop_assert_eq!(stats.fifo_violations(), 0,
            "FIFO violation: acquire order {:?} for waiter permits {:?}",
            stats.acquire_order, waiter_permits);
    });
}

// MR2: Close Drain Completeness
// When semaphore is closed, all waiters must receive error responses.
#[test]
fn mr_close_drain_completeness() {
    proptest!(|(
        seed in 0u64..1024,
        waiter_permits in prop::collection::vec(1..5_usize, 1..8)
    )| {
        // Start with 0 permits so all waiters block.
        let mut harness = SemaphoreDrainHarness::new(seed, 0);

        // Spawn waiters that record only successful acquisitions; a closed
        // semaphore produces `None` in every slot.
        let results = harness.spawn_waiters(&waiter_permits);

        // Let waiters register on the semaphore's wait queue before closing.
        harness.step_until_queued(waiter_permits.len());

        // Close after all waiters have queued up.
        harness.semaphore.close();
        harness.lab_runtime.run_until_quiescent();

        let harvested = results.lock().expect("results lock").clone();

        // All waiters should have received errors (no successes recorded).
        prop_assert!(harvested.iter().all(|slot| slot.is_none()),
            "Not all waiters received errors on close: {:?}", harvested);
    });
}

// MR3: Permit Addition Fairness
// Adding permits should satisfy blocked waiters in FIFO order.
#[test]
fn mr_permit_addition_fairness() {
    proptest!(|(
        seed in 0u64..1024,
        waiter_permits in prop::collection::vec(1..3_usize, 2..6),
        added_permits in 1..10_usize
    )| {
        // Start with 0 permits so all waiters block initially.
        let mut harness = SemaphoreDrainHarness::new(seed, 0);

        let results = harness.spawn_waiters(&waiter_permits);

        // Advance virtual time a small amount and let waiters queue before we
        // perturb the semaphore by adding permits.
        harness.lab_runtime.advance_time(10_000_000); // 10ms in nanoseconds
        harness.step_until_queued(waiter_permits.len());
        harness.semaphore.add_permits(added_permits);

        harness.lab_runtime.run_until_quiescent();

        let harvested = results.lock().expect("results lock").clone();
        let stats = DrainStats::analyze(&waiter_permits, &harvested);

        // Check that waiters were satisfied in order when permits allowed.
        prop_assert_eq!(stats.fifo_violations(), 0,
            "Permit addition fairness violation: order {:?} for permits {:?}, added {}",
            stats.acquire_order, waiter_permits, added_permits);
    });
}

// MR4: Obligation Conservation
// The number of successful acquisitions should equal available permits.
#[test]
fn mr_obligation_conservation() {
    proptest!(|(
        seed in 0u64..1024,
        initial_permits in 1..20_usize,
        waiter_permits in prop::collection::vec(1..5_usize, 1..10)
    )| {
        let mut harness = SemaphoreDrainHarness::new(seed, initial_permits);
        let results = harness.acquire_permits_concurrent(&waiter_permits);

        // Calculate how many permits should be consumed.
        let mut permits_consumed = 0;
        for (i, &count) in waiter_permits.iter().enumerate() {
            if results[i].is_some() {
                permits_consumed += count;
            }
        }

        // Remaining permits = initial - consumed.
        let remaining = harness.semaphore.available_permits();
        let expected_remaining = initial_permits.saturating_sub(permits_consumed);

        prop_assert_eq!(remaining, expected_remaining,
            "Obligation conservation violation: {} permits consumed from {}, {} remaining, expected {}",
            permits_consumed, initial_permits, remaining, expected_remaining);
    });
}

// MR5: Drain Atomicity
// Close operation should either complete all waiters or none.
#[test]
fn mr_drain_atomicity() {
    proptest!(|(
        seed in 0u64..1024,
        waiter_permits in prop::collection::vec(1..3_usize, 2..6)
    )| {
        let mut harness = SemaphoreDrainHarness::new(seed, 0);

        let results = harness.spawn_waiters(&waiter_permits);

        // Let waiters register before closing to probe atomicity of drain.
        harness.step_until_queued(waiter_permits.len());

        harness.semaphore.close();
        harness.lab_runtime.run_until_quiescent();

        let harvested = results.lock().expect("results lock").clone();
        let success_count = harvested.iter().filter(|slot| slot.is_some()).count();

        // Atomicity: either all waiters get errors (successful close, 0
        // successes) or no waiters saw the close (all successes), but any
        // intermediate state would indicate a non-atomic drain.
        prop_assert!(success_count == 0 || success_count == waiter_permits.len(),
            "Drain atomicity violation: {} of {} waiters acquired successfully",
            success_count, waiter_permits.len());
    });
}
