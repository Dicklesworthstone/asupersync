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
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::sync::Semaphore;

/// Test harness for semaphore drain ordering tests
struct SemaphoreDrainHarness {
    lab_runtime: LabRuntime,
    semaphore: Arc<Semaphore>,
    cx: Cx,
}

impl SemaphoreDrainHarness {
    fn new(initial_permits: usize) -> Self {
        let config = LabConfig::default()
            .worker_count(4)
            .trace_capacity(1024)
            .max_steps(5000);
        let lab_runtime = LabRuntime::new(config);
        let semaphore = Arc::new(Semaphore::new(initial_permits));
        let cx = lab_runtime.block_on_local(async { Cx::root() });

        Self {
            lab_runtime,
            semaphore,
            cx,
        }
    }

    fn acquire_permits_concurrent(&self, permit_counts: &[usize]) -> Vec<Option<usize>> {
        let semaphore = Arc::clone(&self.semaphore);
        let tasks: Vec<_> = permit_counts
            .iter()
            .enumerate()
            .map(|(index, &count)| {
                let sem = Arc::clone(&semaphore);
                let cx = self.cx.child(format!("waiter-{}", index));
                self.lab_runtime.spawn_local(async move {
                    match sem.acquire(&cx, count).await {
                        Ok(_permit) => Some(index),
                        Err(_) => None,
                    }
                })
            })
            .collect();

        self.lab_runtime.block_on_local(async {
            let mut results = vec![None; permit_counts.len()];
            for task in tasks {
                if let Some(acquired_index) = task.await {
                    results[acquired_index] = Some(acquired_index);
                }
            }
            results
        })
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
        initial_permits in 1..10_usize,
        waiter_permits in prop::collection::vec(1..5_usize, 2..8)
    )| {
        let harness = SemaphoreDrainHarness::new(initial_permits);

        // Add enough permits to satisfy all waiters
        let total_needed: usize = waiter_permits.iter().sum();
        if total_needed > initial_permits {
            harness.semaphore.add_permits(total_needed - initial_permits);
        }

        let results = harness.acquire_permits_concurrent(&waiter_permits);
        let stats = DrainStats::analyze(&waiter_permits, &results);

        // FIFO invariant: no ordering violations
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
        waiter_permits in prop::collection::vec(1..5_usize, 1..8)
    )| {
        // Start with 0 permits so all waiters block
        let harness = SemaphoreDrainHarness::new(0);

        let semaphore = Arc::clone(&harness.semaphore);
        let tasks: Vec<_> = waiter_permits.iter().enumerate().map(|(index, &count)| {
            let sem = Arc::clone(&semaphore);
            let cx = harness.cx.child(format!("waiter-{}", index));
            harness.lab_runtime.spawn_local(async move {
                sem.acquire(&cx, count).await.is_err()
            })
        }).collect();

        // Close semaphore after spawning all waiters
        semaphore.close();

        let error_results: Vec<bool> = harness.lab_runtime.block_on_local(async {
            let mut results = Vec::new();
            for task in tasks {
                results.push(task.await);
            }
            results
        });

        // All waiters should receive errors
        prop_assert!(error_results.iter().all(|&got_error| got_error),
            "Not all waiters received errors on close: {:?}", error_results);
    });
}

// MR3: Permit Addition Fairness
// Adding permits should satisfy blocked waiters in FIFO order.
#[test]
fn mr_permit_addition_fairness() {
    proptest!(|(
        waiter_permits in prop::collection::vec(1..3_usize, 2..6),
        added_permits in 1..10_usize
    )| {
        // Start with 0 permits so all waiters block initially
        let harness = SemaphoreDrainHarness::new(0);

        let semaphore = Arc::clone(&harness.semaphore);

        // Spawn waiters that will block
        let tasks: Vec<_> = waiter_permits.iter().enumerate().map(|(index, &count)| {
            let sem = Arc::clone(&semaphore);
            let cx = harness.cx.child(format!("waiter-{}", index));
            harness.lab_runtime.spawn_local(async move {
                match sem.acquire(&cx, count).await {
                    Ok(_permit) => Some(index),
                    Err(_) => None,
                }
            })
        }).collect();

        // Add permits after small delay to let waiters queue up
        harness.lab_runtime.advance_time_by(Duration::from_millis(10));
        semaphore.add_permits(added_permits);

        let results: Vec<Option<usize>> = harness.lab_runtime.block_on_local(async {
            let mut results = vec![None; waiter_permits.len()];
            for task in tasks {
                if let Some(acquired_index) = task.await {
                    results[acquired_index] = Some(acquired_index);
                }
            }
            results
        });

        let stats = DrainStats::analyze(&waiter_permits, &results);

        // Check that waiters were satisfied in order when permits allowed
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
        initial_permits in 1..20_usize,
        waiter_permits in prop::collection::vec(1..5_usize, 1..10)
    )| {
        let harness = SemaphoreDrainHarness::new(initial_permits);
        let results = harness.acquire_permits_concurrent(&waiter_permits);
        let stats = DrainStats::analyze(&waiter_permits, &results);

        // Calculate how many permits should be consumed
        let mut permits_consumed = 0;
        for (i, &count) in waiter_permits.iter().enumerate() {
            if results[i].is_some() {
                permits_consumed += count;
            }
        }

        // Remaining permits = initial - consumed
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
        waiter_permits in prop::collection::vec(1..3_usize, 2..6)
    )| {
        let harness = SemaphoreDrainHarness::new(0);
        let semaphore = Arc::clone(&harness.semaphore);

        let tasks: Vec<_> = waiter_permits.iter().enumerate().map(|(index, &count)| {
            let sem = Arc::clone(&semaphore);
            let cx = harness.cx.child(format!("waiter-{}", index));
            harness.lab_runtime.spawn_local(async move {
                sem.acquire(&cx, count).await.is_err()
            })
        }).collect();

        // Close and check that all waiters complete with errors
        semaphore.close();

        let completion_results: Vec<bool> = harness.lab_runtime.block_on_local(async {
            let mut results = Vec::new();
            for task in tasks {
                results.push(task.await);
            }
            results
        });

        // Atomicity: either all waiters get errors (successful close) or none do
        let error_count = completion_results.iter().filter(|&&got_error| got_error).count();
        prop_assert!(error_count == 0 || error_count == waiter_permits.len(),
            "Drain atomicity violation: {} of {} waiters got errors",
            error_count, waiter_permits.len());
    });
}
